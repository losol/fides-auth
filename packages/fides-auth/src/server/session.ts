// server/session.ts
//
// Framework-agnostic session persistence over a {@link CookieStore}. The split
// encode/decode lives in `../session-cookies`; these helpers wire it to a cookie
// store, apply the per-cookie size guard, and own the refresh flow — with no
// dependency on any framework's cookie API.
//
// This is also where the session lifecycle events in `../session-events` are
// emitted: it is the one layer that sees both the session and the bytes it
// costs, so `session.created` / `session.refreshed` are raised from here rather
// than from each caller.

import {
  ACCESS_TOKEN_COOKIE_NAME,
  COOKIE_INFO_BYTES,
  ID_TOKEN_COOKIE_NAME,
  SESSION_COOKIE_NAME,
  assertCookieWithinLimit,
  defaultSessionCookieOptions,
} from '../cookies';
import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import { classifyRefreshFailure, getOAuthErrorLogContext } from '../oauth-logging';
import { refreshSession } from '../session-refresh';
import {
  SESSION_EVENT,
  logSessionEvent,
  type RefreshFailureCause,
  type SessionClearedTrigger,
  type SessionRejectedReason,
} from '../session-events';
import {
  decodeIdTokenCookie,
  encodeSessionCookies,
  tryDecodeSessionCookies,
} from '../session-cookies';
import type { CreateSessionOptions, Session } from '../types';
import type { CookieStore } from './cookie-store';

const logger = createLogger({ namespace: 'fides-auth:server:session' });

type Secret = string | Uint8Array;

/** Applies the browser size guard to one cookie value; logs as it nears the limit. */
function checkSize(name: string, value: string): number {
  // Fail loudly above the browser per-cookie limit (the browser would otherwise
  // drop the cookie silently, producing a broken login).
  const size = assertCookieWithinLimit(name, value);
  if (size >= COOKIE_INFO_BYTES) {
    logger.info({ cookieName: name, size }, 'Cookie approaching browser size limit');
  }
  return size;
}

/** Seconds until the access token expires, for the `expiresIn` log field. */
function expiresInSeconds(session: Session): number | undefined {
  const at = session.tokens?.accessTokenExpiresAt;
  if (!at) return undefined;
  const ms = Date.parse(at);
  return Number.isFinite(ms) ? Math.round((ms - Date.now()) / 1000) : undefined;
}

/** How {@link persistSession} should report what it just wrote. */
export interface PersistSessionOptions {
  /**
   * Which lifecycle event this write represents. Omit to write silently — for
   * callers that emit their own event, or that persist for reasons the session
   * vocabulary doesn't cover.
   */
  event?: typeof SESSION_EVENT.CREATED | typeof SESSION_EVENT.REFRESHED;
  /** Only meaningful for {@link SESSION_EVENT.REFRESHED}: did the provider issue a new refresh token? */
  rotatedRefreshToken?: boolean;
}

/**
 * Encrypts a session and writes it across the "session", "session_at" and
 * "session_it" cookies, clearing the split-out cookies the session has no token for.
 *
 * @returns The encrypted JWT stored in the main "session" cookie.
 */
export async function persistSession(
  store: CookieStore,
  session: Session,
  secret: Secret,
  options: PersistSessionOptions = {},
): Promise<string> {
  const encoded = await encodeSessionCookies(session, secret);

  const values: Array<[string, string | undefined]> = [
    [SESSION_COOKIE_NAME, encoded.session],
    [ACCESS_TOKEN_COOKIE_NAME, encoded.accessToken],
    [ID_TOKEN_COOKIE_NAME, encoded.idToken],
  ];

  // Size-check everything before touching the store. Throwing part-way through
  // would leave one user's session cookie next to another user's tokens — the
  // caller sees an error while the browser holds a working, mixed-up session.
  let cookieBytes = 0;
  for (const [name, value] of values) {
    if (value) cookieBytes += checkSize(name, value);
  }

  for (const [name, value] of values) {
    if (value) {
      await store.set(name, value, defaultSessionCookieOptions);
    } else {
      await store.delete(name);
    }
  }

  if (options.event === SESSION_EVENT.CREATED) {
    logSessionEvent(logger, {
      event: SESSION_EVENT.CREATED,
      sid: session.sid,
      hasRefreshToken: !!session.tokens?.refreshToken,
      scopes: session.scopes,
      expiresIn: expiresInSeconds(session),
      cookieBytes,
    });
  } else if (options.event === SESSION_EVENT.REFRESHED) {
    logSessionEvent(logger, {
      event: SESSION_EVENT.REFRESHED,
      sid: session.sid,
      expiresIn: expiresInSeconds(session),
      rotatedRefreshToken: options.rotatedRefreshToken ?? false,
      cookieBytes,
    });
  }

  return encoded.session;
}

/** Outcome of reading the session from the cookie store. */
export type ReadSessionResult =
  | { session: Session; reason?: undefined }
  | { session: null; reason: SessionRejectedReason };

/**
 * Reads and reassembles the current session, reporting why when there isn't one.
 *
 * The reason comes from the package-wide {@link SessionRejectedReason}
 * vocabulary, so a proxy or status route can log the same word the heartbeat
 * endpoint logs. Does not log on its own — the caller owns the request context
 * and decides whether a missing session is worth a line.
 */
export async function tryReadSession(store: CookieStore, secret: Secret): Promise<ReadSessionResult> {
  try {
    return await tryDecodeSessionCookies(
      {
        session: (await store.get(SESSION_COOKIE_NAME)) ?? null,
        accessToken: (await store.get(ACCESS_TOKEN_COOKIE_NAME)) ?? null,
        idToken: (await store.get(ID_TOKEN_COOKIE_NAME)) ?? null,
      },
      secret,
    );
  } catch (error) {
    // Worker thread errors (e.g. from the crypto worker) should not crash the app.
    if (error instanceof Error && error.message.includes('worker')) {
      logger.error({ error }, 'Worker thread error reading session');
    } else {
      logger.error({ error }, 'Unexpected error reading session');
    }
    return { session: null, reason: 'unreadable_session' };
  }
}

/**
 * Reads and reassembles the current session from the cookie store, or null when
 * there is none. Decode/validation rules live in `decodeSessionCookies`;
 * the returned session may carry an expired access token.
 *
 * Prefer {@link tryReadSession} when you want to log *why* there is no session.
 */
export async function readSession(store: CookieStore, secret: Secret): Promise<Session | null> {
  return (await tryReadSession(store, secret)).session;
}

/** Outcome of a refresh attempt. */
export type RefreshSessionResult =
  | { ok: true; session: Session; rotatedRefreshToken: boolean }
  | {
    ok: false;
    reason: SessionRejectedReason;
    /**
     * Correlation id of the session that failed, when we got far enough to read
     * one. The line that *ends* a session is the one most worth correlating.
     */
    sid?: string;
    /**
     * Present only when a refresh was actually attempted, i.e. when `reason` is
     * `refresh_failed`. Absent means we never got as far as talking to the
     * provider, so there is no provider verdict to report.
     */
    cause?: RefreshFailureCause;
  };

/**
 * Refreshes the stored session and persists the result, reporting why on failure.
 *
 * The `cause` is the point of this function: `refreshSessionInStore` collapses
 * "the provider says this refresh token is dead" and "we could not reach the
 * provider" into the same `null`, and a caller that logs the user out on both
 * ends sessions that were never actually invalid. Only `invalid_grant` is
 * terminal — see {@link classifyRefreshFailure}.
 */
export async function tryRefreshSessionInStore(
  store: CookieStore,
  config: OAuthConfig,
  secret: Secret,
  options: CreateSessionOptions = {},
): Promise<RefreshSessionResult> {
  // readSession also returns sessions with expired access tokens — exactly
  // what refresh is for.
  const read = await tryReadSession(store, secret);
  const current = read.session;

  if (!current) {
    return { ok: false, reason: read.reason };
  }
  if (!current.tokens?.refreshToken) {
    return { ok: false, reason: 'no_refresh_token', sid: current.sid };
  }

  try {
    const updated = await refreshSession(current, config, options);
    if (!updated) {
      // refreshSession resolves to a session or throws; a null here means the
      // provider answered with something we could not build a session from.
      logSessionEvent(logger, {
        event: SESSION_EVENT.REFRESH_FAILED,
        sid: current.sid,
        cause: 'idp_error',
        accessTokenExpiresAt: current.tokens.accessTokenExpiresAt,
      });
      return { ok: false, reason: 'refresh_failed', cause: 'idp_error', sid: current.sid };
    }

    const rotatedRefreshToken = updated.tokens?.refreshToken !== current.tokens.refreshToken;
    await persistSession(store, updated, secret, {
      event: SESSION_EVENT.REFRESHED,
      rotatedRefreshToken,
    });

    return { ok: true, session: updated, rotatedRefreshToken };
  } catch (error) {
    const cause = classifyRefreshFailure(error);
    logSessionEvent(logger, {
      event: SESSION_EVENT.REFRESH_FAILED,
      sid: current.sid,
      cause,
      status: getOAuthErrorLogContext(error).status,
      accessTokenExpiresAt: current.tokens.accessTokenExpiresAt,
      error: getOAuthErrorLogContext(error),
    });
    return { ok: false, reason: 'refresh_failed', cause, sid: current.sid };
  }
}

/**
 * Refreshes the stored session using its refresh token and persists the result.
 * Returns the updated session, or null when there is nothing to refresh or the
 * refresh token is no longer valid.
 *
 * Prefer {@link tryRefreshSessionInStore}: this signature cannot tell a dead
 * refresh token apart from an unreachable provider, and treating the two alike
 * logs out users whose sessions are still valid.
 */
export async function refreshSessionInStore(
  store: CookieStore,
  config: OAuthConfig,
  secret: Secret,
  options: CreateSessionOptions = {},
): Promise<Session | null> {
  const result = await tryRefreshSessionInStore(store, config, secret, options);
  return result.ok ? result.session : null;
}

/**
 * Reads the raw ID token independently of the session cookies — logout needs
 * the hint even when {@link readSession} returns null.
 */
export async function readIdToken(store: CookieStore, secret: Secret): Promise<string | undefined> {
  try {
    const raw = await store.get(ID_TOKEN_COOKIE_NAME);
    return raw ? await decodeIdTokenCookie(raw, secret) : undefined;
  } catch (error) {
    logger.error({ error }, 'Unexpected error reading ID token');
    return undefined;
  }
}

/** Context for the {@link SESSION_EVENT.CLEARED} event raised by {@link clearSession}. */
export interface ClearSessionOptions {
  /** Why the cookies are going away. Omit to clear without raising an event. */
  trigger?: SessionClearedTrigger;
  /** Correlation id of the session being cleared, when the caller has it. */
  sid?: string;
}

/** Deletes all session cookies. */
export async function clearSession(
  store: CookieStore,
  options: ClearSessionOptions = {},
): Promise<void> {
  await store.delete(SESSION_COOKIE_NAME);
  await store.delete(ACCESS_TOKEN_COOKIE_NAME);
  await store.delete(ID_TOKEN_COOKIE_NAME);

  if (options.trigger) {
    logSessionEvent(logger, {
      event: SESSION_EVENT.CLEARED,
      sid: options.sid,
      trigger: options.trigger,
    });
  }
}
