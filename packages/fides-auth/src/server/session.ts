// server/session.ts
//
// Framework-agnostic session persistence over a {@link CookieStore}. Where the
// session lives — encrypted in the cookies, or in a server-side store behind a
// handle — is a {@link SessionPersistence}; a bare secret means the cookies.
// These helpers own the refresh flow and emit the lifecycle events in
// `../session-events`: this is the one layer that sees both the session and
// what persisting it cost, so `session.created` / `session.refreshed` are
// raised from here rather than from each caller.

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
import type { CreateSessionOptions, Session } from '../types';
import type { CookieStore } from './cookie-store';
import {
  clearSessionCookies,
  resolvePersistence,
  type ReadSessionResult,
  type SessionPersistence,
  type SessionSecret,
} from './session-persistence';

export type { ReadSessionResult } from './session-persistence';

const logger = createLogger({ namespace: 'fides-auth:server:session' });

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
   * vocabulary doesn't cover. Under server persistence only
   * {@link SESSION_EVENT.REFRESHED} keeps the handle; every other write starts
   * a new session with a new one.
   */
  event?: typeof SESSION_EVENT.CREATED | typeof SESSION_EVENT.REFRESHED;
  /** Only meaningful for {@link SESSION_EVENT.REFRESHED}: did the provider issue a new refresh token? */
  rotatedRefreshToken?: boolean;
}

/**
 * Persists a session and raises its lifecycle event.
 *
 * With a secret, or {@link cookiePersistence}, the session is encrypted across
 * the "session", "session_at" and "session_it" cookies. With
 * {@link serverPersistence} it goes to the store and the browser gets a handle.
 *
 * @returns The value written to the main session cookie: the encrypted session,
 * or the handle. Either is a bearer secret.
 */
export async function persistSession(
  store: CookieStore,
  session: Session,
  persistence: SessionSecret | SessionPersistence,
  options: PersistSessionOptions = {},
): Promise<string> {
  const target = resolvePersistence(persistence);
  const written = await target.write(store, session, {
    continuation: options.event === SESSION_EVENT.REFRESHED,
  });

  if (options.event === SESSION_EVENT.CREATED) {
    logSessionEvent(logger, {
      event: SESSION_EVENT.CREATED,
      sid: session.sid,
      hasRefreshToken: !!session.tokens?.refreshToken,
      scopes: session.scopes,
      expiresIn: expiresInSeconds(session),
      cookieBytes: written.cookieBytes,
      persistence: target.mode,
    });
  } else if (options.event === SESSION_EVENT.REFRESHED) {
    logSessionEvent(logger, {
      event: SESSION_EVENT.REFRESHED,
      sid: session.sid,
      expiresIn: expiresInSeconds(session),
      rotatedRefreshToken: options.rotatedRefreshToken ?? false,
      cookieBytes: written.cookieBytes,
      persistence: target.mode,
    });
  }

  return written.cookieValue;
}

/**
 * Reads and reassembles the current session, reporting why when there isn't one.
 *
 * The reason comes from the package-wide {@link SessionRejectedReason}
 * vocabulary, so a proxy or status route can log the same word the heartbeat
 * endpoint logs. Does not log on its own — the caller owns the request context
 * and decides whether a missing session is worth a line.
 */
export async function tryReadSession(
  store: CookieStore,
  persistence: SessionSecret | SessionPersistence,
): Promise<ReadSessionResult> {
  try {
    return await resolvePersistence(persistence).read(store);
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
 * Reads and reassembles the current session, or null when there is none. The
 * returned session may carry an expired access token.
 *
 * Prefer {@link tryReadSession} when you want to log *why* there is no session.
 */
export async function readSession(
  store: CookieStore,
  persistence: SessionSecret | SessionPersistence,
): Promise<Session | null> {
  return (await tryReadSession(store, persistence)).session;
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
 *
 * Under server persistence, refreshes of one session are serialized: concurrent
 * callers get the first refresh's result rather than each spending the refresh
 * token, which with rotation would leave all but one holding a dead one.
 */
export async function tryRefreshSessionInStore(
  store: CookieStore,
  config: OAuthConfig,
  persistence: SessionSecret | SessionPersistence,
  options: CreateSessionOptions = {},
): Promise<RefreshSessionResult> {
  const target = resolvePersistence(persistence);

  // Sessions with expired access tokens are returned too — exactly what
  // refresh is for.
  const read = await tryReadSession(store, target);
  const current = read.session;
  if (!current) {
    return { ok: false, reason: read.reason };
  }
  if (!current.tokens?.refreshToken) {
    return { ok: false, reason: 'no_refresh_token', sid: current.sid };
  }

  if (!target.exclusive) {
    return refreshNow(store, target, config, current, options);
  }

  return target.exclusive(store, async () => {
    // Re-read under the lock: another request may have refreshed, or ended,
    // this session while we waited for it.
    const latest = await tryReadSession(store, target);
    if (!latest.session) {
      return { ok: false, reason: latest.reason, sid: current.sid };
    }
    if (refreshedSince(current, latest.session)) {
      return alreadyRefreshed(current, latest.session);
    }
    return refreshNow(store, target, config, latest.session, options);
  });
}

/** Whether `after` carries tokens `before` did not — someone refreshed in between. */
function refreshedSince(before: Session, after: Session): boolean {
  return (
    after.tokens?.accessToken !== before.tokens?.accessToken ||
    after.tokens?.refreshToken !== before.tokens?.refreshToken
  );
}

function alreadyRefreshed(before: Session, after: Session): RefreshSessionResult {
  logger.debug({ sid: after.sid }, 'Session already refreshed by a concurrent request');
  return {
    ok: true,
    session: after,
    rotatedRefreshToken: after.tokens?.refreshToken !== before.tokens?.refreshToken,
  };
}

/** The refresh itself: exchange, persist, classify. */
async function refreshNow(
  store: CookieStore,
  target: SessionPersistence,
  config: OAuthConfig,
  current: Session,
  options: CreateSessionOptions,
): Promise<RefreshSessionResult> {
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
    await persistSession(store, updated, target, {
      event: SESSION_EVENT.REFRESHED,
      rotatedRefreshToken,
    });

    return { ok: true, session: updated, rotatedRefreshToken };
  } catch (error) {
    const cause = classifyRefreshFailure(error);

    if (cause === 'invalid_grant' && target.exclusive) {
      // With rotation, a concurrent refresh on another instance may have spent
      // this token first — in which case its result is ours too.
      const latest = await tryReadSession(store, target);
      if (latest.session && refreshedSince(current, latest.session)) {
        return alreadyRefreshed(current, latest.session);
      }
    }

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
  persistence: SessionSecret | SessionPersistence,
  options: CreateSessionOptions = {},
): Promise<Session | null> {
  const result = await tryRefreshSessionInStore(store, config, persistence, options);
  return result.ok ? result.session : null;
}

/**
 * Reads the raw ID token independently of session validity — logout needs the
 * hint even when {@link readSession} returns null.
 */
export async function readIdToken(
  store: CookieStore,
  persistence: SessionSecret | SessionPersistence,
): Promise<string | undefined> {
  try {
    return await resolvePersistence(persistence).readIdToken(store);
  } catch (error) {
    logger.error({ error }, 'Unexpected error reading ID token');
    return undefined;
  }
}

/** Context for the {@link SESSION_EVENT.CLEARED} event raised by {@link clearSession}. */
export interface ClearSessionOptions {
  /** Why the session is going away. Omit to clear without raising an event. */
  trigger?: SessionClearedTrigger;
  /** Correlation id of the session being cleared, when the caller has it. */
  sid?: string;
  /**
   * Where the session lives. Defaults to the cookies; under server
   * persistence this is what deletes the record, which is the revocation
   * cookie persistence cannot do.
   */
  persistence?: SessionSecret | SessionPersistence;
}

/** Ends the session: deletes the cookies and, under server persistence, the record. */
export async function clearSession(
  store: CookieStore,
  options: ClearSessionOptions = {},
): Promise<void> {
  if (options.persistence) {
    await resolvePersistence(options.persistence).clear(store);
  } else {
    await clearSessionCookies(store);
  }

  if (options.trigger) {
    logSessionEvent(logger, {
      event: SESSION_EVENT.CLEARED,
      sid: options.sid,
      trigger: options.trigger,
    });
  }
}
