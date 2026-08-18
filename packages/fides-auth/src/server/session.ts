// server/session.ts
//
// Framework-agnostic session persistence over a {@link CookieStore}. The split
// encode/decode lives in `../session-cookies`; these helpers wire it to a cookie
// store, apply the per-cookie size guard, and own the refresh flow — with no
// dependency on any framework's cookie API.

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
import { getOAuthErrorLogContext } from '../oauth-logging';
import { refreshSession } from '../session-refresh';
import {
  decodeIdTokenCookie,
  decodeSessionCookies,
  encodeSessionCookies,
} from '../session-cookies';
import type { CreateSessionOptions, Session } from '../types';
import type { CookieStore } from './cookie-store';

const logger = createLogger({ namespace: 'fides-auth:server:session' });

type Secret = string | Uint8Array;

/** Applies the browser size guard to one cookie value; logs as it nears the limit. */
function checkSize(name: string, value: string): void {
  // Fail loudly above the browser per-cookie limit (the browser would otherwise
  // drop the cookie silently, producing a broken login).
  const size = assertCookieWithinLimit(name, value);
  if (size >= COOKIE_INFO_BYTES) {
    logger.info({ cookieName: name, size }, 'Cookie approaching browser size limit');
  }
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
  for (const [name, value] of values) {
    if (value) checkSize(name, value);
  }

  for (const [name, value] of values) {
    if (value) {
      await store.set(name, value, defaultSessionCookieOptions);
    } else {
      await store.delete(name);
    }
  }

  return encoded.session;
}

/**
 * Reads and reassembles the current session from the cookie store, or null when
 * there is none. Decode/validation rules live in {@link decodeSessionCookies};
 * the returned session may carry an expired access token.
 */
export async function readSession(store: CookieStore, secret: Secret): Promise<Session | null> {
  try {
    return await decodeSessionCookies(
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
    return null;
  }
}

/**
 * Refreshes the stored session using its refresh token and persists the result.
 * Returns the updated session, or null when there is nothing to refresh or the
 * refresh token is no longer valid.
 */
export async function refreshSessionInStore(
  store: CookieStore,
  config: OAuthConfig,
  secret: Secret,
  options: CreateSessionOptions = {},
): Promise<Session | null> {
  try {
    // readSession also returns sessions with expired access tokens — exactly
    // what refresh is for.
    const current = await readSession(store, secret);

    if (!current) {
      logger.warn('No current session to refresh');
      return null;
    }
    if (!current.tokens?.refreshToken) {
      logger.error('Current session has no refresh token');
      return null;
    }

    const updated = await refreshSession(current, config, options);
    if (!updated) {
      logger.error('Session refresh returned null');
      return null;
    }

    await persistSession(store, updated, secret);
    return updated;
  } catch (error) {
    // invalid_grant is expected during logout/session expiry — log it quietly.
    // getOAuthErrorLogContext unwraps errors (fields may live on `cause`), which a
    // direct property read would miss and misclassify.
    const errorContext = getOAuthErrorLogContext(error);
    const isInvalidGrant =
      errorContext.code === 'OAUTH_RESPONSE_BODY_ERROR' && errorContext.error === 'invalid_grant';

    if (isInvalidGrant) {
      logger.info('Session refresh failed - refresh token expired or invalid');
    } else {
      logger.error({ error: errorContext }, 'Failed to refresh session');
    }
    return null;
  }
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

/** Deletes all session cookies. */
export async function clearSession(store: CookieStore): Promise<void> {
  await store.delete(SESSION_COOKIE_NAME);
  await store.delete(ACCESS_TOKEN_COOKIE_NAME);
  await store.delete(ID_TOKEN_COOKIE_NAME);
}
