// server/session.ts
//
// Framework-agnostic session persistence over a {@link CookieStore}. The split
// encode/decode lives in `../session-cookies`; these helpers wire it to a cookie
// store, apply the per-cookie size guard, and own the refresh flow — with no
// dependency on any framework's cookie API.

import {
  ACCESS_TOKEN_COOKIE_NAME,
  COOKIE_INFO_BYTES,
  SESSION_COOKIE_NAME,
  assertCookieWithinLimit,
  defaultSessionCookieOptions,
} from '../cookies';
import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import { getOAuthErrorLogContext } from '../oauth-logging';
import { refreshSession } from '../session-refresh';
import { decodeSessionCookies, encodeSessionCookies } from '../session-cookies';
import type { CreateSessionOptions, Session } from '../types';
import type { CookieStore } from './cookie-store';

const logger = createLogger({ namespace: 'fides-auth:server:session' });

type Secret = string | Uint8Array;

/** Writes a cookie after the browser size guard; logs as it nears the limit. */
async function writeChecked(store: CookieStore, name: string, value: string): Promise<void> {
  // Fail loudly above the browser per-cookie limit (the browser would otherwise
  // drop the cookie silently, producing a broken login).
  const size = assertCookieWithinLimit(name, value);
  if (size >= COOKIE_INFO_BYTES) {
    logger.info({ cookieName: name, size }, 'Cookie approaching browser size limit');
  }
  await store.set(name, value, defaultSessionCookieOptions);
}

/**
 * Encrypts a session and writes it across the "session" and "session_at" cookies,
 * clearing a stale access-token cookie when the session carries no access token.
 *
 * @returns The encrypted JWT stored in the main "session" cookie.
 */
export async function persistSession(
  store: CookieStore,
  session: Session,
  secret: Secret,
): Promise<string> {
  const encoded = await encodeSessionCookies(session, secret);

  await writeChecked(store, SESSION_COOKIE_NAME, encoded.session);
  if (encoded.accessToken) {
    await writeChecked(store, ACCESS_TOKEN_COOKIE_NAME, encoded.accessToken);
  } else {
    await store.delete(ACCESS_TOKEN_COOKIE_NAME);
  }

  return encoded.session;
}

/**
 * Reads and reassembles the current session from the cookie store, or null when
 * there is no valid session. All the split/expiry/legacy handling lives in
 * {@link decodeSessionCookies}; this just supplies the two cookie values.
 */
export async function readSession(store: CookieStore, secret: Secret): Promise<Session | null> {
  try {
    return await decodeSessionCookies(
      {
        session: (await store.get(SESSION_COOKIE_NAME)) ?? null,
        accessToken: (await store.get(ACCESS_TOKEN_COOKIE_NAME)) ?? null,
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

/** Deletes both session cookies. */
export async function clearSession(store: CookieStore): Promise<void> {
  await store.delete(SESSION_COOKIE_NAME);
  await store.delete(ACCESS_TOKEN_COOKIE_NAME);
}
