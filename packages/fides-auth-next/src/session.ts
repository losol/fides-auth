import { createEncryptedJWT, getSessionSecret } from '@eventuras/fides-auth/utils';
import {
  persistSession,
  readSession,
  tryReadSession,
  refreshSessionInStore,
  tryRefreshSessionInStore,
  clearSession,
  type ClearSessionOptions,
  type ReadSessionResult,
  type RefreshSessionResult,
} from '@eventuras/fides-auth/server';
import type { Session, CreateSessionOptions } from '@eventuras/fides-auth/types';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';
import { createLogger } from '@eventuras/fides-auth/logger';
import { cache } from 'react';

import { nextCookieStore } from './cookie-store';

const logger = createLogger({ namespace: 'fides-auth-next:session' });

// The result shapes the try* helpers below return, so consumers can name them
// without reaching past this package.
export type { ClearSessionOptions, ReadSessionResult, RefreshSessionResult };

/**
 * Creates an encrypted JWT containing session data.
 *
 * Pre-split API: this serializes the whole session, raw tokens included, into one
 * value. Prefer {@link createAndPersistSession}, which splits the large JWTs across
 * cookies instead of spending one cookie's byte budget on all of them.
 *
 * @param session - Session data (tokens, user, etc.)
 * @param options - Configuration options (e.g., sessionDurationDays)
 * @returns Encrypted JWT string
 */
export async function createSession<TData = Record<string, unknown>>(
  session: Session<TData>,
  options: CreateSessionOptions = {}
): Promise<string> {
  const { sessionDurationDays = 7 } = options;
  try {
    const jwt = await createEncryptedJWT({ ...session }, getSessionSecret());
    logger.info({ sessionDurationDays }, 'Session created successfully');
    return jwt;
  } catch (error) {
    logger.error({ error }, 'Failed to create session');
    throw error;
  }
}

/**
 * Retrieves the current session from cookies, if any. Wraps the framework-
 * agnostic {@link readSession} with React's `cache` so repeated calls within one
 * server render share a single read.
 *
 * The session may carry an expired access token — check `accessTokenExpires`
 * before using it, or refresh via `refreshCurrentSession`.
 *
 * @param _config - Unused; kept for backwards compatibility.
 * @returns Session object or null if no session exists.
 *
 * @example
 * ```ts
 * const session = await getCurrentSession();
 * if (session) console.log('User:', session.user);
 * ```
 */
export const getCurrentSession = cache(
  async (_config?: OAuthConfig): Promise<Session<any> | null> => {
    return (await tryGetCurrentSession()).session;
  },
);

/**
 * Reads the current session and, when there isn't one, says why.
 *
 * The reason comes from the package-wide vocabulary, so a proxy or a status
 * route logs the same word for the same situation that the heartbeat endpoint
 * logs — which is the point of having a vocabulary at all. Cached per render
 * like {@link getCurrentSession}, and shared with it, so asking for the reason
 * costs no extra decrypt.
 *
 * @example
 * ```ts
 * import {
 *   SESSION_EVENT,
 *   createLogger,
 *   logSessionEvent,
 *   tryGetCurrentSession,
 * } from '@eventuras/fides-auth-next';
 * import { redirect } from 'next/navigation';
 *
 * const logger = createLogger({ namespace: 'my-app:proxy' });
 *
 * const { session, reason } = await tryGetCurrentSession();
 * if (!session) {
 *   logSessionEvent(logger, { event: SESSION_EVENT.REJECTED, reason, source: 'proxy' });
 *   redirect('/login');
 * }
 * ```
 */
export const tryGetCurrentSession = cache(
  async (): Promise<ReadSessionResult> => {
    return tryReadSession(await nextCookieStore(), getSessionSecret());
  },
);

/**
 * Refreshes the current session using its refresh token and updates the cookies.
 *
 * @param config - OAuth configuration
 * @param options - Session creation options
 * @returns Updated session or null if refresh failed
 *
 * @example
 * ```ts
 * const updated = await refreshCurrentSession(oauthConfig);
 * if (!updated) redirect('/login');
 * ```
 */
export async function refreshCurrentSession(
  config: OAuthConfig,
  options: CreateSessionOptions = {}
): Promise<Session | null> {
  return refreshSessionInStore(await nextCookieStore(), config, getSessionSecret(), options);
}

/**
 * Refreshes the current session and, on failure, says why.
 *
 * Prefer this over {@link refreshCurrentSession} anywhere the answer decides
 * whether the user stays logged in: a bare null cannot tell "the provider says
 * this refresh token is dead" apart from "we could not reach the provider", and
 * ending a session on the second is how a provider blip becomes a logout.
 *
 * @example
 * ```ts
 * const result = await tryRefreshCurrentSession(oauthConfig);
 * if (!result.ok && result.cause === 'invalid_grant') redirect('/login');
 * // transport / idp_error: keep the session and retry.
 * ```
 */
export async function tryRefreshCurrentSession(
  config: OAuthConfig,
  options: CreateSessionOptions = {}
): Promise<RefreshSessionResult> {
  return tryRefreshSessionInStore(await nextCookieStore(), config, getSessionSecret(), options);
}

/**
 * Creates and persists a new session across the session/session_at cookies.
 *
 * @param session - Session data
 * @param _options - Session creation options (reserved; not currently applied)
 * @returns The encrypted JWT stored in the main "session" cookie.
 *
 * @example
 * ```ts
 * await createAndPersistSession({
 *   tokens: { accessToken: tokens.access_token, refreshToken: tokens.refresh_token },
 *   user: { name: 'John Doe', email: 'john@example.com' },
 * });
 * ```
 */
export async function createAndPersistSession(
  session: Session,
  _options: CreateSessionOptions = {}
): Promise<string> {
  return persistSession(await nextCookieStore(), session, getSessionSecret());
}

/**
 * Clears the current session by deleting the session cookies.
 *
 * @example
 * ```ts
 * await clearCurrentSession();
 * redirect('/');
 * ```
 */
export async function clearCurrentSession(
  options: ClearSessionOptions = {},
): Promise<void> {
  // Defaults to `logout` because that is what this function is for; pass a
  // trigger explicitly when clearing for some other reason. The sid comes from
  // the per-render cache, so correlating the logout costs nothing extra.
  const sid = options.sid ?? (await tryGetCurrentSession()).session?.sid;
  await clearSession(await nextCookieStore(), {
    trigger: options.trigger ?? 'logout',
    sid,
  });
}
