import { createEncryptedJWT, getSessionSecret } from '@eventuras/fides-auth/utils';
import {
  persistSession,
  readSession,
  refreshSessionInStore,
  clearSession,
} from '@eventuras/fides-auth/server';
import type { Session, CreateSessionOptions } from '@eventuras/fides-auth/types';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';
import { Logger } from '@eventuras/logger';
import { cache } from 'react';

import { nextCookieStore } from './cookie-store';

const logger = Logger.create({ namespace: 'fides-auth-next:session' });

/**
 * Creates an encrypted JWT containing session data.
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
 * @param _config - Unused; kept for backwards compatibility.
 * @returns Session object or null if no valid session exists.
 *
 * @example
 * ```ts
 * const session = await getCurrentSession();
 * if (session) console.log('User:', session.user);
 * ```
 */
export const getCurrentSession = cache(
  async (_config?: OAuthConfig): Promise<Session<any> | null> => {
    return readSession(await nextCookieStore(), getSessionSecret());
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
export async function clearCurrentSession(): Promise<void> {
  await clearSession(await nextCookieStore());
}
