/**
 * Cookie helpers for Next.js authentication flows.
 *
 * IMPORTANT: These functions can ONLY be used in:
 * - Server Actions (functions marked with 'use server')
 * - Route Handlers (files in app/api directory)
 * - Server Components (async React components)
 *
 * They CANNOT be used in:
 * - Client Components (marked with 'use client')
 * - Middleware (use NextResponse.cookies instead)
 * - Edge Runtime without proper configuration
 */

import {
  ACCESS_TOKEN_COOKIE_NAME,
  COOKIE_INFO_BYTES,
  assertCookieWithinLimit,
  defaultSessionCookieOptions,
} from '@eventuras/fides-auth/cookies';
import type { CookieOptions } from '@eventuras/fides-auth/cookies';
import { Logger } from '@eventuras/logger';
import { cookies } from 'next/headers';

// Re-export the framework-agnostic cookie attributes, limits, and size guard from
// the core package so existing import sites keep working. This Next adapter only
// owns the actual cookie I/O (via next/headers); the values and the size check
// itself live in @eventuras/fides-auth/cookies.
export {
  COOKIE_INFO_BYTES,
  COOKIE_MAX_BYTES,
  CookieTooLargeError,
  ACCESS_TOKEN_COOKIE_NAME,
  defaultSessionCookieOptions,
  defaultOAuthCookieOptions,
  cookieByteSize,
  assertCookieWithinLimit,
} from '@eventuras/fides-auth/cookies';
export type { CookieOptions } from '@eventuras/fides-auth/cookies';

const logger = Logger.create({ namespace: 'fides-auth-next:cookies' });

/**
 * Sets a cookie with the given name and value.
 *
 * @param name - Cookie name
 * @param value - Cookie value
 * @param options - Cookie options (defaults to session cookie options)
 *
 * @example
 * ```ts
 * // In a server action or route handler
 * await setAuthCookie('session', encryptedJwt);
 *
 * // With custom options
 * await setAuthCookie('oauth_state', state, {
 *   maxAge: 60 * 10, // 10 minutes
 * });
 * ```
 */
export async function setAuthCookie(
  name: string,
  value: string,
  options: CookieOptions = defaultSessionCookieOptions
): Promise<void> {
  try {
    const cookieStore = await cookies();
    const cookieOptions = { ...defaultSessionCookieOptions, ...options };

    // Fail loudly above the browser per-cookie limit (the browser would otherwise
    // drop the cookie silently). The size check lives in the core package.
    const size = assertCookieWithinLimit(name, value);
    if (size >= COOKIE_INFO_BYTES) {
      logger.info({ cookieName: name, size }, 'Cookie approaching browser size limit');
    }

    cookieStore.set(name, value, cookieOptions);

    logger.debug({
      cookieName: name,
      maxAge: cookieOptions.maxAge,
      secure: cookieOptions.secure
    }, 'Cookie set successfully');
  } catch (error) {
    logger.error({ error, cookieName: name }, 'Failed to set cookie');
    throw error;
  }
}

/**
 * Gets a cookie value by name.
 *
 * @param name - Cookie name
 * @returns Cookie value or null if not found
 *
 * @example
 * ```ts
 * // In a server action or route handler
 * const sessionCookie = await getAuthCookie('session');
 * if (sessionCookie) {
 *   // Validate and use session
 * }
 * ```
 */
export async function getAuthCookie(name: string): Promise<string | null> {
  try {
    const cookieStore = await cookies();
    const cookie = cookieStore.get(name);

    if (!cookie?.value) {
      logger.debug({ cookieName: name }, 'Cookie not found');
      return null;
    }

    logger.debug({ cookieName: name }, 'Cookie retrieved');
    return cookie.value;
  } catch (error) {
    logger.error({ error, cookieName: name }, 'Failed to get cookie');
    return null;
  }
}

/**
 * Deletes a cookie by name.
 *
 * @param name - Cookie name to delete
 *
 * @example
 * ```ts
 * // In a server action or route handler
 * await deleteAuthCookie('session');
 * ```
 */
export async function deleteAuthCookie(name: string): Promise<void> {
  try {
    const cookieStore = await cookies();
    cookieStore.delete(name);

    logger.debug({ cookieName: name }, 'Cookie deleted successfully');
  } catch (error) {
    logger.error({ error, cookieName: name }, 'Failed to delete cookie');
    throw error;
  }
}

/**
 * Deletes multiple cookies at once.
 * Useful for cleaning up OAuth flow cookies.
 *
 * @param names - Array of cookie names to delete
 *
 * @example
 * ```ts
 * // Clean up OAuth cookies after callback
 * await deleteAuthCookies(['oauth_state', 'oauth_code_verifier', 'returnTo']);
 * ```
 */
export async function deleteAuthCookies(names: string[]): Promise<void> {
  try {
    const cookieStore = await cookies();

    for (const name of names) {
      cookieStore.delete(name);
    }

    logger.debug({ cookieNames: names }, 'Multiple cookies deleted successfully');
  } catch (error) {
    logger.error({ error, cookieNames: names }, 'Failed to delete cookies');
    throw error;
  }
}

/**
 * Sets the session cookie with proper security settings.
 * This is a convenience wrapper around setAuthCookie.
 *
 * @param encryptedJwt - The encrypted JWT session token
 * @param options - Optional cookie options (merged with defaults)
 *
 * @example
 * ```ts
 * const jwt = await createSession({ ... });
 * await setSessionCookie(jwt);
 * ```
 */
export async function setSessionCookie(
  encryptedJwt: string,
  options: Partial<CookieOptions> = {}
): Promise<void> {
  await setAuthCookie('session', encryptedJwt, {
    ...defaultSessionCookieOptions,
    ...options,
  });

  logger.info('Session cookie set');
}

/**
 * Sets the access-token cookie ("session_at") with session cookie settings.
 *
 * @param encryptedJwt - The encrypted JWT wrapping the access token
 * @param options - Optional cookie options (merged with session defaults)
 */
export async function setAccessTokenCookie(
  encryptedJwt: string,
  options: Partial<CookieOptions> = {}
): Promise<void> {
  await setAuthCookie(ACCESS_TOKEN_COOKIE_NAME, encryptedJwt, {
    ...defaultSessionCookieOptions,
    ...options,
  });
}

/**
 * Gets the access-token cookie ("session_at") value, or null if absent.
 */
export async function getAccessTokenCookie(): Promise<string | null> {
  return await getAuthCookie(ACCESS_TOKEN_COOKIE_NAME);
}

/**
 * Deletes the access-token cookie ("session_at").
 */
export async function deleteAccessTokenCookie(): Promise<void> {
  await deleteAuthCookie(ACCESS_TOKEN_COOKIE_NAME);
}

/**
 * Gets the current session cookie value.
 * Returns null if no session cookie exists.
 *
 * @returns Encrypted JWT session token or null
 *
 * @example
 * ```ts
 * const sessionToken = await getSessionCookie();
 * if (sessionToken) {
 *   const { status, session } = await validateSessionJwt(sessionToken);
 *   // ...
 * }
 * ```
 */
export async function getSessionCookie(): Promise<string | null> {
  return await getAuthCookie('session');
}

/**
 * Deletes the session cookie.
 * Use this when logging out or when session validation fails.
 *
 * @example
 * ```ts
 * await deleteSessionCookie();
 * redirect('/');
 * ```
 */
export async function deleteSessionCookie(): Promise<void> {
  await deleteAuthCookie('session');
  logger.info('Session cookie deleted');
}
