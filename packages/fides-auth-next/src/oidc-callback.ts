/**
 * OIDC callback handler for Next.js route handlers — a thin wrapper over the
 * framework-agnostic handler in `@eventuras/fides-auth/server`, wiring it to the
 * Next cookie store and the global GET rate limiter.
 */

import {
  handleOidcCallback as coreHandleOidcCallback,
  type SessionPersistence,
  type SessionSecret,
} from '@eventuras/fides-auth/server';
import type { MapSession, OAuthConfig } from '@eventuras/fides-auth/oauth';

import { nextCookieStore } from './cookie-store';
import { globalGETRateLimit } from './request';

export interface OidcCallbackConfig {
  /** OAuth/OIDC configuration (issuer, clientId, clientSecret, redirect_uri, scope) */
  oauthConfig: OAuthConfig;

  /** Opens the login transaction and encrypts the session. Must match the login's. */
  secret: SessionSecret;

  /** Where the session lives. Defaults to the cookies under `secret`; see `serverPersistence`. */
  persistence?: SessionPersistence;

  /** Public application URL (used to reconstruct the callback URL and validate redirects) */
  applicationUrl: string;

  /**
   * Name of the ID token claim that contains user roles.
   * @default 'roles'
   */
  rolesClaim?: string;

  /** Changes the session before it is stored, e.g. to add `data`. See {@link MapSession}. */
  mapSession?: MapSession;

  /**
   * Default path to redirect to after login if no returnTo cookie is set.
   * @default '/'
   */
  defaultRedirectPath?: string;

  /**
   * Optional function to validate the returnTo path.
   * If not provided, only same-origin paths are allowed.
   */
  validateReturnTo?: (path: string) => boolean;

  /**
   * Reserved for backwards compatibility. Currently not applied — the session
   * cookie lifetime is fixed by the default cookie options.
   */
  sessionDurationDays?: number;
}

/**
 * Handles the OIDC callback in a Next.js route handler. `createFidesAuth` returns
 * this with `oauthConfig` and `secret` bound.
 *
 * @example
 * ```ts
 * // In app/api/auth/callback/oidc/route.ts
 * import { handleOidcCallback } from '@eventuras/fides-auth-next/oidc-callback';
 *
 * export async function GET(request: Request) {
 *   return handleOidcCallback(request, {
 *     oauthConfig,
 *     secret: process.env.SESSION_SECRET!,
 *     applicationUrl: 'https://example.com',
 *     rolesClaim: 'roles',
 *   });
 * }
 * ```
 */
export async function handleOidcCallback(
  request: Request,
  config: OidcCallbackConfig,
): Promise<Response> {
  // Map explicitly rather than spreading: sessionDurationDays is accepted for
  // backwards compatibility but the core handler doesn't take it.
  return coreHandleOidcCallback(request, {
    oauthConfig: config.oauthConfig,
    secret: config.secret,
    persistence: config.persistence,
    applicationUrl: config.applicationUrl,
    rolesClaim: config.rolesClaim,
    mapSession: config.mapSession,
    defaultRedirectPath: config.defaultRedirectPath,
    validateReturnTo: config.validateReturnTo,
    cookies: await nextCookieStore(),
    rateLimit: globalGETRateLimit,
  });
}
