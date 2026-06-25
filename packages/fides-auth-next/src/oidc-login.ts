/**
 * OIDC login initiation for Next.js route handlers — a thin wrapper over the
 * framework-agnostic handler in `@eventuras/fides-auth/server`, wiring it to the
 * Next cookie store and the global GET rate limiter.
 */

import { handleOidcLogin as coreHandleOidcLogin } from '@eventuras/fides-auth/server';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';

import { nextCookieStore } from './cookie-store';
import { globalGETRateLimit } from './request';

export interface OidcLoginConfig {
  /** OAuth/OIDC configuration */
  oauthConfig: OAuthConfig;

  /**
   * Validates and sanitizes the returnTo parameter.
   * Should return a safe path or null to use the default.
   * @default Only allows relative paths starting with /
   */
  validateReturnTo?: (rawReturnTo: string) => string | null;
}

/**
 * Handles OIDC login initiation in a Next.js route handler.
 *
 * @example
 * ```ts
 * // In app/api/auth/login/route.ts
 * import { handleOidcLogin } from '@eventuras/fides-auth-next/oidc-login';
 *
 * export async function GET(request: Request) {
 *   return handleOidcLogin(request, { oauthConfig });
 * }
 * ```
 */
export async function handleOidcLogin(
  request: Request,
  config: OidcLoginConfig,
): Promise<Response> {
  return coreHandleOidcLogin(request, {
    oauthConfig: config.oauthConfig,
    validateReturnTo: config.validateReturnTo,
    cookies: await nextCookieStore(),
    rateLimit: globalGETRateLimit,
  });
}
