/**
 * OIDC login initiation for Next.js route handlers — a thin wrapper over the
 * framework-agnostic handler in `@eventuras/fides-auth/server`, wiring it to the
 * Next cookie store and the global GET rate limiter.
 */

import {
  handleOidcLogin as coreHandleOidcLogin,
  type OidcLoginConfig as CoreOidcLoginConfig,
  type SessionSecret,
} from '@eventuras/fides-auth/server';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';

import { nextCookieStore } from './cookie-store.js';
import { globalGETRateLimit } from './request.js';

export interface OidcLoginConfig {
  /** OAuth/OIDC configuration */
  oauthConfig: OAuthConfig;

  /** Seals the login transaction. Must match the callback's. */
  secret: SessionSecret;

  /**
   * Validates and sanitizes the returnTo parameter.
   * Should return a safe path or null to use the default.
   * @default Only allows relative paths starting with /
   */
  validateReturnTo?: (rawReturnTo: string) => string | null;

  /** Per-request authorization parameters, e.g. `prompt` or `login_hint`. Reserved keys throw. */
  authorizationParameters?: CoreOidcLoginConfig['authorizationParameters'];
}

/**
 * Handles OIDC login initiation in a Next.js route handler. `createFidesAuth`
 * returns this with `oauthConfig` and `secret` bound.
 *
 * @example
 * ```ts
 * // In app/api/auth/login/route.ts
 * import { handleOidcLogin } from '@eventuras/fides-auth-next/oidc-login';
 *
 * export async function GET(request: Request) {
 *   return handleOidcLogin(request, { oauthConfig, secret: process.env.SESSION_SECRET! });
 * }
 * ```
 */
export async function handleOidcLogin(
  request: Request,
  config: OidcLoginConfig,
): Promise<Response> {
  return coreHandleOidcLogin(request, {
    oauthConfig: config.oauthConfig,
    secret: config.secret,
    validateReturnTo: config.validateReturnTo,
    authorizationParameters: config.authorizationParameters,
    cookies: await nextCookieStore(),
    rateLimit: globalGETRateLimit,
  });
}
