/**
 * RP-initiated logout for Next.js route handlers — a thin wrapper over the
 * framework-agnostic handler in `@eventuras/fides-auth/server`, wiring it to the
 * Next cookie store and the global POST rate limiter.
 */

import { handleOidcLogout as coreHandleOidcLogout } from '@eventuras/fides-auth/server';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';

import { nextCookieStore } from './cookie-store';
import { globalPOSTRateLimit } from './request';

export interface OidcLogoutConfig {
  /** OAuth/OIDC configuration */
  oauthConfig: OAuthConfig;

  /**
   * URI the provider redirects back to after logout. Must be registered with the
   * provider as a post-logout redirect URI.
   */
  postLogoutRedirectUri: string;

  /** Opaque value echoed back on the post-logout redirect. */
  state?: string;

  /** `logout_hint`, when the provider documents one. */
  logoutHint?: string;

  /** Whether to send `client_id`. Default true. */
  includeClientId?: boolean;

  /** Request methods that may trigger a logout. @default ['POST'] */
  allowedMethods?: string[];

  /** Public application URL, used to check the `Origin` header behind a proxy. */
  applicationUrl?: string;

  /**
   * Where to send the user when the provider advertises no end_session_endpoint.
   * @default postLogoutRedirectUri
   */
  fallbackRedirectUri?: string;
}

/**
 * Handles logout in a Next.js route handler: clears the session cookies and
 * redirects to the provider's end-session endpoint with `id_token_hint`.
 *
 * @example
 * ```ts
 * // In app/api/auth/logout/route.ts
 * import { handleOidcLogout } from '@eventuras/fides-auth-next/oidc-logout';
 *
 * export async function POST(request: Request) {
 *   return handleOidcLogout(request, {
 *     oauthConfig,
 *     postLogoutRedirectUri: 'https://example.com/',
 *   });
 * }
 * ```
 */
export async function handleOidcLogout(
  request: Request,
  config: OidcLogoutConfig,
): Promise<Response> {
  return coreHandleOidcLogout(request, {
    oauthConfig: config.oauthConfig,
    postLogoutRedirectUri: config.postLogoutRedirectUri,
    state: config.state,
    logoutHint: config.logoutHint,
    includeClientId: config.includeClientId,
    fallbackRedirectUri: config.fallbackRedirectUri,
    allowedMethods: config.allowedMethods,
    applicationUrl: config.applicationUrl,
    cookies: await nextCookieStore(),
    rateLimit: globalPOSTRateLimit,
  });
}
