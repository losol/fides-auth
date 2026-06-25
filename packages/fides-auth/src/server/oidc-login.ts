// server/oidc-login.ts
//
// Framework-agnostic OIDC login initiation. Builds PKCE parameters, stores them
// in the cookie store, and redirects to the provider's authorization endpoint.
// Uses the standard Request/Response, a CookieStore, and an optional rate-limit
// callback, so any server runtime can call it.

import { defaultOAuthCookieOptions } from '../cookies';
import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import { buildPKCEOptions, discoverAndBuildAuthorizationUrl } from '../oauth';
import type { CookieStore } from './cookie-store';

const logger = createLogger({ namespace: 'fides-auth:server:oidc-login' });

export interface OidcLoginConfig {
  /** OAuth/OIDC configuration. */
  oauthConfig: OAuthConfig;

  /** Cookie store used to persist the PKCE state. */
  cookies: CookieStore;

  /**
   * Optional rate-limit gate. When it resolves false, the handler responds 429.
   */
  rateLimit?: () => boolean | Promise<boolean>;

  /**
   * Validates and sanitizes the returnTo parameter, returning a safe path or null.
   * @default Only allows relative paths starting with a single `/`.
   */
  validateReturnTo?: (rawReturnTo: string) => string | null;
}

const defaultValidateReturnTo = (raw: string): string | null =>
  /^\/(?!\/)/.test(raw) ? raw : null;

/**
 * Handles OIDC login initiation: rate-limit, build PKCE, persist it, and redirect
 * to the authorization endpoint.
 */
export async function handleOidcLogin(
  request: Request,
  config: OidcLoginConfig,
): Promise<Response> {
  const { oauthConfig, cookies, rateLimit, validateReturnTo = defaultValidateReturnTo } = config;

  if (rateLimit && !(await rateLimit())) {
    logger.warn('Rate limit exceeded');
    return new Response('Too many requests', { status: 429 });
  }

  const url = new URL(request.url);
  const rawReturnTo = url.searchParams.get('returnTo');
  const returnTo = rawReturnTo ? validateReturnTo(rawReturnTo) : null;

  const pkce = await buildPKCEOptions(oauthConfig);
  const authorizationUrl = await discoverAndBuildAuthorizationUrl(oauthConfig, pkce);

  logger.info('Redirecting to OIDC provider for login');

  await cookies.set('oauth_state', pkce.state, defaultOAuthCookieOptions);
  await cookies.set('oauth_code_verifier', pkce.code_verifier, defaultOAuthCookieOptions);
  if (returnTo) {
    await cookies.set('returnTo', returnTo, defaultOAuthCookieOptions);
  } else {
    // Clear any stale returnTo from an earlier, abandoned login so this one's
    // post-login redirect is deterministic rather than inheriting a past path.
    await cookies.delete('returnTo');
  }

  return new Response(null, {
    status: 302,
    headers: { Location: authorizationUrl.toString() },
  });
}
