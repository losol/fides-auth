// server/oidc-login.ts
//
// Framework-agnostic OIDC login initiation. Builds PKCE parameters, seals them
// into a login transaction cookie, and redirects to the authorization endpoint.
// Uses the standard Request/Response, a CookieStore, and an optional rate-limit
// callback, so any server runtime can call it.

import { CookieTooLargeError } from '../cookies.js';
import { createLogger } from '../logger.js';
import { buildPKCEOptions, discoverAndBuildAuthorizationUrl } from '../oauth.js';
import type { OAuthConfig } from '../oauth-config.js';
import type { CookieStore } from './cookie-store.js';
import {
  createTransaction,
  persistTransaction,
  transactionCookieOptions,
} from './login-transaction.js';
import { assertSessionSecret, type SessionSecret } from './session-persistence.js';

const logger = createLogger({ namespace: 'fides-auth:server:oidc-login' });

export interface OidcLoginConfig {
  /** OAuth/OIDC configuration. */
  oauthConfig: OAuthConfig;

  /** Cookie store that receives the login transaction cookie. */
  cookies: CookieStore;

  /** Seals the login transaction. Must match the callback's. */
  secret: SessionSecret;

  /**
   * Optional rate-limit gate. When it resolves false, the handler responds 429.
   */
  rateLimit?: () => boolean | Promise<boolean>;

  /**
   * Validates and sanitizes the returnTo parameter, returning a safe path or null.
   * @default Only allows printable-ASCII paths starting with a single `/`.
   */
  validateReturnTo?: (rawReturnTo: string) => string | null;

  /**
   * Per-request authorization parameters, merged over `oauthConfig.authorizationParameters`.
   * Reserved keys throw: `state`, `code_challenge`, `code_challenge_method`, `redirect_uri`,
   * `client_id`, `response_type`, `request`, `request_uri` and `nonce`.
   */
  authorizationParameters?: (
    request: Request,
  ) => Record<string, string> | Promise<Record<string, string>>;
}

const defaultValidateReturnTo = (raw: string): string | null =>
  /^\/(?!\/)[\x20-\x7e]*$/.test(raw) ? raw : null;

/**
 * Handles OIDC login initiation: rate-limit, build PKCE, seal it into a login
 * transaction, and redirect to the authorization endpoint.
 */
export async function handleOidcLogin(
  request: Request,
  config: OidcLoginConfig,
): Promise<Response> {
  const { oauthConfig, cookies, rateLimit, validateReturnTo = defaultValidateReturnTo } = config;
  // Before discovery or PAR: a bad secret should fail without contacting the provider.
  assertSessionSecret(config.secret);

  if (rateLimit && !(await rateLimit())) {
    logger.warn('Rate limit exceeded');
    return new Response('Too many requests', { status: 429 });
  }

  const url = new URL(request.url);
  const rawReturnTo = url.searchParams.get('returnTo');
  const returnTo = rawReturnTo ? validateReturnTo(rawReturnTo) : null;

  const parameters = await config.authorizationParameters?.(request);
  const pkce = await buildPKCEOptions(oauthConfig, { parameters });
  const authorizationUrl = await discoverAndBuildAuthorizationUrl(oauthConfig, pkce);

  const transaction = createTransaction(pkce, { returnTo });
  const secret = config.secret;
  const cookieOptions = transactionCookieOptions(oauthConfig.redirect_uri);
  try {
    await persistTransaction(cookies, transaction, secret, cookieOptions);
  } catch (error) {
    // Too big for a cookie: still log in, just without the way back.
    if (!(error instanceof CookieTooLargeError) || !transaction.returnTo) throw error;
    logger.warn({ size: error.size }, 'Login transaction too large; dropped returnTo');
    await persistTransaction(cookies, { ...transaction, returnTo: undefined }, secret, cookieOptions);
  }

  logger.info('Redirecting to OIDC provider for login');

  return new Response(null, {
    status: 302,
    headers: { Location: authorizationUrl.toString() },
  });
}
