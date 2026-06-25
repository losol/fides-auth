// server/oidc-callback.ts
//
// Framework-agnostic OIDC callback handler. Orchestrates the OIDC concerns —
// rate limit, PKCE cookie read, code exchange, session persistence, safe redirect
// — over the standard Request/Response and a CookieStore, delegating the protocol
// to the core oauth module and persistence to the server session helpers.

import { CookieTooLargeError } from '../cookies';
import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import {
  buildSessionFromTokens,
  exchangeAuthorizationCode,
  validateReturnUrl,
} from '../oauth';
import { getSessionSecret } from '../utils';
import type { CookieStore } from './cookie-store';
import { persistSession } from './session';

const logger = createLogger({ namespace: 'fides-auth:server:oidc-callback' });

export interface OidcCallbackConfig {
  /** OAuth/OIDC configuration. */
  oauthConfig: OAuthConfig;

  /** Public application URL (used to reconstruct the callback URL and validate redirects). */
  applicationUrl: string;

  /** Cookie store holding the PKCE state and receiving the session cookies. */
  cookies: CookieStore;

  /** Optional rate-limit gate. When it resolves false, the handler responds 429. */
  rateLimit?: () => boolean | Promise<boolean>;

  /** Session encryption secret. Defaults to {@link getSessionSecret}. */
  secret?: string | Uint8Array;

  /**
   * Name of the ID token claim that contains user roles.
   * @default 'roles'
   */
  rolesClaim?: string;

  /**
   * Default path to redirect to after login if no returnTo cookie is set.
   * @default '/'
   */
  defaultRedirectPath?: string;

  /**
   * Optional validator for the returnTo path. If omitted, only same-origin paths
   * are allowed.
   */
  validateReturnTo?: (path: string) => boolean;
}

/**
 * Handles the OIDC callback: rate-limit, exchange the code for tokens, persist the
 * session across the cookie store, and redirect to a validated returnTo.
 */
export async function handleOidcCallback(
  request: Request,
  config: OidcCallbackConfig,
): Promise<Response> {
  const {
    oauthConfig,
    applicationUrl,
    cookies,
    rateLimit,
    secret = getSessionSecret(),
    rolesClaim = 'roles',
    defaultRedirectPath = '/',
    validateReturnTo,
  } = config;

  if (rateLimit && !(await rateLimit())) {
    logger.warn('Rate limit exceeded');
    return new Response('Too many requests', { status: 429 });
  }

  try {
    // Reconstruct the public callback URL. Behind a TLS-terminating proxy
    // applicationUrl is just the origin ("/"), and the token-exchange redirect_uri
    // must match the callback path used at authorize — so keep the request path.
    const currentUrl = new URL(request.url);
    const publicUrl = new URL(applicationUrl);
    publicUrl.pathname = currentUrl.pathname;
    publicUrl.search = currentUrl.search;

    const storedState = await cookies.get('oauth_state');
    const storedCodeVerifier = await cookies.get('oauth_code_verifier');

    if (!storedState || !storedCodeVerifier) {
      logger.warn('Missing state or code verifier');
      return new Response('Please restart the login process.', { status: 400 });
    }

    const tokens = await exchangeAuthorizationCode(
      oauthConfig,
      publicUrl,
      storedCodeVerifier,
      storedState,
    );

    // Build the session and persist it (split across session/session_at).
    const session = buildSessionFromTokens(tokens, rolesClaim);
    await persistSession(cookies, session, secret);

    // Clean up PKCE & returnTo cookies (read returnTo first).
    const returnTo = await cookies.get('returnTo');
    await cookies.delete('oauth_state');
    await cookies.delete('oauth_code_verifier');
    await cookies.delete('returnTo');

    const redirectUrl = validateReturnUrl(
      returnTo ?? null,
      applicationUrl,
      defaultRedirectPath,
      validateReturnTo,
    );
    redirectUrl.searchParams.set('login', 'success');

    logger.info({ redirectUrl: redirectUrl.toString() }, 'Login successful, redirecting');

    return new Response(null, {
      status: 302,
      headers: { Location: redirectUrl.toString() },
    });
  } catch (error) {
    // The session was too large for a cookie — surface this distinctly instead of
    // hiding it in a generic 500, so it's diagnosable in production.
    if (error instanceof CookieTooLargeError) {
      logger.error(
        { error, cookieName: error.cookieName, size: error.size },
        'Session cookie too large to store',
      );
      return new Response('The session is too large to store. Please contact support.', {
        status: 431,
      });
    }

    logger.error({ error }, 'OIDC callback error');
    return new Response('An unexpected error occurred. Please restart the login process.', {
      status: 500,
    });
  }
}
