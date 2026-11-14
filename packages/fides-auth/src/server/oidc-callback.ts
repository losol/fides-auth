// server/oidc-callback.ts
//
// Framework-agnostic OIDC callback handler. Orchestrates the OIDC concerns —
// rate limit, login transaction check, code exchange, session persistence, safe
// redirect — over the standard Request/Response and a CookieStore, delegating the
// protocol to the core oauth module and persistence to the server session helpers.

import { CookieTooLargeError } from '../shared/cookies.js';
import { createLogger } from '../shared/logger.js';
import { buildSessionFromTokens, type MapSession } from '../session/build.js';
import { exchangeAuthorizationCode } from '../protocol/code-exchange.js';
import { validateReturnUrl } from './return-to.js';
import type { OAuthConfig } from '../protocol/config.js';
import { SESSION_EVENT } from '../shared/session-events.js';
import type { CookieStore } from './cookie-store.js';
import {
  CallbackValidationError,
  clearTransaction,
  readTransaction,
  transactionCookieOptions,
  validateCallback,
} from './login-transaction.js';
import { persistSession } from './session.js';
import {
  assertSessionSecret,
  type SessionPersistence,
  type SessionSecret,
} from './session-persistence.js';

const logger = createLogger({ namespace: 'fides-auth:server:oidc-callback' });

// Registered OAuth/OIDC error codes are snake_case; nothing else is echoed.
const IDP_ERROR_CODE = /^[a-z0-9_]{1,64}$/;

export interface OidcCallbackConfig {
  /** OAuth/OIDC configuration. */
  oauthConfig: OAuthConfig;

  /** Public application URL (used to reconstruct the callback URL and validate redirects). */
  applicationUrl: string;

  /** Cookie store holding the login transaction and receiving the session cookies. */
  cookies: CookieStore;

  /** Optional rate-limit gate. When it resolves false, the handler responds 429. */
  rateLimit?: () => boolean | Promise<boolean>;

  /**
   * Opens the login transaction (must match `handleOidcLogin`'s) and encrypts the
   * default cookie persistence. Required even with `persistence`.
   */
  secret: SessionSecret;

  /** Where the session lives. Defaults to the cookies under `secret`; see `serverPersistence`. */
  persistence?: SessionPersistence;

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
    secret,
    rateLimit,
    rolesClaim = 'roles',
    mapSession,
    defaultRedirectPath = '/',
    validateReturnTo,
  } = config;
  // Up front, so a bad secret fails before the transaction is read or the code exchanged.
  assertSessionSecret(secret);
  const persistence = config.persistence ?? secret;
  const txCookie = transactionCookieOptions(oauthConfig.redirect_uri);

  if (rateLimit && !(await rateLimit())) {
    logger.warn('Rate limit exceeded');
    return new Response('Too many requests', { status: 429 });
  }

  const currentUrl = new URL(request.url);
  const state = currentUrl.searchParams.get('state');
  const idpError = currentUrl.searchParams.get('error') ?? undefined;

  // A cancel after the login ended still redirects, but with a fixed code:
  // without a live transaction nothing in the query is trusted.
  const loginEnded = (): Response =>
    idpError === undefined
      ? new Response('Please restart the login process.', { status: 400 })
      : loginErrorRedirect(applicationUrl, defaultRedirectPath, 'login_expired');

  try {
    // Reconstruct the public callback URL. Behind a TLS-terminating proxy
    // applicationUrl is just the origin ("/"), and the token-exchange redirect_uri
    // must match the callback path used at authorize — so keep the request path.
    const publicUrl = new URL(applicationUrl);
    publicUrl.pathname = currentUrl.pathname;
    publicUrl.search = currentUrl.search;

    const transaction = state ? await readTransaction(cookies, state, secret, txCookie) : null;
    if (!transaction) {
      logger.warn({ error: idpError }, 'Missing login transaction');
      return loginEnded();
    }

    validateCallback(currentUrl.searchParams, transaction);

    const tokens = await exchangeAuthorizationCode(
      oauthConfig,
      publicUrl,
      transaction.codeVerifier,
      transaction.state,
    );

    // Build the session and persist it (split across session/session_at).
    // persistSession raises session.created — it is the only layer that knows
    // what the session cost in cookie bytes, and a login that comes back without
    // a refresh token (no offline_access) is visible there on day one.
    const session = buildSessionFromTokens(tokens, { rolesClaim, mapSession });
    await persistSession(cookies, session, persistence, { event: SESSION_EVENT.CREATED });

    const redirectUrl = validateReturnUrl(
      transaction.returnTo ?? null,
      applicationUrl,
      defaultRedirectPath,
      validateReturnTo,
    );
    redirectUrl.searchParams.set('login', 'success');

    logger.info(
      { sid: session.sid, redirectUrl: redirectUrl.toString() },
      'Login successful, redirecting',
    );

    return new Response(null, {
      status: 302,
      headers: { Location: redirectUrl.toString() },
    });
  } catch (error) {
    if (error instanceof CallbackValidationError) {
      // A denied or cancelled login: send the user home, not to an error page.
      if (error.reason === 'idp_error') {
        logger.warn(
          {
            reason: error.reason,
            error: error.idpError,
            errorDescription: error.idpErrorDescription,
          },
          'Identity provider returned an error',
        );
        const code = error.idpError ?? '';
        return loginErrorRedirect(
          applicationUrl,
          defaultRedirectPath,
          IDP_ERROR_CODE.test(code) ? code : 'idp_error',
        );
      }
      logger.warn({ reason: error.reason, error: idpError }, 'Rejected OIDC callback');
      return error.reason === 'transaction_expired'
        ? loginEnded()
        : new Response('Please restart the login process.', { status: 400 });
    }

    // The session was too large for a cookie — surface this distinctly instead of
    // hiding it in a generic 500, so it's diagnosable in production. Server
    // persistence is the fix; see docs/server-sessions.md.
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
  } finally {
    // The login transaction is spent whatever the outcome.
    if (state) await clearTransaction(cookies, state, secret, txCookie);
  }
}

/** Redirects to the default path with `login=error` and a safe error code, never a description. */
function loginErrorRedirect(
  applicationUrl: string,
  defaultRedirectPath: string,
  code: string,
): Response {
  const redirectUrl = new URL(defaultRedirectPath, applicationUrl);
  redirectUrl.searchParams.set('login', 'error');
  redirectUrl.searchParams.set('error', code);
  return new Response(null, { status: 302, headers: { Location: redirectUrl.toString() } });
}
