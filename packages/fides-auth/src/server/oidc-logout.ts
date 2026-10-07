// server/oidc-logout.ts
//
// Framework-agnostic RP-initiated logout. Clearing only the local session cookie
// leaves the provider's session alive, so the next /authorize silently
// re-authenticates — this handler ends both.

import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import { buildOidcLogoutUrl } from '../oauth';
import { getSessionSecret } from '../utils';
import type { CookieStore } from './cookie-store';
import { clearSession, readIdToken, tryReadSession } from './session';
import type { SessionPersistence, SessionSecret } from './session-persistence';

const logger = createLogger({ namespace: 'fides-auth:server:oidc-logout' });

/**
 * Whether the request came from the application itself. POST alone is no defence:
 * a third-party page can auto-submit a form at this endpoint, and the response
 * clears the cookies whether or not the browser attached them.
 *
 * `Sec-Fetch-Site` is authoritative where the browser sends it. Otherwise fall back
 * to `Origin`. A request with neither is not a browser form post, so it is allowed.
 */
function isSameOrigin(request: Request, applicationUrl?: string): boolean {
  const site = request.headers.get('sec-fetch-site');
  if (site) {
    return site === 'same-origin' || site === 'none';
  }

  const origin = request.headers.get('origin');
  if (!origin) return true;

  try {
    return new URL(origin).origin === new URL(applicationUrl ?? request.url).origin;
  } catch {
    return false;
  }
}

export interface OidcLogoutConfig {
  /** OAuth/OIDC configuration. */
  oauthConfig: OAuthConfig;

  /** Cookie store holding the session cookies to read and then clear. */
  cookies: CookieStore;

  /** Post-logout redirect URI. Must be registered with the provider. */
  postLogoutRedirectUri: string;

  /** Session encryption secret for the default cookie persistence. Defaults to {@link getSessionSecret}. */
  secret?: SessionSecret;

  /** Where the session lives. Defaults to the cookies under `secret`; see `serverPersistence`. */
  persistence?: SessionPersistence;

  /** Optional rate-limit gate. When it resolves false, the handler responds 429. */
  rateLimit?: () => boolean | Promise<boolean>;

  /** Passed through as `state`; verifying it on the way back is the caller's job. */
  state?: string;

  /** `logout_hint`, when the provider documents one. */
  logoutHint?: string;

  /** Whether to send `client_id`. Default true — see `OidcLogoutOptions`. */
  includeClientId?: boolean;

  /**
   * Request methods that may trigger a logout. Defaults to POST only: on GET, any
   * third-party page can force a logout by navigating the browser.
   * @default ['POST']
   */
  allowedMethods?: string[];

  /**
   * Public application URL, used to check the `Origin` header behind a proxy where
   * the request URL carries the internal origin. Defaults to the request's own
   * origin.
   */
  applicationUrl?: string;

  /**
   * Where to send the user when logout is local-only (no end_session_endpoint).
   * @default postLogoutRedirectUri
   */
  fallbackRedirectUri?: string;
}

/**
 * Clears the session cookies and redirects to the provider's end-session endpoint
 * with `id_token_hint`. Local cookies are cleared even when the provider hop is
 * unavailable, so the user is always logged out of this application.
 */
export async function handleOidcLogout(
  request: Request,
  config: OidcLogoutConfig,
): Promise<Response> {
  const {
    oauthConfig,
    cookies,
    postLogoutRedirectUri,
    rateLimit,
    state,
    logoutHint,
    includeClientId,
    fallbackRedirectUri = postLogoutRedirectUri,
    allowedMethods = ['POST'],
    applicationUrl,
  } = config;
  const persistence = config.persistence ?? config.secret ?? getSessionSecret();

  if (!allowedMethods.includes(request.method)) {
    return new Response(null, {
      status: 405,
      headers: { Allow: allowedMethods.join(', ') },
    });
  }

  if (!isSameOrigin(request, applicationUrl)) {
    logger.warn(
      { origin: request.headers.get('origin'), site: request.headers.get('sec-fetch-site') },
      'Cross-origin logout request rejected',
    );
    return new Response('Forbidden', { status: 403 });
  }

  if (rateLimit && !(await rateLimit())) {
    logger.warn('Rate limit exceeded');
    return new Response('Too many requests', { status: 429 });
  }

  // Read before clearing. A session too broken to read still logs out fine,
  // and the hint matters most exactly then — so fall back to the raw ID token.
  // The sid is best-effort correlation, so the logout line joins the rest of
  // this session's events.
  const read = await tryReadSession(cookies, persistence);
  const idTokenHint =
    read.session?.tokens?.idToken ?? (await readIdToken(cookies, persistence));
  const sid = read.session?.sid;

  try {
    await clearSession(cookies, { trigger: 'logout', sid, persistence });
  } catch (error) {
    // Never redirect to the provider on a half-cleared local session — the user
    // would come back looking logged in.
    logger.error({ error }, 'Failed to clear session cookies');
    return new Response('Logout failed', { status: 500 });
  }

  const logoutUrl = await buildOidcLogoutUrl(oauthConfig, {
    postLogoutRedirectUri,
    idTokenHint,
    state,
    logoutHint,
    includeClientId,
  });

  if (!logoutUrl) {
    // Either the provider advertises no end_session_endpoint or discovery failed;
    // buildOidcLogoutUrl logs which. Local logout stands either way.
    logger.info(
      { issuer: oauthConfig.issuer },
      'No logout URL — local session cleared, provider session may persist',
    );
    return new Response(null, { status: 302, headers: { Location: fallbackRedirectUri } });
  }

  logger.info({ hasIdTokenHint: !!idTokenHint }, 'Redirecting to provider for logout');

  return new Response(null, { status: 302, headers: { Location: logoutUrl.toString() } });
}
