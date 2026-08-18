import { decodeJwt } from 'jose';

import * as openid from 'openid-client';

import { createLogger } from './logger';
import { getOAuthErrorLogContext } from './oauth-logging';
import { newSessionId } from './session-events';
import type { Session } from './types';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

// Re-export commonly used types from openid-client for convenience
export type { Configuration, TokenEndpointResponse } from 'openid-client';

/** Default OIDC scope requesting user identity, profile, email, and offline access. */
export const defaultScope = 'openid profile email offline_access';

/** Configuration for server-side OAuth / OIDC flows. */
export type OAuthConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirect_uri: string;
  scope: string;
  /**
   * Opt in to Pushed Authorization Requests (RFC 9126) when the provider
   * supports it. When true, authorization parameters are posted to the
   * provider's PAR endpoint ahead of the redirect, and only `client_id` +
   * `request_uri` travel through the user-agent. The provider must advertise
   * `pushed_authorization_request_endpoint` in its discovery metadata.
   */
  usePar?: boolean;
};

/**
 * Refreshes an access token using a refresh token grant.
 *
 * @param oAuthConfig - OAuth configuration for the identity provider
 * @param refreshToken - The refresh token to exchange
 * @returns Token endpoint response containing new access and refresh tokens
 */
export async function refreshAccessToken(
  oAuthConfig: OAuthConfig,
  refreshToken: string,
): Promise<openid.TokenEndpointResponse> {
  logger.debug({ issuer: oAuthConfig.issuer }, 'Starting token refresh');

  try {
    const config = await openid.discovery(
      new URL(oAuthConfig.issuer),
      oAuthConfig.clientId,
      oAuthConfig.clientSecret,
      openid.ClientSecretPost(oAuthConfig.clientSecret),
    );

    const tokens = await openid.refreshTokenGrant(
      config,
      refreshToken,
      {
        scope: oAuthConfig.scope,
      },
    );

    logger.info({
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: tokens.expires_in
    }, 'Token refresh successful');

    return tokens;
  } catch (error) {
    const errorContext = getOAuthErrorLogContext(error);
    const isInvalidGrant =
      errorContext.code === 'OAUTH_RESPONSE_BODY_ERROR' && errorContext.error === 'invalid_grant';

    if (isInvalidGrant) {
      // Most often the refresh token has expired - log at info level
      logger.info(
        { ...errorContext, issuer: oAuthConfig.issuer },
        'Token refresh failed - refresh token expired or invalid',
      );
    } else {
      // Unexpected error - log at error level
      logger.error({ error, issuer: oAuthConfig.issuer }, 'Token refresh failed');
    }

    throw error;
  }
}

/** PKCE parameters generated for an authorization request. */
export interface PKCEOptions {
  code_verifier: string;
  code_challenge: string;
  state: string;
  parameters: Record<string, string>;
}

/**
 * Creates PKCE parameters for an OAuth flow.
 *
 * @param config - OAuthConfig configuration including the redirect URI and scope.
 * @returns A promise that resolves to an object containing:
 *  - code_verifier: The randomly generated PKCE code verifier.
 *  - code_challenge: The derived PKCE code challenge.
 *  - state: A random state to protect against CSRF.
 *  - parameters: A Record<string,string> with the assembled parameters.
 */
export async function buildPKCEOptions(config: OAuthConfig): Promise<PKCEOptions> {
  const code_verifier = openid.randomPKCECodeVerifier();
  const code_challenge = await openid.calculatePKCECodeChallenge(code_verifier);
  const state = openid.randomState();

  const parameters: Record<string, string> = {
    redirect_uri: config.redirect_uri,
    scope: config.scope ?? defaultScope,
    code_challenge,
    code_challenge_method: 'S256',
    state,
  };

  logger.info(
    { redirectUri: config.redirect_uri, scope: parameters.scope },
    'PKCE parameters generated'
  );

  return { code_verifier, code_challenge, state, parameters };
}

/**
 * Builds an authorization URL with PKCE parameters.
 *
 * @param config - Discovered OpenID Configuration (use openid.discovery() to obtain)
 * @param pkceOptions - The PKCE options (e.g., code challenge, state, parameters)
 * @returns A Promise that resolves to the authorization URL
 */
export async function buildAuthorizationUrl(
  config: openid.Configuration,
  pkceOptions: PKCEOptions
): Promise<URL> {
  try {
    const authUrl = openid.buildAuthorizationUrl(config, pkceOptions.parameters);
    logger.info('Authorization URL built successfully');
    return authUrl;
  } catch (error) {
    logger.error({ error }, 'Failed to build authorization URL');
    throw error;
  }
}

/**
 * Builds an authorization URL using Pushed Authorization Requests (RFC 9126).
 *
 * Posts the PKCE parameters to the provider's PAR endpoint and returns a URL
 * containing only `client_id` and `request_uri`. The provider's discovery
 * metadata must include `pushed_authorization_request_endpoint`.
 *
 * @param config - Discovered OpenID Configuration (use openid.discovery() to obtain)
 * @param pkceOptions - The PKCE options (e.g., code challenge, state, parameters)
 * @returns A Promise that resolves to the PAR-based authorization URL
 */
export async function buildAuthorizationUrlWithPAR(
  config: openid.Configuration,
  pkceOptions: PKCEOptions
): Promise<URL> {
  try {
    const authUrl = await openid.buildAuthorizationUrlWithPAR(
      config,
      pkceOptions.parameters,
    );
    logger.info('PAR authorization URL built successfully');
    return authUrl;
  } catch (error) {
    logger.error({ error }, 'Failed to build PAR authorization URL');
    throw error;
  }
}

/**
 * Convenience function to discover OpenID configuration and build an
 * authorization URL. Routes through PAR when `oauthConfig.usePar` is true and
 * the provider advertises `pushed_authorization_request_endpoint`.
 *
 * - `usePar === true` + provider advertises PAR → uses PAR.
 * - `usePar === true` + provider does **not** advertise PAR → throws.
 * - `usePar` unset/false + provider advertises PAR → standard flow + one-line
 *   `info` advisory that PAR is available but not enabled.
 * - `usePar` unset/false + no PAR endpoint → standard flow, no advisory.
 *
 * @param oauthConfig - Your OAuth configuration
 * @param pkceOptions - The PKCE options (e.g., code challenge, state, parameters)
 * @returns A Promise that resolves to the authorization URL
 */
export async function discoverAndBuildAuthorizationUrl(
  oauthConfig: OAuthConfig,
  pkceOptions: PKCEOptions
): Promise<URL> {
  logger.debug({ issuer: oauthConfig.issuer }, 'Discovering OpenID configuration');

  try {
    const config = await openid.discovery(
      new URL(oauthConfig.issuer),
      oauthConfig.clientId,
      oauthConfig.clientSecret,
      openid.ClientSecretPost(oauthConfig.clientSecret)
    );

    const parEndpoint = config.serverMetadata().pushed_authorization_request_endpoint;

    if (oauthConfig.usePar) {
      if (!parEndpoint) {
        throw new Error(
          'PAR requested (usePar=true) but provider does not advertise pushed_authorization_request_endpoint',
        );
      }
      return buildAuthorizationUrlWithPAR(config, pkceOptions);
    }

    if (parEndpoint) {
      logger.info(
        { issuer: oauthConfig.issuer },
        'Provider advertises PAR but usePar is not enabled — set OAuthConfig.usePar=true to use it',
      );
    }

    return buildAuthorizationUrl(config, pkceOptions);
  } catch (error) {
    logger.error({ error, issuer: oauthConfig.issuer }, 'Failed to discover config or build URL');
    throw error;
  }
}

/**
 * Configuration for OAuth client credentials flow (machine-to-machine authentication)
 */
export type ClientCredentialsConfig = {
  /** OAuth token endpoint URL. Must be https. */
  tokenEndpoint: string;
  /** OAuth client ID */
  clientId: string;
  /** OAuth client secret */
  clientSecret: string;
  /** Optional scope for the access token */
  scope?: string;
  /**
   * Issuer identifier. Only used to satisfy the server metadata; defaults to the
   * token endpoint's origin, which is right for the common case.
   */
  issuer?: string;
  /**
   * Request timeout in seconds.
   * @default 30
   */
  timeout?: number;
};

/**
 * Exchanges an authorization code for tokens using OIDC discovery and PKCE.
 *
 * @param oauthConfig - OAuth configuration
 * @param callbackUrl - The full callback URL with query parameters from the OIDC provider
 * @param codeVerifier - The PKCE code verifier stored during login initiation
 * @param expectedState - The state parameter stored during login initiation
 * @returns Token response from the OIDC provider
 */
export async function exchangeAuthorizationCode(
  oauthConfig: OAuthConfig,
  callbackUrl: URL,
  codeVerifier: string,
  expectedState: string,
): Promise<openid.TokenEndpointResponse> {
  logger.debug(
    { issuer: oauthConfig.issuer, clientId: oauthConfig.clientId },
    'Exchanging authorization code for tokens',
  );

  const config = await openid.discovery(
    new URL(oauthConfig.issuer),
    oauthConfig.clientId,
    oauthConfig.clientSecret,
    openid.ClientSecretPost(oauthConfig.clientSecret),
  );

  // openid-client overrides the explicit redirect_uri option with
  // stripParams(callbackUrl). Anchor to oauthConfig.redirect_uri so PAR and
  // token-exchange stay consistent behind reverse proxies that don't forward
  // the original scheme. Build from the trusted base and then copy pathname/
  // search by assignment — `new URL(callbackUrl.pathname, base)` would let a
  // `//evil.com/...` pathname swap the host.
  const normalizedCallbackUrl = new URL(oauthConfig.redirect_uri);
  normalizedCallbackUrl.pathname = callbackUrl.pathname;
  normalizedCallbackUrl.search = callbackUrl.search;
  normalizedCallbackUrl.hash = '';

  const tokens = await openid.authorizationCodeGrant(
    config,
    normalizedCallbackUrl,
    {
      pkceCodeVerifier: codeVerifier,
      expectedState,
    },
    { redirect_uri: oauthConfig.redirect_uri },
  );

  logger.info(
    {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: tokens.expires_in,
    },
    'Authorization code exchange successful',
  );

  return tokens;
}

/**
 * Result of extracting user information from an OIDC token response.
 */
export interface OidcUserInfo {
  sub: string;
  name: string;
  email: string;
  roles: string[];
}

/**
 * Extracts user information from an OIDC token response.
 * Decodes the ID token and extracts standard claims plus roles from a configurable claim.
 *
 * @param tokens - Token response from the OIDC provider
 * @param rolesClaim - Name of the claim containing user roles (default: 'roles')
 * @returns Extracted user information
 */
export function extractUserFromTokens(
  tokens: openid.TokenEndpointResponse,
  rolesClaim: string = 'roles',
): OidcUserInfo {
  if (!tokens.id_token) {
    throw new Error('OIDC token response is missing id_token');
  }

  const idToken = decodeJwt(tokens.id_token);

  // Normalize roles: some providers send a single string instead of an array
  const rawRoles = idToken[rolesClaim];
  const nonArrayRoles = typeof rawRoles === 'string' ? [rawRoles] : [];
  const roles = Array.isArray(rawRoles) ? rawRoles : nonArrayRoles;

  logger.debug({ sub: idToken.sub, rolesClaim, rolesCount: roles.length }, 'Extracted user from ID token');

  return {
    sub: idToken.sub ?? '',
    name: idToken.name as string,
    email: idToken.email as string,
    roles,
  };
}

/**
 * Builds a Session object from an OIDC token response.
 * Maps provider tokens and user claims into the internal Session format.
 *
 * @param tokens - Token response from the OIDC provider
 * @param rolesClaim - Name of the claim containing user roles (default: 'roles')
 * @returns A Session object ready to be encrypted and stored
 */
export function buildSessionFromTokens(
  tokens: openid.TokenEndpointResponse,
  rolesClaim: string = 'roles',
): Session {
  if (!tokens.access_token) {
    throw new Error('OIDC token response is missing access_token');
  }

  const userInfo = extractUserFromTokens(tokens, rolesClaim);

  let scopes: string[] | undefined;
  if (typeof tokens.scope === 'string') {
    const parsed = tokens.scope.split(' ').filter(s => s.length > 0);
    if (parsed.length > 0) scopes = parsed;
  }

  return {
    // Minted once here and carried across refreshes, so every log line for this
    // session shares one correlation id.
    sid: newSessionId(),
    tokens: {
      accessToken: tokens.access_token,
      accessTokenExpiresAt: tokens.expires_in
        ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
        : undefined,
      refreshToken: tokens.refresh_token,
      // Kept for `id_token_hint` on RP-initiated logout.
      idToken: tokens.id_token,
    },
    user: {
      name: userInfo.name,
      email: userInfo.email,
      roles: userInfo.roles,
    },
    scopes,
  };
}

/**
 * Validates a return URL against open redirect attacks.
 * Ensures the URL is same-origin and passes optional custom validation.
 *
 * @param returnTo - The raw returnTo path/URL to validate
 * @param applicationOrigin - The application's origin URL (e.g., 'https://example.com')
 * @param defaultPath - Fallback path if validation fails (default: '/')
 * @param validate - Optional custom validation function for the pathname
 * @returns A safe, validated URL
 */
export function validateReturnUrl(
  returnTo: string | null | undefined,
  applicationOrigin: string,
  defaultPath: string = '/',
  validate?: (pathname: string) => boolean,
): URL {
  const redirectPath = returnTo ?? defaultPath;
  let redirectUrl: URL;

  try {
    redirectUrl = new URL(redirectPath, applicationOrigin);
  } catch {
    logger.warn({ returnTo: redirectPath }, 'Invalid returnTo URL, using default');
    return new URL(defaultPath, applicationOrigin);
  }

  // Enforce same-origin — cross-origin returnTo is a potential open redirect attack
  const originUrl = new URL(applicationOrigin);
  if (redirectUrl.origin !== originUrl.origin) {
    logger.error(
      { returnTo: redirectPath, redirectOrigin: redirectUrl.origin, applicationOrigin: originUrl.origin },
      'Possible open redirect attack: returnTo points outside application origin',
    );
    return new URL(defaultPath, applicationOrigin);
  }

  // Custom validation
  if (validate && !validate(redirectUrl.pathname)) {
    logger.warn(
      { pathname: redirectUrl.pathname },
      'returnTo failed custom validation, falling back to default',
    );
    return new URL(defaultPath, applicationOrigin);
  }

  return redirectUrl;
}

/** Parameters for an RP-initiated logout request (OIDC RP-Initiated Logout 1.0 §2). */
export interface OidcLogoutOptions {
  /** Post-logout redirect URI. Must be registered with the provider. */
  postLogoutRedirectUri?: string;

  /**
   * Raw ID token from `session.tokens.idToken`, sent as `id_token_hint`. Tells the
   * OP which session to end, and is usually what lets it skip the confirmation
   * interstitial.
   */
  idTokenHint?: string;

  /** Opaque value echoed back on the post-logout redirect. */
  state?: string;

  /** `logout_hint`, when the provider documents one. */
  logoutHint?: string;

  /**
   * Whether to send `client_id`. Default true, also alongside `id_token_hint`: the
   * spec allows both (the OP must then verify they match), and `client_id` is often
   * what lets the OP accept `post_logout_redirect_uri` when the hint is stale or
   * absent. Set false only for a provider that documents rejecting the combination.
   */
  includeClientId?: boolean;
}

/**
 * Discovers the OIDC provider's end_session_endpoint and builds an RP-initiated
 * logout URL. Returns null when the provider exposes none, so callers can fall
 * back to clearing the local session only.
 *
 * @param oauthConfig - OAuth configuration (issuer, clientId, clientSecret)
 * @param options - Logout parameters, or a string as shorthand for
 *   `postLogoutRedirectUri`
 * @returns Logout URL or null if not supported
 *
 * @example
 * ```typescript
 * const session = await readSession(cookies, secret);
 * const logoutUrl = await buildOidcLogoutUrl(oauthConfig, {
 *   postLogoutRedirectUri: 'https://app.example.com/',
 *   idTokenHint: session?.tokens?.idToken,
 * });
 * ```
 */
export async function buildOidcLogoutUrl(
  oauthConfig: OAuthConfig,
  options: OidcLogoutOptions | string,
): Promise<URL | null> {
  const {
    postLogoutRedirectUri,
    idTokenHint,
    state,
    logoutHint,
    includeClientId = true,
  } = typeof options === 'string' ? { postLogoutRedirectUri: options } : options;

  try {
    const config = await openid.discovery(
      new URL(oauthConfig.issuer),
      oauthConfig.clientId,
      oauthConfig.clientSecret,
      openid.ClientSecretPost(oauthConfig.clientSecret),
    );
    const endSessionEndpoint = config.serverMetadata().end_session_endpoint;

    if (!endSessionEndpoint) {
      logger.info({ issuer: oauthConfig.issuer }, 'No end_session_endpoint found');
      return null;
    }

    const parameters: Record<string, string> = {};
    if (postLogoutRedirectUri) parameters.post_logout_redirect_uri = postLogoutRedirectUri;
    if (idTokenHint) parameters.id_token_hint = idTokenHint;
    if (state) parameters.state = state;
    if (logoutHint) parameters.logout_hint = logoutHint;

    // buildEndSessionUrl always adds client_id, and deleting it afterwards would
    // also drop one the provider baked into its own endpoint — so when it isn't
    // wanted, assemble the URL directly instead.
    let logoutUrl: URL;
    if (includeClientId) {
      logoutUrl = openid.buildEndSessionUrl(config, parameters);
    } else {
      logoutUrl = new URL(endSessionEndpoint);

      // openid-client rejects a non-https endpoint on the path above; the manual
      // one must too. The URL carries a raw id_token_hint, so a discovery document
      // that downgrades the scheme would put it on the wire in the clear.
      if (logoutUrl.protocol !== 'https:') {
        logger.error(
          { issuer: oauthConfig.issuer, protocol: logoutUrl.protocol },
          'end_session_endpoint is not https — refusing to build a logout URL',
        );
        return null;
      }

      for (const [key, value] of Object.entries(parameters)) {
        logoutUrl.searchParams.append(key, value);
      }
    }

    logger.debug(
      { endSessionEndpoint, hasIdTokenHint: !!idTokenHint, hasState: !!state },
      'Built OIDC logout URL',
    );
    return logoutUrl;
  } catch (error) {
    logger.warn({ error, issuer: oauthConfig.issuer }, 'OIDC discovery failed for logout');
    return null;
  }
}

/**
 * Performs OAuth 2.0 client credentials grant flow for machine-to-machine authentication.
 *
 * Uses client_secret_post against the given token endpoint. The endpoint must be
 * https — the request carries the client secret.
 *
 * @param config - Client credentials configuration including token endpoint, client ID, and secret
 * @returns Token response from the OAuth provider
 * @throws Error if the endpoint is not https, the request times out, or the grant fails
 *
 * @example
 * ```typescript
 * const tokens = await clientCredentialsGrant({
 *   tokenEndpoint: 'https://api.example.com/oauth2/token',
 *   clientId: 'my-client-id',
 *   clientSecret: 'my-client-secret',
 *   scope: 'api:read api:write',
 * });
 * ```
 */
export async function clientCredentialsGrant(
  config: ClientCredentialsConfig,
): Promise<openid.TokenEndpointResponse> {
  try {
    // Build the configuration from metadata rather than discovering it: callers
    // give us a token endpoint, not an issuer. Going through openid-client anyway
    // buys the https guard and the timeout, which a raw fetch of a caller-supplied
    // URL carrying a client secret would not have.
    const openidConfig = new openid.Configuration(
      {
        issuer: config.issuer ?? new URL(config.tokenEndpoint).origin,
        token_endpoint: config.tokenEndpoint,
      },
      config.clientId,
      config.clientSecret,
      // Explicit rather than relying on openid-client's default, matching the
      // discovery calls above: the JSDoc promises client_secret_post.
      openid.ClientSecretPost(config.clientSecret),
    );
    openidConfig.timeout = config.timeout ?? 30;

    const tokens = await openid.clientCredentialsGrant(
      openidConfig,
      config.scope ? { scope: config.scope } : undefined,
    );

    logger.debug({ tokenEndpoint: config.tokenEndpoint }, 'Client credentials grant successful');
    return tokens;
  } catch (error) {
    logger.error(
      { ...getOAuthErrorLogContext(error), tokenEndpoint: config.tokenEndpoint },
      'Client credentials grant failed',
    );
    throw error;
  }
}
