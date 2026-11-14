import * as openid from 'openid-client';

import { createLogger } from '../shared/logger.js';
import { redirectUriOf, type OAuthConfig } from './config.js';
import { moduleContext, type ProtocolContext } from './context.js';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

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
  return exchangeCode(moduleContext(oauthConfig, logger), callbackUrl, codeVerifier, expectedState);
}

/**
 * Exchanges the code in `callbackUrl` for tokens, checking `expectedState` and PKCE.
 * The shared core of {@link exchangeAuthorizationCode} and `OidcClient.exchangeCode`.
 *
 * @throws TypeError if the config has no redirect URI.
 */
export async function exchangeCode(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  callbackUrl: URL,
  codeVerifier: string,
  expectedState: string,
): Promise<openid.TokenEndpointResponse> {
  const redirectUri = redirectUriOf(oauthConfig);
  logger.debug(
    { issuer: oauthConfig.issuer, clientId: oauthConfig.clientId },
    'Exchanging authorization code for tokens',
  );

  const config = await configuration();

  // openid-client overrides the explicit redirect_uri option with
  // stripParams(callbackUrl). Anchor to the configured redirect URI so PAR and
  // token-exchange stay consistent behind reverse proxies that don't forward
  // the original scheme. Build from the trusted base and then copy pathname/
  // search by assignment — `new URL(callbackUrl.pathname, base)` would let a
  // `//evil.com/...` pathname swap the host.
  const normalizedCallbackUrl = new URL(redirectUri);
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
    { redirect_uri: redirectUri },
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
