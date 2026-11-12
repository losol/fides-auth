import * as openid from 'openid-client';

import { createLogger } from './logger.js';
import type { OAuthConfig } from './oauth-config.js';
import { discoverConfiguration } from './oidc-discovery.js';

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
  logger.debug(
    { issuer: oauthConfig.issuer, clientId: oauthConfig.clientId },
    'Exchanging authorization code for tokens',
  );

  const config = await discoverConfiguration(oauthConfig);

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
