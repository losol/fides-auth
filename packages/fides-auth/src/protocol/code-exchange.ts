import * as openid from 'openid-client';

import { redirectUriOf } from './config.js';
import type { ProtocolContext } from './context.js';

/**
 * Exchanges the code in `callbackUrl` for tokens, checking `expectedState` and PKCE.
 * With `expectedNonce`, the response must have an ID token whose `nonce` is
 * that value. Without it, an ID token that carries a `nonce` is refused.
 * The core of `OidcClient.exchangeCode`.
 *
 * @throws TypeError if the config has no redirect URI.
 */
export async function exchangeCode(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  callbackUrl: URL,
  codeVerifier: string,
  expectedState: string,
  expectedNonce?: string,
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
      // A string makes openid-client require the ID token and compare its `nonce`.
      ...(expectedNonce ? { expectedNonce } : {}),
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
