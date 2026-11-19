import * as openid from 'openid-client';

import type { DpopKey } from '../shared/types.js';
import { redirectUriOf } from './config.js';
import { assertBound, dpopHandle } from './dpop-grant.js';
import { checkIdTokenAlgorithm, requireDpopKey } from './fapi-profile.js';
import type { ProtocolContext } from './context.js';

/**
 * Exchanges the code in `callbackUrl` for tokens, checking `expectedState` and PKCE.
 * With `expectedNonce`, the response must have an ID token whose `nonce` is
 * that value. Without it, an ID token that carries a `nonce` is refused.
 * With `dpopKey`, the tokens are asked to be bound to it, and a response that
 * isn't is refused.
 * With `profile: 'fapi2'`, a callback without `iss` is refused, whatever the
 * provider's metadata says of it.
 * The core of `OidcClient.exchangeCode`.
 *
 * @throws TypeError if the config has no redirect URI.
 * @throws Error under `profile: 'fapi2'`, if the callback has no `iss`.
 */
export async function exchangeCode(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  callbackUrl: URL,
  codeVerifier: string,
  expectedState: string,
  expectedNonce?: string,
  dpopKey?: DpopKey,
): Promise<openid.TokenEndpointResponse> {
  const redirectUri = redirectUriOf(oauthConfig);
  requireDpopKey(oauthConfig, dpopKey, 'exchangeCode');
  // openid-client requires `iss` only when the metadata says the provider sends
  // it. The profile requires it always (RFC 9207), and before the code goes anywhere.
  if (oauthConfig.profile === 'fapi2' && !callbackUrl.searchParams.get('iss')) {
    throw new Error(
      "profile 'fapi2': the callback has no iss parameter (RFC 9207), so the code was not exchanged",
    );
  }
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
    dpopKey ? { DPoP: await dpopHandle(config, dpopKey) } : undefined,
  );
  if (dpopKey) await assertBound(config, tokens);
  checkIdTokenAlgorithm(oauthConfig, tokens.id_token);

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
