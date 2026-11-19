import * as openid from 'openid-client';

import type { DpopKey } from '../shared/types.js';
import type { ProtocolContext } from './context.js';
import { dpopHandle } from './dpop-grant.js';
import { requireDpopKey } from './fapi-profile.js';

/** Options for `OidcClient.userInfo`. */
export interface UserInfoOptions {
  /** The `sub` the response must be for: the ID token's, e.g. `session.idp.sub`. */
  expectedSubject: string;
  /** The key the access token is bound to, for a DPoP-bound token: `tokens.dpopKey`. */
  dpopKey?: DpopKey;
}

/**
 * Gets the claims from the provider's UserInfo endpoint. The core of `OidcClient.userInfo`.
 *
 * `expectedSubject` is required and cannot be skipped: the access token alone
 * doesn't say whose claims come back, so OIDC Core §5.3.2 says the `sub` of the
 * response must be checked against the ID token's.
 *
 * @throws a `ClientError` (code `OAUTH_MISSING_SERVER_METADATA`) if the provider's metadata has no `userinfo_endpoint`.
 * @throws a `ClientError` (code `OAUTH_JSON_ATTRIBUTE_COMPARISON`) if the response's `sub` is not `expectedSubject`.
 * @throws what else openid-client throws when the request fails.
 */
export async function userInfo(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  accessToken: string,
  { expectedSubject, dpopKey }: UserInfoOptions,
): Promise<openid.UserInfoResponse> {
  requireDpopKey(oauthConfig, dpopKey, 'userInfo');
  logger.debug(
    { issuer: oauthConfig.issuer, clientId: oauthConfig.clientId },
    'Fetching UserInfo',
  );
  const config = await configuration();
  // Without a key, the call is the one it always was.
  if (!dpopKey) return openid.fetchUserInfo(config, accessToken, expectedSubject);
  return openid.fetchUserInfo(config, accessToken, expectedSubject, {
    DPoP: await dpopHandle(config, dpopKey),
  });
}
