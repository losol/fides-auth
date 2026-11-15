import * as openid from 'openid-client';

import type { ProtocolContext } from './context.js';

/** Options for `OidcClient.revoke`. */
export interface RevokeOptions {
  /** Sent as `token_type_hint`, so the provider knows where to look first. */
  tokenTypeHint?: 'refresh_token' | 'access_token';
}

/**
 * Asks the provider to revoke a token (RFC 7009). The core of `OidcClient.revoke`.
 *
 * @returns false when the provider has no `revocation_endpoint`, so nothing was sent.
 * @throws what openid-client throws when the request fails.
 */
export async function revoke(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  token: string,
  { tokenTypeHint }: RevokeOptions = {},
): Promise<boolean> {
  const config = await configuration();
  if (!config.serverMetadata().revocation_endpoint) {
    logger.debug({ issuer: oauthConfig.issuer }, 'No revocation_endpoint; nothing revoked');
    return false;
  }
  await openid.tokenRevocation(
    config,
    token,
    tokenTypeHint ? { token_type_hint: tokenTypeHint } : undefined,
  );
  return true;
}
