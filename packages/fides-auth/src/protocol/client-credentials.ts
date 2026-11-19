import * as openid from 'openid-client';

import type { ProtocolContext } from './context.js';
import { getOAuthErrorLogContext } from './logging.js';
import { joinScope } from './scope.js';

/** Options for `OidcClient.clientCredentials`. */
export interface ClientCredentialsOptions {
  /** Scope for the access token. The config's `scope` is for logins, so it isn't used here. */
  scope?: string | string[];
}

/**
 * Runs a client credentials grant against the discovered token endpoint, with
 * the client's own credentials. Used by `OidcClient.clientCredentials`.
 *
 * @throws TypeError if the client is public (`clientAuth: 'none'`), or under `profile: 'fapi2'`.
 */
export async function clientCredentials(
  { config, configuration, logger }: ProtocolContext,
  options: ClientCredentialsOptions = {},
): Promise<openid.TokenEndpointResponse> {
  if (config.clientAuth === 'none') {
    throw new TypeError("The client credentials grant needs client authentication, not clientAuth 'none'");
  }
  if (config.profile === 'fapi2') {
    // This grant has no DPoP here yet, so its tokens would be bearer tokens.
    throw new TypeError(
      "profile 'fapi2': the client credentials grant is not available, since its tokens would not be bound",
    );
  }

  let tokenEndpoint: string | undefined;
  try {
    const openidConfig = await configuration();
    tokenEndpoint = openidConfig.serverMetadata().token_endpoint;

    const tokens = await openid.clientCredentialsGrant(
      openidConfig,
      options.scope ? { scope: joinScope(options.scope) } : undefined,
    );

    logger.debug({ tokenEndpoint }, 'Client credentials grant successful');
    return tokens;
  } catch (error) {
    logger.error(
      { ...getOAuthErrorLogContext(error), issuer: config.issuer, tokenEndpoint },
      'Client credentials grant failed',
    );
    throw error;
  }
}
