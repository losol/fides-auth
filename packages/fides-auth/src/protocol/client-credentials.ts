import * as openid from 'openid-client';

import { createLogger } from '../shared/logger.js';
import type { ClientCredentialsConfig } from './config.js';
import type { ProtocolContext } from './context.js';
import { getOAuthErrorLogContext } from './logging.js';
import { resolveClientAuth } from './discovery.js';
import { joinScope } from './scope.js';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

/**
 * Performs OAuth 2.0 client credentials grant flow for machine-to-machine authentication.
 *
 * Authenticates with `config.clientAuth` (default client_secret_post). The
 * endpoint must be https — the request carries the client credentials.
 *
 * @param config - Client credentials configuration: token endpoint, client ID and credentials
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
    const { clientSecret, clientAuthentication } = resolveClientAuth(config);
    const openidConfig = new openid.Configuration(
      {
        issuer: config.issuer ?? new URL(config.tokenEndpoint).origin,
        token_endpoint: config.tokenEndpoint,
      },
      config.clientId,
      clientSecret,
      clientAuthentication,
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

/** Options for `OidcClient.clientCredentials`. */
export interface ClientCredentialsOptions {
  /** Scope for the access token. The config's `scope` is for logins, so it isn't used here. */
  scope?: string | string[];
}

/**
 * Runs a client credentials grant against the discovered token endpoint, with
 * the client's own credentials. Used by `OidcClient.clientCredentials`.
 *
 * @throws TypeError if the client is public (`clientAuth: 'none'`).
 */
export async function clientCredentials(
  { config, configuration, logger }: ProtocolContext,
  options: ClientCredentialsOptions = {},
): Promise<openid.TokenEndpointResponse> {
  if (config.clientAuth === 'none') {
    throw new TypeError("The client credentials grant needs client authentication, not clientAuth 'none'");
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
