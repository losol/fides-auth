import * as openid from 'openid-client';

import { createLogger } from './logger.js';
import type { ClientCredentialsConfig } from './oauth-config.js';
import { getOAuthErrorLogContext } from './oauth-logging.js';
import { resolveClientAuth } from './oidc-discovery.js';

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
