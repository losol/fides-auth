import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import type { ProtocolContext } from './context.js';

async function urlFor(
  config: openid.Configuration,
  parameters: Record<string, string>,
  logger: FidesLogger,
): Promise<URL> {
  try {
    const authUrl = openid.buildAuthorizationUrl(config, parameters);
    logger.info('Authorization URL built successfully');
    return authUrl;
  } catch (error) {
    logger.error({ error }, 'Failed to build authorization URL');
    throw error;
  }
}

async function parUrlFor(
  config: openid.Configuration,
  parameters: Record<string, string>,
  logger: FidesLogger,
): Promise<URL> {
  try {
    const authUrl = await openid.buildAuthorizationUrlWithPAR(config, parameters);
    logger.info('PAR authorization URL built successfully');
    return authUrl;
  } catch (error) {
    logger.error({ error }, 'Failed to build PAR authorization URL');
    throw error;
  }
}

/**
 * Builds the authorization URL for `parameters`, through PAR when `usePar` is set.
 * The core of `OidcClient.authorizationUrl`.
 */
export async function authorizationUrl(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  parameters: Record<string, string>,
): Promise<URL> {
  logger.debug({ issuer: oauthConfig.issuer }, 'Discovering OpenID configuration');

  try {
    const config = await configuration();

    const parEndpoint = config.serverMetadata().pushed_authorization_request_endpoint;

    if (oauthConfig.usePar) {
      if (!parEndpoint) {
        throw new Error(
          'PAR requested (usePar=true) but provider does not advertise pushed_authorization_request_endpoint',
        );
      }
      return parUrlFor(config, parameters, logger);
    }

    if (parEndpoint) {
      logger.info(
        { issuer: oauthConfig.issuer },
        'Provider advertises PAR but usePar is not enabled; set usePar: true in the config to use it',
      );
    }

    return urlFor(config, parameters, logger);
  } catch (error) {
    logger.error({ error, issuer: oauthConfig.issuer }, 'Failed to discover config or build URL');
    throw error;
  }
}
