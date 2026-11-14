import * as openid from 'openid-client';

import { createLogger, type FidesLogger } from '../shared/logger.js';
import type { PKCEOptions } from './authorization-parameters.js';
import type { OAuthConfig } from './config.js';
import { moduleContext, type ProtocolContext } from './context.js';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

/**
 * Builds an authorization URL with PKCE parameters.
 *
 * @param config - Discovered OpenID Configuration (use discoverConfiguration() to obtain)
 * @param pkceOptions - The PKCE options (e.g., code challenge, state, parameters)
 * @returns A Promise that resolves to the authorization URL
 */
export async function buildAuthorizationUrl(
  config: openid.Configuration,
  pkceOptions: PKCEOptions
): Promise<URL> {
  return urlFor(config, pkceOptions.parameters, logger);
}

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

/**
 * Builds an authorization URL using Pushed Authorization Requests (RFC 9126).
 *
 * Posts the PKCE parameters to the provider's PAR endpoint and returns a URL
 * containing only `client_id` and `request_uri`. The provider's discovery
 * metadata must include `pushed_authorization_request_endpoint`.
 *
 * @param config - Discovered OpenID Configuration (use discoverConfiguration() to obtain)
 * @param pkceOptions - The PKCE options (e.g., code challenge, state, parameters)
 * @returns A Promise that resolves to the PAR-based authorization URL
 */
export async function buildAuthorizationUrlWithPAR(
  config: openid.Configuration,
  pkceOptions: PKCEOptions
): Promise<URL> {
  return parUrlFor(config, pkceOptions.parameters, logger);
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
 * Convenience function to discover OpenID configuration and build an
 * authorization URL. Routes through PAR when `oauthConfig.usePar` is true and
 * the provider advertises `pushed_authorization_request_endpoint`.
 *
 * - `usePar === true` + provider advertises PAR → uses PAR.
 * - `usePar === true` + provider does **not** advertise PAR → throws.
 * - `usePar` unset/false + provider advertises PAR → standard flow + one-line
 *   `info` advisory that PAR is available but not enabled.
 * - `usePar` unset/false + no PAR endpoint → standard flow, no advisory.
 *
 * @param oauthConfig - Your OAuth configuration
 * @param pkceOptions - The PKCE options (e.g., code challenge, state, parameters)
 * @returns A Promise that resolves to the authorization URL
 */
export async function discoverAndBuildAuthorizationUrl(
  oauthConfig: OAuthConfig,
  pkceOptions: PKCEOptions
): Promise<URL> {
  return authorizationUrl(moduleContext(oauthConfig, logger), pkceOptions.parameters);
}

/**
 * Builds the authorization URL for `parameters`, through PAR when `usePar` is set.
 * The shared core of {@link discoverAndBuildAuthorizationUrl} and `OidcClient.authorizationUrl`.
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
        'Provider advertises PAR but usePar is not enabled — set OAuthConfig.usePar=true to use it',
      );
    }

    return urlFor(config, parameters, logger);
  } catch (error) {
    logger.error({ error, issuer: oauthConfig.issuer }, 'Failed to discover config or build URL');
    throw error;
  }
}
