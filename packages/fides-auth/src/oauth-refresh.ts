import * as openid from 'openid-client';

import { createLogger } from './logger.js';
import type { OAuthConfig } from './oauth-config.js';
import { getOAuthErrorLogContext } from './oauth-logging.js';
import { joinScope } from './oauth-scope.js';
import { discoverConfiguration } from './oidc-discovery.js';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

/**
 * Refreshes an access token using a refresh token grant.
 *
 * @param oAuthConfig - OAuth configuration for the identity provider
 * @param refreshToken - The refresh token to exchange
 * @returns Token endpoint response containing new access and refresh tokens
 */
export async function refreshAccessToken(
  oAuthConfig: OAuthConfig,
  refreshToken: string,
): Promise<openid.TokenEndpointResponse> {
  logger.debug({ issuer: oAuthConfig.issuer }, 'Starting token refresh');

  try {
    const config = await discoverConfiguration(oAuthConfig);

    const tokens = await openid.refreshTokenGrant(
      config,
      refreshToken,
      {
        scope: joinScope(oAuthConfig.scope),
      },
    );

    logger.info({
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: tokens.expires_in
    }, 'Token refresh successful');

    return tokens;
  } catch (error) {
    const errorContext = getOAuthErrorLogContext(error);
    const isInvalidGrant =
      errorContext.code === 'OAUTH_RESPONSE_BODY_ERROR' && errorContext.error === 'invalid_grant';

    if (isInvalidGrant) {
      // Most often the refresh token has expired - log at info level
      logger.info(
        { ...errorContext, issuer: oAuthConfig.issuer },
        'Token refresh failed - refresh token expired or invalid',
      );
    } else {
      // Unexpected error - log at error level
      logger.error({ error, issuer: oAuthConfig.issuer }, 'Token refresh failed');
    }

    throw error;
  }
}
