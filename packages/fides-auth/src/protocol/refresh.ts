import * as openid from 'openid-client';

import type { ProtocolContext } from './context.js';
import { getOAuthErrorLogContext } from './logging.js';
import { joinScope } from './scope.js';

/**
 * Runs a refresh token grant. The core of `OidcClient.refresh`.
 */
export async function refresh(
  { config: oAuthConfig, configuration, logger }: ProtocolContext,
  refreshToken: string,
): Promise<openid.TokenEndpointResponse> {
  logger.debug({ issuer: oAuthConfig.issuer }, 'Starting token refresh');

  try {
    const config = await configuration();

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
