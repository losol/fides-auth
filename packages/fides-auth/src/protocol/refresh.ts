import * as openid from 'openid-client';

import type { DpopKey } from '../shared/types.js';
import type { ProtocolContext } from './context.js';
import { assertBound, dpopHandle } from './dpop-grant.js';
import { checkIdTokenAlgorithm } from './fapi-profile.js';
import { getOAuthErrorLogContext } from './logging.js';

/**
 * Runs a refresh token grant. The core of `OidcClient.refresh`.
 *
 * Sends no `scope`, so the provider keeps the scope it granted at login. The
 * configured scope may hold more than was granted, e.g. `offline_access`, and
 * asking for that on a refresh fails with `invalid_scope` (RFC 6749 §6).
 *
 * With `dpopKey`, the key the session's tokens are bound to, the request
 * carries a proof and the new tokens must be bound to it too.
 */
export async function refresh(
  { config: oAuthConfig, configuration, logger }: ProtocolContext,
  refreshToken: string,
  dpopKey?: DpopKey,
): Promise<openid.TokenEndpointResponse> {
  logger.debug({ issuer: oAuthConfig.issuer }, 'Starting token refresh');

  try {
    const config = await configuration();

    const tokens = dpopKey
      ? await openid.refreshTokenGrant(config, refreshToken, undefined, {
          DPoP: await dpopHandle(config, dpopKey),
        })
      : await openid.refreshTokenGrant(config, refreshToken);
    // Tokens that were bound stay bound: a provider that answers with a bearer token is refused.
    if (dpopKey) await assertBound(config, tokens);
    checkIdTokenAlgorithm(oAuthConfig, tokens.id_token);

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
      logger.error({ ...errorContext, issuer: oAuthConfig.issuer }, 'Token refresh failed');
    }

    throw error;
  }
}
