import { decodeJwt, type JWTPayload } from 'jose';
import type { TokenEndpointResponse } from 'openid-client';

import { userFromClaims } from './oauth-user-claims.js';
import { newSessionId } from './session-events.js';
import type { Session } from './types.js';

/**
 * Changes the session built from a token response, e.g. to add `data` or custom user
 * fields. `claims` are decoded from the ID token, not verified, and undefined without one.
 */
export type MapSession = (
  tokens: TokenEndpointResponse,
  claims: JWTPayload | undefined,
  session: Session,
) => Session;

/** Options for {@link buildSessionFromTokens}. */
export interface BuildSessionOptions {
  /**
   * Name of the ID token claim that contains user roles.
   * @default 'roles'
   */
  rolesClaim?: string;

  /** Changes the session before it is returned. */
  mapSession?: MapSession;
}

/**
 * Builds a Session object from an OIDC token response.
 * Maps provider tokens and user claims into the internal Session format. Without an
 * `id_token` the session has no `user`.
 *
 * Decodes the ID token like `extractUserFromTokens`, without verifying it. Pass tokens
 * straight from `exchangeAuthorizationCode`, or verify them first.
 *
 * @param tokens - Token response from the OIDC provider
 * @param options - `rolesClaim` and `mapSession`
 * @returns A Session object ready to be encrypted and stored
 */
export function buildSessionFromTokens(
  tokens: TokenEndpointResponse,
  options?: BuildSessionOptions,
): Session;
/**
 * @param tokens - Token response from the OIDC provider
 * @param rolesClaim - Name of the claim containing user roles (default: 'roles')
 */
export function buildSessionFromTokens(
  tokens: TokenEndpointResponse,
  rolesClaim?: string,
): Session;
export function buildSessionFromTokens(
  tokens: TokenEndpointResponse,
  options: BuildSessionOptions | string = {},
): Session {
  const { rolesClaim = 'roles', mapSession } =
    typeof options === 'string' ? { rolesClaim: options } : options;

  if (!tokens.access_token) {
    throw new Error('OIDC token response is missing access_token');
  }

  // OAuth-only responses (no `openid` scope) carry no ID token, so no user.
  const claims = tokens.id_token ? decodeJwt(tokens.id_token) : undefined;
  const userInfo = claims && userFromClaims(claims, rolesClaim);

  let scopes: string[] | undefined;
  if (typeof tokens.scope === 'string') {
    const parsed = tokens.scope.split(' ').filter(s => s.length > 0);
    if (parsed.length > 0) scopes = parsed;
  }

  const session: Session = {
    // Minted once here and carried across refreshes, so every log line for this
    // session shares one correlation id.
    sid: newSessionId(),
    tokens: {
      accessToken: tokens.access_token,
      accessTokenExpiresAt: tokens.expires_in
        ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
        : undefined,
      refreshToken: tokens.refresh_token,
      // Kept for `id_token_hint` on RP-initiated logout.
      idToken: tokens.id_token,
    },
    user: userInfo && {
      sub: userInfo.sub,
      name: userInfo.name,
      email: userInfo.email,
      roles: userInfo.roles,
    },
    scopes,
  };

  return mapSession ? mapSession(tokens, claims, session) : session;
}
