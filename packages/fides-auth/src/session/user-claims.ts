import { decodeJwt, type JWTPayload } from 'jose';
// biome-ignore lint/style/noRestrictedImports: type-only, until #142 adds a shared TokenResponse.
import type { TokenEndpointResponse } from 'openid-client';

import { createLogger } from '../shared/logger.js';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

/**
 * Result of extracting user information from an OIDC token response.
 */
export interface OidcUserInfo {
  sub: string;
  name: string;
  email: string;
  roles: string[];
}

/**
 * Extracts user information from an OIDC token response.
 * Decodes the ID token and extracts standard claims plus roles from a configurable claim.
 *
 * Decodes only: the signature, `iss`, `aud` and `exp` are not checked. Safe on tokens
 * straight from `exchangeAuthorizationCode`; verify any others first (e.g. jose `jwtVerify`).
 *
 * @param tokens - Token response from the OIDC provider
 * @param rolesClaim - Name of the claim containing user roles (default: 'roles')
 * @returns Extracted user information
 */
export function extractUserFromTokens(
  tokens: TokenEndpointResponse,
  rolesClaim: string = 'roles',
): OidcUserInfo {
  if (!tokens.id_token) {
    throw new Error('OIDC token response is missing id_token');
  }

  return userFromClaims(decodeJwt(tokens.id_token), rolesClaim);
}

/**
 * Maps ID token claims to {@link OidcUserInfo}, with roles from `rolesClaim`.
 * Verify the claims first, e.g. with `OidcClient.verifyIdToken`. `/oidc` exports it.
 */
export function userFromClaims(idToken: JWTPayload, rolesClaim = 'roles'): OidcUserInfo {
  // Normalize roles: some providers send a single string instead of an array
  const rawRoles = idToken[rolesClaim];
  const nonArrayRoles = typeof rawRoles === 'string' ? [rawRoles] : [];
  const roles = Array.isArray(rawRoles) ? rawRoles : nonArrayRoles;

  logger.debug({ sub: idToken.sub, rolesClaim, rolesCount: roles.length }, 'Extracted user from ID token');

  return {
    sub: idToken.sub ?? '',
    name: idToken.name as string,
    email: idToken.email as string,
    roles,
  };
}
