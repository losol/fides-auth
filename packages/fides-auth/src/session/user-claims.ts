import type { JWTPayload } from 'jose';

/** The user from ID token claims, as {@link userFromClaims} reads them. */
export interface OidcUserInfo {
  sub: string;
  /** Absent when the ID token has no `name` claim. */
  name?: string;
  /** Absent when the ID token has no `email` claim. */
  email?: string;
  roles: string[];
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

  return {
    sub: idToken.sub ?? '',
    name: typeof idToken.name === 'string' ? idToken.name : undefined,
    email: typeof idToken.email === 'string' ? idToken.email : undefined,
    roles,
  };
}
