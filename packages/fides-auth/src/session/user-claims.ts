import type { JWTPayload } from 'jose';

/** The user from ID token claims, as {@link userFromClaims} reads them. */
export interface OidcUserInfo {
  sub: string;
  name: string;
  email: string;
  roles: string[];
}

/**
 * Where the roles are in the ID token: the name of a top-level claim, or a
 * function of the claims for anything else, such as Keycloak's
 * `realm_access.roles`. The function must not throw when the claim is missing.
 */
export type RolesClaim =
  | string
  | ((claims: JWTPayload) => readonly string[] | string | null | undefined);

/**
 * The roles `rolesClaim` finds in the claims. Some providers send one role as
 * a plain string. A claim that is missing, or holds anything else, gives none.
 */
export function rolesFromClaims(claims: JWTPayload, rolesClaim: RolesClaim = 'roles'): string[] {
  const raw: unknown = typeof rolesClaim === 'function' ? rolesClaim(claims) : claims[rolesClaim];
  if (typeof raw === 'string') return [raw];
  return Array.isArray(raw) ? raw.filter((role): role is string => typeof role === 'string') : [];
}

/**
 * Maps ID token claims to {@link OidcUserInfo}, with roles from `rolesClaim`.
 * Verify the claims first, e.g. with `OidcClient.verifyIdToken`. `/oidc` exports it.
 */
export function userFromClaims(idToken: JWTPayload, rolesClaim: RolesClaim = 'roles'): OidcUserInfo {
  const roles = rolesFromClaims(idToken, rolesClaim);

  return {
    sub: idToken.sub ?? '',
    name: idToken.name as string,
    email: idToken.email as string,
    roles,
  };
}
