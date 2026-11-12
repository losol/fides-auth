/** Default OIDC scope requesting user identity, profile, email, and offline access. */
export const defaultScope = 'openid profile email offline_access';

/** Returns a scope as the space-separated string sent on the wire. */
export function joinScope(scope: string | string[]): string {
  return Array.isArray(scope) ? scope.join(' ') : scope;
}
