// id-token.ts
//
// Verifies ID tokens against the provider's JWKS. Universal: jose uses Web Crypto and fetch.

import { createRemoteJWKSet, type JWTPayload, jwtVerify } from 'jose';

/** Asymmetric only, so `none` and `HS*` are rejected. */
export const DEFAULT_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
];

export type RemoteJwks = ReturnType<typeof createRemoteJWKSet>;

/** One getter per JWKS URI; jose refetches it on an unknown `kid`. */
export interface JwksCache {
  get(uri: string | URL): RemoteJwks;
}

/** Creates an empty JWKS cache. Each OIDC client has its own. */
export function createJwksCache(): JwksCache {
  const cache = new Map<string, RemoteJwks>();
  return {
    get(uri) {
      const url = new URL(uri);
      let jwks = cache.get(url.href);
      if (!jwks) {
        jwks = createRemoteJWKSet(url);
        cache.set(url.href, jwks);
      }
      return jwks;
    },
  };
}

/** What an ID token is checked against. */
export interface IdTokenExpectations {
  /** Expected `iss`. */
  issuer: string;
  /** Expected `aud`, usually the client ID. */
  audience: string | string[];
  /** Accepted `alg` values. Defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. */
  algorithms?: string[];
}

/** Verifies an ID token against `jwks`. The core of `OidcClient.verifyIdToken`. */
export async function verifyIdTokenWith(
  jwks: RemoteJwks,
  idToken: string,
  options: IdTokenExpectations,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: options.issuer,
    audience: options.audience,
    algorithms: options.algorithms ?? DEFAULT_ALGORITHMS,
    // jose checks `exp` only when present; OIDC requires it.
    requiredClaims: ['sub', 'exp', 'iat'],
  });
  return payload;
}
