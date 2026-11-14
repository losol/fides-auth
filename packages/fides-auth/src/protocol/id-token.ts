// id-token.ts
//
// Verifies ID tokens against the provider's JWKS. Universal: jose uses Web Crypto and fetch.

import { createRemoteJWKSet, type JWTPayload, jwtVerify } from 'jose';

import type { OAuthConfig } from './config.js';
import { discoverConfiguration } from './discovery.js';

/** Asymmetric only, so `none` and `HS*` are rejected. */
const DEFAULT_ALGORITHMS = [
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

type RemoteJwks = ReturnType<typeof createRemoteJWKSet>;

/** One getter per JWKS URI; jose refetches it on an unknown `kid`. */
export interface JwksCache {
  get(uri: string | URL): RemoteJwks;
  clear(): void;
}

/** Creates an empty JWKS cache: the module keeps one for `verifyIdToken`, and each OIDC client has its own. */
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
    clear() {
      cache.clear();
    },
  };
}

const jwksCache = createJwksCache();

/** What an ID token is checked against. */
export interface IdTokenExpectations {
  /** Expected `iss`. */
  issuer: string;
  /** Expected `aud`, usually the client ID. */
  audience: string | string[];
  /** Accepted `alg` values. Defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. */
  algorithms?: string[];
}

/** Options for {@link verifyIdToken}. Pass `jwksUri` or `oauthConfig`. */
export type VerifyIdTokenOptions = IdTokenExpectations &
  (
    | {
        /** The provider's JWKS URL. */
        jwksUri: string | URL;
        oauthConfig?: never;
      }
    | {
        /** Reads `jwks_uri` from discovery, or from `serverMetadata`. */
        oauthConfig: OAuthConfig;
        jwksUri?: never;
      }
  );

/** Drops every cached JWKS. Tests should call it between cases. */
export function clearJwksCache(): void {
  jwksCache.clear();
}

async function resolveJwksUri(options: VerifyIdTokenOptions): Promise<string | URL> {
  if (options.jwksUri !== undefined) return options.jwksUri;

  const configuration = await discoverConfiguration(options.oauthConfig);
  const { jwks_uri } = configuration.serverMetadata();
  if (!jwks_uri) throw new TypeError('The provider metadata has no jwks_uri');
  return jwks_uri;
}

/**
 * Verifies an ID token's signature, `iss`, `aud` and `exp` against the provider's JWKS.
 *
 * @returns The verified claims.
 * @throws A jose error if the token is invalid, or a `TypeError` if no JWKS URI is found.
 */
export async function verifyIdToken(
  idToken: string,
  options: VerifyIdTokenOptions,
): Promise<JWTPayload> {
  return verifyIdTokenWith(jwksCache.get(await resolveJwksUri(options)), idToken, options);
}

/** Verifies an ID token against `jwks`. The shared core of `verifyIdToken` and `OidcClient.verifyIdToken`. */
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
