// id-token.ts
//
// Verifies ID tokens against the provider's JWKS. Universal: jose uses Web Crypto and fetch.

import { createRemoteJWKSet, type JWTPayload, jwtVerify } from 'jose';

import type { OAuthConfig } from './oauth';
import { discoverConfiguration } from './oidc-discovery';

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
const jwksCache = new Map<string, RemoteJwks>();

interface VerifyIdTokenBaseOptions {
  /** Expected `iss`. */
  issuer: string;
  /** Expected `aud`, usually the client ID. */
  audience: string | string[];
  /** Accepted `alg` values. Defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. */
  algorithms?: string[];
}

/** Options for {@link verifyIdToken}. Pass `jwksUri` or `oauthConfig`. */
export type VerifyIdTokenOptions = VerifyIdTokenBaseOptions &
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

function getJwks(uri: string | URL): RemoteJwks {
  const url = new URL(uri);
  let jwks = jwksCache.get(url.href);
  if (!jwks) {
    jwks = createRemoteJWKSet(url);
    jwksCache.set(url.href, jwks);
  }
  return jwks;
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
  const jwks = getJwks(await resolveJwksUri(options));
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: options.issuer,
    audience: options.audience,
    algorithms: options.algorithms ?? DEFAULT_ALGORITHMS,
    // jose checks `exp` only when present; OIDC requires it.
    requiredClaims: ['sub', 'exp', 'iat'],
  });
  return payload;
}
