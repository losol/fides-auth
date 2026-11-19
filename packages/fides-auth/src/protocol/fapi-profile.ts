// fapi-profile.ts
//
// What `profile: 'fapi2'` asks of the config and of a signature algorithm:
// the client side of the FAPI 2.0 Security Profile. The checks throw, so a
// config that falls short never runs as a weaker one.

import { decodeProtectedHeader } from 'jose';

import type { OidcClientConfig } from './config.js';

/** The signature algorithms the profile allows (FAPI 2.0 Security Profile §5.4). */
export const FAPI2_ALGORITHMS: readonly string[] = ['PS256', 'ES256', 'EdDSA'];

/** The Web Crypto name of an RS256/384/512 key, which the profile doesn't allow. */
const RSA_PKCS1 = 'RSASSA-PKCS1-v1_5';

function algorithmName(privateKey: unknown): string | undefined {
  if (typeof privateKey !== 'object' || privateKey === null) return undefined;
  // A `{ key, kid }` wraps the CryptoKey.
  const key = 'key' in privateKey ? (privateKey as { key: unknown }).key : privateKey;
  if (typeof key !== 'object' || key === null) return undefined;
  const algorithm = (key as { algorithm?: { name?: unknown } }).algorithm;
  return typeof algorithm?.name === 'string' ? algorithm.name : undefined;
}

/**
 * Checks a config against its `profile`. Does nothing without one.
 *
 * @throws TypeError naming every requirement the config doesn't meet, or an unknown profile.
 */
export function checkProfile(config: OidcClientConfig): void {
  const profile: unknown = config.profile;
  if (profile === undefined) return;
  if (profile !== 'fapi2') throw new TypeError(`Unsupported profile: ${String(profile)}`);

  const violations: string[] = [];
  if (config.clientAuth !== 'private_key_jwt') {
    violations.push(
      `clientAuth must be 'private_key_jwt' (got '${String(config.clientAuth ?? 'client_secret_post')}')`,
    );
  } else if (algorithmName(config.privateKey) === RSA_PKCS1) {
    violations.push(
      `privateKey must sign with PS256, ES256 or EdDSA (got an ${RSA_PKCS1} key, which signs RS256)`,
    );
  }
  if (config.usePar !== true) violations.push('usePar must be true');
  if (config.dpop !== true) violations.push('dpop must be true');
  if (config.allowInsecureRequests) violations.push('allowInsecureRequests must not be set');

  if (violations.length > 0) {
    throw new TypeError(`profile 'fapi2' is not met: ${violations.join('; ')}`);
  }
}

/**
 * The algorithms to verify a signature with: under the profile its three,
 * otherwise what was asked for, which may be undefined for the default.
 *
 * @throws TypeError under the profile, for an algorithm outside its three.
 */
export function profileAlgorithms(
  config: OidcClientConfig,
  algorithms: string[] | undefined,
): string[] | undefined {
  if (config.profile !== 'fapi2') return algorithms;
  if (algorithms === undefined) return [...FAPI2_ALGORITHMS];
  const refused = algorithms.filter((algorithm) => !FAPI2_ALGORITHMS.includes(algorithm));
  if (refused.length > 0) {
    throw new TypeError(
      `profile 'fapi2' allows only ${FAPI2_ALGORITHMS.join(', ')}, not ${refused.join(', ')}`,
    );
  }
  return algorithms;
}

/**
 * Under the profile, refuses a token response whose ID token is signed with an
 * algorithm outside its three. openid-client takes an ID token from the token
 * endpoint on the word of TLS and checks its `alg` only against the metadata,
 * where RS256 is the default.
 *
 * @throws Error under the profile, for an ID token with another `alg` or a header that can't be read.
 */
export function checkIdTokenAlgorithm(config: OidcClientConfig, idToken: string | undefined): void {
  if (config.profile !== 'fapi2' || !idToken) return;
  let alg: unknown;
  try {
    alg = decodeProtectedHeader(idToken).alg;
  } catch {
    alg = undefined;
  }
  if (typeof alg !== 'string' || !FAPI2_ALGORITHMS.includes(alg)) {
    throw new Error(
      `profile 'fapi2': the ID token is signed with ${String(alg)}, and only ${FAPI2_ALGORITHMS.join(', ')} are allowed`,
    );
  }
}
