// dpop.ts
//
// DPoP (RFC 9449): an access token bound to a key the client holds, so a token
// that leaks is of no use without the key. The key is a P-256 key pair, kept
// as a JWK so it can be sealed with the session. Each request carries a proof:
// a short JWT signed with the key, for that method, that URL and that token.

import { calculateJwkThumbprint, importJWK, SignJWT } from 'jose';

import { isDpopKey } from '../shared/dpop-key.js';
import type { DpopKey } from '../shared/types.js';

export { isDpopKey };
export type { DpopKey };

/** The proofs are ES256: every provider that has DPoP has it, and FAPI 2.0 allows it. */
const ALG = 'ES256';

/** The token response wasn't bound to the key it was asked to be bound to. */
export class DpopError extends Error {
  override name = 'DpopError';
}

/** Creates a key to bind a session's tokens to. One per login; it is a secret, like the tokens. */
export async function createDpopKey(): Promise<DpopKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const { x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey);
  if (!x || !y || !d) throw new TypeError('Could not export the DPoP key');
  return { kty: 'EC', crv: 'P-256', x, y, d };
}

/** The public half, as it goes in a proof's header. */
function publicJwk({ kty, crv, x, y }: DpopKey) {
  return { kty, crv, x, y };
}

/**
 * The key's thumbprint (RFC 7638): what a provider puts in a bound token's
 * `cnf.jkt`, and what `dpop_jkt` carries.
 */
export function dpopThumbprint(key: DpopKey): Promise<string> {
  return calculateJwkThumbprint(publicJwk(key), 'sha256');
}

/** The key as Web Crypto keys, for openid-client's own proofs at the token endpoint. */
export async function importDpopKey(key: DpopKey): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  if (!isDpopKey(key)) throw new TypeError('Not a DPoP key');
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey('jwk', { ...key, alg: ALG }, algorithm, false, ['sign']),
    crypto.subtle.importKey('jwk', { ...publicJwk(key), alg: ALG }, algorithm, true, ['verify']),
  ]);
  return { privateKey, publicKey };
}

/** What a proof is for. */
export interface DpopProofOptions {
  /** The request's HTTP method. */
  method: string;
  /** The request's URL. Its query and fragment are left out of the proof, as RFC 9449 §4.2 says. */
  url: string | URL;
  /** The access token the request carries. Its hash goes in the proof as `ath`. */
  accessToken?: string;
  /** The server's `DPoP-Nonce`, when it has given one. */
  nonce?: string;
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

/**
 * Creates the proof for one request: the value of its `DPoP` header. Send the
 * token itself as `Authorization: DPoP <token>`. A proof is for one request;
 * make a new one each time.
 */
export async function createDpopProof(
  key: DpopKey,
  { method, url, accessToken, nonce }: DpopProofOptions,
): Promise<string> {
  if (!isDpopKey(key)) throw new TypeError('Not a DPoP key');
  const target = new URL(url);
  // Origin and path only: no query, no fragment, and never credentials.
  const htu = `${target.origin}${target.pathname}`;

  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu,
  };
  if (accessToken) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
    claims.ath = base64url(new Uint8Array(digest));
  }
  if (nonce) claims.nonce = nonce;

  const signingKey = await importJWK({ ...key, alg: ALG }, ALG);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: ALG, typ: 'dpop+jwt', jwk: publicJwk(key) })
    .setIssuedAt()
    .sign(signingKey);
}
