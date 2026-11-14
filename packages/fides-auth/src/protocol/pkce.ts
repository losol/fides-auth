// pkce.ts
//
// PKCE (RFC 7636) and `state` primitives on Web Crypto. No imports, so it runs
// in Node, browsers and edge runtimes.

/** A PKCE code verifier and its S256 code challenge. */
export interface PkcePair {
  verifier: string;
  challenge: string;
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

function randomBase64url(byteLength: number): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** Creates a code verifier (32 random bytes, base64url) and its S256 challenge. */
export async function createPkcePair(): Promise<PkcePair> {
  const verifier = randomBase64url(32);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}

/** Creates a random `state` value (32 random bytes, base64url). */
export function createState(): string {
  return randomBase64url(32);
}
