import * as jose from 'jose';

/**
 * Converts a hex string to a Uint8Array.
 *
 * @param hex - A hexadecimal string.
 * @returns A Uint8Array representing the bytes of the hex string.
 */
export function hexToUint8Array(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  if (hex.length > 0 && !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Invalid hex string: contains non-hex characters');
  }
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

/**
 * Normalizes a secret to a Uint8Array.
 * Accepts either a hex-encoded string or an existing Uint8Array.
 */
function normalizeSecret(secret: string | Uint8Array): Uint8Array {
  if (typeof secret === 'string') {
    return hexToUint8Array(secret);
  }
  return secret;
}

/**
 * Encrypts a payload into a JWT using the specified secret.
 *
 * @param payload - The payload to encrypt (can be any JSON-serializable value)
 * @param secret - The encryption key as a hex string or Uint8Array (32 bytes for A256GCM)
 * @returns A promise that resolves to the encrypted JWT as a string.
 */
export async function createEncryptedJWT(
  payload: unknown,
  secret: string | Uint8Array,
): Promise<string> {
  return new jose.EncryptJWT(payload as jose.JWTPayload)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .encrypt(normalizeSecret(secret));
}

/**
 * Decrypts a JWE produced by {@link createEncryptedJWT} and returns its payload.
 *
 * Counterpart to {@link createEncryptedJWT}. Throws if the token cannot be
 * decrypted (wrong key, tampering, or malformed input).
 *
 * @param encryptedJwt - The encrypted JWT string.
 * @param secret - The decryption key as a hex string or Uint8Array (32 bytes for A256GCM).
 * @returns A promise that resolves to the decrypted JWT payload.
 */
export async function decryptJWT(
  encryptedJwt: string,
  secret: string | Uint8Array,
): Promise<jose.JWTPayload> {
  const { payload } = await jose.jwtDecrypt(encryptedJwt, normalizeSecret(secret));
  return payload;
}

/**
 * Converts input data (string or Uint8Array) to a Uint8Array backed by a plain ArrayBuffer.
 * @param data - The input data.
 * @returns A Uint8Array representing the input data.
 */
function toUint8Array(data: string | Uint8Array): Uint8Array {
  if (typeof data === 'string') {
    return new TextEncoder().encode(data);
  }
  return data;
}

/**
 * Hashes the input using SHA-256 with the Web Crypto API.
 * @param data - The input data (string or Uint8Array).
 * @returns A Promise that resolves to the SHA-256 hash as a hex string.
 */
export async function sha256(data: string | Uint8Array): Promise<string> {
  const buffer = toUint8Array(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as BufferSource);
  return toHex(new Uint8Array(hashBuffer));
}

/**
 * Converts a Uint8Array to a lowercase hexadecimal string.
 */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generates a random token of the given byte length and returns it as a hex string.
 *
 * @param tokenLength - The number of random bytes to generate (default is 32).
 * @returns A hex string representing the token.
 */
export function generateToken(tokenLength: number = 32): string {
  const bytes = new Uint8Array(tokenLength);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}
