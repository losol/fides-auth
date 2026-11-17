// The session secret: 32 bytes that every key the library seals with is
// derived from. A bad one is a configuration error, so it throws its own error
// class rather than looking like an unreadable cookie.

import { hexToUint8Array } from '../session/utils.js';

/** A session encryption key: 32 bytes for A256GCM, as hex or raw bytes. */
export type SessionSecret = string | Uint8Array;

/** A missing or malformed session secret: a configuration error, never a bad cookie. */
export class SessionSecretError extends TypeError {
  override name = 'SessionSecretError';
}

/** Throws unless `secret` is the 32 bytes A256GCM needs. Never echoes the secret. */
export function assertSessionSecret(secret: SessionSecret): void {
  if (!secret || secret.length === 0) {
    throw new SessionSecretError('fides-auth: session secret is missing or empty');
  }
  const valid =
    secret instanceof Uint8Array
      ? secret.length === 32
      : typeof secret === 'string' && /^[0-9a-fA-F]{64}$/.test(secret);
  if (!valid) {
    throw new SessionSecretError(
      'fides-auth: session secret must be 32 bytes (64 hex characters or a Uint8Array)',
    );
  }
}

/**
 * A key for one purpose: HKDF-SHA-256 of the secret, with `info` naming the
 * purpose. What is sealed for one purpose doesn't open for another.
 *
 * @throws SessionSecretError if the secret isn't 32 bytes.
 */
export async function deriveKey(secret: SessionSecret, info: string): Promise<Uint8Array> {
  // HKDF takes a key of any length; the session encryption doesn't.
  assertSessionSecret(secret);
  const ikm = typeof secret === 'string' ? hexToUint8Array(secret) : secret;
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode(info) },
    base,
    256,
  );
  return new Uint8Array(bits);
}
