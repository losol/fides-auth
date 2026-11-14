// The session secret: the A256GCM key that seals the session record and the
// login transaction. A bad one is a configuration error, so it throws its own
// error class rather than looking like an unreadable cookie.

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
