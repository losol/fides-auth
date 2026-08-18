// session-cookies.ts
//
// Framework-agnostic encoding/decoding of a session into cookie *values*. This
// module performs no I/O — it never reads or writes cookies. Framework adapters
// (Next.js, React Router, …) own the actual cookie store and call these helpers
// to split a session across two cookie values and to reassemble it again.
//
// The split: the large raw JWTs — the access token and the ID token (kept for
// `id_token_hint` on logout) — each get their own encrypted value, everything else
// goes in the main one, so no cookie has to carry two JWTs against the ~4KB limit.

import { createEncryptedJWT, decryptJWT } from './utils';
import { validateSessionJwt } from './session-validation';
import { createLogger } from './logger';
import { Session } from './types';

const logger = createLogger({ namespace: 'fides-auth:session-cookies' });

/** Encrypted cookie values produced from a session. */
export interface EncodedSessionCookies {
  /** Value for the main session cookie (everything except the raw access/ID tokens). */
  session: string;
  /**
   * Value for the access-token cookie, or `undefined` when the session carries
   * no access token. Adapters should delete the access-token cookie in that case.
   */
  accessToken?: string;
  /** Value for the ID-token cookie, or `undefined` when the session carries none. */
  idToken?: string;
}

/** Raw cookie values read from the store, before decoding. */
export interface RawSessionCookies {
  /** The main session cookie value, or null if absent. */
  session: string | null;
  /** The access-token cookie value, or null if absent. */
  accessToken: string | null;
  /** The ID-token cookie value, or null if absent. */
  idToken?: string | null;
}

/**
 * Encrypts a session into the three cookie values, splitting the raw access and ID
 * tokens out.
 *
 * @param session - The session to encode.
 * @param secret - The encryption key as a hex string or Uint8Array (32 bytes for A256GCM).
 */
export async function encodeSessionCookies(
  session: Session,
  secret: string | Uint8Array,
): Promise<EncodedSessionCookies> {
  const { tokens, ...rest } = session;
  const accessToken = tokens?.accessToken;
  const idToken = tokens?.idToken;

  // Main value: the whole session minus the raw access and ID tokens (undefined
  // keys are dropped during JWT serialization).
  const coreSession: Session = {
    ...rest,
    tokens: tokens ? { ...tokens, accessToken: undefined, idToken: undefined } : undefined,
  };

  const main = await createEncryptedJWT(coreSession, secret);

  return {
    session: main,
    accessToken: accessToken ? await createEncryptedJWT({ accessToken }, secret) : undefined,
    idToken: idToken ? await createEncryptedJWT({ idToken }, secret) : undefined,
  };
}

/**
 * Decodes the cookie values back into a session, reattaching the access and ID tokens.
 *
 * Returns the session whenever the main value decrypts and validates — an
 * expired access token does not hide it; token freshness is the caller's
 * concern. Returns null for a missing/invalid main value, or a stale legacy
 * single-cookie session (one re-login). A corrupt access-token value is
 * tolerated: the session is returned without it.
 *
 * @param raw - The raw cookie values read from the store.
 * @param secret - The decryption key as a hex string or Uint8Array (32 bytes for A256GCM).
 */
export async function decodeSessionCookies(
  raw: RawSessionCookies,
  secret: string | Uint8Array,
): Promise<Session | null> {
  if (!raw.session) {
    return null;
  }

  const { status, session } = await validateSessionJwt(raw.session, secret);

  // EXPIRED only fires for legacy single-cookie sessions — dropped, not migrated.
  if (status !== 'VALID' || !session) {
    logger.debug({ status }, 'Session cookie did not validate');
    return null;
  }

  if (raw.accessToken) {
    try {
      const payload = await decryptJWT(raw.accessToken, secret);
      const accessToken = typeof payload.accessToken === 'string' ? payload.accessToken : undefined;

      if (accessToken) {
        // Attached as stored, expired or not — freshness is the caller's concern.
        session.tokens = { ...session.tokens, accessToken };
      }
    } catch (error) {
      // A corrupt/forged access-token value shouldn't take down the session.
      logger.warn({ error }, 'Failed to decode access-token cookie');
    }
  }

  if (raw.idToken) {
    const idToken = await decodeIdTokenCookie(raw.idToken, secret);
    if (idToken) {
      session.tokens = { ...session.tokens, idToken };
    }
  }

  return session;
}

/**
 * Decrypts the ID-token cookie value on its own, independent of session validity.
 * Logout needs the hint precisely when the session has gone stale, so this must not
 * go through {@link decodeSessionCookies}.
 *
 * @param raw - The ID-token cookie value.
 * @param secret - The decryption key as a hex string or Uint8Array (32 bytes for A256GCM).
 */
export async function decodeIdTokenCookie(
  raw: string,
  secret: string | Uint8Array,
): Promise<string | undefined> {
  try {
    const payload = await decryptJWT(raw, secret);
    return typeof payload.idToken === 'string' ? payload.idToken : undefined;
  } catch (error) {
    logger.warn({ error }, 'Failed to decode ID-token cookie');
    return undefined;
  }
}
