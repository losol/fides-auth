// session-cookies.ts
//
// Framework-agnostic encoding/decoding of a session into cookie *values*. This
// module performs no I/O — it never reads or writes cookies. Framework adapters
// (Next.js, React Router, …) own the actual cookie store and call these helpers
// to split a session across two cookie values and to reassemble it again.
//
// The split: the access token (typically the largest part — a JWT carrying
// scopes/roles) is encrypted into its own value, and everything else into the
// main value. Giving each its own cookie keeps a large access token from blowing
// the browser's ~4KB per-cookie limit.

import { decodeJwt } from 'jose';

import { createEncryptedJWT, decryptJWT } from './utils';
import { validateSessionJwt } from './session-validation';
import { createLogger } from './logger';
import { Session } from './types';

const logger = createLogger({ namespace: 'fides-auth:session-cookies' });

/**
 * True only when the access token is a JWT carrying an `exp` claim that is in the
 * past. Mirrors {@link validateSessionJwt}: an access token we can't decode (an
 * opaque token, or one without `exp`) has unknown expiry and must NOT be treated
 * as expired — otherwise opaque tokens would silently discard the whole session.
 */
function accessTokenIsExpired(accessToken: string): boolean {
  try {
    const { exp } = decodeJwt(accessToken);
    if (typeof exp !== 'number') {
      return false;
    }
    return exp - Date.now() / 1000 <= 0;
  } catch {
    return false;
  }
}

/** Encrypted cookie values produced from a session. */
export interface EncodedSessionCookies {
  /** Value for the main session cookie (everything except the raw access token). */
  session: string;
  /**
   * Value for the access-token cookie, or `undefined` when the session carries
   * no access token. Adapters should delete the access-token cookie in that case.
   */
  accessToken?: string;
}

/** Raw cookie values read from the store, before decoding. */
export interface RawSessionCookies {
  /** The main session cookie value, or null if absent. */
  session: string | null;
  /** The access-token cookie value, or null if absent. */
  accessToken: string | null;
}

/**
 * Encrypts a session into the two cookie values, splitting the access token out.
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

  // Main value: the whole session minus the raw access token (undefined keys are
  // dropped during JWT serialization).
  const coreSession: Session = {
    ...rest,
    tokens: tokens ? { ...tokens, accessToken: undefined } : undefined,
  };

  const main = await createEncryptedJWT(coreSession, secret);
  const encodedAccessToken = accessToken
    ? await createEncryptedJWT({ accessToken }, secret)
    : undefined;

  return { session: main, accessToken: encodedAccessToken };
}

/**
 * Decodes the cookie values back into a session, reattaching the access token.
 *
 * Returns null when there is no session, the main value fails validation, or the
 * access token has expired — preserving the contract that an expired access token
 * means "no session". A corrupt access-token value is tolerated: the session is
 * returned without an access token rather than discarded.
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

  // status === 'EXPIRED' only fires for legacy single-cookie sessions, where the
  // access token still lives in the main value. Split sessions are checked below.
  if (status !== 'VALID' || !session) {
    logger.debug({ status }, 'Session cookie did not validate');
    return null;
  }

  if (raw.accessToken) {
    try {
      const payload = await decryptJWT(raw.accessToken, secret);
      const accessToken = typeof payload.accessToken === 'string' ? payload.accessToken : undefined;

      if (accessToken) {
        // Preserve the contract: a verifiably-expired access token means no
        // session. Opaque/undecodable tokens are kept (unknown expiry).
        if (accessTokenIsExpired(accessToken)) {
          logger.info('Access token has expired');
          return null;
        }
        session.tokens = { ...session.tokens, accessToken };
      }
    } catch (error) {
      // A corrupt/forged access-token value shouldn't take down the session.
      logger.warn({ error }, 'Failed to decode access-token cookie');
    }
  }

  return session;
}
