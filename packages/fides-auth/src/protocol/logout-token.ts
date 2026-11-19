// logout-token.ts
//
// Verifies a logout token: the signed JWT a provider posts to end a user's
// sessions (OpenID Connect Back-Channel Logout 1.0). It is validated like an
// ID token, and then for what tells the two apart (§2.6): the `events` claim
// it must have, and the `nonce` it must not.

import { type JWTPayload, jwtVerify } from 'jose';

import { DEFAULT_ALGORITHMS, type IdTokenExpectations, type RemoteJwks } from './id-token.js';

/**
 * How old a logout token may be, by its `iat`. A provider sends it the moment
 * the user logs out, so an old one is a copy: a token with only a `sub` would
 * otherwise end sessions the user has started since, for as long as its `exp`
 * allows.
 */
const MAX_AGE_SECONDS = 300;

/** What the clocks of the provider and this server may differ by. */
const CLOCK_TOLERANCE_SECONDS = 30;

/** The member of `events` that makes a JWT a logout token (§2.4). */
export const BACK_CHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** Why a logout token was refused. */
export type LogoutTokenErrorReason =
  /** The signature, `iss`, `aud`, `exp` or a required claim didn't hold. */
  | 'invalid_token'
  /** The header's `typ` names another kind of JWT. */
  | 'wrong_type'
  /** Neither a `sub` nor a `sid`, or one that isn't a string. */
  | 'no_subject'
  /** No `events` claim with the back-channel logout member. */
  | 'no_logout_event'
  /** A `nonce` claim: an ID token, or made to pass for one. */
  | 'has_nonce';

/** A logout token that was refused. `cause` is what jose threw, for `invalid_token`. */
export class LogoutTokenError extends Error {
  override name = 'LogoutTokenError';

  constructor(
    readonly reason: LogoutTokenErrorReason,
    options?: { cause?: unknown },
  ) {
    super(`Logout token refused: ${reason}`, options);
  }
}

/** Whose sessions a verified logout token ends. */
export interface LogoutToken {
  /** The provider, as in the ID token's `iss`. */
  iss: string;
  /** The user. Absent when the token names only a session. */
  sub?: string;
  /** The provider's session, as in the ID token's `sid`. Absent when the token names only a user. */
  sid?: string;
  /** The token's own id. */
  jti: string;
  /** The algorithm the token is signed with: its header's `alg`. */
  alg: string;
  /** Every verified claim. */
  claims: JWTPayload;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/** `logout+jwt` is recommended, and plain `JWT` is what many providers send. */
function isLogoutType(typ: unknown): boolean {
  if (typ === undefined) return true;
  if (typeof typ !== 'string') return false;
  const type = typ.toLowerCase().replace(/^application\//, '');
  return type === 'logout+jwt' || type === 'jwt';
}

/**
 * Verifies a logout token against `jwks`. The core of
 * `OidcClient.verifyLogoutToken`.
 *
 * @throws LogoutTokenError when the token is refused.
 */
export async function verifyLogoutTokenWith(
  jwks: RemoteJwks,
  logoutToken: string,
  options: IdTokenExpectations,
): Promise<LogoutToken> {
  let payload: JWTPayload;
  let typ: unknown;
  let alg: string;
  try {
    const verified = await jwtVerify(logoutToken, jwks, {
      issuer: options.issuer,
      audience: options.audience,
      algorithms: options.algorithms ?? DEFAULT_ALGORITHMS,
      // §2.4 requires all four. jose checks `exp` only when it is there.
      requiredClaims: ['iss', 'aud', 'iat', 'exp', 'jti'],
      maxTokenAge: MAX_AGE_SECONDS,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });
    payload = verified.payload;
    typ = verified.protectedHeader.typ;
    alg = verified.protectedHeader.alg;
  } catch (cause) {
    throw new LogoutTokenError('invalid_token', { cause });
  }

  if (!isLogoutType(typ)) throw new LogoutTokenError('wrong_type');
  // Before anything else is read: with a nonce it is an ID token, whatever else it claims.
  if ('nonce' in payload) throw new LogoutTokenError('has_nonce');

  const events = payload.events;
  const event =
    typeof events === 'object' && events !== null && !Array.isArray(events)
      ? (events as Record<string, unknown>)[BACK_CHANNEL_LOGOUT_EVENT]
      : undefined;
  if (typeof event !== 'object' || event === null || Array.isArray(event)) {
    throw new LogoutTokenError('no_logout_event');
  }

  const { iss, sub, sid, jti } = payload;
  const named = (value: unknown) => value === undefined || nonEmptyString(value);
  if (!named(sub) || !named(sid) || (sub === undefined && sid === undefined)) {
    throw new LogoutTokenError('no_subject');
  }
  if (!nonEmptyString(jti)) throw new LogoutTokenError('invalid_token');

  return {
    iss: iss as string,
    ...(sub === undefined ? {} : { sub: sub as string }),
    ...(sid === undefined ? {} : { sid: sid as string }),
    jti,
    alg,
    claims: payload,
  };
}
