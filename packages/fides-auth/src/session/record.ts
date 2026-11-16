// A session as it is sealed: `{ v: 1, session, tokens }`. The app sees
// `session`, which carries no tokens; only the library reads `tokens`. The
// functions here build, refresh and update a record and say when it has
// expired. They are pure: when each one runs is up to the lifecycle
// (server/session-lifecycle.ts), and where the sealed string is kept is up to
// a storage (server/session-storage.ts).

import { decodeJwt, type JWTPayload } from 'jose';

import { newSessionId } from '../shared/session-events.js';
import type { Session, SessionUser, Tokens, TokenResponse, TokenStatus } from '../shared/types.js';
import { rolesFromClaims, type RolesClaim } from './user-claims.js';
import { createEncryptedJWT, decryptJWT } from './utils.js';

/** What is sealed: one string, the same in both storages. */
export interface SessionRecord {
  v: 1;
  session: Session;
  tokens: Tokens;
}

/**
 * Changes the session built at login, e.g. to add `data` or look the user up.
 * `claims` are decoded from the ID token, not verified, and undefined without
 * one. The identity and lifetime fields are kept whatever it returns.
 */
export type MapRecordSession = (
  tokens: TokenResponse,
  claims: JWTPayload | undefined,
  session: Session,
) => Session | Promise<Session>;

/** Options for {@link createRecord}. */
export interface CreateRecordOptions {
  sessionDurationSeconds: number;
  /** Where the roles are in the ID token. False leaves `user.roles` unset. @default 'roles' */
  rolesClaim?: RolesClaim | false;
  /**
   * The scope the login asked for. Used when the token response names none,
   * which RFC 6749 §5.1 allows only when the two are identical.
   */
  requestedScope?: string;
  /** Milliseconds since the epoch. */
  now?: number;
}

/** How long a session lasts when the app doesn't say: 12 hours, a working day. */
export const DEFAULT_SESSION_DURATION_SECONDS = 12 * 60 * 60;

/**
 * The session lifetime in seconds, the default unless given. Checked before a
 * login depends on it: one that isn't a number would only show as a failed
 * login, when `expiresAt` can't be written.
 *
 * @throws TypeError unless `seconds` is undefined or a finite number above 0.
 */
export function checkSessionDuration(seconds = DEFAULT_SESSION_DURATION_SECONDS): number {
  if (!(Number.isFinite(seconds) && seconds > 0)) {
    throw new TypeError(`sessionDurationSeconds must be a finite number above 0, got ${seconds}`);
  }
  return seconds;
}

/** The access token's lifetime as two timestamps, or neither when the provider gave none. */
function lifetimeOf(
  tokens: TokenResponse,
  now: number,
): Pick<Tokens, 'accessTokenExpiresAt' | 'accessTokenIssuedAt'> {
  if (!tokens.expires_in) return { accessTokenExpiresAt: undefined, accessTokenIssuedAt: undefined };
  return {
    accessTokenExpiresAt: new Date(now + tokens.expires_in * 1000).toISOString(),
    accessTokenIssuedAt: new Date(now).toISOString(),
  };
}

function splitScope(scope: unknown): string[] | undefined {
  if (typeof scope !== 'string') return undefined;
  const scopes = scope.split(' ').filter((s) => s.length > 0);
  return scopes.length > 0 ? scopes : undefined;
}

function scopesOf(tokens: TokenResponse): string[] | undefined {
  return splitScope(tokens.scope);
}

function stringClaim(claims: JWTPayload, name: string): string | undefined {
  const value = claims[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * The user an ID token describes, as at login. Undefined without a `sub`.
 * With `rolesClaim: false` it has no `roles`: they aren't the library's to set.
 */
function userOf(claims: JWTPayload, rolesClaim: RolesClaim | false | undefined): SessionUser | undefined {
  const sub = stringClaim(claims, 'sub');
  if (!sub) return undefined;
  const user: SessionUser = { sub };
  if (rolesClaim !== false) user.roles = rolesFromClaims(claims, rolesClaim);
  const name = stringClaim(claims, 'name');
  const email = stringClaim(claims, 'email');
  if (name) user.name = name;
  if (email) user.email = email;
  return user;
}

/** The decoded, unverified ID token claims. Undefined without an ID token. */
export function claimsOf(tokens: TokenResponse): JWTPayload | undefined {
  return tokens.id_token ? decodeJwt(tokens.id_token) : undefined;
}

/**
 * Builds a new record from a token response, with a new correlation id and a
 * lifetime of `sessionDurationSeconds`.
 *
 * Decodes the ID token without verifying it: pass tokens straight from the code
 * exchange, or verify them first.
 *
 * @throws Error if the response has no access token.
 */
export function createRecord(tokens: TokenResponse, options: CreateRecordOptions): SessionRecord {
  if (!tokens.access_token) {
    throw new Error('OIDC token response is missing access_token');
  }
  const now = options.now ?? Date.now();
  const claims = claimsOf(tokens);
  const sub = claims && stringClaim(claims, 'sub');
  const iss = claims && stringClaim(claims, 'iss');

  const user = claims && userOf(claims, options.rolesClaim);

  const session: Session = {
    correlationId: newSessionId(),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + options.sessionDurationSeconds * 1000).toISOString(),
    user,
    scopes: scopesOf(tokens) ?? splitScope(options.requestedScope),
    idp: claims && iss && sub ? { iss, sub, sid: stringClaim(claims, 'sid') } : undefined,
  };

  return {
    v: 1,
    session,
    tokens: {
      accessToken: tokens.access_token,
      ...lifetimeOf(tokens, now),
      refreshToken: tokens.refresh_token,
      idToken: tokens.id_token,
    },
  };
}

/**
 * Takes the contents of `changed` and the identity and lifetime of `original`:
 * a map or an update can change the user, scopes and data, never the
 * correlation id, the timestamps or the IdP session.
 */
export function keepIdentity(original: Session, changed: Session): Session {
  return {
    ...changed,
    correlationId: original.correlationId,
    createdAt: original.createdAt,
    expiresAt: original.expiresAt,
    idp: original.idp,
  };
}

/** Options for {@link refreshRecord}. */
export interface RefreshRecordOptions {
  /** Where the roles are in the ID token. False keeps the roles the session has. @default 'roles' */
  rolesClaim?: RolesClaim | false;
  /** Milliseconds since the epoch. */
  now?: number;
}

/**
 * Whether a refresh's ID token is for the session's own user: OIDC Core §12.2
 * requires the `iss` and `sub` of the ID token from login. True without an ID
 * token, or for a session that has no IdP session to compare with.
 */
export function isSameSubject(record: SessionRecord, tokens: TokenResponse): boolean {
  const claims = claimsOf(tokens);
  const { idp } = record.session;
  if (!claims || !idp) return true;
  return stringClaim(claims, 'sub') === idp.sub && stringClaim(claims, 'iss') === idp.iss;
}

/**
 * The record after a refresh: new tokens, the same identity. A provider that
 * doesn't rotate the refresh token, or sends no new ID token, keeps the old one.
 *
 * A new ID token updates the user as at login: the roles follow `rolesClaim`,
 * the name and email change when the token carries them, and `sub` and the
 * fields `mapSession` added stay. A token without the roles claim takes the
 * roles away: a provider that leaves out an empty claim says the same as one
 * that sends an empty list. With `rolesClaim: false` the roles stay as they
 * are. Check {@link isSameSubject} first.
 *
 * A response that names its `scope` updates the session's scopes too: a
 * provider must name it when it grants something else than before.
 */
export function refreshRecord(
  record: SessionRecord,
  tokens: TokenResponse,
  { rolesClaim, now = Date.now() }: RefreshRecordOptions = {},
): SessionRecord {
  const { user, idp } = record.session;
  const claims = claimsOf(tokens);
  const fresh = claims && user && idp ? userOf(claims, rolesClaim) : undefined;
  const scopes = scopesOf(tokens);
  let session = record.session;
  if (fresh && user) session = { ...session, user: { ...user, ...fresh, sub: user.sub } };
  if (scopes) session = { ...session, scopes };
  return {
    v: 1,
    session,
    tokens: {
      ...record.tokens,
      accessToken: tokens.access_token,
      ...lifetimeOf(tokens, now),
      refreshToken: tokens.refresh_token ?? record.tokens.refreshToken,
      // A refresh doesn't always return an ID token, and a stale hint still works.
      idToken: tokens.id_token ?? record.tokens.idToken,
    },
  };
}

/**
 * Whether the record's access token can still be used. A token without a
 * known lifetime counts as active, as it does for a refresh that is asked for
 * only when the token is about to expire.
 */
export function tokenStatusOf(tokens: Tokens, now = Date.now()): TokenStatus {
  const expiresAt = Date.parse(tokens.accessTokenExpiresAt ?? '');
  const usable = !!tokens.accessToken && (Number.isNaN(expiresAt) || expiresAt > now);
  if (usable) return 'active';
  return tokens.refreshToken ? 'refreshable' : 'expired';
}

/** Whether the session's lifetime has run out. */
export function isExpired(record: SessionRecord, now = Date.now()): boolean {
  return !(Date.parse(record.session.expiresAt) > now);
}

/** Seals the record into one string. */
export function sealRecord(record: SessionRecord, secret: string | Uint8Array): Promise<string> {
  return createEncryptedJWT(record, secret);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Opens a sealed record, or returns null when it doesn't open or opens as
 * something else. A payload without `v: 1`, such as a session sealed in the
 * older shape, is something else.
 */
export async function openRecord(
  sealed: string,
  secret: string | Uint8Array,
): Promise<SessionRecord | null> {
  let payload: JWTPayload;
  try {
    payload = await decryptJWT(sealed, secret);
  } catch {
    return null;
  }

  const { v, session, tokens } = payload;
  if (v !== 1 || !isObject(session) || !isObject(tokens)) return null;
  if (
    !isString(session.correlationId) ||
    !isString(session.createdAt) ||
    !isString(session.expiresAt) ||
    Number.isNaN(Date.parse(session.expiresAt))
  ) {
    return null;
  }
  // Only the three fields: the seal adds `iat`, which isn't part of the record.
  return { v: 1, session: session as unknown as Session, tokens: tokens as Tokens };
}
