// The 1.0 session record (ADR 0001 §4, "The session model"): what is sealed,
// how it is built, refreshed and updated, and when it has expired. Pure: no
// network, no storage. The lifecycle in server/ decides when each runs, and a
// storage keeps the sealed string.
//
// Not wired in yet: the createFidesAuth factory switches to it.

import { decodeJwt, type JWTPayload } from 'jose';

import { newSessionId } from '../shared/session-events.js';
import type { Tokens, TokenResponse } from '../shared/types.js';
import { userFromClaims } from './user-claims.js';
import { createEncryptedJWT, decryptJWT } from './utils.js';

/** The IdP's own session, from the ID token. Back-channel logout matches on it. */
export interface IdpSession {
  iss: string;
  sub: string;
  /** The ID token's `sid` claim, when the provider sends one. */
  sid?: string;
}

/** What the app sees of a session. It carries no tokens. */
export interface SessionData<TData = Record<string, unknown>> {
  /** The library's id for this session, carried across refreshes and logged on every event. */
  correlationId: string;
  /** ISO 8601. */
  createdAt: string;
  /** ISO 8601. Fixed at creation; nothing extends it. */
  expiresAt: string;
  /** From the ID token. Absent when the token response has none. */
  user?: { sub: string; name?: string; email?: string; roles?: string[] };
  scopes?: string[];
  idp?: IdpSession;
  data?: TData;
}

/** What is sealed: one string, the same in both storages. */
export interface SessionRecord {
  v: 1;
  session: SessionData;
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
  session: SessionData,
) => SessionData | Promise<SessionData>;

/** Options for {@link createRecord}. */
export interface CreateRecordOptions {
  sessionDurationDays: number;
  /** @default 'roles' */
  rolesClaim?: string;
  /** Milliseconds since the epoch. */
  now?: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

function expiresIn(tokens: TokenResponse, now: number): string | undefined {
  return tokens.expires_in ? new Date(now + tokens.expires_in * 1000).toISOString() : undefined;
}

function scopesOf(tokens: TokenResponse): string[] | undefined {
  if (typeof tokens.scope !== 'string') return undefined;
  const scopes = tokens.scope.split(' ').filter((s) => s.length > 0);
  return scopes.length > 0 ? scopes : undefined;
}

function stringClaim(claims: JWTPayload, name: string): string | undefined {
  const value = claims[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** The decoded, unverified ID token claims. Undefined without an ID token. */
export function claimsOf(tokens: TokenResponse): JWTPayload | undefined {
  return tokens.id_token ? decodeJwt(tokens.id_token) : undefined;
}

/**
 * Builds a new record from a token response, with a new correlation id and a
 * lifetime of `sessionDurationDays`.
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

  let user: SessionData['user'];
  if (claims && sub) {
    const { roles } = userFromClaims(claims, options.rolesClaim);
    user = { sub, roles };
    const name = stringClaim(claims, 'name');
    const email = stringClaim(claims, 'email');
    if (name) user.name = name;
    if (email) user.email = email;
  }

  const session: SessionData = {
    correlationId: newSessionId(),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + options.sessionDurationDays * DAY_MS).toISOString(),
    user,
    scopes: scopesOf(tokens),
    idp: claims && iss && sub ? { iss, sub, sid: stringClaim(claims, 'sid') } : undefined,
  };

  return {
    v: 1,
    session,
    tokens: {
      accessToken: tokens.access_token,
      accessTokenExpiresAt: expiresIn(tokens, now),
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
export function keepIdentity(original: SessionData, changed: SessionData): SessionData {
  return {
    ...changed,
    correlationId: original.correlationId,
    createdAt: original.createdAt,
    expiresAt: original.expiresAt,
    idp: original.idp,
  };
}

/**
 * The record after a refresh: new tokens, the same session. A provider that
 * doesn't rotate the refresh token, or sends no new ID token, keeps the old one.
 */
export function refreshRecord(
  record: SessionRecord,
  tokens: TokenResponse,
  now = Date.now(),
): SessionRecord {
  return {
    v: 1,
    session: record.session,
    tokens: {
      ...record.tokens,
      accessToken: tokens.access_token,
      accessTokenExpiresAt: expiresIn(tokens, now),
      refreshToken: tokens.refresh_token ?? record.tokens.refreshToken,
      // A refresh doesn't always return an ID token, and a stale hint still works.
      idToken: tokens.id_token ?? record.tokens.idToken,
    },
  };
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
 * something else. A pre-1.0 session, which has no `v`, is something else.
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
  return { v: 1, session: session as unknown as SessionData, tokens: tokens as Tokens };
}
