// server/login-transaction.ts
//
// One login between the authorize redirect and the callback: state, PKCE
// verifier, returnTo and start time, sealed into one of a few cookie slots, so
// parallel logins in one browser neither overwrite each other nor pile up. It is
// sealed under a key derived from the secret, so it never opens as a session.

import { assertCookieWithinLimit, defaultOAuthCookieOptions } from '../shared/cookies.js';
import type { FidesLogger } from '../shared/logger.js';
import type { AuthorizationRequest } from '../protocol/authorization-parameters.js';
import { createEncryptedJWT, decryptJWT } from '../session/utils.js';
import type { CookieStore } from './cookie-store.js';
import { deriveKey, type SessionSecret } from './session-secret.js';

const COOKIE_NAME = 'oauth_tx_';

// Only a Secure cookie with Path=/ and no Domain may carry it, so a sibling
// subdomain cannot plant a transaction.
const HOST_PREFIX = '__Host-';

/** Live logins per browser. Another login evicts the oldest. */
const MAX_TRANSACTIONS = 3;

/**
 * A longer returnTo is dropped, not stored in a cookie sent with every request.
 * Measured as serialized: JSON escaping grows a control character sixfold.
 */
const MAX_RETURN_TO_BYTES = 1024;

const DEFAULT_MAX_AGE_MS = 10 * 60 * 1000;

const KEY_INFO = 'fides-auth login-tx';

export interface LoginTransaction {
  state: string;
  codeVerifier: string;
  /** Path to return to after login, already validated. */
  returnTo?: string;
  /** The scope the login asked for, as sent. */
  scope?: string;
  /** Start of the login, in epoch milliseconds. */
  createdAt: number;
}

/** Why {@link validateCallback} rejected a callback. */
export type CallbackValidationReason =
  | 'idp_error'
  | 'state_mismatch'
  | 'transaction_expired'
  | 'missing_code';

export class CallbackValidationError extends Error {
  constructor(
    public readonly reason: CallbackValidationReason,
    /** The IdP's `error` code, for `idp_error`. */
    public readonly idpError?: string,
    /** The IdP's `error_description`. For logs, not for the user. */
    public readonly idpErrorDescription?: string,
  ) {
    super(`OIDC callback rejected: ${reason}`);
    this.name = 'CallbackValidationError';
  }
}

export interface CreateTransactionOptions {
  returnTo?: string | null;
  /** Where a dropped `returnTo` is reported. */
  logger: FidesLogger;
}

export interface TransactionCookieOptions {
  /** A Secure, `__Host-` prefixed cookie. Turn off only for plain-http development. @default true */
  secure?: boolean;
}

export interface ReadTransactionOptions extends TransactionCookieOptions {
  /** Where an unreadable transaction cookie is reported. */
  logger: FidesLogger;
}

export interface ValidateCallbackOptions {
  /** @default 600000 (10 minutes) */
  maxAgeMs?: number;
}

/** Starts a login transaction from the authorization request sent to the provider. */
export function createTransaction(
  request: Pick<AuthorizationRequest, 'state' | 'codeVerifier'> &
    Partial<Pick<AuthorizationRequest, 'parameters'>>,
  { returnTo, logger }: CreateTransactionOptions,
): LoginTransaction {
  let kept = returnTo || undefined;
  if (kept && new TextEncoder().encode(JSON.stringify(kept)).length > MAX_RETURN_TO_BYTES) {
    logger.warn({ length: kept.length }, 'returnTo too long, dropped');
    kept = undefined;
  }
  const scope = request.parameters?.scope;
  return {
    state: request.state,
    codeVerifier: request.codeVerifier,
    ...(kept ? { returnTo: kept } : {}),
    ...(typeof scope === 'string' && scope ? { scope } : {}),
    createdAt: Date.now(),
  };
}

/**
 * Seals the transaction into a random free `__Host-oauth_tx_<n>` slot, or the
 * oldest login's. Throws `CookieTooLargeError` if it would not fit in a cookie.
 */
export async function persistTransaction(
  cookies: CookieStore,
  transaction: LoginTransaction,
  secret: SessionSecret,
  { secure = true }: TransactionCookieOptions = {},
): Promise<void> {
  const key = await transactionKey(secret);
  const slots = await readSlots(cookies, key, secure);
  const free = slots.filter((candidate) => !candidate.transaction);
  // A random free slot, so two logins started at the same moment rarely share one.
  const slot =
    free[Math.floor(Math.random() * free.length)] ??
    slots.reduce((oldest, candidate) =>
      (candidate.transaction?.createdAt ?? 0) < (oldest.transaction?.createdAt ?? 0)
        ? candidate
        : oldest,
    );

  const value = await createEncryptedJWT(transaction, key);
  assertCookieWithinLimit(slot.name, value);
  await cookies.set(slot.name, value, { ...defaultOAuthCookieOptions, secure });
}

/** The transaction for `state`, or null when none is stored or it does not open under `secret`. */
export async function readTransaction(
  cookies: CookieStore,
  state: string,
  secret: SessionSecret,
  { secure = true, logger }: ReadTransactionOptions,
): Promise<LoginTransaction | null> {
  const slots = await readSlots(cookies, await transactionKey(secret), secure);
  const match = findSlot(slots, state);
  if (match) return match.transaction;

  if (slots.some((slot) => slot.value && !slot.transaction)) {
    // Usually a different secret at login and callback.
    logger.warn('Unreadable login transaction cookie');
  }
  return null;
}

/** Deletes the transaction cookie for `state`, leaving other logins alone. */
export async function clearTransaction(
  cookies: CookieStore,
  state: string,
  secret: SessionSecret,
  { secure = true }: TransactionCookieOptions = {},
): Promise<void> {
  const match = findSlot(await readSlots(cookies, await transactionKey(secret), secure), state);
  if (!match) return;
  // With the attributes it was set with: a delete that isn't Secure is ignored for a __Host- cookie.
  await cookies.set(match.name, '', { ...defaultOAuthCookieOptions, secure, maxAge: 0 });
}

/** What the handlers use: Secure and `__Host-` unless the callback is plain http. */
export function transactionCookieOptions(redirectUri: string): TransactionCookieOptions {
  return { secure: !/^http:/i.test(redirectUri) };
}

/**
 * Checks the callback query against its transaction and returns the authorization
 * code. Throws {@link CallbackValidationError}.
 */
export function validateCallback(
  query: URLSearchParams,
  transaction: LoginTransaction,
  { maxAgeMs = DEFAULT_MAX_AGE_MS }: ValidateCallbackOptions = {},
): string {
  // Is this our login, and still live? Only then trust what the IdP sent.
  if (!timingSafeEqual(query.get('state') ?? '', transaction.state)) {
    throw new CallbackValidationError('state_mismatch');
  }
  if (Date.now() - transaction.createdAt > maxAgeMs) {
    throw new CallbackValidationError('transaction_expired');
  }

  const error = query.get('error');
  if (error !== null) {
    throw new CallbackValidationError(
      'idp_error',
      error,
      query.get('error_description') ?? undefined,
    );
  }

  const code = query.get('code');
  if (!code) {
    throw new CallbackValidationError('missing_code');
  }
  return code;
}

/** A key of its own, so a transaction and a session never share one. */
function transactionKey(secret: SessionSecret): Promise<Uint8Array> {
  return deriveKey(secret, KEY_INFO);
}

interface Slot {
  name: string;
  value: string | null | undefined;
  transaction: LoginTransaction | null;
}

async function readSlots(cookies: CookieStore, key: Uint8Array, secure: boolean): Promise<Slot[]> {
  const prefix = secure ? HOST_PREFIX : '';
  const names = Array.from({ length: MAX_TRANSACTIONS }, (_, i) => `${prefix}${COOKIE_NAME}${i}`);
  return Promise.all(
    names.map(async (name) => {
      const value = await cookies.get(name);
      return { name, value, transaction: value ? await open(value, key) : null };
    }),
  );
}

function findSlot(slots: Slot[], state: string) {
  for (const { name, transaction } of slots) {
    if (transaction && timingSafeEqual(state, transaction.state)) {
      return { name, transaction };
    }
  }
  return undefined;
}

/** The sealed transaction, or null when the value is forged, malformed or under another key. */
async function open(value: string, key: Uint8Array): Promise<LoginTransaction | null> {
  try {
    const sealed = await decryptJWT(value, key);
    if (
      typeof sealed.state === 'string' &&
      typeof sealed.codeVerifier === 'string' &&
      typeof sealed.createdAt === 'number' &&
      (sealed.returnTo === undefined || typeof sealed.returnTo === 'string') &&
      (sealed.scope === undefined || typeof sealed.scope === 'string')
    ) {
      return {
        state: sealed.state,
        codeVerifier: sealed.codeVerifier,
        returnTo: sealed.returnTo,
        scope: sealed.scope,
        createdAt: sealed.createdAt,
      };
    }
  } catch {
    // Treated as an empty slot.
  }
  return null;
}

/** Compares in time that depends only on the expected value's length. */
function timingSafeEqual(received: string, expected: string): boolean {
  const encoder = new TextEncoder();
  const a = encoder.encode(received);
  const b = encoder.encode(expected);
  let diff = a.length ^ b.length;
  for (let i = 0; i < b.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
