// server/login-transaction.ts
//
// One login between the authorize redirect and the callback: state, PKCE
// verifier, returnTo and start time, sealed into one of a few cookie slots, so
// parallel logins in one browser neither overwrite each other nor pile up. It is
// sealed under a key derived from the secret, so it never opens as a session.

import { assertCookieWithinLimit, defaultOAuthCookieOptions } from '../cookies';
import { createLogger } from '../logger';
import type { PKCEOptions } from '../oauth';
import { createEncryptedJWT, decryptJWT, hexToUint8Array } from '../utils';
import type { CookieStore } from './cookie-store';
import { assertSessionSecret, type SessionSecret } from './session-persistence';

const logger = createLogger({ namespace: 'fides-auth:server:login-transaction' });

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
}

export interface TransactionCookieOptions {
  /** A Secure, `__Host-` prefixed cookie. Turn off only for plain-http development. @default true */
  secure?: boolean;
}

export interface ValidateCallbackOptions {
  /** @default 600000 (10 minutes) */
  maxAgeMs?: number;
}

/** Starts a login transaction from the PKCE parameters sent to the authorize endpoint. */
export function createTransaction(
  pkce: Pick<PKCEOptions, 'state' | 'code_verifier'>,
  { returnTo }: CreateTransactionOptions = {},
): LoginTransaction {
  let kept = returnTo || undefined;
  if (kept && new TextEncoder().encode(JSON.stringify(kept)).length > MAX_RETURN_TO_BYTES) {
    logger.warn({ length: kept.length }, 'returnTo too long, dropped');
    kept = undefined;
  }
  return {
    state: pkce.state,
    codeVerifier: pkce.code_verifier,
    ...(kept ? { returnTo: kept } : {}),
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
  { secure = true }: TransactionCookieOptions = {},
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
  if (secure) {
    // A plain delete is not Secure, and the browser ignores it for a __Host- cookie.
    await cookies.set(match.name, '', { ...defaultOAuthCookieOptions, secure, maxAge: 0 });
  } else {
    await cookies.delete(match.name);
  }
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

/** HKDF-SHA-256 of the secret, so a transaction and a session never share a key. */
async function transactionKey(secret: SessionSecret): Promise<Uint8Array> {
  // HKDF takes a key of any length; the session encryption doesn't.
  assertSessionSecret(secret);
  const ikm = typeof secret === 'string' ? hexToUint8Array(secret) : secret;
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode(KEY_INFO) },
    base,
    256,
  );
  return new Uint8Array(bits);
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
      (sealed.returnTo === undefined || typeof sealed.returnTo === 'string')
    ) {
      return {
        state: sealed.state,
        codeVerifier: sealed.codeVerifier,
        returnTo: sealed.returnTo,
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
