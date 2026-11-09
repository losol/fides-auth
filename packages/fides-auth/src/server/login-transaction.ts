// server/login-transaction.ts
//
// One login between the authorize redirect and the callback: state, PKCE
// verifier, returnTo and start time, sealed into a cookie named by a hash of
// the state, so parallel logins in one browser don't overwrite each other.

import { defaultOAuthCookieOptions } from '../cookies';
import { createLogger } from '../logger';
import type { PKCEOptions } from '../oauth';
import { createEncryptedJWT, decryptJWT, sha256 } from '../utils';
import type { CookieStore } from './cookie-store';
import type { SessionSecret } from './session-persistence';

const logger = createLogger({ namespace: 'fides-auth:server:login-transaction' });

const COOKIE_PREFIX = 'oauth_tx_';

const DEFAULT_MAX_AGE_MS = 10 * 60 * 1000;

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

export interface ValidateCallbackOptions {
  /** @default 600000 (10 minutes) */
  maxAgeMs?: number;
}

/** Starts a login transaction from the PKCE parameters sent to the authorize endpoint. */
export function createTransaction(
  pkce: Pick<PKCEOptions, 'state' | 'code_verifier'>,
  { returnTo }: CreateTransactionOptions = {},
): LoginTransaction {
  return {
    state: pkce.state,
    codeVerifier: pkce.code_verifier,
    ...(returnTo ? { returnTo } : {}),
    createdAt: Date.now(),
  };
}

/** Seals the transaction into its own `oauth_tx_<hash>` cookie. */
export async function persistTransaction(
  cookies: CookieStore,
  transaction: LoginTransaction,
  secret: SessionSecret,
): Promise<void> {
  const value = await createEncryptedJWT(transaction, secret);
  await cookies.set(await cookieName(transaction.state), value, defaultOAuthCookieOptions);
}

/** The transaction for `state`, or null when it is missing or does not open under `secret`. */
export async function readTransaction(
  cookies: CookieStore,
  state: string,
  secret: SessionSecret,
): Promise<LoginTransaction | null> {
  const name = await cookieName(state);
  const value = await cookies.get(name);
  if (!value) return null;

  try {
    const sealed = await decryptJWT(value, secret);
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
    logger.warn({ cookieName: name }, 'Malformed login transaction cookie');
  } catch (error) {
    // Usually a different secret at login and callback.
    logger.warn({ error, cookieName: name }, 'Unreadable login transaction cookie');
  }
  return null;
}

/** Deletes the transaction cookie for `state`. */
export async function clearTransaction(cookies: CookieStore, state: string): Promise<void> {
  await cookies.delete(await cookieName(state));
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

async function cookieName(state: string): Promise<string> {
  return COOKIE_PREFIX + (await sha256(state)).slice(0, 32);
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
