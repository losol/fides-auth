/**
 * Tests for the login transaction: the sealed per-login cookie and the callback
 * checks run against it.
 */
import { describe, it, expect } from 'vitest';

import type { CookieStore } from './cookie-store';
import {
  CallbackValidationError,
  clearTransaction,
  createTransaction,
  persistTransaction,
  readTransaction,
  validateCallback,
  type LoginTransaction,
} from './login-transaction';

const secret = 'a'.repeat(64);

function memoryStore() {
  const jar = new Map<string, string>();
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value) => { jar.set(name, value); },
    delete: (name) => { jar.delete(name); },
  };
  return { store, jar };
}

const pkce = (state: string) => ({ state, code_verifier: `verifier-for-${state}` });

/** The rejection reason, or undefined when validateCallback returns. */
function rejection(query: string, transaction: LoginTransaction, maxAgeMs?: number) {
  try {
    validateCallback(new URLSearchParams(query), transaction, { maxAgeMs });
    return undefined;
  } catch (error) {
    expect(error).toBeInstanceOf(CallbackValidationError);
    return error as CallbackValidationError;
  }
}

describe('login transaction cookie', () => {
  it('seals one cookie per login and reads it back by state', async () => {
    const { store, jar } = memoryStore();
    const transaction = createTransaction(pkce('st'), { returnTo: '/dash' });

    await persistTransaction(store, transaction, secret);

    const names = [...jar.keys()];
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/^oauth_tx_[0-9a-f]{32}$/);
    expect(jar.get(names[0]!)).not.toContain('verifier-for-st');
    expect(await readTransaction(store, 'st', secret)).toEqual(transaction);
  });

  it('keeps parallel logins apart', async () => {
    const { store, jar } = memoryStore();
    await persistTransaction(store, createTransaction(pkce('one')), secret);
    await persistTransaction(store, createTransaction(pkce('two')), secret);
    expect(jar.size).toBe(2);

    await clearTransaction(store, 'one');

    expect(await readTransaction(store, 'one', secret)).toBeNull();
    expect((await readTransaction(store, 'two', secret))?.codeVerifier).toBe('verifier-for-two');
  });

  it('returns null for a missing, tampered or foreign-secret cookie', async () => {
    const { store, jar } = memoryStore();
    expect(await readTransaction(store, 'st', secret)).toBeNull();

    await persistTransaction(store, createTransaction(pkce('st')), secret);
    expect(await readTransaction(store, 'st', 'b'.repeat(64))).toBeNull();

    const [name, value] = [...jar.entries()][0]!;
    jar.set(name, `${value.slice(0, -4)}AAAA`);
    expect(await readTransaction(store, 'st', secret)).toBeNull();
  });
});

describe('validateCallback', () => {
  const transaction = createTransaction(pkce('st'));

  it('returns the code', () => {
    expect(validateCallback(new URLSearchParams('code=abc&state=st'), transaction)).toBe('abc');
  });

  it('rejects a missing or different state before reading the response', () => {
    expect(rejection('code=abc', transaction)?.reason).toBe('state_mismatch');
    expect(rejection('code=abc&state=s', transaction)?.reason).toBe('state_mismatch');
    expect(rejection('error=access_denied&state=other', transaction)?.reason).toBe(
      'state_mismatch',
    );
  });

  it('rejects a transaction older than maxAgeMs (default 10 minutes)', () => {
    const at = (ageMs: number) => ({ ...transaction, createdAt: Date.now() - ageMs });

    expect(rejection('code=abc&state=st', at(9 * 60_000))).toBeUndefined();
    expect(rejection('code=abc&state=st', at(11 * 60_000))?.reason).toBe('transaction_expired');
    expect(rejection('code=abc&state=st', at(11 * 60_000), 15 * 60_000)).toBeUndefined();
  });

  it('reports an IdP error with its description', () => {
    const error = rejection(
      'error=access_denied&error_description=User%20cancelled&state=st',
      transaction,
    );

    expect(error?.reason).toBe('idp_error');
    expect(error?.idpError).toBe('access_denied');
    expect(error?.idpErrorDescription).toBe('User cancelled');
  });

  it('rejects a callback without a code', () => {
    expect(rejection('state=st', transaction)?.reason).toBe('missing_code');
  });
});
