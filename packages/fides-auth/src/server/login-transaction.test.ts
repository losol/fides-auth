/**
 * Tests for the login transaction: the sealed per-login cookie and the callback
 * checks run against it.
 */
import { describe, it, expect } from 'vitest';

import { CookieTooLargeError } from '../cookies';
import { decryptJWT } from '../utils';
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
import { tryReadSession } from './session';

const secret = 'a'.repeat(64);

function memoryStore(initial?: Record<string, string>) {
  const jar = new Map<string, string>(Object.entries(initial ?? {}));
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
    expect(names[0]).toBe('oauth_tx_0');
    expect(jar.get(names[0]!)).not.toContain('verifier-for-st');
    expect(await readTransaction(store, 'st', secret)).toEqual(transaction);
  });

  it('is sealed under its own key, so it never opens as a session', async () => {
    const { store, jar } = memoryStore();
    await persistTransaction(store, createTransaction(pkce('st')), secret);
    const [value] = [...jar.values()];

    await expect(decryptJWT(value!, secret)).rejects.toThrow();
    const { store: forged } = memoryStore({ session: value! });
    expect(await tryReadSession(forged, secret)).toEqual({
      session: null,
      reason: 'unreadable_session',
    });
  });

  it('keeps parallel logins apart', async () => {
    const { store, jar } = memoryStore();
    await persistTransaction(store, createTransaction(pkce('one')), secret);
    await persistTransaction(store, createTransaction(pkce('two')), secret);
    expect(jar.size).toBe(2);

    await clearTransaction(store, 'one', secret);
    await clearTransaction(store, 'unknown', secret);

    expect(jar.size).toBe(1);
    expect(await readTransaction(store, 'one', secret)).toBeNull();
    expect((await readTransaction(store, 'two', secret))?.codeVerifier).toBe('verifier-for-two');
  });

  it('keeps at most three logins, evicting the oldest', async () => {
    const { store, jar } = memoryStore();
    const startedAt = { a: 4000, b: 1000, c: 3000, d: 5000 };
    for (const [state, createdAt] of Object.entries(startedAt)) {
      await persistTransaction(store, { ...createTransaction(pkce(state)), createdAt }, secret);
    }

    expect([...jar.keys()].sort()).toEqual(['oauth_tx_0', 'oauth_tx_1', 'oauth_tx_2']);
    expect(await readTransaction(store, 'b', secret)).toBeNull();
    for (const state of ['a', 'c', 'd']) {
      expect(await readTransaction(store, state, secret)).not.toBeNull();
    }
  });

  it('reuses a slot holding an unreadable cookie', async () => {
    const { store, jar } = memoryStore({ oauth_tx_0: 'garbage' });

    await persistTransaction(store, createTransaction(pkce('st')), secret);

    expect(jar.size).toBe(1);
    expect(await readTransaction(store, 'st', secret)).not.toBeNull();
  });

  it('drops a returnTo over 1 KB', () => {
    const fits = `/${'a'.repeat(1023)}`;
    expect(createTransaction(pkce('st'), { returnTo: fits }).returnTo).toBe(fits);
    expect(createTransaction(pkce('st'), { returnTo: `${fits}a` }).returnTo).toBeUndefined();
  });

  it('refuses to store a transaction too large for a cookie', async () => {
    const { store, jar } = memoryStore();
    const huge = { ...createTransaction(pkce('st')), returnTo: `/${'a'.repeat(4000)}` };

    await expect(persistTransaction(store, huge, secret)).rejects.toBeInstanceOf(
      CookieTooLargeError,
    );
    expect(jar.size).toBe(0);
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
