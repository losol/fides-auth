/**
 * Regression test for the proxy callback-path bug.
 *
 * Behind a TLS-terminating proxy `applicationUrl` is just the origin, so the
 * reconstructed callback URL must take its path from the incoming request. If it
 * doesn't, the token-exchange redirect_uri collapses to "/" and Keycloak rejects
 * it with invalid_redirect_uri (Auth0 tolerated the mismatch).
 *
 * The OAuth machinery (tested elsewhere) is mocked; we assert on the URL handed
 * to exchangeAuthorizationCode and that the session is persisted via the store.
 */
import { vi, describe, it, expect, beforeEach, afterAll } from 'vitest';

vi.mock('../oauth', () => ({
  exchangeAuthorizationCode: vi.fn(),
  buildSessionFromTokens: vi.fn(),
  validateReturnUrl: vi.fn(),
}));

import { handleOidcCallback } from './oidc-callback';
import {
  exchangeAuthorizationCode,
  buildSessionFromTokens,
  validateReturnUrl,
} from '../oauth';
import type { CookieOptions } from '../cookies';
import type { CookieStore } from './cookie-store';
import {
  createTransaction,
  persistTransaction,
  readTransaction,
  type LoginTransaction,
} from './login-transaction';
import { transactionCookieOptions } from './index';
import { serverPersistence } from './session-persistence';
import { createMemorySessionStore } from './session-store';
import { sha256 } from '../utils';

const mockedExchange = vi.mocked(exchangeAuthorizationCode);
const mockedBuildSession = vi.mocked(buildSessionFromTokens);
const mockedValidateReturnUrl = vi.mocked(validateReturnUrl);

const secret = 'a'.repeat(64);

/** Records options and, like a browser, ignores a plain (non-Secure) delete of a __Host- cookie. */
function memoryStore() {
  const jar = new Map<string, string>();
  const options = new Map<string, CookieOptions | undefined>();
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value, opts) => {
      if (opts?.maxAge === 0) jar.delete(name);
      else jar.set(name, value);
      options.set(name, opts);
    },
    delete: (name) => {
      if (!name.startsWith('__Host-')) jar.delete(name);
    },
  };
  return { store, jar, options };
}

/** Starts a login the way handleOidcLogin does: a sealed transaction for `state`. */
async function startLogin(
  store: CookieStore,
  state = 'xyz',
  overrides: Partial<LoginTransaction> = {},
) {
  const transaction = createTransaction({ state, code_verifier: 'verifier' });
  await persistTransaction(store, { ...transaction, ...overrides }, secret);
}

const transactionCookies = (jar: Map<string, string>) =>
  [...jar.keys()].filter((name) => name.includes('oauth_tx_'));

const callback = (query: string) =>
  new Request(`http://internal/api/auth/callback/oidc?${query}`);

const baseConfig = (store: CookieStore) => ({
  oauthConfig: {
    issuer: 'https://id.example.test/realms/test',
    clientId: 'web',
    clientSecret: 'shh',
    redirect_uri: 'https://host.example.test/api/auth/callback/oidc',
    scope: 'openid',
  },
  // Public origin only — no path — as seen behind a TLS-terminating proxy.
  applicationUrl: 'https://host.example.test',
  cookies: store,
  rateLimit: async () => true,
  secret,
});

// The first free transaction slot.
const random = vi.spyOn(Math, 'random');

beforeEach(() => {
  vi.clearAllMocks();
  random.mockReturnValue(0);
  mockedExchange.mockResolvedValue({ accessToken: 'a' } as any);
  mockedBuildSession.mockReturnValue({ tokens: { accessToken: 'a' } } as any);
  mockedValidateReturnUrl.mockReturnValue(new URL('https://host.example.test/'));
});

afterAll(() => {
  random.mockRestore();
});

describe('handleOidcCallback — proxy callback path', () => {
  it('passes the full callback path and https scheme to the token exchange', async () => {
    const { store, jar, options } = memoryStore();
    await startLogin(store);
    // Internal hop arrives over http at the callback path with the auth code.
    const response = await handleOidcCallback(callback('code=abc&state=xyz'), baseConfig(store));

    expect(response.status).toBe(302);
    expect(mockedExchange).toHaveBeenCalledTimes(1);

    const [, passedUrl, codeVerifier, expectedState] = mockedExchange.mock.calls[0]!;
    expect(passedUrl.pathname).toBe('/api/auth/callback/oidc');
    expect(passedUrl.protocol).toBe('https:');
    expect(passedUrl.host).toBe('host.example.test');
    expect(passedUrl.searchParams.get('code')).toBe('abc');
    expect(codeVerifier).toBe('verifier');
    expect(expectedState).toBe('xyz');

    // The session is persisted and the login transaction is spent.
    expect(jar.has('session')).toBe(true);
    expect(transactionCookies(jar)).toEqual([]);
    expect(options.get('__Host-oauth_tx_0')).toMatchObject({ secure: true, maxAge: 0 });
  });
});

describe('handleOidcCallback — session options', () => {
  it('passes rolesClaim and mapSession to buildSessionFromTokens', async () => {
    const { store } = memoryStore();
    await startLogin(store);
    const mapSession = vi.fn();

    const response = await handleOidcCallback(callback('code=abc&state=xyz'), {
      ...baseConfig(store),
      rolesClaim: 'groups',
      mapSession,
    });

    expect(response.status).toBe(302);
    expect(mockedBuildSession).toHaveBeenCalledWith(
      { accessToken: 'a' },
      { rolesClaim: 'groups', mapSession },
    );
  });
});

describe('handleOidcCallback — guards', () => {
  it('rejects an empty secret before reading the transaction', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store);

    await expect(
      handleOidcCallback(callback('code=abc&state=xyz'), { ...baseConfig(store), secret: '' }),
    ).rejects.toThrow('fides-auth: session secret is missing or empty');
    expect(mockedExchange).not.toHaveBeenCalled();
    expect(transactionCookies(jar)).toHaveLength(1);
  });

  it('returns 429 when rate-limited', async () => {
    const { store } = memoryStore();

    const response = await handleOidcCallback(callback('code=abc&state=xyz'), {
      ...baseConfig(store),
      rateLimit: async () => false,
    });

    expect(response.status).toBe(429);
    expect(mockedExchange).not.toHaveBeenCalled();
  });

  it('returns 400 when there is no login transaction', async () => {
    const { store } = memoryStore();

    const response = await handleOidcCallback(callback('code=abc&state=xyz'), baseConfig(store));

    expect(response.status).toBe(400);
    expect(mockedExchange).not.toHaveBeenCalled();
  });

  it('returns 400 for an unknown state and leaves other logins alone', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store, 'xyz');

    const response = await handleOidcCallback(callback('code=abc&state=forged'), baseConfig(store));

    expect(response.status).toBe(400);
    expect(mockedExchange).not.toHaveBeenCalled();
    expect(transactionCookies(jar)).toHaveLength(1);
  });

  it('returns 400 for an expired transaction and clears it', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store, 'xyz', { createdAt: Date.now() - 11 * 60_000 });

    const response = await handleOidcCallback(callback('code=abc&state=xyz'), baseConfig(store));

    expect(response.status).toBe(400);
    expect(mockedExchange).not.toHaveBeenCalled();
    expect(transactionCookies(jar)).toEqual([]);
  });

  it('returns 400 for a callback without a code and clears the transaction', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store);

    const response = await handleOidcCallback(callback('state=xyz'), baseConfig(store));

    expect(response.status).toBe(400);
    expect(transactionCookies(jar)).toEqual([]);
  });
});

describe('handleOidcCallback — login transaction', () => {
  it('redirects to the returnTo sealed in the transaction', async () => {
    const { store } = memoryStore();
    await startLogin(store, 'xyz', { returnTo: '/dash' });

    await handleOidcCallback(callback('code=abc&state=xyz'), baseConfig(store));

    expect(mockedValidateReturnUrl).toHaveBeenCalledWith(
      '/dash',
      'https://host.example.test',
      '/',
      undefined,
    );
  });

  it('pairs a custom login using transactionCookieOptions with an http callback', async () => {
    const { store, jar } = memoryStore();
    const config = baseConfig(store);
    config.oauthConfig.redirect_uri = 'http://dev.test/api/auth/callback/oidc';
    const transaction = createTransaction({ state: 'xyz', code_verifier: 'verifier' });
    await persistTransaction(
      store,
      transaction,
      secret,
      transactionCookieOptions(config.oauthConfig.redirect_uri),
    );
    expect(transactionCookies(jar)).toEqual(['oauth_tx_0']);

    const response = await handleOidcCallback(callback('code=abc&state=xyz'), config);

    expect(response.status).toBe(302);
    expect(transactionCookies(jar)).toEqual([]);
  });

  it('completes one of two parallel logins without touching the other', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store, 'one');
    await startLogin(store, 'two');

    const response = await handleOidcCallback(callback('code=abc&state=one'), baseConfig(store));

    expect(response.status).toBe(302);
    expect(transactionCookies(jar)).toHaveLength(1);
    expect(await readTransaction(store, 'two', secret)).not.toBeNull();
  });
});

describe('handleOidcCallback — IdP errors and cleanup', () => {
  it('redirects an IdP error to the default path with only the error code', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store, 'xyz', { returnTo: '/dash' });

    const response = await handleOidcCallback(
      callback('error=access_denied&error_description=User%20cancelled&state=xyz'),
      baseConfig(store),
    );

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location')!);
    expect(location.origin + location.pathname).toBe('https://host.example.test/');
    expect(location.searchParams.get('login')).toBe('error');
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.search).not.toContain('cancelled');
    expect(mockedExchange).not.toHaveBeenCalled();
    expect(transactionCookies(jar)).toEqual([]);
  });

  it.each([
    ['"><script>', 'idp_error'],
    ['<img src=x onerror=alert(1)>', 'idp_error'],
    ['ACCESS_DENIED', 'idp_error'],
    ['a'.repeat(65), 'idp_error'],
    ['a'.repeat(64), 'a'.repeat(64)],
    ['login_required', 'login_required'],
  ])('passes on error=%s as %s', async (code, expected) => {
    const { store } = memoryStore();
    await startLogin(store);

    const response = await handleOidcCallback(
      callback(`error=${encodeURIComponent(code)}&state=xyz`),
      { ...baseConfig(store), defaultRedirectPath: '/welcome' },
    );

    const location = new URL(response.headers.get('Location')!);
    expect(location.pathname).toBe('/welcome');
    expect(location.searchParams.get('error')).toBe(expected);
  });

  it.each([
    ['whose state matches no login', 'error=access_denied&state=xyz'],
    ['without a state', 'error=access_denied'],
  ])('redirects an IdP error %s with a fixed code', async (_, query) => {
    const { store } = memoryStore();

    const response = await handleOidcCallback(callback(query), baseConfig(store));

    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('Location')!);
    expect(location.searchParams.get('login')).toBe('error');
    expect(location.searchParams.get('error')).toBe('login_expired');
  });

  it('redirects an IdP error on an expired transaction with a fixed code', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store, 'xyz', { createdAt: Date.now() - 11 * 60_000 });

    const response = await handleOidcCallback(
      callback('error=access_denied&state=xyz'),
      baseConfig(store),
    );

    expect(response.status).toBe(302);
    expect(new URL(response.headers.get('Location')!).searchParams.get('error')).toBe(
      'login_expired',
    );
    expect(mockedExchange).not.toHaveBeenCalled();
    expect(transactionCookies(jar)).toEqual([]);
  });

  it('clears the transaction when the code exchange fails', async () => {
    const { store, jar } = memoryStore();
    await startLogin(store);
    mockedExchange.mockRejectedValue(new Error('invalid_grant'));

    const response = await handleOidcCallback(callback('code=abc&state=xyz'), baseConfig(store));

    expect(response.status).toBe(500);
    expect(transactionCookies(jar)).toEqual([]);
  });
});

describe('handleOidcCallback — server persistence', () => {
  it('stores the session and gives the browser a handle, not the session', async () => {
    const store = createMemorySessionStore();
    const persistence = serverPersistence({ store, secret });
    const { store: cookies, jar } = memoryStore();
    await startLogin(cookies);
    mockedBuildSession.mockReturnValue({ sid: 'sid-1', tokens: { accessToken: 'a' } } as any);
    const request = new Request('https://host.example.test/api/auth/callback/oidc?code=abc&state=xyz');

    const response = await handleOidcCallback(request, { ...baseConfig(cookies), persistence });

    expect(response.status).toBe(302);
    expect(jar.has('session')).toBe(false);
    expect(jar.has('session_at')).toBe(false);
    const handle = jar.get('session_ref');
    expect(handle).toBeDefined();
    expect((await store.get(await sha256(handle!)))?.sid).toBe('sid-1');
  });
});
