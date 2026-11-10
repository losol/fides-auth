/**
 * Tests for the OIDC login handler — focused on the login transaction cookie.
 * The OAuth machinery is mocked (tested elsewhere).
 */
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

vi.mock('../oauth', () => ({
  buildPKCEOptions: vi.fn(),
  discoverAndBuildAuthorizationUrl: vi.fn(),
}));

import { handleOidcLogin } from './oidc-login';
import { buildPKCEOptions, discoverAndBuildAuthorizationUrl } from '../oauth';
import type { CookieOptions } from '../cookies';
import type { CookieStore } from './cookie-store';
import { readTransaction } from './login-transaction';

const mockedPkce = vi.mocked(buildPKCEOptions);
const mockedAuthUrl = vi.mocked(discoverAndBuildAuthorizationUrl);

const secret = 'a'.repeat(64);

function memoryStore() {
  const jar = new Map<string, string>();
  const options = new Map<string, CookieOptions | undefined>();
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value, opts) => {
      jar.set(name, value);
      options.set(name, opts);
    },
    delete: (name) => { jar.delete(name); },
  };
  return { store, jar, options };
}

const oauthConfig = {
  issuer: 'https://id.example.test',
  clientId: 'web',
  clientSecret: 'shh',
  redirect_uri: 'https://app.test/api/auth/callback/oidc',
  scope: 'openid',
};

const login = (store: CookieStore, query = '') =>
  handleOidcLogin(new Request(`https://app.test/api/auth/login${query}`), {
    oauthConfig,
    cookies: store,
    secret,
  });

beforeEach(() => {
  vi.clearAllMocks();
  mockedPkce.mockResolvedValue({ state: 'st', code_verifier: 'cv' } as any);
  mockedAuthUrl.mockResolvedValue(new URL('https://id.example.test/authorize?x=1'));
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('handleOidcLogin', () => {
  it('seals the login transaction and redirects to the authorization endpoint', async () => {
    const { store, jar, options } = memoryStore();
    const response = await login(store);

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://id.example.test/authorize?x=1');
    expect([...jar.keys()]).toEqual(['__Host-oauth_tx_0']);
    expect(options.get('__Host-oauth_tx_0')).toEqual({
      path: '/',
      maxAge: 600,
      sameSite: 'lax',
      httpOnly: true,
      secure: true,
    });

    const transaction = await readTransaction(store, 'st', secret);
    expect(transaction).toMatchObject({ state: 'st', codeVerifier: 'cv' });
    expect(transaction?.returnTo).toBeUndefined();
  });

  it('uses a plain, non-Secure cookie when the redirect_uri is http', async () => {
    const { store, options } = memoryStore();
    await handleOidcLogin(new Request('http://dev.test/api/auth/login'), {
      oauthConfig: { ...oauthConfig, redirect_uri: 'http://dev.test/api/auth/callback/oidc' },
      cookies: store,
      secret,
    });

    expect([...options.keys()]).toEqual(['oauth_tx_0']);
    expect(options.get('oauth_tx_0')?.secure).toBe(false);
    expect(await readTransaction(store, 'st', secret, { secure: false })).not.toBeNull();
  });

  it('seals a valid returnTo into the transaction', async () => {
    const { store } = memoryStore();
    await login(store, '?returnTo=%2Fdash');

    expect((await readTransaction(store, 'st', secret))?.returnTo).toBe('/dash');
  });

  it('drops an invalid returnTo', async () => {
    const { store } = memoryStore();
    await login(store, '?returnTo=%2F%2Fevil.example');

    expect((await readTransaction(store, 'st', secret))?.returnTo).toBeUndefined();
  });

  it('gives parallel logins their own transaction', async () => {
    const { store, jar } = memoryStore();
    mockedPkce
      .mockResolvedValueOnce({ state: 'one', code_verifier: 'cv1' } as any)
      .mockResolvedValueOnce({ state: 'two', code_verifier: 'cv2' } as any);

    await login(store, '?returnTo=%2Fa');
    await login(store, '?returnTo=%2Fb');

    expect(jar.size).toBe(2);
    expect((await readTransaction(store, 'one', secret))?.returnTo).toBe('/a');
    expect((await readTransaction(store, 'two', secret))?.returnTo).toBe('/b');
  });

  it('keeps at most three logins in progress', async () => {
    const { store, jar } = memoryStore();
    for (const state of ['one', 'two', 'three', 'four']) {
      mockedPkce.mockResolvedValueOnce({ state, code_verifier: `cv-${state}` } as any);
      await login(store);
    }

    expect(jar.size).toBe(3);
    expect(await readTransaction(store, 'four', secret)).not.toBeNull();
  });

  it('drops a returnTo over 1 KB but still starts the login', async () => {
    const { store } = memoryStore();
    await login(store, `?returnTo=%2F${'a'.repeat(1100)}`);

    const transaction = await readTransaction(store, 'st', secret);
    expect(transaction).not.toBeNull();
    expect(transaction?.returnTo).toBeUndefined();
  });

  it('defaults the secret to SESSION_SECRET', async () => {
    vi.stubEnv('SESSION_SECRET', secret);
    const { store } = memoryStore();

    await handleOidcLogin(new Request('https://app.test/api/auth/login'), {
      oauthConfig,
      cookies: store,
    });

    expect(await readTransaction(store, 'st', secret)).not.toBeNull();
  });

  it('returns 429 when rate-limited, without touching cookies', async () => {
    const { store, jar } = memoryStore();
    const response = await handleOidcLogin(new Request('https://app.test/api/auth/login'), {
      oauthConfig,
      cookies: store,
      rateLimit: async () => false,
    });

    expect(response.status).toBe(429);
    expect(jar.size).toBe(0);
    expect(mockedPkce).not.toHaveBeenCalled();
  });
});
