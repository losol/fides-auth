/**
 * Tests for the OIDC login handler — focused on the login transaction cookie.
 * The OAuth machinery is mocked (tested elsewhere).
 */
import { vi, describe, it, expect, beforeEach, afterEach, afterAll } from 'vitest';

vi.mock('../oauth', () => ({
  buildPKCEOptions: vi.fn(),
  discoverAndBuildAuthorizationUrl: vi.fn(),
}));

import { handleOidcLogin } from './oidc-login';
import { buildPKCEOptions, discoverAndBuildAuthorizationUrl } from '../oauth';
import { CookieTooLargeError, type CookieOptions } from '../cookies';
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

// The first free transaction slot, unless a test draws otherwise.
const random = vi.spyOn(Math, 'random');

beforeEach(() => {
  vi.clearAllMocks();
  random.mockReturnValue(0);
  mockedPkce.mockResolvedValue({ state: 'st', code_verifier: 'cv' } as any);
  mockedAuthUrl.mockResolvedValue(new URL('https://id.example.test/authorize?x=1'));
});

afterEach(() => {
  vi.unstubAllEnvs();
});

afterAll(() => {
  random.mockRestore();
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

  it('lets two logins started at the same moment both complete', async () => {
    // Both requests carry the same empty Cookie header; the browser keeps both responses.
    const browser = new Map<string, string>();
    const request = (): CookieStore => ({
      get: () => null,
      set: (name, value) => { browser.set(name, value); },
      delete: (name) => { browser.delete(name); },
    });
    mockedPkce
      .mockResolvedValueOnce({ state: 'one', code_verifier: 'cv1' } as any)
      .mockResolvedValueOnce({ state: 'two', code_verifier: 'cv2' } as any);
    random.mockReturnValueOnce(0).mockReturnValueOnce(0.5);

    await Promise.all([login(request()), login(request())]);

    const { store } = memoryStore();
    for (const [name, value] of browser) await store.set(name, value);
    expect(await readTransaction(store, 'one', secret)).not.toBeNull();
    expect(await readTransaction(store, 'two', secret)).not.toBeNull();
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

  it.each([
    ['a control character', '%2Fa%01b'],
    ['DEL', '%2Fa%7Fb'],
    ['non-ASCII', '%2Fs%C3%B8k'],
  ])('drops a returnTo with %s', async (_, encoded) => {
    const { store } = memoryStore();
    await login(store, `?returnTo=${encoded}`);

    expect((await readTransaction(store, 'st', secret))?.returnTo).toBeUndefined();
  });

  it('keeps a printable returnTo with a query', async () => {
    const { store } = memoryStore();
    await login(store, `?returnTo=${encodeURIComponent('/dash?tab=1 2')}`);

    expect((await readTransaction(store, 'st', secret))?.returnTo).toBe('/dash?tab=1 2');
  });

  it('retries without returnTo when the transaction is too large for a cookie', async () => {
    const { store } = memoryStore();
    mockedPkce.mockResolvedValue({ state: 'st', code_verifier: 'v'.repeat(2400) } as any);

    const response = await login(store, `?returnTo=%2F${'a'.repeat(900)}`);

    expect(response.status).toBe(302);
    const transaction = await readTransaction(store, 'st', secret);
    expect(transaction).not.toBeNull();
    expect(transaction?.returnTo).toBeUndefined();
  });

  it('still throws when the transaction is too large without returnTo', async () => {
    const { store, jar } = memoryStore();
    mockedPkce.mockResolvedValue({ state: 'st', code_verifier: 'v'.repeat(4000) } as any);

    await expect(login(store, '?returnTo=%2Fdash')).rejects.toBeInstanceOf(CookieTooLargeError);
    expect(jar.size).toBe(0);
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

  it('passes no extra parameters by default', async () => {
    const { store } = memoryStore();
    await login(store);

    expect(mockedPkce).toHaveBeenCalledWith(oauthConfig, { parameters: undefined });
  });

  it('passes per-request authorization parameters to buildPKCEOptions', async () => {
    const { store } = memoryStore();
    const request = new Request('https://app.test/api/auth/login?hint=user%40example.com');
    const authorizationParameters = vi.fn(async (req: Request) => ({
      login_hint: new URL(req.url).searchParams.get('hint') ?? '',
    }));

    await handleOidcLogin(request, { oauthConfig, cookies: store, secret, authorizationParameters });

    expect(authorizationParameters).toHaveBeenCalledWith(request);
    expect(mockedPkce).toHaveBeenCalledWith(oauthConfig, {
      parameters: { login_hint: 'user@example.com' },
    });
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
