/**
 * createFidesAuth end to end: the handlers and members share one cookie jar,
 * the way a browser carries cookies between requests. The OIDC client is
 * replaced with a fake, since the protocol layer has its own tests; what is
 * tested here is how the instance drives it and the session lifecycle.
 */
import { UnsecuredJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from 'vitest';

vi.mock('../protocol/client.js', () => ({ createOidcClient: vi.fn() }));

import type { FidesLogger } from '../shared/logger.js';
import type { SessionEvent } from '../shared/session-events.js';
import type { Session, SessionInfo, TokenResponse, TokenStatus } from '../shared/types.js';
import { createOidcClient, type OidcClient } from '../protocol/client.js';
import { createRecord, sealRecord } from '../session/record.js';
import type { CookieStore } from './cookie-store.js';
import { fetchCookieStore } from './fetch-cookie-store.js';
import {
  createFidesAuth,
  type FidesAuth,
  type FidesAuthConfig,
  issuerForKey,
  type LoginError,
} from './fides-auth.js';
import { sessionKeyInfo } from './session-lifecycle.js';
import { deriveKey, SessionSecretError } from './session-secret.js';
import { createMemorySessionStore, type SessionStore, type StoreFields } from './session-store.js';

const secret = 'a'.repeat(64);
const APP = 'https://app.test';
const quiet: FidesLogger = { debug() {}, info() {}, warn() {}, error() {} };

function cookieJar(): { cookies: CookieStore; jar: Map<string, string> } {
  const jar = new Map<string, string>();
  return {
    jar,
    cookies: {
      get: (name) => jar.get(name) ?? null,
      set: (name, value, options) => {
        if (options?.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
      },
    },
  };
}

function tokens(n: number, extra: Partial<TokenResponse> = {}): TokenResponse {
  return {
    access_token: `access-${n}`,
    token_type: 'bearer',
    expires_in: 300,
    refresh_token: `refresh-${n}`,
    id_token: new UnsecuredJWT({
      iss: 'https://idp.test',
      sub: 'user-1',
      sid: 'idp-1',
      name: 'Ada',
      roles: ['admin'],
    }).encode(),
    scope: 'openid profile',
    ...extra,
  };
}

function oauthError(error: string, code = 'OAUTH_RESPONSE_BODY_ERROR'): Error {
  return Object.assign(new Error(error), { code, error });
}

/** The OIDC client the instance gets. Each login uses the next state. */
function fakeOidc() {
  let logins = 0;
  let refreshes = 1;
  const client = {
    metadata: vi.fn(),
    createAuthorizationRequest: vi.fn(async () => {
      logins += 1;
      return {
        codeVerifier: `verifier-${logins}`,
        codeChallenge: 'challenge',
        state: `state-${logins}`,
        parameters: {},
      };
    }),
    authorizationUrl: vi.fn(
      async (request: { state: string }) => new URL(`https://idp.test/authorize?state=${request.state}`),
    ),
    silentLoginUrl: vi.fn(),
    exchangeCode: vi.fn(async (_url: URL, _request: { codeVerifier: string; state: string }) => tokens(1)),
    refresh: vi.fn(async (_refreshToken: string): Promise<TokenResponse> => {
      refreshes += 1;
      return tokens(refreshes);
    }),
    clientCredentials: vi.fn(),
    logoutUrl: vi.fn(async (_options?: Record<string, unknown>): Promise<URL | null> =>
      new URL('https://idp.test/logout'),
    ),
    verifyIdToken: vi.fn(),
    revoke: vi.fn(async (_token: string, _options?: { tokenTypeHint?: string }) => true),
    userInfo: vi.fn(),
  };
  return client;
}

let oidc: ReturnType<typeof fakeOidc>;

beforeEach(() => {
  oidc = fakeOidc();
  vi.mocked(createOidcClient).mockReturnValue(oidc as unknown as OidcClient);
});

function setup<TData = Record<string, unknown>>(overrides: Partial<FidesAuthConfig<TData>> = {}) {
  const events: SessionEvent[] = [];
  const auth = createFidesAuth<TData>({
    oauthConfig: {
      issuer: 'https://idp.test',
      clientId: 'web',
      clientSecret: 'shh',
      redirectUri: `${APP}/api/auth/callback`,
      scope: 'openid profile offline_access',
    },
    secret,
    logger: { create: () => quiet },
    onSessionEvent: (event) => events.push(event),
    ...overrides,
  });
  return { auth, events, ...cookieJar() };
}

const get = (path: string, headers: Record<string, string> = {}) =>
  new Request(`${APP}${path}`, { headers });
const post = (path: string, headers: Record<string, string> = { 'sec-fetch-site': 'same-origin' }) =>
  new Request(`${APP}${path}`, { method: 'POST', headers });

/** Logs in through the handlers and returns the callback's response. */
async function login(
  auth: Pick<FidesAuth, 'handleOidcLogin' | 'handleOidcCallback'>,
  cookies: CookieStore,
  returnTo?: string,
): Promise<Response> {
  const query = returnTo === undefined ? '' : `?returnTo=${encodeURIComponent(returnTo)}`;
  const started = await auth.handleOidcLogin(get(`/api/auth/login${query}`), cookies);
  const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');
  return auth.handleOidcCallback(get(`/api/auth/callback?code=abc&state=${state}`), cookies);
}

const location = (response: Response) => new URL(response.headers.get('location') ?? '');

describe('createFidesAuth', () => {
  it('needs a confidential client', () => {
    expect(() =>
      createFidesAuth({
        oauthConfig: {
          issuer: 'https://idp.test',
          clientId: 'spa',
          clientAuth: 'none',
          redirectUri: `${APP}/cb`,
          scope: 'openid',
        },
        secret,
      }),
    ).toThrow(TypeError);
  });

  it('reads the redirect URI on first use, so a build can create it without the environment', async () => {
    const auth = createFidesAuth({
      oauthConfig: { issuer: 'https://idp.test', clientId: 'web', clientSecret: 'shh', scope: 'openid' },
      secret,
    });
    const { cookies } = cookieJar();
    await expect(auth.readSession(cookies)).rejects.toThrow(/redirectUri/);
    await expect(auth.handleOidcCallback(get('/api/auth/callback?state=x'), cookies)).rejects.toThrow(
      /redirectUri/,
    );
    expect(() => auth.cookieNames).toThrow(/redirectUri/);
  });

  it('names the session cookie by whether the app is served over https', () => {
    expect(setup().auth.cookieNames.session).toBe('__Host-session');
    const plain = setup({
      oauthConfig: {
        issuer: 'https://idp.test',
        clientId: 'web',
        clientSecret: 'shh',
        redirectUri: 'http://localhost:3000/api/auth/callback',
        scope: 'openid',
      },
    });
    expect(plain.auth.cookieNames.session).toBe('session');
  });

  it('exposes its OIDC client', () => {
    expect(setup().auth.oidc).toBe(oidc);
  });
});

describe('login, session and logout', () => {
  it('runs the whole flow on one cookie jar', async () => {
    const { auth, cookies, jar, events } = setup();

    const started = await auth.handleOidcLogin(get('/api/auth/login?returnTo=%2Fdashboard%3Ftab%3D2'), cookies);
    expect(started.status).toBe(302);
    expect(location(started).origin).toBe('https://idp.test');
    expect([...jar.keys()].some((name) => name.startsWith('__Host-oauth_tx_'))).toBe(true);

    const state = location(started).searchParams.get('state');
    const done = await auth.handleOidcCallback(get(`/api/auth/callback?code=abc&state=${state}`), cookies);
    expect(done.status).toBe(302);
    expect(location(done).toString()).toBe(`${APP}/dashboard?tab=2&login=success`);
    // The login transaction is spent; the session is in its own cookie.
    expect([...jar.keys()]).toEqual(['__Host-session']);

    const [callbackUrl, request] = oidc.exchangeCode.mock.calls[0] ?? [];
    expect(callbackUrl?.toString()).toBe(`${APP}/api/auth/callback?code=abc&state=${state}`);
    expect(request).toEqual({ codeVerifier: 'verifier-1', state });

    const session = await auth.readSession(cookies);
    expect(session?.user).toEqual({ sub: 'user-1', name: 'Ada', roles: ['admin'] });
    expect(session?.idp).toEqual({ iss: 'https://idp.test', sub: 'user-1', sid: 'idp-1' });
    expect((await auth.getTokens(cookies))?.accessToken).toBe('access-1');

    const info = await auth.handleSessionInfo(get('/api/auth/session'), cookies);
    expect(info.headers.get('cache-control')).toBe('private, no-store');
    const body = await info.json();
    expect(body).toMatchObject({ authenticated: true, user: { sub: 'user-1', name: 'Ada' } });
    expect(JSON.stringify(body)).not.toContain('access-1');

    const heartbeat = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
    expect(heartbeat.status).toBe(200);
    expect(await heartbeat.json()).toEqual({ accessTokenExpiresAt: expect.any(String) });
    expect(oidc.refresh).toHaveBeenCalledWith('refresh-1');
    expect((await auth.getTokens(cookies))?.accessToken).toBe('access-2');
    // A refresh keeps the session's identity.
    expect((await auth.readSession(cookies))?.correlationId).toBe(session?.correlationId);

    const out = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(out.status).toBe(302);
    expect(out.headers.get('location')).toBe('https://idp.test/logout');
    expect(oidc.logoutUrl).toHaveBeenCalledWith(
      expect.objectContaining({ postLogoutRedirectUri: APP, idTokenHint: tokens(2).id_token }),
    );
    expect(oidc.revoke).toHaveBeenCalledWith('refresh-2', { tokenTypeHint: 'refresh_token' });
    expect(jar.size).toBe(0);
    expect(await auth.readSession(cookies)).toBeNull();
    expect(await (await auth.handleSessionInfo(get('/api/auth/session'), cookies)).json()).toEqual({
      authenticated: false,
    });

    expect(events.map((event) => event.event)).toEqual([
      'session.created',
      'session.refreshed',
      'session.cleared',
    ]);
  });

  it("checks the ID token against the nonce the login's request had", async () => {
    const { auth, cookies, jar } = setup();
    oidc.createAuthorizationRequest.mockResolvedValueOnce({
      codeVerifier: 'v',
      codeChallenge: 'challenge',
      state: 'state-n',
      nonce: 'nonce-n',
      parameters: { nonce: 'nonce-n' },
    } as never);

    await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    expect([...jar.values()].join('\n')).not.toContain('nonce-n');
    await auth.handleOidcCallback(get('/api/auth/callback?code=abc&state=state-n'), cookies);

    expect(oidc.exchangeCode.mock.calls[0]?.[1]).toEqual({ codeVerifier: 'v', state: 'state-n', nonce: 'nonce-n' });
  });

  it('sends the code exchange the public callback URL, not the one the proxy saw', async () => {
    const { auth, cookies } = setup();
    const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    const state = location(started).searchParams.get('state');
    await auth.handleOidcCallback(
      new Request(`http://internal:3000/api/auth/callback?code=abc&state=${state}`),
      cookies,
    );
    expect(oidc.exchangeCode.mock.calls[0]?.[0].toString()).toBe(
      `${APP}/api/auth/callback?code=abc&state=${state}`,
    );
  });

  it('passes authorization parameters through to the provider', async () => {
    const { auth, cookies } = setup();
    await auth.handleOidcLogin(get('/api/auth/login'), cookies, {
      authorizationParameters: { prompt: 'login' },
    });
    expect(oidc.createAuthorizationRequest).toHaveBeenCalledWith({ parameters: { prompt: 'login' } });
  });

  it('maps the session at login', async () => {
    const { auth, cookies } = setup({
      mapSession: (_tokens, claims, session) => ({ ...session, data: { tenant: claims?.sub } }),
    });
    await login(auth, cookies);
    expect((await auth.readSession(cookies))?.data).toEqual({ tenant: 'user-1' });
  });

  it('logs out when the refresh token cannot be revoked', async () => {
    const { auth, cookies, jar } = setup();
    await login(auth, cookies);
    oidc.revoke.mockRejectedValueOnce(oauthError('invalid_client'));
    const out = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(out.status).toBe(302);
    expect(out.headers.get('location')).toBe('https://idp.test/logout');
    expect(jar.size).toBe(0);
  });

  it('revokes the tokens a refresh still running brings back', async () => {
    const { auth, cookies, jar } = setup();
    await login(auth, cookies);
    let finish: (value: TokenResponse) => void = () => {};
    oidc.refresh.mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)));

    // A prefetch refreshes with the browser's cookie while the user logs out with the same one.
    const prefetch = cookieJar();
    for (const [name, value] of jar) prefetch.jar.set(name, value);
    const refreshing = auth.refreshSession(prefetch.cookies);
    await vi.waitFor(() => expect(oidc.refresh).toHaveBeenCalled());
    const out = auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    // Long enough for the logout to find the refresh, which it then waits for.
    await new Promise((resolve) => setTimeout(resolve, 50));
    finish(tokens(2));

    expect(await refreshing).toMatchObject({ ok: true, refreshed: true });
    expect((await out).status).toBe(302);
    expect(oidc.revoke).toHaveBeenCalledWith('refresh-2', { tokenTypeHint: 'refresh_token' });
  });

  it('redirects to postLogoutRedirectUri when the provider has no logout endpoint', async () => {
    const { auth, cookies, jar } = setup({ postLogoutRedirectUri: `${APP}/bye` });
    await login(auth, cookies);
    oidc.logoutUrl.mockResolvedValueOnce(null);
    const out = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(out.headers.get('location')).toBe(`${APP}/bye`);
    expect(jar.size).toBe(0);
  });

  it('refuses to log in with a bad secret before contacting the provider', async () => {
    const { auth, cookies } = setup({ secret: 'too short' });
    await expect(auth.handleOidcLogin(get('/api/auth/login'), cookies)).rejects.toBeInstanceOf(
      SessionSecretError,
    );
    expect(oidc.createAuthorizationRequest).not.toHaveBeenCalled();
  });

  it('refuses to log out with a bad secret instead of ending sessions quietly', async () => {
    const { auth, cookies } = setup({ secret: 'too short' });
    await expect(auth.handleOidcLogout(post('/api/auth/logout'), cookies)).rejects.toBeInstanceOf(
      SessionSecretError,
    );
    expect(oidc.revoke).not.toHaveBeenCalled();
  });

  it('refuses a session lifetime that is not a number of seconds, when it is created', () => {
    for (const sessionDurationSeconds of [Number.NaN, 0, -1, Number.POSITIVE_INFINITY]) {
      expect(() => setup({ sessionDurationSeconds }), String(sessionDurationSeconds)).toThrow(TypeError);
    }
    // An unset environment variable is the usual way to get here.
    expect(() => setup({ sessionDurationSeconds: Number(undefined) })).toThrow(/sessionDurationSeconds/);
  });

  /** How long the session a login starts lasts, in hours. */
  async function hoursOf(overrides: Partial<FidesAuthConfig> = {}): Promise<number> {
    const { auth, cookies } = setup(overrides);
    await login(auth, cookies);
    const session = await auth.readSession(cookies);
    return (Date.parse(session?.expiresAt ?? '') - Date.parse(session?.createdAt ?? '')) / 3_600_000;
  }

  it('ends a session 12 hours after login unless told otherwise', async () => {
    expect(await hoursOf()).toBeCloseTo(12, 5);
  });

  it('counts the session lifetime in seconds', async () => {
    expect(await hoursOf({ sessionDurationSeconds: 8 * 60 * 60 })).toBeCloseTo(8, 5);
    expect(await hoursOf({ sessionDurationSeconds: 30 * 24 * 60 * 60 })).toBeCloseTo(720, 5);
  });

  it('refuses the old sessionDurationDays, rather than ignore it and shorten the sessions', () => {
    const old = { sessionDurationDays: 30 } as Partial<FidesAuthConfig>;
    expect(() => setup(old)).toThrow(/sessionDurationDays is now sessionDurationSeconds/);
  });

  describe('scopes at login', () => {
    const asked = {
      codeVerifier: 'v',
      codeChallenge: 'c',
      state: 'state-x',
      parameters: { scope: 'openid profile offline_access' },
    };

    it('are the requested scopes when the token response names none', async () => {
      const { auth, cookies } = setup();
      oidc.createAuthorizationRequest.mockResolvedValueOnce(asked);
      oidc.exchangeCode.mockResolvedValueOnce(tokens(1, { scope: undefined }));

      await login(auth, cookies);

      expect((await auth.readSession(cookies))?.scopes).toEqual(['openid', 'profile', 'offline_access']);
    });

    it('are the ones the response names, when it names any', async () => {
      const { auth, cookies } = setup();
      oidc.createAuthorizationRequest.mockResolvedValueOnce(asked);
      oidc.exchangeCode.mockResolvedValueOnce(tokens(1, { scope: 'openid' }));

      await login(auth, cookies);

      expect((await auth.readSession(cookies))?.scopes).toEqual(['openid']);
    });
  });
});

describe('return paths', () => {
  it.each([
    ['//evil.test/x', `${APP}/?login=success`],
    ['https://evil.test/x', `${APP}/?login=success`],
    ['/\\evil.test', `${APP}/?login=success`],
    ['/.//evil.test', `${APP}/?login=success`],
    ['/ok', `${APP}/ok?login=success`],
  ])('returnTo %s lands on %s', async (returnTo, expected) => {
    const { auth, cookies } = setup();
    expect(location(await login(auth, cookies, returnTo)).toString()).toBe(expected);
  });

  it('lands on the return path as it was with loginSuccessParam false', async () => {
    const { auth, cookies } = setup({ loginSuccessParam: false });
    expect(location(await login(auth, cookies, '/ok?tab=2')).toString()).toBe(`${APP}/ok?tab=2`);
    expect(location(await login(auth, cookies)).toString()).toBe(`${APP}/`);
  });

  it('still names the error when a login fails with loginSuccessParam false', async () => {
    const { auth, cookies } = setup({ loginSuccessParam: false });
    const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    const state = location(started).searchParams.get('state');
    const denied = await auth.handleOidcCallback(
      get(`/api/auth/callback?error=access_denied&state=${state}`),
      cookies,
    );
    expect(location(denied).toString()).toBe(`${APP}/?login=error&error=access_denied`);
  });

  it('uses validateReturnTo and defaultRedirectPath', async () => {
    const { auth, cookies } = setup({
      validateReturnTo: (path) => (path.startsWith('/app/') ? path : null),
      defaultRedirectPath: '/home',
    });
    expect(location(await login(auth, cookies, '/app/x')).pathname).toBe('/app/x');
    expect(location(await login(auth, cookies, '/admin')).pathname).toBe('/home');
  });

  it('keeps the return path on the application origin whatever validateReturnTo returns', async () => {
    const { auth, cookies } = setup({ validateReturnTo: (path) => path });
    expect(location(await login(auth, cookies, 'https://evil.test/x')).origin).toBe(APP);
  });
});

describe('callback failures', () => {
  it('sends a callback without a transaction home as an expired login', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleOidcCallback(get('/api/auth/callback?code=abc&state=nope'), cookies);
    expect(response.status).toBe(302);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_expired`);
    expect(oidc.exchangeCode).not.toHaveBeenCalled();
  });

  it('sends a callback without a state home as an expired login', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleOidcCallback(get('/api/auth/callback?code=abc'), cookies);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_expired`);
  });

  it('sends a login that took too long home as an expired login', async () => {
    vi.useFakeTimers({ now: Date.parse('2026-11-14T12:00:00Z'), toFake: ['Date'] });
    try {
      const { auth, cookies } = setup();
      const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
      const state = location(started).searchParams.get('state');
      vi.setSystemTime(Date.parse('2026-11-14T12:11:00Z'));
      const response = await auth.handleOidcCallback(get(`/api/auth/callback?code=abc&state=${state}`), cookies);
      expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_expired`);
      expect(oidc.exchangeCode).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('sends a callback with neither a code nor an error home as an invalid callback', async () => {
    const { auth, cookies } = setup();
    const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    const state = location(started).searchParams.get('state');
    const response = await auth.handleOidcCallback(get(`/api/auth/callback?state=${state}`), cookies);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=invalid_callback`);
  });

  it('sends a cancel without a transaction home with a fixed code', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleOidcCallback(
      get('/api/auth/callback?error=access_denied&state=nope'),
      cookies,
    );
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_expired`);
  });

  it('sends a provider error home with its code', async () => {
    const { auth, cookies, jar } = setup();
    const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    const state = location(started).searchParams.get('state');
    const response = await auth.handleOidcCallback(
      get(`/api/auth/callback?error=access_denied&state=${state}`),
      cookies,
    );
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=access_denied`);
    expect(jar.size).toBe(0);
  });

  it('does not echo an error code that is not a registered shape', async () => {
    const { auth, cookies } = setup();
    const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    const state = location(started).searchParams.get('state');
    const response = await auth.handleOidcCallback(
      get(`/api/auth/callback?error=%3Cscript%3E&state=${state}`),
      cookies,
    );
    expect(location(response).searchParams.get('error')).toBe('idp_error');
  });

  it('sends the user home when the code exchange fails, and spends the transaction', async () => {
    const { auth, cookies, jar } = setup({ defaultRedirectPath: '/start' });
    oidc.exchangeCode.mockRejectedValueOnce(oauthError('invalid_grant'));
    const response = await login(auth, cookies);
    expect(location(response).toString()).toBe(`${APP}/start?login=error&error=login_failed`);
    expect(jar.size).toBe(0);
  });

  it('sends the user home when the session does not fit in the cookies', async () => {
    const { auth, cookies } = setup();
    oidc.exchangeCode.mockResolvedValueOnce(tokens(1, { access_token: 'x'.repeat(20_000) }));
    const response = await login(auth, cookies);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=session_too_large`);
  });

  it('sends the user home when the login cannot be started', async () => {
    const { auth, cookies, jar } = setup();
    oidc.createAuthorizationRequest.mockRejectedValueOnce(new TypeError('fetch failed'));
    const response = await auth.handleOidcLogin(get('/api/auth/login?returnTo=/reports'), cookies);
    expect(response.status).toBe(302);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_unavailable`);
    expect(jar.size).toBe(0);

    oidc.authorizationUrl.mockRejectedValueOnce(new Error('PAR failed'));
    const second = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    expect(location(second).searchParams.get('error')).toBe('login_unavailable');
    expect(jar.size).toBe(0);
  });

  describe('with onLoginError', () => {
    it('answers with the response it returns, at the callback and at the start', async () => {
      const seen: Array<[LoginError, string]> = [];
      const { auth, cookies } = setup({
        onLoginError: (error, request) => {
          seen.push([error, new URL(request.url).pathname]);
          return new Response(`Innlogging feilet: ${error.code}`, { status: 400 });
        },
      });

      const lost = await auth.handleOidcCallback(get('/api/auth/callback?code=abc&state=nope'), cookies);
      expect(lost.status).toBe(400);
      expect(await lost.text()).toBe('Innlogging feilet: login_expired');

      const down = new TypeError('fetch failed');
      oidc.createAuthorizationRequest.mockRejectedValueOnce(down);
      const unavailable = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
      expect(await unavailable.text()).toBe('Innlogging feilet: login_unavailable');

      const refused = oauthError('invalid_grant');
      oidc.exchangeCode.mockRejectedValueOnce(refused);
      expect(await (await login(auth, cookies)).text()).toBe('Innlogging feilet: login_failed');

      expect(seen).toEqual([
        [{ code: 'login_expired', stage: 'callback', cause: undefined }, '/api/auth/callback'],
        [{ code: 'login_unavailable', stage: 'login', cause: down }, '/api/auth/login'],
        [{ code: 'login_failed', stage: 'callback', cause: refused }, '/api/auth/callback'],
      ]);
    });

    it('gets a cancelled login with the provider\'s code', async () => {
      const onLoginError = vi.fn();
      const { auth, cookies } = setup({ onLoginError });
      const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
      const state = location(started).searchParams.get('state');
      const response = await auth.handleOidcCallback(
        get(`/api/auth/callback?error=access_denied&state=${state}`),
        cookies,
      );
      expect(onLoginError).toHaveBeenCalledWith(
        expect.objectContaining({ code: 'access_denied', stage: 'callback' }),
        expect.any(Request),
      );
      // It returned nothing, so the redirect stands.
      expect(location(response).toString()).toBe(`${APP}/?login=error&error=access_denied`);
    });

    it('redirects all the same when it throws', async () => {
      const { auth, cookies } = setup({
        onLoginError: () => {
          throw new Error('broken error page');
        },
      });
      const response = await auth.handleOidcCallback(get('/api/auth/callback?code=abc&state=nope'), cookies);
      expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_expired`);
    });

    it('may return nothing, whether it is async or not', () => {
      // For the compiler: a handler that only logs or reports.
      setup({ onLoginError: (error) => void error.code });
      setup({
        onLoginError: async (error) => {
          await Promise.resolve(error.code);
        },
      });
    });

    it('is not called for a login that succeeds', async () => {
      const onLoginError = vi.fn();
      const { auth, cookies } = setup({ onLoginError });
      expect(location(await login(auth, cookies)).searchParams.get('login')).toBe('success');
      expect(onLoginError).not.toHaveBeenCalled();
    });
  });
});

describe('a callback opened again', () => {
  const callback = (state = 'state-1') => get(`/api/auth/callback?code=abc&state=${state}`);

  it('redirects a logged-in browser home without a login param, and fails nothing', async () => {
    const onLoginError = vi.fn();
    const { auth, cookies } = setup({ onLoginError });
    expect(location(await login(auth, cookies)).searchParams.get('login')).toBe('success');

    const again = await auth.handleOidcCallback(callback(), cookies);
    expect(again.status).toBe(302);
    expect(location(again).toString()).toBe(`${APP}/`);
    expect(oidc.exchangeCode).toHaveBeenCalledTimes(1);
    expect(onLoginError).not.toHaveBeenCalled();
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it('goes to defaultRedirectPath', async () => {
    const { auth, cookies } = setup({ defaultRedirectPath: '/start' });
    await login(auth, cookies);
    const again = await auth.handleOidcCallback(callback(), cookies);
    expect(location(again).toString()).toBe(`${APP}/start`);
  });

  it('does the same with a sessionStore', async () => {
    const onLoginError = vi.fn();
    const { auth, cookies } = setup({ sessionStore: createMemorySessionStore(), onLoginError });
    await login(auth, cookies);
    const again = await auth.handleOidcCallback(callback(), cookies);
    expect(location(again).toString()).toBe(`${APP}/`);
    expect(onLoginError).not.toHaveBeenCalled();
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it('redirects a callback that carries a provider error the same way', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const again = await auth.handleOidcCallback(get('/api/auth/callback?error=access_denied&state=state-1'), cookies);
    expect(location(again).toString()).toBe(`${APP}/`);
  });

  it('is still an expired login for a browser without a session', async () => {
    const onLoginError = vi.fn();
    const { auth, cookies } = setup({ onLoginError });
    await login(auth, cookies);

    await auth.clearSession(cookies);
    const again = await auth.handleOidcCallback(callback(), cookies);
    expect(location(again).toString()).toBe(`${APP}/?login=error&error=login_expired`);
    expect(onLoginError).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'login_expired' }),
      expect.any(Request),
    );

    const fresh = cookieJar();
    const other = await auth.handleOidcCallback(callback(), fresh.cookies);
    expect(location(other).toString()).toBe(`${APP}/?login=error&error=login_expired`);
  });

  it('is an expired login when a login that took too long meets no session', async () => {
    vi.useFakeTimers({ now: Date.parse('2026-11-14T12:00:00Z'), toFake: ['Date'] });
    try {
      const { auth, cookies } = setup();
      const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
      const state = location(started).searchParams.get('state') ?? '';
      vi.setSystemTime(Date.parse('2026-11-14T12:11:00Z'));
      const response = await auth.handleOidcCallback(callback(state), cookies);
      expect(location(response).toString()).toBe(`${APP}/?login=error&error=login_expired`);
    } finally {
      vi.useRealTimers();
    }
  });

  it('redirects home when the transaction has expired but the session is live', async () => {
    vi.useFakeTimers({ now: Date.parse('2026-11-14T12:00:00Z'), toFake: ['Date'] });
    try {
      const { auth, cookies } = setup();
      await login(auth, cookies);
      const started = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
      const state = location(started).searchParams.get('state') ?? '';
      vi.setSystemTime(Date.parse('2026-11-14T12:11:00Z'));
      const response = await auth.handleOidcCallback(callback(state), cookies);
      expect(location(response).toString()).toBe(`${APP}/`);
    } finally {
      vi.useRealTimers();
    }
  });

  it('is an expired login when the session cannot be read', async () => {
    const store = createMemorySessionStore();
    const { auth, cookies } = setup({ sessionStore: store });
    await login(auth, cookies);
    vi.spyOn(store, 'get').mockRejectedValue(new Error('store down'));
    const again = await auth.handleOidcCallback(callback(), cookies);
    expect(location(again).toString()).toBe(`${APP}/?login=error&error=login_expired`);
  });
});

describe('guards', () => {
  const endpoints = [
    ['handleOidcLogout', '/api/auth/logout'],
    ['handleHeartbeat', '/api/auth/heartbeat'],
  ] as const;

  it.each(endpoints)('%s answers only POST', async (member, path) => {
    const { auth, cookies } = setup();
    const response = await auth[member](get(path), cookies);
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('POST');
  });

  it.each(endpoints)('%s rejects a cross-site request and keeps the session', async (member, path) => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const response = await auth[member](post(path, { 'sec-fetch-site': 'same-site' }), cookies);
    expect(response.status).toBe(403);
    expect(await auth.readSession(cookies)).not.toBeNull();
    expect(oidc.refresh).not.toHaveBeenCalled();
  });

  it.each(endpoints)('%s checks Origin when Sec-Fetch-Site is missing', async (member, path) => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const response = await auth[member](post(path, { origin: 'https://evil.test' }), cookies);
    expect(response.status).toBe(403);
  });

  it('rate limits every handler', async () => {
    const rateLimit = vi.fn(() => false);
    const { auth, cookies } = setup({ rateLimit });
    const refused = (response: Response) => response.status === 302 && location(response).searchParams.has('error');
    expect(refused(await auth.handleOidcLogin(get('/api/auth/login'), cookies))).toBe(true);
    expect(refused(await auth.handleOidcCallback(get('/api/auth/callback?code=a&state=b'), cookies))).toBe(true);
    expect(refused(await auth.handleOidcLogout(post('/api/auth/logout'), cookies))).toBe(true);
    expect((await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies)).status).toBe(429);
    expect(rateLimit).toHaveBeenCalledTimes(4);
    expect(oidc.createAuthorizationRequest).not.toHaveBeenCalled();
  });

  it('says in the session info when the session ends, and a refresh does not move it', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const session = await auth.readSession(cookies);
    const info = async () => (await auth.handleSessionInfo(get('/api/auth/session'), cookies)).json();

    expect((await info()).expiresAt).toBe(session?.expiresAt);
    await auth.refreshSession(cookies);
    expect((await info()).expiresAt).toBe(session?.expiresAt);
  });

  it('answers session info only to GET and HEAD', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleSessionInfo(post('/api/auth/session'), cookies);
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
  });
});

describe('logout failures', () => {
  const limited = () => false;

  it('sends a rate-limited login to onLoginError, and its Response is the answer', async () => {
    const onLoginError = vi.fn(() => new Response('slow down', { status: 429 }));
    const { auth, cookies } = setup({ rateLimit: limited, onLoginError });
    const response = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    expect(response.status).toBe(429);
    expect(onLoginError).toHaveBeenCalledWith({ code: 'rate_limited', stage: 'login' }, expect.any(Request));
  });

  it('redirects a rate-limited login by default', async () => {
    const { auth, cookies } = setup({ rateLimit: limited });
    const response = await auth.handleOidcLogin(get('/api/auth/login'), cookies);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=rate_limited`);
  });

  it('sends a rate-limited callback to onLoginError, and its Response is the answer', async () => {
    const onLoginError = vi.fn(() => new Response('slow down', { status: 429 }));
    const { auth, cookies } = setup({ rateLimit: limited, onLoginError });
    const response = await auth.handleOidcCallback(get('/api/auth/callback?code=a&state=b'), cookies);
    expect(response.status).toBe(429);
    expect(onLoginError).toHaveBeenCalledWith({ code: 'rate_limited', stage: 'callback' }, expect.any(Request));
  });

  it('redirects a rate-limited callback by default', async () => {
    const { auth, cookies } = setup({ rateLimit: limited });
    const response = await auth.handleOidcCallback(get('/api/auth/callback?code=a&state=b'), cookies);
    expect(location(response).toString()).toBe(`${APP}/?login=error&error=rate_limited`);
  });

  it('redirects a rate-limited logout and keeps the session', async () => {
    let allowed = true;
    const { auth, cookies } = setup({ rateLimit: () => allowed });
    await login(auth, cookies);
    allowed = false;
    const response = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(location(response).toString()).toBe(`${APP}/?logout=error&error=rate_limited`);
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it('gives a rate-limited logout to onLogoutError, and its Response is the answer', async () => {
    let allowed = true;
    const onLogoutError = vi.fn(() => new Response('slow down', { status: 429 }));
    const { auth, cookies } = setup({ rateLimit: () => allowed, onLogoutError });
    await login(auth, cookies);
    allowed = false;
    const response = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(response.status).toBe(429);
    expect(onLogoutError).toHaveBeenCalledWith({ code: 'rate_limited' }, expect.any(Request));
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  describe('when the session cannot be ended', () => {
    const broken = new Error('store is down');
    function brokenStore() {
      const store = createMemorySessionStore();
      return {
        ...store,
        delete: () => {
          throw broken;
        },
      };
    }

    it('redirects with logout_failed and does not go to the provider', async () => {
      const { auth, cookies } = setup({ sessionStore: brokenStore() });
      await login(auth, cookies);
      const response = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
      expect(location(response).toString()).toBe(`${APP}/?logout=error&error=logout_failed`);
      expect(oidc.logoutUrl).not.toHaveBeenCalled();
    });

    it('gives onLogoutError the code and what was thrown', async () => {
      const onLogoutError = vi.fn(() => new Response('try again', { status: 500 }));
      const { auth, cookies } = setup({ sessionStore: brokenStore(), onLogoutError });
      await login(auth, cookies);
      const response = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
      expect(response.status).toBe(500);
      expect(onLogoutError).toHaveBeenCalledWith({ code: 'logout_failed', cause: broken }, expect.any(Request));
      expect(oidc.logoutUrl).not.toHaveBeenCalled();
    });
  });

  it('redirects all the same when onLogoutError throws', async () => {
    const { auth, cookies } = setup({
      rateLimit: limited,
      onLogoutError: () => {
        throw new Error('broken error page');
      },
    });
    const response = await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(location(response).toString()).toBe(`${APP}/?logout=error&error=rate_limited`);
  });

  it('may return nothing, whether it is async or not', () => {
    // For the compiler: a handler that only logs or reports.
    setup({ onLogoutError: (error) => void error.code });
    setup({
      onLogoutError: async (error) => {
        await Promise.resolve(error.code);
      },
    });
  });
});

describe('heartbeat', () => {
  it('answers 401 without a session', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ reason: 'no_session_cookie' });
  });

  it('answers 401 and reports the rejection when the refresh token is rejected', async () => {
    const { auth, cookies, events } = setup();
    await login(auth, cookies);
    oidc.refresh.mockRejectedValueOnce(oauthError('invalid_grant'));
    const response = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ reason: 'refresh_failed' });
    const correlationId = (await auth.readSession(cookies))?.correlationId;
    expect(events.slice(-2)).toEqual([
      expect.objectContaining({ event: 'session.refresh_failed', cause: 'invalid_grant', correlationId }),
      expect.objectContaining({ event: 'session.rejected', reason: 'refresh_failed', source: 'heartbeat' }),
    ]);
  });

  it('answers 503 and keeps the session when the provider is unreachable', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    oidc.refresh.mockRejectedValueOnce(Object.assign(new TypeError('fetch failed'), { code: 'ECONNREFUSED' }));
    const response = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
    expect(response.status).toBe(503);
    expect(await auth.readSession(cookies)).not.toBeNull();
  });
});

describe('session members', () => {
  it('reports why there is no session', async () => {
    const { auth, cookies, jar } = setup();
    expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'no_session_cookie' });
    jar.set('__Host-session', 'garbage');
    expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'unreadable_session' });
  });

  it('creates, updates, refreshes and clears a session without the handlers', async () => {
    const { auth, cookies, jar, events } = setup();
    const created = await auth.createSession(cookies, tokens(1));
    expect(created.user?.name).toBe('Ada');

    const updated = await auth.updateSession(cookies, (session) => ({ ...session, data: { theme: 'dark' } }));
    expect(updated?.data).toEqual({ theme: 'dark' });
    expect((await auth.readSession(cookies))?.data).toEqual({ theme: 'dark' });

    const refreshed = await auth.refreshSession(cookies);
    expect(refreshed).toMatchObject({
      ok: true,
      refreshed: true,
      rotatedRefreshToken: true,
      session: { data: { theme: 'dark' } },
    });

    await auth.clearSession(cookies);
    expect(jar.size).toBe(0);
    expect(events.at(-1)).toMatchObject({ event: 'session.cleared', trigger: 'logout' });
    expect(oidc.revoke).toHaveBeenCalledWith('refresh-2', { tokenTypeHint: 'refresh_token' });
    expect(await auth.updateSession(cookies, (session) => session)).toBeNull();
    expect(await auth.refreshSession(cookies)).toEqual({ ok: false, reason: 'no_session_cookie' });
  });

  describe('refreshSession with ifExpiresWithin', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    /** Moves the clock on, for a token to age. */
    function later(seconds: number): void {
      vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + seconds * 1000 });
    }

    it('leaves a token that lasts longer alone', async () => {
      const { auth, cookies } = setup();
      await auth.createSession(cookies, tokens(1));
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toMatchObject({
        ok: true,
        refreshed: false,
        rotatedRefreshToken: false,
        session: { user: { name: 'Ada' } },
      });
      expect(oidc.refresh).not.toHaveBeenCalled();
    });

    it('refreshes a token that expires within the window', async () => {
      const { auth, cookies } = setup();
      await auth.createSession(cookies, tokens(1));
      later(200);
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 120 })).toMatchObject({
        ok: true,
        refreshed: true,
      });
      expect(oidc.refresh).toHaveBeenCalledWith('refresh-1');
      expect((await auth.getTokens(cookies))?.accessToken).toBe('access-2');
    });

    it('waits for half the lifetime of a token shorter than the window', async () => {
      const { auth, cookies } = setup();
      await auth.createSession(cookies, tokens(1, { expires_in: 20 }));
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toMatchObject({
        refreshed: false,
      });
      later(9);
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toMatchObject({
        refreshed: false,
      });
      expect(oidc.refresh).not.toHaveBeenCalled();
      later(2);
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toMatchObject({
        refreshed: true,
      });
    });

    it('gives a session saved without the time it got its token the plain window', async () => {
      const { auth, cookies, jar } = setup();
      const record = createRecord(tokens(1, { expires_in: 20 }), { sessionDurationSeconds: 86_400 });
      delete record.tokens.accessTokenIssuedAt;
      const audience = JSON.stringify(['https://idp.test', 'web']);
      const key = await deriveKey(secret, sessionKeyInfo(audience, 'cookie'));
      jar.set('__Host-session', await sealRecord(record, key));
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toMatchObject({
        refreshed: true,
      });
    });

    it('treats a token without a known lifetime as fresh', async () => {
      const { auth, cookies } = setup();
      await auth.createSession(cookies, tokens(1, { expires_in: undefined }));
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 600 })).toMatchObject({
        refreshed: false,
      });
      expect(oidc.refresh).not.toHaveBeenCalled();
    });

    it('says why when there is no session', async () => {
      const { auth, cookies } = setup();
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toEqual({
        ok: false,
        reason: 'no_session_cookie',
      });
    });

    it('needs a number of seconds, 0 or more', async () => {
      const { auth, cookies } = setup();
      await expect(auth.refreshSession(cookies, { ifExpiresWithin: -1 })).rejects.toThrow(TypeError);
      await expect(auth.refreshSession(cookies, { ifExpiresWithin: Number.NaN })).rejects.toThrow(TypeError);
    });
  });

  it('takes the user from the ID token a refresh brings, so lost roles go', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    expect((await auth.readSession(cookies))?.user?.roles).toEqual(['admin']);

    const demoted = new UnsecuredJWT({ iss: 'https://idp.test', sub: 'user-1', name: 'Ada', roles: [] }).encode();
    oidc.refresh.mockResolvedValueOnce(tokens(2, { id_token: demoted }));
    await auth.refreshSession(cookies);
    expect((await auth.readSession(cookies))?.user).toEqual({ sub: 'user-1', name: 'Ada', roles: [] });
  });

  describe('a request that still carries the cookie from before a refresh', () => {
    /** The browser's jar as it is now, for a request already on its way. */
    function sentNow(jar: Map<string, string>) {
      const copy = cookieJar();
      for (const [name, value] of jar) copy.jar.set(name, value);
      return copy;
    }

    it('gets that refresh\'s tokens without another call to the provider', async () => {
      const { auth, cookies, jar } = setup();
      await login(auth, cookies);
      const late = sentNow(jar);
      await auth.refreshSession(cookies);

      expect(await auth.refreshSession(late.cookies)).toMatchObject({ ok: true, refreshed: true });
      expect(oidc.refresh).toHaveBeenCalledTimes(1);
      expect((await auth.getTokens(late.cookies))?.accessToken).toBe('access-2');
    });

    it('revokes the new refresh token when it is a logout', async () => {
      const { auth, cookies, jar } = setup();
      await login(auth, cookies);
      const late = sentNow(jar);
      await auth.refreshSession(cookies);

      await auth.handleOidcLogout(post('/api/auth/logout'), late.cookies);
      expect(oidc.revoke).toHaveBeenCalledWith('refresh-2', { tokenTypeHint: 'refresh_token' });
    });

    it('spends the old token again with refreshGraceSeconds 0', async () => {
      const { auth, cookies, jar } = setup({ refreshGraceSeconds: 0 });
      await login(auth, cookies);
      const late = sentNow(jar);
      await auth.refreshSession(cookies);
      await auth.refreshSession(late.cookies);
      expect(oidc.refresh.mock.calls.map(([token]) => token)).toEqual(['refresh-1', 'refresh-1']);
    });
  });

  it('refuses a refreshGraceSeconds that is not a number of seconds, when it is created', () => {
    expect(() => setup({ refreshGraceSeconds: -1 })).toThrow(TypeError);
    expect(() => setup({ refreshGraceSeconds: Number.NaN })).toThrow(TypeError);
  });

  it('takes the scopes a refresh grants, for the session and the session info', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    expect((await auth.readSession(cookies))?.scopes).toEqual(['openid', 'profile']);

    oidc.refresh.mockResolvedValueOnce(tokens(2, { scope: 'openid' }));
    await auth.refreshSession(cookies);
    expect((await auth.readSession(cookies))?.scopes).toEqual(['openid']);
    const info = await (await auth.handleSessionInfo(get('/api/auth/session'), cookies)).json();
    expect(info.scopes).toEqual(['openid']);
  });

  describe.each([
    ['with', (store: SessionStore): SessionStore => store],
    ['without', (store: SessionStore): SessionStore => ({ ...store, withLock: undefined })],
  ])('a store that can\'t be reached, %s a lock', (_, locking) => {
    async function loggedInThenDown() {
      const base = createMemorySessionStore();
      const down = new Error('db down');
      const state = { down: false };
      const sessionStore = locking({
        ...base,
        get: async (key) => {
          if (state.down) throw down;
          return base.get(key);
        },
      });
      const { auth, cookies } = setup({ sessionStore });
      await login(auth, cookies);
      state.down = true;
      return { auth, cookies, state, down };
    }

    it('answers the heartbeat with 503 and a refresh with cause store', async () => {
      const { auth, cookies, state } = await loggedInThenDown();

      const heartbeat = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
      expect(heartbeat.status).toBe(503);
      expect(heartbeat.headers.get('cache-control')).toBe('private, no-store');
      const failed = { ok: false, reason: 'refresh_failed', cause: 'store' };
      expect(await auth.refreshSession(cookies)).toEqual(failed);
      expect(await auth.refreshSession(cookies, { ifExpiresWithin: 60 })).toEqual(failed);
      expect(oidc.refresh).not.toHaveBeenCalled();

      state.down = false;
      expect((await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies)).status).toBe(200);
    });

    it('answers session info with 503: neither logged in nor logged out', async () => {
      const { auth, cookies, state } = await loggedInThenDown();

      const info = await auth.handleSessionInfo(get('/api/auth/session'), cookies);
      expect(info.status).toBe(503);
      expect(info.headers.get('cache-control')).toBe('private, no-store');
      expect(await info.text()).toBe('');

      state.down = false;
      const back = await auth.handleSessionInfo(get('/api/auth/session'), cookies);
      expect(await back.json()).toMatchObject({ authenticated: true });
    });

    it('still rejects a read with what the store threw', async () => {
      const { auth, cookies, down } = await loggedInThenDown();

      await expect(auth.readSession(cookies)).rejects.toBe(down);
      await expect(auth.tryReadSession(cookies)).rejects.toBe(down);
    });
  });

  it.each([
    ['cookies', () => undefined],
    ['a store', () => createMemorySessionStore()],
  ])('doesn\'t read a session another provider or client started with the same secret, in %s', async (_, makeStore) => {
    const sessionStore = makeStore();
    const { auth, cookies } = setup({ sessionStore });
    await login(auth, cookies);
    const oauthConfig = {
      issuer: 'https://idp.test',
      clientId: 'web',
      clientSecret: 'shh',
      redirectUri: `${APP}/api/auth/callback`,
      scope: 'openid',
    };
    const instance = (overrides: Partial<typeof oauthConfig>) =>
      setup({ sessionStore, oauthConfig: { ...oauthConfig, ...overrides } }).auth;

    // On the same origin, with the same secret and the same cookie.
    for (const other of [instance({ clientId: 'staff' }), instance({ issuer: 'https://staff-idp.test' })]) {
      expect(await other.tryReadSession(cookies)).toEqual({ session: null, reason: 'unreadable_session' });
      expect(await other.getTokens(cookies)).toBeNull();
      expect(await other.refreshSession(cookies)).toEqual({ ok: false, reason: 'unreadable_session' });
    }
    expect(oidc.refresh).not.toHaveBeenCalled();
    // Another instance of the same app reads it.
    expect((await instance({}).readSession(cookies))?.user?.sub).toBe('user-1');
    expect((await auth.readSession(cookies))?.user?.sub).toBe('user-1');
  });

  it.each([
    ['cookies', () => undefined],
    ['a store', () => createMemorySessionStore()],
  ])('reads a session whatever way the issuer is written in the config, in %s', async (_, makeStore) => {
    const sessionStore = makeStore();
    const { auth, cookies } = setup({ sessionStore });
    await login(auth, cookies);
    const withIssuer = (issuer: string) =>
      setup({
        sessionStore,
        oauthConfig: {
          issuer,
          clientId: 'web',
          clientSecret: 'shh',
          redirectUri: `${APP}/api/auth/callback`,
          scope: 'openid',
        },
      }).auth;

    // One provider, written four ways. A slash more or less must not log everyone out.
    for (const issuer of ['https://idp.test/', 'https://idp.test//', 'https://IDP.test', 'https://idp.test:443/']) {
      expect((await withIssuer(issuer).readSession(cookies))?.user?.sub, issuer).toBe('user-1');
    }
    // Another host, port or path is another provider.
    for (const issuer of ['https://idp.test:8443', 'https://idp.test/realms/a', 'http://idp.test']) {
      expect(await withIssuer(issuer).readSession(cookies), issuer).toBeNull();
    }
  });

  it('writes an issuer one way for the key, and leaves one already written that way alone', () => {
    // As written, so sessions from before the issuer was normalized still open.
    expect(issuerForKey('https://idp.test')).toBe('https://idp.test');
    expect(issuerForKey('https://idp.test/realms/Main')).toBe('https://idp.test/realms/Main');
    expect(issuerForKey('https://login.example.com/tenant-1/v2.0')).toBe('https://login.example.com/tenant-1/v2.0');

    expect(issuerForKey('https://idp.test/')).toBe('https://idp.test');
    expect(issuerForKey('https://IDP.Test/realms/Main/')).toBe('https://idp.test/realms/Main');
    expect(issuerForKey('https://idp.test:443')).toBe('https://idp.test');
    expect(issuerForKey('http://localhost:8080/')).toBe('http://localhost:8080');
    // The path's case is the provider's to decide.
    expect(issuerForKey('https://idp.test/realms/main')).not.toBe(issuerForKey('https://idp.test/realms/Main'));
    // Not a URL: the trailing slash is all that is known to be noise.
    expect(issuerForKey('idp/')).toBe('idp');
  });

  it('reports a cookie that doesn\'t open once, also through the heartbeat, and names the reason to the browser', async () => {
    const { auth, cookies, jar, events } = setup();
    await login(auth, cookies);
    // As after a change of secret.
    const elsewhere = setup({ secret: 'b'.repeat(64) });
    await login(elsewhere.auth, elsewhere.cookies);
    jar.set('__Host-session', elsewhere.jar.get('__Host-session') ?? '');
    const rejected = () => events.filter((event) => event.event === 'session.rejected');

    expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'unreadable_session' });
    expect(rejected()).toEqual([{ event: 'session.rejected', reason: 'unreadable_session' }]);

    const heartbeat = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
    expect(heartbeat.status).toBe(401);
    expect(await heartbeat.json()).toEqual({ reason: 'unreadable_session' });
    expect(rejected()).toHaveLength(2);

    // Session info is a read too, and says there is no session.
    const info = await auth.handleSessionInfo(get('/api/auth/session'), cookies);
    expect(await info.json()).toEqual({ authenticated: false });
    expect(rejected()).toHaveLength(3);
  });

  it.each([
    ['cookies', () => undefined],
    ['a store', () => createMemorySessionStore()],
  ])('replaces the secret without logging anyone out, in %s', async (_, makeStore) => {
    const OLD = secret;
    const NEW = 'c'.repeat(64);
    const sessionStore = makeStore();
    const before = setup({ sessionStore, secret: OLD });
    const { cookies } = before;
    await login(before.auth, cookies);

    // New first, old behind it: everyone stays logged in.
    const during = setup({ sessionStore, secret: [NEW, OLD] });
    expect((await during.auth.readSession(cookies))?.user?.sub).toBe('user-1');
    expect(await during.auth.refreshSession(cookies)).toMatchObject({ ok: true, refreshed: true });

    // The old one can go when the sessions it sealed have been saved again or have run out.
    const after = setup({ sessionStore, secret: NEW });
    expect((await after.auth.readSession(cookies))?.user?.sub).toBe('user-1');
    expect(await before.auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'unreadable_session' });
    expect(during.events.filter((event) => event.event === 'session.rejected')).toEqual([]);
  });

  it('finishes a login that was started before the secret was replaced', async () => {
    const OLD = secret;
    const NEW = 'c'.repeat(64);
    const before = setup({ secret: OLD });
    const { cookies } = before;
    const started = await before.auth.handleOidcLogin(get('/api/auth/login'), cookies);
    const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');

    const during = setup({ secret: [NEW, OLD] });
    const response = await during.auth.handleOidcCallback(get(`/api/auth/callback?code=c&state=${state}`), cookies);

    expect(response.headers.get('location')).toBe(`${APP}/?login=success`);
    expect((await setup({ secret: NEW }).auth.readSession(cookies))?.user?.sub).toBe('user-1');
  });

  it('answers the heartbeat with 503, not a throw, when the store lock fails', async () => {
    const store = {
      ...createMemorySessionStore(),
      withLock: async () => {
        throw new Error('lock timeout');
      },
    };
    const { auth, cookies } = setup({ sessionStore: store });
    await login(auth, cookies);

    expect(await auth.refreshSession(cookies)).toMatchObject({ ok: false, cause: 'store' });
    const heartbeat = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
    expect(heartbeat.status).toBe(503);
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  describe('ending a session where its cookie can\'t be deleted', () => {
    /** The request's cookies, readable, and refusing every write as a response already built would. */
    function readOnly(jar: Map<string, string>) {
      const late = new Error('Cookie "__Host-session" was set after the response\'s cookies were taken');
      const cookies: CookieStore = {
        get: (name) => jar.get(name) ?? null,
        set: () => {
          throw late;
        },
      };
      return { cookies, late };
    }

    it('with a store, clearSession ends the session and revokes its token, and then says the cookie is left', async () => {
      const sessionStore = createMemorySessionStore();
      const { auth, cookies, jar, events } = setup({ sessionStore });
      await login(auth, cookies);
      const { cookies: built, late } = readOnly(jar);

      await expect(auth.clearSession(built)).rejects.toBe(late);

      expect(oidc.revoke).toHaveBeenCalledExactlyOnceWith('refresh-1', { tokenTypeHint: 'refresh_token' });
      // The browser keeps the handle, and it finds nothing.
      expect(jar.has('__Host-session')).toBe(true);
      expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
      expect(events.at(-1)).toMatchObject({ event: 'session.cleared', trigger: 'logout' });
    });

    it('with a store, it revokes the tokens of a refresh that came just before', async () => {
      const sessionStore = createMemorySessionStore();
      const { auth, cookies, jar } = setup({ sessionStore });
      await login(auth, cookies);
      await auth.refreshSession(cookies);

      await expect(auth.clearSession(readOnly(jar).cookies)).rejects.toThrow();
      expect(oidc.revoke).toHaveBeenCalledExactlyOnceWith('refresh-2', { tokenTypeHint: 'refresh_token' });
    });

    it('with a store, the logout goes on to the provider: the user is logged out', async () => {
      const sessionStore = createMemorySessionStore();
      const onLogoutError = vi.fn();
      const { auth, cookies, jar } = setup({ sessionStore, onLogoutError });
      await login(auth, cookies);

      const response = await auth.handleOidcLogout(post('/api/auth/logout'), readOnly(jar).cookies);

      expect(response.headers.get('location')).toMatch(/^https:\/\/idp\.test\/logout/);
      expect(onLogoutError).not.toHaveBeenCalled();
      expect(oidc.revoke).toHaveBeenCalledExactlyOnceWith('refresh-1', { tokenTypeHint: 'refresh_token' });
      expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
    });

    it('with cookie storage, nothing is ended: the cookie is the session', async () => {
      const { auth, cookies, jar } = setup();
      await login(auth, cookies);
      const { cookies: built, late } = readOnly(jar);

      await expect(auth.clearSession(built)).rejects.toBe(late);
      expect(oidc.revoke).not.toHaveBeenCalled();
      expect((await auth.readSession(cookies))?.user?.sub).toBe('user-1');

      const response = await auth.handleOidcLogout(post('/api/auth/logout'), built);
      expect(response.headers.get('location')).toBe(`${APP}/?logout=error&error=logout_failed`);
      expect(oidc.revoke).not.toHaveBeenCalled();
    });

    it('with a store that fails, clearSession rejects with what the store threw, and revokes nothing', async () => {
      const base = createMemorySessionStore();
      const down = new Error('db down');
      const state = { down: false };
      const sessionStore: SessionStore = {
        ...base,
        delete: async (key) => {
          if (state.down) throw down;
          return base.delete(key);
        },
      };
      const { auth, cookies } = setup({ sessionStore });
      await login(auth, cookies);
      state.down = true;

      await expect(auth.clearSession(cookies)).rejects.toBe(down);
      expect(oidc.revoke).not.toHaveBeenCalled();
      state.down = false;
      expect((await auth.readSession(cookies))?.user?.sub).toBe('user-1');
    });
  });

  describe('endUserSessions', () => {
    it('ends a user\'s sessions in every browser, and revokes their refresh tokens', async () => {
      const store = createMemorySessionStore();
      const { auth, cookies, events } = setup({ sessionStore: store });
      const phone = cookieJar();
      await login(auth, cookies);
      await login(auth, phone.cookies);
      await auth.refreshSession(phone.cookies);

      expect(await auth.endUserSessions({ sub: 'user-1' })).toBe(2);

      expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
      expect(await auth.tryReadSession(phone.cookies)).toEqual({ session: null, reason: 'session_not_found' });
      expect(oidc.revoke.mock.calls.map(([token]) => token).sort()).toEqual(['refresh-1', 'refresh-2']);
      expect(events.filter((event) => event.event === 'session.cleared')).toHaveLength(2);
    });

    it('ends nothing for another user, and takes the issuer as an option', async () => {
      const { auth, cookies } = setup({ sessionStore: createMemorySessionStore() });
      await login(auth, cookies);

      expect(await auth.endUserSessions({ sub: 'user-2', iss: 'https://idp.test' })).toBe(0);
      // An issuer that is given but empty, an unset variable say, is refused, not read as "any".
      await expect(auth.endUserSessions({ sub: 'user-1', iss: '' })).rejects.toThrow(TypeError);
      expect(await auth.endUserSessions({ sub: 'user-1', iss: 'https://other.test' })).toBe(0);
      expect(await auth.readSession(cookies)).not.toBeNull();
      expect(oidc.metadata).not.toHaveBeenCalled();
      expect(oidc.revoke).not.toHaveBeenCalled();
    });

    it('throws with cookie sessions, rather than end nobody\'s', async () => {
      const { auth, cookies } = setup();
      await login(auth, cookies);
      await expect(auth.endUserSessions({ sub: 'user-1', iss: 'https://idp.test' })).rejects.toThrow(TypeError);
    });

    it('asks the provider for nothing, so it works while the provider is down', async () => {
      const store = createMemorySessionStore();
      const { auth, cookies } = setup({ sessionStore: store });
      await login(auth, cookies);

      // Another instance over the same store, whose provider can't be reached.
      const cold = setup({ sessionStore: store });
      oidc.metadata.mockRejectedValue(new Error('provider down'));

      expect(await cold.auth.endUserSessions({ sub: 'user-1' })).toBe(1);
      expect(oidc.metadata).not.toHaveBeenCalled();
      expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
    });

    it('finds the sessions however the config spells the issuer', async () => {
      // The ID tokens say `https://idp.test`. Each of these is the same issuer to
      // a person, and another string to a store.
      for (const issuer of ['https://IDP.test', 'https://idp.test/', 'https://idp.test:443']) {
        const { auth, cookies } = setup({
          sessionStore: createMemorySessionStore(),
          oauthConfig: {
            issuer,
            clientId: 'web',
            clientSecret: 'shh',
            redirectUri: `${APP}/api/auth/callback`,
            scope: 'openid profile offline_access',
          },
        });
        const phone = cookieJar();
        await login(auth, cookies);
        await login(auth, phone.cookies);

        expect(await auth.endUserSessions({ sub: 'user-1' })).toBe(2);
        expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
      }
    });

    it('ends only one provider\'s sessions when the issuer is named', async () => {
      // Two providers that share a store and a secret, each with a `user-1`.
      const store = createMemorySessionStore();
      const { auth, cookies } = setup({ sessionStore: store });
      const elsewhere = cookieJar();
      await login(auth, cookies);
      oidc.exchangeCode.mockResolvedValueOnce(
        tokens(1, { id_token: new UnsecuredJWT({ iss: 'https://other.test', sub: 'user-1' }).encode() }),
      );
      await login(auth, elsewhere.cookies);

      expect(await auth.endUserSessions({ sub: 'user-1', iss: 'https://other.test' })).toBe(1);
      expect(await auth.readSession(cookies)).not.toBeNull();
      expect(await auth.tryReadSession(elsewhere.cookies)).toEqual({ session: null, reason: 'session_not_found' });

      // Without one, the sub is the whole question.
      await login(auth, elsewhere.cookies);
      expect(await auth.endUserSessions({ sub: 'user-1' })).toBe(2);
    });

    it('hands the store only the keys to compare', async () => {
      const store = createMemorySessionStore();
      const findMatching = vi.spyOn(store, 'findMatching');
      const { auth, cookies } = setup({ sessionStore: store });
      await login(auth, cookies);

      await auth.endUserSessions({ sub: 'nobody' });
      expect(Object.keys(findMatching.mock.calls[0]![0])).toEqual(['subHash']);
      await auth.endUserSessions({ sub: 'nobody', iss: 'https://idp.test' });
      expect(Object.keys(findMatching.mock.calls[1]![0]).sort()).toEqual(['iss', 'subHash']);
    });
  });

  it('keeps the app\'s storeFields next to the stored session', async () => {
    const store = createMemorySessionStore();
    const set = vi.spyOn(store, 'set');
    const { auth, cookies } = setup({
      sessionStore: store,
      storeFields: (session) => ({ userId: session.user?.sub ?? null }),
    });
    await login(auth, cookies);
    expect(set.mock.calls[0]?.[1].fields).toEqual({ userId: 'user-1' });
    expect(set.mock.calls[0]?.[2]).toEqual({ continuation: false, reason: 'login' });
  });

  describe('readSessionWithTokens', () => {
    it('gives the session and its tokens from one read of the store', async () => {
      const store = createMemorySessionStore();
      const { auth, cookies } = setup({ sessionStore: store });
      await login(auth, cookies);
      const get = vi.spyOn(store, 'get');

      const result = await auth.readSessionWithTokens(cookies);
      expect(result.session?.user?.name).toBe('Ada');
      expect(result.tokens).toMatchObject({ accessToken: 'access-1', refreshToken: 'refresh-1' });
      expect(result.reason).toBeUndefined();
      expect(get).toHaveBeenCalledTimes(1);
      // The session it hands back carries no tokens, as elsewhere.
      expect(JSON.stringify(result.session)).not.toContain('access-1');
    });

    it('says why when there is no session', async () => {
      const { auth, cookies } = setup();
      expect(await auth.readSessionWithTokens(cookies)).toEqual({
        session: null,
        tokens: null,
        reason: 'no_session_cookie',
      });
    });

    it('gives the tokens a refresh saved', async () => {
      const { auth, cookies } = setup();
      await login(auth, cookies);
      await auth.refreshSession(cookies);
      expect((await auth.readSessionWithTokens(cookies)).tokens?.accessToken).toBe('access-2');
    });
  });

  it('keeps the session in a store when given one', async () => {
    const store = createMemorySessionStore();
    const { auth, cookies, jar } = setup({ sessionStore: store });
    await login(auth, cookies);

    const handle = jar.get('__Host-session') ?? '';
    expect(handle).toMatch(/^[0-9a-f]{64}$/);
    expect((await auth.readSession(cookies))?.user?.name).toBe('Ada');

    await auth.handleOidcLogout(post('/api/auth/logout'), cookies);
    expect(jar.size).toBe(0);
    // A replayed handle finds nothing: the record went with the logout.
    jar.set('__Host-session', handle);
    expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
  });

  describe('a refresh the provider refuses for good', () => {
    it('ends a stored session, so later reads find none', async () => {
      const { auth, cookies } = setup({ sessionStore: createMemorySessionStore() });
      await login(auth, cookies);
      oidc.refresh.mockRejectedValueOnce(oauthError('invalid_grant'));

      const heartbeat = await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies);
      expect(heartbeat.status).toBe(401);
      expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'no_session_cookie' });
    });

    it('deletes the cookie of the stored session it ends, so the browser stops sending it', async () => {
      const { auth, cookies, jar } = setup({ sessionStore: createMemorySessionStore() });
      await login(auth, cookies);
      expect(jar.has('__Host-session')).toBe(true);
      oidc.refresh.mockRejectedValueOnce(oauthError('invalid_grant'));

      expect(await auth.refreshSession(cookies)).toMatchObject({ ok: false, cause: 'invalid_grant' });
      expect(jar.size).toBe(0);
    });

    it('leaves a cookie session for the app to end', async () => {
      const { auth, cookies, jar } = setup();
      await login(auth, cookies);
      oidc.refresh.mockRejectedValueOnce(oauthError('invalid_grant'));

      const result = await auth.refreshSession(cookies);
      expect(result).toMatchObject({ ok: false, cause: 'invalid_grant' });
      expect(await auth.readSession(cookies)).not.toBeNull();

      // The recipe from the README.
      if (!result.ok && result.cause === 'invalid_grant') {
        await auth.clearSession(cookies, { trigger: 'rejected' });
      }
      expect(jar.size).toBe(0);
      expect(await auth.readSession(cookies)).toBeNull();
    });
  });
});

describe('authorizedFetch', () => {
  const api = 'https://api.test/';

  /** An API that accepts only `access-2`, and records the Authorization headers it got. */
  function stubApi(): Array<string | null> {
    const seen: Array<string | null> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: Request | string | URL, init?: RequestInit) => {
        const authorization = new Headers(init?.headers).get('authorization');
        seen.push(authorization);
        return authorization === 'Bearer access-2'
          ? Response.json({ ok: true })
          : new Response(null, { status: 401 });
      }),
    );
    return seen;
  }

  it('sends the access token and never refreshes: a 401 is an http_error', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const seen = stubApi();
    try {
      await expect(
        auth.authorizedFetch(cookies, `${api}items`, { allowedBase: api }),
      ).rejects.toMatchObject({ reason: 'http_error', status: 401, accessTokenExpired: false });
      expect(seen).toEqual(['Bearer access-1']);
      expect(oidc.refresh).not.toHaveBeenCalled();
      expect((await auth.getTokens(cookies))?.accessToken).toBe('access-1');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('uses the tokens refreshSession saved', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const seen = stubApi();
    try {
      await auth.refreshSession(cookies);
      const result = await auth.authorizedFetch(cookies, `${api}items`, {
        allowedBase: api,
        parse: (response) => response.json() as Promise<{ ok: boolean }>,
      });
      expect(result.data).toEqual({ ok: true });
      expect(seen).toEqual(['Bearer access-2']);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('refuses a URL outside allowedBase', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    await expect(
      auth.authorizedFetch(cookies, 'https://evil.test/x', { allowedBase: api }),
    ).rejects.toThrow();
  });
});

describe('over Request and Response, with fetchCookieStore', () => {
  /** A browser tab: keeps the cookies responses set, and sends them with its requests. */
  function browser() {
    const jar = new Map<string, string>();
    return {
      jar,
      receive(response: Response): Response {
        for (const line of response.headers.getSetCookie()) {
          const [pair = '', ...attributes] = line.split('; ');
          const name = pair.slice(0, pair.indexOf('='));
          if (attributes.includes('Max-Age=0')) jar.delete(name);
          else jar.set(name, pair.slice(name.length + 1));
        }
        return response;
      },
      request(path: string, init: RequestInit = {}): Request {
        const headers = new Headers(init.headers);
        if (jar.size > 0) headers.set('cookie', [...jar].map(([name, value]) => `${name}=${value}`).join('; '));
        return new Request(`${APP}${path}`, { ...init, headers });
      },
    };
  }

  it('runs login, a read, a refresh and logout', async () => {
    const { auth } = setup();
    const tab = browser();

    let request = tab.request('/api/auth/login?returnTo=%2Faccount');
    let cookies = fetchCookieStore(request);
    const started = tab.receive(cookies.apply(await auth.handleOidcLogin(request, cookies)));
    expect(started.status).toBe(302);
    expect([...tab.jar.keys()]).toEqual([expect.stringMatching(/^__Host-oauth_tx_/)]);
    // A `__Host-` cookie is only kept when it is Secure and on `/`.
    for (const line of started.headers.getSetCookie()) {
      expect(line).toMatch(/; Path=\/;.*; HttpOnly; Secure; SameSite=Lax$/);
    }

    const state = location(started).searchParams.get('state');
    request = tab.request(`/api/auth/callback?code=abc&state=${state}`);
    cookies = fetchCookieStore(request);
    const landed = tab.receive(cookies.apply(await auth.handleOidcCallback(request, cookies)));
    expect(location(landed).pathname).toBe('/account');
    // The login transaction is spent, and the session is in its place.
    expect([...tab.jar.keys()]).toEqual(['__Host-session']);

    expect((await auth.readSession(fetchCookieStore(tab.request('/account'))))?.user?.name).toBe('Ada');

    // A route that refreshes and builds its own response.
    request = tab.request('/account');
    cookies = fetchCookieStore(request);
    await auth.refreshSession(cookies);
    // The same store reads the cookies it just wrote.
    expect((await auth.getTokens(cookies))?.accessToken).toBe('access-2');
    tab.receive(new Response(null, { headers: cookies.headers() }));
    expect((await auth.getTokens(fetchCookieStore(tab.request('/account'))))?.accessToken).toBe('access-2');

    request = tab.request('/api/auth/logout', { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } });
    cookies = fetchCookieStore(request);
    const out = tab.receive(cookies.apply(await auth.handleOidcLogout(request, cookies)));
    expect(out.headers.get('location')).toBe('https://idp.test/logout');
    expect(tab.jar.size).toBe(0);
  });

  it('keeps a session too big for one cookie in chunks, and deletes them all at logout', async () => {
    const { auth } = setup();
    const tab = browser();
    let request = tab.request('/');
    let cookies = fetchCookieStore(request);
    await auth.createSession(cookies, tokens(1, { access_token: 'x'.repeat(5000) }));
    tab.receive(new Response(null, { headers: cookies.headers() }));
    expect([...tab.jar.keys()]).toEqual(['__Host-session', '__Host-session.1']);
    expect((await auth.getTokens(fetchCookieStore(tab.request('/'))))?.accessToken).toHaveLength(5000);

    request = tab.request('/');
    cookies = fetchCookieStore(request);
    await auth.clearSession(cookies);
    tab.receive(new Response(null, { headers: cookies.headers() }));
    expect(tab.jar.size).toBe(0);
  });

  it('refuses a refresh after the cookies were taken, as it could not reach the browser', async () => {
    const { auth } = setup();
    const cookies = fetchCookieStore(browser().request('/'));
    await auth.createSession(cookies, tokens(1));
    cookies.headers();
    await expect(auth.refreshSession(cookies)).rejects.toThrow(/was set after the response's cookies were taken/);
  });
});

describe('roles', () => {
  const realmRoles = (claims: Record<string, unknown>) =>
    (claims.realm_access as { roles?: string[] } | undefined)?.roles;
  const withRealmRoles = (n: number, roles: string[]) =>
    tokens(n, {
      id_token: new UnsecuredJWT({ iss: 'https://idp.test', sub: 'user-1', realm_access: { roles } }).encode(),
    });

  it('reads a nested claim through a rolesClaim function, at login and at every refresh', async () => {
    const { auth, cookies } = setup({ rolesClaim: realmRoles });
    oidc.exchangeCode.mockResolvedValueOnce(withRealmRoles(1, ['admin']));
    await login(auth, cookies);
    expect((await auth.readSession(cookies))?.user?.roles).toEqual(['admin']);

    oidc.refresh.mockResolvedValueOnce(withRealmRoles(2, ['admin']));
    await auth.refreshSession(cookies);
    expect((await auth.readSession(cookies))?.user?.roles).toEqual(['admin']);

    oidc.refresh.mockResolvedValueOnce(withRealmRoles(3, []));
    await auth.refreshSession(cookies);
    expect((await auth.readSession(cookies))?.user?.roles).toEqual([]);
  });

  it('keeps the roles mapSession set through a refresh, with rolesClaim false', async () => {
    const { auth, cookies } = setup({
      rolesClaim: false,
      mapSession: (_tokens, claims, session) => ({
        ...session,
        user: session.user && { ...session.user, roles: realmRoles(claims ?? {}) ?? [] },
      }),
    });
    oidc.exchangeCode.mockResolvedValueOnce(withRealmRoles(1, ['admin']));
    await login(auth, cookies);
    oidc.refresh.mockResolvedValueOnce(withRealmRoles(2, ['admin']));
    expect(await auth.refreshSession(cookies)).toMatchObject({ ok: true, refreshed: true });
    expect((await auth.readSession(cookies))?.user?.roles).toEqual(['admin']);
  });

  describe('roles that mapSession set while rolesClaim reads them too', () => {
    function warned(overrides: Partial<FidesAuthConfig>) {
      const warn = vi.fn();
      const made = setup({ logger: { create: () => ({ ...quiet, warn }) }, ...overrides });
      return { ...made, warn };
    }
    const fromRealm: FidesAuthConfig['mapSession'] = (_tokens, claims, session) => ({
      ...session,
      user: session.user && { ...session.user, roles: realmRoles(claims ?? {}) ?? [] },
    });

    it('are gone after a refresh, which the first such login warns about, once', async () => {
      const { auth, cookies, warn } = warned({ mapSession: fromRealm });
      oidc.exchangeCode.mockResolvedValue(withRealmRoles(1, ['admin']));
      await login(auth, cookies);
      await login(auth, cookieJar().cookies);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn).toHaveBeenCalledWith(
        { correlationId: (await auth.readSession(cookies))?.correlationId },
        expect.stringContaining('rolesClaim'),
      );

      oidc.refresh.mockResolvedValueOnce(withRealmRoles(2, ['admin']));
      await auth.refreshSession(cookies);
      expect((await auth.readSession(cookies))?.user?.roles).toEqual([]);
    });

    it('bring no warning when mapSession leaves the roles alone, or rolesClaim is false', async () => {
      const untouched = warned({ mapSession: (_tokens, _claims, session) => ({ ...session, data: { a: 1 } }) });
      await login(untouched.auth, untouched.cookies);
      expect(untouched.warn).not.toHaveBeenCalled();

      const handsOff = warned({ rolesClaim: false, mapSession: fromRealm });
      oidc.exchangeCode.mockResolvedValueOnce(withRealmRoles(1, ['admin']));
      await login(handsOff.auth, handsOff.cookies);
      expect(handsOff.warn).not.toHaveBeenCalled();
    });
  });
});

describe('mapRefresh', () => {
  interface AppData {
    tenant: string;
  }
  const withTenant = (n: number, tenant: string) =>
    tokens(n, {
      id_token: new UnsecuredJWT({ iss: 'https://idp.test', sub: 'user-1', name: 'Ada', tenant }).encode(),
    });

  it('lets data follow the claims of each refresh, typed like mapSession', async () => {
    const { auth, cookies } = setup<AppData>({
      mapSession: (_tokens, claims, session) => ({ ...session, data: { tenant: String(claims?.tenant) } }),
      mapRefresh: (_tokens, claims, session) =>
        // A refresh without an ID token has no claims to follow.
        claims ? { ...session, data: { tenant: String(claims.tenant) } } : session,
    });
    oidc.exchangeCode.mockResolvedValueOnce(withTenant(1, 'acme'));
    await login(auth, cookies);
    expect((await auth.readSession(cookies))?.data).toEqual({ tenant: 'acme' });

    oidc.refresh.mockResolvedValueOnce(withTenant(2, 'globex'));
    const refreshed = await auth.refreshSession(cookies);
    expect(refreshed).toMatchObject({ ok: true, session: { data: { tenant: 'globex' } } });
    if (refreshed.ok) expectTypeOf(refreshed.session.data).toEqualTypeOf<AppData | undefined>();

    oidc.refresh.mockResolvedValueOnce(tokens(3, { id_token: undefined }));
    await auth.refreshSession(cookies);
    expect((await auth.readSession(cookies))?.data).toEqual({ tenant: 'globex' });
  });

  it('keeps roles that are not in the ID token, set at login and again at each refresh, without a warning', async () => {
    // Roles that only the access token carries, as Keycloak sends them unless told otherwise.
    const rolesOf = (accessToken: string) => (accessToken === 'access-1' ? ['admin'] : ['admin', 'editor']);
    const warn = vi.fn();
    const { auth, cookies } = setup({
      logger: { create: () => ({ ...quiet, warn }) },
      mapSession: (response, _claims, session) => ({
        ...session,
        user: session.user && { ...session.user, roles: rolesOf(response.access_token) },
      }),
      mapRefresh: (response, _claims, session) => ({
        ...session,
        user: session.user && { ...session.user, roles: rolesOf(response.access_token) },
      }),
    });
    oidc.exchangeCode.mockResolvedValueOnce(withTenant(1, 'acme'));
    await login(auth, cookies);
    expect((await auth.readSession(cookies))?.user?.roles).toEqual(['admin']);

    oidc.refresh.mockResolvedValueOnce(withTenant(2, 'acme'));
    await auth.refreshSession(cookies);
    expect((await auth.readSession(cookies))?.user?.roles).toEqual(['admin', 'editor']);
    expect(warn).not.toHaveBeenCalled();
  });

  it('also runs for the heartbeat\'s refresh', async () => {
    const mapRefresh = vi.fn<NonNullable<FidesAuthConfig['mapRefresh']>>((_tokens, _claims, session) => session);
    const { auth, cookies } = setup({ mapRefresh });
    await login(auth, cookies);
    expect((await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies)).status).toBe(200);
    expect(mapRefresh).toHaveBeenCalledTimes(1);
  });
});

describe('token status', () => {
  const start = Date.parse('2026-11-14T12:00:00Z');
  const minutes = (n: number) => start + n * 60_000;

  beforeEach(() => {
    vi.useFakeTimers({ now: start, toFake: ['Date'] });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const info = async (auth: FidesAuth, cookies: CookieStore) =>
    (await (await auth.handleSessionInfo(get('/api/auth/session'), cookies)).json()) as SessionInfo;

  it('is active while the access token lives, and refreshable once it has expired with a refresh token', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    expect(await auth.tryReadSession(cookies)).toMatchObject({ tokenStatus: 'active' });
    expect(await info(auth, cookies)).toMatchObject({ authenticated: true, tokenStatus: 'active' });

    // The tokens live five minutes.
    vi.setSystemTime(minutes(6));
    expect(await auth.tryReadSession(cookies)).toMatchObject({ tokenStatus: 'refreshable' });
    expect(await auth.readSessionWithTokens(cookies)).toMatchObject({ tokenStatus: 'refreshable' });
    expect(await info(auth, cookies)).toMatchObject({ authenticated: true, tokenStatus: 'refreshable' });

    await auth.refreshSession(cookies);
    expect(await auth.tryReadSession(cookies)).toMatchObject({ tokenStatus: 'active' });
  });

  it('is expired for a session without a refresh token whose access token has died, and the session still reads', async () => {
    const { auth, cookies } = setup();
    oidc.exchangeCode.mockResolvedValueOnce(tokens(1, { refresh_token: undefined }));
    await login(auth, cookies);
    expect(await auth.tryReadSession(cookies)).toMatchObject({ tokenStatus: 'active' });

    vi.setSystemTime(minutes(6));
    const read = await auth.tryReadSession(cookies);
    expect(read.session?.user?.name).toBe('Ada');
    expect(read.tokenStatus).toBe('expired');
    expect(await info(auth, cookies)).toMatchObject({ authenticated: true, tokenStatus: 'expired' });

    // The rule "a session is no better than its token", for an app that wants it.
    if (read.tokenStatus === 'expired') await auth.clearSession(cookies, { trigger: 'rejected' });
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('is active when the provider gave no lifetime to go by', async () => {
    const { auth, cookies } = setup();
    oidc.exchangeCode.mockResolvedValueOnce(tokens(1, { expires_in: undefined, refresh_token: undefined }));
    await login(auth, cookies);
    vi.setSystemTime(minutes(600));
    expect(await auth.tryReadSession(cookies)).toMatchObject({ tokenStatus: 'active' });
  });

  it('is absent without a session', async () => {
    const { auth, cookies } = setup();
    expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'no_session_cookie' });
    expect(await info(auth, cookies)).toEqual({ authenticated: false });
    expectTypeOf((await auth.tryReadSession(cookies)).tokenStatus).toEqualTypeOf<TokenStatus | undefined>();
  });
});

describe('typed session data', () => {
  interface AppData {
    tenant: string;
    visits: number;
  }

  function typedSetup() {
    return setup<AppData>({
      sessionStore: createMemorySessionStore(),
      mapSession: (_tokens, claims, session) => ({
        ...session,
        data: { tenant: String(claims?.sub), visits: 1 },
      }),
      storeFields: (session) => ({ tenant: session.data?.tenant ?? null }),
    });
  }

  it('gives session.data the type the instance was created with', async () => {
    const { auth, cookies } = typedSetup();
    await login(auth, cookies);

    const session = await auth.readSession(cookies);
    expectTypeOf(session).toEqualTypeOf<Session<AppData> | null>();
    expect(session?.data).toEqual({ tenant: 'user-1', visits: 1 });
    // No cast: `tenant` is a string to the compiler.
    expect(session?.data?.tenant.toUpperCase()).toBe('USER-1');

    expectTypeOf((await auth.tryReadSession(cookies)).session).toEqualTypeOf<Session<AppData> | null>();
    expectTypeOf((await auth.readSessionWithTokens(cookies)).session).toEqualTypeOf<Session<AppData> | null>();
    const refreshed = await auth.refreshSession(cookies);
    if (refreshed.ok) expectTypeOf(refreshed.session.data).toEqualTypeOf<AppData | undefined>();

    const updated = await auth.updateSession(cookies, (current) => ({
      ...current,
      data: { tenant: current.data?.tenant ?? '', visits: (current.data?.visits ?? 0) + 1 },
    }));
    expectTypeOf(updated).toEqualTypeOf<Session<AppData> | null>();
    expect(updated?.data).toEqual({ tenant: 'user-1', visits: 2 });
  });

  it('refuses data of another shape at compile time', async () => {
    const { auth, cookies } = typedSetup();
    // With no session nothing is written; the line is here for the compiler.
    const result = await auth.updateSession(cookies, (current) => ({
      ...current,
      // @ts-expect-error visits is a number
      data: { tenant: 'a', visits: 'many' },
    }));
    expect(result).toBeNull();
  });

  it('leaves data an open record without a type argument', async () => {
    const { auth, cookies } = setup();
    await login(auth, cookies);
    const session = await auth.readSession(cookies);
    expectTypeOf(session).toEqualTypeOf<Session | null>();
    expectTypeOf(session?.data).toEqualTypeOf<Record<string, unknown> | undefined>();
  });
});

describe('the reason a store gets', () => {
  it('is login, refresh and update, and storeFields may hold a list of strings', async () => {
    const store = createMemorySessionStore();
    const set = vi.spyOn(store, 'set');
    const { auth, cookies } = setup({
      sessionStore: store,
      storeFields: (session) => ({ roles: session.user?.roles ?? [] }),
    });
    await login(auth, cookies);
    await auth.refreshSession(cookies);
    await auth.updateSession(cookies, (current) => current);

    expect(set.mock.calls.map(([, , context]) => context)).toEqual([
      { continuation: false, reason: 'login' },
      { continuation: true, reason: 'refresh' },
      { continuation: true, reason: 'update' },
    ]);
    expect(set.mock.calls[0]?.[1].fields).toEqual({ roles: ['admin'] });
  });

  it('types storeFields values as scalars or lists of strings', () => {
    const lists: StoreFields = { roles: ['admin'], userId: 'u', active: true, team: null, n: 1 };
    expectTypeOf(lists).toMatchTypeOf<StoreFields>();
    // @ts-expect-error a nested object is not a field value
    const nested: StoreFields = { profile: { name: 'Ada' } };
    expect(nested).toBeDefined();
  });
});
