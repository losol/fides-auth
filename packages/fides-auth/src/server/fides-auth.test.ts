/**
 * createFidesAuth end to end: the handlers and members share one cookie jar,
 * the way a browser carries cookies between requests. The OIDC client is
 * replaced with a fake, since the protocol layer has its own tests; what is
 * tested here is how the instance drives it and the session lifecycle.
 */
import { UnsecuredJWT } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../protocol/client.js', () => ({ createOidcClient: vi.fn() }));

import type { FidesLogger } from '../shared/logger.js';
import type { SessionEvent } from '../shared/session-events.js';
import type { TokenResponse } from '../shared/types.js';
import { createOidcClient, type OidcClient } from '../protocol/client.js';
import { createRecord, sealRecord } from '../session/record.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type FidesAuthConfig } from './fides-auth.js';
import { SessionSecretError } from './session-secret.js';
import { createMemorySessionStore } from './session-store.js';

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
  };
  return client;
}

let oidc: ReturnType<typeof fakeOidc>;

beforeEach(() => {
  oidc = fakeOidc();
  vi.mocked(createOidcClient).mockReturnValue(oidc as unknown as OidcClient);
});

function setup(overrides: Partial<FidesAuthConfig> = {}) {
  const events: SessionEvent[] = [];
  const auth = createFidesAuth({
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
  auth: ReturnType<typeof setup>['auth'],
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
});

describe('return paths', () => {
  it.each([
    ['//evil.test/x', `${APP}/?login=success`],
    ['https://evil.test/x', `${APP}/?login=success`],
    ['/\\evil.test', `${APP}/?login=success`],
    ['/ok', `${APP}/ok?login=success`],
  ])('returnTo %s lands on %s', async (returnTo, expected) => {
    const { auth, cookies } = setup();
    expect(location(await login(auth, cookies, returnTo)).toString()).toBe(expected);
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
  it('asks for a new login without a transaction', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleOidcCallback(get('/api/auth/callback?code=abc&state=nope'), cookies);
    expect(response.status).toBe(400);
    expect(oidc.exchangeCode).not.toHaveBeenCalled();
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

  it('answers 500 when the code exchange fails, and spends the transaction', async () => {
    const { auth, cookies, jar } = setup();
    oidc.exchangeCode.mockRejectedValueOnce(oauthError('invalid_grant'));
    const response = await login(auth, cookies);
    expect(response.status).toBe(500);
    expect(jar.size).toBe(0);
  });

  it('answers 431 when the session does not fit in the cookies', async () => {
    const { auth, cookies } = setup();
    oidc.exchangeCode.mockResolvedValueOnce(tokens(1, { access_token: 'x'.repeat(20_000) }));
    expect((await login(auth, cookies)).status).toBe(431);
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
    expect((await auth.handleOidcLogin(get('/api/auth/login'), cookies)).status).toBe(429);
    expect((await auth.handleOidcCallback(get('/api/auth/callback?code=a&state=b'), cookies)).status).toBe(429);
    expect((await auth.handleOidcLogout(post('/api/auth/logout'), cookies)).status).toBe(429);
    expect((await auth.handleHeartbeat(post('/api/auth/heartbeat'), cookies)).status).toBe(429);
    expect(rateLimit).toHaveBeenCalledTimes(4);
    expect(oidc.createAuthorizationRequest).not.toHaveBeenCalled();
  });

  it('answers session info only to GET and HEAD', async () => {
    const { auth, cookies } = setup();
    const response = await auth.handleSessionInfo(post('/api/auth/session'), cookies);
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
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
      const record = createRecord(tokens(1, { expires_in: 20 }), { sessionDurationDays: 1 });
      delete record.tokens.accessTokenIssuedAt;
      jar.set('__Host-session', await sealRecord(record, secret));
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

  describe('endUserSessions', () => {
    it('ends a user\'s sessions in every browser, and revokes their refresh tokens', async () => {
      const store = createMemorySessionStore();
      const { auth, cookies, events } = setup({ sessionStore: store });
      oidc.metadata.mockResolvedValue({ issuer: 'https://idp.test' });
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
    expect(set.mock.calls[0]?.[2]).toEqual({ continuation: false });
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
