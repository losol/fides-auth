/**
 * The Next binding over the real core instance. next/headers and React's cache()
 * are small fakes, and fetch answers for the provider's token endpoint and one
 * API, so the protocol and session code run as they do in an app.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { jar, render } = vi.hoisted(() => ({
  jar: new Map<string, string>(),
  render: { id: 0, cookieCalls: 0 },
}));

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => {
    render.cookieCalls += 1;
    return {
      get: (name: string) => (jar.has(name) ? { name, value: jar.get(name) } : undefined),
      set: (name: string, value: string, options?: { maxAge?: number }) => {
        if (options?.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
      },
      delete: (name: string) => {
        jar.delete(name);
      },
    };
  }),
}));

// React's cache() memoizes for one server render; here a render lasts until newRender().
vi.mock('react', () => ({
  cache: <A extends unknown[], R>(fn: (...args: A) => R) => {
    let seen = -1;
    let value: R;
    return (...args: A): R => {
      if (seen !== render.id) {
        seen = render.id;
        value = fn(...args);
      }
      return value;
    };
  },
}));

import { createMemorySessionStore, type FidesAuthConfig, type SessionEvent } from '@eventuras/fides-auth/server';
import { NextRequest } from 'next/server';

import { createFidesAuth, type FidesAuth } from './index.js';

const APP = 'https://app.test';
const ISSUER = 'https://idp.test';
const API = 'https://api.test/';
const secret = 'a'.repeat(64);
const quiet = { debug() {}, info() {}, warn() {}, error() {} };

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

/** An ID token as the token endpoint returns it. Its signature isn't checked there. */
function idToken(): string {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: ISSUER, aud: 'web', sub: 'user-1', sid: 'idp-1', name: 'Ada', iat: now, exp: now + 300 };
  return `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64(claims)}.c2lnbmF0dXJl`;
}

interface Provider {
  /** The token endpoint's requests, as form bodies. */
  tokenRequests: URLSearchParams[];
  /** The ID tokens it issued. */
  idTokens: string[];
  /** The Authorization headers the API got. */
  apiCalls: Array<string | null>;
  /** Makes the next refresh fail with invalid_grant. */
  rejectNextRefresh(): void;
  /** Lifetime of the access tokens it issues, in seconds. */
  expiresIn: number;
}

/** Stubs fetch with the provider's token endpoint, and an API that rejects `access-1`. */
function stubProvider(): Provider {
  let issued = 0;
  let reject = false;
  const provider: Provider = {
    tokenRequests: [],
    idTokens: [],
    apiCalls: [],
    rejectNextRefresh: () => {
      reject = true;
    },
    expiresIn: 300,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.href === `${ISSUER}/token`) {
        const body = new URLSearchParams(String(init?.body ?? ''));
        provider.tokenRequests.push(body);
        if (reject && body.get('grant_type') === 'refresh_token') {
          reject = false;
          return Response.json({ error: 'invalid_grant' }, { status: 400 });
        }
        issued += 1;
        const id = body.get('grant_type') === 'authorization_code' ? idToken() : undefined;
        if (id) provider.idTokens.push(id);
        return Response.json({
          access_token: `access-${issued}`,
          token_type: 'Bearer',
          expires_in: provider.expiresIn,
          refresh_token: `refresh-${issued}`,
          ...(id ? { id_token: id } : {}),
        });
      }
      if (url.href.startsWith(API)) {
        const authorization = new Headers(init?.headers).get('authorization');
        provider.apiCalls.push(authorization);
        return authorization === 'Bearer access-1'
          ? new Response(null, { status: 401 })
          : Response.json({ ok: true });
      }
      throw new Error(`Unexpected request to ${url}`);
    }),
  );
  return provider;
}

function setup(overrides: Partial<FidesAuthConfig> = {}) {
  const events: SessionEvent[] = [];
  const auth = createFidesAuth({
    oauthConfig: {
      issuer: ISSUER,
      clientId: 'web',
      clientSecret: 'shh',
      redirectUri: `${APP}/api/auth/callback`,
      scope: 'openid profile offline_access',
      serverMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        end_session_endpoint: `${ISSUER}/logout`,
      },
    },
    secret,
    logger: { create: () => quiet },
    onSessionEvent: (event) => events.push(event),
    ...overrides,
  });
  return { auth, events };
}

/** A new server render: React's cache starts empty. */
function newRender(): void {
  render.id += 1;
  render.cookieCalls = 0;
}

const post = (path: string) =>
  new Request(`${APP}${path}`, { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } });

async function login(auth: FidesAuth): Promise<Response> {
  const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login?returnTo=%2Faccount`));
  const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');
  newRender();
  return auth.handleOidcCallback(new Request(`${APP}/api/auth/callback?code=abc&state=${state}`));
}

/** The browser's Cookie header for the jar. */
const cookieHeader = () => [...jar].map(([name, value]) => `${name}=${value}`).join('; ');

/** A request through the proxy, carrying the browser's cookies. */
const proxied = (path = '/account') => new NextRequest(`${APP}${path}`, { headers: { cookie: cookieHeader() } });

let provider: Provider;

beforeEach(() => {
  jar.clear();
  newRender();
  provider = stubProvider();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createFidesAuth for Next', () => {
  it('runs login, the callback, session info and logout on the request cookies', async () => {
    const { auth, events } = setup();

    const done = await login(auth);
    expect(done.status).toBe(302);
    expect(done.headers.get('location')).toBe(`${APP}/account?login=success`);
    expect([...jar.keys()]).toEqual(['__Host-session']);
    const [exchange] = provider.tokenRequests;
    expect(exchange?.get('grant_type')).toBe('authorization_code');
    expect(exchange?.get('code')).toBe('abc');
    expect(exchange?.get('redirect_uri')).toBe(`${APP}/api/auth/callback`);

    newRender();
    const session = await auth.readSession();
    expect(session?.user).toMatchObject({ sub: 'user-1', name: 'Ada' });
    expect(session?.idp).toEqual({ iss: ISSUER, sub: 'user-1', sid: 'idp-1' });

    const info = await auth.handleSessionInfo(new Request(`${APP}/api/auth/session`));
    expect(await info.json()).toMatchObject({ authenticated: true, user: { name: 'Ada' } });

    newRender();
    const out = await auth.handleOidcLogout(post('/api/auth/logout'));
    const logoutUrl = new URL(out.headers.get('location') ?? '');
    expect(logoutUrl.origin + logoutUrl.pathname).toBe(`${ISSUER}/logout`);
    expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(APP);
    expect(logoutUrl.searchParams.get('id_token_hint')).toBe(provider.idTokens[0]);
    expect(jar.size).toBe(0);

    expect(events.map((event) => event.event)).toEqual(['session.created', 'session.cleared']);
  });

  it('reads the session once per render', async () => {
    const { auth } = setup();
    await login(auth);

    newRender();
    await auth.readSession();
    await auth.tryReadSession();
    await auth.readSession();
    expect(render.cookieCalls).toBe(1);

    newRender();
    await auth.readSession();
    expect(render.cookieCalls).toBe(1);
  });

  it('refreshes through the heartbeat', async () => {
    const { auth } = setup();
    await login(auth);
    const before = jar.get('__Host-session');

    newRender();
    const response = await auth.handleHeartbeat(post('/api/auth/heartbeat'));
    expect(response.status).toBe(200);
    expect(provider.tokenRequests.at(-1)?.get('refresh_token')).toBe('refresh-1');
    expect(jar.get('__Host-session')).not.toBe(before);
    expect((await auth.getTokens())?.accessToken).toBe('access-2');
  });

  it('creates, updates and clears a session', async () => {
    const { auth, events } = setup();
    const created = await auth.createSession({
      access_token: 'access-0',
      token_type: 'bearer',
      expires_in: 300,
      id_token: idToken(),
    });
    expect(created.user?.name).toBe('Ada');

    newRender();
    await auth.updateSession((session) => ({ ...session, data: { theme: 'dark' } }));
    newRender();
    expect((await auth.readSession())?.data).toEqual({ theme: 'dark' });

    await auth.clearSession();
    expect(jar.size).toBe(0);
    expect(events.at(-1)).toMatchObject({ event: 'session.cleared', trigger: 'logout' });
  });

  it('keeps the session in a store when given one', async () => {
    const sessionStore = createMemorySessionStore();
    const { auth } = setup({ sessionStore });
    await login(auth);

    const handle = jar.get('__Host-session') ?? '';
    expect(handle).toMatch(/^[0-9a-f]{64}$/);
    newRender();
    expect((await auth.readSession())?.user?.name).toBe('Ada');

    await auth.handleOidcLogout(post('/api/auth/logout'));
    jar.set('__Host-session', handle);
    newRender();
    expect(await auth.tryReadSession()).toEqual({ session: null, reason: 'session_not_found' });
  });

  it('can be created where the redirect URI is not set yet, as in a build', () => {
    expect(() =>
      createFidesAuth({
        oauthConfig: { issuer: ISSUER, clientId: 'web', clientSecret: 'shh', scope: 'openid' },
        secret,
      }),
    ).not.toThrow();
  });

  it('exposes the cookie name and the OIDC client', () => {
    const { auth } = setup();
    expect(auth.cookieNames).toEqual({ session: '__Host-session' });
    expect(typeof auth.oidc.authorizationUrl).toBe('function');
  });
});

describe('authorizedFetch and refreshSession', () => {
  it('never refreshes in authorizedFetch: a 401 is an http_error', async () => {
    const { auth } = setup();
    await login(auth);

    newRender();
    await expect(auth.authorizedFetch(`${API}me`, { allowedBase: API })).rejects.toMatchObject({
      reason: 'http_error',
      status: 401,
      accessTokenExpired: false,
    });
    expect(provider.tokenRequests).toHaveLength(1);
  });

  it('refreshes first with ifExpiresWithin, and the call uses the new token', async () => {
    const { auth } = setup();
    provider.expiresIn = 30;
    await login(auth);

    newRender();
    expect(await auth.refreshSession({ ifExpiresWithin: 60 })).toMatchObject({ ok: true, refreshed: true });
    const result = await auth.authorizedFetch(`${API}me`, {
      allowedBase: API,
      parse: (response) => response.json() as Promise<{ ok: boolean }>,
    });
    expect(result.data).toEqual({ ok: true });
    expect(provider.apiCalls).toEqual(['Bearer access-2']);
  });

  it('leaves a fresh session alone with ifExpiresWithin', async () => {
    const { auth } = setup();
    await login(auth);

    newRender();
    expect(await auth.refreshSession({ ifExpiresWithin: 60 })).toMatchObject({ ok: true, refreshed: false });
    expect(provider.tokenRequests).toHaveLength(1);
  });
});

describe('refreshInProxy', () => {
  /** The cookies the proxy forwards to the page, from Next's override header. */
  function forwardedCookies(response: Response): string | null {
    return response.headers.get('x-middleware-request-cookie');
  }

  it('passes a request without a session cookie straight through', async () => {
    const { auth } = setup();
    const response = await auth.refreshInProxy(proxied());
    expect(response.headers.get('x-middleware-next')).toBe('1');
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(provider.tokenRequests).toHaveLength(0);
  });

  it('leaves a session alone while its access token is fresh', async () => {
    const { auth } = setup();
    await login(auth);
    const response = await auth.refreshInProxy(proxied());
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(provider.tokenRequests).toHaveLength(1);
  });

  it('refreshes a session about to expire, for the browser and for the page', async () => {
    const { auth } = setup();
    provider.expiresIn = 30;
    await login(auth);
    const before = jar.get('__Host-session');

    const response = await auth.refreshInProxy(proxied());
    expect(provider.tokenRequests.at(-1)?.get('grant_type')).toBe('refresh_token');

    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toMatch(/^__Host-session=/);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/Path=\//);
    expect(setCookie).toMatch(/SameSite=Lax/i);
    const refreshed = /^__Host-session=([^;]+)/.exec(setCookie)?.[1];
    expect(refreshed).toBeTruthy();
    expect(refreshed).not.toBe(before);

    // The page renders with the refreshed cookie, not the one the browser sent.
    expect(forwardedCookies(response)).toContain(`__Host-session=${refreshed}`);
    jar.set('__Host-session', refreshed ?? '');
    newRender();
    expect((await auth.getTokens())?.accessToken).toBe('access-2');
  });

  it('takes the refresh window as an option', async () => {
    const { auth } = setup();
    await login(auth);
    const response = await auth.refreshInProxy(proxied(), { ifExpiresWithin: 600 });
    expect(response.headers.get('set-cookie')).toMatch(/^__Host-session=/);
  });

  it('leaves the session as it is when the refresh fails', async () => {
    const { auth, events } = setup();
    provider.expiresIn = 30;
    await login(auth);
    provider.rejectNextRefresh();

    const response = await auth.refreshInProxy(proxied());
    expect(response.headers.get('x-middleware-next')).toBe('1');
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(events.at(-1)).toMatchObject({ event: 'session.refresh_failed', cause: 'invalid_grant' });
  });

  it('does nothing for a session without a refresh token', async () => {
    const { auth } = setup();
    await auth.createSession({ access_token: 'a', token_type: 'bearer', expires_in: 5, id_token: idToken() });
    const response = await auth.refreshInProxy(proxied());
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(provider.tokenRequests).toHaveLength(0);
  });
});
