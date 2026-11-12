// @vitest-environment node
/**
 * createFidesAuth with a session store. The core handlers and helpers are real;
 * the cookie jar, the session store and the provider's token endpoint are in memory.
 */
import { vi, describe, it, expect, beforeEach, onTestFinished } from 'vitest';

// The browser's cookies. Like Next, cookies() returns one object per request.
const { jar, currentRequest } = vi.hoisted(() => {
  const jar = new Map<string, string>();
  const newRequestCookies = () => ({
    get: (name: string) => (jar.has(name) ? { value: jar.get(name) } : undefined),
    set: (name: string, value: string, options?: { maxAge?: number }) => {
      if (options?.maxAge === 0) jar.delete(name);
      else jar.set(name, value);
    },
    delete: (name: string) => { jar.delete(name); },
  });
  return { jar, currentRequest: { cookies: newRequestCookies(), newRequestCookies } };
});

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => currentRequest.cookies),
  headers: vi.fn(async () => new Headers()),
}));

// getCurrentSession is wrapped in React's cache(); make it a pass-through.
vi.mock('react', () => ({ cache: (fn: unknown) => fn }));

import { createFidesAuth, type FidesAuth } from './auth.js';
import { createMemorySessionStore, type SessionStore } from '@eventuras/fides-auth/server';
import { sha256 } from '@eventuras/fides-auth/utils';

const secret = 'a'.repeat(64);
const issuer = 'https://id.example.test';
const oauthConfig = {
  issuer,
  clientId: 'web',
  clientSecret: 'shh',
  redirect_uri: 'https://app.test/api/auth/callback/oidc',
  scope: 'openid offline_access',
  // No discovery request: the token endpoint is the only provider call.
  serverMetadata: {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    end_session_endpoint: `${issuer}/logout`,
  },
};
const api = { allowedBase: 'https://api.test/v1/' };

/** Unsigned: the code exchange checks the ID token's claims, not its signature. */
const idToken = (() => {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, aud: 'web', sub: 'user-1', iat: now, exp: now + 3600 };
  return `${enc({ alg: 'RS256', typ: 'JWT' })}.${enc({ ...claims, email: 'ada@example.test' })}.c2ln`;
})();

/**
 * The token endpoint and an API, behind `fetch`. Token request n answers `at-<n>`
 * and `rt-<n>`. The API takes every access token but the login's, which has expired.
 */
function stubNetwork() {
  const tokenRequests: URLSearchParams[] = [];
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (String(input) === `${issuer}/token`) {
      tokenRequests.push(new URLSearchParams(String(init?.body)));
      const n = tokenRequests.length;
      return Response.json({
        access_token: `at-${n}`,
        refresh_token: `rt-${n}`,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken,
      });
    }
    const authorization = new Headers(init?.headers).get('Authorization');
    return authorization && authorization !== 'Bearer at-1'
      ? new Response('{}', { status: 200 })
      : new Response(null, { status: 401 });
  });
  onTestFinished(() => fetchSpy.mockRestore());
  return {
    tokenRequests,
    refreshRequests: () => tokenRequests.filter((body) => body.get('grant_type') === 'refresh_token'),
  };
}

const nextRequest = () => {
  currentRequest.cookies = currentRequest.newRequestCookies();
};

/** Login and callback against the stubbed provider. Returns the callback's response. */
async function logIn(auth: FidesAuth, returnTo = '/'): Promise<Response> {
  const login = await auth.handleOidcLogin(
    new Request(`https://app.test/api/auth/login?returnTo=${returnTo}`),
  );
  const state = new URL(login.headers.get('Location')!).searchParams.get('state');

  nextRequest();
  const callback = await auth.handleOidcCallback(
    new Request(`https://app.test/api/auth/callback/oidc?code=abc&state=${state}`),
    { applicationUrl: 'https://app.test' },
  );
  nextRequest();
  return callback;
}

const post = (path: string) => new Request(`https://app.test${path}`, { method: 'POST' });

/** The record the handle cookie points at. */
const storedRecord = async (store: SessionStore, handle = jar.get('session_ref')) =>
  store.get(await sha256(handle ?? ''));

beforeEach(() => {
  jar.clear();
  nextRequest();
});

describe.each([
  { storage: 'cookies', withStore: false, sessionCookies: ['session', 'session_at', 'session_it'] },
  { storage: 'a session store', withStore: true, sessionCookies: ['session_ref'] },
])('createFidesAuth — the full flow with $storage', ({ withStore, sessionCookies }) => {
  it('logs in, reads, refreshes and logs out', async () => {
    const sessionStore = withStore ? createMemorySessionStore() : undefined;
    const auth = createFidesAuth({ secret, oauthConfig, sessionStore });
    const { tokenRequests } = stubNetwork();

    const callback = await logIn(auth, '/dashboard');
    expect(callback.headers.get('Location')).toBe('https://app.test/dashboard?login=success');
    expect(tokenRequests[0]?.get('grant_type')).toBe('authorization_code');
    // The login transaction is spent; only the session is left.
    expect([...jar.keys()].sort()).toEqual(sessionCookies);

    const session = await auth.getCurrentSession();
    expect(session?.tokens).toMatchObject({ accessToken: 'at-1', refreshToken: 'rt-1', idToken });
    expect(session?.user?.email).toBe('ada@example.test');

    nextRequest();
    const refreshed = await auth.tryRefreshCurrentSession();
    expect(refreshed).toMatchObject({ ok: true, rotatedRefreshToken: true });
    expect(tokenRequests[1]?.get('refresh_token')).toBe('rt-1');

    nextRequest();
    expect((await auth.getCurrentSession())?.tokens?.accessToken).toBe('at-2');
    expect((await auth.refreshCurrentSession())?.tokens?.accessToken).toBe('at-3');

    nextRequest();
    const heartbeat = await auth.handleHeartbeat(post('/api/auth/heartbeat'));
    expect(heartbeat.status).toBe(200);
    expect(tokenRequests[3]?.get('refresh_token')).toBe('rt-3');
    expect((await auth.getCurrentSession())?.tokens?.accessToken).toBe('at-4');
    expect([...jar.keys()].sort()).toEqual(sessionCookies);

    nextRequest();
    const logout = await auth.handleOidcLogout(post('/api/auth/logout'), {
      postLogoutRedirectUri: 'https://app.test/',
    });
    const endSession = new URL(logout.headers.get('Location')!);
    expect(endSession.origin + endSession.pathname).toBe(`${issuer}/logout`);
    expect(endSession.searchParams.get('id_token_hint')).toBe(idToken);
    expect(jar.size).toBe(0);

    nextRequest();
    expect(await auth.tryGetCurrentSession()).toEqual({
      session: null,
      reason: 'no_session_cookie',
    });
  });
});

describe('createFidesAuth — sessionStore', () => {
  let sessionStore: SessionStore;
  let auth: FidesAuth;

  beforeEach(() => {
    sessionStore = createMemorySessionStore();
    auth = createFidesAuth({ secret, oauthConfig, sessionStore });
  });

  it('keeps only the handle in the cookie', async () => {
    stubNetwork();
    await logIn(auth);

    expect([...jar.keys()]).toEqual(['session_ref']);
    expect(jar.get('session_ref')).toMatch(/^[0-9a-f]{64}$/);
    // The session is in the store, encrypted, under the handle's hash.
    const record = await storedRecord(sessionStore);
    expect(record?.data).toEqual(expect.any(String));
    expect(record?.data).not.toContain('at-1');
  });

  it('keeps the handle across a refresh', async () => {
    stubNetwork();
    await logIn(auth);
    const handle = jar.get('session_ref');
    const before = await storedRecord(sessionStore);

    await auth.tryRefreshCurrentSession();

    expect(jar.get('session_ref')).toBe(handle);
    const after = await storedRecord(sessionStore);
    expect(after?.data).not.toBe(before?.data);
    expect(after?.expiresAt).toBe(before?.expiresAt);
  });

  it('deletes the record on logout, so a copied cookie is dead', async () => {
    stubNetwork();
    await logIn(auth);
    const handle = jar.get('session_ref')!;
    expect(await storedRecord(sessionStore, handle)).toBeTruthy();

    await auth.handleOidcLogout(post('/api/auth/logout'), {
      postLogoutRedirectUri: 'https://app.test/',
    });

    expect(await storedRecord(sessionStore, handle)).toBeNull();
    expect(jar.has('session_ref')).toBe(false);

    nextRequest();
    jar.set('session_ref', handle);
    expect(await auth.tryGetCurrentSession()).toEqual({
      session: null,
      reason: 'session_not_found',
    });
  });

  it('persists and clears through the store', async () => {
    const handle = await auth.createAndPersistSession({
      tokens: { accessToken: 'at-0', refreshToken: 'rt-0' },
      user: { name: 'Ada', email: 'ada@example.test' },
    });

    expect(jar.get('session_ref')).toBe(handle);
    expect([...jar.keys()]).toEqual(['session_ref']);
    expect((await auth.getCurrentSession())?.tokens?.accessToken).toBe('at-0');

    await auth.clearCurrentSession();

    expect(await storedRecord(sessionStore, handle)).toBeNull();
    expect(jar.size).toBe(0);
  });

  it('takes an unset secret at creation and rejects it on first use', async () => {
    const unset = createFidesAuth({ secret: undefined as never, oauthConfig, sessionStore });

    await expect(unset.tryGetCurrentSession()).rejects.toThrow('missing or empty');
    await expect(
      unset.createAndPersistSession({ tokens: { accessToken: 'a' } }),
    ).rejects.toThrow('missing or empty');
  });

  describe('authorizedFetch — one refresh', () => {
    it('shares one refresh between parallel 401s', async () => {
      const { refreshRequests } = stubNetwork();
      await logIn(auth);
      const stale = (await auth.getCurrentSession())!;

      const results = await Promise.all(
        ['a', 'b', 'c'].map((path) => auth.authorizedFetch(stale, path, api)),
      );

      expect(refreshRequests()).toHaveLength(1);
      expect(refreshRequests()[0]?.get('refresh_token')).toBe('rt-1');
      for (const result of results) {
        expect(result.refreshed).toBe(true);
        expect(result.session.tokens?.accessToken).toBe('at-2');
      }
      // The refresh is in the store for the next request.
      nextRequest();
      expect((await auth.getCurrentSession())?.tokens?.accessToken).toBe('at-2');
    });

    it('reuses that refresh for a later 401 in the same request', async () => {
      const { refreshRequests } = stubNetwork();
      await logIn(auth);
      const stale = (await auth.getCurrentSession())!;

      await auth.authorizedFetch(stale, 'a', api);
      const later = await auth.authorizedFetch(stale, 'b', api);

      expect(refreshRequests()).toHaveLength(1);
      expect(later.session.tokens?.accessToken).toBe('at-2');
    });

    it('refreshes again in the next request', async () => {
      const { refreshRequests } = stubNetwork();
      await logIn(auth);
      const stale = (await auth.getCurrentSession())!;

      await auth.authorizedFetch(stale, 'a', api);
      nextRequest();
      const next = await auth.authorizedFetch(stale, 'a', api);

      expect(refreshRequests().map((body) => body.get('refresh_token'))).toEqual(['rt-1', 'rt-2']);
      expect(next.session.tokens?.accessToken).toBe('at-3');
    });
  });

  // Without a lock in the store, only the instance's one persistence can join them.
  it.each([
    { store: 'a store with a lock', lock: true },
    { store: 'a store without a lock', lock: false },
  ])('shares one refresh between parallel calls, with $store', async ({ lock }) => {
    const memory = createMemorySessionStore();
    const store: SessionStore = lock ? memory : { ...memory, withLock: undefined };
    const shared = createFidesAuth({ secret, oauthConfig, sessionStore: store });
    const { refreshRequests } = stubNetwork();
    await logIn(shared);

    const results = await Promise.all([
      shared.tryRefreshCurrentSession(),
      shared.tryRefreshCurrentSession(),
      shared.handleHeartbeat(post('/api/auth/heartbeat')),
    ]);

    expect(refreshRequests()).toHaveLength(1);
    expect(results[0]).toMatchObject({ ok: true, session: { tokens: { accessToken: 'at-2' } } });
    expect(results[1]).toEqual(results[0]);
    expect(results[2].status).toBe(200);
  });
});
