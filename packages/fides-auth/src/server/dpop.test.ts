/**
 * DPoP end to end (RFC 9449): the handlers run the real openid-client against
 * a stubbed provider and a stubbed API, and both verify each proof the way a
 * real server would: its signature against the key in its header, its method,
 * its URL, and at the API the hash of the access token and the key the token
 * was bound to.
 */
import { calculateJwkThumbprint, EmbeddedJWK, jwtVerify } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLoggerFactory } from '../shared/logger.js';
import type { SessionEvent } from '../shared/session-events.js';
import { createDpopKey } from '../protocol/dpop.js';
import { AuthorizedFetchError } from './authorized-fetch.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type FidesAuth, type FidesAuthConfig, type LoginError } from './fides-auth.js';
import { createTransaction, persistTransaction } from './login-transaction.js';
import { createMemorySessionStore } from './session-store.js';

const APP = 'https://app.test';
const ISSUER = 'https://idp.test';
const API = 'https://api.test/v1/';
const secret = 'a'.repeat(64);

const quiet: FidesLoggerFactory = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

interface Provider {
  /** False for a provider without DPoP: it ignores the proof and answers with a bearer token. */
  dpop: boolean;
  /** The nonce the token endpoint insists on, when it does. */
  tokenNonce?: string;
  /** The nonce the API insists on, when it does. */
  apiNonce?: string;
  /** Requests to the token endpoint, by grant type. */
  grants: string[];
  /** The thumbprint each issued access token is bound to. */
  boundTo: Map<string, string>;
  /** What the API got: the Authorization scheme and whether the proof held. */
  apiCalls: Array<{ scheme: string; ok: boolean; why?: string }>;
  /** Every proof `jti` seen, to catch one sent twice. */
  jtis: Set<string>;
  /** The tokens the client asked to have revoked. */
  revoked: string[];
  /** The `dpop_jkt` of the authorization request, which the code is then bound to. */
  codeBoundTo?: string | null;
}

let provider: Provider;

/** Verifies a proof as a server does. Returns the key's thumbprint, or why it failed. */
async function checkProof(
  proof: string | null,
  expected: { htm: string; htu: string; accessToken?: string; nonce?: string },
): Promise<{ jkt: string } | { error: string }> {
  if (!proof) return { error: 'no proof' };
  try {
    const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: ['ES256'],
      maxTokenAge: 60,
    });
    if (payload.htm !== expected.htm) return { error: `htm ${String(payload.htm)}` };
    if (payload.htu !== expected.htu) return { error: `htu ${String(payload.htu)}` };
    if (typeof payload.jti !== 'string' || provider.jtis.has(payload.jti)) return { error: 'jti replayed' };
    provider.jtis.add(payload.jti);
    if (expected.nonce !== undefined && payload.nonce !== expected.nonce) return { error: 'use_dpop_nonce' };
    if (expected.accessToken !== undefined) {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expected.accessToken));
      if (payload.ath !== Buffer.from(digest).toString('base64url')) return { error: 'ath' };
    }
    if (!protectedHeader.jwk) return { error: 'no jwk' };
    return { jkt: await calculateJwkThumbprint(protectedHeader.jwk) };
  } catch (error) {
    return { error: (error as Error).message };
  }
}

let issued = 0;

async function tokenEndpoint(init?: RequestInit): Promise<Response> {
  const body = new URLSearchParams(String(init?.body ?? ''));
  const grant = body.get('grant_type') ?? '';
  provider.grants.push(grant);
  const proof = new Headers(init?.headers).get('dpop');
  issued += 1;
  const common = { expires_in: 300, refresh_token: `refresh-${issued}` };
  if (!provider.dpop) return Response.json({ ...common, access_token: `access-${issued}`, token_type: 'Bearer' });

  const checked = await checkProof(proof, { htm: 'POST', htu: `${ISSUER}/token`, nonce: provider.tokenNonce });
  if ('error' in checked) {
    const error = checked.error === 'use_dpop_nonce' ? 'use_dpop_nonce' : 'invalid_dpop_proof';
    return Response.json(
      { error, error_description: checked.error },
      { status: 400, headers: provider.tokenNonce ? { 'DPoP-Nonce': provider.tokenNonce } : {} },
    );
  }
  // A code that was bound with dpop_jkt is exchanged only with a proof from that key (RFC 9449 §10).
  if (grant === 'authorization_code' && provider.codeBoundTo && provider.codeBoundTo !== checked.jkt) {
    return Response.json({ error: 'invalid_grant' }, { status: 400 });
  }
  // A refresh must come with the key the tokens were bound to.
  const refreshToken = body.get('refresh_token');
  if (grant === 'refresh_token' && provider.boundTo.get(refreshToken ?? '') !== checked.jkt) {
    return Response.json({ error: 'invalid_grant' }, { status: 400 });
  }
  const accessToken = `access-${issued}`;
  provider.boundTo.set(accessToken, checked.jkt);
  provider.boundTo.set(common.refresh_token, checked.jkt);
  return Response.json({ ...common, access_token: accessToken, token_type: 'DPoP' });
}

async function api(url: URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  const [scheme = '', token = ''] = (headers.get('authorization') ?? '').split(' ');
  const refuse = (why: string, extra: Record<string, string> = {}) => {
    provider.apiCalls.push({ scheme, ok: false, why });
    return new Response(null, {
      status: 401,
      headers: { 'WWW-Authenticate': `DPoP error="${why}"`, ...extra },
    });
  };
  if (scheme !== 'DPoP') return refuse('invalid_token');
  const checked = await checkProof(headers.get('dpop'), {
    htm: (init?.method ?? 'GET').toUpperCase(),
    htu: `${url.origin}${url.pathname}`,
    accessToken: token,
    nonce: provider.apiNonce,
  });
  if ('error' in checked) {
    return checked.error === 'use_dpop_nonce'
      ? refuse('use_dpop_nonce', { 'DPoP-Nonce': provider.apiNonce ?? '' })
      : refuse('invalid_dpop_proof');
  }
  if (provider.boundTo.get(token) !== checked.jkt) return refuse('invalid_token');
  provider.apiCalls.push({ scheme, ok: true });
  return Response.json({ ok: true, echoed: typeof init?.body === 'string' ? init.body : null });
}

beforeEach(() => {
  issued = 0;
  provider = { dpop: true, grants: [], boundTo: new Map(), apiCalls: [], jtis: new Set(), revoked: [] };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.href === `${ISSUER}/token`) return tokenEndpoint(init);
      if (url.href === `${ISSUER}/revoke`) {
        provider.revoked.push(new URLSearchParams(String(init?.body ?? '')).get('token') ?? '');
        return new Response(null, { status: 200 });
      }
      if (url.href.startsWith(API)) return api(url, init);
      throw new Error(`Unexpected request to ${url.href}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function browser(): { cookies: CookieStore; jar: Map<string, string> } {
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

function setup(overrides: Partial<FidesAuthConfig> = {}, dpop = true) {
  const failures: LoginError[] = [];
  const events: SessionEvent[] = [];
  const auth = createFidesAuth({
    oauthConfig: {
      issuer: ISSUER,
      clientId: 'web',
      clientSecret: 'shh',
      redirectUri: `${APP}/api/auth/callback`,
      // Without `openid`: these tests are about the tokens, not the ID token's nonce.
      scope: 'api:read offline_access',
      dpop,
      serverMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        revocation_endpoint: `${ISSUER}/revoke`,
        dpop_signing_alg_values_supported: ['ES256'],
      },
    },
    secret,
    logger: quiet,
    onLoginError: (failure) => void failures.push(failure),
    onSessionEvent: (event) => void events.push(event),
    ...overrides,
  });
  return { auth, failures, events };
}

async function login(auth: FidesAuth, cookies: CookieStore): Promise<Response> {
  const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
  const authorize = new URL(started.headers.get('location') ?? '');
  const state = authorize.searchParams.get('state');
  // The provider reads dpop_jkt off the authorization request, as a real one does.
  provider.codeBoundTo = authorize.searchParams.get('dpop_jkt');
  return auth.handleOidcCallback(new Request(`${APP}/api/auth/callback?code=c&state=${state}`), cookies);
}

const json = (response: Response) => response.json() as Promise<{ ok: boolean; echoed: string | null }>;

describe.each([
  ['cookie sessions', () => ({})],
  ['stored sessions', () => ({ sessionStore: createMemorySessionStore() })],
])('DPoP with %s', (_, storage) => {
  it('binds the tokens of a login to a key of its own, kept with the session', async () => {
    const { auth, failures } = setup(storage());
    const { cookies, jar } = browser();

    const done = await login(auth, cookies);

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    const tokens = await auth.getTokens(cookies);
    expect(tokens?.tokenType).toBe('dpop');
    expect(tokens?.dpopKey).toMatchObject({ kty: 'EC', crv: 'P-256' });
    // The provider bound the token to that very key.
    const { x, y } = tokens?.dpopKey ?? { x: '', y: '' };
    expect(provider.boundTo.get(tokens?.accessToken ?? '')).toBe(
      await calculateJwkThumbprint({ kty: 'EC', crv: 'P-256', x, y }),
    );
    // The key is a secret: sealed, never in the clear in a cookie.
    expect([...jar.values()].join('\n')).not.toContain(tokens?.dpopKey?.d);
  });

  it('names the key in the authorization request, so the code can only be exchanged with it', async () => {
    const { auth } = setup(storage());
    const { cookies, jar } = browser();

    const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
    const authorize = new URL(started.headers.get('location') ?? '');
    const jkt = authorize.searchParams.get('dpop_jkt');
    expect(jkt).toMatch(/^[\w-]{43}$/);

    provider.codeBoundTo = jkt;
    const done = await auth.handleOidcCallback(
      new Request(`${APP}/api/auth/callback?code=c&state=${authorize.searchParams.get('state')}`),
      cookies,
    );

    // The provider took the proof for the key it was told of, and that key is the session's.
    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    const key = (await auth.getTokens(cookies))?.dpopKey;
    expect(await calculateJwkThumbprint({ kty: 'EC', crv: 'P-256', x: key?.x, y: key?.y })).toBe(jkt);
    // The transaction that carried the key is spent.
    expect([...jar.keys()]).toEqual(['__Host-session']);
  });

  it('gives each login a key of its own', async () => {
    const { auth } = setup(storage());
    const jktOf = async () => {
      const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), browser().cookies);
      return new URL(started.headers.get('location') ?? '').searchParams.get('dpop_jkt');
    };

    expect(await jktOf()).not.toBe(await jktOf());
  });

  it('fails the login when the code was bound to another key', async () => {
    const { auth, failures } = setup(storage());
    const { cookies } = browser();
    const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
    const state = new URL(started.headers.get('location') ?? '').searchParams.get('state');
    // A code from a login someone else started: bound to their key, not this browser's.
    provider.codeBoundTo = 'the-thumbprint-of-another-key';

    const done = await auth.handleOidcCallback(new Request(`${APP}/api/auth/callback?code=c&state=${state}`), cookies);

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('finishes a login that was started before the key was made at the redirect', async () => {
    const { auth, failures } = setup(storage());
    const { cookies } = browser();
    // A deploy between the redirect and the callback: the transaction has no key, and no dpop_jkt was sent.
    await persistTransaction(
      cookies,
      createTransaction({ state: 'from-before', codeVerifier: 'verifier-from-before' }, { logger: quiet.create({ namespace: 'test' }) }),
      secret,
    );

    const done = await auth.handleOidcCallback(new Request(`${APP}/api/auth/callback?code=c&state=from-before`), cookies);

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    expect((await auth.getTokens(cookies))?.tokenType).toBe('dpop');
  });

  it('calls the API with the token as DPoP and a proof for that request', async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    const { response, data } = await auth.authorizedFetch(cookies, `${API}orders?customer=ada`, {
      allowedBase: API,
      parse: json,
    });

    expect(response.status).toBe(200);
    expect(data.ok).toBe(true);
    expect(provider.apiCalls).toEqual([{ scheme: 'DPoP', ok: true }]);
  });

  it('proves each request anew, for its own method and body', async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    await auth.authorizedFetch(cookies, `${API}orders`, { allowedBase: API });
    const posted = await auth.authorizedFetch(cookies, `${API}orders`, {
      allowedBase: API,
      method: 'POST',
      body: '{"item":1}',
      parse: json,
    });

    expect(posted.data.echoed).toBe('{"item":1}');
    // The stub refuses a proof whose jti it has seen, or whose htm is wrong.
    expect(provider.apiCalls.every((call) => call.ok)).toBe(true);
    expect(provider.apiCalls).toHaveLength(2);
  });

  it('refreshes with a proof from the same key, and the new token is bound to it too', async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);
    const before = await auth.getTokens(cookies);

    const refreshed = await auth.refreshSession(cookies);

    expect(refreshed).toMatchObject({ ok: true, refreshed: true, rotatedRefreshToken: true });
    const after = await auth.getTokens(cookies);
    expect(after?.accessToken).not.toBe(before?.accessToken);
    expect(after?.tokenType).toBe('dpop');
    expect(after?.dpopKey).toEqual(before?.dpopKey);
    expect(provider.boundTo.get(after?.accessToken ?? '')).toBe(provider.boundTo.get(before?.accessToken ?? ''));
    // And the API takes the new one.
    await auth.authorizedFetch(cookies, `${API}orders`, { allowedBase: API });
    expect(provider.apiCalls.at(-1)).toEqual({ scheme: 'DPoP', ok: true });
  });

  it('answers the nonce the provider asks for, at login and at a refresh', async () => {
    provider.tokenNonce = 'idp-nonce-1';
    const { auth, failures } = setup(storage());
    const { cookies } = browser();

    const done = await login(auth, cookies);
    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    // Asked once without the nonce, and again with it.
    expect(provider.grants).toEqual(['authorization_code', 'authorization_code']);

    expect((await auth.refreshSession(cookies)).ok).toBe(true);
  });

  it('answers the nonce the API asks for, and remembers it for the next request', async () => {
    provider.apiNonce = 'api-nonce-1';
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    const first = await auth.authorizedFetch(cookies, `${API}orders`, { allowedBase: API, parse: json });
    expect(first.data.ok).toBe(true);
    expect(provider.apiCalls.map((call) => call.ok)).toEqual([false, true]);

    // The second request has the nonce from the start.
    await auth.authorizedFetch(cookies, `${API}orders`, { allowedBase: API });
    expect(provider.apiCalls.map((call) => call.ok)).toEqual([false, true, true]);
  });

  it('sends a body again with the nonce, when it can be read twice', async () => {
    provider.apiNonce = 'api-nonce-1';
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    const { data } = await auth.authorizedFetch(cookies, `${API}orders`, {
      allowedBase: API,
      method: 'POST',
      body: '{"item":1}',
      parse: json,
    });

    expect(data.echoed).toBe('{"item":1}');
  });

  it("doesn't send a streamed body twice: the API's 401 is the answer", async () => {
    provider.apiNonce = 'api-nonce-1';
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"item":1}'));
        controller.close();
      },
    });

    const error = await auth
      .authorizedFetch(cookies, `${API}orders`, {
        allowedBase: API,
        method: 'POST',
        body,
        duplex: 'half',
      } as never)
      .catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(AuthorizedFetchError);
    // The caller is told why, and can send it again itself with a new body.
    expect(error).toMatchObject({ reason: 'http_error', status: 401, bearerError: 'use_dpop_nonce' });
    expect(provider.apiCalls).toHaveLength(1);
  });

  it('fails the login when the provider answers with a bearer token', async () => {
    provider.dpop = false;
    const { auth, failures } = setup(storage());
    const { cookies, jar } = browser();

    const done = await login(auth, cookies);

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(String((failures[0]?.cause as Error | undefined)?.message)).toContain('DPoP-bound');
    expect(await auth.readSession(cookies)).toBeNull();
    expect(jar.has('__Host-session')).toBe(false);
    // The bearer tokens the login was answered with are revoked, not left behind.
    expect(provider.revoked).toEqual(['refresh-1']);
  });

  it.each<[string, () => BodyInit]>([
    ['URLSearchParams', () => new URLSearchParams({ item: '1' })],
    ['bytes', () => new TextEncoder().encode('{"item":1}')],
    ['a Blob', () => new Blob(['{"item":1}'])],
  ])('sends %s again with the nonce', async (_, body) => {
    provider.apiNonce = 'api-nonce-1';
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    const { response } = await auth.authorizedFetch(cookies, `${API}orders`, {
      allowedBase: API,
      method: 'POST',
      body: body(),
    });

    expect(response.status).toBe(200);
    expect(provider.apiCalls.map((call) => call.ok)).toEqual([false, true]);
  });

  it("doesn't send a body it reads as it goes twice: it would go out empty the second time", async () => {
    provider.apiNonce = 'api-nonce-1';
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);
    async function* chunks() {
      yield new TextEncoder().encode('{"item":1}');
    }

    const error = await auth
      .authorizedFetch(cookies, `${API}orders`, {
        allowedBase: API,
        method: 'POST',
        body: chunks(),
        duplex: 'half',
      } as never)
      .catch((thrown: unknown) => thrown);

    expect(error).toMatchObject({ reason: 'http_error', status: 401 });
    expect(provider.apiCalls).toHaveLength(1);
  });

  it("reads the error of the API's DPoP challenge, so the caller can tell an expired token", async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);
    // The API no longer knows the token: revoked, or expired by its clock.
    provider.boundTo.clear();

    const error = await auth
      .authorizedFetch(cookies, `${API}orders`, { allowedBase: API })
      .catch((thrown: unknown) => thrown);

    expect(error).toMatchObject({ reason: 'http_error', status: 401, bearerError: 'invalid_token' });
  });

  it('sends the method as the proof names it', async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    await auth.authorizedFetch(cookies, `${API}orders/1`, { allowedBase: API, method: 'patch', body: '{}' });

    const [, init] = vi.mocked(fetch).mock.calls.at(-1) ?? [];
    expect(init?.method).toBe('PATCH');
    expect(provider.apiCalls.at(-1)).toEqual({ scheme: 'DPoP', ok: true });
  });

  it('refuses a refresh that comes back as a bearer token, and revokes what it was given', async () => {
    const { auth, events } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);
    const before = await auth.getTokens(cookies);

    provider.dpop = false;
    const refreshed = await auth.refreshSession(cookies);

    // Not invalid_grant: the session isn't ended on the provider's word that it downgraded.
    expect(refreshed).toMatchObject({ ok: false, reason: 'refresh_failed', cause: 'idp_error' });
    // The unbound tokens are not kept: the session holds what it held.
    expect(await auth.getTokens(cookies)).toEqual(before);
    expect(events.some((event) => event.event === 'session.cleared')).toBe(false);
    // And not left good with nobody holding them: the refresh token just issued is revoked.
    expect(provider.revoked).toEqual(['refresh-2']);
  });

  it('never shows the key or the token type in the session or the session info', async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);
    const key = (await auth.getTokens(cookies))?.dpopKey;

    const session = await auth.readSession(cookies);
    const info = await (await auth.handleSessionInfo(new Request(`${APP}/api/auth/session`), cookies)).text();

    expect(JSON.stringify(session)).not.toContain(key?.d);
    expect(info).not.toContain(key?.d);
    expect(info).not.toContain('dpopKey');
  });

  it('logs out as before: the refresh token is revoked and the session is gone', async () => {
    const { auth } = setup(storage());
    const { cookies } = browser();
    await login(auth, cookies);

    await auth.clearSession(cookies);

    expect(await auth.readSession(cookies)).toBeNull();
    expect(vi.mocked(fetch).mock.calls.some(([input]) => String(input) === `${ISSUER}/revoke`)).toBe(true);
  });
});

describe('without DPoP', () => {
  it('logs in and calls the API with a bearer token, as before', async () => {
    provider.dpop = false;
    const { auth } = setup({}, false);
    const { cookies } = browser();

    const done = await login(auth, cookies);
    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);

    const tokens = await auth.getTokens(cookies);
    // A bearer session has no type and no key: the record is what it was before DPoP.
    expect(tokens && 'tokenType' in tokens).toBe(false);
    expect(tokens && 'dpopKey' in tokens).toBe(false);

    await auth.authorizedFetch(cookies, `${API}orders`, { allowedBase: API }).catch(() => undefined);
    const [, init] = vi.mocked(fetch).mock.calls.at(-1) ?? [];
    const headers = new Headers(init?.headers);
    expect(headers.get('authorization')).toBe(`Bearer ${tokens?.accessToken}`);
    expect(headers.has('dpop')).toBe(false);
    // No dpop_jkt in the authorization request, and no proof at the token endpoint either.
    expect(provider.codeBoundTo).toBeNull();
    const tokenCall = vi.mocked(fetch).mock.calls.find(([input]) => String(input) === `${ISSUER}/token`);
    expect(new Headers(tokenCall?.[1]?.headers).has('dpop')).toBe(false);
  });

  it('keeps using the key of a session that was bound, after dpop is turned off', async () => {
    const store = createMemorySessionStore();
    const bound = setup({ sessionStore: store });
    const { cookies } = browser();
    await login(bound.auth, cookies);

    // The same app, redeployed with dpop off: the session's tokens are still bound.
    const unbound = setup({ sessionStore: store }, false);
    expect((await unbound.auth.refreshSession(cookies)).ok).toBe(true);
    await unbound.auth.authorizedFetch(cookies, `${API}orders`, { allowedBase: API });

    expect(provider.apiCalls.at(-1)).toEqual({ scheme: 'DPoP', ok: true });
  });
});

describe('tokens this version cannot present', () => {
  /** A session whose tokens have `tokenType`, started outside the handlers. */
  async function sessionOfType(tokenType: string, withKey: boolean) {
    const { auth, events } = setup({ sessionStore: createMemorySessionStore() }, false);
    const { cookies } = browser();
    await auth.createSession(
      cookies,
      { access_token: 'access-x', token_type: tokenType as Lowercase<string>, expires_in: 300, refresh_token: 'refresh-x' },
      withKey ? { dpopKey: await createDpopKey() } : undefined,
    );
    vi.mocked(fetch).mockClear();
    return { auth, cookies, events };
  }

  it.each([
    ['a type from a later version', 'future-pop', false],
    ['a DPoP-bound token without its key', 'dpop', false],
  ])('never sends %s as a bearer token', async (_, type, withKey) => {
    const { auth, cookies } = await sessionOfType(type, withKey);

    const error = await auth
      .authorizedFetch(cookies, `${API}orders`, { allowedBase: API })
      .catch((thrown: unknown) => thrown);

    expect(error).toMatchObject({ reason: 'unsupported_token_type' });
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it.each([
    ['a type from a later version', 'future-pop', false],
    ['a DPoP-bound token without its key', 'dpop', false],
  ])("doesn't refresh %s, and leaves the session as it is", async (_, type, withKey) => {
    const { auth, cookies, events } = await sessionOfType(type, withKey);

    const refreshed = await auth.refreshSession(cookies);

    expect(refreshed).toMatchObject({ ok: false, reason: 'unsupported_token_type' });
    // Nothing went to the provider, which could have ended the session there.
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
    expect(await auth.readSession(cookies)).not.toBeNull();
    expect(events.some((event) => event.event === 'session.cleared')).toBe(false);
  });

  it.each<[string, Record<string, unknown>]>([
    ['an empty object', {}],
    ['a public key only', { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }],
    ['a key that does not sign', { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'd' }],
  ])('treats a DPoP session whose key is %s as one it cannot use, not as a failure to retry', async (_, key) => {
    const store = createMemorySessionStore();
    const { auth } = setup({ sessionStore: store }, false);
    const { cookies } = browser();
    await auth.createSession(
      cookies,
      { access_token: 'access-x', token_type: 'dpop', expires_in: 300, refresh_token: 'refresh-x' },
      // Past the type on purpose: a record written with a key that is no key.
      { dpopKey: key as never },
    );
    vi.mocked(fetch).mockClear();

    const error = await auth
      .authorizedFetch(cookies, `${API}orders`, { allowedBase: API })
      .catch((thrown: unknown) => thrown);
    expect(error).toMatchObject({ reason: 'unsupported_token_type' });

    const refreshed = await auth.refreshSession(cookies);
    // A key with the right shape and the wrong numbers is found out when it is used.
    expect(refreshed.ok).toBe(false);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it.each(['bearer', 'Bearer', undefined])(
    'refuses a dpopKey with tokens of type %s, rather than keep bound tokens as bearer ones',
    async (type) => {
      const { auth } = setup({ sessionStore: createMemorySessionStore() }, false);
      const { cookies, jar } = browser();

      await expect(
        auth.createSession(
          cookies,
          { access_token: 'access-x', token_type: type as never, expires_in: 300 },
          { dpopKey: await createDpopKey() },
        ),
      ).rejects.toThrow('not DPoP-bound');
      expect(jar.size).toBe(0);
    },
  );

  it('answers the heartbeat with 503, so the browser keeps the session', async () => {
    const { auth, cookies } = await sessionOfType('future-pop', false);

    const response = await auth.handleHeartbeat(
      new Request(`${APP}/api/auth/heartbeat`, { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } }),
      cookies,
    );

    expect(response.status).toBe(503);
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it('reads the token type whatever its case', async () => {
    const { auth, cookies } = await sessionOfType('DPoP', true);

    expect((await auth.getTokens(cookies))?.tokenType).toBe('dpop');
  });
});
