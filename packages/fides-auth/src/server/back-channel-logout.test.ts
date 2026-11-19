/**
 * handleBackChannelLogout end to end: sessions live in a store, a provider
 * with real keys signs logout tokens, and the handler verifies them with the
 * real OIDC client against a JWKS that a stubbed fetch serves.
 */
import { exportJWK, generateKeyPair, type JWK, SignJWT, UnsecuredJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLoggerFactory } from '../shared/logger.js';
import type { SessionEvent } from '../shared/session-events.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type FidesAuthConfig } from './fides-auth.js';
import { createMemorySessionStore, type SessionStore } from './session-store.js';

const APP = 'https://app.test';
const ISSUER = 'https://idp.test';
const CLIENT_ID = 'web';
const EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const secret = 'a'.repeat(64);

let key: CryptoKey;
let foreignKey: CryptoKey;
let jwk: JWK;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  key = pair.privateKey;
  foreignKey = (await generateKeyPair('RS256')).privateKey;
  jwk = { ...(await exportJWK(pair.publicKey)), kid: 'key-1', alg: 'RS256', use: 'sig' };
});

/** The refresh tokens the provider was asked to revoke. */
let revoked: string[];
/** When false, the provider's keys can't be fetched. */
let jwksUp: boolean;

beforeEach(() => {
  revoked = [];
  jwksUp = true;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `${ISSUER}/jwks`) {
        return jwksUp ? Response.json({ keys: [jwk] }) : new Response('down', { status: 503 });
      }
      if (url === `${ISSUER}/revoke`) {
        revoked.push(new URLSearchParams(String(init?.body ?? '')).get('token') ?? '');
        return new Response(null, { status: 200 });
      }
      throw new Error(`Unexpected request to ${url}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const logged: Array<{ level: string; args: unknown[] }> = [];
const loggers: FidesLoggerFactory = {
  create: () => ({
    debug: (...args: unknown[]) => void logged.push({ level: 'debug', args }),
    info: (...args: unknown[]) => void logged.push({ level: 'info', args }),
    warn: (...args: unknown[]) => void logged.push({ level: 'warn', args }),
    error: (...args: unknown[]) => void logged.push({ level: 'error', args }),
  }),
};

function setup(overrides: Partial<FidesAuthConfig> = {}) {
  logged.length = 0;
  const store = createMemorySessionStore();
  const events: SessionEvent[] = [];
  const auth = createFidesAuth({
    oauthConfig: {
      issuer: ISSUER,
      clientId: CLIENT_ID,
      clientSecret: 'shh',
      redirectUri: `${APP}/api/auth/callback`,
      scope: 'openid offline_access',
      serverMetadata: {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        revocation_endpoint: `${ISSUER}/revoke`,
      },
    },
    secret,
    sessionStore: store,
    logger: loggers,
    onSessionEvent: (event) => void events.push(event),
    ...overrides,
  });
  return { auth, store, events };
}

function browser(): CookieStore {
  const jar = new Map<string, string>();
  return {
    get: (name) => jar.get(name) ?? null,
    set: (name, value, options) => {
      if (options?.maxAge === 0) jar.delete(name);
      else jar.set(name, value);
    },
  };
}

/** Signs a browser in as `sub`, in the provider's session `sid`, and returns its cookies. */
async function signIn(
  auth: ReturnType<typeof setup>['auth'],
  sub: string,
  sid: string | undefined,
  iss = ISSUER,
): Promise<CookieStore> {
  const cookies = browser();
  await auth.createSession(cookies, {
    access_token: `access-${sub}-${sid}`,
    token_type: 'bearer',
    expires_in: 300,
    refresh_token: `refresh-${sub}-${sid}`,
    // Decoded, not verified: as it comes from the code exchange.
    id_token: new UnsecuredJWT({ iss, sub, ...(sid ? { sid } : {}) }).encode(),
  });
  return cookies;
}

interface TokenOptions {
  claims?: Record<string, unknown>;
  iss?: string;
  aud?: string;
  key?: CryptoKey;
  exp?: string | number;
}

function logoutToken({ claims = {}, iss = ISSUER, aud = CLIENT_ID, key: signingKey, exp = '2m' }: TokenOptions = {}): Promise<string> {
  const payload: Record<string, unknown> = { jti: crypto.randomUUID(), events: { [EVENT]: {} }, ...claims };
  for (const name of Object.keys(payload)) if (payload[name] === undefined) delete payload[name];
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'key-1', typ: 'logout+jwt' })
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(signingKey ?? key);
}

/** The provider's request, as the spec has it: a form post with the token. */
function posted(token: string, init: { headers?: Record<string, string>; body?: string } = {}): Request {
  return new Request(`${APP}/api/auth/backchannel-logout`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...init.headers },
    body: init.body ?? new URLSearchParams({ logout_token: token }).toString(),
  });
}

describe('handleBackChannelLogout', () => {
  it("ends the session the token names by sid, and leaves the user's others", async () => {
    const { auth, events } = setup();
    const laptop = await signIn(auth, 'ada', 'idp-1');
    const phone = await signIn(auth, 'ada', 'idp-2');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada', sid: 'idp-1' } })));

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(await auth.readSession(laptop)).toBeNull();
    expect((await auth.readSession(phone))?.idp?.sid).toBe('idp-2');
    // The ended session's refresh token is revoked; the other's isn't.
    expect(revoked).toEqual(['refresh-ada-idp-1']);
    expect(events.filter((event) => event.event === 'session.cleared')).toEqual([
      expect.objectContaining({ trigger: 'back_channel_logout' }),
    ]);
  });

  it('ends a session named by sid alone', async () => {
    const { auth } = setup();
    const laptop = await signIn(auth, 'ada', 'idp-1');
    const other = await signIn(auth, 'grace', 'idp-9');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sid: 'idp-1' } })));

    expect(response.status).toBe(200);
    expect(await auth.readSession(laptop)).toBeNull();
    expect(await auth.readSession(other)).not.toBeNull();
  });

  it("ends every session of the user when the token has only a sub, and nobody else's", async () => {
    const { auth } = setup();
    const laptop = await signIn(auth, 'ada', 'idp-1');
    const phone = await signIn(auth, 'ada', 'idp-2');
    const withoutSid = await signIn(auth, 'ada', undefined);
    const other = await signIn(auth, 'grace', 'idp-9');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } })));

    expect(response.status).toBe(200);
    for (const cookies of [laptop, phone, withoutSid]) expect(await auth.readSession(cookies)).toBeNull();
    expect((await auth.readSession(other))?.user?.sub).toBe('grace');
    expect([...revoked].sort()).toEqual(['refresh-ada-idp-1', 'refresh-ada-idp-2', 'refresh-ada-undefined']);
  });

  it("doesn't end a session whose sid matches for another sub", async () => {
    const { auth } = setup();
    const grace = await signIn(auth, 'grace', 'idp-1');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada', sid: 'idp-1' } })));

    // Nothing to end is not a failure.
    expect(response.status).toBe(200);
    expect(await auth.readSession(grace)).not.toBeNull();
    expect(revoked).toEqual([]);
  });

  it('answers 200 when the user has no session here', async () => {
    const { auth, events } = setup();

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'nobody' } })));

    expect(response.status).toBe(200);
    expect(events).toEqual([]);
  });

  it('ends the session for a browser that is in the middle of using it', async () => {
    const { auth } = setup();
    const cookies = await signIn(auth, 'ada', 'idp-1');
    expect((await auth.tryReadSession(cookies)).session).not.toBeNull();

    await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sid: 'idp-1' } })));

    expect(await auth.tryReadSession(cookies)).toEqual({ session: null, reason: 'session_not_found' });
    expect(await auth.getTokens(cookies)).toBeNull();
    expect((await auth.refreshSession(cookies)).ok).toBe(false);
  });

  it.each<[string, TokenOptions]>([
    ['signed by a key the provider does not have', { key: undefined }],
    ['for another client', { aud: 'another-client' }],
    ['from another issuer', { iss: 'https://evil.test' }],
    ['that has expired', { exp: Math.floor(Date.now() / 1000) - 60 }],
    ['without the logout event', { claims: { events: undefined } }],
    ['with a nonce', { claims: { nonce: 'n' } }],
    ['without a jti', { claims: { jti: undefined } }],
    ['that names nobody', { claims: { sub: undefined } }],
  ])('refuses a token %s, and ends nothing', async (name, options) => {
    const { auth, events } = setup();
    const cookies = await signIn(auth, 'ada', 'idp-1');
    const token = await logoutToken({
      ...options,
      claims: { sub: 'ada', ...options.claims },
      key: name.startsWith('signed by') ? foreignKey : undefined,
    });

    const response = await auth.handleBackChannelLogout(posted(token));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_request' });
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(await auth.readSession(cookies)).not.toBeNull();
    expect(revoked).toEqual([]);
    expect(events.some((event) => event.event === 'session.cleared')).toBe(false);
    // Why is in the log, and the token isn't.
    expect(logged.some(({ level }) => level === 'warn')).toBe(true);
    expect(JSON.stringify(logged)).not.toContain(token);
  });

  it("refuses the user's own ID token, sent as a logout token", async () => {
    const { auth } = setup();
    const cookies = await signIn(auth, 'ada', 'idp-1');
    const idToken = await logoutToken({ claims: { sub: 'ada', sid: 'idp-1', events: undefined, nonce: 'n-1' } });

    const response = await auth.handleBackChannelLogout(posted(idToken));

    expect(response.status).toBe(400);
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it.each<[string, () => Request]>([
    ['no logout_token in the form', () => posted('', { body: 'other=1' })],
    ['an empty body', () => posted('', { body: '' })],
    ['a JSON body', () => posted('', { headers: { 'content-type': 'application/json' }, body: '{"logout_token":"x"}' })],
    ['the token in the query', () => new Request(`${APP}/api/auth/backchannel-logout?logout_token=x`, { method: 'POST' })],
    ['a body far too large to be a token', () => posted('', { body: `logout_token=${'a'.repeat(64 * 1024)}` })],
  ])('refuses a request with %s', async (_, request) => {
    const { auth } = setup();

    const response = await auth.handleBackChannelLogout(request());

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_request' });
  });

  it('reads a form body with a charset', async () => {
    const { auth } = setup();
    const cookies = await signIn(auth, 'ada', 'idp-1');
    const token = await logoutToken({ claims: { sub: 'ada' } });

    const response = await auth.handleBackChannelLogout(
      posted(token, { headers: { 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8' } }),
    );

    expect(response.status).toBe(200);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('needs no cookie and no origin: the provider is not a browser', async () => {
    const { auth } = setup({ strictOriginCheck: true });
    const cookies = await signIn(auth, 'ada', 'idp-1');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } })));

    expect(response.status).toBe(200);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('answers 405 to anything but a POST', async () => {
    const { auth } = setup();

    const response = await auth.handleBackChannelLogout(new Request(`${APP}/api/auth/backchannel-logout`));

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('POST');
  });

  it('answers 429 when rateLimit refuses, before the token is looked at', async () => {
    const { auth } = setup({ rateLimit: () => false });
    const cookies = await signIn(auth, 'ada', 'idp-1');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } })));

    expect(response.status).toBe(429);
    expect(await auth.readSession(cookies)).not.toBeNull();
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("answers 400, not 200, when the provider's keys can't be read", async () => {
    const { auth } = setup();
    const cookies = await signIn(auth, 'ada', 'idp-1');
    jwksUp = false;

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } })));

    expect(response.status).toBe(400);
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it('answers 400 when the store fails, so the provider may try again', async () => {
    const memory = createMemorySessionStore();
    let down = false;
    const store: SessionStore = {
      ...memory,
      findMatching: (match) => {
        if (down) throw new Error('store is down');
        return memory.findMatching?.(match) ?? [];
      },
    };
    const { auth } = setup({ sessionStore: store });
    const cookies = await signIn(auth, 'ada', 'idp-1');
    const token = await logoutToken({ claims: { sub: 'ada' } });

    down = true;
    const failed = await auth.handleBackChannelLogout(posted(token));
    expect(failed.status).toBe(400);
    expect(await failed.json()).toEqual({ error: 'server_error' });
    expect(await auth.readSession(cookies)).not.toBeNull();

    // The same token, sent again while it is valid.
    down = false;
    const retried = await auth.handleBackChannelLogout(posted(token));
    expect(retried.status).toBe(200);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('still answers 200 when the refresh token cannot be revoked', async () => {
    const { auth } = setup();
    const cookies = await signIn(auth, 'ada', 'idp-1');
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `${ISSUER}/jwks`) return Response.json({ keys: [jwk] });
      throw new TypeError('fetch failed');
    });

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } })));

    expect(response.status).toBe(200);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it("doesn't end a session from another issuer with the same sub", async () => {
    const { auth } = setup();
    const elsewhere = await signIn(auth, 'ada', 'idp-1', 'https://other-idp.test');

    const response = await auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } })));

    expect(response.status).toBe(200);
    expect(await auth.readSession(elsewhere)).not.toBeNull();
  });

  it.each<[string, Partial<FidesAuthConfig>]>([
    ['sessions kept in cookies', { sessionStore: undefined }],
    ['a store that cannot search', { sessionStore: { ...createMemorySessionStore(), findMatching: undefined } }],
  ])('throws with %s, rather than tell the provider it logged anyone out', async (_, overrides) => {
    const { auth } = setup(overrides);

    await expect(
      auth.handleBackChannelLogout(posted(await logoutToken({ claims: { sub: 'ada' } }))),
    ).rejects.toThrow('handleBackChannelLogout needs a sessionStore with findMatching');
  });
});
