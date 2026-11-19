/**
 * The nonce of a login, end to end: the handlers run the real openid-client
 * against a stubbed provider, so what is tested is that an ID token is taken
 * only when it carries the nonce this login sent. The protocol layer's own
 * tests check what is handed to openid-client; these check what it then does.
 */
import { generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLoggerFactory } from '../shared/logger.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth, type FidesAuth, issuerForKey, type LoginError } from './fides-auth.js';
import { createTransaction, persistTransaction } from './login-transaction.js';

const APP = 'https://app.test';
const ISSUER = 'https://idp.test';
const CLIENT_ID = 'web';
const secret = 'a'.repeat(64);
/** What the instance seals its sessions and its logins for: its provider and its client. */
const AUDIENCE = JSON.stringify([issuerForKey(ISSUER), CLIENT_ID]);

const quiet: FidesLoggerFactory = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

const oauthConfig = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: 'shh',
  redirectUri: `${APP}/api/auth/callback`,
  scope: 'openid profile',
  serverMetadata: {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
  },
};

let signingKey: CryptoKey;

beforeAll(async () => {
  ({ privateKey: signingKey } = await generateKeyPair('RS256'));
});

/** An ID token as the provider would sign it, with `nonce` when given. */
function idToken(nonce?: string, sub = 'user-1'): Promise<string> {
  return new SignJWT({ ...(nonce === undefined ? {} : { nonce }), name: 'Ada' })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(ISSUER)
    .setAudience(CLIENT_ID)
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signingKey);
}

/** What the token endpoint answers. Set by each test. */
let tokenResponse: () => Promise<Record<string, unknown>>;

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `${ISSUER}/token`) return Response.json(await tokenResponse());
      throw new Error(`Unexpected request to ${url}`);
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

function instance(config: Partial<typeof oauthConfig> = {}) {
  const failures: LoginError[] = [];
  const auth = createFidesAuth({
    oauthConfig: { ...oauthConfig, ...config },
    secret,
    logger: quiet,
    onLoginError: (failure) => void failures.push(failure),
  });
  return { auth, failures };
}

/** Starts a login and returns what the browser was sent to the provider with. */
async function start(auth: FidesAuth, cookies: CookieStore) {
  const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
  const authorize = new URL(started.headers.get('location') ?? '');
  expect(authorize.origin).toBe(ISSUER);
  return {
    state: authorize.searchParams.get('state') ?? '',
    nonce: authorize.searchParams.get('nonce'),
  };
}

function callback(auth: FidesAuth, cookies: CookieStore, state: string): Promise<Response> {
  return auth.handleOidcCallback(new Request(`${APP}/api/auth/callback?code=c&state=${state}`), cookies);
}

const tokensWith = (id_token?: string) => ({
  access_token: 'access-1',
  token_type: 'bearer',
  expires_in: 300,
  ...(id_token ? { id_token } : {}),
});

describe('the nonce of a login', () => {
  it('is sent to the provider, new for each login and kept out of the cookies in the clear', async () => {
    const { auth } = instance();
    const { cookies, jar } = browser();

    const first = await start(auth, cookies);
    const second = await start(auth, cookies);

    expect(first.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second.nonce).not.toBe(first.nonce);
    expect(first.nonce).not.toBe(first.state);
    // Sealed with the verifier in the login transaction.
    expect([...jar.values()].join('\n')).not.toContain(first.nonce);
  });

  it('logs in when the ID token carries the nonce the login sent', async () => {
    const { auth, failures } = instance();
    const { cookies, jar } = browser();
    const { state, nonce } = await start(auth, cookies);
    tokenResponse = async () => tokensWith(await idToken(nonce ?? undefined));

    const done = await callback(auth, cookies, state);

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    expect((await auth.readSession(cookies))?.user).toMatchObject({ sub: 'user-1', name: 'Ada' });
    // The transaction is spent, and the nonce with it.
    expect([...jar.keys()]).toEqual(['__Host-session']);
  });

  it.each([
    ['carries another nonce', () => idToken('not-the-nonce-of-this-login')],
    ['carries no nonce', () => idToken()],
    ['carries an empty nonce', () => idToken('')],
  ])('refuses the login when the ID token %s', async (_, token) => {
    const { auth, failures } = instance();
    const { cookies, jar } = browser();
    const { state } = await start(auth, cookies);
    tokenResponse = async () => tokensWith(await token());

    const done = await callback(auth, cookies, state);

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(failures[0]).toMatchObject({ code: 'login_failed', stage: 'callback' });
    expect(await auth.readSession(cookies)).toBeNull();
    expect(jar.has('__Host-session')).toBe(false);
  });

  it("refuses an ID token issued for another login of the same browser", async () => {
    const { auth } = instance();
    const { cookies } = browser();
    const mine = await start(auth, cookies);
    const other = await start(auth, cookies);
    // A valid token, for this client and this provider, with the other login's nonce.
    tokenResponse = async () => tokensWith(await idToken(other.nonce ?? undefined, 'someone-else'));

    const done = await callback(auth, cookies, mine.state);

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('refuses a token response without an ID token, when the login asked for openid', async () => {
    const { auth, failures } = instance();
    const { cookies } = browser();
    const { state } = await start(auth, cookies);
    tokenResponse = async () => tokensWith();

    const done = await callback(auth, cookies, state);

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('sends none and expects none without the openid scope', async () => {
    const { auth, failures } = instance({ scope: 'api:read' });
    const { cookies } = browser();
    const { state, nonce } = await start(auth, cookies);
    expect(nonce).toBeNull();
    tokenResponse = async () => tokensWith();

    const done = await callback(auth, cookies, state);

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    expect((await auth.getTokens(cookies))?.accessToken).toBe('access-1');
  });

  it('finishes a login that was started before the nonce was sent', async () => {
    // A deploy between the redirect and the callback: the transaction in the
    // browser has no nonce, and the provider was sent none.
    const { auth, failures } = instance();
    const { cookies } = browser();
    const transaction = createTransaction(
      { state: 'state-from-before', codeVerifier: 'verifier-from-before' },
      { logger: quiet.create({ namespace: 'test' }) },
    );
    await persistTransaction(cookies, transaction, secret, { audience: AUDIENCE });
    tokenResponse = async () => tokensWith(await idToken());

    const done = await callback(auth, cookies, 'state-from-before');

    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    expect(failures).toEqual([]);
    expect((await auth.readSession(cookies))?.user?.sub).toBe('user-1');
  });

  it('still refuses an ID token with a nonce for a login that sent none', async () => {
    const { auth } = instance();
    const { cookies } = browser();
    const transaction = createTransaction(
      { state: 'state-from-before', codeVerifier: 'verifier-from-before' },
      { logger: quiet.create({ namespace: 'test' }) },
    );
    await persistTransaction(cookies, transaction, secret, { audience: AUDIENCE });
    tokenResponse = async () => tokensWith(await idToken('a-nonce-nobody-sent'));

    const done = await callback(auth, cookies, 'state-from-before');

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(await auth.readSession(cookies)).toBeNull();
  });
});
