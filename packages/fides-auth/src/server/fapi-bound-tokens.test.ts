/**
 * `profile: 'fapi2'` holds on every path that asks for tokens or keeps them,
 * not only at the login the handlers run: a caller who leaves the DPoP key
 * out, or starts a session from a bearer response, gets an error and not
 * bearer tokens under a profile that promises bound ones.
 */
import { generateKeyPair } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createOidcClient } from '../protocol/client.js';
import type { OidcClientConfig } from '../protocol/config.js';
import type { FidesLoggerFactory } from '../shared/logger.js';
import type { CookieStore } from './cookie-store.js';
import { createFidesAuth } from './fides-auth.js';
import { createMemorySessionStore } from './session-store.js';

const ISSUER = 'https://idp.test';
const secret = 'a'.repeat(64);
const quiet: FidesLoggerFactory = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };

let privateKey: CryptoKey;

beforeAll(async () => {
  ({ privateKey } = await generateKeyPair('ES256'));
});

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      throw new Error(`Nothing should be sent, but ${String(input instanceof Request ? input.url : input)} was asked`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const base = () => ({
  issuer: ISSUER,
  clientId: 'web',
  redirectUri: 'https://app.test/callback',
  scope: 'openid offline_access',
  serverMetadata: {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    pushed_authorization_request_endpoint: `${ISSUER}/par`,
  },
});

const fapi = (): OidcClientConfig => ({
  ...base(),
  clientAuth: 'private_key_jwt',
  privateKey,
  usePar: true,
  dpop: true,
  profile: 'fapi2',
});

/** The same provider and client without the profile, as the app ran before it turned the profile on. */
const withoutProfile = (): OidcClientConfig => ({ ...base(), clientAuth: 'private_key_jwt', privateKey });

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

describe('the OIDC client under profile fapi2', () => {
  const callback = new URL(`https://app.test/callback?code=c&state=s&iss=${ISSUER}`);

  it('exchanges no code without a DPoP key', async () => {
    const oidc = createOidcClient(fapi(), { logger: quiet });

    await expect(oidc.exchangeCode(callback, { codeVerifier: 'v', state: 's' })).rejects.toThrow(
      "profile 'fapi2': exchangeCode needs a dpopKey",
    );
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it('refreshes nothing without a DPoP key', async () => {
    const oidc = createOidcClient(fapi(), { logger: quiet });

    await expect(oidc.refresh('refresh-token')).rejects.toThrow("profile 'fapi2': refresh needs a dpopKey");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it('asks UserInfo for nothing without a DPoP key', async () => {
    const oidc = createOidcClient(fapi(), { logger: quiet });

    await expect(oidc.userInfo('access-token', { expectedSubject: 'ada' })).rejects.toThrow(
      "profile 'fapi2': userInfo needs a dpopKey",
    );
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it('has no client credentials grant, whose tokens would not be bound', async () => {
    const oidc = createOidcClient(fapi(), { logger: quiet });

    await expect(oidc.clientCredentials({ scope: 'api:read' })).rejects.toThrow(
      "profile 'fapi2': the client credentials grant is not available",
    );
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it('asks for none of this without the profile', async () => {
    const oidc = createOidcClient(withoutProfile(), { logger: quiet });

    // They get as far as the provider, which the stub refuses: the profile's check is not what stops them.
    await expect(oidc.refresh('refresh-token')).rejects.toThrow();
    expect(vi.mocked(fetch)).toHaveBeenCalled();
  });
});

describe('createFidesAuth under profile fapi2', () => {
  it('starts no session from a bearer token response', async () => {
    const auth = createFidesAuth({ oauthConfig: fapi(), secret, sessionStore: createMemorySessionStore(), logger: quiet });
    const cookies = browser();

    await expect(
      auth.createSession(cookies, { access_token: 'access', token_type: 'bearer', expires_in: 300 }),
    ).rejects.toThrow('takes only DPoP-bound tokens');
    expect(await auth.readSession(cookies)).toBeNull();
  });

  it('starts no session from a DPoP response without its key', async () => {
    const auth = createFidesAuth({ oauthConfig: fapi(), secret, sessionStore: createMemorySessionStore(), logger: quiet });
    const cookies = browser();

    await expect(
      auth.createSession(cookies, { access_token: 'access', token_type: 'dpop', expires_in: 300 }),
    ).rejects.toThrow('takes only DPoP-bound tokens');
  });

  it('starts one from a bound response with its key', async () => {
    const auth = createFidesAuth({ oauthConfig: fapi(), secret, sessionStore: createMemorySessionStore(), logger: quiet });
    const cookies = browser();
    const dpopKey = await auth.oidc.createDpopKey();

    await auth.createSession(cookies, { access_token: 'access', token_type: 'dpop', expires_in: 300 }, { dpopKey });

    expect((await auth.getTokens(cookies))?.tokenType).toBe('dpop');
  });

  it("doesn't refresh a bearer session from before the profile was turned on", async () => {
    const sessionStore = createMemorySessionStore();
    const cookies = browser();
    await createFidesAuth({ oauthConfig: withoutProfile(), secret, sessionStore, logger: quiet }).createSession(cookies, {
      access_token: 'access',
      token_type: 'bearer',
      expires_in: 300,
      refresh_token: 'refresh',
    });

    // The same app, now with the profile: the session is still there, and it would refresh into more bearer tokens.
    const auth = createFidesAuth({ oauthConfig: fapi(), secret, sessionStore, logger: quiet });
    const refreshed = await auth.refreshSession(cookies);

    expect(refreshed).toMatchObject({ ok: false, reason: 'unsupported_token_type' });
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
    // It ends with the tokens it has, not at once.
    expect(await auth.readSession(cookies)).not.toBeNull();
  });

  it('keeps DPoP on when the config object is changed after the instance is made', async () => {
    const oauthConfig = { ...withoutProfile(), dpop: true };
    const auth = createFidesAuth({ oauthConfig, secret, logger: quiet });
    oauthConfig.dpop = false;

    const started = await auth.handleOidcLogin(new Request('https://app.test/login'), browser());

    // The login still names a key: the setting was read when the instance was created.
    expect(new URL(started.headers.get('location') ?? '').searchParams.get('dpop_jkt')).toMatch(/^[\w-]{43}$/);
  });
});
