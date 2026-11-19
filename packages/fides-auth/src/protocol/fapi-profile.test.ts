/**
 * `profile: 'fapi2'`: what a config must have to be created, the signature
 * algorithms it accepts, the `iss` it requires on the callback, and one login
 * through the handlers with all of it on.
 *
 * openid-client is not mocked, only `fetch`.
 */
import { calculateJwkThumbprint, decodeProtectedHeader, EmbeddedJWK, exportJWK, generateKeyPair, type JWK, jwtVerify, SignJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { CookieStore } from '../server/cookie-store.js';
import { createFidesAuth, type LoginError } from '../server/fides-auth.js';
import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient } from './client.js';
import type { OidcClientConfig } from './config.js';
import { BACK_CHANNEL_LOGOUT_EVENT, LogoutTokenError } from './logout-token.js';

const APP = 'https://app.example.test';
const issuer = 'https://auth.example.test';
const clientId = 'client-a';
const redirectUri = `${APP}/api/auth/callback`;

const serverMetadata = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  pushed_authorization_request_endpoint: `${issuer}/par`,
  jwks_uri: `${issuer}/jwks`,
  dpop_signing_alg_values_supported: ['ES256'],
};

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };

type Alg = 'RS256' | 'PS256' | 'ES256';
const keys = {} as Record<Alg, CryptoKeyPair>;
let providerJwks: { keys: JWK[] };

beforeAll(async () => {
  const jwks: JWK[] = [];
  for (const alg of ['RS256', 'PS256', 'ES256'] as const) {
    keys[alg] = await generateKeyPair(alg);
    jwks.push({ ...(await exportJWK(keys[alg].publicKey)), kid: alg, alg, use: 'sig' });
  }
  providerJwks = { keys: jwks };
});

/** A config that meets the profile, with `overrides` on top. */
function config(overrides: Record<string, unknown> = {}): OidcClientConfig {
  return {
    issuer,
    clientId,
    clientAuth: 'private_key_jwt',
    privateKey: keys.ES256.privateKey,
    redirectUri,
    scope: 'api:read',
    usePar: true,
    dpop: true,
    profile: 'fapi2',
    serverMetadata,
    ...overrides,
  } as OidcClientConfig;
}

/** The same config without the profile. */
const withoutProfile = (overrides: Record<string, unknown> = {}) => config({ profile: undefined, ...overrides });

const create = (overrides?: Record<string, unknown>) => createOidcClient(config(overrides), { logger: quiet });

/** What creating a client threw. */
function refusal(overrides: Record<string, unknown>): Error {
  try {
    create(overrides);
  } catch (error) {
    return error as Error;
  }
  throw new Error('the config was accepted');
}

/** What the stubbed provider got, by URL. */
let requests: Array<{ url: string; init?: RequestInit }> = [];
/** The key thumbprint of the proof sent with the code. */
let boundTo: string | undefined;

const callsTo = (url: string) => requests.filter((request) => request.url === url);

beforeEach(() => {
  requests = [];
  boundTo = undefined;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      requests.push({ url, init });
      if (url === serverMetadata.jwks_uri) return Response.json(providerJwks);
      if (url === serverMetadata.pushed_authorization_request_endpoint) {
        return Response.json({ request_uri: 'urn:ietf:params:oauth:request_uri:one', expires_in: 60 }, { status: 201 });
      }
      if (url === serverMetadata.token_endpoint) {
        const proof = new Headers(init?.headers).get('dpop');
        if (!proof) return Response.json({ error: 'invalid_dpop_proof' }, { status: 400 });
        const { payload, protectedHeader } = await jwtVerify(proof, EmbeddedJWK, { typ: 'dpop+jwt', algorithms: ['ES256'] });
        if (payload.htm !== 'POST' || payload.htu !== url || !protectedHeader.jwk) {
          return Response.json({ error: 'invalid_dpop_proof' }, { status: 400 });
        }
        boundTo = await calculateJwkThumbprint(protectedHeader.jwk);
        return Response.json({ access_token: 'access-1', token_type: 'DPoP', expires_in: 300, refresh_token: 'refresh-1' });
      }
      throw new Error(`Unexpected request to ${url}`);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('creating a client with profile fapi2', () => {
  it('accepts a config with private_key_jwt, PAR and DPoP', () => {
    expect(() => create()).not.toThrow();
  });

  it.each([
    ['a PS256 key', () => keys.PS256.privateKey],
    ['an ES256 key with a kid', () => ({ key: keys.ES256.privateKey, kid: 'client-key-1' })],
  ])('accepts %s', (_, privateKey) => {
    expect(() => create({ privateKey: privateKey() })).not.toThrow();
  });

  it.each([
    ['client_secret_post, by default', { clientAuth: undefined, privateKey: undefined, clientSecret: 's' }, "clientAuth must be 'private_key_jwt' (got 'client_secret_post')"],
    ['client_secret_basic', { clientAuth: 'client_secret_basic', privateKey: undefined, clientSecret: 's' }, "clientAuth must be 'private_key_jwt' (got 'client_secret_basic')"],
    ['a public client', { clientAuth: 'none', privateKey: undefined }, "clientAuth must be 'private_key_jwt' (got 'none')"],
    ['usePar left out', { usePar: undefined }, 'usePar must be true'],
    ['usePar false', { usePar: false }, 'usePar must be true'],
    ['dpop left out', { dpop: undefined }, 'dpop must be true'],
    ['dpop false', { dpop: false }, 'dpop must be true'],
    ['allowInsecureRequests', { allowInsecureRequests: true }, 'allowInsecureRequests must not be set'],
  ])('refuses %s, and nothing else', (_, overrides, requirement) => {
    const error = refusal(overrides);

    expect(error).toBeInstanceOf(TypeError);
    expect(error.message).toBe(`profile 'fapi2' is not met: ${requirement}`);
  });

  it.each([
    ['an RS256 key', () => keys.RS256.privateKey],
    ['an RS256 key with a kid', () => ({ key: keys.RS256.privateKey, kid: 'client-key-1' })],
  ])('refuses %s, and nothing else', (_, privateKey) => {
    const error = refusal({ privateKey: privateKey() });

    expect(error).toBeInstanceOf(TypeError);
    expect(error.message).toBe(
      "profile 'fapi2' is not met: privateKey must sign with PS256, ES256 or EdDSA (got an RSASSA-PKCS1-v1_5 key, which signs RS256)",
    );
  });

  it('names every requirement that is not met, in one message', () => {
    const error = refusal({
      clientAuth: 'client_secret_basic',
      privateKey: undefined,
      clientSecret: 's',
      usePar: false,
      dpop: false,
      allowInsecureRequests: true,
    });

    expect(error).toBeInstanceOf(TypeError);
    expect(error.message).toBe(
      "profile 'fapi2' is not met: clientAuth must be 'private_key_jwt' (got 'client_secret_basic'); " +
        'usePar must be true; dpop must be true; allowInsecureRequests must not be set',
    );
  });

  it('names an RS256 key next to the others', () => {
    const { message } = refusal({ privateKey: keys.RS256.privateKey, dpop: false });

    expect(message).toContain('privateKey must sign with');
    expect(message).toContain('dpop must be true');
  });

  it('refuses a profile it does not know', () => {
    expect(() => create({ profile: 'fapi1' })).toThrow(new TypeError('Unsupported profile: fapi1'));
  });

  it('refuses the same config through createFidesAuth', () => {
    expect(() =>
      createFidesAuth({ oauthConfig: config({ usePar: false }), secret: 'a'.repeat(64), logger: quiet }),
    ).toThrow(new TypeError("profile 'fapi2' is not met: usePar must be true"));
  });

  it('checks nothing without the profile', () => {
    expect(() =>
      createOidcClient(
        withoutProfile({
          clientAuth: 'private_key_jwt',
          privateKey: keys.RS256.privateKey,
          usePar: false,
          dpop: false,
          allowInsecureRequests: true,
        }),
        { logger: quiet },
      ),
    ).not.toThrow();
  });
});

describe('signature algorithms', () => {
  function idToken(alg: Alg): Promise<string> {
    return new SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg, kid: alg })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(keys[alg].privateKey);
  }

  function logoutToken(alg: Alg): Promise<string> {
    return new SignJWT({ sub: 'user-1', events: { [BACK_CHANNEL_LOGOUT_EVENT]: {} } })
      .setProtectedHeader({ alg, kid: alg, typ: 'logout+jwt' })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime('2m')
      .setJti('logout-1')
      .sign(keys[alg].privateKey);
  }

  const plain = () => createOidcClient(withoutProfile(), { logger: quiet });

  describe('of an ID token', () => {
    it.each(['ES256', 'PS256'] as const)('accepts %s under the profile', async (alg) => {
      await expect(create().verifyIdToken(await idToken(alg))).resolves.toMatchObject({ sub: 'user-1' });
    });

    it('refuses RS256 under the profile, by default', async () => {
      await expect(create().verifyIdToken(await idToken('RS256'))).rejects.toMatchObject({
        code: 'ERR_JOSE_ALG_NOT_ALLOWED',
      });
    });

    it('accepts RS256 without the profile', async () => {
      await expect(plain().verifyIdToken(await idToken('RS256'))).resolves.toMatchObject({ sub: 'user-1' });
    });

    it.each([
      ['RS256 alone', ['RS256'], 'RS256'],
      ['RS256 next to ES256', ['ES256', 'RS256'], 'RS256'],
      ['the larger hashes', ['PS384', 'ES512'], 'PS384, ES512'],
      ['none', ['none'], 'none'],
    ])('throws for an explicit list with %s, before anything is fetched', async (_, algorithms, named) => {
      const error = await create()
        .verifyIdToken(await idToken('RS256'), { algorithms })
        .catch((thrown: unknown) => thrown);

      expect(error).toBeInstanceOf(TypeError);
      expect((error as Error).message).toBe(`profile 'fapi2' allows only PS256, ES256, EdDSA, not ${named}`);
      expect(requests).toEqual([]);
    });

    it('takes an explicit list within the three, and narrows to it', async () => {
      const client = create();

      await expect(client.verifyIdToken(await idToken('ES256'), { algorithms: ['ES256'] })).resolves.toMatchObject({
        sub: 'user-1',
      });
      await expect(client.verifyIdToken(await idToken('PS256'), { algorithms: ['ES256'] })).rejects.toMatchObject({
        code: 'ERR_JOSE_ALG_NOT_ALLOWED',
      });
    });

    it('takes an explicit RS256 without the profile', async () => {
      await expect(plain().verifyIdToken(await idToken('RS256'), { algorithms: ['RS256'] })).resolves.toMatchObject({
        sub: 'user-1',
      });
    });
  });

  describe('of a logout token', () => {
    it.each(['ES256', 'PS256'] as const)('accepts %s under the profile', async (alg) => {
      await expect(create().verifyLogoutToken(await logoutToken(alg))).resolves.toMatchObject({
        sub: 'user-1',
        jti: 'logout-1',
      });
    });

    it('refuses RS256 under the profile, by default', async () => {
      const error = await create()
        .verifyLogoutToken(await logoutToken('RS256'))
        .catch((thrown: unknown) => thrown);

      expect(error).toBeInstanceOf(LogoutTokenError);
      expect(error).toMatchObject({ reason: 'invalid_token', cause: { code: 'ERR_JOSE_ALG_NOT_ALLOWED' } });
    });

    it('accepts RS256 without the profile', async () => {
      await expect(plain().verifyLogoutToken(await logoutToken('RS256'))).resolves.toMatchObject({ sub: 'user-1' });
    });

    it('throws a TypeError for an explicit RS256, not a refused token', async () => {
      const error = await create()
        .verifyLogoutToken(await logoutToken('RS256'), { algorithms: ['RS256'] })
        .catch((thrown: unknown) => thrown);

      expect(error).toBeInstanceOf(TypeError);
      expect((error as Error).message).toBe("profile 'fapi2' allows only PS256, ES256, EdDSA, not RS256");
      expect(requests).toEqual([]);
    });
  });
});

describe('the iss of the callback', () => {
  /** Exchanges the code of a callback with `parameters` next to its `code` and `state`. */
  async function exchange(oidcConfig: OidcClientConfig, parameters: Record<string, string> = {}) {
    const client = createOidcClient(oidcConfig, { logger: quiet });
    // One key for the login: named in the request as dpop_jkt, and proved at the exchange.
    const dpopKey = await client.createDpopKey();
    const request = await client.createAuthorizationRequest({ dpopKey });
    const callbackUrl = new URL(redirectUri);
    callbackUrl.search = new URLSearchParams({ code: 'code-1', state: request.state, ...parameters }).toString();
    return client.exchangeCode(callbackUrl, request, { dpopKey });
  }

  it('needs the key before the redirect, to bind the code to it', async () => {
    const client = createOidcClient(config(), { logger: quiet });

    await expect(client.createAuthorizationRequest()).rejects.toThrow(
      "profile 'fapi2': createAuthorizationRequest needs a dpopKey",
    );
    const dpopKey = await client.createDpopKey();
    const request = await client.createAuthorizationRequest({ dpopKey });
    expect(request.parameters.dpop_jkt).toMatch(/^[\w-]{43}$/);
  });

  it('asks for no key without the profile', async () => {
    const client = createOidcClient(withoutProfile(), { logger: quiet });

    const request = await client.createAuthorizationRequest();

    expect('dpop_jkt' in request.parameters).toBe(false);
  });

  // The metadata here says nothing of `authorization_response_iss_parameter_supported`.
  it.each([
    ['without iss', {}],
    ['with an empty iss', { iss: '' }],
  ])('refuses a callback %s, before the token endpoint is called', async (_, parameters) => {
    const error = await exchange(config(), parameters).catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('no iss parameter');
    expect(requests).toEqual([]);
  });

  it('refuses it when the provider says it sends none, too', async () => {
    const metadata = { ...serverMetadata, authorization_response_iss_parameter_supported: false };

    await expect(exchange(config({ serverMetadata: metadata }))).rejects.toThrow('no iss parameter');
    expect(requests).toEqual([]);
  });

  it('still refuses an iss that is another provider, as openid-client does', async () => {
    await expect(exchange(config(), { iss: 'https://evil.example.test' })).rejects.toMatchObject({
      code: 'OAUTH_INVALID_RESPONSE',
    });
    expect(requests).toEqual([]);
  });

  it('exchanges the code of a callback whose iss is the provider', async () => {
    const tokens = await exchange(config(), { iss: issuer });

    expect(tokens.access_token).toBe('access-1');
    expect(callsTo(serverMetadata.token_endpoint)).toHaveLength(1);
  });

  it('exchanges the code of a callback without iss when there is no profile', async () => {
    const tokens = await exchange(withoutProfile());

    expect(tokens.access_token).toBe('access-1');
    expect(callsTo(serverMetadata.token_endpoint)).toHaveLength(1);
  });
});

describe('a login through createFidesAuth with profile fapi2', () => {
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

  function setup() {
    const failures: LoginError[] = [];
    const auth = createFidesAuth({
      oauthConfig: config({ scope: 'api:read offline_access' }),
      secret: 'a'.repeat(64),
      logger: quiet,
      onLoginError: (failure) => void failures.push(failure),
    });
    return { auth, failures };
  }

  it('pushes the request, authenticates with the key, and binds the tokens with DPoP', async () => {
    const { auth, failures } = setup();
    const cookies = browser();

    const started = await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);

    // Only client_id and request_uri travel through the browser.
    const authorize = new URL(started.headers.get('location') ?? '');
    expect(`${authorize.origin}${authorize.pathname}`).toBe(serverMetadata.authorization_endpoint);
    expect([...authorize.searchParams.keys()].sort()).toEqual(['client_id', 'request_uri']);
    const [pushed] = callsTo(serverMetadata.pushed_authorization_request_endpoint);
    const pushedBody = new URLSearchParams(String(pushed?.init?.body));
    expect(pushedBody.get('code_challenge_method')).toBe('S256');
    expect(pushedBody.has('client_secret')).toBe(false);
    expect(decodeProtectedHeader(pushedBody.get('client_assertion') ?? '').alg).toBe('ES256');

    const state = pushedBody.get('state') ?? '';
    const callback = new URL(redirectUri);
    callback.search = new URLSearchParams({ code: 'code-1', state, iss: issuer }).toString();
    const done = await auth.handleOidcCallback(new Request(callback), cookies);

    expect(failures).toEqual([]);
    expect(done.headers.get('location')).toBe(`${APP}/?login=success`);
    const [tokenCall] = callsTo(serverMetadata.token_endpoint);
    const tokenBody = new URLSearchParams(String(tokenCall?.init?.body));
    expect(tokenBody.get('grant_type')).toBe('authorization_code');
    expect(tokenBody.has('client_secret')).toBe(false);
    await expect(
      jwtVerify(tokenBody.get('client_assertion') ?? '', keys.ES256.publicKey, {
        algorithms: ['ES256'],
        issuer: clientId,
        subject: clientId,
        audience: issuer,
      }),
    ).resolves.toBeDefined();

    const tokens = await auth.getTokens(cookies);
    expect(tokens).toMatchObject({ accessToken: 'access-1', tokenType: 'dpop' });
    const { x, y } = tokens?.dpopKey ?? { x: '', y: '' };
    expect(boundTo).toBe(await calculateJwkThumbprint({ kty: 'EC', crv: 'P-256', x, y }));
    // The code was bound to that same key: its thumbprint was pushed with the request, as dpop_jkt.
    expect(pushedBody.get('dpop_jkt')).toBe(boundTo);
  });

  it('fails the login when the callback has no iss, and sends the code nowhere', async () => {
    const { auth, failures } = setup();
    const cookies = browser();
    await auth.handleOidcLogin(new Request(`${APP}/api/auth/login`), cookies);
    const [pushed] = callsTo(serverMetadata.pushed_authorization_request_endpoint);
    const state = new URLSearchParams(String(pushed?.init?.body)).get('state') ?? '';

    const done = await auth.handleOidcCallback(
      new Request(`${redirectUri}?code=code-1&state=${state}`),
      cookies,
    );

    expect(done.headers.get('location')).toBe(`${APP}/?login=error&error=login_failed`);
    expect(failures).toHaveLength(1);
    expect(failures[0]?.cause).toMatchObject({ message: expect.stringContaining('no iss parameter') });
    expect(callsTo(serverMetadata.token_endpoint)).toEqual([]);
    expect(await auth.readSession(cookies)).toBeNull();
  });
});
