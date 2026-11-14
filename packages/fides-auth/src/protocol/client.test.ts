/**
 * Tests for `createOidcClient`: each client has its own discovery cache, JWKS
 * cache and loggers, it does no I/O until a method needs the provider, and its
 * methods run the same protocol code as the free functions in /oauth.
 */
import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  buildAuthorizationUrl: vi.fn(),
  buildAuthorizationUrlWithPAR: vi.fn(),
  authorizationCodeGrant: vi.fn(),
  refreshTokenGrant: vi.fn(),
  clientCredentialsGrant: vi.fn(),
  buildEndSessionUrl: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
  ClientSecretBasic: vi.fn(() => () => undefined),
  None: vi.fn(() => () => undefined),
  PrivateKeyJwt: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import type { FidesLoggerFactory } from '../shared/logger.js';
import { createOidcClient } from './client.js';
import type { OidcClientConfig } from './config.js';
import { clearDiscoveryCache, discoverConfiguration } from './discovery.js';

const issuer = 'https://auth.example.test';
const jwksUri = `${issuer}/jwks`;

const config: OidcClientConfig = {
  issuer,
  clientId: 'client-a',
  clientSecret: 'secret-a',
  redirectUri: 'https://app.example.test/callback',
  scope: 'openid profile',
};

/** A stand-in for a discovered configuration with the given metadata. */
function discovered(metadata: Record<string, unknown> = {}): openid.Configuration {
  return {
    serverMetadata: () => ({ issuer, jwks_uri: jwksUri, ...metadata }),
  } as unknown as openid.Configuration;
}

interface LogLine {
  namespace: string;
  level: string;
  msg?: string;
}

/** A logger factory that records every line, with its namespace. */
function recordingLoggers(): { factory: FidesLoggerFactory; lines: LogLine[] } {
  const lines: LogLine[] = [];
  const factory: FidesLoggerFactory = {
    create: ({ namespace }) => {
      const log = (level: string) => (data?: unknown, msg?: string) => {
        lines.push({ namespace, level, msg: typeof data === 'string' ? data : msg });
      };
      return { debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error') };
    },
  };
  return { factory, lines };
}

const tokens = { access_token: 'access', token_type: 'bearer' } as openid.TokenEndpointResponse;

beforeEach(() => {
  vi.clearAllMocks();
  clearDiscoveryCache();
  vi.mocked(openid.discovery).mockResolvedValue(discovered());
  vi.mocked(openid.buildAuthorizationUrl).mockImplementation(
    (_config, parameters) => new URL(`${issuer}/authorize?${new URLSearchParams(parameters as Record<string, string>)}`),
  );
  vi.mocked(openid.authorizationCodeGrant).mockResolvedValue(tokens);
  vi.mocked(openid.refreshTokenGrant).mockResolvedValue(tokens);
  vi.mocked(openid.clientCredentialsGrant).mockResolvedValue(tokens);
});

describe('createOidcClient: state', () => {
  it('does no I/O until a method needs the provider', async () => {
    const client = createOidcClient(config);
    expect(openid.discovery).not.toHaveBeenCalled();

    await client.metadata();
    expect(openid.discovery).toHaveBeenCalledTimes(1);
  });

  it('reuses its discovery', async () => {
    const client = createOidcClient(config);
    await Promise.all([client.metadata(), client.metadata()]);
    await client.refresh('refresh-token');

    expect(openid.discovery).toHaveBeenCalledTimes(1);
  });

  it('shares no discovery cache with another client', async () => {
    await createOidcClient(config).metadata();
    await createOidcClient(config).metadata();

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('is independent of the module-level cache that the free functions use', async () => {
    const client = createOidcClient(config);
    await client.metadata();
    await discoverConfiguration({ ...config, redirect_uri: 'https://app.example.test/callback' });
    expect(openid.discovery).toHaveBeenCalledTimes(2);

    clearDiscoveryCache();
    await client.metadata();
    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it('logs only through its own logger factory', async () => {
    const a = recordingLoggers();
    const b = recordingLoggers();
    const clientA = createOidcClient(config, { logger: a.factory });
    const clientB = createOidcClient(config, { logger: b.factory });

    await clientA.refresh('refresh-token');
    expect(a.lines).toContainEqual({
      namespace: 'fides-auth:oidc-discovery',
      level: 'debug',
      msg: 'Discovering OpenID configuration',
    });
    expect(a.lines).toContainEqual({
      namespace: 'fides-auth:oauth',
      level: 'info',
      msg: 'Token refresh successful',
    });
    expect(b.lines).toEqual([]);

    const linesOfA = a.lines.length;
    await clientB.refresh('refresh-token');
    expect(b.lines.length).toBeGreaterThan(0);
    expect(a.lines).toHaveLength(linesOfA);
  });

  it('keeps the config it was created with', async () => {
    const own = { ...config };
    const client = createOidcClient(own);
    own.redirectUri = 'https://other.example.test/callback';

    const request = await client.createAuthorizationRequest();
    expect(request.parameters.redirect_uri).toBe('https://app.example.test/callback');
  });

  it('discovers on every call with discoveryTtlMs 0', async () => {
    const client = createOidcClient(config, { discoveryTtlMs: 0 });
    await client.metadata();
    await client.metadata();

    expect(openid.discovery).toHaveBeenCalledTimes(2);
  });

  it.each([Number.NaN, -1, Number.POSITIVE_INFINITY])(
    'rejects discoveryTtlMs %s when it is created',
    (discoveryTtlMs) => {
      expect(() => createOidcClient(config, { discoveryTtlMs })).toThrow(TypeError);
    },
  );
});

describe('createOidcClient: redirect URI', () => {
  const { redirectUri: _unused, ...withoutRedirect } = config;

  it('takes the older redirect_uri spelling', async () => {
    const client = createOidcClient({
      ...withoutRedirect,
      redirect_uri: 'https://legacy.example.test/callback',
    } as OidcClientConfig);
    const request = await client.createAuthorizationRequest();

    expect(request.parameters.redirect_uri).toBe('https://legacy.example.test/callback');
  });

  it('takes both spellings when they agree, and rejects them when they differ', async () => {
    const same = createOidcClient({ ...config, redirect_uri: config.redirectUri });
    await expect(same.createAuthorizationRequest()).resolves.toBeDefined();

    const different = createOidcClient({ ...config, redirect_uri: 'https://other.example.test/cb' });
    await expect(different.createAuthorizationRequest()).rejects.toThrow(TypeError);
  });

  it('is needed only by the operations that use it', async () => {
    const client = createOidcClient(withoutRedirect as OidcClientConfig);

    await expect(client.createAuthorizationRequest()).rejects.toThrow(/redirectUri/);
    await expect(
      client.exchangeCode(new URL('https://app.example.test/cb?code=c'), {
        codeVerifier: 'v',
        state: 's',
      }),
    ).rejects.toThrow(/redirectUri/);
    await expect(client.clientCredentials({ scope: 'api:read' })).resolves.toBe(tokens);
  });
});

describe('createOidcClient: authorization requests', () => {
  it('creates a PKCE pair, a state and the parameters', async () => {
    const client = createOidcClient({ ...config, authorizationParameters: { prompt: 'login' } });
    const request = await client.createAuthorizationRequest({ parameters: { ui_locales: 'nb' } });

    expect(request.codeVerifier).toMatch(/^[\w-]{43,}$/);
    expect(request.state).toMatch(/^[\w-]+$/);
    expect(request.parameters).toEqual({
      redirect_uri: 'https://app.example.test/callback',
      scope: 'openid profile',
      prompt: 'login',
      ui_locales: 'nb',
      code_challenge: request.codeChallenge,
      code_challenge_method: 'S256',
      state: request.state,
    });
  });

  it('rejects reserved parameters', async () => {
    const client = createOidcClient(config);

    await expect(
      client.createAuthorizationRequest({ parameters: { state: 'mine' } }),
    ).rejects.toThrow(/Reserved/);
  });

  it('builds the authorization URL from the request', async () => {
    const client = createOidcClient(config);
    const request = await client.createAuthorizationRequest();
    const url = await client.authorizationUrl(request);

    expect(openid.buildAuthorizationUrl).toHaveBeenCalledWith(expect.anything(), request.parameters);
    expect(url.searchParams.get('state')).toBe(request.state);
  });

  it('goes through PAR when usePar is set', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(
      discovered({ pushed_authorization_request_endpoint: `${issuer}/par` }),
    );
    vi.mocked(openid.buildAuthorizationUrlWithPAR).mockResolvedValue(new URL(`${issuer}/authorize?request_uri=x`));
    const client = createOidcClient({ ...config, usePar: true });
    const request = await client.createAuthorizationRequest();
    await client.authorizationUrl(request);

    expect(openid.buildAuthorizationUrlWithPAR).toHaveBeenCalledWith(expect.anything(), request.parameters);
    expect(openid.buildAuthorizationUrl).not.toHaveBeenCalled();
  });

  it('builds a silent login URL with prompt=none, login_hint and max_age', async () => {
    const client = createOidcClient({ ...config, authorizationParameters: { prompt: 'login' } });
    const request = await client.createAuthorizationRequest();
    const url = await client.silentLoginUrl(request, { loginHint: 'ada@example.test', maxAge: 0 });

    expect(url.searchParams.get('prompt')).toBe('none');
    expect(url.searchParams.get('login_hint')).toBe('ada@example.test');
    expect(url.searchParams.get('max_age')).toBe('0');
    expect(url.searchParams.get('state')).toBe(request.state);
    expect(url.searchParams.get('code_challenge')).toBe(request.codeChallenge);
  });
});

describe('createOidcClient: tokens', () => {
  it('exchanges a code with the request it started with', async () => {
    const client = createOidcClient(config);
    await client.exchangeCode(new URL('http://internal:3000/callback?code=c&state=s'), {
      codeVerifier: 'verifier',
      state: 's',
    });

    const [, callbackUrl, checks, parameters] = vi.mocked(openid.authorizationCodeGrant).mock.calls[0];
    expect(String(callbackUrl)).toBe('https://app.example.test/callback?code=c&state=s');
    expect(checks).toEqual({ pkceCodeVerifier: 'verifier', expectedState: 's' });
    expect(parameters).toEqual({ redirect_uri: 'https://app.example.test/callback' });
  });

  it('refreshes with the configured scope', async () => {
    const client = createOidcClient({ ...config, scope: ['openid', 'offline_access'] });
    await client.refresh('refresh-token');

    expect(openid.refreshTokenGrant).toHaveBeenCalledWith(expect.anything(), 'refresh-token', {
      scope: 'openid offline_access',
    });
  });

  it('runs client credentials with its own scope, not the login scope', async () => {
    const client = createOidcClient(config);
    await client.clientCredentials({ scope: ['api:read', 'api:write'] });
    await client.clientCredentials();

    expect(openid.clientCredentialsGrant).toHaveBeenNthCalledWith(1, expect.anything(), {
      scope: 'api:read api:write',
    });
    expect(openid.clientCredentialsGrant).toHaveBeenNthCalledWith(2, expect.anything(), undefined);
  });

  it('rejects client credentials for a public client before any I/O', async () => {
    const client = createOidcClient({
      issuer,
      clientId: 'public',
      clientAuth: 'none',
      scope: 'openid',
    });

    await expect(client.clientCredentials()).rejects.toThrow(TypeError);
    expect(openid.discovery).not.toHaveBeenCalled();
  });
});

describe('createOidcClient: logout', () => {
  it('builds a logout URL from the end-session endpoint', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(
      discovered({ end_session_endpoint: `${issuer}/logout` }),
    );
    vi.mocked(openid.buildEndSessionUrl).mockImplementation(
      (_config, parameters) => new URL(`${issuer}/logout?${new URLSearchParams(parameters as Record<string, string>)}`),
    );
    const client = createOidcClient(config);
    const url = await client.logoutUrl({ postLogoutRedirectUri: 'https://app.example.test/' });

    expect(url?.searchParams.get('post_logout_redirect_uri')).toBe('https://app.example.test/');
  });

  it('answers null when the provider has no end-session endpoint', async () => {
    await expect(createOidcClient(config).logoutUrl()).resolves.toBeNull();
  });
});

describe('createOidcClient: verifyIdToken', () => {
  let privateKey: CryptoKey;
  let jwk: JWK;
  const fetchMock = vi.fn(
    async () =>
      new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );

  beforeAll(async () => {
    const pair = await generateKeyPair('RS256');
    privateKey = pair.privateKey;
    jwk = { ...(await exportJWK(pair.publicKey)), kid: 'key-1', alg: 'RS256', use: 'sig' };
  });

  beforeEach(() => {
    fetchMock.mockClear();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function sign(audience = config.clientId): Promise<string> {
    return new SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  }

  it('checks the issuer from the metadata and the client ID as audience', async () => {
    const client = createOidcClient(config);

    await expect(client.verifyIdToken(await sign())).resolves.toMatchObject({ sub: 'user-1' });
    await expect(client.verifyIdToken(await sign('someone-else'))).rejects.toThrow();
  });

  it('caches the JWKS on the client, not across clients', async () => {
    const a = createOidcClient(config);
    const b = createOidcClient(config);
    const token = await sign();

    await a.verifyIdToken(token);
    await a.verifyIdToken(token);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await b.verifyIdToken(token);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects when the metadata has no jwks_uri', async () => {
    vi.mocked(openid.discovery).mockResolvedValue(discovered({ jwks_uri: undefined }));

    await expect(createOidcClient(config).verifyIdToken(await sign())).rejects.toThrow(/jwks_uri/);
  });
});
