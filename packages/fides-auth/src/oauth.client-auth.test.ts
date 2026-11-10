/**
 * Tests for client authentication on the token request.
 *
 * openid-client is not mocked, only `fetch`, so these assert what each
 * `clientAuth` method actually puts on the wire.
 */
import { jwtVerify } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  clientCredentialsGrant,
  refreshAccessToken,
  type ClientCredentialsConfig,
  type OAuthConfig,
} from './oauth';
import { clearDiscoveryCache, discoverConfiguration } from './oidc-discovery';

const issuer = 'https://auth.example.test';
const tokenEndpoint = `${issuer}/token`;
const clientId = 'client-a';
const clientSecret = 'secret-a';

const base = {
  issuer,
  clientId,
  redirect_uri: 'https://app.example.test/callback',
  scope: 'openid',
};

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

const fetchMock = vi.fn(async (input: string | URL | Request, _init?: RequestInit) => {
  if (String(input) === `${issuer}/.well-known/openid-configuration`) {
    return json({ issuer, token_endpoint: tokenEndpoint });
  }
  return json({ access_token: 'access', token_type: 'bearer', expires_in: 300 });
});

/** The body and headers of the token request openid-client sent. */
function tokenRequest() {
  const call = fetchMock.mock.calls.find(([url]) => String(url) === tokenEndpoint);
  if (!call?.[1]) throw new Error('no token request was sent');
  return {
    body: new URLSearchParams(call[1].body as URLSearchParams),
    headers: new Headers(call[1].headers),
  };
}

let keys: CryptoKeyPair;

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
});

beforeEach(() => {
  fetchMock.mockClear();
  vi.stubGlobal('fetch', fetchMock);
  clearDiscoveryCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

type Auth = Record<string, unknown>;

describe.each([
  [
    'refreshAccessToken (discovery)',
    (auth: Auth) => refreshAccessToken({ ...base, ...auth } as OAuthConfig, 'refresh-token'),
  ],
  [
    'clientCredentialsGrant',
    (auth: Auth) =>
      clientCredentialsGrant({
        tokenEndpoint,
        clientId,
        issuer,
        ...auth,
      } as ClientCredentialsConfig),
  ],
])('%s', (_, run) => {
  it('defaults to client_secret_post', async () => {
    await run({ clientSecret });

    const { body, headers } = tokenRequest();
    expect(body.get('client_id')).toBe(clientId);
    expect(body.get('client_secret')).toBe(clientSecret);
    expect(headers.has('authorization')).toBe(false);
  });

  it('sends the secret in the body for client_secret_post', async () => {
    await run({ clientAuth: 'client_secret_post', clientSecret });

    const { body, headers } = tokenRequest();
    expect(body.get('client_id')).toBe(clientId);
    expect(body.get('client_secret')).toBe(clientSecret);
    expect(headers.has('authorization')).toBe(false);
  });

  it('sends HTTP Basic credentials for client_secret_basic', async () => {
    await run({ clientAuth: 'client_secret_basic', clientSecret });

    const { body, headers } = tokenRequest();
    const [scheme, credentials] = headers.get('authorization')!.split(' ');
    expect(scheme).toBe('Basic');
    // RFC 6749 §2.3.1: each part is form-urlencoded before base64.
    expect(atob(credentials!).split(':').map(decodeURIComponent)).toEqual([clientId, clientSecret]);
    expect(body.has('client_secret')).toBe(false);
  });

  it('sends a signed client assertion for private_key_jwt', async () => {
    await run({ clientAuth: 'private_key_jwt', privateKey: keys.privateKey });

    const { body, headers } = tokenRequest();
    expect(body.get('client_id')).toBe(clientId);
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(body.has('client_secret')).toBe(false);
    expect(headers.has('authorization')).toBe(false);

    // Signed with our key, issued by the client, addressed to the server.
    await expect(
      jwtVerify(body.get('client_assertion')!, keys.publicKey, {
        issuer: clientId,
        subject: clientId,
        audience: issuer,
      }),
    ).resolves.toBeDefined();
  });
});

describe('clientAuth none', () => {
  it('sends only client_id', async () => {
    await refreshAccessToken({ ...base, clientAuth: 'none' }, 'refresh-token');

    const { body, headers } = tokenRequest();
    expect(body.get('client_id')).toBe(clientId);
    expect(body.has('client_secret')).toBe(false);
    expect(body.has('client_assertion')).toBe(false);
    expect(headers.has('authorization')).toBe(false);
  });
});

describe('unknown clientAuth', () => {
  it('rejects instead of falling back to another method', async () => {
    const config = {
      ...base,
      clientAuth: 'client_secret_jwt',
      clientSecret,
    } as unknown as OAuthConfig;

    await expect(discoverConfiguration(config)).rejects.toThrow(TypeError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
