/**
 * Two checks the FAPI 2.0 Security Profile asks of a client, both of which
 * openid-client does for us: the `iss` of the authorization response
 * (RFC 9207) and the audience of a `private_key_jwt` client assertion.
 *
 * openid-client is not mocked, only `fetch`, so these fail if an upgrade or a
 * change in how it is called makes either of them stop.
 */
import { decodeJwt, decodeProtectedHeader, generateKeyPair, jwtVerify } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient, type OidcClient } from './client.js';
import type { OidcClientConfig } from './config.js';

const issuer = 'https://auth.example.test';
const tokenEndpoint = `${issuer}/token`;
const clientId = 'client-a';
const redirectUri = 'https://app.example.test/callback';

const serverMetadata = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: tokenEndpoint,
};

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };

const fetchMock = vi.fn(async (input: string | URL | Request, _init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  if (url !== tokenEndpoint) throw new Error(`Unexpected request to ${url}`);
  return Response.json({ access_token: 'access', token_type: 'bearer', expires_in: 300 });
});

beforeEach(() => {
  fetchMock.mockClear();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * Starts a login and exchanges the code of a callback that carries
 * `callbackParameters` next to its `code` and `state`. No `openid` in the
 * scope, so no ID token is needed.
 */
async function exchange(client: OidcClient, callbackParameters: Record<string, string> = {}) {
  const request = await client.createAuthorizationRequest();
  const callbackUrl = new URL(redirectUri);
  callbackUrl.search = new URLSearchParams({
    code: 'code-1',
    state: request.state,
    ...callbackParameters,
  }).toString();
  return client.exchangeCode(callbackUrl, request);
}

describe('the iss of the authorization response', () => {
  const clientFor = (metadata: Record<string, unknown> = {}) =>
    createOidcClient(
      {
        issuer,
        clientId,
        clientSecret: 'secret-a',
        redirectUri,
        scope: 'api:read',
        serverMetadata: { ...serverMetadata, ...metadata },
      },
      { logger: quiet },
    );

  describe('when the provider says it sends one', () => {
    const client = () => clientFor({ authorization_response_iss_parameter_supported: true });

    it('refuses a callback without iss, before the code is sent anywhere', async () => {
      await expect(exchange(client())).rejects.toMatchObject({ code: 'OAUTH_INVALID_RESPONSE' });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it.each([
      ['another provider', 'https://evil.example.test'],
      ['this provider with a trailing slash', `${issuer}/`],
      ['empty', ''],
    ])('refuses a callback whose iss is %s, before the code is sent anywhere', async (_, iss) => {
      await expect(exchange(client(), { iss })).rejects.toMatchObject({
        code: 'OAUTH_INVALID_RESPONSE',
      });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('exchanges the code of a callback whose iss is the provider', async () => {
      const tokens = await exchange(client(), { iss: issuer });

      expect(tokens.access_token).toBe('access');
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe.each([
    ['says nothing of it', {}],
    ['says it sends none', { authorization_response_iss_parameter_supported: false }],
  ])('when the provider %s', (_, metadata) => {
    it('still refuses a callback whose iss is another provider', async () => {
      await expect(
        exchange(clientFor(metadata), { iss: 'https://evil.example.test' }),
      ).rejects.toMatchObject({ code: 'OAUTH_INVALID_RESPONSE' });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('exchanges the code of a callback without iss', async () => {
      const tokens = await exchange(clientFor(metadata));

      expect(tokens.access_token).toBe('access');
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('exchanges the code of a callback whose iss is the provider', async () => {
      const tokens = await exchange(clientFor(metadata), { iss: issuer });

      expect(tokens.access_token).toBe('access');
    });
  });
});

describe.each(['ES256', 'PS256'])('the client assertion of private_key_jwt, signed with %s', (alg) => {
  let keys: CryptoKeyPair;

  beforeAll(async () => {
    keys = await generateKeyPair(alg);
  });

  /** Exchanges a code and returns the body of the token request. */
  async function tokenRequestBody(): Promise<URLSearchParams> {
    const config: OidcClientConfig = {
      issuer,
      clientId,
      clientAuth: 'private_key_jwt',
      privateKey: keys.privateKey,
      redirectUri,
      scope: 'api:read',
      serverMetadata,
    };
    await exchange(createOidcClient(config, { logger: quiet }));

    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) throw new Error('no token request was sent');
    return new URLSearchParams(init.body as URLSearchParams);
  }

  it('is sent with the code, as a JWT bearer assertion', async () => {
    const body = await tokenRequestBody();

    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(body.get('client_id')).toBe(clientId);
    expect(body.has('client_secret')).toBe(false);
  });

  it('has the issuer as its only audience, as a string', async () => {
    const claims = decodeJwt((await tokenRequestBody()).get('client_assertion') ?? '');

    // Not the token endpoint, and not a list with it.
    expect(claims.aud).toBe(issuer);
  });

  it('is signed by the client, about the client, with a jti, iat and exp', async () => {
    const before = Math.floor(Date.now() / 1000);
    const assertion = (await tokenRequestBody()).get('client_assertion') ?? '';
    const after = Math.floor(Date.now() / 1000);

    const { payload, protectedHeader } = await jwtVerify(assertion, keys.publicKey, {
      algorithms: [alg],
      issuer: clientId,
      subject: clientId,
      audience: issuer,
      requiredClaims: ['jti', 'exp', 'iat'],
    });

    expect(protectedHeader.alg).toBe(alg);
    expect(payload.jti).toEqual(expect.any(String));
    expect(payload.jti).not.toBe('');
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    expect(payload.iat).toBeLessThanOrEqual(after);
    expect(payload.exp).toBeGreaterThan(after);
    // Short-lived: a minute at most.
    expect(payload.exp! - payload.iat!).toBeLessThanOrEqual(60);
  });

  it('has a new jti for each request', async () => {
    const first = decodeJwt((await tokenRequestBody()).get('client_assertion') ?? '');
    fetchMock.mockClear();
    const second = decodeJwt((await tokenRequestBody()).get('client_assertion') ?? '');

    expect(second.jti).not.toBe(first.jti);
  });

  it('does not verify with another key', async () => {
    const assertion = (await tokenRequestBody()).get('client_assertion') ?? '';
    const other = await generateKeyPair(alg);

    expect(decodeProtectedHeader(assertion).alg).toBe(alg);
    await expect(jwtVerify(assertion, other.publicKey)).rejects.toThrow();
  });
});
