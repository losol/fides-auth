/**
 * Tests for `verifyIdToken` with real keys and a JWKS served by a mocked `fetch`.
 */
import { exportJWK, generateKeyPair, type JWK, SignJWT, UnsecuredJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { clearJwksCache, verifyIdToken } from './id-token.js';
import type { OAuthConfig } from './oauth.js';
import { clearDiscoveryCache } from './oidc-discovery.js';

const issuer = 'https://auth.example.test';
const jwksUri = `${issuer}/jwks`;
const audience = 'client-a';

let key1: CryptoKey;
let key2: CryptoKey;
let jwk1: JWK;
let jwk2: JWK;

/** What the mocked `fetch` serves, by URL. */
let routes: Record<string, unknown> = {};

const fetchMock = vi.fn(async (input: string | URL | Request, _init?: RequestInit) => {
  const body = routes[String(input)];
  return body === undefined
    ? new Response('not found', { status: 404 })
    : new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
});

async function publicJwk(publicKey: CryptoKey, kid: string): Promise<JWK> {
  return { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
}

interface SignOptions {
  key?: CryptoKey;
  kid?: string;
  iss?: string;
  aud?: string;
  exp?: string | number | null;
}

function sign(options: SignOptions = {}): Promise<string> {
  const jwt = new SignJWT({ sub: 'user-1', roles: ['admin'] })
    .setProtectedHeader({ alg: 'RS256', kid: options.kid ?? 'key-1' })
    .setIssuer(options.iss ?? issuer)
    .setAudience(options.aud ?? audience)
    .setIssuedAt();
  if (options.exp !== null) jwt.setExpirationTime(options.exp ?? '5m');
  return jwt.sign(options.key ?? key1);
}

function jwksCalls(uri = jwksUri): number {
  return fetchMock.mock.calls.filter(([input]) => String(input) === uri).length;
}

beforeAll(async () => {
  const pair1 = await generateKeyPair('RS256');
  const pair2 = await generateKeyPair('RS256');
  key1 = pair1.privateKey;
  key2 = pair2.privateKey;
  jwk1 = await publicJwk(pair1.publicKey, 'key-1');
  jwk2 = await publicJwk(pair2.publicKey, 'key-2');
});

beforeEach(() => {
  routes = { [jwksUri]: { keys: [jwk1] } };
  fetchMock.mockClear();
  vi.stubGlobal('fetch', fetchMock);
  clearJwksCache();
  clearDiscoveryCache();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('verifyIdToken', () => {
  it('returns the claims of a valid token', async () => {
    const claims = await verifyIdToken(await sign(), { issuer, audience, jwksUri });

    expect(claims).toMatchObject({ iss: issuer, aud: audience, sub: 'user-1', roles: ['admin'] });
    expect(jwksCalls()).toBe(1);
  });

  it('reuses the JWKS for the same URI', async () => {
    const token = await sign();
    await verifyIdToken(token, { issuer, audience, jwksUri });
    await verifyIdToken(token, { issuer, audience, jwksUri: new URL(jwksUri) });

    expect(jwksCalls()).toBe(1);
  });

  it('rejects an expired token', async () => {
    const token = await sign({ exp: Math.floor(Date.now() / 1000) - 60 });

    await expect(verifyIdToken(token, { issuer, audience, jwksUri })).rejects.toMatchObject({
      code: 'ERR_JWT_EXPIRED',
    });
  });

  it('rejects a token without exp', async () => {
    const token = await sign({ exp: null });

    await expect(verifyIdToken(token, { issuer, audience, jwksUri })).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'exp',
    });
  });

  it('rejects the wrong issuer', async () => {
    const token = await sign({ iss: 'https://other.example.test' });

    await expect(verifyIdToken(token, { issuer, audience, jwksUri })).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'iss',
    });
  });

  it('rejects the wrong audience', async () => {
    const token = await sign({ aud: 'client-b' });

    await expect(verifyIdToken(token, { issuer, audience, jwksUri })).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'aud',
    });
  });

  it('rejects HS256', async () => {
    const token = await new SignJWT({ sub: 'user-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode('a-shared-secret-of-at-least-32-bytes'));

    await expect(verifyIdToken(token, { issuer, audience, jwksUri })).rejects.toMatchObject({
      code: 'ERR_JOSE_ALG_NOT_ALLOWED',
    });
  });

  it('rejects alg none', async () => {
    const token = new UnsecuredJWT({ sub: 'user-1' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .encode();

    await expect(verifyIdToken(token, { issuer, audience, jwksUri })).rejects.toMatchObject({
      code: 'ERR_JOSE_ALG_NOT_ALLOWED',
    });
  });

  it('refetches the JWKS for an unknown kid', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    await verifyIdToken(await sign(), { issuer, audience, jwksUri });

    // Rotate keys, and wait out jose's 30 s refetch cooldown.
    routes[jwksUri] = { keys: [jwk1, jwk2] };
    vi.setSystemTime(Date.now() + 31_000);

    const claims = await verifyIdToken(await sign({ key: key2, kid: 'key-2' }), {
      issuer,
      audience,
      jwksUri,
    });

    expect(claims.sub).toBe('user-1');
    expect(jwksCalls()).toBe(2);
  });

  describe('with an OAuthConfig', () => {
    const metadataJwksUri = `${issuer}/oauth/keys`;
    const oauthConfig: OAuthConfig = {
      issuer,
      clientId: audience,
      clientAuth: 'none',
      redirect_uri: 'https://app.example.test/callback',
      scope: 'openid',
    };

    it('uses jwks_uri from serverMetadata', async () => {
      routes = { [metadataJwksUri]: { keys: [jwk1] } };

      const claims = await verifyIdToken(await sign(), {
        issuer,
        audience,
        oauthConfig: { ...oauthConfig, serverMetadata: { issuer, jwks_uri: metadataJwksUri } },
      });

      expect(claims.sub).toBe('user-1');
      expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([metadataJwksUri]);
    });

    it('uses jwks_uri from discovery', async () => {
      routes = {
        [`${issuer}/.well-known/openid-configuration`]: { issuer, jwks_uri: metadataJwksUri },
        [metadataJwksUri]: { keys: [jwk1] },
      };

      const claims = await verifyIdToken(await sign(), { issuer, audience, oauthConfig });

      expect(claims.sub).toBe('user-1');
      expect(jwksCalls(metadataJwksUri)).toBe(1);
    });

    it('throws when the metadata has no jwks_uri', async () => {
      await expect(
        verifyIdToken(await sign(), {
          issuer,
          audience,
          oauthConfig: { ...oauthConfig, serverMetadata: { issuer } },
        }),
      ).rejects.toThrow(TypeError);
    });
  });
});
