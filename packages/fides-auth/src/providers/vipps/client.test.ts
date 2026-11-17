/**
 * Tests for the Vipps client: scope handling, extra parameters, and the
 * userinfo call with Vipps' headers.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../../shared/logger.js';
import { VippsLoginClient } from './client.js';
import { defaultVippsLoginScope, getVippsIssuer, VippsEnvironments } from './types.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };

const baseConfig = {
  issuer: 'https://auth.example.com/',
  clientId: 'test-client',
  clientSecret: 'test-secret',
  redirectUri: 'https://app.example.com/callback',
};

const serverMetadata = {
  issuer: 'https://auth.example.com/',
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/token',
  userinfo_endpoint: 'https://auth.example.com/userinfo',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('getVippsIssuer', () => {
  it('gives the issuer under an environment\'s address, with its trailing slash', () => {
    expect(getVippsIssuer(VippsEnvironments.Production)).toBe('https://api.vipps.no/access-management-1.0/access/');
    expect(getVippsIssuer(VippsEnvironments.Test)).toBe('https://apitest.vipps.no/access-management-1.0/access/');
  });

  it('is what the client takes for an issuer: an environment alone is another URL', () => {
    expect(getVippsIssuer(VippsEnvironments.Production)).not.toBe(VippsEnvironments.Production);
  });
});

describe('VippsLoginClient.createAuthorizationRequest', () => {
  it('uses the default scope', async () => {
    const request = await new VippsLoginClient(baseConfig, { logger: quiet }).createAuthorizationRequest();

    expect(request.parameters.scope).toBe(defaultVippsLoginScope);
  });

  it('joins an array scope with spaces', async () => {
    const client = new VippsLoginClient({ ...baseConfig, scope: ['openid', 'name'] }, { logger: quiet });

    expect((await client.createAuthorizationRequest()).parameters.scope).toBe('openid name');
  });

  it('passes extra authorization parameters through', async () => {
    const request = await new VippsLoginClient(baseConfig, { logger: quiet }).createAuthorizationRequest({
      parameters: { prompt: 'login' },
    });

    expect(request.parameters.prompt).toBe('login');
  });
});

/** Answers discovery with `serverMetadata`, and the userinfo endpoint with `userinfo`. */
function provider(userinfo: () => Response) {
  const fetchMock = vi.fn(async (url: string | URL | Request, _init?: RequestInit) =>
    String(url).endsWith('/.well-known/openid-configuration') ? Response.json(serverMetadata) : userinfo(),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('VippsLoginClient.getUserInfo', () => {
  it('sends the subscription key and merchant serial number', async () => {
    const fetchMock = provider(() => Response.json({ sub: 'u-1', email: 'ada@example.com' }));
    const client = new VippsLoginClient(
      { ...baseConfig, subscriptionKey: 'sub-key', merchantSerialNumber: '123456' },
      { logger: quiet },
    );

    const user = await client.getUserInfo('access-token', { expectedSubject: 'u-1' });

    expect(user).toEqual({ sub: 'u-1', email: 'ada@example.com' });
    const [url, init] = fetchMock.mock.calls.at(-1) ?? [];
    expect(url).toBe('https://auth.example.com/userinfo');
    expect(init?.headers).toEqual({
      Authorization: 'Bearer access-token',
      'Ocp-Apim-Subscription-Key': 'sub-key',
      'Merchant-Serial-Number': '123456',
    });
  });

  it('refuses redirects and has a timeout', async () => {
    const fetchMock = provider(() => Response.json({ sub: 'u-1' }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    await client.getUserInfo('access-token', { expectedSubject: 'u-1' });

    const [, init] = fetchMock.mock.calls.at(-1) ?? [];
    expect(init?.redirect).toBe('error');
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it('rejects an answer for another subject, without naming either', async () => {
    provider(() => Response.json({ sub: 'other-sub-999' }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    const error = await client
      .getUserInfo('access-token', { expectedSubject: 'expected-sub-123' })
      .catch((e: Error) => e);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain('another subject');
    expect((error as Error).message).not.toContain('other-sub-999');
    expect((error as Error).message).not.toContain('expected-sub-123');
  });

  it('rejects an answer without a string sub', async () => {
    provider(() => Response.json({ sub: 42 }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    await expect(client.getUserInfo('access-token', { expectedSubject: '42' })).rejects.toThrow('another subject');
  });

  it.each([
    ['missing', undefined],
    ['empty', ''],
  ])('rejects a %s expectedSubject with a TypeError, before any request', async (_name, expectedSubject) => {
    const fetchMock = provider(() => Response.json({ sub: 'u-1' }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    await expect(
      client.getUserInfo('access-token', { expectedSubject } as unknown as { expectedSubject: string }),
    ).rejects.toThrow(TypeError);
    await expect(client.getUserInfo('access-token', undefined as never)).rejects.toThrow(TypeError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws on a non-2xx answer', async () => {
    provider(() => new Response('nope', { status: 401 }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    await expect(client.getUserInfo('access-token', { expectedSubject: 'u-1' })).rejects.toThrow('Failed to fetch user info: 401');
  });

  it('keeps the response body out of the error', async () => {
    provider(() => new Response('secret-detail', { status: 500 }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    const error = await client.getUserInfo('access-token', { expectedSubject: 'u-1' }).catch((e: Error) => e);

    expect((error as Error).message).toContain('500');
    expect((error as Error).message).not.toContain('secret-detail');
  });
});
