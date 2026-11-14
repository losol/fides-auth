/**
 * Tests for the Vipps client: scope handling, extra parameters, and the
 * userinfo call with Vipps' headers.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../../shared/logger.js';
import { VippsLoginClient } from './client.js';
import { defaultVippsLoginScope } from './types.js';

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

    const user = await client.getUserInfo('access-token');

    expect(user).toEqual({ sub: 'u-1', email: 'ada@example.com' });
    const [url, init] = fetchMock.mock.calls.at(-1) ?? [];
    expect(url).toBe('https://auth.example.com/userinfo');
    expect(init?.headers).toEqual({
      Authorization: 'Bearer access-token',
      'Ocp-Apim-Subscription-Key': 'sub-key',
      'Merchant-Serial-Number': '123456',
    });
  });

  it('throws on a non-2xx answer', async () => {
    provider(() => new Response('nope', { status: 401 }));
    const client = new VippsLoginClient(baseConfig, { logger: quiet });

    await expect(client.getUserInfo('access-token')).rejects.toThrow('Failed to fetch user info: 401');
  });
});
