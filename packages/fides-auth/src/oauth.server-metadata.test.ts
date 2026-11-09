/**
 * Tests for `serverMetadata` with the real openid-client and a mocked `fetch`:
 * no discovery request is made, and `clientAuth` still applies.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { refreshAccessToken } from './oauth';
import { clearDiscoveryCache } from './oidc-discovery';

const issuer = 'https://auth.example.test';
const tokenEndpoint = `${issuer}/oauth/token`;

const fetchMock = vi.fn(async (input: string | URL | Request, _init?: RequestInit) =>
  String(input) === tokenEndpoint
    ? new Response(JSON.stringify({ access_token: 'access', token_type: 'bearer' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    : new Response('not found', { status: 404 }),
);

beforeEach(() => {
  fetchMock.mockClear();
  vi.stubGlobal('fetch', fetchMock);
  clearDiscoveryCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('serverMetadata', () => {
  it('sends the token request without a discovery request', async () => {
    const tokens = await refreshAccessToken(
      {
        issuer,
        clientId: 'client-a',
        clientAuth: 'client_secret_basic',
        clientSecret: 'secret-a',
        redirect_uri: 'https://app.example.test/callback',
        scope: 'openid',
        serverMetadata: { issuer, token_endpoint: tokenEndpoint },
      },
      'refresh-token',
    );

    expect(tokens.access_token).toBe('access');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(tokenEndpoint);
    expect(new Headers(init?.headers).get('authorization')).toMatch(/^Basic /);
  });
});
