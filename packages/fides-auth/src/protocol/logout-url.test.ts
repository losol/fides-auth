/**
 * Tests for RP-initiated logout URL construction (OIDC RP-Initiated Logout 1.0).
 *
 * openid-client is mocked; we assert on the parameters that end up on the URL.
 *
 * If these tests fail, run from the repo root:
 *   pnpm --filter @eventuras/fides-auth test
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  buildEndSessionUrl: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient } from './client.js';
import type { OidcClientConfig } from './config.js';
import type { OidcLogoutOptions } from './logout-url.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };

const oauthConfig: OidcClientConfig = {
  issuer: 'https://auth.example.com',
  clientId: 'test-client',
  clientSecret: 'test-secret',
  redirectUri: 'https://app.example.com/callback',
  scope: 'openid profile email',
};

/** The logout URL from a new client, so each case discovers afresh. */
const logoutUrl = (options: OidcLogoutOptions) =>
  createOidcClient(oauthConfig, { logger: quiet }).logoutUrl(options);

function mockDiscovery(endSessionEndpoint?: string) {
  vi.mocked(openid.discovery).mockResolvedValue({
    serverMetadata: () => ({ end_session_endpoint: endSessionEndpoint }),
  } as unknown as openid.Configuration);
}

// Mirrors openid-client 6.8: client_id only when the caller didn't supply one, and
// every parameter appended to whatever the endpoint URL already carries.
function mockEndSessionUrl(endpoint: string) {
  vi.mocked(openid.buildEndSessionUrl).mockImplementation((_config, parameters) => {
    const params = new URLSearchParams(parameters as Record<string, string>);
    if (!params.has('client_id')) {
      params.set('client_id', oauthConfig.clientId);
    }
    const url = new URL(endpoint);
    for (const [key, value] of params.entries()) {
      url.searchParams.append(key, value);
    }
    return url;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockDiscovery('https://auth.example.com/connect/logout');
  mockEndSessionUrl('https://auth.example.com/connect/logout');
});

describe('OidcClient.logoutUrl', () => {
  it('sends id_token_hint alongside post_logout_redirect_uri', async () => {
    const url = await logoutUrl({
      postLogoutRedirectUri: 'https://app.example.com/',
      idTokenHint: 'the-id-token',
    });

    expect(url?.searchParams.get('id_token_hint')).toBe('the-id-token');
    expect(url?.searchParams.get('post_logout_redirect_uri')).toBe('https://app.example.com/');
  });

  it('keeps client_id when id_token_hint is present — the spec allows both', async () => {
    const url = await logoutUrl({
      postLogoutRedirectUri: 'https://app.example.com/',
      idTokenHint: 'the-id-token',
    });

    expect(url?.searchParams.get('client_id')).toBe('test-client');
  });

  it('drops client_id only when includeClientId is false', async () => {
    const url = await logoutUrl({
      idTokenHint: 'the-id-token',
      includeClientId: false,
    });

    expect(url?.searchParams.has('client_id')).toBe(false);
    expect(url?.searchParams.get('id_token_hint')).toBe('the-id-token');
  });

  it('keeps a client_id the provider baked into its own endpoint', async () => {
    const endpoint = 'https://auth.example.com/connect/logout?client_id=tenant-a';
    mockDiscovery(endpoint);
    mockEndSessionUrl(endpoint);

    const url = await logoutUrl({
      idTokenHint: 'the-id-token',
      includeClientId: false,
    });

    expect(url?.searchParams.getAll('client_id')).toEqual(['tenant-a']);
  });

  it('passes state and logout_hint through when supplied', async () => {
    const url = await logoutUrl({
      postLogoutRedirectUri: 'https://app.example.com/',
      state: 'correlation-123',
      logoutHint: 'ola@example.com',
    });

    expect(url?.searchParams.get('state')).toBe('correlation-123');
    expect(url?.searchParams.get('logout_hint')).toBe('ola@example.com');
  });

  it('omits parameters that were not supplied', async () => {
    const url = await logoutUrl({
      postLogoutRedirectUri: 'https://app.example.com/',
    });

    expect(url?.searchParams.has('id_token_hint')).toBe(false);
    expect(url?.searchParams.has('state')).toBe(false);
    expect(url?.searchParams.has('logout_hint')).toBe(false);
  });

  it('returns null when the provider advertises no end_session_endpoint', async () => {
    mockDiscovery(undefined);
    expect(await logoutUrl({ idTokenHint: 'x' })).toBeNull();
    expect(openid.buildEndSessionUrl).not.toHaveBeenCalled();
  });

  it('returns null when discovery fails', async () => {
    vi.mocked(openid.discovery).mockRejectedValue(new Error('unreachable'));
    expect(await logoutUrl({ postLogoutRedirectUri: 'https://app.example.com/' })).toBeNull();
  });

  it('refuses a non-https end_session_endpoint on the manual branch', async () => {
    mockDiscovery('http://auth.example.com/connect/logout');

    const url = await logoutUrl({
      idTokenHint: 'the-id-token',
      includeClientId: false,
    });

    expect(url).toBeNull();
  });
});
