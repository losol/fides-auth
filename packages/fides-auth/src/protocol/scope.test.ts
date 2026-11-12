/**
 * Tests that an array `OAuthConfig.scope` reaches the wire as one space-separated string.
 * Authorize and PAR are covered in oauth.build-pkce-options.test.ts and oauth.par.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  refreshTokenGrant: vi.fn(),
  buildAuthorizationUrl: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import { joinScope, refreshAccessToken, type OAuthConfig } from './oauth.js';
import { getOAuthConfigLogContext } from './oauth-logging.js';
import { clearDiscoveryCache } from './oidc-discovery.js';
import { buildSilentLoginUrl } from './silent-login.js';

const discovered = {} as openid.Configuration;

function makeConfig(scope: string | string[]): OAuthConfig {
  return {
    issuer: 'https://auth.example.com',
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirect_uri: 'https://app.example.com/callback',
    scope,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  clearDiscoveryCache();
  vi.mocked(openid.discovery).mockResolvedValue(discovered);
  vi.mocked(openid.refreshTokenGrant).mockResolvedValue({
    access_token: 'access',
    token_type: 'bearer',
  } as unknown as openid.TokenEndpointResponse);
  vi.mocked(openid.buildAuthorizationUrl).mockReturnValue(new URL('https://auth.example.com/authorize'));
});

describe('joinScope', () => {
  it('joins an array with spaces and leaves a string as is', () => {
    expect(joinScope(['openid', 'profile', 'offline_access'])).toBe('openid profile offline_access');
    expect(joinScope('openid profile')).toBe('openid profile');
  });
});

describe('refreshAccessToken', () => {
  it('sends an array scope as a space-separated string', async () => {
    await refreshAccessToken(makeConfig(['openid', 'offline_access']), 'refresh-token');

    expect(openid.refreshTokenGrant).toHaveBeenCalledWith(discovered, 'refresh-token', {
      scope: 'openid offline_access',
    });
  });

  it('sends a string scope unchanged', async () => {
    await refreshAccessToken(makeConfig('openid offline_access'), 'refresh-token');

    expect(openid.refreshTokenGrant).toHaveBeenCalledWith(discovered, 'refresh-token', {
      scope: 'openid offline_access',
    });
  });
});

describe('buildSilentLoginUrl', () => {
  it('sends an array scope as a space-separated string', async () => {
    await buildSilentLoginUrl(makeConfig(['openid', 'profile']));

    expect(openid.buildAuthorizationUrl).toHaveBeenCalledWith(
      discovered,
      expect.objectContaining({ scope: 'openid profile', prompt: 'none' }),
    );
  });
});

describe('getOAuthConfigLogContext', () => {
  it('logs an array scope as a space-separated string', () => {
    expect(getOAuthConfigLogContext(makeConfig(['openid', 'profile'])).scope).toBe('openid profile');
  });
});
