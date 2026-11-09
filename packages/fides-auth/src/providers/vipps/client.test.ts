/**
 * Tests for the provider client's PKCE options: scope handling and extra parameters.
 */
import { describe, expect, it } from 'vitest';

import { VippsLoginClient } from './client';
import { defaultVippsLoginScope } from './types';

const baseConfig = {
  issuer: 'https://auth.example.com/',
  clientId: 'test-client',
  clientSecret: 'test-secret',
  redirectUri: 'https://app.example.com/callback',
};

describe('VippsLoginClient.buildPKCEOptions', () => {
  it('uses the default scope', async () => {
    const pkce = await new VippsLoginClient(baseConfig).buildPKCEOptions();

    expect(pkce.parameters.scope).toBe(defaultVippsLoginScope);
  });

  it('joins an array scope with spaces', async () => {
    const client = new VippsLoginClient({ ...baseConfig, scope: ['openid', 'name'] });

    expect((await client.buildPKCEOptions()).parameters.scope).toBe('openid name');
  });

  it('passes extra authorization parameters through', async () => {
    const pkce = await new VippsLoginClient(baseConfig).buildPKCEOptions({
      parameters: { prompt: 'login' },
    });

    expect(pkce.parameters.prompt).toBe('login');
  });
});
