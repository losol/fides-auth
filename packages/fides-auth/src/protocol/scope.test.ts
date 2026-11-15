/**
 * Tests that an array scope reaches the wire as one space-separated string.
 * Authorize and PAR are covered in authorization-parameters.test.ts and
 * authorization-url.par.test.ts. A refresh sends no scope (client.test.ts).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(),
  buildAuthorizationUrl: vi.fn(),
  ClientSecretPost: vi.fn(() => () => undefined),
}));

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import { createOidcClient } from './client.js';
import { joinScope } from './scope.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };
const discovered = { serverMetadata: () => ({}) } as unknown as openid.Configuration;

function clientWith(scope: string | string[]) {
  return createOidcClient(
    {
      issuer: 'https://auth.example.com',
      clientId: 'test-client',
      clientSecret: 'test-secret',
      redirectUri: 'https://app.example.com/callback',
      scope,
    },
    { logger: quiet },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(openid.discovery).mockResolvedValue(discovered);
  vi.mocked(openid.buildAuthorizationUrl).mockReturnValue(new URL('https://auth.example.com/authorize'));
});

describe('joinScope', () => {
  it('joins an array with spaces and leaves a string as is', () => {
    expect(joinScope(['openid', 'profile', 'offline_access'])).toBe('openid profile offline_access');
    expect(joinScope('openid profile')).toBe('openid profile');
  });
});

describe('OidcClient.silentLoginUrl', () => {
  it('sends an array scope as a space-separated string', async () => {
    const client = clientWith(['openid', 'profile']);
    await client.silentLoginUrl(await client.createAuthorizationRequest());

    expect(openid.buildAuthorizationUrl).toHaveBeenCalledWith(
      discovered,
      expect.objectContaining({ scope: 'openid profile', prompt: 'none' }),
    );
  });
});
