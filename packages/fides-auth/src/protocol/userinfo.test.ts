/**
 * Tests for the UserInfo call: it reaches openid-client with the configuration,
 * the access token and the expected subject, and it logs neither token nor claims.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('openid-client', () => ({
  fetchUserInfo: vi.fn(),
  getDPoPHandle: vi.fn(),
}));

import * as openid from 'openid-client';

import type { FidesLogger } from '../shared/logger.js';
import type { OidcClientConfig } from './config.js';
import type { ProtocolContext } from './context.js';
import { createDpopKey } from './dpop.js';
import { userInfo } from './userinfo.js';

const issuer = 'https://auth.example.test';
const configuration = { serverMetadata: () => ({ issuer }) } as unknown as openid.Configuration;

const config: OidcClientConfig = {
  issuer,
  clientId: 'client-a',
  clientSecret: 'secret-a',
  scope: 'openid profile',
};

/** A context that records everything its logger is given. */
function contextWithLog(): { context: ProtocolContext; logged: unknown[] } {
  const logged: unknown[] = [];
  const log = (...args: unknown[]) => void logged.push(args);
  const logger: FidesLogger = { debug: log, info: log, warn: log, error: log };
  return { context: { config, configuration: async () => configuration, logger }, logged };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('userInfo', () => {
  it('asks openid-client for the claims, with the token and the expected subject', async () => {
    const { context } = contextWithLog();
    vi.mocked(openid.fetchUserInfo).mockResolvedValue({ sub: 'user-1' });

    await userInfo(context, 'access-token', { expectedSubject: 'user-1' });

    expect(openid.fetchUserInfo).toHaveBeenCalledWith(configuration, 'access-token', 'user-1');
  });

  it('sends a DPoP proof with a bound token, from the key it is bound to', async () => {
    const { context } = contextWithLog();
    const handle = { handle: true };
    vi.mocked(openid.getDPoPHandle).mockReturnValue(handle as never);
    vi.mocked(openid.fetchUserInfo).mockResolvedValue({ sub: 'user-1' });
    const dpopKey = await createDpopKey();

    await userInfo(context, 'access-token', { expectedSubject: 'user-1', dpopKey });

    expect(openid.fetchUserInfo).toHaveBeenCalledWith(configuration, 'access-token', 'user-1', { DPoP: handle });
    const [, keyPair] = vi.mocked(openid.getDPoPHandle).mock.calls[0] ?? [];
    expect((keyPair as CryptoKeyPair).privateKey.extractable).toBe(false);
  });

  it('returns what openid-client returns', async () => {
    const { context } = contextWithLog();
    const claims = { sub: 'user-1', email: 'user@example.test' };
    vi.mocked(openid.fetchUserInfo).mockResolvedValue(claims);

    expect(await userInfo(context, 'access-token', { expectedSubject: 'user-1' })).toBe(claims);
  });

  it('throws what openid-client throws', async () => {
    const { context } = contextWithLog();
    vi.mocked(openid.fetchUserInfo).mockRejectedValue(new Error('unexpected JSON attribute value'));

    await expect(userInfo(context, 'access-token', { expectedSubject: 'user-2' })).rejects.toThrow(
      'unexpected JSON attribute value',
    );
  });

  it('logs neither the token nor the claims', async () => {
    const { context, logged } = contextWithLog();
    vi.mocked(openid.fetchUserInfo).mockResolvedValue({ sub: 'user-1', email: 'user@example.test' });

    await userInfo(context, 'access-token', { expectedSubject: 'user-1' });

    expect(logged.length).toBeGreaterThan(0);
    const text = JSON.stringify(logged);
    expect(text).not.toContain('access-token');
    expect(text).not.toContain('user@example.test');
  });
});
