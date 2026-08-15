/**
 * Tests that a refresh keeps an ID token available for `id_token_hint` on logout.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('./oauth', () => ({ refreshAccessToken: vi.fn() }));

import { refreshSession } from './session-refresh';
import { refreshAccessToken } from './oauth';
import type { OAuthConfig } from './oauth';
import type { Session } from './types';

const mockedRefresh = vi.mocked(refreshAccessToken);

const config: OAuthConfig = {
  issuer: 'https://id.example.test',
  clientId: 'web',
  clientSecret: 'shh',
  redirect_uri: 'https://app.example.test/callback',
  scope: 'openid',
};

const session = (idToken?: string): Session => ({
  tokens: { accessToken: 'old-access', refreshToken: 'old-refresh', idToken },
  user: { name: 'Ada', email: 'ada@example.test' },
});

beforeEach(() => vi.clearAllMocks());

describe('refreshSession — id token', () => {
  it('takes the new ID token when the response carries one', async () => {
    mockedRefresh.mockResolvedValue({ access_token: 'new', id_token: 'new-id' } as never);

    const updated = await refreshSession(session('old-id'), config);

    expect(updated?.tokens?.idToken).toBe('new-id');
  });

  it('keeps the existing ID token when the response carries none', async () => {
    mockedRefresh.mockResolvedValue({ access_token: 'new' } as never);

    const updated = await refreshSession(session('old-id'), config);

    expect(updated?.tokens?.idToken).toBe('old-id');
  });
});
