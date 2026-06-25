/**
 * Tests for the heartbeat handler.
 *
 * The handler is glue: method check → rate-limit → load session → refresh →
 * respond. We mock the session helpers so the tests focus on the handler's
 * branching and response shape, not the OAuth machinery (tested elsewhere).
 */
import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('./session', () => ({
  readSession: vi.fn(),
  refreshSessionInStore: vi.fn(),
}));

import { handleHeartbeat } from './heartbeat-handler';
import { readSession, refreshSessionInStore } from './session';
import type { CookieStore } from './cookie-store';

const mockedReadSession = vi.mocked(readSession);
const mockedRefresh = vi.mocked(refreshSessionInStore);

const noopStore: CookieStore = {
  get: () => null,
  set: () => undefined,
  delete: () => undefined,
};

const config = {
  oauthConfig: {
    issuer: 'https://example.test',
    clientId: 'test',
    clientSecret: 'shh',
    redirect_uri: 'https://app.test/callback',
    scope: 'openid',
  },
  cookies: noopStore,
  rateLimit: vi.fn(async () => true),
  secret: 'a'.repeat(64),
};

const makeRequest = (method: string): Request =>
  new Request('https://app.test/api/auth/heartbeat', { method });

beforeEach(() => {
  vi.clearAllMocks();
  config.rateLimit.mockResolvedValue(true);
});

describe('handleHeartbeat — method handling', () => {
  it('returns 405 with Allow header for non-POST requests', async () => {
    const response = await handleHeartbeat(makeRequest('GET'), config);

    expect(response.status).toBe(405);
    expect(response.headers.get('Allow')).toBe('POST');
    // Pre-condition: never hit rate-limit or session lookup on a method reject.
    expect(config.rateLimit).not.toHaveBeenCalled();
    expect(mockedReadSession).not.toHaveBeenCalled();
  });

  it('returns 405 for PUT, DELETE, PATCH too', async () => {
    for (const method of ['PUT', 'DELETE', 'PATCH']) {
      const response = await handleHeartbeat(makeRequest(method), config);
      expect(response.status, `method ${method}`).toBe(405);
    }
  });
});

describe('handleHeartbeat — rate limiting', () => {
  it('returns 429 when the rate-limit denies the request', async () => {
    config.rateLimit.mockResolvedValue(false);

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(429);
    expect(mockedReadSession).not.toHaveBeenCalled();
  });
});

describe('handleHeartbeat — authentication', () => {
  it('returns 401 when there is no current session', async () => {
    mockedReadSession.mockResolvedValue(null);

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(401);
    expect(mockedRefresh).not.toHaveBeenCalled();
  });

  it('returns 401 when session exists but has no refresh token', async () => {
    mockedReadSession.mockResolvedValue({ tokens: { accessToken: 'access-only' } } as any);

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(401);
    expect(mockedRefresh).not.toHaveBeenCalled();
  });

  it('returns 401 when the refresh returns null (refresh failed)', async () => {
    mockedReadSession.mockResolvedValue({ tokens: { accessToken: 'a', refreshToken: 'r' } } as any);
    mockedRefresh.mockResolvedValue(null);

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(401);
    expect(mockedRefresh).toHaveBeenCalledWith(noopStore, config.oauthConfig, config.secret);
  });
});

describe('handleHeartbeat — success', () => {
  it('returns 200 with accessTokenExpiresAt and no-store Cache-Control', async () => {
    const expiresAt = new Date('2026-05-21T20:00:00.000Z').toISOString();
    mockedReadSession.mockResolvedValue({ tokens: { accessToken: 'a', refreshToken: 'r' } } as any);
    mockedRefresh.mockResolvedValue({
      tokens: { accessToken: 'new-access', refreshToken: 'new-refresh', accessTokenExpiresAt: expiresAt },
    } as any);

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(200);
    // Auth/session endpoints must never be cached by browser or intermediaries.
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    expect(await response.json()).toMatchObject({ accessTokenExpiresAt: expiresAt });
  });

  it('returns accessTokenExpiresAt: null when the refreshed session has no expiry', async () => {
    mockedReadSession.mockResolvedValue({ tokens: { accessToken: 'a', refreshToken: 'r' } } as any);
    mockedRefresh.mockResolvedValue({ tokens: { accessToken: 'new', refreshToken: 'newR' } } as any);

    const response = await handleHeartbeat(makeRequest('POST'), config);
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.accessTokenExpiresAt).toBeNull();
  });
});
