/**
 * Tests for the heartbeat handler.
 *
 * The handler is glue: method check → rate-limit → refresh → respond. We mock
 * the session helper so the tests focus on the handler's branching and response
 * shape, not the OAuth machinery (tested elsewhere).
 *
 * The 401-vs-503 split gets the most attention here: a 401 tells the client to
 * log the user out, so anything that answers 401 when the session was actually
 * fine is a user-visible bug.
 */
import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('./session', () => ({
  tryRefreshSessionInStore: vi.fn(),
}));

import { handleHeartbeat } from './heartbeat-handler';
import { tryRefreshSessionInStore } from './session';
import type { CookieStore } from './cookie-store';

const mockedRefresh = vi.mocked(tryRefreshSessionInStore);

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
    expect(mockedRefresh).not.toHaveBeenCalled();
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
    expect(mockedRefresh).not.toHaveBeenCalled();
  });
});

describe('handleHeartbeat — session is over (401)', () => {
  // Every one of these ends with the user at a login screen, so the reason has
  // to travel to the client that renders it.
  it.each([
    ['no_session_cookie'],
    ['unreadable_session'],
    ['stale_legacy_session'],
    ['no_refresh_token'],
  ] as const)('returns 401 with reason=%s in the body', async (reason) => {
    mockedRefresh.mockResolvedValue({ ok: false, reason });

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ reason });
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
  });

  it('returns 401 when the provider says the refresh token is dead', async () => {
    mockedRefresh.mockResolvedValue({
      ok: false,
      reason: 'refresh_failed',
      cause: 'invalid_grant',
    });

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ reason: 'refresh_failed' });
  });
});

describe('handleHeartbeat — provider unreachable (503)', () => {
  // The regression that matters: these used to answer 401, which logged out
  // users whose sessions were perfectly valid.
  it.each([['transport'], ['idp_error']] as const)(
    'returns 503, not 401, when cause=%s',
    async (cause) => {
      mockedRefresh.mockResolvedValue({ ok: false, reason: 'refresh_failed', cause });

      const response = await handleHeartbeat(makeRequest('POST'), config);

      expect(response.status).toBe(503);
      expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    },
  );
});

describe('handleHeartbeat — success', () => {
  it('returns 200 with accessTokenExpiresAt and no-store Cache-Control', async () => {
    const expiresAt = new Date('2026-05-21T20:00:00.000Z').toISOString();
    mockedRefresh.mockResolvedValue({
      ok: true,
      rotatedRefreshToken: true,
      session: {
        tokens: { accessToken: 'new-access', refreshToken: 'new-refresh', accessTokenExpiresAt: expiresAt },
      },
    });

    const response = await handleHeartbeat(makeRequest('POST'), config);

    expect(response.status).toBe(200);
    // Auth/session endpoints must never be cached by browser or intermediaries.
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    expect(await response.json()).toMatchObject({ accessTokenExpiresAt: expiresAt });
    expect(mockedRefresh).toHaveBeenCalledWith(noopStore, config.oauthConfig, config.secret);
  });

  it('returns accessTokenExpiresAt: null when the refreshed session has no expiry', async () => {
    mockedRefresh.mockResolvedValue({
      ok: true,
      rotatedRefreshToken: false,
      session: { tokens: { accessToken: 'new', refreshToken: 'newR' } },
    });

    const response = await handleHeartbeat(makeRequest('POST'), config);
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.accessTokenExpiresAt).toBeNull();
  });
});
