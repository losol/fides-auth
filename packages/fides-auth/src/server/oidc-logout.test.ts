/**
 * Tests for the RP-initiated logout handler: the ID token hint is read before the
 * cookies are cleared, and the local session is cleared regardless of the provider.
 */
import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('../oauth', () => ({ buildOidcLogoutUrl: vi.fn() }));

import { handleOidcLogout } from './oidc-logout';
import { buildOidcLogoutUrl } from '../oauth';
import { persistSession } from './session';
import type { CookieStore } from './cookie-store';
import type { Session } from '../types';

const mockedBuildLogoutUrl = vi.mocked(buildOidcLogoutUrl);
const secret = 'a'.repeat(64);

function memoryStore() {
  const jar = new Map<string, string>();
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value) => { jar.set(name, value); },
    delete: (name) => { jar.delete(name); },
  };
  return { store, jar };
}

/** Unsigned JWT with a far-future exp, so the access token reads as valid. */
function jwtWithExp(secondsFromNow: number): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ exp })}.sig`;
}

const baseConfig = (store: CookieStore) => ({
  oauthConfig: {
    issuer: 'https://id.example.test',
    clientId: 'web',
    clientSecret: 'shh',
    redirect_uri: 'https://app.example.test/api/auth/callback/oidc',
    scope: 'openid',
  },
  cookies: store,
  postLogoutRedirectUri: 'https://app.example.test/',
  secret,
});

const request = new Request('https://app.example.test/api/auth/logout', { method: 'POST' });

beforeEach(() => {
  vi.clearAllMocks();
  mockedBuildLogoutUrl.mockResolvedValue(new URL('https://id.example.test/connect/logout'));
});

async function storeWithSession(idToken?: string, accessTokenTtl = 3600) {
  const { store, jar } = memoryStore();
  const session: Session = {
    tokens: { accessToken: jwtWithExp(accessTokenTtl), refreshToken: 'r', idToken },
    user: { name: 'Ada', email: 'ada@example.test' },
  };
  await persistSession(store, session, secret);
  return { store, jar };
}

describe('handleOidcLogout', () => {
  it('passes the session ID token as the hint', async () => {
    const { store } = await storeWithSession('the-id-token');

    await handleOidcLogout(request, baseConfig(store));

    expect(mockedBuildLogoutUrl).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        idTokenHint: 'the-id-token',
        postLogoutRedirectUri: 'https://app.example.test/',
      }),
    );
  });

  it('clears the session cookies and redirects to the provider', async () => {
    const { store, jar } = await storeWithSession('the-id-token');

    const response = await handleOidcLogout(request, baseConfig(store));

    expect(jar.size).toBe(0);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://id.example.test/connect/logout');
  });

  it('still clears cookies and redirects locally when there is no end_session_endpoint', async () => {
    mockedBuildLogoutUrl.mockResolvedValue(null);
    const { store, jar } = await storeWithSession('the-id-token');

    const response = await handleOidcLogout(request, {
      ...baseConfig(store),
      fallbackRedirectUri: 'https://app.example.test/logged-out',
    });

    expect(jar.size).toBe(0);
    expect(response.headers.get('Location')).toBe('https://app.example.test/logged-out');
  });

  it('logs out without a hint when there is no session', async () => {
    const { store } = memoryStore();

    const response = await handleOidcLogout(request, baseConfig(store));

    expect(mockedBuildLogoutUrl).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ idTokenHint: undefined }),
    );
    expect(response.status).toBe(302);
  });

  it('responds 429 without touching cookies when rate limited', async () => {
    const { store, jar } = await storeWithSession('the-id-token');

    const response = await handleOidcLogout(request, {
      ...baseConfig(store),
      rateLimit: () => false,
    });

    expect(response.status).toBe(429);
    expect(jar.size).toBeGreaterThan(0);
    expect(mockedBuildLogoutUrl).not.toHaveBeenCalled();
  });

  it('sends the hint even after the access token has expired', async () => {
    // readSession returns null here — the hint has to come from its own cookie.
    const { store } = await storeWithSession('the-id-token', -60);

    await handleOidcLogout(request, baseConfig(store));

    expect(mockedBuildLogoutUrl).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ idTokenHint: 'the-id-token' }),
    );
  });

  it('rejects GET by default so a forced navigation cannot log the user out', async () => {
    const { store, jar } = await storeWithSession('the-id-token');
    const get = new Request('https://app.example.test/api/auth/logout');

    const response = await handleOidcLogout(get, baseConfig(store));

    expect(response.status).toBe(405);
    expect(response.headers.get('Allow')).toBe('POST');
    expect(jar.size).toBeGreaterThan(0);
  });

  it('accepts GET when the app opts in', async () => {
    const { store, jar } = await storeWithSession('the-id-token');
    const get = new Request('https://app.example.test/api/auth/logout');

    const response = await handleOidcLogout(get, {
      ...baseConfig(store),
      allowedMethods: ['GET', 'POST'],
    });

    expect(response.status).toBe(302);
    expect(jar.size).toBe(0);
  });

  it('does not redirect to the provider when clearing the cookies fails', async () => {
    const { store } = await storeWithSession('the-id-token');
    const failing: CookieStore = {
      ...store,
      delete: () => { throw new Error('cookies are immutable here'); },
    };

    const response = await handleOidcLogout(request, { ...baseConfig(store), cookies: failing });

    expect(response.status).toBe(500);
    expect(mockedBuildLogoutUrl).not.toHaveBeenCalled();
  });

  it('rejects a cross-site form post', async () => {
    const { store, jar } = await storeWithSession('the-id-token');
    const forged = new Request('https://app.example.test/api/auth/logout', {
      method: 'POST',
      headers: { 'sec-fetch-site': 'cross-site', origin: 'https://evil.example' },
    });

    const response = await handleOidcLogout(forged, baseConfig(store));

    expect(response.status).toBe(403);
    expect(jar.size).toBeGreaterThan(0);
  });

  it('rejects a foreign Origin when the browser sends no Fetch Metadata', async () => {
    const { store } = await storeWithSession('the-id-token');
    const forged = new Request('https://app.example.test/api/auth/logout', {
      method: 'POST',
      headers: { origin: 'https://evil.example' },
    });

    const response = await handleOidcLogout(forged, {
      ...baseConfig(store),
      applicationUrl: 'https://app.example.test',
    });

    expect(response.status).toBe(403);
  });

  it('accepts a same-origin form post', async () => {
    const { store, jar } = await storeWithSession('the-id-token');
    const own = new Request('https://app.example.test/api/auth/logout', {
      method: 'POST',
      headers: { 'sec-fetch-site': 'same-origin', origin: 'https://app.example.test' },
    });

    const response = await handleOidcLogout(own, baseConfig(store));

    expect(response.status).toBe(302);
    expect(jar.size).toBe(0);
  });
});
