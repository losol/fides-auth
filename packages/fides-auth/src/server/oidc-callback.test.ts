/**
 * Regression test for the proxy callback-path bug.
 *
 * Behind a TLS-terminating proxy `applicationUrl` is just the origin, so the
 * reconstructed callback URL must take its path from the incoming request. If it
 * doesn't, the token-exchange redirect_uri collapses to "/" and Keycloak rejects
 * it with invalid_redirect_uri (Auth0 tolerated the mismatch).
 *
 * The OAuth machinery (tested elsewhere) is mocked; we assert on the URL handed
 * to exchangeAuthorizationCode and that the session is persisted via the store.
 */
import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('../oauth', () => ({
  exchangeAuthorizationCode: vi.fn(),
  buildSessionFromTokens: vi.fn(),
  validateReturnUrl: vi.fn(),
}));

import { handleOidcCallback } from './oidc-callback';
import {
  exchangeAuthorizationCode,
  buildSessionFromTokens,
  validateReturnUrl,
} from '../oauth';
import type { CookieStore } from './cookie-store';

const mockedExchange = vi.mocked(exchangeAuthorizationCode);
const mockedBuildSession = vi.mocked(buildSessionFromTokens);
const mockedValidateReturnUrl = vi.mocked(validateReturnUrl);

const secret = 'a'.repeat(64);

function memoryStore(initial?: Record<string, string>) {
  const jar = new Map<string, string>(Object.entries(initial ?? {}));
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value) => { jar.set(name, value); },
    delete: (name) => { jar.delete(name); },
  };
  return { store, jar };
}

const baseConfig = (store: CookieStore) => ({
  oauthConfig: {
    issuer: 'https://id.example.test/realms/test',
    clientId: 'web',
    clientSecret: 'shh',
    redirect_uri: 'https://host.example.test/api/auth/callback/oidc',
    scope: 'openid',
  },
  // Public origin only — no path — as seen behind a TLS-terminating proxy.
  applicationUrl: 'https://host.example.test',
  cookies: store,
  rateLimit: async () => true,
  secret,
});

beforeEach(() => {
  vi.clearAllMocks();
  mockedExchange.mockResolvedValue({ accessToken: 'a' } as any);
  mockedBuildSession.mockReturnValue({} as any);
  mockedValidateReturnUrl.mockReturnValue(new URL('https://host.example.test/'));
});

describe('handleOidcCallback — proxy callback path', () => {
  it('passes the full callback path and https scheme to the token exchange', async () => {
    const { store, jar } = memoryStore({ oauth_state: 'xyz', oauth_code_verifier: 'verifier' });
    // Internal hop arrives over http at the callback path with the auth code.
    const request = new Request('http://internal/api/auth/callback/oidc?code=abc&state=xyz');

    const response = await handleOidcCallback(request, baseConfig(store));

    expect(response.status).toBe(302);
    expect(mockedExchange).toHaveBeenCalledTimes(1);

    const passedUrl = mockedExchange.mock.calls[0]![1] as URL;
    expect(passedUrl.pathname).toBe('/api/auth/callback/oidc');
    expect(passedUrl.protocol).toBe('https:');
    expect(passedUrl.host).toBe('host.example.test');
    expect(passedUrl.searchParams.get('code')).toBe('abc');

    // The session is persisted and the PKCE cookies are cleared.
    expect(jar.has('session')).toBe(true);
    expect(jar.has('oauth_state')).toBe(false);
    expect(jar.has('oauth_code_verifier')).toBe(false);
  });
});

describe('handleOidcCallback — guards', () => {
  it('returns 429 when rate-limited', async () => {
    const { store } = memoryStore();
    const request = new Request('http://internal/api/auth/callback/oidc?code=abc&state=xyz');

    const response = await handleOidcCallback(request, {
      ...baseConfig(store),
      rateLimit: async () => false,
    });

    expect(response.status).toBe(429);
    expect(mockedExchange).not.toHaveBeenCalled();
  });

  it('returns 400 when the PKCE cookies are missing', async () => {
    const { store } = memoryStore();
    const request = new Request('http://internal/api/auth/callback/oidc?code=abc&state=xyz');

    const response = await handleOidcCallback(request, baseConfig(store));

    expect(response.status).toBe(400);
    expect(mockedExchange).not.toHaveBeenCalled();
  });
});
