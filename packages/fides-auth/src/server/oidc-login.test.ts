/**
 * Tests for the OIDC login handler — focused on the PKCE/returnTo cookie
 * lifecycle. The OAuth machinery is mocked (tested elsewhere).
 */
import { vi, describe, it, expect, beforeEach } from 'vitest';

vi.mock('../oauth', () => ({
  buildPKCEOptions: vi.fn(),
  discoverAndBuildAuthorizationUrl: vi.fn(),
}));

import { handleOidcLogin } from './oidc-login';
import { buildPKCEOptions, discoverAndBuildAuthorizationUrl } from '../oauth';
import type { CookieStore } from './cookie-store';

const mockedPkce = vi.mocked(buildPKCEOptions);
const mockedAuthUrl = vi.mocked(discoverAndBuildAuthorizationUrl);

function memoryStore(initial?: Record<string, string>) {
  const jar = new Map<string, string>(Object.entries(initial ?? {}));
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value) => { jar.set(name, value); },
    delete: (name) => { jar.delete(name); },
  };
  return { store, jar };
}

const oauthConfig = {
  issuer: 'https://id.example.test',
  clientId: 'web',
  clientSecret: 'shh',
  redirect_uri: 'https://app.test/api/auth/callback/oidc',
  scope: 'openid',
};

beforeEach(() => {
  vi.clearAllMocks();
  mockedPkce.mockResolvedValue({ state: 'st', code_verifier: 'cv' } as any);
  mockedAuthUrl.mockResolvedValue(new URL('https://id.example.test/authorize?x=1'));
});

describe('handleOidcLogin', () => {
  it('persists PKCE state and redirects to the authorization endpoint', async () => {
    const { store, jar } = memoryStore();
    const response = await handleOidcLogin(new Request('https://app.test/api/auth/login'), {
      oauthConfig,
      cookies: store,
    });

    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://id.example.test/authorize?x=1');
    expect(jar.get('oauth_state')).toBe('st');
    expect(jar.get('oauth_code_verifier')).toBe('cv');
  });

  it('stores a valid returnTo', async () => {
    const { store, jar } = memoryStore();
    await handleOidcLogin(new Request('https://app.test/api/auth/login?returnTo=%2Fdash'), {
      oauthConfig,
      cookies: store,
    });

    expect(jar.get('returnTo')).toBe('/dash');
  });

  it('clears a stale returnTo when none is provided', async () => {
    const { store, jar } = memoryStore({ returnTo: '/old' });
    await handleOidcLogin(new Request('https://app.test/api/auth/login'), {
      oauthConfig,
      cookies: store,
    });

    expect(jar.has('returnTo')).toBe(false);
  });

  it('returns 429 when rate-limited, without touching cookies', async () => {
    const { store, jar } = memoryStore();
    const response = await handleOidcLogin(new Request('https://app.test/api/auth/login'), {
      oauthConfig,
      cookies: store,
      rateLimit: async () => false,
    });

    expect(response.status).toBe(429);
    expect(jar.size).toBe(0);
    expect(mockedPkce).not.toHaveBeenCalled();
  });
});
