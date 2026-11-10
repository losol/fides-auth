// @vitest-environment node
/**
 * Tests for createFidesAuth. Split-cookie storage: the access token lives in its
 * own "session_at" cookie while the rest of the session lives in "session".
 * getCurrentSession must reassemble the two — expired access token included —
 * and still read legacy single-cookie sessions with a live access token.
 */
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// In-memory cookie jar backing the mocked next/headers cookie store (hoisted so
// the vi.mock factory can close over it). This exercises the real adapter path:
// auth.ts -> nextCookieStore -> @eventuras/fides-auth/server.
const { jar } = vi.hoisted(() => ({ jar: new Map<string, string>() }));

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (jar.has(name) ? { value: jar.get(name) } : undefined),
    set: (name: string, value: string) => { jar.set(name, value); },
    delete: (name: string) => { jar.delete(name); },
  })),
  headers: vi.fn(async () => new Headers()),
}));

// Only the route handlers are stubbed; the session helpers stay real.
vi.mock('@eventuras/fides-auth/server', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eventuras/fides-auth/server')>()),
  handleOidcLogin: vi.fn(async () => new Response(null, { status: 302 })),
  handleOidcCallback: vi.fn(async () => new Response(null, { status: 302 })),
  handleOidcLogout: vi.fn(async () => new Response(null, { status: 302 })),
  handleHeartbeat: vi.fn(async () => new Response(null, { status: 200 })),
}));

// getCurrentSession is wrapped in React's cache(); make it a pass-through.
vi.mock('react', () => ({ cache: (fn: unknown) => fn }));

import { createFidesAuth } from './auth';
import * as core from '@eventuras/fides-auth/server';
import { createEncryptedJWT } from '@eventuras/fides-auth/utils';
import type { MapSession } from '@eventuras/fides-auth/oauth';
import type { Session } from '@eventuras/fides-auth/types';

const secret = 'a'.repeat(64);
const oauthConfig = {
  issuer: 'https://id.example.test',
  clientId: 'web',
  clientSecret: 'shh',
  redirect_uri: 'https://app.test/api/auth/callback/oidc',
  scope: 'openid',
};
const auth = createFidesAuth({ secret, oauthConfig });
const { createAndPersistSession, getCurrentSession, tryGetCurrentSession, clearCurrentSession } =
  auth;

/** Builds an unsigned JWT carrying only an `exp` claim (decoded, never verified). */
function jwtWithExp(secondsFromNow: number): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ exp })}.sig`;
}

const baseSession = (accessToken?: string): Session => ({
  tokens: {
    accessToken,
    refreshToken: 'refresh-token',
    accessTokenExpiresAt: '2099-01-01T00:00:00.000Z',
  },
  user: { name: 'Ada', email: 'ada@example.test', roles: ['admin'] },
  scopes: ['openid', 'profile'],
});

beforeEach(() => {
  jar.clear();
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('split-cookie session storage', () => {
  it('writes the access token to session_at and everything else to session', async () => {
    const accessToken = jwtWithExp(3600);
    await createAndPersistSession(baseSession(accessToken));

    expect(jar.has('session')).toBe(true);
    expect(jar.has('session_at')).toBe(true);
    // The raw access token must not appear in the main cookie.
    expect(jar.get('session')).not.toContain(accessToken.split('.')[1]);
  });

  it('round-trips: getCurrentSession reassembles the access token', async () => {
    const accessToken = jwtWithExp(3600);
    await createAndPersistSession(baseSession(accessToken));

    const session = await getCurrentSession();
    expect(session?.tokens?.accessToken).toBe(accessToken);
    expect(session?.tokens?.refreshToken).toBe('refresh-token');
    expect(session?.user?.email).toBe('ada@example.test');
    expect(session?.scopes).toEqual(['openid', 'profile']);
  });

  it('keeps the session when the split access token has expired', async () => {
    // The refresh path recovers this session; expiry must not read as "logged out".
    const expired = jwtWithExp(-60);
    await createAndPersistSession(baseSession(expired));

    const session = await getCurrentSession();
    expect(session?.tokens?.accessToken).toBe(expired);
    expect(session?.tokens?.refreshToken).toBe('refresh-token');
  });

  it('omits session_at when the session has no access token', async () => {
    // Seed a stale access-token cookie to prove it gets cleared.
    jar.set('session_at', 'stale');
    await createAndPersistSession(baseSession(undefined));

    expect(jar.has('session')).toBe(true);
    expect(jar.has('session_at')).toBe(false);

    const session = await getCurrentSession();
    expect(session?.tokens?.accessToken).toBeUndefined();
    expect(session?.tokens?.refreshToken).toBe('refresh-token');
  });

  it('clearCurrentSession deletes both cookies', async () => {
    await createAndPersistSession(baseSession(jwtWithExp(3600)));
    await clearCurrentSession();

    expect(jar.has('session')).toBe(false);
    expect(jar.has('session_at')).toBe(false);
  });

  it('still reads a legacy session that holds the access token in the main cookie', async () => {
    // No session_at — the full session (incl. access token) lives in "session".
    const accessToken = jwtWithExp(3600);
    const legacyJwt = await createEncryptedJWT(baseSession(accessToken), secret);
    jar.set('session', legacyJwt);

    const session = await getCurrentSession();
    expect(session?.tokens?.accessToken).toBe(accessToken);
  });
});

describe('tryGetCurrentSession — the reason-carrying read', () => {
  // Proxies and status routes need the shared vocabulary without hand-rolling a
  // CookieStore over next/headers.
  it('reports no_session_cookie for an anonymous request', async () => {
    expect(await tryGetCurrentSession()).toEqual({
      session: null,
      reason: 'no_session_cookie',
    });
  });

  it('reports unreadable_session for a cookie that will not decrypt', async () => {
    jar.set('session', 'not-a-jwe');

    const result = await tryGetCurrentSession();

    expect(result.session).toBeNull();
    expect(result.reason).toBe('unreadable_session');
  });

  it('returns the session with no reason when the cookies are good', async () => {
    await createAndPersistSession(baseSession(jwtWithExp(3600)));

    const result = await tryGetCurrentSession();

    expect(result.reason).toBeUndefined();
    expect(result.session?.user?.email).toBe('ada@example.test');
  });

  it('agrees with getCurrentSession, which now delegates to it', async () => {
    await createAndPersistSession(baseSession(jwtWithExp(3600)));

    const [viaTry, viaLegacy] = await Promise.all([
      tryGetCurrentSession(),
      getCurrentSession(),
    ]);

    expect(viaTry.session).toEqual(viaLegacy);
  });
});

describe('createFidesAuth — bound config', () => {
  it('uses its own secret, not another instance\'s or SESSION_SECRET', async () => {
    const other = 'b'.repeat(64);
    vi.stubEnv('SESSION_SECRET', other);
    await createAndPersistSession(baseSession(jwtWithExp(3600)));

    expect((await tryGetCurrentSession()).session).not.toBeNull();
    expect((await createFidesAuth({ secret: other, oauthConfig }).tryGetCurrentSession()).reason)
      .toBe('unreadable_session');
  });

  it('takes an unset secret at creation and rejects it on first use', async () => {
    // Next evaluates route modules during the build, often without the secret.
    const unset = createFidesAuth({ secret: undefined as never, oauthConfig });

    await expect(unset.tryGetCurrentSession()).rejects.toThrow('missing or empty');
    await expect(unset.createAndPersistSession(baseSession('a'))).rejects.toThrow(
      'missing or empty',
    );
  });

  it('passes per-request authorization parameters to the login handler', async () => {
    const request = new Request('https://app.test/api/auth/login?reauth');
    const authorizationParameters = () => ({ prompt: 'login' });

    await auth.handleOidcLogin(request, { authorizationParameters });

    expect(core.handleOidcLogin).toHaveBeenCalledWith(
      request,
      expect.objectContaining({ authorizationParameters, oauthConfig, secret }),
    );
  });

  it('passes mapSession to the callback handler', async () => {
    const request = new Request('https://app.test/api/auth/callback/oidc');
    const mapSession: MapSession = (_tokens, _claims, session) => session;

    await auth.handleOidcCallback(request, { applicationUrl: 'https://app.test', mapSession });

    expect(core.handleOidcCallback).toHaveBeenCalledWith(
      request,
      expect.objectContaining({ mapSession, oauthConfig, secret }),
    );
  });

  it('passes oauthConfig and secret to every handler', async () => {
    const request = new Request('https://app.test/api/auth');

    await auth.handleOidcLogin(request);
    await auth.handleOidcCallback(request, { applicationUrl: 'https://app.test' });
    await auth.handleOidcLogout(request, { postLogoutRedirectUri: 'https://app.test/' });
    await auth.handleHeartbeat(request);

    const bound = expect.objectContaining({ oauthConfig, secret });
    expect(core.handleOidcLogin).toHaveBeenCalledWith(request, bound);
    expect(core.handleOidcCallback).toHaveBeenCalledWith(request, bound);
    expect(core.handleOidcLogout).toHaveBeenCalledWith(request, bound);
    expect(core.handleHeartbeat).toHaveBeenCalledWith(request, bound);
    expect(core.handleOidcCallback).toHaveBeenCalledWith(
      request,
      expect.objectContaining({ applicationUrl: 'https://app.test' }),
    );
  });
});
