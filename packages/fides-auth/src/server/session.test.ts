import { vi, describe, it, expect, beforeEach } from 'vitest';

// Mock only the OAuth exchange; encode/decode and persistence run for real.
vi.mock('../session-refresh', () => ({ refreshSession: vi.fn() }));

import { CookieTooLargeError } from '../cookies';
import { createEncryptedJWT } from '../utils';
import { refreshSession } from '../session-refresh';
import type { Session } from '../types';
import type { CookieStore } from './cookie-store';
import {
  persistSession,
  readSession,
  tryReadSession,
  refreshSessionInStore,
  tryRefreshSessionInStore,
  clearSession,
} from './session';

const mockedRefreshSession = vi.mocked(refreshSession);

beforeEach(() => {
  vi.clearAllMocks();
});

// 32-byte (64 hex char) secret for A256GCM.
const secret = 'a'.repeat(64);

/** A trivial in-memory CookieStore — the role a framework adapter fills. */
function memoryStore(initial?: Record<string, string>) {
  const jar = new Map<string, string>(Object.entries(initial ?? {}));
  const store: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value) => { jar.set(name, value); },
    delete: (name) => { jar.delete(name); },
  };
  return { store, jar };
}

/** Builds an unsigned JWT carrying only an `exp` claim (decoded, never verified). */
function jwtWithExp(secondsFromNow: number): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ exp })}.sig`;
}

/** Minimal OAuth config — the refresh exchange itself is mocked. */
const config = {
  issuer: 'https://idp.test',
  clientId: 'c',
  clientSecret: 's',
  redirect_uri: 'https://app.test/cb',
  scope: 'openid',
};

const baseSession = (accessToken?: string): Session => ({
  tokens: {
    accessToken,
    refreshToken: 'refresh-token',
    accessTokenExpiresAt: '2099-01-01T00:00:00.000Z',
  },
  user: { name: 'Ada', email: 'ada@example.test', roles: ['admin'] },
  scopes: ['openid', 'profile'],
});

describe('persistSession', () => {
  it('writes the access token to session_at and everything else to session', async () => {
    const accessToken = jwtWithExp(3600);
    const { store, jar } = memoryStore();

    await persistSession(store, baseSession(accessToken), secret);

    expect(jar.has('session')).toBe(true);
    expect(jar.has('session_at')).toBe(true);
    // The raw access token must not appear in the main cookie.
    expect(jar.get('session')).not.toContain(accessToken.split('.')[1]);
  });

  it('clears a stale session_at cookie when the session has no access token', async () => {
    const { store, jar } = memoryStore({ session_at: 'stale' });

    await persistSession(store, baseSession(undefined), secret);

    expect(jar.has('session')).toBe(true);
    expect(jar.has('session_at')).toBe(false);
  });

  it('writes the ID token to session_it, kept out of the other two cookies', async () => {
    const idToken = jwtWithExp(3600);
    const session = baseSession(jwtWithExp(3600));
    session.tokens!.idToken = idToken;
    const { store, jar } = memoryStore();

    await persistSession(store, session, secret);

    expect(jar.has('session_it')).toBe(true);
    expect(jar.get('session')).not.toContain(idToken.split('.')[1]);
    expect(jar.get('session_at')).not.toContain(idToken.split('.')[1]);
  });

  it('leaves every cookie untouched when one value is too large', async () => {
    // The previous user's cookies must survive intact: writing some of them and
    // then throwing would leave user B's session beside user A's ID token.
    const previous = {
      session: 'user-a-session',
      session_at: 'user-a-access-token',
      session_it: 'user-a-id-token',
    };
    const { store, jar } = memoryStore(previous);

    const session = baseSession(jwtWithExp(3600));
    session.tokens!.idToken = 'x'.repeat(5000);

    await expect(persistSession(store, session, secret)).rejects.toThrow(CookieTooLargeError);

    expect(Object.fromEntries(jar)).toEqual(previous);
  });
});

describe('readSession', () => {
  it('round-trips: reassembles the access token from the two cookies', async () => {
    const accessToken = jwtWithExp(3600);
    const { store } = memoryStore();
    await persistSession(store, baseSession(accessToken), secret);

    const session = await readSession(store, secret);
    expect(session?.tokens?.accessToken).toBe(accessToken);
    expect(session?.user?.email).toBe('ada@example.test');
  });

  it('returns null when there is no session cookie', async () => {
    const { store } = memoryStore();
    expect(await readSession(store, secret)).toBeNull();
  });

  it('keeps a session whose access token has expired', async () => {
    // Expiry must not hide the session — the refresh path recovers it.
    const expired = jwtWithExp(-10);
    const { store } = memoryStore();
    await persistSession(store, baseSession(expired), secret);

    const session = await readSession(store, secret);
    expect(session?.tokens?.accessToken).toBe(expired);
    expect(session?.tokens?.refreshToken).toBe('refresh-token');
  });

  it('still reads a legacy single-cookie session (access token inside session)', async () => {
    // Legacy layout: the whole session, access token included, in one "session"
    // cookie and no "session_at". Capture the token once — jwtWithExp is
    // time-based, so a second call could differ across a second boundary.
    const accessToken = jwtWithExp(3600);
    const legacy = await createEncryptedJWT(baseSession(accessToken), secret);
    const { store } = memoryStore({ session: legacy });

    const session = await readSession(store, secret);
    expect(session?.tokens?.accessToken).toBe(accessToken);
  });

  it('drops a legacy single-cookie session whose access token has expired', async () => {
    // Stale legacy sessions are dropped, not migrated — one re-login.
    const legacy = await createEncryptedJWT(baseSession(jwtWithExp(-10)), secret);
    const { store } = memoryStore({ session: legacy });

    expect(await readSession(store, secret)).toBeNull();
  });
});

describe('clearSession', () => {
  it('deletes both cookies', async () => {
    const { store, jar } = memoryStore();
    await persistSession(store, baseSession(jwtWithExp(3600)), secret);

    await clearSession(store);
    expect(jar.has('session')).toBe(false);
    expect(jar.has('session_at')).toBe(false);
  });
});

describe('refreshSessionInStore', () => {

  it('returns null when there is no session to refresh', async () => {
    const { store } = memoryStore();
    expect(await refreshSessionInStore(store, config, secret)).toBeNull();
    expect(mockedRefreshSession).not.toHaveBeenCalled();
  });

  it('returns null when the stored session has no refresh token', async () => {
    const { store } = memoryStore();
    const noRefresh: Session = {
      tokens: { accessToken: jwtWithExp(3600), accessTokenExpiresAt: '2099-01-01T00:00:00.000Z' },
      user: { name: 'Ada', email: 'ada@example.test', roles: [] },
    };
    await persistSession(store, noRefresh, secret);

    expect(await refreshSessionInStore(store, config, secret)).toBeNull();
    expect(mockedRefreshSession).not.toHaveBeenCalled();
  });

  it('refreshes a session whose access token has already expired', async () => {
    // The heart of the fix: an expired access token must be refreshable.
    const expired = jwtWithExp(-60);
    const { store } = memoryStore();
    await persistSession(store, baseSession(expired), secret);

    const freshToken = jwtWithExp(3600);
    const refreshed = baseSession(freshToken);
    mockedRefreshSession.mockResolvedValue(refreshed);

    const result = await refreshSessionInStore(store, config, secret);

    expect(result).toEqual(refreshed);
    // The exchange got the session it was refreshing, expired token and all.
    expect(mockedRefreshSession).toHaveBeenCalledWith(
      expect.objectContaining({
        tokens: expect.objectContaining({ accessToken: expired, refreshToken: 'refresh-token' }),
      }),
      config,
      {},
    );
    const persisted = await readSession(store, secret);
    expect(persisted?.tokens?.accessToken).toBe(freshToken);
  });
});

describe('tryReadSession — rejection reasons', () => {
  // The reasons are what a proxy, a status route and the heartbeat endpoint all
  // log, so an operator can tell "nobody was logged in" apart from "the cookie
  // would not decrypt" without reading library source.
  it('reports no_session_cookie for an anonymous request', async () => {
    const { store } = memoryStore();

    expect(await tryReadSession(store, secret)).toEqual({
      session: null,
      reason: 'no_session_cookie',
    });
  });

  it('reports unreadable_session for a cookie encrypted under a different secret', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('token'), 'b'.repeat(64));

    const result = await tryReadSession(store, secret);

    expect(result.session).toBeNull();
    expect(result.reason).toBe('unreadable_session');
  });

  it('reports unreadable_session for a cookie that is not a JWE at all', async () => {
    const { store } = memoryStore({ session: 'not-a-jwe' });

    expect((await tryReadSession(store, secret)).reason).toBe('unreadable_session');
  });

  it('separates a stale legacy session from a corrupt one', async () => {
    // A pre-split single-cookie session with an expired access token. It costs
    // exactly one re-login, which is a different operational story to corruption.
    const legacy = await createEncryptedJWT(baseSession(jwtWithExp(-60)), secret);
    const { store } = memoryStore({ session: legacy });

    expect((await tryReadSession(store, secret)).reason).toBe('stale_legacy_session');
  });

  it('returns the session with no reason when the cookies are good', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('token'), secret);

    const result = await tryReadSession(store, secret);

    expect(result.reason).toBeUndefined();
    expect(result.session?.user?.email).toBe('ada@example.test');
  });
});

describe('tryRefreshSessionInStore — failure causes', () => {
  it('reports no cause when it never got as far as a refresh', async () => {
    const { store } = memoryStore();

    const result = await tryRefreshSessionInStore(store, config, secret);

    expect(result).toEqual({ ok: false, reason: 'no_session_cookie' });
    // No cause: there is no provider verdict to report when we never asked it.
    expect(mockedRefreshSession).not.toHaveBeenCalled();
  });

  it('reports no_refresh_token without calling the provider', async () => {
    const { store } = memoryStore();
    await persistSession(store, { tokens: { accessToken: 'a' } }, secret);

    const result = await tryRefreshSessionInStore(store, config, secret);

    expect(result).toEqual({ ok: false, reason: 'no_refresh_token' });
    expect(mockedRefreshSession).not.toHaveBeenCalled();
  });

  it('classifies a dead refresh token as invalid_grant', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('a'), secret);
    mockedRefreshSession.mockRejectedValue(
      Object.assign(new Error('bad grant'), {
        code: 'OAUTH_RESPONSE_BODY_ERROR',
        error: 'invalid_grant',
      }),
    );

    expect(await tryRefreshSessionInStore(store, config, secret)).toEqual({
      ok: false,
      reason: 'refresh_failed',
      cause: 'invalid_grant',
    });
  });

  it('classifies an unreachable provider as transport', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('a'), secret);
    mockedRefreshSession.mockRejectedValue(
      Object.assign(new TypeError('fetch failed'), {
        cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
      }),
    );

    const result = await tryRefreshSessionInStore(store, config, secret);

    // The distinction that keeps a valid session alive: not invalid_grant.
    expect(result).toEqual({ ok: false, reason: 'refresh_failed', cause: 'transport' });
  });

  it('classifies a provider 500 as idp_error', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('a'), secret);
    mockedRefreshSession.mockRejectedValue(
      Object.assign(new Error('Server Error'), { status: 500 }),
    );

    expect(await tryRefreshSessionInStore(store, config, secret)).toEqual({
      ok: false,
      reason: 'refresh_failed',
      cause: 'idp_error',
    });
  });

  it('reports refresh-token rotation on success', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('a'), secret);
    mockedRefreshSession.mockResolvedValue({
      ...baseSession('new-access'),
      tokens: { accessToken: 'new-access', refreshToken: 'rotated-refresh' },
    });

    const result = await tryRefreshSessionInStore(store, config, secret);

    expect(result.ok).toBe(true);
    // Rotation is what turns a lost cookie write into a bricked session, so it
    // has to be visible without diffing token values by hand.
    expect(result.ok && result.rotatedRefreshToken).toBe(true);
  });

  it('reports no rotation when the provider returned the same refresh token', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession('a'), secret);
    mockedRefreshSession.mockResolvedValue(baseSession('new-access'));

    const result = await tryRefreshSessionInStore(store, config, secret);

    expect(result.ok && result.rotatedRefreshToken).toBe(false);
  });
});

describe('session correlation id', () => {
  it('survives a refresh, so one session is one id across its whole life', async () => {
    const { store } = memoryStore();
    const original = { ...baseSession('a'), sid: 'abc123' };
    await persistSession(store, original, secret);

    // refreshSession spreads the current session, so sid rides along.
    mockedRefreshSession.mockImplementation(async (current) => ({
      ...current,
      tokens: { ...current.tokens, accessToken: 'new-access' },
    }));

    const result = await tryRefreshSessionInStore(store, config, secret);

    expect(result.ok && result.session.sid).toBe('abc123');
    expect((await readSession(store, secret))?.sid).toBe('abc123');
  });
});
