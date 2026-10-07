/**
 * Server persistence: the session in a store, the browser holding a handle.
 * The shared suite runs the same lifecycle against both persistences; the rest
 * is what only a server-side session can promise — size, revocation, and one
 * refresh per session however many requests ask for it.
 */
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// Mock only the OAuth exchange; encode/decode and persistence run for real.
vi.mock('../session-refresh', () => ({ refreshSession: vi.fn() }));

import type { CookieOptions } from '../cookies';
import { refreshSession } from '../session-refresh';
import { SESSION_EVENT } from '../session-events';
import type { Session } from '../types';
import { createEncryptedJWT, sha256 } from '../utils';
import type { CookieStore } from './cookie-store';
import {
  cookiePersistence,
  serverPersistence,
  type ServerPersistenceOptions,
  type SessionPersistence,
} from './session-persistence';
import { createMemorySessionStore, type SessionStore, type StoredSession } from './session-store';
import {
  clearSession,
  persistSession,
  readIdToken,
  readSession,
  tryReadSession,
  tryRefreshSessionInStore,
} from './session';

const mockedRefreshSession = vi.mocked(refreshSession);
const secret = 'a'.repeat(64);

beforeEach(() => {
  vi.clearAllMocks();
});

/** An in-memory CookieStore that also remembers the options each cookie was set with. */
function cookieJar(initial?: Record<string, string>) {
  const jar = new Map<string, string>(Object.entries(initial ?? {}));
  const options = new Map<string, CookieOptions | undefined>();
  const cookies: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value, opts) => { jar.set(name, value); options.set(name, opts); },
    delete: (name) => { jar.delete(name); },
  };
  return { cookies, jar, options };
}

const config = {
  issuer: 'https://idp.test',
  clientId: 'c',
  clientSecret: 's',
  redirect_uri: 'https://app.test/cb',
  scope: 'openid',
};

const baseSession = (accessToken = 'access-token'): Session => ({
  sid: 'sid-1',
  tokens: {
    accessToken,
    refreshToken: 'refresh-token',
    idToken: 'id-token',
    accessTokenExpiresAt: '2099-01-01T00:00:00.000Z',
  },
  user: { name: 'Ada', email: 'ada@example.test' },
  scopes: ['openid'],
});

/** A provider that rotates: new access and refresh tokens on every call. */
function rotatingProvider() {
  let n = 0;
  mockedRefreshSession.mockImplementation(async (current) => {
    n += 1;
    return {
      ...current,
      tokens: { ...current.tokens, accessToken: `access-${n}`, refreshToken: `refresh-${n}` },
    };
  });
}

const invalidGrant = () =>
  Object.assign(new Error('bad grant'), { code: 'OAUTH_RESPONSE_BODY_ERROR', error: 'invalid_grant' });

describe.each([
  ['cookie', () => cookiePersistence(secret)],
  ['server', () => serverPersistence({ store: createMemorySessionStore(), secret })],
] as const)('%s persistence', (_mode, make) => {
  it('round-trips create → read → refresh → clear', async () => {
    const persistence = make();
    const { cookies } = cookieJar();

    await persistSession(cookies, baseSession(), persistence, { event: SESSION_EVENT.CREATED });

    const read = await tryReadSession(cookies, persistence);
    expect(read.session?.user?.email).toBe('ada@example.test');
    expect(read.session?.tokens?.accessToken).toBe('access-token');
    expect(read.session?.tokens?.idToken).toBe('id-token');
    expect(read.session?.sid).toBe('sid-1');

    rotatingProvider();
    const refreshed = await tryRefreshSessionInStore(cookies, config, persistence);
    expect(refreshed.ok && refreshed.session.tokens?.accessToken).toBe('access-1');
    expect(refreshed.ok && refreshed.rotatedRefreshToken).toBe(true);
    expect((await readSession(cookies, persistence))?.tokens?.refreshToken).toBe('refresh-1');
    expect(await readIdToken(cookies, persistence)).toBe('id-token');

    await clearSession(cookies, { persistence, trigger: 'logout' });
    expect(await tryReadSession(cookies, persistence)).toEqual({
      session: null,
      reason: 'no_session_cookie',
    });
    expect(await readIdToken(cookies, persistence)).toBeUndefined();
  });

  it('reports a dead refresh token as invalid_grant', async () => {
    const persistence = make();
    const { cookies } = cookieJar();
    await persistSession(cookies, baseSession(), persistence, { event: SESSION_EVENT.CREATED });
    mockedRefreshSession.mockRejectedValue(invalidGrant());

    expect(await tryRefreshSessionInStore(cookies, config, persistence)).toEqual({
      ok: false,
      reason: 'refresh_failed',
      cause: 'invalid_grant',
      sid: 'sid-1',
    });
  });
});

describe('server persistence', () => {
  function setup(
    store: SessionStore = createMemorySessionStore(),
    options: Partial<ServerPersistenceOptions> = {},
  ) {
    const persistence = serverPersistence({ store, secret, ...options });
    return { store, persistence, ...cookieJar() };
  }

  async function login(cookies: CookieStore, persistence: SessionPersistence, session = baseSession()) {
    await persistSession(cookies, session, persistence, { event: SESSION_EVENT.CREATED });
  }

  it('gives the browser one small cookie whatever the token size', async () => {
    const { persistence, cookies, jar, options } = setup();

    await login(cookies, persistence, baseSession('x'.repeat(8192)));

    expect([...jar.keys()]).toEqual(['session_ref']);
    const handle = jar.get('session_ref')!;
    expect(`session_ref=${handle}`.length).toBeLessThan(100);
    expect(options.get('session_ref')).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60,
    });
    expect((await readSession(cookies, persistence))?.tokens?.accessToken).toBe('x'.repeat(8192));
  });

  it('keys the store by a hash of the handle and encrypts the record', async () => {
    const { store, persistence, cookies, jar } = setup();

    await login(cookies, persistence);

    const handle = jar.get('session_ref')!;
    const key = await sha256(handle);
    expect(key).not.toBe(handle);
    expect(await store.get(handle)).toBeNull();

    const record = await store.get(key);
    expect(record?.sid).toBe('sid-1');
    expect(record?.data).not.toContain('refresh-token');
    expect(record?.data).not.toContain('ada@example.test');
  });

  it('mints a new handle on login and drops the record the old one pointed at', async () => {
    // Session fixation: a handle planted before login must not become a
    // logged-in one.
    const { store, persistence, cookies, jar } = setup();
    await login(cookies, persistence);
    const first = jar.get('session_ref')!;

    await login(cookies, persistence);

    const second = jar.get('session_ref')!;
    expect(second).not.toBe(first);
    expect(await store.get(await sha256(first))).toBeNull();
    expect(await store.get(await sha256(second))).not.toBeNull();
  });

  it('keeps the handle and the absolute expiry across a refresh', async () => {
    const { store, persistence, cookies, jar } = setup();
    await login(cookies, persistence);
    const handle = jar.get('session_ref')!;
    const before = await store.get(await sha256(handle));
    rotatingProvider();

    const result = await tryRefreshSessionInStore(cookies, config, persistence);

    expect(result.ok).toBe(true);
    expect(jar.get('session_ref')).toBe(handle);
    const after = await store.get(await sha256(handle));
    expect(after?.expiresAt).toBe(before?.expiresAt);
    expect(after?.data).not.toBe(before?.data);
  });

  it('revokes: a replayed cookie reads as session_not_found after clearSession', async () => {
    const { persistence, cookies, jar } = setup();
    await login(cookies, persistence);
    const stolen = jar.get('session_ref')!;

    await clearSession(cookies, { persistence, trigger: 'logout' });
    expect(jar.has('session_ref')).toBe(false);

    const replay = cookieJar({ session_ref: stolen });
    expect(await tryReadSession(replay.cookies, persistence)).toEqual({
      session: null,
      reason: 'session_not_found',
    });
    expect(await readIdToken(replay.cookies, persistence)).toBeUndefined();
    expect(await tryRefreshSessionInStore(replay.cookies, config, persistence)).toEqual({
      ok: false,
      reason: 'session_not_found',
    });
  });

  it('rejects an expired record even when the adapter still returns it', async () => {
    // A TTL index sweeps late; the library must not trust it.
    const records = new Map<string, StoredSession>();
    const lax: SessionStore = {
      get: (key) => records.get(key) ?? null,
      set: (key, record) => { records.set(key, record); },
      delete: (key) => { records.delete(key); },
    };
    const persistence = serverPersistence({ store: lax, secret });
    const handle = 'h'.repeat(64);
    records.set(await sha256(handle), {
      data: await createEncryptedJWT(baseSession(), secret),
      expiresAt: '2000-01-01T00:00:00.000Z',
    });
    const { cookies } = cookieJar({ session_ref: handle });

    expect(await tryReadSession(cookies, persistence)).toEqual({
      session: null,
      reason: 'session_not_found',
    });
    expect(records.size).toBe(0);
  });

  it('reports unreadable_session for a record encrypted under another secret', async () => {
    const store = createMemorySessionStore();
    const rotated = serverPersistence({ store, secret: 'b'.repeat(64) });
    const persistence = serverPersistence({ store, secret });
    const { cookies } = cookieJar();
    await login(cookies, rotated);

    expect((await tryReadSession(cookies, persistence)).reason).toBe('unreadable_session');
  });

  it('treats leftover split cookies as a stale legacy session and clears them on the next write', async () => {
    const { persistence, cookies, jar } = setup();
    await persistSession(cookies, baseSession(), cookiePersistence(secret));
    expect(jar.has('session')).toBe(true);

    expect(await tryReadSession(cookies, persistence)).toEqual({
      session: null,
      reason: 'stale_legacy_session',
    });

    await login(cookies, persistence);
    expect([...jar.keys()]).toEqual(['session_ref']);
  });

  it('clears leftover split cookies on logout', async () => {
    const { persistence, cookies, jar } = setup();
    await persistSession(cookies, baseSession(), cookiePersistence(secret));

    await clearSession(cookies, { persistence });

    expect(jar.size).toBe(0);
  });

  it('coalesces concurrent refreshes: one token request, one result for all', async () => {
    const { persistence, cookies } = setup();
    await login(cookies, persistence);
    rotatingProvider();

    const results = await Promise.all(
      Array.from({ length: 5 }, () => tryRefreshSessionInStore(cookies, config, persistence)),
    );

    expect(mockedRefreshSession).toHaveBeenCalledTimes(1);
    for (const result of results) {
      expect(result.ok && result.session.tokens?.accessToken).toBe('access-1');
    }
    expect((await readSession(cookies, persistence))?.tokens?.refreshToken).toBe('refresh-1');
  });

  it('reuses a refresh another instance did while we waited for the lock', async () => {
    const inner = createMemorySessionStore();
    const store: SessionStore = {
      get: (key) => inner.get(key),
      set: (key, record) => inner.set(key, record),
      delete: (key) => inner.delete(key),
      async withLock(key, fn) {
        // The other instance's refresh lands before we get the lock.
        const record = (await inner.get(key))!;
        await inner.set(key, {
          ...record,
          data: await createEncryptedJWT(baseSession('access-elsewhere'), secret),
        });
        return fn();
      },
    };
    const persistence = serverPersistence({ store, secret });
    const { cookies } = cookieJar();
    await login(cookies, persistence);
    rotatingProvider();

    const result = await tryRefreshSessionInStore(cookies, config, persistence);

    expect(mockedRefreshSession).not.toHaveBeenCalled();
    expect(result.ok && result.session.tokens?.accessToken).toBe('access-elsewhere');
  });

  it('recovers from invalid_grant when a concurrent refresh elsewhere spent the token', async () => {
    const { store, persistence, cookies, jar } = setup();
    await login(cookies, persistence);
    const key = await sha256(jar.get('session_ref')!);
    mockedRefreshSession.mockImplementation(async () => {
      const record = (await store.get(key))!;
      await store.set(key, {
        ...record,
        data: await createEncryptedJWT(baseSession('access-elsewhere'), secret),
      });
      throw invalidGrant();
    });

    const result = await tryRefreshSessionInStore(cookies, config, persistence);

    expect(result.ok && result.session.tokens?.accessToken).toBe('access-elsewhere');
  });

  it('does not resurrect a session cleared while its refresh was in flight', async () => {
    const { store, persistence, cookies, jar } = setup();
    await login(cookies, persistence);
    const key = await sha256(jar.get('session_ref')!);
    mockedRefreshSession.mockImplementation(async (current) => {
      await store.delete(key); // a logout on another request
      return { ...current, tokens: { ...current.tokens, accessToken: 'access-1' } };
    });

    const result = await tryRefreshSessionInStore(cookies, config, persistence);

    // This response still carries valid tokens, but the logout wins from here on.
    expect(result.ok).toBe(true);
    expect(await store.get(key)).toBeNull();
  });

  it('honours cookieName and sessionDurationDays', async () => {
    const { store, persistence, cookies, jar, options } = setup(createMemorySessionStore(), {
      cookieName: 'sid_ref',
      sessionDurationDays: 1,
    });
    const before = Date.now();

    await login(cookies, persistence);

    expect([...jar.keys()]).toEqual(['sid_ref']);
    expect(options.get('sid_ref')?.maxAge).toBe(24 * 60 * 60);
    const record = await store.get(await sha256(jar.get('sid_ref')!));
    const ttl = Date.parse(record!.expiresAt) - before;
    expect(ttl).toBeGreaterThan(24 * 60 * 60 * 1000 - 1000);
    expect(ttl).toBeLessThanOrEqual(24 * 60 * 60 * 1000 + 1000);
  });

  describe('logging', () => {
    const levels = ['debug', 'info', 'warn', 'error'] as const;
    let lines: string[];
    let spies: Array<ReturnType<typeof vi.spyOn>>;

    beforeEach(() => {
      lines = [];
      spies = levels.map((level) =>
        vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
          lines.push(args.map(String).join(' '));
        }),
      );
    });

    afterEach(() => {
      spies.forEach((spy) => spy.mockRestore());
    });

    it('never logs the handle or the store key', async () => {
      const { persistence, cookies, jar } = setup();
      await login(cookies, persistence);
      const handle = jar.get('session_ref')!;
      const key = await sha256(handle);
      rotatingProvider();
      await tryRefreshSessionInStore(cookies, config, persistence);
      await clearSession(cookies, { persistence, trigger: 'logout' });
      await tryReadSession(cookieJar({ session_ref: handle }).cookies, persistence);

      expect(lines.length).toBeGreaterThan(0);
      for (const line of lines) {
        expect(line).not.toContain(handle);
        expect(line).not.toContain(key);
      }
    });

    it('tags lifecycle events with persistence=server and no cookieBytes', async () => {
      const { persistence, cookies } = setup();
      await login(cookies, persistence);
      rotatingProvider();
      await tryRefreshSessionInStore(cookies, config, persistence);

      const events = lines
        .filter((line) => line.startsWith('{'))
        .map((line) => JSON.parse(line))
        .filter((entry) => entry.event === 'session.created' || entry.event === 'session.refreshed');

      expect(events.map((e) => e.event)).toEqual(['session.created', 'session.refreshed']);
      for (const event of events) {
        expect(event.persistence).toBe('server');
        expect(event.cookieBytes).toBeUndefined();
        expect(event.sid).toBe('sid-1');
      }
    });
  });
});
