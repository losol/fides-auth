/**
 * The lifecycle rules, run against both storages. A rule that holds for one
 * storage must hold for the other; the few store-only behaviours are at the end.
 */
import { UnsecuredJWT } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import type { SessionEvent } from '../shared/session-events.js';
import type { TokenResponse } from '../shared/types.js';
import { sealRecord } from '../session/record.js';
import type { CookieStore } from './cookie-store.js';
import { createSessionLifecycle, type SessionLifecycleOptions } from './session-lifecycle.js';
import { SessionSecretError } from './session-secret.js';
import { cookieStorage, type SessionStorage, storeStorage } from './session-storage.js';
import { createMemorySessionStore, type SessionStore } from './session-store.js';

const secret = 'a'.repeat(64);
const DAY = 24 * 60 * 60 * 1000;

/** Shares one jar between "requests", the way a browser carries cookies from response to request. */
function cookieJar(): { cookies: CookieStore; jar: Map<string, string> } {
  const jar = new Map<string, string>();
  return {
    jar,
    cookies: {
      get: (name) => jar.get(name) ?? null,
      set: (name, value, options) => {
        if (options?.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
      },
    },
  };
}

const quiet: FidesLogger = { debug() {}, info() {}, warn() {}, error() {} };

function tokens(n: number, extra: Partial<TokenResponse> = {}): TokenResponse {
  return {
    access_token: `access-${n}`,
    token_type: 'bearer',
    expires_in: 300,
    refresh_token: `refresh-${n}`,
    id_token: new UnsecuredJWT({ iss: 'https://idp.test', sub: 'user-1', sid: 'idp-1', name: 'Ada' }).encode(),
    ...extra,
  };
}

/** An error shaped like openid-client's for a rejected refresh token. */
function invalidGrant(): Error {
  return Object.assign(new Error('invalid_grant'), {
    code: 'OAUTH_RESPONSE_BODY_ERROR',
    error: 'invalid_grant',
  });
}

interface StorageCase {
  make(): { storage: SessionStorage; store?: SessionStore };
  /**
   * What a read past expiresAt answers. A store drops an expired record with its
   * TTL (the memory store does on get), so store storage can then only say the
   * record is gone. Either way the session is over.
   */
  expiredReason: 'session_expired' | 'session_not_found';
}

const storages: Array<[string, StorageCase]> = [
  [
    'cookie storage',
    { make: () => ({ storage: cookieStorage({ secure: true }) }), expiredReason: 'session_expired' },
  ],
  [
    'store storage',
    {
      make: () => {
        const store = createMemorySessionStore();
        return { storage: storeStorage({ store, secure: true }), store };
      },
      expiredReason: 'session_not_found',
    },
  ],
];

afterEach(() => {
  vi.useRealTimers();
});

describe.each(storages)('the session lifecycle, with %s', (_, { make: makeStorage, expiredReason }) => {
  function setup(options: Partial<SessionLifecycleOptions> = {}) {
    const events: SessionEvent[] = [];
    const refreshTokens = vi.fn(async () => tokens(2));
    const { storage, store } = makeStorage();
    const lifecycle = createSessionLifecycle({
      storage,
      secret,
      refreshTokens,
      logger: quiet,
      onSessionEvent: (event) => events.push(event),
      ...options,
    });
    return { lifecycle, refreshTokens, events, store, ...cookieJar() };
  }

  it('reads back the session it created', async () => {
    const { lifecycle, cookies } = setup();
    const created = await lifecycle.create(cookies, tokens(1));

    expect(await lifecycle.read(cookies)).toEqual({ record: created });
    expect(created.session.user).toEqual({ sub: 'user-1', name: 'Ada', roles: [] });
  });

  it('hands the session back as it is when `unless` says it needs no refresh', async () => {
    const { lifecycle, cookies, refreshTokens, events } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    const seen: unknown[] = [];

    const skipped = await lifecycle.refresh(cookies, {
      unless: (record) => {
        seen.push(record);
        return true;
      },
    });
    expect(skipped).toEqual({ ok: true, record: created, rotatedRefreshToken: false, skipped: true });
    expect(seen).toEqual([created]);
    expect(refreshTokens).not.toHaveBeenCalled();
    expect(events.map((e) => e.event)).toEqual(['session.created']);

    const refreshed = await lifecycle.refresh(cookies, { unless: () => false });
    expect(refreshed).toMatchObject({ ok: true, rotatedRefreshToken: true });
    expect(refreshed).not.toHaveProperty('skipped');
  });

  it('rule 1: a login discards the session the browser arrived with', async () => {
    const { lifecycle, cookies } = setup();
    const first = await lifecycle.create(cookies, tokens(1));
    const second = await lifecycle.create(cookies, tokens(1));

    expect(second.session.correlationId).not.toBe(first.session.correlationId);
    expect((await lifecycle.read(cookies)).record?.session.correlationId).toBe(
      second.session.correlationId,
    );
  });

  it('rule 2: a session ends at expiresAt, whatever refreshes it had', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.parse('2026-11-14T12:00:00Z') });
    const { lifecycle, cookies } = setup({ sessionDurationSeconds: 1 * 86_400 });
    const created = await lifecycle.create(cookies, tokens(1));

    vi.setSystemTime(Date.now() + DAY / 2);
    const refreshed = await lifecycle.refresh(cookies);
    expect(refreshed.ok && refreshed.record.session.expiresAt).toBe(created.session.expiresAt);

    vi.setSystemTime(Date.now() + DAY);
    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: expiredReason });
  });

  it('rule 3: a refresh changes the tokens, never the identity or the lifetime', async () => {
    const { lifecycle, cookies, events } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    const result = await lifecycle.refresh(cookies);

    expect(result).toEqual({
      ok: true,
      rotatedRefreshToken: true,
      record: { v: 1, session: created.session, tokens: expect.objectContaining({ accessToken: 'access-2' }) },
    });
    expect((await lifecycle.read(cookies)).record?.tokens.refreshToken).toBe('refresh-2');
    expect(events.map((e) => [e.event, e.correlationId])).toEqual([
      ['session.created', created.session.correlationId],
      ['session.refreshed', created.session.correlationId],
    ]);
  });

  it('rule 3: an update changes the user and data, never the identity, lifetime or tokens', async () => {
    const { lifecycle, cookies } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    const updated = await lifecycle.update(cookies, (session) => ({
      ...session,
      correlationId: 'forged',
      expiresAt: '2999-01-01T00:00:00.000Z',
      data: { theme: 'dark' },
    }));

    expect(updated?.session).toEqual({ ...created.session, data: { theme: 'dark' } });
    expect(updated?.tokens).toEqual(created.tokens);
    expect(await lifecycle.read(cookies)).toEqual({ record: updated });
  });

  describe('rule 8: a refresh and an update of one session take turns', () => {
    /** A promise that waits until it is opened. */
    function gate() {
      let open = (): void => {};
      const closed = new Promise<void>((resolve) => {
        open = resolve;
      });
      return { closed, open };
    }

    it('an update that started before a refresh does not put the old tokens back', async () => {
      const { lifecycle, cookies, refreshTokens } = setup();
      await lifecycle.create(cookies, tokens(1));

      // The update has read the session and is still at work when the refresh comes.
      const working = gate();
      const started = gate();
      const updating = lifecycle.update(cookies, async (session) => {
        started.open();
        await working.closed;
        return { ...session, data: { theme: 'dark' } };
      });
      await started.closed;
      const refreshing = lifecycle.refresh(cookies);
      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(refreshTokens).not.toHaveBeenCalled();
      working.open();

      expect((await updating)?.tokens.refreshToken).toBe('refresh-1');
      expect(await refreshing).toMatchObject({ ok: true, rotatedRefreshToken: true });
      const { record } = await lifecycle.read(cookies);
      expect(record?.tokens).toMatchObject({ accessToken: 'access-2', refreshToken: 'refresh-2' });
      expect(record?.session.data).toEqual({ theme: 'dark' });
    });

    it('an update that comes during a refresh starts from what the refresh saved', async () => {
      const atProvider = gate();
      const asked = gate();
      const { lifecycle, cookies } = setup({
        refreshTokens: vi.fn(async () => {
          asked.open();
          await atProvider.closed;
          return tokens(2, { scope: 'openid' });
        }),
      });
      await lifecycle.create(cookies, tokens(1, { scope: 'openid profile' }));

      const refreshing = lifecycle.refresh(cookies);
      await asked.closed;
      const seen: Array<string[] | undefined> = [];
      const updating = lifecycle.update(cookies, (session) => {
        seen.push(session.scopes);
        return { ...session, data: { theme: 'dark' } };
      });
      await new Promise((resolve) => setTimeout(resolve, 5));
      expect(seen).toEqual([]);
      atProvider.open();

      expect(await refreshing).toMatchObject({ ok: true });
      expect((await updating)?.tokens.refreshToken).toBe('refresh-2');
      // The update got the session the refresh left, not the one from before it.
      expect(seen).toEqual([['openid']]);
      const { record } = await lifecycle.read(cookies);
      expect(record?.tokens.refreshToken).toBe('refresh-2');
      expect(record?.session).toMatchObject({ scopes: ['openid'], data: { theme: 'dark' } });
    });

    it('two updates at once both land', async () => {
      const { lifecycle, cookies } = setup();
      await lifecycle.create(cookies, tokens(1));

      await Promise.all([
        lifecycle.update(cookies, async (session) => {
          await new Promise((resolve) => setTimeout(resolve, 5));
          return { ...session, data: { ...session.data, first: true } };
        }),
        lifecycle.update(cookies, (session) => ({ ...session, data: { ...session.data, second: true } })),
      ]);

      expect((await lifecycle.read(cookies)).record?.session.data).toEqual({ first: true, second: true });
    });

    it('an update that throws does not hold up the next one', async () => {
      const { lifecycle, cookies } = setup();
      await lifecycle.create(cookies, tokens(1));

      await expect(
        lifecycle.update(cookies, () => {
          throw new Error('no');
        }),
      ).rejects.toThrow('no');
      const updated = await lifecycle.update(cookies, (session) => ({ ...session, data: { ok: true } }));
      expect(updated?.session.data).toEqual({ ok: true });
      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: true });
    });
  });

  describe('mapRefresh', () => {
    const refreshed = (claims: Record<string, unknown>) =>
      tokens(2, {
        scope: 'openid',
        id_token: new UnsecuredJWT({ iss: 'https://idp.test', sub: 'user-1', name: 'Ada L.', ...claims }).encode(),
      });

    it('changes the session a refresh leaves, from that refresh\'s tokens and claims', async () => {
      const mapRefresh = vi.fn<NonNullable<SessionLifecycleOptions['mapRefresh']>>((_tokens, claims, session) => ({
        ...session,
        data: { ...session.data, tenant: claims?.tenant },
      }));
      const { lifecycle, cookies } = setup({
        mapSession: (_tokens, _claims, session) => ({ ...session, data: { tenant: 'acme', theme: 'dark' } }),
        mapRefresh,
        refreshTokens: vi.fn(async () => refreshed({ tenant: 'globex' })),
      });
      const created = await lifecycle.create(cookies, tokens(1));
      expect(mapRefresh).not.toHaveBeenCalled();

      const result = await lifecycle.refresh(cookies);
      expect(result).toMatchObject({ ok: true, rotatedRefreshToken: true });
      expect(mapRefresh).toHaveBeenCalledTimes(1);
      const [got, claims, session] = mapRefresh.mock.calls[0]!;
      expect(got.access_token).toBe('access-2');
      expect(claims).toMatchObject({ sub: 'user-1', tenant: 'globex' });
      // The session after the library's own changes, with what login put in data.
      expect(session).toMatchObject({ user: { name: 'Ada L.' }, scopes: ['openid'], data: { tenant: 'acme' } });

      const { record } = await lifecycle.read(cookies);
      expect(record?.session.data).toEqual({ tenant: 'globex', theme: 'dark' });
      expect(record?.tokens.refreshToken).toBe('refresh-2');
      expect(record?.session.correlationId).toBe(created.session.correlationId);
    });

    it('can change the user and data, never the identity or the lifetime', async () => {
      const { lifecycle, cookies } = setup({
        mapRefresh: (_tokens, _claims, session) => ({
          ...session,
          correlationId: 'forged',
          expiresAt: '2999-01-01T00:00:00.000Z',
          idp: { iss: 'https://evil.test', sub: 'someone-else' },
          user: session.user && { ...session.user, roles: ['from-the-access-token'] },
        }),
      });
      const created = await lifecycle.create(cookies, tokens(1));
      await lifecycle.refresh(cookies);

      const { record } = await lifecycle.read(cookies);
      expect(record?.session).toMatchObject({
        correlationId: created.session.correlationId,
        expiresAt: created.session.expiresAt,
        idp: created.session.idp,
        user: { sub: 'user-1', roles: ['from-the-access-token'] },
      });
    });

    it('gets no claims from a refresh without an ID token', async () => {
      const mapRefresh = vi.fn<NonNullable<SessionLifecycleOptions['mapRefresh']>>((_tokens, _claims, session) => session);
      const { lifecycle, cookies } = setup({
        mapRefresh,
        refreshTokens: vi.fn(async () => tokens(2, { id_token: undefined })),
      });
      await lifecycle.create(cookies, tokens(1));
      await lifecycle.refresh(cookies);
      expect(mapRefresh.mock.calls[0]![1]).toBeUndefined();
    });

    it('cannot fail the refresh: a throw is logged, and the new tokens are saved', async () => {
      const error = vi.fn();
      const broken = new Error('the lookup failed');
      const { lifecycle, cookies, events } = setup({
        logger: { ...quiet, error },
        mapSession: (_tokens, _claims, session) => ({ ...session, data: { tenant: 'acme' } }),
        mapRefresh: async () => {
          throw broken;
        },
      });
      const created = await lifecycle.create(cookies, tokens(1));

      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: true, rotatedRefreshToken: true });
      const { record } = await lifecycle.read(cookies);
      expect(record?.tokens).toMatchObject({ accessToken: 'access-2', refreshToken: 'refresh-2' });
      expect(record?.session.data).toEqual({ tenant: 'acme' });
      expect(error).toHaveBeenCalledWith(
        { correlationId: created.session.correlationId, error: broken },
        expect.stringContaining('mapRefresh'),
      );
      expect(events.at(-1)).toMatchObject({ event: 'session.refreshed' });
    });

    it('runs only when the provider was asked: not at login, on an update or for a refresh that fails', async () => {
      const mapRefresh = vi.fn<NonNullable<SessionLifecycleOptions['mapRefresh']>>((_tokens, _claims, session) => session);
      const { lifecycle, cookies, refreshTokens } = setup({ mapRefresh });
      await lifecycle.create(cookies, tokens(1));
      await lifecycle.update(cookies, (session) => ({ ...session, data: { a: 1 } }));
      refreshTokens.mockRejectedValueOnce(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }));
      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: false, cause: 'transport' });
      expect(mapRefresh).not.toHaveBeenCalled();

      // Two refreshes at once share one call to the provider, and one mapRefresh.
      await Promise.all([lifecycle.refresh(cookies), lifecycle.refresh(cookies)]);
      expect(mapRefresh).toHaveBeenCalledTimes(1);
    });
  });

  describe('a call for the session from inside its own update or mapRefresh', () => {
    it('is refused at once, where it used to wait for itself', async () => {
      const { lifecycle, cookies, refreshTokens } = setup();
      await lifecycle.create(cookies, tokens(1));

      const attempts: Array<[string, () => Promise<unknown>]> = [
        ['A refresh', () => lifecycle.refresh(cookies)],
        ['An update', () => lifecycle.update(cookies, (session) => session)],
        ['An end of the session', () => lifecycle.end(cookies)],
      ];
      for (const [name, nested] of attempts) {
        const updating = lifecycle.update(cookies, async (session) => {
          await nested();
          return { ...session, data: { reached: true } };
        });
        await expect(updating).rejects.toThrow(TypeError);
        await expect(updating).rejects.toThrow(`${name} was called from inside updateSession`);
      }
      expect(refreshTokens).not.toHaveBeenCalled();

      // Nothing is left waiting: the session is as it was, and the next calls go through.
      expect((await lifecycle.read(cookies)).record?.session.data).toBeUndefined();
      expect(await lifecycle.update(cookies, (session) => ({ ...session, data: { ok: true } }))).not.toBeNull();
      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: true });
    });

    it('lets the update finish when its function handles the refusal', async () => {
      const { lifecycle, cookies } = setup();
      await lifecycle.create(cookies, tokens(1));

      let refusal: unknown;
      const updated = await lifecycle.update(cookies, async (session) => {
        refusal = await lifecycle.refresh(cookies).catch((error: unknown) => error);
        return { ...session, data: { theme: 'dark' } };
      });
      expect(refusal).toBeInstanceOf(TypeError);
      expect(updated?.session.data).toEqual({ theme: 'dark' });
    });

    it('is refused inside mapRefresh too, which is logged while the refresh goes through', async () => {
      const error = vi.fn();
      let lifecycle: ReturnType<typeof setup>['lifecycle'] | undefined;
      const made = setup({
        logger: { ...quiet, error },
        mapRefresh: async (_tokens, _claims, session) => {
          await lifecycle?.update(made.cookies, (current) => current);
          return session;
        },
      });
      lifecycle = made.lifecycle;
      await lifecycle.create(made.cookies, tokens(1));

      expect(await lifecycle.refresh(made.cookies)).toMatchObject({ ok: true, rotatedRefreshToken: true });
      expect(error).toHaveBeenCalledWith(
        expect.objectContaining({ error: expect.any(TypeError) }),
        expect.stringContaining('mapRefresh'),
      );
      expect((await lifecycle.read(made.cookies)).record?.tokens.refreshToken).toBe('refresh-2');
    });

    it('does not refuse what the function left running after it returned', async () => {
      const { lifecycle, cookies } = setup();
      await lifecycle.create(cookies, tokens(1));

      let later: Promise<unknown> = Promise.resolve();
      await lifecycle.update(cookies, (session) => {
        // Not awaited: it refreshes once the update is done.
        later = new Promise((resolve) => setTimeout(resolve, 10)).then(() => lifecycle.refresh(cookies));
        return session;
      });
      expect(await later).toMatchObject({ ok: true });
    });

    it('does not refuse a call for another session', async () => {
      const { lifecycle, cookies } = setup();
      const other = cookieJar();
      await lifecycle.create(cookies, tokens(1));
      await lifecycle.create(other.cookies, tokens(1));

      const updated = await lifecycle.update(cookies, async (session) => {
        expect(await lifecycle.refresh(other.cookies)).toMatchObject({ ok: true });
        return { ...session, data: { done: true } };
      });
      expect(updated?.session.data).toEqual({ done: true });
    });
  });

  it('rule 3: mapSession at login can change the user and data, not the identity', async () => {
    const { lifecycle, cookies } = setup({
      mapSession: async (_tokens, claims, session) => ({
        ...session,
        correlationId: 'forged',
        user: { sub: String(claims?.sub), name: 'Mapped' },
        data: { tenant: 't1' },
      }),
    });
    const created = await lifecycle.create(cookies, tokens(1));

    expect(created.session.correlationId).toMatch(/^[0-9a-f]{16}$/);
    expect(created.session.user).toEqual({ sub: 'user-1', name: 'Mapped' });
    expect(created.session.data).toEqual({ tenant: 't1' });
  });

  it('rule 3: a refresh with an ID token for someone else fails and saves nothing', async () => {
    const { lifecycle, cookies, refreshTokens, events } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    refreshTokens.mockResolvedValueOnce(
      tokens(2, { id_token: new UnsecuredJWT({ iss: 'https://idp.test', sub: 'user-2' }).encode() }),
    );

    expect(await lifecycle.refresh(cookies)).toEqual({
      ok: false,
      reason: 'refresh_failed',
      cause: 'idp_error',
      correlationId: created.session.correlationId,
    });
    expect((await lifecycle.read(cookies)).record).toEqual(created);
    expect(events.at(-1)).toMatchObject({ event: 'session.refresh_failed', cause: 'idp_error' });
  });

  it('rule 4: a session that does not open is unreadable, and is never read in part', async () => {
    const { lifecycle, cookies, jar } = setup();
    await lifecycle.create(cookies, tokens(1));
    const name = '__Host-session';
    const value = jar.get(name) ?? '';
    jar.set(name, value.startsWith('ey') ? `${value.slice(0, -4)}AAAA` : 'f'.repeat(64));

    const read = await lifecycle.read(cookies);
    expect(read.record).toBeNull();
    expect(['unreadable_session', 'session_not_found']).toContain(read.reason);
  });

  it('rule 4: a session in the legacy cookies is not read', async () => {
    const { lifecycle, cookies, jar } = setup();
    jar.set('session', 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.old');
    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'no_session_cookie' });
  });

  it('rule 5: concurrent refreshes in one process share one provider call', async () => {
    const { lifecycle, cookies, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));

    const [a, b] = await Promise.all([lifecycle.refresh(cookies), lifecycle.refresh(cookies)]);
    expect(refreshTokens).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
    expect(a.ok).toBe(true);
  });

  it('rule 6: the same reasons in both storages', async () => {
    const { lifecycle, cookies } = setup();
    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'no_session_cookie' });
    expect(await lifecycle.refresh(cookies)).toEqual({ ok: false, reason: 'no_session_cookie' });

    const created = await lifecycle.create(cookies, tokens(1, { refresh_token: undefined }));
    expect(await lifecycle.refresh(cookies)).toEqual({
      ok: false,
      reason: 'no_refresh_token',
      correlationId: created.session.correlationId,
    });
  });

  it('classifies a failed refresh, and keeps the session for a retry when the provider was down', async () => {
    const { lifecycle, cookies, refreshTokens, events } = setup();
    const created = await lifecycle.create(cookies, tokens(1));

    refreshTokens.mockRejectedValueOnce(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }));
    expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: false, reason: 'refresh_failed', cause: 'transport' });
    expect((await lifecycle.read(cookies)).record).toEqual(created);

    refreshTokens.mockRejectedValueOnce(invalidGrant());
    expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: false, cause: 'invalid_grant' });
    expect(events.filter((e) => e.event === 'session.refresh_failed')).toHaveLength(2);
  });

  it('ends the session, and names it in the event', async () => {
    const { lifecycle, cookies, events } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    await lifecycle.end(cookies, { trigger: 'logout' });

    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'no_session_cookie' });
    expect(events.at(-1)).toEqual({
      event: 'session.cleared',
      correlationId: created.session.correlationId,
      trigger: 'logout',
    });
    expect(await lifecycle.update(cookies, (s) => s)).toBeNull();
  });

  it('waits for a refresh still running, and ends the tokens it brought back', async () => {
    const { lifecycle, cookies, refreshTokens } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    let finish: (value: TokenResponse) => void = () => {};
    refreshTokens.mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)));

    // A prefetch refreshing in one request while the user logs out in another.
    const refreshing = lifecycle.refresh(cookies);
    await vi.waitFor(() => expect(refreshTokens).toHaveBeenCalled());
    const { cookies: logout, jar: logoutJar } = cookieJar();
    for (const name of ['__Host-session', '__Host-session.1', '__Host-session.2']) {
      const value = await cookies.get(name);
      if (value) logoutJar.set(name, value);
    }
    let endDone = false;
    const ending = lifecycle.end(logout, { trigger: 'logout' }).finally(() => {
      endDone = true;
    });
    // Long enough for the end to read the cookie and find the refresh, which it then waits for.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(endDone).toBe(false);
    finish(tokens(2));

    expect((await refreshing).ok).toBe(true);
    const ended = await ending;
    expect(ended?.session.correlationId).toBe(created.session.correlationId);
    expect(ended?.tokens.refreshToken).toBe('refresh-2');
    expect(await lifecycle.read(logout)).toEqual({ record: null, reason: 'no_session_cookie' });
  });

  it('keeps working when onSessionEvent throws', async () => {
    const { lifecycle, cookies } = setup({
      onSessionEvent: () => {
        throw new Error('consumer bug');
      },
    });
    await expect(lifecycle.create(cookies, tokens(1))).resolves.toBeDefined();
  });

  it('refuses a bad secret loudly instead of logging everyone out', async () => {
    const { lifecycle, cookies } = setup({ secret: 'too-short' });
    await expect(lifecycle.read(cookies)).rejects.toBeInstanceOf(SessionSecretError);
  });
});

describe('the session lifecycle, cookie storage only', () => {
  function setup(options: Partial<SessionLifecycleOptions> = {}) {
    let issued = 1;
    const events: SessionEvent[] = [];
    const refreshTokens = vi.fn(async (_refreshToken: string) => tokens(++issued));
    const lifecycle = createSessionLifecycle({
      storage: cookieStorage({ secure: true }),
      secret,
      refreshTokens,
      logger: quiet,
      onSessionEvent: (event) => events.push(event),
      ...options,
    });
    return { lifecycle, refreshTokens, events, ...cookieJar() };
  }

  /** A request the browser sent before a refresh's cookies arrived: the jar as it was then. */
  function sentBefore(jar: Map<string, string>) {
    const copy = cookieJar();
    for (const [name, value] of jar) copy.jar.set(name, value);
    return copy;
  }

  it('rejects a refresh whose cookies can\'t be read: without a store, that is the caller\'s mistake', async () => {
    const { lifecycle, refreshTokens, events } = setup();
    const outside = new Error('cookies() was called outside a request scope');
    const cookies: CookieStore = {
      get: () => {
        throw outside;
      },
      set: () => undefined,
    };

    await expect(lifecycle.refresh(cookies)).rejects.toBe(outside);
    expect(refreshTokens).not.toHaveBeenCalled();
    expect(events).toEqual([]);
  });

  it('an update from a request that still carries the old cookie keeps the refreshed tokens', async () => {
    const { lifecycle, cookies, jar, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const late = sentBefore(jar);
    const later = sentBefore(jar);
    await lifecycle.refresh(cookies);

    const updated = await lifecycle.update(late.cookies, (session) => ({ ...session, data: { theme: 'dark' } }));
    expect(updated?.tokens.refreshToken).toBe('refresh-2');
    // Whichever response the browser takes last, it holds the live refresh token.
    expect((await lifecycle.read(late.cookies)).record?.tokens.refreshToken).toBe('refresh-2');

    // Another request from before the refresh gets the update along with it.
    expect(await lifecycle.refresh(later.cookies)).toMatchObject({ ok: true });
    expect((await lifecycle.read(later.cookies)).record).toMatchObject({
      tokens: { refreshToken: 'refresh-2' },
      session: { data: { theme: 'dark' } },
    });
    expect(refreshTokens).toHaveBeenCalledTimes(1);
  });

  it('hands a request that still carries the old cookie the refresh that was just done', async () => {
    const { lifecycle, cookies, jar, refreshTokens, events } = setup();
    await lifecycle.create(cookies, tokens(1));
    const late = sentBefore(jar);
    const first = await lifecycle.refresh(cookies);

    const second = await lifecycle.refresh(late.cookies);
    expect(second).toEqual(first);
    expect(second).toMatchObject({ ok: true, rotatedRefreshToken: true });
    expect(refreshTokens).toHaveBeenCalledTimes(1);
    // The late request's response carries the new cookies too.
    expect((await lifecycle.read(late.cookies)).record?.tokens.refreshToken).toBe('refresh-2');
    expect(events.filter((event) => event.event === 'session.refreshed')).toHaveLength(1);
  });

  it('refreshes again for a request that carries the new cookie', async () => {
    const { lifecycle, cookies, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    await lifecycle.refresh(cookies);
    await lifecycle.refresh(cookies);
    expect(refreshTokens.mock.calls.map(([token]) => token)).toEqual(['refresh-1', 'refresh-2']);
  });

  it('sends the old token again once the grace period is over', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.parse('2026-11-14T12:00:00Z') });
    const { lifecycle, cookies, jar, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const late = sentBefore(jar);
    await lifecycle.refresh(cookies);

    vi.setSystemTime(Date.now() + 9_000);
    expect((await lifecycle.refresh(sentBefore(late.jar).cookies)).ok).toBe(true);
    expect(refreshTokens).toHaveBeenCalledTimes(1);

    vi.setSystemTime(Date.now() + 2_000);
    refreshTokens.mockRejectedValueOnce(invalidGrant());
    expect(await lifecycle.refresh(late.cookies)).toMatchObject({ ok: false, cause: 'invalid_grant' });
    expect(refreshTokens.mock.calls.map(([token]) => token)).toEqual(['refresh-1', 'refresh-1']);
  });

  it('keeps the result no longer than its access token lasts', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.parse('2026-11-14T12:00:00Z') });
    const { lifecycle, cookies, jar, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const late = sentBefore(jar);
    refreshTokens.mockResolvedValueOnce(tokens(2, { expires_in: 5 }));
    await lifecycle.refresh(cookies);

    vi.setSystemTime(Date.now() + 6_000);
    await lifecycle.refresh(late.cookies);
    expect(refreshTokens).toHaveBeenCalledTimes(2);
  });

  it('does not keep a refresh that left the refresh token as it was', async () => {
    const { lifecycle, cookies, jar, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const late = sentBefore(jar);
    refreshTokens.mockResolvedValueOnce(tokens(2, { refresh_token: 'refresh-1' }));
    await lifecycle.refresh(cookies);

    // Without rotation the old cookie's token still works, and a forced refresh must reach the provider.
    await lifecycle.refresh(late.cookies);
    expect(refreshTokens).toHaveBeenCalledTimes(2);
  });

  it('can be turned off', async () => {
    const { lifecycle, cookies, jar, refreshTokens } = setup({ refreshGraceSeconds: 0 });
    await lifecycle.create(cookies, tokens(1));
    const late = sentBefore(jar);
    await lifecycle.refresh(cookies);
    await lifecycle.refresh(late.cookies);
    expect(refreshTokens.mock.calls.map(([token]) => token)).toEqual(['refresh-1', 'refresh-1']);
  });

  it('needs a number of seconds, 0 or more', () => {
    for (const refreshGraceSeconds of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => setup({ refreshGraceSeconds })).toThrow(TypeError);
    }
  });

  it('ends the tokens of a refresh that finished just before a logout with the old cookie', async () => {
    const { lifecycle, cookies, jar, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const logout = sentBefore(jar);
    const straggler = sentBefore(jar);
    await lifecycle.refresh(cookies);

    const ended = await lifecycle.end(logout.cookies, { trigger: 'logout' });
    expect(ended?.tokens.refreshToken).toBe('refresh-2');

    // The session is over: nothing is handed on after it.
    refreshTokens.mockRejectedValueOnce(invalidGrant());
    expect(await lifecycle.refresh(straggler.cookies)).toMatchObject({ ok: false, cause: 'invalid_grant' });
    expect(refreshTokens).toHaveBeenCalledTimes(2);
  });
});

describe('the session lifecycle, store storage only', () => {
  function setup() {
    const store = createMemorySessionStore();
    const refreshTokens = vi.fn(async () => tokens(2));
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens,
      logger: quiet,
    });
    return { store, lifecycle, refreshTokens, ...cookieJar() };
  }

  it('an update on one instance and a refresh on another take turns under the store\'s lock', async () => {
    const { store, lifecycle, cookies } = setup();
    const other = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: vi.fn(async () => tokens(2)),
      logger: quiet,
    });
    await lifecycle.create(cookies, tokens(1));

    let finish = (): void => {};
    const working = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let started = (): void => {};
    const begun = new Promise<void>((resolve) => {
      started = resolve;
    });
    const updating = lifecycle.update(cookies, async (session) => {
      started();
      await working;
      return { ...session, data: { theme: 'dark' } };
    });
    await begun;
    const refreshing = other.refresh(cookies);
    await new Promise((resolve) => setTimeout(resolve, 5));
    finish();

    await updating;
    expect(await refreshing).toMatchObject({ ok: true, rotatedRefreshToken: true });
    const { record } = await lifecycle.read(cookies);
    expect(record?.tokens.refreshToken).toBe('refresh-2');
    expect(record?.session.data).toEqual({ theme: 'dark' });
  });

  it('reports a store that can\'t lock as a failed refresh, and rejects an update with what the store threw', async () => {
    const base = setup();
    const down = new Error('lock timeout');
    let failing = false;
    const store: SessionStore = {
      ...base.store,
      withLock: (key, fn) => (failing ? Promise.reject(down) : (base.store.withLock?.(key, fn) ?? fn())),
    };
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: base.refreshTokens,
      logger: quiet,
    });
    const created = await lifecycle.create(base.cookies, tokens(1));
    failing = true;

    // A refresh is asked for on the way to something else, so it answers.
    expect(await lifecycle.refresh(base.cookies)).toMatchObject({ ok: false, reason: 'refresh_failed', cause: 'store' });
    // An update is the caller's own write: that it didn't happen is an error, not "no session".
    await expect(lifecycle.update(base.cookies, (session) => ({ ...session, data: { a: 1 } }))).rejects.toBe(down);

    failing = false;
    expect((await lifecycle.read(base.cookies)).record).toEqual(created);
  });

  describe('a refresh the provider refuses for good', () => {
    /** A lifecycle over `store`, with its events, and a jar that counts its writes. */
    function over(store: SessionStore) {
      const events: SessionEvent[] = [];
      const refreshTokens = vi.fn(async () => tokens(2));
      const lifecycle = createSessionLifecycle({
        storage: storeStorage({ store, secure: true }),
        secret,
        refreshTokens,
        logger: quiet,
        onSessionEvent: (event) => events.push(event),
      });
      const { cookies, jar } = cookieJar();
      const set = vi.spyOn(cookies, 'set');
      return { lifecycle, refreshTokens, events, cookies, jar, set };
    }

    it('ends the session under a store that locks, and deletes its cookie', async () => {
      const { lifecycle, refreshTokens, events, cookies, jar, set } = over(createMemorySessionStore());
      const created = await lifecycle.create(cookies, tokens(1));
      set.mockClear();
      refreshTokens.mockRejectedValueOnce(invalidGrant());

      expect(await lifecycle.refresh(cookies)).toEqual({
        ok: false,
        reason: 'refresh_failed',
        cause: 'invalid_grant',
        correlationId: created.session.correlationId,
        ended: true,
      });
      expect(events.slice(-2)).toMatchObject([
        { event: 'session.refresh_failed', cause: 'invalid_grant' },
        { event: 'session.cleared', correlationId: created.session.correlationId, trigger: 'rejected' },
      ]);
      // The browser stops sending a handle that finds nothing.
      expect(set).toHaveBeenCalledTimes(1);
      expect(set).toHaveBeenCalledWith('__Host-session', '', expect.objectContaining({ maxAge: 0, path: '/' }));
      expect(jar.size).toBe(0);
      expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'no_session_cookie' });
    });

    it('ends the session all the same where cookies can only be read', async () => {
      const store = createMemorySessionStore();
      const { lifecycle, refreshTokens, events, cookies, jar, set } = over(store);
      const created = await lifecycle.create(cookies, tokens(1));
      // A Next Server Component: a write throws.
      set.mockImplementation(() => {
        throw new Error('Cookies can only be modified in a Server Action or Route Handler');
      });
      refreshTokens.mockRejectedValueOnce(invalidGrant());

      expect(await lifecycle.refresh(cookies)).toEqual({
        ok: false,
        reason: 'refresh_failed',
        cause: 'invalid_grant',
        correlationId: created.session.correlationId,
        ended: true,
      });
      expect(events.at(-1)).toMatchObject({ event: 'session.cleared', trigger: 'rejected' });
      // The handle stays, and finds nothing.
      expect(jar.get('__Host-session')).toMatch(/^[0-9a-f]{64}$/);
      expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'session_not_found' });
    });

    /** Another request from the same browser: its own jar, with the same handle. */
    function sameBrowser(jar: Map<string, string>) {
      const copy = cookieJar();
      for (const [name, value] of jar) copy.jar.set(name, value);
      return copy;
    }

    it('deletes the cookie on every request that shared the refresh, not only the first', async () => {
      const { lifecycle, refreshTokens, cookies, jar } = over(createMemorySessionStore());
      await lifecycle.create(cookies, tokens(1));
      const second = sameBrowser(jar);
      const third = sameBrowser(jar);
      let refuse: (error: Error) => void = () => {};
      refreshTokens.mockImplementationOnce(() => new Promise((_, reject) => (refuse = reject)));

      const first = lifecycle.refresh(cookies);
      await vi.waitFor(() => expect(refreshTokens).toHaveBeenCalled());
      const others = [lifecycle.refresh(second.cookies), lifecycle.refresh(third.cookies)];
      // Let the others read the session and join the refresh that is running.
      await new Promise((resolve) => setTimeout(resolve, 5));
      refuse(invalidGrant());

      for (const result of [await first, ...(await Promise.all(others))]) {
        expect(result).toMatchObject({ ok: false, cause: 'invalid_grant' });
      }
      expect(refreshTokens).toHaveBeenCalledTimes(1);
      expect(jar.size).toBe(0);
      expect(second.jar.size).toBe(0);
      expect(third.jar.size).toBe(0);
    });

    it('deletes the cookie on another instance that waited for the lock and found the record gone', async () => {
      const store = createMemorySessionStore();
      const here = over(store);
      const there = over(store);
      await here.lifecycle.create(here.cookies, tokens(1));
      for (const [name, value] of here.jar) there.jar.set(name, value);
      let refuse: (error: Error) => void = () => {};
      here.refreshTokens.mockImplementationOnce(() => new Promise((_, reject) => (refuse = reject)));

      const first = here.lifecycle.refresh(here.cookies);
      await vi.waitFor(() => expect(here.refreshTokens).toHaveBeenCalled());
      const waiting = there.lifecycle.refresh(there.cookies);
      await new Promise((resolve) => setTimeout(resolve, 5));
      refuse(invalidGrant());

      expect(await first).toMatchObject({ ok: false, cause: 'invalid_grant' });
      expect(await waiting).toMatchObject({ ok: false, reason: 'session_not_found' });
      // It never asked the provider: the session was gone when its turn came.
      expect(there.refreshTokens).not.toHaveBeenCalled();
      expect(here.jar.size).toBe(0);
      expect(there.jar.size).toBe(0);
    });

    it('leaves the cookie of a request that comes after, which only sees that the record is missing', async () => {
      const { lifecycle, refreshTokens, cookies, jar } = over(createMemorySessionStore());
      await lifecycle.create(cookies, tokens(1));
      const later = sameBrowser(jar);
      refreshTokens.mockRejectedValueOnce(invalidGrant());
      await lifecycle.refresh(cookies);

      // A missing record can also be a store that lost it for a moment. The
      // request has no session either way; only the cookie is left alone.
      expect(await lifecycle.refresh(later.cookies)).toEqual({ ok: false, reason: 'session_not_found' });
      expect(later.jar.get('__Host-session')).toMatch(/^[0-9a-f]{64}$/);
    });

    it('leaves the session under a store without a lock, where another instance may have refreshed', async () => {
      const { lifecycle, refreshTokens, events, cookies } = over({
        ...createMemorySessionStore(),
        withLock: undefined,
      });
      const created = await lifecycle.create(cookies, tokens(1));
      refreshTokens.mockRejectedValueOnce(invalidGrant());

      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: false, cause: 'invalid_grant' });
      expect((await lifecycle.read(cookies)).record).toEqual(created);
      expect(events.some((event) => event.event === 'session.cleared')).toBe(false);
    });

    it('keeps the session when the provider could not be reached', async () => {
      const { lifecycle, refreshTokens, cookies } = over(createMemorySessionStore());
      const created = await lifecycle.create(cookies, tokens(1));
      refreshTokens.mockRejectedValueOnce(
        Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }),
      );

      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: false, cause: 'transport' });
      expect((await lifecycle.read(cookies)).record).toEqual(created);
    });
  });

  it('stores the lookup fields as keyed hashes, never sub itself', async () => {
    const { store, lifecycle, cookies, jar } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    const { sha256 } = await import('../session/utils.js');
    const stored = await store.get(await sha256(jar.get('__Host-session') ?? ''));

    expect(stored).toMatchObject({
      correlationId: created.session.correlationId,
      iss: 'https://idp.test',
      subHash: expect.stringMatching(/^[0-9a-f]{64}$/),
      idpSidHash: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(JSON.stringify(stored)).not.toContain('user-1');
  });

  /** A second instance over the same store, and a copy of the browser's cookie for it. */
  async function otherInstance(store: SessionStore, cookies: CookieStore) {
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: async () => tokens(9),
      logger: quiet,
    });
    const copy = cookieJar();
    copy.jar.set('__Host-session', (await cookies.get('__Host-session')) ?? '');
    return { lifecycle, cookies: copy.cookies };
  }

  /** Makes the next refresh wait until `finish` is called. */
  function holdRefresh(refreshTokens: ReturnType<typeof setup>['refreshTokens']) {
    let finish: (value: TokenResponse) => void = () => {};
    refreshTokens.mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)));
    return (value: TokenResponse) => finish(value);
  }

  it('ends the session after a refresh on another instance, under the lock, with its tokens', async () => {
    const { store, lifecycle, cookies, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const finish = holdRefresh(refreshTokens);

    const refreshing = lifecycle.refresh(cookies);
    await vi.waitFor(() => expect(refreshTokens).toHaveBeenCalled());
    const other = await otherInstance(store, cookies);
    const ending = other.lifecycle.end(other.cookies, { trigger: 'logout' });
    finish(tokens(2));

    expect((await refreshing).ok).toBe(true);
    expect((await ending)?.tokens.refreshToken).toBe('refresh-2');
    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'session_not_found' });
  });

  it('does not bring back a session ended between its check and its write, without a lock', async () => {
    // Without a lock the library can only check that the record is there and
    // then write. A logout on another instance can land in between, and it is
    // the store that must not create the record again.
    const { lifecycle: _, ...base } = setup();
    let logoutElsewhere = false;
    const store: SessionStore = {
      ...base.store,
      withLock: undefined,
      set: (key, record, context) => {
        if (logoutElsewhere) void base.store.delete(key);
        return base.store.set(key, record, context);
      },
    };
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: base.refreshTokens,
      logger: quiet,
    });
    await lifecycle.create(base.cookies, tokens(1));
    logoutElsewhere = true;

    await lifecycle.refresh(base.cookies);
    logoutElsewhere = false;
    expect(await lifecycle.read(base.cookies)).toEqual({ record: null, reason: 'session_not_found' });

    await lifecycle.create(base.cookies, tokens(1));
    logoutElsewhere = true;
    await lifecycle.update(base.cookies, (session) => ({ ...session, data: { a: 1 } }));
    logoutElsewhere = false;
    expect(await lifecycle.read(base.cookies)).toEqual({ record: null, reason: 'session_not_found' });
  });

  it('does not bring back a session another instance ended while its refresh ran, without a lock', async () => {
    const { lifecycle: _, ...base } = setup();
    const store: SessionStore = { ...base.store, withLock: undefined };
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: base.refreshTokens,
      logger: quiet,
    });
    const { cookies, refreshTokens } = base;
    await lifecycle.create(cookies, tokens(1));
    const finish = holdRefresh(refreshTokens);

    const refreshing = lifecycle.refresh(cookies);
    await vi.waitFor(() => expect(refreshTokens).toHaveBeenCalled());
    const other = await otherInstance(store, cookies);
    await other.lifecycle.end(other.cookies);
    finish(tokens(2));

    expect(await refreshing).toMatchObject({ ok: false, reason: 'session_not_found' });
    // The refresh found the session ended, so its request loses the cookie too.
    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'no_session_cookie' });
  });

  it.each([
    ['with', (store: SessionStore) => store],
    ['without', (store: SessionStore): SessionStore => ({ ...store, withLock: undefined })],
  ])('takes a concurrent refresh from another instance instead of spending the token again, %s a lock', async (_, adapt) => {
    const base = setup();
    const store = adapt(base.store);
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: base.refreshTokens,
      logger: quiet,
    });
    const { cookies, refreshTokens, jar } = base;
    const created = await lifecycle.create(cookies, tokens(1));
    const { sha256 } = await import('../session/utils.js');
    const key = await sha256(jar.get('__Host-session') ?? '');

    // Another instance refreshed first and rotated the token; this one gets invalid_grant.
    refreshTokens.mockImplementationOnce(async () => {
      const stored = await store.get(key);
      const rotated = { ...created, tokens: { ...created.tokens, accessToken: 'other', refreshToken: 'refresh-x' } };
      await store.set(key, { ...stored!, data: await sealRecord(rotated, secret) }, { continuation: true, reason: 'refresh' });
      throw invalidGrant();
    });

    const result = await lifecycle.refresh(cookies);
    expect(result).toMatchObject({ ok: true, rotatedRefreshToken: true });
    expect(result.ok && result.record.tokens.accessToken).toBe('other');
  });

  it('hands the store the app\'s fields, and says whether the session is new', async () => {
    const store = createMemorySessionStore();
    const set = vi.spyOn(store, 'set');
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens: async () => tokens(2),
      storeFields: (session) => ({ name: session.user?.name ?? null, team: (session.data?.team as string) ?? null }),
      logger: quiet,
    });
    const { cookies } = cookieJar();

    await lifecycle.create(cookies, tokens(1));
    await lifecycle.refresh(cookies);
    await lifecycle.update(cookies, (session) => ({ ...session, data: { team: 'blue' } }));

    expect(set.mock.calls.map(([, record, context]) => [record.fields, context])).toEqual([
      [{ name: 'Ada', team: null }, { continuation: false, reason: 'login' }],
      [{ name: 'Ada', team: null }, { continuation: true, reason: 'refresh' }],
      [{ name: 'Ada', team: 'blue' }, { continuation: true, reason: 'update' }],
    ]);
    // One key throughout: a refresh and an update keep the handle.
    expect(new Set(set.mock.calls.map(([key]) => key)).size).toBe(1);
  });

  it('leaves fields out without storeFields', async () => {
    const { store, lifecycle, cookies } = setup();
    const set = vi.spyOn(store, 'set');
    await lifecycle.create(cookies, tokens(1));
    expect(set.mock.calls[0]?.[1]).not.toHaveProperty('fields');
  });

  describe('endMatching', () => {
    const forUser = (sub: string, sid: string) =>
      tokens(1, {
        refresh_token: `refresh-${sid}`,
        id_token: new UnsecuredJWT({ iss: 'https://idp.test', sub, sid }).encode(),
      });

    /** Ada signed in on a laptop and a phone, and Bob once. */
    async function threeSessions(adapt: (store: SessionStore) => SessionStore = (store) => store) {
      const base = setup();
      const events: SessionEvent[] = [];
      const lifecycle = createSessionLifecycle({
        storage: storeStorage({ store: adapt(base.store), secure: true }),
        secret,
        refreshTokens: base.refreshTokens,
        logger: quiet,
        onSessionEvent: (event) => events.push(event),
      });
      const laptop = cookieJar();
      const phone = cookieJar();
      const bob = cookieJar();
      await lifecycle.create(laptop.cookies, forUser('ada', 'sid-laptop'));
      await lifecycle.create(phone.cookies, forUser('ada', 'sid-phone'));
      await lifecycle.create(bob.cookies, forUser('bob', 'sid-bob'));
      return { ...base, lifecycle, events, laptop, phone, bob };
    }

    it('ends every session of one user, and hands back their tokens', async () => {
      const { lifecycle, events, laptop, phone, bob } = await threeSessions();

      const ended = await lifecycle.endMatching({ iss: 'https://idp.test', sub: 'ada' }, { trigger: 'logout' });

      expect(ended.map((record) => record.tokens.refreshToken).sort()).toEqual([
        'refresh-sid-laptop',
        'refresh-sid-phone',
      ]);
      expect(await lifecycle.read(laptop.cookies)).toEqual({ record: null, reason: 'session_not_found' });
      expect(await lifecycle.read(phone.cookies)).toEqual({ record: null, reason: 'session_not_found' });
      expect((await lifecycle.read(bob.cookies)).record?.session.idp?.sub).toBe('bob');
      expect(events.filter((event) => event.event === 'session.cleared')).toHaveLength(2);
    });

    it('ends one IdP session by its sid, and asks the store only for the keys to compare', async () => {
      const { store, lifecycle, laptop, phone } = await threeSessions();
      const find = vi.spyOn(store, 'findMatching');
      const ended = await lifecycle.endMatching({ iss: 'https://idp.test', sid: 'sid-phone' });
      expect(ended).toHaveLength(1);
      expect(Object.keys(find.mock.calls[0]?.[0] ?? {})).toEqual(['iss', 'idpSidHash']);
      expect((await lifecycle.read(laptop.cookies)).record).not.toBeNull();
      expect((await lifecycle.read(phone.cookies)).record).toBeNull();
    });

    it('finds nothing for another issuer or an unknown user', async () => {
      const { lifecycle } = await threeSessions();
      expect(await lifecycle.endMatching({ iss: 'https://other.test', sub: 'ada' })).toEqual([]);
      expect(await lifecycle.endMatching({ iss: 'https://idp.test', sub: 'eve' })).toEqual([]);
    });

    it('leaves alone a session the store returns that does not match', async () => {
      const { store, refreshTokens, bob } = await threeSessions();
      // An adapter whose search ignores the hashes and returns the issuer's every session.
      const sloppy: SessionStore = {
        ...store,
        findMatching: ({ iss }) => store.findMatching?.({ iss }) ?? [],
      };
      const lifecycle = createSessionLifecycle({
        storage: storeStorage({ store: sloppy, secure: true }),
        secret,
        refreshTokens,
        logger: quiet,
      });

      const ended = await lifecycle.endMatching({ iss: 'https://idp.test', sub: 'ada' });
      expect(ended).toHaveLength(2);
      expect((await lifecycle.read(bob.cookies)).record?.session.idp?.sub).toBe('bob');
    });

    it('finds a user by sub alone, and narrows to one issuer only when it is named', async () => {
      const { store, lifecycle, refreshTokens, laptop } = await threeSessions();
      const find = vi.spyOn(store, 'findMatching');

      // An adapter whose search ignores the issuer: the sealed record still decides.
      const sloppy: SessionStore = {
        ...store,
        findMatching: ({ iss: _iss, ...rest }) => store.findMatching?.(rest) ?? [],
      };
      const lenient = createSessionLifecycle({
        storage: storeStorage({ store: sloppy, secure: true }),
        secret,
        refreshTokens,
        logger: quiet,
      });
      expect(await lenient.endMatching({ iss: 'https://IDP.test', sub: 'ada' })).toEqual([]);
      expect((await lifecycle.read(laptop.cookies)).record).not.toBeNull();

      expect(await lifecycle.endMatching({ sub: 'ada' })).toHaveLength(2);
      expect(Object.keys(find.mock.calls.at(-1)?.[0] ?? {})).toEqual(['subHash']);
      expect((await lifecycle.read(laptop.cookies)).record).toBeNull();
    });

    // With a lock the delete queues behind the refresh; without one, the wait in this process does it.
    it.each([
      ['with', (store: SessionStore) => store],
      ['without', (store: SessionStore): SessionStore => ({ ...store, withLock: undefined })],
    ])('waits for a refresh still running, and ends the tokens it brought back, %s a lock', async (_, adapt) => {
      const { lifecycle, refreshTokens, laptop } = await threeSessions(adapt);
      const finish = holdRefresh(refreshTokens);

      const refreshing = lifecycle.refresh(laptop.cookies);
      await vi.waitFor(() => expect(refreshTokens).toHaveBeenCalled());
      const ending = lifecycle.endMatching({ iss: 'https://idp.test', sub: 'ada' });
      // Long enough for the search to find the refresh, which it then waits for.
      await new Promise((resolve) => setTimeout(resolve, 50));
      finish({ ...forUser('ada', 'sid-laptop'), access_token: 'access-2', refresh_token: 'refresh-rotated' });

      expect((await refreshing).ok).toBe(true);
      expect((await ending).map((record) => record.tokens.refreshToken).sort()).toEqual([
        'refresh-rotated',
        'refresh-sid-phone',
      ]);
      expect((await lifecycle.read(laptop.cookies)).record).toBeNull();
    });

    it('needs a store that can search, and a sub or a sid', async () => {
      const { store, lifecycle, refreshTokens } = setup();
      await expect(lifecycle.endMatching({ iss: 'https://idp.test' })).rejects.toThrow(TypeError);

      const cannotSearch = createSessionLifecycle({
        storage: storeStorage({ store: { ...store, findMatching: undefined }, secure: true }),
        secret,
        refreshTokens,
        logger: quiet,
      });
      await expect(cannotSearch.endMatching({ iss: 'https://idp.test', sub: 'ada' })).rejects.toThrow(
        /needs a sessionStore with findMatching/,
      );

      const inCookies = createSessionLifecycle({
        storage: cookieStorage({ secure: true }),
        secret,
        refreshTokens,
        logger: quiet,
      });
      await expect(inCookies.endMatching({ iss: 'https://idp.test', sub: 'ada' })).rejects.toThrow(TypeError);
    });
  });

  it('reads the new tokens for a request that still carries the handle, with nothing kept in the process', async () => {
    const { lifecycle, cookies, jar, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    const late = cookieJar();
    late.jar.set('__Host-session', jar.get('__Host-session') ?? '');
    await lifecycle.refresh(cookies);

    // A forced refresh reaches the provider, with the token the store holds now.
    refreshTokens.mockResolvedValueOnce(tokens(3));
    await lifecycle.refresh(late.cookies);
    expect(refreshTokens.mock.calls.map(([token]) => token)).toEqual(['refresh-1', 'refresh-2']);
  });

  describe.each([
    ['with', (store: SessionStore): SessionStore => store],
    ['without', (store: SessionStore): SessionStore => ({ ...store, withLock: undefined })],
  ])('a store that can\'t be reached, %s a lock', (_, locking) => {
    function failing(broken: 'get' | 'set') {
      const base = createMemorySessionStore();
      const down = new Error('db down');
      const state = { down: false };
      const store = locking({
        ...base,
        get: async (key) => {
          if (state.down && broken === 'get') throw down;
          return base.get(key);
        },
        set: async (key, record, context) => {
          if (state.down && broken === 'set') throw down;
          return base.set(key, record, context);
        },
      });
      const events: SessionEvent[] = [];
      const refreshTokens = vi.fn(async () => tokens(2));
      const lifecycle = createSessionLifecycle({
        storage: storeStorage({ store, secure: true }),
        secret,
        refreshTokens,
        logger: quiet,
        onSessionEvent: (event) => events.push(event),
      });
      return { lifecycle, refreshTokens, events, state, down, ...cookieJar() };
    }

    it('fails a refresh that can\'t read the session as a store failure, before the provider is asked', async () => {
      const { lifecycle, refreshTokens, events, state, cookies } = failing('get');
      const created = await lifecycle.create(cookies, tokens(1));
      state.down = true;

      expect(await lifecycle.refresh(cookies)).toEqual({ ok: false, reason: 'refresh_failed', cause: 'store' });
      expect(await lifecycle.refresh(cookies, { unless: () => true })).toMatchObject({ ok: false, cause: 'store' });
      expect(refreshTokens).not.toHaveBeenCalled();
      expect(events.at(-1)).toMatchObject({
        event: 'session.refresh_failed',
        cause: 'store',
        error: { message: 'db down' },
      });

      state.down = false;
      expect((await lifecycle.read(cookies)).record).toEqual(created);
      expect(await lifecycle.refresh(cookies)).toMatchObject({ ok: true });
    });

    it('fails a refresh that can\'t save the new tokens as a store failure', async () => {
      const { lifecycle, events, state, cookies } = failing('set');
      const created = await lifecycle.create(cookies, tokens(1));
      state.down = true;

      expect(await lifecycle.refresh(cookies)).toEqual({
        ok: false,
        reason: 'refresh_failed',
        cause: 'store',
        correlationId: created.session.correlationId,
      });
      expect(events.at(-1)).toMatchObject({ event: 'session.refresh_failed', cause: 'store' });
    });

    it('still rejects a read with what the store threw', async () => {
      const { lifecycle, state, down, cookies } = failing('get');
      await lifecycle.create(cookies, tokens(1));
      state.down = true;

      await expect(lifecycle.read(cookies)).rejects.toBe(down);
    });
  });

  it('fails a refresh whose lock it can\'t take as a store failure, and keeps the session', async () => {
    const events: SessionEvent[] = [];
    const store: SessionStore = {
      ...createMemorySessionStore(),
      withLock: async () => {
        throw new Error('lock timeout');
      },
    };
    const refreshTokens = vi.fn(async () => tokens(2));
    const lifecycle = createSessionLifecycle({
      storage: storeStorage({ store, secure: true }),
      secret,
      refreshTokens,
      logger: quiet,
      onSessionEvent: (event) => events.push(event),
    });
    const { cookies } = cookieJar();
    const created = await lifecycle.create(cookies, tokens(1));

    expect(await lifecycle.refresh(cookies)).toEqual({
      ok: false,
      reason: 'refresh_failed',
      cause: 'store',
      correlationId: created.session.correlationId,
    });
    expect(refreshTokens).not.toHaveBeenCalled();
    expect(events.at(-1)).toMatchObject({
      event: 'session.refresh_failed',
      cause: 'store',
      error: { message: 'lock timeout' },
    });
    expect((await lifecycle.read(cookies)).record).toEqual(created);
  });
});
