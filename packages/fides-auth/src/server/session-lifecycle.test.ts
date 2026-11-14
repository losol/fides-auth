/**
 * The 1.0 lifecycle rules, run against both storages (ADR 0001 §2, "One
 * session model"). A rule that holds for one storage must hold for the other;
 * the few store-only behaviours are at the end.
 */
import { UnsecuredJWT } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import type { SessionEvent } from '../shared/session-events.js';
import type { TokenResponse } from '../shared/types.js';
import { sealRecord } from '../session/record.js';
import type { CookieStore } from './cookie-store.js';
import { createSessionLifecycle, type SessionLifecycleOptions } from './session-lifecycle.js';
import { SessionSecretError } from './session-persistence.js';
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
      delete: () => {
        throw new Error('the 1.0 storages delete with set and maxAge 0');
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
    const { lifecycle, cookies } = setup({ sessionDurationDays: 1 });
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
    expect(events.map((e) => [e.event, e.sid])).toEqual([
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

  it('rule 4: a 0.x session is not read', async () => {
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
      sid: created.session.correlationId,
      trigger: 'logout',
    });
    expect(await lifecycle.update(cookies, (s) => s)).toBeNull();
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

  it('does not bring back a session that ended while its refresh ran', async () => {
    const { lifecycle, cookies, refreshTokens } = setup();
    await lifecycle.create(cookies, tokens(1));
    let finish: (value: TokenResponse) => void = () => {};
    refreshTokens.mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)));

    const refreshing = lifecycle.refresh(cookies);
    await vi.waitFor(() => expect(refreshTokens).toHaveBeenCalled());
    const { cookies: other, jar: otherJar } = cookieJar();
    otherJar.set('__Host-session', await cookies.get('__Host-session') ?? '');
    await lifecycle.end(other);
    finish(tokens(2));

    expect(await refreshing).toMatchObject({ ok: false, reason: 'session_not_found' });
    expect(await lifecycle.read(cookies)).toEqual({ record: null, reason: 'session_not_found' });
  });

  it('takes a concurrent refresh from another instance instead of spending the token again', async () => {
    const { lifecycle, cookies, refreshTokens, store, jar } = setup();
    const created = await lifecycle.create(cookies, tokens(1));
    const { sha256 } = await import('../session/utils.js');
    const key = await sha256(jar.get('__Host-session') ?? '');

    // Another instance refreshed first and rotated the token; this one gets invalid_grant.
    refreshTokens.mockImplementationOnce(async () => {
      const stored = await store.get(key);
      const rotated = { ...created, tokens: { ...created.tokens, accessToken: 'other', refreshToken: 'refresh-x' } };
      await store.set(key, { ...stored!, data: await sealRecord(rotated, secret) });
      throw invalidGrant();
    });

    const result = await lifecycle.refresh(cookies);
    expect(result).toMatchObject({ ok: true, rotatedRefreshToken: true });
    expect(result.ok && result.record.tokens.accessToken).toBe('other');
  });
});
