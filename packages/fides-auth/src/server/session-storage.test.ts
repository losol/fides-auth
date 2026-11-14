/**
 * Tests for the two session storages: cookie chunking and its size limit, the
 * cookie attributes, the deletion of the legacy cookies, and store storage's
 * handle rules. The lifecycle rules they share are in session-lifecycle.test.ts.
 */
import { describe, expect, it } from 'vitest';

import { type CookieOptions, CookieTooLargeError } from '../shared/cookies.js';
import { sha256 } from '../session/utils.js';
import type { CookieStore } from './cookie-store.js';
import {
  cookieStorage,
  LEGACY_COOKIE_NAMES,
  type SaveRequest,
  storeStorage,
} from './session-storage.js';
import { createMemorySessionStore } from './session-store.js';

interface Write {
  name: string;
  value: string;
  options?: CookieOptions;
}

/** A cookie jar that, like a browser, drops a cookie set with `maxAge: 0`. Never deletes otherwise. */
function cookieJar(initial: Record<string, string> = {}) {
  const jar = new Map(Object.entries(initial));
  const writes: Write[] = [];
  const cookies: CookieStore = {
    get: (name) => jar.get(name) ?? null,
    set: (name, value, options) => {
      writes.push({ name, value, options });
      if (options?.maxAge === 0) jar.delete(name);
      else jar.set(name, value);
    },
    delete: () => {
      throw new Error('the storages delete with set and maxAge 0');
    },
  };
  return { cookies, jar, writes };
}

const inAnHour = () => new Date(Date.now() + 3_600_000).toISOString();

function request(sealed: string, extra: Partial<SaveRequest> = {}): SaveRequest {
  return { sealed, expiresAt: inAnHour(), correlationId: 'c1', continuation: false, ...extra };
}

describe('cookieStorage', () => {
  it('writes a small record to one __Host-session cookie, with the time left as Max-Age', async () => {
    const { cookies, jar, writes } = cookieJar();
    const storage = cookieStorage({ secure: true });
    const result = await storage.save(cookies, request('sealed-value'));

    expect([...jar.keys()]).toEqual(['__Host-session']);
    expect(writes[0]?.options).toEqual({
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      maxAge: expect.any(Number),
    });
    expect(writes[0]?.options?.maxAge).toBeGreaterThan(3590);
    expect(writes[0]?.options?.maxAge).toBeLessThanOrEqual(3600);
    expect(result).toEqual({ saved: true, cookieBytes: '__Host-session=sealed-value'.length });
    expect(await storage.load(cookies)).toEqual({ sealed: 'sealed-value' });
  });

  it('cuts a large record into chunks below the per-cookie limit and joins them on load', async () => {
    const { cookies, jar } = cookieJar();
    const storage = cookieStorage({ secure: true });
    const sealed = 'x'.repeat(10_000);
    await storage.save(cookies, request(sealed));

    expect([...jar.keys()]).toEqual(['__Host-session', '__Host-session.1', '__Host-session.2']);
    for (const [name, value] of jar) expect(name.length + 1 + value.length).toBeLessThan(4096);
    expect(await storage.load(cookies)).toEqual({ sealed });
  });

  it('refuses a record that needs more than three cookies, and writes nothing', async () => {
    const { cookies, writes } = cookieJar();
    const storage = cookieStorage({ secure: true });

    await expect(storage.save(cookies, request('x'.repeat(13_000)))).rejects.toBeInstanceOf(
      CookieTooLargeError,
    );
    expect(writes).toEqual([]);
  });

  it('deletes chunks a smaller record no longer needs', async () => {
    const { cookies, jar } = cookieJar();
    const storage = cookieStorage({ secure: true });
    await storage.save(cookies, request('x'.repeat(10_000)));
    await storage.save(cookies, request('small'));

    expect([...jar.keys()]).toEqual(['__Host-session']);
    expect(await storage.load(cookies)).toEqual({ sealed: 'small' });
  });

  it('uses the plain name without Secure for a plain-http redirect URI', async () => {
    const { cookies, jar, writes } = cookieJar();
    await cookieStorage({ secure: false }).save(cookies, request('v'));

    expect([...jar.keys()]).toEqual(['session']);
    expect(writes[0]?.options?.secure).toBe(false);
  });

  it('answers no_session_cookie without a cookie, and removes every chunk', async () => {
    const { cookies, jar } = cookieJar();
    const storage = cookieStorage({ secure: true });
    expect(await storage.load(cookies)).toEqual({ sealed: null, reason: 'no_session_cookie' });

    await storage.save(cookies, request('x'.repeat(10_000)));
    await storage.remove(cookies);
    expect(jar.size).toBe(0);
  });
});

describe('the legacy cookies', () => {
  const legacy = Object.fromEntries(LEGACY_COOKIE_NAMES.map((name) => [name, 'old']));

  it.each([
    ['cookie storage', () => cookieStorage({ secure: true })],
    ['store storage', () => storeStorage({ secure: true, store: createMemorySessionStore() })],
  ])('are deleted, Secure and with Path=/, when %s saves', async (_, storage) => {
    const { cookies, jar, writes } = cookieJar(legacy);
    await storage().save(cookies, request('v'));

    for (const name of LEGACY_COOKIE_NAMES) {
      expect(jar.has(name)).toBe(false);
      expect(writes).toContainEqual({
        name,
        value: '',
        options: { path: '/', httpOnly: true, sameSite: 'lax', secure: true, maxAge: 0 },
      });
    }
  });

  it('are deleted on remove too', async () => {
    const { cookies, jar } = cookieJar(legacy);
    await cookieStorage({ secure: true }).remove(cookies);
    expect(jar.size).toBe(0);
  });

  it('are not read', async () => {
    const { cookies } = cookieJar(legacy);
    expect(await cookieStorage({ secure: true }).load(cookies)).toEqual({
      sealed: null,
      reason: 'no_session_cookie',
    });
  });

  it('leave `session` to be overwritten under plain http, where the new cookie has that name', async () => {
    const { cookies, jar } = cookieJar(legacy);
    await cookieStorage({ secure: false }).save(cookies, request('new'));
    expect([...jar.entries()]).toEqual([['session', 'new']]);
  });

  it('are left alone when absent: no needless Set-Cookie', async () => {
    const { cookies, writes } = cookieJar();
    await cookieStorage({ secure: true }).save(cookies, request('v'));
    expect(writes.map((w) => w.name)).toEqual(['__Host-session']);
  });
});

describe('storeStorage', () => {
  function setup() {
    const store = createMemorySessionStore();
    const jar = cookieJar();
    return { store, ...jar, storage: storeStorage({ store, secure: true }) };
  }

  it('gives the browser a random handle and keys the store by its hash', async () => {
    const { store, cookies, jar, storage } = setup();
    await storage.save(
      cookies,
      request('sealed', { lookup: { iss: 'https://idp', subHash: 'h1', idpSidHash: 'h2' } }),
    );

    const handle = jar.get('__Host-session') ?? '';
    expect(handle).toMatch(/^[0-9a-f]{64}$/);
    expect(await store.get(await sha256(handle))).toEqual({
      data: 'sealed',
      expiresAt: expect.any(String),
      correlationId: 'c1',
      iss: 'https://idp',
      subHash: 'h1',
      idpSidHash: 'h2',
    });
    expect(await storage.load(cookies)).toEqual({ sealed: 'sealed' });
  });

  it('mints a new handle for a new session and deletes the old record', async () => {
    const { store, cookies, jar, storage } = setup();
    await storage.save(cookies, request('first'));
    const first = jar.get('__Host-session') ?? '';
    await storage.save(cookies, request('second'));

    expect(jar.get('__Host-session')).not.toBe(first);
    expect(await store.get(await sha256(first))).toBeNull();
  });

  it('keeps the handle on a continuation', async () => {
    const { cookies, jar, storage } = setup();
    await storage.save(cookies, request('first'));
    const handle = jar.get('__Host-session');
    expect(await storage.save(cookies, request('second', { continuation: true }))).toEqual({
      saved: true,
    });

    expect(jar.get('__Host-session')).toBe(handle);
    expect(await storage.load(cookies)).toEqual({ sealed: 'second' });
  });

  it('does not bring back a session that ended while a continuation ran', async () => {
    const { store, cookies, jar, storage } = setup();
    await storage.save(cookies, request('first'));
    const handle = jar.get('__Host-session') ?? '';
    await store.delete(await sha256(handle));

    expect(await storage.save(cookies, request('late', { continuation: true }))).toEqual({
      saved: false,
    });
    expect(await store.get(await sha256(handle))).toBeNull();
  });

  it('answers unreadable_session for a value that is not a handle, such as cookie storage’s', async () => {
    const { cookies, jar, storage } = setup();
    jar.set('__Host-session', 'eyJhbGciOiJkaXIi.not-a-handle');
    expect(await storage.load(cookies)).toEqual({ sealed: null, reason: 'unreadable_session' });
  });

  it('answers session_not_found for a handle without a record', async () => {
    const { cookies, jar, storage } = setup();
    jar.set('__Host-session', 'a'.repeat(64));
    expect(await storage.load(cookies)).toEqual({ sealed: null, reason: 'session_not_found' });
  });

  it('deletes chunks cookie storage left, and on remove the record and the cookie', async () => {
    const { store, cookies, jar, storage } = setup();
    jar.set('__Host-session.1', 'chunk');
    await storage.save(cookies, request('sealed'));
    expect(jar.has('__Host-session.1')).toBe(false);

    const handle = jar.get('__Host-session') ?? '';
    await storage.remove(cookies);
    expect(jar.size).toBe(0);
    expect(await store.get(await sha256(handle))).toBeNull();
  });
});
