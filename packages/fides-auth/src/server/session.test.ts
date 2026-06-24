import { describe, it, expect } from 'vitest';

import { createEncryptedJWT } from '../utils';
import type { Session } from '../types';
import type { CookieStore } from './cookie-store';
import {
  persistSession,
  readSession,
  refreshSessionInStore,
  clearSession,
} from './session';

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

  it('treats a verifiably-expired access token as no session', async () => {
    const { store } = memoryStore();
    await persistSession(store, baseSession(jwtWithExp(-10)), secret);

    expect(await readSession(store, secret)).toBeNull();
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
    const config = { issuer: 'https://idp.test', clientId: 'c', clientSecret: 's', redirect_uri: 'https://app.test/cb', scope: 'openid' };
    expect(await refreshSessionInStore(store, config, secret)).toBeNull();
  });

  it('returns null when the stored session has no refresh token', async () => {
    const { store } = memoryStore();
    const noRefresh: Session = {
      tokens: { accessToken: jwtWithExp(3600), accessTokenExpiresAt: '2099-01-01T00:00:00.000Z' },
      user: { name: 'Ada', email: 'ada@example.test', roles: [] },
    };
    await persistSession(store, noRefresh, secret);

    const config = { issuer: 'https://idp.test', clientId: 'c', clientSecret: 's', redirect_uri: 'https://app.test/cb', scope: 'openid' };
    expect(await refreshSessionInStore(store, config, secret)).toBeNull();
  });
});
