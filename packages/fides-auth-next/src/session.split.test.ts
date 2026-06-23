// @vitest-environment node
/**
 * Tests for the split-cookie session storage: the access token lives in its own
 * "session_at" cookie while the rest of the session lives in "session".
 * getCurrentSession must reassemble the two, preserve the "expired access token
 * means no session" contract, and still read legacy single-cookie sessions.
 */
import { vi, describe, it, expect, beforeEach } from 'vitest';

// 32-byte (64 hex char) secret for A256GCM, set before any module reads it.
process.env.SESSION_SECRET = 'a'.repeat(64);

// In-memory cookie jar shared with the mocked ./cookies module (hoisted so the
// vi.mock factory can close over it).
const { jar } = vi.hoisted(() => ({ jar: new Map<string, string>() }));

vi.mock('./cookies', () => ({
  getSessionCookie: vi.fn(async () => jar.get('session') ?? null),
  setSessionCookie: vi.fn(async (v: string) => { jar.set('session', v); }),
  deleteSessionCookie: vi.fn(async () => { jar.delete('session'); }),
  getAccessTokenCookie: vi.fn(async () => jar.get('session_at') ?? null),
  setAccessTokenCookie: vi.fn(async (v: string) => { jar.set('session_at', v); }),
  deleteAccessTokenCookie: vi.fn(async () => { jar.delete('session_at'); }),
}));

// getCurrentSession is wrapped in React's cache(); make it a pass-through.
vi.mock('react', () => ({ cache: (fn: unknown) => fn }));

import {
  createAndPersistSession,
  getCurrentSession,
  clearCurrentSession,
} from './session';
import { createEncryptedJWT, getSessionSecret } from '@eventuras/fides-auth/utils';
import type { Session } from '@eventuras/fides-auth/types';

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

  it('returns null when the split access token has expired', async () => {
    await createAndPersistSession(baseSession(jwtWithExp(-60)));

    expect(await getCurrentSession()).toBeNull();
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
    const legacyJwt = await createEncryptedJWT(baseSession(accessToken), getSessionSecret());
    jar.set('session', legacyJwt);

    const session = await getCurrentSession();
    expect(session?.tokens?.accessToken).toBe(accessToken);
  });
});
