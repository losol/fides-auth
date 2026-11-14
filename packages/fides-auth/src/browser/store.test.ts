import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import type { SessionInfo } from '../shared/types.js';
import { type AuthUser, checkAuth, createAuthStore, initializeAuth } from './store.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };
const admin: AuthUser = { sub: 'u-1', name: 'Ada', email: 'ada@example.com', roles: ['Admin'] };
const member: AuthUser = { sub: 'u-2', name: 'Ben', roles: ['Member'] };

const store = (checkAuthStatus?: () => Promise<SessionInfo>, adminRole?: string) =>
  createAuthStore({ checkAuthStatus, adminRole, logger: quiet });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createAuthStore', () => {
  it('starts initializing and logged out', () => {
    expect(store().getSnapshot()).toEqual({
      user: null,
      isAdmin: false,
      isAuthenticated: false,
      error: null,
      lastChecked: null,
      isInitializing: true,
    });
  });

  it('marks an admin by the configured role', () => {
    const auth = store();
    auth.authSuccess(admin);
    expect(auth.getSnapshot()).toMatchObject({ user: admin, isAdmin: true, isAuthenticated: true, isInitializing: false });

    const custom = store(undefined, 'Superuser');
    custom.authSuccess({ ...member, roles: ['Superuser'] });
    expect(custom.getSnapshot().isAdmin).toBe(true);
  });

  it('treats a user without roles as no admin', () => {
    const auth = store();
    auth.authSuccess({ sub: 'u-3' });
    expect(auth.getSnapshot()).toMatchObject({ isAuthenticated: true, isAdmin: false });
  });

  it('clears the user on logout and on sessionExpired', () => {
    const auth = store();
    auth.authSuccess(admin);
    auth.logout();
    expect(auth.getSnapshot()).toMatchObject({ user: null, isAuthenticated: false, error: null });

    auth.authSuccess(admin);
    auth.sessionExpired();
    expect(auth.getSnapshot()).toMatchObject({ user: null, isAuthenticated: false, error: 'Session expired' });
  });

  it('sets and clears an error without touching the session', () => {
    const auth = store();
    auth.authSuccess(admin);
    auth.setError('boom');
    expect(auth.getSnapshot()).toMatchObject({ error: 'boom', isAuthenticated: true });
    auth.clearError();
    expect(auth.getSnapshot().error).toBeNull();
  });

  it('gives a new snapshot on a change and the same one otherwise', () => {
    const auth = store();
    const before = auth.getSnapshot();
    expect(auth.getSnapshot()).toBe(before);
    auth.authSuccess(member);
    expect(auth.getSnapshot()).not.toBe(before);
  });

  it('tells subscribers about each change, until they unsubscribe', () => {
    const auth = store();
    const listener = vi.fn();
    const unsubscribe = auth.subscribe(listener);
    auth.authSuccess(member);
    auth.setError('x');
    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribe();
    auth.clearError();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('keeps telling the other subscribers when one throws', () => {
    const auth = store();
    const after = vi.fn();
    auth.subscribe(() => {
      throw new Error('broken subscriber');
    });
    auth.subscribe(after);
    auth.logout();
    expect(after).toHaveBeenCalledOnce();
  });
});

describe('the default session check', () => {
  it('asks the session info endpoint, same-origin and uncached', async () => {
    const fetchMock = vi.fn(async () => Response.json({ authenticated: true, user: admin }));
    vi.stubGlobal('fetch', fetchMock);
    const auth = createAuthStore({ logger: quiet });

    await initializeAuth(auth);

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/auth/session',
      expect.objectContaining({ credentials: 'same-origin', cache: 'no-store' }),
    );
    expect(auth.getSnapshot()).toMatchObject({ user: admin, isAuthenticated: true });
  });

  it('takes another endpoint', async () => {
    const fetchMock = vi.fn(async () => Response.json({ authenticated: false }));
    vi.stubGlobal('fetch', fetchMock);
    await initializeAuth(createAuthStore({ sessionEndpoint: '/auth/me', logger: quiet }));
    expect(fetchMock).toHaveBeenCalledWith('/auth/me', expect.anything());
  });

  it('fails on a non-2xx answer', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 500 })));
    const auth = createAuthStore({ logger: quiet });
    await checkAuth(auth);
    expect(auth.getSnapshot().error).toBe('Session check failed with status 500');
  });
});

describe('initializeAuth', () => {
  it('logs the user in when the check finds one', async () => {
    const check = vi.fn(async (): Promise<SessionInfo> => ({ authenticated: true, user: admin }));
    const auth = store(check);
    await initializeAuth(auth);
    expect(check).toHaveBeenCalledOnce();
    expect(auth.getSnapshot()).toMatchObject({ user: admin, isAuthenticated: true, isInitializing: false });
  });

  it('ends logged out when the check throws', async () => {
    const auth = store(async () => {
      throw new Error('network down');
    });
    await initializeAuth(auth);
    expect(auth.getSnapshot()).toMatchObject({ isAuthenticated: false, isInitializing: false });
  });
});

describe('checkAuth', () => {
  it('ends the session on a rejected refresh token', async () => {
    const auth = store(async () => {
      throw { code: 'OAUTH_RESPONSE_BODY_ERROR', error: 'invalid_grant' };
    });
    auth.authSuccess(admin);
    await checkAuth(auth);
    expect(auth.getSnapshot()).toMatchObject({ isAuthenticated: false, error: 'Session expired' });
  });

  it('keeps the message of any other failure', async () => {
    const auth = store(async () => {
      throw new Error('kaboom');
    });
    await checkAuth(auth);
    expect(auth.getSnapshot()).toMatchObject({ isAuthenticated: false, error: 'kaboom' });
  });
});
