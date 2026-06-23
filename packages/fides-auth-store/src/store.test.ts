import { describe, it, expect, vi } from 'vitest';

import { createAuthStore, initializeAuth, checkAuth } from './store';
import type { AuthStatus, SessionUser } from './types';

const admin: SessionUser = { name: 'Ada', email: 'ada@example.com', roles: ['Admin'] };
const member: SessionUser = { name: 'Ben', email: 'ben@example.com', roles: ['Member'] };

describe('createAuthStore', () => {
  it('starts in an initializing, unauthenticated state', () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: false }) });
    const ctx = store.getSnapshot().context;
    expect(ctx.isInitializing).toBe(true);
    expect(ctx.isAuthenticated).toBe(false);
    expect(ctx.user).toBeNull();
  });

  it('authSuccess marks admin when the user carries the configured admin role', () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    store.send({ type: 'authSuccess', user: admin });
    const ctx = store.getSnapshot().context;
    expect(ctx.isAuthenticated).toBe(true);
    expect(ctx.isAdmin).toBe(true);
    expect(ctx.user).toEqual(admin);
    expect(ctx.isInitializing).toBe(false);
  });

  it('honours a custom adminRole', () => {
    const store = createAuthStore({
      checkAuthStatus: async () => ({ authenticated: true }),
      config: { adminRole: 'Superuser' },
    });
    store.send({ type: 'authSuccess', user: { ...member, roles: ['Superuser'] } });
    expect(store.getSnapshot().context.isAdmin).toBe(true);
  });

  it('non-admin users are authenticated but not admin', () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    store.send({ type: 'authSuccess', user: member });
    const ctx = store.getSnapshot().context;
    expect(ctx.isAuthenticated).toBe(true);
    expect(ctx.isAdmin).toBe(false);
  });

  it('logout and sessionExpired clear the user', () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    store.send({ type: 'authSuccess', user: admin });

    store.send({ type: 'logout' });
    expect(store.getSnapshot().context.isAuthenticated).toBe(false);

    store.send({ type: 'authSuccess', user: admin });
    store.send({ type: 'sessionExpired' });
    const ctx = store.getSnapshot().context;
    expect(ctx.isAuthenticated).toBe(false);
    expect(ctx.error).toBe('Session expired');
  });

  it('setError / clearError manage the error field without touching auth', () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    store.send({ type: 'authSuccess', user: admin });

    store.send({ type: 'setError', error: 'boom' });
    expect(store.getSnapshot().context.error).toBe('boom');
    expect(store.getSnapshot().context.isAuthenticated).toBe(true);

    store.send({ type: 'clearError' });
    expect(store.getSnapshot().context.error).toBeNull();
  });
});

describe('initializeAuth', () => {
  it('authenticates the store when the check reports a user', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: false }) });
    const checkAuthStatus = vi.fn<[], Promise<AuthStatus>>(async () => ({
      authenticated: true,
      user: admin,
    }));

    await initializeAuth(store, checkAuthStatus);

    expect(checkAuthStatus).toHaveBeenCalledOnce();
    const ctx = store.getSnapshot().context;
    expect(ctx.isAuthenticated).toBe(true);
    expect(ctx.user).toEqual(admin);
    expect(ctx.isInitializing).toBe(false);
  });

  it('falls back to unauthenticated when the check throws', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: false }) });

    await initializeAuth(store, async () => {
      throw new Error('network down');
    });

    const ctx = store.getSnapshot().context;
    expect(ctx.isAuthenticated).toBe(false);
    expect(ctx.isInitializing).toBe(false);
  });
});

describe('checkAuth', () => {
  it('maps an invalid_grant error to sessionExpired', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    store.send({ type: 'authSuccess', user: admin });

    await checkAuth(store, async () => {
      throw { code: 'OAUTH_RESPONSE_BODY_ERROR', error: 'invalid_grant' };
    });

    expect(store.getSnapshot().context.error).toBe('Session expired');
    expect(store.getSnapshot().context.isAuthenticated).toBe(false);
  });

  it('maps an unexpected error to authFailed with the message', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });

    await checkAuth(store, async () => {
      throw new Error('kaboom');
    });

    const ctx = store.getSnapshot().context;
    expect(ctx.isAuthenticated).toBe(false);
    expect(ctx.error).toBe('kaboom');
  });
});
