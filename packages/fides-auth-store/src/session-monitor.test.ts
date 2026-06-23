import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { createAuthStore } from './store';
import { startSessionMonitor } from './session-monitor';
import type { SessionUser } from './types';

const user: SessionUser = { name: 'Ada', email: 'ada@example.com', roles: ['Member'] };

describe('startSessionMonitor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('does not poll before the first interval elapses', () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    const check = vi.fn(async () => ({ authenticated: true, user }));

    startSessionMonitor(store, check, { interval: 1000 });

    expect(check).not.toHaveBeenCalled();
  });

  it('polls on the interval and refreshes the user on success', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    const check = vi.fn(async () => ({ authenticated: true, user }));

    startSessionMonitor(store, check, { interval: 1000 });

    await vi.advanceTimersByTimeAsync(1000);
    expect(check).toHaveBeenCalledTimes(1);
    expect(store.getSnapshot().context.user).toEqual(user);

    await vi.advanceTimersByTimeAsync(1000);
    expect(check).toHaveBeenCalledTimes(2);
  });

  it('stops polling and fires onSessionExpired when unauthenticated', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    const onSessionExpired = vi.fn();
    const check = vi.fn(async () => ({ authenticated: false }));

    startSessionMonitor(store, check, { interval: 1000, onSessionExpired });

    await vi.advanceTimersByTimeAsync(1000);
    expect(onSessionExpired).toHaveBeenCalledOnce();
    expect(store.getSnapshot().context.isAuthenticated).toBe(false);

    // No further polls after expiry.
    await vi.advanceTimersByTimeAsync(5000);
    expect(check).toHaveBeenCalledTimes(1);
  });

  it('cleanup stops further polling', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    const check = vi.fn(async () => ({ authenticated: true, user }));

    const stop = startSessionMonitor(store, check, { interval: 1000 });
    stop();

    await vi.advanceTimersByTimeAsync(5000);
    expect(check).not.toHaveBeenCalled();
  });

  it('fires onError but keeps polling on an unexpected error', async () => {
    const store = createAuthStore({ checkAuthStatus: async () => ({ authenticated: true }) });
    const onError = vi.fn();
    const check = vi
      .fn()
      .mockRejectedValueOnce(new Error('flaky'))
      .mockResolvedValue({ authenticated: true, user });

    startSessionMonitor(store, check, { interval: 1000, onError });

    await vi.advanceTimersByTimeAsync(1000);
    expect(onError).toHaveBeenCalledOnce();

    // Still polling after a transient error.
    await vi.advanceTimersByTimeAsync(1000);
    expect(check).toHaveBeenCalledTimes(2);
  });
});
