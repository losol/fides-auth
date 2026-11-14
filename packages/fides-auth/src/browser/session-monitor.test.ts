import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import type { SessionInfo } from '../shared/types.js';
import { startSessionMonitor } from './session-monitor.js';
import { type AuthUser, createAuthStore } from './store.js';

const quiet = { create: (): FidesLogger => ({ debug() {}, info() {}, warn() {}, error() {} }) };
const user: AuthUser = { sub: 'u-1', name: 'Ada', roles: ['Member'] };

function setup(check: () => Promise<SessionInfo>, loggedIn = true) {
  const checkStatus = vi.fn(check);
  const store = createAuthStore({ checkAuthStatus: checkStatus, logger: quiet });
  if (loggedIn) store.authSuccess(user);
  return { store, checkStatus };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('startSessionMonitor', () => {
  it('waits one interval before the first check', () => {
    const { store, checkStatus } = setup(async () => ({ authenticated: true, user }));
    startSessionMonitor(store, { interval: 1000, logger: quiet });
    expect(checkStatus).not.toHaveBeenCalled();
  });

  it('checks on the interval and keeps the user current', async () => {
    const renamed = { ...user, name: 'Ada L.' };
    const { store, checkStatus } = setup(async () => ({ authenticated: true, user: renamed }));
    startSessionMonitor(store, { interval: 1000, logger: quiet });

    await vi.advanceTimersByTimeAsync(1000);
    expect(store.getSnapshot().user).toEqual(renamed);
    await vi.advanceTimersByTimeAsync(1000);
    expect(checkStatus).toHaveBeenCalledTimes(2);
  });

  it('ends a session the store held, reports it once and stops', async () => {
    const { store, checkStatus } = setup(async () => ({ authenticated: false }));
    const onSessionExpired = vi.fn();
    const onEvent = vi.fn();
    startSessionMonitor(store, { interval: 1000, onSessionExpired, onEvent, logger: quiet });

    await vi.advanceTimersByTimeAsync(1000);
    expect(onSessionExpired).toHaveBeenCalledOnce();
    expect(onEvent).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'session.rejected', source: 'session-monitor' }),
    );
    expect(store.getSnapshot()).toMatchObject({ isAuthenticated: false, error: 'Session expired' });

    await vi.advanceTimersByTimeAsync(5000);
    expect(checkStatus).toHaveBeenCalledTimes(1);
  });

  it('keeps a visitor who was never logged in logged out, without an expiry', async () => {
    const { store, checkStatus } = setup(async () => ({ authenticated: false }), false);
    const onSessionExpired = vi.fn();
    startSessionMonitor(store, { interval: 1000, onSessionExpired, logger: quiet });

    await vi.advanceTimersByTimeAsync(2000);
    expect(onSessionExpired).not.toHaveBeenCalled();
    expect(store.getSnapshot()).toMatchObject({ isAuthenticated: false, error: null, isInitializing: false });
    expect(checkStatus).toHaveBeenCalledTimes(2);
  });

  it('treats a rejected refresh token from a custom check as the end of the session', async () => {
    const { store } = setup(async () => {
      throw { code: 'OAUTH_RESPONSE_BODY_ERROR', error: 'invalid_grant' };
    });
    const onEvent = vi.fn();
    startSessionMonitor(store, { interval: 1000, onEvent, logger: quiet });

    await vi.advanceTimersByTimeAsync(1000);
    expect(onEvent).toHaveBeenCalledWith(expect.objectContaining({ reason: 'refresh_failed' }));
    expect(store.getSnapshot().isAuthenticated).toBe(false);
  });

  it('reports another failure and keeps checking', async () => {
    const check = vi
      .fn<() => Promise<SessionInfo>>()
      .mockRejectedValueOnce(new Error('flaky'))
      .mockResolvedValue({ authenticated: true, user });
    const { store, checkStatus } = setup(check);
    const onError = vi.fn();
    startSessionMonitor(store, { interval: 1000, onError, logger: quiet });

    await vi.advanceTimersByTimeAsync(1000);
    expect(onError).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1000);
    expect(checkStatus).toHaveBeenCalledTimes(2);
    expect(store.getSnapshot().isAuthenticated).toBe(true);
  });

  it('stops when told to, also while a check is in flight', async () => {
    let answer: (status: SessionInfo) => void = () => undefined;
    const { store, checkStatus } = setup(
      () =>
        new Promise<SessionInfo>((resolve) => {
          answer = resolve;
        }),
    );
    const stop = startSessionMonitor(store, { interval: 1000, logger: quiet });

    await vi.advanceTimersByTimeAsync(1000);
    stop();
    answer({ authenticated: false });
    await vi.advanceTimersByTimeAsync(5000);
    expect(checkStatus).toHaveBeenCalledTimes(1);
    // The answer that came after stop() changed nothing.
    expect(store.getSnapshot().isAuthenticated).toBe(true);
  });

  it('keeps going when onEvent throws', async () => {
    const { store } = setup(async () => ({ authenticated: false }));
    const onSessionExpired = vi.fn();
    startSessionMonitor(store, {
      interval: 1000,
      onSessionExpired,
      onEvent: () => {
        throw new Error('beacon down');
      },
      logger: quiet,
    });

    await vi.advanceTimersByTimeAsync(1000);
    expect(onSessionExpired).toHaveBeenCalledOnce();
  });
});
