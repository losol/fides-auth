// @vitest-environment jsdom
/**
 * The hooks render against the real store from @eventuras/fides-auth/browser.
 * The store and the monitor have their own tests in core; these check the
 * binding: re-rendering on a change, stable actions, and starting and stopping
 * the monitor with the component.
 */
import { createAuthStore, type AuthStore } from '@eventuras/fides-auth/browser';
import { createElement } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createAuthStoreHooks, useSessionMonitor } from './index.js';

// React warns unless it knows it runs under act().
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const quiet = { create: () => ({ debug() {}, info() {}, warn() {}, error() {} }) };
const user = { sub: 'u-1', name: 'Ada', roles: ['Admin'] };

let container: HTMLElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.useRealTimers();
});

function makeStore(checkAuthStatus = async () => ({ authenticated: true, user })): AuthStore {
  return createAuthStore({ checkAuthStatus, logger: quiet });
}

// Components live at module scope, as in an app: each test has its own store.
const greetingStore = makeStore();
const greetingHooks = createAuthStoreHooks(greetingStore);
function Greeting() {
  const auth = greetingHooks.useAuthStore();
  return createElement('p', null, auth.isAuthenticated ? `Hello ${auth.user?.name}` : 'Logged out');
}

const probeStore = makeStore();
const probeHooks = createAuthStoreHooks(probeStore);
const seenActions: unknown[] = [];
function Probe() {
  seenActions.push(probeHooks.useAuthActions());
  return null;
}

function Monitor({ store, onError }: { store: AuthStore; onError?: (error: Error) => void }) {
  useSessionMonitor(store, { interval: 1000, logger: quiet, onError });
  return null;
}

describe('createAuthStoreHooks', () => {
  it('renders the current state and re-renders on a change', () => {
    act(() => root.render(createElement(Greeting)));
    expect(container.textContent).toBe('Logged out');

    act(() => greetingStore.authSuccess(user));
    expect(container.textContent).toBe('Hello Ada');

    act(() => greetingStore.logout());
    expect(container.textContent).toBe('Logged out');
  });

  it('hands out the same actions on every render, bound to the store', () => {
    act(() => root.render(createElement(Probe)));
    act(() => root.render(createElement(Probe)));
    expect(seenActions[0]).toBe(seenActions[1]);

    const actions = seenActions[0] as ReturnType<typeof probeHooks.useAuthActions>;
    act(() => actions.authSuccess(user));
    expect(probeStore.getSnapshot().isAdmin).toBe(true);
  });
});

describe('useSessionMonitor', () => {
  it('runs while mounted and stops on unmount', async () => {
    vi.useFakeTimers();
    const checkAuthStatus = vi.fn(async () => ({ authenticated: true, user }));
    const store = makeStore(checkAuthStatus);

    act(() => root.render(createElement(Monitor, { store })));
    await act(() => vi.advanceTimersByTimeAsync(1000));
    expect(checkAuthStatus).toHaveBeenCalledTimes(1);

    act(() => root.render(null));
    await act(() => vi.advanceTimersByTimeAsync(5000));
    expect(checkAuthStatus).toHaveBeenCalledTimes(1);
  });

  it("doesn't restart when the callbacks change between renders", async () => {
    vi.useFakeTimers();
    const checkAuthStatus = vi.fn(async () => ({ authenticated: true, user }));
    const store = makeStore(checkAuthStatus);

    act(() => root.render(createElement(Monitor, { store, onError: () => undefined })));
    await act(() => vi.advanceTimersByTimeAsync(600));
    act(() => root.render(createElement(Monitor, { store, onError: () => undefined })));
    await act(() => vi.advanceTimersByTimeAsync(400));
    // A restart on the second render would have pushed the first check to 1600 ms.
    expect(checkAuthStatus).toHaveBeenCalledTimes(1);
  });
});
