import { describe, it, expect } from 'vitest';

import * as api from './index';

// These hooks are thin wrappers over logic that is tested where it lives — the
// heartbeat engine in @eventuras/fides-auth, the store and session monitor in
// @eventuras/fides-auth-store. This smoke test just guards the public surface:
// the bindings export the expected callables and the module imports cleanly.
describe('@eventuras/fides-auth-react public API', () => {
  it('exports the hook factory and hooks as functions', () => {
    expect(typeof api.createAuthStoreHooks).toBe('function');
    expect(typeof api.useSessionMonitor).toBe('function');
    expect(typeof api.useHeartbeat).toBe('function');
  });

  it('createAuthStoreHooks returns the expected hooks', () => {
    // A minimal store-shaped stub is enough to build the hooks object; the hooks
    // themselves are only invoked inside a React render, which this does not do.
    const store = { send: () => undefined, getSnapshot: () => ({ context: {} }) };
    const hooks = api.createAuthStoreHooks(store as never);
    expect(typeof hooks.useAuthStore).toBe('function');
    expect(typeof hooks.useAuthActions).toBe('function');
  });
});
