# @eventuras/fides-auth-store

Framework-agnostic authentication **state** for [`@eventuras/fides-auth`](../fides-auth),
built on [XState Store](https://stately.ai/docs/xstate-store).

It holds who is logged in, admin status, and error state, plus the logic to keep
that state in sync — with no dependency on any UI framework or server runtime.
The application supplies a `checkAuthStatus` callback; the store never reads
cookies or talks to a server itself, so it can be driven from Next.js, React
Router, or plain JavaScript alike.

React bindings (hooks) are layered on top of this package separately.

## Install

```bash
pnpm add @eventuras/fides-auth-store
```

## Usage

```ts
import {
  configureAuthLogger,
  createAuthStore,
  initializeAuth,
  startSessionMonitor,
} from '@eventuras/fides-auth-store';

// Wire fides-auth's internal logging to @eventuras/logger (once, at startup).
configureAuthLogger();

export const authStore = createAuthStore({
  checkAuthStatus: getAuthStatus, // () => Promise<AuthStatus>
  config: { adminRole: 'Admin', loggerNamespace: 'myapp:auth' },
});

// Populate the store from the current auth status.
await initializeAuth(authStore, getAuthStatus);

// Poll for session changes; returns a cleanup function.
const stop = startSessionMonitor(authStore, getAuthStatus, {
  interval: 30_000,
  onSessionExpired: () => console.warn('Session expired'),
});
```

## API

- `createAuthStore(options)` — create the store.
- `initializeAuth(store, checkAuthStatus)` — set initial state from a status check.
- `checkAuth(store, checkAuthStatus)` — re-check and update state.
- `startSessionMonitor(store, checkAuthStatus, config)` — poll on an interval; returns a cleanup function.
- `configureAuthLogger()` — route `@eventuras/fides-auth` logging through `@eventuras/logger`.
- Types: `AuthStoreContext`, `AuthStoreConfig`, `SessionMonitorConfig`, `SessionUser`, `AuthStatus`.
