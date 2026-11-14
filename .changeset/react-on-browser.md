---
'@eventuras/fides-auth-react': major
---

The hooks are rebuilt on the store in `@eventuras/fides-auth/browser`, and the package no longer
depends on `@eventuras/fides-auth-store`, XState or `@eventuras/logger`. `react` is the only peer
dependency.

- `createAuthStoreHooks(store)` gives `useAuthStore`, which reads the store with React's
  `useSyncExternalStore`, and `useAuthActions`, which returns the store's methods and stays the
  same between renders.
- `useSessionMonitor(store, config)` takes the check from the store, not as an argument. It reads
  its callbacks through a ref, so new callbacks on each render no longer restart the monitor.
- `useHeartbeat` takes `logger` in place of `loggerNamespace`.
- `AuthStoreSelector` and the re-exported `HeartbeatConfig` go; the types come from
  `@eventuras/fides-auth/browser`.
