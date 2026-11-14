---
'@eventuras/fides-auth-react': major
---

1.0, on the store in core's `/browser`. The
[upgrade guide](https://github.com/losol/fides-auth/blob/main/packages/fides-auth/docs/migrating-to-1.0.md)
maps every 0.x API to what replaces it.

- `createAuthStoreHooks(store)` gives `useAuthStore` and `useAuthActions`.
  `useSessionMonitor(store, config)` and `useHeartbeat` run the monitor and the heartbeat.
- No XState, and no dependency on `@eventuras/fides-auth-store`, which ends at 0.x.
- `@eventuras/fides-auth` is a peer dependency. Needs Node 22.
