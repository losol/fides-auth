---
'@eventuras/fides-auth': major
---

New entry: `@eventuras/fides-auth/browser`, with what runs in the page. It loads nothing from the
server side and no third-party code.

- `createAuthStore`, `initializeAuth` and `checkAuth`: the session store, from
  `@eventuras/fides-auth-store`, without XState. A snapshot is a new object on every change, read
  with `getSnapshot()` and `subscribe()`, and the store has a method per action, such as
  `authSuccess(user)`, in place of `send({ type })`. It checks `/api/auth/session`, the
  `handleSessionInfo` route, unless given `sessionEndpoint` or `checkAuthStatus`.
- `startSessionMonitor(store, config)`: reports an expired session only when the store held one, so
  it can run for visitors who were never logged in. It never refreshes.
- `createHeartbeat` and `createActivityTracker`, moved here.

Breaking: `/heartbeat` and `/activity-tracker` go, and the root no longer exports the activity
tracker. The heartbeat, the store and the monitor take a `logger` factory in place of
`loggerNamespace`.
