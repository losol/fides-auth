---
'@eventuras/fides-auth': major
---

1.0. Users log in again once after the upgrade. The
[upgrade guide](https://github.com/losol/fides-auth/blob/main/packages/fides-auth/docs/migrating-to-1.0.md)
maps every 0.x API to what replaces it.

- `createFidesAuth` from `/server` is the server side: the handlers, the session members and
  `authorizedFetch` on one instance. The free `/server` functions are gone.
- One session cookie, `__Host-session`, or a handle with a `SessionStore`. A session ends
  `sessionDurationSeconds` after login, 12 hours by default, and `Session` carries no tokens.
- Nothing refreshes unless asked: `refreshSession({ ifExpiresWithin })`. `authorizedFetch` never
  refreshes, and its error says whether a refresh may help.
- `createOidcClient` on `/oidc` replaces the free protocol functions and the global settings. Each
  part takes its own `logger`.
- `/browser` has the session store, the session monitor, the heartbeat and the activity tracker,
  without XState.
- Six entries: the root, which has only types, `/oidc`, `/server`, `/browser`, `/session-events`
  and `/providers/vipps`. The other 0.x entries are gone, `/utils` and `/rate-limit` among them.
- Logout and heartbeat answer only a same-origin `POST`, and `createFidesAuth` throws on
  `clientAuth: 'none'`.
- Needs Node 22.
