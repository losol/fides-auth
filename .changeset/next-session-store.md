---
'@eventuras/fides-auth-next': minor
---

`createFidesAuth` takes an optional `sessionStore`. With it, every handler and
helper keeps the session in the store, and the cookie holds only a handle.
Without it, sessions stay in cookies as before.

The `SessionStore` and `StoredSession` types are re-exported. The standalone
callback, logout and heartbeat handlers take an optional `persistence`.
