---
'@eventuras/fides-auth': minor
---

Opt-in server-side sessions. `serverPersistence({ store, secret })` keeps the
session in a `SessionStore` and gives the browser a random handle, for providers
whose tokens don't fit a cookie.
