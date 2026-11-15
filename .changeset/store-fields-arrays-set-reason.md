---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`storeFields` values may now be lists of strings, for roles say, as well as strings, numbers, booleans and null. A store's `set` gets `context.reason`, one of `'login'`, `'refresh'` and `'update'`, so an adapter can tell a refresh from an `updateSession` and stamp when a session was last refreshed. `StoreSetReason` is exported.
