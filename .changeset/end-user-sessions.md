---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': minor
---

`endUserSessions({ sub, iss? })` ends every stored session of one user, wherever they are signed in,
and revokes their refresh tokens: for "sign out everywhere" and closed accounts. It needs a
`SessionStore` with the new optional `findMatching`, and throws without one.

A store can now tell whose session a record is, and whether it is new: `storeFields` in the config
puts plain fields of your choice on the record as `fields`, and `set` gets `{ continuation }` as a
third argument. `createMemorySessionStore` implements `findMatching`.
