---
'@eventuras/fides-auth': patch
---

`docs/server-sessions.md` has a PostgreSQL store next to the MongoDB one, and it is the first example with
`withLock`: an advisory lock on a connection from a pool of its own, with what that relies on spelled out. The
docs also say plainly that the library never deletes an expired record, so a store without a TTL index has to
sweep them itself.
