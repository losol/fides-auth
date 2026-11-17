---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

A new page, `docs/session-format.md`, says what the library writes to a cookie and to a store: the record, how it is sealed and what its key is derived from, the store's fields, and the cookie of a login under way. It also says what is stable: every 1.x reads what any 1.x wrote. A test with values written by 1.0.0-beta.8 holds the library to that, and the page shows the supported way to start and read a session in an app's own tests.

The docs now say plainly that `storeFields` are not sealed, and what does and doesn't belong in them.
