---
'@eventuras/fides-auth': patch
---

The store contract now says that `set` must never create a record for a continuation: when a refresh or an
update finds no record, the session was ended while it ran, and an upsert would bring it back. The MongoDB
example upserted on every `set`, so without `withLock` a refresh on one instance could restore a session that
another had just logged out. It now uses `upsert: !continuation`, and the memory store follows the same rule. A
custom `SessionStore` that upserts on every `set` should do the same.
