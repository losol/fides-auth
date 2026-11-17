---
'@eventuras/fides-auth': minor
---

A session that opens but was written by a later major of the library is now told apart from one that doesn't open: it reads with the new reason `unsupported_session_version`, where it was `unreadable_session`. Every 1.x reads a session written by any 1.x.

A read now emits `session.rejected` when a cookie is there and doesn't open, for both reasons. Before, only the heartbeat emitted that event, so an app that doesn't use the heartbeat saw nothing when a changed secret, or a rollback across a major, logged everyone out: `readSession` just answered null. The docs already suggested an alert on `unreadable_session`; now it fires. The heartbeat no longer reports these two itself, so one request is still one event.

`SessionRejectedReason` has a new member, which an exhaustive `switch` over it has to handle.
