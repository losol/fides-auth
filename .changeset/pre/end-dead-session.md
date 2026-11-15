---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

A refresh the provider refuses for good, `invalid_grant`, ends a session held by a `sessionStore` with
`withLock`: the record is deleted, and later reads answer `session_not_found` instead of a session
whose tokens no longer work. It emits `session.cleared` with `trigger: "rejected"`. Cookie sessions,
and stores without a lock, are left as before, since another instance may have refreshed; the README
shows how to end them with `clearSession`.
