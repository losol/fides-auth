---
'@eventuras/fides-auth': patch
---

A refresh whose store lock fails, or whose store throws, returns `{ ok: false, reason:
'refresh_failed', cause: 'store' }` instead of throwing, and emits `session.refresh_failed`. The
heartbeat answers it with 503, so the browser retries. `docs/server-sessions.md` spells out the
`withLock` contract: `fn` uses the store while the lock is held, the lock is held across the call to
the provider, and why more than one instance with a rotating provider needs it.
