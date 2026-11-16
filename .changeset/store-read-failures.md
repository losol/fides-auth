---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

A session store that can't be reached no longer makes the heartbeat, the session info and a refresh throw. Only a
`withLock` that rejected was handled; a `get` that threw went straight through, since the read a refresh starts
with was outside the handling. Now `refreshSession` answers `{ ok: false, reason: 'refresh_failed', cause: 'store' }`
for any call to the store that fails, with or without `ifExpiresWithin`, `handleHeartbeat` answers 503 as
documented, and `refreshInProxy` passes the request on instead of failing every page. `handleSessionInfo` answers
503 without a body: whether there is a session isn't known, so it says neither.

The reads (`readSession`, `tryReadSession`, `getTokens`, `readSessionWithTokens`, `authorizedFetch`) still reject
with what the store threw, as `updateSession` does: null would send a logged-in user to a login that fails on the
same store. `docs/server-sessions.md` has a table of what each call answers.
