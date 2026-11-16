---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`tokenStatus` says whether a session's access token can still be used: `active`, `refreshable` or `expired`. A
session reads until `expiresAt` whatever its tokens are worth, so a login without a refresh token stayed
`authenticated: true` for hours after its access token had died, with nothing to tell the two apart.
`tryReadSession`, `readSessionWithTokens` and the session info endpoint now give the status. The session itself
is left as it is; an app that wants "a session is no better than its token" ends it on `expired`.
