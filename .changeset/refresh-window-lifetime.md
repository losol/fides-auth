---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

`refreshSession({ ifExpiresWithin })` and `refreshInProxy` never count more than half the access
token's lifetime as about to expire. A token that lived shorter than the window, 60 seconds by
default in the proxy, was refreshed on every request. The session now records when its access token
arrived, as `accessTokenIssuedAt` on `Tokens`, and the READMEs describe how a refresh from a stale
cookie fails when the provider rotates refresh tokens.
