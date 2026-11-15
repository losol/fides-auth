---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`SessionUser` names the type of `session.user`, so an app no longer writes
`NonNullable<Session['user']>`. The app's own fields belong in `data`. `Tokens.accessToken` stays
optional, and its doc now says why: a session that keeps only a refresh token must stay possible.
