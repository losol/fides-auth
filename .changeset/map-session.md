---
'@eventuras/fides-auth': minor
---

`buildSessionFromTokens` takes `{ rolesClaim, mapSession }` and `handleOidcCallback`
takes `mapSession`. `mapSession(tokens, claims, session)` returns the session to
store, e.g. with `data` added. The `rolesClaim` string argument still works.
`Session.user` gains `sub`.

Breaking: `Session.user.email` is optional; handle `undefined`. A token response
without `id_token` no longer throws: the session has tokens and no `user`.
