---
'@eventuras/fides-auth-next': minor
---

`handleOidcCallback` takes `mapSession`, also through `createFidesAuth`. See
`buildSessionFromTokens` in `@eventuras/fides-auth`.

Breaking: the re-exported `Session.user.email` is optional; handle `undefined`.
