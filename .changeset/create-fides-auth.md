---
'@eventuras/fides-auth-next': minor
---

`createFidesAuth({ secret, oauthConfig })` returns the session helpers and route
handlers with both bound. The package-level session helpers and the `./session`
entry point are removed; `./auth` replaces it. The standalone route handlers
now require `secret`, and the login handler takes `authorizationParameters`.

Migration:
- Create one `auth = createFidesAuth(…)` and call `auth.getCurrentSession()` and
  so on. `refreshCurrentSession(oauthConfig)` becomes `auth.refreshCurrentSession()`.
- Replace `createSession(session)` with `createEncryptedJWT(session, secret)`.
