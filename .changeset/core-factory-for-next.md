---
'@eventuras/fides-auth': minor
---

`createFidesAuth` reads the redirect URI on first use, so a build can import the module that creates
it without the runtime environment. `clearSession` reports `session.cleared` with the trigger
`logout` unless told otherwise.
