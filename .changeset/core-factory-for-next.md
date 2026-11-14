---
'@eventuras/fides-auth': minor
---

`createFidesAuth` reads the redirect URI on first use, so a build can import the module that creates
it without the runtime environment. `authorizedFetch` takes `refresh: false`, for a Next.js Server
Component that can't save a refresh. `clearSession` reports `session.cleared` with the trigger
`logout` unless told otherwise.
