---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

The session info endpoint answers with `expiresAt`, when the session itself ends. A page knew when
the access token expires, which a refresh moves, but not when the user will be logged out.
