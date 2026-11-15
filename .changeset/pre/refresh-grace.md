---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

With cookie sessions, a request that still carries the cookie from before a refresh gets that
refresh's result for `refreshGraceSeconds` after it, 10 by default, instead of spending the old
refresh token again, which a provider that rotates refresh tokens answers with `invalid_grant`. A
logout with the old cookie revokes the new refresh token. It works within one process and for the
token just spent; set it to 0 to turn it off.
