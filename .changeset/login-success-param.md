---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`loginSuccessParam: false` makes a login land on its return path as it was, without `?login=success`.
The default stays true. A failed login still goes to `defaultRedirectPath` with
`?login=error&error=<code>`.
