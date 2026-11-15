---
'@eventuras/fides-auth': patch
---

A refresh that brings an ID token updates `session.user` from it, as at login, so roles taken away at
the provider go with the next refresh instead of the next login. The roles follow `rolesClaim`, the
name and email change when the token carries them, and `sub`, `data` and the fields `mapSession`
added stay. An ID token whose `iss` or `sub` differs from the login's fails the refresh with
`cause: 'idp_error'` and saves nothing (OIDC Core §12.2).
