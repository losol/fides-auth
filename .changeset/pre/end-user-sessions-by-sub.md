---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`endUserSessions({ sub })` finds the sessions by `sub` alone and no longer needs the issuer. Since beta.3 it
fell back to `oauthConfig.issuer` when the provider couldn't be reached, and ended nothing, without an error,
when the config spelled the issuer another way than the ID tokens do. It now asks the provider for nothing.
`iss` is still an option, to narrow it to one provider, and must then be the ID token's `iss` to the letter.

For a custom `SessionStore`: `SessionMatch.iss` is optional, and `findMatching` must treat a missing `iss` as
"any issuer". An adapter that hands the match to its query as it is needs no change, but an index for it
should start with `subHash`, not `iss`.
