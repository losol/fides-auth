---
'@eventuras/fides-auth': minor
---

`OidcUserInfo.name` and `email` are now optional, and `userFromClaims` leaves them out when the ID token has no such claim or the claim is not a string.
