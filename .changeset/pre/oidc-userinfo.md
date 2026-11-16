---
'@eventuras/fides-auth': minor
---

`oidc.userInfo(accessToken, { expectedSubject })` gets the claims from the provider's UserInfo endpoint. It
checks that the response is for `expectedSubject`, the ID token's `sub`, so you no longer build an openid-client
configuration by hand.
