---
'@eventuras/fides-auth': minor
---

`VippsLoginClient.getUserInfo` now takes a required `{ expectedSubject }`, the ID token's `sub`, and throws if the answer is for another subject (OIDC Core §5.3.2). It no longer follows redirects: a redirect from the userinfo endpoint sent the subscription key and merchant serial number to the new origin, and returned that origin's JSON as the user. The call gives up after 10 seconds. The error for a non-2xx answer no longer carries the response body.
