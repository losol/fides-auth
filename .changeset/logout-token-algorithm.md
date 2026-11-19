---
'@eventuras/fides-auth': patch
---

A back-channel logout token must be signed with the algorithm of the ID token the session was started with. A provider signs both the same way for one client (OpenID Connect Back-Channel Logout 1.0 §2.6), and until now a token signed with any asymmetric algorithm by one of the provider's keys was taken. A token that names a session and has another algorithm is answered with 400 and the session is left as it is. Found by the OpenID conformance suite's back-channel logout plan.

`oidc.verifyLogoutToken` returns the token's `alg`.
