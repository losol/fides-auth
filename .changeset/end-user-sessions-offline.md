---
'@eventuras/fides-auth': patch
---

`endUserSessions` no longer fails when the identity provider is unreachable. It falls back to the issuer it last saw, or to `oauthConfig.issuer`, to find the user's sessions.
