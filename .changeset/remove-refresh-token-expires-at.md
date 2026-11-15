---
'@eventuras/fides-auth': patch
---

`Tokens` loses `refreshTokenExpiresAt`. Nothing ever set it: a token response says how long the
access token lasts, not the refresh token.
