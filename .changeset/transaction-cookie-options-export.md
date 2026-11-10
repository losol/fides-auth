---
'@eventuras/fides-auth': patch
---

`/server` exports `transactionCookieOptions(redirectUri)`, the cookie options the
login handlers use. Pass it to the transaction helpers in custom flows.
