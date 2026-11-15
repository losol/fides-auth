---
'@eventuras/fides-auth': patch
---

`session.scopes` at login are now the scopes the login asked for when the provider's token response names none, which RFC 6749 allows when it granted exactly what was asked. A `scope` in the response still wins.
