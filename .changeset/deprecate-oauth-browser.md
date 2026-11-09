---
'@eventuras/fides-auth': patch
---

Deprecate `@eventuras/fides-auth/oauth-browser`. Use the server flow
(`handleOidcLogin` / `handleOidcCallback` from `/server`) instead; the entry
point will be removed in a later minor.
