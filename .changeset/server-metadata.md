---
'@eventuras/fides-auth': minor
---

`OAuthConfig.serverMetadata` skips OIDC discovery: the configuration is built from
the given metadata and cached the same way. With `openid` in the scope the metadata
must include `issuer`.
