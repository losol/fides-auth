---
'@eventuras/fides-auth': patch
---

An http issuer, or an http endpoint in the provider's metadata, throws a `TypeError` that names the
URL and says what to set, where openid-client only answered `OAUTH_HTTP_REQUEST_FORBIDDEN` and login
failed with a bare 500. `allowInsecureRequests: true` in the OIDC config allows http to a provider on a
loopback address (`localhost`, `*.localhost`, `127.0.0.0/8`, `[::1]`) for development and CI; any
other http URL still throws.
