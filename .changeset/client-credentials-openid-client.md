---
'@eventuras/fides-auth': minor
---

Route `clientCredentialsGrant` through openid-client instead of a raw `fetch`.

It was the one place the server module talked to a token endpoint directly, so it
missed the transport guards the rest of the package gets for free — while being the
request that carries the client secret. Three behaviour changes, all breaking:

- The token endpoint must now be **https**. A plain-http endpoint rejects with
  `OAUTH_HTTP_REQUEST_FORBIDDEN` instead of posting the secret in the clear.
- Failures throw openid-client's typed errors rather than a generic
  `Error("Client credentials grant failed: <status> - <body>")`. Code matching on
  that message needs updating.
- Requests time out, 30 seconds by default, where previously they never did.
  Configurable via the new `timeout` option (seconds).

Also adds an optional `issuer` to `ClientCredentialsConfig`, defaulting to the token
endpoint's origin.
