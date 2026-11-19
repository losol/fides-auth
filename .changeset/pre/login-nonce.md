---
'@eventuras/fides-auth': minor
---

A login now sends a `nonce`, and the callback takes the ID token only when it carries it. PKCE and `state` already tie the code to the browser that started the login; the nonce ties the ID token itself to that login, so one issued for another login is refused even where the provider's PKCE check fails. The nonce is 32 random bytes, sealed in the login transaction cookie with the verifier. It is sent when the scope has `openid`, and with it the token response must have an ID token.

With `createFidesAuth` there is nothing to change. A login that was started before the upgrade and finishes after it sent no nonce and is checked for none.

With the OIDC client on its own, `createAuthorizationRequest` returns the `nonce` and puts it in `parameters`, and `exchangeCode` reads it from the request. Pass `exchangeCode` the request as it was returned, or its `nonce` along with `codeVerifier` and `state`: without it the provider's ID token carries a nonce the exchange doesn't expect, and is refused. `nonce` stays a reserved authorization parameter.
