---
'@eventuras/fides-auth': minor
---

New `@eventuras/fides-auth/id-token` entry point with `verifyIdToken(idToken, options)`.
It checks the signature, `iss`, `aud` and `exp` against the provider's JWKS and returns
the claims. Pass `jwksUri`, or an `oauthConfig` to use `jwks_uri` from its metadata.
Only asymmetric algorithms are accepted by default. The JWKS is cached per URI;
`clearJwksCache()` resets it. Runs in the browser too.
