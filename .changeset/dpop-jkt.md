---
'@eventuras/fides-auth': minor
---

With `dpop: true`, the authorization code is now bound to the DPoP key too (`dpop_jkt`, RFC 9449 §10). The key is made when the login starts instead of at the callback, its thumbprint goes in the authorization request, through PAR when `usePar` is set, and the key is sealed in the login transaction cookie next to the PKCE verifier. A provider that supports `dpop_jkt` then issues a code only that key can exchange, so a code that leaks is of no use to anyone else. A provider that doesn't ignores the parameter. A login that was started before the upgrade has no key in its transaction and gets one at the callback, as before.

On the OIDC client, `createAuthorizationRequest({ dpopKey })` sends the thumbprint; pass the same key to `exchangeCode`. `dpop_jkt` is now a reserved authorization parameter. With `profile: 'fapi2'`, `createAuthorizationRequest` throws without a `dpopKey`; `createFidesAuth` passes one by itself.
