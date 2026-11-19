---
'@eventuras/fides-auth': minor
---

A FAPI 2.0 profile: `profile: 'fapi2'` in the OIDC config enforces what the FAPI 2.0 Security Profile asks of a client, so a config that falls short throws instead of running as something weaker. Creating the client, with `createOidcClient` or `createFidesAuth`, throws a `TypeError` naming every requirement that isn't met: `clientAuth` must be `private_key_jwt`, `usePar` and `dpop` must be true, `allowInsecureRequests` must not be set, and the private key must not be an RS256 key.

With the profile, `verifyIdToken` and `verifyLogoutToken` accept only `PS256`, `ES256` and `EdDSA`, and an `algorithms` option with anything else throws a `TypeError`. A token response whose ID token is signed with another algorithm is refused at the code exchange and at a refresh. `exchangeCode` refuses a callback without the `iss` parameter (RFC 9207) before the code is sent to the token endpoint, whatever the provider's metadata says of it.

It is not a certification, and the provider must follow FAPI 2.0 too. mTLS, `dpop_jkt` and FAPI 2.0 Message Signing (JAR, JARM) are not implemented. Without `profile`, nothing changes.
