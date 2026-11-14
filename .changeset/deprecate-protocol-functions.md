---
'@eventuras/fides-auth': minor
---

The free protocol functions are deprecated in favour of a client from `createOidcClient`
(`@eventuras/fides-auth/oidc`): `buildPKCEOptions`, `buildAuthorizationUrl`,
`buildAuthorizationUrlWithPAR`, `discoverAndBuildAuthorizationUrl`, `exchangeAuthorizationCode`,
`refreshAccessToken`, `clientCredentialsGrant`, `buildOidcLogoutUrl`, `verifyIdToken`,
`discoverConfiguration`, `resolveClientAuth`, `buildSilentLoginUrl` and `extractUserFromTokens`, with
their option types. So are the global settings `configureLogger`, `configureDiscoveryCache`,
`clearDiscoveryCache` and `clearJwksCache`, and `TokenBucket`. Each `@deprecated` tag names the
replacement. All of them keep working until 1.0. `docs/migrating-to-1.0.md` has the full table.
