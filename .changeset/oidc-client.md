---
'@eventuras/fides-auth': minor
---

New entry `@eventuras/fides-auth/oidc` with `createOidcClient(config, { logger, discoveryTtlMs })`
(ADR 0001). A client holds its config, discovery cache, JWKS cache and logger, so two clients share
no state, and creating one does no I/O. Its methods are `metadata`, `createAuthorizationRequest`,
`authorizationUrl`, `silentLoginUrl`, `exchangeCode`, `refresh`, `clientCredentials`, `logoutUrl` and
`verifyIdToken`. The entry also exports the pure helpers `createPkcePair`, `createState`,
`defaultScope`, `joinScope`, `userFromClaims`, `checkSilentLoginResult`, `requiresInteractiveLogin`,
`getOAuthErrorLogContext` and `classifyRefreshFailure`.

`OAuthConfig` accepts `redirectUri` next to `redirect_uri`. The client's config, `OidcClientConfig`,
needs a redirect URI only for the operations that use one.

The free functions in `/oauth`, `/oidc-discovery`, `/id-token` and `/silent-login` behave as before.
