---
'@eventuras/fides-auth': major
---

What 0.16 deprecated is removed. Core has six entries: the root, `/oidc`, `/server`, `/browser`,
`/session-events` and `/providers/vipps`.

Removed:

- The entries `/oauth`, `/pkce`, `/id-token`, `/oidc-discovery`, `/oauth-logging`, `/silent-login`,
  `/types`, `/logger`, `/cookies`, `/utils`, `/rate-limit` and `/oauth-browser`.
- The free protocol functions, such as `buildPKCEOptions`, `exchangeAuthorizationCode`,
  `refreshAccessToken`, `clientCredentialsGrant`, `buildOidcLogoutUrl`, `verifyIdToken`,
  `discoverConfiguration` and `buildSilentLoginUrl`. A client from `createOidcClient` has a method
  for each.
- The global settings `configureLogger`, `configureDiscoveryCache`, `clearDiscoveryCache` and
  `clearJwksCache`. Pass `logger` to each part that logs, and `discoveryTtlMs` to
  `createOidcClient`. A part without `logger` writes JSON lines to the console.
- `redirect_uri` in the config: set `redirectUri`. `OAuthConfig` goes with it; the config type is
  `OidcClientConfig`, from the root or `/oidc`.
- The root entry's functions and constants. The root exports only types: `Session`, `Tokens`,
  `TokenResponse`, `SessionInfo`, `HeartbeatResponse`, `IdpSession`, `CookieOptions`,
  `OidcClientConfig`, `ClientAuthConfig`, `FidesLogger`, `FidesLoggerFactory` and
  `FidesLoggerOptions`.
- `logSessionEvent`, `sessionEventLevel`, `newSessionId` and `SESSION_REJECTED_REASONS` from
  `/session-events`, which keeps `SESSION_EVENT`, `isSessionRejectedReason` and the event types.

`VippsLoginClient` is built on `createOidcClient` and takes its method names:
`createAuthorizationRequest`, `authorizationUrl`, `exchangeCode(callbackUrl, { codeVerifier, state })`
and `refresh`. `getUserInfo` stays, `oidc` is the client underneath, and a second constructor
argument takes `logger` and `discoveryTtlMs`.

Core needs Node 22. See `docs/migrating-to-1.0.md`.
