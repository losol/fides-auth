---
'@eventuras/fides-auth': minor
---

The root entry exports the types shared across layers: `OAuthConfig`, `ClientAuthConfig` and a new
`TokenResponse` join `Session`, `Tokens`, `CookieOptions`, `FidesLogger` and `FidesLoggerFactory`.
`TokenResponse` has the same shape as openid-client's `TokenEndpointResponse`, so either works where
the other is expected. `/server` exports `CookieTooLargeError`.

The old subpaths are deprecated, and each `@deprecated` tag names the new home: `/oauth`, `/pkce`,
`/id-token`, `/oidc-discovery`, `/oauth-logging` and `/silent-login` (now `/oidc`), and `/types`,
`/logger`, `/cookies`, `/utils` and `/rate-limit`. They keep working until 1.0.

New: `docs/migrating-to-1.0.md`, with a 0.16 section and an old-to-new table.
