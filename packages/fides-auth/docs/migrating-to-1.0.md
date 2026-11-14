# Migrating to 1.0

fides-auth reaches 1.0 in four minor releases, 0.16 to 0.19, as
[ADR 0001](https://github.com/losol/fides-auth/blob/main/docs/adr/0001-module-structure-and-bff.md) plans. Each
release adds part of the new API next to the old one and deprecates what it
replaces. Nothing is removed before 1.0, so you can move one release at a time.

This doc grows a section per release. Every `@deprecated` tag in the code names
the replacement, and this doc collects them.

## 0.16: the OIDC client

**New**

- **`@eventuras/fides-auth/oidc`.** `createOidcClient(config, { logger, discoveryTtlMs })`
  holds the config, the discovery and JWKS caches and the logger. Two clients
  share no state, and creating one does no I/O.
- **Types on the root entry.** `Session`, `Tokens`, `OAuthConfig`,
  `ClientAuthConfig`, `TokenResponse`, `CookieOptions`, `FidesLogger`,
  `FidesLoggerFactory` and `FidesLoggerOptions` come from
  `@eventuras/fides-auth`.
- **`redirectUri` in the config.** `redirect_uri` still works. Set one, or both
  to the same value.
- **`CookieTooLargeError` from `/server`.**

Nothing changes behaviour. The deprecated APIs keep working until 1.0.

### From the protocol functions to the client

Create the client once, for example at module load, and reuse it:

```ts
import { createOidcClient } from "@eventuras/fides-auth/oidc";

const oidc = createOidcClient(oauthConfig, { logger });
```

| 0.15 | 0.16 |
|---|---|
| `buildPKCEOptions(config, options)` | `oidc.createAuthorizationRequest(options)`. The fields are camelCase: `codeVerifier`, `codeChallenge`, `state`, `parameters`. |
| `discoverAndBuildAuthorizationUrl(config, pkce)` | `oidc.authorizationUrl(request)`. It uses PAR when `usePar` is set. |
| `buildAuthorizationUrl(configuration, pkce)`, `buildAuthorizationUrlWithPAR(configuration, pkce)` | `oidc.authorizationUrl(request)` |
| `exchangeAuthorizationCode(config, callbackUrl, codeVerifier, state)` | `oidc.exchangeCode(callbackUrl, { codeVerifier, state })` |
| `refreshAccessToken(config, refreshToken)` | `oidc.refresh(refreshToken)` |
| `clientCredentialsGrant({ tokenEndpoint, clientId, ... })` | `oidc.clientCredentials({ scope })`. Without discovery, set `serverMetadata: { issuer, token_endpoint }` in the client's config. |
| `buildOidcLogoutUrl(config, options)` | `oidc.logoutUrl(options)`. The string shorthand for `postLogoutRedirectUri` goes. |
| `verifyIdToken(idToken, { issuer, audience, oauthConfig })` from `/id-token` | `oidc.verifyIdToken(idToken)`. The issuer comes from the metadata, and the audience is the client ID. |
| `extractUserFromTokens(tokens)` | `userFromClaims(await oidc.verifyIdToken(tokens.id_token))`. It verifies the token first. |
| `discoverConfiguration(config).serverMetadata()` | `oidc.metadata()` |
| `buildSilentLoginUrl(config, options)` | `oidc.silentLoginUrl(request, options)`, with a request from `createAuthorizationRequest`. The URL now carries `state` and PKCE, so the callback can check them. |

### Global settings

| 0.15 | 0.16 |
|---|---|
| `configureLogger(factory)` | `createOidcClient(config, { logger: factory })`. Until 1.0, a client without `logger` uses the factory set here. |
| `configureDiscoveryCache({ ttlMs })` | `createOidcClient(config, { discoveryTtlMs })` |
| `clearDiscoveryCache()`, `clearJwksCache()` | Create a new client. Each client has its own caches, so tests need no resets. |

### Imports that move

| 0.15 | 0.16 |
|---|---|
| `createPkcePair`, `createState`, `PkcePair` from `/pkce` | `@eventuras/fides-auth/oidc` |
| `defaultScope`, `joinScope` from `/oauth` | `@eventuras/fides-auth/oidc` |
| `checkSilentLoginResult`, `requiresInteractiveLogin`, `SilentLoginResult` from `/silent-login` | `@eventuras/fides-auth/oidc` |
| `getOAuthErrorLogContext`, `classifyRefreshFailure` from `/oauth-logging` | `@eventuras/fides-auth/oidc` |
| `AuthorizationRequestOptions`, `OidcLogoutOptions`, `OidcUserInfo` from `/oauth` | `@eventuras/fides-auth/oidc` |
| `Session`, `Tokens` from `/types` | `@eventuras/fides-auth` |
| `FidesLogger`, `FidesLoggerFactory`, `FidesLoggerOptions` from `/logger` | `@eventuras/fides-auth` |
| `CookieOptions` from `/cookies` | `@eventuras/fides-auth` |
| `OAuthConfig`, `ClientAuthConfig` from `/oauth` | `@eventuras/fides-auth` |
| `TokenEndpointResponse` from `/oauth` | `TokenResponse` from `@eventuras/fides-auth`. The two have the same shape. |
| `CookieTooLargeError` from `/cookies` | `@eventuras/fides-auth/server` |

### Deprecated with no replacement

These go in 1.0:

- **`/rate-limit` and `TokenBucket`.** Pass a `rateLimit` callback to the
  handlers instead.
- **The `/cookies` constants and helpers.** From 0.17, read the cookie names
  from the `createFidesAuth` instance.
- **`createLogger` from `/logger`.** Log through your own logger.
- **`resolveClientAuth`.** The client sets up client authentication from its
  config.
- **`getOAuthConfigLogContext`, `SilentLoginErrors` and `CreateSessionOptions`.**
- **`/utils`.** For the crypto helpers, use Web Crypto directly:

| `/utils` | Web Crypto |
|---|---|
| `toHex(bytes)` | `Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")` |
| `sha256(data)`, `sha512(data)` | `toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data))))` |
| `generateToken(n)` | `toHex(crypto.getRandomValues(new Uint8Array(n)))` |
| `encrypt(text, key)`, `decrypt(data, key)` | `crypto.subtle.encrypt` and `decrypt` with `{ name: "AES-GCM", iv }` and a 12-byte random IV. The old format is `iv:tag:ciphertext` in hex, with the 16-byte tag split off the end of the ciphertext. |
| `hexToUint8Array(hex)` | `Uint8Array.from(hex.match(/../g) ?? [], (h) => Number.parseInt(h, 16))` |

`createEncryptedJWT`, `decryptJWT`, `accessTokenExpires` and `hasScope` become
internal. For `hasScope(session, scope)`, check `session.scopes?.includes(scope)`.

### Not deprecated yet

- **`buildSessionFromTokens`, `validateReturnUrl` and `MapSession` in `/oauth`,
  and the free `/server` functions.** In 0.17, `createFidesAuth` replaces them.
- **The root entry's functions.** The root becomes types-only in 1.0. Import
  functions from their own entries, such as `SESSION_EVENT` from
  `/session-events`.
