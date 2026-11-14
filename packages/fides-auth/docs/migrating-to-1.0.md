# Migrating to 1.0

fides-auth reaches 1.0 in two steps, as
[ADR 0001](https://github.com/losol/fides-auth/blob/main/docs/adr/0001-module-structure-and-bff.md) plans:

- **0.16** adds the OIDC client and deprecates what it replaces. Nothing changes
  behaviour, so you can move at your own pace.
- **1.0** replaces the server side and removes everything deprecated. It doesn't
  read 0.x sessions, so your users log in again once when you upgrade.

This doc has a section per step. Every `@deprecated` tag in the code names the
replacement, and this doc collects them.

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
- **The `/cookies` constants and helpers.** From 1.0, read the cookie names
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

### Not deprecated

- **`buildSessionFromTokens`, `validateReturnUrl` and `MapSession` in `/oauth`,
  and the free `/server` functions.** In 1.0, `createFidesAuth` replaces them.
- **The root entry's functions.** The root becomes types-only in 1.0. Import
  functions from their own entries, such as `SESSION_EVENT` from
  `/session-events`.

## 1.0: the server side, and what 0.16 deprecated

**New**

- **`createFidesAuth(config)` from `/server`.** One object holds the OIDC
  client, the session storage and the guards. Its members take the `Request`
  and a `CookieStore`:
  - the handlers `handleOidcLogin`, `handleOidcCallback`, `handleOidcLogout`,
    `handleHeartbeat` and `handleSessionInfo`
  - the session members `readSession`, `tryReadSession`, `getTokens`,
    `refreshSession`, `createSession`, `updateSession`, `clearSession` and
    `authorizedFetch`
- **One session cookie.** The session lives in `__Host-session` (`session` over
  plain http), in at most three chunks. With a `sessionStore`, the cookie holds
  only a handle.
- **A same-origin check.** Logout and heartbeat answer only a `POST` from the
  app's own pages.
- **`handleSessionInfo`.** Answers `GET` with whether there is a session, and
  whose. It never refreshes and never returns tokens.
- **`SessionSecretError` from `/server`.**

**Changed**

- **`Session` is the new session shape.** It has `correlationId`, `createdAt`,
  `expiresAt`, `user`, `scopes`, `idp` and `data`, and no tokens: get them with
  `getTokens`.
- **Session events carry `correlationId`, not `sid`.** Update log queries and
  dashboards that filter on `sid`.
- **A session ends after `sessionDurationDays`** (30 by default), whatever the
  refreshes. A read after that answers `session_expired`.
- **A custom `SessionStore` should save the new `StoredSession` fields:**
  `correlationId`, `iss`, `subHash` and `idpSidHash`. `sid` goes: the
  correlation id is `correlationId`.
- **`CookieStore` has only `get` and `set`.** The library deletes a cookie by
  setting it empty with `maxAge: 0`, so an adapter needs no `delete`.
- **Nothing refreshes unless you ask.** `authorizedFetch` no longer refreshes
  on a 401: it throws an `http_error`, and the `refresh` option and the
  `refresh_failed` reason go. Call `refreshSession({ ifExpiresWithin: 60 })`
  first, where cookies can be written. It refreshes only when the access token
  expires within that many seconds, and its result says whether it
  `refreshed`. After a 401, the error's `accessTokenExpired` and `bearerError`
  say whether a refresh is likely to help.
- **Users log in again once.** 1.0 doesn't read 0.x sessions, and deletes their
  cookies the next time it writes a session.

**Gone**

- **The free `/server` functions.** The instance's members replace them:

  | 0.x | 1.0 |
  |---|---|
  | `handleOidcLogin`, `handleOidcCallback`, `handleOidcLogout`, `handleHeartbeat` | the same members on the instance, with the options in `createFidesAuth` |
  | `readSession(cookies, secret)`, `tryReadSession(cookies, secret)` | `readSession(cookies)`, `tryReadSession(cookies)` |
  | `refreshSessionInStore`, `tryRefreshSessionInStore` | `refreshSession(cookies, { ifExpiresWithin? })` |
  | `persistSession(cookies, session, secret)` | `createSession(cookies, tokenResponse)` |
  | `clearSession(cookies, options)` | `clearSession(cookies, options)` |
  | `readIdToken(cookies, secret)` | `getTokens(cookies)`, then `idToken` |
  | `authorizedFetch(session, url, options)` | `authorizedFetch(cookies, url, options)`, which doesn't refresh |
  | `serverPersistence({ store, secret })`, `cookiePersistence(secret)` | `sessionStore` in `createFidesAuth`, or nothing |

- **The login transaction helpers**: `createTransaction`, `persistTransaction`,
  `readTransaction`, `clearTransaction`, `validateCallback`,
  `transactionCookieOptions` and `CallbackValidationError`. The login and
  callback handlers use them; for a custom flow, use the OIDC client from
  `/oidc` and keep the authorization request on your server.
- **`/session-cookies`, `/session-refresh` and `/session-validation`**, with
  `validateSessionJwt`, `refreshSession(session, config)` and the cookie codec.
  The instance reads, refreshes and seals the session itself.
- **`buildSessionFromTokens` and `MapSession` in `/oauth`.** Pass `mapSession`
  and `rolesClaim` to `createFidesAuth`, and import `MapSession` from `/server`.
- **`LegacySession` and `CreateSessionOptions`.**
- **The rejected reason `stale_legacy_session`.** 1.0 doesn't read 0.x
  cookies, so a browser that still has them reads as `no_session_cookie`, or as
  `unreadable_session` over plain http, where the new cookie is also called
  `session`.

### What 0.16 deprecated

All of it goes in 1.0. The [0.16 tables](#016-the-oidc-client) say what
replaces each export.

- **The entries** `/oauth`, `/pkce`, `/id-token`, `/oidc-discovery`,
  `/oauth-logging`, `/silent-login`, `/types`, `/logger`, `/cookies`, `/utils`,
  `/rate-limit` and `/oauth-browser`. Core has six entries: the root, `/oidc`,
  `/server`, `/browser`, `/session-events` and `/providers/vipps`.
- **The free protocol functions.** Create a client with `createOidcClient` and
  call its methods.
- **The global settings**: `configureLogger`, `configureDiscoveryCache`,
  `clearDiscoveryCache` and `clearJwksCache`. Pass `logger` to each part that
  logs: `createFidesAuth`, `createOidcClient`, `createAuthStore`,
  `startSessionMonitor`, `createHeartbeat` and `VippsLoginClient`. A part
  without one writes JSON lines to the console.
- **`redirect_uri`.** Set `redirectUri`. `OAuthConfig` goes with it: the config
  type is `OidcClientConfig`, from the root or `/oidc`.
- **The root entry's functions and constants.** The root exports only types:
  `Session`, `Tokens`, `TokenResponse`, `SessionInfo`, `HeartbeatResponse`,
  `IdpSession`, `CookieOptions`, `OidcClientConfig`, `ClientAuthConfig`,
  `FidesLogger`, `FidesLoggerFactory` and `FidesLoggerOptions`.
- **`logSessionEvent`, `sessionEventLevel`, `newSessionId` and
  `SESSION_REJECTED_REASONS`.** `/session-events` keeps `SESSION_EVENT`,
  `isSessionRejectedReason` and the event types. To log an event yourself, see
  [Consuming the vocabulary](./session-events.md#consuming-the-vocabulary), and
  to get the library's own, pass `onSessionEvent` to `createFidesAuth`.

**Changed**

- **`VippsLoginClient` is built on the OIDC client**, with its method names:

  | 0.x | 1.0 |
  |---|---|
  | `buildPKCEOptions(options)` | `createAuthorizationRequest(options)` |
  | `buildAuthorizationUrl(pkce)` | `authorizationUrl(request)` |
  | `exchangeCodeForTokens(callbackUrl, codeVerifier, state)` | `exchangeCode(callbackUrl, { codeVerifier, state })` |
  | `refreshTokens(refreshToken)` | `refresh(refreshToken)` |
  | `getUserInfo(accessToken)` | `getUserInfo(accessToken)` |

  `vipps.oidc` is the client underneath, and a second constructor argument
  takes `logger` and `discoveryTtlMs`.
- **Core is a peer dependency** of `fides-auth-next` and `fides-auth-react`.
  Install it next to them, for example
  `pnpm add @eventuras/fides-auth @eventuras/fides-auth-next`. All three need
  Node 22.

### fides-auth-next

`createFidesAuth` from `@eventuras/fides-auth-next` is the core instance bound to
`cookies()`. It takes the same config as core's. The options that the handlers
took per call move to it: `applicationUrl`, `mapSession`, `rolesClaim`,
`validateReturnTo`, `defaultRedirectPath`, `postLogoutRedirectUri`,
`sessionDurationDays` and `rateLimit`.

| 0.x | 1.0 |
|---|---|
| `getCurrentSession()` | `readSession()` |
| `tryGetCurrentSession()` | `tryReadSession()` |
| `refreshCurrentSession()`, `tryRefreshCurrentSession()` | `refreshSession({ ifExpiresWithin? })`, which says why on failure |
| `createAndPersistSession(session)` | `createSession(tokenResponse)` |
| `clearCurrentSession(options)` | `clearSession(options)` |
| `authorizedFetch(session, url, options)` | `authorizedFetch(url, options)`: it reads the tokens itself and never refreshes, so `refresh: false` goes |
| `handleOidcLogin(request, { validateReturnTo, authorizationParameters })` | `handleOidcLogin(request, { authorizationParameters })` |
| `handleOidcCallback(request, { applicationUrl, ... })` | `handleOidcCallback(request)` |
| `handleOidcLogout(request, { postLogoutRedirectUri, state, logoutHint, ... })` | `handleOidcLogout(request, { state, logoutHint })` |
| `handleHeartbeat(request)` | `handleHeartbeat(request)` |

New on the instance: `handleSessionInfo`, `getTokens`, `updateSession`,
`cookieNames`, `oidc` and `refreshInProxy(request)`. `refreshInProxy` goes in
`proxy.ts`. It refreshes a session about to expire before the page renders,
which a Server Component can't do itself.

**Gone**

- **The subpaths.** `./auth`, `./cookie-store`, `./request`, `./oidc-login`,
  `./oidc-callback`, `./oidc-logout` and `./heartbeat-handler`: import from
  the root.
- **`./store`.** It re-exported `@eventuras/fides-auth-store` and
  `@eventuras/fides-auth-react`. Import the store from
  `@eventuras/fides-auth/browser` and the hooks from `@eventuras/fides-auth-react`;
  see the next section.
- **The cookie helpers and constants**, such as `setAuthCookie`,
  `getSessionCookie` and `ACCESS_TOKEN_COOKIE_NAME`. The instance owns its
  cookies, and `cookieNames.session` names the session cookie.
- **The default rate limiter**: `globalGETRateLimit`, `globalPOSTRateLimit` and
  `TokenBucket`. The handlers rate-limit only through `rateLimit`.
- **The core re-exports** from `/oauth`, `/logger`, `/session-events`,
  `/session-refresh`, `/session-validation`, `/silent-login`, `/utils` and
  `/types`. Import what remains from `@eventuras/fides-auth`. The root re-exports the types
  an app needs for the instance: `Session`, `Tokens`, `FidesAuthConfig`,
  `SessionStore` and others.
- **Logout options.** `allowedMethods` goes, since logout answers only `POST`.
  `fallbackRedirectUri` goes, since `postLogoutRedirectUri` is the fallback.
  `includeClientId` goes, and `client_id` is always sent.
- **The per-request refresh sharing.** The instance shares refreshes itself.

### The browser side and React

The session store, the session monitor, heartbeat and the activity tracker are
in core's `@eventuras/fides-auth/browser`. `@eventuras/fides-auth-react` keeps
the hooks, rebuilt on that store, and `@eventuras/fides-auth-store` ends at 0.x.

| 0.x | 1.0 |
|---|---|
| `@eventuras/fides-auth-store` | `@eventuras/fides-auth/browser` |
| `@eventuras/fides-auth/heartbeat`, `/activity-tracker` | `@eventuras/fides-auth/browser` |
| `createAuthStore({ checkAuthStatus, config: { adminRole } })` | `createAuthStore({ adminRole })`, which asks `/api/auth/session` by default; `checkAuthStatus` and `sessionEndpoint` replace that |
| `store.send({ type: 'authSuccess', user })` and the other events | `store.authSuccess(user)`, `authFailed(error?)`, `sessionExpired()`, `logout()`, `setError(error)`, `clearError()` |
| `store.getSnapshot().context` | `store.getSnapshot()` |
| `initializeAuth(store, check)`, `checkAuth(store, check)` | `initializeAuth(store)`, `checkAuth(store)` |
| `startSessionMonitor(store, check, config)` | `startSessionMonitor(store, config)` |
| `useSessionMonitor(store, check, config)` | `useSessionMonitor(store, config)` |
| `loggerNamespace` on the store, the monitor and the heartbeat | `logger`, a `FidesLoggerFactory` |
| `configureAuthLogger()` | pass `logger` where you want `@eventuras/logger` |

**Changed**

- **No XState.** The store is the library's own. `@xstate/store` and
  `@xstate/store-react` are no longer needed, and the hooks read the store with
  React's `useSyncExternalStore`.
- **The check is the session info endpoint.** The store and the monitor ask
  `handleSessionInfo` unless you give them another check. Its user is the
  session's `user`, with `sub`, and `roles` may be absent.
- **The monitor leaves a visitor alone.** It reports an expired session only
  when the store held one, so it can run on every page.
- **`useSessionMonitor` doesn't restart on every render.** It reads its
  callbacks through a ref.
- **`loginSuccess` and `updateLastChecked` go.** Use `authSuccess`; the store
  sets `lastChecked` on every check.

