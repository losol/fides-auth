# Upgrading to 1.0

This guide takes an app from any 0.x to 1.0. Each table maps what the app uses
today to what replaces it.

## Before you upgrade

- **Install core next to the framework package.** Core is a peer dependency of
  `fides-auth-next` and `fides-auth-react`:

  ```bash
  pnpm add @eventuras/fides-auth @eventuras/fides-auth-next
  ```

- **Node 22.** All three packages need it.
- **Users log in again once.** 1.0 doesn't read 0.x sessions, and deletes their
  cookies the next time it writes a session. With an active session at the
  provider, that is usually a redirect without a password. A login in progress
  during the deploy has to start again.
- **Replace every instance at once.** 0.x and 1.0 can't read each other's
  sessions, so a rolling deploy, or a rollback, can log a user out more than
  once.
- **A `SessionStore` keeps its 0.x records** until their TTL. 1.0 reads them as
  `unreadable_session`.
- **Log queries and dashboards that filter on `sid`** filter on `correlationId`
  instead.

## Server

One instance replaces the free `/server` functions. Its members take the
`Request` and a `CookieStore`, which needs only `get` and `set`:

```ts
import { createFidesAuth } from "@eventuras/fides-auth/server";

export const auth = createFidesAuth({
  oauthConfig: { issuer, clientId, clientSecret, redirectUri, scope },
  secret: process.env.SESSION_SECRET!,
});
```

| 0.x | 1.0 |
|---|---|
| `handleOidcLogin`, `handleOidcCallback`, `handleOidcLogout`, `handleHeartbeat` with options per call | the same members on the instance. The options that don't vary per request move to `createFidesAuth`: `applicationUrl`, `mapSession`, `rolesClaim`, `validateReturnTo`, `defaultRedirectPath`, `postLogoutRedirectUri`, `rateLimit` and `sessionDurationDays`, which is now `sessionDurationSeconds` |
| — | `handleSessionInfo`: whether there is a session, and whose. Never refreshes, never returns tokens |
| `readSession(cookies, secret)`, `tryReadSession(cookies, secret)` | `readSession(cookies)`, `tryReadSession(cookies)` |
| `refreshSessionInStore`, `tryRefreshSessionInStore`, `refreshSession(session, config)` | `refreshSession(cookies, { ifExpiresWithin? })` |
| `persistSession(cookies, session, secret)` | `createSession(cookies, tokenResponse)` |
| `clearSession(cookies, options)` | `clearSession(cookies, options)` |
| `readIdToken(cookies, secret)`, `session.tokens` | `getTokens(cookies)`, or `readSessionWithTokens(cookies)` for the session and its tokens in one read |
| `authorizedFetch(session, url, options)` | `authorizedFetch(cookies, url, options)`, which never refreshes |
| `serverPersistence({ store, secret })`, `cookiePersistence(secret)` | `sessionStore` in `createFidesAuth`, or nothing for cookies |
| `buildSessionFromTokens`, `MapSession` from `/oauth` | `mapSession` and `rolesClaim` in `createFidesAuth`; `MapSession` from `/server` |
| `validateReturnUrl` | `validateReturnTo` in `createFidesAuth`: `(returnTo) => string \| null` |
| `/session-cookies`, `/session-refresh`, `/session-validation` | the instance reads, refreshes and seals the session itself |
| the login transaction helpers (`createTransaction`, `validateCallback`, …) | internal. For a custom flow, use the OIDC client and keep its authorization request on the server |
| `CookieStore.delete` | not needed: the library deletes a cookie by setting it empty with `maxAge: 0`, so a store must pass `maxAge` on as it is given |
| a `CookieStore` written by hand over a Fetch `Request` | `fetchCookieStore(request)` from `/server`, with `apply(response)` and `headers()` for the `Set-Cookie` lines |

**The session.** `Session` has `correlationId`, `createdAt`, `expiresAt`,
`user`, `scopes`, `idp` and `data`. A type argument,
`createFidesAuth<AppData>(…)`, types `data`. `user.sub` is required and `user.name`
optional. The tokens aren't on it: use `getTokens`. `LegacySession` and
`CreateSessionOptions` are gone.

**A custom `SessionStore`** saves the new `StoredSession` fields:
`correlationId`, `iss`, `subHash`, `idpSidHash` and `fields`. `sid` is gone.
`set` gets a third argument, `{ continuation, reason }`, where `reason` is
`'login'`, `'refresh'` or `'update'`, and an optional `findMatching`
lets `endUserSessions` end a user's sessions. Its match holds `subHash`, and
`iss` only when the caller named an issuer.

## Next.js

`createFidesAuth` from `@eventuras/fides-auth-next` is the core instance bound
to `cookies()`. It takes the same config, and its members drop the `cookies`
argument. Import everything from the package root.

| 0.x | 1.0 |
|---|---|
| `getCurrentSession()`, `tryGetCurrentSession()` | `readSession()`, `tryReadSession()`, cached per render |
| `refreshCurrentSession()`, `tryRefreshCurrentSession()` | `refreshSession({ ifExpiresWithin? })`, which says why on failure |
| — | `refreshInProxy(request, { ifExpiresWithin? })` in `proxy.ts`, to refresh before a page renders |
| `createAndPersistSession(session)` | `createSession(tokenResponse)` |
| `clearCurrentSession(options)` | `clearSession(options)` |
| `authorizedFetch(session, url, options)` | `authorizedFetch(url, options)`. `refresh: false` goes, since it never refreshes |
| `handleOidcLogin(request, { validateReturnTo, authorizationParameters })` | `handleOidcLogin(request, { authorizationParameters })` |
| `handleOidcCallback(request, { applicationUrl, … })` | `handleOidcCallback(request)` |
| `handleOidcLogout(request, { postLogoutRedirectUri, state, logoutHint, … })` | `handleOidcLogout(request, { state, logoutHint })` |
| `allowedMethods`, `fallbackRedirectUri`, `includeClientId` on logout | gone: logout answers only `POST`, `postLogoutRedirectUri` is the fallback, and `client_id` is always sent |
| the subpaths `./auth`, `./cookie-store`, `./request`, `./oidc-login`, `./oidc-callback`, `./oidc-logout`, `./heartbeat-handler` | the package root |
| `./store` | the store from `@eventuras/fides-auth/browser`, the hooks from `@eventuras/fides-auth-react` |
| `setAuthCookie`, `getSessionCookie`, `ACCESS_TOKEN_COOKIE_NAME` and the other cookie helpers | `auth.cookieNames.session` |
| `globalGETRateLimit`, `globalPOSTRateLimit`, `TokenBucket` | `rateLimit` in `createFidesAuth`. There is no default limiter |
| the re-exports of core's `/oauth`, `/logger`, `/utils`, … | import from core's own entries |

New on the instance: `handleSessionInfo`, `getTokens`, `readSessionWithTokens`,
`updateSession`, `cookieNames` and `oidc`.

## OIDC client

Create the client once and reuse it. It holds the config, the discovery and
JWKS caches and the logger, and creating it does no I/O:

```ts
import { createOidcClient } from "@eventuras/fides-auth/oidc";

const oidc = createOidcClient(oauthConfig, { logger, discoveryTtlMs });
```

| 0.x | 1.0 |
|---|---|
| `OAuthConfig` with `redirect_uri` | `OidcClientConfig` with `redirectUri` |
| `buildPKCEOptions(config, options)` | `oidc.createAuthorizationRequest(options)`. The fields are `codeVerifier`, `codeChallenge`, `state` and `parameters` |
| `buildAuthorizationUrl`, `buildAuthorizationUrlWithPAR`, `discoverAndBuildAuthorizationUrl` | `oidc.authorizationUrl(request)`, through PAR when `usePar` is set |
| `buildSilentLoginUrl(config, options)` | `oidc.silentLoginUrl(request, options)`, with a request from `createAuthorizationRequest` |
| `exchangeAuthorizationCode(config, callbackUrl, codeVerifier, state)` | `oidc.exchangeCode(callbackUrl, { codeVerifier, state })` |
| `refreshAccessToken(config, refreshToken)` | `oidc.refresh(refreshToken)` |
| `clientCredentialsGrant({ tokenEndpoint, clientId, … })` | `oidc.clientCredentials({ scope })`. Without discovery, set `serverMetadata: { issuer, token_endpoint }` |
| `buildOidcLogoutUrl(config, options)` | `oidc.logoutUrl(options)`. No string shorthand |
| `verifyIdToken(idToken, { issuer, audience, … })` | `oidc.verifyIdToken(idToken)`: the issuer from the metadata, the client ID as audience |
| `extractUserFromTokens(tokens)` | `userFromClaims(await oidc.verifyIdToken(tokens.id_token))` |
| `discoverConfiguration(config).serverMetadata()` | `oidc.metadata()` |
| `configureDiscoveryCache({ ttlMs })` | `discoveryTtlMs` on the client |
| `clearDiscoveryCache()`, `clearJwksCache()` | create a new client |
| `configureLogger(factory)` | `logger` on each part; see [Logging](#logging) |

**Vipps.** `VippsLoginClient` is built on the OIDC client. A second constructor
argument takes `logger` and `discoveryTtlMs`, and `vipps.oidc` is the client
underneath.

| 0.x | 1.0 |
|---|---|
| `buildPKCEOptions(options)` | `createAuthorizationRequest(options)` |
| `buildAuthorizationUrl(pkce)` | `authorizationUrl(request)` |
| `exchangeCodeForTokens(callbackUrl, codeVerifier, state)` | `exchangeCode(callbackUrl, { codeVerifier, state })` |
| `refreshTokens(refreshToken)` | `refresh(refreshToken)` |

## Browser and React

| 0.x | 1.0 |
|---|---|
| `@eventuras/fides-auth-store`, `@eventuras/fides-auth/heartbeat`, `/activity-tracker` | `@eventuras/fides-auth/browser` |
| `createAuthStore({ checkAuthStatus, config: { adminRole } })` | `createAuthStore({ adminRole })`. It asks `/api/auth/session` (`handleSessionInfo`); `sessionEndpoint` or `checkAuthStatus` change that |
| `store.send({ type: 'authSuccess', user })` and the other events | `store.authSuccess(user)`, `authFailed(error?)`, `sessionExpired()`, `logout()`, `setError(error)`, `clearError()` |
| `loginSuccess`, `updateLastChecked` | `authSuccess`. The store sets `lastChecked` on every check |
| `store.getSnapshot().context` | `store.getSnapshot()` |
| `initializeAuth(store, check)`, `checkAuth(store, check)` | `initializeAuth(store)`, `checkAuth(store)` |
| `startSessionMonitor(store, check, config)` | `startSessionMonitor(store, config)` |
| `useSessionMonitor(store, check, config)` | `useSessionMonitor(store, config)` |
| `loggerNamespace`, `configureAuthLogger()` | `logger` on the store, the monitor and the heartbeat |
| `AuthStoreSelector`, `HeartbeatConfig` from `fides-auth-react` | the types from `@eventuras/fides-auth/browser` |
| `@xstate/store`, `@xstate/store-react` | not needed |

The monitor reports an expired session only when the store held one, so it can
run on every page. `useSessionMonitor` and `useHeartbeat` read their callbacks
through a ref, so new ones on each render don't restart them.

## Imports

The root exports only types: `Session`, `Tokens`, `TokenResponse`,
`SessionInfo`, `HeartbeatResponse`, `IdpSession`, `CookieOptions`,
`OidcClientConfig`, `ClientAuthConfig`, `FidesLogger`, `FidesLoggerFactory`
and `FidesLoggerOptions`.

| 0.x | 1.0 |
|---|---|
| `/oauth`, `/pkce`, `/id-token`, `/oidc-discovery`, `/oauth-logging`, `/silent-login` | `/oidc` |
| `/types`, `/logger`, and `CookieOptions` from `/cookies` | the root |
| `TokenEndpointResponse` from `/oauth` | `TokenResponse` from the root |
| `CookieTooLargeError` from `/cookies` | `/server` |
| `/session-events` | `/session-events`, with `SESSION_EVENT`, `isSessionRejectedReason` and the event types |
| functions and constants from the root | their own entries, or gone (below) |

## Gone without a replacement

- **`/utils`.** Use Web Crypto directly:

  | `/utils` | Web Crypto |
  |---|---|
  | `toHex(bytes)` | `Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")` |
  | `sha256(data)`, `sha512(data)` | `toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data))))` |
  | `generateToken(n)` | `toHex(crypto.getRandomValues(new Uint8Array(n)))` |
  | `hexToUint8Array(hex)` | `Uint8Array.from(hex.match(/../g) ?? [], (h) => Number.parseInt(h, 16))` |
  | `encrypt(text, key)`, `decrypt(data, key)` | `crypto.subtle.encrypt` and `decrypt` with `{ name: "AES-GCM", iv }` and a 12-byte random IV. The old format is `iv:tag:ciphertext` in hex, with the 16-byte tag split off the end of the ciphertext |
  | `hasScope(session, scope)` | `session.scopes?.includes(scope)` |

- **`/rate-limit` and `TokenBucket`.** Pass `rateLimit` to `createFidesAuth`,
  with the limiter of your choice.
- **`/oauth-browser`.** Use the server flow.
- **The cookie constants and helpers from `/cookies`**, such as
  `SESSION_COOKIE_NAME` and `defaultSessionCookieOptions`. Read the session
  cookie's name from `auth.cookieNames`.
- **`createLogger`, `configureLogger`.** See [Logging](#logging).
- **`logSessionEvent`, `sessionEventLevel`, `newSessionId` and
  `SESSION_REJECTED_REASONS`.** Pass `onSessionEvent` to `createFidesAuth` to
  get the library's events, or log your own as
  [Session events](./session-events.md#consuming-the-vocabulary) shows.
- **`resolveClientAuth`, `getOAuthConfigLogContext`, `SilentLoginErrors`,
  `createEncryptedJWT`, `decryptJWT` and `accessTokenExpires`.**
- **The rejected reason `stale_legacy_session`.** A browser with 0.x cookies
  reads as `no_session_cookie`, or as `unreadable_session` over plain http.

## Logging

There is no global logger. Pass a `FidesLoggerFactory` as `logger` to each part
that logs: `createFidesAuth`, `createOidcClient`, `VippsLoginClient`,
`createAuthStore`, `startSessionMonitor` and `createHeartbeat`. A part without
one writes JSON lines to the console.

## Behaviour that changes

- **A session ends `sessionDurationSeconds` after login**, however often it is
  refreshed, and 12 hours is the default. A read after that answers
  `session_expired`. 0.x counted days in `sessionDurationDays`, with 30 as the
  default: to keep that, set `sessionDurationSeconds: 30 * 24 * 60 * 60`.
  `createFidesAuth` throws on the old name, so it can't be left behind unnoticed.
- **Nothing refreshes unless you ask.** `authorizedFetch` throws an
  `http_error` on a 401. Its `refresh` option, the `refresh_failed` reason, and
  `refreshed` and `refreshFailure` in its result are gone. Call `refreshSession({ ifExpiresWithin: 60 })` where cookies
  can be written, `refreshInProxy` in Next's `proxy.ts`, or let the heartbeat
  do it. After a 401, the error's `accessTokenExpired` and `bearerError` say
  whether a refresh is likely to help.
- **Logout and heartbeat answer only a same-origin `POST`.** Anything else gets
  403, or 405 for another method.
- **A login that fails always redirects**, to `defaultRedirectPath` with
  `?login=error&error=<code>`. 0.x answered some failures with a status and
  English text. A page that sends users without a session to the login must
  leave a URL with `login=error` alone. `onLoginError` answers in another way.
- **A rate-limited login and a failed logout redirect too**, to
  `?login=error&error=rate_limited` and `?logout=error&error=<code>`. 0.x
  answered them with a 429 or a 500 and English text. `onLogoutError` answers a
  logout in another way.
- **Next has no default rate limiter.** The handlers rate-limit only through
  `rateLimit`.
- **`createFidesAuth` throws on `clientAuth: 'none'`.** The server side of an
  app is a confidential client.
- **One session cookie.** The session lives in `__Host-session`, in at most
  three chunks, or `session` over plain http. With a `sessionStore`, it holds
  only a handle. The cookies are `Secure` unless `redirectUri` is plain http.
- **The browser store asks the session info endpoint** by default, and its user
  is the session's `user`, where `roles` may be absent.
