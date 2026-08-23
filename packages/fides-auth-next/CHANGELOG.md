# @eventuras/fides-auth-next

## 0.7.1

### Patch Changes

- Updated dependencies [4b3d582]
  - @eventuras/fides-auth@0.14.0
  - @eventuras/fides-auth-react@0.1.6
  - @eventuras/fides-auth-store@0.2.2

## 0.7.0

### Minor Changes

- 8bc51ee: Make the session event vocabulary reachable from Next.js.

  0.13.0 added `tryReadSession` / `tryRefreshSessionInStore` so a proxy or status
  route could log the same reasons the library does — but they take a `CookieStore`
  and `nextCookieStore` was never exported, so the primary consumer could not
  actually use them without hand-rolling an adapter over `next/headers`.

  `@eventuras/fides-auth-next` now provides:

  - `tryGetCurrentSession()` — the reason-carrying read, cached per render and
    sharing `getCurrentSession`'s decrypt, so asking why there is no session costs
    nothing extra.
  - `tryRefreshCurrentSession()` — returns `cause`, so a route can answer 503
    rather than ending a session over a provider blip.
  - `clearCurrentSession()` now emits `session.cleared` and takes an optional
    trigger (defaults to `logout`).
  - `nextCookieStore` is exported, also at `@eventuras/fides-auth-next/cookie-store`,
    for driving the framework-agnostic helpers directly.
  - The event vocabulary (`SESSION_EVENT`, `logSessionEvent`, the reason and cause
    types) and the pluggable logger (`createLogger`, `configureLogger`) are
    re-exported from the package root, so logging an event needs no imports from
    outside this package.

  The Next session/request/cookie helpers and the auth store now log through the
  pluggable `createLogger` rather than importing `@eventuras/logger` directly, so
  `configureAuthLogger()` reaches them — it previously did not. Logs from those
  modules move to whatever factory you configure, which for anyone already calling
  `configureAuthLogger()` is the same place they were going anyway. With no direct
  import left, `@eventuras/logger` is no longer a dependency of
  `@eventuras/fides-auth-next`; it still arrives via `@eventuras/fides-auth-store`.

### Patch Changes

- Updated dependencies [8bc51ee]
  - @eventuras/fides-auth-store@0.2.1
  - @eventuras/fides-auth-react@0.1.5

## 0.6.1

### Patch Changes

- c6007c6: Structured session-lifecycle logging, so production logs explain logouts.

  Every point where the library creates a session, renews one, or decides one
  cannot proceed now emits a named event — `session.created`, `session.refreshed`,
  `session.rejected`, `session.refresh_failed`, `session.cleared` — with a
  correlation id and a low-cardinality `reason` / `cause`. See
  `docs/session-events.md` for the taxonomy, the level policy and example LogQL.

  **Heartbeat: 503 instead of 401 when the provider is unreachable.** The endpoint
  previously answered 401 for a dead refresh token _and_ for a network fault or an
  IdP 5xx, so a provider blip logged out users whose sessions were valid.
  `classifyRefreshFailure` now separates `invalid_grant` (session really is over, 401) from `transport` / `idp_error` (503). Clients already retry non-401
  responses with backoff. 401 responses now carry `{ reason }` in the body.

  **New APIs.** `tryReadSession`, `tryRefreshSessionInStore` and
  `tryDecodeSessionCookies` return the reason or cause instead of a bare `null`, so
  consumers can log the same vocabulary the library does. The existing
  `readSession`, `refreshSessionInStore` and `decodeSessionCookies` are unchanged
  and delegate to them.

  **Session correlation id.** `Session.sid` is minted at creation and carried
  across refreshes, so one session is one id for its whole life — including through
  refresh-token rotation.

  **Browser events.** `createHeartbeat` and `startSessionMonitor` take an `onEvent`
  callback carrying the same event names, so consumers can beacon the client half
  of a session's story to their own endpoint. No transport ships with the library.

  `startSessionMonitor` now logs through the pluggable `createLogger` instead of
  importing `@eventuras/logger` directly, so `configureAuthLogger()` finally
  affects it.

- c542236: Ship the declaration files the entry point re-exports. `dist/index.d.ts`
  re-exported `SessionUser` and `AuthStatus` from `./types`, but `dist/types.d.ts`
  was never emitted, so importing either type failed to resolve. The shared
  tsconfig's `include`/`exclude`/`outDir` resolved relative to the config package
  instead of the consuming package; they now use `${configDir}`. The same fix
  stops `setupTests.d.ts` from being emitted into `@eventuras/fides-auth-next`.
- Updated dependencies [c6007c6]
- Updated dependencies [c542236]
  - @eventuras/fides-auth@0.13.0
  - @eventuras/fides-auth-store@0.2.0
  - @eventuras/fides-auth-react@0.1.4

## 0.6.0

### Minor Changes

- a4f412b: The session is the login; access-token freshness is the caller's concern. An
  expired access token no longer reads as "no session".

  Previously every session read treated an expired access token as "logged out":
  `refreshSessionInStore` could never refresh a token that had actually expired,
  and the heartbeat endpoint answered 401 — the client then showed "session
  expired, log in again" even though the refresh token was still perfectly valid.
  Any missed proactive-refresh window (hidden tab, laptop asleep, throttled
  timers, a transient network error) logged the user out.

  Now `decodeSessionCookies` / `readSession` / `getCurrentSession` return the
  session whenever the session cookie itself decrypts and validates, with the
  stored access token attached whether it is fresh or expired. The refresh paths
  (`refreshSessionInStore`, `handleHeartbeat`, `refreshCurrentSession`) therefore
  recover an expired-but-refreshable session instead of discarding it; a 401 from
  the heartbeat once again means what it should — no session, or a dead refresh
  token.

  Callers that hand `session.tokens.accessToken` to an API must check freshness
  first (`accessTokenExpires` / `accessTokenExpiresAt`) or refresh on 401; the
  library no longer withholds the session to enforce this.

  Legacy single-cookie sessions (written before the split-cookie format) are
  supported only while their embedded access token is still valid: active users
  migrate seamlessly on their next refresh, while stale legacy sessions read as
  "no session" and cost one re-login. Old sessions are dropped, not migrated.

### Patch Changes

- Updated dependencies [a4f412b]
  - @eventuras/fides-auth@0.12.0
  - @eventuras/fides-auth-react@0.1.3
  - @eventuras/fides-auth-store@0.1.3

## 0.5.0

### Minor Changes

- fa9de74: RP-initiated logout: send `id_token_hint`.

  `Tokens.idToken` now holds the raw ID token — populated by `buildSessionFromTokens`,
  kept fresh by `refreshSession`, and stored in its own `session_it` cookie so no cookie
  has to carry two large JWTs. `readIdToken` reads it independently of session validity,
  since logout needs the hint after the access token has expired.

  `buildOidcLogoutUrl(oauthConfig, options)` accepts `idTokenHint`, `state`,
  `logoutHint` and `includeClientId` alongside `postLogoutRedirectUri`. A string second
  argument still means `postLogoutRedirectUri`, and it still returns `null` when the
  provider advertises no `end_session_endpoint`.

  New `handleOidcLogout` handler in `@eventuras/fides-auth/server` — `POST`-only by
  default and same-origin checked via `Sec-Fetch-Site`/`Origin` — wrapped for Next.js at
  `@eventuras/fides-auth-next/oidc-logout`. See
  `packages/fides-auth/docs/rp-initiated-logout.md` for the full parameter set, where
  the ID token is stored, and why `client_id` is still sent.

  Also fixes the `./oidc-callback` and `./oidc-login` subpath exports in
  `@eventuras/fides-auth-next`, which pointed at files the build never emitted.

  `persistSession` now size-checks every cookie value before writing any of them.
  Previously a value that exceeded the browser limit threw part-way through, leaving the
  new session cookie next to the previous user's tokens.

### Patch Changes

- Updated dependencies [82ec137]
- Updated dependencies [db99ad0]
- Updated dependencies [fa9de74]
- Updated dependencies [2468ac6]
  - @eventuras/fides-auth@0.11.0
  - @eventuras/fides-auth-react@0.1.2
  - @eventuras/fides-auth-store@0.1.2

## 0.4.0

### Minor Changes

- 2468c15: Add a size guard for auth cookies. `setAuthCookie` now measures the cookie's
  name + value and throws a new exported `CookieTooLargeError` at or above the
  browser's 4096-byte per-cookie limit, instead of letting the browser silently
  drop the cookie (which manifested as a broken login). An informational log is
  emitted at 3500 bytes for visibility before the hard limit.
- 3c72759: Split the session across two cookies to make room for large access tokens.

  The access token — typically the largest part of a session — now lives in its
  own `session_at` cookie, while the rest stays in `session`, so each gets a full
  per-cookie byte budget instead of competing for one ~4KB limit.

  The framework-agnostic encode/decode logic lives in the core package as a new
  `@eventuras/fides-auth/session-cookies` export (`encodeSessionCookies` /
  `decodeSessionCookies`), plus a `decryptJWT` helper in `@eventuras/fides-auth/utils`.
  `@eventuras/fides-auth-next` is a thin adapter that wires these to the Next.js
  cookie store. Legacy single-cookie sessions are still read transparently, and the
  "expired access token means no session" contract is preserved.

### Patch Changes

- f8c2ee3: Move the framework-agnostic cookie attributes, size limits, and size guard into
  the core package.

  The new `@eventuras/fides-auth/cookies` export holds `CookieOptions`,
  `defaultSessionCookieOptions`, `defaultOAuthCookieOptions`,
  `ACCESS_TOKEN_COOKIE_NAME`, the `COOKIE_MAX_BYTES`/`COOKIE_INFO_BYTES` limits,
  the `CookieTooLargeError` class, and pure `cookieByteSize` /
  `assertCookieWithinLimit` helpers — none of which need a framework. This makes
  them reusable by future adapters (e.g. React Router) instead of living only in
  the Next.js binding.

  `@eventuras/fides-auth-next` now re-exports these from the core package and keeps
  only the actual cookie I/O (via `next/headers`). Its public API is unchanged.

- 01a31d1: Move the React hooks (`createAuthStoreHooks`, `useSessionMonitor`, `useHeartbeat`) into a new `@eventuras/fides-auth-react` package. `fides-auth-next` re-exports them, so its public API is unchanged.
- 7453d3f: Move the framework-agnostic authentication store into a new
  `@eventuras/fides-auth-store` package.

  The XState-Store-based auth state (`createAuthStore`, `initializeAuth`,
  `checkAuth`, `startSessionMonitor`, `configureAuthLogger`, and the `SessionUser`
  / `AuthStatus` / `AuthStoreContext` / `AuthStoreConfig` / `SessionMonitorConfig`
  types) has no dependency on Next.js or React — the application supplies a
  `checkAuthStatus` callback and the store never touches cookies or a server. It
  now lives in its own package so other adapters (e.g. React Router) and plain
  JavaScript can use it directly.

  `@eventuras/fides-auth-next` re-exports the store from the new package, so
  `@eventuras/fides-auth-next/store` imports keep working unchanged. The React
  hooks (`createAuthStoreHooks`, `useSessionMonitor`, `useHeartbeat`) stay in this
  package for now.

- 019f8a0: Add a framework-agnostic `createHeartbeat()` engine at `@eventuras/fides-auth/heartbeat`. `fides-auth-next`'s `useHeartbeat` is now a thin wrapper over it; behaviour and API unchanged.
- dcf1b7d: Add a framework-agnostic `CookieStore` interface and session persistence helpers (`persistSession`, `readSession`, `refreshSessionInStore`, `clearSession`) at `@eventuras/fides-auth/server`. `fides-auth-next`'s session functions now delegate to them through a Next cookie-store adapter; public API unchanged.
- 50f6882: Move the OIDC request handlers — `handleOidcLogin`, `handleOidcCallback`, `handleHeartbeat` — into `@eventuras/fides-auth/server`, taking a `CookieStore` and an optional rate-limit callback over the standard Request/Response. `fides-auth-next` now wraps them with its Next cookie store and rate limiters; public API unchanged.
- 39f2cbd: Standardize MIT licensing across the workspace.

  Every package now carries a `LICENSE` file with a consistent
  `Copyright (c) 2024 Losol AS` notice, and `@eventuras/fides-auth-next` gains the
  `license` / `author` metadata it was missing and ships its `LICENSE` in the
  published tarball. `@eventuras/fides-auth`'s existing license notice is updated
  to the same copyright holder.

- Updated dependencies [f8c2ee3]
- Updated dependencies [019f8a0]
- Updated dependencies [dcf1b7d]
- Updated dependencies [50f6882]
- Updated dependencies [3c72759]
- Updated dependencies [39f2cbd]
  - @eventuras/fides-auth@0.10.0
  - @eventuras/fides-auth-react@0.1.1
  - @eventuras/fides-auth-store@0.1.1

## 0.3.0

### Minor Changes

- d2b4f73: `useHeartbeat` now schedules session refreshes from the access-token expiry
  instead of a fixed interval, so the cadence self-adjusts to any token TTL.
  Adds `fraction`, `minSkewMs`, `minRefreshIntervalMs` and `initialExpiresAt`
  config and decouples `idleThresholdMs` from the token TTL; removes `intervalMs`.

### Patch Changes

- 7e4039e: Preserve the request path when reconstructing the OIDC callback URL. Behind a TLS-terminating proxy the token-exchange `redirect_uri` collapsed to `/`, causing Keycloak to reject login with `invalid_redirect_uri`.
- 7250e63: Upgrade `@xstate/store` to v4. React hooks moved to the dedicated `@xstate/store-react` package; the store API itself is unchanged.
- Updated dependencies [7bcf252]
  - @eventuras/fides-auth@0.9.0

## 0.2.0

### Minor Changes

- e275a40: Add `useHeartbeat` React hook and `handleHeartbeat` route handler for activity-driven session keepalive.

### Patch Changes

- Updated dependencies [2fed638]
  - @eventuras/fides-auth@0.8.0

## 0.1.12

### Patch Changes

- Updated dependencies [3796814]
  - @eventuras/fides-auth@0.7.1

## 0.1.11

### Patch Changes

- a29b507: Stop bundling runtime dependencies into published library output, and stop minifying.

  The vanilla/react/next library presets used to inline every transitive dep (e.g. `oauth4webapi` was bundled into `@eventuras/fides-auth`) and minify class/function names. Two consequences:

  - **`instanceof` failed across module boundaries.** A consumer importing `ResponseBodyError` from `openid-client` got a different class than the one a library threw, because the library carried its own bundled+renamed copy.
  - **Stack traces were unreadable** — minified names like `j` instead of `ResponseBodyError`.

  The presets now:

  - Auto-externalize every entry in the consumer's `dependencies`, `peerDependencies`, and `optionalDependencies` (plus `node:*` built-ins).
  - Set `build.minify: false` (libraries should not minify — consumers minify their own bundle).
  - Emit sourcemaps so consumer stack traces map back to original sources.

  No API changes — all affected packages are bumped `patch`. The only observable effect is leaner, more debuggable output: deps are required at install time (already the case via each lib's `dependencies`) instead of duplicated inside the bundle.

- Updated dependencies [22c3761]
- Updated dependencies [a29b507]
  - @eventuras/fides-auth@0.7.0
  - @eventuras/logger@0.8.1

## 0.1.10

### Patch Changes

- Updated dependencies [7caaea2]
  - @eventuras/fides-auth@0.6.0

## 0.1.9

### Patch Changes

- Updated dependencies [0783155]
  - @eventuras/fides-auth@0.5.0

## 0.1.8

### Patch Changes

- Updated dependencies [ea5bb15]
- Updated dependencies [7d2b896]
- Updated dependencies [fc1f5dc]
  - @eventuras/fides-auth@0.4.0
  - @eventuras/logger@0.8.0

## 0.1.7

### Patch Changes

- 7c9fe79: chore: update dependencies
- Updated dependencies [7c9fe79]
  - @eventuras/fides-auth@0.3.1
  - @eventuras/logger@0.7.1

## 0.1.6

### Patch Changes

- 4b30339: Move @eventuras/typescript-config from dependencies to devDependencies

## 0.1.5

### Patch Changes

- Updated dependencies [6e7d2d4]
  - @eventuras/logger@0.7.0

## 0.1.4

### Patch Changes

- Updated dependencies [d752b18]
  - @eventuras/fides-auth@0.3.0

## 0.1.3

### Patch Changes

- Updated dependencies
  - @eventuras/logger@0.6.0
  - @eventuras/fides-auth@0.2.1

## 0.1.2

### Patch Changes

- chore: update dependencies across frontend packages

## 0.1.1

### Patch Changes

- Updated dependencies
- Updated dependencies
  - @eventuras/logger@0.5.0
  - @eventuras/fides-auth@0.2.0
