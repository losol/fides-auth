# @eventuras/fides-auth

## 0.12.0

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

## 0.11.0

### Minor Changes

- 82ec137: Route `clientCredentialsGrant` through openid-client instead of a raw `fetch`.

  It was the one place the server module talked to a token endpoint directly, so it
  missed the transport guards the rest of the package gets for free — while being the
  request that carries the client secret. Three behaviour changes, all breaking:

  - The token endpoint must now be **https**. A plain-http endpoint rejects with
    `OAUTH_HTTP_REQUEST_FORBIDDEN` instead of posting the secret in the clear.
  - Failures throw openid-client's typed errors rather than a generic
    `Error("Client credentials grant failed: <status> - <body>")`. Code matching on
    that message needs updating.
  - Requests time out, 30 seconds by default, where previously they never did.
    Configurable via the new `timeout` option (seconds).

  Also adds an optional `issuer` to `ClientCredentialsConfig`, defaulting to the token
  endpoint's origin.

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

- 2468ac6: Set `secure` on the default cookie options unconditionally.

  **Breaking for anyone serving over plain http on a non-localhost host.** Minor rather
  than major because this package is pre-1.0, where minor is the breaking channel — a
  major would cut 1.0.0.

  `defaultSessionCookieOptions` and `defaultOAuthCookieOptions` derived the flag from
  `process.env.NODE_ENV === 'production'`, so any deployment that did not set
  `NODE_ENV` — staging, a container, any server that isn't following the Next
  convention — served the session cookie without `Secure`, over plain HTTP, silently.

  The cookie spec exempts localhost from the https requirement, so `Secure` cookies are
  still set and sent over `http://localhost` and local development is unaffected. Plain
  http on a LAN address or a custom dev hostname now needs an explicit `secure: false`,
  which is a deliberate choice rather than a silent default.

### Patch Changes

- db99ad0: Widen the `jose` dependency from an exact pin to `^6.2.8`.

  An exact pin in a library forces a second copy of `jose` into any consumer tree that
  already resolves it through a range — `openid-client` depends on `jose: ^6.2.2`, so
  this repo was carrying two copies itself — and it withholds patch releases from
  consumers until we cut a release of our own. Reproducibility is the lockfile's job,
  not a library's dependency range.

## 0.10.0

### Minor Changes

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

- 019f8a0: Add a framework-agnostic `createHeartbeat()` engine at `@eventuras/fides-auth/heartbeat`. `fides-auth-next`'s `useHeartbeat` is now a thin wrapper over it; behaviour and API unchanged.
- dcf1b7d: Add a framework-agnostic `CookieStore` interface and session persistence helpers (`persistSession`, `readSession`, `refreshSessionInStore`, `clearSession`) at `@eventuras/fides-auth/server`. `fides-auth-next`'s session functions now delegate to them through a Next cookie-store adapter; public API unchanged.
- 50f6882: Move the OIDC request handlers — `handleOidcLogin`, `handleOidcCallback`, `handleHeartbeat` — into `@eventuras/fides-auth/server`, taking a `CookieStore` and an optional rate-limit callback over the standard Request/Response. `fides-auth-next` now wraps them with its Next cookie store and rate limiters; public API unchanged.
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

- 39f2cbd: Standardize MIT licensing across the workspace.

  Every package now carries a `LICENSE` file with a consistent
  `Copyright (c) 2024 Losol AS` notice, and `@eventuras/fides-auth-next` gains the
  `license` / `author` metadata it was missing and ships its `LICENSE` in the
  published tarball. `@eventuras/fides-auth`'s existing license notice is updated
  to the same copyright holder.

## 0.9.0

### Minor Changes

- 7bcf252: Type `tokens.accessTokenExpiresAt` / `tokens.refreshTokenExpiresAt` as ISO 8601 `string` instead of `Date`. The session is a JSON/JWT envelope, so these values are always strings on the wire — the `Date` type was a lie after a `validateSessionJwt` round-trip. Consumers doing date math should wrap in `new Date(value)`.

## 0.8.0

### Minor Changes

- 2fed638: Add `@eventuras/fides-auth/activity-tracker` — framework-agnostic DOM activity tracker used to gate session keepalive on real user interaction.

## 0.7.1

### Patch Changes

- 3796814: Fix `exchangeAuthorizationCode` to normalize the callback URL origin to `oauthConfig.redirect_uri` before invoking the token-exchange. `openid-client` derives `redirect_uri` from the passed callback URL (via `stripParams`), overriding the explicit option — so when a consumer sits behind a reverse proxy that doesn't forward the original scheme (e.g. `@react-router/serve` without trust-proxy), PAR sent `https://...` but token-exchange sent `http://...` and the IdP rejected the mismatch.

## 0.7.0

### Minor Changes

- 22c3761: Add `@eventuras/fides-auth/oauth-logging` with `getOAuthConfigLogContext` and `getOAuthErrorLogContext` helpers — structured, log-safe context objects for OAuth/OIDC config (excluding `clientSecret`) and `oauth4webapi`-style errors (including `cause`).

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

## 0.6.0

### Minor Changes

- 7caaea2: Surface granted scopes as a first-class field on `Session`.

  - Added `scopes?: string[]` to the `Session` interface in `types.ts`
  - `buildSessionFromTokens` now populates `session.scopes` by splitting the space-separated `tokens.scope` string (empty/missing scope leaves the field `undefined`)
  - Added `hasScope(session, scope)` convenience helper in `utils.ts`

  Backwards-compatible — `scopes` is optional and existing consumers compile and run unchanged.

## 0.5.0

### Minor Changes

- 0783155: feat(oauth): opt-in Pushed Authorization Requests (RFC 9126)

  Adds a `usePar?: boolean` flag on `OAuthConfig` and a low-level
  `buildAuthorizationUrlWithPAR(config, pkceOptions)` helper that mirrors
  `openid-client`'s own API.

  `discoverAndBuildAuthorizationUrl` now routes based on the flag:

  - `usePar: true` + provider advertises `pushed_authorization_request_endpoint` → uses PAR.
  - `usePar: true` + provider does **not** advertise PAR → throws.
  - `usePar` unset/false + provider advertises PAR → standard flow plus a
    one-line `info` log noting PAR is available but not enabled.
  - `usePar` unset/false + no PAR endpoint → standard flow, no advisory.

## 0.4.0

### Minor Changes

- ea5bb15: The default `ConsoleLogger` now emits newline-delimited JSON instead of
  bracket-prefixed text. Output stays interoperable with Loki / Grafana /
  Datadog out of the box even when the consuming app hasn't called
  `configureLogger()` to wire in `@eventuras/logger` or pino.

  Each entry includes `level`, ISO `time`, `namespace`, persistent context
  fields, optional `msg`, and the data object (with `Error` instances
  serialized to `{ name, message, stack }`):

  ```json
  {
    "level": "info",
    "time": "2026-04-15T19:40:57.300Z",
    "namespace": "fides-auth:oauth",
    "msg": "PKCE parameters generated"
  }
  ```

  Apps that still want pretty bracketed output during development should
  plug in their own logger via `configureLogger()` — e.g. wire in
  `@eventuras/logger` and let `configureNodeLogger` from
  `@eventuras/logger/node` handle dev pretty-print.

## 0.3.1

### Patch Changes

- 7c9fe79: chore: update dependencies

## 0.3.0

### Minor Changes

- d752b18: ### 🧱 Features
  - feat(fides-auth): add OIDC logout URL builder function (56e010d) [@eventuras/fides-auth]
  - feat(fides-auth): add buildSessionFromTokens function (530c48f) [@eventuras/fides-auth]
  - feat(fides-auth): add exchangeAuthorizationCode function (5187cc4) [@eventuras/fides-auth]

## 0.2.1

### Patch Changes

- Updated dependencies
  - @eventuras/logger@0.6.0

## 0.2.0

### Minor Changes

### 🧱 Features

- feat(fides-auth): enhance authentication library with silent login and logging (a96b1f7) [@eventuras/fides-auth]
- feat(fides-auth): build as library (aaf9247) [@eventuras/fides-auth]

### Patch Changes

- Updated dependencies
  - @eventuras/logger@0.5.0
