# @eventuras/fides-auth-next

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
