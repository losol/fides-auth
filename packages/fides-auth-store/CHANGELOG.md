# @eventuras/fides-auth-store

## 0.2.2

### Patch Changes

- Updated dependencies [4b3d582]
  - @eventuras/fides-auth@0.14.0

## 0.2.1

### Patch Changes

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

## 0.2.0

### Minor Changes

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

### Patch Changes

- c542236: Ship the declaration files the entry point re-exports. `dist/index.d.ts`
  re-exported `SessionUser` and `AuthStatus` from `./types`, but `dist/types.d.ts`
  was never emitted, so importing either type failed to resolve. The shared
  tsconfig's `include`/`exclude`/`outDir` resolved relative to the config package
  instead of the consuming package; they now use `${configDir}`. The same fix
  stops `setupTests.d.ts` from being emitted into `@eventuras/fides-auth-next`.
- Updated dependencies [c6007c6]
  - @eventuras/fides-auth@0.13.0

## 0.1.3

### Patch Changes

- Updated dependencies [a4f412b]
  - @eventuras/fides-auth@0.12.0

## 0.1.2

### Patch Changes

- Updated dependencies [82ec137]
- Updated dependencies [db99ad0]
- Updated dependencies [fa9de74]
- Updated dependencies [2468ac6]
  - @eventuras/fides-auth@0.11.0

## 0.1.1

### Patch Changes

- Updated dependencies [f8c2ee3]
- Updated dependencies [019f8a0]
- Updated dependencies [dcf1b7d]
- Updated dependencies [50f6882]
- Updated dependencies [3c72759]
- Updated dependencies [39f2cbd]
  - @eventuras/fides-auth@0.10.0
