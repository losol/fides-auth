# @eventuras/fides-auth-next

## 1.0.0-beta.9

### Patch Changes

- 99b7dca: A new page, `docs/session-format.md`, says what the library writes to a cookie and to a store: the record, how it is sealed and what its key is derived from, the store's fields, and the cookie of a login under way. It also says what is stable: every 1.x reads what any 1.x wrote. A test with values written by 1.0.0-beta.8 holds the library to that, and the page shows the supported way to start and read a session in an app's own tests.
  
  The docs now say plainly that `storeFields` are not sealed, and what does and doesn't belong in them.
- Updated dependencies [9d1a151]
- Updated dependencies [2a14b0c]
- Updated dependencies [99b7dca]
- Updated dependencies [44a1dec]
  - @eventuras/fides-auth@1.0.0-beta.9

## 1.0.0-beta.8

### Patch Changes

- 132080d: `clearSession` called where cookies can't be written, after the response's cookies were taken with `fetchCookieStore` or in a Next Server Component, deleted a stored session's record and then threw on the cookie, before the refresh token was revoked. The session was gone and its token lived on at the provider. The token is now revoked first, and then the call rejects with what the cookie store threw, as before: the cookie is still in the browser, where it finds no session. `handleOidcLogout` in the same place goes on to the provider, since the user is logged out. With cookie storage nothing changes: the cookie is the session, so nothing is ended and nothing revoked.
- Updated dependencies [132080d]
- Updated dependencies [3d812ba]
  - @eventuras/fides-auth@1.0.0-beta.8

## 1.0.0-beta.7

### Minor Changes

- 1ee5467: The peer range for `next` is now `^16.4.1`, up from `^16.0.0`. Earlier 16 releases have known vulnerabilities:
  below 16.2.11 a request can pass `proxy.ts` in some App Router setups, which is where an app guards its pages, and
  below 16.4.1 there are several remote code execution advisories. An app on an older 16 gets a peer dependency
  warning and should upgrade Next.

### Patch Changes

- Updated dependencies [cbf8d92]
- Updated dependencies [1aa5c85]
- Updated dependencies [727ecec]
- Updated dependencies [4601dc4]
- Updated dependencies [5524142]
- Updated dependencies [09c5941]
- Updated dependencies [ebed293]
  - @eventuras/fides-auth@1.0.0-beta.7

## 1.0.0-beta.6

### Patch Changes

- 1cd8a5f: A session store that can't be reached no longer makes the heartbeat, the session info and a refresh throw. Only a
  `withLock` that rejected was handled; a `get` that threw went straight through, since the read a refresh starts
  with was outside the handling. Now `refreshSession` answers `{ ok: false, reason: 'refresh_failed', cause: 'store' }`
  for any call to the store that fails, with or without `ifExpiresWithin`, `handleHeartbeat` answers 503 as
  documented, and `refreshInProxy` passes the request on instead of failing every page. `handleSessionInfo` answers
  503 without a body: whether there is a session isn't known, so it says neither.
  
  The reads (`readSession`, `tryReadSession`, `getTokens`, `readSessionWithTokens`, `authorizedFetch`) still reject
  with what the store threw, as `updateSession` does: null would send a logged-in user to a login that fails on the
  same store. `docs/server-sessions.md` has a table of what each call answers.
- Updated dependencies [b3d0f1e]
- Updated dependencies [93e7a6e]
- Updated dependencies [dd337be]
- Updated dependencies [1cd8a5f]
  - @eventuras/fides-auth@1.0.0-beta.6

## 1.0.0-beta.5

### Patch Changes

- 8d6694e: `tokenStatus` says whether a session's access token can still be used: `active`, `refreshable` or `expired`. A
  session reads until `expiresAt` whatever its tokens are worth, so a login without a refresh token stayed
  `authenticated: true` for hours after its access token had died, with nothing to tell the two apart.
  `tryReadSession`, `readSessionWithTokens` and the session info endpoint now give the status. The session itself
  is left as it is; an app that wants "a session is no better than its token" ends it on `expired`.
- Updated dependencies [8a172ba]
- Updated dependencies [3081c1d]
- Updated dependencies [27ccacd]
- Updated dependencies [b0ec765]
- Updated dependencies [8110116]
- Updated dependencies [8d6694e]
- Updated dependencies [a03ae17]
  - @eventuras/fides-auth@1.0.0-beta.5

## 1.0.0-beta.4

### Patch Changes

- 02fe7c7: `endUserSessions({ sub })` finds the sessions by `sub` alone and no longer needs the issuer. Since beta.3 it
  fell back to `oauthConfig.issuer` when the provider couldn't be reached, and ended nothing, without an error,
  when the config spelled the issuer another way than the ID tokens do. It now asks the provider for nothing.
  `iss` is still an option, to narrow it to one provider, and must then be the ID token's `iss` to the letter.
  
  For a custom `SessionStore`: `SessionMatch.iss` is optional, and `findMatching` must treat a missing `iss` as
  "any issuer". An adapter that hands the match to its query as it is needs no change, but an index for it
  should start with `subHash`, not `iss`.
- e82c781: A rate-limited login now goes through `onLoginError` with the code `rate_limited`, and redirects like any other failed login. A logout that fails, because of the rate limit or because the session couldn't be ended, redirects to `defaultRedirectPath` with `?logout=error&error=<code>` instead of answering with text. The new `onLogoutError` option answers it in another way.
- a67081d: A function given to `updateSession`, or a `mapRefresh`, that refreshed, updated or ended the same session
  waited for itself and never returned. Such a call is now refused with a TypeError at once, on runtimes with
  `AsyncLocalStorage` (Node, Deno, Bun, Workers with Node compatibility). The docs also say what `updateSession`
  does when the store fails: it rejects with what the store threw, where `refreshSession` answers
  `cause: 'store'`.
- Updated dependencies [6cc8008]
- Updated dependencies [02fe7c7]
- Updated dependencies [3ced1af]
- Updated dependencies [e82c781]
- Updated dependencies [a67081d]
  - @eventuras/fides-auth@1.0.0-beta.4

## 1.0.0-beta.3

### Patch Changes

- b1721c1: A login that fails always redirects to `defaultRedirectPath` with `?login=error&error=<code>`. A callback
  without a live login answered 400 with English text, a failed code exchange 500, and a session too large for
  the cookies 431; they now carry `login_expired`, `login_failed` and `session_too_large`. `handleOidcLogin` no
  longer throws when the login can't be started, because the provider can't be reached say: it redirects with
  `login_unavailable`. `onLoginError` answers a failed login in another way.
- 83860bd: `mapRefresh` changes the session a refresh leaves, the way `mapSession` does at login. What `mapSession` put
  in `data` from the ID token claims stayed as it was at login; with `mapRefresh` it can follow each refresh. It
  is also where roles that only the access token carries are set again. It can't fail the refresh: if it throws,
  the error is logged and the session is saved as the refresh left it.
- bb88bc5: A refresh that ends a stored session, because the provider refused it for good, deletes the session cookie
  too, where cookies can be set. The browser kept sending a handle that found no session, and a proxy that
  checks for the cookie took the user for signed in.
- 094b74d: `rolesClaim` can be a function of the ID token claims, for roles that aren't in a top-level claim, such as
  Keycloak's `realm_access.roles`. Roles that `mapSession` read from such a claim were gone after the first
  refresh. `rolesClaim: false` leaves `user.roles` to `mapSession`, and a refresh then keeps them. A login where
  `mapSession` sets roles that the next refresh would replace logs a warning, once.
- 993e12b: `storeFields` values may now be lists of strings, for roles say, as well as strings, numbers, booleans and null. A store's `set` gets `context.reason`, one of `'login'`, `'refresh'` and `'update'`, so an adapter can tell a refresh from an `updateSession` and stamp when a session was last refreshed. `StoreSetReason` is exported.
- 9d3b85b: `updateSession` could undo a refresh. An update that overlapped a refresh saved the session it had read before
  it, with the refresh token the refresh had just spent, so the next refresh failed with `invalid_grant`. A
  refresh and an update of one session now take turns, in the process and under the store's lock, and each starts
  from what the other saved.
- Updated dependencies [99c0422]
- Updated dependencies [124b84d]
- Updated dependencies [b1721c1]
- Updated dependencies [83860bd]
- Updated dependencies [bb88bc5]
- Updated dependencies [094b74d]
- Updated dependencies [4c57abb]
- Updated dependencies [993e12b]
- Updated dependencies [9d3b85b]
- Updated dependencies [08548be]
  - @eventuras/fides-auth@1.0.0-beta.3

## 1.0.0-beta.2

### Minor Changes

- 1113955: `readSessionWithTokens` gives the session and its tokens in one read, or why there is none.
  `readSession` and `getTokens` each read, which with a `sessionStore` is a round trip each. The README
  says to read once per request where several parts of it need the session.
- ad8b5c4: `createFidesAuth<AppData>(…)` types `session.data` in everything the instance hands out: reads,
  `refreshSession`, `createSession`, `updateSession`, `mapSession` and `storeFields`. `Session` was
  generic already, but the instance wasn't, so `data` came back as an open record and every use
  needed a cast. Without a type argument nothing changes.

### Patch Changes

- 6ffe912: A refresh the provider refuses for good, `invalid_grant`, ends a session held by a `sessionStore` with
  `withLock`: the record is deleted, and later reads answer `session_not_found` instead of a session
  whose tokens no longer work. It emits `session.cleared` with `trigger: "rejected"`. Cookie sessions,
  and stores without a lock, are left as before, since another instance may have refreshed; the README
  shows how to end them with `clearSession`.
- 9fcdd4b: `loginSuccessParam: false` makes a login land on its return path as it was, without `?login=success`.
  The default stays true. A failed login still goes to `defaultRedirectPath` with
  `?login=error&error=<code>`.
- 58fdc40: With cookie sessions, a request that still carries the cookie from before a refresh gets that
  refresh's result for `refreshGraceSeconds` after it, 10 by default, instead of spending the old
  refresh token again, which a provider that rotates refresh tokens answers with `invalid_grant`. A
  logout with the old cookie revokes the new refresh token. It works within one process and for the
  token just spent; set it to 0 to turn it off.
- 038aa72: `sessionDurationDays` is now `sessionDurationSeconds`, like the other durations in the API, and the
  default goes from 30 days to 12 hours. `createFidesAuth` throws a `TypeError` on the old name, and
  unless the lifetime is a finite number above 0: a value such as `NaN`, from an unset environment
  variable, used to pass and then fail every login with a 500. To keep a 30-day session, set
  `sessionDurationSeconds: 30 * 24 * 60 * 60`.
- 41c27cf: The session info endpoint answers with `expiresAt`, when the session itself ends. A page knew when
  the access token expires, which a refresh moves, but not when the user will be logged out.
- e6ce4de: `SessionUser` names the type of `session.user`, so an app no longer writes
  `NonNullable<Session['user']>`. The app's own fields belong in `data`. `Tokens.accessToken` stays
  optional, and its doc now says why: a session that keeps only a refresh token must stay possible.
- Updated dependencies [6ffe912]
- Updated dependencies [790a3f7]
- Updated dependencies [9fcdd4b]
- Updated dependencies [9990390]
- Updated dependencies [1113955]
- Updated dependencies [58fdc40]
- Updated dependencies [bdc86a2]
- Updated dependencies [127c85d]
- Updated dependencies [038aa72]
- Updated dependencies [41c27cf]
- Updated dependencies [e6ce4de]
- Updated dependencies [ad8b5c4]
  - @eventuras/fides-auth@1.0.0-beta.2

## 1.0.0-beta.1

### Minor Changes

- 2487c72: `endUserSessions({ sub, iss? })` ends every stored session of one user, wherever they are signed in,
  and revokes their refresh tokens: for "sign out everywhere" and closed accounts. It needs a
  `SessionStore` with the new optional `findMatching`, and throws without one.
  
  A store can now tell whose session a record is, and whether it is new: `storeFields` in the config
  puts plain fields of your choice on the record as `fields`, and `set` gets `{ continuation }` as a
  third argument. `createMemorySessionStore` implements `findMatching`.

### Patch Changes

- a5f8160: `refreshSession({ ifExpiresWithin })` and `refreshInProxy` never count more than half the access
  token's lifetime as about to expire. A token that lived shorter than the window, 60 seconds by
  default in the proxy, was refreshed on every request. The session now records when its access token
  arrived, as `accessTokenIssuedAt` on `Tokens`, and the READMEs describe how a refresh from a stale
  cookie fails when the provider rotates refresh tokens.
- 8813d4a: Logout and `clearSession` revoke the session's refresh token (RFC 7009) when the provider has a
  `revocation_endpoint`, so a refresh that was running at logout, or a copy of the cookie, can't renew
  the session. A refresh running in the same process is waited for, and the token it brought back is
  the one revoked. With a `sessionStore`, the session ends under `withLock`, so a refresh on another
  instance can't save it again. `OidcClient` gets `revoke(token, { tokenTypeHint })`.
- Updated dependencies [2487c72]
- Updated dependencies [c15514e]
- Updated dependencies [4445da7]
- Updated dependencies [948e89a]
- Updated dependencies [a5f8160]
- Updated dependencies [8813d4a]
- Updated dependencies [dd7aac5]
  - @eventuras/fides-auth@1.0.0-beta.1

## 1.0.0-beta.0

### Major Changes

- 84d3b82: 1.0, on core's `createFidesAuth`. Users log in again once after the upgrade. The
  [upgrade guide](https://github.com/losol/fides-auth/blob/main/packages/fides-auth/docs/migrating-to-1.0.md)
  maps every 0.x API to what replaces it.
  
  - `createFidesAuth(config)` is the core instance bound to `cookies()`. Reads are cached per render,
    and `refreshInProxy` refreshes a session in `proxy.ts` before the page renders.
  - One entry. The subpaths, the cookie helpers, the core re-exports and `./store` are gone.
  - No default rate limiter: pass `rateLimit`.
  - `@eventuras/fides-auth` is a peer dependency. Needs Node 22.

### Patch Changes

- Updated dependencies [84d3b82]
  - @eventuras/fides-auth@1.0.0-beta.0

## 0.8.1

### Patch Changes

- af191f5: The type declarations use explicit `.js` extensions on relative imports, as in
  the packages it re-exports, so the types resolve under
  `moduleResolution: "nodenext"`. No API change.
- Updated dependencies [2c9a137]
- Updated dependencies [af191f5]
- Updated dependencies [af191f5]
- Updated dependencies [af191f5]
- Updated dependencies [39a63cf]
- Updated dependencies [2c9a137]
  - @eventuras/fides-auth@0.16.0
  - @eventuras/fides-auth-react@0.1.9
  - @eventuras/fides-auth-store@0.3.1

## 0.8.0

### Minor Changes

- e6d0aec: `createFidesAuth` now returns `authorizedFetch(session, url, options)`, which on a
  401 refreshes the session in the cookies and retries once. Parallel calls in one
  request share one refresh. The refresh works only in Server Actions and Route
  Handlers; in a Server Component pass `refresh: false`. `AuthorizedFetchError` and
  its types are re-exported.
- bdf5128: `createFidesAuth({ secret, oauthConfig })` returns the session helpers and route
  handlers with both bound. The package-level session helpers and the `./session`
  entry point are removed; `./auth` replaces it. The standalone route handlers
  now require `secret`, and the login handler takes `authorizationParameters`.
  
  Migration:
  - Create one `auth = createFidesAuth(…)` and call `auth.getCurrentSession()` and
    so on. `refreshCurrentSession(oauthConfig)` becomes `auth.refreshCurrentSession()`.
  - Replace `createSession(session)` with `createEncryptedJWT(session, secret)`.
- 344537f: `handleOidcCallback` takes `mapSession`, also through `createFidesAuth`. See
  `buildSessionFromTokens` in `@eventuras/fides-auth`.
  
  Breaking: the re-exported `Session.user.email` is optional; handle `undefined`.
- 9896f85: `createFidesAuth` takes an optional `sessionStore`. With it, every handler and
  helper keeps the session in the store, and the cookie holds only a handle.
  Without it, sessions stay in cookies as before.
  
  The `SessionStore` and `StoredSession` types are re-exported. The standalone
  callback, logout and heartbeat handlers take an optional `persistence`.

### Patch Changes

- 8de23d2: Deprecate `globalGETRateLimit`, `globalPOSTRateLimit` and the `TokenBucket`
  re-export. The Next handlers still use the default limiter. For your own, call
  the handlers from `@eventuras/fides-auth/server` with `nextCookieStore()` and a
  `rateLimit` callback; see "Rate limiting" in the README.
- Updated dependencies [42fe1c5]
- Updated dependencies [8de23d2]
- Updated dependencies [e6d0aec]
- Updated dependencies [9567058]
- Updated dependencies [3e76c27]
- Updated dependencies [7a0bc8f]
- Updated dependencies [8fd8afa]
- Updated dependencies [8fd8afa]
- Updated dependencies [8fd8afa]
- Updated dependencies [7a0bc8f]
- Updated dependencies [344537f]
- Updated dependencies [be42d5e]
- Updated dependencies [623eb89]
- Updated dependencies [42fe1c5]
- Updated dependencies [bdf5128]
- Updated dependencies [9567058]
- Updated dependencies [c2fa830]
- Updated dependencies [7a0bc8f]
- Updated dependencies [344537f]
- Updated dependencies [7a0bc8f]
- Updated dependencies [f9e0b95]
  - @eventuras/fides-auth@0.15.0
  - @eventuras/fides-auth-store@0.3.0
  - @eventuras/fides-auth-react@0.1.8

## 0.7.2

### Patch Changes

- 8a87c07: Emit type declarations with `tsc --emitDeclarationOnly` instead of vite-plugin-dts, and upgrade TypeScript to 7.
- Updated dependencies [8a87c07]
  - @eventuras/fides-auth@0.14.1
  - @eventuras/fides-auth-store@0.2.3
  - @eventuras/fides-auth-react@0.1.7

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
