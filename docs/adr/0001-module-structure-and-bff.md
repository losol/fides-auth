# ADR 0001: Module structure and BFF model for 1.0

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-10 |
| Packages | `@eventuras/fides-auth`, `-next`, `-store`, `-react` |
| Baseline | `main` at `e6d0aec` (includes #124, #125 and #126) |

## Context

fides-auth started as stateless auth: an encrypted session in cookies. Since then it has added:

- server-side sessions behind a handle cookie;
- a sealed login transaction;
- request handlers;
- ID token verification;
- a session mapping hook;
- `authorizedFetch`.

Before 1.0 we want three things:

- every part usable on its own, with clean APIs;
- an API and structure ready for use as a backend-for-frontend (BFF);
- code that doesn't need Node running in browsers and edge runtimes.

### What the code shows

Paths are relative to `packages/`.

| # | Finding | Evidence |
|---|---|---|
| 1 | `oauth.ts` is 728 lines. It holds config types, authorization parameters, URL and PAR, code exchange, refresh, client credentials, the logout URL, user extraction, session building and returnTo validation. | `fides-auth/src/oauth.ts` |
| 2 | Protocol code knows about sessions and the server. It builds a `Session`, mints the session's correlation id and validates the callback's returnTo. | `oauth.ts:9`, `:459`, `:527` |
| 3 | There are two import cycles. Both are type-only on the way back: `oidc-discovery` and `oauth-logging` each `import type { OAuthConfig } from './oauth'`. There is no runtime cycle, but the shared type lives in the wrong module. | `oidc-discovery.ts:19`, `oauth-logging.ts:1` |
| 4 | The root `.` loads `openid-client`. It re-exports `session-refresh`, which imports `refreshAccessToken` from `oauth`. `utils` and `session-validation` load `jose`. | `src/index.ts:12`, `session-refresh.ts:2` |
| 5 | The `fides-auth-next` root re-exports `/oauth`, `/logger`, `/session-events`, `/session-refresh`, `/session-validation`, `/silent-login`, `/utils`, `/types` and `TokenBucket`. Its `./store` re-exports the store and react packages, so Next depends on both. | `fides-auth-next/src/index.ts`, `src/store/index.ts` |
| 6 | Core has 21 export entries at mixed levels (`/oauth` next to `/session-cookies` next to `/utils`). Next has 9, including one per handler. | both `package.json` files |
| 7 | `heartbeat` and `activity-tracker` use `window` and `document`, and the root barrel re-exports `activity-tracker`. Outside core, only `fides-auth-react` uses them. | `heartbeat.ts`, `src/index.ts:7`, `fides-auth-react/src/use-heartbeat.ts` |
| 8 | `TokenBucket` is a generic in-memory limiter. Its only user is Next's default limiter, which keys on the raw `X-Forwarded-For` header and lets requests without the header through. Core handlers already take a `rateLimit` callback. | `fides-auth-next/src/request.ts:20` |
| 9 | Next can't use server sessions. `createFidesAuth` and its handler wrappers pass only `secret`, never `persistence`. | `fides-auth-next/src/auth.ts:112` |
| 10 | `server/` uses no Node APIs, yet Biome exempts it from the Node ban. | `biome.json:28` |
| 11 | Only logout checks the request origin, and its `isSameOrigin` is private. `handleHeartbeat` writes cookies on POST without a check. `SameSite=Lax` stops cross-site POSTs, but not same-site subdomains. | `server/oidc-logout.ts:24`, `server/heartbeat-handler.ts:45` |
| 12 | `validateReturnTo` has two signatures: `(raw) => string \| null` on login and `(path) => boolean` on callback. | `server/oidc-login.ts:41`, `server/oidc-callback.ts:78` |
| 13 | `Session.sid` and `StoredSession.sid` hold the library's correlation id, not the OIDC `sid` claim. The IdP's `sid` exists only inside the raw ID token, which is encrypted in the cookie or store record. A store therefore can't find the session for a logout token. | `types.ts:24`, `server/session-store.ts:17` |
| 14 | Session cookies have no `__Host-` prefix and use `SameSite=Lax`. The login transaction cookie already gets `__Host-` when `Secure`. | `cookies.ts:78`, `:109–134`, `server/login-transaction.ts:220` |

Corrections to the starting analysis:

- **Dependency weight (1, 4).** `openid-client`, `jose` and `oauth4webapi` all declare `"sideEffects": false`, so bundlers drop what isn't used. The real cost is in unbundled runtimes (Node servers, edge isolates, test runners, dev servers), which load the whole module graph, and in coupling.
- **Cycles (3).** Biome's `noImportCycles` ignores type-only imports by default (`ignoreTypes: true`). Turned on as-is, it would catch neither cycle.

### Prior art (checked)

- **RFC 10017 (BCP 212), "OAuth 2.0 for Browser-Based Applications"**, August 2026. This is the published `draft-ietf-oauth-browser-based-apps`. Section 6.1 covers the BFF:
  - **§6.1.2.1 Endpoints:** the BFF offers "check session", login, callback and logout endpoints.
  - **§6.1.2.3 Session storage:** server-side sessions are "only recommended in small-scale scenarios". In a BFF, cookie sessions work because revocation follows from the tokens.
  - **§6.1.3.1 Client type:** the BFF MUST be a confidential client.
  - **§6.1.3.2 Cookies:**
    - They MUST be `Secure` and `HttpOnly`.
    - They SHOULD use `SameSite=Strict` and `Path=/`, with no `Domain` and a `__Host-Http-` prefix.
    - Cookie sessions that hold tokens SHOULD be encrypted.
  - **§6.1.3.3 CSRF:**
    - A CSRF defence is a MUST.
    - `SameSite` doesn't cover same-site subdomains.
    - A CORS-based defence SHOULD require a custom request header.
  - **§6.1.3.6 Proxy:** a proxy MUST allowlist destinations. The RFC adds, without a requirement level, that restricting methods per endpoint "can further reduce attack vectors".
- **OpenID Connect Back-Channel Logout 1.0** (final, errata set 1):
  - The logout token carries `sub` and/or `sid`, an `events` claim and no `nonce` (§2.4).
  - It is validated like an ID token (§2.6).
  - The RP finds sessions by `iss`+`sub` and/or `sid` (§2.7).
  - The RP MUST answer 200 on success or 400 on failure, and SHOULD send `Cache-Control: no-store` (§2.8).
- **Biome 2.6:**
  - `suspicious/noImportCycles` is opt-in, and its `ignoreTypes` option defaults to `true`.
  - `style/noRestrictedImports` takes gitignore-style `patterns`.

## Decision drivers

1. **Independence.** The protocol works without sessions, sessions without the server, and the server without Next.
2. **BFF-ready.** Tokens never reach the browser. The server owns refresh, API calls, CSRF and logout.
3. **Runtime stated per subpath.** Only Web APIs (Fetch, Web Crypto), `/server` included. DOM code lives only in client packages.
4. **Dependency weight.** A subpath loads only the dependencies it needs.
5. **Enforced, not just documented.** Breaking a layer rule fails CI.
6. **Stable 1.0 contracts.** Settle now what consumers implement or store: `SessionStore`, `CookieStore`, cookie names and handler options. Features can come in 1.x.
7. **Low cost**, both for existing consumers and for releases.

## Options

- **A. Keep flat subpaths and only clean internals.** Split `oauth.ts` into internal modules, break the type cycles and keep every public subpath.
- **B. Layered subpaths in one package.** Public subpaths by layer, with dependencies pointing down and enforced by lint.
- **C. A package per layer**, e.g. `fides-auth-protocol`, `-session` and `-server`.

| | A. Flat, clean internals | B. Layered subpaths | C. Package per layer |
|---|---|---|---|
| Independence | Low: `/oauth` still builds sessions and the root barrel stays | High, enforced by lint | Highest, enforced by package boundaries |
| Dependency weight | Unchanged | Per subpath (`/pkce` and `/session-events` load none) | Per package; same runtime result as B |
| Versioning | One version | One version | Several versions to keep in step. If two versions get installed, module state (`configureLogger`, the discovery and JWKS caches) splits silently. |
| Developer experience | Familiar, but four `session-*` subpaths and `/oauth` vs `/oidc-discovery` stay confusing | One install, and the map reads by layer | Several installs and peer ranges |
| Migration cost | None | Import paths change, with shims for one minor | Import paths and package names change |
| Release overhead | None | None | A publish workflow and an npm trusted publisher per new package |

**Choice: B.**

- A leaves the coupling in the public API.
- C adds isolation that lint already gives, and brings version skew between layers that share module state.
- B's subpaths map one-to-one to packages, so C stays possible if a layer gets its own audience.

## Decision

### 1. Module map

`@eventuras/fides-auth`:

| Subpath | Layer | Runtime | Third-party deps | Contents (moved from) |
|---|---|---|---|---|
| `.` | shared | types only | none | cross-layer and wire types (`/types`, `oauth.ts`) |
| `/logger` | shared | universal | none | unchanged |
| `/cookies` | shared | universal | none | base names and a name resolver (replacing the name constants), options, size guard |
| `/session-events` | shared | universal | none | event vocabulary and `newSessionId` (unchanged) |
| `/pkce` | protocol | universal | none | unchanged |
| `/discovery` | protocol | universal | openid-client | discovery and its cache, client auth, server metadata (`/oidc-discovery`) |
| `/authorize` | protocol | universal | openid-client | request parameters, URL, PAR, `prompt=none` (`/oauth`, `/silent-login`) |
| `/token` | protocol | universal | openid-client | code exchange, refresh, client credentials, OAuth error helpers (`/oauth`, `/oauth-logging`) |
| `/id-token` | protocol | universal | jose | verification (unchanged; the `oauthConfig` form loads `/discovery`) |
| `/logout` | protocol | universal | openid-client; jose in 1.x | RP-initiated logout URL; logout token verification in 1.x (`/oauth`) |
| `/session` | session | universal | jose | build, map, update, validate and seal sessions (`/oauth`, `/session-*`, `/utils`) |
| `/server` | server/BFF | Fetch API: Node, edge, Bun, Deno | via lower layers | `createFidesAuth`, handlers, persistence, `SessionStore`, login transaction, `authorizedFetch`, CSRF and returnTo guards |
| `/providers/*` | providers | universal | openid-client | provider clients |

Removed from core: `/oauth`, `/oidc-discovery`, `/oauth-logging`, `/oauth-browser`, `/silent-login`, `/session-refresh`, `/session-validation`, `/session-cookies`, `/utils`, `/types`, `/rate-limit`, `/heartbeat` and `/activity-tracker`.

Other packages:

| Package | Runtime | Role |
|---|---|---|
| `@eventuras/fides-auth-store` | browser | auth state and the session monitor; gains `./heartbeat` and `./activity-tracker` from core |
| `@eventuras/fides-auth-react` | browser | hooks (unchanged) |
| `@eventuras/fides-auth-next` | Next server | one entry: core `createFidesAuth` bound to `cookies()` and React `cache()` |

Where this departs from the starting point:

- **`/discovery`, not `/client`.** In a BFF library, "client" reads as the browser side: the client packages, or RFC 10017 §6.3's browser-based client. The contents are discovery, client authentication and metadata.
- **The root `.` holds the cross-layer types,** including a `TokenResponse` that `openid-client`'s `TokenEndpointResponse` satisfies. Every layer then imports types from the bottom of the graph, which removes both cycles at the source.
- **`/session` is pure: no network and no `openid-client`.**
  - It gets `updateSession(session, tokenResponse)`, the merge half of today's `refreshSession`. The I/O half moves to `/server`.
  - Mapping claims to a user moves here too, because it shapes a session rather than verifying anything.
- **`/session-events` stays on its own,** with no dependencies. It's the vocabulary the server and the client packages share.
- **returnTo validation goes to `/server`, not `/session`.** Only the handlers redirect.
- **`/silent-login` folds into `/authorize`.** It's an authorization request with `prompt=none`.
- **Heartbeat moves to `fides-auth-store`, not a new package.** The store already holds the session monitor, and a new package costs a publish workflow and a trusted publisher.

The source tree mirrors the layers: `src/shared/`, `src/protocol/`, `src/session/`, `src/server/` and `src/providers/`. This lets the lint rules match on paths.

### 2. Dependency rules

| Layer | May import from this package | May import third-party |
|---|---|---|
| shared | shared | none |
| protocol | shared, protocol | `openid-client`, `jose` |
| session | shared | `jose` |
| server | shared, protocol, session | none (Web APIs only) |
| providers | shared, protocol | `openid-client` |
| `fides-auth-next` | core `.` (types), `/server` | `next`, `react` |
| client packages | core `.` (types), `/logger`, `/session-events` | their own |

Enforcement, in `biome.json` and one test:

- **Layer imports.** `style/noRestrictedImports` is set per layer through `overrides`. Patterns match the layer folders, so protocol code can't import `**/server/**`. Bare specifiers are matched too, so `openid-client` is denied in shared, session, server and the client packages. Patterns match specifiers as written; the exact globs get verified in the PR that adds them.
- **Cycles.** `suspicious/noImportCycles` is on with `ignoreTypes: false`.
- **Node APIs.** The Node ban covers all of `src/`, and the `server/**` exemption goes.
- **Dependency weight.** A test imports each subpath in a plain Node ESM process and checks which third-party modules load. For example, `/pkce` and `/session-events` load none.

### 3. Public API sketch

The table lists export names only. *(was …)* marks a rename. The old name stays as a deprecated alias for one minor.

| Subpath | Exports |
|---|---|
| `.` | types: `Session`, `Tokens`, `OAuthConfig`, `ClientAuthConfig`, `TokenResponse`, `SessionInfo`, `HeartbeatResponse` |
| `/logger` | `createLogger`, `configureLogger`, `FidesLogger` |
| `/cookies` | `CookieOptions`, `defaultSessionCookieOptions`, `defaultOAuthCookieOptions`, `COOKIE_BASE_NAMES`, `cookieName` *(replace the `*_COOKIE_NAME` constants)*, `CookieTooLargeError`, `assertCookieWithinLimit` |
| `/session-events` | `SESSION_EVENT`, `SessionEvent`, `SessionRejectedReason`, `RefreshFailureCause`, `logSessionEvent`, `isSessionRejectedReason`, `SessionClientEvent`, `newSessionId` |
| `/pkce` | `createPkcePair`, `createState` |
| `/discovery` | `discoverConfiguration`, `configureDiscoveryCache`, `clearDiscoveryCache`, `resolveClientAuth`, `getOAuthConfigLogContext` |
| `/authorize` | `createAuthorizationRequest` *(was `buildPKCEOptions`)*, `buildAuthorizationUrl`, `buildAuthorizationUrlWithPAR`, `discoverAndBuildAuthorizationUrl`, `defaultScope`, `joinScope`, `buildSilentLoginUrl`, `checkSilentLoginResult`, `requiresInteractiveLogin` |
| `/token` | `exchangeAuthorizationCode`, `refreshAccessToken`, `clientCredentialsGrant`, `getOAuthErrorLogContext`, `classifyRefreshFailure` |
| `/id-token` | `verifyIdToken`, `clearJwksCache` |
| `/logout` | `buildOidcLogoutUrl`; 1.x: `verifyLogoutToken` |
| `/session` | `buildSession` *(was `buildSessionFromTokens`)*, `MapSession`, `userFromClaims` *(was `extractUserFromTokens`)*, `updateSession`, `isSession`, `sealSession`, `unsealSession` *(was `createEncryptedJWT`, `validateSessionJwt`)*, `hasScope` |
| `/server` | `createFidesAuth`; `handleOidcLogin`, `handleOidcCallback`, `handleOidcLogout`, `handleHeartbeat`; `CookieStore`; `cookiePersistence`, `serverPersistence`, `SessionStore`, `StoredSession`, `createMemorySessionStore`; `readSession`, `tryReadSession`, `persistSession`, `refreshSession`, `tryRefreshSession` *(was `…InStore`)*, `clearSession`; the login transaction exports (unchanged); `authorizedFetch`, `AuthorizedFetchError`; `isSameOriginRequest`, `validateReturnTo` *(was `validateReturnUrl`)*. In 1.x: `handleSessionInfo`, `handleApiProxy`, `handleBackChannelLogout`, `createFetchCookieStore` |
| `fides-auth-next` | `createFidesAuth`, `nextCookieStore`, types |
| `fides-auth-store` | unchanged; `./heartbeat`: `createHeartbeat`; `./activity-tracker`: `createActivityTracker` |

Other API cleanups in 1.0:

- `OAuthConfig.redirect_uri` becomes `redirectUri`. It's the only snake_case key.
- The string overloads of `buildSessionFromTokens` and `buildOidcLogoutUrl` go.
- `rateLimit` callbacks receive the `Request`.

### 4. BFF model

The model has two independent axes:

| Axis | Purpose | Choice | Supplied |
|---|---|---|---|
| Transport (`CookieStore`) | read and write this request's cookies | always needed, for the session or handle cookie and the login transaction cookie | per request; the Next binding supplies it implicitly |
| Persistence | where the session lives | encrypted cookies (default) or a `SessionStore` | once, in `createFidesAuth` |

```ts
// @eventuras/fides-auth/server
const auth = createFidesAuth({
  oauthConfig,
  secret,        // seals cookies, store records and the login transaction
  sessionStore,  // optional: omit for encrypted cookies, set for server sessions
  persistence,   // optional escape hatch: a full SessionPersistence; wins over sessionStore
  rateLimit,     // optional: (request) => boolean | Promise<boolean>
});
await auth.handleOidcLogin(request, cookies);
await auth.readSession(cookies);
```

Core methods take the `CookieStore` on every call, because some frameworks only expose cookies on the request context. The Next binding drops that argument by calling `cookies()`. It keeps its `cache()` and the per-request refresh sharing from #126.

**Decided now (the 1.0 contract):**

| Area | Decision | Why now |
|---|---|---|
| Factory | `createFidesAuth` moves to core `/server` with the config above. Next wraps it and gains `sessionStore`. | Core and Next must share one shape. |
| `SessionStore` | Keep `get`, `set`, `delete` and the optional `withLock`. `StoredSession` gains three lookup fields, written from 1.0 on: `iss`, `subHash` and `idpSidHash`. The hashes are HMAC-SHA-256 under a key derived from `secret`, so a store dump doesn't reveal `sub`, which is personal data. Rotating `secret` already makes old records unreadable, so this adds no new rotation cost. An optional `deleteMatching({ iss, subHash?, idpSidHash? })` serves back-channel logout. The library computes the hashes, and each key matches the field of the same name; `correlationId` is never a key. | Adapters written for 1.0 must store the lookup fields. Otherwise, sessions created before back-channel logout ships can't be found. |
| TTL | `expiresAt` is absolute and fixed at login, and the library enforces it on read. Adapter TTLs are only for cleanup, and `get` may return expired records. | Already true; this makes it part of the contract. |
| IdP session | At login, store the ID token's `iss` and `sid` claims in `session.idp`, inside the encrypted session. Server persistence derives the lookup fields from them and from `user.sub`. | Back-channel logout finds sessions by `iss`+`sub` or `iss`+`sid`. |
| Correlation id | `Session.sid`, `StoredSession.sid` and the `sid` key in session events become `correlationId`; the old name is deprecated. 1.0 still reads `sid` from sessions stored before the upgrade, through 1.x. We chose `correlationId` over `id`: it can't be mistaken for the OIDC `sid` (`session.idp.sid`) or for the handle or store key. | From 1.0 the session also carries the IdP's `sid`. |
| Client type | `createFidesAuth` throws at creation when `clientAuth` is `'none'`: a BFF MUST be a confidential client (RFC 10017 §6.1.3.1). The check reads only `clientAuth`, which is static config rather than environment, so it can run eagerly while the secret is still checked on use. `/authorize` and `/token` keep supporting `none` for non-BFF use. The `/server` handlers called directly don't check. | Rejecting a working config is breaking. |
| Rate limiting | There is no default limiter; handlers rate-limit only through the documented `rateLimit` option. Next's default limiter goes: it trusts the client-supplied `X-Forwarded-For` header and counts per instance. | Removing a default changes behaviour. |
| Cookie names | Every library cookie gets the `__Host-` prefix when `Secure`; see the cookie rule below. `SameSite` stays `Lax`. | Renaming cookies after 1.0 would log everyone out again. |
| CSRF | One guard for every state-changing endpoint that a cookie authenticates: logout, heartbeat and proxy. It checks `Sec-Fetch-Site`, then `Origin` against the app's origin and an optional list of allowed origins (for a frontend served from another origin). It can also require a custom header. Exempt: login and callback (top-level navigations), and back-channel logout (server-to-server, with a signed token). | Turning it on for heartbeat changes behaviour. |
| returnTo | One `validateReturnTo: (returnTo) => string \| null` for both login and callback. | It's a breaking signature change. |

The cookie rule:

- **Prefix.** Every cookie the library sets is named `__Host-<base>` when it is `Secure`, and `<base>` otherwise. We use `__Host-` rather than the RFC's example `__Host-Http-`, which only an Internet-Draft defines.
- **Secure.** Session cookies follow the transaction cookie's rule: `Secure` unless `redirectUri` is plain http (`server/login-transaction.ts:160`). Today they are always `Secure`.
- **Path and Domain.** The library always sets `Path=/` and no `Domain`, and offers no option to change either. This is already true, since the persistences pass fixed options (`server/session-persistence.ts:179`, `:320`). The prefix therefore depends on `secure` alone, and the browser never gets a prefixed cookie it must reject. A `CookieStore` must pass the options through unchanged. Next's cookie helpers, the only API that takes a custom path today, go in 1.0 (breaking change 11).
- **Names in code.** The names are no longer constants. `/cookies` replaces the `*_COOKIE_NAME` constants with `COOKIE_BASE_NAMES` and `cookieName(base, { secure })`. The `createFidesAuth` instance exposes the resolved `cookieNames`, which is what middleware should read. `serverPersistence`'s `cookieName` option becomes a base name too.

`SameSite` stays `Lax`, not `Strict`, against the RFC's SHOULD. A `Strict` session cookie isn't sent on the redirect back from the IdP or on links from other sites, so the first page after login would look logged out. CSRF is the guard's job, and §6.1.3.3.1 says `SameSite` can't cover same-site subdomains anyway.

**Additive in 1.x:**

| Feature | Notes |
|---|---|
| `handleSessionInfo` | The "check session" endpoint (§6.1.2.1). Returns `SessionInfo` (`authenticated`, `user`, `scopes`, `accessTokenExpiresAt`), never tokens, with `Cache-Control: no-store`. `fides-auth-store` gets a matching default `checkAuthStatus`. |
| `handleApiProxy` | A same-origin API proxy built on `authorizedFetch`. It has an explicit route table mapping each prefix to a base URL, which is the allowlist §6.1.3.6 requires. As our own choice, each route also lists its allowed methods. It strips `Cookie`, runs the CSRF guard and refreshes at most once per request. Request bodies are buffered so a 401 retry can resend them, up to `maxBodyBytes` (default 1 MiB, set per route). A larger body gets 413 and never reaches the API. We chose 413 over forwarding without a retry so every request behaves the same on a 401 and memory stays bounded on edge runtimes. Upload routes raise the cap. |
| `handleBackChannelLogout` and `verifyLogoutToken` | Validates the logout token per Back-Channel Logout §2.6 using the `/id-token` JWKS cache. It hashes the token's `sub` and `sid` the same way, calls `deleteMatching({ iss, subHash, idpSidHash })` and answers per §2.8. It requires a `SessionStore` with `deleteMatching`; without one it throws rather than answering 200 and logging nobody out. Cookie sessions get no back-channel logout and no denylist. |
| `createFetchCookieStore` | A `CookieStore` over `Request` and `Response` headers, for runtimes without a framework cookie API. |
| BFF guide | `docs/bff.md` covers endpoints, CSRF, proxy routes and the persistence choice. |

### 5. Default persistence for 1.0

**The default is encrypted cookies.** They need no infrastructure, run on the edge and are what existing consumers use. RFC 10017 §6.1.2.3 also calls them a good fit for a BFF.

Set `sessionStore` when:

- tokens don't fit in cookies;
- sessions must be revocable on the server;
- you need back-channel logout;
- refreshes must be serialised across instances (`withLock`).

## Consequences

**Gains:**

- Each layer can be used, tested and documented on its own.
- Unbundled runtimes load only what a subpath needs.
- Next consumers get server sessions and the BFF features.
- The lint rules keep the layers from eroding.

**Costs:**

- Every existing consumer has to update imports once.
- The shims have to be carried for one minor.
- The README needs a rewrite.
- `/server` stays the largest subpath, kept whole because it has one responsibility: the BFF runtime.
- Back-channel logout needs a `SessionStore`. Cookie sessions end only when their tokens stop working.

**Breaking changes in 1.0:**

| # | Change | Migration aid |
|---|---|---|
| 1 | The 13 core subpaths listed under "Removed from core" are removed. | Shims and an old-to-new table in 0.16 |
| 2 | The root `.` exports types only. | The same table |
| 3 | `/heartbeat` and `/activity-tracker` move to `fides-auth-store`. | Both locations in 0.16, with core's copy deprecated (core can't re-export from the store, which depends on core) |
| 4 | `/rate-limit` and `TokenBucket` leave core and the Next root. Next's default limiter (`globalGETRateLimit`, `globalPOSTRateLimit`) goes, so Next handlers no longer rate-limit unless `rateLimit` is set. | Deprecated in 0.16; `rateLimit` documented |
| 5 | `/oauth-browser` is removed (deprecated since #114). | none |
| 6 | `/utils` is removed. `encrypt`, `decrypt`, `sha512` and `toHex` have no internal users and are dropped. The rest become internal or move to `/session`. | Web Crypto |
| 7 | The renames from §3, `redirect_uri` → `redirectUri`, and the dropped overloads. Watch out: `/server`'s `refreshSession` takes a cookie store, while the old root `refreshSession(session, config)` becomes `refreshAccessToken` plus `updateSession`. | Deprecated aliases in 0.16 |
| 8 | One `validateReturnTo` signature. | 0.16 accepts both |
| 9 | Session cookies get the `__Host-` prefix, and aren't `Secure` when `redirectUri` is plain http. | 0.16 reads both names and writes the new ones |
| 10 | The CSRF guard covers heartbeat, so cross-origin POSTs get 403. | On by default in 0.16, with an off switch |
| 11 | `fides-auth-next` keeps one entry. The per-handler subpaths, `./auth`, `./store`, `./request`, `./cookie-store`, the cookie helpers and the core re-exports go. It no longer depends on the store and react packages. | Shims in 0.16 |
| 12 | The `*_COOKIE_NAME` constants go. Code that reads cookies by name (middleware, custom `CookieStore` code) uses `cookieName(base, { secure })` or the `cookieNames` on the `createFidesAuth` instance. | Both in 0.16, with the constants deprecated |
| 13 | `Session.sid`, `StoredSession.sid` and the `sid` key in session events become `correlationId`. | 0.16 writes and logs both and reads either. 1.0 still reads `sid` from sessions stored earlier. |
| 14 | `createFidesAuth` throws when `clientAuth` is `'none'`. | 0.16 logs a warning at creation |

## Migration plan

The pending changesets ship first, as core 0.15. Breaking changes on 0.x keep using `minor` changesets, as they do today. 1.0 needs an explicit `major`.

1. **0.16: move, shim, deprecate and enforce.** Every "in 0.16" aid in the breaking-changes table lands here.
   - **Structure.** Move the code into the layered tree and add the new subpaths.
   - **Old subpaths (1, 2, 11).** Turn the old core and Next subpaths into `@deprecated` re-exports that name the new path. Subpaths with no new home (`/rate-limit`, `/utils`) are only marked `@deprecated`.
   - **Heartbeat (3).** Ship it in `fides-auth-store`, and mark core's copy `@deprecated`.
   - **Renames (7).** Add the new names and keep the old ones as deprecated aliases. `OAuthConfig` accepts both `redirect_uri` and `redirectUri`.
   - **returnTo (8).** Accept both `validateReturnTo` signatures.
   - **Cookies (9, 12).** Add `COOKIE_BASE_NAMES` and `cookieName`, and deprecate the `*_COOKIE_NAME` constants. Read both cookie names and write the prefixed ones.
   - **CSRF (10).** Turn the guard on for heartbeat by default, with an off switch. So 0.16 itself changes heartbeat behaviour: cross-origin POSTs get 403 unless the origin is allowed or the guard is switched off. Defaulting to on surfaces the change while the switch still exists. Defaulting to off would surface it at 1.0, with no way back.
   - **Rate limiting (4).** Deprecate Next's default limiter and `TokenBucket`, and document `rateLimit`.
   - **Correlation id (13).** Write `sid` and `correlationId`, log both keys, and read either.
   - **Client type (14).** `createFidesAuth` warns at creation when `clientAuth` is `'none'`.
   - **Factory.** Add `createFidesAuth` to core, and rebuild Next's version on it with `sessionStore`.
   - **Contract fields.** Add the `StoredSession` lookup fields (`iss`, `subHash`, `idpSidHash`) and `session.idp`.
   - **Lint.** Land the Biome layer rules and `noImportCycles` in this release, with the shims excluded. The starting point put them in 1.0, but the moved code passes them now, and enforcing early stops new violations during the deprecation window.
2. **1.0: remove and enforce.**
   - Delete the shims, aliases, core's heartbeat copy, the name constants, the old cookie names, the CSRF off switch and Next's default limiter.
   - Stop writing and logging `sid`; reads keep the `sid` fallback through 1.x.
   - `createFidesAuth` throws on `clientAuth: 'none'`.
   - The root becomes types-only.
3. **1.x: add.** Ship each as its own minor: the session-info handler, then back-channel logout, then the API proxy, the Fetch cookie store and the BFF guide.

Each step gets a short changeset that points to one migration doc, `docs/migrating-to-1.0.md`.

## Open questions

None. The maintainer decided the six questions from the first draft, and the decisions are recorded in §4:

| Question | Decision | Where |
|---|---|---|
| The `Session.sid` name | Rename it to `correlationId` | contract table, "Correlation id" |
| Cookie prefix | `__Host-` | cookie rule |
| Public clients | `createFidesAuth` throws | contract table, "Client type" |
| Next's default limiter | Deprecate in 0.16, remove in 1.0 | contract table, "Rate limiting" |
| Back-channel logout with cookie sessions | Requires a `SessionStore`; no denylist | 1.x table |
| Proxy request bodies | Buffer up to 1 MiB, then 413 | 1.x table |
