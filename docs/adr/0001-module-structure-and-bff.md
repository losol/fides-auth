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
| 15 | Cookie sessions have no lifetime the server enforces. The sealed session carries only `iat`, nothing checks it on read, and every refresh rewrites the cookies with a fresh 30-day `Max-Age`. Server persistence has an absolute `expiresAt`; cookie persistence has none. | `utils.ts:53`, `session-cookies.ts:95`, `server/session-persistence.ts:179` |
| 16 | `Session` carries the tokens, so anything that reads the session holds them. A session passed to a client component or returned from a loader takes the tokens to the browser. `user.name` is typed `string` but holds whatever the claim was, and `user.sub` is optional. | `types.ts:25`, `oauth.ts:419` |
| 17 | The logger, the discovery cache and the JWKS cache are module state, set through `configureLogger`, `configureDiscoveryCache` and `clearJwksCache`. `fides-auth-next` is published with core pinned to an exact version, so an app that also depends on core can install two copies, each with its own state and its own error classes. | `logger.ts:205`, `oidc-discovery.ts:74`, `id-token.ts:27`, `fides-auth-next/package.json:68` |
| 18 | `CookieStore.delete(name)` takes no options. A browser ignores a deletion that isn't `Secure` for a `__Host-` cookie, which is why `clearTransaction` already deletes with `set` and `maxAge: 0`. | `server/cookie-store.ts`, `server/login-transaction.ts:152` |
| 19 | `/server` has two API levels with overlapping names: free functions that take a persistence, and the Next factory. The null-returning refresh can't tell a dead refresh token from an unreachable provider. The log event passed to `persistSession` decides whether the handle is kept. `SessionPersistence` is documented as not an extension point, yet it is exported. | `server/session.ts:77`, `:292`, `server/session-persistence.ts:93` |
| 20 | `engines` allows Node 18, but `authorizedFetch` uses `AbortSignal.any` (Node 20.3). CI runs Node 22. | `fides-auth/package.json:144`, `server/authorized-fetch.ts:191`, `.nvmrc` |
| 21 | The two persistences behave differently where they needn't. Cookie persistence splits the session by meaning into three cookies and returns a session whose access-token cookie is corrupt; server persistence is all or nothing. Only server persistence shares a refresh, so Next adds its own sharing per request. `clearSession` without a persistence clears cookies only. `stale_legacy_session` means two different things. | `session-cookies.ts:126`, `server/session-persistence.ts:113`, `:331`, `server/session.ts:345`, `fides-auth-next/src/auth.ts:119` |

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
3. **Runtime stated per entry.** Only Web APIs (Fetch, Web Crypto), `/server` included. DOM code lives only in client packages.
4. **Dependency weight.** An entry loads only the dependencies it needs.
5. **Enforced, not just documented.** Breaking a layer rule fails CI.
6. **Stable 1.0 contracts.** Settle now what consumers implement, call or store: the session shape, the `createFidesAuth` instance, `SessionStore`, `CookieStore`, cookie names and the handlers' HTTP behaviour. Features can come in 1.x.
7. **Small public surface.** Every export is a contract. Adding one in 1.x is additive; removing one is breaking.
8. **Low cost**, both for existing consumers and for releases.

## Options

- **A. Keep flat subpaths and only clean internals.** Split `oauth.ts` into internal modules, break the type cycles and keep every public subpath.
- **B. Layers in one package.** The code is split into layers with dependencies pointing down, enforced by lint. The public entries are few and don't have to mirror the layers.
- **C. A package per layer**, e.g. `fides-auth-protocol`, `-session` and `-server`.

| | A. Flat, clean internals | B. Layers in one package | C. Package per layer |
|---|---|---|---|
| Independence | Low: `/oauth` still builds sessions and the root barrel stays | High, enforced by lint | Highest, enforced by package boundaries |
| Dependency weight | Unchanged | Per entry (`.` and `/session-events` load none) | Per package; same runtime result as B |
| Versioning | One version | One version | Several versions to keep in step. If two versions get installed, error classes and instance types split silently. |
| Developer experience | Familiar, but four `session-*` subpaths and `/oauth` vs `/oidc-discovery` stay confusing | One install and five entries | Several installs and peer ranges |
| Migration cost | None | Import paths change, with shims for one minor | Import paths and package names change |
| Release overhead | None | None | A publish workflow and an npm trusted publisher per new package |

**Choice: B.**

- A leaves the coupling in the public API.
- C adds isolation that lint already gives, and brings version skew between layers.
- B's layers are folders, so a layer can get its own entry or its own package later if it finds an audience.

### What we would do differently from scratch

The library began as encrypted cookies and grew the BFF model afterwards. We asked what a fresh start would change, and took what is cheap now and breaking later.

**Adopted:**

- **The session the app sees carries no tokens** (finding 16). See §4, "Session and tokens".
- **No module state** (finding 17). The logger and the caches live on an instance. See §1 and §4, "Instance state".
- **A small public surface** (driver 7). Five entries instead of one per layer. See §1.
- **One session model, whatever stores it** (findings 15 and 21). The record, its lifecycle and its rules are written once. Where the sealed record is kept is a detail behind a narrow seam. See §4, "The session model".

**Considered and not adopted:**

| Idea | Why not |
|---|---|
| The cookie as one more `SessionStore` | A `SessionStore` is a key-value store with no request, and a cookie can only be reached through one. The session model is unified one level up instead (§4), and `SessionStore` stays what adapter authors write. |
| `Request` in and headers out, with no `CookieStore` | Every method that may write would have to hand headers back, and a Next server component can't set them. `CookieStore` stays, with a narrower contract (§4). |
| One client package in place of `-store` and `-react` | A new package costs a publish workflow and a trusted publisher. The two packages are small, and merging them later stays possible. |
| No heartbeat | With a `SessionStore` the server can refresh on demand. With cookie sessions a refresh has to happen in a request that can write cookies, which a server component can't. The heartbeat stays. 1.0 doesn't require it when there is a store. |

## Decision

### 1. Module map

`@eventuras/fides-auth` has five entries:

| Entry | Runtime | Third-party deps | Contents |
|---|---|---|---|
| `.` | types only | none | cross-layer and wire types |
| `/oidc` | universal | openid-client, jose | `createOidcClient`: discovery, the authorization request (URL, PAR, `prompt=none`), code exchange, refresh, client credentials, the logout URL and ID token verification. Plus the pure helpers: PKCE, scope, claims and error classification. |
| `/server` | Fetch API: Node, edge, Bun, Deno | via `/oidc` | `createFidesAuth`, the `SessionStore` and `CookieStore` contracts, the memory store and the error classes |
| `/session-events` | universal | none | the event vocabulary that the server and the client packages share |
| `/providers/*` | universal | openid-client | provider clients |

Removed from core: `/oauth`, `/oidc-discovery`, `/oauth-logging`, `/oauth-browser`, `/silent-login`, `/session-refresh`, `/session-validation`, `/session-cookies`, `/utils`, `/types`, `/rate-limit`, `/heartbeat`, `/activity-tracker`, `/logger`, `/cookies`, `/pkce` and `/id-token`.

Inside the package, the source tree is split into layers. They are not public entries:

| Folder | Holds | Reached through |
|---|---|---|
| `src/shared/` | types, the logger interface, cookie names and options, session events | `.`, `/session-events` |
| `src/protocol/` | the OIDC client and the pure protocol helpers | `/oidc` |
| `src/session/` | the session record: build, map, update, expire and seal | `/server` |
| `src/server/` | the factory, handlers, the session lifecycle and its two storages, login transaction, `authorizedFetch`, CSRF and returnTo guards | `/server` |
| `src/providers/` | provider clients | `/providers/*` |

Other packages:

| Package | Runtime | Role |
|---|---|---|
| `@eventuras/fides-auth-store` | browser | auth state and the session monitor; gains `./heartbeat` and `./activity-tracker` from core |
| `@eventuras/fides-auth-react` | browser | hooks (unchanged) |
| `@eventuras/fides-auth-next` | Next server | one entry: core `createFidesAuth` bound to `cookies()` and React `cache()` |

Where this departs from the starting point:

- **Five entries, not one per layer.** `/discovery`, `/authorize`, `/token` and `/logout` would all load `openid-client` and are used together, so splitting them saves no weight and leaves four paths to keep stable. A layer can get its own entry in 1.x when a consumer needs it.
- **One OIDC client object, not functions that take the config.** `createOidcClient(config)` holds the config, the discovery and JWKS caches and the logger. This is what removes the module state. Creating one does no I/O; discovery runs on first use. "OIDC client" is the specification's own term for the relying party, so it doesn't read as the browser side the way a bare `/client` would.
- **The root `.` holds the cross-layer types,** including a `TokenResponse` that `openid-client`'s `TokenEndpointResponse` satisfies. Every layer then imports types from the bottom of the graph, which removes both cycles at the source.
- **The session layer is pure and internal.** It has no network and no `openid-client`. It gets `updateSession`, the merge half of today's `refreshSession`; the I/O half moves to the server layer. It isn't a public entry in 1.0. This gives up some of "every part usable on its own": nobody builds or seals a session without the server today, and the layer rules keep it ready to publish.
- **returnTo validation sits in the server layer.** Only the handlers redirect.
- **Heartbeat moves to `fides-auth-store`, not a new package.** The store already holds the session monitor.

### 2. Dependency rules

| Layer | May import from this package | May import third-party |
|---|---|---|
| shared | shared | none |
| protocol | shared, protocol | `openid-client`, `jose` |
| session | shared | `jose` |
| server | shared, protocol, session | none (Web APIs only) |
| providers | shared, protocol | `openid-client` |
| `fides-auth-next` | core `.` (types), `/server` | `next`, `react` |
| client packages | core `.` (types), `/session-events` | their own |

Enforcement, in `biome.json` and two tests:

- **Layer imports.** `style/noRestrictedImports` is set per layer through `overrides`. Patterns match the layer folders, so protocol code can't import `**/server/**`. Bare specifiers are matched too, so `openid-client` is denied in shared, session, server and the client packages. Patterns match specifiers as written; the exact globs get verified in the PR that adds them.
- **Cycles.** `suspicious/noImportCycles` is on with `ignoreTypes: false`.
- **Node APIs.** The Node ban covers all of `src/`, and the `server/**` exemption goes.
- **Dependency weight.** A test imports each entry in a plain Node ESM process and checks which modules load. `.` and `/session-events` load no third-party module, and `/oidc` loads nothing from `server/`.
- **No module state.** A test creates two OIDC clients and checks that they share neither a cache nor a logger.
- **One session model.** One test suite runs the whole lifecycle against both storages. A rule that holds for one must hold for the other, apart from the differences listed in §4.

### 3. Public API sketch

The table lists export names only. *(was …)* marks a rename or a move. The old name stays as a deprecated export for one minor.

| Entry | Exports |
|---|---|
| `.` | types: `Session`, `Tokens`, `OAuthConfig`, `ClientAuthConfig`, `TokenResponse`, `SessionInfo`, `HeartbeatResponse`, `CookieOptions`, `FidesLogger`, `FidesLoggerFactory` |
| `/oidc` | `createOidcClient`, `OidcClient`; pure helpers: `createPkcePair`, `createState`, `defaultScope`, `joinScope`, `userFromClaims` *(was `extractUserFromTokens`)*, `checkSilentLoginResult`, `requiresInteractiveLogin`, `getOAuthErrorLogContext`, `classifyRefreshFailure` |
| `/server` | `createFidesAuth`, `FidesAuth`; `CookieStore`; `SessionStore`, `StoredSession`, `createMemorySessionStore`; `MapSession`; `AuthorizedFetchError`, `CookieTooLargeError`, `SessionSecretError`. In 1.x: `createFetchCookieStore` |
| `/session-events` | `SESSION_EVENT`, `SessionEvent`, `SessionRejectedReason`, `RefreshFailureCause`, `isSessionRejectedReason`, `SessionClientEvent` |
| `fides-auth-next` | `createFidesAuth`, `nextCookieStore`, types |
| `fides-auth-store` | unchanged; `./heartbeat`: `createHeartbeat`; `./activity-tracker`: `createActivityTracker` |

The OIDC client:

```ts
// @eventuras/fides-auth/oidc
const oidc = createOidcClient(oauthConfig, { logger, discoveryTtlMs });

await oidc.metadata();                           // was discoverConfiguration().serverMetadata()
const request = await oidc.createAuthorizationRequest({ parameters }); // was buildPKCEOptions
await oidc.authorizationUrl(request);            // uses PAR when usePar is set
await oidc.silentLoginUrl(options);              // was buildSilentLoginUrl
await oidc.exchangeCode(callbackUrl, request);   // was exchangeAuthorizationCode
await oidc.refresh(refreshToken);                // was refreshAccessToken
await oidc.clientCredentials(options);           // was clientCredentialsGrant
await oidc.logoutUrl(options);                   // was buildOidcLogoutUrl
await oidc.verifyIdToken(idToken);               // JWKS from discovery, cached on the client
// 1.x: oidc.verifyLogoutToken(logoutToken)
```

`redirectUri` is checked on use, so a client made only for client credentials doesn't need one.

No longer exported from `/server`: the handler functions, `persistSession` and the other session helpers, `cookiePersistence`, `serverPersistence`, `SessionPersistence`, the login transaction functions, `readIdToken` and `validateReturnUrl`. The `createFidesAuth` instance is the one way in (§4). Any of them can be exported in 1.x if a consumer needs it.

Other API cleanups in 1.0:

- `OAuthConfig.redirect_uri` becomes `redirectUri`. It's the only snake_case key.
- The string overloads of `buildSessionFromTokens` and `buildOidcLogoutUrl` go.
- `rateLimit` callbacks receive the `Request`.
- `mapSession` may return a promise, so it can look the user up.

### 4. BFF model

The model has two independent axes:

| Axis | Purpose | Choice | Supplied |
|---|---|---|---|
| Transport (`CookieStore`) | read and write this request's cookies | always needed, for the session or handle cookie and the login transaction cookie | per request; the Next binding supplies it implicitly |
| Storage | where the sealed session is kept | the cookies (default) or a `SessionStore` | once, in `createFidesAuth` |

```ts
// @eventuras/fides-auth/server
const auth = createFidesAuth({
  oauthConfig,
  secret,                // seals cookies, store records and the login transaction
  sessionStore,          // optional: omit for encrypted cookies, set for server sessions
  sessionDurationDays,   // optional, default 30
  applicationUrl,        // optional: the app's public origin; defaults to redirectUri's origin
  mapSession,            // optional; rolesClaim too
  validateReturnTo,      // optional; defaultRedirectPath too
  postLogoutRedirectUri, // optional: defaults to applicationUrl
  rateLimit,             // optional: (request) => boolean | Promise<boolean>
  logger,                // optional: a FidesLoggerFactory; defaults to JSON lines on console
  onSessionEvent,        // optional: (event) => void
});
```

Everything that is the same for every request is set here. A handler call takes only what varies per request.

| Member | Returns | Notes |
|---|---|---|
| `handleOidcLogin(request, cookies, options?)` | `Response` | `options.authorizationParameters` for this request |
| `handleOidcCallback(request, cookies)` | `Response` | |
| `handleOidcLogout(request, cookies, options?)` | `Response` | `options.state`, `options.logoutHint` |
| `handleHeartbeat(request, cookies)` | `Response` | |
| `readSession(cookies)` | `Session \| null` | |
| `tryReadSession(cookies)` | the session, or `{ session: null, reason }` | |
| `getTokens(cookies)` | `Tokens \| null` | the only way to the tokens |
| `refreshSession(cookies)` | `RefreshSessionResult` | *(was `tryRefreshSessionInStore`)* The null-returning form goes (finding 19). |
| `createSession(cookies, tokenResponse)` | `Session` | Starts a session with a new handle, for a login that doesn't go through the handlers. Runs `mapSession`. |
| `updateSession(cookies, update)` | `Session \| null` | `update(session)` returns the changed session. Keeps the handle and `expiresAt`. For `user` and `data`; it can't touch the tokens. |
| `clearSession(cookies, options?)` | `void` | `options.trigger` |
| `authorizedFetch(cookies, url, options)` | `{ response, data, refreshed }` | Reads the tokens itself and refreshes once on a 401. |
| `cookieNames` | the resolved cookie names | for middleware |
| `oidc` | the instance's `OidcClient` | for protocol calls the instance doesn't wrap |

Core methods take the `CookieStore` on every call, because some frameworks only expose cookies on the request context. The Next binding has the same members without that argument, since it calls `cookies()`. It keeps its `cache()`. The per-request refresh sharing from #126 goes, since the session model now shares refreshes itself.

#### The session model

There is one session model. It doesn't know where a session is kept.

**The record.** A session is one record, sealed as one string:

```ts
{
  v: 1,
  session: {            // what the app sees
    correlationId, createdAt, expiresAt,
    user, scopes, idp, data,
  },
  tokens: {             // what only the library and getTokens see
    accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, idToken,
  },
}
```

**The lifecycle.** Four transitions, each with one implementation:

| Transition | Triggered by | Identity | `expiresAt` | Event |
|---|---|---|---|---|
| create | the callback handler, `createSession` | new `correlationId`; whatever the browser held before is discarded | set from `sessionDurationDays` | `session.created` |
| refresh | the heartbeat handler, `authorizedFetch` on a 401, `refreshSession` | kept | kept | `session.refreshed` or `session.refresh_failed` |
| update | `updateSession` | kept | kept | none |
| end | the logout handler, `clearSession`, expiry, an unusable session, `deleteMatching` | gone | | `session.cleared` or `session.rejected` |

**The rules.** They hold in both storages:

1. A login never continues the session the browser arrived with. This is what defeats session fixation.
2. `expiresAt` is fixed at creation and checked on every read. Nothing extends it.
3. A refresh or an update changes the contents, never the identity or the lifetime.
4. A session is read whole or not at all. A record that doesn't open, or opens as something else, is `unreadable_session`.
5. Concurrent refreshes of one session in one process share one call to the provider and one result.
6. The same `SessionRejectedReason` means the same thing everywhere.

**The seam.** The lifecycle talks to storage through an internal interface, `SessionStorage`, with three operations and an optional lock: load, save and remove. It moves the sealed string and the few plain fields a store needs (`expiresAt`, `correlationId` and the lookup hashes). It never sees a session, so it can't apply a rule differently. It replaces `SessionPersistence` and isn't exported.

There are two storages:

- **Cookie storage** keeps the sealed string in the browser. A string too long for one cookie is cut into numbered chunks, up to three. This replaces today's split by meaning into `session`, `session_at` and `session_it`: the storage no longer knows what a token is, and one seal covers everything, so the parts can't be mixed.
- **Store storage** keeps the sealed string in a `SessionStore` and gives the browser a random handle. The store is keyed by the handle's SHA-256, as today.

Both use the same cookie name. What the storages can't make equal is stated, not hidden:

| | Cookie storage | Store storage |
|---|---|---|
| The browser holds | the sealed record | a random handle |
| Size limit | three cookies, about 12 kB sealed | the store's |
| Logout ends the session | in this browser. A copy of the cookies works until `expiresAt`. | everywhere. The record is deleted. |
| Back-channel logout, ending a user's sessions | no | yes, with `deleteMatching` |
| Refreshes shared | within a process | within a process, and across instances with `withLock` |
| Refresh or update where cookies can't be set, such as a Next server component | no | yes. The handle doesn't change. |
| Infrastructure | none | a store |

**Decided now (the 1.0 contract):**

| Area | Decision | Why now |
|---|---|---|
| Factory | `createFidesAuth` moves to core `/server` with the config and members above. Next wraps it and gains `sessionStore`. There is no `persistence` option: the storage seam is the library's own (finding 19). | Core and Next must share one shape. |
| Session and tokens | `Session` has no `tokens`. It holds `correlationId`, `createdAt`, `expiresAt`, `user`, `scopes`, `idp` and `data`. The tokens are a separate `Tokens` value, reached through `getTokens` or used by `authorizedFetch`. `user.sub` is required when there is a `user`; `user.name` and `user.email` are optional, as the claims are. | A session handed to browser code must not carry tokens (driver 2), and the type is in every consumer. |
| Sealed format | What is sealed is `{ v: 1, session, tokens }`, the same string in both storages. A payload without `v` is the pre-1.0 shape, with the tokens inside the session and `sid` for the correlation id. 1.0 reads it through 1.x. | Without a version, the next format change can't tell old sessions from broken ones. |
| Session lifetime | `expiresAt` is absolute, set at login from `sessionDurationDays`, and enforced on read in both storages. An expired session is rejected with the new reason `session_expired`. The cookie's `Max-Age` is the time left, so a refresh no longer extends it. A session sealed before the upgrade has no `expiresAt`; it gets one, counted from then, the first time it is written. | Cookie sessions have no enforced lifetime today (finding 15). Enforcing one changes behaviour. |
| Instance state | No module-level state. The logger, the discovery cache and the JWKS cache live on the `OidcClient`, and `createFidesAuth` passes its `logger` on. `configureLogger`, `configureDiscoveryCache`, `clearDiscoveryCache` and `clearJwksCache` go. Session events go to the logger and to `onSessionEvent`. | Two installed copies must not split configuration (finding 17), and removing globals is breaking. |
| `SessionStore` | Keep `get`, `set`, `delete` and the optional `withLock`. `StoredSession` gains three lookup fields, written from 1.0 on: `iss`, `subHash` and `idpSidHash`. The hashes are HMAC-SHA-256 under a key derived from `secret`, so a store dump doesn't reveal `sub`, which is personal data. Rotating `secret` already makes old records unreadable, so this adds no new rotation cost. An optional `deleteMatching({ iss, subHash?, idpSidHash? })` serves back-channel logout. The library computes the hashes, and each key matches the field of the same name. A record must match every key that is given. It may return the number of records deleted, which the caller logs. `correlationId` is never a key. | Adapters written for 1.0 must store the lookup fields. Otherwise, sessions created before back-channel logout ships can't be found. |
| Store TTL | The library sets `StoredSession.expiresAt` and enforces it on read. An adapter stores the value from every `set` and takes its own TTL from it. Adapter TTLs are only for cleanup, and `get` may return expired records. In 1.0 the value doesn't change after login, but an adapter must not rely on that. | An adapter that only reads `expiresAt` on the first `set` would break a sliding lifetime in 1.x. |
| IdP session | At login, store the ID token's `iss`, `sub` and `sid` claims in `session.idp`, inside the encrypted session. Store storage derives the lookup fields from `session.idp`, not from `user`, which `mapSession` may change. | Back-channel logout finds sessions by `iss`+`sub` or `iss`+`sid`. |
| Correlation id | `Session.sid`, `StoredSession.sid` and the `sid` key in session events become `correlationId`; the old name is deprecated. 1.0 still reads `sid` from sessions stored before the upgrade, through 1.x. We chose `correlationId` over `id`: it can't be mistaken for the OIDC `sid` (`session.idp.sid`) or for the handle or store key. | From 1.0 the session also carries the IdP's `sid`. |
| Client type | `createFidesAuth` throws at creation when `clientAuth` is `'none'`: a BFF MUST be a confidential client (RFC 10017 §6.1.3.1). The check reads only `clientAuth`, which is static config rather than environment, so it can run eagerly while the secret is still checked on use. `createOidcClient` keeps supporting `none` for non-BFF use. | Rejecting a working config is breaking. |
| Rate limiting | There is no default limiter; handlers rate-limit only through the documented `rateLimit` option. Next's default limiter goes: it trusts the client-supplied `X-Forwarded-For` header and counts per instance. | Removing a default changes behaviour. |
| `CookieStore` | Two methods: `get(name)` and `set(name, value, options)`, with `options` required. There is no `delete`: the library deletes a cookie by setting it empty with `maxAge: 0` and the attributes it was set with, which is the only deletion a browser accepts for a `__Host-` cookie (finding 18). An adapter must pass the options through unchanged. | Consumers implement this interface. |
| Cookie names | One session cookie name for both storages, with numbered chunks in cookie storage. Every library cookie gets the `__Host-` prefix when `Secure`; see the cookie rule below. `SameSite` stays `Lax`. | Renaming cookies after 1.0 would log everyone out again. |
| CSRF | One guard for every state-changing endpoint that a cookie authenticates: logout, heartbeat and proxy. A request passes when `Sec-Fetch-Site` is `same-origin` or `none`. Without that header, it passes when `Origin` equals `applicationUrl`'s origin. A request with neither header isn't from a browser and passes. The guard can also require a custom header. 1.0 is same-origin only. Exempt: login and callback (top-level navigations), and back-channel logout (server-to-server, with a signed token). | Turning it on for heartbeat changes behaviour. |
| returnTo | One `validateReturnTo: (returnTo) => string \| null`, set on the factory, for both login and callback. | It's a breaking signature change. |
| HTTP behaviour | The table below. | Client code and the client packages depend on it. |
| Packaging | The four packages release 1.0 together. Core is a `peerDependency` (`^1.0.0`) of `-next`, `-store` and `-react`, so an app has one copy. `engines` is Node 22 or later. | A peer range and an engine floor can only tighten at a major. |

What the handlers answer:

| Handler | Request | Answers |
|---|---|---|
| login | `GET`, optional `?returnTo=` | 302 to the provider; 429 |
| callback | `GET` from the provider | 302 to the returnTo with `?login=success`, or to the default path with `?login=error&error=<code>`; 400 when the login can't be matched; 431 when the session doesn't fit a cookie; 429 |
| logout | `POST` | 302 to the provider's end-session endpoint, or to `postLogoutRedirectUri`; 403 from the CSRF guard; 405; 429 |
| heartbeat | `POST` | 200 `{ accessTokenExpiresAt }`; 401 `{ reason }` when the session is over; 503 when the provider couldn't be reached; 403 from the CSRF guard; 405; 429 |

The session endpoints send `Cache-Control: private, no-store`.

The cookie rule:

- **Prefix.** Every cookie the library sets is named `__Host-<base>` when it is `Secure`, and `<base>` otherwise. We use `__Host-` rather than the RFC's example `__Host-Http-`, which only an Internet-Draft defines.
- **Secure.** Session cookies follow the transaction cookie's rule: `Secure` unless `redirectUri` is plain http (`server/login-transaction.ts:160`). Today they are always `Secure`.
- **Path and Domain.** The library always sets `Path=/` and no `Domain`, and offers no option to change either. This is already true, since the persistences pass fixed options (`server/session-persistence.ts:179`, `:320`). The prefix therefore depends on `secure` alone, and the browser never gets a prefixed cookie it must reject. Next's cookie helpers, the only API that takes a custom path today, go in 1.0.
- **One session name.** The session cookie is `__Host-session` in both storages. It holds the handle, or the first chunk of the sealed record; further chunks are `__Host-session.1` and `__Host-session.2`. Middleware can check one name without knowing the storage. `session_at`, `session_it` and `session_ref` go. A browser that arrives with the other storage's value gets `unreadable_session` and one new login.
- **Names in code.** The names are no longer constants. The `createFidesAuth` instance exposes the resolved `cookieNames`, which is what middleware reads. The `cookieName` option of `serverPersistence` goes with it; an option to namespace the names can come in 1.x.
- **Changing names.** 0.16 reads the new cookies first and the old set otherwise (`session`, `session_at` and `session_it`, or `session_ref`), never a mix of the two. It writes the new names and deletes the old ones in the same response, so a browser doesn't carry both.

`SameSite` stays `Lax`, not `Strict`, against the RFC's SHOULD. A `Strict` session cookie isn't sent on the redirect back from the IdP or on links from other sites, so the first page after login would look logged out. CSRF is the guard's job, and §6.1.3.3.1 says `SameSite` can't cover same-site subdomains anyway.

A frontend on another origin is out of 1.0. It needs CORS answers the handlers don't give, and a `Lax` cookie is only sent to it from the same site.

**Additive in 1.x:**

| Feature | Notes |
|---|---|
| `handleSessionInfo` | The "check session" endpoint (§6.1.2.1). Returns `SessionInfo` (`authenticated`, `user`, `scopes`, `accessTokenExpiresAt`), never tokens, with `Cache-Control: no-store`. `fides-auth-store` gets a matching default `checkAuthStatus`. |
| `handleApiProxy` | A same-origin API proxy built on `authorizedFetch`. It has an explicit route table mapping each prefix to a base URL, which is the allowlist §6.1.3.6 requires. As our own choice, each route also lists its allowed methods. It strips `Cookie`, runs the CSRF guard and refreshes at most once per request. Request bodies are buffered so a 401 retry can resend them, up to `maxBodyBytes` (default 1 MiB, set per route). A larger body gets 413 and never reaches the API. We chose 413 over forwarding without a retry so every request behaves the same on a 401 and memory stays bounded on edge runtimes. Upload routes raise the cap. |
| `handleBackChannelLogout` and `verifyLogoutToken` | Validates the logout token per Back-Channel Logout §2.6 using the client's JWKS cache. It hashes the token's `sub` and `sid` the same way, calls `deleteMatching({ iss, subHash, idpSidHash })` and answers per §2.8. It requires a `SessionStore` with `deleteMatching`; without one it throws rather than answering 200 and logging nobody out. Cookie sessions get no back-channel logout and no denylist. |
| `createFetchCookieStore` | A `CookieStore` over `Request` and `Response` headers, for runtimes without a framework cookie API. |
| Secret rotation | `secret` takes a list: the first seals, all open. |
| Sliding lifetime | An idle timeout next to the absolute one, as one more lifecycle rule for both storages. The store TTL rule above leaves room for it. |
| Server-side refresh | With a `SessionStore`, `readSession` can refresh a session that is about to expire, so an app needs no heartbeat. |
| BFF guide | `docs/bff.md` covers endpoints, CSRF, proxy routes and the storage choice. |

### 5. Default storage for 1.0

**The default is encrypted cookies.** They need no infrastructure, run on the edge and are what existing consumers use. RFC 10017 §6.1.2.3 also calls them a good fit for a BFF.

Set `sessionStore` when:

- tokens don't fit in cookies;
- sessions must be revocable on the server;
- you need back-channel logout;
- refreshes must be serialised across instances (`withLock`).

## Consequences

**Gains:**

- The session an app passes around holds no tokens.
- There are five entries and one factory to learn, and each export is one we mean to keep.
- Two instances, or two installed copies, don't share or split configuration. Tests need no cache resets.
- A session behaves the same wherever it is kept, and the differences that remain are written down. A new storage, or a new rule, is written once.
- Sessions end when they say they do, in both storages.
- Unbundled runtimes load only what an entry needs.
- Next consumers get server sessions and the BFF features.
- The lint rules keep the layers from eroding.

**Costs:**

- Every existing consumer has to update imports and call sites once. This is more than a path change: protocol calls become methods on a client, and server calls become members of the instance.
- The shims have to be carried for one minor.
- The README needs a rewrite.
- The session code is rewritten, not moved: the lifecycle, the storage seam and cookie chunking are new, and 0.16 must read the old cookies next to them.
- A cookie session with one corrupt part is now unreadable, where today it could come back without its access token.
- A consumer that built on the free `/server` functions or on the session layer has to move to the instance, or ask for the export back.
- Cookie sessions that slid forward on every refresh now end `sessionDurationDays` after login.
- Back-channel logout needs a `SessionStore`. Without one, a cookie session ends at `expiresAt` or when its tokens stop working.

**Breaking changes in 1.0:**

| # | Change | Migration aid |
|---|---|---|
| 1 | Core keeps five entries. The 17 subpaths listed under "Removed from core" are removed. | Shims and an old-to-new table in 0.16 |
| 2 | The root `.` exports types only. | The same table |
| 3 | The protocol functions become members of `createOidcClient`, with the renames in §3. `redirect_uri` becomes `redirectUri`, and the string overloads go. | The old functions stay in 0.16 as deprecated wrappers. `OAuthConfig` accepts both spellings. |
| 4 | The free `/server` functions are no longer exported: the handlers, the session helpers, the persistences and the login transaction. `createFidesAuth` is the way in, and the handler options that don't vary per request move to it. | Deprecated in 0.16, next to the new factory |
| 5 | `Session` has no `tokens`. `user.sub` is required, and `user.name` is optional. | 0.16 adds `getTokens` and deprecates `session.tokens`. 1.0 reads sessions sealed in the old shape. |
| 6 | Sessions have an absolute lifetime in both storages, and `session_expired` joins `SessionRejectedReason`. | `sessionDurationDays` |
| 7 | `configureLogger`, `configureDiscoveryCache`, `clearDiscoveryCache` and `clearJwksCache` go. `fides-auth-store`'s `configureAuthLogger` goes with them; the client packages log through `@eventuras/logger`, which they already depend on. `logSessionEvent` and `newSessionId` become internal. | 0.16 takes `logger` on the factory and the client, and deprecates the globals |
| 8 | `CookieStore` has no `delete`, and `set` always gets options. An adapter that still has `delete` keeps compiling. | 0.16 stops calling `delete` |
| 9 | `/heartbeat` and `/activity-tracker` move to `fides-auth-store`. | Both locations in 0.16, with core's copy deprecated (core can't re-export from the store, which depends on core) |
| 10 | `/rate-limit` and `TokenBucket` leave core and the Next root. Next's default limiter (`globalGETRateLimit`, `globalPOSTRateLimit`) goes, so Next handlers no longer rate-limit unless `rateLimit` is set. | Deprecated in 0.16; `rateLimit` documented |
| 11 | `/oauth-browser` is removed (deprecated since #114). | none |
| 12 | `/utils` is removed. `encrypt`, `decrypt`, `sha256`, `sha512`, `toHex` and `generateToken` have no place in the new surface; the rest become internal. Some consumers call them directly. | Deprecated exports in 0.16. The migration doc gives the Web Crypto equivalents. |
| 13 | One `validateReturnTo` signature, set on the factory. | 0.16 accepts both |
| 14 | The session is kept under one cookie name, `__Host-session`, with chunks in cookie storage. `session`, `session_at`, `session_it` and `session_ref` go, and a cookie session is read whole or not at all. The cookies aren't `Secure` when `redirectUri` is plain http. The `*_COOKIE_NAME` constants go; middleware reads `auth.cookieNames`. | 0.16 reads both sets of cookies and writes the new ones, as the cookie rule describes |
| 15 | The CSRF guard covers heartbeat, so cross-origin POSTs get 403. | On by default in 0.16, with an off switch |
| 16 | `fides-auth-next` keeps one entry. The per-handler subpaths, `./auth`, `./store`, `./request`, `./cookie-store`, the cookie helpers and the core re-exports go. Its instance gets the member names in §4. It no longer depends on the store and react packages. | Shims in 0.16 |
| 17 | `Session.sid`, `StoredSession.sid` and the `sid` key in session events become `correlationId`. | 0.16 writes and logs both and reads either. 1.0 still reads `sid` from sessions stored earlier. |
| 18 | `createFidesAuth` throws when `clientAuth` is `'none'`. | 0.16 logs a warning at creation |
| 19 | Core becomes a peer dependency of the other three packages, and all four need Node 22. | Install core next to them |

## Migration plan

The pending changesets ship first, as core 0.15. Breaking changes on 0.x keep using `minor` changesets, as they do today. 1.0 needs an explicit `major`, and the four packages take it together.

1. **0.16: move, shim, deprecate and enforce.** Every "in 0.16" aid in the breaking-changes table lands here.
   - **Structure (1, 2).** Move the code into the layered tree and add `/oidc`. Turn the old core subpaths into `@deprecated` re-exports that name the new home. Subpaths with no new home (`/rate-limit`, `/utils`) are only marked `@deprecated`.
   - **OIDC client (3, 7).** Add `createOidcClient`, with the caches and the logger on it. The old functions become wrappers over a client kept per config, and the global configuration functions are deprecated. `OAuthConfig` accepts both `redirect_uri` and `redirectUri`.
   - **Factory (4, 13, 16).** Add `createFidesAuth` to core with the config and members in §4, and rebuild Next's version on it with `sessionStore`. The free `/server` functions and Next's old subpaths and member names stay, deprecated. Both `validateReturnTo` signatures are accepted.
   - **Session (5, 6, 14, 17).** Write the lifecycle once over the storage seam, with the two storages behind it and the shared test suite from §2. Seal `{ v: 1, session, tokens }` and read the old shape. Add `getTokens`, `createdAt`, `expiresAt` and `session.idp`. `session.tokens` stays readable and deprecated. Write `sid` and `correlationId`, log both keys, and read either. Enforce `expiresAt` on read.
   - **Store contract.** Add the `StoredSession` lookup fields (`iss`, `subHash`, `idpSidHash`).
   - **`CookieStore` (8).** Stop calling `delete`.
   - **Cookies (14).** Read both sets of cookies, write `__Host-session` and its chunks, and delete the old ones. Add `auth.cookieNames` and deprecate the `*_COOKIE_NAME` constants.
   - **CSRF (15).** Turn the guard on for heartbeat by default, with an off switch. So 0.16 itself changes heartbeat behaviour: cross-origin POSTs get 403 unless the guard is switched off. Defaulting to on surfaces the change while the switch still exists. Defaulting to off would surface it at 1.0, with no way back.
   - **Heartbeat (9).** Ship it in `fides-auth-store`, and mark core's copy `@deprecated`.
   - **Rate limiting (10).** Deprecate Next's default limiter and `TokenBucket`, and document `rateLimit`.
   - **Utilities (12).** Mark the `/utils` exports `@deprecated`.
   - **Client type (18).** `createFidesAuth` warns at creation when `clientAuth` is `'none'`.
   - **Lint.** Land the Biome layer rules and `noImportCycles` in this release, with the shims excluded. The starting point put them in 1.0, but the moved code passes them now, and enforcing early stops new violations during the deprecation window.
2. **1.0: remove and enforce.**
   - Delete the shims, wrappers, deprecated exports and members, core's heartbeat copy, the name constants, the old cookie names, the CSRF off switch, the global configuration functions and Next's default limiter.
   - Remove `tokens` from the `Session` type. Reads keep the old sealed shape and the `sid` fallback through 1.x.
   - Stop writing and logging `sid`.
   - `createFidesAuth` throws on `clientAuth: 'none'`.
   - The root becomes types-only.
   - Core becomes a peer dependency, and `engines` moves to Node 22 (19).
3. **1.x: add.** Ship each as its own minor: the session-info handler, then back-channel logout, then the API proxy, the Fetch cookie store and the BFF guide. Secret rotation, a sliding lifetime and server-side refresh follow when a consumer needs them.

Each step gets a short changeset that points to one migration doc, `docs/migrating-to-1.0.md`.

## Open questions

The maintainer decided the six questions from the first draft, and the decisions are recorded in §4:

| Question | Decision | Where |
|---|---|---|
| The `Session.sid` name | Rename it to `correlationId` | contract table, "Correlation id" |
| Cookie prefix | `__Host-` | cookie rule |
| Public clients | `createFidesAuth` throws | contract table, "Client type" |
| Next's default limiter | Deprecate in 0.16, remove in 1.0 | contract table, "Rate limiting" |
| Back-channel logout with cookie sessions | Requires a `SessionStore`; no denylist | 1.x table |
| Proxy request bodies | Buffer up to 1 MiB, then 413 | 1.x table |

The second revision, which added the "from scratch" changes and findings 15 to 21, leaves four:

1. **Absolute lifetime for cookie sessions.** Today an active cookie session never ends. 1.0 ends it `sessionDurationDays` after login, as server sessions already do. Should 1.0 also ship the sliding lifetime, so consumers who rely on today's behaviour can keep it? Lean: no. Ship absolute only, and add sliding in 1.x.
2. **How little `/server` exports.** The free handler functions, the login transaction and the session layer are not public in 1.0. Is there a consumer that needs one of them and can't use the instance? Lean: none known, and exporting later is additive.
3. **The size of a cookie session.** Three chunks match today's three cookies. More would fit larger tokens, but many proxies refuse a `Cookie` header much above 8 kB. Lean: three, and point larger sessions to a `SessionStore`.
4. **The Node floor.** Node 22 matches CI. Node 20.3 would be enough for the code. Lean: 22, since Node 20 is past its end of life.
