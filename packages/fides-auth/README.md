# @eventuras/fides-auth

Framework-agnostic OAuth 2.0 / OpenID Connect library with PKCE, encrypted sessions and pluggable logging.

## Features

- **OAuth 2.0 + OIDC** — Authorization Code with PKCE, token refresh, client credentials
- **Pushed Authorization Requests** — Opt-in RFC 9126 support (`usePar`) when the provider advertises it
- **Server and browser** — `/server` for the server side and `/browser` for the page; `/oidc` runs anywhere with Web Crypto and `fetch`
- **Encrypted sessions** — AES-256-GCM encrypted JWTs for secure session storage
- **Server-side sessions** — Opt-in store behind an opaque handle cookie, for providers whose tokens don't fit a cookie
- **Rate limiting hook** — `rateLimit` refuses a request, with the limiter of your choice
- **RP-initiated logout** — End the provider's session too, with `id_token_hint` (OIDC RP-Initiated Logout 1.0)
- **Silent login** — `prompt=none` logins, and helpers that read their result
- **Pluggable logging** — Bring your own logger (pino, winston, etc.) or use the built-in console logger
- **Tree-shakeable** — Each module is a separate entry point; import only what you need
- **TypeScript-first** — Full type safety with exported interfaces
- **Identity providers** — Includes a Vipps Login provider; designed to support additional providers

## Installation

```bash
npm install @eventuras/fides-auth
# or
pnpm add @eventuras/fides-auth
# or
yarn add @eventuras/fides-auth
```

**Requirements:** Node.js ≥ 22 (uses Web Crypto API)

## Quick Start

The server side of an app is one object from `/server`. Its members take the
`Request` and a `CookieStore`, a small adapter over your framework's cookies:

```typescript
import { createFidesAuth } from "@eventuras/fides-auth/server";

export const auth = createFidesAuth({
  oauthConfig: {
    issuer: "https://auth.example.com",
    clientId: "your-client-id",
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    redirectUri: "https://app.example.com/api/auth/callback",
    scope: "openid profile email offline_access",
  },
  secret: process.env.SESSION_SECRET!, // openssl rand -hex 32
});

// Route handlers
const login = (request: Request) => auth.handleOidcLogin(request, cookies);
const callback = (request: Request) => auth.handleOidcCallback(request, cookies);

// Anywhere on the server
const session = await auth.readSession(cookies);
```

Next.js apps use [`@eventuras/fides-auth-next`](../fides-auth-next), which binds
the instance to `cookies()`. See [Server](#server-server) for the rest.

## Modules

Each module is available as a separate entry point for tree-shaking:

| Entry Point                               | Environment | Description                                             |
| ----------------------------------------- | ----------- | ------------------------------------------------------- |
| `@eventuras/fides-auth`                   | Universal   | The shared types. No runtime code                       |
| `@eventuras/fides-auth/oidc`              | Universal   | The OIDC client (`createOidcClient`) and pure helpers   |
| `@eventuras/fides-auth/server`            | Node.js     | `createFidesAuth`: the handlers, sessions and API calls |
| `@eventuras/fides-auth/browser`           | Browser     | The session store, session monitor and heartbeat        |
| `@eventuras/fides-auth/session-events`    | Universal   | The names and vocabulary of the session events          |
| `@eventuras/fides-auth/providers/vipps`   | Universal   | Vipps Login identity provider                           |

Coming from 0.x? See [Upgrading to 1.0](docs/migrating-to-1.0.md).

### OIDC client (`/oidc`)

`createOidcClient` holds one provider's config, its discovery and JWKS caches
and its logger, so two clients share no state. Creating one does no I/O:
discovery runs on first use.

```typescript
import { createOidcClient } from "@eventuras/fides-auth/oidc";

const oidc = createOidcClient(
  {
    issuer: "https://auth.example.com",
    clientId: "my-app",
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    redirectUri: "https://app.example.com/callback",
    scope: "openid profile email offline_access",
  },
  { logger, discoveryTtlMs: 5 * 60_000 }, // both optional
);

// Login: keep `request` on the server until the callback.
const request = await oidc.createAuthorizationRequest({ parameters: { ui_locales: "nb" } });
const url = await oidc.authorizationUrl(request); // through PAR when usePar is set

// Callback: checks state and PKCE against the request.
const tokens = await oidc.exchangeCode(new URL(callbackUrl), request);
const claims = await oidc.verifyIdToken(tokens.id_token!);

await oidc.refresh(refreshToken);
await oidc.clientCredentials({ scope: "api:read" });
await oidc.logoutUrl({ postLogoutRedirectUri: "https://app.example.com/", idTokenHint });
await oidc.silentLoginUrl(request, { loginHint }); // prompt=none
await oidc.metadata();
```

- **`redirectUri`** is checked when an operation needs it, so a client used only
  for client credentials can leave it out.
- **`logger`** is a `FidesLoggerFactory`. Without one, the client writes JSON
  lines to the console. See [Logging](#logging).
- **Pure helpers** come from the same entry: `createPkcePair`, `createState`,
  `defaultScope`, `joinScope`, `userFromClaims`, `checkSilentLoginResult`,
  `requiresInteractiveLogin`, `getOAuthErrorLogContext` and
  `classifyRefreshFailure`.

#### Client authentication

`clientAuth` sets how the client authenticates at the token endpoint. Omit it
for `client_secret_post`:

```typescript
{ clientSecret: "…" }                                    // client_secret_post
{ clientAuth: "client_secret_basic", clientSecret: "…" }
{ clientAuth: "none" }                                   // public client, PKCE only
{ clientAuth: "private_key_jwt", privateKey }            // CryptoKey or { key, kid }
```

`oidc.clientCredentials()` throws for `none`: the grant needs client
authentication.

#### Server metadata instead of discovery

If the server publishes its metadata somewhere other than
`/.well-known/openid-configuration` (an RFC 8414 document, say), fetch it
yourself and pass it as `serverMetadata`. The client then skips discovery:

```typescript
const oidc = createOidcClient({
  issuer: "https://auth.example.com",
  clientId: "your-client-id",
  clientAuth: "none",
  redirectUri: "https://app.example.com/callback",
  scope: "openid profile",
  serverMetadata: await fetch(metadataUrl).then((r) => r.json()),
});
```

With `openid` in the scope the metadata must include `issuer`, so the ID token's
`iss` can be checked.

#### A provider over http in development

The client reaches the provider only over https. An http issuer, or an http
endpoint in the provider's metadata, throws a `TypeError` that names it at the
first call to the provider. For a provider on a loopback address, in
development or CI, opt in:

```typescript
const oidc = createOidcClient({
  issuer: "http://localhost:3000",
  allowInsecureRequests: true,
  // …
});
```

That allows http to `localhost`, a `*.localhost` name, `127.0.0.0/8` and
`[::1]`, for the issuer and every endpoint in its metadata. Any other http URL
still throws. A provider in another container isn't loopback: publish its port
on localhost, or put it behind https.

#### Scope and extra authorization parameters

`scope` takes a string or an array. Other authorization parameters (`prompt`,
`login_hint`, `resource`, …) can be set on the config, per authorization
request, or per login in `handleOidcLogin`. They go through PAR too.

```typescript
const oidc = createOidcClient({
  // …
  scope: ["openid", "profile", "offline_access"],
  authorizationParameters: { resource: "https://api.example.com" },
});

const request = await oidc.createAuthorizationRequest({
  parameters: { login_hint: "user@example.com" },
});

// Or per login, in the server handler
return auth.handleOidcLogin(request, cookies, {
  authorizationParameters: { prompt: "login" },
});
```

Per-request parameters override the config's, and a `scope` among them replaces
the config's `scope`. These keys are reserved, and passing one throws:

- `state`, `code_challenge`, `code_challenge_method` and `redirect_uri`, which
  fides-auth sets.
- `client_id` and `response_type`, which openid-client sets.
- `request` and `request_uri`, which would bypass PKCE and `state`.
- `nonce`, which the callback doesn't check, so the login would fail.

#### Pushed Authorization Requests (PAR, RFC 9126)

Opt in with `usePar: true` in the config. `oidc.authorizationUrl` then posts
the authorization parameters to the provider's PAR endpoint and returns a URL
with only `client_id` and `request_uri`:

```typescript
const oidc = createOidcClient({
  issuer: "https://auth.example.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://app.example.com/callback",
  scope: "openid profile email offline_access",
  usePar: true,
});

const request = await oidc.createAuthorizationRequest();
const url = await oidc.authorizationUrl(request);
// redirect the user to url
```

Behaviour:

- `usePar: true` + provider advertises `pushed_authorization_request_endpoint` → uses PAR.
- `usePar: true` + provider does **not** advertise PAR → throws.
- `usePar` unset/false + provider advertises PAR → standard flow, with a
  one-line `info` log noting that PAR is available but not enabled.
- `usePar` unset/false + no PAR endpoint → standard flow, no advisory.

#### ID token verification

`oidc.verifyIdToken` checks an ID token's signature, `iss`, `aud` and `exp`
against the provider's JWKS and returns the claims. The issuer comes from the
metadata and the audience is the client ID:

```typescript
import { userFromClaims } from "@eventuras/fides-auth/oidc";

const claims = await oidc.verifyIdToken(tokens.id_token!);
const user = userFromClaims(claims, "roles"); // { sub, name?, email?, roles }
```

`algorithms` defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. The JWKS is cached on
the client.

#### UserInfo

`oidc.userInfo` gets the claims from the provider's UserInfo endpoint for the
user an access token belongs to. Use it for claims the provider only gives there:

```typescript
const { session, tokens } = await auth.readSessionWithTokens(cookies);
if (session?.idp && tokens?.accessToken) {
  const claims = await auth.oidc.userInfo(tokens.accessToken, { expectedSubject: session.idp.sub });
}
```

`expectedSubject` is required: the access token alone doesn't say whose claims
come back, so the `sub` of the response is checked against the ID token's
(OIDC Core §5.3.2). It throws if the provider has no `userinfo_endpoint` or
the `sub` differs.

#### Silent login

`oidc.silentLoginUrl` is the authorization URL with `prompt=none`: the provider
answers without showing a page, with a code when the user has a session there,
or with an error:

```typescript
import { checkSilentLoginResult, requiresInteractiveLogin } from "@eventuras/fides-auth/oidc";

const request = await oidc.createAuthorizationRequest();
const url = await oidc.silentLoginUrl(request, { loginHint, maxAge: 3600 });

// On the callback
const result = checkSilentLoginResult(callbackUrl);
if (result.success) {
  const tokens = await oidc.exchangeCode(callbackUrl, request);
} else if (requiresInteractiveLogin(result.error)) {
  // send the user to a normal login
}
```

#### RP-Initiated Logout

Clearing your own session cookie is not a logout — the provider's session survives,
so the next `/authorize` re-authenticates silently. `oidc.logoutUrl` builds the
request that ends the provider session too, and returns `null` when the provider
advertises no `end_session_endpoint`:

```typescript
const logoutUrl = await oidc.logoutUrl({
  postLogoutRedirectUri: "https://app.example.com/",
  idTokenHint: (await auth.getTokens(cookies))?.idToken,
});
```

`handleOidcLogout` on the [server instance](#server-server) wraps the whole
dance: end the session, revoke its refresh token where the provider has a
`revocation_endpoint`, and redirect with the ID token as the hint.

See [docs/rp-initiated-logout.md](./docs/rp-initiated-logout.md) for the full
parameter set, where the ID token is stored, and why `client_id` is still sent.

#### PKCE and state

For flows that keep their own login transaction, `createPkcePair` and
`createState` are on `/oidc` too. They use only Web Crypto, so they also run in
the browser and on edge runtimes:

```typescript
import { createPkcePair, createState } from "@eventuras/fides-auth/oidc";

const { verifier, challenge } = await createPkcePair(); // S256
const state = createState();
```

`createAuthorizationRequest` is built on the same two functions.

### Server (`/server`)

`createFidesAuth` is the server side as one object. It holds the OIDC client,
the session storage and the guards, and each member takes the `Request` and a
`CookieStore` over the request's cookies:

```typescript
import { createFidesAuth, fetchCookieStore } from "@eventuras/fides-auth/server";

export const auth = createFidesAuth({ oauthConfig, secret: process.env.SESSION_SECRET! });

// A route in a framework that hands you a Request and takes a Response
export async function login(request: Request): Promise<Response> {
  const cookies = fetchCookieStore(request);
  return cookies.apply(await auth.handleOidcLogin(request, cookies));
}
```

`fetchCookieStore` reads the request's `Cookie` header and keeps what the
members write. `apply` copies a handler's response with those cookies added,
and `headers()` gives them for a response you build yourself:

```typescript
const cookies = fetchCookieStore(request);
await auth.refreshSession(cookies, { ifExpiresWithin: 60 });
return new Response(body, { headers: cookies.headers() });
```

Take the cookies when the work is done: a cookie set after `headers()` or
`apply()` throws, since it could not reach the browser. A refresh that runs
after the response was built, in a stream say, must set its cookies another
way or happen before.

It fits React Router, Hono, SvelteKit, Astro and other frameworks built on
Fetch. Next.js has its own store in `@eventuras/fides-auth-next`. Anything else
needs only `get` and `set`:

```typescript
import type { CookieStore } from "@eventuras/fides-auth/server";

const cookies: CookieStore = {
  get: (name) => requestCookies.get(name),
  set: (name, value, options) => responseCookies.set(name, value, options),
};
```

A store must write each cookie with the options it is given. The library
deletes a cookie by setting it empty with `maxAge: 0`, so a store that sets a
lifetime of its own turns a logout into an empty cookie that stays.

It does no I/O until a member needs it, and checks the secret and the redirect
URI on first use, so a build can load the module that creates it. A client with
`clientAuth: 'none'` throws at once: the server side of an app is a
confidential client.

| Member | |
|---|---|
| `handleOidcLogin(request, cookies, { authorizationParameters? })` | `GET`, with an optional `?returnTo=`. Redirects to the provider. |
| `handleOidcCallback(request, cookies)` | Starts the session. Redirects to the return path with `?login=success`, unless `loginSuccessParam` is false. A login that fails goes to `defaultRedirectPath` with `?login=error&error=<code>`, see [When a login fails](#when-a-login-fails). |
| `handleOidcLogout(request, cookies, { state?, logoutHint? })` | `POST` from the app's own pages. Ends the session, revokes its refresh token, and redirects to the provider's end-session endpoint. |
| `handleSessionInfo(request, cookies)` | `GET`. Whether there is a session, whose, when it ends (`expiresAt`), and whether its access token still works (`tokenStatus`). Never refreshes, never returns tokens. |
| `handleHeartbeat(request, cookies)` | `POST`. Refreshes the session: 401 when it is over, 503 when the provider or the store failed. |
| `readSession`, `tryReadSession` | The session or null, or why there is none. `tryReadSession` also gives `tokenStatus`. |
| `getTokens` | The tokens, which the session doesn't carry. |
| `readSessionWithTokens` | The session and its tokens in one read, or why there is none. |
| `refreshSession(cookies, { ifExpiresWithin? })` | Refreshes the tokens, or only when the access token is about to expire. |
| `createSession`, `updateSession` | Starts a session from a token response, and changes its user or data. An update waits its turn after a refresh, so neither undoes the other. |
| `clearSession(cookies, { trigger? })` | Ends the session and revokes its refresh token, without the redirect. |
| `endUserSessions({ sub, iss? })` | Ends every session of one user, wherever they are signed in, and revokes their refresh tokens. Needs a `sessionStore` with `findMatching`. |
| `authorizedFetch(cookies, url, options)` | Calls an API with the access token. Never refreshes. |
| `cookieNames`, `oidc` | The session cookie's name, and the instance's OIDC client. |

Besides `oauthConfig` and `secret`, the config takes `sessionStore`,
`storeFields`, `sessionDurationSeconds` (12 hours), `refreshGraceSeconds` (10),
`applicationUrl` (the redirect URI's origin),
`mapSession`, `mapRefresh`, `rolesClaim` (`roles`), `validateReturnTo`, `defaultRedirectPath`
(`/`), `postLogoutRedirectUri` (`applicationUrl`), `rateLimit`, `logger`,
`onSessionEvent` and `loginSuccessParam` (true).

#### When a login fails

A login that fails never answers with text of its own. The user is sent to
`defaultRedirectPath` with `?login=error&error=<code>`, for the page to show
in its own words:

| Code | |
|---|---|
| `login_expired` | The callback found no login to finish: it took more than ten minutes, was finished already, or its cookie never arrived. Only for a browser without a session: a callback opened again by a logged-in browser (the back button, a reload) redirects to `defaultRedirectPath` instead. |
| `invalid_callback` | The callback didn't match the login it belongs to. |
| `session_too_large` | The session doesn't fit in the cookies. A `sessionStore` is the fix. |
| `login_failed` | Anything else at the callback, such as a code the provider won't exchange. |
| `login_unavailable` | The login couldn't be started, most often because the provider couldn't be reached. |
| `rate_limited` | `rateLimit` refused the request, at the login or at the callback. |
| `access_denied` and the like | The provider's own error code, when the user cancels say. `idp_error` when the provider sent something that isn't a code. |

The logs have the details. A page that sends users without a session to the
login must leave a URL with `login=error` alone, or a login that keeps failing
goes in circles.

To answer in another way, pass `onLoginError`. It gets the code, whether the
login failed at its `'login'` or `'callback'` stage, and what was thrown. A
Response it returns is the answer; without one the redirect stands:

```typescript
const auth = createFidesAuth({
  oauthConfig,
  secret,
  onLoginError: ({ code }) => Response.redirect(`https://app.example.com/login-failed?why=${code}`),
});
```

A logout that fails leaves the user logged in. It redirects to
`defaultRedirectPath` with `?logout=error&error=logout_failed`, or
`error=rate_limited` when `rateLimit` refused it. `onLogoutError` answers in
another way. A logout while the provider can't be reached still ends the local
session and lands on `postLogoutRedirectUri`.

#### Sessions

A session lasts `sessionDurationSeconds` from login, 12 hours unless you say
otherwise, and refreshes don't extend it. Read `expiresAt` from the session each
time rather than computing it from `createdAt`, since a later version may let a
session be extended. With a session at the provider, the
login after that is a redirect without a password.
It is sealed with AES-256-GCM into the `__Host-session` cookie, in up to three
chunks (`session` over plain http). A `Session` has `correlationId`,
`createdAt`, `expiresAt`, `user`, `scopes`, `idp` and `data`. The tokens aren't
on it: `getTokens` returns them. At login `scopes` are the scopes the provider
granted, which are the ones asked for when its response names none.

Every read opens the session again, and with a `sessionStore` it is a round
trip to the store. Code that needs both the session and its tokens reads them
together:

```typescript
const { session, tokens, reason } = await auth.readSessionWithTokens(cookies);
```

Where several parts of one request need the session, as the loaders of one
page do, read it once per request and pass it on, e.g. from a middleware
through the request's context. Keep `tokens` on the server, and hand the
browser `session`.

To keep more of the token response or the ID token claims, pass `mapSession`.
A type argument to `createFidesAuth` types `data` in every session the instance
hands out. It is your own promise: the library doesn't check what a stored
session holds.

```typescript
interface AppData {
  tenant: string;
}

const auth = createFidesAuth<AppData>({
  oauthConfig,
  secret,
  rolesClaim: "groups",
  mapSession: (tokens, claims, session) => ({
    ...session,
    data: { tenant: String(claims?.tenant) },
  }),
});

const session = await auth.readSession(cookies);
session?.data?.tenant; // string | undefined, without a cast
```

`claims` are decoded, not verified. Without an `id_token` (no `openid` scope),
`claims` is undefined and the session has no `user`. `user` is a `SessionUser`:
`sub`, `name`, `email` and `roles`. Keep the app's own fields in `data`. Extra
fields make the session bigger; large ones need a `sessionStore`.

`mapSession` runs at login only. A refresh that brings an ID token updates
`user` from it the same way, so roles taken away at the provider go with the
next refresh: the roles follow `rolesClaim`, replacing any `mapSession` set,
the name and email change when the token carries them, and `sub` and the
fields `mapSession` added stay. `scopes` follow the refresh too, when its
response names them, so a scope taken away goes as well. `data` doesn't change. An ID token for another
`iss` or `sub` than at login fails the refresh with `cause: 'idp_error'`, and
nothing is saved.

`rolesClaim` says where the roles are in the ID token. A name reads a
top-level claim, `roles` unless you say otherwise. A function reads anything
else, such as Keycloak's realm roles, which are a claim inside a claim:

```typescript
const auth = createFidesAuth({
  oauthConfig,
  secret,
  rolesClaim: (claims) => (claims.realm_access as { roles?: string[] } | undefined)?.roles,
});
```

A token without the claim gives no roles, at login and at a refresh. Some
providers leave out a claim that would be empty, so a missing claim has to
count as the roles being taken away. The function must not throw when the
claim is missing.

Set the roles in `mapSession` only together with `rolesClaim: false`, for roles
that don't come from the ID token: your own database, say. The library then
never sets `user.roles`, and a refresh keeps them as they are. Under any other
`rolesClaim`, roles that `mapSession` set are replaced at the first refresh
that brings an ID token, unless `mapRefresh` sets them again. The first login
that shows this logs a warning.

What `mapSession` put in `data` stays as it was at login. To have it follow
the provider, pass `mapRefresh`. It has the shape of `mapSession` and runs at
each refresh, with that refresh's token response, the claims of its ID token
and the session after the library's own changes:

```typescript
const auth = createFidesAuth<AppData>({
  oauthConfig,
  secret,
  mapSession: (tokens, claims, session) => ({
    ...session,
    data: { tenant: String(claims?.tenant) },
  }),
  // A refresh without an ID token has no claims to follow.
  mapRefresh: (tokens, claims, session) =>
    claims ? { ...session, data: { tenant: String(claims.tenant) } } : session,
});
```

It is also the place for roles that only the access token carries, as Keycloak
sends them unless told otherwise: read them from `tokens.access_token` in both
functions. `mapRefresh` can't fail the refresh, since the provider has spent
the old refresh token by then. If it throws, the error is logged and the
session is saved as the refresh left it. It runs under the store's lock, so it
must not refresh, update or end the same session itself. Such a call is
refused with a TypeError, in `mapRefresh` and in the function you give
`updateSession` alike.

#### Keeping the session fresh

Nothing refreshes unless you ask. `refreshSession(cookies)` refreshes at once;
with `ifExpiresWithin` it refreshes only when the access token expires within
that many seconds, and the result says whether it `refreshed`:

```typescript
await auth.refreshSession(cookies, { ifExpiresWithin: 60 });
```

The window never covers more than half the token's lifetime. A 20-second token
is refreshed once 10 seconds have passed, not on every call.

A session reads until `expiresAt`, whether or not its tokens still work.
`tokenStatus` tells the two apart. `tryReadSession`, `readSessionWithTokens`
and the session info endpoint give it:

| `tokenStatus` | |
|---|---|
| `active` | The access token hasn't expired, or the provider gave no lifetime to go by. |
| `refreshable` | It has expired, and the session holds a refresh token: refresh before calling an API. |
| `expired` | It has expired and there is no refresh token. The user is still logged in, but calls with the token fail until a new login. |

A login without a refresh token, where `offline_access` isn't granted say,
ends up `expired` when the access token dies, often long before the session
does. The session is left as it is, since who the user is hasn't changed. An
app that takes a session to be no better than its token ends it there:

```typescript
const { session, tokenStatus } = await auth.tryReadSession(cookies);
if (session && tokenStatus === "expired") {
  await auth.clearSession(cookies, { trigger: "rejected" });
}
```

When the provider refuses a refresh for good, the result has `cause:
"invalid_grant"` and the user must log in again. A session in a `sessionStore`
that implements `withLock` is ended there and then: its record is deleted, and
its cookie too where cookies can be set. A cookie session, or one in
a store without a lock, is left as it is, because another instance may just
have refreshed it. End it yourself where that can't be the case:

```typescript
const result = await auth.refreshSession(cookies, { ifExpiresWithin: 60 });
if (!result.ok && result.cause === "invalid_grant") {
  await auth.clearSession(cookies, { trigger: "rejected" });
}
```

With cookie storage a refresh writes cookies, so call it where they can be set.
Reads and `authorizedFetch` never refresh, so they are safe anywhere. The
heartbeat endpoint refreshes when the browser asks it to.

Refreshes that overlap in one process share one call to the provider. With
cookie storage, a request the browser sent before the new cookies arrived still
carries the old refresh token. If the provider rotates refresh tokens, sending
that token again fails with `invalid_grant`, and some providers, OpenIddict
among them, then revoke the whole authorization. So for `refreshGraceSeconds`
after a refresh, 10 by default, such a request gets that refresh's result, and
its response sets the new cookies too.

The grace period works within one process, and only for the refresh token just
spent. A request that comes later, or that another instance refreshes at the
same time, still spends the old token. A `sessionStore` avoids that: a later
request reads the new tokens from the store, and `withLock` covers instances
that refresh at once.

Within the grace period a copy of the old cookie gets the new tokens too, as it
would under a provider's own reuse interval, so a stolen cookie isn't caught by
the provider's reuse detection as long as it keeps up. Set `refreshGraceSeconds`
to 0 to turn it off.

#### Cookie or store

By default the whole session lives in the cookie, sealed with AES-256-GCM. Pass
a `sessionStore` and the browser holds only a random handle, while the store
keeps the sealed record under the handle's hash. Nothing else changes: the
members, the lifecycle and the session events are the same.

```typescript
import { createFidesAuth, createMemorySessionStore } from "@eventuras/fides-auth/server";

const auth = createFidesAuth({
  oauthConfig,
  secret,
  sessionStore: createMemorySessionStore(), // or your own SessionStore (Mongo, Redis, …)
});
```

| | Cookie (default) | `sessionStore` |
|---|---|---|
| Size | At most three cookies of 4 kB. A session that doesn't fit fails at login with 431 | No limit; the cookie holds a 64-character handle |
| Sent on every request | The whole sealed session | The handle |
| Refresh | Writes cookies, so it runs where they can be set: a proxy, a route handler or a Server Action | Keeps the handle and writes no cookie, so it also runs in a Server Component |
| Concurrent refreshes | Shared within one process, and for `refreshGraceSeconds` after, with a request that still carries the old cookie | Shared across instances too, when the store implements `withLock` |
| Logout | Clears the cookie and revokes the refresh token. A copy of the cookie still reads as a session, and its access token works until it expires | Deletes the record, so a copied cookie stops working |
| A refresh refused for good | The session reads until `expiresAt`, unless the app ends it | Ended at once, when the store implements `withLock` |
| Ending a user's sessions elsewhere | No | `endUserSessions`, when the store implements `findMatching` |
| To run | Nothing | A store every instance shares, with a TTL on `expiresAt` |

A refresh that is running when the user logs out finishes first, and the
logout revokes the refresh token it brought back. The same goes for one that
finished within the grace period, when the logout still carries the cookie from
before it. With cookie storage, that
refresh's response still sets the cookie again: the browser reads as logged in
until the access token expires, and can't refresh. A store doesn't save a
session that ended, and ends it under `withLock`, so no instance brings it
back.

Choose the store when the provider's tokens don't fit in three cookies
(OpenIddict's encrypted JWE tokens, for instance), when logout must end a
copied cookie, when you need to sign a user out everywhere, or when you
refresh from Server Components. Both seal the
session with `secret`, so rotating it ends every session either way, and
moving from one to the other logs users in again once.

See [docs/server-sessions.md](./docs/server-sessions.md) for the store contract.

#### Login

`handleOidcLogin` seals each login (state, PKCE verifier, return path, start
time) into one of three `__Host-oauth_tx_<n>` cookies, so parallel logins don't
collide; a fourth evicts the oldest. The callback rejects one after 10 minutes,
and deletes it whatever the outcome. `validateReturnTo` turns `?returnTo=` into
a safe path. The default accepts only a path on this origin, and the redirect
stays on `applicationUrl`'s origin whatever it returns.

#### API calls with the access token

`authorizedFetch` sends the session's access token only to URLs under
`allowedBase` (same origin, and a path under its path). It never follows a
redirect, never refreshes, and times out after 10 seconds by default:

```typescript
await auth.refreshSession(cookies, { ifExpiresWithin: 60 });
const { data } = await auth.authorizedFetch(cookies, `users/${id}`, {
  allowedBase: "https://api.example.com/v1/",
  parse: async (response) => parseUser(await response.json()),
});
```

A refused URL, a missing token, a non-2xx response (401 included), a timeout or
a failed `parse` throws an `AuthorizedFetchError` with a `reason`, the status,
and the URL without its query.

For a non-2xx response the error also says why, where it can, so the caller can
decide whether to refresh and retry:

- `accessTokenExpired` is true when the token had passed its expiry by this
  server's clock, and undefined when the provider gave no lifetime.
- `bearerError` is the `error` from the API's `WWW-Authenticate: Bearer`
  challenge (RFC 6750). `invalid_token` means the token is expired, revoked or
  malformed, so a refresh may help; `insufficient_scope` means it won't.

```typescript
try {
  return await auth.authorizedFetch(cookies, "users/me", { allowedBase });
} catch (error) {
  const refreshMayHelp =
    error instanceof AuthorizedFetchError &&
    error.status === 401 &&
    (error.accessTokenExpired || error.bearerError === "invalid_token");
  if (refreshMayHelp && (await auth.refreshSession(cookies)).ok) {
    return auth.authorizedFetch(cookies, "users/me", { allowedBase });
  }
  throw error;
}
```

### Browser (`/browser`)

What runs in the page: a store that knows who is logged in, a monitor that keeps
it in step with the server, and an optional heartbeat that keeps an active
user's session alive. It loads nothing from the server side and no third-party
code. React apps add [`@eventuras/fides-auth-react`](../fides-auth-react) for
the hooks.

```typescript
import {
  createAuthStore,
  initializeAuth,
  startSessionMonitor,
} from "@eventuras/fides-auth/browser";

export const authStore = createAuthStore({ adminRole: "Admin" });
await initializeAuth(authStore);

authStore.subscribe(() => render(authStore.getSnapshot()));

const stop = startSessionMonitor(authStore, {
  onSessionExpired: () => showMessage("Your session has expired"),
});
```

- **The store** asks `/api/auth/session`, the `handleSessionInfo` route, unless
  you pass `sessionEndpoint` or your own `checkAuthStatus`. A snapshot has
  `user`, `isAuthenticated`, `isAdmin`, `error`, `lastChecked` and
  `isInitializing`, and is a new object on every change. Change it with its
  methods: `authSuccess(user)`, `authFailed(error?)`, `sessionExpired()`,
  `logout()`, `setError(error)` and `clearError()`.
- **The monitor** checks every 30 seconds. When a session the store held is
  gone, it calls `onSessionExpired` and stops. A visitor who was never logged in
  just stays logged out, so it can run on every page. It never refreshes.
- **The heartbeat**, `createHeartbeat`, posts to `handleHeartbeat` shortly
  before the access token expires, while the user is active. Use it when
  refreshes should follow user activity; nothing else needs it.
- `onEvent` on the monitor and the heartbeat gets the client side's
  [session events](./docs/session-events.md), for forwarding to your own
  endpoint.

### Logging

Every part that logs takes a `logger` option: a `FidesLoggerFactory` that
creates its loggers. That is `createFidesAuth`, `createOidcClient`,
`createAuthStore`, `startSessionMonitor`, `createHeartbeat` and
`VippsLoginClient`. Without one, a part writes newline-delimited JSON to
`console.<level>`, which Loki, Grafana, Datadog and other log shippers read
without any setup. There is no global setting, so pass your factory to each
part:

```typescript
import pino from "pino";
import type { FidesLoggerFactory } from "@eventuras/fides-auth";

const pinoInstance = pino();
const logger: FidesLoggerFactory = {
  create({ namespace, context }) {
    return pinoInstance.child({ namespace, ...context });
  },
};

export const auth = createFidesAuth({ oauthConfig, secret, logger });
```

Any object implementing `{ debug, info, warn, error }` works — pino, winston, bunyan, or your own.

The default JSONL output looks like:

```json
{"level":"info","time":"2026-04-15T19:40:57.300Z","namespace":"fides-auth:oauth","msg":"Token refresh successful"}
```

### Vipps Login Provider (`/providers/vipps`)

`VippsLoginClient` is an OIDC client with the Vipps defaults, and the userinfo
call that needs Vipps' own headers:

```typescript
import {
  VippsLoginClient,
  VippsEnvironments,
  VippsLoginScopes,
  getVippsIssuer,
} from "@eventuras/fides-auth/providers/vipps";

const vipps = new VippsLoginClient(
  {
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
    redirectUri: "https://app.example.com/callback",
    subscriptionKey: "your-subscription-key",
    // The issuer is under the environment's address, not the address itself.
    issuer: getVippsIssuer(VippsEnvironments.Production),
    scope: [VippsLoginScopes.OpenId, VippsLoginScopes.Email, VippsLoginScopes.Name],
  },
  { logger }, // optional, like createOidcClient's options
);

// Login: keep `request` on the server until the callback.
const request = await vipps.createAuthorizationRequest();
const url = await vipps.authorizationUrl(request);

// Callback
const tokens = await vipps.exchangeCode(new URL(callbackUrl), request);
const user = await vipps.getUserInfo(tokens.access_token);
```

`vipps.oidc` is the OIDC client underneath, for the rest of the protocol.

## Security

- **PKCE** — All OAuth flows use Proof Key for Code Exchange
- **AES-256-GCM** — Sessions encrypted with authenticated encryption
- **Open redirect protection** — Return paths are validated and kept on the app's origin
- **CSRF** — Logout and heartbeat answer only a same-origin `POST`
- **No secret logging** — Tokens, keys, and PII are never logged
- **Web Crypto API** — Uses the platform cryptographic primitives (not userland crypto)

## TypeScript

The shared types come from the root entry, and the server's from `/server`:

```typescript
import type {
  Session,
  Tokens,
  OidcClientConfig,
  TokenResponse,
  FidesLogger,
  FidesLoggerFactory,
} from "@eventuras/fides-auth";
import type {
  CookieStore,
  FidesAuth,
  FidesAuthConfig,
  SessionStore,
} from "@eventuras/fides-auth/server";
```

## License

[MIT](./LICENSE)
