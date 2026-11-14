# @eventuras/fides-auth

Framework-agnostic OAuth 2.0 / OpenID Connect library with PKCE, encrypted sessions, rate limiting, and pluggable logging.

## Features

- **OAuth 2.0 + OIDC** — Authorization Code with PKCE, token refresh, client credentials
- **Pushed Authorization Requests** — Opt-in RFC 9126 support (`usePar`) when the provider advertises it
- **Dual environment** — Node.js (`openid-client`) and browser (Web Crypto) entry points
- **Encrypted sessions** — AES-256-GCM encrypted JWTs for secure session storage
- **Server-side sessions** — Opt-in store behind an opaque handle cookie, for providers whose tokens don't fit a cookie
- **Rate limiting** — Generic token-bucket algorithm, ready for login protection
- **RP-initiated logout** — End the provider's session too, with `id_token_hint` (OIDC RP-Initiated Logout 1.0)
- **Silent login** — Detect `prompt=none` results without user interaction
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

**Requirements:** Node.js ≥ 18 (uses Web Crypto API)

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

| Entry Point                                | Environment | Description                                           |
| ------------------------------------------ | ----------- | ----------------------------------------------------- |
| `@eventuras/fides-auth`                    | Universal   | Types, and the utilities, logger and session events   |
| `@eventuras/fides-auth/oauth`              | Node.js     | **Deprecated** — use `/oidc`                          |
| `@eventuras/fides-auth/oidc`               | Universal   | The OIDC client (`createOidcClient`) and pure helpers |
| `@eventuras/fides-auth/pkce`               | Universal   | **Deprecated** — same functions on `/oidc`            |
| `@eventuras/fides-auth/id-token`           | Universal   | **Deprecated** — use `oidc.verifyIdToken`             |
| `@eventuras/fides-auth/oauth-browser`      | Browser     | **Deprecated** — OAuth/OIDC flows with Web Crypto API |
| `@eventuras/fides-auth/silent-login`       | Node.js     | **Deprecated** — use `oidc.silentLoginUrl`            |
| `@eventuras/fides-auth/utils`              | Universal   | **Deprecated** — no replacement                       |
| `@eventuras/fides-auth/rate-limit`         | Universal   | **Deprecated** — pass `rateLimit` to the handlers     |
| `@eventuras/fides-auth/logger`             | Universal   | **Deprecated** — types on the root entry              |
| `@eventuras/fides-auth/types`              | Universal   | **Deprecated** — types on the root entry              |
| `@eventuras/fides-auth/server`             | Node.js     | `createFidesAuth`: the handlers, sessions and API calls |
| `@eventuras/fides-auth/providers/vipps`    | Node.js     | Vipps Login identity provider                         |

Deprecated entries keep working until 1.0. [Migrating to 1.0](docs/migrating-to-1.0.md)
lists what replaces each one.

### OIDC client (`/oidc`)

`createOidcClient` holds one provider's config, its discovery and JWKS caches
and its logger, so two clients share no state. Creating one does no I/O:
discovery runs on first use. This is the API that 1.0 keeps; the free functions
in `/oauth` are what it replaces.

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
  for client credentials can leave it out. `redirect_uri` is still accepted.
- **`logger`** is a `FidesLoggerFactory`. Without one, the client logs through
  whatever `configureLogger` set.
- **Pure helpers** come from the same entry: `createPkcePair`, `createState`,
  `defaultScope`, `joinScope`, `userFromClaims`, `checkSilentLoginResult`,
  `requiresInteractiveLogin`, `getOAuthErrorLogContext` and
  `classifyRefreshFailure`.

### Server (`/server`)

`createFidesAuth` is the server side as one object. It holds the OIDC client,
the session storage and the guards, and each member takes the `Request` and a
`CookieStore` over the request's cookies:

```typescript
import { createFidesAuth, type CookieStore } from "@eventuras/fides-auth/server";

export const auth = createFidesAuth({ oauthConfig, secret: process.env.SESSION_SECRET! });

const cookies: CookieStore = {
  get: (name) => requestCookies.get(name),
  set: (name, value, options) => responseCookies.set(name, value, options),
};
```

It does no I/O until a member needs it, and checks the secret and the redirect
URI on first use, so a build can load the module that creates it. A client with
`clientAuth: 'none'` throws at once: the server side of an app is a
confidential client.

| Member | |
|---|---|
| `handleOidcLogin(request, cookies, { authorizationParameters? })` | `GET`, with an optional `?returnTo=`. Redirects to the provider. |
| `handleOidcCallback(request, cookies)` | Starts the session. Redirects to the return path with `?login=success`, or home with `?login=error&error=<code>`. |
| `handleOidcLogout(request, cookies, { state?, logoutHint? })` | `POST` from the app's own pages. Ends the session and redirects to the provider's end-session endpoint. |
| `handleSessionInfo(request, cookies)` | `GET`. Whether there is a session, and whose. Never refreshes, never returns tokens. |
| `handleHeartbeat(request, cookies)` | `POST`. Refreshes the session: 401 when it is over, 503 when the provider can't be reached. |
| `readSession`, `tryReadSession` | The session or null, or why there is none. |
| `getTokens` | The tokens, which the session doesn't carry. |
| `refreshSession(cookies, { ifExpiresWithin? })` | Refreshes the tokens, or only when the access token is about to expire. |
| `createSession`, `updateSession`, `clearSession` | |
| `authorizedFetch(cookies, url, options)` | Calls an API with the access token. Never refreshes. |
| `cookieNames`, `oidc` | The session cookie's name, and the instance's OIDC client. |

Besides `oauthConfig` and `secret`, the config takes `sessionStore`,
`sessionDurationDays` (30), `applicationUrl` (the redirect URI's origin),
`mapSession`, `rolesClaim` (`roles`), `validateReturnTo`, `defaultRedirectPath`
(`/`), `postLogoutRedirectUri` (`applicationUrl`), `rateLimit`, `logger` and
`onSessionEvent`.

#### Sessions

A session lasts `sessionDurationDays` from login, and refreshes don't extend it.
It is sealed with AES-256-GCM into the `__Host-session` cookie, in up to three
chunks (`session` over plain http). A `Session` has `correlationId`,
`createdAt`, `expiresAt`, `user`, `scopes`, `idp` and `data`. The tokens aren't
on it: `getTokens` returns them.

To keep more of the token response or the ID token claims, pass `mapSession`:

```typescript
const auth = createFidesAuth({
  oauthConfig,
  secret,
  rolesClaim: "groups",
  mapSession: (tokens, claims, session) => ({ ...session, data: { tenant: claims?.tenant } }),
});
```

`claims` are decoded, not verified. Without an `id_token` (no `openid` scope),
`claims` is undefined and the session has no `user`. Extra fields make the
session bigger; large ones need a `sessionStore`.

#### Keeping the session fresh

Nothing refreshes unless you ask. `refreshSession(cookies)` refreshes at once;
with `ifExpiresWithin` it refreshes only when the access token expires within
that many seconds, and the result says whether it `refreshed`:

```typescript
await auth.refreshSession(cookies, { ifExpiresWithin: 60 });
```

With cookie storage a refresh writes cookies, so call it where they can be set.
Reads and `authorizedFetch` never refresh, so they are safe anywhere. The
heartbeat endpoint refreshes when the browser asks it to.

#### Server-side sessions

When a provider's tokens don't fit in three cookies (OpenIddict's encrypted JWE
tokens, for instance), pass a `sessionStore`. The browser then holds only a
random handle, and the store keeps the sealed record under the handle's hash.
Logout deletes the record, so a copied cookie stops working too.

```typescript
import { createFidesAuth, createMemorySessionStore } from "@eventuras/fides-auth/server";

const auth = createFidesAuth({
  oauthConfig,
  secret,
  sessionStore: createMemorySessionStore(), // or your own SessionStore (Mongo, Redis, …)
});
```

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

### OAuth — Node.js (`/oauth`)

Full OIDC flows using `openid-client`:

```typescript
import {
  buildPKCEOptions,
  buildAuthorizationUrl,
  buildAuthorizationUrlWithPAR,
  discoverAndBuildAuthorizationUrl,
  exchangeAuthorizationCode,
  refreshAccessToken,
  extractUserFromTokens,
  validateReturnUrl,
  buildOidcLogoutUrl,
  clientCredentialsGrant,
} from "@eventuras/fides-auth/oauth";
```

`extractUserFromTokens` only decodes the ID token — it doesn't check its
signature, `iss`, `aud` or `exp`. That is safe on tokens
straight from `exchangeAuthorizationCode`. Verify tokens from anywhere else
first with `verifyIdToken` from `@eventuras/fides-auth/id-token`.

#### Client authentication

`clientAuth` sets how the client authenticates at the token endpoint. Omit it
for `client_secret_post`:

```typescript
{ clientSecret: "…" }                                    // client_secret_post
{ clientAuth: "client_secret_basic", clientSecret: "…" }
{ clientAuth: "none" }                                   // public client, PKCE only
{ clientAuth: "private_key_jwt", privateKey }            // CryptoKey or { key, kid }
```

`clientCredentialsGrant` takes the same options except `none`.

#### Server metadata instead of discovery

If the server publishes its metadata somewhere other than
`/.well-known/openid-configuration` (an RFC 8414 document, say), fetch it
yourself and pass it as `serverMetadata`. fides-auth then skips discovery:

```typescript
const oauthConfig: OAuthConfig = {
  issuer: "https://auth.example.com",
  clientId: "your-client-id",
  clientAuth: "none",
  redirect_uri: "https://app.example.com/callback",
  scope: "openid profile",
  serverMetadata: await fetch(metadataUrl).then((r) => r.json()),
};
```

With `openid` in the scope the metadata must include `issuer`, so the ID token's
`iss` can be checked.

#### PKCE and state (`/pkce`)

For flows that manage their own login transaction. Web Crypto only, so it also
runs in the browser and on edge runtimes:

```typescript
import { createPkcePair, createState } from "@eventuras/fides-auth/pkce";

const { verifier, challenge } = await createPkcePair(); // S256
const state = createState();
```

`buildPKCEOptions` is built on the same two functions.

#### ID token verification (`/id-token`)

Checks an ID token's signature, `iss`, `aud` and `exp` against the provider's
JWKS and returns the claims. Also runs in the browser:

```typescript
import { verifyIdToken } from "@eventuras/fides-auth/id-token";

const claims = await verifyIdToken(idToken, {
  issuer: "https://auth.example.com",
  audience: "your-client-id",
  oauthConfig, // or jwksUri: "https://auth.example.com/jwks"
});
```

`algorithms` defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. The JWKS is cached per URI.

#### Scope and extra authorization parameters

`scope` takes a string or an array. Other authorization parameters (`prompt`,
`login_hint`, `resource`, …) can be set on the config, per call, or per request
in `handleOidcLogin`. They go through PAR too.

```typescript
const oauthConfig = {
  // …
  scope: ["openid", "profile", "offline_access"],
  authorizationParameters: { resource: "https://api.example.com" },
};

const pkce = await buildPKCEOptions(oauthConfig, {
  parameters: { login_hint: "user@example.com" },
});

// Or per request in the server handler
return handleOidcLogin(request, {
  oauthConfig,
  cookies,
  secret: process.env.SESSION_SECRET!,
  authorizationParameters: (request) =>
    new URL(request.url).searchParams.has("reauth") ? { prompt: "login" } : {},
});
```

Per-call parameters override the config's, and a `scope` among them replaces
`OAuthConfig.scope`. These keys are reserved, and passing one throws:

- `state`, `code_challenge`, `code_challenge_method` and `redirect_uri`, which
  fides-auth sets.
- `client_id` and `response_type`, which openid-client sets.
- `request` and `request_uri`, which would bypass PKCE and `state`.
- `nonce`, which the callback doesn't check, so the login would fail.

#### Pushed Authorization Requests (PAR, RFC 9126)

Opt in by setting `usePar: true` on your `OAuthConfig`. The convenience
helper `discoverAndBuildAuthorizationUrl` then posts the authorization
parameters to the provider's PAR endpoint and returns a URL containing
only `client_id` and `request_uri`:

```typescript
const oauthConfig = {
  issuer: "https://auth.example.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirect_uri: "https://app.example.com/callback",
  scope: "openid profile email offline_access",
  usePar: true,
};

const pkce = await buildPKCEOptions(oauthConfig);
const authUrl = await discoverAndBuildAuthorizationUrl(oauthConfig, pkce);
// redirect user to authUrl
```

Behaviour:

- `usePar: true` + provider advertises `pushed_authorization_request_endpoint` → uses PAR.
- `usePar: true` + provider does **not** advertise PAR → throws.
- `usePar` unset/false + provider advertises PAR → standard flow, with a
  one-line `info` log noting that PAR is available but not enabled.
- `usePar` unset/false + no PAR endpoint → standard flow, no advisory.

If you already have a discovered `Configuration` you can call the
low-level wrapper directly:

```typescript
const authUrl = await buildAuthorizationUrlWithPAR(config, pkce);
```

#### RP-Initiated Logout

Clearing your own session cookie is not a logout — the provider's session survives,
so the next `/authorize` re-authenticates silently. `buildOidcLogoutUrl` builds the
request that ends the provider session too, and returns `null` when the provider
advertises no `end_session_endpoint`:

```typescript
const logoutUrl = await buildOidcLogoutUrl(oauthConfig, {
  postLogoutRedirectUri: "https://app.example.com/",
  idTokenHint: (await auth.getTokens(cookies))?.idToken,
});
```

`handleOidcLogout` on the [server instance](#server-server) wraps the whole
dance: read the hint, end the session, redirect.

See [docs/rp-initiated-logout.md](./docs/rp-initiated-logout.md) for the full
parameter set, where the ID token is stored, and why `client_id` is still sent.

### OAuth — Browser (`/oauth-browser`)

> **Deprecated.** It hardcodes the provider endpoints and doesn't validate the
> token response. Use the server flow instead (`createFidesAuth` from
> `/server`). It goes in 1.0.

Lightweight browser-only flows using Web Crypto:

```typescript
import {
  generatePKCE,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
} from "@eventuras/fides-auth/oauth-browser";
```

### Crypto Utilities (`/utils`)

Standalone cryptographic helpers using Web Crypto API:

```typescript
import {
  encrypt,
  decrypt,
  sha256,
  sha512,
  generateToken,
  toHex,
  hexToUint8Array,
} from "@eventuras/fides-auth/utils";

// AES-256-GCM encryption
const secret = "0123456789abcdef".repeat(4); // 64 hex chars
const encrypted = await encrypt("sensitive data", secret);
const decrypted = await decrypt(encrypted, secret);

// Hashing
const hash = await sha256("hello world");

// Random token generation
const token = generateToken(32); // 64 hex char token

// Hex conversions
const bytes = hexToUint8Array("deadbeef");
const hex = toHex(new Uint8Array([0xde, 0xad]));
```

### Rate Limiting (`/rate-limit`)

Generic token-bucket rate limiter:

```typescript
import { TokenBucket } from "@eventuras/fides-auth/rate-limit";

// 5 attempts per 60 seconds per IP
const loginLimiter = new TokenBucket<string>(5, 60);

function handleLogin(ip: string) {
  if (!loginLimiter.consume(ip, 1)) {
    throw new Error("Too many login attempts");
  }
  // proceed with login
}
```

### Silent Login (`/silent-login`)

Detect whether a user has an active session without showing UI:

```typescript
import {
  buildSilentLoginUrl,
  checkSilentLoginResult,
  requiresInteractiveLogin,
  SilentLoginErrors,
} from "@eventuras/fides-auth/silent-login";
```

### Pluggable Logging (`/logger`)

The library writes newline-delimited JSON to `console.<level>` by default — interoperable with Loki, Grafana, Datadog, and other log shippers without any setup. Plug in a richer logger at startup if you want OpenTelemetry, redaction, or shared formatting with the rest of your app:

```typescript
import { configureLogger } from "@eventuras/fides-auth/logger";

// Example: plug in @eventuras/logger
import { Logger } from "@eventuras/logger";
configureLogger({
  create(options) {
    return Logger.create(options);
  },
});

// Or plug in pino directly
import pino from "pino";
const pinoInstance = pino();
configureLogger({
  create({ namespace, context }) {
    return pinoInstance.child({ namespace, ...context });
  },
});
```

Any object implementing `{ debug, info, warn, error }` works — pino, winston, bunyan, or your own.

The default JSONL output looks like:

```json
{"level":"info","time":"2026-04-15T19:40:57.300Z","namespace":"fides-auth:oauth","msg":"PKCE parameters generated"}
```

### Vipps Login Provider (`/providers/vipps`)

```typescript
import {
  VippsLoginClient,
  VippsEnvironments,
  VippsLoginScopes,
} from "@eventuras/fides-auth/providers/vipps";

const client = new VippsLoginClient({
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://app.example.com/callback",
  subscriptionKey: "your-subscription-key",
  issuer: VippsEnvironments.Production,
  scope: [
    VippsLoginScopes.OpenId,
    VippsLoginScopes.Email,
    VippsLoginScopes.Name,
  ].join(" "),
});

const pkce = await client.buildPKCEOptions();
const authUrl = await client.buildAuthorizationUrl(pkce);
// redirect user → callback → exchange code → getUserInfo
```

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
  OAuthConfig,
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
