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

### Node.js — OAuth with PKCE

```typescript
import {
  buildPKCEOptions,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
} from "@eventuras/fides-auth/oauth";
import { validateSessionJwt, createEncryptedJWT } from "@eventuras/fides-auth";

const oauthConfig = {
  issuer: "https://auth.example.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirect_uri: "https://app.example.com/callback",
  scope: "openid profile email offline_access",
};

// 1. Start login — redirect user to auth URL
const pkce = await buildPKCEOptions(oauthConfig);
const authUrl = await buildAuthorizationUrl(oauthConfig, pkce);

// 2. Handle callback — exchange code for tokens
const tokens = await exchangeAuthorizationCode(
  oauthConfig,
  callbackUrl,
  pkce.code_verifier,
  pkce.state,
);

// 3. Create encrypted session
const secret = "0123456789abcdef..."; // 64 hex chars (32 bytes)
const jwt = await createEncryptedJWT({ user, tokens }, secret);

// 4. Validate session later
const { status, session } = await validateSessionJwt(jwt, secret);
```

## Modules

Each module is available as a separate entry point for tree-shaking:

| Entry Point                                | Environment | Description                                           |
| ------------------------------------------ | ----------- | ----------------------------------------------------- |
| `@eventuras/fides-auth`                    | Node.js     | Main entry — re-exports utils, session, types, logger |
| `@eventuras/fides-auth/oauth`              | Node.js     | OAuth/OIDC flows with `openid-client`                 |
| `@eventuras/fides-auth/pkce`               | Universal   | PKCE verifier/challenge and `state` (Web Crypto)      |
| `@eventuras/fides-auth/id-token`           | Universal   | ID token verification against the provider JWKS       |
| `@eventuras/fides-auth/oauth-browser`      | Browser     | **Deprecated** — OAuth/OIDC flows with Web Crypto API |
| `@eventuras/fides-auth/session-validation` | Node.js     | Encrypted JWT session validation                      |
| `@eventuras/fides-auth/session-refresh`    | Node.js     | Automatic token refresh for sessions                  |
| `@eventuras/fides-auth/silent-login`       | Node.js     | Silent login (`prompt=none`) utilities                |
| `@eventuras/fides-auth/utils`              | Universal   | Crypto helpers, hashing, token generation             |
| `@eventuras/fides-auth/rate-limit`         | Universal   | Token-bucket rate limiter                             |
| `@eventuras/fides-auth/logger`             | Universal   | Pluggable logger interface and configuration          |
| `@eventuras/fides-auth/types`              | Universal   | TypeScript types (Session, Tokens, etc.)              |
| `@eventuras/fides-auth/server`             | Node.js     | Request handlers (login, callback, logout, heartbeat) |
| `@eventuras/fides-auth/providers/vipps`    | Node.js     | Vipps Login identity provider                         |

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
  buildSessionFromTokens,
  validateReturnUrl,
  buildOidcLogoutUrl,
  clientCredentialsGrant,
} from "@eventuras/fides-auth/oauth";
```

`extractUserFromTokens` and `buildSessionFromTokens` only decode the ID token —
they don't check its signature, `iss`, `aud` or `exp`. That is safe on tokens
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
  idTokenHint: session?.tokens?.idToken,
});
```

The `/server` entry point wraps the whole dance — read the hint, clear the cookies,
redirect. Its handlers never read the environment; pass the session `secret` in:

```typescript
import { handleOidcLogout } from "@eventuras/fides-auth/server";

return handleOidcLogout(request, {
  oauthConfig,
  cookies,
  secret: process.env.SESSION_SECRET!,
  postLogoutRedirectUri: "https://app.example.com/",
});
```

See [docs/rp-initiated-logout.md](./docs/rp-initiated-logout.md) for the full
parameter set, where the ID token is stored, and why `client_id` is still sent.

#### Server-side sessions

By default the session is encrypted into cookies. When a provider's tokens are
too large for that (OpenIddict's encrypted JWE tokens, for instance), keep the
session in a store and give the browser only a handle:

```typescript
import { serverPersistence, createMemorySessionStore } from "@eventuras/fides-auth/server";

const persistence = serverPersistence({
  store: createMemorySessionStore(), // or your own SessionStore (Mongo, Redis, …)
  secret: process.env.SESSION_SECRET!,
});

return handleHeartbeat(request, { oauthConfig, cookies, persistence });
```

Logout, heartbeat and the session helpers take `persistence` in place of
`secret`. The callback takes both: `secret` also opens the login transaction.
The store gets encrypted records keyed by a hash of the handle; `clearSession`
deletes the record, so logout revokes a copied cookie too. See
[docs/server-sessions.md](./docs/server-sessions.md).

#### Login transaction

`handleOidcLogin` seals each login (state, PKCE verifier, returnTo, start time)
into one of three `__Host-oauth_tx_<n>` cookies, so parallel logins don't
collide; a fourth evicts the oldest, and a `returnTo` over 1 KB as JSON is dropped. With
an `http:` `redirect_uri` (plain-http development) the cookie is a plain,
non-Secure `oauth_tx_<n>`. `handleOidcCallback` rejects it after 10 minutes and
deletes it whatever the outcome. Pass both handlers the same `secret`. A denied
or cancelled login redirects to `defaultRedirectPath` with
`?login=error&error=<code>`, or `error=login_expired` once the login has ended.

Custom flows use the same helpers. Pass them the handlers' cookie options, so a
custom login and the built-in callback (or the reverse) agree on the cookie:

```typescript
import {
  createTransaction,
  persistTransaction,
  readTransaction,
  clearTransaction,
  validateCallback,
  transactionCookieOptions,
} from "@eventuras/fides-auth/server";

const txCookie = transactionCookieOptions(oauthConfig.redirect_uri);

// Login
const pkce = await buildPKCEOptions(oauthConfig);
await persistTransaction(cookies, createTransaction(pkce, { returnTo }), secret, txCookie);

// Callback
try {
  const transaction = await readTransaction(cookies, state, secret, txCookie);
  if (!transaction) throw new Error("No login in progress");
  validateCallback(query, transaction); // throws CallbackValidationError
  // … exchangeAuthorizationCode(oauthConfig, url, transaction.codeVerifier, transaction.state)
} finally {
  await clearTransaction(cookies, state, secret, txCookie);
}
```

### OAuth — Browser (`/oauth-browser`)

> **Deprecated.** It hardcodes the provider endpoints and doesn't validate the
> token response. Use the server flow instead (`handleOidcLogin` /
> `handleOidcCallback` from `/server`). It will be removed in a later minor.

Lightweight browser-only flows using Web Crypto:

```typescript
import {
  generatePKCE,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
} from "@eventuras/fides-auth/oauth-browser";
```

### Session Management

```typescript
import { createEncryptedJWT, validateSessionJwt } from "@eventuras/fides-auth";
import { refreshSession } from "@eventuras/fides-auth/session-refresh";

// Secrets accept hex strings or Uint8Array
const secret = process.env.SESSION_SECRET!; // 64 hex chars = 32 bytes

// Create session JWT (AES-256-GCM encrypted)
const jwt = await createEncryptedJWT(sessionData, secret);

// Validate and decrypt
const { status, session } = await validateSessionJwt(jwt, secret);
if (status === "VALID") {
  // session is typed as Session
}

// Refresh expired tokens
const refreshed = await refreshSession(session, oauthConfig);
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
- **Open redirect protection** — `validateReturnUrl` prevents redirect attacks
- **No secret logging** — Tokens, keys, and PII are never logged
- **Web Crypto API** — Uses the platform cryptographic primitives (not userland crypto)

## TypeScript

All types are exported from `@eventuras/fides-auth/types`:

```typescript
import type {
  Session,
  Tokens,
  CreateSessionOptions,
} from "@eventuras/fides-auth/types";
import type {
  OAuthConfig,
  OidcUserInfo,
  PKCEOptions,
} from "@eventuras/fides-auth/oauth";
import type {
  FidesLogger,
  FidesLoggerFactory,
  FidesLoggerOptions,
} from "@eventuras/fides-auth/logger";
```

## License

[MIT](./LICENSE)
