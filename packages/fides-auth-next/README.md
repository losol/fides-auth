# @eventuras/fides-auth-next

Next.js bindings for `@eventuras/fides-auth`. `createFidesAuth` here is the core
instance bound to `cookies()` from `next/headers`. It caches session reads per
render with React's `cache()`, and adds a refresh for `proxy.ts`.

## Installation

```bash
pnpm add @eventuras/fides-auth @eventuras/fides-auth-next
```

`@eventuras/fides-auth`, `next` and `react` are peer dependencies, so the app
has one copy of core. Needs Node 22.

## Setup

Create one instance in a module of its own and import it where you need it:

```typescript
// lib/auth.ts
import { createFidesAuth } from "@eventuras/fides-auth-next";

export const auth = createFidesAuth({
  oauthConfig: {
    issuer: process.env.OIDC_ISSUER!,
    clientId: process.env.OIDC_CLIENT_ID!,
    clientSecret: process.env.OIDC_CLIENT_SECRET!,
    redirectUri: "https://app.example.com/api/auth/callback",
    scope: "openid profile email offline_access",
  },
  secret: process.env.SESSION_SECRET!, // openssl rand -hex 32
});
```

The library never reads the environment, so pass the values in. It checks the
secret and the redirect URI on first use, so `next build` can import the module
without them. A client with `clientAuth: 'none'` throws at once: the server side
of an app is a confidential client.

| Option | Default | |
|---|---|---|
| `sessionStore` | none | Keeps sessions in a store, with only a handle in the cookie. See below. |
| `storeFields` | none | `(session) => fields`. Plain fields to keep next to each stored session, e.g. your own user id. |
| `sessionDurationDays` | 30 | How long a session lasts from login. Refreshes don't extend it. |
| `applicationUrl` | the redirect URI's origin | The app's public origin, for the same-origin check and redirects. |
| `mapSession` | none | Changes the session built at login, e.g. to add `data`. |
| `rolesClaim` | `'roles'` | The ID token claim that holds the user's roles, at login and on every refresh that brings an ID token. |
| `validateReturnTo` | a path on this origin | Turns `?returnTo=` into a safe path, or null. |
| `defaultRedirectPath` | `'/'` | Where a login without a return path lands. |
| `postLogoutRedirectUri` | `applicationUrl` | Where the provider sends the user after logout. |
| `rateLimit` | none | `(request) => boolean`. The handlers answer 429 when it returns false. |
| `logger` | JSON lines on the console | A `FidesLoggerFactory`. |
| `onSessionEvent` | none | Gets every session event. See [session events](../fides-auth/docs/session-events.md). |

## Route handlers

```typescript
// app/api/auth/login/route.ts
export const GET = (request: Request) => auth.handleOidcLogin(request);

// app/api/auth/callback/route.ts
export const GET = (request: Request) => auth.handleOidcCallback(request);

// app/api/auth/logout/route.ts
export const POST = (request: Request) => auth.handleOidcLogout(request);

// app/api/auth/session/route.ts
export const GET = (request: Request) => auth.handleSessionInfo(request);
```

The callback's path must be the redirect URI's. Login takes `?returnTo=/path`
and lands there with `?login=success`.

Logout answers only a `POST` from the app's own pages, so a form does it:

```tsx
<form method="post" action="/api/auth/logout">
  <button>Log out</button>
</form>
```

`handleSessionInfo` answers whether there is a session, and whose. It never
refreshes and never returns tokens. `handleHeartbeat` is there for apps that tie
refreshes to user activity; it too answers only a same-origin `POST`.

## Reading the session

In Server Components, Server Actions and Route Handlers:

```typescript
const session = await auth.readSession(); // Session | null
const { session, reason } = await auth.tryReadSession();
const tokens = await auth.getTokens(); // Tokens | null
```

`readSession` and `tryReadSession` share one read per render. A `Session` has
`user`, `scopes`, `data`, `idp`, `correlationId`, `createdAt` and `expiresAt`.
The tokens aren't on it: `getTokens` returns them, and `authorizedFetch` uses
them.

`createSession`, `updateSession`, `refreshSession` and `clearSession` write
cookies, so they work in Server Actions and Route Handlers.

## Keeping the session fresh

Nothing refreshes unless you ask, with `refreshSession` or `refreshInProxy`.
Reads and `authorizedFetch` never do, so they are safe anywhere.

A Server Component can't set cookies, so it can't save a refreshed session.
Refresh in the proxy instead, before the page renders:

```typescript
// proxy.ts
import type { NextRequest } from "next/server";
import { auth } from "@/lib/auth";

export function proxy(request: NextRequest) {
  return auth.refreshInProxy(request);
}

export const config = {
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico).*)"],
};
```

`refreshInProxy` refreshes a session whose access token expires within 60
seconds; `ifExpiresWithin` changes that. The window never covers more than half
the token's lifetime, so a token shorter than the window isn't refreshed on
every request. It sets the new cookies on the response and on the request it
forwards, so the page renders with the refreshed session. A request without a
session cookie passes straight through, and a failed refresh leaves a cookie
session as it is.

The proxy runs for every request a page makes, prefetches included. With cookie
sessions and a provider that rotates refresh tokens, a request sent before the
new cookies arrived refreshes with a spent token and fails with
`invalid_grant`; see
[Keeping the session fresh](../fides-auth/README.md#keeping-the-session-fresh)
in the core README. A `sessionStore` avoids it.

To send users without a session to the login, check the cookie first:

```typescript
import { NextResponse, type NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  if (!request.cookies.has(auth.cookieNames.session)) {
    return NextResponse.redirect(new URL("/api/auth/login", request.url));
  }
  return auth.refreshInProxy(request);
}
```

In a Server Action or Route Handler, refresh first if the access token is about
to expire. Without `ifExpiresWithin`, `refreshSession` refreshes at once:

```typescript
await auth.refreshSession({ ifExpiresWithin: 60 });
```

The result says whether it `refreshed`. On failure it gives a `reason`, and
`cause: "invalid_grant"` means the user must log in again.

## Calling APIs

`authorizedFetch` sends the access token to URLs under `allowedBase`. It never
refreshes, so it works the same in a Server Component, a Server Action and a
Route Handler:

```typescript
const { data } = await auth.authorizedFetch("users/me", {
  allowedBase: "https://api.example.com/v1/",
  parse: (response) => response.json(),
});
```

A 401 throws an `AuthorizedFetchError` with the reason `http_error`. Pages get
fresh tokens from `refreshInProxy`; in a Server Action or Route Handler, call
`refreshSession({ ifExpiresWithin: 60 })` before the request.

The error says why, where it can. `accessTokenExpired` is true when the token
had passed its expiry by the server's clock. `bearerError` is the API's own
reason from its `WWW-Authenticate` header: `invalid_token` means a refresh may
help, and `insufficient_scope` means it won't.

## Server sessions

By default the session lives in the `__Host-session` cookie, in up to three
chunks. Pass a `sessionStore` to keep it on the server. The browser then holds
only a random handle, and logout deletes the record.
[Cookie or store](../fides-auth/README.md#cookie-or-store) compares the two.

```typescript
// lib/auth.ts
import { createFidesAuth, type SessionStore } from "@eventuras/fides-auth-next";

const sessionStore: SessionStore = {
  get: (key) => db.sessions.find(key),
  set: (key, record) => db.sessions.save(key, record),
  delete: (key) => db.sessions.remove(key),
};

export const auth = createFidesAuth({ oauthConfig, secret, sessionStore });
```

With a store that implements `findMatching`, `auth.endUserSessions({ sub })`
ends every session of one user, wherever they are signed in, and revokes their
refresh tokens.

Use a store that every instance shares, such as a database, and add `withLock`
when you run more than one instance. `createMemorySessionStore()` from
`@eventuras/fides-auth/server` is for tests. See
[Server-side sessions](../fides-auth/docs/server-sessions.md) for the store
contract.

## Rate limiting

There is no default limiter. Pass `rateLimit`, keyed on something the app
trusts, such as the client address your own proxy sets:

```typescript
export const auth = createFidesAuth({
  oauthConfig,
  secret,
  rateLimit: (request) => limiter.consume(clientKey(request)),
});
```

## Upgrading from 0.x

See [Upgrading to 1.0](../fides-auth/docs/migrating-to-1.0.md).
