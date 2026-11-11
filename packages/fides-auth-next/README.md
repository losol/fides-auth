# @eventuras/fides-auth-next

Next.js authentication with XState Store state management.

## Installation

```bash
pnpm add @eventuras/fides-auth-next @xstate/store
```

## Quick Start

```typescript
// 1. Create store
import {
  createAuthStore,
  createAuthStoreHooks,
} from "@eventuras/fides-auth-next/store";

export const authStore = createAuthStore({
  checkAuthStatus: getAuthStatus,
  config: { adminRole: "Admin" },
});

export const { useAuthStore, useAuthActions } = createAuthStoreHooks(authStore);

// 2. Initialize in app
useEffect(() => {
  initializeAuth(authStore, getAuthStatus);
  return startSessionMonitor(authStore, getAuthStatus, { interval: 30_000 });
}, []);

// 3. Use in components
const { isAuthenticated, user, isAdmin } = useAuthStore();
const { logout } = useAuthActions();
```

## Features

- **XState Store**: Simple auth state management with automatic session monitoring
- **Cookie Helpers**: Server-side cookie operations
- **Session Management**: High-level session functions
- **OAuth**: Complete OAuth flow with PKCE and RP-initiated logout
- **TypeScript**: Full type safety

## Server Setup

Create one instance and import it where you need it. The library never reads
the environment, so pass the secret in:

```typescript
// lib/auth.ts
import { createFidesAuth } from "@eventuras/fides-auth-next";

export const auth = createFidesAuth({
  secret: process.env.SESSION_SECRET!, // openssl rand -hex 32
  oauthConfig,
});
```

Route handlers:

```typescript
// app/api/auth/login/route.ts
export const GET = (request: Request) => auth.handleOidcLogin(request);

// app/api/auth/callback/oidc/route.ts
export const GET = (request: Request) =>
  auth.handleOidcCallback(request, { applicationUrl: "https://app.example.com" });

// app/api/auth/logout/route.ts
export const POST = (request: Request) =>
  auth.handleOidcLogout(request, { postLogoutRedirectUri: "https://app.example.com/" });

// app/api/auth/heartbeat/route.ts
export const POST = (request: Request) => auth.handleHeartbeat(request);
```

Server components, server actions and route handlers:

```typescript
const session = await auth.getCurrentSession();
const { reason } = await auth.tryGetCurrentSession();
const refreshed = await auth.tryRefreshCurrentSession();
await auth.clearCurrentSession();
```

API calls with the access token. On a 401, `authorizedFetch` refreshes the
session and retries once; parallel calls in one request share the refresh. The
refresh writes cookies, so it works only in Server Actions and Route Handlers.
In a Server Component pass `refresh: false`, and a 401 is an `http_error`:

```typescript
const api = { allowedBase: "https://api.example.com/v1/" };

// Server Action or Route Handler
const { data } = await auth.authorizedFetch(session, "users/me", {
  ...api,
  parse: (response) => response.json(),
});

// Server Component
const { data } = await auth.authorizedFetch(session, "users/me", { ...api, refresh: false });
```

The handlers are also exported on their own (`@eventuras/fides-auth-next/oidc-login`
and so on). Those take `oauthConfig` and `secret` in their config.

## Server sessions

By default the session lives in encrypted cookies. Pass a `sessionStore` to keep
it on the server instead. The browser then holds only a random handle, in the
`session_ref` cookie:

```typescript
// lib/auth.ts
import { createFidesAuth, type SessionStore } from "@eventuras/fides-auth-next";

const sessionStore: SessionStore = {
  get: (key) => db.sessions.find(key),
  set: (key, record) => db.sessions.save(key, record),
  delete: (key) => db.sessions.remove(key),
};

export const auth = createFidesAuth({
  secret: process.env.SESSION_SECRET!,
  oauthConfig,
  sessionStore,
});
```

Every handler and helper on `auth` then uses the store, and logout deletes the
record. `secret` is still required: it encrypts the records and seals the login
transaction.

Use a store that every instance shares, such as a database, and add `withLock`
when you run more than one instance. `createMemorySessionStore()` from
`@eventuras/fides-auth/server` is for tests. See
[Server-side sessions](../fides-auth/docs/server-sessions.md) for the store
contract and an adapter example.

## Rate limiting

The route handlers use a default limiter. It is deprecated, together with
`globalGETRateLimit`, `globalPOSTRateLimit` and `TokenBucket`: it keys on the raw
`X-Forwarded-For` header, which a client can send itself, and lets requests
without the header through.

For a limiter of your own, add `@eventuras/fides-auth` and call its handler from
`/server` with the Next cookie store and a `rateLimit` callback. Key it on
something the app trusts, such as the client address your own proxy sets. The
handler answers 429 when the callback returns `false`:

```typescript
// app/api/auth/login/route.ts
import { handleOidcLogin } from "@eventuras/fides-auth/server";
import { nextCookieStore } from "@eventuras/fides-auth-next";

export async function GET(request: Request) {
  return handleOidcLogin(request, {
    oauthConfig,
    secret: process.env.SESSION_SECRET!,
    cookies: await nextCookieStore(),
    rateLimit: () => limiter.consume(clientKey(request)),
  });
}
```

`handleOidcCallback`, `handleOidcLogout` and `handleHeartbeat` take the same option.
With a `sessionStore`, also pass those three
`persistence: serverPersistence({ store: sessionStore, secret })`, or they keep
the session in cookies. Build it once. It does not share refreshes with `auth`,
so give the store `withLock`.

## Documentation

- [Store API](./src/store/) - XState Store details
- [Setup Guide](./SETUP_GUIDE.md) - Complete walkthrough
