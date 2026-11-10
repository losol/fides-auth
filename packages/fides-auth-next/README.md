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

## Documentation

- [Store API](./src/store/) - XState Store details
- [Setup Guide](./SETUP_GUIDE.md) - Complete walkthrough
