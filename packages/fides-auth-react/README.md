# @eventuras/fides-auth-react

React hooks for [`@eventuras/fides-auth`](../fides-auth). The session store, the
session monitor and the heartbeat live in core's `/browser`; this package runs
them with React's lifecycle:

- **`createAuthStoreHooks(store)`** gives `useAuthStore`, which re-renders on
  every change, and `useAuthActions`.
- **`useSessionMonitor(store, config?)`** runs the session monitor while the
  component is mounted.
- **`useHeartbeat(config?)`** runs the heartbeat while the component is
  mounted, to keep an active user's session alive.

## Install

```bash
pnpm add @eventuras/fides-auth @eventuras/fides-auth-react
```

`react` is a peer dependency.

## Usage

```tsx
// auth.ts
"use client";
import { createAuthStore, initializeAuth } from "@eventuras/fides-auth/browser";
import { createAuthStoreHooks } from "@eventuras/fides-auth-react";

export const authStore = createAuthStore({ adminRole: "Admin" });
export const { useAuthStore, useAuthActions } = createAuthStoreHooks(authStore);
void initializeAuth(authStore);
```

```tsx
// auth-provider.tsx
"use client";
import { useHeartbeat, useSessionMonitor } from "@eventuras/fides-auth-react";
import { authStore } from "./auth";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  useSessionMonitor(authStore, {
    onSessionExpired: () => toast.warn("Your session has expired"),
  });
  useHeartbeat({ onSessionExpired: authStore.sessionExpired });
  return children;
}
```

```tsx
// profile.tsx
"use client";
import { useAuthStore } from "./auth";

export function Profile() {
  const auth = useAuthStore();
  if (auth.isInitializing) return null;
  if (!auth.isAuthenticated) return <a href="/api/auth/login">Log in</a>;
  return (
    <form method="post" action="/api/auth/logout">
      <button>Log out {auth.user?.name}</button>
    </form>
  );
}
```

The store asks `/api/auth/session`, the `handleSessionInfo` route, unless you
give `createAuthStore` another `sessionEndpoint` or your own `checkAuthStatus`.
The monitor never refreshes the session; the heartbeat is optional, and posts
to `/api/auth/heartbeat`.

`useAuthActions` changes only the browser's view of the session, for example
after a login that didn't go through the routes. Logging out is a `POST` to
the logout route, as above.

`useSessionMonitor` and `useHeartbeat` read their callbacks through a ref, so
passing new ones on each render doesn't restart them.

## Upgrading from 0.x

The store comes from `@eventuras/fides-auth/browser` instead of
`@eventuras/fides-auth-store`, and has methods instead of
`send({ type })`. See [Migrating to 1.0](../fides-auth/docs/migrating-to-1.0.md).
