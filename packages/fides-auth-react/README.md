# @eventuras/fides-auth-react

React hooks for [`@eventuras/fides-auth`](../fides-auth) — thin bindings over the
framework-agnostic building blocks:

- **`createAuthStoreHooks(store)`** → `useAuthStore` / `useAuthActions` for an
  [`@eventuras/fides-auth-store`](../fides-auth-store) auth store.
- **`useSessionMonitor(store, checkAuthStatus, config?)`** → runs
  `startSessionMonitor` with `useEffect` cleanup.
- **`useHeartbeat(config?)`** → runs the `@eventuras/fides-auth` heartbeat engine
  to keep the session alive for active users.

The heavy logic lives in the packages these wrap (the heartbeat engine in
`@eventuras/fides-auth`, the store and session monitor in
`@eventuras/fides-auth-store`); this package only adds the React lifecycle glue.

## Install

```bash
pnpm add @eventuras/fides-auth-react
```

`react`, `@xstate/store`, and `@xstate/store-react` are peer dependencies.

## Usage

```tsx
'use client';
import {
  createAuthStoreHooks,
  useSessionMonitor,
  useHeartbeat,
} from '@eventuras/fides-auth-react';
import { authStore, checkAuthStatus } from './auth';

export const { useAuthStore, useAuthActions } = createAuthStoreHooks(authStore);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  useSessionMonitor(authStore, checkAuthStatus);
  useHeartbeat({
    onSessionExpired: () => authStore.send({ type: 'sessionExpired' }),
  });
  return <>{children}</>;
}

function Profile() {
  const auth = useAuthStore();
  const { logout } = useAuthActions();
  if (auth.isInitializing) return null;
  return auth.isAuthenticated ? (
    <button onClick={logout}>Log out {auth.user?.name}</button>
  ) : (
    <a href='/login'>Log in</a>
  );
}
```
