/**
 * React bindings for @eventuras/fides-auth.
 *
 * Thin React hooks over the framework-agnostic building blocks:
 * - {@link createAuthStoreHooks} — `useAuthStore` / `useAuthActions` over an
 *   `@eventuras/fides-auth-store` auth store.
 * - {@link useSessionMonitor} — runs `startSessionMonitor` with `useEffect` cleanup.
 * - {@link useHeartbeat} — runs the `@eventuras/fides-auth` heartbeat engine.
 *
 * Pair these with `@eventuras/fides-auth-store` (the store + status checks) and a
 * server adapter such as `@eventuras/fides-auth-next` (cookies, route handlers).
 *
 * @example
 * ```tsx
 * 'use client';
 * import { createAuthStoreHooks, useSessionMonitor, useHeartbeat } from '@eventuras/fides-auth-react';
 * import { authStore, checkAuthStatus } from './auth';
 *
 * export const { useAuthStore, useAuthActions } = createAuthStoreHooks(authStore);
 *
 * export function AuthProvider({ children }: { children: React.ReactNode }) {
 *   useSessionMonitor(authStore, checkAuthStatus);
 *   useHeartbeat({ onSessionExpired: () => authStore.send({ type: 'sessionExpired' }) });
 *   return <>{children}</>;
 * }
 * ```
 */

export {
  createAuthStoreHooks,
  type AuthStoreSelector,
  type AuthStoreActions,
} from './hooks';

export { useSessionMonitor } from './use-session-monitor';

export { useHeartbeat, type HeartbeatConfig } from './use-heartbeat';
