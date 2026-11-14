/**
 * React hooks for @eventuras/fides-auth.
 *
 * Thin bindings over the browser side in `@eventuras/fides-auth/browser`:
 * - {@link createAuthStoreHooks}: `useAuthStore` and `useAuthActions` for a store
 *   from `createAuthStore`.
 * - {@link useSessionMonitor}: runs `startSessionMonitor` while mounted.
 * - {@link useHeartbeat}: runs `createHeartbeat` while mounted.
 *
 * @example
 * ```tsx
 * 'use client';
 * import { createAuthStore, initializeAuth } from '@eventuras/fides-auth/browser';
 * import { createAuthStoreHooks, useHeartbeat, useSessionMonitor } from '@eventuras/fides-auth-react';
 *
 * export const authStore = createAuthStore();
 * export const { useAuthStore, useAuthActions } = createAuthStoreHooks(authStore);
 * void initializeAuth(authStore);
 *
 * export function AuthProvider({ children }: { children: React.ReactNode }) {
 *   useSessionMonitor(authStore);
 *   useHeartbeat({ onSessionExpired: authStore.sessionExpired });
 *   return children;
 * }
 * ```
 */

export { createAuthStoreHooks, type AuthStoreActions } from './hooks.js';
export { useHeartbeat } from './use-heartbeat.js';
export { useSessionMonitor } from './use-session-monitor.js';
