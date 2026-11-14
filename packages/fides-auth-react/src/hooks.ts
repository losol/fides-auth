import type { AuthState, AuthStore } from '@eventuras/fides-auth/browser';
import { useSyncExternalStore } from 'react';

/** The store's actions, for components that change the session state. */
export type AuthStoreActions = Pick<
  AuthStore,
  'authSuccess' | 'authFailed' | 'sessionExpired' | 'logout' | 'setError' | 'clearError'
>;

/**
 * Creates the React hooks for one store. Call it once, next to the store, and
 * export the hooks.
 *
 * @example
 * ```tsx
 * export const authStore = createAuthStore();
 * export const { useAuthStore, useAuthActions } = createAuthStoreHooks(authStore);
 *
 * function Greeting() {
 *   const auth = useAuthStore();
 *   if (auth.isInitializing) return <Spinner />;
 *   return auth.isAuthenticated ? <p>Hello {auth.user?.name}</p> : <LoginLink />;
 * }
 * ```
 */
export function createAuthStoreHooks(store: AuthStore): {
  useAuthStore: () => AuthState;
  useAuthActions: () => AuthStoreActions;
} {
  // The methods don't use `this`, so they can be handed out as they are, and
  // the object stays the same between renders.
  const actions: AuthStoreActions = {
    authSuccess: store.authSuccess,
    authFailed: store.authFailed,
    sessionExpired: store.sessionExpired,
    logout: store.logout,
    setError: store.setError,
    clearError: store.clearError,
  };

  return {
    useAuthStore: () => useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot),
    useAuthActions: () => actions,
  };
}
