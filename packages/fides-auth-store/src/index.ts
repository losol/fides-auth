/**
 * Framework-agnostic authentication state store.
 *
 * Built on XState Store, this package holds authentication *state* (who is logged
 * in, admin status, errors) and the logic to keep it in sync — with no dependency
 * on any UI framework or server runtime. The app supplies a `checkAuthStatus`
 * callback; the store does not read cookies or talk to a server itself, so it can
 * be driven from Next.js, React Router, or plain JavaScript alike.
 *
 * React bindings (hooks) live in a separate package layered on top of this one.
 *
 * @example
 * ```typescript
 * import {
 *   configureAuthLogger,
 *   createAuthStore,
 *   initializeAuth,
 *   startSessionMonitor,
 * } from '@eventuras/fides-auth-store';
 *
 * configureAuthLogger();
 *
 * export const authStore = createAuthStore({
 *   checkAuthStatus: getAuthStatus,
 *   config: { adminRole: 'Admin', loggerNamespace: 'myapp:auth' },
 * });
 *
 * await initializeAuth(authStore, getAuthStatus);
 *
 * const stop = startSessionMonitor(authStore, getAuthStatus, {
 *   interval: 30_000,
 *   onSessionExpired: () => console.warn('Session expired'),
 * });
 * ```
 */

export {
  createAuthStore,
  initializeAuth,
  checkAuth,
  type AuthStoreContext,
  type AuthStoreConfig,
} from './store';

export {
  startSessionMonitor,
  type SessionMonitorConfig,
} from './session-monitor';

export { configureAuthLogger } from './configure-logger';

export type { SessionUser, AuthStatus } from './types';
