export {
  createFidesAuth,
  type FidesAuth,
  type RefreshInProxyOptions,
} from './auth.js';
export { nextCookieStore } from './cookie-store.js';

// The types an app needs to configure the instance and use its results.
export type { Session, SessionInfo, TokenResponse, Tokens } from '@eventuras/fides-auth';
export type {
  CookieStore,
  FidesAuthConfig,
  FidesAuthorizedFetchOptions,
  FidesReadResult,
  FidesRefreshResult,
  MapSession,
  SessionStore,
  StoredSession,
} from '@eventuras/fides-auth/server';
