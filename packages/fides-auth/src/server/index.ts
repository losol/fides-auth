// The server side: createFidesAuth and what an app needs around it, the
// cookie and session store contracts and the errors it can throw.

export type { CookieStore } from './cookie-store.js';
export { fetchCookieStore, type FetchCookieStore } from './fetch-cookie-store.js';
export { CookieTooLargeError } from '../shared/cookies.js';

export {
  createFidesAuth,
  type FidesAuth,
  type FidesAuthConfig,
  type FidesAuthorizedFetchOptions,
  type FidesReadResult,
  type FidesRefreshResult,
  type FidesSessionWithTokens,
  type LoginError,
  type LoginErrorCode,
  type MapSession,
  type RefreshSessionOptions,
} from './fides-auth.js';
export type { RolesClaim } from '../session/user-claims.js';
export { SessionSecretError, type SessionSecret } from './session-secret.js';
export { AuthorizedFetchError, type AuthorizedFetchErrorReason } from './authorized-fetch.js';

export {
  createMemorySessionStore,
  type SessionMatch,
  type SessionStore,
  type StoredSession,
  type StoredSessionEntry,
  type StoreFields,
  type StoreSetContext,
  type StoreSetReason,
} from './session-store.js';
