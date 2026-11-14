// The server side: createFidesAuth and what an app needs around it, the
// cookie and session store contracts and the errors it can throw.

export type { CookieStore } from './cookie-store.js';
export { CookieTooLargeError } from '../shared/cookies.js';

export {
  createFidesAuth,
  type FidesAuth,
  type FidesAuthConfig,
  type FidesAuthorizedFetchOptions,
  type FidesReadResult,
  type FidesRefreshResult,
  type MapSession,
} from './fides-auth.js';
export { SessionSecretError, type SessionSecret } from './session-secret.js';
export { AuthorizedFetchError, type AuthorizedFetchErrorReason } from './authorized-fetch.js';

export {
  createMemorySessionStore,
  type SessionStore,
  type StoredSession,
} from './session-store.js';
