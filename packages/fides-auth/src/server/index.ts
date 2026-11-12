// Framework-agnostic server-side building blocks: a tiny CookieStore contract,
// the two session persistences (cookies, or a server-side store behind a
// handle), the session helpers over them, the login transaction, and the OIDC
// request handlers that adapters like @eventuras/fides-auth-next wire to their
// cookie store.

export type { CookieStore } from './cookie-store.js';

export {
  createMemorySessionStore,
  type SessionStore,
  type StoredSession,
} from './session-store.js';

export {
  cookiePersistence,
  serverPersistence,
  type ServerPersistenceOptions,
  type SessionPersistence,
  type SessionPersistenceConfig,
  type SessionSecret,
} from './session-persistence.js';

export {
  persistSession,
  readSession,
  tryReadSession,
  refreshSessionInStore,
  tryRefreshSessionInStore,
  readIdToken,
  clearSession,
  type ClearSessionOptions,
  type PersistSessionOptions,
  type ReadSessionResult,
  type RefreshSessionResult,
} from './session.js';

export {
  createTransaction,
  persistTransaction,
  readTransaction,
  clearTransaction,
  validateCallback,
  transactionCookieOptions,
  CallbackValidationError,
  type CallbackValidationReason,
  type CreateTransactionOptions,
  type LoginTransaction,
  type TransactionCookieOptions,
  type ValidateCallbackOptions,
} from './login-transaction.js';

export {
  authorizedFetch,
  AuthorizedFetchError,
  type AuthorizedFetchErrorDetails,
  type AuthorizedFetchErrorReason,
  type AuthorizedFetchOptions,
  type AuthorizedFetchResult,
} from './authorized-fetch.js';

export { handleOidcLogin, type OidcLoginConfig } from './oidc-login.js';
export { handleOidcCallback, type OidcCallbackConfig } from './oidc-callback.js';
export { handleOidcLogout, type OidcLogoutConfig } from './oidc-logout.js';
export { handleHeartbeat, type HeartbeatHandlerConfig } from './heartbeat-handler.js';
