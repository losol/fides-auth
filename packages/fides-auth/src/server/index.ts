// Framework-agnostic server-side building blocks: a tiny CookieStore contract,
// the two session persistences (cookies, or a server-side store behind a
// handle), the session helpers over them, the login transaction, and the OIDC
// request handlers that adapters like @eventuras/fides-auth-next wire to their
// cookie store.

export type { CookieStore } from './cookie-store';

export {
  createMemorySessionStore,
  type SessionStore,
  type StoredSession,
} from './session-store';

export {
  cookiePersistence,
  serverPersistence,
  type ServerPersistenceOptions,
  type SessionPersistence,
  type SessionSecret,
} from './session-persistence';

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
} from './session';

export {
  createTransaction,
  persistTransaction,
  readTransaction,
  clearTransaction,
  validateCallback,
  CallbackValidationError,
  type CallbackValidationReason,
  type CreateTransactionOptions,
  type LoginTransaction,
  type TransactionCookieOptions,
  type ValidateCallbackOptions,
} from './login-transaction';

export { handleOidcLogin, type OidcLoginConfig } from './oidc-login';
export { handleOidcCallback, type OidcCallbackConfig } from './oidc-callback';
export { handleOidcLogout, type OidcLogoutConfig } from './oidc-logout';
export { handleHeartbeat, type HeartbeatHandlerConfig } from './heartbeat-handler';
