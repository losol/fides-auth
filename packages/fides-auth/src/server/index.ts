// Framework-agnostic server-side building blocks: a tiny CookieStore contract and
// the session persistence helpers (and, over time, the OIDC request handlers)
// that adapters like @eventuras/fides-auth-next wire to their cookie store.

export type { CookieStore } from './cookie-store';

export {
  persistSession,
  readSession,
  refreshSessionInStore,
  clearSession,
} from './session';

export { handleOidcLogin, type OidcLoginConfig } from './oidc-login';
export { handleOidcCallback, type OidcCallbackConfig } from './oidc-callback';
export { handleHeartbeat, type HeartbeatHandlerConfig } from './heartbeat-handler';
