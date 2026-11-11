// Next.js-specific bindings
export * from './cookie-store.js';
export * from './request.js';
export * from './auth.js';
export * from './cookies.js';
export * from './oidc-callback.js';
export * from './oidc-login.js';
export * from './oidc-logout.js';
export * from './heartbeat-handler.js';

// Authentication Store (XState Store)
export * from './store/index.js';

// Re-export all framework-agnostic utilities from @eventuras/fides-auth
export * from '@eventuras/fides-auth/oauth';
export type { OAuthConfig } from '@eventuras/fides-auth/oauth';
export * from '@eventuras/fides-auth/logger';
export * from '@eventuras/fides-auth/session-events';
export * from '@eventuras/fides-auth/session-refresh';
export * from '@eventuras/fides-auth/session-validation';
export * from '@eventuras/fides-auth/silent-login';
export * from '@eventuras/fides-auth/utils';
export * from '@eventuras/fides-auth/types';
export {
  /** @deprecated Only backs the deprecated default limiter. Use the handlers' `rateLimit` option. */
  TokenBucket,
} from '@eventuras/fides-auth/rate-limit';
