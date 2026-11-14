// The `/oidc` entry: the OIDC client and the protocol's pure helpers (ADR 0001 §3).
// It loads nothing from server/; a lint rule keeps it that way.

export {
  createOidcClient,
  type OidcClient,
  type OidcClientOptions,
  type SilentLoginUrlOptions,
  type VerifyOptions,
} from './protocol/client.js';
export type { OidcClientConfig } from './protocol/config.js';
export type {
  AuthorizationRequest,
  AuthorizationRequestOptions,
} from './protocol/authorization-parameters.js';
export type { ClientCredentialsOptions } from './protocol/client-credentials.js';
export type { OidcLogoutOptions } from './protocol/logout-url.js';

export { createPkcePair, createState, type PkcePair } from './protocol/pkce.js';
export { defaultScope, joinScope } from './protocol/scope.js';
export { userFromClaims, type OidcUserInfo } from './session/user-claims.js';
export {
  checkSilentLoginResult,
  requiresInteractiveLogin,
  type SilentLoginResult,
} from './protocol/silent-login.js';
export { classifyRefreshFailure, getOAuthErrorLogContext } from './protocol/logging.js';
