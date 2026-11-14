// The `/oauth` entry. The code lives in one module per responsibility; this file
// re-exports the names `/oauth` has always had, and no others.

export type { Configuration, TokenEndpointResponse } from 'openid-client';

export type { ClientAuthConfig, ClientCredentialsConfig, OAuthConfig } from './protocol/config.js';
export { defaultScope, joinScope } from './protocol/scope.js';
export {
  buildPKCEOptions,
  type AuthorizationRequestOptions,
  type PKCEOptions,
} from './protocol/authorization-parameters.js';
export {
  buildAuthorizationUrl,
  buildAuthorizationUrlWithPAR,
  discoverAndBuildAuthorizationUrl,
} from './protocol/authorization-url.js';
export { exchangeAuthorizationCode } from './protocol/code-exchange.js';
export { refreshAccessToken } from './protocol/refresh.js';
export { clientCredentialsGrant } from './protocol/client-credentials.js';
export { buildOidcLogoutUrl, type OidcLogoutOptions } from './protocol/logout-url.js';
export { extractUserFromTokens, type OidcUserInfo } from './session/user-claims.js';
export {
  buildSessionFromTokens,
  type BuildSessionOptions,
  type MapSession,
} from './session/build.js';
export { validateReturnUrl } from './server/return-to.js';
