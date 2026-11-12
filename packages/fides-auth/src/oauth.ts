// The `/oauth` entry. The code lives in one module per responsibility; this file
// re-exports the names `/oauth` has always had, and no others.

export type { Configuration, TokenEndpointResponse } from 'openid-client';

export type { ClientAuthConfig, ClientCredentialsConfig, OAuthConfig } from './oauth-config.js';
export { defaultScope, joinScope } from './oauth-scope.js';
export {
  buildPKCEOptions,
  type AuthorizationRequestOptions,
  type PKCEOptions,
} from './oauth-authorization-parameters.js';
export {
  buildAuthorizationUrl,
  buildAuthorizationUrlWithPAR,
  discoverAndBuildAuthorizationUrl,
} from './oauth-authorization-url.js';
export { exchangeAuthorizationCode } from './oauth-code-exchange.js';
export { refreshAccessToken } from './oauth-refresh.js';
export { clientCredentialsGrant } from './oauth-client-credentials.js';
export { buildOidcLogoutUrl, type OidcLogoutOptions } from './oauth-logout-url.js';
export { extractUserFromTokens, type OidcUserInfo } from './oauth-user-claims.js';
export {
  buildSessionFromTokens,
  type BuildSessionOptions,
  type MapSession,
} from './session-from-tokens.js';
export { validateReturnUrl } from './server/return-to.js';
