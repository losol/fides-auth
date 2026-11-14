// The `/oauth` entry, deprecated: an OIDC client from `/oidc` replaces its
// protocol functions. The code lives in one module per responsibility; this
// file re-exports the names `/oauth` has always had, and no others. Names
// that live on elsewhere are re-declared to carry the tag.

import type {
  Configuration as ConfigurationImpl,
  TokenEndpointResponse as TokenEndpointResponseImpl,
} from 'openid-client';

import type { AuthorizationRequestOptions as AuthorizationRequestOptionsImpl } from './protocol/authorization-parameters.js';
import type {
  ClientAuthConfig as ClientAuthConfigImpl,
  OAuthConfig as OAuthConfigImpl,
} from './protocol/config.js';
import type { OidcLogoutOptions as OidcLogoutOptionsImpl } from './protocol/logout-url.js';
import { defaultScope as defaultScopeImpl, joinScope as joinScopeImpl } from './protocol/scope.js';
import type { OidcUserInfo as OidcUserInfoImpl } from './session/user-claims.js';

// Deprecated where they are declared.
export type { ClientCredentialsConfig } from './protocol/config.js';
export { buildPKCEOptions, type PKCEOptions } from './protocol/authorization-parameters.js';
export {
  buildAuthorizationUrl,
  buildAuthorizationUrlWithPAR,
  discoverAndBuildAuthorizationUrl,
} from './protocol/authorization-url.js';
export { exchangeAuthorizationCode } from './protocol/code-exchange.js';
export { refreshAccessToken } from './protocol/refresh.js';
export { clientCredentialsGrant } from './protocol/client-credentials.js';
export { buildOidcLogoutUrl } from './protocol/logout-url.js';
export { extractUserFromTokens } from './session/user-claims.js';

// Not deprecated: createFidesAuth replaces them in 1.0.
export {
  buildSessionFromTokens,
  type BuildSessionOptions,
  type MapSession,
} from './session/build.js';
export { validateReturnUrl } from './server/return-to.js';

/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth` goes in 1.0. */
export const defaultScope = defaultScopeImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth` goes in 1.0. */
export const joinScope = joinScopeImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth` goes in 1.0. */
export type AuthorizationRequestOptions = AuthorizationRequestOptionsImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth` goes in 1.0. */
export type OidcLogoutOptions = OidcLogoutOptionsImpl;
/** @deprecated Import from `@eventuras/fides-auth/oidc`. `/oauth` goes in 1.0. */
export type OidcUserInfo = OidcUserInfoImpl;
/** @deprecated Import from `@eventuras/fides-auth`. `/oauth` goes in 1.0. */
export type OAuthConfig = OAuthConfigImpl;
/** @deprecated Import from `@eventuras/fides-auth`. `/oauth` goes in 1.0. */
export type ClientAuthConfig = ClientAuthConfigImpl;
/** @deprecated Import `TokenResponse` from `@eventuras/fides-auth`. `/oauth` goes in 1.0. */
export type TokenEndpointResponse = TokenEndpointResponseImpl;
/** @deprecated Import from `openid-client`, or use `oidc.metadata()`. `/oauth` goes in 1.0. */
export type Configuration = ConfigurationImpl;
