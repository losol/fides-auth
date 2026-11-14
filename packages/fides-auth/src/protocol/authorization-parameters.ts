import { redirectUriOf } from './config.js';
import type { ProtocolContext } from './context.js';
import { defaultScope, joinScope } from './scope.js';
import { createPkcePair, createState } from './pkce.js';

/** One login's authorization request, from `OidcClient.createAuthorizationRequest`. */
export interface AuthorizationRequest {
  /** PKCE verifier. Keep it on the server until the callback, where `exchangeCode` needs it. */
  codeVerifier: string;
  /** The S256 challenge of `codeVerifier`, already in `parameters`. */
  codeChallenge: string;
  /** Echoed back on the callback, where `exchangeCode` checks it. */
  state: string;
  /** The parameters sent to the authorization endpoint. */
  parameters: Record<string, string>;
}

/** Per-request options for `OidcClient.createAuthorizationRequest`. */
export interface AuthorizationRequestOptions {
  /** Extra authorization parameters, merged over the config's `authorizationParameters`. */
  parameters?: Record<string, string>;
}

/** Extra parameters can't set these. */
const RESERVED_AUTHORIZATION_PARAMETERS = new Set([
  // Set by createAuthorizationRequest
  'state',
  'code_challenge',
  'code_challenge_method',
  'redirect_uri',
  // openid-client fills these in only when absent
  'client_id',
  'response_type',
  // Would bypass the PKCE and state parameters above
  'request',
  'request_uri',
  // The callback expects no nonce, so an ID token carrying one fails the login
  'nonce',
]);

/**
 * Creates a PKCE pair, a state and the authorization parameters for one login.
 * The core of `OidcClient.createAuthorizationRequest`.
 *
 * @throws TypeError if the config has no redirect URI.
 * @throws Error if an extra parameter is a reserved key.
 */
export async function createAuthorizationRequest(
  { config, logger }: ProtocolContext,
  options: AuthorizationRequestOptions = {},
): Promise<AuthorizationRequest> {
  const redirectUri = redirectUriOf(config);
  const extra = { ...config.authorizationParameters, ...options.parameters };
  const reserved = Object.keys(extra).filter((key) => RESERVED_AUTHORIZATION_PARAMETERS.has(key));
  if (reserved.length > 0) {
    throw new Error(`Reserved authorization parameters can't be overridden: ${reserved.join(', ')}`);
  }

  const { verifier: codeVerifier, challenge: codeChallenge } = await createPkcePair();
  const state = createState();

  const parameters: Record<string, string> = {
    redirect_uri: redirectUri,
    scope: joinScope(config.scope ?? defaultScope),
    ...extra,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  };

  // Keys only: values such as login_hint can be personal data.
  logger.debug(
    { redirectUri, scope: parameters.scope, extraParameters: Object.keys(extra) },
    'PKCE parameters generated'
  );

  return { codeVerifier, codeChallenge, state, parameters };
}
