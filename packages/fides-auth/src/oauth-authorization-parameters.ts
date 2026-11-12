import { createLogger } from './logger.js';
import type { OAuthConfig } from './oauth-config.js';
import { defaultScope, joinScope } from './oauth-scope.js';
import { createPkcePair, createState } from './pkce.js';

const logger = createLogger({ namespace: 'fides-auth:oauth' });

/** PKCE parameters generated for an authorization request. */
export interface PKCEOptions {
  code_verifier: string;
  code_challenge: string;
  state: string;
  parameters: Record<string, string>;
}

/** Per-request options for {@link buildPKCEOptions}. */
export interface AuthorizationRequestOptions {
  /** Extra authorization parameters, merged over `OAuthConfig.authorizationParameters`. */
  parameters?: Record<string, string>;
}

/** Extra parameters can't set these. */
const RESERVED_AUTHORIZATION_PARAMETERS = new Set([
  // Set by buildPKCEOptions
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
 * Creates PKCE parameters for an OAuth flow.
 * For the verifier, challenge or state alone, use `createPkcePair` / `createState` from `/pkce`.
 * Adds `config.authorizationParameters` and `options.parameters`; a `scope` among them wins.
 *
 * @param config - OAuthConfig configuration including the redirect URI and scope.
 * @param options - Per-request extra parameters.
 * @returns A promise that resolves to an object containing:
 *  - code_verifier: The randomly generated PKCE code verifier.
 *  - code_challenge: The derived PKCE code challenge.
 *  - state: A random state to protect against CSRF.
 *  - parameters: A Record<string,string> with the assembled parameters.
 * @throws Error if an extra parameter is a reserved key (see `OAuthConfig.authorizationParameters`).
 */
export async function buildPKCEOptions(
  config: OAuthConfig,
  options: AuthorizationRequestOptions = {},
): Promise<PKCEOptions> {
  const extra = { ...config.authorizationParameters, ...options.parameters };
  const reserved = Object.keys(extra).filter((key) => RESERVED_AUTHORIZATION_PARAMETERS.has(key));
  if (reserved.length > 0) {
    throw new Error(`Reserved authorization parameters can't be overridden: ${reserved.join(', ')}`);
  }

  const { verifier: code_verifier, challenge: code_challenge } = await createPkcePair();
  const state = createState();

  const parameters: Record<string, string> = {
    redirect_uri: config.redirect_uri,
    scope: joinScope(config.scope ?? defaultScope),
    ...extra,
    code_challenge,
    code_challenge_method: 'S256',
    state,
  };

  // Keys only: values such as login_hint can be personal data.
  logger.debug(
    { redirectUri: config.redirect_uri, scope: parameters.scope, extraParameters: Object.keys(extra) },
    'PKCE parameters generated'
  );

  return { code_verifier, code_challenge, state, parameters };
}
