// The OIDC client (ADR 0001 §3). One object holds the config, its discovery
// cache, its JWKS cache and its loggers, so two clients share no state.
// Creating one does no I/O: discovery runs on first use.

import type { JWTPayload } from 'jose';
import type * as openid from 'openid-client';

import { createLogger, type FidesLoggerFactory } from '../shared/logger.js';
import {
  createAuthorizationRequest,
  type AuthorizationRequest,
  type AuthorizationRequestOptions,
} from './authorization-parameters.js';
import { authorizationUrl } from './authorization-url.js';
import { clientCredentials, type ClientCredentialsOptions } from './client-credentials.js';
import { exchangeCode } from './code-exchange.js';
import type { OidcClientConfig } from './config.js';
import type { ProtocolContext } from './context.js';
import { checkTtl, createDiscoveryCache } from './discovery.js';
import { createJwksCache, verifyIdTokenWith } from './id-token.js';
import { logoutUrl, type OidcLogoutOptions } from './logout-url.js';
import { refresh } from './refresh.js';

/** Options for {@link createOidcClient}. */
export interface OidcClientOptions {
  /**
   * Creates the client's loggers. Defaults to the factory set with
   * `configureLogger`, which writes JSON lines to the console unless changed.
   */
  logger?: FidesLoggerFactory;
  /**
   * How long discovered metadata is reused, in milliseconds. `0` discovers on
   * every call.
   * @default 300_000 (5 minutes)
   */
  discoveryTtlMs?: number;
}

/** Options for {@link OidcClient.silentLoginUrl}. */
export interface SilentLoginUrlOptions {
  /** Sent as `login_hint`. */
  loginHint?: string;
  /** Sent as `max_age`: the most seconds since the user last authenticated. */
  maxAge?: number;
}

/** Options for {@link OidcClient.verifyIdToken}. */
export interface VerifyOptions {
  /** Accepted `alg` values. Defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. */
  algorithms?: string[];
}

/** An OIDC relying party for one provider and client. Create it with {@link createOidcClient}. */
export interface OidcClient {
  /** The provider's metadata, from discovery or `serverMetadata`. Cached on the client. */
  metadata(): Promise<openid.ServerMetadata>;

  /**
   * Creates the PKCE pair, state and parameters for one login. Keep the result
   * on the server until the callback.
   *
   * @throws TypeError if the config has no `redirectUri`.
   */
  createAuthorizationRequest(options?: AuthorizationRequestOptions): Promise<AuthorizationRequest>;

  /** The URL to send the browser to. Goes through PAR when `usePar` is set. */
  authorizationUrl(request: AuthorizationRequest): Promise<URL>;

  /**
   * Like {@link authorizationUrl}, with `prompt=none`: the provider answers
   * without showing a page, with a code or with an error such as `login_required`.
   * Check the callback with `checkSilentLoginResult`, then call {@link exchangeCode}.
   */
  silentLoginUrl(request: AuthorizationRequest, options?: SilentLoginUrlOptions): Promise<URL>;

  /**
   * Exchanges the code on the callback URL for tokens. Checks `state` and PKCE
   * against the request the login started with.
   *
   * @throws TypeError if the config has no `redirectUri`.
   */
  exchangeCode(
    callbackUrl: URL,
    request: Pick<AuthorizationRequest, 'codeVerifier' | 'state'>,
  ): Promise<openid.TokenEndpointResponse>;

  /** Runs a refresh token grant. */
  refresh(refreshToken: string): Promise<openid.TokenEndpointResponse>;

  /**
   * Runs a client credentials grant with this client's credentials.
   *
   * @throws TypeError if the client is public (`clientAuth: 'none'`).
   */
  clientCredentials(options?: ClientCredentialsOptions): Promise<openid.TokenEndpointResponse>;

  /** An RP-initiated logout URL, or null when the provider has no end-session endpoint. */
  logoutUrl(options?: OidcLogoutOptions): Promise<URL | null>;

  /**
   * Verifies an ID token's signature, `iss`, `aud` and `exp`. The issuer comes
   * from the metadata and the audience is the client ID. The JWKS is cached on
   * the client.
   *
   * @returns The verified claims.
   * @throws A jose error if the token is invalid, or a TypeError if the metadata has no `issuer` or `jwks_uri`.
   */
  verifyIdToken(idToken: string, options?: VerifyOptions): Promise<JWTPayload>;
}

/** The loggers `configureLogger` controls. The default until 1.0 removes `configureLogger`. */
const configuredLoggers: FidesLoggerFactory = { create: (options) => createLogger(options) };

/**
 * Creates an OIDC client. It does no I/O until a method needs the provider.
 *
 * @throws TypeError if `discoveryTtlMs` is not a finite, non-negative number.
 */
export function createOidcClient(
  config: OidcClientConfig,
  options: OidcClientOptions = {},
): OidcClient {
  const loggers = options.logger ?? configuredLoggers;
  const ttlMs =
    options.discoveryTtlMs === undefined
      ? undefined
      : checkTtl(options.discoveryTtlMs, 'createOidcClient: discoveryTtlMs');

  // A copy, so changing the caller's object later doesn't change a live client.
  const ownConfig = { ...config } as OidcClientConfig;
  const discovery = createDiscoveryCache(
    loggers.create({ namespace: 'fides-auth:oidc-discovery' }),
    ttlMs,
  );
  const jwks = createJwksCache();
  const context: ProtocolContext = {
    config: ownConfig,
    configuration: () => discovery.discover(ownConfig),
    logger: loggers.create({ namespace: 'fides-auth:oauth' }),
  };

  const metadata = async () => (await context.configuration()).serverMetadata();

  return {
    metadata,

    createAuthorizationRequest: (requestOptions) =>
      createAuthorizationRequest(context, requestOptions),

    authorizationUrl: (request) => authorizationUrl(context, request.parameters),

    silentLoginUrl: (request, silentOptions = {}) => {
      const parameters: Record<string, string> = { ...request.parameters, prompt: 'none' };
      if (silentOptions.loginHint) parameters.login_hint = silentOptions.loginHint;
      if (silentOptions.maxAge !== undefined) parameters.max_age = String(silentOptions.maxAge);
      return authorizationUrl(context, parameters);
    },

    exchangeCode: (callbackUrl, request) =>
      exchangeCode(context, callbackUrl, request.codeVerifier, request.state),

    refresh: (refreshToken) => refresh(context, refreshToken),

    clientCredentials: (grantOptions) => clientCredentials(context, grantOptions),

    logoutUrl: (logoutOptions = {}) => logoutUrl(context, logoutOptions),

    async verifyIdToken(idToken, verifyOptions = {}) {
      const { issuer, jwks_uri } = await metadata();
      if (!issuer) throw new TypeError('The provider metadata has no issuer');
      if (!jwks_uri) throw new TypeError('The provider metadata has no jwks_uri');
      return verifyIdTokenWith(jwks.get(jwks_uri), idToken, {
        issuer,
        audience: ownConfig.clientId,
        algorithms: verifyOptions.algorithms,
      });
    },
  };
}
