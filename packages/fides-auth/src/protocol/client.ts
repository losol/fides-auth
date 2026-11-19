// The OIDC client. One object holds the config, its discovery
// cache, its JWKS cache and its loggers, so two clients share no state.
// Creating one does no I/O: discovery runs on first use.

import type { JWTPayload } from 'jose';
import type * as openid from 'openid-client';

import { consoleLoggerFactory, type FidesLoggerFactory } from '../shared/logger.js';
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
import { checkProfile, profileAlgorithms } from './fapi-profile.js';
import { createJwksCache, verifyIdTokenWith } from './id-token.js';
import { type LogoutToken, verifyLogoutTokenWith } from './logout-token.js';
import { createDpopKey, type DpopKey } from './dpop.js';
import { withoutResponseBody } from './logging.js';
import { logoutUrl, type OidcLogoutOptions } from './logout-url.js';
import { refresh } from './refresh.js';
import { revoke, type RevokeOptions } from './revocation.js';
import { userInfo, type UserInfoOptions } from './userinfo.js';

/** Options for {@link createOidcClient}. */
export interface OidcClientOptions {
  /** Creates the client's loggers. Defaults to JSON lines on the console. */
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

/** Options for the calls that can bind tokens with DPoP. */
export interface DpopOptions {
  /**
   * The key to bind the tokens to, from {@link OidcClient.createDpopKey}. The
   * request then carries a DPoP proof, and a token response that isn't bound
   * (`token_type` other than `DPoP`) throws a `DpopError`.
   */
  dpopKey?: DpopKey;
}

/** Options for {@link OidcClient.verifyIdToken}. */
export interface VerifyOptions {
  /**
   * Accepted `alg` values. Defaults to `RS*`, `PS*`, `ES*` and `EdDSA`. With
   * `profile: 'fapi2'` the default is `PS256`, `ES256` and `EdDSA`, and any
   * other value throws a TypeError.
   */
  algorithms?: string[];
}

/** An OIDC relying party for one provider and client. Create it with {@link createOidcClient}. */
export interface OidcClient {
  /** The provider's metadata, from discovery or `serverMetadata`. Cached on the client. */
  metadata(): Promise<openid.ServerMetadata>;

  /**
   * Creates the PKCE pair, state, nonce and parameters for one login. Keep the
   * result on the server until the callback.
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
   * Exchanges the code on the callback URL for tokens. Checks `state`, PKCE
   * and the ID token's `nonce` against the request the login started with.
   * Pass the request as `createAuthorizationRequest` returned it: when it has
   * a `nonce` and the exchange isn't given it, the ID token is refused.
   *
   * @throws TypeError if the config has no `redirectUri`.
   */
  exchangeCode(
    callbackUrl: URL,
    request: Pick<AuthorizationRequest, 'codeVerifier' | 'state' | 'nonce'>,
    options?: DpopOptions,
  ): Promise<openid.TokenEndpointResponse>;

  /**
   * Runs a refresh token grant. Sends no `scope`, so the granted scope is
   * kept. For tokens bound with DPoP, pass the key they are bound to.
   */
  refresh(refreshToken: string, options?: DpopOptions): Promise<openid.TokenEndpointResponse>;

  /**
   * Creates a key to bind one login's tokens to with DPoP (RFC 9449). Pass it
   * to {@link exchangeCode}, keep it with the tokens, and pass it again to
   * {@link refresh} and `userInfo`. `createDpopProof` makes the proof a
   * request to an API needs.
   */
  createDpopKey(): Promise<DpopKey>;

  /**
   * Runs a client credentials grant with this client's credentials.
   *
   * @throws TypeError if the client is public (`clientAuth: 'none'`).
   */
  clientCredentials(options?: ClientCredentialsOptions): Promise<openid.TokenEndpointResponse>;

  /** An RP-initiated logout URL, or null when the provider has no end-session endpoint. */
  logoutUrl(options?: OidcLogoutOptions): Promise<URL | null>;

  /**
   * Asks the provider to revoke a token (RFC 7009). Whether that also ends the
   * other tokens of the same grant is up to the provider.
   *
   * @returns false when the provider has no revocation endpoint, so nothing was sent.
   */
  revoke(token: string, options?: RevokeOptions): Promise<boolean>;

  /**
   * Verifies an ID token's signature, `iss`, `aud` and `exp`. The issuer comes
   * from the metadata and the audience is the client ID. The JWKS is cached on
   * the client.
   *
   * @returns The verified claims.
   * @throws A jose error if the token is invalid, or a TypeError if the metadata has no `issuer` or `jwks_uri`.
   */
  verifyIdToken(idToken: string, options?: VerifyOptions): Promise<JWTPayload>;

  /**
   * Verifies a logout token, the JWT a provider posts to end a user's sessions
   * (OpenID Connect Back-Channel Logout 1.0 §2.6): its signature, `iss`, `aud`
   * and `exp` as for an ID token, that it has a `sub` or a `sid`, an `events`
   * claim with the back-channel logout member, and no `nonce`. The same token
   * verifies again until it expires: the `jti` is returned, not remembered.
   *
   * @returns Whose sessions to end.
   * @throws A `LogoutTokenError` if the token is refused, or a TypeError if the metadata has no `issuer` or `jwks_uri`.
   */
  verifyLogoutToken(logoutToken: string, options?: VerifyOptions): Promise<LogoutToken>;

  /**
   * Gets the claims from the provider's UserInfo endpoint for the user an
   * access token belongs to. `expectedSubject` is the ID token's `sub`. Use it
   * for claims a provider only gives there.
   *
   * @throws A `ClientError` if the metadata has no `userinfo_endpoint` or the response's `sub` is not `expectedSubject`, or what else openid-client throws when the request fails.
   */
  userInfo(accessToken: string, options: UserInfoOptions): Promise<openid.UserInfoResponse>;
}

/**
 * Creates an OIDC client. It does no I/O until a method needs the provider.
 *
 * @throws TypeError if `discoveryTtlMs` is not a finite, non-negative number, or if the config doesn't meet its `profile`.
 */
export function createOidcClient(
  config: OidcClientConfig,
  options: OidcClientOptions = {},
): OidcClient {
  checkProfile(config);
  const loggers = options.logger ?? consoleLoggerFactory;
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

  /** Runs a call to the provider. What it throws leaves without the provider's response. */
  const calling = async <T>(call: () => Promise<T>): Promise<T> => {
    try {
      return await call();
    } catch (error) {
      throw withoutResponseBody(error);
    }
  };

  return {
    metadata,

    createAuthorizationRequest: (requestOptions) =>
      createAuthorizationRequest(context, requestOptions),

    authorizationUrl: (request) => calling(() => authorizationUrl(context, request.parameters)),

    silentLoginUrl: (request, silentOptions = {}) => {
      const parameters: Record<string, string> = { ...request.parameters, prompt: 'none' };
      if (silentOptions.loginHint) parameters.login_hint = silentOptions.loginHint;
      if (silentOptions.maxAge !== undefined) parameters.max_age = String(silentOptions.maxAge);
      return calling(() => authorizationUrl(context, parameters));
    },

    exchangeCode: (callbackUrl, request, exchangeOptions) =>
      calling(() =>
        exchangeCode(
          context,
          callbackUrl,
          request.codeVerifier,
          request.state,
          request.nonce,
          exchangeOptions?.dpopKey,
        ),
      ),

    refresh: (refreshToken, refreshOptions) =>
      calling(() =>
        refreshOptions?.dpopKey
          ? refresh(context, refreshToken, refreshOptions.dpopKey)
          : refresh(context, refreshToken),
      ),

    createDpopKey,

    clientCredentials: (grantOptions) => calling(() => clientCredentials(context, grantOptions)),

    logoutUrl: (logoutOptions = {}) => logoutUrl(context, logoutOptions),

    revoke: (token, revokeOptions) => calling(() => revoke(context, token, revokeOptions)),

    userInfo: (accessToken, userInfoOptions) =>
      calling(() => userInfo(context, accessToken, userInfoOptions)),

    async verifyIdToken(idToken, verifyOptions = {}) {
      const algorithms = profileAlgorithms(ownConfig, verifyOptions.algorithms);
      const { issuer, jwks_uri } = await metadata();
      if (!issuer) throw new TypeError('The provider metadata has no issuer');
      if (!jwks_uri) throw new TypeError('The provider metadata has no jwks_uri');
      return verifyIdTokenWith(jwks.get(jwks_uri), idToken, {
        issuer,
        audience: ownConfig.clientId,
        algorithms,
      });
    },

    async verifyLogoutToken(logoutToken, verifyOptions = {}) {
      const algorithms = profileAlgorithms(ownConfig, verifyOptions.algorithms);
      const { issuer, jwks_uri } = await metadata();
      if (!issuer) throw new TypeError('The provider metadata has no issuer');
      if (!jwks_uri) throw new TypeError('The provider metadata has no jwks_uri');
      return verifyLogoutTokenWith(jwks.get(jwks_uri), logoutToken, {
        issuer,
        audience: ownConfig.clientId,
        algorithms,
      });
    },
  };
}
