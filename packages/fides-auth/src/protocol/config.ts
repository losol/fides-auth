// Config types for the protocol layer, and the redirect URI helper. Keep this a leaf: no imports from this package.

import type * as openid from 'openid-client';

/**
 * How the client authenticates at the token endpoint. Omit `clientAuth` to use
 * `client_secret_post`.
 */
export type ClientAuthConfig =
  | {
      /** @default 'client_secret_post' */
      clientAuth?: 'client_secret_post' | 'client_secret_basic';
      clientSecret: string;
    }
  | {
      /** Public client: sends only `client_id`. Pair it with PKCE. */
      clientAuth: 'none';
    }
  | {
      clientAuth: 'private_key_jwt';
      /** Signs the client assertion. Reuse one key object: a new one means a new cache entry. */
      privateKey: openid.CryptoKey | openid.PrivateKey;
    };

/**
 * Configuration for `createOidcClient`. `redirectUri` is checked when an
 * operation needs it, so a client used only for client credentials needs none.
 */
export type OidcClientConfig = ClientAuthConfig & {
  issuer: string;
  clientId: string;
  /** The callback URL registered with the provider. */
  redirectUri?: string;
  /** The older spelling of `redirectUri`. Set one, or both to the same value. */
  redirect_uri?: string;
  /** Space-separated string or an array of scopes. */
  scope: string | string[];
  /**
   * Extra authorization request parameters (e.g. `prompt`, `resource`), added by `buildPKCEOptions`.
   * Reserved keys throw: `state`, `code_challenge`, `code_challenge_method`, `redirect_uri`,
   * `client_id`, `response_type`, `request`, `request_uri` and `nonce`.
   */
  authorizationParameters?: Record<string, string>;
  /**
   * Opt in to Pushed Authorization Requests (RFC 9126) when the provider
   * supports it. When true, authorization parameters are posted to the
   * provider's PAR endpoint ahead of the redirect, and only `client_id` +
   * `request_uri` travel through the user-agent. The provider must advertise
   * `pushed_authorization_request_endpoint` in its discovery metadata.
   */
  usePar?: boolean;
  /**
   * Server metadata to use instead of OIDC discovery, e.g. an RFC 8414 document.
   * Must include `issuer` when `scope` has `openid`. `issuer` above is then used
   * only for logs and caching.
   */
  serverMetadata?: openid.ServerMetadata;
};

/**
 * Configuration for server-side OAuth / OIDC flows. Takes `redirectUri` too,
 * but `redirect_uri` stays required, so code that reads it still compiles.
 */
export type OAuthConfig = OidcClientConfig & { redirect_uri: string };

/**
 * The redirect URI from either spelling.
 *
 * @throws TypeError if neither is set, or if both are set to different values.
 */
export function redirectUriOf(config: OidcClientConfig): string {
  const { redirectUri, redirect_uri } = config;
  if (redirectUri !== undefined && redirect_uri !== undefined && redirectUri !== redirect_uri) {
    throw new TypeError('redirectUri and redirect_uri differ; set one of them');
  }
  const uri = redirectUri ?? redirect_uri;
  if (!uri) throw new TypeError('This operation needs redirectUri in the OIDC config');
  return uri;
}

/**
 * Configuration for OAuth client credentials flow (machine-to-machine authentication).
 * Takes any {@link ClientAuthConfig} except `none`: the grant needs client authentication.
 */
export type ClientCredentialsConfig = Exclude<ClientAuthConfig, { clientAuth: 'none' }> & {
  /** OAuth token endpoint URL. Must be https. */
  tokenEndpoint: string;
  /** OAuth client ID */
  clientId: string;
  /** Optional scope for the access token */
  scope?: string;
  /**
   * Issuer identifier; defaults to the token endpoint's origin. With
   * `private_key_jwt` it is the client assertion's `aud`, so set it to what the server expects.
   */
  issuer?: string;
  /**
   * Request timeout in seconds.
   * @default 30
   */
  timeout?: number;
};
