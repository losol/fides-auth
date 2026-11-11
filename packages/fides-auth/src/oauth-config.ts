// Config types shared by the OAuth modules. Keep this a leaf: no imports from this package.

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

/** Configuration for server-side OAuth / OIDC flows. */
export type OAuthConfig = ClientAuthConfig & {
  issuer: string;
  clientId: string;
  redirect_uri: string;
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
