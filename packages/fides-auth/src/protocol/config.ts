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
  /** Space-separated string or an array of scopes. */
  scope: string | string[];
  /**
   * Extra authorization request parameters (e.g. `prompt`, `resource`), added by `createAuthorizationRequest`.
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
  /**
   * Allows plain http to the provider, for one on a loopback address in
   * development or CI: `localhost`, a `*.localhost` name, `127.0.0.0/8` or
   * `[::1]`. The issuer and every endpoint in its metadata must be https or
   * loopback, or the first call to the provider throws a TypeError. Without it,
   * any http URL throws.
   * @default false
   */
  allowInsecureRequests?: boolean;
};

/**
 * The redirect URI, for an operation that needs one.
 *
 * @throws TypeError if `redirectUri` is not set.
 */
export function redirectUriOf(config: OidcClientConfig): string {
  if (!config.redirectUri) throw new TypeError('This operation needs redirectUri in the OIDC config');
  return config.redirectUri;
}
