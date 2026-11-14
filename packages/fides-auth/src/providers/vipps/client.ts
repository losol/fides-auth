/**
 * Vipps Login Client
 *
 * Client for Vipps Login (OIDC) authentication flow, built on an OIDC client
 * from `createOidcClient`. It adds the Vipps defaults and the userinfo call,
 * which needs Vipps' own headers.
 */

import type * as openid from 'openid-client';

import { consoleLoggerFactory, type FidesLogger } from '../../shared/logger.js';
import type {
  AuthorizationRequest,
  AuthorizationRequestOptions,
} from '../../protocol/authorization-parameters.js';
import { createOidcClient, type OidcClient, type OidcClientOptions } from '../../protocol/client.js';
import { defaultVippsLoginScope, type VippsLoginConfig, type VippsUserInfo } from './types.js';

/** Options for {@link VippsLoginClient}: the same as for `createOidcClient`. */
export type VippsLoginClientOptions = OidcClientOptions;

/**
 * Vipps Login Client
 *
 * Handles Vipps Login (OIDC) authentication flow using PKCE.
 */
export class VippsLoginClient {
  /** The OIDC client underneath, for the protocol calls this class doesn't wrap. */
  readonly oidc: OidcClient;
  private readonly config: VippsLoginConfig;
  private readonly logger: FidesLogger;

  constructor(config: VippsLoginConfig, options: VippsLoginClientOptions = {}) {
    this.config = { ...config };
    this.logger = (options.logger ?? consoleLoggerFactory).create({ namespace: 'fides-auth:vipps' });
    this.oidc = createOidcClient(
      {
        issuer: config.issuer,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: config.redirectUri,
        scope: config.scope ?? defaultVippsLoginScope,
      },
      options,
    );
  }

  /**
   * Creates the PKCE pair, state and parameters for one login. Keep the result
   * on the server until the callback.
   */
  createAuthorizationRequest(options?: AuthorizationRequestOptions): Promise<AuthorizationRequest> {
    return this.oidc.createAuthorizationRequest(options);
  }

  /** The Vipps login URL to send the browser to. */
  authorizationUrl(request: AuthorizationRequest): Promise<URL> {
    return this.oidc.authorizationUrl(request);
  }

  /**
   * Exchanges the code on the callback URL for tokens. Checks `state` and PKCE
   * against the request the login started with.
   */
  exchangeCode(
    callbackUrl: URL,
    request: Pick<AuthorizationRequest, 'codeVerifier' | 'state'>,
  ): Promise<openid.TokenEndpointResponse> {
    return this.oidc.exchangeCode(callbackUrl, request);
  }

  /** Runs a refresh token grant. */
  refresh(refreshToken: string): Promise<openid.TokenEndpointResponse> {
    return this.oidc.refresh(refreshToken);
  }

  /**
   * Gets the user from the Vipps userinfo endpoint. Sends the subscription key
   * and merchant serial number when they are configured.
   *
   * @param accessToken - Access token from the code exchange
   * @throws Error if the provider has no userinfo endpoint, or answers with a non-2xx status.
   */
  async getUserInfo(accessToken: string): Promise<VippsUserInfo> {
    const userinfoUrl = (await this.oidc.metadata()).userinfo_endpoint;
    if (!userinfoUrl) {
      throw new Error('Userinfo endpoint not found in OpenID configuration');
    }

    const response = await fetch(userinfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(this.config.subscriptionKey && {
          'Ocp-Apim-Subscription-Key': this.config.subscriptionKey,
        }),
        ...(this.config.merchantSerialNumber && {
          'Merchant-Serial-Number': this.config.merchantSerialNumber,
        }),
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      this.logger.error({ status: response.status }, 'Failed to fetch user info');
      throw new Error(`Failed to fetch user info: ${response.status} - ${errorText}`);
    }

    const userInfo = (await response.json()) as VippsUserInfo;
    this.logger.debug(
      {
        hasEmail: !!userInfo.email,
        hasPhone: !!userInfo.phone_number,
        hasAddress: !!userInfo.addresses?.length,
      },
      'Fetched user info',
    );
    return userInfo;
  }
}
