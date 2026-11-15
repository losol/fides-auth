import * as openid from 'openid-client';

import type { ProtocolContext } from './context.js';
import { isLoopback } from './discovery.js';

/** Parameters for an RP-initiated logout request (OIDC RP-Initiated Logout 1.0 §2). */
export interface OidcLogoutOptions {
  /** Post-logout redirect URI. Must be registered with the provider. */
  postLogoutRedirectUri?: string;

  /**
   * Raw ID token from `session.tokens.idToken`, sent as `id_token_hint`. Tells the
   * OP which session to end, and is usually what lets it skip the confirmation
   * interstitial.
   */
  idTokenHint?: string;

  /** Opaque value echoed back on the post-logout redirect. */
  state?: string;

  /** `logout_hint`, when the provider documents one. */
  logoutHint?: string;

  /**
   * Whether to send `client_id`. Default true, also alongside `id_token_hint`: the
   * spec allows both (the OP must then verify they match), and `client_id` is often
   * what lets the OP accept `post_logout_redirect_uri` when the hint is stale or
   * absent. Set false only for a provider that documents rejecting the combination.
   */
  includeClientId?: boolean;
}

/**
 * Builds an RP-initiated logout URL, or null when the provider has no end-session endpoint.
 * The core of `OidcClient.logoutUrl`.
 */
export async function logoutUrl(
  { config: oauthConfig, configuration, logger }: ProtocolContext,
  options: OidcLogoutOptions,
): Promise<URL | null> {
  const { postLogoutRedirectUri, idTokenHint, state, logoutHint, includeClientId = true } = options;

  try {
    const config = await configuration();
    const endSessionEndpoint = config.serverMetadata().end_session_endpoint;

    if (!endSessionEndpoint) {
      logger.info({ issuer: oauthConfig.issuer }, 'No end_session_endpoint found');
      return null;
    }

    const parameters: Record<string, string> = {};
    if (postLogoutRedirectUri) parameters.post_logout_redirect_uri = postLogoutRedirectUri;
    if (idTokenHint) parameters.id_token_hint = idTokenHint;
    if (state) parameters.state = state;
    if (logoutHint) parameters.logout_hint = logoutHint;

    // buildEndSessionUrl always adds client_id, and deleting it afterwards would
    // also drop one the provider baked into its own endpoint — so when it isn't
    // wanted, assemble the URL directly instead.
    let logoutUrl: URL;
    if (includeClientId) {
      logoutUrl = openid.buildEndSessionUrl(config, parameters);
    } else {
      logoutUrl = new URL(endSessionEndpoint);

      // openid-client rejects a non-https endpoint on the path above; the manual
      // one must too. The URL carries a raw id_token_hint, so a discovery document
      // that downgrades the scheme would put it on the wire in the clear.
      const allowedHttp = oauthConfig.allowInsecureRequests === true && isLoopback(logoutUrl);
      if (logoutUrl.protocol !== 'https:' && !allowedHttp) {
        logger.error(
          { issuer: oauthConfig.issuer, protocol: logoutUrl.protocol },
          'end_session_endpoint is not https — refusing to build a logout URL',
        );
        return null;
      }

      for (const [key, value] of Object.entries(parameters)) {
        logoutUrl.searchParams.append(key, value);
      }
    }

    logger.debug(
      { endSessionEndpoint, hasIdTokenHint: !!idTokenHint, hasState: !!state },
      'Built OIDC logout URL',
    );
    return logoutUrl;
  } catch (error) {
    logger.warn({ error, issuer: oauthConfig.issuer }, 'OIDC discovery failed for logout');
    return null;
  }
}
