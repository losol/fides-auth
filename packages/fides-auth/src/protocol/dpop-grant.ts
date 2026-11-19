// dpop-grant.ts
//
// DPoP at the provider's own endpoints: openid-client makes the proofs there,
// and answers the provider's `DPoP-Nonce` by itself. This turns a session's
// key into the handle it wants, and checks that what came back is bound.

import * as openid from 'openid-client';

import type { DpopKey } from '../shared/types.js';
import { DpopError, importDpopKey } from './dpop.js';

/** openid-client's handle for `key`. One per call: it holds the nonce the provider gives during it. */
export async function dpopHandle(config: openid.Configuration, key: DpopKey): Promise<openid.DPoPHandle> {
  return openid.getDPoPHandle(config, await importDpopKey(key));
}

/**
 * Throws unless the token response is DPoP-bound. A provider that doesn't
 * support DPoP ignores the proof and answers with a bearer token, which
 * anyone who gets hold of it could use. Such tokens are not kept, so they are
 * revoked first, where the provider can: left alone they would stay good
 * until they expire, with nobody holding them.
 *
 * @throws DpopError
 */
export async function assertBound(
  config: openid.Configuration,
  tokens: openid.TokenEndpointResponse,
): Promise<void> {
  if (tokens.token_type === 'dpop') return;
  if (config.serverMetadata().revocation_endpoint) {
    // The refresh token takes the access token with it at most providers. Best effort.
    const unbound = tokens.refresh_token ?? tokens.access_token;
    try {
      await openid.tokenRevocation(config, unbound);
    } catch {
      // The tokens are refused either way; that they couldn't be revoked changes nothing here.
    }
  }
  throw new DpopError(
    `The provider answered with a "${tokens.token_type}" token where a DPoP-bound one was asked for`,
  );
}
