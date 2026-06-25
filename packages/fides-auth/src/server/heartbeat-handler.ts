// server/heartbeat-handler.ts
//
// Framework-agnostic heartbeat endpoint. Pairs with the client-side heartbeat:
// when the user is active the client POSTs here, and this handler exchanges the
// current refresh token for a fresh access token. Glue only — rate limit, load
// session, refresh, respond — over the standard Request/Response and a CookieStore.

import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import { getSessionSecret } from '../utils';
import type { CookieStore } from './cookie-store';
import { readSession, refreshSessionInStore } from './session';

const logger = createLogger({ namespace: 'fides-auth:server:heartbeat' });

export interface HeartbeatHandlerConfig {
  /** OAuth/OIDC configuration used to refresh the access token. */
  oauthConfig: OAuthConfig;

  /** Cookie store holding the session. */
  cookies: CookieStore;

  /** Optional rate-limit gate. When it resolves false, the handler responds 429. */
  rateLimit?: () => boolean | Promise<boolean>;

  /** Session encryption secret. Defaults to {@link getSessionSecret}. */
  secret?: string | Uint8Array;
}

/**
 * Handles a heartbeat request — refresh the active session if there is one.
 *
 * Returns 200 with `{ accessTokenExpiresAt }` on success, 401 when there is no
 * session or the refresh token is dead, 405 for non-POST methods, and 429 when
 * rate-limited.
 */
export async function handleHeartbeat(
  request: Request,
  config: HeartbeatHandlerConfig,
): Promise<Response> {
  const { oauthConfig, cookies, rateLimit, secret = getSessionSecret() } = config;

  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { Allow: 'POST' } });
  }

  if (rateLimit && !(await rateLimit())) {
    logger.warn('Heartbeat rate limit exceeded');
    return new Response(null, { status: 429 });
  }

  const session = await readSession(cookies, secret);
  if (!session) {
    logger.debug('Heartbeat with no session');
    return new Response(null, { status: 401 });
  }

  if (!session.tokens?.refreshToken) {
    logger.warn('Heartbeat with session but no refresh token');
    return new Response(null, { status: 401 });
  }

  const updated = await refreshSessionInStore(cookies, oauthConfig, secret);
  if (!updated) {
    // Refresh failed — most likely invalid_grant (refresh token expired).
    logger.info('Heartbeat refresh failed');
    return new Response(null, { status: 401 });
  }

  logger.debug('Heartbeat refresh succeeded');
  return Response.json(
    { accessTokenExpiresAt: updated.tokens?.accessTokenExpiresAt ?? null },
    {
      // Auth/session endpoint — must never be cached by the browser or any
      // intermediary, or a stale 200 could fool the client into thinking a refresh
      // succeeded without actually hitting the server.
      headers: { 'Cache-Control': 'private, no-store' },
    },
  );
}
