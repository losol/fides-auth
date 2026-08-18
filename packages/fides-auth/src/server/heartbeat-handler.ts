// server/heartbeat-handler.ts
//
// Framework-agnostic heartbeat endpoint. Pairs with the client-side heartbeat:
// when the user is active the client POSTs here, and this handler exchanges the
// current refresh token for a fresh access token. Glue only — rate limit, load
// session, refresh, respond — over the standard Request/Response and a CookieStore.

import { createLogger } from '../logger';
import type { OAuthConfig } from '../oauth';
import { SESSION_EVENT, logSessionEvent, type SessionRejectedReason } from '../session-events';
import { getSessionSecret } from '../utils';
import type { CookieStore } from './cookie-store';
import { tryRefreshSessionInStore } from './session';

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
 * Returns 200 with `{ accessTokenExpiresAt }` on success, 401 with `{ reason }`
 * when the session is genuinely over, 503 when the provider could not be
 * reached, 405 for non-POST methods, and 429 when rate-limited.
 *
 * The 401/503 split matters: a 401 tells the client to log the user out, so it
 * must be reserved for the cases where the session really is finished. A network
 * blip or a provider 5xx says nothing about the session's validity — answering
 * 401 there logs out users whose sessions were fine, which is precisely the
 * "logged out every few minutes" symptom. The client already retries non-401
 * failures with backoff.
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

  // An expired access token is what the heartbeat recovers from, not 401 on.
  // tryRefreshSessionInStore reads the session, refreshes it, and reports which
  // of the two it failed at — so this handler never has to re-read cookies to
  // work out why.
  const result = await tryRefreshSessionInStore(cookies, oauthConfig, secret);

  if (result.ok) {
    logger.debug({ sid: result.session.sid }, 'Heartbeat refresh succeeded');
    return Response.json(
      { accessTokenExpiresAt: result.session.tokens?.accessTokenExpiresAt ?? null },
      {
        // Auth/session endpoint — must never be cached by the browser or any
        // intermediary, or a stale 200 could fool the client into thinking a refresh
        // succeeded without actually hitting the server.
        headers: { 'Cache-Control': 'private, no-store' },
      },
    );
  }

  // The provider was unreachable or broken. The session is probably still fine,
  // so keep it and let the client retry rather than ending it.
  if (result.cause === 'transport' || result.cause === 'idp_error') {
    logger.warn(
      { sid: result.sid, cause: result.cause },
      'Heartbeat refresh could not be completed — keeping the session',
    );
    return new Response(null, { status: 503, headers: { 'Cache-Control': 'private, no-store' } });
  }

  // Everything left is a session that genuinely cannot continue.
  logSessionEvent(logger, {
    event: SESSION_EVENT.REJECTED,
    sid: result.sid,
    reason: result.reason,
    source: 'heartbeat',
  });

  return unauthorized(result.reason);
}

/**
 * 401 carrying the reason in the body.
 *
 * The browser is where the logout becomes visible, so letting the client name
 * the reason lets a consumer beacon it back with the same vocabulary the server
 * used. The values are session state, not secrets — and clients that ignore the
 * body are unaffected.
 */
function unauthorized(reason: SessionRejectedReason): Response {
  return Response.json(
    { reason },
    { status: 401, headers: { 'Cache-Control': 'private, no-store' } },
  );
}
