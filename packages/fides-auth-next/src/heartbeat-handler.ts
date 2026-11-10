/**
 * Server-side heartbeat handler for Next.js route handlers — a thin wrapper over
 * the framework-agnostic handler in `@eventuras/fides-auth/server`, wiring it to
 * the Next cookie store and the global POST rate limiter.
 *
 * Pairs with the client-side `useHeartbeat` hook: when the user is active, the
 * client POSTs here, and this handler exchanges the current refresh token for a
 * fresh access token (and rotated refresh token, if the IdP rotates).
 */

import {
  handleHeartbeat as coreHandleHeartbeat,
  type SessionSecret,
} from '@eventuras/fides-auth/server';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';

import { nextCookieStore } from './cookie-store';
import { globalPOSTRateLimit } from './request';

export interface HeartbeatHandlerConfig {
  /** OAuth/OIDC configuration used to refresh the access token. */
  oauthConfig: OAuthConfig;

  /** Session encryption secret. */
  secret: SessionSecret;
}

/**
 * Handles a heartbeat request in a Next.js route handler. `createFidesAuth`
 * returns this with `oauthConfig` and `secret` bound.
 *
 * @example
 * ```ts
 * // app/(auth)/api/auth/heartbeat/route.ts
 * import { handleHeartbeat } from '@eventuras/fides-auth-next/heartbeat-handler';
 * import { oauthConfig } from '@/utils/oauthConfig';
 *
 * export async function POST(request: Request) {
 *   return handleHeartbeat(request, { oauthConfig, secret: process.env.SESSION_SECRET! });
 * }
 * ```
 */
export async function handleHeartbeat(
  request: Request,
  config: HeartbeatHandlerConfig,
): Promise<Response> {
  return coreHandleHeartbeat(request, {
    oauthConfig: config.oauthConfig,
    secret: config.secret,
    cookies: await nextCookieStore(),
    rateLimit: globalPOSTRateLimit,
  });
}
