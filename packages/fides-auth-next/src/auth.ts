/**
 * createFidesAuth for Next.js. The core instance takes a CookieStore on every
 * call; this one gets it from `cookies()` in next/headers, caches session reads
 * per render, and adds refreshInProxy for `proxy.ts`.
 */

import type { CookieOptions, Session, TokenResponse, Tokens } from '@eventuras/fides-auth';
import type { OidcClient } from '@eventuras/fides-auth/oidc';
import {
  createFidesAuth as createCoreFidesAuth,
  type CookieStore,
  type FidesAuthConfig,
  type FidesAuthorizedFetchOptions,
  type FidesReadResult,
  type FidesRefreshResult,
  type FidesSessionWithTokens,
  type RefreshSessionOptions,
} from '@eventuras/fides-auth/server';
import type { SessionClearedTrigger } from '@eventuras/fides-auth/session-events';
import { type NextRequest, NextResponse } from 'next/server';
import { cache } from 'react';

import { nextCookieStore } from './cookie-store.js';

/** Options for {@link FidesAuth.refreshInProxy}. */
export interface RefreshInProxyOptions {
  /**
   * Refresh when the access token expires within this many seconds, or within
   * half its lifetime if that is shorter.
   * @default 60
   */
  ifExpiresWithin?: number;
}

/** The core instance's members, bound to the request's cookies. */
export interface FidesAuth {
  /** `GET`, with an optional `?returnTo=`. Redirects to the provider. */
  handleOidcLogin(
    request: Request,
    options?: { authorizationParameters?: Record<string, string> },
  ): Promise<Response>;
  /** The provider's redirect back. Starts the session and redirects to the return path. */
  handleOidcCallback(request: Request): Promise<Response>;
  /**
   * `POST`. Ends the session, revokes its refresh token where the provider has
   * a revocation endpoint, and redirects to the provider's end-session endpoint.
   */
  handleOidcLogout(
    request: Request,
    options?: { state?: string; logoutHint?: string },
  ): Promise<Response>;
  /** `POST`. Refreshes the session. 401 means it is over; 503 means the provider or the store failed. */
  handleHeartbeat(request: Request): Promise<Response>;
  /** `GET`. Whether there is a session, and whose. Never refreshes, never returns tokens. */
  handleSessionInfo(request: Request): Promise<Response>;

  /** The session, or null. Cached per render. */
  readSession(): Promise<Session | null>;
  /** The session, or why there is none. Cached per render, together with `readSession`. */
  tryReadSession(): Promise<FidesReadResult>;
  /** The session's tokens, or null without a session. The access token may have expired. */
  getTokens(): Promise<Tokens | null>;
  /**
   * The session and its tokens in one read, or why there is none. Not cached
   * per render, since a refresh changes the tokens. The tokens are for the
   * server: hand a Client Component `session`, never this result.
   */
  readSessionWithTokens(): Promise<FidesSessionWithTokens>;
  /**
   * Refreshes the tokens, or with `ifExpiresWithin` only when the access token
   * is about to expire. With cookie sessions this writes cookies, so it works
   * only in Server Actions and Route Handlers; pages get theirs from
   * `refreshInProxy`.
   */
  refreshSession(options?: RefreshSessionOptions): Promise<FidesRefreshResult>;
  /** Starts a session from a token response, for a login that doesn't go through the handlers. */
  createSession(tokens: TokenResponse): Promise<Session>;
  /** Changes the user or data. Null when there is no session. */
  updateSession(update: (session: Session) => Session | Promise<Session>): Promise<Session | null>;
  /**
   * Ends the session and revokes its refresh token where the provider has a
   * revocation endpoint. With a store, the record is deleted too. `trigger`
   * defaults to `'logout'`.
   */
  clearSession(options?: { trigger?: SessionClearedTrigger }): Promise<void>;
  /**
   * Ends every session of one user, wherever they are signed in, and revokes
   * their refresh tokens. `sub` is the provider's, from the ID token. Needs a
   * `sessionStore` with `findMatching`.
   *
   * @returns How many sessions it ended.
   */
  endUserSessions(
    user: { sub: string; iss?: string },
    options?: { trigger?: SessionClearedTrigger },
  ): Promise<number>;
  /**
   * Calls an API with the session's access token. It never refreshes, so it is
   * safe in a Server Component; a 401 is an `http_error`.
   */
  authorizedFetch<T = undefined>(
    url: string | URL,
    options: FidesAuthorizedFetchOptions<T>,
  ): Promise<{ response: Response; data: T }>;
  /**
   * For `proxy.ts`. Refreshes a session whose access token expires within
   * `ifExpiresWithin` seconds, or within half its lifetime if that is shorter,
   * before the page renders, since a Server Component can't save a refresh.
   * Sets the new cookies on the response and on the request it forwards, so
   * the page reads the refreshed session.
   *
   * A failed refresh leaves a cookie session as it is. The next API call or
   * heartbeat shows a session that is over; ending it here could undo a refresh
   * that another instance completed with the same refresh token. A session in
   * a store with `withLock` is ended when the provider refuses the refresh for good.
   */
  refreshInProxy(request: NextRequest, options?: RefreshInProxyOptions): Promise<NextResponse>;

  /** The session cookie's name, for a proxy that checks whether one is present. */
  readonly cookieNames: { session: string };
  /** The instance's OIDC client, for protocol calls it doesn't wrap. */
  readonly oidc: OidcClient;
}

/** A cookie written while the proxy handled a request. `maxAge: 0` deletes it. */
interface CookieWrite {
  value: string;
  options?: CookieOptions;
}

/**
 * A CookieStore over the proxied request's cookies, which records the writes
 * so they can go both to the browser and to the forwarded request.
 */
function proxyCookieStore(request: NextRequest): {
  cookies: CookieStore;
  writes: Map<string, CookieWrite>;
} {
  const writes = new Map<string, CookieWrite>();
  const cookies: CookieStore = {
    // A cookie written earlier in this request reads back, as it would in the browser.
    get: (name) => {
      const written = writes.get(name);
      if (written) return written.options?.maxAge === 0 ? null : written.value;
      return request.cookies.get(name)?.value ?? null;
    },
    set: (name, value, options) => {
      writes.set(name, { value, options });
    },
  };
  return { cookies, writes };
}

/** Continues the request, carrying the cookie writes to the page and to the browser. */
function forward(request: NextRequest, writes: Map<string, CookieWrite>): NextResponse {
  if (writes.size === 0) return NextResponse.next();

  for (const [name, { value, options }] of writes) {
    if (options?.maxAge === 0) request.cookies.delete(name);
    else request.cookies.set(name, value);
  }
  const response = NextResponse.next({ request: { headers: request.headers } });
  // A delete is a set with `maxAge: 0`, so the browser gets it with the cookie's own attributes.
  for (const [name, { value, options }] of writes) response.cookies.set(name, value, options);
  return response;
}

/**
 * Creates the app's auth instance. Call it once, in a module of its own, and
 * import the result. It reads nothing from the environment: pass the secret and
 * the provider config in.
 *
 * @example
 * ```ts
 * // lib/auth.ts
 * export const auth = createFidesAuth({ oauthConfig, secret: process.env.SESSION_SECRET! });
 *
 * // app/api/auth/login/route.ts
 * export const GET = (request: Request) => auth.handleOidcLogin(request);
 *
 * // A Server Component
 * const session = await auth.readSession();
 * ```
 */
export function createFidesAuth(config: FidesAuthConfig): FidesAuth {
  const core = createCoreFidesAuth(config);

  const tryReadSession = cache(
    async (): Promise<FidesReadResult> => core.tryReadSession(await nextCookieStore()),
  );

  return {
    handleOidcLogin: async (request, options) =>
      core.handleOidcLogin(request, await nextCookieStore(), options),
    handleOidcCallback: async (request) => core.handleOidcCallback(request, await nextCookieStore()),
    handleOidcLogout: async (request, options) =>
      core.handleOidcLogout(request, await nextCookieStore(), options),
    handleHeartbeat: async (request) => core.handleHeartbeat(request, await nextCookieStore()),
    handleSessionInfo: async (request) => core.handleSessionInfo(request, await nextCookieStore()),

    readSession: cache(async () => (await tryReadSession()).session),
    tryReadSession,
    getTokens: async () => core.getTokens(await nextCookieStore()),
    readSessionWithTokens: async () => core.readSessionWithTokens(await nextCookieStore()),
    refreshSession: async (options) => core.refreshSession(await nextCookieStore(), options),
    createSession: async (tokens) => core.createSession(await nextCookieStore(), tokens),
    updateSession: async (update) => core.updateSession(await nextCookieStore(), update),
    clearSession: async (options) => core.clearSession(await nextCookieStore(), options),
    endUserSessions: (user, options) => core.endUserSessions(user, options),
    authorizedFetch: async (url, options) =>
      core.authorizedFetch(await nextCookieStore(), url, options),

    async refreshInProxy(request, { ifExpiresWithin = 60 } = {}) {
      // Without a session cookie there is nothing to refresh, and nothing to decrypt.
      if (!request.cookies.has(core.cookieNames.session)) return NextResponse.next();

      const { cookies, writes } = proxyCookieStore(request);
      await core.refreshSession(cookies, { ifExpiresWithin });
      return forward(request, writes);
    },

    get cookieNames() {
      return core.cookieNames;
    },
    oidc: core.oidc,
  };
}
