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

/**
 * The core instance's members, bound to the request's cookies. `TData` is the
 * type of `session.data`.
 */
export interface FidesAuth<TData = Record<string, unknown>> {
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
   * A logout that fails leaves the user logged in and is answered with what
   * `onLogoutError` returns, or else a redirect to `defaultRedirectPath` with
   * `?logout=error&error=<code>`.
   */
  handleOidcLogout(
    request: Request,
    options?: { state?: string; logoutHint?: string },
  ): Promise<Response>;
  /** `POST`. Refreshes the session. 401 means it is over; 503 means the provider or the store failed. */
  handleHeartbeat(request: Request): Promise<Response>;
  /**
   * `POST` from the provider, with a `logout_token`: OpenID Connect
   * Back-Channel Logout 1.0. Ends the sessions the token names and answers
   * 200, or 400 when the token is refused. It reads no cookies. Throws a
   * TypeError without a `sessionStore` that has `findMatching`.
   */
  handleBackChannelLogout(request: Request): Promise<Response>;
  /**
   * `GET`. Whether there is a session, and whose. Never refreshes, never
   * returns tokens. 503 means the session store failed, so there is no answer.
   */
  handleSessionInfo(request: Request): Promise<Response>;

  /** The session, or null. Cached per render. */
  readSession(): Promise<Session<TData> | null>;
  /**
   * The session, or why there is none. With a session comes `tokenStatus`,
   * which says whether its access token can still be used. Cached per render,
   * together with `readSession`.
   */
  tryReadSession(): Promise<FidesReadResult<TData>>;
  /** The session's tokens, or null without a session. The access token may have expired. */
  getTokens(): Promise<Tokens | null>;
  /**
   * The session and its tokens in one read, or why there is none. Not cached
   * per render, since a refresh changes the tokens. The tokens are for the
   * server: hand a Client Component `session`, never this result.
   */
  readSessionWithTokens(): Promise<FidesSessionWithTokens<TData>>;
  /**
   * Refreshes the tokens, or with `ifExpiresWithin` only when the access token
   * is about to expire. With cookie sessions this writes cookies, so it works
   * only in Server Actions and Route Handlers; pages get theirs from
   * `refreshInProxy`.
   */
  refreshSession(options?: RefreshSessionOptions): Promise<FidesRefreshResult<TData>>;
  /**
   * Starts a session from a token response, for a login that doesn't go through
   * the handlers. `scopes` come from the response's `scope`; when the provider
   * leaves it out, pass it along, e.g. `{ ...tokens, scope }`.
   */
  createSession(tokens: TokenResponse): Promise<Session<TData>>;
  /**
   * Changes the user or data. Null when there is no session. It waits its
   * turn after a refresh or another update of the session, and `update` gets
   * the session as it is then, so `update` must not refresh, update or end
   * the same session itself: that call is refused with a TypeError. It rejects
   * with what the store threw when the store fails.
   */
  updateSession(
    update: (session: Session<TData>) => Session<TData> | Promise<Session<TData>>,
  ): Promise<Session<TData> | null>;
  /**
   * Ends the session and revokes its refresh token where the provider has a
   * revocation endpoint. With a store, the record is deleted too. `trigger`
   * defaults to `'logout'`.
   *
   * Call it in a Server Action or a Route Handler. In a Server Component,
   * where cookies can't be written, it rejects with what Next threw. With a
   * store the session is over all the same, and the cookie the browser keeps
   * finds nothing; with cookie storage nothing is ended.
   */
  clearSession(options?: { trigger?: SessionClearedTrigger }): Promise<void>;
  /**
   * Ends every session of one user, wherever they are signed in, and revokes
   * their refresh tokens. `sub` is the provider's, from the ID token. It
   * doesn't ask the provider, so it works while the provider is down. `iss`
   * narrows it to one provider, and must be the ID token's `iss` to the
   * letter. Needs a `sessionStore` with `findMatching`.
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
   * a store with `withLock` is ended when the provider refuses the refresh for
   * good, and its cookie is deleted, on the response and on the request it forwards.
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
export function createFidesAuth<TData = Record<string, unknown>>(
  config: FidesAuthConfig<TData>,
): FidesAuth<TData> {
  const core = createCoreFidesAuth(config);

  const tryReadSession = cache(
    async (): Promise<FidesReadResult<TData>> => core.tryReadSession(await nextCookieStore()),
  );

  return {
    handleOidcLogin: async (request, options) =>
      core.handleOidcLogin(request, await nextCookieStore(), options),
    handleOidcCallback: async (request) => core.handleOidcCallback(request, await nextCookieStore()),
    handleOidcLogout: async (request, options) =>
      core.handleOidcLogout(request, await nextCookieStore(), options),
    handleHeartbeat: async (request) => core.handleHeartbeat(request, await nextCookieStore()),
    handleBackChannelLogout: (request) => core.handleBackChannelLogout(request),
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
