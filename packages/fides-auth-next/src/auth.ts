/**
 * The session helpers and route handlers, bound to one secret and OAuth config.
 * No module state: the config lives in the returned object, so a module that
 * Next loads more than once behaves the same.
 */

import {
  authorizedFetch,
  AuthorizedFetchError,
  clearSession,
  persistSession,
  refreshSessionInStore,
  tryReadSession,
  tryRefreshSessionInStore,
  type AuthorizedFetchErrorReason,
  type AuthorizedFetchOptions,
  type AuthorizedFetchResult,
  type ClearSessionOptions,
  type ReadSessionResult,
  type RefreshSessionResult,
  type SessionSecret,
} from '@eventuras/fides-auth/server';
import type { OAuthConfig } from '@eventuras/fides-auth/oauth';
import type { CreateSessionOptions, Session } from '@eventuras/fides-auth/types';
import { cookies } from 'next/headers';
import { cache } from 'react';

import { nextCookieStore } from './cookie-store';
import { handleHeartbeat } from './heartbeat-handler';
import { handleOidcCallback, type OidcCallbackConfig } from './oidc-callback';
import { handleOidcLogin, type OidcLoginConfig } from './oidc-login';
import { handleOidcLogout, type OidcLogoutConfig } from './oidc-logout';

// So consumers can name the helpers' types without reaching past this package.
export type { ClearSessionOptions, ReadSessionResult, RefreshSessionResult, SessionSecret };
export type { AuthorizedFetchErrorReason, AuthorizedFetchOptions, AuthorizedFetchResult };
export { AuthorizedFetchError };

export interface FidesAuthConfig {
  /** Session encryption secret, e.g. 64 hex chars. Also seals the login transaction. */
  secret: SessionSecret;

  /** OAuth/OIDC configuration. */
  oauthConfig: OAuthConfig;
}

/** A handler's config minus what the factory binds. */
type Bound<T> = Omit<T, 'oauthConfig' | 'secret'>;

export type BoundAuthorizedFetchOptions<T = undefined> = Omit<
  AuthorizedFetchOptions<T>,
  'refresh'
> & {
  /**
   * `false` skips the refresh, so a 401 is an `http_error`. Use it in a Server Component:
   * Next won't let it write cookies, and a refresh that can't be saved spends the refresh token.
   */
  refresh?: false;
};

export interface FidesAuth {
  /** The current session, or null. Cached per render; the access token may have expired. */
  getCurrentSession(): Promise<Session<any> | null>;

  /** The current session, or why there is none. Shares the cache with `getCurrentSession`. */
  tryGetCurrentSession(): Promise<ReadSessionResult>;

  /** Refreshes the session and updates the cookies. Null on any failure. */
  refreshCurrentSession(options?: CreateSessionOptions): Promise<Session | null>;

  /** Refreshes the session and, on failure, says why. Prefer it over `refreshCurrentSession`. */
  tryRefreshCurrentSession(options?: CreateSessionOptions): Promise<RefreshSessionResult>;

  /** Persists a new session across the session cookies. Returns the main cookie's value. */
  createAndPersistSession(session: Session): Promise<string>;

  /** Deletes the session cookies. `trigger` defaults to `logout`. */
  clearCurrentSession(options?: ClearSessionOptions): Promise<void>;

  /**
   * `authorizedFetch` that, on a 401, refreshes the session in the cookies and retries once.
   * Parallel calls in one request share one refresh. The refresh writes cookies, so it works
   * only in Server Actions and Route Handlers; pass `refresh: false` in a Server Component.
   */
  authorizedFetch<T = undefined>(
    session: Session,
    url: string | URL,
    options: BoundAuthorizedFetchOptions<T>,
  ): Promise<AuthorizedFetchResult<T>>;

  handleOidcLogin(request: Request, options?: Bound<OidcLoginConfig>): Promise<Response>;
  handleOidcCallback(request: Request, options: Bound<OidcCallbackConfig>): Promise<Response>;
  handleOidcLogout(request: Request, options: Bound<OidcLogoutConfig>): Promise<Response>;
  handleHeartbeat(request: Request): Promise<Response>;
}

/**
 * Creates the app's auth helpers. Call it once and import the result.
 *
 * @example
 * ```ts
 * // lib/auth.ts
 * export const auth = createFidesAuth({ secret: process.env.SESSION_SECRET!, oauthConfig });
 *
 * // app/api/auth/login/route.ts
 * export const GET = (request: Request) => auth.handleOidcLogin(request);
 *
 * // A server component
 * const session = await auth.getCurrentSession();
 * ```
 */
export function createFidesAuth({ secret, oauthConfig }: FidesAuthConfig): FidesAuth {
  const tryGetCurrentSession = cache(
    async (): Promise<ReadSessionResult> => tryReadSession(await nextCookieStore(), secret),
  );
  const getCurrentSession = cache(async () => (await tryGetCurrentSession()).session);

  // Keyed by the request's cookies, so parallel 401s don't each spend the refresh token.
  const refreshes = new WeakMap<object, Promise<RefreshSessionResult>>();
  const refreshOncePerRequest = async (): Promise<RefreshSessionResult> => {
    const requestCookies = await cookies();
    let refresh = refreshes.get(requestCookies);
    if (!refresh) {
      refresh = nextCookieStore().then((store) =>
        tryRefreshSessionInStore(store, oauthConfig, secret),
      );
      refreshes.set(requestCookies, refresh);
    }
    return refresh;
  };

  return {
    getCurrentSession,
    tryGetCurrentSession,

    refreshCurrentSession: async (options = {}) =>
      refreshSessionInStore(await nextCookieStore(), oauthConfig, secret, options),

    tryRefreshCurrentSession: async (options = {}) =>
      tryRefreshSessionInStore(await nextCookieStore(), oauthConfig, secret, options),

    createAndPersistSession: async (session) =>
      persistSession(await nextCookieStore(), session, secret),

    clearCurrentSession: async (options = {}) => {
      // The sid comes from the per-render cache, so correlating the logout costs nothing.
      const sid = options.sid ?? (await tryGetCurrentSession()).session?.sid;
      await clearSession(await nextCookieStore(), { trigger: options.trigger ?? 'logout', sid });
    },

    authorizedFetch: (session, url, options) =>
      authorizedFetch(session, url, {
        ...options,
        refresh: options.refresh === false ? undefined : refreshOncePerRequest,
      }),

    handleOidcLogin: (request, options = {}) =>
      handleOidcLogin(request, { ...options, oauthConfig, secret }),
    handleOidcCallback: (request, options) =>
      handleOidcCallback(request, { ...options, oauthConfig, secret }),
    handleOidcLogout: (request, options) =>
      handleOidcLogout(request, { ...options, oauthConfig, secret }),
    handleHeartbeat: (request) => handleHeartbeat(request, { oauthConfig, secret }),
  };
}
