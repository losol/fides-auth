// createFidesAuth: the server side of fides-auth as one object. It holds what is
// the same for every request (the OIDC client, the session lifecycle over its
// storage, the cookie names and the guards), and each member takes only what
// varies: the Request and the CookieStore, which a framework binding adapts
// from its own cookie API.

import { CookieTooLargeError } from '../shared/cookies.js';
import { consoleLoggerFactory, type FidesLogger, type FidesLoggerFactory } from '../shared/logger.js';
import {
  SESSION_EVENT,
  logSessionEvent,
  type RefreshFailureCause,
  type SessionClearedTrigger,
  type SessionEvent,
  type SessionRejectedReason,
} from '../shared/session-events.js';
import type {
  HeartbeatResponse,
  Session,
  SessionInfo,
  Tokens,
  TokenResponse,
} from '../shared/types.js';
import { createOidcClient, type OidcClient } from '../protocol/client.js';
import { redirectUriOf, type OidcClientConfig } from '../protocol/config.js';
import { getOAuthErrorLogContext } from '../protocol/logging.js';
import { checkSessionDuration, type MapRecordSession, type SessionRecord } from '../session/record.js';
import type { RolesClaim } from '../session/user-claims.js';
import { authorizedFetch as fetchWithTokens, type AuthorizedFetchOptions } from './authorized-fetch.js';
import type { CookieStore } from './cookie-store.js';
import { isSameOriginRequest } from './csrf.js';
import {
  CallbackValidationError,
  clearTransaction,
  createTransaction,
  persistTransaction,
  readTransaction,
  transactionCookieOptions,
  validateCallback,
} from './login-transaction.js';
import { validateReturnUrl } from './return-to.js';
import { checkRefreshGrace, createSessionLifecycle } from './session-lifecycle.js';
import { assertSessionSecret, type SessionSecret } from './session-secret.js';
import { cookieStorage, sessionCookieName, storeStorage } from './session-storage.js';
import type { SessionStore, StoreFields } from './session-store.js';

/**
 * Changes the session built at login, e.g. to add `data` or look the user up.
 * `claims` are decoded from the ID token, not verified, and undefined without
 * one. The correlation id, the timestamps and the IdP session are kept
 * whatever it returns. It runs at login only: a refresh that brings an ID
 * token updates the user's roles, name and email from it, and keeps the rest.
 * So roles set here last only with `rolesClaim: false`; to read them from
 * another claim, make `rolesClaim` a function.
 *
 * `mapRefresh` has the same shape and runs at each refresh, with the session
 * as the refresh left it.
 *
 * `TData` is the type of `session.data`, from `createFidesAuth<TData>`.
 */
export type MapSession<TData = Record<string, unknown>> = (
  tokens: Parameters<MapRecordSession>[0],
  claims: Parameters<MapRecordSession>[1],
  session: Session<TData>,
) => Session<TData> | Promise<Session<TData>>;

/**
 * Why a login failed, as the `error` parameter of the redirect carries it:
 *
 * - `login_expired`: the callback found no login to finish. The login took
 *   too long, was finished already, or its cookie never arrived.
 * - `invalid_callback`: the callback didn't match the login it belongs to.
 * - `session_too_large`: the session doesn't fit in the cookies. A
 *   `sessionStore` is the fix.
 * - `login_failed`: anything else at the callback, such as a code the
 *   provider won't exchange.
 * - `login_unavailable`: the login couldn't be started, most often because
 *   the provider couldn't be reached.
 * - `rate_limited`: `rateLimit` refused the request.
 * - `idp_error`, or the provider's own code when it has the shape of one,
 *   such as `access_denied` when the user cancels.
 */
export type LoginErrorCode =
  | 'login_expired'
  | 'invalid_callback'
  | 'session_too_large'
  | 'login_failed'
  | 'login_unavailable'
  | 'rate_limited'
  | 'idp_error'
  | (string & {});

/** A login that failed, as `onLoginError` gets it. */
export interface LoginError {
  code: LoginErrorCode;
  /** Where it failed: when the login started, or at the provider's redirect back. */
  stage: 'login' | 'callback';
  /** What was thrown, when something was. For logs, not for the user. */
  cause?: unknown;
}

/** Why a logout failed: `logout_failed` when the session couldn't be ended, `rate_limited` when `rateLimit` refused the request. */
export type LogoutErrorCode = 'logout_failed' | 'rate_limited';

/** A logout that failed, as `onLogoutError` gets it. The user is still logged in. */
export interface LogoutError {
  code: LogoutErrorCode;
  /** What was thrown, when something was. For logs, not for the user. */
  cause?: unknown;
}

export interface FidesAuthConfig<TData = Record<string, unknown>> {
  /** The provider and client. A BFF is a confidential client, so `clientAuth: 'none'` throws. */
  oauthConfig: OidcClientConfig;
  /** Seals the session cookies, the store records and the login transaction. 32 bytes, as hex or raw. */
  secret: SessionSecret;
  /** Keeps sessions in a store, with only a handle in the cookie. Without it, sessions live in the cookies. */
  sessionStore?: SessionStore;
  /**
   * Plain fields to keep next to each stored session, as `fields` on the
   * record the store gets: your own user id, say, to list or count who is
   * signed in. They are stored in the clear, so return only what the store may
   * show. Runs on every save. Ignored without a `sessionStore`.
   */
  storeFields?: (session: Session<TData>) => StoreFields;
  /**
   * How long a session lasts from login, in seconds. Refreshes don't extend
   * it. `createFidesAuth` throws a TypeError unless it is a finite number
   * above 0.
   * @default 43200, which is 12 hours
   */
  sessionDurationSeconds?: number;
  /**
   * With cookie sessions: for this many seconds after a refresh, a request
   * that still carries the cookie from before it gets that refresh's result,
   * instead of spending the old refresh token again. A copy of the old cookie
   * gets it too, as with a provider's own reuse interval. 0 turns it off.
   * Ignored with a `sessionStore`, where every request reads the new tokens.
   * @default 10
   */
  refreshGraceSeconds?: number;
  /** The app's public origin, for the CSRF guard and redirects. Defaults to the redirect URI's origin. */
  applicationUrl?: string;
  /** Changes the session built at login. */
  mapSession?: MapSession<TData>;
  /**
   * Changes the session a refresh leaves, the way `mapSession` does at login:
   * to follow claims you keep in `data`, or roles that aren't in the ID token.
   * It runs each time the provider is asked for new tokens and answers, with
   * that token response, the claims of its ID token, undefined when it has
   * none, and the session after the library's own changes to the user and the
   * scopes. The correlation id, the timestamps and the IdP session are kept
   * whatever it returns.
   *
   * It can't fail the refresh: the provider has spent the old refresh token
   * by then. If it throws, the error is logged and the session is saved as
   * the refresh left it. It runs under the store's lock, so it must not
   * refresh or update the same session itself.
   */
  mapRefresh?: MapSession<TData>;
  /**
   * Where the user's roles are in the ID token, read at login and on every
   * refresh that brings an ID token: the name of a top-level claim, or a
   * function of the claims for anything else, such as Keycloak's
   * `(claims) => claims.realm_access?.roles`. A token without the claim gives
   * no roles. False leaves `user.roles` to `mapSession`: the library never
   * sets them, and a refresh keeps them as they are.
   * @default 'roles'
   */
  rolesClaim?: RolesClaim | false;
  /**
   * Turns a requested return path into a safe one, or null to use
   * `defaultRedirectPath`. Runs at login and again at the callback. The
   * result must also be on `applicationUrl`'s origin.
   * @default a path that starts with a single `/`, in printable ASCII, without a backslash
   */
  validateReturnTo?: (returnTo: string) => string | null;
  /**
   * Where a login without a return path lands, and where a failed one is sent.
   * A page that starts a login for users without a session must not do so
   * when the URL has `login=error`, or a login that keeps failing goes in circles.
   * @default '/'
   */
  defaultRedirectPath?: string;
  /**
   * Whether a login lands on its return path with `?login=success` added, so
   * the page can tell that the user just logged in. False leaves the path as
   * it was. A failed login is sent to `defaultRedirectPath` with
   * `?login=error&error=<code>` either way.
   * @default true
   */
  loginSuccessParam?: boolean;
  /**
   * Called when a login fails, at its start or at the callback. Return a
   * Response to answer with it, an error page of the app's own say. Without
   * one, the user is sent to `defaultRedirectPath` with
   * `?login=error&error=<code>`.
   */
  onLoginError?: (
    error: LoginError,
    request: Request,
  ) => Response | undefined | void | Promise<Response | undefined> | Promise<void>;
  /**
   * Called when a logout fails, which leaves the user logged in. Return a
   * Response to answer with it. Without one, the user is sent to
   * `defaultRedirectPath` with `?logout=error&error=<code>`.
   */
  onLogoutError?: (
    error: LogoutError,
    request: Request,
  ) => Response | undefined | void | Promise<Response | undefined> | Promise<void>;
  /** Where the provider sends the user after logout. Defaults to `applicationUrl`. */
  postLogoutRedirectUri?: string;
  /**
   * Answers false to refuse a request. The heartbeat then answers 429. A
   * login or a logout is answered as one that failed, with the code
   * `rate_limited`.
   */
  rateLimit?: (request: Request) => boolean | Promise<boolean>;
  /** Creates the loggers. Defaults to JSON lines on the console. */
  logger?: FidesLoggerFactory;
  /** Gets every session lifecycle event, next to the logger. */
  onSessionEvent?: (event: SessionEvent) => void;
}

/** The result of {@link FidesAuth.tryReadSession}. */
export type FidesReadResult<TData = Record<string, unknown>> =
  | { session: Session<TData>; reason?: undefined }
  | { session: null; reason: SessionRejectedReason };

/** The result of {@link FidesAuth.readSessionWithTokens}. */
export type FidesSessionWithTokens<TData = Record<string, unknown>> =
  | { session: Session<TData>; tokens: Tokens; reason?: undefined }
  | { session: null; tokens: null; reason: SessionRejectedReason };

/** Options for {@link FidesAuth.refreshSession}. */
export interface RefreshSessionOptions {
  /**
   * Refresh only when the access token expires within this many seconds, or
   * within half its lifetime if that is shorter: a window as long as the
   * token's lifetime would refresh on every call. Without it, the session is
   * refreshed at once. A token whose lifetime the provider didn't give counts
   * as fresh.
   */
  ifExpiresWithin?: number;
}

/** The result of {@link FidesAuth.refreshSession}. Only `cause: 'invalid_grant'` means the user must log in again. */
export type FidesRefreshResult<TData = Record<string, unknown>> =
  | {
      ok: true;
      session: Session<TData>;
      /** False when `ifExpiresWithin` found the access token fresh enough. */
      refreshed: boolean;
      rotatedRefreshToken: boolean;
    }
  | { ok: false; reason: SessionRejectedReason; cause?: RefreshFailureCause };

/** Options for {@link FidesAuth.authorizedFetch}. */
export type FidesAuthorizedFetchOptions<T> = AuthorizedFetchOptions<T>;

/**
 * The server side of fides-auth. `TData` is the type of `session.data`, and the
 * same in everything the instance hands out.
 */
export interface FidesAuth<TData = Record<string, unknown>> {
  /**
   * `GET`, with an optional `?returnTo=`. Redirects to the provider. A login
   * that can't be started, because the provider can't be reached say, is
   * answered as a failed one: see `handleOidcCallback`.
   */
  handleOidcLogin(
    request: Request,
    cookies: CookieStore,
    options?: { authorizationParameters?: Record<string, string> },
  ): Promise<Response>;
  /**
   * The provider's redirect back. Starts the session and redirects to the
   * return path, with `?login=success` unless `loginSuccessParam` is false.
   * A login that fails is answered with what `onLoginError` returns, or else
   * redirects to `defaultRedirectPath` with `?login=error&error=<code>`, a
   * {@link LoginErrorCode}. It never answers with text of its own.
   */
  handleOidcCallback(request: Request, cookies: CookieStore): Promise<Response>;
  /**
   * `POST`. Ends the session, revokes its refresh token where the provider has
   * a revocation endpoint, and redirects to the provider's end-session endpoint.
   * A logout that fails leaves the user logged in and is answered with what
   * `onLogoutError` returns, or else a redirect to `defaultRedirectPath` with
   * `?logout=error&error=<code>`, a {@link LogoutErrorCode}.
   */
  handleOidcLogout(
    request: Request,
    cookies: CookieStore,
    options?: { state?: string; logoutHint?: string },
  ): Promise<Response>;
  /** `POST`. Refreshes the session. 401 means it is over; 503 means the provider or the store failed. */
  handleHeartbeat(request: Request, cookies: CookieStore): Promise<Response>;
  /**
   * `GET`. Whether there is a session, whose, and when it ends. Never
   * refreshes, never returns tokens.
   */
  handleSessionInfo(request: Request, cookies: CookieStore): Promise<Response>;

  /** The session, or null. */
  readSession(cookies: CookieStore): Promise<Session<TData> | null>;
  /** The session, or why there is none. */
  tryReadSession(cookies: CookieStore): Promise<FidesReadResult<TData>>;
  /** The session's tokens, or null without a session. */
  getTokens(cookies: CookieStore): Promise<Tokens | null>;
  /**
   * The session and its tokens in one read, or why there is none. For server
   * code that needs both, such as a loader that calls an API: `readSession`
   * and `getTokens` each read, which with a store is a round trip each. The
   * tokens are for the server: hand the browser `session`, never this result.
   */
  readSessionWithTokens(cookies: CookieStore): Promise<FidesSessionWithTokens<TData>>;
  /**
   * Refreshes the tokens, or with `ifExpiresWithin` only when the access token
   * is about to expire. Apart from the heartbeat endpoint, nothing else on the
   * instance refreshes. With cookie storage it writes cookies, so call it where
   * they can be set.
   *
   * A refresh the provider refuses for good, `cause: 'invalid_grant'`, ends a
   * session held by a `sessionStore` with `withLock`: the record is deleted,
   * and the cookie too where cookies can be set. Any other session is left as
   * it is, since another instance may have refreshed it; end it with
   * `clearSession`.
   */
  refreshSession(
    cookies: CookieStore,
    options?: RefreshSessionOptions,
  ): Promise<FidesRefreshResult<TData>>;
  /**
   * Starts a session from a token response, for a login that doesn't go through
   * the handlers. `scopes` come from the response's `scope`; when the provider
   * leaves it out, pass it along, e.g. `{ ...tokens, scope }`.
   */
  createSession(cookies: CookieStore, tokens: TokenResponse): Promise<Session<TData>>;
  /**
   * Changes the user or data. Null when there is no session. It waits its
   * turn after a refresh or another update of the session, under the store's
   * lock where there is one, and `update` gets the session as it is then. So
   * `update` must not refresh or update the same session itself: that call
   * would wait for this one.
   */
  updateSession(
    cookies: CookieStore,
    update: (session: Session<TData>) => Session<TData> | Promise<Session<TData>>,
  ): Promise<Session<TData> | null>;
  /**
   * Ends the session and revokes its refresh token where the provider has a
   * revocation endpoint. With a store, the record is deleted too. `trigger`
   * defaults to `'logout'`.
   */
  clearSession(cookies: CookieStore, options?: { trigger?: SessionClearedTrigger }): Promise<void>;
  /**
   * Ends every session of one user, wherever they are signed in, and revokes
   * their refresh tokens: for "sign out everywhere", or when an account is
   * closed. `sub` is the provider's, from the ID token (`session.idp.sub`),
   * and `iss` defaults to the provider's issuer from its metadata. When the
   * provider can't be reached, it is the issuer this instance last saw, or else
   * `oauthConfig.issuer`: pass `iss` when your ID tokens spell the issuer
   * differently from your config. The browsers keep their cookies, which then
   * find no session.
   *
   * @returns How many sessions it ended.
   * @throws TypeError without a `sessionStore` that has `findMatching`.
   */
  endUserSessions(
    user: { sub: string; iss?: string },
    options?: { trigger?: SessionClearedTrigger },
  ): Promise<number>;
  /**
   * Calls an API with the session's access token. It never refreshes, so a 401
   * is an `http_error`; call `refreshSession({ ifExpiresWithin })` first where
   * the new tokens can be saved.
   */
  authorizedFetch<T = undefined>(
    cookies: CookieStore,
    url: string | URL,
    options: FidesAuthorizedFetchOptions<T>,
  ): Promise<{ response: Response; data: T }>;

  /** The session cookie's name, for middleware that checks whether one is present. */
  readonly cookieNames: { session: string };
  /** The instance's OIDC client, for protocol calls it doesn't wrap. */
  readonly oidc: OidcClient;
}

const NO_STORE = { 'Cache-Control': 'private, no-store' };

/**
 * How long before `expiresAt` a refresh with `ifExpiresWithin` is due, in
 * milliseconds: the window, but never more than half the token's lifetime, so
 * a token that lives shorter than the window isn't refreshed on every call.
 */
function refreshWindowMs(tokens: Tokens, expiresAt: number, ifExpiresWithin: number): number {
  const window = ifExpiresWithin * 1000;
  const issuedAt = Date.parse(tokens.accessTokenIssuedAt ?? '');
  // A session saved before the lifetime was recorded gets the plain window until it is refreshed.
  return Number.isNaN(issuedAt) ? window : Math.min(window, (expiresAt - issuedAt) / 2);
}

/**
 * A path on this origin: one leading `/`, printable ASCII only, and no
 * backslash, which browsers read as `/` and so as the start of `//host`.
 */
const defaultValidateReturnTo = (returnTo: string): string | null =>
  /^\/[\x20-\x7e]*$/.test(returnTo) && !returnTo.startsWith('//') && !returnTo.includes('\\')
    ? returnTo
    : null;

// Registered OAuth/OIDC error codes are snake_case; nothing else is echoed.
const IDP_ERROR_CODE = /^[a-z0-9_]{1,64}$/;

function redirect(location: string | URL): Response {
  return new Response(null, { status: 302, headers: { Location: location.toString() } });
}

function methodNotAllowed(allow: string): Response {
  return new Response(null, { status: 405, headers: { Allow: allow } });
}

const forbidden = () => new Response('Forbidden', { status: 403 });

/**
 * Creates the server side of fides-auth. It does no I/O until a member needs it,
 * and reads the redirect URI only then: an app creates the instance when a module
 * loads, and a build can load that module without the runtime environment.
 *
 * @throws TypeError if `clientAuth` is `'none'`, or `refreshGraceSeconds` isn't a
 * finite number, 0 or more. A member throws TypeError if the config has no redirect URI.
 */
export function createFidesAuth<TData = Record<string, unknown>>(
  config: FidesAuthConfig<TData>,
): FidesAuth<TData> {
  const { oauthConfig, secret, sessionStore, rateLimit } = config;
  if ('sessionDurationDays' in config) {
    // Left unnoticed, the old option would be ignored and its sessions cut to the default.
    throw new TypeError(
      'sessionDurationDays is now sessionDurationSeconds: give the lifetime in seconds, e.g. 30 * 24 * 60 * 60',
    );
  }
  const sessionDurationSeconds = checkSessionDuration(config.sessionDurationSeconds);
  if (oauthConfig.clientAuth === 'none') {
    throw new TypeError(
      "createFidesAuth needs a confidential client: a backend-for-frontend can't use clientAuth 'none'",
    );
  }
  const refreshGraceSeconds = checkRefreshGrace(config.refreshGraceSeconds);
  const defaultRedirectPath = config.defaultRedirectPath ?? '/';
  const validateReturnTo = config.validateReturnTo ?? defaultValidateReturnTo;

  const loggers = config.logger ?? consoleLoggerFactory;
  const log = {
    login: loggers.create({ namespace: 'fides-auth:server:oidc-login' }),
    callback: loggers.create({ namespace: 'fides-auth:server:oidc-callback' }),
    logout: loggers.create({ namespace: 'fides-auth:server:oidc-logout' }),
    heartbeat: loggers.create({ namespace: 'fides-auth:server:heartbeat' }),
    returnTo: loggers.create({ namespace: 'fides-auth:server:return-to' }),
    fetch: loggers.create({ namespace: 'fides-auth:server:authorized-fetch' }),
  };
  const oidc = createOidcClient(oauthConfig, { logger: loggers });

  /** What the redirect URI decides: the app's origin, the cookie flavour and the storage. */
  function resolveSettings() {
    const redirectUri = redirectUriOf(oauthConfig);
    const applicationUrl = config.applicationUrl ?? new URL(redirectUri).origin;
    const txCookie = transactionCookieOptions(redirectUri);
    const secure = txCookie.secure !== false;
    return {
      applicationUrl,
      postLogoutRedirectUri: config.postLogoutRedirectUri ?? applicationUrl,
      txCookie,
      cookieNames: { session: sessionCookieName(secure) },
      // One lifecycle per instance: it shares refreshes between the requests it serves.
      lifecycle: createSessionLifecycle({
        storage: sessionStore ? storeStorage({ store: sessionStore, secure }) : cookieStorage({ secure }),
        secret,
        sessionDurationSeconds,
        rolesClaim: config.rolesClaim,
        // The lifecycle doesn't know what `data` holds; the type is the app's own.
        mapSession: config.mapSession as MapRecordSession | undefined,
        mapRefresh: config.mapRefresh as MapRecordSession | undefined,
        storeFields: config.storeFields as ((session: Session) => StoreFields) | undefined,
        refreshGraceSeconds,
        refreshTokens: (refreshToken) => oidc.refresh(refreshToken),
        logger: loggers.create({ namespace: 'fides-auth:server:session' }),
        onSessionEvent: config.onSessionEvent,
      }),
    };
  }
  let resolved: ReturnType<typeof resolveSettings> | undefined;
  const settings = () => (resolved ??= resolveSettings());
  /** The issuer from the last metadata this instance read, for when the provider is down. */
  let knownIssuer: string | undefined;

  /**
   * Revokes the refresh token of a session that has ended, so neither a copy
   * of the session nor a refresh that was in flight can renew it. The session
   * is over either way, so a failure is only logged.
   */
  async function revokeRefreshToken(ended: SessionRecord | undefined, logger: FidesLogger): Promise<void> {
    if (!ended?.tokens.refreshToken) return;
    const { correlationId } = ended.session;
    try {
      if (await oidc.revoke(ended.tokens.refreshToken, { tokenTypeHint: 'refresh_token' })) {
        logger.info({ correlationId }, 'Refresh token revoked');
      }
    } catch (error) {
      logger.warn(
        { correlationId, error: getOAuthErrorLogContext(error) },
        'Could not revoke the refresh token',
      );
    }
  }

  async function limited(request: Request): Promise<boolean> {
    return !!rateLimit && !(await rateLimit(request));
  }

  /** The return path to redirect to: validated, on the app's origin, or the default. */
  function returnUrl(returnTo: string | null | undefined): URL {
    const path = returnTo ? validateReturnTo(returnTo) : null;
    return validateReturnUrl(log.returnTo, path, settings().applicationUrl, defaultRedirectPath);
  }

  function loginError(code: string): Response {
    const url = new URL(defaultRedirectPath, settings().applicationUrl);
    url.searchParams.set('login', 'error');
    url.searchParams.set('error', code);
    return redirect(url);
  }

  /** Answers a failed login: with what `onLoginError` returns, or else the redirect with the code. */
  async function loginFailed(request: Request, failure: LoginError, logger: FidesLogger): Promise<Response> {
    try {
      const response = await config.onLoginError?.(failure, request);
      if (response instanceof Response) return response;
    } catch (error) {
      logger.error({ error }, 'onLoginError threw');
    }
    return loginError(failure.code);
  }

  /** Answers a failed logout: with what `onLogoutError` returns, or else the redirect with the code. */
  async function logoutFailed(request: Request, failure: LogoutError, logger: FidesLogger): Promise<Response> {
    try {
      const response = await config.onLogoutError?.(failure, request);
      if (response instanceof Response) return response;
    } catch (error) {
      logger.error({ error }, 'onLogoutError threw');
    }
    const url = new URL(defaultRedirectPath, settings().applicationUrl);
    url.searchParams.set('logout', 'error');
    url.searchParams.set('error', failure.code);
    return redirect(url);
  }

  /** The session with `data` as the app typed it: what it holds is what the app put there. */
  const typed = (session: Session): Session<TData> => session as Session<TData>;

  async function tryReadSession(cookies: CookieStore): Promise<FidesReadResult<TData>> {
    const read = await settings().lifecycle.read(cookies);
    return read.record
      ? { session: typed(read.record.session) }
      : { session: null, reason: read.reason };
  }

  async function refreshSession(
    cookies: CookieStore,
    { ifExpiresWithin }: RefreshSessionOptions = {},
  ): Promise<FidesRefreshResult<TData>> {
    const { lifecycle } = settings();
    if (ifExpiresWithin !== undefined) {
      if (!(ifExpiresWithin >= 0)) {
        throw new TypeError('refreshSession: ifExpiresWithin must be a number of seconds, 0 or more');
      }
      const read = await lifecycle.read(cookies);
      if (!read.record) return { ok: false, reason: read.reason };
      const { tokens } = read.record;
      const expiresAt = Date.parse(tokens.accessTokenExpiresAt ?? '');
      // Without a lifetime to judge by, refreshing on every call would only load the provider.
      if (
        Number.isNaN(expiresAt) ||
        expiresAt - Date.now() > refreshWindowMs(tokens, expiresAt, ifExpiresWithin)
      ) {
        return {
          ok: true,
          session: typed(read.record.session),
          refreshed: false,
          rotatedRefreshToken: false,
        };
      }
    }

    const result = await lifecycle.refresh(cookies);
    return result.ok
      ? {
          ok: true,
          session: typed(result.record.session),
          refreshed: true,
          rotatedRefreshToken: result.rotatedRefreshToken,
        }
      : { ok: false, reason: result.reason, cause: result.cause };
  }

  return {
    async handleOidcLogin(request, cookies, options = {}) {
      // Before the provider is contacted: a bad secret is a config error, not a login failure.
      assertSessionSecret(secret);
      const { txCookie } = settings();
      if (await limited(request)) {
        log.login.warn('Rate limit exceeded');
        return loginFailed(request, { code: 'rate_limited', stage: 'login' }, log.login);
      }

      const raw = new URL(request.url).searchParams.get('returnTo');
      const returnTo = raw ? validateReturnTo(raw) : null;
      let url: URL;
      try {
        const authRequest = await oidc.createAuthorizationRequest({
          parameters: options.authorizationParameters,
        });
        url = await oidc.authorizationUrl(authRequest);

        const transaction = createTransaction(authRequest, { returnTo, logger: log.login });
        try {
          await persistTransaction(cookies, transaction, secret, txCookie);
        } catch (error) {
          // Too big for a cookie: still log in, just without the way back.
          if (!(error instanceof CookieTooLargeError) || !transaction.returnTo) throw error;
          log.login.warn({ size: error.size }, 'Login transaction too large; dropped returnTo');
          await persistTransaction(cookies, { ...transaction, returnTo: undefined }, secret, txCookie);
        }
      } catch (error) {
        // Most often the provider's metadata couldn't be read. The user gets
        // the same answer as for a login that failed at the callback.
        log.login.error({ error }, 'Could not start the login');
        return loginFailed(request, { code: 'login_unavailable', stage: 'login', cause: error }, log.login);
      }

      log.login.info('Redirecting to OIDC provider for login');
      return redirect(url);
    },

    async handleOidcCallback(request, cookies) {
      assertSessionSecret(secret);
      const { applicationUrl, txCookie, lifecycle } = settings();
      if (await limited(request)) {
        log.callback.warn('Rate limit exceeded');
        return loginFailed(request, { code: 'rate_limited', stage: 'callback' }, log.callback);
      }

      const currentUrl = new URL(request.url);
      const state = currentUrl.searchParams.get('state');
      const idpError = currentUrl.searchParams.get('error') ?? undefined;

      const failed = (code: LoginErrorCode, cause?: unknown): Promise<Response> =>
        loginFailed(request, { code, stage: 'callback', cause }, log.callback);

      try {
        // The public callback URL. Behind a TLS-terminating proxy the request
        // carries the internal origin, but the path must match the authorize call.
        const publicUrl = new URL(applicationUrl);
        publicUrl.pathname = currentUrl.pathname;
        publicUrl.search = currentUrl.search;

        const transaction = state ? await readTransaction(cookies, state, secret, { ...txCookie, logger: log.callback }) : null;
        if (!transaction) {
          // The code is fixed: without a live transaction nothing in the query is trusted.
          log.callback.warn({ error: idpError }, 'Missing login transaction');
          return await failed('login_expired');
        }
        validateCallback(currentUrl.searchParams, transaction);

        const tokens = await oidc.exchangeCode(publicUrl, {
          codeVerifier: transaction.codeVerifier,
          state: transaction.state,
        });
        const session = await lifecycle.create(cookies, tokens, { requestedScope: transaction.scope });

        const url = returnUrl(transaction.returnTo);
        if (config.loginSuccessParam !== false) url.searchParams.set('login', 'success');
        log.callback.info(
          { correlationId: session.session.correlationId, redirectUrl: url.toString() },
          'Login successful, redirecting',
        );
        return redirect(url);
      } catch (error) {
        if (error instanceof CallbackValidationError) {
          // A denied or cancelled login: send the user home, not to an error page.
          if (error.reason === 'idp_error') {
            log.callback.warn(
              { reason: error.reason, error: error.idpError, errorDescription: error.idpErrorDescription },
              'Identity provider returned an error',
            );
            const code = error.idpError ?? '';
            return await failed(IDP_ERROR_CODE.test(code) ? code : 'idp_error', error);
          }
          log.callback.warn({ reason: error.reason, error: idpError }, 'Rejected OIDC callback');
          return await failed(error.reason === 'transaction_expired' ? 'login_expired' : 'invalid_callback', error);
        }
        if (error instanceof CookieTooLargeError) {
          // The session doesn't fit in three cookies. A sessionStore is the fix.
          log.callback.error(
            { error, cookieName: error.cookieName, size: error.size },
            'Session cookie too large to store',
          );
          return await failed('session_too_large', error);
        }
        log.callback.error({ error }, 'OIDC callback error');
        return await failed('login_failed', error);
      } finally {
        // The login transaction is spent whatever the outcome.
        if (state) await clearTransaction(cookies, state, secret, txCookie);
      }
    },

    async handleOidcLogout(request, cookies, options = {}) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      if (!isSameOriginRequest(request, settings().applicationUrl)) {
        log.logout.warn(
          { origin: request.headers.get('origin'), site: request.headers.get('sec-fetch-site') },
          'Cross-origin logout request rejected',
        );
        return forbidden();
      }
      if (await limited(request)) {
        log.logout.warn('Rate limit exceeded');
        return logoutFailed(request, { code: 'rate_limited' }, log.logout);
      }

      // A bad secret is a config error, not a session to end quietly.
      assertSessionSecret(secret);
      let ended: SessionRecord | undefined;
      try {
        ended = await settings().lifecycle.end(cookies, { trigger: 'logout' });
      } catch (error) {
        // Never send the user to the provider with the local session half ended:
        // they would come back looking logged in.
        log.logout.error({ error }, 'Failed to end the session');
        return logoutFailed(request, { code: 'logout_failed', cause: error }, log.logout);
      }
      await revokeRefreshToken(ended, log.logout);

      // The ID token is the hint that lets the provider skip its prompt.
      const idTokenHint = ended?.tokens.idToken;
      const { postLogoutRedirectUri } = settings();
      const url = await oidc.logoutUrl({
        postLogoutRedirectUri,
        idTokenHint,
        state: options.state,
        logoutHint: options.logoutHint,
      });
      if (!url) {
        log.logout.info('No logout URL; the local session is ended, the provider session may remain');
        return redirect(postLogoutRedirectUri);
      }
      log.logout.info({ hasIdTokenHint: !!idTokenHint }, 'Redirecting to provider for logout');
      return redirect(url);
    },

    async handleHeartbeat(request, cookies) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      if (!isSameOriginRequest(request, settings().applicationUrl)) {
        log.heartbeat.warn(
          { origin: request.headers.get('origin'), site: request.headers.get('sec-fetch-site') },
          'Cross-origin heartbeat rejected',
        );
        return forbidden();
      }
      if (await limited(request)) {
        log.heartbeat.warn('Heartbeat rate limit exceeded');
        return new Response(null, { status: 429 });
      }

      const result = await settings().lifecycle.refresh(cookies);
      if (result.ok) {
        const body: HeartbeatResponse = {
          accessTokenExpiresAt: result.record.tokens.accessTokenExpiresAt ?? null,
        };
        return Response.json(body, { headers: NO_STORE });
      }
      // The provider or the store was unreachable or broken. The session is
      // probably fine, so keep it and let the client retry rather than log the user out.
      if (result.cause === 'transport' || result.cause === 'idp_error' || result.cause === 'store') {
        log.heartbeat.warn(
          { correlationId: result.correlationId, cause: result.cause },
          'Heartbeat refresh could not be completed; keeping the session',
        );
        return new Response(null, { status: 503, headers: NO_STORE });
      }

      const event: SessionEvent = {
        event: SESSION_EVENT.REJECTED,
        correlationId: result.correlationId,
        reason: result.reason,
        source: 'heartbeat',
      };
      logSessionEvent(log.heartbeat, event);
      try {
        config.onSessionEvent?.(event);
      } catch (error) {
        log.heartbeat.error({ error }, 'onSessionEvent threw');
      }
      return Response.json({ reason: result.reason }, { status: 401, headers: NO_STORE });
    },

    async handleSessionInfo(request, cookies) {
      if (request.method !== 'GET' && request.method !== 'HEAD') return methodNotAllowed('GET, HEAD');
      const { record } = await settings().lifecycle.read(cookies);
      const body: SessionInfo = record
        ? {
            authenticated: true,
            user: record.session.user,
            scopes: record.session.scopes,
            accessTokenExpiresAt: record.tokens.accessTokenExpiresAt ?? null,
            expiresAt: record.session.expiresAt,
          }
        : { authenticated: false };
      return Response.json(body, { headers: NO_STORE });
    },

    readSession: async (cookies) => (await tryReadSession(cookies)).session,
    tryReadSession,
    getTokens: async (cookies) => (await settings().lifecycle.read(cookies)).record?.tokens ?? null,
    async readSessionWithTokens(cookies) {
      const read = await settings().lifecycle.read(cookies);
      return read.record
        ? { session: typed(read.record.session), tokens: read.record.tokens }
        : { session: null, tokens: null, reason: read.reason };
    },
    refreshSession,
    createSession: async (cookies, tokens) =>
      typed((await settings().lifecycle.create(cookies, tokens)).session),
    async updateSession(cookies, update) {
      const updated = await settings().lifecycle.update(
        cookies,
        update as (session: Session) => Session | Promise<Session>,
      );
      return updated ? typed(updated.session) : null;
    },
    async clearSession(cookies, { trigger = 'logout' } = {}) {
      await revokeRefreshToken(await settings().lifecycle.end(cookies, { trigger }), log.logout);
    },

    async endUserSessions({ sub, iss }, { trigger = 'logout' } = {}) {
      // The ID token's `iss`, which a session's lookup fields are stored under.
      let issuer = iss;
      if (!issuer) {
        try {
          issuer = (await oidc.metadata()).issuer;
          if (issuer) knownIssuer = issuer;
        } catch (error) {
          // Ending local sessions should not depend on the provider being up.
          issuer = knownIssuer ?? oauthConfig.issuer;
          log.logout.warn(
            { issuer, error: getOAuthErrorLogContext(error) },
            "Could not read the provider's metadata; using the issuer last seen or configured",
          );
        }
      }
      if (!issuer) {
        throw new TypeError("endUserSessions needs iss: the provider's metadata has no issuer");
      }
      const ended = await settings().lifecycle.endMatching({ iss: issuer, sub }, { trigger });
      for (const record of ended) await revokeRefreshToken(record, log.logout);
      log.logout.info({ sessions: ended.length }, "Ended a user's sessions");
      return ended.length;
    },

    async authorizedFetch(cookies, url, options) {
      const tokens = (await settings().lifecycle.read(cookies)).record?.tokens;
      return fetchWithTokens(tokens, url, options, log.fetch);
    },

    get cookieNames() {
      return settings().cookieNames;
    },
    oidc,
  };
}
