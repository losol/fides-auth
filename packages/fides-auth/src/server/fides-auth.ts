// createFidesAuth: the server side of fides-auth as one object. It holds what is
// the same for every request (the OIDC client, the session lifecycle over its
// storage, the cookie names and the guards), and each member takes only what
// varies: the Request and the CookieStore, which a framework binding adapts
// from its own cookie API.

import { CookieTooLargeError } from '../shared/cookies.js';
import { createLogger, type FidesLoggerFactory } from '../shared/logger.js';
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
  LegacySession,
  Session,
  SessionInfo,
  Tokens,
  TokenResponse,
} from '../shared/types.js';
import { createOidcClient, type OidcClient } from '../protocol/client.js';
import { redirectUriOf, type OidcClientConfig } from '../protocol/config.js';
import type { MapRecordSession } from '../session/record.js';
import {
  authorizedFetch as fetchWithSession,
  type AuthorizedFetchOptions,
} from './authorized-fetch.js';
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
import { createSessionLifecycle } from './session-lifecycle.js';
import { assertSessionSecret, type SessionSecret } from './session-persistence.js';
import { cookieStorage, sessionCookieName, storeStorage } from './session-storage.js';
import type { SessionStore } from './session-store.js';
import type { RefreshSessionResult as LegacyRefreshResult } from './session.js';

/**
 * Changes the session built at login, e.g. to add `data` or look the user up.
 * `claims` are decoded from the ID token, not verified, and undefined without
 * one. The correlation id, the timestamps and the IdP session are kept
 * whatever it returns.
 */
export type MapSession = MapRecordSession;

export interface FidesAuthConfig {
  /** The provider and client. A BFF is a confidential client, so `clientAuth: 'none'` throws. */
  oauthConfig: OidcClientConfig;
  /** Seals the session cookies, the store records and the login transaction. 32 bytes, as hex or raw. */
  secret: SessionSecret;
  /** Keeps sessions in a store, with only a handle in the cookie. Without it, sessions live in the cookies. */
  sessionStore?: SessionStore;
  /**
   * How long a session lasts from login. Refreshes don't extend it.
   * @default 30
   */
  sessionDurationDays?: number;
  /** The app's public origin, for the CSRF guard and redirects. Defaults to the redirect URI's origin. */
  applicationUrl?: string;
  /** Changes the session built at login. */
  mapSession?: MapSession;
  /**
   * The ID token claim that holds the user's roles.
   * @default 'roles'
   */
  rolesClaim?: string;
  /**
   * Turns a requested return path into a safe one, or null to use
   * `defaultRedirectPath`. Runs at login and again at the callback. The
   * result must also be on `applicationUrl`'s origin.
   * @default a path that starts with a single `/`, in printable ASCII, without a backslash
   */
  validateReturnTo?: (returnTo: string) => string | null;
  /**
   * Where a login without a return path lands, and where a failed one is sent.
   * @default '/'
   */
  defaultRedirectPath?: string;
  /** Where the provider sends the user after logout. Defaults to `applicationUrl`. */
  postLogoutRedirectUri?: string;
  /** Answers false to make a handler respond 429. */
  rateLimit?: (request: Request) => boolean | Promise<boolean>;
  /** Creates the loggers. Defaults to the factory `configureLogger` set: JSON lines on the console unless changed. */
  logger?: FidesLoggerFactory;
  /** Gets every session lifecycle event, next to the logger. */
  onSessionEvent?: (event: SessionEvent) => void;
}

/** The result of {@link FidesAuth.tryReadSession}. */
export type FidesReadResult =
  | { session: Session; reason?: undefined }
  | { session: null; reason: SessionRejectedReason };

/** The result of {@link FidesAuth.refreshSession}. Only `cause: 'invalid_grant'` means the user must log in again. */
export type FidesRefreshResult =
  | { ok: true; session: Session; rotatedRefreshToken: boolean }
  | { ok: false; reason: SessionRejectedReason; cause?: RefreshFailureCause };

/** Options for {@link FidesAuth.authorizedFetch}. The instance refreshes on a 401 itself. */
export type FidesAuthorizedFetchOptions<T> = Omit<AuthorizedFetchOptions<T>, 'refresh'> & {
  /**
   * `false` skips the refresh, so a 401 is an `http_error`. Pass it where the
   * cookies can't be written, such as a Next.js Server Component: a refresh
   * there spends the refresh token and can't save the new one.
   */
  refresh?: false;
};

export interface FidesAuth {
  /** `GET`, with an optional `?returnTo=`. Redirects to the provider. */
  handleOidcLogin(
    request: Request,
    cookies: CookieStore,
    options?: { authorizationParameters?: Record<string, string> },
  ): Promise<Response>;
  /** The provider's redirect back. Starts the session and redirects to the return path. */
  handleOidcCallback(request: Request, cookies: CookieStore): Promise<Response>;
  /** `POST`. Ends the session and redirects to the provider's end-session endpoint. */
  handleOidcLogout(
    request: Request,
    cookies: CookieStore,
    options?: { state?: string; logoutHint?: string },
  ): Promise<Response>;
  /** `POST`. Refreshes the session. 401 means it is over; 503 means the provider couldn't be reached. */
  handleHeartbeat(request: Request, cookies: CookieStore): Promise<Response>;
  /** `GET`. Whether there is a session, and whose. Never refreshes, never returns tokens. */
  handleSessionInfo(request: Request, cookies: CookieStore): Promise<Response>;

  /** The session, or null. */
  readSession(cookies: CookieStore): Promise<Session | null>;
  /** The session, or why there is none. */
  tryReadSession(cookies: CookieStore): Promise<FidesReadResult>;
  /** The session's tokens, or null without a session. */
  getTokens(cookies: CookieStore): Promise<Tokens | null>;
  /** Refreshes the tokens. The session's identity and lifetime stay. */
  refreshSession(cookies: CookieStore): Promise<FidesRefreshResult>;
  /** Starts a session from a token response, for a login that doesn't go through the handlers. */
  createSession(cookies: CookieStore, tokens: TokenResponse): Promise<Session>;
  /** Changes the user or data. Null when there is no session. */
  updateSession(
    cookies: CookieStore,
    update: (session: Session) => Session | Promise<Session>,
  ): Promise<Session | null>;
  /** Ends the session. With a store, the record is deleted too. `trigger` defaults to `'logout'`. */
  clearSession(cookies: CookieStore, options?: { trigger?: SessionClearedTrigger }): Promise<void>;
  /** Calls an API with the session's access token, refreshing once on a 401. */
  authorizedFetch<T = undefined>(
    cookies: CookieStore,
    url: string | URL,
    options: FidesAuthorizedFetchOptions<T>,
  ): Promise<{ response: Response; data: T; refreshed: boolean }>;

  /** The session cookie's name, for middleware that checks whether one is present. */
  readonly cookieNames: { session: string };
  /** The instance's OIDC client, for protocol calls it doesn't wrap. */
  readonly oidc: OidcClient;
}

/** The loggers `configureLogger` controls. */
const configuredLoggers: FidesLoggerFactory = { create: (options) => createLogger(options) };

const NO_STORE = { 'Cache-Control': 'private, no-store' };

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

const tooManyRequests = () => new Response('Too many requests', { status: 429 });
const forbidden = () => new Response('Forbidden', { status: 403 });

/**
 * Creates the server side of fides-auth. It does no I/O until a member needs it,
 * and reads the redirect URI only then: an app creates the instance when a module
 * loads, and a build can load that module without the runtime environment.
 *
 * @throws TypeError if `clientAuth` is `'none'`. A member throws TypeError if the
 * config has no redirect URI.
 */
export function createFidesAuth(config: FidesAuthConfig): FidesAuth {
  const { oauthConfig, secret, sessionStore, rateLimit } = config;
  if (oauthConfig.clientAuth === 'none') {
    throw new TypeError(
      "createFidesAuth needs a confidential client: a backend-for-frontend can't use clientAuth 'none'",
    );
  }
  const defaultRedirectPath = config.defaultRedirectPath ?? '/';
  const validateReturnTo = config.validateReturnTo ?? defaultValidateReturnTo;

  const loggers = config.logger ?? configuredLoggers;
  const log = {
    login: loggers.create({ namespace: 'fides-auth:server:oidc-login' }),
    callback: loggers.create({ namespace: 'fides-auth:server:oidc-callback' }),
    logout: loggers.create({ namespace: 'fides-auth:server:oidc-logout' }),
    heartbeat: loggers.create({ namespace: 'fides-auth:server:heartbeat' }),
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
        sessionDurationDays: config.sessionDurationDays,
        rolesClaim: config.rolesClaim,
        mapSession: config.mapSession,
        refreshTokens: (refreshToken) => oidc.refresh(refreshToken),
        logger: loggers.create({ namespace: 'fides-auth:server:session' }),
        onSessionEvent: config.onSessionEvent,
      }),
    };
  }
  let resolved: ReturnType<typeof resolveSettings> | undefined;
  const settings = () => (resolved ??= resolveSettings());

  async function limited(request: Request): Promise<boolean> {
    return !!rateLimit && !(await rateLimit(request));
  }

  /** The return path to redirect to: validated, on the app's origin, or the default. */
  function returnUrl(returnTo: string | null | undefined): URL {
    const path = returnTo ? validateReturnTo(returnTo) : null;
    return validateReturnUrl(path, settings().applicationUrl, defaultRedirectPath);
  }

  function loginError(code: string): Response {
    const url = new URL(defaultRedirectPath, settings().applicationUrl);
    url.searchParams.set('login', 'error');
    url.searchParams.set('error', code);
    return redirect(url);
  }

  async function tryReadSession(cookies: CookieStore): Promise<FidesReadResult> {
    const read = await settings().lifecycle.read(cookies);
    return read.record ? { session: read.record.session } : { session: null, reason: read.reason };
  }

  async function refreshSession(cookies: CookieStore): Promise<FidesRefreshResult> {
    const result = await settings().lifecycle.refresh(cookies);
    return result.ok
      ? { ok: true, session: result.record.session, rotatedRefreshToken: result.rotatedRefreshToken }
      : { ok: false, reason: result.reason, cause: result.cause };
  }

  return {
    async handleOidcLogin(request, cookies, options = {}) {
      // Before the provider is contacted: a bad secret is a config error, not a login failure.
      assertSessionSecret(secret);
      const { txCookie } = settings();
      if (await limited(request)) {
        log.login.warn('Rate limit exceeded');
        return tooManyRequests();
      }

      const raw = new URL(request.url).searchParams.get('returnTo');
      const returnTo = raw ? validateReturnTo(raw) : null;
      const authRequest = await oidc.createAuthorizationRequest({
        parameters: options.authorizationParameters,
      });
      const url = await oidc.authorizationUrl(authRequest);

      const transaction = createTransaction(
        { state: authRequest.state, code_verifier: authRequest.codeVerifier },
        { returnTo },
      );
      try {
        await persistTransaction(cookies, transaction, secret, txCookie);
      } catch (error) {
        // Too big for a cookie: still log in, just without the way back.
        if (!(error instanceof CookieTooLargeError) || !transaction.returnTo) throw error;
        log.login.warn({ size: error.size }, 'Login transaction too large; dropped returnTo');
        await persistTransaction(cookies, { ...transaction, returnTo: undefined }, secret, txCookie);
      }

      log.login.info('Redirecting to OIDC provider for login');
      return redirect(url);
    },

    async handleOidcCallback(request, cookies) {
      assertSessionSecret(secret);
      const { applicationUrl, txCookie, lifecycle } = settings();
      if (await limited(request)) {
        log.callback.warn('Rate limit exceeded');
        return tooManyRequests();
      }

      const currentUrl = new URL(request.url);
      const state = currentUrl.searchParams.get('state');
      const idpError = currentUrl.searchParams.get('error') ?? undefined;

      // A cancel after the login ended still redirects, but with a fixed code:
      // without a live transaction nothing in the query is trusted.
      const loginEnded = (): Response =>
        idpError === undefined
          ? new Response('Please restart the login process.', { status: 400 })
          : loginError('login_expired');

      try {
        // The public callback URL. Behind a TLS-terminating proxy the request
        // carries the internal origin, but the path must match the authorize call.
        const publicUrl = new URL(applicationUrl);
        publicUrl.pathname = currentUrl.pathname;
        publicUrl.search = currentUrl.search;

        const transaction = state ? await readTransaction(cookies, state, secret, txCookie) : null;
        if (!transaction) {
          log.callback.warn({ error: idpError }, 'Missing login transaction');
          return loginEnded();
        }
        validateCallback(currentUrl.searchParams, transaction);

        const tokens = await oidc.exchangeCode(publicUrl, {
          codeVerifier: transaction.codeVerifier,
          state: transaction.state,
        });
        const session = await lifecycle.create(cookies, tokens);

        const url = returnUrl(transaction.returnTo);
        url.searchParams.set('login', 'success');
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
            return loginError(IDP_ERROR_CODE.test(code) ? code : 'idp_error');
          }
          log.callback.warn({ reason: error.reason, error: idpError }, 'Rejected OIDC callback');
          return error.reason === 'transaction_expired'
            ? loginEnded()
            : new Response('Please restart the login process.', { status: 400 });
        }
        if (error instanceof CookieTooLargeError) {
          // The session doesn't fit in three cookies. A sessionStore is the fix.
          log.callback.error(
            { error, cookieName: error.cookieName, size: error.size },
            'Session cookie too large to store',
          );
          return new Response('The session is too large to store. Please contact support.', {
            status: 431,
          });
        }
        log.callback.error({ error }, 'OIDC callback error');
        return new Response('An unexpected error occurred. Please restart the login process.', {
          status: 500,
        });
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
        return tooManyRequests();
      }

      // Read before ending: the ID token is the hint that lets the provider skip its prompt.
      const idTokenHint = (await settings().lifecycle.read(cookies)).record?.tokens.idToken;
      try {
        await settings().lifecycle.end(cookies, { trigger: 'logout' });
      } catch (error) {
        // Never send the user to the provider with the local session half ended:
        // they would come back looking logged in.
        log.logout.error({ error }, 'Failed to end the session');
        return new Response('Logout failed', { status: 500 });
      }

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
      // The provider was unreachable or broken. The session is probably fine,
      // so keep it and let the client retry rather than log the user out.
      if (result.cause === 'transport' || result.cause === 'idp_error') {
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
          }
        : { authenticated: false };
      return Response.json(body, { headers: NO_STORE });
    },

    readSession: async (cookies) => (await tryReadSession(cookies)).session,
    tryReadSession,
    getTokens: async (cookies) => (await settings().lifecycle.read(cookies)).record?.tokens ?? null,
    refreshSession,
    createSession: async (cookies, tokens) => (await settings().lifecycle.create(cookies, tokens)).session,
    updateSession: async (cookies, update) => (await settings().lifecycle.update(cookies, update))?.session ?? null,
    clearSession: (cookies, { trigger = 'logout' } = {}) => settings().lifecycle.end(cookies, { trigger }),

    async authorizedFetch(cookies, url, { refresh, ...options }) {
      const tokens = (await settings().lifecycle.read(cookies)).record?.tokens;
      // The token holder authorizedFetch expects; it reads only `tokens`.
      const holder: LegacySession = { tokens };
      const refreshTokens = async (): Promise<LegacyRefreshResult> => {
        const refreshed = await settings().lifecycle.refresh(cookies);
        return refreshed.ok
          ? { ok: true, session: { tokens: refreshed.record.tokens }, rotatedRefreshToken: refreshed.rotatedRefreshToken }
          : { ok: false, reason: refreshed.reason, cause: refreshed.cause };
      };
      const result = await fetchWithSession(holder, url, {
        ...options,
        refresh: refresh === false ? undefined : refreshTokens,
      });
      return { response: result.response, data: result.data, refreshed: result.refreshed };
    },

    get cookieNames() {
      return settings().cookieNames;
    },
    oidc,
  };
}
