// browser/store.ts
//
// The browser's view of the session: who is logged in, and whether that is
// still known to be true. It holds state and the check that refreshes it, and
// nothing else: no cookies, no tokens, no network beyond the session check.
// Any UI layer can subscribe; @eventuras/fides-auth-react does so for React.

import { consoleLoggerFactory, type FidesLoggerFactory } from '../shared/logger.js';
import type { SessionInfo, SessionUser } from '../shared/types.js';

/** The user the session info endpoint reports. */
export type AuthUser = SessionUser;

/** A snapshot of the store. A new object on every change, so it can be compared by identity. */
export interface AuthState {
  user: AuthUser | null;
  /** The user has the configured admin role. */
  isAdmin: boolean;
  isAuthenticated: boolean;
  error: string | null;
  /** When the session was last checked or changed. */
  lastChecked: Date | null;
  /** True until the first check has answered. */
  isInitializing: boolean;
}

export interface AuthStoreConfig {
  /**
   * Where the session check asks. Answered by `handleSessionInfo`.
   * @default '/api/auth/session'
   */
  sessionEndpoint?: string;
  /** Replaces the default check, for an app that learns the session another way. */
  checkAuthStatus?: () => Promise<SessionInfo>;
  /**
   * The role that makes `isAdmin` true.
   * @default 'Admin'
   */
  adminRole?: string;
  /** Creates the logger. Defaults to JSON lines on the console. */
  logger?: FidesLoggerFactory;
}

export interface AuthStore {
  /** The current state. The same object until the next change. */
  getSnapshot(): AuthState;
  /** Calls `listener` after every change. Returns the unsubscribe function. */
  subscribe(listener: () => void): () => void;
  /** Asks the session endpoint, or the configured `checkAuthStatus`. Doesn't change the state. */
  checkStatus(): Promise<SessionInfo>;

  /** Back to the state before the first check. */
  initialize(): void;
  /** A session check or a login found this user. */
  authSuccess(user: AuthUser): void;
  /** There is no session, or none could be found: the check failed with `error`. */
  authFailed(error?: string): void;
  /** A session the store held has ended. Sets `error` to 'Session expired'. */
  sessionExpired(): void;
  /** The user logged out. */
  logout(): void;
  /** Sets `error` and leaves the rest, e.g. for a check that failed while a session is held. */
  setError(error: string): void;
  clearError(): void;
}

const INITIAL: AuthState = {
  user: null,
  isAdmin: false,
  isAuthenticated: false,
  error: null,
  lastChecked: null,
  isInitializing: true,
};

/** Fetches the session info endpoint. Throws on a non-2xx answer. */
async function fetchSessionInfo(endpoint: string): Promise<SessionInfo> {
  const response = await fetch(endpoint, {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`Session check failed with status ${response.status}`);
  return (await response.json()) as SessionInfo;
}

/**
 * Creates the store. It starts out initializing; call {@link initializeAuth} to
 * run the first check.
 *
 * @example
 * ```ts
 * export const authStore = createAuthStore({ adminRole: 'Admin' });
 * await initializeAuth(authStore);
 * authStore.subscribe(() => render(authStore.getSnapshot()));
 * ```
 */
export function createAuthStore(config: AuthStoreConfig = {}): AuthStore {
  const sessionEndpoint = config.sessionEndpoint ?? '/api/auth/session';
  const adminRole = config.adminRole ?? 'Admin';
  const check = config.checkAuthStatus ?? (() => fetchSessionInfo(sessionEndpoint));
  const logger = (config.logger ?? consoleLoggerFactory).create({
    namespace: 'fides-auth:browser:store',
  });

  let state = INITIAL;
  const listeners = new Set<() => void>();

  function set(next: Partial<AuthState>): void {
    state = { ...state, ...next };
    for (const listener of [...listeners]) {
      try {
        listener();
      } catch (error) {
        // One broken subscriber must not keep the others from hearing about the change.
        logger.warn({ error: String(error) }, 'Auth store listener threw');
      }
    }
  }

  const signedOut = (error: string | null): Partial<AuthState> => ({
    user: null,
    isAdmin: false,
    isAuthenticated: false,
    error,
    lastChecked: new Date(),
    isInitializing: false,
  });

  return {
    getSnapshot: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    checkStatus: check,

    initialize: () => set(INITIAL),
    authSuccess(user) {
      set({
        user,
        isAdmin: user.roles?.includes(adminRole) ?? false,
        isAuthenticated: true,
        error: null,
        lastChecked: new Date(),
        isInitializing: false,
      });
    },
    authFailed: (error) => set(signedOut(error ?? null)),
    sessionExpired() {
      logger.info('Session expired');
      set(signedOut('Session expired'));
    },
    logout() {
      logger.info('User logged out');
      set(signedOut(null));
    },
    setError: (error) => set({ error }),
    clearError: () => set({ error: null }),
  };
}

/** Whether `error` is openid-client's rejection of a refresh token. */
export function isInvalidGrant(error: unknown): boolean {
  const value = error as { code?: unknown; error?: unknown } | null;
  return value?.code === 'OAUTH_RESPONSE_BODY_ERROR' && value?.error === 'invalid_grant';
}

/**
 * Runs the first check and leaves the store initialized either way. A failed
 * check counts as no session, since the page can't show one it can't confirm.
 */
export async function initializeAuth(store: AuthStore): Promise<void> {
  store.initialize();
  try {
    const status = await store.checkStatus();
    if (status.authenticated && status.user) store.authSuccess(status.user);
    else store.authFailed();
  } catch {
    store.authFailed();
  }
}

/**
 * Checks the session again and updates the store. An answer is taken as it
 * is: a user logs in, no user logs out. A rejected refresh token from a
 * custom `checkAuthStatus` ends the session.
 *
 * A check that fails, because the network or the server is down, is not an
 * answer. A session the store holds is then kept, with the failure as
 * `error`, as the monitor keeps it: the user is probably still logged in, and
 * the next check that answers settles it. Without a session to keep, the
 * store ends logged out with the same `error`.
 */
export async function checkAuth(store: AuthStore): Promise<void> {
  try {
    const status = await store.checkStatus();
    if (status.authenticated && status.user) store.authSuccess(status.user);
    else store.authFailed();
  } catch (error) {
    if (isInvalidGrant(error)) return store.sessionExpired();
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (store.getSnapshot().isAuthenticated) store.setError(message);
    else store.authFailed(message);
  }
}
