// server/authorized-fetch.ts
//
// fetch() with the session's access token, locked to one API base. The token
// goes only to URLs under `allowedBase` and never follows a redirect. A 401 gets
// one refresh and one retry. Lives in server/ because a refresh must be persisted.

import { createLogger } from '../logger';
import type { RefreshFailureCause, SessionRejectedReason } from '../session-events';
import type { Session } from '../types';
import type { RefreshSessionResult } from './session';

const logger = createLogger({ namespace: 'fides-auth:server:authorized-fetch' });

const DEFAULT_TIMEOUT_MS = 10_000;

/** Why {@link authorizedFetch} failed. */
export type AuthorizedFetchErrorReason =
  /** The URL is outside `allowedBase` or carries credentials. Nothing was sent. */
  | 'url_not_allowed'
  /** The session has no access token. Nothing was sent. */
  | 'no_access_token'
  /** The request failed before a response, including a refused redirect. */
  | 'network_error'
  /** No response within `timeoutMs`. */
  | 'timeout'
  /** A 401, and the refresh failed. Not retried. */
  | 'refresh_failed'
  /** A non-2xx response. */
  | 'http_error'
  /** `parse` threw. */
  | 'parse_failed';

export interface AuthorizedFetchErrorDetails {
  status?: number;
  method?: string;
  url?: string;
  refreshFailure?: { reason: SessionRejectedReason; cause?: RefreshFailureCause };
  response?: Response;
  cause?: unknown;
}

/** A failed {@link authorizedFetch}. Never carries the token or the query string. */
export class AuthorizedFetchError extends Error {
  readonly reason: AuthorizedFetchErrorReason;
  /** HTTP status, for `http_error` and `refresh_failed`. */
  readonly status?: number;
  readonly method?: string;
  /** Origin and path only. */
  readonly url?: string;
  /** Why the refresh failed. Only `cause: 'invalid_grant'` means the user must log in again. */
  readonly refreshFailure?: { reason: SessionRejectedReason; cause?: RefreshFailureCause };
  /** The unread non-2xx response, for `http_error`. */
  declare readonly response?: Response;

  constructor(reason: AuthorizedFetchErrorReason, details: AuthorizedFetchErrorDetails = {}) {
    const { status, method, url, refreshFailure, response, cause } = details;
    const target = url ? ` for ${method ?? 'GET'} ${url}` : '';
    super(
      `authorizedFetch ${reason}${status ? ` (${status})` : ''}${target}`,
      cause === undefined ? undefined : { cause },
    );
    this.name = 'AuthorizedFetchError';
    this.reason = reason;
    this.status = status;
    this.method = method;
    this.url = url;
    this.refreshFailure = refreshFailure;
    // Non-enumerable, so logging the error doesn't print the full URL.
    Object.defineProperty(this, 'response', { value: response, enumerable: false });
  }
}

export interface AuthorizedFetchOptions<T = undefined> extends Omit<RequestInit, 'redirect'> {
  /** Absolute http(s) URL. The token goes only to its origin, under its path. */
  allowedBase: string | URL;
  /** Reads and validates a 2xx response. Its result is `data`; a throw is `parse_failed`. */
  parse?: (response: Response) => T | Promise<T>;
  /** Per request, including a retry. @default 10000 */
  timeoutMs?: number;
  /**
   * Called once on a 401, e.g. `() => tryRefreshSessionInStore(store, config, persistence)`.
   * Without it a 401 is an `http_error`. A retry resends `body`, so don't pass a stream.
   */
  refresh?: () => Promise<RefreshSessionResult | Session | null>;
}

export interface AuthorizedFetchResult<T> {
  /** The 2xx response. `parse` has read its body, if given. */
  response: Response;
  /** What `parse` returned. */
  data: T;
  /** The session that made the call: the refreshed one if `refreshed`. Use it from now on. */
  session: Session;
  /** A 401 led to a refresh. Persist `session` unless `refresh` already did. */
  refreshed: boolean;
}

/**
 * Calls an API with the session's access token.
 *
 * @throws {AuthorizedFetchError} on a disallowed URL, non-2xx, timeout, network error or failed refresh.
 * @throws {TypeError} when `allowedBase` is not an http(s) URL without credentials.
 */
export async function authorizedFetch<T = undefined>(
  session: Session,
  url: string | URL,
  options: AuthorizedFetchOptions<T>,
): Promise<AuthorizedFetchResult<T>> {
  const { allowedBase, parse, timeoutMs = DEFAULT_TIMEOUT_MS, refresh, ...init } = options;
  const target = resolveAllowedUrl(url, allowedBase);
  const request = { method: (init.method ?? 'GET').toUpperCase(), url: redactUrl(target) };

  let current = session;
  let attempt = await send(current, target, init, timeoutMs, request);
  let refreshed = false;

  if (attempt.response.status === 401 && refresh) {
    await attempt.response.body?.cancel().catch(() => undefined);
    attempt.unlink();
    logger.debug(request, 'Got 401, refreshing the session once');
    current = await refreshOnce(refresh, request);
    refreshed = true;
    attempt = await send(current, target, init, timeoutMs, request);
  }

  const { response, timeout, unlink } = attempt;
  if (!response.ok) {
    throw new AuthorizedFetchError('http_error', { ...request, status: response.status, response });
  }

  try {
    const data = (parse ? await parse(response) : undefined) as T;
    // A body still to be read stays under the timeout and the caller's signal.
    if (!response.body || response.bodyUsed) unlink();
    return { response, data, session: current, refreshed };
  } catch (error) {
    unlink();
    if (init.signal?.aborted) throw error;
    // A body read cut off by the timeout rejects with the timeout's own reason.
    const reason = error === timeout.reason ? 'timeout' : 'parse_failed';
    throw new AuthorizedFetchError(reason, { ...request, status: response.status, cause: error });
  }
}

/** Resolves `url` against the base and throws unless it stays under it. */
function resolveAllowedUrl(url: string | URL, allowedBase: string | URL): URL {
  const base = new URL(allowedBase);
  if (base.protocol !== 'https:' && base.protocol !== 'http:') {
    throw new TypeError('authorizedFetch: allowedBase must be an http(s) URL');
  }
  if (base.username || base.password) {
    throw new TypeError('authorizedFetch: allowedBase must not carry credentials');
  }
  // A trailing slash makes `users` resolve under `/v1`, and `/v1` not match `/v1-evil`.
  if (!base.pathname.endsWith('/')) base.pathname += '/';

  let target: URL;
  try {
    target = new URL(url, base);
  } catch {
    // No cause: Node's TypeError carries the raw input, query and all.
    throw new AuthorizedFetchError('url_not_allowed');
  }

  const underBase =
    target.pathname.startsWith(base.pathname) || `${target.pathname}/` === base.pathname;
  if (target.username || target.password || target.origin !== base.origin || !underBase) {
    logger.warn(
      { url: redactUrl(target), allowedBase: redactUrl(base) },
      'Refused to send the access token outside allowedBase',
    );
    throw new AuthorizedFetchError('url_not_allowed', { url: redactUrl(target) });
  }
  return target;
}

interface Attempt {
  response: Response;
  timeout: AbortSignal;
  /** Stops listening to the caller's signal, once nobody will read the body. */
  unlink: () => void;
}

async function send(
  session: Session,
  target: URL,
  init: RequestInit,
  timeoutMs: number,
  request: { method: string; url: string },
): Promise<Attempt> {
  const token = session.tokens?.accessToken;
  if (!token) throw new AuthorizedFetchError('no_access_token', request);

  const headers = new Headers(init.headers);
  headers.set('Authorization', `Bearer ${token}`);
  const timeout = AbortSignal.timeout(timeoutMs);
  const { signal, unlink } = linkSignals(timeout, init.signal);

  try {
    const response = await fetch(target, { ...init, headers, signal, redirect: 'error' });
    return { response, timeout, unlink };
  } catch (error) {
    unlink();
    // The caller's own abort is theirs to handle.
    if (init.signal?.aborted) throw error;
    const reason = timeout.aborted ? 'timeout' : 'network_error';
    throw new AuthorizedFetchError(reason, { ...request, cause: error });
  }
}

/**
 * A signal that aborts when the timeout or the caller's signal does, with that signal's
 * reason, and `unlink` to remove the listeners. `AbortSignal.any` would need Node 18.17.
 */
function linkSignals(
  timeout: AbortSignal,
  caller?: AbortSignal | null,
): { signal: AbortSignal; unlink: () => void } {
  if (!caller) return { signal: timeout, unlink: () => undefined };

  const sources = [caller, timeout];
  const controller = new AbortController();
  const unlink = () => {
    for (const source of sources) source.removeEventListener('abort', onAbort);
  };
  const onAbort = () => {
    unlink();
    controller.abort(sources.find((source) => source.aborted)?.reason);
  };

  if (sources.some((source) => source.aborted)) onAbort();
  else for (const source of sources) source.addEventListener('abort', onAbort);
  return { signal: controller.signal, unlink };
}

async function refreshOnce(
  refresh: NonNullable<AuthorizedFetchOptions['refresh']>,
  request: { method: string; url: string },
): Promise<Session> {
  let result: RefreshSessionResult;
  try {
    result = toRefreshResult(await refresh());
  } catch (error) {
    throw new AuthorizedFetchError('refresh_failed', { ...request, status: 401, cause: error });
  }

  if (!result.ok) {
    const refreshFailure = { reason: result.reason, cause: result.cause };
    throw new AuthorizedFetchError('refresh_failed', { ...request, status: 401, refreshFailure });
  }
  return result.session;
}

/** Accepts both `tryRefreshSessionInStore` and `refreshSessionInStore` results. */
function toRefreshResult(value: RefreshSessionResult | Session | null): RefreshSessionResult {
  if (!value) return { ok: false, reason: 'refresh_failed' };
  if ('ok' in value) return value;
  return { ok: true, session: value, rotatedRefreshToken: false };
}

/** Origin and path: never credentials, query or fragment. */
function redactUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}
