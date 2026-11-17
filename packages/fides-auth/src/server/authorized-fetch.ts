// server/authorized-fetch.ts
//
// fetch() with an access token, locked to one API base. The token goes only to
// URLs under `allowedBase` and never follows a redirect. It never refreshes: a
// caller that wants fresh tokens asks for them first, with refreshSession.

import type { FidesLogger } from '../shared/logger.js';
import type { Tokens } from '../shared/types.js';

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
  /** A non-2xx response, a 401 included. */
  | 'http_error'
  /** `parse` threw. */
  | 'parse_failed';

export interface AuthorizedFetchErrorDetails {
  status?: number;
  method?: string;
  url?: string;
  accessTokenExpired?: boolean;
  bearerError?: string;
  response?: Response;
  cause?: unknown;
}

/** A failed {@link authorizedFetch}. Never carries the token or the query string. */
export class AuthorizedFetchError extends Error {
  readonly reason: AuthorizedFetchErrorReason;
  /** HTTP status, for `http_error`. */
  readonly status?: number;
  readonly method?: string;
  /** Origin and path only. */
  readonly url?: string;
  /**
   * For `http_error`: whether the access token had passed its expiry by this
   * server's clock when the request went out. Undefined when the provider gave
   * no lifetime. With a 401, true means a refresh will probably help.
   */
  readonly accessTokenExpired?: boolean;
  /**
   * For `http_error`: the `error` of the API's `Bearer` challenge in
   * `WWW-Authenticate` (RFC 6750 §3). `invalid_token` means the token is expired,
   * revoked or malformed, so a refresh may help; `insufficient_scope` means it
   * won't. Only a snake_case code is kept.
   */
  readonly bearerError?: string;
  /** The unread non-2xx response, for `http_error`. */
  declare readonly response?: Response;

  constructor(reason: AuthorizedFetchErrorReason, details: AuthorizedFetchErrorDetails = {}) {
    const { status, method, url, accessTokenExpired, bearerError, response, cause } = details;
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
    this.accessTokenExpired = accessTokenExpired;
    this.bearerError = bearerError;
    // Non-enumerable, so logging the error doesn't print the full URL.
    Object.defineProperty(this, 'response', { value: response, enumerable: false });
  }
}

export interface AuthorizedFetchOptions<T = undefined> extends Omit<RequestInit, 'redirect'> {
  /** Absolute http(s) URL. The token goes only to its origin, under its path. */
  allowedBase: string | URL;
  /** Reads and validates a 2xx response. Its result is `data`; a throw is `parse_failed`. */
  parse?: (response: Response) => T | Promise<T>;
  /** @default 10000 */
  timeoutMs?: number;
}

export interface AuthorizedFetchResult<T> {
  /** The 2xx response. `parse` has read its body, if given. */
  response: Response;
  /** What `parse` returned. */
  data: T;
}

/**
 * Calls an API with an access token. A refused URL is reported to `logger`.
 *
 * @throws {AuthorizedFetchError} on a disallowed URL, a missing token, non-2xx, timeout or network error.
 * @throws {TypeError} when `allowedBase` is not an http(s) URL without credentials.
 */
export async function authorizedFetch<T = undefined>(
  tokens: Tokens | null | undefined,
  url: string | URL,
  options: AuthorizedFetchOptions<T>,
  logger: FidesLogger,
): Promise<AuthorizedFetchResult<T>> {
  const { allowedBase, parse, timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options;
  const target = resolveAllowedUrl(url, allowedBase, logger);
  const request = { method: (init.method ?? 'GET').toUpperCase(), url: redactUrl(target) };

  const sentAt = Date.now();
  const { response, timeout, signal, unlink } = await send(tokens, target, init, timeoutMs, request);
  if (!response.ok) {
    const expiresAt = Date.parse(tokens?.accessTokenExpiresAt ?? '');
    throw new AuthorizedFetchError('http_error', {
      ...request,
      status: response.status,
      accessTokenExpired: Number.isNaN(expiresAt) ? undefined : expiresAt <= sentAt,
      bearerError: bearerErrorOf(response.headers.get('www-authenticate')),
      response,
    });
  }

  try {
    const data = (parse ? await whileNotAborted(parse(response), signal) : undefined) as T;
    // A body still to be read stays under the timeout and the caller's signal.
    if (!response.body || response.bodyUsed) unlink();
    return { response, data };
  } catch (error) {
    unlink();
    if (init.signal?.aborted) throw error;
    // A body read cut off by the timeout rejects with the timeout's own reason.
    const reason = error === timeout.reason ? 'timeout' : 'parse_failed';
    throw new AuthorizedFetchError(reason, { ...request, status: response.status, cause: error });
  }
}

/** Resolves `url` against the base and throws unless it stays under it. */
function resolveAllowedUrl(url: string | URL, allowedBase: string | URL, logger: FidesLogger): URL {
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
  if (
    target.username ||
    target.password ||
    target.origin !== base.origin ||
    !underBase ||
    hasDotSegment(target.pathname)
  ) {
    logger.warn(
      { url: redactUrl(target), allowedBase: redactUrl(base) },
      'Refused to send the access token outside allowedBase',
    );
    throw new AuthorizedFetchError('url_not_allowed', { url: redactUrl(target) });
  }
  return target;
}

/**
 * Whether the path has a `.` or `..` segment, in any of its encodings. A gateway
 * that decodes before it routes would resolve `..%2f` or `%252e%252e` out of the base.
 */
function hasDotSegment(pathname: string): boolean {
  let path = pathname;
  for (let round = 0; round <= 3; round++) {
    const dotted = path
      .split(/[/\\]/)
      .some((segment) => segment === '.' || segment === '..' || /^\.\.?;/.test(segment));
    if (dotted) return true;
    let decoded: string;
    try {
      decoded = decodeURIComponent(path);
    } catch {
      return false;
    }
    if (decoded === path) return false;
    path = decoded;
  }
  return false;
}

interface Attempt {
  response: Response;
  timeout: AbortSignal;
  /** The signal the request was sent with: the timeout, linked with the caller's own. */
  signal: AbortSignal;
  /** Stops listening to the caller's signal, once nobody will read the body. */
  unlink: () => void;
}

async function send(
  tokens: Tokens | null | undefined,
  target: URL,
  init: RequestInit,
  timeoutMs: number,
  request: { method: string; url: string },
): Promise<Attempt> {
  const token = tokens?.accessToken;
  if (!token) throw new AuthorizedFetchError('no_access_token', request);

  const headers = new Headers(init.headers);
  try {
    headers.set('Authorization', `Bearer ${token}`);
  } catch {
    // A token with CR, LF or NUL: the TypeError's message would carry the token.
    throw new AuthorizedFetchError('no_access_token', request);
  }
  const timeout = AbortSignal.timeout(timeoutMs);
  const { signal, unlink } = linkSignals(timeout, init.signal);

  try {
    const response = await fetch(target, { ...init, headers, signal, redirect: 'error' });
    return { response, timeout, signal, unlink };
  } catch (error) {
    unlink();
    // The caller's own abort is theirs to handle.
    if (init.signal?.aborted) throw error;
    const reason = timeout.aborted ? 'timeout' : 'network_error';
    throw new AuthorizedFetchError(reason, { ...request, cause: error });
  }
}

/**
 * Waits for `reading`, but no longer than `signal` allows, and then rejects
 * with the signal's reason.
 *
 * The signal given to `fetch` should do this alone, and mostly does. But Node's
 * fetch follows it through an object that nothing holds on to once the
 * response is back. When that object is garbage collected, an abort no longer
 * reaches the body, and a body that stalls is read until the connection times
 * out by itself, minutes later.
 */
async function whileNotAborted<T>(reading: T | Promise<T>, signal: AbortSignal): Promise<T> {
  let onAbort = (): void => undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason);
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([reading, aborted]);
  } finally {
    signal.removeEventListener('abort', onAbort);
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

/**
 * The `error` of the `Bearer` challenge in a `WWW-Authenticate` header, such as
 * `invalid_token`. Registered codes are snake_case, and nothing else is kept, so
 * an API can't put arbitrary text in the error.
 */
function bearerErrorOf(header: string | null): string | undefined {
  const params = header ? /\bBearer\b(.*)$/is.exec(header)?.[1] : undefined;
  if (!params) return undefined;
  const match = /(?:^|[\s,])error\s*=\s*(?:"([^"]*)"|([^\s,"]+))/i.exec(params);
  const code = match?.[1] ?? match?.[2];
  return code && /^[a-z0-9_]{1,64}$/.test(code) ? code : undefined;
}

/** Origin and path: never credentials, query or fragment. */
function redactUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}
