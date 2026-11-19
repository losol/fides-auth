// server/authorized-fetch.ts
//
// fetch() with an access token, locked to one API base. The token goes only to
// URLs under `allowedBase` and never follows a redirect. It never refreshes: a
// caller that wants fresh tokens asks for them first, with refreshSession.
//
// A DPoP-bound token (RFC 9449) goes as `Authorization: DPoP`, with a proof
// for this method and URL. An API that asks for a nonce is asked once more
// with it, when the body can be sent twice.

import type { FidesLogger } from '../shared/logger.js';
import type { Tokens } from '../shared/types.js';
import { createDpopProof } from '../protocol/dpop.js';
import { presentationOfRecord } from '../session/record.js';

const DEFAULT_TIMEOUT_MS = 10_000;

/** Why {@link authorizedFetch} failed. */
export type AuthorizedFetchErrorReason =
  /** The URL is outside `allowedBase` or carries credentials. Nothing was sent. */
  | 'url_not_allowed'
  /** The session has no access token. Nothing was sent. */
  | 'no_access_token'
  /**
   * The access token is of a type this version can't present: a later version
   * wrote the session, or the key a DPoP-bound token needs is missing.
   * Nothing was sent.
   */
  | 'unsupported_token_type'
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
   * `WWW-Authenticate` (RFC 6750 §3), or of its `DPoP` challenge (RFC 9449 §7.1). `invalid_token` means the token is expired,
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
  dpopNonces: DpopNonces = new Map(),
): Promise<AuthorizedFetchResult<T>> {
  const { allowedBase, parse, timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options;
  const target = resolveAllowedUrl(url, allowedBase, logger);
  const request = { method: (init.method ?? 'GET').toUpperCase(), url: redactUrl(target) };

  const sentAt = Date.now();
  const { response, timeout, signal, unlink } = await send(tokens, target, init, timeoutMs, request, dpopNonces);
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

/** The escapes a dot segment can hide in: `.`, `/`, `\`, `;`, and `%` for an escape of an escape. */
const HIDING = /%(2e|2f|5c|3b|25)/gi;

/**
 * Whether the path has a `.` or `..` segment, in any of its encodings. A gateway
 * that decodes before it routes would resolve `..%2f` or `%252e%252e` out of the base.
 *
 * Each escape is decoded on its own, so a malformed one elsewhere in the path
 * doesn't stop the rest from being looked at.
 */
function hasDotSegment(pathname: string): boolean {
  let path = pathname;
  for (let round = 0; round <= 3; round++) {
    const dotted = path
      .split(/[/\\]/)
      .some((segment) => segment === '.' || segment === '..' || /^\.\.?;/.test(segment));
    if (dotted) return true;
    const decoded = path.replace(HIDING, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
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

/**
 * The `DPoP-Nonce` each API gave last, by origin. An instance has its own, so
 * a request rarely needs to be sent twice.
 */
export type DpopNonces = Map<string, string>;

/** At most this many origins are remembered. An app calls a handful. */
const MAX_NONCE_ORIGINS = 100;

function rememberNonce(nonces: DpopNonces, origin: string, response: Response): void {
  const nonce = response.headers.get('dpop-nonce');
  if (!nonce) return;
  nonces.delete(origin);
  nonces.set(origin, nonce);
  if (nonces.size > MAX_NONCE_ORIGINS) {
    const oldest = nonces.keys().next().value;
    if (oldest !== undefined) nonces.delete(oldest);
  }
}

/** Whether a response asks for the request again, with the nonce it gives (RFC 9449 §9). */
function asksForNonce(response: Response): boolean {
  return (
    response.status === 401 &&
    !!response.headers.get('dpop-nonce') &&
    /\buse_dpop_nonce\b/.test(response.headers.get('www-authenticate') ?? '')
  );
}

/**
 * Whether a body can be sent a second time: the kinds that are held whole.
 * A stream, or anything else that is read as it is sent, is spent by the
 * first request and would go out empty the second time.
 */
function canSendAgain(body: RequestInit['body']): boolean {
  return (
    body === undefined ||
    body === null ||
    typeof body === 'string' ||
    body instanceof URLSearchParams ||
    body instanceof FormData ||
    body instanceof Blob ||
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body)
  );
}

async function send(
  tokens: Tokens | null | undefined,
  target: URL,
  init: RequestInit,
  timeoutMs: number,
  request: { method: string; url: string },
  dpopNonces: DpopNonces,
): Promise<Attempt> {
  const token = tokens?.accessToken;
  if (!tokens || !token) throw new AuthorizedFetchError('no_access_token', request);
  const presentation = presentationOfRecord(tokens);
  // Never as a bearer token: where it is refused, it has still been sent.
  if (presentation === null) throw new AuthorizedFetchError('unsupported_token_type', request);

  const timeout = AbortSignal.timeout(timeoutMs);
  const { signal, unlink } = linkSignals(timeout, init.signal);

  const attempt = async (): Promise<Response> => {
    const headers = new Headers(init.headers);
    try {
      headers.set('Authorization', `${presentation === 'dpop' ? 'DPoP' : 'Bearer'} ${token}`);
    } catch {
      // A token with CR, LF or NUL: the TypeError's message would carry the token.
      throw new AuthorizedFetchError('no_access_token', request);
    }
    if (presentation === 'dpop' && tokens.dpopKey) {
      let proof: string;
      try {
        proof = await createDpopProof(tokens.dpopKey, {
          method: request.method,
          url: target,
          accessToken: token,
          nonce: dpopNonces.get(target.origin),
        });
      } catch {
        // A key that doesn't sign: nothing was sent, and sending again won't help.
        throw new AuthorizedFetchError('unsupported_token_type', request);
      }
      headers.set('DPoP', proof);
    }
    // The method as the proof names it: `patch` is sent as it is written, and refused.
    const response = await fetch(target, {
      ...init,
      method: request.method,
      headers,
      signal,
      redirect: 'error',
    });
    if (presentation === 'dpop') rememberNonce(dpopNonces, target.origin, response);
    return response;
  };

  try {
    let response = await attempt();
    if (presentation === 'dpop' && asksForNonce(response) && canSendAgain(init.body)) {
      // Nothing of this answer is read: the API only said which nonce it wants.
      await response.body?.cancel();
      response = await attempt();
    }
    return { response, timeout, signal, unlink };
  } catch (error) {
    unlink();
    if (error instanceof AuthorizedFetchError) throw error;
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
 * The `error` of the `Bearer` or `DPoP` challenge in a `WWW-Authenticate` header, such as
 * `invalid_token`. Registered codes are snake_case, and nothing else is kept, so
 * an API can't put arbitrary text in the error.
 */
function bearerErrorOf(header: string | null): string | undefined {
  const params = header ? /\b(?:Bearer|DPoP)\b(.*)$/is.exec(header)?.[1] : undefined;
  if (!params) return undefined;
  const match = /(?:^|[\s,])error\s*=\s*(?:"([^"]*)"|([^\s,"]+))/i.exec(params);
  const code = match?.[1] ?? match?.[2];
  return code && /^[a-z0-9_]{1,64}$/.test(code) ? code : undefined;
}

/** Origin and path: never credentials, query or fragment. */
function redactUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}
