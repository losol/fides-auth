// cookies.ts
//
// Framework-agnostic cookie attributes, size limits, and the access-token cookie
// name. This module performs no I/O — it never reads or writes cookies. Framework
// adapters (Next.js, React Router, …) own the actual cookie store and use these
// values and helpers to configure and size-check the cookies they set.
//
// The companion module `session-cookies.ts` encodes/decodes a session into cookie
// *values*; this module is about the cookie *attributes* and *limits*.

/**
 * Browser per-cookie size limit (RFC 6265: browsers must support at least
 * 4096 bytes for the sum of the cookie's name and value). Cookies at or above
 * this size are silently dropped by the browser, which manifests as a broken
 * login (the cookie is never stored, so the user appears unauthenticated).
 */
export const COOKIE_MAX_BYTES = 4096;

/**
 * Threshold at which an adapter should emit an informational log that a cookie is
 * getting large. This is not an error — a session with many scopes/roles can
 * legitimately approach this size — it just gives visibility before the hard limit.
 */
export const COOKIE_INFO_BYTES = 3500;

/**
 * Thrown when a cookie's name + value would meet or exceed the browser's
 * per-cookie size limit. Setting such a cookie would be silently dropped by the
 * browser, so adapters should fail loudly instead. Callers (e.g. an OIDC callback)
 * can catch this to surface a clear error rather than producing a broken login.
 */
export class CookieTooLargeError extends Error {
  constructor(
    public readonly cookieName: string,
    public readonly size: number,
    public readonly limit: number = COOKIE_MAX_BYTES,
  ) {
    super(
      `Cookie "${cookieName}" is ${size} bytes, which meets or exceeds the browser limit of ${limit} bytes and would be silently dropped`,
    );
    this.name = 'CookieTooLargeError';
  }
}

export interface CookieOptions {
  /** Cookie path (default: '/') */
  path?: string;
  /** Max age in seconds */
  maxAge?: number;
  /** SameSite policy (default: 'lax') */
  sameSite?: 'strict' | 'lax' | 'none';
  /** HTTP only flag (default: true) */
  httpOnly?: boolean;
  /**
   * Secure flag. `true` in {@link defaultSessionCookieOptions} and
   * {@link defaultOAuthCookieOptions}; when omitted from a hand-built options
   * object, the adapter's own default applies.
   */
  secure?: boolean;
}

/**
 * Default cookie options for session cookies.
 * - Secure
 * - HTTP only
 * - Lax same-site policy
 * - 30 days max age
 *
 * `secure` is unconditional rather than derived from NODE_ENV: a deployment that
 * doesn't set it — staging, a container, any non-Next server — would otherwise put
 * the session cookie on the wire in the clear, silently.
 *
 * The cookie spec exempts localhost from the https requirement, so a `Secure`
 * cookie is still set and sent over `http://localhost` and local development is
 * unaffected. Plain http on any other host — a LAN address, a custom dev hostname —
 * needs an explicit `secure: false`.
 */
export const defaultSessionCookieOptions: CookieOptions = {
  path: '/',
  maxAge: 60 * 60 * 24 * 30, // 30 days
  sameSite: 'lax',
  httpOnly: true,
  secure: true,
};

/**
 * Default cookie options for OAuth state/PKCE cookies.
 * - Secure — see {@link defaultSessionCookieOptions}
 * - HTTP only
 * - Lax same-site policy
 * - 10 minutes max age (short-lived for security)
 */
export const defaultOAuthCookieOptions: CookieOptions = {
  path: '/',
  maxAge: 60 * 10, // 10 minutes
  sameSite: 'lax',
  httpOnly: true,
  secure: true,
};

/**
 * Name of the cookie holding the (split-out) access token.
 *
 * The access token — typically a large JWT carrying scopes/roles — is stored in
 * its own cookie so it gets a full per-cookie byte budget, instead of competing
 * for space with the rest of the session inside a single "session" cookie. See
 * {@link CookieTooLargeError} for the limit this works around.
 */
export const ACCESS_TOKEN_COOKIE_NAME = 'session_at';

/**
 * Name of the cookie holding the (split-out) ID token, kept for `id_token_hint`
 * on RP-initiated logout.
 *
 * It gets its own cookie for two reasons: it is a second large JWT, which would
 * eat into the access token's byte budget, and it must outlive access-token
 * expiry — a logout after the session has gone stale is exactly when the hint is
 * needed.
 */
export const ID_TOKEN_COOKIE_NAME = 'session_it';

/**
 * Name of the main session cookie (everything except the split-out access and ID
 * tokens). See {@link ACCESS_TOKEN_COOKIE_NAME} for why the raw tokens are stored
 * apart.
 */
export const SESSION_COOKIE_NAME = 'session';

/**
 * Serialized byte size of a `name=value` cookie pair. The browser per-cookie
 * limit applies to the serialized pair, so the `=` separator is counted too —
 * otherwise a borderline pair (name+value === 4095) would slip through only to be
 * dropped at 4096 once serialized.
 */
export function cookieByteSize(name: string, value: string): number {
  const encoder = new TextEncoder();
  return encoder.encode(name).length + 1 + encoder.encode(value).length;
}

/**
 * Asserts that a `name=value` cookie pair is within the browser's per-cookie
 * limit, throwing {@link CookieTooLargeError} if not. Returns the measured byte
 * size so callers can additionally log when it crosses {@link COOKIE_INFO_BYTES}.
 */
export function assertCookieWithinLimit(name: string, value: string): number {
  const size = cookieByteSize(name, value);
  if (size >= COOKIE_MAX_BYTES) {
    throw new CookieTooLargeError(name, size);
  }
  return size;
}
