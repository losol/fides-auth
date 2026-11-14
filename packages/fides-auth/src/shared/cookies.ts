// cookies.ts
//
// Framework-agnostic cookie attributes and size limits. This module performs no
// I/O: it never reads or writes cookies. The session storages in
// `server/session-storage.ts` use these values to set and size-check theirs.

/**
 * Browser per-cookie size limit (RFC 6265: browsers must support at least
 * 4096 bytes for the sum of the cookie's name and value). Cookies at or above
 * this size are silently dropped by the browser, which manifests as a broken
 * login (the cookie is never stored, so the user appears unauthenticated).
 */
export const COOKIE_MAX_BYTES = 4096;

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
   * Secure flag. `true` in {@link defaultOAuthCookieOptions}; when omitted from
   * a hand-built options object, the adapter's own default applies.
   */
  secure?: boolean;
}

/**
 * Default cookie options for the login transaction cookies.
 * - Secure
 * - HTTP only
 * - Lax same-site policy
 * - 10 minutes max age (short-lived for security)
 *
 * `secure` is unconditional rather than derived from NODE_ENV: a deployment that
 * doesn't set it — staging, a container, any non-Next server — would otherwise put
 * the cookie on the wire in the clear, silently. The cookie spec exempts localhost
 * from the https requirement, so local development over `http://localhost` is
 * unaffected.
 */
export const defaultOAuthCookieOptions: CookieOptions = {
  path: '/',
  maxAge: 60 * 10, // 10 minutes
  sameSite: 'lax',
  httpOnly: true,
  secure: true,
};

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
 * limit, throwing {@link CookieTooLargeError} if not. Returns the measured byte size.
 */
export function assertCookieWithinLimit(name: string, value: string): number {
  const size = cookieByteSize(name, value);
  if (size >= COOKIE_MAX_BYTES) {
    throw new CookieTooLargeError(name, size);
  }
  return size;
}
