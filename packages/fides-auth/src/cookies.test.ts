import { describe, it, expect } from 'vitest';

import {
  COOKIE_MAX_BYTES,
  CookieTooLargeError,
  ACCESS_TOKEN_COOKIE_NAME,
  ID_TOKEN_COOKIE_NAME,
  defaultSessionCookieOptions,
  defaultOAuthCookieOptions,
  cookieByteSize,
  assertCookieWithinLimit,
} from './cookies';

describe('cookieByteSize', () => {
  it('counts name + "=" + value in UTF-8 bytes', () => {
    // 4 + 1 + 5 = 10
    expect(cookieByteSize('sess', 'value')).toBe(10);
  });

  it('counts multi-byte characters by their UTF-8 length', () => {
    // "é" is 2 bytes in UTF-8: 1 (name) + 1 (=) + 2 (value) = 4
    expect(cookieByteSize('x', 'é')).toBe(4);
  });
});

describe('assertCookieWithinLimit', () => {
  it('returns the byte size for a pair under the limit', () => {
    expect(assertCookieWithinLimit('session', 'short')).toBe(cookieByteSize('session', 'short'));
  });

  it('throws CookieTooLargeError at or above the browser limit', () => {
    const name = 'session';
    // value sized so that name + '=' + value === COOKIE_MAX_BYTES exactly
    const value = 'a'.repeat(COOKIE_MAX_BYTES - name.length - 1);
    expect(cookieByteSize(name, value)).toBe(COOKIE_MAX_BYTES);
    expect(() => assertCookieWithinLimit(name, value)).toThrow(CookieTooLargeError);
  });

  it('does not throw just below the limit', () => {
    const name = 'session';
    const value = 'a'.repeat(COOKIE_MAX_BYTES - name.length - 2);
    expect(cookieByteSize(name, value)).toBe(COOKIE_MAX_BYTES - 1);
    expect(() => assertCookieWithinLimit(name, value)).not.toThrow();
  });
});

describe('CookieTooLargeError', () => {
  it('carries the cookie name, size, and default limit', () => {
    const err = new CookieTooLargeError('session', 5000);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('CookieTooLargeError');
    expect(err.cookieName).toBe('session');
    expect(err.size).toBe(5000);
    expect(err.limit).toBe(COOKIE_MAX_BYTES);
  });
});

describe('cookie defaults', () => {
  it('exposes the split cookie names', () => {
    expect(ACCESS_TOKEN_COOKIE_NAME).toBe('session_at');
    expect(ID_TOKEN_COOKIE_NAME).toBe('session_it');
  });

  it('uses lax, httpOnly, root-path defaults', () => {
    for (const opts of [defaultSessionCookieOptions, defaultOAuthCookieOptions]) {
      expect(opts.path).toBe('/');
      expect(opts.sameSite).toBe('lax');
      expect(opts.httpOnly).toBe(true);
    }
  });

  it('sets secure unconditionally, not only when NODE_ENV is production', () => {
    // A deployment that doesn't set NODE_ENV must not silently drop the flag.
    for (const opts of [defaultSessionCookieOptions, defaultOAuthCookieOptions]) {
      expect(opts.secure).toBe(true);
    }
  });

  it('keeps OAuth/PKCE cookies short-lived relative to session cookies', () => {
    expect(defaultOAuthCookieOptions.maxAge).toBeLessThan(defaultSessionCookieOptions.maxAge!);
  });
});
