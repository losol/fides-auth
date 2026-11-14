import { describe, it, expect } from 'vitest';

import type { FidesLogger } from '../shared/logger.js';
import { validateReturnUrl } from './return-to.js';

const quiet: FidesLogger = { debug() {}, info() {}, warn() {}, error() {} };

const origin = 'https://example.com';

describe('validateReturnUrl', () => {
  it('returns the returnTo path as a full URL', () => {
    const url = validateReturnUrl(quiet, '/dashboard', origin);
    expect(url.toString()).toBe('https://example.com/dashboard');
  });

  it('falls back to defaultPath when returnTo is null', () => {
    const url = validateReturnUrl(quiet, null, origin, '/home');
    expect(url.pathname).toBe('/home');
  });

  it('falls back to defaultPath when returnTo is undefined', () => {
    const url = validateReturnUrl(quiet, undefined, origin);
    expect(url.pathname).toBe('/');
  });

  it('rejects absolute URLs to a different origin', () => {
    const url = validateReturnUrl(quiet, 'https://evil.com/steal', origin);
    expect(url.origin).toBe(origin);
    expect(url.pathname).toBe('/');
  });

  it('rejects protocol-relative URLs', () => {
    const url = validateReturnUrl(quiet, '//evil.com/steal', origin);
    expect(url.origin).toBe(origin);
    expect(url.pathname).toBe('/');
  });

  it('allows same-origin absolute URLs', () => {
    const url = validateReturnUrl(quiet, 'https://example.com/safe', origin);
    expect(url.toString()).toBe('https://example.com/safe');
  });

  it('handles unusual paths gracefully', () => {
    // new URL('://broken', origin) resolves to a relative path, which is fine
    const url = validateReturnUrl(quiet, '://broken', origin, '/fallback');
    expect(url.origin).toBe(origin);
  });

  it('preserves query parameters in returnTo', () => {
    const url = validateReturnUrl(quiet, '/search?q=test', origin);
    expect(url.pathname).toBe('/search');
    expect(url.searchParams.get('q')).toBe('test');
  });

  it('uses custom defaultPath', () => {
    const url = validateReturnUrl(quiet, null, origin, '/admin');
    expect(url.pathname).toBe('/admin');
  });
});
