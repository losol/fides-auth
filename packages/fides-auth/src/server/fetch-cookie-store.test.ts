/**
 * fetchCookieStore: what it reads from a request, what it writes for a
 * response, and what it refuses to write.
 */
import { describe, expect, it } from 'vitest';

import { fetchCookieStore } from './fetch-cookie-store.js';

const request = (cookie?: string) =>
  new Request('https://app.test/', cookie === undefined ? undefined : { headers: { cookie } });

describe('fetchCookieStore: reading', () => {
  it('reads the request cookies by name', () => {
    const cookies = fetchCookieStore(request('a=1; __Host-session=abc.def; b=x=y'));
    expect(cookies.get('a')).toBe('1');
    expect(cookies.get('__Host-session')).toBe('abc.def');
    // Only the first `=` separates the name from the value.
    expect(cookies.get('b')).toBe('x=y');
    expect(cookies.get('missing')).toBeNull();
  });

  it('takes the first cookie of a name, and ignores what is not a pair', () => {
    const cookies = fetchCookieStore(request('a=first;  a=second; stray; =nameless'));
    expect(cookies.get('a')).toBe('first');
    expect(cookies.get('stray')).toBeNull();
    expect(cookies.get('')).toBeNull();
  });

  it('reads nothing from a request without cookies', () => {
    expect(fetchCookieStore(request()).get('a')).toBeNull();
  });

  it('reads back what was written, and nothing once it is deleted', () => {
    const cookies = fetchCookieStore(request('a=old'));
    cookies.set('a', 'new');
    expect(cookies.get('a')).toBe('new');
    cookies.set('a', '', { maxAge: 0 });
    expect(cookies.get('a')).toBeNull();
  });
});

describe('fetchCookieStore: writing', () => {
  it('writes a cookie with safe defaults', () => {
    const cookies = fetchCookieStore(request());
    cookies.set('a', '1');
    expect(cookies.headers().getSetCookie()).toEqual(['a=1; Path=/; HttpOnly; Secure; SameSite=Lax']);
  });

  it('writes the options it is given', () => {
    const cookies = fetchCookieStore(request());
    cookies.set('a', '1', { path: '/auth', maxAge: 600.9, httpOnly: false, secure: false, sameSite: 'strict' });
    expect(cookies.headers().getSetCookie()).toEqual(['a=1; Path=/auth; Max-Age=600; SameSite=Strict']);
  });

  it('deletes with Max-Age=0 and the cookie\'s own attributes', () => {
    const cookies = fetchCookieStore(request('__Host-session=abc'));
    cookies.set('__Host-session', '', { path: '/', secure: true, httpOnly: true, sameSite: 'lax', maxAge: 0 });
    expect(cookies.headers().getSetCookie()).toEqual([
      '__Host-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
    ]);
  });

  it('sends a cookie written twice once, as it was written last, and last in line', () => {
    const cookies = fetchCookieStore(request());
    cookies.set('a', '1');
    cookies.set('b', '2');
    cookies.set('a', '3');
    expect(cookies.headers().getSetCookie().map((line) => line.split(';')[0])).toEqual(['b=2', 'a=3']);
  });

  it.each([
    ['a name with a space', 'a b', '1', undefined],
    ['a name with a separator', 'a;b', '1', undefined],
    ['an empty name', '', '1', undefined],
    ['a value with a line break', 'a', '1\r\nSet-Cookie: evil=1', undefined],
    ['a value with a semicolon', 'a', '1; Domain=evil.test', undefined],
    ['a value with a space', 'a', 'one two', undefined],
    ['a path with a semicolon', 'a', '1', '/; Domain=evil.test'],
  ])('refuses %s', (_, name, value, path) => {
    const cookies = fetchCookieStore(request());
    expect(() => cookies.set(name, value, { path })).toThrow(TypeError);
    expect(cookies.headers().getSetCookie()).toEqual([]);
  });
});

describe('fetchCookieStore: the response', () => {
  it('adds its cookies after the headers it is given', () => {
    const cookies = fetchCookieStore(request());
    cookies.set('a', '1');
    const headers = cookies.headers({ 'Cache-Control': 'no-store', 'Set-Cookie': 'other=1' });
    expect(headers.get('cache-control')).toBe('no-store');
    expect(headers.getSetCookie()).toEqual(['other=1', 'a=1; Path=/; HttpOnly; Secure; SameSite=Lax']);
  });

  it('has no Set-Cookie when nothing was written', () => {
    expect(fetchCookieStore(request('a=1')).headers().getSetCookie()).toEqual([]);
  });

  it('copies a response with its cookies added', async () => {
    const cookies = fetchCookieStore(request());
    cookies.set('a', '1');
    const original = new Response('body', {
      status: 201,
      statusText: 'Created',
      headers: { 'Content-Type': 'text/plain', 'Set-Cookie': 'kept=1' },
    });

    const response = cookies.apply(original);
    expect(response.status).toBe(201);
    expect(response.statusText).toBe('Created');
    expect(response.headers.get('content-type')).toBe('text/plain');
    expect(response.headers.getSetCookie()).toEqual(['kept=1', 'a=1; Path=/; HttpOnly; Secure; SameSite=Lax']);
    expect(await response.text()).toBe('body');
    expect(original.headers.getSetCookie()).toEqual(['kept=1']);
  });

  it('adds cookies to a redirect, whose own headers can\'t be changed', () => {
    const cookies = fetchCookieStore(request());
    cookies.set('a', '1');
    const response = cookies.apply(Response.redirect('https://idp.test/authorize', 302));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('https://idp.test/authorize');
    expect(response.headers.getSetCookie()).toHaveLength(1);
  });
});
