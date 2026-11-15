// server/fetch-cookie-store.ts
//
// A CookieStore over a Fetch `Request`, for frameworks that hand a route a
// Request and take a Response back: React Router, Hono, SvelteKit, Astro and
// the like. It reads the request's `Cookie` header and keeps what is written,
// to go out as `Set-Cookie` headers on the response.
//
// Only Web APIs, so it runs on Node, on edge runtimes and in workers.

import type { CookieOptions } from '../shared/cookies.js';
import type { CookieStore } from './cookie-store.js';

/** A {@link CookieStore} over a Fetch request, which carries its writes to a response. */
export interface FetchCookieStore extends CookieStore {
  /**
   * New headers with a `Set-Cookie` line for each cookie written so far, after
   * the ones in `init`. For a response the route builds itself.
   */
  headers(init?: HeadersInit): Headers;
  /**
   * A copy of `response` with those `Set-Cookie` lines added. For a response a
   * handler such as `handleOidcLogin` returned.
   */
  apply(response: Response): Response;
}

// RFC 6265: a cookie name is a token, and a value is made of cookie-octets.
// Anything else could end the header or start another attribute.
const NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const VALUE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;
// A path is cut off by `;`, and a control character could end the header.
const PATH = /^[\x20-\x3A\x3C-\x7E]*$/;

/** The request's cookies by name. The first of a name wins, as the more specific path comes first. */
function parseCookies(header: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const pair of header?.split(';') ?? []) {
    const separator = pair.indexOf('=');
    if (separator === -1) continue;
    const name = pair.slice(0, separator).trim();
    if (name && !cookies.has(name)) cookies.set(name, pair.slice(separator + 1).trim());
  }
  return cookies;
}

/**
 * One `Set-Cookie` header value.
 *
 * @throws TypeError if the name, value or path holds a character that isn't allowed there.
 */
function serialize(name: string, value: string, options: CookieOptions = {}): string {
  const path = options.path ?? '/';
  if (!NAME.test(name) || !VALUE.test(value) || !PATH.test(path)) {
    throw new TypeError(`Refusing to write cookie "${name}": its name, value or path is not cookie-safe`);
  }
  const parts = [`${name}=${value}`, `Path=${path}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure !== false) parts.push('Secure');
  const sameSite = options.sameSite ?? 'lax';
  parts.push(`SameSite=${sameSite.charAt(0).toUpperCase()}${sameSite.slice(1)}`);
  return parts.join('; ');
}

/**
 * A {@link CookieStore} over `request`'s cookies. Pass it to the members of
 * `createFidesAuth`, then put what they wrote on the response:
 *
 * ```ts
 * const cookies = fetchCookieStore(request);
 * return cookies.apply(await auth.handleOidcLogin(request, cookies));
 * ```
 *
 * A cookie written during the request reads back from the store, as it would
 * from the browser. Values are written as they are, not encoded: the
 * library's own are cookie-safe, and a write of anything else throws a
 * TypeError. Cookies are `HttpOnly`, `Secure` and `SameSite=Lax` on `/` unless
 * the options say otherwise, and `maxAge: 0` deletes one.
 */
export function fetchCookieStore(request: Pick<Request, 'headers'>): FetchCookieStore {
  const sent = parseCookies(request.headers.get('cookie'));
  // By name, so a cookie written twice goes out once, as it was written last.
  const written = new Map<string, { value: string; deleted: boolean; header: string }>();

  function headers(init?: HeadersInit): Headers {
    const result = new Headers(init);
    for (const { header } of written.values()) result.append('Set-Cookie', header);
    return result;
  }

  return {
    get(name) {
      const write = written.get(name);
      if (write) return write.deleted ? null : write.value;
      return sent.get(name) ?? null;
    },

    set(name, value, options) {
      // Deleted first, so the line for the last write also comes last.
      written.delete(name);
      written.set(name, {
        value,
        deleted: options?.maxAge === 0,
        header: serialize(name, value, options),
      });
    },

    headers,

    apply(response) {
      // A copy: the headers of a redirect or a fetched response can't be changed.
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: headers(response.headers),
      });
    },
  };
}
