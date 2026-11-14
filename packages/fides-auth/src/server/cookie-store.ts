// server/cookie-store.ts
//
// The cookie contract the server side depends on: read and write a cookie by
// name. Each framework binding implements it over its own cookie API. Methods
// may be sync or async; the library awaits them either way.

import type { CookieOptions } from '../shared/cookies.js';

export interface CookieStore {
  /** Returns the cookie's value, or null/undefined when it is not set. */
  get(name: string): string | null | undefined | Promise<string | null | undefined>;
  /**
   * Sets a cookie. The library deletes one by setting it empty with `maxAge: 0`
   * and the attributes it was set with, so a `__Host-` cookie is deleted too.
   */
  set(name: string, value: string, options?: CookieOptions): void | Promise<void>;
}
