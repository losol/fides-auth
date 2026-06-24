// server/cookie-store.ts
//
// The cookie-store contract the framework-agnostic server handlers depend on.
// A tiny interface — just read/write/delete a cookie by name — that each
// framework adapter (Next.js, React Router, …) implements over its own cookie
// store. Methods may be sync or async; the handlers `await` them either way.

import type { CookieOptions } from '../cookies';

export interface CookieStore {
  /** Returns the cookie's value, or null/undefined when it is not set. */
  get(name: string): string | null | undefined | Promise<string | null | undefined>;
  /** Sets a cookie. Adapters apply their own defaults for any omitted options. */
  set(name: string, value: string, options?: CookieOptions): void | Promise<void>;
  /** Deletes a cookie by name. */
  delete(name: string): void | Promise<void>;
}
