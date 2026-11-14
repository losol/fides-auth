import type { CookieStore } from '@eventuras/fides-auth/server';
import { cookies } from 'next/headers';

/**
 * A {@link CookieStore} over Next's `cookies()`, for the core instance from
 * `@eventuras/fides-auth/server`. It works wherever `cookies()` does. A Server
 * Component can read cookies but not set them, and Next throws on a write there.
 */
export async function nextCookieStore(): Promise<CookieStore> {
  const store = await cookies();
  const cookieStore: CookieStore = {
    get: (name) => store.get(name)?.value ?? null,
    set: (name, value, options) => {
      store.set(name, value, options);
    },
    delete: (name) => {
      store.delete(name);
    },
  };
  return cookieStore;
}
