import type { CookieStore } from '@eventuras/fides-auth/server';
import { cookies } from 'next/headers';

/**
 * Builds a {@link CookieStore} backed by Next.js's request cookie store, for the
 * framework-agnostic server helpers in `@eventuras/fides-auth/server`.
 *
 * Must be called where `next/headers` `cookies()` is available: Server Actions,
 * Route Handlers, or Server Components.
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
