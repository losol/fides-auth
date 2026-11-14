// The `/cookies` entry, deprecated. The code lives in shared/cookies.ts. Each
// export is re-declared to carry the tag.

import {
  ACCESS_TOKEN_COOKIE_NAME as ACCESS_TOKEN_COOKIE_NAME_IMPL,
  assertCookieWithinLimit as assertCookieWithinLimitImpl,
  COOKIE_INFO_BYTES as COOKIE_INFO_BYTES_IMPL,
  COOKIE_MAX_BYTES as COOKIE_MAX_BYTES_IMPL,
  type CookieOptions as CookieOptionsImpl,
  CookieTooLargeError as CookieTooLargeErrorImpl,
  cookieByteSize as cookieByteSizeImpl,
  defaultOAuthCookieOptions as defaultOAuthCookieOptionsImpl,
  defaultSessionCookieOptions as defaultSessionCookieOptionsImpl,
  ID_TOKEN_COOKIE_NAME as ID_TOKEN_COOKIE_NAME_IMPL,
  SESSION_COOKIE_NAME as SESSION_COOKIE_NAME_IMPL,
  SESSION_REF_COOKIE_NAME as SESSION_REF_COOKIE_NAME_IMPL,
} from './shared/cookies.js';

/** @deprecated Import from `@eventuras/fides-auth`. `/cookies` goes in 1.0. */
export type CookieOptions = CookieOptionsImpl;
/** @deprecated Import from `@eventuras/fides-auth/server`. `/cookies` goes in 1.0. */
export const CookieTooLargeError = CookieTooLargeErrorImpl;
/** @deprecated Import from `@eventuras/fides-auth/server`. `/cookies` goes in 1.0. */
export type CookieTooLargeError = CookieTooLargeErrorImpl;

/** @deprecated `/cookies` goes in 1.0. The library sets its own cookies. */
export const COOKIE_MAX_BYTES = COOKIE_MAX_BYTES_IMPL;
/** @deprecated `/cookies` goes in 1.0. The library sets its own cookies. */
export const COOKIE_INFO_BYTES = COOKIE_INFO_BYTES_IMPL;
/** @deprecated `/cookies` goes in 1.0. The library sets its own cookies. */
export const defaultSessionCookieOptions = defaultSessionCookieOptionsImpl;
/** @deprecated `/cookies` goes in 1.0. The library sets its own cookies. */
export const defaultOAuthCookieOptions = defaultOAuthCookieOptionsImpl;
/** @deprecated `/cookies` goes in 1.0. The library sets its own cookies. */
export const cookieByteSize = cookieByteSizeImpl;
/** @deprecated `/cookies` goes in 1.0. The library sets its own cookies. */
export const assertCookieWithinLimit = assertCookieWithinLimitImpl;
/** @deprecated `/cookies` goes in 1.0. From 1.0, read the names from the `createFidesAuth` instance. */
export const ACCESS_TOKEN_COOKIE_NAME = ACCESS_TOKEN_COOKIE_NAME_IMPL;
/** @deprecated `/cookies` goes in 1.0. From 1.0, read the names from the `createFidesAuth` instance. */
export const ID_TOKEN_COOKIE_NAME = ID_TOKEN_COOKIE_NAME_IMPL;
/** @deprecated `/cookies` goes in 1.0. From 1.0, read the names from the `createFidesAuth` instance. */
export const SESSION_COOKIE_NAME = SESSION_COOKIE_NAME_IMPL;
/** @deprecated `/cookies` goes in 1.0. From 1.0, read the names from the `createFidesAuth` instance. */
export const SESSION_REF_COOKIE_NAME = SESSION_REF_COOKIE_NAME_IMPL;
