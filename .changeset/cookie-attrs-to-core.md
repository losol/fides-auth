---
"@eventuras/fides-auth": minor
"@eventuras/fides-auth-next": patch
---

Move the framework-agnostic cookie attributes, size limits, and size guard into
the core package.

The new `@eventuras/fides-auth/cookies` export holds `CookieOptions`,
`defaultSessionCookieOptions`, `defaultOAuthCookieOptions`,
`ACCESS_TOKEN_COOKIE_NAME`, the `COOKIE_MAX_BYTES`/`COOKIE_INFO_BYTES` limits,
the `CookieTooLargeError` class, and pure `cookieByteSize` /
`assertCookieWithinLimit` helpers — none of which need a framework. This makes
them reusable by future adapters (e.g. React Router) instead of living only in
the Next.js binding.

`@eventuras/fides-auth-next` now re-exports these from the core package and keeps
only the actual cookie I/O (via `next/headers`). Its public API is unchanged.
