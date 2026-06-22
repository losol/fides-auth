---
"@eventuras/fides-auth-next": minor
---

Add a size guard for auth cookies. `setAuthCookie` now measures the cookie's
name + value and throws a new exported `CookieTooLargeError` at or above the
browser's 4096-byte per-cookie limit, instead of letting the browser silently
drop the cookie (which manifested as a broken login). An informational log is
emitted at 3500 bytes for visibility before the hard limit.
