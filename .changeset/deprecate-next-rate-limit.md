---
'@eventuras/fides-auth-next': patch
---

Deprecate `globalGETRateLimit`, `globalPOSTRateLimit` and the `TokenBucket`
re-export. The Next handlers still use the default limiter. For your own, call
the handlers from `@eventuras/fides-auth/server` with `nextCookieStore()` and a
`rateLimit` callback; see "Rate limiting" in the README.
