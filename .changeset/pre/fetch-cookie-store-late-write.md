---
'@eventuras/fides-auth': minor
---

`fetchCookieStore` now throws when a cookie is set after `headers()` or `apply()` has taken the cookies, as such a cookie could not reach the browser. Set cookies before building the response.
