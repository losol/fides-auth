---
'@eventuras/fides-auth': minor
---

`fetchCookieStore(request)` in `/server` is a `CookieStore` over a Fetch `Request`, for React Router,
Hono, SvelteKit, Astro and other frameworks that hand a route a Request and take a Response.
`apply(response)` copies a handler's response with the cookies it wrote, and `headers()` gives the
`Set-Cookie` lines for a response the route builds itself. It refuses a name, value or path that
isn't cookie-safe.
