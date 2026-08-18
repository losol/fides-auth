---
'@eventuras/fides-auth-next': minor
'@eventuras/fides-auth-store': patch
---

Make the session event vocabulary reachable from Next.js.

0.13.0 added `tryReadSession` / `tryRefreshSessionInStore` so a proxy or status
route could log the same reasons the library does — but they take a `CookieStore`
and `nextCookieStore` was never exported, so the primary consumer could not
actually use them without hand-rolling an adapter over `next/headers`.

`@eventuras/fides-auth-next` now provides:

- `tryGetCurrentSession()` — the reason-carrying read, cached per render and
  sharing `getCurrentSession`'s decrypt, so asking why there is no session costs
  nothing extra.
- `tryRefreshCurrentSession()` — returns `cause`, so a route can answer 503
  rather than ending a session over a provider blip.
- `clearCurrentSession()` now emits `session.cleared` and takes an optional
  trigger (defaults to `logout`).
- `nextCookieStore` is exported, also at `@eventuras/fides-auth-next/cookie-store`,
  for driving the framework-agnostic helpers directly.
- The event vocabulary (`SESSION_EVENT`, `logSessionEvent`, the reason and cause
  types) and the pluggable logger (`createLogger`, `configureLogger`) are
  re-exported from the package root, so logging an event needs no imports from
  outside this package.

The Next session/request/cookie helpers and the auth store now log through the
pluggable `createLogger` rather than importing `@eventuras/logger` directly, so
`configureAuthLogger()` reaches them — it previously did not. Logs from those
modules move to whatever factory you configure, which for anyone already calling
`configureAuthLogger()` is the same place they were going anyway. With no direct
import left, `@eventuras/logger` is no longer a dependency of
`@eventuras/fides-auth-next`; it still arrives via `@eventuras/fides-auth-store`.
