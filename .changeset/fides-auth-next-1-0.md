---
'@eventuras/fides-auth-next': major
---

1.0, on core's `createFidesAuth`. Users log in again once after the upgrade. The
[upgrade guide](https://github.com/losol/fides-auth/blob/main/packages/fides-auth/docs/migrating-to-1.0.md)
maps every 0.x API to what replaces it.

- `createFidesAuth(config)` is the core instance bound to `cookies()`. Reads are cached per render,
  and `refreshInProxy` refreshes a session in `proxy.ts` before the page renders.
- One entry. The subpaths, the cookie helpers, the core re-exports and `./store` are gone.
- No default rate limiter: pass `rateLimit`.
- `@eventuras/fides-auth` is a peer dependency. Needs Node 22.
