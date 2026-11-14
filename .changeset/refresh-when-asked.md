---
'@eventuras/fides-auth': major
'@eventuras/fides-auth-next': major
---

Nothing refreshes unless the caller asks.

- `refreshSession(cookies, { ifExpiresWithin })` refreshes only when the access token expires
  within that many seconds, and its result says whether it `refreshed`. Without the option it
  refreshes at once. A token whose lifetime the provider didn't give counts as fresh.
- `authorizedFetch` no longer refreshes on a 401: it throws an `http_error`. The `refresh` option,
  the `refresh_failed` reason, `refreshFailure` and `refreshed` in the result go. Call
  `refreshSession({ ifExpiresWithin: 60 })` before it, where cookies can be written.
- In Next, `refreshSession` takes the same option, and `refreshInProxy` takes `ifExpiresWithin` in
  place of `refreshWithinSeconds`. `authorizedFetch` is now safe in a Server Component.

With no implicit refresh, the library never has to know whether cookies can be written, so a
refresh can't spend a rotated refresh token it is unable to save.
