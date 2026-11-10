---
'@eventuras/fides-auth-next': minor
---

`createFidesAuth` now returns `authorizedFetch(session, url, options)`, which on a
401 refreshes the session in the cookies and retries once. Parallel calls in one
request share one refresh. The refresh works only in Server Actions and Route
Handlers; in a Server Component pass `refresh: false`. `AuthorizedFetchError` and
its types are re-exported.
