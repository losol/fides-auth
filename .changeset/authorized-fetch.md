---
'@eventuras/fides-auth': minor
---

New `authorizedFetch(session, url, { allowedBase, parse?, timeoutMs?, refresh? })`
in `@eventuras/fides-auth/server`. It sends the access token only to URLs under
`allowedBase`, refuses redirects, times out after 10 s, and throws a typed
`AuthorizedFetchError`. On a 401 it calls `refresh` once (e.g.
`tryRefreshSessionInStore`) and retries; the result carries the session to use next.
