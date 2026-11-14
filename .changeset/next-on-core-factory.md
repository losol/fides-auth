---
'@eventuras/fides-auth-next': major
---

`createFidesAuth` is the core instance from `@eventuras/fides-auth/server`, bound to `cookies()`. It
takes the same config as core's, `sessionStore` included, and has the same members without the
cookie argument: the five handlers, `readSession`, `tryReadSession`, `getTokens`, `refreshSession`,
`createSession`, `updateSession`, `clearSession`, `authorizedFetch`, `cookieNames` and `oidc`.
`readSession` and `tryReadSession` share one read per render.

New: `refreshInProxy(request)` for `proxy.ts`. It refreshes a session whose access token is about
to expire before the page renders, and sets the new cookies on the response and on the forwarded
request.

Breaking:

- The members are renamed: `getCurrentSession` is `readSession`, `tryGetCurrentSession` is
  `tryReadSession`, `tryRefreshCurrentSession` is `refreshSession`, `clearCurrentSession` is
  `clearSession`, and `createAndPersistSession(session)` is `createSession(tokenResponse)`.
  `refreshCurrentSession` goes. `authorizedFetch` no longer takes the session.
- The handlers take their options from `createFidesAuth`: `applicationUrl`, `postLogoutRedirectUri`,
  `validateReturnTo`, `mapSession` and the rest.
- One entry. The subpaths `./auth`, `./cookie-store`, `./request`, `./store`, `./oidc-login`,
  `./oidc-callback`, `./oidc-logout` and `./heartbeat-handler` go, and so do the cookie helpers and
  the core re-exports. `./store` re-exported the store and the React hooks; import the store from
  `@eventuras/fides-auth/browser` and the hooks from `@eventuras/fides-auth-react`.
- No default rate limiter: `globalGETRateLimit`, `globalPOSTRateLimit` and `TokenBucket` go. The
  handlers rate-limit only through `rateLimit`.
