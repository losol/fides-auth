---
'@eventuras/fides-auth': major
---

`createFidesAuth` in `/server` is the server side as one object. It holds the OIDC client, the
session storage and the guards, and its members take the `Request` and a `CookieStore`:
`handleOidcLogin`, `handleOidcCallback`, `handleOidcLogout`, `handleHeartbeat`,
`handleSessionInfo`, `readSession`, `tryReadSession`, `getTokens`, `refreshSession`,
`createSession`, `updateSession`, `clearSession` and `authorizedFetch`. A session lives in the
`__Host-session` cookie, in at most three chunks, or in a `sessionStore` with only a handle in the
cookie. Logout and heartbeat answer only a same-origin `POST`. `SessionSecretError` is exported from
`/server`.

Breaking:

- `Session` is the new session shape: `correlationId`, `createdAt`, `expiresAt`, `user`, `scopes`,
  `idp` and `data`. Tokens are not on it; `getTokens` returns them.
- Session events carry `correlationId` instead of `sid`. Log queries that filter on `sid` need the
  new name.
- `SessionRejectedReason` adds `session_expired`.
- `StoredSession` adds `correlationId` and the lookup fields `iss`, `subHash` and `idpSidHash`. A
  custom `SessionStore` should save them. `sid` goes.
- `createFidesAuth` doesn't read 0.x sessions, so users log in again once. It deletes their cookies
  the next time it writes a session.
