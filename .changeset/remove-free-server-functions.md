---
'@eventuras/fides-auth': major
'@eventuras/fides-auth-next': major
---

The server side is `createFidesAuth` alone. `/server` exports the factory and its types,
`CookieStore`, `SessionStore`, `StoredSession`, `createMemorySessionStore`, `AuthorizedFetchError`,
`CookieTooLargeError`, `SessionSecretError` and `SessionSecret`.

Removed:

- The free `/server` functions: `handleOidcLogin`, `handleOidcCallback`, `handleOidcLogout`,
  `handleHeartbeat`, `readSession`, `tryReadSession`, `persistSession`, `refreshSessionInStore`,
  `tryRefreshSessionInStore`, `readIdToken`, `clearSession`, `authorizedFetch`,
  `cookiePersistence` and `serverPersistence`. The instance has a member for each.
- The login transaction helpers, which the handlers use internally.
- The `/session-cookies`, `/session-refresh` and `/session-validation` entries, and
  `buildSessionFromTokens` and `MapSession` from `/oauth`. Pass `mapSession` to `createFidesAuth`.
- `LegacySession`, `CreateSessionOptions` and the rejected reason `stale_legacy_session`.
- `CookieStore.delete`. The library deletes a cookie by setting it empty with `maxAge: 0`, so a
  store needs only `get` and `set`; `nextCookieStore` has no `delete` either.
- `StoredSession.sid`. Read `correlationId`.
