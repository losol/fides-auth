---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-store': minor
'@eventuras/fides-auth-react': patch
'@eventuras/fides-auth-next': patch
---

Structured session-lifecycle logging, so production logs explain logouts.

Every point where the library creates a session, renews one, or decides one
cannot proceed now emits a named event — `session.created`, `session.refreshed`,
`session.rejected`, `session.refresh_failed`, `session.cleared` — with a
correlation id and a low-cardinality `reason` / `cause`. See
`docs/session-events.md` for the taxonomy, the level policy and example LogQL.

**Heartbeat: 503 instead of 401 when the provider is unreachable.** The endpoint
previously answered 401 for a dead refresh token *and* for a network fault or an
IdP 5xx, so a provider blip logged out users whose sessions were valid.
`classifyRefreshFailure` now separates `invalid_grant` (session really is over,
401) from `transport` / `idp_error` (503). Clients already retry non-401
responses with backoff. 401 responses now carry `{ reason }` in the body.

**New APIs.** `tryReadSession`, `tryRefreshSessionInStore` and
`tryDecodeSessionCookies` return the reason or cause instead of a bare `null`, so
consumers can log the same vocabulary the library does. The existing
`readSession`, `refreshSessionInStore` and `decodeSessionCookies` are unchanged
and delegate to them.

**Session correlation id.** `Session.sid` is minted at creation and carried
across refreshes, so one session is one id for its whole life — including through
refresh-token rotation.

**Browser events.** `createHeartbeat` and `startSessionMonitor` take an `onEvent`
callback carrying the same event names, so consumers can beacon the client half
of a session's story to their own endpoint. No transport ships with the library.

`startSessionMonitor` now logs through the pluggable `createLogger` instead of
importing `@eventuras/logger` directly, so `configureAuthLogger()` finally
affects it.
