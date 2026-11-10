---
'@eventuras/fides-auth': minor
---

The library no longer reads `SESSION_SECRET`: `getSessionSecret` and
`getSessionSecretUint8Array` are removed. `handleOidcLogin` and
`handleOidcCallback` require `secret`; `handleOidcLogout` and `handleHeartbeat`
require `secret` or `persistence`. A missing, empty or non-32-byte secret (64
hex characters or a `Uint8Array`) throws a `TypeError` on first use, session
reads included.

Migration: pass `secret` to every handler (e.g. `process.env.SESSION_SECRET`),
and replace `getSessionSecret()` with your own read of it.
