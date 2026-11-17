---
'@eventuras/fides-auth': minor
---

A session is now sealed with a key derived from the secret, the provider and client (`issuer` and `clientId`), and
where it is kept: its own store key under a `sessionStore`. Before, every session was sealed with the secret itself,
so a sealed record opened wherever the secret was. Someone with write access to the store could copy another user's
record over their own row and read it with their own handle; a row from a leaked store opened as a session cookie
on any instance running cookie storage with the same secret, during a rollout from cookies to a store say; and two
`createFidesAuth` instances on one origin with the same secret, for different providers or clients, read each
other's sessions, roles included. None of these open now: they read as `unreadable_session`.

**Everyone logs in again once**, since sessions sealed by an earlier beta don't open. From here on, changing
`issuer` or `clientId` ends all sessions, as changing the secret does. Decryption also accepts only the algorithms
the library seals with (`dir`, `A256GCM`).

A row put back under its own key after a logout still reads until `expiresAt`: sealing can't cover that, and
`docs/server-sessions.md` now says that write access to the store is trusted to that extent.
