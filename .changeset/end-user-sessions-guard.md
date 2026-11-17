---
'@eventuras/fides-auth': patch
---

`endUserSessions` no longer ends a record it can't tie to the user. A `findMatching` that returned too much was already kept from ending another user's session, but a record without an ID token, or one that doesn't open, slipped through that check and was deleted, with its refresh token revoked. Such a record is now left alone. An `iss` that is an empty string, an unset variable say, is refused with a `TypeError`: it was read as no issuer, which matches the most. The `merge` example in `docs/server-sessions.md` now follows the rule for a continuation.
