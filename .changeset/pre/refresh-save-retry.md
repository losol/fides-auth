---
'@eventuras/fides-auth': patch
---

A session store that fails once, just after the provider has answered a refresh, no longer costs the user the
session. With a provider that rotates refresh tokens, the store was left holding a spent one: the next refresh got
`invalid_grant`, and under `withLock` the session was deleted. Now the save is tried twice more, after 0.2 and 1
second. If the store still fails, the refresh answers `cause: 'store'` as before, and the instance keeps the new
tokens in memory: the next refresh or update of that session on the same instance saves them without asking the
provider, and a logout revokes them. Another instance doesn't have them, so a store that stays down can still cost
a session whose next refresh lands elsewhere.
