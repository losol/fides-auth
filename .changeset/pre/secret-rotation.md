---
'@eventuras/fides-auth': minor
---

`secret` takes a list, so a secret can be replaced without logging anyone out. The first one seals, and every one of them opens: `secret: [newSecret, oldSecret]`. A session sealed with the old secret is read as it is, and sealed with the new one the next time it is refreshed or updated. A login that was under way when the secret changed finishes, and `endUserSessions` finds a user's sessions whichever secret their lookup hash was keyed with.

In a fleet replaced one instance at a time, deploy `[old, new]` first, then `[new, old]`, then `new` alone once `sessionDurationSeconds` has passed. The README has the steps under "Replacing the secret". A single secret works as before.
