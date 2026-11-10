---
'@eventuras/fides-auth': patch
---

`encodeSessionCookies` and `serverPersistence` throw a `TypeError` for a session
with neither `tokens` nor `user`, instead of writing one that reads back as null.
