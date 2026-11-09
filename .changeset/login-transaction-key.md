---
'@eventuras/fides-auth': patch
---

Login transaction cookies are sealed under a key derived from the secret, so
one can no longer be sent back as a `session` cookie. `isSession` now requires
a `tokens` or `user` object.
