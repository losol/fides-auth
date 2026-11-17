---
'@eventuras/fides-auth': patch
---

The same secret listed twice in `secret` counts once. A config that always passes a current and a previous secret has the same value in both between two changes, and that now costs nothing: before, each key was derived and each search for a user's sessions was made twice. It is logged once as a warning when the instance starts to work, since a list like that is also what a change of secret that didn't happen looks like. The same bytes written as hex in another case, or as a `Uint8Array`, are the same secret.
