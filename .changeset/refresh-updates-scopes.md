---
'@eventuras/fides-auth': patch
---

A refresh updates `session.scopes` when its response names the scope. They were set at login only, so
a scope the provider took away stayed on the session until the next login, and an app that gates
features on `session.scopes` kept showing them.
