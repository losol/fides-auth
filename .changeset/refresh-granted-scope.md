---
'@eventuras/fides-auth': patch
---

A refresh sends no `scope`, so the provider keeps the scope it granted at login. Sending the
configured scope failed with `invalid_scope` whenever the provider granted less, e.g. without
`offline_access`, and the session could never be refreshed.
