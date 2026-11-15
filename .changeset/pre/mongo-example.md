---
'@eventuras/fides-auth': patch
---

The MongoDB adapter in `docs/server-sessions.md` compiles: `replaceOne` doesn't take `_id` in the
replacement document. It also creates the index that `findMatching` uses. The example has now been
run against MongoDB 8, on its own and through `createFidesAuth`.
