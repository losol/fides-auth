---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': minor
---

`createFidesAuth<AppData>(…)` types `session.data` in everything the instance hands out: reads,
`refreshSession`, `createSession`, `updateSession`, `mapSession` and `storeFields`. `Session` was
generic already, but the instance wasn't, so `data` came back as an open record and every use
needed a cast. Without a type argument nothing changes.
