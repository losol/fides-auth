---
'@eventuras/fides-auth': patch
---

The upgrade guide says what to do where 0.x sealed a value of its own. `createEncryptedJWT` and `decryptJWT`
were listed as gone without a recipe, and `createAndPersistSession(session)` pointed to
`createSession(tokenResponse)`, which is not the same for a session that didn't come from a login. Such sessions
are outside the library; the guide now says so and shows how to seal a value with jose.
