---
'@eventuras/fides-auth': minor
---

Fixes from a second security review.

A login under way is now sealed for its provider and client, as a session already was. Two instances that share a secret and an origin, one for each of two providers, could finish each other's logins: provider B could send the browser to A's callback with a code of its choosing, and A would take B's login transaction for its own and sign the user in as whoever the code was for. The transaction's key now has the instance's audience in it. A login that an earlier version started still opens, so one that is under way during an upgrade finishes; until every instance is upgraded, an older one's logins can still be finished by another.

`profile: 'fapi2'` now holds on every path, not only the login the handlers run. `exchangeCode`, `refresh` and `userInfo` throw without a `dpopKey`, `clientCredentials` throws, `createSession` refuses a token response that isn't DPoP-bound with its key, and a bearer session from before the profile was turned on is not refreshed.

The tokens of a refresh that finds its session ended meanwhile, by a logout on another instance say, are revoked instead of dropped: they were good at the provider with nobody holding them. So are the tokens of a refresh the store never took, when the session is then ended with `endUserSessions` or a back-channel logout.

A logout token whose `iat` is more than five minutes old is refused, whatever its `exp`, with 30 seconds allowed for clocks that differ.

`dpop` and `profile` are read when the instance is created. Changing the config object afterwards doesn't turn either off.
