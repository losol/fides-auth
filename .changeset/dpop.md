---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': minor
---

DPoP (RFC 9449): with `dpop: true` in `oauthConfig`, the tokens of a login are bound to a key that never leaves the server, so an access token that leaks is of no use without it. The callback makes a P-256 key for each session and sends a proof with the code exchange; the key is kept with the tokens, sealed in the session. A refresh carries a proof from the same key, and `authorizedFetch` sends the token as `Authorization: DPoP` with a proof for that method, URL and token, answering an API's `DPoP-Nonce` by asking once more. A provider that answers with a bearer token fails the login, so turn it on only where the provider supports DPoP.

Roll this version out to every instance before turning `dpop` on: an earlier beta reads a bound session's token as a bearer token.

Code that sets `Authorization: Bearer` itself from `getTokens` must move to `authorizedFetch` before it turns `dpop` on, or make the proof with `createDpopProof` from `/oidc`.

On the OIDC client: `createDpopKey()`, and a `dpopKey` option on `exchangeCode`, `refresh` and `userInfo`. A response that isn't bound throws a `DpopError`, after its tokens are revoked where the provider has a revocation endpoint. `AuthorizedFetchError.bearerError` now also reads the `error` of a `DPoP` challenge. `/oidc` also exports `createDpopProof` and `dpopThumbprint`.

`Tokens` has two new optional fields, `tokenType` and `dpopKey`. A session with bearer tokens has neither and is sealed as before. A session whose `tokenType` this version doesn't know, as a later version may write, is never sent as a bearer token and never refreshed: `authorizedFetch` throws `unsupported_token_type`, `refreshSession` answers with that reason, the heartbeat answers 503, and the session is left as it is. `createSession` takes a `dpopKey` for tokens that were bound outside the handlers.
