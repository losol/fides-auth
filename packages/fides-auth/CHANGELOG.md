# @eventuras/fides-auth

## 1.0.0-beta.11

### Minor Changes

- 6630716: Fixes from a second security review.
  
  A login under way is now sealed for its provider and client, as a session already was. Two instances that share a secret and an origin, one for each of two providers, could finish each other's logins: provider B could send the browser to A's callback with a code of its choosing, and A would take B's login transaction for its own and sign the user in as whoever the code was for. The transaction's key now has the instance's audience in it, and a login sealed by an earlier beta is not read: one that is under way during the upgrade ends as `login_expired`, and the user starts it again.
  
  `profile: 'fapi2'` now holds on every path, not only the login the handlers run. `exchangeCode`, `refresh` and `userInfo` throw without a `dpopKey`, `clientCredentials` throws, `createSession` refuses a token response that isn't DPoP-bound with its key, and a bearer session from before the profile was turned on is not refreshed.
  
  The tokens of a refresh that finds its session ended meanwhile, by a logout on another instance say, are revoked instead of dropped: they were good at the provider with nobody holding them. So are the tokens of a refresh the store never took, when the session is then ended with `endUserSessions` or a back-channel logout.
  
  A logout token whose `iat` is more than five minutes old is refused, whatever its `exp`, with 30 seconds allowed for clocks that differ.
  
  `dpop` and `profile` are read when the instance is created. Changing the config object afterwards doesn't turn either off.

### Patch Changes

- 936e20b: A back-channel logout token must be signed with the algorithm of the ID token the session was started with. A provider signs both the same way for one client (OpenID Connect Back-Channel Logout 1.0 §2.6), and until now a token signed with any asymmetric algorithm by one of the provider's keys was taken. A token that names a session and has another algorithm is answered with 400 and the session is left as it is. Found by the OpenID conformance suite's back-channel logout plan.
  
  `oidc.verifyLogoutToken` returns the token's `alg`.
- 327a3cc: An ID token that is not signed, with `alg: "none"`, is refused at the code exchange and at a refresh, whatever the provider's metadata lists. openid-client checks an ID token's `alg` against the provider's `id_token_signing_alg_values_supported`, so a provider that listed `none` there had an unsigned ID token taken. The login then fails as `login_failed`, and a refresh as `idp_error`. Found by the OpenID conformance suite's basic client plan.

## 1.0.0-beta.10

### Minor Changes

- f510999: `handleBackChannelLogout` lets the provider end a user's sessions: OpenID Connect Back-Channel Logout 1.0. Register its route as the client's `backchannel_logout_uri`. The provider posts a signed logout token there when the user logs out with it, or when an administrator ends their session, and the handler ends the sessions the token names, the one with its `sid` or else all of its `sub`, and revokes their refresh tokens, as `endUserSessions` does. It answers 200 when they are ended, also when there were none, and 400 when the token is refused or the store failed.
  
  It needs a `sessionStore` with `findMatching`, and throws a `TypeError` without one rather than tell the provider that it logged anyone out: a session kept in cookies can't be ended from the server.
  
  `oidc.verifyLogoutToken(logoutToken)` is the check on its own, for an app that ends its sessions another way. It verifies the signature, `iss`, `aud`, `iat`, `exp` and `jti`, that the token has a `sub` or a `sid` and the back-channel logout event, and that it has no `nonce`. It throws a `LogoutTokenError` with a `reason`.
  
  A session ended this way is a `session.cleared` event with the new `trigger: "back_channel_logout"`. Code that switches over the triggers gets one more.
- 49f587f: With `dpop: true`, the authorization code is now bound to the DPoP key too (`dpop_jkt`, RFC 9449 §10). The key is made when the login starts instead of at the callback, its thumbprint goes in the authorization request, through PAR when `usePar` is set, and the key is sealed in the login transaction cookie next to the PKCE verifier. A provider that supports `dpop_jkt` then issues a code only that key can exchange, so a code that leaks is of no use to anyone else. A provider that doesn't ignores the parameter. A login that was started before the upgrade has no key in its transaction and gets one at the callback, as before.
  
  On the OIDC client, `createAuthorizationRequest({ dpopKey })` sends the thumbprint; pass the same key to `exchangeCode`. `dpop_jkt` is now a reserved authorization parameter. With `profile: 'fapi2'`, `createAuthorizationRequest` throws without a `dpopKey`; `createFidesAuth` passes one by itself.
- 1b9c8f0: DPoP (RFC 9449): with `dpop: true` in `oauthConfig`, the tokens of a login are bound to a key that never leaves the server, so an access token that leaks is of no use without it. The callback makes a P-256 key for each session and sends a proof with the code exchange; the key is kept with the tokens, sealed in the session. A refresh carries a proof from the same key, and `authorizedFetch` sends the token as `Authorization: DPoP` with a proof for that method, URL and token, answering an API's `DPoP-Nonce` by asking once more. A provider that answers with a bearer token fails the login, so turn it on only where the provider supports DPoP.
  
  Roll this version out to every instance before turning `dpop` on: an earlier beta reads a bound session's token as a bearer token.
  
  Code that sets `Authorization: Bearer` itself from `getTokens` must move to `authorizedFetch` before it turns `dpop` on, or make the proof with `createDpopProof` from `/oidc`.
  
  On the OIDC client: `createDpopKey()`, and a `dpopKey` option on `exchangeCode`, `refresh` and `userInfo`. A response that isn't bound throws a `DpopError`, after its tokens are revoked where the provider has a revocation endpoint. `AuthorizedFetchError.bearerError` now also reads the `error` of a `DPoP` challenge. `/oidc` also exports `createDpopProof` and `dpopThumbprint`.
  
  `Tokens` has two new optional fields, `tokenType` and `dpopKey`. A session with bearer tokens has neither and is sealed as before. A session whose `tokenType` this version doesn't know, as a later version may write, is never sent as a bearer token and never refreshed: `authorizedFetch` throws `unsupported_token_type`, `refreshSession` answers with that reason, the heartbeat answers 503, and the session is left as it is. `createSession` takes a `dpopKey` for tokens that were bound outside the handlers.
- 1b9c8f0: A FAPI 2.0 profile: `profile: 'fapi2'` in the OIDC config enforces what the FAPI 2.0 Security Profile asks of a client, so a config that falls short throws instead of running as something weaker. Creating the client, with `createOidcClient` or `createFidesAuth`, throws a `TypeError` naming every requirement that isn't met: `clientAuth` must be `private_key_jwt`, `usePar` and `dpop` must be true, `allowInsecureRequests` must not be set, and the private key must not be an RS256 key.
  
  With the profile, `verifyIdToken` and `verifyLogoutToken` accept only `PS256`, `ES256` and `EdDSA`, and an `algorithms` option with anything else throws a `TypeError`. A token response whose ID token is signed with another algorithm is refused at the code exchange and at a refresh. `exchangeCode` refuses a callback without the `iss` parameter (RFC 9207) before the code is sent to the token endpoint, whatever the provider's metadata says of it.
  
  It is not a certification, and the provider must follow FAPI 2.0 too. mTLS, `dpop_jkt` and FAPI 2.0 Message Signing (JAR, JARM) are not implemented. Without `profile`, nothing changes.
- aaec2de: A login now sends a `nonce`, and the callback takes the ID token only when it carries it. PKCE and `state` already tie the code to the browser that started the login; the nonce ties the ID token itself to that login, so one issued for another login is refused even where the provider's PKCE check fails. The nonce is 32 random bytes, sealed in the login transaction cookie with the verifier. It is sent when the scope has `openid`, and with it the token response must have an ID token.
  
  With `createFidesAuth` there is nothing to change. A login that was started before the upgrade and finishes after it sent no nonce and is checked for none.
  
  With the OIDC client on its own, `createAuthorizationRequest` returns the `nonce` and puts it in `parameters`, and `exchangeCode` reads it from the request. Pass `exchangeCode` the request as it was returned, or its `nonce` along with `codeVerifier` and `state`: without it the provider's ID token carries a nonce the exchange doesn't expect, and is refused. `nonce` stays a reserved authorization parameter.
- f510999: `strictOriginCheck: true` makes logout and the heartbeat refuse a request that has neither `Sec-Fetch-Site` nor `Origin`. Such a request isn't a browser's, so it has passed the CSRF guard, and still does by default: a script or a server of the app's own can call the two. Every browser in use sends one of the headers on a POST, so an app that only browsers call can turn it on and refuse the rest with 403.

### Patch Changes

- acbcdef: The same secret listed twice in `secret` counts once. A config that always passes a current and a previous secret has the same value in both between two changes, and that now costs nothing: before, each key was derived and each search for a user's sessions was made twice. It is logged once as a warning when the instance starts to work, since a list like that is also what a change of secret that didn't happen looks like. The same bytes written as hex in another case, or as a `Uint8Array`, are the same secret.

## 1.0.0-beta.9

### Minor Changes

- 2a14b0c: `secret` takes a list, so a secret can be replaced without logging anyone out. The first one seals, and every one of them opens: `secret: [newSecret, oldSecret]`. A session sealed with the old secret is read as it is, and sealed with the new one the next time it is refreshed or updated. A login that was under way when the secret changed finishes, and `endUserSessions` finds a user's sessions whichever secret their lookup hash was keyed with.
  
  In a fleet replaced one instance at a time, deploy `[old, new]` first, then `[new, old]`, then `new` alone once `sessionDurationSeconds` has passed. The README has the steps under "Replacing the secret". A single secret works as before.
- 44a1dec: A session that opens but was written by a later major of the library is now told apart from one that doesn't open: it reads with the new reason `unsupported_session_version`, where it was `unreadable_session`. Every 1.x reads a session written by any 1.x.
  
  A read now emits `session.rejected` when a cookie is there and doesn't open, for both reasons. Before, only the heartbeat emitted that event, so an app that doesn't use the heartbeat saw nothing when a changed secret, or a rollback across a major, logged everyone out: `readSession` just answered null. The docs already suggested an alert on `unreadable_session`; now it fires. The heartbeat no longer reports these two itself, so one request is still one event.
  
  `SessionRejectedReason` has a new member, which an exhaustive `switch` over it has to handle.

### Patch Changes

- 9d1a151: `docs/session-format.md` says how a list of secrets seals and opens, and that a search for a user's sessions asks for the lookup hash of each secret.
- 99b7dca: A new page, `docs/session-format.md`, says what the library writes to a cookie and to a store: the record, how it is sealed and what its key is derived from, the store's fields, and the cookie of a login under way. It also says what is stable: every 1.x reads what any 1.x wrote. A test with values written by 1.0.0-beta.8 holds the library to that, and the page shows the supported way to start and read a session in an app's own tests.
  
  The docs now say plainly that `storeFields` are not sealed, and what does and doesn't belong in them.

## 1.0.0-beta.8

### Patch Changes

- 132080d: `clearSession` called where cookies can't be written, after the response's cookies were taken with `fetchCookieStore` or in a Next Server Component, deleted a stored session's record and then threw on the cookie, before the refresh token was revoked. The session was gone and its token lived on at the provider. The token is now revoked first, and then the call rejects with what the cookie store threw, as before: the cookie is still in the browser, where it finds no session. `handleOidcLogout` in the same place goes on to the provider, since the user is logged out. With cookie storage nothing changes: the cookie is the session, so nothing is ended and nothing revoked.
- 3d812ba: The key that seals a session no longer depends on how `issuer` is written in the config. It was derived from the string as given, so adding a trailing slash, or writing the host in another case, changed the key and logged everyone out. The issuer is now written one way before it goes into the key: scheme and host in lower case, no default port, no trailing slash. The path keeps its case.
  
  An issuer already written without a trailing slash, with a lower-case host and no default port, gives the same key as in beta.7, so those sessions stay. An app whose config has it another way logs its users in once more with this release, and not again when the config is tidied.

## 1.0.0-beta.7

### Minor Changes

- cbf8d92: `authorizedFetch` now refuses a path with `.` or `..` segments that are percent-encoded (once or twice), written with a backslash, or written as `..;`. Before, these were sent with the access token, path unchanged. A gateway that decodes before it routes could then serve a path outside `allowedBase`. An encoded slash inside one segment, such as `group%2Fproject`, still passes. An access token with CR, LF or NUL no longer puts the token in a `TypeError` message: the call fails with `no_access_token`.
- 09c5941: A session is now sealed with a key derived from the secret, the provider and client (`issuer` and `clientId`), and
  where it is kept: its own store key under a `sessionStore`. Before, every session was sealed with the secret itself,
  so a sealed record opened wherever the secret was. Someone with write access to the store could copy another user's
  record over their own row and read it with their own handle; a row from a leaked store opened as a session cookie
  on any instance running cookie storage with the same secret, during a rollout from cookies to a store say; and two
  `createFidesAuth` instances on one origin with the same secret, for different providers or clients, read each
  other's sessions, roles included. None of these open now: they read as `unreadable_session`.
  
  **Everyone logs in again once**, since sessions sealed by an earlier beta don't open. From here on, changing
  `issuer` or `clientId` ends all sessions, as changing the secret does. Decryption also accepts only the algorithms
  the library seals with (`dir`, `A256GCM`).
  
  A row put back under its own key after a logout still reads until `expiresAt`: sealing can't cover that, and
  `docs/server-sessions.md` now says that write access to the store is trusted to that extent.
- ebed293: `VippsLoginClient.getUserInfo` now takes a required `{ expectedSubject }`, the ID token's `sub`, and throws if the answer is for another subject (OIDC Core §5.3.2). It no longer follows redirects: a redirect from the userinfo endpoint sent the subscription key and merchant serial number to the new origin, and returned that origin's JSON as the user. The call gives up after 10 seconds. The error for a non-2xx answer no longer carries the response body.

### Patch Changes

- 1aa5c85: `endUserSessions` no longer ends a record it can't tie to the user. A `findMatching` that returned too much was already kept from ending another user's session, but a record without an ID token, or one that doesn't open, slipped through that check and was deleted, with its refresh token revoked. Such a record is now left alone. An `iss` that is an empty string, an unset variable say, is refused with a `TypeError`: it was read as no issuer, which matches the most. The `merge` example in `docs/server-sessions.md` now follows the rule for a continuation.
- 727ecec: When the known access-token expiry was more than about 35 days ahead, the browser heartbeat passed a delay above 2^31-1 ms to `setTimeout`. The timer then fired at once, so the heartbeat posted in a tight loop and every post made the server refresh at the provider. The wait between beats is now at most 24 hours.
- 4601dc4: `validateReturnUrl` now uses the default path when a `returnTo` such as `/.//evil.test` resolves to a path that starts with `//`, which code that navigates to the pathname could take for another site. The cookie reader of `fetchCookieStore` trims only space and tab around names and values, as a browser does, and skips a name that is not a valid cookie name. A `Cookie` header with a name padded by a non-breaking space can no longer stand in for a `__Host-` cookie. A `returnTo` is kept in the login cookie only up to 512 serialized bytes, down from 1024, so that a few logins started from another site stay under the header limit of common web servers.
- 5524142: An error from the provider no longer carries the provider's response. When a token response arrived with a 2xx
  status and then failed validation, a missing `token_type` say, `oauth4webapi` attached the whole response to the
  error it threw, access and refresh tokens included. The library logged that error and handed it to `onLoginError`
  as `cause`. The default logger prints only the name, the message and the stack, so nothing leaked there, but a
  logger that prints an error in depth, or a `console.error(failure.cause)` in the app, wrote the tokens out. A
  UserInfo response without a `sub` carried the user's claims the same way. The OIDC client now takes the response
  off every error it lets out, and what the error says was wrong stays.

## 1.0.0-beta.6

### Minor Changes

- b3d0f1e: `checkAuth` no longer logs the user out when the session check fails. A network error or a 5xx, such as the 503
  `handleSessionInfo` answers while the session store is down, is not an answer, so a session the browser store holds
  is kept, with the failure as `error`, until a check answers. That is what the session monitor already did. A check
  that answers "no session" logs out as before, and a store without a session still ends logged out with the `error`.

### Patch Changes

- 93e7a6e: `docs/server-sessions.md` has a PostgreSQL store next to the MongoDB one, and it is the first example with
  `withLock`: an advisory lock on a connection from a pool of its own, with what that relies on spelled out. The
  docs also say plainly that the library never deletes an expired record, so a store without a TTL index has to
  sweep them itself.
- dd337be: A session store that fails once, just after the provider has answered a refresh, no longer costs the user the
  session. With a provider that rotates refresh tokens, the store was left holding a spent one: the next refresh got
  `invalid_grant`, and under `withLock` the session was deleted. Now the save is tried twice more, after 0.2 and 1
  second. If the store still fails, the refresh answers `cause: 'store'` as before, and the instance keeps the new
  tokens in memory: the next refresh or update of that session on the same instance saves them without asking the
  provider, and a logout revokes them. Another instance doesn't have them, so a store that stays down can still cost
  a session whose next refresh lands elsewhere.
- 1cd8a5f: A session store that can't be reached no longer makes the heartbeat, the session info and a refresh throw. Only a
  `withLock` that rejected was handled; a `get` that threw went straight through, since the read a refresh starts
  with was outside the handling. Now `refreshSession` answers `{ ok: false, reason: 'refresh_failed', cause: 'store' }`
  for any call to the store that fails, with or without `ifExpiresWithin`, `handleHeartbeat` answers 503 as
  documented, and `refreshInProxy` passes the request on instead of failing every page. `handleSessionInfo` answers
  503 without a body: whether there is a session isn't known, so it says neither.
  
  The reads (`readSession`, `tryReadSession`, `getTokens`, `readSessionWithTokens`, `authorizedFetch`) still reject
  with what the store threw, as `updateSession` does: null would send a logged-in user to a login that fails on the
  same store. `docs/server-sessions.md` has a table of what each call answers.

## 1.0.0-beta.5

### Minor Changes

- 3081c1d: `fetchCookieStore` now throws when a cookie is set after `headers()` or `apply()` has taken the cookies, as such a cookie could not reach the browser. Set cookies before building the response.
- 27ccacd: `oidc.userInfo(accessToken, { expectedSubject })` gets the claims from the provider's UserInfo endpoint. It
  checks that the response is for `expectedSubject`, the ID token's `sub`, so you no longer build an openid-client
  configuration by hand.
- 8d6694e: `tokenStatus` says whether a session's access token can still be used: `active`, `refreshable` or `expired`. A
  session reads until `expiresAt` whatever its tokens are worth, so a login without a refresh token stayed
  `authenticated: true` for hours after its access token had died, with nothing to tell the two apart.
  `tryReadSession`, `readSessionWithTokens` and the session info endpoint now give the status. The session itself
  is left as it is; an app that wants "a session is no better than its token" ends it on `expired`.

### Patch Changes

- 8a172ba: `authorizedFetch` times out a body that stalls while `parse` reads it, also after Node's garbage collector has
  run. Node's fetch stops passing an abort on to the body once its own request object has been collected, so the
  read could hang for minutes, long past `timeoutMs`. The read is now held to the timeout and to the caller's
  signal by `authorizedFetch` itself.
- b0ec765: The upgrade guide says what to do where 0.x sealed a value of its own. `createEncryptedJWT` and `decryptJWT`
  were listed as gone without a recipe, and `createAndPersistSession(session)` pointed to
  `createSession(tokenResponse)`, which is not the same for a session that didn't come from a login. Such sessions
  are outside the library; the guide now says so and shows how to seal a value with jose.
- 8110116: The store contract now says that `set` must never create a record for a continuation: when a refresh or an
  update finds no record, the session was ended while it ran, and an upsert would bring it back. The MongoDB
  example upserted on every `set`, so without `withLock` a refresh on one instance could restore a session that
  another had just logged out. It now uses `upsert: !continuation`, and the memory store follows the same rule. A
  custom `SessionStore` that upserts on every `set` should do the same.
- a03ae17: The Vipps example in the README passed `VippsEnvironments.Production` as the issuer. That is the environment's
  address, not its issuer: the example now uses `getVippsIssuer(VippsEnvironments.Production)`, and the doc
  comments say which is which.

## 1.0.0-beta.4

### Minor Changes

- 02fe7c7: `endUserSessions({ sub })` finds the sessions by `sub` alone and no longer needs the issuer. Since beta.3 it
  fell back to `oauthConfig.issuer` when the provider couldn't be reached, and ended nothing, without an error,
  when the config spelled the issuer another way than the ID tokens do. It now asks the provider for nothing.
  `iss` is still an option, to narrow it to one provider, and must then be the ID token's `iss` to the letter.
  
  For a custom `SessionStore`: `SessionMatch.iss` is optional, and `findMatching` must treat a missing `iss` as
  "any issuer". An adapter that hands the match to its query as it is needs no change, but an index for it
  should start with `subHash`, not `iss`.
- e82c781: A rate-limited login now goes through `onLoginError` with the code `rate_limited`, and redirects like any other failed login. A logout that fails, because of the rate limit or because the session couldn't be ended, redirects to `defaultRedirectPath` with `?logout=error&error=<code>` instead of answering with text. The new `onLogoutError` option answers it in another way.

### Patch Changes

- 6cc8008: A login callback opened again by a browser that is already logged in, with the back button or a reload, now redirects to `defaultRedirectPath` instead of failing with `login_expired`. A browser without a session still gets `login_expired`.
- 3ced1af: When a refresh ends a stored session, every request that was waiting for it has its session cookie deleted,
  not only the one that asked the provider. Requests that shared the refresh in the same process kept the cookie,
  and so did a request on another instance that waited for the store's lock and then found the record gone.
- a67081d: A function given to `updateSession`, or a `mapRefresh`, that refreshed, updated or ended the same session
  waited for itself and never returned. Such a call is now refused with a TypeError at once, on runtimes with
  `AsyncLocalStorage` (Node, Deno, Bun, Workers with Node compatibility). The docs also say what `updateSession`
  does when the store fails: it rejects with what the store threw, where `refreshSession` answers
  `cause: 'store'`.

## 1.0.0-beta.3

### Minor Changes

- b1721c1: A login that fails always redirects to `defaultRedirectPath` with `?login=error&error=<code>`. A callback
  without a live login answered 400 with English text, a failed code exchange 500, and a session too large for
  the cookies 431; they now carry `login_expired`, `login_failed` and `session_too_large`. `handleOidcLogin` no
  longer throws when the login can't be started, because the provider can't be reached say: it redirects with
  `login_unavailable`. `onLoginError` answers a failed login in another way.
- 83860bd: `mapRefresh` changes the session a refresh leaves, the way `mapSession` does at login. What `mapSession` put
  in `data` from the ID token claims stayed as it was at login; with `mapRefresh` it can follow each refresh. It
  is also where roles that only the access token carries are set again. It can't fail the refresh: if it throws,
  the error is logged and the session is saved as the refresh left it.
- 094b74d: `rolesClaim` can be a function of the ID token claims, for roles that aren't in a top-level claim, such as
  Keycloak's `realm_access.roles`. Roles that `mapSession` read from such a claim were gone after the first
  refresh. `rolesClaim: false` leaves `user.roles` to `mapSession`, and a refresh then keeps them. A login where
  `mapSession` sets roles that the next refresh would replace logs a warning, once.
- 993e12b: `storeFields` values may now be lists of strings, for roles say, as well as strings, numbers, booleans and null. A store's `set` gets `context.reason`, one of `'login'`, `'refresh'` and `'update'`, so an adapter can tell a refresh from an `updateSession` and stamp when a session was last refreshed. `StoreSetReason` is exported.
- 08548be: `OidcUserInfo.name` and `email` are now optional, and `userFromClaims` leaves them out when the ID token has no such claim or the claim is not a string.

### Patch Changes

- 99c0422: `endUserSessions` no longer fails when the identity provider is unreachable. It falls back to the issuer it last saw, or to `oauthConfig.issuer`, to find the user's sessions.
- 124b84d: The docs say that `expiresAt` is fixed at login today, and that apps should read it each time because a later version may let a session be extended.
- bb88bc5: A refresh that ends a stored session, because the provider refused it for good, deletes the session cookie
  too, where cookies can be set. The browser kept sending a handle that found no session, and a proxy that
  checks for the cookie took the user for signed in.
- 4c57abb: `session.scopes` at login are now the scopes the login asked for when the provider's token response names none, which RFC 6749 allows when it granted exactly what was asked. A `scope` in the response still wins.
- 9d3b85b: `updateSession` could undo a refresh. An update that overlapped a refresh saved the session it had read before
  it, with the refresh token the refresh had just spent, so the next refresh failed with `invalid_grant`. A
  refresh and an update of one session now take turns, in the process and under the store's lock, and each starts
  from what the other saved.

## 1.0.0-beta.2

### Minor Changes

- 6ffe912: A refresh the provider refuses for good, `invalid_grant`, ends a session held by a `sessionStore` with
  `withLock`: the record is deleted, and later reads answer `session_not_found` instead of a session
  whose tokens no longer work. It emits `session.cleared` with `trigger: "rejected"`. Cookie sessions,
  and stores without a lock, are left as before, since another instance may have refreshed; the README
  shows how to end them with `clearSession`.
- 790a3f7: `fetchCookieStore(request)` in `/server` is a `CookieStore` over a Fetch `Request`, for React Router,
  Hono, SvelteKit, Astro and other frameworks that hand a route a Request and take a Response.
  `apply(response)` copies a handler's response with the cookies it wrote, and `headers()` gives the
  `Set-Cookie` lines for a response the route builds itself. It refuses a name, value or path that
  isn't cookie-safe.
- 9fcdd4b: `loginSuccessParam: false` makes a login land on its return path as it was, without `?login=success`.
  The default stays true. A failed login still goes to `defaultRedirectPath` with
  `?login=error&error=<code>`.
- 1113955: `readSessionWithTokens` gives the session and its tokens in one read, or why there is none.
  `readSession` and `getTokens` each read, which with a `sessionStore` is a round trip each. The README
  says to read once per request where several parts of it need the session.
- 58fdc40: With cookie sessions, a request that still carries the cookie from before a refresh gets that
  refresh's result for `refreshGraceSeconds` after it, 10 by default, instead of spending the old
  refresh token again, which a provider that rotates refresh tokens answers with `invalid_grant`. A
  logout with the old cookie revokes the new refresh token. It works within one process and for the
  token just spent; set it to 0 to turn it off.
- 038aa72: `sessionDurationDays` is now `sessionDurationSeconds`, like the other durations in the API, and the
  default goes from 30 days to 12 hours. `createFidesAuth` throws a `TypeError` on the old name, and
  unless the lifetime is a finite number above 0: a value such as `NaN`, from an unset environment
  variable, used to pass and then fail every login with a 500. To keep a 30-day session, set
  `sessionDurationSeconds: 30 * 24 * 60 * 60`.
- 41c27cf: The session info endpoint answers with `expiresAt`, when the session itself ends. A page knew when
  the access token expires, which a refresh moves, but not when the user will be logged out.
- e6ce4de: `SessionUser` names the type of `session.user`, so an app no longer writes
  `NonNullable<Session['user']>`. The app's own fields belong in `data`. `Tokens.accessToken` stays
  optional, and its doc now says why: a session that keeps only a refresh token must stay possible.
- ad8b5c4: `createFidesAuth<AppData>(…)` types `session.data` in everything the instance hands out: reads,
  `refreshSession`, `createSession`, `updateSession`, `mapSession` and `storeFields`. `Session` was
  generic already, but the instance wasn't, so `data` came back as an open record and every use
  needed a cast. Without a type argument nothing changes.

### Patch Changes

- 9990390: The MongoDB adapter in `docs/server-sessions.md` compiles: `replaceOne` doesn't take `_id` in the
  replacement document. It also creates the index that `findMatching` uses. The example has now been
  run against MongoDB 8, on its own and through `createFidesAuth`.
- bdc86a2: A refresh updates `session.scopes` when its response names the scope. They were set at login only, so
  a scope the provider took away stayed on the session until the next login, and an app that gates
  features on `session.scopes` kept showing them.
- 127c85d: `Tokens` loses `refreshTokenExpiresAt`. Nothing ever set it: a token response says how long the
  access token lasts, not the refresh token.

## 1.0.0-beta.1

### Minor Changes

- 2487c72: `endUserSessions({ sub, iss? })` ends every stored session of one user, wherever they are signed in,
  and revokes their refresh tokens: for "sign out everywhere" and closed accounts. It needs a
  `SessionStore` with the new optional `findMatching`, and throws without one.
  
  A store can now tell whose session a record is, and whether it is new: `storeFields` in the config
  puts plain fields of your choice on the record as `fields`, and `set` gets `{ continuation }` as a
  third argument. `createMemorySessionStore` implements `findMatching`.

### Patch Changes

- c15514e: An http issuer, or an http endpoint in the provider's metadata, throws a `TypeError` that names the
  URL and says what to set, where openid-client only answered `OAUTH_HTTP_REQUEST_FORBIDDEN` and login
  failed with a bare 500. `allowInsecureRequests: true` in the OIDC config allows http to a provider on a
  loopback address (`localhost`, `*.localhost`, `127.0.0.0/8`, `[::1]`) for development and CI; any
  other http URL still throws.
- 4445da7: A refresh sends no `scope`, so the provider keeps the scope it granted at login. Sending the
  configured scope failed with `invalid_scope` whenever the provider granted less, e.g. without
  `offline_access`, and the session could never be refreshed.
- 948e89a: A refresh that brings an ID token updates `session.user` from it, as at login, so roles taken away at
  the provider go with the next refresh instead of the next login. The roles follow `rolesClaim`, the
  name and email change when the token carries them, and `sub`, `data` and the fields `mapSession`
  added stay. An ID token whose `iss` or `sub` differs from the login's fails the refresh with
  `cause: 'idp_error'` and saves nothing (OIDC Core §12.2).
- a5f8160: `refreshSession({ ifExpiresWithin })` and `refreshInProxy` never count more than half the access
  token's lifetime as about to expire. A token that lived shorter than the window, 60 seconds by
  default in the proxy, was refreshed on every request. The session now records when its access token
  arrived, as `accessTokenIssuedAt` on `Tokens`, and the READMEs describe how a refresh from a stale
  cookie fails when the provider rotates refresh tokens.
- 8813d4a: Logout and `clearSession` revoke the session's refresh token (RFC 7009) when the provider has a
  `revocation_endpoint`, so a refresh that was running at logout, or a copy of the cookie, can't renew
  the session. A refresh running in the same process is waited for, and the token it brought back is
  the one revoked. With a `sessionStore`, the session ends under `withLock`, so a refresh on another
  instance can't save it again. `OidcClient` gets `revoke(token, { tokenTypeHint })`.
- dd7aac5: A refresh whose store lock fails, or whose store throws, returns `{ ok: false, reason:
  'refresh_failed', cause: 'store' }` instead of throwing, and emits `session.refresh_failed`. The
  heartbeat answers it with 503, so the browser retries. `docs/server-sessions.md` spells out the
  `withLock` contract: `fn` uses the store while the lock is held, the lock is held across the call to
  the provider, and why more than one instance with a rotating provider needs it.

## 1.0.0-beta.0

### Major Changes

- 84d3b82: 1.0. Users log in again once after the upgrade. The
  [upgrade guide](https://github.com/losol/fides-auth/blob/main/packages/fides-auth/docs/migrating-to-1.0.md)
  maps every 0.x API to what replaces it.
  
  - `createFidesAuth` from `/server` is the server side: the handlers, the session members and
    `authorizedFetch` on one instance. The free `/server` functions are gone.
  - One session cookie, `__Host-session`, or a handle with a `SessionStore`. A session ends
    `sessionDurationDays` after login, and `Session` carries no tokens.
  - Nothing refreshes unless asked: `refreshSession({ ifExpiresWithin })`. `authorizedFetch` never
    refreshes, and its error says whether a refresh may help.
  - `createOidcClient` on `/oidc` replaces the free protocol functions and the global settings. Each
    part takes its own `logger`.
  - `/browser` has the session store, the session monitor, the heartbeat and the activity tracker,
    without XState.
  - Six entries: the root, which has only types, `/oidc`, `/server`, `/browser`, `/session-events`
    and `/providers/vipps`. The other 0.x entries are gone, `/utils` and `/rate-limit` among them.
  - Logout and heartbeat answer only a same-origin `POST`, and `createFidesAuth` throws on
    `clientAuth: 'none'`.
  - Needs Node 22.

## 0.16.0

### Minor Changes

- 2c9a137: The free protocol functions are deprecated in favour of a client from `createOidcClient`
  (`@eventuras/fides-auth/oidc`): `buildPKCEOptions`, `buildAuthorizationUrl`,
  `buildAuthorizationUrlWithPAR`, `discoverAndBuildAuthorizationUrl`, `exchangeAuthorizationCode`,
  `refreshAccessToken`, `clientCredentialsGrant`, `buildOidcLogoutUrl`, `verifyIdToken`,
  `discoverConfiguration`, `resolveClientAuth`, `buildSilentLoginUrl` and `extractUserFromTokens`, with
  their option types. So are the global settings `configureLogger`, `configureDiscoveryCache`,
  `clearDiscoveryCache` and `clearJwksCache`, and `TokenBucket`. Each `@deprecated` tag names the
  replacement. All of them keep working until 1.0. `docs/migrating-to-1.0.md` has the full table.
- 39a63cf: New entry `@eventuras/fides-auth/oidc` with `createOidcClient(config, { logger, discoveryTtlMs })`
  (ADR 0001). A client holds its config, discovery cache, JWKS cache and logger, so two clients share
  no state, and creating one does no I/O. Its methods are `metadata`, `createAuthorizationRequest`,
  `authorizationUrl`, `silentLoginUrl`, `exchangeCode`, `refresh`, `clientCredentials`, `logoutUrl` and
  `verifyIdToken`. The entry also exports the pure helpers `createPkcePair`, `createState`,
  `defaultScope`, `joinScope`, `userFromClaims`, `checkSilentLoginResult`, `requiresInteractiveLogin`,
  `getOAuthErrorLogContext` and `classifyRefreshFailure`.
  
  `OAuthConfig` accepts `redirectUri` next to `redirect_uri`. The client's config, `OidcClientConfig`,
  needs a redirect URI only for the operations that use one.
  
  The free functions in `/oauth`, `/oidc-discovery`, `/id-token` and `/silent-login` behave as before.
- 2c9a137: The root entry exports the types shared across layers: `OAuthConfig`, `ClientAuthConfig` and a new
  `TokenResponse` join `Session`, `Tokens`, `CookieOptions`, `FidesLogger` and `FidesLoggerFactory`.
  `TokenResponse` has the same shape as openid-client's `TokenEndpointResponse`, so either works where
  the other is expected. `/server` exports `CookieTooLargeError`.
  
  The old subpaths are deprecated, and each `@deprecated` tag names the new home: `/oauth`, `/pkce`,
  `/id-token`, `/oidc-discovery`, `/oauth-logging` and `/silent-login` (now `/oidc`), and `/types`,
  `/logger`, `/cookies`, `/utils` and `/rate-limit`. They keep working until 1.0.
  
  New: `docs/migrating-to-1.0.md`, with a 0.16 section and an old-to-new table.

### Patch Changes

- af191f5: The type declarations use explicit `.js` extensions on relative imports, so they
  resolve under `moduleResolution: "node16"` and `"nodenext"`. No API change.

## 0.15.0

### Minor Changes

- 42fe1c5: `OAuthConfig.scope` (and provider client configs) accept `string | string[]`;
  arrays are joined with spaces on authorize, PAR, refresh and silent login. New
  `OAuthConfig.authorizationParameters`, `buildPKCEOptions(config, { parameters })`
  and `OidcLoginConfig.authorizationParameters(request)` add extra authorization
  parameters. `state`, `code_challenge`, `code_challenge_method`, `redirect_uri`,
  `client_id`, `response_type`, `request`, `request_uri` and `nonce` are reserved
  and throw. Code that reads `OAuthConfig.scope` must handle an array; `joinScope()`
  from `/oauth` returns the string.
- e6d0aec: New `authorizedFetch(session, url, { allowedBase, parse?, timeoutMs?, refresh? })`
  in `@eventuras/fides-auth/server`. It sends the access token only to URLs under
  `allowedBase`, refuses redirects, times out after 10 s, and throws a typed
  `AuthorizedFetchError`. On a 401 it calls `refresh` once (e.g.
  `tryRefreshSessionInStore`) and retries; the result carries the session to use next.
- 9567058: `OAuthConfig` and `ClientCredentialsConfig` take `clientAuth`: `client_secret_post`
  (default), `client_secret_basic`, `private_key_jwt` with `privateKey`, or `none`
  (`OAuthConfig` only). The discovery cache now tells entries apart by method and key.
  
  Breaking (types only): `config.clientSecret` is no longer always a `string`. Narrow
  on `clientAuth` before reading it. Configs that set `clientSecret` without
  `clientAuth` work as before.
- 344537f: `buildSessionFromTokens` takes `{ rolesClaim, mapSession }` and `handleOidcCallback`
  takes `mapSession`. `mapSession(tokens, claims, session)` returns the session to
  store, e.g. with `data` added. The `rolesClaim` string argument still works.
  `Session.user` gains `sub`.
  
  Breaking: `Session.user.email` is optional; handle `undefined`. A token response
  without `id_token` no longer throws: the session has tokens and no `user`.
- 623eb89: Each login is now one sealed `__Host-oauth_tx_<n>` cookie (state, PKCE verifier,
  returnTo, start time), replacing `oauth_state`, `oauth_code_verifier` and
  `returnTo`. The callback rejects it after 10 minutes. New in `/server`:
  `createTransaction`, `persistTransaction`, `readTransaction`, `clearTransaction`,
  `validateCallback`.
  
  Breaking: `handleOidcLogin` takes `secret`; pass both handlers the same one.
  Code reading the old cookies must use the new helpers. Logins in progress
  during the upgrade must be restarted.
- 42fe1c5: New `@eventuras/fides-auth/pkce` entry point with `createPkcePair()` (verifier
  and S256 challenge) and `createState()`. It uses Web Crypto only, so it also runs
  in the browser and on edge runtimes. `buildPKCEOptions` now uses them and logs at
  `debug` instead of `info`.
- bdf5128: The library no longer reads `SESSION_SECRET`: `getSessionSecret` and
  `getSessionSecretUint8Array` are removed. `handleOidcLogin` and
  `handleOidcCallback` require `secret`; `handleOidcLogout` and `handleHeartbeat`
  require `secret` or `persistence`. A missing, empty or non-32-byte secret (64
  hex characters or a `Uint8Array`) throws a `TypeError` on first use, session
  reads included.
  
  Migration: pass `secret` to every handler (e.g. `process.env.SESSION_SECRET`),
  and replace `getSessionSecret()` with your own read of it.
- 9567058: `OAuthConfig.serverMetadata` skips OIDC discovery: the configuration is built from
  the given metadata and cached the same way. With `openid` in the scope the metadata
  must include `issuer`.
- c2fa830: Opt-in server-side sessions. `serverPersistence({ store, secret })` keeps the
  session in a `SessionStore` and gives the browser a random handle, for providers
  whose tokens don't fit a cookie.
- f9e0b95: New `@eventuras/fides-auth/id-token` entry point with `verifyIdToken(idToken, options)`.
  It checks the signature, `iss`, `aud` and `exp` against the provider's JWKS and returns
  the claims. Pass `jwksUri`, or an `oauthConfig` to use `jwks_uri` from its metadata.
  Only asymmetric algorithms are accepted by default. The JWKS is cached per URI;
  `clearJwksCache()` resets it. Runs in the browser too.

### Patch Changes

- 8de23d2: `authorizedFetch` with a `signal` no longer needs `AbortSignal.any`, so it works
  on Node before 18.17.
- 3e76c27: Deprecate `@eventuras/fides-auth/oauth-browser`. Use the server flow
  (`handleOidcLogin` / `handleOidcCallback` from `/server`) instead; the entry
  point will be removed in a later minor.
  
  Document that `extractUserFromTokens` and `buildSessionFromTokens` decode the
  ID token without verifying it.
- 7a0bc8f: The default `returnTo` validator in `handleOidcLogin` accepts only printable
  ASCII, and the 1 KB `returnTo` cap is measured after JSON escaping. If the login
  transaction is still too large for a cookie, `handleOidcLogin` stores it without
  `returnTo` instead of failing.
- 8fd8afa: The login transaction cookie is `__Host-oauth_tx_<n>`, or a plain non-Secure
  `oauth_tx_<n>` when `redirect_uri` is http. The transaction helpers take
  `{ secure }` for custom flows. The callback passes on only `[a-z0-9_]` error
  codes (others become `idp_error`), and an IdP error after the login has ended
  redirects with `error=login_expired` instead of returning 400.
- 8fd8afa: Login transaction cookies are sealed under a key derived from the secret, so
  one can no longer be sent back as a `session` cookie. `isSession` now requires
  a `tokens` or `user` object.
- 8fd8afa: At most three login transaction cookies (`oauth_tx_0`–`oauth_tx_2`) are kept; a
  fourth login evicts the oldest. A `returnTo` over 1 KB is dropped, and
  `persistTransaction` throws `CookieTooLargeError` instead of setting a cookie the
  browser would drop. `clearTransaction` now takes the secret.
- 7a0bc8f: A login takes a random free transaction slot instead of the first, so two logins
  started at the same moment usually keep separate cookies.
- be42d5e: `handleOidcCallback` redirects an IdP error response (`?error=access_denied`) to
  `defaultRedirectPath` with `?login=error&error=<code>` instead of returning 500.
  The login transaction cookies are now cleared after every callback, not only on
  success.
- 7a0bc8f: `encodeSessionCookies` and `serverPersistence` throw a `TypeError` for a session
  with neither `tokens` nor `user`, instead of writing one that reads back as null.
- 7a0bc8f: `/server` exports `transactionCookieOptions(redirectUri)`, the cookie options the
  login handlers use. Pass it to the transaction helpers in custom flows.

## 0.14.1

### Patch Changes

- 8a87c07: Emit type declarations with `tsc --emitDeclarationOnly` instead of vite-plugin-dts, and upgrade TypeScript to 7.

## 0.14.0

### Minor Changes

- 4b3d582: Cache the provider's OpenID configuration instead of discovering it before every
  token operation, removing a round-trip from each refresh, login and logout.
  Cached per issuer and client for five minutes; tune with
  `configureDiscoveryCache({ ttlMs })` or drop entries with `clearDiscoveryCache()`
  from `@eventuras/fides-auth/oidc-discovery`. See `docs/discovery-cache.md`.

  Fixes `VippsLoginClient` caching a failed discovery for the client's lifetime.

## 0.13.0

### Minor Changes

- c6007c6: Structured session-lifecycle logging, so production logs explain logouts.

  Every point where the library creates a session, renews one, or decides one
  cannot proceed now emits a named event — `session.created`, `session.refreshed`,
  `session.rejected`, `session.refresh_failed`, `session.cleared` — with a
  correlation id and a low-cardinality `reason` / `cause`. See
  `docs/session-events.md` for the taxonomy, the level policy and example LogQL.

  **Heartbeat: 503 instead of 401 when the provider is unreachable.** The endpoint
  previously answered 401 for a dead refresh token _and_ for a network fault or an
  IdP 5xx, so a provider blip logged out users whose sessions were valid.
  `classifyRefreshFailure` now separates `invalid_grant` (session really is over, 401) from `transport` / `idp_error` (503). Clients already retry non-401
  responses with backoff. 401 responses now carry `{ reason }` in the body.

  **New APIs.** `tryReadSession`, `tryRefreshSessionInStore` and
  `tryDecodeSessionCookies` return the reason or cause instead of a bare `null`, so
  consumers can log the same vocabulary the library does. The existing
  `readSession`, `refreshSessionInStore` and `decodeSessionCookies` are unchanged
  and delegate to them.

  **Session correlation id.** `Session.sid` is minted at creation and carried
  across refreshes, so one session is one id for its whole life — including through
  refresh-token rotation.

  **Browser events.** `createHeartbeat` and `startSessionMonitor` take an `onEvent`
  callback carrying the same event names, so consumers can beacon the client half
  of a session's story to their own endpoint. No transport ships with the library.

  `startSessionMonitor` now logs through the pluggable `createLogger` instead of
  importing `@eventuras/logger` directly, so `configureAuthLogger()` finally
  affects it.

## 0.12.0

### Minor Changes

- a4f412b: The session is the login; access-token freshness is the caller's concern. An
  expired access token no longer reads as "no session".

  Previously every session read treated an expired access token as "logged out":
  `refreshSessionInStore` could never refresh a token that had actually expired,
  and the heartbeat endpoint answered 401 — the client then showed "session
  expired, log in again" even though the refresh token was still perfectly valid.
  Any missed proactive-refresh window (hidden tab, laptop asleep, throttled
  timers, a transient network error) logged the user out.

  Now `decodeSessionCookies` / `readSession` / `getCurrentSession` return the
  session whenever the session cookie itself decrypts and validates, with the
  stored access token attached whether it is fresh or expired. The refresh paths
  (`refreshSessionInStore`, `handleHeartbeat`, `refreshCurrentSession`) therefore
  recover an expired-but-refreshable session instead of discarding it; a 401 from
  the heartbeat once again means what it should — no session, or a dead refresh
  token.

  Callers that hand `session.tokens.accessToken` to an API must check freshness
  first (`accessTokenExpires` / `accessTokenExpiresAt`) or refresh on 401; the
  library no longer withholds the session to enforce this.

  Legacy single-cookie sessions (written before the split-cookie format) are
  supported only while their embedded access token is still valid: active users
  migrate seamlessly on their next refresh, while stale legacy sessions read as
  "no session" and cost one re-login. Old sessions are dropped, not migrated.

## 0.11.0

### Minor Changes

- 82ec137: Route `clientCredentialsGrant` through openid-client instead of a raw `fetch`.

  It was the one place the server module talked to a token endpoint directly, so it
  missed the transport guards the rest of the package gets for free — while being the
  request that carries the client secret. Three behaviour changes, all breaking:

  - The token endpoint must now be **https**. A plain-http endpoint rejects with
    `OAUTH_HTTP_REQUEST_FORBIDDEN` instead of posting the secret in the clear.
  - Failures throw openid-client's typed errors rather than a generic
    `Error("Client credentials grant failed: <status> - <body>")`. Code matching on
    that message needs updating.
  - Requests time out, 30 seconds by default, where previously they never did.
    Configurable via the new `timeout` option (seconds).

  Also adds an optional `issuer` to `ClientCredentialsConfig`, defaulting to the token
  endpoint's origin.

- fa9de74: RP-initiated logout: send `id_token_hint`.

  `Tokens.idToken` now holds the raw ID token — populated by `buildSessionFromTokens`,
  kept fresh by `refreshSession`, and stored in its own `session_it` cookie so no cookie
  has to carry two large JWTs. `readIdToken` reads it independently of session validity,
  since logout needs the hint after the access token has expired.

  `buildOidcLogoutUrl(oauthConfig, options)` accepts `idTokenHint`, `state`,
  `logoutHint` and `includeClientId` alongside `postLogoutRedirectUri`. A string second
  argument still means `postLogoutRedirectUri`, and it still returns `null` when the
  provider advertises no `end_session_endpoint`.

  New `handleOidcLogout` handler in `@eventuras/fides-auth/server` — `POST`-only by
  default and same-origin checked via `Sec-Fetch-Site`/`Origin` — wrapped for Next.js at
  `@eventuras/fides-auth-next/oidc-logout`. See
  `packages/fides-auth/docs/rp-initiated-logout.md` for the full parameter set, where
  the ID token is stored, and why `client_id` is still sent.

  Also fixes the `./oidc-callback` and `./oidc-login` subpath exports in
  `@eventuras/fides-auth-next`, which pointed at files the build never emitted.

  `persistSession` now size-checks every cookie value before writing any of them.
  Previously a value that exceeded the browser limit threw part-way through, leaving the
  new session cookie next to the previous user's tokens.

- 2468ac6: Set `secure` on the default cookie options unconditionally.

  **Breaking for anyone serving over plain http on a non-localhost host.** Minor rather
  than major because this package is pre-1.0, where minor is the breaking channel — a
  major would cut 1.0.0.

  `defaultSessionCookieOptions` and `defaultOAuthCookieOptions` derived the flag from
  `process.env.NODE_ENV === 'production'`, so any deployment that did not set
  `NODE_ENV` — staging, a container, any server that isn't following the Next
  convention — served the session cookie without `Secure`, over plain HTTP, silently.

  The cookie spec exempts localhost from the https requirement, so `Secure` cookies are
  still set and sent over `http://localhost` and local development is unaffected. Plain
  http on a LAN address or a custom dev hostname now needs an explicit `secure: false`,
  which is a deliberate choice rather than a silent default.

### Patch Changes

- db99ad0: Widen the `jose` dependency from an exact pin to `^6.2.8`.

  An exact pin in a library forces a second copy of `jose` into any consumer tree that
  already resolves it through a range — `openid-client` depends on `jose: ^6.2.2`, so
  this repo was carrying two copies itself — and it withholds patch releases from
  consumers until we cut a release of our own. Reproducibility is the lockfile's job,
  not a library's dependency range.

## 0.10.0

### Minor Changes

- f8c2ee3: Move the framework-agnostic cookie attributes, size limits, and size guard into
  the core package.

  The new `@eventuras/fides-auth/cookies` export holds `CookieOptions`,
  `defaultSessionCookieOptions`, `defaultOAuthCookieOptions`,
  `ACCESS_TOKEN_COOKIE_NAME`, the `COOKIE_MAX_BYTES`/`COOKIE_INFO_BYTES` limits,
  the `CookieTooLargeError` class, and pure `cookieByteSize` /
  `assertCookieWithinLimit` helpers — none of which need a framework. This makes
  them reusable by future adapters (e.g. React Router) instead of living only in
  the Next.js binding.

  `@eventuras/fides-auth-next` now re-exports these from the core package and keeps
  only the actual cookie I/O (via `next/headers`). Its public API is unchanged.

- 019f8a0: Add a framework-agnostic `createHeartbeat()` engine at `@eventuras/fides-auth/heartbeat`. `fides-auth-next`'s `useHeartbeat` is now a thin wrapper over it; behaviour and API unchanged.
- dcf1b7d: Add a framework-agnostic `CookieStore` interface and session persistence helpers (`persistSession`, `readSession`, `refreshSessionInStore`, `clearSession`) at `@eventuras/fides-auth/server`. `fides-auth-next`'s session functions now delegate to them through a Next cookie-store adapter; public API unchanged.
- 50f6882: Move the OIDC request handlers — `handleOidcLogin`, `handleOidcCallback`, `handleHeartbeat` — into `@eventuras/fides-auth/server`, taking a `CookieStore` and an optional rate-limit callback over the standard Request/Response. `fides-auth-next` now wraps them with its Next cookie store and rate limiters; public API unchanged.
- 3c72759: Split the session across two cookies to make room for large access tokens.

  The access token — typically the largest part of a session — now lives in its
  own `session_at` cookie, while the rest stays in `session`, so each gets a full
  per-cookie byte budget instead of competing for one ~4KB limit.

  The framework-agnostic encode/decode logic lives in the core package as a new
  `@eventuras/fides-auth/session-cookies` export (`encodeSessionCookies` /
  `decodeSessionCookies`), plus a `decryptJWT` helper in `@eventuras/fides-auth/utils`.
  `@eventuras/fides-auth-next` is a thin adapter that wires these to the Next.js
  cookie store. Legacy single-cookie sessions are still read transparently, and the
  "expired access token means no session" contract is preserved.

### Patch Changes

- 39f2cbd: Standardize MIT licensing across the workspace.

  Every package now carries a `LICENSE` file with a consistent
  `Copyright (c) 2024 Losol AS` notice, and `@eventuras/fides-auth-next` gains the
  `license` / `author` metadata it was missing and ships its `LICENSE` in the
  published tarball. `@eventuras/fides-auth`'s existing license notice is updated
  to the same copyright holder.

## 0.9.0

### Minor Changes

- 7bcf252: Type `tokens.accessTokenExpiresAt` / `tokens.refreshTokenExpiresAt` as ISO 8601 `string` instead of `Date`. The session is a JSON/JWT envelope, so these values are always strings on the wire — the `Date` type was a lie after a `validateSessionJwt` round-trip. Consumers doing date math should wrap in `new Date(value)`.

## 0.8.0

### Minor Changes

- 2fed638: Add `@eventuras/fides-auth/activity-tracker` — framework-agnostic DOM activity tracker used to gate session keepalive on real user interaction.

## 0.7.1

### Patch Changes

- 3796814: Fix `exchangeAuthorizationCode` to normalize the callback URL origin to `oauthConfig.redirect_uri` before invoking the token-exchange. `openid-client` derives `redirect_uri` from the passed callback URL (via `stripParams`), overriding the explicit option — so when a consumer sits behind a reverse proxy that doesn't forward the original scheme (e.g. `@react-router/serve` without trust-proxy), PAR sent `https://...` but token-exchange sent `http://...` and the IdP rejected the mismatch.

## 0.7.0

### Minor Changes

- 22c3761: Add `@eventuras/fides-auth/oauth-logging` with `getOAuthConfigLogContext` and `getOAuthErrorLogContext` helpers — structured, log-safe context objects for OAuth/OIDC config (excluding `clientSecret`) and `oauth4webapi`-style errors (including `cause`).

### Patch Changes

- a29b507: Stop bundling runtime dependencies into published library output, and stop minifying.

  The vanilla/react/next library presets used to inline every transitive dep (e.g. `oauth4webapi` was bundled into `@eventuras/fides-auth`) and minify class/function names. Two consequences:

  - **`instanceof` failed across module boundaries.** A consumer importing `ResponseBodyError` from `openid-client` got a different class than the one a library threw, because the library carried its own bundled+renamed copy.
  - **Stack traces were unreadable** — minified names like `j` instead of `ResponseBodyError`.

  The presets now:

  - Auto-externalize every entry in the consumer's `dependencies`, `peerDependencies`, and `optionalDependencies` (plus `node:*` built-ins).
  - Set `build.minify: false` (libraries should not minify — consumers minify their own bundle).
  - Emit sourcemaps so consumer stack traces map back to original sources.

  No API changes — all affected packages are bumped `patch`. The only observable effect is leaner, more debuggable output: deps are required at install time (already the case via each lib's `dependencies`) instead of duplicated inside the bundle.

## 0.6.0

### Minor Changes

- 7caaea2: Surface granted scopes as a first-class field on `Session`.

  - Added `scopes?: string[]` to the `Session` interface in `types.ts`
  - `buildSessionFromTokens` now populates `session.scopes` by splitting the space-separated `tokens.scope` string (empty/missing scope leaves the field `undefined`)
  - Added `hasScope(session, scope)` convenience helper in `utils.ts`

  Backwards-compatible — `scopes` is optional and existing consumers compile and run unchanged.

## 0.5.0

### Minor Changes

- 0783155: feat(oauth): opt-in Pushed Authorization Requests (RFC 9126)

  Adds a `usePar?: boolean` flag on `OAuthConfig` and a low-level
  `buildAuthorizationUrlWithPAR(config, pkceOptions)` helper that mirrors
  `openid-client`'s own API.

  `discoverAndBuildAuthorizationUrl` now routes based on the flag:

  - `usePar: true` + provider advertises `pushed_authorization_request_endpoint` → uses PAR.
  - `usePar: true` + provider does **not** advertise PAR → throws.
  - `usePar` unset/false + provider advertises PAR → standard flow plus a
    one-line `info` log noting PAR is available but not enabled.
  - `usePar` unset/false + no PAR endpoint → standard flow, no advisory.

## 0.4.0

### Minor Changes

- ea5bb15: The default `ConsoleLogger` now emits newline-delimited JSON instead of
  bracket-prefixed text. Output stays interoperable with Loki / Grafana /
  Datadog out of the box even when the consuming app hasn't called
  `configureLogger()` to wire in `@eventuras/logger` or pino.

  Each entry includes `level`, ISO `time`, `namespace`, persistent context
  fields, optional `msg`, and the data object (with `Error` instances
  serialized to `{ name, message, stack }`):

  ```json
  {
    "level": "info",
    "time": "2026-04-15T19:40:57.300Z",
    "namespace": "fides-auth:oauth",
    "msg": "PKCE parameters generated"
  }
  ```

  Apps that still want pretty bracketed output during development should
  plug in their own logger via `configureLogger()` — e.g. wire in
  `@eventuras/logger` and let `configureNodeLogger` from
  `@eventuras/logger/node` handle dev pretty-print.

## 0.3.1

### Patch Changes

- 7c9fe79: chore: update dependencies

## 0.3.0

### Minor Changes

- d752b18: ### 🧱 Features
  - feat(fides-auth): add OIDC logout URL builder function (56e010d) [@eventuras/fides-auth]
  - feat(fides-auth): add buildSessionFromTokens function (530c48f) [@eventuras/fides-auth]
  - feat(fides-auth): add exchangeAuthorizationCode function (5187cc4) [@eventuras/fides-auth]

## 0.2.1

### Patch Changes

- Updated dependencies
  - @eventuras/logger@0.6.0

## 0.2.0

### Minor Changes

### 🧱 Features

- feat(fides-auth): enhance authentication library with silent login and logging (a96b1f7) [@eventuras/fides-auth]
- feat(fides-auth): build as library (aaf9247) [@eventuras/fides-auth]

### Patch Changes

- Updated dependencies
  - @eventuras/logger@0.5.0
