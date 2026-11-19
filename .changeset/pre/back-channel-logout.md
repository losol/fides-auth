---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': minor
---

`handleBackChannelLogout` lets the provider end a user's sessions: OpenID Connect Back-Channel Logout 1.0. Register its route as the client's `backchannel_logout_uri`. The provider posts a signed logout token there when the user logs out with it, or when an administrator ends their session, and the handler ends the sessions the token names, the one with its `sid` or else all of its `sub`, and revokes their refresh tokens, as `endUserSessions` does. It answers 200 when they are ended, also when there were none, and 400 when the token is refused or the store failed.

It needs a `sessionStore` with `findMatching`, and throws a `TypeError` without one rather than tell the provider that it logged anyone out: a session kept in cookies can't be ended from the server.

`oidc.verifyLogoutToken(logoutToken)` is the check on its own, for an app that ends its sessions another way. It verifies the signature, `iss`, `aud`, `iat`, `exp` and `jti`, that the token has a `sub` or a `sid` and the back-channel logout event, and that it has no `nonce`. It throws a `LogoutTokenError` with a `reason`.

A session ended this way is a `session.cleared` event with the new `trigger: "back_channel_logout"`. Code that switches over the triggers gets one more.
