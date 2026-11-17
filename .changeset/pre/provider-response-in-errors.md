---
'@eventuras/fides-auth': patch
---

An error from the provider no longer carries the provider's response. When a token response arrived with a 2xx
status and then failed validation, a missing `token_type` say, `oauth4webapi` attached the whole response to the
error it threw, access and refresh tokens included. The library logged that error and handed it to `onLoginError`
as `cause`. The default logger prints only the name, the message and the stack, so nothing leaked there, but a
logger that prints an error in depth, or a `console.error(failure.cause)` in the app, wrote the tokens out. A
UserInfo response without a `sub` carried the user's claims the same way. The OIDC client now takes the response
off every error it lets out, and what the error says was wrong stays.
