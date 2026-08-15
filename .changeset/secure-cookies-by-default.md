---
"@eventuras/fides-auth": minor
---

Set `secure` on the default cookie options unconditionally.

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
