---
"@eventuras/fides-auth": minor
"@eventuras/fides-auth-next": minor
---

Split the session across two cookies to make room for large access tokens.

The access token — typically the largest part of a session — now lives in its
own `session_at` cookie, while the rest stays in `session`, so each gets a full
per-cookie byte budget instead of competing for one ~4KB limit.

The framework-agnostic encode/decode logic lives in the core package as a new
`@eventuras/fides-auth/session-cookies` export (`encodeSessionCookies` /
`decodeSessionCookies`), plus a `decryptJWT` helper in `@eventuras/fides-auth/utils`.
`@eventuras/fides-auth-next` is a thin adapter that wires these to the Next.js
cookie store. Legacy single-cookie sessions are still read transparently, and the
"expired access token means no session" contract is preserved.
