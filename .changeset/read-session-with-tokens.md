---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': minor
---

`readSessionWithTokens` gives the session and its tokens in one read, or why there is none.
`readSession` and `getTokens` each read, which with a `sessionStore` is a round trip each. The README
says to read once per request where several parts of it need the session.
