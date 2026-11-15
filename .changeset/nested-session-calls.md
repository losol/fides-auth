---
'@eventuras/fides-auth': patch
'@eventuras/fides-auth-next': patch
---

A function given to `updateSession`, or a `mapRefresh`, that refreshed, updated or ended the same session
waited for itself and never returned. Such a call is now refused with a TypeError at once, on runtimes with
`AsyncLocalStorage` (Node, Deno, Bun, Workers with Node compatibility). The docs also say what `updateSession`
does when the store fails: it rejects with what the store threw, where `refreshSession` answers
`cause: 'store'`.
