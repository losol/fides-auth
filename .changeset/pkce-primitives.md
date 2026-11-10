---
'@eventuras/fides-auth': minor
---

New `@eventuras/fides-auth/pkce` entry point with `createPkcePair()` (verifier
and S256 challenge) and `createState()`. It uses Web Crypto only, so it also runs
in the browser and on edge runtimes. `buildPKCEOptions` now uses them and logs at
`debug` instead of `info`.
