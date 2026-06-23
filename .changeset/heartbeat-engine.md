---
"@eventuras/fides-auth": minor
"@eventuras/fides-auth-next": patch
---

Add a framework-agnostic `createHeartbeat()` engine at `@eventuras/fides-auth/heartbeat`. `fides-auth-next`'s `useHeartbeat` is now a thin wrapper over it; behaviour and API unchanged.
