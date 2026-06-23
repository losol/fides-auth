---
"@eventuras/fides-auth-next": patch
---

Move the React hooks (`createAuthStoreHooks`, `useSessionMonitor`, `useHeartbeat`) into a new `@eventuras/fides-auth-react` package. `fides-auth-next` re-exports them, so its public API is unchanged.
