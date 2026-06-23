---
"@eventuras/fides-auth-next": patch
---

Move the framework-agnostic authentication store into a new
`@eventuras/fides-auth-store` package.

The XState-Store-based auth state (`createAuthStore`, `initializeAuth`,
`checkAuth`, `startSessionMonitor`, `configureAuthLogger`, and the `SessionUser`
/ `AuthStatus` / `AuthStoreContext` / `AuthStoreConfig` / `SessionMonitorConfig`
types) has no dependency on Next.js or React — the application supplies a
`checkAuthStatus` callback and the store never touches cookies or a server. It
now lives in its own package so other adapters (e.g. React Router) and plain
JavaScript can use it directly.

`@eventuras/fides-auth-next` re-exports the store from the new package, so
`@eventuras/fides-auth-next/store` imports keep working unchanged. The React
hooks (`createAuthStoreHooks`, `useSessionMonitor`, `useHeartbeat`) stay in this
package for now.
