---
'@eventuras/fides-auth-store': patch
'@eventuras/fides-auth-next': patch
---

Ship the declaration files the entry point re-exports. `dist/index.d.ts`
re-exported `SessionUser` and `AuthStatus` from `./types`, but `dist/types.d.ts`
was never emitted, so importing either type failed to resolve. The shared
tsconfig's `include`/`exclude`/`outDir` resolved relative to the config package
instead of the consuming package; they now use `${configDir}`. The same fix
stops `setupTests.d.ts` from being emitted into `@eventuras/fides-auth-next`.
