---
'@eventuras/fides-auth-next': major
'@eventuras/fides-auth-react': major
---

`@eventuras/fides-auth` is a peer dependency instead of a dependency, so an app has one copy of
core. Install it next to this package, for example:

```bash
pnpm add @eventuras/fides-auth @eventuras/fides-auth-next
```

Needs Node 22.
