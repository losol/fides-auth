# fides-auth

Framework-agnostic OAuth/OIDC authentication for JavaScript — PKCE, session
management, and pluggable logging — with optional store, React, and Next.js
bindings.

## Packages

| Package                                                    | Description                                                 |
| ---------------------------------------------------------- | ----------------------------------------------------------- |
| [`@eventuras/fides-auth`](packages/fides-auth)             | Core OAuth/OIDC library (PKCE, sessions, logging)           |
| [`@eventuras/fides-auth-store`](packages/fides-auth-store) | Framework-agnostic auth state store (XState Store)          |
| [`@eventuras/fides-auth-react`](packages/fides-auth-react) | React hooks — store bindings, session monitoring, heartbeat |
| [`@eventuras/fides-auth-next`](packages/fides-auth-next)   | Next.js bindings                                            |

See each package's README for install and usage.

## Development

Requires Node 22 (see [`.nvmrc`](.nvmrc)) and pnpm.

```bash
pnpm install      # install dependencies
pnpm build        # build all packages
pnpm test         # run tests
pnpm changeset    # record a change for release
```

## License

MIT
