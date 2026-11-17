# Security policy

## Reporting a vulnerability

Please don't open a public issue for a vulnerability. Report it privately on
GitHub: the repository's **Security** tab, then **Report a vulnerability**, or
<https://github.com/losol/fides-auth/security/advisories/new>.

Say what you found, in which package and version, and how to reproduce it. A
failing test or a short script is the best report there is.

## Supported versions

Security fixes go into the latest release of `@eventuras/fides-auth`,
`@eventuras/fides-auth-next` and `@eventuras/fides-auth-react`.

## What the library trusts

A report is easier to judge against what the library takes on trust:

- **The session secret.** Whoever has it can read and forge sessions.
- **The identity provider** named in the configuration, over TLS.
- **Write access to the session store.** A stored session is sealed for its
  own key, so it can't be moved to another, but a record put back after a
  logout reads again until it expires. See the security notes in
  [`docs/server-sessions.md`](packages/fides-auth/docs/server-sessions.md).
- **The app's own callbacks**, such as `mapSession` and `validateReturnTo`.
