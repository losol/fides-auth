# The session format

What the library writes to a browser and to a store, and what stays the same
through 1.x. For an operator who has to read a store, plan an upgrade or
explain a cookie, and for whoever changes the library.

It is not an API. An app reads and writes sessions through `createFidesAuth`,
not by opening these values itself: see [In a test](#in-a-test).

## What is stable

- **Every 1.x reads what any 1.x wrote**: a session cookie, a store record, a
  lookup hash and a login under way. An upgrade or a rollback inside 1.x logs
  nobody out.
- A later 1.x may add optional fields to `session` or `tokens`. An older 1.x
  keeps the ones it doesn't know when it saves the session again.
- The record's `v` changes only in a new major. A 1.x that meets another
  version says so, as `unsupported_session_version`, and reads nothing from it.
- The secret, `issuer` and `clientId` are part of every sealing key, so a
  change of one of them is a change of key: old sessions read as
  `unreadable_session`. A secret can be replaced without that, by keeping the
  old one in the list for a while: see
  [Replacing the secret](../README.md#replacing-the-secret).

`src/server/session-format.test.ts` holds values written by 1.0.0-beta.8 and
fails the moment one of them stops reading.

## The record

One JSON object, the same under both storages:

```ts
{
  v: 1,
  session: {
    correlationId: string,   // the library's id for the session, in every log line
    createdAt: string,       // ISO 8601
    expiresAt: string,       // ISO 8601, fixed at login
    user?: { sub: string, name?: string, email?: string, roles?: string[] },
    scopes?: string[],
    idp?: { iss: string, sub: string, sid?: string }, // from the ID token
    data?: unknown,          // the app's own, from mapSession and updateSession
  },
  tokens: {
    accessToken?: string,
    accessTokenExpiresAt?: string,
    accessTokenIssuedAt?: string,
    refreshToken?: string,
    idToken?: string,
  },
}
```

`session` is what the app sees. `tokens` never leaves the server.

## How it is sealed

The record is the payload of a compact JWE with `alg: dir` and
`enc: A256GCM`, with an `iat` claim added. A token that names another
algorithm doesn't open.

The key is 32 bytes from HKDF-SHA-256 over the secret, with an empty salt and
this `info`:

```ts
JSON.stringify(["fides-auth session", audience, binding])
```

- `audience` is `JSON.stringify([issuer, clientId])`. The issuer is written
  one way first: scheme and host in lower case, no default port, no trailing
  slash.
- `binding` is `cookie` under cookie storage, and `store <key>` under a store,
  where `<key>` is the record's own store key.

So a sealed session opens only for the provider and client it was made for,
and a stored one only under its own key: not under another, and not as a
cookie.

Where `secret` is a list, each secret gives a key of its own. The first one's
seals, and each is tried in turn to open.

## Cookie storage

The sealed string is the value of `__Host-session`. One that doesn't fit in a
cookie is cut into up to three, `__Host-session`, `__Host-session.1` and
`__Host-session.2`, each below 4096 bytes with its name. They are `HttpOnly`,
`Secure`, `SameSite=Lax`, on `/`, with a `Max-Age` of the time left in the
session.

Over plain http, for development, the cookies are called `session`,
`session.1` and `session.2`, and are not `Secure`.

## Store storage

`__Host-session` holds a handle: 32 random bytes as 64 hex characters. The
record is stored under `SHA-256(handle)`, as hex, so neither a store dump nor
a logged key is a cookie.

What the store gets under that key:

| Field | What it is |
|---|---|
| `data` | The sealed record. |
| `expiresAt` | The session's end, ISO 8601, for the store's own expiry. The library goes by the sealed one. |
| `correlationId` | The session's id, so a record can be found from a log line. |
| `iss` | The ID token's issuer, as the provider wrote it. |
| `subHash` | HMAC-SHA-256 of the ID token's `sub`, as hex. |
| `idpSidHash` | HMAC-SHA-256 of the ID token's `sid`, as hex. |
| `fields` | What `storeFields` returned. Not sealed. |

The two hashes find a user's sessions without the store knowing the user.
Their key is HKDF-SHA-256 of the secret with the info
`fides-auth session lookup v1`. A record carries the hashes of the secret it
was last saved with, so where `secret` is a list a search asks for each.

**`fields` are in the clear.** Whoever can read the store reads them. A role
or the app's own user id is what they are for. An e-mail address, a name or
anything else that identifies a person is not: put that in the session's
`data`, which is sealed, and keep in `fields` only what a query needs.

## A login under way

Between the redirect to the provider and the callback, the state, the PKCE
verifier, the return path and the scope asked for are sealed in a cookie of
their own: `__Host-oauth_tx_0`, `_1` or `_2`, for ten minutes. It is a JWE
like the session's, under a key with the info `fides-auth login-tx`, so a
login never opens as a session.

## In a test

To start a session in a test, or read one, use the instance. It needs no
provider for that:

```ts
import { createFidesAuth, fetchCookieStore } from "@eventuras/fides-auth/server";

const auth = createFidesAuth({ oauthConfig, secret });

// Start a session, and take the cookies it set.
const cookies = fetchCookieStore(new Request("https://app.test/"));
await auth.createSession(cookies, {
  access_token: "access-token",
  token_type: "bearer",
  expires_in: 300,
  id_token: unsignedIdToken({ iss: oauthConfig.issuer, sub: "user-1" }),
});
const cookie = cookies
  .headers()
  .getSetCookie()
  .map((line) => line.split(";")[0])
  .join("; ");

// Send them with a request, as a browser would.
const request = new Request("https://app.test/account", { headers: { cookie } });
const session = await auth.readSession(fetchCookieStore(request));
```

`createSession` decodes the ID token without verifying it, so a test can make
one up: a base64url header and payload, and an empty signature.

```ts
const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const unsignedIdToken = (claims: object) => `${b64({ alg: "none" })}.${b64(claims)}.`;
```

With `sessionStore: createMemorySessionStore()` the same code gives a stored
session and a handle in the cookie.
