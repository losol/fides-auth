# RP-Initiated Logout

Clearing your application's session cookie is not a logout. The provider's session
cookie survives, so the next `/authorize` round trip re-authenticates silently and
the user appears logged in again. Ending the provider session too requires an
RP-initiated logout request — [OpenID Connect RP-Initiated Logout 1.0][spec].

"RP" is the *relying party*: your application, the one relying on the provider for
authentication. The provider itself is the "OP", the *OpenID provider*. RP-initiated
means your application starts the logout, as opposed to OP-initiated logout, where the
provider notifies applications that a session ended elsewhere — fides-auth has no
support for that direction.

[spec]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

## The short version

```typescript
import { createFidesAuth } from "@eventuras/fides-auth/server";

const auth = createFidesAuth({
  oauthConfig,
  secret: process.env.SESSION_SECRET!,
  postLogoutRedirectUri: "https://app.example.com/", // defaults to the app's origin
});

// The logout route
return auth.handleOidcLogout(request, cookies);
```

That reads the session's ID token, ends the session, and redirects to the
provider's end-session endpoint. Next.js apps get the same member from
`createFidesAuth` in `@eventuras/fides-auth-next`, without the `cookies`
argument. Pass `{ state, logoutHint }` as the third argument when you need them.

## Building the URL yourself

```typescript
const logoutUrl = await auth.oidc.logoutUrl({
  postLogoutRedirectUri: "https://app.example.com/",
  idTokenHint: (await auth.getTokens(cookies))?.idToken,
  state: "correlation-123",
});
```

`auth.oidc` is the instance's client; a client from `createOidcClient` in `/oidc`
has the same `logoutUrl`.

| Option                 | Sent as                    | Notes                                                       |
| ---------------------- | -------------------------- | ----------------------------------------------------------- |
| `postLogoutRedirectUri` | `post_logout_redirect_uri` | Must be registered with the provider                        |
| `idTokenHint`          | `id_token_hint`            | Identifies the session to end; recommended                  |
| `state`                | `state`                    | Echoed back unchanged on the redirect                       |
| `logoutHint`           | `logout_hint`              | Meaning is provider-specific                                |
| `includeClientId`      | `client_id`                | Default `true`                                              |

Unsupplied parameters are omitted.

`logoutUrl` returns `null` when the provider advertises no
`end_session_endpoint`, when discovery fails, or when the endpoint is not https —
the URL carries a raw ID token, so it never travels in the clear. Callers fall back to
a local-only logout.

## Why `id_token_hint` matters

The spec recommends it, and in practice it is what makes logout work smoothly:

- It tells the provider **which** session to terminate when several are active.
- Providers that can skip the "are you sure you want to sign out?" interstitial
  generally do so only when the hint is present.

The session's tokens hold the raw ID token from login, and a refresh replaces it
whenever the response carries a new `id_token`. Otherwise the hint would go stale,
and eventually fall outside the window in which the provider still recognises it.

## Why `client_id` is still sent

`client_id` is sent by default, including alongside `id_token_hint`. The spec allows
both:

> When both `client_id` and `id_token_hint` are present, the OP MUST verify that the
> Client Identifier matches the one used when issuing the ID Token.

It also earns its place in the degraded cases. A provider **must not** redirect to
`post_logout_redirect_uri` unless it can confirm the target is legitimate, and
`client_id` is one of the ways it does that — which is what keeps logout working when
there is no session left to take a hint from, or when the ID token is old enough that
the provider no longer accepts it.

Set `includeClientId: false` only for a provider that documents rejecting the
combination.

## Where the ID token is stored

The ID token is sealed into the session record with the other tokens: in the
session cookie, or in the store record with a
[`sessionStore`](./server-sessions.md). A session reads until `expiresAt`,
whether or not its access token has expired. So the hint is there when an idle
user comes back to a stale tab and logs out, which is when it is needed most:
the provider session is still live.

## Correlating the response with `state`

`state` is passed through to the provider and echoed back on the redirect. fides-auth
does not store or verify it; generating a value, persisting it, and checking it on the
way back is the caller's job.

## CSRF

`handleOidcLogout` accepts `POST` only and answers `405` to anything else. That
alone is not protection: a third-party page can auto-submit a form at the
endpoint, and the browser attaches the session cookie. So the handler also
requires the request to come from the application itself:

- `Sec-Fetch-Site` must be `same-origin` or `none` where the browser sends it.
- Otherwise `Origin`, when present, must match `applicationUrl`, which defaults
  to the redirect URI's origin. Set it behind a proxy, if the redirect URI's
  origin isn't the one the browser sees.
- A request with neither header is not a browser form post and is allowed through.

Cross-origin requests get `403`. Cross-*subdomain* logout is rejected too; if you
need it, call `auth.oidc.logoutUrl` from your own handler with whatever origin
check fits.

Use a form or a fetch rather than a plain link:

```html
<form method="post" action="/api/auth/logout"><button>Log out</button></form>
```

## Non-Next.js frameworks

The instance's members take a standard `Request` and a `CookieStore`, an object
with `get` and `set`. Any framework that can expose its cookies behind those two
methods can use `handleOidcLogout`, the same way it uses the login and callback
handlers.
