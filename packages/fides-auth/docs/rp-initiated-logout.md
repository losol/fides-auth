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
import { handleOidcLogout } from "@eventuras/fides-auth/server";

return handleOidcLogout(request, {
  oauthConfig,
  cookies,
  postLogoutRedirectUri: "https://app.example.com/",
});
```

That reads the session's ID token, clears the local cookies, and redirects to the
provider's end-session endpoint. Next.js apps can use the wrapper at
`@eventuras/fides-auth-next/oidc-logout`.

## Building the URL yourself

```typescript
import { buildOidcLogoutUrl } from "@eventuras/fides-auth/oauth";

const logoutUrl = await buildOidcLogoutUrl(oauthConfig, {
  postLogoutRedirectUri: "https://app.example.com/",
  idTokenHint: session?.tokens?.idToken,
  state: "correlation-123",
});
```

| Option                 | Sent as                    | Notes                                                       |
| ---------------------- | -------------------------- | ----------------------------------------------------------- |
| `postLogoutRedirectUri` | `post_logout_redirect_uri` | Must be registered with the provider                        |
| `idTokenHint`          | `id_token_hint`            | Identifies the session to end; recommended                  |
| `state`                | `state`                    | Echoed back unchanged on the redirect                       |
| `logoutHint`           | `logout_hint`              | Meaning is provider-specific                                |
| `includeClientId`      | `client_id`                | Default `true`                                              |

Unsupplied parameters are omitted. A string second argument is shorthand for
`postLogoutRedirectUri`.

`buildOidcLogoutUrl` returns `null` when the provider advertises no
`end_session_endpoint`, when discovery fails, or when the endpoint is not https —
the URL carries a raw ID token, so it never travels in the clear. Callers fall back to
a local-only logout.

## Why `id_token_hint` matters

The spec recommends it, and in practice it is what makes logout work smoothly:

- It tells the provider **which** session to terminate when several are active.
- Providers that can skip the "are you sure you want to sign out?" interstitial
  generally do so only when the hint is present.

`session.tokens.idToken` holds the raw token. `buildSessionFromTokens` populates it,
and `refreshSession` replaces it whenever a refresh response carries a new `id_token`
— otherwise the hint would go stale and eventually fall outside the window in which
the provider still recognises it.

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

Sessions are split across three cookies: the access token in `session_at`, the ID
token in `session_it`, everything else in `session`. Each large JWT gets its own
per-cookie byte budget — an encoded ID token is typically 0.5–1.5 kB, and cookies at
or above 4096 bytes are silently dropped by the browser, so sharing a cookie between
two JWTs would eventually surface as a failed *login*.

The ID token is also read independently of session validity. `readSession` returns
null once the access token has expired, but the hint is needed precisely then: an
idle user coming back to a stale tab and clicking log out still has a live session at
the provider. `readIdToken` reads the `session_it` cookie directly, and
`handleOidcLogout` uses it rather than going through the session.

## Correlating the response with `state`

`state` is passed through to the provider and echoed back on the redirect. fides-auth
does not store or verify it; generating a value, persisting it, and checking it on the
way back is the caller's job.

## CSRF

`handleOidcLogout` accepts `POST` only and answers `405` to anything else. That alone
is not protection — a third-party page can auto-submit a form at the endpoint, and the
response clears the cookies whether or not the browser attached them — so the handler
also requires the request to come from the application itself:

- `Sec-Fetch-Site` must be `same-origin` or `none` where the browser sends it.
- Otherwise `Origin`, when present, must match `applicationUrl` (falling back to the
  request's own origin). Set `applicationUrl` behind a proxy, where the request URL
  carries the internal origin.
- A request with neither header is not a browser form post and is allowed through.

Cross-origin requests get `403`. Cross-*subdomain* logout is rejected too; if you need
it, call `buildOidcLogoutUrl` from your own handler with whatever origin check fits.

Use a form or a fetch rather than a plain link:

```html
<form method="post" action="/api/auth/logout"><button>Log out</button></form>
```

Pass `allowedMethods: ["GET", "POST"]` to opt into link-based logout — note this
drops the method check, leaving only the origin check.

## Non-Next.js frameworks

`handleOidcLogout` takes a standard `Request` and a `CookieStore` — an object with
`get`, `set` and `delete`. Any framework that can expose its cookie jar behind those
three methods can use it, the same way `handleOidcLogin` and `handleOidcCallback` do.
