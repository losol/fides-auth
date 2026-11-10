---
'@eventuras/fides-auth-store': minor
---

Breaking: `SessionUser.email`, and so `AuthStatus.user.email`, is optional; handle
`undefined`. The login log line falls back to the user's name.
