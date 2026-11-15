---
'@eventuras/fides-auth': minor
'@eventuras/fides-auth-next': patch
---

`sessionDurationDays` is now `sessionDurationSeconds`, like the other durations in the API, and the
default goes from 30 days to 12 hours. `createFidesAuth` throws a `TypeError` on the old name, and
unless the lifetime is a finite number above 0: a value such as `NaN`, from an unset environment
variable, used to pass and then fail every login with a 500. To keep a 30-day session, set
`sessionDurationSeconds: 30 * 24 * 60 * 60`.
