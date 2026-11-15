---
'@eventuras/fides-auth': patch
---

`createFidesAuth` throws a `TypeError` when `sessionDurationDays` isn't a finite number above 0.
A value such as `NaN`, from an unset environment variable, used to pass and then fail every login
with a 500. A fraction of a day is fine, and now documented: `1 / 3` is eight hours.
