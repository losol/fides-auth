---
'@eventuras/fides-auth-next': patch
---

The type declarations use explicit `.js` extensions on relative imports, as in
the packages it re-exports, so the types resolve under
`moduleResolution: "nodenext"`. No API change.
