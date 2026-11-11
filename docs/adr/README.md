# Architecture Decision Records

This folder records decisions that shape the structure and public API of fides-auth.

## Convention

- **One decision per file**, named `NNNN-short-title.md`. Numbers go up in order and are never reused.
- **Sections:** Status, Context, Decision drivers, Options, Decision and Consequences. Add a migration plan and open questions when the decision needs them.
- **Status** starts as Proposed. The maintainer then accepts or rejects the ADR. A later ADR can supersede an accepted one, which then links to its replacement. Apart from the status, an accepted ADR isn't edited.
- **New ADRs** are proposed in a docs-only PR. Implementation issues link back to the ADR they come from.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-module-structure-and-bff.md) | Module structure and BFF model for 1.0 | Proposed |
