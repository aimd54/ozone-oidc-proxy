# Architecture Decision Records

Significant architectural decisions are recorded here as ADRs, in the spirit
of [MADR](https://adr.github.io/madr/). An ADR is immutable once accepted:
if a decision changes, a new ADR supersedes the old one (which gets its
`Status` updated to `superseded by ADR-XXXX`), preserving the reasoning trail.

The system as a whole is described in
[`docs/architecture.md`](../architecture.md); ADRs pin down individual
decisions and the reasoning behind them.

| ID | Title | Status |
|----|-------|--------|
| [ADR-0001](0001-external-proxy-rather-than-patching-ozone.md) | Add OIDC in front of Ozone rather than inside it | accepted |
| [ADR-0002](0002-identity-through-the-synthetic-header.md) | Carry identity in a synthetic Authorization header | accepted |
| [ADR-0003](0003-temporary-credentials-only.md) | Temporary credentials only, minted by token exchange | accepted |
| [ADR-0004](0004-credential-store-memory-and-valkey.md) | Two credential stores, in-memory and valkey | accepted |
| [ADR-0005](0005-strict-authentication-by-default.md) | Refuse anything unauthenticated, by default | accepted |

Use [`template.md`](template.md) for new ADRs.
