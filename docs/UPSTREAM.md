# Upstream OIDC/STS tracking — apache/ozone#10266 and HDDS-13323

Status snapshot **2026-07-12**. This project deliberately stays
API-compatible with the upstream direction (DESIGN.md §9.5, §11.6); this
document tracks the upstream work, compares the designs, and sketches the
migration for the day upstream ships something usable. Until then the Go
proxy remains the working path.

## What exists upstream

- **HDDS-13323** — epic "STS - temporary, limited-privilege credentials
  service" (status: Open). Its feature branch `HDDS-13323-sts` carries an
  STS runtime that is **not merged to master**: `AssumeRole`,
  `STSTokenIdentifier`/`STSTokenSecretManager` (OM-signed session tokens),
  `S3STSEndpoint` on a dedicated STS port (9881 in examples),
  `ozone.s3g.sts.http.enabled`, session policies consumed by Ranger.
  The 2.1.x line has been accumulating its authorization plumbing
  (HDDS-13848 in 2.1.0, HDDS-15064 in 2.1.1 — see DESIGN.md §9.5).
- **PR [#10266](https://github.com/apache/ozone/pull/10266)** (HDDS-15273,
  author `paf91`, opened 2026-05-14) — "Add OIDC AssumeRoleWithWebIdentity
  support to Ozone STS", **based on the `HDDS-13323-sts` branch**, 60
  files, +6375. OM validates the JWT (issuer/audience/exp/nbf/JWKS with
  debounced refresh-on-unknown-kid), strips the raw token before Ratis
  replication, authorizes role assumption through a new
  `IAccessAuthorizer.generateAssumeRoleWithWebIdentitySessionPolicy(...)`
  hook, and issues credentials through the existing STS token
  infrastructure. S3G gains a narrowly-scoped unauthenticated bypass for
  `POST /sts` + `Action=AssumeRoleWithWebIdentity` only.
- **PR [#10338](https://github.com/apache/ozone/pull/10338)** — the design
  doc, split out of #10266 on maintainer request, against master
  (label: `design`).

## Where it stands (the "not comfortable" part)

- 2026-05-25, `fmorg-git` (the STS-branch driver): a 6000+-line
  security-impactful PR is unreviewable as one unit; the accepted process
  is design review → feature branch + epic → split PRs ("could easily be
  10 PRs"). The author agreed and reclassified #10266 as **implementation
  reference / discussion material**.
- 2026-05-27: 16 substantive review comments on the design doc (#10338) —
  config naming (`ozone.sts.*` vs the branch's `ozone.s3g.sts.*`),
  single-issuer limitation, how the OIDC claim maps to an Ozone/Kerberos
  identity, why groups/roles claims when Ranger holds the roles, reuse of
  the existing `generateAssumeRoleSessionPolicy` path, JWKS-outage error
  semantics, the need for full Ranger container testing.
- The design review stalled: stale-marked 2026-06-19, author revived it
  2026-06-22 ("busy, gonna pick it up soon"), no activity since.
  **#10266 itself was stale-marked 2026-07-11 and will auto-close ~7 days
  later** — closure will mean "parked", not "rejected".
- Net: even the *base* STS branch is unmerged; the OIDC layer is a
  reference implementation awaiting a design verdict. No released Ozone
  version carries any of it.

## Design comparison

| | Upstream (HDDS-13323-sts + #10266) | This project |
| --- | --- | --- |
| Cluster premise | **Secure** Ozone (Kerberos, `ozone.security.enabled=true`) | Stock **unsecured** 2.1.1 with native ACLs on |
| JWT validator | **OM** is authoritative; raw JWT stripped pre-Ratis | The proxy, in front of the S3 Gateway |
| Credential model | OM-signed `STSTokenIdentifier` via the existing secret-manager path — stateless at S3G, survives restarts, multi-S3G native | Minted into a store (memory / valkey AES-256-GCM), TTL sweeper, admin revocation endpoint |
| Data-path verification | Native secure-mode SigV4 + OM session-token validation; presigned/streaming/multipart are stock secure behavior | Wire-form re-verification in the proxy + synthetic-header attribution; header auth, presigned, streaming and multipart all verified live |
| Authorization | Ranger / `IAccessAuthorizer` is the PDP; role assumption is a policy on the RoleArn resource; groups/roles claims are identity attributes | Ozone native ACLs against the attributed username; RoleArn allowlist only |
| Issuers | Single issuer (`ozone.sts.web.identity.issuer.uri`; flagged in review) | Multi-issuer registry, per-issuer audiences/username-claim, OIDC discovery |
| Client contract | `POST /sts` form `Action=AssumeRoleWithWebIdentity` → AWS-shaped XML → SigV4 + `x-amz-security-token` | **Same, deliberately** (§6.1–§6.4) |
| Hard dependency | A WebIdentity-capable authorizer: the default `generateAssumeRoleWithWebIdentitySessionPolicy` **fails closed** (`NOT_SUPPORTED_OPERATION`); the external Ranger Ozone authorizer must implement it — adoption needs an Ozone release *and* a Ranger release | None beyond stock 2.1.1 |
| Status | Unmerged branch + parked reference PR + stalled design review | M1–M3 implemented and verified live ([VERIFICATION.md](VERIFICATION.md)) |

Convergent details worth noting (independent validation of both designs):
JWKS caching with debounced refresh-on-unknown-kid, fail-closed defaults,
strict no-token-logging discipline, AWS-shaped STS XML. Upstream's OM-side
validation also structurally removes the "S3G must be unreachable" constraint
that this design handles with network policy (§7).

## Migration sketch (when upstream ships)

The client contract matches, so migration is mostly operational:

1. Point clients' STS endpoint at the native S3G STS port (same env-var
   flow; `ozone-login` keeps working — it just produces the JWT).
2. Secure the cluster (Kerberos) and deploy a WebIdentity-capable
   authorizer; translate the RoleArn allowlist into role-assumption
   policies and the native-ACL grants into Ranger policies.
3. Retire the proxy and the valkey store; presigned, streaming and
   multipart come back from stock secure-mode behavior.

Gaps to re-check at that point: multi-issuer support (upstream is
single-issuer today), a second-issuer story for the stub-IdP use case,
and revocation semantics (our admin endpoint vs OM token lifetimes).

## Watch list

```bash
# The design review — the actual gate:
curl -s https://api.github.com/repos/apache/ozone/pulls/10338 | jq '{state, merged, updated_at}'
# The reference implementation (stale; auto-close ≈ 2026-07-18 is expected):
curl -s https://api.github.com/repos/apache/ozone/pulls/10266 | jq '{state, updated_at}'
# The STS epic and the OIDC feature:
curl -s "https://issues.apache.org/jira/rest/api/2/issue/HDDS-13323?fields=status" | jq -r .fields.status.name
curl -s "https://issues.apache.org/jira/rest/api/2/issue/HDDS-15273?fields=status" | jq -r .fields.status.name
# Branch merge status:
git ls-remote https://github.com/apache/ozone.git refs/heads/HDDS-13323-sts
```

Signals that change our posture: the design doc (#10338) merging; the
`HDDS-13323-sts` branch landing on master; a Ranger Ozone authorizer release
implementing the WebIdentity hook; any of it appearing in an Ozone release
changelog. Until at least the first two, there is nothing to adopt.
