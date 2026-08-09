# Upstream OIDC/STS tracking, apache/ozone#10266 and HDDS-13323

Status snapshot **2026-08-06**. This project deliberately stays
API-compatible with the upstream direction (architecture.md); this
document tracks the upstream work, compares the designs, says what would
make this project unnecessary, and sketches the migration for the day
upstream ships something usable. Until then the Go proxy remains the
working path.

Read it in this order: the published roadmap says what the project has
committed to, the issues and pull requests say how far that work has
actually got, and the two do not currently agree.

## What exists upstream

- **The published [Ozone roadmap](https://ozone.apache.org/roadmap/) lists
  HDDS-13323, "STS - temporary, limited-privilege credentials service",
  under the upcoming 2.3.0 release.** That is the strongest public statement
  of intent on record. What it covers is the STS credential service.
  **OIDC does not appear on the
  roadmap at any release**, past or upcoming: the WebIdentity layer is
  HDDS-15273, a separate issue, absent from the plan. The roadmap's
  authentication history runs Kerberos and Ranger (0.4.0), native ACLs
  (0.4.1), S3 multi-tenancy (1.3.0) and symmetric-key delegation tokens
  (2.0.0), with no OIDC or single sign-on entry anywhere.
- **HDDS-13323**: epic "STS - temporary, limited-privilege credentials
  service" (status: Open, no fix version set, last updated 2026-05-14). Its
  feature branch `HDDS-13323-sts` carries an
  STS runtime that is **not merged to master**: `AssumeRole`,
  `STSTokenIdentifier`/`STSTokenSecretManager` (OM-signed session tokens),
  `S3STSEndpoint` on a dedicated STS port (9881 in examples),
  `ozone.s3g.sts.http.enabled`, session policies consumed by Ranger.
  The 2.1.x line has been accumulating its authorization plumbing
  (HDDS-13848 in 2.1.0, HDDS-15064 in 2.1.1, see architecture.md).
- **PR [#10266](https://github.com/apache/ozone/pull/10266)** (HDDS-15273,
  opened 2026-05-14): "Add OIDC AssumeRoleWithWebIdentity
  support to Ozone STS", **based on the `HDDS-13323-sts` branch**, 60
  files, +6375. OM validates the JWT (issuer/audience/exp/nbf/JWKS with
  debounced refresh-on-unknown-kid), strips the raw token before Ratis
  replication, authorizes role assumption through a new
  `IAccessAuthorizer.generateAssumeRoleWithWebIdentitySessionPolicy(...)`
  hook, and issues credentials through the existing STS token
  infrastructure. S3G gains a narrowly-scoped unauthenticated bypass for
  `POST /sts` + `Action=AssumeRoleWithWebIdentity` only.
- **PR [#10338](https://github.com/apache/ozone/pull/10338)**: the design
  doc, split out of #10266 on maintainer request, against master
  (label: `design`). Closed unmerged 2026-07-22.

## Where it stands

- 2026-05-25: reviewers held that a 6000+-line security-impactful PR is not
  reviewable as one unit, and that the accepted process is design review →
  feature branch + epic → split PRs. #10266 was reclassified as
  **implementation reference / discussion material** rather than a merge
  candidate.
- 2026-05-27: 16 substantive review comments on the design doc (#10338),
  config naming (`ozone.sts.*` vs the branch's `ozone.s3g.sts.*`),
  single-issuer limitation, how the OIDC claim maps to an Ozone/Kerberos
  identity, why groups/roles claims when Ranger holds the roles, reuse of
  the existing `generateAssumeRoleSessionPolicy` path, JWKS-outage error
  semantics, the need for full Ranger container testing.
- The design review did not conclude. #10338 was stale-marked 2026-06-19,
  briefly revived 2026-06-22, and **closed unmerged on 2026-07-22**.
  Closure here reads as "parked", not "rejected": no verdict was recorded
  on the design itself.
- **#10266 was converted to a draft on 2026-08-05** and remains open.
  `HDDS-13323-sts` still exists as a branch, so the reference implementation
  is still there to read, but a draft is a step away from merge rather than
  toward it, and HDDS-15273 carries no discussion alongside the change.
- Net: the roadmap commits to STS for a named release, and the code is not
  close. The base STS branch is unmerged, the epic has no fix version
  assigned and has not changed since 2026-05-14, the design review closed
  without a decision, and the OIDC implementation is a draft. No released
  Ozone version carries any of it. Both are true at the same time. The
  roadmap carries more weight, because a release plan is a project decision
  and a pull request is not.

## Design comparison

| | Upstream (HDDS-13323-sts + #10266) | This project |
| --- | --- | --- |
| Cluster premise | **Secure** Ozone (Kerberos, `ozone.security.enabled=true`) | Stock **unsecured** 2.1.1 with native ACLs on |
| JWT validator | **OM** is authoritative; raw JWT stripped pre-Ratis | The proxy, in front of the S3 Gateway |
| Credential model | OM-signed `STSTokenIdentifier` via the existing secret-manager path, stateless at S3G, survives restarts, multi-S3G native | Minted into a store (memory / valkey AES-256-GCM), TTL sweeper, admin revocation endpoint |
| Data-path verification | Native secure-mode SigV4 + OM session-token validation; presigned/streaming/multipart are stock secure behavior | Wire-form re-verification in the proxy + synthetic-header attribution; header auth, presigned, streaming and multipart all verified live |
| Data-path authorization | Ranger / `IAccessAuthorizer` is the PDP; groups and roles claims are identity attributes | Whatever `ozone.acl.authorizer.class` is set to, evaluating the attributed username. The proxy is authorizer-agnostic by construction: it injects a username and takes no part in the decision. Native ACLs are what has been verified; Ranger needs no change to the proxy but has not been exercised here |
| Role assumption | A Ranger policy on the RoleArn resource, with session policies scoping the credentials | A static RoleArn allowlist. Coarser, and the one place upstream's model is genuinely richer |
| Issuers | Single issuer (`ozone.sts.web.identity.issuer.uri`; flagged in review) | Multi-issuer registry, per-issuer audiences/username-claim, OIDC discovery |
| Client contract | `POST /sts` form `Action=AssumeRoleWithWebIdentity` → AWS-shaped XML → SigV4 + `x-amz-security-token` | **Same, deliberately** (–) |
| Hard dependency | A WebIdentity-capable authorizer: the default `generateAssumeRoleWithWebIdentitySessionPolicy` **fails closed** (`NOT_SUPPORTED_OPERATION`); the external Ranger Ozone authorizer must implement it, adoption needs an Ozone release *and* a Ranger release | None beyond stock 2.1.1 |
| Status | Slated for 2.3.0 on the roadmap; branch unmerged, design review closed without a verdict, OIDC layer in draft | Implemented and verified live ([verification.md](verification.md)) |

Convergent details worth noting (independent validation of both designs):
JWKS caching with debounced refresh-on-unknown-kid, fail-closed defaults,
strict no-token-logging discipline, AWS-shaped STS XML. Upstream's OM-side
validation also structurally removes the "S3G must be unreachable" constraint
that this design handles with network policy.

## What would make this project unnecessary

This project is a bridge. Two things would end it, and neither is on the
roadmap today.

**Upstream STS shipping in 2.3.0 is not one of them.** Per the design
comparison, upstream STS assumes a Kerberos-secured cluster with
`ozone.security.enabled=true` and an authorizer implementing the
WebIdentity hook, which in practice means Ranger, so adopting it needs an
Ozone release *and* a Ranger release. A cluster running unsecured with
native ACLs gains nothing from it, and that cluster is the premise this
project is built on.

**The first ending is HDDS-15273 landing and working without Kerberos.**
If OIDC WebIdentity reaches a release and can attribute identities on a
cluster that has not been secured, this project has no remaining purpose
and its users should migrate. Nothing in the design as published points
that way, but it is the thing to watch, and it is why the client contract
is kept identical.

**The second is Ozone becoming easy to secure.** If running Kerberos and
Ranger stops being burdensome enough to justify an unsecured cluster
behind a proxy, the trade this project makes no longer pays, whatever
happens to OIDC upstream.

## Migration sketch (when upstream ships)

The client contract matches, so migration is mostly operational:

1. Point clients' STS endpoint at the native S3G STS port (same env-var
   flow; `ozone-login` keeps working; it just produces the JWT).
2. Secure the cluster (Kerberos) and deploy a WebIdentity-capable
   authorizer; translate the RoleArn allowlist into role-assumption
   policies and the native-ACL grants into Ranger policies.
3. Retire the proxy and the valkey store; presigned, streaming and
   multipart come back from stock secure-mode behavior.

Gaps to re-check at that point: multi-issuer support (upstream is
single-issuer today), a second-issuer story for the stub-IdP use case,
and revocation semantics (this project's admin endpoint against OM token
lifetimes).

## Watch list

```bash
# The release plan: whether STS is still slated for 2.3.0, and whether OIDC
# has appeared alongside it. Read it first; it outranks the rest. The page is
# one long line of HTML, so pull the issue titles out rather than grepping it
# whole.
curl -s https://ozone.apache.org/roadmap/ |
  grep -o 'HDDS-[0-9]*</a>[^<]*' | grep -iE 'sts|oidc|identity|token|auth|credential'
# The epic and the OIDC feature. Watch fixVersion, not just status: an epic
# with a fix version assigned has been scheduled rather than merely filed.
curl -s "https://issues.apache.org/jira/rest/api/2/issue/HDDS-13323?fields=status,fixVersions,updated" | jq '.fields|{status:.status.name, fixVersions:[.fixVersions[].name], updated}'
curl -s "https://issues.apache.org/jira/rest/api/2/issue/HDDS-15273?fields=status,fixVersions,updated" | jq '.fields|{status:.status.name, fixVersions:[.fixVersions[].name], updated}'
# The reference implementation. `draft: false` returning to review is the
# signal; it was converted to a draft on 2026-08-05.
curl -s https://api.github.com/repos/apache/ozone/pulls/10266 | jq '{state, draft, updated_at}'
# The design review that gated the OIDC layer, closed unmerged. Watch for a
# successor design PR against master rather than for this one reopening.
curl -s https://api.github.com/repos/apache/ozone/pulls/10338 | jq '{state, merged, updated_at}'
# Branch merge status: equal hashes mean the STS runtime reached master.
git ls-remote https://github.com/apache/ozone.git refs/heads/HDDS-13323-sts refs/heads/master
```

Signals that change the picture, in descending order of weight: **OIDC or
WebIdentity appearing on the roadmap**, which today it does not; HDDS-15273
gaining a fix version; the `HDDS-13323-sts` branch landing on master; a
Ranger Ozone authorizer release implementing the WebIdentity hook; any of it
appearing in an Ozone release changelog.

STS shipping in 2.3.0 as planned is not on that list, and its absence is
not an oversight: it serves secured clusters and this serves unsecured
ones, as "What would make this project unnecessary" sets out.
