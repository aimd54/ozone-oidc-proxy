# ADR-0001: Add OIDC in front of Ozone rather than inside it

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

Apache Ozone's S3 Gateway authenticates one of two ways. Secure mode uses
Kerberos-backed SigV4, with credentials issued by `ozone s3 getsecret` and
validated by the Ozone Manager. Unsecured mode validates nothing: any access
key and secret pair is accepted.

An organisation already running an OIDC identity provider can therefore use it
for everything except S3 access to Ozone, where the options are deploying
Kerberos everywhere or accepting a gateway that authenticates nobody.

Upstream is moving but has not arrived. The STS work (HDDS-13323) lives on a
feature branch, and `AssumeRoleWithWebIdentity` is in no release. Authorization
plumbing is being backported into the 2.1.x line (HDDS-13848, HDDS-15064),
which signals direction rather than availability. Adoption would additionally
need a Ranger release, because the default authorizer fails closed on the
WebIdentity path.

Three approaches were weighed: patch or fork Ozone, wait for upstream, or sit
in front of it.

## Decision

We will run **beside a stock, unmodified Ozone** as an external reverse proxy,
coupled to it only through the public S3 API and the header-parsing behaviour
of unsecured mode.

The STS surface will stay **API-compatible with AWS**, which is also the shape
upstream is moving toward, so the day Ozone ships native
`AssumeRoleWithWebIdentity` clients repoint one endpoint URL rather than
rebuilding their tooling.

## Consequences

- Ozone is deployed as released. No fork to rebase, no patch to carry across
  upgrades, and the operational blast radius is one process.
- The proxy owns its release cycle and can move faster than the storage
  cluster underneath it.
- The gateway performs no authentication of its own, so **the network becomes
  the trust boundary**: anyone who can reach the gateway directly can act as
  anyone. Reachability has to be constrained by deployment, which is why the
  Helm chart ships network policies and the production checklist leads with
  this.
- Being API-compatible costs some freedom in the STS surface. Parameters that
  would be convenient to repurpose stay reserved for the meaning AWS gives
  them.
- Revisit when upstream ships `AssumeRoleWithWebIdentity` in a release
  together with an authorizer that implements it. At that point this proxy
  becomes a migration path rather than a destination, and
  [UPSTREAM.md](../UPSTREAM.md) tracks the gap.
