# Roadmap

What works, what has been checked against a running cluster, what is planned
next, and what has deliberately not been built.

## Working

- **Token exchange.** An AWS-compatible `AssumeRoleWithWebIdentity` endpoint,
  accepting tokens from several issuers at once, each with its own audiences,
  username claim, and JWKS source.
- **SigV4 data path.** Header authentication, presigned URLs, and streaming
  uploads (`aws-chunked`), with the signature recomputed from the wire and
  compared in constant time.
- **Bearer data path.** `Authorization: Bearer <token>` accepted directly, for
  browsers behind oauth2-proxy and for clients that would rather not sign.
- **Native ACL attribution.** Requests reach Ozone attributed to the
  authenticated user, so its own ACLs apply (ADR-0002).
- **Strict authentication.** No anonymous fallback on the data path
  (ADR-0005).
- **Multipart uploads**, including the ACL behaviour Ozone enforces on
  `ListParts` and `ListMultipartUploads`.
- **Human credential flows.** `ozone-login` runs a device-flow login and keeps
  a token file fresh; the credential portal renders temporary credentials in a
  browser.
- **Shared credential store.** valkey-backed, encrypted at rest, so more than
  one replica can serve the same clients (ADR-0004).
- **Revocation.** An administrative endpoint deletes a credential, taking
  effect across replicas.
- **Deployment.** A Helm chart with network policies, a compose stack for
  local work, and a Prometheus and Grafana overlay. A worked Kubernetes
  example runs Ozone from its own official chart with the proxy in front of
  it, so the deployment path is exercised rather than described.
- **Signed releases.** Binaries for linux and darwin on amd64 and arm64, each
  archive carrying an SBOM, with the checksums signed keylessly and build
  provenance attested. A distroless container image is published alongside.

## Verified against a running cluster

Recorded with dates, image digests, and the commands used in
[verification.md](verification.md), including the findings that changed the
implementation. boto3, mc and s3a are each exercised against a running
cluster, including an 8 MiB streaming upload read back byte-identical by a
different client, and a lakehouse walkthrough exercises table writes over
these credentials.

On Kubernetes, the same attribution was confirmed against Ozone installed
from its official Helm chart: a bucket created through the proxy is owned by
the OIDC user, and a pod that tries to reach the S3 Gateway directly cannot,
so the network policy holding the trust boundary is enforced rather than only
rendered.

Verification tracks the current Ozone release. The exact build under test is in
that record rather than in prose that would go stale.

## Planned

Ordered by what stands between this and a defensible production deployment.
Each is intended work rather than a decision against it, which is what
separates this list from the one below.

- **Rate limiting on the STS lane.** The token exchange is the only surface
  that accepts an unauthenticated request, since the JWT is parsed before
  anything is trusted, and no shipped configuration throttles it. The
  production checklist lists it as a requirement and defers it to the edge,
  but the TLS edge overlay does not implement it either, so the box cannot
  currently be ticked with anything this repository provides. Where it belongs
  is an open question: the proxy would cover every deployment shape, including
  the chart, which ships no edge, but it would have to decide whether to trust
  a forwarded client address, and that is a security decision in its own
  right. The 1 MiB body cap is not a rate limit.
- **Alert rules, and a probe that fails loudly.** The metrics and the Grafana
  dashboard exist; nothing acts on them. Two checks matter more than the rest,
  because both fail silently open if a policy is edited carelessly: an
  anonymous request to the proxy must be refused, and the S3 Gateway must not
  be reachable from outside the sanctioned path. Verification-failure spikes,
  store errors, issuer unreachability and upstream error rates are worth
  alerting on once the rules file exists.
- **Unit coverage on the identity-injection path.** `RewriteAccessKeyID` in
  `internal/forward` decides which username Ozone attributes every
  primary-data-path request to, and strips the session token from both the
  header and the signed-headers list. It has no unit test, while its two
  siblings do. `internal/s3err` renders every data-path rejection and has no
  test file at all, though correct S3 error codes are what make SDK retry
  behaviour work. Both are exercised by the acceptance suite, but this
  project's own rule is that anything on the authentication path carries a
  negative case.
- **An operations runbook.** Credential revocation, identity-provider signing
  key rotation, and the response to a leaked credential. All three are
  implemented and verified; none is written down as a procedure someone could
  follow under pressure.

## Not built

- **Per-chunk streaming signature verification.** Streaming uploads are
  accepted and forwarded; each chunk's signature is not independently verified.
- **Apache Ranger as the authorizer**, in place of native ACLs. The design
  supports the swap by construction because authorization stays in Ozone, but
  it has not been exercised here. See [production.md](production.md).
- **Group claims mapped to Ozone groups.** Out of scope by choice; identity is
  a user, and grouping belongs to whatever manages Ozone's own groups.
- **Migration to native Ozone STS.** The endpoint does not exist in a release
  yet. The exchange stays API-compatible so that migration is a change of
  endpoint URL rather than of tooling; [upstream.md](upstream.md) tracks the
  upstream work.
