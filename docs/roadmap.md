# Roadmap

What works, what has been checked against a running cluster, and what has not
been built.

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
  local work, and a Prometheus and Grafana overlay.

## Verified against a running cluster

Recorded with dates, image digests, and the commands used in
[VERIFICATION.md](VERIFICATION.md), including the findings that changed the
implementation. boto3, mc and s3a are each exercised against a running
cluster, including an 8 MiB streaming upload read back byte-identical by a
different client, and a lakehouse walkthrough exercises table writes over
these credentials.

Verification tracks the current Ozone release. The exact build under test is in
that record rather than in prose that would go stale.

## Not built

- **Per-chunk streaming signature verification.** Streaming uploads are
  accepted and forwarded; each chunk's signature is not independently verified.
- **Apache Ranger as the authorizer**, in place of native ACLs. The design
  supports the swap by construction because authorization stays in Ozone, but
  it has not been exercised here. See [PRODUCTION.md](PRODUCTION.md).
- **Group claims mapped to Ozone groups.** Out of scope by choice; identity is
  a user, and grouping belongs to whatever manages Ozone's own groups.
- **Migration to native Ozone STS.** The endpoint does not exist in a release
  yet. The exchange stays API-compatible so that migration is a change of
  endpoint URL rather than of tooling; [UPSTREAM.md](UPSTREAM.md) tracks the
  upstream work.
