# ADR-0002: Carry identity in a synthetic Authorization header

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

Something has to tell Ozone which user a request belongs to, or its ACLs have
nothing to act on and every request arrives as the same identity.

Two properties of the system make one approach possible.

The S3 Gateway parses the SigV4 `Authorization` header and forwards the access
key ID to the Ozone Manager, which derives the request user from it and
evaluates ACLs against that user. With `ozone.security.enabled=false`, **only
signature validation is skipped**: attribution and ACL evaluation still happen.
Verified live against a running cluster, recorded in
[VERIFICATION.md](../VERIFICATION.md).

Separately, SigV4 never transmits the secret. A client sends an HMAC derived
from it, so a proxy cannot validate credentials it did not mint. The token has
to reach the proxy once, away from the data path, which is exactly what a token
exchange is.

## Decision

We will **put the authenticated username in the access-key-ID field** of an
`Authorization` header the gateway considers well-formed, and let the Ozone
Manager enforce that user's ACLs.

Authorization stays in Ozone. The proxy authenticates and attributes; it does
not decide what a user may reach.

## Consequences

- Ozone's own ACLs work unchanged, including bucket ownership, and an operator
  keeps using the tooling they already know rather than learning a policy
  language that exists only here.
- **This is why the project is Ozone-specific.** It depends on how Ozone
  attributes requests in unsecured mode, which is not how other S3
  implementations behave. Pointing it at MinIO or Ceph would not merely be
  unsupported, it would authenticate nobody.
- Authorization logic never accumulates in the proxy, so there is no second
  policy engine to keep consistent with the first, and no bypass when someone
  reaches Ozone directly.
- The synthetic header is not upstream authentication, and it must not be
  mistaken for it. Everything in ADR-0001 about the network being the trust
  boundary follows from this.
- Revisit if Ozone changes how the gateway derives identity in unsecured mode.
  The verification record exists so that a future release can be checked
  against the same assertions rather than assumed to behave the same way.
