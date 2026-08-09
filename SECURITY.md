# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository
(<https://github.com/aimd54/ozone-oidc-proxy/security/advisories/new>).

You can expect an acknowledgement within 7 days. Reports are triaged,
fixed privately, and disclosed via a GitHub Security Advisory once a
patched release is available.

## Supported versions

Pre-1.0, only the latest minor release line receives security fixes.

## Disclosure in releases

Every release whose changes fix a publicly known vulnerability names it in the
release notes, with its CVE identifier where one has been assigned, so that
reading the notes is enough to tell whether an upgrade carries a security fix.
Vulnerabilities reported privately are disclosed the same way once a patched
release exists, alongside the GitHub Security Advisory.

Releases that fix nothing security-relevant say nothing about it, so the
absence of a note means no known vulnerability was addressed.

## Scope notes

This proxy is an authentication boundary in front of an Ozone cluster running
with `ozone.security.enabled=false`, where **anything that reaches the S3
Gateway can act as any user** (see [docs/architecture.md](docs/architecture.md)).
Anything that lets a caller obtain an identity it should not have is in scope
and highly appreciated:

- **Authentication bypass**: any request that reaches the upstream gateway
  without a valid Bearer token or a verified temporary-credential SigV4
  signature, in either forward mode.
- **Signature verification weaknesses**: canonicalization mismatches between
  what is verified and what is forwarded, presigned-URL replay past its
  expiry, session tokens accepted for the wrong access key ID, or any
  non-constant-time comparison of signatures or tokens.
- **Token validation weaknesses**: algorithm confusion, missing or bypassed
  `aud`/`iss`/`exp` checks, JWKS poisoning or key-rotation races.
- **Identity injection flaws**: anything that lets a caller influence the
  username written into the synthetic `Authorization` header,
  including username-sanitation escapes (`/` and `$` are rejected by design).
- **Credential-store issues**: plaintext or relocatable records in valkey,
  store-key handling, or revocation that fails to propagate.
- **Secret leakage** through logs, error responses or metrics.

Out of scope, because they are documented properties rather than defects:

- Per-chunk streaming signatures are not verified; the seed signature is.
- `resign` mode signs with a public constant and provides parser robustness,
  **not** upstream authentication.
- The admin listener (`:9090`) is unauthenticated by design and must be kept
  internal; the compose stack binds it to localhost and the Helm chart puts it
  behind a NetworkPolicy.
- Reaching the Ozone S3 Gateway directly, bypassing the proxy: preventing that
  is the deployment's job ([docs/production.md](docs/production.md)).
- The compose stack and its Keycloak realm, the stub issuer, the self-signed
  edge certificate and the Jupyter notebook are a **lab**: they ship insecure
  defaults on purpose (password grants, an unauthenticated token mint, no TLS
  verification) and are not meant to be deployed.

## Project status

Pre-1.0 and under active development. The security review to date has been a
self-review, recorded in [docs/verification.md](docs/verification.md), and the
project has no production track record;
[docs/production.md](docs/production.md) lists what a real deployment still
needs. Independent review is very welcome, and findings against the guarantees
above are the most useful kind.
