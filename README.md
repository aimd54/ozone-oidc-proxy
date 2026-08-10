# ozone-oidc-proxy

[![CI](https://github.com/aimd54/ozone-oidc-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/aimd54/ozone-oidc-proxy/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aimd54/ozone-oidc-proxy/badge)](https://scorecard.dev/viewer/?uri=github.com/aimd54/ozone-oidc-proxy)
[![Go](https://img.shields.io/github/go-mod/go-version/aimd54/ozone-oidc-proxy)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**OIDC single sign-on for the [Apache Ozone](https://ozone.apache.org/) S3
Gateway.**

Sign in with the identity provider you already run, and get short-lived S3
credentials that standard clients refresh on their own. No Kerberos, no
static access keys, no patches to Ozone.

Ozone's S3 Gateway authenticates one of two ways: Kerberos-backed SigV4 in
secure mode, or nothing at all in unsecured mode. Neither gives you single
sign-on.

This proxy puts standards-based OIDC in front of a stock, unmodified Ozone,
and Ozone's own ACLs still decide who may do what.

```bash
export AWS_ROLE_ARN=arn:ozone:iam::dev:role/oidc
export AWS_WEB_IDENTITY_TOKEN_FILE=~/.ozone/token.jwt
export AWS_ENDPOINT_URL_STS=https://ozone.example.com
export AWS_ENDPOINT_URL_S3=https://ozone.example.com

aws s3 ls
```

That is the whole client-side integration: four environment variables, no
plugin, no custom credential provider. Web identity is an ordinary part of
the SigV4 credential chain, so the exchange and the refresh happen behind
the scenes, and anything that already speaks the S3 API can use it.

> **Scope.** This is an Apache Ozone-specific tool rather than a generic S3
> gateway. It relies on how Ozone attributes requests in unsecured mode,
> which is not how other S3 implementations behave
> ([why](#why-ozone-only)).

## Works with

| Client | How it authenticates | Verified |
| --- | --- | --- |
| aws CLI v2 (≥ 2.13) | `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`, or a profile | auto-exchange + auto-refresh |
| boto3 / botocore | the same env vars, zero code | 8 MiB round-trip, no static keys |
| Java SDK v2, s3a, Spark, Iceberg | `WebIdentityTokenFileCredentialsProvider` | 8 MiB put, md5-identical get |
| minio-go | `credentials.NewSTSWebIdentity(...)` | same STS API |
| mc | session token in `MC_HOST_<alias>` | streaming upload, byte-identical |

Every row is exercised against a running cluster rather than asserted. The
streamed `aws-chunked` upload from mc is read back byte-identical by s3a,
and the evidence, with dates and image digests, is in
[docs/verification.md](docs/verification.md).

Presigned URLs, multipart uploads and streaming all work. The fuller table,
with the credential-lifecycle caveats per client, is in
[docs/architecture.md](docs/architecture.md).

## What the proxy does

- **Turns an OIDC token into S3 credentials.** An AWS-compatible
  `AssumeRoleWithWebIdentity` endpoint mints temporary credentials. Any
  standards-compliant OIDC provider works, and several at once.
- **Verifies every signed request.** Signatures are recomputed from the wire
  and compared in constant time. Header auth and presigned URLs both work.
- **Accepts bearer tokens too**, for people and clients that would rather
  not sign.
- **Keeps your Ozone ACLs in charge.** The authenticated username reaches
  the Ozone Manager in the header shape it parses, so it enforces the grants
  it already understands, bucket ownership included.
- **Lets nothing through unauthenticated.** Anything that is not a valid
  bearer token or a verified temporary-credential SigV4 request is refused
  with S3-shaped 403 XML.

```txt
                       ┌────────────────────────────────────┐
  (1) JWT ────────────▶│  ozone-oidc-proxy                  │
                       │                                    │
                       │  STS: AssumeRoleWithWebIdentity    │
  (2) temp creds ◀─────│                            JWKS ───┼──▶  any OIDC provider
                       │                                    │
  (3a) SigV4 S3 ──────▶│  verify signature ──┐              │
                       │                     ├──▶ attribute ┼──▶  Ozone S3G :9878
  (3b) Bearer S3 ─────▶│  verify JWT ────────┘              │     stock and unmodified,
                       │                                    │     reachable only here
                       └────────────────────────────────────┘
```

## Try it

```bash
git clone https://github.com/aimd54/ozone-oidc-proxy
cd ozone-oidc-proxy
make demo
```

That starts a self-contained stack (Keycloak, a single-node Ozone, and the
proxy), signs in as a test user, exchanges the token for credentials, does a
real S3 round-trip, and confirms Ozone recorded the OIDC user as the
bucket's owner. Nothing touches an existing cluster.

Needs Docker, GNU make and Go. First run pulls several gigabytes.
[examples/compose/README.md](examples/compose/README.md) covers the stack
and its six overlays: high availability, monitoring, a TLS edge, the
credential portal, a load test, and an Iceberg lakehouse.

On Kubernetes, [examples/kubernetes/](examples/kubernetes/README.md) does the
same thing with two Helm releases on a kind cluster: Apache Ozone from its
official chart, Keycloak, and this proxy, with the NetworkPolicy that keeps
the S3 Gateway reachable by nothing else.

## Against your own Ozone

Two prerequisites decide whether this fits your cluster:

- **`ozone.security.enabled=false`**, with the native authorizer and ACLs
  on. This is a decision about your whole cluster, not about the proxy.
- **The S3 Gateway must be unreachable by anything but the proxy.** In
  unsecured mode, whoever reaches the gateway directly can act as any user.
  The Helm chart ships NetworkPolicies for exactly this.

[docs/install.md](docs/install.md) covers both in full, along with what your
identity provider has to emit and a working `helm install`.

## Why Ozone only?

The proxy authenticates the client itself, then hands Ozone a request whose
`Credential=<username>/...` field carries the OIDC identity. In unsecured
mode Ozone *attributes* that request to the username and enforces its native
ACLs without verifying the signature, and that property is what makes
per-user authorization possible without touching Ozone at all.

No other S3 implementation behaves that way. Backends that verify signatures
reject the injected header, and backends that already ship OIDC and STS do
not need this. Ozone is the case where the gap is both real and closable, so
the design targets it specifically:
[ADR-0002](docs/adr/0002-identity-through-the-synthetic-header.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [Install](docs/install.md) | Cluster prerequisites, the identity provider checklist, and Helm |
| [Clients](docs/clients.md) | aws, boto3, mc, s3a, bearer tokens, presigned URLs |
| [Configuration](docs/configuration.md) | Every key, with its default |
| [Operations](docs/operations.md) | Revocation, metrics, running replicas |
| [Architecture](docs/architecture.md) | How the pieces fit, and what is trusted where |

[docs/README.md](docs/README.md) is the full index, adding the production
checklist, the verification record, upstream tracking, the roadmap and the
decision records. Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
Security reporting and scope: [SECURITY.md](SECURITY.md).

## Status

Pre-1.0 and under active development. Everything claimed here is verified
live against a stock Ozone release
([docs/verification.md](docs/verification.md)). The security review to date
has been a self-review and the project has no production track record, so
read [docs/production.md](docs/production.md) before running it anywhere
real.

## Trademarks

Apache, Apache Ozone and Ozone are trademarks of the Apache Software
Foundation. This project is independent, and is not affiliated with or
endorsed by the Apache Software Foundation.

## License

[Apache-2.0](LICENSE)
