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

aws s3 ls                        # exchange and refresh happen behind the scenes
```

That is the whole client-side integration: four environment variables, no
plugin, no custom credential provider.

Web identity is an ordinary part of the SigV4 credential chain, so anything
that already speaks the S3 API can use it. The aws CLI and boto3 read those
variables directly; other clients take the minted credentials the same way
they would take any temporary key pair.

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
[docs/VERIFICATION.md](docs/VERIFICATION.md).

Presigned URLs, multipart uploads and streaming all work. The fuller table,
with the credential-lifecycle caveats per client, is in
[docs/architecture.md](docs/architecture.md).

## What the proxy does

- **STS token exchange.** An AWS-compatible `AssumeRoleWithWebIdentity`
  endpoint turns an OIDC token into temporary AWS-style credentials. Any
  standards-compliant OIDC provider works, and several at once.
- **Signed requests, verified.** Requests signed with those temporary
  credentials have their signature recomputed from the wire and compared in
  constant time. Header auth and presigned URLs both work, so
  `aws s3 presign` links are shareable.
- **Bearer tokens, for browsers and scripts.** `Authorization: Bearer
  <token>` works directly, for people and clients that would rather not sign.
- **Your Ozone ACLs still apply.** The proxy injects the authenticated
  username into the header shape Ozone parses, so the Ozone Manager
  attributes every request to that user and enforces the grants it already
  understands, bucket ownership included.
- **Nothing gets through unauthenticated.** Anything that is not a valid
  bearer token or a verified temporary-credential SigV4 request is refused
  with S3-shaped 403 XML.

> **Scope.** This is an Apache Ozone-specific tool rather than a generic S3
> gateway. It relies on how Ozone attributes requests in unsecured mode, which
> is not how other S3 implementations behave ([why](#why-ozone-only)).

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

Attribution is the part that makes this work without touching Ozone. The
proxy rewrites the request's `Authorization` header so its `Credential`
field carries the authenticated username, and the Ozone Manager applies
that user's own ACLs.

## Quickstart (compose lab)

A self-contained stack: Keycloak, a single-node Ozone, and the proxy. Nothing
here touches an existing cluster, so it is safe to run first and read
[Run it against your own Ozone](#run-it-against-your-own-ozone) after.

Requirements: Docker (compose v2), `curl`, `jq`, GNU make, and about 6 GB of
RAM for the stack.

The proxy is built inside its image and the aws CLI runs containerized, so
neither Go nor the aws CLI is needed on the host. Go is only needed for
`make build`, which produces the `ozone-login` and portal binaries.

A first run pulls several GB of images, so expect a few minutes before
anything answers.

Browser sign-in needs one more step, because the lab pins the issuer hostname
and tokens must carry it exactly:

```bash
echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
make check-hosts    # confirms it, and says what to do if not
```

Only the credential portal, the device-flow sign-in page and `ozone-login`
need this. The acceptance suite and `make demo` do not.

```bash
make demo    # up + init + a real S3 round-trip through the proxy
```

That is the shortest path to a working S3 call. The steps it chains, if you
would rather run them yourself:

```bash
make up      # build the proxy image, start Keycloak + Ozone + proxy
make init    # provision Keycloak (realm ozone, client ozone-s3, alice/bob)
             # and grant alice/bob rwlc on the /s3v volume
make e2e     # the full acceptance suite
```

> **Status.** Pre-1.0 and under active development. Everything claimed here is
> verified live against a stock Ozone release
> ([docs/VERIFICATION.md](docs/VERIFICATION.md)). The security review to date
> has been a self-review and the project has no production track record, so
> read [docs/PRODUCTION.md](docs/PRODUCTION.md) before running it anywhere
> real.

Endpoints after `make up`:

| URL                     | What                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| `http://localhost:9000` | S3 **and** STS (the only public data endpoint)                                                  |
| `http://127.0.0.1:9090` | admin: `/healthz`, `/readyz`, `/metrics`, and `DELETE /credentials/{akid}`, **localhost only** |
| `http://localhost:8080` | Keycloak (admin/admin123)                                                                       |

The Ozone S3 Gateway is intentionally **not** published: with
`ozone.security.enabled=false` anyone who can reach it can impersonate anyone,
so the proxy must be the only path (network policy in production).

The admin port is **security-sensitive** and unauthenticated: besides metrics
it serves the state-changing revocation endpoint, so it is bound to `127.0.0.1`
in the lab stack and must never be exposed on a shared network. In Kubernetes the
Helm chart keeps it ClusterIP behind a NetworkPolicy scoped to the scrape
source (see below).

## Run it against your own Ozone

The compose stack above brings its own Ozone and its own identity provider.
This section is for pointing the proxy at yours.

### What your Ozone cluster must look like

```txt
ozone.security.enabled     = false
ozone.acl.enabled          = true
ozone.acl.authorizer.class = org.apache.hadoop.ozone.security.acl.OzoneNativeAuthorizer
```

Run a recent Ozone release on JDK 17 or newer.

`ozone.security.enabled=false` is the load-bearing setting, and it is a
decision about your whole cluster rather than about this proxy.

Ozone in unsecured mode has no internal authentication: **anyone who can
reach the S3 Gateway, the Ozone Manager, the SCM or a DataNode can act as
any user.** Deploying this means making the network the security boundary,
with the proxy as the only door.

The Helm chart ships NetworkPolicies for exactly that, and
[docs/PRODUCTION.md](docs/PRODUCTION.md) is the checklist.

Each user needs grants on the S3 volume. `rl` is the floor for any access;
`rwlc` additionally lets them create their own buckets through the S3 API,
because the Ozone Manager checks WRITE on the volume for `CreateBucket`:

```bash
ozone sh volume addacl -a user:alice:rwlc /s3v
```

### What your identity provider must do

Any standards-compliant OIDC provider works (Keycloak, Okta, Entra ID,
Auth0, Google, Dex, and others). The proxy uses OIDC discovery and plain
JWKS; there is no provider-specific code in it. What it needs from yours:

- **A client your users authenticate against.** Its type depends on the flow
  you offer them (see the two conditional requirements below).
- **An `aud` claim matching your configured `audiences`.** This is mandatory
  and enforced: an issuer with empty `audiences` is rejected at startup, and
  a token whose `aud` does not intersect is rejected at the door. Many
  providers do not put a useful audience in access tokens by default, so
  this is the setting most likely to need changing.
- **A stable username claim.** Configured per issuer as `username_claim`,
  falling back to `sub`. Its value becomes the Ozone identity, so it must be
  stable and must satisfy `username_policy.pattern` (which excludes `/` and
  `$` by design).
- **RS256 or ES256 signing.** `none` and the `HS*` family are rejected at
  both config and token level.
- **An access-token lifespan long enough to be useful.** The temporary
  credential's TTL is capped by the JWT's own `exp`, so a 5-minute default
  caps every credential at 5 minutes. Raise it on the client you dedicate to
  this audience rather than realm-wide, or use `ozone-login`, which refreshes.
- **The OAuth 2.0 device authorization grant**, on a public client, *if* you
  want people to use `ozone-login`.
- **A confidential client with a registered redirect URI**, *if* you want the
  browser credential portal.

Several providers can run side by side, each with its own audiences and
username claim. The acceptance suite exercises two issuers of different
shapes, not just Keycloak, and checks that identities from one cannot reach
the other's buckets.

#### Worked example: Keycloak

Keycloak is the provider the lab stack provisions, and the one these
requirements have been exercised against.

Its default access tokens carry `aud=account`, which the proxy rejects. Add an
**audience mapper** to the client for this audience so tokens carry
`aud=ozone-s3`. Token lifetime is `Access Token Lifespan` on that client
rather than realm-wide.

The compose init service does all of it non-interactively
(`deploy/compose/init/init.py`): the audience mapper, the device grant on the
public client, and the confidential client the credential portal needs. It is
readable as a worked configuration even if you run a different provider.

### Minimal configuration

One YAML file (`-config` flag or `OZPX_CONFIG`):

```yaml
upstream:
  s3_endpoint: http://ozone-s3g:9878   # your S3 Gateway, reachable only by the proxy
issuers:
  - name: corp-idp
    issuer: https://idp.example.com    # must equal the token's `iss`, byte for byte
    audiences: [ozone-s3]              # must match an `aud` your provider emits
    username_claim: preferred_username
```

Everything else has a working default; the full reference is under
[Configuration](#configuration).

### On Kubernetes

```bash
cp deploy/helm/ozone-oidc-proxy/values-example.yaml my-values.yaml
$EDITOR my-values.yaml      # issuer, s3_endpoint, s3gPodSelector, store key
helm install ozpx deploy/helm/ozone-oidc-proxy -f my-values.yaml
```

Use a values file rather than `--set`: `config.issuers` is a list of maps and
`--set` cannot express it. The chart ships **no default issuer** on purpose,
so a release installed without one fails closed at startup ("at least one
issuer must be configured") instead of starting green and rejecting every
token.

Set `networkPolicy.s3gPodSelector` to your S3 Gateway's pod labels. Until you
do, the lockdown policy is not rendered at all and the gateway stays reachable
from the rest of the namespace, which in unsecured mode means impersonation of
anyone. Verify your CNI actually enforces NetworkPolicy; not all do.

## Using it

The examples below use the compose lab's endpoints and users. Against your own
deployment, substitute your proxy address and your own accounts.

### Humans: `ozone-login` (device flow + auto-refresh)

```bash
make build
bin/ozone-login -issuer http://keycloak:8080/realms/ozone
# → open the printed URL, sign in (alice / password123), leave it running
```

It writes `~/.ozone/token.jwt` (atomic, 0600), refreshes it at two thirds
of the token lifetime, and prints the exports every AWS SDK/CLI needs to
auto-exchange against the proxy (architecture.md):

```bash
export AWS_ROLE_ARN=arn:ozone:iam::dev:role/oidc
export AWS_WEB_IDENTITY_TOKEN_FILE=~/.ozone/token.jwt
export AWS_ENDPOINT_URL_STS=http://localhost:9000
export AWS_ENDPOINT_URL_S3=http://localhost:9000
aws s3 ls        # exchange + refresh happen behind the scenes
```

### Humans: credential portal (browser)

```bash
make portal-up   # oauth2-proxy + portal → http://localhost:4180
```

Sign in as alice and copy the rendered credentials (shell exports or an
`~/.aws/credentials` profile). Reload to mint a fresh set.

### Scripts / CI: direct token exchange

```bash
TOKEN=$(curl -s http://localhost:8080/realms/ozone/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ozone-s3 \
  -d username=alice -d password=password123 | jq -r .access_token)  # password grant: lab only

aws sts assume-role-with-web-identity \
  --endpoint-url http://localhost:9000 \
  --role-arn arn:ozone:iam::dev:role/oidc \
  --role-session-name alice-dev \
  --web-identity-token "$TOKEN"
# export the returned AccessKeyId / SecretAccessKey / SessionToken, then:
aws s3 mb s3://demo --endpoint-url http://localhost:9000
aws s3 cp report.csv s3://demo/ --endpoint-url http://localhost:9000
```

Note on token lifetime: the temporary credentials' TTL is capped by the
JWT's own `exp`, so your provider's access-token lifespan sets the ceiling
(the lab client uses 1 h); `ozone-login` papers over it by refreshing.

### Bearer (curl, browsers, custom clients)

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/demo/report.csv
curl -X PUT -H "Authorization: Bearer $TOKEN" --data-binary @report.csv \
     http://localhost:9000/demo/report.csv
```

### Presigned URLs (shareable links)

```bash
aws s3 presign s3://demo/report.csv --expires-in 3600 \
    --endpoint-url http://localhost:9000
# → http://localhost:9000/demo/report.csv?X-Amz-Algorithm=...&X-Amz-Signature=...
curl "$URL"        # no credentials needed until the URL expires
```

The link is bound to the temporary credentials that minted it: it stops
working when they expire, whichever comes first (`X-Amz-Expires` or the
credential TTL).

### boto3, mc, s3a

Anything that understands AWS temporary credentials works. All three below run
against the live stack in e2e: boto3 mints its own credentials from env vars
alone, mc's 8 MiB `aws-chunked` streaming upload is verified on the wire, and
s3a reads that same object back byte-identical.

boto3 picks up the same env vars as the aws CLI, including the web-identity
auto-exchange. For mc and s3a, pass the minted credentials explicitly:

```bash
# minio mc: the session token goes inside the alias URL
export MC_HOST_ozone="http://$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY:$AWS_SESSION_TOKEN@localhost:9000"
mc ls ozone/demo

# Hadoop s3a (3.4+ / AWS SDK v2)
hadoop fs \
  -D fs.s3a.endpoint=http://localhost:9000 -D fs.s3a.endpoint.region=us-east-1 \
  -D fs.s3a.path.style.access=true \
  -D fs.s3a.aws.credentials.provider=org.apache.hadoop.fs.s3a.TemporaryAWSCredentialsProvider \
  -D fs.s3a.access.key=$AWS_ACCESS_KEY_ID -D fs.s3a.secret.key=$AWS_SECRET_ACCESS_KEY \
  -D fs.s3a.session.token=$AWS_SESSION_TOKEN \
  -ls s3a://demo/
```

Streaming uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, aws-chunked) pass
through the proxy verified; mc and the AWS SDK v2 use them by default on
plain HTTP.

### Granting access (Ozone native ACLs)

Buckets created through the proxy belong to the OIDC user. Cross-user grants
use plain Ozone ACLs (architecture.md):

```bash
docker compose -f deploy/compose/docker-compose.yml exec ozone-om \
  ozone sh bucket addacl -a user:bob:rl /s3v/demo            # bob may list/read
  # 'user:bob:rwl[DEFAULT]' additionally inherits to new keys
```

## Configuration

One YAML file (`-config` flag or `OZPX_CONFIG`); every key shown is the
default except the issuer list:

```yaml
listen: 0.0.0.0:9000
admin_listen: 0.0.0.0:9090
upstream:
  s3_endpoint: http://ozone-s3g:9878   # required
  forward_mode: rewrite                # rewrite | resign (see below)
data_path:
  accept_bearer: true
  strict: true                         # keep true outside labs
issuers:                               # one or more
  - name: corp-idp
    issuer: https://idp.example.com    # must equal the token's iss
    # jwks_uri: https://...            # optional; else OIDC discovery
    audiences: [ozone-s3]              # required, non-empty (aud is enforced)
    username_claim: preferred_username # falls back to sub
sts:
  max_duration: 3600                   # cap on temp-credential TTL (s)
  role_arn_allowlist: []               # empty = any RoleArn accepted
credential_store:
  type: memory                         # memory | valkey
  # valkey:                            # required when type: valkey
  #   addr: valkey:6379
  #   key_env: OZPX_STORE_KEY          # env holding the base64 AES-256 key
security:
  sigv4_clock_skew: 15m
  allowed_signing_algs: [RS256, ES256]
  region: us-east-1
username_policy:
  pattern: "^[A-Za-z0-9._@-]{1,64}$"   # rejects '/' and '$' by design
```

The `audiences` list is the setting most likely to need work on the provider
side: many providers do not put a useful audience in access tokens by default.
See [What your identity provider must
do](#what-your-identity-provider-must-do).

**Forward mode** (`upstream.forward_mode`, architecture.md) picks how the
request reaches Ozone.

`rewrite`, the default, swaps the access key ID in the incoming
`Authorization` header for the OIDC username and leaves the rest. That is
the leanest path, and all a stock Ozone needs.

`resign` computes a fresh, fully valid SigV4 header toward Ozone, signed
over the upstream host. It costs one extra signature and is robust to a
future upstream that parses signatures strictly.

Note that `resign` signs with a public constant, so it buys parser
robustness, **not** upstream authentication. A secure-mode Ozone would need
a real shared secret.

**Credential store** (`credential_store.type`): `memory` (single replica; TTL
sweeper) or `valkey` (shared across replicas, and required for more than one). For
`valkey`, values are AES-256-GCM encrypted with a 32-byte key the proxy reads
from the env var named by `key_env` (base64; **never** in the YAML or logs):

```bash
export OZPX_STORE_KEY=$(head -c 32 /dev/urandom | base64)
```

## Deployment (HA, revocation, monitoring, Helm)

### High availability (compose)

```bash
make ha-up     # shared valkey store + a second replica (:9001/:9091, resign mode)
make e2e       # the suite adds the HA/valkey/resign/revocation matrix (78/78)
```

Replica A serves `:9000/:9090` in `rewrite` mode, replica B `:9001/:9091` in
`resign` mode; both share the valkey store, so a credential minted on either is
honored on the other and a revocation on one propagates to the other.

### Revoking a credential

The admin listener exposes a revocation endpoint (network-internal, on the same
trust zone as `/metrics`):

```bash
curl -X DELETE http://localhost:9090/credentials/OZPX...   # 204 revoked, 404 unknown
```

The credential is deleted from the store immediately; with valkey the deletion
invalidates every replica's local cache, so the credential stops working fleet-wide.

### Monitoring (compose)

```bash
make monitor-up   # Prometheus + Grafana → http://localhost:3000 (anonymous viewer)
```

Grafana auto-loads the **Ozone OIDC Proxy** dashboard
(`deploy/dashboards/ozone-oidc-proxy.json`): traffic and verification-latency
percentiles (p99 against a 1 ms line), lane split, verification outcomes,
upstream status families, active credentials, and revocations. Drive traffic
with `make e2e` or `make loadtest` to populate it.

### TLS edge (compose)

```bash
make edge-up   # HAProxy terminating TLS → https://localhost:8443 (self-signed)
```

Models the production ingress: HAProxy terminates TLS and forwards to the
proxy with the SigV4-signed Host header untouched; its healthcheck is the
anonymous-probe boundary check (expects the strict 403). With the overlay
up, `make e2e` adds a TLS section (aws ls, presigned over https).

### Lakehouse: Nessie + Iceberg (compose)

```bash
make lakehouse-up      # Nessie (Iceberg REST) + Postgres + Jupyter
make lakehouse-smoke   # health checks
```

A worked example of a service account rather than a person: Nessie reaches
Ozone S3 through the proxy with **no static S3 secret**, exchanging a
client-credentials token for temporary credentials like any other client.

Jupyter (<http://localhost:8890>) ships a runnable notebook covering every
auth flow and ending with an Iceberg table written over these credentials.

### Kubernetes (Helm)

`deploy/helm/ozone-oidc-proxy/` is a deployable chart: Deployment, Service,
ConfigMap, an optional store-key Secret and in-chart valkey, and the
NetworkPolicies that make the network the trust boundary (the S3 Gateway
accepts traffic **only** from proxy pods, rendered when you set
`networkPolicy.s3gPodSelector`).

Install it with a values file, as [Run it against your own
Ozone](#on-kubernetes) describes: `config.issuers` is a list of maps, so
`--set` cannot express it, and the chart ships no default issuer.

```bash
cp deploy/helm/ozone-oidc-proxy/values-example.yaml my-values.yaml
$EDITOR my-values.yaml
helm install ozpx deploy/helm/ozone-oidc-proxy -f my-values.yaml

./deploy/helm/smoke.sh    # lint + install on a throwaway kind cluster, then assert (8/8)
```

`values-example.yaml` covers the multi-replica shape: two replicas on a
shared valkey store, the store key from an existing Secret, the S3 Gateway
lockdown selector, and egress limited to your provider.

## Development

```bash
make build   # bin/: ozone-oidc-proxy, ozone-login, credential-portal
make test    # unit tests (SigV4 is pinned to the AWS test-suite vector and
             # round-tripped against the real aws-sdk-go-v2 signer)
make vet
```

Contributing (DCO sign-off, `make check`, testing policy):
[CONTRIBUTING.md](CONTRIBUTING.md). Security reporting and scope:
[SECURITY.md](SECURITY.md).

Further reading:

| Document | What it covers |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | How the pieces fit, and what is trusted where |
| [docs/adr/](docs/adr/README.md) | The decisions and their reasoning |
| [docs/roadmap.md](docs/roadmap.md) | What is shipped, and what is not built |
| [docs/PRODUCTION.md](docs/PRODUCTION.md) | Production checklist, and the Ranger note |
| [docs/VERIFICATION.md](docs/VERIFICATION.md) | What was checked against a running cluster |
| [docs/UPSTREAM.md](docs/UPSTREAM.md) | Upstream OIDC and STS work, and what would end this project |

## Why Ozone only?

The proxy authenticates the client itself, then hands Ozone a request whose
`Credential=<username>/...` field carries the OIDC identity. In unsecured mode
Ozone *attributes* that request to the username and enforces its native ACLs
without verifying the signature, and that property is what makes
per-user authorization possible without touching Ozone at all.

Other S3 implementations do not behave that way:

- Backends that verify signatures (MinIO, Ceph RGW, AWS itself) reject the
  injected header. The proxy could re-sign with a single real backend
  credential, but then every user would collapse into one backend identity:
  authentication would survive, per-user authorization would not.
- Backends that already ship OIDC/STS (MinIO, Ceph RGW, AWS) do not need this
  in the first place.

Ozone is the case where the gap is both real and closable, so the design
targets it specifically.

## Trademarks

Apache, Apache Ozone and Ozone are trademarks of the Apache Software
Foundation. This project is independent, and is not affiliated with or
endorsed by the Apache Software Foundation.

## License

[Apache-2.0](LICENSE)
