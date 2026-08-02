# ozone-oidc-proxy

[![CI](https://github.com/aimd54/ozone-oidc-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/aimd54/ozone-oidc-proxy/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aimd54/ozone-oidc-proxy/badge)](https://scorecard.dev/viewer/?uri=github.com/aimd54/ozone-oidc-proxy)
[![Go](https://img.shields.io/github/go-mod/go-version/aimd54/ozone-oidc-proxy)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

OIDC authentication for the [Apache Ozone](https://ozone.apache.org/) S3
Gateway, as an external Go reverse proxy. Ozone's S3 API authenticates one of
two ways: Kerberos-backed SigV4 in secure mode, or nothing at all in unsecured
mode. This proxy adds standards-based OIDC in front of a stock, unmodified
Ozone.

- **STS token exchange.** An AWS-compatible `AssumeRoleWithWebIdentity`
  endpoint turns an OIDC token into temporary AWS-style credentials. Standard
  tooling consumes it natively, auto-refresh included: aws cli, boto3, the Java
  SDK and s3a, minio-go, mc. Any OIDC issuer works, and several at once.
- **SigV4 data path.** Requests signed with those temporary credentials are
  verified by the proxy, recomputing the signature from the wire and comparing
  in constant time, then forwarded to Ozone. Header auth and presigned URLs
  both work, so `aws s3 presign` links are shareable.
- **Bearer data path.** `Authorization: Bearer <token>` works directly, for
  people, browsers, and clients that would rather not sign.
- **Native ACLs.** The proxy injects the authenticated username into the header
  shape Ozone parses, so the Ozone Manager attributes every request to that
  user and enforces the grants it already understands, bucket ownership
  included.
- **Strict by default.** Anything that is not a valid bearer token or a
  verified temporary-credential SigV4 request is refused with S3-shaped 403
  XML.

> **Scope.** This is an Apache Ozone-specific tool rather than a generic S3
> gateway. It relies on how Ozone attributes requests in unsecured mode, which
> is not how other S3 implementations behave ([why](#why-ozone-only)). Not
> affiliated with or endorsed by the Apache Software Foundation.
>
> **Status.** Pre-1.0 and under active development. Everything claimed here is
> verified live against a stock Ozone release
> ([docs/VERIFICATION.md](docs/VERIFICATION.md)). The security review to date
> has been a self-review and the project has no production track record, so
> read [docs/PRODUCTION.md](docs/PRODUCTION.md) before running it anywhere
> real.

The rationale, threat model, and trust boundaries are in
[docs/architecture.md](docs/architecture.md); what is shipped and what is
planned is in [docs/roadmap.md](docs/roadmap.md).

Working today: the STS exchange; SigV4 over header, presigned, and streaming
uploads; the bearer lane; strict mode; multipart; multiple issuers; human
credential flows through `ozone-login` device login and the credential portal;
a valkey-backed credential store with replicas; the `resign` forward mode; an
administrative revocation endpoint; a Helm chart with network policies; and a
Prometheus and Grafana overlay. Clients are smoke-tested with boto3, mc, and
s3a. All of it is exercised against a running cluster rather than asserted;
see [docs/VERIFICATION.md](docs/VERIFICATION.md).

```txt
                      ┌────────────────────────────────────────┐
 (1) JWT ────────────▶│  ozone-oidc-proxy          JWKS  ──────┼──▶ Keycloak / any OIDC IdP
 (2) temp creds ◀─────│  STS: AssumeRoleWithWebIdentity        │
                      │                                        │
 (3a) SigV4 S3 ──────▶│  verify sig ─┐                         │
 (3b) Bearer S3 ─────▶│  verify JWT ─┴─▶ synthetic header ─────┼──▶ Ozone S3G :9878
                      │              Credential=<username>/...   │    (stock Ozone, internal-only,
                      └────────────────────────────────────────┘     ACLs on, security off)
```

## Quickstart (compose lab)

Requirements: Docker (compose v2), `curl`, `jq`, GNU make. ~6 GB RAM for the
stack. The aws CLI is run containerized by the test suite.

```bash
make up      # build the proxy image, start Keycloak + Ozone + proxy
make init    # provision Keycloak (realm ozone, client ozone-s3, alice/bob)
             # and grant alice/bob rwlc on the /s3v volume
make e2e     # run the acceptance suite
```

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

## Using it

Browser flows (portal, device-flow sign-in page) redirect to the pinned
issuer host: add `127.0.0.1 keycloak` to `/etc/hosts` on the machine
running the browser.

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
JWT's own `exp`, so the Keycloak client's access-token lifespan matters
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

### Other clients (boto3, mc, s3a)

Anything that understands AWS temporary credentials works (all three below
are smoke-tested in e2e). boto3 picks up the same env vars as the aws CLI, so
including the web-identity auto-exchange. For mc and s3a, pass the minted
credentials explicitly:

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
  - name: keycloak
    issuer: http://keycloak:8080/realms/ozone   # must equal the token's iss
    # jwks_uri: http://...                        # optional; else OIDC discovery
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

Keycloak note: default tokens carry `aud=account`, which the proxy rejects, so
the realm client needs an audience mapper (the compose init service creates
one; architecture.md).

**Forward mode** (`upstream.forward_mode`, architecture.md): `rewrite` (default)
swaps the AKID in the incoming `Authorization` header for the OIDC username and
leaves the rest. That is the leanest path, and all a stock Ozone needs. `resign`
computes a *fresh, fully valid* SigV4 header toward Ozone (signed over the
upstream host, `Credential=<username>/...`); it costs one extra signature but is
robust to a future upstream that parses signatures strictly. It signs with a
public constant today, so it adds parser-robustness, **not** upstream
authentication; a secure-mode Ozone would need a real shared secret.

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

Nessie authenticates to Ozone S3 through the proxy with **no static S3
secret**: a sidecar keeps a Keycloak client-credentials JWT fresh and the
AWS SDK's default chain auto-exchanges it at the proxy STS
(`service-account-nessie`). Jupyter (<http://localhost:8890>) ships
`ozone-oidc-tour.ipynb`, a runnable tour of every auth flow, ending with a
PyIceberg table on `s3://lakehouse/` and its Nessie commit history.

### Kubernetes (Helm)

`deploy/helm/ozone-oidc-proxy/` is a deployable chart: Deployment, Service,
ConfigMap, an optional store-key Secret and in-chart valkey, and the
NetworkPolicies that make the network the trust boundary (the S3 Gateway
accepts traffic **only** from proxy pods, rendered when you set
`networkPolicy.s3gPodSelector`).

```bash
helm install ozpx deploy/helm/ozone-oidc-proxy \
  --set replicaCount=2 --set valkey.enabled=true \
  --set config.credential_store.type=valkey \
  --set config.credential_store.valkey.addr=ozpx-ozone-oidc-proxy-valkey:6379 \
  --set storeKey.create=true --set storeKey.value=$(head -c 32 /dev/urandom | base64 -w0) \
  --set networkPolicy.s3gPodSelector.app=ozone-s3g

./deploy/helm/smoke.sh    # lint + install on a throwaway kind cluster, then assert (8/8)
```

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

Further reading: [docs/architecture.md](docs/architecture.md) for how the
pieces fit and what is trusted where, [docs/adr/](docs/adr/README.md) for the
decisions and their reasoning, [docs/roadmap.md](docs/roadmap.md) for what is
shipped and what is planned, [docs/PRODUCTION.md](docs/PRODUCTION.md) for the
production checklist and the Ranger note, and
[docs/UPSTREAM.md](docs/UPSTREAM.md) for the upstream OIDC and STS work this
tracks.

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

## License

[Apache-2.0](LICENSE)
