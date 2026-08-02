# Architecture

How OIDC authentication is added in front of an unmodified Apache Ozone S3
Gateway: what the proxy does on each request, what it assumes about Ozone, and
where the trust boundaries sit.

Decisions and their reasoning are recorded separately as
[ADRs](adr/README.md). What is shipped and what is planned is in
[the roadmap](roadmap.md), and what has actually been exercised against a
running cluster is in [VERIFICATION.md](VERIFICATION.md).

## Problem statement

Apache Ozone's S3 Gateway supports only two authentication modes:

1. **Secure mode**: Kerberos-backed. S3 credentials issued via `ozone s3
   getsecret` and validated by the Ozone Manager (OM).
2. **Unsecured mode**: no validation. Any access key / secret key pair is
   accepted.

There is no OIDC support. Ozone's STS work (HDDS-13323) lives on a feature
branch; the `AssumeRoleWithWebIdentity` action is not implemented in any
release. Authorization plumbing for STS is, however, already being backported
into the 2.1.x line (HDDS-13848 and HDDS-15064), signaling
active upstream movement ([upstream STS status](#upstream-sts-status), [UPSTREAM.md](UPSTREAM.md)).

Organizations that already run an OIDC identity provider therefore cannot use
it for S3 access to Ozone: they must either deploy Kerberos everywhere, or
accept an unauthenticated gateway. This project closes that gap **without
modifying or rebuilding Ozone**.

## Goals

- Authenticate S3 clients via OIDC (JWT) from **multiple issuers**
  (configurable to N; per-issuer audiences, username claim and JWKS source).
- **SigV4 lane (primary):** standard AWS tooling unchanged, clients exchange a
  JWT for temporary AWS-style credentials (STS `AssumeRoleWithWebIdentity`
  semantics) and sign normal SigV4 requests, verified against the secrets we
  minted.
- **Bearer lane (secondary):** `Authorization: Bearer <jwt>` accepted directly
  on the data path for humans, browsers (via oauth2-proxy) and custom clients.
- Map the OIDC identity to an Ozone user so **native ACLs** enforce per-user
  access (bucket ownership, `ozone sh ... addacl`).
- **Strict authentication:** no anonymous fallback. Every request is either a
  valid Bearer or a verified temp-credential SigV4; anything else → 403.
- **Zero Ozone source modifications**: nothing Ozone-side beyond configuration
  and network policy.
- Forward-compatible: when Ozone ships native `AssumeRoleWithWebIdentity`,
  clients repoint one endpoint URL ([upstream STS status](#upstream-sts-status)).

## Non-goals

- Not an identity provider; no user/group provisioning in the IdP or in Ozone.
- No group-claim → Ozone-group synchronization ([groups](#groups)).
- No Ranger integration (native ACLs first; Ranger is an Ozone-side authorizer
  swap, see [PRODUCTION.md](PRODUCTION.md)).
- No request-body integrity beyond standard SigV4 semantics.
- No UI beyond the optional credential portal ([the oauth2-proxy satellite](#oauth2-proxy-an-official-satellite)).

## Background: why this design

### In Ozone, the access key ID *is* the identity

The S3 Gateway parses the SigV4 `Authorization` header and forwards the access
key ID to OM with each request; OM derives the request user from it and
evaluates ACLs against that user. With `ozone.security.enabled=false`, **only
signature validation is skipped, identity attribution and ACL evaluation still
happen.** That is the property this design builds on: if we can put a username
in the access-key-ID field of a request Ozone considers well-formed, Ozone
enforces that user's ACLs for us.

### SigV4 never transmits the secret

Clients send only an HMAC *derived from* the secret. A proxy cannot validate
credentials it does not already know, "secret = the user's OIDC password" is
impossible, since no IdP reveals passwords. Therefore the JWT must reach us
once, out-of-band of the data path, a **token exchange**, after which we
verify SigV4 against secrets **we** minted.

That is exactly AWS `AssumeRoleWithWebIdentity`, so we expose it with
AWS-compatible semantics and inherit native SDK support (auto-refresh
included) for free ([client compatibility](#client-compatibility-and-credential-lifecycle)).

## How the pieces fit

### Topology

```txt
                        ┌──────────────────────────────────────────┐
                        │             ozone-oidc-proxy              │
 (1) JWT ──────────────▶│ STS handler            JWKS validator ───┼──▶ Keycloak
 (2) temp creds ◀───────│ (AssumeRoleWith        (multi-issuer,    │──▶ any OIDC IdP
                        │  WebIdentity)           cached)          │
                        │        │                    ▲            │
                        │        ▼                    │            │
                        │  Credential store    Bearer validator    │
                        │  (memory | valkey)          ▲            │
                        │        ▲                    │            │
 (3a) SigV4 S3 ────────▶│  SigV4 verifier ──┐         │            │
 (3b) Bearer S3 ───────▶│───────────────────┴─▶ Synthetic-header ──┼──▶ Ozone S3G :9878
                        │                       injector           │    (stock Ozone,
                        └──────────────────────────────────────────┘     internal only)
        Browser ──▶ oauth2-proxy ──(Bearer)──▶ proxy (3b)   [satellite, [the oauth2-proxy satellite](#oauth2-proxy-an-official-satellite)]
```

The proxy is an independent process beside a **stock, unmodified** Ozone
deployment: it owns its release cycle, its blast radius is one process, and its
only coupling to Ozone is the public S3 API plus the header-parsing behavior of
unsecured mode ([how Ozone derives identity](#in-ozone-the-access-key-id-is-the-identity)). Because the gateway itself performs no authentication,
the network is the trust boundary, S3G must be reachable *only* from the proxy
([security considerations](#security-considerations)).

### oauth2-proxy: an official satellite

Scoped to what it does well:

1. **Browser lane:** session cookie ↔ IdP auth-code flow; forwards
   `Authorization: Bearer <jwt>` to the Bearer lane.
2. **Credential portal:** oauth2-proxy fronts a one-page app that takes the
   validated token, calls our STS, and renders temp credentials plus a ready
   `~/.aws/config` snippet; so humans never need a password grant.
3. **Admin surfaces:** protects Recon UI, S3G web-admin, our admin/metrics port.

It performs **no** data-path authentication decisions. A header-trust mode
(trusting `X-Auth-Request-User` from a satellite) is deliberately rejected:
anything that can reach the proxy could then assert any identity.

### Sequences

Token exchange:

```txt
Client            STS handler                Issuer
  │ POST Action=AssumeRoleWithWebIdentity      │
  │ WebIdentityToken=<JWT>, RoleArn, ...         │
  ├─────────────▶│ iss allowlist → JWKS verify │
  │              │──(cached JWKS)─────────────▶│
  │              │ aud, exp/nbf, alg allowlist │
  │              │ username_claim → sanitize   │
  │              │ mint {AKID, secret, token}  │
  │              │ TTL=min(jwt.exp−now, req, max)
  │ ◀── XML Credentials{AKID, Secret, SessionToken, Expiration}
```

Data path:

```txt
Client                 Proxy                             Ozone S3G
  │ 3a SigV4(temp creds)  │ AKID lookup → miss/expired → 403│
  │  + security token     │ session-token match             │
  ├──────────────────────▶│ recompute SigV4, const-time cmp │
  │ 3b Bearer <jwt>       │ validate JWT (issuer registry)  │
  ├──────────────────────▶│                                 │
  │        both:          │ inject synthetic header         │
  │                       │  Credential=<username>/...        ├──▶ parse header,
  │                       │                                 │    user=<username>,
  │  ◀── streamed response┤                                 │    OM native ACL check
```

## Detailed design

### Endpoint layout

Single listener (default `:9000`), MinIO-style dispatch:

- `POST /` with `Content-Type: application/x-www-form-urlencoded` and
  `Action=AssumeRoleWithWebIdentity` → STS handler.
- `Authorization: Bearer ...` → Bearer lane (if `data_path.accept_bearer`).
- SigV4 query parameters without an `Authorization` header → presigned lane.
- Everything else → SigV4 lane.
- `/healthz`, `/readyz`, `/metrics` and credential revocation on the admin
  listener `:9090`.

One URL for clients: `AWS_ENDPOINT_URL_S3 = AWS_ENDPOINT_URL_STS`.

### STS: AssumeRoleWithWebIdentity

| Param              | Handling                                                                                                                                                                                                                                                                |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WebIdentityToken` | Required. The JWT.                                                                                                                                                                                                                                                      |
| `RoleArn`          | Required by SDKs. Checked against `sts.role_arn_allowlist`; otherwise opaque. **Forward-compatible:** reserved to map onto Ozone session policies. The HDDS-15064 model (`OzoneGrant` carrying a set of allowed S3 actions) is the target shape when native STS lands. |
| `RoleSessionName`  | Logged; echoed in `AssumedRoleUser`.                                                                                                                                                                                                                                    |
| `DurationSeconds`  | Effective TTL = `min(jwt.exp − now, DurationSeconds, sts.max_duration)`.                                                                                                                                                                                                |

**JWT validation** (shared by the STS and Bearer lanes):

1. Parse unverified to read `iss`; exact match against a configured issuer.
2. Verify the signature via that issuer's JWKS (OIDC discovery or an explicit
   `jwks_uri`); cache with **refresh-on-unknown-`kid`** (key rotation),
   single-flight, plus a cooldown so unknown kids cannot drive a refresh storm.
3. `alg` ∈ allowlist (`RS256`, `ES256`); reject `none`/`HS*`.
4. `exp`/`nbf` with skew; **`aud` must intersect the configured `audiences`**,
   Keycloak's default `aud=account` makes this the classic silent gap, so the
   realm needs an audience mapper (the compose bootstrap creates one).
5. Extract `username_claim` (default `preferred_username`; per-issuer; fallback
   `sub`).
6. Sanitize: `username_policy.pattern` (default `^[A-Za-z0-9._@-]{1,64}$`).
   Rejects `/` (breaks `Credential` scope parsing) and `$` (reserved by Ozone
   multi-tenancy, `tenant$user`). Reject → `400 InvalidIdentityToken`.

**Minting:** `AccessKeyId` = `OZPX` + 16 Crockford-base32 CSPRNG chars;
`SecretAccessKey` = 40 base64url chars; `SessionToken` = 43 base64url chars
(opaque, bound to the AKID). Store: `AKID → {secret, session_token, username,
issuer, expires_at}`.

**Response / errors:** AWS-shaped XML (`AssumeRoleWithWebIdentityResponse` with
`Credentials{AccessKeyId, SecretAccessKey, SessionToken, Expiration}`;
`InvalidIdentityToken`, `ExpiredTokenException`, `ValidationError`).

### SigV4 verification on the data path

Header auth and query ("presigned") auth:

1. Parse `Credential=<AKID>/<date>/<region>/<service>/aws4_request`,
   `SignedHeaders`, `Signature`: from the header, or from the `X-Amz-*` query
   parameters for presigned URLs.
2. Store lookup. Miss → `403 InvalidAccessKeyId`; expired → `403 ExpiredToken`;
   `X-Amz-Security-Token` must equal the stored session token (constant-time).
3. Rebuild the canonical request **from the wire**: URI as received (no
   re-encoding round-trips); canonical query; canonical headers restricted to
   `SignedHeaders`; **payload hash = `x-amz-content-sha256` as sent**
   (`UNSIGNED-PAYLOAD` / `STREAMING-*` pass through verbatim, bodies are never
   buffered). Presigned requests use the literal `UNSIGNED-PAYLOAD` and exclude
   `X-Amz-Signature` from the canonical query, per the query-auth scheme.
4. Derive the signing key from the stored secret; HMAC; constant-time compare.
5. `X-Amz-Date` within `security.sigv4_clock_skew` (±15 min default); presigned
   URLs are additionally valid only until `X-Amz-Date + X-Amz-Expires` (→
   `AccessDenied`, "Request has expired").
6. Region `security.region` (default `us-east-1`), service `s3`.

Streaming uploads: the **seed signature** is verified; per-chunk signatures pass
through unverified ([security considerations](#security-considerations)). Failures return S3 error XML
(`SignatureDoesNotMatch`, ...) so SDK retry behavior works.

### Identity injection: the synthetic header

After authentication (any lane), the request presented to Ozone carries:

```txt
Authorization: AWS4-HMAC-SHA256 Credential=<username>/<yyyymmdd>/us-east-1/s3/aws4_request,
               SignedHeaders=host;x-amz-date, Signature=<64 hex chars, junk>
X-Amz-Date: <now, ISO8601 basic UTC>
x-amz-content-sha256: UNSIGNED-PAYLOAD
```

Structurally valid for `AuthorizationV4HeaderParser` → `SignatureInfo` populated
with `awsAccessId=<username>` → OM attributes the request and evaluates native
ACLs. Unsecured mode validates nothing further. `X-Amz-Security-Token` is
stripped before forwarding. **Verified end to end against a stock Ozone**
([VERIFICATION.md](VERIFICATION.md)).

Two forward modes (`upstream.forward_mode`):

- `rewrite` (default): for temp-cred SigV4 the proxy minimally rewrites only
  the AKID inside the client's existing header (preserving the client's payload
  hash, so streaming keeps working); Bearer and presigned requests get the
  fully synthetic header above.
- `resign`: a full re-sign toward Ozone: robust to future parser strictness and
  the on-ramp for a secure-mode Ozone. **Today `resign` provides no upstream
  authentication**: it signs with a public constant (`forward.ResignSecret`)
  that unsecured Ozone never checks, so its only value is a self-consistent
  header. A secure-mode deployment must replace that constant with a real
  shared secret before relying on the signature.

For presigned requests the verified auth query parameters are stripped before
forwarding, so Ozone never sees half a query signature.

### Credential store

One interface, two implementations: `memory` (single replica; TTL sweeper) and
`valkey` (HA/multi-replica; values encrypted with a proxy key; small local
cache).

The valkey store's "small local cache" is valkey-go's server-assisted
**client-side caching** (CSC): each replica caches recently-read credentials
and valkey pushes an invalidation the moment a key changes, so the same
mechanism that provides the cache also propagates revocation across replicas
within milliseconds (a `DELETE` on one replica is honored by the others without
a store round-trip per request). Values are AES-256-GCM sealed
(nonce‖ciphertext) with a 32-byte key from `OZPX_STORE_KEY`, **bound to their
access key ID as additional authenticated data** so a record cannot be grafted
onto another key. The valkey key is `ozpx:cred:<AKID>` and its TTL is
`expiry + retention`, so a just-expired credential still resolves to
`ExpiredToken` (not `InvalidAccessKeyId`), matching memory-store semantics.

### Configuration

```yaml
listen: 0.0.0.0:9000
admin_listen: 0.0.0.0:9090

upstream:
  s3_endpoint: http://ozone-s3g:9878
  forward_mode: rewrite        # rewrite | resign

data_path:
  accept_bearer: true          # Bearer lane on/off
  strict: true                 # no fallback; unauthenticated → 403

issuers:
  - name: keycloak
    issuer: https://keycloak.local/realms/ozone
    audiences: [ozone-s3]
    username_claim: preferred_username
  - name: corp-dev
    issuer: https://token.corp.example
    jwks_uri: https://token.corp.example/keys
    audiences: [s3]
    username_claim: sub

sts:
  max_duration: 3600
  role_arn_allowlist: ["arn:ozone:iam::dev:role/oidc"]

credential_store:
  type: memory                 # memory | valkey

security:
  sigv4_clock_skew: 15m
  allowed_signing_algs: [RS256, ES256]
  region: us-east-1

username_policy:
  pattern: "^[A-Za-z0-9._@-]{1,64}$"
```

Validation is strict and fails at startup: issuers with empty `audiences` are
rejected, symmetric and `none` algorithms are rejected, and the valkey
encryption key is read **only** from the environment variable named by
`credential_store.valkey.key_env`: never from the config file.

### Technology choices

| Decision     | Choice                                                                                                                                                                             |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Language     | Go, static binary, streaming `httputil.ReverseProxy`, distroless image                                                                                                            |
| JWT / JWKS   | `lestrrat-go/jwx`                                                                                                                                                                  |
| SigV4 verify | internal package; canonicalization per the AWS specification, pinned to the official test-suite vector and round-tripped against `aws-sdk-go-v2`'s signer (a test-only dependency) |
| Metrics      | Prometheus client                                                                                                                                                                  |

Runtime dependencies are deliberately few: jwx, yaml, prometheus, valkey-go.

### Repository layout

```txt
/cmd/proxy/                  # the proxy itself
/cmd/ozone-login/            # device-flow token helper for humans ([client compatibility](#client-compatibility-and-credential-lifecycle))
/cmd/credential-portal/      # browser credential page behind oauth2-proxy
/internal/{config,oidc,sts,sigv4,store,forward,server,s3err,devicelogin}/
/deploy/compose/             # runnable stack: Ozone + Keycloak + proxy
/deploy/helm/                # Kubernetes chart + NetworkPolicies
/docs/
```

### Client compatibility and credential lifecycle

Target clients: aws cli, boto3, mc/minio-go, the Java SDK (and therefore s3a,
Spark, Iceberg FileIO) and modern SDKs generally. All consume the exchange flow
natively, a legacy of EKS IRSA, which made WebIdentity credential providers
standard across the AWS SDK family. **No durable/static keypair feature is
required for this population.**

| Client                         | Mechanism                                                                                                   | Notes                                                                 |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| aws cli v2 (≥ 2.13)            | profile `role_arn` + `web_identity_token_file`, or env vars; `AWS_ENDPOINT_URL_STS` / `AWS_ENDPOINT_URL_S3` | auto-exchange + auto-refresh                                          |
| boto3 / botocore (2023+)       | same env vars, zero code                                                                                    | the provider re-reads the token file on each refresh                  |
| Java SDK v2 / s3a (Hadoop 3.4) | `WebIdentityTokenFileCredentialsProvider` + same env; `fs.s3a.endpoint` for S3                              | Spark / Iceberg FileIO inherit for free                               |
| minio-go                       | `credentials.NewSTSWebIdentity(stsEndpoint, tokenFn)`                                                       | MinIO's STS is the same API, so support is first-class                |
| mc CLI                         | `MC_HOST_<alias>="https://<AK>:<SK>:<SESSION>@proxy:9000"`                                                  | session token supported, but **no auto-refresh** → re-issue on expiry |

Standard environment recipe:

```bash
export AWS_ROLE_ARN=arn:ozone:iam::dev:role/oidc
export AWS_WEB_IDENTITY_TOKEN_FILE=~/.ozone/token.jwt
export AWS_ENDPOINT_URL_STS=https://proxy:9000
export AWS_ENDPOINT_URL_S3=https://proxy:9000
```

**Token-file lifecycle, the real operational detail.** SDKs refresh
*credentials* by re-reading the token file; nothing refreshes the *JWT inside
it*. And since the temp TTL is `min(jwt.exp − now, ...)` ([the STS exchange](#sts-assumerolewithwebidentity)), an IdP's default
short access-token lifespan (5 minutes in a stock Keycloak realm) would cap
every credential at that value and break refresh once the file goes stale. Two
knobs, both required in practice:

1. Raise the access-token lifespan **per client** on the dedicated IdP client
   for this audience (e.g. 1–8 h): not realm-wide.
2. `ozone-login`: device-flow login, writes the token file, keeps it fresh via
   the refresh token. Service accounts use `client_credentials` on a timer
   (systemd timer / CronJob / sidecar).

## Security considerations

**The trust boundary is the network.** Ozone remains unsecured; anyone who
reaches S3G:9878 with a well-formed header *is* whoever they claim. S3G must be
reachable **only** from the proxy, NetworkPolicy in Kubernetes, an internal
network with no published port in compose. This is non-negotiable, and it
applies to every Ozone port (OM RPC, SCM, DataNodes), not just the gateway.

| Threat                 | Mitigation                                                                                                                                                                                                                                                                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Stolen JWT             | Short issuer TTLs; the JWT travels only on STS/Bearer calls, over TLS.                                                                                                                                                                                                                                                                     |
| Stolen temp creds      | TTL ≤ token exp; session-token binding; revocation = store delete (admin endpoint).                                                                                                                                                                                                                                                        |
| Replay                 | SigV4 date skew ±15 min; TLS everywhere.                                                                                                                                                                                                                                                                                                   |
| Direct S3G access      | Network policy, and it *is* the whole boundary, so verify the CNI enforces it.                                                                                                                                                                                                                                                            |
| Username forgery       | Only the proxy writes the synthetic header; strict username pattern; `$` and `/` rejected.                                                                                                                                                                                                                                                 |
| Alg confusion / `none` | Alg allowlist; issuer pinned by exact `iss`; **`aud` verified** (audience mapper required in Keycloak).                                                                                                                                                                                                                                    |
| Key rotation           | JWKS refresh-on-unknown-`kid`, single-flight, with cooldown.                                                                                                                                                                                                                                                                               |
| Secret leakage         | Secrets live only in the store (AES-256-GCM for valkey); never logged; constant-time compares.                                                                                                                                                                                                                                             |
| Store tampering        | GCM additional-data binding: a record cannot be moved to another access key ID.                                                                                                                                                                                                                                                            |
| Admin endpoint abuse   | The admin listener (`:9090`) carries metrics **and** the state-changing revocation `DELETE`; it is unauthenticated by design, so it must stay internal, compose binds it to localhost, and the chart keeps it ClusterIP behind a NetworkPolicy scoped to the scrape source (an empty source list denies the port rather than opening it). |
| Proxy egress abuse     | Egress NetworkPolicy: the proxy may reach only DNS, the S3 Gateway, valkey and the configured issuers.                                                                                                                                                                                                                                     |

**Known gap:** per-chunk streaming signatures are not verified (the seed
signature is; [SigV4 verification](#sigv4-verification-on-the-data-path)).

Deployment hardening beyond the code, TLS, secret management, rate limiting,
audit retention, is checklisted in [PRODUCTION.md](PRODUCTION.md).

## Observability

Prometheus: `sts_exchanges_total{issuer,result}`,
`bearer_auth_total{issuer,result}`, `sigv4_verifications_total{result}`,
`presigned_verifications_total{result}`, `upstream_requests_total{code}`,
`credential_revocations_total`, latency histograms (including a dedicated
verification-overhead histogram) and an `active_credentials` gauge.

JSON logs: request id, username, AKID, issuer, lane, decision, **never**
secrets, session tokens or raw JWTs.

A Grafana dashboard is committed at `deploy/dashboards/`.

## Ozone-side notes and constraints

### Required Ozone configuration

```txt
ozone.security.enabled = false
ozone.acl.enabled      = true
ozone.acl.authorizer.class = org.apache.hadoop.ozone.security.acl.OzoneNativeAuthorizer
```

Development tracks the current Ozone release, and the version actually
exercised is recorded with its image digest in
[VERIFICATION.md](VERIFICATION.md). Run a recent patch release on JDK 17 or
newer: HDDS-14858 breaks Ozone Manager operations on JDK 11 and earlier.

### ACL bootstrap

Per user, the working grant set:

```bash
ozone sh volume addacl -a user:alice:rl /s3v                      # volume list/read, floor for any access
ozone sh volume addacl -a user:alice:rwlc /s3v                    # + self-service bucket creation
ozone sh bucket addacl -a user:alice:a  /s3v/<bucket>             # or granular rwl
ozone sh bucket addacl -a "user:alice:rwl[DEFAULT]" /s3v/<bucket> # key inheritance
```

- Buckets created through the proxy are owned by the OIDC username.
- **CreateBucket checks WRITE on the volume** (verified live;
  om-audit: `User alice doesn't have WRITE permission to access volume
  Volume:s3v`). `rl` alone suits pre-provisioned buckets; where users create
  buckets through S3, grant `rwlc` (the compose bootstrap does).
- **Multipart ACL enforcement (HDDS-14898, HDDS-14894):** `ListParts` and `ListMultipartUploads`
  now enforce ACLs (previously unchecked). Multipart workflows need LIST/READ on
  the bucket; setups that "worked" on ≤ 2.1.0 may now 403. → Covered by the e2e
  multipart matrix: `user:X:rl` on the bucket suffices
  ([VERIFICATION.md](VERIFICATION.md)).

### Groups

Native ACL group checks resolve via **Hadoop group mapping on the OM**
(shell/LDAP/static), not JWT claims. If needed later: an LDAP-backed IdP with
`LdapGroupsMapping`, static overrides, a custom group mapper, or Ranger.

### Multi-tenancy collision

`tenant$user` accessIds ⇒ `$` is rejected in usernames; if Ozone tenants are
adopted, the injector can emit `tenant$username`.

### Upstream STS status

The `AssumeRoleWithWebIdentity` endpoint is absent from released Ozone, but the 2.1.x
line is accumulating STS authorization plumbing: Ranger artifacts for STS
tokens (HDDS-13848, 2.1.0); S3-action-aware authorization, `s3Action` in
`RequestContext`, `OzoneGrant` with allowed-action sets, backported "so Ranger
can consume it upstream" (HDDS-15064), with release notes referencing
STS session policies.

This project deliberately mirrors the AWS client contract, so if and when
native support ships, migration is an endpoint swap plus an ACL→policy
translation rather than a client rewrite. Status tracking, a design comparison
and a watch list live in [UPSTREAM.md](UPSTREAM.md).

## Alternatives considered

1. **JWT in the access-key field**: zero infrastructure, but fat tokens versus
   header limits, mid-session expiry, and no real verification (the gateway
   would still accept anything). A debugging trick, not a design.
2. **Wait for upstream STS**: moving ([upstream STS status](#upstream-sts-status)) but unmerged and without
   WebIdentity in any release; the timeline risk is unacceptable for anyone who
   needs OIDC today. We stay API-compatible instead.
3. **Authorization inside the proxy** (claim → bucket-prefix rules, Ozone as a
   dumb backend): would duplicate a policy engine Ozone already has, and would
   break the moment anyone reached Ozone directly. Rejected in favor of
   attributing the request and letting native ACLs decide ([how Ozone derives identity](#in-ozone-the-access-key-id-is-the-identity)).

## Design decisions

The reasoning behind the choices above, and the alternatives that were
weighed against them, is recorded as [ADRs](adr/README.md).

## References

- Ozone STS umbrella: <https://github.com/apache/ozone>, HDDS-13323
  (`HDDS-13323-sts` branch; `AssumeRoleWithWebIdentity` listed as future work)
- **Ozone release notes:** <https://ozone.apache.org/release-notes/>
  HDDS-14858 (JDK ≤ 11 regression), HDDS-14898/HDDS-14894 (multipart ACL
  enforcement), HDDS-15064 (S3-action-aware authorization for STS/Ranger).
- Ozone S3 docs (any keypair is accepted when security is disabled):
  <https://ozone.apache.org/docs/>
- AWS `AssumeRoleWithWebIdentity`:
  <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html>
- AWS SigV4:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>
- MinIO web-identity STS (the same pattern, a reference implementation):
  <https://github.com/minio/minio/blob/master/docs/sts/web-identity.md>
- oauth2-proxy: <https://oauth2-proxy.github.io/oauth2-proxy/>
