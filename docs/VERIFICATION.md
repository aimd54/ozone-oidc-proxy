# Verification record

What follows is the evidence trail for every claim this project makes:
each entry was executed against the runnable compose stack in
`deploy/compose/`, on stock Apache Ozone, and records what was checked, what
passed, and what was found along the way. Milestones and section numbers
refer to [architecture.md](architecture.md).

The first entries date from **2026-07-06**.

## Stack under test

| Component                             | Version                                                           |
| ------------------------------------- | ----------------------------------------------------------------- |
| Apache Ozone (scm, om, datanode, s3g) | `apache/ozone@sha256:2fef7c97b3a8...` (tag 2.1.1), OpenJDK 21.0.2 |
| Keycloak                              | `quay.io/keycloak/keycloak@sha256:09a381c715ab...` (tag 26.0)     |
| ozone-oidc-proxy                      | built from this tree (Go 1.26, distroless image)                  |

Ozone config: `ozone.security.enabled=false`, `ozone.acl.enabled=true`,
`OzoneNativeAuthorizer`. S3G publishes no host port; the proxy is the
only ingress.

## The synthetic header, end to end

**VERIFIED, stock Ozone 2.1.1 accepts the synthetic `Authorization` header
end-to-end and attributes operations to the injected username.** The design
stands as specified; no pivot to `resign` mode needed.

Evidence, in increasing strength:

1. OM audit log shows the OIDC username as the acting principal for a
   request that entered as proxy-verified SigV4 (AKID rewritten to
   `alice`):

   ```txt
   # pre-fix run (grant was rcl):
   user=alice | op=CREATE_BUCKET {"volume":"s3v"} | ret=FAILURE |
     OMException: User alice doesn't have WRITE permission to access volume ...
   # post-fix run:
   user=alice | op=CREATE_BUCKET {"volume":"s3v","bucket":"acl-test-28070",
     ...,"acls":"[user:alice:a[ACCESS]]",...,"owner":"alice",...} | ret=SUCCESS
   ```

   The identity reached OM's *authorizer*, not just a parser, so ACL
   decisions are made against the OIDC user.

2. `ozone sh bucket info /s3v/<bucket>` → `owner: alice` for a bucket
   created via `aws s3 mb` through the proxy (e2e check).

3. The alice/bob matrix behaves per native ACLs: bob is denied on alice's
   bucket (`AccessDenied`), can list after
   `ozone sh bucket addacl -a user:bob:rl`.

The other day-0 item, upstream STS status, is design-time research,
recorded in and tracked in [UPSTREAM.md](UPSTREAM.md).

## Finding: CreateBucket requires WRITE on the volume

The only deviation found: OM gates S3 `CreateBucket` on **WRITE** on the
volume; the initial `rcl[ACCESS]` grant was insufficient (audit line above).
Fixed: the bootstrap grants `rwlc` on `/s3v`, architecture.md amended. `rl` remains the floor for pre-provisioned
buckets.

## Acceptance suite, first full pass

`make up && make init && make e2e` → **27 passed, 0 failed**
(`deploy/compose/scripts/e2e.sh`):

- **Token acquisition**: ROPC JWTs for alice/bob; `aud=ozone-s3` present
  (audience mapper).
- **STS**: `aws sts assume-role-with-web-identity` yields `OZPX...`
  credentials; disallowed `RoleArn` → `AccessDenied`; forged
  unknown-issuer token → `InvalidIdentityToken`.
- **SigV4 lane**: bucket create / put / get round-trip through the proxy
  with temp credentials; tampered secret → `SignatureDoesNotMatch`; wrong
  session token → `InvalidToken`.
- **Native ACLs through the proxy**: alice/bob matrix incl. live
  `addacl` grant.
- **Bearer lane**: GET and PUT with `Authorization: Bearer <jwt>`;
  garbage token → 403.
- **Strict mode**: plain SigV4 with `AWS_ACCESS_KEY_ID=alice` →
  `InvalidAccessKeyId`; anonymous → 403; S3G unreachable from the host.
- **Admin surface**: `/healthz`; `sts_exchanges_total`,
  `bearer_auth_total`, `sigv4_verifications_total`, `active_credentials`
  exposed on `:9090/metrics`.

Expired-JWT and expired-temp-credential paths are covered by unit tests
with injected clocks (`internal/oidc`, `internal/store`, `internal/sts`,
`internal/sigv4`) rather than by wall-clock waits in e2e; `go test ./...`
green on the same tree.

## Presigned URLs (2026-07-06, same stack)

Query-auth SigV4 verified live: `aws s3 presign` mints a URL from the
temporary credentials; an **anonymous** fetch through the proxy round-trips
(the proxy verifies the query signature, strips the auth parameters and
forwards the synthetic header); a tampered query returns
`SignatureDoesNotMatch`; a URL past `X-Amz-Expires` returns `AccessDenied`
("Request has expired", AWS parity). New counter
`presigned_verifications_total` exposed. Suite total with the four new
checks: **32 passed, 0 failed**. Unit coverage pins the AWS documentation
presigned-GET vector and round-trips against the SDK's `PresignHTTP`.

## Multipart matrix (2026-07-06, same stack)

The 2.1.1 ACL tightening (HDDS-14898/14894) is confirmed live, through the
proxy identity: with no grant, bob's `ListMultipartUploads` and `ListParts`
against alice's bucket return `AccessDenied`; after
`ozone sh bucket addacl -a user:bob:rl`, both succeed, **`rl` on the bucket
is the sufficient grant**, as predicted. Owner flow verified end to
end: `CreateMultipartUpload` → 2 × 5 MiB `UploadPart` → owner lists →
`CompleteMultipartUpload` → the assembled 10 MiB object round-trips
byte-identical; `AbortMultipartUpload` removes the upload from listings;
`aws s3 cp` automatic multipart (10 MiB, 8 MiB threshold) works unmodified.
Suite total: **48 passed, 0 failed**.

## Human credential flows (2026-07-07, same stack)

ROPC is no longer the only human path:

- **`ozone-login` (device flow)**: the real binary, run on the compose
  network against Keycloak 26, completed the RFC 8628 flow end to end:
  printed the verification URL, and after a scripted browser login +
  consent, wrote the 0600 token file and printed the recipe. The
  token carries `aud=[ozone-s3, account]` and exchanged at the proxy's STS
  for `OZPX...` credentials.
- **Credential portal behind oauth2-proxy**: browser session driven by
  curl (cookie jar + Keycloak login form): oauth2-proxy code flow →
  `X-Forwarded-Access-Token` → portal exchange → page renders the
  credentials for alice; those credentials then passed a live
  `aws s3 ls` through the proxy.
- Keycloak side provisioned idempotently by init.py: device grant on
  `ozone-s3`, confidential `ozone-portal` client, both with the
  `aud=ozone-s3` mapper.

Browser flows resolve the pinned issuer host via `/etc/hosts`
(`127.0.0.1 keycloak`) for humans, `curl --resolve` in e2e. Suite total:
**54 passed, 0 failed** (portal checks skip when the overlay is down).

## A second issuer (2026-07-07, same stack)

Multi-issuer is verified live. A static stub issuer
(`deploy/compose/stub-issuer/`: discovery + JWKS + an unauthenticated,
test-only `/token` mint, internal-only, no host port) is registered as a
second issuer with a deliberately different audience (`ozone-data`) and
username claim (`uid`):

- carol's stub-minted token exchanged at the proxy's STS, OIDC discovery
  against a non-Keycloak document shape, JWKS fetch, `username_claim: uid`
  honored (the stub's `sub` is username-policy-invalid by design, so any
  fallback to `sub` would fail loudly instead of mis-attributing);
- data-path attribution via issuer #2: a bucket created with carol's
  `OZPX...` credentials shows `owner: carol`; the Bearer lane accepts the
  stub token directly;
- isolation: alice (Keycloak issuer) is denied on carol's bucket; a stub
  token carrying Keycloak's audience (`ozone-s3`) is rejected with
  `InvalidIdentityToken` (per-issuer `aud` enforcement).

Suite total: **63 passed, 0 failed** (`make up && make init &&
make portal-up && make e2e` on this tree).

## Client smoke tests (2026-07-07, same stack)

Three real clients, containerized in e2e, against the proxy:

- **boto3** (python:3.12-slim, current boto3): credentials resolved by
  botocore's own web-identity provider from `AWS_ROLE_ARN` +
  `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ENDPOINT_URL_STS`: no explicit
  keys anywhere. It minted its own `OZPX...` credentials at the proxy's STS
  and round-tripped an object: the recipe proven with a real SDK.
- **mc** (minio/mc): `MC_HOST_<alias>` with the session token embedded in
  the URL; `mc --debug` shows the 8 MiB upload went out as
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked): the "streaming
  seed-signature" item observed live: the proxy verified the seed
  signature from the wire, Ozone unwrapped the chunk framing, and `mc cat`
  round-trips byte-identical.
- **s3a** (apache/hadoop:3.4.1, AWS SDK v2,
  `TemporaryAWSCredentialsProvider`): 8 MiB put, `-ls` exact size, `-get`
  md5-identical; cross-client, s3a reads mc's streamed object
  byte-identical.

Every item is verified live. Suite total:
**71 passed, 0 failed**.

## Hardening: shared store, revocation, Helm, monitoring (2026-07-08, same stack + HA/monitoring overlays)

All exit criteria are verified live: valkey store + two replicas, the
`resign` forward mode, admin revocation, the Helm chart + NetworkPolicies, the
monitoring overlay, and the load test's p99 gate.

### HA / valkey / resign / revocation

Both replicas share a valkey store (`OZPX_STORE_KEY` AES-256-GCM value
encryption,); replica A forwards in `rewrite` mode, replica B in `resign`.
The e2e "HA / valkey / resign / revocation" step (skips when the overlay is
down) proves, end-to-end:

- **cross-replica store**: credentials minted at replica A's STS create a
  bucket through replica B, and B-minted credentials verify on A (both
  directions);
- **resign attribution**: an object round-trips through replica B, whose
  `resign` mode emits a *fully valid* SigV4 header toward Ozone signed over the
  upstream host; the bucket owner is still the OIDC user (`owner=alice`), so a
  parser-hardened upstream would accept it;
- **revocation propagation**: `DELETE /credentials/<akid>` on replica B's
  admin returns 204, and the credential is then rejected on replica A with
  `InvalidAccessKeyId` (valkey `DEL` + server-assisted client-side-cache
  invalidation); a second delete returns 404;
- **persistence**: the credential survives `docker restart` of a replica (the
  store outlives the process).

Suite total with the HA overlay up: **78 passed, 0 failed**
(`make up && make init && make ha-up && make e2e`).

### Load test, verification overhead ( exit criterion)

`make loadtest` mints a credential, signs GETs with the proxy's own
`sigv4.Sign`, and reads the p99 back from the `verification_duration_seconds`
histogram (bucket-delta over the run, no PromQL). The pure verification step
(measured immediately after the compare, before logging/rewrite) meets the
< 1 ms p99 target with wide margin:

- dedicated run (idle host): **20 000 requests, 7 254 req/s, 0 errors, p99 ≤
  0.25 ms**;
- during this session (monitoring overlay co-resident): **5 000 requests,
  1 813 req/s, 0 errors, p99 ≤ 0.5 ms**.

### Helm chart + NetworkPolicies, kind smoke

`deploy/helm/smoke.sh` stands up a throwaway kind cluster, loads the image,
installs with the in-chart valkey and two replicas, and asserts: **8 passed,
0 failed**: both replicas Ready on a valkey-backed readiness probe;
`/healthz`, `/readyz`, `/metrics` reachable through the Service; the revocation
endpoint returns 404 for an unknown AKID; and all three NetworkPolicies
render (proxy-ingress, s3g-lockdown, valkey). Proxy pods carry an
`app.kubernetes.io/component: proxy` label so the Service and policies select
only proxy pods, never the same-named in-chart valkey. `helm lint` runs in CI.

### Monitoring overlay

`make monitor-up` adds Prometheus (5 s scrape of both replicas' `:9090`) and
Grafana with an auto-provisioned datasource and the committed dashboard
(`deploy/dashboards/ozone-oidc-proxy.json`). Verified live: both scrape targets
`up`; the dashboard auto-loaded; and every one of the eight panel queries
returns data during an e2e + loadtest run, sigv4 verification **p99 ~0.5 ms**
(under the 1 ms threshold line), request-rate split by lane, verification
outcomes (success vs. `mismatch`/`unknown_akid`), upstream codes by 2xx/4xx/5xx
family, `active_credentials`, and the revocations tile populated by a real
revoke (`revocations_total{result="revoked"}=1`).

## Security review (2026-07-08)

A read-only review of the hardening surface (resign signer, valkey store and key
handling, admin revocation endpoint, forward path, config validation, and the
Helm secret/NetworkPolicy/deployment manifests). The code was found careful,
secrets stay out of logs and errors, decryption failures don't leak, session
tokens are stripped before forwarding, GCM uses a fresh random nonce per seal,
and the store key is env-only. No high-severity bug.

Fixed here:

- **Admin-port exposure**: hardening added a state-changing, unauthenticated
  `DELETE /credentials/{akid}` to the admin listener, which previously served
  only read-only health/metrics. Compose now binds the admin port to
  `127.0.0.1` (both replicas) instead of publishing it on all interfaces, and
  the README/threat-model flag it as security-sensitive.
- **Helm admin NetworkPolicy**: the proxy-ingress policy admitted port 9090
  from `podSelector: {}` (the whole namespace). It now renders from a
  configurable `networkPolicy.adminIngress` (default: pods labelled
  `app.kubernetes.io/name=prometheus`), so the revocation endpoint is not
  reachable by every workload in the namespace.

Documented:

- `resign` mode signs with a public constant, so it provides parser-robustness,
  **not** upstream authentication under a future Ozone secure mode.
- `Count` SCANs the keyspace on every `/readyz` and `/metrics` scrape,
  accepted at the credential volumes this proxy handles (already noted in code).

Deferred at review time, **both since fixed**:

- **No egress NetworkPolicy** on the proxy pod (all policies were
  ingress-only). The chart now emits egress rules limiting the proxy to DNS,
  the S3 Gateway, valkey and the configured issuers
  (`networkPolicy.issuerEgress`).
- **valkey values were not bound to their key slot** as GCM additional
  authenticated data, so a party with valkey write access could relocate a
  sealed record (not impersonation-exploitable, the secret stayed encrypted
  and the signature still had to verify against it). Records are now sealed
  with the access key ID as AAD, so a relocated record fails decryption.

The same pass also made the chart's admin ingress fail closed: an empty
`networkPolicy.adminIngress` list now renders no rule at all (denying the
port) instead of an empty `from:`, which the NetworkPolicy API reads as
"all sources".

Both fixes were re-verified live afterwards: with the HA overlay up the full
e2e matrix passes **82/82**, including the nine cross-replica checks that now
run against AAD-bound records, mint on replica A → verify on replica B
through the shared store, revocation propagation, and credential survival
across a replica restart, and the chart renders and lints clean with the
egress rules in place.

## TLS edge, HAProxy overlay (2026-07-12)

**VERIFIED, the e2e suite passes 73/73 with the edge overlay up**, the
four new TLS checks included: `aws s3 ls` against `https://haproxy:8443`,
a presigned URL minted for and fetched anonymously over the https
endpoint, and the strict 403 preserved through the edge. TLS terminates at
HAProxy (self-signed lab cert, SAN `haproxy/localhost/127.0.0.1`); the
SigV4-signed Host header passes through untouched, so client signatures
verify unchanged, the same shape as the production HAProxy ingress this
overlay models.

Operational findings baked into the overlay:

- The HAProxy healthcheck **is** the PRODUCTION.md boundary probe: an
  anonymous request through the edge must answer 403 (TLS handshake +
  backend routing + strict mode in one check). `localhost` resolves to
  `::1` inside the container while the frontend binds IPv4, the check
  targets `127.0.0.1`.
- Backend resolution goes through Docker's embedded DNS at runtime
  (`resolvers` + `init-addr libc,none`): compose recreates the proxy
  container (new IP) on image rebuilds, and a startup-only libc lookup
  left the backend permanently DOWN (observed live as 503s).

## Lakehouse, Nessie + Iceberg on OIDC credentials (2026-07-12)

**VERIFIED, the tour notebook executes headless end-to-end**
(`jupyter nbconvert --execute`, exit 0) on `make lakehouse-up`, and the
smoke script passes 4/4 (Nessie API v2, Iceberg REST facade, token file,
Jupyter).

The day-0 unknown resolved **yes**: Nessie's AWS SDK (Java v2) honors
`AWS_ENDPOINT_URL_STS` inside its web-identity credentials provider, so
`auth-type=APPLICATION_GLOBAL` + the refresher sidecar give Nessie S3
access with **no static secret anywhere**: the proxy log shows the whole
chain:

```txt
"msg":"token exchange succeeded","handler":"sts",
  "username":"service-account-nessie","issuer":"keycloak",
  "access_key_id":"OZPXP0CQ1HJ6K9R9N5ED","role_session_name":"nessie"
"msg":"sigv4 verified","lane":"sigv4","method":"HEAD","path":"/lakehouse",
  "username":"service-account-nessie","issuer":"keycloak"
```

Two OIDC identities cooperate on one Iceberg table: Nessie (workload,
client-credentials grant) writes catalog metadata to `s3://lakehouse/`;
alice (human, minted temp creds) writes the data files via PyIceberg
against Nessie's Iceberg REST endpoint; the Nessie commit log records the
table history. Notebook sections verified in the same run: raw STS
exchange, boto3 auto-exchange from env vars only, S3 CRUD, presigned
(round-trip + tamper), Bearer, bob's AccessDenied, revocation
(204 → InvalidAccessKeyId), and the https edge. Packaging notes:
PyIceberg resolves the *table-level* FileIO to fsspec regardless of a
client `py-io-impl` pin, so the Jupyter image ships `s3fs`; and boto3
presigns with the legacy v2 query scheme unless
`Config(signature_version="s3v4")` is set, both strict implementations
rightly 403'd the v2 URLs, which the notebooks' first headless runs
surfaced (a silent print, not an exception, worth remembering when
reading notebook "green" runs).

## Reproduce

```bash
make up && make init && make e2e     # base suite (69/69)
make edge-up && make e2e             # + TLS edge via HAProxy (73/73)
make lakehouse-up && make lakehouse-smoke   # Nessie/Iceberg overlay (4/4)
docker exec oidc-jupyter jupyter nbconvert --to notebook --execute \
  ozone-oidc-tour.ipynb --output /tmp/executed.ipynb   # the full tour
make ha-up && make e2e               # + HA/valkey/resign/revocation (78/78)
make loadtest                        # p99 gate (fails if verification p99 ≥ 1 ms)
make monitor-up                      # Prometheus + Grafana → http://localhost:3000
./deploy/helm/smoke.sh               # Helm chart on a throwaway kind cluster (8/8)
make clean                           # tear down + delete volumes
docker compose -f deploy/compose/docker-compose.yml exec ozone-om \
  cat /var/log/hadoop/om-audit-om.log   # attribution evidence
```
