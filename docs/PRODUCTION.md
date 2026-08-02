# Production readiness, checklist and posture

The compose stack in this repository is a **lab**: it is what the
[verification record](VERIFICATION.md) runs against, not a production
deployment. This document is the gap between the two.

The expected shape is the proxy behind a TLS edge (the compose `edge`
overlay models one with HAProxy), with the S3 Gateway unreachable by anything
else. The identity provider is assumed to be operated and hardened
separately; this document focuses on what *this* project must get right.
Threat model: [architecture.md](architecture.md); the native-Ozone alternative and its
migration path: [UPSTREAM.md](UPSTREAM.md).

## Must-have before production

- [ ] **TLS at the edge.** Terminate TLS in front of the proxy (HAProxy,
  see `make edge-up` for the modeled setup). SigV4 signs the `Host` header,
  so the edge must forward it unmodified; unsigned `X-Forwarded-*` headers
  are harmless.
- [ ] **HTTPS issuer and JWKS URLs only.** The JWKS fetch is the token
  trust chain: plain HTTP or lax cert validation lets an on-path attacker
  substitute signing keys and mint identities. The compose stack's
  `http://keycloak:8080` is lab-only.
- [x] **F3, egress NetworkPolicy.** The proxy may talk only to the
  issuers, the S3 Gateway, valkey and DNS (chart:
  `networkPolicy.issuerEgress` / `issuerEgressPorts`).
- [x] **F4, store records bound to their key.** Valkey values are
  AES-256-GCM sealed with the access key ID as AAD: a store-level attacker
  cannot graft one record's ciphertext onto another AKID.
- [x] **Admin port fails closed.** `networkPolicy.adminIngress: []` now
  renders *no* admin ingress rule (port denied) instead of "all sources".
- [ ] **Valkey with AUTH + TLS**, reachable only from proxy pods (the
  chart's valkey policy covers the network side for the in-chart instance).
- [ ] **`OZPX_STORE_KEY` from a real secret manager** (Vault,
  external-secrets, sealed-secrets, never `values.yaml`). Document the
  rotation procedure: rotating the key invalidates all live credentials,
  acceptable by design (they are short-lived), but it must be a scheduled
  decision, not a surprise.
- [ ] **Boundary enforcement verified, not assumed.** NetworkPolicies are
  only as real as the CNI enforcing them, verify with a probe pod that
  S3G/OM/SCM/DataNode ports are unreachable from outside the sanctioned
  paths. The entire unsecured Ozone cluster is one trust zone; the proxy is
  its only door.
- [ ] **Rate limiting on the STS lane** (edge or ingress level, per-IP).
  The exchange endpoint is unauthenticated until the JWT is validated,
  it is the DoS surface. The 1 MiB body cap is not a rate limit.
- [ ] **A negative probe in monitoring**: an anonymous request to the proxy
  must return 403, and a direct request to the S3 Gateway from outside the
  sanctioned path must not connect at all. Both are cheap to alert on and
  both fail silently open if someone edits the wrong policy.

## Should-have

- [ ] **Durable authentication audit.** The proxy log *is* the auth audit
  trail (usernames, AKIDs, issuers, error codes, never secrets). Ship it
  (Loki/ELK) with retention; correlate with the OM audit log by username.
- [ ] **Alert rules** on the metrics already exported: verification-failure
  spikes, `store_error`s, issuer unreachable (STS 503s), replica down,
  upstream 5xx rate. The Grafana dashboard shows them; alerts act on them.
- [ ] **A valkey availability stance.** Either operate valkey replicated
  (Sentinel/managed), or explicitly accept "store loss ⇒ all clients
  re-exchange a token", defensible for short-lived credentials, but write
  it down as policy.
- [ ] **Image supply chain.** CI builds and publishes the image; deploy by
  pinned digest. The proxy *is* the security boundary, a tampered image
  removes it silently.
- [ ] **External security review.** The M3 review
  ([VERIFICATION.md](VERIFICATION.md)) was a self-review; get a second
  pair of eyes before real data.
- [ ] **Disable the Bearer lane** (`data_path.accept_bearer: false`).
  It puts long-lived JWTs on every request; SigV4 with short-lived minted
  credentials is the primary path and strictly better hygiene.
- [ ] **Ops runbook**: credential revocation (admin endpoint), IdP signing
  key rotation (publish old+new JWKS ≥ max token lifetime), incident
  response for a leaked credential (revoke, then rotate the store key if
  the store itself is suspect).

## What must be protected, ranked by blast radius

1. **Network access to every Ozone port**: S3G, OM RPC, SCM, DataNodes.
   Unsecured Ozone has no internal authentication; anyone who reaches any
   of them acts as anyone.
2. **The JWKS trust chain** (HTTPS + real CA validation to every issuer).
3. **Issuer configuration integrity**: one rogue issuer in `config.yaml`
   equals full compromise; config changes go through reviewed GitOps only.
4. **The store key and store contents** (`OZPX_STORE_KEY`, valkey).
5. **The admin listener** (revocation): operators only.
6. **The proxy artifact itself** (signed/pinned images).
7. **Log discipline**: usernames and AKIDs yes; secrets, tokens, raw JWTs
   never (standing invariant; hold it under debugging pressure too).

## Enabling Ranger one day

Swapping the authorizer is compatible with this design *by construction*:
after the proxy authenticates, Ozone only ever sees a plain username, and
`ozone.acl.authorizer.class` (native ACLs today,
`RangerOzoneAuthorizer` tomorrow) evaluates that same username against its
policies. Nothing in the proxy changes.

What does change is identity plumbing, plan for these:

- **Ranger must know the users**: usersync from LDAP/AD (or Keycloak
  federated through LDAP). IdP-only users otherwise mean hand-made
  per-user policies.
- **Groups are resolved OM-side**, not from the JWT: Hadoop group mapping
  (default shell lookup is useless for OIDC identities). Options: LDAP
  group mapping on OM, or a custom group mapper that asks the IdP
  directly.
- **Semantics shift**: Ranger is deny-by-default with central policies,
  the native model's implicit owner rights and `ozone sh addacl` workflow
  no longer apply.
- **Unverified here.** This repo has never run Ranger; treat it as a
  future compose overlay + verification milestone before relying on it.

## When upstream ships

If the native OIDC/STS effort (apache/ozone#10266 on the HDDS-13323 STS
branch) merges and releases, re-evaluate against
[UPSTREAM.md](UPSTREAM.md): the client contract matches deliberately, so
migration is an endpoint swap plus ACL→Ranger policy translation, not a
client rewrite.
