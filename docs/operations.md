# Operations

What running the proxy involves once it is installed: revoking credentials,
scraping metrics, and running more than one replica.

The compose commands that exercise each of these in a lab are in
[examples/compose/README.md](../examples/compose/README.md).

## The admin listener

The proxy serves a second listener, `admin_listen`, defaulting to
`0.0.0.0:9090`. It carries `/healthz`, `/readyz`, `/metrics` and the
revocation endpoint.

**It is unauthenticated and state-changing.** Besides metrics it serves an
endpoint that deletes credentials, so it must never be reachable from a
shared network. The lab binds it to `127.0.0.1`. In Kubernetes the chart
keeps it ClusterIP behind a NetworkPolicy scoped to the scrape source.

## Revoking a credential

```bash
curl -X DELETE http://localhost:9090/credentials/OZPX...   # 204 revoked, 404 unknown
```

The credential is deleted from the store immediately. With the valkey store
the deletion also invalidates every replica's local cache, so the credential
stops working fleet-wide rather than only on the replica that received the
call.

Revocation is the only way to cut a credential short. Minted credentials
carry their own expiry and the proxy holds no session state beyond the
store, so there is nothing else to invalidate.

## Metrics and dashboards

`/metrics` on the admin listener exposes Prometheus metrics: request
counts and durations per lane, verification outcomes, upstream status
families, active credentials, and revocations.

A Grafana dashboard is committed at
[`dashboards/ozone-oidc-proxy.json`](../dashboards/ozone-oidc-proxy.json).
It is a plain dashboard file, importable into any Grafana rather than only
the one the compose overlay starts. It shows traffic and
verification-latency percentiles with p99 against a 1 ms line, the split
between lanes, verification outcomes, upstream status families, active
credentials, and revocations.

## Running more than one replica

A single replica can use the in-memory credential store. More than one
cannot: a credential minted on replica A is unknown to replica B, so a
client would see intermittent `InvalidAccessKeyId`. Multi-replica
deployments need `credential_store.type: valkey`, which is shared.

With a shared store, a credential minted on any replica is honored on every
replica, and a revocation on one propagates to all of them.

Replicas may differ in forward mode. `rewrite` and `resign` interoperate
against the same upstream and the same store, so a fleet can carry a mix
while a change rolls out. [Configuration](configuration.md) covers what each
mode does.

## What to watch

- **Verification latency.** The p99 of signature verification is the proxy's
  own overhead, separate from upstream time. The committed dashboard draws
  it against a 1 ms line.
- **Verification outcomes.** A rise in `SignatureDoesNotMatch` usually means
  a clock problem or a client signing over a rewritten host. A rise in
  `InvalidAccessKeyId` after a restart means credentials were held in the
  memory store and did not survive it.
- **Upstream status families.** These are Ozone's answers, not the proxy's,
  and separate an authentication problem from an ACL one.

Before deploying any of this, read the [production
checklist](production.md).
