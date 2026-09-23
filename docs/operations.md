# Operations

What running the proxy involves once it is installed: revoking credentials,
scraping metrics and alerting on them, and running more than one replica.

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
families, requests the S3 Gateway never answered, whether the credential
store is answering, active credentials, and revocations.

A Grafana dashboard is committed at
[`dashboards/ozone-oidc-proxy.json`](../dashboards/ozone-oidc-proxy.json).
It is a plain dashboard file, importable into any Grafana rather than only
the one the compose overlay starts. It shows traffic and
verification-latency percentiles with p99 against a 1 ms line, the split
between lanes, verification outcomes, upstream status families beside the
requests the gateway never answered, active credentials, and revocations.

## Alerts

Two rule files ship in [`alerts/`](../alerts/), each with promtool tests
beside it that `make alerts-check` runs:

- `ozone-oidc-proxy.rules.yml` alerts on the proxy's own metrics, and needs
  nothing beyond the scrape of the admin listener.
- `ozone-oidc-proxy-probes.rules.yml` alerts on two probes, defined for
  blackbox_exporter in `blackbox.yml`, which check from outside the two
  properties the proxy cannot report on itself.

Load them through `rule_files`, or place their groups under the `spec` of a
`PrometheusRule` for the Prometheus Operator. The compose monitor overlay
loads the first file.

**Every rule selects `job="ozone-oidc-proxy"`.** A rule whose selector
matches nothing never fires, and nothing reports that it cannot. Scrape the
admin listener under that job name, or change the name throughout the file.
`OzoneOIDCProxyNotScraped` fires when no target of that job exists, which is
how the mistake shows up.

The thresholds are starting points, to tune against real traffic. Rates are
taken over five minutes, and no rule built on a rate fires sooner than that,
so a single failed request never pages anyone.

| Alert | Severity | What it means, and where to look first |
| --- | --- | --- |
| `OzoneOIDCProxyNotScraped` | warning | No target exists under the job the rules select, so no other rule can fire. |
| `OzoneOIDCProxyDown` | critical | A replica's admin listener has not answered for two minutes. |
| `OzoneOIDCProxyCredentialStoreDown` | critical | A replica cannot read valkey. Token exchanges and SigV4 requests fail on it; bearer requests do not use the store. |
| `OzoneOIDCProxyCredentialStoreErrors` | warning | valkey answers reads but fails requests. A valkey out of memory rejects writes while still serving reads. |
| `OzoneOIDCProxyIssuerUnreachable` | critical | An issuer's discovery document or signing keys cannot be fetched. No new credentials are issued; issued ones work until they expire. Check the issuer, and that the egress policy admits it. |
| `OzoneOIDCProxyTokenExchangesRejected` | warning | Over a quarter of exchanges fail with one error. `InvalidIdentityToken`: an audience or issuer that no longer matches after a change at the identity provider. `ExpiredTokenException`: stale tokens, or a clock problem. `AccessDenied`: a role ARN outside the allowlist. |
| `OzoneOIDCProxyRequestsRejected` | warning | Over a tenth of one lane's requests fail with one result. `skew`: a clock problem, on the clients or the proxy's host. `mismatch`: a `Host` header rewritten between client and proxy, or a client holding the wrong secret. `unknown_akid`: credentials held in the memory store and lost on a restart, or a revoked credential still in use. Expiry is not counted: it is how credentials are meant to end. |
| `OzoneOIDCProxyUpstreamUnreachable` | critical | The S3 Gateway is not answering at all, and the proxy is returning 502 in its place. |
| `OzoneOIDCProxyUpstreamErrors` | warning | Over 5% of the gateway's responses are server errors. These are Ozone's own answers: look at the Ozone Manager and the Datanodes. |
| `OzoneOIDCProxyVerificationSlow` | warning | Verification p99 has stayed above 1 ms for fifteen minutes. This is the proxy's own overhead: look for CPU starvation, or a slow store. |

### The two probes

Two properties matter more than anything the metrics show, because both fail
silently open when a policy is edited carelessly, and the proxy cannot see
either failure itself.

- **An anonymous request must be refused by the proxy.** Module
  `ozpx_anonymous_refused` sends a request with no credentials and passes
  only on a 403 carrying the proxy's own message. The message is the check:
  with strict mode off the request reaches Ozone, which refuses it with a 403
  of its own, so a probe going by the status would keep passing. A unit test
  holds the module against the proxy's refusal and against Ozone's, so
  rewording the refusal breaks the build rather than the probe.
- **The S3 Gateway must not accept a connection from outside the
  sanctioned path.** Module `ozpx_tcp_connect` opens a TCP connection to the
  gateway, and the alert fires when it succeeds. What makes this a negative
  check is where the exporter runs: somewhere the network policy is meant to
  keep out, such as the monitoring namespace, and never alongside the proxy.

The rules expect two scrape jobs with these names:

```yaml
scrape_configs:
  - job_name: ozone-oidc-proxy-anonymous
    metrics_path: /probe
    params:
      module: [ozpx_anonymous_refused]
    static_configs:
      - targets: [https://s3.example.com/] # the endpoint clients use
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
  - job_name: ozone-oidc-proxy-bypass
    metrics_path: /probe
    params:
      module: [ozpx_tcp_connect]
    static_configs:
      - targets: [ozone-s3g-rest.ozone.svc:9878] # the gateway, by the name its clients resolve
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

A negative probe has a failure mode of its own: one that cannot run looks
exactly like a gateway refusing it. Two rules cover that.
`OzoneOIDCProxyProbeNotReporting` fires when either job has no result at
all, and `OzoneOIDCProxyBypassProbeUnresolved` fires when the gateway's name
does not resolve from where the probe runs, which fails the probe without
testing anything.

The compose lab cannot demonstrate the second probe: every container shares
one network, so anything in it reaches the gateway, and the bypass alert
would fire. That boundary is one the lab does not hold, which is part of why
it is a lab.

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

Before deploying any of this, read the [production
checklist](production.md).
