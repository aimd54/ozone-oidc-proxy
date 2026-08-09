# Compose lab

A self-contained stack: Keycloak, a single-node Apache Ozone, and the proxy.
Nothing here touches an existing cluster, so it is safe to run first and
read [Install](../../docs/install.md) afterwards.

## What it costs to start

A first run pulls Keycloak and three `apache/ozone` containers, several
gigabytes in total, and builds two images locally. Expect a few minutes
before anything answers. The running stack wants about 6 GB of RAM.

## Requirements

- Docker, with Compose v2
- GNU make, `curl`, `jq`
- Go, for `make build`, which produces `ozone-login` and the credential
  portal

The proxy itself is built inside its image and the aws CLI runs
containerized, so neither is needed on the host.

## Start it

```bash
make demo    # build + up + init + a real S3 round-trip through the proxy
```

That is the shortest path from a clean checkout to a working S3 call. It
signs in as alice, exchanges her token for temporary credentials, uses them
like any other S3 credentials, and then confirms with `ozone sh` that Ozone
recorded alice as the bucket's owner.

The steps it chains, if you would rather run them yourself:

```bash
make build   # bin/: ozone-oidc-proxy, ozone-login, credential-portal
make up      # build the proxy image, start Keycloak + Ozone + proxy
make init    # provision Keycloak (realm ozone, client ozone-s3, alice/bob)
             # and grant alice/bob rwlc on the /s3v volume
```

## Endpoints

| URL | What |
| --- | --- |
| `http://localhost:9000` | S3 **and** STS, the only public data endpoint |
| `http://127.0.0.1:9090` | admin: `/healthz`, `/readyz`, `/metrics`, `DELETE /credentials/{akid}`, **localhost only** |
| `http://localhost:8080` | Keycloak (admin/admin123) |

The Ozone S3 Gateway is intentionally **not** published. With
`ozone.security.enabled=false`, anyone who can reach it can impersonate
anyone, so the proxy has to be the only path. In production that is a
network policy; here it is simply an unpublished port.

The admin port is security-sensitive and unauthenticated. Besides metrics it
serves the state-changing revocation endpoint, which is why it is bound to
`127.0.0.1` here and must never be exposed on a shared network.

## Browser sign-in needs a hosts entry

Only the credential portal, the device-flow sign-in page and `ozone-login`
need this. `make demo` and the acceptance suite do not: the suite reaches
the issuer with `curl --resolve`, and the demo talks to it on localhost.

The lab pins the issuer hostname and tokens must carry it exactly, so the
host has to resolve `keycloak` to the stack:

```bash
echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
make check-hosts    # confirms it, and says what to do if not
```

Run `make check-hosts` **after** the stack is up. It answers by asking the
issuer, so with nothing running it can only tell you to start the stack
first.

## The acceptance suite

```bash
make e2e
```

The full matrix: every lane, every client, the ACL cases, and a negative
case for each authentication path. It needs the stack up and `make init`
done.

## Overlays

Each one adds services to the running stack. They compose, so several can be
up at once.

### Credential portal

```bash
make portal-up   # oauth2-proxy + portal at http://localhost:4180
```

A browser page that mints credentials for the signed-in user and renders
them as shell exports or an `~/.aws/credentials` profile. Needs the hosts
entry above.

### High availability

```bash
make ha-up     # shared valkey store + a second replica (:9001/:9091, resign mode)
make e2e       # the suite adds the HA, valkey, resign and revocation matrix
```

Replica A serves `:9000/:9090` in `rewrite` mode, replica B `:9001/:9091` in
`resign` mode. Both share the valkey store, so a credential minted on either
is honored on the other, and a revocation on one propagates to the other.

### Monitoring

```bash
make monitor-up   # Prometheus + Grafana at http://localhost:3000 (anonymous viewer)
```

Grafana auto-loads the **Ozone OIDC Proxy** dashboard from
[`dashboards/`](../../dashboards): traffic and verification-latency
percentiles with p99 against a 1 ms line, lane split, verification outcomes,
upstream status families, active credentials, and revocations. Drive traffic
with `make e2e` or `make loadtest` to populate it.

### TLS edge

```bash
make edge-up   # HAProxy terminating TLS at https://localhost:8443 (self-signed)
```

Models the production ingress: HAProxy terminates TLS and forwards to the
proxy with the SigV4-signed Host header untouched. Its healthcheck is the
anonymous-probe boundary check, which expects the strict 403. With the
overlay up, `make e2e` adds a TLS section.

### Lakehouse: Nessie and Iceberg

```bash
make lakehouse-up      # Nessie (Iceberg REST) + Postgres + Jupyter
make lakehouse-smoke   # health checks
```

A worked example of a service account rather than a person. Nessie reaches
Ozone S3 through the proxy with **no static S3 secret**, exchanging a
client-credentials token for temporary credentials like any other client.

Jupyter, at <http://localhost:8890>, ships a runnable notebook covering
every auth flow and ending with an Iceberg table written over these
credentials.

### Load test

```bash
make loadtest   # verification-overhead p99 gate
```

Drives signed traffic and fails if the proxy's own verification p99 crosses
1 ms.

## Tear down

```bash
make down    # stop the stack, keep volumes
make clean   # stop the stack and delete volumes, all overlays included
```
