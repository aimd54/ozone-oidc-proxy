# Kubernetes example

A whole working stack on one machine: Apache Ozone from its official Helm
chart, Keycloak, and this proxy in front of them, on a kind cluster.

```bash
bash ./up.sh          # build it and run the checks
bash ./up.sh down     # delete the cluster
```

Needs kind, kubectl, helm, docker and python3, plus about 4 GB of free
memory. The first run pulls the Ozone image, which is around 1.5 GB.

Where the [compose lab](../compose/README.md) shows the proxy working, this
shows it working the way it would be deployed: two Helm releases, a
NetworkPolicy holding the trust boundary, and nothing hand-wired.

## What it proves

Every check asserts a positive state rather than that a command exited 0.

| Check | Why it matters |
| --- | --- |
| Keycloak issues a JWT for alice | the sign-in works at all |
| the token carries `aud=ozone-s3` | audience is enforced, and providers rarely emit a useful one by default |
| STS mints temporary credentials | the token exchange works over the cluster network |
| put and get round-trip byte-identical | the data path works, not just the control plane |
| **the bucket owner is `alice`** | Ozone attributed the request to the OIDC user, which is the whole design |
| the object is in Ozone at 22 bytes | it really landed, rather than a 200 with nothing written |
| an unauthenticated request gets 403 | strict mode holds |
| **a bypass pod cannot reach the S3 Gateway** | the NetworkPolicy is enforced, not merely rendered |

The last one is the one to care about. Ozone runs with
`ozone.security.enabled=false`, so anything that can reach the S3 Gateway can
act as any user. Deleting the lockdown policy and re-running the probe takes
it from `HTTP 000` to `HTTP 403`: blocked becomes reachable. That difference
is the security model.

## The pieces

| File | What it is |
| --- | --- |
| `ozone-values.yaml` | values for the official Ozone chart, sized for a laptop |
| `keycloak-realm.json` | realm imported at startup: client, audience mapper, alice and bob |
| `keycloak.yaml` | Keycloak in development mode, one manifest |
| `proxy-values.yaml` | values for this project's chart |
| `up.sh` | builds it and runs the checks |

Only three settings in `ozone-values.yaml` actually matter to the proxy:

```yaml
ozone.security.enabled     = false   # Ozone authenticates nobody
ozone.acl.enabled          = true    # but still evaluates ACLs
ozone.acl.authorizer.class = ...OzoneNativeAuthorizer
```

Everything else there only makes a single-node cluster fit on one machine.

## Two things worth knowing before you copy this

**The Ozone chart cannot be scaled below three Datanodes.** Version 0.3.0
pins `hdds.scm.safemode.min.datanode` to `"3"` in `_helpers.tpl`, with no
value to override it and no reference to `datanode.replicas`. Run one
Datanode and SCM never leaves safe mode, so `allocateBlock` fails and every
write hangs until the client gives up. The upload reports its bytes and then
the object is not there, which reads as a proxy fault and is not one.
`up.sh` forces the exit with `ozone admin safemode exit`, which is fine for
an example and is not something to do to a real cluster. Three or more
Datanodes need none of this.

**The proxy's egress policy has to admit your identity provider.** The chart
defaults to any peer on port 443, which fits a provider reached over TLS off
the cluster. Keycloak here is in-cluster and plain HTTP on 8080, so both the
peer and the port are set explicitly in `proxy-values.yaml`. Without them
every exchange returns `IDPCommunicationError`, which is the policy working
rather than failing. The example scopes egress to the Keycloak pod, which is
tighter than the chart's default.

## Not a production shape

Keycloak runs in development mode with an in-memory database and no TLS. The
proxy runs one replica on the in-memory credential store, so credentials do
not survive a restart and more than one replica would need the valkey store.
There is no ingress and no TLS termination.

[docs/production.md](../../docs/production.md) is the checklist for a real
deployment, and [docs/install.md](../../docs/install.md) covers pointing the
proxy at a cluster you already run.
