# Install

Pointing the proxy at an Ozone cluster and an identity provider you already
run. The [compose lab](../examples/compose/README.md) brings its own of
both, and is the safer place to start.

## What your Ozone cluster must look like

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
with the proxy as the only door. The Helm chart ships NetworkPolicies for
exactly that, and [production.md](production.md) is the checklist.

Each user needs grants on the S3 volume. `rl` is the floor for any access.
`rwlc` additionally lets them create their own buckets through the S3 API,
because the Ozone Manager checks WRITE on the volume for `CreateBucket`:

```bash
ozone sh volume addacl -a user:alice:rwlc /s3v
```

## What your identity provider must do

Any standards-compliant OIDC provider works: Keycloak, Okta, Entra ID,
Auth0, Google, Dex, and others. The proxy uses OIDC discovery and plain
JWKS, and there is no provider-specific code in it. What it needs from
yours:

- **A client your users authenticate against.** Its type depends on the
  flow you offer them, per the two conditional requirements below.
- **An `aud` claim matching your configured `audiences`.** This is mandatory
  and enforced: an issuer with empty `audiences` is rejected at startup, and
  a token whose `aud` does not intersect is rejected at the door. Many
  providers do not put a useful audience in access tokens by default, so
  this is the setting most likely to need changing.
- **A stable username claim.** Configured per issuer as `username_claim`,
  falling back to `sub`. Its value becomes the Ozone identity, so it must be
  stable and must satisfy `username_policy.pattern`, which excludes `/` and
  `$` by design.
- **RS256 or ES256 signing.** `none` and the `HS*` family are rejected at
  both config and token level.
- **An access-token lifespan long enough to be useful.** The temporary
  credential's TTL is capped by the JWT's own `exp`, so a five-minute
  default caps every credential at five minutes. Raise it on the client you
  dedicate to this audience rather than realm-wide, or use `ozone-login`,
  which refreshes.
- **The OAuth 2.0 device authorization grant**, on a public client, *if* you
  want people to use `ozone-login`.
- **A confidential client with a registered redirect URI**, *if* you want
  the browser credential portal.

Several providers can run side by side, each with its own audiences and
username claim. The acceptance suite exercises two issuers of different
shapes rather than two of the same, and checks that identities from one
cannot reach the other's buckets.

### Worked example: Keycloak

Keycloak is the provider the lab stack provisions, and the one these
requirements have been exercised against live.

Its default access tokens carry `aud=account`, which the proxy rejects. Add
an **audience mapper** to the client for this audience so tokens carry
`aud=ozone-s3`. Token lifetime is `Access Token Lifespan` on that client
rather than realm-wide.

The compose init service does all of it non-interactively, in
[`examples/compose/init/init.py`](../examples/compose/init/init.py): the
audience mapper, the device grant on the public client, and the confidential
client the credential portal needs. It is readable as a worked configuration
even if you run a different provider.

## Minimal configuration

One YAML file, passed with `-config` or named by `OZPX_CONFIG`:

```yaml
upstream:
  s3_endpoint: http://ozone-s3g:9878   # your S3 Gateway, reachable only by the proxy
issuers:
  - name: my-idp
    issuer: https://idp.example.com    # must equal the token's `iss`, byte for byte
    audiences: [ozone-s3]              # must match an `aud` your provider emits
    username_claim: preferred_username
```

Everything else has a working default. The full reference is in
[configuration.md](configuration.md).

## On Kubernetes

[`charts/ozone-oidc-proxy/`](../charts/ozone-oidc-proxy) is a deployable
chart: Deployment, Service, ConfigMap, an optional store-key Secret and
in-chart valkey, and the NetworkPolicies that make the network the trust
boundary.

```bash
cp charts/ozone-oidc-proxy/values-example.yaml my-values.yaml
$EDITOR my-values.yaml      # issuer, s3_endpoint, s3gPodSelector, store key
helm install ozpx charts/ozone-oidc-proxy -f my-values.yaml
```

Use a values file rather than `--set`. `config.issuers` is a list of maps
and `--set` cannot express it. The chart ships **no default issuer** on
purpose, so a release installed without one fails closed at startup with
"at least one issuer must be configured" instead of starting green and
rejecting every token.

Set `networkPolicy.s3gPodSelector` to your S3 Gateway's pod labels. Until
you do, the lockdown policy is not rendered at all and the gateway stays
reachable from the rest of the namespace, which in unsecured mode means
anyone in that namespace can impersonate anyone. Verify your CNI actually
enforces NetworkPolicy; not all do.

`values-example.yaml` covers the multi-replica shape: two replicas on a
shared valkey store, the store key from an existing Secret, the S3 Gateway
lockdown selector, and egress limited to your provider.

```bash
./charts/smoke.sh    # lint + install on a throwaway kind cluster, then assert
```

## Next

- [clients.md](clients.md) for pointing tools at the proxy.
- [operations.md](operations.md) for revocation, metrics and replicas.
- [production.md](production.md) before running it anywhere real.
