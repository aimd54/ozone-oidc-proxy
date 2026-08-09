# Configuration

One YAML file, passed with the `-config` flag or named by `OZPX_CONFIG`.
Every key shown is the default except the issuer list, which has none.

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
  - name: my-idp
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

## Issuers

The `audiences` list is the setting most likely to need work on the provider
side: many providers do not put a useful audience in access tokens by
default. An issuer with an empty `audiences` is rejected at startup, and a
token whose `aud` does not intersect the list is rejected at the door.

`issuer` must equal the token's `iss` claim byte for byte. Issuer selection
is an exact match, not a prefix or a pattern.

Several issuers can run side by side, each with its own audiences and
username claim. [Install](install.md) covers what a provider has to do.

## Forward mode

`upstream.forward_mode` picks how the request reaches Ozone.

`rewrite`, the default, swaps the access key ID in the incoming
`Authorization` header for the OIDC username and leaves the rest. That is
the leanest path, and all a stock Ozone needs.

`resign` computes a fresh, fully valid SigV4 header toward Ozone, signed
over the upstream host. It costs one extra signature and is robust to a
future upstream that parses signatures strictly.

Note that `resign` signs with a public constant, so it buys parser
robustness, **not** upstream authentication. A secure-mode Ozone would need
a real shared secret. The reasoning is in
[architecture.md](architecture.md).

## Credential store

`credential_store.type` is `memory` (single replica, with a TTL sweeper) or
`valkey` (shared across replicas, and required for more than one).

For `valkey`, values are AES-256-GCM encrypted with a 32-byte key the proxy
reads from the environment variable named by `key_env`. The key is base64
and **never** appears in the YAML or in logs:

```bash
export OZPX_STORE_KEY=$(head -c 32 /dev/urandom | base64)
```

Each stored value is bound to its access key ID, so a value lifted from the
store cannot be replayed under a different one.

## Strict mode

`data_path.strict` defaults to true and should stay that way outside a lab.
With it on, anything that is not a valid bearer token or a verified
temporary-credential SigV4 request is refused with S3-shaped 403 XML.

Turning it off forwards unauthenticated requests untouched, which hands
Ozone whatever identity it infers on its own. That is a security bypass
rather than a feature, and the reasoning is recorded in
[ADR-0005](adr/0005-strict-authentication-by-default.md).
