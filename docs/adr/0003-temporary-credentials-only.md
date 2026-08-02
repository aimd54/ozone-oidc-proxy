# ADR-0003: Temporary credentials only, minted by token exchange

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

Clients need credentials the proxy can verify. Three shapes were available:
long-lived keypairs issued per user, the user's OIDC password used as a secret,
or short-lived credentials minted from a token.

The second is impossible rather than merely unwise: no identity provider
reveals passwords, and SigV4 sends an HMAC rather than the secret, so the proxy
would have nothing to compare against.

Long-lived keypairs are possible but bring a lifecycle nobody wants: storage,
rotation, revocation, and an audit story for keys that outlive the sessions
that created them.

The clients that matter already know how to do this. The aws CLI, boto3, the
Java SDK and s3a, minio-go, and mc all implement `AssumeRoleWithWebIdentity`
including automatic refresh.

## Decision

We will mint **only temporary credentials**, through an AWS-compatible
`AssumeRoleWithWebIdentity` exchange, with the lifetime capped by the
presenting token's own expiry.

Humans get the same credentials through paths that suit them: a device-flow
login that keeps a token file fresh, and a browser portal behind oauth2-proxy.
The resource-owner password grant stays a scripted convenience in the lab stack
and is not a supported path.

Durable long-lived keypairs are **not supported**. If a legacy tool ever needs
one, the portal's service-account pattern is the escape hatch.

## Consequences

- Standard tooling works with no plugin and no wrapper, because the exchange is
  the one those SDKs already implement. Refresh is theirs to handle.
- A leaked credential expires on its own, and the blast radius is bounded by
  the token that produced it rather than by whenever someone notices.
- Credentials cannot outlive the session that created them, which is the point,
  but it does mean an unattended job needs a token source rather than a key in
  a file.
- The credential store becomes load-bearing: verification needs the minted
  secret, so the store is on the data path. That is what ADR-0004 addresses.
- Revisit if a class of client appears that cannot perform the exchange and
  cannot use the portal. The answer would still not be unbounded keys.
