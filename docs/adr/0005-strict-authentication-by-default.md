# ADR-0005: Refuse anything unauthenticated, by default

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

The proxy exists because the gateway behind it authenticates nobody. Whatever
the proxy lets through reaches a system that will attribute it to whichever
identity the request claims.

A permissive fallback is tempting during bring-up, when a client is
misconfigured and an anonymous path would let work continue. The cost is that
the fallback is indistinguishable, from the gateway's point of view, from the
attack this project exists to prevent.

## Decision

Every data-path request will be **either a valid bearer token or a
temporary-credential SigV4 request the proxy verified**. Anything else is
refused with S3-shaped 403 XML, so clients see a failure they already know how
to report.

Signature comparison is constant-time, and verification recomputes the
signature from the wire rather than trusting anything the client asserts about
it.

A permissive mode exists for labs and is off by default. It is a debugging
affordance, not a deployment option.

## Consequences

- There is no configuration in which an unauthenticated request reaches Ozone
  through the proxy. Turning that off is a deliberate act with an obvious name.
- Misconfigured clients fail immediately and visibly rather than working by
  accident and silently acting as nobody, which is the failure that would be
  discovered last.
- Refusals are S3-shaped, so existing tooling surfaces them as access denied
  rather than as a transport error.
- The strictness is only as good as the network policy around it. An
  unauthenticated request that reaches the gateway directly bypasses all of
  this, which is ADR-0001's consequence and the production checklist's first
  item.
- Revisit nothing here lightly. If a future lane needs different treatment, it
  gets its own verification path rather than a relaxation of this one.
