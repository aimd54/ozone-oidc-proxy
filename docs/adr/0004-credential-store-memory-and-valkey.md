# ADR-0004: Two credential stores, in-memory and valkey

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

Verifying a SigV4 request means recomputing the signature from the secret that
was minted for that access key, so the store sits directly on the data path. It
is read on every signed request.

A single process can keep credentials in memory, which is fast and has no
dependency. That stops working the moment there is a second replica: a client
that exchanged its token at one replica and signs a request that reaches
another gets a verification failure, because the second replica never saw the
secret.

The stored value is a secret capable of authenticating as a user until it
expires.

## Decision

We will ship **two implementations behind one interface**: an in-memory store
with a sweeper for single-replica deployments, and a valkey-backed store shared
across replicas.

Values in the shared store are **encrypted with AES-256-GCM** before they
leave the process, with the key supplied through the environment. A read of the
backing store yields ciphertext, and the record is bound to its access key so a
ciphertext cannot be replayed onto another one.

Running more than one replica **requires** the shared store; the choice is not
left implicit.

## Consequences

- A small deployment needs no extra infrastructure, and a larger one scales
  horizontally without sticky sessions or a shared filesystem.
- Someone who reads the valkey keyspace, from a backup or a compromised
  instance, gets ciphertext rather than usable credentials. The encryption key
  becomes the thing to protect, and rotating it invalidates every live
  credential, which the production checklist says explicitly.
- Revocation becomes a store delete, which is why an administrative endpoint
  can exist at all and why deleting through one replica takes effect on the
  others.
- The store is on the hot path, so its latency is the proxy's latency. That is
  why verification overhead is measured rather than assumed.
- Revisit if a deployment needs credentials to survive a full valkey outage.
  That would mean durable storage, and a different set of trade-offs about what
  happens to a secret at rest.
