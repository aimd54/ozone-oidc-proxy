# Contributing to ozone-oidc-proxy

Thank you for your interest in contributing! The conventions below keep
the project easy to review, audit, and maintain.

This proxy is a security boundary: it decides who may act as whom against a
storage cluster that performs no authentication of its own. Review here leans
conservative, and changes touching authentication, signature verification, or
identity injection are held to the threat model in
[docs/architecture.md](docs/architecture.md).

## Developer Certificate of Origin (DCO)

All commits must be signed off, certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer matching
your git identity. Unsigned commits cannot be merged.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<optional scope>): <imperative subject>

<body: what and why, wrapped at ~72 columns>
```

Common types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`.
Scopes mirror the package tree, e.g. `feat(store): ...`, `fix(sigv4): ...`.
Keep commits small and self-contained; every commit must build and pass tests.

## Development setup

Requirements: Go (see `go.mod`), `make`,
[golangci-lint](https://golangci-lint.run/) v2, and Docker with compose v2 for
the end-to-end suite (~6 GB RAM for the stack). The aws CLI is run
containerized by the suite, so it is not needed on the host.

```sh
make build      # bin/: ozone-oidc-proxy, ozone-login, credential-portal
make check      # gofmt, go vet, golangci-lint, tidy check, race-enabled unit tests
make demo       # up + init + one real S3 round-trip, the fastest sanity check
make up         # start the compose stack (Keycloak + Ozone + proxy)
make init       # provision the Keycloak realm/users and the /s3v volume ACLs
make e2e        # end-to-end suite against that stack
make lint-docs  # markdownlint over the docs (requires Node)
make help       # list all targets, including the optional overlays
```

Run `make check` before every commit; CI runs the same gates.

## Testing policy

New functionality comes with new tests, and bug fixes come with a test that
fails before the fix and passes after it. A pull request that adds behaviour
without covering it will be asked for tests before review continues.

What that means in practice:

- Unit tests next to the code, in the same package for unexported behaviour.
- **Time-dependent code takes an injectable clock** (`WithClock` / `Now`
  fields) and is tested at the boundaries, expiry, clock skew, presigned
  validity windows, rather than with `time.Sleep`.
- **Signature work is pinned to external references**: the SigV4 package is
  checked against the official AWS test-suite vector, the AWS documentation's
  presigned example, and a round-trip against the real `aws-sdk-go-v2` signer.
  Do not replace those with self-generated fixtures.
- Anything on the authentication path gets a **negative** test: a tampered
  signature, a wrong session token, an expired credential, a foreign issuer.
  A test that only proves the happy path does not cover this code.
- Changes to lane dispatch, forwarding or ACL behaviour get a case in the
  `make e2e` suite, which runs against a real Ozone cluster. Assert the state
  you expect (bucket owner, S3 error code), not merely that a command exited 0.
- Live verification results belong in [docs/verification.md](docs/verification.md)
  with the date and what was run.

## Code conventions

- Go code is formatted with `gofmt` and `goimports`
  (local prefix `github.com/aimd54/ozone-oidc-proxy`).
- Every source file starts with the SPDX header:

  ```go
  // Copyright The ozone-oidc-proxy Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- Implementation lives under `internal/`; there is no exported Go API.
- **Never log secrets.** Usernames, access key IDs, issuers and error codes
  are fine; secret keys, session tokens and raw JWTs are not, in logs or in
  error strings.
- Errors that cross package boundaries are wrapped sentinel errors
  (`oidc.ErrTokenExpired`, `sigv4.ErrSignatureMismatch`, ...) matched with
  `errors.Is`, so the HTTP layer can map them to the right S3 error code.
- Design decisions live in [docs/architecture.md](docs/architecture.md), which
  the code cross-references by heading rather than by section number, so a
  reference survives an edit to the document. A significant design change
  updates that document in the same pull request; a decision that reverses an
  earlier one gets a new record in [docs/adr/](docs/adr/) instead of an edit to
  the old one.

## Filing issues and pull requests

- Use the issue templates for bugs and feature requests.
- PRs should reference the issue they address and describe testing performed.
- **Client compatibility is a contract**: the STS exchange and the SigV4 data
  path must keep working unmodified for the AWS CLI, boto3, the Java SDK/s3a,
  minio-go and mc (see the client smoke tests in the e2e suite). Changes that
  break a standard client will not be accepted.
