# Documentation

| Document | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | How the four lanes fit together, and the identity injection the design rests on |
| [install.md](install.md) | Cluster prerequisites, the identity provider checklist, minimal config, and Helm |
| [configuration.md](configuration.md) | Every configuration key, with its default |
| [clients.md](clients.md) | Pointing aws, boto3, mc, s3a, curl and presigned URLs at the proxy |
| [operations.md](operations.md) | Revocation, the admin listener, metrics, and running replicas |
| [production.md](production.md) | The production checklist, what has to be protected, and the Ranger note |
| [verification.md](verification.md) | What has been exercised against a running cluster, with dates and image digests |
| [upstream.md](upstream.md) | The upstream Ozone OIDC and STS work, and what would make this project unnecessary |
| [roadmap.md](roadmap.md) | Working, verified, and deliberately not built |
| [adr/](adr/README.md) | The decisions and the reasoning behind them |

The [compose lab](../examples/compose/README.md) has its own guide, covering
the stack it starts and the six overlays that extend it.
