# Operating model

This guide is for the people who run *openstack-spiffe* day to day and answer its alerts. It assumes the solution is installed as the *Setup Guide* describes. *Architecture and Design* explains why it behaves as it does.

## What runs where

| Process | Where | Unit or host process |
| ---------------------- | ---------------------------------------- | ------------------------------------------------- |
| Signer replica | Two or more hosts beside the control plane, behind a load balancer | `openstack-spire-issuer.service` |
| JWKS aggregator (optional) | Two or more hosts, behind their own load balancer | `openstack-spire-issuer-aggregator.service` |
| Server plugin | Inside every SPIRE Server | Started by SPIRE Server |
| Agent plugin | Inside SPIRE Agent, on every instance | Started by SPIRE Agent |

## State, and what a restart does

Nothing the solution holds survives a restart, by design:

- **A signer replica** keeps its signing keys only in memory. A restart generates a new key, which the replica publishes for `publish_ahead` (2 minutes) before signing with it. During that time it reports *not ready*, and its load balancer sends Nova to the other replicas. The old key is gone: the merged key sets drop it at their next fetch. A token the replica signed just before the restart, and not yet presented, is then refused, and its agent attests again with a fresh token. Restart replicas one at a time.
- **A JWKS aggregator** holds nothing but its configuration. A restarted aggregator fetches every replica at once and is ready as soon as one answers.
- **The server plugin** keeps its replay cache in memory. After a SPIRE Server restart, it refuses every token issued before it started, so agents attesting right then are refused once, and succeed on their next attempt with a fresh token.
- **The agent plugin** holds only the ID of the last token it presented.

Nothing needs backing up, apart from the configuration files, certificates and credentials.

## Dependencies, and how failures show

Every component fails closed: an unavailable dependency costs attestations, never security.

| When this is unavailable | Then |
| ---------------------------- | ------------------------------------------------------------------- |
| Keystone | Replicas refuse requests whose Nova token is not cached (`503`), and report not ready |
| The Nova API | Replicas refuse requests for instances not cached (`503`), and report not ready |
| A signer replica | The load balancer sends Nova to the others; its peers and aggregators keep its last keys for 5 minutes |
| All signer replicas | Nova serves instances' metadata without a token; instances booting then cannot attest until the issuers return |
| The merged key set, for SPIRE Server | The server plugin keeps its last keys for 5 minutes, then refuses every attestation |
| Syslog | Audit records are dropped and counted; they remain in the regular log |
| A metrics collector | Exports fail and are logged once; nothing else is affected |

Agents already attested keep their identities: only new attestations and re-attestations need the issuer. That is why the issuers' availability matters most when many instances boot at once.

## Health endpoints

Every signer replica and aggregator serves, over HTTPS on its service port:

- `/liveness`: `200` as long as the process serves.
- `/readiness`: `200` when every check passed in its latest run, `503` otherwise. The checks run in the background every 5 seconds, each within 2 seconds, so probes never wait on a dependency. The body lists each check as `ok`, `failing` or `pending` (before its first run), without details; a check's error is logged when it starts failing and when it recovers.

| Check | On | Fails when |
| --------------- | -------------- | -------------------------------------------------------------------- |
| `key_store` | Signer | The replica has no active key yet (for `publish_ahead` after a start), or cannot sign |
| `keystone` | Signer | Keystone cannot be reached, or refuses the replica's service credentials |
| `nova` | Signer, with instance verification | The Nova API cannot be reached |
| `replicas` | Aggregator | No replica was fetched successfully within `stale_key_retention` |

Peers are deliberately not a readiness check: a replica's merged set always holds its own keys.
