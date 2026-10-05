# Components and data flows

## Components

| Component | Runs | Holds | Role |
| --------------------------- | ---------------------------- | ------------------------------------------ | -------------------------------------------- |
| Signer replica (`openstack-spire-issuer service start`) | Beside the control plane, two or more | Its signing keys (in memory), its OpenStack service credentials, its TLS key | Authenticates Nova, verifies instances, signs tokens, publishes its public keys |
| JWKS aggregator (`openstack-spire-issuer jwks aggregate`) | Optional, two or more | Its TLS key | Merges the replicas' public keys for SPIRE Server |
| Server plugin (`openstack-server-plugin`) | Inside every SPIRE Server | Its replay cache, the fetched public keys | Verifies tokens, gives agents their SPIFFE ID and selectors |
| Agent plugin (`openstack-agent-plugin`) | Inside SPIRE Agent, on every instance | Nothing secret | Reads the token from the metadata service and presents it |

The issuer and both plugins share one definition of the token, its limits and its validation rules, compiled into all three. They cannot disagree on the contract.

## External dependencies

- **Nova's metadata service** (`nova-api-metadata`, reached through Neutron's metadata proxy) identifies the instance reading its metadata, and calls the issuer as a *DynamicJSON vendordata target*.
- **Keystone** validates the tokens Nova presents to the issuer, and answers the issuer's project lookups.
- **The Nova API** answers the issuer's instance lookups.
- **SPIRE Server and SPIRE Agent**, unchanged: the plugins use SPIRE's plugin interface.

## Data flows and trust boundaries

Each flow crosses a trust boundary, where data passes from one party's control to another's. The *Threat model* chapter analyses each one.

![Data flows and trust boundaries](trust-boundaries.pdf){width=85%}

| Boundary | From, to | What crosses | How it is protected |
| ------ | ------------------------------------ | ------------------------------------ | ------------------------------------------------ |
| TB1 | Instance to Nova's metadata service | `vendor_data2.json`, with the token | Nothing from the instance: Neutron identifies it by its port |
| TB2 | `nova-api-metadata` to the signers' `/attest` | Nova's claims about the instance, its metadata and user data | Nova's Keystone token, server TLS, optionally the source address and a client certificate |
| TB3 | Signers to Keystone and the Nova API | Token validations, project and server records | Service credentials, verified TLS |
| TB4 | Replicas and aggregators to a replica's `/jwks/local.json` | Public keys | Verified TLS, with a pinned CA |
| TB5 | Server plugin to the merged JWK Set | Public keys | Verified TLS, with a pinned CA |
| TB6 | SPIRE Agent to SPIRE Server | The token | SPIRE's own TLS |
| TB7 | Release pipeline to hosts and images | Binaries, packages | Signed checksums and packages |
| TB8 | Signers to a metrics collector | Counts, latencies, key and peer state | Loopback by default; TLS with client certificates, or verified TLS to the collector |

## Deployment topologies

SPIRE Server needs the public keys of every replica, merged. Either the replicas do it themselves, each one fetching its peers' keys and serving them merged with its own (*peered signers*), or separate aggregators do it (*signers plus aggregators*), for when SPIRE Server must not reach the network the signers sit on. Both serve the same merged set, with the same rules.

![Peered signers](topology-peered.pdf){width=55%}

![Signers plus aggregators](topology-aggregated.pdf){width=50%}
