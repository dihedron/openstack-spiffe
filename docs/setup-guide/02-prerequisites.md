# Prerequisites

## Software

- **OpenStack** with Nova's DynamicJSON vendordata (any supported release) and Keystone v3. The issuer uses the compute API microversion 2.47 or later.
- **SPIRE** Server and Agent of the major version the plugins are built against (see the release notes), and at least its minor version.
- **Linux on x86-64 or arm64** for every component. Releases provide `deb` packages (Debian, Ubuntu) and `rpm` packages (RHEL and its derivatives, Fedora), plus plain archives.
- **systemd** on the issuer hosts: the packages install systemd units.
- **nftables** in the instance images, for the guest hardening rule (see *Installing the agent plugin*).

### Which build to install

Every amd64 release comes in three builds of each package and archive:

- the **baseline** build (`_amd64` packages, `x86_64` archives), which runs on any x86-64 CPU: install it unless you know your CPUs;
- two optimized builds, suffixed `v2` and `v3`, for CPUs of the x86-64-v2 level (roughly 2009 onwards) and x86-64-v3 level (with AVX2, roughly 2015 onwards).

The optimized builds behave identically and are only faster where the compiler can use newer instructions; on an older CPU they fail at startup. The agent plugin runs inside every instance, whose virtual CPU model the hypervisor decides: use its baseline build unless every hypervisor exposes an x86-64-v3 CPU model to its guests.

## Hosts

| Role | How many | Notes |
| ------------------ | ------------ | ---------------------------------------------------------------------- |
| Signer replica | 2 or more | Share nothing; put them behind a load balancer for Nova. Their needs are modest: the process uses a few tens of MB of memory, and the work per token is one signature plus, at most, a Keystone and a Nova lookup, both cached. Size them for your peak boot rate, and watch the metrics (`attest_duration_seconds`). Swap should be disabled or encrypted, as defence in depth (the signer locks its memory anyway) |
| JWKS aggregator | 0, or 2 or more | Only in the *signers plus aggregator* topology (see *Installing the issuer*) |
| SPIRE Server | as you run it | The server plugin runs inside it |

## Network paths

Every connection is HTTPS, except the instances' access to the metadata service. Open these paths, and only these:

| From | To | Port (default) | Purpose |
| ---------------------- | ---------------------- | -------------- | ------------------------------------------ |
| `nova-api-metadata` hosts | signer replicas (or their load balancer) | 8443 | `POST /attest`: token requests |
| signer replicas | Keystone, Nova API | as in the catalog | Token validation, instance verification |
| signer replicas | the other signer replicas | 8443 | `GET /jwks/local.json` (peered topology) |
| JWKS aggregators | signer replicas | 8443 | `GET /jwks/local.json` (aggregator topology) |
| SPIRE Server | signers' or aggregators' load balancer | 8443 or 8444 | `GET /.well-known/jwks.json`: the verification keys |
| instances | metadata service `169.254.169.254` | 80 | `vendor_data2.json` (local to the hypervisor) |
| SPIRE Agent | SPIRE Server | 8081 | Node attestation, as usual for SPIRE |
| load balancers and monitoring | signers, aggregators | 8443, 8444 | `/liveness`, `/readiness` |

The issuer can restrict `/attest` to the `nova-api-metadata` hosts by address and by client certificate. Plan for both (see *Installing the issuer*).

## Names and certificates

Prepare, from the CA you use for internal services:

- a **server certificate for each signer replica**, valid for the names Nova and the other replicas use to reach it (the load balancer's name included, if the load balancer passes TLS through);
- a **server certificate for each aggregator**, if you use them;
- a **client certificate for Nova**, which the `nova-api-metadata` hosts present to `/attest`, with the *client authentication* extended key usage;
- the **CA bundles** that verify each of them, distributed to their clients: Nova (to verify the signers), the signers (to verify each other and Nova's client certificate), the aggregators (to verify the signers) and SPIRE Server (to verify the JWK Set's endpoint).

Pinning these internal CAs, rather than trusting the public ones, matters: whoever can impersonate the JWK Set's endpoint could add a key of their own to it. Each component has a setting for its CA bundle, and its configuration check warns when it is not set.

## Time

Tokens are valid for 5 minutes, and SPIRE Server tolerates a clock difference of 30 seconds by default. Keep the signers' and SPIRE Servers' clocks synchronized (NTP or chrony).
