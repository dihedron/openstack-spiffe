# OpenStack SPIRE node attestation — STRIDE threat model

Oct 4, 2026 (revised Oct 5, 2026: metrics) · @Andrea Funtò

## Overview

This document is the STRIDE threat model of the OpenStack node attestation solution: the metadata JWT issuer (`openstack-spire-issuer`, see `openstack-spire-issuer.md`, and its metrics, `openstack-spire-issuer-metrics.md`), the `openstack_iid` SPIRE agent and server plugins (see `openstack-spire-plugins.md`), the shared contract in `pkg/iid`, and the way all of them are built, packaged and released.

It lists the assets, the actors, the trust boundaries and the assumptions the design rests on. It then lists every threat identified, each with its status and with the control that addresses it. Threat IDs (`S-1`, `T-3`, ...) are stable: the companion specs cite them next to the requirements that mitigate them, so that every control can be traced back to its threat and back again.

**Scope**: the issuer (signer replicas, peer aggregation, JWKS aggregator), both plugins, `pkg/iid`, the systemd units and packages, and the release pipeline.

**Out of scope**, though their security properties are listed as assumptions below:
- Nova, Neutron and Keystone themselves.
- The internals of SPIRE Server and SPIRE Agent.
- Vault (not implemented yet).
- Registration entry automation.

## Status legend

| Status | Meaning |
| --- | --- |
| **M** | Mitigated by a control already specified (and implemented) in the companion specs. |
| **P** | Partially mitigated: a control exists, but it leaves a gap that a revision of the companion specs closes or narrows. |
| **U** | Unmitigated before this revision: the companion specs now carry a planned control, marked with the threat ID. |
| **A** | Accepted residual risk: inherent to the design, or out of this solution's reach; documented with its rationale. |

A threat marked **P** or **U** lists the revised spec section that addresses it. The planned controls were implemented on Oct 4 and 5, 2026; the residual status after them is given in the last column.

## Assets

| Asset | Why it matters |
| --- | --- |
| Signing private keys (per replica, in memory) | Whoever holds one can mint a valid token for any instance: the highest-value asset. |
| Issued JWTs | Bearer credentials. During the acceptance window (at most 7 minutes) a token yields the agent identity of its instance. |
| Integrity of the JWK Set (local, merged, aggregated) | A key added to it is as good as a stolen signing key. |
| Agent SVIDs, and the workload SVIDs registered under them | The end product. A node identity gives access to every workload identity parented on it. |
| Nova's `[vendordata_dynamic_auth]` credentials | Authorize calls to `/attest`, so they let their holder mint tokens for any existing instance. |
| The issuer's `OS_*` service credentials | Read any project and any server, and validate any token. |
| TLS private keys of the signers and aggregators | Spoofing the JWKS endpoints. |
| Tenant `user-data` and `metadata` | Tenant secrets, often (cloud-init scripts, passwords, API keys). |
| Logs (issuer, SPIRE Server) | The audit trail for detection and forensics. |
| Metrics (issuer) | Per-project issuance volumes (when enabled), the deployment's topology and its failure modes. |

## Actors

| ID | Actor | Capabilities assumed |
| --- | --- | --- |
| A1 | Unprivileged process inside a guest (local user, container, compromised workload) | Can reach `169.254.169.254` unless the guest prevents it. Can reach the SPIRE Server's agent API. |
| A2 | Tenant project member | Can boot instances and set their name, hostname, metadata and user-data through the OpenStack API. |
| A3 | Another tenant | Controls its own instances and projects only. |
| A4 | Network attacker in the control plane | Can reach the issuer's listeners. Can attempt DNS spoofing and on-path attacks between components. |
| A5 | Compromised compute node (hypervisor) | Holds the credentials in its `nova.conf`, typically the `nova` service user's. |
| A6 | Compromised issuer replica | Holds its own signing keys and its `OS_*` credentials. |
| A7 | Malicious insider or operator | Has configuration or host access to some components. |
| A8 | Supply-chain attacker | Tampers with release artifacts or images on their way to hosts. |

## Data flows and trust boundaries

```
 ┌──────────── guest (VM) ────────────┐
 │ SPIRE Agent + openstack-agent-plugin│
 │ other local processes / containers  │
 └──────┬───────────────────┬──────────┘
   TB1  │ HTTP GET          │ TB6  agent API (SPIRE mTLS / TLS)
        │ vendor_data2.json │
        ▼                   ▼
 ┌───────────────┐   ┌──────────────────────────────┐
 │ Neutron meta- │   │ SPIRE Server                 │
 │ data proxy →  │   │  + openstack-server-plugin   │
 │ nova-api-     │   └──────────────┬───────────────┘
 │ metadata      │             TB5  │ HTTPS GET JWK Set
 └──────┬────────┘                  │ (pinned CA)
   TB2  │ HTTPS POST /attest        ▼
        │ X-Auth-Token      ┌──────────────────────────────┐
        ▼                   │ LB → signer replicas         │
 ┌──────────────────────┐   │      /.well-known/jwks.json  │
 │ LB → signer replicas │◄──┤  or JWKS aggregator(s)       │
 │ (in-memory keys)     │TB4└──────────────────────────────┘
 └──────┬───────────────┘   HTTPS GET /jwks/local.json
   TB3  │ HTTPS (service credentials)
        ▼
 ┌──────────────────────┐
 │ Keystone, Nova API   │
 └──────────────────────┘

 TB7: build and release pipeline → packages → issuer hosts, SPIRE Server hosts, guest images
```

| Boundary | From → to | Crossing data | Authentication across it |
| --- | --- | --- | --- |
| TB1 | Guest → Nova metadata | `vendor_data2.json`, carrying the token | None from the guest. Nova identifies the instance by its port (Neutron metadata proxy). |
| TB2 | `nova-api-metadata` → issuer `/attest` | Nova's claims about the instance, plus tenant metadata and user-data | Keystone token (`X-Auth-Token`), server TLS. Optionally source allowlist and mTLS (this revision). |
| TB3 | Issuer → Keystone, Nova API | Token validation, project and server records | Service credentials, verified TLS. |
| TB4 | Replica or aggregator → replica `/jwks/local.json` | Public keys | Verified TLS (pinned CA or system roots). |
| TB5 | SPIRE Server plugin → JWK Set URL | Public keys | Verified TLS (pinned CA or system roots). |
| TB6 | SPIRE Agent → SPIRE Server | Attestation payload (the token) | SPIRE's TLS, server-authenticated during node attestation. |
| TB7 | Release pipeline → hosts and images | Binaries, packages, units | Checksums. GPG signatures on the checksums file and on each package, added in this revision. |
| TB8 | Issuer → metrics consumer (a collector agent scraping `/metrics`, or an OpenTelemetry Collector receiving OTLP) | Metrics: counts, latencies, key and peer state; project IDs when enabled | Loopback by default; beyond it, TLS with client certificates (scrape) or verified TLS to the collector (push). Added and implemented Oct 5 (lab: MET-1, MET-2). |

## Security assumptions

The design relies on the following properties of components outside its scope. If one of them fails, the corresponding threats below fail with it.

- **AS-1 Instance identification at the metadata service**: Neutron's metadata proxy identifies the calling instance by its port. It authenticates to `nova-api-metadata` with the HMAC of `metadata_proxy_shared_secret`, and port security prevents IP and MAC spoofing between instances. Nova therefore calls the issuer only on behalf of the instance actually reading its metadata.
- **AS-2 Control-plane integrity**: Keystone and the Nova API return correct answers. The issuer's view of an instance (existence, project, status, availability zone) is the control plane's.
- **AS-3 Clock synchronization**: the issuer hosts and the SPIRE Server hosts keep their clocks within `clock_skew_tolerance` of each other (NTP).
- **AS-4 SPIRE behaviour**: SPIRE Server stores the serial of the latest agent SVID it issued for an agent ID and rejects calls made with a superseded one. The agent-to-server channel is TLS-protected. `plugin_checksum` is enforced when a plugin is loaded.
- **AS-5 Host integrity**: the issuer, aggregator and SPIRE Server hosts are operated by trusted administrators. Their configuration files and binaries are writable only by root.

## Threat register

### Spoofing

| ID | Threat | Boundary / element | Existing controls | Status | Addressed by | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| S-1 | Forged or altered token: self-signed, `alg: none`, an HMAC algorithm keyed with a public key, or an `alg` differing from the key's | TB6, server plugin | Signature verification by kid. Algorithm allowlist (RS256 with RSA at least 2048 bits, ES256 on P-256). The token's `alg` must equal the JWK's. Exact `iss` and `aud` (plugins: verification rules) | **M** | — | — |
| S-2 | Anything able to reach `/attest` impersonates Nova and mints tokens for arbitrary instances | TB2, issuer | Mandatory `X-Auth-Token` validated against Keystone. `allowed_users` and `required_role`. Instance cross-check against Nova (issuer: caller authentication, instance verification) | **M** | — | — |
| S-3 | Stolen or over-broad Nova credentials. `allowed_users` commonly lists `nova@Default`, whose password sits in `nova.conf` on every compute node, so a compromised hypervisor (A5) or any leak of that file mints a token for any instance in the cloud. The Nova cross-check does not help: the instances exist | TB2, issuer | Keystone authentication only. Any network location holding valid credentials is accepted | **U** | Issuer: caller authentication (`attest.allowed_sources`, optional mTLS with `attest.client_ca_path`, dedicated vendordata user), audit of issuance (R-1) | **A**: an attacker holding the dedicated user's credentials *and* a foothold on a metadata API host, or its client key, can still mint tokens. Detected through the issuance audit |
| S-4 | **In-guest token theft**. Any process in the guest (A1) reads `vendor_data2.json` and presents the token to the SPIRE Server before or instead of the SPIRE Agent. It gets the node's agent SVID and, through it, every workload SVID registered under that node. The token cannot be bound to the agent's key: Nova's DynamicJSON request carries nothing chosen by the guest | TB1, TB6, agent and server plugins | Single use per token (replay cache). Short acceptance window. The legitimate agent never presents a token twice | **U** | Plugins: guest hardening (required metadata access restriction to root and the SPIRE Agent's user), re-attestation detection (`reattest_alert_window`), optional TOFU mode (`reattest = false`) | **A**: a process running as root or as the agent's user in the guest, or a race at first attestation, cannot be prevented. Root in the guest owns the node identity by definition |
| S-5 | Spoofed JWK Set endpoint: DNS spoofing plus a certificate from any publicly trusted CA, when the plugin or the peer and aggregator fetches rely on the system roots instead of a pinned CA | TB4, TB5 | Verified TLS, never an insecure fallback, no redirects | **P** | Plugins: `Configure` warns when `jwks_ca_cert_path` is unset. Issuer: `config check` warns when `peers.ca_cert_path` or `replica_ca_cert_path` is unset | Low: requires mis-issuance by a public CA for an internal name |
| S-6 | A rogue responder at `169.254.169.254` inside the guest (a local process, or a spoofed link-local peer) serves a bogus token to the agent | TB1, agent plugin | The server verifies every token. A bogus token only fails attestation | **M** | — | Denial of service of that node's attestation only |
| S-7 | An instance makes Nova believe it is another instance (metadata request spoofing) | TB1, Nova and Neutron | AS-1 | **A** | — | Outside this solution. Relies on `metadata_proxy_shared_secret` and port security |
| S-8 | Cross-deployment acceptance. `iss` and `aud` are fixed contract values, so two SPIRE Servers (e.g. production and staging trust domains) that trust the same issuer each accept the other's instances | TB5, server plugin | Optional `allowed_project_ids` | **P** | Plugins: `Configure` warns when `allowed_project_ids` is unset. The trust model documents the shared audience | **A**: a per-consumer audience is impossible, since Nova obtains one token per instance for all consumers |

### Tampering

| ID | Threat | Boundary / element | Existing controls | Status | Addressed by | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| T-1 | Token claims modified in transit or in the guest | TB1, TB6 | Signature over header and claims | **M** | — | — |
| T-2 | A key injected into the JWK Set in transit or by a peer | TB4, TB5 | Verified TLS. Private key material rejected. Kid conflicts fail closed. Peers import only each other's local sets | **M** | — | A compromised replica can publish extra keys, but it can already sign with its own (E-5) |
| T-3 | **Tenant-asserted selectors**. Any project member (A2) sets `metadata` (the source of `tags`) and the hostname. A registration entry selecting only on `openstack_iid:tag:...` or `openstack_iid:hostname:...` can therefore be claimed by an instance the tenant boots, including an instance in *another* project (A3) | Issuer claims, server plugin selectors | The issuer's optional `tags.allowlist` limits the *keys* only, not who sets them | **U** | Plugins: normative rule that entries using `tag` or `hostname` selectors also carry a `project_id` or `instance_id` selector. Server-side `allowed_tag_keys`. Selectors table marks tenant-asserted selectors | **A**: inside a project, tags are as trustworthy as the project's members. That is their documented meaning |
| T-4 | Control characters, invalid UTF-8 or Unicode format characters in tag keys and values, or in enrichment claims, flow into selectors, SPIFFE-adjacent data and logs (selector confusion, log forging) | Issuer claims, server plugin | Hostnames are already checked for control characters, and `:` is rejected in tag keys | **U** | `pkg/iid` validation shared by the issuer (drops such tags) and the server plugin (rejects the token) | — |
| T-5 | Log forging or flooding through the unverified token header. The `kid` (attacker-chosen, up to the 16 KiB token cap) is logged on rejection before the signature has been checked | TB6, server plugin | `slog` quoting of values | **U** | `pkg/iid` kid format and length check, applied before lookup or logging. A malformed kid is logged as `invalid` | — |
| T-6 | Request smuggling at `/attest`: a second `instance-id` member, or a non-canonical UUID giving one instance two subjects | TB2, issuer | Duplicate members rejected. Canonical lowercase UUID required | **M** | — | — |
| T-7 | Supply chain. Release archives and packages are unsigned, so operators compute `plugin_checksum` from whatever they downloaded. A tampered agent plugin baked into images, or a tampered server plugin, would pass | TB7 | goreleaser checksums file, SBOMs, `plugin_checksum` | **U** | Issuer and plugins specs: signed checksums file and signed packages, verification documented before computing `plugin_checksum` | **A**: a compromise of the signing identity itself |
| T-8 | Configuration or binaries modified on issuer, aggregator or SPIRE Server hosts | Hosts | File modes `0640`/`0750`, `ProtectSystem=strict`, `plugin_checksum` | **M** | — | Within AS-5 |

### Repudiation

| ID | Threat | Boundary / element | Existing controls | Status | Addressed by | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| R-1 | Nothing is recorded when a token is issued. A token minted with stolen Nova credentials (S-3), or one later abused (S-4), cannot be traced to its caller, client address or replica | Issuer | Rejections are logged. Successes are not | **U** | Issuer: one `token issued` audit record per token (request ID, caller user ID, client address, project and instance IDs, `jti`, `kid`, `iat`, `exp`), optionally forwarded off the host by the syslog audit sink | — |
| R-2 | The server plugin's success record omits `jti`, `kid` and `iat`, so an attestation cannot be matched with the issuance that produced its token | Server plugin | `agent attested` with project, instance and SPIFFE ID | **U** | Plugins: success record carries `jti`, `kid`, `iat`, `exp`; optional syslog audit sink (`audit_syslog`) | — |
| R-3 | Ephemeral keys leave no trace. After a restart, nobody can prove which public key a past token was signed with, or that a kid ever belonged to a replica | Issuer key store | kid naming (date, replica ID) | **U** | Issuer: key lifecycle records (generated, published, active, retired) with the kid, algorithm and RFC 7638 thumbprint | — |

### Information disclosure

| ID | Threat | Boundary / element | Existing controls | Status | Addressed by | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| I-1 | Tokens, keys or credentials written to logs | All | Never logged by any component. Keystone tokens cached by SHA-256 | **M** | — | — |
| I-2 | Rejected-payload logs carry tenant `metadata` values, a common place for secrets (only `user-data` is redacted). The fallback for unparseable payloads looks for the literal `"user-data`, so an escaped member name (`"user-data"`) slips past it | Issuer logs | 512-byte truncation, `user-data` redaction | **U** | Issuer: `metadata` values redacted (keys kept). An unparseable payload is logged only with its size and a hash, never its content | — |
| I-3 | Physical layout (compute host, hypervisor) disclosed to tenants through claims readable in the guest | Issuer claims | Such claims are deliberately not offered | **M** | — | — |
| I-4 | Signing keys leak from process memory through core dumps, `ptrace` or a heap profile | Issuer host | Keys only in memory, never on disk. `ProtectSystem=strict`, `NoNewPrivileges` | **P** | Issuer: the units set `LimitCORE=0`, and the signer marks itself non-dumpable and locks its memory into RAM (`mlockall`) at startup, so that no key or signing temporary reaches swap | Root on the host can still read the process memory (within AS-5) |
| I-5 | CPU and heap profiles of a signer, enabled through environment variables, contain private key material and are created with default permissions (`0666` minus the umask) | Issuer | Not supported under the systemd units (the working directory is read-only) | **U** | Issuer: profiles are created `0600`, and the signer logs a warning at startup that they contain key material | — |
| I-6 | Error details revealed to callers | TB2, TB6 | The issuer returns bare status text. Health endpoints return no details | **M** (issuer) / **A** (server plugin) | — | The server plugin returns the rejection reason to the presenting agent only, which needs it to diagnose its own failures |
| I-7 | Any process in the guest can read the token | TB1 | — | see S-4 | — | — |
| I-8 | Metrics disclose per-project activity and the deployment's topology to whoever can scrape or receive them | TB8 | — (new, Oct 5) | **U** | Metrics spec: disabled by default; a loopback listener by default, TLS and client certificates beyond it; verified TLS to the collector; `project_id` opt-in and capped; no instance, user, token or address data in metrics | Low: what an authorized consumer sees is by design |

### Denial of service

| ID | Threat | Boundary / element | Existing controls | Status | Addressed by | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| D-1 | `/attest` flooded to exhaust signing, memory or the instance limit | TB2 | Per-source token bucket before the body is read, body cap, per-instance limit, bounded buckets, HTTP timeouts | **M** | — | — |
| D-2 | Keystone amplification. Every distinct, bogus `X-Auth-Token` costs one Keystone validation (failures are not cached), at up to the per-source rate from each of any number of sources, so an attacker (A4) can push load onto Keystone through the issuer | TB2 → TB3 | Per-source rate limit. Merged concurrent validations of the *same* token | **U** | Issuer: `attest.allowed_sources` (S-3) and a global cap on concurrent Keystone validations (`keystone.max_concurrent_validations`) | — |
| D-3 | Nova and Keystone lookup amplification by an authenticated caller | TB3 | Authentication first, per-instance limit, bounded caches, merged lookups | **M** | — | — |
| D-4 | The per-instance limit is per replica, so N replicas issue up to N tokens per period for an instance | Issuer | Callers are authenticated, and tokens are single use | **A** | — | Bounded by N; no impact on security properties |
| D-5 | Unauthenticated `/jwks/*`, `/liveness` and `/readiness` endpoints have no rate limit | Issuer, aggregator | HTTP timeouts. The readiness answer is precomputed | **P** | Issuer: per-source limit on every route, with its own rate (`rate_limit_per_source_public`) | — |
| D-6 | The server plugin is flooded with tokens carrying made-up kids (re-fetch storm), or the replay cache is saturated | TB5, TB6 | Re-fetch rate-limited. Only fully verified tokens enter the bounded cache. Fail closed when full | **M** | — | Saturation needs ~240 valid tokens per second, i.e. thousands of instances and issuer capacity |
| D-7 | JWK Set endpoint unreachable beyond `jwks_stale_key_retention` | TB5 | Last known good keys for 5 minutes, then fail closed | **A** | — | By design: unavailability is never a reason to loosen verification |
| D-8 | Agents rejected once after a SPIRE Server restart (startup watermark) | Server plugin | The agent's next attempt carries a fresh token | **A** | — | Documented cost |
| D-9 | Oversized vendordata or attestation payload | TB1, TB6 | 1 MiB vendordata cap, `MaxTokenBytes`, payload cap | **M** | — | — |
| D-10 | Scrapes, or series of unbounded cardinality, exhaust a signer's CPU or memory | TB8 | — (new, Oct 5) | **U** | Metrics spec: a separate, rate-limited listener answering `GET /metrics` only; closed attribute sets; `max_projects` cap; exporter failures never block issuance | — |

### Elevation of privilege

| ID | Threat | Boundary / element | Existing controls | Status | Addressed by | Residual |
| --- | --- | --- | --- | --- | --- | --- |
| E-1 | An unprivileged guest process gains the node identity, and from it every workload identity under the node | TB1 → TB6 | — | see S-4 | Plugins: guest hardening, TOFU option, detection | **A** for root in the guest |
| E-2 | A tenant member gains a privileged workload identity by setting instance metadata or the hostname | Selectors | — | see T-3 | Plugins: entry rule, `allowed_tag_keys` | — |
| E-3 | A compromised compute node, or any other holder of the credentials Nova uses, mints tokens for every instance in the cloud | TB2 | — | see S-3 | Issuer: source allowlist, mTLS, dedicated user | — |
| E-4 | An agent SVID outlives its instance (deleted, or shelved), so stolen agent credentials stay usable | SPIRE Server | The issuer refuses tokens for deleted instances or disallowed statuses. With `CanReattest`, an agent renews its SVID by re-attesting, which needs a fresh token, so its identity lapses at the next renewal | **P** | Plugins: deployment recommends SPIRE Server's `agent_ttl` of 1h or less. Ties to the TOFU trade-off (`reattest = false` renews without re-attestation, so it also needs eviction on instance deletion) | **A**: exposure up to `agent_ttl`. An evictor driven by Nova notifications is a possible future component, out of scope |
| E-5 | A compromised issuer replica mints arbitrary tokens | Issuer | Hardened units, keys only in memory, rotation, verified peers, distinct kids per replica | **A** | Issuer: audit of issuance (R-1) and key lifecycle records (R-3) support detection and scoping | Inherent: the issuer is the root of trust |
| E-6 | An `allowed_users` entry of the form `name@domain` matches a different user later renamed (or recreated) to that name with the required role | TB2 | Domain-qualified names, required role | **P** | Issuer: `config check` warns about name entries and recommends user IDs | — |

## Residual risks and accepted limitations

The following risks remain after every planned control. Each is documented in the companion specs where the behaviour is defined.

1. **Root in the guest owns the node identity** (S-4, E-1). The token is a bearer credential that the guest receives. Restricting metadata access confines it to root and the SPIRE Agent's user, but those cannot be excluded. TOFU mode closes the window after first attestation at the cost of manual eviction.
2. **Lateral replay across HA SPIRE Servers** within the acceptance window (plugins spec: trust model). The replay cache is per server instance.
3. **Tenant-asserted selectors** (T-3, E-2): `tag` and `hostname` selectors mean "a project member said so", never more.
4. **Shared audience** across SPIRE deployments trusting one issuer (S-8). Scoped only by `allowed_project_ids`.
5. **The issuer is the root of trust** (E-5). A compromised replica signs anything until it is detected and restarted.
6. **Agent identity outlives instance deletion** for up to `agent_ttl` (E-4).
7. **Availability over attestation**: issuer or JWK Set outages fail closed (D-7, D-8), so boot-time attestation depends on the issuer's availability.

## Review

This model is revisited whenever a companion spec changes a trust boundary, a credential, a claim or a selector, and before the `vault_transit` backend is implemented, which adds a new boundary (issuer → Vault proxy) and new assets (Vault credentials).
