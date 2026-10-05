# Threat model

This chapter is the solution's threat model, organized by the STRIDE categories: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service and Elevation of privilege. It lists what is worth protecting, who might attack it, the assumptions the design rests on, every threat identified with the controls that address it, and the risks that remain. Threat IDs (`S-3`, `T-4`, ...) are stable: the *Setup Guide*'s configuration reference cites them next to the settings that bear on them.

**Scope**: the issuer (signer replicas, peer aggregation, JWKS aggregators), both plugins, their shared token contract, the packages and systemd units, and the release pipeline. Nova, Neutron, Keystone and SPIRE's internals are outside it: their relevant properties are listed as assumptions.

## Assets

| Asset | Why it matters |
| ---------------------------------- | -------------------------------------------------------------- |
| The signing private keys (per replica, in memory) | Whoever holds one can sign a token for any instance: the most valuable asset |
| Issued tokens | Bearer credentials: during its acceptance window (7 minutes at most), a token yields its instance's agent identity |
| The integrity of the key sets (local, merged, aggregated) | A key added to one is as good as a stolen signing key |
| Agent identities, and the workload identities registered under them | What the solution produces: a node identity gives access to every workload identity under it |
| Nova's vendordata credentials | They authorize calls to `/attest`, so they let their holder obtain tokens for any existing instance |
| The issuer's service credentials | They read any project and any server, and validate any token |
| The signers' and aggregators' TLS keys | They let their holder impersonate the key sets' endpoints |
| Tenants' user data and metadata | Often holding tenant secrets (scripts, passwords, API keys) |
| Logs and audit records | The trail for detection and forensics |
| Metrics | Per-project activity (when enabled), the deployment's topology and its failure modes |

## Actors

| ID | Actor | Capabilities assumed |
| ---- | ------------------------------ | ---------------------------------------------------------------- |
| A1 | An unprivileged process inside an instance (a local user, a container, a compromised workload) | Can reach the metadata service, unless the instance prevents it, and SPIRE Server's agent API |
| A2 | A tenant project member | Boots instances and sets their name, host name, metadata and user data through the OpenStack API |
| A3 | Another tenant | Controls its own instances and projects only |
| A4 | A network attacker in the control plane | Reaches the issuer's listeners; attempts DNS spoofing and on-path attacks between components |
| A5 | A compromised compute node | Holds the credentials in its `nova.conf`, typically Nova's service user's |
| A6 | A compromised issuer replica | Holds its own signing keys and its service credentials |
| A7 | A malicious insider or operator | Has configuration or host access to some components |
| A8 | A supply-chain attacker | Tampers with release artifacts or images on their way to hosts |

## Trust boundaries

The trust boundaries TB1 to TB8, and the data crossing each, are described in *Components and data flows*.

## Security assumptions

The design relies on these properties of components outside its scope. If one fails, the threats that depend on it fail with it.

- **AS-1, instance identification at the metadata service.** Neutron's metadata proxy identifies the calling instance by its network port, and authenticates to `nova-api-metadata` with a shared secret; port security prevents address spoofing between instances. Nova therefore calls the issuer only on behalf of the instance actually reading its metadata.
- **AS-2, control-plane integrity.** Keystone and the Nova API answer correctly: the issuer's view of an instance is the control plane's.
- **AS-3, clock synchronization.** The issuer hosts and the SPIRE Server hosts keep their clocks within the plugin's clock tolerance of each other.
- **AS-4, SPIRE's behaviour.** SPIRE Server keeps only the latest agent identity issued for an agent ID valid; the agent-to-server channel is TLS-protected; SPIRE checks a plugin's checksum before loading it.
- **AS-5, host integrity.** The issuer, aggregator and SPIRE Server hosts are run by trusted administrators, and their configuration files and binaries are writable only by root.

## Status

Each threat below has one of these statuses, after every control described in this document:

| Status | Meaning |
| ---------- | ----------------------------------------------------------------------------- |
| Mitigated | A control addresses the threat; what remains, if anything, is negligible or within an assumption |
| Partial | A control reduces the threat; a stated gap remains |
| Accepted | A residual risk inherent to the design, or out of the solution's reach, accepted with its rationale |

\needspace{12\baselineskip}

## Spoofing

| ID | Threat | Controls | Status, residual |
| ------- | ------------------------------ | ------------------------------------ | -------------------------- |
| S-1 | A forged or altered token: self-signed, `alg: none`, an HMAC keyed with a public key, or an algorithm differing from its key's | Signature verified with the key named by the key ID; RS256 and ES256 only; the token's algorithm must equal its key's; exact issuer and audience | Mitigated |
| S-2 | Anything able to reach `/attest` impersonates Nova and obtains tokens for arbitrary instances | A Keystone token is mandatory; the allowed users and required role; every instance confirmed against the Nova API | Mitigated |
| S-3 | Stolen or over-broad Nova credentials: Nova's service user's password is on every compute node, so a compromised hypervisor (A5) could obtain a token for any instance; the Nova cross-check does not help, since the instances exist | A dedicated vendordata user, configured only on the metadata hosts and listed by ID; `/attest` restricted by source address and client certificate; every issuance audited (R-1) | Accepted: an attacker with the vendordata user's credentials *and* a foothold on a metadata host, or its client key, can still obtain tokens; the audit trail detects it |
| S-4 | **Token theft inside the instance**: any process (A1) reads the token from the metadata service and presents it before or instead of SPIRE Agent, obtaining the node's identity and every workload identity under it; the token cannot be bound to the agent's key, since Nova's request carries nothing the instance chooses | Single use per token; a short acceptance window; the agent never presents a token twice; **guest hardening** (required): only root and SPIRE Agent's user may reach the metadata service; re-attestation alerts; an optional trust-on-first-use mode | Accepted: root or SPIRE Agent's user in the instance, or a race at the very first attestation, cannot be prevented; root owns the instance's identity by definition |
| S-5 | A spoofed key set endpoint: DNS spoofing plus a certificate from a public CA, when consumers trust the public CAs | Verified TLS, never an insecure fallback, no redirects; every consumer can pin its CA, and warns when it does not | Partial: low; it requires a public CA to issue a certificate for an internal name |
| S-6 | A rogue responder at the metadata address inside the instance serves a bogus token | SPIRE Server verifies every token: a bogus one only fails attestation | Mitigated: denial of that node's attestation only |
| S-7 | An instance makes Nova believe it is another instance | AS-1 | Accepted: outside the solution, it relies on Neutron's shared secret and port security |
| S-8 | Several SPIRE deployments trusting the same issuer (production and staging) accept each other's instances, since the issuer and audience are fixed | `allowed_project_ids`; the plugin warns when it is unset | Accepted: a per-consumer audience is impossible, since Nova obtains one token per instance for every consumer |

\needspace{12\baselineskip}

## Tampering

| ID | Threat | Controls | Status, residual |
| ------- | ------------------------------ | ------------------------------------ | -------------------------- |
| T-1 | A token's claims modified in transit or inside the instance | The signature covers the header and the claims | Mitigated |
| T-2 | A key injected into a key set, in transit or by a peer | Verified TLS; private key material rejected; conflicts fail closed; peers import only each other's local sets | Mitigated: a compromised replica can publish extra keys, but it can already sign with its own (E-5) |
| T-3 | **Tenant-asserted selectors**: any project member (A2) sets the metadata (the tags' source) and the host name, so an entry selecting only on a tag or host name can be claimed by an instance the tenant boots, including in *another* project (A3) | The rule that entries using `tag` or `hostname` selectors also use a `project_id` or `instance_id` selector; `allowed_tag_keys` in SPIRE Server; `tags.allowlist` in the issuer; the documentation marks these selectors | Accepted: within a project, tags are as trustworthy as the project's members, which is their documented meaning |
| T-4 | Control characters, invalid UTF-8 or format characters (bidirectional overrides, zero-width characters) in tags or optional claims, confusing selectors and forging log lines | One shared validation rule: the issuer drops such tags and refuses such claims; the server plugin rejects a token carrying either | Mitigated |
| T-5 | Log forging or flooding through the token's unverified key ID, which the attacker controls until the signature is checked | The key ID's format and length are checked before any lookup or logging; a malformed one is logged as `invalid` | Mitigated |
| T-6 | Request smuggling at `/attest`: a second `instance-id`, or one instance under two subjects | Duplicate members rejected; canonical lowercase instance IDs required | Mitigated |
| T-7 | Supply chain (A8): a tampered plugin baked into images, or installed on SPIRE Server, would pass `plugin_checksum`, computed from whatever was downloaded | Signed checksums file covering every artifact; signed rpm and deb packages; verification documented before computing `plugin_checksum`; SBOMs | Mitigated: a compromise of the packaging key itself remains |
| T-8 | Configuration or binaries modified on the issuer, aggregator or SPIRE Server hosts | Restrictive file modes; hardened systemd units with a read-only system; `plugin_checksum` | Mitigated: within AS-5 |

\needspace{12\baselineskip}

## Repudiation

| ID | Threat | Controls | Status, residual |
| ------- | ------------------------------ | ------------------------------------ | -------------------------- |
| R-1 | A token issued leaves no trace, so one obtained with stolen credentials (S-3), or later abused (S-4), cannot be traced to its caller or replica | One `token_issued` audit record per token (request ID, caller, client address and certificate, project and instance IDs, `jti`, key ID, times), written whatever the log level, and optionally sent to syslog for a central store | Mitigated |
| R-2 | An attestation cannot be matched with the issuance of its token | The `agent_attested` record carries the token's `jti`, key ID and times; optionally sent to syslog | Mitigated |
| R-3 | Ephemeral keys leave no trace: after a restart, nobody can prove which key a past token was signed with | Key lifecycle records with the key ID, algorithm and thumbprint | Mitigated |

\needspace{12\baselineskip}

## Information disclosure

| ID | Threat | Controls | Status, residual |
| ------- | ------------------------------ | ------------------------------------ | -------------------------- |
| I-1 | Tokens, keys or credentials written to logs | Never logged by any component; Keystone tokens cached by hash | Mitigated |
| I-2 | Rejected requests' logs carry tenants' metadata values, a common place for secrets | User data and metadata values redacted (keys kept); an unparseable body logged only by size and hash | Mitigated |
| I-3 | The cloud's physical layout (compute hosts) disclosed to tenants through claims readable inside instances | Such claims are deliberately not offered | Mitigated |
| I-4 | Signing keys leaking from memory, through core dumps, debugging or swap | Keys only in memory; the replica non-dumpable; its memory locked into RAM; core dumps disabled by the unit | Partial: root on the host can still read the process's memory (within AS-5) |
| I-5 | CPU and heap profiles, which contain key material, readable by others | Profiles written readable by their owner only; their use logged as a warning; not supported under the units | Mitigated |
| I-6 | Error details revealed to callers | The issuer answers with bare status text, and its health endpoints with no details | Mitigated for the issuer; accepted for the server plugin, which returns the reason to the presenting agent, which needs it to diagnose its own failures |
| I-7 | Any process in an instance can read the token | See S-4 | See S-4 |
| I-8 | Metrics disclose per-project activity and the deployment's topology to whoever can read them | Metrics off by default; a loopback listener by default, TLS and client certificates beyond it; verified TLS to the collector; per-project counts opt-in and capped; no instance, user, token or address data | Mitigated: what an authorized consumer sees is by design |

\needspace{12\baselineskip}

## Denial of service

| ID | Threat | Controls | Status, residual |
| ------- | ------------------------------ | ------------------------------------ | -------------------------- |
| D-1 | `/attest` flooded to exhaust signing, memory or the per-instance limit | A per-source limit before the body is read; a body size cap; a per-instance limit; bounded state; HTTP timeouts | Mitigated |
| D-2 | Keystone amplification: every distinct bogus token costs a Keystone validation | The source allowlist (S-3); a cap on concurrent Keystone validations, beyond which requests are refused at once | Mitigated |
| D-3 | Nova and Keystone lookups amplified by an authenticated caller | Authentication first; the per-instance limit; bounded caches; merged concurrent lookups | Mitigated |
| D-4 | The per-instance limit is per replica, so N replicas issue up to N tokens per period for an instance | Callers are authenticated, and tokens single use | Accepted: bounded by N, with no effect on security |
| D-5 | The unauthenticated key set and health endpoints flooded | Their own per-source limit, separate from `/attest`'s; precomputed readiness | Mitigated |
| D-6 | The server plugin flooded with tokens carrying invented key IDs, or its replay cache saturated | Refetches rate-limited; malformed key IDs rejected before any fetch; only fully verified tokens enter the bounded cache, which fails closed | Mitigated: saturation would need about 240 valid tokens per second |
| D-7 | The key set endpoint unreachable beyond the stale key retention | The last known keys kept for 5 minutes, then every attestation refused | Accepted: unavailability is never a reason to loosen verification |
| D-8 | Agents refused once after a SPIRE Server restart (the startup watermark) | The agent's next attempt carries a fresh token | Accepted: a documented cost |
| D-9 | Oversized vendordata or attestation payloads | A 1 MiB vendordata cap; the token size limit; a payload cap | Mitigated |
| D-10 | Metrics scrapes, or series of unbounded cardinality, exhausting a signer | A separate, rate-limited metrics listener; closed attribute sets; a cap on per-project series; exporters never block issuance | Mitigated |

\needspace{12\baselineskip}

## Elevation of privilege

| ID | Threat | Controls | Status, residual |
| ------- | ------------------------------ | ------------------------------------ | -------------------------- |
| E-1 | An unprivileged process in an instance gains the node identity, and every workload identity under it | See S-4: guest hardening, trust on first use, re-attestation alerts | Accepted for root in the instance |
| E-2 | A tenant member gains a privileged workload identity by setting metadata or the host name | See T-3: the registration entry rule, `allowed_tag_keys` | Accepted within a project (T-3) |
| E-3 | A compromised compute node, or any holder of Nova's credentials, obtains tokens for every instance | See S-3: a dedicated user, source allowlist, client certificate | See S-3 |
| E-4 | An agent identity outlives its instance, so stolen agent credentials stay usable | Tokens refused for deleted or disallowed instances; with re-attestation, an identity lapses at its next renewal; `agent_ttl` of one hour or less recommended; eviction documented for trust on first use | Accepted: exposure up to `agent_ttl`; an evictor driven by Nova's notifications is a possible future component |
| E-5 | A compromised issuer replica (A6) signs arbitrary tokens | Hardened units; keys only in memory; rotation; verified peers; distinct key IDs per replica; issuance and key audit records for detection and scoping | Accepted: the issuer is the root of trust |
| E-6 | A `name@domain` allowed user matching a different user later renamed or recreated under that name | Domain-qualified names; the required role; the configuration check warns about name entries and recommends user IDs | Partial: avoided by listing user IDs |

## Residual risks

After every control, these risks remain, each accepted with its rationale above:

1. **Root in an instance owns its identity** (S-4, E-1). Restricting metadata access confines the token to root and SPIRE Agent's user, but those cannot be excluded. Trust on first use closes the window after the first attestation, at the cost of manual eviction.
2. **Lateral replay across highly available SPIRE Servers**, within a token's acceptance window: the replay cache is per server.
3. **Tenant-asserted selectors** (T-3, E-2) mean "a project member said so", never more.
4. **A shared audience** across SPIRE deployments trusting one issuer (S-8), scoped only by `allowed_project_ids`.
5. **The issuer is the root of trust** (E-5): a compromised replica signs anything until it is detected and restarted.
6. **Agent identities outlive deleted instances** for up to `agent_ttl` (E-4).
7. **Availability over attestation**: issuer or key set outages fail closed (D-7, D-8), so attestation at boot depends on the issuer's availability.

This model is revisited whenever a change affects a trust boundary, a credential, a claim or a selector, and before the Vault key store backend is implemented, which adds a boundary and new credentials.
