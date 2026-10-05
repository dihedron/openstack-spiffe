# Design decisions

The significant choices behind the design, and why they were made.

**A fresh token on every metadata read.** The issuer signs a new token whenever Nova asks, rather than caching one per instance. Tokens can then be short-lived (5 minutes) and single use, without the issuer tracking anything: replay protection belongs to SPIRE Server, which sees the tokens presented. The per-instance rate limit bounds the cost.

**Keys generated in memory, per replica.** Each replica owns ephemeral keys, never stored. There is no key file to protect, back up or distribute, replicas need no coordination, and a restart replaces a suspected key. The cost is that SPIRE Server must learn the keys dynamically, which publication ahead of use makes safe. A Vault-backed key store is planned for deployments that want keys outside the replicas.

**No per-token calls to a key manager.** Barbican, or any control-plane key manager, would turn boot storms into load on a shared service, and add a dependency to every boot. Signing stays local to each replica.

**A key set endpoint, not a pinned key.** Keys rotate daily and on every restart, so SPIRE Server fetches them from a key set whose endpoint's certificate it pins. The endpoint's TLS identity is part of the trust chain, and the last known keys bridge short outages.

**Peers or aggregators.** Merging keys in the replicas themselves needs no extra component; aggregators exist for networks where SPIRE Server must not reach the signers. Both apply the same rules, and replicas only ever import each other's own keys, so keys never circulate.

**Instance verification against Nova.** Nova's request is authenticated, but its claims are cross-checked against the Nova API anyway, with the issuer's own credentials. This catches a misbehaving caller, and refuses deleted and stopped instances, at the cost of a cached lookup.

**A dedicated vendordata user, and restrictions on `/attest`.** Nova's service user is everywhere in a cloud; the user that can obtain tokens should be on the metadata hosts only. The source allowlist and client certificate confine leaked credentials further.

**Tenant-asserted values passed on, and marked.** Host names and tags are useful to tell instances apart within a project, so they become selectors. They are never presented as control-plane facts, and the registration entry rule keeps them from crossing projects.

**Replay protection in SPIRE Server, with a startup watermark.** A cache of used tokens makes each token single use; the watermark keeps a restart from reopening replay, at the cost of one refused attempt for agents attesting right after a restart. Sharing the cache across SPIRE Servers was left out: the tokens' short life and protected path make lateral replay an accepted risk.

**Re-attestation configurable, with detection.** Allowing re-attestation lets identities lapse with their instances, while trust on first use defeats later token theft: the right trade-off depends on the deployment, so it is the operator's. Detection of quick re-attestations is always on, and never refuses.

**Locking the whole process into memory.** Locking only the keys would leave the signature's temporary values swappable. Locking everything is simple, needs no C code, and costs a few megabytes of unswappable memory.

**Fail closed, always.** No unavailable dependency, missing claim or stale key ever leads to a weaker token or a weaker check. Unavailability costs attestations, never security.

**One shared contract.** The token's format, limits and validation rules are defined once and compiled into the issuer and both plugins, so they cannot drift apart.

**GPG-signed releases.** One GPG key signs the checksums file and every rpm and deb package, all verifiable offline with standard tools. Keyless signing would avoid a long-lived secret, but rpm and deb signatures need GPG anyway, and the lab can verify GPG signatures with the same commands operators use.

**Metrics off by default, and contained.** Metrics disclose activity, so they are opt-in, on a listener of their own, loopback by default, without per-instance data, and never able to delay a token.
