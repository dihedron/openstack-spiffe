# OpenStack node attestor plugins — implementation spec

Sep 20, 2026 (revised Oct 2 and Oct 4, 2026) · @Andrea Funtò

*Revision notes (Oct 2)*: aligned with the issuer spec and `pkg/iid`; then revised for the review observations on replay across restarts and Nova's metadata cache, replay across HA servers, payload and JWK Set size limits, and clock skew.

*Revision notes (Oct 4)*: security revision following the STRIDE threat model (`openstack-spire-threat-model.md`). Changes:
- In-guest token theft made explicit, with required guest hardening, an optional TOFU mode and re-attestation detection (S-4, E-1).
- Tenant-asserted selectors made explicit, with `allowed_tag_keys` and a normative registration rule (T-3, E-2).
- `kid` and claim character validation (T-4, T-5).
- Correlatable success records (R-2).
- Configuration warnings (S-5, S-8).
- Deployment guidance on `agent_ttl` and signed releases (E-4, T-7).

Requirements introduced by this revision are tagged with the threat ID they address. They were implemented on Oct 4 and 5, 2026, in eight chunks, each with its tests and, where it involves OpenStack, its lab scenarios (see the test environment spec).

## Overview

This spec defines a matched pair of SPIRE plugins, `openstack_iid`, that attest an OpenStack Nova instance's identity to a SPIRE Server using a short-lived signed JWT issued by the OpenStack metadata JWT issuer (`openstack-spire-issuer`, companion spec) and delivered to the instance through Nova's DynamicJSON vendordata (`vendor_data2.json`, under the `openstack_iid` target).

- **Agent-side plugin** (`openstack-agent-plugin`): runs inside SPIRE Agent on the VM. Fetches the signed JWT from the local metadata service and forwards it to the Server.
- **Server-side plugin** (`openstack-server-plugin`): runs inside SPIRE Server. Verifies the JWT's signature and claims against the issuer's published keys, then emits the agent's SPIFFE ID and selectors.

This replaces network-position trust (assuming only a real instance can reach `169.254.169.254`) with a cryptographic proof issued by a trusted signer, and avoids relying on an unverified callback to the Nova API: the issuer already verified the instance against Nova before signing.

**Non-goals**: this spec does not cover the JWT issuer itself (companion spec), workload attestation, or registration entry automation — those are separate components with their own specs.

## Trust model

The entire security of this design reduces to the issuer's signing keys and to the channel through which the SPIRE Server learns them. Claude should treat the server-side verification and key retrieval as the highest-scrutiny part of the implementation.

- **Signing key custody** (owned by the issuer, see its spec): every signer replica signs with its own keys, held in memory (`ephemeral_memory`) or, later, in Vault transit (`vault_transit`); private keys never touch disk, and Barbican is deliberately not used for per-token signing. Keys rotate every `key_store.rotation_interval` (default 24h) and on every replica restart, so no public key is stable enough to be pinned in a configuration file.
- **Server trust anchor**: the server-side plugin learns the verification keys from a JWK Set URL (`jwks_url`) only, refreshed periodically, holding the keys of all signer replicas, selected by `kid`. The URL is either the peered signer replicas' `/.well-known/jwks.json` or a JWKS aggregator's `/.well-known/jwks.json`, never a replica's `/jwks/local.json` (which carries that replica's keys only). Since anyone able to tamper with the JWK Set could add a key, the endpoint's TLS identity is part of the trust chain: it is always reached over verified TLS, with a pinned CA (`jwks_ca_cert_path`) or the system roots, never with an insecure fallback.
- **Rotation**: the JWT header carries the `kid` of the signing key (`<YYYY-MM-DD>-<replica-id>-key-<n>`, e.g. `2026-09-29-signer-a-key-52331`). The key store holds every key of the current JWK Set at once, so a rotation doesn't invalidate in-flight tokens: the issuer keeps a retired key published for at least one token TTL. The issuer also publishes every new key `publish_ahead` before it signs with it, so a token with a kid the plugin does not know yet is rare; when it happens, the plugin re-fetches the JWK Set (rate-limited) before rejecting.
- **Binding to the real instance**: the issuer authenticates Nova's service token against Keystone and cross-checks `instance_id` and `project_id` against the Nova API before signing, so the claims are bound to the real instance by the compute control plane, never by client-supplied input. The plugins rely on this invariant without being able to enforce it, and document it in code comments.
- **Replay protection and its limits**: a token is a bearer credential for its acceptance window (see lifetime below), so the server-side plugin accepts each `jti` at most once (a replay cache) and never accepts a token minted before its own process started (a startup watermark, which closes the gap of a cache emptied by a restart); see replay protection in the server-side plugin. **Known limitation**: the replay cache is local to each SPIRE Server instance. In an HA deployment, a token intercepted within its acceptance window could be presented once to *each* other SPIRE Server instance, yielding that instance's agent identity (lateral replay). This is accepted, and mitigated by keeping tokens hard to intercept, not by the cache: the token travels from the instance's own metadata service to the SPIRE Agent and then over SPIRE's TLS-protected agent-to-server channel, it is never logged by any component, and its acceptance window is at most 7 minutes. Sharing the cache across SPIRE Server instances (e.g. in a store every instance can reach) is out of scope and remains a possible future hardening.
- **In-guest token theft** (S-4, E-1): the token is a bearer credential that the guest receives, and it is not bound to the SPIRE Agent's key. Nova's DynamicJSON request carries nothing the guest chooses, so no proof of possession is possible. Any process in the guest able to read `vendor_data2.json` could present the token to the SPIRE Server before the agent does. It would obtain the node's agent SVID, and through it every workload SVID registered under the node. With SPIRE Server keeping only the latest agent SVID serial per agent ID valid, the two would then displace each other at each re-attestation. Three controls address it:
  - **Prevention**: guest hardening restricts metadata access to root and the SPIRE Agent's user (agent-side plugin, required).
  - **Narrowing**: an optional TOFU mode (`reattest = false`) makes a stolen token useless once the agent has attested.
  - **Detection**: the server plugin flags an instance attesting again within `reattest_alert_window`.

  **Accepted residual risk**: root (or the agent's user) in the guest, and a race at the very first attestation, cannot be excluded. Root in the guest owns the node identity by definition.
- **Tenant-asserted claims** (T-3, E-2): `tags` come from instance metadata and `hostname` from the instance's name. Both are set by any member of the owning project through the OpenStack API, and the issuer passes them on unverified. Their selectors therefore mean "a member of this project said so". They distinguish instances *within* a project for workloads the whole project is trusted with, never across projects (see SPIFFE ID and selector naming). `project_id`, `instance_id` and the enrichment claims are control-plane facts.
- **Shared audience** (S-8): `iss` and `aud` are fixed contract values, and Nova obtains one token per instance for every consumer. Several SPIRE deployments trusting the same issuer (e.g. production and staging trust domains) therefore accept each other's instances unless `allowed_project_ids` scopes each of them. The server plugin warns when it is unset.

## Claim schema

The JWT is the shared contract defined once, in `pkg/iid`, and imported by both plugins and by the issuer, never hand-copied: the header (`iid.Header`) and claims (`iid.Claims`), the fixed values (`iid.Issuer` = `nova-spire-plugin`, `iid.Audience` = `spire-node-attestation`, `iid.TargetName` = `openstack_iid`, `iid.TTL` = 5 minutes, `iid.MaxTagsBytes` = 1024, `iid.MaxTokenBytes` = 16 KiB, the largest compact-serialized token either side handles, and `iid.MaxJWKSKeys` = 100, the most keys a JWK Set may hold), the field validation rules, and the vendordata response shape (`iid.VendorDataResponse`). The authoritative example is in the issuer spec; in short:

- header: `alg`, `kid`, `typ: "JWT"`;
- payload: `iss`, `aud`, `sub` (the instance ID), `iat`, `nbf`, `exp`, `jti` (a fresh UUID per token), `project_id`, `instance_id`, `hostname`, `tags` (a flat string map);
- optional enrichment claims, present only when the issuer enables them: `availability_zone`, `flavor`, `user_id`, `project_name`, `domain_id`;
- optional operator-configured custom claims: static top-level string claims whose names never collide with the claims above.

**Forward compatibility**: claims are decoded with `iid.ParseClaims`, which collects any string claim it does not model into `Claims.Custom` and skips unmodelled claims of other JSON types, so a claim added later by the issuer never breaks parsing in an older plugin; the plugins ignore claims they do not use. Duplicate claim names are still rejected.

**Verification rules** (server side, every one enforced, never trusted from the token):

- **Algorithms**: an explicit allowlist of RS256 (RSA, at least 2048 bits) and ES256 (ECDSA P-256), the same as the issuer's and the JWKS aggregator's. `none`, HMAC algorithms and anything else are rejected, and so is a token whose `alg` differs from the `alg` of the JWK selected by its `kid` (no algorithm confusion). `typ`, when present, must be `JWT`.
- **Issuer and audience**: `iss` must equal `iid.Issuer` and `aud` must equal `iid.Audience`, both exactly; this prevents a token minted for another consumer, or by another issuer sharing the keys, from being accepted here.
- **Lifetime**: `nbf <= iat < exp` and `exp - iat` at most `iid.TTL` (5 minutes), both checked on the token's own values, without any tolerance; then, against the server's clock, `nbf` and `iat` not later than now + `clock_skew_tolerance`, and `exp` later than now - `clock_skew_tolerance`. The tolerance (at most 60s) only absorbs clock differences between the issuer and the SPIRE Server; since it applies at both ends, the **maximum acceptance window** of a token is `iid.TTL + 2 × clock_skew_tolerance`: 6 minutes by default, 7 minutes at most. The issuer and the SPIRE Server hosts should keep their clocks synchronized (NTP).
- **Subject**: `sub` must equal `instance_id`.
- **Field formats** (the issuer's request validation rules, part of the shared contract): `instance_id` is a canonical lowercase UUID; `project_id` is 1 to 64 characters from `[A-Za-z0-9_-]`; `hostname` is non-empty, at most 255 characters, without control characters. Both IDs end up in the SPIFFE ID path, so this check also guarantees well-formed path segments.
- **Tags**: a flat map of string values (a non-string value is rejected, never silently dropped), at most `iid.MaxTagsBytes` once serialized, and no empty key or key containing `:` (the issuer drops such keys, see selectors below; a token carrying one is a contract violation). Keys and values must be valid UTF-8 without control (`Cc`) or format (`Cf`) characters (`iid.ValidateTagKey`, `iid.ValidateTagValue`, T-4). The issuer drops such entries, so a token carrying one is rejected.
- **Enrichment claims**: when present, each is a non-empty string passing `iid.ValidateEnrichmentValue`: valid UTF-8, at most 255 bytes, no control or format characters (T-4).
- **Key ID** (T-5): the header `kid` must match the issuer's kid format, `<YYYY-MM-DD>-<replica-id>-key-<n>` with `replica-id` a DNS label, at most 128 bytes (`iid.ValidateKeyID`). The check runs on the unverified header *before* the key lookup and before the kid is logged. A malformed kid is rejected without triggering a JWK Set re-fetch, and is logged as `kid=invalid` with its length, never its content. The attacker controls this field until the signature is checked.

## Agent-side plugin

Package: `internal/plugin/agent/openstackiid`; binary `openstack-agent-plugin`, built from `cmd/openstack-agent-plugin`. Implements `nodeattestorv1.NodeAttestorServer` (the `AidAttestation` streaming RPC) plus `configv1.ConfigServer`. Started without arguments, as SPIRE Agent does, the binary serves the plugin; `openstack-agent-plugin version` prints the version information, following the project's `<object> <verb>` command line convention.

**Flow**, one round trip, no challenge/response:

1. On `AidAttestation`, HTTP GET the configured vendordata URL (default `http://169.254.169.254/openstack/latest/vendor_data2.json`). Only a `200` response of at most 1 MiB is accepted; redirects are not followed.
2. Decode the body as `iid.VendorDataResponse` and extract `openstack_iid.jwt`. If the `openstack_iid` key is missing, return a distinct error saying so: Nova omits a DynamicJSON target whose call failed (`vendordata_dynamic_failure_fatal = False`), so this almost always means the issuer was unavailable (see its `/readiness`).
3. Check that the token is a compact-serialized JWS (three non-empty, dot-separated segments) of at most `iid.MaxTokenBytes`, the server's limit; a larger token is an error and nothing is sent. (The 1 MiB cap of step 1 bounds the whole `vendor_data2.json` document, which may carry other vendordata targets.) The agent does not verify the signature: it does not hold the keys, and the server verifies anyway.
4. If the token is the one this plugin presented last (same `jti`), wait for a fresh one (see freshness below).
5. Marshal `{"jwt": "<token>"}` as the attestation payload and send it once via `stream.Send`.
6. Return right after sending, which closes the stream — this attestor never expects a server challenge, and the plugin SDK allows attestors without challenge/response to close the stream as soon as they send the payload.

**Freshness**: every attestation and re-attestation fetches the token anew; the plugin never caches one. Nova itself may serve a cached `vendor_data2.json` for up to `[api] metadata_cache_expiration` (default 15s), so a token can be that old when fetched, well within its 5-minute TTL — but two attestations within that window would get the *same* token, and the server rejects the second as a replay. To avoid that, the plugin remembers, in memory, the `jti` of the last token it presented (reading it from the payload without verifying the signature, only for this purpose). When the vendordata serves that same token again, the plugin polls the vendordata URL every second until it serves a different token, bounded by `fresh_token_timeout` (default 30s: Nova's default cache window, plus the issuer's per-instance rate limit of one token every 5 seconds, plus a margin); past it, it returns a distinct error saying that Nova keeps serving an already presented token. This covers re-attestation by a running SPIRE Agent. A *restarted* SPIRE Agent normally does not run node attestation at all: it reuses the agent SVID persisted in its data directory while it is valid. An agent that lost its state and attests again within the cache window presents a token the server already accepted, is rejected with a distinct, transient "token already used" error, and succeeds on SPIRE Agent's next attempt, once Nova serves a fresh token. A config drive is not supported as a source: its `vendor_data2.json` is written once at boot, so the token it holds expires minutes later.

**Failure handling**: if the HTTP GET fails, times out, or the response is malformed, return a wrapped error and do not send a payload. Retries/backoff are the SPIRE Agent's responsibility, not this plugin's — do not add a retry loop inside `AidAttestation`. The bounded wait for a fresh token is not a retry: it only runs after a successful fetch of an already presented token, and any error during it is returned at once.

**Config** (`Configure` RPC), from `plugin_data`:

- `vendordata_url` (string, optional, default above)
- `http_timeout` (duration, default `5s`, bounds each fetch)
- `fresh_token_timeout` (duration, default `30s`, at least `http_timeout`; bounds the wait for a fresh token)

Unknown keys are errors, as in the issuer's configuration, so that typos are never silently ignored.

**Logging**: through the logger the plugin SDK provides (forwarded to SPIRE Agent's log). The token is never logged.

**Guest hardening** (required, S-4): every process in the guest can read the token from the metadata service, so images running the agent must restrict access to `169.254.169.254` (and `fe80::a9fe:a9fe` where the IPv6 metadata service is used). Only root and the SPIRE Agent's user may reach it. Root is needed because cloud-init reads metadata as root.

- The restriction is an nftables rule on the `output` hook that accepts traffic to the metadata addresses for `meta skuid` root and the agent's user, and rejects it for everyone else. It must be loaded before any untrusted workload starts, i.e. at boot through the image's nftables service, not by the agent.
- A sample, `examples/agent-metadata-nftables.conf`, is installed by the agent plugin's packages under `/usr/share/doc/openstack-agent-plugin/`. It is documentation, never activated by the package: activating it is a decision of the image owner.
- Containers must not share the host network namespace (e.g. `--network host`), since the rule matches on the UID inside the namespace where it is loaded. Container runtimes on the instance must not route the containers' traffic to the metadata addresses, and their bridge network must not reach them.
- `vendordata_url` should stay on the instance-local metadata address. An address elsewhere on the network widens who can serve or observe the token.

The agent plugin cannot enforce any of this from inside SPIRE Agent, so it does not check for it at runtime. The README's agent deployment section carries the rule and the reasoning.

The plugin has no dependency on SPIRE Agent or Server internals: only `github.com/spiffe/spire-plugin-sdk` and `pkg/iid`.

## Server-side plugin

Package: `internal/plugin/server/openstackiid`; binary `openstack-server-plugin`, built from `cmd/openstack-server-plugin` (same command line conventions as the agent's). Implements `nodeattestorv1.NodeAttestorServer` (the `Attest` streaming RPC) plus `configv1.ConfigServer`.

**Flow**:

1. `stream.Recv` the agent's payload (at most `iid.MaxTokenBytes` plus 1 KiB for the JSON envelope; the issuer never mints a token over `iid.MaxTokenBytes`, and a real one is about 6 KiB at most); unmarshal the `jwt` field.
2. Verify the JWT: look up the key by the header `kid` in the key store (see JWK Set retrieval), verify the signature, and apply every verification rule of the claim schema.
3. If `allowed_project_ids` is set, reject any `project_id` not listed.
4. Reject a token minted before this plugin process started, or whose `jti` was already used, then record the `jti` (see replay protection). These checks come last, so that only tokens passing every other check reach the replay cache.
5. On any failure, return an error immediately. Never emit an agent identity for a token that fails any check.
6. On success, build the SPIFFE ID `spiffe://<trust_domain>/spire/agent/openstack_iid/<project_id>/<instance_id>` and the selectors (see below), from verified claims only, never from anything outside the signed token.
7. Check the instance against the re-attestation tracker (see re-attestation detection) and record the attestation. This logs only and never rejects.
8. Log the success record (see logging) and return `AgentAttributes{SpiffeId, SelectorValues, CanReattest: <reattest>}`.

Claude should keep JWT verification in its own pure, testable function (token, key set, current time and options in; verified `iid.Claims` or an error out), separate from the RPC handler and the key retrieval, so it can be unit-tested without a running SPIRE Server or HTTP endpoint.

**Trust domain**: taken from SPIRE Server's core configuration (`CoreConfiguration.TrustDomain` in the `Configure` request), not from `plugin_data`, so the plugin can never disagree with the server it runs in.

**JWK Set retrieval** (same rules as the issuer's peer aggregation and JWKS aggregator; the implementation reuses their code):

- **Size**: a JWK Set holding more than `iid.MaxJWKSKeys` (100) entries is a failed fetch, never truncated (which would keep an arbitrary subset); the keys of the last successful fetch stay in use (see last known good). With each signer replica publishing a handful of keys, this allows about 25 replicas. Verification never tries several keys: the token's `kid` selects exactly one key, by map lookup, so the number of keys does not multiply the signature work of an attestation.
- **Polling**: at startup and then every `jwks_refresh_interval` (default 30s, the issuer's default `cache_max_age`), each fetch bounded by `jwks_fetch_timeout` (default 5s).
- **Fetch rules**: `jwks_url` is https only; TLS `tls_min_version` (`"1.2"` or `"1.3"`, default `"1.3"`) or later, verified against `jwks_ca_cert_path` or the system roots; `200` only, at most 1 MiB, a standard RFC 7517 JWK Set; redirects are never followed.
- **Key filtering**: only public keys with `use=sig` and an allowed algorithm (RS256 with RSA of at least 2048 bits, ES256 on P-256) are kept; others are left out and logged. A key carrying private key material is rejected and logged as an error, without the material. Two keys with the same kid and different material exclude that kid (fail closed).
- **Unknown kid**: the plugin re-fetches the JWK Set at once, at most once per `jwks_min_refetch_interval` (default 5s, so a flood of tokens with made-up kids cannot turn into a flood of fetches), then rejects the token if the kid is still unknown.
- **Last known good**: when a fetch fails, the keys of the last successful fetch keep being used for `jwks_stale_key_retention` (default and minimum 5m, the maximum token TTL), so in-flight tokens keep verifying during short outages. Past that, every attestation is rejected until a fetch succeeds. A failing endpoint is logged when it starts failing and when it recovers, not on every poll.

**Replay protection** (see the trust model for its limits):

- **Replay cache**: after a token passes every other check, its `jti` is recorded in an in-memory cache until `exp + clock_skew_tolerance`, the end of its acceptance window, and a token whose `jti` is already recorded is rejected with a distinct error ("token already used"). Only successful attestations are recorded, so a rejected attempt never burns a `jti`. The cache is bounded (100,000 entries, far above any realistic attestation rate over 7 minutes); when it is full even after purging expired entries, attestations are rejected and the condition is logged as an error, rather than forgetting a `jti` early (fail closed).
- **Startup watermark**: the cache is lost when the plugin process restarts, so a token accepted just before a restart could otherwise be replayed just after it. The plugin therefore records its process start time and rejects, with a distinct error ("token issued before this server started"), any token whose `iat` is earlier than that start time plus `clock_skew_tolerance`. Since the issuer's and the server's clocks differ by at most the tolerance, every token accepted was minted after the process started, and so was never presented to a previous process. The rule is always on and stops mattering once tokens minted before the start have expired. The watermark and the cache belong to the process, not to the configuration: a new `Configure` call keeps both.
- **Cost for legitimate agents**: right after a SPIRE Server restart, an agent attesting with a token minted shortly before it (still served by Nova's cache) is rejected once, and succeeds on SPIRE Agent's next attempt with a fresh token, typically within `clock_skew_tolerance` plus Nova's cache window (about 45s by default). A running agent never presents the same token twice (see the agent's freshness wait), and a restarted one usually does not attest at all.

**Re-attestation mode** (`reattest`, S-4, E-4): `CanReattest` is configurable. Each setting changes what SPIRE Server does with a second attestation of the same agent ID, so the choice is the operator's:

- `true` (default): SPIRE Agent renews its SVID by re-attesting with a fresh token, and an agent that lost its state attests again without operator action. Since renewal requires a fresh token, which the issuer refuses for a deleted or disallowed instance, an agent's identity lapses at its next renewal once its instance is gone. However, a stolen token can displace the legitimate agent at any time within its window.
- `false` (trust on first use): SPIRE Server refuses to attest an agent ID that is already attested, until it is evicted. A token stolen after the agent's first attestation is useless. On the other hand, an agent that lost its state needs an operator's `spire-server agent evict`. The SVID is renewed without re-attestation, so the identity also survives the instance's deletion until it is evicted or expires. Operators choosing `false` must evict agents of deleted instances.

**Re-attestation detection** (S-4, E-1): the plugin keeps, in memory, the time of the last successful attestation of each `instance_id`. The record is bounded at 100,000 instances, with the oldest evicted first. It is lost on restart, like the replay cache. When an instance attests again within `reattest_alert_window` (default 5m, `0` disables), the plugin logs a `warn` record, `possible token theft: instance re-attested`, with the instance and project IDs, both `jti`s and the time between them. A running SPIRE Agent re-attests only near its SVID's expiry (tens of minutes), and a restarted one reuses its persisted SVID. A quick second attestation therefore means either an agent that lost its state, or a second presenter of the instance's tokens. Detection never rejects: rejecting would let a thief who attests first lock out the legitimate agent.

**Config**, from `plugin_data`:

- `jwks_url` (string, required, https; a path ending in `/jwks/local.json` is an error, since it would serve a single replica's keys)
- `jwks_ca_cert_path` (string, optional; default: system roots)
- `tls_min_version` (`"1.2"` or `"1.3"`, default `"1.3"`)
- `jwks_refresh_interval` (duration, default `30s`)
- `jwks_fetch_timeout` (duration, default `5s`, less than `jwks_refresh_interval`)
- `jwks_min_refetch_interval` (duration, default `5s`)
- `jwks_stale_key_retention` (duration, default `5m`, at least `5m`)
- `allowed_project_ids` (array of strings, optional allowlist; reject attestation for any other project)
- `clock_skew_tolerance` (duration, default `30s`, at most `60s`)
- `allowed_tag_keys` (array of strings, optional, T-3): when set, only tags with a listed key become `tag` selectors. Other tags are ignored (not an error, logged at `debug`). The SPIRE Server operator, who writes the registration entries, may not be the issuer's operator, who sets `tags.allowlist`, so this list lets them fix which tenant-asserted keys their entries can rely on. Each entry must be a valid tag key.
- `reattest` (bool, default `true`): the `CanReattest` value; see re-attestation mode
- `reattest_alert_window` (duration, default `5m`, `0` disables, at most `1h`): see re-attestation detection
- `audit_syslog` (block, optional): `enabled` (bool, default `false`), `socket` (default `/dev/log`), `facility` (default `authpriv`) and `app_name` (default `openstack-server-plugin`). See audit records to syslog

Unknown keys are errors. The CA bundle, if set, must exist and parse at `Configure` time.

**Configuration warnings** (logged at `warn` by `Configure`, which still succeeds):
- `jwks_ca_cert_path` unset: every public CA is trusted for the JWK Set (S-5).
- `allowed_project_ids` unset: any project's instances attest, including those meant for another SPIRE deployment trusting the same issuer (S-8).
- `allowed_tag_keys` unset: every tag becomes a selector (T-3).
- `audit_syslog` disabled: audit records reach only SPIRE Server's log (R-2).

**Logging**: through the logger the plugin SDK provides. Rejections are logged with the reason, the `kid` (or `kid=invalid`, see the key ID rule), and the `project_id` and `instance_id` when they could be read; tokens and key material are never logged. Every successful attestation is logged at `info` as `agent attested` with `audit=agent_attested` (R-2). The record carries:
- `project_id`, `instance_id` and the SPIFFE ID
- `jti`, `kid`, `iat` and `exp`
- the number of selectors

The `jti` matches the issuer's `token issued` record, which ties every agent identity to the Nova call and the key that produced its token. The re-attestation detection warning is also an audit record, `audit=reattest_alert`.

**Audit records to syslog** (R-2, S-4): when `audit_syslog.enabled` is set, the plugin also sends its audit records (`agent_attested` and `reattest_alert`) to the local syslog daemon. It uses the issuer's syslog audit sink (`pkg/syslog`, same format and delivery rules, see the issuer spec): RFC 3164 with `app_name` as the tag and the record as a JSON `MSG` carrying the audit kind (`audit`) and the exact time. `reattest_alert` uses severity `warning`, the others `info`.
- Only audit records go there. Everything else, audit records included, still goes to SPIRE Server's log through the plugin SDK.
- Delivery never blocks or fails an attestation: it goes through a bounded queue, and drops are counted and logged.
- `Configure` fails when the socket cannot be opened. A new `Configure` call replaces the sink only if its settings changed, draining the old one first.

The issuer's and the plugin's records then reach the same central store, where they can be joined on `jti`.

## SPIFFE ID and selector naming

| Element | Pattern | Example |
| --- | --- | --- |
| Agent SPIFFE ID | `spiffe://<trust_domain>/spire/agent/openstack_iid/<project_id>/<instance_id>` | `spiffe://example.org/spire/agent/openstack_iid/a1b2/c3d4` |
| Selector: project | `openstack_iid:project_id:<id>` | `openstack_iid:project_id:a1b2` |
| Selector: instance | `openstack_iid:instance_id:<id>` | `openstack_iid:instance_id:c3d4` |
| Selector: hostname | `openstack_iid:hostname:<name>` | `openstack_iid:hostname:web-03` |
| Selector: tag | `openstack_iid:tag:<key>:<value>` (one per tag) | `openstack_iid:tag:role:jboss` |
| Selector: availability zone | `openstack_iid:availability_zone:<az>` | `openstack_iid:availability_zone:az-1` |
| Selector: flavor | `openstack_iid:flavor:<name>` | `openstack_iid:flavor:m1.large` |
| Selector: booting user | `openstack_iid:user_id:<id>` | `openstack_iid:user_id:9f8e` |
| Selector: project name | `openstack_iid:project_name:<name>` | `openstack_iid:project_name:billing` |
| Selector: domain | `openstack_iid:domain_id:<id>` | `openstack_iid:domain_id:default` |

- The enrichment selectors (availability zone through domain) are emitted only when the token carries the claim, i.e. when the issuer enables it.
- **Tenant-asserted selectors** (T-3, E-2): `tag` and `hostname` selectors carry values that any member of the instance's project sets through the OpenStack API. **A registration entry that uses a `tag` or `hostname` selector must also carry an `openstack_iid:project_id` or `openstack_iid:instance_id` selector.** SPIRE matches an entry when a node has all of its selectors, so an entry selecting on `openstack_iid:tag:role:db` alone matches an instance of *any* project, in any tenant, that sets that tag. The plugin cannot enforce this rule, since entries live in SPIRE Server, and the README repeats it next to every example entry. Tag selectors are emitted only for keys in `allowed_tag_keys` when it is set.
- `project_name` is chosen by project administrators, and `domain_id` and `user_id` identify principals, so entries keying off identity should prefer `project_id` and `instance_id`, which are immutable control-plane IDs.
- Tag keys never contain `:` (the issuer drops them, the server rejects them), so a tag selector always splits unambiguously into key and value; values may contain `:`.
- Custom claims are deliberately not turned into selectors: they are static per issuer deployment and say nothing about the individual instance.

`openstack_iid` is the fixed attestor identifier, used consistently as the plugin name, the SPIFFE ID path segment, the selector type prefix and Nova's DynamicJSON target name — this is what downstream registration entries (workload SPIFFE IDs with this node as `parentID`) key off of. Both plugins take it from `iid.TargetName`, never from a literal, so the agent, the server and the issuer can never diverge; a mismatch would break entry matching silently.

## Configuration reference

`agent.conf`:

```hcl
NodeAttestor "openstack_iid" {
  plugin_cmd      = "/usr/bin/openstack-agent-plugin"
  plugin_checksum = "<sha256 of the installed binary>"
  plugin_data {
    vendordata_url      = "http://169.254.169.254/openstack/latest/vendor_data2.json"
    http_timeout        = "5s"
    fresh_token_timeout = "30s"
  }
}
```

`server.conf`:

```hcl
NodeAttestor "openstack_iid" {
  plugin_cmd      = "/usr/bin/openstack-server-plugin"
  plugin_checksum = "<sha256 of the installed binary>"
  plugin_data {
    jwks_url                  = "https://openstack-metadata-jwks.internal:8444/.well-known/jwks.json"
    jwks_ca_cert_path         = "/etc/ssl/openstack-metadata-ca.pem"
    tls_min_version           = "1.3"
    jwks_refresh_interval     = "30s"
    jwks_fetch_timeout        = "5s"
    jwks_min_refetch_interval = "5s"
    jwks_stale_key_retention  = "5m"
    allowed_project_ids       = ["a1b2", "e5f6"]
    clock_skew_tolerance      = "30s"
    allowed_tag_keys          = ["role", "env"]
    reattest                  = true
    reattest_alert_window     = "5m"
    audit_syslog {
      enabled  = true
      socket   = "/dev/log"
      facility = "authpriv"
      app_name = "openstack-server-plugin"
    }
  }
}
```

Keep SPIRE Server's `agent_ttl` at 1h or less (its default) (E-4). With `reattest = true`, an agent's identity lapses at its next renewal after its instance is deleted, so `agent_ttl` bounds how long a deleted instance's identity, or a stolen one, stays usable.

The binary paths are those installed by the `openstack-agent-plugin` and `openstack-server-plugin` packages. Claude should validate all fields in `Configure` and return a clear error naming the offending field (missing, unknown, malformed or out of range), rather than failing later at attestation time with an ambiguous error. Sample files live in `examples/`, kept valid by a test, as for the issuer's samples.

## Error handling and failure modes

| Failure | Agent-side behavior | Server-side behavior |
| --- | --- | --- |
| Vendordata endpoint unreachable, non-`200`, or too large | Return error from `AidAttestation`; no payload sent | N/A |
| Malformed vendordata response | Return error; no payload sent | N/A |
| `openstack_iid` target missing from the vendordata (issuer unavailable) | Return a distinct error naming the missing target; no payload sent | N/A |
| Token larger than `iid.MaxTokenBytes` | Return error; no payload sent | Reject (payload over the limit) |
| Vendordata still serving the last presented token after `fresh_token_timeout` | Return a distinct error; no payload sent | N/A |
| Payload malformed or over its size limit | N/A | Reject, return error |
| `alg` not allowed, or differing from the JWK's | N/A | Reject, return error, log the `alg` and `kid` |
| Unknown `kid` | N/A | Re-fetch the JWK Set (rate-limited); reject if still unknown, log the `kid` |
| JWT signature invalid | N/A (agent doesn't verify) | Reject attestation, return error, log the `kid` attempted |
| JWT expired, not yet valid, or with a lifetime over the TTL | N/A | Reject, return error |
| `iss` or `aud` mismatch | N/A | Reject, return error |
| `sub` differs from `instance_id`; malformed `instance_id`, `project_id` or `hostname` | N/A | Reject, return error |
| Tag value not a string, tag key containing `:`, tags over the size cap, or a tag or enrichment value with control/format characters or invalid UTF-8 | N/A | Reject, return error |
| Malformed `kid` (not the issuer's format, or over 128 bytes) | N/A | Reject without re-fetching, log `kid=invalid` and its length |
| Tag key not in `allowed_tag_keys` | N/A | Accept; no selector for that tag |
| Same `instance_id` attested again within `reattest_alert_window` | N/A | Accept; log a "possible token theft" warning |
| Agent ID already attested, with `reattest = false` | N/A | SPIRE Server refuses the attestation until the agent is evicted |
| `project_id` not in `allowed_project_ids` | N/A | Reject, return error naming the disallowed project |
| `jti` already used | N/A | Reject with a distinct "token already used" error, log the `instance_id` |
| Token issued before the plugin process started (startup watermark) | N/A | Reject with a distinct "issued before this server started" error; the agent's next attempt carries a fresh token |
| Replay cache full, even after purging expired entries | N/A | Reject, log an error (fail closed) |
| JWK Set with more than `iid.MaxJWKSKeys` keys | N/A | Treat as a failed fetch: keep the last known good keys, log the error |
| JWK Set fetch fails | N/A | Keep using the last known good keys for `jwks_stale_key_retention`; past that, reject all attestation until a fetch succeeds |

None of these paths should panic. Every rejection must be a clean gRPC error surfaced through the plugin SDK, never a crashed plugin process — a crashed server-side plugin takes down node attestation for every agent, not just the failing one. Like the issuer, the server plugin treats unavailability as safe, never as a reason to loosen verification.

## Testing and validation

**Unit tests** (no running SPIRE needed):

- JWT verification function: valid RS256 and ES256 tokens accepted; expired, not-yet-valid, over-long lifetime, wrong `iss`, wrong `aud`, `sub` differing from `instance_id`, unknown `kid`, tampered signature, `alg: none`, an HMAC `alg`, and an `alg` differing from the JWK's all rejected.
- Claim validation: malformed IDs and hostnames, non-string tag values, tag keys containing `:` and oversized tags rejected; unknown extra claims, string or not, accepted and ignored.
- Clock skew: tokens just inside and just outside `iid.TTL + 2 × clock_skew_tolerance` around the server's clock; a token with `exp - iat` over `iid.TTL` rejected whatever the tolerance.
- SPIFFE ID and selector construction from a fixed set of verified claims, including tags with special characters (values containing `:`) and with and without enrichment claims.
- JWK Set retrieval: key filtering, kid conflict exclusion, a set with more than `iid.MaxJWKSKeys` keys treated as a failed fetch, last-known-good retention and its expiry, a rate-limited re-fetch on an unknown kid that then succeeds.
- Replay cache: a reused `jti` rejected, a rejected attempt not recorded, entries forgotten after `exp + clock_skew_tolerance`, a full cache rejecting attestations.
- Startup watermark: a token minted before the process start (plus tolerance) rejected, one minted after accepted; a new `Configure` call keeps the cache and the watermark.
- Config validation: missing, unknown, malformed and out-of-range fields produce errors naming them; a non-https `jwks_url` or one ending in `/jwks/local.json` rejected.
- Key ID (T-5): a kid of the wrong format, or over 128 bytes, or carrying control characters is rejected without a re-fetch, and the log record never contains it.
- Character validation (T-4): tag keys and values and enrichment values with control characters, format characters (e.g. U+202E, U+200B) or invalid UTF-8 rejected.
- `allowed_tag_keys` (T-3): unlisted tags produce no selector, and listed ones do. Unset, every tag produces one.
- `reattest` maps to `CanReattest`.
- Re-attestation detection (S-4): two attestations of one instance within the window log the warning with both `jti`s and are both accepted. Outside the window, or with `0`, nothing is logged. The tracker is bounded.
- Success record (R-2): it carries the token's `jti`, `kid`, `iat` and `exp`, and never the token.
- Configuration warnings (S-5, S-8, T-3, R-2) for unset `jwks_ca_cert_path`, `allowed_project_ids` and `allowed_tag_keys`, and for `audit_syslog` disabled.
- Syslog audit (R-2), against a temporary Unix datagram socket:
  - a successful attestation yields one `agent_attested` datagram whose `jti` equals the token's;
  - a quick second attestation yields a `reattest_alert` datagram with severity `warning`;
  - rejections and other records never reach the socket;
  - an unopenable socket fails `Configure`.

**Integration tests**, using the plugin SDK's test harness (`plugintest`):

- Agent plugin against a mock vendordata HTTP server (success, timeout, malformed JSON, missing `openstack_iid` target, token over `iid.MaxTokenBytes`, 500 response, redirect), including the freshness wait: a second attestation served the same token waits until the server serves a fresh one, and fails with the distinct error if none comes within `fresh_token_timeout`.
- Server plugin against a table of JWTs signed with test keys and a test JWKS server, covering every server-side row in the failure-modes table above.
- End-to-end with the real issuer: the issuer's test harness (`internal/issuer/integration`, with the mocked Keystone and Nova of `internal/issuer/openstacktest`) runs the signer replicas, peered or with an aggregator; a mock metadata server serves the token the signer returned for the instance; the agent plugin presents it and the server plugin verifies it against the replicas' (or the aggregator's) `/.well-known/jwks.json`, yielding the expected SPIFFE ID and selectors. Key rotation drill: tokens signed just before a rotation and just after it both attest.
- Optionally, a real SPIRE Agent and Server pair running both plugins, confirming that the resulting agent SVID carries the expected SPIFFE ID.

**Explicitly required negative tests**: a token signed with a *different* valid key (not in the JWK Set), and a token with an unlisted `project_id`, must both be rejected — these are the two cases most likely to pass by accident if selector/claim matching logic has a bug. A replayed token must be rejected on its second use.

## Build, packaging, deployment

- Both plugins live in this repository's single Go module, next to the issuer, so that all three import the same `pkg/iid`; each is its own binary (`openstack-agent-plugin`, `openstack-server-plugin`), built with `CGO_ENABLED=0` for simple, static distribution.
- Both are built against `github.com/spiffe/spire-plugin-sdk` at a pinned version, recorded in `go.mod`.
- **Supported CPUs**: linux/amd64 and linux/arm64. The amd64 builds come in three levels: the baseline (`GOAMD64=v1`), which runs on any x86-64 CPU and has unsuffixed artifact names, and two optimized variants suffixed `v2` and `v3`. The baseline is the default everywhere, including in the lab; nothing in the design requires a particular CPU level. The agent plugin, which runs inside every instance, should use the baseline build unless every hypervisor exposes an x86-64-v3 CPU model to its guests.
- Releases go through the existing goreleaser configuration: each plugin gets its own archive and its own `deb` and `rpm` package, installing only its binary.
- The server plugin is deployed wherever SPIRE Server runs (a small number of hosts, standard config management), with network access to the JWK Set URL (the signer replicas' or the aggregator's load balancer).
- The agent plugin must ship inside every OpenStack instance image the agent runs on — bake it into the base image or install it via the provisioning pipeline, so it's present before SPIRE Agent starts. The same images carry the metadata access restriction of guest hardening (S-4).
- Record the SHA-256 of each installed binary and set it as `plugin_checksum` in the corresponding `.conf` file — this is a supply-chain control (SPIRE refuses to load a plugin binary whose hash doesn't match), not optional hardening. A `make checksum` target prints the SHA-256 of each plugin binary produced by the build; goreleaser's checksums file covers the release archives and packages.
- **Verify before pinning** (T-7): `plugin_checksum` only proves that the binary is the one that was installed. Before computing it, verify the release's signed checksums file, or the package's own signature: `rpm --checksig` (or `dnf` with `localpkg_gpgcheck`) for rpm, `debsig-verify` for deb, since apt does not verify standalone packages (see the issuer spec's signed releases). Image pipelines baking the agent plugin do the same.

## Implementation plan for the Oct 4 security revision

Done (Oct 5, 2026). Tests came first, as for every change.

| Area | Change | Threats |
| --- | --- | --- |
| `pkg/iid` | `ValidateKeyID`, `ValidateTagValue`, `ValidateEnrichmentValue`; UTF-8, control and format checks in `ValidateTagKey` (shared with the issuer) | T-4, T-5 |
| `internal/plugin/server/openstackiid/verify.go` | Validate the unverified `kid` before lookup, re-fetch or logging; apply the new tag and enrichment checks | T-4, T-5 |
| `internal/plugin/server/openstackiid/plugin.go` | Config keys `allowed_tag_keys`, `reattest` and `reattest_alert_window`; `Configure` warnings; `CanReattest` from configuration; success record with `jti`, `kid`, `iat`, `exp`; `kid=invalid` in rejection logs | S-4, S-5, S-8, T-3, R-2 |
| `internal/plugin/server/openstackiid/selectors.go` | Filter tag selectors by `allowed_tag_keys` | T-3 |
| `internal/plugin/server/openstackiid` (new `reattest.go`) | Bounded, process-scoped re-attestation tracker kept across `Configure` calls, like the replay cache | S-4, E-1 |
| `internal/plugin/server/openstackiid/plugin.go`, `internal/plugin/logging` | `audit_syslog` block; the `pkg/syslog` `AuditHandler` combined with the hclog bridge, so audit records go to both SPIRE's log and syslog | R-2, S-4 |
| `examples/` | `agent-metadata-nftables.conf`; `server.conf` sample with the new keys | S-4, T-3 |
| `.goreleaser.yaml` | Install the nftables sample as documentation in the agent packages; signing (see the issuer spec) | S-4, T-7 |
| README | Guest hardening, the registration entry rule for tenant-asserted selectors, `reattest` trade-off, `agent_ttl`, release verification | S-4, T-3, E-4, T-7 |

## Resolved questions and out of scope

**Resolved questions** (open in earlier drafts):

- Static pinned key vs. JWKS endpoint for the server trust anchor: JWKS endpoint only. The issuer's keys are ephemeral and rotate at least daily, so a pinned key cannot work; the endpoint's availability is covered by last-known-good retention, its integrity by verified TLS with a pinned CA.
- Server-side `jti` tracking: yes, in a bounded in-memory cache per SPIRE Server instance, on top of the short TTL and the TLS-protected transport (the issuer leaves replay tracking to this plugin); the agent waits for a fresh token rather than present one twice.
- Server-side replay across restarts: a startup watermark rejects tokens minted before the plugin process started; replay across HA SPIRE Server instances is a documented, accepted limitation (see the trust model).
- Re-attestation cadence: SPIRE's default needs no tuning. A running SPIRE Agent re-attests when its agent SVID nears expiry (about half of the server's `agent_ttl`, i.e. roughly every 30 minutes with the default 1h), far beyond Nova's metadata cache window; a restarted agent reuses its persisted SVID. A cadence shorter than `fresh_token_timeout` would still work, but each attempt might wait for Nova to serve a fresh token. Operators may also lower Nova's `metadata_cache_expiration` to shorten those waits, at the cost of more vendordata calls to the issuer.

**Explicitly out of scope for this spec**:

- The OpenStack metadata JWT issuer that signs and serves the JWT (companion spec), beyond the contract in `pkg/iid` and the JWK Set retrieval rules above.
- Registration entry automation that consumes `openstack_iid:*` selectors to issue workload SVIDs.
- Workload-side attestors (`unix`, `docker`) and anything downstream of the agent's own SVID.
