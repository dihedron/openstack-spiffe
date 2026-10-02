# OpenStack node attestor plugins — implementation spec

Sep 20, 2026 (revised Oct 2, 2026) · @Andrea Funtò

## Overview

This spec defines a matched pair of SPIRE plugins, `openstack_iid`, that attest an OpenStack Nova instance's identity to a SPIRE Server using a short-lived signed JWT issued by the OpenStack metadata JWT issuer (`openstack-spire-metadata`, companion spec) and delivered to the instance through Nova's DynamicJSON vendordata (`vendor_data2.json`, under the `openstack_iid` target).

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

## Claim schema

The JWT is the shared contract defined once, in `pkg/iid`, and imported by both plugins and by the issuer, never hand-copied: the header (`iid.Header`) and claims (`iid.Claims`), the fixed values (`iid.Issuer` = `nova-spire-plugin`, `iid.Audience` = `spire-node-attestation`, `iid.TargetName` = `openstack_iid`, `iid.TTL` = 5 minutes, `iid.MaxTagsBytes` = 1024), the field validation rules, and the vendordata response shape (`iid.VendorDataResponse`). The authoritative example is in the issuer spec; in short:

- header: `alg`, `kid`, `typ: "JWT"`;
- payload: `iss`, `aud`, `sub` (the instance ID), `iat`, `nbf`, `exp`, `jti` (a fresh UUID per token), `project_id`, `instance_id`, `hostname`, `tags` (a flat string map);
- optional enrichment claims, present only when the issuer enables them: `availability_zone`, `flavor`, `user_id`, `project_name`, `domain_id`;
- optional operator-configured custom claims: static top-level string claims whose names never collide with the claims above.

**Forward compatibility**: `iid.Claims` collects any claim it does not model into `Custom`, so a claim added later by the issuer never breaks parsing in an older plugin; the plugins ignore claims they do not use.

**Verification rules** (server side, every one enforced, never trusted from the token):

- **Algorithms**: an explicit allowlist of RS256 (RSA, at least 2048 bits) and ES256 (ECDSA P-256), the same as the issuer's and the JWKS aggregator's. `none`, HMAC algorithms and anything else are rejected, and so is a token whose `alg` differs from the `alg` of the JWK selected by its `kid` (no algorithm confusion). `typ`, when present, must be `JWT`.
- **Issuer and audience**: `iss` must equal `iid.Issuer` and `aud` must equal `iid.Audience`, both exactly; this prevents a token minted for another consumer, or by another issuer sharing the keys, from being accepted here.
- **Lifetime**: `nbf <= iat < exp`, `exp - iat` at most `iid.TTL` (5 minutes), `nbf` and `iat` not in the future and `exp` not in the past, each within `clock_skew_tolerance`.
- **Subject**: `sub` must equal `instance_id`.
- **Field formats** (the issuer's request validation rules, part of the shared contract): `instance_id` is a canonical lowercase UUID; `project_id` is 1 to 64 characters from `[A-Za-z0-9_-]`; `hostname` is non-empty, at most 255 characters, without control characters. Both IDs end up in the SPIFFE ID path, so this check also guarantees well-formed path segments.
- **Tags**: a flat map of string values (a non-string value is rejected, never silently dropped), at most `iid.MaxTagsBytes` once serialized, and no key containing `:` (the issuer drops such keys, see selectors below; a token carrying one is a contract violation).
- **Enrichment claims**: when present, each is a non-empty string.

## Agent-side plugin

Package: `internal/plugin/agent/openstackiid`; binary `openstack-agent-plugin`, built from `cmd/openstack-agent-plugin`. Implements `nodeattestorv1.NodeAttestorServer` (the `AidAttestation` streaming RPC) plus `configv1.ConfigServer`. Started without arguments, as SPIRE Agent does, the binary serves the plugin; `openstack-agent-plugin version` prints the version information, following the project's `<object> <verb>` command line convention.

**Flow**, one round trip, no challenge/response:

1. On `AidAttestation`, HTTP GET the configured vendordata URL (default `http://169.254.169.254/openstack/latest/vendor_data2.json`). Only a `200` response of at most 1 MiB is accepted; redirects are not followed.
2. Decode the body as `iid.VendorDataResponse` and extract `openstack_iid.jwt`. If the `openstack_iid` key is missing, return a distinct error saying so: Nova omits a DynamicJSON target whose call failed (`vendordata_dynamic_failure_fatal = False`), so this almost always means the issuer was unavailable (see its `/readiness`).
3. Check that the token is a compact-serialized JWS (three non-empty, dot-separated segments). The agent does not verify the signature: it does not hold the keys, and the server verifies anyway.
4. Marshal `{"jwt": "<token>"}` as the attestation payload and send it once via `stream.Send`.
5. Drain the stream (`stream.Recv`) and return cleanly on `io.EOF` — this attestor never expects a server challenge.

**Freshness**: every attestation and re-attestation fetches a fresh token; the plugin never caches one. Nova itself may serve a cached `vendor_data2.json` for up to `[api] metadata_cache_expiration` (default 15s), so a token can be that old when fetched, well within its 5-minute TTL. A config drive is not supported as a source: its `vendor_data2.json` is written once at boot, so the token it holds expires minutes later.

**Failure handling**: if the HTTP GET fails, times out, or the response is malformed, return a wrapped error and do not send a payload. Retries/backoff are the SPIRE Agent's responsibility, not this plugin's — do not add a retry loop inside `AidAttestation`.

**Config** (`Configure` RPC), from `plugin_data`:

- `vendordata_url` (string, optional, default above)
- `http_timeout` (duration, default `5s`)

Unknown keys are errors, as in the issuer's configuration, so that typos are never silently ignored.

**Logging**: through the logger the plugin SDK provides (forwarded to SPIRE Agent's log). The token is never logged.

The plugin has no dependency on SPIRE Agent or Server internals: only `github.com/spiffe/spire-plugin-sdk` and `pkg/iid`.

## Server-side plugin

Package: `internal/plugin/server/openstackiid`; binary `openstack-server-plugin`, built from `cmd/openstack-server-plugin` (same command line conventions as the agent's). Implements `nodeattestorv1.NodeAttestorServer` (the `Attest` streaming RPC) plus `configv1.ConfigServer`.

**Flow**:

1. `stream.Recv` the agent's payload (at most 16 KiB: a valid token is a few KiB, bounded by the issuer's tags cap); unmarshal the `jwt` field.
2. Verify the JWT: look up the key by the header `kid` in the key store (see JWK Set retrieval), verify the signature, and apply every verification rule of the claim schema.
3. If `allowed_project_ids` is set, reject any `project_id` not listed.
4. Reject a `jti` already used (see replay protection), then record it.
5. On any failure, return an error immediately. Never emit an agent identity for a token that fails any check.
6. On success, build the SPIFFE ID `spiffe://<trust_domain>/spire/agent/openstack_iid/<project_id>/<instance_id>` and the selectors (see below), from verified claims only, never from anything outside the signed token.
7. Return `AgentAttributes{SpiffeId, SelectorValues, CanReattest: true}`.

Claude should keep JWT verification in its own pure, testable function (token, key set, current time and options in; verified `iid.Claims` or an error out), separate from the RPC handler and the key retrieval, so it can be unit-tested without a running SPIRE Server or HTTP endpoint.

**Trust domain**: taken from SPIRE Server's core configuration (`CoreConfiguration.TrustDomain` in the `Configure` request), not from `plugin_data`, so the plugin can never disagree with the server it runs in.

**JWK Set retrieval** (same rules as the issuer's peer aggregation and JWKS aggregator; the implementation reuses their code):

- **Polling**: at startup and then every `jwks_refresh_interval` (default 30s, the issuer's default `cache_max_age`), each fetch bounded by `jwks_fetch_timeout` (default 5s).
- **Fetch rules**: `jwks_url` is https only; TLS `tls_min_version` (`"1.2"` or `"1.3"`, default `"1.3"`) or later, verified against `jwks_ca_cert_path` or the system roots; `200` only, at most 1 MiB, a standard RFC 7517 JWK Set; redirects are never followed.
- **Key filtering**: only public keys with `use=sig` and an allowed algorithm (RS256 with RSA of at least 2048 bits, ES256 on P-256) are kept; others are left out and logged. A key carrying private key material is rejected and logged as an error, without the material. Two keys with the same kid and different material exclude that kid (fail closed).
- **Unknown kid**: the plugin re-fetches the JWK Set at once, at most once per `jwks_min_refetch_interval` (default 5s, so a flood of tokens with made-up kids cannot turn into a flood of fetches), then rejects the token if the kid is still unknown.
- **Last known good**: when a fetch fails, the keys of the last successful fetch keep being used for `jwks_stale_key_retention` (default and minimum 5m, the maximum token TTL), so in-flight tokens keep verifying during short outages. Past that, every attestation is rejected until a fetch succeeds. A failing endpoint is logged when it starts failing and when it recovers, not on every poll.

**Replay protection**: after a token passes every check, its `jti` is recorded in a bounded in-memory cache until `exp + clock_skew_tolerance`, and a token whose `jti` is already recorded is rejected. Only successful attestations are recorded, so a rejected attempt never burns a `jti`. Limits, documented in code and README:

- protection is per SPIRE Server instance: HA servers do not share the cache, so a stolen token could still be replayed once against each other server within its TTL;
- two attestations of the same agent within Nova's metadata cache window (default 15s) would present the same token, and the second is rejected; SPIRE Agent's re-attestation cadence is far longer.

**Config**, from `plugin_data`:

- `jwks_url` (string, required, https; a path ending in `/jwks/local.json` is an error, since it would serve a single replica's keys)
- `jwks_ca_cert_path` (string, optional; default: system roots)
- `tls_min_version` (`"1.2"` or `"1.3"`, default `"1.3"`)
- `jwks_refresh_interval` (duration, default `30s`)
- `jwks_fetch_timeout` (duration, default `5s`, less than `jwks_refresh_interval`)
- `jwks_min_refetch_interval` (duration, default `5s`)
- `jwks_stale_key_retention` (duration, default `5m`, at least `5m`)
- `allowed_project_ids` (array of strings, optional allowlist; reject attestation for any other project)
- `clock_skew_tolerance` (duration, default `30s`, at most `5m`)

Unknown keys are errors. The CA bundle, if set, must exist and parse at `Configure` time.

**Logging**: through the logger the plugin SDK provides. Rejections are logged with the reason, the `kid`, and the `project_id` and `instance_id` when they could be read; tokens and key material are never logged.

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
    vendordata_url = "http://169.254.169.254/openstack/latest/vendor_data2.json"
    http_timeout   = "5s"
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
  }
}
```

The binary paths are those installed by the `openstack-agent-plugin` and `openstack-server-plugin` packages. Claude should validate all fields in `Configure` and return a clear error naming the offending field (missing, unknown, malformed or out of range), rather than failing later at attestation time with an ambiguous error. Sample files live in `examples/`, kept valid by a test, as for the issuer's samples.

## Error handling and failure modes

| Failure | Agent-side behavior | Server-side behavior |
| --- | --- | --- |
| Vendordata endpoint unreachable, non-`200`, or too large | Return error from `AidAttestation`; no payload sent | N/A |
| Malformed vendordata response | Return error; no payload sent | N/A |
| `openstack_iid` target missing from the vendordata (issuer unavailable) | Return a distinct error naming the missing target; no payload sent | N/A |
| Payload malformed or larger than 16 KiB | N/A | Reject, return error |
| `alg` not allowed, or differing from the JWK's | N/A | Reject, return error, log the `alg` and `kid` |
| Unknown `kid` | N/A | Re-fetch the JWK Set (rate-limited); reject if still unknown, log the `kid` |
| JWT signature invalid | N/A (agent doesn't verify) | Reject attestation, return error, log the `kid` attempted |
| JWT expired, not yet valid, or with a lifetime over the TTL | N/A | Reject, return error |
| `iss` or `aud` mismatch | N/A | Reject, return error |
| `sub` differs from `instance_id`; malformed `instance_id`, `project_id` or `hostname` | N/A | Reject, return error |
| Tag value not a string, tag key containing `:`, or tags over the size cap | N/A | Reject, return error |
| `project_id` not in `allowed_project_ids` | N/A | Reject, return error naming the disallowed project |
| `jti` already used | N/A | Reject, return error, log the `instance_id` |
| JWK Set fetch fails | N/A | Keep using the last known good keys for `jwks_stale_key_retention`; past that, reject all attestation until a fetch succeeds |

None of these paths should panic. Every rejection must be a clean gRPC error surfaced through the plugin SDK, never a crashed plugin process — a crashed server-side plugin takes down node attestation for every agent, not just the failing one. Like the issuer, the server plugin treats unavailability as safe, never as a reason to loosen verification.

## Testing and validation

**Unit tests** (no running SPIRE needed):

- JWT verification function: valid RS256 and ES256 tokens accepted; expired, not-yet-valid, over-long lifetime, wrong `iss`, wrong `aud`, `sub` differing from `instance_id`, unknown `kid`, tampered signature, `alg: none`, an HMAC `alg`, and an `alg` differing from the JWK's all rejected.
- Claim validation: malformed IDs and hostnames, non-string tag values, tag keys containing `:` and oversized tags rejected; an unknown extra claim accepted and ignored.
- SPIFFE ID and selector construction from a fixed set of verified claims, including tags with special characters (values containing `:`) and with and without enrichment claims.
- JWK Set retrieval: key filtering, kid conflict exclusion, last-known-good retention and its expiry, a rate-limited re-fetch on an unknown kid that then succeeds.
- Replay cache: a reused `jti` rejected, a rejected attempt not recorded, entries forgotten after `exp + clock_skew_tolerance`, the cache bounded.
- Config validation: missing, unknown, malformed and out-of-range fields produce errors naming them; a non-https `jwks_url` or one ending in `/jwks/local.json` rejected.

**Integration tests**, using the plugin SDK's test harness (`plugintest`):

- Agent plugin against a mock vendordata HTTP server (success, timeout, malformed JSON, missing `openstack_iid` target, 500 response, redirect).
- Server plugin against a table of JWTs signed with test keys and a test JWKS server, covering every server-side row in the failure-modes table above.
- End-to-end with the real issuer: the issuer's test harness (`internal/metadata/integration`, with the mocked Keystone and Nova of `internal/metadata/openstacktest`) runs the signer replicas, peered or with an aggregator; a mock metadata server serves the token the signer returned for the instance; the agent plugin presents it and the server plugin verifies it against the replicas' (or the aggregator's) `/.well-known/jwks.json`, yielding the expected SPIFFE ID and selectors. Key rotation drill: tokens signed just before a rotation and just after it both attest.
- Optionally, a real SPIRE Agent and Server pair running both plugins, confirming that the resulting agent SVID carries the expected SPIFFE ID.

**Explicitly required negative tests**: a token signed with a *different* valid key (not in the JWK Set), and a token with an unlisted `project_id`, must both be rejected — these are the two cases most likely to pass by accident if selector/claim matching logic has a bug. A replayed token must be rejected on its second use.

## Build, packaging, deployment

- Both plugins live in this repository's single Go module, next to the issuer, so that all three import the same `pkg/iid`; each is its own binary (`openstack-agent-plugin`, `openstack-server-plugin`), built with `CGO_ENABLED=0` for simple, static distribution.
- Both are built against `github.com/spiffe/spire-plugin-sdk` at a pinned version, recorded in `go.mod`.
- Releases go through the existing goreleaser configuration: each plugin gets its own archive and its own `deb`, `rpm` and `apk` package, installing only its binary.
- The server plugin is deployed wherever SPIRE Server runs (a small number of hosts, standard config management), with network access to the JWK Set URL (the signer replicas' or the aggregator's load balancer).
- The agent plugin must ship inside every OpenStack instance image the agent runs on — bake it into the base image or install it via the provisioning pipeline, so it's present before SPIRE Agent starts.
- Record the SHA-256 of each installed binary and set it as `plugin_checksum` in the corresponding `.conf` file — this is a supply-chain control (SPIRE refuses to load a plugin binary whose hash doesn't match), not optional hardening. A `make checksum` target prints the SHA-256 of each plugin binary produced by the build; goreleaser's checksums file covers the release archives and packages.

## Resolved questions and out of scope

**Resolved questions** (open in the first draft):

- Static pinned key vs. JWKS endpoint for the server trust anchor: JWKS endpoint only. The issuer's keys are ephemeral and rotate at least daily, so a pinned key cannot work; the endpoint's availability is covered by last-known-good retention, its integrity by verified TLS with a pinned CA.
- Server-side `jti` tracking: yes, in a bounded in-memory cache per SPIRE Server instance, on top of the short TTL and the TLS-protected transport (the issuer leaves replay tracking to this plugin).

**Open question**:

- [ ] Re-attestation cadence: how often should the SPIRE Agent be configured to re-run this flow, given `CanReattest: true`. Any cadence works with the issuer, since every attempt fetches a fresh token; attempts more frequent than the issuer's per-instance rate limit (1/5s) or Nova's metadata cache (15s) gain nothing.

**Explicitly out of scope for this spec**:

- The OpenStack metadata JWT issuer that signs and serves the JWT (companion spec), beyond the contract in `pkg/iid` and the JWK Set retrieval rules above.
- Registration entry automation that consumes `openstack_iid:*` selectors to issue workload SVIDs.
- Workload-side attestors (`unix`, `docker`) and anything downstream of the agent's own SVID.
