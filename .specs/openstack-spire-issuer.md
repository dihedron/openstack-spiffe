# OpenStack metadata JWT issuer — implementation spec

Sep 20, 2026 (revised Oct 1, Oct 2 and Oct 4, 2026) · @Andrea Funtò

*Revision notes (Oct 4)*: security revision following the STRIDE threat model (`openstack-spire-threat-model.md`). Changes:
- Network and mTLS restrictions on `/attest`, and a cap on concurrent Keystone validations (S-3, D-2).
- Character validation of tags and enrichment claims (T-4).
- Audit records of issuance and of the key lifecycle (R-1, R-3).
- Redaction of `metadata` values (I-2).
- Protection of in-memory keys against dumps and profiles (I-4, I-5).
- Rate limits on the public endpoints (D-5).
- New configuration warnings (S-5, E-6).
- Signed releases (T-7).

Requirements introduced by this revision are tagged with the threat ID they address. They are planned and not implemented yet.

## Overview

This spec defines the OpenStack metadata JWT issuer (`openstack-spire-issuer`): the service that runs alongside Nova's dynamic vendordata mechanism and hands each booting instance a short-lived, signed JWT proving its `project_id` and `instance_id`.

This JWT is the trust root that the `openstack_iid` SPIRE node attestor pair (see the companion spec) verifies. Its correctness matters more than almost any other component in the system: every downstream SPIFFE ID and selector is only as trustworthy as this service's binding between "who is asking" and "what the token claims". The design addresses high-throughput data-plane requirements (instance boot storms), the realities of control-plane authorization, and the size of the token payload.

**Non-goals**: this spec does not cover the SPIRE agent/server plugins that consume the JWT (companion spec), nor the key management system itself (e.g. Vault) beyond how this service talks to it.

## Architecture

The system has three parts:

- **Signer replicas** (`openstack-spire-issuer service start`): several independent, share-nothing replicas behind a load balancer, the target of Nova's DynamicJSON configuration. Each replica authenticates Nova, verifies the instance, mints tokens signed with its own key, and publishes its own public keys. When its configuration lists its peers (the other replicas), a replica also acts as a JWKS aggregator: it polls its peers' public keys and serves them merged with its own (see peer aggregation). Running N replicas with each other as peers thus gives N token minters and N JWKS aggregators, with no further deployment.
- **Key store**: behind a single interface, either ephemeral in-memory keys owned by each replica (implemented first) or Vault's transit engine (later).
- **JWKS aggregator** (`openstack-spire-issuer jwks aggregate`, optional): one or more stateless instances behind their own load balancer that merge the replicas' public keys into a single JWK Set, for deployments where the SPIRE Server-side plugin should not reach the signers directly (e.g. to keep it off the Nova-facing network).

The SPIRE Server-side plugin fetches the merged JWK Set either from the signer replicas (when peers are configured) or from the JWKS aggregator.

The Nova-facing HTTP handler, the JWKS handler, the peer aggregation and the key-signing client are separate, independently testable components.

## Nova integration

This service is a Nova **DynamicJSON vendordata target**: a REST service that `nova-api-metadata` calls on the instance's behalf, not something the instance calls directly. It is invoked whenever the instance reads `vendor_data2.json` (subject to Nova's own metadata caching), so not just at boot.

**Registration** (Nova operator configuration, out of scope to change here, but this service must match it):

- `api.vendordata_providers` includes `DynamicJSON`.
- `api.vendordata_dynamic_targets` includes an entry named `openstack_iid`, e.g. `openstack_iid@https://openstack-metadata-signer.internal:8443/attest`.

**Request shape** (Nova → this service, JSON `POST`):

| Field | Content | Use |
| --- | --- | --- |
| `project-id` | The project that owns the instance | Claim, verified against Nova |
| `instance-id` | The instance UUID | Claim, verified against Nova |
| `image-id` | The boot image ID | Validated only |
| `hostname` | The instance hostname | Claim |
| `metadata` | User-supplied key/value pairs set at boot time | Source of the `tags` claim |
| `user-data` | The instance user data | Ignored: never decoded into the request model, never copied into a token, and redacted whenever a payload is logged |
| `boot-roles` | The roles of the booting user | Ignored |

**Request validation** (`400` on failure, no token issued):

- The body must be well-formed JSON of at most `max_body_bytes` (default 256 KiB: Nova forwards `user-data`, up to 64 KiB base64-encoded, together with `metadata`). Duplicate member names are rejected, so a second `instance-id` cannot be smuggled in.
- `project-id`: required, at most 64 characters from `[A-Za-z0-9_-]`.
- `instance-id`: required, a canonical lowercase UUID; other forms (uppercase, braces, `urn:` prefix) are rejected, so that an instance can never appear under two different `sub` values.
- `hostname`: required, at most 255 characters, no control characters.
- `image-id`: optional (empty for instances booted from volume).

**Response shape**: this service returns `{"jwt": "<token>"}` (`application/json`, `iid.VendorData`). Nova nests every DynamicJSON target's response under the target's name in `vendor_data2.json`, so instances find the token at `openstack_iid.jwt` (`iid.VendorDataResponse`), the fixed lookup path of the agent plugin (companion spec). The response must not repeat the target name: Nova adds it, and the token would end up at `openstack_iid.openstack_iid.jwt`, where the agent does not look (found on the lab, Oct 4). The body is a credential, so every `/attest` response carries `Cache-Control: no-store`. Only `POST` is accepted (`405` otherwise), and error responses carry the bare status text, never details.

**Nova's metadata cache**: `nova-api-metadata` caches an instance's metadata, vendordata included, for `[api] metadata_cache_expiration` (default 15s), so reads within that window return the same token. The SPIRE Server-side plugin accepts each token only once (companion spec), so the agent plugin waits, bounded, for a fresh token rather than present the same one twice. Operators may lower the cache expiration to shorten such waits, at the cost of more calls to this service.

**Processing order**: source allowlist and client certificate (see network restriction of `/attest`) → per-source rate limit and body cap → caller authentication → decoding and validation → per-instance rate limit → instance verification and enrichment → signing → audit record. Each step runs only if the previous ones succeeded, so an unauthenticated or invalid request never costs a lookup or a signature.

**Logging of rejected payloads** (I-2): a malformed or invalid body is logged truncated to 512 bytes, with `user-data` and every value of `metadata` redacted. Tenants commonly keep secrets in either of them. The `metadata` keys are kept, since they help diagnose a rejected request. Only a body that parses as a JSON object is logged this way. A payload that cannot be parsed is logged with its size and SHA-256 only, never its content, since the sensitive values cannot be located reliably in it: a member name may be escaped (`"user-data"`). An oversized body is logged only with the size cap.

## Caller authentication and request-context binding

The `project-id` and `instance-id` fields are Nova's own claims about the instance. Treating them as pre-authorized input would let anything able to reach this endpoint mint a token for an arbitrary instance ID, so this service must authenticate the caller before minting a token.

The request is made by `nova-api-metadata`, not by the user who booted the instance, so it does *not* carry the original user's Keystone token. Instead, Nova authenticates to this service with the credentials of its `[vendordata_dynamic_auth]` section and sends the resulting token in the `X-Auth-Token` header. This service must:

- reject a request without `X-Auth-Token` with `401`;
- validate the token against Keystone (`GET /v3/auth/tokens`); an invalid or expired token is rejected with `401`;
- require the token's user to be listed in `keystone.allowed_users` **and** to carry `keystone.required_role` (default `service`); otherwise reject with `403` and log the user ID (never the token);
- reject with `503` if Keystone cannot be reached;
- cache successful validations, keyed by the SHA-256 of the token, for at most `keystone.validation_cache_ttl` (default 60s) and never beyond the token's own expiry, in a bounded cache. Failures are not cached, and concurrent validations of the same token (Nova reuses its token across requests) are merged into a single Keystone request;
- run at most `keystone.max_concurrent_validations` (default 32) Keystone validations at once, across all callers (D-2). A request that would exceed the cap is rejected with `503` at once, without queueing, so a flood of distinct bogus tokens cannot be relayed to Keystone faster than the cap allows. Cache hits and requests merged into an in-flight validation do not count.

**Allowed users**: each `keystone.allowed_users` entry is either a user ID (32 or 64 lowercase hex digits, as Keystone generates them) or `name@domain`, where `domain` is the domain's name or ID. The name may itself contain `@`; the domain follows the last one. Bare names are configuration errors: user names are only unique within a domain, and a same-named user with the same role in another domain would otherwise be accepted. Names are also mutable within a domain, so a user renamed or recreated under an allowed name would be accepted too: `config check` warns about every `name@domain` entry and recommends the user ID (E-6).

**Dedicated vendordata user** (S-3): Nova's `[vendordata_dynamic_auth]` credentials should belong to a dedicated Keystone user (e.g. `nova-vendordata@Default`), configured only on the hosts running `nova-api-metadata`, and listed alone in `keystone.allowed_users`. The general `nova` service user must not be listed: its credentials are in `nova.conf` on every compute node, so any compromised hypervisor could mint a token for any instance in the cloud. The README and the Nova settings in `examples/` follow this rule.

**Service credentials**: the service validates tokens with its own credentials, taken from the `OS_*` environment variables of a standard openrc file and never from the configuration file:

- `OS_AUTH_URL`, https only (the service connects to OpenStack endpoints with `tls_min_version` or later, see TLS below);
- either `OS_USERNAME` or `OS_USER_ID` with `OS_USER_DOMAIN_NAME`/`_ID`, `OS_PASSWORD` and a project scope (`OS_PROJECT_NAME` with `OS_PROJECT_DOMAIN_NAME`/`_ID`, or `OS_PROJECT_ID`);
- or an application credential (`OS_APPLICATION_CREDENTIAL_ID` or `_NAME`, and `_SECRET`);
- optionally `OS_REGION_NAME` and `OS_INTERFACE` (`public`, `internal` or `admin`; default `public`), which select the catalog endpoints used for instance verification.

The service user needs, with default policies, the permissions to validate other users' tokens (`identity:validate_token`), to read any project (`identity:get_project`, for the `project_name` and `domain_id` enrichment) and to read any server (`os_compute_api:servers:show`, for instance verification): typically the `admin` role in the `service` project, as for the other OpenStack service users, or a dedicated role with policy overrides for these rules. It re-authenticates when its own token expires.

Trust in Nova's claims about `project-id` and `instance-id` thus rests on the authenticated identity of the compute control plane, and is independently confirmed by the instance verification described below.

### Network restriction of `/attest` (S-3, D-2)

Keystone authentication proves possession of the credentials, not that the caller is a metadata API host. Two optional, complementary controls restrict `/attest` to where Nova actually calls from. Both apply to `/attest` only. The JWKS and health endpoints stay reachable by their own consumers.

- **Source allowlist** (`attest.allowed_sources`: IP addresses or CIDR ranges): a request to `/attest` whose client address (see client address) is not covered is rejected with `403` before the per-source rate limit, before the body is read and before any Keystone call. The rejection is logged with the client address. Behind a trusted proxy, the client address is the forwarded one, so the proxy must preserve the metadata hosts' addresses. Empty (the default) means any source.
- **Client certificate** (`attest.client_ca_path`, a PEM CA bundle): when set, `/attest` requires a client certificate that chains to this bundle. A request without one, or with an invalid one, is rejected with `403` before the body is read and before any Keystone call. Since TLS requests client certificates during the handshake, before the path is known, the listener asks every client for one (`RequestClientCert`) without verifying it there; `/attest` verifies it against the bundle (chain, validity, client-authentication usage; a CA certificate is never a client's). Verifying in the handshake instead (`VerifyClientCertIfGiven`) would answer an invalid certificate with a failed handshake on every endpoint rather than a `403` from `/attest`. Peers, aggregators and the SPIRE Server keep connecting without one. Nova presents a client certificate through the keystoneauth session options `certfile` and `keyfile` of its `[vendordata_dynamic_auth]` section, which also carry the vendordata request (confirmed on the lab, Oct 5: NET-2; the README and `examples/nova.conf` document it).
- `config check` warns when neither `attest.allowed_sources` nor `attest.client_ca_path` is set. Either one confines stolen vendordata credentials to the metadata API hosts. Together, they also require the client key.

## Claim schema

The schema must match the companion `openstack_iid` node attestor spec exactly: it is a shared contract. The header and claim definitions, the fixed values (`iss`, `aud`, target name, maximum TTL, tags size cap, maximum token size `MaxTokenBytes` = 16 KiB, maximum JWK Set size `MaxJWKSKeys` = 100 keys), the reserved claim names and the field validation rules (the `project-id`, `instance-id` and `hostname` rules of request validation, which the SPIRE Server-side plugin re-applies to the claims) are defined once, in a single Go package (`pkg/iid`) imported by this service and by the SPIRE plugins, never hand-copied.

```json
{
  "header": {
    "alg": "RS256",
    "kid": "2026-09-29-signer-a-key-52331",
    "typ": "JWT"
  },
  "payload": {
    "iss": "nova-spire-plugin",
    "aud": "spire-node-attestation",
    "sub": "<instance-id>",
    "iat": 1758000000,
    "nbf": 1758000000,
    "exp": 1758000300,
    "jti": "<uuid, freshly generated per token>",
    "project_id": "<project-id from the Nova request>",
    "instance_id": "<instance-id from the Nova request>",
    "hostname": "<hostname from the Nova request>",
    "tags": { "<key>": "<value>", "...": "..." }
  }
}
```

- **TTL**: `exp - iat` is a short, fixed window: `token_ttl_seconds`, default 300 (5 minutes), never more. This service enforces it, not just documents it: it refuses to start with a longer or non-positive value. `iat` and `nbf` are the issuance time.
- **Tags and payload bloat protection**: users frequently abuse instance metadata for large cloud-init scripts. To keep JWT-bearing headers within standard HTTP limits (4–8 KB) downstream, the `tags` claim is derived from the incoming `metadata` field as follows:
  - only string values are kept; other entries are dropped (not an error);
  - keys and values that are not valid UTF-8 or that contain control characters (Unicode category `Cc`) or format characters (`Cf`, e.g. bidirectional overrides and zero-width characters) are dropped (T-4). Such characters could make selectors that look alike differ, or forge log lines. The rule is `iid.ValidateTagKey` and `iid.ValidateTagValue`, shared with the SPIRE Server-side plugin, which rejects a token carrying such a tag;
  - empty keys and keys containing `:` are dropped, since they would make the `openstack_iid:tag:<key>:<value>` selector of the SPIRE plugins ambiguous (the SPIRE Server-side plugin rejects a token carrying one);
  - if `tags.allowlist` is configured, only the listed keys are kept (an empty allowlist keeps every string entry, and `config check` warns about it);
  - the JSON-serialized `tags` object never exceeds 1024 bytes (escaping included): entries are considered in sorted key order and any entry that would not fit is dropped, so the result is deterministic and later, smaller entries can still fit;
  - every dropped entry is logged with its key (quoted and escaped, and truncated to 64 bytes) and the reason, never its value; the token is still issued.
- **Immutability**: every claim value comes exclusively from the authorized Nova request, except the operator-configured custom claims and the enrichment claims looked up from Nova and Keystone (see below). The service accepts no override of `project_id`, `instance_id` or `hostname` from any other input path.
- **Custom claims**: the operator can configure static string claims (e.g. `"country": "italy"`) in `custom_claims`; they are added as top-level claims to every token, and their values are strings. Custom claims must not use a reserved claim name (`iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `project_id`, `instance_id`, `hostname`, `tags`, and the enrichment claims `availability_zone`, `flavor`, `user_id`, `project_name`, `domain_id`). The service refuses to start if they do, and re-checks the names right before signing, so it can never emit a token where a custom claim shadows a reserved one. The JSON-serialized `custom_claims` object must not exceed 2048 bytes (escaping included), checked like the names.
- **Token size**: the compact-serialized token never exceeds `MaxTokenBytes` (16 KiB), the most the SPIRE plugins accept. The caps above (tags at 1024 bytes, custom claims at 2048, bounded IDs, hostname and enrichment values) keep a token at about 6 KiB at most; the minter still checks the size of every token it signs and, should it ever exceed the limit, refuses to issue it (`500`, logged) rather than hand out a token the SPIRE Server would reject.

## Instance verification and claim enrichment

Nova's DynamicJSON request carries only `project-id`, `instance-id`, `image-id`, `hostname`, `metadata`, `user-data` and `boot-roles`. The availability zone and other control-plane attributes are not part of it, so the service looks them up itself, with its own service credentials, before signing.

**Instance verification** (`nova_lookup.enabled`, on by default): the service fetches the server record (`GET /servers/{instance-id}` on the Nova API) and checks, against this independent source, that:

- the instance exists;
- it belongs to the `project-id` stated in the request;
- its status is one of `nova_lookup.allowed_statuses` (default: `ACTIVE`, `BUILD`, `REBOOT`, `HARD_REBOOT`, `REBUILD`, `RESIZE`, `VERIFY_RESIZE`, `MIGRATING`, `PASSWORD`).

Any mismatch is rejected with `403` and logged; no token is issued.

**Claim enrichment** (`enrich`, a list of attribute names, empty by default): each enabled attribute is added as an optional top-level claim.

| Claim | Source | Notes |
| --- | --- | --- |
| `availability_zone` | Nova server record (`OS-EXT-AZ:availability_zone`) | Requires `nova_lookup` |
| `flavor` | Nova server record (flavor `original_name`, microversion ≥ 2.47) | Requires `nova_lookup` |
| `user_id` | Nova server record (`user_id` of the booting user) | Requires `nova_lookup` |
| `project_name` | Keystone (`GET /v3/projects/{project-id}`) | |
| `domain_id` | Keystone (`GET /v3/projects/{project-id}`) | |

- Only control-plane-authoritative attributes are offered. User-controlled server attributes (name, tags, key pair) are deliberately not, since they carry no more trust than metadata.
- Compute host and hypervisor names are deliberately not offered: the token is readable from inside the guest (`vendor_data2.json`) and would disclose the physical layout to tenants.
- The enrichment claim names are reserved: custom claims cannot use them.
- **Lookups**: the Nova endpoint is taken from the service catalog (selected by `OS_REGION_NAME` and `OS_INTERFACE`, default `public`), and server records are requested with compute microversion 2.47, so that they embed the flavor's original name. Keystone is reached at `OS_AUTH_URL`. Each lookup is bounded by a timeout (5s). The Nova and Keystone lookups are independent and run concurrently, so a request waits for the slower of the two, not for their sum; this keeps the worst case within Nova's own wait for the vendordata response (`[api] vendordata_dynamic_read_timeout`, default 5s). A failed instance check is answered at once, without waiting for the Keystone lookup.
- **Caching**: to protect nova-api and Keystone during boot storms, server records are cached per instance ID for at most `nova_lookup.cache_ttl` (default 60s, never more than the token TTL, since the availability zone can change on migration or resize); project records are cached for `keystone.project_cache_ttl` (default 10m). The cached record is still checked against each request. Caches are bounded in size, failures are not cached, and concurrent lookups of the same record are merged into a single request.
- **Unknown project**: if a Keystone lookup finds no project with the request's `project-id`, the request is rejected with `403`, like an instance mismatch.
- **Failure**: if Nova or Keystone cannot be reached, the request is rejected with `503`. The service never issues a token with missing enrichment claims, or with enrichment claims staler than the TTL: an enabled attribute that is empty in the record (e.g. the availability zone of an instance not scheduled yet) is also rejected with `503`, so that Nova retries on the instance's next metadata read.
- **Value validation** (T-4): an enrichment value must be valid UTF-8, at most 255 bytes, without control or format characters (`iid.ValidateEnrichmentValue`, shared with the SPIRE Server-side plugin). Some of these values (e.g. `project_name`, a flavor name) are chosen by administrators or, for projects, by domain admins, and they end up in selectors. A value that fails is rejected with `503` and logged with the attribute name, since it is a control-plane anomaly, not a client error.

## Signing key management

This is the highest-risk component in the whole system: compromise of a signing key means anyone can mint a valid attestation for any instance ID.

**Custody**: private key material is never written to disk on the host running this service. The service signs through a key store interface (a `Sign` operation on a digest) and never exports keys. To prevent thundering-herd failures during cluster scale-ups, per-token signing requests are not routed to control-plane key managers such as Barbican. Two backends sit behind the interface:

1. **Vault transit** (`vault_transit`, recommended for enterprise persistence): signing is offloaded to a HashiCorp Vault REST API proxy (`key_store.vault_proxy_endpoint`); the private key never leaves Vault. Dual-cluster token replication and DBOS durable workflows provide the high-throughput, data-plane resilience that instance boot storms require, without writing private keys to disk.
2. **Ephemeral in-memory keys** (`ephemeral_memory`, recommended for stateless simplicity): each replica generates its key pairs entirely in memory and never persists them; if the replica restarts, it simply generates a new key. The public halves are published through the JWKS endpoint.

The `ephemeral_memory` backend is implemented first; `vault_transit` comes later behind the same interface (until then, the configuration check reports it as not supported).

**Memory protection** (I-4, I-5): with `ephemeral_memory`, process memory is the only place keys exist, so it must not leak through the usual side doors:

- At startup, before generating any key, `service start` marks the process non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`). This disables core dumps and blocks `ptrace` and `/proc/<pid>/mem` access by other processes of the same user. A failure is a startup error.
- It then locks the process memory into RAM (`mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)`), so that no page holding a key, or a temporary of a signature, is ever written to swap. Pages are locked as they are first touched, so the process uses only the memory it needs (a few MB). The kernel counts the locked *virtual* size, which the Go runtime makes large (about 1.3 GB), so the locked-memory limit must be unlimited: the signer's unit sets `LimitMEMLOCK=infinity`, which needs no capability. A failure is a startup error, naming the limit. `key_store.lock_memory: false` (default `true`) turns locking off for hosts that cannot raise the limit; `config check` warns about it, and such hosts must disable or encrypt swap.
- The systemd units set `LimitCORE=0` as a second layer against core dumps.
- CPU and heap profiling (enabled through the `*_CPU_PROFILE` and `*_MEM_PROFILE` environment variables) write their files with mode `0600`, even over an existing file. When either is enabled, `service start` logs a warning that profiles contain private key material.
- Disabled or encrypted swap on signer hosts remains good practice, as defense in depth.

*Why the whole process is locked, rather than only the keys* (assessment, Oct 5): keeping only the private keys in a pinned, unswappable area would not keep them out of swap. Go's crypto copies key material into heap and stack temporaries to sign (big-number buffers for the RSA exponentiation, the ECDSA nonce, intermediate values), Go decides where those live, and goroutine stacks move as they grow. A pinned area therefore protects the key at rest while the copies made by every signature stay swappable, unless the signing code is rewritten to work in that area, which is out of the question for constant-time RSA and ECDSA. The options considered:

| Option | Protects | Cost |
| --- | --- | --- |
| `mlockall` (chosen) | Every page the signer touches: keys, temporaries, stacks | `LimitMEMLOCK=infinity`; the process is never swapped (a few MB). Pure Go (`golang.org/x/sys/unix`), as HashiCorp Vault does |
| An arena from `memfd_secret` (Linux 5.14+, available on the lab's Ubuntu 24.04 and AlmaLinux 10 kernels), pure Go | The key at rest, even from the kernel's direct map and from root reading `/proc/<pid>/mem` | Go's crypto still copies it into ordinary memory to sign |
| CGO and OpenSSL's secure heap (a locked, guarded, non-dumpable arena) | The keys and most of OpenSSL's temporaries | `CGO_ENABLED=1`: no more static binaries, a `libcrypto` dependency in the packages, harder arm64 cross-builds, signing outside Go's memory safety; C stack temporaries still unprotected |
| The kernel keyring (`KEYCTL_PKEY_SIGN`) | The key never in user space once loaded | RS256 only (the kernel cannot sign with ECDSA); the key is generated in Go first; needs the `pkcs8_key_parser` module |
| Out of process (the planned `vault_transit` backend, an HSM, a TPM) | The key never in this process at all | A separate backend behind the key store interface, not memory hardening |

**Algorithms**: RS256 with RSA 2048-bit keys (default) or ES256 with ECDSA P-256 keys (`key_store.algorithm`).

**Rotation and retention**: keys rotate on a fixed schedule (`key_store.rotation_interval`, default 24h, at least 5 minutes) and whenever a replica restarts; restarting a replica therefore also replaces its key on suspected compromise. The previous key's public half stays in the JWKS for at least one full token TTL past rotation, so that in-flight tokens do not fail verification during the cutover.

**Access control**: with `vault_transit`, only this service's identity (not humans, not other services) may sign with the active key, and creating or rotating Vault keys is a separate, more privileged operation, documented as a runbook rather than done autonomously by this service. With `ephemeral_memory`, key generation and rotation are necessarily performed by the replica itself.

**Replica topology**: the service runs as multiple independent, share-nothing replicas, each with its own keys; their public keys are merged for the SPIRE Server by the replicas themselves (peer aggregation) or by the JWKS aggregator (see below).

- **kid**: every key gets a unique kid at creation, and every token is tagged with the kid of the key that signed it. The format is `<YYYY-MM-DD>-<replica-id>-key-<n>` (e.g. `2026-09-29-signer-a-key-52331`), where the date is the UTC date the key was generated and `n` the number of seconds since UTC midnight at that moment, bumped when needed so that it strictly increases within a process. Kids therefore never collide across replicas, nor across restarts of the same replica (a counter restarting from 1 would reuse a kid with different key material, which the aggregator would exclude).
- **replica_id** is a lowercase DNS label, unique across replicas; if not configured, it is derived from the first label of the hostname (`config check` warns about it).
- **Publication before use**: a token must never carry a kid the aggregated JWKS cannot serve yet, whether served by a peer replica or by the aggregator. Each new key is generated and published in the replica's JWKS `key_store.publish_ahead` (default 2m) before it is used for signing; `publish_ahead` must exceed `peers.poll_interval` plus `peers.fetch_timeout` plus `peers.cache_max_age` (when peers are configured), and the aggregator's `poll_interval` plus `fetch_timeout` plus `cache_max_age`. The poll and fetch terms bound how late a merged set picks up a new key; the cache term bounds how long a consumer may keep serving itself an older copy of the merged set, so that a new kid reaches the SPIRE Server before its first use without relying on its re-fetch on an unknown kid (which remains as a fallback, e.g. for a peer that was unreachable). At startup, a replica reports not ready (`/readiness` → `503`) until its first key has been published for `publish_ahead`.
- **Signing**: only the active key signs, and the token header carries its kid. If a rotation lands while a token is being signed, signing is retried once with the new active key; if it fails again, the request is rejected with `503`.
- **Key lifecycle records** (R-3): every key's transitions are logged at `info` (`dropped` at the notice level, info+2, which the syslog audit sink maps to `notice`) with `audit=key_lifecycle`, the event (`generated`, `published`, `active`, `retired`, `dropped`), the kid, the algorithm and the key's RFC 7638 JWK thumbprint (SHA-256, base64url). Ephemeral keys leave no other trace. These records are what lets an investigator later tie a kid, and the tokens it signed, to a replica, a time window and specific key material, after the replica has restarted.

## JWKS endpoints (signer replica)

Each replica exposes the public halves of its trusted signing keys on two endpoints, both standard RFC 7517 JWK Sets with one entry per key:

- **`GET /jwks/local.json`** (always): the replica's own keys only, never its peers'. This is the endpoint peer replicas and JWKS aggregators poll.
- **`GET /.well-known/jwks.json`**: without peers, exactly the same content and headers as `/jwks/local.json`, so a JWKS aggregator polling it keeps working; with peers, the local set merged with the peers' sets (see peer aggregation), the endpoint the SPIRE Server-side plugin uses.

Rules for the local set:

- **Content**: the key about to become active (published ahead), the currently active key, and any key retired within the last token TTL (5 minutes); keys past that window are excluded. Each entry carries `kid`, `kty`, `alg`, `use=sig` and the public key material only (`n`/`e` for RSA, `crv`/`x`/`y` for EC).
- **Freshness**: the content is read live from the key store, so rotations are published automatically, without any manual step.
- **Protection**: both endpoints are read-only and unauthenticated by design (public keys are not secrets), but they are served over TLS with a certificate their consumers can pin: the endpoint's own TLS identity is part of the trust chain, not an afterthought.
- **Caching headers**: the local set is served with `Cache-Control: no-cache`. Its consumers, peers and aggregators, poll it on their own schedule, and a cache in between could hide a key published ahead beyond `publish_ahead`, breaking publication before use. The merged set (with peers) is served with `Cache-Control: public, max-age=<peers.cache_max_age>` (default 30s), like the aggregator's.
- **Errors**: `GET` and `HEAD` only (`405` otherwise). If the replica's own keys cannot be read, both endpoints reply `503`; they never serve a partial set. Error responses are not cacheable (`Cache-Control: no-store`).

## Peer aggregation (signer replica)

When `peers.urls` lists the local JWKS endpoints of the other replicas, a replica polls them and serves their keys merged with its own on `/.well-known/jwks.json`, so that every replica can serve the SPIRE Server-side plugin the keys of all replicas.

- **Peer URLs**: https only, without duplicates, pointing at the peers' `/jwks/local.json`. A peer URL whose path ends in `/.well-known/jwks.json` is a configuration error: importing a peer's *merged* set would make keys circulate between replicas forever (A retires a key, B still serves it from A's last fetch, A imports it back from B, and so on). Since replicas only ever import each other's own keys, a key disappears from every merged set at most `peers.stale_key_retention` after its owner stops publishing it. The list may include the replica's own local URL, so that all replicas can share the same peer list; its own keys then come back identical and are served once.
- **Same rules as the aggregator**: polling (at startup, then every `peers.poll_interval`, all peers concurrently, each within `peers.fetch_timeout`), fetch limits (`200` only, at most 1 MiB, a JWK Set of at most `MaxJWKSKeys` keys, no redirects), TLS (`tls_min_version` or later, verified against `peers.ca_cert_path` or the system roots), key filtering (`use=sig`, allowed algorithms, private key material rejected), deduplication by kid, fail-closed conflicts, sorting by kid, retention of an unreachable peer's keys for `peers.stale_key_retention`, and logging of a failing peer when it starts failing and when it recovers: all follow the JWKS aggregator rules below.
- **Trust**: peer fetches are part of the trust chain, since anyone able to tamper with them could add a key that every replica's merged set would serve. Peers are therefore always reached over verified TLS, never with an insecure fallback. A compromised peer gains nothing it did not already have, since it can sign tokens with its own key anyway.
- **Own keys**: the replica's own keys are read live from the key store, never fetched over HTTP, and take part in conflict detection: a peer key with the same kid as an own key but different material excludes that kid (fail closed), which can only happen with a duplicated `replica_id`.
- **Readiness**: peers are not a readiness check. The merged set always holds the replica's own keys, and taking a signer out of Nova's load balancer because a peer is down would break attestation for no gain. If the SPIRE Server's load balancer picks a replica that is temporarily missing a peer's key because that peer was unreachable, the SPIRE Server-side plugin's re-fetch on an unknown kid covers it (a key published ahead is covered by the `publish_ahead` rule, see publication before use).
- **Full mesh**: each replica must list all the other replicas; a replica missing a peer in its list silently lacks that peer's keys in its merged set.

## JWKS aggregator

Since every replica signs with its own keys, the SPIRE Server-side plugin fetches the merged keys of all replicas, either from the replicas themselves (peer aggregation, above) or from a separate JWKS aggregator, which is optional and useful when the SPIRE Server should not reach the signers directly.

- **Command**: `openstack-spire-issuer jwks aggregate --config <path>`. The aggregator is stateless, so it can itself run as multiple replicas behind a load balancer; it is served over TLS (`tls_min_version`, default 1.3, or later), with the certificate the SPIRE Server operator pins.
- **Discovery**: a static list of replica JWKS URLs (`replicas`, https only), pointing at the replicas' `/jwks/local.json`. A replica's `/.well-known/jwks.json` still works, but on a replica with peers it also carries the peers' keys, which the aggregator then imports twice and drops later than needed, so `config check` warns about it.
- **Polling**: at startup and then every `poll_interval` (default 30s), all replicas are fetched concurrently, each within `fetch_timeout` (default 5s), over TLS (`tls_min_version` or later) verified against `replica_ca_cert_path` (or the system roots). A fetch fails on a non-`200` status, a response larger than 1 MiB, a body that is not a JWK Set, or a JWK Set with more than `MaxJWKSKeys` (100) entries (never truncated, which would keep an arbitrary subset; a replica publishes a handful of keys); redirects are never followed, since the configured URL itself must answer. A failing replica is logged when it starts failing and when it recovers, not on every poll.
- **Merging**: the output is a standard RFC 7517 JWK Set (not a custom map), deduplicated by kid. If two replicas, or one replica twice, publish the same kid with different key material, that kid is excluded and an error is logged on every poll while the conflict lasts (fail closed); identical duplicates are served once. Only public keys with `use=sig` and an allowed algorithm (RS256 with RSA of at least 2048 bits, ES256 on P-256) are passed through; other keys are left out and logged. A key carrying private key material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k`) is rejected and logged as an error, without the material itself; the replica's other keys are still used. The merged set is sorted by kid.
- **Unreachable replicas**: the keys from a replica's last successful fetch are kept for `stale_key_retention` (default and minimum: 5 minutes, the maximum token TTL), so in-flight tokens keep verifying during short outages. Keys a reachable replica stops publishing are dropped on its next successful fetch.
- **Endpoints**: `GET /.well-known/jwks.json` with `Cache-Control: public, max-age=<cache_max_age>` (default 30s), so consumers refresh on a reasonable schedule without hitting the endpoint on every attestation; `/liveness`; `/readiness` (ready while at least one replica has been fetched successfully within `stale_key_retention`, i.e. while the merged set holds any replica's keys; see the health endpoints).

**Requirements on the SPIRE Server-side plugin** (companion spec, which details them): fetch keys from the peered signer replicas' `/.well-known/jwks.json` or from the aggregator, never from a replica's `/jwks/local.json`, over verified TLS; select the verification key by the JWT header kid, and re-fetch the JWK Set (rate-limited) when it meets an unknown kid; keep the last known good keys for at least the maximum token TTL; and enforce `iss`, `aud` and the maximum TTL itself rather than trusting the token.

## Freshness, replay and rate limiting

Because Nova calls this service whenever the instance reads its vendordata, the service mints a brand-new token on every call rather than caching one per instance.

- **Short TTL**: 5 minutes (see the claim schema), which bounds the damage window if a token is exfiltrated in transit.
- **Fresh jti**: a new UUID for every token, even for the same instance asking again seconds later; a jti is never reused.
- **No replay tracking**: enforcing jti uniqueness is the responsibility of the downstream SPIRE Server-side plugin, which keeps a bounded in-memory cache of used jtis per SPIRE Server instance and rejects tokens minted before its process started, so that a restart does not reopen replay; replay across HA SPIRE Server instances is a documented limitation (companion spec). This service's job is to never issue two tokens with the same jti, not to police reuse downstream.
- **Two-stage rate limiting**: limits blunt any attempt to use this endpoint to exhaust the signing key store's request budget. The instance ID is only available inside the JSON body, so rate limiting happens in two stages, both answering `429`:
  1. **Before the body is read**: a per-source-IP token bucket (`rate_limit_per_source`, default 200/1s, keyed by the client address described below) in the HTTP middleware, together with a cap on the body size (`max_body_bytes`: a larger declared `Content-Length` is rejected with `400` at once, and reading an undeclared body stops at the cap), so spam is rejected cheaply without allocating memory for the payload. IPv6 sources are keyed by their /64 prefix, since a single host usually controls a whole /64 and could otherwise bypass the limit by rotating addresses.
  2. **Right after a size-capped decode**: a per-instance-ID token bucket (`rate_limit_per_instance`, default 1/5s: no more than one token every few seconds per instance), before any lookup or signing operation.

  A `429` carries a `Retry-After` header. A rate `N/period` allows bursts of up to N requests and refills N tokens per period. Limits are enforced per replica, since replicas share nothing.

  **Public endpoints** (D-5): `/jwks/local.json`, `/.well-known/jwks.json`, `/liveness` and `/readiness` are unauthenticated, so they get their own per-source token bucket, `rate_limit_per_source_public` (default 50/1s, keyed by the same client address), separate from the `/attest` bucket. A flood against them can therefore never starve Nova's calls. The aggregator limits its own endpoints the same way. It has its own `rate_limit_per_source` (default 50/1s) and `client_address` settings, with the signer's semantics. Their consumers (peers, aggregators, SPIRE Servers, probes) poll at most a few times a minute, far below the limit. The number of tracked keys is bounded: buckets that have refilled completely are forgotten, and if the bound is still reached, an arbitrary bucket is evicted (its key starts over with a full bucket), so a flood of distinct sources can neither exhaust memory nor lock out every new source.

### Client address

The client address keys the per-source rate limit and identifies the caller in logs. How it is determined depends on the deployment:

- **Not proxied** (`client_address.trusted_proxies` empty, the default): replicas are reached directly, or through a load balancer that preserves the client's address (e.g. layer-4 pass-through). The client address is the TCP peer address; forwarding headers are ignored, so a client cannot choose its own rate-limiting key.
- **Proxied** (`client_address.trusted_proxies` lists the addresses or CIDR ranges of the reverse proxies or load balancers in front of the replicas): for a request whose TCP peer is a trusted proxy, the client address is taken from the `client_address.header` header (default `X-Forwarded-For`); for any other peer, the header is ignored and the peer address is used, exactly as when not proxied.
  - `X-Forwarded-For`, and any header holding a comma-separated list of addresses, is read from the right, skipping the addresses of trusted proxies: the first address that is not a trusted proxy is the client address. Entries further left were supplied by the client and are never trusted. Several `X-Forwarded-For` headers count as one list, in order.
  - Any other header (e.g. `X-Real-IP`) must hold a single address, set by the trusted proxy.
  - If the header is missing, empty or malformed, or holds only trusted proxies, the client address is the proxy's own address (logged at debug level), so such requests share the proxy's bucket instead of escaping the limit.
  - The proxies must set or append the header themselves, and the replicas must only be reachable through them; otherwise the per-source limit can be bypassed.

## API surface

**Signer endpoints**:

| Method | Path | Called by | Purpose |
| --- | --- | --- | --- |
| `POST` | `/attest` | Nova (DynamicJSON target) | Issue a signed JWT for the requesting instance |
| `GET` | `/jwks/local.json` | Peer replicas, JWKS aggregator | Fetch this replica's own current trusted public keys |
| `GET` | `/.well-known/jwks.json` | SPIRE Server-side plugin (with peers), JWKS aggregator (without) | Fetch this replica's keys merged with its peers' (with peers), or its own keys (without) |
| `GET` | `/liveness` | Orchestrator | HTTP server process check, used to restart crashed pods |
| `GET` | `/readiness` | Orchestrator / load balancer | Dependency and key store connectivity check, used to route traffic; also not ready until the first key has been published for `publish_ahead` |

**Aggregator endpoints**: `GET /.well-known/jwks.json` (called by the SPIRE Server-side plugin), `/liveness` and `/readiness` (see above).

**TLS**: each service's `tls_min_version` (`"1.2"` or `"1.3"`, default `"1.3"`) is the minimum TLS version of both its HTTPS server and the connections it makes: the signer's to Keystone, Nova and its peers, the aggregator's to the replicas. `"1.3"` is recommended; `"1.2"` exists for peers that cannot negotiate TLS 1.3 (e.g. an older load balancer in front of the OpenStack APIs) and makes `config check` warn. Any other value is an error.

**Logging**: structured logs (`log/slog`, text format) go to standard error at level `info` by default; `OPENSTACK_SPIRE_ISSUER_LOG_LEVEL` selects `debug`, `info`, `warn`, `error` or `off`, and `OPENSTACK_SPIRE_ISSUER_LOG_STREAM` selects `stderr`, `stdout` or `file`. The level applies to ordinary records only: audit records (those carrying an `audit` attribute) are always written to the regular stream, whatever the level, `off` included, so that turning operational logging down never removes the audit trail. Audit records can additionally go to syslog (see the syslog audit sink below). Tokens, keys, credentials, `user-data` and `metadata` values are never logged.

**Issuance audit** (R-1): every issued token produces exactly one `info` record, `token issued`, with `audit=token_issued`, written after the response has been encoded and before it is sent. Its fields are:
- `request_id`
- the caller's Keystone user ID
- the client address, and the TCP peer address when it differs
- the client certificate's subject and serial, when one was presented
- `project_id`, `instance_id`, `jti`, `kid`, `iat` and `exp`

The token itself is never part of it. Together with the SPIRE Server-side plugin's `agent attested` record, which carries the same `jti`, it traces every attestation back to the Nova call, the replica and the key that produced it. It also makes tokens minted with stolen credentials (S-3) visible as issuances without a matching metadata request. Operators should ship these records to a central, append-only log store, which the syslog audit sink below makes straightforward.

**Syslog audit sink** (R-1, R-3): besides the regular log, audit records can be sent to the local syslog daemon, from which rsyslog or syslog-ng forward them to a central store. Only audit records go there: the records carrying an `audit` attribute (`token_issued`, `key_lifecycle`). The regular log stays on the stream selected by `OPENSTACK_SPIRE_ISSUER_LOG_STREAM`, and audit records keep appearing in it too.

- **Configuration**: `audit.syslog.enabled` (default `false`), `audit.syslog.socket` (default `/dev/log`, a Unix datagram socket), `audit.syslog.facility` (default `authpriv`, or one of `auth`, `daemon`, `local0` to `local7`), and `audit.syslog.app_name` (default `openstack-spire-issuer`). It is enabled in the configuration file rather than the environment, because it is part of the security configuration and `config check` must see it. `config check` warns when it is disabled. `service start` refuses to start when it is enabled and the socket cannot be opened.
- **Format**: RFC 3164, in the form glibc's `syslog()` sends to a local socket: `<PRI>Mmm dd hh:mm:ss TAG[PID]: MSG`, without a hostname.
  - `TAG` is `app_name` and `PID` the process ID: journald, which provides `/dev/log` under systemd, records them as `SYSLOG_IDENTIFIER` and `SYSLOG_PID`, and rsyslog parses them too. RFC 5424 was the first choice, but journald does not parse it: the whole header ends up in the message text, with no identifier (found on the lab, Oct 4).
  - `MSG` is a single-line JSON object holding the record's message, its level, its exact time (`time`, RFC 3339 with nanoseconds: the RFC 3164 timestamp has neither year nor fraction), the audit kind (`audit`: `token_issued`, `key_lifecycle`) and all its attributes, with the same keys as in the regular log (`request_id`, `jti`, `kid`, ...).
  - `pkg/syslog` still offers RFC 5424 (`syslog.WithFormat`) for syslog daemons that own the socket and understand it; the audit sink does not use it.
- **Severity**: `info` for `token_issued` and for `key_lifecycle` events, except `notice` for `dropped`. Never `emerg` or `alert`, which journald forwards to every terminal.
- **Delivery never blocks issuance**:
  - A bounded queue (1024 records) feeds the socket from a dedicated goroutine.
  - When the queue is full, records are dropped and counted. The count is logged on the regular log when dropping starts and when it stops, never once per record.
  - A send that fails redials the socket once, so a restart of journald or rsyslog loses at most the record in flight.
  - Each send is bounded by a 1s timeout.
  - On `SIGTERM` the queue is drained within the graceful shutdown.

  Audit records are best effort, never a reason to refuse a token: the copy in the regular log remains.
- **Size**: a record never exceeds 8 KiB once serialized (Unix datagram sockets reject larger ones). The audit records defined here are well below that. A larger one is truncated on a UTF-8 character boundary and marked `"truncated": true`.
- **Content**: the same rule as the regular log. Tokens, keys, credentials, `user-data` and `metadata` values are never part of an audit record.
- **Under systemd**: the units already allow `AF_UNIX`. `PrivateDevices=yes` keeps the `/dev/log` symlink to journald's socket. Since that is systemd behaviour rather than this service's, the lab (`test/lab/lab.sh`, see `openstack-spire-test-environment.md`) confirms delivery under the packaged unit.

The sink is implemented by `pkg/syslog`, shared with the SPIRE Server-side plugin (companion spec). Before it is used, that package needs these fixes:
- A structured-data parameter without `=` is an error, not a panic.
- Every message is validated (facility, severity, header fields, structured-data names) before it is sent, in RFC 3164 (the default) or RFC 5424. The package implements the parts of both RFCs it needs itself, without a third-party dependency.
- Structured data is serialized in sorted order. It is not used by the audit sink, but stays available for callers that have an enterprise number.
- The connection is redialed once after a failed send, and the client gets a `Close` method.
- The socket path, size cap and send timeout are options.
- The default app name is the binary's base name, not `os.Args[0]`.
- The package returns errors without logging them.
- An `AuditHandler` (a `slog.Handler`) forwards only records carrying an `audit` attribute, through the queue above. It is combined with the regular handler, so a single `slog` call writes to both.
- Its tests run against a temporary Unix datagram socket, never the host's `/dev/log`, and never send `emerg`.

**Request IDs**: every response carries an `X-Request-Id` header with a random ID generated by the service (incoming values are ignored), and every log record written while handling the request carries it as `request_id`.

**Health endpoints** (signer and aggregator; `GET` and `HEAD` only, `Cache-Control: no-store`, unauthenticated):

- `/liveness` answers `200` as long as the HTTP server is serving.
- `/readiness` answers `200` only if every readiness check passed in its latest run, else `503`. The checks run in the background, concurrently, every 5 seconds, each bounded by a 2-second timeout; probes are answered at once from the latest results, so they never wait on a dependency (orchestrators' probe timeouts are often shorter than a dependency check), and dependencies are checked at a fixed rate however often the endpoint is probed. The service is not ready before the first run completes, nor when the latest results are older than three intervals.
- Aggregator check: `replicas` (at least one replica fetched within `stale_key_retention`).
- Signer checks: `key_store` (the key store can sign, which includes the publish-ahead gate at startup), `keystone` (Keystone is reachable and accepts the service's token; an expired service token is renewed, not reported), and `nova` when `nova_lookup.enabled` (the Nova API is reachable). Peers are deliberately not a signer check (see peer aggregation).
- The JSON body gives the overall status and each check as `ok`, `failing` or `pending`, never error details, which are logged when a check changes state (not on every run).

**Command line** (object/verb convention):

- `openstack-spire-issuer service start --config <path>`: run a signer replica. It refuses to start (exit code 1) on any configuration error (the pre-flight check includes the file checks of `config check`), missing or invalid `OS_*` credentials, a failed Keystone authentication or an unusable TLS certificate, and logs configuration warnings. It serves HTTPS with TLS `tls_min_version` or later and bounded timeouts (read header 5s, read 15s, write 30s, idle 2m; headers at most 64 KiB), and on `SIGINT` or `SIGTERM` stops accepting connections and lets in-flight requests complete for up to 15 seconds.
- `openstack-spire-issuer jwks aggregate --config <path>`: run the JWKS aggregator. Like `service start`, it refuses to start on any configuration error, file checks included, logs configuration warnings, serves TLS `tls_min_version` or later with the same timeouts, and shuts down gracefully on `SIGINT` or `SIGTERM`.
- `openstack-spire-issuer config check ...`: validate configuration files (see below).

## Configuration

**Signer** (values shown are the defaults where one exists):

```yaml
listen_addr: "0.0.0.0:8443"
tls_min_version: "1.3"                                  # or "1.2" (server and OpenStack connections)
tls_cert_path: "/etc/openstack-spire-issuer/tls.crt"    # required
tls_key_path: "/etc/openstack-spire-issuer/tls.key"     # required
replica_id: "signer-a"                                  # default: first label of the hostname
key_store:
  backend: "ephemeral_memory"                           # or "vault_transit" (later)
  algorithm: "RS256"                                    # or "ES256"
  rotation_interval: "24h"                              # at least 5m
  publish_ahead: "2m"                                   # > poll_interval + fetch_timeout + cache_max_age of peers and aggregator
  lock_memory: true                                     # lock the process memory into RAM (I-4); false: warning
  vault_proxy_endpoint: "https://vault-proxy.internal:8200"  # vault_transit only
token_ttl_seconds: 300                                  # at most 300
rate_limit_per_instance: "1/5s"
rate_limit_per_source: "200/1s"
rate_limit_per_source_public: "50/1s"                   # JWKS and health endpoints (D-5)
max_body_bytes: 262144
attest:                                                 # restrictions on /attest only (S-3)
  allowed_sources: ["10.0.20.0/24"]                     # default: any; the metadata API hosts
  client_ca_path: "/etc/openstack-spire-issuer/nova-client-ca.pem"  # optional; requires a Nova client certificate
client_address:
  trusted_proxies: ["10.0.10.0/24"]                     # default: none (not proxied)
  header: "X-Forwarded-For"                             # used only for trusted proxies
custom_claims:                                          # static string claims, no reserved names
  country: "italy"
tags:
  allowlist: ["role", "env"]                            # empty: every string entry
keystone:
  allowed_users: ["3f2a9c1e5b7d4a8e9f0c1b2a3d4e5f60"]   # required: user IDs (recommended) or name@domain; a dedicated vendordata user, never nova
  required_role: "service"
  validation_cache_ttl: "60s"
  max_concurrent_validations: 32                        # D-2
  project_cache_ttl: "10m"
  ca_cert_path: "/etc/ssl/openstack-ca.pem"             # optional
nova_lookup:
  enabled: true
  cache_ttl: "60s"                                      # at most the token TTL
  allowed_statuses: ["ACTIVE", "BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "RESIZE", "VERIFY_RESIZE", "MIGRATING", "PASSWORD"]
enrich: ["availability_zone", "flavor", "user_id", "project_name", "domain_id"]  # default: none
audit:
  syslog:                                               # audit records only (R-1, R-3)
    enabled: true                                       # default: false (warning)
    socket: "/dev/log"
    facility: "authpriv"                                # auth, authpriv, daemon, local0..local7
    app_name: "openstack-spire-issuer"
peers:                                                  # default: none (no peer aggregation)
  urls:                                                 # https only, the peers' /jwks/local.json
    - "https://signer-b.internal:8443/jwks/local.json"
    - "https://signer-c.internal:8443/jwks/local.json"
  ca_cert_path: "/etc/ssl/signer-ca.pem"                # optional; default: system roots
  poll_interval: "30s"
  fetch_timeout: "5s"                                   # < poll_interval
  stale_key_retention: "5m"                             # at least 5m
  cache_max_age: "30s"                                  # whole seconds
```

The service's OpenStack credentials never appear in this file: they come from the `OS_*` environment variables (see caller authentication).

**Aggregator**:

```yaml
listen_addr: "0.0.0.0:8444"
tls_min_version: "1.3"                                 # or "1.2" (server and replica connections)
tls_cert_path: "/etc/openstack-spire-issuer/aggregator-tls.crt" # required
tls_key_path: "/etc/openstack-spire-issuer/aggregator-tls.key" # required
replicas:                                              # required, https only
  - "https://signer-a.internal:8443/jwks/local.json"
  - "https://signer-b.internal:8443/jwks/local.json"
poll_interval: "30s"
fetch_timeout: "5s"
replica_ca_cert_path: "/etc/ssl/signer-ca.pem"         # optional (warning when unset)
stale_key_retention: "5m"                              # at least 5m
cache_max_age: "30s"                                   # whole seconds
rate_limit_per_source: "50/1s"                         # D-5
client_address:                                        # as for the signer
  trusted_proxies: []
  header: "X-Forwarded-For"
```

Unknown keys are errors in both files, so that typos are never silently ignored.

## Configuration validation

The binary provides a command to validate configuration files before deployment (e.g. in CI or a pre-rollout hook), applying the same rules the services apply at startup:

```
openstack-spire-issuer config check [--signer PATH]... [--aggregator PATH] [--format text|json|yaml] [--strict] [--skip-files] [--print-effective]
```

- **Complete report**: all findings are reported in a single run, each with file, line, YAML path, severity (error or warning) and message; the command never stops at the first problem.
- **Unknown keys** are errors and carry a "did you mean ...?" suggestion when a known key is close (e.g. `rate_limt_per_instance`).
- **Invalid values** (wrong types, malformed durations or rates) and **rule violations** (ranges, required values, reserved custom claim names, `custom_claims` over 2048 serialized bytes, enrichment requiring `nova_lookup`, `allowed_users` entries that are neither user IDs nor `name@domain`, `trusted_proxies` entries that are neither IP addresses nor CIDR ranges, an empty or invalid `client_address.header`, a `tls_min_version` other than `"1.2"` or `"1.3"`, a non-https or duplicate peer URL, a peer URL whose path ends in `/.well-known/jwks.json`, `peers` ranges as for the aggregator's corresponding keys, ...) are errors.
- **Peer consistency** (within a signer file): when peers are configured, `key_store.publish_ahead` must exceed `peers.poll_interval` plus `peers.fetch_timeout` plus `peers.cache_max_age`.
- **Cross-file consistency**: when an aggregator file is given, each signer's `key_store.publish_ahead` must exceed the aggregator's `poll_interval` plus `fetch_timeout` plus `cache_max_age` (otherwise tokens could carry a kid the aggregated JWKS does not publish yet), and the aggregator's `stale_key_retention` must be at least each signer's token TTL (always true, since the aggregator itself requires at least the maximum token TTL). `replica_id` must be unique across all signer files.
- **File checks** (skippable with `--skip-files`): TLS certificate and key exist, parse and match; the certificate is not expired; CA bundles (`peers.ca_cert_path` included) parse. A certificate expiring within 30 days and a private key readable by group or others are warnings.
- **Warnings** flag valid but risky settings: `tls_min_version` set to `"1.2"`, instance verification disabled, no tags allowlist, keys ignored by the selected backend, `client_address.header` set without `trusted_proxies` (ignored), `trusted_proxies` covering every address (e.g. `0.0.0.0/0` or `::/0`, which lets any client choose its rate-limiting key), `replica_id` derived from the hostname, a per-instance rate limit looser than 1/5s, `peers` keys set without `peers.urls` (ignored), an aggregator replica URL whose path ends in `/.well-known/jwks.json` (see the JWKS aggregator). This revision adds:
  - neither `attest.allowed_sources` nor `attest.client_ca_path` set (S-3);
  - `attest.allowed_sources` covering every address (S-3);
  - an `allowed_users` entry given as `name@domain` rather than a user ID (E-6);
  - an `allowed_users` entry whose name is `nova` (S-3);
  - `peers.urls` set without `peers.ca_cert_path`, or an aggregator without `replica_ca_cert_path`, which trusts every public CA for the JWKS fetches (S-5).
- **Errors added by this revision**: `attest.allowed_sources` entries that are neither IP addresses nor CIDR ranges; an unparseable `attest.client_ca_path` (file check); `keystone.max_concurrent_validations` below 1; a malformed `rate_limit_per_source_public`; an unknown `audit.syslog.facility`; an `audit.syslog.app_name` that is not 1 to 48 printable ASCII characters (the syslog tag, within RFC 5424's `APP-NAME` limits). `audit.syslog.enabled: false` is a warning (R-1).
- **Exit codes**: 0 when there are no errors (warnings allowed), 1 on errors (or on warnings with `--strict`), 2 when a file cannot be read or the command line is invalid.
- The services run the same checks at startup, file checks included, as a pre-flight check: they refuse to start on any error (e.g. a missing, mismatched or expired TLS certificate, or an unparseable CA bundle) and log the warnings.

## Error handling and failure modes

| Failure | Behavior |
| --- | --- |
| `/attest` from a source outside `attest.allowed_sources`, or without a valid client certificate when `attest.client_ca_path` is set | Reject with `403` *before* the body is read and before any Keystone call; log the client address |
| Per-source rate limit exceeded | Reject with `429` *before* the body is read |
| Public endpoint per-source limit exceeded | Reject with `429` and `Retry-After` |
| `keystone.max_concurrent_validations` reached | Reject with `503`, do not queue |
| Malformed, oversized or invalid request body | Reject with `400`; log the payload truncated and with `user-data` redacted |
| Missing `X-Auth-Token`, or invalid/expired token | Reject with `401`, do not sign |
| Token user not in `keystone.allowed_users` or lacking `keystone.required_role` | Reject with `403`, do not sign, log the user ID (never the token) |
| Keystone unreachable while authenticating the caller | Reject with `503` |
| Per-instance rate limit exceeded | Reject with `429` before any lookup or signing |
| Instance not found, owned by another project, or in a disallowed status; project not found | Reject with `403`, do not sign, log the mismatch |
| Nova API / Keystone unreachable during verification or enrichment, or an enabled enrichment attribute missing from the record or failing value validation | Reject with `503` |
| Key store / Vault proxy unreachable | Reject with `503`; Nova omits this target from the metadata response, and the instance retries on its next metadata poll |
| Signing fails for any other reason (e.g. a custom claim colliding with a reserved name, or a token over `MaxTokenBytes`) | Reject with `500` |

A failure must never fall back to issuing an unsigned, weakly signed or partial token: every rejection path ends in "no token issued", never a degraded one. The service treats unavailability as safe, never as a reason to loosen verification.

**Operational warning**: while an instance retries a missing metadata target on its next poll, cloud-init configures the host during the initial local boot sequence. If a `503` (e.g. a key store failure) causes the JWT to be omitted during this exact window, downstream SPIRE-dependent systemd units will fail. Operators must monitor `/readiness` strictly, since transient failures break attestation for newly booting instances.

## Testing and validation

**Unit tests**:

- Claim construction from a valid Nova request body, including `tags` filtering: non-string values and keys containing `:` dropped, the allowlist applied, the strict size limit enforced.
- Request validation rejects malformed bodies, duplicate members and non-canonical instance IDs.
- Instance verification rejects unknown instances, project mismatches and disallowed statuses; enrichment claims appear only when enabled; lookups are served from cache within the TTL.
- The kid correctly reflects the active (in-memory or Vault-backed) signing key on every issued token.
- kid format and uniqueness across replicas; a new key is published before it is used; readiness stays false until the first key has been published for `publish_ahead`.
- The JWKS response includes the key published ahead, the active key and any key still within its post-rotation retention window, and excludes keys past it.
- The aggregator merges replica key sets, excludes conflicting kids, retains an unreachable replica's keys for `stale_key_retention` and then drops them; a replica set with more than `MaxJWKSKeys` keys is a failed fetch.
- The minter refuses to issue a token over `MaxTokenBytes`; the configuration check rejects `custom_claims` over 2048 serialized bytes.
- `/jwks/local.json` never contains peer keys; without peers, `/.well-known/jwks.json` serves the same content and headers as `/jwks/local.json`.
- Peer aggregation: the merged set always includes the replica's own keys, even with every peer unreachable, and readiness is unaffected; a peer kid that conflicts with an own kid is excluded; a peer URL whose path ends in `/.well-known/jwks.json` is rejected by the configuration check; with two replicas polling each other's local set, a key one of them retires disappears from both merged sets instead of circulating between them.
- The configuration check reports every finding of a broken file in one run, with correct lines.
- Tags (T-4): keys and values with control characters, format characters (e.g. U+202E) or invalid UTF-8 are dropped and logged by key only. An enrichment value failing `iid.ValidateEnrichmentValue` gives `503`.
- Redaction (I-2): `metadata` values are redacted and keys kept. An unparseable payload is logged with size and hash only, including one with an escaped `"user-data"` member name.
- Audit (R-1, R-3): a successful request produces exactly one `token issued` record whose `jti` and `kid` equal the token's, and no token in it. Every rotation produces `generated`, `published`, `active` and `retired` records with the key's thumbprint.
- Keystone cap (D-2): with `max_concurrent_validations` validations in flight, the next distinct token gets `503` at once, while a cached or merged token is still served.
- Configuration check: the new warnings and errors of this revision.
- Syslog audit sink, against a temporary Unix datagram socket:
  - an issued token yields exactly one RFC 3164 datagram with the configured facility, severity `info`, `app_name` as its tag and a JSON `MSG` whose `audit` is `token_issued` and whose `jti` equals the token's;
  - non-audit records never reach the socket;
  - a full queue drops and counts records without blocking the request;
  - a closed and recreated socket is redialed;
  - an oversized record is truncated on a character boundary.
- `pkg/syslog`: a parameter without `=` returns an error; an invalid message is refused before sending; structured data is serialized in sorted order.

**Security integration tests** (this revision):

- Source allowlist (S-3): a request with a valid Nova token from a source outside `attest.allowed_sources` is rejected with `403`. Neither the body is read nor Keystone called.
- Client certificate (S-3): with `attest.client_ca_path` set, `/attest` without a client certificate, or with one from another CA, is rejected with `403`. With a valid one it succeeds, and `/.well-known/jwks.json` still answers clients without a certificate.
- Public endpoint limit (D-5): a burst over `rate_limit_per_source_public` on `/.well-known/jwks.json` gets `429`, while `/attest` from the same source is unaffected.
- Non-dumpable signer (I-4): `/proc/self/status` of a running `service start` shows it is not dumpable (Linux only).

**Integration tests**:

- **Required negative test**: a request with a well-formed body but no `X-Auth-Token` is rejected with `401` and nothing is signed. This is the test that most directly validates the request-context binding the whole design depends on.
- Keystone token validation accepts the allowlisted service user carrying the required role and rejects arbitrary user tokens (`401`/`403`).
- Full request against the key store backend (real or fully mocked): request in, valid signed JWT out, signature verifiable against the JWKS endpoint's own output.
- Rate limiting: the middleware answers `429` without reading the body; a burst from one instance ID gets `429` after the configured threshold, while a different instance ID is unaffected.
- Client address: without trusted proxies, a forged `X-Forwarded-For` does not change the rate-limiting key; behind a trusted proxy, clients with different forwarded addresses get separate buckets, while addresses prepended by the client itself are ignored.
- End-to-end with two signer replicas and one aggregator: a token from either replica verifies against the aggregated JWKS by kid. Key rotation drill: after a rotation, tokens signed just before it still verify, and new tokens carry the new kid, which the aggregate publishes before its first use.
- End-to-end with three signer replicas, each listing the other two as peers, and no aggregator: a token from any replica verifies by kid against every replica's `/.well-known/jwks.json`, also across a key rotation, and every replica's `/jwks/local.json` carries only its own keys.

## Build, packaging, deployment

- A standalone HTTP service written in Go, for consistency with the SPIRE plugins of the companion specs.
- **Supported CPUs**: linux/amd64 and linux/arm64. The amd64 builds come in three levels: the baseline (`GOAMD64=v1`), which runs on any x86-64 CPU and has unsuffixed artifact names, and two optimized variants suffixed `v2` and `v3`. The baseline is the default everywhere, including in the lab; nothing in the design requires a particular CPU level. The same holds for the SPIRE plugins (companion spec).
- Deployed close to the Nova control plane's network segment, since `nova-api-metadata` must reach it on every vendordata request; its availability is coupled to that of the metadata service. It runs as several share-nothing signer replicas behind a load balancer (the target of Nova's DynamicJSON configuration), in one of two topologies:
  - **Peered signers**: each replica lists all the others as peers, and the SPIRE Server-side plugin fetches `/.well-known/jwks.json` through a load balancer in front of the replicas, pinning the signers' certificate. No other deployment is needed.
  - **Signers plus aggregator**: one or more JWKS aggregator instances behind their own load balancer poll the replicas' `/jwks/local.json` and serve the SPIRE Server-side plugin, for when it must not reach the Nova-facing network.

  The signer's load balancer either preserves client addresses, or is listed in `client_address.trusted_proxies` and forwards them in `client_address.header` (see client address).
- No private key material is ever written to the deployment host's disk. The only secrets the service holds locally are its client credentials (Keystone `OS_*` variables, and the Vault credentials once `vault_transit` exists); they come from the platform's standard secret-injection mechanism, never baked into the image.
- Annotated sample configurations (signer, with peers, aggregator, `OS_*` credentials template and the Nova settings) live in `examples/`, and a test keeps the signer and aggregator samples valid, cross-file checks included; the README documents deployment, OpenStack setup and tuning.
- **System packages and systemd.** goreleaser builds a `deb` and an `rpm` package (no `apk`: the services are not meant to run on Alpine). Besides the binary (`/usr/bin/openstack-spire-issuer`), the package installs:
  - two systemd units in `/usr/lib/systemd/system/`: `openstack-spire-issuer.service` runs a signer replica (`service start --config /etc/openstack-spire-issuer/signer.yaml`, credentials from `EnvironmentFile=/etc/openstack-spire-issuer/signer.env`), and `openstack-spire-issuer-aggregator.service` runs the JWKS aggregator (`jwks aggregate --config /etc/openstack-spire-issuer/aggregator.yaml`);
  - the sample `signer.yaml`, `aggregator.yaml` and `signer.env` in `/etc/openstack-spire-issuer/` as configuration files the package manager never overwrites, mode `0640`, owned by `root:openstack-spire-issuer`; the directory itself is mode `0750` with the same ownership.

  Both units are installed **disabled** and stopped: no package script enables or starts them, since the samples are not a working configuration. The operator configures the replica, installs its TLS certificate and key (key mode `0600`, owned by `openstack-spire-issuer`), and runs `systemctl enable --now` on the unit(s) it needs. The package scripts:
  - create the locked system user and group `openstack-spire-issuer` (no home, no login shell) before installation;
  - after installation, reload systemd and restart only the units that were running, so an upgrade picks up the new binary while a fresh install starts nothing;
  - before removal (not on upgrade), stop and disable both units, and reload systemd afterwards. The user is kept, so that files it owns stay attributed.

  The units run as `openstack-spire-issuer` with no capabilities (the default ports are unprivileged) and a read-only view of the system (`ProtectSystem=strict` and related hardening), and with core dumps disabled (`LimitCORE=0`, I-4); the signer's unit also lifts the locked-memory limit (`LimitMEMLOCK=infinity`), which memory locking needs. They restart on failure after 5 seconds, and allow 30 seconds to stop, above the 15-second graceful drain. Logs go to standard error and thus to the journal; file logging and profiling, which write to the working directory, are not supported under the units.
- **Signed releases** (T-7): goreleaser signs the release checksums file, which covers every archive and package, together with the SBOMs. The deb and rpm packages are also signed with the project's packaging key, so that `apt` and `dnf` verify them natively. The signing method (cosign keyless through the CI's OIDC identity, or a GPG key held by CI) is chosen at implementation time. The README documents how to verify the signature before installing. For the SPIRE plugins, verification comes before computing `plugin_checksum` (companion spec).
- Separate `/liveness` and `/readiness` probes: readiness verifies connectivity to the service's dependencies (key store included), not just process liveness, so that orchestrators take a replica out of load-balancer rotation during backend disruptions without crash-looping the pods.

## Implementation plan for the Oct 4 security revision

Planned and not implemented yet. Tests come first, as for every change.

| Area | Change | Threats |
| --- | --- | --- |
| `pkg/iid` | `ValidateTagValue`, `ValidateEnrichmentValue`, and control, format and UTF-8 checks in `ValidateTagKey`. `ValidateKeyID` (used by the server plugin) | T-4, T-5 |
| `internal/metadata/config` | `attest` block, `rate_limit_per_source_public`, `keystone.max_concurrent_validations`, aggregator `rate_limit_per_source` and `client_address`; the new errors and warnings; file check of `attest.client_ca_path` | S-3, S-5, D-2, D-5, E-6 |
| `internal/metadata/server/signer.go`, `serve.go`, `aggregator.go` | Source-allowlist middleware and `/attest`-only client certificate enforcement ahead of the per-source limit; `VerifyClientCertIfGiven` with the client CA pool in the TLS config; a public per-source limiter on every other route | S-3, D-2, D-5 |
| `internal/metadata/auth` | Non-blocking semaphore around Keystone validations, outside the merge of identical tokens; `503` when full | D-2 |
| `internal/metadata/claims` | Drop tags failing the new checks; validate enrichment values | T-4 |
| `internal/metadata/attest` | `token issued` audit record, which needs the minter to return the `jti`, `kid`, `iat` and `exp`, and the authenticator to put the caller's user ID in the request context; `metadata` redaction, and the size-and-hash fallback in `redact.go` | R-1, I-2 |
| `internal/metadata/keystore` | Key lifecycle records with RFC 7638 thumbprints | R-3 |
| `cmd/openstack-spire-issuer` | `PR_SET_DUMPABLE` and `mlockall` at `service start` (via `golang.org/x/sys/unix`, Linux only; `key_store.lock_memory`); profiles created `0600` in both `cmd/*/init.go` that profile, plus a key-material warning | I-4, I-5 |
| `packaging/systemd` | `LimitCORE=0` in both units, `LimitMEMLOCK=infinity` in the signer's | I-4 |
| `.goreleaser.yaml`, README | Signed checksums, SBOMs and packages; verification instructions | T-7 |
| `pkg/syslog` | Fixes listed under the syslog audit sink; `AuditHandler` with its bounded queue; tests on a temporary socket | R-1, R-3 |
| `internal/metadata/config`, `cmd/openstack-spire-issuer` | `audit.syslog` block and its checks; at `service start`, a handler that writes to the regular stream and forwards audit records to syslog | R-1, R-3 |
| `examples/` | Samples updated with the new keys, a dedicated vendordata user, and Nova `[vendordata_dynamic_auth]` `certfile`/`keyfile` once confirmed on DevStack | S-3 |

## Resolved questions and out of scope

**Resolved questions** (open in the first draft):

- Barbican vs. a cloud-neutral HSM/KMS abstraction: neither is used for per-token signing. Keys live behind a key store interface, with ephemeral in-memory keys first and Vault transit later.
- Rotation cadence (30 vs. 90 days): with ephemeral per-replica keys, rotation is cheap; `key_store.rotation_interval` defaults to 24h and is configurable (at least 5 minutes).
- Whether `tags` should be restricted to an allowlist of metadata keys: an optional `tags.allowlist`; when empty, every string entry passes, within the 1024-byte cap, and `config check` warns about it.

**Explicitly out of scope**:

- The SPIRE agent and server-side `openstack_iid` plugins that consume this service's output (companion spec), beyond the requirements stated above.
- Nova operator configuration (`vendordata_providers`, `vendordata_dynamic_targets`, `[vendordata_dynamic_auth]`) beyond the values this service must match.
- Setup and operation of the key management infrastructure itself (Vault clusters and their replication).
