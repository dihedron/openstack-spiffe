# OpenStack metadata JWT issuer — implementation spec

Sep 20, 2026 (revised Oct 1, 2026) · @Andrea Funtò

## Overview

This spec defines the OpenStack metadata JWT issuer (`openstack-spire-metadata`): the service that runs alongside Nova's dynamic vendordata mechanism and hands each booting instance a short-lived, signed JWT proving its `project_id` and `instance_id`.

This JWT is the trust root that the `openstack_iid` SPIRE node attestor pair (see the companion spec) verifies. Its correctness matters more than almost any other component in the system: every downstream SPIFFE ID and selector is only as trustworthy as this service's binding between "who is asking" and "what the token claims". The design addresses high-throughput data-plane requirements (instance boot storms), the realities of control-plane authorization, and the size of the token payload.

**Non-goals**: this spec does not cover the SPIRE agent/server plugins that consume the JWT (companion spec), nor the key management system itself (e.g. Vault) beyond how this service talks to it.

## Architecture

The system has three parts:

- **Signer replicas** (`openstack-spire-metadata service start`): several independent, share-nothing replicas behind a load balancer, the target of Nova's DynamicJSON configuration. Each replica authenticates Nova, verifies the instance, mints tokens signed with its own key, and publishes its own public keys. When its configuration lists its peers (the other replicas), a replica also acts as a JWKS aggregator: it polls its peers' public keys and serves them merged with its own (see peer aggregation). Running N replicas with each other as peers thus gives N token minters and N JWKS aggregators, with no further deployment.
- **Key store**: behind a single interface, either ephemeral in-memory keys owned by each replica (implemented first) or Vault's transit engine (later).
- **JWKS aggregator** (`openstack-spire-metadata jwks aggregate`, optional): one or more stateless instances behind their own load balancer that merge the replicas' public keys into a single JWK Set, for deployments where the SPIRE Server-side plugin should not reach the signers directly (e.g. to keep it off the Nova-facing network).

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

**Response shape**: Nova nests the response under the target name in `vendor_data2.json`. This service returns `{"openstack_iid": {"jwt": "<token>"}}` (`application/json`); matching the `openstack_iid` target name gives the agent plugin (companion spec) a fixed lookup path. The body is a credential, so every `/attest` response carries `Cache-Control: no-store`. Only `POST` is accepted (`405` otherwise), and error responses carry the bare status text, never details.

**Processing order**: per-source rate limit and body cap → caller authentication → decoding and validation → per-instance rate limit → instance verification and enrichment → signing. Each step runs only if the previous ones succeeded, so an unauthenticated or invalid request never costs a lookup or a signature.

**Logging of rejected payloads**: a malformed or invalid body is logged truncated to 512 bytes, with `user-data` redacted: in a JSON object its value is replaced; in a payload that cannot be parsed, everything from the first mention of `user-data` onwards is dropped, since the value cannot be located reliably. An oversized body is logged only with the size cap.

## Caller authentication and request-context binding

The `project-id` and `instance-id` fields are Nova's own claims about the instance. Treating them as pre-authorized input would let anything able to reach this endpoint mint a token for an arbitrary instance ID, so this service must authenticate the caller before minting a token.

The request is made by `nova-api-metadata`, not by the user who booted the instance, so it does *not* carry the original user's Keystone token. Instead, Nova authenticates to this service with the credentials of its `[vendordata_dynamic_auth]` section and sends the resulting token in the `X-Auth-Token` header. This service must:

- reject a request without `X-Auth-Token` with `401`;
- validate the token against Keystone (`GET /v3/auth/tokens`); an invalid or expired token is rejected with `401`;
- require the token's user to be listed in `keystone.allowed_users` **and** to carry `keystone.required_role` (default `service`); otherwise reject with `403` and log the user ID (never the token);
- reject with `503` if Keystone cannot be reached;
- cache successful validations, keyed by the SHA-256 of the token, for at most `keystone.validation_cache_ttl` (default 60s) and never beyond the token's own expiry, in a bounded cache. Failures are not cached, and concurrent validations of the same token (Nova reuses its token across requests) are merged into a single Keystone request.

**Allowed users**: each `keystone.allowed_users` entry is either a user ID (32 or 64 lowercase hex digits, as Keystone generates them) or `name@domain`, where `domain` is the domain's name or ID. The name may itself contain `@`; the domain follows the last one. Bare names are configuration errors: user names are only unique within a domain, and a same-named user with the same role in another domain would otherwise be accepted.

**Service credentials**: the service validates tokens with its own credentials, taken from the `OS_*` environment variables of a standard openrc file and never from the configuration file:

- `OS_AUTH_URL`, https only (the service connects to OpenStack endpoints with `tls_min_version` or later, see TLS below);
- either `OS_USERNAME` or `OS_USER_ID` with `OS_USER_DOMAIN_NAME`/`_ID`, `OS_PASSWORD` and a project scope (`OS_PROJECT_NAME` with `OS_PROJECT_DOMAIN_NAME`/`_ID`, or `OS_PROJECT_ID`);
- or an application credential (`OS_APPLICATION_CREDENTIAL_ID` or `_NAME`, and `_SECRET`);
- optionally `OS_REGION_NAME` and `OS_INTERFACE` (`public`, `internal` or `admin`; default `public`), which select the catalog endpoints used for instance verification.

The service user needs, with default policies, the permissions to validate other users' tokens (`identity:validate_token`), to read any project (`identity:get_project`, for the `project_name` and `domain_id` enrichment) and to read any server (`os_compute_api:servers:show`, for instance verification): typically the `admin` role in the `service` project, as for the other OpenStack service users, or a dedicated role with policy overrides for these rules. It re-authenticates when its own token expires.

Trust in Nova's claims about `project-id` and `instance-id` thus rests on the authenticated identity of the compute control plane, and is independently confirmed by the instance verification described below.

## Claim schema

The schema must match the companion `openstack_iid` node attestor spec exactly: it is a shared contract. The header and claim definitions, the fixed values (`iss`, `aud`, target name, maximum TTL, tags size cap) and the reserved claim names are defined once, in a single Go package (`pkg/iid`) imported by this service and by the SPIRE plugins, never hand-copied.

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
  - if `tags.allowlist` is configured, only the listed keys are kept (an empty allowlist keeps every string entry, and `config check` warns about it);
  - the JSON-serialized `tags` object never exceeds 1024 bytes (escaping included): entries are considered in sorted key order and any entry that would not fit is dropped, so the result is deterministic and later, smaller entries can still fit;
  - every dropped entry is logged with its key and the reason, never its value; the token is still issued.
- **Immutability**: every claim value comes exclusively from the authorized Nova request, except the operator-configured custom claims and the enrichment claims looked up from Nova and Keystone (see below). The service accepts no override of `project_id`, `instance_id` or `hostname` from any other input path.
- **Custom claims**: the operator can configure static string claims (e.g. `"country": "italy"`) in `custom_claims`; they are added as top-level claims to every token, and their values are strings. Custom claims must not use a reserved claim name (`iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `project_id`, `instance_id`, `hostname`, `tags`, and the enrichment claims `availability_zone`, `flavor`, `user_id`, `project_name`, `domain_id`). The service refuses to start if they do, and re-checks the names right before signing, so it can never emit a token where a custom claim shadows a reserved one.

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

## Signing key management

This is the highest-risk component in the whole system: compromise of a signing key means anyone can mint a valid attestation for any instance ID.

**Custody**: private key material is never written to disk on the host running this service. The service signs through a key store interface (a `Sign` operation on a digest) and never exports keys. To prevent thundering-herd failures during cluster scale-ups, per-token signing requests are not routed to control-plane key managers such as Barbican. Two backends sit behind the interface:

1. **Vault transit** (`vault_transit`, recommended for enterprise persistence): signing is offloaded to a HashiCorp Vault REST API proxy (`key_store.vault_proxy_endpoint`); the private key never leaves Vault. Dual-cluster token replication and DBOS durable workflows provide the high-throughput, data-plane resilience that instance boot storms require, without writing private keys to disk.
2. **Ephemeral in-memory keys** (`ephemeral_memory`, recommended for stateless simplicity): each replica generates its key pairs entirely in memory and never persists them; if the replica restarts, it simply generates a new key. The public halves are published through the JWKS endpoint.

The `ephemeral_memory` backend is implemented first; `vault_transit` comes later behind the same interface (until then, the configuration check reports it as not supported).

**Algorithms**: RS256 with RSA 2048-bit keys (default) or ES256 with ECDSA P-256 keys (`key_store.algorithm`).

**Rotation and retention**: keys rotate on a fixed schedule (`key_store.rotation_interval`, default 24h, at least 5 minutes) and whenever a replica restarts; restarting a replica therefore also replaces its key on suspected compromise. The previous key's public half stays in the JWKS for at least one full token TTL past rotation, so that in-flight tokens do not fail verification during the cutover.

**Access control**: with `vault_transit`, only this service's identity (not humans, not other services) may sign with the active key, and creating or rotating Vault keys is a separate, more privileged operation, documented as a runbook rather than done autonomously by this service. With `ephemeral_memory`, key generation and rotation are necessarily performed by the replica itself.

**Replica topology**: the service runs as multiple independent, share-nothing replicas, each with its own keys; their public keys are merged for the SPIRE Server by the replicas themselves (peer aggregation) or by the JWKS aggregator (see below).

- **kid**: every key gets a unique kid at creation, and every token is tagged with the kid of the key that signed it. The format is `<YYYY-MM-DD>-<replica-id>-key-<n>` (e.g. `2026-09-29-signer-a-key-52331`), where the date is the UTC date the key was generated and `n` the number of seconds since UTC midnight at that moment, bumped when needed so that it strictly increases within a process. Kids therefore never collide across replicas, nor across restarts of the same replica (a counter restarting from 1 would reuse a kid with different key material, which the aggregator would exclude).
- **replica_id** is a lowercase DNS label, unique across replicas; if not configured, it is derived from the first label of the hostname (`config check` warns about it).
- **Publication before use**: a token must never carry a kid the aggregated JWKS cannot serve yet, whether served by a peer replica or by the aggregator. Each new key is generated and published in the replica's JWKS `key_store.publish_ahead` (default 2m) before it is used for signing; `publish_ahead` must exceed `peers.poll_interval` plus `peers.fetch_timeout` plus `peers.cache_max_age` (when peers are configured), and the aggregator's `poll_interval` plus `fetch_timeout` plus `cache_max_age`. The poll and fetch terms bound how late a merged set picks up a new key; the cache term bounds how long a consumer may keep serving itself an older copy of the merged set, so that a new kid reaches the SPIRE Server before its first use without relying on its re-fetch on an unknown kid (which remains as a fallback, e.g. for a peer that was unreachable). At startup, a replica reports not ready (`/readiness` → `503`) until its first key has been published for `publish_ahead`.
- **Signing**: only the active key signs, and the token header carries its kid. If a rotation lands while a token is being signed, signing is retried once with the new active key; if it fails again, the request is rejected with `503`.

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
- **Same rules as the aggregator**: polling (at startup, then every `peers.poll_interval`, all peers concurrently, each within `peers.fetch_timeout`), fetch limits (`200` only, at most 1 MiB, a JWK Set, no redirects), TLS (`tls_min_version` or later, verified against `peers.ca_cert_path` or the system roots), key filtering (`use=sig`, allowed algorithms, private key material rejected), deduplication by kid, fail-closed conflicts, sorting by kid, retention of an unreachable peer's keys for `peers.stale_key_retention`, and logging of a failing peer when it starts failing and when it recovers: all follow the JWKS aggregator rules below.
- **Trust**: peer fetches are part of the trust chain, since anyone able to tamper with them could add a key that every replica's merged set would serve. Peers are therefore always reached over verified TLS, never with an insecure fallback. A compromised peer gains nothing it did not already have, since it can sign tokens with its own key anyway.
- **Own keys**: the replica's own keys are read live from the key store, never fetched over HTTP, and take part in conflict detection: a peer key with the same kid as an own key but different material excludes that kid (fail closed), which can only happen with a duplicated `replica_id`.
- **Readiness**: peers are not a readiness check. The merged set always holds the replica's own keys, and taking a signer out of Nova's load balancer because a peer is down would break attestation for no gain. If the SPIRE Server's load balancer picks a replica that is temporarily missing a peer's key because that peer was unreachable, the SPIRE Server-side plugin's re-fetch on an unknown kid covers it (a key published ahead is covered by the `publish_ahead` rule, see publication before use).
- **Full mesh**: each replica must list all the other replicas; a replica missing a peer in its list silently lacks that peer's keys in its merged set.

## JWKS aggregator

Since every replica signs with its own keys, the SPIRE Server-side plugin fetches the merged keys of all replicas, either from the replicas themselves (peer aggregation, above) or from a separate JWKS aggregator, which is optional and useful when the SPIRE Server should not reach the signers directly.

- **Command**: `openstack-spire-metadata jwks aggregate --config <path>`. The aggregator is stateless, so it can itself run as multiple replicas behind a load balancer; it is served over TLS (`tls_min_version`, default 1.3, or later), with the certificate the SPIRE Server operator pins.
- **Discovery**: a static list of replica JWKS URLs (`replicas`, https only), pointing at the replicas' `/jwks/local.json`. A replica's `/.well-known/jwks.json` still works, but on a replica with peers it also carries the peers' keys, which the aggregator then imports twice and drops later than needed, so `config check` warns about it.
- **Polling**: at startup and then every `poll_interval` (default 30s), all replicas are fetched concurrently, each within `fetch_timeout` (default 5s), over TLS (`tls_min_version` or later) verified against `replica_ca_cert_path` (or the system roots). A fetch fails on a non-`200` status, a response larger than 1 MiB, or a body that is not a JWK Set; redirects are never followed, since the configured URL itself must answer. A failing replica is logged when it starts failing and when it recovers, not on every poll.
- **Merging**: the output is a standard RFC 7517 JWK Set (not a custom map), deduplicated by kid. If two replicas, or one replica twice, publish the same kid with different key material, that kid is excluded and an error is logged on every poll while the conflict lasts (fail closed); identical duplicates are served once. Only public keys with `use=sig` and an allowed algorithm (RS256 with RSA of at least 2048 bits, ES256 on P-256) are passed through; other keys are left out and logged. A key carrying private key material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k`) is rejected and logged as an error, without the material itself; the replica's other keys are still used. The merged set is sorted by kid.
- **Unreachable replicas**: the keys from a replica's last successful fetch are kept for `stale_key_retention` (default and minimum: 5 minutes, the maximum token TTL), so in-flight tokens keep verifying during short outages. Keys a reachable replica stops publishing are dropped on its next successful fetch.
- **Endpoints**: `GET /.well-known/jwks.json` with `Cache-Control: public, max-age=<cache_max_age>` (default 30s), so consumers refresh on a reasonable schedule without hitting the endpoint on every attestation; `/liveness`; `/readiness` (ready while at least one replica has been fetched successfully within `stale_key_retention`, i.e. while the merged set holds any replica's keys; see the health endpoints).

**Requirements on the SPIRE Server-side plugin** (companion spec): fetch keys from the peered signer replicas' `/.well-known/jwks.json` or from the aggregator, select the verification key by the JWT header kid, and re-fetch the JWK Set (rate-limited) when it meets an unknown kid.

## Freshness, replay and rate limiting

Because Nova calls this service whenever the instance reads its vendordata, the service mints a brand-new token on every call rather than caching one per instance.

- **Short TTL**: 5 minutes (see the claim schema), which bounds the damage window if a token is exfiltrated in transit.
- **Fresh jti**: a new UUID for every token, even for the same instance asking again seconds later; a jti is never reused.
- **No replay tracking**: enforcing jti uniqueness is the responsibility of the downstream SPIRE Server-side plugin, if it chooses to track it. This service's job is to never issue two tokens with the same jti, not to police reuse downstream.
- **Two-stage rate limiting**: limits blunt any attempt to use this endpoint to exhaust the signing key store's request budget. The instance ID is only available inside the JSON body, so rate limiting happens in two stages, both answering `429`:
  1. **Before the body is read**: a per-source-IP token bucket (`rate_limit_per_source`, default 200/1s, keyed by the client address described below) in the HTTP middleware, together with a cap on the body size (`max_body_bytes`: a larger declared `Content-Length` is rejected with `400` at once, and reading an undeclared body stops at the cap), so spam is rejected cheaply without allocating memory for the payload. IPv6 sources are keyed by their /64 prefix, since a single host usually controls a whole /64 and could otherwise bypass the limit by rotating addresses.
  2. **Right after a size-capped decode**: a per-instance-ID token bucket (`rate_limit_per_instance`, default 1/5s: no more than one token every few seconds per instance), before any lookup or signing operation.

  A `429` carries a `Retry-After` header. A rate `N/period` allows bursts of up to N requests and refills N tokens per period. Limits are enforced per replica, since replicas share nothing. The number of tracked keys is bounded: buckets that have refilled completely are forgotten, and if the bound is still reached, an arbitrary bucket is evicted (its key starts over with a full bucket), so a flood of distinct sources can neither exhaust memory nor lock out every new source.

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

**Logging**: structured logs (`log/slog`, text format) go to standard error at level `info` by default; `OPENSTACK_SPIRE_METADATA_LOG_LEVEL` selects `debug`, `info`, `warn`, `error` or `off`, and `OPENSTACK_SPIRE_METADATA_LOG_STREAM` selects `stderr`, `stdout` or `file`. Tokens, keys, credentials and `user-data` are never logged.

**Request IDs**: every response carries an `X-Request-Id` header with a random ID generated by the service (incoming values are ignored), and every log record written while handling the request carries it as `request_id`.

**Health endpoints** (signer and aggregator; `GET` and `HEAD` only, `Cache-Control: no-store`, unauthenticated):

- `/liveness` answers `200` as long as the HTTP server is serving.
- `/readiness` answers `200` only if every readiness check passed in its latest run, else `503`. The checks run in the background, concurrently, every 5 seconds, each bounded by a 2-second timeout; probes are answered at once from the latest results, so they never wait on a dependency (orchestrators' probe timeouts are often shorter than a dependency check), and dependencies are checked at a fixed rate however often the endpoint is probed. The service is not ready before the first run completes, nor when the latest results are older than three intervals.
- Aggregator check: `replicas` (at least one replica fetched within `stale_key_retention`).
- Signer checks: `key_store` (the key store can sign, which includes the publish-ahead gate at startup), `keystone` (Keystone is reachable and accepts the service's token; an expired service token is renewed, not reported), and `nova` when `nova_lookup.enabled` (the Nova API is reachable). Peers are deliberately not a signer check (see peer aggregation).
- The JSON body gives the overall status and each check as `ok`, `failing` or `pending`, never error details, which are logged when a check changes state (not on every run).

**Command line** (object/verb convention):

- `openstack-spire-metadata service start --config <path>`: run a signer replica. It refuses to start (exit code 1) on any configuration error (the pre-flight check includes the file checks of `config check`), missing or invalid `OS_*` credentials, a failed Keystone authentication or an unusable TLS certificate, and logs configuration warnings. It serves HTTPS with TLS `tls_min_version` or later and bounded timeouts (read header 5s, read 15s, write 30s, idle 2m; headers at most 64 KiB), and on `SIGINT` or `SIGTERM` stops accepting connections and lets in-flight requests complete for up to 15 seconds.
- `openstack-spire-metadata jwks aggregate --config <path>`: run the JWKS aggregator. Like `service start`, it refuses to start on any configuration error, file checks included, logs configuration warnings, serves TLS `tls_min_version` or later with the same timeouts, and shuts down gracefully on `SIGINT` or `SIGTERM`.
- `openstack-spire-metadata config check ...`: validate configuration files (see below).

## Configuration

**Signer** (values shown are the defaults where one exists):

```yaml
listen_addr: "0.0.0.0:8443"
tls_min_version: "1.3"                                  # or "1.2" (server and OpenStack connections)
tls_cert_path: "/etc/openstack-metadata-signer/tls.crt" # required
tls_key_path: "/etc/openstack-metadata-signer/tls.key"  # required
replica_id: "signer-a"                                  # default: first label of the hostname
key_store:
  backend: "ephemeral_memory"                           # or "vault_transit" (later)
  algorithm: "RS256"                                    # or "ES256"
  rotation_interval: "24h"                              # at least 5m
  publish_ahead: "2m"                                   # > poll_interval + fetch_timeout + cache_max_age of peers and aggregator
  vault_proxy_endpoint: "https://vault-proxy.internal:8200"  # vault_transit only
token_ttl_seconds: 300                                  # at most 300
rate_limit_per_instance: "1/5s"
rate_limit_per_source: "200/1s"
max_body_bytes: 262144
client_address:
  trusted_proxies: ["10.0.10.0/24"]                     # default: none (not proxied)
  header: "X-Forwarded-For"                             # used only for trusted proxies
custom_claims:                                          # static string claims, no reserved names
  country: "italy"
tags:
  allowlist: ["role", "env"]                            # empty: every string entry
keystone:
  allowed_users: ["nova@Default"]                       # required: user IDs or name@domain
  required_role: "service"
  validation_cache_ttl: "60s"
  project_cache_ttl: "10m"
  ca_cert_path: "/etc/ssl/openstack-ca.pem"             # optional
nova_lookup:
  enabled: true
  cache_ttl: "60s"                                      # at most the token TTL
  allowed_statuses: ["ACTIVE", "BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "RESIZE", "VERIFY_RESIZE", "MIGRATING", "PASSWORD"]
enrich: ["availability_zone", "flavor", "user_id", "project_name", "domain_id"]  # default: none
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
tls_cert_path: "/etc/jwks-aggregator/tls.crt"          # required
tls_key_path: "/etc/jwks-aggregator/tls.key"           # required
replicas:                                              # required, https only
  - "https://signer-a.internal:8443/jwks/local.json"
  - "https://signer-b.internal:8443/jwks/local.json"
poll_interval: "30s"
fetch_timeout: "5s"
replica_ca_cert_path: "/etc/ssl/signer-ca.pem"         # optional
stale_key_retention: "5m"                              # at least 5m
cache_max_age: "30s"                                   # whole seconds
```

Unknown keys are errors in both files, so that typos are never silently ignored.

## Configuration validation

The binary provides a command to validate configuration files before deployment (e.g. in CI or a pre-rollout hook), applying the same rules the services apply at startup:

```
openstack-spire-metadata config check [--signer PATH]... [--aggregator PATH] [--format text|json|yaml] [--strict] [--skip-files] [--print-effective]
```

- **Complete report**: all findings are reported in a single run, each with file, line, YAML path, severity (error or warning) and message; the command never stops at the first problem.
- **Unknown keys** are errors and carry a "did you mean ...?" suggestion when a known key is close (e.g. `rate_limt_per_instance`).
- **Invalid values** (wrong types, malformed durations or rates) and **rule violations** (ranges, required values, reserved custom claim names, enrichment requiring `nova_lookup`, `allowed_users` entries that are neither user IDs nor `name@domain`, `trusted_proxies` entries that are neither IP addresses nor CIDR ranges, an empty or invalid `client_address.header`, a `tls_min_version` other than `"1.2"` or `"1.3"`, a non-https or duplicate peer URL, a peer URL whose path ends in `/.well-known/jwks.json`, `peers` ranges as for the aggregator's corresponding keys, ...) are errors.
- **Peer consistency** (within a signer file): when peers are configured, `key_store.publish_ahead` must exceed `peers.poll_interval` plus `peers.fetch_timeout` plus `peers.cache_max_age`.
- **Cross-file consistency**: when an aggregator file is given, each signer's `key_store.publish_ahead` must exceed the aggregator's `poll_interval` plus `fetch_timeout` plus `cache_max_age` (otherwise tokens could carry a kid the aggregated JWKS does not publish yet), and the aggregator's `stale_key_retention` must be at least each signer's token TTL (always true, since the aggregator itself requires at least the maximum token TTL). `replica_id` must be unique across all signer files.
- **File checks** (skippable with `--skip-files`): TLS certificate and key exist, parse and match; the certificate is not expired; CA bundles (`peers.ca_cert_path` included) parse. A certificate expiring within 30 days and a private key readable by group or others are warnings.
- **Warnings** flag valid but risky settings: `tls_min_version` set to `"1.2"`, instance verification disabled, no tags allowlist, keys ignored by the selected backend, `client_address.header` set without `trusted_proxies` (ignored), `trusted_proxies` covering every address (e.g. `0.0.0.0/0` or `::/0`, which lets any client choose its rate-limiting key), `replica_id` derived from the hostname, a per-instance rate limit looser than 1/5s, `peers` keys set without `peers.urls` (ignored), an aggregator replica URL whose path ends in `/.well-known/jwks.json` (see the JWKS aggregator).
- **Exit codes**: 0 when there are no errors (warnings allowed), 1 on errors (or on warnings with `--strict`), 2 when a file cannot be read or the command line is invalid.
- The services run the same checks at startup, file checks included, as a pre-flight check: they refuse to start on any error (e.g. a missing, mismatched or expired TLS certificate, or an unparseable CA bundle) and log the warnings.

## Error handling and failure modes

| Failure | Behavior |
| --- | --- |
| Per-source rate limit exceeded | Reject with `429` *before* the body is read |
| Malformed, oversized or invalid request body | Reject with `400`; log the payload truncated and with `user-data` redacted |
| Missing `X-Auth-Token`, or invalid/expired token | Reject with `401`, do not sign |
| Token user not in `keystone.allowed_users` or lacking `keystone.required_role` | Reject with `403`, do not sign, log the user ID (never the token) |
| Keystone unreachable while authenticating the caller | Reject with `503` |
| Per-instance rate limit exceeded | Reject with `429` before any lookup or signing |
| Instance not found, owned by another project, or in a disallowed status; project not found | Reject with `403`, do not sign, log the mismatch |
| Nova API / Keystone unreachable during verification or enrichment, or an enabled enrichment attribute missing from the record | Reject with `503` |
| Key store / Vault proxy unreachable | Reject with `503`; Nova omits this target from the metadata response, and the instance retries on its next metadata poll |
| Signing fails for any other reason (e.g. a custom claim colliding with a reserved name) | Reject with `500` |

A failure must never fall back to issuing an unsigned, weakly signed or partial token: every rejection path ends in "no token issued", never a degraded one. The service treats unavailability as safe, never as a reason to loosen verification.

**Operational warning**: while an instance retries a missing metadata target on its next poll, cloud-init configures the host during the initial local boot sequence. If a `503` (e.g. a key store failure) causes the JWT to be omitted during this exact window, downstream SPIRE-dependent systemd units will fail. Operators must monitor `/readiness` strictly, since transient failures break attestation for newly booting instances.

## Testing and validation

**Unit tests**:

- Claim construction from a valid Nova request body, including `tags` filtering: non-string values dropped, the allowlist applied, the strict size limit enforced.
- Request validation rejects malformed bodies, duplicate members and non-canonical instance IDs.
- Instance verification rejects unknown instances, project mismatches and disallowed statuses; enrichment claims appear only when enabled; lookups are served from cache within the TTL.
- The kid correctly reflects the active (in-memory or Vault-backed) signing key on every issued token.
- kid format and uniqueness across replicas; a new key is published before it is used; readiness stays false until the first key has been published for `publish_ahead`.
- The JWKS response includes the key published ahead, the active key and any key still within its post-rotation retention window, and excludes keys past it.
- The aggregator merges replica key sets, excludes conflicting kids, retains an unreachable replica's keys for `stale_key_retention` and then drops them.
- `/jwks/local.json` never contains peer keys; without peers, `/.well-known/jwks.json` serves the same content and headers as `/jwks/local.json`.
- Peer aggregation: the merged set always includes the replica's own keys, even with every peer unreachable, and readiness is unaffected; a peer kid that conflicts with an own kid is excluded; a peer URL whose path ends in `/.well-known/jwks.json` is rejected by the configuration check; with two replicas polling each other's local set, a key one of them retires disappears from both merged sets instead of circulating between them.
- The configuration check reports every finding of a broken file in one run, with correct lines.

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
- Deployed close to the Nova control plane's network segment, since `nova-api-metadata` must reach it on every vendordata request; its availability is coupled to that of the metadata service. It runs as several share-nothing signer replicas behind a load balancer (the target of Nova's DynamicJSON configuration), in one of two topologies:
  - **Peered signers**: each replica lists all the others as peers, and the SPIRE Server-side plugin fetches `/.well-known/jwks.json` through a load balancer in front of the replicas, pinning the signers' certificate. No other deployment is needed.
  - **Signers plus aggregator**: one or more JWKS aggregator instances behind their own load balancer poll the replicas' `/jwks/local.json` and serve the SPIRE Server-side plugin, for when it must not reach the Nova-facing network.

  The signer's load balancer either preserves client addresses, or is listed in `client_address.trusted_proxies` and forwards them in `client_address.header` (see client address).
- No private key material is ever written to the deployment host's disk. The only secrets the service holds locally are its client credentials (Keystone `OS_*` variables, and the Vault credentials once `vault_transit` exists); they come from the platform's standard secret-injection mechanism, never baked into the image.
- Annotated sample configurations (signer, with peers, aggregator, `OS_*` credentials template and the Nova settings) live in `examples/`, and a test keeps the signer and aggregator samples valid, cross-file checks included; the README documents deployment, OpenStack setup and tuning.
- Separate `/liveness` and `/readiness` probes: readiness verifies connectivity to the service's dependencies (key store included), not just process liveness, so that orchestrators take a replica out of load-balancer rotation during backend disruptions without crash-looping the pods.

## Resolved questions and out of scope

**Resolved questions** (open in the first draft):

- Barbican vs. a cloud-neutral HSM/KMS abstraction: neither is used for per-token signing. Keys live behind a key store interface, with ephemeral in-memory keys first and Vault transit later.
- Rotation cadence (30 vs. 90 days): with ephemeral per-replica keys, rotation is cheap; `key_store.rotation_interval` defaults to 24h and is configurable (at least 5 minutes).
- Whether `tags` should be restricted to an allowlist of metadata keys: an optional `tags.allowlist`; when empty, every string entry passes, within the 1024-byte cap, and `config check` warns about it.

**Explicitly out of scope**:

- The SPIRE agent and server-side `openstack_iid` plugins that consume this service's output (companion spec), beyond the requirements stated above.
- Nova operator configuration (`vendordata_providers`, `vendordata_dynamic_targets`, `[vendordata_dynamic_auth]`) beyond the values this service must match.
- Setup and operation of the key management infrastructure itself (Vault clusters and their replication).
