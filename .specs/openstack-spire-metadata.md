# OpenStack vendor data JWT issuer — implementation spec

Sep 20, 2026 · @Andrea Funtò

> **Note:** this document contains the original specification followed by a revision ("implementation spec revision"). The revision supersedes the original wherever the two differ.

## Overview

This spec defines the vendordata JWT issuer: the service that runs alongside (or as part of) Nova's dynamic vendordata mechanism and hands each booting instance a short-lived, signed JWT proving its `project_id` and `instance_id`.

This JWT is the trust root the `openstack_iid` SPIRE node attestor pair (see the companion spec) verifies. Its correctness matters more than almost any other component in this system — every downstream SPIFFE ID and selector is only as trustworthy as this service's binding between "who is asking" and "what the token claims."

**Non-goals**: this spec does not cover the SPIRE agent/server plugins that consume the JWT (separate spec), or the key management system (Barbican/HSM) itself beyond how this service talks to it.

## Nova integration and request-context binding

This service is a Nova **DynamicJSON vendordata target** — a REST service Nova's `nova-api`/`nova-api-metadata` calls on the instance's behalf, not something the instance calls directly.

**Registration** (Nova operator config, out of scope to change here, but this service must match it):

- `api.vendordata_providers` includes `DynamicJSON`.
- `api.vendordata_dynamic_targets` includes an entry named `openstack_iid`, e.g. `openstack_iid@https://vendordata-signer.internal:8443/attest`.

**Request shape** (Nova → this service, JSON POST, re-sent on every metadata request the instance makes, not just at boot):

| Field | Source |
| --- | --- |
| `project-id` | The project that owns the instance |
| `instance-id` | The instance UUID |
| `image-id` | The boot image ID |
| `hostname` | The instance hostname |
| `metadata` | User-supplied key/value pairs at boot time |

**The binding this service must enforce**: Nova also passes the Keystone authentication details for the original boot request alongside this payload. This service must use those Keystone details — not the `project-id`/`instance-id` fields alone — to authorize the request before minting a token. The `project-id`/`instance-id` fields are Nova's own claims about the instance; treating them as pre-authorized input without checking the accompanying Keystone context would let anything able to reach this endpoint mint a token for an arbitrary instance ID.

**Response shape**: Nova nests the response under the target name in `vendor_data2.json`. This service must return `{"openstack_iid": {"jwt": "<token>"}}` — matching the `openstack_iid` target name means the agent plugin (companion spec) can rely on a fixed lookup path.

## Claim schema

Must match the companion `openstack_iid` node attestor spec exactly — this is a shared contract. Define it once and vendor/import it into both codebases rather than hand-copying.

```json
{
  "header": {
    "alg": "RS256",
    "kid": "2026-09-key-1"
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

- `tags` is populated from the incoming `metadata` field, filtered to string-only values — drop (don't error on) any non-string entry, but log it.
- `exp - iat` must be a short, fixed window (recommend 5 minutes) — this service owns enforcing that, not just documenting it.
- Every claim value comes from the authorized Nova request, never from anything else. This service must not accept overrides for `project_id`, `instance_id`, or `hostname` from any other input path.

## Signing key management

This is the highest-risk component in the whole system — compromise of the signing key means anyone can mint a valid attestation for any instance ID.

- **Custody**: the private key must never be stored on disk in plaintext on the host running this service. Use Barbican (OpenStack's key manager) or an HSM-backed KMS for signing operations, so the private key material never leaves the key store — this service should call a `Sign` operation, not load and hold the key itself.
- **Key generation**: RSA 2048-bit minimum (or ECDSA P-256) per signing key, generated inside the key store, never exported.
- **`kid` assignment**: each key gets a unique `kid` at creation (recommend `<date>-key-<n>`, matching the format used in the claim schema example). This service must tag every JWT it signs with the `kid` of the key used.
- **Rotation policy**: rotate signing keys on a fixed schedule (recommend every 30-90 days) and immediately on suspected compromise. Keep the previous key's public component in the JWKS response (see next section) for at least one full token TTL past rotation, so in-flight tokens don't fail verification during the cutover.
- **Access control**: only this service's identity (not humans, not other services) should have `Sign` permission on the active key in Barbican/the KMS. Key creation/rotation is a separate, more privileged operation — document it as a runbook, not something this service does autonomously.

## JWKS endpoint

This service exposes the public half of every currently-trusted signing key, so the SPIRE Server-side plugin (companion spec) can fetch and cache them by `kid`.

- **Endpoint**: `GET /.well-known/jwks.json`, standard RFC 7517 JWK Set format, one entry per active or recently-rotated key.
- **Protection**: this endpoint is read-only and unauthenticated-by-design (public keys are not secrets), but must be served over TLS with a certificate SPIRE Server's operator can pin — treat the endpoint's own TLS identity as part of the trust chain, not an afterthought.
- **Caching headers**: set a `Cache-Control` max-age matching the rotation cadence, so consumers refresh on a reasonable schedule without hammering this endpoint on every attestation.
- **Content**: include keys for the currently active `kid` plus any key retired within the last full token TTL window (see rotation policy above), each with its `kid`, `kty`, `alg`, and public key material (`n`/`e` for RSA, `x`/`y` for EC).
- This service must regenerate this endpoint's content automatically whenever a key rotation completes — never require a manual step to publish a new key's public half.

## Freshness and replay controls

Because Nova re-queries this service on every metadata request the instance makes (not just at boot), this service should mint a brand-new token on every call rather than caching one per instance.

- **Short TTL**: 5 minutes recommended (`exp - iat`), matching the claim schema. This bounds the damage window if a token is somehow exfiltrated in transit.
- **Fresh `jti` per token**: always generate a new UUID, even for the same instance requesting again seconds later. Never reuse a `jti`.
- **No server-side replay tracking in this service**: `jti` uniqueness enforcement (if the SPIRE Server-side plugin chooses to track it) is out of scope here — this service's job is to never issue two tokens with the same `jti`, not to police reuse downstream.
- **Rate limiting**: apply a per-instance-ID rate limit (recommend no more than one token issuance per few seconds per instance) to blunt any attempt to use this endpoint to exhaust the signing key store's request budget.

## API surface and configuration

**Endpoints**:

| Method | Path | Called by | Purpose |
| --- | --- | --- | --- |
| `POST` | `/attest` | Nova (DynamicJSON target) | Issue a signed JWT for the requesting instance |
| `GET` | `/.well-known/jwks.json` | SPIRE Server | Fetch current trusted public keys |
| `GET` | `/healthz` | Load balancer / orchestrator | Liveness check |

**Config**:

```yaml
listen_addr: "0.0.0.0:8443"
tls_cert_path: "/etc/vendordata-signer/tls.crt"
tls_key_path: "/etc/vendordata-signer/tls.key"
key_store:
  backend: "barbican"     # or "hsm"
  barbican_endpoint: "https://barbican.internal:9311"
  active_key_id: "<barbican secret ref>"
token_ttl_seconds: 300
rate_limit_per_instance: "1/5s"
```

Claude should keep the Nova-facing HTTP handler, the JWKS handler, and the key-signing client as separate, independently testable components.

## Error handling and failure modes

| Failure | Behavior |
| --- | --- |
| Request missing Keystone auth context | Reject with `401`, do not sign |
| Keystone context doesn't authorize this project/instance | Reject with `403`, do not sign, log the mismatch |
| Key store (Barbican/HSM) unreachable | Reject with `503`; Nova's metadata response for this target is simply omitted, instance retries on next metadata poll |
| Rate limit exceeded for an instance ID | Reject with `429` |
| Malformed request body from Nova | Reject with `400`, log full payload for operator review |

A failure here must never fall back to issuing an unsigned or weakly-signed token — every rejection path ends in "no token issued," never a degraded one. Nova instances that fail to get a token will simply retry on their next metadata poll; this service should treat unavailability as safe, not as a reason to loosen verification.

## Testing and validation

**Unit tests**:

- Claim construction from a valid Nova request body, including `tags` filtering of non-string metadata values.
- Rejection of a request whose Keystone context doesn't match its claimed `project-id`.
- `kid` correctly reflects the active signing key on every issued token.
- JWKS response includes both the active key and any key still within its post-rotation retention window; excludes keys past it.

**Integration tests**:

- Full request against a real (or fully mocked) Barbican/KMS backend: request in, valid signed JWT out, signature verifiable against the JWKS endpoint's own output.
- Key rotation drill: rotate the active key, confirm tokens signed just before rotation still verify against the JWKS response, confirm new tokens use the new `kid`.
- Rate limiting: burst requests from one instance ID, confirm `429` after the configured threshold, confirm a different instance ID is unaffected.

**Required negative test**: a request with a well-formed body but no Keystone auth context attached must be rejected — this is the single test that most directly validates the request-context binding this entire design depends on.

## Build, packaging, deployment

- A standalone HTTP service (any language; Go recommended for consistency with the SPIRE plugins in the companion specs), stateless aside from its key-store client — safe to run as multiple replicas behind a load balancer.
- No local private key material ever written to the deployment host's disk — the Barbican/HSM client credentials are the only secret this service holds locally, and those should come from the platform's standard secret-injection mechanism, not baked into the image.
- Deploy close to (or as part of) the Nova control plane's network segment, since `nova-api`/`nova-api-metadata` must reach it on every metadata request — treat its availability as coupled to metadata-service availability more broadly.
- Health checks (`/healthz`) should verify connectivity to the key store, not just process liveness — a service that's up but can't reach Barbican should report unhealthy so it's taken out of rotation.

## Open questions and out of scope

**Open questions**:

- [ ] Barbican vs. a cloud-neutral HSM/KMS abstraction — depends on whether this OpenStack deployment already standardizes on Barbican elsewhere.
- [ ] Exact rotation cadence (30 vs. 90 days) — a security/operability tradeoff to decide with whoever owns key management policy.
- [ ] Whether `tags` should be an allowlist of specific metadata keys rather than passing all user-supplied metadata through — passing everything is simpler but widens what ends up in a selector-bearing token.

**Explicitly out of scope for this spec**:

- The SPIRE agent and server-side `openstack_iid` plugins that consume this service's output (companion spec).
- Nova operator configuration (`vendordata_providers`, `vendordata_dynamic_targets`) beyond the values this service must match.
- Barbican/HSM cluster setup and operation itself.

# **OpenStack vendor data JWT issuer — implementation spec revision**

## **Overview**

This spec defines the vendordata JWT issuer: the service that runs alongside (or as part of) Nova's dynamic vendordata mechanism and hands each booting instance a short-lived, signed JWT proving its project\_id and instance\_id.  
This JWT serves as the trust root for the openstack\_iid SPIRE node attestor pair. Its correctness dictates the trustworthiness of every downstream SPIFFE ID. This revised architecture addresses high-throughput data-plane requirements, control-plane authorization realities, and payload optimization.  
**Precedence:** this revision supersedes the original specification above wherever the two differ (e.g. Vault/ephemeral keys instead of Barbican, /liveness and /readiness instead of /healthz, service-token authentication instead of the original user's Keystone context).

## **Nova integration and request-context binding**

This service operates as a Nova **DynamicJSON vendordata target**. It is invoked by nova-api-metadata on the instance's behalf, whenever the instance reads vendor\_data2.json (subject to Nova's own metadata caching).  
**Registration** (Nova operator config):

* api.vendordata\_providers must include DynamicJSON.  
* api.vendordata\_dynamic\_targets includes an entry named openstack\_iid, e.g., openstack\_iid@\[https://vendordata-signer.internal:8443/attest\](https://vendordata-signer.internal:8443/attest).

**Request shape** (Nova → this service, JSON POST):

* project-id: The project that owns the instance.  
* instance-id: The instance UUID.  
* image-id: The boot image ID.  
* hostname: The instance hostname.  
* metadata: User-supplied key/value pairs at boot time.  
* user-data: The instance user data. Ignored: never decoded into the request model, never copied into a token, and redacted whenever a payload is logged.  
* boot-roles: The roles of the booting user. Ignored.

**Request validation** (400 on failure, no token issued):

* The body must be well-formed JSON of at most max\_body\_bytes (default 256 KiB: Nova forwards user-data, up to 64 KiB base64-encoded, together with metadata); duplicate member names are rejected, so a second instance-id cannot be smuggled in.  
* project-id: required, at most 64 characters from \[A-Za-z0-9\_-\].  
* instance-id: required, a canonical lowercase UUID; other forms (uppercase, braces, urn: prefix) are rejected so that an instance can never appear under two different "sub" values.  
* hostname: required, at most 255 characters, no control characters.  
* image-id: optional (empty for instances booted from volume).

**The Authorization Binding (Service-to-Service):**  
The request is made by nova-api-metadata, not by the user who booted the instance, so it does *not* carry the original user's Keystone token. Instead, Nova authenticates to this service with the credentials of its \[vendordata\_dynamic\_auth\] section and sends the resulting token in the X-Auth-Token header. This service must:

* reject a request without X-Auth-Token with 401;  
* validate the token against Keystone (GET /v3/auth/tokens), using its own service credentials taken from the OS\_\* environment variables (never from the configuration file); an invalid or expired token is rejected with 401;  
* require the token's user to be listed in keystone.allowed\_users (by ID or name) **and** to carry keystone.required\_role (default "service"); otherwise reject with 403 and log the user ID (never the token);  
* reject with 503 if Keystone cannot be reached;  
* cache successful validations, keyed by the SHA-256 of the token, for at most keystone.validation\_cache\_ttl (default 60s) and never beyond the token's own expiry.

Trust in Nova's claims about project-id and instance-id is thus based on the authenticated identity of the compute control plane, and independently confirmed by the instance verification described below.  
**Response shape**: The service must return {"openstack\_iid": {"jwt": "\<token\>"}} to match the target name expected by the agent plugin.

## **Claim schema**

JSON  
{  
  "header": {  
    "alg": "RS256",  
    "kid": "2026-09-29-signer-a-key-52331",  
    "typ": "JWT"  
  },  
  "payload": {  
    "iss": "nova-spire-plugin",  
    "aud": "spire-node-attestation",  
    "sub": "\<instance-id\>",  
    "iat": 1758000000,  
    "nbf": 1758000000,  
    "exp": 1758000300,  
    "jti": "\<uuid, freshly generated per token\>",  
    "project\_id": "\<project-id from the Nova request\>",  
    "instance\_id": "\<instance-id from the Nova request\>",  
    "hostname": "\<hostname from the Nova request\>",  
    "tags": { "\<key\>": "\<value\>", "...": "..." }  
  }  
}

* **Payload Bloat Protection:** Users frequently abuse OpenStack instance metadata for large cloud-init scripts. To prevent JWT headers from exceeding standard HTTP limits (4KB-8KB) downstream, the tags claim is derived from the incoming metadata field as follows:  
  * only string values are kept; other entries are dropped (not an error);  
  * if tags.allowlist is configured, only the listed keys are kept (an empty allowlist keeps every string entry, and config check warns about it);  
  * the JSON-serialized tags object never exceeds 1024 bytes (escaping included): entries are considered in sorted key order and any entry that would not fit is dropped, so the result is deterministic and later, smaller entries can still fit;  
  * every dropped entry is logged with its key and the reason, never its value; the token is still issued.  
* **TTL:** exp \- iat is a short, fixed window: token\_ttl\_seconds, default 300 (5 minutes), never more; the service refuses to start with a longer or non-positive value. iat and nbf are the issuance time.  
* **Immutability:** Every claim value comes exclusively from the authorized Nova request, except for operator-configured custom claims (see below).
* **Custom claims:** The operator can configure static string claims (e.g. "country": "italy") in the service configuration file (custom\_claims); they are added as top-level claims to every token. Custom claims must not use a reserved claim name (iss, aud, sub, iat, nbf, exp, jti, project\_id, instance\_id, hostname, tags, and the enrichment claims availability\_zone, flavor, user\_id, project\_name, domain\_id): the service refuses to start if they do, and re-checks the names right before signing, so it can never emit a token where a custom claim shadows a reserved one. Custom claim values are strings.
* **Shared contract:** the header and claim definitions, the fixed values (iss, aud, target name, maximum TTL, tags size cap) and the reserved names live in a single Go package (pkg/iid) imported by this service and by the SPIRE plugins.

## **Instance verification and claim enrichment**

Nova's DynamicJSON request carries only project-id, instance-id, image-id, hostname, metadata, user-data and boot-roles. The availability zone and other control-plane attributes are not part of it, so the service looks them up itself, with its own service credentials, before signing.

**Instance verification** (nova\_lookup.enabled, on by default): the service fetches the server record (GET /servers/{instance-id} on the Nova API) and checks, against this independent source, that:

* the instance exists;
* it belongs to the project-id stated in the request;
* its status is one of nova\_lookup.allowed\_statuses (default: ACTIVE, BUILD, REBOOT, HARD\_REBOOT, REBUILD, RESIZE, VERIFY\_RESIZE, MIGRATING, PASSWORD).

Any mismatch is rejected with 403 and logged; no token is issued.

**Claim enrichment** (enrich, a list of attribute names, empty by default): each enabled attribute is added as an optional top-level claim:

| Claim | Source | Notes |
| :---- | :---- | :---- |
| availability\_zone | Nova server record (OS-EXT-AZ:availability\_zone) | Requires nova\_lookup |
| flavor | Nova server record (flavor original\_name, microversion ≥ 2.47) | Requires nova\_lookup |
| user\_id | Nova server record (user\_id of the booting user) | Requires nova\_lookup |
| project\_name | Keystone (GET /v3/projects/{project-id}) | |
| domain\_id | Keystone (GET /v3/projects/{project-id}) | |

* Only control-plane-authoritative attributes are offered; user-controlled server attributes (name, tags, key pair) are deliberately not, since they carry no more trust than metadata.
* Compute host / hypervisor names are deliberately not offered: the token is readable from inside the guest (vendor\_data2.json) and would disclose the physical layout to tenants.
* The enrichment claim names are reserved: custom claims cannot use them.
* **Caching:** to protect nova-api and Keystone during boot storms, server records are cached per instance-id for at most nova\_lookup.cache\_ttl (default 60s, never more than the token TTL, since the availability zone can change on migration/resize); project records are cached for keystone.project\_cache\_ttl (default 10m).
* **Failure:** if Nova or Keystone cannot be reached, the request is rejected with 503. The service never issues a token with missing or stale-beyond-TTL enrichment claims.

## **Signing key management**

To prevent thundering herd failures during cluster scale-ups, this service avoids routing per-token Sign requests to control-plane key managers like Barbican.  
**Custody & Generation Architectures:**

> 1. **Vault Transit Backend (Recommended for Enterprise Persistence):** Offload signing operations to a HashiCorp Vault REST API proxy. Utilizing dual-cluster token replication and DBOS durable workflows ensures the high-throughput, data-plane resilience required for instance boot storms without writing private keys to disk.  
> 2. **Ephemeral In-Memory Keys (Recommended for Stateless Simplicity):** The Golang service generates an RSA 2048-bit (or ECDSA P-256) keypair entirely in memory at startup. The public half is published to the JWKS endpoint. If the pod restarts, it simply generates a new key.

The ephemeral\_memory backend is implemented first; vault\_transit comes later behind the same key store interface (the configuration check reports it as not supported yet).

**Algorithms:** RS256 with RSA 2048-bit keys (default) or ES256 with ECDSA P-256 keys (key\_store.algorithm).

**Rotation & Retention:** Keys rotate on a fixed schedule (key\_store.rotation\_interval, default 24h, at least 5 minutes) or upon service restart. The previous key's public component remains in the JWKS response for at least one full token TTL past rotation to validate in-flight tokens.

**Replica topology:** The service runs as multiple independent, share-nothing replicas, each with its own ephemeral key; a separate JWKS aggregator (see below) merges their public keys for the SPIRE Server.

* **kid:** \<YYYY-MM-DD\>-\<replica-id\>-key-\<n\> (e.g. 2026-09-29-signer-a-key-52331), where the date is the UTC date the key was generated and n the number of seconds since UTC midnight at that moment, bumped when needed so that it strictly increases within a process; kids therefore never collide across replicas, nor across restarts of the same replica (a counter restarting from 1 would reuse a kid with different key material, which the aggregator would exclude). replica\_id is a lowercase DNS label; if not configured it is derived from the first label of the hostname (config check warns about it), and it must be unique across replicas.  
* **Publication before use:** a token must never carry a kid the aggregated JWKS cannot serve yet. Each new key is generated and published in the replica's JWKS key\_store.publish\_ahead (default 2m) before it is used for signing; publish\_ahead must exceed the aggregator's poll\_interval plus fetch\_timeout. At startup, a replica reports not ready (/readiness 503) until its first key has been published for publish\_ahead.
* **Signing:** only the active key signs, and the token header carries its kid. If a rotation lands while a token is being signed, signing is retried once with the new active key; if it fails again, the request is rejected with 503.

## **JWKS endpoint**

This service exposes the public half of trusted signing keys for the SPIRE Server-side plugin.

* **Endpoint**: GET /.well-known/jwks.json, formatted as a standard RFC 7517 JWK Set.  
* **Protection**: Served over TLS with a certificate the SPIRE Server operator can pin.  
* **Caching headers**: a replica serves its JWKS with Cache-Control: no-cache. Its only consumer, the aggregator, polls it on its own schedule, and a cache in between could hide a key published ahead beyond publish\_ahead, breaking publication before use. Caching for the SPIRE Server is the aggregator's job (cache\_max\_age).  
* **Content**: Includes the key about to become active (published ahead), the currently active key and any key retired within the last token TTL (5 minutes); each entry carries kid, kty, alg, use=sig and the public key material only.  
* **Freshness**: The content is read live from the key store, so rotations are published automatically, without any manual step.
* **Errors**: GET and HEAD only (405 otherwise); if the keys cannot be read the endpoint replies 503, and it never serves a partial set; error responses are not cacheable (Cache-Control: no-store).

## **JWKS aggregator**

Since every replica signs with its own key, the SPIRE Server-side plugin fetches keys from a JWKS aggregator rather than from individual replicas.

* **Command:** openstack-spire-metadata jwks aggregate --config \<path\>; stateless, so it can itself run as multiple replicas behind a load balancer, served over TLS.  
* **Discovery:** a static list of replica JWKS URLs (replicas, https only).  
* **Polling:** every poll\_interval (default 30s) each replica is fetched concurrently, with fetch\_timeout (default 5s), a response size cap, and TLS verified against replica\_ca\_cert\_path (or the system roots).  
* **Merging:** the output is a standard RFC 7517 JWK Set (not a custom map), deduplicated by kid. If two replicas publish the same kid with different key material, that kid is excluded and an error is logged (fail closed). Only public keys with use=sig and an allowed algorithm are passed through; private key material is rejected.  
* **Unreachable replicas:** the keys from a replica's last successful fetch are kept for stale\_key\_retention (default and minimum: 5 minutes, the maximum token TTL), so in-flight tokens keep verifying during short outages; keys a reachable replica stops publishing are dropped on its next successful fetch.  
* **Endpoints:** GET /.well-known/jwks.json (Cache-Control max-age = cache\_max\_age, default 30s), /liveness, /readiness (ready once at least one replica has been fetched successfully).

**Requirements on the SPIRE Server-side plugin** (companion spec): fetch keys from the aggregator, select the verification key by the JWT header kid, and re-fetch the JWK Set (rate-limited) when it meets an unknown kid.

## **Freshness and replay controls**

* **Fresh jti**: Generate a new UUID for every token minted.  
* **No Replay Tracking**: Enforcing jti reuse is the responsibility of the downstream SPIRE Server, not this service.  
* **Two-stage Rate Limiting**: the instance ID is only available inside the JSON body, so rate limiting happens in two stages, both answering 429:  
  1. **Before the body is read:** a per-source-IP token bucket (rate\_limit\_per\_source, default 200/1s) in the HTTP middleware, together with a cap on the body size (max\_body\_bytes), so spam is rejected cheaply without allocating memory for the payload.  
  2. **Right after a size-capped decode:** the per-instance-ID token bucket (rate\_limit\_per\_instance, default 1/5s), before any lookup or signing operation.  
  Limits are enforced per replica (replicas share nothing).

## **API surface and configuration**

**Endpoints**:

| Method | Path | Purpose |
| :---- | :---- | :---- |
| POST | /attest | Issue a signed JWT for the requesting instance |
| GET | /.well-known/jwks.json | Fetch current trusted public keys |
| GET | /liveness | HTTP server process check (used by orchestrator to restart crashed pods) |
| GET | /readiness | Dependency and KMS connectivity check (used by orchestrator to route traffic); also not ready until the first key has been published for publish\_ahead |

**Command line** (object/verb convention):

* openstack-spire-metadata service start --config \<path\>: run a signer replica.  
* openstack-spire-metadata jwks aggregate --config \<path\>: run the JWKS aggregator.  
* openstack-spire-metadata config check ...: validate configuration files (see below).

**Signer config** (values shown are the defaults where one exists):

YAML  
listen\_addr: "0.0.0.0:8443"  
tls\_cert\_path: "/etc/vendordata-signer/tls.crt"         \# required  
tls\_key\_path: "/etc/vendordata-signer/tls.key"          \# required  
replica\_id: "signer-a"                                  \# default: first label of the hostname  
key\_store:  
  backend: "ephemeral\_memory"                            \# or "vault\_transit" (later)  
  algorithm: "RS256"                                     \# or "ES256"  
  rotation\_interval: "24h"  
  publish\_ahead: "2m"  
  vault\_proxy\_endpoint: "https://vault-proxy.internal:8200"  \# vault\_transit only  
token\_ttl\_seconds: 300  
rate\_limit\_per\_instance: "1/5s"  
rate\_limit\_per\_source: "200/1s"  
max\_body\_bytes: 262144  
custom\_claims:  
  country: "italy"  
tags:  
  allowlist: \["role", "env"\]  
keystone:  
  allowed\_users: \["nova"\]                               \# required  
  required\_role: "service"  
  validation\_cache\_ttl: "60s"  
  project\_cache\_ttl: "10m"  
  ca\_cert\_path: "/etc/ssl/openstack-ca.pem"             \# optional  
nova\_lookup:  
  enabled: true  
  cache\_ttl: "60s"  
  allowed\_statuses: \["ACTIVE", "BUILD", "REBOOT", "HARD\_REBOOT", "REBUILD", "RESIZE", "VERIFY\_RESIZE", "MIGRATING", "PASSWORD"\]  
enrich: \["availability\_zone", "flavor", "user\_id", "project\_name", "domain\_id"\]

**Aggregator config**:

YAML  
listen\_addr: "0.0.0.0:8444"  
tls\_cert\_path: "/etc/jwks-aggregator/tls.crt"          \# required  
tls\_key\_path: "/etc/jwks-aggregator/tls.key"           \# required  
replicas:                                               \# required, https only  
  \- "https://signer-a.internal:8443/.well-known/jwks.json"  
  \- "https://signer-b.internal:8443/.well-known/jwks.json"  
poll\_interval: "30s"  
fetch\_timeout: "5s"  
replica\_ca\_cert\_path: "/etc/ssl/signer-ca.pem"          \# optional  
stale\_key\_retention: "5m"  
cache\_max\_age: "30s"

Unknown keys are errors in both files, so that typos are never silently ignored.

## **Configuration validation**

The binary provides a command to validate configuration files before deployment (e.g. in CI or a pre-rollout hook), with the same rules the services apply at startup:

    openstack-spire-metadata config check [--signer PATH]... [--aggregator PATH] [--format text|json|yaml] [--strict] [--skip-files] [--print-effective]

* **Complete report:** all findings are reported in a single run, each with file, line, YAML path, severity (error or warning) and message; the command never stops at the first problem.
* **Unknown keys** are errors and carry a "did you mean ...?" suggestion when a known key is close (e.g. rate\_limt\_per\_instance).
* **Invalid values** (wrong types, malformed durations or rates) and **rule violations** (ranges, required values, reserved custom claim names, enrichment requiring nova\_lookup, ...) are errors.
* **Cross-file consistency:** when an aggregator file is given, each signer's key\_store.publish\_ahead must exceed the aggregator's poll\_interval plus fetch\_timeout (otherwise tokens could carry a kid the aggregated JWKS does not publish yet), and the aggregator's stale\_key\_retention must be at least each signer's token TTL (always true, since the aggregator itself requires at least the maximum token TTL); replica\_id must be unique across all signer files.
* **File checks** (skippable): TLS certificate and key exist, parse and match; the certificate is not expired; CA bundles parse. A certificate expiring within 30 days and a private key readable by group/others are warnings.
* **Warnings** flag valid but risky settings: instance verification disabled, no tags allowlist, keys ignored by the selected backend, replica\_id derived from the hostname, a per-instance rate limit looser than 1/5s.
* **Exit codes:** 0 when there are no errors (warnings allowed), 1 on errors (or on warnings with --strict), 2 when a file cannot be read or the command line is invalid.
* The services refuse to start on any error and log warnings at startup.

## **Error handling and failure modes**

| Failure | Behavior |
| :---- | :---- |
| Missing X-Auth-Token, or invalid/expired token | Reject with 401, do not sign |
| Token user not in keystone.allowed\_users or lacking keystone.required\_role | Reject with 403, do not sign, log the user ID (never the token) |
| Keystone unreachable while authenticating the caller | Reject with 503 |
| Key store / Proxy unreachable | Reject with 503; Nova omits metadata response |
| Signing fails for any other reason (e.g. a custom claim colliding with a reserved name) | Reject with 500, never issue an unsigned or partial token |
| Instance not found, owned by another project, or in a disallowed status | Reject with 403, do not sign, log mismatch |
| Nova API / Keystone unreachable during verification or enrichment | Reject with 503 |
| Per-source rate limit exceeded | Reject with 429 *before* the body is read |
| Per-instance rate limit exceeded | Reject with 429 before any lookup or signing |
| Malformed, oversized or invalid request body | Reject with 400, log the payload truncated and with user-data redacted |

**Operational Warning:** While an instance will retry a missing metadata target on its next poll, cloud-init configures the host during the initial local boot sequence. If a 503 KMS failure causes the JWT to be omitted during this exact window, downstream SPIRE-dependent systemd units will crash. Operators must monitor /readiness strictly, as transient failures will break attestation for newly booting instances.

## **Testing and validation**

**Unit tests**:

* Claim construction verifying the strict size limits/allowlist on the tags field.  
* Instance verification rejects unknown instances, project mismatches and disallowed statuses; enrichment claims appear only when enabled; lookups are served from cache within the TTL.  
* kid accurately reflects the active in-memory or Vault-backed signing key.  
* JWKS response correctly manages the retention window for rotated keys.

* Request validation rejects malformed bodies, duplicate members and non-canonical instance IDs.  
* kid format and uniqueness across replicas; a new key is published before it is used; readiness stays false until the first key has been published for publish\_ahead.  
* The aggregator merges replica key sets, excludes conflicting kids, retains an unreachable replica's keys for stale\_key\_retention and then drops them.  
* The configuration check reports every finding of a broken file in one run, with correct lines.

**Integration tests**:

* Keystone token validation accepts the allowlisted service user carrying the required role and rejects arbitrary user tokens (401/403).  
* **Required negative test:** a well-formed request without X-Auth-Token is rejected with 401 and nothing is signed.  
* Rate limiting middleware triggers 429 without reading the body; a burst from one instance gets 429 while another instance is unaffected.  
* End-to-end with two signer replicas and one aggregator: a token from either replica verifies against the aggregated JWKS by kid; after a rotation, tokens signed before it still verify and new tokens carry the new kid, which the aggregate publishes before its first use.

## **Build, packaging, deployment**

* Developed as a standalone HTTP service in Golang.  
* Deployed adjacent to the Nova control plane network segment, as several share-nothing signer replicas behind a load balancer (target of Nova's DynamicJSON configuration), plus one or more JWKS aggregator instances behind their own load balancer (endpoint of the SPIRE Server-side plugin).  
* Utilizes separate /liveness and /readiness probes to ensure orchestrators gracefully remove the service from the load balancer rotation during backend KMS disruptions without crash-looping the pods.