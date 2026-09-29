# OpenStack vendor data JWT issuer — implementation spec

Sep 20, 2026 · @Andrea Funtò

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

## **Nova integration and request-context binding**

This service operates as a Nova **DynamicJSON vendordata target**. It is invoked by nova-api/nova-api-metadata on the instance's behalf.  
**Registration** (Nova operator config):

* api.vendordata\_providers must include DynamicJSON.  
* api.vendordata\_dynamic\_targets includes an entry named openstack\_iid, e.g., openstack\_iid@\[https://vendordata-signer.internal:8443/attest\](https://vendordata-signer.internal:8443/attest).

**Request shape** (Nova → this service, JSON POST):

* project-id: The project that owns the instance.  
* instance-id: The instance UUID.  
* image-id: The boot image ID.  
* hostname: The instance hostname.  
* metadata: User-supplied key/value pairs at boot time.

**The Authorization Binding (Service-to-Service):**  
Because the HTTP request is made asynchronously by nova-compute during the instance boot sequence, it does *not* possess the original user's Keystone token. Therefore, this service must authenticate the incoming request by validating the nova-compute service token via oslo.middleware (or equivalent). We must establish trust in Nova's claims about the project-id and instance-id based on the authenticated identity of the OpenStack compute control plane.  
**Response shape**: The service must return {"openstack\_iid": {"jwt": "\<token\>"}} to match the target name expected by the agent plugin.

## **Claim schema**

JSON  
{  
  "header": {  
    "alg": "RS256",  
    "kid": "2026-09-key-1"  
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

* **Payload Bloat Protection:** Users frequently abuse OpenStack instance metadata for large cloud-init scripts. To prevent JWT headers from exceeding standard HTTP limits (4KB-8KB) downstream, tags must filter the incoming metadata field using an explicit allowlist of approved keys, or enforce a strict 1024-byte maximum size for the tags object.  
* **TTL:** exp \- iat must be a short, fixed window of 5 minutes.  
* **Immutability:** Every claim value comes exclusively from the authorized Nova request.

## **Signing key management**

To prevent thundering herd failures during cluster scale-ups, this service avoids routing per-token Sign requests to control-plane key managers like Barbican.  
**Custody & Generation Architectures:**

> 1. **Vault Transit Backend (Recommended for Enterprise Persistence):** Offload signing operations to a HashiCorp Vault REST API proxy. Utilizing dual-cluster token replication and DBOS durable workflows ensures the high-throughput, data-plane resilience required for instance boot storms without writing private keys to disk.  
> 2. **Ephemeral In-Memory Keys (Recommended for Stateless Simplicity):** The Golang service generates an RSA 2048-bit (or ECDSA P-256) keypair entirely in memory at startup. The public half is published to the JWKS endpoint. If the pod restarts, it simply generates a new key.

**Rotation & Retention:** Keys rotate on a fixed schedule or upon service restart. The previous key's public component remains in the JWKS response for at least one full token TTL past rotation to validate in-flight tokens.

## **JWKS endpoint**

This service exposes the public half of trusted signing keys for the SPIRE Server-side plugin.

* **Endpoint**: GET /.well-known/jwks.json, formatted as a standard RFC 7517 JWK Set.  
* **Protection**: Served over TLS with a certificate the SPIRE Server operator can pin.  
* **Caching headers**: Cache-Control max-age must align with the rotation cadence.  
* **Content**: Includes the currently active key and any key retired within the last 5 minutes.

## **Freshness and replay controls**

* **Fresh jti**: Generate a new UUID for every token minted.  
* **No Replay Tracking**: Enforcing jti reuse is the responsibility of the downstream SPIRE Server, not this service.  
* **Pre-Parsing Rate Limiting**: Apply a per-instance-ID rate limit (e.g., 1 token per 5 seconds). This must be implemented in the HTTP middleware (e.g., a token bucket) *before* the JSON payload is read into memory, ensuring spam requests are rejected cheaply.

## **API surface and configuration**

**Endpoints**:

| Method | Path | Purpose |
| :---- | :---- | :---- |
| POST | /attest | Issue a signed JWT for the requesting instance |
| GET | /.well-known/jwks.json | Fetch current trusted public keys |
| GET | /liveness | HTTP server process check (used by orchestrator to restart crashed pods) |
| GET | /readiness | Dependency and KMS connectivity check (used by orchestrator to route traffic) |

**Config**:

YAML  
listen\_addr: "0.0.0.0:8443"  
tls\_cert\_path: "/etc/vendordata-signer/tls.crt"  
tls\_key\_path: "/etc/vendordata-signer/tls.key"  
key\_store:  
  backend: "vault\_transit" \# or "ephemeral\_memory"  
  vault\_proxy\_endpoint: "https://vault-proxy.internal:8200"  
token\_ttl\_seconds: 300  
rate\_limit\_per\_instance: "1/5s"

## **Error handling and failure modes**

| Failure | Behavior |
| :---- | :---- |
| Missing/Invalid nova-compute service token | Reject with 401/403, do not sign, log mismatch |
| Key store / Proxy unreachable | Reject with 503; Nova omits metadata response |
| Rate limit exceeded | Reject with 429 *before* payload parsing |
| Malformed JSON body | Reject with 400, log payload |

**Operational Warning:** While an instance will retry a missing metadata target on its next poll, cloud-init configures the host during the initial local boot sequence. If a 503 KMS failure causes the JWT to be omitted during this exact window, downstream SPIRE-dependent systemd units will crash. Operators must monitor /readiness strictly, as transient failures will break attestation for newly booting instances.

## **Testing and validation**

**Unit tests**:

* Claim construction verifying the strict size limits/allowlist on the tags field.  
* kid accurately reflects the active in-memory or Vault-backed signing key.  
* JWKS response correctly manages the retention window for rotated keys.

**Integration tests**:

* Verify oslo.middleware successfully authenticates valid nova-compute service tokens and rejects arbitrary user tokens.  
* Rate limiting middleware triggers 429 without allocating memory for body parsing.

## **Build, packaging, deployment**

* Developed as a standalone HTTP service in Golang.  
* Deployed adjacent to the Nova control plane network segment.  
* Utilizes separate /liveness and /readiness probes to ensure orchestrators gracefully remove the service from the load balancer rotation during backend KMS disruptions without crash-looping the pods.