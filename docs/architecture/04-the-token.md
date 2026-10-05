# The token

The token is a JSON Web Token (JWT), signed with the issuer replica's key (JWS compact serialization). Its format is a contract between the issuer and the plugins, defined once and compiled into all three.

## Header

| Field | Value |
| ------ | -------------------------------------------------------------------- |
| `alg` | `RS256` (RSA 2048) or `ES256` (ECDSA P-256), the replica's key algorithm |
| `kid` | The signing key's ID: `<YYYY-MM-DD>-<replica_id>-key-<n>`, such as `2026-09-29-signer-a-key-52331` |
| `typ` | `JWT` |

The key ID tells which replica signed the token, and when the key was created. It is unique across replicas and across restarts of a replica: the date and the seconds since midnight (`n`) never repeat within a replica.

## Claims

| Claim | Content | Source | Trust |
| --------------- | ------------------------------------------------- | ------------------------------ | -------------------- |
| `iss` | `nova-spire-plugin` | Fixed | Contract value |
| `aud` | `spire-node-attestation` | Fixed | Contract value |
| `sub` | The instance's ID | Nova's request, confirmed against the Nova API | Control plane |
| `instance_id` | The instance's ID, as `sub` | As above | Control plane |
| `project_id` | The instance's project | Nova's request, confirmed against the Nova API | Control plane |
| `iat`, `nbf`, `exp` | Issuance time, and expiry 5 minutes later | The issuer's clock | Issuer |
| `jti` | A fresh random ID, unique to the token | The issuer | Issuer |
| `hostname` | The instance's host name | Nova's request | **Tenant-asserted** |
| `tags` | A map of strings from the instance's metadata | Nova's request | **Tenant-asserted** |
| `availability_zone`, `flavor`, `user_id` | Optional, from the Nova server record | Nova API | Control plane |
| `project_name`, `domain_id` | Optional, from Keystone | Keystone | Control plane; the name is set by the project's administrators |
| Custom claims | Static strings the operator configures | Configuration | Issuer's operator |

**Tenant-asserted claims.** Any member of the instance's project sets its name and metadata through the OpenStack API, and the issuer passes them on unverified. Their selectors mean "a member of this project said so": good for telling instances apart within a project, never for trusting one across projects. *Verification in SPIRE Server* explains the rule this imposes on registration entries.

**What is never in a token.** The instance's user data, never decoded; the compute host and hypervisor, which would disclose the cloud's physical layout to tenants, since the token is readable inside the instance; and user-controlled server attributes (server tags, key pair), which carry no more trust than metadata.

## Limits

- **Lifetime**: 5 minutes at most. The issuer refuses a longer configuration, and the server plugin rejects a longer token. With the clock tolerance applied at both ends, a token is accepted for 6 minutes by default, and 7 at most.
- **Size**: tags at most 1024 bytes, custom claims at most 2048 bytes, optional claim values at most 255 bytes each, and the whole token at most 16 KiB. A real token is about 6 KiB at most. The issuer refuses to issue a larger token, and the plugins refuse to handle one.
- **Characters**: tag keys and values, and optional claim values, must be valid UTF-8 without control or format characters (such as bidirectional overrides), which could make selectors that look identical differ, or forge log lines. The issuer drops such tags. An optional claim failing the rule makes the issuer refuse the request, since it signals a control-plane anomaly. The server plugin rejects a token carrying either.
- **Tag keys** never contain `:`, so that a selector `openstack_iid:tag:<key>:<value>` always splits unambiguously.
- **Instance IDs** are canonical lowercase UUIDs, and project IDs at most 64 characters from `[A-Za-z0-9_-]`, so that one instance never has two forms, and both make safe SPIFFE ID path segments.

## Delivery

The issuer answers Nova with `{"jwt": "<token>"}`. Nova nests each vendordata target's answer under the target's name in `vendor_data2.json`, so the instance finds the token at `openstack_iid.jwt`. The answer is marked `Cache-Control: no-store`: it is a credential.
