# Appendix

## Log messages

Every message the issuer logs at the warning level or above, and the plugins' notable ones. The *Error reference* gives the remedies.

| Message | Component | Level | Meaning |
| -------------------------------------------------- | ---------------- | ------- | ---------------------------------------------- |
| `configuration warning` | Issuer | warn | A risky setting, at startup: see its `path` and `message` |
| `profiling is enabled: profiles may contain private key material; ...` | Signer | warn | CPU or heap profiling is on |
| `rejecting /attest request` | Signer | warn | The source or client certificate is refused |
| `rejecting unauthenticated request` | Signer | warn | No valid Keystone token |
| `rejecting unauthorized caller` | Signer | warn | A user not allowed, or without the role |
| `cannot validate caller token` | Signer | error | Keystone failed |
| `request body too large`, `rejecting oversized request body` | Signer | warn | Over `max_body_bytes` |
| `cannot read request body`, `rejecting malformed request body`, `rejecting invalid request`, `rejecting invalid nova request` | Signer | warn | An invalid request |
| `per-instance rate limit exceeded` | Signer | warn | Too many tokens for one instance |
| `instance verification failed` | Signer | warn | The instance does not match: see `reason` |
| `cannot look up instance in Nova`, `cannot look up project in Keystone` | Signer | error | A lookup failed |
| `server record lacks an enrichment attribute`, `project record lacks an enrichment attribute`, `invalid enrichment attribute` | Signer | error | An optional claim is missing or invalid |
| `cannot sign token` | Signer | error | The key store failed |
| `refusing to sign claims with reserved custom claim names`, `refusing to issue an oversized token`, `cannot mint token`, `cannot encode response` | Signer | error | An internal error |
| `an /attest rejection named no reason: please report it` | Signer | error | A bug |
| `key maintenance failed, retrying` | Signer | error | Key generation or rotation failed |
| `cannot read public keys for the JWKS`, `cannot encode public key for the JWKS`, `cannot encode the JWKS` | Signer | error | A key set could not be served |
| `replica fetch failing`, `replica published ...`, `replicas publish different keys under the same kid: kid excluded`, `cannot read the local keys to check them for conflicts` | Signer, aggregator | warn, error | See *Peers and aggregators* |
| `readiness check failing` | Signer, aggregator | warn | A readiness check started failing |
| `syslog audit records dropped, they remain in the regular log` | Signer | warn | The syslog sink drops records |
| `syslog audit records delivered again` | Signer | warn | It recovered, with the count dropped |
| `cannot send every queued audit record to syslog, they remain in the regular log` | Signer | error | At shutdown |
| `metrics export failing` | Signer, aggregator | warn | The OpenTelemetry Collector cannot be reached |
| `metrics: max_projects reached, further projects are counted as "other"` | Signer | warn | Per-project counts are capped |
| `flushing the metrics` | Signer, aggregator | warn | The last export failed at shutdown |
| `background loop failed` | Signer, aggregator | error | An internal loop ended with an error |
| `attestation rejected`, `attestation rejected: project not allowed`, `attestation rejected: no verification keys`, `attestation rejected: replay cache full` | Server plugin | warn, error | See *The server plugin* |
| `possible token theft: instance re-attested` | Server plugin | warn | A quick re-attestation (audit) |
| `syslog audit records dropped, they remain in SPIRE Server's log` | Server plugin | warn | Its syslog sink drops records |

## Audit records

Every audit record carries `audit=<kind>` and, in its syslog copy, the exact `time`.

**`token_issued`** (signer): `request_id`; `user_id`, Nova's caller; `client_address`, and `peer_address` when a trusted proxy forwarded it; `client_cert_subject` and `client_cert_serial` when Nova presented a certificate; `project_id`, `instance_id`; `jti`, `kid`, `iat`, `exp`.

**`key_lifecycle`** (signer): `event` (`generated`, `published`, `active`, `retired`, `dropped`); `replica_id`, `kid`, `algorithm`; `thumbprint`, the key's RFC 7638 SHA-256 thumbprint; `effective_at`; `activates_at` for `published`. `dropped` is logged at the notice level.

**`agent_attested`** (server plugin): `project_id`, `instance_id`, `spiffe_id`; `jti`, `kid`, `iat`, `exp`; `selectors`, the number of selectors.

**`reattest_alert`** (server plugin): `project_id`, `instance_id`; `jti` and `previous_jti`; `interval`, the time between the two attestations.

## Metrics

The metrics' names in Prometheus, with their labels. Resource attributes (`service_instance_id`, the replica's `replica_id` or the aggregator's host name; `openstack_spire_component`; `service_version`) are on the `target_info` series.

| Metric | Type | Labels |
| -------------------------------------------------- | ---------- | ---------------------------------------------- |
| `openstack_spire_tokens_issued_total` | counter | `algorithm`, `project_id` (if enabled) |
| `openstack_spire_attest_requests_total` | counter | `outcome`, `reason`, `http_response_status_code` |
| `openstack_spire_attest_duration_seconds` | histogram | `outcome` |
| `openstack_spire_token_size_bytes` | histogram | — |
| `openstack_spire_tags_dropped_total` | counter | `reason` |
| `openstack_spire_keystone_validations_total` | counter | `result`, `source` |
| `openstack_spire_keystone_validation_duration_seconds` | histogram | `result` |
| `openstack_spire_keystone_validations_in_flight` | gauge | — |
| `openstack_spire_verification_lookups_total` | counter | `kind`, `result`, `source` |
| `openstack_spire_verification_lookup_duration_seconds` | histogram | `kind`, `result` |
| `openstack_spire_signing_duration_seconds` | histogram | `algorithm`, `result` |
| `openstack_spire_keys` | gauge | `state` |
| `openstack_spire_key_active_age_seconds` | gauge | — |
| `openstack_spire_key_rotations_total` | counter | — |
| `openstack_spire_jwks_fetches_total` | counter | `peer`, `result` |
| `openstack_spire_jwks_fetch_age_seconds` | gauge | `peer` |
| `openstack_spire_jwks_conflicts` | gauge | `peer` |
| `openstack_spire_jwks_keys` | gauge | `set` |
| `openstack_spire_rate_limit_rejections_total` | counter | `limiter` |
| `openstack_spire_rate_limit_tracked` | gauge | `limiter` |
| `openstack_spire_audit_syslog_dropped_total` | counter | — |
| `openstack_spire_audit_syslog_queue` | gauge | — |
| `openstack_spire_readiness_check` | gauge | `check` |
| `http_server_request_duration_seconds` | histogram | `http_route`, `http_request_method`, `http_response_status_code` |

Go runtime metrics (`go_...`) are added when `runtime` is on. With OTLP, the names keep their dotted form (`openstack_spire.tokens.issued`), and the resource attributes stay on the resource.
