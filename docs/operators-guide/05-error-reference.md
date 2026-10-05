# Error reference

Every error the solution can produce, where it appears, what causes it, and what to do. Log messages are quoted as the components write them; the `error` or `reason` attribute of a record gives the detail.

## The issuer's `/attest` responses

Nova calls `/attest` for every instance metadata read. When the issuer refuses, Nova logs the failed vendordata call and serves the metadata without the token; the instance's agent then fails to attest (see *The agent plugin* below). The `reason` is the label of `openstack_spire_attest_requests_total`; the log message is the issuer's.

| Status | Reason | Issuer's log message | Cause | Remedy |
| ----- | ------------------------ | ------------------------- | ----------------------- | ----------------------- |
| `200` | `none` | `token issued` (audit) | A token was issued | — |
| `403` | `source_not_allowed` | `rejecting /attest request`, reason `source not in attest.allowed_sources` | The client address is not in `attest.allowed_sources` | If Nova: add the metadata hosts' (or the load balancer's) addresses, or set `client_address.trusted_proxies`. Otherwise: someone else holds the credentials (see *Incident procedures*) |
| `403` | `client_certificate` | `rejecting /attest request`, reason `no client certificate` or `invalid client certificate: ...` | No client certificate, or one not issued by `attest.client_ca_path`'s CA for client authentication, or expired | Check Nova's `certfile` and `keyfile`; a load balancer terminating TLS removes the certificate |
| `429` | `rate_limited_source` | `per-source rate limit exceeded` (debug) | More requests from one client address than `rate_limit_per_source` | Raise the limit for your metadata hosts' peak; behind a load balancer, set `client_address.trusted_proxies` |
| `400` | `invalid_request` | `request body too large`, `rejecting oversized request body`, `cannot read request body`, `rejecting malformed request body`, `rejecting invalid request`, `rejecting invalid nova request` | A body over `max_body_bytes`, unreadable, malformed JSON, duplicate members, or an invalid project ID, instance ID or host name; also `405` for a method other than `POST` | Raise `max_body_bytes` if large user data is legitimate; otherwise the caller is not Nova, or Nova sends something unexpected |
| `401` | `unauthenticated` | `rejecting unauthenticated request` | No `X-Auth-Token`, or a token Keystone rejects or that expired | Check `[vendordata_dynamic_auth]`'s credentials on the metadata hosts |
| `403` | `caller_not_allowed` | `rejecting unauthorized caller`, with the `user_id` | The token's user is not in `keystone.allowed_users`, or lacks `keystone.required_role` | List the vendordata user's ID; grant it the role. An unknown user ID means someone else is calling |
| `503` | `keystone_busy` | `refusing caller: Keystone validation cap reached` (debug) | `keystone.max_concurrent_validations` validations already in flight | Usually a flood of bogus tokens: find its source; raise the cap only if legitimate traffic needs it |
| `503` | `keystone_unavailable` | `cannot validate caller token` | Keystone unreachable, slow, or refusing the replica's service credentials | Keystone's health; the replica's `signer.env`; `readiness` shows `keystone` failing |
| `429` | `rate_limited_instance` | `per-instance rate limit exceeded` | More tokens for one instance than `rate_limit_per_instance` | Normal in bursts: Nova asks again at the next read. Persistent: something reads the instance's metadata in a loop |
| `403` | `instance_not_allowed` | `instance verification failed`, reason `instance not found in Nova`, `instance belongs to another project`, `disallowed instance status` or `project not found in Keystone` | The instance does not exist, is another project's, is in a status not in `nova_lookup.allowed_statuses`, or its project is unknown | Expected for deleted and shelved instances. Otherwise the caller lies about the instance: investigate |
| `503` | `lookup_unavailable` | `cannot look up instance in Nova`, `cannot look up project in Keystone` | The Nova API or Keystone failed during verification | Their health; `readiness` shows `nova` failing |
| `503` | `enrichment_invalid` | `server record lacks an enrichment attribute`, `project record lacks an enrichment attribute`, `invalid enrichment attribute` | An enabled `enrich` claim is empty (e.g. the availability zone of an instance not scheduled yet) or has invalid characters | Usually transient at boot: Nova asks again. Persistent: fix the value in OpenStack (a flavor or project name) or disable that claim |
| `503` | `key_store_unavailable` | `cannot sign token`, error `key store unavailable` | The replica has no active key (just started) or cannot sign | Transient after a start; persistent: restart the replica |
| `500` | `signing_failed` | `refusing to sign claims with reserved custom claim names`, `refusing to issue an oversized token`, `cannot mint token`, `cannot encode response` | An internal error: a custom claim colliding with a reserved name, a token over 16 KiB | Report it, with the log record |
| any | `unspecified` | `an /attest rejection named no reason: please report it` | A refusal path that does not name its reason: a bug | Report it, with the log record |

## The issuer at startup

`service start` and `jwks aggregate` refuse to start on any problem, log `refusing to start: <cause>` (`error: refusing to start: ...` on standard error) and exit with code 1; systemd restarts them after 5 seconds, so the message repeats in the journal.

| Cause in the message | Meaning | Remedy |
| ---------------------------------- | -------------------------------------------- | ---------------------------------------- |
| A configuration finding, with its file, line and key | The configuration has an error | Run `config check` for the full report, and fix it |
| `syslog audit sink: ...` | `audit.syslog.enabled` is on and the socket cannot be opened | Check `audit.syslog.socket` (`/dev/log`) and the syslog daemon |
| `marking the process non-dumpable: ...` | The kernel refused to make the process non-dumpable | Very unusual: a security module denying `prctl`; check the host's policy |
| `locking the process memory: ...: raise the locked-memory limit ...` | Memory locking failed, usually because the locked-memory limit is not unlimited | Keep the unit's `LimitMEMLOCK=infinity` (a drop-in may override it), or set `key_store.lock_memory: false` and disable or encrypt swap |
| `only supported on Linux` | Memory protection exists only on Linux | Run the signer on Linux |
| `OS_...` variables missing or invalid | `signer.env` lacks or misstates the credentials | Fix `signer.env` (see the *Setup Guide*) |
| An authentication error from Keystone | The service credentials are wrong, or Keystone is unreachable | Check them with the `openstack` CLI, with the same variables |
| A TLS certificate or key error | The certificate or key cannot be loaded | `config check` names the problem |

## `config check`

`openstack-spire-issuer config check` reports every finding, each with its file, line, key, severity and kind, and exits with:

- exit code `0`: no errors (warnings allowed);
- exit code `1`: errors, or warnings with `--strict`;
- exit code `2`: a file could not be read, or the command line is invalid.

| Kind | Meaning |
| ---------------- | ---------------------------------------------------------------------------- |
| `syntax` | The YAML does not parse |
| `unknown-key` | A key the configuration does not have; a suggestion names the closest known key |
| `invalid-value` | A value of the wrong type or format (a duration, a rate, an address) |
| `rule-violation` | A value out of its range, or inconsistent with another key of the same file |
| `inconsistency` | Values that conflict across files: duplicate `replica_id`s, or a `publish_ahead` too short for the aggregator's timings |
| `file` | A referenced certificate, key or CA bundle is missing, unparsable, mismatched or expired |
| `risky` (a warning) | A valid but risky choice; the *Setup Guide*'s configuration reference explains each |

## Peers and aggregators

| Log message | Meaning | Remedy |
| ---------------------------------------- | -------------------------------------------- | ---------------------------------------- |
| `replica fetch failing` | A peer or replica cannot be fetched: unreachable, a TLS error, a non-`200` status, an oversized or invalid set, too many keys. Logged when it starts failing; its keys are kept for `stale_key_retention` | The peer's health; the URL (`/jwks/local.json`); the CA bundle |
| `replica fetch recovered` | The fetch works again | — |
| `replica published a malformed key, ignored`, `replica published an unacceptable key, ignored` | A key that is not a valid public signing key of an allowed algorithm | The peer runs something else than the issuer at that URL |
| `replica published private key material: key rejected` | A key carrying private material: never served | Treat the peer as compromised |
| `replicas publish different keys under the same kid: kid excluded` | A key ID conflict: tokens signed with that key are refused | Duplicate `replica_id`s, or a compromised source (see *Incident procedures*) |
| `cannot read the local keys to check them for conflicts` | The replica's own key store failed during a poll | Restart the replica if it persists |
| `readiness check failing`, check `replicas` | An aggregator fetched no replica within `stale_key_retention` | The replicas' health and the network |
| `JWK Set polling stopped` | A polling loop ended with an error | Restart the process; report it |

## The server plugin

SPIRE Server logs the plugin's records, and returns its errors to the agent, which logs them too. Each error carries a gRPC status code.

### Attestation errors

| Code | Message | Cause | Remedy |
| ---------------------- | -------------------------------------------- | ---------------------------------------- | ---------------------------------- |
| `InvalidArgument` | `attestation payload of N bytes, at most M allowed`, `decoding attestation payload: ...`, `attestation payload carries no jwt` | The agent sent no valid payload | The agent is not running the `openstack_iid` agent plugin, or another version |
| `Unavailable` | `reading verification keys: ...` | The key set could not be read | The JWK Set endpoint's health (see `jwks_url`) |
| `Unavailable` | `no verification keys: the JWK Set has not been fetched successfully within jwks_stale_key_retention` | No successful fetch for longer than `jwks_stale_key_retention`: every attestation is refused | The endpoint, `jwks_ca_cert_path`, the network from SPIRE Server |
| `PermissionDenied` | `attestation rejected: <detail>` | The token failed verification: see the details below | Per detail |
| `PermissionDenied` | `attestation rejected: project <id> is not in allowed_project_ids` | The instance's project is not served by this SPIRE deployment | Add it to `allowed_project_ids` if it should be |
| `PermissionDenied` | `attestation rejected: token already used; a fresh token is needed` | The token was accepted before: a replay, or an agent presenting a token twice | Transient for an agent: its next attempt gets a fresh token. Repeated: someone replays tokens |
| `PermissionDenied` | `attestation rejected: token issued before this server started; a fresh token is needed` | The startup watermark, right after a SPIRE Server restart | None: the agent's next attempt succeeds |
| `Unavailable` | `attestation rejected: replay cache full` | 100,000 tokens accepted within their lifetime: far above any normal rate; it fails closed | An attestation flood: find its source |
| `FailedPrecondition` | `not configured` | The plugin received an attestation before its configuration | SPIRE Server's log shows why configuration failed |

### Verification details

The detail after `attestation rejected:` names the check that failed. Most start with `invalid token`:

| Detail | Cause | Remedy |
| ---------------------------------------- | ------------------------------------------------ | ---------------------------------------- |
| `unknown kid "<kid>"` | No key in the set has that ID, even after a refetch | The signing replica is missing from the peers' or aggregators' lists, or its key was dropped (a restart, a conflict) |
| `invalid kid` (logged as `kid=invalid`) | The key ID is not the issuer's format | Not a token of this issuer |
| `invalid token: N bytes, at most M allowed`, `not a compact-serialized JWS`, `decoding header`, `decoding payload`, `decoding signature`, `critical header extensions are not supported` | Malformed token | Not a token of this issuer |
| `invalid token: algorithm "X" not allowed`, `type "X", want JWT`, `alg X, but key "K" is for Y` | A disallowed algorithm or type, or an algorithm differing from its key's | Not a token of this issuer, or a forged one |
| `invalid token: signature does not verify with key "K"`, `ES256 signature of N bytes, want 64`, `key "K" ... cannot verify tokens` | Forged or corrupted | Investigate: a token not signed by the issuer |
| `invalid token: issuer "X", want "nova-spire-plugin"`, `audience "X", want "spire-node-attestation"` | Wrong issuer or audience | Not a token of this issuer |
| `invalid token: expired (exp T)` | Older than its lifetime plus the clock tolerance | Clocks out of sync, or a token held too long (Nova's cache, a slow agent) |
| `invalid token: not valid yet (nbf N, iat T)` | Issued in the future by more than the tolerance | The issuer's clock is ahead: fix NTP |
| `invalid token: inconsistent times (nbf ...)`, `lifetime D exceeds 5m0s`, `no jti` | Malformed times or ID | Not a token of this issuer |
| `invalid token: sub differs from instance_id`, `instance_id: ...`, `project_id: ...`, `hostname: ...` | A claim with an invalid format | Not a token of this issuer, or an incompatible version |
| `invalid token: tags: ...`, `tags of N bytes, at most 1024 allowed`, `<claim>: ...` | A tag or optional claim with invalid characters, or too large | An older issuer: upgrade the issuers before the server plugin |

### Configuration errors

The plugin fails to configure, and SPIRE Server to start, with `InvalidArgument` and one of:

| Message | Remedy |
| ------------------------------------------------ | ---------------------------------------------------------------- |
| `jwks_url is required`; `jwks_url: "..." is not an https URL`; `jwks_url: "..." serves a single replica's keys` | Point `jwks_url` at the merged set, over https |
| `tls_min_version: "X", want "1.2" or "1.3"` | Fix `tls_min_version` |
| `jwks_ca_cert_path: ...` | The CA bundle is missing or unparsable |
| `jwks_fetch_timeout: D must be less than jwks_refresh_interval` | Fix the timings |
| `allowed_project_ids[N]: ...`, `allowed_tag_keys[N]: ...` | An invalid entry |
| `audit_syslog: ...`, `audit_syslog.facility: ...`, `audit_syslog.app_name: ...` | Fix the block; the socket must be openable |
| `trust domain "..." from the core configuration is not a valid SPIFFE trust domain name` | Fix SPIRE Server's `trust_domain` |
| `creating JWK Set client: ...` | The TLS settings or CA bundle cannot be used |
| An unknown key, a malformed duration, or a value out of range | The message names the key |

Configuration warnings (`jwks_ca_cert_path`, `allowed_project_ids`, `allowed_tag_keys` unset, `audit_syslog` disabled) do not stop SPIRE Server.

## The agent plugin

SPIRE Agent logs the plugin's errors when node attestation fails, and retries.

| Code | Message | Cause | Remedy |
| ---------------------- | -------------------------------------------- | ---------------------------------------- | ---------------------------------- |
| `Unavailable` | `fetching the instance identity token: vendordata has no openstack_iid target (Nova omits it when the issuer fails: check the issuer's readiness)` | Nova's call to the issuer failed | The issuer's log for this instance; *The issuer's /attest responses* above |
| `Unavailable` | `fetching the instance identity token: vendordata: unexpected status ...`, `reading vendordata: ...`, `vendordata larger than N bytes`, `decoding vendordata: ...` | The metadata service is unreachable or answers badly | The instance's network to `169.254.169.254`; Neutron's metadata proxy; the guest hardening rule (is SPIRE Agent's user allowed?) |
| `Unavailable` | `fetching the instance identity token: invalid token in vendordata: ...` (`no token`, `N bytes, at most M allowed`, `not a compact-serialized JWS`, `decoding payload: ...`, `no jti`) | `openstack_iid.jwt` is missing or malformed | Another service answers as `openstack_iid` in Nova's `vendordata_dynamic_targets` |
| `Unavailable` | `fetching the instance identity token: vendordata keeps serving an already presented token (jti J) after D; Nova may be caching it longer ([api] metadata_cache_expiration)` | Nova served the token already presented for longer than `fresh_token_timeout` | Raise `fresh_token_timeout` above Nova's `metadata_cache_expiration`, or lower that |
| `Internal` | `encoding payload: ...` | An internal error | Report it |
| `FailedPrecondition` | `not configured` | Attestation before configuration | SPIRE Agent's log shows why configuration failed |
| `InvalidArgument` | `vendordata_url: "..." is not an http or https URL`; `fresh_token_timeout ... (it must be at least http_timeout)`; an unknown key or malformed duration | A configuration error: SPIRE Agent does not start | Fix `plugin_data` |
