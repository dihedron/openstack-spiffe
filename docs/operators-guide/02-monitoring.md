# Monitoring

## Logs

The issuer logs to standard error, so to the journal under its units:

```bash
journalctl -u openstack-spire-issuer -f
journalctl -u openstack-spire-issuer-aggregator -f
```

`OPENSTACK_SPIRE_ISSUER_LOG_LEVEL`, in `signer.env` or a unit drop-in, selects `debug`, `info` (the default), `warn`, `error` or `off`. Every record handling a request carries its `request_id`, also returned to the caller in `X-Request-Id`. The plugins log through SPIRE Server's and SPIRE Agent's own logs, at their log level.

No component ever logs a token, a key, a credential, an instance's user data or its metadata values.

## The audit trail

Four kinds of audit records are written whatever the log level, even with `off`, each marked with an `audit` attribute:

| Record | By | Meaning |
| ---------------- | -------------- | ----------------------------------------------------------------- |
| `token_issued` | Signer replica | A token was issued |
| `key_lifecycle` | Signer replica | A key was generated, published, activated, retired or dropped |
| `agent_attested` | Server plugin | An agent attested |
| `reattest_alert` | Server plugin | An instance attested again within `reattest_alert_window` |

With `audit.syslog.enabled` on the signers and `audit_syslog.enabled` in the server plugin, these records also go to the local syslog daemon, with the `authpriv` facility by default. Forward them from there to a central, append-only store, and keep them as long as your incident response needs: they are the only record of which tokens were issued and which identities were given.

**Following a token.** Every token's ID, `jti`, is in the issuer's `token_issued` record and in the server plugin's `agent_attested` record:

```bash
# on a signer: the tokens issued for an instance
journalctl -u openstack-spire-issuer -o cat | grep 'audit=token_issued' | grep 'instance_id=<instance-id>'
# on SPIRE Server: the attestation that used a token
journalctl -u spire-server -o cat | grep 'audit=agent_attested' | grep 'jti=<jti>'
```

In the syslog copy, each record is a JSON object (journald's `MESSAGE`), with the same attributes and the exact time. *Appendix* lists every record's attributes.

## Metrics

When enabled (see the *Setup Guide*), the signers and aggregators export metrics, with the `openstack_spire_` prefix in Prometheus. The ones to watch first:

| Metric | What it tells |
| ---------------------------------------- | ------------------------------------------------------------- |
| `tokens_issued_total` | Tokens issued, by algorithm (and project, if enabled) |
| `attest_requests_total` | Every `/attest` call, by `outcome` (`issued`, `rejected`), `reason` and status |
| `attest_duration_seconds` | `/attest` latency, which delays every instance's first boot |
| `keystone_validations_total`, `keystone_validations_in_flight` | Keystone validations by result and source (cache, merged, backend), and how close to `max_concurrent_validations` |
| `verification_lookups_total`, `verification_lookup_duration_seconds` | Nova and Keystone lookups, by kind, result and source |
| `keys`, `key_active_age_seconds`, `key_rotations_total` | Keys by state, the active key's age, rotations |
| `jwks_fetches_total`, `jwks_fetch_age_seconds`, `jwks_conflicts`, `jwks_keys` | Peer and replica fetches, by peer; conflicting key IDs; keys served |
| `rate_limit_rejections_total`, `rate_limit_tracked` | Refusals and buckets, by limiter |
| `audit_syslog_dropped_total` | Audit records the syslog sink dropped |
| `readiness_check` | Each readiness check: 1 passing, 0 failing |

`attest_requests_total`'s `reason` is the most useful label: each value is one cause, explained in *Error reference*.

## Recommended alerts

| Alert | Condition | Means | First action |
| -------------------- | ---------------------------------------- | -------------------------------- | -------------------------------- |
| No active key | `keys{state="active"} == 0` for more than 5 minutes | The replica issues nothing | Its log: `key maintenance failed`; restart it |
| Rotation stalled | `key_active_age_seconds` above `rotation_interval` plus 10 minutes | Keys are not rotating | Its log; restart it |
| Replica not ready | `readiness_check == 0`, or `/readiness` failing, for more than 2 minutes | A dependency is down | The failing check's log record |
| Audit gap | `increase(audit_syslog_dropped_total[10m]) > 0` | The syslog trail is incomplete | The syslog daemon, the socket |
| Stale peer | `jwks_fetch_age_seconds` above 3 minutes | That peer's keys will soon be dropped | The peer's health, the network, its certificate |
| Key conflict | `jwks_conflicts > 0` | Two sources publish one key ID differently | Duplicate `replica_id`s; a compromised peer |
| Refusals rising | `rate(attest_requests_total{outcome="rejected"}[15m])` above its usual level | See its `reason` | *Error reference* |
| Credentials tried elsewhere | `increase(attest_requests_total{reason="source_not_allowed"}[15m]) > 0`, and the same for `client_certificate` and `caller_not_allowed` | Someone presents vendordata credentials from where Nova does not | *Incident procedures* |
| Keystone saturated | `increase(attest_requests_total{reason="keystone_busy"}[5m]) > 0` | The validation cap is reached | A flood of bogus tokens, or a cap too low |
| Slow issuance | 99th percentile of `attest_duration_seconds` above 2 seconds | Instances wait at boot | `verification_lookup_duration_seconds`, Keystone |

On SPIRE Server, alert on `reattest_alert` audit records (`possible token theft: instance re-attested`), and on a rise of attestation errors in its log.
