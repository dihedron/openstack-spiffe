# OpenStack metadata JWT issuer — metrics spec

Oct 5, 2026 · @Andrea Funtò · **Approved Oct 5, 2026; not implemented yet**

## Overview

The issuer (`openstack-spire-issuer`: the signer replicas and the JWKS aggregator, see `openstack-spire-issuer.md`) can today be observed only through its logs, its audit records and its `/liveness` and `/readiness` probes. Counting tokens per project, seeing how long issuance takes during a boot storm, or noticing that a dependency degrades before readiness fails all require processing the logs.

This spec adds metrics, instrumented with OpenTelemetry and exported either for scraping (Prometheus format, on a dedicated listener) or by push (OTLP, to an OpenTelemetry Collector). It is a companion of the issuer spec, which refers to it for everything about metrics; the threat model carries the threats and the trust boundary it introduces (I-8, D-10, TB8), and the test environment spec its lab scenarios (MET-1, MET-2).

**Questions the metrics answer**, the business ones first:

- How many tokens are issued, per replica and, if enabled, per project; how many instances attest per hour.
- Which share of Nova's calls fail, and why: refused callers, rate limits, unknown instances, unavailable dependencies.
- How long issuance takes, end to end and per dependency (Keystone, Nova, signing), since it delays every instance's first boot.
- Whether keys rotate on schedule, and whether peers and aggregators keep their merged key sets fresh.
- Whether the audit trail is complete (syslog records dropped).

**Out of scope**:

- The SPIRE plugins. They run inside SPIRE Server and SPIRE Agent, which have their own telemetry (`telemetry` block), and the plugin SDK gives plugins no metrics channel. The server plugin's attestation outcomes remain in its audit records.
- Traces and logs through OpenTelemetry. Logs stay on `log/slog` and syslog; tracing can come later on the same SDK.
- Dashboards and alert rules, beyond the examples in the README.

## Design

**Instrumentation**: the OpenTelemetry metrics API (`go.opentelemetry.io/otel/metric`) and SDK (`go.opentelemetry.io/otel/sdk/metric`). A new package, `internal/issuer/metrics`, creates every instrument once, behind a small typed API (`metrics.TokenIssued(ctx, attrs)`, ...), so that instrument names, units and attribute sets are defined in one place and the components never touch the OpenTelemetry API directly. When metrics are disabled, the package uses OpenTelemetry's no-op provider: instrumentation costs nothing and needs no branches in the components.

**Exporters**, one per process, selected by `metrics.exporter`:

- `prometheus`: a pull endpoint, `GET /metrics` in the Prometheus text format, served on its own listener (`metrics.prometheus.listen_addr`), never on the Nova-facing one (see protection). Uses `go.opentelemetry.io/otel/exporters/prometheus`.
- `otlp`: periodic push (`metrics.otlp.interval`, default 30s) to an OpenTelemetry Collector over OTLP/HTTP (`go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp`), or OTLP/gRPC with `metrics.otlp.protocol: grpc`. gRPC is already a dependency of the module (through the SPIRE plugin SDK).

**Configuration comes from the file only.** The SDK's `OTEL_*` environment variables are not read, as for the syslog audit sink: the metrics configuration decides what leaves the host, so `config check` must see all of it. The one exception is credentials for the collector (`metrics.otlp.headers_env`, below), which never belong in a file.

**Resource attributes**, on every metric: `service.name` (`openstack-spire-issuer`), `service.version`, `service.instance.id` (the `replica_id` for a signer, the host name for an aggregator) and `openstack_spire.component` (`signer` or `aggregator`). With the Prometheus exporter they appear on the `target_info` series.

**Naming**: OpenTelemetry semantic conventions. Instrument names are dotted and prefixed with `openstack_spire.` (the Prometheus exporter turns `openstack_spire.tokens.issued` into `openstack_spire_tokens_issued_total`); units follow UCUM (`s`, `By`, `{token}`). Durations are histograms in seconds, with explicit buckets suited to each (below).

## Metrics

### Business

| Instrument | Type | Attributes | Meaning |
| --- | --- | --- | --- |
| `openstack_spire.tokens.issued` | counter `{token}` | `algorithm`; `project_id` when `metrics.project_attribute` is on (see cardinality) | Tokens issued: one per `token_issued` audit record |
| `openstack_spire.attest.requests` | counter `{request}` | `outcome` (`issued`, `rejected`), `reason` (below), `http.response.status_code` | Every `/attest` call, by outcome |
| `openstack_spire.attest.duration` | histogram `s` | `outcome` | `/attest` from the first byte read to the response, rejections included. Buckets: 5ms to 10s |
| `openstack_spire.token.size` | histogram `By` | — | Serialized token size, to watch the margin to `iid.MaxTokenBytes` |
| `openstack_spire.tags.dropped` | counter `{tag}` | `reason` (`not_string`, `not_allowed`, `too_large`, `not_encodable`, `invalid_key`, `invalid_value`: the `claims.Reason` values) | Instance tags left out of tokens |

`reason` is a closed set, one value per row of the issuer spec's failure table: `source_not_allowed`, `client_certificate`, `rate_limited_source`, `rate_limited_instance`, `invalid_request`, `unauthenticated`, `caller_not_allowed`, `keystone_busy`, `keystone_unavailable`, `instance_not_allowed` (unknown instance, project mismatch, disallowed status, unknown project), `nova_unavailable`, `enrichment_invalid`, `key_store_unavailable`, `signing_failed`; and `none` for issued tokens. A rejection path without a reason fails the tests.

Instances attested per hour is `rate(openstack_spire_tokens_issued_total)` divided by the expected tokens per instance; the issuer does not count distinct instances, which would mean tracking instance IDs in memory for metrics alone.

### Dependencies

| Instrument | Type | Attributes | Meaning |
| --- | --- | --- | --- |
| `openstack_spire.keystone.validations` | counter | `result` (`valid`, `invalid`, `not_allowed`, `error`, `busy`), `source` (`cache`, `merged`, `keystone`) | Caller token validations, and how they were answered |
| `openstack_spire.keystone.validation.duration` | histogram `s` | `result` | Calls actually made to Keystone. Buckets: 5ms to 10s |
| `openstack_spire.keystone.validations.in_flight` | up-down counter | — | Against `keystone.max_concurrent_validations` |
| `openstack_spire.nova.lookups` | counter | `result` (`found`, `not_found`, `error`), `source` (`cache`, `nova`) | Instance verification lookups |
| `openstack_spire.nova.lookup.duration` | histogram `s` | `result` | Calls actually made to Nova. Buckets: 5ms to 10s |
| `openstack_spire.signing.duration` | histogram `s` | `algorithm`, `result` | Signing operations. Buckets: 100µs to 1s |

### Keys and key sets

| Instrument | Type | Attributes | Meaning |
| --- | --- | --- | --- |
| `openstack_spire.keys` | gauge `{key}` | `state` (`published`, `active`, `retired`) | Keys of this replica, by lifecycle state |
| `openstack_spire.key.active.age` | gauge `s` | — | Age of the active key: grows past `rotation_interval` only if rotation stalls |
| `openstack_spire.key.rotations` | counter | — | Completed rotations |
| `openstack_spire.jwks.fetches` | counter | `peer` (the URL's host), `result` (`ok`, `error`, `invalid`) | Peer fetches (signer) or replica fetches (aggregator) |
| `openstack_spire.jwks.fetch.age` | gauge `s` | `peer` | Time since the last successful fetch: approaching `stale_key_retention` means keys are about to be dropped |
| `openstack_spire.jwks.keys` | gauge `{key}` | `set` (`local`, `merged`) | Keys served |
| `openstack_spire.jwks.conflicts` | counter | `peer` | Kids excluded for conflicting material |

`peer` takes its values from the configuration (`peers.urls`, `replicas`), so it is bounded.

### Protection and health

| Instrument | Type | Attributes | Meaning |
| --- | --- | --- | --- |
| `openstack_spire.rate_limit.rejections` | counter | `limiter` (`source`, `source_public`, `instance`) | Requests refused by each limiter, the public endpoints included |
| `openstack_spire.rate_limit.tracked` | gauge | `limiter` | Buckets held, against their bound |
| `openstack_spire.audit.syslog.dropped` | counter `{record}` | — | Audit records the syslog sink dropped (R-1): should stay at zero |
| `openstack_spire.audit.syslog.queue` | gauge `{record}` | — | Records waiting in the sink's queue |
| `openstack_spire.readiness.check` | gauge | `check` (`key_store`, `keystone`, `nova`, `replicas`) | 1 when the check passes, 0 when failing |
| `http.server.request.duration` | histogram `s` | `http.route` (the fixed routes), `http.request.method`, `http.response.status_code` | Every endpoint, per the OpenTelemetry HTTP conventions; unknown paths share the route `other` |

Go runtime metrics (memory, goroutines, GC) come from `go.opentelemetry.io/contrib/instrumentation/runtime` when `metrics.runtime` is on (default `true`).

### Cardinality and content

Every attribute takes its values from a closed set or from the configuration, with one opt-in exception:

- `project_id` on `openstack_spire.tokens.issued` (`metrics.project_attribute`, default `false`) is the per-tenant business view. Projects are unbounded, so at most `metrics.max_projects` (default 500) distinct values are reported per process; tokens of further projects are counted under `project_id="other"`, and a warning is logged once when that starts. Project names are never used (they change, and enrichment may be off).
- Never attributes: instance IDs, user IDs, `jti`, kids, client addresses, token or claim content. Per-instance and per-caller detail stays in the audit records.

## Protection (I-8, D-10)

Metrics are not secrets, but they disclose activity: per-project issuance volumes (with `project_attribute`), the deployment's topology (peer hosts) and its failure modes. Scraping also costs CPU on the signer.

- **Disabled by default** (`metrics.enabled: false`).
- **Never on the Nova-facing listener.** The Prometheus endpoint has its own listener, default `127.0.0.1:9464`, so a local collector agent scrapes it and nothing else reaches it.
- **A non-loopback `listen_addr` requires TLS and client certificates** (`metrics.prometheus.tls_cert_path`, `tls_key_path`, `client_ca_path`): `config check` reports an error otherwise. There is no plain-HTTP exposure beyond the host.
- **OTLP push** verifies the collector's certificate (`metrics.otlp.ca_cert_path`, default system roots, with a warning, as for `peers.ca_cert_path`) and can present a client certificate (`metrics.otlp.client_cert_path`, `client_key_path`). Insecure transport is not supported. Credentials for the collector (e.g. an `Authorization` header) are read from the environment variable named by `metrics.otlp.headers_env`, never from the file.
- **The metrics listener is rate limited** by its own per-source bucket (`metrics.prometheus.rate_limit_per_source`, default `10/1s`) and answers only `GET /metrics`, with the issuer's server timeouts. Collection is bounded by the cardinality rules above, so a scrape never grows with the number of instances.
- **A failing exporter never affects issuance.** OTLP pushes run in the background with a timeout (`metrics.otlp.timeout`, default 10s); failures are logged when they start and stop, not per attempt.

New threat model entries:

| ID | Threat | Mitigation |
| --- | --- | --- |
| I-8 | Metrics disclose per-project activity and the deployment's topology to whoever can scrape or receive them | Disabled by default; loopback listener by default; TLS and client certificates required beyond loopback; verified TLS to the collector; `project_id` opt-in and capped; no instance, user or token data in metrics |
| D-10 | Scrapes or high-cardinality series exhaust the signer's CPU or memory | Separate, rate-limited listener; closed attribute sets; `max_projects` cap |

New trust boundary: **TB8**, issuer → metrics consumer (a local collector agent scraping `/metrics`, or a remote OpenTelemetry Collector receiving OTLP).

## Configuration

Signer and aggregator alike (the aggregator has no Keystone, Nova, key or project metrics):

```yaml
metrics:
  enabled: false                                   # default
  exporter: "prometheus"                           # or "otlp"
  runtime: true                                    # Go runtime metrics
  project_attribute: false                         # project_id on tokens.issued (signer only)
  max_projects: 500                                # distinct project_id values, then "other"
  prometheus:
    listen_addr: "127.0.0.1:9464"                  # non-loopback requires the TLS settings below
    tls_cert_path: ""                              # required beyond loopback
    tls_key_path: ""
    client_ca_path: ""                             # required beyond loopback: clients present a certificate
    rate_limit_per_source: "10/1s"
  otlp:
    endpoint: "https://otel-collector.internal:4318"  # https only; required with exporter: otlp
    protocol: "http/protobuf"                      # or "grpc"
    interval: "30s"                                # at least 5s
    timeout: "10s"                                 # less than interval
    ca_cert_path: ""                               # default: system roots (warning)
    client_cert_path: ""                           # optional, with client_key_path
    client_key_path: ""
    headers_env: ""                                # name of an environment variable holding "key=value,..." headers
```

**Validation** (`config check`, `service start`, `jwks aggregate`):

- Errors: an unknown exporter or protocol; `otlp.endpoint` missing or not `https`; `interval` under 5s or `timeout` not under it; a non-loopback `listen_addr` without the three TLS settings; `listen_addr` equal to the service's own `listen_addr`; a client certificate without its key (and the reverse); `max_projects` under 1; `headers_env` naming an unset variable (at startup only); the referenced certificate files, under the existing file checks.
- Warnings: `project_attribute` enabled (it discloses per-tenant activity, I-8); `otlp.ca_cert_path` unset; `project_attribute` set on an aggregator (ignored).
- Metrics settings while `enabled` is `false` are validated but have no effect.

## Testing

**Unit tests** (with the SDK's `ManualReader`, no exporter):

- Each `reason` value: a request failing that way increments `attest.requests` with that reason and the matching status code; an issued token increments `tokens.issued` once and `attest.requests` with `issued`. A table test fails if a rejection path of the failure table has no reason.
- `project_attribute`: off, no `project_id` attribute; on, one series per project up to `max_projects`, then `other`, with one warning.
- Keystone: cached, merged and fresh validations are told apart; `in_flight` returns to zero; `busy` counted when the cap is reached.
- Keys: a rotation moves the `keys` gauge between states, resets `key.active.age` and increments `key.rotations`.
- Peers and aggregator: a failing peer increments `jwks.fetches{result="error"}` and its `fetch.age` grows; a conflict increments `jwks.conflicts`.
- Disabled metrics: the no-op provider is used, and no listener is opened.
- No metric carries an attribute outside the allowed set (a test walks every collected data point).

**Integration tests**:

- Prometheus: the endpoint on its own listener serves the text format after a token is issued; the Nova-facing listener answers `404` on `/metrics`; a non-loopback listener refuses clients without a certificate.
- OTLP: an in-process OTLP/HTTP receiver gets the issued-token counter after one interval; an unreachable collector does not delay `/attest`.
- Configuration check: every error and warning above.

**Lab scenarios** (added to the test environment spec):

- **MET-1**: with `exporter: prometheus` on `issuer-a`, booting a guest raises `openstack_spire_tokens_issued_total` by the number of `token_issued` audit records; a call from a source outside `attest.allowed_sources` counts under `source_not_allowed`, and one for an instance Nova does not know under `instance_not_allowed`. An instance of a project SPIRE Server does not allow still gets a token: that refusal is the server plugin's, outside these metrics.
- **MET-2**: with `exporter: otlp` towards an OpenTelemetry Collector on the `spire` VM (with its `debug` or file exporter), the same counters arrive within two intervals.

## Implementation plan

Tests first, as for every change.

| Area | Change | Threats |
| --- | --- | --- |
| `go.mod` | `go.opentelemetry.io/otel` (API, SDK, Prometheus and OTLP metric exporters), `go.opentelemetry.io/contrib/instrumentation/runtime` | — |
| `internal/issuer/metrics` (new) | Provider setup from configuration (no-op, Prometheus, OTLP), resource attributes, every instrument behind a typed API, the project cap | I-8, D-10 |
| `internal/issuer/config` | `metrics` block for signer and aggregator, its errors and warnings, file checks | I-8 |
| `internal/issuer/server` | The metrics listener (TLS, client certificates, rate limit, `GET /metrics` only); HTTP server duration middleware; provider start and shutdown with the service | I-8, D-10 |
| `internal/issuer/attest` | Outcome, reason and duration of every request; token size; tags dropped | — |
| `internal/issuer/auth`, `novalookup`, `keystore`, `aggregator`, `ratelimit`, `health`, `auditsink` | Their instruments | — |
| `examples/`, README | `metrics` in the samples (disabled), a Metrics section with example Prometheus queries and alerts | — |
| `test/lab` | MET-1, MET-2; an OpenTelemetry Collector on `spire` | — |

## Decisions (Oct 5)

The review accepted every proposal of the draft:

1. **Both exporters**, Prometheus pull and OTLP push, one per process. Prometheus serves deployments without a collector; OTLP serves those that already run one, without opening a port on the signer.
2. **Per-project metrics are opt-in and capped** (`project_attribute`, `max_projects: 500`). The per-tenant view is the main business metric, but it discloses tenant activity (I-8) and its cardinality must stay bounded (D-10). Exact per-project accounting stays with the audit records.
3. **The default listener is loopback without TLS** (`127.0.0.1:9464`), for a collector agent on the same host. TLS and client certificates are required on any other address.
4. **Go runtime metrics are on by default** (`runtime: true`): they cost little and explain most latency anomalies (GC, memory).
5. **The aggregator takes the same `metrics` block** as the signer, with the metrics that apply to it (HTTP, key sets, fetches, rate limits, readiness, runtime).
