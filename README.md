# openstack-spiffe
A complete solution providing all needed components to implement SPIFFE on OpenStack.

## openstack-spire-metadata: the instance identity token issuer

`openstack-spire-metadata` hands every OpenStack instance a short-lived signed JWT (the *instance identity document*) that proves its `project_id` and `instance_id`. The SPIRE `openstack_iid` node attestor verifies this token, so it is the trust root of every SPIFFE ID issued to OpenStack workloads. The full design is in [.specs/openstack-spire-metadata.md](.specs/openstack-spire-metadata.md).

### How it works

```
  instance ──reads vendor_data2.json──▶ nova-api-metadata
                                            │ POST /attest  (X-Auth-Token: Nova's service token)
                                            ▼
                            ┌──── load balancer ────┐
                            ▼                       ▼
                   signer replica A         signer replica B     ── Keystone (token validation, projects)
                   own in-memory keys       own in-memory keys   ── Nova API (instance verification)
                            │ GET /.well-known/jwks.json │
                            └──────────┬────────────────┘
                                       ▼
                               JWKS aggregator(s)  ◀── GET /.well-known/jwks.json ── SPIRE Server
```

- **Signer replicas** (`service start`) are Nova's DynamicJSON vendordata target. For each request they authenticate Nova's service token against Keystone, verify the instance against the Nova API (it exists, belongs to the stated project, and is in an allowed status), and return `{"openstack_iid": {"jwt": "…"}}`. Nova places this in the instance's `vendor_data2.json`.
- Each replica **signs with its own in-memory keys** (RSA-2048 or P-256), which are rotated on a schedule and on every restart and never written to disk. Key IDs have the form `<date>-<replica-id>-key-<n>`, so they never collide across replicas.
- The **JWKS aggregator** (`jwks aggregate`) polls every replica's public keys and serves the merged set, which is what the SPIRE Server fetches. A replica publishes each new key `publish_ahead` before using it, so the aggregate always knows a kid before any token carries it.

### Build

```bash
make                       # or: go build ./cmd/openstack-spire-metadata
```

### Configure

Annotated samples are in [examples/](examples): [signer.yaml](examples/signer.yaml), [aggregator.yaml](examples/aggregator.yaml), [signer.env](examples/signer.env) (credentials) and [nova.conf](examples/nova.conf). Unknown keys are errors, so typos never go unnoticed. Validate the files before every rollout:

```bash
openstack-spire-metadata config check --signer signer-a.yaml --signer signer-b.yaml --aggregator aggregator.yaml
```

The command reports every problem in one run, each with its line, and applies the same rules the services apply at startup. That includes checks across files, such as unique `replica_id`s and `publish_ahead` against the aggregator's timing, and checks on the files referenced (certificates and keys exist, match and have not expired; CA bundles parse). It exits with 0 when the files are valid, 1 on errors (or on warnings with `--strict`), and 2 when a file cannot be read. Use `--format json|yaml` for CI and `--print-effective` to see the defaults applied.

### OpenStack setup

**Signer service user.** The signer calls Keystone and Nova with its own credentials, read from the standard `OS_*` openrc variables ([signer.env](examples/signer.env)), never from the configuration file. With default policies, this user needs:

| Operation | API | Needed for |
| --- | --- | --- |
| Validate other users' tokens | `GET /v3/auth/tokens` (`identity:validate_token`) | Authenticating Nova |
| Read any project | `GET /v3/projects/{id}` (`identity:get_project`) | `project_name` / `domain_id` enrichment |
| Read any server | `GET /servers/{id}` (`os_compute_api:servers:show`) | Instance verification, server enrichment |

Like the other OpenStack service users, it typically gets the `admin` role in the `service` project. For least privilege, grant a dedicated role instead and add policy overrides for these three rules. Nova must offer compute API microversion 2.47 or later (Pike).

**Nova's vendordata user.** Nova authenticates to the signer with the user of its `[vendordata_dynamic_auth]` section. List that user in the signer's `keystone.allowed_users` as `name@domain` (e.g. `nova@Default`) or by ID, and make sure it carries `keystone.required_role` (default `service`). Bare names are rejected, because user names are only unique within a domain.

**Nova configuration** ([nova.conf](examples/nova.conf)) on the `nova-api-metadata` nodes:
- register the target as `openstack_iid@https://<signer-lb>/attest`;
- set `vendordata_dynamic_ssl_certfile` to trust the signer's certificate;
- keep `vendordata_dynamic_read_timeout` at 5 seconds or more, since the signer's Nova and Keystone lookups run concurrently and each is bounded by 5 seconds.

### Run

```bash
set -a; . /run/secrets/signer.env; set +a      # or your platform's secret injection
openstack-spire-metadata service start --config /etc/openstack-spire-metadata/signer.yaml
openstack-spire-metadata jwks aggregate --config /etc/openstack-spire-metadata/aggregator.yaml
```

Both services perform a pre-flight check at startup. They refuse to start (exit code 1) on any configuration error, on problems with the referenced files, and, for the signer, on missing credentials or a failed Keystone authentication. Both shut down gracefully on `SIGINT`/`SIGTERM`, giving in-flight requests up to 15 seconds.

**Probes.**
- `/liveness` returns 200 while the process is serving.
- `/readiness` returns 200 only when every dependency check passed recently. The checks run every 5 seconds and are:
  - signer: `key_store`, `keystone`, and `nova` when instance verification is enabled;
  - aggregator: `replicas`.
- A freshly started signer stays not ready until its first key has been published for `publish_ahead`.
- Route traffic on readiness. A missed token during an instance's first boot can break SPIRE-dependent units on that instance, so alert on readiness failures.

**Logging.** Logs go to standard error at `info` level. Set `OPENSTACK_SPIRE_METADATA_LOG_LEVEL` to `debug`, `info`, `warn`, `error` or `off`. Every request carries an `X-Request-Id`, which also appears in its log lines as `request_id`. Tokens, keys, credentials and user data are never logged.

**TLS.** `tls_min_version` (`"1.3"` by default, or `"1.2"`) applies both to what each service accepts and to the connections it makes. Set `"1.2"` only for peers that cannot negotiate TLS 1.3.

### Tuning

- **`publish_ahead` must exceed the aggregator's `poll_interval + fetch_timeout`.** The defaults are 2m against 30s + 5s. If it is too short, a token could carry a kid the aggregate does not serve yet, and SPIRE Server would reject the token until its next fetch. `config check --aggregator` enforces this rule.
- **`rotation_interval`** (default 24h) bounds how long any single key is used. Restarting a replica also replaces its key: that is the remedy if a key may have been compromised.
- **`stale_key_retention`** (default 5m, at least the token TTL) keeps a briefly unreachable replica's keys in the aggregate, so its in-flight tokens keep verifying.
- **`cache_max_age`** (default 30s) is how long consumers may cache the aggregate. The SPIRE Server-side plugin must select keys by the JWT header kid and re-fetch the set, rate-limited, when it meets an unknown kid.
- **Rate limits** apply per replica: `rate_limit_per_source` (200/1s) is applied before the request body is read, and `rate_limit_per_instance` (1/5s) right after it is decoded. If the replicas sit behind a proxy or load balancer that hides client addresses, list it in `client_address.trusted_proxies` so that the per-source limit applies to the real client, which the proxy reports in `X-Forwarded-For`.
- **Deployment.** Run several signer replicas, each with a unique `replica_id`, behind a load balancer close to the Nova control plane, and one or more aggregators behind their own load balancer.
