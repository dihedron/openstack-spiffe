# openstack-spiffe

[![codecov](https://codecov.io/gh/dihedron/openstack-spiffe/graph/badge.svg?token=d8NsmmlTOn)](https://codecov.io/gh/dihedron/openstack-spiffe)

A complete solution providing all needed components to implement SPIFFE on OpenStack.

## openstack-spire-issuer: the instance identity token issuer

`openstack-spire-issuer` hands every OpenStack instance a short-lived signed JWT (the *instance identity document*) that proves its `project_id` and `instance_id`. The SPIRE `openstack_iid` node attestor verifies this token, so it is the trust root of every SPIFFE ID issued to OpenStack workloads. The full design is in [.specs/openstack-spire-issuer.md](.specs/openstack-spire-issuer.md).

### How it works

```
  instance ──reads vendor_data2.json──▶ nova-api-metadata
                                            │ POST /attest  (X-Auth-Token: Nova's service token)
                                            ▼
                            ┌──── load balancer ────┐
                            ▼                       ▼
                   signer replica A         signer replica B     ── Keystone (token validation, projects)
                   own in-memory keys       own in-memory keys   ── Nova API (instance verification)
                            │◀── GET /jwks/local.json ─▶│   with peers: each replica polls the others
                            │                          │
      with peers: SPIRE Server ── GET /.well-known/jwks.json ──▶ any replica (own + peers' keys)
   without peers: SPIRE Server ── GET /.well-known/jwks.json ──▶ JWKS aggregator(s),
                                                                 polling every GET /jwks/local.json
```

- **Signer replicas** (`service start`) are Nova's DynamicJSON vendordata target. For each request they authenticate Nova's service token against Keystone, verify the instance against the Nova API (it exists, belongs to the stated project, and is in an allowed status), and return `{"openstack_iid": {"jwt": "…"}}`. Nova places this in the instance's `vendor_data2.json`.
- Each replica **signs with its own in-memory keys** (RSA-2048 or P-256), which are rotated on a schedule and on every restart and never written to disk. Key IDs have the form `<date>-<replica-id>-key-<n>`, so they never collide across replicas.
- Every replica serves its own public keys on `/jwks/local.json`. The SPIRE Server needs the **merged set** of all replicas' keys, which can be served in two ways:
  - **Peered signers**: each replica lists the others under `peers` in its configuration, polls their `/jwks/local.json` and serves its own keys merged with theirs on `/.well-known/jwks.json`. Three replicas are then three token minters and three JWKS aggregators, with nothing else to deploy.
  - **JWKS aggregator** (`jwks aggregate`): a separate service polls every replica's `/jwks/local.json` and serves the merged set. Use it when the SPIRE Server must not reach the Nova-facing network.

  Without peers, a replica's `/.well-known/jwks.json` serves the same keys as its `/jwks/local.json`. A replica publishes each new key `publish_ahead` before using it, so every merged set knows a kid before any token carries it.

### Build

```bash
make                       # or: go build ./cmd/openstack-spire-issuer
```

`make go-snapshot` builds release artifacts in `dist/` with goreleaser. Each application gets its own archive and its own `deb` and `rpm` packages: `openstack-spire-issuer` (which also installs the sample configurations under `/etc/openstack-spire-issuer/`), `openstack-server-plugin` and `openstack-agent-plugin`.

### Configure

Annotated samples are in [examples/](examples): [signer.yaml](examples/signer.yaml), [aggregator.yaml](examples/aggregator.yaml), [signer.env](examples/signer.env) (credentials) and [nova.conf](examples/nova.conf). Unknown keys are errors, so typos never go unnoticed. Validate the files before every rollout:

```bash
openstack-spire-issuer config check --signer signer-a.yaml --signer signer-b.yaml --aggregator aggregator.yaml
```

The command reports every problem in one run, each with its line, and applies the same rules the services apply at startup. That includes checks across files, such as unique `replica_id`s and `publish_ahead` against the aggregator's timing (and, within each signer file, against its peers' timing), and checks on the files referenced (certificates and keys exist, match and have not expired; CA bundles parse). It exits with 0 when the files are valid, 1 on errors (or on warnings with `--strict`), and 2 when a file cannot be read. Use `--format json|yaml` for CI and `--print-effective` to see the defaults applied.

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
openstack-spire-issuer service start --config /etc/openstack-spire-issuer/signer.yaml
openstack-spire-issuer jwks aggregate --config /etc/openstack-spire-issuer/aggregator.yaml   # only without peers
```

Both services perform a pre-flight check at startup. They refuse to start (exit code 1) on any configuration error, on problems with the referenced files, and, for the signer, on missing credentials or a failed Keystone authentication. Both shut down gracefully on `SIGINT`/`SIGTERM`, giving in-flight requests up to 15 seconds.

**Running under systemd.** The `deb` and `rpm` packages install two units, both **disabled**: `openstack-spire-issuer.service` (signer) and `openstack-spire-issuer-aggregator.service` (aggregator). They run as the `openstack-spire-issuer` system user, which the package creates, and read their configuration from `/etc/openstack-spire-issuer/`. The signer also reads its `OS_*` credentials from `signer.env` there. To bring a replica up:

```bash
sudoedit /etc/openstack-spire-issuer/signer.yaml /etc/openstack-spire-issuer/signer.env
sudo install -o openstack-spire-issuer -g openstack-spire-issuer -m 0600 tls.key /etc/openstack-spire-issuer/tls.key
sudo install -m 0644 tls.crt /etc/openstack-spire-issuer/tls.crt
sudo -u openstack-spire-issuer openstack-spire-issuer config check --signer /etc/openstack-spire-issuer/signer.yaml
sudo systemctl enable --now openstack-spire-issuer.service
journalctl -u openstack-spire-issuer.service -f
```

Package upgrades restart only the units that are running, and removing the package stops and disables them. The units are sandboxed (`ProtectSystem=strict`, no capabilities), so set `OPENSTACK_SPIRE_ISSUER_LOG_LEVEL` in `signer.env` (or with `systemctl edit` for the aggregator), and leave logs on standard error.

**Probes.**
- `/liveness` returns 200 while the process is serving.
- `/readiness` returns 200 only when every dependency check passed recently. The checks run every 5 seconds and are:
  - signer: `key_store`, `keystone`, and `nova` when instance verification is enabled (peers are deliberately not checked: a replica always serves its own keys, and a peer outage must not take it out of Nova's load balancer);
  - aggregator: `replicas`.
- A freshly started signer stays not ready until its first key has been published for `publish_ahead`.
- Route traffic on readiness. A missed token during an instance's first boot can break SPIRE-dependent units on that instance, so alert on readiness failures.

**Logging.** Logs go to standard error at `info` level. Set `OPENSTACK_SPIRE_ISSUER_LOG_LEVEL` to `debug`, `info`, `warn`, `error` or `off`. Every request carries an `X-Request-Id`, which also appears in its log lines as `request_id`. Tokens, keys, credentials and user data are never logged.

**TLS.** `tls_min_version` (`"1.3"` by default, or `"1.2"`) applies both to what each service accepts and to the connections it makes. Set `"1.2"` only for peers that cannot negotiate TLS 1.3.

### Tuning

- **`publish_ahead` must exceed `poll_interval + fetch_timeout + cache_max_age`** of the peers and of the aggregator. The defaults are 2m against 30s + 5s + 30s. If it is too short, a token could carry a kid the merged set (or the SPIRE Server's cached copy of it) does not serve yet, and SPIRE Server would reject the token until its next fetch. `config check` enforces this rule: for the peers within each signer file, for the aggregator with `--aggregator`.
- **`rotation_interval`** (default 24h) bounds how long any single key is used. Restarting a replica also replaces its key: that is the remedy if a key may have been compromised.
- **`stale_key_retention`** (default 5m, at least the token TTL; `peers.stale_key_retention` for peers) keeps a briefly unreachable replica's keys in the merged set, so its in-flight tokens keep verifying.
- **`cache_max_age`** (default 30s; `peers.cache_max_age` for peers) is how long consumers may cache the merged set. The SPIRE Server-side plugin must select keys by the JWT header kid and re-fetch the set, rate-limited, when it meets an unknown kid.
- **Rate limits** apply per replica: `rate_limit_per_source` (200/1s) is applied before the request body is read, and `rate_limit_per_instance` (1/5s) right after it is decoded. If the replicas sit behind a proxy or load balancer that hides client addresses, list it in `client_address.trusted_proxies` so that the per-source limit applies to the real client, which the proxy reports in `X-Forwarded-For`.
- **Deployment.** Run several signer replicas, each with a unique `replica_id`, behind a load balancer close to the Nova control plane. Either list every other replica under `peers.urls` in each replica's configuration (always their `/jwks/local.json`: `config check` rejects a peer's `/.well-known/jwks.json`, which would make keys circulate between replicas) and point the SPIRE Server at the replicas' `/.well-known/jwks.json`, or run one or more aggregators behind their own load balancer. A replica missing from a peer list is silently missing from that replica's merged set.

## openstack_iid: the SPIRE node attestor plugins

The `openstack_iid` plugin pair attests an OpenStack instance to SPIRE Server using the token issued by `openstack-spire-issuer`. The full design is in [.specs/openstack-spire-plugins.md](.specs/openstack-spire-plugins.md).

- **`openstack-agent-plugin`** runs inside SPIRE Agent on the instance. It reads the token from `http://169.254.169.254/openstack/latest/vendor_data2.json` and sends it to SPIRE Server. It does not verify the token.
- **`openstack-server-plugin`** runs inside SPIRE Server. It verifies the token against the issuer's merged JWK Set and returns the agent's identity:
  - the SPIFFE ID is `spiffe://<trust_domain>/spire/agent/openstack_iid/<project_id>/<instance_id>`;
  - the selectors are `openstack_iid:project_id:<id>`, `openstack_iid:instance_id:<id>`, `openstack_iid:hostname:<name>` and one `openstack_iid:tag:<key>:<value>` per tag;
  - when the issuer enables the matching claims, there are also `openstack_iid:availability_zone:<az>`, `openstack_iid:flavor:<name>`, `openstack_iid:user_id:<id>`, `openstack_iid:project_name:<name>` and `openstack_iid:domain_id:<id>`.

### Install

The `openstack-agent-plugin` and `openstack-server-plugin` packages install their binary in `/usr/bin` and a sample configuration in `/usr/share/doc/<package>/`.

- **Agent plugin:** bake it into every instance image that runs SPIRE Agent, or install it during provisioning, so that it is present before SPIRE Agent starts.
- **Server plugin:** install it wherever SPIRE Server runs.

Set `plugin_checksum` to the SHA-256 of the installed binary; `make checksum` prints it for the binaries in `dist/`. SPIRE refuses to load a plugin whose hash does not match.

### Configure

Merge [examples/agent.conf](examples/agent.conf) and [examples/server.conf](examples/server.conf) into the `plugins` blocks of SPIRE Agent and SPIRE Server. Unknown keys are errors.

- **Agent.** `vendordata_url` defaults to Nova's metadata service. Config drives are not supported: their token is frozen at boot and expires minutes later.
- **Server: `jwks_url`.** Point it at the merged JWK Set, never at a single replica's `/jwks/local.json`. That is either the JWKS aggregator's `/.well-known/jwks.json`, or the peered signer replicas' `/.well-known/jwks.json` behind their load balancer.
- **Server: `jwks_ca_cert_path`.** Pin the endpoint's CA with it: whoever can tamper with the JWK Set can add a key.
- **Server: trust domain.** It comes from SPIRE Server's own configuration.
- **Server: `allowed_project_ids`.** Optionally restricts attestation to the listed projects.

### Replay protection

Each token is accepted once by a given SPIRE Server.

- **Repeated attestations.** Nova's metadata cache (`[api] metadata_cache_expiration`, 15s by default) can serve the same token again. In that case the agent plugin waits, for up to `fresh_token_timeout` (30s), until Nova serves a fresh one.
- **After a SPIRE Server restart.** The server plugin rejects tokens minted before its process started. Agents attesting right after a restart may be refused once, and succeed on SPIRE Agent's next attempt.
- **Clock skew.** `clock_skew_tolerance` (30s, at most 60s) absorbs clock differences between the issuer and SPIRE Server. A token is accepted for at most 5 minutes plus twice the tolerance; keep both clocks synchronized.
- **Limitation.** The replay cache is local to each SPIRE Server instance. In an HA deployment, a token intercepted within its acceptance window could be presented once to each other SPIRE Server instance. Tokens travel only from the instance's metadata service to SPIRE Agent and then over SPIRE's TLS channel, and they are never logged.
