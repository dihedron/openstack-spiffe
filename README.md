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
                            │                           │
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

**Supported CPUs.** All three applications (the issuer, the agent plugin and the server plugin) run on any 64-bit x86 CPU, and on arm64. For amd64, every release includes three builds of each archive and package:

- the baseline build (`x86_64` archives, `_amd64` packages), for any x86-64 CPU (`GOAMD64=v1`): use it unless you know your CPUs;
- two optimized builds, suffixed `v2` and `v3`, for CPUs of the x86-64-v2 level (roughly 2009 onwards) and x86-64-v3 level (AVX2, roughly 2015 onwards).

The optimized builds behave identically and are only faster where the compiler can use the newer instructions; on an older CPU they fail at startup. The agent plugin runs inside every instance, so prefer the baseline build for it unless all your hypervisors expose an x86-64-v3 CPU model to their guests. `make` builds for the CPU level set in `GOAMD64` (default: baseline).

`make snapshot` signs the build when `GPG_FINGERPRINT` (the key's fingerprint, in gpg's keyring) and `GPG_KEY_FILE` (the same key, armored, for the packages; passphrase in `NFPM_PASSPHRASE`) are set, and leaves it unsigned otherwise. `make release` refuses to run unsigned.

### Verify a release

Releases are signed with the project's packaging key, [packaging/signing-key.asc](packaging/signing-key.asc). Get the key from this repository, not from the release you are verifying.

- **The checksums file** covers every archive, package and SBOM of the release, and its signature (`.asc`) covers it:

  ```bash
  gpg --import signing-key.asc
  gpg --verify openstack-spiffe_<version>_checksums.txt.asc openstack-spiffe_<version>_checksums.txt
  sha256sum --check --ignore-missing openstack-spiffe_<version>_checksums.txt
  ```

- **rpm packages** carry their own signature, which `rpm` and `dnf` check once the key is imported:

  ```bash
  sudo rpm --import signing-key.asc
  rpm --checksig openstack-agent-plugin_<version>_linux_amd64.rpm   # must report "digests signatures OK"
  ```

  Keep `localpkg_gpgcheck=1` in `dnf.conf` so that `dnf install ./package.rpm` refuses an unsigned or tampered package.

- **deb packages** carry a `debsig` origin signature. `apt` and `dpkg` do not check it on a standalone package (apt only verifies signed repositories), so verify it with `debsig-verify`, after installing its policy for the key (`<keyid>` is the last 16 hex digits of the fingerprint):

  ```bash
  sudo apt-get install debsig-verify
  sudo mkdir -p /usr/share/debsig/keyrings/<keyid> /etc/debsig/policies/<keyid>
  gpg --dearmor < signing-key.asc | sudo tee /usr/share/debsig/keyrings/<keyid>/debsig.gpg > /dev/null
  sudo tee /etc/debsig/policies/<keyid>/openstack-spiffe.pol > /dev/null <<'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
  <Policy xmlns="https://www.debian.org/debsig/1.0/">
    <Origin Name="openstack-spiffe" id="<keyid>" Description="openstack-spiffe packages"/>
    <Selection><Required Type="origin" File="debsig.gpg" id="<keyid>"/></Selection>
    <Verification MinOptional="0"><Required Type="origin" File="debsig.gpg" id="<keyid>"/></Verification>
  </Policy>
  EOF
  debsig-verify openstack-agent-plugin_<version>_linux_amd64.deb
  ```

For the SPIRE plugins, verify the release **before** computing `plugin_checksum`: the checksum only proves that SPIRE loads the binary that was installed. Image pipelines baking the agent plugin verify it the same way.

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

**Nova's vendordata user.** Nova authenticates to the signer with the user of its `[vendordata_dynamic_auth]` section. Create a dedicated user for it (e.g. `nova-vendordata`), configured only on the hosts running `nova-api-metadata`, with `keystone.required_role` (default `service`). Never use Nova's own service user: its credentials are on every compute node, so any compromised hypervisor could mint tokens for any instance. List the dedicated user in the signer's `keystone.allowed_users` by ID (`openstack user show nova-vendordata -f value -c id`); `name@domain` also works, but a user renamed or recreated under that name would be accepted, so `config check` warns about it.

**Restricting `/attest`.** Keystone authentication proves possession of the vendordata credentials, not that the caller is a metadata host. Confine `/attest` to the `nova-api-metadata` hosts with either or both of:
- `attest.allowed_sources`: their addresses or CIDR ranges; other sources get a `403` before the body is read or Keystone is called;
- `attest.client_ca_path`: a CA bundle; `/attest` then requires a client certificate it issued, which Nova presents with `certfile` and `keyfile` in `[vendordata_dynamic_auth]` ([nova.conf](examples/nova.conf)). The JWKS and health endpoints never require one.

`config check` warns when neither is set.

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

**Private keys stay in RAM.** The signing keys only exist in the signer's memory. At start, the signer makes itself non-dumpable (no core dump, no `ptrace` by other processes of its user) and locks its memory into RAM, so that neither the keys nor the copies made while signing ever reach swap. The packaged unit allows this (`LimitMEMLOCK=infinity`); run elsewhere with a low locked-memory limit, the signer refuses to start, unless `key_store.lock_memory: false`, in which case disable or encrypt swap on that host. Profiling, if enabled, writes files only their owner can read, and the signer warns that they contain key material.

**Probes.**
- `/liveness` returns 200 while the process is serving.
- `/readiness` returns 200 only when every dependency check passed recently. The checks run every 5 seconds and are:
  - signer: `key_store`, `keystone`, and `nova` when instance verification is enabled (peers are deliberately not checked: a replica always serves its own keys, and a peer outage must not take it out of Nova's load balancer);
  - aggregator: `replicas`.
- A freshly started signer stays not ready until its first key has been published for `publish_ahead`.
- Route traffic on readiness. A missed token during an instance's first boot can break SPIRE-dependent units on that instance, so alert on readiness failures.

**Logging.** Logs go to standard error at `info` level. Set `OPENSTACK_SPIRE_ISSUER_LOG_LEVEL` to `debug`, `info`, `warn`, `error` or `off`. Every request carries an `X-Request-Id`, which also appears in its log lines as `request_id`. Tokens, keys, credentials and user data are never logged.

**Audit trail.** Every issued token is recorded as `token issued` (`audit=token_issued`, with the caller, client address, `jti` and `kid`), and every signing key's lifecycle as `audit=key_lifecycle` records (with its RFC 7638 thumbprint). These records are always logged, whatever the log level, `off` included. With `audit.syslog.enabled` in `signer.yaml`, they are also sent to the local syslog daemon (`/dev/log`, facility `authpriv` by default), from which rsyslog or syslog-ng can forward them to a central, append-only store. `service start` refuses to start if the sink is enabled and its socket cannot be opened.

**TLS.** `tls_min_version` (`"1.3"` by default, or `"1.2"`) applies both to what each service accepts and to the connections it makes. Set `"1.2"` only for peers that cannot negotiate TLS 1.3.

### Tuning

- **`publish_ahead` must exceed `poll_interval + fetch_timeout + cache_max_age`** of the peers and of the aggregator. The defaults are 2m against 30s + 5s + 30s. If it is too short, a token could carry a kid the merged set (or the SPIRE Server's cached copy of it) does not serve yet, and SPIRE Server would reject the token until its next fetch. `config check` enforces this rule: for the peers within each signer file, for the aggregator with `--aggregator`.
- **`rotation_interval`** (default 24h) bounds how long any single key is used. Restarting a replica also replaces its key: that is the remedy if a key may have been compromised.
- **`stale_key_retention`** (default 5m, at least the token TTL; `peers.stale_key_retention` for peers) keeps a briefly unreachable replica's keys in the merged set, so its in-flight tokens keep verifying.
- **`cache_max_age`** (default 30s; `peers.cache_max_age` for peers) is how long consumers may cache the merged set. The SPIRE Server-side plugin must select keys by the JWT header kid and re-fetch the set, rate-limited, when it meets an unknown kid.
- **Rate limits** apply per replica: on `/attest`, `rate_limit_per_source` (200/1s) is applied before the request body is read, and `rate_limit_per_instance` (1/5s) right after it is decoded. The unauthenticated JWKS and health endpoints have their own per-source bucket, `rate_limit_per_source_public` (50/1s), so that a flood against them never starves Nova's calls; the aggregator limits its endpoints with its own `rate_limit_per_source` (50/1s). If the replicas or the aggregator sit behind a proxy or load balancer that hides client addresses, list it in `client_address.trusted_proxies` so that the per-source limits apply to the real client, which the proxy reports in `X-Forwarded-For`.
- **`keystone.max_concurrent_validations`** (default 32) caps the Keystone validations in flight: beyond it, a token that is neither cached nor already being validated gets `503` at once, so a flood of bogus tokens cannot be relayed to Keystone faster than that.
- **Deployment.** Run several signer replicas, each with a unique `replica_id`, behind a load balancer close to the Nova control plane. Either list every other replica under `peers.urls` in each replica's configuration (always their `/jwks/local.json`: `config check` rejects a peer's `/.well-known/jwks.json`, which would make keys circulate between replicas) and point the SPIRE Server at the replicas' `/.well-known/jwks.json`, or run one or more aggregators behind their own load balancer. A replica missing from a peer list is silently missing from that replica's merged set.

### Metrics

The signer and the aggregator can export OpenTelemetry metrics, disabled by default (`metrics` in [signer.yaml](examples/signer.yaml) and [aggregator.yaml](examples/aggregator.yaml); design in [.specs/openstack-spire-issuer-metrics.md](.specs/openstack-spire-issuer-metrics.md)):

- **`exporter: prometheus`** serves `GET /metrics` on its own listener, `127.0.0.1:9464` by default, for a collector agent on the same host. Any other address requires `tls_cert_path`, `tls_key_path` and `client_ca_path`: scrapers must present a client certificate. Metrics are never served on the Nova-facing listener.
- **`exporter: otlp`** pushes them every `interval` (30s) to an OpenTelemetry Collector over verified TLS, by OTLP/HTTP or gRPC. Credentials for the collector come from the environment variable named by `headers_env`, never from the file. The `OTEL_*` environment variables cannot redirect the metrics.

What they cover, with the `openstack_spire_` prefix in Prometheus:

- **Issuance**: `tokens_issued_total`, and `attest_requests_total` by `outcome` and `reason`. There is one reason per refusal, such as `source_not_allowed`, `caller_not_allowed`, `rate_limited_instance`, `instance_not_allowed`, `lookup_unavailable` or `key_store_unavailable`. `attest_duration_seconds` measures the end-to-end latency, which delays every instance's first boot.
- **Dependencies**: Keystone validations (served from the cache, merged, or sent to Keystone, with the number in flight against `max_concurrent_validations`), Nova and Keystone verification lookups, and signing durations.
- **Keys and key sets**: keys by state, the active key's age, rotations, peer and replica fetches with their age, conflicting kids, and the keys served.
- **Protection and health**: rate-limit refusals per limiter, syslog audit records dropped, and the readiness checks. Go runtime metrics are on by default (`runtime`).

**Per-project counts** (`project_attribute: true`) add `project_id` to `tokens_issued_total`, for at most `max_projects` (500) projects; tokens of further projects count under `other`. They disclose each tenant's activity to whoever reads the metrics, so `config check` warns about them. Instance IDs, user IDs, token IDs and client addresses never appear in metrics: the audit records keep that detail.

Examples (Prometheus):

```promql
# tokens issued per hour, per scraped replica (target_info maps each
# instance to its replica_id, as service_instance_id)
sum by (instance) (increase(openstack_spire_tokens_issued_total[1h]))
# refusals by reason over the last 15 minutes
sum by (reason) (increase(openstack_spire_attest_requests_total{outcome="rejected"}[15m]))
# 99th percentile of the /attest latency
histogram_quantile(0.99, sum by (le) (rate(openstack_spire_attest_duration_seconds_bucket[5m])))
```

Alerts worth having:

- `openstack_spire_keys{state="active"} == 0`: a replica without an active key issues nothing.
- `openstack_spire_key_active_age_seconds` above `rotation_interval` plus a margin: rotation has stalled.
- `increase(openstack_spire_audit_syslog_dropped_total[10m]) > 0`: the syslog audit trail is incomplete.
- `openstack_spire_jwks_fetch_age_seconds` approaching `stale_key_retention`: that peer's keys are about to be dropped from the merged set.
- `openstack_spire_jwks_conflicts > 0`: two sources publish different keys under the same kid.
- A sustained rise of `attest_requests_total{reason="caller_not_allowed"}` or `{reason="source_not_allowed"}`: someone is trying the vendordata credentials from elsewhere.

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

Set `plugin_checksum` to the SHA-256 of the installed binary, once you have [verified the release](#verify-a-release); `make checksum` prints it for the binaries in `dist/`. SPIRE refuses to load a plugin whose hash does not match.

**Upgrade order:** upgrade the issuer replicas before the server plugin. A newer server plugin rejects tokens whose tags or enrichment claims carry control or format characters (e.g. bidirectional overrides) and tokens whose `kid` does not have the issuer's format. A newer issuer drops such tags itself; an older one may still issue them.

### Configure

Merge [examples/agent.conf](examples/agent.conf) and [examples/server.conf](examples/server.conf) into the `plugins` blocks of SPIRE Agent and SPIRE Server. Unknown keys are errors.

- **Agent.** `vendordata_url` defaults to Nova's metadata service. Config drives are not supported: their token is frozen at boot and expires minutes later.
- **Server: `jwks_url`.** Point it at the merged JWK Set, never at a single replica's `/jwks/local.json`. That is either the JWKS aggregator's `/.well-known/jwks.json`, or the peered signer replicas' `/.well-known/jwks.json` behind their load balancer.
- **Server: `jwks_ca_cert_path`.** Pin the endpoint's CA with it: whoever can tamper with the JWK Set can add a key.
- **Server: trust domain.** It comes from SPIRE Server's own configuration.
- **Server: `allowed_project_ids`.** Optionally restricts attestation to the listed projects. Without it, every SPIRE Server trusting the same issuer accepts every instance.
- **Server: `allowed_tag_keys`.** Optionally limits `tag` selectors to the listed keys; other tags are ignored.
- **Server: `reattest`.** `true` (the default) lets an agent renew its SVID by re-attesting with a fresh token, so its identity lapses at the next renewal once its instance is deleted; a stolen token, though, can displace the agent at any time. `false` is trust on first use: a token stolen after the first attestation is useless, but an agent that lost its state, and every agent of a deleted instance, must be evicted by an operator (`spire-server agent evict`).
- **Server: `reattest_alert_window`.** An instance attesting again within this window (5m by default) is logged as `possible token theft: instance re-attested`. The attestation is still accepted.
- **Server: `audit_syslog`.** With `enabled = true`, the audit records (`agent_attested`, whose `jti` matches the issuer's `token_issued` record, and `reattest_alert`) also go to the local syslog daemon, independently of SPIRE Server's log level.
- **Server: `agent_ttl`.** Keep SPIRE Server's `agent_ttl` at 1h or less (its default): it bounds how long the identity of a deleted instance, or a stolen one, stays usable.

`Configure` logs a warning for each of `jwks_ca_cert_path`, `allowed_project_ids` and `allowed_tag_keys` left unset, and for `audit_syslog` disabled.

**Registration entries.** `tag` and `hostname` selectors carry values that any member of the instance's project sets through the OpenStack API. A registration entry using them must also carry an `openstack_iid:project_id` or `openstack_iid:instance_id` selector: an entry selecting only on `openstack_iid:tag:role:db` matches an instance of any project that sets that tag.

```sh
# the database nodes of one project
spire-server entry create -node -spiffeID spiffe://example.org/db-nodes \
  -selector openstack_iid:project_id:<project_id> -selector openstack_iid:tag:role:db
```

### Guest hardening

Every process in an instance can read the token from the metadata service and present it to SPIRE Server before the agent does, taking over the node's identity. Images running SPIRE Agent must therefore let only root (cloud-init reads metadata as root) and the agent's user reach `169.254.169.254` (and `fe80::a9fe:a9fe` where the IPv6 metadata service is used).

- **Run SPIRE Agent as its own user**, e.g. `spire`, with `User=`, `StateDirectory=` and `RuntimeDirectory=` in its systemd unit.
- **Load the nftables rule at boot**, before any untrusted workload starts. [examples/agent-metadata-nftables.conf](examples/agent-metadata-nftables.conf), installed by the agent plugin's packages under `/usr/share/doc/openstack-agent-plugin/`, is a sample: the package never activates it. Set `spire_agent_user` in it, then include it from the image's nftables configuration (`/etc/nftables.conf` on Debian and Ubuntu, `/etc/sysconfig/nftables.conf` on RHEL-like systems) and enable the `nftables` service. The user must exist when the rule is loaded.
- **Containers** must not share the instance's network namespace (no `--network host`): the rule matches the user inside the namespace where it is loaded. Container networks must not reach the metadata addresses.
- **Keep `vendordata_url` on the instance-local metadata address.** Any other address widens who can serve or observe the token.

Root, or the agent's user, in the instance can still read the token: root owns the node's identity by definition. With `reattest = false` on the server, a token read after the agent's first attestation is useless.

### Replay protection

Each token is accepted once by a given SPIRE Server.

- **Repeated attestations.** Nova's metadata cache (`[api] metadata_cache_expiration`, 15s by default) can serve the same token again. In that case the agent plugin waits, for up to `fresh_token_timeout` (30s), until Nova serves a fresh one.
- **After a SPIRE Server restart.** The server plugin rejects tokens minted before its process started. Agents attesting right after a restart may be refused once, and succeed on SPIRE Agent's next attempt.
- **Clock skew.** `clock_skew_tolerance` (30s, at most 60s) absorbs clock differences between the issuer and SPIRE Server. A token is accepted for at most 5 minutes plus twice the tolerance; keep both clocks synchronized.
- **Limitation.** The replay cache is local to each SPIRE Server instance. In an HA deployment, a token intercepted within its acceptance window could be presented once to each other SPIRE Server instance. Tokens travel only from the instance's metadata service to SPIRE Agent and then over SPIRE's TLS channel, and they are never logged.

## Lab: end-to-end tests on a real OpenStack

[test/lab/](test/lab) builds a disposable test environment on libvirt VMs and runs the whole solution in it: DevStack (Keystone, Nova, Neutron and Glance behind TLS, with nested KVM instances), two issuer replicas installed from the deb and rpm packages, and SPIRE Server with the server plugin. Instances booted by Nova run SPIRE Agent with the agent plugin and attest through the real vendordata path. The design is in [.specs/openstack-spire-test-environment.md](.specs/openstack-spire-test-environment.md).

It runs on any x86-64 Linux machine with KVM and nested virtualization, about 14 vCPUs, 37 GiB of free memory and 120 GiB of disk with the default sizes; every setting is in [test/lab/lab.env](test/lab/lab.env), overridable in a git-ignored `lab.local.env` or the environment.

```bash
test/lab/lab.sh preflight    # check the machine; installs missing software after confirmation
test/lab/lab.sh up           # build the lab (about 15 minutes) and snapshot it
test/lab/lab.sh deploy       # build the packages here and install them on the VMs (about 3 minutes)
test/lab/lab.sh test         # run the acceptance tests (about 20 minutes; -long adds key rotation)
test/lab/lab.sh reset        # return to the snapshot in under a minute, then deploy again
test/lab/lab.sh down         # remove everything but the download cache
```

`status`, `ssh <vm>` and `logs <vm> [unit]` inspect it. Nothing is compiled in the VMs: `deploy` installs the baseline amd64 packages that `make snapshot` builds on the lab host.

## Documents

Each release publishes three PDFs beside its packages, covered by the signed checksums file: the **Setup Guide** (installing and configuring the issuer and both plugins), **Architecture and Design** (how it works, the threat model and every mitigation) and the **Operator's Guide** (monitoring, procedures, and every error with its remedy). Their sources are in [docs/](docs); `make docs` builds them.

## Development

[DEVELOPMENT.md](DEVELOPMENT.md) covers setting up a development machine (hardware, software, and `make dev-check`, which checks the environment), the everyday workflow, and, for maintainers, releases and the packaging key.
