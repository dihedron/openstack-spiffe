# Configuration reference

This chapter describes every configuration key of the four configuration files: the signer's (`signer.yaml`), the JWKS aggregator's (`aggregator.yaml`), and the plugins' `plugin_data` in SPIRE Server's and SPIRE Agent's configurations. For each key it gives its type, default and accepted values, what it is for, how it depends on other keys, its caveats and, where a choice affects security, the threat it bears on and the safe choice. Threat IDs (such as `S-3`) refer to the threat model in *Architecture and Design*.

Some conventions:

- **Durations** are written as Go durations: `300ms`, `30s`, `5m`, `24h`.
- **Rates** are written as `<events>/<period>`, such as `1/5s`: a bucket of `<events>` tokens, refilled at `<events>` per `<period>`. This allows bursts of up to `<events>` requests.
- **Unknown keys are errors** in every file, with a suggestion when a known key is close. A typo never silently falls back to a default.
- The issuer's files are checked by `openstack-spire-issuer config check` with the same rules the services apply at startup. Errors stop the service; warnings are logged and listed by the check.

## Signer

The signer replica's configuration, `/etc/openstack-spire-issuer/signer.yaml`. The service's OpenStack credentials are not part of it: they come from the `OS_*` environment variables (see *Installing the issuer*).

### Listener and identity

`listen_addr`
:   *Address, default `0.0.0.0:8443`.* Where the replica serves HTTPS: `/attest` for Nova, the JWK Sets, and the health endpoints. Nova, the peers, the aggregators and SPIRE Server (in the peered topology) must reach it. The port is unprivileged, so the service needs no capability.

`tls_cert_path`
:   *Path, required.* The replica's server certificate (PEM), with its chain. Its names must cover every name its clients use, the load balancer's included if TLS passes through it. The check refuses a missing, unparsable or expired certificate, or one that does not match the key, and warns 30 days before it expires.

`tls_key_path`
:   *Path, required.* The certificate's private key. Keep it readable by the service user only (mode `0600`): the check warns when group or others can read it. Whoever holds it can impersonate the replica to Nova and to its peers.

`tls_min_version`
:   *`"1.2"` or `"1.3"`, default `"1.3"`.* The minimum TLS version of the replica's server, and of its own connections to Keystone, Nova and its peers. Keep `"1.3"`. `"1.2"` exists for a peer or load balancer that cannot negotiate TLS 1.3, and makes the check warn.

`replica_id`
:   *Lowercase DNS label, default: the first label of the host name.* Names the replica in every key ID it creates (`<date>-<replica_id>-key-<n>`) and in its metrics, so the audit trail tells which replica signed each token. It must be unique among the replicas: two replicas with the same ID could create the same key ID with different keys, which the merged key sets then exclude (a conflict), refusing both replicas' tokens. Set it explicitly: the check warns when it is derived from the host name, which may change or collide.

### Signing keys

`key_store.backend`
:   *`ephemeral_memory`, default `ephemeral_memory`.* Where the signing keys live. With `ephemeral_memory`, each replica generates its keys in memory, never writes them anywhere, and loses them when it stops: a restart replaces the replica's key, which is also the remedy for a suspected key compromise. `vault_transit` (keys held by HashiCorp Vault) is planned and refused for now.

`key_store.algorithm`
:   *`RS256` or `ES256`, default `RS256`.* The signature algorithm of the replica's keys: RSA 2048 or ECDSA P-256. Both are equally secure for this purpose. ES256 keys and signatures are smaller and faster to generate. Replicas may use different algorithms: the plugin accepts both.

`key_store.rotation_interval`
:   *Duration, default `24h`, at least `5m`.* How long a key stays active before the next one replaces it. Shorter intervals limit how long a single key is used, at no cost to agents: the previous key stays published as long as tokens signed with it can still be presented. A restart also replaces the key, whatever this interval says.

`key_store.publish_ahead`
:   *Duration, default `2m`, positive and shorter than `rotation_interval`.* How long each new key is published before the replica signs with it, so that every consumer knows a key before it meets a token signed with it. It must exceed the time a new key takes to reach SPIRE Server: `peers.poll_interval + peers.fetch_timeout + peers.cache_max_age` with peers, and the aggregator's `poll_interval + fetch_timeout + cache_max_age` with aggregators. The check verifies the first, and the second when given the aggregator's file. After a start, the replica reports not ready for this long, until its first key may be used.

`key_store.lock_memory`
:   *Boolean, default `true`.* Locks the replica's memory into RAM, so that no page holding a key, or a signature's temporary values, is ever written to swap (`I-4`). It needs an unlimited locked-memory limit, which the packaged unit sets (`LimitMEMLOCK=infinity`): the replica refuses to start when locking fails. Set `false` only on hosts that cannot raise the limit, and disable or encrypt swap there: the check warns. The replica also marks itself non-dumpable whatever this setting says, which keeps its memory out of core dumps and away from other processes of the same user.

`key_store.vault_proxy_endpoint`
:   *URL.* Reserved for the planned `vault_transit` backend; ignored, with a warning, by `ephemeral_memory`.

### Tokens and limits

`token_ttl_seconds`
:   *Integer, default `300`, from 1 to 300.* The tokens' lifetime. Five minutes is the maximum the plugins accept, and leaves room for Nova's metadata cache and SPIRE Agent's retries. A shorter lifetime narrows the window in which an intercepted token is usable, but an instance whose agent attests late may then need a fresh token.

`rate_limit_per_instance`
:   *Rate, default `1/5s`.* At most this many tokens per instance. Nova asks for a token on every metadata read of the instance (outside its cache), so this caps what an instance can make the issuer sign, and protects the key store and Nova's API during boot storms. The check warns about anything looser than `1/5s`.

`rate_limit_per_source`
:   *Rate, default `200/1s`.* At most this many `/attest` requests per client address (an IPv6 client's whole /64), applied before the request body is read. The clients are Nova's metadata hosts, so size it for their peak rate. Behind a load balancer that hides client addresses, see `client_address.trusted_proxies`, or every request shares one bucket.

`rate_limit_per_source_public`
:   *Rate, default `50/1s`.* The same limit for the unauthenticated endpoints: the JWK Sets, `/liveness` and `/readiness` (`D-5`). It is a separate bucket, so a flood against them never starves Nova's calls. Their consumers (peers, aggregators, SPIRE Servers, probes) poll a few times a minute.

`max_body_bytes`
:   *Integer, default `262144` (256 KiB), from 1024 to 16 MiB.* The largest request body `/attest` accepts. Nova forwards the instance's user data (up to 64 KiB, base64-encoded) and metadata in the same body, so legitimate requests can exceed 150 KiB. A larger declared body is refused at once, without being read.

### Restrictions on `/attest`

`attest.allowed_sources`
:   *List of IP addresses or CIDR ranges, default: empty (any source).* `/attest` refuses, with `403`, any request whose client address is not listed, before reading it and before any call to Keystone (`S-3`). List the `nova-api-metadata` hosts, or the load balancer's address if it does not preserve client addresses. With stolen vendordata credentials, an attacker could otherwise request tokens from anywhere. The check warns when neither this nor `attest.client_ca_path` is set, and when a range covers every address. The JWK Set and health endpoints are never restricted.

`attest.client_ca_path`
:   *Path to a PEM CA bundle, default: unset.* When set, `/attest` refuses any request without a client certificate issued by this CA, for client authentication (`S-3`). Nova presents its certificate through `certfile` and `keyfile` in `[vendordata_dynamic_auth]`. With `attest.allowed_sources`, it confines stolen credentials to the metadata hosts and also requires the certificate's key. TLS must reach the replica for it to work: a load balancer terminating TLS removes the certificate.

### Client address

`client_address.trusted_proxies`
:   *List of IP addresses or CIDR ranges, default: empty (not proxied).* The reverse proxies or load balancers in front of the replica. For a request from one of them, the client address is read from `client_address.header`; for any other request, the TCP peer's address is used, and forwarding headers are ignored. The client address keys the per-source rate limits and `attest.allowed_sources`. Never list a range that covers clients: they could then choose their own address, and the check warns about a range covering every address.

`client_address.header`
:   *HTTP header name, default `X-Forwarded-For`.* The header carrying the client address set by the trusted proxies. `X-Forwarded-For` is read from the right, skipping the trusted proxies' own addresses, so a client cannot prepend a fake one. Any other header must hold a single address. Ignored, with a warning, without `trusted_proxies`.

### Claims

`custom_claims`
:   *Map of strings, default: empty.* Static claims added to every token, such as the region. They must not use a reserved claim name, and their JSON form must not exceed 2048 bytes: the check refuses both. They do not become selectors in SPIRE: they describe the issuer's deployment, not the instance.

`tags.allowlist`
:   *List of metadata keys, default: empty (every string entry).* The instance metadata entries copied into the token's `tags` claim, which become `openstack_iid:tag:<key>:<value>` selectors. Any member of the instance's project sets metadata (`T-3`), so tags mean "a project member said so": list only the keys your registration entries rely on. Entries that are not strings, or whose key or value is malformed, are always dropped, and the tags never exceed 1024 bytes. The check warns when the list is empty. SPIRE Server's operator can also restrict tags, with the server plugin's `allowed_tag_keys`.

`enrich`
:   *List of `availability_zone`, `flavor`, `user_id`, `project_name`, `domain_id`; default: empty.* Optional claims the issuer looks up and adds to every token, which become selectors. The first three come from the Nova server record, and need `nova_lookup.enabled`; the last two come from Keystone. A token is never issued without an enabled claim: if a lookup fails, or a value is missing or malformed, the request is refused with `503`, and Nova retries at the instance's next metadata read. `project_name` is chosen by the project's administrators: prefer `project_id` in registration entries.

### Keystone

`keystone.allowed_users`
:   *List, required.* The users whose tokens may request tokens: the vendordata user. Each entry is a user ID (recommended) or `name@domain`. List the dedicated vendordata user only, by ID (`S-3`, `E-6`). Never list `nova`, Nova's service user, whose credentials are on every compute node: the check warns about it, and about every `name@domain` entry, since a user renamed or recreated under that name would be accepted.

`keystone.required_role`
:   *Role name, default `service`.* The role the caller's token must carry, besides being listed.

`keystone.validation_cache_ttl`
:   *Duration, default `60s`, at most `10m`.* How long a validated Nova token is remembered, never beyond its own expiry. Nova reuses its token across requests, so this saves a Keystone call per request. A shorter value makes a revoked token stop working sooner.

`keystone.max_concurrent_validations`
:   *Integer, default `32`, at least 1.* At most this many token validations in flight to Keystone, across all callers (`D-2`). Beyond it, a request with a token that is neither cached nor already being validated is refused with `503` at once. A flood of bogus tokens can then never be relayed to Keystone faster than this.

`keystone.project_cache_ttl`
:   *Duration, default `10m`, at most `1h`.* How long project records are remembered, for the `project_name` and `domain_id` claims. A renamed project shows its new name within this time.

`keystone.ca_cert_path`
:   *Path to a PEM CA bundle, default: the system's roots.* The CA bundle verifying Keystone and Nova, when they use a private CA.

### Instance verification

`nova_lookup.enabled`
:   *Boolean, default `true`.* Checks every request against the Nova API before signing: the instance must exist, belong to the stated project, and be in an allowed status. It confirms Nova's claims through an independent source, and is required for the claims read from the server record. Keep it on: the check warns when it is off.

`nova_lookup.cache_ttl`
:   *Duration, default `60s`, at most the token lifetime.* How long a server record is remembered. The record is still checked against each request. The availability zone can change with a migration, which this bounds.

`nova_lookup.allowed_statuses`
:   *List of Nova statuses, default `ACTIVE`, `BUILD`, `REBOOT`, `HARD_REBOOT`, `REBUILD`, `RESIZE`, `VERIFY_RESIZE`, `MIGRATING`, `PASSWORD`.* The statuses for which tokens are issued. Only statuses in which an instance can run are accepted (`REVERT_RESIZE` and `RESCUE` may be added). Deleted, errored or shelved instances never get one.

### Peers

`peers.urls`
:   *List of https URLs, default: empty (no peers).* The other replicas' `/jwks/local.json`. With peers, the replica fetches their keys and serves them merged with its own at `/.well-known/jwks.json`. List every other replica: one missing from the list has its tokens refused when SPIRE Server fetches this replica's set. The replica itself may be listed, so all replicas can share one list. A peer's `/.well-known/jwks.json` is refused: it carries that peer's peers too, and keys would circulate between replicas forever.

`peers.ca_cert_path`
:   *Path to a PEM CA bundle, default: the system's roots.* Verifies the peers' certificates. Set it (`S-5`): anyone who can impersonate a peer can add keys to this replica's merged set. The check warns when it is unset.

`peers.poll_interval`
:   *Duration, default `30s`.* How often each peer is fetched.

`peers.fetch_timeout`
:   *Duration, default `5s`, shorter than `poll_interval`.* Bounds each fetch.

`peers.stale_key_retention`
:   *Duration, default `5m`, at least `5m`.* How long an unreachable peer's last keys are still served, so that the tokens it signed before going down keep verifying. Keys a reachable peer stops publishing are dropped at the next fetch.

`peers.cache_max_age`
:   *Duration in whole seconds, default `30s`.* The `Cache-Control` lifetime of the merged set, which consumers may cache for that long. With `poll_interval` and `fetch_timeout`, it bounds how late a new key reaches SPIRE Server: their sum must stay below `key_store.publish_ahead`.

### Audit

`audit.syslog.enabled`
:   *Boolean, default `false`.* Also sends the audit records (`token_issued`, `key_lifecycle`) to the local syslog daemon, from which rsyslog, syslog-ng or journald forward them to a central, append-only store (`R-1`, `R-3`). The records always reach the regular log too, whatever the log level. Enable it, and forward the records: the check warns when it is off. Delivery never delays a token: records that cannot be sent are dropped and counted.

`audit.syslog.socket`
:   *Path, default `/dev/log`.* The syslog daemon's Unix datagram socket. The service refuses to start when the sink is enabled and the socket cannot be opened.

`audit.syslog.facility`
:   *`auth`, `authpriv`, `daemon`, `local0` to `local7`; default `authpriv`.* The records' syslog facility. `authpriv` keeps them with other security records, readable by administrators only.

`audit.syslog.app_name`
:   *1 to 48 printable ASCII characters, default `openstack-spire-issuer`.* The records' syslog tag (journald's `SYSLOG_IDENTIFIER`).

### Metrics

`metrics.enabled`
:   *Boolean, default `false`.* Exports metrics (see *Metrics*). The other keys are checked even while it is off.

`metrics.exporter`
:   *`prometheus` or `otlp`, default `prometheus`.* Served for scraping on a listener of their own, or pushed to an OpenTelemetry Collector.

`metrics.runtime`
:   *Boolean, default `true`.* Adds the Go runtime's metrics: memory, goroutines, garbage collection.

`metrics.project_attribute`
:   *Boolean, default `false`.* Adds the project ID to the issued tokens counter. This discloses each tenant's activity to whoever reads the metrics (`I-8`): the check warns about it.

`metrics.max_projects`
:   *Integer, default `500`, at least 1.* At most this many distinct project IDs; tokens of further projects are counted as `other` (`D-10`).

`metrics.prometheus.listen_addr`
:   *Address, default `127.0.0.1:9464`.* The metrics listener, which never shares the service's port. Beyond loopback (`localhost` or a loopback address), TLS and client certificates are required (`I-8`): the check refuses a non-loopback address without `tls_cert_path`, `tls_key_path` and `client_ca_path`.

`metrics.prometheus.tls_cert_path`
:   *Path.* The metrics listener's certificate. Required beyond loopback.

`metrics.prometheus.tls_key_path`
:   *Path.* Its key, readable by the service user only.

`metrics.prometheus.client_ca_path`
:   *Path to a PEM CA bundle.* Scrapers must present a certificate from this CA. Required beyond loopback.

`metrics.prometheus.rate_limit_per_source`
:   *Rate, default `10/1s`.* Scrapes per client address (`D-10`).

`metrics.otlp.endpoint`
:   *https URL, required with `exporter: otlp`.* The OpenTelemetry Collector. Plain HTTP is refused. OTLP/HTTP adds the standard `/v1/metrics` when the URL has no path.

`metrics.otlp.protocol`
:   *`http/protobuf` or `grpc`, default `http/protobuf`.* The OTLP transport.

`metrics.otlp.interval`
:   *Duration, default `30s`, at least `5s`.* Time between exports.

`metrics.otlp.timeout`
:   *Duration, default `10s`, shorter than `interval`.* Bounds each export. A failing collector never delays a token: failures are logged when they start and when they stop.

`metrics.otlp.ca_cert_path`
:   *Path to a PEM CA bundle, default: the system's roots.* Verifies the collector. The check warns when it is unset.

`metrics.otlp.client_cert_path`
:   *Path.* A client certificate presented to the collector, if it requires one; with `client_key_path`.

`metrics.otlp.client_key_path`
:   *Path.* The client certificate's key.

`metrics.otlp.headers_env`
:   *Environment variable name.* The variable holding the headers sent to the collector, as `key=value,...` with percent-encoded values: typically an `Authorization` header. Credentials never belong in the configuration file. The service refuses to start if the named variable is unset.

## JWKS aggregator

The aggregator's configuration, `/etc/openstack-spire-issuer/aggregator.yaml`.

`listen_addr`
:   *Address, default `0.0.0.0:8444`.* Where the aggregator serves `/.well-known/jwks.json` and its health endpoints.

`tls_cert_path`
:   *Path, required.* The aggregator's certificate: the one SPIRE Server verifies, with `jwks_ca_cert_path`. Checked like the signer's.

`tls_key_path`
:   *Path, required.* Its key, mode `0600`.

`tls_min_version`
:   *`"1.2"` or `"1.3"`, default `"1.3"`.* As for the signer: for its server and its connections to the replicas.

`replicas`
:   *List of https URLs, required.* Every signer replica's `/jwks/local.json`. A replica missing from the list has its tokens refused. A replica's `/.well-known/jwks.json` also works, but with peers it carries the peers' keys too, which the aggregator then imports twice: the check warns.

`replica_ca_cert_path`
:   *Path to a PEM CA bundle, default: the system's roots.* Verifies the replicas' certificates (`S-5`): anyone who can impersonate a replica can add keys to the merged set. The check warns when it is unset.

`poll_interval`
:   *Duration, default `30s`.* How often every replica is fetched.

`fetch_timeout`
:   *Duration, default `5s`, shorter than `poll_interval`.* Bounds each fetch.

`stale_key_retention`
:   *Duration, default `5m`, at least `5m`.* How long an unreachable replica's last keys are still served. The aggregator is ready while at least one replica was fetched within this time.

`cache_max_age`
:   *Duration in whole seconds, default `30s`.* The `Cache-Control` lifetime of the merged set. `poll_interval + fetch_timeout + cache_max_age` must stay below every signer's `key_store.publish_ahead`: check the aggregator's file with the signers' to verify it.

`rate_limit_per_source`
:   *Rate, default `50/1s`.* Requests per client address, on every endpoint (`D-5`).

`client_address.trusted_proxies`
:   As for the signer: the load balancers in front of the aggregator, whose forwarded client addresses are trusted.

`client_address.header`
:   As for the signer, default `X-Forwarded-For`.

**Metrics.** The `metrics` block takes the same keys as the signer's, with the same meaning: `metrics.enabled`, `metrics.exporter`, `metrics.runtime`, `metrics.max_projects`, `metrics.prometheus.listen_addr` (use another port than a signer's on the same host, such as `127.0.0.1:9465`), `metrics.prometheus.tls_cert_path`, `metrics.prometheus.tls_key_path`, `metrics.prometheus.client_ca_path`, `metrics.prometheus.rate_limit_per_source`, `metrics.otlp.endpoint`, `metrics.otlp.protocol`, `metrics.otlp.interval`, `metrics.otlp.timeout`, `metrics.otlp.ca_cert_path`, `metrics.otlp.client_cert_path`, `metrics.otlp.client_key_path` and `metrics.otlp.headers_env`. `metrics.project_attribute` is accepted but ignored, with a warning: the aggregator issues no tokens.

## Server plugin

The `plugin_data` of the `openstack_iid` node attestor in SPIRE Server's configuration. The trust domain comes from SPIRE Server's own configuration. The plugin fails to configure on any error, naming the key; it logs a warning for each risky setting.

`jwks_url`
:   *https URL, required.* The merged JWK Set: the peered signers' load balancer's `/.well-known/jwks.json`, or the aggregators'. A single replica's `/jwks/local.json` is refused: it carries only that replica's keys.

`jwks_ca_cert_path`
:   *Path to a PEM CA bundle, default: the system's roots.* Verifies the JWK Set's endpoint. Set it (`S-5`): anyone who can impersonate the endpoint can add a key and sign tokens for any instance. The plugin warns when it is unset.

`tls_min_version`
:   *`"1.2"` or `"1.3"`, default `"1.3"`.* The minimum TLS version of the JWK Set fetches.

`jwks_refresh_interval`
:   *Duration, default `30s`, at least `1s`.* How often the JWK Set is fetched.

`jwks_fetch_timeout`
:   *Duration, default `5s`, shorter than `jwks_refresh_interval`.* Bounds each fetch.

`jwks_min_refetch_interval`
:   *Duration, default `5s`.* A token signed with an unknown key makes the plugin fetch the set again at once, at most this often. This lets a new key be found before the next refresh, without letting a stream of forged key IDs hammer the endpoint.

`jwks_stale_key_retention`
:   *Duration, default `5m`, at least `5m`.* How long the last fetched keys stay in use while the endpoint cannot be reached. Past it, every attestation is refused until a fetch succeeds: unavailability never loosens verification.

`allowed_project_ids`
:   *List of project IDs, default: empty (every project).* Only these projects' instances attest. Every SPIRE Server trusting the same issuer would otherwise accept every instance of the cloud (`S-8`). List the projects this SPIRE deployment serves: the plugin warns when the list is empty.

`clock_skew_tolerance`
:   *Duration, default `30s`, at most `60s`.* The tolerated clock difference with the issuers. A token is accepted for at most its lifetime plus twice this. Keep clocks synchronized rather than raising it.

`allowed_tag_keys`
:   *List of tag keys, default: empty (every tag).* Only tags with these keys become `openstack_iid:tag` selectors; the others are ignored. Tags are set by any member of the instance's project (`T-3`): list the keys your registration entries use. This lets SPIRE Server's operator decide, whatever the issuer's `tags.allowlist` lets through. The plugin warns when the list is empty.

`reattest`
:   *Boolean, default `true`.* Whether an agent may attest again: `true` lets it renew its identity with a fresh token, and lose it once its instance is deleted, but lets a stolen token displace it; `false` is trust on first use, which makes a token stolen after the first attestation useless, at the cost of manual eviction for agents that lost their state and for deleted instances (`S-4`, `E-4`). See *Installing the server plugin*.

`reattest_alert_window`
:   *Duration, default `5m`, `0` disables, at most `1h`.* An instance attesting again within this window is logged as `possible token theft: instance re-attested`, an audit record. A running agent re-attests only near its identity's expiry, so a quick second attestation means an agent that lost its state, or a second presenter of the instance's tokens. The attestation is still accepted.

`audit_syslog.enabled`
:   *Boolean, default `false`.* Also sends the plugin's audit records (`agent_attested`, `reattest_alert`) to the local syslog daemon (`R-2`), to be joined with the issuer's on the token ID. The plugin warns when it is off.

`audit_syslog.socket`
:   *Path, default `/dev/log`.* The syslog daemon's socket. The plugin fails to configure when it cannot be opened.

`audit_syslog.facility`
:   *As for the issuer, default `authpriv`.*

`audit_syslog.app_name`
:   *As for the issuer, default `openstack-server-plugin`.*

## Agent plugin

The `plugin_data` of the `openstack_iid` node attestor in SPIRE Agent's configuration. The defaults suit every OpenStack cloud.

`vendordata_url`
:   *http or https URL, default `http://169.254.169.254/openstack/latest/vendor_data2.json`.* Where the token is read. Keep the instance-local metadata address (`S-4`): any other address widens who can serve or observe the token. Config drives are not supported: their token expires minutes after boot.

`http_timeout`
:   *Duration, default `5s`.* Bounds each fetch of the vendordata.

`fresh_token_timeout`
:   *Duration, default `30s`, at least `http_timeout`.* Nova caches each instance's metadata for 15 seconds by default, so an agent attesting again may read the token it already presented, which SPIRE Server refuses. The plugin then polls every second for a fresh token, for at most this long. The default covers Nova's default cache and the issuer's per-instance rate limit. Raise it if Nova's `metadata_cache_expiration` is longer.
