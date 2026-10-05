# Installing the issuer

The issuer, `openstack-spire-issuer`, runs as several **signer replicas**: independent processes that share nothing, each with its own signing keys, which exist only in its memory. Nova calls them through a load balancer. Each replica publishes the public half of its keys, and SPIRE Server needs all of them, merged into one JWK Set, to verify any replica's tokens.

## Choosing a topology

There are two ways to give SPIRE Server the merged keys:

- **Peered signers**: each replica lists the others as its *peers*, fetches their keys, and serves its own merged with theirs at `/.well-known/jwks.json`. SPIRE Server fetches that through the signers' load balancer. Nothing else is deployed. Choose this unless SPIRE Server must not reach the signers.
- **Signers plus aggregators**: separate *JWKS aggregator* processes, behind their own load balancer, fetch every replica's keys and serve them merged. SPIRE Server only talks to the aggregators. Choose this when the signers sit on a network SPIRE Server must not reach, typically the one Nova's metadata service lives on. See *The JWKS aggregator*.

![Peered signers](topology-peered.pdf){width=60%}

![Signers plus aggregators](topology-aggregated.pdf){width=55%}

The rest of this chapter installs signer replicas, and configures peers for the first topology.

## Installing the package

On each signer host, install the package you verified:

```bash
apt-get install ./openstack-spire-issuer_<version>_linux_amd64.deb      # Debian, Ubuntu
dnf install ./openstack-spire-issuer_<version>_linux_amd64.rpm           # RHEL-like
```

The package:

- installs `/usr/bin/openstack-spire-issuer`;
- creates the system user and group `openstack-spire-issuer`, with no login shell, which the services run as;
- installs two systemd units, `openstack-spire-issuer.service` (a signer replica) and `openstack-spire-issuer-aggregator.service` (a JWKS aggregator), **disabled and stopped**: the sample configuration is not a working one, so nothing starts until you configure it;
- installs sample configuration files in `/etc/openstack-spire-issuer/` (`signer.yaml`, `aggregator.yaml`, `signer.env`), owned by `root:openstack-spire-issuer` with mode `0640`. The package manager never overwrites them once edited.

## The TLS certificate

Each replica serves HTTPS with its own certificate. Install it and its key where the configuration expects them, with the key readable only by the service user:

```bash
install -m 0644 -o root -g openstack-spire-issuer signer-a.pem /etc/openstack-spire-issuer/tls.crt
install -m 0600 -o openstack-spire-issuer -g openstack-spire-issuer signer-a.key /etc/openstack-spire-issuer/tls.key
```

Install the CA bundles the replica needs beside them: the one verifying its peers' certificates (`peers.ca_cert_path`), the one verifying Nova's client certificate (`attest.client_ca_path`), and, if your OpenStack endpoints use a private CA, the one verifying Keystone and Nova (`keystone.ca_cert_path`).

## The service credentials

The issuer reads its OpenStack credentials from the environment, in the variables of a standard openrc file, never from its configuration file. The unit loads them from `/etc/openstack-spire-issuer/signer.env`:

```{.bash include="examples/signer.env"}
```

Put the issuer's service user's credentials there (see *OpenStack preparation*), or an application credential. `OS_AUTH_URL` must be `https`. `OS_INTERFACE` selects which catalog endpoints the issuer uses for Nova. Keep the file's mode at `0640` and its group `openstack-spire-issuer`. If your platform injects secrets another way (a secrets manager, systemd credentials), point the unit at it with a drop-in instead.

The same file can set `OPENSTACK_SPIRE_ISSUER_LOG_LEVEL` (`debug`, `info`, `warn`, `error` or `off`; `info` by default). Audit records are written whatever the level, even with `off`.

## The signer configuration

The signer's configuration is `/etc/openstack-spire-issuer/signer.yaml`. The sample shows every setting with its default, and the *Configuration reference* explains each one. A working configuration needs at least the following.

**Identity and TLS.** `tls_cert_path` and `tls_key_path` point to the certificate and key above. Set `replica_id` explicitly: a short, lowercase name unique among the replicas, such as `signer-a`. It is part of every key ID the replica creates, so it tells which replica signed a token. Without it, the replica derives one from the host name, and the configuration check warns.

**Who may ask for tokens.** `keystone.allowed_users` lists the vendordata user's ID. Restrict `/attest` to where Nova calls from, with either or both of:

- `attest.allowed_sources`: the addresses or ranges of the `nova-api-metadata` hosts, or of the load balancer, if it does not preserve client addresses (see *Behind a load balancer* below);
- `attest.client_ca_path`: the CA bundle of Nova's client certificate. `/attest` then refuses any call without a certificate from that CA.

Either one confines stolen vendordata credentials to the metadata hosts; both together also require the certificate's key. The JWK Set and health endpoints are never restricted: SPIRE Server, peers and probes need them.

**Peers.** In the peered topology, list every other replica's `/jwks/local.json` under `peers.urls`, and the CA bundle that verifies them under `peers.ca_cert_path`. Listing the replica itself is harmless, so every replica can share the same list. Always use `/jwks/local.json`, never `/.well-known/jwks.json`: the latter already carries the peers' keys, and the configuration check rejects it.

**Instance verification and claims.** `nova_lookup.enabled` (on by default) makes the issuer check each instance against the Nova API before signing. Keep it on. `enrich` adds optional claims, such as `availability_zone` and `project_name`, which become selectors in SPIRE. `tags.allowlist` limits which instance metadata keys become `tags` claims.

**Audit.** Turn on `audit.syslog.enabled` to send the audit records, one per issued token and one per key event, to the local syslog daemon, from which they can be forwarded to a central store. Under systemd, journald provides the socket.

**Memory protection.** The signing keys exist only in the replica's memory. By default (`key_store.lock_memory: true`), the replica locks its memory into RAM so that no key ever reaches swap. This needs an unlimited locked-memory limit, which the unit sets (`LimitMEMLOCK=infinity`). If a host cannot allow it, set `lock_memory: false`, and disable or encrypt swap on that host.

The sample, for reference:

```{.yaml include="examples/signer.yaml"}
```

## Checking the configuration

Check the configuration before starting the service, as the service user, so that the file permissions are checked as the service will see them:

```bash
sudo -u openstack-spire-issuer openstack-spire-issuer config check \
    --signer /etc/openstack-spire-issuer/signer.yaml
```

The check applies every rule the service applies at startup, and reports every problem in one run, each with its line. It also checks the files the configuration references: certificates exist, match their keys and have not expired, and CA bundles parse. It exits with:

- `0`: no errors; warnings are allowed;
- `1`: errors (or, with `--strict`, warnings);
- `2`: a file could not be read, or the command line is invalid.

Warnings point at valid but risky choices, each explained in the *Configuration reference*. With several replicas and an aggregator, check them together, so that the settings that span files are checked too (unique replica IDs, timings):

```bash
openstack-spire-issuer config check --signer signer-a.yaml --signer signer-b.yaml --aggregator aggregator.yaml
```

## Starting the replica

```bash
systemctl enable --now openstack-spire-issuer
journalctl -u openstack-spire-issuer -f
```

At startup, the replica checks its configuration again and refuses to start on any error, then locks its memory, authenticates to Keystone and generates its first signing key. It publishes that key before using it, for `key_store.publish_ahead` (2 minutes by default), so that every peer and SPIRE Server knows the key before the first token signed with it. During that time it reports *not ready*:

```bash
curl --cacert ca.pem https://signer-a.example.org:8443/readiness
```

`/readiness` answers `200` once the key store, Keystone and Nova checks all pass, and `503` with the failing checks otherwise. `/liveness` answers `200` as long as the process serves.

Start every replica the same way.

## Behind a load balancer

Put the replicas behind a load balancer for Nova, with these settings:

- **Health check**: `GET /readiness` over HTTPS, expecting `200`. A replica that cannot reach Keystone or Nova, or has no published key yet, is then taken out of rotation.
- **TLS**: pass TLS through to the replicas (layer 4), or terminate it and re-encrypt. If the load balancer terminates TLS, Nova's client certificate does not reach the replicas: use `attest.allowed_sources` instead of `attest.client_ca_path`, or have the load balancer verify the certificate itself.
- **Client addresses**: the replicas limit requests per client address. If the load balancer hides the clients' addresses, list it in `client_address.trusted_proxies`, and have it add the clients' address in `X-Forwarded-For`. Otherwise every request would come from the load balancer's address, and share one rate-limiting bucket.

## The first token

From a `nova-api-metadata` host, ask for a token as Nova would, for a running instance. With the vendordata user's token in `TOKEN`, and the instance's project and ID:

```bash
curl --cacert ca.pem --cert nova-client.pem --key nova-client.key \
    -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' \
    -d '{"project-id":"<project-id>","instance-id":"<instance-id>","hostname":"test","metadata":{}}' \
    https://signers.example.org:8443/attest
```

The answer is `{"jwt":"..."}`, and the replica logs a `token issued` audit record. Any other answer is explained in the *Operator's Guide*'s error reference. Then boot an instance, and look for its token in `vendor_data2.json`:

```bash
curl -s http://169.254.169.254/openstack/latest/vendor_data2.json   # inside the instance
```

The answer must contain an `openstack_iid` object with a `jwt` member. If `openstack_iid` is missing, Nova could not get a token: Nova's metadata log and the issuer's log say why.
