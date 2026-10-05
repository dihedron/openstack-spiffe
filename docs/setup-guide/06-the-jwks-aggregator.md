# The JWKS aggregator

Skip this chapter if you chose the peered topology.

A JWKS aggregator fetches every signer replica's own public keys and serves them merged, as one JWK Set, to SPIRE Server. It holds no secret and keeps no state, so it can run as several identical instances behind a load balancer. It comes in the same package as the signer, as its own command (`openstack-spire-issuer jwks aggregate`) and systemd unit.

## Installing

On each aggregator host, install the `openstack-spire-issuer` package as for a signer, then install the aggregator's TLS certificate and key: this is the certificate SPIRE Server verifies.

```bash
install -m 0644 -o root -g openstack-spire-issuer aggregator.pem /etc/openstack-spire-issuer/aggregator-tls.crt
install -m 0600 -o openstack-spire-issuer -g openstack-spire-issuer aggregator.key /etc/openstack-spire-issuer/aggregator-tls.key
```

## Configuring

The aggregator's configuration is `/etc/openstack-spire-issuer/aggregator.yaml`:

```{.yaml include="examples/aggregator.yaml"}
```

- `replicas` lists every signer replica's `/jwks/local.json`, which carries only that replica's keys. A replica missing from the list has its tokens refused by SPIRE Server.
- `replica_ca_cert_path` is the CA bundle verifying the replicas' certificates. Without it, any certificate from a public CA is accepted for them, and the configuration check warns.
- `poll_interval`, `fetch_timeout` and `cache_max_age` decide how quickly a new key reaches SPIRE Server. Their sum must stay below every signer's `key_store.publish_ahead`, or a token could carry a key SPIRE Server cannot see yet. Check the signers' and the aggregator's files together to verify it:

  ```bash
  openstack-spire-issuer config check --signer signer-a.yaml --signer signer-b.yaml --aggregator aggregator.yaml
  ```

- `stale_key_retention` keeps an unreachable replica's keys for a while (5 minutes at least), so that the tokens it signed before going down keep verifying.

## Starting

```bash
sudo -u openstack-spire-issuer openstack-spire-issuer config check --aggregator /etc/openstack-spire-issuer/aggregator.yaml
systemctl enable --now openstack-spire-issuer-aggregator
```

The aggregator fetches every replica at once at startup, then every `poll_interval`. Its `/readiness` answers `200` while at least one replica has been fetched successfully within `stale_key_retention`. Put the aggregators behind a load balancer with that health check, and point SPIRE Server at the load balancer's `/.well-known/jwks.json`.

If two replicas ever publish different keys under the same key ID, the aggregator excludes that key ID and logs an error on every poll while the conflict lasts. Key IDs contain each replica's `replica_id`, so this only happens if two replicas share one: give every replica a unique `replica_id`.
