# Routine procedures

Every change to an issuer's configuration follows the same steps: edit, check, restart one replica at a time, and wait for it to be ready before the next.

```bash
sudo -u openstack-spire-issuer openstack-spire-issuer config check --signer /etc/openstack-spire-issuer/signer.yaml
systemctl restart openstack-spire-issuer
curl --cacert ca.pem https://<replica>:8443/readiness     # 200 after about 2 minutes
```

The issuer reads its configuration, certificates and credentials only at startup: every change needs a restart. Remember that a restart replaces the replica's key (see *Operating model*).

## Adding a signer replica

1. Install and configure it as in the *Setup Guide*, with a new, unique `replica_id`.
2. With peers: add its `/jwks/local.json` to every other replica's `peers.urls`, and list every other replica in its own; restart the existing replicas one at a time. With aggregators: add it to every aggregator's `replicas`, and restart them one at a time.
3. Check the files together: `config check --signer ... --signer ... --aggregator ...`.
4. Start it, wait for `/readiness`, then add it to Nova's load balancer.

Add it to the load balancer **last**: SPIRE Server must know its keys before Nova reaches it, or its tokens would be refused until the next fetch.

## Removing a signer replica

1. Take it out of Nova's load balancer, and wait for a token's lifetime (5 minutes), so that its last tokens are presented.
2. Stop it, and remove it from the peers' `peers.urls` or the aggregators' `replicas`, restarting them one at a time. Its keys leave the merged sets after `stale_key_retention`.

## Renewing certificates

| Certificate | Where | After replacing it |
| ------------------------------ | -------------------------------------- | ---------------------------------------- |
| A replica's server certificate | `tls_cert_path`, `tls_key_path` | Restart the replica. Nova, peers, aggregators and SPIRE Server verify it with their CA bundles: renew it from the same CA, or update their bundles first |
| An aggregator's certificate | Its `tls_cert_path`, `tls_key_path` | Restart the aggregator. SPIRE Server verifies it with `jwks_ca_cert_path` |
| Nova's client certificate | `certfile`, `keyfile` in `[vendordata_dynamic_auth]` | Restart `nova-api-metadata`. The replicas verify it with `attest.client_ca_path` |
| A CA | Every bundle that pins it | Add the new CA to the bundles first, renew the certificates, then remove the old CA |

`config check` warns 30 days before a replica's or an aggregator's certificate expires: run it regularly, or monitor the certificates' expiry.

## Rotating credentials

- **The issuer's service credentials** (`signer.env`): create the new password or application credential, update `signer.env` on every replica, restart them one at a time, then revoke the old one.
- **The vendordata user's password**: update `[vendordata_dynamic_auth]` on every `nova-api-metadata` host and restart it. The issuer needs no change, since it accepts the user, not a password. Tokens Nova obtained with the old password stay valid until they expire.

## Forcing a key rotation

Restart the replica: it discards its key and generates a new one. Use this on suspicion of a key compromise (see *Incident procedures*), or to test that rotation works end to end.

## Evicting agents

With `reattest = false` in the server plugin, an agent that lost its state cannot attest again until evicted, and a deleted instance's agent identity lasts until evicted or expired:

```bash
spire-server agent list
spire-server agent evict -spiffeID spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>
```

Evict agents when their instances are deleted, or automate it from Nova's instance deletion notifications.

## Upgrading

Upgrade the issuer replicas before the server plugin, one replica at a time, as the *Setup Guide*'s *Upgrades and removal* describes.
