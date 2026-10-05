# Incident procedures

Each procedure contains first, then investigates. Keep the evidence first: the audit records (central store and journals) and the metrics of the period. A restarted replica keeps nothing.

## A signing key may be compromised

A key could leak from a replica's host: root access, a memory dump, a profile left behind.

1. **Contain.** Restart the replica: its key is discarded, and a new one generated. The merged key sets drop the old key at their next fetch, and SPIRE Server refuses tokens signed with it after its next refresh (30 seconds by default). If the host itself is compromised, stop the replica, take it out of Nova's load balancer, and remove it from the peers' or aggregators' lists.
2. **Scope.** The `key_lifecycle` records give the key's ID, thumbprint and active period. The `token_issued` records list every token signed with it (`kid=<key ID>`). A forged token signed with the stolen key has **no** `token_issued` record: find `agent_attested` records with that key ID whose `jti` matches no `token_issued` record.
3. **Remediate.** Evict the agents attested with forged tokens (`spire-server agent evict`), and treat their workload identities as compromised.

## Vendordata credentials may be stolen

Someone holding the vendordata user's credentials can request tokens for any existing instance, within the limits of `attest.allowed_sources` and `attest.client_ca_path`.

1. **Contain.** Change the vendordata user's password (or disable the user and create a new one), and update `[vendordata_dynamic_auth]` on the metadata hosts. If they are not set yet, set `attest.allowed_sources` and `attest.client_ca_path`.
2. **Scope.** Refusals with `reason` `source_not_allowed`, `client_certificate` or `caller_not_allowed` show where the credentials were tried. `token_issued` records carry each request's client address, peer address and client certificate: tokens issued to an unexpected address or certificate were not requested by Nova.
3. **Remediate.** Evict the agents attested with those tokens (match their `jti` in `agent_attested` records).

## A token may have been stolen inside an instance

The server plugin logs `possible token theft: instance re-attested` (`audit=reattest_alert`) when an instance attests again within `reattest_alert_window`. That happens when an agent lost its state, or when someone else presented one of the instance's tokens.

1. **Check the instance.** Did its SPIRE Agent restart with an empty data directory around that time? If so, the alert is benign.
2. **If not**, treat the instance as compromised: some process other than SPIRE Agent read its metadata. Check its guest hardening (the nftables rule, SPIRE Agent's user). Evict the agent, and investigate the workloads registered under it.
3. **Consider** `reattest = false` (trust on first use) for that SPIRE deployment: a token stolen after the first attestation is then useless.

## A peer replica may be compromised

A compromised replica can sign any token with its own key, and publish extra keys in its set.

1. **Contain.** Stop it, take it out of Nova's load balancer, and remove it from every peer's `peers.urls` and every aggregator's `replicas`, restarting them one at a time. Its keys leave the merged sets after `stale_key_retention` (5 minutes).
2. **Scope.** Its `token_issued` and `key_lifecycle` records, if they were shipped off the host, show what it did while they were trustworthy. Attestations with its key IDs (`<date>-<replica_id>-key-<n>`) and no matching `token_issued` record were forged.
3. **Remediate.** Rebuild the host, with new TLS certificates and service credentials, before it rejoins.

## Key ID conflicts

`replicas publish different keys under the same kid: kid excluded`, or `jwks_conflicts > 0`, means two sources publish the same key ID with different keys. Tokens signed with either are refused. The usual cause is two replicas with the same `replica_id`: give each a unique one. If the IDs are unique, a source is publishing keys it does not own: treat it as a compromised peer.
