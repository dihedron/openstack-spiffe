# Verification in SPIRE Server

The server plugin decides whether an agent gets a node identity. It trusts nothing in the token until it has verified it, and applies every rule itself, never trusting the issuer to have done so.

## Checks

In order, any failure ending the attestation:

1. **Payload**: at most the token's size limit plus a small envelope.
2. **Key ID**: the issuer's format, at most 128 bytes, checked before the key is looked up or the key ID logged. The attacker controls this field until the signature is checked.
3. **Signature**: with the key named by the key ID. Only RS256 (RSA of at least 2048 bits) and ES256 (P-256) are accepted. `none`, HMAC algorithms and anything else are rejected, and so is a token whose algorithm differs from its key's (no algorithm confusion).
4. **Issuer and audience**: exactly `nova-spire-plugin` and `spire-node-attestation`.
5. **Lifetime**: `nbf <= iat < exp`, at most 5 minutes between `iat` and `exp`, and the token valid now, within `clock_skew_tolerance` (30 seconds by default, at most 60).
6. **Formats**: the subject equals the instance ID; IDs, host name, tags and optional claims follow the contract's rules (see *The token*).
7. **Project**: in `allowed_project_ids`, when set.
8. **Startup watermark**: the token was issued after the plugin's process started.
9. **Replay**: the token's ID was never accepted before.

The last two come last, so that only fully verified tokens reach the replay cache.

## Replay protection

A token is a bearer credential during its acceptance window, so each is accepted once:

- **The replay cache** records every accepted token's ID until the token can no longer be accepted (its expiry plus the clock tolerance). A token whose ID is recorded is rejected as *already used*. Only successful attestations are recorded, so a rejected attempt never uses up a token. The cache is bounded (100,000 entries, far above any realistic rate). When it is full even after purging expired entries, attestations are refused rather than forgetting an ID early: it fails closed.
- **The startup watermark** closes the gap a restart would open, since the cache lives in memory. Tokens issued before the plugin process started (plus the clock tolerance) are rejected. Every token accepted was therefore issued after the start, and was never presented to the previous process. The cost: right after a SPIRE Server restart, an agent attesting with a token issued just before is refused once, and succeeds on its next attempt with a fresh token.
- **The agent never presents a token twice.** Nova caches an instance's metadata for about 15 seconds, so an agent attesting twice within that window would read the same token. The agent plugin remembers the ID of the last token it presented, and waits for Nova to serve a fresh one.

**Limit.** The cache is local to each SPIRE Server. With several SPIRE Servers for high availability, a token intercepted within its window could be presented once to each of them. This is an accepted limitation (see *Threat model*): tokens travel only from the instance's metadata service to its agent, and then over SPIRE's TLS channel, and they are never logged.

## SPIFFE IDs and selectors

An attested agent's SPIFFE ID is `spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>`. The trust domain is SPIRE Server's own. The selectors come only from verified claims: `project_id`, `instance_id`, `hostname`, one `tag` per tag (restricted to `allowed_tag_keys` when set), and the optional claims the issuer enables. Custom claims never become selectors: they describe the issuer's deployment, not the instance.

`openstack_iid` is the fixed name of the attestor, its selectors' prefix, its SPIFFE IDs' path segment, and Nova's vendordata target. All three components take it from their shared contract, so they can never diverge.

**The rule for registration entries.** `tag` and `hostname` selectors carry values that any member of the instance's project sets. SPIRE matches an entry when a node has all of the entry's selectors. So **an entry using a `tag` or `hostname` selector must also use a `project_id` or `instance_id` selector**. Otherwise an entry selecting `openstack_iid:tag:role:db` matches an instance of any project that sets that tag. The plugin cannot enforce this, since entries live in SPIRE Server; the documentation states it wherever entries are shown.

## Re-attestation

When an agent that already attested attests again, SPIRE Server's behaviour depends on `reattest`:

- `true` (the default): the agent renews its identity by attesting with a fresh token. Renewal needs a token, which the issuer refuses for a deleted instance, so a deleted instance's agent loses its identity at its next renewal. However, a stolen token can displace the real agent at any time within its window.
- `false` (trust on first use): a second attestation of the same agent is refused until an operator evicts it. A token stolen after the first attestation is useless; but an agent that lost its state needs an operator, and a deleted instance's identity lasts until it is evicted or expires.

Either way, the plugin remembers each instance's last attestation, and logs `possible token theft: instance re-attested` when an instance attests again within `reattest_alert_window` (5 minutes). A running agent re-attests only near its identity's expiry, so this means an agent that lost its state, or a second presenter of the instance's tokens. It never refuses: refusing would let a thief who attests first lock out the real agent.

## Shared audience

The issuer and audience are fixed values, and Nova obtains one token per instance for every consumer, so a per-consumer audience is impossible. Several SPIRE deployments trusting the same issuer, such as production and staging, therefore accept each other's instances, unless `allowed_project_ids` scopes each to its own projects.
