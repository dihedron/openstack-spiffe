# Installing the server plugin

The server plugin runs inside SPIRE Server, as its `openstack_iid` node attestor. For each agent that attests, it verifies the agent's token against the issuer's public keys, and tells SPIRE Server the agent's SPIFFE ID and selectors.

## Installing

On every SPIRE Server host, install the package you verified, and record the binary's SHA-256, which SPIRE Server checks before loading it:

```bash
apt-get install ./openstack-server-plugin_<version>_linux_amd64.deb      # or: dnf install ./...rpm
sha256sum /usr/bin/openstack-server-plugin
```

The package installs only the binary and a sample configuration, `/usr/share/doc/openstack-server-plugin/server.conf`. It does not restart SPIRE Server: restart it yourself once it is configured, and after every upgrade, with the new checksum.

## Configuring SPIRE Server

Add the node attestor to the `plugins` block of SPIRE Server's configuration. The SPIFFE trust domain is SPIRE Server's own: the plugin takes it from there.

```{.hcl include="examples/server.conf"}
```

**Where the keys come from.** `jwks_url` is the merged JWK Set: the signers' load balancer's `/.well-known/jwks.json` in the peered topology, or the aggregators' in the other. Never a single replica's `/jwks/local.json`, which only carries that replica's keys: the plugin refuses it. `jwks_ca_cert_path` pins the CA that verifies that endpoint. Set it: whoever can impersonate the endpoint could add a key of their own, and sign tokens for any instance.

**Which instances may attest.** `allowed_project_ids` restricts attestation to the instances of the listed projects. Without it, every project's instances attest; and every SPIRE Server trusting the same issuer, a staging one for instance, accepts every instance of the cloud. List the projects this SPIRE deployment serves.

**Which tags become selectors.** Instance metadata entries become `tags` in the token, and `openstack_iid:tag:<key>:<value>` selectors. `allowed_tag_keys` limits the selectors to the listed keys, so that the SPIRE Server operator decides which ones registration entries can use, whatever the issuer lets through.

**Re-attestation.** `reattest` decides what SPIRE Server does when an agent that already attested attests again:

- `true` (the default): the agent renews its identity by attesting with a fresh token. Since the issuer refuses tokens for deleted instances, an instance's agent loses its identity at its next renewal once the instance is gone. However, someone who steals one of the instance's tokens can attest in the agent's place at any time.
- `false` (trust on first use): a second attestation of the same agent is refused until an operator evicts the agent (`spire-server agent evict`). A token stolen after the first attestation is useless. But an agent that lost its state needs an operator to recover, and the identities of deleted instances last until evicted, so evict them when instances are deleted.

`reattest_alert_window` (5 minutes by default) logs a `possible token theft` warning when an instance attests again that soon, which a running agent never does. The attestation is still accepted: refusing it would let a thief who attests first lock out the real agent.

**Audit.** `audit_syslog` sends the plugin's audit records, one per attestation and one per re-attestation alert, to the local syslog daemon. Each attestation record carries the token's ID (`jti`), which the issuer's `token issued` record also carries: together they tie every agent identity to the Nova call that produced its token.

**Agent identities' lifetime.** Keep SPIRE Server's own `agent_ttl` at one hour or less (its default). It bounds how long an agent identity, a stolen one or one of a deleted instance, remains usable.

Restart SPIRE Server and check its log: the plugin logs a warning for each risky setting left unset (`jwks_ca_cert_path`, `allowed_project_ids`, `allowed_tag_keys`, `audit_syslog`), and fails to configure on any error, naming the offending key.

## SPIFFE IDs and selectors

An attested agent's SPIFFE ID is:

```text
spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>
```

and it gets these selectors:

| Selector | Value | Set by |
| ------------------------------------------------ | ------------------------------ | ---------------------- |
| `openstack_iid:project_id:<id>` | The instance's project | OpenStack |
| `openstack_iid:instance_id:<id>` | The instance's ID | OpenStack |
| `openstack_iid:hostname:<name>` | The instance's host name | **A member of the instance's project** |
| `openstack_iid:tag:<key>:<value>` | One per metadata entry | **A member of the instance's project** |
| `openstack_iid:availability_zone:<az>` | When the issuer enables the claim | OpenStack |
| `openstack_iid:flavor:<name>` | When the issuer enables the claim | OpenStack administrators |
| `openstack_iid:user_id:<id>` | When the issuer enables the claim: the user who booted the instance | OpenStack |
| `openstack_iid:project_name:<name>` | When the issuer enables the claim | The project's administrators |
| `openstack_iid:domain_id:<id>` | When the issuer enables the claim | OpenStack |

## Registration entries

**A registration entry that uses a `tag` or `hostname` selector must also use a `project_id` or `instance_id` selector.** Any member of a project can set an instance's metadata and name. SPIRE matches an entry when a node has all of its selectors. So an entry selecting only `openstack_iid:tag:role:db` matches an instance of *any* project that sets that tag, in any tenant of the cloud. The plugin cannot enforce this rule, since entries live in SPIRE Server.

```bash
# the database nodes of one project
spire-server entry create -node -spiffeID spiffe://example.org/db-nodes \
    -selector openstack_iid:project_id:<project_id> \
    -selector openstack_iid:tag:role:db
```

Prefer `project_id` and `instance_id`, which are immutable IDs, over `project_name`, which a project's administrators can change.
