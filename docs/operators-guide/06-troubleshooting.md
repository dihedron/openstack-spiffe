# Troubleshooting

Each section starts from a symptom and narrows down to a cause, pointing to the *Error reference* for the details.

## An instance's agent does not attest

Follow the token from Nova to SPIRE Server:

1. **What does SPIRE Agent say?** Its log names the `openstack_iid` attestor's error.
   - `vendordata has no openstack_iid target`: Nova got no token. Go to step 2.
   - `vendordata: unexpected status`, `reading vendordata`: the instance cannot reach its metadata service, or SPIRE Agent's user is not allowed through the guest hardening rule.
   - `vendordata keeps serving an already presented token`: raise `fresh_token_timeout`.
   - An error from SPIRE Server (`attestation rejected: ...`): go to step 4.
2. **Did Nova call the issuer?** Look for the instance's ID in the issuer replicas' logs.
   - A refusal (`instance verification failed`, `rejecting /attest request`, `rejecting unauthorized caller`, ...): the *Error reference* explains it.
   - Nothing: Nova did not reach the issuer. Nova's metadata log (`nova-api-metadata`) shows the vendordata call's error: a connection failure (the load balancer, no replica ready), a TLS failure (`vendordata_dynamic_ssl_certfile`), a timeout.
3. **Is `openstack_iid` configured in Nova?** `vendordata_providers` includes `DynamicJSON`, and `vendordata_dynamic_targets` names `openstack_iid` with the right URL, on every metadata host.
4. **Why did SPIRE Server refuse?** Its log has the plugin's `attestation rejected` record, with the detail (see *Verification details*). The commonest:
   - `unknown kid`: SPIRE Server's key set lacks the signing replica's key: the replica is missing from the peers' or aggregators' lists, its key was just dropped by a restart, or `jwks_url` points at a single replica.
   - `project <id> is not in allowed_project_ids`: by design, unless the project should be served.
   - `expired`, `not valid yet`: clocks.
   - `no verification keys`: SPIRE Server cannot fetch the key set.

## Tokens are refused as already used, or issued before the server started

- **`token issued before this server started`**, right after a SPIRE Server restart: expected; each agent's next attempt succeeds. If it lasts longer than a few minutes, an agent keeps presenting an old token: check that agents run the current agent plugin.
- **`token already used`**, once for an agent that lost its state: expected, since Nova's cache served it the token it presented before; its next attempt succeeds.
- **`token already used`** repeatedly, or for agents that did not restart: someone is presenting tokens a second time. Correlate the `jti` with the `agent_attested` record that first used it, and see *Incident procedures*.

## Nova omits the vendordata

Instances' `vendor_data2.json` lacks `openstack_iid` for every instance:

1. Are the replicas ready? `curl https://<replica>:8443/readiness` on each, and through the load balancer from a metadata host.
2. Does a metadata host reach the load balancer, and trust its certificate? `curl --cacert <vendordata_dynamic_ssl_certfile> https://<load balancer>:8443/liveness`.
3. Nova's metadata log shows the call's error. A `403` from the issuer with `source_not_allowed` or `client_certificate` means the restrictions on `/attest` do not match the metadata hosts.

## Readiness flaps

`readiness check failing` and `readiness check recovered` alternating for a check:

- `keystone` or `nova`: the dependency answers slowly, beyond the 2-second check timeout, or intermittently. Check its load and the network; the replica's `verification_lookup_duration_seconds` shows the latency it sees.
- `key_store`: only after a start, for `publish_ahead`. Flapping later is abnormal: check the log for `key maintenance failed`.
- `replicas` (aggregator): the replicas' fetches fail intermittently: `replica fetch failing` names them.

## The metrics show something wrong

- **`reason="unspecified"`**: a bug. Report it with the `an /attest rejection named no reason` log record.
- **A rising refusal reason**: the *Error reference* row for that reason gives the cause.
- **`keystone_validations_in_flight` near `max_concurrent_validations`**, with `keystone_busy` refusals: a flood of distinct tokens, or Keystone too slow for the load.
- **`attest_duration_seconds` high**: compare with `verification_lookup_duration_seconds` and `keystone_validation_duration_seconds`: the slow dependency is the one to look at.
