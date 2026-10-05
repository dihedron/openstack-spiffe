# End-to-end check

Boot an instance from an image prepared as in *Installing the agent plugin*, in a project listed in the server plugin's `allowed_project_ids`, and follow its token from Nova to SPIRE. Each step names where to look when it fails; the *Operator's Guide* explains every error.

1. **The issuers are ready.** `/readiness` answers `200` on every replica (and aggregator). If not, its body names the failing check: the key store (the first key is still being published, for 2 minutes after a start), Keystone or Nova.
2. **Nova got a token.** In the issuer's log, a `token issued` record names the instance's ID. If there is none, Nova's metadata log (`nova-api-metadata`) shows the vendordata call's error, and the issuer's log shows why it refused, if it was reached.
3. **The instance sees it.** Inside the instance, as root, `vendor_data2.json` contains `openstack_iid.jwt`. If `openstack_iid` is missing, Nova's call failed: back to step 2.
4. **SPIRE Agent attested.** SPIRE Agent's log shows a successful node attestation. If it shows an error from the `openstack_iid` attestor, the agent plugin could not read the token (step 3) or SPIRE Server refused it (step 5).
5. **SPIRE Server accepted it.** SPIRE Server's log shows the plugin's `agent attested` record, with the same `jti` as the issuer's `token issued` record of step 2, and:

   ```bash
   spire-server agent list
   ```

   lists `spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>`. If SPIRE Server refused the token, its log names the reason: an unknown key, an expired token, a project not allowed, a token already used, and so on.
6. **The selectors are right.** `spire-server agent show -spiffeID <the agent's SPIFFE ID>` lists its selectors: the project and instance IDs, the host name, one per tag, and the claims the issuer enables.
7. **The guest is hardened.** As an ordinary user inside the instance, the metadata service refuses connections.

Once this works, register your workloads under the node identities, following the rule on tenant-asserted selectors in *Installing the server plugin*.
