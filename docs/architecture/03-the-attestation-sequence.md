# The attestation sequence

This chapter follows one attestation from beginning to end. Each step's checks are detailed in the chapters that follow.

![The attestation sequence](attestation-sequence.pdf){width=100%}

1. **SPIRE Agent asks for the token.** When SPIRE Agent attests its node, the agent plugin reads `vendor_data2.json` from the metadata service at `169.254.169.254`. Neutron's metadata proxy identifies the instance by the network port the request comes from, and forwards the request to `nova-api-metadata`.
2. **Nova calls the issuer.** For each DynamicJSON vendordata target, Nova posts a JSON document describing the instance (its project and instance IDs, host name, image, metadata and user data) to the target's URL, with a Keystone token obtained with Nova's `[vendordata_dynamic_auth]` credentials. The target named `openstack_iid` is the issuer, through its load balancer.
3. **The issuer screens the request.** Before reading the body, a signer replica checks the client's address and certificate, if configured, and its per-source rate limit and the body's size.
4. **The issuer authenticates Nova.** It validates the token with Keystone, or finds it in its cache, and checks that the token's user is the configured vendordata user, with the required role.
5. **The issuer verifies the instance.** It decodes and validates the request, applies its per-instance rate limit, and looks the instance up in the Nova API, or its cache. The instance must exist, belong to the stated project, and be in an allowed status. If enabled, it also reads the optional claims from the server record and from Keystone.
6. **The issuer signs.** It builds the claims from the request and the lookups, signs them with its active key, and writes a `token issued` audit record carrying the token's ID (`jti`).
7. **Nova serves the token.** The issuer answers `{"jwt": "..."}`. Nova nests it under the target's name, so the instance finds the token at `openstack_iid.jwt` in `vendor_data2.json`. Nova caches the instance's metadata for a few seconds; the agent plugin never presents the same token twice, and waits for a fresh one if it must.
8. **SPIRE Agent attests.** The agent plugin sends the token to SPIRE Server, over SPIRE's TLS channel.
9. **SPIRE Server verifies.** The server plugin selects the public key named by the token's key ID, from the merged JWK Set it fetches periodically, and verifies the signature. It then checks the issuer and audience, the lifetime against its clock, the claims' formats, the project allowlist, and finally that the token was never used before and was issued after the plugin started.
10. **The agent gets its identity.** The plugin returns the agent's SPIFFE ID, `spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>`, with its selectors, and writes an `agent attested` audit record carrying the same `jti` as the issuer's record.

Any failure, at any step, ends without a token or without an identity: no step ever falls back to a weaker check. The *Operator's Guide* lists every failure and its cause.
