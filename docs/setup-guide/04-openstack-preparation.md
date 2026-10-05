# OpenStack preparation

The issuer depends on two Keystone users, which play different roles:

- **the vendordata user**, whose credentials Nova uses to call the issuer: the issuer accepts token requests only from it;
- **the issuer's service user**, whose credentials the issuer uses to validate Nova's tokens and to look up instances and projects.

Keep them separate: the first proves who is asking for a token, the second gives the issuer read access to the cloud.

## The vendordata user

Nova sends the issuer a Keystone token with every vendordata request, obtained with the credentials of its `[vendordata_dynamic_auth]` section. The issuer accepts only the users listed in its `keystone.allowed_users`, carrying the role in `keystone.required_role` (`service` by default).

Create a **dedicated** user for this, and configure its credentials **only on the hosts that run `nova-api-metadata`**:

```bash
openstack user create --domain Default --password-prompt nova-vendordata
openstack role add --user nova-vendordata --user-domain Default \
    --project service --project-domain Default service
openstack user show nova-vendordata --domain Default -f value -c id   # the ID, for keystone.allowed_users
```

Never use Nova's own service user (`nova`) for this. Its credentials are in `nova.conf` on every compute node, so any compromised hypervisor could then request a token for any instance in the cloud. The issuer's configuration check warns when `nova` is listed.

List the user **by ID** in the issuer's configuration. A `name@domain` entry is accepted, but a user renamed or recreated under the same name would then be accepted too, and the configuration check warns about it.

## The issuer's service user

The issuer validates Nova's tokens and verifies each instance with its own credentials. With the default OpenStack policies, it needs to:

- validate other users' tokens (`identity:validate_token`);
- read any server, to verify instances (`os_compute_api:servers:show`);
- read any project, for the `project_name` and `domain_id` claims (`identity:get_project`).

The usual way is the `admin` role on the `service` project, as for the other OpenStack service users. Alternatively, define a dedicated role and grant it these three rules with policy overrides.

```bash
openstack user create --domain Default --password-prompt spire-issuer
openstack role add --user spire-issuer --user-domain Default \
    --project service --project-domain Default admin
```

An application credential works too, and can be rotated without touching the user's password. The credentials go into the issuer's `signer.env` file, never into its configuration file (see *Installing the issuer*).

## Nova's vendordata configuration

On every host running `nova-api-metadata`, register the issuer as a DynamicJSON vendordata target named `openstack_iid`, and give Nova the vendordata user's credentials and the client certificate it presents to the issuer:

```{.ini include="examples/nova.conf"}
```

What each setting is for:

- `vendordata_providers` must include `DynamicJSON`. Keep `StaticJSON` if you already use it.
- `vendordata_dynamic_targets`: the target's name **must** be `openstack_iid`, which the agent plugin looks for in `vendor_data2.json`. The URL is the signers' load balancer, ending in `/attest`.
- `vendordata_dynamic_ssl_certfile`: the CA bundle that verifies the signers' certificates.
- The timeouts: the issuer answers within one lookup timeout (5 seconds) even when Nova or Keystone is slow, so do not set them lower.
- `vendordata_dynamic_failure_fatal = False`: when the issuer is unavailable, Nova serves the rest of the metadata without the token, instead of failing the instance's whole metadata request. The instance gets a token on a later read.
- `[vendordata_dynamic_auth]`: the vendordata user's credentials. `certfile` and `keyfile` are Nova's client certificate and key: Nova's authentication library presents them on every request of that session, `/attest` included. If your Keystone uses a private CA that Nova's Python libraries do not trust, add its bundle as `cafile`.

Restart `nova-api-metadata` after the change. Until the issuer runs, Nova logs a connection failure for each vendordata read and serves the metadata without the token: that is expected.

## Nova's metadata cache

`nova-api-metadata` caches each instance's metadata, vendordata included, for `[api] metadata_cache_expiration` (15 seconds by default). Within that window, an instance reads the same token again. SPIRE Server accepts each token only once, so the agent plugin waits, up to its `fresh_token_timeout`, for Nova to serve a new one. The default cache window needs no change. A shorter one makes those waits shorter, at the cost of more calls to the issuer.
