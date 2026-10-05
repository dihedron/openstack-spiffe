# Caller authentication and instance verification

A token's value comes entirely from the claims the issuer is willing to sign. The issuer must therefore be sure of two things: that the request comes from Nova's metadata service, and that what Nova says about the instance is true.

## Who may ask for a token

Nova's request carries no credential of the instance's owner: `nova-api-metadata` calls on the instance's behalf, with its own credentials, from its `[vendordata_dynamic_auth]` configuration. The issuer:

- **requires a Keystone token**, in `X-Auth-Token`, and validates it with Keystone. A missing, invalid or expired token is refused (`401`);
- **requires a specific user and role**: the token's user must be listed, preferably by ID, in `keystone.allowed_users`, and carry `keystone.required_role`. Others are refused (`403`);
- **caches** successful validations by the token's SHA-256, for at most a minute and never beyond the token's expiry, and merges concurrent validations of the same token into one call. Failures are not cached.

**A dedicated vendordata user.** Nova's own service user is unfit for this: its credentials are in `nova.conf` on every compute node, so a single compromised hypervisor could request a token for any instance of the cloud. The design requires a dedicated user, configured only on the hosts running `nova-api-metadata`.

**Where the request comes from.** Credentials can leak. Two optional controls confine them to the metadata hosts, and are checked before the body is read and before any call to Keystone:

- **a source allowlist** (`attest.allowed_sources`) of the metadata hosts' addresses;
- **a client certificate** (`attest.client_ca_path`) that Nova presents through the same `[vendordata_dynamic_auth]` session. The listener asks every client for a certificate but checks it only on `/attest`, so that the public endpoints stay open to their consumers, and a bad certificate gets a clean `403` rather than a failed handshake.

Together, they require an attacker to hold the vendordata user's credentials, the certificate's key, *and* a foothold on a metadata host.

**Keystone protection.** Every distinct bogus token costs a Keystone validation. The issuer caps validations in flight (`keystone.max_concurrent_validations`). Beyond the cap, a request whose token is neither cached nor being validated is refused at once (`503`), so a flood of bogus tokens cannot be relayed to Keystone faster than that.

## Is the instance what Nova says?

Nova's request states the instance's project and ID. The issuer confirms them independently, with its own service credentials, before signing:

- the instance must **exist** in the Nova API;
- it must **belong to the stated project**;
- its **status** must be one in which an instance can run (`ACTIVE`, `BUILD`, `REBOOT`, `MIGRATING` and similar): deleted, errored or shelved instances never get a token.

A mismatch is refused (`403`), and so is an unknown project. Server records are cached for at most a minute, and never longer than a token's lifetime, so a migration's effect on the availability zone is seen in time. The cached record is still checked against each request.

**Optional claims** come from the same lookups: the availability zone, the flavor and the booting user from the server record, and the project's name and domain from Keystone. The two lookups run concurrently, each within 5 seconds, so a request waits for the slower one, which keeps the issuer within Nova's own timeout. If a lookup fails, or an enabled claim is missing or malformed, the request is refused (`503`): a token is never issued without its claims, nor with stale ones. Nova serves the instance's metadata without the token, and asks again at its next read.

## Request validation

The request body is untrusted input, even from Nova, since it carries tenant data:

- its size is capped (256 KiB by default) before it is read;
- it must be well-formed JSON, without duplicate members, so that a second `instance-id` cannot be smuggled in;
- the instance ID must be a canonical lowercase UUID, the project ID at most 64 characters from `[A-Za-z0-9_-]`, and the host name at most 255 characters without control characters;
- the user data is never decoded, never copied into a token, and never logged. When a rejected request is logged, its metadata values are redacted too (tenants keep secrets there), and a body that cannot be parsed is logged only by its size and hash.

## Rate limits

- **Per source**, before the body is read: by client address (an IPv6 client's whole /64), with a separate, lower limit for the public endpoints.
- **Per instance**, right after decoding: one token every 5 seconds by default, before any lookup or signature. This bounds what one instance can make the issuer do.

Limits are per replica, since replicas share nothing: with N replicas, an instance can get up to N tokens per period. That does not weaken anything, since callers are authenticated and tokens are single use.

## Processing order

Every step runs only if the previous ones succeeded, so an unauthenticated or invalid request never costs a lookup or a signature: source and client certificate, per-source limit and body cap, Keystone authentication, decoding and validation, per-instance limit, instance verification and optional claims, signature, audit record.
