# Signing keys

The signing keys are the solution's most valuable asset: whoever holds one can sign a token for any instance of the cloud.

## Custody

Each signer replica generates its own keys, **in memory**, and never writes them anywhere. When a replica stops, its keys are gone; a restarted replica simply generates new ones. This removes the hardest problems of key custody: there is no key file to protect, back up or rotate by hand, and a suspected compromise is remedied by restarting the replica.

The keys sit behind a key store interface: the replica asks it to sign a digest, and never handles the private key otherwise. A second backend, keeping the keys in HashiCorp Vault's transit engine so that they never enter the replica, is planned behind the same interface. OpenStack's Barbican is deliberately not used for signing: a call per token to a control-plane service would turn every boot storm into a load on it.

## Rotation and publication

![The signing key lifecycle](key-lifecycle.pdf){width=35%}

Each key goes through four states:

1. **Published**: a new key is generated and added to the replica's public key set, but not yet used.
2. **Active**: after `publish_ahead` (2 minutes by default), it signs every new token.
3. **Retired**: when the next key activates, after `rotation_interval` (24 hours by default), it stops signing, but stays published, so that the tokens it signed keep verifying.
4. **Dropped**: one token lifetime later, no valid token can carry it any more, and it leaves the set.

**Publication before use** is what lets the replicas share nothing: a key must reach SPIRE Server before a token signed with it does. `publish_ahead` must exceed the time a new key takes to reach SPIRE Server, through the peers' or the aggregators' polling and the caching of the merged set. The configuration check verifies it. After a start, a replica reports not ready until its first key has been published that long.

If a rotation lands while a token is being signed, signing is retried once with the new key.

**Restarts.** A restart discards the replica's keys at once. A token signed just before, and not yet presented, is refused once the merged set no longer carries its key, and its agent attests again with a fresh token. This is the price of keys that never leave memory.

## Key IDs

Every key gets an ID, `<YYYY-MM-DD>-<replica_id>-key-<n>`, where the date is the key's creation date and `n` the number of seconds since midnight, bumped if needed so that it strictly increases within a process. Key IDs never collide across replicas, which have distinct `replica_id`s, nor across restarts. If two sources ever publish the same key ID with different key material (which only a duplicated `replica_id` could cause), every merged set excludes that key ID: a conflict fails closed.

## Memory protection

Since keys exist only in memory, the replica protects its memory:

- **non-dumpable**: at startup, before generating any key, the replica marks itself non-dumpable. That disables core dumps, and blocks debugging and memory reads by other processes of the same user. The systemd unit also disables core dumps (`LimitCORE=0`);
- **locked into RAM**: the replica locks its whole memory, as pages are first touched, so that no key, and no temporary value of a signature, is ever written to swap. It refuses to start if it cannot, unless `key_store.lock_memory` is off;
- **profiles**: CPU and heap profiles, which contain key material, are written readable by their owner only, and their use is logged as a warning.

**Why the whole process is locked.** Locking only the keys' memory would not keep them out of swap. The signature code copies key material into temporary values, wherever the language runtime places them, and those move. The options considered:

| Option | Protects | Cost |
| ---------------------- | -------------------------------------- | ---------------------------------------------- |
| Locking all memory (chosen) | Every page the signer touches: keys, temporaries, stacks | An unlimited locked-memory limit; the process is never swapped (a few MB) |
| A protected area for the keys only (`memfd_secret`) | The key at rest, even from root reading memory | The signature still copies it into ordinary memory |
| OpenSSL's secure heap, through C bindings | Keys and most temporaries | No more static binaries, a library dependency, signing outside Go's memory safety |
| The kernel keyring | The key never in user space once loaded | RSA only; the key is generated in user space first |
| Out of process (Vault, an HSM, a TPM) | The key never in the replica at all | A separate backend, planned behind the key store interface |

Root on the replica's host can still read its memory: the host's integrity is an assumption of the design (see *Threat model*).

## Audit

Every key transition (generated, published, active, retired, dropped) is an audit record, with the key ID, the algorithm and the key's RFC 7638 thumbprint. Ephemeral keys leave no other trace: these records let an investigator tie a key ID, and every token it signed, to a replica, a time window and specific key material, long after the replica restarted.
