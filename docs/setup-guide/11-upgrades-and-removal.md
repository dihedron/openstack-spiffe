# Upgrades and removal

## Order

Upgrade **the issuer replicas before the server plugin**. A newer server plugin may refuse what an older issuer still produces. For example, the server plugin rejects tokens with control or format characters in their tags, which a newer issuer drops, and an older one may still issue. A newer issuer always produces tokens an older server plugin accepts.

Upgrade the agent plugin with your images, at any time: it only fetches and forwards tokens.

## Upgrading the issuer

Upgrade one replica at a time, so that Nova always reaches a ready one:

```bash
apt-get install ./openstack-spire-issuer_<new version>_linux_amd64.deb   # or: dnf install ./...rpm
```

The package restarts the units that were running. A restarted replica generates a new signing key and publishes it for `publish_ahead` before signing with it. Meanwhile, it reports *not ready*, and the load balancer sends Nova to the other replicas.

The old key existed only in the old process's memory, so the restart discards it, and the merged key set drops it at the next fetch. A token the replica signed just before the restart, and that no agent has presented yet, is then refused by SPIRE Server. Its agent attests again with a fresh token, from another replica, at its next attempt. Upgrading one replica at a time, at a quiet moment, keeps this to a handful of retries.

Check the configuration with the new version before upgrading the next replica, since a new version may add checks:

```bash
sudo -u openstack-spire-issuer openstack-spire-issuer config check --signer /etc/openstack-spire-issuer/signer.yaml
```

## Upgrading the plugins

The plugins' packages do not restart SPIRE. After upgrading, update `plugin_checksum` with the new binary's SHA-256 and restart SPIRE Server, or, for the agent plugin, roll out the new image.

After a SPIRE Server restart, its plugin refuses tokens issued before it started, since it no longer knows which ones it already accepted. Agents attesting right then are refused once, and succeed on their next attempt with a fresh token.

## Removal

Removing the issuer's package stops and disables its units. It keeps the configuration files, the system user and the group, so that files the user owns stay attributed. Removing a plugin's package removes its binary: remove the plugin from SPIRE's configuration first, or SPIRE will not start.
