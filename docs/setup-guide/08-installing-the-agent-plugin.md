# Installing the agent plugin

The agent plugin runs inside SPIRE Agent, on every instance, as its `openstack_iid` node attestor. It reads the instance's token from the metadata service and sends it to SPIRE Server. It holds no key and verifies nothing: SPIRE Server does.

## Getting it into the instances

The plugin must be on the instance before SPIRE Agent starts. Either:

- **bake it into the image** (recommended): install the package during the image build, after verifying it, and record the binary's SHA-256 for SPIRE Agent's configuration;
- or **install it at boot**, with cloud-init, from a repository or an artifact server your instances can reach, verifying the package's signature there too.

Use the baseline (`_amd64`) build unless every hypervisor exposes an x86-64-v3 CPU model to its guests.

```bash
apt-get install ./openstack-agent-plugin_<version>_linux_amd64.deb      # or: dnf install ./...rpm
sha256sum /usr/bin/openstack-agent-plugin
```

The package installs the binary, a sample configuration and the guest hardening sample, both under `/usr/share/doc/openstack-agent-plugin/`.

## Configuring SPIRE Agent

Add the node attestor to the `plugins` block of SPIRE Agent's configuration, with the checksum you recorded:

```{.hcl include="examples/agent.conf"}
```

The defaults suit every OpenStack cloud: the token comes from Nova's metadata service at `169.254.169.254`. Keep it there: an address elsewhere on the network widens who can serve or observe the token. Config drives are not supported. Their copy of `vendor_data2.json` is written once, at boot, so the token in it expires minutes later.

## Guest hardening

Every process in an instance can read the metadata service, and with it the instance's token. A process that presents the token to SPIRE Server before the agent does gets the instance's agent identity, and every workload identity registered under it. The images that run SPIRE Agent must therefore let only root and SPIRE Agent's user reach the metadata service. Root needs it because cloud-init reads metadata as root.

**Run SPIRE Agent as its own user**, for instance `spire`, created in the image. In its systemd unit:

```ini
[Service]
User=spire
StateDirectory=spire/agent
RuntimeDirectory=spire/agent/public
ExecStart=/opt/spire/bin/spire-agent run -config /etc/spire/agent.conf
```

**Load the nftables rule at boot**, before any untrusted workload starts. The package ships a sample, which it never activates: activating it is the image owner's decision.

```{.bash include="examples/agent-metadata-nftables.conf"}
```

Set `spire_agent_user` to SPIRE Agent's user. Copy the file into the image, include it from the image's nftables configuration, and enable the nftables service:

```bash
install -m 0644 /usr/share/doc/openstack-agent-plugin/agent-metadata-nftables.conf /etc/openstack-metadata.nft
echo 'include "/etc/openstack-metadata.nft"' >> /etc/nftables.conf             # Debian, Ubuntu
echo 'include "/etc/openstack-metadata.nft"' >> /etc/sysconfig/nftables.conf   # RHEL-like
systemctl enable nftables
```

The user must exist when the rule loads, since the name is resolved then.

**Containers** on the instance must not share its network namespace (no `--network host`): the rule matches the user inside the namespace where it is loaded. Make sure container networks do not route to the metadata addresses either.

To check the rule from inside an instance:

```bash
curl -s -m 5 http://169.254.169.254/openstack/latest/meta_data.json           # an ordinary user: refused
sudo curl -s -m 5 http://169.254.169.254/openstack/latest/meta_data.json      # root: answered
sudo -u spire curl -s -m 5 http://169.254.169.254/openstack/latest/meta_data.json   # SPIRE Agent's user: answered
```

Root, and SPIRE Agent's user, can still read the token: root controls the instance, and its identity, by definition. With `reattest = false` on SPIRE Server, a token read after the agent's first attestation is useless.
