# Getting and verifying a release

Every release is published on the project's GitHub releases page. For each component and architecture, it carries a `deb` and an `rpm` package, an archive, and an SBOM; plus a checksums file, its signature, and these documents.

Verify what you download **before** you install it. For the SPIRE plugins this matters twice: SPIRE checks each plugin's binary against the `plugin_checksum` you configure, but that only proves that SPIRE loads the binary you installed. If the binary was tampered with before you computed the checksum, the check passes anyway.

## The packaging key

Releases are signed with the project's GPG packaging key, published in the repository as `packaging/signing-key.asc`. Get it from the repository, not from the release you are verifying, and check its fingerprint against the one the project publishes elsewhere (its website or its maintainers' profiles).

```bash
gpg --show-keys signing-key.asc        # shows the fingerprint
gpg --import signing-key.asc
```

## The checksums file

The checksums file lists the SHA-256 of every archive, package, SBOM and document of the release, and its detached signature (`.asc`) covers it. Verifying both verifies everything you downloaded:

```bash
gpg --verify openstack-spiffe_<version>_checksums.txt.asc openstack-spiffe_<version>_checksums.txt
sha256sum --check --ignore-missing openstack-spiffe_<version>_checksums.txt
```

`gpg` must report a good signature from the packaging key, and `sha256sum` an `OK` for every file you downloaded.

## rpm packages

rpm packages also carry their own signature, which `rpm` and `dnf` check once the key is in rpm's keyring:

```bash
rpm --import signing-key.asc
rpm --checksig openstack-spire-issuer_<version>_linux_amd64.rpm   # must report "digests signatures OK"
```

Keep `localpkg_gpgcheck=1` in `/etc/dnf/dnf.conf`, so that `dnf install ./package.rpm` refuses an unsigned or tampered package by itself.

## deb packages

deb packages carry a *debsig* origin signature. Neither `apt` nor `dpkg` checks it on a package installed from a file (apt only verifies signed repositories), so check it with `debsig-verify`. It needs a policy for the key; `<keyid>` below is the last 16 hexadecimal digits of the key's fingerprint:

```bash
apt-get install debsig-verify
mkdir -p /usr/share/debsig/keyrings/<keyid> /etc/debsig/policies/<keyid>
gpg --dearmor < signing-key.asc > /usr/share/debsig/keyrings/<keyid>/debsig.gpg
cat > /etc/debsig/policies/<keyid>/openstack-spiffe.pol <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
<Policy xmlns="https://www.debian.org/debsig/1.0/">
  <Origin Name="openstack-spiffe" id="<keyid>" Description="openstack-spiffe packages"/>
  <Selection><Required Type="origin" File="debsig.gpg" id="<keyid>"/></Selection>
  <Verification MinOptional="0"><Required Type="origin" File="debsig.gpg" id="<keyid>"/></Verification>
</Policy>
EOF
debsig-verify openstack-spire-issuer_<version>_linux_amd64.deb
```

`debsig-verify` exits with 0 and prints nothing alarming for a valid package.

## Image pipelines

Instance images carry the agent plugin. Make the image build verify the package the same way before installing it, and record the plugin binary's SHA-256 from the installed file, for SPIRE Agent's `plugin_checksum`.
