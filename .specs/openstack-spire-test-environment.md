# OpenStack SPIRE node attestation — lab test environment

Oct 4, 2026 · @Andrea Funtò · **Draft for review**

## Overview

This spec defines the lab: a scripted, disposable test environment that runs the whole solution against a real OpenStack (DevStack) on libvirt VMs. It covers the issuer replicas behind Nova's DynamicJSON vendordata, the `openstack_iid` plugins in a real SPIRE Server, and SPIRE Agents running inside Nova instances. A set of acceptance tests runs against it on demand.

The unit and integration tests run everything in one process, against fakes of Keystone, Nova and SPIRE. They cannot check what only a real deployment shows:

- Nova's behaviour: how `nova-api-metadata` calls a DynamicJSON target, with which credentials and client certificate, from which address, and how its metadata cache serves tokens to instances.
- The packages and the hardened systemd units: what the sandbox allows (`/dev/log`, `PrivateDevices=yes`), core dump limits, the non-dumpable process.
- The guest side: SPIRE Agent fetching the token from `169.254.169.254`, and the nftables rule that keeps other users away from it.
- The full chain: an instance boots, its agent attests, and SPIRE Server issues the expected agent SVID.

The specs refer to these checks as "confirmed on the DevStack test bed". This spec defines that test bed. Its script replaces the `test/install_devstack_lxd.sh` the issuer spec mentions, which was never written.

**Portability**: the lab runs on any Linux x86-64 machine with KVM and enough resources, not only on the machine it was written on. Nothing in it depends on a particular host: every path, address, size and version is a setting with a default, and a preflight check verifies the host, installs the missing software and refuses to start with a clear explanation when something cannot be fixed automatically.

**Non-goals**:
- Running in CI. A full bring-up takes 15 to 30 minutes (12 on the reference host, a 16-core desktop) and needs nested virtualization.
- Load, performance or soak testing.
- High-availability SPIRE Server, the Vault transit key store, Barbican.
- A production-like OpenStack. DevStack is a development deployment; the lab tests this solution, not OpenStack.
- Non-x86-64 hosts, and hosts without hardware virtualization.

## Architecture

All VMs run on the lab host's libvirt (`qemu:///system`) and share a dedicated NAT network, `spiffe-lab`. The lab host takes part as the test runner, the artifact server and the "outsider" of the network checks.

| VM | OS (default) | Role | Default size (vCPU / RAM / disk) |
| --- | --- | --- | --- |
| `devstack` | Ubuntu 24.04 LTS | DevStack all-in-one: Keystone, Nova (with `nova-api-metadata` and nested KVM compute), Neutron, Glance, every API behind DevStack's TLS proxy | 8 / 24 GiB / 100 GiB |
| `issuer-a` | Ubuntu 24.04 LTS | Signer replica, installed from the deb package | 2 / 3 GiB / 20 GiB |
| `issuer-b` | AlmaLinux 10 | Signer replica, installed from the rpm package | 2 / 3 GiB / 20 GiB |
| `spire` | Ubuntu 24.04 LTS | SPIRE Server with `openstack-server-plugin` (deb package) | 2 / 3 GiB / 20 GiB |

Inside DevStack, Nova boots the instances under test from two Glance images: the Ubuntu 24.04 and AlmaLinux 10 cloud images. Each runs SPIRE Agent with `openstack-agent-plugin`, installed from the deb or rpm package respectively. Each distro family is thus exercised once as an issuer host and once as a guest. The RHEL-like distro is AlmaLinux by default and Rocky Linux when `LAB_RHEL_DISTRO=rocky`, both at their latest major release (10). RHEL 10 derivatives require an x86-64-v3 CPU, so every VM runs with the host's CPU model (`host-passthrough`), and so do the Nova instances (`LIBVIRT_CPU_MODE=host-passthrough` in DevStack's `local.conf`; DevStack's default is a fixed, older model). The issuer and the plugins themselves run on any x86-64 CPU: the lab installs their baseline (`GOAMD64=v1`) packages.

**Addressing** (defaults, all settings): `spiffe-lab` is `10.250.0.0/24`, with the lab host at `.1`, `devstack` at `.10`, `issuer-a` at `.21`, `issuer-b` at `.22` and `spire` at `.30`. libvirt's DNS on the lab network resolves the VMs' names (`issuer-a.lab`, ...), and its DHCP gives each VM a fixed address from a fixed MAC. The instances reach the lab network through their Neutron router and DevStack's public network, which DevStack itself masquerades behind the `devstack` VM's address; their private subnet uses libvirt's DNS (the lab host's address) so that they resolve the lab names too.

**Flows**:

1. An instance reads `vendor_data2.json` from `169.254.169.254`. Neutron's metadata proxy forwards the request to `nova-api-metadata` on `devstack`.
2. `nova-api-metadata` calls `https://issuer-a.lab:8443/attest` as the dedicated vendordata user (S-3), from `devstack`'s address.
3. The issuer replicas peer with each other: each serves the merged JWK Set on `/.well-known/jwks.json`.
4. SPIRE Agent in the instance sends the token to SPIRE Server on `spire.lab:8081`. The server plugin fetches the merged JWK Set from `https://issuer-a.lab:8443/.well-known/jwks.json`, pinned to the lab CA: the replicas peer, so it carries both replicas' keys.
5. Both issuers and the server plugin send their audit records to their host's journald through `/dev/log`.

There is no load balancer. Nova calls a single target URL, so `issuer-a` serves every vendordata call; `issuer-b` takes part through peering and key rotation, and the acceptance tests call its `/attest` directly as the vendordata user from `devstack`. A TLS-terminating load balancer would hide Nova's client certificate from the issuers, which NET-2 needs; `client_address.trusted_proxies` stays covered by the unit and integration tests.

**OpenStack over TLS**: the issuer refuses an `OS_AUTH_URL` that is not https, since its own credentials must not travel in clear. DevStack therefore runs with its TLS proxy (`tls-proxy`), which puts every API behind https with DevStack's own CA; the issuers pin that CA as `keystone.ca_cert_path`, and Nova's `[vendordata_dynamic_auth]` uses it as `cafile` (Nova's Python stack does not use the system's trust store). The issuers call Keystone and Nova as their own service user, `spire-issuer`, with the `admin` role on the `service` project, as the README prescribes.

**Lab PKI**: the bring-up creates a lab CA (ECDSA P-256). It issues the issuers' server certificates (`issuer-a.lab` and `issuer-b.lab`, with their names and addresses) and the client certificate Nova presents to `/attest` (chunk 4). SPIRE Server needs none: it runs its own CA, and the server plugin only needs to trust the issuers. The CA bundle is what `jwks_ca_cert_path`, `peers.ca_cert_path` and Nova's `vendordata_dynamic_ssl_certfile` pin. Keys never leave the lab's state directory.

## Settings

`test/lab/lab.env` holds every setting with its default, and documents it. A git-ignored `test/lab/lab.local.env` overrides it for one machine, and environment variables override both. The settings are:

- **Versions**:
  - `LAB_UBUNTU_RELEASE` (default `24.04`).
  - `LAB_RHEL_DISTRO` (`alma` or `rocky`, default `alma`) and `LAB_RHEL_RELEASE` (default `10`).
  - `LAB_DEVSTACK_BRANCH`: empty by default, meaning the most recent `stable/*` branch of DevStack, resolved at `up` from the DevStack repository.
  - `LAB_SPIRE_VERSION` and `LAB_SPIRE_SHA256`: empty by default, meaning the most recent SPIRE release compatible with the `spire-plugin-sdk` version in `go.mod` (same major version, and a minor version at least the SDK's), resolved at `up` from SPIRE's releases, with its checksum taken from the release's published checksums file. A pinned version must come with its SHA-256.
  - Image URLs are derived from the distro and release, and can be overridden (`LAB_UBUNTU_IMAGE_URL`, `LAB_RHEL_IMAGE_URL`) for mirrors and air-gapped hosts.
- **Network**: `LAB_SUBNET` (default `10.250.0.0/24`), `LAB_NETWORK` (default `spiffe-lab`), and the host part of each VM's address.
- **Sizes**: vCPUs, RAM and disk of each VM (`LAB_DEVSTACK_VCPUS`, ...), and the flavor of the instances. They apply when a VM is created: `up` warns when an existing VM's memory differs from the settings, and `down` followed by `up` applies them.
- **Locations**: `LAB_STATE_DIR` (default `test/lab/.state`, git-ignored: PKI, SSH key, `env.json`), `LAB_CACHE_DIR` (default `${XDG_CACHE_HOME:-~/.cache}/openstack-spiffe-lab`: downloaded images and tarballs, kept across `down`), and `LAB_POOL` (default: a libvirt storage pool named `spiffe-lab`, created under `LAB_POOL_DIR`, default `/var/lib/libvirt/images/spiffe-lab`).
- **Behaviour**: `LAB_ASSUME_YES` (default unset) answers yes to the preflight's installation prompts, for unattended use.

Every resolved value, the DevStack commit, SPIRE version and checksum, and image checksums included, is recorded in `env.json` at `up`. `lab.sh status` shows them, and a test report can therefore always be traced to exact versions. `reset` reuses them; a new `up` resolves them again.

## Preflight

`lab.sh preflight` checks that the machine can run the lab, and `up` runs it first. Each check prints `ok`, `warn` (the lab can run, with the stated consequence) or `fail` (with what to do), and the command exits non-zero on any `fail`. All checks run, so that one run reports every problem.

**Operating system**:
- Linux on x86-64, identified through `/etc/os-release`.
- Supported host families, which determine the package manager: Debian and Ubuntu (`apt`), Fedora and RHEL-like distros (`dnf`). Other distros get a `fail` listing the software to install by hand, and `lab.sh preflight --no-install` reports without installing anything on any host.
- systemd is running (libvirt's services are managed through it).

**Virtualization**:
- The CPU has hardware virtualization (`vmx` or `svm`) and `/dev/kvm` exists. The user does not need to open it: with `qemu:///system`, libvirt does.
- Nested virtualization is enabled (`kvm_intel` or `kvm_amd` `nested` parameter), since Nova runs its instances in KVM inside `devstack`. When it is off, preflight fails and prints how to enable it persistently. It does not reload kernel modules itself: that would disrupt VMs already running on the host.
- The CPU supports x86-64-v3, required by RHEL 10 derivatives (checked through the CPU flags `avx2`, `bmi2`, `fma`, `movbe` and related). Without it, preflight fails for `LAB_RHEL_RELEASE=10` and suggests release 9. The lab's own packages need no such check: it installs the baseline amd64 packages, which run on any x86-64 CPU.

**Resources**, computed from the configured sizes, not fixed numbers:
- CPUs: the sum of the VMs' vCPUs against the host's logical CPUs. `warn` above 1.5 times overcommit, `fail` above 3.
- Memory: the sum of the VMs' RAM, plus 4 GiB for the host, against the memory available now; the lab's VMs already running hold their memory, so only the others count. `fail` below it, `warn` when the margin is under 4 GiB more.
- Disk: the VMs' disks (thin-provisioned, so their actual use at the end of `up`, about 40% of their size) and the VMs' memory, which the snapshots save, plus 20% margin, against the free space under `LAB_POOL_DIR`, less what the lab's storage pool already holds; and about 10 GiB of downloads against the free space under `LAB_CACHE_DIR`. `fail` below, `warn` within 20%.
- With the defaults, that means 14 vCPUs, 33 GiB of RAM and about 90 GiB of disk: a host with 16 logical CPUs, 48 GiB of RAM and 150 GiB free runs the lab comfortably. The small VMs get 3 GiB each, the minimum libvirt recommends for Ubuntu 24.04, although their services need much less.

**Software**: each tool is checked with its minimum version, and installed when missing or too old, after a single confirmation listing everything to install (or none with `LAB_ASSUME_YES`). Installation uses `sudo` and the host's package manager; Go and goreleaser come from their official releases, with checksums verified, when the distro's packages are too old.
- libvirt (daemon running and enabled), `virsh`, `virt-install`, `qemu-img`, QEMU with KVM support.
- `cloud-localds` or, failing it, `xorriso`/`genisoimage` (cloud-init seed images).
- `ssh`, `ssh-keygen`, `openssl`, `curl`, `jq`, `git`, `make`, `python3` (for the artifact server).
- Go, at the version `go.mod` requires, and goreleaser v2: `deploy` builds the packages on the lab host.

**Permissions**:
- The user can manage `qemu:///system` (member of the `libvirt` group, or polkit rules allowing it). If not, preflight offers to add the user to the group, and says that a new login is needed before `up`.
- The user can use `sudo` for the installation step, and only for it: nothing else in the lab runs as root on the host.

**Network**:
- `LAB_SUBNET` does not overlap any route on the host or any existing libvirt network, and `LAB_NETWORK` either does not exist or is the lab's own. On overlap, preflight fails and names the conflicting route or network.
- The endpoints the bring-up downloads from are reachable over HTTPS: the DevStack and OpenStack Git repositories, the Ubuntu and RHEL-like image hosts (or their configured mirrors), SPIRE's releases, and the Python package index DevStack uses. The ones that are not reachable are listed.

Preflight changes nothing on the host except installing software and adding the user to the `libvirt` group, both only after confirmation.

## Lifecycle

Everything lives in `test/lab/`. `lab.sh` is the entry point. Each command is idempotent and prints what it does:

- `preflight [--no-install]`: see above.
- `up`: runs `preflight`, generates the lab PKI, creates the storage pool, network and VMs from cloud images with cloud-init, runs DevStack's `stack.sh`, then configures DevStack for the lab: the dedicated vendordata user (`nova-vendordata`, with the `service` role on the `service` project), Nova's DynamicJSON target (`openstack_iid` at `https://issuer-a.lab:8443/attest`, verified against the lab CA, not fatal on failure, with the `nova-vendordata` client certificate as `certfile`/`keyfile`), the guest images in Glance, a `lab.guest` flavor, and the lab's SSH key with SSH and ICMP access in the `demo` project. A smoke test then boots a CirrOS instance that reaches `spire.lab` by address and by name and reads its vendordata; Nova's log tells whether it called the target as the vendordata user (a connection failure while no issuer runs) or could not authenticate. On its first success, `up` takes the snapshot, then runs `deploy`. Most of the time goes into DevStack's `stack.sh`, which runs as a systemd unit on `devstack` so that a dropped SSH connection cannot interrupt it; `up` reports its progress. A second `up` on a complete lab only verifies it, so `up` can always be rerun after a failure.
- `snapshot` / `reset`: saves the running VMs as the lab's baseline (refusing while DevStack has instances, and asking before replacing a snapshot), or returns every VM to it, in under a minute. This is the normal way to start a test session. Snapshots are internal to the VMs' disks and include their memory: DevStack does not survive a cold reboot (the public bridge's address and its NAT rule are not persistent), so reverting resumes the running VMs rather than booting them. The VMs then resume at the snapshot's time, so `reset` sets each VM's clock from the lab host's, waits for Nova's compute service to report in again, and runs the smoke test.
- `deploy`: builds the deb and rpm packages on the lab host with `make snapshot` (goreleaser) and installs the baseline amd64 ones, as an operator would; nothing is compiled in the VMs. It then:
  - installs `openstack-spire-issuer` on `issuer-a` (deb) and `issuer-b` (rpm) and writes their configuration: peered with each other, the syslog sink enabled, `nova-vendordata` listed by ID in `keystone.allowed_users`, `/attest` restricted to `devstack`'s address and to Nova's client certificate (`attest.allowed_sources`, `attest.client_ca_path` with the lab CA), DevStack's CA for Keystone and Nova, the lab CA for the peer, the server certificate with its key readable by the service user only, and `signer.env` with the `spire-issuer` credentials. `config check` runs as the service user, the service starts, and `deploy` waits for both replicas' `/readiness` (about 2 minutes: each first key is published ahead of use);
  - installs the pinned SPIRE release (verified) and `openstack-server-plugin` (deb) on `spire`, with a systemd unit, the trust domain `openstack.lab`, the plugin's checksum, the merged JWK Set URL and `allowed_project_ids` set to the `demo` project, and waits for SPIRE Server's health check;
  - publishes what the guests install (the SPIRE tarball and the agent plugin's deb and rpm) on `http://spire.lab:8080/`, served from `spire` (instances cannot be reached with `scp`, and the lab host runs no services);
  - writes the guests' cloud-init configurations (`guest/ubuntu.yaml`, `guest/rhel.yaml` in the state directory): they install the agent plugin package and SPIRE (verifying the tarball's checksum again), with SPIRE's trust bundle embedded rather than downloaded, the plugin's checksum, and a SPIRE Agent unit.

  `deploy` after `reset` is the inner loop after a code change.
- `test [-run REGEX]`: runs the acceptance tests.
- `status`, `ssh <vm>`, `logs <vm> [unit]`: inspection.
- `down`: destroys the VMs with their snapshots, the network, the storage pool and the state directory, after confirmation. The download cache stays.

Downloads are verified like an operator would: cloud images against their distributor's checksum files, SPIRE's tarball against its release checksum (or the pinned `LAB_SPIRE_SHA256`). Once chunk 8 signs our releases, `deploy` can also install a signed release instead of a snapshot.

## Acceptance tests

The acceptance tests are Go tests in `test/lab/acceptance`, behind the `lab` build tag, so that `go test ./...` never runs them. They read `env.json` from the state directory (addresses, SSH key, project and image IDs, trust domain, resolved versions). They reach the VMs through the system `ssh` client and OpenStack through the `openstack` CLI on `devstack`, so they add no dependencies to `go.mod` and depend on nothing specific to the lab host.

Each test boots the instances it needs and deletes them afterwards, so tests are independent and can run in any order. They run one after another, since some reconfigure or restart the issuers, and each restores what it changes. The scenarios of later chunks are written together with those chunks; until then they do not exist, rather than being skipped.

- `lab.sh test [-run REGEX] [-long]` runs them (`go test -tags lab` in `test/lab/acceptance`). The long scenarios (E2E-3, about 20 minutes) run only with `-long`; the others take about 20 minutes together.
- Guests are booted in the `demo` project (or `alt_demo` for E2E-4, on `demo`'s private network shared with it), with the `lab.guest` flavor and the configuration `deploy` wrote. They are reached, when a test needs a shell in them, over SSH from the `devstack` VM's OVN metadata namespace, which sits on their private network: no floating IP is needed.
- Every token check joins the issuer's regular log (the `token issued` records) with what journald recorded from the syslog socket, by `jti`.

| ID | Scenario | Checks | Chunk |
| --- | --- | --- | --- |
| E2E-1 | Attestation | An Ubuntu and a RHEL-like instance boot; each agent attests; `spire-server agent list` shows `spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>` with the expected selectors | 3.5 |
| E2E-2 | Freshness | Restarting an agent with its data directory wiped attests again within the bound of the spec (Nova cache plus one retry), with the "already used" rejection at most once | 3.5 |
| E2E-3 | Rotation | With `rotation_interval: 5m` on both issuers, instances keep attesting across two rotations; no attestation fails on an unknown kid | 3.5 |
| E2E-4 | Unlisted project | An instance in a project missing from `allowed_project_ids` is refused | 3.5 |
| PKG-1 | Packages | deb on `issuer-a` and `spire`, rpm on `issuer-b`, and both in the guests, install and upgrade cleanly; units are installed disabled, then started by `deploy`; `config check` passes on the deployed files | 3.5 |
| AUD-1 | Syslog under the unit | Every token issued during E2E-1 has exactly one `token_issued` entry in `issuer-a`'s journal with `SYSLOG_IDENTIFIER=openstack-spire-issuer`, the token's `jti`, and the `authpriv` facility; key rotations in E2E-3 appear as `key_lifecycle` entries | 3.5 (closes chunk 3) |
| AUD-2 | Log level off | With `OPENSTACK_SPIRE_ISSUER_LOG_LEVEL=off`, AUD-1 still holds and the unit's standard error still carries the audit records | 3.5 |
| S3-1 | Dedicated vendordata user | Nova authenticates as the dedicated user. The `nova` service user's token is refused by `/attest` (`403`) | 3.5 |
| NET-1 | Source allowlist | With `attest.allowed_sources` set to `devstack`'s address, `/attest` from the lab host with a valid vendordata token is refused with `403`; E2E-1 still passes | 4 |
| NET-2 | Nova client certificate | With `attest.client_ca_path` set, Nova's `[vendordata_dynamic_auth]` `certfile`/`keyfile` make E2E-1 pass; without them `/attest` refuses with `403`, and the JWK Set stays reachable without a certificate | 4 |
| DOS-1 | Public endpoint limit | A burst on `/.well-known/jwks.json` from the lab host gets `429` while E2E-1 still passes | 5 |
| MEM-1 | Memory protection | The running signer is non-dumpable and its memory is locked (`VmLck`); its unit has `LimitCORE=0` and `LimitMEMLOCK=infinity` | 6 |
| AUD-3 | Correlation | Every `agent_attested` record on `spire` has a `token_issued` record with the same `jti` on an issuer; a quick re-attestation produces a `reattest_alert` with severity `warning` | 7 |
| GST-1 | Guest hardening | With the sample nftables rule loaded, an unprivileged user in the guest cannot reach `169.254.169.254`, while root and the SPIRE Agent user can, and E2E-1 passes | 8 |
| REL-1 | Signed releases | `deploy` from a signed release verifies the checksums file and the packages before installing | 8 |

Every failing check prints what it observed (HTTP status, journal lines, agent list), so that a failure can be diagnosed without re-running it.

## Implementation plan for chunk 3.5

1. `lab.env` and `lab.sh preflight`, with every check above. Done when preflight reports correctly on this machine, and, with `--no-install`, in a clean Ubuntu and a clean Fedora or RHEL-like container (the OS and software checks; the virtualization checks need a real host).
2. `up` (network, pool, VMs, DevStack, version resolution), `down`, `status`, `ssh`, `logs`. Done when `stack.sh` completes and `openstack server create` boots an instance that reaches `spire.lab`. This step settles how instances reach the lab network.
3. Lab PKI, the dedicated vendordata user, Nova's DynamicJSON configuration, the Glance images, `snapshot` and `reset`.
4. `deploy`: packages from `make snapshot`, configuration of both issuers (peered, syslog sink enabled), of SPIRE Server and of the guests' cloud-init. Done when an Ubuntu guest booted by Nova with that configuration attests (done Oct 4: the first real attestation; it also found a contract bug the in-process tests could not see, Nova's nesting of the vendordata response, now covered by them).
5. The acceptance test harness and the 3.5 scenarios above. Chunk 3's open item is closed by AUD-1 and AUD-2, which also found that journald does not parse RFC 5424: the syslog sink now sends RFC 3164 (issuer spec).
6. README: a short "Lab" section (requirements, `preflight`, `up`, `test`). Issuer spec: the references to `test/install_devstack_lxd.sh` point to `test/lab/lab.sh` instead.

Chunks 4 to 8 each add their own scenarios from the table and run them before their commit. Chunk 4 added NET-1 and NET-2 (Oct 5): the lab runs with both `/attest` restrictions on, and confirmed that Nova presents its client certificate through `[vendordata_dynamic_auth]`. Chunk 5 added DOS-1.

## Resolved questions

- Versions: Ubuntu 24.04 LTS, DevStack's most recent stable branch, and the most recent SPIRE release compatible with the plugin SDK, all resolved at `up` unless pinned in `lab.env`.
- RHEL-like distro: the most recent major release (10) of AlmaLinux by default, Rocky Linux as an option.
- No load balancer in front of the issuers.
- Instance access to the lab network: DevStack's public network, through the NAT DevStack sets up itself; no provider network is needed (step 2).
