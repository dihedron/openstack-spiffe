# Developing openstack-spiffe

This guide is for contributors and maintainers. It covers setting up a development machine, the everyday workflow, and, for maintainers, releases and the packaging key. What the software does and how to deploy it are in the [README](README.md); the designs are in [.specs/](.specs).

## The machine

Development needs Linux, on x86-64 or arm64. The services, the packages and several tests are Linux-only: memory locking, syslog sockets, nftables and systemd units.

| | Minimum | Recommended |
| --- | --- | --- |
| CPU | 2 logical CPUs | 4 or more: goreleaser builds 12 binaries in parallel |
| RAM | 4 GiB | 8 GiB or more |
| Free disk | 5 GiB | 10 GiB or more: the Go module and build caches take a few GiB, and each snapshot in `dist/` about 350 MiB |

The [lab](#the-lab) is a different matter. It runs DevStack and three more VMs, and needs KVM with nested virtualization, about 14 vCPUs, 37 GiB of free memory and 120 GiB of disk with its default sizes. A host with 16 logical CPUs, 48 GiB of RAM and 150 GiB free runs it comfortably.

## The software

| Tool | Version | Used for |
| --- | --- | --- |
| Go | the `go` line of [go.mod](go.mod) (Go 1.21 or later downloads it automatically) | everything |
| git, make, curl, bash | any recent | the build |
| goreleaser | v2 | `make`, `make snapshot`, `make release`: binaries, archives, deb and rpm packages |
| syft | any recent | the SBOMs `make snapshot` generates |
| golangci-lint | v2 (CI runs v2) | lint |
| gpg | 2.2 or later | signed builds, the packaging key, the lab |
| shellcheck | any recent, or docker to run `koalaman/shellcheck:stable` | the lab's and packaging scripts |
| Docker or Podman | any recent | `make docs`: the release documents build in pinned pandoc and mermaid-cli images |
| nftables, with unprivileged user namespaces | optional | the nftables sample's test, skipped without them |

On Debian and Ubuntu:

```bash
sudo apt-get install -y git make curl gnupg shellcheck nftables
```

On Fedora and RHEL-like distributions (ShellCheck comes from EPEL on RHEL):

```bash
sudo dnf install -y git make curl gnupg2 ShellCheck nftables
```

Then Go, from [go.dev/dl](https://go.dev/dl/) (distributions usually lag behind), and the Go tools:

```bash
go install github.com/goreleaser/goreleaser/v2@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
```

`make go-setup-tools` installs golangci-lint and syft along with other Go tools (gopls, dlv, staticcheck, govulncheck, gosec), and `make go-check-tools` lists which ones are present.

## Sanity check

```bash
make dev-check        # or scripts/dev-check.sh: the machine, the tools, and a build (about a minute)
make dev-check-full   # the same, then the unit and integration tests
```

[scripts/dev-check.sh](scripts/dev-check.sh) installs nothing. It checks the machine against the minimums above, then each tool and its version, and finally builds and vets every package and validates `.goreleaser.yaml`. Each check prints `ok`, `warn` (development works, with the stated limitation) or `fail`, with what to do. The script exits non-zero on any `fail`.

For the lab, run `test/lab/lab.sh preflight --no-install`. It checks virtualization, resources and the lab's software, and reports without installing anything.

## Everyday workflow

The project is spec-driven (see [CLAUDE.md](CLAUDE.md)):

1. **Specs first.** Every feature or non-trivial fix starts from an approved specification in [.specs/](.specs). Requirements that address a threat carry its ID from the [threat model](.specs/openstack-spire-threat-model.md) (`S-4`, `T-7`, ...).
2. **Tests first.** Write the tests that match the spec's acceptance criteria, then the code.
3. **Check against the spec** before calling a change done: contracts, data models, edge cases.

The commands:

```bash
go test ./...                       # unit and integration tests (in-process servers, temporary sockets)
go test -race ./...                 # the same, with the race detector
go test -cpu 1,2 ./...              # the same on one and two CPUs, like CI runners: before pushing
golangci-lint run ./...             # lint; --new-from-rev=HEAD for your changes only
golangci-lint run --build-tags lab ./test/lab/acceptance   # the lab's tests are behind a build tag
docker run --rm -v "$PWD:/mnt" -w /mnt/test/lab koalaman/shellcheck:stable -x -P lib lab.sh lib/*.sh
make                                # a development build for this machine (dist/)
make snapshot                       # every platform, archive and package, unsigned
make checksum                       # the plugins' SHA-256, for plugin_checksum
make docs                           # the release documents (PDF) into build/docs/: needs docker or podman
make help                           # every target
```

Many-core machines hide timing assumptions that CI runners, with one or two CPUs, expose: a test reading what a goroutine records must wait for that goroutine, never assume it has already run. `-cpu 1,2` catches such races before CI does.

The examples in [examples/](examples) are read by tests: keep them valid when a configuration key changes.

The release documents (Setup Guide, Architecture and Design, Operator's Guide) live in [docs/](docs), as Markdown chapters with Mermaid diagrams, and are built to PDF with pandoc (see [.specs/openstack-spire-docs.md](.specs/openstack-spire-docs.md)). Update them in the change that alters what they describe: behaviour, configuration, errors or log messages. Configuration samples are included from `examples/` (a code block marked `{include="examples/signer.yaml"}`), never copied. The `Documents` workflow builds them on every change and attaches the PDFs to the run.

## The lab

Changes that involve OpenStack (Nova's vendordata calls, Keystone, the packages, the units, syslog under systemd) are verified on the lab: DevStack and the whole solution on libvirt VMs. It is described in the README's [lab section](README.md#lab-end-to-end-tests-on-a-real-openstack) and specified in [.specs/openstack-spire-test-environment.md](.specs/openstack-spire-test-environment.md). The inner loop after a code change:

```bash
test/lab/lab.sh reset && test/lab/lab.sh deploy && test/lab/lab.sh test [-run REGEX]
```

`deploy` builds the packages on the host, signed with a lab-only packaging key as CI signs a release. It verifies them, then installs them on the VMs. Nothing is compiled in the VMs.

## Maintainers

### Releasing

1. Check that `main` is green in CI and that the lab suite passes (`test/lab/lab.sh test`, plus `-long` before a major release).
2. Tag the release: `make release-patch`, `make release-minor` or `make release-major`. Each creates the next `vX.Y.Z` tag and pushes it.
3. The tag starts the [release workflow](.github/workflows/release.yml). It imports the packaging key from the repository secrets and checks it against [packaging/signing-key.asc](packaging/signing-key.asc). It then runs `make release`, which builds every artifact, signs the checksums file and the packages, and publishes the GitHub release.
4. Verify the published release as a user would (README, [Verify a release](README.md#verify-a-release)) before announcing it.

`make release` refuses to run without the packaging key, so a release can never be published unsigned.

### The packaging key

Releases are signed with one GPG key (T-7). Its public half is `packaging/signing-key.asc`. Its private half and passphrase are the repository secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, and an offline backup.

**Creating it** (once, from a trusted machine, with `gh` logged in as a repository admin):

```bash
packaging/create-signing-key.sh [BACKUP_DIR]   # default: ~/openstack-spiffe-packaging-key
```

The script:
- creates an RSA 4096 signing key, valid for 3 years, in a throwaway keyring;
- writes the private key (protected by the passphrase you choose) and its revocation certificate to `BACKUP_DIR`;
- writes the public key to `packaging/signing-key.asc`;
- sets both secrets with `gh secret set`;
- prints the fingerprint and the next steps.

Then:
- move `BACKUP_DIR` to offline storage and the passphrase to a password manager;
- commit `packaging/signing-key.asc`;
- publish the fingerprint somewhere outside the repository, so users can cross-check it.

`KEY_UID` and `KEY_EXPIRY` override the key's identity and lifetime.

**Renewing it** before it expires, from the backup, in a throwaway keyring:

```bash
export GNUPGHOME=$(mktemp -d)
gpg --import private-key.asc
gpg --quick-set-expire <fingerprint> 3y
gpg --armor --export <fingerprint> > packaging/signing-key.asc
gpg --armor --export-secret-keys <fingerprint> | gh secret set GPG_PRIVATE_KEY
```

Commit the re-exported public key, replace the backup, and remove the throwaway keyring. The fingerprint does not change, and signatures made before the renewal stay valid.

**If it is compromised:**
1. Revoke it. Import the public key and the revocation certificate from the backup into a throwaway keyring, then commit the re-exported, revoked public key, so users who refresh it see the revocation.
2. Remove `packaging/signing-key.asc` and create a new key with the script, which also replaces the secrets.
3. Publish the new fingerprint, and re-release what users should install, signed with the new key.
4. Announce which releases were signed with the old key.

The lab never uses this key: it creates its own in its state directory.
