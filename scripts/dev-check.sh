#!/usr/bin/env bash
# Sanity check of a development environment for openstack-spiffe (see
# DEVELOPMENT.md): the machine, the tools the build, tests and lint need, and
# a build of every package. It installs nothing.
#
#   scripts/dev-check.sh          # checks and a build (about a minute)
#   scripts/dev-check.sh --test   # also runs the unit and integration tests
#
# Each check prints ok, warn (development works, with the stated limitation)
# or fail; the script exits non-zero on any fail. The lab has its own, much
# larger requirements: test/lab/lab.sh preflight --no-install checks them.
set -uo pipefail

run_tests=
case "${1:-}" in
--test) run_tests=1 ;;
"") ;;
*)
	echo "usage: $0 [--test]" >&2
	exit 2
	;;
esac

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo" || exit 1

failures=0
green='' yellow='' red='' plain=''
if [[ -t 1 ]]; then green=$'\033[32m' yellow=$'\033[33m' red=$'\033[31m' plain=$'\033[0m'; fi
ok() { printf '  %sok%s    %s\n' "$green" "$plain" "$*"; }
warn() { printf '  %swarn%s  %s\n' "$yellow" "$plain" "$*"; }
fail() {
	printf '  %sfail%s  %s\n' "$red" "$plain" "$*"
	failures=$((failures + 1))
}
section() { printf '\n%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
# version_ge A B: A >= B, as versions
version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }
# free_gib PATH: free space, in GiB, on the file system holding PATH
free_gib() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print int($4 / 1048576) }'; }

section "Machine"
os="$(uname -s)" arch="$(uname -m)"
if [[ "$os" == Linux ]]; then
	# shellcheck source=/dev/null
	ok "Linux ($(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown distribution}"))"
else
	fail "$os: the services, packages and tests are Linux-only"
fi
case "$arch" in
x86_64 | aarch64) ok "$arch" ;;
*) warn "$arch: releases are built for amd64 and arm64 only" ;;
esac
cpus="$(nproc 2>/dev/null || echo 1)"
if ((cpus >= 4)); then ok "$cpus logical CPUs"; else warn "$cpus logical CPUs: builds and tests will be slow (4 or more recommended)"; fi
ram="$(awk '/^MemTotal:/ { print int($2 / 1048576 + 0.5) }' /proc/meminfo 2>/dev/null || echo 0)"
if ((ram >= 8)); then ok "${ram} GiB of RAM"; elif ((ram >= 4)); then warn "${ram} GiB of RAM: 8 GiB or more recommended (goreleaser builds 12 binaries in parallel)"; else fail "${ram} GiB of RAM: at least 4 GiB needed"; fi
for dir in "$repo" "$(go env GOMODCACHE 2>/dev/null || echo "$HOME")"; do
	free="$(free_gib "$dir")"
	if ((free >= 10)); then ok "${free} GiB free under $dir"; elif ((free >= 5)); then warn "${free} GiB free under $dir: 10 GiB or more recommended"; else fail "${free} GiB free under $dir: at least 5 GiB needed (dist/ alone takes about 350 MiB per snapshot)"; fi
done

section "Required tools"
for tool in git make bash curl; do
	if have "$tool"; then ok "$tool"; else fail "$tool is missing"; fi
done
required_go="$(awk '$1 == "go" { print $2; exit }' go.mod)"
if have go; then
	go_version="$(go env GOVERSION | sed 's/^go//')"
	if version_ge "$go_version" "$required_go"; then
		ok "Go $go_version (go.mod requires $required_go)"
	elif [[ "$(go env GOTOOLCHAIN)" != local* ]] && version_ge "$go_version" 1.21; then
		warn "Go $go_version: the go command will download go$required_go on first use (GOTOOLCHAIN=$(go env GOTOOLCHAIN))"
	else
		fail "Go $go_version is older than $required_go (go.mod)"
	fi
else
	fail "Go is missing: install go$required_go from https://go.dev/dl/"
fi

section "Packaging (make snapshot, make release)"
if have goreleaser; then
	gr_version="$(goreleaser --version 2>/dev/null | awk '/^GitVersion:/ { print $2 }')"
	if version_ge "${gr_version:-0}" 2.0.0; then ok "goreleaser $gr_version"; else fail "goreleaser ${gr_version:-of unknown version}: v2 needed"; fi
else
	fail "goreleaser is missing: go install github.com/goreleaser/goreleaser/v2@latest"
fi
if have syft; then ok "syft (SBOMs)"; else fail "syft is missing (make snapshot generates SBOMs): see DEVELOPMENT.md"; fi
if have gpg; then ok "gpg (signed builds, the lab's packaging key)"; else warn "gpg is missing: only unsigned snapshots can be built, and the lab cannot run"; fi

section "Quality (lint)"
if have golangci-lint; then
	gl_version="$(golangci-lint --version 2>/dev/null | grep -oE 'version v?[0-9.]+' | grep -oE '[0-9.]+$')"
	if version_ge "${gl_version:-0}" 2.0.0; then ok "golangci-lint $gl_version"; else fail "golangci-lint ${gl_version:-of unknown version}: v2 needed (CI runs v2)"; fi
else
	fail "golangci-lint is missing: make go-setup-tools, or see DEVELOPMENT.md"
fi
if have shellcheck; then
	ok "shellcheck"
elif have docker; then
	ok "shellcheck through docker (koalaman/shellcheck:stable)"
else
	warn "neither shellcheck nor docker: the lab's scripts cannot be checked"
fi

section "Optional test dependencies"
if have nft && have unshare && unshare -rn true 2>/dev/null; then
	ok "nft and unprivileged user namespaces (the nftables sample is checked)"
else
	warn "nft or unprivileged user namespaces missing: TestMetadataNftablesSample is skipped"
fi

section "Build"
if ! have go; then
	fail "skipped: Go is missing"
else
	if out="$(go build ./... 2>&1)"; then ok "go build ./..."; else fail "go build ./...:"$'\n'"$out"; fi
	if out="$(go vet ./... 2>&1)"; then ok "go vet ./..."; else fail "go vet ./...:"$'\n'"$out"; fi
	if have goreleaser; then
		if goreleaser check >/dev/null 2>&1; then ok "goreleaser check"; else fail "goreleaser check: .goreleaser.yaml is invalid for this goreleaser"; fi
	fi
	if [[ -n "$run_tests" ]]; then
		if out="$(go test ./... 2>&1)"; then ok "go test ./..."; else fail "go test ./...:"$'\n'"$(grep -vE '^(ok|\?)' <<<"$out")"; fi
	fi
fi

echo
if ((failures > 0)); then
	echo "$failures check(s) failed: see DEVELOPMENT.md"
	exit 1
fi
echo "The development environment is ready."
