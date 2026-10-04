#!/usr/bin/env bash
# The openstack-spiffe lab: a disposable DevStack test environment on libvirt
# VMs. See .specs/openstack-spire-test-environment.md and "lab.sh help".
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"

# shellcheck source=lib/common.sh
source "$LAB_DIR/lib/common.sh"
# shellcheck source=lib/preflight.sh
source "$LAB_DIR/lib/preflight.sh"

usage() {
	cat <<USAGE
usage: lab.sh <command> [options]

commands:
  preflight [--no-install]  check that this machine can run the lab, and
                            install the missing software after confirmation
                            (--no-install: only report)
  help                      show this help

Settings are in lab.env, overridden by lab.local.env and by the environment.
USAGE
}

main() {
	local command="${1:-help}"
	shift || true
	load_settings
	case "$command" in
	preflight) run_preflight "$@" ;;
	up | down | status | ssh | logs | snapshot | reset | deploy | test)
		die "\"$command\" is not implemented yet (chunk 3.5, steps 2 to 5)"
		;;
	help | -h | --help) usage ;;
	*)
		usage >&2
		exit 2
		;;
	esac
}

main "$@"
