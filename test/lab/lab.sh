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
# shellcheck source=lib/versions.sh
source "$LAB_DIR/lib/versions.sh"
# shellcheck source=lib/vm.sh
source "$LAB_DIR/lib/vm.sh"
# shellcheck source=lib/devstack.sh
source "$LAB_DIR/lib/devstack.sh"
# shellcheck source=lib/pki.sh
source "$LAB_DIR/lib/pki.sh"
# shellcheck source=lib/snapshot.sh
source "$LAB_DIR/lib/snapshot.sh"
# shellcheck source=lib/deploy.sh
source "$LAB_DIR/lib/deploy.sh"

usage() {
	cat <<USAGE
usage: lab.sh <command> [options]

commands:
  preflight [--no-install]  check that this machine can run the lab, and
                            install the missing software after confirmation
                            (--no-install: only report)
  up                        build the lab (or complete a partial one)
  down                      destroy the lab: VMs, network, storage, state
  status                    show the VMs, the resolved versions and DevStack
  ssh <vm> [command]        open a shell, or run a command, on a VM
  logs <vm> [unit]          show a VM's cloud-init log (stack.sh's on
                            devstack), or a systemd unit's journal
  snapshot                  save the running lab as its baseline (up takes
                            one when there is none)
  reset                     return the lab to its baseline, in minutes
  deploy                    build the packages here and install them on the
                            VMs, configured for the lab
  test [-run REGEX] [-long] run the acceptance tests (-long: also the long
                            scenarios, e.g. key rotation)
  help                      show this help

VMs: ${LAB_VMS[*]}
Settings are in lab.env, overridden by lab.local.env and by the environment.
USAGE
}

require_state() {
	[[ -f "$(env_file)" ]] || die "no lab here: run lab.sh up first"
}

# resolve_versions: records in env.json every version the lab uses, unless a
# previous (possibly partial) "up" already did; "down" forgets them.
resolve_versions() {
	if [[ -f "$(env_file)" ]]; then
		info "reusing the versions resolved at the first up (lab.sh status)"
		return
	fi
	section "Versions"
	local branch spire ubuntu_url ubuntu_sha rhel_url rhel_sha
	branch="$(resolve_devstack_branch)"
	spire="$(resolve_spire)"
	ubuntu_url="$(ubuntu_image_url)"
	rhel_url="$(rhel_image_url)"
	ubuntu_sha="${LAB_UBUNTU_IMAGE_SHA256:-$(published_sha256 "$ubuntu_url")}" ||
		die "no published checksum for $ubuntu_url: set LAB_UBUNTU_IMAGE_SHA256"
	rhel_sha="${LAB_RHEL_IMAGE_SHA256:-$(published_sha256 "$rhel_url")}" ||
		die "no published checksum for $rhel_url: set LAB_RHEL_IMAGE_SHA256"
	jq -n \
		--arg branch "$branch" --arg spire "${spire% *}" --arg spire_sha "${spire#* }" \
		--arg sdk "$(sdk_version)" \
		--arg ubuntu_release "$LAB_UBUNTU_RELEASE" --arg ubuntu_url "$ubuntu_url" --arg ubuntu_sha "$ubuntu_sha" \
		--arg rhel_distro "$LAB_RHEL_DISTRO" --arg rhel_release "$LAB_RHEL_RELEASE" --arg rhel_url "$rhel_url" --arg rhel_sha "$rhel_sha" \
		--arg network "$LAB_NETWORK" --arg subnet "$LAB_SUBNET" --arg user "$LAB_USER" --arg key "$(ssh_key)" \
		'{
			versions: {devstack_branch: $branch, spire: $spire, spire_sha256: $spire_sha, spire_plugin_sdk: $sdk},
			images: {
				ubuntu: {distro: "ubuntu", release: $ubuntu_release, url: $ubuntu_url, sha256: $ubuntu_sha},
				rhel: {distro: $rhel_distro, release: $rhel_release, url: $rhel_url, sha256: $rhel_sha}
			},
			network: {name: $network, subnet: $subnet},
			ssh: {user: $user, key: $key},
			vms: {}
		}' >"$(env_file)"
	local vm
	for vm in "${LAB_VMS[@]}"; do
		env_set ".vms[\"$vm\"].ip" "$(vm_ip "$vm")"
		env_set ".vms[\"$vm\"].os" "$(vm_attr "$vm" os)"
	done
	info "DevStack $branch, SPIRE ${spire% *}, Ubuntu $LAB_UBUNTU_RELEASE, $LAB_RHEL_DISTRO $LAB_RHEL_RELEASE"
}

cmd_up() {
	run_preflight || die "the preflight failed: fix the failures above and run lab.sh up again"
	mkdir -p "$LAB_STATE_DIR"
	ensure_ssh_key
	resolve_versions
	ensure_pki

	section "VMs"
	ensure_pool
	ensure_base_images
	ensure_network
	local vm
	for vm in "${LAB_VMS[@]}"; do
		ensure_vm "$vm"
	done
	for vm in "${LAB_VMS[@]}"; do
		wait_for_vm "$vm"
	done

	section "DevStack"
	devstack_up
	devstack_configure
	devstack_smoke

	if ! all_snapshots_exist; then
		section "Snapshot"
		LAB_ASSUME_YES=1 lab_snapshot
	fi

	section "Done"
	info "the lab is up: lab.sh status, lab.sh ssh <vm>, lab.sh reset"
}

cmd_down() {
	if ! confirm "Destroy the lab (VMs, network $LAB_NETWORK, storage pool $LAB_POOL and $LAB_STATE_DIR)?"; then
		info "nothing destroyed"
		return 1
	fi
	destroy_all
	rm -rf "$LAB_STATE_DIR"
	info "the lab is gone (the download cache in $LAB_CACHE_DIR stays)"
}

cmd_status() {
	require_state
	section "Versions"
	info "DevStack:  $(env_get '.versions.devstack_branch') $(env_get '.versions.devstack_commit // "" | .[0:12]')"
	info "SPIRE:     $(env_get '.versions.spire') (for spire-plugin-sdk $(env_get '.versions.spire_plugin_sdk'))"
	info "images:    $(env_get '.images.ubuntu | "\(.distro) \(.release)"'), $(env_get '.images.rhel | "\(.distro) \(.release)"')"
	section "VMs"
	local vm state
	for vm in "${LAB_VMS[@]}"; do
		state="$(vsh domstate "$(vm_domain "$vm")" 2>/dev/null || echo absent)"
		printf '        %-9s %-12s %s\n' "$vm" "$(vm_ip "$vm")" "$state"
	done
	section "Snapshot"
	if all_snapshots_exist; then
		info "taken $(env_get '.snapshot.taken')"
	else
		info "none (lab.sh snapshot)"
	fi
	section "DevStack"
	if devstack_stacked; then
		info "running"
	else
		info "not stacked ($(vm_ssh devstack "systemctl show -p ActiveState --value $DEVSTACK_UNIT" 2>/dev/null || echo unreachable))"
	fi
}

cmd_ssh() {
	require_state
	local vm="${1:-}"
	[[ " ${LAB_VMS[*]} " == *" $vm "* ]] || die "usage: lab.sh ssh <vm> [command]; VMs: ${LAB_VMS[*]}"
	shift
	exec ssh -t "${SSH_OPTS[@]}" "$LAB_USER@$(vm_ip "$vm")" "$@"
}

cmd_logs() {
	require_state
	local vm="${1:-}" unit="${2:-}"
	[[ " ${LAB_VMS[*]} " == *" $vm "* ]] || die "usage: lab.sh logs <vm> [unit]; VMs: ${LAB_VMS[*]}"
	if [[ -n "$unit" ]]; then
		vm_ssh "$vm" "sudo journalctl --no-pager -n 300 -u $(printf '%q' "$unit")"
	elif [[ "$vm" == devstack ]] && vm_ssh "$vm" "test -e $DEVSTACK_LOG"; then
		vm_ssh "$vm" "sudo tail -n 300 $DEVSTACK_LOG"
	else
		vm_ssh "$vm" "sudo tail -n 300 /var/log/cloud-init-output.log"
	fi
}

cmd_test() {
	local args=() long=""
	while (($#)); do
		case "$1" in
		-run)
			[[ $# -ge 2 ]] || die "usage: lab.sh test [-run REGEX] [-long]"
			args+=(-run "$2")
			shift 2
			;;
		-long)
			long=1
			shift
			;;
		*) die "usage: lab.sh test [-run REGEX] [-long]" ;;
		esac
	done
	[[ -n "$(env_get '.spire.trust_domain // ""')" ]] || die "the lab is not deployed: run lab.sh deploy"
	cd "$LAB_DIR/acceptance"
	LAB_STATE_DIR="$LAB_STATE_DIR" LAB_LONG="$long" go test -tags lab -count=1 -v -timeout 90m "${args[@]}" .
}

main() {
	local command="${1:-help}"
	shift || true
	load_settings
	load_ssh
	case "$command" in
	preflight) run_preflight "$@" ;;
	up) cmd_up ;;
	down) cmd_down ;;
	status) cmd_status ;;
	ssh) cmd_ssh "$@" ;;
	logs) cmd_logs "$@" ;;
	snapshot)
		require_state
		lab_snapshot
		;;
	reset)
		require_state
		lab_reset
		;;
	deploy)
		require_state
		lab_deploy
		;;
	test)
		require_state
		cmd_test "$@"
		;;
	help | -h | --help) usage ;;
	*)
		usage >&2
		exit 2
		;;
	esac
}

main "$@"
