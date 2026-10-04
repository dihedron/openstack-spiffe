# shellcheck shell=bash
# Snapshots of the whole lab, so that a test session starts from a known
# state in minutes instead of a new "up". Snapshots are internal to each VM's
# disk and include its memory: DevStack does not survive a cold reboot (its
# public bridge address and NAT rule are not persistent), so a reset resumes
# the VMs where they were rather than booting them.

readonly LAB_SNAPSHOT=lab-base

snapshot_exists() {
	vsh snapshot-info "$(vm_domain "$1")" "$LAB_SNAPSHOT" >/dev/null 2>&1
}

all_snapshots_exist() {
	local vm
	for vm in "${LAB_VMS[@]}"; do
		snapshot_exists "$vm" || return 1
	done
}

# lab_snapshot: saves every VM, running, as the lab's baseline.
lab_snapshot() {
	local vm instances
	for vm in "${LAB_VMS[@]}"; do
		[[ "$(vsh domstate "$(vm_domain "$vm")" 2>/dev/null)" == running ]] || die "$vm is not running: run lab.sh up first"
	done
	instances="$(devstack_openstack server list --all-projects -f value -c Name 2>/dev/null || true)"
	[[ -z "$instances" ]] || die "DevStack has instances ($(echo "$instances" | tr '\n' ' ')): delete them before taking the baseline"
	if all_snapshots_exist && ! confirm "Replace the lab's snapshot, taken $(env_get '.snapshot.taken // "at an unknown time"')?"; then
		info "snapshot kept"
		return 1
	fi
	for vm in "${LAB_VMS[@]}"; do
		snapshot_exists "$vm" && vsh snapshot-delete "$(vm_domain "$vm")" "$LAB_SNAPSHOT" >/dev/null
		info "snapshotting $vm"
		vsh snapshot-create-as "$(vm_domain "$vm")" "$LAB_SNAPSHOT" \
			--description "openstack-spiffe lab baseline" >/dev/null
	done
	env_set .snapshot.taken "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	info "snapshot taken: lab.sh reset returns the lab to this state"
}

# lab_reset: returns every VM to the snapshot, then fixes their clocks, which
# resume at the time of the snapshot, and checks DevStack.
lab_reset() {
	all_snapshots_exist || die "no snapshot of the whole lab: run lab.sh up (or lab.sh snapshot)"
	local vm
	for vm in "${LAB_VMS[@]}"; do
		info "reverting $vm"
		vsh snapshot-revert "$(vm_domain "$vm")" "$LAB_SNAPSHOT" --running >/dev/null
	done
	for vm in "${LAB_VMS[@]}"; do
		set_clock "$vm"
	done
	devstack_wait_compute
	devstack_smoke
	info "the lab is back to the snapshot taken $(env_get '.snapshot.taken')"
}

# set_clock VM: sets VM's clock from the lab host's; NTP takes over from there.
set_clock() {
	local deadline=$((SECONDS + 120))
	until vm_ssh "$1" "sudo date -u -s @$(date +%s.%N) >/dev/null" 2>/dev/null; do
		((SECONDS < deadline)) || die "$1 does not answer over SSH after the revert"
		sleep 2
	done
}

# devstack_wait_compute: waits until Nova's compute service reports in again,
# with the corrected clock, so that instances can be scheduled.
devstack_wait_compute() {
	local deadline=$((SECONDS + 180)) state
	until state="$(devstack_openstack compute service list --service nova-compute -f value -c State 2>/dev/null)" && [[ "$state" == up ]]; do
		((SECONDS < deadline)) || die "Nova's compute service is not up after the revert (lab.sh logs devstack devstack@n-cpu)"
		sleep 5
	done
}
