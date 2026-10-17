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
# resume at the time of the snapshot, and checks DevStack. A saved state
# (lab.sh stop) is discarded: the snapshot wins.
lab_reset() {
	all_snapshots_exist || die "no snapshot of the whole lab: run lab.sh up (or lab.sh snapshot)"
	local vm
	for vm in "${LAB_VMS[@]}"; do
		if vm_saved "$vm"; then
			info "discarding the saved state of $vm"
			vsh managedsave-remove "$(vm_domain "$vm")" >/dev/null
		fi
	done
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

# --- Stop and start -------------------------------------------------------------
# A session ends with "stop", which keeps the lab as it is, and resumes with
# "start". libvirt's managed save writes each VM's memory and devices to its
# save directory and stops it; starting the VM resumes it from there. A
# shutdown would lose DevStack, which does not survive a cold boot.

readonly LIBVIRT_SAVE_DIR=/var/lib/libvirt/qemu/save

# vm_saved VM: whether VM is stopped with a saved state.
vm_saved() {
	[[ "$(vsh domstate --reason "$(vm_domain "$1")" 2>/dev/null)" == "shut off (saved)" ]]
}

# lab_saved: whether any VM of the lab is stopped with a saved state.
lab_saved() {
	local vm
	for vm in "${LAB_VMS[@]}"; do
		vm_saved "$vm" && return 0
	done
	return 1
}

# require_started: refuses a command that needs the VMs while the lab is
# stopped.
require_started() {
	! lab_saved || die "the lab is stopped: run lab.sh start first"
}

# lab_stop: saves every running VM, after checking that libvirt's save
# directory has room for their memory plus 10%.
lab_stop() {
	local vm running=() need_kib=0 avail_kib
	for vm in "${LAB_VMS[@]}"; do
		if [[ "$(vsh domstate "$(vm_domain "$vm")" 2>/dev/null)" == running ]]; then
			running+=("$vm")
			need_kib=$((need_kib + $(vsh dominfo "$(vm_domain "$vm")" | awk '/^Used memory:/ { print $3 }')))
		fi
	done
	if ((${#running[@]} == 0)); then
		if lab_saved; then
			info "the lab is already stopped: lab.sh start resumes it"
		else
			info "no VM of the lab is running: nothing to save"
		fi
		return
	fi
	need_kib=$((need_kib * 110 / 100))
	# the save directory itself is libvirt's, not readable by the user: the
	# file system holding it
	avail_kib="$(df --output=avail -k "$(dirname "$LIBVIRT_SAVE_DIR")" | tail -n1)"
	((avail_kib >= need_kib)) ||
		die "saving the VMs needs $((need_kib / 1024 / 1024)) GiB under $LIBVIRT_SAVE_DIR, $((avail_kib / 1024 / 1024)) GiB are free: free some space (nothing was saved)"
	for vm in "${running[@]}"; do
		info "saving $vm"
		vsh managedsave "$(vm_domain "$vm")" >/dev/null || die "cannot save $vm (lab.sh status)"
	done
	info "the lab is stopped, as it was: lab.sh start resumes it"
}

# lab_start: resumes the saved VMs, then fixes their clocks, which resume at
# the time they were saved, and checks DevStack, as lab_reset does.
lab_start() {
	local vm state saved=()
	for vm in "${LAB_VMS[@]}"; do
		state="$(vsh domstate "$(vm_domain "$vm")" 2>/dev/null)" || die "$vm does not exist: run lab.sh up"
		if vm_saved "$vm"; then
			saved+=("$vm")
		elif [[ "$state" != running ]]; then
			die "$vm is $state without a saved state, and DevStack does not survive a cold boot: run lab.sh reset"
		fi
	done
	if ((${#saved[@]} == 0)); then
		info "the lab is already running"
		return
	fi
	for vm in "${saved[@]}"; do
		info "resuming $vm"
		vsh start "$(vm_domain "$vm")" >/dev/null || die "cannot resume $vm (lab.sh status)"
	done
	for vm in "${LAB_VMS[@]}"; do
		set_clock "$vm"
	done
	devstack_wait_compute
	devstack_smoke
	info "the lab is running again, as it was stopped"
}
