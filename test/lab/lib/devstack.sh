# shellcheck shell=bash
# DevStack on the devstack VM: installation, stack.sh, and a smoke test.

readonly DEVSTACK_DIR=/opt/stack/devstack
readonly DEVSTACK_MARKER=/opt/stack/.lab-stacked
readonly DEVSTACK_UNIT=lab-stack
readonly DEVSTACK_LOG=/opt/stack/logs/stack.sh.log

devstack_password() {
	local file="$LAB_STATE_DIR/devstack-admin-password"
	[[ -f "$file" ]] || openssl rand -hex 16 >"$file"
	cat "$file"
}

devstack_stacked() { vm_ssh devstack "test -f $DEVSTACK_MARKER" 2>/dev/null; }

# devstack_up: installs DevStack and runs stack.sh, unless already done.
devstack_up() {
	if devstack_stacked; then
		info "DevStack is already running"
		return
	fi
	local branch state
	branch="$(jq -r .versions.devstack_branch "$LAB_STATE_DIR/env.json")"
	state="$(vm_ssh devstack "systemctl show -p ActiveState --value $DEVSTACK_UNIT" 2>/dev/null || true)"
	case "$state" in
	active | activating) info "stack.sh is already running" ;;
	failed) die "a previous stack.sh failed (lab.sh logs devstack); start over with lab.sh down && lab.sh up" ;;
	*)
		info "installing DevStack $branch"
		vm_ssh devstack "bash -s -- $(printf '%q ' "$branch" "$DEVSTACK_DIR")" <<'SCRIPT'
set -euo pipefail
branch="$1" dir="$2"
sudo apt-get update -q >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q git >/dev/null
[[ -d /tmp/devstack-bootstrap ]] || git clone -q --depth 1 -b "$branch" https://opendev.org/openstack/devstack /tmp/devstack-bootstrap
id stack >/dev/null 2>&1 || sudo /tmp/devstack-bootstrap/tools/create-stack-user.sh >/dev/null
[[ -d "$dir" ]] || sudo -u stack git clone -q -b "$branch" https://opendev.org/openstack/devstack "$dir"
SCRIPT
		devstack_local_conf | vm_ssh devstack "sudo -u stack tee $DEVSTACK_DIR/local.conf >/dev/null"
		local commit
		commit="$(vm_ssh devstack "sudo -u stack git -C $DEVSTACK_DIR rev-parse HEAD")"
		env_set ".versions.devstack_commit" "$commit"
		info "running stack.sh (10 to 30 minutes, depending on the host and the network; follow it with: lab.sh logs devstack)"
		vm_ssh devstack "sudo systemd-run --quiet --unit=$DEVSTACK_UNIT -p User=stack -p RemainAfterExit=yes \
			-p WorkingDirectory=$DEVSTACK_DIR --setenv=HOME=/opt/stack \
			/bin/bash -c './stack.sh && touch $DEVSTACK_MARKER'"
		;;
	esac
	devstack_wait
}

devstack_local_conf() {
	local password ip
	password="$(devstack_password)"
	ip="$(vm_ip devstack)"
	cat <<CONF
[[local|localrc]]
ADMIN_PASSWORD=$password
DATABASE_PASSWORD=$password
RABBIT_PASSWORD=$password
SERVICE_PASSWORD=$password
HOST_IP=$ip
SERVICE_HOST=$ip
LIBVIRT_TYPE=kvm
# RHEL 10 guests need an x86-64-v3 CPU: pass the VM's (the host's) through.
# DevStack's default is a fixed, older model (custom, Nehalem).
LIBVIRT_CPU_MODE=host-passthrough
LOGFILE=$DEVSTACK_LOG
LOG_COLOR=False
# only what the lab needs: Keystone, Nova (with the metadata API), Neutron,
# Glance and Placement
disable_service horizon
disable_service c-api c-vol c-sch c-bak
disable_service tempest
disable_service dstat
CONF
}

# devstack_wait: waits for stack.sh, reporting its progress.
devstack_wait() {
	local deadline=$((SECONDS + 7200)) state last="" line
	while :; do
		state="$(vm_ssh devstack "systemctl show -p ActiveState --value $DEVSTACK_UNIT" 2>/dev/null || echo unknown)"
		if devstack_stacked; then
			info "stack.sh completed"
			return
		fi
		case "$state" in
		failed | inactive)
			vm_ssh devstack "sudo tail -n 30 $DEVSTACK_LOG" 2>/dev/null | sed 's/^/        | /'
			die "stack.sh failed on devstack (full log: lab.sh logs devstack)"
			;;
		esac
		((SECONDS < deadline)) || die "stack.sh did not complete within 2 hours"
		line="$(vm_ssh devstack "sudo grep -E '^[0-9-]+ [0-9:.]+ \| ' $DEVSTACK_LOG.summary 2>/dev/null | tail -n1" 2>/dev/null || true)"
		if [[ -n "$line" && "$line" != "$last" ]]; then
			info "stack.sh: ${line#* | }"
			last="$line"
		fi
		sleep 30
	done
}

# devstack_smoke: boots a CirrOS instance that pings the spire VM by address
# and by name, and reports what its console shows.
devstack_smoke() {
	info "smoke test: an instance reaching spire.lab"
	local result
	result="$(vm_ssh devstack "sudo -u stack bash -s -- $(printf '%q ' "$(vm_ip spire)" "$(lab_ip 1)" "$DEVSTACK_DIR")" <<'SCRIPT'
set -uo pipefail
spire_ip="$1" dns="$2" dir="$3"
cd /opt/stack
# openrc reads variables that may be unset
set +u
# shellcheck disable=SC1091
source "$dir/openrc" demo demo >/dev/null 2>&1
set -u
openstack subnet set --dns-nameserver "$dns" private-subnet >/dev/null 2>&1 || true
image="$(openstack image list -f value -c Name | grep -m1 -i cirros)"
cat >/tmp/lab-smoke.sh <<DATA
#!/bin/sh
ping -c 3 -W 2 $spire_ip >/dev/null 2>&1 && echo LAB-SMOKE-ADDRESS-OK || echo LAB-SMOKE-ADDRESS-FAIL
ping -c 3 -W 2 spire.lab >/dev/null 2>&1 && echo LAB-SMOKE-NAME-OK || echo LAB-SMOKE-NAME-FAIL
DATA
openstack server delete --wait lab-smoke >/dev/null 2>&1 || true
openstack server create --image "$image" --flavor m1.tiny --network private \
	--user-data /tmp/lab-smoke.sh --wait lab-smoke >/dev/null || { echo LAB-SMOKE-BOOT-FAIL; exit 0; }
for _ in $(seq 60); do
	log="$(openstack console log show lab-smoke 2>/dev/null)"
	if grep -q 'LAB-SMOKE-NAME-' <<<"$log"; then
		grep -o 'LAB-SMOKE-[A-Z]*-[A-Z]*' <<<"$log"
		break
	fi
	sleep 5
done
openstack server delete --wait lab-smoke >/dev/null 2>&1 || true
SCRIPT
)"
	case "$result" in
	*LAB-SMOKE-ADDRESS-OK*LAB-SMOKE-NAME-OK*) info "an instance reaches spire.lab by address and by name" ;;
	*LAB-SMOKE-ADDRESS-OK*) die "an instance reaches spire's address, but cannot resolve spire.lab" ;;
	*LAB-SMOKE-BOOT-FAIL*) die "the smoke test instance did not boot (lab.sh logs devstack devstack@n-cpu)" ;;
	*LAB-SMOKE-ADDRESS-FAIL*) die "an instance cannot reach spire at $(vm_ip spire)" ;;
	*) die "the smoke test instance reported nothing within 5 minutes" ;;
	esac
}
