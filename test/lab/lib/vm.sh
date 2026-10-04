# shellcheck shell=bash
# The lab's libvirt resources: storage pool, base images, network and VMs.

readonly LAB_VMS=(devstack issuer-a issuer-b spire)
readonly LAB_USER=lab

vsh() { virsh -q -c qemu:///system "$@"; }

# vm_attr VM ATTRIBUTE: host (address host part), vcpus, ram (GiB), disk
# (GiB) or os (ubuntu or rhel).
vm_attr() {
	case "$1:$2" in
	devstack:host) echo "$LAB_DEVSTACK_HOST" ;;
	devstack:vcpus) echo "$LAB_DEVSTACK_VCPUS" ;;
	devstack:ram) echo "$LAB_DEVSTACK_RAM_GIB" ;;
	devstack:disk) echo "$LAB_DEVSTACK_DISK_GIB" ;;
	issuer-a:host) echo "$LAB_ISSUER_A_HOST" ;;
	issuer-b:host) echo "$LAB_ISSUER_B_HOST" ;;
	issuer-*:vcpus) echo "$LAB_ISSUER_VCPUS" ;;
	issuer-*:ram) echo "$LAB_ISSUER_RAM_GIB" ;;
	issuer-*:disk) echo "$LAB_ISSUER_DISK_GIB" ;;
	spire:host) echo "$LAB_SPIRE_HOST" ;;
	spire:vcpus) echo "$LAB_SPIRE_VCPUS" ;;
	spire:ram) echo "$LAB_SPIRE_RAM_GIB" ;;
	spire:disk) echo "$LAB_SPIRE_DISK_GIB" ;;
	issuer-b:os) echo rhel ;;
	*:os) echo ubuntu ;;
	*) die "unknown VM attribute $1:$2" ;;
	esac
}

vm_ip() { lab_ip "$(vm_attr "$1" host)"; }
vm_domain() { echo "$LAB_NETWORK-$1"; }
vm_mac() { printf '52:54:00:fa:00:%02x' "$(vm_attr "$1" host)"; }

# --- SSH ----------------------------------------------------------------------

ssh_key() { echo "$LAB_STATE_DIR/id_ed25519"; }

# SSH_OPTS: the options of every SSH connection to the VMs (set by load_ssh).
SSH_OPTS=()
load_ssh() {
	SSH_OPTS=(-i "$(ssh_key)" -o "UserKnownHostsFile=$LAB_STATE_DIR/known_hosts"
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes
		-o LogLevel=ERROR -o ServerAliveInterval=15)
}

# vm_ssh VM [COMMAND...]: runs COMMAND (a shell string) on VM as the lab user.
vm_ssh() {
	local vm="$1"
	shift
	ssh "${SSH_OPTS[@]}" "$LAB_USER@$(vm_ip "$vm")" "$@"
}

ensure_ssh_key() {
	[[ -f "$(ssh_key)" ]] || ssh-keygen -q -t ed25519 -N '' -C "openstack-spiffe-lab" -f "$(ssh_key)"
}

# --- Storage ------------------------------------------------------------------

ensure_pool() {
	if ! vsh pool-info "$LAB_POOL" >/dev/null 2>&1; then
		info "creating storage pool $LAB_POOL in $LAB_POOL_DIR"
		vsh pool-define-as "$LAB_POOL" dir --target "$LAB_POOL_DIR" >/dev/null
		vsh pool-build "$LAB_POOL" >/dev/null
		vsh pool-autostart "$LAB_POOL" >/dev/null
	fi
	[[ "$(vsh pool-info "$LAB_POOL" | awk '/^State:/ { print $2 }')" == running ]] || vsh pool-start "$LAB_POOL" >/dev/null
}

# upload_volume NAME FILE: uploads FILE as volume NAME, unless it exists.
upload_volume() {
	vsh vol-info --pool "$LAB_POOL" "$1" >/dev/null 2>&1 && return 0
	info "uploading $1"
	vsh vol-create-as "$LAB_POOL" "$1" "$(stat -c %s "$2")" --format raw >/dev/null
	vsh vol-upload --pool "$LAB_POOL" "$1" "$2"
	vsh pool-refresh "$LAB_POOL" >/dev/null
}

# base_volume OS: the name of the base image volume of OS (ubuntu or rhel),
# which includes the start of the image's checksum: a newer cloud image
# becomes a new base, never altering the VMs built on the previous one.
base_volume() {
	local sha
	sha="$(jq -r ".images.$1.sha256" "$LAB_STATE_DIR/env.json")"
	echo "base-$1-${sha:0:12}.qcow2"
}

ensure_base_images() {
	local os url sha path
	for os in ubuntu rhel; do
		url="$(jq -r ".images.$os.url" "$LAB_STATE_DIR/env.json")"
		sha="$(jq -r ".images.$os.sha256" "$LAB_STATE_DIR/env.json")"
		path="$(fetch "$url" "$sha")"
		upload_volume "$(base_volume "$os")" "$path"
	done
}

# --- Network ------------------------------------------------------------------

ensure_network() {
	if ! vsh net-info "$LAB_NETWORK" >/dev/null 2>&1; then
		info "creating network $LAB_NETWORK ($LAB_SUBNET)"
		local xml="$LAB_STATE_DIR/network.xml" vm
		{
			echo "<network>"
			echo "  <name>$LAB_NETWORK</name>"
			echo "  <forward mode='nat'/>"
			echo "  <bridge stp='on' delay='0'/>"
			echo "  <domain name='lab' localOnly='yes'/>"
			echo "  <dns>"
			for vm in "${LAB_VMS[@]}"; do
				echo "    <host ip='$(vm_ip "$vm")'><hostname>$vm.lab</hostname></host>"
			done
			echo "  </dns>"
			echo "  <ip address='$(lab_ip 1)' netmask='255.255.255.0'>"
			echo "    <dhcp>"
			echo "      <range start='$(lab_ip 200)' end='$(lab_ip 250)'/>"
			for vm in "${LAB_VMS[@]}"; do
				echo "      <host mac='$(vm_mac "$vm")' name='$vm' ip='$(vm_ip "$vm")'/>"
			done
			echo "    </dhcp>"
			echo "  </ip>"
			echo "</network>"
		} >"$xml"
		vsh net-define "$xml" >/dev/null
		vsh net-autostart "$LAB_NETWORK" >/dev/null
	fi
	[[ "$(vsh net-info "$LAB_NETWORK" | awk '/^Active:/ { print $2 }')" == yes ]] || vsh net-start "$LAB_NETWORK" >/dev/null
}

# --- VMs ----------------------------------------------------------------------

# seed_image VM: builds the cloud-init seed of VM and prints its path.
seed_image() {
	local vm="$1" dir="$LAB_STATE_DIR/seed/$1"
	mkdir -p "$dir"
	cat >"$dir/meta-data" <<META
instance-id: $vm-$(date +%s)
local-hostname: $vm
META
	cat >"$dir/user-data" <<USER
#cloud-config
hostname: $vm
fqdn: $vm.lab
manage_etc_hosts: true
ssh_pwauth: false
users:
  - name: $LAB_USER
    gecos: openstack-spiffe lab
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$(ssh_key).pub")
USER
	local iso="$dir/seed.iso"
	if have cloud-localds; then
		cloud-localds "$iso" "$dir/user-data" "$dir/meta-data"
	elif have xorriso; then
		xorriso -as genisoimage -quiet -output "$iso" -volid cidata -joliet -rock "$dir/user-data" "$dir/meta-data" 2>/dev/null
	else
		genisoimage -quiet -output "$iso" -volid cidata -joliet -rock "$dir/user-data" "$dir/meta-data"
	fi
	echo "$iso"
}

# vm_osinfo VM: the most precise OS name this host's libvirt knows for the
# VM's image (e.g. ubuntu24.04, almalinux10), or a recent generic Linux.
VM_OSINFO_KNOWN=""
vm_osinfo() {
	if [[ -z "$VM_OSINFO_KNOWN" ]]; then
		VM_OSINFO_KNOWN=" $(virt-install --osinfo list 2>/dev/null | tr ',' '\n' | tr -d ' ' | tr '\n' ' ') "
	fi
	local name
	case "$(vm_attr "$1" os):$LAB_RHEL_DISTRO" in
	ubuntu:*) name="ubuntu$LAB_UBUNTU_RELEASE" ;;
	rhel:alma) name="almalinux$LAB_RHEL_RELEASE" ;;
	rhel:rocky) name="rocky$LAB_RHEL_RELEASE" ;;
	esac
	for name in "$name" linux2024 linux2022; do
		if [[ "$VM_OSINFO_KNOWN" == *" $name "* ]]; then
			echo "$name"
			return
		fi
	done
	echo generic
}

# ensure_vm VM: creates and starts VM, or starts it if it is shut off.
ensure_vm() {
	local vm="$1" domain
	domain="$(vm_domain "$vm")"
	if vsh dominfo "$domain" >/dev/null 2>&1; then
		[[ "$(vsh domstate "$domain")" == running ]] || vsh start "$domain" >/dev/null
		local kib
		kib="$(vsh dominfo "$domain" | awk '/^Max memory:/ { print $3 }')"
		if ((kib != $(vm_attr "$vm" ram) * 1024 * 1024)); then
			info "warning: $vm has $((kib / 1024 / 1024)) GiB of memory, the settings say $(vm_attr "$vm" ram) GiB: sizes apply to new VMs only (lab.sh down && lab.sh up)"
		fi
		return
	fi
	info "creating VM $vm ($(vm_ip "$vm"))"
	local os disk seed
	os="$(vm_attr "$vm" os)"
	disk="$vm.qcow2" seed="$vm-seed.iso"
	vsh vol-delete --pool "$LAB_POOL" "$disk" >/dev/null 2>&1 || true
	vsh vol-delete --pool "$LAB_POOL" "$seed" >/dev/null 2>&1 || true
	vsh vol-create-as "$LAB_POOL" "$disk" "$(vm_attr "$vm" disk)G" --format qcow2 \
		--backing-vol "$(base_volume "$os")" --backing-vol-format qcow2 >/dev/null
	upload_volume "$seed" "$(seed_image "$vm")"
	virt-install --connect qemu:///system --name "$domain" \
		--memory $(($(vm_attr "$vm" ram) * 1024)) --vcpus "$(vm_attr "$vm" vcpus)" \
		--cpu host-passthrough --osinfo "$(vm_osinfo "$vm")" \
		--disk "vol=$LAB_POOL/$disk,bus=virtio" \
		--disk "vol=$LAB_POOL/$seed,device=cdrom" \
		--network "network=$LAB_NETWORK,mac=$(vm_mac "$vm"),model=virtio" \
		--import --graphics none --console pty,target_type=serial --noautoconsole >/dev/null
}

# wait_for_vm VM: waits until VM answers over SSH and cloud-init is done.
wait_for_vm() {
	local vm="$1" deadline=$((SECONDS + 900)) status
	until vm_ssh "$vm" true 2>/dev/null; do
		((SECONDS < deadline)) || die "$vm does not answer over SSH at $(vm_ip "$vm") (see: virsh console $(vm_domain "$vm"))"
		sleep 5
	done
	status=0
	vm_ssh "$vm" sudo cloud-init status --wait >/dev/null 2>&1 || status=$?
	case "$status" in
	0) info "$vm is up" ;;
	2) info "$vm is up (cloud-init reported recoverable errors: lab.sh logs $vm)" ;;
	*) die "cloud-init failed on $vm (lab.sh logs $vm)" ;;
	esac
}

# --- Teardown -----------------------------------------------------------------

destroy_all() {
	local vm domain volume
	for vm in "${LAB_VMS[@]}"; do
		domain="$(vm_domain "$vm")"
		vsh dominfo "$domain" >/dev/null 2>&1 || continue
		info "destroying VM $vm"
		vsh destroy "$domain" >/dev/null 2>&1 || true
		vsh undefine "$domain" --remove-all-storage >/dev/null 2>&1 || vsh undefine "$domain" >/dev/null
	done
	if vsh pool-info "$LAB_POOL" >/dev/null 2>&1; then
		info "destroying storage pool $LAB_POOL"
		vsh pool-start "$LAB_POOL" >/dev/null 2>&1 || true
		# plain rows (vsh is quiet), the name first: "vol-list --name" is
		# missing from older virsh
		while read -r volume _; do
			[[ -n "$volume" ]] && vsh vol-delete --pool "$LAB_POOL" "$volume" >/dev/null
		done < <(vsh vol-list "$LAB_POOL")
		vsh pool-destroy "$LAB_POOL" >/dev/null 2>&1 || true
		vsh pool-delete "$LAB_POOL" >/dev/null 2>&1 ||
			info "warning: $LAB_POOL_DIR could not be removed: remove it by hand (sudo rm -r $LAB_POOL_DIR)"
		vsh pool-undefine "$LAB_POOL" >/dev/null
	fi
	if vsh net-info "$LAB_NETWORK" >/dev/null 2>&1; then
		info "destroying network $LAB_NETWORK"
		vsh net-destroy "$LAB_NETWORK" >/dev/null 2>&1 || true
		vsh net-undefine "$LAB_NETWORK" >/dev/null
	fi
}
