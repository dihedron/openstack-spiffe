# shellcheck shell=bash
# The preflight check: whether this machine can run the lab, installing the
# missing software after confirmation. See "Preflight" in
# .specs/openstack-spire-test-environment.md.

# minimum versions of the tools whose version matters
readonly PF_MIN_GO_AUTO_TOOLCHAIN="1.21"
readonly PF_MIN_GORELEASER="2.0.0"
# headroom left to the lab host, in GiB
readonly PF_HOST_RAM_GIB=4
readonly PF_RAM_MARGIN_GIB=4
# disks are thin-provisioned: expected use at the end of "up", plus margin
readonly PF_DISK_USE_PERCENT=40
readonly PF_DISK_MARGIN_PERCENT=20
readonly PF_CACHE_GIB=10

PF_OK=0 PF_WARN=0 PF_FAIL=0 PF_FAIL_SOFTWARE=0
PF_NO_INSTALL=""
PF_FAMILY=""   # apt, dnf, or empty when unsupported
PF_PACKAGES=() # packages to install with the host's package manager
PF_ACTIONS=()  # descriptions of every installation step, for the prompt
PF_INSTALL_GO=""
PF_INSTALL_GORELEASER=""
PF_START_LIBVIRT=""

pf_ok() {
	PF_OK=$((PF_OK + 1))
	printf '  %sok%s    %s\n' "$_green" "$_reset" "$*"
}
pf_warn() {
	PF_WARN=$((PF_WARN + 1))
	printf '  %swarn%s  %s\n' "$_yellow" "$_reset" "$*"
}
pf_fail() {
	PF_FAIL=$((PF_FAIL + 1))
	printf '  %sfail%s  %s\n' "$_red" "$_reset" "$*"
}

# confirm QUESTION: yes with LAB_ASSUME_YES, no without a terminal.
confirm() {
	[[ -n "$LAB_ASSUME_YES" ]] && return 0
	[[ -r /dev/tty ]] || return 1
	local answer
	read -r -p "$1 [y/N] " answer </dev/tty || return 1
	[[ "$answer" == [yY]* ]]
}

# --- Operating system ---------------------------------------------------------

pf_os() {
	section "Operating system"
	if [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]; then
		pf_ok "Linux on x86-64"
	else
		pf_fail "$(uname -s) on $(uname -m): the lab needs Linux on x86-64"
	fi
	if ((EUID == 0)); then
		pf_fail "running as root: run the lab as a regular user (it uses sudo only to install software)"
	fi

	local id="" like="" pretty="unknown distribution"
	if [[ -r /etc/os-release ]]; then
		# shellcheck disable=SC1091
		id="$(. /etc/os-release && echo "${ID:-}")"
		# shellcheck disable=SC1091
		like="$(. /etc/os-release && echo "${ID_LIKE:-}")"
		# shellcheck disable=SC1091
		pretty="$(. /etc/os-release && echo "${PRETTY_NAME:-$id}")"
	fi
	case " $id $like " in
	*" debian "* | *" ubuntu "*) PF_FAMILY=apt ;;
	*" fedora "* | *" rhel "* | *" centos "*) PF_FAMILY=dnf ;;
	esac
	if [[ -n "$PF_FAMILY" ]]; then
		pf_ok "$pretty (packages with $PF_FAMILY)"
	elif [[ -n "$PF_NO_INSTALL" ]]; then
		pf_warn "$pretty: not a supported family (Debian/Ubuntu, Fedora/RHEL-like); missing software is only reported"
	else
		pf_fail "$pretty: not a supported family (Debian/Ubuntu, Fedora/RHEL-like); install the missing software by hand and use --no-install"
	fi

	if [[ -d /run/systemd/system ]]; then
		pf_ok "systemd is running"
	else
		pf_fail "systemd is not running: libvirt's services are managed through it"
	fi
}

# --- Virtualization -----------------------------------------------------------

pf_cpu_flags() {
	awk -F: '/^flags/ { print " " $2 " "; exit }' /proc/cpuinfo
}

pf_virtualization() {
	section "Virtualization"
	local flags vendor=""
	flags="$(pf_cpu_flags)"
	case "$flags" in
	*" vmx "*) vendor=intel ;;
	*" svm "*) vendor=amd ;;
	esac
	if [[ -n "$vendor" ]]; then
		pf_ok "hardware virtualization (${vendor^^})"
	else
		pf_fail "no hardware virtualization (vmx/svm): enable VT-x or AMD-V in the firmware"
	fi

	if [[ -c /dev/kvm ]]; then
		pf_ok "/dev/kvm is present"
	else
		pf_fail "/dev/kvm is missing: load the kvm_intel or kvm_amd module"
	fi

	if [[ -n "$vendor" ]]; then
		local module="kvm_$vendor" nested=""
		nested="$(cat "/sys/module/$module/parameters/nested" 2>/dev/null || true)"
		case "$nested" in
		Y | y | 1) pf_ok "nested virtualization is enabled ($module)" ;;
		*)
			pf_fail "nested virtualization is disabled: Nova runs its instances in KVM inside the devstack VM"
			info "enable it persistently, with no VM running:"
			info "  echo 'options $module nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf"
			info "  sudo modprobe -r $module && sudo modprobe $module"
			;;
		esac
	fi

	local flag missing=()
	for flag in avx avx2 bmi1 bmi2 f16c fma abm movbe xsave; do
		[[ "$flags" == *" $flag "* ]] || missing+=("$flag")
	done
	# RHEL 10 derivatives need x86-64-v3; the lab's own packages are the
	# baseline (v1) ones, which run on any x86-64 CPU
	if ((${#missing[@]} == 0)); then
		pf_ok "x86-64-v3 CPU (RHEL 10 derivatives need it)"
	elif ((LAB_RHEL_RELEASE >= 10)); then
		pf_fail "the CPU is not x86-64-v3 (missing ${missing[*]}): $LAB_RHEL_DISTRO $LAB_RHEL_RELEASE cannot run; set LAB_RHEL_RELEASE=9"
	else
		pf_ok "x86-64-v3 not needed for $LAB_RHEL_DISTRO $LAB_RHEL_RELEASE"
	fi
}

# --- Resources ----------------------------------------------------------------

# existing_ancestor PATH: PATH, or its closest existing parent.
existing_ancestor() {
	local path="$1"
	while [[ ! -e "$path" ]]; do
		path="$(dirname "$path")"
	done
	echo "$path"
}

# free_gib PATH: free space, in GiB, of the file system holding PATH.
free_gib() {
	df -P -B1G "$(existing_ancestor "$1")" | awk 'NR == 2 { print $4 }'
}

pf_resources() {
	section "Resources"
	local vcpus ram disk cpus
	vcpus=$((LAB_DEVSTACK_VCPUS + 2 * LAB_ISSUER_VCPUS + LAB_SPIRE_VCPUS))
	ram=$((LAB_DEVSTACK_RAM_GIB + 2 * LAB_ISSUER_RAM_GIB + LAB_SPIRE_RAM_GIB))
	disk=$((LAB_DEVSTACK_DISK_GIB + 2 * LAB_ISSUER_DISK_GIB + LAB_SPIRE_DISK_GIB))
	cpus="$(nproc)"

	# overcommit in tenths: 15 is 1.5 vCPUs per logical CPU
	local ratio=$((vcpus * 10 / cpus))
	if ((ratio > 30)); then
		pf_fail "$vcpus vCPUs on $cpus logical CPUs: more than 3 per CPU; reduce the LAB_*_VCPUS settings"
	elif ((ratio > 15)); then
		pf_warn "$vcpus vCPUs on $cpus logical CPUs: more than 1.5 per CPU, the lab will be slow"
	else
		pf_ok "$vcpus vCPUs on $cpus logical CPUs"
	fi

	# the lab's VMs already running hold their memory (as libvirt reports
	# it, whatever the settings say now): only the others still need it
	local available need running=0 vm kib
	for vm in devstack issuer-a issuer-b spire; do
		if have virsh && [[ "$(virsh -q -c qemu:///system domstate "$LAB_NETWORK-$vm" 2>/dev/null)" == running ]]; then
			kib="$(virsh -q -c qemu:///system dominfo "$LAB_NETWORK-$vm" | awk '/^Max memory:/ { print $3 }')"
			running=$((running + ${kib:-0} / 1024 / 1024))
		fi
	done
	available=$(($(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo) / 1024 / 1024))
	need=$((ram - running + PF_HOST_RAM_GIB))
	local detail="${ram} for the VMs"
	((running == 0)) || detail="${ram} for the VMs, ${running} of them already in use by the running lab"
	if ((available < need)); then
		pf_fail "${available} GiB of memory available, the lab needs ${need} GiB more (${detail}, ${PF_HOST_RAM_GIB} for the host)"
	elif ((available < need + PF_RAM_MARGIN_GIB)); then
		pf_warn "${available} GiB of memory available for ${need} GiB needed (${detail}): little margin"
	else
		pf_ok "${available} GiB of memory available, ${need} GiB needed (${detail})"
	fi

	# the VMs' disks, plus their memory, which the snapshots save; what the
	# lab's pool already holds is used, not needed
	local disk_need held=0
	disk_need=$(((disk * PF_DISK_USE_PERCENT / 100 + ram) * (100 + PF_DISK_MARGIN_PERCENT) / 100))
	if have virsh && virsh -q -c qemu:///system pool-info "$LAB_POOL" >/dev/null 2>&1; then
		# the sum of its volumes: a directory pool's own allocation is the
		# whole file system's
		local volume bytes
		while read -r volume _; do
			[[ -n "$volume" ]] || continue
			bytes="$(virsh -q -c qemu:///system vol-info --bytes --pool "$LAB_POOL" "$volume" | awk '/^Allocation:/ { print $2 }')"
			held=$((held + ${bytes:-0}))
		done < <(virsh -q -c qemu:///system vol-list "$LAB_POOL")
		held=$((held / 1024 / 1024 / 1024))
	fi
	disk_need=$((disk_need > held ? disk_need - held : 0))
	pf_space "VM disks and snapshots" "$LAB_POOL_DIR" "$disk_need"
	pf_space "download cache" "$LAB_CACHE_DIR" "$PF_CACHE_GIB"
}

# pf_space WHAT PATH GIB
pf_space() {
	local free
	free="$(free_gib "$2")"
	if ((free < $3)); then
		pf_fail "$1: ${free} GiB free under $(existing_ancestor "$2"), ${3} GiB needed"
	elif ((free < $3 * 120 / 100)); then
		pf_warn "$1: ${free} GiB free under $(existing_ancestor "$2") for ${3} GiB needed: little margin"
	else
		pf_ok "$1: ${free} GiB free under $(existing_ancestor "$2"), ${3} GiB needed"
	fi
}

# --- Software -----------------------------------------------------------------

# pf_need DESCRIPTION APT_PACKAGE DNF_PACKAGE: records a missing tool.
pf_need() {
	local package=""
	case "$PF_FAMILY" in
	apt) package="$2" ;;
	dnf) package="$3" ;;
	esac
	if [[ -n "$package" && -z "$PF_NO_INSTALL" ]]; then
		pf_warn "$1 is missing: will install $package"
		[[ " ${PF_PACKAGES[*]} " == *" $package "* ]] || PF_PACKAGES+=("$package")
	else
		pf_fail "$1 is missing${package:+ (package $package)}"
	fi
}

# pf_tool COMMAND APT_PACKAGE DNF_PACKAGE
pf_tool() {
	if have "$1"; then
		pf_ok "$1"
	else
		pf_need "$1" "$2" "$3"
	fi
}

pf_libvirt_active() {
	local unit
	for unit in libvirtd.service libvirtd.socket virtqemud.service virtqemud.socket; do
		systemctl is-active --quiet "$unit" 2>/dev/null && return 0
	done
	return 1
}

pf_software() {
	section "Software"
	PF_PACKAGES=() PF_INSTALL_GO="" PF_INSTALL_GORELEASER="" PF_START_LIBVIRT=""

	pf_tool virsh libvirt-clients libvirt-client
	pf_tool virt-install virtinst virt-install
	pf_tool qemu-img qemu-utils qemu-img
	if have qemu-system-x86_64 || [[ -x /usr/libexec/qemu-kvm ]]; then
		pf_ok "QEMU with KVM"
	else
		pf_need "QEMU with KVM" qemu-system-x86 qemu-kvm
	fi
	if [[ -e /usr/sbin/libvirtd || -e /usr/sbin/virtqemud ]]; then
		if pf_libvirt_active; then
			pf_ok "libvirt daemon is running"
		elif [[ -z "$PF_NO_INSTALL" ]]; then
			pf_warn "libvirt daemon is not running: will enable and start it"
			PF_START_LIBVIRT=1
		else
			pf_fail "libvirt daemon is not running"
		fi
	else
		pf_need "libvirt daemon" libvirt-daemon-system libvirt-daemon-kvm
		PF_START_LIBVIRT=1
	fi
	if have cloud-localds || have xorriso || have genisoimage; then
		pf_ok "cloud-init seed image tool"
	else
		pf_need "cloud-init seed image tool (cloud-localds or xorriso)" cloud-image-utils xorriso
	fi
	pf_tool ssh openssh-client openssh-clients
	pf_tool ssh-keygen openssh-client openssh-clients
	pf_tool openssl openssl openssl
	pf_tool gpg gnupg gnupg2
	pf_tool curl curl curl
	pf_tool jq jq jq
	pf_tool git git git
	pf_tool make make make
	pf_tool python3 python3 python3
	pf_tool ip iproute2 iproute

	pf_go
	pf_goreleaser
}

pf_go() {
	local required version="" toolchain
	required="$(go_mod_version)"
	if have go; then
		version="$(go env GOVERSION 2>/dev/null)"
		toolchain="$(go env GOTOOLCHAIN 2>/dev/null)"
	fi
	if [[ -n "$version" ]] && version_ge "$version" "$required"; then
		pf_ok "Go ${version#go} (go.mod requires $required)"
	elif [[ -n "$version" ]] && version_ge "$version" "$PF_MIN_GO_AUTO_TOOLCHAIN" && [[ "$toolchain" != local* ]]; then
		pf_ok "Go ${version#go}: it downloads the go$required toolchain go.mod requires (GOTOOLCHAIN=$toolchain)"
	elif [[ -z "$PF_NO_INSTALL" ]]; then
		pf_warn "Go ${version:-is missing}${version:+ is older than $required}: will install go$required under $LAB_TOOLS_DIR"
		PF_INSTALL_GO=1
	else
		pf_fail "Go ${version:-is missing}${version:+ is older than $required}"
	fi
}

pf_goreleaser() {
	local version=""
	if have goreleaser; then
		version="$(goreleaser --version 2>/dev/null | awk '/GitVersion:/ { print $2 }')"
	fi
	if [[ -n "$version" ]] && version_ge "$version" "$PF_MIN_GORELEASER"; then
		pf_ok "goreleaser $version"
	elif [[ -z "$PF_NO_INSTALL" ]]; then
		pf_warn "goreleaser ${version:-is missing}${version:+ is older than $PF_MIN_GORELEASER}: will install the latest v2 under $LAB_TOOLS_DIR"
		PF_INSTALL_GORELEASER=1
	else
		pf_fail "goreleaser ${version:-is missing}${version:+ is older than $PF_MIN_GORELEASER}"
	fi
}

# pf_install: installs what pf_software found missing, after confirmation.
pf_install() {
	PF_ACTIONS=()
	if ((${#PF_PACKAGES[@]} > 0)); then
		case "$PF_FAMILY" in
		apt) PF_ACTIONS+=("sudo apt-get install -y ${PF_PACKAGES[*]}") ;;
		dnf) PF_ACTIONS+=("sudo dnf install -y ${PF_PACKAGES[*]}") ;;
		esac
	fi
	[[ -n "$PF_START_LIBVIRT" ]] && PF_ACTIONS+=("sudo systemctl enable --now libvirtd (or virtqemud on modular libvirt)")
	[[ -n "$PF_INSTALL_GO" ]] && PF_ACTIONS+=("download go$(go_mod_version) from go.dev, verify its SHA-256 and unpack it under $LAB_TOOLS_DIR")
	[[ -n "$PF_INSTALL_GORELEASER" ]] && PF_ACTIONS+=("go install github.com/goreleaser/goreleaser/v2@latest into $LAB_TOOLS_DIR/bin (verified by the Go checksum database)")
	((${#PF_ACTIONS[@]} > 0)) || return 0

	section "Installation"
	local action
	for action in "${PF_ACTIONS[@]}"; do
		info "$action"
	done
	if ! confirm "Install now?"; then
		info "nothing installed"
		return 1
	fi
	pf_install_steps || info "some steps failed: the checks below show what is still missing"
}

# pf_install_steps: attempts every installation step, failing if any failed.
pf_install_steps() {

	# every step is attempted; the checks that follow report what is still missing
	local failed=""
	if ((${#PF_PACKAGES[@]} > 0)); then
		case "$PF_FAMILY" in
		apt) sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${PF_PACKAGES[@]}" ;;
		dnf) sudo dnf install -y "${PF_PACKAGES[@]}" ;;
		esac || failed=1
	fi
	if [[ -n "$PF_INSTALL_GO" ]]; then
		pf_install_go || failed=1
	fi
	if [[ -n "$PF_INSTALL_GORELEASER" ]]; then
		mkdir -p "$LAB_TOOLS_DIR/bin"
		GOBIN="$LAB_TOOLS_DIR/bin" go install github.com/goreleaser/goreleaser/v2@latest || failed=1
	fi
	if [[ -n "$PF_START_LIBVIRT" ]]; then
		if systemctl list-unit-files libvirtd.service >/dev/null 2>&1; then
			sudo systemctl enable --now libvirtd.service
		else
			sudo systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket
		fi || failed=1
	fi
	[[ -z "$failed" ]]
}

# pf_install_go: the latest go<go.mod version>.x release, from go.dev.
pf_install_go() {
	local required release file sha
	required="$(go_mod_version)"
	release="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' |
		jq -r --arg v "go$required" '[.[] | select(.stable and (.version == $v or (.version | startswith($v + "."))))][0]')" || return 1
	file="$(jq -r '.files[] | select(.os == "linux" and .arch == "amd64" and .kind == "archive") | .filename' <<<"$release")"
	sha="$(jq -r '.files[] | select(.os == "linux" and .arch == "amd64" and .kind == "archive") | .sha256' <<<"$release")"
	[[ -n "$file" && "$file" != null ]] || {
		info "no Go release matches go$required"
		return 1
	}
	mkdir -p "$LAB_CACHE_DIR" "$LAB_TOOLS_DIR"
	curl -fsSL -o "$LAB_CACHE_DIR/$file" "https://go.dev/dl/$file" || return 1
	echo "$sha  $LAB_CACHE_DIR/$file" | sha256sum -c --quiet || return 1
	rm -rf "$LAB_TOOLS_DIR/go"
	tar -C "$LAB_TOOLS_DIR" -xzf "$LAB_CACHE_DIR/$file"
}

# --- Permissions --------------------------------------------------------------

pf_permissions() {
	section "Permissions"
	if ! have virsh; then
		pf_fail "cannot check access to libvirt: virsh is missing"
	elif virsh -c qemu:///system list --all >/dev/null 2>&1; then
		pf_ok "$USER can manage qemu:///system"
	elif id -nG "$USER" | tr ' ' '\n' | grep -qx libvirt; then
		pf_fail "$USER is in the libvirt group, but not in this session: log in again (or run 'newgrp libvirt')"
	elif [[ -z "$PF_NO_INSTALL" ]] && getent group libvirt >/dev/null && confirm "Add $USER to the libvirt group (sudo usermod -aG libvirt $USER)?"; then
		sudo usermod -aG libvirt "$USER"
		pf_fail "$USER added to the libvirt group: log in again, then rerun the preflight"
	else
		pf_fail "$USER cannot manage qemu:///system: add $USER to the libvirt group (sudo usermod -aG libvirt $USER) and log in again"
	fi

	if ((PF_FAIL_SOFTWARE > 0)) && ! have sudo; then
		pf_fail "sudo is missing: it is needed to install the missing software"
	elif have sudo; then
		pf_ok "sudo is available (used only to install software)"
	fi
}

# --- Network ------------------------------------------------------------------

pf_network() {
	section "Network"
	if [[ ! "$LAB_SUBNET" =~ ^([0-9]{1,3}\.){3}0/24$ ]]; then
		pf_fail "LAB_SUBNET=$LAB_SUBNET: it must be an IPv4 /24 network (A.B.C.0/24)"
		return
	fi

	local own_bridge="" own_subnet=""
	if have virsh && virsh -c qemu:///system net-info "$LAB_NETWORK" >/dev/null 2>&1; then
		own_bridge="$(virsh -c qemu:///system net-info "$LAB_NETWORK" | awk '/^Bridge:/ { print $2 }')"
		own_subnet="$(pf_libvirt_subnet "$LAB_NETWORK")"
		if [[ "$own_subnet" == "$LAB_SUBNET" ]]; then
			pf_ok "libvirt network $LAB_NETWORK exists with $LAB_SUBNET (the lab's own)"
		else
			pf_fail "libvirt network $LAB_NETWORK exists with ${own_subnet:-no IPv4 subnet}, not $LAB_SUBNET: remove it or change LAB_NETWORK"
		fi
	fi

	local conflicts=() dest dev
	if ! have ip; then
		pf_fail "cannot check the routes for overlaps with LAB_SUBNET: ip is missing"
	else
		while read -r dest dev; do
			[[ "$dest" == default || -z "$dest" ]] && continue
			[[ -n "$own_bridge" && "$dev" == "$own_bridge" ]] && continue
			cidr_overlap "$dest" "$LAB_SUBNET" && conflicts+=("route $dest ($dev)")
		done < <(ip -4 -o route show | awk '{ for (i = 2; i < NF; i++) if ($i == "dev") { print $1, $(i + 1); next } print $1, "" }')
	fi
	if have virsh; then
		local name subnet
		while read -r name; do
			[[ -z "$name" || "$name" == "$LAB_NETWORK" ]] && continue
			subnet="$(pf_libvirt_subnet "$name")"
			[[ -n "$subnet" ]] && cidr_overlap "$subnet" "$LAB_SUBNET" && conflicts+=("libvirt network $name ($subnet)")
		done < <(virsh -c qemu:///system net-list --all --name 2>/dev/null)
	fi
	if ((${#conflicts[@]} > 0)); then
		local joined
		joined="$(printf '%s, ' "${conflicts[@]}")"
		pf_fail "LAB_SUBNET=$LAB_SUBNET overlaps ${joined%, }: change LAB_SUBNET"
	else
		pf_ok "LAB_SUBNET=$LAB_SUBNET overlaps no route or libvirt network"
	fi

	if ! have curl; then
		pf_fail "cannot check the download endpoints: curl is missing"
		return
	fi
	pf_endpoint "DevStack repository" "https://opendev.org/openstack/devstack"
	pf_endpoint "Ubuntu $LAB_UBUNTU_RELEASE image" "$(ubuntu_image_url)"
	pf_endpoint "$LAB_RHEL_DISTRO $LAB_RHEL_RELEASE image" "$(rhel_image_url)"
	pf_endpoint "SPIRE releases" "https://api.github.com/repos/spiffe/spire/releases?per_page=1"
	pf_endpoint "Python package index" "https://pypi.org/simple/pip/"
	pf_endpoint "Go module proxy" "https://proxy.golang.org/"
}

# pf_libvirt_subnet NETWORK: its IPv4 subnet as A.B.C.D/N, if any.
pf_libvirt_subnet() {
	local xml address mask prefix
	xml="$(virsh -c qemu:///system net-dumpxml "$1" 2>/dev/null)" || return 0
	address="$(grep -oP "<ip [^>]*address='\K[0-9.]+" <<<"$xml" | head -n1)"
	[[ -n "$address" ]] || return 0
	prefix="$(grep -oP "<ip [^>]*prefix='\K[0-9]+" <<<"$xml" | head -n1)"
	if [[ -z "$prefix" ]]; then
		mask="$(grep -oP "<ip [^>]*netmask='\K[0-9.]+" <<<"$xml" | head -n1)"
		prefix="$(netmask_bits "${mask:-255.255.255.0}")"
	fi
	local start
	read -r start _ <<<"$(cidr_range "$address/$prefix")"
	printf '%d.%d.%d.%d/%d\n' $((start >> 24 & 255)) $((start >> 16 & 255)) $((start >> 8 & 255)) $((start & 255)) "$prefix"
}

# pf_endpoint NAME URL: whether the first byte of URL can be fetched.
pf_endpoint() {
	local code
	code="$(curl -sS -L -r 0-0 -o /dev/null --max-time 20 -w '%{http_code}' "$2" 2>/dev/null)" || code="${code:-000}"
	case "$code" in
	200 | 206) pf_ok "reachable: $1" ;;
	*) pf_fail "not reachable (HTTP $code): $1, $2" ;;
	esac
}

# --- Entry point --------------------------------------------------------------

# run_preflight [--no-install]: returns non-zero on any failed check.
run_preflight() {
	case "${1:-}" in
	--no-install) PF_NO_INSTALL=1 ;;
	"") ;;
	*) die "preflight: unknown option $1" ;;
	esac

	pf_os
	pf_virtualization
	pf_resources

	local fail_before=$PF_FAIL ok_before=$PF_OK warn_before=$PF_WARN
	pf_software
	PF_FAIL_SOFTWARE=$((PF_FAIL - fail_before))
	if [[ -z "$PF_NO_INSTALL" ]] && { ((${#PF_PACKAGES[@]} > 0)) || [[ -n "$PF_START_LIBVIRT$PF_INSTALL_GO$PF_INSTALL_GORELEASER" ]]; }; then
		if pf_install; then
			# check again, replacing the first results: whatever is still
			# missing after an installation attempt is a failure
			PF_OK=$ok_before PF_WARN=$warn_before PF_FAIL=$fail_before
			PF_NO_INSTALL=1 pf_software
			PF_FAIL_SOFTWARE=$((PF_FAIL - fail_before))
		else
			PF_FAIL_SOFTWARE=$((PF_FAIL_SOFTWARE + 1))
			pf_fail "the missing software was not installed"
		fi
	fi

	pf_permissions
	pf_network

	section "Summary"
	info "$PF_OK ok, $PF_WARN warnings, $PF_FAIL failures"
	if ((PF_FAIL > 0)); then
		info "the lab cannot run on this machine until the failures above are fixed"
		return 1
	fi
	info "this machine can run the lab"
}
