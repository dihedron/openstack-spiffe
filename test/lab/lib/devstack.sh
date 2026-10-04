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
# every API behind DevStack's TLS proxy, with its own CA: the issuer only
# talks to Keystone and Nova over https
enable_service tls-proxy
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
# and by name and reads its vendordata, and reports what its console shows
# and what Nova logged about the openstack_iid target.
devstack_smoke() {
	info "smoke test: an instance reaching spire.lab and reading its vendordata"
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
curl -s -m 30 http://169.254.169.254/openstack/latest/vendor_data2.json >/dev/null; echo LAB-SMOKE-VENDORDATA-READ
DATA
openstack server delete --wait lab-smoke >/dev/null 2>&1 || true
since="$(date '+%Y-%m-%d %H:%M:%S')"
openstack server create --image "$image" --flavor m1.tiny --network private \
	--user-data /tmp/lab-smoke.sh --wait lab-smoke >/dev/null || { echo LAB-SMOKE-BOOT-FAIL; exit 0; }
for _ in $(seq 60); do
	log="$(openstack console log show lab-smoke 2>/dev/null)"
	if grep -q 'LAB-SMOKE-VENDORDATA-READ' <<<"$log"; then
		grep -o 'LAB-SMOKE-[A-Z]*-[A-Z]*' <<<"$log"
		break
	fi
	sleep 5
done
openstack server delete --wait lab-smoke >/dev/null 2>&1 || true
# what Nova made of the openstack_iid target
call="$(sudo journalctl -u devstack@n-api-meta --since "$since" -o cat 2>/dev/null |
	sed 's/\x1b\[[0-9;]*m//g' | grep -o 'dynamic vendordata service openstack_iid at .*' | tail -n1)"
echo "LAB-SMOKE-VENDORDATA-LOG ${call:-none}"
SCRIPT
)"
	case "$result" in
	*LAB-SMOKE-ADDRESS-OK*LAB-SMOKE-NAME-OK*) info "an instance reaches spire.lab by address and by name" ;;
	*LAB-SMOKE-ADDRESS-OK*) die "an instance reaches spire's address, but cannot resolve spire.lab" ;;
	*LAB-SMOKE-BOOT-FAIL*) die "the smoke test instance did not boot (lab.sh logs devstack devstack@n-cpu)" ;;
	*LAB-SMOKE-ADDRESS-FAIL*) die "an instance cannot reach spire at $(vm_ip spire)" ;;
	*) die "the smoke test instance reported nothing within 5 minutes" ;;
	esac
	smoke_vendordata "$(grep -o 'LAB-SMOKE-VENDORDATA-LOG .*' <<<"$result")"
}

# smoke_vendordata LOGLINE: interprets what Nova logged about its call to the
# openstack_iid target. Nova gets a Keystone token as the vendordata user
# before calling the target, so a failure to connect to the issuer means the
# credentials worked; an authentication failure means they did not.
smoke_vendordata() {
	local line="${1#LAB-SMOKE-VENDORDATA-LOG }"
	case "$line" in
	"" | none)
		if issuer_listening; then
			info "Nova reached the openstack_iid target (no error logged)"
		else
			die "Nova logged nothing about the openstack_iid target (lab.sh logs devstack devstack@n-api-meta)"
		fi
		;;
	*"Unable to establish connection to https://issuer-a.lab:8443/attest"*)
		info "Nova calls https://issuer-a.lab:8443/attest as $VENDORDATA_USER (no issuer is running yet)"
		;;
	*401* | *Unauthorized* | *authenticat*)
		die "Nova cannot authenticate as $VENDORDATA_USER: $line"
		;;
	*) die "unexpected error from Nova's openstack_iid call: $line" ;;
	esac
}

# issuer_listening: whether an issuer answers on issuer-a.lab:8443.
issuer_listening() {
	vm_ssh devstack "timeout 3 bash -c '</dev/tcp/issuer-a.lab/8443'" 2>/dev/null
}

# --- OpenStack configuration (chunk 3.5, step 3) --------------------------------

readonly VENDORDATA_USER=nova-vendordata
readonly ISSUER_USER=spire-issuer
readonly GUEST_FLAVOR=lab.guest
# DevStack's CA chain, which signs its TLS proxy's certificates
readonly DEVSTACK_CA=/opt/stack/data/CA/int-ca/ca-chain.pem

# devstack_openstack ARGS...: runs the openstack CLI on devstack as admin of
# the admin project (or as PROJECT with OS_LAB_PROJECT=PROJECT).
devstack_openstack() {
	local project="${OS_LAB_PROJECT:-admin}"
	vm_ssh devstack "cd /opt/stack && sudo -u stack bash -c $(printf '%q' "set +u; source $DEVSTACK_DIR/openrc admin $project >/dev/null 2>&1; set -u; openstack $(printf '%q ' "$@")")"
}

# user_password USER: the password the lab generated for a Keystone user.
user_password() {
	local file="$LAB_STATE_DIR/$1-password"
	[[ -f "$file" ]] || openssl rand -hex 16 >"$file"
	cat "$file"
}

vendordata_password() { user_password "$VENDORDATA_USER"; }

# devstack_keystone_url: Keystone's public endpoint, behind the TLS proxy.
devstack_keystone_url() { echo "https://$(vm_ip devstack)/identity/v3"; }

# devstack_service_user USER ROLE DESCRIPTION: a Keystone user with ROLE on
# the service project, and a password the lab generated; prints its ID.
devstack_service_user() {
	local id
	id="$(devstack_openstack user show --domain Default -f value -c id "$1" 2>/dev/null || true)"
	if [[ -z "$id" ]]; then
		info "creating the Keystone user $1" >&2
		id="$(devstack_openstack user create --domain Default --password "$(user_password "$1")" \
			--description "openstack-spiffe lab: $3" -f value -c id "$1")"
	fi
	devstack_openstack role add --user "$id" --project service --project-domain Default "$2"
	echo "$id"
}

# devstack_users: the dedicated user Nova authenticates to the issuers with
# (S-3), and the issuers' own service user, which validates Nova's tokens and
# reads projects and servers (admin on the service project, as the README
# prescribes).
devstack_users() {
	env_set .openstack.vendordata_user_id "$(devstack_service_user "$VENDORDATA_USER" service "Nova's vendordata calls to the issuers")"
	env_set .openstack.issuer_user_id "$(devstack_service_user "$ISSUER_USER" admin "the issuers' own Keystone and Nova calls")"
}

# devstack_ca: copies DevStack's CA chain into the lab's PKI directory, for
# the issuers to verify Keystone and Nova.
devstack_ca() {
	vm_ssh devstack "sudo cat $DEVSTACK_CA" >"$(pki_dir)/openstack-ca.pem"
}

# devstack_vendordata_config: registers the issuer as Nova's openstack_iid
# DynamicJSON target, called as the dedicated user and verified against the
# lab CA.
devstack_vendordata_config() {
	info "configuring Nova's DynamicJSON vendordata (openstack_iid at issuer-a.lab)"
	vm_ssh devstack "sudo tee /etc/nova/lab-ca.pem >/dev/null" <"$(pki_dir)/ca.pem"
	vm_ssh devstack "sudo bash -s -- $(printf '%q ' "$DEVSTACK_DIR" "$VENDORDATA_USER" "$(vendordata_password)" "$(vm_ip devstack)")" <<'SCRIPT'
set -euo pipefail
dir="$1" user="$2" password="$3" keystone="$4"
# shellcheck disable=SC1091
source "$dir/inc/ini-config"
conf=/etc/nova/nova.conf
iniset -sudo $conf api vendordata_providers StaticJSON,DynamicJSON
iniset -sudo $conf api vendordata_dynamic_targets openstack_iid@https://issuer-a.lab:8443/attest
iniset -sudo $conf api vendordata_dynamic_ssl_certfile /etc/nova/lab-ca.pem
iniset -sudo $conf api vendordata_dynamic_connect_timeout 5
iniset -sudo $conf api vendordata_dynamic_read_timeout 5
iniset -sudo $conf api vendordata_dynamic_failure_fatal False
iniset -sudo $conf vendordata_dynamic_auth auth_type password
iniset -sudo $conf vendordata_dynamic_auth auth_url "https://$keystone/identity/v3"
# Nova's Python stack has its own CA bundle, not the system's
iniset -sudo $conf vendordata_dynamic_auth cafile /opt/stack/data/CA/int-ca/ca-chain.pem
iniset -sudo $conf vendordata_dynamic_auth username "$user"
iniset -sudo $conf vendordata_dynamic_auth password "$password"
iniset -sudo $conf vendordata_dynamic_auth user_domain_name Default
iniset -sudo $conf vendordata_dynamic_auth project_name service
iniset -sudo $conf vendordata_dynamic_auth project_domain_name Default
systemctl restart devstack@n-api-meta.service
SCRIPT
}

# devstack_images: the guest images in Glance, from the download cache.
devstack_images() {
	local os name url sha path
	for os in ubuntu rhel; do
		name="lab-$(env_get ".images.$os | \"\(.distro)-\(.release)\"")"
		if devstack_openstack image show -f value -c id "$name" >/dev/null 2>&1; then
			env_set ".openstack.images.$os" "$name"
			continue
		fi
		url="$(env_get ".images.$os.url")"
		sha="$(env_get ".images.$os.sha256")"
		path="$(fetch "$url" "$sha")"
		info "uploading the $name image to Glance"
		scp -q "${SSH_OPTS[@]}" "$path" "$LAB_USER@$(vm_ip devstack):/tmp/$name.qcow2"
		devstack_openstack image create --public --disk-format qcow2 --container-format bare \
			--property "lab_sha256=$sha" --file "/tmp/$name.qcow2" "$name" >/dev/null
		vm_ssh devstack "rm -f /tmp/$name.qcow2"
		env_set ".openstack.images.$os" "$name"
	done
}

# devstack_guest_access: the flavor of the guests, and the lab's SSH key and
# SSH and ICMP access in the demo project, where the tests boot them.
devstack_guest_access() {
	devstack_openstack flavor show "$GUEST_FLAVOR" >/dev/null 2>&1 ||
		devstack_openstack flavor create --public --vcpus 2 --ram 2048 --disk 20 "$GUEST_FLAVOR" >/dev/null
	env_set .openstack.flavor "$GUEST_FLAVOR"
	OS_LAB_PROJECT=demo devstack_openstack keypair show lab >/dev/null 2>&1 || {
		scp -q "${SSH_OPTS[@]}" "$(ssh_key).pub" "$LAB_USER@$(vm_ip devstack):/tmp/lab.pub"
		OS_LAB_PROJECT=demo devstack_openstack keypair create --public-key /tmp/lab.pub lab >/dev/null
	}
	env_set .openstack.keypair lab
	env_set .openstack.project demo
	local project group rule output
	project="$(devstack_openstack project show demo -f value -c id)"
	env_set .openstack.project_id "$project"
	# by ID: several groups named "default" are visible to demo
	group="$(devstack_openstack security group list --project "$project" -f value -c ID -c Name | awk '$2 == "default" { print $1 }')"
	[[ -n "$group" ]] || die "the demo project has no default security group"
	for rule in "--protocol icmp" "--protocol tcp --dst-port 22"; do
		# shellcheck disable=SC2086 # rule is a word list
		output="$(devstack_openstack security group rule create --ingress $rule "$group" 2>&1)" ||
			[[ "$output" == *"already exists"* || "$output" == *Conflict* ]] ||
			die "cannot open the demo project's default security group: $output"
	done
}

# devstack_configure: everything step 3 adds to DevStack.
devstack_configure() {
	devstack_users
	devstack_ca
	devstack_vendordata_config
	devstack_images
	devstack_guest_access
}
