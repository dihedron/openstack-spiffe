# shellcheck shell=bash
# deploy: builds the packages on the lab host, as a release would, and
# installs and configures them on the VMs, as an operator would. Nothing is
# compiled in the VMs.

readonly ISSUER_ETC=/etc/openstack-spire-issuer
readonly ISSUER_SERVICE=openstack-spire-issuer

# deploy_build: builds every package with goreleaser (make snapshot), signed
# with the lab packaging key as a release is (T-7), and verifies the signed
# checksums file as an operator would.
deploy_build() {
	pki_packaging_key
	info "building the packages (make snapshot, signed with the lab packaging key)"
	GNUPGHOME="$(pki_dir)/gnupg" GPG_FINGERPRINT="$(packaging_fingerprint)" GPG_KEY_FILE="$(pki_dir)/packaging-key.asc" \
		make -C "$REPO_DIR" snapshot >"$LAB_STATE_DIR/build.log" 2>&1 ||
		die "the build failed: see $LAB_STATE_DIR/build.log"
	verify_checksums
}

# verify_checksums: the checksums file's signature, against the lab packaging
# key only, then every artifact against the checksums file.
verify_checksums() {
	local checksums=("$REPO_DIR"/dist/*_checksums.txt) keyring
	[[ ${#checksums[@]} -eq 1 && -f "${checksums[0]}.asc" ]] || die "no signed checksums file in dist/"
	keyring="$(pki_dir)/packaging-key.gpg"
	gpg --dearmor <"$(pki_dir)/packaging-key.pub.asc" >"$keyring"
	gpgv --keyring "$keyring" "${checksums[0]}.asc" "${checksums[0]}" 2>/dev/null ||
		die "the signature of ${checksums[0]##*/} does not verify"
	(cd "$REPO_DIR/dist" && sha256sum --check --quiet --strict "${checksums[0]##*/}") ||
		die "dist/ does not match ${checksums[0]##*/}"
	info "verified the signed ${checksums[0]##*/}"
}

# trust_packaging_key VM FORMAT: makes VM's package tools verify packages
# signed with the lab packaging key: debsig-verify's policy and keyring for
# deb, rpm's keyring for rpm. Idempotent.
trust_packaging_key() {
	local vm="$1" format="$2" fpr
	fpr="$(packaging_fingerprint)"
	put "$vm" "$(pki_dir)/packaging-key.pub.asc" /tmp/packaging-key.asc root:root 0644
	vm_ssh "$vm" "sudo bash -s -- $format ${fpr: -16}" <<'SCRIPT'
set -euo pipefail
format="$1" keyid="$2"
if [[ "$format" == rpm ]]; then
	rpm --import /tmp/packaging-key.asc
else
	command -v debsig-verify >/dev/null ||
		{ apt-get update -qq && DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 apt-get install -y -qq debsig-verify >/dev/null 2>&1; }
	mkdir -p "/usr/share/debsig/keyrings/$keyid" "/etc/debsig/policies/$keyid"
	gpg --dearmor </tmp/packaging-key.asc >"/usr/share/debsig/keyrings/$keyid/debsig.gpg"
	cat >"/etc/debsig/policies/$keyid/openstack-spiffe.pol" <<POLICY
<?xml version="1.0"?>
<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
<Policy xmlns="https://www.debian.org/debsig/1.0/">
  <Origin Name="openstack-spiffe" id="$keyid" Description="openstack-spiffe lab packages"/>
  <Selection>
    <Required Type="origin" File="debsig.gpg" id="$keyid"/>
  </Selection>
  <Verification MinOptional="0">
    <Required Type="origin" File="debsig.gpg" id="$keyid"/>
  </Verification>
</Policy>
POLICY
fi
rm -f /tmp/packaging-key.asc
SCRIPT
}

# verify_package VM FILE: checks the signature of a package already copied
# to VM, with the tool an operator uses (T-7).
verify_package() {
	local vm="$1" remote="$2"
	case "$remote" in
	*.deb) vm_ssh "$vm" "debsig-verify --quiet $remote" ;;
	*.rpm) vm_ssh "$vm" "rpm --checksig $remote | grep -q 'signatures OK'" ;;
	esac || die "the signature of ${remote##*/} does not verify on $vm"
}

# package PACKAGE FORMAT: the baseline amd64 build of PACKAGE (deb or rpm) in
# dist/, which runs on any x86-64 CPU.
package() {
	local found=("$REPO_DIR"/dist/"$1"_*_linux_amd64."$2")
	[[ ${#found[@]} -eq 1 && -f "${found[0]}" ]] || die "expected one $1 baseline $2 in dist/, found ${#found[@]}"
	echo "${found[0]}"
}

# install_package VM FILE BINARY: verifies the signature of a local package
# on VM, installs, upgrades, reinstalls or downgrades it, then checks that /usr/bin/BINARY on VM is the
# one goreleaser built. Snapshot versions carry the commit hash, which is not
# ordered: a newer build can look older to the package manager.
install_package() {
	local vm="$1" file="$2" binary="$3" remote="/tmp/${2##*/}"
	trust_packaging_key "$vm" "${file##*.}"
	scp -q "${SSH_OPTS[@]}" "$file" "$LAB_USER@$(vm_ip "$vm"):$remote"
	verify_package "$vm" "$remote"
	case "$remote" in
	*.deb) vm_ssh "$vm" "sudo dpkg -i $remote >/dev/null 2>&1 && rm -f $remote" ;;
	*.rpm) vm_ssh "$vm" "sudo rpm -U --replacepkgs --oldpackage --quiet $remote && rm -f $remote" ;;
	esac || die "cannot install ${file##*/} on $vm"
	local built installed
	built="$(sha256sum "$REPO_DIR/dist/${binary}_linux_amd64_v1/$binary" | awk '{ print $1 }')"
	installed="$(vm_ssh "$vm" "sha256sum /usr/bin/$binary" | awk '{ print $1 }')"
	[[ "$built" == "$installed" ]] || die "/usr/bin/$binary on $vm is not the binary just built: the package manager kept another version"
}

# put VM FILE PATH OWNER MODE: writes the local FILE (- for standard input)
# to PATH on VM.
put() {
	local vm="$1" file="$2" path="$3" owner="$4" mode="$5"
	if [[ "$file" == - ]]; then
		vm_ssh "$vm" "sudo install -o ${owner%:*} -g ${owner#*:} -m $mode /dev/stdin $path"
	else
		vm_ssh "$vm" "sudo install -o ${owner%:*} -g ${owner#*:} -m $mode /dev/stdin $path" <"$file"
	fi
}

# issuer_config VM: the signer configuration of an issuer replica.
issuer_config() {
	local vm="$1" peer
	[[ "$vm" == issuer-a ]] && peer=issuer-b || peer=issuer-a
	cat <<YAML
# written by the lab's deploy (test/lab/lib/deploy.sh)
listen_addr: "0.0.0.0:8443"
tls_cert_path: "$ISSUER_ETC/tls.crt"
tls_key_path: "$ISSUER_ETC/tls.key"
replica_id: "$vm"
tags:
  allowlist: ["role", "env"]
keystone:
  allowed_users: ["$(env_get .openstack.vendordata_user_id)"]   # $VENDORDATA_USER
  ca_cert_path: "$ISSUER_ETC/openstack-ca.pem"
nova_lookup:
  enabled: true
enrich: ["availability_zone", "project_name"]
peers:
  urls:
    - "https://$peer.lab:8443/jwks/local.json"
  ca_cert_path: "$ISSUER_ETC/lab-ca.pem"
attest:
  allowed_sources: ["$(vm_ip devstack)"]                  # nova-api-metadata
  client_ca_path: "$ISSUER_ETC/nova-client-ca.pem"        # Nova's client certificate
audit:
  syslog:
    enabled: true
YAML
}

issuer_env() {
	cat <<ENV
# written by the lab's deploy (test/lab/lib/deploy.sh)
OS_AUTH_URL=$(devstack_keystone_url)
OS_USERNAME=$ISSUER_USER
OS_PASSWORD=$(user_password "$ISSUER_USER")
OS_USER_DOMAIN_NAME=Default
OS_PROJECT_NAME=service
OS_PROJECT_DOMAIN_NAME=Default
OS_REGION_NAME=RegionOne
OS_INTERFACE=public
ENV
}

# deploy_issuer VM: installs and configures an issuer replica, and starts it.
deploy_issuer() {
	local vm="$1" format pki owner="root:$ISSUER_SERVICE"
	[[ "$(vm_attr "$vm" os)" == rhel ]] && format=rpm || format=deb
	pki="$(pki_dir)"
	info "installing $ISSUER_SERVICE ($format) on $vm"
	install_package "$vm" "$(package "$ISSUER_SERVICE" "$format")" "$ISSUER_SERVICE"
	issuer_config "$vm" | put "$vm" - "$ISSUER_ETC/signer.yaml" "$owner" 0640
	issuer_env | put "$vm" - "$ISSUER_ETC/signer.env" "$owner" 0640
	put "$vm" "$pki/$vm.lab.pem" "$ISSUER_ETC/tls.crt" "$owner" 0644
	put "$vm" "$pki/$vm.lab.key" "$ISSUER_ETC/tls.key" "$ISSUER_SERVICE:$ISSUER_SERVICE" 0600
	put "$vm" "$pki/ca.pem" "$ISSUER_ETC/lab-ca.pem" "$owner" 0644
	# the lab CA also issues Nova's client certificate
	put "$vm" "$pki/ca.pem" "$ISSUER_ETC/nova-client-ca.pem" "$owner" 0644
	put "$vm" "$pki/openstack-ca.pem" "$ISSUER_ETC/openstack-ca.pem" "$owner" 0644
	# the same checks the service applies at startup, as the service user
	local report
	report="$(vm_ssh "$vm" "sudo -u $ISSUER_SERVICE /usr/bin/openstack-spire-issuer config check --signer $ISSUER_ETC/signer.yaml" 2>&1)" ||
		die "config check failed on $vm:"$'\n'"$report"
	grep -q "warning" <<<"$report" && printf '%s\n' "$report" | sed -n 's/^ *line/        config check: line/p'
	vm_ssh "$vm" "sudo systemctl enable --quiet $ISSUER_SERVICE && sudo systemctl restart $ISSUER_SERVICE"
}

# wait_issuer_ready VM: waits for VM's /readiness, from the devstack VM (where
# Nova calls from): its first key is published ahead of use, for
# key_store.publish_ahead (2 minutes by default).
wait_issuer_ready() {
	local vm="$1" deadline=$((SECONDS + 300))
	until vm_ssh devstack "curl -sf --cacert /etc/nova/lab-ca.pem https://$vm.lab:8443/readiness >/dev/null"; do
		if ! vm_ssh "$vm" "systemctl is-active --quiet $ISSUER_SERVICE"; then
			vm_ssh "$vm" "sudo journalctl -u $ISSUER_SERVICE -n 20 --no-pager" | sed 's/^/        | /'
			die "$ISSUER_SERVICE is not running on $vm"
		fi
		((SECONDS < deadline)) || die "$vm is not ready after 5 minutes (lab.sh logs $vm $ISSUER_SERVICE)"
		sleep 10
	done
	info "$vm is ready"
}

# deploy_issuers: both replicas, which peer with each other.
deploy_issuers() {
	local vm
	for vm in issuer-a issuer-b; do
		deploy_issuer "$vm"
	done
	info "waiting for the issuers' first keys (published ahead of use: about 2 minutes)"
	for vm in issuer-a issuer-b; do
		wait_issuer_ready "$vm"
	done
}

# --- SPIRE Server and the guests (chunk 3.5, step 4b) ---------------------------

readonly TRUST_DOMAIN=openstack.lab
readonly SPIRE_HOME=/opt/spire
readonly SPIRE_SOCKET=/var/lib/spire/server/api.sock
readonly ARTIFACTS=/srv/lab-artifacts
readonly ARTIFACTS_PORT=8080

spire_tarball() {
	fetch "$(spire_url "$(env_get .versions.spire)")" "$(env_get .versions.spire_sha256)"
}

# spire_server ARGS...: runs the spire-server CLI on the spire VM.
spire_server() {
	vm_ssh spire "sudo -u spire $SPIRE_HOME/bin/spire-server $(printf '%q ' "$@") -socketPath $SPIRE_SOCKET"
}

spire_server_config() {
	cat <<HCL
# written by the lab's deploy (test/lab/lib/deploy.sh)
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  socket_path  = "$SPIRE_SOCKET"
  trust_domain = "$TRUST_DOMAIN"
  data_dir     = "/var/lib/spire/server"
  log_level    = "INFO"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/var/lib/spire/server/datastore.sqlite3"
    }
  }
  KeyManager "disk" {
    plugin_data {
      keys_path = "/var/lib/spire/server/keys.json"
    }
  }
  NodeAttestor "openstack_iid" {
    plugin_cmd      = "/usr/bin/openstack-server-plugin"
    plugin_checksum = "$1"
    plugin_data {
      # the peered replicas' merged JWK Set (the lab has no load balancer)
      jwks_url            = "https://issuer-a.lab:8443/.well-known/jwks.json"
      jwks_ca_cert_path   = "/etc/spire/lab-ca.pem"
      allowed_project_ids = ["$(env_get .openstack.project_id)"]
      audit_syslog {
        enabled = true
      }
    }
  }
}
HCL
}

# deploy_spire_server: SPIRE (the pinned, verified release) and the server
# plugin package on the spire VM, run by systemd as a dedicated user.
deploy_spire_server() {
	info "installing SPIRE $(env_get .versions.spire) and openstack-server-plugin (deb) on spire"
	local tarball
	tarball="$(spire_tarball)"
	scp -q "${SSH_OPTS[@]}" "$tarball" "$LAB_USER@$(vm_ip spire):/tmp/spire.tar.gz"
	vm_ssh spire "sudo bash -s -- $(printf '%q ' "$SPIRE_HOME")" <<'SCRIPT'
set -euo pipefail
home="$1"
id spire >/dev/null 2>&1 || useradd --system --home-dir /var/lib/spire --shell /usr/sbin/nologin spire
rm -rf "$home" && mkdir -p "$home" /etc/spire /var/lib/spire/server
tar -xzf /tmp/spire.tar.gz -C "$home" --strip-components=1 && rm -f /tmp/spire.tar.gz
chown -R spire:spire /var/lib/spire
cat >/etc/systemd/system/spire-server.service <<UNIT
[Unit]
Description=SPIRE Server (openstack-spiffe lab)
After=network-online.target
Wants=network-online.target

[Service]
User=spire
ExecStart=$home/bin/spire-server run -config /etc/spire/server.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
SCRIPT
	install_package spire "$(package openstack-server-plugin deb)" openstack-server-plugin
	put spire "$(pki_dir)/ca.pem" /etc/spire/lab-ca.pem root:root 0644
	local checksum
	checksum="$(vm_ssh spire "sha256sum /usr/bin/openstack-server-plugin" | awk '{ print $1 }')"
	spire_server_config "$checksum" | put spire - /etc/spire/server.conf root:spire 0640
	vm_ssh spire "sudo systemctl enable --quiet spire-server && sudo systemctl restart spire-server"
	local deadline=$((SECONDS + 120))
	until spire_server healthcheck >/dev/null 2>&1; do
		((SECONDS < deadline)) || die "SPIRE Server is not healthy (lab.sh logs spire spire-server)"
		sleep 3
	done
	spire_server bundle show >"$LAB_STATE_DIR/spire-bundle.pem"
	info "SPIRE Server is up (trust domain $TRUST_DOMAIN)"
}

# deploy_artifacts: what the guests install, served from the spire VM: Nova
# instances cannot be reached with scp, and the lab host runs no services.
deploy_artifacts() {
	info "publishing the guests' artifacts on http://spire.lab:$ARTIFACTS_PORT/"
	vm_ssh spire "sudo rm -rf $ARTIFACTS && sudo mkdir -p $ARTIFACTS"
	local file
	for file in "$(spire_tarball)" "$(package openstack-agent-plugin deb)" "$(package openstack-agent-plugin rpm)"; do
		put spire "$file" "$ARTIFACTS/${file##*/}" root:root 0644
	done
	vm_ssh spire "sudo bash -s -- $(printf '%q ' "$ARTIFACTS" "$ARTIFACTS_PORT")" <<'SCRIPT'
set -euo pipefail
cat >/etc/systemd/system/lab-artifacts.service <<UNIT
[Unit]
Description=openstack-spiffe lab: artifacts for the guests
After=network-online.target

[Service]
User=nobody
ExecStart=/usr/bin/python3 -m http.server $2 --directory $1
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --quiet lab-artifacts
systemctl restart lab-artifacts
SCRIPT
}

# guest_user_data OS: the cloud-init configuration that turns a guest (ubuntu
# or rhel) into a SPIRE Agent attesting with openstack_iid. Its trust bundle
# is part of it rather than downloaded.
guest_user_data() {
	local os="$1" plugin tarball spire_version spire_sha plugin_sha install nftables_conf
	spire_version="$(env_get .versions.spire)"
	spire_sha="$(env_get .versions.spire_sha256)"
	tarball="$(spire_url "$spire_version")"
	tarball="${tarball##*/}"
	if [[ "$os" == ubuntu ]]; then
		plugin="$(package openstack-agent-plugin deb)"
		install="dpkg -i /tmp/agent-plugin"
		nftables_conf=/etc/nftables.conf
	else
		plugin="$(package openstack-agent-plugin rpm)"
		install="rpm -U --replacepkgs /tmp/agent-plugin"
		nftables_conf=/etc/sysconfig/nftables.conf
	fi
	# the binary the package installs
	plugin_sha="$(sha256sum "$REPO_DIR"/dist/openstack-agent-plugin_linux_amd64_v1/openstack-agent-plugin | awk '{ print $1 }')"
	cat <<YAML
#cloud-config
# SPIRE Agent runs as its own user, the only one besides root allowed to
# reach the metadata service (guest hardening, S-4)
users:
  - default
  - name: spire
    system: true
    homedir: /var/lib/spire
    shell: /usr/sbin/nologin
$([[ "$os" == ubuntu ]] || printf 'packages:\n  - nftables\n')
write_files:
  - path: /etc/openstack-metadata.nft
    permissions: "0644"
    content: |
$(sed 's/^/      /' "$REPO_DIR/examples/agent-metadata-nftables.conf")
  - path: /etc/spire/bundle.pem
    permissions: "0644"
    content: |
$(sed 's/^/      /' "$LAB_STATE_DIR/spire-bundle.pem")
  - path: /etc/spire/agent.conf
    permissions: "0644"
    content: |
      agent {
        data_dir          = "/var/lib/spire/agent"
        log_level         = "DEBUG"
        server_address    = "spire.lab"
        server_port       = "8081"
        socket_path       = "/run/spire/agent/public/api.sock"
        trust_bundle_path = "/etc/spire/bundle.pem"
        trust_domain      = "$TRUST_DOMAIN"
      }
      plugins {
        NodeAttestor "openstack_iid" {
          plugin_cmd      = "/usr/bin/openstack-agent-plugin"
          plugin_checksum = "$plugin_sha"
          plugin_data {}
        }
        KeyManager "disk" {
          plugin_data {
            directory = "/var/lib/spire/agent"
          }
        }
        WorkloadAttestor "unix" {
          plugin_data {}
        }
      }
  - path: /etc/systemd/system/spire-agent.service
    permissions: "0644"
    content: |
      [Unit]
      Description=SPIRE Agent (openstack-spiffe lab)
      After=network-online.target
      Wants=network-online.target
      [Service]
      User=spire
      StateDirectory=spire/agent
      RuntimeDirectory=spire/agent/public
      ExecStart=$SPIRE_HOME/bin/spire-agent run -config /etc/spire/agent.conf
      Restart=on-failure
      RestartSec=5s
      [Install]
      WantedBy=multi-user.target
runcmd:
  # the sample rule, loaded at boot by the image's nftables service, before
  # the agent starts
  - [sh, -c, "echo 'include \\"/etc/openstack-metadata.nft\\"' >> $nftables_conf && systemctl enable nftables && systemctl restart nftables"]
  - [sh, -c, "curl -fsS -o /tmp/agent-plugin http://spire.lab:$ARTIFACTS_PORT/${plugin##*/} && $install"]
  - [sh, -c, "curl -fsS -o /tmp/spire.tar.gz http://spire.lab:$ARTIFACTS_PORT/$tarball && echo '$spire_sha  /tmp/spire.tar.gz' | sha256sum -c --quiet && mkdir -p $SPIRE_HOME /var/lib/spire/agent && tar -xzf /tmp/spire.tar.gz -C $SPIRE_HOME --strip-components=1"]
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, spire-agent]
  - [sh, -c, "echo LAB-GUEST-AGENT-STARTED > /dev/console"]
YAML
}

# deploy_guests: the guests' cloud-init configurations, for the tests.
deploy_guests() {
	mkdir -p "$LAB_STATE_DIR/guest"
	local os
	for os in ubuntu rhel; do
		guest_user_data "$os" >"$LAB_STATE_DIR/guest/$os.yaml"
	done
	info "guest configurations in $LAB_STATE_DIR/guest/"
}

lab_deploy() {
	# idempotent: also brings a lab restored from an older snapshot up to date
	devstack_guest_access
	devstack_vendordata_config
	section "Build"
	deploy_build
	section "Issuers"
	deploy_issuers
	section "SPIRE"
	env_set .openstack.project_id "$(devstack_openstack project show demo -f value -c id)"
	env_set .spire.trust_domain "$TRUST_DOMAIN"
	deploy_spire_server
	deploy_artifacts
	deploy_guests
	env_set .deployed.commit "$(git -C "$REPO_DIR" rev-parse --short HEAD)$(git -C "$REPO_DIR" diff --quiet HEAD || echo +changes)"
	env_set .deployed.at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
