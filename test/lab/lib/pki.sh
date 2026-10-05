# shellcheck shell=bash
# The lab's PKI: a CA, the issuers' server certificates, the client
# certificate Nova presents to the issuers, and the packaging key that signs
# the lab's builds. Lab-only material, kept in the state directory.

pki_dir() { echo "$LAB_STATE_DIR/pki"; }

# pki_ca: creates the lab CA, unless it exists.
pki_ca() {
	local dir
	dir="$(pki_dir)"
	[[ -f "$dir/ca.pem" ]] && return 0
	mkdir -p "$dir"
	chmod 700 "$dir"
	info "creating the lab CA"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 3650 \
		-keyout "$dir/ca.key" -out "$dir/ca.pem" -subj "/O=openstack-spiffe lab/CN=lab CA" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

# pki_issue NAME USAGE [SAN]: issues NAME.pem and NAME.key, signed by the lab
# CA, for USAGE (serverAuth or clientAuth), unless they exist.
pki_issue() {
	local dir name="$1" usage="$2" san="${3:-}"
	dir="$(pki_dir)"
	[[ -f "$dir/$name.pem" ]] && return 0
	info "issuing the $name certificate"
	local ext="$dir/$name.ext"
	{
		echo "basicConstraints=critical,CA:FALSE"
		echo "keyUsage=critical,digitalSignature"
		echo "extendedKeyUsage=$usage"
		[[ -z "$san" ]] || echo "subjectAltName=$san"
	} >"$ext"
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$dir/$name.key" -out "$dir/$name.csr" -subj "/O=openstack-spiffe lab/CN=$name" 2>/dev/null
	openssl x509 -req -sha256 -days 825 -in "$dir/$name.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
		-set_serial "0x$(openssl rand -hex 16)" -extfile "$ext" -out "$dir/$name.pem" 2>/dev/null
	rm -f "$dir/$name.csr" "$ext"
}

# pki_gpg ARGS...: gpg on the lab's own keyring.
pki_gpg() { gpg --homedir "$(pki_dir)/gnupg" --batch --quiet "$@"; }

# packaging_fingerprint: the lab packaging key's fingerprint.
packaging_fingerprint() { cat "$(pki_dir)/packaging-key.fpr"; }

# pki_packaging_key: the GPG key signing the lab's builds as a release is
# signed (T-7), unless it exists: packaging-key.asc (the armored private key,
# without passphrase, for nfpm), packaging-key.pub.asc and packaging-key.fpr.
pki_packaging_key() {
	local dir
	dir="$(pki_dir)"
	[[ -f "$dir/packaging-key.fpr" ]] && return 0
	info "creating the lab packaging key"
	mkdir -p "$dir/gnupg"
	chmod 700 "$dir/gnupg"
	pki_gpg --pinentry-mode loopback --passphrase '' \
		--quick-gen-key "openstack-spiffe lab packaging <packaging@openstack.lab>" rsa3072 sign 10y
	local fpr
	fpr="$(pki_gpg --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')"
	[[ -n "$fpr" ]] || die "cannot create the lab packaging key"
	(umask 077 && pki_gpg --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$fpr" >"$dir/packaging-key.asc")
	pki_gpg --armor --export "$fpr" >"$dir/packaging-key.pub.asc"
	echo "$fpr" >"$dir/packaging-key.fpr"
}

# ensure_pki: the CA, every certificate the lab uses and the packaging key.
ensure_pki() {
	pki_ca
	local vm
	for vm in issuer-a issuer-b; do
		pki_issue "$vm.lab" serverAuth "DNS:$vm.lab,IP:$(vm_ip "$vm")"
	done
	# presented by nova-api-metadata to /attest (chunk 4)
	pki_issue nova-vendordata clientAuth
	# the OpenTelemetry Collector receiving issuer-b's metrics (metrics)
	pki_issue spire.lab serverAuth "DNS:spire.lab,IP:$(vm_ip spire)"
	# signs the lab's builds (chunk 8)
	pki_packaging_key
}
