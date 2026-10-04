# shellcheck shell=bash
# The lab's PKI: a CA, the issuers' server certificates and the client
# certificate Nova presents to the issuers. Lab-only material, kept in the
# state directory.

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

# ensure_pki: the CA and every certificate the lab uses.
ensure_pki() {
	pki_ca
	local vm
	for vm in issuer-a issuer-b; do
		pki_issue "$vm.lab" serverAuth "DNS:$vm.lab,IP:$(vm_ip "$vm")"
	done
	# presented by nova-api-metadata to /attest (chunk 4)
	pki_issue nova-vendordata clientAuth
}
