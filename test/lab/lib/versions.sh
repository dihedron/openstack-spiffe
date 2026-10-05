# shellcheck shell=bash
# Resolution of the versions the lab uses, and verification of downloads.

# resolve_devstack_branch: LAB_DEVSTACK_BRANCH, or DevStack's most recent
# stable/YYYY.N branch.
resolve_devstack_branch() {
	if [[ -n "$LAB_DEVSTACK_BRANCH" ]]; then
		echo "$LAB_DEVSTACK_BRANCH"
		return
	fi
	local branch
	branch="$(git ls-remote --heads https://opendev.org/openstack/devstack 'refs/heads/stable/*' |
		awk '{ sub("refs/heads/", "", $2); print $2 }' |
		grep -E '^stable/[0-9]{4}\.[0-9]+$' | sort -V | tail -n1)"
	[[ -n "$branch" ]] || die "cannot list DevStack's stable branches"
	echo "$branch"
}

# sdk_version: the spire-plugin-sdk version in go.mod (e.g. 1.15.3).
sdk_version() {
	awk '$1 == "github.com/spiffe/spire-plugin-sdk" { sub("^v", "", $2); print $2; exit }' "$REPO_DIR/go.mod"
}

# resolve_spire: prints "VERSION SHA256" of the SPIRE release to use:
# LAB_SPIRE_VERSION with LAB_SPIRE_SHA256, or the most recent release with
# the plugin SDK's major version and at least its minor version, with the
# SHA-256 its release publishes.
resolve_spire() {
	local version="$LAB_SPIRE_VERSION" sha="$LAB_SPIRE_SHA256"
	if [[ -n "$version" ]]; then
		[[ -n "$sha" ]] || die "LAB_SPIRE_VERSION=$version is pinned without LAB_SPIRE_SHA256"
		echo "$version $sha"
		return
	fi
	local sdk major minor
	sdk="$(sdk_version)"
	[[ -n "$sdk" ]] || die "no github.com/spiffe/spire-plugin-sdk in go.mod"
	major="${sdk%%.*}" minor="${sdk#*.}" minor="${minor%%.*}"
	version="$(curl -fsSL 'https://api.github.com/repos/spiffe/spire/releases?per_page=100' |
		jq -r '.[] | select(.prerelease | not) | select(.draft | not) | .tag_name | ltrimstr("v")' |
		awk -F. -v major="$major" -v minor="$minor" '$1 == major && $2 >= minor && NF == 3 && $3 ~ /^[0-9]+$/' |
		sort -V | tail -n1)"
	[[ -n "$version" ]] || die "no SPIRE release $major.x (x >= $minor) found for spire-plugin-sdk $sdk"
	sha="$(curl -fsSL "https://github.com/spiffe/spire/releases/download/v$version/spire-$version-linux-amd64-musl_sha256sum.txt" | awk '{ print $1; exit }')"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "cannot read the SHA-256 of SPIRE $version"
	echo "$version $sha"
}

# resolve_otelcol: prints "VERSION SHA256" of the OpenTelemetry Collector
# release (core distribution) to use: LAB_OTELCOL_VERSION with
# LAB_OTELCOL_SHA256, or the most recent release, with the SHA-256 published
# next to its tarball.
resolve_otelcol() {
	local version="$LAB_OTELCOL_VERSION" sha="$LAB_OTELCOL_SHA256"
	if [[ -n "$version" ]]; then
		[[ -n "$sha" ]] || die "LAB_OTELCOL_VERSION=$version is pinned without LAB_OTELCOL_SHA256"
		echo "$version $sha"
		return
	fi
	version="$(curl -fsSL 'https://api.github.com/repos/open-telemetry/opentelemetry-collector-releases/releases/latest' |
		jq -r '.tag_name | ltrimstr("v")')"
	[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "cannot find the latest OpenTelemetry Collector release"
	sha="$(curl -fsSL "$(otelcol_url "$version").sha256" | awk '{ print $1; exit }')"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "cannot read the SHA-256 of the OpenTelemetry Collector $version"
	echo "$version $sha"
}

# otelcol_url VERSION: the linux-amd64 tarball of a collector release.
otelcol_url() {
	echo "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$1/otelcol_$1_linux_amd64.tar.gz"
}

# spire_url VERSION: the linux-amd64 tarball of a SPIRE release.
spire_url() {
	echo "https://github.com/spiffe/spire/releases/download/v$1/spire-$1-linux-amd64-musl.tar.gz"
}

# published_sha256 URL: the SHA-256 of URL from the checksum file published
# next to it (SHA256SUMS or CHECKSUM, in GNU or BSD format), if any.
published_sha256() {
	local dir="${1%/*}" file="${1##*/}" list name
	for list in SHA256SUMS CHECKSUM; do
		curl -fsSL "$dir/$list" 2>/dev/null | awk -v f="$file" '
			$2 == f || $2 == "*" f { print $1; found = 1; exit }
			$1 == "SHA256" && $2 == "(" f ")" && $3 == "=" { print $4; found = 1; exit }
			END { exit !found }' && return 0
	done
	return 1
}

# fetch URL SHA256: downloads URL into the cache unless already there with
# that checksum, and prints the cached path. Fails on a checksum mismatch.
fetch() {
	local url="$1" sha="$2" path
	path="$LAB_CACHE_DIR/downloads/${url##*/}"
	mkdir -p "${path%/*}"
	if [[ -f "$path" ]] && echo "$sha  $path" | sha256sum -c --quiet >/dev/null 2>&1; then
		echo "$path"
		return
	fi
	info "downloading $url" >&2
	curl -fL --progress-bar -o "$path.part" "$url" >&2 || die "cannot download $url"
	echo "$sha  $path.part" | sha256sum -c --quiet >/dev/null 2>&1 || {
		rm -f "$path.part"
		die "checksum mismatch for $url (expected $sha)"
	}
	mv "$path.part" "$path"
	echo "$path"
}
