# Add custom targets below...

#
# compile is the default target; it builds the
# application for the default platform (linux/amd64)
#
.DEFAULT_GOAL := compile

.PHONY: compile
compile: go-dev ## build for the default linux/amd64 platform

.PHONY: snapshot
snapshot: signing-check go-snapshot ## build a snapshot version for the supported platforms (signed if GPG_FINGERPRINT and GPG_KEY_FILE are set)

.PHONY: release
release: signing-check ## build a release version (requires a valid tag and the packaging key), documents included
	@test -n "$(GPG_FINGERPRINT)" || { echo "a release must be signed: set GPG_FINGERPRINT and GPG_KEY_FILE" >&2; exit 1; }
	@DOCS_VERSION="$$(git describe --tags --exact-match)" docs/build.sh
	@$(MAKE) --no-print-directory go-release

.PHONY: docs
docs: ## build the release documents (PDF) into build/docs/ (needs docker or podman)
	@docs/build.sh

# signing-check: the packaging key (T-7) signs the checksums file through gpg
# (GPG_FINGERPRINT) and the packages through nfpm (GPG_KEY_FILE, its armored
# private key): both or neither, so that no build is half signed
.PHONY: signing-check
signing-check:
	@if [ -n "$(GPG_FINGERPRINT)" ] && [ ! -r "$(GPG_KEY_FILE)" ]; then echo "GPG_FINGERPRINT is set but GPG_KEY_FILE is not a readable key file" >&2; exit 1; fi
	@if [ -z "$(GPG_FINGERPRINT)" ] && [ -n "$(GPG_KEY_FILE)" ]; then echo "GPG_KEY_FILE is set but GPG_FINGERPRINT is not" >&2; exit 1; fi

.PHONY: clean
clean: ## clean the binary directory
	@rm -rf dist


.PHONY: checksum
checksum: ## print the SHA-256 of the SPIRE plugin binaries in dist/ (for plugin_checksum)
	@find dist -type f \( -name openstack-agent-plugin -o -name openstack-server-plugin \) -exec sha256sum {} + | sort -k2

.PHONY: dev-check
dev-check: ## check the development environment (tools, resources, build); see DEVELOPMENT.md
	@scripts/dev-check.sh

.PHONY: dev-check-full
dev-check-full: ## check the development environment, then run the unit and integration tests
	@scripts/dev-check.sh --test
