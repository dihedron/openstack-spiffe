# Add custom targets below...

#
# compile is the default target; it builds the
# application for the default platform (linux/amd64)
#
.DEFAULT_GOAL := compile

.PHONY: compile
compile: go-dev ## build for the default linux/amd64 platform

.PHONY: snapshot
snapshot: go-snapshot ## build a snapshot version for the supported platforms

.PHONY: release
release: go-release ## build a release version (requires a valid tag)

.PHONY: clean
clean: ## clean the binary directory
	@rm -rf dist


.PHONY: checksum
checksum: ## print the SHA-256 of the SPIRE plugin binaries in dist/ (for plugin_checksum)
	@find dist -type f \( -name openstack-agent-plugin -o -name openstack-server-plugin \) -exec sha256sum {} + | sort -k2
