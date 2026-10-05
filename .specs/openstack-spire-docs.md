# OpenStack SPIRE node attestation — documentation spec

Oct 5, 2026 · @Andrea Funtò · **Approved Oct 5, 2026; not implemented yet**

## Overview

The solution has a README for its developers and evaluators, a development guide, and specs that hold the authoritative design. People who deploy and run it have nothing written for them: they must piece together the README, the samples and the specs. This spec adds three documents, written for them, built as PDFs with pandoc and published with every release next to the deb and rpm packages:

| Document | For | Answers |
| --- | --- | --- |
| **Setup Guide** | Whoever installs the solution: OpenStack and SPIRE operators, image builders | How do I install and configure the issuer, the server plugin and the agent plugin, and check that they work? |
| **Architecture and Design** | Architects, security reviewers, auditors | How does it work, why is it built this way, what does it protect against and what does it not? |
| **Operator's Guide** | Whoever runs it day to day, and on call | How do I watch it, what are the routine procedures, and what does each error mean and what do I do about it? |

**Audience and relation to the specs** (decided Oct 5): the documents speak to operators and architects in their own words and are self-contained: a reader never needs the specs. The specs stay the developers' authoritative design; the documents restate what their readers need and name the spec a detail comes from, for those who want more. Architecture and Design carries the full threat register with every mitigation and residual risk, restated, not linked.

**Out of scope**: an HTML documentation site, translations, and documentation of the code (the README, DEVELOPMENT.md and the specs cover developers).

## Toolchain

- **pandoc with LaTeX and the Eisvogel template** (decided Oct 5), run from the official `pandoc/extra` container image, pinned by version and digest: it carries pandoc, a LaTeX distribution and Eisvogel, so neither developers nor CI install LaTeX. The look: a title page with the document's title, version and date; a table of contents; numbered sections; running headers and footers; code listings with line wrapping.
- **Sources** in Markdown (pandoc's dialect), one directory per document, one file per chapter, numbered so that their order is the file order:

  ```text
  docs/
    setup-guide/          00-metadata.yaml, 01-introduction.md, 02-prerequisites.md, ...
    architecture/         ...
    operators-guide/      ...
    common/               defaults.yaml (shared pandoc options), filters/, figures/
  ```

- **Samples are included, not copied**: a small Lua filter (`docs/common/filters/include.lua`) replaces a code block marked `{include="examples/signer.yaml"}` with the file's content at build time, so configuration examples in the documents are always the tested samples (`examples/` is checked by the unit tests).
- **Diagrams as code, in Mermaid** (decided Oct 5): every figure (data flows, trust boundaries, the attestation sequence, the key lifecycle, the deployment topologies) is a Mermaid source under `docs/common/diagrams/` (`*.mmd`), rendered to PDF by the official `mermaid-cli` container image, pinned by version and digest, before pandoc runs, and included as an image. Mermaid rather than PlantUML: GitHub renders Mermaid in Markdown, so a reviewer sees a diagram's source and its picture in the pull request without building the PDFs; it has every kind of diagram needed (flowcharts, sequence and state diagrams). The diagram sources also appear in a `docs/common/diagrams/README.md` gallery, which GitHub renders.
- **Artwork** (decided Oct 5): the project logo (`docs/common/artwork/logo.png`, committed at 1024 × 1024 pixels from the 2048-pixel original) appears on every title page. Every document's copyright page credits the Go gopher, which the logo draws on: "The Go gopher was designed by Renée French and is licensed under the Creative Commons Attribution 4.0 license". The logo also evokes OpenStack's emblem, a trademark of the OpenInfra Foundation, whose trademark policy governs its use in other projects' marks: clearing that is the project owner's decision, outside this spec.
- **Version stamping**: every PDF carries the version it documents (the release tag, or `git describe` for a development build) and the build date, on its title page and in its footer.

## Build and publication

- **`make docs`** builds the three PDFs into `dist/docs/` with the pinned container (Docker or Podman); `DOCS_VERSION` overrides the version. File names: `openstack-spiffe-setup-guide-<version>.pdf`, `openstack-spiffe-architecture-and-design-<version>.pdf`, `openstack-spiffe-operators-guide-<version>.pdf`.
- **Continuous build** (`.github/workflows/docs.yml`): on every push and pull request that touches `docs/`, `examples/` or the workflow itself, it builds the PDFs and attaches them to the run as artifacts, so a document that does not build is caught before a release, and reviewers can read the result.
- **Releases**: the release workflow builds the documents with the release version before goreleaser runs. goreleaser attaches them to the GitHub release (`release.extra_files`) and lists them in the checksums file (`checksum.extra_files`), so the signed checksums cover them like every archive and package (T-7). `make release` builds them first; `make snapshot` does not need them (a snapshot without documents is still valid).
- The packages do not install the PDFs: they stay release assets, so the packages do not grow by several MB per architecture.

## Content

Every chapter below is required; the outlines fix the scope, not the wording. The documents use the terms of the solution consistently (signer replica, JWKS aggregator, merged JWK Set, vendordata user, ...), put every configuration key, path, command and log message in code font, and explain each step's purpose before its commands.

### Setup Guide

1. **Introduction**: what the solution does in one page; the three components and where each runs; what the reader needs before starting.
2. **Prerequisites**: supported OpenStack and SPIRE versions; operating systems and CPU levels (any x86-64, arm64; the v2/v3 builds); network paths between Nova, the issuers, the aggregator, SPIRE Server and instances; DNS names and TLS certificates to prepare.
3. **Getting and verifying a release**: download, checksums and signatures (gpg, rpm, debsig-verify), before anything is installed or a `plugin_checksum` computed.
4. **OpenStack preparation**: the dedicated vendordata user and its role; the issuer's own service user; Nova's DynamicJSON vendordata configuration, `[vendordata_dynamic_auth]` with the client certificate; what to check in Nova's logs.
5. **Installing the issuer**: packages; the signer configuration, key by key, from the sample; credentials (`signer.env`); TLS; `attest` restrictions; peers or an aggregator (with the choice explained); the syslog audit sink; memory protection and its limits; `config check`; starting, readiness, and the first token.
6. **The JWKS aggregator** (optional): when to use it, configuration, deployment.
7. **Installing the server plugin**: package, `plugin_checksum`, SPIRE Server configuration, `allowed_project_ids`, `allowed_tag_keys`, `reattest`, `audit_syslog`, `agent_ttl`; registration entries and the rule for tenant-asserted selectors.
8. **Installing the agent plugin**: baking it into images or installing at boot; SPIRE Agent under its own user; the guest hardening nftables rule; containers.
9. **Metrics** (optional): Prometheus or OTLP, protection, a first dashboard.
10. **End-to-end check**: a checklist from an instance boot to an attested agent, with what to look at when a step fails (pointing to the Operator's Guide).
11. **Upgrades and removal**: upgrade order (issuers before the server plugin), what packages do on upgrade and removal.
12. **Configuration reference**: every configuration key of the three components, written from the specs (decided Oct 5), not generated from the samples, which stay short. For each key: its purpose; its default; its type and range, or its possible values and what each does; its dependencies on other keys (e.g. `publish_ahead` against the peers' and the aggregator's polling, `nova_lookup.cache_ttl` against the token TTL, the enrichment claims that need instance verification); its caveats; and, where a choice weakens or strengthens the security of the deployment, the threat it bears on (by its threat model ID) and the safe choice. Keys are grouped by component and section, in the order of the samples.

### Architecture and Design

1. **Context and goals**: the problem (proving an instance's identity to SPIRE without trusting the guest), the solution in one diagram, the goals and non-goals.
2. **Components and data flows**: the signer replicas, the JWKS aggregator and peer aggregation, the two plugins, Nova, Keystone and SPIRE; one diagram of the flows with the trust boundaries.
3. **The attestation sequence**: from an instance's metadata read to an agent SVID, step by step.
4. **The token**: claims, their sources and trustworthiness (control plane versus tenant-asserted), size limits, the `kid` format, lifetime.
5. **Caller authentication and instance verification**: Keystone validation and caching, the dedicated user, the `/attest` restrictions, Nova verification and enrichment.
6. **Signing keys**: custody (ephemeral in memory, Vault later), rotation and publication ahead of use, memory protection and the options considered, the key lifecycle audit.
7. **Distributing the verification keys**: local and merged JWK Sets, peers, the aggregator, conflict handling, stale key retention, the plugin's fetching and refetching.
8. **Verification in SPIRE Server**: checks, replay protection and its limits, re-attestation modes, selectors and SPIFFE IDs.
9. **Observability**: logs, the audit trail and its correlation (`jti`), metrics.
10. **Threat model**: assets, actors, trust boundaries and security assumptions; the full threat register (every threat, its status, every mitigation and the residual risk), grouped by STRIDE category; accepted risks.
11. **Design decisions**: the significant choices and their reasons (e.g. per-call minting, ephemeral keys, GPG signing, whole-process memory locking), from the specs' resolved questions.

### Operator's Guide

1. **Operating model**: what runs where, what is stateful (nothing persistent in the issuer), what a restart does (a new key), the health endpoints.
2. **Monitoring**: readiness and liveness; the logs and the audit trail, and where they go; the metrics with the recommended alerts and what each alert means.
3. **Routine procedures**: adding and removing a signer replica or an aggregator; renewing TLS certificates and the Nova client certificate; rotating the issuer's service credentials; forcing a key rotation; upgrading; changing configuration safely (`config check` first); evicting agents (with `reattest = false`, after instance deletion).
4. **Incident procedures**: suspected signing key compromise; stolen vendordata credentials; a suspected stolen token (the `reattest_alert`); a compromised peer replica; what evidence to keep (audit records, metrics) and how to correlate it.
5. **Error reference**, the core of the guide, as tables mapping each error to its meaning, likely causes and remediation:
   - **The issuer's `/attest` responses**: every HTTP status, with the metrics `reason` and the log message that goes with it.
   - **The issuer at startup**: every refusal to start (configuration, credentials, Keystone, TLS, memory locking, the syslog socket), with its message and exit code.
   - **`config check`**: its exit codes, and the meaning of each kind of finding.
   - **Peers and the aggregator**: fetch failures, invalid responses, conflicts, stale keys, readiness failures.
   - **The server plugin**: every gRPC status code it returns to SPIRE Server (`InvalidArgument`, `PermissionDenied`, `Unavailable`, `FailedPrecondition`, `Internal`), with each rejection message, its cause and remediation; configuration errors and warnings.
   - **The agent plugin**: its errors as SPIRE Agent logs them.
6. **Troubleshooting**: from symptoms to causes, as decision paths: an instance's agent does not attest; tokens are refused with "token already used" or "issued before this server started"; Nova omits the vendordata; readiness flaps; metrics show `unspecified` or rising refusals.
7. **Appendix**: the log message catalogue (every warn and error message of the three components), the audit record formats, the metric list.

## Keeping the documents true

- **Same change, same commit**: a change of behaviour, configuration, error or log message updates the documents in the change that makes it, as it updates the specs; DEVELOPMENT.md says so.
- **The error reference is checked by a test**: a Go test reads the Operator's Guide's sources and fails if any `/attest` metrics reason (`metrics.Reason*`), any server plugin rejection message, any `config check` exit code or any startup refusal message is missing from the error reference. Adding an error without documenting it fails the build.
- **The configuration reference is checked by a test**: a Go test walks every configuration key of the signer, the aggregator (their YAML schema, `internal/issuer/config`) and the two plugins (their HCL keys) and fails if any is missing from the Setup Guide's configuration reference.
- **Samples are included** from `examples/` (see the toolchain), never copied.
- **The documents build on every change** (continuous build), and a release cannot be published without them.

## Testing

- The continuous build produces the three PDFs without warnings (pandoc and LaTeX warnings fail the build: missing references, unknown includes, overfull boxes beyond a tolerance).
- The error reference test above.
- A release dry run (`goreleaser release --snapshot` with the documents present) shows the PDFs among the release's extra files and in the checksums file.
- The documents are read: each chunk below ends with the user's review of the PDFs.

## Implementation plan

| Chunk | Content |
| --- | --- |
| D1 | Toolchain: `docs/` skeleton with the three documents' metadata and chapter stubs, the shared defaults, the include filter, Mermaid rendering, the logo and title pages, `make docs`, the continuous build workflow, the release integration (`release.extra_files`, `checksum.extra_files`, the release workflow); DEVELOPMENT.md and README pointers |
| D2 | The Setup Guide, its configuration reference, and the configuration reference test |
| D3 | Architecture and Design, its diagrams included |
| D4 | The Operator's Guide, and the error reference test |

## Decisions (Oct 5)

1. **pandoc with LaTeX and Eisvogel**, from the `pandoc/extra` container image.
2. **Written for operators and architects**, self-contained; the specs stay the developers' design.
3. **Diagrams as code, in Mermaid**, rendered in the build (see the toolchain).
4. **The configuration reference is written from the specs**, with rationale, dependencies, choices, caveats and security considerations for every key, and checked for completeness by a test.
5. **The project logo** on the title pages, with the Go gopher credited.
