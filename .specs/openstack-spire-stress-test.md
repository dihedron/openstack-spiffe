# OpenStack SPIRE node attestation — lab stress test

Oct 17, 2026 · @Andrea Funtò · **Approved Oct 17, 2026**

## Overview

The acceptance tests (test environment spec) check each behaviour once, on one or two guests, one test at a time. They cannot show what only goes wrong under repetition and concurrency: a race between parallel `/attest` calls, a Nova metadata cache serving one instance's token to a retry, a replay or re-attestation cache that misbehaves after hundreds of entries, a slow leak in the signer or SPIRE Server, an attestation that fails one time in two hundred.

This spec adds a **stress test**: a harness that builds the code, deploys it on the lab, then boots, stops, starts and deletes Nova instances continuously for a given duration (`--duration 1h`), as many in parallel as the lab can hold. For every instance it checks the whole chain, node attestation through the `openstack_iid` plugins and then workload (process) attestation through SPIRE Agent's `unix` attestor. It logs every failure with the evidence needed to diagnose it, and carries on. At the end it reports what it ran, what failed and how long each step took.

It runs on the lab of the test environment spec, unchanged except for what this spec adds. That spec lists "load, performance or soak testing" as a non-goal; this spec takes the soak and stress part of it (see changes to other specs). Performance benchmarking stays out.

**Goals**:
- Find intermittent failures in node and workload attestation: every failed cycle is recorded and classified, none is retried away silently.
- Exercise both ways an instance gets an identity again: a new instance (fresh node attestation) and a stopped and restarted one (SPIRE Agent reusing its persisted SVID).
- Watch the services over time: their error records, readiness, the audit trail's consistency and their memory use.
- Use the lab's capacity: run cycles in parallel, as many as the `devstack` VM can host, without the harness itself causing failures.

**Non-goals**:
- Throughput benchmarks of `/attest` or the JWK Set endpoint (DOS-1 covers bursts).
- Fault injection that is expected to cause failures (stopping `issuer-a`, cutting or delaying the network) during an ordinary run. It needs windows of expected failures, which a later spec can add on top of a clean baseline. The harness's self-test injects such faults only to check that they are detected (see acceptance criteria). `--chaos` injects only faults that must cause no failure.
- Running in CI: like the lab itself, it needs a KVM host and takes an hour or more.
- Scale beyond one compute host: DevStack is all-in-one.

## Command line

`lab.sh stress [options]` is the entry point, like the lab's other commands. It runs the harness, a Go program in `test/lab/stress` behind the `lab` build tag (`go run -tags lab ./test/lab/stress run ...`), which parses its options with `go-flags` (already in `go.mod`, so no new dependency).

| Option | Default | Meaning |
| --- | --- | --- |
| `--duration D` | `1h` | How long new cycles keep starting (a Go duration). The run then drains (see lifecycle). |
| `--cycles N` | unset | Stop after N cycles have started instead, whichever of the two comes first. |
| `--parallel N\|auto` | `auto` | Number of cycles running at once. `auto` computes it from the lab's capacity (see parallelism). |
| `--max-parallel N` | `8` | Upper bound for `auto`. |
| `--mix create=W,restart=W` | `create=3,restart=1` | Relative weights of the cycle kinds (see cycles). |
| `--distros LIST` | `ubuntu,rhel` | Guest images to use, alternated. |
| `--hold D` | `0s-2m` | How long an instance stays up after its checks pass, as a fixed duration or a random range, to vary what overlaps with what. |
| `--bound STEP=D,...` | see cycles | Overrides the time bound of one or more cycle steps, e.g. `--bound attest=8m,svid=2m` on a slower host. An unknown step name or a non-positive duration is refused at start. |
| `--rotation D` | unset | Sets both issuers' `rotation_interval` to D for the run (at least `5m`, as in E2E-3) and restores it afterwards, so that attestations cross key rotations. |
| `--agent-ttl D` | unset | Sets SPIRE Server's `agent_ttl` to D for the run (at least `15m`, see TOFU mode) and restores it afterwards, so that agent SVIDs are renewed or re-attested within the run. |
| `--tofu` | off | Sets the server plugin's `reattest = false` for the run and restores it afterwards (see TOFU mode). |
| `--chaos` | off | Injects faults that must cause no failure at random times during the run (see chaos). |
| `--keep-failed N` | `3` | Keep up to N failed instances for inspection instead of deleting them; they count against capacity. |
| `--max-infra-rate P` | `5%` | Share of cycles with `infra` failures above which the run fails with exit status 2 (see detection). |
| `--no-deploy` | off | Skip the build and `deploy`, and test what the lab runs now. |
| `--no-reset` | off | Skip `reset`: run on the lab as it is. |
| `--out DIR` | `$LAB_STATE_DIR/stress/<UTC time>` | Where the run's records and report go. |
| `--seed N` | random | Seed for the cycle choices and hold times, recorded in the report, so that a run's schedule can be replayed. |

`lab.sh stress --duration 10m --parallel 2` is the quick sanity run.

## Lifecycle

1. **Prepare the lab.** The harness refuses to start when there is no lab (`env.json` missing): `lab.sh up` takes 15 to 30 minutes and should be run on its own. Otherwise it runs `reset` (unless `--no-reset`), then `deploy`, which builds the deb and rpm packages from the working tree with `make snapshot` and installs them (unless `--no-deploy`). The report records the git commit and whether the tree had uncommitted changes.
2. **Check the lab.** Both issuers' `/readiness`, SPIRE Server's health check, Nova's compute service up, and no instance whose name starts with `stress-` left over from an interrupted run (they are deleted and their agents evicted). Any failure here stops the run before it starts, with exit status 3.
3. **Set up.** In the `demo` project, it raises the Nova quotas (instances, cores, RAM) to what the chosen parallelism needs, recording the original values. In SPIRE Server, it creates the run's registration entries (see workload attestation). With `--rotation`, it reconfigures and restarts the issuers and waits for their readiness. With `--agent-ttl` or `--tofu`, it reconfigures and restarts SPIRE Server and waits for its health check. Every change is recorded in `run.json` so that teardown, or a later run's step 2, can undo it.
4. **Run.** The scheduler keeps the target number of cycles running until `--duration` or `--cycles` is reached.
5. **Drain.** It starts no new cycles and waits for the running ones to finish, for up to 15 minutes, after which they are recorded as `aborted` and their instances deleted.
6. **Tear down.** It deletes every remaining `stress-` instance except the kept failures, evicts their agents, deletes the registration entries, restores the quotas, the issuers' and SPIRE Server's configuration, and writes the report.

`SIGINT` or `SIGTERM` during the run moves straight to drain; a second one moves to teardown, aborting the running cycles. Teardown always runs, and a failure in it is reported (exit status 3) but does not hide the run's result.

## Cycles

A cycle is one instance's life, or one restart of it. Each step has a time bound, and missing a bound is a failure of that step. The defaults fit the reference host's boot and cloud-init times, and `--bound` overrides them by step name:

| Step | Name | Default | From → to |
| --- | --- | --- | --- |
| Boot | `boot` | `5m` | create request → `ACTIVE` |
| Node attestation | `attest` | `5m` | `ACTIVE` → agent listed by SPIRE Server |
| Workload SVID | `svid` | `60s` | node attestation, or the agent back after a restart → SVID fetched as `workload` |
| Stop | `stop` | `2m` | stop request → `SHUTOFF` |
| Start | `start` | `3m` | start request → `ACTIVE` |
| Agent back | `back` | `3m` | `ACTIVE` after a start → the agent serves identities |
| Delete | `delete` | `2m` | delete request → instance gone |

The report records the bounds in effect, and its latency table shows how close each step came to its bound. Every cycle has an ID (`c0042`), and the instance is named `stress-<run>-<cycle>-<distro>`.

**`create`** (a new identity):
1. Boot the instance from the distro's image with the `lab.guest` flavor and the guest configuration `deploy` wrote. It must become `ACTIVE` within 5 minutes.
2. **Node attestation**: SPIRE Server must list `spiffe://<trust domain>/spire/agent/openstack_iid/<project_id>/<instance_id>` within 5 minutes of `ACTIVE`, the time cloud-init needs to install the agent and start it.
3. **Workload attestation**: in the guest, the workload user gets the expected SVID within 60 seconds of node attestation (see workload attestation).
4. Hold for the `--hold` time, then run step 3 again: the agent still serves identities.
5. Delete the instance (bound: 2 minutes), evict its agent, and check that SPIRE Server no longer lists it.

**`restart`** (an identity that survives a stop):
1. Boot and check as in `create`, steps 1 to 3, recording the agent's SVID serial number.
2. Stop the instance (`openstack server stop`, bound: 2 minutes to `SHUTOFF`), wait for the `--hold` time, start it again (bound: 3 minutes to `ACTIVE`).
3. The agent comes back: within 3 minutes it serves identities again (step 3 of `create`). While its persisted SVID is valid, SPIRE Agent does not attest the node again, so the same serial is expected and there must be no new `agent_attested` record. If the SVID expired while the instance was stopped, or was past half its lifetime (when SPIRE Agent renews it, by attesting again when it can), a single new node attestation with a fresh token is acceptable. In either case, at most one "token already used" rejection is acceptable (the plugins spec's freshness bound).
4. Delete and evict as in `create`, step 5.

The scheduler picks each new cycle's kind by the `--mix` weights and alternates the distros, using the run's seed.

**Renewal within a cycle.** With the default `agent_ttl` of 1h and holds of a few minutes, agent SVIDs are almost never renewed during a cycle. With `--agent-ttl`, an instance held past half the TTL goes through it. With `reattest = true`, a running SPIRE Agent re-attests near its SVID's expiry (plugins spec). With `reattest = false`, it renews the SVID without attesting. Either is a pass when the workload check that follows the hold still succeeds. The run should then use holds past half the TTL (for example `--agent-ttl 15m --hold 5m-10m`), and the report counts the renewals and re-attestations it saw.

## TOFU mode

`--tofu` runs the whole stress test with the server plugin's `reattest = false` (trust on first use, plugins spec): once an agent ID has attested, SPIRE Server refuses to attest it again until it is evicted. It exercises what operators choosing that mode run: SVID renewal without re-attestation, and eviction as the only way to free an agent ID. The cycles' expectations change:

- `create`, step 5: the eviction after deletion is required for correctness, not only tidiness. A cycle that evicts an agent and then finds the agent ID still attested is a `node` failure.
- `restart`, step 3: the same serial or a renewed SVID is a pass. A new node attestation of the same agent ID is a `node` failure flagged as a security failure: TOFU must have refused it. When the SVID expired while the instance was stopped, the agent's refusal is the expected outcome. The cycle passes when SPIRE Server logs the refusal, and is not counted as an attestation failure.
- Run-wide: no `agent_attested` record for an agent ID that already has one in the run, unless it was evicted in between.

**Lower bound on `--agent-ttl`.** With `reattest = true`, SPIRE Agent re-attests at about half the TTL. A TTL under twice the server plugin's `reattest_alert_window` (5 minutes in the lab) would make every renewal raise a `reattest_alert`, which the run-wide checks count as an invariant failure. `--agent-ttl` therefore refuses values under `15m`, which leaves a margin above that.

## Chaos

`--chaos` injects faults chosen so that none of them may cause a failure: the system must absorb them. Any failure that counts against the verdict during a fault is therefore a real finding, and detection needs no windows of expected failures. The faults:

| Fault | What must hold |
| --- | --- |
| Restart `issuer-b` | Nova calls only `issuer-a`, so attestation is unaffected. `issuer-a` keeps serving the merged JWK Set with `issuer-b`'s keys while its peer is down. `issuer-b` becomes ready again within its usual bound, about 2 minutes. |
| Restart SPIRE Server | Agents reconnect, and attestations in progress succeed on a retry: the plugin rejects tokens minted before its process started, and the agent's next attempt brings a fresh token. Previously attested agents keep their identity: the datastore persists them, so TOFU mode still refuses their re-attestation. |

Faults are drawn with the run's seed, at random times, at least 10 minutes apart, with none in the first or last 10 minutes of the run. The report lists them with their times. From the start of a fault until one minute after the service is healthy again:
- each step's bound is extended by how long the service was down;
- for a SPIRE Server restart, the "token issued before this server started" rejections inside the window are expected: the startup watermark refuses every attempt for the plugin's `clock_skew_tolerance` (30 seconds by default) after its start, not only the first, as the first self-test found; each agent may also get one more "token already used" rejection, since the restart empties the replay cache;
- the observer and the in-guest checks tolerate SPIRE Server being unreachable while it restarts, recording it as an expected `harness` event, not a failure.

`--chaos` combines with `--rotation`, which covers key rotation: the issuer has no command to rotate keys on demand, and rotations on a short interval exercise the same path.

## Workload attestation

The lab's guests run SPIRE Agent with the `unix` workload attestor, but SPIRE Server has no registration entries, so no workload gets an identity today. The run creates two entries in step 3 and removes them in step 6:

- A node alias, `spiffe://<trust domain>/stress/node`, selecting `openstack_iid:project_id:<demo project ID>`: every guest of the `demo` project gets it. This also follows the plugins spec's registration rule (an entry that matches on a guest's identity carries `project_id`).
- A workload entry, `spiffe://<trust domain>/stress/workload`, with the alias as parent, selecting `unix:uid:2000`.

`deploy` adds an unprivileged user `workload` with UID 2000 to both guest configurations, and a second one, `outsider` (UID 2001), with no entry. The users are harmless to the acceptance tests, which never use them.

The check, run in the guest over SSH, as the acceptance tests reach guests (from the `devstack` VM's OVN metadata namespace):
- As `workload`: `spire-agent api fetch x509` on the agent's socket returns an SVID whose URI SAN is `spiffe://<trust domain>/stress/workload` and whose chain verifies against the trust bundle.
- As `outsider`: the same command returns no identity. An SVID here is a failure of class `workload`, and the report flags it as a security failure.

## Parallelism

All guests run nested inside the `devstack` VM (24 GiB by default), so the binding limit is that VM's memory, not the lab host's. With `--parallel auto`, the target number of running cycles is the smallest of:
- what Placement says the compute host can still hold of the `lab.guest` flavor (VCPU, MEMORY_MB, DISK_GB), with its allocation ratios;
- what the `devstack` VM's `MemAvailable` holds, minus a 3 GiB margin, divided by the flavor's RAM: Placement counts allocations, not what DevStack's own services actually use;
- the lab host's `MemAvailable`, minus 4 GiB, must stay positive, and its load average below its CPU count; otherwise the target drops by one;
- `--max-parallel`;
- the compute host's total slots for the flavor, less the kept failures: the free slots and the running instances are read seconds apart, so an instance deleted in between would otherwise count twice.

The running instances are the cycles' own: an instance in `ERROR` holds no allocation, and a kept failure's capacity is not the cycles' to use. Failures of class `capacity` are never kept, since their instance never ran.

The harness computes the target at the start and again every minute while it runs, and moves it by at most one per minute in either direction. A `NoValidHost` failure at boot also lowers it by one. Such a failure is recorded as class `capacity`, not as an attestation failure. With the defaults this gives about 4 to 6 parallel cycles; a larger `LAB_DEVSTACK_RAM_GIB` gives more. The report records the target over time and the highest value reached.

**Load the harness itself adds.** Each `openstack` CLI call costs seconds of Python start-up on `devstack`, so workers do not poll on their own. A single observer polls Nova's server list and SPIRE Server's agent list for all instances every 5 seconds and passes state changes to the workers, which only issue actions (create, stop, start, delete, evict) and run the in-guest checks. SSH connections to the lab VMs are multiplexed (`ControlMaster`).

## Detection

Every check that fails produces a **failure record**. The harness then gathers evidence and carries on: a failed cycle deletes its instance (unless kept) and frees its slot for the next cycle.

**Classes**:

| Class | Examples | Counts against the verdict |
| --- | --- | --- |
| `node` | agent not attested within its bound; wrong SPIFFE ID or missing `project_id`/`instance_id` selectors; issuer refused or failed `/attest` for the instance; server plugin rejected its token; more than one "token already used" | yes |
| `workload` | no SVID within its bound, wrong SPIFFE ID, chain not verifying, SVID issued to `outsider` | yes |
| `invariant` | see run-wide checks below | yes |
| `infra` | instance in `ERROR`, boot or delete timeout, guest unreachable over SSH | only above `--max-infra-rate` (default 5% of cycles) |
| `capacity` | `NoValidHost` | no |
| `harness` | the harness's own errors (a malformed CLI output, an SSH failure to a lab VM) | no, but reported first: they make the run's other results doubtful |

A failure is classed by its first failing step and what the logs say about it. An agent that never attests because the guest never got a network is `infra`, recognised from the console log and the absence of any `/attest` call for the instance. An agent that never attests because `/attest` returned `500` is `node`.

**Run-wide checks** (class `invariant`), from the services' journals, which the harness follows for the whole run (`journalctl -f -o json` on `issuer-a`, `issuer-b`, `spire`, and `nova-api-metadata` on `devstack`), saved in the run's directory:
- Every `agent_attested` record on `spire` has a `token_issued` record with the same `jti` on one of the issuers (AUD-3), and no `jti` is attested twice.
- No attestation fails on an unknown `kid`, including across rotations with `--rotation`.
- No `reattest_alert` for a `create` cycle's instance. For a `restart` cycle, one is acceptable only when its SVID expired while it was stopped (see cycles).
- No `error`-level record from either issuer or the server plugin, except for those that explain a failure already recorded in another class.
- Both issuers stay ready: `/readiness` is polled every 30 seconds; a non-ready answer is a failure with its reason.
- Resource drift: the RSS of both signers and of SPIRE Server is sampled every minute. A sustained growth (a linear fit over the last half of the run, above 10% of the starting value per hour) is reported as a `warning` in the report, not a failure: an hour is too short to tell a leak from a cache filling up. Longer runs make it meaningful.
- Counters agree: `issuer-a`'s `openstack_spire_tokens_issued_total` (from its Prometheus endpoint) has grown by the number of its `token_issued` records during the run. Nova calls only `issuer-a`, so `issuer-b` issues no token in a run, and its OTLP output is not compared. The check is skipped when `issuer-a` restarted during the run (the self-test), since its counter restarts too.

**Evidence** for each failure, in `failures/<cycle>/`: the instance's console log (`openstack console log show`), the guest's `spire-agent` and `cloud-init` journals when the guest is reachable, the issuers', SPIRE Server's and `nova-api-metadata`'s journal lines for the instance's ID and `jti`s around the failure, the output of `spire-server agent show`, and the step's own output. A failed instance is kept, up to `--keep-failed`, with its name in the report, for `lab.sh ssh` inspection; `lab.sh stress --cleanup` deletes kept instances later.

## Records and report

The run's directory holds:
- `run.json`: options, seed, git commit and dirty flag, the versions from `env.json`, start and end times, the changes made in setup.
- `events.jsonl`: one structured record per cycle step (`log/slog` JSON: `cycle`, `kind`, `distro`, `instance_id`, `step`, `outcome`, `duration`, `class`, `jti`), written as it happens, so that an interrupted run still has its record.
- `samples.jsonl`: the parallelism target, the capacity inputs, readiness and RSS, every minute.
- `journals/`: the followed journals.
- `failures/`: the evidence above.
- `report.txt` and `report.json`: the summary.

The report gives: cycles started, passed, failed and aborted, by kind and by distro; failures by class, each with its cycle and a one-line reason, `harness` failures first; latency of each step (boot, node attestation, workload SVID, restart, delete) as minimum, p50, p95, p99 and maximum; the parallelism reached; the drift warnings; and the verdict. `lab.sh stress` prints `report.txt` at the end.

**Exit status**: 0 when no failure counts against the verdict, 1 when one does, 2 when only the infra rate was exceeded, 3 when the lab could not be prepared or torn down.

## Code structure

The acceptance tests' helpers (SSH, the `openstack` CLI, booting guests, SPIRE Server queries, journals) live in `test/lab/acceptance/lab_test.go`, bound to `testing.T`. They move to a package `test/lab/labkit` (behind the `lab` tag) that both the acceptance tests and the harness use. In it, they take a `context.Context`, return wrapped errors instead of calling `t.Fatal`, and log with `log/slog`. The acceptance tests keep thin `t.Helper` wrappers and do not change their behaviour. The harness itself:

- `test/lab/stress/main.go`: options, signals, lifecycle.
- `scheduler`: parallelism target and cycle choice, with the seed.
- `observer`: the single poller of Nova and SPIRE Server.
- `cycle`: the two cycle kinds as step sequences with bounds.
- `detect`: journal following, the run-wide checks, failure classification.
- `report`: records and summary.

The scheduler, classification, run-wide checks and report sit behind an interface to the lab, so that they have unit tests against a fake lab and run with `go test -tags lab ./test/lab/...` without a lab.

## Acceptance criteria

- **ST-1, unit tests (no lab)**: the scheduler never exceeds the target and adjusts it as specified; a seed reproduces the same cycle sequence; each failure example in the classes table, fed to the classifier from recorded outputs, gets its class; the run-wide checks flag an `agent_attested` without a matching `token_issued`, a duplicate `jti`, a `reattest_alert` on a `create` cycle, and pass on the clean case; the exit status follows the verdict; `--bound` overrides only the named steps and refuses unknown names and non-positive durations.
- **ST-2, clean run**: `lab.sh stress --duration 30m` on a freshly reset lab completes with exit status 0, at least 2 parallel cycles reached, both cycle kinds and both distros run, and leaves no `stress-` instance, registration entry, quota change or issuer configuration change behind.
- **ST-3, the harness sees failures** (self-test, `lab.sh stress --self-test`, a short run that injects known faults and expects them to be found; unless given, it runs for 25 minutes, with an `attest` bound of 2 minutes so that the `issuer-a` outage outlasts it, and keeps no failed instance): stopping `issuer-a` for 3 minutes produces `node` failures for the cycles attesting meanwhile, with evidence naming the refused vendordata call, and the run recovers afterwards. Removing the workload entry produces `workload` failures. Restarting SPIRE Server (which clears the plugin's replay and re-attestation caches) does not produce false `invariant` failures.
- **ST-4, interruption**: `SIGINT` during a run drains and tears down; a second `SIGINT` aborts and still tears down; `kill -9` followed by a new run cleans the leftovers in step 2.
- **ST-5, TOFU**: `lab.sh stress --tofu --agent-ttl 15m --hold 5m-10m --duration 30m` exits with status 0 and reports at least one SVID renewal and no re-attestation. A deliberate re-attestation of an attested, non-evicted agent during it (the self-test's TOFU step: wiping a guest's agent data directory and restarting the agent) is refused and recognised as expected. `--agent-ttl 10m` is refused at start.
- **ST-6, chaos**: `lab.sh stress --chaos --duration 1h` injects both faults at least once and exits with status 0. The unit tests also check that a failure inside a fault's window still counts against the verdict, and that the extended bounds and the single transient rejection are applied only inside the window.
- **ST-7, one hour**: the default `lab.sh stress` (1 hour) runs to completion on the reference host. Its report is attached to the commit that closes this spec, as the baseline for later runs.

## Changes to other specs

- Test environment spec: the non-goal becomes "Load and performance testing; soak and stress testing are in the stress test spec". The lifecycle gains `stress`, and the acceptance tests' section notes that the helpers live in `labkit`. Guest configurations gain the `workload` and `outsider` users.

## Implementation plan

1. Move the helpers to `labkit`; the acceptance tests pass unchanged on the lab.
2. The harness skeleton: options, lifecycle (prepare, check, set up, tear down, signals), records; the `workload` and `outsider` users in `deploy`. ST-4.
3. The observer, the cycles and workload attestation, with fixed `--parallel`. ST-1 for the cycles.
4. Detection: journals, run-wide checks, classification, evidence. ST-1, ST-3.
5. `--parallel auto` and the report. ST-1, ST-2.
6. `--agent-ttl` and `--tofu`, with the cycles' TOFU expectations. ST-5.
7. `--chaos`. ST-6.
8. The one-hour baseline, ST-7; README's Lab section and the test environment spec.

## Resolved questions

- Cycle kinds (decided Oct 17): both `create` and `restart`, weighted 3 to 1 by default.
- Infra failures (decided Oct 17): they count against the verdict only above `--max-infra-rate`, 5% of cycles by default.
- Lab preparation (decided Oct 17): the harness refuses to run without a lab, and never runs `up` itself.
- TOFU mode (decided Oct 17): `--tofu`, with `--agent-ttl` so that renewals happen within a run.
- Fault injection (decided Oct 17): `--chaos`, limited to faults that must cause no failure (restarting `issuer-b`, restarting SPIRE Server). Faults expected to cause failures are left to a later spec.
- Step bounds (decided Oct 17): defaults per step, each overridable with `--bound`.
