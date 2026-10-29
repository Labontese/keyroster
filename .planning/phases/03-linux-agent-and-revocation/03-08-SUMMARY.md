---
phase: 03-linux-agent-and-revocation
plan: 08
subsystem: agent
tags: [agent, heartbeat, host-status, drift, krl-stale, clock-skew, identity-rotation, systemd, openrc, forget, capslock]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-05: generations, the pending marker, last-good and RollbackTarget; 03-06: Check (drift), Detect, preflight, phase2_adoption_pending; 03-07: the agent listener, requireAgent, the agent limiters, the outbox, accepted.json, host forget (D-R1)"
provides:
  - "internal/agent/heartbeat: the closed Status and Heartbeat types, Validate, ParseStatus, ParseHeartbeat, ClockSkew (portable; server, CLI, applier and fetcher share them)"
  - "apply.WriteStatus (outbox/status.json 0640 plus the state copy heartbeat.json 0600), apply.LogKRLAge, KRLStaleAfter; keyroster-agent run checks drift after every apply and every 15 min +- 60 s"
  - "apply units: ApplierSystemdUnit, FetcherSystemdUnit, ApplierOpenRCScript, FetcherOpenRCScript; keyroster-agent install --bin-dir writes them; paths.Layout.ServiceFiles"
  - "fetcher: heartbeat after every answered poll with clock_offset_s; --rotate-identity with identity.next, identity.lock and the unknown_agent fallback; fetch_dir_not_owned"
  - "server: POST /api/v1/agent/heartbeat, POST /api/v1/agent/identity, GET /api/v1/admin/hosts/status; refusals stale_heartbeat, heartbeat_field_invalid, identity_rotation_invalid, host_removal_not_applied; serverdb 0006_heartbeats.sql (heartbeats, agents.removed_dir_version)"
  - "CLI: keyroster host status [--json]; host pending lists served hosts; host forget --host-gone"
  - "execsite.SSHDVersion (sshd -V), the applier's one new exec site"
  - "test/systemd/agent-smoke.sh and TestAgentSystemdSmoke in the systemd-sandbox job; TestAgentStatusEndToEnd"
affects: [03-08b, 03-09, 03-10, 03-12, 03-14, 03-16]

actuals:
  tokens: 68038
  tasks: 3
  commits: 8
plan_head_before: 74504cf98683a7a232ab64e49187d2d1f4963aaf
plan_head_after: 1881498

tech-stack:
  added: []
  patterns:
    - "The applier never reads its outbox: what it needs again (the last status, seq) is in its own state copy"
    - "Every host-supplied field is validated twice by the same function (heartbeat.Validate): by the server before storage, and by the CLI before printing"
    - "A host's silence is judged from its last authenticated request, not from its heartbeat (owner decision D-2)"

key-files:
  created:
    - internal/agent/heartbeat/heartbeat.go
    - internal/agent/heartbeat/heartbeat_test.go
    - internal/agent/apply/status.go
    - internal/agent/apply/status_test.go
    - internal/agent/apply/units.go
    - internal/agent/apply/units_test.go
    - internal/agent/fetch/heartbeat.go
    - internal/agent/fetch/heartbeat_test.go
    - internal/serverdb/migrations/0006_heartbeats.sql
    - internal/server/heartbeat_test.go
    - cmd/keyroster/hoststatus.go
    - cmd/keyroster/hoststatus_test.go
    - cmd/keyroster-agent/units_test.go
    - test/e2e/agent_status_test.go
    - test/e2e/agent_systemd_test.go
    - test/systemd/agent-smoke.sh
  modified:
    - internal/agent/apply/apply.go
    - internal/agent/apply/run.go
    - internal/agent/apply/installed.go
    - internal/agent/apply/sshd.go
    - internal/agent/execsite/execsite.go
    - internal/agent/paths/paths.go
    - internal/agent/fetch/fetch.go
    - cmd/keyroster-agent/install.go
    - cmd/keyroster-agent-fetch/main.go
    - internal/server/agent.go
    - internal/server/hosts.go
    - internal/server/server.go
    - internal/serverclient/agent.go
    - internal/serverclient/client.go
    - internal/serverdb/agents.go
    - cmd/keyroster/host.go
    - test/e2e/agent_enroll_test.go
    - test/capslock/keyroster-agent-fetch.json
    - .github/workflows/systemd.yml
    - docs/runbooks/host-setup.md
    - .planning/phases/03-linux-agent-and-revocation/03-08-PLAN.md
    - .planning/todos/pending/2026-10-28-audit-host-forget-and-directory-reset.md

key-decisions:
  - "03-08 owner decision D-1 (2026-10-28): host forget waits for the heartbeat that shows the removal applied (host_removal_not_applied) with an explicit --host-gone override, printed and logged; forget stays single-admin with a server log line, and 03-08b adds leaf kind 16, a signer-checked admin quorum and an audit record for forget and --host-gone (threat row T-03-282)"
  - "03-08 owner decision D-2 (2026-10-28): silent is judged from agents.last_seen_us (every authenticated request); the server stores a status body only on a higher seq; the fetcher treats 409 stale_heartbeat as quiet"
  - "03-08: removed_dir_version is recorded on an approved-once agent's first request under a directory in which no entry holds any of its keys, and cleared when an entry holds them again; a disabled or re-keyed entry does not count as the removal"
  - "03-08: the applier unit creates sshd's privilege separation directory /run/sshd before it starts (ExecStartPre=+install -d), because a socket-activated ssh.service creates it only once a connection started sshd"
  - "03-08: Status and Heartbeat are one portable type shared by both sides (internal/agent/heartbeat), not two mirrored structs"

patterns-established:
  - "A host-reported field reaches an admin's terminal only after heartbeat.Validate and heartbeat.Sanitize"

requirements-completed: [AGENT-07, AGENT-05]

duration: 330min
completed: 2026-10-29
status: complete
---

# Phase 3 Plan 08: Agent Operations Summary

**Every enrolled host now reports what it applied. The root applier writes a validated status into its outbox after every apply and every drift check, and the unprivileged fetcher posts it with its clock offset after every poll. `keyroster host status` shows convergence (`KRL v<k> on n/m hosts`) and the `silent`, `krl_stale`, `clock_skew`, `pending` and `stuck` alerts. Agent identities rotate safely. Both processes run as hardened systemd units (exposure 1.2 and 2.0), which `keyroster-agent install` writes and which a real-systemd smoke test runs in CI against the runner's own socket-activated `ssh.service`.**

PR: **#72** (`p03/08-agent-operations`), opened without auto-merge. AGENT-07 and AGENT-05 are complete as CI-verified; real hosts re-check them in 03-16.

## Owner attention first

1. **A product bug found by the systemd smoke test, and fixed (commit `f3d142f`).** On Ubuntu 24.04's default socket-activated `ssh.service`, `/run/sshd` (sshd's privilege separation directory) exists only once a connection has started sshd, and `sshd -t`/`-T` refuse without it. The applier could not answer the enrollment: `sshd_T_failed: Missing privilege separation directory: /run/sshd`. After a boot it could neither apply nor check, and the first connection would start sshd with the trust files from before the boot, the revocations since then missing. The applier unit now runs `ExecStartPre=+/usr/bin/install -d -m 0755 -o root -g root /run/sshd` (outside its sandbox). The plan does not name this line. **Fix round 1: kept by the owner (D-R3), an owner-approved deviation; `TestUnits/applier_unit` pins the exact line.** The alternative was to have the applier connect to sshd once to start it, which turns the self-test's loopback dial into a trigger. A hand-run `apply --once` on such a host before the unit ever ran still needs `install -d /run/sshd` first (host-setup.md says so).
2. **Carry-over (b), as decided (D-1).** Forget refuses `host_removal_not_applied` until the host's newest heartbeat shows a committed directory version at or above `removed_dir_version`. `--host-gone` overrides it; the CLI prints the override and the server logs it at warning level with the admin's name. The removal version is the first version the server served the agent in which **no** entry holds its keys (a disabled entry does not count). It was found in self-review before the first commit: disabled at v3, applied, then removed at v4 would otherwise pass forget on a v3 heartbeat. `TestHostForgetWaitsForRemoval/disabled_first_then_removed_waits_for_the_removal` pins it. Quorum and the audit leaf are 03-08b's (T-03-282; the todo says "forget half: 03-08b").
3. **Silence and clock skew follow D-2.** `silent` uses `last_seen_us`. Consequence: `clock_offset_s` (and so `clock_skew`) is the offset carried by the stored heartbeat, the one with the highest seq. Between status writes (up to 15 min) the fetcher's later offsets are in heartbeats the server refuses as stale. The fetcher logs a skew above 300 s at every poll; the server's flag can lag by up to one check period. **Fix round 1 (D-R2): superseded. The server now keeps the offset of every heartbeat that parses, stale ones included, so the flag no longer lags.**
4. **capslock: keyroster-agent-fetch 21 -> 23 pairs, still no EXEC.**
   - New: READ_SYSTEM_STATE for `cmd/keyroster-agent-fetch` and `internal/agent/fetch` (`os.Getenv("JOURNAL_STREAM")` in `journalPrefix`, for the `<3>` priority of the clock_skew line), and REFLECT for `internal/serverclient` (`PostJSON` -> `encoding/json.Marshal`, from `AgentRotateIdentity`).
   - No longer reported: `internal/trust` REFLECT.
   - keyroster-agent stays at 37 pairs and the signer at 92. EXEC still leaves the module only through execsite (2 edges).
   - dep-firewall: all four targets clean, and the fetcher has no os/exec.

## Accomplishments

- **Status (`internal/agent/heartbeat`, `apply/status.go`).**
  - A closed struct under the pinned JSON names, carrying:
    - `agent_version`;
    - bundle, policy and directory `{version, sha256}`;
    - KRL `{version, sha256, issued_at}`;
    - `generation` and the SHA-256 of every file of the committed generation (plus `files_truncated` above 256 files);
    - `dropin_sha256` and `sshd_version` (`sshd -V`);
    - the four effective trust settings;
    - `last_apply {at, result, rollback, error, detail, host_status}` and `last_check {at, drift}`;
    - `pending`, `stuck`, `krl_stale` and `seq`.
  - Written with `spool.WriteFileAt` to `outbox/status.json` (0640) and to the applier's own copy `heartbeat.json` (0600), from which seq and the last apply and check are carried. The applier never reads the outbox.
  - `seq = max(previous + 1, now in µs)`.
  - While a swap is pending, `generation` and `files` are the marker's `from`, and the KRL is the one in the generation `current` names (03-05's inherited rule).
  - `krl_stale` is set at 24 h, with a `<3>` error line on every check under journald; nothing else changes.
- **Validation.** `heartbeat.Validate` implements every rule of the must_haves:
  - uint64 versions;
  - 64-hex hashes, empty only with version 0;
  - at most 256 sorted, unique files under the path grammar, each at most 128 bytes;
  - closed `result`, `pending.step`, `stuck` and `host_status`;
  - `detail` matching `^[a-z0-9_]+(:[a-z0-9_]+)?$` within 64 bytes;
  - free text of at most 512 bytes of printable ASCII;
  - trust timestamps;
  - seq from 1 to the largest int64.

  The server and the CLI both run it, and the CLI also replaces non-printable bytes with `?`. Fuzz targets: `FuzzParseHeartbeat`, `FuzzParseStatus`.
- **Run loop (AGENT-05).**
  - A status is written at start, so a host that never applied reports generation 0.
  - The drift check runs after every round that applied, and every 15 min ± 60 s on the injected clock, in the applier's goroutine. Each check writes a status and logs drift and staleness.
- **Fetcher.**
  - Heartbeat after every poll the server answered. `clock_offset_s` is the Date header minus local time at receipt, in whole seconds; a clock_skew error line is logged above 300 s; `stale_heartbeat` is quiet.
  - `--rotate-identity` writes `identity.next` before the POST. Polls and rotation share `identity.lock`, and every poll reloads the identity from disk. `unknown_agent` with an `identity.next` present triggers a retry with it and promotion on 200; an `identity.next` the server never took is removed after the old key's next 200.
  - The fetcher refuses `fetch_dir_not_owned` when its euid does not own `--dir`, so a root rotation cannot leave keys the service cannot read.
- **Server.**
  - The heartbeat route: `requireAgent`, a 64 KiB cap (413), strict decoding and validation (400 `heartbeat_field_invalid` with `field`), and a single-statement upsert `WHERE excluded.seq > heartbeats.seq` (409 `stale_heartbeat`).
  - The identity route: the old key's Ed25519 signature over `keyroster/agent-identity/v1 || 0 || new SPKI`; the new key must be Ed25519 and not the old one (403 `identity_rotation_invalid`); 409 `identity_in_use`.
  - `hosts/status`: per approved-once agent, its name and directory state, `last_seen` and `silent` (> 180 s), the heartbeat, `clock_skew`, `never_applied`, and the current versions.
  - `TestAgentMuxRoutes` lists exactly enroll, state, heartbeat and identity.
- **Units (D-05).**
  - The applier runs as root without capabilities: `NoNewPrivileges`, `ProtectSystem=strict`, exactly `ReadWritePaths=/etc/ssh/keyroster /etc/ssh/sshd_config.d /var/lib/keyroster-agent`, `IPAddressDeny=any`, `IPAddressAllow=localhost`, `SystemCallFilter=@system-service`.
  - The fetcher runs as `User=keyroster-agent` with an empty `CapabilityBoundingSet`, exactly `ReadWritePaths=/var/lib/keyroster-agent-fetch /var/lib/keyroster-agent/spool`, and TCP only.
  - OpenRC scripts: the fetcher has `command_user="keyroster-agent"`.
  - `install` refuses `install_no_service_manager` and, on a systemd host, `install_no_sshd_config_d`. It creates `/etc/ssh/keyroster` before the units. `paths.Allowed` gains exactly the four service paths.
- **Carry-over (a).** An agent approved once that the directory no longer approves (removed, disabled or keys changed) is listed under `served` in host pending, printed as `Host <name>: removed, served until forget`, and shown in `host status` with that state. `host approve <name>` refuses it with the way out (add the entry back, or forget and re-enroll).
- **Runbook.** host-setup.md gains:
  - "Running the agent": the units, their exact writable paths, the Phase 2 `apply --once`, `/run/sshd`, starting the units, the status table, the alerts, `clock_offset_s`'s 1 s resolution, and rotation;
  - "Manual recovery";
  - "Removing a host": the heartbeat wait, `host_removal_not_applied`, `--host-gone`, and no quorum or audit leaf until 03-08b;
  - new rows in the refusal table, and the drift period.

## Task commits

| Commit | Task / item |
|---|---|
| `6d8427d` feat(agent): report each host's applied state in heartbeats and show convergence in keyroster host status | Task 1 (tracer); Task 2's identity rotation and heartbeat edge tests; **carry-over (a)**; **carry-over (b)**; conflicts 2, 4, 5 |
| `266045e` feat(agent): install hardened systemd units or OpenRC scripts for both agent processes | Task 2 (units, OpenRC, install, paths.Allowed) |
| `fea5093` fix(agent): write the outbox's accepted.json without reading the outbox back | conflict 3 |
| `6052c2d` test(agent): run both agent units under real systemd in the systemd-sandbox job | Task 3 (agent-smoke.sh, workflow) |
| `a1bc84a` docs(agent): document running and watching the agent, forget's removal wait and manual recovery | Task 3 (runbook), carry-over (b) docs, plan threat rows, todo |
| `855f65b` test(agent): build the systemd smoke test and annotate the planted-file write | Task 3 fix (the first systemd run did not build) |
| `f3d142f` fix(agent): create sshd's privilege separation directory before the applier unit starts | Task 3 finding (Owner attention 1) |
| `1881498` ci(agent): gate systemd-analyze security on the agent units' measured exposure | Task 3 thresholds |
| this file's `docs(03-08)` commit | SUMMARY, STATE.md, ROADMAP.md, REQUIREMENTS.md |

Carry-overs (a) and (b) are in `6d8427d` rather than in their own commits. They share `hosts.go`, `agent.go`, `serverclient/agent.go` and `host.go` with the status view; splitting them would have meant committing intermediate file versions that were never built. Every commit is SSH-signed by keyroster-bot (`%G?` = G against the configured key) and has no attribution lines.

## The heartbeat in CI (Task 1's tracer gate)

E2E run **40784522314** on `a1bc84a`, both lanes green, `--- PASS: TestAgentStatusEndToEnd` (190 s and 192 s):
- after the first apply: `bundle v1 on 1/1 hosts`, `directory v4 on 1/1 hosts`, `KRL v1793228727 on 1/1 hosts`;
- after `keyroster revoke serial` and one poll: `KRL v1793228731 on 1/1 hosts`;
- a KRL issued 24 h 1 min earlier, signed by the test ops key: the applier's line `<3>keyroster-agent run: ERROR krl_stale: the installed KRL version 1793228732 was issued at 2026-10-27T23:04:33Z, 24h0m0s or more ago; ...`; certificate c2 logs in while `krl_stale` is set, and c1 is still refused (`revoked by file`);
- the fetcher stopped: not silent at 3m0s (2m58s on 9.5p1), silent at 3m4s (3m2s), measured on the server's clock through `last_seen`; the 180/181 s edge itself is `TestHeartbeat/silent_boundary_180_not_181`.

The tracer's e2e cannot run in WSL (keyroster.localhost), so Task 2 was built before it ran in CI. That is deviation 1, as in 03-07.

## The systemd smoke test (Task 3)

Systemd run **40786881636** on `f3d142f` (systemd 255.4, OpenSSH 9.6p1 Ubuntu-3ubuntu13.20, kernel 7.0.0-1017-azure), `--- PASS: TestAgentSystemdSmoke` (255 s):
- install wrote the units, systemd started both, the host enrolled and was approved;
- the first apply reloaded sshd with `/usr/bin/systemctl try-reload-or-restart ssh.service`: **the runner uses socket activation**;
- a certificate logged in as `krsmoke` to the runner's own `ssh.service` on 127.0.0.1:22;
- `keyroster host status` showed the host on the current versions;
- `--rotate-identity` as root was refused `fetch_dir_not_owned`; as `keyroster-agent` it rotated, and the running service polled with the new identity;
- systemd loaded the units: the fetcher's `User=keyroster-agent`, both exact `ReadWritePaths`, `IPAddressDeny=0.0.0.0/0 ::/0`, `IPAddressAllow=::1/128 127.0.0.0/8`; the fetcher's process had `CapEff 0`, `NoNewPrivs 1` and `Seccomp 2`;
- as the real `keyroster-agent` user, every attempt was refused with Permission denied: creating a file in `/var/lib/keyroster-agent`, in `accepted/` and in the outbox, overwriting `pins.json`, `outbox/status.json` and `outbox/accepted.json`, and replacing `outbox/status.json` by a rename from the spool. Reading `outbox/status.json` and creating and removing a file in the spool were allowed. This closes 03-07's deferred cross-user check of `outbox/accepted.json`;
- **`systemd-analyze security`**: `keyroster-agent-fetch.service` **1.2** (OK) and `keyroster-agent.service` **2.0** (OK). The thresholds are now 15 and 20 (exposure ×10 rounded up to the next 5), recorded in the workflow comment.

The first systemd run (40784522353) did not build the smoke test, and the second (40785872516) found the `/run/sshd` problem; both are fixed in the commits above.

## What ran and what did not

**Ran:**

- **WSL (Ubuntu, Go 1.27.3), on copies built from `git ls-files -co --exclude-standard` or from `git archive` of the staged tree and of HEAD, removed afterwards:**
  - the full gate on `a1bc84a`'s code: `CGO_ENABLED=1 go test -race -count=1 ./...`; `go vet` for linux, windows and darwin, with `-tags e2e`, `-tags "e2e systemdsmoke"` and `-tags e2edistro`; gofmt; golangci-lint for three GOOS; capslock-check (92/37/23); dep-firewall; testonly-firewall; check-pinned-actions. It had two failures; their fixes were verified in CI, not by a second local run of the gate (corrected in fix round 1);
  - each commit's staged tree: vet and the agent, server and CLI unit tests;
  - the 33 mutants below;
  - `FuzzParseHeartbeat` and `FuzzParseStatus` for 20 s each with `-fuzzminimizetime 5s`: about 1.2 M and 0.9 M executions, no finding.
- **Windows (Go 1.27.1):** the server, serverdb, serverclient and CLI tests, and the heartbeat package with both fuzz targets.
- **CI:** the E2E and Systemd runs above. The PR's required checks on the final head are in the handback.

**Mutants (each applied in the WSL copy, its named test run, the file restored byte for byte): 33 run, 33 killed.**

| # | Mutant | Killed by |
|---|---|---|
| M1 | upsert on `>=` (an equal seq stored) | `TestHeartbeat/equal_seq_refused` |
| M2 | silent at `>=` 180 s | `silent_boundary_180_not_181` |
| M3 | silent from the heartbeat's receipt instead of `last_seen` | `silent_boundary_180_not_181` |
| M4 | skew at `>=` 300 | `clock_skew_boundary_300_not_301` |
| M5 | detail grammar loosened to `[a-z0-9_:]+` | `detail_field_validated` |
| M6 | `sshd_version` not checked | `escape_sequence_in_sshd_version_refused` |
| M7 | file order not checked | `files_sorted_by_path` |
| M8 | staleness at `>` 24 h | `TestStale` |
| M9 | seq without `prev + 1` | `TestStatus/seq_grows_and_survives_a_reset` |
| M10 | seq without the clock | the same |
| M11 | generation from `current` while a swap is pending | `TestStatus/pending_swap_reports_the_committed_generation` (first a survivor: the test crashed before the first swap, where both are equal; it now crashes at the intermediate) |
| M12 | the applier reads the outbox's status | `applier_never_reads_the_outbox` |
| M13 | served hosts listed as pending | `TestServedHostsNeverPending` |
| M14 | approve ignores served hosts | `TestServedHostNotPending/approve_refuses_a_served_host` |
| M15 | forget gate removed | `TestHostForgetWaitsForRemoval` |
| M16 | `host_gone` ignored | `host_gone_overrides_and_is_logged` |
| M17 | the removal recorded while an entry still holds the keys | `disabled_first_then_removed_waits_for_the_removal` |
| M18 | the CLI does not send `host_gone` | `TestHostForgetHostGone` |
| M19 | `Once` without the flock and the reload | `TestIdentityRotation/rotation_concurrent_with_poll` |
| M20 | no `recoverRotation` | `rotation_response_lost_recovers` |
| M21 | `identity.next` written after the POST | `TestIdentityRotation` |
| M22 | `stale_heartbeat` an error | `TestHeartbeatPost/stale_heartbeat_quiet` |
| M23 | `/etc/ssh/keyroster` not in install's layout | `TestUnits/install_creates_readwrite_dirs` |
| M24 | no `sshd_config.d` refusal | `TestUnits/no_sshd_config_d_refused` |
| M25 | the applier's writable path widened to `/etc/ssh` | `TestUnits/applier_unit` |
| M26 | `IPAddressAllow` dropped | `TestUnits/applier_unit` |
| M27 | the fetcher's OpenRC script without `command_user` | `TestUnits/openrc_scripts` |
| M28 | no periodic check | `TestRunChecks` |
| M29 | the CLI's check of the answer off | `TestHostStatus/escape_from_the_server_refused` |
| M30 | convergence counts a pending swap | `TestHostStatus/table` |
| M31 | rotation accepts any signer | `TestIdentityRotation/signature_by_another_key_refused` |
| M32 | the server's field check skipped | `escape_sequence_in_sshd_version_refused` |
| M33 | `WriteAccepted` reads the outbox back | `TestWriteAccepted` |

Two mutants (M22, M28) did not compile at first and were rewritten as `false &&` guards. Not mutated: the `ExecStartPre` line (pinned by `TestUnits/applier_unit`, and its effect shown by the systemd run that failed without it).

**UNVERIFIED (not run here):**

- **OpenRC**: both scripts and the `rc-update` and `rc-service` lines; the other distributions' service managers. Until 03-16 (PLAT-01).
- **Every homelab step**, until 03-16: the units on real hosts, `host status` against real hosts, the removal and forget order with a real heartbeat, `--host-gone`, rotation, and manual recovery with `--recover-to-last-good`.
- **The hand-run `apply --once` on a socket-activated host before the unit ever ran** (the runbook's `install -d /run/sshd`).
- **`files_truncated`** (more than 256 generation files): set by the code, never produced by a test of the applier.
- **The applier's `<3>` line under journald**: the e2e run shows it because the runner's environment has `JOURNAL_STREAM`; the smoke run's applier journal was not grepped for a stale KRL (none was stale there).

## Decisions Made

See `key-decisions` in the frontmatter. D-1 and D-2 are the owner's (2026-10-28).

## Deviations from Plan

### Auto-fixed and plan-versus-code reconciliations

1. **[Process] Task 2 built before the tracer's CI run.** The tracer's e2e needs keyroster.localhost, which WSL cannot resolve. Task 2 was written and unit-tested before E2E run 40784522314 proved the tracer; that run is green.
2. **[Conflict 2] Where status.json lives.** The existing `<state>/status.json` (the applier's report, `statusDoc`) stays: the e2e tests, `reset-directory`'s message and the runbook read it. The plan's Status is a new file, `<state>/outbox/status.json`, plus the applier's own copy `<state>/heartbeat.json`.
3. **[Conflict 3] The applier read `outbox/accepted.json` back** (03-07's `WriteAccepted`). It now writes after every apply without reading (`fea5093`, M33).
4. **[Conflict 4 / carry-over a, Rule 1 bug] A removed or disabled approved-once agent was listed as pending**, and `host approve` could pick its identity. Fixed with a test (`TestServedHostsNeverPending`, `TestServedHostNotPending`).
5. **[Conflict 5 / carry-over b] Forget's gate needed the heartbeats table.** It lives in Task 1's migration (`agents.removed_dir_version` beside `heartbeats`), and `hostHolds` is shared by forget's `host_in_directory` and the removal recording.
6. **[Conflict 6] Already in place from 03-07.**
   - `last_seen_us` is now the source of `silent` (D-2).
   - The heartbeat and identity routes go through `requireAgent`, so the agent limiter class (burst 64) charges them. A poll costs two requests a minute.
7. **[D-2] The plan's "silent when the last heartbeat is more than 180 s old"** is the last authenticated request, so a refused stale heartbeat also keeps a host from being silent (`silent_boundary_180_not_181` checks that too).
8. **[Plan detail] One shared type.** Status and Heartbeat are one portable package (`internal/agent/heartbeat`), not a struct per side. The heartbeat body nests the status (`{"status": ..., "clock_offset_s": N}`), so the fetcher checks the file it reads with the server's own rules.
9. **[Plan detail] `files_truncated`.** The directory has no account cap, so a generation can hold more than 256 files. The status lists the first 256 by path and says so, instead of a list the server would refuse.
10. **[Plan detail] `last_apply.result`.** `refused` covers the verification, preflight, adoption, clock-bound and `pending_state_unknown` refusals (`applyResult`); a tool failure is `error`; a rollback is `rolled_back`.
11. **[Plan detail] Where the KRL comes from while a swap is pending.** It is the one in the generation `current` names (03-05's inherited rule). The generation and files are the marker's `from`. The issued_at of a KRL that a rollback kept newer than `accepted/` is unknown, and its age is measured from the older accepted manifest (an alert may come early, never late).
12. **[Plan detail] Where the tests live.** `TestUnits` exists in both `internal/agent/apply` (rendering) and `cmd/keyroster-agent` (install). `TestIdentityRotation` exists in both `internal/server` (the server's rules) and `internal/agent/fetch` (the client cases). `TestStatus/clock_offset_whole_seconds` is in the fetcher. The fetcher's heartbeat cases are `TestHeartbeatPost`. The run loop's cases are `TestRunChecks` and `TestCheckJitter`.
13. **[Plan detail] The smoke test's mechanics.** agent-smoke.sh runs a Go test (`TestAgentSystemdSmoke`, tags `e2e systemdsmoke`) as root, which reuses the e2e harness's signer, server and CLI bootstrap instead of replaying it in bash. The script does the cross-user writes and `systemd-analyze` itself. The smoke test also rotates the identity with the real users (not in the plan).
14. **[Plan detail] The silent e2e uses real time.** The server binary has no clock injection, and adding one would be production surface. The e2e waits for real time with the fetcher stopped and logs both sides of the edge; the exact 180/181 s is the unit test's.
15. **[Rule 2] `install_no_sshd_config_d` and `fetch_dir_not_owned`.** The first: systemd refuses a unit whose `ReadWritePaths` path is missing, and the agent never creates sshd's directory. The second: a rotation run as root would leave keys the service cannot read.
16. **[Rule 1, found in CI] `/run/sshd`** (Owner attention 1, `f3d142f`).
17. **[Rule 1, found in review] The removal version was first recorded when an entry still held the keys** (Owner attention 2); fixed before the first commit, with M17.
18. **[Plan detail] `sshd -V`** is a new execsite constructor (`SSHDVersion`, pinned in `paths.ExecSites`). It is the plan's own field; it is not a new `os/exec` site. An sshd without `-V` prints its version in its usage text, which is taken from there.

**Total deviations:** 18, of them 3 Rule 1, 1 Rule 2, 5 plan-versus-code reconciliations, 1 owner decision and 8 plan details. No Go module was added. The applier's one new exec target is `sshd -V`, through execsite; the fetcher has no exec site.

## TDD Gate Compliance

Task 2 is `tdd="true"`, but the tracer had built most of the code first, as in 03-05 to 03-07. There is no separate RED commit, and RED was not faked. The evidence instead:
- the 33 mutants above;
- the real RED runs: `TestStatus/pending_swap...` passing on mutant M11 led to a better test; `TestRunChecks` failed until the default jitter was accounted for; the systemd job failed twice before it passed.

## Issues Encountered

- **Backslashes in shell heredocs.** Several edits made through a Bash heredoc turned `\n` inside Go strings into newlines. Each was caught by the build or by gofmt and redone with the Edit tool; nothing broken was committed.
- **`TestFetch/more_repolls_immediately`** (a 900 ms bound) failed once under the full parallel test run in WSL and passed 5 of 5 alone. It is a pre-existing timing test, sensitive to load.

## Known Stubs

None.

## Threat Flags

| Flag | File | Description |
|---|---|---|
| threat_flag: new agent route | internal/server/agent.go | `POST /api/v1/agent/heartbeat`: host-supplied data stored and shown to admins; every field validated (T-03-227), one row per agent, and charged to the agent limiter |
| threat_flag: new agent route | internal/server/agent.go | `POST /api/v1/agent/identity`: replaces an agent's identity on the old key's signature over mTLS (T-03-55); a stolen identity key can rotate itself away from its owner, as it could already poll |
| threat_flag: new admin route | internal/server/hosts.go | `GET /api/v1/admin/hosts/status`: `requireAdmin`, read-only |
| threat_flag: unit outside the sandbox | internal/agent/apply/units.go | `ExecStartPre=+` runs `install -d /run/sshd` as root outside the applier's sandbox; fixed argv, no input |

## Open questions for the owner

1. **The `/run/sshd` line** (Owner attention 1): answered in fix round 1, D-R3: keep the unit's `ExecStartPre=+`.
2. **The clock-skew flag lags behind the fetcher's log** (Owner attention 3): answered in fix round 1, D-R2: store the offset of every authenticated, parseable heartbeat.
3. **Spool pruning** (03-07 open question 3) stays a pending todo by the owner's fix-round-1 decision. The 03-07 readiness line had named 03-08 for it.

## User Setup Required

None in this plan. On the homelab (03-16): run `systemctl enable --now` for both units on each host, then `keyroster host status`.

## Next Phase Readiness

- **03-08b:** leaf kind 16, a signer-checked admin quorum for forget, and an audit record for forget and `--host-gone`.
- **03-09, 03-10, 03-14:** extend `heartbeat.Status` and its `Validate` (`host_certs` and `host_keys_skipped`; probe outcomes in `last_apply.detail`; `breakglass`).
- **03-12:** the rotation gate reads `pending == null` and the committed versions (`Status.Committed`).
- **03-16:** every UNVERIFIED item above.

## Fix round 1 (PR #72 pre-merge review)

The review ran at `b95a59f` against base `74504cf`: 18 findings confirmed (2 of 2 skeptics each), one split (S1), two refuted. The owner decided D-R1 to D-R4; every other confirmed finding was fixed without an owner decision, except C18 (a pending todo). Each fix got a test that is RED on the head before it and GREEN after it (evidence below). No Go module was added.

### Owner decisions

- **D-R1, identity rotation (fixes C12): log it and show it.** Every rotation is logged at warning level (`agent identity rotated`) with the host, the old and new identity fingerprints and the client IP. The agents row records `identity_rotated_at_us` and `identity_rotations`. **Migration choice: the columns are added to 0006**, which has never been released: there is no tag, and 0006 is not on `origin/main` (`git log origin/main -- internal/serverdb/migrations/0006_heartbeats.sql` prints nothing). `keyroster host status` shows `identity rotated <age>` for a rotation in the last 7 days, and the JSON carries `identity_rotated_at` and `identity_rotations`. The fetcher logs `unknown_agent` at error level (`<3>` under journald, once, and Run does not log it again). host-setup.md gains "An unexpected identity rotation": the key may be stolen; re-enroll the host and forget the old row.
- **D-R2, seq bound and clock offset (fixes C3, C11 and open question 2).**
  - A seq more than an hour (`heartbeat.MaxSeqAhead`) beyond the server's clock is refused 400 `heartbeat_seq_future`, logged at warning level, and leaves the stored status alone.
  - A lower seq is still 409 `stale_heartbeat`, and is logged as `heartbeat_seq_regressed` at most once an hour per agent. `host status` flags `seq_regressed` while the host is seen and its heartbeats since the stored one were lower. An equal seq stays quiet.
  - The clock offset of every authenticated, parseable heartbeat is stored on the agents row (`clock_offset_s`), stale and future ones included, and `clock_skew` reads it. `silent` is still `last_seen_us`, and a status is still stored only on a higher seq.
- **D-R3, `/run/sshd`:** `ExecStartPre=+/usr/bin/install -d -m 0755 -o root -g root /run/sshd` is kept. It is an owner-approved deviation from the plan, and `TestUnits/applier_unit` pins the exact line (a whole-line match, already at `b95a59f`).
- **D-R4, authenticity of the heartbeat status (S1, split): a known residual, no code change.** Threat row **T-03-284** in 03-08-PLAN.md and the host-setup.md paragraph "What host status rests on" say:
  - host status rests on the host's own report;
  - a compromised unprivileged fetcher can report an applied KRL it withheld;
  - the host still logs `krl_stale` at error level in its journal;
  - a signed applier status is a possible later plan (pending todo `signed-applier-status`).

### Finding → commit

| Finding | Commit | What changed |
|---|---|---|
| C1 (high) | `fc8ce6c` | `requireAgent` refuses 403 `unknown_agent` when `TouchAgent` finds the row gone. `StoreHeartbeat` checks, in its transaction, that the row still exists with the request's identity (403 otherwise). `DeleteAgent` already deleted the heartbeat row in its transaction at `b95a59f`, so that part needed no change. `foreign_keys` stays off. |
| D-R2 (C3, C11, Q2) | `4c60381` | seq bound, `heartbeat_seq_regressed`, `seq_regressed`, the offset on the agents row (0006: `clock_offset_s`, `seq_regressed_at_us`), and the applier's seq restart (deviation 3) |
| D-R1 (C12) | `89e525c` | rotation log line, row fields (0006: `identity_rotated_at_us`, `identity_rotations`), host status line, the fetcher's error line, runbook section |
| C10/C15 (high) | `c9e4ecf` | the agent limiter is keyed by the agents row ID; a row rotates at most once an hour (429 `identity_rotation_too_soon` with `Retry-After`, in the rotation's own conditional UPDATE) |
| C9/C13 (high) | `6faf573` | `--rotate-identity` never replaces an `identity.next` it finds. It tries that key with a state request and promotes it when the server takes it. On `unknown_agent` it asks again for that same key. On any other failure it keeps the file and returns an error. The poll's recovery also keeps the file on a transient failure. |
| C14 | `9be781a` | An active entry under the agent's expected name that holds entirely new keys is `keys_changed`, not a removal. No `removed_dir_version` is recorded, and it shows as `host_keys_changed (re-enroll), served until forget`. Forget needs `--host-gone`. |
| C4/C5 | `89d672e` | Forget's wait requires all three: the reported directory is at or above the removal version, it is not above the current version, and its SHA-256 matches the server's directory under that number (the signer's copy for an older one). hosts/status carries the current SHA-256s. host status counts a host on a version, and marks a difference with `*`, by SHA-256 too. It flags `diverged` for a version above the current one, or the current number with other bytes. `Status.Committed` compares the SHA-256 (03-12's gate), and `Status.Diverged` is new. |
| C2/C6 | `306dee5` | a STATUS column (the stored status's age); `status_stale` once the stored status is more than 2 × (15 min + 60 s) = 1920 s old while the host is seen |
| C16 | `ab55814`, `4bf60c1` | a failed drift check writes a status with `last_check.error` (printable, at most 512 bytes, `drift` false), and the KRL's age is still logged; host status shows DRIFT `failed` and `check_failed` with the error |
| C17 | `d4832e4`, `89ffc7b` | every pending-marker write in `Transition` publishes a status under the apply lock Apply holds (`publishStatus`, `publishPending`), and the KRL is still the one `current` names. `d4832e4`'s message says that status runs no program, but `sshd -T` still ran in an if statement's init; `89ffc7b` corrects it (found in the post-commit advisor review), so it now runs nothing and carries sshd's version and settings over. |
| C7 | `b02f579` | the fetcher's OpenRC script creates its log in `start_pre` (`checkpath -f -o keyroster-agent:keyroster-agent -m 0640 "/var/log/${RC_SVCNAME}.log"`), asserted by `TestUnits/openrc_scripts`; OpenRC stays UNVERIFIED until 03-16 |
| C8 | `b02f579` | The fetcher unit's comment and the runbook table now say what the unit enforces: IPv4 and IPv6 sockets only, with no destination limit. No `IPAddressAllow` was added. |
| D-R4 (S1), C18 todo | `79074b9` | T-03-284, host-setup.md paragraph, todos `signed-applier-status` and `page-host-status` |
| docs, lint | `5ac2b86`, `a6e6e23` | the alert list (`seq_regressed`, `identity rotated <age>`, `clock_skew` from every heartbeat) and the refusal table (`heartbeat_seq_future`); `a6e6e23` clears gosec G115 on the applier's seq bound |
| SUMMARY corrections | this file's fix-round commit | The "full gate" sentence now names `a1bc84a`, with its two failures and the CI verification. "Pre-merge advisor's catch" now reads "found in self-review before the first commit". `actuals.tokens` is 68038. |

### Tests added (RED before, GREEN after)

The RED runs were made on the head before each fix, with only the test (and, where needed, a new constant or test hook) added:

- `TestHeartbeatAfterForget/in_flight_heartbeat_not_inherited`: `the forgotten agent's heartbeat: 200 {"seq":2}`. `row_gone_after_lookup_refused`: 200, want 403. (Uses the new nil-by-default hook `Server.afterAgentLookup`.)
- `TestHeartbeatSeq/future_seq_refused`: `seq 9223372036854775807: 200`. `lower_seq_after_reset_flagged`, `equal_seq_not_flagged` and `offset_updates_on_stale`: the fields were missing (`clock_offset_s <nil>` after a stale heartbeat with offset 400). `TestStatus/seq_restarts_from_the_clock_after_running_ahead` (WSL): `seq 1793016000000001 ..., want the clock's 1793008800000000`.
- `TestIdentityRotationRecorded`: `identity_rotations <nil>`. `TestUnknownAgentLoggedAtError` (WSL): the line was `keyroster-agent-fetch: ERROR state: ...unknown_agent`, without `<3>`. The `TestHostStatus` rotation line was a compile-error RED (new row fields).
- `TestAgentLimitAcrossRotation`: `the rotated identity's first state request with the row's burst spent: 200, want 429`.
- `TestIdentityRotation/rotation_answer_lost_then_rotated_again` (WSL): `HTTP 403 unknown_agent`. `rotation_retried_with_the_same_key`: the retry rotated to a new key. `rotation_kept_when_the_server_is_unreachable`: identity.next was replaced.
- `TestRekeyedHostNotRemoved`: `removed_dir_version 2 for a re-keyed entry, want none`. `TestServedLine` was added GREEN.
- `TestForgetGateChecksTheDirectory/version_above_current_refused` and `same_number_other_sha_refused`: forget answered 200. `TestHostStatusDiverged`: `directory v5 on 2/3 hosts`, and no `diverged`. `TestCommittedAndDiverged` was added GREEN.
- `TestStatusStale`: `status_stale <nil>`. `TestHostStatusAge`: no STATUS column and no `status_stale`.
- `TestRunPublishesFailedCheck` (WSL): no status after the failed check within 10 s. `TestHostStatusCheckFailed`: DRIFT showed `no`. The `TestValidate` `last_check.error` cases were added GREEN.
- `TestStatus/pending_published_during_the_swap` (WSL): the outbox showed `pending none` at both swaps. `TestStatus/swap_status_runs_nothing` (WSL, before `89ffc7b`): `the swap's status ran ["sshd -T -f .../sshd_config"]`.
- `TestUnits/fetcher_unit` and `openrc_scripts` (WSL): the comment claimed "the agent server only", and the script had no `checkpath`.

Expected test changes, not regressions:
- the forget tests that pass now send the directory's real SHA-256 (`e.hbAt`), not the fake `ab…`;
- `TestHostStatus`'s answer carries the current SHA-256s;
- the CLI's clock-skew line reads the row's `clock_offset_s`.

### Deviations (fix round 1)

1. **[Already present] C1, third part.** `DeleteAgent` deleted the heartbeat row in its transaction at `b95a59f`. Nothing changed there; `TestHeartbeatAfterForget` covers it with the other two parts.
2. **[Interpretation, D-R2] A `heartbeat_seq_future` heartbeat stores its clock offset.** The owner's "every authenticated, parseable heartbeat" includes it, and a host whose clock runs more than an hour ahead is exactly the one whose `clock_skew` must show. Its status, seq and received_at are untouched.
3. **[Rule 1, D-R2] The applier restarts its seq from its clock when the previous seq is more than `MaxSeqAhead` beyond it.** Without that, a host whose clock once ran ahead and was then corrected would keep sending a future seq, refused, for as long as its clock had been ahead (decades for a typo'd year). The plan's `seq = max(previous + 1, now)` holds within the bound.
4. **[Design, D-R2] The rate limit uses the database.** `heartbeat_seq_regressed` is logged at most once an hour per agent through `agents.seq_regressed_at_us`, which is set when it is unset, older than the stored heartbeat, or an hour old; that holds across server restarts. `seq_regressed` is "that column is later than the stored heartbeat's `received_at`, and the host is not silent".
5. **[Interpretation, D-R1] "Unknown or not enrolled (403)" is `unknown_agent`.** `not_approved` stays the fetcher's quiet "waiting for approval" line.
6. **[Design, C10/C15] The rotation limit is the row's `identity_rotated_at_us`** (one rotation per hour), checked in the same conditional UPDATE as the rotation. It answers 429 `identity_rotation_too_soon` with `Retry-After`.
7. **[Design, C9] "Ask the server which SPKI it accepts" is a state request with identity.next** (no new route: AGENT-02's operation set is closed, and `TestAgentMuxRoutes` pins four routes). A `not_approved` answer for that key also means the server holds it.
8. **[Limit, C14] The agent's directory name is its expected name**, the name `host approve` gives its entry. An agent whose entry was added by hand under another name and then fully re-keyed still counts as removed, as before.
9. **[Design, C4] An older reported version is checked against the signer's copy** (`GetDirectoryVersion`). A signer that cannot answer makes forget refuse with 503; forget never guesses.
10. **[Design, C5] `diverged` is computed by the CLI** from the answer, which now carries the current SHA-256s, like the convergence counts it belongs to. `silent`, `status_stale` and `seq_regressed` are server flags on the server's clock. `Status.Committed` now takes `heartbeat.Doc`s, and its two e2e callers pass `HostVersions.Docs()`.
11. **[Schema, C16] `last_check` gains an optional `error`.** It is printable ASCII within 512 bytes, `drift` is never set beside it, and it is validated on both sides, as the closed-struct rule asks.
12. **[Scope, C17] The one-step (collapsed) swap also publishes its `final` marker.**
13. **[Test fix] `TestHostStatusAge` (added in `306dee5`) matched "12s ago" exactly.** A run slower than a second would turn that into "13s ago". One Windows run of `-run TestHostStatus` failed while `ab55814` was being prepared; which test failed was not captured, so this is the likely cause, not an observed one. `ab55814` loosens the match. Afterwards `go test -count=30 -run TestHostStatus ./cmd/keyroster/` passed 30 of 30 on Windows.

### What ran and what did not (fix round 1)

**Ran:**

- **WSL (Ubuntu, Go 1.27.3), on a `git archive` copy of `5ac2b86`, removed afterwards:**
  - `CGO_ENABLED=1 go test -race -count=1 ./...`: every package passed, with no data race;
  - `go vet` for linux, windows and darwin, and with `-tags e2e`, `-tags "e2e systemdsmoke"` and `-tags e2edistro`;
  - the `e2e systemdsmoke` test binary built (`go test -run XXX_build_only`);
  - gofmt, dep-firewall, testonly-firewall and check-pinned-actions;
  - capslock-check: keyroster-signer 92, keyroster-agent 37, keyroster-agent-fetch 23 pairs, all equal to the baseline, and EXEC still leaves the module only through execsite (2 edges). **No capslock delta in fix round 1.**
  - golangci-lint found one issue, gosec G115 in `status.go`, fixed in `a6e6e23`. On a copy of the tree with that fix it then reported 0 issues for linux, windows and darwin, and `TestStatus` passed again.
- **WSL, on copies of the working tree, removed afterwards:**
  - each fix's RED and GREEN runs for `internal/agent/apply` and `internal/agent/fetch`;
  - `go vet` and `go test ./internal/agent/... ./cmd/keyroster-agent/` on the tree of `d4832e4`: every package passed;
  - after `89ffc7b`, on its tree: `go test -run 'TestStatus|TestRun|TestApply' ./internal/agent/apply/`, `CGO_ENABLED=1 go test -race ./internal/agent/apply/` and golangci-lint for linux, windows and darwin on `./internal/agent/...` (0 issues) passed. The full gate ran before `89ffc7b`; CI runs it on the final head.
- **Windows (Go 1.27.1):**
  - after each commit: `go vet ./...` and the server, serverdb, serverclient, heartbeat and CLI tests;
  - `go test ./...` on the final tree: every package passed except `internal/agent/paths` `TestAllowed`. It fails on Windows at `b95a59f` too, because its paths are POSIX, and no CI lane runs that package on Windows. It is pre-existing and was not touched.
- **CI on the new head:** see the handback (the e2e, systemd and required checks).

**Not run here:**

- The e2e tests (`TestAgentStatusEndToEnd`, `TestAgentEnrollEndToEnd`) and the systemd smoke test (`TestAgentSystemdSmoke`) did not run locally: WSL cannot resolve `keyroster.localhost`. They run in CI on the new head. They are the first runs of the SHA-256 convergence (C5) against a real agent: `Committed` now needs the agent's SHA-256 of `accepted/`'s bundle and directory, and of the generation's KRL, to equal the server's of the bytes it serves.

**UNVERIFIED (fix round 1):**
- the OpenRC `start_pre`/`checkpath` line (OpenRC is UNVERIFIED until 03-16);
- re-enrolling a host after an unexpected identity rotation, and re-enrolling a re-keyed host (runbook steps; no test runs them, on CI or a host);
- every fix-round behaviour on a real host (03-16).

### Not fixed in this round

- **C18, `host status` has no paging** (low; it fails loudly above the CLI's 4 MiB cap): pending todo `2026-10-29-page-host-status.md`.
- **Spool pruning**: still the pending todo of #71's fix round 1.
- **`TestFetch/more_repolls_immediately`** can flake under WSL load (900 ms bound, Issues Encountered above); it is noted only.
- **Refuted, so not changed:** "rotation needs no proof of possession of the new key", and "the runbook names a file the agent never writes".

## Self-Check: PASSED

- **Files.** Every created key file exists; `test/systemd/agent-smoke.sh` is tracked with mode 100755.
- **Commits.** `6d8427d`, `266045e`, `fea5093`, `6052c2d`, `a1bc84a`, `855f65b`, `f3d142f` and `1881498` are ancestors of HEAD; `git rev-list --count 74504cf..1881498` is 8, and this file's commit makes 9.
- **Task 1 acceptance.** TestAgentStatusEndToEnd's log shows `KRL v1793228727 on 1/1 hosts`, silent only past 180 s, and a login while `krl_stale` is set. `grep -n stale_heartbeat internal/server/agent.go` and `grep -n heartbeat_field_invalid internal/server/agent.go` print the refusals. `grep -rn clock_offset_ms internal cmd` prints nothing.
- **Task 2 acceptance.** Every named case exists and passes. `TestAgentMuxRoutes` lists exactly POST enroll, GET state, POST heartbeat, POST identity.
- **Task 3 acceptance.** The systemd job's log shows the certificate login, every refused cross-user write with the one allowed spool write, and both `systemd-analyze security` results under their thresholds. `grep -n 'apply --once' docs/runbooks/host-setup.md` prints the Phase 2 adoption step in "Running the agent". The PR is open without auto-merge.

## Fix round 1 self-check: PASSED

- **Commits.** `fc8ce6c`, `4c60381`, `89e525c`, `c9e4ecf`, `6faf573`, `9be781a`, `89d672e`, `306dee5`, `ab55814`, `d4832e4`, `4bf60c1`, `b02f579`, `79074b9`, `5ac2b86`, `a6e6e23`, `6fb5cad` (this section's first version) and `89ffc7b` are ancestors of HEAD: 17 commits from `b95a59f`, and this file's update makes 18. Each is SSH-signed by keyroster-bot (`%G?` = G against the bot's allowed signer) and has no attribution lines.
- **Files.** `.planning/todos/pending/2026-10-29-signed-applier-status.md` and `2026-10-29-page-host-status.md` exist. T-03-284 is in 03-08-PLAN.md's threat register.
- **No private address or host name** in any staged diff (checked before each commit).
