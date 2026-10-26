---
phase: 03-linux-agent-and-revocation
plan: 05
subsystem: agent
tags: [agent, apply, sshd, krl, principals, two-step-swap, self-test, rollback, crash-recovery, spool, capslock, dep-firewall]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-03: krl.Parse, VerifyManifest, the time-derived krl_version and the no-drop rule (EntryLive, TestPublishNeverDropsLiveEntry); 03-04: Directory.Hosts, HostForKey, RenderPrincipalsFile per host group, CheckInstallation, pop.hosts"
provides:
  - "keyroster-agent apply --once [--dry-run] [--recover-to-last-good] (linux): the root applier, verified spool -> generation -> two-step swap -> self-test -> rollback"
  - "internal/agent/spool: OpenDir, ReadFileAt, ReadFileAtInfo, WriteFileAt (the F2 open contract), Read, Write, State"
  - "internal/agent/state: Pins, LoadPins, WritePins, Stored, LoadStored, Save, Verify, Verified"
  - "internal/agent/apply: Layout, Generation, Render, Intermediate, FileClass, GenerationFiles, Transition, swapCurrent, ObserveLoginGrace, Apply, Config, Report, DropIn, CheckReload, ParseDump"
  - "internal/agent/paths: Layout, Allowed, ExecSites, GenLink, ParseGenLink"
  - "dep-firewall and capslock targets for keyroster-agent; depguard agent-apply-no-http; forbidigo exec rule"
affects: [03-06, 03-07, 03-08, 03-09, 03-10, 03-12, 03-14, 03-16]

actuals:
  tokens: 75000
  tasks: 3
  commits: 8
plan_head_before: 326007a703eb0bd68a85e157c26b579005f33194
plan_head_after: 5046eb36253f14e089a3a0a9885ad5ec57b422f1

tech-stack:
  added: []
  patterns:
    - "Every move of current goes through Transition and swapCurrent: intermediate generation, swap timing by boot ID and CLOCK_BOOTTIME, monotone check"
    - "Every fetcher-written file is read once through spool.ReadFileAt and the bytes read are the bytes verified and installed"
    - "Every root write goes through paths.Allowed in the same function; TestPaths checks it with an AST walk"
    - "Fault points before every durable step, so crash recovery is tested by injection at every step"

key-files:
  created:
    - cmd/keyroster-agent/main.go
    - cmd/keyroster-agent/main_other.go
    - cmd/keyroster-agent/commands.go
    - cmd/keyroster-agent/apply.go
    - internal/agent/paths/paths.go
    - internal/agent/paths/paths_test.go
    - internal/agent/spool/spool.go
    - internal/agent/spool/spool_test.go
    - internal/agent/state/state.go
    - internal/agent/state/verify.go
    - internal/agent/state/state_test.go
    - internal/agent/apply/layout.go
    - internal/agent/apply/render.go
    - internal/agent/apply/validate.go
    - internal/agent/apply/swap.go
    - internal/agent/apply/sshd.go
    - internal/agent/apply/selftest.go
    - internal/agent/apply/apply.go
    - internal/agent/apply/harness_test.go
    - internal/agent/apply/apply_test.go
    - internal/agent/apply/interleave_test.go
    - test/e2e/agent_apply_test.go
    - test/e2e/sshd_reread_test.go
    - test/capslock/keyroster-agent.json
  modified:
    - test/e2e/bootstrap_test.go
    - scripts/dep-firewall.sh
    - scripts/capslock-check.sh
    - .golangci.yml
    - cmd/keyroster/machine.go
    - cmd/keyroster/machine_test.go
    - cmd/keyroster/host_test.go
    - docs/runbooks/machine-identities.md

key-decisions:
  - "03-05: D-05 network answer loopback-only (owner, 2026-10-26): the applier dials only loopback addresses from sshd -T, only for the self-test; a non-loopback listen address is skipped, never dialed, and no_loopback_listener is refused only when no loopback address remains"
  - "03-05: the self-test ends the SSH handshake once sshd has proved one of the host keys sshd -T names (key exchange complete), before any authentication attempt, so it never counts as a failed authentication for OpenSSH 10.x's PerSourcePenalties"
  - "03-05: the agent never creates /etc/ssh/sshd_config.d (no_dropin_dir) nor any parent of its tree; the allowlist is the keyroster tree, the one drop-in file and the state directory"
  - "03-05: a directory chain is authenticated by the newest offered version's quorum signatures and the prev-hash chain back to the accepted version; versions between are never rendered and not signature-checked one by one"
  - "03-05: KRLs have no chain (krl_version is time-derived since 03-03): the newest complete KRL is verified against the stored version, an equal version is a no-op before VerifyManifest, an older one is krl_older"
  - "03-05: waited_ms reports, for each widening swap that had to wait, the interval from the previous swap of current to that swap"
  - "03-05: spool.Read takes the accepted versions as a Floor and reads the lowest 64 versions above it, so a host far behind converges over several applies"

patterns-established:
  - "Root applier exec sites live in internal/agent/apply/sshd.go only, each listed in paths.ExecSites with its binary and flags"
  - "A generation file's behaviour in Intermediate and in the swap classification comes from its FileClass in GenerationFiles"

requirements-completed: []

coverage:
  - id: D1
    description: "keyroster-agent drives a real sshd from signed state: first install with one reload, a revocation and a principal removal each in one swap without reload, a revoke-and-add change through the intermediate (both refused while current names it, the added principal accepted after the final swap, waited_ms >= 8000), sshd PID unchanged, a failed self-test rolled back"
    requirement: "AGENT-04"
    verification:
      - kind: e2e
        ref: "test/e2e/agent_apply_test.go#TestAgentApplyEndToEnd (CI E2E run 40319562159, 9.5p1 and 10.5p1; local WSL both versions)"
        status: pass
    human_judgment: false
  - id: D2
    description: "sshd re-reads the trust files per authentication through the current link: revoked serial, removed principal, removed CA, corrupt and missing KRL refuse every key, zero-byte KRL accepted, CA garbage line order, HostCertificate per version"
    requirement: "REVOKE-03"
    verification:
      - kind: e2e
        ref: "test/e2e/sshd_reread_test.go#TestSshdRereadsTrustFiles (local WSL 9.5p1 and 10.5p1; CI on the PR)"
        status: pass
    human_judgment: false
  - id: D2b
    description: "F1's LoginGraceTime premise: the plan's criterion (a banner-only connection closed within 5 s with LoginGraceTime 3) is NOT met on 10.5p1 (closes after 3.2 to 6.6 s), and 10.5p1 still authenticates a certificate offered 4 s after connect; the tests now assert the bound the agent's wait uses, LoginGraceTime + 5 s"
    requirement: "AGENT-04"
    verification:
      - kind: e2e
        ref: "test/e2e/sshd_reread_test.go#TestSshdRereadsTrustFiles/login_grace_closes_preauth and /login_grace_bounds_auth_reads"
        status: pass
    human_judgment: true
    rationale: "A plan acceptance criterion failed as written on 10.5p1, and the owner-decided + 5 s margin was as small as 1.4 s in local runs; whether it is enough is the owner's decision, not a test's"
  - id: D3
    description: "No interleaving of sshd's four reads across Transition's swaps accepts a certificate that no generation current in the window accepts; the direct-swap and back-to-back controls find the Codex violation"
    requirement: "AGENT-04"
    verification:
      - kind: unit
        ref: "internal/agent/apply/interleave_test.go#TestSwapInterleaving (46085 read sets x 27 certificates)"
        status: pass
      - kind: unit
        ref: "internal/agent/apply/interleave_test.go#TestIntermediate"
        status: pass
    human_judgment: false
  - id: D4
    description: "Apply edges: versions and documents, candidate checks with the host's ssh-keygen, self-test and rollback, the timing rule, monotone swaps, the LoginGraceTime bound, crash recovery by fault injection at every step (nested), the operator's recovery, PR #57's supersede and collapse cases, retention, locking, state-directory checks"
    requirement: "AGENT-04"
    verification:
      - kind: unit
        ref: "internal/agent/apply/apply_test.go#TestApply"
        status: pass
    human_judgment: false
  - id: D5
    description: "Principals files only through directory.RenderPrincipalsFile for the host found by its sshd host keys; Intermediate only drops lines"
    requirement: "AUTHZ-02"
    verification:
      - kind: unit
        ref: "internal/agent/apply/apply_test.go#TestApplyTracer"
        status: pass
      - kind: e2e
        ref: "test/e2e/agent_apply_test.go#TestAgentApplyEndToEnd"
        status: pass
    human_judgment: false
  - id: D6
    description: "F2 open contract: symlink, FIFO, oversize, symlinked spool, symlink to pins.json, names outside the patterns, torn temp files, planted symlinks on write"
    verification:
      - kind: unit
        ref: "internal/agent/spool/spool_test.go#TestSpool"
        status: pass
      - kind: unit
        ref: "internal/agent/state/state_test.go#TestPins"
        status: pass
    human_judgment: false
  - id: D7
    description: "The applier's confinement: no HTTP/TLS/RPC in its graph, exec sites pinned, writes through paths.Allowed, current moved only in swapCurrent; dep-firewall, capslock and lint gates"
    verification:
      - kind: unit
        ref: "internal/agent/paths/paths_test.go#TestPaths"
        status: pass
      - kind: other
        ref: "bash scripts/dep-firewall.sh; bash scripts/capslock-check.sh; golangci-lint run ./... (linux, windows, darwin)"
        status: pass
    human_judgment: false
  - id: D8
    description: "Carry-overs from the PR #65 fix check: machine remove names the actual remedy; directory sign and install refuse a foreign served directory"
    verification:
      - kind: unit
        ref: "cmd/keyroster/machine_test.go#TestMachineCommands/machine_remove_hint_names_the_actual_remedy"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/host_test.go#TestReadCommandsCheckInstallation"
        status: pass
    human_judgment: false
  - id: D9
    description: "machine-identities.md removal section names both remedies"
    verification: []
    human_judgment: true
    rationale: "A runbook's wording needs a human reader; every homelab step is UNVERIFIED until 03-16"

duration: 160min
completed: 2026-10-26
status: complete
---

# Phase 3 Plan 05: Apply Engine Summary

**`keyroster-agent apply --once` verifies the spool's signed bundle, directory and KRL against its own pins, renders this host's trust files through the one principals renderer, checks them with the host's own ssh-keygen, and moves `current` through an intermediate generation whenever a change both adds and removes, with a swap timing rule that keeps every widening swap LoginGraceTime + 5 s after the previous swap. It reloads sshd only for the drop-in, self-tests over loopback, rolls back to last-good, and recovers from a crash at any step. A real sshd is driven this way on both CI OpenSSH versions.**

## Owner attention first: a failed criterion behind F1's timing rule

**F1's premise was weaker on 10.5p1 than the plan assumed.** The plan's `login_grace_closes_preauth` criterion was "closed by sshd within 5 s" with LoginGraceTime 3. As written, that criterion is not met on 10.5p1.

| Measurement (LoginGraceTime 3) | 9.5p1 | 10.5p1 |
|---|---|---|
| A banner-only connection is closed | after about 3.0 to 3.1 s | after 3.2 to 6.6 s (14 local runs) |
| A certificate offered 4 s after connect | refused | accepted (2 of 3 runs, then again in the final run) |
| A certificate offered 8.5 s after connect | refused | refused |

So on 10.5p1, sshd still reads the trust files for an authentication more than LoginGraceTime after its connection started. The agent's widening wait is LoginGraceTime + 5 s, which covered every observation here, but by as little as 1.4 s. The tests now assert that bound: a close after LoginGraceTime and within LoginGraceTime + 5 s, and a refusal at LoginGraceTime + 5.5 s. They pass on both versions.

This plan did not change the owner's timing rule. **The owner decides** whether the + 5 s margin stands, needs to grow, or needs 10.x's slack explained first. UNVERIFIED: the slack on a loaded production host.

## D-05 network answer (Task 1)

D-05 network answer: loopback-only
Owner's verbatim answer (AskUserQuestion, 2026-10-26): "loopback-only (Recommended)"
Claude's description of the option (not the owner's words): the applier dials only loopback addresses, only for the self-test and the probes; no HTTP, TLS or RPC code; the unit gets IPAddressDeny=any with IPAddressAllow=localhost. A host whose sshd does not listen on loopback is refused with an explanation.

The record is `$HOME/keyroster-ceremony/phase3/d05-answer.txt`; its first line is `loopback-only`, and Task 1's verify passes on it. Tasks 2 to 4 implement that answer. The unit's `IPAddressDeny`/`IPAddressAllow` lines are 03-08's.

## Performance

- **Duration:** about 160 min of executor time (about 11:05Z to 13:55Z, CI waits included)
- **Tasks:** 3 executed (Tasks 2 to 4); Task 1 was answered before this run; Task 5 is the merge gate
- **Files modified:** 32
- **PR:** opened from branch `p03/05-apply-engine` after this file is pushed. Its number is in the handback; this file carries no merge facts.

## Accomplishments

- **Spool (F2).** `OpenDir` opens with O_DIRECTORY|O_NOFOLLOW. A symlinked spool is refused `spool_symlink`: on Linux that combination fails ENOTDIR, so an lstat tells the two apart. `ReadFileAt` opens relative to the descriptor with O_NOFOLLOW|O_NONBLOCK, requires a regular file within the cap, and reads at most cap+1 bytes. `WriteFileAt` writes through an O_EXCL|O_NOFOLLOW temporary file, fchmod, fsync, renameat and a directory fsync. `Read` reads only names that match the fixed patterns and only complete sets. For each kind it reads the lowest 64 versions above what the applier accepted, plus the newest version at or below it (`Floor`; the newest 64 when nothing is accepted yet), and of the KRLs only the newest complete one. A host more than 64 versions behind therefore catches up over several applies.
- **State.** `pins.json` must be canonical JSON, mode 0600, owned by the effective uid. `Verify`:
  - **Bundle.** The first bundle is checked by `serverclient.Trust`'s rule, reimplemented from exported trust functions because serverclient imports net/http. After that, successors only, by `trust.VerifySuccessor`. Every accepted bundle must name the pinned installation.
  - **Directory.** The newest offered version is checked: quorum signatures, strict `CheckInstallation`, `CheckPolicy`, and the prev-hash chain back to the accepted version.
  - **KRL.** The newest complete KRL goes through `VerifyManifest`, then `krl.Parse`.
  - **Refusals:** `bundle_older`, `bundle_chain_gap`, `bundle_installation`, `directory_older`, `directory_chain_gap`, `directory_installation`, `krl_older`, `krl_not_verified`.
- **Render.** The host entry is found by any sshd host key (`host_keys_disagree`, `host_not_in_directory`, with the unmatched keys in the report). `user_ca_keys` holds the active and next user and machine CA keys. `principals/<account>` is `directory.RenderPrincipalsFile` for each account of the host's group. `revoked.krl` is the verified KRL, or zero bytes when none is published.
- **Intermediate and the swap rule (F1).** `GenerationFiles` maps each file to a `FileClass`. `Intermediate` takes the target's KRL and intersects CA keys by key and principal lines by account. It collapses on classified content: headers never block a collapse, and an absent principals file equals a header-only one. `Transition` rewrites the marker before every swap. `swapCurrent` is the only function that moves `current`:
  - a narrowing swap happens at once;
  - a widening swap waits LoginGraceTime + 5 s after the previous swap, by `last_swap.json` (boot ID and CLOCK_BOOTTIME), and checks the spool every 5 s for a superseding state;
  - anything else is `swap_not_monotone`.
- **LoginGraceTime bound.** `ObserveLoginGrace` and `login_grace.json`: the largest value seen since the agent's own last reload, and the earlier maximum until that reload plus that maximum plus 5 s. `logingracetime 0` is refused `login_grace_unbounded` and an unreadable value `login_grace_unknown`, both before anything is written.
- **Sequence.**
  - The state-directory check, pins and `sshd -T` come before the lock.
  - Crash recovery comes next. A move left pending goes back to last-good through Transition; a first install is undone.
  - Then one capture, `Verify`, `Render`, and the generation is written. It is validated with `ssh-keygen -l` per CA line and `ssh-keygen -Q` with a fresh key; a KRL that drops an installed explicit key is refused `krl_drops_key_entry`.
  - First install: a direct swap, then the drop-in, `sshd -t`, the `sshd -T` path check (`dropin_not_effective`), the reload and the self-test. A failure undoes all of it (`first_install_failed`).
  - Otherwise Transition, with supersede; the drop-in and reload only when the drop-in changed.
  - Then the self-test. On failure: rollback through Transition, the previous drop-in, a second self-test.
  - Commit: last-good, then accepted/, then the marker is cleared and old generations are removed, never those current, last-good or the marker names.
- **Recovery.** A layout the agent did not make makes the run stuck: `pending_state_unknown` is in the report and status.json, one error line goes to stderr, and nothing is swapped. `--recover-to-last-good` refuses `last_good_invalid`. A missing current, or one without revoked.krl, gets a direct swap; a readable foreign current goes through `Transition(X, last-good)` built from X's bytes.
- **Self-test (loopback-only).** It dials every loopback listen address from `sshd -T` (a wildcard maps to 127.0.0.1 or ::1). One deadline, `SelfTestTimeout` (10 s by default), covers dial, banner and key exchange. The test passes when sshd proves one of the host keys `sshd -T` names.
- **CLI.** `keyroster-agent apply --once --spool --state-dir --root --sshd --sshd-config --ssh-keygen --reload {signal|systemd:<unit>.service|openrc} [--dry-run] [--recover-to-last-good]` prints the report as JSON. `main_other.go` keeps the binary building off Linux.
- **Gates.** dep-firewall has a target per binary; the signer's lines are byte-identical. capslock has the baseline `test/capslock/keyroster-agent.json`. golangci gains depguard `agent-apply-no-http` and the forbidigo `exec.Command(Context)` rule.
- **Carry-overs (PR #65 fix check).**
  - (a) `machine remove` names the remedy for each refusal kind: `--max-ttl D`, `--no-extensions` or the `--extension` list the user profile allows, or both in one command. machine-identities.md follows.
  - (b) `directory sign` and `directory install` are in TestReadCommandsCheckInstallation, on a proposal bound to the bundle's own ID, and are shown to post nothing.

## Task Commits

1. **Carry-over (a):** `f3200b9` (fix): machine remove names the actual remedy
2. **Carry-over (b):** `0ba17b9` (test): directory sign and install in TestReadCommandsCheckInstallation
3. **Task 2 (tracer):** `aeb74db` (feat): apply signed state through an intermediate generation, with self-test and rollback
4. **Task 3:** `39b2f78` (test): sshd re-reads, swap interleaving, apply edges, spool, pins, paths, and the fixes they found
5. **Task 4:** `a65f9ce` (chore): dep-firewall per binary, capslock baseline, lint rules
6. **Task 3 follow-up:** `6b0aac9` (test): a documentation address (192.0.2.20) replaces a private one in a unit test
7. **Pre-push review fix:** `b434787` (fix): the spool is read from the accepted versions up
8. **Pre-push review test:** `5046eb3` (test): when sshd stops processing an authentication after LoginGraceTime

**Plan metadata:** the `docs(03-05): complete apply-engine plan` commit that carries this file, STATE.md and ROADMAP.md.

## Tracer gate (Task 2)

- **Locally, before the push.** TestAgentApplyEndToEnd passed in WSL on 10.5p1 and 9.5p1. The unit verify (`go test -race ./internal/agent/... ./cmd/keyroster-agent/...`) passed.
- **CI.** The E2E workflow was dispatched on the pushed tracer head `aeb74db` as **run 40319562159**. Both lanes passed, and each log has `--- PASS: TestAgentApplyEndToEnd` (30.5 s and 31.9 s) and no `--- FAIL`.
- Task 3 started only after that.

## Swap timing rule for operators

- Revocations and removals (CA keys, principal lines) are live at once.
- Additions (new CA keys, new principal lines) are live at most LoginGraceTime + 5 s after the previous swap of `current`: at once when no swap happened in that interval, and LoginGraceTime + 5 s after the intermediate within a change that both adds and removes. That is 125 s with the default LoginGraceTime of 120.
- A revocation that arrives during a widening wait is swapped in within one spool check (5 s).
- The bound is the largest LoginGraceTime the agent has observed since its own last reload of sshd.
- The operator runbook gets this rule in 03-07, and 03-16 measures it.

## Capslock pairs (test/capslock/keyroster-agent.json, 19 pairs)

| Package | Capabilities |
|---|---|
| `cmd/keyroster-agent` | ARBITRARY_EXECUTION, EXEC, FILES, NETWORK, READ_SYSTEM_STATE, REFLECT, SYSTEM_CALLS, UNANALYZED, UNSAFE_POINTER (everything it reaches) |
| `internal/agent/apply` | ARBITRARY_EXECUTION, EXEC (the sshd.go exec sites), FILES, NETWORK (the loopback self-test through net and x/crypto/ssh), READ_SYSTEM_STATE (boot ID, euid), REFLECT (JSON), SYSTEM_CALLS (x/sys/unix), UNANALYZED |
| `golang.org/x/crypto/ssh` | REFLECT |
| `golang.org/x/sys/unix` | SYSTEM_CALLS (the descriptor-relative opens of F2, flock, CLOCK_BOOTTIME, SIGHUP) |

- EXEC appears only for the applier and its main package.
- The signer's baseline is unchanged (91 pairs).

## Mutant results

Each mutant was applied in WSL, run, and restored byte for byte (cmp with a kept copy).

- **M1, writeDropIn also writes `<root>/etc/ssh/sshd_config`.** Killed by TestPaths `writes_through_allowed` ("os.WriteFile in writeDropIn without paths.Allowed") and `no_sshd_config_in_write_paths`.
- **M2, forward renames a temp symlink over `current` in apply.go.** Killed by TestPaths `current_renamed_only_in_swapCurrent` ("forward moves current outside swap.go's swapCurrent").
- **M3, Intermediate replaced by an identity function (`return to, true`).** Killed by `TestSwapInterleaving/forward_A_M_B`, which fails with swap_not_monotone: swapCurrent refuses the direct move.
- **M4, M3 plus swapCurrent's classification disabled.** Killed by `forward_A_M_B` through the model itself: "2 violations, first: reads from generations 3,3,3,4 accept the certificate of CA 0 serial 5 ... which none of generations 3..4 accepts".
- **Lint rules.** A file importing net/http under internal/agent/apply is refused by depguard `agent-apply-no-http`, and `exec.Command` there by the forbidigo rule. sshd.go's sites stay excluded.
- **Carry-over (a).** The three new subtests fail on the old hint.
- **Carry-over (b).** With `CheckStoredInstallation` disabled in fetchVerifiedDirectory, both new `directory sign` and `directory install` entries fail.

## TestSwapInterleaving

- **Size:** 46085 read sets checked, each against 27 certificates.
- **Pairs:**
  - 2000 seeded pairs for `forward_A_M_B`;
  - 300 each for `rollback_B_M_L`, `collapsed_single_swap` and `pruned_expired_serial`;
  - 150 schedules of 2 or 3 applies with gaps of 0 to 200 s;
  - 100 superseded waits;
  - 150 each for the four crash-recovery subtests.
- **Controls.** `direct_swap_control_finds_violation` reports "reads from generations 1,1,1,2 accept the certificate of CA 0 serial 1 (key ID kid-1, principals [p1], account acc1), which none of generations 1..2 accepts". `back_to_back_revoke_then_add` finds the violation without the timing rule and none with it.
- **Read order.** The model's read order follows auth2-pubkey.c at V_9_5_P1 and V_10_5_P1, as cited in the test's doc comment (REVIEWS L1397@e7b3b32). The model does not observe that order in a running sshd.

## sshd findings recorded for later plans

- **HostCertificate (for 03-09).** 9.5p1 serves a replaced HostCertificate at the next connection without SIGHUP: it re-executes sshd per connection. 10.5p1 serves the old certificate until SIGHUP. The subtest asserts the observed behaviour per version; the plan's single statement holds on 10.5p1 only.
- **LoginGraceTime (F1's premise, for the owner).** See "Owner attention first" at the top: the plan's criterion failed on 10.5p1, which still authenticates after LoginGraceTime, and the LoginGraceTime + 5 s bound held with a margin as small as 1.4 s.
- **Log strings** (identical on 9.5p1 and 10.5p1) are recorded in the test: `revoked by file` and `Certificate does not contain an authorized principal`.

## What ran and what did not

**Ran (2026-10-26):**

- **WSL (Ubuntu, Go 1.27.3):**
  - `go test -race -count=1 ./...` passed in full on the second run. The first run had two signer tests fail under load, TestStartRefusedOnLogMismatch and TestSignerRestore; both pass alone and in the full rerun. See Issues.
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/` passed, and gofmt was clean.
  - golangci-lint reported 0 issues for linux, windows and darwin.
  - `scripts/capslock-check.sh` reported signer 91/91 and agent 19/19, and `scripts/dep-firewall.sh` was clean for both targets.
  - `scripts/testonly-firewall.sh` was clean in 6 combinations, and govulncheck found 0 reachable vulnerabilities.
  - The PR title passes `scripts/check-pr-title.sh`.
- **e2e in WSL:** TestAgentApplyEndToEnd and TestSshdRereadsTrustFiles, on OpenSSH 10.5p1 and 9.5p1 (signer only, no keyroster-server, so no `keyroster.localhost` workaround was needed).
- **CI E2E run 40319562159** (tracer head): both lanes green.
- **Windows:** `go test ./cmd/keyroster/...` (carry-overs), and `go build ./...` and `go vet` of the agent for windows and darwin.

**Not run here (UNVERIFIED):**

- **The required checks on the final head.** They run on the PR, so their result is in the handback.
- **Real root, real systemd or OpenRC reloads, and real host paths.** Every run was non-root, with `--reload signal` against the test sshd, `openrc` against a fake runner, and `--root` in a temporary directory. `reloadSystemd` and `reloadOpenRC` never ran a real binary.
- **The stuck alert "once a minute".** Each `apply --once` run writes one stderr line and status.json. Repeating it every minute is 03-08's timer (journald). UNVERIFIED.
- **A `current` that is a real directory rather than a link.** `--recover-to-last-good` refuses with an instruction to move it by hand; this is not tested.
- **IPv6 loopback (`::1`) self-test dials.** Only the address mapping is unit-tested; no sshd ran on ::1.
- **Every homelab step.** UNVERIFIED until 03-16. The agent is not installable until 03-07.

## Decisions Made

See `key-decisions` in the frontmatter. Also:

- **No operator step changes in this plan (D-20).** The agent is not installable until 03-07, so no runbook gains an agent step. The only runbook change is the carry-over in machine-identities.md.
- **Rollback can undo a revocation.** A revocation whose self-test fails is rolled back to last-good's KRL. That is the plan's rule (rollback to last-good on a failed self-test); the report shows `rollback: true` with the error. 03-08's status surfaces it.

## Deviations from Plan

### Auto-fixed Issues

**1. [Merged code] The KRL rules of 03-03 replace the plan's version wording**
- **Issue:** `krl_version` is time-derived and `VerifyManifest` refuses a version equal to the stored one.
- **Fix:** The newest complete KRL only, with no chain or gap rule. The equal-version no-op is detected before `VerifyManifest`, and an older version is `krl_older`. The spool reader skips older KRL files and reports them.
- **Committed in:** aeb74db

**2. [Merged code] The directory installation rule of 03-04**
- **Fix:**
  - Strict `directory.CheckInstallation` against the pin; agents never use the lenient stored rule.
  - Every accepted bundle must name the pinned installation, because `VerifySuccessor` alone lets a successor add an ID.
  - The first directory is accepted standalone at any version. `CheckSuccessor(nil, …)` would demand version 1.
  - A chain is authenticated by the newest version's quorum signatures and the prev-hash chain back to the accepted version.
- **Committed in:** aeb74db

**3. [Rule 3 - Blocking] serverclient.Trust reimplemented in state.verifyPinned**
- **Issue:** serverclient imports net/http, which the agent's firewall bans.
- **Fix:** The same checks from trust's exported functions, in the same order: authenticate the root set before the strict parse.
- **Committed in:** aeb74db

**4. [Rule 2 - Missing critical] Self-test details**
- The handshake stops right after sshd proves its host key, in the HostKeyCallback, before any authentication.
- The host key must be one that `sshd -T` names.
- Non-loopback listen addresses are skipped; `no_loopback_listener` is refused only when no loopback address remains. Without the early stop, every apply would add a failed-authentication penalty for 127.0.0.1 on OpenSSH 10.x. The e2e logs show only a 1 s "connections without attempting authentication" deferred penalty per self-test, below the 15 s minimum.
- **Committed in:** aeb74db

**5. [Rule 2 - Missing critical] Confinement tighter than the allowlist needed**
- The agent creates neither `sshd_config.d` (`no_dropin_dir`) nor any parent of its tree: it uses `mkdir` per component, not `MkdirAll`.
- The first e2e run found the drop-in directory creation refused by `paths.Allowed`. The test now creates the host's own sshd_config.d.
- **Committed in:** aeb74db

**6. [Rule 1 - Bug] Found by Task 3's tests**
- `login_grace_unbounded` wrote status.json and the subdirectories. The pins and `sshd -T` checks now run before the lock, and status.json is written only after the lock.
- A symlinked spool gave `spool_not_directory` instead of `spool_symlink`, because O_DIRECTORY|O_NOFOLLOW fails ENOTDIR on Linux.
- **Committed in:** 39b2f78, together with the tests: the commit is typed `test` and carries these two fixes.

**7. [Plan detail] `waited_ms`**
- **What it reports:** the interval from the previous swap to each widening swap that had to wait.
- **Why:** the sleep time alone was 7995 ms for an 8 s rule, since the clock had moved between the swap and the start of the wait.
- **Committed in:** aeb74db

**8. [Plan detail] e2e mechanics**
- **Agent binary.** It is built inside agent_apply_test.go, because harness_test.go's TestMain is not this plan's file.
- **Spool.** It is filled from the signer socket through signerclient (Status, GetDirectory, GetKRL), and revocations are sent straight to the signer.
- **pop.hosts.** `bootstrapOpts.PoPHosts` sets `pop.hosts` by editing the genesis policy before the root signs it; `root genesis-policy` has no pop flag.
- **sshd.** The test sshd starts with `Include <root>/etc/ssh/sshd_config.d/*.conf` and `LoginGraceTime 3`.
- **Logins.** Refused logins come from 127.0.0.2 to 127.0.0.6 (`BindAddress`); accepted logins and the self-test use 127.0.0.1.
- **Marker check.** The test polls the marker until it reaches `step: final`, since current moves a moment before the marker is rewritten.

**9. [Plan detail] TestSwapInterleaving runs on /dev/shm**
- **Why:** on WSL ext4, fsync made one pair cost about 190 ms, so 2000 pairs exceeded the 10-minute test timeout.
- **Effect:** on tmpfs the whole test takes about 50 s with -race. rename(2), symlinks and directory reads behave the same there.
- **Durability:** the durability-dependent crash tests stay in TestApply on the ordinary temporary directory.
- TestApply and TestSwapInterleaving subtests run in parallel.

**10. [Plan detail] Additions**
- **Report fields:** `rollback_self_test`, `recovered`, `no_op`, `stuck`, `unmatched_host_keys`, `spool_ignored`, `diff`.
- **Refusal codes:** `pins_invalid`, `stored_state_invalid`, `bundle_missing`, `bundle_not_verified`, `policy_missing`, `directory_not_verified`, `directory_chain_gap`, `krl_not_verified`, `krl_invalid`, `krl_rejected_by_ssh_keygen`, `ca_line_rejected`, `sshd_t_failed`, `sshd_T_failed`, `reload_failed`, `dropin_not_effective`, `no_dropin_dir`, `config_invalid`, `path_not_allowed`, `spool_bad_name`, `spool_not_directory`.
- **Test cases:** TestAllowed, `read_write_round_trip`, `bad_names_refused`, TestPins and TestStored.
- **Fault point:** `self-test`, so that a crash between the swap and the self-test can be injected.

**11. [Plan detail] Gates**
- The forbidigo pattern is `exec\.Command(Context)?\b`. The anchored form `^…$` matched nothing (shown by a mutant file).
- It excludes the existing exec users: the CLI's browser opener, the Windows agent check and tests.
- The depguard rule also covers the agent packages' tests.

**12. [Plan criterion not met as written] LoginGraceTime, and a per-version HostCertificate assertion**
- **LoginGraceTime.** The plan's `login_grace_closes_preauth` criterion ("closed within 5 s") fails on 10.5p1. The assertion now checks the agent's actual bound, LoginGraceTime + 5 s, and the new subtest `login_grace_bounds_auth_reads` measures authentication rather than closing. The owner decides on the margin (top of this file).
- **HostCertificate.** The case is asserted per version, because 9.5p1 and 10.5p1 differ.
- **Committed in:** 39b2f78 and 5046eb3

**13. [Rule 1 - Bug, pre-push review] A spool read cut catch-up chains**
- **Issue:** `Read` kept only the newest 64 versions per kind, while `Verify` needs every version from the accepted one up. A host more than 64 versions behind would have refused `directory_chain_gap` (or `bundle_chain_gap`) on every run, and never converged. The code comment claimed otherwise.
- **Fix:** `spool.Read(dir, Floor)` reads the lowest 64 versions above what was accepted, plus the newest at or below it. `Stored.Floor` provides the floor. The plan's `Read(dir)` signature gains that argument.
- **Verification:** TestApply/catch_up_beyond_one_capture fails with the floor ignored (a mutant was run and restored), and passes with it. TestSpool/floor_selects_versions also passes.
- **Committed in:** b434787

**14. [Orchestrator] Carry-overs (a) and (b), one commit each**
- **(a)** computes every fix the role needs at once, because CheckPolicy reports only its first violation.
- **(b)** asserts, in the ID-less control, that the proposal commands are not refused at the base read.

---

**Total deviations:** 14: 2 from merged code, 2 Rule 1, 2 Rule 2, 1 Rule 3, 5 plan details, 1 plan criterion not met as written, and 1 orchestrator-directed.
**Impact on plan:** No new module and no scope beyond the plan. The LoginGraceTime finding is surfaced for the owner, not acted on.

## TDD Gate Compliance

- **Order.** Task 3 is `tdd="true"`, but Task 2, the tracer, had implemented the engine first. Most Task 3 tests passed on their first run.
- **Real RED.** Five failed first on real defects or test assumptions:
  - `login_grace_unbounded_refused` (wrote status.json);
  - `spool_dir_symlink_refused` (ENOTDIR);
  - `sshd_t_failure_rolls_back_dropin` (the fake's sshd -t failed on the restored config too);
  - `crash_anywhere_recovers` (the spool reset collided with the commit);
  - `recover_foreign_readable_current_via_intermediate` (its foreign generation collapsed).
- **Commits.** Fixes and tests went into one `test(03-05)` commit; there is no separate RED commit. RED was not faked.
- **Evidence instead.** The mutants above show that the tests check what they name.
- **The classifier was not used.** Go's test output is not a format `gsd-tools check tdd-red-evidence` reads, and `workflow.tdd_mode` is off.

## Issues Encountered

- **A signer flake under load.** In the first full `go test -race ./...` in WSL, TestStartRefusedOnLogMismatch and TestSignerRestore failed. They passed alone and in a second full run. They do not touch agent code; the cause is likely the heavier parallel load the new apply tests add. Watch the CI build-test job.
- **Heredoc backslashes again.** The Bash tool halves backslashes in heredocs, so some Python edits silently matched nothing. Edits switched to the Write and Edit tools; nothing broken was committed.
- **WSL's /tmp is cleared** between some `linux.sh` calls, so logs were kept in the scratchpad instead.

## Known Stubs

None. `--dry-run`'s diff is a line listing, enough for an operator; its wording is not a contract.

## Threat Flags

None beyond the plan's threat model. The only new network use is T-03-32's loopback self-test. The new file writes are all inside the paths allowlist (T-03-30).

## User Setup Required

None.

## Next Phase Readiness

- **03-06:**
  - calls `ObserveLoginGrace` and `Dump.LoginGrace`, and adds `no_loopback_listener` and `no_dropin_dir` to the preflight;
  - reads `generations/<N>.json` for drift;
  - should know that a drop-in other files override is caught only when the drop-in changes (`dropin_not_effective`).
- **03-07:** writes the spool with `spool.Write`. The applier reads at most 64 versions per kind above its accepted ones per run, so a fetcher may keep older files but catch-up takes several runs. Enrollment writes `pins.json` with `state.WritePins`. The operator runbook gets the timing rule above.
- **03-08:** units, a journald repeat of the stuck alert, `status.json` (`stuck`, `last_apply`), and `IPAddressDeny=any` with `IPAddressAllow=localhost`.
- **03-08 and 03-10:** each self-test adds a 1 s "noauth" penalty for 127.0.0.1 on OpenSSH 10.x, and 03-10's probes will add more. Frequent applies could reach the 15 s minimum that makes a penalty bite. A self-test failed that way rolls back to last-good, and so to last-good's KRL, until the next run. That is plan-conformant, but the interaction belongs on 03-08's and 03-10's radar.
- **03-09:** HostCertificate needs SIGHUP on 10.x and not on 9.x (see findings).
- **03-10 and 03-14:** register their files in `GenerationFiles` and leave swap.go alone.
- **Owner:** the LoginGraceTime slack on 10.5p1 (up to 3.6 s over LoginGraceTime 3) against the + 5 s margin.

## Self-Check: PASSED

- **Files.** Every key-files entry exists, including test/capslock/keyroster-agent.json and both e2e files.
- **Commits.** f3200b9, 0ba17b9, aeb74db, 39b2f78, a65f9ce, 6b0aac9, b434787 and 5046eb3 are ancestors of HEAD; `git rev-list --count 326007a..HEAD` is 8.
- **Task 2 acceptance greps:**
  - non-test `exec.Command` call sites exist only in internal/agent/apply/sshd.go;
  - `RenderPrincipalsFile` is called in render.go;
  - `spool.Read(` appears once outside tests, in apply.go's `capture`;
  - `Intermediate(` is called inside Transition in swap.go;
  - the only rename of `current` is replaceLink's `os.Rename`, reached only from swapCurrent (TestPaths 5). layout.go's `renameDir` renames generation directories only.
- **Task 3.** Every named case in the behaviour lists exists and passes, including every name in the plan's verify list (checked from `go test -v` output).
- **Task 4.** `git ls-files test/capslock/keyroster-agent.json` prints the baseline (after the commit), and `grep -n agent-apply-no-http .golangci.yml` prints the rule.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-26*
