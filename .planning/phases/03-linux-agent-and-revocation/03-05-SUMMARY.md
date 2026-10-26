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
  - "03-05 PR #67, owner decision 2026-10-26: the KRL never rolls back; a rollback or crash recovery moves current to RollbackTarget(current, last-good), last-good's CA keys, principals and drop-in with the newer KRL"
  - "03-05 PR #67, owner decision 2026-10-26: once the host has trust files, the KRL and CA keys always apply; a disabled or removed host gets no principals, rotated host keys keep last-good's principals, host_status in the report"
  - "03-05 PR #67, owner decision 2026-10-26: the widening wait is the LoginGraceTime bound + 30 s on CLOCK_MONOTONIC"

patterns-established:
  - "Root applier exec sites are internal/agent/execsite constructors (the only importer of os/exec), each listed in paths.ExecSites with its argv and its one caller in sshd.go (PR #67 review; first written as sshd.go only)"
  - "accepted/ is one atomic unit: snapshot directories and a current.json pointer with SHA-256s (PR #67 review)"
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

**Superseded (owner decision 2026-10-26, PR #67):** the owner set the margin to LoginGraceTime + 30 s, measured on CLOCK_MONOTONIC. See "Pre-merge review fixes" at the end.

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

**Superseded (owner decision 2026-10-26, PR #67):** additions are live at most LoginGraceTime + 30 s after the previous swap of `current` (150 s with the default), measured on CLOCK_MONOTONIC. A failed self-test no longer takes a revocation back, and a host the directory disables or removes still gets every KRL.

## Capslock pairs (test/capslock/keyroster-agent.json, 19 pairs; 20 since PR #67)

PR #67 review: the baseline gained `internal/agent/execsite CAPABILITY_EXEC`, because the exec sites moved there. capslock-check also requires every EXEC edge that leaves the module to start in execsite.


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
- **IPv6 loopback (`::1`) self-test dials.** Only the address mapping is unit-tested; no sshd ran on ::1. **PR #67 review:** an unreachable ::1 is now skipped. The real EADDRNOTAVAIL path ran as root in a network namespace with `disable_ipv6=1` on lo. A dial to a real sshd on a reachable ::1 is still not run.
- **Every homelab step.** UNVERIFIED until 03-16. The agent is not installable until 03-07.

## Decisions Made

See `key-decisions` in the frontmatter. Also:

- **No operator step changes in this plan (D-20).** The agent is not installable until 03-07, so no runbook gains an agent step. The only runbook change is the carry-over in machine-identities.md.
- **Rollback can undo a revocation.** A revocation whose self-test fails is rolled back to last-good's KRL. That is the plan's rule (rollback to last-good on a failed self-test); the report shows `rollback: true` with the error. 03-08's status surfaces it. **Superseded (owner decision 2026-10-26, PR #67):** the KRL never rolls back (decision 1 below).

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
- **03-08 and 03-10:** each self-test adds a 1 s "noauth" penalty for 127.0.0.1 on OpenSSH 10.x, and 03-10's probes will add more. Frequent applies could reach the 15 s minimum that makes a penalty bite. A self-test failed that way rolls back to last-good, and so to last-good's KRL, until the next run. That is plan-conformant, but the interaction belongs on 03-08's and 03-10's radar. **Superseded (owner decision 2026-10-26, PR #67):** such a rollback now keeps the newest KRL.
- **03-09:** HostCertificate needs SIGHUP on 10.x and not on 9.x (see findings).
- **03-10 and 03-14:** register their files in `GenerationFiles` and leave swap.go alone.
- **Owner:** the LoginGraceTime slack on 10.5p1 (up to 3.6 s over LoginGraceTime 3) against the + 5 s margin. **Superseded (owner decision 2026-10-26, PR #67):** + 30 s on CLOCK_MONOTONIC.

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

## Pre-merge review fixes

PR #67's pre-merge review (Claude lenses plus Codex) confirmed 14 findings, with duplicates merged here, and split 2. Each fix is on the branch from head `d2e9fb5`. Every item has a test that failed before the fix, or a mutant that the test kills. Mutants were applied, run and restored byte for byte. All 13 commits are SSH-signed by keyroster-bot.

### Owner decisions (2026-10-26, PR #67)

Recorded as T-03-270, T-03-271 and T-03-272 and in the review ledger of 03-05-PLAN.md, with the must_haves edited in place. Each later plan they reach gets one line per affected rule in a closing section, "Inherited from 03-05's pre-merge review": 03-06, 03-07, 03-08, 03-09, 03-10, 03-12, 03-14 and 03-16.

1. **The KRL never rolls back.** `99632f0`. A rollback or crash recovery now moves `current` to `RollbackTarget(current, last-good)`. That is last-good's files, except that each revocation list (FileKRL class) is the newer of the two by KRL version. CA keys, principals and the drop-in go back to last-good. The generation is last-good itself when the content is equal, otherwise a new validated generation, or current itself for a revocation-only change.
   - **Bookkeeping, defined precisely.** last-good names the last generation that passed a self-test, so its KRL may be older than current's. At rest current may hold last-good's CA keys and principals with a newer KRL. A start that finds current there recovers nothing. A later commit sets last-good as before.
   - **Tests.** `selftest_failure_after_krl_only_change_keeps_krl` covers a KRL-only change with a forced self-test failure: the KRL stays and last-good keeps its own KRL. `selftest_failure_rolls_back` covers a mixed change: principals and CA keys back to last-good, KRL 7 still in force, and the next run recovers nothing. Both failed against a stub with the old target.
   - **Also changed.** `TestSwapInterleaving/rollback_keeps_newest_krl` models the move. TestAgentApplyEndToEnd step 5 now expects last-good unchanged and current with last-good's CA keys and principals and the new KRL. The crash-recovery tests accept current at the rollback target.
2. **The KRL and CA keys always apply; principals are emptied for a disabled or removed host.** `e971d2e`. Once the host has a last-good, a Render refusal for this host goes on through `RenderFallback`:
   - the KRL and CA keys apply as Render renders them;
   - `host_disabled` or `host_removed` installs no principals files;
   - `host_keys_rotated` (keys match no entry while the entry last-good was rendered for is still active) and `host_keys_disagree` (keys match two entries) keep last-good's principals files.

   The report carries `host_status` and a warning goes to the log. Generation records now carry `host`, which tells a removed host from rotated keys.
   - **Tests.** `host_disabled_empties_principals_krl_applies`, `host_removed_...`, `host_keys_rotated_keeps_last_good_principals` (also with a record that has no host name), `host_keys_disagree_...` and `host_not_active_on_first_install_refused`.
   - **Mutants.** Without the fallback, all four host cases fail. Never keeping principals fails the rotated and disagree cases. Counting a removed host as rotated fails the removed case.
3. **The widening wait is LoginGraceTime + 30 s on CLOCK_MONOTONIC.** `da8df2e`. `graceMargin` is 30 s, used in widenDue, the marker deadline and the window of the earlier LoginGraceTime maximum. The timing rule reads CLOCK_MONOTONIC (`Clock.Monotonic`), and the records became `monotonic_ns` and `own_reload_monotonic_ns`. `last_swap.json` is now decoded strictly, so an old `boottime_ns` record counts as just made, which means a full wait.
   - **Go's clock.** Go 1.27.3's runtime `nanotime1` uses CLOCK_MONOTONIC (`runtime/sys_linux_amd64.s`), and Sleep runs on it.
   - **Safety argument, independent of the kernel detail.** The wait never counts suspended time. If sshd's timer also pauses during a suspend, the two match. If sshd's timer counts the suspend, it fires sooner and the agent waits longer. Either way the wait is never shorter than sshd's, so no extra period after a detected suspend is needed. The review checked that sshd arms its timer with `setitimer(ITIMER_REAL)`, in 9.9p1's sshd-session.c. On Linux that timer runs on CLOCK_MONOTONIC; this was not re-read in kernel source this session.
   - **Tests.** The TestApply timing cases now expect 150 s, 37 s and 630 s. `last_swap_old_format_means_full_wait` and TestSystemClockMonotonic are new. The e2e mixed change waits at least 33 s and measured 33.0 s. The `login_grace_*` subtests still bound sshd at LoginGraceTime + 5 s, as the owner asked.
   - **Mutants.** `graceMargin` set to 5 s fails four TestApply cases. Lenient decoding of `last_swap.json` fails the old-format case.

### Fixes without an owner decision

| Item (severity) | Commit | Test | Proof it bites |
|---|---|---|---|
| Crash in commit's first-install window left the drop-in and removed `current` (HIGH; Claude and Codex duplicates) | `79d1b36` | TestApply `crash_anywhere_first_install`: a crash at every fault point of a first install, then at every fault point of the recovery run; the drop-in must exist exactly when current and last-good name a generation with a KRL, with no marker left | Failed before the fix at k=7 (drop-in true, current false). The marker's new step `commit` keeps dropin_changed and dropin.prev until last-good is durable, and recovery finishes such a commit |
| Self-test failed every host with IPv6 disabled (HIGH) | `4857710` | TestSelfTestLoopbackFamilies (injected EADDRNOTAVAIL and EAFNOSUPPORT, IPv6 off, only ::1, an IPv4 EADDRNOTAVAIL, nothing on 127.0.0.1); TestSelfTestIPv6DisabledHost (real dialer) | The first three cases failed before the fix. The real-kernel test passed as root in an `unshare -n` namespace with `disable_ipv6=1` on lo, which gave a real EADDRNOTAVAIL |
| keyroster/ and gen/ modes depended on the umask (HIGH) | `f5a83fc` | TestGenerationModesUnderUmask (umask 077) | Before: keyroster/ and gen/ 0700 |
| accepted/ saved one file at a time (HIGH/MEDIUM; Claude and Codex duplicates) | `5f03c95` | TestApply `torn_accepted_save_never_mixes` (a crash between bundle.json and policy.json during a policy rotation that renders the same files); `crash_anywhere_recovers` now also requires accepted/ to move with last-good; TestStored (partial state never activated, files without a pointer, a staged snapshot not in force, a tampered file) | Before: accepted/ held bundle 2 with policy 1. Now `accepted/<N>/` plus `current.json` with SHA-256s, one rename; LoadStored refuses a hash mismatch and a bundle that does not name its policy; the commit marker names the staged snapshot and recovery activates it |
| hostKeys refused a missing default HostKey .pub (MEDIUM) | `aa5e76b` | TestHostKeys (default paths with only ed25519 present, none present, a private key without .pub) | Failed before: an open of ssh_host_rsa_key.pub |
| Exec pin, forbidigo and capslock missed trivial rewrites (MEDIUM) | `0ae678d` | TestPaths `exec_only_in_execsite` and `exec_sites_pinned`; depguard `agent-exec-only-in-execsite`; forbidigo process-start pattern; capslock-check EXEC call-graph gate | Mutant A (aliased os/exec plus an exec.Cmd literal in apply) and mutant B (os.StartProcess) each failed TestPaths, golangci-lint and capslock-check. Mutant C (an unlisted execsite constructor) and mutant D (a listed constructor called with another binary) failed TestPaths |
| Generation read limits not validated before install (MEDIUM) | `e94b9c0` | TestApply `oversize_generation_refused_before_install` (17 bulk roles, 32 principals of 128 characters) | Before: installed (generation 2), which would fail every later readCurrent |
| Capped catch-up refused every capture across a policy rotation (MEDIUM) | `56638ea` | TestApply `catch_up_across_policy_rotation` (67 directories under the old policy, then a rotation, once also with a new ops key and a KRL signed by it) | Before: `directory_not_verified` on every run. A mutant without the KRL wait fails the ops-key case |
| Signal reload signalled a stale PidFile's PID (LOW) | `d9d8633` | TestReloadSignal (another process, the configured binary, a binary replaced under it, an exited process) | Before: the unrelated process got SIGHUP |
| no_loopback_listener only detected by the post-swap self-test (SPLIT LOW) | `b141e95` | TestApply `non_loopback_listener_refused` now also requires no reload, no drop-in, no current and no marker | Before: 2 reloads. Decision: 03-06's preflight covers the first apply and drop-in changes (its key_link "the first apply, and every drop-in change, runs Preflight before any reload"), but 03-06 is not merged and the check is a pure function of the `sshd -T` dump, so writeDropIn now runs it before writing. A steady-state host that loses its listener with the drop-in unchanged is still caught by the self-test, whose rollback now keeps the KRL |
| Widening wait's + 5 s margin and CLOCK_BOOTTIME (SPLIT LOW) | `da8df2e` | as decision 3 | as decision 3 |

### Choices made inside the decisions, for the owner to confirm

- **First install.** It still refuses a disabled or absent host and installs nothing, as before. There is no access to narrow yet, and installing the drop-in would change sshd's configuration for a host the directory does not admit.
- **Identity uncertain.** `host_keys_disagree`, and a last-good record without a host name (only records from before this change), are treated like rotated keys: last-good's principals are kept.
- **Residual of decision 2.** While a host's keys stay rotated, principal changes in the directory do not reach it.
- **`generation_too_large`.** It refuses the whole apply, so a KRL in the same capture does not land either. Option: route it through the fallback, with the KRL and CA keys applied and last-good's principals kept.
- **`--recover-to-last-good`.** The operator's recovery from a foreign `current` still goes to last-good's own files, so it can install an older KRL than the one in force. Not changed here; this is a residual of decision 1. Option: apply RollbackTarget to an agent-made `current` there too. *(Superseded in round 2, `04b7d8e`: an agent-made `current` now goes to RollbackTarget; a foreign one still goes to last-good's KRL.)*
- **03-10 interaction.** A host with `host_status` host_disabled or host_removed has no principals files, so 03-10's positive probe cannot pass there. 03-10-PLAN.md now carries a line saying the probe must skip such a host, or keep its principals file, instead of rolling back every apply.
- **Contract changes later plans read.**
  - `pending.json` has the step `commit` and an `accepted` field.
  - accepted/ is snapshot directories plus `current.json`.
  - Generation records gain `host`.
  - The report gains `host_status` and `bundle_held`.
  - New exec sites must be execsite constructors with a `paths.ExecSites` entry.

### Gates on the final code head (`e971d2e`), WSL Ubuntu, Go 1.27.3

- `gofmt -l .` is empty.
- `go vet ./...` passes for linux, windows and darwin, and so does `GOOS=linux go vet -tags e2e ./test/e2e/`.
- `CGO_ENABLED=1 go test -race -count=1 ./...` passes. internal/agent/apply took 130 s under -race, against the 10-minute default timeout.
- golangci-lint reports 0 issues for linux, windows and darwin.
- `scripts/capslock-check.sh`: signer 91/91, agent 20/20, and EXEC leaves the module only through execsite (2 edges).
- `scripts/dep-firewall.sh` and `scripts/testonly-firewall.sh` are clean.
- TestAgentApplyEndToEnd and TestSshdRereadsTrustFiles pass locally on OpenSSH 10.5p1 and 9.5p1, with the `signal` reload against the real test sshd, so the PidFile check matched the real sshd process.
- The required checks on the pushed head are in the handback.

### UNVERIFIED

- A real suspend during a widening wait. WSL and CI cannot suspend, so TestSystemClockMonotonic only bounds the reading (BOOTTIME - MONOTONIC was 0 here).
- EAFNOSUPPORT from a kernel booted with `ipv6.disable=1`. It is covered only by the injected dialer.
- A self-test dial to a real sshd on a reachable ::1.
- The pidfd path on kernels older than 5.3. pidfd_open is required, and RHEL 8 is already unsupported (03-06).
- Real root, systemd and OpenRC reloads, and every homelab step, as before.

### Self-Check (pre-merge review fixes): PASSED

- The commits `f5a83fc`, `aa5e76b`, `4857710`, `d9d8633`, `b141e95`, `e94b9c0`, `0ae678d`, `79d1b36`, `5f03c95`, `56638ea`, `da8df2e`, `99632f0` and `e971d2e` are ancestors of HEAD, and each has a good SSH signature from keyroster-bot's signing key.
- `git rev-list --count d2e9fb5..e971d2e` is 13.
- internal/agent/execsite/execsite.go exists.

## Pre-merge review fixes, round 2

The fix-round check on head `8760bc3` confirmed four findings and split one. Each item has one SSH-signed keyroster-bot commit and a test that fails with the fix reverted or mutated (mutants applied, run and restored byte for byte).

1. **The KRL in force could still go back (HIGH, both skeptics upheld).** `04b7d8e`. A KRL that a rollback or crash recovery kept in `current` was not in accepted/, so a later capture that no longer offered it rendered the older accepted KRL, swapped to it and committed it. Fix: forward and pollSpool render with the KRL of the agent's `current` as the floor (`keepKRLInForce`). As a hard guard, swapCurrent (every mode) and setLastGood refuse a generation whose KRL is older than the agent's generation in current or last-good (`krl_rollback_refused`). `--recover-to-last-good` from an agent-made `current` moves to RollbackTarget, and the report names the KRL version in force. The floor is the KRL in force, not a KRL staged into accepted/ at rollback, the reviewer's alternative. accepted/ still moves only with last-good (5f03c95, asserted by `crash_anywhere_recovers`), and crash recovery holds no verified manifest it could stage, so staging would stall a recovered host. 03-08 already reads the KRL in force from `current`. Tests: TestApply `krl_kept_by_{rollback,crash}_survives_withheld_capture_{commit,rollback}` (the reviewer's probe), `krl_floor_refuses_older_swap_and_last_good`, `recover_to_last_good_keeps_newer_krl`. Proof: with the floor and the guard both removed, current and last-good no longer revoke serial 7 (the bug reproduced). With only the floor removed the guard refuses the swap, and the commit cases fail. With only the guard removed the guard test fails. With the recovery routed to last-good as before the recover test fails. The crash matrix stays green. Remaining exception: the operator's recovery from a *foreign* `current` (whose KRL was never verified) goes to last-good's KRL.
2. **Exec-site pin bypass (MEDIUM, split).** `03f7d3a`. `exec_sites_pinned` now requires every `execsite.<Ctor>` selector outside execsite to be the callee of a pinned call, and it refuses a dot import of execsite. The new `execsite_imported_only_by_apply` subtest (`go list ./...`, GOOS=linux, non-test imports) refuses any package of the module but internal/agent/apply importing execsite. Proof: mutants E7 (func value in sshd.go), E8 (helper in a new internal/hx), E9 (package-level var) and E10 (dot import in apply) each passed TestPaths at `8760bc3` and fail it now.
3. **No test bit on LoadStored's SHA-256 check (LOW).** `8c48a59`. TestStored `tampered_byte_of_valid_snapshot_refused` saves a complete snapshot (the golden genesis bundle and policy), flips one byte of `bundle.json.sigs` and requires `stored_state_invalid` with "does not match its SHA-256". Proof: with the check disabled only the new subtest fails.
4. **IPv4 never-skipped case did not bite (LOW).** `100c99e`. TestSelfTestLoopbackFamilies adds `[::]:port`, `0.0.0.0:port` and `127.0.0.9:port` with 127.0.0.9 failing EADDRNOTAVAIL. Proof: with `v6 &&` dropped from the skip case, the self-test passes on 127.0.0.1 and the new case fails.
5. **Signal reload refused after an upgrade through a symlinked directory (LOW).** `d7384d8`. runsBinary also accepts the configured path with its directory's symlinks resolved (`resolvedDir`), in the " (deleted)" form too. TestReloadSignal adds sshd started as `link/sshd` with `link -> real` and the binary replaced. Proof: with the comparison back to `filepath.Clean` only, it fails with "runs .../real/sshd (deleted), not .../link/sshd".

**Gates on the round-2 code head (`d7384d8`), WSL Ubuntu, Go 1.27.3:**
- gofmt is clean.
- go vet passes for linux, windows and darwin, and with `-tags e2e`.
- golangci-lint reports 0 issues for linux, windows and darwin.
- dep-firewall and testonly-firewall are clean.
- capslock-check: signer 91/91, agent 20/20, EXEC only through execsite (2 edges).
- `go test -race -count=1 ./...` passes; internal/agent/apply took 128 s.
- TestAgentApplyEndToEnd and TestSshdRereadsTrustFiles pass on OpenSSH 10.5p1 and 9.5p1.

**UNVERIFIED (round 2):**
- A real distribution with `/usr/sbin` or `/sbin` symlinked (Arch, merged-/usr Debian). Only the temp-directory symlink of TestReloadSignal was run.
- A real withholding fetcher. Only the spool emptied by the test was run.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-26*
