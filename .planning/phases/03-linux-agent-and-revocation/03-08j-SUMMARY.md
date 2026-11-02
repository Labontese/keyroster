---
phase: 03-linux-agent-and-revocation
plan: 08j
subsystem: agent
tags: [agent, apply, state, spool, fetch, heartbeat, krl, revocation, d-r2]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08e: spool.Cap, spool.Keep, pickAbove, the fetcher's pruneSpool (Keep(accepted.json, 1024)), parseApply's defaults (this plan's precondition)"
provides:
  - "state: verify(p, chain, alone, in), the steps against chain and the KRL-alone pass against alone; the bundle in force as the lowest hold step"
  - "state: Unapplied (UnappliedFile, MaxUnapplied, ErrUnapplied, ParseUnapplied, Encode, Base), Verified.Unapplied and VerifyAhead"
  - "apply: loadUnapplied (the one loader), recordUnapplied (merging), mergeUnapplied, dropPassedRecord in finishCommit, Report.Unapplied"
  - "apply: WriteAccepted raised to the record's versions; ResetDirectory's record step (step 0)"
  - "heartbeat: Status.Unapplied and its Validate rule; keyroster host status's unapplied alert and note"
  - "spool: Read's one recapture after an ENOENT (readOnce, readSpool)"
  - "tests: TestSpoolWindow (23 cases), TestSpoolWindowWideningWait (7 cases), TestValidate's unapplied row, TestHostStatusUnapplied, TestReadRecapture"
  - "apply: pollCapture, a widening wait's capture chained from the record while it is ahead of the pending target (pre-merge review fix round 1)"
  - "heartbeat: Status.UnappliedAbove; Committed and Diverged count an unapplied version above current (pre-merge review fix round 1)"
  - "docs: host-setup.md far-behind paragraphs, two sentences after the fetcher paragraph, the unapplied alert; signer-install.md host selection and remedy; the spool-pruning todo's remaining item"
affects: [03-08k, 03-09, 03-10]

actuals:
  tokens: 16600
  tasks: 5
  commits: 6
plan_head_before: 9ac9c12d4415083ed1985637bf56f1c028857bb5
plan_head_after: 41b47fd6db2d50fa61b5314ccc20075e299c1856

tech-stack:
  added: []
  patterns:
    - "A refused verified state is recorded as copies in the root-owned state directory and becomes the only chain base; the KRL-alone pass stays on accepted/"
    - "One loader (loadUnapplied) for every reader of the record; no loader error stops an apply, a reset or a status write"

key-files:
  created:
    - internal/agent/state/unapplied.go
    - internal/agent/apply/window_test.go
    - .planning/phases/03-linux-agent-and-revocation/03-08j-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md
  modified:
    - internal/agent/state/verify.go
    - internal/agent/apply/apply.go
    - internal/agent/apply/installed.go
    - internal/agent/apply/resetdir.go
    - internal/agent/apply/status.go
    - internal/agent/fetch/fetch.go (doc comment only)
    - internal/agent/enroll/pop.go (doc comment only)
    - internal/agent/spool/spool.go
    - internal/agent/spool/spool_test.go
    - internal/agent/heartbeat/heartbeat.go
    - internal/agent/heartbeat/heartbeat_test.go
    - cmd/keyroster/hoststatus.go
    - cmd/keyroster/hoststatus_test.go
    - docs/runbooks/host-setup.md
    - docs/runbooks/signer-install.md
    - .planning/todos/pending/2026-10-28-agent-spool-pruning.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (to 03-16-PLAN.md, the wave lines; 03-09 also depends_on and its precondition)

key-decisions:
  - "The bundle in force is offered as the lowest hold step exactly when chain.BundleVersion is above alone.BundleVersion, compared by version only, so a directory-only record leaves Verify's steps unchanged"
  - "VerifyAhead recomputes BundleChanged and DirectoryChanged against accepted/ by bytes; KRLChanged stays as verified against the base, which carries accepted/'s KRL"
  - "recordUnapplied keeps the existing part at an equal version; a part is replaced only by a higher version of the same kind"
  - "forward does not record a refusal that is an injected crash (isCrash), so a fault test never leaves a record"
  - "ResetDirectory logs a failed removal of a damaged record to stderr (its engine had no log writer before)"
  - "The bundle case uses the dropped-entry shape: bundle 66, a successor of 65 without its next CA entry, passes trust.ParseBundle and trust.VerifySuccessor"

requirements-completed: []

duration: 60min
completed: 2026-11-02
---

# Phase 3 Plan 08j: Read past a verified version a host cannot apply, and report it, Summary

**A verified state refused for its content is recorded in `<state>/unapplied.json`; the next apply reads and chains from the record, installs the next version it can and reports `unapplied` fleet-wide, while the KRL-alone pass stays on accepted/ (PR #76 review F8). spool.Read also recaptures once after a listed file vanished (F01 (03-08e) follow-up).**

## PR

- PR: #78 (branch `p03/08j-agent-spool-window`), opened without auto-merge after the SUMMARY was pushed.
- CI on 43d75c1: every required check green. Workflow runs 41387425820 (ci: build-test, lint, fuzz, capslock, govulncheck, dependency-firewall, cli-macos, cli-windows), 41387425370 (e2e-distro, seven distributions), 41387425600 (e2e 9.5p1 and 10.5p1), 41387425552 (systemd-sandbox), 41387425510 (e2e-pkcs11), 41387425450 (e2e-tpm), 41387425446 (build-piv), 41387425509 (CodeQL analyze), 41387425561 (pinned-actions), 41387425595 (pr-title); build-test job 125091260620.

## Commits

| Task | Commit | Message |
|------|--------|---------|
| 1 (tracer) | cbe5c4a | fix(agent): read past a verified directory the host cannot apply (PR #76 review F8) |
| 2 | 9a8e7ed | fix(agent): record refused bundles too and keep the record the only chain base (PR #76 review F8) |
| 3 | 8153986 | feat(agent): report unapplied versions in the heartbeat status (PR #76 review F8) |
| 4 | 18f6a39 | fix(agent): recapture the spool once when a listed file is gone (F01 (03-08e) follow-up) |
| 5 | 3b140be | docs(agent): how a host reads past a version it cannot apply (PR #76 review F8) |
| 2 (follow-up) | 41b47fd | test(agent): run the policy-rotation rows below a recorded bundle as subtests (PR #76 review F8) |
| 5 | (this commit) | docs(03-08j): complete agent spool-window plan |

## What changed

- **state.** Verify's body moved into `verify(p, chain, alone, in)`. The bundle, directory and KRL steps run against chain; a refused step returns `KRLAlone(p, alone, ...)`. When alone has a bundle and chain's BundleVersion is above it, alone's bundle step is prepended as `steps[0]`, so `holdBundle` can still hold the capture at the bundle in force. `Verify` is `verify(p, prev, prev, in)`, unchanged in behaviour.
- **state, unapplied.go.** The record type with its codec (`trust.CanonicalJSON`, `ParseUnapplied` with `trust.DecodeStrict`, per-field caps as spool.Read's, complete parts, never empty). `Verified.Unapplied` records the parts of `Next` ahead of accepted/ (the held step after `holdBundle`). `Base` copies accepted/ and takes each part above accepted/'s version (a bundle part only when the bundle names its policy). `VerifyAhead` is `verify(p, base, accepted, in)` with Changed recomputed against accepted/.
- **apply.** `loadUnapplied` reads the record without following links. forward drops a damaged record with a warning, removes a passed one (with a log line since the pre-merge fix round), reads from the record's floor with `VerifyAhead`, and calls `recordUnapplied` (merging) just before the KRL-alone pass of a content refusal. `finishCommit` removes a record the new accepted/ has passed. Apply's epilogue sets `Report.Unapplied`. pollSpool was unchanged in the plan; the pre-merge fix round chains its captures from the record (below).
- **installed.go.** `WriteAccepted` raises the bundle and directory to the record's versions where higher; `AcceptedVersions` is unchanged.
- **resetdir.go.** Step 0 (after the lock and the pending-marker check, before step 1) rewrites the record without its directory part when its bundle part is still ahead, and removes it otherwise.
- **heartbeat, status, CLI.** `Status.Unapplied {bundle, directory}` (omitempty); Validate refuses only both zero. buildStatus sets it from the record. `keyroster host status` shows `unapplied: bundle vB, directory vD` and a note.
- **spool.** `Read` is `readSpool(dir, floor, nil)`; `readSpool` runs `readOnce` and, when its error wraps `unix.ENOENT`, runs it once more from a fresh listing.
- **docs.** host-setup.md: 03-08d's far-behind paragraph replaced; two sentences after 03-08e's fetcher paragraph; the `unapplied` alert with the rollout order. signer-install.md: the host selection names the record, with the remedy for a recorded bundle a restore lost. The spool-pruning todo: one Status sentence and the read-floors item.

## RED evidence

All RED runs were taken locally in WSL with `go test -race -count=1 -v`.

- **Task 1** (on the stubs: `Base` returning nil, `Unapplied` returning nil, `VerifyAhead` = `Verify` from accepted/): `refused_window_newest_then_fix_applies` FAIL with `apply 1: Unapplied <nil>, want {Directory: 65}`, `apply 1 wrote no unapplied.json` and `apply 2: generation_too_large: principals/deploy would be 70382 bytes, above 65536, want directory 66 installed` (DirectoryVersion 1, role:old still granted): the review's defect. `window_control_within_reach` PASS (the control).
- **Task 2** (on Task 1's head, cbe5c4a): RED as the plan expects: `unchanged_spool_still_refused` (`apply: <nil>, want generation_too_large`: Changed against the record reported ok), `bundle_ca_line_window_newest_then_fixed_bundle_applies` (`Unapplied <nil>, want {Bundle: 65}`), `recorded_state_installed_when_the_host_accepts_it`, `krl_only_the_recorded_bundle_signs_waits` (record `{Directory: 2}` without its bundle), `policy_rotation_below_the_recorded_bundle`, `held_content_refusal_keeps_the_records_bundle`, `bundle_fork_after_the_record_takes_the_krl_against_accepted`, `removed_record_takes_the_remade_bundle_chain`, `reset_directory_keeps_the_records_bundle` (each: no record with a bundle part), `fetcher_cursor_follows_the_record` (`accepted.json {Bundle:1 Directory:1 ...}`), `reset_directory_drops_the_records_directory` (`the interrupted reset left the record's directory as the chain base`).
- **Task 2, GREEN at once** (as the plan expects, with its reasons): `refused_run_longer_than_a_window_reaches_fix` (Task 1 already reads past each window), `fork_after_the_record_refused` and `spool_copy_of_the_recorded_version_ignored` (Task 1 already chains from the record's bytes), `withheld_record_version_does_not_roll_back` (no capture is verified from accepted/ while a record exists), `damaged_record_dropped` and `removed_record_reads_from_accepted` (Task 1's loader), `no_record_after_a_verify_refusal_or_a_dry_run`, `record_write_failure_keeps_the_krl` (the harness's state directory accepts a directory at the record's path; CheckStateDirs does not refuse it).
- **Task 3** (field only): `status_reports_unapplied` (`unapplied <nil>`), `TestValidate` (`unapplied: <nil>, want heartbeat_field_invalid naming unapplied`), `TestHostStatusUnapplied` (no alert, no note).
- **Task 4** (seam, no retry): `listed_name_gone_is_recaptured_once` (`open policy-9.json: no such file or directory, want a recapture`), `gone_again_fails_the_capture` (`after 1 listings, want ENOENT after 2`).

## Mutants

Each was applied in a scratch copy of the tree, run against its named test (locally in WSL), and restored; the files were then compared byte for byte with the working tree (`cmp`), and no backup was left. All are killed.

| # | Mutant | Killed by |
|---|--------|-----------|
| T1a | forward's recordUnapplied call removed | refused_window_newest_then_fix_applies |
| T1b | finishCommit's removal (dropPassedRecord) removed | refused_window_newest_then_fix_applies (the file assertion after apply 2) |
| T1c | Base taking a directory part at or below accepted/'s version | refused_window_newest_then_fix_applies |
| T2a | VerifyAhead's Changed left against the base | unchanged_spool_still_refused, recorded_state_installed_when_the_host_accepts_it |
| T2b | forward handing the base to krlAlone instead of stored | krl_only_the_recorded_bundle_signs_waits |
| T2c | verify's refused step taken alone against chain | bundle_fork_after_the_record_takes_the_krl_against_accepted (accepted/'s bundle became 2), fork_after_the_record_refused |
| T2d | verify no longer offering the bundle in force as the lowest step | policy_rotation_below_the_recorded_bundle |
| T2e | recordUnapplied replacing the record instead of merging | held_content_refusal_keeps_the_records_bundle |
| T2f | forward verifying a second capture from accepted/'s floor after a refusal from the record | fork_after_the_record_refused (it installed the renderable 65') |
| T2g | loadUnapplied reading the recorded version's file from the spool instead of the record's bytes | spool_copy_of_the_recorded_version_ignored |
| T2h | verifyDirectory chaining from the capture's copy at the base's version | spool_copy_of_the_recorded_version_ignored |
| T2i | WriteAccepted's raise removed | fetcher_cursor_follows_the_record |
| T2j | ResetDirectory's record step removed | reset_directory_drops_the_records_directory |
| T2k | ResetDirectory's record step moved after the spool removal, just before WriteAccepted | reset_directory_drops_the_records_directory (its interrupted reset left the record) |
| T3a | buildStatus not setting Unapplied | status_reports_unapplied |
| T3b | Validate's both-zero rule removed | TestValidate |
| T3c | the CLI alert removed | TestHostStatusUnapplied |
| T4a | Read without the recapture | listed_name_gone_is_recaptured_once |
| T4b | Read recapturing until it succeeds (bounded at 10 in the mutant) | gone_again_fails_the_capture (11 listings) |

T2d was run against each row of `policy_rotation_below_the_recorded_bundle` separately (`newOps=false` and `newOps=true`, subtests since 41b47fd); both fail with `directory_not_verified: version 65: directory: admin quorum not met`. The harness cannot tell step 0 apart from a placement directly after step 1's save (the plan says so); the doc comment's step 0 covers that order.

## Verification

- Task verifies (locally in WSL, -race): Task 1's, Task 2's, Task 3's and Task 4's `-run` sets all PASS, with every line the plans' fails_when lists.
- Full gate (locally in WSL, at 3b140be; 41b47fd only splits one test into subtests): `go test -race -count=1 ./...` passed (378 s), `go vet` (plain, `e2e`, `e2e systemdsmoke`), gofmt, golangci-lint (0 issues), capslock-check, dep-firewall, testonly-firewall and check-pinned-actions all pass.
- Acceptance greps: `func VerifyAhead(` 1 in unapplied.go, `state.VerifyAhead(` 1 in apply.go code, no `json:"krl` in unapplied.go, window_test.go starts with `//go:build linux`; `loadUnapplied(` in installed.go, resetdir.go and status.go code; fetch.go and pop.go changed in comment lines only (0); `json:"unapplied,omitempty"` 1 in heartbeat.go; `^func readSpool(dir string, floor Floor, listed func())` 1.
- Publish checks: the waves of 03-09 to 03-16 at origin/main + 1, 03-09's depends_on and precondition clause, STATE's total_plans and `of M`, the ROADMAP's Plans line and wave headers (1..23, each "blocked on Wave N-1"), the 03-08j row under Wave 15 and 03-09 under Wave 16: all pass.
- Test times under -race: internal/agent/apply took 294 s locally in WSL at Task 2's head (with other runs in parallel), beside 290 s locally at 03-08e's last code commit and 164 s in CI at PR #76's head; internal/agent/spool 3.4 s locally. In the full local gate, internal/agent/apply took 310.6 s and internal/agent/spool 4.8 s. In CI (build-test job 125091260620, under -race): internal/agent/apply 160.6 s, internal/agent/spool 2.7 s, internal/agent/fetch 12.5 s, internal/agent/state 1.1 s; all well below the 400 s limit.

## Pre-merge review fix round 1

The PR #78 review's items D-1, D-2, D-3 and L-1 to L-4 are fixed. Every RED below was run locally in WSL on the tree at 21e7135 with the new tests added. Every mutant was applied in a scratch copy and then restored.

| Item | Commit | What changed |
|------|--------|--------------|
| D-1 | aeb15e9, 6cf4449 | A widening wait's polls chain from the unapplied record, as forward does |
| L-1, L-2 | 2d97a92 | reset-directory's step 0: a removal is synced; every drop is logged |
| D-3 | b8f75e3 | An unapplied version above the server's current one counts as diverged |
| D-2 | 1b5acb1 | signer-install.md's remedy for a lost recorded bundle converges |
| L-3, L-4 | 1151aa5 | ROADMAP row encoding; STATE file count |

### D-1: polls during a widening wait

- **The problem.** pollSpool verified each poll's capture against the pending target alone. When forward held that target at the bundle in force, below a recorded bundle, a poll read from the bundle in force again. Three things could then supersede the target: an older bundle below the record (at the 64-version window boundary, or held at an earlier policy), a spool copy at the record's version, or a re-made chain. The commit then removed the record.
- **pollCapture.**
  - It lays the record over the pending target (`Unapplied.Base` against it): per kind, the record's part where it is higher, otherwise the pending target's.
  - While a part is ahead, it reads from that base's floor and verifies with `VerifyAhead`. The pending target is the state for the KRL-alone pass and for the lowest hold step.
  - A capture that brings nothing beyond the base supersedes the target only with a newer KRL, verified against the pending target (`KRLAlone`). So no poll renders the refused record again.
  - When no record is ahead, or the record does not load, the poll uses `Verify` against the pending target, as before.
- **Logging.** dropPassedRecord and forward's load now log the removal of a passed record.
- **Truths met.** The plan's truth that the record is the only chain base while it exists, and that no capture is verified below it, now holds during a widening wait too. The plan's line "pollSpool is unchanged" is superseded by this fix.
- **Tests.** TestSpoolWindowWideningWait has seven rows. Each asserts the following:
  - accepted/ keeps the original bundle 1 bytes;
  - the record keeps the recorded bundle's bytes;
  - the CA line the record removed is in no trust file;
  - the widened principals land;
  - no poll rendered the record;
  - the KRL published during the wait lands.
- **RED at 21e7135: all seven rows.**

  | Row | Result at 21e7135 |
  |-----|-------------------|
  | `older_bundle_at_the_window_boundary` | installed bundle 65 |
  | `record_version_withheld` | installed bundle 2 |
  | `newer_directory_under_the_policy_in_force` | installed bundle 2 |
  | `fork_at_the_record_version` | installed 3' |
  | `remade_chain` | installed 4' |
  | `remade_chain_under_the_old_policy` | installed 4' |
  | `nothing_new` | the wait rendered the recorded bundle 60 times |

  GREEN after the fix.
- **Mutants: all killed.**

  | Mutant | Killed by |
  |--------|-----------|
  | No guard | `nothing_new`, `fork_at_the_record_version`, `newer_directory_under_the_policy_in_force`, `older_bundle_at_the_window_boundary` |
  | `VerifyAhead` with the base as alone | `record_version_withheld`, both re-made rows, `newer_directory_under_the_policy_in_force` |
  | The guard returning nothing | `fork_at_the_record_version` (the KRL did not land) |
  | The capture read from the pending target's floor | `remade_chain_under_the_old_policy` |
  | No log line for a passed record | `refused_window_newest_then_fix_applies` |

### L-1 and L-2: reset-directory's step 0

- **Sync.** resetRecord syncs the state directory after it removes unapplied.json. A failed sync fails the reset for a record that parsed, and is logged for a damaged one.
- **Log lines.** Every change step 0 makes is logged:
  - a rewrite without the directory part, and a removal, name the recorded directory version and SHA-256 when it was ahead of accepted/;
  - a damaged record's removal is a WARNING with the loader's error.
- **Log seam.** `resetDirectory` takes the log writer, and `ResetDirectory` writes to stderr as before.
- **Tests.** `reset_directory_drops_the_records_directory` now checks the log line, and `reset_directory_logs_what_it_drops_from_the_record` is new.
- **Mutants: all killed.** Three mutants, each dropping one log line: removal (killed by the first test), rewrite and damaged record (both killed by the second). L-1 has no RED: no test can lose an unsynced unlink (see Untested paths).

### D-3: an unapplied version above current

- **Status.** `Status.UnappliedAbove` is new. Committed is false and Diverged is true for a host whose unapplied record is above the server's current version.
- **keyroster host status.** It leaves such a host out of that kind's "on version" count, and its note gives the signer-install.md remedy instead of "applies the next version it can".
- **host-setup.md.** The `diverged` and `unapplied` alerts, and the counting rule, say so.
- **Tests.**
  - Three new TestCommittedAndDiverged rows.
  - A web4 row in TestHostStatusDiverged.
  - TestHostStatusUnapplied's server versions are now the recorded ones, and it asserts no `diverged`.
- **RED.** On hoststatus.go and heartbeat.go at 21e7135, with `UnappliedAbove` as a stub returning false: `TestHostStatusDiverged` (counted as converged) and the two above-current TestCommittedAndDiverged rows.
- **Mutants: all killed.** Diverged ignoring the record; Committed ignoring the record; the note not switched; the count ignoring the record.

### D-2: the remedy for a lost recorded bundle

- **The remedy.** signer-install.md's remedy now has four steps:
  1. Read the accepted bundle version from `outbox/status.json`.
  2. Remove the spool's bundle files above it.
  3. Remove the record.
  4. Let the next poll bring the re-made chain.

  The spool files go first, so that an apply between steps 2 and 3 records nothing.
- **The test.** `removed_record_takes_the_remade_bundle_chain` now leaves the spool as a fetcher does. It has two rows: re-made up to 2', and up to 3'.
  - Removing only the record does not converge: the lost 2 is recorded again and accepted.json names it again, or the chain refuses to link.
  - An apply between the remedy's steps records nothing.
  - After a fetch from the accepted bundle, the re-made chain installs.
- **No RED.** This is a documentation and test change; the code is unchanged.
- **UNVERIFIED.** The fetcher side is reasoned, not run (see UNVERIFIED).

### L-3 and L-4

- **ROADMAP.md.** The 03-08j row's Windows-1252 dash byte is now a UTF-8 em dash. Every file the PR changes passes `iconv -f UTF-8 -t UTF-8`.
- **STATE.md.** The metrics row counts 30 files, which is `git diff --stat 9ac9c12 21e7135`.

### Gate

Run locally in WSL at 1151aa5:
- `go test -race -count=1 ./...`: passed (392 s). internal/agent/apply took 351.0 s under -race in that run, alongside every other package.
- vet, gofmt, capslock-check, dep-firewall, testonly-firewall and check-pinned-actions: pass.
- golangci-lint: reported three unused test parameters, fixed in 6cf4449.

At 6cf4449, run locally in WSL: golangci-lint reports 0 issues and gofmt is clean. internal/agent/apply took 278.9 s under -race when run alone, below its 400 s limit. Under Verification above, the same package took 294 s at Task 2's head (with other runs in parallel) and 310.6 s in the full gate.

## Deviations from Plan

1. **The tracking updates were made by hand**, not with gsd-tools, so no untracked state file is touched. The plan inserts the 03-08j row unchecked and then runs the tracking updates once; as in 03-08e's PR (whose plan said the same), they check the row and count the plan as executed: the Plans line reads 16/24 in 23 waves, STATE.md total_plans 59, completed_plans 51, `Plan: 17 of 24`, with the metrics row and decisions. `requirements.mark-complete` was not run (requirements-completed is empty). The plan's publish checks pass.
2. **forward does not record an injected crash's refusal** (`!isCrash(refusal)` around recordUnapplied). The plan lists when nothing is written; a crash refusal never reaches the KRL-alone pass, so this only makes that explicit.
3. **ResetDirectory's engine logs to stderr**, so the warning for a damaged record whose removal fails is printed (the plan says it is logged; the engine had no log writer).
4. **Test helpers in window_test.go**: `successorNextUnder` (successorWithNext under a kept, rotated policy) and `successorWithout` (a successor dropping the next CA entry), because the existing builders hardcode policy 1 and their issued_at. rechain_test.go and apply_test.go are unchanged.
5. **TestSpoolWindow cases use the production spool place** (`spoolInState`), so accepted.json is written to an outbox and ResetDirectory may remove spool files.
6. **policy_rotation_below_the_recorded_bundle's two rows are subtests** (41b47fd, after Task 2's commit), so the T2d mutant is shown killed on each row, not only on the first.

## Deferred Issues

None.

## Untested paths

- ResetDirectory with a record that parses but cannot be rewritten or removed (the reset then fails before step 1): no test makes that write fail.
- ResetDirectory's sync of the state directory after it removes the record (pre-merge fix round, L-1): no test loses an unsynced unlink, and none makes the sync fail.

## UNVERIFIED

- That 03-08e's prune, counted from the raised accepted.json, keeps what a capture from the record reads: reasoned from the code (Planner decisions), not tested with the fetcher.
- A removed record meeting a pruned spool (the chain-gap sentence in host-setup.md).
- A real capture racing a real prune; the seam stands in for it.
- The residual (a directory signed only under a policy strictly between the bundle in force and the recorded bundle) and its hand remedy: no test builds two policy rotations in one gap.
- Mixed server versions during the rollout (server before agents, no rollback).
- signer-install.md's remedy for a lost recorded bundle (pre-merge fix round, D-2): that the fetcher then asks from the accepted bundle and brings the re-made versions is reasoned from its cursor (the lower of accepted.json and the spool's newest version); the test writes what such a fetch would. That a lost policy file left in the spool is harmless (the applier finds a bundle's policy by its SHA-256) is reasoned, not run.
- Everything on a real host, and hosts more than 130 versions behind.

## Threat model

- T-03-316 (the stuck window): mitigated by the record, the hold step, the cursor and the status; tests as the plan lists, all passing.
- T-03-317 (the record used to widen what is installed): mitigated; the KRL-alone pass and every refusal from the record use accepted/, the record is never lowered, and no capture is verified from accepted/ while a record exists. The listed tests and the Task 1 and 2 mutants pass and are killed.
- T-03-321 (a capture racing the prune): mitigated by Read's one recapture; TestReadRecapture.
- T-03-SC: no module added. capslock-check: keyroster-signer 92 pairs, keyroster-agent 37, keyroster-agent-fetch 23, each equal to the baseline: no new pair.

## Threat Flags

None: the record is a new root-owned file in the state directory, as the plan's threat model describes, and the heartbeat field is the one the plan adds.

## Known Stubs

None.

## TDD Gate Compliance

- Every behaviour change had its test RED first, on the code before the change (above): Task 1 on symbol-only stubs, Tasks 2-4 on the previous task's head (Task 3 and Task 4 with the field or the seam added, without behaviour).
- The stubs were symbol-only, so the REDs fail on behaviour, not on the build.
- Each task's tests and implementation were committed together, one commit per task.

## Self-Check: PASSED

- FOUND: internal/agent/state/unapplied.go, internal/agent/apply/window_test.go, 03-08j-PLAN.md (byte-identical to the planned file), 03-08j-SUMMARY.md.
- FOUND (ancestors of HEAD): cbe5c4a, 9a8e7ed, 8153986, 18f6a39, 3b140be, 41b47fd.
