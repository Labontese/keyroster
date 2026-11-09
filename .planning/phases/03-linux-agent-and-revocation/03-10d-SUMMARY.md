---
phase: 03-linux-agent-and-revocation
plan: 10d
subsystem: agent, krl, signer, audit, cli, docs
tags: [rollback, kept-state, recovery, probe-certificates, agent-04]
status: complete
requires: [03-10c]
provides: [rollback-keeping, keeping-recover, recovery-revokes-probe-certificates]
requirements-completed: [AGENT-04]
commits: 10
plan_head_before: e22cc064638bfae97c08f3bd7e347ffdc02b363b
plan_head_after: 80df5e134b1c2d042edc19f4063229836c1de965
actuals:
  tokens: 96230  # chars/4 over git diff e22cc06..80df5e1 (the plan's own reconcile and addendum commits included; this SUMMARY's last revision not included)
  tasks: 3
  commits: 10  # git rev-list --count e22cc06..80df5e1; the SUMMARY commit ddfe75c (docs(03-10d): complete rollback-and-recovery plan) and this count's correction follow plan_head_after
---

# Phase 3 Plan 10d: No rollback re-grants a landed removal; recovery revokes every lost probe certificate Summary

Every rollback of an in-flight apply, the start-up recovery and the fallback and KRL-alone renders now end in the kept content: last-good, current and the base intersected, with the newest KRL (RollbackKeeping). Only the operator's `--recover-to-last-good` keeps the plain target. A signer recovery revokes every lost probe certificate, both polarities, recognised by its key ID, and the signer and `audit verify` refuse a recovery that keeps one.

Owner answers: Q-S Q-R Q-D D-R1 P4
AGENT-04: complete

## Bases

The test-time base is measured on unchanged origin/main e22cc06 in a detached worktree outside the repository, with no other heavy job, through scripts/linux.sh (go1.27.3 linux/amd64 in WSL), with the one command of 'Budget and verify'; each time is that package's `ok` line.

Base attempt 1 (started at 1794176190, not used): apply 498.715 s, krl 7.234 s, signer 418.078 s, audit 87.593 s, agentcmd 1.872 s ok; cmd/keyroster FAILED at 230.563 s on the known flake `TestRevokeHost/success_line_says_agent_keeps_state` (revoke_test.go:1290: a random SHA-256 in the output contained `403`, as 'Budget and verify' names). Because cmd's reading came from a FAIL line, not an `ok` line, the whole command was run again.

test-time base: apply=488.967 krl=7.347 signer=395.214 audit=87.541 cmd=269.858 agentcmd=1.811 at=1794176707

Base attempt 2 (the line above; `at` is its start, epoch seconds): every package `ok`, exit 0, ended at 1794177191.

## Task 1

### Step 0: reconcile

- Branch `p03/10d-no-regrant-recovery` from origin/main e22cc06 (03-10c merged, PR #92).
- The reconciled plan was copied over the tracked 03-10d-PLAN.md, checked LF and byte-identical to the checked plan with `cmp` (also the staged blob), and committed alone as 32e1fd1 `docs(03-10d): reconcile the plan with 03-10c`.
- `git diff --stat e22cc06 origin/main -- internal/agent/apply internal/agent/state internal/krl internal/signer internal/audit cmd/keyroster/recover.go docs/runbooks/signer-install.md` is empty: no file moved since e22cc06, so every path:line of the plan stands.
- Preconditions checked on origin/main: `checkProbeAccountFull` and `settleFailedAddition` present, `RollbackKeeping` absent, `ErrLostProbeKept` absent, both todos in pending.

The Reconcile table of the plan, as Step 0 found it on the branch base e22cc06. No cited file moved since e22cc06, so every premise stands as the plan cites it.

| # | Premise | At e22cc06 (Step 0) | Covered by |
|---|---|---|---|
| 1 | Every rollback in forward ends at last-good | as cited: the forward sites apply.go:1073 to :1140, settle's fallbacks probegate.go:952 to :992, `recover` at :1778, `recoverToLastGood` at :1948 | Task 1 (`rollbackAs`, D8, D9, D10); only `recoverToLastGood` passes the plain flag |
| 2 | A kept rollback state is stable | as cited: Apply's start recovers a current that is neither last-good nor `atRollbackTarget` (apply.go:491, :706-720) | Task 1: atRollbackTarget by classified content; drift.go comment |
| 3 | The equal-content commit is safe | as cited: no listener test on the equal-content commit (apply.go:1004-1026) | Task 1: the listener test when current is not last-good and `!dropInRepaired` |
| 4 | A recovery can tell a lost negative probe certificate | as cited: no polarity in the bytes or key ID | Task 2: Q-R option 1, every lost probe certificate revoked |
| 5 | The test the todo names flips | as cited: `TestCheckCarriedLost` a bare table at krl_test.go:1282 | Task 2: krl_test.go's table made `t.Run` subtests |
| 6 | The audit refusal table | as cited: verify_test.go, signer/recovery_test.go:573, signer-install.md:1137-1141 | Task 2: the new refusal beside them |
| 7 | `pop_hosts_off_fails` passes through trust's rule | as cited (confirmed by a throwaway test, see Task 2 Step 1) | Task 2: the fixture starts from a policy that never set pop.hosts |

### Step 1: the rollback sites

K is the kept content, last-good ∩ current ∩ the bounds with the newest KRL (RollbackKeeping); the base B is the generation current named at the top of forward's last loop pass.

| Site | Current at that point | Base / bounds | Kept content | Marker left | Behaviour |
|---|---|---|---|---|---|
| apply.go:1073 readCurrent error | unreadable (the rollback reads it again) | B of the previous pass, or none | last-good ∩ current ∩ B | forward's, if a pass swapped | keep; structural only |
| :1081 gateSuperseded error | the previous pass's intermediate or its from | B = that generation | B ∩ last-good | forward's | keep (reuse current) |
| :1120 Transition error | from or M (narrowing landed) | B = from | M's content | forward's | keep (reuse M, no swap) |
| :1128 writeDropIn error | T | B | M's content | forward's | keep (reuse preN = M) |
| :1132 activation error | T | B | M's content | forward's | keep (reuse M), drop-in restored |
| :1140 listener test | T | B | M's content (a pure addition: B) | forward's | keep; back to base when nothing landed |
| :1159 / :1168 settle calls | T | B | Intermediate(B, T) settles | forward's | settle on B (D7) |
| probegate.go:952 last-good read | T | B | the keeping rollback | forward's | keep; structural only |
| :959 plain case (target only adds to B) | T | B | B ∩ last-good = B | forward's | keep (back to base) |
| :972 install / :976 validate | T | B | the keeping rollback | forward's | keep; :972 structural only, :976 behavioural |
| :983 held write | T | B | the keeping rollback | forward's | keep; structural only |
| :987 settle's Transition | T (marker {T, M} may be written) | B | the keeping rollback | settle's or forward's | keep |
| :992 settle's listener test | M | B | M ∩ last-good = M | settle's | keep (reuse current) |
| :995-997 setHostStatus, :1000-1002 commit | M | (no rollback) | — | settle's {T, M} | out: closed by the keeping recover (bounds T, M) |
| apply.go:1171 forward's commit | T | (no rollback) | — | forward's {from, T, M} | out: closed by the keeping recover (bounds from, T, M) |
| recover (:1778) | whatever a crash or failure left | every nonzero generation the marker names | last-good ∩ current ∩ marker generations | — | keep; unreadable bound fails closed (`pending_state_unknown`) |
| recoverToLastGood (:1948) | as the operator found it | — | RollbackTarget(X, last-good) | — | plain (Q1 = A, D6), the one plain path |
| the held round of D5 | M (Intermediate(cur, g), a subset of current) | B = current | M itself | forward's | keep (current's bytes); `gated` false, so rollback, not settle |

### RED (Task 1)

- RED 1 (compile): the new internal/agent/apply/rollbackkeep_test.go against origin/main's code: `go test -run '^$' ./internal/agent/apply/` failed with `[build failed]`, `rollbackkeep_test.go:95:10: undefined: RollbackKeeping` (and the same at the other call sites; `too many errors`).
- RED 2 (behaviour): with signature-only stubs (RollbackKeeping returning RollbackTarget(cur, lg), the keep flag and bounds plumbed through rollbackAs, backToLastGood and rollbackTarget but ignored), `go test -race -v -run '^(TestRollbackKeeping|TestRollbackSites|TestAtRollbackTarget)$'` ended FAIL with 98 `--- FAIL` lines (parents included) and 12 `--- PASS` lines. Passing already, as they must against the plain rollback: TestRollbackKeeping/pure_addition_over_last_good_base_is_last_good, host_fields_are_last_goods, no_bounds_is_last_good; TestAtRollbackTarget/a_wider_current_is_not_a_target, older_krl_is_not_a_target; TestRollbackSites/operator_recover_still_goes_to_last_good, second_round_does_not_commit_untested_current, and crash_recovery_keeps_removal's forward_1_marker, forward_2_swap, forward_16_save-state, forward_17_last-good and forward_18_clear-marker (no removal had landed, or the commit finishes). Every other new subtest failed, every_forward_call_keeps included.

### Implementation (Task 1, commit d8335e7)

- render.go: `RollbackKeeping(cur, lg, bounds)`; RollbackTarget byte-unchanged.
- apply.go: `rollback` is `rollbackAs(..., true)`; backToLastGood and rollbackTarget take `keep` and `bounds`; the keeping branch is `keepingTarget` (reuse by classified content in the order last-good, each bound, current, preN; else install and validate, an error returned with current left where it is); `recover` passes `true` with every nonzero generation its marker names as bounds and fails closed (`ErrPendingStateUnknown`, `Report.Stuck = pending_state_unknown`) when one does not read; only `recoverToLastGood` passes `false`; `e.base = from` at the top of every loop pass and `e.preN` beside the local preN; atRollbackTarget by `sameContent(c, RollbackKeeping(c, l, nil))`; the equal-content commit runs `e.selfTest` when `curLink.n != lg.n && !e.dropInRepaired`; `render(v, cur, curLink)` puts current's principals-class files into the fallback's last-good generation when current is the agent's and not last-good.
- probegate.go: settleFailedAddition settles on `Intermediate(base, target)`; its plain case is the keeping rollback back to the base.
- drift.go: Check's comment names the kept state (comment only).

### Existing tests whose expectation changed (all in files_modified)

| Test | Old | New |
|---|---|---|
| apply_test.go `selftest_failure_rolls_back` | principals `[role:old role:ops]`, forward and rollback waits `>= 2*150 s` | principals `[role:ops]`; one wait (forward's, `>= 150 s` and `< 300 s`): the keeping rollback reuses M with one narrowing swap |
| apply_test.go `crash_at_intermediate_back_through_transition`, renamed `crash_at_intermediate_keeps_it` | `atRollback(lg)` after a widening step of `>= 150 s` | `atKept(lg)`, current stays M, no wait |
| apply_test.go `crash_during_recovery_transition` | recovery crashed at its 4th point (its final swap) | recovery crashed at its 2nd point (its one swap, current still B); then `atKept(lg)` |
| apply_test.go `crash_during_rollback_transition` | crash at 8 (the rollback's second marker) | crash at 7 (the keeping rollback's one swap); `atKept(lg)` |
| apply_test.go `crash_anywhere_recovers` (`two_step`, `rollback`) | `atRollback(lastGood)` | `atKept(lastGood)`, which covers last-good, RollbackTarget's content and the kept content |
| apply_test.go `crash_after_final_swap_two_step_back`, renamed `crash_after_final_swap_back_to_kept_content` | `atRollback(lg)` after a two-step move with a full wait | `atKept(lg)`, principals `[role:ops]`, no wait |
| apply_test.go `crash_between_final_marker_and_swap` | `atRollback(lg)` | `atKept(lg)` |
| apply_test.go `crash_in_rollback_intermediate_waits_then_last_good`, renamed `crash_in_rollback_swap_keeps_removal` | crash at 8 in the rollback's intermediate, then a full wait to last-good | crash at 7 (the keeping rollback has no intermediate), `atKept(lg)`, no widening wait |
| probegate_test.go `settle_listener_failure_falls_back_to_plain_rollback`, renamed `settle_listener_failure_keeps_removal` | principals `[role:a role:b]` (re-granted) | `[role:b]` |
| probegate_test.go `superseded_mixed_failure_keeps_removal` (not predicted by the plan) | settle on M and commit: last-good = current, accepted/ directory 3 | the second pass's target only adds to its base (the first pass's intermediate), so the keeping rollback goes back to that base: last-good unchanged, accepted/ directory 1, KRL 70 in force |
| probegate_test.go `superseded_readd_failure_keeps_last_good_lines`, renamed `superseded_readd_failure_keeps_landed_removal` (not predicted by the plan) | `full_readd`, `partial_readd`, `readd_only_removes_from_last_good`: principals `[role:a role:b]` (role:a, removed by the first pass's narrowing, granted again), committed or rolled back to last-good | principals `[role:b]`, current is the base (not last-good), accepted/ directory 1, no held record after the run |

The two probegate_test.go rows the plan did not predict are the Base refinement (D7) at work: the second pass's base is the first pass's narrowing intermediate.

### Sequences derived from the code, as the run showed them

- Held round (D5), `held_round_failure_keeps_removal` (probes on, drop-in removed, last-good {role:a, role:x}, candidate {role:x, role:b}): as the plan states. Round 1 held `sshd_override`, landed M {role:x}, wrote the drop-in, the stalled listener test rolled back with no swap (current M), restoreDropIn removed the drop-in, the held record stayed. Round 2 (stall off, clock +1 min) held `sshd_override` again, repaired the drop-in and committed M as last-good, `Recovered` false. Round 3 landed role:b. `held_round_runs_one_listener_test/probes_on`: round 2 made exactly the connections of one listener test (the reference is a pure narrowing with probes off).
- Double failure (`double_failure_next_start_keeps_removal`, probes off and on): `transition` (the rollback's own swap failed once after the stalled listener test), `restore_dropin` (forward's activation failed at `reload`; sshd -t failed in restoreDropIn after the rollback's swap) and `clear_marker` (the rollback's first clear-marker failed) each occurred as stated: the joined error, role:a absent, a marker pending; the next start's keeping recover (`Recovered` true) kept role:a absent at every fault point and after, sent no probe and left last-good unchanged; a further apply landed role:b.
- `crash_at_settle_swap_on_kept_base_keeps_readd_out`: a crash at the first `swap` after the probe failure left settle's marker and current at T; the keeping recover ended at {role:e}, as stated.
- `settle_validate_error` and `settle_validate_timeout`: with preN's directory removed during the refused probe, settle took its install-and-validate branch, the first validate failed (CA line refused, or the blocked ssh-keygen with `context.DeadlineExceeded`), and the keeping rollback installed the kept content as a new generation (asserted in `settle_validate_error`: current is neither M, T nor last-good), as stated.
- `crash_recovery_keeps_removal`: forward's points of a mixed change are 1 marker, 2 swap, 3 marker, 4 swap, 5 self-test, 6 to 14 the `accepted:` files, 15 marker (commit), 16 save-state, 17 last-good, 18 clear-marker; the keeping rollback's after a failed listener test are 6 marker, 7 swap, 8 clear-marker (one collapsed narrowing swap to M). The assertions by range of n hold as the plan states them.

## Owner questions (both answered during Task 1)

1. **hostcert_test.go had to change and was not in files_modified.** `TestHostCertStep/no_install_while_recover_due_sshd_t_fails` (hostcert_test.go:1441) failed after d8335e7: its fixture pointed current back at an older generation inside last-good with the same KRL, which the content-based start check of sec-5 accepts as a kept state, so HostCerts went on and wrote. Confirmed by putting atRollbackTarget back to a byte comparison (the subtest passed; restored with `git checkout --`, tree clean). Answer (orchestrator, execution addendum of the plan): rebuild the fixture so the older current holds a principal last-good lacks; hostcert_test.go is added to files_modified and Task 1's `<files>`. Done in a37a72c: the newer last-good holds `role:new` instead of `role:ops`; the subtest passes.
2. **The KRL-alone pass re-granted a kept removal.** Read from the code at d8335e7: after a content refusal forward takes the capture once more as KRL-alone against accepted/, which a keeping rollback leaves at last-good's directory, so the render widened current back to the removed line. Answer: designed in under Q-D as D10 (the plan's addendum): the KRL-alone render takes every file but the KRL from the generation current names when current is the agent's and is not last-good. Done in a37a72c (`krlOnly`, applied in `candidate` when `v.Refused` is set, which marks a KRL-alone Verified). The pre-merge review showed that this test on link names switches itself off after its own commit, and that pollSpool's use of it dropped a pending addition. D10 is restated in the plan, and the fix is recorded in 'Pre-merge review fix round 1'.

### D10 and the hostcert fixture (commit a37a72c)

- RED: `TestRollbackSites/krl_alone_after_kept_rollback_keeps_removal` (a kept rollback, then a capture with KRL 93 and a directory whose render is refused as `generation_too_large`) failed on both lanes before the code: `rollbackkeep_test.go:1220: principals [role:a role:x], want [role:x]` (probes_off and probes_on).
- GREEN: after `krlOnly`, both lanes pass: current holds role:x only and KRL 93, role:a is in force at no fault point, and last-good is never widened to role:a.

## UNVERIFIED (Task 1, as recorded during the task; the full list is 'UNVERIFIED' below)

- The failure of the keeping rollback's own install of the kept content (Q-D's 'cannot be installed' case) is not injected; its success is exercised by `settle_validate_error`.
- settle's `m == target` case (probegate.go, the `case m == target:` branch) is not reached in the harness.
- The sites with no one-shot injector (apply.go:1073 readCurrent, probegate.go:952 the last-good read, :972 install, :983 the held write) are covered structurally only (`every_forward_call_keeps`).
- A kept state can hold an empty `user_ca_keys` when the base, last-good and current hold disjoint CA lists (plan check sec-8; fail-safe direction, no code).
- 03-12 and 03-14 read current, which may now differ from last-good at rest (hand-over todo in Task 3).

## Deviations (Task 1)

- hostcert_test.go was changed (the recovery-due fixture), as the plan's execution addendum adds it to files_modified (owner question 1).
- D10 is applied wherever the render's Verified has `Refused` set, which marks a KRL-alone Verified (state/verify.go): forward's krlAlone pass, pollSpool's, and also a capture whose bundle or directory step the verifier refused (D-R2), whose contract is likewise that only the KRL moves on. As first built (a37a72c), pollSpool's pass took the intermediate's files during a widening wait, which dropped the pending target's additions. That was wrong, and the pre-merge review found it. Since fix round 1, forward's pass is bounded by the generation current names and pollSpool's by the pending target.
- Mutants 5 and 26 were re-run with corrected specs (see Mutants); the first runs are recorded there, not counted.

- `kept_state_start_failure_keeps_removal` uses a validate refusal of the KRL query (`queryCode`, with a new KRL published so validate queries it), which forward returns before its first swap (apply.go:1038-1040). The plan's example, the oversize candidate of rechain_test.go:288, is a Render refusal (`ErrGenerationTooLarge`, render.go:182): candidate refuses it and forward takes the KRL-alone pass instead of returning, so it does not reach :1038.
- `gate_superseded_error`: the next round is held for the account's reason (`shell_not_nologin`, the superseding passwd that makes the gate hold), not `failure_backoff` as the plan's grouped assertion for the settle and gate sites says; it lands role:b once the input changes (the passwd fixed). Reported, not adjusted.
- `settle_validate_timeout` runs Apply with a 20 s context: the harness's Apply has no deadline of its own, so "until the context ends" needs one; the blocked ssh-keygen returns `context.DeadlineExceeded` and the keeping rollback still completes (its steps do not depend on the expired context in the harness).

### Gates (Task 1, local, at a37a72c, T1)

- Gate 1: `go build ./... && go vet ./... && go vet -tags keyroster_e2e ./internal/agent/... ./cmd/keyroster-agent/` ok; the test part of gate 1 passed at d8335e7 (below) and the new D10 subtest passes at a37a72c; gate 2's run below covers the whole package at a37a72c.
- Gate 2: `go test -race -count=1 -timeout 15m ./internal/agent/... ./cmd/keyroster-agent/` ok (internal/agent/apply 403.355 s under the parallel load of the other packages; not a delta reading); the swap.go, selftest.go and interleave_test.go diff against origin/main is empty.
- Gate 3: `bash scripts/capslock-check.sh` ok (23 pairs, baseline 23); test/capslock, internal/wire, internal/tlog, internal/cert, internal/certprofile and internal/server unchanged; the todo is in completed/ with `## Resolution`; one `func RollbackKeeping(`.
- Lints: golangci-lint for linux, windows and darwin on `./...`: 0 issues each; `gofmt -l .` empty.

### Gates run earlier (Task 1, local, at d8335e7)

- Gate 1's test part: `go test -race -count=1 -timeout 15m -v -run "^(TestRollbackKeeping|TestRollbackSites|TestAtRollbackTarget|TestProbeGate)$" ./internal/agent/apply/` ok (31.094 s); gate 1's PASS loop over that log printed no missing PASS line and no FAIL, panic or DATA RACE. `go build ./...` and `go vet ./internal/agent/apply/` ok; `gofmt -l internal cmd` empty; golangci-lint (linux) on ./internal/agent/apply/ 0 issues. The full gate 1 command (with `go vet ./...` and the tagged vet) has not been run as one command yet.
- Gate 2: `go test -race -count=1 -timeout 15m ./internal/agent/... ./cmd/keyroster-agent/` FAILED, only on `TestHostCertStep/no_install_while_recover_due_sshd_t_fails` (owner question 1); every other package ok (internal/agent/apply 438.895 s under the parallel load of the other packages, not a delta reading). `git diff --quiet origin/main -- internal/agent/apply/interleave_test.go internal/agent/apply/swap.go internal/agent/apply/selftest.go` ok.

### Mutants (Task 1)

Each mutant ran with the task's work committed, on its named subtest (`go test -count=1 -timeout 5m -v -run`), restored with `git checkout --` and checked with `git diff --quiet HEAD` per file and for the whole tree (`':!.planning/config.json'`). Two first specs were not valid runs and were re-run: mutant 5's first spec removed the bounds from the intersection only, so the lines were still drawn from the first bound and base_bounds_the_result did not fail (that partial mutant is killed by every_bound_applies, run separately); mutant 26's first spec did not compile (`declared and not used: baseGen`, `[build failed]`, not a kill). The lines below are the valid runs.

mutant killed: 1 RollbackKeeping returns the union instead of the intersection (TestRollbackKeeping/mixed_is_intersection)
mutant killed: 2 RollbackKeeping returns RollbackTarget always (TestRollbackKeeping/pure_narrowing_stays)
mutant killed: 3 RollbackKeeping drops the newest-KRL rule (TestRollbackKeeping/newest_krl_kept)
mutant killed: 4 RollbackKeeping's N always 0 (TestRollbackKeeping/pure_addition_over_last_good_base_is_last_good)
mutant killed: 5 RollbackKeeping ignores the bounds, in the intersection and the order (TestRollbackKeeping/base_bounds_the_result)
mutant killed: 6 forward's readCurrent rollback flipped to plain, apply.go:1073 (TestRollbackSites/every_forward_call_keeps)
mutant killed: 7 gateSuperseded's rollback flipped to plain, apply.go:1081 (TestRollbackSites/gate_superseded_error)
mutant killed: 8 the Transition-error rollback flipped to plain, apply.go:1120 (TestRollbackSites/transition_error/probes_off and /probes_on)
mutant killed: 9 the writeDropIn-error rollback flipped to plain, apply.go:1128 (TestRollbackSites/write_dropin_error/probes_off and /probes_on)
mutant killed: 10 the activation-error rollback flipped to plain, apply.go:1132 (TestRollbackSites/activate_dropin_error/probes_off and /probes_on)
mutant killed: 11 the listener-test rollback flipped to plain, apply.go:1140 (TestRollbackSites/self_test_failure/probes_off and /probes_on)
mutant killed: 12 settle's last-good-read rollback flipped to plain, probegate.go:952 (TestRollbackSites/every_forward_call_keeps)
mutant killed: 13 settle's plain case flipped to plain, probegate.go:959 (TestRollbackSites/kept_state_then_readd_and_add_fails_keeps_readd_out/settle_probe_failure_collapsed)
mutant killed: 14 settle's install rollback flipped to plain, probegate.go:972 (TestRollbackSites/every_forward_call_keeps)
mutant killed: 15 settle's validate rollback flipped to plain, probegate.go:976 (TestRollbackSites/settle_validate_error)
mutant killed: 16 settle's held-write rollback flipped to plain, probegate.go:983 (TestRollbackSites/every_forward_call_keeps)
mutant killed: 17 settle's Transition rollback flipped to plain, probegate.go:987 (TestRollbackSites/settle_swap_error)
mutant killed: 18 settle's listener-test rollback flipped to plain, probegate.go:992 (TestProbeGate/settle_listener_failure_keeps_removal)
mutant killed: 19 recover flipped to the plain variant (TestRollbackSites/crash_recovery_keeps_removal, first at forward_3_marker)
mutant killed: 20 recoverToLastGood flipped to the keeping variant (TestRollbackSites/operator_recover_still_goes_to_last_good)
mutant killed: 21 atRollbackTarget compares by bytes (TestAtRollbackTarget/content_equal_but_bytes_differ_counts)
mutant killed: 22 the equal-content commit without the listener test (TestRollbackSites/kept_state_commit_needs_listener_test)
mutant killed: 23 the guard runs even when repairDropIn's listener test ran (TestRollbackSites/held_round_runs_one_listener_test/probes_on)
mutant killed: 24 RenderFallback fed last-good's principals again (TestRollbackSites/keys_rotated_render_after_kept_rollback_keeps_removal/probes_off)
mutant killed: 25 the base recorded once before the loop instead of on every pass (TestRollbackSites/superseded_readd_fails_keeps_readd_out/settle_probe_failure)
mutant killed: 26 settleFailedAddition uses Intermediate(lgGen, target) (TestRollbackSites/kept_state_then_readd_and_add_fails_keeps_readd_out/settle_probe_failure)
mutant killed: 27 recover ignores the marker's To (TestRollbackSites/crash_at_settle_swap_on_kept_base_keeps_readd_out)
mutant killed: 28 recover falls back to last-good when a marker generation does not read (TestRollbackSites/unreadable_marker_generation_fails_closed)
mutant killed: 29 the keeping rollback's Transition error swallowed (TestRollbackSites/double_failure_next_start_keeps_removal/transition/probes_off and /probes_on)
mutant killed: 30 the KRL-alone pass renders accepted/'s principals again after a kept rollback (TestRollbackSites/krl_alone_after_kept_rollback_keeps_removal/probes_off)

No Task 1 mutant is equivalent: the four expected-equivalent flips (apply.go:1073, probegate.go:952, :972, :983) are killed by every_forward_call_keeps. The pairs that run on both lanes (8 to 11, 29) died on both.

T1: a37a72c

## Task 2

### Preconditions (read-only, at origin/main e22cc06)

`git merge-base --is-ancestor e22cc06 origin/main` 0; `git grep -q 'func CheckCarriedLost(' origin/main -- internal/krl/recovery.go` 0; `git grep -q 'ErrLostProbeKept' origin/main -- internal/krl` 1; the pending todo exists on origin/main. Every hit of `recovery_user_certificate_kept` outside .planning (krl, signer, audit, their tests, the runbook) is in files_modified.

### pop_hosts_off_fails (Step 1)

Before the change the subtest's failure text came from the trust successor rule, not from audit's host-issue rule: `audit: entry 2: bundle_install is not a valid successor of trust bundle v1: trust: pop_hosts_removed: a successor policy may not turn pop.hosts off once a policy set it (policy v1 sets it; v2 clears it)` (shown by a throwaway test, removed before any commit). The fixture now starts from `newProbeFixtureNoPoP` (a genesis policy that never set pop.hosts), and the subtest wants audit's own text `does not set pop.hosts, so no host certificate could be issued`. It passes; a test-only change, no RED expected.

### RED (Task 2)

All tests written before any code (`go test -race -count=1 -timeout 15m -v -run "^(TestIsProbeKeyID|TestCheckCarriedLost|TestRecoverRevocations|TestRevokeRecover|TestVerifyRecovery|TestVerifyHostIssue)$"` over krl, signer, audit and cmd/keyroster):
- internal/krl `[build failed]`: `krl_test.go:1311:74: undefined: ErrLostProbeKept`, `krl_test.go:1318:76: too many arguments in call to CheckCarriedLost (have (uint64, uint64, bool, bool, bool) want (uint64, uint64, bool, bool))`, `krl_test.go:1347:14: undefined: IsProbeKeyID`.
- signer: `--- FAIL: TestRecoverRevocations/lost_probe_certificate_kept_is_refused`: `RecoverRevocations = &{... Revoked:0 Kept:1}, <nil>; want the refusal recovery_probe_certificate_kept`.
- audit: `--- FAIL: TestVerifyRecovery/recovery_probe_certificate_kept`: `Verify = <nil>, want a refusal containing "(recovery_probe_certificate_kept)"`.
- cmd/keyroster: `--- FAIL` for `lost_negative_probe_revoked_without_flag` (carried true, revoke false), `lost_positive_probe_revoked_too` (the positive kept), `output_says_probe_certificate_revoked` (no `revoke` line and no summary line for the probes) and `revoke_lost_flag_accepts_a_probe_serial` (with the flag the named probe was revoked, without it kept, so the maps differed).
- Passing already, as they must against the old rule: `lost_probe_certificate_revoked_is_listed`, `lost_machine_certificate_still_keepable`, `recovery_probe_certificate_revoked_verifies`, `recovery_machine_certificate_kept_verifies`, `kept_machine_certificate_unchanged`, and `pop_hosts_off_fails`.

Two faults in my own new signer subtest showed after the code, and were fixed in the test, not the code: the refusal's `Error()` carries only the code (`refused: recovery_probe_certificate_kept`), so the message check now reads the wrapped cause (`errors.Unwrap`); and the second request of that subtest listed its certificates out of serial order (`wire: malformed message: the certificates must be sorted by serial with no serial twice`), so they are now in serial order.

### Implementation (Task 2, commits ccac467 and 7427197)

- internal/krl/recovery.go: `IsProbeKeyID(kid cert.KeyID) bool` (`kid.V3 && kid.CA == "machine" && strings.HasPrefix(kid.Subject, "probe.")`); `ErrLostProbeKept`; `CheckCarriedLost(validBefore, createdAt, user, probe, revoke)`, order revoke, expiry, user, probe; the doc comments of the rule, the errors and RecoveryCarrySkew updated.
- internal/signer/recovery.go: `recoveryCert.probe` set from `krl.IsProbeKeyID(kid)`; ErrLostProbeKept refused as `recovery_probe_certificate_kept` ("a recovery revokes every lost probe certificate, positive or negative, since its polarity is not in its bytes"); the refusal list of RecoverRevocations' doc names it.
- internal/audit/recovery.go: passes `krl.IsProbeKeyID(kid)`; the error ends `(recovery_probe_certificate_kept)`.
- cmd/keyroster/recover.go: `revoke := user || probe || named[c.Serial]`; the summary prints `lost probe certificates revoked: <n> (a recovery revokes every lost probe certificate, positive or negative)` after the per-certificate lines when n > 0 (the per-certificate line is unchanged, `... (live): revoke`).
- Fixtures: signer `makeProbeCert` and `signTestCert` (makeCert now signs through it); audit `lostProbeCert`, `lostMachineCert`, `lostMachineCertWith`; the CLI `newProbeRecoverScenario` (a pop.hosts policy, a directory_install leaf with host web1, `logBuilder.probe` porting audit's addProbe so audit.Verify accepts the probe_issue leaves, a negative's serial added to the next publish), `installDirectory`, `newRecoverSigner`.
- docs/runbooks/signer-install.md: the refusal list names `recovery_probe_certificate_kept`; one bullet under the summary lines says every lost probe certificate is revoked, both polarities, and that a host whose positive was revoked finds it in the KRL (`positive_in_krl`) and asks for a new pair, with additions on it waiting up to about two hours (P4).
- The todo moved with `git mv` to completed/ with `## Resolution` (7427197).

### Gates (Task 2, local)

- Gate 1 (at ccac467's tree): the plan's command passed: `GATE1_PASS`, every named PASS line present, no FAIL, panic or DATA RACE. Package times (not delta readings): krl 1.040 s, signer 96.794 s, audit 1.633 s, cmd/keyroster 4.051 s.
- Gate 2 (at 7427197): `go test -race -count=1 -timeout 15m ./internal/krl/ ./internal/signer/ ./internal/audit/ ./internal/tlog/ ./internal/wire/ ./cmd/keyroster/` ok (krl 6.891 s, signer 356.071 s, audit 85.624 s, tlog 3.648 s, wire 7.794 s, cmd/keyroster 212.875 s; another package set than the delta command, so not delta readings); the frozen diff empty; `scripts/capslock-check.sh` ok (signer 92 pairs, agent 37, agent-fetch 23, each equal to its baseline); the todo checks ok.
- Gate 3: golangci-lint for linux, windows and darwin on `./...` 0 issues each and `gofmt -l internal cmd` empty (on the tree committed as ccac467); the runbook names the refusal.
- Acceptance: `git diff --name-only origin/main -- internal/wire internal/tlog internal/cert internal/certprofile docs/format-registry.md` prints nothing.

### Mutants (Task 2)

Each mutant ran with the task's work committed (7427197) through run_mutants.py on its single named subtest (`go test -count=1 -timeout 5m -v -run`), restored with `git checkout --` and checked with `git diff --quiet HEAD` per file and for the whole tree (`':!.planning/config.json'`), clean before the first and after the last.

mutant killed: 31 IsProbeKeyID matches a non-machine CA (TestIsProbeKeyID/kr3_host_probe_subject)
mutant killed: 32 IsProbeKeyID matches any machine subject (TestIsProbeKeyID/kr3_machine_other_subject)
mutant killed: 33 CheckCarriedLost ignores probe (TestCheckCarriedLost/probe_kept_is_refused)
mutant killed: 34 the probe check placed before the expiry check (TestCheckCarriedLost/probe_expired_and_kept_is_expired_first)
mutant killed: 35 the signer passes probe=false (TestRecoverRevocations/lost_probe_certificate_kept_is_refused)
mutant killed: 36 audit passes probe=false (TestVerifyRecovery/recovery_probe_certificate_kept)
mutant killed: 37 the CLI decides revoke without probe (TestRevokeRecover/lost_negative_probe_revoked_without_flag)
mutant killed: 38 the CLI revokes only the first probe certificate it meets, a seen flag (TestRevokeRecover/lost_positive_probe_revoked_too)
mutant killed: 39 the CLI revokes every machine certificate (TestRevokeRecover/kept_machine_certificate_unchanged)
mutant killed: 40 the signer refuses every kept machine certificate (TestRecoverRevocations/lost_machine_certificate_still_keepable)

Total: 40 killed, 0 equivalent (floors 36 killed, 40 killed or equivalent).

T-03-389 is mitigated as the threat register states; its residual (the restore path is UNVERIFIED end to end, 03-10's R9) stands.

T2: 7427197

## UNVERIFIED (Task 2)

- That an old log holds no recovery which kept a lost probe certificate (such a log would now fail `audit verify`; 03-10 merged days before and no release has shipped).
- The restore path end to end (03-10's R9). The CLI test proves that `keyroster revoke recover` revokes lost probe certificates from an export audit.Verify accepts, and the signer test that the KRL then lists them; that the host's agent then asks for a new pair after a real restore, and the wait it causes, is not run (the `positive_in_krl` hold and the new-pair request are unit-tested in internal/agent/apply and internal/agent/probe only).
- A lost probe certificate the saved export cannot show (the export itself lost) is not recoverable by this rule; it expires with its lifetime.

## Deviations (Task 2)

- The CLI's per-certificate line for a probe certificate is unchanged (`... (live): revoke`); the reason is a separate summary line (`lost probe certificates revoked: <n> (...)`), so `summary_lists_kept_with_key`'s exact user line still holds.
- The runbook bullet does not say that removals and new KRLs still land while a host waits for a new pair: no test here shows that for the `positive_in_krl` route, so it is not claimed.

## Task 3

### Publish

- **The plan file** equals HEAD (verify 1) and the committed copy is byte-identical to the checked plan (`cmp`). It was not edited in Task 3.
- **80df5e1 `docs(03-10d): tick the plan and AGENT-04, and add the hand-over todos`** holds:
  - ROADMAP.md: the 03-10d row `- [ ]` to `- [x]`, and 26/33 to 27/33 on the Plans line and on the Progress row;
  - REQUIREMENTS.md: the AGENT-04 checkbox and its traceability row Pending to Complete (four changed lines);
  - STATE.md: the tracking update (completed_plans 62, the decision line, the session);
  - the two hand-over todos, created in the format of the others in pending/.

  `git diff -U0` was checked before the commit. The tracking update ran once, in that edit. The GSD state handlers were not run again, because gate 7 accepts only the one tick and the one Plans and Progress transition.
- **Capslock:** `scripts/capslock-check.sh` passed inside gate 2 (agent 37 pairs, agent-fetch 23, each equal to its baseline). `test/capslock` is unchanged.

### Gates (local, at 80df5e1, through scripts/linux.sh where they run Go)

- **Gate 1** (todos tracked in HEAD, tracking and phase files committed): exit 0.
- **Gate 2** (whole module): exit 0, from 1794182653 to 1794183405, pass or fail only. Every package `ok`, with no FAIL, panic or DATA RACE. The run covered:
  - `go test -race ./...`;
  - `go vet` default and with the tags keyroster_e2e, e2e, `e2e e2eprobe`, `e2e systemdsmoke` and e2edistro;
  - gofmt;
  - golangci-lint for linux, windows and darwin;
  - capslock, the dependency firewall, the test-only firewall (6 GOOS and tag combinations clean), and the pinned actions (51 `uses:` references pinned).
- **Gate 3** (test-time delta): exit 0. It ran alone after gate 2, from 1794183435 to 1794183913; the base was 6728 s old.
- **Gate 4** (the test-build tag in its six files): exit 0.
- **Gate 5** (files gate): exit 0.
- **Gate 6** (author, committer, signatures over origin/main..HEAD): exit 0.
- **Gate 7** (wave, dependency, later plans, ROADMAP and REQUIREMENTS lines): exit 0.

Test-time readings (the one command of 'Budget and verify'), base, reading and delta per package:

| Package | Base (s) | Reading (s) | Delta (s) | Stop |
|---|---|---|---|---|
| apply (internal/agent/apply) | 488.967 | 481.805 | -7.162 | +90 |
| krl | 7.347 | 6.931 | -0.416 | +90 |
| signer | 395.214 | 407.846 | +12.632 | +90 |
| audit | 87.541 | 87.303 | -0.238 | +90 |
| cmd (cmd/keyroster) | 269.858 | 254.028 | -15.830 | +90 |
| agentcmd (cmd/keyroster-agent) | 1.811 | 1.776 | -0.035 | +90 |

The plan expected apply to grow by 40 to 70 s; it read 7 s under the base. The reading includes Task 1's new tests and the base (origin/main) does not; the cause of the difference is not measured, and the reading is recorded as read. The whole-module run of gate 2 read apply at 585.887 s under the parallel load of every other package; that is not a delta reading.

### Gate controls

gate control: files gate exits 0 on the branch as committed
gate control: files gate exits 1 on a throwaway detached worktree with one commit adding an unlisted file (`unlisted-control.txt`, the only name X printed; the worktree was removed and its commit never pushed)
gate control: key parser reads all six keys (the sample base line `test-time base: apply=1.5 krl=2.5 signer=3.5 audit=4.5 cmd=5.5 agentcmd=6.5 at=1` through the same g() printed 1.5, 2.5, 3.5, 4.5, 5.5 and 6.5)
gate control: files gate exits 0 on a fixture that moves the two todos with git mv (a throwaway detached worktree at origin/main with this branch's plan file and one commit that moves both todos from pending/ to completed/ with `git mv`; the gate's `--no-renames` diff listed each as D and A, both in files_modified; removed, never pushed)

ROADMAP gate control (gate 7):
- **On origin/main** (a throwaway detached worktree at e22cc06): exit 1. The changed-line filter is empty (0 changed lines), so `test -n "$R"` fails.
- **On a commit that ticks 03-11** (a throwaway detached worktree at 80df5e1 with one commit, `- [ ] 03-11-PLAN.md` to `- [x]`): exit 1.

A stray tick no longer passes the gate (03-10c's gate passed one). Both worktrees were removed; neither commit was pushed.

### Push, the PR and CI

- **Branch:** pushed at 80df5e1 with `env -u GITHUB_TOKEN -u GH_TOKEN git push`.
- **PR:** PR #93 (https://github.com/Labontese/keyroster/pull/93), opened by keyroster-bot through scripts/gh-as-bot.sh with the plan's title. Auto-merge is not enabled.
- **The PR body** names:
  - the changes;
  - the owner decisions Q-S, Q-R, Q-D and D-R1 (and Q1 = A, Q2, the Base refinement);
  - the deviations;
  - the UNVERIFIED list;
  - the new fail-closed stop of `recover` (T-03-395: `stuck: pending_state_unknown`, reachable only when gen/ is damaged, the way out `--recover-to-last-good`) as an extension of Q-D.
- **Gates on the PR:**
  - Gate 9 (scrub, the PR body included): exit 0.
  - Gate 11 (auto-merge off): exit 0.
- **Gate 10** (`pr checks --required --watch`, then the 03-10b e2e gate in `pr` mode with B as a prefix assignment): exit 0, e2e run 42540126467, headSha 80df5e1 (checked by the gate against HEAD).
  - Every PROBE_PASS test passed in both probe lanes.
  - Neither main lane ran a probe test.
- **Checks at 80df5e1:** 29 of 29 succeeded. That includes the seven `e2e-distro` jobs, both `e2e-probe` lanes and `systemd-sandbox`. The `pull_request` runs:

| Run ID | Workflow | Result |
|---|---|---|
| 42540126464 | CI | success |
| 42540126467 | E2E | success |
| 42540126461 | E2E distro | success |
| 42540126471 | Systemd | success |
| 42540126460 | E2E TPM | success |
| 42540126462 | E2E PKCS#11 | success |
| 42540126459 | CodeQL | success |
| 42540126455 | PIV | success |
| 42540126466 | PR title | success |
| 42540126470 | Workflow lint | success |

The e2e lanes of the PR run (`go test` elapsed of ./test/e2e, as the gate reads it), against 03-10c's last head:

| Lane | 03-10c (s) | This PR (s) | Delta (s) | Cap (s) |
|---|---|---|---|---|
| e2e (9.5p1) | 751.584 | 758.538 | +6.954 | 900 |
| e2e (10.5p1) | 773.107 | 777.304 | +4.197 | 900 |
| e2e-probe (9.5p1) | 279.601 | 285.583 | +5.982 | 420 |
| e2e-probe (10.5p1) | 286.412 | 271.747 | -14.665 | 420 |

Other CI timings:
- **systemd-sandbox:** `--- PASS: TestAgentSystemdSmoke (499.99s)` (03-10c's last head: 511.30 s).
- **e2e-distro job durations:**

| Job | Duration |
|---|---|
| almalinux:9 | 6m36s |
| alpine | 5m45s |
| archlinux | 6m27s |
| debian:12 | 4m9s |
| debian:13 | 6m22s |
| ubuntu:24.04 | 4m11s |
| ubuntu:26.04 | 6m25s |

  03-10c's last head ran from 3m58s to 6m33s.

The required checks and gates 1 and 5 to 11 on the head that carries this SUMMARY are reported with the hand-off, not here: a SUMMARY cannot record the checks of its own commit.

### The pre-merge review

The orchestrator runs it on the green PR: a full security review against T-03-374, T-03-388 and T-03-389, with the rollback rule, its two guards and the recovery rule flagged. It also checks the diff for real host names, private addresses and private terms. This executor did not run it. Fix round 1 is recorded under 'Pre-merge review fix round 1'.

### Pre-merge review fix round 1

The orchestrator's review of head 30dfcf8 confirmed two findings (R1 and R2) and one documentation finding (R4). Two more were refuted:
- the structural test does not police direct Transition calls; that is test hardening only;
- old dev logs that kept a lost probe certificate; this is already UNVERIFIED, under Q-R.

Fixing R1 then turned up one more issue, and the R3 check one owner question (Q3); both are below.

The plan was amended first. D10 and T-03-392 are restated, and a 'Pre-merge review addendum' is added. The amended plan was committed on its own three times:
- c0dc912, the first amendment;
- 772df77, when the held-record row was added;
- 388b525, when owner decision Q3 was added.

Each copy was checked byte-identical with `cmp`. The plan's `<automated>` lines are unchanged against 30dfcf8.

**R1 (high): D10 switched itself off.**
- krlOnly decided that a kept state existed from `curLink.n != lg.n`.
- The D10 pass's own commit made the kept generation last-good, while accepted/ still held last-good's old directory.
- So the next KRL-alone pass rendered that directory again. role:a was granted again and committed as last-good, with probes off and on. The probe gate tests enforcement, not authorization, so it passed.

Fix (039a319):
- Every KRL-alone pass is bounded by its reference generation. Every file except the KRL is `RollbackKeeping(ref, render, nil)`'s: the render's CA and principal lines that the reference also holds. Only the KRL comes from the render.
- In forward, the reference is the generation current names, when it is the agent's.
- The test on link names is gone.
- A render that the reference covers keeps its own bytes. `TestRollbackSites/krl_alone_bound_equal_render_keeps_bytes` checks this:
  - with equal content, the result is sameBytes with the render;
  - a wider render keeps only the reference's CA and principal lines, with the render's KRL;
  - a nil reference changes nothing.

**R2 (medium): pollSpool dropped a pending addition.** This was a regression against e22cc06.
- During a widening wait, current is the intermediate M. pollSpool's KRL-alone pass took M's files, so the superseding generation was M plus the newer KRL.
- accepted/ then recorded directory 2 while role:b was not in force, and every later apply was a no-op.

Fix (039a319): pollSpool passes the pending target as the reference, explicitly (`candidate(v, cur, curLink, target)`). The superseding generation is again the pending target's render with the newer KRL.

The same test logic passes at e22cc06, probes off and on. It ran as a throwaway copy with keepHost inlined, because keepHost does not exist at e22cc06. The result in both lanes:
- role:b and role:x are in force, with KRL 93;
- last-good equals current;
- accepted/ holds directory 2 and the KRL in force.

The superseding generation's files were hashed in both trees:
- `user_ca_keys` and the probes_off `revoked.krl` hash the same.
- The principals bodies are equal except for the per-run directory sha256 in the render header. Both trees give the render header, a directory version 2 line, then `role:b` and `role:x`.

The committed test also asserts that deploy's file starts with the render header, not the intersection's header.

**R1's fix cleared a held addition's record.** The fixer found this; the orchestrator accepted the fix and the addendum row.

With probes on, the bounded KRL-alone pass left the held addition out. It then committed as an ordinary candidate and cleared the held record.

Scenario: gateHost {role:a, role:b}; D2 {role:a, role:c} is held `cert_missing`; then an oversize D3 with KRL 93, applied twice. Measured with a throwaway test:

| Tree | Run 1 error | Held record | Principals | Run 2 |
|---|---|---|---|---|
| e22cc06 | generation_too_large, probe_held: cert_missing | cert_missing | [role:a], KRL 93 | held again |
| 30dfcf8 | generation_too_large, probe_held: cert_missing | cert_missing | [role:a], KRL 93 | held again |
| 039a319 | generation_too_large only | cleared | [role:a], KRL 93 | no-op, no hold |

RED at 772df77 (the R1-fixed code, with the new subtest added):
- `--- FAIL: TestRollbackSites/bounded_krl_alone_keeps_held_record/probes_on`, with `want held cert_missing: err generation_too_large: , detail ""`;
- `--- FAIL: TestProbeGate/krl_alone_pass_is_classified`, an existing subtest, which fails the same way.

The fixer had not run that existing subtest before committing 039a319, so 039a319 alone fails it; 9aa10f6 makes it pass again.

Fix (9aa10f6): a KRL-alone pass whose bound dropped a line of its render is not a full candidate. When it meets a readable held record with probes on, the hold stands, as it does for a substituted target:
- the record is rewritten with the pass's versions;
- the run reports `probe_held`;
- no commit of the pass clears the record;
- the equal-bytes branch clears the record only when nothing is held.

The error, the record and the detail again match e22cc06 and 30dfcf8. One difference remains: run 2 now reports `NoOp` true, where e22cc06 reports `NoOp` false (it does not write either).

The comment of `krl_alone_pass_is_classified` now says that the bound keeps the held addition out and the hold stands.

**R4 (docs).** T-03-392 is restated in the plan, and this SUMMARY repeated none of its old claims. The D10 text is corrected in 'Owner questions' item 2 and in 'Deviations (Task 1)'.

**RED before the fix**, at 30dfcf8 (WSL, `go test -count=1 -v`):
- `--- FAIL: TestRollbackSites/krl_alone_twice_after_kept_rollback_keeps_removal/probes_off` and `/probes_on`:
  - `rollbackkeep_test.go:1258: round 2: role:a re-granted: principals [role:a role:x]`;
  - role:a was in force from `self-test` to `clear-marker`, and in last-good at `clear-marker`.
- `--- FAIL: TestRollbackSites/refused_capture_during_wait_lands_addition/probes_off` and `/probes_on`: `rollbackkeep_test.go:1302: principals [role:x], want [role:b role:x]`.
- `krl_alone_after_kept_rollback_keeps_removal` still passed, because it covers one pass only.

**GREEN:**
- At 039a319, all of TestRollbackSites passes: the two new subtests on both lanes, and `krl_alone_bound_equal_render_keeps_bytes`.
- At 9aa10f6:
  - `go test -count=1 -v ./internal/agent/apply/` ok (384.620 s);
  - `go test -race -count=1 -timeout 15m -v ./internal/agent/apply/` ok (452.992 s), with no DATA RACE;
  - `bounded_krl_alone_keeps_held_record/probes_on` and `krl_alone_pass_is_classified` pass.

**Mutants.** They ran with run_mutants.py at 9aa10f6, each on its named subtest. Each was restored with `git checkout --` and checked with `git diff --quiet HEAD`, per file and for the whole tree; the tree was clean afterwards.
- The numbers are the plan addendum's, not Task 2's 31 to 33 above.
- Mutant 30 is redefined on the new text: the bound's call is removed. It ran again.
- The lines are not prefixed `mutant killed:`, so the Task 1 and Task 2 counts stay as recorded.

fix-round mutant killed: 30 (redefined) the KRL-alone bound removed (TestRollbackSites/krl_alone_after_kept_rollback_keeps_removal/probes_off and /probes_on)
fix-round mutant killed: 31 the early return on current equal to last-good restored (TestRollbackSites/krl_alone_twice_after_kept_rollback_keeps_removal/probes_off and /probes_on)
fix-round mutant killed: 32 pollSpool's reference set back to current (TestRollbackSites/refused_capture_during_wait_lands_addition/probes_off and /probes_on)
fix-round mutant killed: 33 the held-record guard removed (TestRollbackSites/bounded_krl_alone_keeps_held_record/probes_on)
fix-round mutant killed: 34 the record write after the keeping rollback removed (TestRollbackSites/withdrawn_directory_after_kept_rollback_keeps_removal/krl_only/probes_off, /krl_only/probes_on, /bundle_only/probes_off and /bundle_only/probes_on)

All five were run again at a44c318, the final code, and each died on the same lines.

**R3 checks** (throwaway tests in WSL copies, not committed).

(a) D9 during a widening wait: safe; D9 is unchanged. Scenario: {role:a, role:x}, then D2 {role:x, role:b}. During the wait, D3 {role:x, role:b} arrives with rotated host keys plus KRL 93, so the fallback renders.
- e22cc06: principals [role:a role:x]. Last-good's principals bring role:a back, the removal the intermediate had landed. Status host_keys_rotated, accepted/ at directory 3.
- The fixed head: [role:x], from current M, with the same status and KRL.
- The fallback is never wider than the reference, and it does not drop an authorized addition the way R2 did. role:b is absent at e22cc06 too, because D3's refused host entry decides, not D2.
- Once K is last-good, D9's guard returns early with last-good = K, so the fallback takes K's principals (read from the code, not run).

(b) Other renders of accepted/'s stored directory. Each case starts from a kept state with D2 withdrawn from the spool and D1 still offered. This was reported as an owner question; it is fixed under owner decision Q3, below.
- A KRL-only capture (KRL 93) re-granted role:a. It rendered accepted/'s D1 with `Refused` nil, so the D10 bound never applied, and role:a was committed as last-good. Probes off and on; the probe gate passed. The code is the same at 30dfcf8.
- A bundle-only capture (a successor bundle) re-granted role:a the same way.
- An unchanged capture was a no-op and kept [role:x].
- A withheld directory (D-R2) gives a Refused Verified, which the bound now covers.

**Owner decision Q3 (record the directory), a44c318.** A keeping rollback that leaves current without a line last-good holds records e.tv, the verified state the failed apply was moving to, in the existing unapplied record (`recordKept`, through `recordUnapplied` and `Verified.Unapplied`). This is the same path a content refusal takes.
- `Verified.Unapplied` accepts the state as it is: the state is not refused, and its directory is ahead of accepted/. No format change, no wire change and no file outside files_modified.
- A rollback whose error is an injected crash writes nothing more. The first version wrote the record there too, and `TestApply/crash_during_rollback_transition` and `crash_anywhere_recovers/rollback` failed, because the next run read a record that a killed process could not have written.
- Later captures are read and chained from the record. One that offers only D1 with a newer KRL or bundle has that directory step refused (`directory_older`), so only its KRL moves on, bounded by current (D10). The report and the status name directory 2 as unapplied.

RED at 388b525 (the code of 9aa10f6, with the new subtest): `--- FAIL: TestRollbackSites/withdrawn_directory_after_kept_rollback_keeps_removal/krl_only/probes_off`, `/krl_only/probes_on`, `/bundle_only/probes_off` and `/bundle_only/probes_on`, with these messages:
- `the report names <nil> as unapplied, want directory 2`;
- `the status: <nil>; want directory 2 named as unapplied`;
- `role:a granted again: <nil>, principals [role:a role:x]`, in force from `self-test` to `clear-marker`.

The R3(b) throwaway test showed the same re-grant before the subtest was written.

GREEN at a44c318:
- all four lanes pass;
- `go test -race -count=1 -timeout 15m -v ./internal/agent/apply/` ok (445.903 s, before a comment-only edit), no DATA RACE;
- R2 (`refused_capture_during_wait_lands_addition`) and the held-record guard (`bounded_krl_alone_keeps_held_record`, `krl_alone_pass_is_classified`) still pass.

The retry path, checked in the same subtest:
- with directory 2 offered again, its addition lands once the listener test passes;
- role:a is in force at no fault point;
- the commit passes the record: `<state>/unapplied.json` is gone and Report.Unapplied is nil;
- accepted/ is at directory 2 and last-good = current.

The earlier kept-state subtests that retry with directory 2 still in the spool (for example `mustKeptSite`'s next apply) pass unchanged.

**Gates at 9aa10f6 (local, through scripts/linux.sh).** Gates 2 and 3 ran with this SUMMARY's revision uncommitted in the working tree; that revision changes docs only.
- **Gate 2** (whole module): exit 0, from 1794194651 to 1794195382.
- **Gate 3** (test-time delta): exit 0. It ran alone after gate 2, from 1794195394 to 1794195832, on the same base line; the base was 18687 s old.

| Package | Base (s) | Reading (s) | Delta (s) | Stop |
|---|---|---|---|---|
| apply (internal/agent/apply) | 488.967 | 441.949 | -47.018 | +90 |
| krl | 7.347 | 7.066 | -0.281 | +90 |
| signer | 395.214 | 404.431 | +9.217 | +90 |
| audit | 87.541 | 88.822 | +1.281 | +90 |
| cmd (cmd/keyroster) | 269.858 | 229.304 | -40.554 | +90 |
| agentcmd (cmd/keyroster-agent) | 1.811 | 1.834 | +0.023 | +90 |

The fix round adds five subtest runs to apply. The reading is 47 s under the base. The cause of that difference is not measured, and the reading is recorded as read.

**CI at 9aa10f6** (pushed as a fast-forward). 28 checks passed and one was skipped; no required check failed. These are the `pull_request` runs, all with headSha 9aa10f6:

| Run ID | Workflow | Result |
|---|---|---|
| 42556194780 | CI | success |
| 42556194704 | E2E | success |
| 42556194873 | E2E distro | success |
| 42556194853 | Systemd | success |
| 42556194695 | E2E TPM | success |
| 42556194710 | E2E PKCS#11 | success |
| 42556194694 | CodeQL | success |
| 42556194773 | PIV | success |
| 42556194909 | PR title | success |
| 42556194717 | Workflow lint | success |

At 28594ac, the SUMMARY revision that recorded the above, gates 1, 4 to 9 and 11 exited 0. Gate 10 was stopped while it was waiting on CI, when owner decision Q3 arrived. The Q3 fix moved the head past 28594ac.

**Gates at a44c318, the final code (local, through scripts/linux.sh).** Gates 2 and 3 ran with this SUMMARY's revision uncommitted in the working tree; that revision changes docs only.
- **Gate 2** (whole module): exit 0, from 1794198455 to 1794199148.
- **Gate 3** (test-time delta): exit 0. It ran alone after gate 2, from 1794199148 to 1794199656, on the same base line; the base was 22441 s old.

| Package | Base (s) | Reading (s) | Delta (s) | Stop |
|---|---|---|---|---|
| apply (internal/agent/apply) | 488.967 | 512.945 | +23.978 | +90 |
| krl | 7.347 | 7.189 | -0.158 | +90 |
| signer | 395.214 | 418.999 | +23.785 | +90 |
| audit | 87.541 | 88.648 | +1.107 | +90 |
| cmd (cmd/keyroster) | 269.858 | 224.476 | -45.382 | +90 |
| agentcmd (cmd/keyroster-agent) | 1.811 | 1.794 | -0.017 | +90 |

**CI at a44c318** (pushed as a fast-forward). 28 checks passed and one was skipped; no required check failed. These are the `pull_request` runs, all with headSha a44c318:

| Run ID | Workflow | Result |
|---|---|---|
| 42561932764 | CI | success |
| 42561932755 | E2E | success |
| 42561932778 | E2E distro | success |
| 42561932759 | Systemd | success |
| 42561932827 | E2E TPM | success |
| 42561932793 | E2E PKCS#11 | success |
| 42561932786 | CodeQL | success |
| 42561932780 | PIV | success |
| 42561932795 | PR title | success |
| 42561932787 | Workflow lint | success |

This SUMMARY's revision is pushed after these runs. Its own checks, and the gates that run against it, are reported with the hand-off.

### Deviations (Task 3)

- The GSD tracking handlers were not run a second time for the final commit. The tracking update is the one already in 80df5e1. A second `state.advance-plan` would count the plan twice, and a second roadmap update could change lines that gate 7 forbids.

## UNVERIFIED

The plan's Edge Coverage list, item by item, with what the run showed. Nothing named here is claimed as verified.

- **The start-up `recover` keeps removals (D8)**, so a crash, a failed keeping rollback, or a non-crash error after a swap that leaves a marker all end at the kept content at the next start. The marker can come from forward's commit, or from settle's setHostStatus and commit. Tested: `crash_recovery_keeps_removal`, `double_failure_next_start_keeps_removal/*`, `commit_stage_error`, `settle_commit_error`. The residuals:
  - **`--recover-to-last-good` (`recoverToLastGood`) keeps its plain target** (D6, Q1 = A). It is the only plain path: an operator-invoked re-grant, with the newer KRL kept.
  - **A marker generation that does not read makes recover fail closed** (`pending_state_unknown`, T-03-395). Cleanup keeps the marker's generations while it is pending (swap.go:723), so this is not expected outside a damaged gen/. A keeping recover that keeps failing blocks Apply at :492 and holds newer KRLs back.
  - **The failure of the keeping rollback's own install of the kept content** (Q-D's 'cannot be installed' case) is not injected. Its success is exercised by `settle_validate_error`.
  - **settle's `m == target` case** (probegate.go, the `case m == target:` branch) is not reached in the harness.
  - **Covered structurally only** (`every_forward_call_keeps`): settleFailedAddition's install at :972 and held write at :983, and the readCurrent and last-good reads at apply.go:1073 and probegate.go:952. They have no one-shot injector.
  - **A T inside last-good passes atRollbackTarget by content**, so only its pending marker sends it to recover (`double_failure_after_kept_base_keeps_readd_out`).
- **The sequences of the drop-in sites and of the held round (D5)** were derived from the code at e22cc06. The run matched them, as 'Sequences derived from the code, as the run showed them' records. One hold reason differed and is reported there: `gate_superseded_error` is held for `shell_not_nologin`.
- **The fallback render keeps the principals in force** (D9, tested probes off and on). Not covered: a render that Render itself accepts after a kept rollback widens like any other addition, and is gated when probes are on. The gate tests enforcement, not authorization.
  - Fix round 1's R3(b) check confirmed this with a run. On a kept state, a KRL-only capture and a bundle-only capture, each with the failed directory withdrawn, rendered accepted/'s directory with nothing refused and granted the kept removal again (probes off and on). Owner decision Q3 fixed it (a44c318): the keeping rollback records the directory as unapplied. The residuals:
    - A run killed after the removal landed and before the record is written, and a kept state left by a build before a44c318, have no record. The next start's keeping recover keeps the removal, but a later capture that withdraws the directory can still render accepted/'s. Not tested.
    - That a rollback which itself failed (current or last-good unreadable, or a double failure) writes the record follows from the code; no test asserts it.
    - A capture that offers no directory at all after the withdrawal (rather than D1) would render the recorded directory as the newest verified state. Not tested.
- **A held addition is not gated again while a refused capture persists** (D10 as restated). The bounded KRL-alone pass keeps it out, and the hold stands (`bounded_krl_alone_keeps_held_record`). It is gated again on the first directory that renders. This is accepted under D10 as known behaviour, not a defect.
- **A kept state can hold an empty `user_ca_keys`** when the base, last-good and current hold disjoint CA lists (plan check sec-8). Certificate logins are then locked out until the keeping recover or the next round moves current. This is the fail-safe direction; there is no code for it.
- **systemd userdb in nsswitch.conf** (03-10c fix round 1) is not measured. The worst case is a false `account_excluded` hold: liveness only, never fail-open. Handed to 03-16 through the hand-over todo.
- **The double failure of D1 (Q-D option 1)** leaves current on the failed target until the next Apply's start (T-03-388, T-03-392). For a gated addition, that is a live unproven addition until then.
- **Current can name a generation that is neither last-good nor last-good's content after a rollback.** Whether 03-12 and 03-14 need to know is not checked (hand-over todo).
- **The extra listener test of the equal-content guard.** No unit test outside the files_modified failed on it in the whole-module run. Whether an e2e or distro run takes that path is not counted: the PR's e2e lanes passed, see Task 3.
- **Recovery:**
  - No old log is checked for a recovery that kept a lost probe certificate. Such a log would now fail `audit verify`; 03-10 merged days before and no release has shipped.
  - The recovery path is not run end to end (03-10's R9).
  - A revoked lost positive makes its host ask for a new pair and wait (P4). This is unit-tested only.
- **A lost probe certificate that the saved export cannot show** is not recoverable by this rule. It expires with its lifetime (at most seven days, min with the machine cap).
- **Local only, not run here:** Docker is not available in WSL. The distro, systemd and e2e lanes ran in CI only (Task 3).

## For later plans

- **03-12 (CA rotation)** waits on a host with a broken probe account (R11).
- **03-12 and 03-14 read current**, which can differ from last-good after a kept rollback. 03-12-PLAN.md:371 and 03-14-PLAN.md:324 describe the old target. Hand-over todo: `.planning/todos/pending/2026-11-08-03-12-and-03-14-read-current-after-a-kept-rollback.md`.
- **03-16, through `.planning/todos/pending/2026-11-08-03-16-host-setup-and-preflight-handovers.md`:**
  - the `--recover-to-last-good` warning sentence (host-setup.md near :1982);
  - the rollback contract at host-setup.md:2309-2311, now with the kept state, the keeping start-up recovery and `pending_state_unknown`;
  - 03-10c's three hand-overs:
    - preflight's report-only note for possible probe-account exclusions;
    - the nsswitch.conf sentence of host-setup.md (an unreadable file counts as files only);
    - the systemd userdb measurement.
- **The older follow-ups of 'Not done here', unchanged** (later, no plan):
  - the sshd `Match User` lockdown for the probe account;
  - a live revocation set for fleets above about 1000 hosts;
  - `TestFetch/more_repolls_immediately` under a parallel `-race` load;
  - the 16 e2e lint issues under build tags CI never lints.
- **Not planned:** a polarity field in the recovery request (declined by Q-R option 1), and the operator's `--recover-to-last-good` keeping removals (Q1 = A).

## Where to resume

- **Done:**
  - Task 1 (T1 a37a72c), Task 2 (T2 7427197) and Task 3 up to the merge gate: tracking commit 80df5e1, gates 1 to 7 and 9 to 11, and this SUMMARY.
  - 40 of 40 mutants killed.
  - Pre-merge review fix round 1: c0dc912, 039a319, 772df77, 9aa10f6, 28594ac, 388b525, a44c318 and this SUMMARY's revision; fix-round mutants 30 to 34 killed.
  - PR #93 is open, with auto-merge off.
- **Next:**
  - The orchestrator's review of the fix round's head.
  - Then the owner's merge gate: Daniel reviews, approves and squash-merges in the GitHub web UI.
  - Before the merge, Claude runs only `bash scripts/merge-gate.sh --check p03/10d-no-regrant-recovery`.
- **If main moves first:** `git rebase --gpg-sign origin/main`, take origin/main's tracking files and re-apply only this plan's entries, push with lease, wait for the checks, re-run the gates (the delta gate's base expires at epoch 1794263107), and ask for a review of the new head.
- **After "merged":** from the main checkout, `bash scripts/merge-gate.sh p03/10d-no-regrant-recovery`, then the `--check` form.

## Self-Check: PASSED

- Files: internal/agent/apply/rollbackkeep_test.go, the two hand-over todos and both completed todos exist; `func RollbackKeeping(` (render.go) and `func IsProbeKeyID(` (krl/recovery.go) are present.
- Commits: 32e1fd1, d8335e7, 0f69d51, 5c78955, a37a72c, 28fffc2, ccac467, 7427197, a4b5432 and 80df5e1 are ancestors of HEAD and on origin.
- Fix round 1 commits: c0dc912, 039a319, 772df77, 9aa10f6, 28594ac, 388b525 and a44c318 are ancestors of HEAD and on origin.
