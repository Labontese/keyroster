---
phase: 03-linux-agent-and-revocation
plan: 10d
subsystem: agent, krl, signer, audit, cli, docs
tags: [rollback, kept-state, recovery, probe-certificates, agent-04]
status: in-progress
requires: [03-10c]
provides: [rollback-keeping, keeping-recover, recovery-revokes-probe-certificates]
requirements-completed: []
---

# Phase 3 Plan 10d: No rollback re-grants a landed removal; recovery revokes every lost probe certificate Summary

Draft (Task 1 in progress). Completed in Task 3.

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

## Owner questions

1. **hostcert_test.go must change, and it is not in files_modified (blocking).** `TestHostCertStep/no_install_while_recover_due_sshd_t_fails` (internal/agent/apply/hostcert_test.go:1441) fails after Task 1: `HostCerts wrote: ... 00-keyroster.conf ... hostcert.json ...`. Its fixture points current back at an older generation with no marker and relies on that not being a rollback target. The older generation lies inside last-good with the same KRL, so the content check that Step 3b(1) (sec-5) requires now accepts it as a kept state, and HostCerts proceeds. Confirmed: with atRollbackTarget put back to `sameBytes(c, RollbackTarget(c, l))` the subtest passes; restored with `git checkout --`, tree clean. The plan judged hostcert_test.go unaffected and says an unlisted file a fix needs is added to files_modified first; that edits the plan, which this executor may not do. Proposed fix: rebuild the fixture so the older current holds a principal last-good lacks (a wider current is still not a rollback target, so recovery stays due and the subtest keeps its intent), with `internal/agent/apply/hostcert_test.go` added to files_modified and to Task 1's `<files>`. Alternative: a stricter start check, which contradicts sec-5; not recommended. Task 2 is independent of this (D4).

2. **A content refusal after a kept rollback can widen back through the KRL-alone pass (not blocking; read from the code, not run).** A rollback leaves accepted/ at last-good's directory. When a later capture's candidate is refused as content (a CA line ssh-keygen refuses, or a Render refusal such as `generation_too_large`), forward takes the KRL-alone pass (apply.go, `krlAlone`), which renders accepted/'s directory, the one that still grants the removed line, and the candidate widens current back to it: ungated with probes off, gated (enforcement only) with probes on. This is forward's render of the directory in force, not a rollback, so this plan's rules do not cover it; the Edge Coverage bullet 'a render that Render itself accepts after a kept rollback widens like any other addition' is the closest. Listed UNVERIFIED below; whether a later plan should make the KRL-alone pass keep current's principals is the owner's call.

## UNVERIFIED (Task 1, so far)

- The KRL-alone path of owner question 2.
- The failure of the keeping rollback's own install of the kept content (Q-D's 'cannot be installed' case) is not injected; its success is exercised by `settle_validate_error`.
- settle's `m == target` case (probegate.go, the `case m == target:` branch) is not reached in the harness.
- The sites with no one-shot injector (apply.go:1073 readCurrent, probegate.go:952 the last-good read, :972 install, :983 the held write) are covered structurally only (`every_forward_call_keeps`).
- A kept state can hold an empty `user_ca_keys` when the base, last-good and current hold disjoint CA lists (plan check sec-8; fail-safe direction, no code).
- 03-12 and 03-14 read current, which may now differ from last-good at rest (hand-over todo in Task 3).

## Deviations (Task 1, so far)

- `kept_state_start_failure_keeps_removal` uses a validate refusal of the KRL query (`queryCode`, with a new KRL published so validate queries it), which forward returns before its first swap (apply.go:1038-1040). The plan's example, the oversize candidate of rechain_test.go:288, is a Render refusal (`ErrGenerationTooLarge`, render.go:182): candidate refuses it and forward takes the KRL-alone pass instead of returning, so it does not reach :1038.
- `gate_superseded_error`: the next round is held for the account's reason (`shell_not_nologin`, the superseding passwd that makes the gate hold), not `failure_backoff` as the plan's grouped assertion for the settle and gate sites says; it lands role:b once the input changes (the passwd fixed). Reported, not adjusted.
- `settle_validate_timeout` runs Apply with a 20 s context: the harness's Apply has no deadline of its own, so "until the context ends" needs one; the blocked ssh-keygen returns `context.DeadlineExceeded` and the keeping rollback still completes (its steps do not depend on the expired context in the harness).

### Gates run so far (Task 1, local, at d8335e7)

- Gate 1's test part: `go test -race -count=1 -timeout 15m -v -run "^(TestRollbackKeeping|TestRollbackSites|TestAtRollbackTarget|TestProbeGate)$" ./internal/agent/apply/` ok (31.094 s); gate 1's PASS loop over that log printed no missing PASS line and no FAIL, panic or DATA RACE. `go build ./...` and `go vet ./internal/agent/apply/` ok; `gofmt -l internal cmd` empty; golangci-lint (linux) on ./internal/agent/apply/ 0 issues. The full gate 1 command (with `go vet ./...` and the tagged vet) has not been run as one command yet.
- Gate 2: `go test -race -count=1 -timeout 15m ./internal/agent/... ./cmd/keyroster-agent/` FAILED, only on `TestHostCertStep/no_install_while_recover_due_sshd_t_fails` (owner question 1); every other package ok (internal/agent/apply 438.895 s under the parallel load of the other packages, not a delta reading). `git diff --quiet origin/main -- internal/agent/apply/interleave_test.go internal/agent/apply/swap.go internal/agent/apply/selftest.go` ok.
- Gate 3 (capslock, frozen packages, the todo move): not run yet.

## Where to resume

- Done: Step 0 (32e1fd1); the base; Task 1 Steps 1 to 4 (d8335e7: tests, implementation, existing-test conversions). Task 1's unit gate (gate 1's PASS loop) passes on a log of the same `-run`.
- Blocked: owner question 1 (hostcert_test.go). After the answer: the fixture fix, then Task 1 gate 2 (`./internal/agent/...` under -race and the swap/selftest/interleave diff).
- Then Step 5: capslock, the lints for linux, windows and darwin on `./...` (a single-package windows lint excludes every file of this linux-only package by design), the `git mv` of the todo with a `## Resolution` section, and its commit; then the 29 Task 1 mutants (spec and runner prepared outside the repository), then Task 2, then Task 3.
- The kept-state twin `atKept` is in rollbackkeep_test.go; the injectors and helpers there are reusable for the hostcert fixture.
