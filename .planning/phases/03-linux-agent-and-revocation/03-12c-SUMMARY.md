---
phase: 03-linux-agent-and-revocation
plan: 12c
subsystem: trust, agent, heartbeat, doctor
tags: [ca-rotation, draining, trusted-until, drop-latch, bundle-behind]
status: complete
requires: [03-12b]
provides: [CAEntry.TrustedUntil, TrustedAt, TrustedCAs, UserCAKeysFile, UserCAKeysFileExcept, RenderAt, Report.TrustDue, trust-dropped.json latch, DrainingCA, bundle_behind, BundleBehind, GenerationFact.TrustedUntil]
affects: [03-12d, 03-12e, 03-12f, 03-13, 03-14]
key-files:
  created: [internal/agent/apply/latch.go, internal/agent/apply/behind.go, internal/agent/apply/draining_test.go, internal/agent/apply/latch_test.go, internal/agent/apply/behind_test.go, test/vectors/bundle_rotation_v1.json, test/vectors/user_ca_keys_rotation_v1.txt, internal/rootceremony/testdata/summary/draining.golden]
  modified: [internal/trust/bundle.go, internal/trust/castate.go, internal/rootceremony/summary.go, internal/agent/apply/render.go, internal/agent/apply/apply.go, internal/agent/apply/run.go, internal/agent/apply/drift.go, internal/agent/apply/hostcert.go, internal/agent/apply/probe.go, internal/agent/apply/adopt.go, internal/agent/apply/status.go, internal/agent/hostcert/hostcert.go, internal/agent/heartbeat/heartbeat.go, cmd/keyroster-agent/check.go, cmd/keyroster-signer/doctor.go, internal/doctor/doctor.go, docs/runbooks/host-setup.md]
decisions:
  - "The genesis refusal of a draining entry is in Validate (every path that reads a first bundle runs it), not in VerifyGenesisBundle, which the agent's first acceptance never calls"
  - "The latch records every draining user or machine key the render omits, before anything lands, keyed by key and never pruned; an unreadable latch renders no draining key and is never overwritten"
  - "check's draining, trust_expired, trust_latch and bundle_behind are report-only: Drift() and the exit status are unchanged"
  - "Run's check sets trustExpired, and the next round applies it at once, after a failed apply only once Retry has passed (T-03-443): a failing apply is retried per Retry, not on every iteration (orchestrator decision, 2026-11-16; the guard moved from the check into the round's trigger in the PR #107 review fix); every check also arms the draining timer from the accepted bundle (PR #108 review)"
requirements-completed: []
actuals:
  tokens: 45208
  tasks: 5
  commits: 14
plan_head_before: 335af53ce8dbe6188e60a541e5d49f844f9989bc
plan_head_after: aacf9dd8f21bd1d9ff679e669a48a044f779bc76
---

# Phase 3 Plan 12c: CA rotation readers Summary

test-time base: signercmd=55.139 apply=616.365 at=1794848954

A bundle may carry a `draining` CA with a `trusted_until`; every agent trusts it until that date and drops it on its own clock as a narrowing change, with a permanent per-key latch that a clock step, a rollback or a directory reset cannot undo; the answer sets and adoption read the same time-aware rule, `bundle_behind` reports a withheld bundle after 2 hours, and doctor and `keyroster-agent check` show the end dates. Nothing can create a `draining` entry before 03-12e, so nothing drops in production.

## PR and CI

- PR #107 (`feat(agent): trust a draining CA until its end date and drop it on the agent's clock`), opened by keyroster-bot without auto-merge (`autoMergeRequest` null).
- The check run IDs and the house e2e gate readings of the final head are recorded in the PR description. A SUMMARY cannot name the runs of the commit that carries it, and recording them here would need one more push after the checks.
- PR #107 was squash-merged to main as fefd624 before its pre-merge review ran. The review then ran on fefd624, and its issues and their fixes are recorded under "Review (after merge)" below.
- Requirement KEY-08: advanced, not completed (it completes in 03-13). `requirements.mark-complete` was not run and REQUIREMENTS.md is untouched.

## Reversibility

Task 1's format change is the costly one the plan names: once 03-12e lets a signer issue bundles with `draining` and `trusted_until`, a release that renamed the field or changed its rules would refuse the chain of an installation that already rotated, and entries are never removed. The owner decided the shape (six plans, 2026-11-14); no checkpoint was inserted.

## Execution log

- Stop guard, base values, ruleset (30), names free, threat IDs and mutant numbers free, and every code anchor: all passed on origin/main 335af53 before any edit (main had moved from 015d26e to 335af53 by PR #106; recorded, no baseline edited).
- Base measured on unchanged 335af53 before any edit: signercmd 50.993 s, apply 659.566 s.
- Capslock pair counts at 335af53 (before any edit): keyroster-signer 94 (baseline 97; the three ARBITRARY_EXECUTION pairs of internal/directory, internal/sshsig and internal/trust are no longer reported, as the reconcile ledger predicted), keyroster-agent 37, keyroster-agent-fetch 23.

## Commits

`git diff --cached` was run on every staged file and read in full, file by file, after the last edit and before each commit below (new files read whole). The plan commit P was read in full as well (its 917-line staged diff against the early plan, no edit after the read).

| Name | SHA | Subject |
|---|---|---|
| S0 | 9343dd0b72db8c75813d03d531d81a359f51cfd7 | refactor(agent): hand the engine's clock to the render |
| R1a | 6282220923fdaa0dddc971b7f189ddd72db1bbc7 | test(trust): pin draining entries, trusted_until and the CA file |
| T1a | e8916121211a03dc759fab733eabb8d9ba925bc7 | feat(trust): parse draining CA entries and trusted_until, and the CA file at a time |
| R1b | 42d08c1bc4860cbf69cc9b2b5550256eb7a29196 | test(agent): pin the drop of a draining CA at its end date |
| T1b | 597803a5be08c4f85af297139bf287ed6158b919 | feat(agent): trust a draining CA until its end date and drop it at that time |
| R2 | 9447ca94a69f0abc60169a388901459c26ec1dd3 | test(agent): pin the drop latch and the check's trust reports |
| T2 | 7871ed682373fee34a21eb7718bbfb34a204995c | feat(agent): keep a dropped draining CA out for good and report it in check |
| R3a | 87291dcfbb53e26d4c38dd739bfd70640d4c7933 | test(agent): take the answer sets and adoption from the time-aware CA set |
| T3a | 99cf4eca5b2ac15ef9570158070b26fc0d234396 | fix(agent): decide answers, kept certificates, probe pairs and adoption on the CA keys trusted now |
| R3b | 84de1b4fc23091af23cd74166f4e2209fcf78e5e | test(agent): pin bundle_behind from the accepted KRL manifest |
| T3b | 52ee3f1407bc27f910f8298a91a4ea7bd5cfef2a | feat(agent): report bundle_behind when the KRL manifest names a bundle the host has not accepted |
| R4 | 40d7216065ec16641e31426222c844935e4fc3b7 | test(trust): pin the rotation vector, the draining pins and doctor's trusted_until |
| T4 | 898b198f0146811855711a95656484d44b6212d0 | feat(doctor): show the end date of a draining CA generation, and document the agent side of the rotation |
| P | aacf9dd8f21bd1d9ff679e669a48a044f779bc76 | docs(03-12c): plan out the CA rotation readers |

R2 was amended once before any push (its first form, 2811169, was never pushed); the amend's staged diff was read in full as well.

## Task 1

- S0 verify (TestSwapInterleaving, TestIntermediate, TestRenderable with -race): ok. S0 changes no golden (`git diff -U0 S0^ S0 -- cmd/keyroster/testdata internal/rootceremony/testdata` is empty).
- R1a declarations: `CAEntry.TrustedUntil` (json `trusted_until,omitempty`, last field); stubs `CAEntry.TrustedAt` (false), `TrustedCAs` (nil), `UserCAKeysFile` and `UserCAKeysFileExcept` (nil, nil).
- R1a RED, from a detached worktree of R1a: exactly 32 `--- FAIL:` lines, every named one present, no build or setup failure, no FAIL outside the seven named top-level tests. Controls passed on R1a: TestTrustedAt/`retired_never`, `draining_at_the_end_false`, `draining_after_the_end_false`, `unparsable_end_untrusted` (the stub trusts nothing); TestBundleCAStates/`one_next_per_role_ok`, `single_active_bundle_unchanged`, `empty_trusted_until_not_canonical` (the field exists and is omitted when empty).
- The two 03-12b tests converted in R1a (OQ-B): internal/signer TestInstallNextBundle/`second_next_while_one_is_next_refused` now expects `trust.ErrInvalid` holding `more than one next entry`, nothing written; cmd/keyroster-signer TestCANextTracer's `second_next` leg expects exit 1 and `more than one next entry` (the `active_changed` leg keeps the chain-rule text and `CA user generation`, now also with exit 1). The chain rule's own `the role already has a next entry` stays pinned by TestCATransitions/`add_second_next_refused`.
- T1a verify: go vet, gofmt, internal/trust, internal/rootceremony, internal/doctor, the focused signer and audit cases, cmd/keyroster-signer, the focused cmd/keyroster ceremony cases, and the windows and darwin builds of the shared helpers: all ok. `git diff --name-only T1a^ T1a -- cmd/keyroster/testdata internal/rootceremony/testdata` is empty.
- R1b declarations: `Report.TrustDue` (json `-`); stubs `hasDraining` (false), `trustDue` (zero), `(*engine).narrowingPending` (false). Test helpers (harness_test.go): `withBundle`, `drainingCA`, `useBundle`; (run_test.go) `trustLoop`, `startTrustLoop`; (draining_test.go) `newDrainingHost`, `caText`, `setCurrentCA`, `verifiedOf`.
- R1b RED, from a detached worktree of R1b (which holds T1a): exactly 12 `--- FAIL:` lines, every named one present, `DRAIN:` and `TRACER:` in the log, no `want active, next or retired`. Controls passed on R1b: TestDrainingDrop/`no_draining_bytes_unchanged`, TestNarrowingPending/`held_next_line_is_not_pending`, `kept_state_of_an_aborted_key_is_not_pending`, `bundle_without_draining_is_never_pending`, TestTrustDue/`none_without_draining` (each describes today's bundles, and the stubs return false and zero).
- Scratch-run fact confirmed in the tests: a fresh testHost accepts a hand-signed version 3 bundle with a draining entry as its first bundle and renders its draining, active and machine lines (TestDrainingDrop/`draining_trusted_before_the_end`).
- T1b verify: go vet, gofmt, `go test -race ./internal/agent/...` (apply 615.953 s), capslock, dep-firewall and golangci-lint (0 issues): all ok. The whole internal/agent tree ran at T1b only, not at T1a (T1b does not touch Validate, so a T1a-only failure is unlikely, but it was not run there).
- Capslock after T1b: keyroster-signer 94 (baseline 97, the same three pairs no longer reported), keyroster-agent 37, keyroster-agent-fetch 23. No new pair.
- Commit checks: no test or test data changed between R1a and T1a, or between R1b and T1b; no added line from S0^ to T1b carries a `"keyroster/` literal.

### Task 1 mutants

Each mutant was applied to the working tree at T1b, `go vet` of the mutated package exited 0, the exact command ran with `-timeout 5m` (`-v` added to read the subtest lines), the file was restored with `git checkout -- <file>`, its sha256 compared equal with the pre-mutant value (full hash compared; first 16 hex digits shown), and `git status --short` listed no code path. The unmutated commands passed first. No build or setup failure and no timeout.

| Mutant | Mutation | Killed by (named) | sha256 (before = after) |
|---|---|---|---|
| M135 | castate.go TrustedAt `!t.After(end)` | TestTrustedAt/draining_at_the_end_false | 58cd42fbca1e7b38 |
| M136 | castate.go TrustedAt trusts a draining entry whatever its end | TestTrustedAt/draining_at_the_end_false, draining_after_the_end_false, TestUserCAKeysFile/draining_dropped_at_the_end | 58cd42fbca1e7b38 |
| M137 | render.go renderTrust passes the zero time | TestDrainingDrop/draining_dropped_unchanged_capture, TestRunTrustDue/trust_due_triggers_apply | e650604571b6507c |
| M138 | apply.go no-op loses `!e.narrowingPending(v)` | TestDrainingDrop/draining_dropped_unchanged_capture, TestRunTrustDue/trust_due_triggers_apply | c9c9001d6a4985d9 |
| M140 | run.go trigger ignores trustDue (`false &&`) | TestRunTrustDue/trust_due_triggers_apply | 6301cf4a8888a0d0 |
| M145 (trust leg) | castate.go writes a `cert-authority ` option prefix | TestUserCAKeysFile/plain_lines_only | 58cd42fbca1e7b38 |
| M145 (apply leg) | render.go prefixes a `# keyroster` comment line | TestDrainingDrop/render_plain_lines_only | e650604571b6507c |
| M208 | bundle.go no trusted_until required on draining (both checks off) | TestBundleCAStates/draining_without_trusted_until_refused, draining_with_bad_trusted_until_refused | 38c128e71061b98a |
| M209 | bundle.go trusted_until allowed on any state | TestBundleCAStates/trusted_until_on_active_refused, _next_, _retired_ | 38c128e71061b98a |
| M210 | bundle.go version 1 may carry draining | TestBundleCAStates/genesis_with_draining_refused, genesis_verify_refuses_draining | 38c128e71061b98a |
| M211 | bundle.go no limit of one next per role | TestBundleCAStates/second_next_for_one_role_refused | 38c128e71061b98a |
| M212 | castate.go machine role before user role | TestUserCAKeysFile/user_then_machine_by_generation | 58cd42fbca1e7b38 |
| M213 | summary.go prints no `trusted until` | TestBundleReflectGate/CAEntry.TrustedUntil | 94e1263d85d310a8 |
| M214 | apply.go trustDue counts an end equal to now | TestTrustDue/an_end_at_now_is_not_due_again | c9c9001d6a4985d9 |
| M215 | apply.go trustDue skips the host role | TestTrustDue/covers_every_role | c9c9001d6a4985d9 |

M140 and M211 use `false &&` guards because deleting the code would leave `trustDue` or `next` unused and the mutant would not compile (the mutant rule requires that every mutant compiles); M208 to M210 and M213 use the same form for consistency.

Full sha256 of each mutated file before the mutant and after the restore (equal to its blob at T1b):
- internal/trust/castate.go 58cd42fbca1e7b388fff3458ab61587bf4250f9ea3daace888207b089d8d8dea
- internal/trust/bundle.go 38c128e71061b98ab43cddd01836c69446095bd4e354e934688f8a3165d9afad
- internal/agent/apply/render.go e650604571b6507ca2e28ac619f78743a35372565c0f7798363403db5d1e3fd2
- internal/agent/apply/apply.go c9c9001d6a4985d9b169bef12b182786b28d48f200838297fa385abe55ff1800
- internal/agent/apply/run.go 6301cf4a8888a0d0676e1bd703f08ae4aa07fcdc23eba46f75b4531013c45cda
- internal/rootceremony/summary.go 94e1263d85d310a859df04c865ff3661a22a8ba2f30cabd84e6226973700716a

## Task 2

- Precondition: `git fetch origin` (origin/main still 335af53) and Task 1's stop guard: exit 0, before any Task 2 edit. T1b 597803a was on the branch.
- Test-time base re-measured first (another session), on origin/main 335af53 in a detached worktree outside the repository, with no other job running: signercmd 43.759 s, apply 598.542 s; the `test-time base:` line was replaced in place (one line, the acceptance grep passes). The worktree was removed afterwards.
- R2 declarations: internal/agent/apply/latch.go with `trustLatchFile`, `latchKey`, `Latch` (fields `keys`, `unreadable`), `newLatch` (complete: it is the test constructor), and the stubs `(*Latch).Blocks` (false), `(*engine).readLatch` (an empty latch) and `(*engine).recordDropped` (nil); drift.go `DrainingCA` (json `role, generation, fingerprint, trusted_until, state, in_file, latched`) and the DriftReport fields `Draining`, `TrustExpired` (omitempty) and `TrustLatch` (omitempty).
- R2 test helpers: (latch_test.go) `fp`, `latchText` (the contract's canonical latch bytes, built in the test, not by latch.go), `writeLatchFile`, `latchFile`; (draining_test.go) `stepWall` (steps the fake clock's wall time only, so a backward step leaves the monotonic clock alone), `twoDrainingCA(f, a, endA, b, endB)`; (drift_test.go) `stateListing`, `heldNextHost` (a probes-on host whose gate holds 03-12b's chain-legal next user CA: `probe_held`, the next line absent from current).
- R2 RED, from a detached worktree of R2 (which holds T1b): exactly 24 `--- FAIL:` lines, every named one present, `LATCH:` and `CHECK:` in the log, no `want active, next or retired`, no build or setup failure, no FAIL outside the six named top-level tests. Each failure is the test's assertion (the latch file empty, the draining key rendered after a step back, Check's trust lists empty, two applies where three are wanted).
- R2 controls (12) passed on R2: TestLatch/`missing_file_is_empty`, `unreadable_is_never_overwritten`, `record_skips_when_nothing_new` (the file is written by the test first, so the stub's no-write is the expected behaviour), `path_is_allowed` (the stubs record nothing and read an empty file); TestDrainingLatch/`dry_run_writes_no_latch` (the stub writes nothing); TestDrainingDrop/`drop_with_directory_unauthorized` (T1b's narrowing path: forward is never a no-op while the directory is unauthorized); TestCheckTrust/`nothing_for_a_held_next_line`, `healthy_host_has_no_trust_fields`, `check_writes_nothing` (the stub report is empty); TestRunTrustDue/`trust_due_error_backs_off`, `trust_due_covers_host_role` (T1b's TrustDue covers both) and `held_next_line_does_not_retrigger`.
- R2 was amended once before any push (9447ca9 replaces 2811169): TestDrainingLatch/`latch_survives_reset_directory` gained `spoolInState(t, h)`, because ResetDirectory refuses a spool outside the agent's paths (`path_not_allowed`), as the existing reset tests arrange. On R2 the leaf had failed earlier, at its latch assertion, so the first RED was not wrong, but the leaf could not pass on T2. The amend's staged diff (that one line) was read in full, and the RED above was taken again from the amended R2: 24 FAIL lines, the same names, all 12 controls passing.

- T2 verify: Task 2's command (go vet of internal/agent and cmd/keyroster-agent, then `go test -race` of TestLatch, TestDrainingLatch, TestDrainingDrop, TestNarrowingPending, TestCheckTrust, TestRunTrustDue, TestDrift, TestRunChecks, TestRenderable, TestKRLAlone, TestDirectoryUnderPolicyInForce and TestRollbackKeeping): ok (181.055 s). The full verify (go vet ./..., gofmt, `go test -race ./internal/agent/...` with apply 550.153 s and every other agent package ok, go build of keyroster-agent, capslock-check, dep-firewall, golangci-lint 0 issues): exit 0, run on the T2 tree before the commit, which changed nothing after it. TestPaths (internal/agent/paths) is unchanged and green.
- Capslock after T2: keyroster-signer 94 (baseline 97, the same three pairs no longer reported), keyroster-agent 37, keyroster-agent-fetch 23. No new pair.
- Commit checks: no test changed between R2 and T2; the added lines of internal/agent/apply and cmd/keyroster-agent (non-empty) carry no private-term word and no os.Rename, os.Symlink, os.Remove or unix.Renameat: the latch is written only through `e.writeState`.
### Task 2 mutants

Each mutant was applied to the working tree at T2 by a script that requires its anchor to match exactly once, `go vet ./internal/agent/apply/` exited 0, the plan's command ran with `-timeout 5m` (`-v` added), the file was restored with `git checkout -- <file>`, its sha256 compared equal with the pre-mutant value (full hash compared; first 16 hex digits shown), and `git status --short` listed no code path. The unmutated command passed first (10.540 s). No build or setup failure and no timeout.

| Mutant | Mutation | Killed by (named) | sha256 (before = after) |
|---|---|---|---|
| M139 (pending leg) | apply.go narrowingPending returns true when the render holds a line that current lacks | TestNarrowingPending/held_next_line_is_not_pending | 6bcfd9e04d75d287 |
| M139 (check leg) | drift.go reports as trust_expired every trusted user or machine entry whose line current lacks | TestCheckTrust/nothing_for_a_held_next_line, TestRunTrustDue/held_next_line_does_not_retrigger | 48f99c6c7b6129a1 |
| M141 | apply.go engine.render passes no Dropped predicate | TestDrainingLatch/clock_step_back_keeps_drop (also drop_survives_rollback, latch_written_before_the_swap, fresh_agent_after_the_end_latches, latch_unreadable_fails_closed) | 6bcfd9e04d75d287 |
| M142 | latch.go Blocks compares the entry's end with the latch's ends instead of the key | TestLatch/blocks_by_key_not_by_end | 7f297ce63efe6f81 |
| M143 | latch.go recordDropped writes only the newly omitted keys, replacing the file | TestLatch/record_adds_and_keeps, TestDrainingLatch/latch_never_pruned | 7f297ce63efe6f81 |
| M216 | latch.go an unreadable latch counts as empty | TestLatch/unreadable_blocks_every_draining_entry, TestDrainingLatch/latch_unreadable_fails_closed (also TestLatch/unreadable_is_never_overwritten, TestCheckTrust/latch_unreadable_reported) | 7f297ce63efe6f81 |
| M217 | apply.go the latch is recorded after the commit (a deferred call in commit) instead of at the render | TestDrainingLatch/latch_written_before_the_swap (also TestDrainingDrop/drop_survives_rollback) | 6bcfd9e04d75d287 |
| M218 | latch.go recordDropped writes in a dry run | TestDrainingLatch/dry_run_writes_no_latch | 7f297ce63efe6f81 |
| M219 | latch.go an unreadable latch is overwritten by the next record | TestLatch/unreadable_is_never_overwritten | 7f297ce63efe6f81 |
| M220 (check leg) | drift.go reports no trust_expired | TestCheckTrust/trust_expired_when_current_holds_a_drained_key (also recover_to_last_good_then_drop_again, trust_expired_sets_force_apply) | 48f99c6c7b6129a1 |
| M220 (run leg) | run.go the check closure does not make the next round apply for trust_expired (at T2 it set forceApply; since the PR #107 review fix it sets trustExpired) | TestRunTrustDue/trust_expired_sets_force_apply | 6601d06504945af5 |

- M142: TestDrainingLatch/`forward_jump_spares_later_rotation`, the plan's second named killer, does not kill this form: its latch holds key A with A's own end, and B's end differs, so comparing ends gives the same answer as comparing keys. TestLatch/`blocks_by_key_not_by_end` kills it.
- M215 (a Task 1 mutant, trustDue skips the host role) was also run once against the new TestRunTrustDue/`trust_due_covers_host_role`, which the plan names as its second killer: killed (`the host-certificate step ran 0 more times, want 1`); apply.go restored, sha256 6bcfd9e04d75d287 before and after.
- M139 (check leg) and M220 use `false &&` guards or added blocks so that every mutant compiles.

Full sha256 of each mutated file before the mutant and after the restore (equal to its blob at T2):
- internal/agent/apply/apply.go 6bcfd9e04d75d2874eac764293340240d26585de0a74d8fa421e78b2d09b4283
- internal/agent/apply/drift.go 48f99c6c7b6129a15e114899684b608c2c6f9ede930fe0f8dd985bb004e83f35
- internal/agent/apply/latch.go 7f297ce63efe6f811276a83e5af3d9f2ef3811856649867da576515876a95c0a
- internal/agent/apply/run.go 6601d06504945af53a191e28345a1046808326d9366bc62c7a45716d710121a9

- Residuals (stated, unchanged by this plan): a stopped agent narrows nothing; a wiped state directory loses the latch; the agent's answer sets (Task 3) and the CLI have no latch, so they trust a drained CA again while a clock is set back.

## Task 3

- Test-time base re-measured first in this session (a continuation), on origin/main 335af53 in a detached worktree outside the repository, with no other job running: signercmd 40.797 s, apply 590.181 s; the `test-time base:` line was replaced in place (one line, the acceptance grep passes) and the worktree removed.
- Precondition: `git fetch origin` (origin/main still 335af53) and Task 1's stop guard: exit 0, before any Task 3 edit. T2 7871ed6 was on the branch.

### Part a

- R3a declarations: none (the plan allows none). The new cases reuse Task 1's `withBundle`, `drainingCA` and `useBundle` and Task 1's `seedDrainOld` and `drainAt`; their setup lives in closures inside TestHostCertStep (`drainingHost`, `byOld`, `pastEnd`, `installedByOld`), TestProbeStep (`drainingProbeHost`, `byOld`, `committedByOld`, `pastEnd`) and TestAdopt (`caLine`).
- R3a RED, from a detached worktree of R3a (which holds T2), the plan's verify command with the FAIL and control lists as measured (deviation below): exactly 11 `--- FAIL:` lines, no build or setup failure, no timeout, no `want active, next or retired`, no FAIL outside TestHostCertStep, TestProbeStep and TestAdopt. FAIL: TestHostCertStep, `hostcert_answer_draining_ca_accepted`, `hostcert_kept_cert_of_draining_ca_kept_until_due`, `hostcert_kept_cert_of_drained_ca_replaced`; TestProbeStep, `probe_pair_draining_ca_kept`, `probe_pair_drained_ca_unusable`, `probe_pair_expires_before_drop`; TestAdopt, `adopt_next_user_ca_ok`, `adopt_draining_user_ca_ok`. Each failure is the test's assertion: the hostcert leaves at `an answer signed by the draining host CA key before its end: ... want it installed` (hostcert_test.go:464, :500, :508; the answer was refused, back-off deferred), the probe leaves at `a pair signed by the draining machine CA key before its end: ... want both kept` (probe_test.go:413, :419, :434; `LastCode:ca_not_trusted`), the adopt leaves at phase2_layout_differs `... which is not the active user CA key of trust bundle version 2` and `... version 3`.
- R3a controls (8) passed on R3a: TestHostCertStep/`hostcert_answer_drained_ca_refused` (main's active-or-next set refuses the draining key too, with the same `answer_unpinned_ca`), the three 03-12b cases `hostcert_answer_aborted_ca_refused`, `hostcert_answer_next_ca_accepted`, `hostcert_kept_cert_of_aborted_ca_replaced`; TestProbeStep/`probe_pair_aborted_ca_refused`, `probe_pair_next_ca_kept` (03-12b); TestAdopt/`adopt_drained_user_ca_refused` and `adopt_retired_user_ca_refused` (main accepts the active key only).
- T3a: apply/hostcert.go and apply/probe.go loop over `trust.TrustedCAs(bundle, trust.RoleHost, st.now)` and `trust.TrustedCAs(bundle, trust.RoleMachine, st.now)`; `Adopt(l, v, hostGroup, now)` with its one caller passing `e.clock.Now()`, and `isTrustedUserCA(b, pub, now)` over `trust.TrustedCAs(b, trust.RoleUser, now)`; the difference text keeps `which is not the active user CA key of trust bundle version %d` and gains `(nor a next or still-trusted draining one)`; internal/agent/hostcert/hostcert.go: the `Action.Code` comment lists `untrusted_ca` (03-12b's review nit), and the Due and Decide comments say the agent passes the host CA keys trusted at the run's clock. `krl.RoleCAKeys` and its callers are unchanged.
- Carried-forward duty (03-12b review): `hostcert.Due` keeps its membership check, now against the time-aware set. Proven by `hostcert_kept_cert_of_draining_ca_kept_until_due` (a draining CA's certificate is kept 30 minutes into the window, no request) and `hostcert_kept_cert_of_drained_ca_replaced` (past the end, a certificate that is otherwise not due, far from ValidBefore and RenewAt with the directory's principals and no revocation, is replaced: one request; the report names keys, not codes, so `untrusted_ca` is shown by elimination, as the case's comment says), beside 03-12b's `hostcert_kept_cert_of_aborted_ca_replaced` for a retired one. The empty set stays fail-closed (hostcert.Due unchanged).
- `hostcert_answer_drained_ca_refused` uses an end two minutes after the clock's start, and asserts that the request is still live (`now < CreatedAt + RequestTTL`) when the answer is read past the end and that the refusal code is `answer_unpinned_ca`, so the refusal is the CA's and not the request's age.
- T3a verify (part a; the plan's combined verify runs after T3b): go vet ./..., gofmt, the internal/agent/hostcert and internal/agent/probe packages, TestAdopt, TestDrift, TestStatus and the seven-case TestHostCertStep and five-case TestProbeStep runs with -race, then TestCheckTrust, TestStatus, TestStale, TestAdopt, TestDrift, TestProbeStep and TestHostCertStep whole (63.854 s), capslock-check, dep-firewall, golangci-lint (0 issues): all ok. `git diff --name-only R3a T3a -- '*_test.go'` is empty; both call sites carry the exact arguments.
- Capslock after T3a: keyroster-signer 94 (baseline 97, the same three pairs no longer reported), keyroster-agent 37, keyroster-agent-fetch 23. No new pair.
- R3a and T3a pushed (7871ed6..99cf4ec), after a scan of the added lines for private terms, lab host names and dotted quads (none).

#### Part a mutants

Each mutant was applied to the working tree at T3a by a script that requires its anchor to match exactly once, `go vet ./internal/agent/apply/` exited 0, the plan's command ran with `-timeout 5m` (`-v` added), the file was restored with `git checkout -- <file>`, its sha256 compared equal with the pre-mutant value (full hash compared; first 16 hex digits shown), and `git status --short` listed no code path. The three unmutated commands passed first. No build or setup failure and no timeout.

| Mutant | Mutation | Killed by (named) | sha256 (before = after) |
|---|---|---|---|
| M221 | hostcert.go the host answer set is `trust.IssuingCAs(bundle, trust.RoleHost)` again | TestHostCertStep/hostcert_answer_draining_ca_accepted, hostcert_kept_cert_of_draining_ca_kept_until_due (also hostcert_kept_cert_of_drained_ca_replaced, at its setup) | da93def1aa4a33c6 |
| M222 | hostcert.go the host answer set takes every non-retired host entry | TestHostCertStep/hostcert_answer_drained_ca_refused, hostcert_kept_cert_of_drained_ca_replaced | da93def1aa4a33c6 |
| M144 | probe.go the machine answer set takes every non-retired machine entry | TestProbeStep/probe_pair_drained_ca_unusable | 3054ddaf2bae49d0 |
| M148 | adopt.go `isTrustedUserCA` takes active user entries only | TestAdopt/adopt_next_user_ca_ok, adopt_draining_user_ca_ok | f791d6caedb03c77 |
| M223 | adopt.go `isTrustedUserCA` accepts a draining user entry whatever its end | TestAdopt/adopt_drained_user_ca_refused | f791d6caedb03c77 |

M222, M144, M148 and M223 replace the `TrustedCAs` call by a `slices.DeleteFunc` over a clone of the bundle's entries, so every mutant compiles.

Full sha256 of each mutated file before the mutant and after the restore (equal to its blob at T3a):
- internal/agent/apply/hostcert.go da93def1aa4a33c6a34f7f8d0d5bac256986e0dd989e50845853c375d58428c0
- internal/agent/apply/probe.go 3054ddaf2bae49d00613866124a93f3ec78b227f81ee21ce5cfd3e3ce7d580d3
- internal/agent/apply/adopt.go f791d6caedb03c776f11d4a3121b177c9ab07b2452602dd5d1abfca98054fe97

### Part b

- R3b declarations: internal/agent/heartbeat/heartbeat.go `type BundleBehind struct` (json `manifest_bundle_version, accepted_version, since, reason`) and `Status.BundleBehind *BundleBehind` (json `bundle_behind,omitempty`, right after `Unapplied`), Validate unchanged; internal/agent/apply/behind.go with the stub `(*engine) bundleBehind(*state.Stored, time.Time, bool) *heartbeat.BundleBehind` (nil, parameters named `_`); drift.go `DriftReport.BundleBehind *heartbeat.BundleBehind` (json `bundle_behind,omitempty`). Test helpers: harness_test.go `fixture.manifestBundle` (zero means 1, used by `krlWithHeader` for the manifest's `BundleVersion`) and `(*testHost).publishKRLNaming(bundle, serials...)`; behind_test.go `behindHost`, `behindRecord` (the record's bytes, nil when absent) and `sawManifest` (offers a KRL naming a bundle, applies it, returns the clock before and after).
- `TestBundleBehind/absent_when_nil` pins the pre-03-12c encoding of the full status by SHA-256 (`ace03ad4dfd6d96c...`), taken with a throwaway print test at T3a 99cf4ec before the field existed (the throwaway file was deleted and never staged).
- R3b RED, from a detached worktree of R3b (which holds T3a), the plan's verify command unchanged: exactly 12 `--- FAIL:` lines, every named one present, `BEHIND:` in the log, no build or setup failure, no FAIL outside TestBundleBehind and TestBehind. Each failure is the test's assertion: the heartbeat leaves at `<nil>, want heartbeat_field_invalid naming bundle_behind.<field>`, the TestBehind leaves at `BEHIND: ... <nil>, want ...` (the setup steps all held: the unapplied record named bundle 2, the refused bundle 2 left bundle 1 accepted).
- R3b controls (5) passed on R3b: TestBundleBehind/`optional_roundtrip`, `absent_when_nil`, `no_cross_field_rule` (the field exists and Validate has no rule); TestBehind/`behind_within_grace_quiet` and `behind_older_manifest_quiet` (the stub reports nothing and writes no record).
- T3b: heartbeat.go Validate checks `bundle_behind` when set (both versions at least 1, `since` in trust's timestamp format, the reason from `BehindReasons()`, each failure naming `bundle_behind.<field>`, no rule against the versions in force); `BehindReasons` is an exported function returning a fresh slice (the plan says "an exported BehindReasons"; a function keeps importers from changing the closed set). behind.go: `behindFile` (`bundle-behind.json`), `maxBehindFile` (4 KiB), `bundleBehindGrace` (2 h), the record type `behindDoc` (named so because R3b's test helper already took `behindRecord`; T3b changes no test), `bundleBehind`, `behindReason`, `readBehind` (spool.ReadFileAtInfo on the state fd, 0600 regular file of the effective uid, strict canonical JSON, a version of at least 1 and a since in trust's format; anything else counts as absent and only restarts the grace) and `writeBehind` (through `e.writeState`); the record is removed through `e.remove` (paths.Allowed). status.go: `buildStatus` sets `s.BundleBehind = e.bundleBehind(st, now, true)` beside the manifest parse; drift.go: trustReport sets `r.BundleBehind = e.bundleBehind(st, now, false)` (reads only). cmd/keyroster-agent/check.go is not changed: Task 2's usage text covers the draining fields, and bundle_behind's report-only status is in the DriftReport comment; Task 4's runbook section names it for operators.
- T3b verify (Task 3's combined command): go vet ./..., gofmt, `go test -race` of ./internal/agent/... (apply 635.773 s), ./internal/server/ (171.275 s) and ./internal/serverclient/, go build of keyroster-agent and keyroster, the windows and darwin builds of cmd/keyroster and the heartbeat package, capslock-check, dep-firewall, testonly-firewall and golangci-lint (0 issues): exit 0. A comment of `bundleBehindGrace` was then reworded (the grace's fit to a fleet is unverified), and gofmt, go vet and golangci-lint of ./internal/agent/... ran again (0 issues) before the commit. No stray binary in the repository root.
- Capslock after T3b: keyroster-signer 94 (baseline 97, the same three pairs no longer reported), keyroster-agent 37, keyroster-agent-fetch 23. No new pair.
- Commit checks (Task 3's last verify): no test changed between R3a and T3a or between R3b and T3b; both call sites carry `trust.TrustedCAs(bundle, trust.RoleHost, st.now)` and `trust.TrustedCAs(bundle, trust.RoleMachine, st.now)`; no added line of internal/ from R3a to T3b holds the private-term word. R3b and T3b pushed (99cf4ec..52ee3f1) after the added-line scan (none).

#### Part b mutants

As for part a: anchored script, `go vet ./internal/agent/apply/ ./internal/agent/heartbeat/` exit 0, the plan's command with `-timeout 5m` (`-v` added), `git checkout -- <file>`, sha256 equal before and after, `git status --short` with no code path. The two unmutated commands passed first. No build or setup failure and no timeout.

| Mutant | Mutation | Killed by (named) | sha256 (before = after) |
|---|---|---|---|
| M146 | behind.go the manifest's version is not compared with the accepted one (`named == 0` instead of `named <= st.BundleVersion`) | TestBehind/behind_older_manifest_quiet, behind_clears_when_accepted | 8568c45821d7a9be |
| M147 | behind.go no grace (`false &&` on the grace test) | TestBehind/behind_within_grace_quiet (also withheld_switch_bundle_behind_reported, at its in-grace status) | 8568c45821d7a9be |
| M225 | behind.go since is now on every status build (the record's since ignored) | TestBehind/behind_since_is_kept, withheld_switch_bundle_behind_reported (also five more leaves: with since always now, nothing passes the grace) | 8568c45821d7a9be |
| M226 | behind.go the record is not removed once the manifest names no newer bundle | TestBehind/behind_clears_when_accepted | 8568c45821d7a9be |
| M227 | behind.go the unapplied record is not consulted for the reason | TestBehind/behind_reason_unapplied | 8568c45821d7a9be |
| M224 | heartbeat.go Validate accepts any reason | TestBundleBehind/reason_outside_the_set_refused | 533bd54e4ea85e1a |

Full sha256 of each mutated file before the mutant and after the restore (equal to its blob at T3b):
- internal/agent/apply/behind.go 8568c45821d7a9be4280054707cb8604678f4795f26c6d823a35c3dbe077d481
- internal/agent/heartbeat/heartbeat.go 533bd54e4ea85e1ad88ab476b7bb4f670cf7c1a8613aa45eafc8eaea5ec1a793

## Task 4

- Precondition: T3b on the branch, `git fetch origin` (origin/main still 335af53) and Task 1's stop guard: exit 0.
- R4 declaration: `GenerationFact.TrustedUntil string` (internal/doctor). Test helpers: internal/trust helpers_test.go `seedRotUser1` to `seedRotUser5` (P-256 seeds 40 to 44) and `goldenRotationBundle(t, policy)`; vectors_test.go `rotationCAFileAt` (2026-10-06T00:00:00Z), a `text` flag on the vector table (a text vector ends in one newline but not in `}`) and `errNotPlain`. The vector files and the golden were generated on the R4 tree from the finished T1a output (`go test -run TestGoldenVectors -update ./internal/trust/`, `go test -run TestSummaryGolden -update-golden ./internal/rootceremony/`); the update left `bundle_genesis_v1.json`, `policy_genesis_v1.json` and the three existing summary goldens byte-identical (`git status` listed only the three new files). The three new files were read in full before the commit, and the CA file vector was cross-checked against the bundle vector (user g3, g4, g5, then machine g1, one plain line each).
- `bundle_rotation_v1.json` carries the log key's `origin` (`keyroster/log/...`), as the genesis vector does: data computed by `trust.LogOrigin`, not a Go literal, so Task 1's `"keyroster/` scan (Go code of S0 to T1b) and 03-14d's duty are not touched.
- R4 RED, from a detached worktree of R4, the plan's verify command unchanged: exactly 3 `--- FAIL:` lines (TestDoctorGenerations, `draining_shows_trusted_until`, TestDoctorDrainingTrustedUntil), each at its assertion (`the generations line lacks "draining g1 SHA256:aaa until 2026-10-20T00:00:00Z": OK generations: user draining g1 SHA256:aaa, active g2 SHA256:bbb` and the same for the signer's line); no build or setup failure, no timeout.
- R4 controls (all passed on R4): TestDoctorGenerations/`other_states_show_none` (no state prints an end yet); TestGoldenVectors/`bundle_rotation_v1.json` and `user_ca_keys_rotation_v1.txt`, FuzzParseBundle's seeds and TestSummaryGolden/`draining` (built from T1a's output); the eight TestCATransitions cases `draining_unchanged_ok`, `draining_kept_with_next_added_ok`, `draining_trusted_until_changed_refused`, `draining_to_retired_refused`, `draining_to_active_refused`, `active_to_draining_refused`, `new_draining_refused`, `draining_removed_refused` (03-12b's rule already compares whole entries); TestCheckBundleKeysGenerations/`draining_parsed_bundle_refused` and `draining_successor_refused_by_the_chain_rule` (03-12b's refusals: `ErrBundleKeys` naming 03-12e, and `ErrVersionChain` with `a new entry must be next` and nothing written).
- T4: internal/doctor/doctor.go prints ` until <TrustedUntil>` after the fingerprint for a draining generation with an end, and the GenerationFact comment says what TrustedUntil is; cmd/keyroster-signer/doctor.go `generationFacts` sets TrustedUntil from a draining entry; docs/runbooks/host-setup.md gains `## CA rotation: what the agent does` after `## Drift` (the upgrade order, the drop, what `check` reports for `draining`, `trust_expired`, `trust_latch` and `bundle_behind`, and that none changes the exit status; read-only commands only, no signer path, the latch file not named) and three bullets in `## Drift`; cmd/keyroster-agent/check.go's usage text also names `bundle_behind` (deviation below).
- T4 verify (Task 4's second command): go vet ./..., gofmt, internal/trust, internal/rootceremony and internal/doctor with -race, the two signer cases, the whole cmd/keyroster-signer package (37.192 s), the six runbook and ceremony cases of cmd/keyroster, FuzzParseBundle for 30 s (1,951,358 execs, no failure, no input written), the windows and darwin builds of internal/trust, internal/rootceremony and internal/doctor, go build of keyroster-agent and golangci-lint (0 issues): all ok. The stray `keyroster-agent` binary that `go build` left in the repository root was deleted. After the run, one runbook sentence was corrected (the `not_accepted` example) and the six cmd/keyroster runbook cases ran again (ok) before the commit.
- Task 4's third verify (commit checks): no test, vector or golden changed between R4 and T4; the added runbook lines do not name `/var/lib/keyroster-signer`, never pair the latch file with a command that changes it (the file is not named at all), and hold no private-term word or dotted quad. R4 and T4 pushed (52ee3f1..898b198) after the added-line scan (none).
- UNVERIFIED (stated in the section and the PR): the section's steps on a real host, the fleet upgrade order, and the drop against a real sshd (this plan has no e2e; the switch plan's TestCARotationNoFailedLogin is the end-to-end proof).

### Task 4 mutants

As in Task 3. The unmutated commands passed first.

| Mutant | Mutation | Killed by (named) | sha256 (before = after) |
|---|---|---|---|
| M228 | doctor.go the end is not printed (`false &&`) | TestDoctorGenerations/draining_shows_trusted_until, TestDoctorDrainingTrustedUntil | d73678ac92a93fd9 |
| M229 | castate.go checkRoleTransition compares entries without their trusted_until | TestCATransitions/draining_trusted_until_changed_refused | 58cd42fbca1e7b38 |
| M230 | castate.go the abort branch also accepts `old.State == "draining"`, compared against `aborted` with `TrustedUntil = ""` | TestCATransitions/draining_to_retired_refused | 58cd42fbca1e7b38 |
| M231 | castate.go an added entry may be draining | TestCATransitions/new_draining_refused | 58cd42fbca1e7b38 |
| M232 | castate.go a state change to or from draining is accepted | TestCATransitions/draining_to_active_refused, active_to_draining_refused (also draining_trusted_until_changed_refused, draining_to_retired_refused) | 58cd42fbca1e7b38 |

- M228 ran as one `go test -run "^(TestDoctorGenerations|TestDoctorDrainingTrustedUntil)$" ./internal/doctor/ ./cmd/keyroster-signer/` after `go vet` of both packages, instead of the plan's two commands joined by `&&`, so that the second killer runs although the first fails; both killed it.
- M231's second named killer, TestCheckBundleKeysGenerations/draining_successor_refused_by_the_chain_rule, is not in the plan's mutant command (TestCATransitions only); it was run once more against M231 (`go vet ./internal/trust/ ./internal/signer/`, then `-run "^TestCheckBundleKeysGenerations$/^draining_successor_refused_by_the_chain_rule$" ./internal/signer/`): killed; castate.go restored, sha256 58cd42fbca1e7b38 before and after.

Full sha256 of each mutated file before the mutant and after the restore (equal to its blob at T4):
- internal/doctor/doctor.go d73678ac92a93fd97aa7005f62a2bb5502a0f2a9572780260691c51c00e9fad9
- internal/trust/castate.go 58cd42fbca1e7b388fff3458ab61587bf4250f9ea3daace888207b089d8d8dea

## Task 5

- Stop guard and base values: re-run in this session before the plan commit and again before the push (`git fetch origin`, origin/main still 335af53): `STOPGUARD_OK` and `BASEVALUES_OK` (ROADMAP `34/42 plans executed in 41 waves`, Progress row `34/42`, the unticked 03-12c row, STATE `total_plans: 77`, `completed_plans: 69`, `Plan: 34 of 42`).
- Test-time base, re-measured first in this session on origin/main 335af53 in a detached worktree outside the repository (removed afterwards), and replaced in place (one line): signercmd 55.139 s, apply 616.365 s, at=1794848954. The signercmd figure is above the three earlier readings (40.797 to 51.0 s) because the staged plan diff was read and the plan commit made while that run was under way (light git work, no build or test job, but not strictly "nothing else running"; see Deviations).
- The plan commit (`docs(03-12c): plan out the CA rotation readers`): the plan file was staged by path and its whole staged diff (917 lines, against the early plan) read in full, in several reads covering every line, after the last edit (the file had no edit afterwards); the plan file has no CR; its scans (private terms, lab host names, dotted quads, design-review labels) found nothing.
- Test-time delta gate (same session as the base, run right after it, nothing else running): signercmd 48.559 s (-6.580 against 55.139), apply 565.352 s (-51.013 against 616.365); both far inside the +90 s cap; pass.
- Full gate (main checkout at aacf9dd): `go test -race -count=1 -timeout 15m ./...` (36 packages ok; cmd/keyroster 320.273 s, cmd/keyroster-signer 51.905 s, apply 668.359 s, pass or fail only), `go vet ./...` and with each e2e tag set (e2e; e2e e2erotation; e2e e2eprobe e2emachine; e2e systemdsmoke; e2e_pkcs11; e2e_tpm), `bash -n test/systemd/smoke.sh`, gofmt, golangci-lint (0 issues), capslock, dep-firewall, testonly-firewall (6 GOOS and tag combinations), check-pinned-actions (55 references), and the windows and darwin builds of cmd/keyroster, internal/rootceremony, internal/trust and internal/doctor: exit 0 in 847 s. No stray binary in the repository root.
- Capslock at the end: keyroster-signer 94 pairs (baseline 97: the three ARBITRARY_EXECUTION pairs of internal/directory, internal/sshsig and internal/trust are no longer reported, as at 335af53 before any edit), keyroster-agent 37 (baseline 37), keyroster-agent-fetch 23 (baseline 23). No new pair at T1b, T2, T3a, T3b or at the end; no baseline edited (the check accepts a reduction; tightening it is for a reviewed change of its own).
- Tracking (GSD `state.advance-plan`, `state.update-progress`, `roadmap.update-plan-progress 03`; no other tracking command, and `requirements.mark-complete` not run): ROADMAP `35/42 plans executed in 41 waves`, Progress row `| 35/42 |`, and only the 03-12c row ticked (three lines changed, `git diff --numstat` 3 3; the ROADMAP gate's intended file, built from origin/main's by awk, is identical); STATE `total_plans: 77`, `completed_plans: 70`, `Plan: 35 of 42` (the tool also set `last_updated` and `state_head`). `progress` 70/77, 17%.
- Publish scans (before the SUMMARY was added): the plan file and the 3,940 lines the branch adds hold no private term, lab host name, design-review label or address other than loopback; the 14 commit messages and the PR text hold none; the PR title passes `scripts/check-pr-title.sh`. Authorship: all 14 commits are authored as Daniel and committed by keyroster-bot with a signature and no attribution line. No other plan file, no landed SUMMARY, no file under cmd/keyroster/testdata, no workflow, ruleset or CONTRIBUTING line changed; the plan's wave (34) and depends_on (`["03-12b"]`) are unchanged; the ruleset still lists 30 checks. Every file the branch changes is in the plan's files_modified list.
- Threat-ID and mutant-number checks: T-03-439 to T-03-443 and M208 to M232 were free on origin/main at Task 1, and T-03-81, T-03-414, T-03-418 and T-03-429 were defined only in the early plan; no renumbering.
- The final head's whole-module and CI results, the check run IDs and the house e2e gate (MODE=pr) readings are in the PR description (see "PR and CI").

## Reconcile ledger at execution

The plan's ledger holds at 335af53 with these differences: main had moved from 015d26e to 335af53 (PR #106, dependency bumps only; recorded in the plan; the signer's capslock count is 94 there); R3a's RED has 11 FAIL lines and 8 controls (Deviations); cmd/keyroster-agent/check.go also names `bundle_behind` (Deviations); every code anchor of Task 1's precondition matched.

## Deviations from Plan

- cmd/keyroster-agent/check.go: Task 3's action says its usage text "already names the field (Task 2)", but Task 2's text names `draining`, `trust_expired` and `trust_latch` only. T3b changes no test or file outside its list, so T4 adds `bundle_behind` to the same paragraph (report only, not counted by the exit status), which OQ-D's decision requires the usage to say. A wording change only; no test pins the text.

- R3a's RED has 11 FAIL lines, not the plan's 8, and 8 controls, not 11. The plan lists `hostcert_kept_cert_of_drained_ca_replaced`, `probe_pair_drained_ca_unusable` and `probe_pair_expires_before_drop` as controls that pass on both sides. Each needs a certificate or pair signed by the draining key installed or kept before the end (a kept certificate of a draining CA, a pair in use of a draining machine CA, a pair of the draining key that expires before the drop); main's active-or-next set refuses that answer, so on R3a the setup cannot exist and the case cannot pass without dropping its setup assertion, which would make it vacuous. The setup assertions are kept, the three cases fail on R3a at them (the lines above), and they pass on T3a; M222 and M144 bite the first two. The RED was run with the plan's verify command and these three names moved from the PASS list to the FAIL list and the count set to 11; everything else in the command is the plan's. No code was bent to fit.

- Validate's text for an unparsable end is `cas[i] (role): trusted_until: "<value>" must be RFC 3339 UTC with whole seconds (<TimeFormat>)`. The plan says "the checkTimestamp error wrapped under `trusted_until:`"; wrapping checkTimestamp's own error verbatim would print `issued_at` inside a trusted_until refusal, so the text applies checkTimestamp's rule with its own field name. The test pins the `cas[0] (user): trusted_until:` prefix.
- TestCANextTracer: the `active_changed` leg now also requires exit 1, where it used to accept any non-zero exit; the plan specified exit 1 for the `second_next` leg only. The table form of the loop applies one exit check to both legs, and install-bundle exits 1 for every refusal (commands.go dispatch).
- renderTrust returns UserCAKeysFileExcept's error unwrapped: that error already reads `the bundle's <role> CA key generation <N>: ...`, which holds the old text, and wrapping it again would repeat it.
- [Rule 1, T-03-443] Run's check closure sets `trustExpired` for `trust_expired`, and the next round applies it only while `failedAt` is zero or once Retry has passed (`trustNow` in run.go). As written at T2 the closure set `forceApply` only while `failedAt` was zero; the PR #107 review fix moved that guard into the round's trigger, so the round also applies with no document in the spool, under the same rule. The ERROR line is logged at every such check either way. The plan says "sets forceApply = true ... whenever d.TrustExpired is not empty". Run clears `nextCheck` after every apply round, so a check runs right after an apply that failed at the end; when that failure leaves the drained line in current (a crash before the swap, a refused candidate), Check reports `trust_expired`, the next iteration applies, fails and checks again: an apply every iteration, the load T-03-443 rules out ("Run's retry (`failedAt`, Retry) governs"). Evidence: with the closure written as the plan words it, TestRunTrustDue/`trust_due_error_backs_off` (an apply that crashes at the marker past the end, Retry an hour) failed on the T2 tree with `TRACER: after the failed apply at the end: iteration 0: 3 applies, want 2`; with the guard it passes. After a successful apply (the operator's `--recover-to-last-good` case, `recover_to_last_good_then_drop_again` and `trust_expired_sets_force_apply`) the next round still applies at once. The probe-pair `forceApply` is unchanged. The test uses a marker crash, not the plan's example of a stalled sshd: with a stall the rollback keeps the narrowing, current lacks the line, and the loop never reaches this path. **Resolved (orchestrator decision, 2026-11-16): the guard stays, and the code is not changed.** The plan's wording ("whenever d.TrustExpired is not empty") conflicts with T-03-443 ("Run's retry (`failedAt`, Retry) governs"); the evidence is the `iteration 0: 3 applies, want 2` failure above. While an apply is failing, Run's retry branch (run.go:253, `time.Since(failedAt) >= rc.Retry`, DefaultRetry 60 s) re-applies anyway, so the guard only replaces an apply on every iteration with one per Retry, which is what T-03-443 requires; after a successful apply the T-03-414 heal (M220) still forces the next round at once. The PR body states this in one line. Every check also arms the draining timer from the accepted bundle (PR #108 review, `acceptedTrustDue`); the end it arms is strictly after the check's clock, so an end that has passed stays under this rule.
- The latch reader also refuses keys that are not sorted by fingerprint or repeat one (the output contract says sorted; the agent writes them so), which makes such a file unreadable: fail closed, one more reason under `non_canonical` in spirit. Not named in the plan's reader list.

- **[Rule 3] Base measured with light work alongside (Task 5).** The re-measure of the test-time base overlapped a read of the staged plan diff and the plan commit. The signercmd base (55.139 s) is therefore higher than the earlier readings, which only widens the delta gate's margin; the delta gate itself ran with nothing else running and read 48.559 s against it. The apply base (616.365 s) sits inside the earlier readings (590.181 to 598.542 s at 335af53 in other sessions, 649.777 s at 03-12b's base).
- **No pair changed in capslock.** The signer's count is 94 against the baseline's 97 at 335af53 before any edit and at every task; the plan's prediction ("none") holds, and the baseline was not edited.
- **STATE `stopped_at` is stale.** It still reads `Completed 03-12-PLAN.md (PR #102 open, merge gate pending)`; the plan's STATE gate checks only the three counts, and the task allows only the three tracking commands, so `state.record-session` was not run.
- **The review did not run before the merge**: PR #107 was merged as fefd624 first, and the review ran on fefd624 afterwards (see "Review (after merge)").

## What stays UNVERIFIED

The drop against a real sshd (a drop is a narrowing, and this plan has no e2e: 03-12e's TestCARotationNoFailedLogin is the end-to-end proof); the runbook text of host-setup.md on hosts and the fleet upgrade order; the 2-hour grace in a fleet; the host-certificate step's reaction to a draining host CA's end on a real host; Windows OpenSSH; the repair of an unreadable drop latch from a backup (host-setup.md) on a real host.

Residuals, stated and unchanged by this plan: a stopped agent narrows nothing; a wiped state directory loses the latch; the agent's answer sets, the CLI and login have no latch, so they trust a drained CA again while a clock is set back; a forward jump of the host clock drops the drains under way early and for good (the owner accepted this); root itself can edit the latch and the since record; a server that withholds bundles and publishes no newer manifest shows only through `krl_stale`.

## Review (after merge)

PR #107 was squash-merged to main as fefd624 before its pre-merge review ran. The review then ran on fefd624 (run wf_bd2e9061-d8e): two Opus lenses (one on the agent side, one on the format, the docs and doctor), one Codex lens at high, and Sonnet skeptics. Four issues were confirmed, one was split and is folded into the first because it has the same cause, and one was refuted. The fixes are one follow-up PR from branch `p03/12c-review-fixes`, each issue as old → new:

- **A due drop and a capture that does not verify.** Old: when the spool's capture did not read or did not verify, the apply returned before the narrowing, so a draining CA past its end stayed in `user_ca_keys` for as long as every capture failed. New: forward lands the due drop from the accepted state alone (`dropDue`: `state.KRLAlone` against an empty capture, `candidate`'s render and latch, bounded by current, current's KRL files byte for byte, one narrowing swap, self-test, commit) and still returns the capture's error; with an unapplied record ahead, the accepted bundle decides. `Report.TrustDue` is now kept after a failed run (the plan's "an apply that returns an error clears it" is reversed), so the next end is armed while captures keep failing. Tests d04ba31, fix 59f238e.
- **A due drop and an empty or unreadable spool** (the split issue, folded into the one above). Old: Run applied only while the spool listed a document, so the timer and `trust_expired` did nothing with an empty or unreadable spool. New: the timer and the check's `trust_expired` apply whatever the spool holds; after a failed apply Retry still governs the check's trigger (T-03-443); a host that is not installed still does nothing. Tests d04ba31, fix 59f238e.
- **The repair of an unreadable drop latch.** Old: host-setup.md said only to restore the record from a backup and never to edit or delete it, without naming the file, its mode or owner, or a path without a backup. New: it names `/var/lib/keyroster-agent/trust-dropped.json`, the `install -m 0600 -o root -g root` restore of that one file, and the repair without a backup (stop the applier, check the clock, remove the file; the next render records every key past its end again, pinned by `removed_latch_written_again_by_next_render`), and Run logs `ERROR trust_latch` on every check. Tests eecfe72, log line 722d202, runbook 38f840d.
- **A `bundle_behind` since after now.** Old: a recorded since ahead of the clock kept `bundle_behind` quiet for the time the clock was off plus 2 hours. New: it counts as unreadable, the grace restarts with since = now and the status build rewrites the record. Tests 976fdf5, fix d4656ca.
- **The latch's 64 KiB bound in tests.** Old: the oversize row was refused as non-canonical anyway, so a removed or raised read bound passed, and the write-side bound had no case. New: the row is a canonical, parsable latch just over the bound, and a record that would pass the bound fails and leaves the latch unchanged. Tests 13cd419.
- Refuted (the latch's capacity): the latch holds about 600 keys within its 64 KiB bound; more draining entries need a root-signed bundle.

A narrow check after these fixes (two Opus skeptics on the first two issues, one Sonnet pass on the rest) found the remaining path; the fixes are on the same branch and PR #108, each as old → new:

- **R1: a due drop and a generation the host refuses.** Old: when the capture verified but the host refused its generation (a KRL that validate refuses, a refusal with no KRL-alone pass, or a KRL-alone pass that does not verify), forward returned before any narrowing, so a draining CA past its end stayed in `user_ca_keys` for as long as the spool held that capture. New: those returns go through `dropDue` too: the drop lands from the accepted state with current's KRL byte for byte, the refusal is still returned, and the discarded candidate's generation number is not allocated again. Tests 39e4e31, fix 97c4e03.
- **R2 and R3: the draining timer.** Old: Run armed the timer only from `Report.TrustDue`, which an apply that fails before its lock (sshd -T, pins, LoginGraceTime, host keys) leaves zero, and a restart with an empty spool runs no apply, so the end was caught only by the periodic check. New: every check arms the timer from the accepted bundle's next end after now (`acceptedTrustDue`), whatever the apply or the check returned; an end that has passed is never armed again (T-03-443 unchanged). Tests 442c03c, fix 01bd0f6.
- **R4: tests that pin claims already made.** Old: no case showed that a drop from the accepted state never adds a principal line, keeps an unreadable latch as it is while blocking every draining entry, lands when a capture chained from an unapplied record does not read, or leaves the drop-in, host certificates and takeover plan alone; the empty-spool timer case did not say that it never reaches `dropDue`. New: four cases and a comment, each case killing its own mutant. Tests 7fb2486.
- **R5: docs and comments.** Old: `dropDue`'s comment said it removes only due draining lines; host-setup.md's backup restore did not stop the applier or check the clock, did not say the path is the default `--state-dir`, and the `bundle_behind` `since` sentence predated the fix above for a since after now; this SUMMARY described the T2 `forceApply` guard and the latch's capacity as a scenario. New: the comment says it removes every CA and principal line current holds that the accepted render omits (97c4e03); the runbook stops the applier on both repair paths, puts the clock warning on both, names the state directory and the `since` restart, and says when a drop waits (29463cd); this SUMMARY is updated here.
- **Known limitation, kept on purpose.** While the drop-in on disk is not the agent's, a due drop waits at every route: a preflight refusal returns before any narrowing, and `dropDue` returns its cause unchanged (see S1 below). On an installed host the preflight runs only while the drop-in is not the agent's, and its refusals name a configuration in which sshd may not read the agent's files, may not take its keys, or cannot be self-tested; `dropDue` never writes the drop-in, so it would commit as last-good a generation running under a drop-in the agent did not write, and a narrowed `user_ca_keys` is not known to narrow what sshd trusts. The drop lands with the next apply that goes through, which rewrites the drop-in, as every KRL does; `check` reports the drop-in's drift and `trust_expired`. apply.go says so at the preflight call and in `dropDue`'s comment.

A second narrow check found one more route; the fix is on the same branch and PR #108:

- **S1: a due drop under a drop-in the agent did not write.** Old: `dropDue` could still be reached while the drop-in on disk was not the agent's, through a capture that does not read or verify, or a generation the host refuses, and then committed the narrowed generation as last-good under that drop-in and removed `dropin.prev`; only the preflight route waited. New: `dropDue` returns its cause unchanged while the drop-in is not the agent's (`dropInIsWanted`, the comparison the preflight makes): it only reads and compares the drop-in and never repairs it. When the host refuses the KRL of a rendered generation, forward's own render has latched the key before that, as before; the drop itself writes no latch. Tests eab4441, fix 7ddcf54.

## Self-Check

Self-Check: PASSED (the eight created files exist; the thirteen commits S0 to T4 and the plan commit (fourteen in all) are ancestors of HEAD; the plan's files_modified list covers every file the branch changes).
