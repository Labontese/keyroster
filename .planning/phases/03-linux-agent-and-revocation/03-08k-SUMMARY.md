---
phase: 03-linux-agent-and-revocation
plan: 08k
subsystem: agent
tags: [agent, apply, state, krl, revocation, ops-key, d-r2]
status: draft
---

# Phase 3 Plan 08k: KRLs across an ops-key change, Summary (draft)

DRAFT: completed task by task; Task 4 finishes it.

## Base

- Branch `p03/08k-agent-krl-signer` from origin/main at 6572649 (`chore(scripts): wait for the owner's squash merge in merge-gate.sh (#79)`). The plan was reconciled against ae754a3; 6572649 is ae754a3 plus #79, which changes scripts/merge-gate.sh, CONTRIBUTING.md, 01-SKELETON.md, STATE.md and a quick-task's plan and summary, and no Go code. Every anchor the precondition names was found on 6572649. Because #79 is already on main, Task 5's possible STATE.md conflict with it cannot occur.

## Test time (internal/agent/apply under -race, locally in WSL)

| Point | Alone (limit 400 s) | Under `./...` (limit 480 s) |
|-------|---------------------|-----------------------------|
| Task 1 base (origin/main 6572649, before any edit) | 355.5 s | 341.2 s |
| Task 2 (the tree committed as 7cc88f7) | 310.1 s | 317.4 s |
| Task 3 (the tree committed as 0767bbf) | 285.4 s | 309.6 s |

- CI on origin/main 6572649: 126.1 s (workflow run 41446523949, build-test job 125280885778, "Test (race detector)" step). Read with `scripts/gh-as-bot.sh run view 41446523949 --job 125280885778 --log`, grepping for `internal/agent/apply`.
- No figure is above its limit, so the stop rule did not apply. The alone base is higher than 03-08j's 280.2 s on the same code; it leaves 44.5 s to the 400 s limit, which is the tighter of Tasks 2 and 3's two bounds (alone base + 120 s = 475.5 s).

## Task 1: the successor rule

Commit 9c214b3 `fix(agent): let a fully verified successor's ops key authorise a KRL`.

### RED (on 6572649 with the tests added, locally in WSL, `go test -race -count=1 -v`)

| Case | Result on 6572649 |
|------|-------------------|
| TestKRLAlone/ops_key_changed_krl_lands_alone | RED: `generation_too_large ... krl_not_verified: KRL version 1793000001: krl: the manifest is not signed by the bundle's ops key` |
| TestSpoolWindow/krl_only_the_recorded_bundle_signs_lands_alone | RED: `generation_too_large ... krl_not_verified` (same text) |
| TestKRLSigner/successor_signed_krl_then_no_new_krl_is_a_noop | RED at the first assertion: apply 1 `generation_too_large ... krl_not_verified`, revokes 6 false |
| TestKRLSigner/successor_signed_krl_after_a_refused_directory_lands_alone | RED: `directory_not_verified ... krl_not_verified` |
| TestKRLSigner/record_signed_krl_during_a_wait_lands/poll | RED: `KRL 8 did not land during the wait: revokes 5 true, 8 false` |
| TestKRLSigner/successor_signed_krl_after_a_refused_bundle_step_is_refused | GREEN at once, as the plan expects: a step verified before a refused bundle step authorises nothing |
| TestKRLSigner/successor_signed_krl_needs_a_verified_successor | GREEN at once, as the plan expects: a bundle that was only offered never authorises a KRL |

After the change, Task 1's verify set passes (no FAIL, no DATA RACE), with every line its fails_when lists; it was run again on 9c214b3 as the tracer gate.

### Mutants (each applied with `git apply` to 9c214b3, run against its named test with an anchored `-run`, restored with `git checkout`, then `git diff --quiet -- internal/`)

| # | Mutant | Result |
|---|--------|--------|
| T1a | the successor not tried in KRLAlone | killed by `TestKRLAlone/ops_key_changed_krl_lands_alone` and `successor_signed_krl_after_a_refused_directory_lands_alone` (krl_not_verified) |
| T1b | verify's refused branch passing nil as from (Q2 off) | killed by `successor_signed_krl_after_a_refused_directory_lands_alone` |
| T1c | pollCapture passing nil as from | killed by `record_signed_krl_during_a_wait_lands/poll` (KRL 8 waits) |
| T1d | fullyVerified raised whatever the bundle step returned | killed by `successor_signed_krl_after_a_refused_bundle_step_is_refused` (the KRL landed) |
| T1e | S the capture's newest offered bundle, verified or not | killed by `successor_signed_krl_needs_a_verified_successor` (the KRL landed) |

### Notes

- verify sets fullyVerified right after the bundle step returns nil, from the last bundle step, before the directory step. So a directory refusal still carries it (Q2), and holdBundle, which changes Verified.Bundle, does not change it. On the record path the last step is the record's bundle (the base), which is why `krl_only_the_recorded_bundle_signs_lands_alone` and `record_signed_krl_during_a_wait_lands/poll` pass in Task 1, before Task 3 carries the record's bundle into a capture whose bundle step was refused.
- `successor_signed_krl_after_a_refused_bundle_step_is_refused` builds bundle 3 with a new test helper, `successorUnder` (bundle 2's policy kept), because `f.successor` builds only under the genesis policy, and bundle 2 carries policy 2.
- The shared fixture `opsRotated` installs KRL 5 (signed by the original ops key) before it offers bundle 2, and gives the host an outbox, so Task 2's cases can check last_apply and an in-force KRL.

## Task 2: the retired-key refusal and the held rule

Commit 7cc88f7 `fix(agent): refuse a KRL whose ops key a newer verified bundle dropped`. 15 cases (13 new TestKRLSigner cases, one of them a wait case with the subtests `poll` and `forward`, and the two flipped tests).

### RED (on 7151615, Task 1's head, with the tests added, locally in WSL, `go test -race -count=1 -v`)

So that the tests compile on Task 1's head, the RED tree also had `state.ErrKRLSignerRetired` declared, with no behaviour behind it.

| Case | Result on Task 1's head |
|------|-------------------------|
| retired_key_krl_on_the_krl_step_is_refused | RED at apply 1: `krl_not_verified: KRL version 1793000002: krl: the manifest is not signed by the bundle's ops key` |
| retired_key_krl_after_a_refused_directory_is_refused | RED: only `directory_not_verified` (KRL 6 landed, dropping serial 5) |
| retired_key_krl_after_a_refused_bundle_step_is_refused | RED: only `bundle_not_verified` (KRL 6 landed) |
| held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step | RED: apply 1 committed the held step with KRL version 1793000001 (KRL 5), without KRL 6 |
| held_step_krl_signed_by_a_retired_key_is_refused | RED: apply 1 returned nil with KRL version 1793000002 (KRL 6 landed with the held step) |
| retired_in_force_key_krl_under_a_held_step_is_refused | RED: apply 1 committed the held step and returned nil (no refusal reported) |
| retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused | RED: apply 2 returned nil with KRL 7 (version 1793000002) landed under directory 65 |
| retired_key_krl_during_a_wait_from_the_record_is_refused/forward | RED: `krl_signer_retired named false, want true: apply <nil>` (KRL 8 landed with the held step) |
| retired_key_krl_during_a_wait_from_the_record_is_refused/poll | RED by the refusal code only: `krl_signer_retired named false` (the poll's KRL step refused KRL 8 with krl_not_verified; it never landed) |
| TestApply/catch_up_across_policy_rotation (newOps=true row) | RED: `the KRL signed by the newest bundle's ops key did not land with the held step` (KRLVersion 0 under bundle 1) |
| TestSpoolWindow/policy_rotation_below_the_recorded_bundle/newOps=true | RED: `KRL 7 was not applied` |
| krl_third_key_under_changed_bundle_not_retired | GREEN at once: a third key matches no candidate |
| first_install_krl_refusal_unchanged | GREEN at once: main's refusal before a first install |
| krl_the_new_bundle_authorises_applies_with_it | GREEN at once: no candidate after P is tried when P signed |
| unchanged_krl_under_a_rotated_bundle_installs | GREEN at once: the skip rules come before any candidate |
| rotated_back_key_is_current | GREEN at once: main lands it, and Q4 keeps it |

`first_install_krl_refusal_unchanged` first failed on Task 1's head because of a wrong assertion in the test itself: it required that `accepted/` does not exist, but the state directory holds it before a first install. The assertion now checks that current and last-good do not exist, and the case was GREEN on Task 1's head after that fix, as the plan expects.

After the change, Task 2's verify set passes (no FAIL, no DATA RACE), with every line its fails_when lists. The acceptance greps print: `krl_signer_retired` in state.go code 1, `state.ErrKRLSignerRetired` in status.go code 1, `KRLRefused` in verify.go code 2 and in apply.go code 4, `waits with the bundle` in verify.go 0, `the KRL waits with the bundle` in apply_test.go 0, `the KRL lands with the held step (03-08k)` in apply_test.go 1.

### Mutants (each applied to 7cc88f7, run against its named tests, restored, then `git diff --quiet -- internal/`)

Every named test failed under its mutant. Where a mutant names several tests, each of them failed.

| # | Mutant | Killed by |
|---|--------|-----------|
| T2a | the retirement check removed in KRLAlone | retired_key_krl_after_a_refused_directory_is_refused (KRL 6 landed, dropping serial 5) |
| T2b | the retirement check removed in krlStep | retired_key_krl_on_the_krl_step_is_refused (apply 1 nil: bundle 2, directory 2 and KRL 6 installed); held_step_krl_signed_by_a_retired_key_is_refused (KRL 6 landed with the held step) |
| T2c | F not tried in krlStep | retired_key_krl_on_the_krl_step_is_refused (krl_not_verified); retired_in_force_key_krl_under_a_held_step_is_refused (apply 1 nil: no refusal reported) |
| T2d | the held step dropped: the refusal returned as a Verify error under BundleHeld too | retired_in_force_key_krl_under_a_held_step_is_refused, held_step_krl_signed_by_a_retired_key_is_refused, retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused (the held step did not commit) |
| T2e | outcome ignoring KRLRefused | retired_in_force_key_krl_under_a_held_step_is_refused (apply 1 nil) |
| T2f | a partial reset: the refused KRL's Next.KRL, KRLManifest and KRLSig assigned under the held step | held_step_krl_signed_by_a_retired_key_is_refused (accepted/'s KRL bytes differ after apply 1) |
| T2g | known(X) without the steps verified before a refused bundle step | retired_key_krl_after_a_refused_bundle_step_is_refused |
| T2h | retired when any known bundle above X names another key (Q4 off) | rotated_back_key_is_current (krl_signer_retired) |
| T2i | krlStep's S branch removed | held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step; TestApply/catch_up_across_policy_rotation (its newOps=true assertion, apply_test.go:590); TestSpoolWindow/policy_rotation_below_the_recorded_bundle/newOps=true; each run on its own |
| T2j | the S branch landing K alone through KRLAlone instead of with the held step | held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step (directory 1 stayed: directory 65 waited) |
| T2k | krl_signer_retired returned before K is verified under F | krl_third_key_under_changed_bundle_not_retired |
| T2l | the retirement check run before the skip rules | unchanged_krl_under_a_rotated_bundle_installs |
| T2m | F tried without the "alone has a bundle" guard | first_install_krl_refusal_unchanged (nil pointer panic) |
| T2n | the `refusals` entry removed | retired_key_krl_on_the_krl_step_is_refused (last_apply.result error) |

**The mutant that must survive.** Task 1's T1c (pollCapture passing nil as from) was run again on 7cc88f7 against `retired_key_krl_during_a_wait_from_the_record_is_refused/poll` and `/forward`. Both stayed GREEN: the poll's KRL step refuses the old-key KRL before the KRL-alone call, because both check against the pending target's KRL floor. This is the evidence that a nil from cannot widen a poll while Unapplied.Base never carries a KRL part.

### Notes

- verifyKRLUnder now returns the verified KRL and assigns nothing of it. `take` assigns the parsed KRL, KRLChanged and Next's four KRL fields together, only for a KRL that lands. The stored KRL's parse still sets Verified.KRL to the KRL in force.
- Main's held-step wait still applies only to a manifest the bundle does not verify. verifyKRLUnder marks that error (`manifestRefused`), and under BundleHeld krlStep lets only that error wait, so a parse or header error under a held step is still an error, as on main.
- The krl_signer_retired error names both bundle versions: `KRL version N: its signer, the ops key of bundle version X, is retired by bundle version Y, which names another ops key`.

## Task 3: what the apply knows beyond one capture

Commit 0767bbf `fix(agent): carry the verified bundle into the record's capture and the wait's polls`. Ten cases, three of them wait cases with the subtests `poll` and `forward`, plus the subtest `forward` of Task 1's `record_signed_krl_during_a_wait_lands`.

### RED (on 003adca, Task 2's head, with the tests added, locally in WSL, `go test -race -count=1 -v`)

| Case | Result on Task 2's head |
|------|-------------------------|
| successor_from_the_record_after_a_refused_bundle_step_above_it | RED: `bundle_not_verified ... krl_not_verified: KRL version 1793000002: krl: the manifest is not signed by the bundle's ops key` (nothing carried the record's bundle) |
| record_successor_dropped_by_a_verified_bundle_above_it_is_refused | RED for the code only: `bundle_not_verified ... krl_not_verified` |
| retired_key_krl_during_a_wait_is_refused/poll | RED: `krl_signer_retired named false, want true: apply <nil>` (the poll took KRL 7) |
| retired_key_krl_during_a_wait_is_refused/forward | RED: `accepted/ bundle 1, directory 65, KRL 1793000002; want ... 1793000001` (forward refused KRL 7, then a poll took it) |
| successor_signed_krl_during_a_wait_lands/poll | RED: `accepted/ ... KRL 1793000001; want ... 1793000002` (KRL 8 waited) |
| successor_signed_krl_during_a_wait_lands/forward | GREEN at once (Task 2's held rule) |
| retired_key_krl_during_a_wait_above_the_record_is_refused/poll | RED: `krl_signer_retired named false, want true: apply <nil>` |
| retired_key_krl_during_a_wait_above_the_record_is_refused/forward | RED: `accepted/ bundle 1, directory 2, KRL 1793000002; want ... 1793000001` (forward refused KRL 8, then a poll took it alone) |
| record_signed_krl_during_a_wait_lands/forward | GREEN at once (the held rule) |
| retired_key_krl_after_a_krl_alone_supersede_is_refused | RED: `the KRL-alone state never superseded the pending target (30 sleeps)`: the first poll could not land KRL 8 |
| retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main | GREEN at once: the withholding-server residual's boundary. Once the spool no longer offers bundle 2, the host no longer knows it, and the KRL the retired key signed is taken as on main |
| krl_other_error_under_changed_bundle_keeps_its_error | GREEN at once |
| krl_in_force_key_for_another_installation_keeps_the_first_error | GREEN at once: the fallback returns the first error unchanged |
| TestVerifyManifest/bundle_read_only_for_its_ops_key | GREEN at once |

Each wait subtest's failure line above was taken from a run of that subtest alone, so each line is attributed to its own subtest.

`retired_key_krl_after_a_krl_alone_supersede_is_refused` was built as the plan writes it. The KRL-alone supersede does not end the wait: the superseding generation still carries the held directory, so the wait goes on, and a later poll runs against the KRL-alone pending target. The case therefore needed no deviation. It detects the supersede by the wait's log line `a newer state arrived during the wait` and publishes KRL 9 at the next sleep.

After the change, Task 3's verify set passes for both packages (no FAIL, no DATA RACE), with every line its fails_when lists. The acceptance greps print: `func VerifyAfter(` 1 in verify.go; `func VerifyAheadAfter(` 1 in unapplied.go; `pollCapture(pending *state.Verified)` 1; in apply.go code, `state.VerifyAfter(` 1, `state.VerifyAheadAfter(` 1, `state.Verify(` 1 (forward's), `state.VerifyAhead(` 1 (forward's), and `state.KRLAlone(e.pins, prev, st, nil, v)` 1.

### Mutants (each applied to 0767bbf, run against its named tests, restored, then `git diff --quiet -- internal/`)

| # | Mutant | Killed by |
|---|--------|-----------|
| T3a | VerifyAhead passing nil as carried | successor_from_the_record_after_a_refused_bundle_step_above_it |
| T3b | the retirement check skipped for the successor in KRLAlone | record_successor_dropped_by_a_verified_bundle_above_it_is_refused |
| T3c | pollCapture's branch without a record keeping state.Verify | retired_key_krl_during_a_wait_is_refused/poll and /forward; successor_signed_krl_during_a_wait_lands/poll (each run on its own) |
| T3d | pollCapture's record branch keeping state.VerifyAhead | retired_key_krl_during_a_wait_above_the_record_is_refused/poll and /forward (each run on its own) |
| T3e | KRLAlone's Verified given a nil fullyVerified instead of from's (its own successor still read from from) | retired_key_krl_after_a_krl_alone_supersede_is_refused (`current revokes 8 true, 9 true`: the second poll landed KRL 9) |
| T3f | the fallback returning the last candidate's error | krl_in_force_key_for_another_installation_keeps_the_first_error (it reported krl.ErrInstallation) |

**Equivalent mutants.** Each was applied and run against all of TestKRLSigner, TestKRLAlone/ops_key_changed_krl_lands_alone, TestSpoolWindow/krl_only_the_recorded_bundle_signs_lands_alone and policy_rotation_below_the_recorded_bundle, TestApply/catch_up_across_policy_rotation and TestSpoolWindowWideningWait. All three survived, as the plan expects:

| # | Mutant | Why it changes no outcome |
|---|--------|---------------------------|
| E1 | the krl.ErrSigner restriction removed, in krlStep and in KRLAlone | krl.VerifyManifest reads the bundle only for its ops-key comparison (pinned by `TestVerifyManifest/bundle_read_only_for_its_ops_key`). So a non-signer error under one bundle is the same error, or krl.ErrSigner, under every other bundle, and the fallback returns the first candidate's error unchanged (pinned by `krl_in_force_key_for_another_installation_keeps_the_first_error`) |
| E2 | the "ops key differs" conditions on S and F removed, in krlStep and in KRLAlone | the same two facts: a bundle with the same ops key gives the same result as the one already tried |
| E3 | VerifyAheadAfter without the record's half of the higher-of | within one apply the pending capture's fully verified bundle already starts at the record's bundle (forward's VerifyAhead carried it, or forward wrote the record from that capture), and every later poll inherits it. A version tie between the two halves is the same bundle. Only a record rewritten during the wait could differ; the half is kept so that a poll never knows less than the record |

UNVERIFIED: no test supersedes the pending target twice within one wait. `retired_key_krl_after_a_krl_alone_supersede_is_refused` pins the inheritance through one supersede and a later poll.
