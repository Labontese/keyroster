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
