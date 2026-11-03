---
phase: 03-linux-agent-and-revocation
plan: 08f
subsystem: agent
tags: [agent, apply, state, spool, fetch, directory, policy, roots, f02, f03]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08d (KRLAlone, storedOnly, outcome's errNoDirectory), 03-08e (spool.Cap, checkCaps, healSpool, pruneSpool), 03-08j (verify's chain and alone, the unapplied record, WriteAccepted's raise), 03-08k (krlStep, fullyVerified, VerifyAfter, VerifyAheadAfter, outcome joining Refused and KRLRefused)"
provides:
  - "state: checkStored, (s *Stored) DirectoryUnderPolicy, Verified.DirectoryUnauthorized, ErrDirUnauthorized (directory_not_authorized), ErrDirFork (directory_fork)"
  - "state: verifyDirectory checks the stored directory under the policy in force; standaloneDirectory recovery; refusals converted while unauthorized, with the bundle part restored; the fork rule at the stored version; storedOnly carries the flag"
  - "state: verifyBundle retries a step once on trust.ErrThreshold with the union of admitted policy-signature files (unitePolicySigs, admitPolicySigs, storedPolicySigs)"
  - "spool and fetch: bundle-<N>.policy.sigs (State.BundlePolicySigs), in Cap, checkCaps, healSpool, dropAbove and pruneSpool"
  - "apply: Render's trust-only generation while unauthorized, the forced render with its no-op, outcome joining DirectoryUnauthorized, Report.DirectoryUnauthorized, WriteAccepted's directory 0 by the chain base (O-2 (c)), two refusals in last_apply"
  - "tests: TestDirectoryUnderPolicyInForce (13 cases), TestRootRotationUnchangedPolicy (11), three TestSpool, four TestFetch and one TestSpoolPrune case"
  - "docs: root-ceremony.md, enroll-user.md, signer-install.md, host-setup.md; todo 2026-10-21 Status"
  - "pre-merge review fix round 1: (*Stored).PrincipalsUnder and coversAuthority, engine.render keeping last-good's principals only under a policy that authorizes their source, bundle_held at the supersede step, TestLastGoodPrincipalsUnderPolicyInForce (8 cases), the M-2, T2b and widening-directory cases, the corrected spool bound"
  - "pre-merge review fix round 2: bundle_held at the supersede step for a poll that moved only the directory, TestDirectoryUnderPolicyInForce/widening_wait_superseded_into_a_hold_at_its_bundle, the kept-host and standalone-recovery runbook wording, the upgrade residual"
affects: [03-09, 03-10, 03-12, 03-13, 03-14]

requirements-completed: []

actuals:
  tokens: 89000
  tasks: 4
  commits: 9
plan_head_before: b1ebff3ff9484c02a4f574451fe7848fa95fa451
plan_head_after: 561542dce63db43e6200df74e593f5f364ff89a2

tech-stack:
  added: []
  patterns:
    - "The stored directory is checked again under the policy in force on every verification and in the KRL-alone state; the flag is derived, never stored"
    - "While unauthorized, the host renders trust files only, and every refusal of an offered directory joins the unauthorized state instead of refusing the capture"
    - "A threshold failure of a successor step is retried once with a union of admitted signature files; one admitted file is stored, never the union"

key-files:
  created:
    - internal/agent/apply/policy_change_test.go
    - .planning/phases/03-linux-agent-and-revocation/03-08f-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md
  modified:
    - internal/agent/state/state.go
    - internal/agent/state/verify.go
    - internal/agent/apply/render.go
    - internal/agent/apply/apply.go
    - internal/agent/apply/installed.go
    - internal/agent/apply/status.go
    - internal/agent/apply/status_test.go
    - internal/agent/apply/apply_test.go
    - internal/agent/apply/window_test.go
    - internal/agent/spool/spool.go
    - internal/agent/spool/spool_test.go
    - internal/agent/fetch/fetch.go
    - internal/agent/fetch/fetch_test.go
    - internal/agent/fetch/prune_test.go
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/enroll-user.md
    - docs/runbooks/signer-install.md
    - docs/runbooks/host-setup.md
    - .planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (and the wave lines of 03-10 to 03-16)

key-decisions:
  - "F03: the flag is derived on every run and the stored directory kept, so 03-08d's no-directory fallback is never reached from the unauthorized state"
  - "F03: while unauthorized, every refusal of an offered directory is converted, with the bundle part restored (plan check 3, M-2); stored_state_invalid stays an error"
  - "F03 (O-2 (c)): accepted.json's directory is 0 only while the chain base's directory is unauthorized under the chain base's policy"
  - "F02: the union is tried only on ErrThreshold, from admitted sources only, bundle signatures never; one admitted file is stored"

metrics:
  duration: "about 3 h 20 min over two executor runs (Run A 06:08-07:00, Run B 07:05-08:30 local time, 2026-11-03)"
  completed: 2026-11-03
---

# Phase 3 Plan 08f: the policy in force decides what a host trusts (F02, F03) Summary

**An enrolled host checks its stored directory again under the root-signed policy in force on every verification, including the KRL-alone pass. While the policy's admin quorum has not signed that directory, the host renders trust files only and reports `directory_not_authorized`. It takes the new admins' directory standalone at the same version or higher. A root rotation that carries the policy over verifies with the policy signatures delivered per bundle (`bundle-<N>.policy.sigs`), united only on a threshold failure.**

Run A (Tasks 1 and 2) wrote the draft; Run B (Tasks 3 to 5) completed it. Code comments cite `F02 (03-08f)` and `F03 (03-08f)`. PR: #82 (https://github.com/Labontese/keyroster/pull/82).

## Branch

`p03/08f-agent-policy-in-force`, created from origin/main b1ebff3. Task 4 committed the plan file unchanged (4a1e5a5).

## Base (before any edit, on b1ebff3)

Measured locally in WSL under -race, with the Budget's two gates (scratch script: the alone gate, then the `./...` margin gate, each through `bash scripts/linux.sh` and the Budget's awk filter):

| Run | internal/agent/apply `ok` line | Limit | Gate exit |
|---|---|---|---|
| alone (`go test -race -count=1 ./internal/agent/apply/`) | 296.502 s | 400 s | 0 |
| `./...` (`go test -race -count=1 ./...`) | 330.309 s | 480 s | 0 |
| CI, origin/main b1ebff3, CI run 41579130798, job build-test 125729546783 | 205.402 s | 480 s | n/a |

CI's figure was read with `bash scripts/gh-as-bot.sh run view 41579130798 --job 125729546783 --log` (the log line `ok  github.com/Labontese/keyroster/internal/agent/apply 205.402s`). No figure is above its limit, so the stop rule did not trip.

## Task 1: the stored directory under the policy in force (F03 tracer)

Code commit: dff4921 `fix(agent): check the stored directory under the policy in force (F03)`.

### RED (on b1ebff3 with the tests and the symbol stubs added, locally in WSL, `go test -race -count=1 -v -run "^TestDirectoryUnderPolicyInForce$|^TestSpoolWindow$/^held_content_refusal_keeps_the_records_bundle$" ./internal/agent/apply/`)

The stubs were only the new symbols, with no behaviour: `state.ErrDirUnauthorized`, `state.ErrDirFork`, `Verified.DirectoryUnauthorized`, `Report.DirectoryUnauthorized` and `(s *Stored) DirectoryUnderPolicy()` returning nil. Both cases then built and failed on behaviour:

```
    policy_change_test.go:94: apply 3: <nil>, want directory_not_authorized
    policy_change_test.go:97: current still holds a principals file: [role:evil]
    policy_change_test.go:106: report: bundle 2, directory_unauthorized false; want 2, true
    policy_change_test.go:109: accepted.json names directory 2, want 0
--- FAIL: TestDirectoryUnderPolicyInForce (0.00s)
    --- FAIL: TestDirectoryUnderPolicyInForce/lagging_host_admin_removed_principals_dropped (0.67s)
    window_test.go:654: accepted.json bundle 3, directory 65; want 3, 0
--- FAIL: TestSpoolWindow (0.00s)
    --- FAIL: TestSpoolWindow/held_content_refusal_keeps_the_records_bundle (1.39s)
FAIL	github.com/Labontese/keyroster/internal/agent/apply	2.109s
```

On main's code the removed admin's directory 2 stays in force under bundle 2: the principals of deploy stay `[role:evil]` and the error is nil, as the plan states. The two checks that pass on main are about bundle 2 itself: its next user CA line is in user_ca_keys, and the KRL offered with it revokes serial 4242. The added assertion of held_content_refusal_keeps_the_records_bundle reads directory 65 on main.

### GREEN (the tree committed as dff4921)

Task 1's verify command exited 0, with no FAIL and no DATA RACE, and printed all eight required PASS lines. The command is `go test -race -count=1 ./internal/agent/state/`, then the anchored `-v -run` over TestDirectoryUnderPolicyInForce, the four TestKRLAlone cases, TestResetDirectory, the two TestApply cases, TestStatus/apply_result, TestWriteAccepted, the two TestSpoolWindow cases and TestKRLSigner. `go vet ./internal/agent/...` and `test -z "$(gofmt -l internal/)"` passed in the same run.

### Test time (the tree committed as dff4921)

| Run | internal/agent/apply `ok` line | Stop rule | Gate exit |
|---|---|---|---|
| alone | 300.933 s | above 296.5 + 120 = 416.5 s, or above 400 s | 0 |
| `./...` | 318.232 s | above 480 s | 0 |

Both runs passed in full, with no `--- FAIL` anywhere under `./...`.

### What was built

- **state.**
  - `checkStored(prev, d, pol)` runs `directory.VerifySignatures` over the stored directory's stored signatures, then `directory.CheckPolicy`. Any failure is wrapped in `ErrDirUnauthorized` (`directory_not_authorized`), naming the stored directory version and the policy version.
  - `ErrDirFork` (`directory_fork`) is declared for Task 3.
  - `(s *Stored) DirectoryUnderPolicy()` returns nil without a directory, a stored_state_invalid error for a directory that does not parse or a missing parsed policy, and otherwise checkStored under s's own policy.
- **verifyDirectory** computes `unauth := checkStored(prev, d, v.Policy)` for the stored directory. prev is verify's chain, and v.Policy is the newest policy the bundle step reached, before any hold.
  - While unauth is nil, the offered-directory logic runs unchanged. It moved into `offeredDirectory`.
  - While it is set, `standaloneDirectory` looks at the offered versions from the newest down to the stored version, that version only when its bytes differ. It accepts the first that carries v.Policy's quorum, parses with its version, and passes CheckInstallation and CheckPolicy. It is standalone, with no chain to the stored bytes, and a version below the stored one is never taken.
  - Otherwise today's logic runs, chain and hold included. When it accepts nothing and returns nil, `v.DirectoryUnauthorized = unauth`. Its refusals are returned unchanged; Task 3 converts them.
  - verify's raise of fullyVerified (03-08k) is untouched: it still runs after verifyBundle and before verifyDirectory.
- **apply.**
  - Render returns `renderTrust(v)` while `v.DirectoryUnauthorized` is set: the CA keys and the KRL, no principals files and no host. engine.render fills `g.Host` from last-good's record when there is an agent last-good.
  - outcome joins `v.DirectoryUnauthorized` with Refused and KRLRefused (and errNoDirectory). krlAlone's `v.Refused != nil` return joins it too.
  - `Report.DirectoryUnauthorized` (json `directory_unauthorized,omitempty`) is set in three places: right after Verify, before every later return; after each KRL-alone pass in forward; and from tv at the supersede step.
  - The comment at the supersede step says that a poll's Verified carries the state, the state.KRLAlone branch through storedOnly included. **storedOnly does not carry the flag yet; that is Task 3's step.** Until then, the comment is ahead of the code.
  - WriteAccepted computes the raised versions as before. It then takes the chain base: the record's base when loadUnapplied returns one, else accepted/ (also on a loader error). It writes Directory 0 when the base's DirectoryUnderPolicy returns an error. Its doc comment gives the plan's three reasons, the crash sentence (m-5) and the ResetDirectory note.
  - status.go's `refusals` gains `state.ErrDirUnauthorized` and `state.ErrDirFork`. TestStatus/apply_result gains a row for each, expecting `refused`.
  - internal/agent/heartbeat is unchanged: `git diff --exit-code origin/main -- internal/agent/heartbeat/` exits 0.

### The unauthorized-state helper (for Task 3)

`adminRemoved(t *testing.T) *adminRemovedHost` is in internal/agent/apply/policy_change_test.go. It puts the spool in `<state>/spool` (spoolInState), so accepted.json lands in the production outbox, and builds steps 1 to 3:
1. Bundle 1, policy 1 (admin alice, the fixture's admin, quorum 1) and directory 1 with role:ops are installed.
2. Alice's directory 2, granting role:evil to deploy, is applied. The helper fails the test if that does not take.
3. Bundle 2 is offered and applied, with a newer KRL revoking serial 4242. `f.rotationNext` builds it: policy 2 names bob alone (seedKey 11), and bundle 2 adds a next user CA (seedKey 31).

It returns `*adminRemovedHost`. This embeds the `*testHost` and holds:
- `bob`, policy 2's admin signer;
- `next`, bundle 2's next user CA signer;
- `b2`, bundle 2, parsed;
- `serial`, 4242;
- `r` and `err`, the third apply's report and error.

`h.dirs` holds directories 1 and 2 (alice's). After Task 1, accepted/ holds bundle 2 over alice's directory 2, current holds no principals, and readAccepted's Directory is 0.

`(f *fixture) rotationNext(prev, prevDoc, prevPolicyDoc, prevPolicy, admins, issuedAt, next)`, also in policy_change_test.go, is f.rotation with a next user CA key added to the successor. The rendered CA keys then show which bundle is in force.

### Existing tests the change flipped

| Test | Change | Reason |
|---|---|---|
| TestApply/torn_accepted_save_never_mixes | Its rotation's admins are now `f.policy.Admins` instead of bob (seedKey 11), and the comment says why. | Under F03, a policy naming bob alone does not authorize directory 1, which the fixture's admin signed. The run after the crash would return directory_not_authorized and render no principals, so the case would no longer test a byte-equal commit. |

No other existing test flipped: the alone gate's full output for internal/agent/apply shows no `--- FAIL`. That run confirms these expected survivors stayed green:
- TestApply/catch_up_across_policy_rotation;
- TestSpoolWindow/policy_rotation_below_the_recorded_bundle and older_bundle_at_the_window_boundary;
- TestSpoolWindowWideningWait's recordAbove rows;
- TestKRLSigner's heldShape, heldWait and recordBelowWait cases;
- TestWriteAccepted, and the TestSpoolWindow cases that read accepted.json (bundleRecorded, recordedWindow, fetcher_cursor_follows_the_record).

The one added assertion is in `TestSpoolWindow/held_content_refusal_keeps_the_records_bundle`. After `mustRecord(t, h, 3, 65)`, it now also requires readAccepted's Bundle 3 and Directory 0 (owner decision O-2 (c), plan check 3 m-1). Its RED, directory 65, is above.

## Task 2: root rotations that keep the policy (F02)

Code commit: b55c264 `fix(agent): verify a root rotation that keeps the policy with the signatures delivered per bundle (F02)`.

### RED (on 605a99a, Task 1's head, with the tests and the `State.BundlePolicySigs` field added, locally in WSL)

The field was the only code change, and Read and Write ignored it. Every case built, and each RED fails on behaviour. The commands were `go test -race -count=1 -v -run "^TestSpool$|^TestFetch$|^TestSpoolPrune$" ./internal/agent/spool/ ./internal/agent/fetch/` and `go test -race -count=1 -v -run "^TestRootRotationUnchangedPolicy$" ./internal/agent/apply/`. Reports and temporary paths are shortened:

```
    spool_test.go:255: Cap("bundle-1.policy.sigs") = 0, false, want 1048576, true
    spool_test.go:295: bundles 2, per-bundle policy signatures map[]; want bundles 2 and 3, bundle 3's file alone
    --- FAIL: TestSpool/cap_is_what_read_enforces (0.09s)
    --- FAIL: TestSpool/bundle_policy_sigs_read_when_present (0.00s)
    fetch_test.go:581: bundle-2.policy.sigs: "", open <tmp>/bundle-2.policy.sigs: no such file or directory; want "p2"
    fetch_test.go:581: bundle-3.policy.sigs: "", open <tmp>/bundle-3.policy.sigs: no such file or directory; want "p3"
    fetch_test.go:594: bundle-4.policy.sigs was not written before bundle-4.json
    fetch_test.go:611: bundle-3.policy.sigs spooled true, want false
    fetch_test.go:622: an oversize per-bundle policy signature file: state_item_over_cap: policy version 1: policy-1.json.sigs would be 1048577 bytes, above the 1048576 the applier reads; nothing of this answer was written, want state_item_over_cap naming bundle-2.policy.sigs
    fetch_test.go:634: healSpool: [], <nil>; want bundle-2.policy.sigs removed
    --- FAIL: TestFetch/per_bundle_policy_sigs_spooled (0.05s)
    --- FAIL: TestFetch/drop_above_removes_per_bundle_policy_sigs (0.00s)
    --- FAIL: TestFetch/per_bundle_policy_sigs_over_cap_refused (0.00s)
    --- FAIL: TestFetch/heal_covers_per_bundle_policy_sigs (0.01s)
    prune_test.go:311: accepted bundle 3: bundle-9.policy.sigs spooled true, want false
    prune_test.go:311: accepted bundle 3: bundle-1.policy.sigs spooled true, want false
    prune_test.go:311: accepted bundle 3: bundle-2.policy.sigs spooled true, want false
    prune_test.go:323: no accepted.json: bundle-1.policy.sigs spooled true, want false
    (... the same for bundles 2 to 6 ...)
    --- FAIL: TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle (0.04s)
    policy_change_test.go:310: the rotation through policy-1.json.sigs: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    policy_change_test.go:369: the rotation through the offered policy file: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    policy_change_test.go:326: apply: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 2 roots, need 2, want bundle_not_verified with policy (new roots) signed by 1 of 2 roots, need 2
    policy_change_test.go:295: three hops: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    policy_change_test.go:437: three hops: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    policy_change_test.go:284: the rotation with directory 2: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    policy_change_test.go:271: the rotation to {C}: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    policy_change_test.go:385: the rotation to {C}: bundle_not_verified: bundle version 2: trust: root threshold not met: policy (new roots) signed by 0 of 1 roots, need 1, &{...report...}
    --- FAIL: TestRootRotationUnchangedPolicy/spool_without_per_bundle_sigs_one_hop (0.52s)
    --- FAIL: TestRootRotationUnchangedPolicy/malformed_delivered_sigs_not_stored (0.59s)
    --- FAIL: TestRootRotationUnchangedPolicy/union_never_lowers_threshold (0.59s)
    --- FAIL: TestRootRotationUnchangedPolicy/three_hops_in_one_capture (0.64s)
    --- FAIL: TestRootRotationUnchangedPolicy/stored_policy_sigs_stay_bounded (0.64s)
    --- PASS: TestRootRotationUnchangedPolicy/same_roots_unchanged_policy_accepted (0.71s)
    --- PASS: TestRootRotationUnchangedPolicy/growing_root_set_second_root_signs_policy (0.74s)
    --- FAIL: TestRootRotationUnchangedPolicy/one_hop_with_directory_in_same_capture (0.82s)
    --- FAIL: TestRootRotationUnchangedPolicy/one_hop_new_roots (0.85s)
    --- FAIL: TestRootRotationUnchangedPolicy/retired_root_fork_refused_after_rotation (0.85s)
    --- PASS: TestRootRotationUnchangedPolicy/malformed_delivered_sigs_change_nothing (0.99s)
```

**RED: 15 of the 19 cases.**
- TestSpool: `bundle_policy_sigs_read_when_present` and `cap_is_what_read_enforces`.
- TestFetch: all four.
- TestSpoolPrune: `per_bundle_policy_sigs_pruned_with_their_bundle`.
- TestRootRotationUnchangedPolicy: eight of eleven.
  - `one_hop_new_roots` is refused `policy (new roots) signed by 0 of 1 roots, need 1`, and its report shows the KRL applied alone (KRL 1793000001, generation 2).
  - `one_hop_with_directory_in_same_capture` is refused the same way, so directory 2 is skipped.
  - `retired_root_fork_refused_after_rotation` is RED at its first step, because the rotation is refused.
  - `union_never_lowers_threshold` is refused too, but with 0 of 2 rather than the expected 1 of 2: today's code counts only the stored A.

**GREEN at once: 4 cases, each with its reason.**
- `TestSpool/bundle_policy_sigs_absent_is_allowed` is a control: a spool without the per-bundle file reads as before.
- `same_roots_unchanged_policy_accepted` is a control: the 03-12/03-13 shape passes the plain check today and after, and accepted/ stores the stored signatures.
- `growing_root_set_second_root_signs_policy` is a control. {A}→{A,B}→{A,B,C} at threshold 1: the stored signatures by A count for every root set that keeps A, so the plain check passes today and after.
- `malformed_delivered_sigs_change_nothing` pins today's behaviour in both halves, which the union must not change. Same roots with a malformed delivered file are accepted with the stored signatures. A rotation to {C} with the malformed file and an offered file holding only A is refused.

### GREEN (the tree committed as b55c264)

Task 2's verify command exited 0, with no FAIL and no DATA RACE, and printed all 20 required PASS lines. The command is `go test -race -count=1 ./internal/agent/state/ ./internal/agent/spool/ ./internal/agent/fetch/`, then the anchored `-v` runs over TestSpool, TestFetch and TestSpoolPrune, then TestRootRotationUnchangedPolicy, TestDirectoryUnderPolicyInForce, the two TestKRLAlone cases, the two TestApply cases and TestKRLSigner. `go vet ./internal/agent/...` and `test -z "$(gofmt -l internal/)"` passed in the same run. `git diff --exit-code origin/main -- internal/trust/` exits 0.

The first verify run failed `TestFetch/more_repolls_immediately` on its exact spool listing. That is an existing test this task changes (below), so its expected list was updated. The second run then failed the same case on its timing bound: `in 906.830716ms`, against 900 ms. In that run the spool package took 21.9 s rather than its usual 2.6 s, so the machine was under load; one extra file write per bundle item does not take hundreds of milliseconds. The third run passed, as did the case in both test-time runs below. It is recorded here because it is a timing-sensitive case.

### Test time (the tree committed as b55c264)

| Run | internal/agent/apply `ok` line | Stop rule | Gate exit |
|---|---|---|---|
| alone | 329.188 s | above 296.5 + 120 = 416.5 s, or above 400 s | 0 |
| `./...` | 346.190 s | above 480 s | 0 |

Both runs passed in full, with no `--- FAIL` anywhere under `./...`. internal/agent/fetch took 44.2 s under `./...`.

### Mutants (scripted loop: each applied with `git apply` to b55c264, run against its named test with an anchored `-run` under -race, restored with `git checkout`, then `git diff --quiet -- internal/`)

| Mutant | Run against | Result | Failing lines |
|---|---|---|---|
| T2a: the union built from every source, unfiltered, and tried before the plain check | `malformed_delivered_sigs_change_nothing`, `same_roots_unchanged_policy_accepted` | **killed** | `same roots with a malformed delivered file: bundle_not_verified: ... policy (previous roots) signatures: block 2: sshsig: malformed signature` (ParseAll refuses the unfiltered union) and `accepted/'s policy signatures are not the stored ones` |
| T2b: the bundle signatures added to the union | `union_never_lowers_threshold`, `one_hop_new_roots` | **survived; not equivalent** (corrected below; killed in fix round 1 by `bundle_sigs_never_united`) | both PASS |
| T2c: Next.PolicySigs set to the union | `stored_policy_sigs_stay_bounded` | **killed** | `accepted/'s policy signatures (2826 bytes) are not bundle-4.policy.sigs (628 bytes)` |
| T2d: a rejected delivered file stored | `malformed_delivered_sigs_not_stored` | **killed** | `accepted/'s policy signatures are not the offered file` |
| T2e: the per-bundle file not written by the fetcher | `TestFetch/per_bundle_policy_sigs_spooled` | **killed** | `bundle-2.policy.sigs: "", open ...: no such file or directory; want "p2"` and `bundle-4.policy.sigs was not written before bundle-4.json` |
| T2f: the offered policy file left out of the union | `spool_without_per_bundle_sigs_one_hop` | **killed** | `the rotation through policy-1.json.sigs: bundle_not_verified: ... policy (new roots) signed by 0 of 1 roots, need 1` |
| T2g: spoolSet left without the per-bundle name, so pruneSpool keeps every such file | `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle` | **killed** | `accepted bundle 3: bundle-1.policy.sigs spooled true, want false` (and bundles 2 and 9, and bundles 1 to 6 without accepted.json) |

Six mutants were killed and one survived. The plan required T2b to survive as equivalent, but it is not equivalent (see the correction below), and pre-merge review fix round 1 kills it. Each was restored byte for byte, and `git diff --quiet -- internal/` passed after each.

**T2b is not equivalent (correction, PR #82 review, D-2 (b)).** Run A argued it was (plan check 3, m-2): CountPinnedSigners (internal/trust/verify.go:29-62) verifies each block over the policy's digest under the policy namespace and skips a block that does not verify there, so a root's bundle signature never counts toward the policy threshold. That holds for bundle-namespace blocks, but the argument assumed `bundle-N.json.sigs` holds only those. It is a spool file of any well-formed SSHSIG blocks, so it can also carry a root's policy-namespace signature over the exact policy bytes. The bundle check skips such a block, and the real union never reads that file, so a rotation whose new root signed the policy only there is refused. Under T2b that block counts and the rotation is accepted. The outcomes differ, so T2b is killable. Only a genuine root's policy signature can count either way, so there is no security impact, but the plan's "the bundle signatures are never united" (T-03-304) had no test. Fix round 1's `bundle_sigs_never_united` pins it and kills T2b.

### The threshold argument, in internal/trust/verify.go (unchanged)

- Line 315: VerifySuccessor's two checks take their thresholds from the bundles, `int(prev.Root.Threshold)` for the previous roots and `int(b.Root.Threshold)` for the new roots.
- Lines 316 and 319: each check runs requireSigners over the bundle (bundle namespace) and over the policy (policy namespace).
- Line 232: requireSigners fails with ErrThreshold when `len(signed) < threshold`.
- Lines 44, 48 and 51: CountPinnedSigners counts each pinned fingerprint at most once (`signed := map[string]bool{}`, and `signed[fp]` skips a second block). It counts only a block whose public key equals the pinned key byte for byte (`bytes.Equal(pub.Marshal(), s.PublicKey().Marshal())`) and whose SSHSIG verifies over SHA-512 of the exact policy bytes under the namespace (`s.VerifyDigest(namespace, digest)`).

So the union only adds blocks, each counted under the same per-root rule and the same thresholds. `union_never_lowers_threshold` pins this: C's block twice, a block by X, a key that is no root, and the stored A count C once, which is 1 of 2.

### What was built

- **spool.go.**
  - `State.BundlePolicySigs map[uint64][]byte`.
  - `bundlePolicyRE` (`^bundle-([1-9][0-9]{0,19})\.policy\.sigs$`, docRE's version grammar); `Cap` gives it MaxBundle.
  - readOnce does not list the file as ignored. It reads the file with readCapped for every bundle version it takes, when present, and allocates the map only then. The file does not decide whether a bundle set is complete.
  - Write writes it before `bundle-<N>.json.sigs` and `bundle-<N>.json`.
- **fetch.go.**
  - writeState passes each item's PolicySigs as `BundlePolicySigs[b.Version]`.
  - checkCaps names `bundle-<N>.policy.sigs`, between the bundle's signatures and the policy, so an oversize PolicySigs is refused naming the per-bundle file.
  - spoolFileRE gains `policy\.sigs` (dropAbove).
  - `spoolSetBundlePolicyRE` makes spoolSet return `("bundle", N)` for the file, so pruneSpool keeps it exactly while it keeps bundle N and removes an orphan. A set's completeness is still decided by `bundle-<N>.json` and its `.sigs`.
  - pruneSpool's doc comment states the bound of about 6.1 GiB kept and 6.6 GiB in all (owner decision O-3 (a)). Fix round 1 corrects the total to about 6.9 GiB (D-3).
  - dropAbove's and writeState's comments say why the per-bundle file exists.
- **verify.go.** verifyBundle keeps findPolicy and the plain VerifySuccessor call. On `errors.Is(err, trust.ErrThreshold)` it calls `unitePolicySigs` with `in.BundlePolicySigs[ver]` and the offered policy file whose body has the bundle's policy SHA-256 (`findPolicy(sum, nil, in)`).
  - `admitPolicySigs` (sshsig.ParseAll on the source alone) admits each source; identical files are admitted once, and each is concatenated with a trailing newline.
  - VerifySuccessor is retried once only when the union differs from pol.Sigs. The retry's error is returned when it fails, which is how `union_never_lowers_threshold` reports 1 of 2.
  - `storedPolicySigs` then chooses the file to store, in the plan's order: the first admitted file of delivered and offered that passes alone, else the admitted offered file, else the admitted delivered file. As a defensive last resort it falls back to pol.Sigs, the file the plain check parsed.
  - The doc comments of Verify, verifyBundle and unitePolicySigs state the rule and the threshold argument, citing F02 (03-08f).
  - verify's raise of fullyVerified is unchanged: a rotation the union verifies raises it like any verified step (Reconciliation I-1).
- internal/agent/state now imports internal/sshsig directly. `bash scripts/capslock-check.sh`, run through scripts/linux.sh on b55c264, reports every baseline unchanged: keyroster-agent has 37 pairs against the baseline's 37.

### Existing tests the change flipped

| Test | Change | Reason |
|---|---|---|
| TestFetch/more_repolls_immediately | Its exact spool listing gains `bundle-1.policy.sigs`, with a comment. | The fetcher now writes each bundle item's policy signatures per bundle (F02), so the listing of a spool written from one bundle item holds that file. |

No other existing test flipped. The alone gate and the `./...` run on b55c264 passed in full.

## Task 3: F03's edges (Run B)

Code commit: 941d459 `fix(agent): keep a host fail-closed on every path while its directory is not authorized (F03)`. Docs commit: 3878169 `docs(agent): describe hosts under the policy in force (03-08f)`.

### RED

The REDs were taken in two scratch worktrees outside the checkout (`git worktree add --detach`). Each got only its scratch test file and was removed afterwards with `git worktree remove` and `git worktree prune`.

**On origin/main b1ebff3: four cases.** The scratch file `red_task3_main_test.go` holds copies of the four cases, plus copies of rotationNext and adminRemoved. It uses no symbol this plan adds: the new codes are matched by text (`strings.Contains`), and the report's DirectoryUnauthorized is not read. The command was `go test -race -count=1 -v -run "^TestRedTask3Main$" ./internal/agent/apply/`. All four fail on behaviour:

```
    red_task3_main_test.go:84: bob's directory 3: directory_not_verified: directory version 3 does not chain to version 2: directory: version or prev hash breaks the chain: prev is not the SHA-256 of the installed version 2, &{...}
    red_task3_main_test.go:111: apply 2: <nil>, bundle 2; want bundle 2 with directory_not_authorized
    red_task3_main_test.go:113: apply 2: current holds a principals file for deploy: [role:evil]
    red_task3_main_test.go:124: apply 1: <nil>, bundle 2; want bundle 2 with directory_not_authorized
    red_task3_main_test.go:127: apply 1: current holds a principals file for deploy: [role:ops]
    red_task3_main_test.go:133: apply 2: directory_not_verified: version 2: directory: admin quorum not met: 0 of 1 admin signatures, want directory_not_authorized joined with directory_not_verified
    red_task3_main_test.go:138: apply 2: current holds a principals file for deploy: [role:ops]
    red_task3_main_test.go:162: apply 1: accepted.json bundle 2, directory 2; want 2, 0
    red_task3_main_test.go:174: apply 2: principals of deploy [role:ops], want bob's [role:bob]
    --- FAIL: TestRedTask3Main/rotation_first_then_removed_admin_refused (0.85s)
    --- FAIL: TestRedTask3Main/same_capture_hold_then_dropped (0.90s)
    --- FAIL: TestRedTask3Main/recorded_bundle_over_unauthorized_directory_reports_directory_0 (1.16s)
    --- FAIL: TestRedTask3Main/new_admins_next_version_accepted_standalone (1.25s)
```

Each matches the plan:
- `new_admins_next_version_accepted_standalone` fails with the chain refusal the plan names.
- `same_capture_hold_then_dropped`: bundle 2 keeps `[role:evil]`. Apply 1's hold passes on main as well.
- `rotation_first_then_removed_admin_refused`: both applies return without directory_not_authorized and keep `[role:ops]`.
- `recorded_bundle_over_unauthorized_directory_reports_directory_0`: apply 1's accepted.json names directory 2, and apply 2 keeps alice's principals.

**On Task 2's head 06820de: seven cases.** The branch's committed policy_change_test.go (941d459) was copied in, and every symbol it uses exists at 06820de. The command was the anchored `-run "^TestDirectoryUnderPolicyInForce$/^(...)$"` over the seven cases. All seven fail on behaviour:

```
    policy_change_test.go:324: apply 1 with nothing new: current holds a principals file for deploy: [role:evil]
    policy_change_test.go:347: apply: bundle_chain_gap: bundle version 3 is missing between the accepted version 2 and the offered version 4, &{...}
    policy_change_test.go:377: apply 1: directory_older: the spool offers directory version 4, below the accepted version 5, &{BundleVersion:1 DirectoryVersion:5 ...}
    policy_change_test.go:413: a same-number directory with other bytes: <nil>, want directory_fork
    policy_change_test.go:436: a same-number directory without the quorum: <nil>, want directory_not_verified, not directory_fork
    policy_change_test.go:461: apply 1: generation_too_large: principals/deploy would be 70372 bytes, above 65536, &{...}
    policy_change_test.go:551: apply: directory_not_verified: directory version 2 does not chain to version 1: ..., want directory_not_authorized joined with directory_not_verified
    --- FAIL: TestDirectoryUnderPolicyInForce/unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle (0.61s)
    --- FAIL: TestDirectoryUnderPolicyInForce/stored_version_above_new_admins_needs_reset (0.80s)
    --- FAIL: TestDirectoryUnderPolicyInForce/same_version_unsigned_bytes_not_verified (0.86s)
    --- FAIL: TestDirectoryUnderPolicyInForce/same_version_other_bytes_refused_as_fork (0.87s)
    --- FAIL: TestDirectoryUnderPolicyInForce/persisted_unauthorized_state_dropped_on_noop_capture (0.91s)
    --- FAIL: TestDirectoryUnderPolicyInForce/refused_bundle_step_still_checks_directory (1.09s)
    --- FAIL: TestDirectoryUnderPolicyInForce/recorded_authorized_directory_keeps_the_record_raise (3.95s)
```

Each matches the plan:
- The persisted state keeps `[role:evil]`, because forward skips the render for an unchanged capture.
- `refused_bundle_step_still_checks_directory` and `recorded_authorized_directory_keeps_the_record_raise` return no directory_not_authorized, because storedOnly does not check. The test asserts the joined error before the principals.
- `stored_version_above_new_admins_needs_reset` and `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle` fail because the directory refusal refuses the capture: bundle 1 stays.
- The two same-number cases are a silent no-op (`<nil>`).

**GREEN at once: one control.** `admin_set_unchanged_rotation_keeps_directory` is a control, as the plan says. Its RED was not taken anywhere.

### GREEN

Task 3's verify command exited 0, with no FAIL and no DATA RACE, and printed all 17 required PASS lines (`verify-task3.txt`). It was run again on the final tree, the committed 941d459, with TestStatus added and with `test -z "$(gofmt -l internal/)"` and `go vet ./internal/agent/...` in front: exit 0, all 13 TestDirectoryUnderPolicyInForce cases PASS. The docs verify command exited 0, every grep counting 1.

### Test time

| Run | internal/agent/apply `ok` line | Stop rule | Gate exit |
|---|---|---|---|
| alone | 291.798 s | above 296.5 + 120 = 416.5 s, or above 400 s | 0 |
| `./...` | 323.579 s | above 480 s | 0 |

Both runs passed in full, with no `--- FAIL` anywhere under `./...`, so no existing test flipped in Task 3. The timing runs started on the uncommitted Task 3 tree. While the alone run was in progress, the two directory_fork and directory_not_verified messages of the fork rule were reworded ("accepted version" became "stored version", and "both signed" became "signed"). That change touches text only, and no test matches on that text. The final verify above ran on the committed tree.

### Mutants (scripted loop, each applied with `git apply` to 941d459, run against its named test with an anchored `-run` under -race, restored with `git checkout`, then `git diff --quiet -- internal/`)

| Mutant | Run against | Result | Failing lines |
|---|---|---|---|
| T3a: the check skipped in storedOnly | `refused_bundle_step_still_checks_directory` | **killed** | `apply: bundle_chain_gap: ... want bundle_chain_gap joined with directory_not_authorized` |
| T3b: the forced render removed | `persisted_unauthorized_state_dropped_on_noop_capture` | **killed** | `apply 1 with nothing new: current holds a principals file for deploy: [role:evil]` |
| T3c: the forced render's no-op test removed | `persisted_unauthorized_state_dropped_on_noop_capture`, `lagging_host_admin_removed_principals_dropped` | **killed by both** | `apply 2 with nothing new: directory_not_authorized ..., want ... a no-op` and `the idle run: ... want directory_not_authorized, a no-op` |
| T3d: WriteAccepted's zero rule removed | the tracer, `recorded_bundle_over_unauthorized_directory_reports_directory_0` | **killed by both** | `accepted.json names directory 2, want 0` and `accepted.json bundle 2, directory 2; want 2, 0` |
| T3e: Report.DirectoryUnauthorized not set from v right after Verify (m-3) | the tracer | **killed** | `report: bundle 2, directory_unauthorized false; want 2, true` |
| T3f: O-2 reading (a), directory 0 whenever the run's report is unauthorized | `recorded_authorized_directory_keeps_the_record_raise` | **killed** | `accepted.json names directory 0, want the record's 3` |
| T3g: O-2 reading (b), the record's raise kept whatever the chain base's directory | `recorded_bundle_over_unauthorized_directory_reports_directory_0` | **killed** | `accepted.json bundle 2, directory 2; want 2, 0` |
| T3h: WriteAccepted checking accepted/'s directory under accepted/'s policy | both record cases | **killed by both** | `accepted.json names directory 0, want the record's 3` and `accepted.json bundle 2, directory 2; want 2, 0` |
| T3i: outcome not joining DirectoryUnauthorized | the tracer | **killed** | `apply 3: <nil>, want directory_not_authorized` |
| T3j: state.ErrDirUnauthorized left out of status.go's refusals | `TestStatus/apply_result` | **killed** | `status_test.go:341: applyResult(...)` |
| T3k: the fork comparison removed | `same_version_other_bytes_refused_as_fork` | **killed** | `a same-number directory with other bytes: <nil>, want directory_fork` |
| T3l: the fork reported without the quorum check | `same_version_unsigned_bytes_not_verified` | **killed** | `directory_fork: version 2: ..., want directory_not_verified, not directory_fork` |
| T3m: the standalone acceptance chained to the stored bytes | `new_admins_next_version_accepted_standalone` | **killed** | `bob's directory 3: directory_not_authorized: ...` |
| T3n: the unauthorized case returning today's refusal | `stored_version_above_new_admins_needs_reset`, `rotation_first_then_removed_admin_refused` | **killed, by the first only** | `apply 1: directory_older: ... BundleVersion:1 ...`. `rotation_first_then_removed_admin_refused` **passes** under T3n (see below) |
| T3o: no restore of the saved bundle part (M-2) | `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle` | **killed** | `report: bundle 1, held true; want 2, not held` |

All 15 mutants were killed. Each was restored byte for byte, and `git diff --quiet -- internal/` passed after each. The loop's output is in the session scratch file `mutants-task3.txt`. Each kill is a test failure, not a build failure: the output has no build error.

**How the WriteAccepted mutants were modelled.** WriteAccepted takes only the layout, so reading (a) cannot be expressed inside it. T3f is therefore a two-file patch. WriteAccepted gains a variadic `unauth ...bool` and writes 0 exactly when it is true. Apply passes `r.DirectoryUnauthorized`, the run's report, so the variadic keeps resetdir.go's call building. T3g writes 0 only when there is no record (`chain == stored`). T3h reads `stored.DirectoryUnderPolicy()` instead of the chain base's.

**Why `rotation_first_then_removed_admin_refused` does not kill T3n.** The plan names it as a second killer. Under T3n its second apply returns alice's directory_not_verified as a refusal, so verify takes KRLAlone over accepted/: bundle 2 over alice's directory 1. storedOnly's new check (T3a's line) then sets the flag there. The outcome is the same one the case asserts: the error joins both codes, no principals render, bundle 2 stays and the KRL lands. The two code paths converge in that shape, and only `stored_version_above_new_admins_needs_reset` tells them apart: there the KRL-alone pass keeps bundle 1. The mutant is still killed.

### What was built

- **verify.go.**
  - storedOnly (and so KRLAlone) sets `DirectoryUnauthorized = checkStored(prev, d, prev.policy)` for a stored directory. A stored directory without a parsed policy is stored_state_invalid, because checkStored reads the policy's version.
  - In verifyDirectory's unauthorized branch, after standalone, step b runs `saved := *v` before offeredDirectory. On any error it restores v.Bundle, v.Policy, v.BundleHeld, v.BundleChanged and Next's Bundle, BundleSigs, Policy, PolicySigs and BundleVersion. It then sets `DirectoryUnauthorized = errors.Join(unauth, err)` and returns nil. stored_state_invalid is returned before unauth exists, as before. The authorized branch is unchanged.
  - The fork rule is in offeredDirectory's `newest == storedVersion` case. Equal bodies are a no-op, compared as standaloneDirectory compares them, so a re-signature changes nothing. Other bodies with v.Policy's quorum return ErrDirFork, and otherwise ErrDir.
  - The doc comments of Verify, storedOnly, verifyDirectory and offeredDirectory say so.
- **apply.go.**
  - The no-change branch is taken only while `v.DirectoryUnauthorized == nil`.
  - After candidate, `!v.Changed() && cur != nil && sameBytes(cur, g)` is the no-op: NoOp as the no-change branch sets it, setVersions with cur only when current is the agent's, and `return outcome(v)`. That is before preflightApply, the dry run and the committing sameBytes branch. It does not assign Report.DirectoryUnauthorized, so T3e stays killable (m-3).
  - pollCapture's doc sentence gained "unless it is the newest offered, which is directory_fork or directory_not_verified (F03 (03-08f))".
  - The comment at forward's supersede step, which Run A noted as ahead of the code, is now true: storedOnly carries the flag.
- **policy_change_test.go.**
  - Twelve new TestDirectoryUnderPolicyInForce cases, each with t.Parallel.
  - The helpers `bobDir`, `persistedUnauthorized` (the pre-fix state through LoadStored and Save, with the spool still offering bundle 2 and policy 2), `acceptedSnapshots` (accepted/'s entries and current.json's bytes) and `noPrincipals`.
- **Runbooks** (3878169). Every changed paragraph names its CI tests and says UNVERIFIED on the homelab:
  - enroll-user.md: the hosts' side, install right after the bundle, reset-directory, and the O-1 residual labelled UNVERIFIED;
  - root-ceremony.md: after "Rotate the roots" step 6;
  - signer-install.md: the accepted.json directory-0 note and directory_fork;
  - host-setup.md: the outbox row, the I-2 sentence, the fork rule, the prune paragraph with 6.1 and 6.6 GiB (6.9 GiB after fix round 1, D-3), the record paragraph (O-2 (c)) and the `diverged` item.
- **The todo** stays in pending/ and has a Status section with both lines.

## Task 4: the publish edits, the gates, the PR

Commits:
- 4a1e5a5 `docs(03-08f): add the agent policy-in-force plan at wave 17`, which holds the plan unchanged and the publish edits;
- 561542d `test(agent): mark the per-bundle policy signature reads as test fixtures for gosec (03-08f)`, deviation 6 below.

**Publish edits** (origin/main's values + 1; the guard found 03-09 at `wave: 17` with `depends_on: ["03-08k"]`, as expected):
- ROADMAP: `17/26 plans executed in 25 waves`. The new Wave 17 block holds the 03-08f row, and 03-09 to 03-16 moved to Waves 18 to 25, each "blocked on Wave N-1 completion".
- STATE: `total_plans: 61` and `Plan: 18 of 26`.
- 03-09: `wave: 18` and `depends_on: ["03-08f"]`, and its Task 1 precondition gains the 03-08f-SUMMARY clause beside the five that stay.
- 03-10 to 03-16: waves 19 to 25.
- Both publish checks of Task 4 exited 0.

**Precondition (gofmt).** `grep -q -- '--exec' scripts/linux.sh` exits 0, the normal case since PR #81. Evidence that gofmt runs in WSL's login shell: `command -v gofmt` there prints the Go SDK's gofmt, `gofmt -l . | wc -l` prints 0, and `test -z "$(gofmt -l .)"` exits 0. The gate command ran as written.

**Gates** (the Budget's commands, alone first; session scratch files `gate4-*.txt`):

| Run | Head | internal/agent/apply | Result |
|---|---|---|---|
| alone gate, first run | 47fd8ec | 280.220 s | exit 0 |
| full gate, first run | 4a1e5a5 | 306.832 s | **exit 1**: every test passed, but golangci-lint reported 2 gosec G304 issues in Task 2's test files (deviation 6) |
| alone gate, after the fix | 561542d | **275.251 s** (limit 400 s) | exit 0 |
| full gate, after the fix | 561542d | **335.171 s** (limit 480 s) | exit 0: `go test -race ./...`, `go vet` (plain, e2e, e2e systemdsmoke), gofmt, golangci-lint `0 issues.`, capslock, dep-firewall, testonly-firewall and check-pinned-actions all passed |

**capslock:** no new pair. keyroster-agent has 37 pairs against a baseline of 37, keyroster-agent-fetch 23 of 23, and keyroster-signer 92 of 92. keyroster-agent's EXEC still leaves the module only through internal/agent/execsite.

**PR #82**, https://github.com/Labontese/keyroster/pull/82, opened by keyroster-bot through `scripts/gh-as-bot.sh pr create`, without auto-merge.
- `autoMergeRequest == null` was checked after opening.
- The body and every branch commit message hold no attribution lines (both greps count 0).
- Every branch commit is `Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot`, and SSH-signed.
- **CI on head 561542d:** all 27 checks pass, `pr checks --required --watch` exited 0. Workflow run IDs: 41593450589, 41593450602, 41593450606, 41593450607, 41593450623, 41593450633, 41593450641, 41593450661, 41593450754, 41593450854.
- **build-test** (run 41593450606, job 125775250952; `bash scripts/gh-as-bot.sh run view 41593450606 --job 125775250952 --log`): `ok github.com/Labontese/keyroster/internal/agent/apply 226.924s`, below the 480 s margin. No `--- FAIL` in the log.

**Confidentiality.** Before the push, the full diff against origin/main, the commit messages and the PR body were grepped:
- for private IPs (100.x, 10.x, 192.168.x), the host names of the owner's machines and the private source names: nothing;
- for local paths: only the public repository name.

## Test time (internal/agent/apply under -race)

| Point | Alone (limit 400 s) | Under `./...` (limit 480 s) |
|---|---|---|
| Base, origin/main b1ebff3 | 296.502 s | 330.309 s |
| Task 1, dff4921's tree | 300.933 s | 318.232 s |
| Task 2, b55c264's tree | 329.188 s | 346.190 s |
| Task 3, 941d459's tree (deviation 4) | 291.798 s | 323.579 s |
| Task 4 gates, 561542d | 275.251 s | 335.171 s |

| CI build-test (`./...`, limit 480 s) | internal/agent/apply |
|---|---|
| origin/main b1ebff3 (run 41579130798) | 205.402 s |
| PR #82 at 561542d (run 41593450606) | 226.924 s |

No figure is above its limit. The stop rule never tripped. The local figures vary with machine load, by about 50 s on unchanged code.

## RED evidence, by task

- **Task 1** (tracer and the held_content_refusal assertion): on b1ebff3 with symbol stubs only. See Task 1.
- **Task 2** (15 of 19 cases RED, 4 GREEN controls): on 605a99a with the `State.BundlePolicySigs` field only. See Task 2.
- **Task 3** (11 RED, 1 GREEN control): 4 on origin/main b1ebff3 in a scratch worktree, using no new symbols, and 7 on Task 2's head 06820de in a scratch worktree. See Task 3.

## Mutants

- **Task 2**: 7 mutants. 6 killed. T2b survived and was called equivalent (plan check 3, m-2); it is not, and fix round 1 kills it with `bundle_sigs_never_united`.
- **Task 3**: 15 mutants, all killed. T3n is killed by one of its two named tests.
- **In all** (Tasks 2 and 3): 22 mutant runs. T2b survived and is killed in fix round 1.
- **Fix round 1**: 10 mutants in 13 runs, all killed (see that section).
- **Fix round 2**: 1 mutant in 1 run, killed (see that section).

## Existing tests the change flipped

| Test | Task | Change and reason |
|---|---|---|
| TestApply/torn_accepted_save_never_mixes | 1 | Its rotation keeps `f.policy.Admins`. Under F03, a policy naming bob alone does not authorize directory 1, so the run after the crash would render no principals instead of a byte-equal commit. |
| TestSpoolWindow/held_content_refusal_keeps_the_records_bundle | 1 | One added assertion: readAccepted is bundle 3, directory 0 (O-2 (c), m-1). Its RED read directory 65. |
| TestStatus/apply_result | 1 | Two rows: directory_not_authorized and directory_fork read `refused`. |
| TestSpool/cap_is_what_read_enforces | 2 | `bundle-1.policy.sigs` joins the bundle set. |
| TestFetch/more_repolls_immediately | 2 | The exact spool listing gains `bundle-1.policy.sigs`. |

Task 3 flipped none: its `./...` run and the gates show no `--- FAIL`.

## The threshold argument, and the stored-sigs rule

- **The threshold argument** rests on internal/trust/verify.go, unchanged (see Task 2):
  - line 315 takes both thresholds from the bundles;
  - lines 316 and 319 run requireSigners per namespace;
  - line 232 is the ErrThreshold comparison;
  - CountPinnedSigners, lines 29-62, counts each pinned fingerprint once: lines 44 and 48 check for a byte-equal key, and line 51 verifies over the exact digest under the namespace.
- **The stored-sigs rule.** When the union was needed and neither admitted source passes VerifySuccessor alone, the stored file (the offered one, or the delivered one) may not pass on its own. That is safe. The stored file was admitted by sshsig.ParseAll, so the next hop's plain check fails with ErrThreshold, not with a parse error. It therefore reaches the union with that hop's delivered signatures, and recovers. `malformed_delivered_sigs_not_stored` shows the next hop passing.

## Owner answers to O-1 to O-3, and where they shaped the code

- **O-1 (a), accept the residual.** No code change. Healing is promised only on a run that ends without a Verify or KRL-alone error. enroll-user.md names the residual as UNVERIFIED (T-03-323).
- **O-2 (c).**
  - `(s *Stored) DirectoryUnderPolicy()` (state.go) and WriteAccepted (installed.go) take the chain base, which is the record's base when there is a record and accepted/ otherwise, and write directory 0 only while its directory is unauthorized under its own policy.
  - Pinned by the tracer, `held_content_refusal_keeps_the_records_bundle`, `recorded_authorized_directory_keeps_the_record_raise` and `recorded_bundle_over_unauthorized_directory_reports_directory_0`.
  - Mutants T3d, T3f (reading (a)), T3g (reading (b)) and T3h.
- **O-3 (a), accept the bound.** pruneSpool keeps `bundle-<N>.policy.sigs` exactly while it keeps bundle N (spoolSet), and its doc comment and host-setup.md state about 6.1 GiB kept and 6.6 GiB in all. These figures are computed from the caps, not measured. Fix round 1 corrects the total to about 6.9 GiB: the per-poll term missed the second copy of each bundle item's policy signatures (D-3, arithmetic in that section).

## Requirements

`requirements-completed` is empty. AGENT-03 and AUTHZ-02 were completed by earlier plans; this plan hardens them.

## Tracking updates

They were applied by hand, in the shape 03-08k's PR used: ROADMAP's 03-08f row is checked and its count is `18/26 plans executed in 25 waves`. STATE gets stopped_at, `completed_plans: 53`, `Plan: 19 of 26`, a metrics row and three decisions. No requirement is marked.

## Deviations (Run A)

1. **[Rule 1, test oracle] TestFetch/more_repolls_immediately changed** (Task 2). This existing test lists the spool exactly, and the per-bundle file is now in that list. The plan's Task 2 named no changed fetch test. The assertion was extended by the one file name, and nothing else changed.
2. **A stronger tracer check** (Task 1, not a behaviour change). With `f.rotation`, bundle 2 keeps bundle 1's CA set, so "current's user_ca_keys comes from bundle 2" would compare identical files. The tracer therefore uses the test helper `f.rotationNext`, whose bundle 2 adds a next user CA (seedKey 31), and it checks that line in user_ca_keys. The swap is then a mixed one, with principals dropped, a CA added and a new KRL, and it goes through Intermediate and the widening wait.
3. **The comment at forward's supersede step is ahead of the code** (Task 1, as the plan words it). The comment says that pollCapture's state.KRLAlone branch carries the flag through storedOnly, but storedOnly gains the flag only in Task 3.
4. **A timing-sensitive case failed once under load** (Task 2). TestFetch/more_repolls_immediately has a 900 ms bound, and one verify run took 906.8 ms while the machine was loaded. The rerun and both test-time runs passed. No code change was made for it.

Everything else ran as the plan wrote it, and the stop rule never tripped.

## UNVERIFIED (Run A)

- **CI.** Nothing of this branch has run in CI yet; the branch is not pushed. Every figure and result here is local, from WSL.
- **A crash between forward's record write and WriteAccepted** (WriteAccepted's doc comment, m-5). No test exercises it; the sentence is reasoning from the code.
- **The fill of `g.Host` in engine.render while unauthorized.** It runs in the tracer, but no test asserts the host name it fills.
- **storedPolicySigs's last fallback to pol.Sigs.** It is unreachable when the union differed from pol.Sigs, and no test reaches it.
- **pruneSpool's bound of about 6.1 GiB kept and 6.6 GiB in all** (about 6.9 GiB after fix round 1, D-3). It is computed from the caps, not measured.

## Deviations (Run B)

1. **Test construction: `same_capture_hold_then_dropped` starts from a directory 1 with role:ops and role:evil.** Alice's directory 2 holds only role:evil, so it narrows directory 1. The first draft started from directory 1 with role:ops alone, so directory 2 widened, and apply 1 went into a widening wait. That wait's poll verified the same capture again under the pending target (bundle 1 over alice's 2), took bundle 2 and superseded the target within the same run. It reported BundleVersion 2 with DirectoryUnauthorized, which is fail-closed, but it is not the two-apply shape the plan describes. With a narrowing directory 2, apply 1 holds and renders alice's directory, and apply 2 moves to bundle 2, as written. No code changed for it.
2. **signer-install.md step 2 of "Which hosts saw a lost version"** now lists `bundle-N.policy.sigs` beside `bundle-N.json` and `bundle-N.json.sigs`. The plan did not name this edit. The step enumerates a lost bundle's spool files, and this plan adds one. A leftover file would be harmless: it holds only signatures, and pruneSpool removes an orphan. The list is now complete.
3. **T3n is killed by one of its two named tests.** See Task 3's mutants: `rotation_first_then_removed_admin_refused` reaches the same fail-closed outcome through KRLAlone and storedOnly's check.
4. **The fork messages were reworded while the alone timing run was in progress.** This is text only; see Task 3's test time. The final verify ran on the committed tree.
5. **The fork error at an equal version says "stored version", not "accepted version",** because the stored version is the chain base's, which is the record's on the record path.
6. **[Rule 3, lint] Two gosec G304 reports in Task 2's test files** (`fetch_test.go:582` and `spool_test.go:307`, `os.ReadFile` of a path built in the test). Run A's verify ran go vet and gofmt but not golangci-lint, so Task 4's first full gate was the first lint run. Both lines got the repository's convention, `//nolint:gosec // test fixture`, in commit 561542d. Both gates were then run again on 561542d. Only comments changed.
7. **The tracking updates were made by hand**, in the shape 03-08k's PR used, not through the gsd-tools state verbs. This keeps the publish checks' formats (`N/26 plans executed in 25 waves`, `Plan: N of 26`) exactly as the repository writes them.
8. **No plan ledger from Run A.** `plan_head_before` is the branch base b1ebff3, origin/main when Task 1 created the branch. `commits: 9` is `git rev-list --count b1ebff3..561542d`, measured before this final docs commit, which is the tenth.

Run A's UNVERIFIED item "CI" no longer holds: PR #82's CI ran all 27 checks green on 561542d.

## UNVERIFIED (Run B)

- **Converted refusals that no case pins.** These take the same step-b branch as the refusals the cases pin: directory_older (`stored_version_above_new_admins_needs_reset`), the chain refusal (`unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle`), and since fix round 1 directory_installation, directory_chain_gap and a directory file that holds another version (`unauthorized_hold_then_other_refusals_keep_the_verified_bundle`):
  - directory_not_verified for a parse or CheckPolicy cause.
- **The fork rule at an unapplied record's directory version.** No test offers a same-number directory there; it is reasoned from the code (the stored version is the chain base's).
- **A KRL signed by a new ops key in the unauthorized shape** (host-setup.md's I-2 sentence). No test builds it; it is reasoned from krlStep.
- **The O-1 residual** (owner decision O-1 (a)). No test builds the state from before this change together with a refused KRL (enroll-user.md labels it).
- **The `diverged` item's advice** to read the directory version from status.json while accepted.json reads 0. No test reads status.json for it.
- **The homelab.** Every runbook note is run in CI only; Phase 3 runs no admin-set change and no root rotation of enrolled hosts.

## Handoff to Task 3 (from Run A to Run B, kept as written)

For Run B, a fresh executor resuming at Task 3 (plan "What to read", Run B).

**Branch and commits.**
- The branch is `p03/08f-agent-policy-in-force`, from origin/main b1ebff3.
- Run A's commits, oldest first:
  - dff4921 `fix(agent): check the stored directory under the policy in force (F03)` (Task 1 code);
  - 605a99a `docs(03-08f): record the tracer's evidence` (Task 1 draft);
  - **b55c264** `fix(agent): verify a root rotation that keeps the policy with the signatures delivered per bundle (F02)`, Task 2's code commit. Task 3 takes its REDs on Task 2's head, which is this draft's commit `docs(03-08f): record F02's evidence`. It holds the same code as b55c264.
  - That draft commit is the last commit of Run A.
- The plan file lies untracked at `.planning/phases/03-linux-agent-and-revocation/03-08f-PLAN.md`; Task 4 commits it. Nothing has been pushed.

**Test time (internal/agent/apply under -race, locally in WSL).** Task 3's stop rule is above the alone base + 120 s, which is **416.5 s**, or above 400 s, whichever comes first; so 400 s binds. Under `./...` the limit is 480 s.

| Point | Alone (limit 400 s) | Under `./...` (limit 480 s) |
|---|---|---|
| **Base**, origin/main b1ebff3, before any edit | **296.502 s** | 330.309 s |
| Task 1, dff4921's tree | 300.933 s | 318.232 s |
| Task 2, b55c264's tree | 329.188 s | 346.190 s |

| CI (build-test, `./...` under -race; limit 480 s) | internal/agent/apply |
|---|---|
| origin/main b1ebff3 (CI run 41579130798, job build-test 125729546783; `bash scripts/gh-as-bot.sh run view 41579130798 --job 125729546783 --log`) | 205.402 s |

The local figures vary with machine load (03-08k saw 274 s to 356 s on near-identical code). Task 2's alone figure is about 33 s above the base, about 70 s below 400 s.

**Test helpers Task 3 reuses, all in internal/agent/apply/policy_change_test.go.**
- `adminRemoved(t) *adminRemovedHost` is the unauthorized-state helper, with steps 1 to 3 of the tracer.
  - It returns the embedded `*testHost`, plus `bob` (policy 2's only admin, seedKey 11), `next` (bundle 2's next user CA, seedKey 31), `b2` (bundle 2), `serial` (4242), and `r` and `err` (the third apply's report and error).
  - The spool is in `<state>/spool` (spoolInState), so readAccepted works.
  - `h.dirs` holds directories 1 and 2, the second alice's. After it, accepted/ holds bundle 2 over alice's directory 2, current has no principals, and readAccepted's Directory is 0.
  - Bob's same-number directory is `s := h.spec(...); s.signer = a.bob; h.f.directory(h.dirs[0].Body, s)`.
- `(f *fixture) rotationNext(prev, prevDoc, prevPolicyDoc, prevPolicy, admins, issuedAt, next)` is f.rotation with a next user CA added to the successor bundle.
- `rootSigs(t, namespace, doc, signers...)` gives the concatenated SSHSIG blocks of the signers.
- `(f *fixture) rootSuccessor(prev, prevDoc, roots, threshold, issuedAt, signers...)` is a successor over a new root set with the fixture's policy unchanged.
- `rootHop{roots, threshold, bundleBy, policyBy}` and `offerHops(t, h, from, prevDoc, hops...)` offer root hops, each with its delivered `bundle-<N>.policy.sigs`, and return the newest bundle and its bytes.
- `rootKeys(t)` gives C, D, E, B and X: seedKey 21, 22, 23 and 24, and X (25), which is no root.
- `rotatedHost(t)` is an installed host offered bundle 2 over {C}, with a KRL revoking serial 31. `threeHops(t)` is an installed host offered {A}→{C}→{D}→{E}.
- `mustAcceptedBundle(t, h, want) *state.Stored` requires accepted/ to hold bundle want and returns it.
- seedKey values in use: 11 (bob), 21-25 (roots and X), 31 (next CA). The other test files already use 12, 13 and 21 (window_test.go's policyRotated), so prefer fresh seeds for new keys.

**Code Task 3 builds on.**
- verifyDirectory splits into `checkStored`, `standaloneDirectory` (step a) and `offeredDirectory` (today's logic, step b). The unauthorized branch is in verifyDirectory: `if unauth == nil { return v.offeredDirectory(...) }`, then standalone, then offeredDirectory with `v.DirectoryUnauthorized = unauth` when nothing is accepted.
  - Task 3's conversion of refusals belongs where verifyDirectory returns offeredDirectory's error, with the save and restore of the bundle part around it (M-2).
  - The fork rule at an equal version belongs in offeredDirectory's `case stored != nil && newest == storedVersion` branch, which is unchanged.
- storedOnly does not yet carry the flag.
- forward has no forced render for an unchanged capture: the `!v.Changed()` branch still returns at once.
- `Report.DirectoryUnauthorized` is set after Verify, after each krlAlone pass and at the supersede step (m-3's mutant removes the assignment after Verify).

**Existing tests changed in Run A, with their reasons.**
- TestApply/torn_accepted_save_never_mixes: its rotation keeps `f.policy.Admins`, so directory 1 stays authorized under policy 2 (Task 1).
- TestSpoolWindow/held_content_refusal_keeps_the_records_bundle gained the assertion that readAccepted reads Bundle 3 and Directory 0 (Task 1, m-1). Its RED read directory 65.
- TestStatus/apply_result gained two rows (Task 1).
- TestSpool/cap_is_what_read_enforces gained `bundle-1.policy.sigs` in the bundle set (Task 2).
- TestFetch/more_repolls_immediately's spool listing gained `bundle-1.policy.sigs` (Task 2, deviation 1).

**Expected survivors confirmed by the full alone run on dff4921 and on b55c264.**
- TestApply/catch_up_across_policy_rotation;
- TestSpoolWindow/policy_rotation_below_the_recorded_bundle and older_bundle_at_the_window_boundary;
- TestSpoolWindowWideningWait's recordAbove rows;
- TestKRLSigner's heldShape, heldWait and recordBelowWait cases;
- TestWriteAccepted, and the TestSpoolWindow cases that read accepted.json (bundleRecorded, recordedWindow, fetcher_cursor_follows_the_record).

**Mutant tooling.** The mutant loop is scripted in Run A's session scratch directory, which a fresh run may not have. It takes a patch per mutant (python, from `(path, old, new)` triples: write the mutated file, take `git diff`, restore with `git checkout`). The loop applies each patch with `git apply`, runs `go test -race -count=1 -v -run '<anchored>' <pkg>` through scripts/linux.sh, records killed or survived from `--- FAIL`, `FAIL` or `panic` lines, restores with `git checkout -- <files>`, and requires `git diff --quiet -- internal/`.

**Open questions for the owner.** None from Run A.

## Pre-merge review fix round 1

PR #82's pre-merge review confirmed seven findings and refuted none. The owner decided D-1 to D-4; all four are fixed here, on the branch after dac2244.

| Item | Commit | What changed |
|---|---|---|
| D-1 | 255b285 `fix(agent): keep last-good's principals only under a policy that authorizes their source` | state.go `(*Stored).PrincipalsUnder` and its policy comparison; apply.go `engine.accepted` and the check in `engine.render` before RenderFallback; new lastgood_test.go |
| D-1 | a77151a `fix(agent): keep kept principals across a policy that only adds admins` | the comparison becomes `coversAuthority` (below); the control gains a step that adds an admin; host-setup.md and enroll-user.md follow |
| D-2 | ad103cb `fix(agent): report bundle_held from a superseding capture that moved the bundle` | apply.go's supersede step; policy_change_test.go's new and changed cases |
| D-3, D-4 and the D-1 runbook text | 9342e14 `docs(agent): correct the spool bound, the fork rule and the kept-principals rule` | fetch.go's pruneSpool doc comment, host-setup.md, enroll-user.md |

### D-1: last-good's principals and the policy in force

**The defect.** RenderFallback kept last-good's principals for `host_keys_rotated`, `host_keys_disagree` and a host with no accepted directory, whatever the policy in force. After an admin-set change, the host could therefore keep principals rendered from the removed admin's directory, with no error. An example: last-good renders alice's role:evil, and one capture brings policy 2 (bob only) with bob's directory 2 listing the host under another key. Bob's directory is taken standalone, so DirectoryUnauthorized stays nil, and every later idle run keeps role:evil.

**The fix.** Before RenderFallback, engine.render checks accepted/ (`e.accepted`, which forward loads) under v's policy with `(*Stored).PrincipalsUnder`. At rest, accepted/ is the state last-good was committed with, and the commit marker keeps the two together. When the check fails, last-good's principals files are dropped from the generation RenderFallback reads. The fallback then renders the trust files with the KRL, and the host status is still reported. The rule:

- last-good's record names no kept status, so it rendered its principals from accepted/'s directory: kept only while that directory carries the policy's admin quorum and fits it (checkStored);
- otherwise their source is not at hand. That covers a record with `host_keys_rotated` or `host_keys_disagree`, an unreadable record, and accepted/ without a directory (F08, after reset-directory). Here they are kept only while the policy authorizes every directory accepted/'s policy does (`coversAuthority`). That means:
  - the same admin quorum;
  - every admin key of accepted/'s policy among the policy's admins, compared as key strings, so another spelling of a key fails closed;
  - the same CA profiles.

  Those are the only fields directory.VerifySignatures and directory.CheckPolicy read, and VerifySignatures counts distinct pinned admin keys. So a directory that accepted/'s quorum signed carries the new policy's quorum too. The invariant behind this is that kept principals' source is always authorized under accepted/'s policy, for state this agent version committed (fix round 2, R2-5: a host upgraded from main can carry state it does not hold for). 255b285 first required equal admin lists. That dropped kept principals when an admin was only added, so a77151a relaxes it to the covering rule;
- a nil accepted/, policy or target policy is a failure, so the fallback keeps nothing.

**Every keepPrincipals path, each RED on dac2244 at the principals assertion** (all the case's earlier assertions passed there). Eight cases are in `TestLastGoodPrincipalsUnderPolicyInForce`:

| Case | Path | RED on dac2244 |
|---|---|---|
| `recovery_with_rotated_host_keys_keeps_no_principals` | the reproduced shape: standalone recovery, then host_keys_rotated, then an idle no-op | `apply: current holds a principals file for deploy: [role:evil]` |
| `recovery_with_disagreeing_host_keys_keeps_no_principals` | the same capture, with host_keys_disagree | `[role:evil]` |
| `record_path_rotated_host_keys_keeps_no_principals` | VerifyAhead: the record's directory (bob's 3), which policy 2 authorizes, is the chain base, while last-good is alice's | `apply 2: ... [role:evil]` |
| `widening_wait_supersede_keeps_no_principals` | VerifyAfter: the pending target (bob's 2) is the chain base during the wait, while last-good is alice's | `[role:evil role:ops]` |
| `reset_directory_then_rotation_keeps_no_principals` | RenderFallback's no-directory keep (F08) after reset-directory | `[role:evil]` |
| `kept_principals_then_admin_removed_keeps_none` | a chained keep: last-good's principals predate accepted/'s still-authorized directory | `policy 3: ... [role:evil]` |
| `authorized_directory_across_rotation_keeps_principals` (control) | a rotation that keeps alice, with her directory listing the host under another key | PASS (keeps role:ops) |
| `kept_principals_across_rotations_keeping_or_adding_admins_stay` (control, added after the RED run) | a chained keep across a rotation that adds bob, then the F08 keep after reset-directory across a rotation that keeps alice and bob | not run on dac2244; passes on 255b285 (then without the added admin) and on a77151a |

The RED run used a scratch worktree at dac2244 holding only the new test file. Its output is in the session scratch file `red-d1.txt`. GREEN: all eight pass on a77151a, and the full local gate passes there (see the test time below), so no existing test flipped.

### D-2: test gaps and the stale flag

- **(a) M-2's restore.**
  - `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle` now builds bundle 2 with `f.rotationNext` and checks that user_ca_keys holds bundle 2's next CA, through the new helper `holdThenRefused`.
  - `unauthorized_hold_then_other_refusals_keep_the_verified_bundle` adds three shapes, each holding the capture at bundle 1 first:
    - `directory_installation`, with a valid-format foreign ID;
    - `directory_chain_gap`;
    - `directory_holds_another_version`.
  - All four pass on dac2244, as expected, because the production restore is correct. The evidence is mutant D2a below, run against each of the four separately and killed by each.
- **(b) T2b.** `TestRootRotationUnchangedPolicy/bundle_sigs_never_united` puts C's policy-namespace signature only in `bundle-2.json.sigs` and expects bundle_not_verified, with accepted/ at bundle 1. It passes on dac2244. T2b (mutant D2b) is killed. The Task 2 mutant table and the T2b paragraph are corrected above.
- **(c) The widening directory 2 in the rotation capture.** `widening_directory_with_rotation_supersedes_into_bundle_2` covers that shape. Directory 1 is [role:ops], and one capture offers alice's [role:ops, role:evil] together with bundle 2 (policy 2: bob). The case asserts:
  - the apply returns directory_not_authorized;
  - BundleVersion is 2, with an intermediate and a wait;
  - there are no principals, and bundle 2's next CA is in user_ca_keys;
  - role:evil is never in current at any sleep of the wait;
  - neither the report nor status.json says bundle_held.

  RED on dac2244, only on the flag: `the report says a bundle is held while bundle 2 is in force`, and status.json had `"bundle_held":true`. Every fail-closed assertion already passed there.
- **The fix.** At the supersede step, fix round 1 assigned `e.report.BundleHeld = tv.BundleHeld` only when `tv.BundleChanged`. Its reasoning was that a superseding capture that moved the bundle decided again whether a newer one waits, and that only a KRL-alone one did not. That missed a poll that holds at the pending target's own bundle (k=0). Such a poll moves only the directory and leaves BundleChanged false while a newer bundle waits. Fix round 2 (R2-1) widens the guard to `tv.BundleChanged || tv.DirectoryChanged`. The false side is now a poll that moved only the KRL: a KRL-alone Verified, or a full verification whose capture brings only a newer KRL over the target's bundle and directory. Neither can carry a new hold, because a hold needs a newest directory other than the target's: taken, it moves the directory; refused, the hold is undone. So the earlier answer stands.
- **The KRL-alone refresh (apply.go, forward's loop) is left unchanged.** There the Verified is KRL-alone over accepted/: the bundle in force is accepted/'s, and a bundle the capture held still waits, so the flag the capture set is still accurate. No case showed a wrong status there.

### D-3: the spool bound, recomputed from the caps

- **Kept.** 1025 versions per kind: the newest at or below the accepted one, plus keepAbove = 64 x 16 = 1024 above it. Per version:
  - a bundle set of 3 MiB: `bundle-N.json`, its `.sigs` and `bundle-N.policy.sigs`, each at most spool.MaxBundle, 1 MiB;
  - a policy set of 2 MiB;
  - a directory set of 1 MiB + 64 KiB (wire.MaxDirectory, wire.MaxDirectorySigs).

  That is 6.0625 MiB a version, and 1025 x 6.0625 = 6214.1 MiB. One KRL set adds 4 MiB + 4 KiB + 16 KiB. **About 6218 MiB, 6.07 GiB.**
- **One poll.** 64 answers (MaxAgentStateRounds), each at most 8 MiB of JSON (MaxAgentStateResponse).
  - Byte fields are base64, so one answer carries at most 6 MiB of document bytes.
  - writeState writes each bundle item's PolicySigs twice, as `policy-V.json.sigs` and `bundle-N.policy.sigs`, which adds at most another 6 MiB.
  - So one answer writes at most 12 MiB, and one poll at most 768 MiB, **0.75 GiB**.
- **In all,** at most 6.07 + 0.75 = 6.82 GiB. The comment and host-setup.md say "about 6.9 GiB", 6.1 + 0.75 rounded up, as an upper bound. The earlier 6.6 GiB counted the poll at 512 MiB, once.

No code changed for D-3. The figure is computed, not measured.

### D-4: the runbook fork rule

- host-setup.md: directory_fork applies while the host's directory is authorized by the policy in force. While it is not (directory_not_authorized), a directory at the same number signed by the new quorum is taken standalone (enroll-user.md).
- enroll-user.md: "the first directory" now reads "the newest directory", because standaloneDirectory scans from the newest down.

These are doc-only, so there is no RED.

### Mutants (fix round 1; the same scripted loop, each applied with `git apply` to a77151a, the final code, run against its named test with an anchored `-run` under -race, restored with `git checkout`, then `git diff --quiet -- internal/`)

| Mutant | Run against | Result | Failing lines |
|---|---|---|---|
| D1a: the PrincipalsUnder check dropped in engine.render | all of `TestLastGoodPrincipalsUnderPolicyInForce` | **killed** | the six D-1 REDs' `current holds a principals file for deploy: [role:evil]` lines |
| D1b: PrincipalsUnder without checkStored | the four recovery, record and wait cases | **killed by all four** | `[role:evil]` / `[role:evil role:ops]` |
| D1c: PrincipalsUnder without the coversAuthority check | `reset_directory_then_rotation_keeps_no_principals`, `kept_principals_then_admin_removed_keeps_none` | **killed by both** | `apply: ... [role:evil]`, `policy 3: ... [role:evil]` |
| D1d: the record's kept status ignored (`rendered = true`) | `kept_principals_then_admin_removed_keeps_none` | **killed** | `policy 3: ... [role:evil]` |
| D1e: coversAuthority replaced by an equal policy version | `kept_principals_across_rotations_keeping_or_adding_admins_stay` | **killed** | `policy 2, bob added: ...; want role:ops kept` |
| D1f: the admin subset replaced by equal admin lists (255b285's rule) | `kept_principals_across_rotations_keeping_or_adding_admins_stay` | **killed** | `policy 2, bob added: ...; want role:ops kept` |
| D1g: the admin subset reversed (the new admins among the accepted ones) | `kept_principals_then_admin_removed_keeps_none` | **killed** | `policy 3: ... [role:evil]` (policy 3's {bob} is a subset of policy 2's {alice, bob}) |
| D2a: the partial restore (BundleHeld and BundleChanged restored, not v.Bundle and v.Policy) | each of the four M-2 cases, separately | **killed by each** | `current's user_ca_keys is not bundle 2's` |
| D2b: T2b, the bundle signatures added to the union | `bundle_sigs_never_united` | **killed** | `apply: <nil>, want bundle_not_verified, policy (new roots) signed by 0 of 1` |
| D2c: the supersede step's bundle_held assignment dropped | `widening_directory_with_rotation_supersedes_into_bundle_2` | **killed** | `the report says a bundle is held while bundle 2 is in force` and the status.json line |

All 10 mutants were killed, in 13 runs on a77151a. D1a to D1e and D2a to D2c were also killed on ad103cb, with D1c and D1e then aimed at 255b285's equality rule. Each was restored byte for byte, and `git diff --quiet -- internal/` passed after each. No kill is a build failure. The loop's output is in the session scratch files `mutants.txt` (ad103cb), `mutants2.txt` and `mutants3.txt` (a77151a).

### Test time (internal/agent/apply under -race)

| Point | Alone (limit 400 s) | Under `./...` (limit 480 s) |
|---|---|---|
| Task 4 gates, 561542d | 275.251 s | 335.171 s |
| Fix round 1, 9342e14 (before a77151a) | 304.566 s | 398.781 s |
| Fix round 1, a77151a (the final code) | 353.028 s | 318.387 s |

No figure is above its limit. The two fix-round runs differ by about 50 s each way on near-identical code, which is the machine-load variance noted above. The final full gate on a77151a passed in full: go test -race ./..., go vet (with the e2e tags), gofmt (it printed its path, then GOFMT_OK), golangci-lint (0 issues), capslock (92, 37 and 23 pairs, each equal to its baseline), dep-firewall, testonly-firewall and check-pinned-actions.

### Deviations (fix round 1)

1. **D-1's check reads accepted/, not a Verified flag set by verifyDirectory.** The owner suggested recording in Verified that the chain base's directory was unauthorized and skipping the keep when it is set. Two paths make the chain base differ from the state last-good was committed with, and a flag on the chain base misses both:
   - the unapplied record (VerifyAhead);
   - a widening wait's poll (VerifyAfter, VerifyAheadAfter).

   `record_path_rotated_host_keys_keeps_no_principals` and `widening_wait_supersede_keeps_no_principals` show both, RED on dac2244. The check is therefore anchored on accepted/ in engine.render, the one place every render passes through: forward's and pollSpool's candidate. In the plain Verify path the chain base is accepted/, so the two rules agree there. The owner's rule is the one applied: last-good's principals are never kept when the target policy does not authorize their source.
2. **D-1 also covers the F08 keep and the chained keep (owner question, not blocking).** Both were RED on dac2244, and the cover is fail-closed. It narrows one shape the owner's constraint ("a host whose directory stays authorized keeps today's fallback behaviour") might be read to protect: a host whose kept principals predate its accepted directory (record status host_keys_rotated or host_keys_disagree), or a host after reset-directory. Such a host now drops its kept principals on a policy change that does either of these, even when its accepted directory stays authorized:
   - removes an admin of the accepted policy;
   - changes the admin quorum or the CA profiles.

   Those are the changes under which the source of those principals cannot be shown to be authorized. A rotation that keeps or only adds admins keeps them (`kept_principals_across_rotations_keeping_or_adding_admins_stay`). The common case keeps today's behaviour: there the principals were rendered from the authorized accepted directory (`authorized_directory_across_rotation_keeps_principals`). No existing test flipped. **The owner accepted this narrowing on 2026-11-03** (fix round 2), so the chained case keeps the `kept_principals_then_admin_removed_keeps_none` behaviour.
3. **D-2 (c): the guard at the supersede step, and the KRL-alone refresh left unchanged.** See D-2 above. Fix round 2 widens the guard (R2-1).
4. **D-1's log line.** The fallback's warning used to say "kept as last-good's" from the host status alone. It now says "emptied" when the check dropped them, and a separate WARNING names the reason.

### UNVERIFIED (fix round 1)

- **The supersede guard's false side.** When a poll that moved only the KRL supersedes, the earlier bundle_held stays. That is a KRL-alone Verified, or a full verification whose capture brings only a newer KRL over the target's bundle and directory. No test builds a held pending target superseded by such a poll. (Corrected in fix round 2. This item first named the KRL-alone poll alone, and round 1's guard also left a poll that moved only the directory on this side; see R2-1.)
- **PrincipalsUnder's fail-closed edges in render.** No test exercises an unreadable last-good record (treated as kept principals) or a nil accepted/.
- **coversAuthority for a quorum-only or CA-profile-only change.** The cases remove or add an admin, or keep all three. A change of only the quorum or only the profiles is reasoned from the code.
- **The D-1 log lines.** No test reads them.
- The converted refusals still not pinned stay on Run B's list: directory_not_verified for a parse or CheckPolicy cause.
- **The homelab.** As before, Phase 3 runs no admin-set change of enrolled hosts.

## Pre-merge review fix round 2

The check of fix round 1 judged D-1 correct, with no fail-open path. It upheld four low items, split two and refuted none. The owner accepted fix round 1's deviation 2 and decided R2-1 to R2-5, all in this round, on the branch after 052da53.

| Item | Commit | What changed |
|---|---|---|
| R2-1 | 93690d3 `fix(agent): report bundle_held from a superseding poll that moved the directory` | apply.go's supersede guard; the new case in policy_change_test.go |
| R2-1 | 4722324 `docs(agent): describe the supersede guard's false side as a KRL-only move` | the apply.go comment at that guard |
| R2-2, R2-3 | dbf8e14 `docs(agent): state the kept-host leg and the standalone-directory conditions` | host-setup.md, enroll-user.md |
| R2-4, R2-5, the owner's acceptance | the commit that records this section | this SUMMARY. The PR #82 body was edited too; that edit has no commit. |

### The owner's acceptance of fix round 1's deviation 2

Accepted on 2026-11-03. A host whose principals were already kept, because its record says `host_keys_rotated` or `host_keys_disagree` or because it ran reset-directory, drops them on a policy change that does any of these, even when its accepted directory stays authorized:

- removes an admin;
- changes the admin quorum;
- changes the CA profiles.

A policy that only adds admins keeps them. Deviation 2 above now records this.

### R2-1: bundle_held after a poll that held at the target's bundle

**The defect.** Fix round 1's guard, `if tv.BundleChanged`, missed a superseding poll that holds at the pending target's own bundle.
- Forward waits to widen at bundle 2, which is not held. Policy 2 names alice and bob, and bob's directory 2 [role:ops, role:new] widens.
- The wait's poll brings bundle 3 (policy 3: bob alone) and alice's directory 3 [role:ops].
- Only policy 2 authorizes alice's directory 3. offeredDirectory therefore holds at step 0 (holdBundle(0)), which sets BundleHeld true and leaves BundleChanged false, and the directory supersedes the target.
- The report and status.json said bundle_held false, with bundle 2 and directory 3, while bundle 3 waits.

This was operator-visible only: the fail-closed behaviour was intact.

**The case.** `TestDirectoryUnderPolicyInForce/widening_wait_superseded_into_a_hold_at_its_bundle` builds that shape from the existing helpers, `f.rotation` twice. The poll's state is written at the wait's first sleep. The case asserts:
- the apply returns nil, after a poll, with bundle 2 and directory 3;
- the report says bundle_held;
- status.json has `"bundle_held":true`.

**RED on 052da53**, with only the test file changed and apply.go as on the branch head:
- `policy_change_test.go:650: bundle 3 waits (the poll held at bundle 2), but the report says bundle_held false`;
- `policy_change_test.go:653: status.json (<nil>) does not say a bundle is held while bundle 3 waits`, with status.json reading bundle 2, directory 3 and no bundle_held.

`widening_directory_with_rotation_supersedes_into_bundle_2` passed in the same run. The output is in the session scratch file `red-r2-1.txt`.

The first draft of the case also asserted `r.Intermediate != 0`, copied from the widening case. On unchanged code that assertion failed first, with Intermediate 0. The last transition, to alice's directory 3 [role:ops], does not widen, so it reports no intermediate. The assertion was dropped before the fix, and `polled` shows that the wait ran. The RED above is the final test's.

**The fix.** The guard is `if tv.BundleChanged || tv.DirectoryChanged`. The comment and D-2 (c)'s fix paragraph above now describe the false side correctly: a poll that moved only the KRL. That is a KRL-alone Verified (state.KRLAlone, storedOnly, or krlAlone after a refused candidate), or a full verification whose capture brings only a newer KRL over the target's bundle and directory. KRL-alone supersedes are unchanged, as decided. The KRL-alone refresh in forward's loop is unchanged too.

**GREEN on 93690d3.** All 16 top-level cases of `TestDirectoryUnderPolicyInForce` pass under -race, `widening_directory_with_rotation_supersedes_into_bundle_2` among them (session scratch file `green-r2-1.txt`).

**Mutant.** The loop is fix round 1's: `git apply`, an anchored `-run` under -race, then `git checkout` and `git diff --quiet -- internal/`.

| Mutant | Run against | Result | Failing lines |
|---|---|---|---|
| R2a: the guard reverted to `tv.BundleChanged` only (fix round 1's) | `widening_wait_superseded_into_a_hold_at_its_bundle`, `widening_directory_with_rotation_supersedes_into_bundle_2` | **killed** by the new case; the widening case passes | the two RED lines above |

It was run on 93690d3 and restored byte for byte (session scratch file `mutants.txt`). D2c, the assignment dropped, was not run again. The assignment it removes is unchanged, and the widening case still pins it.

### R2-2 and R2-3: the runbooks

- **R2-2.** The host_keys_rotated bullet in host-setup.md and the kept-principals paragraph in enroll-user.md now give the second leg of the rule. A host that already kept its principals (its last status was `host_keys_rotated` or `host_keys_disagree`) keeps them only while the new policy keeps three things from the accepted policy:
  - the same admin quorum;
  - the same CA profiles;
  - every admin of the accepted policy.

  This matches the reset-directory sentence. Both runbooks name `kept_principals_then_admin_removed_keeps_none`.
- **R2-3.** Both runbooks now say that standalone recovery takes "the newest directory the new admins sign that names this installation and fits the policy (at the stored version only with other bytes)". host-setup.md adds what happens to such a directory that does not fit: it is refused as `directory_fork` or `directory_not_verified`, joined to `directory_not_authorized`, and the KRL still lands.

These are doc-only, so there is no RED.

### R2-4: counts and the PR body

- The Mutants overview now says 10 mutants in 13 runs for fix round 1, and 1 mutant in 1 run for fix round 2.
- The PR #82 body was edited with `scripts/gh-as-bot.sh pr edit 82 --body-file`. It keeps its structure and now says:
  - no mutant survives: T2b is not equivalent, and `bundle_sigs_never_united` kills it;
  - the current case counts: `TestDirectoryUnderPolicyInForce` 16, `TestRootRotationUnchangedPolicy` 12, `TestLastGoodPrincipalsUnderPolicyInForce` 8;
  - a short paragraph on the kept-principals rule (D-1) and the corrected spool bound (about 6.9 GiB);
  - the round-2 changes.

### R2-5: a known residual from an upgrade (not wider than main)

The rule that kept principals' source is authorized under accepted/'s policy holds by induction only for state this code wrote. Every keep is checked, every render comes from a verified directory, and finishCommit moves accepted/ and last-good together. Main has no F03 and keeps principals unconditionally.

So a host upgraded from main can keep principals that main had already chain-kept from a directory the policy in force no longer authorizes. An example:
- main kept alice's role:evil under `host_keys_rotated`, then committed policy 3 (bob alone) with bob's directory 3, which policy 3 authorizes;
- after the upgrade, coversAuthority(policy 3, policy 3) holds, so role:evil stays.

The reset-directory variant is the same. accepted/ then has no directory, and the comparison is of the accepted policy with itself.

This is no wider than main, which keeps those principals the same way. No host is known to be in this state, because Phase 3 runs no admin-set change of enrolled hosts. No code changed for it.

**Remedy for an operator:** publish a directory that names the host under its current host keys. Its next run renders from that directory, so the kept principals are replaced. UNVERIFIED: no test builds main-written state and runs this remedy.

### Test time (internal/agent/apply under -race), fix round 2

| Point | Alone (limit 400 s) | Under `./...` (limit 480 s) |
|---|---|---|
| Fix round 2, 4722324 (the final code) | 335.093 s | 368.472 s |

No figure is above its limit. The full gate on 4722324 passed in full: go test -race ./..., go vet (with the e2e tags), gofmt (GOFMT_OK), golangci-lint (0 issues), capslock (92, 37 and 23 pairs, each equal to its baseline), dep-firewall, testonly-firewall and check-pinned-actions. Session scratch files `time-alone.txt` and `gate-full.txt`.

### Deviations (fix round 2)

1. **The guard's false side covers more than the KRL-alone Verifieds.** The decision named KRL-alone supersedes as the side that stays unchanged. A full verification whose capture brings only a newer KRL over the target's bundle and directory moves neither flag either, so it is on the false side too. The comment (4722324) and this SUMMARY say so. Such a poll cannot carry a new hold. This is a wording precision, not a code change: the guard is exactly the decided one.
2. **The test-time gate was restarted.** The first gate run was stopped during the alone run, before it recorded a time, when the comment was corrected (4722324). The figures above are from one complete run on 4722324.

### UNVERIFIED (fix round 2)

- **A standalone candidate that does not fit.** No test offers a directory that the new admins sign but that names another installation or does not fit the policy. host-setup.md labels this sentence UNVERIFIED and says it is reasoned from the code.
- **R2-5's remedy.** No test builds main-written state.
- **The supersede guard's false side,** as corrected in fix round 1's UNVERIFIED list above.
- **The homelab.** As before, Phase 3 runs no admin-set change of enrolled hosts.

## Self-Check: PASSED

- The files exist: internal/agent/apply/policy_change_test.go, the plan, this SUMMARY and the four runbooks.
- The nine branch commits before this one are ancestors of HEAD: dff4921, 605a99a, b55c264, 06820de, 941d459, 3878169, 47fd8ec, 4a1e5a5 and 561542d.
- Both of Task 4's publish checks exit 0 after the tracking updates.
- Fix round 1: internal/agent/apply/lastgood_test.go exists, and its commits 255b285, ad103cb, 9342e14 and a77151a are ancestors of HEAD (`git merge-base --is-ancestor`).
- Fix round 2: the commits 93690d3, dbf8e14 and 4722324 are ancestors of HEAD (`git merge-base --is-ancestor`).
- Task 5, the owner's merge gate, is open. Daniel reviews, approves and squash-merges PR #82. After his "merged", Claude runs merge-gate.sh in its plain form from the main checkout, then `--check`.
