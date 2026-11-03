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
| T2b: the bundle signatures added to the union | `union_never_lowers_threshold`, `one_hop_new_roots` | **survived, as required: equivalent** | both PASS |
| T2c: Next.PolicySigs set to the union | `stored_policy_sigs_stay_bounded` | **killed** | `accepted/'s policy signatures (2826 bytes) are not bundle-4.policy.sigs (628 bytes)` |
| T2d: a rejected delivered file stored | `malformed_delivered_sigs_not_stored` | **killed** | `accepted/'s policy signatures are not the offered file` |
| T2e: the per-bundle file not written by the fetcher | `TestFetch/per_bundle_policy_sigs_spooled` | **killed** | `bundle-2.policy.sigs: "", open ...: no such file or directory; want "p2"` and `bundle-4.policy.sigs was not written before bundle-4.json` |
| T2f: the offered policy file left out of the union | `spool_without_per_bundle_sigs_one_hop` | **killed** | `the rotation through policy-1.json.sigs: bundle_not_verified: ... policy (new roots) signed by 0 of 1 roots, need 1` |
| T2g: spoolSet left without the per-bundle name, so pruneSpool keeps every such file | `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle` | **killed** | `accepted bundle 3: bundle-1.policy.sigs spooled true, want false` (and bundles 2 and 9, and bundles 1 to 6 without accepted.json) |

Six mutants were killed and one survived, as the plan requires. Each was restored byte for byte, and `git diff --quiet -- internal/` passed after each.

**Why T2b is equivalent (plan check 3, m-2).** CountPinnedSigners (internal/trust/verify.go:29-62) verifies every block over the policy's digest under the policy namespace (`s.VerifyDigest(namespace, digest)`, line 51) and skips a block that does not verify there. A root's bundle signature is a signature over the bundle under the bundle namespace, so it never verifies there and never counts toward the policy threshold. Its blocks are well-formed, so ParseAll accepts the union with them. The mutant therefore changes no outcome, and both tests pass under it.

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
  - pruneSpool's doc comment states the bound of about 6.1 GiB kept and 6.6 GiB in all (owner decision O-3 (a)).
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
  - host-setup.md: the outbox row, the I-2 sentence, the fork rule, the prune paragraph with 6.1 and 6.6 GiB, the record paragraph (O-2 (c)) and the `diverged` item.
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

- **Task 2**: 7 mutants. 6 killed, and T2b survives as required: it is equivalent (plan check 3, m-2).
- **Task 3**: 15 mutants, all killed. T3n is killed by one of its two named tests.
- **In all**: 22 mutant runs, one equivalent.

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
- **O-3 (a), accept the bound.** pruneSpool keeps `bundle-<N>.policy.sigs` exactly while it keeps bundle N (spoolSet), and its doc comment and host-setup.md state about 6.1 GiB kept and 6.6 GiB in all. These figures are computed from the caps, not measured.

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
- **pruneSpool's bound of about 6.1 GiB kept and 6.6 GiB in all.** It is computed from the caps, not measured.

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

- **Converted refusals that no case pins.** These take the same step-b branch as the refusals the cases pin, directory_older (`stored_version_above_new_admins_needs_reset`) and the chain refusal (`unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle`):
  - directory_installation;
  - directory_chain_gap;
  - directory_not_verified for a parse, version or CheckPolicy cause.
- **The fork rule at an unapplied record's directory version.** No test offers a same-number directory there; it is reasoned from the code (the stored version is the chain base's).
- **A KRL signed by a new ops key in the unauthorized shape** (host-setup.md's I-2 sentence). No test builds it; it is reasoned from krlStep.
- **The O-1 residual** (owner decision O-1 (a)). No test builds the state from before this change together with a refused KRL (enroll-user.md labels it).
- **The `diverged` item's advice** to read the directory version from status.json while accepted.json reads 0. No test reads status.json for it.
- **A poll during a widening wait that supersedes into the unauthorized state** (deviation 1's first shape). It was observed in the draft run, but no committed test asserts it.
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

## Self-Check: PASSED

- The files exist: internal/agent/apply/policy_change_test.go, the plan, this SUMMARY and the four runbooks.
- The nine branch commits before this one are ancestors of HEAD: dff4921, 605a99a, b55c264, 06820de, 941d459, 3878169, 47fd8ec, 4a1e5a5 and 561542d.
- Both of Task 4's publish checks exit 0 after the tracking updates.
- Task 5, the owner's merge gate, is open. Daniel reviews, approves and squash-merges PR #82. After his "merged", Claude runs merge-gate.sh in its plain form from the main checkout, then `--check`.
