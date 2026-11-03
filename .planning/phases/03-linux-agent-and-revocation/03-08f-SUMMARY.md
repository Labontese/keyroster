---
phase: 03-linux-agent-and-revocation
plan: 08f
subsystem: agent
tags: [agent, apply, state, spool, fetch, directory, policy, roots, f02, f03]
status: draft

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08d (KRLAlone, storedOnly, outcome's errNoDirectory), 03-08e (spool.Cap, checkCaps, healSpool, pruneSpool), 03-08j (verify's chain and alone, the unapplied record, WriteAccepted's raise), 03-08k (krlStep, fullyVerified, VerifyAfter, VerifyAheadAfter, outcome joining Refused and KRLRefused)"
affects: [03-09, 03-10, 03-12, 03-13, 03-14]
---

# Phase 3 Plan 08f: agent policy in force (DRAFT, Run A: Tasks 1 and 2)

This is the SUMMARY draft. Run A (Tasks 1 and 2) wrote it; Run B (Tasks 3 to 5) completes it. Code comments cite `F02 (03-08f)` and `F03 (03-08f)`.

## Branch

`p03/08f-agent-policy-in-force`, created from origin/main b1ebff3. The plan file lies untracked in the phase directory (Task 4 commits it).

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

**Why T2b is equivalent (plan check 3, m-2).** CountPinnedSigners (internal/trust/verify.go:29-60) verifies every block over the policy's digest under the policy namespace (`s.VerifyDigest(namespace, digest)`, line 51) and skips a block that does not verify there. A root's bundle signature is a signature over the bundle under the bundle namespace, so it never verifies there and never counts toward the policy threshold. Its blocks are well-formed, so ParseAll accepts the union with them. The mutant therefore changes no outcome, and both tests pass under it.

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

## Deviations so far (Run A)

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

## Handoff to Task 3

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
