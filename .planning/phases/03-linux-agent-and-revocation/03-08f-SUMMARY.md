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
