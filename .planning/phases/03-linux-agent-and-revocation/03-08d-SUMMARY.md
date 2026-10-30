---
phase: 03-linux-agent-and-revocation
plan: 08d
subsystem: agent
tags: [agent, apply, krl, revocation, d-r2, reset-directory, generation-caps]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08b: the generation record's host_status, buildStatus from the committed generation, the sameBytes record rewrite; 03-08c: forget through the signer (this plan's precondition)"
provides:
  - "state: KRLAlone, the one implementation of owner decision D-R2's KRL-alone state, used by Verify's refused branch and by the applier"
  - "apply: candidate (render, keepKRL, checkCandidate) and krlAlone, the KRL-alone pass after a content refusal in forward and pollSpool, one per run"
  - "apply: checkCandidate checks the target and the intermediate Transition would install against the caps before anything is written"
  - "apply: the ErrCALineRejected trigger; rollback ends with cleanup; Transition discards an unvalidated intermediate"
  - "apply: RenderFallback without an accepted directory (last-good's principals and recorded host status), errNoDirectory, outcome"
  - "tests: TestKRLAlone (12 new cases), TestResetDirectory (4 new cases), dirSpec.bare"
  - "docs: host-setup.md 'Revocations keep applying'; signer-install.md host selection by bundle version and the KRL sentence"
affects: [03-08e, 03-08f, 03-09, 03-10, 03-12, 03-13, 03-14]

actuals:
  tokens: 16147
  tasks: 3
  commits: 10
plan_head_before: 98e9e5c6ed635d6b5f110b0488580ebec97c4830
plan_head_after: f31bbdebcbcd8a88a8be1de5d82345f3017f76c6

tech-stack:
  added: []
  patterns:
    - "A content refusal of a verified capture before current moves re-enters the apply loop at its no-change check with the capture taken as KRL-alone against the accepted (or pending) state, never with the refused Verified's KRL"
    - "Every refusal that is not a content refusal (preflight, I/O, lock, crash, after current moved) keeps its old handling; a rollback already keeps the newest KRL"

key-files:
  created:
    - .planning/phases/03-linux-agent-and-revocation/03-08d-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md
  modified:
    - internal/agent/state/verify.go
    - internal/agent/apply/apply.go
    - internal/agent/apply/swap.go
    - internal/agent/apply/render.go
    - internal/agent/apply/resetdir.go
    - internal/agent/apply/rechain_test.go
    - internal/agent/apply/harness_test.go
    - docs/runbooks/host-setup.md
    - docs/runbooks/signer-install.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (to 03-16-PLAN.md, the wave lines)
    - .planning/phases/03-linux-agent-and-revocation/deferred-items.md

key-decisions:
  - "F08's fallback without a directory reports last-good's recorded host_status, not the empty string, so the sameBytes record rewrite (03-08b) never replaces a real status with an empty one"
  - "outcome() joins host_not_in_directory on every forward return while no directory is accepted, no-op and dry run included, because every apply rewrites last_apply"
  - "One KRL-alone pass per run, shared by forward and pollSpool (engine.krlAloneTaken)"
  - "The checkCandidate-before-keepKRL mutant is not equivalent; intermediate_checked_with_the_kept_krl kills it"

requirements-completed: []

duration: 94min
completed: 2026-10-30
---

# Phase 3 Plan 08d: Agent revocation flow Summary

**A verified KRL now lands whatever else its capture holds. The cases:**
- an oversize or unrenderable directory, its intermediate included;
- a CA line the host's ssh-keygen refuses;
- a widening wait;
- no accepted directory after reset-directory.

**The mechanism:**
- One KRL-alone pass through state.KRLAlone, against the accepted (or pending) bundle.
- Failed runs no longer leave generations behind.

PR [#76](https://github.com/Labontese/keyroster/pull/76), branch `p03/08d-agent-revocation-flow`, opened by keyroster-bot. Auto-merge is not enabled. It waits for the orchestrator's pre-merge review and the owner's merge gate (Task 4).

## Commits

| Commit | Message |
|--------|---------|
| 06ca554 | refactor(agent): factor the KRL-alone state out of state.Verify |
| b51be21 | fix(agent): apply a verified KRL alone when its directory is above the caps (F07) |
| ac065fa | test(agent): pin the KRL-alone pass's edges (F07, F08) |
| 2f5039e | fix(agent): check the swap's intermediate against the caps before install (F07) |
| 78e8ac8 | fix(agent): apply a verified KRL alone after a CA line ssh-keygen refuses (F07) |
| 0823fed | fix(agent): take the KRL-alone pass during a widening wait (F07) |
| 503e639 | fix(agent): clean up generations after a rollback (F07) |
| f820a86 | fix(agent): apply newer KRLs and bundles before a reset host's directory arrives (F08) |
| aca1154 | docs(runbooks): say that revocations keep applying (F07, F08) |
| f31bbde | docs(03-08d): plan the agent revocation-flow hardening and shift the later waves |
| (after f31bbde) | docs(03-08d): complete agent revocation-flow plan. It holds this SUMMARY and the tracking files, so it is not counted in `commits:`, which is measured as `git rev-list --count 98e9e5c..f31bbde` = 10. |

Every commit is SSH-signed by keyroster-bot, with no attribution lines.

## What changed

**F07.** forward's order is now:
1. readCurrent.
2. render.
3. keepKRL.
4. checkCandidate. It checks the target and, when current is the agent's and the move does not collapse, the intermediate.
5. preflight, DryRun and sameBytes.
6. install, then validate.

After a content refusal, krlAlone takes the capture again as state.KRLAlone(pins, accepted/, capture, refusal), and the loop re-enters at the no-change check. A content refusal is any of:
- a render error;
- a generation, or its intermediate, above the caps;
- ErrCALineRejected from validate.

The pass runs only when all of these hold:
- v.Refused is nil;
- the bundle or directory changed;
- the error is not an injected crash;
- the run has not taken its one pass yet.

Otherwise the refusal is returned, joined to v.Refused. pollSpool uses the same helper, against pending.AsStored(). Every rollback ends with e.cleanup(). Transition discards an intermediate whose validate failed.

**F08.**
- RenderFallback with v.Directory nil, a host_not_in_directory refusal and a last-good returns:
  - renderTrust(v);
  - last-good's principals files, unchanged;
  - lastHost;
  - last-good's recorded host status.
- engine.render logs `host_not_in_directory: no directory is accepted yet; the KRL and CA keys apply, principals are kept as last-good's`.
- forward returns outcome(v), which joins errNoDirectory to v.Refused while no directory is accepted.
- ResetDirectory's doc comment says what an apply does before the directory arrives.

The heartbeat's host_status set is unchanged.

## RED evidence

Each RED failed on behaviour, never on the build. Every assertion uses only symbols that exist on origin/main.

**Task 1, on origin/main's code (98e9e5c) with the new test.**
- `oversize_principals_file_krl_applied` failed:
  ```
  rechain_test.go:108: the newer KRL was not applied alone: current does not revoke 6 (... Errors:[generation_too_large: principals/deploy would be 70372 bytes, above 65536]})
  --- FAIL: TestKRLAlone/oversize_principals_file_krl_applied
  ```
- In the same run `--- PASS: TestApply/oversize_generation_refused_before_install`. It also passed unchanged after Task 1, with its meaning: an oversize directory without a newer KRL writes nothing, and the next directory applies.
- Task 1's verify on the committed head b51be21 passed (the tracer gate), with `--- PASS: TestKRLAlone/oversize_principals_file_krl_applied`.

**Task 2, on Task 1's head (b51be21) with all Task 2 tests.**

RED:

| Test | Failing line |
|------|--------------|
| `ca_line_rejected_krl_applied` | `rechain_test.go:214: the newer KRL was not applied alone: current does not revoke 6` |
| `superseded_during_wait_krl_applied` | `rechain_test.go:285: an oversize superseding directory: <nil>, want generation_too_large reported` |
| `failed_runs_do_not_grow_gen` | `rechain_test.go:331: generations after each failed run [2 3 4 5 6 7 8 9]: want at most 7, and no growth over the last three runs` |
| `intermediate_union_too_large_krl_applied` | `rechain_test.go:156: the newer KRL was not applied alone: current does not revoke 6 (... Rollback:true ...)`. The intermediate failed inside Transition, and the rollback left the target generation behind. |
| `reset_then_newer_krl_before_directory_arrives` | `rechain_test.go:549: a newer KRL before the directory: host_not_in_directory: no directory is accepted yet, revokes 5 false` |
| `reset_then_new_bundle_before_directory` | `rechain_test.go:570: a new bundle before the directory: host_not_in_directory: no directory is accepted yet` |
| `lost_bundle_then_reset_krl_still_applied` | `rechain_test.go:608: apply 0 after the reset: bundle_not_verified: bundle version 3: ... breaks the chain`. The failing assertion is the KRL (revokes 6 false). Task 1's krlAlone already joins v.Refused to a refusal it does not take, so on that head the error names bundle_not_verified. On origin/main it is host_not_in_directory alone. |
| `unvalidated_intermediate_discarded` (added test, see Deviations) | `rechain_test.go:354: 3 generations, want 2: the unvalidated intermediate stayed` |

GREEN at once on Task 1's head, with the reason:

| Test | Why it passed |
|------|---------------|
| `too_many_accounts_krl_applied` | Task 1's checkCandidate already checks the target's caps. Its RED was taken on an origin/main worktree (below). |
| `ops_key_changed_krl_waits` | Task 1's KRLAlone already re-verifies under the accepted bundle. RED on origin/main (below). |
| `refusal_without_newer_krl_is_noop` | Task 1's pass ends at the no-change check. |
| `selftest_failure_after_swap_keeps_new_krl` | RollbackTarget already keeps the newest KRL. TestApply/selftest_failure_after_krl_only_change_keeps_krl covers the KRL-only shape. |
| `first_install_refusal_stands` and `reset_without_last_good_refusal_stands` | Today's handling: with nothing accepted, the refusal stands. |
| `intermediate_checked_with_the_kept_krl` | A guard for the order after keepKRL. It exists to kill a mutant (below). |

**origin/main worktree.** This was a scratch `git worktree add --detach <tmp> origin/main`, removed afterwards. Only the two cases and their two test helpers (mustKRLAlone, accountNames) were copied in.
```
rechain_test.go:107: the newer KRL was not applied alone: current does not revoke 6 (...)
--- FAIL: TestKRLAlone/too_many_accounts_krl_applied
rechain_test.go:131: a KRL only the refused bundle verifies: generation_too_large: principals/deploy would be 70372 bytes, above 65536, want generation_too_large and krl_not_verified
--- FAIL: TestKRLAlone/ops_key_changed_krl_waits
```

## Mutants

Each mutant was applied to its own scratch copy of HEAD f820a86, whose base checksums matched HEAD. Each ran against its named test without -race, and the copy was then deleted, so the checkout stayed byte for byte unchanged. All ten were killed:

| Mutant | Killed by | Failing line |
|--------|-----------|--------------|
| The pass removed from forward | too_many_accounts_krl_applied | `current does not revoke 6` |
| KRLAlone made to keep the refused Verified's KRL | ops_key_changed_krl_waits | `... want generation_too_large and krl_not_verified` |
| checkCandidate's intermediate check removed | intermediate_union_too_large_krl_applied | `current does not revoke 6 (... Rollback:true ...)` |
| checkCandidate moved before keepKRL. Not equivalent: Intermediate's collapse depends on the KRL bytes keepKRL substitutes. | intermediate_checked_with_the_kept_krl (added) | `generation_too_large: 4097 principals files, above 4096 (the intermediate generation from generation 3)` |
| The ErrCALineRejected trigger removed | ca_line_rejected_krl_applied | `current does not revoke 6` |
| The cleanup after rollback removed | failed_runs_do_not_grow_gen | `[2 3 4 5 6 7 8 9]: want at most 7` |
| The pass removed from pollSpool | superseded_during_wait_krl_applied | `<nil>, want generation_too_large reported` |
| RenderFallback's no-directory branch removed | reset_then_newer_krl_before_directory_arrives | `revokes 5 false` |
| The v.Refused join removed from outcome | lost_bundle_then_reset_krl_still_applied | `apply 0 after the reset: host_not_in_directory: no directory is accepted yet, revokes 6 true` |
| Transition's discard removed (extra) | unvalidated_intermediate_discarded | `3 generations, want 2` |

## Verification

**Task 2 verify** (`-race`, the plan's -run set, on the final code): exit 0. All 14 named lines are present, plus the two added cases:
- `--- PASS: TestKRLAlone/` oversize_principals_file_krl_applied, too_many_accounts_krl_applied, intermediate_union_too_large_krl_applied, ca_line_rejected_krl_applied, ops_key_changed_krl_waits, refusal_without_newer_krl_is_noop, superseded_during_wait_krl_applied, selftest_failure_after_swap_keeps_new_krl, failed_runs_do_not_grow_gen, first_install_refusal_stands, intermediate_checked_with_the_kept_krl, unvalidated_intermediate_discarded.
- `--- PASS: TestResetDirectory/` reset_then_newer_krl_before_directory_arrives, reset_then_new_bundle_before_directory, lost_bundle_then_reset_krl_still_applied, reset_without_last_good_refusal_stands.

Every existing TestKRLAlone, TestResetDirectory, TestApply, TestSwapInterleaving and TestIntermediate case passed unchanged. No assertion had to move.

**Full gate** on f31bbde, in a WSL scratch copy:

| Step | Result |
|------|--------|
| `go test -race -count=1 ./...` | rc 0. `internal/agent/apply` took 511 s, with every package running at once (see Deferred Issues). |
| `go vet ./...` | rc 0 |
| `go vet -tags e2e ./test/e2e/` | rc 0 |
| `go vet -tags "e2e systemdsmoke" ./test/e2e/` | rc 0 |
| `gofmt -l .` | Empty. The positive control was listed. |
| golangci-lint | rc 0 |
| capslock-check | rc 0, no new pair. The agent still leaves the module for EXEC only through execsite. |
| dep-firewall, testonly-firewall, check-pinned-actions | rc 0 |

**Acceptance greps:**

| Check | Result | Required |
|-------|--------|----------|
| `func KRLAlone(` in verify.go | 1 | |
| `KRLAlone(` in verify.go, outside comments | 2 | at least 2 |
| `state.KRLAlone(` in apply.go, outside comments | 1 | at least 1 |
| resetdir.go: the old sentence | 0 | 0 |
| resetdir.go: the new sentence | 1 | 1 |

**Commit messages:** no attribution line (the count is 0).

**CI** on f31bbde (PR #76): all 26 required checks passed:
- CI run 41064103229: build-test, lint, govulncheck, capslock, dependency-firewall, cli-windows, cli-macos and fuzz;
- E2E run 41064103243: e2e 9.5p1 and 10.5p1;
- E2E distro run 41064103326: 7 images;
- e2e-pkcs11 run 41064103742;
- e2e-tpm run 41064103946;
- build-piv run 41064103998;
- systemd-sandbox run 41064103652;
- CodeQL run 41064103598;
- pr-title run 41064103255;
- pinned-actions run 41064103787.

In build-test, `internal/agent/apply` took 317 s under `-race`. Main's last run took 101 s. The default per-binary timeout is 600 s.

e2e: CI only. WSL cannot resolve the e2e host name.

## Deviations from Plan

### Reconciliations with main (the plan was checked before 03-08b's fix rounds)

1. **forward's order.**
   - On main, forward rendered and then read current. It now reads current first and then renders, so every error from candidate is a content refusal and readCurrent's are not.
   - checkCandidate comes before the sameBytes branch, which since 03-08b writes the record's host status and commits. It also comes before the DryRun return, so a dry run reports the refusal.
   - preflightApply stays after checkCandidate, so a preflight refusal is no trigger.
2. **F08's host status is last-good's recorded host_status**, not the empty string the plan's action named.
   - Since 03-08b the record persists host_status, and the sameBytes branch rewrites current's status from the render. An empty status would overwrite a real one (host_removed, host_keys_rotated) in the heartbeat.
   - The plan's tests use an active host, whose status is empty, so their assertions hold. The closed set is unchanged.
   - engine.render now reads the record's HostStatus into last-good's Generation, beside its Host.
3. **outcome() on every forward return.** That covers the no-op, dry run, sameBytes, first install and final paths, not only after the commit.
   - Every apply, a no-op included, rewrites last_apply, so a no-op returning nil would clear the note "until a directory is accepted".
   - outcome derives the note from v.Directory being nil, which only the no-directory fallback renders. The note therefore travels with the superseding Verified through pollSpool, and no engine field carries it.
4. **The v.Refused join is in krlAlone from Task 1** (the second-pass rule: errors.Join(firstRefusal, err)).
   - It also covers F08's "when Verify set Refused and render still fails".
   - The F08 join mutant was therefore applied to outcome. That is where lost_bundle_then_reset_krl_still_applied depends on it.
5. **Report fields** HostStatus, UnmatchedHostKeys and KRLKept are cleared when the pass starts, so the report describes the KRL-alone render. BundleHeld keeps the first Verify's value.
6. **checkCandidate is a plain function** in swap.go, next to checkLimits, because it reads no engine state.

### Test-shape decisions

7. **reset_then_new_bundle_before_directory also publishes a newer KRL.** A bundle that only adds a CA line collapses to one widening swap, and the plan asks for Transition's two steps. The test asserts `r.Intermediate != 0`.
8. **lost_bundle_then_reset_krl_still_applied** re-spools the server's directory 3 after the reset, as the fetcher would. The bundle refusal comes first, so the directory is never verified while the bundle step is refused.
9. **Two added tests.**
   - `intermediate_checked_with_the_kept_krl` kills the order mutant. The mutant is not equivalent: with current holding a KRL that a rollback kept, a widening that renames a header-only account collapses only with the kept KRL. Without it, the intermediate holds 4097 files.
   - `unvalidated_intermediate_discarded` pins Transition's discard. It makes ssh-keygen -Q fail from its second call, the intermediate's.
10. **harness_test.go** gained `dirSpec.bare` (accounts mapped to no role), for the order case. The file is not in the plan's files_modified.
11. **The origin/main worktree RED** copied the two test helpers with the case, so it was self-contained.

### Delivery

12. **Task 1 is two commits**, a refactor (KRLAlone) and the fix. Each fix lands with its test. The RED runs used scratch trees: HEAD plus the new test files, or an origin/main worktree.

### Auto-fixed

None. No Rule 1-3 fix was needed beyond the plan's own work.

## Deferred Issues

Logged in deferred-items.md:

- **Render cost.** Rendering costs time that grows with the square of a host group's accounts: `directory.RenderPrincipalsFile` canonicalises the whole directory once per account. The three cases at the 4096-file cap cost about 80 s of CPU each under -race, so the agent apply package now runs for several minutes under -race (511 s locally with every package running at once). The directory package is outside this plan's files.
- **last_apply result.** `ErrGenerationTooLarge` is not in status.go's `refusals`, so a KRL-alone commit after an oversize directory reports `last_apply.result = error`.

## Threat model

| Threat | Mitigation | Tests |
|--------|-----------|-------|
| T-03-294 (DoS by a withheld KRL) | Mitigated. | oversize_principals_file_krl_applied, too_many_accounts_krl_applied, intermediate_union_too_large_krl_applied, ca_line_rejected_krl_applied, superseded_during_wait_krl_applied |
| T-03-295 (gen/ growth) | Mitigated. | failed_runs_do_not_grow_gen, unvalidated_intermediate_discarded |
| T-03-296 (a fallback installs nothing unauthenticated) | KRLAlone takes prev's bundle, policy and directory, and re-runs krl.VerifyManifest against prev's bundle, the pins and prev's KRL version. The no-directory fallback uses the verified bundle's CA keys and last-good's installed principals. Every fallback generation passes checkCandidate, validate and Transition. | ops_key_changed_krl_waits, first_install_refusal_stands, reset_without_last_good_refusal_stands |
| T-03-297 (reset host stops KRLs) | Mitigated. | lost_bundle_then_reset_krl_still_applied, reset_then_newer_krl_before_directory_arrives, reset_then_new_bundle_before_directory |
| T-03-SC (dependencies) | No module added. capslock is unchanged. | |

No threat flag: the change adds no endpoint, file path or trust boundary.

## Known Stubs

None.

## UNVERIFIED

- Behaviour on a real host: no 03-16 drill provokes these refusals. The runbook paragraphs say "Run in CI" and "UNVERIFIED on a real host".
- e2e ran in CI only.

## TDD Gate Compliance

Each behaviour change has a RED run on the code before it: origin/main for Task 1 and for the two cases Task 1 already fixes, and Task 1's head for Task 2. Each also has a GREEN run on its own commit's tree:
- step A with the full -race set;
- steps B, C and D with the -race set minus the 4096-file cases;
- step E and HEAD with everything.

## Self-Check: PASSED

- The files exist: 03-08d-PLAN.md, 03-08d-SUMMARY.md, state/verify.go, apply/apply.go, apply/swap.go, apply/render.go, apply/resetdir.go, apply/rechain_test.go, apply/harness_test.go, and both runbooks.
- The commits 06ca554, b51be21, ac065fa, 2f5039e, 78e8ac8, 0823fed, 503e639, f820a86, aca1154 and f31bbde are all ancestors of HEAD.
