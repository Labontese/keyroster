---
phase: 01-trust-core
fixed_at: 2026-10-10
review_path: .planning/phases/01-trust-core/01-REVIEW.md
method: two sequential area fixers (gsd-code-fixer), G then F, merged by the orchestrator; the fix report of the first review (59 findings) is in git history at 582f932
branch: p01/26-review2-fixes
fix_scope: critical_warning
iteration: 1
findings_in_scope: 8
fixed: 8
skipped: 0
status: all_fixed
---

# Phase 1 re-review fixes (merged)

**Scope:** the 1 critical and 7 warning findings of the re-review in `01-REVIEW.md`. Info findings were out of scope. Each fix is its own signed commit.

| ID | Outcome | Commits |
|----|---------|---------|
| G-CR-01 | fixed: requires human verification. `--prev-sha256` is mandatory with `--prev`, and prev must be self-signed by its own threshold. | 7b8a7d1, 23f97c6 |
| G-WR-01 | fixed: requires human verification. A custody change for a carried-over root is refused. | 99ecb4a |
| G-WR-02 | fixed. The threshold-1 claim is corrected, and `root sign --prev` warns. | e89b18a |
| G-WR-03 | fixed. Order-independent test; multi-root, overlap, duplicate and recurring-set anchor cases. | 2c6a53d |
| F-WR-01 | fixed: requires human verification. The validity window must start at the issuance time, and serial ≤ leaf time. | 8386c26 |
| F-WR-02 | fixed: requires human verification. No root of ANY logged bundle may be an admin (audit, install, serve, doctor). | 88407db |
| F-WR-03 | fixed. merge-gate.sh runs only as `origin/main`'s reviewed copy and returns to `main`; exit 4 prints resume steps. | 5b73ceb |
| F-WR-04 | fixed. doctor reports `INFO piv_custody_reported` instead of OK custody for piv. | 84389ee |

## Checked against the real homelab log (orchestrator, 2026-10-10)

`keyroster audit verify` built from this branch was run on the homelab export taken after 01-21 (6 entries, sha256 `cc01648e…4f77`). It printed OK, anchored on trust bundle v2 with pins C and D, and on v1 with pins A and B. The new F-WR-01 and F-WR-02 checks therefore accept the real log.

**Not run:** `keyroster-signer doctor` and `serve` with this build on the homelab state. These need a deployment, which is UNVERIFIED.

## Merge-gate bootstrap (one time)

This PR changes `merge-gate.sh`, so the copy on this branch refuses to gate its own PR. Gate it from `main` with `origin/main`'s reviewed copy:

`git switch main && git merge --ff-only origin/main && bash scripts/merge-gate.sh p01/26-review2-fixes`

## UNVERIFIED

- `--prev-sha256` has been exercised only by unit and e2e tests. It has never run on the homelab or in an offline ceremony.
- The merge-gate rebase, push and resume paths against real GitHub. A local harness passed 13/13. shellcheck was not run.
- doctor and serve on the homelab with this build.
- Not run: the `e2e_tpm` and `e2e_pkcs11` suites. They run in CI.

The two area reports follow, each unchanged apart from its frontmatter.

---


# Phase 01: Code Review Fix Report (Area G)

**Fixed at:** 2026-10-10T07:35:23Z
**Source review:** .planning/phases/01-trust-core/01-REVIEW.md (Area G)
**Iteration:** 1
**Branch:** `p01/26-review2-fixes`, main checkout (`workflow.use_worktrees: false`, no worktree)

**Summary:**
- Findings in scope: 4 (G-CR-01, G-WR-01, G-WR-02, G-WR-03; G-IN-* out of scope)
- Fixed: 4
- Skipped: 0

## Fixed Issues

### G-CR-01: `--prev` is never authenticated

**Files modified:** `cmd/keyroster/root.go`, `cmd/keyroster/trust.go`, `internal/trust/verify.go`, `cmd/keyroster/root_test.go`, `cmd/keyroster/trust_test.go`, `internal/trust/verify_test.go`, `test/e2e/rotation_test.go`, `docs/runbooks/root-ceremony.md`
**Status:** fixed: requires human verification (new authentication rule that the owed v3 ceremony depends on)
**Commits:** 7b8a7d1, then 23f97c6 (the e2e test adds the wrong-hash refusal of both commands with real binaries; runbook UNVERIFIED wording)
**Applied fix:**
- Both `root sign` and `trust verify` take `--prev-sha256`, which is required with `--prev`. They refuse `--prev` without it, `--prev-sha256` without `--prev`, and any value that is not 64 lowercase hex digits (exit 2).
- A shared `loadPrev` in `cmd/keyroster/trust.go` does the following, in order:
  - reads `prev/bundle.json`;
  - compares its SHA-256 with `--prev-sha256` and refuses on a mismatch;
  - reads `bundle.json.sigs`, `policy.json` and `policy.json.sigs`;
  - requires the bundle's own root threshold of its own roots on both documents, via the new `trust.VerifySelfSigned`.
- In `root sign`, `loadPrev` runs inside `successorBuilder`, before `CheckAdminsNotRoots` and `prepareBundle`. Every refusal therefore ends in "nothing was written or signed" and leaves no out-dir. In `trust verify`, it runs before `VerifySuccessor` and before any output.
- `BuildSuccessor` and `checkSuccessorChain` are unchanged and remain the single source of the chain rule.
- Regression test `TestTrustVerifySuccessor/foreign_prev_refused_by_both_commands`:
  - **Setup:** a foreign genesis {Z} with the attacker's CA, ops and log keys, self-signed by Z. A forged v2 names the honest roots C and D and is signed by Z and C.
  - `root sign` and `trust verify` both refuse when given the recorded real SHA-256. Both exit 2 without the flag. Nothing is written and no `OK:` line is printed.
  - **Control:** pinned to the foreign genesis's own SHA-256, the forged v2 verifies. This shows that the hash pin is what refuses it.
- Other new tests:
  - unit tests for `VerifySelfSigned`;
  - in `root sign`: `prev_sha256_required`, `prev_sha256_mismatch_refused`, `prev_without_sigs_refused`, `prev_signed_by_non_root_refused`;
  - in `trust verify`: `prev_sha256_mismatch_refused`, `prev_without_sigs_refused`.
- Edited-prev subtests: `copyPrev` now copies the `.sigs` files and re-signs the edited file with root A, so `custody_mismatch` and `policy_mismatch` still reach their own refusals.
- `root-ceremony.md`, "Rotate the roots":
  - copy all four files;
  - take `--prev-sha256` from the transcript, never from `sha256sum` of the copy;
  - the flag is added to steps 3 and 5 (step 4 reruns the step 3 command);
  - step 4 now says the trust also rests on the recorded hash;
  - the UNVERIFIED box notes that the 01-20 rehearsal predates the flag.
- e2e `TestRootRotationLiveSigner` passes `--prev-sha256` to both commands. Since 23f97c6 it also checks, with the real binaries, that both commands refuse a wrong `--prev-sha256` and that `root sign` writes nothing.
- **Fail-before:** with a temporary test (not committed), the unfixed code accepted the foreign prev. `root sign --prev <foreign>` signed. `trust verify --prev <foreign> --pin C --pin D` exited 0 with `OK: successor of trust bundle v1: previous roots 1 of 1 signed ... new roots 1 of 2 ... (pinned)`.
- **Pass-after:** all new tests pass.

### G-WR-01: A carried-over root can change its custody label

**Files modified:** `internal/trust/verify.go`, `internal/trust/successor_test.go`, `cmd/keyroster/root_test.go`
**Status:** fixed: requires human verification (new chain-rule condition)
**Commit:** 99ecb4a
**Applied fix:**
- New `checkCarriedCustody`, called from `checkSuccessorChain`. It refuses with `ErrCustody` any key present in both root sets whose custody label differs. Keys are compared by wire encoding.
- Because the check is in `checkSuccessorChain`, the same rule applies in `BuildSuccessor`, `VerifySuccessor`, `install-bundle` (`internal/signer/trust.go`) and `audit verify`.
- Tests:
  - `TestBuildSuccessor/carried_root_changes_custody` (A goes from software to piv). The table's previously unused `roots` field is now wired up, and the case covers both the builder and the verifier.
  - `TestRootSignSuccessor/carried_root_custody_change_refused`: the CLI refuses, and the out-dir does not exist.
- **Fail-before:**
  - the builder returned a bundle with `err = <nil>`;
  - with the old `verify.go`, the CLI went on to the signing prompt and failed only at the agent.
- **Pass-after:** both pass.

### G-WR-02: "A stolen old root cannot rotate trust alone" is false at threshold 1

**Files modified:** `internal/trust/verify.go`, `cmd/keyroster/root.go`, `docs/runbooks/root-ceremony.md`, `cmd/keyroster/root_test.go`, `cmd/keyroster/trust_test.go`
**Status:** fixed
**Commit:** e89b18a
**Applied fix:**
- **`VerifySuccessor` doc comment.** It now says the two counts are independent and that a root in both sets counts toward both. A new root cannot rotate trust without the current threshold. At threshold 1, any single current root can, either alone (if kept in next) or with a fresh key.
- **Runbook "The rule".** Same correction. It also mentions the warning.
- **Warning.** `root sign --prev` prints a warning to stderr when `prev.Root.Threshold == 1`, after the successor header and before the confirmation prompt.
- **Tests.**
  - New `TestRootSignSuccessorThreshold1Warning`: the warning is present at threshold 1 and absent at threshold 2.
  - The `previous_root_signs_with_key` assertion also checks the warning.
  - The new successor tests now pin the ceremony clock with `setCeremonyNow`. A WSL clock step made the real-clock threshold-2 case fail once (`issued_at ... before the previous bundle's`). This touched `trust_test.go`'s G-CR-01 subtest too.
- **Fail-before:** the `threshold_1` case and `previous_root_signs_with_key` failed because the warning was missing.
- **Pass-after:** both pass.

### G-WR-03: Test gaps and an order-dependent test

**Files modified:** `cmd/keyroster/root_test.go`, `internal/audit/verify_test.go`
**Status:** fixed
**Commit:** 2c6a53d
**Applied fix:**
- `new_root_signs_with_key` now has its own out-dir. It signs with C first, which is the runbook order, checks that the previous-roots threshold is unmet, then signs with A and verifies.
  - **Fail-before:** `go test -run 'TestRootSignSuccessor/new_root_signs_with_key$'` failed with `bundle (previous roots) signed by 0 of 2 roots, need 1`.
  - **Pass-after:** the same command passes.
- `TestVerifyAnchorsOnLaterBundle` gains a per-check `threshold` field (0 means 1) and a `rootSet`/`rotatedTo` helper. New cases:
  - `two_new_roots_threshold_2_anchor_v2`: pins C,D at threshold 2 anchor v2, in either order. At threshold 1 they are refused (`bundle threshold 2, pinned threshold 1`). Pins of C alone are refused, and A anchors v1.
  - `two_new_roots_threshold_2_one_signed`;
  - `duplicate_signature_toward_threshold_2` (signed by A, C, C);
  - `root_in_both_sets_counts_toward_both` ({A, C} at threshold 1, signed by A alone, is accepted, which documents G-WR-02);
  - `root_in_both_sets_threshold_2` (signed by A alone is refused; signed by A and C anchors v2 at threshold 2);
  - `root_set_recurs_first_match_anchors` ({A}, then {C}, then {A}: pins A anchor v1).
  - The foreign prev is covered by the G-CR-01 test.
- These cases cover behavior that already works, so they could not fail before. Instead, a **mutation check** was run, each mutation reverted with `git checkout --`:
  - removing the dedup in `CountPinnedSigners` turns `duplicate_signature_toward_threshold_2` red;
  - dropping the threshold comparison in `MatchPins` turns `two_new_roots_threshold_2_anchor_v2` and `root_in_both_sets_threshold_2` red;
  - anchoring on the last match turns `root_set_recurs_first_match_anchors` red ("anchored on trust bundle v3, want v1").

## Verification (where it ran)

All gates ran in the **main checkout** (`C:/Users/labon/ssh-cert-manager`, reached from WSL at `/mnt/c/...`). No worktree was used, so the numbers can be reproduced from this tree.

- **Windows, Go 1.27.1:**
  - per fix: `go build ./...`, `go vet`, `gofmt -l`;
  - `go test -count=1 ./cmd/keyroster ./internal/trust ./internal/audit` passes.
- **WSL, Go 1.27.1, before each commit:** build, vet, gofmt and `go test -race -count=1` on the touched packages all pass.
- **WSL, before the final commit:**
  - `go test -race -count=1 ./...` passes (all packages).
  - `~/go/bin/golangci-lint run ./...` reports 0 issues.
  - The e2e run `KEYROSTER_OPENSSH_PREFIX=~/.cache/keyroster/openssh-10.5p1 go test -tags e2e -count=1 -run 'TestRootRotationLiveSigner|Trust' ./test/e2e/` passes: `TestRootRotationLiveSigner`, `TestTrustRefuses` and `TestTrustFlowEndToEnd` ran, none skipped.
- **Not run:** `CGO_ENABLED=1 -tags piv`. No PIV code was touched.
- **Lint with the e2e tag:** `golangci-lint --build-tags e2e ./test/e2e/` reports 9 issues, all in `harness_test.go`, which I did not touch. CI does not lint with this tag, and `rotation_test.go` is clean.

Evidence files (scratchpad): `gcr01-failbefore.txt`, `gwr01-failbefore.txt`, `gwr02-failbefore.txt`, `gwr02-passafter.txt`, `gwr03-failbefore.txt`, `gwr03-passafter.txt`, `gwr03-mutations.txt`.

The final gates (full `-race`, lint, e2e) ran on the tree at 2c6a53d. 23f97c6 changes only the e2e test and the runbook. After it, the e2e rotation and trust tests, `go vet -tags e2e` and gofmt were rerun, and they pass.

## UNVERIFIED

- `--prev-sha256` has not been used on the homelab or in an offline ceremony.
  - It is exercised only by tests.
  - The e2e `TestRootRotationLiveSigner` (real binaries) covers the accepted path and the wrong-hash refusal of both commands.
  - The foreign prev, the missing or malformed flag and a prev without its own roots' signatures are covered by the in-process unit tests only.
  - The runbook's UNVERIFIED box says so.
- The new runbook instruction to copy all four files into `/media/transfer/prev` from `ceremony/` or `rotation/` has not been rehearsed with real media.

## Notes for area F

- `trust.checkSuccessorChain` now calls `checkCarriedCustody` right before `CheckAdminsNotRoots`. F-WR-02 (root as admin across generations) edits that same call site.
- `root sign --prev` and `trust verify --prev` exit 2 without `--prev-sha256` (64 lowercase hex). Any test or doc that calls them must pass it, and `prev/` must hold `bundle.json`, `policy.json` and both `.sigs` files.
- New package-level test helpers in `cmd/keyroster` (`package main`): `readTestFile`, `fileSHA256` and `noPrevSHA` in `trust_test.go`. Do not redefine them.
- Changed helper signatures:
  - In `TestRootSignSuccessor`, `copyPrev(t, name, edit, resign bool)` returns `(dir, sha)`.
  - In `TestTrustVerifySuccessor`, `verify` takes `prevSHA`.
- `TestVerifyAnchorsOnLaterBundle` has a `threshold` field per check and the `rootSet`/`rotatedTo` helpers. The `successor_test.go` refusal table now honours `roots`.
- WSL's clock can step backwards. In any genesis-then-successor test, pin the clock with `setCeremonyNow`.
- `/tmp/wsl-check.sh` (modes `race`, `e2e`, `full`) and `/tmp/wsl-gofmt.sh` exist in WSL with CRLFs stripped. `cmd/keyroster` under `-race` from `/mnt/c` takes about 2.5 to 8 minutes.

---

_Fixed: 2026-10-10_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_

---


# Phase 01, Area F: Code Review Fix Report

**Fixed at:** 2026-10-10
**Source review:** .planning/phases/01-trust-core/01-REVIEW.md (Area F section)
**Iteration:** 1
**Branch:** `p01/26-review2-fixes` (main checkout, `workflow.use_worktrees=false`), on top of the five area G commits
**Where verification ran:** Go unit tests in Git Bash (Windows) and in WSL (`-race`, piv tag, e2e) against the main checkout; the merge-gate harness in a scratch directory with a local bare origin and a stub `gh`.

**Summary:**
- Findings in scope: 4 (F-WR-01..04; F-IN-* out of scope)
- Fixed: 4
- Skipped: 0

## Fixed Issues

### F-WR-01: `cert.CheckIssued` / `audit.Verify` accept a logged certificate whose validity window is anywhere in time

**Files modified:** `internal/cert/builder.go`, `internal/cert/builder_test.go`, `internal/audit/verify.go`, `internal/audit/verify_test.go`, `internal/signer/issue.go`, `internal/signer/log_test.go`
**Commit:** 8386c26
**Status:** fixed: requires human verification (logic)
**Applied fix:**
- `cert.CheckIssued(c, p, issuedFrom, issuedTo)` checks that `ValidAfter` lies in `[floor(issuedFrom - 300 s), floor(issuedTo - 300 s)]`, so `backdate` stays in one place. A reversed or zero range is refused.
- `audit.Verify` passes `[serial, leaf time]` as that range and refuses a serial after the leaf time. The bounds come from `serial.Next` (the serial is a µs clock reading, returned once the clock reached it) and from `appendLocked` (leaf time = issuance time, raised to the previous leaf's).
  - The reviewer suggested "leaf time minus 300 s within a slack". That would refuse an honest log after a clock step back, where the leaf time is raised by up to the size of the step; test `leaf_time_raised_ok` covers it. No slack is needed.
- **Signer:** `Issue` reads the clock again after `serial.Next`, so the issuance time could drop below the serial. `Issue` now refuses that as `clock_regression` before signing. This makes `serial <= issuance time <= leaf time` hold by construction.
- **Tests:**
  - `TestCheckIssued` gains window cases: 2030, ±2 s, a year back, and the range edges.
  - New `TestVerifyChecksIssuanceTime`: postdated to 2030, postdated by 1 min, backdated a year, serial after the leaf time, a raised leaf time that is OK, and an expired certificate that is still OK (moved here from the earlier table).
  - New `TestIssueRefusesClockStepAfterSerial`.
  - The audit fixture now issues at the time its serial names, as the signer does. Before, it took `time.Now()` independently of its serial and leaf times.
- **Fail-before:**
  - `TestVerifyChecksIssuanceTime`: postdated_to_2030, postdated_by_a_minute, backdated_a_year and serial_after_leaf_time all got `Verify error = <nil>`.
  - `TestIssueRefusesClockStepAfterSerial`: the issue succeeded (serial 1791618451085305).
- **Pass-after:** cert, audit and signer pass `-race`, and the e2e audit, CA-role and rotation tests pass with real binaries.

### F-WR-02: "no root as policy admin" holds for only one generation of retired roots

**Files modified:** `internal/audit/verify.go`, `internal/audit/verify_test.go`, `internal/signer/logstate.go`, `internal/signer/signer.go`, `internal/signer/trust.go`, `internal/signer/trust_test.go`, `internal/trust/verify.go` (doc only), `docs/runbooks/root-ceremony.md`, `docs/runbooks/signer-install.md`
**Commit:** 88407db
**Status:** fixed: requires human verification (authorization logic)
**Applied fix:**
- **audit:** `anchor` keeps the root set of every accepted bundle. Each `bundle_install` is refused when its policy names any earlier root, and the error wraps `trust.ErrKeyIsRoot`.
- **signer:** `rebuildLogFrom` and `CheckTrust` collect the root set of every `bundle_install` leaf (type `loggedInstalls`, which replaces `loadedInstall`). Log leaves are used rather than `trust_bundle` rows because the log is anchored by its checkpoint and the rows are not. The policy is refused when it names any of these roots:
  - in `InstallBundle`, after `VerifySuccessor`;
  - in `New` (serve start), after `checkBundleLogged`;
  - in `CheckTrust` (doctor).
- **Unchanged:**
  - `VerifySuccessor` and `checkSuccessorChain` keep their signatures. `checkCarriedCustody` → `CheckAdminsNotRoots(next, prev)` is untouched.
  - `root sign --prev` and `trust verify --prev` hold only the bundle in force, so they cannot see older roots. Their doc comment and the rotation runbook now say this.
- **Tests:**
  - `TestRetiredRootNeverAdmin`: install refused, a fresh admin as control, and start plus doctor refused on a hand-written v3.
  - `TestVerifyRefusesRetiredRootAsAdmin`: refused at entry 3, with a control.
  - The row-and-leaf writer of `TestStartRefusesRootAsAdmin` moved into `writeUnverifiedBundle`.
- **Fail-before:** `Verify = <nil>`; `InstallBundle v3 ... = &{3 ...}, <nil>`; `New ... = <nil>`.
- **Pass-after:**
  - audit, signer, trust and cmd pass `-race`.
  - e2e passes: rotation, doctor, trust flow, audit and trust refusals.

### F-WR-03: merge-gate still runs the PR's unreviewed copy of itself on its own rerun paths

**Files modified:** `scripts/merge-gate.sh`, `CONTRIBUTING.md`
**Commit:** 5b73ceb
**Status:** fixed
**Applied fix:**
- **Self-check:**
  - `git hash-object -- "$0"` runs before the `cd`, so a relative `$0` from a subdirectory works.
  - After the fetch, the script compares that hash with `git ls-tree origin/main -- scripts/merge-gate.sh`. It uses `ls-tree` rather than `origin/main:path`, which Git Bash path conversion can mangle.
  - It refuses with exit 1 when the two differ or `$0` is not a file (stdin), and prints how to run it from an up-to-date main.
- **Rebase in progress:** the script refuses to run while one is in progress, before any `gh` call.
- **Back to main:** `rebase_onto_main` is split into rebase, `push_rebased` and `back_to_main`. Every exit after the switch to the PR branch returns to main: exit 3, and exit 1 when the push, `gh` or the checks fail.
- **Exit 4:** the rebase stays in progress, so the script cannot switch back. It says so and prints the resume steps: continue, push, `git switch main`, rerun.
  - The printed push command uses `bot_git`'s credential helper and the lease. A plain `git push` would use the clone's helper, which could make the owner the last pusher.
- **Messages:** the "rebased onto main" lines now print before the switch back, so a failed switch still reports the push.
- **Docs:** the header exit codes, the E-WR-02 comment and CONTRIBUTING are updated.
- **Verification:**
  - `bash -n` passes.
  - shellcheck was NOT run: it is installed neither in Git Bash nor in WSL.
  - `bash scripts/merge-gate.sh --check p01/zz-made-up-branch-nonexistent` against real GitHub (identity check and fetch only, read-only) refused with exit 1: the final blob is 6abdb7c…, `origin/main`'s is 0925514…. The same refusal came from `internal/` with a relative `$0`.
  - `git credential fill` through the printed helper string returned `username=keyroster-bot`; the token was not printed.
  - `origin/main`'s old copy, run from a temp file, did not refuse: it reported "no pull requests found" and exited 1.
- **Local harness** (`scratchpad/mg-harness.sh`: a bare origin in the scratchpad, a stub `gh`, an ssh signing key; no GitHub, pushes only to the local bare repo): 13/13 passed. Cases:
  - `--check` passes the guard from main;
  - exit 3 lands on main, and the rebased head is signed and contains `origin/main`;
  - exit 1 after the push lands on main;
  - exit 4 leaves the rebase in progress;
  - a rerun mid-rebase is refused with no `gh` call;
  - the documented resume path, with the printed push command run verbatim, ends in a signed head and a rerun with exit 2 on main;
  - a PR's changed copy is refused;
  - stdin is refused;
  - a stale main is refused.

### F-WR-04: doctor still prints OK hardware custody for `piv` keys it never inspects

**Files modified:** `internal/doctor/doctor.go`, `internal/doctor/doctor_test.go`, `docs/backends/piv.md`, `docs/security/custody.md`, `docs/security/needs-hardware.md`
**Commit:** 84389ee
**Status:** fixed
**Applied fix:**
- `hardwareCustody` is now only `{"tpm"}`.
- `piv` gets `INFO piv_custody_reported`: the keys are named, slot attestation is not checked, and doctor did not read the card. Like pkcs11-agent, it never yields `OK custody`, alone or mixed with a confirmed TPM.
- The package doc, the custody table, piv.md and the hardware checklist are updated.
- **Fail-before:** `OK custody: every online key has hardware custody (user, host, machine, ops, log: piv)`.
- **Pass-after:**
  - all doctor tests pass, including `TestTPMNotInspected` and the new `TestPIVCustodyReported`;
  - `CGO_ENABLED=1 -tags piv` build, vet and `-race` pass for doctor, keyroster-signer and keystore/piv;
  - the e2e `TestDoctor*` tests pass.

## Final verification (after the last commit)

- **WSL:** `go test -race -count=1 ./...` passes in every package.
- **golangci-lint:** 0 issues, both by default and with `--build-tags piv`.
- **piv-tag tests:** pass (doctor, keyroster-signer, keystore/piv). They need `LD_LIBRARY_PATH` set to the cached libpcsclite, which WSL does not install.
- **e2e** (`-tags e2e`, OpenSSH 10.5p1): all 16 tests pass, including TestAudit*, TestRefusalsAreAudited, TestDoctor*, TestRootRotationLiveSigner and TestTrustFlowEndToEnd.
- **Not run:** the `e2e_tpm` and `e2e_pkcs11` suites.

## UNVERIFIED

- **F-WR-01:** not run against the homelab signer's real log (bundle v2). The stricter audit check would refuse an old certificate only in one case: the clock stepped back between `serial.Next` and the issuance-time read. That window is microseconds. Run `keyroster audit verify --pin` on a fresh export before merging.
- **F-WR-02:** not run against the homelab database. serve and doctor now parse every logged trust bundle at start. Run `keyroster-signer doctor` on the homelab state.
- **F-WR-03:** not run against GitHub:
  - the real rebase, push, auto-merge and checks paths;
  - the resume push to github.com with the bot's credentials. The harness pushed to a local bare repo, where the github.com helper never fires; only `git credential fill` ran against the real bot config.
  - shellcheck was not run either.

## Out of scope, noted

- `doctor`'s `rootResults` still prints `OK roots: every root has hardware custody` from the bundle's root custody labels alone, `piv` and `fido` roots included. That is the root holders' own declaration in the root-signed bundle, not the online-key claim F-WR-04 is about, so it is unchanged by design.
- F-WR-02 leaves one gap: `root sign --prev` and `trust verify --prev` still accept a v3 that names a root retired in v1, because they hold only the bundle in force. install-bundle refuses that v3 before anything is installed or logged.

## Merge-gate bootstrap

This PR changes `merge-gate.sh`. Its new copy compares itself with `origin/main`'s old copy and refuses to gate from this branch, which is correct: it is unreviewed. There is no bypass. Gate this PR the normal way, from main:

```
git switch main && git merge --ff-only origin/main && bash scripts/merge-gate.sh p01/26-review2-fixes
```

- On main, the file on disk is `origin/main`'s reviewed old copy, which has no guard and runs (shown above, on a made-up branch).
- If it exits 3, the old copy leaves the checkout on the PR branch. Run `git switch main` before you rerun it. A rerun from the PR branch is safe: the new copy refuses and says to switch.
- From the merge on, main's copy carries the guard.

---

_Fixed: 2026-10-10_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
