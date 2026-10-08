---
phase: 01-trust-core
plan: 18
subsystem: trust
tags: [trust-bundle, root-rotation, audit, anchor, pins, runbook, key-07, vis-03, tdd]

requires:
  - phase: 01-trust-core
    provides: "trust.BuildSuccessor, root sign --prev and TestRootRotationLiveSigner (01-17, PR #22); trust.VerifySuccessor and the genesis pin rule (01-03, 01-05, PR #20); audit verify across bundle_install entries (01-05)"
provides:
  - "trust.MatchPins: the exact pinned root set at the pinned threshold, shared by VerifyGenesisBundle, trust verify --prev and audit verify; trust.CheckPins for the pin list alone"
  - "keyroster trust verify --prev DIR: VerifySuccessor against the bundle in force, then MatchPins on the successor's new root set"
  - "audit verify anchored on any bundle in the chain (the anchor bundle), Report.AnchorVersion, an 'anchored:' output line and the anchor_bundle_version JSON field"
  - "docs/runbooks/root-ceremony.md 'Rotate the roots (successor bundle)' built from exercised commands"
affects: [01-20, 01-21, KEY-07, VIS-03]

actuals:
  tokens: 10113
  tasks: 3
  commits: 3
plan_head_before: 24f694311378866c3e718f58f06fca5e21030d5d
plan_head_after: 3172a056222c5fe13d7ad7befe68432bc1406aed

tech-stack:
  added: []
  patterns:
    - "Self-verify, then anchor: the first bundle_install is verified against its own root set (VerifyGenesisBundle with its own fingerprints and threshold), and which bundle the operator's pins anchor is a separate, signature-free decision (MatchPins) on the bundle the verifier returned"
    - "Fail closed at end of stream: anchoring is recorded while the chain is walked, and a log with no anchor is refused after the whole chain verified, with the last bundle's mismatch as the reason"

key-files:
  created:
    - cmd/keyroster/trust_test.go
  modified:
    - internal/trust/verify.go
    - internal/trust/verify_test.go
    - cmd/keyroster/trust.go
    - internal/audit/verify.go
    - internal/audit/verify_test.go
    - cmd/keyroster/audit.go
    - test/e2e/rotation_test.go
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/signer-install.md

key-decisions:
  - "Assumption delta, promote: the anchor bundle (the installed bundle whose root set and threshold equal the pins) replaces 'genesis bundle' as what audit verify pins against; genesis is the special case where the first bundle matches. No second mode (--pin-genesis/--pin-latest) is added"
  - "audit verify anchors on the FIRST bundle that matches the pins; a self-verification failure of the first bundle is reported as 'bundle_install is not a valid genesis bundle', so 'not anchored in the pinned roots' means only that no bundle has the pinned root set and threshold"
  - "Pins and threshold are checked up front with trust.CheckPins (new exported helper), so a malformed pin list or an out-of-range threshold is refused before the log is read, with the same ErrPins/ErrThreshold texts"
  - "trust verify --prev wraps the two refusals distinctly: 'not a valid successor of trust bundle vN in DIR' (VerifySuccessor) and 'the successor's new roots are not the pinned roots' (MatchPins); ignored-signature lines use the union of the previous and new root sets"
  - "fork_under_old_pins is an accepted, documented property: pins of an exposed old root anchor any fork that root signed; the runbook tells auditors to pin the new roots after rotating away from exposed roots"
  - "KEY-07 is not marked complete (it closes in 01-21); requirements-completed lists VIS-03 only"
  - "The requirements.mark-complete tracking step is skipped: REQUIREMENTS.md carries the phase-level status 'Gaps Found' for every phase 1 requirement, set by 01-VERIFICATION.md (which rates VIS-03 SATISFIED), and the phase re-verification after 01-21 resets it; flipping VIS-03 alone mid gap-closure would contradict that status (same handling as 01-19)"

patterns-established:
  - "A runbook section lists the test that runs each of its commands, and labels every step no test runs UNVERIFIED with the plan that will run it"

requirements-completed: [VIS-03]

coverage:
  - id: D1
    description: "trust.MatchPins: the exact root set at its threshold matches (also reordered); a missing, extra or substituted pin and a differing threshold are refused with ErrPins, threshold 0 or above the pins with ErrThreshold, a repeated, malformed or empty pin list with ErrPins; CheckPins refuses exactly the malformed lists. VerifyGenesisBundle unchanged (TestVerifyGenesisBundle unmodified, passing)"
    requirement: VIS-03
    verification:
      - kind: unit
        ref: "go test -count=1 -v -run 'MatchPins|VerifyGenesisBundle' ./internal/trust/ (TestMatchPins 11 subtests)"
        status: pass
    human_judgment: false
  - id: D2
    description: "audit verify anchors on any bundle: new pins anchor v2 and old pins v1 of a rotated log; with v3, each of A, C, D anchors its own bundle; a fork signed by the old root verifies under the old pins and is refused under the new pins ('not anchored in the pinned roots'); v2 without the previous or the new root's signatures, a v2 prev mismatch, a v1 whose policy was changed and a v1 replaced and re-signed by the old root are refused under the new pins; pins matching no bundle are refused. All existing TestVerifyAnchoring cases pass unmodified"
    requirement: VIS-03
    verification:
      - kind: unit
        ref: "go test -count=1 -v -run 'VerifyAnchoring|VerifyAnchorsOnLaterBundle' ./internal/audit/ (TestVerifyAnchorsOnLaterBundle 10 subtests); git diff --numstat origin/main -- internal/audit/verify_test.go -> 176 0"
        status: pass
    human_judgment: false
  - id: D3
    description: "trust verify --prev in the homelab shape (genesis A,B at 1; successor C,D at 1): A+C (plus a foreign signature) under pins C,D passes, with the successor header, per-set signer lines, an ignored line for the foreign key only, and the OK line naming v1; refused: C only (previous roots), A only (new roots), pins A,B, pin C alone, threshold 2, --prev of another genesis (prev hash), and the successor without --prev (not genesis)"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "go test -count=1 -v -run TestTrustVerifySuccessor ./cmd/keyroster/ (8 subtests)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Live rotation R1 -> C,D with the real binaries: trust verify --prev pinned to C,D passes before install and pinned to R1 is refused; after the install and restart, audit verify anchors on v2 under C,D (also --json anchor_bundle_version 2), on v1 under R1, and is refused under C alone"
    requirement: KEY-07
    verification:
      - kind: e2e
        ref: "bash scripts/linux.sh 'KEYROSTER_OPENSSH_PREFIX=$HOME/.cache/keyroster/openssh-10.5p1 go test -tags e2e -count=1 -v ./test/e2e/' -> all 16 tests PASS including TestRootRotationLiveSigner, TestAuditVerifiesIssuance, TestTrustFlowEndToEnd; CI e2e (9.5p1) and e2e (10.5p1) pass"
        status: pass
    human_judgment: false
  - id: D5
    description: "Rotation runbook: 'Rotate the roots (successor bundle)' in root-ceremony.md with the successor rule, the requirement that both the current and the new roots' thresholds sign, the instruction to pin the new roots after rotating away from exposed roots, and the UNVERIFIED label on the offline and homelab steps; signer-install.md links to it"
    requirement: KEY-07
    verification:
      - kind: other
        ref: "grep -c '^## Rotate the roots (successor bundle)' / 'trust verify --prev' / 'UNVERIFIED offline and on the homelab signer' docs/runbooks/root-ceremony.md -> 1 / 3 / 1"
        status: pass
    human_judgment: true
    rationale: "The live-USB steps, separate sticks, paper fingerprints, the vTPM install and the destruction of old roots are run by the owner in 01-20 and 01-21; the owner reviews the procedure at the merge gate"
  - id: D6
    description: "PR #24 is green with auto-merge on and waits for the owner's approval at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 24 --required --watch -> exit 0, all 17 required checks pass on implementation head 3172a05; all three commits verified: true (GitHub API)"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 4 blocking-human merge gate, after this SUMMARY is written"

duration: 29min
completed: 2026-10-08
status: complete
---

# Phase 1 Plan 18: Rotation Verify Summary

**A root rotation can now be checked against the new roots' paper fingerprints at two points. Before the install, `keyroster trust verify --prev DIR --pin <new roots>` runs `VerifySuccessor` against the bundle in force and then requires the successor's root set to be exactly the pins. After the install, `keyroster audit verify --pin <new roots>` anchors on the bundle whose root set and threshold equal the pins (v2), and authenticates the earlier bundles through the prev-hash chain. It fails closed when no bundle matches. A fork signed by an exposed old root verifies under the old pins but not under the new ones. The runbook has a rotation procedure built only from commands the tests run. KEY-07 stays open until 01-21.**

## Performance

- **Duration:** about 29 min
- **Started:** 2026-10-08T12:01:22Z
- **Completed:** 2026-10-08T12:30Z (SUMMARY written)
- **Tasks:** 3 of 4 executed before the merge gate (Task 4 is the owner's approval)
- **Files modified:** 10 (1 created, 9 modified), 858 insertions, 61 deletions

## Accomplishments

- **Task 1 (tracer), `2892f77`.**
  - **`trust.MatchPins`.** The pin block of `VerifyGenesisBundle` is extracted, and `VerifyGenesisBundle` still checks the pin list up front, so its error order is unchanged.
  - **`trust verify --prev`.**
  - **The generalised audit anchor:**
    - the first `bundle_install` self-verifies as a genesis bundle;
    - later ones must pass `VerifySuccessor`;
    - the first bundle that passes `MatchPins` is the anchor;
    - at the end of the log, "not anchored in the pinned roots" carries the last mismatch as its reason.
  - **The `anchored:` line and `anchor_bundle_version`.**
  - **The e2e extension.**
  - **Tracer feedback gate:** interactive, `end-of-phase`, automated-only `<verify>`. Both verify commands were re-run green before Task 2 started.
- **Task 2 (TDD), `55c13b1`.** TestMatchPins (11), TestVerifyAnchorsOnLaterBundle (10) and TestTrustVerifySuccessor (8), plus an e2e `--json` anchor check.
  - All passed against Task 1's code, so no `fix(audit)` commit was needed.
  - Seven mutations show that the tests discriminate (see below).
- **Task 3, `3172a05`.** The rotation section in `root-ceremony.md` and the successor note in `signer-install.md`. PR #24 was published with auto-merge.

### Assumption delta: promote the anchor bundle

`audit verify` used to pin against the genesis bundle. It now pins against the **anchor bundle**: the first installed bundle whose root set and threshold equal the pins. Genesis is the case where the first bundle matches.
- No `--pin-genesis`/`--pin-latest` pair was added.
- `TestVerifyAnchorsOnLaterBundle/rotation_new_pins_anchor_v2` and `rotation_twice_pins_middle_anchor_v2` fail if anchoring becomes genesis-only again (mutation M3).

### Documented residual: fork_under_old_pins

Pins of an exposed old root anchor any chain that root signed. The test builds a separate genesis signed by root A, with its own log key and CAs.
- It verifies under pins A.
- It is refused under pins C with "not anchored in the pinned roots".

This is accepted and documented, not prevented. The runbook (step 7) tells auditors to pin the NEW roots after rotating away from exposed roots, and `audit verify` names the anchored bundle so the auditor sees which root set vouches for the log (T-01-82, T-01-84).

## PR

- **PR #24**: `feat(trust): verify root rotations against the new roots` (https://github.com/Labontese/keyroster/pull/24).
  - Branch `p01/18-rotation-verify`, opened by keyroster-bot, auto-merge (squash) enabled.
- **Required checks:** all 17 pass on implementation head `3172a05`:
  - Analyze (actions), Analyze (go), build-piv, build-test, capslock, dependency-firewall;
  - e2e (9.5p1), e2e (10.5p1), e2e-pkcs11 (10.5p1-ed25519), e2e-pkcs11 (distro-p256), e2e-tpm;
  - fuzz, govulncheck, lint, pinned-actions, pr-title, systemd-sandbox.
- **Signatures:** `2892f77`, `55c13b1` and `3172a05` all show `verified: true` (GitHub API).

## Task Commits

1. **Task 1 (tracer): verify root rotations against the new roots.** `2892f77` (feat)
2. **Task 2: anchoring and successor-verify rules as tests.** `55c13b1` (test). No fix commit, because no code change was needed.
3. **Task 3: rotation runbook.** `3172a05` (docs)
4. **Task 4: merge gate.** No commit (owner approval; GitHub squash-merges).

**Plan metadata:** the `docs(01-18): complete rotation-verify plan` commit on the same PR branch. `actuals.commits` (3) is measured at `3172a05`, before that commit.

### TDD evidence

| Gate | Command | Exit | Result |
|---|---|---|---|
| RED (`55c13b1`) | `go test -count=1 -v -run 'MatchPins\|VerifyGenesisBundle\|VerifySuccessor\|TrustVerify\|VerifyAnchoring\|VerifyAnchorsOnLaterBundle' ./internal/trust/... ./internal/audit/... ./cmd/keyroster/...` | 0 | **Unexpected GREEN**: all 29 new cases passed, and 106 PASS lines in total, including every existing TestVerifyAnchoring case. |
| Discrimination (mutation check, not committed) | 7 mutations of Task 1's code, each applied, run with the same command, then restored | 1 each | Every mutation made at least one test fail (table below). |
| GREEN | same command, plus `go test -race -count=1 ./...` (WSL), the full e2e suite (WSL) and CI | 0 | All pass, no DATA RACE. |

**Why the RED run was green.** Task 1 is a tracer that builds the whole slice. The tests were committed as written and are recorded as an unexpected GREEN; no failure was invented. Breaking each rule in turn shows that the tests can fail:

| Mutation | Tests that failed |
|---|---|
| M1: audit anchors on the first bundle unconditionally (no MatchPins) | TestVerifyAnchoring/unpinned_root, pins_name_other_root, threshold_above_bundle; TestVerifyAnchorsOnLaterBundle/fork_under_old_pins, pins_match_no_bundle, rotation_new_pins_anchor_v2, rotation_twice_pins_middle_anchor_v2 |
| M2: end-of-stream anchor check skipped | TestVerifyAnchoring/unpinned_root, pins_name_other_root, threshold_above_bundle; TestVerifyAnchorsOnLaterBundle/fork_under_old_pins, pins_match_no_bundle |
| M3: genesis-only anchoring | TestVerifyAnchorsOnLaterBundle/rotation_new_pins_anchor_v2, rotation_twice_pins_middle_anchor_v2 |
| M4: trust verify --prev without MatchPins | TestTrustVerifySuccessor/pins_name_previous_roots_refused, pins_one_new_root_refused, pinned_threshold_differs_refused |
| M5: --prev ignored-signature lines from the previous roots only | TestTrustVerifySuccessor/previous_and_new_root_signed_ok |
| M6: MatchPins without the threshold equality | TestMatchPins/threshold_differs_from_bundle; TestVerifyGenesisBundle/threshold_differs_from_bundle_refused; TestVerifyAnchoring/threshold_above_bundle; TestTrustVerifySuccessor/pinned_threshold_differs_refused |
| M7: MatchPins without the root count | TestMatchPins/extra_pin; TestVerifyGenesisBundle/extra_pin_refused; TestVerifyAnchoring/pins_name_other_root; TestVerifyAnchorsOnLaterBundle/pins_match_no_bundle; TestTrustVerifySuccessor/pins_one_new_root_refused |

## Commands Run (all on the PR branch)

| Command | Result |
|---|---|
| `bash scripts/linux.sh 'KEYROSTER_OPENSSH_PREFIX=… go test -tags e2e -count=1 -v -run "TestRootRotationLiveSigner\|TestAuditVerifiesIssuance\|TestTrustFlowEndToEnd" ./test/e2e/'` (Task 1) | 3 × PASS |
| `go build ./... && go vet ./... && go test -count=1 ./internal/trust/... ./internal/audit/... ./cmd/keyroster/...` (Windows) | pass |
| `git diff origin/main -- internal/audit/verify_test.go internal/trust/verify_test.go test/e2e/audit_test.go go.mod go.sum` after Task 1 | empty |
| `git diff --numstat origin/main -- internal/audit/verify_test.go internal/trust/verify_test.go` after Task 2 | `176 0`, `49 0` (additions only) |
| WSL: `go test -race -count=1 ./...` | exit 0, no FAIL, no DATA RACE |
| WSL: `go vet ./... && go vet -tags e2e ./test/e2e/` | exit 0 |
| WSL: `$(go env GOROOT)/bin/gofmt -l .` | empty |
| WSL: `$HOME/go/bin/golangci-lint run ./...` (v2.14.0) | 0 issues |
| WSL: `bash scripts/capslock-check.sh` and `bash scripts/dep-firewall.sh` | both exit 0 |
| WSL: the full e2e suite (`go test -tags e2e -count=1 -v ./test/e2e/`, OpenSSH 10.5p1) | exit 0, all 16 tests PASS |
| `grep -c` for the runbook heading, `trust verify --prev` and the UNVERIFIED label | 1, 3, 1 |
| `scripts/gh-as-bot.sh pr checks 24 --required --watch` | exit 0, 17/17 pass on `3172a05` |

## Files Created/Modified

- `internal/trust/verify.go`: `CheckPins` and `MatchPins`. `VerifyGenesisBundle` calls both, with unchanged behaviour.
- `cmd/keyroster/trust.go`:
  - the `--prev` flag and `verifySuccessorBundle`;
  - `rootKeyMap` and `reportSigners`, shared with the unchanged genesis path.
- `internal/audit/verify.go`:
  - `verifySelfSignedGenesis`;
  - `anchorVersion` and `lastMismatch` on the anchor state;
  - the up-front `CheckPins`, the end-of-stream anchor check and `Report.AnchorVersion`;
  - updated doc comments on `Options.Pins`, `Options.Threshold` and `Verify`.
- `cmd/keyroster/audit.go`:
  - the `--pin`/`--threshold` help;
  - the `anchored:` line, printed between the byte-identical OK and `not checked:` lines;
  - `anchor_bundle_version`.
- `test/e2e/rotation_test.go`: `trust verify --prev` before the install, and `audit verify` anchoring (v2, v1, none, `--json`) after it.
- `internal/trust/verify_test.go`: `TestMatchPins`.
- `internal/audit/verify_test.go`: `TestVerifyAnchorsOnLaterBundle`.
- `cmd/keyroster/trust_test.go` (new): `TestTrustVerifySuccessor`.
- `docs/runbooks/root-ceremony.md`: "Rotate the roots (successor bundle)".
- `docs/runbooks/signer-install.md`: the successor's origin and check, and the updated UNVERIFIED note.

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

**1. [Rule 2 - Correctness] `trust.CheckPins` exported.**
- **Issue:** `audit` must validate pins and the threshold before reading the log (plan step 3), but `pinSet` is unexported.
- **Fix:** `CheckPins` (the pinSet parse and the 1..len range) is exported, and `MatchPins` and `VerifyGenesisBundle` use it. The error texts are unchanged.
- Without it, `threshold_zero` would only pass because the end-of-stream text happens to contain "threshold".

**2. [Wording] The genesis self-verification failure has its own prefix.**
- The first bundle's failures read "bundle_install is not a valid genesis bundle: ..." instead of "not anchored in the pinned roots", so the latter means only "no bundle matches the pins".
- The existing assertions ("threshold not met") still pass unmodified.

**3. [Test shape] TestTrustVerifySuccessor uses agent-held keys.**
- Its software roots (custody=software) are held in the in-memory agent keyring of `root_test.go` rather than created with `root init`. That avoids four scrypt runs per test run.
- The successor still comes from `root sign --prev`, and its signatures are added per case.
- The `root init` + `--key` path for successors is covered by `TestRootSignSuccessor` (01-17) and by the e2e test.

**4. [Test additions] Cases beyond the plan's list:**
- `rotation_twice_pins_middle_anchor_v2`: a v3 after the anchor is still checked as a successor, and each root set anchors its own bundle;
- `v1_replaced_and_resigned_anchor_v2`: the old root re-signs a replacement v1, so v1 self-verifies, and only v2's prev hash catches it;
- in `TestMatchPins`, the reordered, substituted, above-the-pins and empty cases;
- in `TestTrustVerifySuccessor`, `pins_one_new_root_refused`, `pinned_threshold_differs_refused`, `without_prev_successor_is_not_genesis`, and a foreign signature in the OK case;
- an e2e `--json` check of `anchor_bundle_version`.

**5. [Precision] Stricter e2e assertions than the plan's.**
- The plan asked for `pinned` on the R1 refusal. The test checks the more specific "not the pinned roots", which only the MatchPins refusal prints.
- The anchored lines are matched in full, including the trailing newline.

**6. [Tracking] `requirements.mark-complete` was not run.**
- REQUIREMENTS.md lists every phase 1 requirement as `Gaps Found`, the phase-level result of `01-VERIFICATION.md`, which rates VIS-03 SATISFIED.
- Marking VIS-03 Complete alone during gap closure would contradict that phase-level status. The phase re-verification after 01-21 sets it.
- 01-19 handled its step the same way. STATE.md and ROADMAP.md were updated once.

**Total deviations:** 1 Rule 2 addition, 1 wording choice, 1 test-shape choice, test and precision additions, and 1 skipped tracking step. No scope creep, and no module was added.

## Issues Encountered

- **Escaping in the Bash tool.** In this session the Bash tool rewrote escape sequences inside heredocs and inline WSL command strings. `\\n` became a newline, and `$?`/`$(...)` were expanded in the wrong shell.
  - One Python heredoc patch failed on its assertion, and one inserted a literal newline into a Go string. The newline was fixed with Edit before any commit.
  - The WSL checks were moved into script files in the scratchpad, which gave clean exit codes.
- **capslock reports a pre-existing difference.** It still reports `internal/cert CAPABILITY_ARBITRARY_EXECUTION` as no longer present, as recorded in 01-17. The check exits 0.

## Not Exercised (UNVERIFIED)

- **The offline ceremony and the homelab rotation:**
  - the live-USB steps, separate sticks and paper fingerprints;
  - signing with the exposed TEST roots where they are kept;
  - the stop, install and start sequence on the vTPM signer;
  - the destruction of the old roots.

  The runbook labels these UNVERIFIED. Plans 01-20 and 01-21 run them.
- **Exact numbers in the runbook's example OK line.** The homelab line in the runbook ("previous roots 1 of 2 ...; new roots 2 of 2 ...") has the format the tests check, but with numbers no test produces. The unit test produces 1 of 2 and 1 of 2, and the e2e test 1 of 1 and 1 of 2.

## Threat Flags

None. No new network endpoint, auth path or file access pattern. `trust verify --prev` reads two files from a directory the operator names, like the existing `--bundle`/`--policy`.

## User Setup Required

None.

## Next Phase Readiness

- Plan 01-20 can run the real ceremony with `root sign --prev`, `trust verify --prev` and `audit verify --pin <new roots>`, following "Rotate the roots".
- KEY-07 remains Pending in REQUIREMENTS.md. It closes in 01-21.

---
*Phase: 01-trust-core*
*Completed: 2026-10-08*

## Self-Check: PASSED

- Files exist: `internal/trust/verify.go`, `cmd/keyroster/trust.go`, `cmd/keyroster/trust_test.go`, `internal/audit/verify.go`, `cmd/keyroster/audit.go`, `docs/runbooks/root-ceremony.md`, and this SUMMARY.
- Commits exist on `p01/18-rotation-verify`: `2892f77`, `55c13b1`, `3172a05`.
- `frontmatter.validate --schema summary`: valid; `requirements-completed: [VIS-03]`, no KEY-07.
