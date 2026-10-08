---
phase: 01-trust-core
plan: 17
subsystem: trust
tags: [trust-bundle, root-rotation, successor, tuf, root-ceremony, sshsig, e2e, openssh, tdd]

requires:
  - phase: 01-trust-core
    provides: "trust.VerifySuccessor with the policy chain and admin-not-root rule (PR #20), keyroster root sign/init (01-03, 01-11), install-bundle successor path and the state-dir lock (01-07, PR #20), audit verify across bundle_install entries (01-05)"
provides:
  - "trust.BuildSuccessor: the unsigned successor bundle (version+1, prev hash, new root set, CA/ops/log carried unchanged, policy hash)"
  - "checkSuccessorChain: one signature-free successor rule shared by BuildSuccessor and VerifySuccessor"
  - "keyroster root sign --prev DIR: successor mode, signable by a previous or a new root through --key or --agent-key"
  - "e2e TestRootRotationLiveSigner: stop, install-bundle, start, issue, sshd login and audit verify across a root rotation"
affects: [01-18, 01-20, 01-21, KEY-07, KEY-08]

actuals:
  tokens: 11401
  tasks: 2
  commits: 3
plan_head_before: b1bf20605ea89c046c65ab15124f02a781d4cb3e
plan_head_after: f6f419dfdc1f8e167aa96e42f6439df3e7c2d381

tech-stack:
  added: []
  patterns:
    - "Builder and verifier share one unexported rule function (checkSuccessorChain), so a document the builder emits verifies under the verifier's rule by construction"
    - "A marker sentinel that wraps a public sentinel with identical text (errIssuedBeforePrev) lets a caller add a hint without changing the verifier's error text"
    - "prepareBundle takes the bundle builder as a function of issued_at, so genesis and successor share the write-or-rerun-compare contract"

key-files:
  created:
    - internal/trust/successor.go
    - internal/trust/successor_test.go
    - test/e2e/rotation_test.go
  modified:
    - internal/trust/verify.go
    - cmd/keyroster/root.go
    - cmd/keyroster/root_test.go

key-decisions:
  - "root sign --prev DIR selects successor mode (no separate --successor switch); --ca-pubkeys with --prev is a usage error (exit 2) because CA, ops and log keys are carried from the previous bundle and CA rotation is KEY-08 (Phase 3)"
  - "A signing root is looked up in the new root set first, then the previous one; its custody label comes from the set it is in, and a --key custody mismatch names DIR/bundle.json when the label came from the previous bundle"
  - "BuildSuccessor validates the assembled bundle before the shared chain check (the order VerifySuccessor uses: parse next, then chain); VerifySuccessor now parses next before the prev-side checks, which changes only which error wins when both sides are malformed"
  - "The ceremony-clock hint is added by BuildSuccessor around the shared error (errIssuedBeforePrev), so VerifySuccessor's error texts stay byte-identical"
  - "KEY-07 is not marked complete: it closes in 01-21 after the owner's offline ceremony and the destruction of the TEST roots"

patterns-established:
  - "Successor refusals happen before --out-dir is created: the admin check runs before prepareBundle, and the builder runs before MkdirAll"

requirements-completed: []

coverage:
  - id: D1
    description: "BuildSuccessor builds version N+1 (prev = SHA-256 of the previous canonical bundle, new roots and threshold, CA/ops/log copied and not aliased, policy hash); round trips through VerifySuccessor: A+C accepted, C+D only and A+B only refused with ErrThreshold, chained v2 policy accepted"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "go test -count=1 -v -run TestBuildSuccessor ./internal/trust/ (round_trip_unchanged_policy, round_trip_chained_policy, carries_online_keys)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Refusal table: BuildSuccessor and VerifySuccessor (input signed by both root sets) refuse each case with the same sentinel: prev_canonical_differs, prev_policy_hash_mismatch, policy_same_version_changed, policy_version_plus_two, policy_wrong_prev, issued_before_prev (with the clock hint), admin_is_new_root, admin_is_previous_root; threshold_zero and threshold_above_roots refused through Bundle.Validate"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "go test -count=1 -v -run TestBuildSuccessor ./internal/trust/"
        status: pass
    human_judgment: false
  - id: D3
    description: "root sign --prev in the homelab shape (software roots A,B -> C,D): previous root A and new root C sign with --key, VerifySuccessor passes over the --out-dir files; --ca-pubkeys (exit 2), unknown root, admin is a previous/new root, unchained policy, out-dir = prev, non-canonical prev bundle, prev policy mismatch and a clock before the previous issued_at are refused with --out-dir unwritten; a rerun signs only the missing document and --threshold 2 on a rerun is refused"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "go test -count=1 -v -run TestRootSignSuccessor ./cmd/keyroster/ (13 subtests)"
        status: pass
    human_judgment: false
  - id: D4
    description: "A live signer rotates from genesis root R1 to new age software roots C and D with the real binaries: install-bundle refused while serve holds the lock, refused after stop with only C's signatures (threshold not met, previous roots), installed without --pin once R1 co-signs; after restart a pol=1 certificate under the unchanged user CA logs in to sshd 10.5p1, and audit verify pinned to R1 reports trust bundle v2, issued 2"
    requirement: KEY-07
    verification:
      - kind: e2e
        ref: "bash scripts/linux.sh 'KEYROSTER_OPENSSH_PREFIX=$HOME/.cache/keyroster/openssh-10.5p1 go test -tags e2e -count=1 -v -run TestRootRotationLiveSigner ./test/e2e/' -> --- PASS; CI e2e (9.5p1) and e2e (10.5p1) pass"
        status: pass
    human_judgment: false
  - id: D5
    description: "Genesis root sign and VerifySuccessor behaviour unchanged: verify_test.go, internal/signer and internal/audit untouched and passing; genesis output prints no successor header"
    verification:
      - kind: unit
        ref: "git diff origin/main -- internal/trust/verify_test.go internal/signer internal/audit (empty); go test -race -count=1 ./... in WSL (exit 0, no DATA RACE)"
        status: pass
    human_judgment: false
  - id: D6
    description: "A FIDO, PIV or PKCS#11 previous root signing a successor through ssh-agent (UNVERIFIED: covered only by the shared genesis agent path plus rootByFingerprint's second set)"
    requirement: KEY-07
    verification: []
    human_judgment: true
    rationale: "No test drives a hardware-held previous root through root sign --prev; the homelab rotation (01-20/01-21) uses software TEST roots as the previous set"
  - id: D7
    description: "PR #22 is green with auto-merge on and waits for the owner's approval at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 22 --required --watch -> all 17 required checks pass on head f6f419d"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 3 blocking-human merge gate, after this SUMMARY is written"

duration: 35min
completed: 2026-10-08
status: complete
---

# Phase 1 Plan 17: Successor Builder Summary

**`keyroster root sign --prev DIR` now builds trust bundle version N+1 from the bundle and policy in force. Its `prev` is the SHA-256 of the previous bundle, it names the new root set, and it carries the CA, ops and log keys unchanged. A root of the previous set or of the new set can sign it. The builder and `VerifySuccessor` share one chain rule (`checkSuccessorChain`), so a successor the builder emits verifies by construction. An e2e test rotates a live signer from root R1 to roots C and D with the real binaries and real sshd. KEY-07 stays open until the owner's ceremony (01-20/01-21).**

## Performance

- **Duration:** 35 min
- **Started:** 2026-10-08T05:27:39Z
- **Completed:** 2026-10-08T06:02:44Z
- **Tasks:** 2 of 3 executed before the merge gate (Task 3 is the owner's approval)
- **Files modified:** 6 (3 created, 3 modified), 963 insertions, 70 deletions

## Accomplishments

- **Task 1 (tracer):** `trust.BuildSuccessor`, the `--prev` mode of `root sign`, and the e2e test `TestRootRotationLiveSigner`. The successor header prints `Successor of trust bundle vN, sha256 …`, the previous roots, and `signatures needed: t1 of the n previous roots AND t2 of the m new roots, on both documents`. Genesis output is unchanged.
  - The tracer feedback gate applied row 3 (interactive, `end-of-phase`, automated-only `<verify>`). `<verify>` was re-run and was green before Task 2 started.
- **Task 2:** `TestBuildSuccessor` (3 round trips, 8 refusals checked against both functions, 2 Validate refusals) and `TestRootSignSuccessor` (13 subtests).
  - The signature-free rules moved into `checkSuccessorChain`, which `VerifySuccessor` and `BuildSuccessor` both call.
  - The branch was published as PR #22 with auto-merge, and all 17 required checks pass.

## PR

- **PR #22**: `feat(root): build successor trust bundles with root sign --prev` (https://github.com/Labontese/keyroster/pull/22).
  - Branch `p01/17-successor-builder`, opened by keyroster-bot, auto-merge (squash) enabled.
- **Required checks on implementation head `f6f419d`:** all 17 pass.
  - Analyze (actions), Analyze (go), build-piv, build-test, capslock, dependency-firewall;
  - e2e (9.5p1), e2e (10.5p1), e2e-pkcs11 (10.5p1-ed25519), e2e-pkcs11 (distro-p256), e2e-tpm;
  - fuzz, govulncheck, lint, pinned-actions, pr-title, systemd-sandbox.
- **Signatures:** all three implementation commits show `verified: true` (GitHub API).

## Task Commits

1. **Task 1 (tracer): end-to-end rotation of a live signer's roots.** `65ee671` (feat)
2. **Task 2: successor rules as tests, then one shared chain check.** Tests `0c3f1b2` (test), then `f6f419d` (feat).
3. **Task 3: merge gate.** No commit (owner approval; GitHub squash-merges).

**Plan metadata:** the `docs(01-17): complete successor-builder plan` commit on the same PR branch.

### TDD evidence

| Gate | Command | Exit | Result |
|---|---|---|---|
| RED (`0c3f1b2`) | `go test -count=1 -v -run 'TestBuildSuccessor\|TestRootSignSuccessor' ./internal/trust/... ./cmd/keyroster/...` | 0 | **Unexpected GREEN**: all 26 new cases passed (13 in TestBuildSuccessor, 13 in TestRootSignSuccessor). |
| Discrimination (mutation check, not committed) | 8 mutations, each applied to `successor.go` or `root.go` at `0c3f1b2`, then restored | 1 each | Every mutation made at least one new test fail (table below). |
| GREEN (`f6f419d`) | same command, plus `go test ./...` (Windows), `go test -race ./...` (WSL), and the full e2e suite (WSL) | 0 | All pass, no DATA RACE. |

**Why the RED run was green.** Task 1 is a tracer. The plan has it build the whole slice first, with the checks written inline, and Task 2's action says the cases those inline checks satisfy "may pass".
- The tests were committed as written and are recorded here as an unexpected GREEN. No failure was invented to manufacture a RED.
- To show that the tests can fail, each rule was broken in turn:

| Mutation | New tests that failed |
|---|---|
| admin check removed from BuildSuccessor | TestBuildSuccessor/admin_is_new_root, admin_is_previous_root |
| issued_at order check disabled | TestBuildSuccessor/issued_before_prev; TestRootSignSuccessor/clock_before_prev_refused |
| prevPolicy hash check disabled | TestBuildSuccessor/prev_policy_hash_mismatch; TestRootSignSuccessor/prev_policy_mismatch_refused |
| CA slice aliased instead of copied | TestBuildSuccessor/carries_online_keys |
| policy chain check disabled | TestBuildSuccessor/policy_same_version_changed, policy_version_plus_two, policy_wrong_prev; TestRootSignSuccessor/unchained_policy_refused |
| previous root set not searched by rootByFingerprint | TestRootSignSuccessor/previous_root_signs_with_key (and the subtests that sign with A) |
| out-dir = prev check disabled | TestRootSignSuccessor/out_dir_equals_prev_refused |
| CLI admin pre-check without the previous roots | TestRootSignSuccessor/admin_is_previous_root |

The first mutation pass showed two weak spots, and both were fixed before the test commit:
- `prev_policy_hash_mismatch` was caught only through the policy-chain rule. Its policy now equals its prevPolicy, so only the hash check can refuse it.
- With aliasing, `carries_online_keys` corrupted the shared fixture. It now uses its own fixture.

## Commands Run (all on the PR branch)

| Command | Result |
|---|---|
| `bash scripts/linux.sh 'KEYROSTER_OPENSSH_PREFIX=… go test -tags e2e -count=1 -v -run TestRootRotationLiveSigner ./test/e2e/'` | `--- PASS: TestRootRotationLiveSigner` (4.6 s) |
| `go build ./... && go vet ./... && go test -count=1 ./internal/trust/... ./cmd/keyroster/...` (Windows) | pass |
| `bash scripts/linux.sh 'go vet -tags e2e ./test/e2e/'` | pass |
| `git diff --name-only origin/main -- test/e2e/harness_test.go test/e2e/bootstrap_test.go go.mod go.sum` | empty |
| `git diff origin/main -- internal/trust/verify_test.go internal/signer internal/audit` | empty |
| `go test -count=1 -v -run 'BuildSuccessor\|VerifySuccessor\|RootSignSuccessor\|SoftwareRoot\|RootSign' ./internal/trust/... ./cmd/keyroster/...` | all PASS |
| `bash scripts/linux.sh 'go test -race -count=1 ./...'` | exit 0, no FAIL, no DATA RACE |
| `gofmt -l` (Windows over internal, cmd, test; WSL `$(go env GOROOT)/bin/gofmt -l .`) | empty |
| `bash scripts/linux.sh '$HOME/go/bin/golangci-lint run ./...'` (v2.14.0) | 0 issues |
| `bash scripts/linux.sh 'bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh'` | both exit 0 |
| `bash scripts/linux.sh 'KEYROSTER_OPENSSH_PREFIX=… go test -tags e2e -count=1 -v ./test/e2e/'` | exit 0, all 16 tests PASS |
| `scripts/gh-as-bot.sh pr checks 22 --required --watch` | exit 0, 17/17 pass |

## Files Created/Modified

- `internal/trust/successor.go`: `BuildSuccessor`.
- `internal/trust/verify.go`: `checkSuccessorChain` and `errIssuedBeforePrev`. `VerifySuccessor` now parses next, calls the chain check, then runs its unchanged signature loop.
- `cmd/keyroster/root.go`:
  - the `--prev` flag and the mode-specific usage text;
  - `successorBuilder` and `successorHeader`;
  - `prepareBundle` now takes the builder as a function of issued_at;
  - `rootByFingerprint` also searches the previous set.
- `internal/trust/successor_test.go`: `TestBuildSuccessor`.
- `cmd/keyroster/root_test.go`: `TestRootSignSuccessor` and `setCeremonyNow`. The existing tests are unchanged.
- `test/e2e/rotation_test.go`: `TestRootRotationLiveSigner`, plus the `serveStoppable` and `keyrosterWithPassphrase` helpers.

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

**1. [Ordering] BuildSuccessor validates before the chain check.**
- The plan said BuildSuccessor "calls checkSuccessorChain and then next.Validate()". It runs `next.Validate()` first, which is the order VerifySuccessor uses (ParseBundle validates next before the chain check).
- The refusal set is the same, and the threshold cases are still refused with `ErrInvalid`.

**2. [Ordering] VerifySuccessor now parses next before the prev-side checks.**
- This is the shape the plan specifies ("VerifySuccessor parses next, calls checkSuccessorChain").
- The only observable effect is which error is reported when both the previous and the next documents are malformed. Every input is refused exactly as before, and every existing test passes unmodified.

**3. [Rule 2 - Correctness] The custody-mismatch error names the right file.**
- When `--key` resolves to a previous root whose label is not `custody=software`, the error names `DIR/bundle.json` (where that label comes from) instead of `--roots`.

**4. [TDD] Unexpected GREEN at RED.** See "TDD evidence" above.

**Total deviations:** 2 ordering notes, 1 Rule 2 refinement, and 1 documented TDD outcome. No scope creep, and no module was added.

## Issues Encountered

- **A Python heredoc failed.** A heredoc that applied the root.go patch through Python failed with a shell quoting error before writing anything. The changes were made with the Edit tool instead.
- **gofmt is not on PATH in the WSL login shell.** The `test -z "$(gofmt -l .)"` form of the plan's verify therefore passes vacuously there. gofmt was rerun with `$(go env GOROOT)/bin/gofmt` (empty) and on Windows (empty). Plan authors should use that form in `<verify>`.
- **capslock reports a pre-existing difference.** It reports 72 (package, capability) pairs against a baseline of 73, because `internal/cert CAPABILITY_ARBITRARY_EXECUTION` is no longer reported.
  - The same result occurs on `origin/main` (checked in a temporary worktree), so this plan did not cause it.
  - The check exits 0. Tightening the baseline is left to a reviewed PR, as the script says.

## Not Exercised (UNVERIFIED)

- **Hardware-held previous root.** No test covers a FIDO, PIV or PKCS#11 previous root signing a successor through ssh-agent.
  - That path is the genesis `--agent-key` path plus `rootByFingerprint`'s second set. The e2e test covers the agent path with an ordinary Ed25519 key in ssh-agent (R1, custody=software).
  - The homelab rotation (01-20/01-21) signs with the software TEST roots as the previous set.
- **Rotations with more than one previous root.** Successor bundles beyond v2 (v2 to v3) and previous root sets with more than one signer required (threshold above 1) are covered only by the shared rule's unit tests, not end to end.

## User Setup Required

None.

## Next Phase Readiness

- Plan 01-18 can build `trust verify --prev`, `audit verify` anchored on any bundle, and the rotation runbook on top of `BuildSuccessor` and `root sign --prev`.
- KEY-07 remains Pending in REQUIREMENTS.md. It closes in 01-21.

---
*Phase: 01-trust-core*
*Completed: 2026-10-08*

## Self-Check: PASSED

- Files exist: `internal/trust/successor.go`, `internal/trust/successor_test.go`, `test/e2e/rotation_test.go`, and this SUMMARY.
- Commits exist on `p01/17-successor-builder`: `65ee671`, `0c3f1b2`, `f6f419d`.
