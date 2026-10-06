---
phase: quick-261006-ixz
plan: 01
subsystem: testing
tags: [go, signer, test-clock, flaky-test, freshness, d-14]

requires:
  - phase: 01-trust-core
    provides: "signer.Config.Clock seam (serial.Clock), signerOpts.clock in newTestSigner, fakeClock in refusal_test.go"
provides:
  - "fakeClock.Tick: a stepping signer test clock (1 µs per read, never reads the wall clock)"
  - "TestSignerRefusals that gives the same result regardless of elapsed wall time, with a self-check that fails if the clock advanced 1 s or more"
  - "logEnv.clock / newLogEnvClock: an optional signer and bootstrap clock for in-package signer tests"
  - "TestEvidence/created_at_outside_skew_* on a pinned whole-second signer clock"
affects: [internal/signer tests, CI build-test stability]

actuals:
  tokens: 9500      # chars/4 over the realized diff (code ~1440 + planning docs)
  tasks: 3
  commits: 2        # MEASURED at SUMMARY write: git rev-list --count plan_head_before..HEAD (the docs commit carrying this file is the 3rd)
plan_head_before: f69d050e6a0dbd6d618214b7b228575d9b22e37c
plan_head_after: 66fd3c3974232f463759def280e007f6593dc2e7

tech-stack:
  added: []
  patterns:
    - "Boundary tests for whole-second wire timestamps run the signer on an injected clock from a whole-second base, never on the wall clock"
    - "A stepping clock (strictly increasing per read) where serial.Next must progress; a frozen clock only where the request is refused before serial.Next"

key-files:
  created: []
  modified:
    - internal/signer/refusal_test.go
    - internal/signer/signer_test.go
    - internal/signer/log_test.go
    - internal/signer/evidence_test.go
    - .planning/phases/01-trust-core/deferred-items.md
    - .planning/STATE.md

key-decisions:
  - "Fix in test code only, through the existing Config.Clock seam. issue.go (maxClockSkew 300 s, strict > / <) stays byte-identical."
  - "TestSignerRefusals uses a stepping clock rather than a frozen one: after the seed issuance a frozen clock would stall serial.Next (serial_unavailable) for certificate_subject and the bad_subject cases."
  - "TestEvidence's skew subtests use a frozen clock pinned to a whole second. The request is refused at the freshness check, before serial.Next, so stepping is unnecessary."

patterns-established:
  - "fakeClock.Tick for socket-level signer tests that need a deterministic and progressing clock"
  - "newLogEnvClock(t, fx, clock) for in-package signer tests that need a pinned clock"

requirements-completed: [D-14]

coverage:
  - id: D1
    description: "TestSignerRefusals/created_301s_* gives the same result regardless of wall time (stepping test clock)"
    requirement: "D-14"
    verification:
      - kind: unit
        ref: "bash scripts/linux.sh 'go test -race -count=200 -timeout 60m -run TestSignerRefusals/created_301s ./internal/signer/'"
        status: pass
      - kind: unit
        ref: "internal/signer/signer_test.go#TestSignerRefusals with an injected 1.1 s pause (temporary, reverted)"
        status: pass
    human_judgment: false
  - id: D2
    description: "TestEvidence/created_at_outside_skew_* gives the same result regardless of wall time (pinned logEnv clock)"
    requirement: "D-14"
    verification:
      - kind: unit
        ref: "bash scripts/linux.sh 'go test -race -count=200 -timeout 60m -run TestEvidence/created_at_outside_skew ./internal/signer/'"
        status: pass
      - kind: unit
        ref: "internal/signer/evidence_test.go#TestEvidence with an injected 1.1 s pause (temporary, reverted)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Production freshness check unchanged; the whole signer suite is green"
    requirement: "D-14"
    verification:
      - kind: unit
        ref: "bash scripts/linux.sh 'go test -race -count=1 ./internal/signer/' + go vet + gofmt -l + no non-_test.go diff vs origin/main under internal/signer + go.mod/go.sum unchanged"
        status: pass
    human_judgment: false
  - id: D4
    description: "Bot PR #16 open with auto-merge squash, required checks green, merge gate waiting for the owner's approval"
    verification: []
    human_judgment: true
    rationale: "The owner's approval and the merge are human steps by design (main-review ruleset; the bot never approves or merges)."

duration: ~25min (execution and local verification; the CI wait is extra)
completed: 2026-10-06
status: complete
---

# Quick Task 261006-ixz: Deterministic signer freshness-boundary tests Summary

**`TestSignerRefusals` now runs on a stepping fake clock (`fakeClock.Tick`, 1 µs per read from a whole-second base), and the `TestEvidence` skew subtests run on a pinned `logEnv` signer clock. The ±301 s refusal cases no longer depend on whether a wall-clock second boundary falls between the test's capture and the signer's read, and the production 300 s check is untouched.**

## Performance

- **Duration:** about 25 min for execution and local verification, plus the CI wait
- **Started:** 2026-10-06T11:55:32Z
- **Completed (local work):** 2026-10-06T12:06Z
- **Tasks:** 3 of 3
- **Files modified:** 4 test files and 3 planning files

## Root cause (corrected)

`IssueRequest.CreatedAt` holds whole seconds, while the signer clock has sub-seconds (`internal/signer/issue.go:55-57`). The test captured `now` once from the wall clock, and the signer read the wall clock again at the check. `now + 301` is refused only while both reads fall in the **same wall-clock second**. A few milliseconds of delay across a second boundary is enough, not "about one second", so the failure rate grows with CPU load. This caused CI runs 37307671187 (PR #9) and 37425878563 (PR #15). `TestEvidence/created_at_outside_skew_future` had the same race between `logEnv.request()` and the `logEnv` signer.

## Accomplishments

- **`fakeClock.Tick`** (`refusal_test.go`): a strictly increasing signer clock that moves only when read. `Now`, `Set`, `Add` and `newFakeClock` are unchanged, so `TestRefusalClockRegressionEpisodes` still asserts its exact frozen value.
- **`TestSignerRefusals`**:
  - runs on `signerOpts{clock: clk.Tick}` from `base := time.Now().Truncate(time.Second)`;
  - the seed request gets `CreatedAt = now`, and every subtest request comes from `requestAt(t, clk)`;
  - the table (`now ± 301`, `0`, `1<<64 - 1`) and its expected codes are unchanged;
  - a self-check fails the test if the clock advanced 1 s or more.
- **`logEnv`** gains `clock func() time.Time` and `newLogEnvClock(t, fx, clock)`. The clock is passed to `fx.Bootstrap` and `Config.Clock`. A nil clock gives exactly today's behaviour, and `newLogEnvFx` now delegates to it.
- **`TestEvidence/created_at_outside_skew_*`** run on a signer pinned to `at := time.Now().Truncate(time.Second)`, with `CreatedAt = at ± 301`.
- **`deferred-items.md`**: the 01-09 entry is marked resolved with the corrected cause, both CI runs and the fix. The 01-08 and 01-13 "still not fixed" entries point to it.

## Evidence (all on Linux via WSL, `scripts/linux.sh`)

| Step | Command | Result |
|---|---|---|
| Baseline, unmodified | `go test -race -count=200 -timeout 60m -run TestSignerRefusals/created_301s_future ./internal/signer/` | **1/200 failed** (`signer_test.go:523: error = <nil>, want a *wire.ErrorResponse refused: request_time_skew`). Three batches were run: 1 failure, a FAIL, then 1 failure. |
| RED T1 (1.1 s pause after `tc.edit`) | `go test -count=1 -run TestSignerRefusals/created_301s ./internal/signer/` | exit 1: `created_301s_future` **FAIL** (`signer_test.go:524: error = <nil>, want ... request_time_skew`), `created_301s_past` PASS |
| GREEN T1 (same pause, on fix `ad281f6`) | same | exit 0: both PASS |
| T1 verify | `-race -count=200 -run TestSignerRefusals/created_301s`; `-race -count=3 -run TestSignerRefusals`; `-race -count=3 -run TestRefusalClockRegressionEpisodes` | ok (21.4 s / 2.7 s / 2.4 s). Re-run as the tracer gate: ok. |
| RED T2 (1.1 s pause before `refuseThroughSigner`) | `go test -count=1 -run TestEvidence/created_at_outside_skew ./internal/signer/` | exit 1: `_future` **FAIL** (`evidence_test.go:172: request issued (...), want the refusal request_time_skew`), `_past` PASS |
| GREEN T2 (same pause, on fix `66fd3c3`) | same | exit 0: both PASS |
| T2 verify | `-race -count=200 -run TestEvidence/created_at_outside_skew`; `-race -count=1 ./internal/signer/`; `go vet`; `gofmt -l`; production-file gate; go.mod/go.sum gate | all ok (38.2 s, 10.0 s, clean, clean, no non-test file, unchanged) |

Every injected pause was reverted with `git checkout -- <file>`, and `git status --porcelain -- internal/signer` was empty after each revert.

## Task Commits

1. **Task 1: TestSignerRefusals on a stepping test clock**: `ad281f6` (test)
2. **Task 2: Pin the signer clock in TestEvidence's skew subtests**: `66fd3c3` (test)
3. **Task 3: Delivery**: PR [#16](https://github.com/Labontese/keyroster/pull/16) (keyroster-bot, auto-merge squash). The docs commit carries this SUMMARY, the PLAN, `deferred-items.md` and STATE.md.

## Files Created/Modified

- `internal/signer/refusal_test.go`: `fakeClock.Tick`
- `internal/signer/signer_test.go`: `TestSignerRefusals` on the stepping clock, plus the self-check
- `internal/signer/log_test.go`: `logEnv.clock`, `newLogEnvClock`, `Clock: e.clock` in `open()`
- `internal/signer/evidence_test.go`: pinned clock in the skew subtests (adds the `time` import)
- `.planning/phases/01-trust-core/deferred-items.md`: the three flaky-test entries are resolved
- `.planning/STATE.md`: Quick Tasks Completed record and the Last activity line

## Decisions Made

- **Stepping clock, not frozen, for `TestSignerRefusals`.** `serial.Next` needs `cur >= max(last+1, n)`. After the seed issuance stores LastSerial at a frozen microsecond, later subtests that reach `cert.Build` would stall and return `serial_unavailable`.
- **Frozen clock is fine for `TestEvidence`.** The request is refused at the freshness check, before `serial.Next`, and `fakeClock` is not visible there anyway (it lives in a linux-tagged `signer_test` file).
- **Seam.** The `logEnv` clock uses `func() time.Time` rather than `serial.Clock`, so the file needs no new import. The type is assignable to both `Config.Clock` and the `fx.Bootstrap` clock parameter.

## Deviations from Plan

**1. [Orchestrator-directed] STATE.md is in the docs commit**
- The orchestrator required the STATE.md quick-task record to travel in the PR's docs commit, because `main` is protected and the squash includes only what is on the branch.
- As a result, the staged-list check in Task 3 step 5(c) and the PR-diff regex in Task 3 `<verify>` were run with `^\.planning/STATE\.md$` added to their allow-lists.
- STATE.md was updated only through `gsd-tools quick-tasks-migrate` and `quick-tasks-append`, plus the section header insert and the Last activity line. gsd-tools also refreshed the frontmatter `last_updated` and `state_head`.
- The generic executor `state_updates` block (advance-plan, record-metric, `roadmap.update-plan-progress`, `requirements.mark-complete`) was deliberately skipped, because this is a quick task and must not move phase counters. ROADMAP.md is untouched.

**2. [Tooling] The RED evidence verb cannot parse Go test output**
- `gsd-tools check tdd-red-evidence` parses only TAP and Surefire XML. On the persisted Go `-v` record it returns `INVALID_RED (zero_tests_discovered)`.
- The RED is still valid. The package built, the named target subtest `TestEvidence/created_at_outside_skew_future` failed on its own assertion ("request issued, want the refusal request_time_skew"), and its sibling passed. The record is kept in the session scratchpad.
- Task 2's RED is the injected, reverted pause on the unmodified test, as the plan specifies. It is not a separate committed failing test, so there is no `test(...)`-then-`feat(...)` pair. Both commits are `test(signer): ...`, because the plan is `type: execute` and the change is test-only.

**Total deviations:** 2 (1 orchestrator-directed scope addition, 1 tooling limitation). **Impact:** none on the code. Production is unchanged.

## Issues Encountered

- A first attempt to inject the RED pause with `sed` inserted a literal `t`, and then a literal `$(printf ...)`. Both broke the build. They were reverted, and the pause was injected with the Edit tool instead. No such state was ever committed.
- `golangci-lint` is not installed locally (neither in Git Bash nor in WSL), so CI's `lint` job is the lint gate.

## User Setup Required

None.

## Next Phase Readiness

The owner approves PR #16 in the GitHub UI. Do not use "Update branch" or the admin bypass. Auto-merge then squash-merges it, and `bash scripts/merge-gate.sh quick/261006-ixz-flaky-clock` fast-forwards local `main`.

## Self-Check: PASSED

- FOUND: internal/signer/refusal_test.go, signer_test.go, log_test.go, evidence_test.go (all modified in commits)
- FOUND: commit ad281f6 (signed, keyroster-bot)
- FOUND: commit 66fd3c3 (signed, keyroster-bot)
- FOUND: .planning/phases/01-trust-core/deferred-items.md has 3 references to 261006-ixz
- FOUND: PR #16 open, author keyroster-bot, auto-merge SQUASH

---
*Quick task: 261006-ixz*
*Completed: 2026-10-06*
