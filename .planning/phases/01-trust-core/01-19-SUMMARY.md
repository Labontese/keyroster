---
phase: 01-trust-core
plan: 19
subsystem: planning
tags: [gap-closure, planning-record, key-07, deferred-items, code-review]

requires:
  - phase: 01-trust-core
    provides: "01-VERIFICATION.md gap 3 (KEY-07 overclaim), 01-REVIEW-FIX.md design-level findings, 01-17 successor builder (PR #22)"
provides:
  - "No phase 1 SUMMARY claims KEY-07 in requirements-completed (01-06, 01-07, 01-09 corrected)"
  - "deferred-items.md: the four design-level review items (C-WR-06 part 2, C-WR-01 remainder, D-WR-02, D-WR-04) with decisions needed and targets"
  - "deferred-items.md: the 01-14 entry points to the gap plans 01-17, 01-18, 01-20, 01-21"
affects: [01-18, 01-20, 01-21, KEY-07, VIS-02, phase-04, phase-06]

actuals:
  tokens: 1390
  tasks: 2
  commits: 2
plan_head_before: 23995a3f65243f12dd09659f1d8ce6be346f28fc
plan_head_after: 4d8069141409768c1fd1b65fcebb675fc914c7b6

tech-stack:
  added: []
  patterns:
    - "Deferred design item entry: bold lead sentence (what is missing, deferred not planned), a 'Decisions needed' list copied verbatim from the finding, and a 'Target' line"

key-files:
  created:
    - .planning/phases/01-trust-core/01-19-SUMMARY.md
  modified:
    - .planning/phases/01-trust-core/01-06-SUMMARY.md
    - .planning/phases/01-trust-core/01-07-SUMMARY.md
    - .planning/phases/01-trust-core/01-09-SUMMARY.md
    - .planning/phases/01-trust-core/deferred-items.md

key-decisions:
  - "KEY-07 is removed from requirements-completed only; the coverage rows with requirement KEY-07 and the body text of 01-06, 01-07 and 01-09 stay unchanged (owner decision 3)"
  - "The four design-level review items are deferred, not planned: C-WR-06 part 2 and the C-WR-01 remainder target the Phase 4 audit and visibility work (VIS-02); D-WR-02 and D-WR-04 target the hardware validation in issue #13, before the Phase 6 external review (owner decision 4)"
  - "D-WR-02 and D-WR-04 are recorded as hardening the tpm and piv custody claims; they do not gate the software levels, and hardware stays optional"
  - "The requirements.mark-complete tracking step is skipped for this plan, although its frontmatter lists KEY-07: KEY-07 closes only in 01-21"

requirements-completed: []

coverage:
  - id: D1
    description: "No phase 1 SUMMARY lists KEY-07 under requirements-completed; 01-06 and 01-09 now read [], 01-07 reads [CA-01, CA-04, CA-05, CA-07, KEY-01, VIS-01]; exactly three lines changed"
    requirement: KEY-07
    verification:
      - kind: other
        ref: "! grep -l '^requirements-completed:.*KEY-07' .planning/phases/01-trust-core/*-SUMMARY.md (no file printed); git diff --numstat origin/main on the three files: 1/1 each"
        status: pass
      - kind: other
        ref: "gsd-tools query frontmatter.get <file> --field requirements-completed and query frontmatter.validate <file> --schema summary for 01-06, 01-07, 01-09 (all valid)"
        status: pass
    human_judgment: false
  - id: D2
    description: "deferred-items.md records C-WR-06 part 2, C-WR-01 remainder, D-WR-02 and D-WR-04, each with a 'Decisions needed' list copied from 01-REVIEW-FIX.md (5, 4, 4 and 4 bullets) and a Target line; additions only"
    verification:
      - kind: other
        ref: "Task 2 verify 1 (all four IDs present, section heading count 1, 'Gap closure planned (2026-10-08' count 1); git diff --numstat origin/main -- deferred-items.md -> 42 0"
        status: pass
    human_judgment: true
    rationale: "That each decision bullet traces to 01-REVIEW-FIX.md and that the targets are right is for the owner's review at the merge gate"
  - id: D3
    description: "PR #23 is green with auto-merge on and waits for the owner's approval at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks p01/19-planning-corrections --required --watch -> exit 0, all 17 required checks pass on implementation head 4d80691"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 3 blocking-human merge gate, after this SUMMARY is written"

duration: 10min
completed: 2026-10-08
status: complete
---

# Phase 1 Plan 19: Planning Corrections Summary

**KEY-07 is no longer claimed as complete by any phase 1 SUMMARY (01-06, 01-07 and 01-09 corrected, one frontmatter line each), and `deferred-items.md` now records the four design-level review items with the decisions each one needs and a target. It also points the 01-14 entry at the gap plans 01-17, 01-18, 01-20 and 01-21. Documentation only; KEY-07 stays open until 01-21.**

## Performance

- **Duration:** about 10 min
- **Started:** 2026-10-08T09:19:41Z
- **Completed:** 2026-10-08T09:29Z (SUMMARY written)
- **Tasks:** 2 of 3 executed before the merge gate (Task 3 is the owner's approval)
- **Files modified:** 4 planning files, 45 insertions, 3 deletions

## Accomplishments

- **Task 1 (tracer): KEY-07 claim correction.** The phase-wide grep found the claim in 01-06, 01-07 and 01-09 only (01-10 lists `[KEY-03]`; no other SUMMARY claims KEY-07). Changed lines:
  - `01-06-SUMMARY.md` line 71: `requirements-completed: [KEY-07]` -> `requirements-completed: []`
  - `01-07-SUMMARY.md` line 84: `[CA-01, CA-04, CA-05, CA-07, KEY-01, KEY-07, VIS-01]` -> `[CA-01, CA-04, CA-05, CA-07, KEY-01, VIS-01]`
  - `01-09-SUMMARY.md` line 60: `requirements-completed: [KEY-07]` -> `requirements-completed: []`
  - Coverage rows with `requirement: KEY-07` and the body text are unchanged (owner decision 3).
  - Tracer feedback gate: interactive, `end-of-phase`, automated-only `<verify>`. Both verify commands were re-run green before Task 2 started.
- **Task 2: deferred design items and the 01-14 repointing.** New section `## Design items deferred from the phase 1 code review (owner decision 2026-10-08)`:

| Item | What is deferred | Decisions needed | Target |
|---|---|---|---|
| C-WR-06 part 2 | Offline check of issuance authorization (the issue leaf logs only the request digest) | 5, copied from 01-REVIEW-FIX.md | Phase 4 audit and visibility work (VIS-02 witnessed log, quorum-signed policy changes) |
| C-WR-01 remainder | Whole-database restore, cuts that also roll back issuance rows and the high-water mark, trailing non-issue cuts | 4, copied | Phase 4 (VIS-02, success criterion 4), as `01-VERIFICATION.md` `deferred:` records |
| D-WR-02 | TPM endorsement-key certificate verification | 4, copied | Issue #13 (needs-hardware item 4), before the Phase 6 external review |
| D-WR-04 | PIV slot attestation | 4, copied | Issue #13 (needs-hardware item 2), before the Phase 6 external review |

  - The 01-14 entry gained the sub-bullet `**Gap closure planned (2026-10-08, owner decision 1: rotate, do not rebuild).**` It names 01-17 (merged, PR #22), 01-18, 01-20 and 01-21, says the rebuild alternative is not taken and that KEY-07 stays open until 01-21, and notes that the builder accepts a chained v2 policy (`TestBuildSuccessor/round_trip_chained_policy`, 01-17) while policy authoring is Phase 4, so the rotation carries the policy unchanged.
  - Additions only: `git diff --numstat origin/main -- deferred-items.md` is `42 0`.

## PR

- **PR #23**: `docs(01): correct KEY-07 claims and record deferred review design items` (https://github.com/Labontese/keyroster/pull/23).
  - Branch `p01/19-planning-corrections`, opened by keyroster-bot, auto-merge (squash) enabled.
- **Required checks:** all 17 pass on implementation head `4d80691`: Analyze (actions), Analyze (go), build-piv, build-test, capslock, dependency-firewall, e2e (9.5p1), e2e (10.5p1), e2e-pkcs11 (10.5p1-ed25519), e2e-pkcs11 (distro-p256), e2e-tpm, fuzz, govulncheck, lint, pinned-actions, pr-title, systemd-sandbox.
- **Signatures:** `d373b91` and `4d80691` show `verified: true` (GitHub API).

## Task Commits

1. **Task 1 (tracer): remove KEY-07 from completed requirements.** `d373b91` (docs)
2. **Task 2: record deferred review design items and the KEY-07 gap plans.** `4d80691` (docs)
3. **Task 3: merge gate.** No commit (owner approval; GitHub squash-merges).

**Plan metadata:** the `docs(01-19): complete planning-corrections plan` commit on the same PR branch. `actuals.commits` (2) is measured at `4d80691`, before that commit.

## Commands Run

| Command | Result |
|---|---|
| `grep -n '^requirements-completed:' .planning/phases/01-trust-core/*-SUMMARY.md` (before) | KEY-07 in 01-06, 01-07, 01-09 only |
| `! grep -l '^requirements-completed:.*KEY-07' .planning/phases/01-trust-core/*-SUMMARY.md` | no file printed, exit 0 |
| `gsd-tools query frontmatter.get … --field requirements-completed` (01-06, 01-07, 01-09) | `[]`; `[CA-01, CA-04, CA-05, CA-07, KEY-01, VIS-01]`; `[]` |
| `gsd-tools query frontmatter.validate … --schema summary` (01-06, 01-07, 01-09) | `"valid": true` for all three |
| Task 2 verify 1 (four IDs, heading count, gap-closure count) | all present; 1; 1 |
| `git diff --numstat origin/main -- …/deferred-items.md` | `42 0` |
| `scripts/gh-as-bot.sh pr checks p01/19-planning-corrections --required --watch` | exit 0, 17/17 pass |

## Deviations from Plan

### Deliberate skips

**1. `requirements.mark-complete` not run.**
- **Why:** the plan frontmatter lists `requirements: [KEY-07]`, so the standard tracking recipe would mark KEY-07 complete. The plan's purpose and the orchestrator's instruction are that KEY-07 is not marked complete before 01-21. REQUIREMENTS.md was checked after the tracking updates: KEY-07 stays `Pending`.

Otherwise the plan was executed as written.

## Issues Encountered

- `state.advance-plan` declined to advance (`plans_outstanding`: 01-18, 01-20 and 01-21 have no SUMMARY yet) and left STATE.md unchanged, as designed. `state.update-progress` (18/21), `state.record-metric`, `state.add-decision --phase 01` (two decisions), `state.record-session` and `roadmap.update-plan-progress 01` ran once each.

## Known Stubs

None (documentation only).

## Next Phase Readiness

- Re-verification after the gap work will find no SUMMARY claiming KEY-07 before 01-21.
- The four deferred items are where Phase 4 and the issue #13 hardware work will find them.
- Remaining gap plans: 01-18 (verification and runbook), 01-20 (ceremony and rotation, owner action), 01-21 (test-root retirement, KEY-07 closes).

## Self-Check: PASSED

- FOUND: `.planning/phases/01-trust-core/01-19-SUMMARY.md`, `01-06-SUMMARY.md`, `01-07-SUMMARY.md`, `01-09-SUMMARY.md`, `deferred-items.md`
- FOUND: commits `d373b91`, `4d80691` (on `origin/p01/19-planning-corrections`)
