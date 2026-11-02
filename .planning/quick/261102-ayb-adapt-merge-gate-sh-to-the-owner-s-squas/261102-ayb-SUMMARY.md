---
phase: quick-261102-ayb
plan: 01
subsystem: delivery
tags: [process, merge-gate, github]
status: complete
requires: []
provides: ["merge-gate.sh that waits for the owner's squash merge and never enables auto-merge"]
affects: ["CONTRIBUTING.md (pull request flow)", ".planning/phases/01-trust-core/01-SKELETON.md (Delivery Protocol)"]
tech-stack:
  added: []
  patterns: []
key-files:
  created: []
  modified: [scripts/merge-gate.sh, CONTRIBUTING.md, .planning/phases/01-trust-core/01-SKELETON.md, .planning/STATE.md]
decisions:
  - "The owner squash-merges every PR in the GitHub UI. The bot never enables auto-merge, and merge-gate.sh only waits for the merge."
requirements: []
metrics:
  completed: 2026-11-02
actuals:
  tasks: 3
  commits: 3
plan_head_before: ae754a3343f7d541e6ea389f17e4188f6ba5cf73
---

# Quick 261102-ayb Plan 01: merge-gate.sh waits for the owner's squash merge Summary

`scripts/merge-gate.sh` no longer relies on GitHub's auto-merge. `push_rebased` no longer re-enables auto-merge after a rebase. After approval the gate prints `approved; waiting for the owner to squash-merge #N` and waits as before, bounded by `MERGE_GATE_TIMEOUT`. CONTRIBUTING.md and the Delivery Protocol in 01-SKELETON.md now describe the owner's approval and squash merge in the GitHub UI. PR [#79](https://github.com/Labontese/keyroster/pull/79), opened by keyroster-bot without auto-merge.

## Commits

- `228d8ad` chore(scripts): have merge-gate.sh wait for the owner's squash merge
- `383e61c` docs: describe the owner's squash merge instead of auto-merge
- the docs commit carrying this PLAN, this SUMMARY and the STATE.md row

The owner (Labontese) is the author of each commit, and keyroster-bot is the committer, with an SSH signature that GitHub reports as `verified=true valid`.

## What changed in merge-gate.sh

- `push_rebased`: removed the `autoMergeRequest` lookup, the `gh pr merge --auto --squash` call and the now unused `auto` local variable. The comment says the function never enables auto-merge.
- Post-approval message: `approved; waiting for the owner to squash-merge #$number`. The timeout message now says it was waiting for the owner's squash merge.
- Header: the script never submits a review, never merges and never enables auto-merge. Approval and the squash merge belong to the owner in the GitHub UI (D-05). `MERGE_GATE_TIMEOUT` bounds the wait for that merge.
- Unchanged: exit codes 0-4, `--check`, the reviewed-copy check (F-WR-03), the bot identity check, the wait loop and the timeout default.

## Verification

- `bash -n scripts/merge-gate.sh`: passes.
- `grep -nE 'pr merge|autoMergeRequest' scripts/merge-gate.sh`: no match.
- The PR has `autoMergeRequest == null`.
- CI: see "CI" below.
- **UNVERIFIED:** shellcheck. CI has no shellcheck job, and shellcheck is not installed on the Windows or WSL side.
- **UNVERIFIED:** the rebase path (exit 3) and the post-approval wait. Exercising either one means running the gate, and this task does not run it. No test harness for merge-gate.sh exists.

## CI

On head `383e61c` (the two code and docs commits), all 27 checks passed, and the 26 required ones among them (`pr checks 79 --required`) also passed. That includes the e2e suites, systemd-sandbox, build-test, fuzz and pr-title. The docs commit that adds this SUMMARY runs the checks again on the new head.

## Deviations from Plan

None. The PLAN was written for this brief and executed as written.

## Notes for the gate

This PR changes `merge-gate.sh`, so it is gated by the copy already on `main`. If `main` moves before the merge, that copy's exit-3 rebase path re-enables auto-merge on this PR. If that happens, turn auto-merge off before the owner's squash merge.
