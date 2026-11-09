---
created: 2026-11-08T12:00:00.000Z
title: 03-12 and 03-14 read current, which a kept rollback leaves apart from last-good
area: agent
severity: minor
resolves_phase: 3
files:
  - .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md
---

## Problem

03-10d changed which generation a rollback and the start-up recovery leave in force.
- **Before:** they moved `current` to RollbackTarget(current, last-good).
- **Now:** every rollback of an in-flight apply and the start-up recovery move it to the kept content. That is last-good intersected with current and the base (the generation in force when the apply's last pass started), with the newest KRL. Only the operator's `--recover-to-last-good` keeps the old target (owner decision Q1 = A, 2026-11-08).

So `current` can now name a generation that is neither last-good nor last-good's content, and stay that way at rest.

Two later plans describe the old target:
- 03-12-PLAN.md:371 (CA rotation) says a rollback or recovery moves `current` to RollbackTarget(current, last-good).
- 03-14-PLAN.md:324 says the same for the break-glass files.

03-12 also waits on a host whose probe account is broken (R11). 03-14 mirrors account.go.

Whether either plan needs to know that current can differ from last-good is UNVERIFIED.

## Solution

When 03-12 and 03-14 are reconciled before execution:
- re-read the rollback and recovery targets in internal/agent/apply (RollbackKeeping, `rollbackAs`, `recover`, `recoverToLastGood`);
- correct the two plan lines;
- add a test where a rotation or a break-glass change meets a kept state;
- keep the rule that no rollback re-grants a landed removal.

Sources: 03-10d-PLAN.md (Edge Coverage, 'Not done here', D6 to D10) and 03-10d-SUMMARY.md ('For later plans').
