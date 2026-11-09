---
created: 2026-11-08T12:00:00.000Z
title: No rollback widens back to last-good once a removal has landed
area: auth
severity: minor
resolves_phase: 3
files:
  - internal/agent/apply/apply.go
  - internal/agent/apply/probegate.go
  - internal/agent/apply/apply_test.go
  - internal/agent/apply/probegate_test.go
---

## Problem

The 03-10b pre-merge review (PR #91) found a third way that a removal can be granted again for about one round. It is in the same class as the two residuals 03-10b already records: a listener-test failure after the move to M, and a crash between the final swap and the commit.

In settleFailedAddition and gateSuperseded (internal/agent/apply/probegate.go), several errors fall back to `e.rollback(lg)` and backToLastGood. These are transient local errors that are not crashes:
- an I/O error in writeMarker, replaceLink or writeHeld;
- a validate (ssh-keygen) that fails or times out.

Last-good still grants what the change removed, so the removal is in force again until the next round's hold lands it once more. 03-05's existing rule does the same thing: every non-crash error after a mixed change's narrowing swap rolls back to last-good (forward in apply.go, the error paths after the Transition passes).

Owner decision D-R1 (2026-11-08) makes no code change in 03-10b. The case is recorded as the third UNVERIFIED residual in 03-10b-SUMMARY.md and in the plan's settle bullet (D13), its T-03-374 threat row and its Edge Coverage. Owner: 03-10c.

## Solution

Once a removal has landed, no rollback path widens back to last-good: neither 03-05's forward error paths, nor settleFailedAddition's fallbacks, nor gateSuperseded's. backToLastGood or rollback then targets an intermediate that keeps the removal instead. That intermediate is the content of Intermediate(last-good, target) with the newest KRL, as settleFailedAddition already computes it. Use the generation that is live when its content is that, or one installed afresh. Last-good itself remains the target only when the target removes nothing that last-good grants.

Tests:
- for each fallback (writeMarker, replaceLink and writeHeld failing; validate failing and timing out), a mixed change whose addition fails keeps its removal through the error, and the next round holds;
- the same for an error after a mixed change's narrowing swap in forward (03-05's paths);
- a pure addition that fails still goes back to last-good;
- a mutant that restores the plain rollback on each path dies on its own subtest.

Sources: 03-10b-PLAN.md (D13, settleFailedAddition, T-03-374), 03-10b-SUMMARY.md ("Pre-merge review round 1", D-R1).

## Resolution

Resolved in 03-10d (PR from branch `p03/10d-no-regrant-recovery`; owner decisions Q-S, Q-D and D-R1, 2026-11-08). Every rollback of an in-flight apply (forward's error paths, settleFailedAddition's fallbacks, gateSuperseded) and the start-up recover take RollbackKeeping: last-good intersect current intersect the base (the generation in force when forward's last pass started) with the newest KRL; recover is bounded by every generation its marker names and fails closed with `pending_state_unknown` when one does not read. settleFailedAddition settles on Intermediate(base, target). A kept state passes the start check by classified content, the equal-content commit runs a listener test before it makes a current that is not last-good into last-good, the fallback render keeps current's principals (D9) and a KRL-alone pass moves only the KRL (D10). Only the operator's `--recover-to-last-good` keeps the plain target (Q1 = A, a named residual). Tests: TestRollbackKeeping, TestRollbackSites, TestAtRollbackTarget, TestProbeGate/settle_listener_failure_keeps_removal.
