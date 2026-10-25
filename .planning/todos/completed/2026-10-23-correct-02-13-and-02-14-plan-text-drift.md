---
created: 2026-10-23T12:00:00.000Z
title: Correct the 02-13 and 02-14 plan text that drifted from what was executed
area: planning
severity: minor
resolves_phase: 3
files:
  - .planning/phases/02-passkey-login-mvp/02-13-PLAN.md
  - .planning/phases/02-passkey-login-mvp/02-14-PLAN.md
  - .planning/phases/02-passkey-login-mvp/02-VERIFICATION.md
---

## Problem

Phase 2 verification, advisory 3. On 2026-10-23 the owner accepted both affected truths by override ("Godkänn alla tre (Rekommenderas)"), but the plan text was left as executed.

- **Anchor 3.** 02-13 truth 8 and 02-14 (about L223, L265, L322, L354) assert `anchor_bundle_version==3`. That assertion fails on a valid log:
  - `audit verify` anchors on the first bundle whose root set equals the pins.
  - TEST roots C and D became the root set in bundle v2, so the anchor is 2, with bundle v3 in force.
  - This is by design (phase 02 deferred-items.md, 02-13 row). At run time, 02-14 checked `bundle_version==3 and anchor_bundle_version==2` instead.
- **cli-windows.** 02-14 truth 9 says cli-windows and cli-macos have run green on main since 02-02 and are both required. That is false:
  - Owner decision D1 requires only cli-macos until go-winio PR #41 merges and cli-windows is green on main.
  - cli-windows failed on main at 391a49f.

## Solution

- Decide whether to correct the plan text at all. The plans and summaries are in 02-VERIFICATION.md's `covered_files`, so editing them makes the phase 2 verification read `stale` until it is re-run.
- If they are corrected:
  - Replace each `anchor_bundle_version==3` with `bundle_version==3 and anchor_bundle_version==2`.
  - Reword 02-14 truth 9 to match D1.
  - Re-run the verifier, or refresh the digest, in the same change.
- Otherwise close this todo with a note that the overrides in 02-VERIFICATION.md are the record.
- When PR #41 has merged and cli-windows is green on main, add cli-windows to main-integrity (deferred-items.md, 02-14 D1 row).

## Resolution

Resolved in 03-02 (PR from branch `p03/02-phase2-followups`). Closed with the note option: the 02-13 and 02-14 plans and summaries stay as executed, because they are covered files of 02-VERIFICATION.md and editing them would stale a passed verification; the four overrides in 02-VERIFICATION.md are the record. The cli-windows step is done: the live main-integrity ruleset lists cli-windows (checked 2026-10-25, same 19 checks as .github/rulesets/main-integrity.json).
