---
created: 2026-10-23T12:00:00.000Z
title: A redeemed login code always reaches the signer inside its 300 s window
area: server
severity: minor
resolves_phase: 3
files:
  - internal/server/login.go
  - .planning/phases/02-passkey-login-mvp/02-12-PLAN.md
---

## Problem

Phase 2 code review, finding C-IN-01 (Info, low, not adversarially verified). Filed after the phase 2 verification (owner decision 2026-10-23).

The redeem handler (internal/server/login.go, about L732) reads `now` once. It uses that reading for both the expiry check (about L741) and `RedeemLogin` (about L755). In between, `currentStatus` runs and can take up to 3 s, and the signer call then has up to 10 s.

So a code capped at CreatedAt+290 s and redeemed at T+289.9 s can reach the signer after T+300 s. The code is burnt, and the signer refuses `request_time_skew`.

The impact is UX only: nothing is minted wrongly. But the comment at about L63-66 and threat row T-02-107 claim the cap "always" fits. The timing was not reproduced by execution (UNVERIFIED).

## Solution

- Re-read the clock after `currentStatus`, or check the status before the expiry check.
- Bound the signer context deadline at CreatedAt+300 s minus a margin, or lower `loginCodeCap`.
- Otherwise, correct the comment and T-02-107.
- A test with an injected clock that stalls in `currentStatus` should show the fix.
