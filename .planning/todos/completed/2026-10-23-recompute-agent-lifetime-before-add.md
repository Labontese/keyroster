---
created: 2026-10-23T12:00:00.000Z
title: Recompute the agent lifetime immediately before the add
area: cli
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster/login.go
  - internal/winagent/ensure_windows.go
  - docs/runbooks/enroll-user.md
---

## Problem

Phase 2 code review, finding E-IN-02 (Info, low, not adversarially verified). Filed after the phase 2 verification (owner decision 2026-10-23).

The lifetime is computed before the agent may need to start:
- `checkLoginCert` turns the remaining validity into `LifetimeSecs` (cmd/keyroster/login.go, about L315), with a 1 s margin.
- `winagent.Ensure` then may start the agent, poll for up to 5 s, verify the owner and retry once.
- The keyring counts the lifetime from its own Add.

So after a Windows cold start, the key and certificate can stay in the agent past ValidBefore by the start delay. That breaks the promise in enroll-user.md (about L283-286). sshd already refuses the expired certificate, so access is not affected.

The timed Windows run of 2026-10-23 started from a cold start (02-VERIFICATION.md, "Owner decisions and resolution"):
- The key left the agent between 3.9 s before and 1.1 s after valid_before.
- The listing resolution was 5 s, and the clock skew was not measured.

So the effect did not show at that resolution, but the run does not rule it out.

## Solution

- Connect to the agent first, as in the E-IN-01 todo (`2026-10-23-cli-checks-the-agent-before-issuance.md`).
- Recompute the lifetime from a fresh `loginNow()` immediately before `ag.Add`, and refuse below `minLoginRemaining`.
- A unit test with an injected clock and a slow Ensure should show the lifetime shrink by the delay.

## Resolution

Resolved in 03-02 (PR from branch `p03/02-phase2-followups`). The lifetime is computed from a fresh `loginNow()` immediately before `ag.Add` and refused below 60 s (`TestLoginFlowFakeServer/lifetime_recomputed_at_add`, `too_little_left_at_add_refused`). Connecting before the begin also moves a Windows cold start before the certificate exists. Not re-timed on Windows (UNVERIFIED there).
