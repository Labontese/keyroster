---
created: 2026-10-23T12:00:00.000Z
title: Record the timed Windows expiry run in needs-hardware.md
area: docs
severity: minor
resolves_phase: 3
files:
  - docs/security/needs-hardware.md
---

## Problem

docs/security/needs-hardware.md (the "Windows expiry timing" bullet near L185 and the Windows text near L274) still says the times of the Windows agent listings were not recorded.

On 2026-10-23 the owner ran the timed `--ttl 5m` test from a cold start on Daniel-PC (02-VERIFICATION.md, "Owner decisions and resolution"):
- The key left the keyroster agent between 3.9 s before and 1.1 s after valid_before.
- The listing resolution was 5 s, and the clock skew was not measured.

The doc now understates what was exercised; it does not overclaim.

needs-hardware.md is a covered file of the phase 2 verification and lives on main, so the change goes through a PR, not a planning commit.

## Solution

- Update the Windows text and the "Windows expiry timing" bullet with the run's date, procedure and result, in the same words as 02-VERIFICATION.md.
- Keep the limits:
  - 5 s resolution;
  - skew not measured;
  - one key only: no 8 h key was in the agent alongside it in that run;
  - E-IN-02 still open.
- Give dates and order only, no times of day next to any WebPKI certificate step (deferred-items.md, 02-13 rule). This run had none.
