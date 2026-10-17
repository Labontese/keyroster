---
created: 2026-10-17T08:30:00.000Z
title: Serve refuses to start without a witnessed checkpoint
area: auth
severity: blocker
resolves_phase: 4
files:
  - internal/signer/logstate.go
  - internal/signerdb/log.go
---

## Problem

Every start-up check of `keyroster-signer serve` (and `doctor`) compares the state database with itself: the stored leaves with the latest checkpoint, and the trust_bundle, directory, issuance and serial tables with the log. None of it is anchored outside `signer.db`. So a log rolled back together with its tables to an earlier, genuinely signed prefix, or an older `signer.db` restored, passes every check and reinstates the older authorization state.

Verified in the pre-merge review of PR #38 (plan 02-03), reproduced in WSL on `ae57f1a`:

- With only SQL write access to `signer.db` and no keys, truncating `log_leaf` and `checkpoint` back to an earlier signed prefix and deleting the newer stored row makes serve start with the **older directory**: a user disabled in v2 gets a certificate again.
- The same works for the **trust bundle**: deleting trust_bundle v2 brings back the old policy, admin set and quorum, CA profiles and WebAuthn RP. A removed admin is accepted again. The CA, ops and log keys cannot be rolled back (`checkBundleKeys`). Rolling back the root set is UNVERIFIED.
- An honest restore of an older `signer.db` backup has exactly the same effect, with no attacker.
- `keyroster audit verify` without `--previous` says OK; with `--previous` it reports the log shrunk or rewritten. Until plan 02-04, it refuses logs that contain `directory_install` entries.
- Reinstalling the newest bundle and directory afterwards is accepted, but so is a different v2' built on the rolled-back v1, so a disablement can be lost for good.

The gap predates Phase 2: it is Phase 1's C-WR-01 remainder (`.planning/phases/01-trust-core/deferred-items.md`), moved to Phase 4 (VIS-02, success criterion 4) by `01-VERIFICATION.md`. 02-03's T-02-14 covers only the directory table rolled back or substituted alone.

## Solution

Owner decision (2026-10-17): in Phase 4, `keyroster-signer serve` refuses to start without a witnessed checkpoint at least as new as the local one. This is prevention at start, not only detection afterwards.

Options to settle in Phase 4 planning:

- **Witness cosignatures checked at start.** Host agents and the CLI keep the latest checkpoint they verified and cosign it (C2SP witness format). serve requires a witness-cosigned checkpoint whose size is at least the local log's, with a consistency proof from it to the local log, before it serves.
- **An operator-supplied minimum checkpoint, as an interim measure.** serve (and doctor) take the latest checkpoint the operator kept outside the signer (for example from the last export) and refuse a local log that is shorter or does not extend it.

Trade-offs:

- Bootstrapping: a fresh signer has no witnessed checkpoint yet.
- Availability: an unreachable witness must not become a way to stop the signer for good; the operator path needs a documented override that is itself logged.
- Restores: after a legitimate restore the operator must reinstall the lost bundles and directory versions, in order and byte for byte, before the signer serves.
