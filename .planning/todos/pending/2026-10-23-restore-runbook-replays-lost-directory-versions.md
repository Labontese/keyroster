---
created: 2026-10-23T12:00:00.000Z
title: The signer restore runbook replays lost directory versions with directory install
area: docs
severity: minor
resolves_phase: 3
files:
  - docs/runbooks/signer-install.md
  - cmd/keyroster/directory.go
  - cmd/keyroster/dirpipe.go
  - internal/server/directory.go
---

## Problem

Phase 2 code review, finding A-IN-01 (Info, low, not adversarially verified; also reported by area F). Filed after the phase 2 verification (owner decision 2026-10-23).

After a signer restore that lost `directory_install` entries, step 3 of the restore procedure in docs/runbooks/signer-install.md (about L424-438) still says no command can replay them "until plan 02-09 adds `keyroster directory install`". It tells the operator to keep the signer stopped until then. That command exists now (`cmd/keyroster/directory.go`, proposal files from `dirpipe.go`), but the runbook gives no procedure. So the operator either keeps the CA down or starts it with no guidance. While the signer runs, it serves the older directory, so a user disabled in a lost version can log in again.

A replayed version that newly binds a passkey would also be refused with 409 `credential_not_pending` (`internal/server/directory.go`), because the pending row was deleted at the original install. These code paths are UNVERIFIED: read from the code, not run.

## Solution

- Rewrite step 3: write each lost leaf's `directory.json` and `directory.json.sigs` from the saved export into a proposal directory, then replay them in log order with `keyroster directory install`.
- State the exposure window, and keep the server unreachable to users until the replay is done.
- Document the 409 limit for versions that bind a passkey, or add an operator path that skips the pending check for a byte-identical replay of a logged version.
- Run the procedure once on a test signer before labelling it verified.
