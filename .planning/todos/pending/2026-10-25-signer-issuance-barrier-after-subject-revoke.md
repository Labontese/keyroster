---
created: 2026-10-25T12:00:00.000Z
title: The signer blocks issuance for a subject from its revocation until the next directory install
area: auth
severity: minor
resolves_phase: 4
files:
  - internal/signer/revoke.go
  - internal/signer/login.go
  - internal/signer/issue.go
  - internal/signerdb/revocation.go
  - internal/audit/revoke.go
  - cmd/keyroster/revoke.go
  - docs/runbooks/revoke.md
---

## Problem

The 03-03 plan check (Codex + Claude, PR #59 follow-up) found a window in `keyroster revoke user`, and both skeptics upheld it (codex high). The subject revoke and the directory disable are two separate signer transactions. A login or issuance that completes after the revoke commits, and before the disable is installed, gets a certificate outside the revoked set. Signer.LoginIssue authorizes against the directory installed at that moment. The certificate stays valid until it expires.

Owner decision 2026-10-25, question Q3: a second sweep now, the barrier in Phase 4. 03-03b's `revoke user` (the CLI half of 03-03 since the split, owner decision 2026-10-25, PR #60) revokes, disables, and once the install is reported revokes the subject a second time. That closes the window at admin quorum 1.

At quorum above 1, the disable is only a proposal, and the window stays open until the co-signers install it. The CLI exits 4 (`revoked, disable pending`), says that the user can still obtain certificates, and prints `run keyroster revoke user <name> again after the proposal is installed`. The fix then depends on the operator re-running the command. A server that reports an install that did not happen also moves the second sweep early: signer-signed install receipts are Phase 4 too, in the todo [The CLI verifies signer-signed receipts for directory installs](2026-10-21-cli-verifies-directory-install-receipts.md).

This is threat T-03-19's accepted residual (03-03b since the split; 03-03 before).

## Solution

A signer-side issuance barrier, next to Phase 4 SC3's quorum and revocation-authority semantics ("any single admin can revoke immediately, un-revoking requires quorum"):
- A subject revoke records a barrier for that subject inside its own transaction.
- issue and login_issue for the subject are refused until the next installed directory version. That version is quorum-signed, and it either disables the subject or deliberately keeps it active.
- `audit verify` refuses issue and login_issue leaves for the subject between the revoke and that install.

This closes the window at every quorum with one rule, in the fail-safe direction. It is an authority change: a single admin's revoke then acts as a disable until a quorum decides. Decide it together with SC3, and give it a threat row.

Once the barrier exists, the CLI's exit 4 and the second sweep can be simplified. Keep the second sweep until audit enforces the barrier.

Tests:
- a login interleaved between the revoke and the install is refused (signer and audit);
- an install that keeps the user active lifts the barrier;
- quorum 2 end to end.

Sources: 03-03-PLAN.md, the Q3 rows of Round 2 in the Review Dispositions Ledger, and threat T-03-19; since the split, 03-03b-PLAN.md holds the CLI half, the moved Q3 rows and T-03-19.
