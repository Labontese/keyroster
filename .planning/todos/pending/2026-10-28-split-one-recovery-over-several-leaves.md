---
created: 2026-10-28T12:00:00.000Z
title: Split one recovery over several revocation_recovery (kind 15) leaves with one publish
area: auth
severity: minor
resolves_phase: 4
files:
  - internal/tlog/leaf.go
  - internal/wire/recovery.go
  - internal/krl/recovery.go
  - internal/signer/recovery.go
  - internal/audit/recovery.go
  - cmd/keyroster/recover.go
  - docs/runbooks/signer-install.md
---

## Problem

The pre-merge review of PR #69 (03-06b) found this, and the owner accepted the gap for now (owner decision 2026-10-27, D-R1, carried over to 03-06c on 2026-10-28). T-03-269 in 03-06b-PLAN.md records it.

A signer restore recovers its lost revocations in one `revocation_recovery` leaf (kind 15), and that leaf's body is capped at 11 MiB (`tlog.MaxRecoveryBody`). The cap cannot rise without a format change: the leaf body has a uint24 length, so at most 16 MiB, and audit's 16 MiB export line carries the leaf in base64, which keeps the body under about 12 MiB.

03-06b measured the sizes (`TestRecoveryNearPublishableMaximum`, with two imports):

- an entry takes 74 B under an Ed25519 CA and 127 B under P-256;
- the two imports add 16 B per serial;
- so one recovery holds about 128 000 serials under Ed25519 and about 80 000 under P-256.

One KRL holds about 500 000 non-adjacent serials (`krl.MaxKRL`), and more when serials are adjacent, because those are encoded as ranges. A signer whose live revocation set is larger than one recovery can carry is refused `recovery_too_large` after a restore. The refusal fails closed: the hold stays, the restored signer publishes nothing, and hosts keep their last KRL (D-10). The cost is availability: the restore cannot finish, and signer-install.md step 2b says to escalate.

Since PR #69 review round 2, every lost user certificate is carried, including long-expired ones. After a long gap between the backup and the latest saved export, these certificates also count against `wire.MaxRecoveryCertificates` (65535) and the body cap, so the ceiling can be reached sooner.

## Solution

Split one recovery over several `revocation_recovery` leaves and publish once, the way 03-03 splits a subject revoke:

- the CLI writes one admin-signed request whose entries and carried certificates span N leaves, each leaf naming its part (index and count) and the request it belongs to;
- the signer writes all N leaves and the one `krl_publish` in one transaction, so no KRL is published between the parts, and the recovery stays single-use (bound to one restored log size and root);
- audit verify re-derives the union across the N leaves, refuses a missing, repeated or reordered part, and requires the one publish after the last part.

The other way out that 03-06b named was to have the normal publish refuse to grow the live set past what one recovery carries. The owner chose neither yet.

Needs: a new leaf body version or field, with a golden vector, and fuzz targets for the new decoder; a drill in `TestRestoreRecoversLostRevocations` above the single-leaf ceiling (CI e2e) or at least a signer and audit test of it.

Sources: 03-06b-SUMMARY.md, "Review fix round 1 (PR #69)", "D-R1 is only partially met" and "Follow-ups"; 03-06b-PLAN.md, T-03-269.
