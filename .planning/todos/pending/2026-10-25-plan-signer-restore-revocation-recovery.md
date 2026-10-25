---
created: 2026-10-25T12:00:00.000Z
title: Plan the recovery of revocations that a signer restore lost
area: auth
severity: blocker
resolves_phase: 3
files:
  - docs/runbooks/signer-install.md
  - test/e2e/restore_test.go
  - internal/signer/revoke.go
  - internal/signer/krl.go
  - internal/wire/revoke.go
  - internal/tlog/leaf.go
  - internal/audit/revoke.go
  - internal/audit/export.go
  - internal/server/revoke.go
  - cmd/keyroster/revoke.go
---

## Problem

Owner decision 2026-10-25 on the 03-03 plan check (Codex + Claude, PR #59 follow-up), question Q2: recovering revocations that a signer restore lost gets its own Phase 3 plan. **It must be planned and merged before 03-07**, because agents start pulling KRLs there. 03-07's Task 1 precondition requires it.

The PR #59 review (round 5) had put a replay, a krl_version floor and a restore drill into 03-03-PLAN.md Task 3 (a)-(c). That text never went through plan review, and the plan check found it could not be built as written. 03-03 drops it and keeps only a stop. signer-install.md step 2 counts `"kind":"revoke"` in both verified exports. When the saved export has more, the restore lost a revocation: the operator keeps the hold, records both counts and escalates. `restoreSavedGreps` in test/e2e/restore_test.go pins that count.

The stop is fail-safe:
- the signer stays down;
- hosts keep their last KRL, which still lists the lost revocations;
- hosts never lock out because a KRL is old (D-10).

Its cost is availability. Until this plan merges, a restore that lost a revocation leaves the signer down and access goes through break-glass. 03-03's time-derived krl_version (Q1) makes the gap urgent: once the hold is released, every host accepts the restored signer's next KRL.

The plan check found these facts about replay material (both skeptics upheld each, unless noted):

1. **A serial entry carries no key ID and no key.** `RevokedEntry.check` (internal/tlog/leaf.go) refuses either on a `RevokedSerial` entry, and 03-03's subject revokes resolve to serial entries too. Suppose the restore also lost the certificate's issuance. Then `revoke serial` refuses the serial with `unknown_serial`: internal/signer/revoke.go looks it up in the issuance index, and the audit rule for a serial target needs the serial's issue leaf. So "replay by the entry's recorded key ID" names a field that does not exist.
2. **The decoded fields a grep-based replay would read cannot be trusted.**
   - `serial` and `key_id` on issue and login_issue export lines are not bound by `audit verify`. checkGrepFields binds only `kind` on every line, `bundle_version` on bundle_install lines and `version` on directory_install lines.
   - Those names collide with the field names that 03-03 gives revoke entries.
   - Key IDs are JSON-escaped, so grep can read mangled bytes.
3. **A lost `revoke key` cannot be rebuilt from the export.** 03-03 exports an explicit-key entry as a fingerprint only. The leaf holds the wire bytes, but no decoded field carries them.
4. **Replaying one revocation at a time is unsafe.** Every revoke publishes its own KRL in its own transaction. With N lost revocations, a replay one by one publishes N−1 intermediate KRLs. Hosts accept each of them, and each lacks the later lost revocations.
5. **Lost but still valid certificates.** issue and login_issue entries lost with the restore are certificates that are still valid in the wild, and the restored signer does not know them. Decide what happens to them. The fail-safe default the check proposed:
   - revoke lost user certificates that are still live;
   - list host and machine certificates for an admin to decide.
6. **Revocations newer than the saved export are in neither file.** The restore loses them without a trace, and 03-03's stop cannot see them: T-03-207's accepted residual. Until this plan, the operating rule in revoke.md and signer-install.md is "take a saved export after every revocation".
7. **03-10's negative-probe revocations are a second source of revocation rows.** A first Negative `probe_issue` writes one. Recovery must cover every leaf kind that writes revocation rows, keep their host and key provenance, and be tested with an installed negative-probe key followed by a successful renewal (codex medium).
8. **03-13's start-up publish.** After an ops-key rotation, 03-13 publishes a KRL with the new ops key when the signer starts. That publish must respect a pending recovery. This was a split item: it cannot happen before 03-13, because successors copy the ops key until then.
9. **Leaf kind numbers.** If the plan needs a new leaf kind, 11 to 14 are taken by 03-09 to 03-12. Reserve the next free number and note it in those plans.
10. **The floor that round 5 proposed is moot.** It was set above the saved export's highest krl_version, which is too low after any later publish, and the export's krl_version is not bound either. Under Q1 the versions are time-derived, so no floor and no new leaf kind are needed for numbering.

## Solution

**Owner's direction for the planner (2026-10-25):** import the newest ops-signed KRL as a union with the saved export's lost entries, in one admin-signed transaction. The owner named keyroster-server as the source: it holds {krl, manifest, sig}, and a signer restore does not roll it back.
- One publish, so no unsafe intermediate KRL is ever accepted.
- It covers explicit keys, because the KRL holds the key bytes.
- It covers revocations newer than the saved export, as long as their KRL reached that source.
- It reads no export field by grep.
- It can only over-revoke, never under-revoke.

**Premise to settle first.** At main 4aaa62e, keyroster-server holds the KRL only in memory: currentKRL in internal/server/revoke.go caches the signer's answer for at most `serverclient.KRLMaxStale` (5 s). The restore hold also stops keyroster-server, so today nothing of it survives a restore. The plan must give the KRL a durable home that a signer restore does not roll back. Two candidates:
- keyroster-server persists the last {krl, manifest, sig} it verified with krl.VerifyManifest in serverdb;
- after 03-07, an agent's accepted state supplies it: 03-05 stores the KRL, its manifest and its signature under `<state>/accepted/`.

Either way the imported KRL is verified against the root-pinned bundle and the installation ID before it is used.

**Costs the plan must solve:**
- **Size.** MaxRequest is 64 KiB, but MaxKRL is 4 MiB. Audit needs the imported KRL bytes in the log to prove that the union is complete, so the import needs chunking or a dedicated leaf body, with a golden vector.
- **Audit rule.** The imported KRL's ops-key signature, its installation ID and version, and the union's equality with the next published set.
- **Lost serials without an issuance.** They are revoked under their CA key and serial, taken from the imported KRL's certificate section, without an issuance lookup.
- **Point 5's default,** and the coverage in points 7 and 8.
- **The runbook.** Remove signer-install.md's stop once the recovery exists, and update `restoreSavedGreps` and `TestRestoreRunbookChecks` with it.

**Test it with an e2e restore drill** that loses several revocations:
- one for a certificate issued before the snapshot;
- one for a certificate issued after it;
- one explicit key;
- one revocation made after the saved export was taken;
- one negative probe, once 03-10 exists.

Assert that no krl_publish between the restored log's end and the recovery lacks any of them. Assert also that `ssh-keygen -Q` and sshd refuse each one afterwards. Include a restart while the recovery is pending.

Sources: 03-03-PLAN.md, Round 2 of the Review Dispositions Ledger (the Deferred table) and threat T-03-207; 03-03-PLAN.md at 4aaa62e, Task 3 (a)-(c), for the removed text.
