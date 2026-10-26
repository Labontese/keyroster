---
created: 2026-10-26T12:00:00.000Z
title: The signer checks the issuance rows a revocation reads against its log
area: auth
severity: minor
resolves_phase: 4
files:
  - internal/signer/revoke.go
  - internal/signer/logstate.go
  - internal/signer/issue.go
  - internal/signer/login.go
  - internal/signerdb/revocation.go
---

## Problem

The pre-merge review of PR #61 (03-03) found this, and one of two skeptics upheld it (split, low). Subject and serial revocations read the issuance table, and nothing checks those rows against the signed log while the signer runs:

- `LiveIssuanceForSubjectTx` (internal/signerdb/revocation.go) filters on the mutable `ca_role` and `key_id` columns. A row whose `ca_role` or `key_id` is changed through another database handle is never returned, so a subject revoke leaves that certificate out of its revoke leaf and the signed KRL and answers a `SerialCount` one lower.
- A serial revoke takes the CA key and ValidBefore from the stored certificate blob (`certCAKey`), which is not checked against the logged certificate either, so an edited blob can move the entry under another CA key or prune it early.
- At start, `checkLogCovers` (internal/signer/logstate.go) compares only the issuance count and the last serial with the log. There is no UPDATE trigger on `issuance`.

It needs write access to the signer's state database outside the signer, the same position as `revocations_not_logged`. It is detected after the fact: `keyroster audit verify` re-derives every revoke entry from the issue and login_issue leaves (03-03), so the shortened subject revoke or the moved serial entry fails at that entry. It is not prevented: until someone runs audit verify, the published KRL omits the certificate.

No small exact guard exists in the style of the revocation multiset (`loggedRevocations.check`, which publishKRLLocked runs against every revocation row before the ops key signs). A row edited out of the subject query's WHERE clause cannot be seen by comparing the rows the query returns, and the signer keeps no per-certificate record of its logged issuance in memory, only the count and the last serial. So the pre-merge review skipped it (03-03-SUMMARY.md, "Pre-merge review fixes").

## Solution

Keep, from the verified log at start and from every committed issue and login_issue leaf after it, an in-memory record of the logged certificates (serial, CA role, key ID, CA key, ValidBefore; about 100 bytes each), the way the signer keeps the logged revocation multiset. Then either:

- resolve subject and serial revocations from that record, not from the table (the audit side already does: `revocations.certs`, `bySubject`), or
- inside the revoke transaction, read every issuance row and refuse `issuance_not_logged` (and stop the signer, as for `revocations_not_logged`) unless the rows are exactly the logged certificates.

The first is simpler and removes the table from the trust path of a revocation. Memory grows with every certificate ever issued; bound it or drop certificates that are no longer live by `krl.EntryLive` at the latest publish.

Tests: a subject revoke after an issuance row's `key_id` or `ca_role` was edited through another handle still lists the certificate (or is refused and stops the signer); the same for a serial revoke after the certificate blob was edited.
