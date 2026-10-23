---
created: 2026-10-23T12:00:00.000Z
title: The directory install pending check covers re-keyed and moved credentials
area: auth
severity: minor
resolves_phase: 4
files:
  - internal/server/directory.go
  - internal/server/session.go
  - internal/server/weblogin.go
  - internal/signer/directory.go
---

## Problem

Phase 2 code review, finding B-IN-01 (Info, low, not adversarially verified). Filed after the phase 2 verification (owner decision 2026-10-23).

`directoryBindings` (internal/server/directory.go, about L389) treats a binding as new only when its credential ID is missing from `base.credIDs`. An admin-signed successor can keep credential ID X but change its SPKI or algorithm, or move X to another user. Such a successor installs without a `credential_not_pending` check, although the handler's doc promises that check "with the same algorithm and key".

`withSession` and `boundCredential` match on user and ID only, so a web session opened with the old key survives up to 12 h after a re-key.

The admin signature remains the authority. This is a gap in a server safeguard, not an escalation. The finding comes from code reading only; no test exercises it (UNVERIFIED).

## Solution

- Keep each base credential's (user, alg, SPKI) in `directoryView`, and count a changed binding as newly bound. Alternatively, refuse such transitions outright, in the server or as a successor rule in the signer.
- Store the SPKI hash in the sessions row and compare it in `withSession`.
- Add a test for each transition (same ID with a new SPKI, same ID under another user).
