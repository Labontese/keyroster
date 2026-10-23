---
created: 2026-10-23T12:00:00.000Z
title: The CLI takes software custody from the root-signed bundle, not only the server header
area: auth
severity: minor
resolves_phase: 4
files:
  - internal/serverclient/client.go
  - internal/trust/bundle.go
  - docs/security/custody.md
  - docs/runbooks/server-install.md
---

## Problem

Phase 2 code review, finding F-IN-02 (Info, low, not adversarially verified). Filed after the phase 2 verification (owner decision 2026-10-23).

`checkCustody` (internal/serverclient/client.go, about L735) reads only the server's unauthenticated `Keyroster-Custody` header. That lets a compromised server hide the banner:
- The signer runs the software keystore, and the root-signed bundle records `custody=software`.
- The server sends `Keyroster-Custody: user=tpm,...`.
- The CLI prints no banner.

That contradicts docs/security/custody.md ("no ... configuration of the CLI or the server can hide or soften the warning") and server-install.md (about L364-365). The finding comes from code reading only; no test exercises it (UNVERIFIED).

## Solution

- Also derive the software roles from the root-verified bundle the CLI already fetches, and print the banner if either source says software.
- Alternatively, refuse when the header contradicts the bundle.
- Otherwise, correct the two docs.
- A test with a header that says tpm and a bundle that says software should print the banner (or refuse).
