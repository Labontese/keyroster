---
created: 2026-10-23T12:00:00.000Z
title: A negative test proves there is no non-passkey sign-in route
area: test
severity: minor
resolves_phase: 3
files:
  - internal/server/server.go
  - internal/server/server_test.go
---

## Problem

Owner decision 2026-10-23 on the phase 2 verification: "Acceptera, lägg till tester senare (Rekommenderas)". The owner accepted the verifier's code-reading evidence for the 02-10 test-tier prohibition "no password, TOTP, recovery-code or magic-link sign-in path", and asked for the negative test later.

Today the evidence is the route table (internal/server/server.go, about L122-155): it has no password, TOTP, recovery or magic-link handler. No named test enforces it, so a later route could add such a path without any test failing.

## Solution

- Add a test that enumerates the server's registered routes (or the mux patterns). It fails on any sign-in or session-creating route other than the passkey ceremony.
- Probe the obvious paths (`/login/password`, `/totp`, `/recovery`, `/magic`, and form posts with a password field), expecting 404 or 405 and no session cookie.
- Make sure the test fails when a dummy password route is added (mutant check).

## Resolution

Resolved in 03-02 (PR from branch `p03/02-phase2-followups`). `TestNoNonPasskeySignInRoute` (internal/server/routes_test.go) over the patterns `newRouteMux` records, with the `passkeyRoutes` allowlist, a single-mux source check and probes; mutant checks in 03-02-SUMMARY.md.
