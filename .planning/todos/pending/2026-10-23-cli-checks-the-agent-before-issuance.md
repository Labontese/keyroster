---
created: 2026-10-23T12:00:00.000Z
title: keyroster login checks the ssh-agent before the certificate is issued
area: cli
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster/login.go
  - cmd/keyroster/loginagent_unix.go
  - cmd/keyroster/loginagent_windows.go
  - cmd/keyroster/login_unix_test.go
---

## Problem

Phase 2 code review, finding E-IN-01 (Info; raised as medium, both skeptics upheld it at low). Filed after the phase 2 verification (owner decision 2026-10-23).

The CLI checks for a usable agent only after the certificate is issued:
- This happens on Unix with `SSH_AUTH_SOCK` unset, or on Windows when `winagent.Ensure` returns `ErrOwnerUnverifiable`. The user still approves with the passkey.
- The signer issues the certificate and commits a `login_issue` leaf.
- Only then does `connectLoginAgent` fail. It is called only from `addLoginToAgent` (cmd/keyroster/login.go, about L574).

Every retry adds another logged grant that nobody holds. The ephemeral key is zeroed at exit, but in the log these grants look exactly like real ones, which works against "full visibility". `login_unix_test.go` (about L76-88) locks in the after-issuance order, and no plan records this order as accepted.

## Solution

- Call `connectLoginAgent` right after `plan()` and before begin, including Ensure's owner check and List on Windows.
- Hold the connection until the Add and the listing check, and pass it to `addLoginToAgent`.
- Change the test to require the before-issuance order (no begin when no agent is usable).
- Do this together with the E-IN-02 todo (`2026-10-23-recompute-agent-lifetime-before-add.md`), which changes the same code path.
