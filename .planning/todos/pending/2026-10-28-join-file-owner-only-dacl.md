---
created: 2026-10-28T20:00:00.000Z
title: Give a join file written on Windows an owner-only DACL
area: cli
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster/host.go
  - cmd/keyroster/root.go
  - docs/runbooks/host-setup.md
---

## Problem

PR #71 review F14. `keyroster host join-token --out FILE` writes the live join string with `os.OpenFile(..., 0o600)`. On Windows the mode only sets the read-only attribute and the file inherits its directory's ACL, so in a shared directory any local user can read the unused token for up to an hour and race the real host to enroll. Fix round 1 stopped the CLI from claiming mode 0600 there and prints a warning to use a private directory; the file itself is still not protected.

## Solution

On Windows, create the file with an explicit DACL that grants only the current user (and SYSTEM, if needed) full control, with inheritance disabled, through `golang.org/x/sys/windows` (already a dependency; the agent's Windows paths plan the same `SetNamedSecurityInfo` pattern). Then restore the "mode 0600"-equivalent wording ("readable by you only"). Test on the Windows CI lane: read the file's DACL back and check its entries.
