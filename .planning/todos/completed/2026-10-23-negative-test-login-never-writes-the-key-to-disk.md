---
created: 2026-10-23T12:00:00.000Z
title: A negative test proves keyroster login never writes the ephemeral key to disk
area: test
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster/login.go
  - cmd/keyroster/loginagent_unix.go
  - cmd/keyroster/loginagent_windows.go
  - cmd/keyroster/loopback.go
  - cmd/keyroster/login_test.go
---

## Problem

Owner decision 2026-10-23 on the phase 2 verification: "Acceptera, lägg till tester senare (Rekommenderas)". The owner accepted the verifier's code-reading evidence for the disk half of the 02-12 prohibition "the CLI never writes the ephemeral private key to disk", and asked for the negative test later. The retry half is already tested.

Today the evidence is that login.go, loginagent_*.go and loopback.go contain no file write. No named test enforces it, so a later change could write the key (or a debug dump) without any test failing.

## Solution

- Run the login flow test (TestLoginFlowFakeServer or a variant) with HOME, the config dir and TMPDIR pointed at empty temporary directories. Afterwards, assert that no file contains the private key bytes or an OpenSSH private-key header.
- Optionally add a forbidigo/static rule that bans `os.WriteFile`, `os.Create` and `os.OpenFile` in the login files.
- Make sure the test fails when a dummy key write is added (mutant check).

## Resolution

Resolved in 03-02 (PR from branch `p03/02-phase2-followups`). `TestLoginNeverWritesKey` (cmd/keyroster/login_disk_test.go), with a mutant check; no forbidigo rule was added.
