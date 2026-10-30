---
created: 2026-10-28T20:00:00.000Z
title: Record host forget in the tamper-evident log and pin the directory a reset accepts
area: agent
severity: minor
resolves_phase: 4
files:
  - internal/server/hosts.go
  - internal/agent/apply/resetdir.go
  - cmd/keyroster-agent/resetdir.go
  - docs/runbooks/signer-install.md
---

## Problem

Two hardening ideas from PR #71 review fix round 1, kept out of code there.

1. `keyroster host forget` (owner decision D-R1) is an admin-signed server action, but it leaves only a keyroster-server log line. The signer's tamper-evident log records the directory removal, not that the agent was forgotten, so who stopped a host's state delivery, and when, is not in the audit log.
2. `keyroster-agent reset-directory` (owner decision D-R2) drops the accepted directory, so the next apply accepts the newest directory the server serves under the admin quorum, standalone, like a first install. A compromised server could serve an older admin-signed version at that moment (a replay of removed access). The runbook says to compare the applied version with `keyroster directory show`, after the fact.

## Status

- **Forget half: resolved in 03-08b and 03-08c (PR from branch p03/08c-forget-signer; the SUMMARY is pushed before the PR opens).** 03-08 made forget wait for the host's heartbeat (`host_removal_not_applied`) with an explicit, logged `--host-gone`; 03-08b addresses forget by agent identity and keeps a confirmed removal confirmed; 03-08c routes every forget, `--host-gone` included, through keyroster-signer under a signer-checked admin quorum (one admin for an agent never approved, owner decision Q3) and records it as a `host_forget` entry (leaf kind 16) that `keyroster audit verify` re-checks.
- Reset half (item 2): open.

## Solution

1. An audit leaf (or a signer-recorded event) for forget, or route forget through the signer.
2. `reset-directory --expect SHA256:<directory hash>` (or `--min-version N`): the reset records the expected directory, and the next apply accepts only that directory or a successor chained to it; the runbook prints the hash from `keyroster directory show`.
