---
created: 2026-10-29T06:00:00.000Z
title: Sign the applier's status so host status does not rest on the fetcher's word
area: agent
severity: minor
resolves_phase: 3
files:
  - internal/agent/apply/status.go
  - internal/agent/heartbeat/heartbeat.go
  - internal/agent/fetch/heartbeat.go
  - internal/server/agent.go
  - docs/runbooks/host-setup.md
---

## Problem

PR #72 review S1 (split 1 of 2), owner decision D-R4: a known residual, documented as threat row T-03-284 and in host-setup.md "What host status rests on". `keyroster host status` rests on the host's own report, and the unprivileged fetcher composes the heartbeat body: it reads the root applier's `outbox/status.json`, but nothing in the body proves that the applier wrote it. A compromised fetcher (D-05's sandboxed, network-facing process) can withhold a new KRL or directory version from the spool and post a status that claims it applied, with any seq above the stored one (within `heartbeat.MaxSeqAhead`). host status then shows the host converged, and the same status satisfies forget's removal wait and, later, 03-12's rotation gate. What remains on the host: the applier logs `krl_stale` at error level in the journal once the KRL in force is 24 h old, and `keyroster-agent check` shows what is installed.

## Solution

A possible later plan, not decided. The review's suggestion: the root applier signs the canonical status (seq included) under a dedicated domain, with one of the sshd host keys it already uses for the enrollment proof of possession, or with an applier key the fetcher cannot read, and writes `{status, sig}` to the outbox. The server verifies the signature against the host keys approved for that agent before StoreHeartbeat and refuses `heartbeat_signature_invalid` otherwise. Decide with the owner: which key signs (a host key can sign through `HostKeyAgent` setups or not at all; a separate applier key needs enrollment), how a host key rotation (host_keys_rotated) is handled, and whether forget and 03-12's gate then require a signed status.
