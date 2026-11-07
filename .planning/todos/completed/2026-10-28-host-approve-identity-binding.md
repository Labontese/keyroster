---
created: 2026-10-28T20:00:00.000Z
title: Bind host approve and host forget to the agent identity the admin compared
area: agent
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster/host.go
  - internal/server/hosts.go
  - internal/serverclient/agent.go
  - docs/runbooks/host-setup.md
---

## Problem

PR #71 review fix round 1 (owner decision D-R4) binds `keyroster host approve --yes` to the host keys the admin compared (`--host-key`, the exact set). The agent identity fingerprint that `keyroster-agent identity` prints is still compared by eye only: approval is by host keys, and the server ties the approval to the agents row whose keys match. A server that swaps the pending row's identity, keeping the host keys, cannot get a key signed that the host does not hold, but the admin's comparison of the identity line binds nothing.

`keyroster host forget NAME` deletes every agent enrolled under NAME. With two agents under one name (two join tokens used for one name), the admin cannot forget only one of them.

## Solution

- `host approve --identity SHA256:...`: refuse unless the re-fetched pending host's identity fingerprint is the given one; required with `--yes` next to `--host-key`.
- `host forget NAME --identity SHA256:...`: forget only that agent; the server answers `host_name_ambiguous` without it when several agents share the name.
- Tests: a swapped identity refused with nothing signed; forget of one of two agents.

## Resolution

Resolved in 03-09b (PR from branch `p03/09b-host-trust`), owner decision QB-4. The approve half is settled by documentation, not code: host-setup.md step 4 of "Enrolling a host" now says that the `agent identity:` line `keyroster host approve` prints is informational, and that the approval is bound by the host keys of the entry the admin signs (`--host-key`, the exact set; `TestHostApproveHostKeys`). The forget half shipped earlier as `keyroster host forget --identity`, which forgets exactly one agent (cmd/keyroster/host.go, `TestHostForget`).
