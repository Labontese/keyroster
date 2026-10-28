---
created: 2026-10-28T20:00:00.000Z
title: Prune versions the applier accepted from the agent's spool
area: agent
severity: minor
resolves_phase: 3
files:
  - internal/agent/fetch/fetch.go
  - internal/agent/spool/spool.go
  - internal/agent/enroll/pop.go
---

## Problem

03-07 executor open question 3, kept open by the PR #71 review (fix round 1). The fetcher never removes old spool files: every bundle, policy, directory and KRL version stays, and the spool grows by every version the server publishes. Fix round 1 only removes files above the server's current versions after a complete poll (`dropAbove`, F3/F7) and, for `keyroster-agent reset-directory`, the spool's directory files.

A related cost from F3/F7: the fetcher now starts every poll from the applier's accepted versions, so while the applier cannot accept a version (a refused chain, a stopped applier) every poll downloads the same versions again, up to the 64 more-rounds.

## Solution

The fetcher has the applier's accepted versions now (`outbox/accepted.json`, F3/F7). It can remove spool versions at or below them, keeping the accepted version itself (spool.Read uses the newest version at or below the floor to read an equal version as a no-op) and the policy the accepted bundle names. Decide with the owner whether the fetcher or the applier prunes, and whether to skip rewriting a spool file whose bytes are unchanged. Tests: a long-running spool stays bounded; an apply after pruning is a no-op.
