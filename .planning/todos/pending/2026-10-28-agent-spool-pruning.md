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

03-07 executor open question 3, kept open by the PR #71 review (fix round 1). The fetcher never removed old spool files: every bundle, policy, directory and KRL version stayed, and the spool grew by every version the server publishes. Fix round 1 only removes files above the server's current versions after a complete poll (`dropAbove`, F3/F7) and, for `keyroster-agent reset-directory`, the spool's directory files.

A related cost from F3/F7: the fetcher starts every poll from the applier's accepted versions, so while the applier cannot accept a version (a refused chain, a stopped applier) every poll downloads the same versions again, up to the 64 more-rounds.

## Status

The pruning is done by 03-08e's pre-merge review fix rounds 1 to 3 (F01, `pruneSpool` and `spool.Keep`). At the start of every poll the fetcher removes, by the versions in `outbox/accepted.json`, every bundle and directory version but the accepted one and up to 1024 above it (what one poll can fetch, which also covers every pending swap's floor; the newest 64 with none accepted), every KRL but the newest complete one, and every policy no kept bundle names under its own version. An apply after the prune reads what it read before (`TestSpoolPrune/prune_keeps_what_the_applier_reads`), and the spool stays bounded (`spool_stays_bounded_across_polls`). Since 03-08j, `outbox/accepted.json` names an unapplied record's versions where they are higher, so the prune's window counts from them.

## Remaining

- Whether to skip rewriting a spool file whose bytes are unchanged.
- The repeated download from the accepted versions described above.
- The prune's window could shrink from 1024 to 64 versions once the applier publishes, in the outbox, every floor it reads the spool from (its accepted versions, a recorded unapplied state, and the pending target of a widening wait). A host catching up must keep today's pace, so while the applier moves between polls the fetcher would keep and fetch as it does now.

None of these changes what the applier reads.
