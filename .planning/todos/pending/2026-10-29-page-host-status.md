---
created: 2026-10-29T06:00:00.000Z
title: Page keyroster host status so the fleet view survives the CLI's 4 MiB cap
area: server
severity: minor
resolves_phase: 3
files:
  - internal/server/hosts.go
  - internal/serverclient/agent.go
  - cmd/keyroster/hoststatus.go
---

## Problem

PR #72 review C18 (upheld as low; not fixed in fix round 1). `GET /api/v1/admin/hosts/status` returns every approved agent's full heartbeat in one answer, with no paging or size budget, and the CLI reads it through `AdminJSON` under the 4 MiB `maxResponse`. Above that the call fails before decoding (`response larger than 4194304 bytes`), and `--json` uses the same call, so the admin gets no host status at all: no `silent`, `stuck`, `krl_stale`, `clock_skew`, `status_stale` or convergence line for any host. The reviewer measured a typical row (20 accounts) at about 3.5 KB, so about 1,190 hosts reach the cap; a compromised host can post a heartbeat of about 56 KiB that passes validation, so a dozen such hosts in a fleet of 1,000 push the answer over. It fails loudly, never silently. 03-12's CA-rotation gate also reads this view.

## Solution

Give the admin view a size budget. Either page `AdminHostsStatusPath` (a cursor and a limit) and have the CLI fetch every page, or return a summary row per host (versions with SHA-256, flags, file count and a hash of the file list instead of the full `files` array) with a per-host detail route for the whole heartbeat. Add a test that builds an answer for N maximal heartbeats and checks that the CLI still renders it.
