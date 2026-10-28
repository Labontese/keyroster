---
created: 2026-10-28T20:00:00.000Z
title: Decide on keyroster-agent install --replace for a host moving deployments
area: agent
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster-agent/install.go
  - docs/runbooks/host-setup.md
---

## Problem

03-07 executor open question 4, kept open by the PR #71 review (fix round 1). `keyroster-agent install` refuses `install_pins_differ` unless an existing `pins.json` is byte-equal, so moving a host to another deployment (other trust roots or installation ID) means removing `/var/lib/keyroster-agent` by hand, which no runbook spells out step by step.

## Solution

Owner decision first: either document the manual removal (stop both units, keep a copy of the state for the record, remove the state directory and the fetcher's directory, `keyroster host forget` on the old deployment), or add `install --replace`, which does the same under the apply lock and refuses while an apply is unfinished. Either way, the old deployment should forget the agent (`keyroster host forget`, fix round 1).
