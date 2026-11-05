---
phase: quick-261105-ntp
plan: 01
subsystem: formats
tags: [registry, tlog, wire, docs, runbooks]
status: complete
requires: []
provides: ["docs/format-registry.md, the one allocator of leaf kinds, wire message types and tags, pinned to the code by TestFormatRegistry"]
affects: ["every later plan that adds a leaf kind, wire message type, tag, signed format or key ID field (03-09 to 03-12, Phases 4 and 5)"]
tech-stack:
  added: []
  patterns: ["a registry document pinned to constants by a go/parser test"]
key-files:
  created: [docs/format-registry.md, internal/tlog/registry_test.go]
  modified: [internal/tlog/leaf.go, internal/wire/frame.go, docs/runbooks/root-ceremony.md, docs/runbooks/signer-install.md]
decisions:
  - "docs/format-registry.md allocates every leaf kind and wire message type: next free number to the next plan that needs one, in merge order, claimed in that plan's PR. Phase 4 and 5 drafts hold no numbers; migrations are not reserved."
  - "The registry lives in docs/, not .planning/: a Go test reads it, and phase directories are archived at milestone end."
requirements: []
metrics:
  completed: 2026-11-05
actuals:
  tasks: 3
  commits: 3
plan_head_before: f7eb0184bffbbe4bd82e65f852cb1a8ba20aaf96
---

# Quick 261105-ntp Plan 01: number and format registry, and UNVERIFIED build claims Summary

docs/format-registry.md now owns every number and tag that the audit log or the wire reads forever, and TestFormatRegistry (internal/tlog) fails when it and the code disagree. The two reproducible-build claims in the runbooks are labelled UNVERIFIED. PR [#87](https://github.com/Labontese/keyroster/pull/87), opened by keyroster-bot without auto-merge.

## Commits

- `b7cca53` docs(registry): add a number and format registry pinned to the code
- `e6c752f` docs(runbooks): label the reproducible-build claims UNVERIFIED
- the docs commit carrying this PLAN and this SUMMARY

The owner is the author of each commit, and keyroster-bot is the committer, with an SSH signature.

## The registry

- Leaf kinds 1 to 10, 15 and 16 in use (01-05, 02-01, 03-01, 03-06b, 03-08c); 11 to 14 reserved for 03-09 to 03-12; next free 17.
- Request types 0x01 to 0x09 and 0x0D in use; 0x0A to 0x0C reserved for 03-09 to 03-11 (answered with 0x81); next free 0x0E. Responses 0x81 to 0x84, 0x86 to 0x89, 0x8D, 0xFF.
- The other closed enumerations, the domain tags and SSHSIG namespaces, the refusal-detail rule (classify; unclassified means ReasonInternal and 503), the installation-binding rule and the key ID budget.

## Key ID budget (from OpenSSH log.c and auth.c, master, 2026-11-05)

`do_log` logs `syslog(pri, "%.500s", fmtbuf)` after `strnvis`. The `Accepted publickey` line costs at most 289 bytes besides the key ID (32-byte user, IPv6 address), so the key ID gets 211 bytes (143 with sshd's 100-byte user cap). kr1 at its longest: 167 bytes (170 for `ca=machine`). kr2 with 16 roles of 32 bytes: 726 bytes, over the budget; only 12 bytes of role names fit at the longest subject and 20-digit numbers. Lengths measured with `KeyID.String` and `ParseKeyID`.

## RED first

Eleven mutants, each applied alone and undone: a fake leaf constant 17, a fake wire constant 0x0E, kind 16's row removed, 0x8D's row removed, 0x0D renumbered 0x0E in the registry, a constant at reserved kind 11, reserved row 12 marked in use, a non-literal constant, KindHostForget renumbered in the code, a stale next free kind, a reserved 0x0E row with a stale next free request type. Every one fails TestFormatRegistry; the restored tree passes.

## Verification (Windows, Git Bash, WSL)

- `bash scripts/linux.sh 'go test -race -count=1 ./internal/tlog/ ./internal/wire/ ./cmd/keyroster/'`: ok (the runbook tests in cmd/keyroster included).
- `golangci-lint run ./internal/tlog/... ./internal/wire/... ./cmd/keyroster/...` (v2.14.0): 0 issues; `gofmt -l .` clean.
- .github/workflows and scripts: no job builds a commit twice and compares hashes, so the two runbook claims are UNVERIFIED. No other claim under docs/.

## Deviations from Plan

- No STATE.md quick-task row: the brief excludes ROADMAP and STATE changes.
- leaf.go and frame.go gained one comment sentence each pointing at the registry, and the test also pins the next-free sentences. Neither was asked for; both keep the registry from drifting.

## Notes

- The 03-09 to 03-11 plans list the HostIssueRequest, ProbeIssueRequest and MachineIssueRequest fields without an installation ID. The registry's installation-binding rule covers them, so they must carry it when those plans are executed.
- kr2 key IDs with long role lists exceed the budget today. The registry records the numbers; changing the caps or the format needs its own plan.

## Self-Check: PASSED
