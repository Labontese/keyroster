---
phase: quick-261110-hxf
plan: 01
subsystem: cli-tests
tags: [flaky-test, revoke, tests]
status: complete
requires: []
provides: ["a TestRevokeHost success-line assertion that random hex cannot trip"]
affects: []
key-files:
  modified: [cmd/keyroster/revoke_test.go]
decisions:
  - "The 403 check looks for HTTP 403, the text serverclient prints for a 403 (client.go: HTTP %d), not the bare digits."
requirements: []
metrics:
  completed: 2026-11-10
actuals:
  tasks: 1
  commits: 1
plan_head_before: 3484eda
---

# Quick 261110-hxf Plan 01: fix the revoke host 403 flake Summary

TestRevokeHost/success_line_says_agent_keeps_state asserted that stdout and stderr hold neither "403" nor "not_approved". The output carries fingerprints, and hex or base64 in them sometimes contains "403", so the subtest failed about once in N runs (seen on the cli-windows lane). It now checks for "HTTP 403" and "not_approved". A 403 from the server reaches the user as an error wrapping serverclient's `HTTP 403`; random material cannot contain that string. Test-only; no behaviour change.

## Other subtests

None. The only other bare "403" in cmd/keyroster tests are the status field of the table in TestRevokeRefusalText, which is a fake server's response code and not an output assertion.

## Mutant proof

Changed the success format string in cmd/keyroster/revoke.go to start with `HTTP 403 `. The subtest gave `--- FAIL` (`output names "HTTP 403"`). Restored the file; `git diff --exit-code cmd/keyroster/revoke.go` was clean.

## Verification

- `go test ./cmd/keyroster/ -run TestRevokeHost -count=50`: ok (158.6s).
- `go vet ./cmd/keyroster/`: clean. `gofmt -l cmd/keyroster`: no output.

## Deviations from Plan

None.
