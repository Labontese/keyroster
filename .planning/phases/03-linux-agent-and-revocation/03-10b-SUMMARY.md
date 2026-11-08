---
phase: 03-linux-agent-and-revocation
plan: 10b
subsystem: agent, ci
tags: [probe-certificates, self-test, d-06, agent-04, e2e]
status: in-progress
requires: [03-10]
requirements-completed: []
---

# Phase 3 Plan 10b: The agent's probe self-test Summary (draft)

Owner answers: Q2 Q5 Q6 P4 planner-defaults
AGENT-04: open until 03-10c

## Bases

test-time base: apply=515.806 fetch=39.539 heartbeat=1.069 serverclient=4.333 agentcmd=2.279 cmd=241.507 at=1794104446
e2e base: run 42403955637 9.5p1=779.609 10.5p1=794.258 probe9.5p1=35.006 probe10.5p1=37.983

The test-time base ran on unchanged origin/main 1260b8c in a detached worktree outside the repository, with no other heavy job, through scripts/linux.sh (go1.27.3 linux/amd64 in WSL); each time is that package's `ok` line.

## Task 1

e2e RED run: 42439277162

RED (CI): the throwaway branch p03/10b-e2e-red held test/e2e/probe_selftest_test.go and .github/workflows/e2e.yml only (`git diff --name-only origin/main...p03/10b-e2e-red` printed exactly those two). Both main lanes passed and showed no probe test; both e2e-probe lanes failed to build with `undefined:` lines in probe_selftest_test.go (16 such lines across the run's log: withGenesisMachineMaxTTL, apply.ProbeQuery, apply.ProbeTarget, apply.ProbeOutcome, apply.ProbeAccepted, apply.ProbeRefused, apply.ProbePairSpacing, ...). The branch was deleted afterwards (`git ls-remote --exit-code origin refs/heads/p03/10b-e2e-red` exits 2). After the RED run the test file changed only by two `//nolint` comments for the e2e lint.

RED (unit, compile failures): internal/agent/probe with probe.go moved aside (`undefined: Pair`, `Polarities`, `NewCert`, ...); internal/serverclient with the method reverted (`c.AgentProbeCert undefined`); internal/agent/fetch (`s.f.postProbeCerts undefined`). The first run of TestVerifyCert against the drafted core then failed for real: `TestVerifyCert/ok`, `not_yet_valid` and `expired_or_in_margin` refused a valid certificate as signature_invalid, because x/crypto's CertChecker in this version does not skip source-address; both options are now listed as supported (they are checked exactly before the signature).

The check step of the e2e-probe job, cut out of the workflow and run under `bash -eo pipefail` on a canned log, exits 0 with all four PASS lines and exits 1 with `the log has no PASS line for TestProbePairSpacing` when that line is missing: it bites.

## Task 2

## Task 3

## Task 4

## Mutants

## Deviations

## UNVERIFIED
