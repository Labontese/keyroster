---
gsd_state_version: "1.0"
current_phase: 01
current_phase_name: Trust Core
status: executing
stopped_at: "01-04 Task 3 merge gate: owner applies ruleset, then approves PR #5"
last_updated: "2026-10-05T06:05:45.833Z"
last_activity: 2026-10-04
last_activity_desc: Phase 01 execution started
state_head: 310c7750aa00bfb52c02380496e3961613e28067
progress:
  total_phases: 6
  completed_phases: 0
  total_plans: 16
  completed_plans: 5
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-04)

**Core value:** Full visibility: at any moment you know exactly who has access to what, and can revoke it immediately.
**Current focus:** Phase 01 — Trust Core

## Current Position

Phase: 01 (Trust Core) — EXECUTING
Plan: 6 of 16
Status: Ready to execute
Last activity: 2026-10-04 — Phase 01 execution started

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 01 P01 | 54 min | 4 tasks | 23 files |
| Phase 01 P02 | 31 min | 2 tasks | 32 files |
| Phase 01 P03 | 14 min | 2 tasks | 13 files |
| Phase 01 P16 | 22 min | 3 tasks | 11 files |
| Phase 01 P04 | 23 min | 2 tasks | 7 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: 6 coarse phases; Phase 2 is the MVP checkpoint (passkey, cert in ssh-agent, real SSH login)
- [Roadmap]: The KRL encoder ships with revocation in Phase 3 (REVOKE-02), not Phase 1 as research suggested; Phase 1 only defines the KRL authority in the trust-bundle format
- [Roadmap]: The who-has-access overview (VIS-04) lands in Phase 5 so it covers plain keys from inventory, not only certificates
- [Roadmap]: Break-glass access (BREAK-01) is in Phase 3, since a dogfooding lockout is the likeliest early incident; break-glass logging (BREAK-02) reuses login reconciliation (VIS-05) in Phase 5
- [Roadmap]: Log witnessing by agents and CLI (VIS-02) is an insider-resistance control in Phase 4
- [Phase 01]: Required status checks keep integration_id 15368 (GitHub Actions); accepted by the API and resolved on PR #1
- [Phase 01]: keyroster-bot (id 337682656) signs with ed25519 key 1218459 held only in the Windows ssh-agent; private key file deleted
- [Phase 01]: scripts/merge-gate.sh rebases with --autostash and an explicit lease so GSD's uncommitted working files cannot block the rebase loop
- [Phase 01]: IssueRequest variable fields use uint16 length prefixes (cryptobyte has no uint32 reader); the 64 KiB frame cap is unchanged
- [Phase 01]: keyroster-signer serve: umask 0077, empty allowlist refused, 32 concurrent connections, single DB connection, SetLastSerial only raises; socket group = first --allow-group
- [Phase 01]: Finding for 01-13: keyroster-signer has no net/http or crypto/tls in its deps but reaches os/exec transitively via modernc.org/libc; depguard only catches direct imports
- [Phase 01]: Admin-only repo settings are applied by the owner via scripts/apply-security-settings.sh; the API accepted all of them including sha_pinning_required=true
- [Phase 01]: Code of Conduct contact is @Labontese via GitHub report-abuse (no private messages on GitHub); flagged for the owner
- [Phase 01]: New third-party actions need a selected-actions allowlist entry (owner) plus a SHA pin; Scorecard publishes only from main, verified in 01-15
- [Phase 01]: IssueRequest.SigningBytes starts with the raw keyroster/issue-request/v1 tag (no uint16 length prefix), per the 01-02 contract; 01-07 signs these bytes
- [Phase 01]: The agent keystore backend skips certificate entries by the -cert-v01@openssh.com key type, since the x/crypto agent client returns entries as agent.Key, never ssh.Certificate
- [Phase 01]: gsd-tools tdd-red-evidence parses only TAP/Surefire; Go RED evidence is recorded in the plan SUMMARY
- [Phase 01]: 01-04: a ruleset that adds required checks is applied by the owner from the PR branch after the checks are green on that PR and before approval (Pitfall 10); Claude never applies rulesets
- [Phase 01]: 01-04: every sshd authentication refusal in e2e runs against its own sshd (OpenSSH >= 9.8 PerSourcePenalties; 9.5p1 lacks the option), and each refusal has a control that succeeds
- [Phase 01]: 01-04: the plan's -L 0:... forwarding case was replaced by -W (direct-tcpip) and -R with ExitOnForwardFailure, because ssh rejects -L 0:... before connecting

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 1]: Ed25519 via PKCS#11/ssh-agent and TPM algorithm support unverified; decide CA key algorithm and custody together in phase research
- [Phase 2]: CLI WebAuthn transport undecided (browser loopback is the default); Windows CTAP access for non-admin users unverified
- [Phase 3]: Unknown whether sshd re-reads `RevokedKeys` without a reload; settle with an integration test
- [Phase 5]: Windows edge cases (principal case, domain/Entra accounts, `verify-required`, KRL on 9.5p2) at LOW-MEDIUM confidence
- [General]: HSM signing throughput under login storms not measured

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| *(none)* | | | | |

## Session Continuity

Last session: 2026-10-05T06:05:45.760Z
Stopped at: 01-04 Task 3 merge gate: owner applies ruleset, then approves PR #5
Resume file: None
