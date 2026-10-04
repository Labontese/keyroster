---
phase: 01-trust-core
plan: 03
subsystem: repo-hygiene
tags: [github, codeql, scorecard, dependabot, secret-scanning, private-vulnerability-reporting, actions-permissions, sha-pinning, community-files]

requires:
  - phase: 01-01
    provides: "Public repo, SHA-pinned CI (build-test, lint, govulncheck, pr-title), keyroster-bot, scripts/gh-as-bot.sh, scripts/merge-gate.sh, minimal SECURITY.md and README.md"
provides:
  - "CodeQL advanced setup: Analyze (go) with a manual CGO_ENABLED=0 build and Analyze (actions), security-extended queries, on push to main, pull_request and weekly"
  - "OpenSSF Scorecard workflow (push to main, weekly, branch_protection_rule, workflow_dispatch) with publish_results and SARIF upload"
  - "pinned-actions check: scripts/check-pinned-actions.sh run by .github/workflows/workflow-lint.yml; fails any uses: that is not ./local or @<40 lowercase hex>"
  - "scripts/apply-security-settings.sh: idempotent owner-run script for secret scanning + push protection, private vulnerability reporting, Dependabot alerts + security updates, read-only GITHUB_TOKEN, no PR approval by Actions, selected-actions allowlist, sha_pinning_required"
  - "Dependabot: gomod for / (golang-x group) and /tools, github-actions (actions group), weekly, Conventional Commits prefixes build/ci"
  - "Community files: Contributor Covenant 2.1, bug/feature issue forms, blank issues off with vulnerability reports routed to private reporting, PR template, full SECURITY.md, README CI + Scorecard badges"
affects: [01-04, 01-13, 01-15, all later plan PRs (pinned-actions, CodeQL), Dependabot PRs through the merge gate]

actuals:
  tokens: 5568
  tasks: 2
  commits: 2
plan_head_before: e4e6359ebc798484a75e87019b543cb3394aec11
plan_head_after: 01e111b458ad9a70f6773fbe1e5440424b5f051b

tech-stack:
  added: [github/codeql-action v4.38.2, ossf/scorecard-action v2.4.4, actions/checkout v7.0.1, actions/setup-go v7.0.0 (all SHA-pinned)]
  patterns:
    - "Repository settings that need admin rights live in an idempotent owner-run script (like scripts/apply-rulesets.sh); keyroster-bot never holds admin and Claude never writes with the owner token"
    - "Every workflow has top-level permissions: {} and grants per job; every uses: is pinned to a full commit SHA with the tag in a comment"
    - "Pinning is enforced twice: GitHub's sha_pinning_required repository setting and the in-repo pinned-actions check"

key-files:
  created:
    - .github/workflows/codeql.yml
    - .github/workflows/scorecard.yml
    - .github/workflows/workflow-lint.yml
    - scripts/check-pinned-actions.sh
    - scripts/apply-security-settings.sh
    - .github/dependabot.yml
    - CODE_OF_CONDUCT.md
    - .github/ISSUE_TEMPLATE/bug_report.yml
    - .github/ISSUE_TEMPLATE/feature_request.yml
    - .github/ISSUE_TEMPLATE/config.yml
    - .github/pull_request_template.md
  modified:
    - SECURITY.md
    - README.md

key-decisions:
  - "Admin-only repository settings are applied by the owner through scripts/apply-security-settings.sh; the API accepted every setting, including sha_pinning_required=true (no fallback needed)"
  - "Code of Conduct enforcement contact reads 'the maintainer, @Labontese, via a private message or GitHub's report-abuse function'; GitHub has no private messages, so in practice the channel is report-abuse (flagged for the owner)"
  - "Scorecard publishes only from main, so no Scorecard analysis exists before this PR merges; plan 01-15 verifies at least one analysis (workflow_dispatch if needed)"

patterns-established:
  - "New third-party actions need both an allowlist entry (selected-actions patterns) and a SHA pin; GitHub-owned actions need only the pin"
  - "Dependabot commit prefixes (build for gomod, ci for actions) keep its PR titles passing the pr-title check"

requirements-completed: [REPO-04]

coverage:
  - id: D1
    description: "Secret scanning and push protection enabled"
    requirement: REPO-03
    verification:
      - kind: other
        ref: "gh api repos/Labontese/keyroster --jq '[.security_and_analysis.secret_scanning.status, .security_and_analysis.secret_scanning_push_protection.status] | join(\",\")' -> enabled,enabled"
        status: pass
    human_judgment: false
  - id: D2
    description: "Private vulnerability reporting enabled; SECURITY.md and the issue config route reports to security/advisories/new; SECURITY.md has no email address"
    requirement: REPO-04
    verification:
      - kind: other
        ref: "gh api repos/Labontese/keyroster/private-vulnerability-reporting --jq .enabled -> true; grep checks on SECURITY.md and .github/ISSUE_TEMPLATE/config.yml pass; email grep finds nothing"
        status: pass
    human_judgment: false
  - id: D3
    description: "Dependabot alerts and security updates enabled; dependabot.yml covers / , /tools and github-actions"
    requirement: REPO-03
    verification:
      - kind: other
        ref: "gh api repos/Labontese/keyroster/vulnerability-alerts exit 0; automated-security-fixes {enabled:true,paused:false}; security_and_analysis.dependabot_security_updates enabled; grep checks on .github/dependabot.yml pass"
        status: pass
    human_judgment: false
  - id: D4
    description: "GITHUB_TOKEN read-only by default, Actions cannot approve PRs, selected-actions allowlist with SHA pinning required"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "actions/permissions/workflow -> read,false; actions/permissions -> allowed_actions=selected, sha_pinning_required=true; selected-actions -> github_owned_allowed=true, verified_allowed=false, patterns [golangci/golangci-lint-action@*, ossf/scorecard-action@*]"
        status: pass
    human_judgment: false
  - id: D5
    description: "pinned-actions check passes on all workflows and fails on an unpinned reference"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "bash scripts/check-pinned-actions.sh -> all 16 uses: references pinned; scratch copy with uses: actions/checkout@v7 -> exit 1, reports bad.yml:7"
        status: pass
    human_judgment: false
  - id: D6
    description: "CodeQL analyses Go and Actions on the PR and reports to code scanning"
    requirement: REPO-03
    verification:
      - kind: other
        ref: "PR #3 head 01e111b: Analyze (go) pass, Analyze (actions) pass, CodeQL pass; code-scanning/analyses contains CodeQL -> true"
        status: pass
    human_judgment: false
  - id: D7
    description: "All checks green on the rebased head under selected-actions + sha_pinning_required (first run with the settings live)"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks p01/03-github-hygiene --watch on 01e111b: build-test, lint, govulncheck, pr-title, pinned-actions, Analyze (go), Analyze (actions), CodeQL all pass"
        status: pass
    human_judgment: false
  - id: D8
    description: "OpenSSF Scorecard publishes results"
    requirement: REPO-03
    verification:
      - kind: other
        ref: "Not observable before merge: Scorecard publishes only from main; plan 01-15 verifies an analysis exists"
        status: deferred
    human_judgment: false
  - id: D9
    description: "PR #3 is green with auto-merge on and waits for the owner's approval at the merge gate"
    requirement: REPO-03
    verification:
      - kind: other
        ref: "bash scripts/merge-gate.sh p01/03-github-hygiene -> exit 2 (awaiting owner approval)"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 3 blocking-human merge gate, after this SUMMARY is written"

duration: 14min
completed: 2026-10-04
status: complete
---

# Phase 1 Plan 03: GitHub Hygiene Summary

**Secret scanning with push protection, private vulnerability reporting, Dependabot alerts and security updates, a read-only `GITHUB_TOKEN` that cannot approve PRs, and a selected-actions allowlist with GitHub-enforced SHA pinning are live on Labontese/keyroster; CodeQL (Go + Actions), Scorecard and an in-repo pinned-actions check run as workflows, and the community files (Code of Conduct, issue forms, PR template, full SECURITY.md) route every vulnerability report to private reporting. PR #3 is green under the new settings and waits for the owner.**

## Performance

- **Duration:** 14 min wall clock from the recorded start, including the owner's settings run
- **Started:** 2026-10-04T12:42:12Z
- **Completed:** 2026-10-04T12:56:12Z
- **Tasks:** 2 of 3 executed before the merge gate (Task 3 is the owner's approval)
- **Files modified:** 13 (11 created, 2 modified), 522 insertions, 5 deletions

## Accomplishments

- Task 1 (tracer): CodeQL, Scorecard and workflow-lint workflows plus `scripts/check-pinned-actions.sh`. The repository settings were applied by the owner with `scripts/apply-security-settings.sh` and verified read-only through the API (all values in the coverage table).
- Task 2: Dependabot config, Contributor Covenant 2.1, issue forms with blank issues disabled, PR template, full SECURITY.md, CI and Scorecard badges in README.
- Tracer feedback gate: after the settings went live, the branch was rebased onto main (PR #2 had merged) and every check ran again under `allowed_actions=selected` and `sha_pinning_required=true`; all passed, so no workflow uses a disallowed or unpinned action.

## PR

- **PR #3** `ci: enable CodeQL, Scorecard, Dependabot and repository security policies` (https://github.com/Labontese/keyroster/pull/3), branch `p01/03-github-hygiene`, opened by keyroster-bot, auto-merge squash enabled.
- Checks on the rebased implementation head `01e111b`: `build-test`, `lint`, `govulncheck`, `pr-title`, `pinned-actions`, `Analyze (go)`, `Analyze (actions)`, `CodeQL` all pass. GitHub reports both rebased commits as verified (keyroster-bot signature).

## Settings Accepted by the API

| Setting | Value read back |
|---|---|
| `security_and_analysis.secret_scanning` | enabled |
| `security_and_analysis.secret_scanning_push_protection` | enabled |
| `private-vulnerability-reporting` | enabled: true |
| `vulnerability-alerts` | HTTP 204 (enabled) |
| `automated-security-fixes` / `dependabot_security_updates` | enabled, not paused |
| `actions/permissions/workflow` | `default_workflow_permissions=read`, `can_approve_pull_request_reviews=false` |
| `actions/permissions` | `enabled=true`, `allowed_actions=selected`, **`sha_pinning_required=true` (accepted)** |
| `actions/permissions/selected-actions` | `github_owned_allowed=true`, `verified_allowed=false`, patterns `golangci/golangci-lint-action@*`, `ossf/scorecard-action@*` |

Pinned action SHAs (re-resolved 2026-10-04): codeql-action v4.38.2 `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2`, scorecard-action v2.4.4 `2d1146689b8cda280b9bc96326124645441f03bc`, checkout v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1`, setup-go v7.0.0 `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`.

## Task Commits

1. **Task 1: Security features on and reporting (workflows, pinned-actions check, settings script)** - `b3bc9be` (ci)
2. **Task 2: Dependabot, community files, full SECURITY.md, README badges** - `01e111b` (docs)
3. **Task 3: Merge gate** - no commit (owner approval; squash merge by GitHub)

**Plan metadata:** the `docs(01-03): complete GitHub hygiene plan` commit on the same PR branch.

The task commits were first pushed as `235aff6` and `23db4bd` on top of `372f672`; after PR #2 merged they were rebased onto `e4e6359` and re-signed by keyroster-bot, so the plan's commit range is `e4e6359..HEAD`.

## Files Created/Modified

- `.github/workflows/codeql.yml` - CodeQL advanced setup, Go (manual build) and Actions
- `.github/workflows/scorecard.yml` - OpenSSF Scorecard with published results and SARIF upload
- `.github/workflows/workflow-lint.yml`, `scripts/check-pinned-actions.sh` - pinned-actions check
- `scripts/apply-security-settings.sh` - owner-run, idempotent repository security settings
- `.github/dependabot.yml` - gomod (/, /tools) and github-actions updates
- `CODE_OF_CONDUCT.md` - Contributor Covenant 2.1
- `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml` - issue forms, blank issues off, security link
- `.github/pull_request_template.md` - Conventional Commits, signing, tests, security impact, bypass line
- `SECURITY.md` - full private-reporting policy
- `README.md` - CI and Scorecard badges, pre-alpha warning kept at the top

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `scripts/apply-security-settings.sh` (not in `files_modified`)**
- **Found during:** Task 1
- **Issue:** The settings endpoints need admin rights. keyroster-bot deliberately has none, and Claude must not use the owner token for writes.
- **Fix:** an idempotent script the owner runs with his own `gh` login (same pattern as `scripts/apply-rulesets.sh`); Claude verified the result with read-only calls.
- **Files modified:** scripts/apply-security-settings.sh
- **Verification:** all settings read back as intended (table above)
- **Committed in:** `b3bc9be`

**2. [Wording] Code of Conduct enforcement contact**
- **Found during:** Task 2
- **Issue:** The Contributor Covenant template has a contact placeholder; the plan prescribes "the maintainer, @Labontese, via a private message or GitHub's report-abuse function".
- **Fix:** the sentence reads ": the maintainer, @Labontese, via a private message or GitHub's report-abuse function." GitHub has no private messages, so the effective channel is report-abuse. Flagged for the owner, who may want a different contact.
- **Files modified:** CODE_OF_CONDUCT.md
- **Committed in:** `01e111b`

---

**Total deviations:** 2 (1 Rule 3, 1 wording flag). **Impact:** no scope creep; the settings script keeps admin writes with the owner.

## Issues Encountered

- The bot cannot change admin settings, so Task 1 paused at a checkpoint until the owner ran `scripts/apply-security-settings.sh` ("klart").
- PR #2 merged while this plan waited, so the branch was rebased onto main before the planning docs were written.

## User Setup Required

None beyond the owner's already completed run of `scripts/apply-security-settings.sh`.

## Next Phase Readiness

- The owner approves PR #3 at the Task 3 merge gate; `bash scripts/merge-gate.sh p01/03-github-hygiene` then waits for the auto-merge and fast-forwards local `main`.
- Plan 01-15 makes `Analyze (go)`, `Analyze (actions)` and `pinned-actions` required and verifies a published Scorecard analysis.
- Any later plan that adds a third-party action must add it to the selected-actions allowlist (owner, via the settings script) as well as pin it.

## Self-Check: PASSED

- Files present: all 13 files of `git diff --name-only e4e6359..01e111b`, including `.github/workflows/codeql.yml`, `scripts/check-pinned-actions.sh`, `scripts/apply-security-settings.sh`, `.github/dependabot.yml`, `CODE_OF_CONDUCT.md`, `SECURITY.md`.
- Commits present: `b3bc9be`, `01e111b` on origin/p01/03-github-hygiene, both verified by GitHub.
- Checks on PR #3 head `01e111b`: all eight pass.
