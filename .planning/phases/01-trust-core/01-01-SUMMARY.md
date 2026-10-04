---
phase: 01-trust-core
plan: 01
subsystem: infra
tags: [github, rulesets, ci, ssh-signing, bot-identity, go-module, merge-gate]

requires: []
provides:
  - "Public repo Labontese/keyroster with signed, address-free history and green CI"
  - "Go module github.com/Labontese/keyroster (go 1.26, toolchain go1.27.1), CLI keyroster with register/dispatch registry and `version`"
  - "SHA-pinned least-privilege CI: build-test, lint, govulncheck, pr-title"
  - "Rulesets main-integrity (no bypass) and main-review (admin bypass, pull_request mode) as code plus scripts/apply-rulesets.sh"
  - "keyroster-bot identity (write collaborator, own SSH signing key) and scripts/gh-as-bot.sh"
  - "scripts/merge-gate.sh [--check] BRANCH: per-plan merge gate for every later plan"
  - "CONTRIBUTING.md: PR flow, signing setup, required checks, owner bypass policy"
affects: [01-02, 01-03, 01-04, all later phase-1 plans, release-phase-6]

actuals:
  tokens: 10771
  tasks: 4
  commits: 2
plan_head_before: 3984f3874fedc35256516c2ebd7b475c3c4415d9
plan_head_after: 216db487c92c4cdffd52cbb25541da86bf82a2c3

tech-stack:
  added: [go1.27.1, golangci-lint v2.14.0 (CI), govulncheck v1.8.0 (tools/go.mod)]
  patterns:
    - "Ruleset-as-code in .github/rulesets, applied by name with the owner token"
    - "All Claude GitHub calls through scripts/gh-as-bot.sh (GH_TOKEN unset)"
    - "One plan = one bot PR, closed by scripts/merge-gate.sh after owner approval"
    - "CLI subcommands self-register via init() + register(); main.go never changes"

key-files:
  created:
    - CONTRIBUTING.md
    - .github/rulesets/main-integrity.json
    - .github/rulesets/main-review.json
    - scripts/apply-rulesets.sh
    - scripts/gh-as-bot.sh
    - scripts/merge-gate.sh
    - go.mod
    - cmd/keyroster/commands.go
    - .github/workflows/ci.yml
  modified:
    - .planning/research/PITFALLS.md
    - .planning/phases/01-trust-core/01-RESEARCH.md

key-decisions:
  - "Required status checks keep integration_id 15368 (GitHub Actions): the API accepted it and all four checks resolved on PR #1"
  - "keyroster-bot (GitHub id 337682656) signs with ed25519 key 1218459 held only in the Windows ssh-agent; the private key file was deleted"
  - "scripts/merge-gate.sh rebases with --autostash and an explicit lease so GSD's uncommitted working files cannot block the rebase loop"

patterns-established:
  - "Merge gate exit codes: 0 merged, 1 error, 2 approval pending, 3 rebased (re-approval needed), 4 rebase conflict"
  - "Direct pushes to main are rejected for owner and bot (GH013); main changes only via signed, green, owner-approved squash PRs"

requirements-completed: [REPO-01, REPO-02, REPO-04]

coverage:
  - id: D1
    description: "Public repo with fully signed, scrubbed history and green CI on main"
    requirement: REPO-04
    verification:
      - kind: other
        ref: "gh api repos/Labontese/keyroster --jq .visibility = public; all commits verification.verified=true; git grep for CGNAT/LAN addresses over origin/main finds nothing; CI run 37197794973 success"
        status: pass
    human_judgment: false
  - id: D2
    description: "SHA-pinned, least-privilege CI with build-test, lint, govulncheck, pr-title"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "PR #1 required checks (run 37199663722): build-test, lint, govulncheck, pr-title all pass"
        status: pass
    human_judgment: false
  - id: D3
    description: "Two active rulesets make main PR-only, signed, CI-gated and reviewed; direct push rejected for owner and bot"
    requirement: REPO-01
    verification:
      - kind: other
        ref: "gh api repos/Labontese/keyroster/rules/branches/main -> deletion,non_fast_forward,pull_request,required_linear_history,required_signatures,required_status_checks; both direct pushes rejected with GH013"
        status: pass
    human_judgment: false
  - id: D4
    description: "keyroster-bot works through PRs only; its first PR (#1) is green and waits for the owner's approval at the merge gate"
    requirement: REPO-01
    verification:
      - kind: other
        ref: "bash scripts/merge-gate.sh p01/01-contributing -> exit 2 'awaiting owner approval'; bot commit 216db48 verified=true; collaborator role_name=write"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 4 blocking-human merge gate, after this SUMMARY is written"

duration: 54min
completed: 2026-10-04
status: complete
---

# Phase 1 Plan 01: Repository Bootstrap Summary

**Public Labontese/keyroster with signed, scrubbed history, SHA-pinned CI, two GitHub rulesets (integrity without bypass, review with PR-only admin bypass), a write-only keyroster-bot identity with its own SSH signing key, and a bot-driven merge gate; PR #1 is green and waits for the owner.**

## Performance

- **Duration:** 54 min (wall clock across the agent runs; excludes the owner's bot setup wait)
- **Started:** 2026-10-04T10:50:41Z
- **Completed:** 2026-10-04T11:45:01Z
- **Tasks:** 3 of 4 executed before the merge gate (Task 4 is the owner's approval)
- **Files modified:** 23 in the product tree, plus 2 scrubbed planning files

## Accomplishments

- Task 1 (tracer): Go 1.27.1 installed on Windows and WSL with SHA-256 checked against go.dev; history scrubbed of homelab and Tailscale addresses and re-signed (16 commits, all Verified on GitHub); scaffold committed; public repo created and pushed; CI run 37197794973 green.
- Task 2: the owner created `keyroster-bot` (2FA, private email) and logged it into `$HOME/.config/gh-keyroster-bot`; verified: `gh api user` answers `keyroster-bot`, scopes include `repo`, `workflow`, `admin:ssh_signing_key`.
- Task 3: bot signing key, collaborator access, repository settings, both rulesets, CONTRIBUTING.md and the merge gate; PR #1 opened by the bot with auto-merge (squash) and all required checks green.

## PR

- **PR #1** `docs: add contributing guide and repository rulesets` (https://github.com/Labontese/keyroster/pull/1), branch `p01/01-contributing`, opened by keyroster-bot, auto-merge squash enabled.
- Required checks on the implementation head (run 37199663722): `build-test` pass, `lint` pass, `govulncheck` pass, `pr-title` pass.
- `bash scripts/merge-gate.sh p01/01-contributing` before approval: exit 2, `awaiting owner approval (review: REVIEW_REQUIRED, merge state: BLOCKED)`.

## Recorded Facts

| Item | Value |
|---|---|
| Ruleset `main-integrity` | id 24454165, `bypass_actors: []`, `current_user_can_bypass: never` for the owner |
| Ruleset `main-review` | id 24454166, bypass `RepositoryRole` 5 (admin) in `pull_request` mode; owner sees `pull_requests_only` |
| `integration_id` 15368 | kept: accepted by the API and every required check resolved on PR #1 (none stuck as "Expected") |
| keyroster-bot | GitHub id 337682656, email `337682656+keyroster-bot@users.noreply.github.com`, role `write` |
| Bot signing key | GitHub signing key id 1218459, `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIBwvrP8uN8Y272Z0Ons21gcRqjHpUp5ej9hrz+ihz6+` |
| Owner signing key | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJrlH4O9nR6yb2oJ/vlh741PrlPc9Ko9YjgkXaS5GgrN` |
| Repo settings | squash only (title `PR_TITLE`, message `PR_BODY`), auto-merge on, update-branch on, delete branch on merge, no wiki, no projects |

Resolved action SHAs (ci.yml):

| Action | SHA | Tag |
|---|---|---|
| actions/checkout | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 |
| actions/setup-go | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | v7.0.0 |
| golangci/golangci-lint-action | `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a` | v9.3.0 |

### Rejected direct pushes to main (step 9)

A throwaway signed empty commit was pushed to `main` once with each identity. Both were rejected and `origin/main` stayed at `889946e`.

As keyroster-bot (clone credential helper):

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - 4 of 4 required status checks are expected.
remote: - Changes must be made through a pull request.
 ! [remote rejected] HEAD -> main (push declined due to repository rule violations)
```

As the owner (`git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push`, owner `GH_TOKEN`):

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - 4 of 4 required status checks are expected.
remote: - Changes must be made through a pull request.
 ! [remote rejected] HEAD -> main (push declined due to repository rule violations)
```

## Task Commits

1. **Task 1: End-to-end bootstrap** - `889946e` (chore)
2. **Task 2: Owner creates keyroster-bot** - no commit (human action)
3. **Task 3: Bot identity, settings, rulesets, first bot PR** - `216db48` (docs)
4. **Task 4: Merge gate** - no commit (owner approval; squash merge by GitHub)

**Plan metadata:** the `docs(01-01): complete repository bootstrap plan` commit on the same PR branch.

## Files Created/Modified

- `CONTRIBUTING.md` - PR titles, SSH signing setup (Windows note), required checks, bot PR flow, owner bypass policy
- `.github/rulesets/main-integrity.json` - integrity ruleset, no bypass actors
- `.github/rulesets/main-review.json` - review ruleset, admin bypass in pull_request mode
- `scripts/apply-rulesets.sh` - create-or-update rulesets by name (owner token)
- `scripts/gh-as-bot.sh` - gh as keyroster-bot, GH_TOKEN/GITHUB_TOKEN unset
- `scripts/merge-gate.sh` - merge gate, `--check` read-only mode
- Task 1 scaffold: `go.mod`, `tools/go.mod`, `tools/go.sum`, `cmd/keyroster/{main,commands,version,commands_test}.go`, `LICENSE`, `README.md`, `SECURITY.md`, `.github/CODEOWNERS`, `.github/workflows/ci.yml`, `.golangci.yml`, `scripts/linux.sh`, `scripts/check-pr-title.sh`, `.gitattributes`, `.gitignore`

## Decisions Made

- `integration_id` 15368 kept in the required checks (see table).
- GitHub fills two `pull_request` parameters the JSON does not set: `require_extra_approval_for_unattributed_changes: true` and `required_reviewers: []`. The JSON stays as planned; both values are GitHub's defaults and come back the same on every `apply-rulesets.sh` run.
- No `01-USER-SETUP.md` was generated for the plan's `user_setup`: the owner completed that setup in Task 2 and it is verified above.
- The local repository has no `gpg.ssh.allowedSignersFile`, so local `git log %G?` shows `N`. GitHub's verification is authoritative here; no allowed_signers file is committed in this plan.
- The bot's token scopes also include gh's defaults `gist` and `read:org` from the owner's interactive login; harmless for a write collaborator, noted for least privilege.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Robustness] merge-gate rebase loop hardened**
- **Found during:** Task 3 (step 1a)
- **Issue:** The plan's rebase step (`git switch BRANCH; git rebase --gpg-sign origin/main`) fails when the main checkout has uncommitted GSD working files (STATE.md, config.json are routinely dirty during execution), and `gh pr checks --watch` right after a force push can run before GitHub has registered the new head's checks.
- **Fix:** `git rebase --autostash --gpg-sign`; `--force-with-lease=refs/heads/BRANCH:<fetched sha>` (explicit expected value); refuse when the local branch differs from `origin/BRANCH`; wait until the PR head equals the pushed SHA and checks are registered before `--watch`; re-enable auto-merge only when it is off; explicit error returns in helpers called from `||` lists (bash suspends errexit there); `|`-separated fields because a tab would collapse an empty `reviewDecision`.
- **Files modified:** scripts/merge-gate.sh
- **Verification:** `bash -n` and the plan's grep pass; live run before approval exits 2 with the PR URL; `--check` exits 1 while the PR is open.
- **Committed in:** `216db48`

---

**Total deviations:** 1 auto-fixed (Rule 2). **Impact:** robustness of the merge gate only; exit codes, bot-only GitHub access and the no-review/no-admin prohibitions are unchanged.

## Issues Encountered

- A previous agent's read-only bot check (`gh api user`) was denied by the permission classifier; in this run it was allowed and answered `keyroster-bot`.

## User Setup Required

None remaining: the keyroster-bot account and its gh login were completed by the owner in Task 2.

## Next Phase Readiness

- The owner approves PR #1 at the Task 4 merge gate; `bash scripts/merge-gate.sh p01/01-contributing` then waits for the auto-merge and fast-forwards local `main`.
- Every later plan branches from `origin/main` as keyroster-bot and closes through the same merge gate.

## Self-Check: PASSED

- Files present: CONTRIBUTING.md, .github/rulesets/main-integrity.json, .github/rulesets/main-review.json, scripts/apply-rulesets.sh, scripts/gh-as-bot.sh, scripts/merge-gate.sh, go.mod, cmd/keyroster/commands.go, .github/workflows/ci.yml.
- Commits present: `889946e`, `216db48` (both on GitHub, both verified=true).
- Task 3 acceptance: rulesets JSON contain `"bypass_actors": []`, `required_signatures`, `"bypass_mode": "pull_request"`, no `exempt`; repo flags `true,false,false,true`; CONTRIBUTING.md has the bypass line and all four check names; `user.email` ends with `+keyroster-bot@users.noreply.github.com`; merge-gate.sh has `--check`, `--force-with-lease`, `--gpg-sign`, `gh-as-bot.sh pr view` and ends with `main "$@"; exit`; pre-approval run exits 2.
