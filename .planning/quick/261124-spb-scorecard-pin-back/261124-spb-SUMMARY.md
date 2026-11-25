---
phase: quick-261124-spb
plan: 01
subsystem: ci-workflows
tags: [ci, scorecard, dependabot, supply-chain]
status: complete
requires: []
provides: ["a Scorecard workflow that uses the scorecard-action release whose container image can be pulled"]
affects: []
key-files:
  modified: [.github/workflows/scorecard.yml]
decisions:
  - "ossf/scorecard-action goes back to v2.5.0 (fa7117db83c52d787ae5a89f350999701505d78e), the commit main had before #121. The CodeQL bump of #121 stays. When Dependabot proposes v2.6.0 again, that pull request waits until the image can be pulled. No Dependabot ignore rule is added."
requirements: []
metrics:
  completed: 2026-11-24
actuals:
  tasks: 1
  commits: 3
plan_head_before: 2d61b55d6e7317d4658a96447f5e759a730131ba
---

# Quick 261124-spb Plan 01: the Scorecard workflow goes back to scorecard-action v2.5.0

PR #121 (Dependabot's actions group, merged 2026-11-24T20:06:11Z as 2d61b55) moved `.github/workflows/scorecard.yml` from `ossf/scorecard-action` v2.5.0 to v2.6.0. The container image of v2.6.0 cannot be pulled, so every Scorecard run since then fails. The `uses:` line is set back to the v2.5.0 commit, with a two-line comment above it. Workflow change only; no product code.

## What failed and where

The first Scorecard run on main after #121 failed: run 45477219825, job `scorecard`, step "Pull ghcr.io/ossf/scorecard-action:v2.6.0". The four log lines:

```
##[command]/usr/bin/docker pull ghcr.io/ossf/scorecard-action:v2.6.0
v2.6.0: Pulling from ossf/scorecard-action
manifest unknown
##[error]Docker pull failed with exit code 1
```

The Scorecard workflow runs on a push to main, on Mondays at 05:29 UTC, when branch protection changes and by hand. It does not run on pull requests and is not a required check, so main is not blocked; but every run fails until the image can be pulled again, and no result is published.

## Why

- The action at the pinned commit runs from a container image (`action.yaml`: `using: "docker"`, `image: "docker://ghcr.io/ossf/scorecard-action:v2.6.0"`).
- The registry, read anonymously and read-only at 2026-11-24T20:13Z with a small script that asks for each tag's manifest and then for every manifest the tag lists:
  - `v2.6.0`: the tag answers with an image index (200); both manifests the index lists (linux/amd64 and unknown/unknown) answer 404.
  - `v2.5.0`: the tag answers with one manifest (200).
- Upstream knows: ossf/scorecard-action#1752, opened 2026-11-24T10:48Z. Its state when read at 2026-11-24T20:13Z: open, last updated 2026-11-24T19:39:26Z, 3 comments. It says the image could be pulled until about 10:40Z that day.

## The owner's decision

The pin goes back to v2.5.0, the commit main had before #121; the CodeQL bump of #121 stays; when Dependabot proposes v2.6.0 again, that pull request waits until the image can be pulled.

## The change

`.github/workflows/scorecard.yml`, line 32 at the base (one line removed, three added, six spaces of indent, LF only):

```diff
-      - uses: ossf/scorecard-action@23f22cd43608bae7a1f1fa2603d7314dee9538a5 # v2.6.0
+      # Held at v2.5.0: the container image of v2.6.0 cannot be pulled
+      # (ossf/scorecard-action#1752). Take v2.6.0 or later once it can.
+      - uses: ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e # v2.5.0
```

Nothing else in the file changes.

## Proof, and what stays unverified

No check of a pull request runs the Scorecard workflow, so no run can show the fix before the merge. What was read before the commit:

- origin/main was 2d61b55d6e7317d4658a96447f5e759a730131ba after `git fetch origin`.
- Line 32 of the file at origin/main is the old line above, byte for byte, and is the file's only line that names `ossf/scorecard-action`.
- The new `uses:` line is byte for byte line 32 of the file at 20983a4dfc0e538b82b4b728007758d413c43695, the commit main was at before #121.
- The Scorecard run 45307752359 is on 20983a4dfc0e538b82b4b728007758d413c43695 and concluded `success`.
- The v2.5.0 image answers (200), as read above.

UNVERIFIED: a green Scorecard run with this pin on the day of the change; the first run on main after the merge shows it.

## Gates

- `git diff --name-only origin/main...HEAD` lists `.github/workflows/scorecard.yml` and the quick task's PLAN (the SUMMARY joins it with the commit that adds this file).
- `git diff origin/main...HEAD -- .github/workflows/scorecard.yml`: one removed line, three added lines, the ones above. The file holds no carriage return (count 0).
- `bash scripts/linux.sh 'exec 2>&1; bash scripts/check-pinned-actions.sh'`: exit 0, "all 55 uses: references in .github/workflows are pinned to commit SHAs".
- The scan of the staged added lines: exit 0 before each of the three commits.
- Each commit carries one `gpgsig` header; author Daniel Gustafsson, committer keyroster-bot.
- `PR_TITLE='ci(deps): pin ossf/scorecard-action back to v2.5.0' bash scripts/check-pr-title.sh`: "PR title OK", exit 0.
- Not run locally: the Go tests, lint and the other jobs. The change touches one workflow line and the planning folder; the pull request's own checks run.

## Commits

- `docs(quick-261124-spb): plan the return of scorecard-action to v2.5.0` (the PLAN)
- `ci(deps): pin ossf/scorecard-action back to v2.5.0` (scorecard.yml)
- `docs(quick-261124-spb): record the pin` (this SUMMARY)

## Not changed here

- `.github/workflows/codeql.yml` keeps codeql-action v4.39.4.
- `.github/dependabot.yml` is not changed (no ignore rule).
- No product code. ROADMAP.md and STATE.md are not edited.

## Deviations from Plan

None - plan executed as written.

## Follow-up

When ossf/scorecard-action#1752 is closed and the v2.6.0 image (or a later release's) can be pulled, take that release: Dependabot's pull request for it can be merged then.
