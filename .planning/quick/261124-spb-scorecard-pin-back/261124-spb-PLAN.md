---
phase: quick-261124-spb
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - .github/workflows/scorecard.yml
autonomous: true
requirements: []
must_haves:
  truths:
    - "The Scorecard workflow uses ossf/scorecard-action at the v2.5.0 commit fa7117db83c52d787ae5a89f350999701505d78e again, the line main had before #121, with a two-line comment above it that says why and what to wait for."
    - "The CodeQL bump of #121 stays: .github/workflows/codeql.yml keeps codeql-action v4.39.4. .github/dependabot.yml is not changed."
    - "No product code changes. No ROADMAP or STATE change."
---

<objective>
PR #121 (Dependabot's actions group, merged as 2d61b55) moved .github/workflows/scorecard.yml from ossf/scorecard-action v2.5.0 to v2.6.0. The first Scorecard run on main after it (run 45477219825, job `scorecard`) failed in the step "Pull ghcr.io/ossf/scorecard-action:v2.6.0" with `manifest unknown`: the action runs from a container image, and the registry holds the tag's image index but neither of the manifests it lists. Upstream tracks it as ossf/scorecard-action#1752. Set the `uses:` line back to the v2.5.0 commit, whose image can be pulled, and say in a comment why and what to wait for. When Dependabot proposes v2.6.0 again, that pull request waits until the image can be pulled.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: pin scorecard-action back to v2.5.0</name>
  <files>.github/workflows/scorecard.yml</files>
  <action>Replace line 32 (the `uses: ossf/scorecard-action@23f22cd43608bae7a1f1fa2603d7314dee9538a5 # v2.6.0` line) with three lines at six spaces of indent: a two-line comment ("Held at v2.5.0: the container image of v2.6.0 cannot be pulled" and "(ossf/scorecard-action#1752). Take v2.6.0 or later once it can.") and the `uses:` line of the v2.5.0 commit, byte for byte line 32 of the file at 20983a4, the commit main was at before #121. Nothing else in the file changes. Before the commit, check that main has not moved from 2d61b55, that line 32 at the base is the old line and the file's only line that names the action, that the run of 20983a4 concluded success, and that the registry still answers 404 for both manifests of v2.6.0 and 200 for v2.5.0.</action>
  <verify><automated>git diff origin/main...HEAD -- .github/workflows/scorecard.yml && bash scripts/linux.sh 'exec 2>&1; bash scripts/check-pinned-actions.sh'</automated></verify>
</task>

</tasks>
