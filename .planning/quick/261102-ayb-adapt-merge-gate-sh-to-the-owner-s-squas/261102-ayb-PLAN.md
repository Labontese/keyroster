---
phase: quick-261102-ayb
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/merge-gate.sh
  - CONTRIBUTING.md
  - .planning/phases/01-trust-core/01-SKELETON.md
  - .planning/STATE.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "push_rebased never enables auto-merge: no autoMergeRequest lookup and no `pr merge` call remain in scripts/merge-gate.sh."
    - "After approval the gate prints `approved; waiting for the owner to squash-merge #N`; the wait loop and MERGE_GATE_TIMEOUT are unchanged."
    - "The header says the script never submits a review, never merges and never enables auto-merge; approval and the squash merge belong to the owner in the GitHub UI."
    - "Exit codes 0-4, --check, the reviewed-copy check (F-WR-03) and the bot identity check are unchanged."
    - "CONTRIBUTING.md and the Delivery Protocol in 01-SKELETON.md describe the owner's squash merge, not auto-merge. Earlier PLANs and SUMMARYs are not edited."
    - "One keyroster-bot PR, opened without auto-merge, with every required check green. Its commits are authored by the owner and committed and signed by keyroster-bot."
---

<objective>
The owner now squash-merges each PR in the GitHub UI, so that he is the author of the commit on main. The bot cannot enable auto-merge with the owner as author. Adapt scripts/merge-gate.sh and the docs that state the delivery process to this change, and keep everything else in the gate unchanged.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: merge-gate.sh waits for the owner's squash merge</name>
  <files>scripts/merge-gate.sh</files>
  <action>Remove the auto-merge block from push_rebased, together with its local variable, and update the comment above it. Change the post-approval message and the timeout message to name the owner's squash merge. Rewrite the header paragraph about review and merge, and the MERGE_GATE_TIMEOUT line.</action>
  <verify><automated>bash -n scripts/merge-gate.sh && ! grep -nE 'pr merge|autoMergeRequest' scripts/merge-gate.sh</automated></verify>
</task>

<task type="auto">
  <name>Task 2: process docs</name>
  <files>CONTRIBUTING.md, .planning/phases/01-trust-core/01-SKELETON.md</files>
  <action>Replace the auto-merge steps with the owner's squash merge in the GitHub UI. Drop "re-enabled auto-merge" from the exit-3 description, and rule out `gh pr merge` in any form in the prohibitions.</action>
  <verify><automated>! grep -niE 'auto-merge (then|after)|--auto --squash|re-enabled auto-merge' CONTRIBUTING.md .planning/phases/01-trust-core/01-SKELETON.md</automated></verify>
</task>

<task type="auto">
  <name>Task 3: deliver</name>
  <action>Push as keyroster-bot, open the PR with `scripts/gh-as-bot.sh pr create` without auto-merge, write the SUMMARY and the STATE.md quick-task row, push, and wait for the required checks. Never approve or merge, and never run merge-gate.sh.</action>
  <verify><automated>test "$(bash scripts/gh-as-bot.sh pr view chore/merge-gate-owner-merge --json autoMergeRequest --jq '.autoMergeRequest == null')" = true && bash scripts/gh-as-bot.sh pr checks chore/merge-gate-owner-merge --required</automated></verify>
</task>

</tasks>
