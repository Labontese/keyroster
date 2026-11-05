---
phase: quick-261105-ntp
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - docs/format-registry.md
  - internal/tlog/registry_test.go
  - internal/tlog/leaf.go
  - internal/wire/frame.go
  - docs/runbooks/root-ceremony.md
  - docs/runbooks/signer-install.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "docs/format-registry.md lists every leaf kind and wire message type in use, with its number and the plan that introduced it, and the reservations the code comments hold: kinds 11 to 14 for 03-09 to 03-12, request types 0x0A to 0x0C for 03-09 to 03-11."
    - "It states the allocation rule (next free number to the next plan that needs one, in merge order, claimed in the plan's own PR; Phase 4 and 5 drafts hold no numbers) and that migrations are not reserved."
    - "It lists the domain-separation tags and SSHSIG namespaces, points at classify in internal/signer/refusal.go for refusal details, states the installation-binding rule with the formats that carry the ID today, and states the key ID budget against sshd's %.500s syslog line."
    - "TestFormatRegistry fails when a leaf kind or wire type constant and the registry disagree, when an in-use row has no constant, when a reserved number gets a constant, and when a next-free sentence is stale. It is syntactic (go/parser) and adds no module."
    - "The two reproducible-build claims in the runbooks are labelled UNVERIFIED, saying what is claimed and what would verify it, because no CI job or test rebuilds and compares binaries."
    - "One keyroster-bot PR, opened without auto-merge, with every required check green. Commits are authored by the owner and committed and signed by keyroster-bot."
---

<objective>
Drafts for later phases claim the same leaf kinds and wire types. Add one registry that owns every number audit or the wire reads forever, pin it to the code with a test, and label the unexercised reproducible-build claims in two runbooks UNVERIFIED. No ROADMAP or STATE change.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: the registry and TestFormatRegistry</name>
  <files>docs/format-registry.md, internal/tlog/registry_test.go, internal/tlog/leaf.go, internal/wire/frame.go</files>
  <action>Write docs/format-registry.md from the code (leaf.go, frame.go, the tag constants, refusal.go, the installation-bound formats, keyid.go) and OpenSSH's log.c and auth.c. Add TestFormatRegistry in internal/tlog. Point the leaf.go and frame.go constant comments at the registry. Prove the test RED with mutants (a fake constant, a removed row, a renumbered row, a constant at a reserved number, a stale next-free sentence), then restore.</action>
  <verify><automated>bash scripts/linux.sh 'go test -race -count=1 -run TestFormatRegistry ./internal/tlog/ && golangci-lint run ./internal/tlog/... ./internal/wire/...'</automated></verify>
</task>

<task type="auto">
  <name>Task 2: label the reproducible-build claims UNVERIFIED</name>
  <files>docs/runbooks/root-ceremony.md, docs/runbooks/signer-install.md</files>
  <action>Check .github/workflows and scripts for a job that rebuilds and compares binaries. None does, so label both claims UNVERIFIED with what is claimed and what would verify it. grep docs/ for other reproducibility claims.</action>
  <verify><automated>go test -count=1 ./cmd/keyroster/ -run 'Runbook|Repin'</automated></verify>
</task>

<task type="auto">
  <name>Task 3: deliver</name>
  <action>Push as keyroster-bot, open the PR with scripts/gh-as-bot.sh pr create without auto-merge, write this quick task's SUMMARY, push, and wait for the required checks. Never approve or merge.</action>
  <verify><automated>bash scripts/gh-as-bot.sh pr checks docs/format-registry --required</automated></verify>
</task>

</tasks>
