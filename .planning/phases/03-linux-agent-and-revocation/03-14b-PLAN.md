---
phase: 03-linux-agent-and-revocation
plan: 14b
type: execute
wave: 29
depends_on: ["03-11b"]
files_modified:
  - internal/rootceremony/summary.go
  - internal/rootceremony/summary_test.go
  - internal/rootceremony/testdata/summary/genesis.golden
  - internal/rootceremony/testdata/summary/pop_hosts_machines.golden
  - internal/rootceremony/testdata/summary/pop_machines_only.golden
  - cmd/keyroster/policydiff.go
  - cmd/keyroster/policydiff_test.go
  - cmd/keyroster/root.go
  - cmd/keyroster/trust.go
  - cmd/keyroster/ceremony_golden_test.go
  - cmd/keyroster/testdata/ceremony/successor_unchanged.root_sign.golden
  - cmd/keyroster/testdata/ceremony/successor_unchanged.trust_verify.golden
  - cmd/keyroster/testdata/ceremony/successor_rp_only.root_sign.golden
  - cmd/keyroster/testdata/ceremony/successor_added_admin.root_sign.golden
  - cmd/keyroster/testdata/ceremony/successor_added_admin.trust_verify.golden
  - cmd/keyroster/testdata/ceremony/successor_every_field.root_sign.golden
  - cmd/keyroster/testdata/ceremony/successor_pop.root_sign.golden
  - cmd/keyroster/testdata/ceremony/successor_pop.trust_verify.golden
  - cmd/keyroster/testdata/ceremony/genesis_pop.root_sign.golden
  - cmd/keyroster/testdata/ceremony/genesis_pop.trust_verify.golden
  - cmd/keyroster/runbook_test.go
  - test/e2e/audit_login_test.go
  - docs/runbooks/root-ceremony.md
  - docs/runbooks/ceremony-transcript-template.md
  - docs/runbooks/host-setup.md
  - docs/runbooks/machine-identities.md
  - .planning/phases/03-linux-agent-and-revocation/03-14b-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [AGENT-03, AGENT-06]

estimate:
  tokens: 165000
  raw_tokens: 165000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-10-29 and 2026-11-05): F04 and F14 are fixed in one plan, 03-14b. Q-B3: it runs right after 03-11 and before 03-12, in the wave origin/main's 03-12 holds, and 03-12 depends on it. 03-11 was split into 03-11 and 03-11b (owner OQ-1, 2026-11-10), so 'after 03-11' is after 03-11b; at b4e6b4c 03-12 holds wave 29. 03-12, 03-13 and 03-14 then carry the duties named in their pointer sentences. Q-B1: a fixed warning line, no new flag. Q-B2: three advisory pointers in 03-15"
    - "F04. Before the confirmation prompt, `keyroster root sign --prev` prints a policy block as the last thing before the prompt, after the summary and the installation line. The block holds:
      - the policy in force (`Policy in force: vN, sha256 ...`);
      - then either `Successor policy: unchanged, every field carried over`, or the successor's version and sha256 followed by one line per policy field in policy.json order;
      - each field line reads `carried over` or `CHANGED` with the old and new values: admin_quorum; admins by name, fingerprint and key type (added, removed, renamed, reordered, and the names carried over); each CA profile by role with every changed sub-field; timelock_seconds; webauthn (rp_id marked one-way); pop (pop.hosts marked one-way).

      The first signer and every co-signer (an out-dir that already holds the bundle) see the same block"
    - "Q-B1. When the successor changes a field that `root successor-policy` never writes (admin_quorum, admins, ca_profiles, timelock_seconds), the block prints `WARNING: this successor changes <fields>, which root successor-policy never writes; sign only if each is part of the agreed change` right after its header. No flag is added"
    - "F04. `keyroster trust verify --prev` prints the same block after the summary, before the signer lines. Its exit status and acceptance are unchanged. The block's base is only the policy in force that loadPrev read, and it is printed only after the successor chain check (BuildSuccessor in root sign, VerifySuccessor in trust verify) bound that policy to the bundle in force, which `--prev-sha256` pins"
    - "F14. rootceremony.Summary, which `root sign` (genesis and --prev) and `trust verify` (with and without --prev) print, renders policy.pop after the webauthn line. It prints `pop: none (host agents and machine renewals are off)`, or `pop hosts=<bool> machines=<bool>`; when hosts is true, `pop.hosts is one-way: no later policy may turn it off (pop_hosts_removed)` follows. Its exported signature and the package's exported identifiers are unchanged"
    - "The display is pinned byte for byte by golden files through the real commands (TestCeremonyGolden: 11 subtests, 10 files) and on the test vectors (TestSummaryGolden, 3 files).
      - Both were committed RED (commit R1) before the fix (commit T1).
      - Structural invariants that do not depend on the golden files' contents back them up.
      - Reflect gates walk every type reachable from trust.Policy: TestPolicyFieldsCovered requires a diff case per field, and TestSummaryFieldsCovered requires that Summary's output changes for every field but Policy.Prev.
      - Named mutants, each compiling and each killed by a named FAIL, drop a diff line, the pop line, a one-way note or the warning line"
    - "The runbooks make the policy block, the warning line, the roots and the pop line mandatory checks for every custodian who signs a successor or a genesis, as rp_id is. They name where the agreed change comes from (the transcript's `Agreed policy change` row, recorded independently of the proposer), and that `--confirm` skips the read point. One section helper in TestRootCeremonyPolicyChecks asserts these checks in every successor-signing section that exists on main at execution time. Later plans extend that helper. The checks run in CI and are UNVERIFIED in a real ceremony. No hardware is needed by any test or step"
  artifacts:
    - path: "cmd/keyroster/policydiff.go"
      provides: "the policy block: policyChange and changedPolicyFields"
      contains: "func policyChange("
    - path: "internal/rootceremony/summary.go"
      provides: "the pop line in every ceremony summary"
      contains: "p.PoP"
    - path: "cmd/keyroster/ceremony_golden_test.go"
      provides: "golden output and structural invariants of root sign and trust verify on a fixed, seeded ceremony"
      contains: "func TestCeremonyGolden("
    - path: "cmd/keyroster/policydiff_test.go"
      provides: "the diff field gate and the single-field cases"
      contains: "func TestPolicyFieldsCovered("
    - path: "internal/rootceremony/summary_test.go"
      provides: "golden summaries on the test vectors, and the Summary field gate"
      contains: "func TestSummaryFieldsCovered("
    - path: "cmd/keyroster/runbook_test.go"
      provides: "the section helper over every successor-signing runbook section"
      contains: "func TestRootCeremonyPolicyChecks("
  key_links:
    - from: "cmd/keyroster/root.go"
      to: "cmd/keyroster/policydiff.go"
      via: "runRootSign writes the policy block as the last thing before the confirmation prompt"
      pattern: "policyChange("
    - from: "cmd/keyroster/trust.go"
      to: "cmd/keyroster/policydiff.go"
      via: "verifySuccessorBundle writes the policy block after the summary, from loadPrev's prevPolicy"
      pattern: "policyChange(prevPolicy"
    - from: "cmd/keyroster/root.go"
      to: "cmd/keyroster/trust.go"
      via: "successorBuilder hands runRootSign the prevPolicy that loadPrev authenticated, instead of dropping it"
      pattern: "loadPrev("
    - from: "internal/rootceremony/summary.go"
      to: "internal/trust/policy.go"
      via: "Summary renders Policy.PoP"
      pattern: "p.PoP"
  prohibitions:
    - statement: "Nothing changes what is signed or what any verifier accepts. This plan does not change:
        - any signed document format;
        - any rule of BuildSuccessor, checkSuccessorChain or VerifySuccessor;
        - any install-bundle or audit verify behaviour;
        - any exported identifier of internal/rootceremony;
        - any command-line flag;
        - any number in docs/format-registry.md: it allocates no leaf kind, wire type, namespace or refusal detail.

        It changes only what root sign and trust verify print, and the runbooks. No module is added and no hardware is required"
      status: resolved
      verification: test
---

<objective>
A root custodian who signs or verifies a successor bundle sees, from the tool itself, the policy in force and exactly which policy fields the successor changes, with a warning when a change could only have been written by hand. Every ceremony summary also shows the policy's proof-of-possession switches, and marks pop.hosts as one-way.

Purpose:
- **F04.** Today `root sign --prev` and `trust verify --prev` print the successor policy's values in the same form whether they changed or not. They show neither the policy in force nor a change marker. A co-signer handed a hand-written successor can therefore sign an added admin, a lowered quorum or a widened CA profile while checking only the lines the runbook names.
- **F14.** The summary never prints policy.pop. A root holder can therefore confirm the one-way pop.hosts switch without being shown it, and 03-15's owner checklist names a "pop line" that does not exist.
- **Requirements.**
  - AGENT-03 (hosts apply only policy the pinned roots signed) depends on what the M-of-N roots sign being what their holders reviewed.
  - AGENT-06 (host certificates by proof of possession) is gated by the pop.hosts switch this plan makes visible.
  - KEY-07's real offline ceremony (03-15) is the first real use.

Output:
- the policy block, with the warning line, in both commands, from one unexported helper in cmd/keyroster;
- the pop line in rootceremony.Summary;
- golden-output tests through the real commands and on the test vectors, committed RED first, with structural invariants and mutants;
- reflect gates on the diff and on Summary;
- the runbook checklists with one section helper that pins them;
- the transcript's `Agreed policy change` row;
- fixed pointer sentences in 03-12, 03-13, 03-14 and 03-15;
- the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Fix home (Daniel, 2026-10-29).** F04 and F14 are fixed together in plan 03-14b. The plan lands in the repository in the same PR as its fix, together with its ROADMAP and STATE rows, the wave shift of the plans after it, and the pointer sentences below.
- **Q-B3, the slot (Daniel, 2026-11-05): EARLY, before 03-12.**
  - 03-14b lands after 03-11 (depends_on ["03-11"]), and 03-12 depends on 03-14b. Waves shift accordingly.
  - 03-11 was split into 03-11 and 03-11b (owner OQ-1, 2026-11-10), so "after 03-11" is after 03-11b: this plan's depends_on is ["03-11b"]. At b4e6b4c 03-12 holds wave 29, so this plan takes wave 29 and 03-12 moves to wave 30.
  - This plan's reflect gates cover trust.Policy and its nested types only. Bundle fields are outside their scope.
  - 03-12, 03-13 and 03-14 each render their own new bundle fields and states in every ceremony summary, the carried and absent states included.
  - 03-12 introduces a reflect gate that Summary's output changes for every exported field of trust.Bundle and its nested types. 03-13 and 03-14 extend it.
    - The planner makes this precise without changing the decision. The gate compares Summary's output with its `Bundle SHA-256:` line removed, because that line changes for every field, so a gate that keeps it could never fail.
    - Summary prints no line for Bundle.InstallationID; root sign shows it through installationLine. 03-12 records which of two choices it makes: render it in Summary, or name a gate exception that points at installationLine and 03-14c.
  - Their new successor-signing runbook sections use this plan's checklist, and extend its section helper.
  - A later plan may change this plan's golden files only by adding its own lines, visible in the PR diff. This is the additions-only rule.
  - Each of 03-12, 03-13 and 03-14 gets one fixed pointer sentence carrying these duties, inserted by this plan's publish task.
- **Q-B1, a further confirmation (Daniel, 2026-11-05): a warning line, no new flag.**
  - When a field that `root successor-policy` never writes changes (admins, admin_quorum, ca_profiles, timelock_seconds), the block prints a fixed, prominent warning line.
  - The runbook says that `--confirm` skips the read point.
  - The checklist rule reads "answer no when any field other than the agreed change is CHANGED", and names where the agreed change comes from (an `Agreed policy change` row in the transcript, recorded independently of the proposer).
- **Q-B2, 03-15 (Daniel, 2026-11-05): three pointers.**
  - The pointers go into the Task 2 rehearsal, the runbook section at 03-15's "The section also says what the summary must show", and Task 3 instruction 2.
  - They are advisory text: 03-15's acceptance criteria are unchanged.
  - The numstat expectation is recomputed.
  - The new precondition clause this plan inserts carries `MSYS_NO_PATHCONV=1`.
- **Delivery (owner, 2026-10-29 and 2026-11-02).**
  - The PR title, every commit and the SUMMARY describe the change neutrally, as hardening, and name the two issues only as F04 and F14.
  - Pushing the branch and opening the PR before the merge is allowed; the PR's diff is public while it is open.
  - Branch commits are signed and authored as Daniel, with keyroster-bot as committer, signer and pusher. The bot opens the PR without auto-merge, and Daniel squash-merges it himself.
- **Outside review.** A reviewer outside Claude (Codex) may review this PR. Its input is the repository diff and the PR's text only, never a ceremony folder, a passphrase file, `~/.ssh` or any planning file outside the repository.
- **Security levels (owner).** Hardware is optional and never required. Every test here uses seeded software keys in an in-memory ssh-agent, and no step needs a token.
- **One-way settings stand.** pop.hosts stays one-way (owner decision 2026-10-24, trust.CheckPoPSuccessor), and so does rp_id (Phase 2 D-09). This plan shows them; it changes neither rule.

## Open owner questions

None open.

**Planner decisions (Claude's discretion), recorded with their reasons:**
- *Where the code lives.*
  - The policy block is an unexported helper in package main (cmd/keyroster/policydiff.go). internal/rootceremony's exported identifiers are pinned by TestExportedAPI and do not move.
  - The pop line goes inside rootceremony.Summary, the one place every ceremony summary comes from. Its signature stays the same.
- *Where the block is printed.*
  - In `root sign --prev`: as the last thing before the prompt, after the summary and the installation line.
  - In `trust verify --prev`: after the summary, before the signer lines.
  - A genesis signing or verification prints no block, because there is no policy in force.
- *The base.* Only the prevPolicy that loadPrev read, and only after the chain check: in root sign, prepareBundle runs BuildSuccessor in both of its branches before anything is printed; in trust verify, VerifySuccessor has returned. checkSuccessorChain requires `SHA256Hex(prevPolicy) == prev.PolicySHA256`, and loadPrev requires the bundle in force to have the `--prev-sha256` from the transcript.
- *Unchanged, and field comparison.* "Unchanged" means byte-identical. Policy documents are canonical (DecodeStrict; ParseKey accepts only the canonical key form), so two policies differ in a field exactly when its values differ. version and prev are in the header, not field lines.
- *Field granularity.* Top-level policy.json names, in policy.json order; each CA profile by role (Validate pins user, host and machine, in that order) with its changed sub-fields; webauthn's rp_id and origins; pop through root.go's existing popText. Admins are matched by key, so a key replaced under the same name shows as removed plus added; a rename, a pure reorder and the names carried over each get a line.
- *The warning line (Q-B1).* It is tied to Phase 3: `root successor-policy` writes only webauthn and pop. AUTHZ-03 (Phase 4) adds a path that writes the other fields, and must revisit the text then (Cross-plan notes).
- *Completeness is a CI gate.* TestPolicyFieldsCovered (cmd/keyroster) and TestSummaryFieldsCovered (internal/rootceremony) pin, by a recursive reflect walk, every struct type reachable from trust.Policy and its fields. They require a case per field: a diff case in the first, a Summary-output difference in the second. A runtime "unknown difference" branch was rejected: with canonical documents and every field compared, it could never run.
- *Rejected: restricting what a successor may change in VerifySuccessor.* That would change trust semantics and pre-empt AUTHZ-03.
- *Rejected: a tool-side diff of bundle fields.* That is outside F04 and F14 and outside this plan's gates (Q-B3). Instead:
  - the roots of a policy change are a checklist item, compared before signing;
  - root sign builds the CA, ops and log keys from prev;
  - 03-12, 03-13 and 03-14 render their own bundle changes (pointer duties).

  Whether the tool itself should mark a root-set change is recorded as deferred.
- *Goldens.*
  - Inputs: seeded keys, as internal/trust's helpers seed theirs, and the public CA, ops and log keys of test/vectors/bundle_genesis_v1.json.
  - The successor goldens chain to a bundle in force that the test builds and signs itself, with a fixed installation ID that the successor carries.
  - The genesis goldens replace the fresh installation ID and the bundle SHA-256 with placeholders.
  - No golden holds a path, so they run unchanged on cli-windows and cli-macos; `.gitattributes` keeps them LF.
  - An `-update-golden` test flag rewrites them. It is used only for the baseline and the no-drift check, never with a mutant applied.
- *RED first, auditable.* Commit R1 holds the new tests and the hand-edited goldens with production code unchanged. Commit T1 is the fix. R1's RED is re-run from a worktree, and T1 must not touch a golden. A golden that GREEN shows was hand-edited wrongly is corrected in its own commit and listed in the SUMMARY's `Golden corrections` section.
- *Mutant evidence.* Every mutant compiles. Its record is:
  - the unmutated `-run` passing;
  - `go vet` of the mutated package exiting 0;
  - the named `--- FAIL:` lines, with no `[build failed]` or `[setup failed]`.

  Each mutant has an exact command per package.
- *The summary's pop wording.* `pop: none (host agents and machine renewals are off)`. Both halves land before this plan:
  - Without pop.hosts, the server mints no join token and enrolls no host agent (internal/server/agent.go, hosts.go), the CLI refuses the host commands (cmd/keyroster/host.go), and the signer and audit refuse host and probe certificate issuance (internal/signer/hostissue.go, internal/audit/probeissue.go): 03-09, 03-09b and 03-10.
  - Without pop.machines, machine renewals are refused by the signer and by audit's re-derivation (internal/signer/machineissue.go, internal/audit/machineissue.go: 03-11), and by the CLI and the server (cmd/keyroster/machinerenew.go; internal/server/machine.go, `machine_pop_not_enabled`: 03-11b).
  - The wording itself is unchanged.
- *The stale runbook paragraph.* root-ceremony.md says that in Phase 2 only the RP can change. Since 03-04 `root successor-policy` also changes the PoP switches, and root sign has always signed any chained policy. The paragraph is rewritten.

## The display contract

The goldens are this contract, byte for byte.
- `<fp>` is a key's `ssh.FingerprintSHA256`, for example `SHA256:` followed by base64.
- `<type>` is a key type.
- `<sha>` is 64 lowercase hex digits of `trust.SHA256Hex` of the policy bytes.
- `<d>` is a duration rendered as rootceremony's `seconds` renders it: a Go duration string, or `<n>s` above the duration bound.
- `<list>` is space-joined values in brackets, `[]` when empty.
- Two spaces indent a field line, four a sub-line.

**Unchanged policy** (the two documents are byte-identical), exactly two lines:

```
Policy in force: v<N>, sha256 <sha>
Successor policy: unchanged, every field carried over
```

**Changed policy.** The header, then the warning line only when the rule below says so, then the eight field lines in this order, each with its sub-lines:

```
Policy in force: v<N>, sha256 <sha>
Successor policy: v<N+1>, sha256 <sha>, chained to the policy in force; against it:
WARNING: this successor changes <fields>, which root successor-policy never writes; sign only if each is part of the agreed change
  admin_quorum: ...
  admins: ...
  ca_profiles user: ...
  ca_profiles host: ...
  ca_profiles machine: ...
  timelock_seconds: ...
  webauthn: ...
  pop: ...
```

Rules for each line, in the same order:
- **The warning line.** Printed when changedPolicyFields holds any of admin_quorum, admins, ca_profiles or timelock_seconds. `<fields>` is those names, in policy.json order, joined by `, `.
- **admin_quorum:** `  admin_quorum: carried over`, or `  admin_quorum: CHANGED <old> -> <new>`.
- **admins:** `  admins: carried over`, or `  admins: CHANGED`, followed by these sub-lines, in this order:
  - `    - admin <name> <fp> <type>` for each key only in the policy in force, in its order;
  - `    + admin <name> <fp> <type>` for each key only in the successor, in its order;
  - `    ~ admin <fp> <type> renamed <old> -> <new>` for each key in both under another name, in successor order;
  - `    order: <names> -> <names>` when the keys in both are in another order (the old names in the old order, then the new names in the new order);
  - `    carried over: <names>`, the successor's names of keys in both under the same name, in successor order, or `(none)`.
- **ca_profiles <role>** (user, host, machine): `  ca_profiles <role>: carried over`, or `  ca_profiles <role>: CHANGED`, followed by one sub-line per changed sub-field, in this order:
  - `    max_ttl_seconds: <old> (<d>) -> <new> (<d>)`
  - `    default_extensions: <list> -> <list>`
  - `    allowed_extensions: <list> -> <list>`
  - `    allowed_critical_options: <list> -> <list>`
- **timelock_seconds:** `  timelock_seconds: carried over`, or `  timelock_seconds: CHANGED <old> (<d>) -> <new> (<d>)`.
- **webauthn:** `  webauthn: carried over`, or `  webauthn: CHANGED`. ` (rp_id is one-way)` is appended when rp_id differs, none and some included. Then, only for what differs:
  - `    rp_id: <old or (none)> -> <new or (none)>`
  - `    origins: <list or (none)> -> <list or (none)>`
- **pop:** `  pop: carried over`, or `  pop: CHANGED <popText(old)> -> <popText(new)>`, where popText is `(none)` or `hosts=<bool> machines=<bool>`. When the successor sets hosts and the policy in force does not, this sub-line follows:
  - `    pop.hosts is one-way: no later policy may turn it off (pop_hosts_removed)`

**The summary's pop lines** (rootceremony.Summary, right after the webauthn line and before the timelock line). Either:

```
  pop: none (host agents and machine renewals are off)
```

or:

```
  pop hosts=<bool> machines=<bool>
    pop.hosts is one-way: no later policy may turn it off (pop_hosts_removed)
```

where the second line is printed only when hosts is true.

**Worked example, the F04 shape.** The policy in force is test/vectors/policy_genesis_v1.json: version 1, sha256 `d18c6893440b8becc2e13548fe04dfeba6ed0d7d2e7a90e9b24b29ff6f654c63`, admin alice. The successor adds the RP keyroster.example.org, adds admin mallory, and raises the user profile's max TTL to 2592000. The block reads:

```
Policy in force: v1, sha256 d18c6893440b8becc2e13548fe04dfeba6ed0d7d2e7a90e9b24b29ff6f654c63
Successor policy: v2, sha256 <sha>, chained to the policy in force; against it:
WARNING: this successor changes admins, ca_profiles, which root successor-policy never writes; sign only if each is part of the agreed change
  admin_quorum: carried over
  admins: CHANGED
    + admin mallory <fp> ssh-ed25519
    carried over: alice
  ca_profiles user: CHANGED
    max_ttl_seconds: 43200 (12h0m0s) -> 2592000 (720h0m0s)
  ca_profiles host: carried over
  ca_profiles machine: carried over
  timelock_seconds: carried over
  webauthn: CHANGED (rp_id is one-way)
    rp_id: (none) -> keyroster.example.org
    origins: (none) -> [https://keyroster.example.org]
  pop: carried over
```

## Budget

About 15 code and test files (5 of them new), 13 golden files and four runbooks.
- Task 1 touches 5 code files (2 of them new) and writes the 13 goldens. It stays one task because the tracer wires both commands and the summary end to end, and the goldens are generated output, edited only by the contract's added lines.
- Task 2 adds one test file and edits the e2e test.
- Task 3 edits four runbooks and runbook_test.go, and makes the publish edits in seven planning files.

About 165k tokens, at low confidence (the estimate calibration has no samples yet, so the projection is not scaled). It covers two sessions:
- the plan itself, about 182 KB or roughly 45k tokens, read once per session, so about 90k;
- about 48 KB read through the function-scoped read_first lists, roughly 14k tokens;
- about 32k written, most of it tests and goldens;
- about 29k of test, mutant, gate and e2e-gate output.

That is over the 100k smart-zone budget, and each session alone comes close to it. Recent plans of this phase ran well over their estimates: 03-11 about 5x, 03-11b about 2x. If this plan runs like them, the real cost is about 330k to 800k tokens. Task 1, with its 13 goldens and 18 mutants, is the heavy part. Budget one continuation after Task 1: the executor hands over through the SUMMARY draft (R1, T1, the RED lines, the test-time base, the mutant records so far), and the continuation starts at Task 2. If the continuation's context is about half used before Task 3 starts, it may hand over once more after Task 2, the same way. The task count and the files are unchanged.

**Why the plan is not split.** The one clean seam is between the code (Tasks 1 and 2: the policy block, the pop line, the goldens and the gates) and Task 3 (the runbook checklists and the publish edits). A split there would cost:
- a second PR through the owner merge gate, with a second e2e run and a second pre-merge review;
- a code PR that ships the block without the runbook checks that tell a custodian how to read it, while the checklists quote the block's lines and goldens that Task 1 produces;
- a second publish and wave shift: a new plan in the next wave would move 03-12 to 03-16 again, and with them the brackets of 03-14c and 03-14d.

The continuation gives the same fresh context at the Task 1 boundary without those costs.

**Test time (Q-09-3, owner decision; it replaces the fixed 480 s caps of 03-08k and 03-08i).**
- **Timeout.** Every go test command of this plan carries `-timeout 15m`, and every mutant command `-timeout 5m`. CI's build-test already runs with `-timeout 15m`.
- **Base.** Task 1 measures a quiet base on unchanged origin/main, with no other heavy job on the machine: `go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/rootceremony/` through `bash scripts/linux.sh`. It records one SUMMARY line, `test-time base: cmd=<s> rootceremony=<s> at=<epoch seconds>`, each time read from that package's `ok` line in seconds without the trailing `s`. There is exactly one such line.
- **The rule.** Task 3's delta gate runs the same command and stops if either package adds more than 90 s to its base. If the base is more than 24 h (86400 s) old, re-measure it on origin/main in a detached worktree outside the repository, immediately before; a re-measure REPLACES the base line in place, never appends a second one. Stop and report only if the fresh delta is still above 90 s.
- **Another session.** If the delta gate runs in a different session or WSL boot from the one that measured the base, re-measure the base first on origin/main in a detached worktree outside the repository, as 03-11b's continuation did, and replace the line in place. The continuation after Task 1 is a new session, so in practice Task 3 always re-measures. The 24 h age check still applies. The base line keeps its format: the delta gate reads `at=` at the end of the line, so no session or boot field is added.
- **The whole module.** `go test -race -count=1 -timeout 15m ./...` in the full gate is pass or fail only, and is never compared with a base. internal/agent/apply and internal/signer already read about 400 s under load on main, in packages this plan does not touch, so no per-package cap is applied to them.
- **Expected.** The new tests use seeded keys in an in-memory agent (no scrypt run) and add a few seconds to cmd/keyroster, which takes about 226 to 265 s under -race on main. internal/rootceremony gains three goldens and one reflect walk. A reading near the 15-minute timeout is a stop-and-report, not a reason to raise it.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-11b-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names. Since PR #79, its steps 2, 3 and 5 carry the owner's authorship and merge rules of 2026-11-02, which the points below restate. The one override is merge-gate.sh's plain form, as in 03-08f and 03-08i.
- **Branch.** Create `p03/14b-ceremony-display` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 3 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Authorship (01-SKELETON step 2).** Every `git commit` of this plan is signed (`-S`) and authored as Daniel, with keyroster-bot as committer, SSH signer and pusher. Put the two variables on the same command line as the commit, because shell state does not persist between commands: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit -S ...`. Push with `env -u GITHUB_TOKEN -u GH_TOKEN git push`.
- **No auto-merge (01-SKELETON steps 3 and 5).** The bot opens the PR through scripts/gh-as-bot.sh and never enables auto-merge or waits for it. Daniel reviews, approves and squash-merges the PR in the GitHub web UI, and replies "merged".
- **merge-gate.sh.** Before the merge it runs only as `--check`, which is read-only. Its plain form may rebase and force-push (exit 3), and this plan rebases by hand, so the plain form runs only after Daniel has merged (Task 4).
- **Shells.**
  - The go test, gate and mutant commands run through `bash scripts/linux.sh '...'`, which runs in the WSL path of the current directory. Its single-quoted argument reaches WSL's login shell unexpanded (wsl.exe --exec), so `$(...)` and `$VAR` inside it expand in WSL.
  - The git checks run in Git Bash. Every `git show` or `git cat-file` of an `origin/main:path` or `FETCH_HEAD:path` argument is prefixed with `MSYS_NO_PATHCONV=1`, because Git Bash would otherwise rewrite the path (or run it in PowerShell).
  - scripts/gh-as-bot.sh and scripts/merge-gate.sh always run in Git Bash without MSYS_NO_PATHCONV.
- **Wording.** Conventional Commits (`fix(root): ...`, `test(root): ...`, `docs(runbooks): ...`, `docs(03-14b): ...`) with neutral wording. The two issues are named only as F04 and F14. No attribution lines, no IP addresses, no real host names. The SUMMARY records local evidence by test or golden name and result only, never a temporary directory's path.
- **Code comments** cite `(03-14b)`.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md`, a draft from Task 1 on.
  - It records R1, T1 and T2: the RED commit, the fix commit and Task 2's last commit.
  - It has a `## Golden corrections` section, which reads `none` unless Task 1 records one.
  - The final docs commit is `docs(03-14b): complete ceremony-display plan`.

**What lands before this plan (Q-B3).** On main at b4e6b4c: 03-09, 03-09b, 03-10, 03-10b, 03-10c, 03-10d, 03-11 and 03-11b, plus three non-plan PRs: #87 (the format registry, docs/format-registry.md), #94 (a dependency bump) and #96 (a quick task). Among their changes:
- docs/runbooks/host-setup.md and docs/runbooks/machine-identities.md grew; revoke.md, signer-install.md and enroll-user.md changed;
- package main gained test files (audit_test.go, hosttrust_runbook_test.go, knownhosts_test.go, knownhosts_unix_test.go, machinekey_test.go, machinerenew_test.go, probeaccount_runbook_test.go), and the dirpipe, hoststatus, login, machine, recover and revoke tests grew.

None of them changed root.go, trust.go, internal/rootceremony, internal/trust, ceremony-transcript-template.md, runbook_test.go, audit_login_test.go or the test vectors. #87 changed root-ceremony.md in one hunk only: step 2 of "## 1. Prepare the binary and the ceremony machine" (the reproducible-build UNVERIFIED label), outside every section, marker and substring this plan edits or pins. That hunk was reconciled on 2026-11-10 and changes nothing here. Task 1's precondition re-checks the frozen files against b4e6b4c, and finds this plan's two host-side anchors by text, not by line.

**What lands after this plan.** 03-12, 03-13 and 03-14 change runRootSign, successorBuilder and rootceremony.Summary for CA transitions, log-key and ops-key rotation, and the break-glass field. They extend this plan's goldens, invariants and section helper by additions only. Their pointer sentences, inserted by Task 3, carry those duties.

**What this plan builds on:**
- 03-04: root successor-policy's `--pop-hosts` and `--pop-machines`, popText, trust.CheckPoPSuccessor and the policy_pop_v1 vector;
- 02-04 and 02-13: the WebAuthn RP successor, and the runbook's policy-change section;
- 01-07 to 01-20: root sign, trust verify, `--prev` with `--prev-sha256` (loadPrev), BuildSuccessor and VerifySuccessor (checkSuccessorChain), and the test vectors with their seeded keys.

**The code this plan changes, as read on main at f7eb018 and re-read at b4e6b4c** (unchanged by 03-09 to 03-11b; Task 1's precondition checks it against b4e6b4c):
- **cmd/keyroster/root.go:**
  - runRootSign reads and parses `--policy` (pol), calls successorBuilder for `--prev`, checks admins against roots, and runs prepareBundle, which calls the builder, so BuildSuccessor's chain check has run in both of its branches.
  - It then prints `successorHeader(prev, prevBundle, b)` for a successor, then `rootceremony.Summary(b, pol)` and `installationLine(prev, b)`.
  - It reads the typed prefix, or takes `--confirm` and skips the prompt, and compares the prefix with the bundle hash.
  - successorBuilder receives prevPolicy from loadPrev, passes it only to the BuildSuccessor closure, and returns prev, prevBundle and the builder.
  - popText renders a PoPPolicy.
- **cmd/keyroster/trust.go:**
  - loadPrev returns prev, prevBundle and prevPolicy, after the `--prev-sha256` and self-signed checks.
  - verifySuccessorBundle calls VerifySuccessor and MatchPins, then prints the `Successor of trust bundle` line, `rootceremony.Summary(next, p)`, the signer lines and the OK line.
- **internal/rootceremony/summary.go:** the policy block prints the version, admin quorum, admins, CA profiles, webauthn and timelock. It has no case for PoP, and no line for the policy's prev.
- **internal/trust/policy.go:**
  - Policy {Version, Prev, AdminQuorum, Admins, CAProfiles, TimelockSeconds, WebAuthn, PoP};
  - AdminKey {Name, Key};
  - CAProfile {Role, MaxTTLSeconds, DefaultExtensions, AllowedExtensions, AllowedCriticalOptions};
  - WebAuthnRP {RPID, Origins};
  - PoPPolicy {Hosts, Machines}.

  Validate requires exactly the profiles user, host and machine, in that order, and requires every origin to be https://rp_id with an optional port.
- **internal/trust/verify.go** (read only; this plan changes nothing in internal/trust): checkSuccessorChain binds prevPolicy to prev.PolicySHA256. It accepts a changed policy at version + 1 with the chained prev, provided CheckPoPSuccessor passes and no admin is a root.
- **internal/signer/trust.go** (read only): checkBundleKeys runs after both the genesis and the successor branch of installation, and at start, so install-bundle refuses CA, ops or log keys the signer does not hold.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a co-signer runs root sign --prev on a successor that adds an admin and widens a CA profile → the policy block names the policy in force, warns about the hand-written change and marks every CHANGED field as the last thing before the prompt → trust verify --prev prints the same block → every summary, genesis included, shows the pop line", committed RED first and then fixed</name>
  <reversibility rating="reversible">Only command output and test files change. No signed document, verifier rule, flag or stored format changes; reverting restores today's output.</reversibility>
  <precondition>All six checks hold:
    - `git fetch origin` succeeds, and `P=.planning/phases/03-linux-agent-and-revocation && MSYS_NO_PATHCONV=1 git cat-file -e "origin/main:$P/03-11b-SUMMARY.md" && MSYS_NO_PATHCONV=1 git show "origin/main:$P/03-12-PLAN.md" | grep -qx 'wave: 29' && W28=$(for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do if MSYS_NO_PATHCONV=1 git show "origin/main:$f" | grep -qx 'wave: 28'; then basename "$f"; fi; done) && test "$W28" = 03-11b-PLAN.md` exits 0. This is the stop guard: this plan's dependency, 03-11b, has its SUMMARY on main; origin/main's 03-12 holds wave 29, the slot this plan takes; and 03-11b is the only plan at wave 28. Otherwise main moved since the reconcile of 2026-11-10 (another plan was slotted in, or 03-12 moved): stop and report for a re-reconcile. Never re-slot this plan silently.
    - `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:cmd/keyroster/policydiff.go` fails, and `! git grep -q 'Policy in force' origin/main -- cmd/keyroster` exits 0: this plan is not applied yet.
    - `git diff --quiet b4e6b4c origin/main -- cmd/keyroster/root.go cmd/keyroster/trust.go cmd/keyroster/runbook_test.go internal/rootceremony internal/trust/policy.go internal/trust/verify.go internal/trust/successor.go docs/runbooks/root-ceremony.md docs/runbooks/ceremony-transcript-template.md test/e2e/audit_login_test.go test/vectors/policy_genesis_v1.json test/vectors/policy_pop_v1.json test/vectors/bundle_genesis_v1.json` exits 0. Between f7eb018 and b4e6b4c only root-ceremony.md changed among these files, in #87's one hunk outside this plan's sections, which was reconciled. A difference since b4e6b4c is unplanned: stop and report which file changed.
    - `H=$(MSYS_NO_PATHCONV=1 git show origin/main:docs/runbooks/host-setup.md) && printf '%s\n' "$H" | grep -q '^## Registering a host in the directory' && printf '%s\n' "$H" | grep -qF 'Host agents need `pop.hosts`'` exits 0, and `M=$(MSYS_NO_PATHCONV=1 git show origin/main:docs/runbooks/machine-identities.md) && printf '%s\n' "$M" | grep -q '^## Renewal needs pop.machines'` exits 0. 03-09 to 03-11b edited these two runbooks, and Task 3 finds its places there by these anchors. If either is gone, stop and report.
    - `git grep -nE 'func (seedKey|checkGolden|checkInvariants|successorSigningSections|display|signWith|verifyPrev|sectionWindow|policyChange|changedPolicyFields)\(|updateGolden|update-golden|func Test(CeremonyGolden|Policy[A-Za-z]*|SummaryGolden|SummaryFieldsCovered|RootCeremonyPolicyChecks|SectionWindowRefusals)\(' origin/main -- cmd/keyroster internal/rootceremony` prints nothing (it printed nothing at b4e6b4c). Otherwise, rename this plan's helpers or tests to avoid the collision with the tests 03-09 to 03-11b added, and record the new names. A collision the grep misses fails R1's build, which the RED check refuses; the response is the same.
    - `awk '/^## Open owner questions/{f=1;next} f && NF{print; exit}' .planning/phases/03-linux-agent-and-revocation/03-14b-PLAN.md | grep -qx 'None open.'` exits 0.
  </precondition>
  <files>internal/rootceremony/summary.go, internal/rootceremony/summary_test.go, internal/rootceremony/testdata/summary/*.golden (3), cmd/keyroster/policydiff.go, cmd/keyroster/root.go, cmd/keyroster/trust.go, cmd/keyroster/ceremony_golden_test.go, cmd/keyroster/testdata/ceremony/*.golden (10)</files>
  <read_first>
    Read functions, not files. Find each with `grep -n` and read only that range.
    - cmd/keyroster/root.go: `func runRootSign(` from the policy read to the confirmation compare; `func successorBuilder(`; `func successorHeader(`; `func installationLine(`; `func popText(` (about 9 KB).
    - cmd/keyroster/trust.go: `func loadPrev(` and `func verifySuccessorBundle(` (about 3 KB).
    - internal/rootceremony/summary.go: the whole file (about 3 KB).
    - internal/trust/policy.go: the five types, `func CheckPoPSuccessor(` and `func (p *Policy) Validate(` (about 5 KB).
    - internal/trust/verify.go: `func checkSuccessorChain(` (about 3 KB). Read only.
    - internal/trust/helpers_test.go: `edKey` and the seed constants (about 1 KB), for the seeding pattern.
    - internal/rootceremony/sign_test.go: `readVector` and `TestSummaryShowsWebAuthnRP` (about 1.5 KB).
    - internal/signer/statuswriters_test.go: the reflect field-list check on wire.StatusResponse (about 1 KB), for the pattern.
    - cmd/keyroster/root_test.go: `useKeyring`, `run`, `writeTestFile`, `typeHashPrefix` with `hashPrefixReader`, and `setCeremonyNow` (about 3 KB).
    - cmd/keyroster/trust_test.go: `readTestFile`, `fileSHA256`, and the `signed` closure in `TestTrustVerifySuccessor` (sshsig.Sign plus appendSignature) (about 2 KB).
    - test/vectors/policy_genesis_v1.json, policy_pop_v1.json, and bundle_genesis_v1.json's `cas`, `ops_key` and `log` (about 3 KB).
  </read_first>
  <action>
Create branch `p03/14b-ceremony-display` from origin/main. Place this plan file untracked in the phase directory; Task 3 commits it.

**The test-time base (Q-09-3, Budget).** Before any edit, while the tree still equals origin/main and no other heavy job runs, run `bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/rootceremony/'`. Create the SUMMARY draft with one line `test-time base: cmd=<s> rootceremony=<s> at=<epoch seconds>`, the two times read from the `ok` lines without the trailing `s`, and `at=` from `date +%s`. A later re-measure uses a detached worktree of origin/main outside the repository and replaces this line in place.

**The fixture (cmd/keyroster/ceremony_golden_test.go, no build tag, `(03-14b)`).** Every value is fixed, so every byte of the display is fixed.
- **Keys.** A helper returns the Ed25519 key with seed byte n repeated, as internal/trust's edKey does:
  - root A: seed 1, custody software;
  - root B: seed 2, custody piv;
  - admin alice: seed 20, the vector's admin;
  - mallory: seed 21;
  - bob: seed 22;
  - carol is alice's key under a new name.
- **ca-pubkeys.json.** Built from bundle_genesis_v1.json's user, host and machine CA entries, ops key and log key (role, key, alg, custody), in trust.CAPubKeyRoles order, as trust.CAPubKeys canonical bytes. Only public keys are needed.
- **roots.pub.** Roots A and B, each as `trust.FormatKey` plus ` custody=<label>`. useKeyring serves both private keys.
- **The bundle in force (`prev/`).**
  - prev/bundle.json is a trust.Bundle literal, validated and written canonically:
    - version 1, GenesisPrev, issued_at `2026-10-05T00:00:00Z`;
    - roots A and B at threshold 2;
    - the vector's CAs, ops key and log entry;
    - policy_sha256 of policy_genesis_v1.json;
    - installation ID `00112233445566778899aabbccddeeff`.
  - `prev/policy.json` is policy_genesis_v1.json, byte for byte.
  - Both documents are signed by A and B (sshsig.Sign under their namespaces, appendSignature into the `.sigs` files). prevSHA is the bundle's SHA-256.
- **Successor policies.** A helper writes, from policy_genesis_v1.json, version 2 with prev its SHA-256, edited by a function, canonical. setCeremonyNow is `2026-10-06T00:00:00Z` for successors and `2026-10-05T00:00:00Z` for the genesis case.
- **Command helpers.**
  - `display` runs `root sign --prev prev --prev-sha256 <prevSHA> --roots roots.pub --threshold 2 --policy P --out-dir O --agent-key <root> --confirm 00000000`. It requires exit 1 with `nothing was signed` on stderr, and returns stdout.
  - `signWith` runs the same command with the bundle's real prefix (`--confirm` with the prefix of `O/bundle.json`), and requires exit 0.
  - `verifyPrev` runs `trust verify --prev prev --prev-sha256 <prevSHA> --pin A --pin B --threshold 2 --bundle O/bundle.json --policy O/policy.json`, requires exit 0, and returns stdout.
- **checkGolden(t, name, got).** It reads `testdata/ceremony/<name>.golden` and compares bytes. On a mismatch it reports with t.Errorf, starting with `golden <name>.golden: first difference at line <n>`, then the wanted and got lines and the whole output. With `-update-golden` (a test flag defined in this file, documented as for a deliberate output change only, never with a mutant applied) it writes the file instead.
- **checkInvariants(t, kind, got).** It does not read any golden. Every leaf calls it, and then always calls checkGolden. It reports each broken rule with t.Errorf, never t.Fatal, and each message starts with `invariant:`. So other assertions still run: on today's code the baseline run still writes all 13 goldens while the leaves fail on the missing pop line, which is expected and recorded. Its rules:
  - every output has exactly one summary pop line (a line that starts `  pop: none (` or `  pop hosts=`). It lies in the window from the output's first line that starts `  webauthn` to its first line that starts `  timelock `. The block's own `  webauthn:` field line comes later, so "first" is what keeps the window inside the summary;
  - a successor root_sign output has exactly one `Policy in force:` line, after the `installation id:` line, and every line from it to the end is a block line (the block is the last thing before the prompt). A block line is a line that starts `Policy in force:`, `Successor policy:` or `WARNING:`, or that starts with two spaces;
  - a successor trust_verify output has exactly one `Policy in force:` line, after the `Bundle SHA-256:` line and before the first `signed by ` line;
  - a genesis output has none.

**TestCeremonyGolden.** Its subtests are not parallel. Each group's parent body runs every command of the group in order and keeps the outputs, and its leaves only assert, so each leaf also runs alone under its own `-run`.
- **`successor_unchanged`.** The policy is `prev/policy.json`.
  - Steps: A's display, then A signs, then B signs, then verifyPrev.
  - Leaves: `root_sign` (A's display) and `trust_verify`.
- **`successor_rp_only`.** The RP keyroster.example.org with origins [https://keyroster.example.org], exactly what `root successor-policy --webauthn-rp-id keyroster.example.org` writes.
  - Step: A's display.
  - Leaf: `root_sign`.
- **`successor_added_admin`** (F04's shape). The same RP, plus admin mallory appended, plus the user profile's max_ttl_seconds 2592000.
  - Steps: A's display; A signs; B's display in the out-dir that now holds the bundle and A's signatures (prepareBundle's existing-bundle branch); B signs; verifyPrev.
  - Leaves: `root_sign`, `cosigner` and `trust_verify`. `cosigner` compares B's display with the same golden as `root_sign` and never writes.
- **`successor_every_field`.** Every top-level field changes:
  - admin_quorum 2;
  - admins carol, mallory and bob;
  - user max_ttl_seconds 3600, allowed_extensions [permit-agent-forwarding] and allowed_critical_options [force-command];
  - host max_ttl_seconds 604800;
  - machine default_extensions [];
  - timelock_seconds 3600;
  - the RP as above;
  - pop hosts=true machines=false.

  Step: A's display. Leaf: `root_sign`.
- **`successor_pop`** (03-15's shape). pop hosts=true machines=true, every other field unchanged.
  - Steps: A's display, A signs, B signs, verifyPrev.
  - Leaves: `root_sign` and `trust_verify`.
- **`genesis_pop`.** The genesis policy is policy_genesis_v1.json plus pop hosts=true machines=false, version 1, canonical, with roots A and B at threshold 2 and the fixture's ca-pubkeys.json.
  - Steps: A's genesis display (`--confirm 00000000`), A signs, B signs, then `trust verify --pin A --pin B --threshold 2`.
  - Both outputs are normalised: the bundle's installation ID becomes `<INSTALLATION_ID>` and its SHA-256 `<BUNDLE_SHA256>`, both read from the out-dir's bundle.json.
  - Leaves: `root_sign` and `trust_verify`.

The golden of each leaf is `<group>.<leaf>.golden`, except `cosigner`, which uses `successor_added_admin.root_sign.golden`.

**internal/rootceremony/summary_test.go (`(03-14b)`).** It has its own `-update-golden` flag, and its own checkGolden with the same `golden <name>.golden: first difference at line <n>` message.
- **TestSummaryGolden**, with goldens in `testdata/summary/`:
  - `genesis`: Summary of bundle_genesis_v1 and policy_genesis_v1;
  - `pop_hosts_machines`: Summary of bundle_genesis_v1 and policy_pop_v1;
  - `pop_machines_only`: Summary of bundle_genesis_v1 and policy_genesis_v1 with pop hosts=false machines=true.
- **TestSummaryFieldsCovered.**
  - A recursive reflect walk from trust.Policy unwraps pointer, slice, array and map types, and requires every struct type it reaches to have an entry in a pinned map. Each entry is the type's fields as `Name Type json-tag` strings, equal to these literal lists:
    - Policy: `Version uint64 version`, `Prev string prev`, `AdminQuorum uint32 admin_quorum`, `Admins []trust.AdminKey admins`, `CAProfiles []trust.CAProfile ca_profiles`, `TimelockSeconds uint64 timelock_seconds`, `WebAuthn *trust.WebAuthnRP webauthn,omitempty`, `PoP *trust.PoPPolicy pop,omitempty`;
    - AdminKey: `Name string name`, `Key string key`;
    - CAProfile: `Role string role`, `MaxTTLSeconds uint64 max_ttl_seconds`, `DefaultExtensions []string default_extensions`, `AllowedExtensions []string allowed_extensions`, `AllowedCriticalOptions []string allowed_critical_options`;
    - WebAuthnRP: `RPID string rp_id`, `Origins []string origins`;
    - PoPPolicy: `Hosts bool hosts`, `Machines bool machines`.
  - The base is policy_genesis_v1 with the RP keyroster.example.org and pop hosts=false machines=true, so every nested type is non-nil.
  - For every field except Policy.Prev (Summary prints no policy prev), one subtest named `<Type>.<Field>` mutates one copy of the base in that field and requires that Summary's output differs. Summary does not validate, so a mutant need not be valid.
  - The test fails, naming the field or type:
    - when a field has no mutation entry;
    - when the walk meets an unpinned type (the message starts `unpinned policy type`);
    - when the walk never reaches an entry of the pinned map (the message starts `pinned type not reached`).

    The message says that a new policy field needs a Summary line, a policydiff.go line and a TestPolicyChangeFields case.

**RED first: commit R1, with production code unchanged.**
1. **Baseline.** Run `bash scripts/linux.sh 'go test -count=1 -timeout 15m -run "^TestCeremonyGolden$" ./cmd/keyroster/ -args -update-golden; go test -count=1 -timeout 15m -run "^TestSummaryGolden$" ./internal/rootceremony/ -args -update-golden'`. It writes the 13 goldens from today's output. The ceremony run exits non-zero, because checkInvariants reports the missing pop line; that is expected, and it does not stop the writes. Keep a copy outside the repository.
2. **Edit each golden by hand** to insert exactly the lines of "The display contract":
   - the summary's pop line or lines, after the `webauthn` line;
   - in every successor root_sign golden, the policy block after the installation line;
   - in every successor trust_verify golden, the block after the summary, before the first signer line.

   Read the fingerprints from the summary's admin lines. The policy in force's SHA-256 is policy_genesis_v1.json's (`sha256sum`). Each successor's SHA-256 is its summary's `policy sha256:` value.
3. **The additions-only check.** For every golden, `diff <baseline> <golden>` prints no line that starts with `<`. Record it in the SUMMARY by golden name and result only (for example `pop_hosts_machines: additions only`), never with the baseline's path or the diff command line.
4. **Commit R1** (`test(root): pin the ceremony display before the fix (F04, F14)`): the two test files and the 13 goldens only. Record R1 in the SUMMARY.
5. **The RED, from a worktree of R1.** This is the second verify command below. Every TestCeremonyGolden leaf (11) and every TestSummaryGolden case (3) ends in a named `--- FAIL`. TestSummaryFieldsCovered fails exactly its three PoP subtests (`Policy.PoP`, `PoPPolicy.Hosts`, `PoPPolicy.Machines`).
   - The log also holds a `golden <name>.golden: first difference` message for each of the 13 goldens. That shows the hand-edited goldens differ from today's output, independently of checkInvariants, which fails every ceremony leaf on today's missing pop line.
   - Record each line.
   - The command string passed to linux.sh runs no git: in a worktree, the `.git` file holds a Windows path that git inside WSL cannot follow.

**internal/rootceremony/summary.go (F14, `(03-14b)`).** In Summary's policy block, right after the webauthn line and before the timelock line, render p.PoP as the contract says. Extend the doc comment: Summary also renders the proof-of-possession switches, and pop.hosts is one-way, like the WebAuthn RP. Change no other line and no signature.

**cmd/keyroster/policydiff.go (new, F04 and Q-B1, `(03-14b)`).**
- `func changedPolicyFields(prev, next *trust.Policy) []string` returns the top-level policy.json names whose values differ, in policy.json order, from admin_quorum, admins, ca_profiles, timelock_seconds, webauthn and pop. version and prev are not listed.
- `func policyChange(prevPolicy, policy []byte) (string, error)` parses both with trust.ParsePolicy, and returns an error naming which document failed to parse. Otherwise it renders the block: the unchanged form when the bytes are equal; otherwise the changed form, with the warning line by the contract's rule.
  - Fingerprints come from trust.ParseKey and ssh.FingerprintSHA256, as successorHeader does.
  - Durations come from a local helper that renders as rootceremony's seconds does; it is duplicated because seconds is unexported.
- Its doc comments say:
  - the base must be the policy in force after the successor chain check has bound it to the bundle in force;
  - every rendered value has passed trust.Policy.Validate, so no free text reaches the terminal;
  - the warning's wording is tied to Phase 3's root successor-policy and is revisited with AUTHZ-03.

**cmd/keyroster/root.go (`(03-14b)`).**
- Make loadPrev's prevPolicy reach runRootSign alongside prev and prevBundle. The builder closure keeps using the same bytes.
- In runRootSign, for a successor, write `policyChange(prevPolicy, policy)` after the summary and the installation line, and before the prompt or the `--confirm` compare.
- On its error, return it wrapped with `; nothing was signed`. That cannot happen, because both documents parsed earlier; record it as reasoned, not run.
- A genesis signing prints no block.

**cmd/keyroster/trust.go (`(03-14b)`).** In verifySuccessorBundle, write `policyChange(prevPolicy, policy)` after the summary and before the signer lines, and return its error (unreachable, as above). Genesis verification prints no block.

**GREEN: commit T1** (`fix(root): show the policy in force, each changed field and the PoP switches before a root signs (F04, F14)`).
- **The commit.** T1 changes summary.go, policydiff.go, root.go and trust.go only.
- **A golden that does not match.** If GREEN fails on a golden, decide which side is wrong:
  - If the implementation prints what the contract says and the hand edit was wrong, correct that golden in its own commit, `test(root): correct golden <name> to the display contract`, made before T1. Record it in the SUMMARY's `Golden corrections` section with the golden's name, the line number and the contract line it now matches.
  - Otherwise fix the code.
  - Never regenerate a golden to make GREEN pass.
- **After T1.** Run the verify commands, the no-drift check included. Then run cmd/keyroster, internal/rootceremony and internal/trust. Every existing test must keep its meaning; among them:
  - TestRootSignSuccessor, TestTrustVerifySuccessor, TestRootSuccessorPolicyPoP and TestRootSignAccumulates;
  - TestSummaryShowsWebAuthnRP and TestExportedAPI;
  - the tests that 03-09 to 03-11b added.

  Record any assertion that moved, and why.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^(TestCeremonyGolden|TestRootSignSuccessor|TestTrustVerifySuccessor|TestRootSignTrustVerifyRoundTrip|TestRootSuccessorPolicyPoP|TestRootSignAccumulates)$" ./cmd/keyroster/ && go test -race -count=1 -timeout 15m -v -run "^(TestSummaryGolden|TestSummaryFieldsCovered|TestSummaryShowsWebAuthnRP|TestSignBundleAndPolicy|TestExportedAPI)$" ./internal/rootceremony/ && go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/rootceremony/ ./internal/trust/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestCeremonyGolden/successor_unchanged/root_sign", "--- PASS: TestCeremonyGolden/successor_unchanged/trust_verify", "--- PASS: TestCeremonyGolden/successor_rp_only/root_sign", "--- PASS: TestCeremonyGolden/successor_added_admin/root_sign", "--- PASS: TestCeremonyGolden/successor_added_admin/cosigner", "--- PASS: TestCeremonyGolden/successor_added_admin/trust_verify", "--- PASS: TestCeremonyGolden/successor_every_field/root_sign", "--- PASS: TestCeremonyGolden/successor_pop/root_sign", "--- PASS: TestCeremonyGolden/successor_pop/trust_verify", "--- PASS: TestCeremonyGolden/genesis_pop/root_sign", "--- PASS: TestCeremonyGolden/genesis_pop/trust_verify", "--- PASS: TestSummaryGolden/genesis", "--- PASS: TestSummaryGolden/pop_hosts_machines", "--- PASS: TestSummaryGolden/pop_machines_only", "--- PASS: TestSummaryFieldsCovered", "--- PASS: TestExportedAPI"</fails_when>
    <automated>D=$(git diff --name-only origin/main...R1) && ! printf '%s\n' "$D" | grep -vE '(_test\.go|^cmd/keyroster/testdata/ceremony/[a-z_.]+\.golden|^internal/rootceremony/testdata/summary/[a-z_.]+\.golden)$' | grep -q . && W=$(mktemp -d) && git worktree add --detach "$W/r1" R1 >/dev/null && { ( cd "$W/r1" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^TestCeremonyGolden$" ./cmd/keyroster/ ; go test -count=1 -timeout 15m -v -run "^(TestSummaryGolden|TestSummaryFieldsCovered)$" ./internal/rootceremony/ ; true' ) > "$W/red.log" 2>&1; git worktree remove --force "$W/r1"; } && L="$W/red.log" && test "$(grep -oE 'golden [a-z_.]+\.golden: first difference' "$L" | sort -u | wc -l)" -eq 13 && test "$(grep -oE -- '--- FAIL: TestCeremonyGolden/[a-z_]+/[a-z_]+ ' "$L" | sort -u | wc -l)" -eq 11 && test "$(grep -oE -- '--- FAIL: TestSummaryGolden/[a-z_]+ ' "$L" | sort -u | wc -l)" -eq 3 && test "$(grep -oE -- '--- FAIL: TestSummaryFieldsCovered/[A-Za-z.]+ ' "$L" | sort -u | wc -l)" -eq 3 && grep -qE -- '--- FAIL: TestSummaryFieldsCovered/Policy\.PoP ' "$L" && grep -qE -- '--- FAIL: TestSummaryFieldsCovered/PoPPolicy\.Hosts ' "$L" && grep -qE -- '--- FAIL: TestSummaryFieldsCovered/PoPPolicy\.Machines ' "$L" && ! grep -qE '\[(build|setup) failed\]' "$L"</automated>
    <fails_when>non-zero exit: R1 changed a file other than test files and the 13 goldens, or R1 does not fail the way the RED says (11 named TestCeremonyGolden leaves, 3 TestSummaryGolden cases, exactly the three PoP subtests of TestSummaryFieldsCovered, and a golden-mismatch message for each of the 13 goldens), or it did not build. R1 is the commit recorded in the SUMMARY</fails_when>
    <automated>G=$(git diff --name-only T1^ T1 -- cmd/keyroster/testdata/ceremony internal/rootceremony/testdata/summary) && test -z "$G" && ( for c in $(git rev-list R1..HEAD); do N=$(git diff --name-only "$c^" "$c") || exit 1; if printf '%s\n' "$N" | grep -qE '\.golden$'; then if printf '%s\n' "$N" | grep -qvE '^(cmd/keyroster/testdata/ceremony|internal/rootceremony/testdata/summary)/[a-z_.]+\.golden$'; then exit 1; fi; fi; done ) && C=$(git diff --name-only R1 HEAD -- cmd/keyroster/testdata/ceremony internal/rootceremony/testdata/summary) && S=$(awk '/^## Golden corrections/{f=1;print;next} f&&/^## /{exit} f' .planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md) && test -n "$S" && ( for f in $C; do printf '%s\n' "$S" | grep -qF "$(basename "$f")" || exit 1; done )</automated>
    <fails_when>non-zero exit: any of these:
      - the fix commit T1 changed a golden;
      - a commit after R1 that changes a golden also changes any other file (a golden correction is its own commit, of golden files only);
      - a golden changed after R1 without an entry in the SUMMARY's `Golden corrections` section;
      - that section is missing.

      Run it after T1, again in Task 2, and again before the final docs commit</fails_when>
    <automated>bash scripts/linux.sh 'go test -count=1 -timeout 15m -run "^TestCeremonyGolden$" ./cmd/keyroster/ -args -update-golden && go test -count=1 -timeout 15m -run "^TestSummaryGolden$" ./internal/rootceremony/ -args -update-golden' && git diff --exit-code -- cmd/keyroster/testdata/ceremony internal/rootceremony/testdata/summary && test -z "$(git ls-files --others --exclude-standard -- cmd/keyroster/testdata/ceremony internal/rootceremony/testdata/summary)"</automated>
    <fails_when>non-zero exit: regenerating the goldens from the implementation changed a committed golden or added an untracked one. The `git diff --exit-code` without a range is intentional: it compares the regenerated working tree with T1, so run it after T1. Restore with `git checkout -- cmd/keyroster/testdata internal/rootceremony/testdata` before investigating</fails_when>
    <automated>D=$(git diff --name-only origin/main...T1) && ! printf '%s\n' "$D" | grep -vE '^(cmd/keyroster/|internal/rootceremony/|\.planning/)' | grep -q . && V=$(git diff --name-only origin/main...HEAD -- internal/trust internal/signer internal/audit internal/agent internal/server cmd/keyroster-signer cmd/keyroster-agent cmd/keyroster-server internal/rootceremony/imports_test.go) && test -z "$V"</automated>
    <fails_when>non-zero exit: Task 1 changed a file outside cmd/keyroster, internal/rootceremony and .planning, or the branch touched a verifier package or the exported-API pin</fails_when>
  </verify>
  <acceptance_criteria>
    - `awk '/^func Summary\(/,/^}/' internal/rootceremony/summary.go | grep -v '^[[:space:]]*//' | grep -q 'p\.PoP'` exits 0.
    - `awk '/^func runRootSign\(/,/^}/' cmd/keyroster/root.go | grep -v '^[[:space:]]*//' | grep -q 'policyChange('` exits 0, and the same holds for `func verifySuccessorBundle(` in cmd/keyroster/trust.go.
    - `test "$(grep -c '^test-time base: ' .planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md)" -eq 1 && grep -Eqx 'test-time base: cmd=[0-9]+(\.[0-9]+)? rootceremony=[0-9]+(\.[0-9]+)? at=[0-9]+' .planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md` exits 0 (the base line exists once, in the format Task 3's delta gate reads).
    - The SUMMARY records:
      - R1 and T1;
      - the RED lines from R1's worktree;
      - the additions-only check per golden;
      - the `Golden corrections` section;
      - the no-drift result;
      - every existing assertion that moved.
    - **The mutant rule.** For every mutant below, the SUMMARY records three things:
      - the unmutated command passing;
      - `bash scripts/linux.sh 'go vet <package>'` on the mutated code exiting 0;
      - the mutated command printing every listed `--- FAIL:` line, and no `[build failed]` or `[setup failed]`. A timeout is not a kill.

      Each mutant compiles; where it removes a use of prevPolicy, it keeps `_ = prevPolicy`. Each is restored byte for byte (`git diff --quiet -- <file>`). Every command is `bash scripts/linux.sh 'go test -count=1 -timeout 5m -v -run "<pattern>" <package>'`, with the pattern in double quotes inside the single-quoted argument, as in the verify commands. The single quotes around each pattern below only mark its extent and are not typed.

      For example, mutant 6's command is `bash scripts/linux.sh 'go test -count=1 -timeout 5m -v -run "^TestCeremonyGolden$/^successor_.*$/^(root_sign|cosigner)$" ./cmd/keyroster/'`.

      Mutant numbers in this plan are local (Task 1's 1-18, Task 2's 1-16, and the four runbook mutants). This plan allocates no global M-IDs: 03-11 and 03-11b use M1-M110, and 03-12 starts at M111.

      Below, C is ./cmd/keyroster/ and R is ./internal/rootceremony/. "The successor root_sign leaves" are successor_unchanged/root_sign, successor_rp_only/root_sign, successor_added_admin/root_sign, successor_added_admin/cosigner, successor_every_field/root_sign and successor_pop/root_sign.
      1. **Summary's pop branch removed.**
         - R `'^(TestSummaryGolden|TestSummaryFieldsCovered)$'`: TestSummaryGolden/genesis, /pop_hosts_machines and /pop_machines_only; TestSummaryFieldsCovered/Policy.PoP, /PoPPolicy.Hosts and /PoPPolicy.Machines.
         - C `'^TestCeremonyGolden$'`: all 11 leaves (no pop line in any summary; the invariant and the golden).
      2. **Summary's one-way note removed.**
         - R `'^TestSummaryGolden$/^pop_hosts_machines$'`.
         - C `'^TestCeremonyGolden$/^(genesis_pop|successor_pop|successor_every_field)$'`: genesis_pop/root_sign, genesis_pop/trust_verify, successor_pop/root_sign, successor_pop/trust_verify and successor_every_field/root_sign.
      3. **The one-way note printed also when only machines is set.**
         - R `'^TestSummaryGolden$/^pop_machines_only$'`.
      4. **Summary's timelock line removed.**
         - R `'^TestSummaryFieldsCovered$/^Policy\.TimelockSeconds$'` and `'^TestSummaryGolden$'` (all 3).
         - C `'^TestCeremonyGolden$'`: all 11 leaves.
      5. **Summary's pop line moved after the timelock line.**
         - C `'^TestCeremonyGolden$'`: all 11 leaves. The record must also show an `invariant:` line for each of them, so that it proves checkInvariants bites, not only the golden.
         - R `'^TestSummaryGolden$'` (all 3).
      6. **runRootSign's block write removed**, with the call kept and its result discarded.
         - C `'^TestCeremonyGolden$/^successor_.*$/^(root_sign|cosigner)$'`: the successor root_sign leaves.
      7. **runRootSign's block written before the summary instead of after the installation line.**
         - C, the same pattern: the successor root_sign leaves. The record must also show an `invariant:` line for each of them.
      8. **verifySuccessorBundle's block write removed**, with the result discarded.
         - C `'^TestCeremonyGolden$/^successor_.*$/^trust_verify$'`: successor_unchanged/trust_verify, successor_added_admin/trust_verify and successor_pop/trust_verify.
      9. **The block's base taken from the successor itself:** `_ = prevPolicy` and `policyChange(policy, policy)` in runRootSign.
         - C `'^TestCeremonyGolden$/^(successor_rp_only|successor_added_admin|successor_every_field|successor_pop)$/^(root_sign|cosigner)$'`: those five leaves.
      10. **The admins comparison removed**, so admins always read carried over.
          - C `'^TestCeremonyGolden$/^(successor_added_admin|successor_every_field)$'`: their four leaves.
      11. **The `+ admin` line dropped.**
          - C, the same pattern and the same four leaves.
      12. **The `max_ttl_seconds` sub-line dropped.**
          - C, the same pattern and the same four leaves.
      13. **The webauthn one-way marker dropped.**
          - C `'^TestCeremonyGolden$/^(successor_rp_only|successor_added_admin|successor_every_field)$'`: their five leaves.
      14. **The pop comparison removed.**
          - C `'^TestCeremonyGolden$/^(successor_pop|successor_every_field)$'`: successor_pop/root_sign, successor_pop/trust_verify and successor_every_field/root_sign.
      15. **The diff's pop.hosts one-way line dropped.**
          - C, the same pattern and the same three leaves.
      16. **The unchanged form replaced by the changed form**, with every field carried over.
          - C `'^TestCeremonyGolden$/^successor_unchanged$'`: both leaves.
      17. **The warning line dropped.**
          - C `'^TestCeremonyGolden$/^(successor_added_admin|successor_every_field)$'`: their four leaves.
      18. **The warning line printed for any CHANGED field**, webauthn and pop included.
          - C `'^TestCeremonyGolden$/^(successor_rp_only|successor_pop)$'`: successor_rp_only/root_sign, successor_pop/root_sign and successor_pop/trust_verify.
  </acceptance_criteria>
  <done>A co-signer of a successor sees, as the last thing before confirming, the policy in force, every field the successor changes, and a warning when a change could only have been written by hand. trust verify --prev shows the same block. Every ceremony summary shows the pop switches, with pop.hosts marked one-way. Each line is pinned by a golden committed RED before the fix, and by invariants that do not depend on any golden.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The durable gates — every policy field has an isolated diff case, the warning's rule, admins edge cases, the authenticated base in both commands, and the real-binary pin</name>
  <files>cmd/keyroster/policydiff_test.go, test/e2e/audit_login_test.go</files>
  <behavior>
    - **`TestPolicyFieldsCovered`** (no build tag). The same recursive walk and the same pinned literal lists as Task 1's TestSummaryFieldsCovered, kept in this package.
      - Every field except Policy.Version and Policy.Prev (the block's header) and CAProfile.Role (Validate pins the roles and their order) must be the key of at least one TestPolicyChangeFields case. A case's key is its name up to an optional `_suffix`.
      - It fails, naming the field or the unpinned type, with the message that a new policy field needs a policydiff.go line, a case here, and a Summary line (TestSummaryFieldsCovered).
      - The walk must also reach every entry of the pinned map; an entry it never reaches fails, naming it. So a gate that stopped recursing would fail today.
      - Task 1's precondition stops on any change to policy.go since b4e6b4c (where policy.go is byte-identical to f7eb018), so the lists match origin/main when this task runs.
    - **`TestPolicyChangeFields`** (table, a package-level slice).
      - **The base**, valid and canonical, version 1: policy_genesis_v1 with admins alice (seed 20) and bob (seed 22) at quorum 1, the RP keyroster.example.org with origins [https://keyroster.example.org], and pop hosts=false machines=true. A case may name its own base.
      - **Each case** derives version 2, with prev the base's SHA-256 and the case's change; the result must validate. It requires:
        - changedPolicyFields to return exactly the case's top-level field;
        - exactly one `CHANGED` field line, for that field (for a profile, its role's line), with every other of the 8 field lines ending in `carried over`;
        - the case's expected sub-lines;
        - the warning line exactly when the field is admin_quorum, admins, ca_profiles or timelock_seconds, naming that field.
      - **Leaf honesty.** For a key of the form `AdminKey.X`, `CAProfile.X`, `WebAuthnRP.X` or `PoPPolicy.X`, a reflect walk of the base and the successor (same shape, no nil on either side, Version and Prev excluded) finds exactly field X differing. The exception is WebAuthnRP.RPID: Validate ties origins to rp_id, so its case changes Origins too. Container keys (`Policy.X`) have no such check.
      - **The cases:**
        - `Policy.AdminQuorum`: 1 → 2.
        - `Policy.Admins`: admin dave (seed 24) appended (`+ admin dave <fp24> ssh-ed25519`, `carried over: alice bob`).
        - `AdminKey.Name`: bob renamed robert (`~ admin <fp22> ssh-ed25519 renamed bob -> robert`, `carried over: alice`).
        - `AdminKey.Key`: bob's key replaced by seed 23 (`- admin bob <fp22> ssh-ed25519`, `+ admin bob <fp23> ssh-ed25519`).
        - `CAProfile.MaxTTLSeconds`: user 43200 → 3600.
        - `Policy.CAProfiles`: host max_ttl_seconds 2592000 → 604800 (`ca_profiles host: CHANGED`).
        - `CAProfile.DefaultExtensions`: machine [permit-pty] → [].
        - `CAProfile.AllowedExtensions`: user [] → [permit-agent-forwarding].
        - `CAProfile.AllowedCriticalOptions`: user [] → [force-command].
        - `Policy.TimelockSeconds`: 0 → 3600.
        - `WebAuthnRP.RPID`: rp_id other.example.org with its origin; the one-way marker; no warning.
        - `WebAuthnRP.Origins`: https://keyroster.example.org:8443 added; no marker.
        - `Policy.WebAuthn`: the RP removed (`rp_id: keyroster.example.org -> (none)`).
        - `PoPPolicy.Hosts`: {hosts false, machines true} → {true, true}, with the one-way line.
        - `PoPPolicy.Machines`: hosts true on both sides. Its own base sets pop {hosts true, machines true}, and the successor has {true, false}: `pop: CHANGED hosts=true machines=true -> hosts=true machines=false`, without the one-way line.
        - `Policy.PoP_added`: from a base without pop, pop {false, true} added (`pop: CHANGED (none) -> hosts=false machines=true`, no one-way line).
        - `Policy.PoP_removed`: {false, true} → none (`pop: CHANGED hosts=false machines=true -> (none)`).
    - **`TestPolicyChangeAdmins`**: `added_only`, `removed_only` (the quorum stays valid), `order_only` (alice and bob swapped: `order: alice bob -> bob alice`, `carried over: bob alice`), `rename_and_add`, and `all_replaced` (`carried over: (none)`). Each asserts the exact sub-lines in the contract's order.
    - **`TestPolicyChangeUnchanged`**: identical bytes give exactly the two unchanged lines, and changedPolicyFields is empty. `version_bump_only`: version 2, chained, every field equal, gives the changed header, no warning and all 8 field lines `carried over`.
    - **`TestPolicyChangeDurations`**: a timelock of 1<<62 renders `<n> (<n>s)`; 3600 renders `3600 (1h0m0s)`. Both branches of the duration helper.
    - **`TestPolicyChangeInvalid`**: a non-canonical policy in force, and an invalid successor, each return an error naming which document failed to parse.
    - **`TestPolicyBlockBase`** (F04's base, T-03-331), on Task 1's fixture:
      1. Build a successor out-dir O against the real `prev`, signed by A and B (signWith).
      2. Copy `prev` to P2, and replace P2/policy.json with another valid version 1 policy (user max TTL 3600).
      3. Re-sign that policy.json with A and B, so loadPrev's self-signed check passes. P2/bundle.json still names the original policy and keeps its hash, so `--prev-sha256` is unchanged.
      4. `root_sign`: `root sign --prev P2 ...` into a fresh out-dir exits 1 with `prevPolicy is not the previous bundle's policy`, and its stdout holds no `Policy in force`.
      5. `trust_verify`: `trust verify --prev P2 ... --bundle O/bundle.json --policy O/policy.json` (the `.sigs` files present) exits 1 with the same refusal, from checkSuccessorChain, and no `Policy in force`.

      GREEN on origin/main too; record that.
    - **The real-binary pin** in test/e2e/audit_login_test.go (TestAuditLoginAcrossPolicyChange, `(03-14b)`):
      - The wrong-confirmation output of `root sign --prev` holds `Policy in force: v1, sha256 ` followed by the SHA-256 of policyV1, and these lines:
        - `  webauthn: CHANGED (rp_id is one-way)`;
        - `  admins: carried over`;
        - `  pop: carried over`;
        - `  pop: none (host agents and machine renewals are off)`.

        It holds no `WARNING: this successor changes`.
      - The `trust verify --prev` output holds the first three of these and the summary's pop line.
      - It runs in CI's e2e workflow only, and has no RED of its own: the code path is the one R1's dispatch goldens prove RED.
  </behavior>
  <read_first>
    - Task 1's diff of cmd/keyroster (in context), and its fixture helpers in ceremony_golden_test.go.
    - Task 1's TestSummaryFieldsCovered walk (in context).
    - test/e2e/audit_login_test.go: steps 3 and 4 of TestAuditLoginAcrossPolicyChange (about 3 KB).
  </read_first>
  <action>
Write the tests in `<behavior>`.

If a case fails because policydiff.go does not print what "The display contract" says, fix policydiff.go in its own commit and record it. Then rerun Task 1's first and no-drift verify commands, because the goldens pin the same lines. A golden change here follows Task 1's `Golden corrections` rule: its own commit, golden files only, recorded in the section. Task 1's third verify command checks that over R1..HEAD; rerun it. Change no other production code. If a case needs another change, stop and report.

Run `go vet -tags e2e ./test/e2e/` and gofmt. Local e2e cannot run on this machine; the pin's first run is the PR's e2e workflow (Task 3).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^(TestPolicyFieldsCovered|TestPolicyChangeFields|TestPolicyChangeAdmins|TestPolicyChangeUnchanged|TestPolicyChangeDurations|TestPolicyChangeInvalid|TestPolicyBlockBase|TestCeremonyGolden)$" ./cmd/keyroster/ && go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l cmd internal test)"'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestPolicyFieldsCovered", "--- PASS: TestPolicyChangeFields/PoPPolicy.Machines", "--- PASS: TestPolicyChangeFields/Policy.PoP_removed", "--- PASS: TestPolicyChangeFields/Policy.AdminQuorum", "--- PASS: TestPolicyChangeAdmins/order_only", "--- PASS: TestPolicyChangeAdmins/all_replaced", "--- PASS: TestPolicyChangeUnchanged/version_bump_only", "--- PASS: TestPolicyChangeDurations", "--- PASS: TestPolicyChangeInvalid", "--- PASS: TestPolicyBlockBase/root_sign", "--- PASS: TestPolicyBlockBase/trust_verify", "--- PASS: TestCeremonyGolden"</fails_when>
    <automated>D=$(git diff --name-only T1...HEAD) && ! printf '%s\n' "$D" | grep -vE '^(cmd/keyroster/policydiff(_test)?\.go|test/e2e/audit_login_test\.go|cmd/keyroster/testdata/ceremony/[a-z_.]+\.golden|\.planning/.*)$' | grep -q .</automated>
    <fails_when>non-zero exit: Task 2 changed a file other than its tests, the e2e pin and (only for a recorded contract fix) policydiff.go and a corrected golden; with T1 as recorded in the SUMMARY</fails_when>
    <automated>G=$(git diff --name-only T1^ T1 -- cmd/keyroster/testdata/ceremony internal/rootceremony/testdata/summary) && test -z "$G" && ( for c in $(git rev-list R1..HEAD); do N=$(git diff --name-only "$c^" "$c") || exit 1; if printf '%s\n' "$N" | grep -qE '\.golden$'; then if printf '%s\n' "$N" | grep -qvE '^(cmd/keyroster/testdata/ceremony|internal/rootceremony/testdata/summary)/[a-z_.]+\.golden$'; then exit 1; fi; fi; done ) && C=$(git diff --name-only R1 HEAD -- cmd/keyroster/testdata/ceremony internal/rootceremony/testdata/summary) && S=$(awk '/^## Golden corrections/{f=1;print;next} f&&/^## /{exit} f' .planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md) && test -n "$S" && ( for f in $C; do printf '%s\n' "$S" | grep -qF "$(basename "$f")" || exit 1; done )</automated>
    <fails_when>non-zero exit: Task 1's golden-correction bound fails after Task 2 (a golden changed in a commit that also changed other files, or without an entry in `Golden corrections`)</fails_when>
  </verify>
  <acceptance_criteria>
    - The SUMMARY records every case's result, that TestPolicyBlockBase is GREEN on origin/main, and any contract fix with Task 1's checks after it.
    - **The mutants.** Each follows Task 1's mutant rule (unmutated pass, `go vet` 0, named FAILs, no build or setup failure, restored byte for byte). Every command is `bash scripts/linux.sh 'go test -count=1 -timeout 5m -v -run "<pattern>" ./cmd/keyroster/'`, except where R is named, with the pattern in double quotes as in Task 1's rule. A timeout is not a kill. The single quotes around each pattern below only mark its extent. For example, mutant 7's command is `bash scripts/linux.sh 'go test -count=1 -timeout 5m -v -run "^TestPolicyChangeFields$/^(PoPPolicy\.Hosts|PoPPolicy\.Machines|Policy\.PoP_added|Policy\.PoP_removed)$" ./cmd/keyroster/'`.
      1. **The `- admin` line dropped.** `'^TestPolicyChangeFields$/^AdminKey\.Key$'`, and `'^TestPolicyChangeAdmins$/^(removed_only|all_replaced)$'`.
      2. **Rename detection removed.** `'^TestPolicyChangeFields$/^AdminKey\.Name$'`.
      3. **The order line dropped.** `'^TestPolicyChangeAdmins$/^order_only$'`.
      4. **The timelock comparison removed.** `'^TestPolicyChangeFields$/^Policy\.TimelockSeconds$'`.
      5. **The allowed_critical_options comparison removed.** `'^TestPolicyChangeFields$/^CAProfile\.AllowedCriticalOptions$'`.
      6. **Only rp_id compared, not origins.** `'^TestPolicyChangeFields$/^WebAuthnRP\.Origins$'`.
      7. **changedPolicyFields without pop.** `'^TestPolicyChangeFields$/^(PoPPolicy\.Hosts|PoPPolicy\.Machines|Policy\.PoP_added|Policy\.PoP_removed)$'`: all four.
      8. **pop compared only by nil-ness and Hosts.** `'^TestPolicyChangeFields$/^PoPPolicy\.Machines$'`.
      9. **The one-way line printed whenever the successor sets hosts**, ignoring the policy in force. `'^TestPolicyChangeFields$/^PoPPolicy\.Machines$'`.
      10. **The warning line printed for webauthn.** `'^TestPolicyChangeFields$/^WebAuthnRP\.RPID$'`.
      11. **The warning line without timelock_seconds in its set.** `'^TestPolicyChangeFields$/^Policy\.TimelockSeconds$'`.
      12. **A field `Note string` with tag `note,omitempty` temporarily added to trust.Policy.** `'^TestPolicyFieldsCovered$'`, and R `'^TestSummaryFieldsCovered$'`. The build stays green.
      13. **Two mutants of the gates themselves**, which only the recursive walk can kill. Each mutates the test file in both packages and is restored byte for byte.
          - (a) The pinned map's trust.WebAuthnRP entry deleted. `'^TestPolicyFieldsCovered$'`, and R `'^TestSummaryFieldsCovered$'`. The output must contain `unpinned policy type` naming trust.WebAuthnRP. No field list or case changes, so only the walk sees it.
          - (b) The walk made non-recursive, so only trust.Policy is examined. The same two commands. The output must contain `pinned type not reached` for the four nested types.
      14. **runRootSign writes the block right after successorBuilder returns**, before prepareBundle and so before the chain check. `'^TestPolicyBlockBase$/^root_sign$'`.
      15. **verifySuccessorBundle writes the block right after loadPrev**, before VerifySuccessor. `'^TestPolicyBlockBase$/^trust_verify$'`.
      16. **The duration helper's large-value branch removed.** `'^TestPolicyChangeDurations$'`.
  </acceptance_criteria>
  <done>A policy field that a later plan adds, a comparison that a later edit drops, a pop or warning rule that a later edit loosens, and a base that is not the authenticated policy in force each fail a named test in CI. The real binaries print the block in the e2e workflow.</done>
</task>

<task type="auto">
  <name>Task 3: The runbook checklists and their section helper, the transcript row, the pointer sentences, the publish edits, the gates, the PR, the pre-merge review and the SUMMARY</name>
  <files>docs/runbooks/root-ceremony.md, docs/runbooks/ceremony-transcript-template.md, docs/runbooks/host-setup.md, docs/runbooks/machine-identities.md, cmd/keyroster/runbook_test.go, .planning/phases/03-linux-agent-and-revocation/03-14b-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/root-ceremony.md, about 12 KB:
      - "## 4. Sign with root A, then with root B";
      - steps 3, 4 and 5 of "## Rotate the roots";
      - "## Change the policy", from its first paragraph through step 4, the bookkeeping paragraph and the "What has run" note;
      - the first paragraph of "## Hardware-root variant".
    - docs/runbooks/ceremony-transcript-template.md: the "## Ceremony" table (about 0.5 KB).
    - docs/runbooks/host-setup.md: the section `## Registering a host in the directory`, from the paragraph that begins `**Host agents need` to the end of the section (about 1.5 KB, as 03-09 to 03-11b left it).
    - docs/runbooks/machine-identities.md: "## Renewal needs pop.machines" (about 1 KB, as 03-11 and 03-11b left it).
    - cmd/keyroster/runbook_test.go: `hostSetupSection` and `TestHostSetupSignerCheck` (about 2 KB), the pattern.
    - .planning/ROADMAP.md: Phase 3's Plans line, its wave blocks (`grep -n 'Wave\|Plans:'`) and the Progress table's Phase 3 row (`grep -n '^| 3\. Linux Agent'`).
    - .planning/STATE.md: the frontmatter and the `Plan:` line.
    - The anchor lines in 03-12, 03-13, 03-14 and 03-15, found with `grep -nF` on each anchor below. The frontmatter, and 03-12's `<precondition>`. The `wave:` lines of every phase-3 plan from 03-12 on.
  </read_first>
  <action>
**Runbooks (CONTEXT D-20).**
- **Labels.** Every new text in root-ceremony.md and the transcript template says: run in CI (TestCeremonyGolden, TestSummaryGolden and TestRootCeremonyPolicyChecks, 03-14b; TestAuditLoginAcrossPolicyChange, e2e, real binaries); UNVERIFIED in a real ceremony. It carries no date. host-setup.md's and machine-identities.md's pop checks say UNVERIFIED in a real ceremony until 03-15, whose v4 ceremony runs the same block and pop checks.
- **Execution-time inventory.** First run `git grep -n 'root sign' origin/main -- docs/runbooks`. Every section with a confirmation list for a successor or genesis signing gets the checks below, and an entry in the section helper. Under Q-B3 these are the sections of root-ceremony.md, host-setup.md and machine-identities.md named here. If the grep finds another, add it the same way and record it. If a runbook defers to a root-ceremony.md step, record that and add nothing. Expected at b4e6b4c, besides the three target runbooks: revoke.md ("Before you start", the installation-ID upgrade by `root sign --prev … --installation-id new`, which points at 03-15), host-setup.md's "Binding an existing directory to the installation", and signer-install.md's two passages that defer to root-ceremony.md. Each of these defers or describes and holds no confirmation list for a signing, so it is recorded as "defers or describes, nothing added".

1. **ceremony-transcript-template.md.**
   - The Purpose row becomes `genesis / root rotation / policy change / re-sign`.
   - Add the row `| Agreed policy change (the changed field names, and a reference to the record that holds the agreed values; no hostname or other value is written here; agreed before the successor policy is written, and recorded by someone other than its proposer, or by the owner on a single-owner installation) | |` to the Ceremony table. It records no rp_id or other hostname, which keeps the template's rule that no hostname is written into a transcript. The RP check compares against the referenced record.
2. **root-ceremony.md, "4. Sign with root A, then with root B".**
   - In the list of what the summary shows, add the WebAuthn RP and the PoP switches.
   - Before the sentence that tells you to type the hash prefix (it starts `Then type the hash` and is wrapped onto the next line, so a one-line `grep -F` for the whole phrase does not find it), add two checks:
     - Run `root sign` without `--confirm`. `--confirm` skips the prompt and signs as soon as the prefix matches, so the summary is never read before signing. Remove it from any command you were given.
     - The pop line: a policy from `root genesis-policy` reads `pop: none (...)`. A policy that sets pop.hosts can never be followed by one that clears it.
3. **root-ceremony.md, "Rotate the roots".**
   - **Step 3.** In the "Before you type the hash prefix, compare" list:
     - add the `--confirm` check first;
     - replace the bullet about the policy hash with this one: with this section's command, which passes the policy in force as `--policy`, the policy block reads `Policy in force: ...` and `Successor policy: unchanged, every field carried over`, and any other block means answer no;
     - add the combined-ceremony sentence after the list: "A ceremony that both rotates the roots and changes the policy (03-15's v4) follows the section written for it. That section compares the new roots with the paper, as this list does, and checks the policy items of the policy-change list: no `--confirm`, the policy in force, only the agreed change, the RP, the PoP switches and the hash. It expects the installation line its own section names. The unchanged-block item of this list and the roots item of the policy-change list do not apply there."
   - **Step 4.** Add: before you type the hash prefix, make the checks of step 3, the policy block included.
   - **Step 5.** Add that trust verify's output shows the same block.
4. **root-ceremony.md, "Change the policy".**
   - **The paragraph that begins `In Phase 2`.** Replace it with:
     - `keyroster root successor-policy` changes only the WebAuthn relying party and the PoP switches (`--pop-hosts`, `--pop-machines`), and carries every other field over.
     - `root sign --prev` signs any policy that chains to the policy in force. A successor written by hand may change the admins (for example, to remove a lost admin key, enroll-user.md), the admin quorum, a CA profile or the timelock, and the chain rule accepts it.
     - The policy block of `root sign --prev` is where every custodian sees what changed. It prints a `WARNING: this successor changes ...` line for any change root successor-policy cannot make.
     - A quorum-gated policy change comes in Phase 4 (AUTHZ-03).
   - **"You need"** gains: the agreed change, which policy fields change and to what. It is agreed before step 2. The transcript's `Agreed policy change` row records the field names and a reference to the record that holds the agreed values, written by someone other than the proposer, or by the owner on a single-owner installation. A custodian who was not part of the agreement takes it from that row and that record, never from the proposer's message or command.
   - **Step 3, "Before you confirm".** Replace the two-line check with an intro, then a list.
     - The intro starts `Before you confirm`. It says that each further custodian runs the same command with their own key and the same `--out-dir`, and that every root custodian who signs checks the list, including one who did not see step 2's output.
     - The list:
       - **No `--confirm`.** Run `root sign` without `--confirm`. If the command you were given carries it, remove it: `--confirm` signs as soon as the prefix matches, so the block is never read.
       - **The roots do not change.** With this section's command, which reuses the roots in force: the `Root keys (threshold t of n)` lines list exactly the keys of the `Previous root keys (threshold t of n)` lines, at the same threshold, and match the paper; and the summary shows no installation line marked `(new in this version)`. Otherwise answer no.
       - **The policy in force.** `Policy in force: vN, sha256 ...` names the policy version you expect. This is the version of the policy, which after a rotation is lower than the bundle version; on the homelab, bundle v3 carries policy v2. root sign has already bound this policy to the bundle you pinned with `--prev-sha256`: it takes the policy.json that bundle names and refuses any other. Compare its SHA-256 with your transcript only where the transcript records that policy's SHA-256.
       - **Only the agreed change.** Under `Successor policy: vN+1, ...`, every field reads `carried over` except the fields the `Agreed policy change` row names, and each `-`, `+`, `~` and `CHANGED` line matches that row. If any other field reads `CHANGED`, or a value differs from the row, answer no: nothing is signed. A `WARNING: this successor changes ...` line names fields root successor-policy never writes; sign only when the row names exactly those fields and values.
       - **The RP.** `webauthn rp_id <hostname>  origins [...]` names exactly the hostname and origins in the record that the `Agreed policy change` row refers to. rp_id is one-way.
       - **The PoP switches.** The pop line, `pop: none (...)` or `pop hosts=<true|false> machines=<true|false>`, matches the agreed change. pop.hosts is one-way: once a policy sets it, no later policy may clear it. This line is as mandatory as the rp_id line.
       - **The hash, if you saw step 2.** `policy sha256:` equals the last `sha256:` line of step 2's output.
   - **After the list**, the combined-ceremony sentence in this section's words: "A ceremony that both rotates the roots and changes the policy (03-15's v4) follows the section written for it. That section compares the new roots with the paper, as the rotation list does, and checks the policy items of this list: no `--confirm`, the policy in force, only the agreed change, the RP, the PoP switches and the hash. It expects the installation line its own section names. The roots item of this list and the unchanged-block item of the rotation list do not apply there."
   - **Step 4.** trust verify's summary shows the same `webauthn` and `pop` lines, and its policy block the same lines that were checked in step 3.
   - **The "What has run" note.** Add the tests above and the UNVERIFIED label.
5. **root-ceremony.md, "Hardware-root variant".** Add a sentence to its first paragraph: the checks of the step being replaced apply before each touch or confirmation, the policy block and the pop line included.
6. **host-setup.md, the pop.hosts paragraph** (found by its anchor `**Host agents need`).
   - Where the paragraph says that no test runs `trust verify --prev` with such a policy, replace that clause with: `TestCeremonyGolden/successor_pop` runs `root sign --prev` and `trust verify --prev` with such a policy (03-14b). If 03-09 or 03-10 already reworded it, adjust the new text and record that.
   - After "then `keyroster root sign --prev` with the new policy", add: before you confirm, check the summary's `pop hosts=true ...` line with its one-way note, and that the policy block marks only `pop` as `CHANGED` (root-ceremony.md, "Change the policy", step 3). Label it as above.
7. **machine-identities.md, "Renewal needs pop.machines".** After the successor-policy sentence, add the same check for `machines=true`. Label it the same way.

**TestRootCeremonyPolicyChecks (cmd/keyroster/runbook_test.go, `(03-14b)`).**
- **One section helper, `successorSigningSections`.** It returns entries of {file, the `## ` section prefix, an optional start and end marker inside it, the required substrings}. Later plans extend this list (their pointer sentences say so).
- **How a window is found.** A function `sectionWindow(text, entry) (string, error)`:
  - It splits the file into `## ` sections, and returns an error when the entry's prefix matches a number of sections other than one.
  - It finds each marker on a line after trimming that line's leading whitespace, so an indented `- **` bullet or step counts. A marker matches as a prefix of the trimmed line.
  - It returns an error when a start marker or a fixed end marker occurs other than exactly once inside its parent window, or when the end marker comes before the start marker. The two "next line" end markers below (the pop item and the intro) are the first matching line after the start; their absence is an error.
  - The window runs from the start marker's line up to, not including, the end marker's line.
- **How an entry fails.**
  - The test runs one subtest per entry, named by its id. A sectionWindow error ends the subtest with t.Fatalf, naming the entry and the marker.
  - Each required substring missing from the window is a t.Errorf naming the entry and the substring.
  - Substrings are compared against the window normalised with `strings.Join(strings.Fields(s), " ")`, as TestServerInstallTailscalePrerequisites does, so a phrase wrapped across lines still matches. The substrings below are written in that normalised form.
  - A self-test, `TestSectionWindowRefusals`, feeds sectionWindow fixtures with a duplicated marker, a missing marker and an end before its start, and requires an error for each.
- **The entries:**
  - `genesis_step_4`: root-ceremony.md, `4. Sign with root A`. Requires `pop: none`, `pop.hosts` and `without \`--confirm\``.
  - `rotation_step_3`: root-ceremony.md, `Rotate the roots`, between `3. **Build the successor` and `4. **Sign with a current root`. Requires `Successor policy: unchanged, every field carried over`, `without \`--confirm\`` and `do not apply there`.
  - `rotation_step_4`: the same section, between `4. **Sign with a current root` and `5. **Verify against the paper`. Requires `checks of step 3` and `policy block`.
  - `change_the_policy_you_need`: root-ceremony.md, `Change the policy`, between `You need everything from` and `0. **Prepare.**`. Requires `Agreed policy change` and `never from the proposer`.
  - `change_the_policy_step_3`: root-ceremony.md, `Change the policy`, between `3. **Sign the successor bundle` and `4. **Verify against the paper`. Requires:
    - `Policy in force:`, `Successor policy:`, `carried over`, `CHANGED` and `WARNING: this successor changes`;
    - `Agreed policy change`, `Previous root keys` and `Root keys (threshold`;
    - `without \`--confirm\``, `policy version` and `bundle you pinned with`;
    - `do not apply there`.
  - `change_the_policy_pop_item`: within `change_the_policy_step_3`, from the line whose trimmed text starts `- **The PoP switches.**` up to the next line whose trimmed text starts `- **`, or the next numbered step line, whichever comes first. Requires `pop: none (`, `pop hosts=`, `one-way` and `as mandatory as the rp_id line`.
  - `change_the_policy_intro`: within `change_the_policy_step_3`, from the line that starts `Before you confirm` up to the next line whose trimmed text starts `- **`. Requires `including one who did not see step 2's output` and `same \`--out-dir\``.
  - `hardware_variant`: root-ceremony.md, `Hardware-root variant`. Requires `before each touch`.
  - `transcript_template`: ceremony-transcript-template.md, `Ceremony`. Requires `root rotation / policy change / re-sign` (the Purpose row), `Agreed policy change (the changed field names` and `someone other than its proposer`. No one of these is a substring of another.
  - `host_setup_pop`: host-setup.md, `Registering a host in the directory`. Requires `successor_pop` and `CHANGED`.
  - `machine_identities_pop`: machine-identities.md, `Renewal needs pop.machines`. Requires `machines=true` and `CHANGED`.
- **The doc-to-output link.** One shared list of output prefixes: `Policy in force: v`, `Successor policy: unchanged, every field carried over`, `WARNING: this successor changes`, `Previous root keys (threshold`, `Root keys (threshold`, `pop hosts=`, `pop: none (`, `webauthn rp_id ` and `pop.hosts is one-way`.
  - Each prefix must occur, after whitespace normalisation, in at least one helper section, and in at least one cmd/keyroster/testdata/ceremony golden.
  - The test's doc comment says what this proves: each prefix the runbook quotes for these checks is one the tool prints. It does not prove every backticked span.
- Record the RED of every subtest on origin/main's runbooks.

**Pointer sentences (Q-B3, Q-B2).** Each is inserted exactly once, right after its anchor and inside the same line. Change nothing else in those files. Each anchor occurs exactly once at f7eb018 and at b4e6b4c; if one is not found exactly once on origin/main, stop and report.
- **03-12-PLAN.md.**
  - Anchor: `proven end to end with a login loop that never fails.`
  - Insert: ` (Since 03-14b: render the new bundle fields and CA states in every ceremony summary, root sign and trust verify alike, the carried and absent states included; add a reflect gate that Summary's output, compared with its Bundle SHA-256: line removed, changes for every exported field of trust.Bundle and its nested types, for 03-13 and 03-14 to extend; record how InstallationID is handled, either a Summary line or a named gate exception pointing at installationLine and 03-14c; give every new successor-signing runbook section 03-14b's checklist and an entry in its section helper (TestRootCeremonyPolicyChecks); change 03-14b's goldens by additions only, visible in the PR diff, and keep the policy block the last thing before the prompt. See 03-14b-PLAN.md.)`
- **03-13-PLAN.md.**
  - Anchor: `and give admins an emergency path that replaces a compromised CA and kills its certificates at once.`
  - Insert: ` (Since 03-14b: render the log-key, ops-key and emergency changes in every ceremony summary, root sign and trust verify alike, the carried and absent states included, and extend 03-12's Bundle reflect gate; give every new successor-signing runbook section 03-14b's checklist and an entry in its section helper; change 03-14b's goldens by additions only, visible in the PR diff, and keep the policy block the last thing before the prompt. See 03-14b-PLAN.md.)`
- **03-14-PLAN.md.**
  - Anchor: `and keeps working when the server is down or the main KRL or CA file is broken (BREAK-01, D-13).`
  - Insert: ` (Since 03-14b: render the break-glass field in every ceremony summary, root sign and trust verify alike, its absence included, and extend 03-12's Bundle reflect gate; give the break-glass runbook's successor-signing sections 03-14b's checklist and entries in its section helper; change 03-14b's goldens by additions only, visible in the PR diff, and keep the policy block the last thing before the prompt. See 03-14b-PLAN.md.)`
- **03-15-PLAN.md**, three advisory pointers. 03-15's acceptance criteria are unchanged.
  - **Task 2.**
    - Anchor: `which proves the comparison the owner makes in Task 3.`
    - Insert: ` (Since 03-14b, the rehearsal also asserts that the policy block of root sign --prev and trust verify --prev names the policy of bundle v3 as the policy in force and marks only pop as CHANGED, with no WARNING line, and that the summary's pop line reads pop hosts=true machines=true; see 03-14b-PLAN.md.)`
  - **The runbook section.**
    - Anchor: `what the summary must show (installation id new, break-glass line, pop line, CA next line)`
    - Insert: ` (since 03-14b also the policy block, which names the policy of bundle v3 as the policy in force and must mark only pop as CHANGED; the section carries the policy items of 03-14b's policy-change checklist without its roots item, compares the new roots with the paper as in a rotation, expects the installation line to read (new in this version), and gets an entry in 03-14b's section helper in TestRootCeremonyPolicyChecks; see 03-14b-PLAN.md)`
  - **Task 3, instruction 2.**
    - Anchor: `and that the admin lines match v3's admins`, before the `;` that follows it.
    - Insert: ` (since 03-14b, also that the policy block names the policy of bundle v3, policy v2 on the homelab, as the policy in force and marks only pop as CHANGED, every other field carried over and no WARNING line; see 03-14b-PLAN.md)`

**Publish edits.** Make them in this PR, on top of origin/main. Every wave number is origin/main's value + 1. The totals (edits 2 and 3) are the true counts of the PLAN and SUMMARY files, which is what GSD's tracking update writes: main's totals were stale at b4e6b4c, and this plan corrects them. The values in brackets are what main holds at b4e6b4c. W12 is the `wave:` of origin/main's 03-12-PLAN.md [29].
0. **Stop guard, first.** Re-run Task 1's first precondition (03-11b's SUMMARY on main, origin/main's 03-12 at `wave: 29`, 03-11b the only plan at `wave: 28`). If it fails, main moved since the reconcile of 2026-11-10: stop and report for a re-reconcile, and make none of the edits below. This plan never takes over another plan's values.
1. Commit this plan as `.planning/phases/03-linux-agent-and-revocation/03-14b-PLAN.md`, unchanged: `wave: 29` and `depends_on: ["03-11b"]`.
2. ROADMAP.md, Phase 3:
   - The Plans line ([29/33 plans executed in 33 waves] → 29/35 plans executed in 34 waves). The total is the true count: main listed 34 plan rows and files against `/33`, and this plan adds the 35th. The wave count goes up by one. GSD's tracking update at the end of this task rewrites only the counts, from the phase's PLAN and SUMMARY files: 30/35 plans executed in 34 waves. No tool touches the wave count.
   - The Progress table's Phase 3 row ([29/33] → 29/35, and 30/35 after the tracking update).
   - Insert, right before 03-12's wave block, the block `**Wave 29** *(blocked on Wave 28 completion)*` with the unchecked entry `- [ ] 03-14b-PLAN.md — Show what a root signs (F04, F14): the policy in force and each changed field before a successor is signed or verified, a warning for hand-written changes, and the PoP switches in every ceremony summary`, followed by one blank line.
   - Renumber every later block one wave later ([29–33] → 30–34), each "blocked on" clause with them.
3. STATE.md, set by hand to the true counts, each stale on main:
   - `total_plans` ([68] → 70): every PLAN file under .planning/phases with this plan (21, 14 and 35). Main held 68 against its 69 files.
   - `completed_plans` stays [64]: 64 SUMMARY files until this plan's SUMMARY lands.
   - The Plan line ([Plan: 28 of 30] → Plan: 29 of 35): 29 of phase 3's plans are executed, and the phase has 35 with this one. Main held 28 of 30 against 29 executed of 34.

   GSD's tracking update then writes, in this order (checked against the installed GSD tools on a copy of b4e6b4c's .planning):
   - `state.advance-plan` bumps only the Plan line's leading number, to `Plan: 30 of 35`, and keeps the `of 35` this edit wrote. Like every STATE write, it also resets `total_plans` and `completed_plans` from the files: 70 and 65.
   - `state.update-progress` writes the same 70 and 65 again.
   - `roadmap.update-plan-progress` writes 30/35 into the Plans line and the Progress row and ticks the 03-14b row.

   So main ends at `total_plans: 70`, `completed_plans: 65` and `Plan: 30 of 35`.
4. 03-12-PLAN.md:
   - `depends_on` becomes `["03-14b"]` [it reads the stale `["03-11"]`];
   - in its first `<precondition>`, add the clause `` `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md` exits 0 `` right before that first `</precondition>`, joined with `; `. Every other clause stays as it is.
5. Every phase-3 plan whose origin/main `wave:` is W12 or above gets `wave:` + 1: 03-12 to 03-16 [29–33] → 30–34. The stop guard ensures no other plan is there.
6. The pointer sentences above.

**After the tracking update** (the end of this task), check that GSD's roadmap update ticked only this plan's row: in Phase 3, every row other than the new 03-14b row is byte-identical to origin/main's, and the 03-12 to 03-16 rows are still `- [ ]`. An earlier tracking update ticked a plan by prefix (03-11b when 03-11 completed); here the prefix hazard is the 03-14 row. If another row was ticked, untick it with a scoped edit, record it in the SUMMARY, and rerun the ROADMAP gate below.

**Gates.** Run the test-time delta gate (Budget, Q-09-3) and the full gate. If this session or WSL boot is not the one that measured the base (after the continuation it never is), re-measure the base on origin/main in a detached worktree first, in place (Budget, "Another session"). `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**Push, the PR and the pre-merge review.**
1. Commit by path only, signed and authored as Daniel:
   - the runbooks, the transcript template and runbook_test.go (`docs(runbooks): check the policy block, the roots and the pop line before a root signs (F04, F14)`);
   - the publish edits and pointers (`docs(03-14b): publish the plan, point 03-12 to 03-15 at it, and shift the later waves`);
   - later, the SUMMARY.
2. Push the branch for the first time.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(root): show the policy in force, each changed field and the PoP switches before a root signs (F04, F14)"`. The body is neutral, lists the changes as in the objective, and names the limits that remain:
   - a custodian who reads neither the block nor the warning;
   - `--confirm`, which skips the read point;
   - bundle fields outside the policy, which are 03-12 to 03-14's;
   - threshold-1 installations, which have no co-signer.

   Do not enable auto-merge, now or later.
4. Wait for the required checks. Then run the house e2e gate in `MODE=pr` (the script between `# E2E_GATE_BEGIN` and `# E2E_GATE_END` of 03-10b-PLAN.md, with 03-11b's PROBE_PASS list): it requires the PR's e2e run to be for HEAD, both main lanes to pass at or under 900 s, and both probe lanes to pass. Confirm that both main lanes passed TestAuditLoginAcrossPolicyChange and that cli-windows and cli-macos passed (verify below). Record each main lane's `go test` seconds in the SUMMARY: the pin adds only assertions to an existing e2e test, so its time cost is negligible.
5. The orchestrator then runs the pre-merge review on the green PR, before Task 4.
   - It reviews the diff against T-03-329 to T-03-334, and that review is the owner's threat review.
   - A Codex lens may be part of it. Its input is `git diff origin/main...HEAD` and the PR's text only, never a ceremony folder, a passphrase file, `~/.ssh` or a planning file outside the repository.
   - It also checks the diff for host names and private terms, which this plan does not list.
   - Its review items, the fix rounds and their checks are recorded in the SUMMARY.

**The SUMMARY** contains:
- the PR number and the check run IDs;
- R1, T1 and T2, the RED evidence of Tasks 1 to 3, the additions-only check and the `Golden corrections` section;
- the mutants of Tasks 1 and 2 under the mutant rule, plus these runbook mutants:
  - the pop item removed from "Change the policy" (killed by `TestRootCeremonyPolicyChecks/change_the_policy_pop_item`);
  - the step-4 check removed from "Rotate the roots" (killed by `/rotation_step_4`);
  - the independence clause removed from the transcript row and from "You need" (killed by `/transcript_template` and `/change_the_policy_you_need`);
  - the Purpose row's edit reverted (killed by `/transcript_template`);
- TestSectionWindowRefusals' three fixtures, each refused by sectionWindow;
- the `test-time base:` line and the delta gate's readings of cmd/keyroster and internal/rootceremony (the whole-module run is pass or fail only);
- the main e2e lanes' seconds against the 900 s stop;
- that this plan corrected the totals that were stale on main at b4e6b4c:
  - the ROADMAP's Phase 3 total, `/33` against 34 plan rows and files;
  - STATE's `total_plans: 68` against 69 PLAN files;
  - STATE's `Plan: 28 of 30` against 29 executed of 34.

  Record the values after the tracking update: the Plans line `30/35 plans executed in 34 waves`, the Progress row `30/35`, `total_plans: 70`, `completed_plans: 65` and `Plan: 30 of 35`;
- every existing assertion that moved, and why;
- the execution-time runbook inventory;
- what stays UNVERIFIED:
  - every runbook check in a real ceremony;
  - policyChange's two error returns at its call sites (unreachable after the chain check; reasoned, not run);
  - checkBundleKeys's refusal on the successor path (tested on the genesis path only);
  - a successor built by a tool other than root sign;
- capslock, and the pre-merge review;
- `requirements-completed` left empty: AGENT-03 is complete and AGENT-06 is 03-09's; this plan hardens both.

Then run the tracking updates once, commit `docs(03-14b): complete ceremony-display plan`, push, and wait.
  </action>
  <verify>
    <automated>git diff --quiet HEAD -- docs/runbooks/root-ceremony.md docs/runbooks/ceremony-transcript-template.md docs/runbooks/host-setup.md docs/runbooks/machine-identities.md cmd/keyroster/runbook_test.go .planning/ROADMAP.md .planning/STATE.md .planning/phases/03-linux-agent-and-revocation/ && test -z "$(git ls-files --others --exclude-standard .planning/phases/03-linux-agent-and-revocation/03-14b-*.md)"</automated>
    <fails_when>non-zero exit: an edit to a file this plan publishes is not committed, so the content checks below would read the working tree instead of the commit. This guard runs first. It is path-scoped, because the intentionally dirty .planning files would fail a bare `git status --porcelain`</fails_when>
    <automated>bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^(TestRootCeremonyPolicyChecks|TestSectionWindowRefusals|TestHostSetupSignerCheck|TestHostSetupEffectiveSshdConfig)$" ./cmd/keyroster/'</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or any of these lines missing: "--- PASS: TestRootCeremonyPolicyChecks/genesis_step_4", "--- PASS: TestRootCeremonyPolicyChecks/rotation_step_3", "--- PASS: TestRootCeremonyPolicyChecks/rotation_step_4", "--- PASS: TestRootCeremonyPolicyChecks/change_the_policy_you_need", "--- PASS: TestRootCeremonyPolicyChecks/change_the_policy_step_3", "--- PASS: TestRootCeremonyPolicyChecks/change_the_policy_pop_item", "--- PASS: TestRootCeremonyPolicyChecks/change_the_policy_intro", "--- PASS: TestRootCeremonyPolicyChecks/hardware_variant", "--- PASS: TestRootCeremonyPolicyChecks/transcript_template", "--- PASS: TestRootCeremonyPolicyChecks/host_setup_pop", "--- PASS: TestRootCeremonyPolicyChecks/machine_identities_pop", "--- PASS: TestSectionWindowRefusals"</fails_when>
    <automated>( set -o pipefail; S=.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md; { test "$(grep -c '^test-time base: ' $S)" -eq 1 && T=$(sed -n 's/^test-time base: .* at=\([0-9][0-9]*\)$/\1/p' $S) && test -n "$T" && test $(( $(date +%s) - T )) -le 86400 || { echo 're-measure the base (Budget, test time)'; false; }; } && g() { sed -n "s/^test-time base: \(.* \)\{0,1\}$1=\([0-9.]*\) .*/\2/p" $S; } && CM=$(g cmd) && RC=$(g rootceremony) && test -n "$CM" && test -n "$RC" && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/rootceremony/' | awk -v m="$CM" -v r="$RC" '{print} $1=="ok" {t=$3; sub(/s$/,"",t); if ($2 ~ /\/cmd\/keyroster$/) {n++; if (t+0 > m+90) bad=1} else if ($2 ~ /\/internal\/rootceremony$/) {n++; if (t+0 > r+90) bad=1}} END{exit (n!=2||bad)}' )</automated>
    <fails_when>non-zero exit: the SUMMARY's single `test-time base:` line is missing, repeated or more than 24 h old (re-measure it in place, Budget), or the `ok` line of cmd/keyroster or internal/rootceremony is missing or more than 90 s above its base (stop and report, after a fresh re-measure confirms it), or "FAIL" or "DATA RACE" in the output (Q-09-3)</fails_when>
    <automated>grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./... && go vet ./... && go vet -tags keyroster_e2e ./internal/agent/... ./cmd/keyroster-agent/ && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e e2eprobe" ./test/e2e/ && go vet -tags "e2e e2emachine" ./test/e2e/ && go vet -tags "e2e e2eprobe e2emachine" ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && go vet -tags e2edistro ./test/distro/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit (a gate failed; the whole-module test run is pass or fail only, with no per-package time cap, Q-09-3), or "FAIL", "DATA RACE" or a golangci-lint issue line in the output. The vet tag list is the house list at b4e6b4c (03-11b's full gate)</fails_when>
    <automated>test "$(tr -s '[:space:]' ' ' < docs/runbooks/root-ceremony.md | grep -c 'the only field you can change this way')" -eq 0 && test "$(tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'but no test runs that command')" -eq 0</automated>
    <fails_when>non-zero exit: root-ceremony.md still holds the stale Phase 2 paragraph, or host-setup.md still says that no test runs trust verify --prev with a pop policy</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && fw() { awk 'NR>1 && /^---$/{exit} /^wave: /{sub(/^wave: /,""); print}'; } && MSYS_NO_PATHCONV=1 git cat-file -e "origin/main:$P/03-11b-SUMMARY.md" && test "$(MSYS_NO_PATHCONV=1 git show "origin/main:$P/03-12-PLAN.md" | fw)" = 29 && W28=$(for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do if MSYS_NO_PATHCONV=1 git show "origin/main:$f" | grep -qx 'wave: 28'; then basename "$f"; fi; done) && test "$W28" = 03-11b-PLAN.md && test "$(fw < $P/03-14b-PLAN.md)" = 29 && grep -qx 'depends_on: \["03-11b"\]' $P/03-14b-PLAN.md && grep -qx 'depends_on: \["03-14b"\]' $P/03-12-PLAN.md && grep -n '<precondition>' $P/03-12-PLAN.md | head -1 | grep -qF '`MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md` exits 0</precondition>' && ( for e in 03-12:30 03-13:31 03-14:32 03-15:33 03-16:34; do test "$(fw < "$P/${e%%:*}-PLAN.md")" = "${e#*:}" || exit 1; done ) && ( for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do W=$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw) || exit 1; test -n "$W" || exit 1; if [ "$W" -ge 29 ]; then E=$((W+1)); else E=$W; fi; test "$(fw < "$f")" = "$E" || exit 1; done ) && AP='^\.planning/phases/[^/]+/[^/]+-PLAN\.md$' && AS='^\.planning/phases/[^/]+/[^/]+-SUMMARY\.md$' && PP='^\.planning/phases/03-linux-agent-and-revocation/03-[0-9a-z]+-PLAN\.md$' && PS='^\.planning/phases/03-linux-agent-and-revocation/03-[0-9a-z]+-SUMMARY\.md$' && n() { git ls-tree -r --name-only "$1" -- .planning/phases/ | grep -cE "$2"; } && ( for r in "$AP" "$AS" "$PP" "$PS"; do H=$(n HEAD "$r") && M=$(n origin/main "$r") && test "$H" -eq $((M+1)) || exit 1; done ) && ST=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/STATE.md) && printf '%s\n' "$ST" | grep -qx '  total_plans: 68' && printf '%s\n' "$ST" | grep -qx '  completed_plans: 64' && printf '%s\n' "$ST" | grep -qx 'Plan: 28 of 30' && test "$(grep -c '^  total_plans: ' .planning/STATE.md)" -eq 1 && grep -qx "  total_plans: $(n HEAD "$AP")" .planning/STATE.md && test "$(grep -c '^  completed_plans: ' .planning/STATE.md)" -eq 1 && grep -qx "  completed_plans: $(n HEAD "$AS")" .planning/STATE.md && test "$(grep -c '^Plan: ' .planning/STATE.md)" -eq 1 && grep -qx "Plan: $(n HEAD "$PS") of $(n HEAD "$PP")" .planning/STATE.md</automated>
    <fails_when>non-zero exit: the stop guard fails on origin/main (03-11b's SUMMARY missing, 03-12 not at wave 29, or a plan other than 03-11b at wave 28: re-reconcile, publish nothing), or a publish edit is missing or wrong. It passes only on exactly the intended edit:
      - this plan's frontmatter reads `wave: 29` and `depends_on: ["03-11b"]`;
      - 03-12 reads `depends_on: ["03-14b"]`, and its first precondition ends with the new MSYS_NO_PATHCONV=1 clause;
      - 03-12 to 03-16 read waves 30 to 34; every other phase-3 plan on origin/main kept its frontmatter wave (each wave is read from the frontmatter only);
      - HEAD holds exactly one more PLAN file and one more SUMMARY file than origin/main, both in phase 3 (counted in the tree of HEAD, top-level phase directories only);
      - origin/main's STATE held the stale b4e6b4c values `total_plans: 68`, `completed_plans: 64` and `Plan: 28 of 30`, and the branch's STATE holds exactly one line of each, with the true counts of HEAD's files: `total_plans: 70`, `completed_plans: 65` and `Plan: 30 of 35` (phase 3's SUMMARY files of its PLAN files).

      The gate counts files in HEAD's tree, and GSD's tracking update counts them on disk. An untracked PLAN or SUMMARY file under .planning/phases therefore shows up as a mismatch, which is right: that number would be wrong on main. Run it after the tracking update; before that update `completed_plans` reads 64 and the Plan line 29 of 35, and the gate fails by design
    </fails_when>
    <automated>ROW='- [x] 03-14b-PLAN.md — Show what a root signs (F04, F14): the policy in force and each changed field before a successor is signed or verified, a warning for hand-written changes, and the PoP switches in every ceremony summary' && E=$(mktemp) && { MSYS_NO_PATHCONV=1 git show origin/main:.planning/ROADMAP.md | awk -v row="$ROW" '/^### Phase /{p=($0 ~ /^### Phase 3:/)} p && /^\*\*Plans:\*\* 29\/33 plans executed in 33 waves\./ {sub(/29\/33 plans executed in 33 waves/, "30/35 plans executed in 34 waves"); np++} p && /^\*\*Wave [0-9]+\*\* \*\(blocked on Wave [0-9]+ completion\)\*$/ {w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; if (w==29) {print "**Wave 29** *(blocked on Wave 28 completion)*"; print row; print ""; ni++} if (w>=29) {$0="**Wave " (w+1) "** *(blocked on Wave " w " completion)*"; nw++}} /^\| 3\. Linux Agent and Revocation \| 29\/33 \|/ {sub(/\| 29\/33 \|/, "| 30/35 |"); nr++} {print} END{exit (np!=1 || ni!=1 || nw!=5 || nr!=1)}' > "$E"; } && diff "$E" .planning/ROADMAP.md; rc=$?; rm -f "$E"; test "$rc" -eq 0</automated>
    <fails_when>non-zero exit: the ROADMAP differs from the exact intended file. The gate builds it from origin/main's ROADMAP (which must hold the b4e6b4c base: the Phase 3 Plans line `29/33 plans executed in 33 waves`, Wave blocks 29 to 33, and the Progress row `29/33`), and compares whole files:
      - the Plans line reads `30/35 plans executed in 34 waves`, and the Progress row `| 30/35 |`: the true counts of phase 3's SUMMARY and PLAN files, which the publish gate checks against HEAD's tree, with the wave count 34 that no tool touches;
      - a new `**Wave 29** *(blocked on Wave 28 completion)*` block holds exactly the ticked 03-14b row, right before 03-12's block;
      - the former blocks 29 to 33 read 30 to 34, each blocked on the wave before;
      - every other line is byte-identical, so no other row was ticked (the 03-12 to 03-16 rows stay `- [ ]`) and nothing matched by prefix.

      Run it after the tracking update, which ticks the 03-14b row and sets the executed count; before that update the row reads `- [ ]` and the count 29, and the gate fails by design</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && ns(){ N=$(git diff --numstat origin/main...HEAD -- "$P/$1") || return 1; printf '%s\n' "$N" | awk '{print $1" "$2}'; } && test "$(ns 03-12-PLAN.md)" = "4 4" && test "$(ns 03-13-PLAN.md)" = "2 2" && test "$(ns 03-14-PLAN.md)" = "2 2" && test "$(ns 03-15-PLAN.md)" = "4 4" && test "$(ns 03-16-PLAN.md)" = "1 1" && test "$(grep -oF 'See 03-14b-PLAN.md.)' $P/03-12-PLAN.md | wc -l)" -eq 1 && test "$(grep -oF 'See 03-14b-PLAN.md.)' $P/03-13-PLAN.md | wc -l)" -eq 1 && test "$(grep -oF 'See 03-14b-PLAN.md.)' $P/03-14-PLAN.md | wc -l)" -eq 1 && test "$(grep -oF 'see 03-14b-PLAN.md' $P/03-15-PLAN.md | wc -l)" -eq 3 && grep -qF 'proven end to end with a login loop that never fails. (Since 03-14b:' $P/03-12-PLAN.md && grep -qF 'kills its certificates at once. (Since 03-14b:' $P/03-13-PLAN.md && grep -qF '(BREAK-01, D-13). (Since 03-14b:' $P/03-14-PLAN.md && grep -qF "which proves the comparison the owner makes in Task 3. (Since 03-14b," $P/03-15-PLAN.md && grep -qF 'CA next line) (since 03-14b also the policy block' $P/03-15-PLAN.md && grep -qF "and that the admin lines match v3's admins (since 03-14b," $P/03-15-PLAN.md</automated>
    <fails_when>non-zero exit: a later plan changed beyond its wave line and its pointer lines. The expected line counts are:
      - 03-12: 4 4 (wave, depends_on, precondition, pointer);
      - 03-13 and 03-14: 2 2 (wave, pointer);
      - 03-15: 4 4 (wave, three pointer lines);
      - 03-16: 1 1.

      The check also fails when a pointer is missing, repeated or not right after its anchor. If the guard shifted another plan, that plan must show 1 1, which the wave check above already implies; record its numstat in the SUMMARY</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')" && RL=$(git rev-list origin/main..HEAD) && test -n "$RL" && ( for c in $RL; do C=$(git cat-file commit "$c") || exit 1; printf '%s
' "$C" | grep -q '^gpgsig' || exit 1; done )</automated>
    <fails_when>non-zero exit (the branch has no commits, a commit has another author or a committer other than keyroster-bot, or a commit is unsigned)</fails_when>
    <automated>git fetch origin p03/14b-ceremony-display && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-14b-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics|^\.planning/todos/'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, a forbidden file was committed, or a todo file was added)</fails_when>
    <automated>D=$(git diff origin/main...HEAD) && L=$(git log origin/main..HEAD --format=%B) && B=$(scripts/gh-as-bot.sh pr view p03/14b-ceremony-display --json body,title --jq '.title + "\n" + .body') && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '127\.0\.0\.1' | grep -q . && printf '%s\n%s\n' "$L" "$B" | grep -ciE 'co-authored-by|generated with' | grep -qx 0 && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -iqE 'find[i]ngs[.]json|FIND[I]NGS[-]DETAIL|FIX[-]PLAN|security[-]audit[-]skill|scratch[p]ad|App[D]ata' && PR_TITLE="$(scripts/gh-as-bot.sh pr view p03/14b-ceremony-display --json title --jq .title)" bash scripts/check-pr-title.sh</automated>
    <fails_when>non-zero exit: an IP address other than loopback is in the diff, a commit message or the PR title or body; an attribution line is present; a private planning artefact or a local temporary path is named; or the PR title is not Conventional Commits within 100 characters</fails_when>
    <automated>B=p03/14b-ceremony-display && scripts/gh-as-bot.sh pr checks "$B" --required --watch && test "$(scripts/gh-as-bot.sh pr checks "$B" --json name,bucket --jq '[.[] | select(.name=="cli-windows" or .name=="cli-macos") | .bucket] | sort | join(" ")')" = "pass pass" && G=$(mktemp) && sed -n '/^# E2E_GATE_BEGIN/,/^# E2E_GATE_END/p' .planning/phases/03-linux-agent-and-revocation/03-10b-PLAN.md > "$G" && B="$B" PROBE_PASS='TestProbeSelfTestEndToEnd TestProbePairSpacing TestProbeCertsAgainstSSHD TestProbeSSHDFacts TestMachineIdentityEndToEnd TestMachineIdentityEndToEnd/renew_and_login TestMachineIdentityEndToEnd/collapse_is_generic TestMachineIdentityEndToEnd/if_due_sends_nothing TestMachineIdentityEndToEnd/revoke_machine_refuses_login_and_renewal TestMachineIdentityEndToEnd/keys_revokes_key_for_good TestMachineIdentityEndToEnd/sk_through_agent TestMachineIdentityEndToEnd/sk_key_file_named_error TestMachineIdentityEndToEnd/audit_verify_counts_machine_certificates' MODE=pr bash "$G"; rc=$?; rm -f "$G"; test "$rc" -eq 0 && R=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch "$B" --event pull_request --limit 1 --json databaseId --jq '.[0].databaseId // 0') && test "$R" -gt 0 && test "$(scripts/gh-as-bot.sh run view "$R" --json headSha --jq .headSha)" = "$(git rev-parse HEAD)" && JOBS=$(scripts/gh-as-bot.sh run view "$R" --json jobs --jq '.jobs[] | [(.databaseId|tostring), .conclusion, .name] | join("\t")') && for L in 9.5p1 10.5p1; do ID=$(printf '%s\n' "$JOBS" | awk -F'\t' -v n="e2e ($L)" '$3 == n {print $1}'); test -n "$ID" || { echo "no main lane $L"; exit 1; }; LOG=$(scripts/gh-as-bot.sh run view "$R" --job "$ID" --log); printf '%s\n' "$LOG" | grep -qF -- '--- PASS: TestAuditLoginAcrossPolicyChange (' || { echo "main lane $L: no PASS line of TestAuditLoginAcrossPolicyChange"; exit 1; }; done</automated>
    <fails_when>non-zero exit: a required check failed or never reported; cli-windows or cli-macos did not pass (the goldens on Windows and macOS); the house e2e gate in MODE=pr failed (the PR's pull_request e2e run is not for HEAD, a main lane failed, ran a probe test or took over 900 s, or a probe lane failed, lacks one of 03-11b's PASS lines or took over 420 s); or a main lane (9.5p1 or 10.5p1) lacks the `--- PASS: TestAuditLoginAcrossPolicyChange (` line. `B` is passed to the gate script as a prefix assignment because the script reads it from its environment</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/14b-ceremony-display --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled on the PR)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new runbook text names at least one CI test, and an UNVERIFIED label that says what, if anything, will run it.
    - The SUMMARY records:
      - the RED of every TestRootCeremonyPolicyChecks subtest on origin/main's runbooks;
      - the four runbook mutants, each with its `--- FAIL:` line;
      - the runbook inventory.
    - `git log origin/main..HEAD --format='%an <%ae> %cn'` prints at least one line, every line is `Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot`, and every commit carries a signature.
    - The PR is open without auto-merge, and every required check is green. cli-windows and cli-macos passed, the house e2e gate passed in MODE=pr for HEAD with both main lanes at or under 900 s, both main lanes passed TestAuditLoginAcrossPolicyChange, and 03-14b-SUMMARY.md is on its head.
    - The test-time delta gate passed against a base at most 24 h old, and the ROADMAP gate passed after the tracking update.
    - The pre-merge review's results and fix rounds are in the SUMMARY.
  </acceptance_criteria>
  <done>The PR waits green and reviewed. It carries:
    - the plan;
    - the runbook checklists, with their section helper and the transcript row;
    - the pointer sentences in 03-12 to 03-15;
    - the publish edits: this plan at wave 29 after 03-11b, and 03-12 to 03-16 one wave later (30 to 34).
  </done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — the owner reviews PR p03/14b-ceremony-display, and Daniel squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7), read with this plan's Delivery protocol override (merge-gate.sh's plain form only after the merge)
  </read_first>
  <action>After the pre-merge review (Task 3 step 5), the owner reviews, approves and squash-merges the PR in the GitHub web UI (owner, 2026-11-02). Claude never approves or merges, never enables auto-merge and never waits for it.</action>
  <instructions>
    1. Open `gh pr view p03/14b-ceremony-display --web`. Read 03-14b-SUMMARY.md, and review:
       - policydiff.go;
       - the pop lines in rootceremony.Summary;
       - the two call sites in root.go and trust.go;
       - the goldens (they are the display);
       - the runbook checklists;
       - the pointer sentences.

       Check especially:
       - the block's base is the prevPolicy that loadPrev returned, used only after BuildSuccessor or VerifySuccessor;
       - no file under internal/trust, internal/signer or internal/audit changed;
       - the successor_added_admin golden shows the WARNING line, `admins: CHANGED` and `ca_profiles user: CHANGED`;
       - the successor_pop golden shows the one-way line and no WARNING line.
    2. Approve and squash-merge in the GitHub web UI, with your commit email. No admin bypass, no "Update branch".
    3. Reply "merged". If main moved before you merged, Claude rebases the branch by hand and pushes it. Review the new head, then merge it and reply "merged".
  </instructions>
  <verification>
    - **Before the merge.** Claude runs merge-gate.sh only as `bash scripts/merge-gate.sh --check p03/14b-ceremony-display`, which is read-only and exits 1 while the PR is open. It never runs the plain form before the merge.
    - **When main moved.** If `git merge-base --is-ancestor origin/main origin/p03/14b-ceremony-display` fails after `git fetch origin`, Claude rebases by hand:
      - On the branch, run `git rebase --gpg-sign origin/main`. The authors stay Daniel's, and keyroster-bot is committer and signer.
      - For `.planning/` tracking files, take origin/main's version and re-apply only this plan's entries, as 01-SKELETON step 5's exit 4 describes. For the runbooks, keep main's text and re-apply this plan's updates.
      - If main changed what root sign or trust verify print, regenerate the goldens with `-update-golden`. `diff old new` may then show no removed line except lines that main's change names. Record it.
      - Push with lease, as keyroster-bot, and do not enable auto-merge.
      - Wait for the required checks, run Task 3's authorship and signature check again, and ask the owner to review the new head.
    - **After the owner replies "merged".** From the main checkout, Claude runs `bash scripts/merge-gate.sh p03/14b-ceremony-display`; the script refuses to run as any copy but origin/main's. For a merged PR it only fast-forwards local main and exits 0. Then Claude runs the `--check` form below.
  </verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/14b-ceremony-display</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-12's new precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/14b-ceremony-display --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>On main, every custodian of a successor sees the policy in force, what changed, and a warning for hand-written changes. Every summary shows the pop switches. 03-12 may start.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-09 to 03-11b** (03-09, 03-09b, 03-10, 03-10b, 03-10c, 03-10d, 03-11 and 03-11b) land first; all are on main at b4e6b4c.
  - They edit host-setup.md and machine-identities.md. Task 3 finds its places there by anchor, and Task 1's precondition stops if an anchor is gone.
  - They add test files to package main. Task 1's precondition checks this plan's helper and test names against them.
  - The pop wording relies on 03-09, 03-09b and 03-10 (host and probe certificates under pop.hosts) and 03-11 and 03-11b (machine renewals under pop.machines).
- **03-12, 03-13 and 03-14** land after this plan (Q-B3). Each carries a fixed pointer sentence with these duties:
  - render its new bundle fields and states in every ceremony summary, root sign and trust verify alike, the carried and absent states included;
  - 03-12 adds a reflect gate that Summary's output, compared with its `Bundle SHA-256:` line removed, changes for every exported field of trust.Bundle and its nested types; 03-13 and 03-14 extend it. 03-12 records how InstallationID is handled: a Summary line, or a named gate exception that points at installationLine and 03-14c;
  - every new successor-signing runbook section gets this plan's checklist and an entry in `successorSigningSections`;
  - this plan's goldens change by additions only, visible in the PR diff, and the policy block stays the last thing before the prompt.

  checkInvariants holds them to that last point. A regenerated golden whose `diff old new` shows a removed or changed line breaks the rule. Such a line needs an owner decision, recorded in that plan's check and SUMMARY.

  Their files_modified lists name cmd/keyroster/root_test.go but none of the files these duties touch:
  - cmd/keyroster/testdata/ceremony/;
  - ceremony_golden_test.go;
  - internal/rootceremony/summary_test.go and its testdata;
  - cmd/keyroster/runbook_test.go.

  Their own plan checks, or their executors as a recorded deviation, must widen files_modified and any task-scope gate to these files. As read at f7eb018, and again at b4e6b4c, they have no broad scope gate; 03-12's only gate is on internal/agent/apply/swap.go. The pointer sentence names the duty, not the file list, because the owner scoped the edit to one sentence per plan. The same holds for 03-15: its own plan check, or its executor as a recorded deviation, adds cmd/keyroster/runbook_test.go to its files_modified for its section-helper entry.
- **03-14c** (installation binding, before 03-15, not yet on main) is expected to be slotted right after this plan.
  - It then extends the goldens by the same additions-only rule.
  - It is the owner of an installation-ID line in trust verify (render-05).
  - It must keep TestCeremonyGolden, both field gates and TestRootCeremonyPolicyChecks green.
  - If it, or any other plan, lands before this plan instead, it takes wave 29 or moves 03-12, so the stop guard (Task 1's first precondition, re-run as publish edit 0) stops this plan for a re-reconcile, and a change to a file in Task 1's b4e6b4c diff list stops it too. This plan is never re-slotted silently.
- **03-15** consumes the block and the pop line. Its v4 ceremony rotates the roots and sets pop.hosts and pop.machines (D-01), so:
  - the owner's check reads `pop: CHANGED (none) -> hosts=true machines=true` with the one-way line, no WARNING line, and every other field `carried over`;
  - the roots are compared with paper, as in a rotation; the roots item of the policy-change list does not apply, and the installation line reads `(new in this version)`.

  Its new root-ceremony.md section must carry this plan's checklist and an entry in the section helper. The three advisory pointers say so. TestRootCeremonyPolicyChecks pins the sections `Change the policy`, `Rotate the roots`, `4. Sign with root A` and `Hardware-root variant`; 03-15 must keep them, or update the test in the same PR.
- **03-16** changes only its wave.
- **Phase 4 (AUTHZ-03)**, the quorum-gated policy change, writes fields that root successor-policy does not. It must reword or retire the WARNING line, and can reuse changedPolicyFields.
- **A later plan that adds a policy field** fails TestPolicyFieldsCovered and TestSummaryFieldsCovered until the field has a diff line, a case and a Summary line.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: what the block can and cannot show.**
- **What it shows.** It shows every field of the successor policy against the policy in force that the bundle pinned by `--prev-sha256` names, and warns about fields only a hand-written policy changes. It does not show whether a change was agreed. The transcript's `Agreed policy change` row and the custodian decide that.
- **`--confirm`.** It skips the read point, and the runbook tells every custodian to remove it.
- **Threshold 1.** There is no co-signer, and the block only helps the one holder avoid a mistake.
- **The roots of a policy change.** The tool shows the previous roots (header) and the new roots (summary) as values, without a change marker. The checklist compares them before signing. In a rotation the new roots are also compared with paper before signing; in a policy change they must equal the roots in force. Whether the tool should mark a root-set change itself is deferred (T-03-334).
- **CA, ops and log keys.**
  - VerifySuccessor does not require them to be carried over.
  - root sign builds them from prev (BuildSuccessor), or later from 03-12 and 03-13's explicit flags, and refuses a stored bundle that differs (prepareBundle).
  - install-bundle refuses keys the signer does not hold: checkBundleKeys runs after both the genesis and the successor branch, and at start. That is tested on the genesis path (TestInstallBundleRefusals), and UNVERIFIED by test on the successor path.

  So this is not a co-signer gap. trust verify --prev prints these keys as values. The pointer duty is to render each new bundle field and state in Summary, which trust verify prints too. Old-to-new change lines in trust verify --prev are not a pointer duty and stay deferred.
- **The installation ID.** trust verify, in both modes, prints no installation ID; only root sign does (installationLine). A successor that adds one is shown to its signers, not to a verifier. Not covered here; owner 03-14c.
- **Hardware.** No hardware is involved anywhere: seeded software keys in an in-memory agent drive every test.

**Edges:**
- **policy:**
  - unchanged (two lines);
  - a version bump only (all carried over, no warning);
  - each field alone (the table, with leaf honesty);
  - every field at once (golden);
  - the F04 shape, for the first signer and for a co-signer in an out-dir that already holds the bundle.
- **warning:** present exactly for admin_quorum, admins, ca_profiles and timelock_seconds; absent for webauthn and pop.
- **CHANGED without the warning (Q-B1's set):** a hand-written pop.machines true→false (machine-identities.md says no flag clears it, so only a hand-written successor does), or a removed or changed RP, prints CHANGED without the WARNING. internal/trust's chain rule has no rp_id successor rule at b4e6b4c; only a running keyroster-server refuses an RP that differs from the one it started with (internal/server/signer.go). The checklist's "only the agreed change" item and its RP item cover both. No code or test change: the `PoPPolicy.Machines`, `Policy.PoP_removed`, `WebAuthnRP.RPID` and `Policy.WebAuthn` cases already pin the display.
- **admins:** added, removed, renamed, key replaced under the same name, reordered only, all replaced.
- **CA profiles:** every sub-field; the host profile by TTL only (Validate forbids extensions there).
- **webauthn:** added, rp_id changed (one-way marker), origins only, removed.
- **pop:**
  - none to hosts (one-way line), and none to hosts and machines (03-15's shape);
  - machines changed with hosts true on both sides (no one-way line);
  - none to machines only, and machines only to none;
  - the summary for none, hosts and machines, and machines only.
- **durations:** within and above the Duration bound.
- **base:** a --prev policy.json that its own roots signed but its bundle does not name is refused before any block, by root sign and by trust verify.
- **layout:** the block is the last thing before root sign's prompt, after trust verify's summary and before its signer lines; there is exactly one summary pop line, between webauthn and timelock.
- **platforms:** the cmd/keyroster goldens run on Linux, and on Windows and macOS through cli-windows and cli-macos.
- **the controls that must not change:**
  - TestRootSignSuccessor, TestTrustVerifySuccessor, TestRootSuccessorPolicyPoP and TestRootSignAccumulates;
  - TestExportedAPI;
  - the e2e rotation and bootstrap tests;
  - the tests 03-09 to 03-11b added.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access granted or rotated centrally takes effect across the fleet: what the roots sign is what their holders reviewed | Tasks 1-3 |
| REQ | AGENT-03 (hosts apply only policy the pinned roots signed) | Task 1 (the block in both commands), Task 2 (field gate), Task 3 (runbooks) |
| REQ | AGENT-06 (host certificates by PoP, gated by pop.hosts) | Task 1 (the pop line, the pop diff with the one-way line), Task 3 (host-setup.md) |
| F04 | The policy in force (version, sha256) in root sign --prev and trust verify --prev | Task 1 (`Policy in force:`, goldens, invariants) |
| F04 | A diff of every policy field, unchanged fields marked carried over | Task 1 (contract, goldens), Task 2 (both gates, TestPolicyChangeFields, TestPolicyChangeAdmins), Task 1 (TestSummaryFieldsCovered) |
| F04 | The co-signer's checklist checks the diff, not only the webauthn line and the hash | Task 3 (genesis, rotation steps 3 and 4, policy-change step 3, hardware variant; section helper) |
| F14 | Summary renders policy.pop and marks pop.hosts one-way, for root sign genesis and --prev and for trust verify | Task 1 (summary.go, TestSummaryGolden, TestSummaryFieldsCovered, goldens) |
| F14 | The runbook makes pop a mandatory check line, as rp_id is | Task 3 (pop item, genesis step, host-setup.md, machine-identities.md; section helper) |
| Owner request | Golden-output tests, RED first, mutants that drop a diff line or the pop line | Task 1 (R1/T1, worktree RED, mutant rule), Task 2 |
| Owner decision | Q-B1: a warning line, no flag; `--confirm` named; the agreed change has an independent source | Task 1 (warning), Task 2 (warning rule cases), Task 3 (checklist, transcript row) |
| Owner decision | Q-B2: three advisory pointers in 03-15, numstat recomputed, MSYS prefix on the new clause | Task 3 (pointers, numstat gate, the 03-12 clause) |
| Owner decision | Q-B3: early slot before 03-12, with duties for 03-12, 03-13 and 03-14 (after 03-11b since owner OQ-1 split 03-11) | Frontmatter (wave 29, depends_on ["03-11b"]); Task 1 (stop guard); Task 3 (publish edits, pointers, exact publish and ROADMAP gates); Cross-plan notes |
| Owner decision | Q-09-3: `-timeout 15m` on every go test gate, a delta over a quiet base at most 24 h old, stop at +90 s | Budget; Task 1 (base line); Task 3 (delta gate, full gate pass or fail); `-timeout 5m` on every mutant |
| Owner decision | Fix home; plan in its PR; neutral wording with F-numbers only; signed commits; no auto-merge | Delivery protocol; Task 3; Task 4 |
| Owner decision | Outside review on the repository diff only | Task 3 step 5 |
| Owner decision | Hardware never required; untested paths labelled UNVERIFIED | Edge Coverage; Task 3 SUMMARY list; runbook labels |
| CONTEXT | 03-CONTEXT D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 3 |
| CONTEXT | 03-CONTEXT D-01 (one real v4 ceremony carries the Phase 3 fields, pop included) | Q-B2 pointers; Cross-plan notes |
| Owner decision | pop.hosts one-way (2026-10-24); rp_id one-way (Phase 2 D-09) | Contract one-way lines; no rule change |
| Deferred | A tool-side root-set marker; a bundle-field diff in trust verify (03-12 to 03-14); trust verify's installation ID (03-14c); a successor-path test of checkBundleKeys; a semantic restriction of successor policies | Review Feedback Deferred |

## Artifacts this phase produces (this plan)

- **cmd/keyroster:**
  - policydiff.go (policyChange, changedPolicyFields, the warning line);
  - the block in runRootSign and verifySuccessorBundle;
  - successorBuilder hands prevPolicy on.
- **internal/rootceremony:** the pop line in Summary.
- **Tests:**
  - TestCeremonyGolden (11 subtests, 10 goldens, invariants);
  - TestSummaryGolden (3 goldens) and TestSummaryFieldsCovered;
  - TestPolicyFieldsCovered, TestPolicyChangeFields, TestPolicyChangeAdmins, TestPolicyChangeUnchanged, TestPolicyChangeDurations, TestPolicyChangeInvalid and TestPolicyBlockBase;
  - TestRootCeremonyPolicyChecks, with successorSigningSections;
  - the real-binary pin in TestAuditLoginAcrossPolicyChange.
- **Docs:**
  - root-ceremony.md: the genesis, rotation (steps 3 and 4), policy-change and hardware-variant checks, and the corrected scope paragraph;
  - ceremony-transcript-template.md: the `Agreed policy change` row and the policy-change purpose;
  - host-setup.md and machine-identities.md: the pop checks.
- **Planning:**
  - 03-12 to 03-16 one wave later;
  - 03-12's dependency and precondition clause;
  - the pointer sentences in 03-12, 03-13, 03-14 and 03-15.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| proposing custodian → co-signing custodian | The successor policy.json, and the roots file, are prepared by one custodian and signed by others. What root sign --prev shows must let each signer see what the root signature will vouch for, and what changes against the documents in force |
| transfer medium → ceremony tool | `--prev` holds the documents in force. Only the bundle hash from the transcript (`--prev-sha256`) authenticates them, and the policy in force is authentic only once the chain check has bound it to that bundle |
| ceremony tool → terminal | Values from a document someone else prepared are printed for a human to judge |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-329 | Elevation of privilege | root sign --prev and trust verify --prev: a co-signer is shown the successor policy but not the policy in force or what changed. An added admin, a lowered quorum or a widened CA profile in a hand-written successor reads like a carried-over value (F04) | medium | mitigate | The policy block in both commands, for the first signer and every co-signer: the policy in force (version, sha256), every field marked `CHANGED` with old and new values or `carried over`, and a fixed WARNING line for fields root successor-policy never writes (Q-B1). The checklist tells each custodian to remove `--confirm` and to answer no when any field other than the agreed change, as the transcript records it, reads `CHANGED`. Tests: TestCeremonyGolden (`successor_added_admin/*`, `successor_every_field`), the invariants, TestPolicyChangeFields, TestPolicyChangeAdmins, TestRootCeremonyPolicyChecks, and their mutants. **Residual:** a custodian who reads neither the block nor the warning, or who signs with a proposer-supplied `--confirm`. VerifySuccessor still accepts any root-signed change at version + 1, unchanged by design; quorum-gated changes are AUTHZ-03. At threshold 1 there is no co-signer |
| T-03-330 | Tampering | rootceremony.Summary omits policy.pop, so a root holder confirms the one-way pop.hosts switch, or a machine-renewal switch, without being shown it (F14) | low | mitigate | Summary renders `pop: none (...)` or `pop hosts=… machines=…`, with the one-way line when hosts is true. The policy block marks a pop change with its one-way line. The runbook makes the pop line a mandatory check, like rp_id. Tests: TestSummaryGolden, TestSummaryFieldsCovered, `genesis_pop/*` and `successor_pop/*`, the pop-line invariant, the `change_the_policy_pop_item` and `genesis_step_4` checks, and the pop mutants. **Residual:** a holder who does not read the line |
| T-03-331 | Spoofing | the block's base: a `--prev` policy.json that is not the policy the pinned bundle names, re-signed by its own roots, would make the block compare against a policy chosen by whoever prepared the transfer medium | medium | mitigate | The block takes only loadPrev's prevPolicy. Both commands print it only after BuildSuccessor or VerifySuccessor, whose checkSuccessorChain requires `SHA256Hex(prevPolicy) == prev.PolicySHA256`, with prev pinned by `--prev-sha256`. Tests: TestPolicyBlockBase (`root_sign`, `trust_verify`) and its two mutants, one per command. **Residual:** a wrong `--prev-sha256` in the transcript; that is the existing rule of the rotation runbook |
| T-03-332 | Tampering | the renderers themselves (this plan's own risk): a field shown `carried over` while it changed, or not shown at all in the block or in Summary, including a field a later plan adds | medium | mitigate | changedPolicyFields compares every field; the policies are canonical, so a value comparison is exact. TestPolicyFieldsCovered and TestSummaryFieldsCovered walk every type reachable from trust.Policy and require a diff case and a Summary difference per field. Leaf honesty keeps a case from passing on another field's change. The goldens were committed RED before the fix and regenerate without drift, and the invariants hold the block's and the pop line's places independently of the goldens. Mutants drop each comparison. **Residual:** a comparison wrong in a way no case covers |
| T-03-333 | Spoofing | terminal output: a value in a prepared policy that fakes a `carried over` line (a newline or control characters) | low | accept | Only validated values are rendered. trust.ParsePolicy runs Validate before either command prints anything: admin names are limited to a-z, 0-9, `.`, `_` and `-`; keys are canonical and shown as fingerprints; rp_id follows the DNS label grammar; origins are exactly https://rp[:port]; roles, extensions and options come from closed sets; the rest are numbers and booleans. Accepted: no free text from a policy reaches the terminal, and policydiff.go's doc comment says that this rests on Validate |
| T-03-334 | Elevation of privilege | a root or a lower threshold slipped into a policy-change ceremony, whose roots file the proposer prepares (the policy-change section reuses the roots in force) | medium | mitigate | The policy-change checklist requires the `Root keys (threshold t of n)` lines to equal the `Previous root keys (threshold t of n)` lines and the paper, and no installation line marked `(new in this version)`, before signing; pinned by `change_the_policy_step_3`. A combined rotation and policy change follows its own section: it compares the new roots with paper as a rotation does and checks the policy items of the policy-change list, and this roots item does not apply there (pinned as `do not apply there`). **Residual:** the tool marks no root-set change itself, so this rests on the custodian reading the two lists (deferred) |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added. reflect and flag are stdlib and used in tests only. The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes, locally (scripts/linux.sh) or in CI as stated, and the full gate passes.
- The PR's required checks are green, with cli-windows, cli-macos and the e2e pin passing.
- R1's RED is reproducible from its worktree.
- The pre-merge review is recorded, and the merge gate passes.
</verification>

<success_criteria>
- Before confirming a successor, every custodian sees, as the last thing before the prompt:
  - the policy in force (version, sha256);
  - for every policy field, whether it is carried over or `CHANGED`, with its old and new values;
  - a warning when a change could only have been written by hand.

  trust verify --prev shows the same.
- Every ceremony summary, genesis and successor, signing and verifying, shows the pop switches and marks pop.hosts as one-way.
- The display is pinned byte for byte by goldens that were committed RED before the fix, and by invariants that do not depend on them. A missing diff line, pop line, one-way note or warning, and a new policy field without a diff line or a Summary line, each fail a named test.
- The runbooks make the policy block, the warning, the roots and the pop line mandatory checks in every successor and genesis signing section that exists. They name the agreed change's source and the `--confirm` hazard. One section helper keeps them, and later plans extend it.
- Nothing that is signed, no flag, and no rule any verifier applies changes. No module is added, and no hardware is needed.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md` in Task 1 as a draft, with its `## Golden corrections` section, and complete it in Task 3, before the merge gate. Leave `requirements-completed` empty: AGENT-03 was completed by earlier plans and AGENT-06 belongs to 03-09; this plan hardens both. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (F04 and F14; the owner's fix home of 2026-10-29)

| Item | How Addressed |
|------|---------------|
| F04: root sign --prev and trust verify --prev never show the policy in force or which fields changed; the runbook's checklist names only the webauthn line and a proposer-supplied hash | Task 1 (the block, the warning), Task 2 (gates), Task 3 (checklist); T-03-329, T-03-331, T-03-332 |
| F14: the summary never renders policy.pop; pop.hosts is one-way; 03-15's checklist names a pop line that does not exist | Task 1 (the pop line, TestSummaryFieldsCovered), Task 3 (mandatory check, 03-15 pointers); T-03-330 |

### Round 0b — planner self-review while drafting (2026-11-05), before plan check 1

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Random keys and a fresh genesis installation ID would make goldens unstable | MAJOR | Seeded keys; vector public keys; a prev built and signed in the test with a fixed ID; genesis normalised |
| Windows and macOS lanes run ./cmd/keyroster/... | MEDIUM | No path in any golden; `.gitattributes` keeps LF; Task 3 checks both lanes |
| A diff against an unauthenticated policy would hide changes | MEDIUM | Printed only after the chain check; TestPolicyBlockBase; T-03-331 |
| The comment-text rule | LOW | Negative greps use fragments the actions describe by concept; character classes in the private-artefact pattern, so the plan does not match itself |

### Round 1 — plan check 1 (2026-11-05, FAIL, fixable) and the owner's answers to Q-B1, Q-B2 and Q-B3 (Daniel, 2026-11-05)

| Review item | Severity | How Addressed |
|---------|----------|---------------|
| render-01: the gate does not require a Summary line per policy field | MAJOR | TestSummaryFieldsCovered in Task 1 (critic-03's placement, so Task 2's scope gate holds), RED for the three PoP fields on R1; mutant 4 (timelock line); gate messages and T-03-332 name it |
| render-02 + tests-03: PoPPolicy.Machines not isolated; no case with hosts true on both sides | MAJOR (merged) | `PoPPolicy.Machines` on its own base {true,true} → {true,false}; `Policy.PoP_added` and `Policy.PoP_removed`; leaf honesty for leaf keys (narrowed per the verdict, RPID excepted); Task 2 mutants 8 and 9 |
| render-03: `vN` is ambiguous after a rotation | MINOR | Merged into the rewritten policy-in-force bullet (the policy version, lower than the bundle version after a rotation) and the 03-15 pointers ("the policy of bundle v3, policy v2 on the homelab"); the contract header is unchanged (optional part not taken: no ambiguity in what the tool prints) |
| render-04 + threat-02: Q-B1 lacked the warning option and B' | MAJOR (merged) | Owner decided Q-B1 = warning line, no flag. Implemented as the contract's WARNING line, its rule cases and mutants (Task 1: 17, 18; Task 2: 10, 11); B' recorded as considered and not chosen |
| render-05: trust verify prints no installation ID | INFO | Edge Coverage and the deferred table, owner 03-14c; Cross-plan note |
| render-06: the gate does not walk nested types; literals not spelled out | INFO | Recursive walk in both gates; every literal list spelled out; Task 2 mutants 13a and 13b (round 2, close-rt-02) |
| threat-01: the policy-change checklist never compares roots and threshold | MAJOR | "The roots do not change" bullet, scoped to the policy-change section (critic-05); combined-ceremony sentence; pinned in `change_the_policy_step_3`; T-03-334; the tool-side marker deferred; paper wording corrected in Edge Coverage |
| threat-03 + runbook-policy-sha-not-recorded: a transcript hash the runbook never records | MINOR (merged) | One rewritten bullet: the policy version; root sign binds it through `--prev-sha256`; compare with the transcript only where it records the hash |
| threat-04: Edge Coverage wrong on CA/ops/log keys | MINOR | Rewritten with checkBundleKeys after both branches and at start (tested on genesis, UNVERIFIED on the successor path); the planner decision and the cross-plan note corrected |
| threat-05 + tests-05: no trust verify mutant for the base test | MINOR (merged) | Task 2 mutant 15; TestPolicyBlockBase's trust verify runs against a signed out-dir built before the swap |
| tests-01: build-failure mutants; no named FAIL required | MAJOR | Compiling forms (`_ = prevPolicy`, discarded result); the three-record mutant rule; parent bodies run every command, leaves only assert |
| tests-02: RED-first unauditable | MAJOR | R1 committed with tests and goldens only; R1's RED re-run from a worktree with exact counts; T1 touches no golden; `Golden corrections` exception path |
| tests-04: no exact -run commands | MINOR | One anchored command per mutant and package, with every expected FAIL line |
| tests-06 + the paragraph part of runbook-test-weaker-than-claimed | MINOR (merged) | `change_the_policy_pop_item` and `change_the_policy_intro` subtests with defined boundaries; the runbook mutant named |
| slot-01: the slot was presented as an owner decision | MAJOR | Owner decided Q-B3 = EARLY before 03-12; recorded with its duties |
| slot-02 + runbook-rotation-step4-unchecked: unchecked signing sections | MAJOR (merged) | `successorSigningSections` over every successor and genesis signing section that exists at execution (rotation steps 3 and 4, policy change, hardware variant, genesis, host-setup, machine-identities, transcript), an execution-time inventory grep, extension through the pointer sentences (ca-rotation.md and break-glass.md do not exist yet) |
| slot-03 + runbook-0315-section-not-pointed: Q-B2 advisory; the runbook section at 03-15:155 not pointed | MAJOR (merged) | Owner decided three advisory pointers; the third anchor is on 03-15's runbook-section sentence; numstat `4 4` and a pointer count of 3, derived from the final edit list |
| slot-04: the 03-15 clause lacked MSYS_NO_PATHCONV=1 | MINOR | Owner decision applied to the clause this plan now inserts, which under Q-B3 goes into 03-12's precondition; 03-15's precondition is not edited. Existing clauses keep the house form, as one verdict noted, so 03-12's precondition line holds one bare clause and one prefixed clause |
| slot-05: scrub list incomplete | MINOR | Pattern extended with `scratch[p]ad`, `FIX[-]PLAN` and `App[D]ata`, with character classes; the SUMMARY records local evidence by name only (Delivery protocol, Task 1 step 3) |
| slot-06: hard-coded wave text | INFO | Truth 1 is worded relative to origin/main's 03-12 with the f7eb018 value in brackets; the guard updates it |
| runbook-unverified-until-0315 | MINOR | Labels without a date for root-ceremony.md; "until 03-15" kept only for host-setup.md and machine-identities.md |
| runbook-test-weaker-than-claimed (rest) | MINOR | `machine_identities_pop` subtest; the doc-to-output link checks a shared prefix list in the runbook sections and in the goldens, and its doc comment says what it proves |
| runbook-example-fp-prefix | INFO | The worked example uses `<fp>`; the contract now lists literal lines and the rules separately, which removes the ", then:" ambiguity |
| critic-01: the fixed rule blocks a legitimate hand-written change; no independent intent source | MINOR | The rule reads "any field other than the agreed change"; the transcript's `Agreed policy change` row, recorded by someone other than the proposer; pinned |
| critic-02: `--confirm` skips the read point | MINOR | The first checklist line in genesis step 4, rotation step 3 (step 4 refers to it) and policy-change step 3; pinned |
| critic-03: TestSummaryFieldsCovered collides with Task 2's scope gate | MINOR | Placed in Task 1 |
| critic-04: later regenerations are self-confirming | MINOR | checkInvariants, which reads no golden, in every leaf; mutants 5 and 7; the additions-only regeneration rule in Task 4 and the Cross-plan notes |
| critic-05: rotation and roots bullets contradict 03-15's combined ceremony | MINOR | Both scoped to their section's command. Round 2 (close-rt-01) rewrote the combined-ceremony sentence in both sections so that the roots item and the unchanged-block item do not apply to a combined ceremony, and the 03-15 runbook pointer says the same in its own words |

### Round 2 — plan check 2 (2026-11-05, narrow; two MAJOR, the rest MINOR or INFO)

| Review item | Severity | How Addressed |
|---------|----------|---------------|
| decisions-01: the Bundle reflect gate assigned to 03-12 cannot fail, because Summary's `Bundle SHA-256:` line changes for every field; Summary prints no InstallationID | MAJOR | In the Q-B3 record (as the planner's precision, decision text unchanged), in the 03-12 pointer and in the Cross-plan notes: the gate compares Summary's output with that line removed, and 03-12 records InstallationID's handling (a Summary line, or a named exception pointing at installationLine and 03-14c). The insert stays one line ending `See 03-14b-PLAN.md.)` |
| decisions-02: the Cross-plan clause that let a regenerating plan excuse a removed line in its own SUMMARY contradicts additions-only | MAJOR | Clause deleted. A removed or changed line needs an owner decision recorded in that plan's check and SUMMARY |
| close-rt-01: "check both lists" re-imports the roots and installation items into 03-15's combined ceremony | MINOR | The roots item is conditional on the section's own command. The combined-ceremony sentence, in both sections, lists which items apply and says the roots item and the unchanged-block item `do not apply there` (pinned). The same scoping is in the 03-15 runbook pointer, T-03-334 and the 03-15 cross-plan note; the critic-05 ledger row is corrected |
| close-rt-02: mutant 13 did not exercise the recursion | MINOR | Mutant 13 replaced by 13a (the pinned map's WebAuthnRP entry deleted: `unpinned policy type`) and 13b (the walk made non-recursive: `pinned type not reached`); both gates require every pinned entry to be reached |
| close-rt-03 + close-slot-rb-02 + decisions-04: the Purpose row and the agreed-change source were unpinned | MINOR | transcript_template requires `root rotation / policy change / re-sign`, `Agreed policy change (the changed field names` and `someone other than its proposer`; a new `change_the_policy_you_need` entry requires `never from the proposer`; two more runbook mutants |
| decisions-05: the agreed-change row asked for values, which conflicts with the no-hostname rule | MINOR | The row records the field names and a reference to the record of the agreed values, and no hostname or other value; the RP bullet compares with that record |
| close-tests-01: per-mutant commands not pasteable | MINOR | The template puts the pattern in double quotes inside the single-quoted linux.sh argument, with a worked example in each task; the single quotes in the lists only mark extent |
| close-tests-02: Golden corrections bounded only between R1 and T1 | MINOR | The check runs over R1..HEAD, requires every golden-touching commit after R1 to touch golden files only, and is rerun in Task 2 and before the final docs commit |
| close-tests-03: checkInvariants' failure mode unspecified | MINOR | t.Errorf with an `invariant:` prefix, and checkGolden always runs after it, so the baseline writes all 13 goldens. R1's RED also counts 13 `golden <name>.golden: first difference` messages, and mutants 5 and 7 require an `invariant:` line per leaf |
| close-tests-04 + close-slot-rb-01: section and item boundaries undefined | MINOR | sectionWindow defines prefix matching on whitespace-trimmed lines, an error (t.Fatalf) for a missing, repeated or reversed marker, normalised substring matching (t.Errorf per missing phrase), and the self-test TestSectionWindowRefusals |
| close-tests-05: chain shape of the worktree command | INFO | The worktree run and its removal are grouped, so a failed scope check ends the chain directly; the RED string runs no git inside linux.sh (stated) |
| close-slot-rb-03: `--prev-sha256` already in the step-3 window | MINOR | Replaced by `bundle you pinned with`, which f7eb018 does not hold, so the pin is RED first |
| decisions-03: the guard's dependency was not checked by Task 1; the 03-14c bullet contradicted itself | MINOR | Task 1's first precondition derives the dependency from origin/main's 03-12 and requires its SUMMARY. The 03-14c bullet says it is expected after this plan, and that if it lands first, the f7eb018 diff list stops this plan for re-planning |
| close-rt-04: a trust-verify change-line duty the pointers do not carry | INFO | Edge Coverage and the deferred table now say the duty is rendering in Summary; change lines in trust verify stay deferred |
| close-rt-05: dead "extend both gates" sentence | INFO | Replaced: Task 1's precondition stops on a changed policy.go |
| close-slot-rb-04 + decisions-06 + decisions-07 | INFO | The 03-13 and 03-14 pointers also carry "keep the policy block the last thing before the prompt" (one line each); the cross-plan note says 03-15 must add runbook_test.go to its files_modified |
| close-slot-rb-05: "truth 1's bracketed wave number" | INFO | Publish edit 1 reworded: only `wave:` and `depends_on:` change; truth 1 keeps its f7eb018 value; the SUMMARY records the deviation and the preceding plan |

### Review Feedback Deferred

| Item | Why deferred | Revisit |
|------|--------------|---------|
| A tool-side `Root set: unchanged / CHANGED` line in root sign --prev and trust verify --prev (threat-01's optional question) | Outside F04 and F14; the checklist compares the two root lists before signing (T-03-334) | An owner decision with 03-12, which adds the Bundle gate |
| Old-to-new bundle change lines in trust verify --prev (CA, log, ops, break-glass) | Q-B3: Bundle fields are 03-12, 03-13 and 03-14's. Their pointer duty is to render each field and state in Summary, which trust verify prints; change lines in trust verify are not a pointer duty | 03-12 to 03-14 |
| trust verify's installation ID (render-05) | Installation binding | 03-14c |
| A test of checkBundleKeys refusing foreign keys on the successor path | Outside this plan's files; root sign cannot be made to produce such a bundle | A later signer plan |
| Restricting which fields a successor policy may change (a trust-semantics change) | Not asked for; would refuse legitimate root-signed changes and pre-empt AUTHZ-03 | AUTHZ-03 (Phase 4) |
| An intent flag (Q-B1 options B, B', C) | Owner chose the warning line | AUTHZ-03 (Phase 4) |

## Reconcile ledger (b4e6b4c, 2026-11-10)

The plan was written and checked at f7eb018. The reconcile of 2026-11-10 compared it with main at b4e6b4c (PR #97, 03-11b merged). Verdict: fix in place, no re-plan; trust.Policy, trust.Bundle, Summary and every file this plan changes are unchanged, so the display contract, the goldens, both reflect gates and every mutant stand. No owner question is open: the slot after 03-11b (Q-B3 with OQ-1), the order 03-14b, 03-14c, 03-14d, 03-12, the missing WARNING for pop.machines and RP changes (Q-B1) and the test-time rule (Q-09-3) are settled.

| id | severity | what changed in this plan |
|----|----------|---------------------------|
| D01 | BLOCKER | Task 1 precondition 3 diffs the 13 frozen paths against b4e6b4c instead of f7eb018, with the same stop rule. The context records #87's one root-ceremony.md hunk (step 2 of section 1, the reproducible-build label) as reconciled and outside every section this plan uses, and reads "as read on main at f7eb018 and re-read at b4e6b4c". The 03-14c cross-plan bullet names Task 1's b4e6b4c diff list. Task 2's policy.go sentence and the pointer-anchor sentence name b4e6b4c too |
| D02 | BLOCKER | Frontmatter `wave: 29`, `depends_on: ["03-11b"]`. Truth 1 and the Q-B3 record keep the owner text and add the OQ-1 sentence. Precondition 1 is a stop guard: 03-11b's SUMMARY on origin/main, 03-12 at wave 29, 03-11b the only plan at wave 28, otherwise stop for a re-reconcile. The absorb-by-guard rule is gone; publish edit 0 re-runs the stop guard. Brackets updated to b4e6b4c (29/33 in 33 waves → 34 in 34; Progress /33 → /34; a new Wave 29 block; 29–33 → 30–34; STATE 68 → 69, of 30 → of 31; 03-12 to ["03-14b"]). The publish gate checks literal values (03-14b 29 and ["03-11b"], 03-12 to 03-16 at 30 to 34, frontmatter waves only, STATE 69 and of 31 from a 68 and of 30 base). The ROADMAP gate builds the exact intended file from origin/main and compares whole files, so a wrong edit or a prefix tick fails. Numstat expectations unchanged |
| D03 | MAJOR | Budget's test-time rule is Q-09-3: Task 1 writes one `test-time base: cmd=<s> rootceremony=<s> at=<epoch>` line on unchanged origin/main, with a format check; Task 3's delta gate stops at +90 s per package and requires the base to be at most 24 h old (re-measured in place). The 480 s awk and the apply and signer times are gone; the whole-module run is pass or fail only. Every go test gate carries `-timeout 15m`, every mutant command `-timeout 5m`, and a timeout is not a kill |
| D04 | MINOR | The full gate vets the house tag list: `keyroster_e2e` on the agent, `e2e`, `e2e e2eprobe`, `e2e e2emachine`, `e2e e2eprobe e2emachine`, `e2e systemdsmoke` and `e2edistro` |
| D05 | MINOR | The PR check runs 03-10b's house e2e gate in MODE=pr with 03-11b's PROBE_PASS list (run for HEAD, main lanes at or under 900 s, probe lanes green), then requires `--- PASS: TestAuditLoginAcrossPolicyChange (` in both main lanes. The SUMMARY records the main lanes' seconds; the pin adds only assertions |
| D06 | MINOR | The context cites 03-11b-SUMMARY.md. "What lands before this plan" lists 03-09 to 03-11b, #87, #94 and #96, the new package-main test files and the runbooks that grew or changed. "03-09 to 03-11" reads "03-09 to 03-11b" in the context, Task 1, Task 3's read_first, the cross-plan notes and Edge Coverage |
| D07 | MINOR | The collision grep adds `sectionWindow`, `policyChange`, `changedPolicyFields`, `update-golden` and the new test names. It finds nothing at b4e6b4c (seedKey exists only outside cmd/keyroster and internal/rootceremony) |
| D08 | MINOR | Publish edit 3 keeps the mechanical + 1 on `of M`; the SUMMARY records that `of M` was stale on main (30 against 33 plans). Re-reading b4e6b4c showed the ROADMAP's Phase 3 total is stale the same way (34 plan rows and files against `/33`); publish edit 2 keeps its mechanical + 1 (/34) and the SUMMARY records it too |
| scrub | (this pass) | The private-term gate's pattern spells both artefact names with character classes (`find[i]ngs`, `FIND[I]NGS`), so the plan text no longer holds the literal upper-case word; under `grep -i` it matches exactly as before |
| D09 | MINOR | After the tracking update, only the 03-14b row may change to `- [x]`; the whole-file ROADMAP gate enforces it, and the action says to untick a prefix-ticked row and record it |
| D10 | MINOR | Estimate 150k at low confidence (raw 75k, about 2x); one continuation after Task 1, handed over through the SUMMARY draft. Task count and files unchanged |
| D11 | MINOR | The pop-wording decision names the consumers by plan: host and probe certificates and the host commands under pop.hosts (03-09, 03-09b, 03-10); machine renewals refused by the signer and audit (03-11) and by the CLI and server (03-11b). The contract text is unchanged |
| D12 | MINOR | The runbook inventory records the expected extra hits (revoke.md, host-setup.md's directory binding, signer-install.md) as "defers or describes, nothing added". No rule change |
| D13 | MINOR | One Edge Coverage line: a hand-written pop.machines true→false, or a removed or changed RP, prints CHANGED without the WARNING (Q-B1's set); the agreed-change and RP checklist items cover it. No code or test change |
| D14 | MINOR | Runbook action 2 names the anchor as the sentence that starts `Then type the hash`, which is line-wrapped (root-ceremony.md:184-185 at b4e6b4c; #87's hunk moved it four lines from f7eb018's :180-181) |
| D15 | INFO | The mutant rule says the numbering is local and that this plan allocates no global M-IDs; 03-12 starts at M111 |
| D16 | INFO | The prohibitions add: no number in docs/format-registry.md is allocated |
| D17 | INFO | No change: T-03-329 to T-03-334 occur nowhere on main; the highest there is T-03-412 |
| R2-1 | BLOCKER | The totals are the true file counts, not origin/main + 1. This supersedes D08 and the totals in D02's brackets. A run of the installed GSD tools on a copy of b4e6b4c's .planning showed that the tracking update counts the PLAN and SUMMARY files: the ROADMAP reads 30/35, `total_plans` 70 and `completed_plans` 65, while `advance-plan` bumps only N and keeps the `of M` the publish edit wrote. So the old gates (/34, 69, `of 31`) failed on a correct run. Publish edit 2 writes `29/35 plans executed in 34 waves` and the Progress row `29/35`, and the tracking update makes both 30/35. Publish edit 3 sets `total_plans: 70`, keeps `completed_plans: 64` and writes `Plan: 29 of 35`, which tracking makes `Plan: 30 of 35`. A second run with these values on a fresh copy gave exactly those results. The publish gate derives the STATE values from HEAD's PLAN and SUMMARY counts, each exactly one more than origin/main's, and pins main's stale base (68, 64, `Plan: 28 of 30`). The ROADMAP gate keeps the whole-file comparison and its prefix-tick protection, with 30/35. The SUMMARY records the corrected staleness: main had 34 rows against /33, 68 against 69 PLAN files, and `Plan: 28 of 30` against 29 executed of 34. The brackets in "For later plans" for 03-14c and 03-14d follow the true totals |
| R2-2 | MINOR | Budget, "Another session": if the delta gate runs in a different session or WSL boot from the one that measured the base, the base is re-measured first on origin/main in a detached worktree, in place, as 03-11b's continuation did. After the continuation following Task 1, that is always the case. The 24 h age check stays. The base line format is unchanged, because the gate reads `at=` at the end of the line. Task 3's Gates paragraph repeats the rule |
| R2-3 | MINOR | The estimate is restated, superseding D10: raw and calibrated 165k at low confidence (the calibration has no samples), now counting the plan file itself (about 182 KB) once per session. 03-11 ran about 5x its estimate and 03-11b about 2x, so the expected range is about 330k to 800k. The plan is over the 100k smart-zone budget. The continuation after Task 1 stays, and an optional second handover after Task 2 is allowed. The Budget states why the code and runbook seam is not split: a second PR, merge gate and review; code that ships without its custodian checks; and a second wave shift for 03-12 to 03-16, 03-14c and 03-14d |
| R2-4 | MINOR | Repo text: the plain-English word for review results is reworded at the wording rules, the pre-merge review step, its acceptance criterion and the two older round-table headers ("the two issues", "review items", "results", "Review item"). The private-term gate keeps its escaped pattern, and the plan holds the word in no case |

**For later plans** (not edited here; each plan's own check or re-plan carries it):
- **03-14c.** Its Q-C1 facts and brackets assume 03-14b at wave 25 with ["03-11"] and `[N/30 in 29 waves]`. After this plan's PR the values are wave 30, depends_on ["03-14b"], and /35 in 34 waves → /36 in 35 (this plan writes the true totals, so the bracket is 30/35 in 34 waves, not /34). Its STATE edit and gate must follow R2-1, true counts, because advance-plan keeps the `of M` it is given: `total_plans` [70] → 71 and the Plan line [Plan: 30 of 35] → Plan: 30 of 36, which the tracking update makes 31 of 36 with `completed_plans` 66; not its current + 1 on `of M`. Its account of this plan's precondition must say b4e6b4c, not f7eb018. Its two "REVOKE-01 is 03-09's" sentences must read "REVOKE-01 is 03-11b's (complete)". Its anchors in 03-12 and 03-13 (created by this plan's pointers) and its trust_verify golden additions are compatible with this plan.
- **03-14d.** Its brackets become wave 31, 03-12 at 32 to 36, and /36 in 35 → /37 in 36. Its STATE edit and gate follow R2-1 the same way: `total_plans` [71] → 72 and [Plan: 31 of 36] → Plan: 31 of 37, which tracking makes 32 of 37 with `completed_plans` 67. Optionally name the requirement owners: REVOKE-01 and AUTH-06 are 03-11b's, AGENT-06 is 03-09's.
- **03-12** (and its security design note). After 03-14c and 03-14d it sits at wave 32 with ["03-14d"]. Its re-plan carries this plan's pointer duties into every sub-plan that changes trust.Bundle if it is split, and corrects the note's premise that 03-14b adds successorHeader (it exists on main; this plan only passes prevPolicy on).
- **03-15.** Its anchors hold. Its wave moves to 33 here (35 after 03-14c and 03-14d), and its files_modified must still gain cmd/keyroster/runbook_test.go.
- **03-12, 03-13 and 03-14.** Their files_modified still name none of the ceremony goldens, ceremony_golden_test.go, summary_test.go or runbook_test.go; their checks must widen them, as the cross-plan notes say.
