---
phase: 03-linux-agent-and-revocation
plan: 10d
type: execute
wave: 26
depends_on: ["03-10c"]
files_modified:
  - internal/agent/apply/render.go
  - internal/agent/apply/rollbackkeep_test.go
  - internal/agent/apply/apply.go
  - internal/agent/apply/probegate.go
  - internal/agent/apply/probegate_test.go
  - internal/agent/apply/apply_test.go
  - internal/agent/apply/status_test.go
  - .planning/todos/pending/2026-11-08-no-rollback-regrants-a-landed-removal.md
  - internal/krl/recovery.go
  - internal/krl/recovery_test.go
  - internal/signer/recovery.go
  - internal/signer/recovery_test.go
  - internal/audit/recovery.go
  - internal/audit/recovery_test.go
  - internal/audit/verify_test.go
  - cmd/keyroster/recover.go
  - cmd/keyroster/recover_test.go
  - docs/runbooks/signer-install.md
  - .planning/todos/pending/2026-11-07-recovery-revokes-lost-negative-probe-certificates.md
  - .planning/phases/03-linux-agent-and-revocation/03-10d-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
  - .planning/REQUIREMENTS.md
autonomous: false
requirements: [AGENT-04]

estimate:
  tokens: 95000
  raw_tokens: 95000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decisions Q-S, Q-R and Q-D (2026-11-08) and D-R1 (2026-11-07 and 2026-11-08) are binding (Owner decisions). This plan holds the two hardening tasks that 03-10c's owner split moved out of it. It adds no format and no new capability"
    - "Task 1 (todo 2026-11-08). After a removal has landed, no rollback of an in-flight apply widens back to last-good: forward's error paths, settleFailedAddition's fallbacks and gateSuperseded's all end in lg intersect current (RollbackKeeping), with the newest KRL. A pure addition that fails still goes back to last-good. When the kept generation cannot be installed or validated, the rollback returns the error and leaves current where it is (Q-D option 1, T-03-388). Crash recovery (recover) is out and keeps going to last-good: that residual stays named"
    - "A kept state is not mistaken for an interrupted move: atRollbackTarget accepts it, so the next Apply's start does not recover it back to last-good, and the equal-content commit passes a listener test before it makes a current that is not last-good into last-good"
    - "Task 2 (todo 2026-11-07, Q-R option 1). A lost probe certificate cannot be told apart by polarity from its bytes, so the recovery revokes every lost probe certificate, both polarities, recognised by its key ID (ca=machine, subject probe.*), and the signer and `audit verify` refuse a carried probe certificate that is not revoked (`recovery_probe_certificate_kept`). No wire format changes. That an old log holds no recovery which kept a probe certificate is UNVERIFIED"
    - "AGENT-04 is complete when this plan is on main (03-10c left it open): its SUMMARY says `AGENT-04: complete` and `requirements-completed: [AGENT-04]`"
  artifacts:
    - path: "internal/agent/apply/render.go"
      provides: "RollbackKeeping, the rollback target that never grants what current lacks"
      contains: "func RollbackKeeping("
    - path: "internal/agent/apply/rollbackkeep_test.go"
      provides: "TestRollbackKeeping, TestRollbackSites, TestAtRollbackTarget additions"
      contains: "func TestRollbackKeeping("
    - path: "internal/krl/recovery.go"
      provides: "IsProbeKeyID and the probe rule of CheckCarriedLost"
      contains: "func IsProbeKeyID("
  key_links:
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/apply/render.go"
      via: "rollback calls backToLastGood with the keeping flag, which targets RollbackKeeping; recover does not"
      pattern: "RollbackKeeping("
    - from: "internal/signer/recovery.go"
      to: "internal/krl/recovery.go"
      via: "the signer, audit and the CLI pass krl.IsProbeKeyID to CheckCarriedLost"
      pattern: "IsProbeKeyID("
  prohibitions:
    - statement: "No rollback of an in-flight apply grants again an access that a landed change removed, except through crash recovery (a named residual)"
      status: resolved
      verification: test
    - statement: "No wire, tlog, cert, certprofile, serverclient, server or registry change, no new module and no capslock baseline change"
      status: resolved
      verification: test
    - statement: "No test code names the test-build tag outside the six files 03-10b allows"
      status: resolved
      verification: test
---

<objective>
Two hardening rules that the 03-10b pre-merge review recorded as owner decision D-R1 and handed to 03-10c, and that the owner then split out of 03-10c into this plan (Q-S, 2026-11-08).
- A rollback of an in-flight apply never widens back to last-good once a removal has landed (Task 1).
- A signer recovery revokes every lost probe certificate, and the signer and `audit verify` refuse a recovery that carries one unrevoked (Task 2).

Purpose: finish AGENT-04's 'rolls back on failure' without ever granting a removed access again, and keep the probe promise (a negative probe is always refused) across a signer restore.

Output: Task 1 the rollback rule and its guards; Task 2 the recovery rule; Task 3 the gates, the PR and the SUMMARY.
</objective>

## Reconcile (written against main at cee452a, before 03-10c; every apply.go, probegate.go and probegate_test.go line must be reconciled after 03-10c merges)

This plan was written against main at cee452a (03-10b merged), **before 03-10c**. 03-10c's Task 1 edits apply.go (the served-certificate site of forward), probegate.go (the gate, runProbes, opportunistic, the reason list) and probegate_test.go, so the line numbers below for those three files will have moved. Task 1's Step 0 re-reads every one of them against main after 03-10c has merged and records the new line numbers in the SUMMARY (a Reconcile table of old and new), before any test is written. The other files (render.go, status_test.go, the krl, signer, audit and cmd/keyroster files) are not touched by 03-10c, except that 03-10c's Task 3 edits cmd/keyroster/audit.go and docs/runbooks/host-setup.md, and Task 2 here edits neither.

| # | Premise | True at cee452a | Effect here |
|---|---|---|---|
| 1 | Every rollback in forward ends at last-good | forward's `e.rollback(ctx, err, lg)` sites are apply.go:1070, :1078, :1117, :1125, :1129, :1137; settleFailedAddition is called at :1156 and :1165; its own fallbacks are probegate.go:943, :950, :963, :967, :974, :978, :983; rollback is apply.go:1669-1680, backToLastGood :1685-1723, rollbackTarget :1729-1752, RollbackTarget render.go:435-449; `recover` (crash) calls backToLastGood at :1775 | Task 1 changes `rollback` only; `recover` is out |
| 2 | A kept rollback state is stable | Apply's start treats a current that is neither last-good nor `atRollbackTarget` as an interrupted move and recovers it (apply.go:488, atRollbackTarget :703-717); HostCerts and ProbeCerts treat it as unfinished (hostcert.go:169, probe.go:251) | Task 1 generalises atRollbackTarget |
| 3 | The equal-content commit is safe | forward commits current as last-good when the candidate equals it, with no listener test (apply.go:1001-1022) | Task 1 adds a listener test when current is not last-good |
| 4 | A recovery can tell a lost negative probe certificate | wire.RecoveredCertificate is `{Cert, Revoke}` (wire/recovery.go:64-67); krl.CheckCarriedLost(validBefore, createdAt, user, revoke) knows only user (krl/recovery.go:62); the signer (signer/recovery.go:138) and audit (audit/recovery.go:130) pass `role == user`; the CLI revokes `user || named` (cmd/keyroster/recover.go:290-291); the key ID carries a random request ID and the subject, no polarity (signer/probeissue.go:188-192) and both polarities have the same options (certprofile.go:78-79) | The todo's 'a lost positive may be kept' cannot be checked by signer or audit; owner decision Q-R option 1 revokes both polarities |
| 5 | The test the todo names flips | `recovery_collects_probe_certificate` (internal/audit/probeissue_test.go:595) only asserts that Report.Certificates lists a probe certificate; it does not carry one as kept | Not changed; internal/audit/recovery_test.go is the likely home of the new audit rows |
| 6 | The audit refusal table | verify_test.go :3439-3484 names `recovery_user_certificate_kept`; signer/recovery_test.go pins the signer's | New refusals are added beside them |
| 7 | The older follow-up `pop_hosts_off_fails` of 03-09 passes through trust's rule | internal/audit/verify_test.go:3951 asserts the text "pop.hosts", which the policy-install rule produces; audit's own host-issue rule is exercised by internal/audit/probeissue_test.go:241 | Task 2 (conditional, see its Step 1) |

## Owner decisions (recorded, do not ask again)

All by Daniel. This plan implements these:
- **Q-S = split (2026-11-08, before plan check 1).** 03-10c holds the account check, the matrix, the systemd test, the runbook and the audit line; this plan (03-10d, wave 26, depends_on 03-10c) holds the rollback rule and the recovery rule, moved unchanged with their todos, mutants and threat rows. 03-11 to 03-16 move one wave later. AGENT-04 stays open until this plan.
- **Q-R = option 1 (2026-11-08).** Revoke every lost probe certificate, both polarities, recognised by the key ID. No format change. The signer and audit refuse a carried probe certificate that is not revoked (`recovery_probe_certificate_kept`). A revoked lost positive makes its host ask for a new pair, so additions on that host wait up to about two hours (owner answer P4, 2026-11-07). That an old log holds no recovery which kept a probe certificate is UNVERIFIED. This replaces the todo's 'a lost positive may be kept' test.
- **Q-D = option 1 (2026-11-08).** Stay and retry. When the kept generation (last-good intersect current) cannot be installed or validated, return the error and leave current where it is. No removal is re-granted (T-03-388).
- **D-R1 (2026-11-07 and 2026-11-08).** Both todos were recorded as residuals in 03-10 and 03-10b and handed to 03-10c, now to this plan.
- **Q2 (2026-11-07), refined by 03-10b:** probes never roll back a removal.
- **Owner approval recorded in 03-10b (2026-11-08):** the settle branch that takes the target itself when it only removes from last-good is kept.

## Planner decisions (Claude's discretion), recorded with their reasons

- **D1. Rollback that keeps removals (Task 1).** `RollbackKeeping(cur, lg)` returns RollbackTarget(cur, lg) when cur covers it (nothing landed), else the lines both lg and cur hold with the newest KRL: lg intersect cur. It is used by `rollback` only, through a flag of backToLastGood; `recover` keeps RollbackTarget. When a generation of that content cannot be installed (I/O or validation error), the rollback returns the error and leaves current where it is (Q-D option 1, binding), and the next round (accepted/ was not advanced, so the capture is unapplied) retries. That is the named residual T-03-388: for a gated addition current can be the live unproven addition until that retry.
- **D2. Recovery revokes every lost probe certificate (Task 2).** Recognised by the key ID (kr3, ca=machine, subject starting `probe.`), the only thing the signer and audit can see (Q-R option 1, binding). A revoked lost positive makes the host ask for a new pair (`positive_in_krl`, then a fresh request); that costs the P4-style wait for additions on that host and nothing else.
- **D3. Both tasks keep their tests per site, per rule and per mutant,** probes off and on where the apply path is involved, because heldPresent ignores the probe switch (probegate.go:557-566).
- **D4. Tasks stand alone.** Task 1 touches the applier, Task 2 the rule that the signer, audit and the CLI share; they share no file. If one needs a split again, it can go to a plan of its own without rewriting the other.

## Code facts this plan rests on (read-only on main at cee452a)

| # | Fact | Where |
|---|---|---|
| C1 | forward: the gate block, the Transition loop with `reclassify`, the served-certificate and probe block, the rollback sites, the equal-content commit | internal/agent/apply/apply.go:844-1178 (:1001-1022 equal commit, :1067-1119 loop, :1144-1167 probes) |
| C2 | rollback, backToLastGood, rollbackTarget, recover, atRollbackTarget, the recovery trigger at Apply's start | apply.go:1669-1680, :1685-1723, :1729-1752, :1757-1776, :703-717, :488 |
| C3 | Intermediate, RollbackTarget, covers, sameContent, isNarrowing | internal/agent/apply/render.go:386-418, :435-449, :507-522, :543-554 |
| C4 | settleFailedAddition, gateSuperseded, heldPresent | internal/agent/apply/probegate.go:937-995, :625-656, :557-566 |
| C5 | The tests that pin today's rollback: the listener-failure test, rollback_keeps_newer_krl, narrowing_negative_accepted_no_rollback_reports, the mixed and superseded subtests; the fixtures gateHost, ready, scriptProbes, mustPrincipals, heldNow; the Fault hook (a plain error is not a crash, isCrash tests the InjectedCrash method) and its point names (`marker`, `swap`, `last-good`, `save-state`, `self-test`, `dropin`, `reload`) | probegate_test.go:1331, :1457-1485, :1581; apply.go:134-141, :285-290, :1654-1659; apply_test.go:70-85; harness_test.go (fakeRunner switches rejectDropIn, sshdTestErr, queryCode, rejectCA, stall) |
| C6 | Recovery: CheckCarriedLost and its errors, the signer's, audit's and the CLI's call sites and outputs | internal/krl/recovery.go:42-72; internal/signer/recovery.go:70-149, :310-380; internal/audit/recovery.go:100-140; cmd/keyroster/recover.go:60-135, :268-330, :425-450 |
| C7 | Key IDs | internal/cert/keyid.go:55-100; internal/signer/probeissue.go:169-215 |
| C8 | The recovery runbook text | docs/runbooks/signer-install.md:1100-1160 |

## Contracts frozen by this plan

**Names.** `RollbackKeeping(cur, lg *Generation) *Generation` (render.go); `rollbackAs(ctx, cause, lg, keep bool)`; `krl.IsProbeKeyID(kid cert.KeyID) bool`; `krl.ErrLostProbeKept`; `krl.CheckCarriedLost(validBefore, createdAt uint64, user, probe, revoke bool)`; the signer refusal code `recovery_probe_certificate_kept`. No wire, tlog or registry name changes.

## Budget and verify

**Size.** 23 entries in files_modified: 20 code, test, documentation and todo files (1 new: rollbackkeep_test.go; the two todo files are moved to the completed folder, so they are entries) plus the plan, ROADMAP, STATE and REQUIREMENTS (tracking only; REQUIREMENTS.md flips AGENT-04 here). About 95k tokens in all: Task 1 about 45k, Task 2 about 40k, Task 3 about 10k. Each task is self-contained; the executor drops a task's read_first context once it is done. If a task nears half the context, stop after its unit gate and report instead of trimming.

**Test time.** One command for the base and every reading: `go test -race -count=1 -timeout 15m ./internal/agent/apply/ ./internal/krl/ ./internal/signer/ ./internal/audit/ ./cmd/keyroster/ ./cmd/keyroster-agent/` through `bash scripts/linux.sh`. Task 1 measures a quiet base on unchanged origin/main (03-10c merged; a detached worktree outside the repository, no other heavy job) and writes one SUMMARY line: `test-time base: apply=<s> krl=<s> signer=<s> audit=<s> cmd=<s> agentcmd=<s> at=<epoch seconds>`, each time from that package's `ok` line (the bases of 03-10b and 03-10c are not reused). The delta gate (Task 3) fails if the base is over 24 h old (re-measure in place) and stops if any package adds more than 90 s. The whole-module `go test -race ./...` is pass or fail only. Expected: apply +20 to 40 s (the per-site tests are parallel subtests, probes off and on), the rest +5 s each.

**The e2e budget.** This plan adds no e2e test. The PR's e2e run must show the main lanes at or under 900 s with no `=== RUN   TestProbe` line, and the probe lanes at or under 420 s, as 03-10c left them; the equal-content listener test of Task 1 adds one listener test to a path that e2e rarely takes. The e2e gate is the script that 03-10b committed in its plan file on main (between `# E2E_GATE_BEGIN` and `# E2E_GATE_END` of .planning/phases/03-linux-agent-and-revocation/03-10b-PLAN.md), run in `pr` mode only.

**Verify rules** (as 03-10b and 03-10c).
- **WSL.** Every Go test, vet or fuzz command runs through `bash scripts/linux.sh '...'`; lints run for GOOS linux, windows and darwin; `go vet -tags keyroster_e2e ./internal/agent/... ./cmd/keyroster-agent/` runs locally.
- **`-run` patterns.** Whole functions anchored; one subtest `-run '^TestA$/^case$'`; a subtest path is never combined with `|`. Subtests are required by their `--- PASS:` lines, which the gates check in a loop.
- **RED first.** Each task writes its tests first and records the failures (a compile failure counts) in the SUMMARY.
- **Mutants.** The task's work is committed before its first mutant. Each mutant is applied, run on its single named subtest with `-timeout 5m`, killed by the named `--- FAIL:` line (a timeout or `[build failed]` is not a kill), restored with `git checkout -- <file>` and proven by `git diff --quiet HEAD -- <the mutated file>`. Every mutant changes behaviour; one that cannot be killed is equivalent and reported with its reason, not counted. **Executor rule, verbatim: Before each commit, run `git diff` on every staged file and confirm only intended lines changed. Restore every mutant before ending a task; never commit with a mutant applied.** Every executor also runs `git diff --cached` on each staged file before committing.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-10b-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-10c-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/01-SKELETON.md

Delivery protocol: 01-SKELETON.md with phase 03 names, as 03-10b and 03-10c followed it.
- **Branch** `p03/10d-no-regrant-recovery` from origin/main (Task 1), after 03-10c has merged. This plan file is placed untracked in the phase directory; Task 3 commits it. (03-10c's executor commits it together with the plan row, see 03-10c Task 4; if it is already on main, Task 3 only verifies it.)
- **Staging** by path only; never `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or a `.review-diagnostics` directory. Every executor runs `git diff --cached` on each staged file before committing.
- **Authorship.** Every commit is signed (`-S`) and authored as Daniel, committed and pushed by keyroster-bot: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit -S ...`; push with `env -u GITHUB_TOKEN -u GH_TOKEN git push`. No attribution lines.
- **No auto-merge.** The bot opens the PR through scripts/gh-as-bot.sh; Daniel squash-merges in the web UI and replies "merged". `scripts/merge-gate.sh` runs only as `--check` before the merge.
- **Shells.** Go commands through `bash scripts/linux.sh '...'`; git checks in Git Bash, `MSYS_NO_PATHCONV=1` before `git show` or `git cat-file` of an `origin/main:path`.
- **Wording.** Conventional Commits, neutral; no IP address other than loopback in any added line, no real host names, no private-workspace terms (Task 3's scrub gate). Code comments cite `(03-10d)`. Owner decisions are cited by ID and date.
- **SUMMARY** `.planning/phases/03-linux-agent-and-revocation/03-10d-SUMMARY.md`, a draft from Task 1: base lines, the Reconcile table of Step 0, T1 and T2 (the last commit of each), CI run IDs, RED evidence, mutants, readings. The final docs commit is `docs(03-10d): complete rollback-and-recovery plan`.

**Existing tests this plan changes, with their new expectations** (the executor confirms each by the RED run and lists any other in the SUMMARY; a file needed by a fix is added to files_modified first).
- Task 1: `settle_listener_failure_falls_back_to_plain_rollback` (probegate_test.go:1457-1485 at cee452a) asserted that role:a is re-granted by the fallback; after Task 1 the fallback keeps it removed, and the test is renamed `settle_listener_failure_keeps_removal` with the opposite assertion. The rollback tests of apply_test.go, status_test.go (`rollback_reports_last_good_status`, `rollback_in_place_reports_last_good_status`, `rollback_is_rolled_back`), dropin_test.go (`rollback_restores_agents_dropin_not_the_edit`), hostcert_test.go (`generation_rollback_keeps_section`, `hostcert_rollback_keeps_trust_files`) and socket_test.go (`rollback_reloads_before_current_is_removed`) are the candidates; those whose change is not a mixed or narrowing one with a landed removal are unaffected, and the others change their expected principals only. The RED run decides; the interleave model tests call RollbackTarget directly and do not change. Tests that count self-tests change by the one listener test of the equal-content guard.
- Task 2: the recovery tests that pin `recovery_user_certificate_kept` in verify_test.go (:3439-3484) and signer/recovery_test.go keep their expectations; new refusals are added beside them. If the RED run shows a test in an unlisted file that carries a probe certificate unrevoked, its file is added to files_modified first and the test is listed in the SUMMARY.
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1 (todo 2026-11-08): once a removal has landed, no rollback of an in-flight apply widens back to last-good</name>
  <reversibility rating="costly">It changes the state a failed apply leaves behind (current may name a generation that is not last-good and not last-good's content); 03-05's rollback contract, the status values after a rollback and the recovery semantics are read by later plans (03-12, 03-14).</reversibility>
  <precondition>`git merge-base --is-ancestor cee452a origin/main` exits 0; 03-10c is merged (`git grep -q 'func (e \*engine) checkProbeAccountFull(' origin/main -- internal/agent/apply/account.go` exits 0; this plan was written before it, so Step 0 reconciles every line number); `git grep -q 'func (e \*engine) settleFailedAddition(' origin/main -- internal/agent/apply/probegate.go` exits 0 and `git grep -q 'func RollbackKeeping(' origin/main -- internal/agent/apply/render.go` exits 1; the todo file `.planning/todos/pending/2026-11-08-no-rollback-regrants-a-landed-removal.md` exists on origin/main.</precondition>
  <files>internal/agent/apply/render.go, internal/agent/apply/rollbackkeep_test.go, internal/agent/apply/apply.go, internal/agent/apply/probegate.go, internal/agent/apply/probegate_test.go, internal/agent/apply/apply_test.go, internal/agent/apply/status_test.go, .planning/todos/pending/2026-11-08-no-rollback-regrants-a-landed-removal.md, .planning/phases/03-linux-agent-and-revocation/03-10d-SUMMARY.md</files>
  <read_first>
    - internal/agent/apply/apply.go :844-1178 (forward; the six rollback sites and the two settle calls), :1669-1776 (rollback, backToLastGood, rollbackTarget, recover); probegate.go :625-656 (gateSuperseded), :937-995 (settleFailedAddition); render.go :376-449 and :507-569 (Intermediate, RollbackTarget, covers, sameContent, isNarrowing, sameBytes).
    - probegate_test.go :1331 (rollback_keeps_newer_krl), :1457-1485 (the listener-failure test whose expectation flips), :1581 (narrowing_negative_accepted_no_rollback_reports), the mixed_* and superseded_* subtests (the fixtures for a mixed change); the Fault hook type (apply.go:134-141) and the crash type of apply_test.go :70-85 (a plain error from Fault is not a crash: isCrash tests the InjectedCrash method); the fault point names (`marker`, `swap`, `last-good`, `save-state`, `self-test`, `dropin`, `reload`) and the fakeRunner switches (rejectDropIn, sshdTestErr, queryCode, rejectCA, stall).
    - The todo file whole; 03-10b-SUMMARY.md 'Pre-merge review round 1' (D-R1) and its Deviations bullet on settleFailedAddition.
    - internal/agent/apply/interleave_test.go :586-640 only to see that the model tests call RollbackTarget and must stay green unchanged.
  </read_first>
  <behavior>
    - `TestRollbackKeeping` (rollbackkeep_test.go, pure): `pure_addition_is_last_good` (cur covers lg: the result equals RollbackTarget(cur, lg), N = lg.N when the KRL is not newer), `pure_narrowing_stays` (cur only removes: the result has cur's lines and the newest KRL, never a line cur lacks), `mixed_is_intersection` (lines in both, principals under the intermediate header, lg's order), `newest_krl_kept` (the newer of cur's and lg's, by KRL version), `never_grants_what_cur_lacks` (a table of 2000 generated pairs: every line of the result is in lg and in cur, or the result is RollbackTarget because cur covers lg), `host_fields_are_last_goods`, `cur_nil_is_last_good`.
    - `TestRollbackSites` (rollbackkeep_test.go; each subtest runs twice, probes off with the default harness and probes on with the gate fixture of probegate_test.go, as `/probes_off` and `/probes_on`): a mixed change (role:a removed, role:b added) fails at the site, with a plain (non-crash) error injected; the apply returns the error and reports a rollback; current's principals hold neither role:a nor role:b; last-good is unchanged; accepted/ is not advanced; the next apply with the injection removed re-renders (the capture is unapplied), lands role:b and keeps role:a absent. Sites, one subtest each: `read_current_error` (apply.go:1070), `gate_superseded_error` (:1078; probes on only), `transition_error` (:1117, injected at the swap fault point after the narrowing swap), `write_dropin_error` (:1125), `activate_dropin_error` (:1129), `self_test_failure` (:1137, the listener stall), `settle_read_last_good_error`, `settle_install_error`, `settle_validate_error`, `settle_validate_timeout` (the runner blocks until the context ends), `settle_held_write_error` (probe-state.json cannot be written), `settle_marker_error`, `settle_swap_error` (probegate.go:943 to :978, probes on only). `TestProbeGate/settle_listener_failure_keeps_removal` is the 03-10b test `settle_listener_failure_falls_back_to_plain_rollback` renamed and with the opposite assertion (role:a stays removed).
    - Also subtests of `TestRollbackSites`: `pure_addition_failure_goes_back_to_last_good` (probes off and on), `pure_narrowing_failure_keeps_removal` (a failed self-test after a removal-only change leaves the removal in force, the drop-in restored), `m_install_fails_leaves_current` (D1: when no generation of the kept content can be installed the rollback returns the joined error and current is where it was; the next round retries), `crash_recovery_still_goes_to_last_good` (recover unchanged: the existing crash tests plus one assertion that recover calls RollbackTarget).
    - `TestAtRollbackTarget` additions (the function is apply.go:707-717; Apply's start treats a current that is not last-good and not a rollback target as an interrupted move and recovers it to last-good, apply.go:488, and HostCerts and ProbeCerts treat it as unfinished, hostcert.go:169 and probe.go:251): `kept_state_is_a_rollback_target` (a current that is a fixed point of RollbackKeeping(current, last-good) counts), `plain_target_still_counts`, `a_wider_current_is_not_a_target`; and in `TestRollbackSites`: `next_apply_does_not_recover_a_kept_state` (after a kept rollback the next Apply reports no recovery and the removal is still absent), `hostcert_and_probe_steps_not_blocked_by_kept_state`, `second_round_does_not_commit_untested_current` (the listener stall stays for two rounds after a kept pure narrowing: the second round neither commits nor makes the current generation last-good).
    - Every existing rollback test is run; those whose expectation changes are listed in the SUMMARY with the old and the new principals (Context: Existing tests this plan changes).
  </behavior>
  <action>
**Step 0. Branch, reconcile, bases.** (1) `git fetch origin`, then create `p03/10d-no-regrant-recovery` from origin/main (03-10c merged). Place this plan file untracked in the phase directory if it is not on main yet. Create the SUMMARY draft (frontmatter `status: in-progress`, `requirements-completed: []` until Task 3). (2) **Reconcile.** Every path:line of apply.go, probegate.go and probegate_test.go in this plan was taken at cee452a; 03-10c's Task 1 edited those files. Re-read each function this task names (forward and its rollback sites, rollback, backToLastGood, rollbackTarget, recover, atRollbackTarget, settleFailedAddition, gateSuperseded, heldPresent, the equal-content commit, the fixtures gateHost, ready, scriptProbes, mustPrincipals, heldNow) and write a table of old and new line numbers in the SUMMARY; if a premise changed (a site disappeared, the account check moved a call), stop and report before writing a test. (3) Measure the quiet test-time base on unchanged origin/main in a detached worktree outside the repository (the command of Budget and verify) and write the single `test-time base:` line.

**Step 1. Enumerate and RED first.** Write a table in the SUMMARY of every rollback site (the six of forward, the two settle calls, the seven rollback calls of settleFailedAddition (six error fallbacks and the plain case at :950), gateSuperseded's error return and the one of `recover`): what current names at that point, what the kept content is, and the planned behaviour (keep, plain because nothing landed, or out). Write the tests of `<behavior>`; run the whole apply package once to see which existing tests fail as the new tests are not yet satisfied, and record both lists. Compile failures count as RED.

**Step 2. The function (render.go).** `RollbackKeeping(cur, lg *Generation) *Generation`: let t be RollbackTarget(cur, lg); if cur is nil or cur covers t (nothing t grants is missing from cur, `covers(cur, t)`), return t; otherwise the generation whose CA lines and principal lines are those of t that cur also holds (the vocabulary and the intermediate header of Intermediate, in t's order), whose revocation lists are t's (the newest by KRL version) and whose Host and HostStatus are t's, with N 0. It is a pure function; it never adds a line that cur lacks and never drops one that both hold. RollbackTarget itself is byte-unchanged (recover and the interleave model use it).

**Step 3. The rollbacks (apply.go).** `rollback(ctx, cause, lg)` becomes a thin call of `rollbackAs(ctx, cause, lg, true)`; backToLastGood and rollbackTarget take the flag; with it true the target is RollbackKeeping(from, lgGen), with it false RollbackTarget as today; `recover` passes false. forward records preN (the generation live just before the final widening swap, as settleFailedAddition already tracks it) in an engine field; rollbackTarget reuses, in this order, last-good itself when the kept content is last-good's, current when its bytes are the kept content (as it does today), that recorded generation when its content equals the kept content (the common case of a failure after the final swap: the narrowing intermediate that Transition installed and validated), else installs and validates a new generation; an error there is returned joined with the cause, and current stays where it is (D1, T-03-388). forward and settleFailedAddition keep every call as `e.rollback`; no call site is rewritten except that settleFailedAddition's own computation of the kept content now shares the helper, and its listener-failure fallback needs no special case. The settle path's commit of M as last-good is unchanged. A rollback commits nothing and does not advance accepted/, so the next round is unapplied and re-renders without a held record (Task 1's own subtests prove it for every site, probes on and off, because heldPresent ignores the switch).

**Step 3b. Two guards that a kept state needs.** (1) `atRollbackTarget` (apply.go:707-717) also returns true when current's bytes equal RollbackKeeping(current, last-good): without it the next Apply's start (apply.go:488) would take a kept current for an interrupted move and run `recover`, whose plain backToLastGood re-grants the removal at once, and HostCerts and ProbeCerts (hostcert.go:169, probe.go:251) would hold as unfinished. A pending marker still wins (the first operand of that condition), so a crash during the keeping rollback itself is the unchanged crash residual. (2) forward's equal-content commit (apply.go:1001-1022) commits current as last-good without a listener test; when current is not last-good (`curLink.n != lg.n`), it must first pass `e.selfTest`, and a failure returns the error without committing, so a generation whose listener test failed never becomes last-good by being found equal to the next candidate. Report the extra listener test in the SUMMARY (tests that count self-tests are in the changed list).

**Step 4. Report values.** `Report.Rollback` stays true; RollbackSelfTest is the listener test on the kept generation; the status after a rollback reports last-good's host status as before. If a status test's expectation changes only because the kept generation is not last-good, change the expectation and say so in the SUMMARY.

**Step 5. Gates.** Run the apply package under -race, the interleave model tests, the lints, capslock, and record the new test times against the base (the delta rule). Move the todo to the completed folder in this task's last commit.

**Mutants** (the task's work committed first; one SUMMARY line each): RollbackKeeping returning the union instead of the intersection (TestRollbackKeeping/mixed_is_intersection); returning RollbackTarget always (TestRollbackKeeping/pure_narrowing_stays); dropping the newest-KRL rule (newest_krl_kept); ignoring `covers` so a pure addition gets a new generation (pure_addition_is_last_good); and, for each of the sites, flipping that one call to `rollbackAs(..., false)`: apply.go:1070 (TestRollbackSites/read_current_error), :1078 (gate_superseded_error), :1117 (transition_error), :1125 (write_dropin_error), :1129 (activate_dropin_error), :1137 (self_test_failure), and each of the six error fallbacks of settleFailedAddition (probegate.go:943, :963, :967, :974, :978, :983, each with its own subtest; :950 is the legitimate plain rollback of a pure addition and stays plain); `recover` flipped to the keeping variant (TestRollbackSites/crash_recovery_still_goes_to_last_good); the install error swallowed so the rollback returns nil (TestRollbackSites/m_install_fails_leaves_current); atRollbackTarget left as it is (TestRollbackSites/next_apply_does_not_recover_a_kept_state); the equal-content commit without the listener test (TestRollbackSites/second_round_does_not_commit_untested_current). Each probes-off and probes-on pair dies on its own `/probes_off` or `/probes_on` subtest; a mutant that only one of the two kills is reported with the reason. The executor rule applies.
  </action>
  <verify>
    <automated>L=$(bash scripts/linux.sh 'go build ./... && go vet ./... && go vet -tags keyroster_e2e ./internal/agent/... && go test -race -count=1 -timeout 15m -v -run "^(TestRollbackKeeping|TestRollbackSites|TestProbeGate)$" ./internal/agent/apply/' 2>&1) && ( for n in TestRollbackKeeping/pure_addition_is_last_good TestRollbackKeeping/pure_narrowing_stays TestRollbackKeeping/mixed_is_intersection TestRollbackKeeping/newest_krl_kept TestRollbackKeeping/never_grants_what_cur_lacks TestRollbackSites/read_current_error/probes_off TestRollbackSites/transition_error/probes_on TestRollbackSites/write_dropin_error/probes_off TestRollbackSites/self_test_failure/probes_on TestRollbackSites/settle_install_error/probes_on TestRollbackSites/settle_validate_timeout/probes_on TestRollbackSites/settle_held_write_error/probes_on TestProbeGate/settle_listener_failure_keeps_removal TestRollbackSites/pure_addition_failure_goes_back_to_last_good/probes_on TestRollbackSites/pure_narrowing_failure_keeps_removal/probes_off TestRollbackSites/m_install_fails_leaves_current TestRollbackSites/crash_recovery_still_goes_to_last_good; do printf '%s\n' "$L" | grep -qF -- "--- PASS: $n (" || { echo "missing PASS: $n"; exit 1; }; done ) && ! printf '%s\n' "$L" | grep -qE '^(--- FAIL|FAIL|panic:)|DATA RACE'</automated>
    <fails_when>non-zero exit, a missing PASS line, FAIL, a panic or DATA RACE</fails_when>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./internal/agent/...' && git diff --quiet origin/main -- internal/agent/apply/interleave_test.go internal/agent/apply/swap.go internal/agent/apply/selftest.go</automated>
    <fails_when>non-zero exit: an existing agent test fails, or the swap, the listener test or the interleave model were edited (the model proves the swap order and must not change)</fails_when>
    <automated>bash scripts/capslock-check.sh && git diff --quiet origin/main -- test/capslock internal/wire internal/tlog internal/cert internal/certprofile internal/signer internal/server internal/audit && test ! -e .planning/todos/pending/2026-11-08-no-rollback-regrants-a-landed-removal.md && test "$(grep -c 'func RollbackKeeping(' internal/agent/apply/render.go)" -eq 1</automated>
    <fails_when>non-zero exit: a new capability pair, a frozen package changed, the todo is still in pending, or the function is missing</fails_when>
  </verify>
  <acceptance_criteria>
    - Every rollback site of the SUMMARY's table has a subtest, probes off and on, and a mutant that restores the plain rollback at that site; the list of existing tests whose expectation changed is in the SUMMARY.
    - The residuals are written down: crash recovery still goes to last-good (the crash residual of 03-10b stays); the double failure of D1.
  </acceptance_criteria>
  <done>A failed apply after a removal has landed never grants the removed access again; a pure addition that fails still goes back to last-good; crash recovery is unchanged.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2 (todo 2026-11-07; owner decision Q-R option 1): a recovery revokes every lost probe certificate, and the signer and `audit verify` refuse a recovery that carries one unrevoked</name>
  <reversibility rating="costly">It tightens a rule that the signer and the audit verifier share (a recovery request that was valid before is refused after, and an old log that holds one would fail `audit verify`); the format of the request is not changed, but the rule is part of the log's meaning.</reversibility>
  <precondition>`git merge-base --is-ancestor cee452a origin/main` exits 0; owner decision Q-R option 1 (2026-11-08) is binding; `git grep -q 'func CheckCarriedLost(' origin/main -- internal/krl/recovery.go` exits 0 and `git grep -q 'ErrLostProbeKept' origin/main -- internal/krl` exits 1; the todo file `.planning/todos/pending/2026-11-07-recovery-revokes-lost-negative-probe-certificates.md` exists on origin/main.</precondition>
  <files>internal/krl/recovery.go, internal/krl/recovery_test.go, internal/signer/recovery.go, internal/signer/recovery_test.go, internal/audit/recovery.go, internal/audit/recovery_test.go, internal/audit/verify_test.go, cmd/keyroster/recover.go, cmd/keyroster/recover_test.go, docs/runbooks/signer-install.md, .planning/todos/pending/2026-11-07-recovery-revokes-lost-negative-probe-certificates.md, .planning/phases/03-linux-agent-and-revocation/03-10d-SUMMARY.md</files>
  <read_first>
    - internal/krl/recovery.go :1-110 (CheckCarriedLost, its errors, RecoveredCert, RecoveryEntries); internal/signer/recovery.go :70-150 and :310-380 (RecoverRevocations, the carried-certificate struct and its role); internal/audit/recovery.go :100-140; cmd/keyroster/recover.go :60-135, :268-330 and :425-450 (the flags, the lost-certificate loop, the output lines).
    - internal/cert/keyid.go :55-100 (ParseKeyID, KeyID fields CA, Subject, V3; keyIDProbeRE); internal/signer/probeissue.go :169-215 (the key ID a probe certificate gets: a random request ID, no polarity); internal/wire/recovery.go :60-70 (RecoveredCertificate is Cert and Revoke).
    - internal/signer/recovery_test.go and internal/audit/verify_test.go :3430-3490 (the table of refusals that names recovery_user_certificate_kept) for the fixtures; cmd/keyroster/recover_test.go for the export fixtures; docs/runbooks/signer-install.md :1100-1160.
    - The todo file whole; 03-10-SUMMARY.md 'Pre-merge review' (R9, D-R1).
  </read_first>
  <behavior>
    - `krl.IsProbeKeyID(kid cert.KeyID) bool` (internal/krl/recovery.go; `TestIsProbeKeyID`): true for a kr3 key ID with ca=machine and a subject starting `probe.`; false for any other machine subject, for ca=host or ca=user with such a subject, and for kr1 and kr2.
    - `krl.CheckCarriedLost(validBefore, createdAt uint64, user, probe, revoke bool)` gains `probe` and `ErrLostProbeKept`: a revoked certificate is always carried; otherwise expired is ErrLostExpired, a user certificate ErrLostUserKept, and a probe certificate ErrLostProbeKept. `TestCheckCarriedLost` subtests: `probe_kept_is_refused`, `probe_revoked_ok`, `probe_expired_and_revoked_ok`, `probe_expired_and_kept_is_expired_first` (the existing order is kept: expiry before kind), `machine_non_probe_may_be_kept`, `user_rules_unchanged`.
    - Signer (`TestRecoverRevocations`): `lost_probe_certificate_kept_is_refused` with the new refusal code `recovery_probe_certificate_kept` and a message that says a recovery revokes every lost probe certificate; `lost_probe_certificate_revoked_is_listed` (the published KRL lists its serial under the machine CA key); `lost_machine_certificate_still_keepable`.
    - Audit (`verify_test.go`, beside the :3439 table): a carried probe certificate with revoke false fails `audit verify` with `(recovery_probe_certificate_kept)`; with revoke true it verifies; a carried non-probe machine certificate kept still verifies.
    - CLI (`TestRevokeRecover` additions): `lost_negative_probe_revoked_without_flag`, `lost_positive_probe_revoked_too`, `kept_machine_certificate_unchanged`, `output_says_probe_certificate_revoked` (the per-certificate line says `revoke` and the summary names the reason), `revoke_lost_flag_accepts_a_probe_serial` (naming a probe serial by `--revoke-lost` stays valid and changes nothing).
    - `pop_hosts_off_fails` (verify_test.go :3951, the follow-up of 03-09): the subtest fails through audit's own host-issue rule, not through the policy-install rule that refuses clearing pop.hosts; its `wantFail` text is audit's.
  </behavior>
  <action>
**Step 1. RED first.** Write the tests (compile failures count) and record them. For `pop_hosts_off_fails`, first show in the SUMMARY which rule produces the present failure text (the fixture's installPolicy runs the trust rule), then build the fixture so that the policy without pop.hosts is in force in the log by the route audit's own verification accepts, and the failure comes from the host-issue rule. If that cannot be done within a tenth of this task's budget, leave the subtest as it is and move the item to 'Not done here' with the reason; do not widen the task.

**Step 2. The rule.** Add `IsProbeKeyID`, the `probe` parameter and the error to internal/krl/recovery.go and update its doc comment (a recovery revokes every lost user certificate and every lost probe certificate; the polarity of a probe certificate is not in its bytes, D2). Callers: the signer passes the result of IsProbeKeyID on the certificate's parsed key ID and maps ErrLostProbeKept to `recovery_probe_certificate_kept`; audit does the same and words the error with the code in parentheses; cmd/keyroster/recover.go decides `revoke := user || probe || named[serial]` and passes `probe` to CheckCarriedLost. No wire type, no tlog body and no registry document changes.

**Step 3. The text.** docs/runbooks/signer-install.md (near :1138) names the new refusal beside the two existing ones and says in one paragraph that lost probe certificates, both polarities, are revoked by the recovery, that the hosts then ask for a new pair, and what that costs (additions on those hosts wait, owner answer P4); nothing else in the runbook changes.

**Step 4. Gates and todo.** Run the packages under -race, the lints, capslock and the frozen-file diff; move the todo to the completed folder in the last commit.

**Mutants** (the task's work committed first; one SUMMARY line each): IsProbeKeyID matching a non-machine CA (TestIsProbeKeyID); matching any machine subject (the same); CheckCarriedLost ignoring `probe` (TestCheckCarriedLost/probe_kept_is_refused); the probe check placed before the expiry check (probe_expired_and_kept_is_expired_first); the signer passing probe=false (TestRecoverRevocations/lost_probe_certificate_kept_is_refused); audit passing probe=false (the verify_test.go row); the CLI deciding revoke without probe (TestRevokeRecover/lost_negative_probe_revoked_without_flag); the CLI revoking only the polarity it can see in the export (lost_positive_probe_revoked_too); the CLI revoking every machine certificate (kept_machine_certificate_unchanged); the signer refusing every kept machine certificate (lost_machine_certificate_still_keepable). The executor rule applies.
  </action>
  <verify>
    <automated>L=$(bash scripts/linux.sh 'go build ./... && go vet ./... && go test -race -count=1 -timeout 15m -v -run "^(TestIsProbeKeyID|TestCheckCarriedLost|TestRecoverRevocations|TestRevokeRecover)$" ./internal/krl/ ./internal/signer/ ./cmd/keyroster/' 2>&1) && ( for n in TestIsProbeKeyID TestCheckCarriedLost/probe_kept_is_refused TestCheckCarriedLost/probe_revoked_ok TestCheckCarriedLost/probe_expired_and_kept_is_expired_first TestCheckCarriedLost/machine_non_probe_may_be_kept TestCheckCarriedLost/user_rules_unchanged TestRecoverRevocations/lost_probe_certificate_kept_is_refused TestRecoverRevocations/lost_probe_certificate_revoked_is_listed TestRecoverRevocations/lost_machine_certificate_still_keepable TestRevokeRecover/lost_negative_probe_revoked_without_flag TestRevokeRecover/lost_positive_probe_revoked_too TestRevokeRecover/kept_machine_certificate_unchanged; do printf '%s\n' "$L" | grep -qF -- "--- PASS: $n (" || { echo "missing PASS: $n"; exit 1; }; done ) && ! printf '%s\n' "$L" | grep -qE '^(--- FAIL|FAIL|panic:)|DATA RACE'</automated>
    <fails_when>non-zero exit, a missing PASS line, FAIL, a panic or DATA RACE</fails_when>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./internal/krl/ ./internal/signer/ ./internal/audit/ ./internal/tlog/ ./internal/wire/ ./cmd/keyroster/' && git diff --quiet origin/main -- internal/wire internal/tlog internal/cert internal/certprofile internal/server internal/serverclient docs/format-registry.md test/capslock && bash scripts/capslock-check.sh && test ! -e .planning/todos/pending/2026-11-07-recovery-revokes-lost-negative-probe-certificates.md</automated>
    <fails_when>non-zero exit: a test of the shared packages fails (the audit package's recovery tests included), a frozen package, the registry or a capslock baseline changed (this task changes the rule, not a format), or the todo is still in pending</fails_when>
    <automated>bash scripts/linux.sh '$HOME/go/bin/golangci-lint run ./... && GOOS=windows $HOME/go/bin/golangci-lint run ./... && GOOS=darwin $HOME/go/bin/golangci-lint run ./... && test -z "$(gofmt -l internal cmd)"' && grep -q 'recovery_probe_certificate_kept' docs/runbooks/signer-install.md</automated>
    <fails_when>non-zero exit or a lint issue for any GOOS, or the runbook does not name the new refusal</fails_when>
  </verify>
  <acceptance_criteria>
    - Every lost probe certificate, positive or negative, is revoked by `keyroster revoke recover` without a flag, and the signer and `audit verify` refuse a request that carries one unrevoked; the mutant lines are in the SUMMARY; T5 is recorded.
    - `git diff --name-only origin/main -- internal/wire internal/tlog internal/cert internal/certprofile docs/format-registry.md` prints nothing.
  </acceptance_criteria>
  <done>A signer restore can no longer leave a lost probe certificate unrevoked; the polarity question is answered without a format change.</done>
</task>

<task type="auto">
  <name>Task 3: the gates, the PR, the pre-merge review and the SUMMARY (the owner's merge gate follows)</name>
  <precondition>The verify of Tasks 1 and 2 passes on this branch, and the SUMMARY records T1 and T2.</precondition>
  <files>.planning/phases/03-linux-agent-and-revocation/03-10d-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md, .planning/REQUIREMENTS.md, .planning/phases/03-linux-agent-and-revocation/03-10d-SUMMARY.md</files>
  <read_first>
    - ROADMAP.md's `**Plans:**` line and the 03-10d row (added by 03-10c's tracking), REQUIREMENTS.md's AGENT-04 line (:56) and its traceability row (:201); 03-10c-SUMMARY.md for the shape and for `AGENT-04: open until 03-10d`.
    - scripts/capslock-check.sh header, scripts/merge-gate.sh usage line, scripts/gh-as-bot.sh usage.
  </read_first>
  <action>
**Publish.**
1. The plan file `.planning/phases/03-linux-agent-and-revocation/03-10d-PLAN.md` with `wave: 26` and `depends_on: ["03-10c"]` is on main already if 03-10c's executor committed it with the row; if it is not, commit it here. Verify, do not duplicate.
2. ROADMAP.md: tick this plan's row (03-10c's tracking added it at wave 26 and moved 03-11 to 03-16 one wave later) and let GSD's tracking update recompute the Plans line and the Progress table; REQUIREMENTS.md: tick AGENT-04 and set its traceability row to Complete; STATE.md through the tracking update. Do not touch any other plan file.
3. **Capslock.** `bash scripts/capslock-check.sh` must pass and `test/capslock` must be unchanged. Neither task adds a capability; a new pair is a stop-and-report: a baseline change needs a reviewed `chore(capslock)` commit, which this plan does not expect.

**Push, the PR and the pre-merge review.**
1. Commit by path only, signed and authored as Daniel; run the gates below.
2. Push, then `scripts/gh-as-bot.sh pr create --title "fix(agent): keep a landed removal through a rollback and revoke every lost probe certificate"`. The body is neutral: the changes, the owner decisions (Q-S, Q-R, Q-D, D-R1), the deviations and what stays UNVERIFIED. Never enable auto-merge.
3. Wait for the required checks, the seven `e2e-distro` jobs, both `e2e-probe` lanes and `systemd-sandbox` included.
4. The orchestrator runs the pre-merge review on the green PR, as a full security review against T-03-374, T-03-388 and T-03-389, with the rollback rule, its two guards and the recovery rule flagged for the review, and checks the diff for real host names, private addresses and private terms. Fix rounds go into the SUMMARY.

**The SUMMARY** contains: the base line (`test-time base:`) and the Reconcile table of Task 1 Step 0; T1 and T2 (the last commit of each); the PR number and check run IDs; the RED evidence and the mutants of both tasks; every test-time reading as base, reading and delta; the e2e elapsed times of the PR run against 03-10c's; the table of rollback sites and the list of existing tests whose expectation changed; the line `Owner answers: Q-S Q-R Q-D D-R1 P4`; `AGENT-04: complete` and `requirements-completed: [AGENT-04]`; the deviations; the gate control lines (`gate control: files gate exits 0 on the branch as committed`, `gate control: files gate exits 1 on a throwaway detached worktree with one commit adding an unlisted file`); one `mutant killed: <description> (<subtest>)` line per mutant, or `mutant equivalent: <description>: <reason>`; the UNVERIFIED list (Edge Coverage); and 'For later plans': 03-12's CA rotation waits on a host with a broken probe account (R11), current may differ from last-good after a kept rollback (03-12 and 03-14 read current), and the older follow-ups of 'Not done here'.

Then run the tracking updates once, commit `docs(03-10d): complete rollback-and-recovery plan`, push, and wait for the checks again.

**Owner merge gate (not a task).** Stop here. Daniel reviews, approves and squash-merges in the GitHub web UI with his commit email and replies "merged"; Claude never approves, merges or enables auto-merge, and before the merge runs only `bash scripts/merge-gate.sh --check p03/10d-no-regrant-recovery`. If main moved first, Claude runs `git rebase --gpg-sign origin/main`, takes origin/main's tracking files and re-applies only this plan's entries, pushes with lease, waits for the checks, re-runs the gates and asks for a review of the new head. After "merged", from the main checkout: `bash scripts/merge-gate.sh p03/10d-no-regrant-recovery`, then the `--check` form.
  </action>
  <verify>
    <automated>git diff --quiet HEAD -- .planning/ROADMAP.md .planning/STATE.md .planning/REQUIREMENTS.md && test -z "$(git ls-files --others --exclude-standard .planning/phases/03-linux-agent-and-revocation/03-10d-*.md)" && git diff --quiet HEAD -- .planning/phases/03-linux-agent-and-revocation</automated>
    <fails_when>non-zero exit: an edit this task publishes is not committed (the guard is path-scoped so that .planning/config.json and the other intentionally dirty files do not fail it)</fails_when>
    <automated>git diff --quiet origin/main -- test/capslock && grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./... && go vet ./... && go vet -tags keyroster_e2e ./internal/agent/... ./cmd/keyroster-agent/ && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e e2eprobe" ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && go vet -tags e2edistro ./test/distro/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && GOOS=windows $HOME/go/bin/golangci-lint run ./... && GOOS=darwin $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit (a test failed, a lint issue for any GOOS, a capslock pair or baseline change, or a firewall or pinned-action failure). The whole-module run is pass or fail only</fails_when>
    <automated>set -o pipefail; S=.planning/phases/03-linux-agent-and-revocation/03-10d-SUMMARY.md; { test "$(grep -c '^test-time base: ' $S)" -eq 1 && T=$(sed -n 's/^test-time base: .* at=\([0-9][0-9]*\)$/\1/p' $S) && test -n "$T" && test $(( $(date +%s) - T )) -le 86400 || { echo 're-measure the base (Budget and verify, test time)'; false; }; } && g() { sed -n "s/^test-time base: .* $1=\([0-9.]*\) .*/\1/p" $S; } && A=$(g apply) && K=$(g krl) && SG=$(g signer) && AU=$(g audit) && C=$(g cmd) && G=$(g agentcmd) && test -n "$A" && test -n "$K" && test -n "$SG" && test -n "$AU" && test -n "$C" && test -n "$G" && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./internal/agent/apply/ ./internal/krl/ ./internal/signer/ ./internal/audit/ ./cmd/keyroster/ ./cmd/keyroster-agent/' | awk -v a="$A" -v k="$K" -v s="$SG" -v u="$AU" -v c="$C" -v g="$G" '{print} $1=="ok" {t=$3; sub(/s$/,"",t); if ($2 ~ /\/internal\/agent\/apply$/) {n++; if (t+0 > a+90) bad=1} else if ($2 ~ /\/internal\/krl$/) {n++; if (t+0 > k+90) bad=1} else if ($2 ~ /\/internal\/signer$/) {n++; if (t+0 > s+90) bad=1} else if ($2 ~ /\/internal\/audit$/) {n++; if (t+0 > u+90) bad=1} else if ($2 ~ /\/cmd\/keyroster$/) {n++; if (t+0 > c+90) bad=1} else if ($2 ~ /\/cmd\/keyroster-agent$/) {n++; if (t+0 > g+90) bad=1}} END{exit (n!=6||bad)}'</automated>
    <fails_when>non-zero exit: the base is missing or over 24 h old (re-measure it as Task 1 Step 0 does, replace the line, run again), or one of the six packages added more than 90 s over the base in this separate run</fails_when>
    <automated>got=$(git grep -l -F "keyroster_e2e" -- . ":(exclude).planning" | sort) && want=$(printf '%s\n' cmd/keyroster-agent/probeoff.go cmd/keyroster-agent/probeoff_e2e.go cmd/keyroster-agent/probeoff_test.go internal/agent/apply/probeoff_e2e.go test/distro/run.sh test/e2e/agent_apply_test.go | sort) && test "$got" = "$want"</automated>
    <fails_when>non-zero exit: the test-build tag is outside its six files (this plan adds it to none)</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && D=$(git diff --name-only --no-renames origin/main...HEAD) && FM=$(awk '/^files_modified:/{f=1;next} f && /^  - /{sub(/^  - /,""); print; next} f{exit}' $P/03-10d-PLAN.md) && test -n "$FM" && X=$(printf '%s\n' "$D" | grep -vxF -f <(printf '%s\n%s\n' "$FM" "$P/03-10d-SUMMARY.md") || true) && test -z "$X" && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics' && git diff --quiet origin/main...HEAD -- internal/wire internal/tlog internal/cert internal/certprofile internal/serverclient internal/server docs/format-registry.md test/capslock cmd/keyroster/root.go cmd/keyroster/trust.go internal/rootceremony internal/trust test/vectors</automated>
    <fails_when>non-zero exit: the branch changes a file outside files_modified, a forbidden file, or a frozen package. The grep inside the command substitution exits 1 when it finds nothing, which is the correct case, so it carries `|| true`. The SUMMARY records two controls: `gate control: files gate exits 0 on the branch as committed` and `gate control: files gate exits 1 on a throwaway detached worktree with one commit adding an unlisted file`</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')" && RL=$(git rev-list origin/main..HEAD) && test -n "$RL" && ( for c in $RL; do C=$(git cat-file commit "$c") || exit 1; printf '%s\n' "$C" | grep -q '^gpgsig' || exit 1; done )</automated>
    <fails_when>non-zero exit (no commits, a commit by another author or committer than keyroster-bot, or an unsigned commit)</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && grep -qx 'wave: 26' $P/03-10d-PLAN.md && grep -qx 'depends_on: \["03-10c"\]' $P/03-10d-PLAN.md && git diff --quiet origin/main...HEAD -- $P/03-10-PLAN.md $P/03-10b-PLAN.md $P/03-10c-PLAN.md $P/03-11-PLAN.md $P/03-12-PLAN.md $P/03-13-PLAN.md $P/03-14-PLAN.md $P/03-15-PLAN.md $P/03-16-PLAN.md && RD=$(git diff -U0 origin/main...HEAD -- .planning/ROADMAP.md) && R=$(printf '%s\n' "$RD" | grep -E '^[-+]' | grep -vE '^(\+\+\+|---) ') && test -n "$R" && ! printf '%s\n' "$R" | grep -vE '^[-+]- \[( |x)\] 03-10d-PLAN\.md — |^[-+]\*\*Plans:\*\* [0-9]+/[0-9]+ plans executed in [0-9]+ waves|^[-+]\| 3\. Linux Agent and Revocation \| [0-9]+/[0-9]+ \|' | grep -q .</automated>
    <fails_when>non-zero exit: this plan's wave or dependency is wrong, a later plan file changed, or ROADMAP.md changed in any line but this plan's checkbox and the Plans and Progress tracking tokens. The SUMMARY records that on origin/main the changed-line filter is empty, so `test -n "$R"` fails there and the gate bites</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && S=$P/03-10d-SUMMARY.md && git fetch origin p03/10d-no-regrant-recovery && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:$S && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:$P/03-10d-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && grep -qx 'Owner answers: Q-S Q-R Q-D D-R1 P4' $S && grep -qx 'AGENT-04: complete' $S && grep -qE '^requirements-completed: \[AGENT-04\]' $S && grep -qE '^gate control: files gate exits 0 on the branch as committed' $S && grep -qE '^gate control: files gate exits 1 on a throwaway' $S && test "$(grep -c '^mutant killed: ' $S)" -ge 28 && test $(( $(grep -c '^mutant killed: ' $S) + $(grep -c '^mutant equivalent: ' $S) )) -ge 30</automated>
    <fails_when>non-zero exit: the SUMMARY or plan is not on the pushed branch, local commits are unpushed, a required SUMMARY line is missing, or it records fewer than 28 killed mutants or fewer than 30 killed and equivalent together (Task 1 lists 20 and Task 2 lists 10; an equivalent mutant is reported as `mutant equivalent: <description>: <reason>`)</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && DA=$(git diff origin/main...HEAD) && test -n "$DA" && A=$(printf '%s\n' "$DA" | grep '^+') && L=$(git log origin/main..HEAD --format=%B) && B=$(scripts/gh-as-bot.sh pr view p03/10d-no-regrant-recovery --json body --jq .body) && W1="FIX""-PLAN|FIND""INGS|App""Data" && W2="security-audit""-skill|scratch""pad|run""-1" && ! printf '%s\n%s\n%s\n' "$A" "$L" "$B" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | grep -q . && ! printf '%s\n%s\n%s\n' "$A" "$L" "$B" | grep -qE "$W1" && ! printf '%s\n%s\n%s\n' "$A" "$L" "$B" | grep -qiE "$W2" && ! cat $P/03-10d-PLAN.md $P/03-10d-SUMMARY.md | grep -qE "$W1" && ! cat $P/03-10d-PLAN.md $P/03-10d-SUMMARY.md | grep -qiE "$W2" && printf '%s\n%s\n' "$L" "$B" | grep -ciE 'co-authored-by|generated with' | grep -qx 0</automated>
    <fails_when>non-zero exit: an IP address outside 127.0.0.0/8, a private-workspace term (the split literals above) or an attribution line is in an added diff line, a commit message, the PR body, the plan or the SUMMARY</fails_when>
    <automated>B=p03/10d-no-regrant-recovery && scripts/gh-as-bot.sh pr checks $B --required --watch && PROBE_PASS='TestProbeSelfTestEndToEnd TestProbePairSpacing TestProbeCertsAgainstSSHD TestProbeSSHDFacts TestProbeSelfTestEndToEnd/pair_issued_and_enforced TestProbeSelfTestEndToEnd/widening_passes_probes TestProbeSelfTestEndToEnd/positive_refused_rolls_back TestProbeSelfTestEndToEnd/unusable_account_holds_widening_krl_and_narrowing_land TestProbeSelfTestEndToEnd/fixing_the_account_lands_the_held_addition' MODE=pr bash <(sed -n '/^# E2E_GATE_BEGIN/,/^# E2E_GATE_END/p' .planning/phases/03-linux-agent-and-revocation/03-10b-PLAN.md)</automated>
    <fails_when>non-zero exit (a required check failed or never reported, the seven e2e-distro jobs and systemd-sandbox included, or the PR's e2e run did not pass the named tests in both probe lanes with the main lanes under 900 s and showing no probe test)</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/10d-no-regrant-recovery --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every commit is authored as Daniel, committed by keyroster-bot and signed; the capslock baselines, the registry and every frozen package are untouched; the tag is in six files.
    - The PR is open without auto-merge with every required check green and 03-10d-SUMMARY.md on its head; the pre-merge review is recorded.
  </acceptance_criteria>
  <done>The PR waits green and reviewed for the owner's merge gate, with the plan, the SUMMARY and the tracking update; AGENT-04 is complete when it merges.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Edge Coverage (spec-less fallback, this plan)

**UNVERIFIED in this repository** (nothing named above exercises it; the SUMMARY repeats the list):
- Crash recovery still goes back to last-good (`recover`), so a crash between the final swap and the commit of a mixed change, or a crash during the keeping rollback itself (its marker is pending and wins), can still re-grant a removal for about one round. No test crashes at those points.
- The double failure of D1 (Q-D option 1) leaves current on the failed target until the next round (T-03-388); for a gated addition that is a live unproven addition.
- Current may now name a generation that is neither last-good nor last-good's content after a rollback. 03-12 (CA rotation) and 03-14 read current: whether they need to know is UNVERIFIED and listed in 'For later plans'.
- The extra listener test of the equal-content guard on a path found by the next candidate: whether any e2e or distro test counts listener tests is found by the RED run.
- Recovery: an old log that holds a recovery which kept a lost probe certificate would fail `audit verify` after the change (UNVERIFIED that none exists; 03-10 merged days before and no release has shipped); the recovery path itself is UNVERIFIED end to end (03-10's R9); a revoked lost positive makes its host ask for a new pair and wait (P4).
- A lost probe certificate that the saved export cannot show (the export itself lost) is not recoverable by this rule; it expires with its lifetime (at most seven days, min with the machine cap).

**Deviations from the todos:** the recovery todo's third test, 'a lost positive can still be kept', is replaced by 'a lost positive is revoked too' (Q-R option 1); the rollback todo's 'last-good itself remains the target only when the target removes nothing that last-good grants' is implemented as lg intersect current, which equals last-good exactly in that case.

## Not done here (never silently dropped)

| Item | Where it goes |
|---|---|
| A polarity field in the recovery request (keeps a lost positive) | Not planned: a format change, declined by Q-R option 1 |
| Crash recovery keeping removals (a marker-aware recovery target) | Later: not planned; the residual is named. The marker carries from, to and mid, which a future plan could use |
| `pop_hosts_off_fails` of 03-09 passing through trust's rule | Task 2 (conditional); if the fixture cannot be built within the tenth-of-budget limit it stays here with the reason |
| 03-12's CA rotation waiting on a broken probe account; 03-14 mirroring account.go; a capability-less root on a mode-0000 shadow | 03-12, 03-14 and 03-16 respectively; recorded in 'For later plans' |
| The account check, matrix, systemd test, runbook, audit line | 03-10c |

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access removed stays removed; no lockout | Task 1 |
| REQ | AGENT-04 ('rolls back on failure') | Task 1 and the whole plan; complete when it merges |
| CONTEXT | D-06 (probes never roll back a removal, Q2) | Task 1 |
| Owner | Q-S, Q-R, Q-D, D-R1, P4 | Tasks 1 and 2 |
| Todos | 2026-11-08 (rollback), 2026-11-07 (recovery) | Tasks 1 and 2; each todo is moved when done |
| 03-10b | the third UNVERIFIED residual (transient local error rolls back to last-good) and the listener-failure fallback | Task 1 (`TestRollbackSites/*`, `TestProbeGate/settle_listener_failure_keeps_removal`) |
| 03-10c hand-over | the two todos | This plan |
| Older follow-up | `pop_hosts_off_fails` | Task 2 (conditional) |

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| failed apply -> rollback target | What a rollback may grant again after a removal landed |
| signer restore -> recovery request | Which lost certificates a recovery must revoke |
| current (not last-good) -> Apply's start and the equal-content commit | A kept state must not be undone or promoted without a test |

## STRIDE Threat Register

Threat IDs are unique within the phase and across 03-10c and 03-10d. T-03-374 is inherited from 03-10b and rewritten here; T-03-388 and T-03-389 are new. 03-10c holds T-03-66, T-03-381, T-03-385 to T-03-387, T-03-390 and T-03-391. The highest ID any plan held when this plan was written is T-03-391; the next plan continues after it.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-374 | Tampering | A rollback re-granting a removal that landed | high | mitigate | Task 1: `rollback` ends in lg intersect current with the newest KRL at every forward error path, every settle fallback and gateSuperseded; a pure addition still returns to last-good; a kept state is accepted by atRollbackTarget so the next Apply does not undo it, and the equal-content commit needs a listener test (`TestRollbackKeeping/never_grants_what_cur_lacks`, `TestRollbackSites/*` probes off and on, the per-site mutants). Residuals: crash recovery goes to last-good (UNVERIFIED how often), and T-03-388 |
| T-03-388 | Elevation of privilege | Task 1's double failure: the kept generation cannot be installed or validated, so the rollback returns an error and current stays on the failed target, which for a gated addition is the live unproven addition until the next round | medium | accept | Chosen over re-granting the removal (Q-D option 1, owner decision 2026-11-08). The next round retries: accepted/ is not advanced, so the capture is unapplied and re-renders (`TestRollbackSites/m_install_fails_leaves_current` and the per-site next-round assertions); the reused generation (the narrowing intermediate that Transition installed, or current's bytes) makes the install rare |
| T-03-389 | Tampering | A signer restore leaving a lost probe certificate unrevoked, so that sshd accepts a negative the probe promises is refused | low | mitigate | Task 2: the CLI revokes every lost probe certificate by its key ID, and the signer and `audit verify` refuse a request that carries one kept (`TestCheckCarriedLost/probe_kept_is_refused`, `TestRecoverRevocations/lost_probe_certificate_kept_is_refused`, the audit row, the CLI subtests, the mutants). The certificate is restricted to force-command /bin/false and loopback sources, so the exposure was small. Residual: the restore path is UNVERIFIED end to end (03-10's R9) |
| T-03-SC | Tampering | dependencies and capabilities | low | mitigate | No module is added; the capslock baselines, the dependency firewall, the test-only firewall and the pinned actions are checked unchanged and green in Task 3 |
</threat_model>

<verification>
- Every verify command passes locally through scripts/linux.sh (lint for linux, windows and darwin, `go vet` of the tagged agent packages), or in CI as stated.
- The base and every delta use the one command of Budget and verify; the whole-module run is pass or fail.
- The PR's required checks are green, the e2e probe lanes under 420 s and the main lanes under 900 s with no probe test.
- The pre-merge review is recorded; the owner's merge gate follows.
</verification>

<success_criteria>
- No failed apply grants a landed removal again (crash recovery excepted and named); a kept state survives the next Apply and is never promoted to last-good without a listener test.
- No lost probe certificate stays unrevoked after a recovery; the signer and `audit verify` refuse a request that carries one.
- AGENT-04 complete; nothing frozen (wire, tlog, cert, certprofile, serverclient, server, registry, capslock) changed.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-10d-SUMMARY.md` in Task 1 as a draft, and complete it in Task 3, before the merge gate. It carries the base lines, the Reconcile table of Step 0, the owner-answers line, `AGENT-04: complete`, `requirements-completed: [AGENT-04]`, the mutant lines and the gate controls. Never record merge facts.
</output>
