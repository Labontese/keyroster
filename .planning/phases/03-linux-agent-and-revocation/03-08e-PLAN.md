---
phase: 03-linux-agent-and-revocation
plan: 08e
type: execute
wave: 14
depends_on: ["03-08d"]
files_modified:
  - internal/agent/spool/spool.go
  - internal/agent/spool/spool_test.go
  - internal/agent/fetch/fetch.go
  - internal/agent/fetch/fetch_test.go
  - internal/agent/apply/preflight.go
  - internal/agent/apply/drift.go
  - internal/agent/apply/adopt_test.go
  - cmd/keyroster-agent/apply.go
  - cmd/keyroster-agent/apply_test.go
  - docs/runbooks/host-setup.md
  - .planning/phases/03-linux-agent-and-revocation/03-08e-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [REVOKE-02, AGENT-04]

estimate:
  tokens: 75000
  raw_tokens: 75000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decisions Q-split (Daniel, 2026-10-29) and Q1 (Daniel, 2026-10-30): this plan holds F01, F09 and apply's path defaults, and runs second, after 03-08d. The rule F01 and F09 serve is D-R2's: a revocation never gets stuck on a host. F01 keeps a compromised server's answer from outliving the compromise; F09 keeps the run loop applying while a Phase 2 takeover's removal is unfinished"
    - "F01. The fetcher never spools a file that the applier's spool.Read would refuse. Before writeState writes anything, it refuses a state answer with `state_item_over_cap` and writes nothing, when:
      - an item's file is above the cap spool.Read applies to that file name; or
      - the answer holds more than serverclient.MaxAgentStatePerKind bundles or directories.
    spool.Cap(name) is the single source of those caps, and spool.Read uses it too. An honest answer never trips the check: the server stops at MaxAgentStatePerKind, and the signer bounds what it serves by tlog.MaxDocument, wire.MaxDirectory, wire.MaxDirectorySigs and the krl caps. honest_answers_fit_the_caps pins those equalities"
    - "F01 heal. At the start of every poll the fetcher removes each recognised regular spool file that is above its cap. It finds them by fixed-pattern name and does not follow links. A spool poisoned before this plan therefore heals at the next poll. Symlinks, non-regular files and unrecognised names are left alone: the applier still refuses them (T-03-225). Policy files are still replaced by name and never made write-once, and a replaced policy under the cap blocks nothing, because the applier finds its accepted policy by SHA-256 first"
    - "F09. Preflight, preflightApply and Check use one helper for the Phase 2 runbook's two lines in 50-keyroster.conf on an installed host. preflightApply drops those lines from the trust-setting hits exactly as Preflight and Check do today. While a takeover's removal is unfinished (readAdopt returns a plan), Preflight and preflightApply also skip an sshd -T base value equal to the runbook's value for trustedusercakeys or authorizedprincipalsfile. writeDropIn then rewrites the drop-in, and activateDropIn's checkDropInEffective proves that the agent's values win. The run loop therefore repairs a drifted or missing 00-keyroster.conf and installs newer KRLs, while it keeps reporting phase2_adoption_pending. Any other foreign trust setting still refuses"
    - "apply's path defaults. keyroster-agent apply --once without --state-dir and --spool uses /var/lib/keyroster-agent and <state-dir>/spool, as run does, and refuses a relative path. Every apply --once in host-setup.md and in the code's hints (adoptCommand, recoveryCommand, preflight.go's trial Fix, resetdir.go's pending hint) works as written, including the one in the sentence this plan adds for F09"
  artifacts:
    - path: "internal/agent/spool/spool.go"
      provides: "Cap, the read cap of every recognised spool name"
      contains: "func Cap("
    - path: "internal/agent/fetch/fetch.go"
      provides: "the per-answer cap check and the spool heal"
      contains: "state_item_over_cap"
    - path: "internal/agent/apply/preflight.go"
      provides: "phase2Shadowed, the one Phase 2 leftover filter"
      contains: "func phase2Shadowed("
    - path: "cmd/keyroster-agent/apply.go"
      provides: "apply's path defaults through parseApply"
      contains: "func parseApply("
  key_links:
    - from: "internal/agent/fetch/fetch.go"
      to: "internal/agent/spool/spool.go"
      via: "the answer check and the heal use the caps spool.Read enforces"
      pattern: "spool.Cap("
    - from: "internal/agent/apply/preflight.go"
      to: "internal/agent/apply/drift.go"
      via: "one Phase 2 leftover filter for Preflight, preflightApply and Check"
      pattern: "phase2Shadowed"
    - from: "cmd/keyroster-agent/apply.go"
      to: "cmd/keyroster-agent/preflight.go"
      via: "apply defaults its state directory as run does"
      pattern: "defaultStateDir"
  prohibitions:
    - statement: "Neither fix widens what the applier accepts. The fetcher only refuses or removes spool files. The Phase 2 exemption applies only to the runbook's own two lines and values, only on an installed host with an unfinished takeover, and only where activateDropIn's sshd -T check then proves the agent's values in force"
      status: resolved
      verification: test
---

<objective>
This plan closes two remaining ways a revocation can get stuck on a host, and makes the runbook's hand-run command work:
- **F01.** One oversized answer from a compromised server can no longer leave a spool file that blocks every later capture once the server is fixed. The fetcher also never spools what the applier would refuse.
- **F09.** A host whose Phase 2 takeover stopped halfway keeps repairing its drop-in and keeps applying newer KRLs from the run loop.
- **apply's path defaults.** `sudo keyroster-agent apply --once`, as the runbook and the code's hints write it, runs instead of exiting 2.

Purpose: REVOKE-02 (the KRL reaches every enrolled host) and AGENT-04 (the apply repairs drift without locking out). It restores T-03-41's recovery property and extends D-R2 to the run loop.

Output:
- spool.Cap;
- the fetcher's answer caps and its spool heal;
- the shared Phase 2 leftover filter;
- parseApply with run's path defaults;
- named tests with RED evidence;
- host-setup.md;
- the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **D-R2 (PR #71 review F5), existing:** a revocation never waits.
- **Q-split (Daniel, 2026-10-29), with the order of Q1 (Daniel, 2026-10-30):**
  - 03-08d: F07 and F08 (wave 13). Merged as PR #76 (a70c661, 2026-10-30).
  - 03-08e (this plan): F01 and F09 (wave 14, depends on 03-08d, branch `p03/08e-agent-spool-and-takeover`).
  - 03-08j: wave 15, depends on 03-08e.
  - 03-08f: F02 and F03 (wave 16).
  - 03-09 to 03-16 move one wave later per plan. This plan's publish edits make the second move.
- **Q1 (Daniel, 2026-10-30):** split. This plan keeps F01, F09 and apply's path defaults, and 03-08d's far-behind paragraph in host-setup.md stays as it is on main.
- **apply's path defaults (2026-10-30, carried here from PR #76's fix-round check, low):** host-setup.md and the code's hints name `sudo keyroster-agent apply --once`, which exits 2 because apply has no defaults for `--spool` and `--state-dir`. Fix it by giving apply run's defaults, or by writing the full command everywhere. This plan gives apply the defaults (planner's choice, below).
- **Grades (2026-10-29 and 2026-10-30):** F01 is medium; F09 and apply's path defaults are low. F01 overlaps the todo agent-spool-pruning but is not covered by it.
- **Delivery (2026-10-29):**
  - The plan lands in the same PR as its fix, with neutral hardening wording that names findings only by F-number.
  - Pushing the branch and opening the PR before the merge is allowed (Daniel, 2026-10-29).
- **Homelab:** no 03-16 drill provokes these refusals on a real host. The runbook text is labelled as run in CI, and UNVERIFIED on a real host.

**Planner decisions (Claude's discretion), with their reasons:**
- *No write-once policy files.* The fetcher cannot tell honest bytes. A first-writer-wins rule would let one compromised answer pin junk under a version that an honest bundle names later. Replacement under the cap is harmless, and the heal covers spools poisoned before this plan.
- *No applier-side tolerance for oversize files.* spool.Read's open contract stays strict, and the fetcher keeps the spool within it.
- *The F09 value exemption is gated on an unfinished takeover.* It is safe because activateDropIn proves the agent's values win after the rewrite.
- *apply gets run's defaults, rather than every mention getting the full command.* It is one change in one place. It makes the existing hints right (adoptCommand, recoveryCommand and the runbook's commands), and it removes a difference between two commands that read the same state. The defaults are parsed in a pure function (parseApply), so the test never touches /var/lib.

No `checkpoint:decision` precedes Task 1.

## Budget

10 code, test and runbook files; cmd/keyroster-agent/apply_test.go is new. The publish edits add the plan itself, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16. The estimate is about 75k tokens:
- about 65 KB read (function-scoped read_first lists);
- about 28k written;
- about 15k of test and gate output.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names.
- **Branch.** Create `p03/08e-agent-spool-and-takeover` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 3 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Commits and PR text.** Neutral hardening wording that names findings only by F-number. No attribution lines, no IP addresses and no real host names.
- **Code comments.** Cite `F01 (03-08e)` or `F09 (03-08e)`, never a bare F-number that could be read as PR #71's or PR #72's.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md`. The docs commit is `docs(03-08e): complete agent spool-and-takeover plan`.

**The defects this plan fixes, as read on main at a70c661 (after 03-08d and its fix round 1; none of these functions changed in 03-08d):**

**F01.** The fetcher's answer checks, AgentStateResponse.Check and CheckSince, constrain bundle, directory and KRL versions. They constrain neither PolicyVersion, nor item sizes, nor the per-kind count.
- writeState writes `policy-<PolicyVersion>.json` by renaming over any existing file.
- dropAbove never removes policy files.
- So one compromised answer can leave a policy file above spool.MaxBundle, either at the host's floor version or at 2^64-1. spool.Read's pick selects it, and Read then refuses every later capture (`spool_oversize`), KRLs included, until someone deletes the file by hand. This breaks T-03-41's property that a fixed server restores the host's progress.

**F09.** preflightApply returns early only when last-good exists and 00-keyroster.conf equals DropIn (preflight.go, `bytes.Equal(old, DropIn(e.l))`). Otherwise its installed-host branch passes every trust-setting hit to foreignFindings.
- After a takeover whose removal was cut short before 50-keyroster.conf went, the hits include the runbook's two lines there.
- Preflight and Check filter exactly those lines; preflightApply does not.
- The run loop forces AllowAdoption to false (apply/run.go, `rc.AllowAdoption = false`), so it only logs phase2_adoption_pending. A drifted drop-in is never repaired, and newer KRLs never install, until someone runs `apply --once`.
- With the drop-in missing, the sshd -T value check also refuses, because the runbook's values are then in force.

**apply's path defaults.**
- runApply registers `--spool` and `--state-dir` with empty defaults and refuses either one when it is not absolute (cmd/keyroster-agent/apply.go:63-80). So `sudo keyroster-agent apply --once`, as host-setup.md (lines 889, 950, 1569) and the code's hints write it, exits 2 with `apply: --spool must be an absolute path`.
- run defaults `--state-dir` to defaultStateDir (cmd/keyroster-agent/preflight.go) and the spool to Layout.Spool(), which is `<state-dir>/spool` (cmd/keyroster-agent/run.go:52-71).

## Reconciliation with main at a70c661 (revision of 2026-10-30)

The plan passed plan check 2 on 2026-10-29, against main before 03-08d. Every task, file, function, line, test name and must_have was checked again on a70c661:

1. **Task 1's precondition** named 03-08d's SUMMARY and `func KRLAlone(`, and both exist on main. It now also names `func NewPrincipalsRenderer(` (internal/directory/render.go, from 03-08d's fix round 1).
2. **"As read on main at 18a30c9" became a70c661.** The F01 and F09 defect sites are unchanged by 03-08d; their claims were re-read above.
3. **Task 2's read_first named `func adoptHost(`.** It is a closure, `adoptHost := func(t *testing.T) *testHost`, inside TestAdopt (adopt_test.go:99). `crash_during_removal_resumes`, `installPhase2` and fakeRunner's `after` map (harness_test.go) exist as named.
4. **"The fetcher log's refusal table"** is the **Refusals.** table under "Enrolling a host" in host-setup.md. It has four columns (Code, Where, What it means, Fix), so the new row's Where is `fetcher log`.
5. **No code file overlaps 03-08d.** 03-08d's fix round edited adopt.go, which this plan only reads.
6. **The publish values match main.** The ROADMAP's Phase 3 Plans line reads 14/22 plans in 21 waves. STATE.md reads total_plans 57 and `Plan: 15 of 22`. 03-09 has `wave: 14` and `depends_on: ["03-08d"]`, and its Task 1 precondition holds the 03-08c and 03-08d SUMMARY clauses. 03-10 to 03-16 have waves 15 to 21. The guard in Task 3 stands.
7. **Host-setup.md.** The paragraph 03-08d's fix round added after "Revocations keep applying" (about lines 944-960) stays as it is (owner decision Q1). The new F09 sentence names `sudo keyroster-agent apply --once`, which works once Task 3 has given apply its defaults.
8. **03-08d-SUMMARY's sentence "Failed runs no longer leave generations behind"** is not carried. This plan never touches 03-08d-SUMMARY.md.

</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a compromised state answer whose bundle item carries an oversize policy at the host's accepted policy version → checkCaps finds it above spool.Cap(policy-1.json) → the fetcher refuses the answer with state_item_over_cap and writes nothing → the honest policy-1.json keeps its bytes → the next honest answer is written → spool.Read with the applier's floor succeeds"</name>
  <reversibility rating="reversible">These are fetcher-side checks and one exported spool function. No on-disk format, wire message or signed document changes.</reversibility>
  <precondition>`git fetch origin` succeeds. `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md` exits 0. `V=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$V" | grep -c 'func KRLAlone('` prints 1, and `R=$(git show origin/main:internal/directory/render.go) && printf '%s\n' "$R" | grep -c 'func NewPrincipalsRenderer('` prints 1, which shows that 03-08d and its fix round 1 are merged. `P=$(git show origin/main:internal/agent/spool/spool.go) && printf '%s\n' "$P" | grep -c 'func Cap('` prints 0, which shows that this plan is not on main yet.</precondition>
  <files>internal/agent/spool/spool.go, internal/agent/spool/spool_test.go, internal/agent/fetch/fetch.go, internal/agent/fetch/fetch_test.go</files>
  <read_first>
    Read functions, not whole files. Find each with `grep -n` and read only that range.
    - internal/agent/spool/spool.go: the `docRE` and `krlRE` vars, `func Read(` and the signature of `func ReadFileAt(` (about 6 KB).
    - internal/agent/spool/spool_test.go: the head of `func TestSpool(`, up to its first two subtests (about 3 KB).
    - internal/agent/fetch/fetch.go: `func (f *Fetcher) pollState(`, `func writeState(` and the vars `spoolDocRE`, `spoolKRLRE` and `spoolFileRE` (about 6 KB).
    - internal/agent/fetch/fetch_test.go: `newTestServer` and the subtest `poisoned_answer_then_honest_delivers_newer_krl` (about 5 KB).
    - internal/serverclient/agent.go: `MaxAgentStatePerKind`, and the types `AgentStateResponse`, `AgentBundle`, `AgentDirectory` and `AgentKRL` (about 3 KB).
    - internal/server/agent.go: the item loops of `bundleItems` and `directoryItems` (about 2 KB). internal/tlog/leaf.go: the size-limit const block (about 1 KB).
  </read_first>
  <action>
Create branch `p03/08e-agent-spool-and-takeover` from origin/main. Place this plan file untracked in the phase directory.

**RED first.** Write these tests. Before running them, add only the new symbols, with no behaviour: `ErrAnswerOverCap`, and a `spool.Cap` stub that reports (0, false). Every RED then fails on behaviour, not on the build. Run them and record the output in the SUMMARY.
- `TestFetch/oversize_policy_answer_refused_nothing_written`, the tracer:
  1. Seed the spool with bundle-1, an honest policy-1 and outbox/accepted.json {bundle: 1}.
  2. Have the test server's first answer carry bundle 2, whose policy, at version 1, is spool.MaxBundle+1 bytes.
  3. Expect the poll to return state_item_over_cap, with every spool file keeping its bytes.
  4. Expect a second, honest more:false answer to succeed, and spool.Read(Floor{Bundle: 1, Policy: 1}) to succeed.

  RED today: the poll writes the policy, and Read returns spool_oversize.
- `TestFetch/high_policy_version_oversize_refused`: the same at policy version 18446744073709551615. Nothing is written.
- `TestFetch/item_at_cap_written`: a policy of exactly spool.MaxBundle bytes is written. This is an adjacency guard, expected GREEN at once.
- `TestSpool/cap_is_what_read_enforces`: for each recognised kind (bundle, policy and directory documents with their sigs; the KRL, manifest and manifest sig), a file of exactly Cap(name) bytes is read, and one of Cap(name)+1 bytes refuses the capture with spool_oversize. Cap of an unrecognised name reports false.
- `TestFetch/honest_answers_fit_the_caps`:
  - tlog.MaxDocument equals spool.MaxBundle (both 1 MiB on main). It bounds every bundle_install document and signature file, and so what the server serves.
  - tlog.MaxManifest and tlog.MaxManifestSig equal krl.MaxManifest and krl.MaxManifestSig (4 KiB and 16 KiB on main).
  - spool.Cap of `directory-1.json` and `directory-1.json.sigs` returns wire.MaxDirectory and wire.MaxDirectorySigs.

  This test and the Cap test are RED against the stub.

**spool.go.**
- Add `func Cap(name string) (int64, bool)`, the cap Read applies to a recognised name:
  - MaxBundle for bundle and policy documents and their sigs;
  - wire.MaxDirectory and wire.MaxDirectorySigs for directory documents and their sigs;
  - krl.MaxKRL, krl.MaxManifest and krl.MaxManifestSig for the KRL files.
- Read takes its caps from Cap, so the two cannot drift.

**fetch.go.**
- Add `ErrAnswerOverCap = errors.New("state_item_over_cap")` and `checkCaps(r *serverclient.AgentStateResponse) error`.
- In this task, checkCaps covers every file of every bundle item: bundle, bundle sigs, policy and policy sigs. It builds each name exactly as writeState does and refuses when the size is above Cap(name). Task 2 extends it to directories, the KRL and the per-kind count.
- The refusal wraps ErrAnswerOverCap and names the kind, version and size.
- writeState calls checkCaps before its first write.
- Its doc comment explains why an honest answer never trips the check, citing `F01 (03-08e)`:
  - the server's bundleItems and directoryItems stop at MaxAgentStatePerKind;
  - the signer bounds bundle_install documents at tlog.MaxDocument;
  - the signer bounds directories by the wire caps and KRLs by krl.MaxKRL.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestSpool|TestFetch" ./internal/agent/spool/ ./internal/agent/fetch/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestFetch/oversize_policy_answer_refused_nothing_written", "--- PASS: TestFetch/high_policy_version_oversize_refused", "--- PASS: TestFetch/item_at_cap_written", "--- PASS: TestFetch/honest_answers_fit_the_caps", "--- PASS: TestSpool/cap_is_what_read_enforces"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'func Cap(' internal/agent/spool/spool.go` prints 1.
    - `grep -v '^[[:space:]]*//' internal/agent/fetch/fetch.go | grep -c 'spool.Cap('` prints at least 1.
    - The SUMMARY records the RED output of the tracer on origin/main's code.
  </acceptance_criteria>
  <done>A compromised answer with an oversize policy is refused before anything is written, and the honest spool stays readable.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The remaining caps and the per-kind count, the spool heal, and F09's shared Phase 2 filter</name>
  <files>internal/agent/fetch/fetch.go, internal/agent/fetch/fetch_test.go, internal/agent/apply/preflight.go, internal/agent/apply/drift.go, internal/agent/apply/adopt_test.go</files>
  <behavior>
    - **F01 (`TestFetch`)**
      - `more_than_per_kind_refused`: an answer with 17 contiguous bundles is refused, and nothing is written. An answer with 16 is accepted.
      - `oversize_directory_and_krl_refused`: a directory one byte above wire.MaxDirectory is refused, and so is a KRL one byte above krl.MaxKRL.
      - `poisoned_spool_file_removed_at_next_poll`: the spool starts with a policy-1.json of spool.MaxBundle+1 bytes, left from before this plan. After one poll it is gone, its name is logged at warning level, and spool.Read(Floor{Bundle: 1, Policy: 1}) succeeds.
      - `heal_leaves_symlinks_and_unknown_names`: a symlink named policy-2.json and an unrecognised name are left in place.
      - `heal_error_logged_and_poll_continues`: healSpool cannot remove an oversize file because the test made the spool directory read-only (chmod 0555). The poll logs a warning naming the error and still sends its state request, and spool.Read still refuses the oversize file. As root the mode does not block unlink, so in that case the test skips with t.Skip, and the SUMMARY names the non-root run (WSL or CI) where it passed.
    - **F09 (`TestAdopt`)**
      - *Fixture.* Every case starts from a takeover by `apply --once` whose removal crashes at the **first** `phase2-remove` (a Fault that crashes when n == 1). That stops it before 50-keyroster.conf is removed. Unlike `crash_during_removal_resumes`, which crashes at the third removal after that file is gone, this fixture asserts its own starting state:
        - last-good is the agent's;
        - phase2-adopt.json, 50-keyroster.conf, keyroster_user_ca.pub and the Phase 2 principals directory all exist;
        - h.run.after holds the runbook's two values (installPhase2 sets trustedusercakeys to phase2CAValue and authorizedprincipalsfile to phase2PrincipalsVal). That is what the fake sshd -T reports, after the agent's drop-in, once 00-keyroster.conf lacks them.

        Then the Fault is cleared, AllowAdoption is set false as in the run loop, a newer KRL is published, and Apply runs.
      - `unfinished_removal_edited_dropin_run_loop_applies_krl`: 00-keyroster.conf was edited (one of its trust lines removed). The expected result:
        - no error, and 00-keyroster.conf equals DropIn again;
        - current revokes the new serial;
        - a phase2_adoption_pending warning is logged;
        - 50-keyroster.conf still exists.

        RED today: a PreflightError with foreign_trust_setting.
      - `unfinished_removal_missing_dropin_run_loop_applies_krl`: the same with 00-keyroster.conf deleted. RED today.
      - `unfinished_removal_foreign_line_still_refused`: a third trust line in 50-keyroster.conf that is not one of the runbook's (for example `TrustedUserCAKeys /etc/ssh/other.pub`). foreign_trust_setting still refuses.
      - `missing_dropin_without_adoption_plan_still_refused`: the missing-drop-in fixture with phase2-adopt.json removed. The sshd -T value refusal stands.
      - `preflight_command_agrees`: keyroster-agent preflight's Preflight, on the edited and missing variants, reports no refusal from the runbook's lines or values, matching what the apply now does.
  </behavior>
  <read_first>
    Read functions, not whole files. Find each with `grep -n` and read only that range. Task 1's own edits are already in context.
    - internal/agent/fetch/fetch.go: `func dropAbove(` (about 1.5 KB).
    - internal/agent/apply/preflight.go: `type settingHit`, `func foreignFindings(`, the installed branch of `func Preflight(` (found with `grep -n 'case installed:'`), and `func (e *engine) preflightApply(` (about 9 KB).
    - internal/agent/apply/drift.go: the hits loop in `func Check(` (`grep -n 'Phase2DropIn'`; about 1 KB).
    - internal/agent/apply/adopt.go: the const block with phase2CALine, phase2PrincipalsLine, phase2CAValue and phase2PrincipalsVal; `adoptFile`; `func (e *engine) readAdopt(`; and the `phase2-remove` loop in finishAdoption (about 3 KB).
    - internal/agent/apply/apply.go: the takeover branch at the end of `func (e *engine) apply(` (`grep -n 'CodePhase2Pending'`; about 1 KB).
    - internal/agent/apply/adopt_test.go: `func (h *testHost) installPhase2(`, the closure `adoptHost := func(` inside TestAdopt, and the subtest `crash_during_removal_resumes` (about 5 KB).
    - internal/agent/apply/harness_test.go: `func (r *fakeRunner) dumpFor(` and fakeRunner's `before, after` maps (about 1.5 KB).
    - internal/agent/apply/run.go: where AllowAdoption is forced off (`grep -n 'rc.AllowAdoption = false'`; about 0.5 KB).
  </read_first>
  <action>
**Tests first.** Write the tests in `<behavior>` first and run them on Task 1's head. Record in the SUMMARY which were RED and which were GREEN at once; `heal_leaves_symlinks_and_unknown_names` may be GREEN. Then implement.

**F01, the rest (fetch.go).**
- **checkCaps.** Extend it to every file writeState would write for directories and the KRL. Also refuse more than serverclient.MaxAgentStatePerKind bundles or directories.
- **healSpool.** Add `healSpool(dir string) ([]string, error)`:
  - It walks the spool through spool.OpenDir and ListDir.
  - It unlinks each recognised name (Cap reports true) whose fstatat with AT_SYMLINK_NOFOLLOW shows a regular file above its cap.
  - It leaves non-regular files and unrecognised names alone.
  - pollState calls it before it computes the cursor, and logs the removed names at warning level.
  - When healSpool fails (for example, the spool cannot be listed or a file cannot be unlinked), pollState logs a warning naming the error and goes on with the poll. The heal is best effort: the oversize file stays, spool.Read still refuses the capture, and the next poll tries again. The behavior case `heal_error_logged_and_poll_continues` pins this.
- **Comments.** dropAbove's comment about policies stays true. Add a sentence: a policy is still replaced by name, which is harmless because the applier finds the accepted policy by SHA-256 first.

**F09 (preflight.go, drift.go).**
- **The helper.** Add `phase2Shadowed(l Layout, hits []settingHit, adoptPending bool) (rest []settingHit, shadowed map[string]string, found bool)`:
  - It drops each hit in l.Phase2DropIn() whose text is phase2CALine or phase2PrincipalsLine. This is exactly the filter Preflight and Check use today.
  - found is true when it dropped any.
  - When found and adoptPending are both true, shadowed maps `trustedusercakeys` to phase2CAValue and `authorizedprincipalsfile` to phase2PrincipalsVal. Otherwise shadowed is nil.
- **foreignFindings** gains a shadowed parameter. A base sshd -T value equal to shadowed[keyword] is not a finding.
- **Callers.**
  - Preflight's installed branch uses the helper, with adoptPending true when readAdopt returns a plan, and keeps its Note.
  - preflightApply's installed branch (lg is the agent's) does the same. Its first-install branch and its own-drop-in-without-generation branch pass nil.
  - Check uses only rest. Its setting drift for the runbook's values stays reported, because sshd really enforces those values until the next apply rewrites the drop-in.
- **Doc comment.** The helper's doc comment says why the exemption is safe: writeDropIn reports the change, and activateDropIn's checkDropInEffective refuses unless the agent's values win. It cites `F09 (03-08e)`.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestAdopt|TestPreflight|TestDrift|TestSpool|TestFetch" ./internal/agent/apply/ ./internal/agent/spool/ ./internal/agent/fetch/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestFetch/more_than_per_kind_refused", "--- PASS: TestFetch/oversize_directory_and_krl_refused", "--- PASS: TestFetch/poisoned_spool_file_removed_at_next_poll", "--- PASS: TestFetch/heal_leaves_symlinks_and_unknown_names", "--- PASS: TestFetch/heal_error_logged_and_poll_continues", "--- PASS: TestAdopt/unfinished_removal_edited_dropin_run_loop_applies_krl", "--- PASS: TestAdopt/unfinished_removal_missing_dropin_run_loop_applies_krl", "--- PASS: TestAdopt/unfinished_removal_foreign_line_still_refused", "--- PASS: TestAdopt/missing_dropin_without_adoption_plan_still_refused", "--- PASS: TestAdopt/preflight_command_agrees", "--- PASS: TestAdopt/crash_during_removal_resumes"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'func phase2Shadowed(' internal/agent/apply/preflight.go` prints 1, and `grep -c 'phase2Shadowed(' internal/agent/apply/drift.go` prints at least 1.
    - The SUMMARY lists these mutants. Each is applied, run against its named test, and restored byte for byte:
      - preflightApply without the helper: killed by `unfinished_removal_edited_dropin_run_loop_applies_krl`;
      - shadowed not gated on adoptPending: killed by `missing_dropin_without_adoption_plan_still_refused`;
      - checkCaps removed: killed by `oversize_policy_answer_refused_nothing_written`;
      - the per-kind count removed: killed by `more_than_per_kind_refused`;
      - healSpool removed: killed by `poisoned_spool_file_removed_at_next_poll`;
      - Cap off by one: killed by `item_at_cap_written` or `cap_is_what_read_enforces`;
      - the fixture's crash moved back to the third removal: the F09 REDs disappear, recorded as the reason for the fixture.
  </acceptance_criteria>
  <done>The fetcher never spools what the applier refuses and heals old spools. The run loop repairs a drifted drop-in and installs newer KRLs during an unfinished takeover, while every other foreign setting still refuses.</done>
</task>

<task type="auto">
  <name>Task 3: apply's path defaults, host-setup.md, the publish edits, the gates, the PR and the SUMMARY</name>
  <files>cmd/keyroster-agent/apply.go, cmd/keyroster-agent/apply_test.go, docs/runbooks/host-setup.md, .planning/phases/03-linux-agent-and-revocation/03-08e-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - cmd/keyroster-agent/apply.go (whole, about 4 KB); cmd/keyroster-agent/run.go, runUsage and the flag block of `func runRun(` (about 2 KB); cmd/keyroster-agent/preflight.go, `defaultStateDir` and `func addServiceFlags(` (about 1.5 KB).
    - cmd/keyroster-agent/identity.go:39-50, the flag block of `func runIdentity(`. It is the pattern parseApply follows: `--state-dir` defaults to defaultStateDir, `--spool` "" means `<state-dir>/spool`, and each must be absolute when given (about 1 KB).
    - docs/runbooks/host-setup.md: the paragraph "Revocations keep applying", the paragraph starting "**On a Phase 2 host**", and the **Refusals.** table under "Enrolling a host". Find each with `grep -n` (about 6 KB).
    - .planning/ROADMAP.md: Phase 3's Plans line and wave blocks. .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter and its Task 1 precondition. 03-10 to 03-16: their `wave:` lines.
  </read_first>
  <action>
**apply's path defaults (cmd/keyroster-agent/apply.go), test first.**
- **parseApply.** Factor runApply's flag parsing into `parseApply(args []string, stderr io.Writer) (applyArgs, error)`. applyArgs holds once, the spool, the state directory, dry run, recover-to-last-good and the service flags. parseApply only parses and checks paths: it detects no service and touches no file. runApply calls it and then svc.resolve, as today.
  - Model it on runIdentity's flag block (cmd/keyroster-agent/identity.go:39-50), which run.go shares. Three commands then follow one rule for these two paths; a shared helper is optional.
- **RED.** Write `TestApplyFlags` in the new cmd/keyroster-agent/apply_test.go.
  - Its first line is `//go:build linux`, as on every file in cmd/keyroster-agent (apply.go, install_test.go, units_test.go). parseApply exists only on Linux, and CI's golangci-lint runs with GOOS=windows, where an untagged test would not typecheck.
  - Run it against a parseApply that still has today's rules, and record the RED in the SUMMARY. The cases:
  - no path flag: the state directory is /var/lib/keyroster-agent (defaultStateDir) and the spool /var/lib/keyroster-agent/spool;
  - `--state-dir /x`: the spool is /x/spool;
  - `--spool /y`: the spool is /y;
  - a relative `--state-dir` or `--spool`: errUsage;
  - no `--once`: errUsage.

  RED today: the first two cases return errUsage.
- **GREEN.** `--state-dir` defaults to defaultStateDir. `--spool` defaults to "", which means apply.Layout{StateDir: <state-dir>}.Spool(), as run computes it. Each must be absolute when given. applyUsage changes in two places:
  - its first line becomes `usage: keyroster-agent apply --once [--spool DIR] [--state-dir DIR] [--root DIR]`;
  - it gains run's sentence `--spool defaults to <state-dir>/spool, --state-dir to /var/lib/keyroster-agent.`

  The two flags' help strings carry the defaults, as run's and identity's do: `--spool`'s reads "the spool directory (default <state-dir>/spool)", and `--state-dir` shows defaultStateDir as its flag default. `-h` then shows both.
- **Every mention.** Run `grep -rn 'apply --once' docs/ internal/ cmd/ test/`. Record each hit in the SUMMARY as one of three kinds: it works with the defaults (no path flag), it passes both flags, or it is prose. The hits on main are about these:
  - docs/runbooks/host-setup.md, about lines 598, 611, 856, 889, 950, 1225, 1569, 1581 and 1594 (598 and 611 are table rows);
  - internal/agent/apply/adopt.go:58 (adoptCommand), internal/agent/apply/apply.go:292 (the stuck log line), internal/agent/apply/preflight.go:469 (the trial Fix), internal/agent/apply/resetdir.go:90 (the pending hint), internal/agent/apply/units.go (comments), internal/agent/apply/run.go:34 (a comment) and internal/agent/heartbeat/heartbeat.go:68 (a comment);
  - cmd/keyroster/hoststatus.go:32 (recoveryCommand);
  - cmd/keyroster-agent/main.go:5, run.go:37 and apply.go:20, 25 and 57: prose, usage and comments;
  - test comments and invocations in internal/agent/apply/adopt_test.go, test/distro and test/e2e, which pass both flags or are prose.

  None of these needs an edit once apply has the defaults. A hit outside this list is not a deviation as long as it falls into one of the three kinds. Fix any hit that does need an edit here, and record it.

**host-setup.md (D-20).** Label every changed or new text "Run in CI" with the test names and 03-08e, and "UNVERIFIED on a real host". The paragraph 03-08d's fix round added after "Revocations keep applying" stays as it is (owner decision Q1).
- **"Revocations keep applying".** Add a sentence: the fetcher refuses a state answer with an item above what the applier reads (`state_item_over_cap`), and removes such files from the spool at its next poll.
- **"On a Phase 2 host".** Add a sentence: if a takeover's removal was cut short, the units keep applying. They rewrite a drifted or missing 00-keyroster.conf, install newer KRLs, and report phase2_adoption_pending until `sudo keyroster-agent apply --once` finishes the removal.
- **The Refusals. table under "Enrolling a host".** Add the row `state_item_over_cap` | `fetcher log` | A state answer held an item above what the applier reads, or more items of a kind than the server sends; nothing was written | Check the server; the next poll asks again.

**Publish edits.** Make them in this PR, on top of origin/main, which holds 03-08d. Every number is origin/main's value + 1; the values in brackets are what main at a70c661 holds.
1. Commit this plan, unchanged, as `.planning/phases/03-linux-agent-and-revocation/03-08e-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each grow by one (14/22 plans in 21 waves → 14/23 in 22 waves).
   - After 03-08d's Wave 13 block, insert `**Wave 14** *(blocked on Wave 13 completion)*` with the unchecked entry `03-08e-PLAN.md — The spool and a cut-short takeover never hold back a KRL (F01, F09): the fetcher refuses answers above the applier's read caps and heals its spool; the run loop repairs the drop-in while a Phase 2 removal is unfinished; apply --once has run's path defaults`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 14–21 → 15–22), and update each block's "blocked on Wave N completion" clause with them.
   - Add nothing about any other plan.
3. STATE.md: `total_plans` +1 (57 → 58), and the Plan line's `of M` +1 (Plan: 15 of 22 → Plan: 15 of 23).
4. 03-09-PLAN.md:
   - `wave:` +1 (14 → 15);
   - `depends_on` becomes `["03-08e"]`;
   - Task 1's `<precondition>` gains the clause `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md` exits 0. It goes next to the 03-08c and 03-08d clauses, which stay.
5. The `wave:` lines of 03-10 to 03-16 each +1 (15–21 → 16–22).
6. **Guard.** If origin/main's 03-09 does not hold `wave: 14` and `depends_on: ["03-08d"]`, another plan was slotted in first. Apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**Push and the PR.**
1. Commit by path only.
2. Push the branch.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(agent): keep the spool and a cut-short takeover from holding back KRLs (F01, F09)"` with a neutral body that also names apply's path defaults. Do not enable auto-merge.
4. Wait for the required checks.

**The SUMMARY.** Include:
- the PR number and the check run IDs;
- the RED evidence, with where each was taken;
- the mutants;
- the GREEN-at-once cases with their reasons;
- the list of `apply --once` mentions;
- capslock;
- `requirements-completed` empty: REVOKE-02 is complete since earlier plans, AGENT-04 stays pending, and this plan hardens both.

Then run the tracking updates once, commit `docs(03-08e): complete agent spool-and-takeover plan`, push, and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run TestApplyFlags ./cmd/keyroster-agent/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or "--- PASS: TestApplyFlags" missing</fails_when>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'state_item_over_cap' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'unfinished_removal_edited_dropin_run_loop_applies_krl' && grep -qx 'depends_on: \["03-08e"\]' .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md && M=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md) && W=$(printf '%s\n' "$M" | sed -n 's/^wave: //p') && test -n "$W" && grep -qx "wave: $((W+1))" .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md && grep -c '03-08e-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit (a runbook sentence, the dependency, the +1 wave shift or the ROADMAP row is missing)</fails_when>
    <automated>git fetch origin p03/08e-agent-spool-and-takeover && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08e-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08e-agent-spool-and-takeover --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new or rewritten runbook sentence names at least one CI test and says UNVERIFIED on a real host.
    - `grep -c 'defaultStateDir' cmd/keyroster-agent/apply.go` prints at least 1.
    - `head -1 cmd/keyroster-agent/apply_test.go` prints `//go:build linux`.
    - `grep -c '(default <state-dir>/spool)' cmd/keyroster-agent/apply.go` prints at least 1.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0, and `B=$(scripts/gh-as-bot.sh pr view p03/08e-agent-spool-and-takeover --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08e-SUMMARY.md is on its head. The PR title and every commit message name findings only by F-number.
  </acceptance_criteria>
  <done>`sudo keyroster-agent apply --once` runs as the docs write it. The runbook says what the fetcher refuses and what an unfinished takeover still applies. The PR waits green with the plan and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — owner approves PR p03/08e-agent-spool-and-takeover, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. Open `gh pr view p03/08e-agent-spool-and-takeover --web`. Review spool.Cap, checkCaps, healSpool, phase2Shadowed and parseApply, and read 03-08e-SUMMARY.md. Check especially that the Phase 2 exemption is limited to the runbook's own lines and values during an unfinished takeover.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved". After a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08e-agent-spool-and-takeover` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08e-agent-spool-and-takeover</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which the next plan's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08e-agent-spool-and-takeover --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The spool caps, the heal, the takeover filter and apply's defaults are on main, and 03-08j may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08d** (merged, a70c661) is this plan's base. Its "Revocations keep applying" paragraph in host-setup.md gains this plan's fetcher sentence. No code file overlaps 03-08d.
- **03-08j and then 03-08f** follow, and keep this plan's tests green.
- **03-08c.** The only shared file is docs/runbooks/host-setup.md, which 03-08b and 03-08c edited in other sections. On a rebase conflict, keep their text and re-apply this plan's sentences and row. This plan does not touch internal/serverclient/agent.go; it only reads MaxAgentStatePerKind.
- **The todo 2026-10-28-agent-spool-pruning keeps** two jobs: removing spool versions the applier accepted, and removing policy files no bundle names. The per-answer count now bounds those files per answer only. This plan adds caps, the per-kind count and the heal; it prunes nothing.
- **Later plans.** 03-10 edits preflight.go and must keep TestAdopt's `unfinished_removal_*` cases and `missing_dropin_without_adoption_plan_still_refused` green. Any later plan that edits runApply keeps TestApplyFlags green.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: the fetcher is honest.** The caps and the heal fix a compromised server's answer. A compromised fetcher can still plant or withhold files (T-03-225, accepted).

**Edges:**
- adjacency: `item_at_cap_written`, `cap_is_what_read_enforces`, 16 versus 17 bundles;
- a version at the floor and at 2^64-1;
- old state: `poisoned_spool_file_removed_at_next_poll`;
- what the heal must not touch: `heal_leaves_symlinks_and_unknown_names`;
- the takeover's crash point, which is the first removal;
- the negative cases: a foreign line, and a missing adoption plan;
- apply's paths: no flag, one flag, both, and a relative path (`TestApplyFlags`).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Revocation takes effect across the fleet without risking lockout | Tasks 1, 2 |
| REQ | REVOKE-02 (the KRL reaches every enrolled host) | Tasks 1, 2 |
| REQ | AGENT-04 (an atomic apply that repairs drift) | Task 2 (F09) |
| Finding | F01: one answer leaves a spool file that blocks every capture; spool writes need caps | Tasks 1, 2 |
| Finding | F09: the run loop refuses drift repair during an unfinished takeover | Task 2 |
| Review | PR #76 fix-round check: `sudo keyroster-agent apply --once` exits 2 without path flags | Task 3 |
| CONTEXT | D-20: runbooks in the same PR, labelled run or UNVERIFIED | Task 3 |
| Owner decision | D-R2; Q-split, Q1, grades, delivery and push before merge | Owner decisions block |
| Finding fix, optional parts | write-once policy files; tolerance for oversize files on the applier side; pruning | Deferred, with reasons, in the ledger |
| Review, optional | 03-08d-SUMMARY's "Failed runs no longer leave generations behind" | Not carried: this plan does not touch 03-08d-SUMMARY.md |

## Artifacts this phase produces (this plan)

- spool: `Cap`.
- fetch: `ErrAnswerOverCap` (`state_item_over_cap`), `checkCaps`, `healSpool`.
- apply: `phase2Shadowed`, and foreignFindings' shadowed values.
- keyroster-agent apply: `parseApply`, with run's path defaults.
- Tests:
  - TestSpool/cap_is_what_read_enforces;
  - eight TestFetch cases;
  - five TestAdopt cases, built on a fixture that crashes at the first removal;
  - TestApplyFlags.
- Docs: host-setup.md gains the fetcher sentence, the unfinished-takeover sentence and the `state_item_over_cap` row.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| keyroster-server → fetcher | The server's state answer is lower-trust input. A compromised server can withhold; this plan stops one answer from outliving the compromise |
| sshd configuration → applier | Files the agent does not own must never widen trust; the runbook's own leftovers are shadowed only where sshd -T proves it |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-298 | Denial of service | the run loop refusing drift repair and newer KRLs while a Phase 2 takeover's removal is unfinished (F09) | low | mitigate | One filter for Preflight, preflightApply and Check. The sshd -T value exemption applies only while phase2-adopt.json exists, and is safe only because activateDropIn's checkDropInEffective proves the agent's values win. Tests: `unfinished_removal_edited_dropin_run_loop_applies_krl`, `unfinished_removal_missing_dropin_run_loop_applies_krl`, `unfinished_removal_foreign_line_still_refused`, `missing_dropin_without_adoption_plan_still_refused`. **Residual:** the run loop's sandbox still cannot finish the removal; the operator runs `apply --once`, which now works without path flags. **Pre-merge review fix round 1 (D-2):** the line exemption also applies only while phase2-adopt.json exists, and only to the two lines at the top level of 50-keyroster.conf, outside any Match block. Tests: `runbook_line_in_match_block_refused`, `runbook_file_included_in_match_block_refused`, `runbook_lines_without_adoption_plan_refused` |
| T-03-299 | Denial of service / Tampering | one compromised-server answer leaving a spool file above the applier's read caps, which blocks every capture after the server is fixed (F01; breaks T-03-41's recovery property) | medium | mitigate | checkCaps, through spool.Cap and the per-kind count, refuses the answer before any write. healSpool removes oversize recognised files at every poll. Tests: `oversize_policy_answer_refused_nothing_written`, `high_policy_version_oversize_refused`, `more_than_per_kind_refused`, `poisoned_spool_file_removed_at_next_poll`. **Residual:** policy files that no bundle names are never pruned (todo agent-spool-pruning); a compromised fetcher is T-03-225. **Pre-merge review fix round 1 (D-1):** pruneSpool removes at every poll what the applier does not read, policies no kept bundle names included, so the spool stays within what it keeps plus one poll's answers, and junk cannot hide the honest policy from a floor-0 capture. Tests: `TestSpoolPrune` |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; capslock baseline unchanged (a new pair is a recorded deviation) |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh), the full gate passes, the PR's required checks are green, and the merge gate passes.
</verification>

<success_criteria>
- One compromised answer never blocks a host's later captures once the server is honest again, and a spool poisoned before this plan heals at the next poll.
- An unfinished Phase 2 takeover never holds back drift repair or a newer KRL, and every other foreign trust setting still refuses.
- `sudo keyroster-agent apply --once` runs as the runbook and the code's hints write it.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md` in Task 3, before the merge gate. `requirements-completed` is empty: REVOKE-02 is complete since earlier plans, AGENT-04 stays pending, and this plan hardens both. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (findings F01 and F09, and the owner decisions of 2026-10-29)

### Round 1 — plan check 1 of the former 03-08d (2026-10-29, PASS WITH FIXES), items that moved here

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| F01: the fetcher spools items above the applier's read caps and more items per kind than documented; one oversize policy blocks every capture after the server is fixed | MEDIUM | must_haves truths 2-3; Tasks 1, 2; T-03-299 |
| F09: preflightApply lacks the Phase 2 line filter that Preflight and Check have; the missing-drop-in variant also trips the sshd -T value check | LOW | must_haves truth 4; Task 2; T-03-298 |
| Check 1 item 1 (BLOCKER): the F09 fixture crashed at the third removal, after 50-keyroster.conf was gone | BLOCKER | Task 2's fixture crashes at the first `phase2-remove`, asserts its starting state, keeps h.run.after at the runbook's values; a mutant records why |
| Check 1 item 3 (MAJOR): unrealistic budget | MAJOR | Split by owner decision Q-split; read_first scoped to functions; about 65 KB read |
| Check 1 item 5: every subtest in fails_when | MINOR | Every task lists every named subtest |
| Check 1 item 11: neutrality | MINOR | Attribution grep over commits and the PR body includes "Generated with"; comments cite `F01 (03-08e)` and `F09 (03-08e)` |
| Planner: each task's tests must be RED at that task's start | MAJOR | Task 1 implements only the bundle-item caps its tests need; the directory, KRL and count caps, the heal and F09 come after their tests in Task 2; TestApplyFlags runs RED against today's rules first |

### Round 2 — revision after 03-08d merged (PR #76, a70c661; owner decision Q1, 2026-10-30)

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| PR #76 fix-round check: `sudo keyroster-agent apply --once` exits 2 because apply has no path defaults | LOW | must_haves truth 5; Task 3 (parseApply, TestApplyFlags, the list of every mention) |
| Reconciliation with a70c661 | n/a | Reconciliation section, items 1-8 |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| F01: make policy files write-once, or protect the accepted policy version | The fetcher cannot tell honest bytes, so first-writer-wins lets one compromised answer pin junk under a version an honest bundle names later. Protecting the accepted version needs a new accepted.json field. A replaced policy under the cap blocks nothing |
| F01: prune policy files that no remaining bundle names | Todo 2026-10-28-agent-spool-pruning; the per-answer count bounds what one answer adds |
| F01: tolerance for oversize policy files on the applier side | spool.Read's open contract stays strict, and the fetcher's caps and heal keep the spool within it |
| 03-08d-SUMMARY's "Failed runs no longer leave generations behind" | Optional, and only if this plan touched that sentence; it does not |

