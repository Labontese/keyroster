---
phase: 03-linux-agent-and-revocation
plan: 08d
type: execute
wave: 13
depends_on: ["03-08c"]
files_modified:
  - internal/agent/state/verify.go
  - internal/agent/apply/apply.go
  - internal/agent/apply/swap.go
  - internal/agent/apply/render.go
  - internal/agent/apply/resetdir.go
  - internal/agent/apply/rechain_test.go
  - docs/runbooks/host-setup.md
  - docs/runbooks/signer-install.md
  - .planning/phases/03-linux-agent-and-revocation/03-08d-PLAN.md
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
requirements: [REVOKE-02, REVOKE-03]

estimate:
  tokens: 75000
  raw_tokens: 75000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decision D-R2 (PR #71 review F5) holds at every stage of an apply, not only inside state.Verify: revocations only narrow what sshd accepts, so a verified KRL never waits for a bundle or directory the agent cannot apply. Owner decision Q-split (Daniel, 2026-10-29): this plan holds F07 and F08 and runs first of three, after 03-08c"
    - "F07. A capture that state.Verify accepted with a changed bundle or directory (v.Refused nil, BundleChanged or DirectoryChanged) and that the applier then refuses for its content, before current moved, installs its KRL alone. Content refusals are:
      - a render error;
      - ErrGenerationTooLarge for the target generation, or for the intermediate that Transition would install between current and the target (checked after keepKRL and before anything is written);
      - ErrCALineRejected from validate.
    validate's KRL refusals (ErrKRLInvalid, ErrKRLRejected, ErrKRLDropsKeyEntry) are not content refusals for this rule: the KRL-alone generation carries the same KRL, so they would only recur. The KRL-alone state is state.KRLAlone(pins, prev, capture, refusal), where prev is the accepted state, or during a widening wait the pending target's state (pending.AsStored(), which pollSpool already verifies against). It takes prev's bundle, policy and directory unchanged (storedOnly) and runs verifyKRL against prev's bundle again; it never reuses the KRL of the refused Verified. The generation goes through the same render, caps, validate and Transition, and the apply returns the refusal after the commit, so the report and last_apply name it. A KRL-alone state with no newer KRL takes forward's no-change path and returns the refusal"
    - "F07 limits. A run takes at most one KRL-alone pass. A first install (no last-good) is excluded: KRLAlone returns the refusal when nothing is accepted. A preflightApply refusal is not a trigger: the KRL-alone generation meets the same preflight. I/O and lock errors, an injected crash and any failure after current moved keep today's handling. After a swap, a rollback already keeps the newest KRL (RollbackTarget), and a named test proves it"
    - "F07 leak. Every rollback ends with the retention cleanup that commit runs, so repeated failed runs never grow gen/ beyond keepGenerations plus current and last-good. Transition discards an intermediate it installed but could not validate"
    - "F08. With no accepted directory (after keyroster-agent reset-directory) and a last-good generation of the agent's, a Render refusal `host_not_in_directory: no directory is accepted yet` falls back to the trust files: the CA keys of the bundle in force and the verified KRL, with last-good's principals files unchanged and the host from last-good's record. Before a first install the refusal stands. heartbeat's closed set of host_status values is unchanged: the condition is reported through the apply's error. When Verify set Refused and render still fails, the returned error joins v.Refused, so last_apply names the real cause"
  artifacts:
    - path: "internal/agent/state/verify.go"
      provides: "KRLAlone, D-R2's KRL-alone state, used by Verify's refused branch and by the applier's post-verify pass"
      contains: "func KRLAlone("
    - path: "internal/agent/apply/apply.go"
      provides: "forward's and pollSpool's KRL-alone pass after a content refusal, and cleanup after rollback"
      contains: "state.KRLAlone("
    - path: "internal/agent/apply/render.go"
      provides: "RenderFallback without an accepted directory"
      contains: "no directory is accepted yet"
  key_links:
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/state/verify.go"
      via: "a content refusal after Verify rebuilds the capture as KRL-alone against the accepted (or pending) state"
      pattern: "state.KRLAlone"
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/apply/swap.go"
      via: "checkCandidate runs checkLimits on the target and its intermediate before installGeneration"
      pattern: "checkCandidate"
  prohibitions:
    - statement: "A fallback installs nothing that was not authenticated already: only CA keys of a bundle that state.Verify accepted; the accepted directory's principals, or last-good's unchanged when no directory is accepted; and a KRL that krl.VerifyManifest accepted against the accepted bundle, or during a widening wait against the pending target's verified bundle, for the pinned installation and above the accepted KRL version"
      status: resolved
      verification: test
---

<objective>
Make a verified KRL land whatever else its capture holds. After this plan:
- **F07.** A verified KRL lands even when the bundle or directory it arrived with cannot be rendered, is above the generation caps (alone or through its intermediate), or carries a CA line the host's ssh-keygen refuses. Failed runs no longer leave generations behind.
- **F08.** A host whose directory was reset keeps applying newer KRLs before a directory arrives, also when it holds a bundle that a signer restore lost.

Purpose: REVOKE-02 (the KRL reaches every enrolled host) and REVOKE-03 (a broken input never stops revocation). It extends owner decision D-R2 and threat row T-03-280 to every stage of the apply.

Output:
- state.KRLAlone;
- the post-verify KRL-alone pass in forward and pollSpool, the candidate check with the intermediate's caps, and cleanup after rollback;
- RenderFallback without a directory;
- named tests with RED evidence;
- host-setup.md and signer-install.md;
- the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **D-R2 (PR #71 review F5), existing:** a refused bundle or directory step never holds back the KRL. This plan applies it after Verify as well, and to an accepted state without a directory.
- **Q-split (Daniel, 2026-10-29).** The agent fix group is three plans, each with its own PR:
  - 03-08d (this plan): F07 and F08. Wave 13, depends on 03-08c.
  - 03-08e: F01 and F09. Wave 14, depends on 03-08d.
  - 03-08f: F02 and F03. Wave 15, depends on 03-08e.
  - 03-09 to 03-16 move one wave later per plan, and 03-09's `depends_on` follows the last of them. This plan's publish edits make the first move.
- **Grades (2026-10-29):** F07 low, F08 low.
- **Delivery (2026-10-29):**
  - The plan lands in the same PR as its fix.
  - The PR title and every commit message use neutral hardening wording and name findings only by F-number.
  - Pushing the branch and opening the PR before the merge is allowed, with its diff public while it is open (Daniel, 2026-10-29).
- **directory_unrenderable (Daniel, 2026-10-29):** a signer-side refusal, at install, of a directory the agent cannot render belongs to the signer-capacity plan (03-08g). It is out of scope here.
- **Homelab:** no 03-16 drill provokes these refusals on a real host. The runbook text this plan writes is labelled run in CI, and UNVERIFIED on a real host.

**Planner decisions, Claude's discretion, recorded with their reasons:**
- *Content refusals only, before current moved.*
  - A preflight refusal, and a KRL refusal from validate, would only recur on the KRL-alone generation.
  - An I/O failure retries at the next run.
  - After a swap, RollbackTarget already keeps the newest KRL.
- *The intermediate's caps are checked before install*, so Transition can then only fail for I/O, never for content.
- *Leak fix:* run retention cleanup after every rollback, the same code commit runs, rather than discarding piecemeal.
- *F08 keeps last-good's principals.* That is what current holds after a reset today; only the KRL and the bundle's CA keys change.
- *No new host_status value.* heartbeat.go, status.go and the server keep a closed set. A new value would make an updated agent's heartbeat fail on a server that is not yet updated.

No `checkpoint:decision` precedes Task 1.

## Budget

8 code, test and runbook files: 2 runbooks and 1 test file, all existing. The publish edits add the plan itself, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16.

About 75k tokens:
- about 85 KB actually read, through the function-scoped read_first lists below;
- about 30k written;
- about 15k of test and gate output.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names.
- **Branch.** Create `p03/08d-agent-revocation-flow` from origin/main in Task 1.
- **Plan file.** This file is placed untracked in the phase directory at the start, and Task 3 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Commits and PR text.** Neutral hardening wording (`fix(agent): ...`, `test(agent): ...`) that names findings only by F-number. No attribution lines, no IP addresses, no real host names; test fixtures use the existing dummy names.
- **Code comments.** A comment that cites these fixes writes `F07 (03-08d)` or `F08 (03-08d)`, so it is not read as one of PR #71's or PR #72's review numbers (F5, F3/F7).
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md`, with the docs commit `docs(03-08d): complete agent revocation-flow plan`.
- **Dependencies.** 03-08c is the plan before this one, and it shares docs/runbooks/host-setup.md (Cross-plan notes).

The defects this plan fixes, as read on main at 18a30c9:
- **F07.**
  - state.Verify implements D-R2's KRL-alone fallback only for refusals inside Verify (its refused branch: storedOnly, then verifyKRL).
  - engine.forward then renders, calls installGeneration (checkLimits), validates and runs Transition. Any refusal there returns or rolls back, and the capture's KRL is discarded.
  - Three directory shapes pass the signer's directory checks but exceed the agent-only caps in swap.go (64 KiB per principals file, 4096 principals files):
    - (A) 17 roles of 32 long principals mapped to one account;
    - (B) a host group of 4097 accounts;
    - (C) 4096 accounts and then a rename, whose intermediate covers the union of both sides' accounts (fileNames(from, to)).
  - A root-signed bundle with a CA line the host's ssh-keygen refuses fails validate in the same way.
  - In variant C each failed run also leaves an installed target generation under gen/, because cleanup runs only from finishCommit.
- **F08.** ResetDirectory clears only the accepted directory. On a host that also holds a bundle a signer restore lost:
  1. The bundle or directory step is refused on every run.
  2. Verify takes storedOnly with a nil Directory.
  3. Render refuses `host_not_in_directory: no directory is accepted yet`, and RenderFallback returns that refusal because v.Directory is nil.
  4. forward returns before the commit, on every run.

  The same happens, for one poll, to any newer KRL that arrives before the server's current directory.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a capture with a directory whose principals file is above the generation cap and a newer KRL → Verify accepts both → render, keepKRL, then the candidate check refuses generation_too_large → state.KRLAlone re-verifies the KRL against the accepted bundle → the KRL-alone generation is rendered, checked, installed, validated and moved to through Transition → commit → the report names generation_too_large and current revokes the new serial"</name>
  <reversibility rating="reversible">Applier-internal control flow and one exported state function. No on-disk format, wire message or signed document changes.</reversibility>
  <precondition>`git fetch origin` succeeds. `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md` exits 0. `S=$(git show origin/main:internal/signer/forget.go) && printf '%s\n' "$S" | grep -cF 'func (s *Signer) ForgetAgent('` prints at least 1, which shows 03-08c is merged. `V=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$V" | grep -c 'func KRLAlone('` prints 0.</precondition>
  <files>internal/agent/state/verify.go, internal/agent/apply/apply.go, internal/agent/apply/rechain_test.go</files>
  <read_first>
    Read functions, not files: find each with `grep -n` and read only that range.
    - internal/agent/state/verify.go: `func Verify(`, `func storedOnly(`, `func (v *Verified) verifyKRL(` and the Refused field's doc comment (about 6 KB)
    - internal/agent/apply/apply.go: `func (e *engine) forward(`, `func (e *engine) keepKRL(`, `func (e *engine) render(`, `func (e *engine) discard(` (about 8 KB)
    - internal/agent/apply/swap.go: `func checkLimits(` and the head of `func (e *engine) installGeneration(` (about 2 KB)
    - internal/agent/apply/rechain_test.go: `func TestKRLAlone(` (about 3 KB)
    - internal/agent/apply/harness_test.go: `type fixture struct`, `func newFixture(`, `type dirSpec struct`, and the testHost helpers `publishDir`, `publishKRL`, `apply`, `current`, `principals` and `installed` (`grep -n 'func (h \*testHost)'`; about 10 KB)
    - internal/agent/apply/apply_test.go: the subtest `oversize_generation_refused_before_install` (about 1 KB). It must stay green with its meaning
  </read_first>
  <action>
Create branch `p03/08d-agent-revocation-flow` from origin/main. Place this plan file untracked in the phase directory; Task 3 commits it.

**RED first.** Add `TestKRLAlone/oversize_principals_file_krl_applied` to rechain_test.go:
- install role:ops;
- publish a KRL revoking serial 5 and apply;
- publish a directory with `bulkRoles = 17` and a KRL revoking 5 and 6;
- apply.

Assert:
- the error is ErrGenerationTooLarge;
- current revokes 6;
- the principals of `deploy` are still `[role:ops]`;
- the report's DirectoryVersion and the accepted directory version are unchanged;
- InstalledKRLVersion is the new KRL version;
- Report.Errors names generation_too_large.

Run it on the unchanged code and record the failing lines in the SUMMARY. Today current keeps the old KRL.

**state (verify.go).** Add `func KRLAlone(p *Pins, prev *Stored, in spool.State, refusal error) (*Verified, error)`:
- it validates p;
- with no accepted bundle (prev nil, or prev.Bundle nil) it returns refusal;
- otherwise it builds storedOnly(prev), runs verifyKRL(p, prev, in) and sets Refused to refusal;
- a refused KRL returns `errors.Join(refusal, err)`.

Verify's own refused branch calls it, so D-R2's rule has one implementation. Its doc comment says that it uses only prev's bundle, policy and directory (the accepted state, or the pending target's during a widening wait) and re-verifies the KRL against prev's bundle, never under a bundle the refused Verified carried.

**apply (apply.go).**
- **Order.** forward reads current before rendering. Its order becomes: render, then keepKRL, then a new `checkCandidate(g, cur *Generation, curLink link) error`, which in this task runs checkLimits(g). Task 2 adds the intermediate.
- **When the pass runs.** After a render error or a checkCandidate error, when all of these hold:
  - v.Refused is nil;
  - BundleChanged or DirectoryChanged;
  - the error is not isCrash;
  - this run has not taken a KRL-alone pass yet.
- **The pass:**
  1. Log `WARNING <refusal>; the KRL is verified against the accepted bundle and applied alone`.
  2. Set `v = state.KRLAlone(e.pins, stored, st, refusal)`. Its error is returned as is; it already joins the refusal.
  3. Continue from forward's no-change check with the new v, so a KRL-alone state with no newer KRL returns the refusal without writing.
  4. A refusal in the second pass returns `errors.Join(firstRefusal, err)`.
- **Return value.** Every later return of forward that today returns v.Refused or tv.Refused returns the refusal after the commit.
- **No trigger:** preflightApply refusals, lock and I/O errors, and every Transition error.
- **Doc comment.** Rewrite forward's doc comment to state the rule and its exclusions, citing `F07 (03-08d)`.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestKRLAlone|TestResetDirectory|TestApply" ./internal/agent/apply/ ./internal/agent/state/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or "--- PASS: TestKRLAlone/oversize_principals_file_krl_applied" or "--- PASS: TestApply/oversize_generation_refused_before_install" missing</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'func KRLAlone(' internal/agent/state/verify.go` prints 1, and `grep -v '^[[:space:]]*//' internal/agent/state/verify.go | grep -c 'KRLAlone('` prints at least 2 (the definition, and the call in Verify's refused branch).
    - `grep -v '^[[:space:]]*//' internal/agent/apply/apply.go | grep -c 'state.KRLAlone('` prints at least 1.
    - The SUMMARY records the RED output of `oversize_principals_file_krl_applied` on origin/main's code, and that `oversize_generation_refused_before_install` passed unchanged.
  </acceptance_criteria>
  <done>A verified KRL lands when the directory it arrived with renders above the generation cap, re-verified against the accepted bundle, with the refusal reported.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The intermediate's caps, the CA-line refusal, pollSpool, the post-swap rollback, the gen/ leak, and F08's fallback without a directory</name>
  <files>internal/agent/apply/apply.go, internal/agent/apply/swap.go, internal/agent/apply/render.go, internal/agent/apply/resetdir.go, internal/agent/apply/rechain_test.go</files>
  <behavior>
    - F07 (`TestKRLAlone`). Each case below ends with current revoking the newer KRL's new serial, the accepted directory and bundle unchanged, and the refusal in Report.Errors, unless the case says otherwise:
      - `too_many_accounts_krl_applied`: a directory whose host group lab maps 4097 accounts. Task 1 already fixes this case, so its RED is taken on origin/main (see the action).
      - `intermediate_union_too_large_krl_applied`: version 1 maps 4096 accounts and is applied; version 2 renames one of them. Each version is within the cap, but the intermediate would hold 4097 principals files. The test asserts that no generation directory was written for version 2: genCount grows by the KRL-alone generation only. RED on Task 1's head.
      - `ca_line_rejected_krl_applied`: a root-signed successor bundle adds a `next` user CA entry whose line the fake runner's rejectCA refuses. validate refuses ErrCALineRejected, and the KRL-alone generation keeps the accepted bundle's CA lines. The report's BundleVersion is unchanged. RED on Task 1's head.
      - `ops_key_changed_krl_waits`: an f.rotationOps successor with a new ops key, a directory with bulkRoles 17, and a KRL signed by the new ops key. KRLAlone refuses that KRL under the accepted bundle, so nothing is installed and the error joins generation_too_large with krl_not_verified. This is the case that proves the fallback never reuses the refused Verified's KRL.
      - `refusal_without_newer_krl_is_noop`: the oversize directory alone. The error is ErrGenerationTooLarge, current and genCount are unchanged, and the report is NoOp.
      - `superseded_during_wait_krl_applied`: a widening transition is waiting. The spool then gains a bulkRoles-17 directory and a newer KRL. pollSpool supersedes with the pending target's directory and the newer KRL (KRL-alone against pending.AsStored()), and the run commits with current revoking it. Model it on TestSwapInterleaving/superseded_during_wait. RED on Task 1's head.
      - `selftest_failure_after_swap_keeps_new_krl`: a renderable directory change and a newer KRL, with the fake sshd failing the self-test after the swap. The rollback leaves current revoking the newer KRL (RollbackTarget). Expected GREEN at once; record that, and that TestApply/selftest_failure_after_krl_only_change_keeps_krl covers the KRL-only shape.
      - `failed_runs_do_not_grow_gen`: keepGenerations + 3 failed runs (8, with keepGenerations = 5 in swap.go), each with a new renderable directory version and a self-test that fails. The test records genCount after every run.
        - After the last run, gen/ holds at most keepGenerations + 2 numbered generations.
        - genCount does not grow over the last three runs.

        Each failed run leaks one target generation. With fewer runs than keepGenerations + 3, the bound holds even without the cleanup, so the run count is what makes this case RED on Task 1's head, where the count grows by one per run. The cleanup mutant must die on it.
      - `first_install_refusal_stands`: a host with no last-good is offered a bulkRoles-17 directory and a KRL. The error is ErrGenerationTooLarge and nothing is installed.
    - F08 (`TestResetDirectory`):
      - `reset_then_newer_krl_before_directory_arrives`: after ResetDirectory the spool offers a newer KRL and no directory. The apply installs it, the principals of deploy stay last-good's, the report's HostStatus is empty, and the error names host_not_in_directory. RED today: nothing is installed.
      - `reset_then_new_bundle_before_directory`: after ResetDirectory, the capture holds a verified successor bundle that adds a `next` user CA entry, and no directory. The apply takes the new bundle's CA lines in user_ca_keys and keeps last-good's principals, with BundleVersion 2; the widening goes through Transition's two steps. RED today.
      - `lost_bundle_then_reset_krl_still_applied`:
        1. The host accepted a bundle version 2 and a directory version 2 that a signer restore lost. The server serves a re-made bundle 3 built on a different version 2, and a directory version 3.
        2. A control apply refuses bundle_not_verified and applies a KRL alone.
        3. ResetDirectory runs, and a KRL revoking a new serial is published.
        4. Four applies each install it or are no-ops, and the error names bundle_not_verified, not only host_not_in_directory.

        RED today: each apply returns `host_not_in_directory: no directory is accepted yet`, and the serial is not revoked.
      - `reset_without_last_good_refusal_stands`: with no agent last-good, nothing is installed.
  </behavior>
  <read_first>
    Read functions, not files: find each with `grep -n` and read only that range. Task 1's own edits are already in context.
    - internal/agent/apply/apply.go: `func (e *engine) pollSpool(`, `func (e *engine) rollback(`, `func (e *engine) backToLastGood(` (about 4 KB)
    - internal/agent/apply/swap.go: `func (e *engine) Transition(`, `func (e *engine) cleanup(`, `const keepGenerations` (about 3 KB)
    - internal/agent/apply/render.go: `func Render(`, `func RenderFallback(`, `func renderTrust(`, `func Intermediate(` (about 9 KB)
    - internal/agent/apply/validate.go: the refusal sentinels (about 1 KB)
    - internal/agent/apply/resetdir.go: ResetDirectory's doc comment (about 2 KB)
    - internal/agent/apply/rechain_test.go: `func TestResetDirectory(`, `spoolInState`, `readAccepted` (about 5 KB)
    - internal/agent/apply/apply_test.go: `func (f *fixture) successor(`, `rotation(`, `rotationOps(`, and the subtests `selftest_failure_rolls_back` and `selftest_failure_after_krl_only_change_keeps_krl` (about 5 KB)
    - internal/agent/apply/interleave_test.go: the subtest `superseded_during_wait` (about 2 KB)
    - internal/agent/apply/harness_test.go: `type fakeRunner struct`, for rejectCA and the self-test switches (about 2 KB)
  </read_first>
  <action>
Write the tests in `<behavior>` first, before any code below. Run them on Task 1's head and record in the SUMMARY which are RED there.

`too_many_accounts_krl_applied` is GREEN on Task 1's head, because Task 1's checkCandidate already covers the target's caps. Take its RED instead from a scratch worktree of origin/main outside the checkout (`git worktree add <tmp> origin/main`), with only the new test case copied in, and remove the worktree afterwards (`git worktree remove`). For each case that is GREEN at once, say why in the SUMMARY. Every test in this task asserts only through symbols that already exist on origin/main: ErrGenerationTooLarge, ErrCALineRejected, state.ErrKRL, state.ErrBundle, ErrHostNotInDirectory and the test helpers. So every RED, the worktree one included, fails on behaviour, not on the build.

Then implement.

**checkCandidate (apply.go).** When curLink is the agent's and Intermediate(cur, g) does not collapse, also run checkLimits on that intermediate (Transition would install exactly it). Wrap the error to say it is the intermediate. checkCandidate stays after keepKRL.

**The CA-line trigger (apply.go).**
- A validate error wrapping ErrCALineRejected, under the same conditions as Task 1, discards the target and takes the KRL-alone pass.
- The KRL sentinels (ErrKRLInvalid, ErrKRLRejected, ErrKRLDropsKeyEntry) do not trigger it: the KRL-alone generation carries the same KRL. A comment says so.

**pollSpool (apply.go).**
- On a content refusal of the superseding capture, under the same conditions, take one KRL-alone pass with `state.KRLAlone(e.pins, pending.AsStored(), st, refusal)`.
- Then render, keepKRL, checkCandidate against current, compare sameBytes against the target, install and validate.
- forward and pollSpool share one helper for the eligibility test and the pass, so the two cannot drift.

**Leak (apply.go, swap.go).**
- rollback calls e.cleanup() after backToLastGood succeeds. Today only finishCommit cleans up.
- Transition calls e.discard(m.N) when the validate of an intermediate it installed fails.

**F08 (render.go, apply.go, resetdir.go).**
- **RenderFallback.** When v.Directory is nil, the refusal is ErrHostNotInDirectory and lastGood is not nil, it returns renderTrust(v) with every principals-class file of lastGood copied unchanged. Host is lastHost and the status is the empty string. Every other refusal with a nil directory is returned as is.
- **engine.render.** Its warning for the empty status says `host_not_in_directory: no directory is accepted yet; the KRL and CA keys apply, principals are kept as last-good's`.
- **forward.**
  - When Verify set Refused and render still fails, return `errors.Join(v.Refused, err)`.
  - When the fallback without a directory was used, return `errors.Join(v.Refused, the host_not_in_directory error)` after the commit, so last_apply shows it until a directory is accepted.
- **Doc comments.**
  - RenderFallback's doc comment says the no-directory case.
  - Rewrite the last paragraph of ResetDirectory's doc comment, which says an apply with a newer KRL fails until the directory arrives. The new paragraph contains the words `installs it with the accepted bundle's CA keys and last-good's principals`.
  - Both cite `F08 (03-08d)`.

Run the whole apply package. Every existing TestKRLAlone, TestResetDirectory, TestApply, TestSwapInterleaving and TestIntermediate case must keep its meaning. Record in the SUMMARY any assertion that had to move, and why.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestKRLAlone|TestResetDirectory|TestApply|TestSwapInterleaving|TestIntermediate" ./internal/agent/apply/ ./internal/agent/state/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestKRLAlone/oversize_principals_file_krl_applied", "--- PASS: TestKRLAlone/too_many_accounts_krl_applied", "--- PASS: TestKRLAlone/intermediate_union_too_large_krl_applied", "--- PASS: TestKRLAlone/ca_line_rejected_krl_applied", "--- PASS: TestKRLAlone/ops_key_changed_krl_waits", "--- PASS: TestKRLAlone/refusal_without_newer_krl_is_noop", "--- PASS: TestKRLAlone/superseded_during_wait_krl_applied", "--- PASS: TestKRLAlone/selftest_failure_after_swap_keeps_new_krl", "--- PASS: TestKRLAlone/failed_runs_do_not_grow_gen", "--- PASS: TestKRLAlone/first_install_refusal_stands", "--- PASS: TestResetDirectory/reset_then_newer_krl_before_directory_arrives", "--- PASS: TestResetDirectory/reset_then_new_bundle_before_directory", "--- PASS: TestResetDirectory/lost_bundle_then_reset_krl_still_applied", "--- PASS: TestResetDirectory/reset_without_last_good_refusal_stands"</fails_when>
    <automated>bash scripts/linux.sh 'go test -count=1 -run NONE ./... && go vet ./internal/agent/...'</automated>
    <fails_when>non-zero exit (a package no longer builds or vet reports a problem)</fails_when>
  </verify>
  <acceptance_criteria>
    - `tr -s '[:space:]' ' ' < internal/agent/apply/resetdir.go | grep -c 'one with a newer KRL fails and changes nothing'` prints 0, and `tr -s '[:space:]' ' ' < internal/agent/apply/resetdir.go | grep -c "installs it with the accepted bundle's CA keys and last-good's principals"` prints 1.
    - The SUMMARY lists these mutants, each applied, run against its named test and restored byte for byte:
      - the pass removed from forward (killed by `too_many_accounts_krl_applied`);
      - KRLAlone made to keep the refused Verified's KRL (killed by `ops_key_changed_krl_waits`);
      - checkCandidate's intermediate check removed (killed by `intermediate_union_too_large_krl_applied`);
      - checkCandidate moved before keepKRL (killed by a named case the executor adds and records, or recorded as equivalent with its reason);
      - the ErrCALineRejected trigger removed (killed by `ca_line_rejected_krl_applied`);
      - the cleanup after rollback removed (killed by `failed_runs_do_not_grow_gen`);
      - the pass removed from pollSpool (killed by `superseded_during_wait_krl_applied`);
      - RenderFallback's no-directory branch removed (killed by `reset_then_newer_krl_before_directory_arrives`);
      - the v.Refused join removed (killed by `lost_bundle_then_reset_krl_still_applied`).
  </acceptance_criteria>
  <done>Every content refusal before current moves lets the verified KRL land alone, in forward and during a widening wait; a reset host applies newer KRLs and bundles before its directory arrives; failed runs leave nothing behind; and every such refusal is named in the apply's error.</done>
</task>

<task type="auto">
  <name>Task 3: The runbooks, the publish edits, the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/host-setup.md, docs/runbooks/signer-install.md, .planning/phases/03-linux-agent-and-revocation/03-08d-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/host-setup.md: the "Running the agent" section only (`grep -n '^## \|^### '`; about 6 KB), as 03-08b and 03-08c left it
    - docs/runbooks/signer-install.md: the paragraph "Enrolled hosts and a re-made version" (`grep -n 'Enrolled hosts and a re-made version'`; about 3 KB)
    - .planning/ROADMAP.md: Phase 3's Plans line and its wave blocks (`grep -n 'Wave\|Plans:'`); .planning/STATE.md: the frontmatter and the `Plan:` line
    - 03-09-PLAN.md's frontmatter and Task 1 precondition; the `wave:` lines of 03-10 to 03-16 (`grep -n '^wave:\|^depends_on:'`)
    - .planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md deviation 8 (the SUMMARY is pushed before approval is asked)
  </read_first>
  <action>
**Runbooks (D-20).** Every changed or new paragraph is labelled run in CI (with the test names and 03-08d) and UNVERIFIED on a real host, since no 03-16 drill provokes these refusals.
- **host-setup.md, "Running the agent".** Add a paragraph "Revocations keep applying": when the applier cannot apply a capture's bundle or directory, the KRL still lands. The cases:
  - a refused verification;
  - a directory too large for the agent's generation caps;
  - a CA line the host's ssh-keygen refuses;
  - no accepted directory after reset-directory.

  The applier then installs the capture's KRL alone, verified against the bundle it accepted, with the CA keys and principals in force, and last_apply names the refusal. On a rebase conflict with 03-08b's or 03-08c's edits, which are in other sections, keep their text and re-apply this paragraph.
- **signer-install.md, "Enrolled hosts and a re-made version":**
  - "Which hosts saw a lost version" also reads `bundle` in accepted.json. A host whose bundle is above the restored signer's bundle version saw a lost bundle: escalate, because reset-directory re-bootstraps the directory only.
  - After the reset, newer KRLs keep applying with the CA keys of the bundle the host accepted, while it keeps the principals it had.
  - Run in CI: `TestResetDirectory/lost_bundle_then_reset_krl_still_applied`.

**Publish edits** (this PR, on top of origin/main). Every number is origin/main's value + 1; the values in brackets are today's expectation.
1. Commit this plan as `.planning/phases/03-linux-agent-and-revocation/03-08d-PLAN.md`, unchanged.
2. ROADMAP.md, Phase 3:
   - Plans line: the plan total and the wave count each grow by one (`N/21 plans executed in 20 waves` → `N/22 ... in 21 waves`). GSD's tracking update sets N.
   - After the Wave 12 block, insert `**Wave 13** *(blocked on Wave 12 completion)*` with the unchecked entry `03-08d-PLAN.md — Verified KRLs land whatever else a capture holds (F07, F08): a KRL-alone pass after render, size or CA-line refusals (also of the intermediate) and after reset-directory`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 13–20 → 14–21), each "blocked on" clause with them.
   - Add nothing about any other plan.
3. STATE.md: `total_plans` +1 (56 → 57), and the Plan line's `of M` +1 (of 21 → of 22).
4. 03-09-PLAN.md:
   - `wave:` +1 (13 → 14);
   - `depends_on` becomes `["03-08d"]`;
   - Task 1's `<precondition>` gains the clause `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md` exits 0, next to its 03-08c clause, which stays.
5. The `wave:` lines of 03-10 to 03-16 +1 each (14–20 → 15–21).
6. Guard: if origin/main's 03-09 does not hold `wave: 13` and `depends_on: ["03-08c"]`, another plan was slotted in first. Apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**Push and the PR.**
1. Commit by path only.
2. Push the branch for the first time. The owner allows pushing before the merge.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(agent): apply verified KRLs whatever else a capture holds (F07, F08)"` with a neutral body: what changed, the tests, the labels.
4. Do not enable auto-merge; the orchestrator enables it after the pre-merge review.
5. Wait for the required checks.

**The SUMMARY.** Contents:
- the PR number and the check run IDs;
- the RED evidence, and where each RED was taken (Task 1's or Task 2's head, or origin/main);
- the mutants;
- the GREEN-at-once cases with their reasons;
- capslock;
- `requirements-completed` empty: REVOKE-02 and REVOKE-03 are complete since earlier plans, and this plan hardens them.

Then run the tracking updates once, commit `docs(03-08d): complete agent revocation-flow plan`, push, and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'Revocations keep applying' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'lost_bundle_then_reset_krl_still_applied' && grep -qx 'depends_on: \["03-08d"\]' .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md && M=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md) && W=$(printf '%s\n' "$M" | sed -n 's/^wave: //p') && test -n "$W" && grep -qx "wave: $((W+1))" .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md && grep -c '03-08d-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit (a runbook paragraph, the dependency, the +1 wave shift or the ROADMAP row is missing)</fails_when>
    <automated>git fetch origin p03/08d-agent-revocation-flow && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08d-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08d-agent-revocation-flow --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new or rewritten runbook paragraph names at least one CI test and says UNVERIFIED on a real host.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0, and `B=$(scripts/gh-as-bot.sh pr view p03/08d-agent-revocation-flow --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08d-SUMMARY.md is on its head. The PR title and every commit message name findings only by F-number.
  </acceptance_criteria>
  <done>The runbooks say that revocations keep applying, and the PR waits green with the plan and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — owner approves PR p03/08d-agent-revocation-flow, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/08d-agent-revocation-flow --web`. Review:
       - forward's KRL-alone pass and its exclusions;
       - checkCandidate;
       - state.KRLAlone;
       - RenderFallback without a directory;
       - 03-08d-SUMMARY.md.

       Check especially that no fallback installs a KRL that was not verified against the accepted bundle, or, during a widening wait, against the pending target's bundle.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08d-agent-revocation-flow` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08d-agent-revocation-flow</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which the next plan's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08d-agent-revocation-flow --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>Verified KRLs land on every apply path on main, and 03-08e may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08c overlap.** 03-08b and 03-08c also edit docs/runbooks/host-setup.md, in "Removing a host" and the forget rows of the refusal table. This plan starts from an origin/main that holds both (Task 1's precondition) and writes another paragraph. No code file overlaps 03-08c's files_modified.
- 03-08e (F01, F09) and 03-08f (F02, F03) follow and keep this plan's tests green.
- **Later plans that edit the same files** must keep TestKRLAlone (every subtest) and TestResetDirectory green with their meaning:
  - 03-09, 03-10 and 03-14 edit apply.go;
  - 03-10, 03-12 and 03-14 edit render.go;
  - 03-13 edits state/verify.go.

  A later change that adds a refusal to render, to the caps or to validate's CA check makes it a content refusal: it triggers the pass and needs a named TestKRLAlone case.
- **03-12 (draining CAs on the agent's own clock).** The re-render in run.go without a new capture is not a capture with a changed bundle or directory, so it never takes the pass.
- **Signer capacity (03-08g)** owns the signer-side refusal of directories the agent cannot render (owner decision 2026-10-29).

## Edge Coverage (spec-less fallback, this plan)

This plan authors the fallback's edges as truths.

**Flagged assumption, "content refusal".** Only render, the caps (target and intermediate) and ErrCALineRejected count. The named tests show why everything else is safe with today's handling: `selftest_failure_after_swap_keeps_new_krl` covers post-swap failures, and the next run covers I/O.

**Edges:**
- adjacency (4096 versus 4097 accounts, the intermediate's union);
- ordering (`superseded_during_wait_krl_applied`, `selftest_failure_after_swap_keeps_new_krl`);
- refusal with nothing to apply (`refusal_without_newer_krl_is_noop`, `first_install_refusal_stands`, `reset_without_last_good_refusal_stands`);
- a KRL valid only under the refused bundle (`ops_key_changed_krl_waits`);
- a bundle without a directory (`reset_then_new_bundle_before_directory`);
- repetition (`failed_runs_do_not_grow_gen`, four applies after the reset).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Revocation takes effect across the fleet without risking lockout | Tasks 1, 2 |
| REQ | REVOKE-02 (the KRL reaches every enrolled host) | Tasks 1, 2 |
| REQ | REVOKE-03 (a broken input never stops revocation) | Tasks 1, 2 |
| Finding | F07 (post-verify refusals withhold the KRL; the gen/ leak) | Tasks 1, 2 |
| Finding | F08 (reset-directory after a lost bundle stops later KRLs) | Task 2, Task 3 runbook |
| CONTEXT | D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 3 |
| Owner decision | D-R2; Q-split, grades, delivery and push before merge (2026-10-29) | Owner decisions block, Tasks 1-3 |
| Owner decision | directory_unrenderable to the signer-capacity plan (03-08g) | Ledger, deferred |

## Artifacts this phase produces (this plan)

- state: `KRLAlone`.
- apply:
  - forward's and pollSpool's KRL-alone pass;
  - `checkCandidate` with the intermediate's caps;
  - the ErrCALineRejected trigger;
  - cleanup after rollback, and the discard of an unvalidated intermediate;
  - RenderFallback without a directory.
- Tests: TestKRLAlone (10 new cases), TestResetDirectory (4 new cases).
- Docs: host-setup.md "Revocations keep applying"; signer-install.md's host selection by bundle version and the KRL sentence.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| admin quorum and roots → applier | A validly signed bundle or directory can still be one the agent cannot apply; its refusal must not take the KRL with it |
| fetcher (spool) → root applier | Every spool byte is untrusted until state.Verify checks it against the pins and the accepted state |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-294 | Denial of service | engine.forward and pollSpool: a validly signed bundle or directory that fails render, the caps (its intermediate's included) or the CA-line check, and so withholds every later KRL (F07) | medium | mitigate | One KRL-alone pass through state.KRLAlone after a content refusal, before current moves; the intermediate's caps are checked before install. Tests: `oversize_principals_file_krl_applied`, `too_many_accounts_krl_applied`, `intermediate_union_too_large_krl_applied`, `ca_line_rejected_krl_applied`, `superseded_during_wait_krl_applied`. **Residual:** the host keeps its old directory and principals until a renderable successor arrives; the signer-side refusal belongs to the signer-capacity plan (03-08g) |
| T-03-295 | Denial of service | gen/ growing by one generation, or one intermediate, per failed run (F07, variant C) | low | mitigate | Retention cleanup after every rollback; Transition discards an unvalidated intermediate. Test: `failed_runs_do_not_grow_gen` |
| T-03-296 | Elevation of privilege / Tampering | a fallback installing a KRL, CA key or principals line that was not authenticated (this plan's own risk) | high | mitigate | The prohibition. KRLAlone takes prev's bundle, policy and directory, and re-runs krl.VerifyManifest against prev's bundle, the pinned installation and the accepted KRL version. prev is the accepted state, or during a widening wait the pending target's state, whose bundle state.Verify accepted in the same run (pending.AsStored). The fallback without a directory uses the verified bundle's CA keys and last-good's installed principals. Every fallback generation passes validate and Transition. Tests: `ops_key_changed_krl_waits`, `first_install_refusal_stands`, `reset_without_last_good_refusal_stands` |
| T-03-297 | Denial of service | reset-directory on a host whose accepted bundle a signer restore lost, which stops every later KRL; and a newer KRL or bundle that waits a poll for the directory after any reset (F08) | medium | mitigate | RenderFallback without a directory installs the trust files with last-good's principals, and the error names the refused step. signer-install.md selects hosts by bundle version too, and escalates. Tests: `lost_bundle_then_reset_krl_still_applied`, `reset_then_newer_krl_before_directory_arrives`, `reset_then_new_bundle_before_directory`. **Residual:** the host stays on the lost bundle until escalation; reset-directory does not re-bootstrap a bundle |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; capslock baseline unchanged (a new pair is a recorded deviation) |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh), the full gate passes, the PR's required checks are green, and the merge gate passes.
</verification>

<success_criteria>
- A verified KRL lands on an enrolled host whatever the rest of its capture holds: an unrenderable, oversize or ssh-keygen-refused bundle or directory, or no accepted directory.
- No fallback installs anything that the accepted state (or, during a widening wait, the pending target), the pins and that state's bundle did not authenticate.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md` in Task 3, before the merge gate. `requirements-completed` is empty: REVOKE-02 and REVOKE-03 are complete since earlier plans, and this plan hardens them. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (findings F07 and F08, and the owner decisions of 2026-10-29)

### Round 1 — plan check 1 (2026-10-29, PASS WITH FIXES)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| F07: D-R2's KRL-alone fallback exists only inside Verify; render, caps, validate and Transition's intermediate refusals withhold the KRL; variant C leaks a target generation per run | LOW | must_haves truths 2-4; Tasks 1, 2; T-03-294, T-03-295, T-03-296 |
| F08: after reset-directory with a refused bundle or directory step, Render and RenderFallback refuse without a directory and no KRL lands; the error hides the refused step | LOW | must_haves truth 5; Task 2; Task 3 signer-install.md; T-03-297 |
| Planner: the fallback must never install a KRL that only an uncommitted bundle verifies | HIGH | KRLAlone re-verifies under prev's bundle; `ops_key_changed_krl_waits`; the prohibition |
| Planner: a new host_status value would break heartbeats to a server that is not yet updated | MEDIUM | No new value; the refusal is in the apply's error |
| Check 1 item 2 (MAJOR): Task 2 could not show RED because Task 1 implemented its behaviour | MAJOR | Task 1 now implements only KRLAlone and the target's caps. The intermediate check, the CA-line trigger, pollSpool, the cleanup and the discard moved to Task 2, after their tests. `too_many_accounts_krl_applied` takes its RED on an origin/main worktree |
| Check 1 item 3 (MAJOR): unrealistic budget | MAJOR | Split by owner decision Q-split (F01 and F09 to 03-08e); read_first scoped to functions; about 85 KB read |
| Check 1 item 4: interleave regex | MINOR | `TestSwapInterleaving|TestIntermediate` in Task 2's verify |
| Check 1 item 5: every subtest in fails_when | MINOR | Task 2's fails_when lists all 14 |
| Check 1 item 6: vacuous resetdir.go grep | MINOR | `tr -s` normalisation, plus a positive check for the new sentence |
| Check 1 item 7: KRLAlone wording during a widening wait | MINOR | Truth 2, the prohibition, Task 1's doc comment and T-03-296 name the pending target's state |
| Check 1 item 8: KRL sentinels as triggers | MINOR | Dropped; only ErrCALineRejected from validate triggers, with the reason in a comment |
| Check 1 item 9: a bundle change without a directory | MINOR | `reset_then_new_bundle_before_directory` |
| Check 1 item 10: checkCandidate after keepKRL | MINOR | Task 1's order (render, keepKRL, checkCandidate); a mutant for the order |
| Check 1 item 11: neutrality | MINOR | The attribution grep also matches "Generated with", in commits and the PR body; comments cite `F07 (03-08d)` and `F08 (03-08d)` |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| F07: the signer refuses at install a directory the agent cannot render (`directory_unrenderable`) | Owner decision 2026-10-29: the signer-capacity plan, 03-08g |
| F08: reset-directory refuses or warns while the bundle step is refused | The fallback removes the outage; the runbook's host selection by bundle version covers the operator step, and a bundle re-bootstrap is an escalation |
