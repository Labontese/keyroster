---
phase: 03-linux-agent-and-revocation
plan: 08f
type: execute
wave: 17
depends_on: ["03-08k"]
files_modified:
  - internal/agent/state/state.go
  - internal/agent/state/verify.go
  - internal/agent/apply/render.go
  - internal/agent/apply/apply.go
  - internal/agent/apply/installed.go
  - internal/agent/apply/status.go
  - internal/agent/apply/status_test.go
  - internal/agent/apply/apply_test.go
  - internal/agent/apply/policy_change_test.go
  - internal/agent/apply/window_test.go
  - internal/agent/spool/spool.go
  - internal/agent/spool/spool_test.go
  - internal/agent/fetch/fetch.go
  - internal/agent/fetch/fetch_test.go
  - internal/agent/fetch/prune_test.go
  - docs/runbooks/root-ceremony.md
  - docs/runbooks/enroll-user.md
  - docs/runbooks/signer-install.md
  - docs/runbooks/host-setup.md
  - .planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md
  - .planning/phases/03-linux-agent-and-revocation/03-08f-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md
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
requirements: [AGENT-03, AUTHZ-02]

estimate:
  tokens: 265000
  raw_tokens: 265000
  tasks: 5
  confidence: low

must_haves:
  truths:
    - "Owner decision Q-split (Daniel, 2026-10-29): this plan holds F02 and F03 and runs after 03-08e, 03-08j and 03-08k, all three merged (main at 682782e, and b1ebff3 adds only PR #81). Its goal is that the agent never keeps trusting what the root-signed policy in force has retired: retired roots, or a removed admin's directory"
    - "F03. On every verification of a capture (state.Verify, VerifyAfter, VerifyAhead and VerifyAheadAfter, which all run verify), and in storedOnly and therefore KRLAlone, the stored directory is checked again under the policy in force: directory.VerifySignatures over its stored signatures, then directory.CheckPolicy. This is the signer's own check at start-up (loadDirectory). In verify the stored directory is the one the capture chains from (accepted/'s, or the unapplied record's directory part when the record holds one, 03-08j), and the policy is the newest one the bundle step reached; in storedOnly both are prev's (accepted/'s, or a widening wait's pending target's). When either check fails, Verified.DirectoryUnauthorized wraps `directory_not_authorized`. The stored directory stays in accepted/ and the flag is derived on every run, never stored, so a host that already holds the bad state heals on its first run of this code that ends without a Verify or KRL-alone error. A run whose Verify or KRL-alone pass returns an error installs nothing, as on main: an accepted residual (owner decision O-1 (a), T-03-323). While the stored directory is unauthorized, a refusal of the offered directories no longer refuses the capture. That covers directory_older, directory_chain_gap, directory_not_verified for any cause (a missing quorum, a broken chain, a parse or version error, CheckPolicy) and directory_installation; an unparseable stored directory stays an error. The verified bundle step is kept, the newest one, and a hold that the refused directory set up is undone, so the host stays fail-closed under the newest verified bundle"
    - "F03 while unauthorized (owner decision Q-F03a, keep the fail-closed window). Render emits only the trust files: the CA keys of the bundle in force and the verified KRL. It emits no principals files, so certificate logins fail closed, as on the signer (T-02-15); authorized_keys and the console are unaffected. forward renders even when the capture changed nothing, so principals already installed are removed, and a run whose rendered generation equals current is a no-op that commits nothing. Every return carries the unauthorized error (forward's outcome and krlAlone's joined refusals), so last_apply names it, with result refused. outbox/accepted.json reports directory 0 while the directory the next capture chains from is unauthorized under its chain base's policy, so the fetcher asks for the server's current directory. The chain base is the unapplied record's base when the record has a part ahead of accepted/ (its directory part, when it holds one), else accepted/. While that directory is authorized, accepted.json names the versions WriteAccepted names today, the record's raise included, so the fetcher keeps fetching the versions after the record (owner decision O-2 (c)). enroll-user.md tells operators to install the new admins' directory right after the bundle"
    - "F03 recovery (owner decision Q-F03b, the same version or higher only). Verify accepts, standalone (no chain to the stored bytes), the newest offered directory at or above the stored version that carries the current policy's admin quorum, parses, names the pinned installation and fits the policy. At the stored version it does so only when the bytes differ. That clears the flag. A host whose stored version is above anything the new admins signed stays fail-closed until an operator runs reset-directory explicitly. While the stored directory is authorized, an offered directory with the stored version and other bytes is reported as `directory_fork` only when it also carries the current admin quorum (both sides then verified); otherwise it is `directory_not_verified`. D-R2 still applies the KRL alone in both cases. PR #67's hold path stays, with 03-08j's in-force hold step. The signer and CLI side of recovery stays with todo 2026-10-21-recover-directory-after-admin-set-change (Phase 4)"
    - "F02, verification. Each successor step is first verified exactly as today, with the policy signatures findPolicy returns, which are the stored ones when the policy is unchanged. Only when trust.VerifySuccessor fails with trust.ErrThreshold does the step retry once, with a union of policy-signature files. The union draws on three sources: the step's previous signatures (at the first step the chain base's: accepted/'s, the unapplied record's, or the pending target's), the signatures delivered with that bundle (spool file `bundle-<N>.policy.sigs`), and the offered `policy-<v>.json.sigs` whose body has that SHA-256. A source is admitted only when sshsig.ParseAll accepts it on its own, and identical files are admitted once. The bundle signatures are never united. So the union never refuses a successor that today's check accepts, and it accepts only what VerifySuccessor accepts for a file of genuine signatures over those exact policy bytes"
    - "F02, why the union cannot widen trust, read in internal/trust/verify.go:
      - Both thresholds come from the bundles (prev.Root.Threshold and the successor's Root.Threshold).
      - CountPinnedSigners counts each pinned fingerprint at most once (its signed map), and only for a block whose public key equals the pinned key byte for byte and whose SSHSIG verifies over SHA-512 of the exact policy bytes under the policy namespace.
      - Every source is a signature file the signer accepted or served, so a spool writer could already present it.
    Neither accepted/ nor unapplied.json (whose bundle part copies Next.PolicySigs, 03-08j) stores the union. Next.PolicySigs is the file the plain check passed with, or, when the union was needed, one admitted source: the first of the delivered file and the offered file that passes VerifySuccessor alone, else the offered file if admitted, else the delivered file. A source ParseAll rejected is never stored, so a malformed delivered file cannot bring F02 back at the next hop. Every stored file was read under spool.MaxBundle, so LoadStored's and ParseUnapplied's caps always hold"
    - "F02, the spool. The fetcher writes each bundle item's PolicySigs as `bundle-<N>.policy.sigs`, before `bundle-<N>.json`. spool.Read returns it in State.BundlePolicySigs, and accepts its absence (a spool written before this plan). 03-08e's spool.Cap, checkCaps and healSpool cover it, dropAbove removes it with its bundle, and pruneSpool keeps it exactly while it keeps its bundle (owner decision O-3 (a): the spool's computed bound grows by one spool.MaxBundle file per kept bundle, to about 6.1 GiB kept and 6.6 GiB in all). A rotation that keeps the policy and replaces the roots or raises the threshold is then accepted, in one hop or several in one capture, and the retired roots stop anchoring the host"
  artifacts:
    - path: "internal/agent/state/verify.go"
      provides: "the stored directory checked again under the policy in force, standalone recovery, the fork rule, the policy-signature union on ErrThreshold"
      contains: "DirectoryUnauthorized"
    - path: "internal/agent/apply/policy_change_test.go"
      provides: "TestDirectoryUnderPolicyInForce and TestRootRotationUnchangedPolicy"
      contains: "func TestRootRotationUnchangedPolicy"
    - path: "internal/agent/spool/spool.go"
      provides: "BundlePolicySigs, the per-bundle policy signature file"
      contains: "BundlePolicySigs"
    - path: "internal/agent/fetch/fetch.go"
      provides: "the per-bundle policy signature file written, dropped and pruned with its bundle"
      contains: "BundlePolicySigs"
    - path: "internal/agent/apply/status.go"
      provides: "directory_not_authorized and directory_fork count as refusals in last_apply"
      contains: "state.ErrDirUnauthorized"
    - path: "internal/agent/apply/installed.go"
      provides: "WriteAccepted writes directory 0 while the chain base's directory is unauthorized, and the record's raise otherwise (owner decision O-2 (c))"
      contains: "DirectoryUnderPolicy"
  key_links:
    - from: "internal/agent/fetch/fetch.go"
      to: "internal/agent/spool/spool.go"
      via: "writeState spools each bundle item's policy signatures under the bundle's version"
      pattern: "BundlePolicySigs"
    - from: "internal/agent/fetch/fetch.go"
      to: "internal/agent/spool/spool.go"
      via: "pruneSpool keeps bundle-<N>.policy.sigs exactly when spool.Keep keeps bundle N"
      pattern: "spoolSet"
    - from: "internal/agent/state/verify.go"
      to: "internal/trust/verify.go"
      via: "a step that fails with ErrThreshold is retried with the united policy signatures"
      pattern: "trust.ErrThreshold"
    - from: "internal/agent/apply/render.go"
      to: "internal/agent/state/verify.go"
      via: "Render emits no principals while the stored directory is unauthorized"
      pattern: "DirectoryUnauthorized"
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/state/verify.go"
      via: "outcome joins the unauthorized error, so every run that leaves the host unauthorized names it"
      pattern: "v.DirectoryUnauthorized"
    - from: "internal/agent/apply/installed.go"
      to: "internal/agent/state/verify.go"
      via: "WriteAccepted checks the chain base's directory under the chain base's policy (Stored.DirectoryUnderPolicy) and writes directory 0 only while it is unauthorized"
      pattern: "DirectoryUnderPolicy"
  prohibitions:
    - statement: "A host never renders principals from a directory that the admin quorum of the root-signed policy in force did not sign, and never lowers a root threshold: a successor bundle is accepted only when prev's threshold of previous roots and the successor's threshold of new roots, each root counted once, signed the successor bundle itself and the exact policy bytes"
      status: resolved
      verification: test
---

<objective>
Make the root-signed policy in force decide what a host trusts. After this plan:
- **F03.** A host stops rendering principals from a directory that the policy's current admin quorum did not sign, such as a removed admin's. It reports this and takes the new admins' first directory.
- **F02.** A host takes a root rotation that keeps the policy unchanged, so the retired roots stop anchoring it.

Purpose: AGENT-03 (the agent applies only what the pinned roots and their delegated keys signed) and AUTHZ-02 (principals come from the signed host policy in force). It closes the gap where the documented remedies, a policy that removes an admin and a root rotation, did not take effect on enrolled hosts.

Output:
- the directory check under the policy in force, with fail-closed rendering, standalone recovery and the fork rule;
- the two refusal codes in last_apply's refusals;
- the policy-signature union on threshold failures, and the per-bundle policy signature file in the spool and the fetcher, pruneSpool included;
- named tests with RED evidence and mutants;
- root-ceremony.md, enroll-user.md, signer-install.md and host-setup.md;
- the todo's status line;
- the publish edits and a PR.
</objective>

## What to read (executor)

**The plan runs in two executor runs** (Budget). Run A does Tasks 1 and 2 and ends with Task 2's committed SUMMARY draft. Run B is a fresh executor and does Tasks 3, 4 and 5.

**Run A, before Task 1.** Read:
- the frontmatter and the objective;
- the owner answers to O-1 to O-3 under Owner decisions;
- the Planner decisions and the Budget;
- the Phase Goal;
- the `<context>` block up to "## Reconciliation": the Delivery protocol, what this plan builds on, and the defects;
- Tasks 1 and 2;
- the Cross-plan notes.

Tasks 3 to 5 can wait for Run B.

**Run B, resuming at Task 3 (fresh executor).**
1. Check that you are resuming in the right place:
   - the checkout is on branch `p03/08f-agent-policy-in-force`;
   - `git status --porcelain -- internal/ docs/` prints nothing;
   - `git log -1 --format=%s` prints `docs(03-08f): record F02's evidence`;
   - `.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md` has a section `## Handoff to Task 3`;
   - this plan file still lies untracked in the phase directory.

   If any of these fails, stop and report: Run A did not finish.
2. Read:
   - the frontmatter and the owner answers;
   - the Planner decisions and the Budget's test-time rules;
   - the Delivery protocol in `<context>`;
   - Tasks 3 to 5 and the Cross-plan notes.
3. Read the SUMMARY draft's `## Handoff to Task 3`. It gives the alone base that Task 3's stop rule needs, Task 2's head commit (where Task 3 takes its REDs), the test helpers to reuse, and the changed tests.
4. Read the code Task 3's read_first names. Nothing from Run A is in context.

Skip these until you write the SUMMARY, because they record history or restate the rules:
- the "Revision 2026-11-02", "Revision 2026-11-03" and "Revision 2026-11-03, after plan check 3" notes;
- the owner decisions above "Owner answers to O-1 to O-3" (the truths and the Planner decisions restate them);
- Reconciliation, except where a task or an owner answer points to it;
- Edge Coverage, the source-coverage table and the Artifacts list;
- the threat sections (Trust Boundaries and the STRIDE register);
- the Review Dispositions Ledger.

## Revision 2026-11-02 (after 03-08k merged)

The plan was written on 2026-10-29 against main at 18a30c9 and has now been reconciled against main at 682782e. That main holds 03-08e (PR #77), 03-08j (PR #78), merge-gate.sh's wait for the owner's merge (PR #79) and 03-08k (PR #80, with its two pre-merge fix rounds). Changes:
- **Anchors.**
  - verify is now `verify(p, chain, alone, in, carried, pending)` (03-08j, 03-08k), and verifyDirectory receives chain: the chain base, which is the unapplied record's base on the record path.
  - KRLAlone takes a final `from`, and krlStep is the KRL step.
  - forward returns through `outcome` (03-08k).
  - A poll verifies through pollCapture's three branches (VerifyAfter, VerifyAheadAfter, and KRLAlone with the capture as from).
  - state/verify.go is 32 KB, not 19 KB. installed.go is 4 KB.
  - The read_first grep for forward's returns now finds them.
  - The runbook anchors are given by text, not line.
  - Task 1's precondition checks 03-08k's SUMMARY, `func (v *Verified) krlStep(` and the other names this plan builds on, and checks that F02 and F03 are still unfixed.
- **Shapes main changed underneath the plan.**
  - **pruneSpool** (03-08e fix rounds 1-3) did not exist when the plan was written. Its spoolSet does not recognise `bundle-<N>.policy.sigs`, so the file would never be pruned. Task 2 adds it, with `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle`. The computed spool bound grows (owner question O-3).
  - **WriteAccepted** raises accepted.json's bundle and directory to the unapplied record's versions (03-08j). Task 1's helper overrides that raise for the directory while the host is unauthorized (owner question O-2), and Task 3 adds `unauthorized_with_a_recorded_directory`. (Superseded by the owner's answer (c); see "Revision 2026-11-03".)
  - **forward** returns its state through outcome, which joins Refused and KRLRefused (03-08k). The unauthorized error joins it there. Main's sameBytes branch commits, which stages an accepted/ snapshot, so Task 3's forced render tests for a no-op before that branch.
  - **status.go's refusals** gained krl_signer_retired in 03-08k. directory_not_authorized and directory_fork join the list, so last_apply.result reads refused (a planner decision). TestStatus/apply_result gains two rows.
  - **engine.render** fills the host name only on its fallback path. Task 1 adds the fill for the trust-only render.
  - **checkStored's directory.** In verify, checkStored checks the directory the capture chains from, which is the record's directory part when the record holds one. storedOnly checks accepted/'s, or the pending target's.
  - **TestApply/torn_accepted_save_never_mixes** (main) rotates the policy to admin bob alone over directory 1, which the fixture's admin signed. It expects the next run to succeed, but under F03 that run returns directory_not_authorized. Task 1 keeps the fixture's admins in its rotation, runs the whole package, and names every other test the change flips.
- **Interactions with 03-08k.** These are Reconciliation I-1 to I-3; none needs a design change. T-03-302's note is updated, and one host-setup.md sentence is added.
- **Delivery.**
  - Every branch commit has Daniel as author, with keyroster-bot as committer, signer and pusher.
  - The PR is opened without auto-merge, and Daniel squash-merges it himself.
  - merge-gate.sh runs only as `--check` before the merge, and in its plain form only after it. A rebase is made by hand.
  - Task 5 is rewritten after 03-08k's Task 5, and Task 4 gains 03-08k's authorship, auto-merge and publish checks.
  - Each code task commits its code and tests, runs its mutants against that commit, and commits the SUMMARY draft, as 03-08k's Budget says.
- **Test time.**
  - 03-08k's two limits apply: 400 s for internal/agent/apply alone, 480 s under `./...`.
  - Both are measured before any edit, with the stop rule.
  - Every -run filter is anchored per level.
- **The gofmt gate.** Task 4's precondition requires one of two things:
  - `--exec` in scripts/linux.sh (branch chore/linux-sh-wsl-exec);
  - or gofmt run from a script file in WSL's login shell, in a way that shows gofmt ran.
- **Open owner questions** O-1 to O-3 must be answered before execution (Owner decisions; the full text is under Reconciliation). They were answered on 2026-11-03; see the next note.
- **Estimate.** It rises from 92k to about 185k tokens (Budget). Most of the rise is this plan's own length, the reads 03-08j and 03-08k added, and 03-08k's per-task test-time runs and mutant loops.

## Revision 2026-11-03 (owner answers to O-1 to O-3)

Daniel answered the three questions on 2026-11-03. He did not veto the planner's additions to the must-haves: last_apply.result refused, an idle unauthorized run commits nothing, pruneSpool in Truth 7, the changed torn_accepted_save_never_mixes, and the fork rule at the record's version. Changes:
- **O-1: (a), accept the residual.**
  - Truth 2 now promises healing only on a run that ends without a Verify or KRL-alone error.
  - The residual is the new accepted threat T-03-323, and T-03-300's residual (5) moves there.
  - enroll-user.md's sentence about it is labelled UNVERIFIED.
- **O-2: (c), directory 0 only while the chain base's directory is unauthorized; otherwise the record's raise wins.**
  - state gains `(s *Stored) DirectoryUnderPolicy() error`, and Task 1 makes WriteAccepted apply the rule. It no longer depends on the report.
  - Truth 3, the artifacts and the key links say so.
  - Report.DirectoryUnauthorized stays as the report's field.
  - Task 3's `unauthorized_with_a_recorded_directory` is replaced by two cases, each with its mutants:
    - `recorded_authorized_directory_keeps_the_record_raise`: the stall shape, which no longer stalls;
    - `recorded_bundle_over_unauthorized_directory_reports_directory_0`: the chain base is unauthorized, so directory 0 is written, and the new admins' same-number directory recovers the host.
  - The runbook notes now tie accepted.json's 0 to the chain base, not to last_apply.
- **O-3: (a), accept the bound** of about 6.1 GiB kept and 6.6 GiB in all, as Task 2, host-setup.md and T-03-305 already state it.
- **Bookkeeping.**
  - Each question's marker reads `(answered 2026-11-03)`, so Task 1's precondition counts 3.
  - Task 3 has 11 cases, and the plan adds 23 cases to internal/agent/apply.
  - The estimate is about 195k, mostly because of the plan's own growth.
  - Ledger Round 3 is added.

## Revision 2026-11-03, after plan check 3 (PASS WITH FIXES, against main b1ebff3)

**Main** is now b1ebff3. It adds only PR #81 on top of 682782e: scripts/linux.sh passes the command to WSL with `--exec`, plus one STATE.md row and the quick-task's files. Every anchor holds there.
- The publish values are unchanged: 17/25 plans in 24 waves, total_plans 60, `Plan: 18 of 25`, 03-09 at wave 17 with `depends_on: ["03-08k"]`, and 03-10 to 03-16 at waves 18 to 24.
- Task 4's `--exec` precondition now passes on main, and is described as present.

**Changes:**
- **M-1. `rotation_first_then_removed_admin_refused` is re-expected for the code after this plan, with its RED on origin/main.** Directory 1 is alice's, so applying bundle 2 (bob alone) already makes the host unauthorized. The case now pins that the removed admin cannot get back in by signing the next version while the host is fail-closed: the refusal joins the unauthorized state, and nothing of alice's renders.
  - Co-signing directory 1 by alice and bob was rejected. Bob is no admin under policy 1, so that shape is one the tooling never produces, and the case would only repeat `admin_set_unchanged_rotation_keeps_directory`.
- **M-2. Task 3's step b saves and restores the bundle part.** Before today's logic runs, it saves v.Bundle, v.Policy, v.BundleHeld, v.BundleChanged and Next's bundle part. It restores them when it converts a refusal, so a hold that the refused directory set up is undone and the newest verified bundle step is kept.
  - New case `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle`, with the mutant "no restore".
  - The converted refusals are now listed in full: directory_older, directory_chain_gap, directory_not_verified for every cause (quorum, chain, parse, version, CheckPolicy) and directory_installation. An unparseable stored directory (stored_state_invalid) stays an error. The reasons are under Planner decisions, and Truth 2 says so.
- **m-1. The mixed record {3, 65}.** `TestSpoolWindow/held_content_refusal_keeps_the_records_bundle` gains a readAccepted assertion (bundle 3, directory 0) in Task 1. T-03-300 residual (4) and host-setup.md's record note name the shape. The owner's O-2 (c) rule is unchanged.
- **m-2.** The mutant "the bundle signatures added to the union" is marked equivalent. CountPinnedSigners verifies every block over the policy bytes under the policy namespace and skips one that does not verify, so a bundle signature block never counts. It is still run, and must survive.
- **m-3.** The Report.DirectoryUnauthorized mutant removes the assignment from v after Verify. After Task 3, an unauthorized idle run returns through the forced no-op and takes the flag from there, so the tracer's second apply kills it on Task 3's commit.
- **m-5.** Task 1's WriteAccepted bullet gains the crash sentence.
- **The budget warning: two executor runs.**
  - Run A does Tasks 1 and 2. Task 2's SUMMARY draft ends with a `## Handoff to Task 3` section, and Task 2 checks that it is there.
  - Run B is a fresh executor for Tasks 3 to 5, with a resume entry under "What to read" and a full read list in Task 3.
  - The estimate is now per run: about 115k for Run A and 150k for Run B, about 265k in all. Run B rereads code that a single run would have kept in context.
- **Counts.** Task 3 has 12 cases. The plan adds 24 cases to internal/agent/apply (TestDirectoryUnderPolicyInForce 13, TestRootRotationUnchangedPolicy 11) and one assertion to an existing TestSpoolWindow case. There are 22 mutant runs, one of them equivalent.

## Owner decisions (recorded, do not ask again)

- **Q-split (Daniel, 2026-10-29).** The agent fix group is three plans:
  - 03-08d: F07 and F08 (wave 13).
  - 03-08e: F01 and F09 (wave 14).
  - 03-08f, this plan: F02 and F03 (wave 17, depends on 03-08k, branch `p03/08f-agent-policy-in-force`).
  - Since 2026-11-01 the order is 03-08e (14) → 03-08j (15) → 03-08k (16) → 03-08f, this plan (17) → 03-08g (18) → 03-08h (19). This follows the owner decisions on the 03-08j/03-08k split (2026-11-01) and of 2026-11-02, which keep 03-08j directly before 03-08k. 03-08e, 03-08j and 03-08k are merged.
  - 03-09 to 03-16 move one wave later per plan; this plan's publish edits make one such move.
  - The signer-capacity plan is 03-08g, and nothing here depends on it.
- **Grades (2026-10-29).** F02 is medium and F03 is medium.
- **Scope (2026-10-29).** This plan is the agent's half of F03. Recovering the directory on the signer and the CLI after an admin-set change stays with todo 2026-10-21-recover-directory-after-admin-set-change (Phase 4), and Task 3 records this in that todo.
- **Q-F03a (Daniel, 2026-10-29): keep the fail-closed window.** While the policy in force does not authorize a host's directory, the host renders no principals, as the signer refuses issuance (T-02-15). The runbook says to install the new admins' directory right after the bundle.
- **Q-F03b (Daniel, 2026-10-29): recovery at the same version or higher only.** A host recovers only from a directory the new admins signed at or above its stored version. A host whose stored version is above anything the new admins signed needs an explicit `keyroster-agent reset-directory`. The todo's Status line notes the Phase 4 variant: the new admins sign their first directory above the old admins' highest version, through the re-sign path.
- **Delivery (2026-10-29).**
  - The plan lands in the same PR as its fix.
  - The wording is neutral hardening, and findings are named only by F-number.
  - Pushing the branch and opening the PR before the merge is allowed (Daniel, 2026-10-29).
- **Authorship and merge (Daniel, 2026-11-02, given for 03-08k; in 01-SKELETON.md since PR #79).**
  - Branch commits are authored as Daniel (`GIT_AUTHOR_NAME="Daniel Gustafsson"`, `GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com`), with keyroster-bot as committer, signer and pusher.
  - The PR is opened by the bot without auto-merge. Daniel approves and squash-merges it himself and replies "merged".
  - merge-gate.sh runs only with `--check` before the merge, and in its plain form only after Daniel has merged. A rebase is made by hand.
- **Test-time limits (Daniel, 2026-11-02, given for 03-08k).**
  - 400 s for internal/agent/apply run alone under -race.
  - 480 s for the package's line under `./...`, the margin against go test's 600 s per-binary timeout.
  - If a base figure is already above a limit, the executor stops before any edit and reports. The options are to raise CI's test -timeout or to move the slow cases into their own package, and the owner chooses.
- **D-R2 (PR #71 review F5), existing.** A refused step never holds back the KRL. The fork rule and the unauthorized state both keep the KRL flowing.

**Owner answers to O-1 to O-3 (asked 2026-11-02, answered by Daniel 2026-11-03).** Each question is written out under Reconciliation item 7, and the task text follows these answers. Task 1's precondition counts the answered markers.
- **O-1 (answered 2026-11-03): (a).** A host that already holds the bad state, when its first run's verification fails. Accept it as a residual: Truth 2 promises healing only on a run that ends without a Verify or KRL-alone error. The residual is the accepted threat T-03-323, and enroll-user.md names it as UNVERIFIED. No code change.
- **O-2 (answered 2026-11-03): (c).** accepted.json's directory 0 against 03-08j's record raise. WriteAccepted writes directory 0 only while the directory the next capture chains from is unauthorized under its chain base's policy; otherwise the record's raise wins (Task 1, Task 3's two record cases, Truth 3). This was the planner's recommendation.
- **O-3 (answered 2026-11-03): (a).** The spool's computed bound grows by one spool.MaxBundle file per kept bundle. Accept the new bound, about 6.1 GiB kept and 6.6 GiB in all (Task 2, host-setup.md, T-03-305).
- **The planner's must-have additions** were not vetoed (2026-11-03): last_apply.result refused, an idle unauthorized run commits nothing, pruneSpool in Truth 7, the changed torn_accepted_save_never_mixes, and the fork rule at the record's version.

**Planner decisions, Claude's discretion, recorded with their reasons:**
- *Derive the flag on every run, and keep the stored directory.* It is never set to nil, which would hand the host to 03-08d's no-directory fallback, and that fallback keeps last-good's principals.
- *accepted.json reports directory 0 while the chain base's directory is unauthorized (owner decision O-2 (c)).* The fetcher then asks from 0, and the server's answer for 0 is its current directory, even at the same number: internal/server's directoryItems answers since 0 with the current directory only. No server change is needed. The rule reads the chain base, not the run's report, because the cursor must follow what the next capture chains from. A recorded directory the policy authorises keeps the record's raise, so the fetcher keeps fetching the versions after it. A KRL-alone pass over an unauthorized accepted/ does not change that.
- *Union only on ErrThreshold, and only from admitted sources.* sshsig.ParseAll rejects a whole file on one malformed block.
- *Per-bundle policy signature file rather than merging blocks.* It holds exactly "the policy signatures delivered with that bundle", and it is bounded per file and removed with its bundle, by dropAbove and pruneSpool.
- *The hold path stays.* Refusing it would change PR #67's catch-up across a policy rotation.
- *The two new codes are refusals in last_apply (status.go's refusals).* last_apply.result is `refused` for a refusal by design: the signed state refused, nothing of it applied. 03-08k added krl_signer_retired to the same list. Without these entries, directory_not_authorized alone would read `error`.
- *outcome carries the unauthorized error.* Every return of forward that names the state in force goes through outcome since 03-08k. Joining the error there covers the no-change path, the dry run, the byte-equal commit, the first install and the final commit at once.
- *The forced render tests for a no-op before the byte-equal commit.* Main's sameBytes branch commits, which stages an accepted/ snapshot. An unchanged unauthorized capture on the idle run every 60 s must commit nothing.
- *While unauthorized, every refusal of an offered directory is converted (plan check 3, M-2).* That covers directory_older, directory_chain_gap, directory_installation and directory_not_verified for every cause: a missing quorum, a broken chain, a document that does not parse, a version that does not match its name, or CheckPolicy. The reasons:
  - It fails closed. While the stored directory is unauthorized, the host renders no principals whatever the offered directory's fault, so no conversion can widen access. A refused directory is never taken: v.Directory stays the stored one, which renders nothing.
  - It matches Truth 2 and the owner's decisions. Q-F03a's window ends only with a directory the new admins signed. Refusing the whole capture instead would hold back the verified bundle step, that is the newer roots, CA keys and KRL authority, because of a directory the host would not render anyway. Every cause is a fault of that directory, not of the bundle chain.
  - The error still names the refusal, joined with directory_not_authorized, so last_apply shows why the new directory was not taken.
  - Not converted: an accepted directory that does not parse (stored_state_invalid). That is the host's own state, and it stays a hard error as on main.
- *The conversion restores the bundle part (plan check 3, M-2).* verifyDirectory's hold loop calls holdBundle before it parses, version-checks, CheckInstallation-checks, CheckPolicy-checks and chain-checks the directory. A refusal after the hold would otherwise leave the capture held at an older bundle. That bundle is often 03-08j's in-force step, and krlStep would then run under the held rules. Step b therefore saves v.Bundle, v.Policy, v.BundleHeld, v.BundleChanged and Next's bundle part before today's logic runs, and restores them when it converts. A hold whose directory is accepted stays (PR #67).

No `checkpoint:decision` precedes Task 1.

## Budget

- **Files.** There are 15 code and test files, four runbooks and the todo.
  - Two files are new: internal/agent/apply/policy_change_test.go and this plan's SUMMARY.
  - Five files get small edits:
    - apply_test.go: one rotation's admins in torn_accepted_save_never_mixes;
    - window_test.go: one readAccepted assertion in held_content_refusal_keeps_the_records_bundle;
    - status.go: two refusals entries;
    - status_test.go: two rows;
    - prune_test.go: one case.
  - The publish edits add the plan, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16.
- **Two executor runs (plan check 3).** One run of the whole plan would come close to one executor window, so execution is split.
  - **Run A** does Tasks 1 and 2. It ends when Task 2's SUMMARY draft is committed with its `## Handoff to Task 3` section (Task 2's acceptance criteria).
  - **Run B** is a fresh executor. It resumes at Task 3 as "What to read" says, and does Tasks 3, 4 and 5.
  - Nothing crosses from Run A to Run B but the branch, its commits, the untracked plan file and the SUMMARY draft. Each task's evidence is committed before the next starts, so a reset inside a run loses nothing either.
- **Estimate per run**, counted as 03-08k counts (about 2.5 bytes per token for the plan, about 3.4 for code):
  - **Run A: about 115k.**
    - about 31k to read the plan parts "What to read" gives Run A (about 78 KB of a 176 KB plan);
    - about 30k of code read (about 100 KB: state/verify.go whole, 32 KB, and function-scoped reads of state, apply, render, installed, status, trust, spool, fetch and the tests);
    - about 24k written;
    - about 28k of test and mutant output: the base runs, two package runs per task, and Task 2's seven mutants.
  - **Run B: about 150k.**
    - about 39k to read the plan parts "What to read" gives Run B (about 86 KB) and the SUMMARY draft (about 15 KB);
    - about 10k of the history parts (about 50 KB in all), which the final SUMMARY draws on;
    - about 36k of code and runbooks read (about 120 KB). Task 3's read_first rereads what Run A had in context;
    - about 26k written;
    - about 40k of test, gate and mutant output: Task 3's two package runs and 15 mutants, Task 4's alone and full gates, and CI.
  - **In all, about 265k.** That is above a single run's earlier 195k, because Run B rereads the code and both runs read the plan's common parts, and because plan check 3 grew the plan to 176 KB. Each run stays well under one executor window.
- **Test time: two limits under -race (owner, 2026-11-02, as for 03-08k).**
  - **The budget, 400 s**, is internal/agent/apply run alone. It is measured and gated with this command, which prints the output and fails when the package's `ok` line is missing or above 400 s:

    `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'`
  - **The margin, 480 s**, is the package's `ok` line under `go test -race -count=1 ./...`, where every package runs at once. That is the mode Task 4's gate and CI run, with headroom under go test's default 600 s per-binary timeout. It is gated the same way, with `./...` in place of the package path and 480 in place of 400.
  - **What the figures say.**
    - At 03-08k the package's local alone figure ranged from 274.1 s to 355.5 s on near-identical code, and under `./...` from 286.7 s to 346.8 s. The highest alone figure was its base, on unchanged code. All were measured on one WSL machine under varying load.
    - CI's build-test recorded 126.1 s on origin/main 6572649 and 164.8 s on PR #80 at c47f535 (03-08k-SUMMARY). The owner reports 195 to 215 s on PR #80's later CI runs.
    - So the alone margin can be as small as about 45 s.
    - This plan adds 24 cases to internal/agent/apply: TestDirectoryUnderPolicyInForce has 13 and TestRootRotationUnchangedPolicy has 11.
    - Every one calls t.Parallel, and none builds a window of 64 versions. The largest shapes are three bundle hops and a stored directory at version 5.
  - **Task 1, before any edit**, measures the package on the branch, which is still origin/main, in both modes.
    - It records both figures, and CI's latest build-test time for the package on origin/main, with the command used. When `run view --log` refuses, read the job log with `scripts/gh-as-bot.sh api repos/Labontese/keyroster/actions/jobs/<job id>/logs`, as 03-08k did.
    - **If the alone base is above 400 s, or the `./...` base or CI's time is above 480 s, the executor stops before any edit and reports to the owner.** The options to put are raising CI's test -timeout or moving the slow cases into their own package. The executor does not choose.
  - **Tasks 1, 2 and 3** each run both modes on their finished code and tests, before the code commit. Task 3 runs in Run B and takes the alone base from the SUMMARY draft's handoff section:
    - the alone run stops the task above the alone base + 120 s or above 400 s, whichever comes first;
    - the `./...` run stops it above 480 s.

    A stopped task does not commit. It thins its slowest new cases, such as TestRootRotationUnchangedPolicy's three-hop shape or the reset case's stored directory 5. If thinning cannot bring the time under, the task stops and reports with the same two options.
  - The task verifies anchor every -run filter per level (`^Name$/^(...)$`), so TestKRLAlone's 4096-file cases and TestApply's 70-odd other cases never run there.
  - **Task 4** runs the alone gate before the full gate, and the full gate checks the margin.
  - **CI's time for the package is a pre-merge check.** CI runs `./...`, so its limit is the 480 s margin. Task 4 records it from the PR's build-test log beside the local figures. Above 480 s, the executor stops before the merge gate and reports with the same two options.
- **Task size.** Three code tasks, the publish task and the merge gate:
  - Task 1 has one new case, one changed test and one added assertion.
  - Task 2 has 19: eleven TestRootRotationUnchangedPolicy cases, three TestSpool, four TestFetch and one TestSpoolPrune.
  - Task 3 has 12 cases, the runbook notes and the todo.

  A code task that grows past about 20 cases while it is written is split at its last group of cases into one more task of this plan, with its own commit.
- **Commits.** Every task ends with a commit by path, authored as the Delivery protocol says. A code task does three things in order:
  1. it commits its code and tests;
  2. it runs its mutants against that commit;
  3. it commits the SUMMARY draft with its RED evidence, mutant results and the two test-time figures.

  A context reset therefore loses no evidence.
- **Mutants** run as one scripted loop per task:
  - each mutant is a patch kept outside the repository;
  - the loop applies it with git apply and runs its named test with an anchored -run filter;
  - it records killed or survived, with the test's last lines;
  - it restores the file with git checkout and requires git diff --quiet before the next mutant.

  The loop's output goes into the SUMMARY draft.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

In 03-08k-SUMMARY.md, read these sections:
- Task 1's Notes: verify raises the fully verified bundle right after the bundle step returns nil, before the directory step.
- "A poll decides a KRL as forward does".
- "Pre-merge review fix round 1", "D-1: the fix": verify's pending parameter.
- "Test time".

In 03-08j-SUMMARY.md, read the fix-round sections on pollCapture and on the record's base.

Delivery protocol: 01-SKELETON.md, with phase 03 names. Since PR #79, its steps 2, 3 and 5 carry the owner's authorship and merge rules of 2026-11-02. The points below restate them. The one override is merge-gate.sh's plain form.
- **Branch.** Create `p03/08f-agent-policy-in-force` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 4 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Authorship (01-SKELETON step 2).**
  - Every `git commit` of this plan is authored as Daniel, with keyroster-bot as committer, SSH signer and pusher. Put the two variables on the same command line as the commit, because shell state does not persist between commands: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit ...`.
  - The repository's own git identity (keyroster-bot) stays the committer.
  - Task 4 checks every branch commit with `git log origin/main..HEAD --format='%an <%ae> %cn'`.
- **No auto-merge (01-SKELETON steps 3 and 5).**
  - The bot opens the PR through scripts/gh-as-bot.sh, and never enables auto-merge or waits for it.
  - Daniel reviews, approves and squash-merges the PR in the GitHub web UI, and replies "merged".
- **merge-gate.sh. This overrides 01-SKELETON step 5's plain run at the gate.** Before the merge, merge-gate.sh runs only as `--check`, which is read-only. Its plain form may rebase and force-push the branch itself (exit 3), and this plan rebases by hand. So the plain form runs only after Daniel has merged (Task 5).
- **Commits and PR text.** Conventional Commits with neutral hardening wording, and findings named by F-number only. No attribution lines, no IP addresses and no real host names.
- **Code comments** cite `F02 (03-08f)` or `F03 (03-08f)`.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md`, a draft from Task 1 on. The final docs commit is `docs(03-08f): complete agent policy-in-force plan`.

**What this plan builds on** (all on main at 682782e):
- **From 03-08d:**
  - state.KRLAlone and storedOnly;
  - the KRL-alone pass krlAlone, which forward and pollSpool call;
  - RenderFallback without a directory;
  - outcome's errNoDirectory.
- **From 03-08e:**
  - spool.Cap, the fetcher's checkCaps (which names every file exactly as writeState writes it) and healSpool;
  - pruneSpool (fix rounds 1-3). It keeps the spool by the versions in outbox/accepted.json: the newest version at or below them and keepAbove (1024) versions above, or the newest 64 without a version;
  - spool.Read's floor and its one recapture.
- **From 03-08j:**
  - verify's split: chain is the base the bundle, directory and KRL steps run against, and alone is the accepted state of the KRL-alone pass;
  - the unapplied record: Unapplied, and Base, which takes a bundle part and a directory part above accepted's, never a KRL;
  - VerifyAhead;
  - recordUnapplied in forward's content-refusal branch;
  - verify's in-force hold step: the bundle in force first in v.steps when chain's bundle is above alone's;
  - pollCapture;
  - WriteAccepted's raise of accepted.json to the record's versions.
- **From 03-08k:**
  - KRLAlone's from parameter;
  - krlStep: the authorisers P, S and F, the retired-key refusal, and Verified.KRLRefused under a held step;
  - Verified.fullyVerified, raised in verify right after the bundle step returns nil;
  - VerifyAfter and VerifyAheadAfter with the pending parameter (fix round 1);
  - outcome joining Refused and KRLRefused;
  - krl_signer_retired in status.go's refusals;
  - TestKRLSigner.
- This plan adds:
  - `bundle-<N>.policy.sigs` to 03-08e's spool and fetcher functions, pruneSpool included;
  - the unauthorized flag to verifyDirectory and storedOnly;
  - DirectoryUnauthorized to outcome.

The defects this plan fixes, read on main at 682782e. 03-08e, 03-08j and 03-08k leave these functions unchanged, except that verifyDirectory now receives verify's chain.

**F03.**
- verifyDirectory runs VerifySignatures and CheckPolicy only on a newer offered directory. It returns nil when no directory is offered, or when the newest offered equals the stored version (`case stored != nil && newest == storedVersion`). It does so even after verifyBundle has just moved v.Policy to a root-signed successor that removed an admin.
- The hold path accepts a directory under an earlier policy of the chain, 03-08j's in-force hold step included. Nothing checks that directory again once the bundle has moved on.
- A host that took a removed admin's directory before the rotation therefore keeps rendering its principals while reporting the current bundle.
- It also ignores the new admins' directory at the same version: the server never offers a version at or below the host's accepted one. It refuses the new admins' next version as a broken chain.
- The signer treats the same state as unauthorized and refuses logins (T-02-15, loadDirectory: VerifySignatures, then CheckPolicy, under the policy in force).

**F02.**
- verifyBundle calls findPolicy with `Stored{Policy: curPolicy, PolicySigs: v.Next.PolicySigs}`. At the first step, those are the chain base's policy signatures: accepted/'s from the previous acceptance, the unapplied record's, or the pending target's. When the successor names the unchanged policy, findPolicy returns that stored document before it looks at the spool's re-signed copy.
- trust.VerifySuccessor needs the new roots' threshold on the policy signatures. So a rotation to new roots, or a raised threshold, with the policy carried over is refused on every capture. That is root-ceremony.md's "Rotate the roots" with `--policy prev/policy.json`.
- The host keeps the retired roots as its anchor, skips a directory offered in the same capture, and accepts a successor fork signed only by a retired root.
- The spool keeps one `policy-<v>.json.sigs` per policy version and replaces it. In a capture with several unchanged-policy rotations, only the last bundle's policy signatures survive.

**Check 1, answered: 03-12 and 03-13.** This plan is **not** a hard prerequisite for 03-12 or 03-13; they run after it anyway.
- 03-12 builds CA successors (`root sign --prev --ca-next/--ca-switch/--ca-drop`). 03-13 builds log-key, ops-key and emergency successors (`--log-rotate/--ops-rotate/--ca-emergency`).
- All of them keep the previous root set and its threshold, and carry the policy over unchanged. So they take findPolicy's stored-first branch, but the stored policy signatures come from the same roots and meet both unchanged thresholds, and hosts accept them today.
- The case that fails is a successor that keeps the policy and changes the root set or raises the threshold.
- 03-15's v4 ceremony changes the policy (pop) together with the roots, so it takes the changed-policy branch, and the homelab's hosts enroll after it, through verifyPinned.

## Reconciliation (2026-11-02, against main at 682782e)

1. **Source.**
   - The plan was written on 2026-10-29 against main at 18a30c9, and passed plan checks 1 and 2.
   - Its wave and dependency moved with the 03-08j/03-08k split (2026-11-01 and 2026-11-02).
   - It is now reconciled against 682782e, which holds 03-08e (PR #77), 03-08j (PR #78), PR #79 and 03-08k (PR #80).
   - The notes for this plan from that split are applied: Q-split's list, Task 1's precondition, 03-09's clause list and the bracketed publish values.
2. **Each must-have on 682782e.** None is dropped.
   - **Truth 1 (order):** holds. 03-08e, 03-08j and 03-08k are merged, and this plan is wave 17.
   - **Truth 2 (the check):** no merged plan covers it. verifyDirectory still returns nil for no offered directory or for the stored version, and storedOnly checks nothing. It is re-anchored to verify's chain (the record's directory part on the record path) and to storedOnly's prev. Narrowed by owner decision O-1 (a) to runs that end without a Verify or KRL-alone error.
   - **Truth 3 (the render while unauthorized):** not covered. It is re-anchored to:
     - outcome (03-08k);
     - the sameBytes commit;
     - engine.render's host fill;
     - status.go's refusals;
     - WriteAccepted's record raise, which wins while the chain base's directory is authorized (O-2 (c)).
   - **Truth 4 (recovery and the fork rule):** not covered.
     - The fork rule now also applies at the record's version, because the record is the chain base.
     - 03-08j's `spool_copy_of_the_recorded_version_ignored` stays green, because its newest offered version (66) is above the record's (65).
     - pollCapture's doc sentence "a spool copy at the record's version adds no step" gains a clause (Task 3).
   - **Truth 5 (the union):** not covered. verifyBundle still calls findPolicy stored-first and VerifySuccessor once. Interaction I-1.
   - **Truth 6 (why the union cannot widen trust):** internal/trust is unchanged, and the argument holds as written. It now also covers unapplied.json.
   - **Truth 7 (the spool):** stale where it named the fetcher's functions. pruneSpool is added, with the higher bound (O-3 (a)).
   - **Artifacts and key links:** unchanged, plus status.go, fetch.go's prune and outcome.
   - **The prohibition:** unchanged. No merged plan touches a root threshold.
3. **03-08k and this plan.** Nothing in 03-08k covers F02 or F03, and nothing in it contradicts a must-have here. Where they meet:
   - **I-1. A rotation the union verifies raises the fully verified bundle.**
     - Today a root rotation that keeps the policy is refused at the bundle step. The KRL-alone pass then verifies the KRL under the bundle in force, and a KRL the in-force ops key signs lands alone.
     - After F02 the rotation verifies in full, and verify raises fullyVerified to it (03-08k).
     - When such a rotation also names a new ops key, a KRL only the old key signs is krl_signer_retired. The host then waits for the new key's KRL, at most about an hour with an honest server, and the bundle waits with it.
     - That is 03-08k's retired-key rule (owner, 2026-11-01 and 2026-11-02), applied as written. No change is proposed.
     - The documented root rotation carries the CA, ops and log keys over unchanged (root-ceremony.md, "Rotate the roots", its rule), and 03-13's `--ops-rotate` keeps the roots. So no shipped ceremony produces this shape.
   - **I-2. While unauthorized, a refused directory step no longer goes to the KRL-alone pass.**
     - Task 3's step b turns directory_older, a broken chain or a missing quorum into the unauthorized state, so verify goes on to krlStep. The KRL is then checked under P (the bundle the capture puts in force), then S, then F, with the retired-key rule. Without a held step, a refusal there is a Verify error (03-08k).
     - On main, and under 03-08k's Q2, such a capture took its KRL alone, verified under the bundle in force or the fully verified successor.
     - In both, the revocation lands when a current authorised key signed it. The difference is that the verified bundle is now installed with no principals (owner decision Q-F03a). It is the newest verified bundle step: a hold the refused directory set up is undone, so krlStep runs without BundleHeld (plan check 3, M-2).
     - host-setup.md's 03-08k paragraph on successor-signed KRLs gains one sentence for this shape (Task 3).
   - **I-3. T-03-302's note.** The note said that a fork or not_verified refusal discards a bundle successor offered in the same capture, and that D-R2 then takes only the KRL. Since 03-08k, that KRL-alone pass also verifies the KRL under the capture's fully verified successor (Q2), so a successor-signed KRL still lands. The note is updated.
   - **O-1** (below) is the one place where 03-08k's behaviour narrows a truth of this plan. The owner accepted the narrowing as a residual (T-03-323).
   - TestKRLSigner (33 cases, with the five wait cases' poll and forward subtests) stays green. 03-08k's Cross-plan notes require that of a plan that edits KRLAlone, and this plan changes storedOnly, which KRLAlone calls, and verify's directory step. Tasks 1 and 3 run it, and the Budget's package runs cover the rest.
4. **Shapes from 03-08e and 03-08j.**
   - pruneSpool: Task 2, O-3 (a).
   - WriteAccepted's record raise: Task 1, Task 3, O-2 (c).
   - forward's record path and pollCapture's record branch verify against the base, so checkStored checks the record's directory part when there is one.
   - TestApply/torn_accepted_save_never_mixes flips: Task 1.
   - The runbook text that 03-08e, 03-08j and 03-08k added to host-setup.md and signer-install.md: Task 3's notes are written against it.
5. **Publish values on main 682782e, unchanged on b1ebff3 (plan check 3).**
   - The ROADMAP's Phase 3 Plans line reads 17/25 plans in 24 waves.
   - STATE.md reads total_plans 60 and `Plan: 18 of 25`.
   - 03-09 has `wave: 17` and `depends_on: ["03-08k"]`. Its Task 1 precondition has the 03-08, 03-08c, 03-08d, 03-08e, 03-08j and 03-08k clauses.
   - 03-10 to 03-16 have waves 18 to 24.

   These match the bracketed values in Task 4. Task 4 still computes every number from origin/main.
6. **Threat IDs.** T-03-300 to T-03-305 stay this plan's: no plan on main uses them, and main's highest is T-03-321. One is added: T-03-323, O-1's accepted residual. This phase's plans not yet on main use IDs up to T-03-322, so 323 is the first free one. The spool bound joins T-03-305.
7. **Owner questions (asked 2026-11-02; answered by Daniel 2026-11-03: O-1 (a), O-2 (c), O-3 (a)).** The options are kept as asked.
   - **O-1. A host that already holds the bad state, when its first run's verification fails.**
     - **The problem.** Truth 2 says the flag is derived on every run, so a host that holds the bad state heals on its first run of this code. The bad state is accepted/ holding a bundle whose policy no longer authorises the stored directory, while current still renders that directory's principals.
     - The heal holds only for a run whose verification returns a Verified. Two kinds of error install nothing, as on main, so current keeps those principals for that run:
       - a Verify error: krl_not_verified, krl_older, krl_header_version_mismatch, or 03-08k's krl_signer_retired on the KRL step without a held step;
       - a KRL-alone error: a KRL no known key verifies, or 03-08k's retired-key refusal in KRLAlone.
     - A spool writer that keeps such a KRL newest keeps the host in that state.
     - After this plan the state can arise only from code before it: every commit of an unauthorized state installs the trust-only generation.
     - Phase 3 changes no admin set and rotates no roots on an enrolled host, so no real host holds the state today.
     - **(a)** Accept it as a residual. The truth reads "heals on its first run whose verification returns a state", T-03-300 names the residual, and enroll-user.md says so. No code change.
     - **(b)** Extend the scope. On such an error, when accepted/'s directory is unauthorized under accepted/'s policy, forward still renders storedOnly(accepted/)'s trust-only generation and returns both errors.
       - That generation holds nothing of the capture: the bundle, KRL and directory are the ones in force. So 03-08k's rule that nothing of a refused capture is installed still holds.
       - It adds about one case and one mutant to Task 3.
     - **Planner's recommendation: (a).** No enrolled host can hold the state, and (b) adds a render path on an error return.
     - **Answer (2026-11-03): (a).**
   - **O-2. accepted.json's directory 0 while the unapplied record holds a directory part.**
     - **The background.** Truth 3 says accepted.json reports directory 0 while the host is unauthorized. Since 03-08j, WriteAccepted raises the bundle and the directory to the record's versions, so the fetcher asks from them and pruneSpool keeps the spool from them.
     - **The stall under (a).** One shape stalls under the plain reading:
       1. The run's flag comes from the KRL-alone pass over accepted/, which is unauthorized.
       2. The record's directory part is the new admins' and authorised: their directory was refused for its content and recorded.
       3. The fetcher asks from 0 and receives only the server's current directory (directoryItems).
       4. Once the server is two or more versions above the record, the next capture cannot chain from the record (directory_chain_gap), and every run reports it again.
       5. The host stays fail-closed until reset-directory.
     - **(a)** Directory 0 whenever the run is unauthorized: the plain reading, as the tasks are written. The stall is accepted and documented.
     - **(b)** The record's raise wins: directory 0 only while no record directory part is ahead of accepted/. A host whose recorded directory the policy in force does not authorise then waits for the new admins' first directory above the record's version, as Q-F03b already requires above the stored version.
     - **(c)** Directory 0 exactly while the directory the next capture chains from is unauthorized: the record's directory part when it is ahead, else accepted/'s, checked under the record's base policy or accepted/'s.
       - This keeps the cursor on the chain base, avoids the stall, and keeps same-number recovery wherever the base is unauthorized.
       - It needs that check when accepted.json is written (one exported state helper over a Stored).
     - **In every option** pruneSpool counts from what accepted.json names. With directory 0 it keeps the newest 64 directory versions, as on a host that accepted none. The applier reads the stored directory from accepted/, not from the spool.
     - **Planner's recommendation: (c).** These follow the answer: Task 1's Apply bullet, Task 3's `unauthorized_with_a_recorded_directory` and its mutant, and host-setup.md's record note.
     - **Answer (2026-11-03): (c).** Task 1's WriteAccepted bullet applies it. Task 3 replaces `unauthorized_with_a_recorded_directory` with `recorded_authorized_directory_keeps_the_record_raise` (the stall shape, which no longer stalls) and `recorded_bundle_over_unauthorized_directory_reports_directory_0`, each with its mutants. The runbook notes follow.
   - **O-3. The spool bound grows with the per-bundle file.**
     - pruneSpool's computed bound (03-08e) counts 1025 bundle, policy and directory sets: about 5.1 GiB kept and 5.6 GiB in all.
     - The per-bundle policy signature file adds one file of at most spool.MaxBundle (1 MiB) per kept bundle. That makes about 6.1 GiB kept and 6.6 GiB in all, computed from the caps, not measured.
     - An honest file is a few kilobytes, one SSHSIG block per root.
     - **(a)** Accept the new bound, as Task 2 and host-setup.md state it.
     - **(b)** Give the per-bundle file a smaller cap of its own in spool.Cap, sized for a root set's signatures. That keeps the bound near today's, but adds a cap that the signer's bound on policy signatures (tlog.MaxDocument) must stay below.
     - **Planner's recommendation: (a).** A later plan that shrinks the prune window shrinks this bound with it.
     - **Answer (2026-11-03): (a).**

</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a host holds a directory version 2 signed by admin alice → a root-signed bundle 2 whose policy 2 names only admin bob → Verify checks the stored directory again under policy 2 and flags it unauthorized → Render emits the CA keys and the KRL with no principals → forward installs it and returns directory_not_authorized → accepted.json reports directory 0 → bob's directory version 2 arrives at the same number and is accepted standalone → principals are bob's and the error clears"</name>
  <reversibility rating="costly">While the directory in force is unauthorized, hosts stop rendering principals. That is operator-visible on every later admin-set change, Phase 4's AUTHZ-03 included (owner decision Q-F03a).</reversibility>
  <precondition>All of these hold:
    - `git fetch origin` succeeds.
    - `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md` exits 0.
    - 03-08k, and with it 03-08e and 03-08j, is merged, with the names this plan builds on. Each command prints 1:
      - `K=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$K" | grep -c 'func (v \*Verified) krlStep('`;
      - `K=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$K" | grep -c '^func KRLAlone(p \*Pins, prev \*Stored, in spool.State, refusal error, from \*Verified)'`;
      - `K=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$K" | grep -c '^func VerifyAfter('`;
      - `U=$(git show origin/main:internal/agent/state/unapplied.go) && printf '%s\n' "$U" | grep -c '^func VerifyAheadAfter('`;
      - `A=$(git show origin/main:internal/agent/apply/apply.go) && printf '%s\n' "$A" | grep -c '^func outcome(v \*state.Verified) error'`;
      - `A=$(git show origin/main:internal/agent/apply/apply.go) && printf '%s\n' "$A" | grep -c '^func (e \*engine) pollCapture(pending \*state.Verified)'`;
      - `F=$(git show origin/main:internal/agent/fetch/fetch.go) && printf '%s\n' "$F" | grep -c '^func pruneSpool('`.
    - F02 and F03 are still unfixed on main.
      - Each of these prints 0: `K=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$K" | grep -c 'DirectoryUnauthorized'`, and `S=$(git show origin/main:internal/agent/spool/spool.go) && printf '%s\n' "$S" | grep -c 'BundlePolicySigs'`.
      - Each of these prints 1: `K=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$K" | grep -c 'PolicySigs: v.Next.PolicySigs}, in)'` (findPolicy's stored-first call in verifyBundle), and `K=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$K" | grep -c 'case stored != nil && newest == storedVersion:'`.
    - The owner has answered O-1, O-2 and O-3, and the answers are applied to this plan: `grep -c '^- \*\*O-[1-3] (answered' "$PLAN"` prints 3, where `$PLAN` is the full path of this plan file as handed to the executor (the copy this task's action then places in the phase directory).
  </precondition>
  <files>internal/agent/state/state.go, internal/agent/state/verify.go, internal/agent/apply/render.go, internal/agent/apply/apply.go, internal/agent/apply/installed.go, internal/agent/apply/status.go, internal/agent/apply/status_test.go, internal/agent/apply/apply_test.go, internal/agent/apply/window_test.go, internal/agent/apply/policy_change_test.go, .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md</files>
  <read_first>
    Find functions with `grep -n` on the branch and read only those ranges, except where noted.
    - internal/agent/state/verify.go, read whole once (about 32 KB). It is the core of both fixes, and Tasks 2 and 3 reuse it. It holds:
      - the Verified struct with BundleHeld, KRLRefused, Refused and fullyVerified;
      - Verify, VerifyAfter, verify, KRLAlone, storedOnly, findPolicy, verifyBundle, holdBundle, verifyDirectory and krlStep.
    - internal/agent/state/unapplied.go: `func (u *Unapplied) Base(`, `func VerifyAhead(`, `func VerifyAheadAfter(` and `func verifyAhead(` (about 4 KB).
    - internal/agent/state/state.go: the error var block, `type Stored`, `func (s *Stored) Floor(`, `func LoadStored(` and its caps, and `func (s *Stored) Save(` (about 6 KB).
    - internal/signer/directory.go: `func (s *Signer) loadDirectory(` (about 3 KB). This is the signer's check, mirrored here.
    - internal/directory/verify.go: the signatures of `func VerifySignatures(` and `func CheckPolicy(` (about 1 KB).
    - internal/agent/apply/render.go: `func Render(` and `func renderTrust(` (about 4 KB).
    - internal/agent/apply/apply.go (about 14 KB in all):
      - `func Apply(`, around its WriteAccepted call;
      - `func (e *engine) forward(` with its doc comment. Find its return points with `grep -n 'return outcome(\|Changed()\|sameBytes(cur, g)\|krlAlone(\|target, tv = '`;
      - `func outcome(`, `func (e *engine) render(` and `func (e *engine) krlAlone(`;
      - `func (e *engine) pollSpool(` and `func (e *engine) pollCapture(`;
      - `func loadUnapplied(`, which WriteAccepted calls.
    - internal/agent/apply/installed.go, read whole (about 4 KB): AcceptedVersions, and WriteAccepted's raise to the unapplied record (03-08j).
    - internal/agent/apply/status.go: `var refusals` and `func applyResult(` (about 1.5 KB). internal/agent/apply/status_test.go: the subtest `apply_result` of TestStatus (`grep -n 'apply_result'`).
    - Test helpers, about 7 KB in all:
      - internal/agent/apply/apply_test.go: `func (f *fixture) rotation(`, `func (f *fixture) rotationOps(` and the subtest `torn_accepted_save_never_mixes`;
      - internal/agent/apply/harness_test.go: `type dirSpec struct` (its signer field), `func seedKey(` and `func (h *testHost) publishDir(`;
      - internal/agent/apply/rechain_test.go: `func spoolInState(` and `func readAccepted(`;
      - internal/agent/apply/window_test.go: the subtest `held_content_refusal_keeps_the_records_bundle` and its helper `policyRotated` (about 2 KB).
  </read_first>
  <action>
Create branch `p03/08f-agent-policy-in-force` from origin/main. Place this plan file untracked in the phase directory.

**The base time, before any edit.** On the branch, which is still origin/main:
- Run the Budget's alone gate (the package alone, limit 400 s) and its `./...` margin run (limit 480 s). Record internal/agent/apply's `ok` line from each. The alone figure is the alone base, and the `./...` figure the `./...` base.
- Record CI's time for the package from the build-test job log of origin/main's latest CI run, with the command used.

**Stop rule.** Stop here, before any edit, if the alone base is above 400 s, or the `./...` base or CI's time is above 480 s (an alone or margin gate that exits non-zero). Report the figures to the owner with the two options under Budget: raise CI's test -timeout, or move the slow cases into their own package. Do not choose between them.

**RED first.** Create internal/agent/apply/policy_change_test.go, with first line `//go:build linux`, and the subtest `TestDirectoryUnderPolicyInForce/lagging_host_admin_removed_principals_dropped`.
- Every case of TestDirectoryUnderPolicyInForce and TestRootRotationUnchangedPolicy calls t.Parallel.
- Use spoolInState, so that accepted.json lands in the production outbox.
- Build steps 1 to 3 in a package-level helper in policy_change_test.go that returns the host in its unauthorized state, so that Task 3's cases reuse it in Run B. Record the helper's name and what it returns in the SUMMARY draft.

The steps:
1. Install bundle 1, policy 1 (admin alice, quorum 1) and directory 1 with role:ops.
2. Apply alice's directory 2, which grants role:evil to deploy.
3. Offer f.rotation's bundle 2, with policy 2 (admins: bob alone, seedKey 11), and a newer KRL. Apply.

Assert:
- the error wraps state.ErrDirUnauthorized;
- current has no principals file;
- current's user_ca_keys comes from bundle 2, and current revokes the new serial;
- the report's BundleVersion is 2, and its DirectoryUnauthorized is true;
- readAccepted's Directory is 0, while accepted/ still holds directory 2 (the chain base is accepted/, whose directory policy 2 does not authorize);
- a second apply with nothing new returns the same error, changes nothing, reports NoOp with DirectoryUnauthorized true, and leaves readAccepted's Directory at 0. This is the idle run every 60 s, and same-number recovery depends on it.

Then replace the spool's directory-2.json with bob's directory 2, whose bytes differ and which chains to version 1. Apply, and assert that the error is nil, the principals of deploy are bob's, and readAccepted's Directory is 2.

Before running RED, add only the new symbols, with no behaviour: `state.ErrDirUnauthorized`, `state.ErrDirFork`, the `Verified.DirectoryUnauthorized` field, the `Report.DirectoryUnauthorized` field, and `(s *Stored) DirectoryUnderPolicy()` returning nil. The test then fails on behaviour, not on the build. Run it on the branch and record the failing lines in the SUMMARY draft. Today the principals stay `[role:evil]` and the error is nil.

**state.**
- state.go gains `ErrDirUnauthorized = errors.New("directory_not_authorized")` and `ErrDirFork = errors.New("directory_fork")`. Task 3 uses the second.
- Verified gains `DirectoryUnauthorized error`. Its comment says: the stored directory does not carry the admin quorum of the policy in force, or does not fit it; derived on every verification, never stored; F03 (03-08f).
- Add `checkStored(prev *Stored, d *directory.Directory, pol *trust.Policy) error`. It runs directory.VerifySignatures(prev.Directory, prev.DirectorySigs, pol), then directory.CheckPolicy(d, pol). Any failure is wrapped in ErrDirUnauthorized and names the stored version and the policy version.
- Add the exported `(s *Stored) DirectoryUnderPolicy() error` (owner decision O-2 (c)), for WriteAccepted.
  - It is nil when s holds no directory.
  - Otherwise it parses s's directory and returns checkStored under s's own parsed policy. That policy is the one LoadStored parses for accepted/, or the record's policy when Unapplied.Base took the record's bundle part.
  - A directory that does not parse, or a missing policy, is an error too. WriteAccepted then writes directory 0, which costs at most one re-sent directory.
- **verifyDirectory(p, prev, in).** Its prev is verify's chain, the directory the capture chains from:
  - accepted/ for Verify;
  - the unapplied record's base for VerifyAhead and VerifyAheadAfter, whose directory is the record's directory part when the record holds one (03-08j);
  - the pending target's state for VerifyAfter.

  It works like this:
  1. Parse the stored directory as today.
  2. When there is a stored directory, compute `unauth := checkStored(prev, d, v.Policy)`. Here v.Policy is the newest policy the bundle step reached, before any hold.
  3. When unauth is nil, run today's offered-directory logic unchanged. Task 3 adds the rule for an equal version.
  4. When unauth is set:
     a. *Standalone.* Look at the offered versions from the newest down to the stored version. Include the stored version only when its bytes differ. Take the first one that:
        - carries v.Policy's admin quorum (no hold);
        - parses, with the matching version;
        - passes CheckInstallation and CheckPolicy.

        Accept it standalone, with no chain to the stored bytes. The flag stays clear.
     b. *Otherwise,* run today's logic, chain and hold included, and return its result. The hold includes 03-08j's in-force hold step, the bundle in force that verify puts first in v.steps when chain's bundle is above alone's. If today's logic accepts nothing and returns nil, set v.DirectoryUnauthorized to unauth. Task 3 turns its refusals into the unauthorized state as well.
  5. A candidate that fails step a is skipped, not refused.
  6. Versions below the stored one are never taken here (owner decision Q-F03b).
- verify's raise of fullyVerified (03-08k) is unchanged. It runs after verifyBundle and before verifyDirectory, so the directory check never changes which bundle the apply verified in full.

**apply.**
- **Render.** When v.DirectoryUnauthorized is set, return renderTrust(v) with no principals files and an empty Host.
- **engine.render.** Render's trust-only generation returns with a nil error, so main's fallback code, which reads last-good's record host (`lastHost, lgGen.HostStatus = rec.Host, rec.HostStatus`), does not run for it. Add the fill: when v.DirectoryUnauthorized is set and there is a last-good of the agent's, set g.Host from that last-good's record (`e.readRecord(lg.n)`). Otherwise leave Host empty.
- **forward.**
  - **outcome(v)** joins v.DirectoryUnauthorized with v.Refused and v.KRLRefused (03-08k), and with errNoDirectory while no directory is accepted (03-08d). Every return of forward that names the state in force goes through it: the no-change path, the dry run, the byte-equal commit, the first install and the final `return outcome(tv)`.
  - **krlAlone's error return** `errors.Join(v.Refused, refusal)` joins v.DirectoryUnauthorized as well.
  - **Report.DirectoryUnauthorized** is a `bool` with json `directory_unauthorized,omitempty`. It is set from the Verified the run last moved to, before any return, error returns and rollbacks included. That Verified is:
    - v after Verify;
    - v after each krlAlone pass;
    - tv once a superseding capture replaced it.

    It is set on the no-change path too, so that every unauthorized run's report, the idle ones included, names it. accepted.json does not read it: WriteAccepted follows the chain base on disk (below).
  - **Polls.** pollSpool has no report of its own. It hands its generation and Verified to forward through `superseded`, and forward then sets `target, tv = s.gen, s.verified`. That includes a Verified produced by the KRL-alone pass in pollSpool (krlAlone) or by pollCapture's branch that brings nothing beyond the record (state.KRLAlone with the capture as from). KRLAlone uses storedOnly, which carries the flag (Task 3), so that path, too, sets the flag through forward, from tv. A comment at forward's supersede step says so.
  - Task 3 adds the forced render for a capture that changed nothing.
- **WriteAccepted (installed.go; owner decision O-2 (c)).** Apply calls it after every locked run, as today.
  1. It computes its versions as today: accepted/'s, the bundle and the directory raised to the unapplied record's (03-08j), and the KRL in force.
  2. It then takes the chain base: the record's base when loadUnapplied returns one, else accepted/ (loadAcceptedState).
  3. When that base's DirectoryUnderPolicy returns an error, it writes Directory 0. Otherwise it writes the raised versions unchanged. The bundle and the KRL are never changed by this rule.

  A loader error keeps today's fallback, accepted/'s versions, checked the same way against accepted/. ResetDirectory calls WriteAccepted after dropping the accepted directory and the record's directory part, so its base holds none and nothing changes for it. AcceptedVersions is unchanged. The doc comment gives the reasons:
  - the fetcher then asks from 0, and the server's answer for 0 is its current directory (internal/server's directoryItems), which same-number recovery needs;
  - while the base's directory is authorized, the cursor keeps following the chain base. A host whose recorded directory is the new admins' then keeps fetching the versions after the record. With directory 0 it would receive only the server's current directory, which does not chain to the record once the server is two or more versions ahead;
  - a crash between forward's record write (recordUnapplied) and WriteAccepted, or between a commit and WriteAccepted, leaves the previous accepted.json for one run. The next locked run rewrites it from disk, and the record holds its own copies, so this costs at most one poll of extra or fewer directory items, and nothing stalls. DryRun and unlocked runs skip WriteAccepted, as today (plan check 3, m-5).
- **Existing accepted.json tests.** TestWriteAccepted and the TestSpoolWindow cases that read accepted.json (bundleRecorded, recordedWindow, fetcher_cursor_follows_the_record) keep the policy, so their chain base stays authorized and the planner expects them to stay green. A record shape whose recorded bundle rotates the policy (recordAbove, recordBelowWait, policyRotated) now writes directory 0 while the base's directory is the old admins'. No existing case reads accepted.json there; confirm that from the run.
- **The mixed record {3, 65} (plan check 3, m-1).** `TestSpoolWindow/held_content_refusal_keeps_the_records_bundle` ends with the record {Bundle: 3, Directory: 65}, built through mergeUnapplied. Recorded bundle 3 carries policyRotated's policy, which names bob. Recorded directory 65 is the old admins', taken by the in-force hold and then refused for its content.
  - Add one assertion after its `mustRecord(t, h, 3, 65)`: readAccepted's Bundle is 3 and its Directory is 0.
  - That is the owner's O-2 (c) rule as decided: the chain base's directory, 65, is not authorized by the base's policy. With an honest server it is safe, because after the rotation the server's current directory is the new admins'.
  - Take its RED on the branch before this task's change: accepted.json reads directory 65 there.
- **status.go.** `refusals` gains state.ErrDirUnauthorized and state.ErrDirFork (a planner decision), so last_apply.result is `refused`. TestStatus/apply_result gains a row for each, expecting heartbeat.ResultRefused.
- **internal/agent/heartbeat/** stays unchanged, with no new host_status value. The error reaches last_apply through Report.Errors.

**Existing tests that F03 changes.**
- **TestApply/torn_accepted_save_never_mixes.** It rotates the policy to admin bob alone (seedKey 11) over directory 1, which the fixture's admin signed, and requires the run after the crash to return nil. Under F03 that run returns directory_not_authorized and renders no principals, so the case would no longer test a byte-equal commit. Change only its rotation's admins to f.policy.Admins, so that directory 1 stays authorized and the render stays byte-equal, and say so in its comment.
- **Every other test.** Run the Budget's alone gate. Every other existing test that now fails is one F03 changes. Name it in the SUMMARY draft with its reason, as 03-08k's "The four changed tests" does, and change only the assertion or the admin set that the reason names.
- **The expected survivors.** The planner expects the shapes that rotate the policy to bob and then hold to stay green: the hold accepts the newer directory under the earlier policy, so the flag stays clear. They are:
  - TestApply/catch_up_across_policy_rotation;
  - TestSpoolWindow/policy_rotation_below_the_recorded_bundle and older_bundle_at_the_window_boundary;
  - TestSpoolWindowWideningWait's recordAbove rows;
  - TestKRLSigner's heldShape, heldWait and recordBelowWait cases.

  Confirm this from the run rather than assume it.

**Commit and the SUMMARY draft.**
1. Run both of the Budget's modes (the alone run and the `./...` run) on the finished code and tests, with the Budget's stop rule.
2. Commit the code and tests by path, authored as the Delivery protocol says, as `fix(agent): check the stored directory under the policy in force (F03)`.
3. Commit the SUMMARY draft the same way, as `docs(03-08f): record the tracer's evidence`. It holds the base figures, CI's time, the RED, the two runs, the changed tests and the name of the unauthorized-state helper.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/state/ && go test -race -count=1 -v -run "^TestDirectoryUnderPolicyInForce$|^TestKRLAlone$/^(directory_rechain_refused_krl_applied|bundle_step_refused_krl_applied|ops_key_changed_krl_lands_alone|refusal_without_newer_krl_is_noop)$|^TestResetDirectory$|^TestApply$/^(torn_accepted_save_never_mixes|catch_up_across_policy_rotation)$|^TestStatus$/^apply_result$|^TestWriteAccepted$|^TestSpoolWindow$/^(held_content_refusal_keeps_the_records_bundle|fetcher_cursor_follows_the_record)$|^TestKRLSigner$" ./internal/agent/apply/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestDirectoryUnderPolicyInForce/lagging_host_admin_removed_principals_dropped", "--- PASS: TestApply/torn_accepted_save_never_mixes", "--- PASS: TestApply/catch_up_across_policy_rotation", "--- PASS: TestStatus/apply_result", "--- PASS: TestWriteAccepted", "--- PASS: TestSpoolWindow/held_content_refusal_keeps_the_records_bundle", "--- PASS: TestSpoolWindow/fetcher_cursor_follows_the_record", "--- PASS: TestKRLAlone/ops_key_changed_krl_lands_alone"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'directory_not_authorized' internal/agent/state/state.go` prints 1. `grep -v '^[[:space:]]*//' internal/agent/apply/render.go | grep -c 'DirectoryUnauthorized'` prints at least 1. `grep -v '^[[:space:]]*//' internal/agent/apply/status.go | grep -c 'state.ErrDirUnauthorized'` prints 1. `grep -v '^[[:space:]]*//' internal/agent/apply/installed.go | grep -c 'DirectoryUnderPolicy'` prints at least 1.
    - `git diff --exit-code origin/main -- internal/agent/heartbeat/` exits 0: the closed host_status set is unchanged.
    - `head -1 internal/agent/apply/policy_change_test.go` prints `//go:build linux`.
    - The SUMMARY draft records:
      - the alone base, the `./...` base and CI's time;
      - the RED output of `lagging_host_admin_removed_principals_dropped` on origin/main's code;
      - Task 1's two runs;
      - every existing test the change flipped, with its reason (at least torn_accepted_save_never_mixes);
      - the RED of held_content_refusal_keeps_the_records_bundle's added assertion (directory 65 before this task's change);
      - the name of the unauthorized-state helper.
    - `git status --porcelain -- internal/` prints nothing after the last commit.
  </acceptance_criteria>
  <done>A host whose directory the policy in force no longer authorizes renders no principals from it. It reports directory_not_authorized as a refusal, asks the server for its current directory, and takes the new admins' directory at the same number.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: F02, rotations that keep the policy: the policy-signature union on threshold failures, the stored-sigs rule, the per-bundle policy signature file in the spool, the fetcher and the prune, and their edges</name>
  <files>internal/agent/state/verify.go, internal/agent/spool/spool.go, internal/agent/spool/spool_test.go, internal/agent/fetch/fetch.go, internal/agent/fetch/fetch_test.go, internal/agent/fetch/prune_test.go, internal/agent/apply/policy_change_test.go, .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md</files>
  <behavior>
    - **`TestRootRotationUnchangedPolicy`**, in the apply package, with its fixture. Every case calls t.Parallel.
      - *Setup.*
        - Root A is the fixture's root. New roots C, D and E use seedKey 21, 22 and 23.
        - A successor is trust.BuildSuccessor over the given root set and threshold, with the fixture's policy bytes unchanged.
        - Each document is signed with the concatenated SSHSIG blocks of the roots named.
        - The spool is written with spool.Write, the way fetch.writeState writes it: the policy under version 1, the bundle, and the bundle's `bundle-<N>.policy.sigs`.
      - `one_hop_new_roots`: stored genesis {A}. Bundle 2 has roots {C} at threshold 1; bundle and policy are signed by A and C.
        - Expected: no error, BundleVersion 2, accepted/ holds bundle 2.
        - RED today: `bundle_not_verified: ... policy (new roots) signed by 0 of 1 roots, need 1`, with the KRL applied alone.
      - `one_hop_with_directory_in_same_capture`: the same capture also offers directory 2, which is accepted too. RED today: DirectoryChanged is false.
      - `three_hops_in_one_capture`: {A}→{C}→{D}→{E}. Each step is signed by its previous and its new roots, and each bundle has its own policy sigs file. All are accepted, up to 4. RED today.
      - `spool_without_per_bundle_sigs_one_hop`: as `one_hop_new_roots`, but there is no `bundle-2.policy.sigs`, and `policy-1.json.sigs` holds A and C. This is what a fetcher from before this plan leaves. Accepted through the union with the offered policy file. RED today.
      - `union_never_lowers_threshold`: bundle 2 has roots {C, D} at threshold 2 and is signed by A, C and D. Its delivered policy sigs hold C's block twice, a block by a key that is not a root, and the stored A. Refused: `policy (new roots) signed by 1 of 2 roots, need 2`.
      - `malformed_delivered_sigs_change_nothing`: a successor with the same roots {A} whose `bundle-2.policy.sigs` is not SSHSIG. It is accepted with the stored signatures, as today. The same malformed file under a rotation to {C}, with the offered policy file holding only A, is refused.
      - `malformed_delivered_sigs_not_stored`:
        1. A rotation to {C} whose `bundle-2.policy.sigs` is malformed and whose offered `policy-1.json.sigs` holds A and C. It is accepted through the union.
        2. accepted/'s PolicySigs equals the offered file, byte for byte, not the malformed one.
        3. A next hop {C}→{D}, with a valid delivered file signed by C and D, is accepted.

        This test fails if a source that ParseAll rejected is ever stored: the next hop's plain check would then fail with a parse error, not ErrThreshold, and never reach the union.
      - `retired_root_fork_refused_after_rotation`: after `one_hop_new_roots`, a bundle 3' with roots {A}, signed only by A, is refused `bundle (previous roots) signed by 0 of 1`. This is RED today at its first step, because the rotation is refused. A host still on {A} accepts a bundle 2' fork signed only by A; the SUMMARY records that contrast.
      - `same_roots_unchanged_policy_accepted`: the 03-12/03-13 shape, a successor with roots {A} and the policy unchanged. Accepted, today and after. accepted/'s PolicySigs equals the stored signatures that today's code stores (the plain check passed).
      - `growing_root_set_second_root_signs_policy`: {A}→{A,B}→{A,B,C} at threshold 1, with bundle 3's policy signed by B only. Accepted, today and after.
      - `stored_policy_sigs_stay_bounded`: after `three_hops_in_one_capture`, state.LoadStored reads accepted/, and its PolicySigs equals `bundle-4.policy.sigs`.
    - **`TestSpool`**:
      - `bundle_policy_sigs_read_when_present`;
      - `bundle_policy_sigs_absent_is_allowed`;
      - `cap_is_what_read_enforces` gains the new name: MaxBundle reads, MaxBundle+1 refuses.
    - **`TestFetch`**:
      - `per_bundle_policy_sigs_spooled`: each bundle item's PolicySigs is written as `bundle-<N>.policy.sigs`, before `bundle-<N>.json`;
      - `drop_above_removes_per_bundle_policy_sigs`;
      - `per_bundle_policy_sigs_over_cap_refused`, through checkCaps;
      - `heal_covers_per_bundle_policy_sigs`.
    - **`TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle`.** accepted.json names bundle 3. Complete bundles 1 to 5 are in the spool, each with its `bundle-<N>.policy.sigs`, and so is an orphan `bundle-9.policy.sigs` with no bundle 9. After pruneSpool:
      - the per-bundle files of 3, 4 and 5 stay;
      - those of 1 and 2 go with their bundles;
      - the orphan goes.

      A second spool with no accepted.json and 70 complete bundles keeps the per-bundle files of the newest spool.MaxVersionsPerKind bundles only. RED today: every per-bundle file stays, because pruneSpool does not recognise the name.
  </behavior>
  <read_first>
    Read functions only, found with `grep -n`. state/verify.go is already in context from Task 1.
    - internal/trust/verify.go: `func CountPinnedSigners(`, `func requireSigners(`, `func VerifySuccessor(` and the `ErrThreshold` var (about 5 KB).
    - internal/trust/successor.go: `func BuildSuccessor(` signature (about 1 KB). internal/sshsig/sshsig.go: `func ParseAll(` (about 1 KB).
    - internal/agent/spool/spool.go: `type State struct`, `docRE`, `func Cap(`, `func readOnce(` (Read takes a Floor and calls it), `func pickAbove(` and `func Write(` (about 10 KB).
    - internal/agent/fetch/fetch.go (about 12 KB):
      - `func writeState(`, `func dropAbove(`, `func checkCaps(` and `func healSpool(`;
      - `func pruneSpool(` with its doc comment and keepAbove's;
      - `func spoolSet(`, and the regexp block with spoolFileRE and spoolSetDocRE.
    - Patterns, about 9 KB in all:
      - internal/agent/spool/spool_test.go: `cap_is_what_read_enforces`;
      - internal/agent/fetch/fetch_test.go: `oversize_policy_answer_refused_nothing_written` and `poisoned_spool_file_removed_at_next_poll`;
      - internal/agent/fetch/prune_test.go: `prune_keeps_what_the_applier_reads`.
  </read_first>
  <action>
Write the tests in `<behavior>` first. Before running them, add only the `State.BundlePolicySigs` field, which Read and Write ignore for now, so every RED fails on behaviour, not on the build. Run them on Task 1's head. Record in the SUMMARY draft each case that is RED, and each that is GREEN at once with its reason. The controls are expected GREEN. Then implement:

**spool.go.**
- State gains `BundlePolicySigs map[uint64][]byte`.
- `bundle-<N>.policy.sigs` is recognised, with the same version grammar as docRE and with Cap MaxBundle.
- readOnce fills BundlePolicySigs for every bundle version it takes (pick's floor rule), when the file is present. The file does not decide whether a bundle set is complete, and it is not listed as ignored.
- Write writes it before `bundle-<N>.json.sigs` and `bundle-<N>.json`.

**fetch.go.**
- writeState passes each item's PolicySigs as BundlePolicySigs, under the bundle's version.
- spoolFileRE gains `policy\.sigs`, so that dropAbove removes the file with its bundle.
- spoolSet recognises `bundle-<N>.policy.sigs` as a file of bundle N's set. pruneSpool then keeps it exactly while it keeps bundle N, and removes an orphan, because only complete bundles are kept. A set's completeness stays decided by `bundle-<N>.json` and its `.sigs`.
- pruneSpool's doc comment bound becomes about 6.1 GiB kept and 6.6 GiB in all, because 1025 more files of at most spool.MaxBundle are counted. It stays computed from the caps (owner decision O-3 (a)).
- checkCaps names the file as writeState writes it. Its size is that of PolicySigs, which checkCaps already checks as the policy's signature file, but the name keeps checkCaps' rule that it names every file exactly as writeState writes it. healSpool covers the file through Cap.
- The policy comment gains a sentence: the per-bundle file is what keeps each bundle's signatures when several bundles share a policy version.

**verify.go: verifyBundle's successor loop.**
1. Keep findPolicy and today's VerifySuccessor call with pol.Sigs. At the first step, pol.Sigs is the chain base's PolicySigs: accepted/'s, the unapplied record's (Base), or the pending target's (VerifyAfter).
2. When that call fails with `errors.Is(err, trust.ErrThreshold)`, build the union and retry VerifySuccessor once with it, if it differs from pol.Sigs:
   - The sources are pol.Sigs, `in.BundlePolicySigs[ver]` and the offered policy file whose body has the bundle's policy SHA-256.
   - A source is admitted only when sshsig.ParseAll accepts it on its own.
   - Identical files are admitted once.
   - The union is the admitted files concatenated, each ending in a newline.
3. A step that passes stores one file in `Next.PolicySigs` and the bundleStep's polDoc.Sigs, chosen in this order:
   - pol.Sigs, when the plain call passed;
   - otherwise, of the admitted delivered file and the admitted offered file, the first that passes VerifySuccessor alone;
   - otherwise the admitted offered file;
   - otherwise the admitted delivered file.

   It never stores the union, and never a source ParseAll rejected. The unapplied record's bundle part copies Next.PolicySigs (03-08j), so the same rule governs unapplied.json.
4. The doc comments of Verify and verifyBundle state the rule and why the union cannot widen trust:
   - the thresholds come from the bundles;
   - CountPinnedSigners counts a root once, and only for a valid signature over the exact policy bytes;
   - the bundle signatures are never united.

   Cite `F02 (03-08f)`.
5. verify raises fullyVerified only after verifyBundle returns nil (03-08k). A rotation the union now verifies raises it like any verified step: that is 03-08k's rule applied to it (Reconciliation I-1), and no code here changes it.

Do not change internal/trust. The SUMMARY records the trust/verify.go lines the threshold argument rests on.

**Commit, mutants and the SUMMARY draft.**
1. Run both of the Budget's modes on the finished code and tests, with the stop rule.
2. Commit the code and tests by path, authored as the Delivery protocol says, as `fix(agent): verify a root rotation that keeps the policy with the signatures delivered per bundle (F02)`.
3. Run the mutants below as the Budget's scripted loop.
4. Write the SUMMARY draft's `## Handoff to Task 3` section (acceptance criteria), then commit the draft the same way, as `docs(03-08f): record F02's evidence`. This ends Run A.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/state/ ./internal/agent/spool/ ./internal/agent/fetch/ && go test -race -count=1 -v -run "^TestSpool$|^TestFetch$|^TestSpoolPrune$" ./internal/agent/spool/ ./internal/agent/fetch/ && go test -race -count=1 -v -run "^TestRootRotationUnchangedPolicy$|^TestDirectoryUnderPolicyInForce$|^TestKRLAlone$/^(bundle_step_refused_krl_applied|ops_key_changed_krl_lands_alone)$|^TestApply$/^(torn_accepted_save_never_mixes|catch_up_across_policy_rotation)$|^TestKRLSigner$" ./internal/agent/apply/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestRootRotationUnchangedPolicy/one_hop_new_roots", "--- PASS: TestRootRotationUnchangedPolicy/one_hop_with_directory_in_same_capture", "--- PASS: TestRootRotationUnchangedPolicy/three_hops_in_one_capture", "--- PASS: TestRootRotationUnchangedPolicy/spool_without_per_bundle_sigs_one_hop", "--- PASS: TestRootRotationUnchangedPolicy/union_never_lowers_threshold", "--- PASS: TestRootRotationUnchangedPolicy/malformed_delivered_sigs_change_nothing", "--- PASS: TestRootRotationUnchangedPolicy/malformed_delivered_sigs_not_stored", "--- PASS: TestRootRotationUnchangedPolicy/retired_root_fork_refused_after_rotation", "--- PASS: TestRootRotationUnchangedPolicy/same_roots_unchanged_policy_accepted", "--- PASS: TestRootRotationUnchangedPolicy/growing_root_set_second_root_signs_policy", "--- PASS: TestRootRotationUnchangedPolicy/stored_policy_sigs_stay_bounded", "--- PASS: TestSpool/bundle_policy_sigs_read_when_present", "--- PASS: TestSpool/bundle_policy_sigs_absent_is_allowed", "--- PASS: TestSpool/cap_is_what_read_enforces", "--- PASS: TestFetch/per_bundle_policy_sigs_spooled", "--- PASS: TestFetch/drop_above_removes_per_bundle_policy_sigs", "--- PASS: TestFetch/per_bundle_policy_sigs_over_cap_refused", "--- PASS: TestFetch/heal_covers_per_bundle_policy_sigs", "--- PASS: TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle", "--- PASS: TestDirectoryUnderPolicyInForce/lagging_host_admin_removed_principals_dropped"</fails_when>
  </verify>
  <acceptance_criteria>
    - `git diff --exit-code origin/main -- internal/trust/` exits 0: the trust package is unchanged.
    - `grep -v '^[[:space:]]*//' internal/agent/state/verify.go | grep -c 'trust.ErrThreshold'` prints at least 1.
    - The SUMMARY draft records Task 2's two runs, and lists these mutants. Each is applied to Task 2's code commit, run against its named test, and restored byte for byte:
      - the union built from every source, unfiltered, and tried before the plain check: killed by `malformed_delivered_sigs_change_nothing`, because ParseAll refuses the unfiltered union, and by `same_roots_unchanged_policy_accepted`'s check of the stored PolicySigs;
      - the bundle signatures added to the union: **equivalent, and must survive** (plan check 3, m-2). CountPinnedSigners (internal/trust/verify.go) verifies every block over the policy bytes under the policy namespace and skips a block that does not verify there. A root's bundle signature never verifies there, so it can never count toward the policy threshold, and the well-formed blocks pass ParseAll. Run it against `union_never_lowers_threshold` and `one_hop_new_roots`, and record its survival and this reason in the SUMMARY draft;
      - Next.PolicySigs set to the union: killed by `stored_policy_sigs_stay_bounded`;
      - a rejected delivered file stored: killed by `malformed_delivered_sigs_not_stored`;
      - the per-bundle file not written by the fetcher: killed by `per_bundle_policy_sigs_spooled`;
      - the offered policy file left out of the union: killed by `spool_without_per_bundle_sigs_one_hop`;
      - spoolSet left without the per-bundle name, so pruneSpool keeps every such file: killed by `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle`.
    - `git status --porcelain -- internal/` prints nothing after the last commit.
    - **The handoff to Run B.** Task 2's SUMMARY draft commit is the last commit of Run A, and its draft ends with a section `## Handoff to Task 3` that holds everything Task 3 needs in a fresh run:
      - the branch, and Task 2's code commit, where Task 3 takes the REDs it takes on Task 2's head;
      - the alone base, the `./...` base and CI's time, and Tasks 1's and 2's figures in both modes. Task 3's stop rule uses the alone base;
      - the test helpers Task 3 reuses: the unauthorized-state helper from Task 1, and any fixture or spool helper Tasks 1 and 2 added, each with its name, its file and what it builds;
      - every existing test Tasks 1 and 2 changed, with its reason, and every expected survivor the run confirmed;
      - the deviations so far, and any open question for the owner.

      Check: `grep -c '^## Handoff to Task 3' .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md` prints 1, `git log -1 --format=%s` prints `docs(03-08f): record F02's evidence`, and `git status --porcelain -- internal/ docs/` prints nothing.
  </acceptance_criteria>
  <done>Enrolled hosts accept a root rotation that keeps the policy, in one hop or several. The retired roots stop anchoring them, nothing about the root thresholds is weakened, accepted/ and unapplied.json store only an admitted, bounded signature file, and the spool removes each per-bundle file with its bundle.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: F03's edges: the forced render, storedOnly, refusals while unauthorized, the fork rule and the recorded directory; then the runbooks and the todo</name>
  <files>internal/agent/state/verify.go, internal/agent/apply/apply.go, internal/agent/apply/policy_change_test.go, docs/runbooks/root-ceremony.md, docs/runbooks/enroll-user.md, docs/runbooks/signer-install.md, docs/runbooks/host-setup.md, .planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md, .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md</files>
  <behavior>
    - **`TestDirectoryUnderPolicyInForce`.** Each case says where its RED is taken, and calls t.Parallel.
      - `new_admins_next_version_accepted_standalone`: from Task 1's unauthorized state, bob's directory 3 is accepted. It chains to bob's own version 2, never to alice's. Task 1 implements this behaviour, so the RED is taken on origin/main, where it fails with `directory_not_verified: directory version 3 does not chain to version 2`.
      - `same_capture_hold_then_dropped`: starting from directory 1, one capture offers bundle 2 (policy 2: bob) and alice's directory 2.
        - The first apply holds the bundle at 1 and renders alice's directory. That is PR #67's hold, kept and documented.
        - The second apply moves to bundle 2 and returns directory_not_authorized with no principals.
        - RED on origin/main, where bundle 2 keeps `[role:evil]`.
      - `rotation_first_then_removed_admin_refused`, re-expected for the code after this plan (plan check 3, M-1). The host holds alice's directory 1 (role:ops).
        1. Bundle 2 (f.rotation, policy 2: bob alone) is applied first. Expect directory_not_authorized, no principals and BundleVersion 2.
        2. Alice's directory 2 is then offered with a newer KRL. Expect:
           - the error joins directory_not_authorized with directory_not_verified;
           - no principals;
           - bundle 2 in force;
           - the KRL landed.

        The case pins that a removed admin cannot get back in by signing the next version while the host is fail-closed: her directory is refused, the refusal joins the unauthorized state (step b), and nothing of hers renders.

        Co-signing directory 1 by alice and bob, to keep the case a control, was rejected. Under policy 1 bob is no admin, so the tooling never produces that shape, and the case would only repeat `admin_set_unchanged_rotation_keeps_directory`.

        RED on origin/main, where the first apply returns nil and both applies keep `[role:ops]`.
      - `admin_set_unchanged_rotation_keeps_directory`: an f.rotation that keeps alice. No error, and the principals are kept. GREEN.
      - `persisted_unauthorized_state_dropped_on_noop_capture`: the bad state as it was before this fix.
        - Build it through the test fixtures, never through a production hook: accepted/ holds bundle 2, policy 2 and alice's directory 2, saved with state.LoadStored and Save, while current renders `[role:evil]`.
        - An apply with nothing new must remove the principals and return directory_not_authorized.
        - A second apply with nothing new reports NoOp and commits nothing: accepted/'s snapshot does not change.
        - RED on Task 2's head, because forward still skips the render for a capture that changed nothing.
      - `refused_bundle_step_still_checks_directory`: the same persisted state, plus a bundle chain gap and a newer KRL. The KRL lands alone (D-R2, KRLAlone) with no principals, and the error joins bundle_chain_gap with directory_not_authorized. RED on Task 2's head, because storedOnly does not check yet.
      - `stored_version_above_new_admins_needs_reset`: the host holds alice's directory 5 under policy 1. One capture offers bundle 2 (policy 2: bob) and only directory versions below 5. That is what the spool holds once the fetcher's dropAbove has removed versions above the server's current one.
        - The capture keeps bundle 2 and renders no principals. The error joins directory_not_authorized with directory_older.
        - Bob's directory 2 is then offered, and the host stays unauthorized.
        - After ResetDirectory, bob's directory 2 is accepted.

        RED on Task 2's head, because there directory_older still refuses the capture. This case pins owner decision Q-F03b's runbook step.
      - `same_version_other_bytes_refused_as_fork`: the stored directory 2 is authorized. The spool's directory-2.json is replaced by another directory 2 that alice signed (the current quorum), and a newer KRL is offered. Expect directory_fork, the KRL applied alone, and the principals unchanged. RED on Task 2's head, where it is a silent no-op.
      - `same_version_unsigned_bytes_not_verified`: as above, but the replacement directory 2 carries no admin quorum. Expect directory_not_verified, not directory_fork, and the KRL applied alone. RED on Task 2's head.
      - `recorded_authorized_directory_keeps_the_record_raise` (owner decision O-2 (c)). This is the record shape of 03-08j that stalled under reading (a).
        1. Start from Task 1's unauthorized state: bundle 2 with policy 2 (bob), alice's directory 2 stored, current with no principals.
        2. Offer bob's directory 3, chained to alice's 2, signed by bob and above the caps (`bulkRoles = 17`, as TestKRLAlone/oversize_principals_file_krl_applied builds it), with a newer KRL.
        3. Apply. Directory 3 is accepted standalone, and its generation is refused generation_too_large. Forward records it: `mustRecord(t, h, 0, 3)`. The KRL-alone pass over accepted/ lands the KRL with no principals, still unauthorized.
        4. Assert:
           - the error joins generation_too_large with directory_not_authorized;
           - the report's DirectoryUnauthorized is true;
           - readAccepted's Directory is 3. The chain base is the record's base, whose directory 3 policy 2 authorizes, so the record's raise wins.
        5. Bob then publishes directories 4 and 5, both within the caps and chained 3→4→5. They reach the spool as a fetcher asking from 3 receives them, and the spool's 3 stays.
        6. Apply. The capture chains from the record's 3 to 5 and installs it. Assert:
           - the error is nil;
           - the principals of deploy are directory 5's;
           - readAccepted's Directory is 5;
           - the unapplied record is gone.

        Under reading (a), readAccepted's Directory would be 0 at step 4. A fetcher asking from 0 receives only the server's current directory 5, which does not chain to 3: the stall. Step 4's assertion pins that this no longer happens.

        RED on Task 2's head. The run's flag comes from the KRL-alone pass over accepted/, and storedOnly does not check yet. So step 3's KRL-alone render brings alice's principals back, and the error has no directory_not_authorized.
      - `recorded_bundle_over_unauthorized_directory_reports_directory_0` (owner decision O-2 (c)). The chain base is unauthorized, so directory 0 is written.
        1. The host holds bundle 1 and alice's directory 2 (role:ops), with spoolInState.
        2. One capture offers bundle 2 from `f.rotationDropping` with its policy: policy 2 names admin bob (seedKey 12), and the bundle adds a next CA line that `h.run.rejectCA` refuses.
        3. Apply 1. Assert:
           - the error is ca_line_rejected, and `mustRecord(t, h, 2, 0)`;
           - current keeps alice's principals under bundle 1, whose policy authorizes them, and the report's DirectoryUnauthorized is false;
           - readAccepted's Bundle is 2 and its Directory is 0. The chain base is the record's bundle 2 over alice's directory 2, which policy 2 does not authorize.
        4. Set `h.run.rejectCA = nil`. Replace the spool's directory-2.json with bob's directory 2 (signer seedKey 12, other bytes). That is what a fetcher asking from 0 receives: the server's current directory.
        5. Apply 2. From the record, bob's directory 2 is accepted standalone at the same number, and bundle 2 is installed with bob's principals. Assert:
           - the error is nil;
           - readAccepted's Bundle is 2 and its Directory is 2;
           - the unapplied record is gone.

        RED on origin/main, because Task 1 implements WriteAccepted's rule and the standalone acceptance. On origin/main apply 1's readAccepted names directory 2, and apply 2 ignores bob's same-number directory, so the principals stay alice's.
      - `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle` (plan check 3, M-2).
        1. The host holds bundle 1 and alice's directory 1 (role:ops).
        2. One capture offers bundle 2 (f.rotation, policy 2: bob alone), alice's directory 2 and a newer KRL. The directory is signed under policy 1 and built on a re-made directory 1' (`h.f.directory(remade.Body, ...)` with `remade := h.f.directory(nil, ...)`), so it does not chain to the stored directory 1.
        3. Today's logic in step b holds at bundle 1, whose policy carries alice's quorum, and then refuses the chain (directory_not_verified).
        4. Assert:
           - the report's BundleVersion is 2 and BundleHeld is false;
           - no principals;
           - accepted/ holds bundle 2;
           - the KRL landed;
           - the error joins directory_not_authorized with directory_not_verified.

        RED on Task 2's head. There the chain refusal refuses the capture: the KRL lands alone under bundle 1, and alice's principals stay.
  </behavior>
  <read_first>
    - **Run B starts here with nothing of Run A in context.** First do the resume check and the reads under "What to read (executor)", Run B. Then read, on the branch:
      - the SUMMARY draft's `## Handoff to Task 3` (about 3 KB);
      - internal/agent/state/verify.go, whole (about 36 KB with Tasks 1 and 2). It holds checkStored, DirectoryUnderPolicy, Task 1's unauthorized branch of verifyDirectory, storedOnly, KRLAlone, holdBundle, and verifyBundle with Task 2's union;
      - internal/agent/apply/apply.go: forward with its no-change and sameBytes branches (`grep -n 'if !v.Changed()\|sameBytes(cur, g)\|return outcome('`), `func outcome(`, `func (e *engine) krlAlone(` and pollCapture's doc comment (about 10 KB);
      - internal/agent/apply/installed.go: `func WriteAccepted(` (about 2 KB);
      - internal/agent/apply/policy_change_test.go: the unauthorized-state helper the handoff names, and the tracer case (about 6 KB).
    - internal/agent/apply/rechain_test.go: `func TestResetDirectory(`. Read only its `diverged` helper (about 2 KB). Also the setup of the subtest `oversize_principals_file_krl_applied` (`grep -n 'bulkRoles = 17'`; about 1 KB).
    - internal/agent/apply/window_test.go: `func mustRecord(` and `func (f *fixture) rotationDropping(` (about 2 KB).
    - docs/runbooks/enroll-user.md: the paragraph ending "The signer is not fooled: it checks against the policy in force" (`grep -n 'not fooled'`; about 2 KB).
    - docs/runbooks/root-ceremony.md: "Rotate the roots (successor bundle)" step 6 (`grep -n '6. \*\*Install'`; about 2 KB).
    - docs/runbooks/signer-install.md: the step "Which hosts saw a lost version" (`grep -n 'Which hosts saw a lost version'`), through the end of its "Removing only the record does not converge" paragraph (about 5 KB). Since 03-08j, the step's accepted.json names, per kind, the accepted or recorded version, and its numbered steps read the accepted bundle from status.json.
    - docs/runbooks/host-setup.md (about 8 KB in all):
      - the outbox row of the file table (`grep -n 'the versions it accepted, which the fetcher'`);
      - the successor paragraph after "Revocations keep applying" (`grep -n 'A KRL that only a fully verified successor bundle'`);
      - "The record counts as an accepted version" (`grep -n 'The record counts as an accepted version'`);
      - the prune paragraph (`grep -n 'by the versions in .outbox/accepted.json.'`);
      - the record paragraph after it (`grep -n 'While a host holds an unapplied record'`);
      - the `diverged` item under `keyroster host status` (`grep -n '^- .diverged.'`).

      Each reads accepted.json's `directory` as the version the host accepted or recorded, or counts the spool from it.
    - .planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md, whole (about 3 KB).
  </read_first>
  <action>
Write the tests in `<behavior>` first.

- **REDs on origin/main.** Four cases test behaviour Task 1 already implements, or a shape whose control flips from main: `new_admins_next_version_accepted_standalone`, `same_capture_hold_then_dropped`, `rotation_first_then_removed_admin_refused` and `recorded_bundle_over_unauthorized_directory_reports_directory_0`. Take their RED from a scratch worktree of origin/main outside the checkout:
  - create it with `git worktree add <tmp> origin/main`;
  - add only a scratch test file holding copies of those four cases;
  - remove the worktree afterwards with `git worktree remove`.

  The copies must assert only on what exists on origin/main: principals, BundleVersion, krlRevokes, readAccepted, mustRecord, and error text through strings.Contains. They must not use ErrDirUnauthorized or any other symbol this plan adds, so that the RED fails on behaviour, not on the build.
- Take the other REDs on Task 2's head, the code commit the handoff names. Use a scratch worktree of that commit too (`git worktree add <tmp> <commit>`), because the branch's head then already holds the SUMMARY draft.
- Record each RED and where it was taken in the SUMMARY draft.

Then implement:

**verify.go.**
- *storedOnly* (and through it KRLAlone) sets DirectoryUnauthorized from checkStored under prev.policy when a stored directory exists. Its prev is accepted/, or during a widening wait the pending target's state.
- *Unauthorized, step b* (Planner decisions, plan check 3, M-2).
  1. Before today's logic runs, save v.Bundle, v.Policy, v.BundleHeld, v.BundleChanged and Next's bundle part (Bundle, BundleSigs, Policy, PolicySigs, BundleVersion).
  2. Run today's logic. When it accepts a directory, a hold included, return as today (PR #67).
  3. When it refuses with any refusal of the offered directories, do not return the refusal. That covers directory_older, directory_chain_gap, directory_installation and directory_not_verified for any cause: quorum, chain, parse, version, CheckPolicy. Instead:
     - restore the saved fields, so that a hold the refused directory set up (holdBundle runs before the parse, CheckInstallation, CheckPolicy and chain checks) is undone;
     - set v.DirectoryUnauthorized to unauth joined with the refusal;
     - return nil.

     Verify then keeps the newest verified bundle step, goes on to krlStep without BundleHeld, and the host stays fail-closed (Reconciliation I-2).
  4. stored_state_invalid, a stored directory that does not parse, is returned before unauth exists and stays an error.
- *Authorized, equal version.* When the newest offered version equals the stored version and its bytes differ:
  - If it carries v.Policy's admin quorum (VerifySignatures), refuse with `ErrDirFork`, naming the version. Both sides are then verified by the current quorum.
  - Otherwise refuse with ErrDir (directory_not_verified).
  - Equal bytes stay a no-op.

  The stored version is the chain base's, so the rule also applies at the unapplied record's directory version. pollCapture's doc sentence "a spool copy at the record's version adds no step" gains "unless it is the newest offered, which is directory_fork or directory_not_verified (F03 (03-08f))".

**apply.go.** forward's no-change branch (`if !v.Changed()`) is taken only when nothing changed and v.DirectoryUnauthorized is nil. With the flag set, forward renders and checks the candidate as for a change. When nothing changed and the candidate is sameBytes with cur, the run is a no-op:
- set NoOp as the no-change branch does;
- call setVersions;
- `return outcome(v)`.

All of this happens before the sameBytes branch, which commits, so an idle unauthorized run never stages an accepted/ snapshot. A generation that differs from current is installed through the normal path, which narrows, because it only removes principals.

**Runbooks (D-20).** Label every changed paragraph as run in CI, with the named tests and 03-08f. Also label it UNVERIFIED on the homelab: Phase 3 runs no admin-set change and no root rotation of enrolled hosts.
- **enroll-user.md.** After "The signer is not fooled: it checks against the policy in force", add the hosts' side:
  - an enrolled host checks its directory against the policy in force too;
  - while the new policy's admins have not signed it, the host renders no certificate principals (certificate logins to it are refused; authorized_keys and the console are not affected), and reports `directory_not_authorized`, which last_apply shows as refused;
  - **install the new admins' directory right after the bundle** (owner decision Q-F03a);
  - the host takes the first directory the new admins sign at its stored version or higher;
  - a host whose stored directory version is above anything the new admins have signed needs `sudo keyroster-agent reset-directory` (owner decision Q-F03b);
  - a host that already rendered such a directory before this change removes its principals at its first run that ends without a verification or KRL error. A run refused in verification or for its KRL (krl_not_verified, or krl_signer_retired) installs nothing (owner decision O-1 (a)). UNVERIFIED: no test builds the state from before this change together with a refused KRL;
  - installing the new admins' directory is the signer and CLI recovery that todo 2026-10-21 tracks for Phase 4.
- **root-ceremony.md, "Rotate the roots", after step 6.**
  - Enrolled hosts take a successor that keeps the policy unchanged at their next poll.
  - They verify it with the policy signatures delivered with that bundle, and `keyroster host status` shows the new bundle version on every host.
  - Until every host shows it, a retired root still anchors the hosts that have not taken it.
- **signer-install.md, "Which hosts saw a lost version".** Add one note after its opening sentences, which name accepted.json's per-kind accepted or recorded version:
  - A host's `accepted.json` reports directory 0 on purpose while the directory it chains from is not authorized by the policy it is under. That directory is the recorded one when the host holds a record, otherwise the accepted one. The fetcher then asks for the server's current directory. `last_apply` then usually names `directory_not_authorized`, or a refusal of the recorded state, such as `ca_line_rejected`.
  - The directory version the host actually holds is then named in `last_apply`'s error text, or is `directory.version` in `/var/lib/keyroster-agent/outbox/status.json`, the DIRECTORY column of `keyroster host status`. Use that version, not 0, to decide whether the host saw a lost directory.
  - A host that holds a lost directory version, and is offered the re-made version with that number as its newest, reports `directory_fork`.
  - Label: run in CI (`lagging_host_admin_removed_principals_dropped`, `recorded_bundle_over_unauthorized_directory_reports_directory_0`, `same_version_other_bytes_refused_as_fork`, 03-08f), UNVERIFIED on the homelab.
- **host-setup.md.**
  - *The outbox row of the file table:* accepted.json's directory is 0 on purpose while the directory the host chains from is not authorized (as in signer-install.md).
  - *After the successor paragraph* that follows "Revocations keep applying" (03-08k), one sentence (Reconciliation I-2): while the host's directory is not authorized (`directory_not_authorized`), a refused directory does not refuse the bundle, so the host installs the verified bundle with no principals, and the capture's KRL is checked with that bundle (03-08k's rules for the KRL step). Run in CI: `stored_version_above_new_admins_needs_reset`. A KRL signed by a new ops key in that shape is UNVERIFIED, reasoned from krlStep.
  - *"The record counts as an accepted version":* a different version with the same number is `directory_fork` when the current admin quorum signed it, and `directory_not_verified` otherwise. Run in CI for an accepted directory: `same_version_other_bytes_refused_as_fork`, `same_version_unsigned_bytes_not_verified`. At the record's version the same check runs on the record's bytes; this is reasoned from the code (UNVERIFIED: no test offers it there).
  - *The prune paragraph:*
    - the per-bundle policy signature file is kept and removed with its bundle;
    - the computed figures become about 6.1 GiB kept and 6.6 GiB in all (owner decision O-3 (a));
    - Run in CI: `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle`. The figures are computed from the caps, not measured.
  - *The record paragraph that follows the prune paragraph* (owner decision O-2 (c)):
    - accepted.json names the recorded versions while the recorded directory, or the accepted one when the record holds none, is authorized by the policy it is under. The fetcher then keeps fetching the versions after the record.
    - While that directory is not authorized, accepted.json's directory is 0, so the fetcher asks for the server's current directory and the prune keeps the newest 64 directory versions, as on a host that accepted none.
    - That includes a record whose bundle part rotates the policy over a directory part that the earlier policy signed. A host catching up across a policy rotation records that shape when it holds at its bundle in force and that directory is then refused for its content. Its directory then reads 0 while its bundle names the recorded version. With an honest server this is safe: after the rotation, the server's current directory is the new admins'.
    - Run in CI: `recorded_authorized_directory_keeps_the_record_raise`, `recorded_bundle_over_unauthorized_directory_reports_directory_0`, `held_content_refusal_keeps_the_records_bundle` (the mixed record).
  - *The `diverged` item:* it says to check the host's accepted.json. Add: when accepted.json's directory is 0 on a host that holds a directory, read the directory version from status.json instead.
- **Overlap.** 03-08b to 03-08e, 03-08j and 03-08k edit host-setup.md in other places. 03-08d and 03-08j edit signer-install.md's same step. This plan starts from an origin/main that holds them all. On a rebase conflict, keep their text and re-apply this plan's notes.

**The todo stays in pending/.** Add a Status section with two lines:
- The host-agent side is resolved in 03-08f (branch p03/08f-agent-policy-in-force). Hosts check the directory again under the policy in force, render no principals while it is unauthorized, and take the new admins' first directory at the same version or higher. A host whose stored version is above that needs an explicit reset-directory.
- Phase 4 variant (owner decision Q-F03b): the re-sign path should let the new admins sign their first directory above the old admins' highest version, so that no host needs the reset. The signer and CLI recovery in Solution stays open for Phase 4.

**Commits, mutants and the SUMMARY draft.**
1. Run both of the Budget's modes on the finished code and tests, with the stop rule.
2. Commit the code and tests by path, authored as the Delivery protocol says, as `fix(agent): keep a host fail-closed on every path while its directory is not authorized (F03)`.
3. Commit the runbooks and the todo as `docs(agent): describe hosts under the policy in force (03-08f)`.
4. Run the mutants below as the Budget's scripted loop.
5. Commit the SUMMARY draft as `docs(03-08f): record F03's edge evidence`.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/state/ && go test -race -count=1 -v -run "^TestDirectoryUnderPolicyInForce$|^TestRootRotationUnchangedPolicy$|^TestKRLAlone$/^(directory_rechain_refused_krl_applied|bundle_step_refused_krl_applied|ops_key_changed_krl_lands_alone|refusal_without_newer_krl_is_noop)$|^TestResetDirectory$|^TestWriteAccepted$|^TestKRLSigner$|^TestSpoolWindow$|^TestSpoolWindowWideningWait$" ./internal/agent/apply/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestDirectoryUnderPolicyInForce/lagging_host_admin_removed_principals_dropped", "--- PASS: TestDirectoryUnderPolicyInForce/new_admins_next_version_accepted_standalone", "--- PASS: TestDirectoryUnderPolicyInForce/same_capture_hold_then_dropped", "--- PASS: TestDirectoryUnderPolicyInForce/rotation_first_then_removed_admin_refused", "--- PASS: TestDirectoryUnderPolicyInForce/admin_set_unchanged_rotation_keeps_directory", "--- PASS: TestDirectoryUnderPolicyInForce/persisted_unauthorized_state_dropped_on_noop_capture", "--- PASS: TestDirectoryUnderPolicyInForce/refused_bundle_step_still_checks_directory", "--- PASS: TestDirectoryUnderPolicyInForce/stored_version_above_new_admins_needs_reset", "--- PASS: TestDirectoryUnderPolicyInForce/same_version_other_bytes_refused_as_fork", "--- PASS: TestDirectoryUnderPolicyInForce/same_version_unsigned_bytes_not_verified", "--- PASS: TestDirectoryUnderPolicyInForce/recorded_authorized_directory_keeps_the_record_raise", "--- PASS: TestDirectoryUnderPolicyInForce/recorded_bundle_over_unauthorized_directory_reports_directory_0", "--- PASS: TestDirectoryUnderPolicyInForce/unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle", "--- PASS: TestSpoolWindow/spool_copy_of_the_recorded_version_ignored", "--- PASS: TestSpoolWindow/held_content_refusal_keeps_the_records_bundle", "--- PASS: TestSpoolWindow/fetcher_cursor_follows_the_record", "--- PASS: TestWriteAccepted"</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/enroll-user.md | grep -c 'directory_not_authorized' && tr -s '[:space:]' ' ' < docs/runbooks/enroll-user.md | grep -ci 'right after the bundle' && tr -s '[:space:]' ' ' < docs/runbooks/root-ceremony.md | grep -c 'TestRootRotationUnchangedPolicy' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'directory_not_authorized' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'directory_fork' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'directory_not_authorized' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'per_bundle_policy_sigs_pruned_with_their_bundle' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'recorded_authorized_directory_keeps_the_record_raise' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'recorded_bundle_over_unauthorized_directory_reports_directory_0' && grep -c '03-08f' .planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md && grep -ci 'highest version' .planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md && test ! -e .planning/todos/completed/2026-10-21-recover-directory-after-admin-set-change.md</automated>
    <fails_when>non-zero exit, when any of these is missing or wrong: a runbook paragraph; the install-right-after instruction; the accepted.json note or the directory_fork sentence in signer-install.md; the accepted.json, prune or record notes in host-setup.md; the todo's status or its Phase 4 variant; or the todo was moved although its signer half is open</fails_when>
  </verify>
  <acceptance_criteria>
    - The SUMMARY draft records Task 3's two runs, and lists these mutants. Each is applied to Task 3's code commit, run against its named test, and restored byte for byte:
      - the check skipped in storedOnly: killed by `refused_bundle_step_still_checks_directory`;
      - the forced render removed: killed by `persisted_unauthorized_state_dropped_on_noop_capture`;
      - the forced render's no-op test removed, so an unchanged unauthorized capture reaches the sameBytes commit: killed by `persisted_unauthorized_state_dropped_on_noop_capture`'s second apply (NoOp, the snapshot unchanged) and by the tracer's second apply;
      - WriteAccepted's zero rule removed, so accepted.json names the stored directory version while the chain base's directory is unauthorized: killed by the tracer's readAccepted assertions and by `recorded_bundle_over_unauthorized_directory_reports_directory_0`;
      - Report.DirectoryUnauthorized not set from v right after Verify: killed by the tracer's second-apply assertion on the report's DirectoryUnauthorized (plan check 3, m-3). On this commit an unauthorized idle run returns through the forced no-op, which reports the flag that assignment set. `if !v.Changed()` is reached there only with the flag nil, so a mutant on that branch alone would be equivalent;
      - WriteAccepted writing directory 0 whenever the run's report is unauthorized (O-2 reading (a)): killed by `recorded_authorized_directory_keeps_the_record_raise`, whose step 4 then reads 0 instead of 3;
      - WriteAccepted keeping the record's raise whatever the chain base's directory (O-2 reading (b)): killed by `recorded_bundle_over_unauthorized_directory_reports_directory_0`, whose apply 1 then reads 2 instead of 0;
      - WriteAccepted checking accepted/'s directory under accepted/'s policy instead of the chain base's: killed by both record cases. accepted/ is unauthorized in the first, so it reads 0 instead of 3, and authorized in the second, so it reads 2 instead of 0;
      - outcome not joining DirectoryUnauthorized: killed by the tracer's assertion that the error wraps state.ErrDirUnauthorized;
      - state.ErrDirUnauthorized left out of status.go's refusals: killed by `TestStatus/apply_result`;
      - the fork comparison removed: killed by `same_version_other_bytes_refused_as_fork`;
      - the fork reported without the quorum check: killed by `same_version_unsigned_bytes_not_verified`;
      - the standalone acceptance chained to the stored bytes: killed by `new_admins_next_version_accepted_standalone`;
      - the unauthorized case returning today's refusal: killed by `stored_version_above_new_admins_needs_reset` and `rotation_first_then_removed_admin_refused`;
      - no restore: step b converts the refusal without restoring the saved bundle part (plan check 3, M-2). Killed by `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle`: BundleVersion 1 and BundleHeld true.
    - No case pins the conversion of directory_installation or of a parse or version refusal. They take the same branch as the chain refusal the new case pins, and the SUMMARY records them as UNVERIFIED by test.
    - Every new or changed runbook sentence names at least one CI test or says UNVERIFIED.
    - `git status --porcelain -- internal/ docs/ .planning/todos/` prints nothing after the last commit.
  </acceptance_criteria>
  <done>Hosts follow the policy in force for the directory in every path: forward, the polls, storedOnly, refusals, the record, and same-number replacements. The runbooks and the todo say what hosts do and what operators must do.</done>
</task>

<task type="auto">
  <name>Task 4: The publish edits, the gates, the PR and the SUMMARY</name>
  <precondition>One of these holds on a Windows checkout, where scripts/linux.sh runs the command string through wsl.exe:
    - `grep -q -- '--exec' scripts/linux.sh` exits 0 on the branch. This is the normal case. PR #81 (b1ebff3) put `--exec` into scripts/linux.sh on main before this plan's branch was created from it. wsl.exe `--exec` hands the string to WSL's login shell unexpanded, so the gate's `test -z "$(gofmt -l .)"` runs where gofmt is on PATH.
    - Only if that grep fails (a branch created from a main before PR #81), before the gate, the executor runs gofmt from a script file in WSL's login shell. The script's first line prints `command -v gofmt`, its second `go version`, and its third is `test -z "$(gofmt -l .)"`. The run counts only when it printed gofmt's path and exited 0, and the SUMMARY records its output and notes the gate's own gofmt step as vacuous. This is what 03-08k's fix round 1 did, now with proof that gofmt ran.

    The gate command itself stays as written. On a Linux checkout, scripts/linux.sh runs `bash -c` and neither is needed.
  </precondition>
  <files>.planning/phases/03-linux-agent-and-revocation/03-08f-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - .planning/ROADMAP.md: Phase 3's Plans line and its wave blocks (`grep -n 'Wave\|Plans:'`).
    - .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter and Task 1's precondition.
    - The `wave:` lines of 03-10 to 03-16.
  </read_first>
  <action>
**Publish edits.** Make them in this PR, on top of origin/main, which holds 03-08d, 03-08e, 03-08j and 03-08k. Every number is origin/main's value + 1. The values in brackets are what main holds at 682782e (Reconciliation item 5): N/25 plans in 24 waves, total_plans 60, `of 25`, 03-09 at wave 17 depending on 03-08k, and 03-10 to 03-16 at waves 18 to 24.
1. Commit this plan unchanged as `.planning/phases/03-linux-agent-and-revocation/03-08f-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each go up by one (N/25 in 24 waves → N/26 in 25 waves).
   - After 03-08k's Wave 16 block, insert `**Wave 17** *(blocked on Wave 16 completion)*` with this unchecked entry: `03-08f-PLAN.md — The policy in force decides what a host trusts (F02, F03): the stored directory checked again under it (no principals while unauthorized, the new admins' directory taken at the same version or higher), and rotations that keep the policy verified with the signatures delivered per bundle`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 17–24 → 18–25), and update each block's "blocked on Wave N completion" clause with them.
   - Add nothing about any other plan.
3. STATE.md: `total_plans` + 1 (60 → 61), and the Plan line's `of M` + 1 (of 25 → of 26).
4. 03-09-PLAN.md:
   - `wave:` + 1 (17 → 18);
   - `depends_on` becomes `["03-08f"]`;
   - Task 1's `<precondition>` gains the clause "`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md` exits 0". It goes next to the 03-08c, 03-08d, 03-08e, 03-08j and 03-08k clauses, which stay.
5. The `wave:` lines of 03-10 to 03-16 each go up by one (18–24 → 19–25).
6. **Guard.** If origin/main's 03-09 does not hold `wave: 17` and `depends_on: ["03-08k"]`, another plan was slotted in first. Apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY. The automated checks below compute from origin/main, so they hold either way.

**Gates.** Run the Budget's alone gate first (internal/agent/apply alone, limit 400 s), then the full gate locally, whose `./...` run checks the 480 s margin. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record, as 03-08k's was.

**Push and the PR.**
1. Commit by path only, authored as the Delivery protocol says.
2. Push the branch.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(agent): verify rotations and the directory under the policy in force (F02, F03)"` with a neutral body. Do not enable auto-merge, now or later (owner, 2026-11-02).
4. Wait for the required checks.
5. Record internal/agent/apply's time under -race from the PR's build-test log beside the local figures of Tasks 1 to 4. CI runs `./...`, so its limit is the 480 s margin. Above it, stop before the merge gate and report to the owner with the two options under Budget; the executor does not choose.

**The SUMMARY.** Complete the draft with:
- the PR number and the check run IDs;
- the RED evidence of each task, with where each RED was taken;
- the mutants of Tasks 2 and 3;
- the existing tests the change flipped, with the reason for each;
- the trust/verify.go lines the threshold argument rests on;
- a note on the stored-sigs rule. When the union was needed and neither admitted source passes VerifySuccessor alone, the stored file (the offered file, or the delivered one) may not pass on its own. That is safe. The next hop's plain check then fails with ErrThreshold, not a parse error, because the stored file was admitted. So it reaches the union with that hop's delivered signatures and recovers (`malformed_delivered_sigs_not_stored` shows the next hop passing);
- the owner's answers to O-1, O-2 and O-3, and where each shaped the code;
- the local times of Tasks 1 to 4 in both modes (alone against 400 s, `./...` against 480 s), origin/main's CI time and the PR's CI time;
- the gofmt evidence of this task's precondition;
- capslock;
- `requirements-completed` left empty, because AGENT-03 and AUTHZ-02 were completed by earlier plans and this plan hardens them.

Then run the tracking updates once, commit `docs(03-08f): complete agent policy-in-force plan` (authored as the Delivery protocol says), push, and wait.
  </action>
  <verify>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit (a test failed, or internal/agent/apply's `ok` line is missing or above the 400 s budget), or "FAIL" or "DATA RACE" in the output</fails_when>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit (a gate failed, or internal/agent/apply's `ok` line under `./...` is missing or above the 480 s margin), or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')"</automated>
    <fails_when>non-zero exit (the branch has no commits, or a commit has another author or a committer other than keyroster-bot)</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && ( for n in 09 10 11 12 13 14 15 16; do X=$(git show origin/main:$P/03-$n-PLAN.md) || exit 1; W=$(printf '%s\n' "$X" | sed -n 's/^wave: //p'); test -n "$W" && grep -qx "wave: $((W+1))" $P/03-$n-PLAN.md || exit 1; done ) && grep -qx 'depends_on: \["03-08f"\]' $P/03-09-PLAN.md && grep -c '03-08f-SUMMARY.md' $P/03-09-PLAN.md && ST=$(git show origin/main:.planning/STATE.md) && T=$(printf '%s\n' "$ST" | sed -n 's/^  total_plans: //p') && test -n "$T" && grep -qx "  total_plans: $((T+1))" .planning/STATE.md && O=$(printf '%s\n' "$ST" | sed -n 's/^Plan: [0-9]* of \([0-9]*\)$/\1/p') && test -n "$O" && grep -Eq "^Plan: [0-9]+ of $((O+1))$" .planning/STATE.md && RM=$(git show origin/main:.planning/ROADMAP.md) && R=$(printf '%s\n' "$RM" | grep -m1 -oE '[0-9]+/[0-9]+ plans executed in [0-9]+ waves') && M=$(printf '%s' "$R" | sed -E 's#^[0-9]+/([0-9]+) .*#\1#') && V=$(printf '%s' "$R" | sed -E 's#.* in ([0-9]+) waves#\1#') && grep -Eq "[0-9]+/$((M+1)) plans executed in $((V+1)) waves" .planning/ROADMAP.md && grep -c '03-08f-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit: a publish edit is missing or wrong. Each of these is checked against origin/main's value + 1: the waves of 03-09 to 03-16, 03-09's dependency and its new precondition clause, STATE's total_plans and `of M`, the ROADMAP Plans line's total and wave count, and the ROADMAP row</fails_when>
    <automated>RM=$(git show origin/main:.planning/ROADMAP.md) && X=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md) && W9=$(printf '%s\n' "$X" | sed -n 's/^wave: //p') && test -n "$W9" && N0=$(printf '%s\n' "$RM" | awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}') && N1=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}' .planning/ROADMAP.md) && test "$N1" -eq "$((N0+1))" && awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; n++; if (w!=n) bad=1; if (w>1 && index($0,"*(blocked on Wave " (w-1) " completion)*")==0) bad=1} END{exit bad}' .planning/ROADMAP.md && K8=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-08f-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K8" | grep -q "^\*\*Wave $W9\*\*" && K9=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-09-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K9" | grep -q "^\*\*Wave $((W9+1))\*\*"</automated>
    <fails_when>non-zero exit: any of these fails in Phase 3 of the ROADMAP:
      - the wave headers number one more than on origin/main;
      - they run 1..N in order;
      - every block N above 1 says "blocked on Wave N-1 completion";
      - the 03-08f row sits under the wave origin/main's 03-09 had, and the 03-09 row one wave later.
    </fails_when>
    <automated>git fetch origin p03/08f-agent-policy-in-force && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08f-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08f-agent-policy-in-force --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/08f-agent-policy-in-force --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled on the PR)</fails_when>
  </verify>
  <acceptance_criteria>
    - The SUMMARY records internal/agent/apply's times under -race, or, for a figure above its limit, the owner's choice:
      - alone: Task 1's base and Tasks 1, 2, 3 and 4, none above 400 s;
      - under `./...`: Task 1's base, Tasks 1, 2 and 3, and Task 4's full gate, plus origin/main's CI time and the PR's CI time, none above 480 s.
    - `git log origin/main..HEAD --format='%an <%ae> %cn'` prints at least one line, and every line it prints is `Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot`.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0. `B=$(scripts/gh-as-bot.sh pr view p03/08f-agent-policy-in-force --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08f-SUMMARY.md is on its head. The PR title and every commit message name findings only by F-number.
  </acceptance_criteria>
  <done>The PR waits green, with the plan and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — the owner reviews PR p03/08f-agent-policy-in-force, and Daniel squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7), read with this plan's Delivery protocol override (merge-gate.sh's plain form only after the merge)
  </read_first>
  <action>After the pre-merge review, the owner reviews, approves and squash-merges the PR in the GitHub web UI (owner, 2026-11-02). Claude never approves or merges, never enables auto-merge and never waits for it.</action>
  <instructions>
    1. Open `gh pr view p03/08f-agent-policy-in-force --web`. Read 03-08f-SUMMARY.md, and review:
       - checkStored and the standalone acceptance;
       - Render while unauthorized, and the forced render's no-op;
       - WriteAccepted's directory 0 while the chain base's directory is unauthorized, and the record's raise otherwise (owner decision O-2 (c));
       - the fork rule;
       - the union on ErrThreshold, what accepted/ and unapplied.json store, and pruneSpool's per-bundle file.

       Check especially:
       - no threshold comes from the signatures;
       - the bundle signatures are never united;
       - a rejected signature file is never stored;
       - no principals render from a directory the policy in force does not authorize, on any path that returns a state.
    2. Approve and squash-merge in the GitHub web UI, with your commit email. No admin bypass, no "Update branch".
    3. Reply "merged". If main moved before you merged, Claude rebases the branch by hand and pushes it. Review the new head, then merge it and reply "merged".
  </instructions>
  <verification>
    - **Before the merge.** Claude runs merge-gate.sh only as `bash scripts/merge-gate.sh --check p03/08f-agent-policy-in-force`, which is read-only and exits 1 while the PR is open. It never runs the plain form before the merge: the plain form may rebase and push the branch itself (exit 3), and this plan rebases by hand.
    - **When main moved.** If `git merge-base --is-ancestor origin/main origin/p03/08f-agent-policy-in-force` fails after `git fetch origin`, Claude rebases by hand:
      - on the branch, `git rebase --gpg-sign origin/main`. The authors stay Daniel's, and keyroster-bot is committer and signer;
      - for `.planning/` tracking files, take origin/main's version and re-apply only this plan's entries, as 01-SKELETON step 5's exit 4 describes. For the runbooks, keep main's text and re-apply this plan's notes;
      - push with lease, as keyroster-bot;
      - do not enable auto-merge;
      - wait for the required checks, check the authorship again with Task 4's `git log` check, and ask the owner to review the new head.
    - **After the owner replies "merged".** From the main checkout, Claude runs `bash scripts/merge-gate.sh p03/08f-agent-policy-in-force` (the script refuses to run as any copy but origin/main's). For a merged PR, it only fast-forwards local main and exits 0. Then Claude runs the `--check` form below.
  </verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08f-agent-policy-in-force</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-09's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08f-agent-policy-in-force --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>Hosts follow the policy in force on main, and 03-09 may start.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08d** gives this plan KRLAlone, which uses storedOnly. storedOnly now carries DirectoryUnauthorized, so a KRL-alone generation never renders a directory the policy in force does not authorize. 03-08d's no-directory fallback, which keeps last-good's principals, is never reached from the unauthorized state, because the stored directory is kept.
- **03-08e** gives this plan spool.Cap, checkCaps, healSpool and pruneSpool. This plan adds `bundle-<N>.policy.sigs` to all four.
- **03-08j.**
  - Its unapplied record is the chain base on the record path, so checkStored checks the record's directory part when there is one.
  - Its bundle part copies Next.PolicySigs, which the stored-sigs rule governs.
  - WriteAccepted's raise meets this plan's directory 0. The raise wins while the chain base's directory is authorized (owner decision O-2 (c)).
  - TestSpoolWindow and TestSpoolWindowWideningWait stay green. The shapes that rotate the policy to bob hold at the bundle in force, where the flag stays clear.
- **03-08k.**
  - This plan changes storedOnly, which KRLAlone calls, and verify's directory step, and joins outcome. TestKRLSigner stays green, including the five wait cases' `poll` and `forward` subtests, as 03-08k's Cross-plan notes require.
  - The rotations F02 verifies raise fullyVerified, and 03-08k's rules then decide their KRLs (Reconciliation I-1).
  - While unauthorized, a refused directory step goes to krlStep instead of the KRL-alone pass (I-2).
- Every test of 03-08d, 03-08e, 03-08j and 03-08k stays green, apart from the changed tests that Task 1 names with their reasons.
- **03-08b to 03-08e, 03-08j and 03-08k** edit docs/runbooks/host-setup.md in other places. 03-08d and 03-08j edit signer-install.md's same step. No code file overlaps 03-08c. On a rebase conflict, keep their text and re-apply this plan's notes (Task 3).
- **03-12 and 03-13 (check 1).** Neither is a prerequisite (see context). Their successors still pass on the first VerifySuccessor call, and `same_roots_unchanged_policy_accepted` pins that shape and what accepted/ stores for it.
- **Later plans that edit the same files** must keep TestDirectoryUnderPolicyInForce and TestRootRotationUnchangedPolicy green:
  - 03-13 edits state/verify.go;
  - 03-12 edits render.go and run.go; its draining-CA re-render must respect DirectoryUnauthorized;
  - 03-09, 03-10 and 03-14 edit apply.go;
  - 03-10 and 03-14 edit render.go.
- **A later plan that changes pruneSpool's window** keeps the per-bundle file with its bundle (`TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle`), and recomputes the bound with it.
- **03-15** (v4 ceremony) changes roots and policy together, so it takes the changed-policy branch, and nothing here changes what it relies on.
- **Phase 4 (AUTHZ-03)** makes changes to the admin set routine. The fail-closed window (owner decision Q-F03a) then needs the new admins' directory installed right after the bundle. The re-sign path should let them sign above the old admins' highest version (owner decision Q-F03b, noted in todo 2026-10-21).

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: an honest change of the admin set.** Hosts refuse certificate logins between the bundle and the new admins' directory, just as the signer refuses issuance (owner decision Q-F03a).

**Flagged assumption: standalone acceptance.** The newest directory at or above the stored version that the current quorum signed is accepted without a chain, like reset-directory's first-install rule. A compromised server can choose which such directory to serve. That residual is the same as item 2 of the reset todo.

**Edges:**
- adjacency: the stored version itself with other bytes, signed or unsigned; versions above it; a version above anything the new admins signed;
- ordering:
  - rotation and directory in one capture;
  - the hold for one capture;
  - rotation first, then the removed admin's directory, which now joins the unauthorized state;
  - a hold that a later chain refusal undoes, so the newest verified bundle is kept;
- persistence: the pre-fix state on a no-op capture, and through a refused bundle step; the idle unauthorized run, which commits nothing;
- the record (owner decision O-2 (c)):
  - the new admins' directory recorded for its content while accepted/ is unauthorized, where the record's raise wins and the chain goes on;
  - a recorded policy-rotating bundle over the old admins' directory, where directory 0 is written and the same-number directory recovers;
  - the fork rule at the record's version (reasoned, UNVERIFIED);
- thresholds: one, two and three hops; duplicated, foreign and malformed blocks; a growing root set; a malformed delivered file never stored;
- the spool: the per-bundle file pruned with its bundle, and an orphan pruned;
- the controls that must not change: same roots; an unchanged admin set; the hold shapes of 03-08j and 03-08k.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Rotated trust and revoked authority take effect across the fleet | Tasks 1-3 |
| REQ | AGENT-03 (only what the pinned roots and delegated keys signed) | Tasks 1-3 |
| REQ | AUTHZ-02 (principals from the signed host policy in force) | Tasks 1, 3 |
| Finding | F02 (a rotation that keeps the policy is refused; retired roots keep anchoring; multi-hop signatures lost in the spool) | Task 2, Task 3 runbook |
| Finding | F03 (a directory signed only by a removed admin stays in force; a same-number replacement is ignored) | Tasks 1, 3 |
| Todo | 2026-10-21-recover-directory-after-admin-set-change: the signer and CLI recovery | Out of scope here. The todo keeps it, and Task 3 adds the status line and the Phase 4 variant |
| CONTEXT | D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 3 |
| Owner decision | Q-split, Q-F03a, Q-F03b, grades, scope, delivery and pushing before the merge (2026-10-29) | Owner decisions block, Tasks 1-4 |
| Owner decision | Authorship and merge, and the test-time limits (2026-11-02) | Delivery protocol, Budget, Tasks 1-5 |
| Owner decision | O-1 (a), O-2 (c), O-3 (a), and the planner's must-have additions kept (2026-11-03) | Truths 2, 3 and 7; Tasks 1-3; T-03-300, T-03-305, T-03-323 |
| Merged plan | 03-08e's pruneSpool (fix rounds 1-3) | Task 2, Task 3 runbook; O-3 |
| Merged plan | 03-08j's unapplied record (Base, VerifyAhead, WriteAccepted's raise, the in-force hold step, pollCapture) | Tasks 1, 3; O-2 |
| Merged plan | 03-08k's outcome, refusals, krlStep, KRLAlone's from and fullyVerified | Tasks 1, 3; Reconciliation I-1 to I-3, O-1 |
| Check 1 | Do 03-12 and 03-13 take the unchanged-policy branch? | Context (yes, but they are accepted; not a prerequisite), `same_roots_unchanged_policy_accepted` |
| Finding fix, optional parts | The server re-offering its current directory; refusing the hold path | Deferred with reasons in the ledger |

## Artifacts this phase produces (this plan)

- **state:**
  - `ErrDirUnauthorized` (`directory_not_authorized`) and `ErrDirFork` (`directory_fork`);
  - `Verified.DirectoryUnauthorized` and checkStored;
  - standalone recovery;
  - the fork rule;
  - the policy-signature union on ErrThreshold, and the stored-sigs rule.
- **spool:** `State.BundlePolicySigs` and `bundle-<N>.policy.sigs`.
- **fetch:** the per-bundle policy signatures are written, dropped and pruned with their bundle.
- **apply:**
  - Render while unauthorized, and the host fill in engine.render;
  - forward's forced render and its no-op;
  - outcome's unauthorized error and `Report.DirectoryUnauthorized`;
  - accepted.json's directory 0 while the chain base's directory is unauthorized (WriteAccepted, Stored.DirectoryUnderPolicy);
  - the two refusals in status.go.
- **Tests:**
  - TestDirectoryUnderPolicyInForce (13 cases) and TestRootRotationUnchangedPolicy (11 cases);
  - the readAccepted assertion added to TestSpoolWindow/held_content_refusal_keeps_the_records_bundle;
  - the additions to TestSpool, TestFetch, TestSpoolPrune and TestStatus/apply_result;
  - the changed TestApply/torn_accepted_save_never_mixes.
- **Docs:**
  - enroll-user.md: hosts and the policy in force, installing the new admins' directory right after the bundle, and the reset;
  - root-ceremony.md: hosts take a rotation that keeps the policy;
  - signer-install.md and host-setup.md: where to read the stored directory version while accepted.json reports 0, directory_fork, the refused directory while unauthorized, and the prune's per-bundle file and bound;
  - the todo's status line, with the Phase 4 variant.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| offline roots → hosts | The root-signed bundle chain decides which roots and which policy a host trusts. A rotation must move every host off retired roots |
| admin quorum of the policy in force → hosts | Only that quorum's directory may produce principals on a host |
| keyroster-server and fetcher → root applier | Lower-trust delivery. They may withhold, reorder or offer stale or forked documents, but must not make the host keep what the policy retired |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-300 | Elevation of privilege | state.verifyDirectory and storedOnly: a host keeps rendering a directory signed only by an admin that the root-signed policy in force removed (F03) | medium | mitigate | **Mitigation.** Every verification and storedOnly checks the stored directory again under the policy in force: the chain base's directory in verify, the unapplied record's included. While it is unauthorized, Render emits no principals, the apply reports directory_not_authorized as a refusal, and refusals of offered directories no longer block the newest verified bundle step; a hold the refused directory set up is undone. The new admins' first directory at the stored version or higher is accepted standalone. It arrives at the same number through accepted.json's directory 0, which WriteAccepted writes while the chain base's directory is unauthorized (owner decision O-2 (c)). Tests: `lagging_host_admin_removed_principals_dropped`, `same_capture_hold_then_dropped`, `persisted_unauthorized_state_dropped_on_noop_capture`, `refused_bundle_step_still_checks_directory`, `stored_version_above_new_admins_needs_reset`, `recorded_authorized_directory_keeps_the_record_raise`, `recorded_bundle_over_unauthorized_directory_reports_directory_0`, `rotation_first_then_removed_admin_refused`, `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle`. **Residuals.** (1) PR #67's hold path, 03-08j's in-force hold step included, renders such a directory for one capture before the next capture drops it. (2) A delivery that holds the removed admin's key can keep a host on the pre-rotation bundle by offering ever newer old-policy directories, and the host then visibly reports the old bundle, as when the rotation is withheld. (3) A host whose stored version is above anything the new admins signed needs reset-directory, and stays fail-closed until then (owner decision Q-F03b). (4) While a host's chain base directory is unauthorized, its fetcher asks from directory 0 at every poll, so the server re-sends its current directory (up to 1 MiB) each time, and pruneSpool keeps the newest 64 directory versions. This lasts only as long as the unauthorized window (O-2 (c)). It includes the mixed record {3, 65} that `TestSpoolWindow/held_content_refusal_keeps_the_records_bundle` builds through mergeUnapplied. There the record's bundle 3 rotates the policy, and its directory part 65 is the old admins', taken by the in-force hold and then refused for its content. Its accepted.json reads bundle 3 and directory 0, so the record's raise is lost for the directory. That is the owner's rule as decided, and it is safe with an honest server, whose current directory after the rotation is the new admins'. (5) A host that held the bad state before this plan, on a run that ends with a Verify or KRL-alone error, is the accepted T-03-323 |
| T-03-301 | Denial of service | certificate logins on enrolled hosts during an honest change of the admin set, between the bundle and the new admins' directory (this plan's fail-closed rule) | low | accept | Owner decision Q-F03a. This follows the signer's T-02-15, which refuses issuance in the same window. authorized_keys and the console are unaffected. enroll-user.md says to install the new admins' directory right after the bundle. A change that keeps the admins and the quorum is unaffected (`admin_set_unchanged_rotation_keeps_directory`) |
| T-03-302 | Tampering | a same-number directory with other bytes treated as a silent no-op (F03) | low | mitigate | **Mitigation.** `directory_fork` when both sides carry the current admin quorum, and `directory_not_verified` otherwise, at the accepted version and at the unapplied record's. D-R2 keeps the KRL. Tests: `same_version_other_bytes_refused_as_fork`, `same_version_unsigned_bytes_not_verified`. **Note.** Like every refused directory step, a fork or not_verified refusal also discards, for that capture, a bundle successor offered with it, and D-R2 then takes only the KRL. Since 03-08k, that KRL-alone pass also verifies the KRL under the capture's fully verified successor (Q2), so a successor-signed KRL still lands. This is no new capability: a spool writer can already cause the same with a bad newer directory, and the bundle step is taken at the next capture without the offending file |
| T-03-303 | Elevation of privilege | state.verifyBundle: a documented rotation to new roots with the policy unchanged is refused, so hosts keep the retired roots as anchors and accept a fork signed by a retired root (F02) | medium | mitigate | One retry with the united policy signatures on trust.ErrThreshold, and per-bundle policy signatures in the spool. Tests: `one_hop_new_roots`, `three_hops_in_one_capture`, `spool_without_per_bundle_sigs_one_hop`, `retired_root_fork_refused_after_rotation`. **Residual:** a host that has not polled since the rotation is still anchored by the retired roots, and `keyroster host status` shows its bundle version. A rotation that also names a new ops key retires the old key's KRLs under 03-08k's rules (Reconciliation I-1); no shipped ceremony produces that shape |
| T-03-304 | Elevation of privilege | the union itself: a spool writer adding blocks to lower a root threshold (this plan's own risk) | high | mitigate | The thresholds come only from the bundles. CountPinnedSigners counts a root once, and only for a valid signature over the exact policy bytes under the policy namespace. The bundle signatures are never united. Sources that ParseAll rejects are never admitted and never stored, and the union is tried only after ErrThreshold. Tests: `union_never_lowers_threshold`, `malformed_delivered_sigs_change_nothing`, `malformed_delivered_sigs_not_stored`, `same_roots_unchanged_policy_accepted`. The prohibition |
| T-03-305 | Denial of service | accepted/ or unapplied.json growing past their caps through stored policy signatures; the spool growing through per-bundle policy signature files the prune never removes; or a stored malformed file bringing F02 back at the next hop | low | mitigate | Next.PolicySigs is one admitted file read under spool.MaxBundle, never the union and never a rejected source. unapplied.json copies it under the same cap (ParseUnapplied). pruneSpool keeps a per-bundle file exactly while it keeps its bundle, and removes an orphan. The spool's computed bound grows to about 6.1 GiB kept and 6.6 GiB in all, which the owner accepted (O-3 (a)). Tests: `stored_policy_sigs_stay_bounded`, `malformed_delivered_sigs_not_stored`, `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle` |
| T-03-323 | Elevation of privilege | a host that already rendered a removed admin's directory before this plan, on a run whose Verify or KRL-alone pass returns an error (owner decision O-1 (a)) | low | accept | **Why accepted.** Such a run installs nothing, as on main, so current keeps those principals until the host's first run that ends without such an error. The errors are krl_not_verified, krl_older, krl_header_version_mismatch, or 03-08k's krl_signer_retired on the KRL step without a held step or in KRLAlone. A spool writer that keeps such a KRL newest can extend the state. Only state from before this plan is affected: after it, every commit of an unauthorized state installs the trust-only generation. Phase 3 changes no admin set and rotates no roots on an enrolled host, so no enrolled host holds the state. **Documentation.** enroll-user.md names the residual, labelled UNVERIFIED: no test builds the state from before this plan together with a refused KRL |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added. internal/trust is unchanged. The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh).
- The Budget's alone gate and its `./...` margin hold.
- The full gate passes, with gofmt shown to have run (Task 4's precondition).
- The PR's required checks are green, and the merge gate passes after Daniel's merge.
</verification>

<success_criteria>
- No enrolled host renders principals from a directory that the admin quorum of the policy in force did not sign, on any path that returns a state.
- Enrolled hosts accept a root rotation that keeps the policy, and afterwards refuse a fork signed by retired roots.
- No root threshold is lowered, and the trust package is unchanged. accepted/ and unapplied.json store only an admitted signature file, and the spool removes each per-bundle file with its bundle.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md` as a draft from Task 1 on, and complete it in Task 4, before the merge gate. Leave `requirements-completed` empty: AGENT-03 and AUTHZ-02 were completed by earlier plans, and this plan hardens them. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (findings F02 and F03, and the owner decisions of 2026-10-29)

### Round 1 — plan check 1 (2026-10-29, PASS WITH FIXES), with owner decisions Q-split, Q-F03a and Q-F03b

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| F03: the stored directory is never checked again under a new policy; a same-number replacement is ignored, and the next version is refused | MEDIUM | must_haves truths 2-4; Tasks 1, 3; T-03-300, T-03-302 |
| F02: findPolicy returns the stored policy signatures for an unchanged policy, so rotations to new roots are refused; the spool keeps only the last bundle's policy signatures | MEDIUM | must_haves truths 5-7; Task 2; T-03-303 |
| Check 3: the union must not lower a root threshold | HIGH | Truth 6 with the code facts; union only on ErrThreshold and only from admitted sources; `union_never_lowers_threshold`; T-03-304 |
| Check item 1 (MAJOR): a malformed per-bundle file could be stored and bring F02 back at the next hop | MAJOR | Stored-sigs rule: only an admitted source, preferring one that passes VerifySuccessor alone, else the offered file; `malformed_delivered_sigs_not_stored`; T-03-305 |
| Check item 2 (MAJOR): the union mutant could not be killed | MAJOR | Redefined as "built unfiltered and tried before the plain check", killed by `malformed_delivered_sigs_change_nothing` and by `same_roots_unchanged_policy_accepted`'s check of the stored PolicySigs |
| Check item 3: REDs for behaviour Task 1 implements | MINOR | Those cases take their RED on an origin/main worktree. The forced render, the storedOnly check, the refusal conversion and the fork rule moved to Task 3, after their tests |
| Check item 4: directory_fork without a signature check | MINOR | directory_fork only when the current quorum signed the offered side too, else directory_not_verified; `same_version_unsigned_bytes_not_verified` |
| Check item 5: the hard-coded 03-16 wave | MINOR | Task 4 checks origin/main's wave + 1 |
| Check item 6: the frontmatter plan ID | MINOR | Superseded by owner decision Q-split: `plan: 08f` |
| Check item 7: the tight budget | WARNING | The publish edits moved into their own Task 4 (precedent: 03-08c's four implementation tasks); read_first scoped to functions |
| Owner decision Q-F03a: keep the window; runbook instruction | — | Truth 3; Task 3 enroll-user.md; T-03-301 |
| Owner decision Q-F03b: same version or higher; explicit reset; Phase 4 variant in the todo | — | Truths 2 and 4; `stored_version_above_new_admins_needs_reset`; Task 3 todo Status |
| Planner: setting the unauthorized directory to nil would let 03-08d's no-directory fallback keep last-good's principals | HIGH | The flag is derived on every run, and the stored directory is kept |

### Round 2 — reconciliation against main 682782e (2026-11-02, after 03-08e, 03-08j and 03-08k merged)

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Stale anchors: verify's chain, alone, carried and pending; KRLAlone's from; outcome; pollCapture; krlStep; VerifyAfter and VerifyAheadAfter; file sizes; the read_first grep for forward's returns | MINOR | Revision note; Task 1's precondition and read_first; context |
| pruneSpool (03-08e) never removes `bundle-<N>.policy.sigs`, so the spool grows without bound | MAJOR | Task 2: spoolSet; `TestSpoolPrune/per_bundle_policy_sigs_pruned_with_their_bundle`; its mutant; T-03-305; O-3 for the new bound |
| WriteAccepted's raise to the unapplied record (03-08j) meets directory 0, and one record shape stalls | MAJOR | Task 1's helper (O-2 reading (a)); `unauthorized_with_a_recorded_directory` and its mutant; O-2 for the owner, with options. Superseded in Round 3 by the answer (c) |
| forward returns through outcome, and main's sameBytes branch commits | MINOR | Task 1 joins outcome; Task 3's forced render tests for a no-op before the commit; two mutants |
| status.go's refusals lack the new codes, so last_apply.result would read error | MINOR | Task 1; TestStatus/apply_result; its mutant |
| engine.render fills the host only on its fallback path | MINOR | Task 1's host fill |
| TestApply/torn_accepted_save_never_mixes flips under F03 | MINOR | Task 1 keeps the fixture's admins, runs the package and names every flipped test |
| Unanchored -run filters; the test-time limits | WARNING | Budget (03-08k's model); anchored verifies; both modes per code task |
| Auto-merge in Task 5; merge-gate.sh's plain form before the merge; authorship | MINOR | Delivery protocol; Task 4's checks; Task 5 after 03-08k's |
| The gate's gofmt step was vacuous through wsl.exe | MINOR | Task 4's precondition |
| Interactions with 03-08k | — | Reconciliation I-1 to I-3; O-1; T-03-302 and T-03-303 |
| Runbook anchors moved; 03-08j and 03-08k text in host-setup.md and signer-install.md | MINOR | Task 3's read_first and notes |

### Round 3 — owner answers to O-1 to O-3 (Daniel, 2026-11-03)

| Concern | Decision | How Addressed |
|---------|----------|---------------|
| O-1: a host holding the bad state from before this plan, on a run whose Verify or KRL-alone pass returns an error | (a) accept as a residual | Truth 2 narrowed to runs that end without such an error; the accepted T-03-323; T-03-300 residual (5) points there; enroll-user.md's sentence labelled UNVERIFIED |
| O-2: accepted.json's directory 0 against 03-08j's record raise | (c) directory 0 only while the chain base's directory is unauthorized | Truth 3, an artifact and a key link; Stored.DirectoryUnderPolicy; WriteAccepted's rule in Task 1. Task 3 replaces `unauthorized_with_a_recorded_directory` with `recorded_authorized_directory_keeps_the_record_raise` (the stall shape, which no longer stalls) and `recorded_bundle_over_unauthorized_directory_reports_directory_0`, with three mutants (readings (a) and (b), and a check against accepted/ instead of the chain base). The runbook notes now follow the chain base |
| O-3: the spool's computed bound with the per-bundle file | (a) accept about 6.1 GiB kept and 6.6 GiB in all | Task 2, host-setup.md and T-03-305 unchanged in substance, now marked as accepted |

### Round 4 — plan check 3 (2026-11-03, PASS WITH FIXES, against main b1ebff3)

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| M-1: `rotation_first_then_removed_admin_refused` cannot pass after the fix: directory 1 is alice's, so bundle 2 already makes the host unauthorized | MAJOR | Re-expected for the code after this plan (directory_not_authorized; then the removed admin's directory joins it, with no principals and the KRL landed), RED on origin/main. Co-signing was rejected, with the reason in the case |
| M-2: step b leaves a hold behind when the chain refuses after holdBundle; the converted refusals were not all listed | MAJOR | Step b saves and restores the bundle part; Truth 2 and the Planner decisions list every converted refusal (stored_state_invalid stays an error); `unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle` and the mutant "no restore"; the conversions no case pins are recorded as UNVERIFIED by test |
| m-1: a mixed record {3, 65} writes directory 0 | MINOR | The owner's O-2 (c) rule kept; Task 1 adds a readAccepted assertion to `held_content_refusal_keeps_the_records_bundle`; T-03-300 residual (4) and host-setup.md's record note name the shape |
| m-2: the mutant "bundle signatures added to the union" is equivalent | MINOR | Marked equivalent with CountPinnedSigners' reason; it is still run and must survive |
| m-3: the Report.DirectoryUnauthorized mutant is equivalent on Task 3's commit | MINOR | Retargeted to the assignment from v after Verify, which the tracer's second apply kills |
| m-4: the notes still named 682782e, and `--exec` as a future PR | MINOR | Revision note for b1ebff3 (PR #81); Task 4's precondition describes `--exec` as present; publish values unchanged |
| m-5: the crash between a record write or commit and WriteAccepted was not stated | MINOR | Task 1's WriteAccepted bullet |
| WARNING: about 195k tokens at low confidence is near one executor window | WARNING | Two executor runs: Run A for Tasks 1 and 2, ending with the SUMMARY draft's `## Handoff to Task 3`; Run B, a fresh executor for Tasks 3 to 5, with a resume entry under "What to read" and a full read list in Task 3. Estimated per run |
| The planner's additions to the must-haves | not vetoed | kept |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| F03: the server re-offers its current directory when a host reports the same version with another SHA-256 | Not needed for recovery: accepted.json's directory 0 makes the fetcher ask from 0. PR #72's host status already flags `diverged` |
| F03: refuse the hold path's acceptance of a directory under a policy that the same capture's successor replaces | It would change PR #67's catch-up across a policy rotation. The next capture's check bounds the hold to one capture (residual of T-03-300) |
| F02: merge new signature blocks into `policy-<v>.json.sigs` | The per-bundle file keeps each bundle's signatures without accumulating what a compromised server sent |
| F03: the signer and CLI recovery after a change to the admin set | Todo 2026-10-21-recover-directory-after-admin-set-change (Phase 4) |