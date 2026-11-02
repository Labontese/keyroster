---
phase: 03-linux-agent-and-revocation
plan: 08k
type: execute
wave: 16
depends_on: ["03-08j"]
files_modified:
  - internal/agent/state/state.go
  - internal/agent/state/verify.go
  - internal/agent/state/unapplied.go
  - internal/agent/apply/apply.go
  - internal/agent/apply/status.go
  - internal/agent/apply/krlsigner_test.go
  - internal/agent/apply/rechain_test.go
  - internal/agent/apply/window_test.go
  - internal/agent/apply/apply_test.go
  - internal/krl/krl_test.go
  - docs/runbooks/host-setup.md
  - .planning/phases/03-linux-agent-and-revocation/03-08k-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md
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
  tokens: 180000
  raw_tokens: 180000
  tasks: 5
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-11-01): this plan decides which signed KRL a host takes when the newest KRL and the bundles the host knows name different ops keys. It runs after 03-08j and before 03-08f. The rule is D-R2's, bounded by trust: a revocation lands when the bundle in force or a fully verified successor authorises it, and no other KRL lands. A fully verified successor is the newest bundle the apply verified in full (Verified.fullyVerified): the newest bundle step of a capture whose whole bundle chain verified with trust.VerifySuccessor, the bundle of 03-08j's unapplied record, whose chain verified when it was recorded (also when a bundle offered above it is refused), or, in a poll of a widening wait (03-08j's pollCapture), the pending capture's, and while the record is ahead of the pending target the higher of the record's bundle and the pending capture's. A bundle that was only offered, and one this apply verified only as a step before a refused bundle step, is never one"
    - "The successor rule. A KRL only the successor's ops key signed lands alone after a content refusal of the capture, after a refused directory step whose bundle chain verified in full (owner answer Q2), and after a refused bundle step above the record when the successor is the record's bundle. KRLAlone verifies it under the bundle in force first and, only on krl.ErrSigner, under the successor: its ops key, the pins' installation ID, the stored KRL version and the header check. TestKRLAlone/ops_key_changed_krl_lands_alone (it replaces 03-08d's ops_key_changed_krl_waits) and TestKRLSigner/successor_from_the_record_after_a_refused_bundle_step_above_it pin it; successor_signed_krl_after_a_refused_bundle_step_is_refused pins that a refused bundle step authorises nothing in its own capture"
    - "The retired-key rule: always refuse. An ops key is retired when the newest verified bundle the host knows above that key's bundle names another ops key; a key the newest one names again is current (owner answer Q4). A KRL whose authoriser's key is retired never lands, alone or with anything else, and krl_signer_retired is reported. That holds on the KRL step, in the KRL-alone pass after any refusal, on the capture read from the record, under a hold, and in a poll of a widening wait. Without a held step nothing else of the capture is installed (on the KRL step a Verify error); with one, the held rule applies. The host waits for a KRL the new key signs: with an honest server at most about an hour once the signer runs with the newer bundle, during which the newer bundle and every directory change outside a held step wait too. One shape waits longer: after a bundle step refused above a verified rotation, with no record, no KRL lands until the bundle chain verifies, because the old key is retired and the new one has no successor (Q2's limit); main there still lands the last old-key KRL (successor_signed_krl_after_a_refused_bundle_step_is_refused, retired_key_krl_after_a_refused_bundle_step_is_refused). TestKRLSigner/retired_key_krl_on_the_krl_step_is_refused pins the rule, including a second apply with no newer KRL that is refused the same way"
    - "What the host knows. The bundles above a bundle X that the host knows are the capture's verified bundle steps (those verified before a refused bundle step included) and the apply's fully verified bundle. VerifyAhead carries the record's bundle into forward's capture. Every poll of a widening wait carries the pending capture's, on each of pollCapture's three branches: VerifyAfter without a record; VerifyAheadAfter from the record, which starts at the higher of the record's bundle and the pending capture's; and, on the branch that brings nothing beyond the record, KRLAlone with that capture as from. KRLAlone's Verified inherits its from's at every call site. Nothing else: a bundle verified in an earlier apply and neither installed nor recorded is not known, so when a server withholds it the KRL is taken as on main. That is part of the accepted withholding-server residual (retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main). retired_key_krl_during_a_wait_is_refused, retired_key_krl_during_a_wait_from_the_record_is_refused and retired_key_krl_during_a_wait_above_the_record_is_refused pin the polls"
    - "The held rule. Under BundleHeld the bundle the capture puts in force (P) is a held step below the newest verified one, or the bundle in force below 03-08j's record. A KRL only the successor's ops key signed lands with the held step in the same apply. A KRL P's retired key signed, or one only the retired in-force key verifies, never lands, but the held step commits without it, as on main (owner, 2026-11-01): the KRL in force stays, so no revocation is lost, access removals take effect at once, and krl_signer_retired is reported after the commit (Verified.KRLRefused). retired_in_force_key_krl_under_a_held_step_is_refused and held_step_krl_signed_by_a_retired_key_is_refused pin it. TestApply/catch_up_across_policy_rotation's newOps=true row and the subtest TestSpoolWindow/policy_rotation_below_the_recorded_bundle/newOps=true each change one assertion: the new-key KRL is taken with the held step"
    - "The fallback stays narrow. The successor and the bundle in force are tried only on krl.ErrSigner, and only when their ops key differs from those already tried. Every other KRL error, an ErrSigner no known key explains, and every refusal before a first install read exactly as on main, with the error of the first bundle tried. The two narrowing conditions are equivalent mutants for two reasons, each pinned: krl.VerifyManifest reads the bundle only for its ops-key comparison (TestVerifyManifest/bundle_read_only_for_its_ops_key), and the fallback returns the first error unchanged (krl_in_force_key_for_another_installation_keeps_the_first_error)"
    - "A poll decides a KRL as forward does, neither wider nor narrower (owner, 2026-11-02). Each of pollCapture's three branches applies the same authorisers and the same retired-key rule as forward, with at least what forward knew: the pending capture's fullyVerified, and from the record the record's bundle. Without a record the poll verifies with VerifyAfter, from the record with VerifyAheadAfter, and the branch that brings nothing beyond the record takes the KRL alone with that capture as from. The test: each of the five wait cases (retired_key_krl_during_a_wait_is_refused, successor_signed_krl_during_a_wait_lands, retired_key_krl_during_a_wait_from_the_record_is_refused, record_signed_krl_during_a_wait_lands, retired_key_krl_during_a_wait_above_the_record_is_refused) runs its shape twice under one assertion, as subtest poll (the KRL arrives at the wait's first sleep, so a poll decides it) and subtest forward (the same KRL is in the spool before the widening apply, so forward decides it). Both runs must leave the same bundle, directory and KRL in force, and both or neither name krl_signer_retired"
  artifacts:
    - path: "internal/agent/state/verify.go"
      provides: "the KRL step's authorisers and the retired-key refusal, KRLAlone's successor and refusal, Verified.fullyVerified and VerifyAfter"
      contains: "func (v *Verified) krlStep("
    - path: "internal/agent/state/unapplied.go"
      provides: "VerifyAhead carrying the record's bundle, and VerifyAheadAfter for a poll read from the record, carrying the higher of the record's bundle and the pending capture's"
      contains: "func VerifyAheadAfter("
    - path: "internal/agent/state/state.go"
      provides: "the refusal krl_signer_retired"
      contains: "ErrKRLSignerRetired"
    - path: "internal/agent/apply/status.go"
      provides: "krl_signer_retired counts as a refusal in last_apply"
      contains: "state.ErrKRLSignerRetired"
  key_links:
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/state/verify.go"
      via: "pollCapture's branch without a record verifies with what the pending capture knew"
      pattern: "state.VerifyAfter("
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/state/unapplied.go"
      via: "pollCapture's record branch verifies with the higher of the record's bundle and what the pending capture knew"
      pattern: "state.VerifyAheadAfter("
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/state/verify.go"
      via: "every KRL-alone pass names the capture it verified: krlAlone (forward's and pollSpool's) and pollCapture's branch that brings nothing beyond the record"
      pattern: "state.KRLAlone("
  prohibitions:
    - statement: "No KRL lands that neither the bundle in force nor a fully verified successor authorises, and no bundle verified only in a capture whose bundle step was refused authorises one. A KRL whose authoriser's ops key a newer verified bundle the host knows dropped never lands, on any path. Nothing else of its capture is installed with it, except a held step, which commits with the KRL in force unchanged"
      status: resolved
      verification: test
---

<objective>
This plan decides which signed KRL a host takes when the newest KRL and the bundles the host knows name different ops keys. On main, three such cases either fail closed, so the revocations never reach the host, or let a KRL through unchecked:
- **Signed by a fully verified successor.** The host refused the capture of the bundle that rotated the ops key, for its content or for a directory that does not verify. Every new KRL is signed by the new key, so the host gets no revocation at all. After this plan the KRL lands alone.
- **Signed by a key a newer verified bundle dropped** (a retired key, possibly a stolen one). In the KRL-alone pass after a refused bundle or directory step, and under a hold, such a KRL lands unchecked, whatever it drops. After this plan it is always refused (krl_signer_retired) and the host waits for the new key's KRL. Nothing else of its capture is installed, except a held step, which commits with the KRL in force unchanged.
- **The same under BundleHeld.** The held path swallows the signer mismatch, so a new-key KRL waits a capture. After this plan it lands with the held step.

Purpose:
- REVOKE-02: the KRL reaches every enrolled host across an ops-key change.
- REVOKE-03: a KRL never rolls back what is revoked. A retired key can neither drop a revocation, revoke the fleet nor raise the KRL floor, because nothing it signs lands while the host knows the newer bundle.

Output:
- KRLAlone's successor and its retired-key refusal;
- the KRL step's authorisers and refusal (krlStep);
- Verified.fullyVerified, carried by VerifyAhead from the record, and into every poll of a widening wait by the new VerifyAfter and VerifyAheadAfter (all three branches of 03-08j's pollCapture);
- one refusal, krl_signer_retired;
- named tests with RED evidence and mutants;
- host-setup.md;
- the publish edits and a PR.
</objective>

## What to read (executor)

Read these before Task 1: the frontmatter, the objective, the Planner decisions (inside the Owner decisions section, from "**Planner decisions (Claude's discretion)**" on), the Budget, the Phase Goal, the `<context>` block up to "## Reconciliation" (the Delivery protocol and the defects), the tasks, and the Cross-plan notes.

Skip these until you write the SUMMARY, because they record history or restate the rules:
- the "Revision 2026-11-02" note;
- the owner decisions above "Planner decisions" (the Planner decisions restate them);
- Reconciliation;
- the source-coverage table before the Artifacts section;
- the threat sections (Trust Boundaries and the STRIDE register);
- the Review Dispositions Ledger.

## Revision 2026-11-02 (after plan check 4)

The plan was reconciled against main at ae754a3, which holds 03-08j with its three pre-merge review fix rounds. The owner's decisions of 2026-11-02 are under Owner decisions. Changes:
- **The polls.** 03-08j's fix round 1 moved a poll's verification into pollCapture, which has three calls: Verify without a record, VerifyAhead from the record, and KRLAlone on the branch that brings nothing beyond the record. All three now carry what forward knew:
  - Task 1 passes that capture as KRLAlone's from at pollCapture's call. KRLAlone has three call sites on ae754a3, not two.
  - Task 3 routes the branch without a record through VerifyAfter, and the record branch through the new VerifyAheadAfter, which starts fullyVerified at the higher of the record's bundle and the pending capture's.
  - Three record-path wait cases are added:
    - `record_signed_krl_during_a_wait_lands` (Task 1): the record's key, which lands;
    - `retired_key_krl_during_a_wait_from_the_record_is_refused` (Task 2): the in-force key that the record's bundle retired, which is refused;
    - `retired_key_krl_during_a_wait_above_the_record_is_refused` (Task 3): the record's key, retired by a bundle forward verified above the record, which is refused. This case pins the higher-of.
  - Two mutants are added: pollCapture passing nil as from, and the record branch keeping VerifyAhead. The nil-from mutant is also run against the second case, which survives it by design.
  - A new truth says that a poll decides as forward does, neither wider nor narrower. Each of the five wait cases tests it with subtests `poll` and `forward` under one assertion.
- **Test time.** The 400 s limit is for internal/agent/apply run alone. The package's line under `./...` keeps 480 s as the margin under go test's timeout. Tasks 1-4 measure and gate both.
- **Authorship and merge.** Every branch commit has Daniel as author, with keyroster-bot as committer, signer and pusher. The PR is opened without auto-merge, and Daniel squash-merges it himself. merge-gate.sh runs only as `--check` before the merge, and in its plain form only after it; a rebase is made by hand.
- **Anchors.** a70c661 becomes ae754a3, and pollSpool becomes pollCapture where the poll's verification is meant. 03-08j's fix-round sections are added to the context. The check for the old apply_test.go comment is whitespace-normalised, and a check that the new text is present is added.

## Owner decisions (recorded, do not ask again)

- **D-R2 (PR #71 review F5), existing:** a revocation never waits.
- **The KRL signer (Daniel, 2026-10-30):** the KRL is checked against the bundle actually in force, and a revocation still lands. Never accept a KRL that neither the in-force bundle nor a fully verified successor authorises.
- **When this plan was split out of 03-08j (Daniel, 2026-11-01):**
  - **Order:** 03-08e (wave 14) → 03-08j (wave 15) → 03-08k, this plan (wave 16, depends on 03-08j, branch `p03/08k-agent-krl-signer`) → 03-08f (wave 17). 03-09 to 03-16 move one wave later per plan; this plan's publish edits make one such move.
  - **The successor rule.** A KRL signed only by a fully verified successor's new ops key, while that successor is refused for its content, lands alone. It is verified against the successor's ops key and pins, with the usual version checks.
  - **The held rule.** The same rules extend to the BundleHeld path.
  - The false claim that "the newer bundle waits" is corrected, and the apply with no new KRL is tested.
- **After this plan's plan check 1 (Daniel, 2026-11-01):**
  - **Q2: yes, when the bundle chain verified.** A successor-signed KRL also lands alone when the successor's bundle chain verified in full (trust.VerifySuccessor) and Verify refused the directory step. It does not land when the bundle step itself was refused.
  - **Q4:** a key the newest known verified bundle names again (a rotation back) counts as current, not retired.
  - **Size:** one plan.
- **After this plan's plan check 2 (Daniel, 2026-11-01).** These replace the earlier rule that a retired key's KRL may land when it only adds revocations within a version bound, with its addition cap. Q1 and Q3 concerned that rule and fell away with it.
  - **Retired key: always refuse.** When the host knows a verified newer bundle that dropped the in-force ops key, a KRL signed only by that retired key is refused; it never lands alone or with anything else. The host waits for the new key's KRL. The signer republishes hourly with its current ops key, so the delay is at most about an hour. Where main guards against a KRL that revokes the installation's own keys, the guard stays.
  - **Knowledge of the newer bundle.** The refusal applies within the same apply, or while unapplied.json holds the newer bundle. Beyond that it is part of the accepted withholding-server residual: a compromised server could withhold the bundle before the host ever saw it. A test pins the boundary.
  - **The record counts as a successor.** A fully verified bundle in unapplied.json authorises KRLs its ops key signed, which land alone, also when a broken bundle is offered above the record.
  - **Unchanged:** the successor rule, Q2, Q4, the same-apply landing under BundleHeld, and one plan.
- **After this plan's revision (Daniel, 2026-11-01):**
  - **Under BundleHeld, the held step is installed.** When a retired-key KRL is refused and the capture has a held step, the held step commits without the KRL, as main does. The KRL in force stays, so no revocation is lost, and access removals take effect at once. The retired-key KRL never lands, and krl_signer_retired is reported. Without a held step, nothing of the capture is installed.
  - **The record successor, applied narrowly, is accepted:** the record's bundle authorises nothing when a bundle the capture verified above it retired the record's key (fail closed).
- **After this plan's plan check 3 (Daniel, 2026-11-01):**
  - **A refused bundle step above a verified rotation, with no record, is an accepted residual, with no design change.** No KRL lands there until the bundle chain verifies: the old key is retired by the step verified before the refusal, and the new key has no successor (Q2's limit). Main there still lands the last old-key KRL. This follows from Q2 and always-refuse, and a compromised server could withhold KRLs anyway.
  - **The test-time ceiling.** If Task 1 finds internal/agent/apply already above a limit on main (see the plan check 4 decisions below for the two limits), the executor stops before any edit and reports. The options are to raise CI's test -timeout or to move the slow cases into their own package, and the owner chooses; the executor does not.
- **After this plan's plan check 4 (Daniel, 2026-11-02):**
  - **The polls decide as forward does.** This plan's KRL rules apply equally to forward, to the widening wait's pollCapture, and to the KRL-alone pass. In pollCapture:
    - the branch without a record verifies with VerifyAfter;
    - the record branch verifies as VerifyAhead does, with fullyVerified starting at the higher of the record's bundle and the pending target's fullyVerified;
    - the KRL-alone call on the branch that brings nothing beyond the record gets a real from.

    Record-path wait cases with the old key (refused, as in forward) and with the record's key (landing, as in forward) are added, with the mutant "pollCapture passes nil as from".
  - **The test-time limit.** The 400 s limit applies to internal/agent/apply run alone (280.2 s at 03-08j's fix round 2 gate). The package's line under `./...` keeps 480 s as the margin against go test's 600 s per-binary timeout.
  - **Authorship and merge.**
    - Branch commits are authored as Daniel (`GIT_AUTHOR_NAME="Daniel Gustafsson"`, `GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com`), with keyroster-bot as committer and pusher.
    - The PR is opened without auto-merge. Daniel squash-merges it himself and replies "merged".
    - merge-gate.sh runs only with `--check` before the merge, or after Daniel has merged. A rebase is done by hand.
    - Changing merge-gate.sh itself (removing its re-enabling of auto-merge) is a separate small PR, not part of this plan.
- **Delivery (2026-10-29):** the plan lands in the same PR as its fix, with neutral hardening wording. Pushing the branch and opening the PR before the merge is allowed.
- **Homelab:** no 03-16 drill rotates the ops key. The runbook text is labelled as run in CI, and UNVERIFIED on a real host.

**Planner decisions (Claude's discretion), with their reasons:**
- **The rule set.** Four definitions, read the same way on every path. X is the bundle a KRL K is checked under first: the bundle the capture puts in force (P) on the KRL step, and prev's bundle, the bundle in force (F), in the KRL-alone pass.
  - **fullyVerified**, an unexported Verified field, is the newest bundle the apply verified in full up to this capture. verify starts it at what its caller passes: nil from Verify, the record's bundle from VerifyAhead (03-08j's base, when the record holds a bundle part above accepted's), the pending capture's fullyVerified from VerifyAfter, and the higher of those two from VerifyAheadAfter (by version; on a tie the pending capture's). It raises it to the capture's newest bundle step only when the bundle step returned nil (Q2). The Verified KRLAlone returns inherits from's, so the carry survives a poll that supersedes the pending target (forward's `target, tv = s.gen, s.verified`).
  - **known(X)** is the capture's verified bundle steps above X, those verified before a refused bundle step included, and fullyVerified when it is above X. The newest of known(X) has the highest version. On a tie, which only a fork of the root-signed chain can cause, fullyVerified counts.
  - **X's key is retired** when the newest of known(X) names another ops key (OpsKey.Key, compared as krl.VerifyManifest compares it). A key the newest one names again is current (Q4).
  - **The successor S** is fullyVerified when it is above X.
- **One rule for every path.** The authoriser of K is the first candidate that verifies it with verifyKRLUnder. On the KRL step the candidates are P, then S, then F; in the KRL-alone pass F, then S. A later candidate is tried only after krl.ErrSigner, and only when its ops key differs from those already tried. **K never lands when its authoriser's key is retired.** Otherwise it lands as on main: with the capture on the KRL step (a held step included), and alone in the KRL-alone pass.
  - On the KRL step, F is a candidate only so that the refusal is named. Reaching it means F's key is retired: P or S is a newer known bundle with another ops key, and when S names F's key, K already verified under S.
  - S's key is current except in one shape: a bundle verified before a refused bundle step lies above S and names another key. The rule then refuses S's KRL too (fail closed; `record_successor_dropped_by_a_verified_bundle_above_it_is_refused`).
- **Where the refusal goes.**
  - **The KRL step without a held step:** a Verify error, so nothing of the capture is installed. Skipping the KRL and installing the newer bundle and directory was rejected: once the newer bundle is in force, main already fails a KRL the old key signed with krl_not_verified on every apply until the new key's KRL arrives, so skipping would gain one apply and leave that apply's refusal unreported.
  - **The KRL step with a held step (BundleHeld; owner, 2026-11-01):** krlStep returns nil with the KRL unchanged and sets the new exported field Verified.KRLRefused. The held step commits as on main, and forward reports the refusal after the commit (outcome joins it to Refused). It is a field of its own, not Refused, because Refused marks a KRL-alone Verified, and krlAlone's guard, 03-08j's recording and VerifyAhead's Changed recomputation all read it; the held step stays an ordinary accepted capture.
  - **The KRL-alone pass:** joined to the capture's own refusal, and nothing is installed.
  - **A poll:** without a held step, the poll's Verify error, which the wait logs, and the pending target commits as before. With a held step, the poll's capture can supersede, and its KRLRefused is reported after the commit like forward's.
- **One refusal code, krl_signer_retired** (state.ErrKRLSignerRetired), which last_apply reports as refused. It does not wrap krl_not_verified, which keeps its meaning: no known key authorises the KRL.
- **fullyVerified travels in Verified, not in a context parameter.** Verify's and VerifyAhead's signatures, forward's two calls and the preflight's Verify call stay as they are. pollSpool already receives the pending Verified, and pollCapture now takes it in place of prev. fullyVerified is unexported, so apply cannot take the higher of the record's bundle and the pending capture's; state does. The polls therefore get two new entry points:
  - `VerifyAfter(p, pending, in)` for pollCapture's branch without a record;
  - `VerifyAheadAfter(p, pending, base, in)` for its record branch: VerifyAhead's steps, with pending.AsStored() as accepted.

  Every Verified on the poll path inherits the bundle, KRLAlone's through from, so no engine field is needed.
- **A poll decides as forward does, on each of pollCapture's three branches (owner, 2026-11-02).** A poll that knew less than forward would be wider (a retired-key KRL lands in the poll where forward refuses it) or narrower (a successor's KRL waits in the poll where forward lands it). The branch that brings nothing beyond the record reaches KRLAlone only after its KRL step accepted the KRL, with the same knowledge and the same rule.

  **The invariant this rests on.** On the record path the KRL step checks a KRL against prev's KRL floor, because Unapplied.Base never takes a KRL part from the record: the base's KRL, manifest and version are always prev's (unapplied.go, Base). So the KRL step's byte-equal and same-version skips are exactly KRLAlone's, which also checks against prev, and only a KRL the KRL step verified reaches the nothing-new KRL-alone call. **A later plan that lets Base carry a KRL part must keep KRLAlone's from.** The KRL step's same-version skip would then pass another KRL at the record's version unverified, and a nil from would widen the poll.

  With a nil from, KRLAlone tries only F:
  - a KRL the KRL step authorised under F's key, which the KRL step found current, lands either way;
  - a KRL the KRL step authorised under another key (the record's bundle's or a successor's) fails there with krl.ErrSigner and waits.

  So a nil from can only make the poll narrower. `record_signed_krl_during_a_wait_lands` kills the nil-from mutant through that narrowing.

  `retired_key_krl_during_a_wait_from_the_record_is_refused` runs the path where a wider poll was feared: the record names the new key, the capture brings nothing beyond the record, and an old-key KRL arrives. The KRL step refuses that KRL before the KRL-alone call, because both check against prev's KRL floor (the invariant above), so the case survives the nil-from mutant by design. That survival is the evidence that a nil from cannot widen a poll while the invariant holds.

  A wider poll can only come from what the capture knows, which is why VerifyAfter and VerifyAheadAfter carry the pending capture's fullyVerified (`retired_key_krl_during_a_wait_is_refused`, `retired_key_krl_during_a_wait_above_the_record_is_refused`).
- **A KRL the successor's key signed lands with a held step in the same apply.** This changes two existing tests. The alternative, landing it alone first with a second code and the held step one apply later, would turn both into three-apply shapes and delay the held directory, which may carry access removals. Keeping the held step's progress is as safe:
  - the KRL's authority is a fully verified successor's ops key;
  - the held directory was verified under its own policy;
  - a KRL only narrows access.
- **The successor's KRL lands alone with the accepted bundle and directory.** A bundle-only step with the successor's CA keys was rejected: a ca_line_rejected refusal cannot take the bundle, and the step would install more than the revocation.
- **Installation-key guards.** Main's agent has no check of its own against a KRL that revokes a key of the installation. The signer refuses to sign one (key_is_ca_of_this_installation, krl.InstallationKeys), and validate's krl_drops_key_entry keeps every explicit key of the installed KRL. This plan changes neither, so both stay where main has them.
- **The KRL a rollback kept in current.** keepKRLInForce keeps a KRL newer than accepted/'s in force. A retired-key KRL never lands while the host knows the newer bundle, so it cannot replace that KRL. A KRL the retired key signed can replace it only on the withheld-bundle path, which is main's behaviour and the accepted residual; validate's krl_drops_key_entry still keeps its explicit keys there. A successor's KRL replaces it only when newer, as any KRL does on main. No code is needed.
- **Residuals** (T-03-318, host-setup.md):
  - **The wait.** A retired-key KRL waits for a KRL the new key signs. An honest signer stops publishing with the old key once the newer bundle is installed on it (republishIfDue's trust check). With the new bundle it publishes at its next revocation, or at its hourly republish (krlRepublishAfter). With an honest server the wait is therefore at most about an hour once a signer process runs with the newer bundle; one started before the bundle install publishes nothing (checkTrustCurrent), and the hour counts from the last publish. Outside a held step, the newer bundle and every directory change, access removals included, wait with it; a held step commits at once. UNVERIFIED on a real host.
  - **A refused bundle step above a verified rotation, with no record** (owner, after plan check 3). No KRL lands until the bundle chain verifies: the step verified before the refusal retires the old key, and the new key has no successor (Q2's limit). Main there still lands the last old-key KRL. A fetcher that controls the spool can cause it with one junk or gapped bundle above the rotation, which is the withholding-server residual below. Run in CI: `successor_signed_krl_after_a_refused_bundle_step_is_refused`, `retired_key_krl_after_a_refused_bundle_step_is_refused`.
  - **What a poll does not carry.** Only fullyVerified reaches a poll, not the steps a capture verified before a refused bundle step. That is harmless: such a capture lands only a KRL that is current against those steps, so it commits nothing that a wait could follow.
  - **Withheld bundles.** The host knows a newer bundle only within the apply that verified it, its polls included, or while unapplied.json holds it. A refusal on the KRL step without a held step records nothing, because 03-08j records only a capture Verify accepted, and root may remove the record.
    - A server that withholds the bundle then, or before the host ever saw it, can land any KRL the retired key signs on that host, as on main.
    - A server holding the retired key can also keep an old-key KRL above the new key's version as the spool's newest (spool.Read takes only the newest complete KRL). That holds the host back for as long as it does, as main's krl_not_verified after a rotation does.
    - Both are part of the accepted withholding-server residual.

## Budget

- **Files:** 10 code and test files and one runbook. One is new: internal/agent/apply/krlsigner_test.go. Four are small edits: rechain_test.go, apply_test.go and internal/krl/krl_test.go (one assertion or one case each), and window_test.go (one rename, one flipped subtest, and rotationDropping's ops parameter). The publish edits add the plan, its SUMMARY, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16.
- **Estimate:** about 180k tokens:
  - about 50k to read this plan as "What to read" says. The full plan is about 170 KB, about 68k; the parts read only for the SUMMARY are about 45 KB;
  - about 75 KB of code read (function-scoped), about 22k;
  - about 40k written;
  - about 70k of test, gate and mutant-loop output (26 mutant runs, and two package-alone runs per code task).
- **Test time: two limits under -race (owner, 2026-11-02).**
  - **The budget, 400 s**, is internal/agent/apply run alone (280.2 s at 03-08j's round-2 gate). It is measured and gated with this command, which prints the output and fails when the package's `ok` line is missing or above 400 s:

    `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'`
  - **The margin, 480 s**, is the package's `ok` line under `go test -race -count=1 ./...`, where every package runs at once: the mode Task 4's gate and CI run, with headroom under go test's default 600 s per-binary timeout. It is gated the same way, with `./...` in place of the package path and 480 in place of 400.
  - **Task 1, before any edit**, measures the package on the branch, which is still origin/main, in both modes. It records both figures, and CI's latest build-test time for the package on origin/main, with the command used. **If the alone base is above 400 s, or the `./...` base or CI's time is above 480 s, the executor stops before any edit and reports to the owner.** The options to put are raising CI's test -timeout or moving the slow cases into their own package. The executor does not choose.
  - **Tasks 2 and 3** each end with both runs:
    - the alone run stops the task above the alone base + 120 s or above 400 s, whichever comes first;
    - the `./...` run stops it above 480 s.

    A stopped task does not commit; it thins its slowest new cases. Those share catch_up_across_policy_rotation's window shape, or the wait shape below a record. If thinning cannot bring the time under, the task stops and reports with the same two options.
  - The task verifies anchor every -run filter per level (`^Name$`), so TestKRLAlone's 4096-file cases never run there.
  - **Task 4** runs the alone gate before the full gate, and the full gate checks the margin.
  - **CI's time for the package is a pre-merge check.** CI runs `./...`, so its limit is the 480 s margin. Task 4 records it from the PR's build-test log beside the local figures. Above 480 s, the executor stops before the merge gate and reports with the same two options.
- **Task size.** Three code tasks, the publish task and the merge gate:
  - Task 1 has seven cases: five TestKRLSigner cases and the two renamed ones.
  - Task 2 has 15, one of them a wait case with the subtests `poll` and `forward`.
  - Task 3 has ten, three of them wait cases with both subtests. It also adds the subtest `forward` to Task 1's `record_signed_krl_during_a_wait_lands`, so all five wait cases run twice.

  A code task that grows past about 20 cases while it is written is split at its last group of cases into one more task of this plan, with its own commit.
- **Commits.** Every task ends with a commit by path, authored as the Delivery protocol says. A code task first commits its code and tests, then runs its mutants against that commit, then commits the SUMMARY draft with its RED evidence and mutant results. A context reset therefore loses no evidence.
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
@.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

In 03-08j-SUMMARY.md, read the three "Pre-merge review fix round" sections. Round 1's "D-1: polls during a widening wait" added pollCapture, the poll's capture and verification that this plan routes (Task 1 and Task 3). Round 2's gate gives the package's figures under -race: 382.7 s under `./...` and 280.2 s alone.

Delivery protocol: 01-SKELETON.md, with phase 03 names, except where this plan overrides it (owner, 2026-11-02).
- **Branch.** Create `p03/08k-agent-krl-signer` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 4 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Authorship. This overrides 01-SKELETON step 2's "all commits are made by keyroster-bot".**
  - Every `git commit` of this plan is authored as Daniel, with keyroster-bot as committer, SSH signer and pusher. Put the two variables on the same command line as the commit, because shell state does not persist between commands: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit ...`.
  - The repository's own git identity (keyroster-bot) stays the committer.
  - Task 4 checks every branch commit with `git log origin/main..HEAD --format='%an <%ae> %cn'`.
- **No auto-merge. This overrides 01-SKELETON's auto-merge wording, where it still has it** (step 3's "enables auto-merge", step 5's "auto-merge then squash-merges").
  - The bot opens the PR and never enables auto-merge or waits for it.
  - The owner reviews, approves and squash-merges the PR in the GitHub web UI, and replies "merged".
  - Before the merge, merge-gate.sh runs only as `--check`. Its plain form may rebase and push the branch itself (exit 3), and this plan rebases by hand, so the plain form runs only after the merge (Task 5). This holds whether or not PR #79 (merge-gate.sh waits for the owner's merge and never enables auto-merge) is merged first.
- **Commits and PR text.** Conventional Commits with neutral hardening wording. No attribution lines, no IP addresses and no real host names.
- **Code comments.** Cite `(03-08k)`.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md`, a draft from Task 1 on. The final docs commit is `docs(03-08k): complete agent KRL-signer plan`.

**The defects this plan fixes**, as read on main at ae754a3, with 03-08j's split of Verify into verify(p, chain, alone, in) and its pollCapture:
- **The KRL-alone pass.** state.KRLAlone verifies the newest KRL only under prev's bundle (verifyKRL, `krl.VerifyManifest(..., v.Bundle, ...)`). None of its three callers passes it anything the capture verified: verify's refused branch (verify.go about line 152), apply's krlAlone (apply.go about line 1012, which forward and pollSpool call), and pollCapture's branch that brings nothing beyond the record (`state.KRLAlone(e.pins, prev, st, nil)`, apply.go about line 1304).
  - When a verified successor replaced the ops key, a KRL the new key signed fails with krl.ErrSigner and lands nowhere. 03-08d pins this as TestKRLAlone/ops_key_changed_krl_waits, and 03-08j as TestSpoolWindow/krl_only_the_recorded_bundle_signs_waits. After a real rotation every new KRL is signed by the new key, so such a host gets no revocation until its refusal is fixed.
  - A KRL the dropped key signed lands unchecked, even when it drops revocations or sets the KRL floor arbitrarily high. 03-08j's record does not change that.
- **The KRL step.** verifyKRL checks the newest KRL under v.Bundle, the bundle the capture would put in force. On krl.ErrSigner without BundleHeld, Verify returns the generic krl_not_verified, and nothing is installed.
- **BundleHeld.** When the manifest fails under the held step, verifyKRL returns nil whatever the error, and the KRL waits while the held step commits. A KRL the held step's own key signed is taken with the capture even when a newer verified bundle dropped that key. With 03-08j's in-force hold step, the same holds for the bundle in force below the record.
- **The polls of a widening wait.** pollCapture (apply.go about line 1285, 03-08j fix round 1) takes only prev, the pending target's state, so a poll knows nothing forward verified above it. It has three calls:
  - `state.Verify(e.pins, prev, st)` without a record (about line 1292);
  - `state.VerifyAhead(e.pins, prev, base, st)` from the record (about line 1299);
  - the KRL-alone call above on the branch that brings nothing beyond the record.

  Once this plan's rules exist, each of these would decide a KRL differently from forward if it were left as it is.
- **The skip rules.** verifyKRL returns early when the newest KRL is byte-equal to the stored one (verify.go about line 451) or has the stored version (about line 461). A refused KRL never becomes the stored one, so the skip rules never pass it.
- **Stale doc comments** become false: Verify's KRL bullet (about lines 107-112), Verified.BundleHeld's, Verified.Refused's, verifyKRL's held-wait comment, and KRLAlone's ("a KRL that only the refused bundle's ops key signed is refused").
- **What a holder of a retired key could do** if a KRL it signed were accepted:
  - drop revocations, since a KRL replaces the list;
  - set a huge krl_version, which refuses every later KRL (krl_older);
  - revoke a serial range such as 1..2^64-1, or every key ID or user key it knows, which refuses every certificate.

## Reconciliation (2026-11-01)

1. **Source.** This plan was split out of 03-08j by the owner's decisions of 2026-11-01, and revised after its plan checks 1 and 2 with the owner's decisions of the same day. After plan check 4 (2026-11-02) it was reconciled against main at ae754a3, which holds 03-08j with its three fix rounds. It owns the correction of "the newer bundle waits" and the test of an apply with no new KRL.
2. **What 03-08j adds that this plan builds on.** Each was checked in 03-08j-PLAN.md:
   - verify(p, chain, alone, in): the steps against chain, the KRL-alone pass against alone;
   - state.VerifyAhead(p, accepted, base, in) and the unapplied record, whose Base takes a bundle part only above accepted's, and whose base carries accepted/'s KRL;
   - verify's in-force hold step: with a recorded bundle part, the bundle in force is the lowest holdBundle step, below the record's, so P can be F;
   - only a capture Verify accepted with Refused nil is recorded, and recordUnapplied merges per kind, raise only;
   - pollCapture (03-08j-SUMMARY, fix round 1). It verifies a poll's capture against the pending target in three ways: Verify without a record, VerifyAhead while the record has a part ahead of the pending target, and KRLAlone on the branch that brings nothing beyond the record. pollSpool calls it, and calls krlAlone after a content refusal;
   - the TestSpoolWindow cases. This plan changes two of them: `krl_only_the_recorded_bundle_signs_waits` becomes `krl_only_the_recorded_bundle_signs_lands_alone` (the successor rule), and the subtest `policy_rotation_below_the_recorded_bundle/newOps=true` changes one assertion (the held rule). TestSpoolWindowWideningWait's seven rows (fix round 1) never rotate the ops key and stay unchanged.
3. **Main's tests change too.** TestKRLAlone/ops_key_changed_krl_waits becomes ops_key_changed_krl_lands_alone, with the opposite assertion on the KRL. TestApply/catch_up_across_policy_rotation's newOps=true row changes one assertion, as 03-08j's row does. Neither is a regression.
4. **Two facts of main the rules rest on.** krl.VerifyManifest reads the bundle only at its ops-key comparison (`trust.FormatKey(s.PublicKey()) != b.OpsKey.Key`), before the signature, installation, version and digest checks (internal/krl/manifest.go). spool.Read takes only the newest complete KRL.
5. **The publish values expected after 03-08j:**
   - the ROADMAP's Phase 3 Plans line reads N/24 plans in 23 waves;
   - STATE.md reads total_plans 59 and `Plan: <n> of 24`;
   - 03-09 has `wave: 16` and `depends_on: ["03-08j"]`;
   - 03-10 to 03-16 have waves 17 to 23.

   Task 4 computes every number from origin/main's actual values, with a guard, and checks each one.
6. **Threat IDs.** This plan adds T-03-318 and T-03-319.

</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a fully verified successor replaced the ops key and the host refused the capture, for its content or for a directory that does not verify → the KRL-alone pass verifies the newest KRL under that successor's ops key → the KRL lands alone with the accepted bundle and directory → an apply with no newer KRL stays the same refusal; a widening wait's poll read from the record takes the same KRL alone"</name>
  <reversibility rating="reversible">One more authoriser in the KRL-alone pass, a fully verified successor, at all three of its call sites. No on-disk format, wire message or signed document changes.</reversibility>
  <precondition>All of these hold:
    - `git fetch origin` succeeds.
    - `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md` exits 0.
    - 03-08j is merged, with the names this plan builds on. Each command prints 1:
      - `U=$(git show origin/main:internal/agent/state/unapplied.go) && printf '%s\n' "$U" | grep -c 'func VerifyAhead('`;
      - `V=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$V" | grep -c '^func verify('`;
      - `W=$(git show origin/main:internal/agent/apply/window_test.go) && printf '%s\n' "$W" | grep -c '"krl_only_the_recorded_bundle_signs_waits"'`;
      - `W=$(git show origin/main:internal/agent/apply/window_test.go) && printf '%s\n' "$W" | grep -c '"policy_rotation_below_the_recorded_bundle"'`;
      - `A=$(git show origin/main:internal/agent/apply/apply.go) && printf '%s\n' "$A" | grep -c '^func (e \*engine) pollCapture(prev \*state.Stored)'` (03-08j fix round 1).
    - This plan is not on main yet: `git grep -q 'krl_signer_retired' origin/main -- internal/agent/` exits non-zero.
  </precondition>
  <files>internal/agent/state/verify.go, internal/agent/apply/apply.go, internal/agent/apply/krlsigner_test.go, internal/agent/apply/rechain_test.go, internal/agent/apply/window_test.go</files>
  <read_first>
    Read functions, not whole files. Find each with `grep -n` on the branch.
    - internal/agent/state/verify.go: the Verified struct with its Refused and steps comments, `func verify(` (03-08j), `func KRLAlone(`, `func storedOnly(` and `func (v *Verified) verifyKRL(` (about 8 KB).
    - internal/krl/manifest.go: `ErrSigner` and `func VerifyManifest(` (about 2 KB).
    - internal/agent/apply/apply.go: `func (e *engine) forward(`'s doc comment, `func (e *engine) krlAlone(` with its doc comment and its two callers (forward and pollSpool), and `func (e *engine) pollCapture(` with its doc comment and its KRLAlone call (about 6 KB).
    - internal/agent/apply/rechain_test.go: the subtests ops_key_changed_krl_waits and bundle_step_refused_krl_applied, and the helper mustKRLAlone. internal/agent/apply/window_test.go: the subtest krl_only_the_recorded_bundle_signs_waits, `func (f *fixture) rotationDropping(` and its three callers, and TestSpoolWindowWideningWait's recordAbove and its sleep hook. internal/agent/apply/apply_test.go: successor, rotationOps, and the last step of catch_up_across_policy_rotation (a directory no admin signed) (about 10 KB together).
  </read_first>
  <action>
Create branch `p03/08k-agent-krl-signer` from origin/main. Place this plan file untracked in the phase directory.

**The base time, before any edit.** On the branch, which is still origin/main:
- run the Budget's alone gate (the package alone, limit 400 s) and its `./...` margin run (limit 480 s), and record internal/agent/apply's `ok` line from each. The alone figure is the alone base, and the `./...` figure the `./...` base;
- record CI's time for the package from the build-test job log of origin/main's latest CI run, with the command used.

**Stop rule.** Stop here, before any edit, if the alone base is above 400 s, or the `./...` base or CI's time is above 480 s (an alone or margin gate that exits non-zero). Report the figures to the owner with the two options under Budget (raise CI's test -timeout, or move the slow cases into their own package). Do not choose between them.

**RED first.** Write these cases and run them on 03-08j's head (the branch). Record which are RED and which GREEN at once, then implement. This is the successor rule and Q2 of the owner's decisions of 2026-11-01.
- **`TestKRLAlone/ops_key_changed_krl_lands_alone`** (rechain_test.go). It replaces 03-08d's ops-key case that expected the KRL to keep waiting, under the new name and with the same setup:
  - bundle 2 replaces the ops key (f.rotationOps), directory 2 is above the caps, f.ops is the new key, and publishKRL(6) runs;
  - the apply returns generation_too_large and does not match state.ErrKRL;
  - current revokes 6, accepted/ stays at bundle 1 and directory 1, and CAFile holds bundle 1's CA lines.
  - RED: krl_not_verified, and nothing is installed.
- **`TestSpoolWindow/krl_only_the_recorded_bundle_signs_lands_alone`** (window_test.go). It replaces 03-08j's recorded-bundle case that expected the KRL to keep waiting, under the new name and with the same setup. It makes the same assertions on the record's path, and the record stays. RED.
- **The new file internal/agent/apply/krlsigner_test.go**, first line `//go:build linux`, with `TestKRLSigner`. Every case calls t.Parallel.
  - `successor_signed_krl_then_no_new_krl_is_a_noop`: the setup of ops_key_changed_krl_lands_alone. Assert first that apply 1 landed KRL 6. Then apply 2, with no newer KRL, returns generation_too_large again; KRL 6 stays in force, and neither the generation count nor current changes. RED at the first assertion.
  - `successor_signed_krl_after_a_refused_directory_lands_alone` (Q2):
    - bundle 2 replaces the ops key (f.rotationOps with f.policy.Admins);
    - directory 2 is signed by a key no policy names, as the last step of catch_up_across_policy_rotation builds one;
    - f.ops is the new key, and publishKRL(6) runs.
    - The apply returns directory_not_verified (state.ErrDir) and does not match state.ErrKRL. Current revokes 6, accepted/ stays at bundle 1 and directory 1, and CAFile holds bundle 1's CA lines.
    - RED: krl_not_verified, and nothing is installed.
  - `successor_signed_krl_after_a_refused_bundle_step_is_refused` (Q2's limit):
    - bundle 2 as in the previous case, which verifies;
    - bundle 3 is a successor of bundle 2 (h.f.successor) whose sigs are replaced by bundle 2's, so trust.VerifySuccessor refuses it (bundle_not_verified);
    - KRL 6 is signed by bundle 2's ops key.
    - The apply returns state.ErrBundle and state.ErrKRL. Nothing is installed: current, the generation count and accepted/ are unchanged.
    - GREEN at once: a step verified before a refused bundle step authorises nothing.
  - `successor_signed_krl_needs_a_verified_successor`: bundle 3 is offered without bundle 2 (a chain gap) and names a new ops key, and KRL 6 is signed by that key. The apply returns bundle_chain_gap and krl_not_verified, and nothing is installed. GREEN at once: a bundle that was only offered never authorises a KRL.
  - **The wait helper `recordBelowWait(t, recordOps, aboveOps ssh.Signer) *testHost`**, package-level in krlsigner_test.go. It builds the shape of TestSpoolWindowWideningWait's recordAbove, a closure this file cannot call; recordAbove itself stays as it is. K1 is the fixture's original ops key.
    - h.clock.advance(time.Hour), then KRL 5, signed by K1, is published and applied: the swap the widening apply waits after.
    - Bundle 2 is f.successorNextUnder of bundle 1 (the policy kept, a next CA x added). Bundle 3 is f.rotationDropping of bundle 2 (the policy rotated to admin bob, x dropped, a CA line h.run.rejectCA refuses). With recordOps, bundle 3 names recordOps as its ops key.
    - Apply 1 returns ca_line_rejected and records {Bundle: 3}. KRL 5 is byte-equal to the stored one, so no KRL is checked.
    - With aboveOps, bundle 4 is f.rotationOps over bundle 3 and its policy, with admin bob and the ops key aboveOps. rotationDropping returns only documents, so bundle 3 (trust.ParseBundle) and its policy (trust.ParsePolicy) are parsed from them first. rotationOps always writes a new policy version (Version+1, Prev = bundle 3's policy hash), here with the same admin bob, so bundle 4 comes with policy version 3, and both go into h.state. Bundle 4 verifies in full.
    - Directory 2, signed under bundle 1's policy, widens deploy to role:q. The next apply therefore holds at the bundle in force (P = F = bundle 1, BundleHeld) below the record, and waits. Every case built on the helper fails when that apply did not sleep.
  - **window_test.go: rotationDropping gains a trailing `ops ssh.Signer`.** rotationDropping builds its bundle with its own outer trust.BuildSuccessor and discards the bundle of its inner rotationOps call, so passing ops to that inner call would change nothing. When ops is non-nil, rotationDropping sets `b.OpsKey` on its own outer bundle, as rotationOps does (`trust.KeyEntry{Key: trust.FormatKey(ops.PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "software"}`), before it canonicalises and signs the bundle. Its three existing callers pass nil, so 03-08j's tests read as before.
  - `record_signed_krl_during_a_wait_lands`, as its subtest `poll` (Task 3 adds the subtest `forward`). It is built with recordBelowWait(t, K2, nil), where K2 is a new ops key, so the record's bundle 3 names K2.
    - At the wait's first sleep (once, as superseded_during_wait_krl_applied guards it): f.ops = K2, KRL 8 revoking 5 and 8 is published, and h.resetSpool and h.write run.
    - The poll reads from the record, and its capture brings nothing beyond it. Its KRL step verifies KRL 8 under bundle 3, so pollCapture takes the KRL alone against the pending target. That pass fails under bundle 1 with krl.ErrSigner, then verifies KRL 8 under the capture's fullyVerified, the record's bundle 3. KRL 8 lands as the superseding generation, and the wait goes on.
    - After apply 2, which returns nil: directory 2 is in force under bundle 1, current revokes 5 and 8, accepted/'s KRL version is KRL 8's, and the record stays {Bundle: 3}.
    - RED on 03-08j's head: the poll's KRL-alone pass verifies KRL 8 only under bundle 1, the wait logs krl_not_verified, and KRL 8 waits for the next apply.

**state, verify.go.**
- **verifyKRL's authoriser becomes a parameter.** `verifyKRLUnder(p, prev, in, b *trust.Bundle)` holds today's body with v.Bundle replaced by b. `verifyKRL(p, prev, in)` is verifyKRLUnder with v.Bundle, so nothing else changes in this task.
- **Verified gains an unexported `fullyVerified *trust.Bundle`.** In this task verify sets it to the capture's newest bundle step when its bundle step returned nil, and leaves it nil otherwise; Task 3 adds the value it starts from. Its comment gives the definition under Planner decisions and says that a refused bundle step never raises it, even for the steps verified before the refusal (Q2).
- **KRLAlone gains a final `from *Verified`:** the capture the caller verified. All three call sites on ae754a3 pass one: verify's refused branch, apply's krlAlone, and pollCapture's branch that brings nothing beyond the record. A nil from reads as main. No call site passes nil (see the acceptance criteria).
  - **The successor S** is from.fullyVerified when its version is above prev's bundle's.
  - When the KRL fails under prev's bundle with an error wrapping krl.ErrSigner, S is present, and S's ops key differs from prev's bundle's, KRLAlone verifies it again with verifyKRLUnder under S: its ops key, the pins' installation ID, prev's KRL version and the header check.
  - Otherwise it reads as on main: prev's bundle's error, joined to the refusal.
  - The KRL-alone Verified's Bundle, Policy and Directory stay prev's. Only the authoriser differs. Its fullyVerified is from's.
  - Its doc comment cites `(03-08k)` and states the owner's rule: a fully verified successor may authorise a KRL, which then lands with the bundle and directory in force. A bundle only offered, and a step verified before a refused bundle step, authorise nothing. The sentence "a KRL that only the refused bundle's ops key signed is refused" goes.
- **verify's refused branch passes v as from.** A directory-step refusal after a fully verified chain then names its successor (Q2), and a bundle-step refusal names none.
- **Verified.Refused's comment.** The KRL-alone KRL is "verified against the bundle in force", and now also "or, on krl.ErrSigner, against the apply's fully verified successor (03-08k)".

**apply, apply.go.** krlAlone passes v as from. Its guard already returns earlier when v.Refused is set, so v is a capture Verify accepted, with fullyVerified set. Both doc comments change the same way: krlAlone's ("verified against prev's bundle; never the KRL v verified under a bundle that is not applied") and forward's ("the KRL verified again against the accepted bundle") each gain "or, on krl.ErrSigner, the apply's fully verified successor (03-08k)".

**apply, pollCapture.** Its KRL-alone call on the branch that brings nothing beyond the record becomes `state.KRLAlone(e.pins, prev, st, nil, v)`: from is the VerifyAhead capture v. Its refusal stays nil. Its doc comment's "supersedes the target only with a newer KRL, verified against prev (KRLAlone)" gains "or, on krl.ErrSigner, against that capture's fully verified successor (03-08k)". Task 3 changes pollCapture's other two calls. forward and pollSpool are otherwise unchanged.

**Commit and mutants.** Commit the code and tests by path, authored as the Delivery protocol says, as `fix(agent): let a fully verified successor's ops key authorise a KRL`. Run the mutants below as the scripted loop of the Budget, then commit the SUMMARY draft the same way (`docs(03-08k): record the successor rule's evidence`).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "^TestKRLSigner$|^TestKRLAlone$/^(ops_key_changed_krl_lands_alone|bundle_step_refused_krl_applied|oversize_principals_file_krl_applied|ca_line_rejected_krl_applied|refusal_without_newer_krl_is_noop)$|^TestSpoolWindow$/^(krl_only_the_recorded_bundle_signs_lands_alone|refused_window_newest_then_fix_applies|bundle_fork_after_the_record_takes_the_krl_against_accepted)$|^TestSpoolWindowWideningWait$" ./internal/agent/apply/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestKRLAlone/ops_key_changed_krl_lands_alone", "--- PASS: TestKRLAlone/bundle_step_refused_krl_applied", "--- PASS: TestKRLAlone/refusal_without_newer_krl_is_noop", "--- PASS: TestSpoolWindow/krl_only_the_recorded_bundle_signs_lands_alone", "--- PASS: TestSpoolWindow/bundle_fork_after_the_record_takes_the_krl_against_accepted", "--- PASS: TestSpoolWindowWideningWait/nothing_new", "--- PASS: TestSpoolWindowWideningWait/older_bundle_at_the_window_boundary", "--- PASS: TestKRLSigner/successor_signed_krl_then_no_new_krl_is_a_noop", "--- PASS: TestKRLSigner/successor_signed_krl_after_a_refused_directory_lands_alone", "--- PASS: TestKRLSigner/successor_signed_krl_after_a_refused_bundle_step_is_refused", "--- PASS: TestKRLSigner/successor_signed_krl_needs_a_verified_successor", "--- PASS: TestKRLSigner/record_signed_krl_during_a_wait_lands/poll"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'ops_key_changed_krl_waits' internal/agent/apply/rechain_test.go` prints 0, and `grep -c 'krl_only_the_recorded_bundle_signs_waits' internal/agent/apply/window_test.go` prints 0.
    - `head -1 internal/agent/apply/krlsigner_test.go` prints `//go:build linux`.
    - Every KRLAlone call names its capture. `K=$(git grep -h 'KRLAlone(' -- 'internal/*.go' ':!*_test.go') && printf '%s\n' "$K" | grep -v '^[[:space:]]*//'` prints exactly four lines: the definition, verify's refused branch, krlAlone's call and pollCapture's call. None of them contains `nil)`.
    - The SUMMARY draft records the alone base, the `./...` base, CI's time, the REDs, and these mutants, each applied, run against its named test, and restored byte for byte:
      - the successor not tried in KRLAlone: killed by `ops_key_changed_krl_lands_alone` and `successor_signed_krl_after_a_refused_directory_lands_alone`;
      - verify's refused branch passing nil as from (Q2 off): killed by `successor_signed_krl_after_a_refused_directory_lands_alone`;
      - pollCapture passing nil as from (`state.KRLAlone(e.pins, prev, st, nil, nil)`): killed by `record_signed_krl_during_a_wait_lands/poll`, where KRL 8 waits;
      - fullyVerified raised whatever the bundle step returned: killed by `successor_signed_krl_after_a_refused_bundle_step_is_refused`;
      - S being the capture's newest offered bundle, verified or not: killed by `successor_signed_krl_needs_a_verified_successor`.
    - `git status --porcelain -- internal/` prints nothing after the last commit.
  </acceptance_criteria>
  <done>A host that refused the capture of the bundle that rotated the ops key, for its content or for a directory that does not verify, still receives every revocation the new key signs, and so does a widening wait's poll read from a record whose bundle names the new key. A bundle that was only offered, or a step verified before a refused bundle step, never authorises a KRL.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The retired-key refusal and the held rule within one capture: the KRL step's authorisers (P, the successor, F), a held step kept without a refused KRL (KRLRefused), KRLAlone's refusal, krl_signer_retired, and Verify's doc comments</name>
  <reversibility rating="reversible">The KRL step tries two more authorisers before it refuses, and one refusal code is added. No on-disk format, wire message or signed document changes.</reversibility>
  <files>internal/agent/state/state.go, internal/agent/state/verify.go, internal/agent/apply/status.go, internal/agent/apply/apply.go, internal/agent/apply/krlsigner_test.go, internal/agent/apply/apply_test.go, internal/agent/apply/window_test.go</files>
  <behavior>
    TestKRLSigner gains these cases, each with t.Parallel.
    - **Fixture.**
      - The fixture's f.ops decides which key signs a published KRL. A retired-key case sets f.ops back to the original key K1 before it publishes. publishKRL replaces h.state.KRLs, but the spool keeps older files until h.resetSpool.
      - In-force KRL 5 (publishKRL(5) and mustApply), signed by K1, is installed first.
      - "Bundle 2" replaces the ops key with K2 (f.rotationOps with f.policy.Admins, as ops_key_changed_krl_lands_alone builds it).
      - "The P-K1 shape" is built as TestApply/catch_up_across_policy_rotation builds its window: bundle 2 is a successor of bundle 1 with the same admins and K1; bundle 3 rotates the admins to bob and the ops key to K2 (rotationOps); directories 2-65 are signed by the original admin, and two more by bob. The first capture holds at bundle 2 (P, key K1) below bundle 3 (N, key K2).
    - **The KRL step.**
      - `retired_key_krl_on_the_krl_step_is_refused`: bundle 2 and a directory 2 that adds role:q are offered, and KRL 6, signed by K1, revokes 5 and 6.
        - Apply 1 returns an error matching state.ErrKRLSignerRetired that names bundle versions 1 and 2, and does not match state.ErrKRL. Nothing is installed: current, the generation count, accepted/ (bundle 1, directory 1) and KRL 5 stay. last_apply.result is refused, and no unapplied.json exists.
        - Apply 2, with no newer KRL, is refused the same way. The refused KRL never became the stored one, so verifyKRL's skip rules do not pass it: the newer bundle waits, for the new key's KRL.
        - Then KRL 7, signed by K2, revokes 5, 6 and 7. Apply 3 installs bundle 2, directory 2 and KRL 7 together.
        - RED at apply 1: krl_not_verified.
      - `krl_third_key_under_changed_bundle_not_retired`: bundle 2 is offered, with KRL 6 signed by a third key. The error matches state.ErrKRL and krl.ErrSigner, not state.ErrKRLSignerRetired, and nothing is installed. GREEN at once.
      - `first_install_krl_refusal_unchanged`: before a first install, a bundle is offered with a KRL signed by an unknown key. The error matches state.ErrKRL and not state.ErrKRLSignerRetired, exactly as main reports it. GREEN at once.
      - `krl_the_new_bundle_authorises_applies_with_it`: bundle 2, with KRL 6 signed by K2. The apply installs bundle 2 and KRL 6 with no error. GREEN at once: no candidate after P is tried when P signed.
      - `unchanged_krl_under_a_rotated_bundle_installs`: bundle 2 is offered, and the spool's newest KRL is KRL 5, byte-equal to the stored one and signed by K1. The apply installs bundle 2 with KRL 5 still in force, and returns nil. GREEN at once: the skip rules come before any candidate, so a KRL the host already accepted is never refused for its signer. This is a rotation's usual shape.
    - **The KRL-alone pass.**
      - `retired_key_krl_after_a_refused_directory_is_refused`: bundle 2 is offered, with a directory 2 signed by a key no policy names, and KRL 6, signed by K1, revokes only 6.
        - The error matches state.ErrDir and state.ErrKRLSignerRetired. Nothing is installed, and current still revokes 5.
        - RED: 03-08j's KRL-alone pass lands KRL 6, which drops serial 5.
      - `retired_key_krl_after_a_refused_bundle_step_is_refused`: bundle 2 verifies, bundle 3 is refused as in successor_signed_krl_after_a_refused_bundle_step_is_refused, and KRL 6, signed by K1, revokes only 6. The error matches state.ErrBundle and state.ErrKRLSignerRetired, and nothing is installed. RED, as above. It pins that a step verified before a refused bundle step counts as known.
      - `rotated_back_key_is_current` (Q4): bundle 2 replaces K1 with K2, bundle 3 replaces K2 with K1 again (f.rotationOps takes the ops signer as its last argument, so bundle 3 passes the K1 signer kept before f.ops changed), directory 2 is signed by a key no policy names, and KRL 6, signed by K1, revokes 5 and 6. The error matches state.ErrDir and not state.ErrKRLSignerRetired; current revokes 6, and accepted/ stays at bundle 1. GREEN at once: main lands it, and Q4 keeps it.
    - **Held.**
      - `held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step`: the P-K1 shape, with KRL 6, signed by K2, revoking 5 and 6.
        - Apply 1 returns nil, with bundle 2, directory 65, BundleHeld, and current revoking 6.
        - Apply 2 installs bundle 3 and the last directory, with KRL 6 still in force.
        - RED: apply 1 commits the held step without KRL 6.
      - `held_step_krl_signed_by_a_retired_key_is_refused`: the P-K1 shape, but KRL 6 is signed by K1 (P's key, which N dropped) and revokes only 6.
        - Before apply 1, read accepted/'s KRL, KRL manifest and KRL sig bytes.
        - Apply 1 commits the held step (bundle 2, directory 65, BundleHeld) with KRL 5 still in force, and returns an error matching state.ErrKRLSignerRetired; last_apply.result is refused. accepted/'s KRL, manifest and sig are byte-equal to what they were before, and its KRL version is 5's.
        - Apply 2, with no newer KRL, returns state.ErrKRLSignerRetired again. Nothing is installed: bundle 2 stays, current still revokes serial 5, and accepted/'s three KRL files are still byte-equal. A KRL that leaked into accepted/ would pass the byte-equal skip here and land.
        - Then KRL 7, signed by K2, revokes 5, 6 and 7. Apply 3 installs bundle 3, the last directory and KRL 7.
        - RED: on 03-08j's head KRL 6 lands with the held step and drops serial 5.
      - `retired_in_force_key_krl_under_a_held_step_is_refused`. Here P differs from F:
        - bundle 2 replaces K1 with K2 (rotationOps, same admins); bundle 3 keeps K2 and rotates the admins to bob;
        - directories 2-65 are signed by the original admin, and two more by bob;
        - KRL 6, signed by K1, revokes 5 and 6.
        - Apply 1 commits the held step (bundle 2, directory 65, BundleHeld). The KRL is unchanged: KRL 5 is in force, r.KRLVersion is 5's, and accepted/'s KRL, manifest and sig are byte-equal to what they were before the apply. The apply returns an error matching state.ErrKRLSignerRetired; last_apply.result is refused.
        - Then KRL 7, signed by K2, revokes 5, 6 and 7. Apply 2 installs bundle 3, the last directory and KRL 7.
        - RED: on 03-08j's head apply 1 commits the held step but returns nil, so no refusal is reported.
      - `retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused`. The record shape of 03-08j's policy_rotation_below_the_recorded_bundle, newOps row:
        - bundle 2 rotates the policy (rotationOps, new admin bob, ops key K2); bundle 3 is successorWithNext of 2 and adds a CA line h.run.rejectCA refuses. Apply 1 returns ca_line_rejected and records {Bundle: 3}.
        - Directories 2-65 arrive, signed under bundle 1's policy, with KRL 7, signed by K1, revoking only 7.
        - Apply 2 is held at the bundle in force (P = F = bundle 1). It commits directory 65 under bundle 1 with KRL 5 still in force and accepted/'s KRL, manifest and sig byte-equal to before, returns an error matching state.ErrKRLSignerRetired, and the record stays {Bundle: 3}.
        - RED: on 03-08j's head KRL 7 lands with directory 65 and drops serial 5.
      - **TestApply/catch_up_across_policy_rotation, newOps=true row** (apply_test.go): held at k=0, so P = F = bundle 1, and KRL 7 is signed by N's new key.
        - The assertion that fails when the KRL was taken under bundle 1 becomes its opposite. Apply 1 takes it: r.KRLVersion is f.krlVersion and current revokes 7, with directory 1 + MaxVersionsPerKind, bundle 1 and BundleHeld.
        - Apply 2's assertions and the closing no-admin step are unchanged. The comment "the KRL waits with the bundle" becomes "the KRL lands with the held step (03-08k)".
        - RED on Task 1's head.
      - **The subtest TestSpoolWindow/policy_rotation_below_the_recorded_bundle/newOps=true** (window_test.go; 03-08j made the rows subtests): the same flip. "With newOps, the KRL the new key signed is not taken under bundle 1" becomes: it is taken with the held step, signed by the record's bundle's key. The record stays {Bundle: 3}. RED on Task 1's head.
    - **A poll from the record.** This group introduces the two subtests and the one assertion function that every wait case of this plan uses (the truth "A poll decides a KRL as forward does"; Task 3 uses them for its wait cases too):
      - subtest `poll`: the case's KRL is published at the wait's first sleep (h.clock.onSleep, once, as superseded_during_wait_krl_applied guards it), so only a poll sees it;
      - subtest `forward`: the same KRL is published before the widening apply, so forward decides it. The first-sleep hook does everything else it does in `poll`. The KRL stays in the spool through the wait, so this subtest also pins that no later poll undoes forward's decision.

      The assertion is the same in both subtests:
      - after the apply, accepted/'s bundle and directory versions, the KRL version in force, and which of the case's serials current revokes are the case's expected values;
      - krl_signer_retired is named, in the apply's error or in the wait's log, in both subtests or in neither.

      Every wait case fails when the widening apply did not sleep.
      - `retired_key_krl_during_a_wait_from_the_record_is_refused` (the in-force key, which the record's bundle retired):
        - Built with Task 1's recordBelowWait(t, K2, nil), so the record's bundle 3 names K2. Apply 2 holds at bundle 1 (P = F, key K1) below it, and waits.
        - The case's KRL is KRL 8, signed by K1, revoking 5 and 8. The first-sleep hook only runs h.resetSpool and h.write.
        - `poll`: the poll reads from the record, and its capture brings nothing beyond it. Its KRL step fails under bundle 3 (P) with krl.ErrSigner. No bundle the poll knows lies above bundle 3, so there is no successor to try. F, bundle 1, verifies KRL 8, and F's key is retired by the record's bundle, a step of the poll's capture. The KRL step refuses KRL 8 before the KRL-alone call, and the wait logs krl_signer_retired. `forward`: the KRL step refuses KRL 8 under the held step (KRLRefused, as in `retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused`), and the apply returns krl_signer_retired.
        - Expected in both: directory 2 is in force under bundle 1, KRL 5 is in force, current does not revoke 8, and the record stays {Bundle: 3}.
        - RED on Task 1's head:
          - in `forward`, KRL 8 lands with the held step;
          - in `poll`, only by the refusal code: VerifyAhead's KRL step refuses KRL 8 there too, but with krl_not_verified, so it never lands.
        - This case runs the path where a wider poll was feared. The record names the new key, the capture brings nothing beyond the record, and an old-key KRL arrives. It must survive the nil-from mutant (see the mutants).
  </behavior>
  <read_first>
    Task 1's edits are in context. Find each with `grep -n` on the branch.
    - internal/agent/state/verify.go: `func verify(`, `func Verify(`'s doc comment, the Verified struct's BundleHeld comment, `func (v *Verified) verifyKRLUnder(` with its held-wait comment, and `func KRLAlone(` (about 6 KB). internal/agent/state/state.go: the Refusals var block (about 1 KB).
    - internal/agent/apply/status.go: `refusals`. internal/agent/apply/apply.go: `func outcome(`, forward's refused-Verify warning and `func (e *engine) pollCapture(` (about 4 KB). internal/agent/apply/krlsigner_test.go: Task 1's recordBelowWait and record_signed_krl_during_a_wait_lands.
    - internal/agent/apply/apply_test.go: rotation, rotationOps, `func (h *testHost) resetSpool(` and `t.Run("catch_up_across_policy_rotation"`. internal/agent/apply/window_test.go: policy_rotation_below_the_recorded_bundle. internal/agent/apply/harness_test.go: `func (f *fixture) krl(` (about 7 KB together).
  </read_first>
  <action>
**Tests first.** Write the cases in `<behavior>`, flip the two newOps=true assertions, and run them on Task 1's head. Record which were RED and which GREEN at once, with the reasons given there. Then implement. This is the retired-key rule of the owner's decisions of 2026-11-01 (always refuse) and the held rule, on every path within one capture.

**state, state.go.** `ErrKRLSignerRetired = errors.New("krl_signer_retired")` joins the Refusals block. Its comment cites `(03-08k)`: a KRL whose only authoriser is an ops key a newer verified bundle the host knows dropped. It never lands, and nothing else of its capture is installed with it.

**state, verify.go: the definitions.** Two unexported helpers implement the Planner decisions' definitions, with from being v itself on the KRL step:
- the newest of known(X): from's verified bundle steps above X and from.fullyVerified when above X, by version, fullyVerified on a tie;
- retired(X): that newest bundle exists and its OpsKey.Key differs from X's.

**state, the KRL step.** verify's call of verifyKRL becomes `v.krlStep(p, chain, alone, in)`. Because it runs inside verify, the rule holds for every caller alike: forward's Verify and VerifyAhead, the preflight's Verify, and pollCapture's two verify calls (Task 3 carries what those know).
- **Definitions.** K is the capture's newest complete KRL. P is v.Bundle, the bundle the capture puts in force: under BundleHeld the held step, and with 03-08j's in-force hold step possibly F. F is alone's bundle, present only when alone and alone.Bundle are non-nil. S is v.fullyVerified when above P.
- **The skip rules come first, unchanged.** Byte-equal or the same version is no change, and an older version is krl_older. No candidate is tried for them.
- **The authoriser.** K is checked with verifyKRLUnder under P. Only when that error wraps krl.ErrSigner is it checked under S, when S's ops key differs from P's, and then under F, when F's ops key differs from P's and S's. The first candidate that verifies K is its authoriser.
- **The rule.** When the authoriser's key is retired, K never lands. The refusal is an error wrapping ErrKRLSignerRetired that names the authoriser's bundle version and the newest known version.
  - Without BundleHeld, krlStep returns it, and Verify returns it with nothing installed.
  - Under BundleHeld (owner, 2026-11-01), krlStep sets `v.KRLRefused` to it and returns nil, so the held step commits as on main with the KRL in force unchanged.
- **No candidate writes v.** Today's verifyKRL writes v.KRL, KRLChanged and the four Next.KRL* fields (KRL, KRLManifest, KRLSig, KRLVersion) as soon as the manifest verifies, so after a retired authoriser they would hold the refused KRL. verifyKRLUnder therefore returns the verified KRL (the parsed KRL, its files and its version) and assigns nothing. krlStep and KRLAlone assign all six fields together, and only when K lands. A leaked Next.KRL, KRLManifest or KRLSig would be stored in accepted/, and the next quiet apply's byte-equal skip would then install the retired KRL. The stored KRL's parse, which sets v.KRL to the KRL in force, stays as it is.
  - Otherwise K is taken with the capture, a held step included.
- **Verified gains `KRLRefused error`**, exported, with a comment citing `(03-08k)`: set only under BundleHeld when the capture's newest KRL was refused for a retired signer. The capture's held step is taken, the KRL in force stays, and the caller reports it after the commit. It is not Refused, which marks a KRL-alone Verified and which krlAlone's guard, 03-08j's recording and VerifyAhead's Changed recomputation read.
- **No authoriser.** Main's behaviour: under BundleHeld the KRL waits (no KRL change), and otherwise P's original error is returned unchanged, never a later candidate's.
- **The doc comment** cites `(03-08k)` and states three things:
  - the owner's rule: no KRL lands that neither the bundle in force nor a fully verified successor authorises;
  - why a KRL whose authoriser's key is retired never lands: a retired key may be a compromised one;
  - why F is tried at all: only to name the refusal, since reaching it means its key is retired.

**state, KRLAlone.** Its candidates are F (prev's bundle), then Task 1's S. When K is new (KRLChanged) and its authoriser's key is retired by from's known bundles, KRLAlone returns nil and errors.Join(refusal, an error wrapping ErrKRLSignerRetired with the same versions). The doc comment adds the rule and cites `(03-08k)`.

**Doc comments** (each cites `(03-08k)`):
- Verify's KRL bullet (verify.go, about lines 107-112): its last sentence, which says that under BundleHeld a KRL the bundle in force does not verify waits along with that bundle, is replaced by the rule. The authoriser is the first of P, the successor and F that verifies the KRL. A KRL whose authoriser's key a newer known bundle dropped is refused with krl_signer_retired: under BundleHeld the held step is taken without it (KRLRefused), and otherwise Verify returns the refusal. Any other authorised KRL lands with the capture, a held step included. A KRL no candidate verifies waits under BundleHeld and is an error otherwise.
- Verified.BundleHeld's comment: "and a KRL only its ops key verifies" waits no longer. A KRL the successor's key signed lands with the held step.
- verifyKRL's held-wait comment ("Signed by an ops key of a bundle this capture holds back: it waits for that bundle") moves into krlStep's no-authoriser branch as "signed by no known key: it waits for the next capture".

**apply, status.go.** state.ErrKRLSignerRetired joins `refusals`, so last_apply.result is refused.

**apply, apply.go.** outcome(v) returns errors.Join(v.Refused, v.KRLRefused), with errNoDirectory as today, so forward reports a held step's refused KRL after the commit, a superseding poll's included (forward returns outcome(tv)). When v.KRLRefused is set, forward logs `WARNING <refusal>; the held step is applied, and the KRL in force stays` beside its refused-Verify warning. Its doc comment cites `(03-08k)`.

**Local time, commit and mutants.**
- Run the Budget's alone gate (limit 400 s) and its `./...` margin run (limit 480 s). Record internal/agent/apply's `ok` line from each beside Task 1's two bases.
- If the alone time is above the alone base + 120 s or above 400 s, whichever comes first, or the `./...` time is above 480 s, stop before the commit and thin the slowest new cases. If that cannot bring the time under, stop and report (Budget).
- Commit the code and tests by path, authored as the Delivery protocol says, as `fix(agent): refuse a KRL whose ops key a newer verified bundle dropped`.
- Run the mutants as the scripted loop. Read the two flipped tests' evidence per row: catch_up_across_policy_rotation's newOps=true row, and the subtest policy_rotation_below_the_recorded_bundle/newOps=true.
- Commit the SUMMARY draft the same way (`docs(03-08k): record the retired-key rule's evidence`).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "^TestKRLSigner$|^TestKRLAlone$/^(ops_key_changed_krl_lands_alone|oversize_principals_file_krl_applied|bundle_step_refused_krl_applied|krl_refused_too_changes_nothing|ca_line_rejected_krl_applied|superseded_during_wait_krl_applied)$|^TestSpoolWindow$/^(krl_only_the_recorded_bundle_signs_lands_alone|policy_rotation_below_the_recorded_bundle|held_content_refusal_keeps_the_records_bundle|bundle_fork_after_the_record_takes_the_krl_against_accepted|refused_window_newest_then_fix_applies)$|^TestApply$/^catch_up_across_policy_rotation$|^TestStatus$/^cap_refusal_is_refused$|^TestSpoolWindowWideningWait$" ./internal/agent/apply/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestKRLSigner/record_signed_krl_during_a_wait_lands/poll", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_from_the_record_is_refused/poll", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_from_the_record_is_refused/forward", "--- PASS: TestSpoolWindowWideningWait/nothing_new", "--- PASS: TestSpoolWindow/policy_rotation_below_the_recorded_bundle/newOps=true", "--- PASS: TestKRLSigner/retired_key_krl_on_the_krl_step_is_refused", "--- PASS: TestKRLSigner/krl_third_key_under_changed_bundle_not_retired", "--- PASS: TestKRLSigner/first_install_krl_refusal_unchanged", "--- PASS: TestKRLSigner/krl_the_new_bundle_authorises_applies_with_it", "--- PASS: TestKRLSigner/unchanged_krl_under_a_rotated_bundle_installs", "--- PASS: TestKRLSigner/retired_key_krl_after_a_refused_directory_is_refused", "--- PASS: TestKRLSigner/retired_key_krl_after_a_refused_bundle_step_is_refused", "--- PASS: TestKRLSigner/rotated_back_key_is_current", "--- PASS: TestKRLSigner/held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step", "--- PASS: TestKRLSigner/held_step_krl_signed_by_a_retired_key_is_refused", "--- PASS: TestKRLSigner/retired_in_force_key_krl_under_a_held_step_is_refused", "--- PASS: TestKRLSigner/retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused", "--- PASS: TestKRLSigner/successor_signed_krl_after_a_refused_directory_lands_alone", "--- PASS: TestApply/catch_up_across_policy_rotation", "--- PASS: TestSpoolWindow/policy_rotation_below_the_recorded_bundle", "--- PASS: TestSpoolWindow/held_content_refusal_keeps_the_records_bundle"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/agent/state/state.go | grep -c 'krl_signer_retired'` prints 1, and `grep -v '^[[:space:]]*//' internal/agent/apply/status.go | grep -c 'state.ErrKRLSignerRetired'` prints at least 1.
    - `grep -v '^[[:space:]]*//' internal/agent/state/verify.go | grep -c 'KRLRefused'` and `grep -v '^[[:space:]]*//' internal/agent/apply/apply.go | grep -c 'KRLRefused'` each print at least 1.
    - The old comments are gone, read with the comment markers stripped and the whitespace normalised, because a comment can wrap across lines (apply_test.go's does: "the KRL" / "// waits with the bundle."). On origin/main each of the first two commands below prints 1:
      - `sed 's#^[[:space:]]*//##' internal/agent/state/verify.go | tr -s '[:space:]' ' ' | grep -c 'waits with the bundle'` prints 0;
      - `sed 's#^[[:space:]]*//##' internal/agent/apply/apply_test.go | tr -s '[:space:]' ' ' | grep -c 'the KRL waits with the bundle'` prints 0;
      - `sed 's#^[[:space:]]*//##' internal/agent/apply/apply_test.go | tr -s '[:space:]' ' ' | grep -c 'the KRL lands with the held step (03-08k)'` prints 1.
    - The SUMMARY draft records the alone and `./...` times and these mutants, each applied, run against its named test, and restored byte for byte:
      - the retirement check removed in KRLAlone: killed by `retired_key_krl_after_a_refused_directory_is_refused`, where KRL 6 lands and drops serial 5;
      - the retirement check removed in krlStep, so every authoriser is taken with the capture: killed by `retired_key_krl_on_the_krl_step_is_refused` (apply 1 installs bundle 2, directory 2 and KRL 6) and `held_step_krl_signed_by_a_retired_key_is_refused` (KRL 6 lands with the held step);
      - F not tried in krlStep: killed by `retired_key_krl_on_the_krl_step_is_refused` (krl_not_verified) and `retired_in_force_key_krl_under_a_held_step_is_refused` (no refusal is reported);
      - the held step dropped, the refusal returned as a Verify error under BundleHeld too: killed by `retired_in_force_key_krl_under_a_held_step_is_refused`, `held_step_krl_signed_by_a_retired_key_is_refused` and `retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused` (the held step does not commit);
      - outcome ignoring KRLRefused: killed by `retired_in_force_key_krl_under_a_held_step_is_refused` (apply 1 returns nil);
      - a partial reset, where the refused KRL's Next.KRL, KRLManifest and KRLSig are assigned and only v.KRL, KRLChanged and Next.KRLVersion are kept: killed by `held_step_krl_signed_by_a_retired_key_is_refused` (accepted/'s bytes differ after apply 1, and apply 2 installs bundle 3 with the retired KRL);
      - known(X) without the steps verified before a refused bundle step: killed by `retired_key_krl_after_a_refused_bundle_step_is_refused`;
      - retired when any known bundle above X names another key (Q4 off): killed by `rotated_back_key_is_current`;
      - krlStep's S branch removed: killed by `held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step`, by catch_up_across_policy_rotation's newOps=true row and by the subtest `policy_rotation_below_the_recorded_bundle/newOps=true`, each read on its own;
      - the S branch landing K alone through KRLAlone instead of with the held step: killed by `held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step` (directory 65 would wait);
      - krl_signer_retired returned before K is verified under F: killed by `krl_third_key_under_changed_bundle_not_retired`;
      - the retirement check run before the skip rules: killed by `unchanged_krl_under_a_rotated_bundle_installs`;
      - F tried without the "alone has a bundle" guard: killed by `first_install_krl_refusal_unchanged`;
      - the `refusals` entry removed: killed by `retired_key_krl_on_the_krl_step_is_refused` (last_apply.result).
    - The SUMMARY draft also records one mutant that must survive. Task 1's "pollCapture passes nil as from" is run again against `retired_key_krl_during_a_wait_from_the_record_is_refused/poll` and `/forward`, and both stay GREEN, because the KRL step refuses the old-key KRL before the KRL-alone call. The SUMMARY names this the evidence that a nil from cannot widen a poll. If either subtest fails under the mutant, that claim is false: stop and report.
  </acceptance_criteria>
  <done>A KRL whose authoriser's key a newer verified bundle in the capture dropped never lands, on the KRL step, under a hold, or in the KRL-alone pass, also in a widening wait's poll read from the record, and krl_signer_retired is reported. Without a held step nothing else of its capture is installed; a held step commits with the KRL in force unchanged. A KRL the successor's key signed lands with a held step.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: What the apply knows beyond one capture: the record's bundle (VerifyAhead); the pending capture's in every poll, on each of pollCapture's branches (VerifyAfter, VerifyAheadAfter), with the polls deciding as forward does; the withheld-bundle boundary; and the narrow fallback's equivalence pinned</name>
  <reversibility rating="reversible">VerifyAhead and pollCapture's two verify calls pass one more verified bundle to verify (pollCapture calls VerifyAfter and VerifyAheadAfter). No on-disk format, wire message or signed document changes.</reversibility>
  <files>internal/agent/state/verify.go, internal/agent/state/unapplied.go, internal/agent/apply/apply.go, internal/agent/apply/krlsigner_test.go, internal/krl/krl_test.go</files>
  <behavior>
    TestKRLSigner gains these cases, each with t.Parallel, on Task 2's fixture.
    - **The record (03-08j).**
      - `successor_from_the_record_after_a_refused_bundle_step_above_it`:
        - Apply 1: bundle 2 with directory 2 above the caps and no newer KRL. It returns generation_too_large and records {Bundle: 2, Directory: 2}.
        - Then bundle 3 is a successor of bundle 2 whose sigs are replaced by bundle 2's (bundle_not_verified), and KRL 6, signed by K2, revokes 5 and 6.
        - Apply 2 reads from the record. Its error matches state.ErrBundle and not state.ErrKRL. Current revokes 6, accepted/ stays at bundle 1 and directory 1, and the record stays.
        - RED on Task 2's head: krl_not_verified, because the capture's bundle step was refused and nothing carried the record's bundle.
      - `record_successor_dropped_by_a_verified_bundle_above_it_is_refused` (the fail-closed shape under Planner decisions): as the previous case, but bundle 3 replaces K2 with K3 and verifies (f.rotationOps from bundle 2 with a fresh signer K3, made as K2 was), bundle 4 is refused as bundle 3 was there, and KRL 6 is signed by K2. Apply 2's error matches state.ErrBundle and state.ErrKRLSignerRetired, nothing is installed, and the record stays. RED on Task 2's head for the code only: krl_not_verified.
    - **A poll during a widening wait** (03-08j's pollCapture verifies a poll's capture against the pending target). Each wait case below runs its shape twice, with the subtests `poll` and `forward` and the one assertion function that Task 2 introduced. With Task 1's and Task 2's record cases, these are the five wait cases that test the truth "A poll decides a KRL as forward does". Every wait case fails when the widening apply did not sleep.
      - `retired_key_krl_during_a_wait_is_refused` (no record):
        - h.clock.advance(time.Hour), then KRL 5, signed by K1, is published and applied. That swap is the one the widening apply must wait after.
        - The window of catch_up_across_policy_rotation's newOps=true row, with no record: bundle 2 rotates the admins and the ops key to K2, and the window's directories, signed by the original admin, add role:q. The capture is held at the bundle in force (P = F = bundle 1, BundleHeld) and widens, so the apply waits. Nothing is refused, so nothing is recorded.
        - The case's KRL is KRL 7, signed by K1, revoking 5 and 7. At the wait's first sleep, bundle 2 and every directory above the pending target leave h.state, and h.resetSpool and h.write run.
        - `poll`: the poll's KRL verifies under P, whose key bundle 2 retired, and bundle 2 is known only from the pending capture. The wait logs krl_signer_retired. `forward`: the KRL step refuses KRL 7 under the held step (KRLRefused), and the apply returns krl_signer_retired.
        - Expected in both: directory 1 + MaxVersionsPerKind is in force under bundle 1, KRL 5 is in force, and current does not revoke 7.
        - RED on Task 2's head, in both subtests. In `poll`, the poll takes KRL 7 as the superseding generation. In `forward`, forward refuses it, and then a poll takes it.
      - `successor_signed_krl_during_a_wait_lands` (no record): as the previous case, but the KRL is KRL 8, signed by K2, revoking 5 and 8.
        - `poll`: the poll's KRL fails under P, and its successor is bundle 2, carried from the pending capture, so KRL 8 is taken with the pending target's state as the superseding generation. `forward`: KRL 8 lands with the held step (Task 2's held rule).
        - Expected in both: directory 1 + MaxVersionsPerKind is in force under bundle 1, and current revokes 5 and 8.
        - RED on Task 2's head in `poll`: the poll logs krl_not_verified, and KRL 8 waits for the next apply. `forward` is GREEN at once.
      - `retired_key_krl_during_a_wait_above_the_record_is_refused` (from the record; it pins the higher of the record's bundle and the pending capture's):
        - Built with Task 1's recordBelowWait(t, nil, K2). The record's bundle 3 keeps K1, and bundle 4 above it names K2.
        - Apply 2's capture is read from the record. It verifies bundle 4 in full and holds at bundle 1 (P = F), so the pending capture's fullyVerified is bundle 4.
        - The case's KRL is KRL 8, signed by K1, revoking 5 and 8. At the wait's first sleep, bundle 4 and its policy leave h.state, and h.resetSpool and h.write run.
        - `poll`: the poll reads from the record, and its capture brings nothing beyond it. Its KRL step verifies KRL 8 under bundle 3, whose key bundle 4 retired, and bundle 4 is known only from the pending capture. The wait logs krl_signer_retired. `forward`: bundle 4 is a step of forward's capture, so the KRL step refuses KRL 8 under the held step, and the apply returns krl_signer_retired.
        - Expected in both: directory 2 is in force under bundle 1, KRL 5 is in force, current does not revoke 8, and the record stays {Bundle: 3}.
        - RED on Task 2's head, in both subtests. Each poll's VerifyAhead knows only the record's bundle, so KRL 8 is current under bundle 3 and lands through the KRL-alone pass: in `poll` at the first poll, and in `forward` after forward refused it.
      - `record_signed_krl_during_a_wait_lands` (from the record; Task 1's case, with its subtest `poll` unchanged). This task adds its subtest `forward`: KRL 8, signed by K2, is published before apply 2, and lands with the held step, signed by the record's bundle's key. Expected in both: Task 1's. `forward` is GREEN at once on Task 2's head (the held rule).
      - `retired_key_krl_after_a_krl_alone_supersede_is_refused` (KRLAlone's Verified inherits fullyVerified):
        - The fixture of retired_key_krl_during_a_wait_is_refused, up to apply 2's wait.
        - At the wait's first sleep (once): bundle 2 and every directory above the pending target leave h.state. One directory above the pending target, signed under bundle 1's policy and above the caps (bulkRoles 17), is published, together with KRL 8, signed by K2, revoking 5 and 8. h.resetSpool and h.write run.
        - The poll's generation is refused for its content (generation_too_large). Its KRL-alone pass lands KRL 8 under the carried successor (bundle 2), and that KRL-alone Verified supersedes the pending target. The superseding generation still carries the held directory, so it still widens and the wait goes on.
        - At the next sleep after the supersede (once): KRL 9, signed by K1, revokes 5, 8 and 9, and h.resetSpool and h.write run. This poll verifies against the KRL-alone pending, which inherited bundle 2, so KRL 9 is refused (krl_signer_retired, logged).
        - After the apply, directory 1 + MaxVersionsPerKind is in force under bundle 1, current revokes 8 and not 9, and the apply's error matches generation_too_large.
        - RED on Task 2's head: the first poll cannot land KRL 8, and the second lands KRL 9.
        - If the executor finds that a KRL-alone supersede ends the wait, the case cannot be built as written. Then the SUMMARY labels the inheritance UNVERIFIED with that reason, lists its mutant as surviving, and records the deviation.
    - **The boundary** (the owner's decision on what the host knows):
      - `retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main`:
        - Apply 1 is retired_key_krl_on_the_krl_step_is_refused's: refused with krl_signer_retired, nothing installed, and no unapplied.json.
        - Then bundle 2 and directory 2 leave h.state, and h.resetSpool and h.write run, so the spool holds KRL 6 and no newer bundle.
        - Apply 2 returns nil. Current revokes 5 and 6, and accepted/ stays at bundle 1, now with KRL 6.
        - GREEN at once on Task 2's head. The host no longer knows bundle 2, so the KRL is taken as on main. This is the withholding-server residual's boundary, and the SUMMARY names it so.
    - **The narrow fallback:**
      - `krl_other_error_under_changed_bundle_keeps_its_error`: bundle 2 is offered, and KRL 6 is signed by K2 but names another installation (f.krl's id argument). The error is main's: it matches state.ErrKRL and krl.ErrInstallation and contains "the manifest is for another installation", and it matches neither krl.ErrSigner nor state.ErrKRLSignerRetired. GREEN at once.
      - `krl_in_force_key_for_another_installation_keeps_the_first_error`: bundle 2 is offered, and KRL 6 is signed by K1 but names another installation. The error is the one under bundle 2: it matches state.ErrKRL and krl.ErrSigner, not krl.ErrInstallation and not state.ErrKRLSignerRetired. Nothing is installed. GREEN at once: the fallback returns the first error unchanged.
      - `TestVerifyManifest/bundle_read_only_for_its_ops_key` (internal/krl/krl_test.go). Every row of the refusal table, and the accepted case, runs again under a copy of f.bundle that keeps only its ops key: another version, CA set, root set, log key and installation ID. Each row gives the same sentinel, and the accepted case is still accepted. GREEN at once.
  </behavior>
  <read_first>
    Task 2's edits are in context. Find each with `grep -n` on the branch.
    - internal/agent/state/verify.go: `func verify(`, `func Verify(` and the fullyVerified comment (about 3 KB). internal/agent/state/unapplied.go: `func VerifyAhead(` and `func (u *Unapplied) Base(` (about 2 KB).
    - internal/agent/apply/apply.go: `func (e *engine) pollSpool(` and `func (e *engine) pollCapture(`, each with its doc comment, and forward's supersede step (`target, tv = s.gen, s.verified`) (about 5 KB). internal/agent/apply/swap.go: `func (e *engine) waitWidening(` (about 1 KB).
    - internal/agent/apply/rechain_test.go: superseded_during_wait_krl_applied (its onSleep hook). internal/agent/apply/window_test.go: fork_after_the_record_refused. internal/agent/apply/krlsigner_test.go: Task 1's recordBelowWait and record_signed_krl_during_a_wait_lands. internal/agent/apply/harness_test.go: fakeClock (about 6 KB together).
    - internal/krl/krl_test.go: `func TestVerifyManifest(` and newManifestFixture (about 3 KB).
  </read_first>
  <action>
**Tests first.** Write the cases in `<behavior>`, and add the subtest `forward` to Task 1's `record_signed_krl_during_a_wait_lands`. Run them on Task 2's head. Record which were RED and which GREEN at once, per subtest, with the reasons given there. Then implement. This is the owner's decisions of 2026-11-01 on the record as a successor and on what the host knows, with the knowledge of the forward capture carried into every poll of the same apply. It is also the owner's decision of 2026-11-02 that a poll decides as forward does, on each of pollCapture's three branches.

**state, verify.go.**
- **verify gains a final `carried *trust.Bundle`:** a bundle this apply verified in full outside the capture. verify starts v.fullyVerified at carried, and when the bundle step returned nil raises it to the capture's newest bundle step if that is above carried (on a tie carried stays). Task 1's rule is unchanged apart from the starting value.
- **Verify** passes nil, so it reads as in Task 2.
- **`func VerifyAfter(p *Pins, pending *Verified, in spool.State) (*Verified, error)`** is verify(p, prev, prev, in, pending.fullyVerified), with prev being pending.AsStored(). It serves pollCapture's branch without a record. Its doc comment cites `(03-08k)`: a capture during a widening wait is verified against the pending target, and it knows every bundle the apply verified in full before it. Every Verified it returns, KRLAlone's included, carries that bundle on, so a later poll after a supersede knows it too.

**state, unapplied.go.**
- **Today's VerifyAhead body** (verify, then the Changed recomputation against accepted) moves into an unexported `verifyAhead(p, accepted, base, in, carried)`, which passes carried to verify.
- **VerifyAhead** keeps its signature. It passes as carried base's parsed bundle when base.BundleVersion is above accepted.BundleVersion (03-08j's Base takes a bundle part only then), and nil otherwise. Its doc comment gains one sentence citing `(03-08k)`: the record's bundle verified in full when it was recorded, so it authorises a KRL its ops key signed, also when a bundle offered above it is refused, unless a bundle this capture verified above it retired that key.
- **`func VerifyAheadAfter(p *Pins, pending *Verified, base *Stored, in spool.State) (*Verified, error)`** is verifyAhead with accepted = pending.AsStored(). Its carried is the higher, by version, of two bundles: the record's bundle, taken by VerifyAhead's rule against that accepted, and pending.fullyVerified. On a tie it is pending's, and either may be nil. It serves pollCapture's record branch (owner, 2026-11-02). Its doc comment cites `(03-08k)`: a poll read from the record knows the record's bundle and every bundle the apply verified in full before it, so it decides a KRL as forward does. The higher of the two is taken here because fullyVerified is unexported.

**apply, apply.go: pollCapture.**
- It takes `pending *state.Verified` in place of `prev *state.Stored`, and computes prev := pending.AsStored() itself. loadUnapplied and the floors are unchanged.
- Its branch without a record calls `state.VerifyAfter(e.pins, pending, st)` in place of state.Verify.
- Its record branch calls `state.VerifyAheadAfter(e.pins, pending, base, st)` in place of state.VerifyAhead.
- The call on the branch that brings nothing beyond the record stays Task 1's `state.KRLAlone(e.pins, prev, st, nil, v)`.
- Its doc comment cites `(03-08k)`: each branch knows what the pending capture knew, and from the record also the record's bundle, so a poll decides a KRL as forward does.

pollSpool calls `e.pollCapture(pending)`. It keeps prev (pending.AsStored()) for its krlAlone call, and its doc comment's "verified as forward's is (pollCapture)" gains "with what the pending capture knew (03-08k)". forward is unchanged.

**The two narrowing conditions are equivalent mutants.** Removing either one changes no outcome:
- the krl.ErrSigner restriction, before the later candidates in krlStep and KRLAlone;
- the "ops key differs" conditions on S and F.

Both rest on two facts, each pinned by a GREEN-at-once case of this task:
- **krl.VerifyManifest reads the bundle only for its ops-key comparison** (TestVerifyManifest/bundle_read_only_for_its_ops_key). Its checks before that comparison read only the manifest, the signature and the KRL bytes, and those after it only the installation ID and stored-version arguments. So a non-signer error under one bundle is the same error, or krl.ErrSigner, under every other bundle, and a bundle with the same ops key gives the same result.
- **The fallback returns the first candidate's error unchanged:** P's in krlStep, F's in KRLAlone (krl_in_force_key_for_another_installation_keeps_the_first_error). A fallback that returned a later candidate's error would make the restriction observable.

**One equivalent mutant of VerifyAheadAfter.** Dropping the record's half of the higher-of, so that only pending.fullyVerified is carried, changes no outcome on any reachable path. Within one apply the pending capture's fullyVerified already starts at the record's bundle: forward's VerifyAhead carried it, or forward wrote the record from that very capture, and every later poll inherits it. A version tie between the two halves therefore means the same bundle, because pending's chain was verified against the record's bytes, so the tie rule decides nothing either. Only a record rewritten during the wait could differ. The half is kept so that a poll never knows less than the record, whatever the pending target's origin. The SUMMARY lists this mutant with that reason.

`retired_key_krl_after_a_krl_alone_supersede_is_refused` pins KRLAlone's inheritance through a supersede and a later poll. UNVERIFIED: no test supersedes the pending target twice within one wait.

**Local time, commit and mutants.**
- Run the Budget's alone gate (limit 400 s) and its `./...` margin run (limit 480 s). Record internal/agent/apply's `ok` line from each beside Task 1's two bases and Task 2's figures.
- If the alone time is above the alone base + 120 s or above 400 s, whichever comes first, or the `./...` time is above 480 s, stop before the commit and thin the slowest new cases. If that cannot bring the time under, stop and report (Budget).
- Commit the code and tests by path, authored as the Delivery protocol says, as `fix(agent): carry the verified bundle into the record's capture and the wait's polls`.
- Run the mutants as the scripted loop, then commit the SUMMARY draft the same way (`docs(03-08k): record the knowledge rule's evidence`).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "^TestKRLSigner$|^TestVerifyManifest$|^TestApply$/^catch_up_across_policy_rotation$|^TestSpoolWindow$/^(policy_rotation_below_the_recorded_bundle|held_content_refusal_keeps_the_records_bundle|krl_only_the_recorded_bundle_signs_lands_alone|bundle_fork_after_the_record_takes_the_krl_against_accepted|refused_window_newest_then_fix_applies)$|^TestKRLAlone$/^(ops_key_changed_krl_lands_alone|ca_line_rejected_krl_applied|superseded_during_wait_krl_applied)$|^TestSpoolWindowWideningWait$" ./internal/agent/apply/ ./internal/krl/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestKRLSigner/successor_from_the_record_after_a_refused_bundle_step_above_it", "--- PASS: TestKRLSigner/record_successor_dropped_by_a_verified_bundle_above_it_is_refused", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_is_refused/poll", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_is_refused/forward", "--- PASS: TestKRLSigner/successor_signed_krl_during_a_wait_lands/poll", "--- PASS: TestKRLSigner/successor_signed_krl_during_a_wait_lands/forward", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_above_the_record_is_refused/poll", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_above_the_record_is_refused/forward", "--- PASS: TestKRLSigner/record_signed_krl_during_a_wait_lands/poll", "--- PASS: TestKRLSigner/record_signed_krl_during_a_wait_lands/forward", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_from_the_record_is_refused/poll", "--- PASS: TestKRLSigner/retired_key_krl_during_a_wait_from_the_record_is_refused/forward", "--- PASS: TestSpoolWindowWideningWait/nothing_new", "--- PASS: TestSpoolWindowWideningWait/newer_directory_under_the_policy_in_force", "--- PASS: TestKRLSigner/retired_key_krl_after_a_krl_alone_supersede_is_refused" (unless the SUMMARY records the deviation the case allows), "--- PASS: TestKRLSigner/retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main", "--- PASS: TestKRLSigner/krl_other_error_under_changed_bundle_keeps_its_error", "--- PASS: TestKRLSigner/krl_in_force_key_for_another_installation_keeps_the_first_error", "--- PASS: TestKRLSigner/retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused", "--- PASS: TestVerifyManifest/bundle_read_only_for_its_ops_key", "--- PASS: TestKRLAlone/superseded_during_wait_krl_applied", "--- PASS: TestSpoolWindow/krl_only_the_recorded_bundle_signs_lands_alone", "--- PASS: TestSpoolWindow/policy_rotation_below_the_recorded_bundle"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'func VerifyAfter(' internal/agent/state/verify.go` prints 1, and `grep -c 'func VerifyAheadAfter(' internal/agent/state/unapplied.go` prints 1.
    - pollCapture's three calls are routed, and forward's two are unchanged. `grep -c '^func (e \*engine) pollCapture(pending \*state.Verified)' internal/agent/apply/apply.go` prints 1. With `C=$(grep -v '^[[:space:]]*//' internal/agent/apply/apply.go)`, each of these prints 1:
      - `printf '%s\n' "$C" | grep -c 'state.VerifyAfter('`;
      - `printf '%s\n' "$C" | grep -c 'state.VerifyAheadAfter('`;
      - `printf '%s\n' "$C" | grep -c 'state.Verify('` (forward's);
      - `printf '%s\n' "$C" | grep -c 'state.VerifyAhead('` (forward's);
      - `printf '%s\n' "$C" | grep -c 'state.KRLAlone(e.pins, prev, st, nil, v)'` (pollCapture's).
    - The SUMMARY draft records the alone and `./...` times and these mutants, each applied, run against its named test, and restored byte for byte:
      - VerifyAhead passing nil as carried: killed by `successor_from_the_record_after_a_refused_bundle_step_above_it`;
      - the retirement check skipped for the successor in KRLAlone: killed by `record_successor_dropped_by_a_verified_bundle_above_it_is_refused`;
      - pollCapture's branch without a record keeping state.Verify (VerifyAfter not called): killed by `retired_key_krl_during_a_wait_is_refused/poll` and `/forward`, and by `successor_signed_krl_during_a_wait_lands/poll`;
      - pollCapture's record branch keeping state.VerifyAhead, so the pending capture's fullyVerified is not carried: killed by `retired_key_krl_during_a_wait_above_the_record_is_refused/poll` and `/forward`;
      - KRLAlone's Verified given a nil fullyVerified instead of from's: killed by `retired_key_krl_after_a_krl_alone_supersede_is_refused` (the second poll lands KRL 9);
      - the fallback returning the last candidate's error: killed by `krl_in_force_key_for_another_installation_keeps_the_first_error`.
    - The SUMMARY draft lists the equivalent mutants with their reasons:
      - the krl.ErrSigner restriction removed, and the "ops key differs" conditions removed, in krlStep and in KRLAlone, with the two facts above and the cases that pin them;
      - VerifyAheadAfter without the record's half of the higher-of.
  </acceptance_criteria>
  <done>The record's bundle authorises a KRL its key signed even when a bundle above it is refused, unless a verified bundle above it retired that key. Every poll of a widening wait knows the bundles the apply verified before it, on each of pollCapture's branches, so a retired-key KRL is refused there and a successor's KRL lands, exactly as forward decides the same KRL. A bundle known in no apply's capture and no record leaves the KRL as on main, the accepted residual. The fallback's narrowness is pinned by the two facts that make its conditions equivalent.</done>
</task>

<task type="auto">
  <name>Task 4: host-setup.md, the publish edits, the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/host-setup.md, .planning/phases/03-linux-agent-and-revocation/03-08k-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/host-setup.md: the paragraph "Revocations keep applying" with its list of cases and the sentences after it, through 03-08j's far-behind paragraph. Find it with `grep -n` (about 6 KB).
    - .planning/ROADMAP.md: Phase 3's Plans line and wave blocks. .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter and its Task 1 precondition. 03-10 to 03-16: their `wave:` lines.
  </read_first>
  <action>
**host-setup.md (D-20).** Label every changed or new text "Run in CI (03-08k)" with the test names. Add "UNVERIFIED on a real host: no ceremony on main rotates the ops key yet" once, after the new paragraph.
- **The sentence about a KRL signed only by the refused bundle's ops key** ("... waits with that bundle, and before the first install ..."). Replace it with this text:
  - A KRL that only a fully verified successor bundle's ops key signed lands as well. That holds after a content refusal of that bundle, and after a directory the host refuses while the whole bundle chain verified.
  - A fully verified successor is a bundle whose chain from the accepted bundle verified to the pinned roots: in that apply, or in the recorded unapplied state, also when a bundle offered above the recorded one is refused.
  - The KRL is checked against that bundle's ops key, the pinned installation and the host's KRL version, and lands with the accepted bundle and directory.
  - A bundle that only arrived, or one verified before a refused bundle step, never authorises a KRL. Before the first install the refusal stands, and nothing is installed.
  - During a widening wait, a KRL that arrives decides the same way as one that was there when the apply started, also while the host reads from the recorded unapplied state.
  - Run in CI: `ops_key_changed_krl_lands_alone`, `krl_only_the_recorded_bundle_signs_lands_alone`, `successor_signed_krl_after_a_refused_directory_lands_alone`, `successor_from_the_record_after_a_refused_bundle_step_above_it`, `successor_signed_krl_after_a_refused_bundle_step_is_refused`, `successor_signed_krl_needs_a_verified_successor`, `record_signed_krl_during_a_wait_lands`.
- **A new paragraph, "An ops-key rotation", after the list of cases:**
  - **A retired key.** When a verified bundle the host knows names a newer ops key, the old key is retired. The host knows a bundle it verified in the current apply (also one verified before a refused bundle step, and, during a widening wait, every bundle the apply verified before it), or one it recorded as unapplied.
  - **Its KRL never lands** (`krl_signer_retired`), and nothing else of that apply is installed with it: the newer bundle and every directory change, access removals included, wait too. The exception is a held bundle (catching up across a policy rotation): the held bundle and directory are installed, the KRL in force stays, so no revocation is lost, and the refusal is reported. Run in CI: `retired_in_force_key_krl_under_a_held_step_is_refused`, `held_step_krl_signed_by_a_retired_key_is_refused`. The host waits for a KRL the new key signs. The signer publishes one at its next revocation, or at its hourly republish once it runs with the newer bundle (signer side: `TestKRLStartupAndRepublish`), so with an honest server the wait is at most about an hour; that end-to-end wait is UNVERIFIED on a real host. Run in CI: `retired_key_krl_on_the_krl_step_is_refused`, `retired_key_krl_after_a_refused_directory_is_refused`, `retired_key_krl_during_a_wait_is_refused`, `retired_key_krl_during_a_wait_from_the_record_is_refused`, `retired_key_krl_during_a_wait_above_the_record_is_refused`.
  - **A key a newer bundle names again** is current. Run in CI: `rotated_back_key_is_current`.
  - **Under a held bundle** (catching up across a policy rotation), a KRL the newest verified bundle's ops key signed lands with the held bundle and directory. Run in CI: `held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step`, `catch_up_across_policy_rotation`.
  - **Limits.**
    - The hour counts only once a signer process runs with the newer bundle. One started before the bundle was installed publishes nothing, and the hour runs from the last publish. UNVERIFIED on a real host.
    - After a bundle step refused above a verified rotation, with no record, no KRL lands until the bundle chain verifies: the old key is retired, and the new key has no successor in that apply. Before this change the last old-key KRL landed there. A fetcher that controls the spool can cause this with one broken bundle, which is the withholding risk below. Run in CI: `successor_signed_krl_after_a_refused_bundle_step_is_refused`, `retired_key_krl_after_a_refused_bundle_step_is_refused`.
    - The host knows the newer bundle only in the apply that verified it, or while it is recorded as unapplied. A refused apply records nothing, and removing unapplied.json forgets the record: the host then reads from the accepted state (Run in CI (03-08j): `removed_record_reads_from_accepted`). A server that withholds the newer bundle from the next apply, or before the host ever saw it, can still land a KRL the retired key signs on that host, as before this change. Run in CI: `retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main` (the case the rule does not reach). A server holding the retired key can also keep such a KRL newest in the spool and hold the host back; that is the same withholding risk. UNVERIFIED: no test keeps an old-key KRL newest in the spool.
- **03-08j's stuck-window residual.** Its sentence says that KRLs the in-force ops key signed still land while a directory is stuck between the bundle in force and the recorded bundle. After this plan that is false when the recorded bundle replaced the ops key. Rewrite it as: "KRLs signed by the ops key of the bundle in force land, or, when the recorded bundle replaced that key, KRLs signed by the recorded bundle's key. Run in CI (03-08k): `retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused`, `krl_only_the_recorded_bundle_signs_lands_alone`." The rest of that paragraph stays.

**Publish edits.** Make them in this PR, on top of origin/main, which holds 03-08j. Every number is origin/main's value + 1. The values in brackets are what main holds after 03-08j: N/24 plans in 23 waves, total_plans 59, `of 24`, 03-09 at wave 16 depending on 03-08j, and 03-10 to 03-16 at waves 17 to 23.
1. Commit this plan as `.planning/phases/03-linux-agent-and-revocation/03-08k-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each grow by one (N/24 plans in 23 waves → N/25 in 24 waves).
   - After 03-08j's Wave 15 block, insert `**Wave 16** *(blocked on Wave 15 completion)*` with the unchecked entry `03-08k-PLAN.md — KRLs land across an ops-key change: a fully verified successor's key authorises a KRL, and a KRL only a retired key signed is refused`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 16–23 → 17–24), and update each block's "blocked on Wave N completion" clause with them.
   - Add nothing about any other plan.
3. STATE.md: `total_plans` +1 (59 → 60), and the Plan line's `of M` +1 (of 24 → of 25).
4. 03-09-PLAN.md:
   - `wave:` +1 (16 → 17);
   - `depends_on` becomes `["03-08k"]`;
   - Task 1's `<precondition>` gains the clause `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md` exits 0. It goes next to the 03-08c, 03-08d, 03-08e and 03-08j clauses, which stay.
5. The `wave:` lines of 03-10 to 03-16 each +1 (17–23 → 18–24).
6. **Guard.** If origin/main's 03-09 does not hold `wave: 16` and `depends_on: ["03-08j"]`, another plan was slotted in first. Apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY. The automated checks below compute from origin/main, so they hold either way.

**Gates.** Run the Budget's alone gate first (internal/agent/apply alone, limit 400 s), then the full gate locally, whose `./...` run checks the 480 s margin. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**Push and the PR.**
1. Commit by path only, authored as the Delivery protocol says.
2. Push the branch.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(agent): land KRLs across an ops-key change, and refuse KRLs a retired ops key signed"` with a neutral body. Do not enable auto-merge, now or later (owner, 2026-11-02).
4. Wait for the required checks. Record internal/agent/apply's time under -race from the PR's build-test log beside the local figures of Tasks 1-4. CI runs `./...`, so its limit is the 480 s margin. Above it, stop before the merge gate and report to the owner with the two options under Budget; the executor does not choose.

**The SUMMARY.** Complete the draft with:
- the PR number and the check run IDs;
- the RED evidence of each task, with where each was taken;
- the mutants, with the equivalent ones and the two facts and cases that make them so;
- the GREEN-at-once cases with their reasons, the boundary case named as the withholding residual;
- the four changed tests, with the reason for each (the successor rule for the two renames, the held rule for the flipped catch_up row and the flipped subtest `newOps=true`);
- the five wait cases' `poll` and `forward` results, as the test of "a poll decides as forward does", and the nil-from mutant that `retired_key_krl_during_a_wait_from_the_record_is_refused` survives by design;
- the local times of Tasks 1-4 in both modes (alone against 400 s, `./...` against 480 s) and the CI time;
- capslock;
- `requirements-completed` empty: REVOKE-02 and REVOKE-03 are complete since earlier plans, and this plan hardens both.

Then run the tracking updates once, commit `docs(03-08k): complete agent KRL-signer plan` (authored as the Delivery protocol says), push, and wait.
  </action>
  <verify>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit (a test failed, or internal/agent/apply's `ok` line is missing or above the 400 s budget), or "FAIL" or "DATA RACE" in the output</fails_when>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit (a gate failed, or internal/agent/apply's `ok` line under `./...` is missing or above the 480 s margin), or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')"</automated>
    <fails_when>non-zero exit (the branch has no commits, or a commit has another author or a committer other than keyroster-bot)</fails_when>
    <automated>H=$(tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md) && printf '%s\n' "$H" | grep -c 'krl_signer_retired' && printf '%s\n' "$H" | grep -c 'ops_key_changed_krl_lands_alone' && printf '%s\n' "$H" | grep -c 'successor_signed_krl_after_a_refused_directory_lands_alone' && printf '%s\n' "$H" | grep -c 'successor_from_the_record_after_a_refused_bundle_step_above_it' && printf '%s\n' "$H" | grep -c 'retired_key_krl_on_the_krl_step_is_refused' && printf '%s\n' "$H" | grep -c 'retired_key_krl_during_a_wait_is_refused' && printf '%s\n' "$H" | grep -c 'retired_key_krl_during_a_wait_from_the_record_is_refused' && printf '%s\n' "$H" | grep -c 'retired_key_krl_during_a_wait_above_the_record_is_refused' && printf '%s\n' "$H" | grep -c 'record_signed_krl_during_a_wait_lands' && printf '%s\n' "$H" | grep -c 'retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main' && printf '%s\n' "$H" | grep -c 'retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused' && printf '%s\n' "$H" | grep -c 'removed_record_reads_from_accepted' && printf '%s\n' "$H" | grep -c 'retired_key_krl_after_a_refused_bundle_step_is_refused' && test "$(printf '%s\n' "$H" | grep -c 'signed waits with that bundle')" = 0 && test "$(printf '%s\n' "$H" | grep -c 'in-force ops key still land')" = 0</automated>
    <fails_when>non-zero exit: a runbook sentence or label is missing, or an old sentence is still there (a successor-signed KRL waits, or 03-08j's stuck-window sentence about the in-force key)</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && ( for n in 09 10 11 12 13 14 15 16; do X=$(git show origin/main:$P/03-$n-PLAN.md) || exit 1; W=$(printf '%s\n' "$X" | sed -n 's/^wave: //p'); test -n "$W" && grep -qx "wave: $((W+1))" $P/03-$n-PLAN.md || exit 1; done ) && grep -qx 'depends_on: \["03-08k"\]' $P/03-09-PLAN.md && grep -c '03-08k-SUMMARY.md' $P/03-09-PLAN.md && ST=$(git show origin/main:.planning/STATE.md) && T=$(printf '%s\n' "$ST" | sed -n 's/^  total_plans: //p') && test -n "$T" && grep -qx "  total_plans: $((T+1))" .planning/STATE.md && O=$(printf '%s\n' "$ST" | sed -n 's/^Plan: [0-9]* of \([0-9]*\)$/\1/p') && test -n "$O" && grep -Eq "^Plan: [0-9]+ of $((O+1))$" .planning/STATE.md && RM=$(git show origin/main:.planning/ROADMAP.md) && R=$(printf '%s\n' "$RM" | grep -m1 -oE '[0-9]+/[0-9]+ plans executed in [0-9]+ waves') && M=$(printf '%s' "$R" | sed -E 's#^[0-9]+/([0-9]+) .*#\1#') && V=$(printf '%s' "$R" | sed -E 's#.* in ([0-9]+) waves#\1#') && grep -Eq "[0-9]+/$((M+1)) plans executed in $((V+1)) waves" .planning/ROADMAP.md && grep -c '03-08k-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit: a publish edit is missing or wrong. Each of these is checked against origin/main's value + 1: the waves of 03-09 to 03-16, 03-09's dependency and its new precondition clause, STATE's total_plans and `of M`, the ROADMAP Plans line's total and wave count, and the ROADMAP row</fails_when>
    <automated>RM=$(git show origin/main:.planning/ROADMAP.md) && X=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md) && W9=$(printf '%s\n' "$X" | sed -n 's/^wave: //p') && test -n "$W9" && N0=$(printf '%s\n' "$RM" | awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}') && N1=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}' .planning/ROADMAP.md) && test "$N1" -eq "$((N0+1))" && awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; n++; if (w!=n) bad=1; if (w>1 && index($0,"*(blocked on Wave " (w-1) " completion)*")==0) bad=1} END{exit bad}' .planning/ROADMAP.md && K8=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-08k-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K8" | grep -q "^\*\*Wave $W9\*\*" && K9=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-09-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K9" | grep -q "^\*\*Wave $((W9+1))\*\*"</automated>
    <fails_when>non-zero exit: any of these fails in Phase 3 of the ROADMAP:
      - the wave headers number one more than on origin/main;
      - they run 1..N in order;
      - every block N above 1 says "blocked on Wave N-1 completion";
      - the 03-08k row sits under the wave origin/main's 03-09 had, and the 03-09 row one wave later.
    </fails_when>
    <automated>git fetch origin p03/08k-agent-krl-signer && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08k-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08k-agent-krl-signer --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/08k-agent-krl-signer --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled on the PR)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new or rewritten runbook sentence names at least one CI test or says UNVERIFIED on a real host.
    - The SUMMARY records internal/agent/apply's times under -race:
      - alone: Task 1's base and Tasks 2, 3 and 4, none above 400 s;
      - under `./...`: Task 1's base, Tasks 2 and 3 and Task 4's full gate, plus origin/main's CI time and the PR's CI time, none above 480 s;
      - or, for a figure above its limit, the owner's choice.
    - `git log origin/main..HEAD --format='%an <%ae> %cn'` prints at least one line, and every line it prints is `Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot`.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0, and `B=$(scripts/gh-as-bot.sh pr view p03/08k-agent-krl-signer --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08k-SUMMARY.md is on its head. The PR title and every commit message use neutral wording.
  </acceptance_criteria>
  <done>The runbook says which KRL lands across an ops-key change, which is refused, how long the host waits, and what the withholding residual leaves open. The PR waits green with the plan and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — the owner reviews PR p03/08k-agent-krl-signer, and Daniel squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7), read with this plan's Delivery protocol overrides (no auto-merge; Daniel merges)
  </read_first>
  <action>After the pre-merge review, the owner reviews, approves and squash-merges the PR in the GitHub web UI (owner, 2026-11-02). Claude never approves or merges, never enables auto-merge and never waits for it. Where 01-SKELETON step 5 still says "auto-merge then squash-merges", this replaces it for this plan. Every step below holds whether or not PR #79 (merge-gate.sh waits for the owner's merge and never enables auto-merge) is merged first.</action>
  <instructions>
    1. Open `gh pr view p03/08k-agent-krl-signer --web`. Read 03-08k-SUMMARY.md, and review:
       - krlStep's authorisers, and KRLAlone's successor and refusal;
       - fullyVerified, VerifyAhead's carried bundle, and VerifyAfter and VerifyAheadAfter in pollCapture.

       Check especially:
       - no KRL lands that neither the bundle in force nor a fully verified successor authorises, and a refused bundle step authorises nothing in its own capture;
       - a KRL whose authoriser's key is retired never lands, on any path; nothing else of its capture is installed except a held step, which commits with the KRL in force unchanged and reports krl_signer_retired;
       - a poll of a widening wait decides a KRL as forward does (the five wait cases' `poll` and `forward` subtests).
    2. Approve and squash-merge in the GitHub web UI, with your commit email. No admin bypass, no "Update branch".
    3. Reply "merged". If main moved before you merged, Claude rebases the branch by hand and pushes it. Review the new head, then merge it and reply "merged".
  </instructions>
  <verification>
    - **Before the merge.** Claude runs merge-gate.sh only as `bash scripts/merge-gate.sh --check p03/08k-agent-krl-signer`, which is read-only and exits 1 while the PR is open. It never runs the plain form before the merge: the plain form may rebase and push the branch itself (exit 3), and this plan rebases by hand.
    - **When main moved.** If `git merge-base --is-ancestor origin/main origin/p03/08k-agent-krl-signer` fails after `git fetch origin`, Claude rebases by hand:
      - on the branch, `git rebase --gpg-sign origin/main`. The authors stay Daniel's, and keyroster-bot is committer and signer;
      - for `.planning/` tracking files, take origin/main's version and re-apply only this plan's entries, as 01-SKELETON step 5's exit 4 describes. If PR #79 merged first, it also edited STATE.md, so expect a trivial STATE.md conflict here;
      - push with lease, as keyroster-bot;
      - do not enable auto-merge;
      - wait for the required checks, check the authorship again with Task 4's `git log` check, and ask the owner to review the new head.
    - **After the owner replies "merged".** From the main checkout (the script refuses to run as any copy but origin/main's), Claude runs `bash scripts/merge-gate.sh p03/08k-agent-krl-signer`. For a merged PR, it only fast-forwards local main and exits 0. Then Claude runs the `--check` form below.
  </verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08k-agent-krl-signer</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which the next plan's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08k-agent-krl-signer --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The KRL signer rules are on main, and 03-08f may start.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08d** (merged) and **03-08j** are this plan's base.
  - Four existing tests change, each named with its reason:
    - 03-08d's TestKRLAlone/ops_key_changed_krl_waits and 03-08j's TestSpoolWindow/krl_only_the_recorded_bundle_signs_waits become `..._lands_alone` (the successor rule);
    - main's TestApply/catch_up_across_policy_rotation (its newOps=true row) and 03-08j's subtest TestSpoolWindow/policy_rotation_below_the_recorded_bundle/newOps=true each flip one assertion: the KRL the newest verified bundle's key signed lands with the held step (the held rule).
  - Every other TestKRLAlone, TestResetDirectory, TestSpoolWindow, TestSpoolWindowWideningWait, TestApply and TestStatus case stays green unchanged. Their KRLs are signed by the key in force, or by a key no bundle they verify drops. TestSpoolWindowWideningWait's seven rows (03-08j fix round 1) never rotate the ops key, so their polls through VerifyAheadAfter and the KRL-alone pass with a real from read as on main.
  - rotationDropping (window_test.go) gains a trailing ops parameter, nil at its three existing callers.
  - The KRL step uses 03-08j's verify(p, chain, alone, in), which gains a carried bundle: chain for the steps, alone (accepted/) for the KRL-alone pass and as F. It builds on 03-08j's in-force hold step (P can be F) and on its record, whose bundle VerifyAhead now carries.
  - 03-08j's pollCapture (its fix round 1) verifies a poll's capture against the pending target in three ways: Verify without a record, VerifyAhead from the record, and KRLAlone on the branch that brings nothing beyond the record. This plan routes all three: VerifyAfter, VerifyAheadAfter, and KRLAlone with the VerifyAheadAfter capture as from. A poll then knows what forward knew and decides a KRL as forward does. pollSpool's own krlAlone call goes through krlAlone, which passes its capture as from.
- **03-08f** follows and keeps this plan's tests green, with KRLAlone's from parameter, verify's carried bundle, VerifyAfter and VerifyAheadAfter.
- **When the ops key is rotated** (no ceremony on main does it yet), a host refuses every KRL the old key signs while it knows the newer bundle, and takes the newer bundle with the first KRL the new key signs.
- **Any later plan that edits verifyKRLUnder, krlStep, KRLAlone, VerifyAhead, VerifyAheadAfter or pollCapture's three verification calls** keeps TestKRLSigner green, including the five wait cases' `poll` and `forward` subtests.
- **Any later plan that lets Unapplied.Base carry a KRL part from the record** must keep KRLAlone's from at pollCapture's nothing-new call. Today the record path's KRL step checks against prev's KRL floor, because Base never takes a record KRL part, so its skips equal KRLAlone's, and only a verified KRL reaches that call. With a record KRL in the base, the same-version skip would pass another KRL at the record's version unverified, and a nil from would widen the poll (Planner decisions, the invariant under "A poll decides as forward does").
- **merge-gate.sh and PR #79.** PR #79 (merge-gate.sh waits for the owner's merge and never enables auto-merge) is a separate small PR (owner, 2026-11-02), not this plan. Task 5 holds whether #79 merges first or not: before the merge it runs the script only as `--check`, and it rebases by hand. #79 also edits STATE.md, so if it merges first, this plan's hand rebase may meet a trivial STATE.md conflict, which Task 5's rule for `.planning/` tracking files resolves.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: the bundle chain is root-signed.** A fully verified successor's ops key is trusted because the roots signed that bundle. A compromised root quorum is outside this plan's scope (T-03-SC and the root ceremony's own threats). A fork of the root-signed chain at fullyVerified's version resolves to fullyVerified. That is UNVERIFIED: no test builds a forked bundle chain.

**Edges:**
- the authoriser: P, the successor, F, a third key, F's key for another installation, no bundle before a first install, and none at all for a KRL the host already accepted (`unchanged_krl_under_a_rotated_bundle_installs`);
- the retired key: P's own (held below N, and P = F below the record), F's under a hold, in the KRL-alone pass and in a poll from a record whose bundle retired it (`retired_key_krl_during_a_wait_from_the_record_is_refused`), the successor's when a verified bundle above it dropped it, and a key a newer bundle names again (current); with a held step the step commits and the KRL in force stays, without one nothing is installed; a held step in a poll's capture that supersedes is UNVERIFIED (no test holds a poll's capture);
- the path:
  - the KRL step, plain and held;
  - the KRL-alone pass after a content refusal, a refused directory step and a refused bundle step, with and without a record;
  - a poll during a widening wait, retired and successor-signed, without a record (VerifyAfter) and from the record (VerifyAheadAfter, and the KRL-alone pass of a capture that brings nothing beyond the record), each beside forward's decision of the same KRL (subtests `poll` and `forward`);
  - a first install;
- the successor: a verified chain, a step before a refused bundle step (none), an offered bundle with a chain gap (none), the record's bundle below a refused bundle (one), the forward capture's bundle in a poll, and in a poll from the record the higher of the record's bundle and the forward capture's (`retired_key_krl_during_a_wait_above_the_record_is_refused`; the record's half alone is an equivalent mutant);
- the apply after: no newer KRL (`retired_key_krl_on_the_krl_step_is_refused`'s second apply, `successor_signed_krl_then_no_new_krl_is_a_noop`);
- where the rule does not reach: a bundle withheld after a refusal that recorded nothing (`retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main`); an old-key KRL kept newest in the spool, and two supersedes within one wait (both UNVERIFIED);
- one supersede by a KRL-alone poll, then a poll that must still know the carried bundle (`retired_key_krl_after_a_krl_alone_supersede_is_refused`);
- a poll's held capture whose bytes equal the pending target's: pollSpool's sameBytes return drops it together with its KRLRefused, which is benign, because the pending's own refusal is reported and the next forward recomputes it (UNVERIFIED);
- a refused bundle step above a verified rotation, with no record: no KRL lands until the chain verifies (owner-accepted residual; `successor_signed_krl_after_a_refused_bundle_step_is_refused`, `retired_key_krl_after_a_refused_bundle_step_is_refused`).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Revocation takes effect across the fleet without risking lockout | Tasks 1-3 |
| REQ | REVOKE-02 (the KRL reaches every enrolled host) | Tasks 1, 2, 3 |
| REQ | REVOKE-03 (signed KRLs, rollback refused, a broken KRL never locks out the fleet) | Tasks 2, 3 |
| Owner decision | The successor rule (a successor-signed KRL lands alone after a content refusal) | Task 1 |
| Owner decision | Q2: yes for a refused directory step with a fully verified chain; never for a refused bundle step | Task 1 |
| Owner decision | Q4: a key the newest known bundle names again is current | Task 2 (`rotated_back_key_is_current`) |
| Owner decision | The held rule, with the same-apply landing under BundleHeld | Task 2 |
| Owner decision | The corrected claim and the apply with no new KRL | Task 2 (`retired_key_krl_on_the_krl_step_is_refused`'s second apply) |
| Owner decision | Retired key: always refuse, nothing lands with it; the wait of about an hour; the installation-key guards stay where main has them | Task 2; Planner decisions; T-03-318 |
| Owner decision | The refused-bundle-step residual stated, with no design change; the owner choosing the route when a base already passes a time limit | Truth 3, T-03-318, Task 4's Limits; Budget and Task 1's stop rule |
| Owner decision (2026-11-02) | The KRL rules apply equally to forward, to every branch of the wait's pollCapture and to the KRL-alone pass: VerifyAfter without a record; from the record, fullyVerified starting at the higher of the record's bundle and the pending target's; a real from on the nothing-new KRL-alone call; record-path wait cases with the old key and the record's key; the mutant "pollCapture passes nil as from" | Task 1 (pollCapture's from, `record_signed_krl_during_a_wait_lands`, the nil-from mutant); Task 2 (`retired_key_krl_during_a_wait_from_the_record_is_refused`, the `poll`/`forward` subtests, the nil-from mutant it survives); Task 3 (VerifyAfter, VerifyAheadAfter, `retired_key_krl_during_a_wait_above_the_record_is_refused`, the other `poll`/`forward` subtests); truths 1, 4 and 7 |
| Owner decision (2026-11-02) | The 400 s limit for internal/agent/apply run alone; 480 s under `./...` as the margin | Budget; Task 1's stop rule; Tasks 2 and 3's local-time steps; Task 4's alone gate, full gate and acceptance |
| Owner decision (2026-11-02) | Daniel as author of every branch commit, keyroster-bot as committer and pusher; no auto-merge; Daniel squash-merges; merge-gate.sh only as `--check` before the merge; a rebase by hand | Delivery protocol; Tasks 1-4's commit steps; Task 4's authorship and auto-merge checks; Task 5 |
| Owner decision | Under BundleHeld the held step commits without the refused KRL, the KRL in force stays, and krl_signer_retired is reported | Task 2 (Verified.KRLRefused, outcome; `retired_in_force_key_krl_under_a_held_step_is_refused`, with the held-step-dropped mutant) |
| Owner decision | Knowledge of the newer bundle: the same apply or the record; the boundary pinned | Task 3 (`retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main`); T-03-318; Task 4's runbook |
| Owner decision | The record counts as a successor, also below a broken bundle | Task 3 (`successor_from_the_record_after_a_refused_bundle_step_above_it`) |
| Review | A poll keeps what the forward capture verified | Task 3 (VerifyAfter and VerifyAheadAfter in pollCapture; `retired_key_krl_during_a_wait_is_refused`, `retired_key_krl_during_a_wait_above_the_record_is_refused`) |
| Review | The KRL a rollback kept in current | Planner decisions (no code needed) |
| Review | Local timing before the PR; a commit per task; the split rule | Budget; Tasks 1-4 |
| CONTEXT | D-20: runbooks in the same PR, labelled run or UNVERIFIED | Task 4 |

## Artifacts this phase produces (this plan)

- state:
  - `ErrKRLSignerRetired` (krl_signer_retired);
  - `verifyKRLUnder`, `Verified.fullyVerified`, `Verified.KRLRefused`, verify's carried bundle, the KRL step's authorisers and refusal (krlStep), KRLAlone's from parameter and refusal;
  - `VerifyAfter`, `VerifyAheadAfter` (with the unexported verifyAhead it shares with VerifyAhead), and VerifyAhead carrying the record's bundle.
- apply: krlAlone's from; pollCapture taking the pending Verified, with VerifyAfter, VerifyAheadAfter and a real from on its KRL-alone call; outcome reporting KRLRefused; one `refusals` entry.
- Tests:
  - twenty-seven TestKRLSigner cases, five of them wait cases with the subtests `poll` and `forward`, and the helper recordBelowWait;
  - TestVerifyManifest/bundle_read_only_for_its_ops_key;
  - two renamed cases (`ops_key_changed_krl_lands_alone`, `krl_only_the_recorded_bundle_signs_lands_alone`), the flipped newOps=true row of catch_up_across_policy_rotation and the flipped subtest policy_rotation_below_the_recorded_bundle/newOps=true;
  - rotationDropping's ops parameter.
- Docs: host-setup.md's "Revocations keep applying" names the successor rule, and its new "An ops-key rotation" paragraph names the refusal, the wait and the withholding limit.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| signed KRL → applier | A KRL is authorised only by the ops key of a bundle the host trusts: the one it is checked under, or the apply's fully verified successor. A key a newer verified bundle the host knows dropped authorises nothing |
| the unapplied record → the KRL rules | The record's bundle (03-08j, root-owned, written only from a capture Verify accepted) is known, and is a successor, on every path of an apply that reads from the record |
| the pending capture → the polls | Within one apply, every poll of a widening wait knows the bundle the apply verified in full before it, on each of pollCapture's branches: VerifyAfter without a record, VerifyAheadAfter (the higher of the record's bundle and the pending capture's) from the record, and the KRL-alone pass with that capture as from. A poll decides a KRL as forward does. Nothing crosses from one apply to the next except the record |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-318 | Tampering / Denial of service | a KRL a retired ops key signed (a key a newer verified bundle the host knows dropped, possibly a stolen one). If it landed it could drop revocations, revoke the fleet with a wide serial range or many keys, or raise the KRL floor so later KRLs are refused; it could also land through a path where the host's knowledge of the newer bundle is not consulted | medium | mitigate | Such a KRL never lands: krl_signer_retired on the KRL step, in the KRL-alone pass after any refusal, on the capture read from the record, under a hold, and in a poll of a widening wait. Nothing else of its capture is installed (on the KRL step a Verify error), except a held step, which commits with the KRL in force unchanged, so no revocation is lost, and reports the refusal (Verified.KRLRefused; `retired_in_force_key_krl_under_a_held_step_is_refused`). The host knows the capture's verified steps, those before a refused bundle step included, the record's bundle, and in a poll the bundle the apply verified before it, on each of pollCapture's branches. Tests: the TestKRLSigner retired_key_* and held_step_krl_signed_by_a_retired_key_is_refused cases (among them `retired_key_krl_during_a_wait_is_refused`, `retired_key_krl_during_a_wait_from_the_record_is_refused` and `retired_key_krl_during_a_wait_above_the_record_is_refused`, each with its `poll` and `forward` subtests), `retired_in_force_key_krl_under_a_held_step_is_refused`, `record_successor_dropped_by_a_verified_bundle_above_it_is_refused`. **Residuals:** (1) The host waits for a KRL the new key signs. With an honest server that is at most about an hour once a signer process runs with the newer bundle (the signer's next revocation or hourly republish; one started before the bundle install publishes nothing). Outside a held step, the newer bundle and every directory change, access removals included, wait with it (`retired_key_krl_on_the_krl_step_is_refused`; the end-to-end wait is UNVERIFIED on a real host). After a bundle step refused above a verified rotation, with no record, no KRL lands until the bundle chain verifies (the old key is retired, and the new key has no successor under Q2's limit), where main lands the last old-key KRL. The owner accepts this; a compromised server could withhold KRLs anyway (`successor_signed_krl_after_a_refused_bundle_step_is_refused`, `retired_key_krl_after_a_refused_bundle_step_is_refused`). (2) The host knows the newer bundle only within the apply that verified it, its polls included, or while unapplied.json holds it. A refusal on the KRL step records nothing, and root may remove the record. A server that withholds the bundle then, or before the host ever saw it, can land any KRL the retired key signs on that host, as on main; with the retired key it can also keep such a KRL newest in the spool and hold the host back. Both are part of the accepted withholding-server residual (`retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main`; the spool case is UNVERIFIED). Main's agent has no installation-key check of its own; the signer's key_is_ca_of_this_installation and validate's krl_drops_key_entry are unchanged |
| T-03-319 | Spoofing / Elevation of privilege / Denial of service | a KRL authorised by a key other than the in-force bundle's (a successor's). It goes wrong when an unverified or refused bundle authorises one, so a forged KRL lands; or when a real successor's KRL is held back while the successor is refused, so revocations never land | medium | mitigate | Only the apply's fully verified bundle is a successor: the newest step of a capture whose bundle step completed (trust.VerifySuccessor), the record's bundle, or in a poll the pending capture's (from the record, the higher of the record's and it). It is tried only on krl.ErrSigner, with its ops key, the pins' installation ID, the stored KRL version and the header check, and never when a verified bundle above it retired its key. An offered bundle, and a step verified before a refused bundle step, authorise nothing. Tests: `ops_key_changed_krl_lands_alone`, `krl_only_the_recorded_bundle_signs_lands_alone`, `successor_signed_krl_after_a_refused_directory_lands_alone`, `successor_signed_krl_after_a_refused_bundle_step_is_refused`, `successor_signed_krl_needs_a_verified_successor`, `successor_from_the_record_after_a_refused_bundle_step_above_it`, `held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step`, `successor_signed_krl_during_a_wait_lands`, `record_signed_krl_during_a_wait_lands`, and Task 3's equivalence pins. **Residual:** a fork of the root-signed chain at fullyVerified's version resolves to fullyVerified (UNVERIFIED) |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; capslock baseline unchanged (a new pair is a recorded deviation) |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh), the full gate passes, the PR's required checks are green, and the merge gate passes.
</verification>

<success_criteria>
- A host that refused the capture of the bundle that rotated the ops key, for its content, for a directory that does not verify, or for a broken bundle above its recorded one, still receives every revocation the new key signs.
- A KRL whose authoriser's key a newer verified bundle the host knows dropped never lands, on any path. Nothing else of its capture is installed with it, except a held step, which commits with the KRL in force unchanged and reports the refusal.
- No KRL lands that neither the bundle in force nor a fully verified successor authorises, and every other KRL error reads as on main.
- A poll of a widening wait decides every KRL as forward does, neither wider nor narrower, with or without a record.
- Every branch commit is authored by Daniel and committed by keyroster-bot, and the PR reaches main only through Daniel's own squash-merge, with no auto-merge.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08k-SUMMARY.md` as a draft in Task 1 and complete it in Task 4, before the merge gate. `requirements-completed` is empty: REVOKE-02 and REVOKE-03 are complete since earlier plans, and this plan hardens both. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources

- The owner's KRL-signer rule (Daniel, 2026-10-30).
- The owner's decisions of 2026-11-01 that moved the KRL-signer task out of 03-08j into this plan: the successor rule, the held rule, the corrected claim that the newer bundle waits, and a first retired-key rule that round 2 replaced.

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| A KRL a retired key signed could land on hosts that verified the rotation, and drop revocations or freeze the KRL floor; "the newer bundle waits" was false | MAJOR | Round 2: such a KRL never lands (truth 3, Task 2). The newer bundle now does wait, for the new key's KRL, and `retired_key_krl_on_the_krl_step_is_refused` tests the apply with no new KRL |
| A KRL only a verified successor's new key signs never lands while that successor is refused for its content | MAJOR | Owner: land it. Truth 2, Task 1: KRLAlone's verified successor; the two renamed tests |
| The BundleHeld path swallows the signer mismatch | WARNING | Owner: the same rules. Truth 5, Task 2 |
| The fallback fired before a first install | MINOR | F needs alone and alone.Bundle non-nil; `first_install_krl_refusal_unchanged` |

### Round 1 — plan check 1 (2026-11-01, PASS WITH FIXES), with the owner's decisions of 2026-11-01

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| The retired-key rule was bypassed on every path that reaches the KRL-alone pass through a Verify refusal, and on the record's paths | MAJOR | KRLAlone takes the capture it verified (from), and the record's bundle and the polls are known (reworked in round 2). Cases: `retired_key_krl_after_a_refused_directory_is_refused`, `retired_key_krl_after_a_refused_bundle_step_is_refused`, `retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused`, `retired_key_krl_during_a_wait_is_refused`, each RED |
| The held rule's new-key branch broke two tests the plan listed as unchanged | MAJOR | Planner decision: the successor's KRL lands with the held step in the same apply. The two newOps=true rows flip one assertion each, named with the reason |
| Additions let a retired key revoke every certificate with one serial range or many key IDs | MAJOR | Round 1 added a cap; round 2 replaced it: a retired key's KRL never lands |
| The version bound's claims, the withholding residual, and what a refusal holds back | WARNING | Round 2 removed the bound with its rule. T-03-318 and the runbook state the wait, what waits with it, and the withholding residual |
| "Fully verified successor" was defined inconsistently | MINOR | One definition, Verified.fullyVerified (truth 1, Planner decisions) |
| The two equivalent mutants rested on an unstated implementation detail | MINOR | Task 3 states both facts and pins each: `TestVerifyManifest/bundle_read_only_for_its_ops_key`, `krl_in_force_key_for_another_installation_keeps_the_first_error`; `krl_other_error_under_changed_bundle_keeps_its_error` asserts the installation text |
| Verify's doc comment became false | MINOR | Task 2 rewrites it, with Verified.BundleHeld's and verifyKRL's held-wait comments |
| The precondition did not check 03-08j's test names; the publish check missed the ROADMAP wave blocks | MINOR | Task 1's precondition checks both test names and `func verify(` on origin/main; Task 4's fourth check covers the headers, their order, the "blocked on" clauses and the 03-08k and 03-09 rows |
| Wording that cited review items by number | MINOR | Neutral labels throughout (the successor, retired-key and held rules, Q2 and Q4) |
| Test cost | WARNING | Task 1 measures the base; every -run filter is anchored per level; held and wait cases share catch_up's window with t.Parallel; round 2 adds local times per task |
| Q1 and Q2 | INFO | Q2 is under Owner decisions; Q1 concerned the round-1 rule and fell away with it |

### Round 2 — plan check 2 (2026-11-01, FAIL), with the owner's decisions of 2026-11-01

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| The host forgot a verified newer bundle across applies, so withholding it once undid the rule wherever nothing was recorded | MAJOR | Owner: narrow the claim. The refusal binds within the apply that verified the bundle, its polls included, or while unapplied.json holds it; beyond that it is the accepted withholding-server residual. Truth 4, T-03-318 residual 2, Planner decisions, the trust-boundary rows and the runbook's Limits say so. `retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main` pins the boundary, GREEN at once and named as the residual |
| A poll during a widening wait without a record lost what the forward capture verified | MAJOR | Verified.fullyVerified carries it, the poll calls VerifyAfter(p, pending, in) (from round 4 in pollCapture, which 03-08j's fix round 1 added), and every Verified on the poll path inherits it. `retired_key_krl_during_a_wait_is_refused` (RED) with the mutant that keeps state.Verify; `successor_signed_krl_during_a_wait_lands` |
| The cap and the version bound reset at every landing, so repeated retired-key KRLs removed both limits | MAJOR | Owner: always refuse. The comparison of KRL contents, the addition cap, the version bound and the applier's clock in Verify are removed, with their unit tables and mutants. Nothing a retired key signs lands while the host knows the newer bundle, so nothing accumulates. `retired_key_krl_on_the_krl_step_is_refused` and `retired_key_krl_after_a_refused_directory_is_refused`, with the mutants that remove the retirement check |
| The successor definition and its implementation disagreed for the record | MAJOR | Owner: the record counts. VerifyAhead carries the record's bundle as fullyVerified, so it is a successor whatever the capture's bundle step did, and truth 1, T-03-319 and Task 3 share the definition. `successor_from_the_record_after_a_refused_bundle_step_above_it` (RED), with the mutant VerifyAhead passing nil. When a verified bundle above the record retired its key, the rule fails closed (`record_successor_dropped_by_a_verified_bundle_above_it_is_refused`) |
| A KRL a rollback kept in current could be undercut by a retired-key KRL | WARNING | Moot: no retired-key KRL lands while the newer bundle is known. On the withheld-bundle path, main's behaviour and the accepted residual, validate's krl_drops_key_entry still keeps explicit keys (Planner decisions) |
| The content comparison's membership checks were unbounded | MINOR | Removed with the comparison; no KRL contents are compared |
| Answered owner questions were still listed as open | MINOR | Q2 and Q4 are under Owner decisions, Q1 and Q3 fell away, and no question is left open |
| Ledger wording about earlier rounds | MINOR | Neutral wording throughout |
| The timing guard came after the PR | MINOR | Tasks 2 and 3 end with a local run against Task 1's local base and stop above base + 120 s; CI's time is a pre-merge check in Task 4 |
| One executor at the edge of its context | WARNING | The work is much smaller: one refusal code instead of two, no content comparison, 24 TestKRLSigner cases instead of 28 plus two unit tables, and 23 mutants instead of about 34 (counts after round 3). Every task commits its code and then a SUMMARY draft with its evidence, the mutants run as one scripted loop, and a task past about 20 cases is split |
| Owner answers after the revision: a refused retired-key KRL under BundleHeld; the record successor applied narrowly | INFO | The held step commits without the KRL, the KRL in force stays and krl_signer_retired is reported (Verified.KRLRefused, outcome). `retired_in_force_key_krl_under_a_held_step_is_refused` asserts it, with the held-step-dropped mutant. The narrow record successor is kept as written |

### Round 3 — plan check 3 (2026-11-01, PASS WITH FIXES), with the owner's decisions of 2026-11-01

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| The test-time guard was relative to a package-alone base and not tied to go test's 600 s timeout | MAJOR | Every timing is the package's line under `./...`, against base + 120 s and an absolute 480 s ceiling. Task 1 records both modes and origin/main's CI time, and stops before any edit when the base is already above 480 s; Tasks 2-4 stop at the ceiling. The owner chooses between a CI -timeout and moving the slow cases into their own package; the executor does not choose (Budget, Owner decisions) |
| A held refusal's "KRL in force unchanged" was not pinned where a leak is exploitable | MAJOR | verifyKRLUnder assigns nothing, and krlStep and KRLAlone assign the six KRL fields only when K lands. `held_step_krl_signed_by_a_retired_key_is_refused` compares accepted/'s KRL, manifest and sig bytes and adds an apply with no newer KRL; the other held cases compare the bytes. The partial-reset mutant is killed by that apply |
| KRLAlone's inheritance of fullyVerified was untested | MINOR | `retired_key_krl_after_a_krl_alone_supersede_is_refused`, with the nil-inheritance mutant. A fallback label applies only if the executor finds a KRL-alone supersede ends the wait |
| The liveness claim omitted a shape and a condition | MINOR | Owner-accepted residual: after a bundle step refused above a verified rotation, with no record, no KRL lands until the chain verifies, where main lands the last old-key KRL. The hour counts once the signer runs with the newer bundle. Truth 3, T-03-318, Planner decisions and the runbook's Limits state both |
| 03-08j's runbook sentence about in-force KRLs became false | MINOR | Task 4 rewrites it for a recorded bundle that replaced the ops key, with its tests, and the runbook grep checks it |
| The token estimate was low | WARNING | About 140k, counting the plan read and the mutant-loop output; the split rule stays |
| The runbook's record-removal sentence named no test | INFO | It cites 03-08j's `removed_record_reads_from_accepted` |

### Round 4 — plan check 4 (2026-11-02, against main ae754a3), with the owner's decisions of 2026-11-02

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| 03-08j's fix round 1 moved a poll's verification into pollCapture: Verify, VerifyAhead, and a KRL-alone call with no capture. The plan routed only one poll call and named two KRLAlone call sites, so a poll could decide a KRL wider or narrower than forward | MAJOR | All three branches are routed (owner, 2026-11-02). Task 1 passes the VerifyAhead capture as from at pollCapture's KRL-alone call, with `record_signed_krl_during_a_wait_lands` and the nil-from mutant. Task 3 adds VerifyAfter for the branch without a record and VerifyAheadAfter for the record branch, which starts at the higher of the record's bundle and the pending capture's. It adds `retired_key_krl_during_a_wait_above_the_record_is_refused` and the mutant that keeps VerifyAhead. Task 2 adds `retired_key_krl_during_a_wait_from_the_record_is_refused`, the old-key KRL in the shape the widening was feared in. Truth 7 states that a poll decides as forward does, and the five wait cases test it with the subtests `poll` and `forward`. A nil from can only narrow a poll, because the KRL step decides first with the same knowledge (Planner decisions). The record case survives the nil-from mutant by design, which is the evidence for that claim. The record's half of the higher-of is an equivalent mutant, listed with its reason. Call sites are checked on ae754a3 by acceptance greps |
| The plan's 480 s guard and the 400 s test-time budget disagreed | WARNING | Owner: 400 s is for internal/agent/apply run alone, and 480 s under `./...` stays as the margin. The Budget defines both gates as commands; Task 1's stop rule, Tasks 2 and 3's local-time steps and Task 4's gates and acceptance use both |
| The delivery text enabled and waited for auto-merge, and commits had the bot as author | WARNING | Owner: Daniel authors every branch commit (author variables on each `git commit`), and keyroster-bot commits, signs and pushes. There is no auto-merge, and Daniel squash-merges. merge-gate.sh runs only as `--check` before the merge, and in its plain form only after it. A rebase is done by hand. The Delivery protocol overrides 01-SKELETON steps 2, 3 and 5; Task 4 checks the authorship and that auto-merge is off; Task 5 is rewritten |
| Stale anchors: a70c661, pollSpool as the poll's verifier, 03-08j's fix rounds missing from the context | WARNING | ae754a3 throughout. pollCapture is named where the poll's verification is meant (pollSpool stays where its own krlAlone call and sameBytes return are meant), and the context cites 03-08j-SUMMARY's three fix-round sections |
| The check for the old apply_test.go comment could not fail, because the comment wraps across lines | WARNING | The check strips comment markers and normalises whitespace (it prints 1 on main), and a second check requires the new text |
| The policy-rotation rows are now subtests | INFO | The flipped row is named as the subtest `policy_rotation_below_the_recorded_bundle/newOps=true`, and its mutant evidence is read per row |
| The token estimate | INFO | About 200k: the plan read is about 66k, not 30k, and there are three more cases, five `forward` subtests, two more mutants, one mutant re-run that must survive, and the alone runs (round 5: about 180k with the read guidance) |

### Round 5 — plan check 5 (2026-11-02, PASS WITH FIXES, against main ae754a3)

The check confirmed that a nil from cannot widen a poll, and that the planned survival run of the nil-from mutant is the right tripwire.

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| "A nil from cannot widen a poll" named its effect, not the invariant it rests on | WARNING | Planner decisions and the Cross-plan notes now state the invariant: Unapplied.Base never takes a KRL part from the record, so the record path's KRL step and the nothing-new KRL-alone call both check against prev's KRL floor, with the same skips. They also state the rule for later plans: a plan that lets Base carry a KRL part must keep KRLAlone's from |
| The authorship format's literal pipe raised a false R4 warning | INFO | A space separates the fields in the Delivery protocol, Task 4's verify and its acceptance criterion |
| The fixture text was imprecise | INFO | rotationDropping's ops sets `b.OpsKey` on its own outer bundle. Bundle 4 is rotationOps over bundle 3 and its policy, parsed from the documents, and comes with a new policy version with the same admin |
| Task 5's reasons went stale once PR #79 merges | INFO | The reason for the hand rebase is that the plain form may rebase and push the branch itself (exit 3). 01-SKELETON's auto-merge wording is overridden only where it still has it. #79's STATE.md edit is named as a trivial rebase conflict |
| The equivalent mutant's reason did not cover a version tie | INFO | A tie means the same bundle, because pending's chain was verified against the record's bytes |
| An executor did not need to read the whole plan | INFO | "What to read (executor)" lists what to skip until the SUMMARY. The estimate is about 180k |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| A bundle-only step that applies a successor's CA keys with the accepted directory | It cannot take a ca_line_rejected bundle, and it installs more than the revocation |
| Holding the bundle at the newest step whose ops key signed the KRL | It needs the directory verified again under that step's policy, and gains only liveness |
| A refusal code when a successor's KRL lands with a held step | A successor's key signing a KRL is no event to report; BundleHeld is already in the report |
| Keeping knowledge of a verified newer bundle across applies | The owner narrowed the claim instead: beyond the apply and the record it is the accepted withholding-server residual |
| Installing the newer bundle and directory while a retired-key KRL is refused, outside a held step | It gains one apply: once the newer bundle is in force, main refuses the old key's KRL until the new key's arrives |

