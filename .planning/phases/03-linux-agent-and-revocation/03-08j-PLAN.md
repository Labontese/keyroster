---
phase: 03-linux-agent-and-revocation
plan: 08j
type: execute
wave: 15
depends_on: ["03-08e"]
files_modified:
  - internal/agent/state/verify.go
  - internal/agent/state/unapplied.go
  - internal/agent/apply/apply.go
  - internal/agent/apply/installed.go
  - internal/agent/apply/resetdir.go
  - internal/agent/apply/status.go
  - internal/agent/apply/window_test.go
  - internal/agent/fetch/fetch.go
  - internal/agent/spool/spool.go
  - internal/agent/spool/spool_test.go
  - internal/agent/enroll/pop.go
  - internal/agent/heartbeat/heartbeat.go
  - internal/agent/heartbeat/heartbeat_test.go
  - cmd/keyroster/hoststatus.go
  - cmd/keyroster/hoststatus_test.go
  - docs/runbooks/host-setup.md
  - docs/runbooks/signer-install.md
  - .planning/todos/pending/2026-10-28-agent-spool-pruning.md
  - .planning/phases/03-linux-agent-and-revocation/03-08j-PLAN.md
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
requirements: [AGENT-04, AGENT-07]

estimate:
  tokens: 115000
  raw_tokens: 115000
  tasks: 5
  confidence: low

must_haves:
  truths:
    - "Owner decisions D-2 (Daniel, 2026-10-30) and Q1 (Daniel, 2026-10-30, with the order of 2026-11-01): this plan holds the applier fix for the stuck spool window (PR #76 review F8) with its status. It runs after 03-08e and before 03-08k. The rule it serves is D-R2's, extended to grants: once the server publishes a directory the host can apply, a grant's removal reaches the host as a revocation does"
    - "Stuck window (PR #76 review F8). forward refuses a verified capture for its content (a render error, a generation or intermediate above the caps, or ca_line_rejected) after the capture changed the bundle or directory, with Verify refusing nothing and accepted/ holding a bundle. It then records, in <state>/unapplied.json, the parts of Verified.Next that are ahead of accepted/: the bundle with its policy, and the directory, each with its signatures, never a KRL. After that it takes the KRL-alone pass against accepted/ as before. The next apply reads from that record. Its capture's floor is the record's versions, so spool.Read's window starts above the refused version, and state.VerifyAhead chains every later version from the record's own bytes. TestSpoolWindow/refused_window_newest_then_fix_applies (directories 2-64, 65 above the caps, 66 fixed) installs 66 at the second apply. refused_run_longer_than_a_window_reaches_fix (65 and 129 above the caps, 130 fixed) installs 130 at the third"
    - "The record never widens what is installed. Nothing from it is rendered except as the newest state a later capture verified. The versions between the record and that newest state are chain-checked as today and never rendered. The KRL-alone pass runs against accepted/, both after a content refusal and after every refusal Verify makes of a capture read from the record. The base read from the record carries accepted/'s KRL, so the newest KRL is verified against the bundle actually put in force. Changed is computed against accepted/, so an apply with nothing newer than the record re-renders it and reports the refusal again: last_apply.result refused, never ok"
    - "The record is the only chain base while it exists, and the bundle in force stays a hold step. No capture is verified from accepted/ while a record exists. When the record holds a bundle part, verify offers the bundle in force as the lowest bundle step, below the record's. holdBundle can then hold the capture at the bundle in force when the newest directory carries only that policy's quorum, as main does for a host catching up across a policy rotation. TestSpoolWindow/policy_rotation_below_the_recorded_bundle pins both rows of TestApply/catch_up_across_policy_rotation's shape (newOps false and true). Its newOps=true row needs this: it shows directory 65 under bundle 1 with the new-key KRL waiting, as on main. Residual (UNVERIFIED, accepted by the owner): a directory signed only under a policy strictly between the bundle in force and the recorded bundle is refused on every apply. KRLs signed by the in-force ops key still land, and `unapplied` shows. Clearing it takes a hand action: root removes unapplied.json, or reset-directory succeeds (the newest directory then verifies standalone). A later commit passing the record is not a realistic way out, because the refused capture only ever makes KRL-alone commits"
    - "The record is never narrowed, lowered or replaced except by a commit that passes it (finishCommit), by reset-directory (its directory part), by root removing it, or by forward dropping one that does not parse. recordUnapplied writes, per kind, the higher of the record's part and the new capture's, so a capture held at the bundle in force keeps the record's bundle part (held_content_refusal_keeps_the_records_bundle)"
    - "The record counts as accepted/ does for ordering and chaining. spool.Read still reads the spool's newest copy at or below it (pick's `below`, as for accepted/), but no step chains from that copy or renders it: the chain starts at the record's own bytes, a copy at the record's version adds no step (the record's bytes stay the base, whatever the copy holds), and a lower newest version is refused as older. A version not built on its bytes is refused (directory_not_verified or bundle_not_verified), and the KRL still applies alone. A record that does not parse, or whose bundle does not name its policy, is dropped with a warning. A record with no part ahead of accepted/ is removed silently, and finishCommit removes the record once a commit passes it. Either way the run reads from accepted/ as it does on main, and no loader error stops an apply, a reset or a status write. keyroster-agent reset-directory drops the record's directory with the accepted one, and keeps a bundle part that is still ahead. Removing unapplied.json by hand is always safe (removed_record_reads_from_accepted): nothing is installed that main would not install. While the record exists, the fetcher's prune keeps the spool from the record's versions (truth 7), so after a removal the spool can lack accepted/'s versions below the record; the next apply then reports a chain gap until the next poll fetches them again (T-03-317)"
    - "The fetcher reaches past the record. For the bundle and the directory, WriteAccepted writes the higher of accepted/'s version and the record's. A host whose accepted/ stays put therefore still spools versions more than 1024 (MaxAgentStateRounds x MaxAgentStatePerKind) above it. AcceptedVersions, which InstalledKRLVersion uses, is unchanged. pruneSpool (03-08e, unchanged by this plan) keeps Keep(accepted.json, 1024) from that raised accepted.json, so from Task 2 on the prune follows the record too: it keeps the record's version and the 1024 above it, which covers everything a capture from the record, and a pending target above it, reads. Without the raise, a record more than 1024 above accepted/ would be pruned and the next apply would refuse it as older. The raise costs accepted/'s own versions below the record, which only a removed or dropped record reads (truth 6). It lags only if WriteAccepted fails on 16 or more applies in a row (T-03-317)"
    - "Fleet-wide visibility. The apply's report and the heartbeat status carry unapplied {bundle, directory}: the record's versions that are ahead of accepted/ (omitempty). heartbeat.Validate refuses an unapplied with both versions zero and checks nothing else. keyroster host status shows an `unapplied: directory vN` alert and a note. A server from before this plan refuses a heartbeat that carries the field, so the runbook says to update the server before the agents, and not to roll the server back once agents have sent the field"
    - "The spool's bound is unchanged. This plan keeps 03-08e's prune, Keep(accepted.json, 1024), and its computed bound of about 5.6 GiB; the raise only moves the window's start. A smaller window, once the applier publishes the floors it reads the spool from, is deferred (owner, 2026-11-02) and recorded as a remaining item of the spool-pruning todo (Task 5)"
    - "spool.Read recaptures once when a name its listing returned is gone at its open (ENOENT): a capture that races the fetcher's prune reads a fresh listing instead of failing. A second ENOENT fails the capture as before, so the apply retries as on main. TestReadRecapture"
  artifacts:
    - path: "internal/agent/state/unapplied.go"
      provides: "the unapplied record (codec, base) and VerifyAhead"
      contains: "func VerifyAhead("
    - path: "internal/agent/state/verify.go"
      provides: "verify(p, chain, alone, in): the steps against chain, the KRL-alone pass against alone"
      contains: "func verify("
    - path: "internal/agent/apply/apply.go"
      provides: "forward's merging record write and the capture read from the record"
      contains: "state.VerifyAhead("
    - path: "internal/agent/heartbeat/heartbeat.go"
      provides: "Status.Unapplied"
      contains: "json:\"unapplied,omitempty\""
    - path: "internal/agent/spool/spool.go"
      provides: "Read's one recapture after a listed name is gone"
      contains: "unix.ENOENT"
  key_links:
    - from: "internal/agent/apply/apply.go"
      to: "internal/agent/state/unapplied.go"
      via: "a capture read from the record is verified from it; the KRL-alone pass stays on accepted/"
      pattern: "state.VerifyAhead("
    - from: "internal/agent/apply/installed.go"
      to: "internal/agent/state/unapplied.go"
      via: "the fetcher's cursor follows the record through the one loader"
      pattern: "loadUnapplied("
    - from: "internal/agent/apply/status.go"
      to: "internal/agent/heartbeat/heartbeat.go"
      via: "the heartbeat status carries the record's versions"
      pattern: "Unapplied"
  prohibitions:
    - statement: "The record never widens what is installed and never skips a verification. Only a capture that Verify accepted with Refused nil is recorded. Nothing from the record is rendered except as the newest verified state of a later capture, and no version that passed only the chain check is rendered. The KRL-alone pass, and every refusal Verify makes of a capture read from the record, use accepted/. The base read from the record carries accepted/'s KRL"
      status: resolved
      verification: test
---

## Revision 2026-11-01 (after PR #77)

PR #77 (plan 03-08e) merged as 9ac9c12 after this plan was written. It added `spool.Cap`, `spool.Keep(vs, floor, above)`, `pickAbove` (behind `pick`), and the fetcher's `pruneSpool`, `checkCaps` and `healSpool`. pruneSpool keeps `keepAbove` = MaxRounds x MaxAgentStatePerKind = 1024 versions above `outbox/accepted.json`. PR #77's fix round 2 had narrowed that to 64 counted from accepted.json, which pruned a superseded pending target (a false bundle_older), and fix round 3 restored 1024. The owner then decided that this plan carries the 64 window, with the floors that make it safe. This revision does that and reconciles the plan with main.

What changed, and why:
- **Reconciled with main at 9ac9c12.** state/, apply/ (apply.go, installed.go, resetdir.go, status.go, layout.go), heartbeat and hoststatus are unchanged by PR #77, so Tasks 1-3's anchors hold. spool.go's window rule is now `pickAbove`'s `case n < above` (pick passes MaxVersionsPerKind), fetch.go has pruneSpool, and `apply --once` has run's defaults (parseApply). The context, the reconciliation list, Task 1's precondition (it now also checks `func Keep(` and `func pruneSpool(`) and the read_first lists say so.
- **The prune follows the record.** From Task 2 on, WriteAccepted's raise makes accepted.json name the record's versions, so 03-08e's pruneSpool, unchanged here, keeps the 1024 versions above the record (truth 7). This plan needs no interim prune rule; Planner decisions give the reasoning.
- **New Task 4: spool.Read recaptures once after an ENOENT** (truth 10, T-03-321), so a capture that races the fetcher's prune does not fail.
- **The docs task is now Task 5,** and the merge gate Task 6. In the ledger's Rounds 1-3, "Task 4" and "Task 5" mean today's Tasks 5 and 6.
- **Threat model.** T-03-321 (the capture racing the prune) is added. T-03-318 and T-03-319 belong to 03-08k.
- **Supersedes.** This plan had no explicit 64-from-accepted window. Its earlier cross-plan note, that a pruning keyed on outbox/accepted.json stays safe for the record, is superseded: a pruning at 64 counted from accepted.json alone is exactly what failed. The record is safe because the prune counts from the raised accepted.json (Task 2).

**Split after plan check 4 (owner decision W3, 2026-11-01).** A first version of this revision also carried the read floors (outbox/floors.json), the union prune with the 64 window, and the disk bound, as Tasks 4 and 5. The owner split them out of this plan (W3), together with his later decisions on fetching only what is kept (W1) and on the recheck before the unlinks (W2), and on 2026-11-02 deferred them as technical debt, not scheduled: keeping main's catch-up pace would need a prune and a fetch stop gated on the applier's progress, for a smaller bound that holds only while the applier does not move. WriteAccepted's move under the apply lock went with them; only the pending floor needs it. Task 5 records the idea as a remaining item of the public spool-pruning todo. This plan keeps the record, VerifyAhead, the status and spool.Read's recapture, with 03-08e's prune unchanged; the order is 03-08j → 03-08k → 03-08f → 03-08g → 03-08h.

<objective>
This plan closes the stuck spool window (PR #76 review F8).

Take a host 64 or more versions behind, where the newest version of its read window is one it cannot apply. Today it never reaches a fixed version, and the grants that later directories removed stay in force. After this plan the host records that verified version, reads past it at the next apply, and installs the fixed version. Its status shows the recorded versions fleet-wide.

Purpose:
- AGENT-04: principals follow the newest directory the host can apply.
- AGENT-07: the heartbeat shows a host that verified a state it cannot apply.

It makes reset-directory unnecessary for a refused window.

It also makes a capture that races the fetcher's prune capture once more instead of failing. The prune stays 03-08e's, counted from accepted.json as this plan raises it.

Output:
- the unapplied record, state.VerifyAhead and the fetcher's cursor, which 03-08e's prune then follows;
- the bundle in force as a hold step, the merging record write, and reset-directory's record step;
- the status field and the CLI alert;
- spool.Read's one recapture;
- named tests with RED evidence and mutants;
- host-setup.md and signer-install.md;
- the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **D-R2 (PR #71 review F5), existing:** a revocation never waits.
- **D-2 (Daniel, 2026-10-30, PR #76 review F8, low):** 03-08d's fix round changed only the runbook for the stuck window (reset-directory, or escalation for a bundle). The applier fix goes into a later plan, together with a stuck-window state in the host status.
- **Q1 (Daniel, 2026-10-30):** the stuck-window fix is its own plan, this one, 03-08j.
- **Plan order (Daniel, 2026-11-01, after plan check 1):** 03-08e (wave 14) → 03-08j (wave 15) → 03-08k (wave 16) → 03-08f (wave 17).
  - 03-09 to 03-16 move one wave later per plan, and this plan's publish edits make one such move.
  - Branch `p03/08j-agent-spool-window`.
- **Delivery (2026-10-29):**
  - The plan lands in the same PR as its fix, with neutral hardening wording. The stuck window is named as PR #76 review F8.
  - Pushing the branch and opening the PR before the merge is allowed.
- **Homelab:** no 03-16 drill provokes these refusals on a real host. The runbook text is labelled as run in CI, and UNVERIFIED on a real host.
- **The record's fork and rollback evidence, and the residual (Daniel, 2026-11-01, with the redesign):**
  - The record stays the only chain base. verify offers the bundle in force as the lowest hold step, and recordUnapplied merges per kind, raise only.
  - Residual accepted (UNVERIFIED), stated in truth 4, T-03-316 and host-setup.md. A directory signed only under a policy strictly between the bundle in force and the recorded bundle is refused on every apply; that takes two policy rotations inside one gap. KRLs signed by the in-force ops key still land, and `unapplied` shows.
  - Clearing it takes a hand action: root removes unapplied.json, or reset-directory succeeds (the newest directory then verifies standalone). A later commit passing the record is not a realistic way out, because the refused capture only ever makes KRL-alone commits.
- **The read floors and the 64 window (Daniel, 2026-11-01, after PR #77's fix-round-2 check):** publish the applier's read floors, prune by the union of spool.Keep over them, then shrink the window to 64, with the check's probe as the regression test. After plan check 4 they were split out of this plan (W3), with the fetch limit (W1) and the recheck before the unlinks (W2). **On 2026-11-02 the owner deferred them as technical debt, not scheduled.** Task 5 records the idea in the spool-pruning todo. The order is 03-08j (wave 15) → 03-08k (wave 16) → 03-08f → 03-08g → 03-08h.
- **The prune must follow the record (carried from PR #77):** delivered here by Task 2's raise of accepted.json, which 03-08e's prune counts from.
- **The capture racing the prune (low, carried from PR #77; kept in this plan by W3):** fix it in spool.Read: on ENOENT for a name the listing returned, recapture once.
- **Size (Daniel, 2026-11-02, after plan check 5, W-j1):** this plan stays as it is, five auto tasks and about 115k tokens, with the recapture in it.

**Planner decisions (Claude's discretion), with their reasons:**
- *No interim prune rule: 03-08e's prune, unchanged, is safe with the record (plan check 4's question).* With Task 2's raise, accepted.json names the record's base, so the prune keeps Keep(base, 1024): the record's own version, as the `below` a capture reads, and the 1024 versions above it.
  - **What the applier reads is kept.** forward's capture reads from the base, which is in that window. pollSpool reads from a pending target, at most 64 above the base per supersede, so within 1024 for up to 16 supersedes in one wait, as 03-08e's window covers them above accepted/.
  - **The record write and the raise.** Between the record write and the apply's end, where WriteAccepted raises accepted.json, the prune still counts from the previous accepted.json. The new record is that capture's window-newest, at most 64 above the base the previous accepted.json named, so it is kept.
  - **Without the raise it would not be safe.** A record more than 1024 above accepted/, after 16 refused windows, would be pruned, and the next capture would find only older versions and refuse them as directory_older or bundle_older. The raise is what makes the prune follow the record.
  - **What the raise costs.** accepted/'s own versions below the record are no longer kept. Only a record that is removed by hand, or dropped as damaged, reads them again. That apply then reports directory_chain_gap or bundle_chain_gap, the KRL lands alone, and the next poll fetches them again, because accepted.json then names accepted/ and the cursor follows it. Nothing is installed. Truth 6, T-03-317 and the runbook say so.
  - **The alternative, rejected.** Keeping Keep(accepted/, 1024) as well would need accepted/'s own versions in the outbox beside the raised ones: the read-floors idea the owner deferred (Task 5's todo item).
- *spool.Read recaptures once, not the prune's policy rule made a superset of Read's window.* One fresh listing covers every kind the race reaches. That is an orphaned policy, and also an older KRL the prune drops when a newer one completes between the two listings. A wider policy rule would cover policies only, and would bring back policies no kept bundle names. The test seam is an unexported function parameter, not a package variable.
- *The stuck window: a persisted record of the refused verified state, which the next apply reads past.* Three designs were weighed against the threat model (a compromised server feeding crafted chains, a malicious admin, a compromised fetcher):
  - **Rejected, A: install the newest renderable version below the refused one.** It fails on four counts.
    - verifyDirectory fully checks only the window-newest version (signatures, Parse, installation, policy). The versions below it pass only the prev-hash chain check and are "never rendered". Rendering one would need a full verification per candidate, possibly under an earlier policy (holdBundle). For a bundle it would also need one written and validated generation per step, because ca_line_rejected exists only after validate.
    - It knowingly installs a version whose verified successor may have removed a grant.
    - It cannot move when every version in the window is refused. That is the usual shape: a host group over the cap stays over it until someone fixes it, and every window's newest version is then refused. refused_run_longer_than_a_window_reaches_fix walks two such windows.
    - It adds up to 63 extra verify-and-render rounds per apply.
  - **Rejected, B: look past within one apply and persist nothing.** It fails on two counts.
    - The fetcher's cursor is min(outbox accepted.json, the spool's newest), and one poll walks at most MaxAgentStateRounds x MaxAgentStatePerKind = 1024 versions above it. So a host refused for longer than that never even spools the fix while accepted/ stays put.
    - Every retry would walk again from accepted/, re-reading the whole distance as root while no version renders.
  - **Chosen, C: a record in its own state file, holding copies.** The record is `<state>/unapplied.json` (root, 0600). It holds the parts of Verified.Next that are ahead of accepted/ (bundle with policy, directory, with signatures, no KRL). The next capture reads and chains from it, and the fetcher's cursor follows it.
    - The installed state only ever moves to the newest version a capture fully verified, as today.
    - A compromised server can only make the host record a state that Verify accepted (root-signed, admin-quorum-signed, chained from accepted/). It cannot forge one, and withholding is already possible.
    - A malicious admin quorum gains nothing it could not sign directly.
    - The record holds copies, not hashes of spool files. A compromised fetcher that deletes or swaps spool files therefore cannot redirect the chain (T-03-225 otherwise), and the record is fork evidence just as accepted/ is.
    - Dropping the record only makes the host read from accepted/ again, so a damaged record is never worse than main.
- *A separate state file, not new names in accepted/.* loadSnapshot refuses a pointer that names a file it does not know (state.go), so an older agent would refuse an accepted/ that held them.
- *The record counts as accepted/ for chaining.* After a signer restore lost versions above accepted/ but at or below the record, the host refuses the re-made chain, as it does today for an accepted lost version. signer-install.md selects hosts by outbox accepted.json, which now names the record's versions, and says how to clear a recorded bundle the restore lost. Silently dropping the record would hide that history was rewritten.
- **The bundle in force stays a hold step; there is no second verification from accepted/.** holdBundle looks for the policy that carries the newest directory's quorum among the capture's bundle steps. With a recorded bundle those steps start at the record's bundle, so a directory signed under the in-force policy finds none. That is a host catching up across a policy rotation (TestApply/catch_up_across_policy_rotation). verify therefore offers the bundle in force as the lowest step: one step more in the list holdBundle already searches, so the record stays the only chain base.
  - **Rejected: a retry from accepted/'s floor with plain Verify** (the earlier design; see the ledger). It is a second result verified without the record, which brings three problems:
    - it bypasses the record's fork and rollback evidence (a re-made 65', or a withheld 65 with 64 installed);
    - a content refusal of its result rewrote the record;
    - it never ran when the KRL-alone pass errored, as in the newOps=true shape.

    A consistency check on the retry would close the first two only by re-deriving what the record already anchors.
  - **Rejected: the lower bundle chain read from the spool** (accepted/ up to the record, required to pass through the record's bytes). It would also cover a policy strictly between the bundle in force and the record's. But it needs a second spool read on every apply while a bundle record exists, plus its own chain check and equality rule, for a shape that needs two policy rotations inside one gap.
  - **Rejected: dropping the record's bundle part when the directory step fails.** The owner keeps the record's fork evidence.
  - **Residual (UNVERIFIED), accepted by the owner (above) and stated in truth 4, T-03-316 and host-setup.md:** a directory signed only under a policy strictly between the bundle in force and the recorded bundle is refused on every apply. KRLs signed by the in-force ops key still land, and `unapplied` shows.
    - Clearing it takes a hand action. Root removes unapplied.json, which is always safe and lets the host proceed as main would, or reset-directory succeeds.
    - A later commit passing the record is not a realistic way out. The refused capture only ever makes KRL-alone commits, which leave the record ahead. The directory window stays the lowest 64 versions above accepted/'s directory, so publishing newer versions does not move it.
- *recordUnapplied merges per kind and never lowers a part.* A capture held at the bundle in force carries no bundle part, so a plain write would replace a recorded bundle with a directory-only record. The merge keeps it.
- *pollSpool is unchanged.* During a widening wait the capture is verified against the pending target. After its commit, the next forward records a refused state if one remains.
- *Pace.* A refusal ends the run loop's catch-up, so the walk moves one window (64 versions) per DefaultRetry (60 s), and faster when the fetcher spools new versions. The run loop is unchanged; the runbook states the pace.
- *A new status field, unapplied.* Neither existing field fits:
  - 03-10 owns `last_apply.detail` for its probe outcomes;
  - `stuck` is a closed set whose CLI note says the host "applies nothing", which is false here.

  The field is omitempty. An older server decodes strictly, so it refuses only the heartbeats of hosts in this state, and those hosts then show the status_stale alert. For the same reason a server rolled back below this plan cannot parse the heartbeats it already stored for such hosts. The runbook says to update the server first, and not to roll it back. The CLI's client decodes server responses with plain json.Unmarshal (serverclient client.go), so an older CLI ignores the field.

No `checkpoint:decision` precedes Task 1.

## Budget

- **Files:** 17 code, test and runbook files. Two are new: internal/agent/state/unapplied.go and internal/agent/apply/window_test.go. The publish edits add the plan itself, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16.
- **Estimate:** about 115k tokens (the calibration has no samples yet: factor 1, confidence low):
  - about 50k reading: this plan (about 25k) and function-scoped read_first lists of about 95 KB;
  - about 40k written;
  - about 25k of test and gate output.
  - That is 1.15x the 100k guideline. The record's tasks (1-3) were about 110k on their own before the revision after PR #77, and the recapture adds about 5k. Splitting them further would cut the tracer from its guard cases. The owner accepted this size on 2026-11-02 (W-j1).
- **Test time.** CI runs `go test -race -count=1 ./...` with Go's default 10-minute timeout per package (ci.yml). internal/agent/apply took 164 s in CI at PR #76's head (263 s locally under -race in WSL). At PR #77's last code commit (982b157) it took 290 s locally under -race in WSL, internal/agent/fetch 32 s and internal/agent/spool 4 s (03-08e-SUMMARY.md, fix round 3).
  - The task verifies anchor their -run filters, so TestKRLAlone's 4096-file cases never run there.
  - Only each window's newest directory is made above the caps, because the versions between are only chain-checked.
  - Task 5 records internal/agent/apply's and internal/agent/spool's times in CI. Above about 400 s (two thirds of the timeout), a time is a deviation to fix before the PR.
- **Task size:** five auto tasks (Task 1 a tracer) and the merge gate. Tasks 2 and 3 touch seven and six files, two of Task 2's are doc comments only; Task 4 touches two. That is above the 2-3 task guideline; the owner kept the recapture in this plan when splitting the floors out (W3), and accepted five tasks and about 115k on 2026-11-02 (W-j1).

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
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names.
- **Branch.** Create `p03/08j-agent-spool-window` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 5 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Commits and PR text.** Neutral hardening wording; the stuck window is named as PR #76 review F8, and Read's recapture as F01 (03-08e) follow-up. Refer to findings by these F-numbers only. No attribution lines, no IP addresses and no real host names.
- **Code comments.** Cite `PR #76 review F8 (03-08j)` for the record, and `F01 (03-08e), 03-08j` for Read's recapture.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md`. The docs commit is `docs(03-08j): complete agent spool-window plan`.

**The defect this plan fixes, as read on main at 9ac9c12** (03-08e merged; Task 1's precondition checks it).
- spool.Read's pick takes, per kind, the lowest MaxVersionsPerKind (64) complete versions above the floor, plus the newest at or below it (spool.go: pick calls pickAbove with MaxVersionsPerKind, whose `case n < above` takes them).
- verifyDirectory fully checks only the newest of them (verify.go, `newest := vs[len(vs)-1]`). The versions between are checked only by chainHead and CheckSuccessor.
- When forward's candidate or validate refuses that newest state for its content, krlAlone commits the KRL alone. state.KRLAlone keeps accepted/'s bundle and directory, so the floor never moves, and every later apply reads the same window and refuses the same version.
- The run loop's catch-up stops on the error and retries every DefaultRetry.
- The fetcher's cursor is min(outbox accepted.json, the spool's newest) (fetch.go cursor), and one poll walks at most 64 rounds of 16 versions above it. So the spool also stops about 1024 versions above accepted/. Since 03-08e, pruneSpool also removes, at the start of every poll, every bundle and directory version but the newest at or below accepted.json's and the lowest keepAbove (1024) above it.
- The KRL lands (T-03-294 holds), but the grants later directories removed stay in force.
- The bundle shape is the same: a window-newest bundle whose CA line the host's ssh-keygen refuses.
- host-setup.md (03-08d's D-2 paragraph) tells the operator to run reset-directory, or to escalate for a bundle.
- The PR #76 review reproduced it with the existing harness: directory 1, versions 2-64, 65 above the caps, 66 fixed. Every apply refused 65, and role:old stayed granted. The control (64 above the caps, 65 fixed) installed 65 at the first apply.

## Reconciliation with main at 9ac9c12, after 03-08e (2026-11-01)

1. **This plan was split out of 03-08e's revision of 2026-10-30** (owner decision Q1). Its tasks are that revision's stuck-window tasks, re-cut so the first is a tracer. Their file, function and test names were checked on a70c661. After plan check 1 (2026-11-01), one task moved out of this plan by owner decision; nothing of it remains here. They were checked again on 9ac9c12, after PR #77 merged. PR #77 changed none of internal/agent/state, internal/agent/apply's apply.go, installed.go, resetdir.go, status.go and layout.go, internal/agent/heartbeat or cmd/keyroster/hoststatus.go, so every anchor in Tasks 1-3 holds. It changed spool.go, fetch.go, fetch_test.go, prune_test.go, host-setup.md, the spool-pruning todo and cmd/keyroster-agent/apply.go; items 4 and 7 and Tasks 4-5 build on those.
2. **03-08d's renderer** is `directory.PrincipalsRenderer` (NewPrincipalsRenderer, File), with RenderPrincipalsFile as its wrapper. This plan does not edit the renderer.
3. **03-08d changed what the stuck window meets:**
   - forward reads current first, then calls candidate (render, keepKRL, checkCandidate);
   - krlAlone runs once per capture, not once per run (fix round 1);
   - Render refuses a host group above 4096 accounts before rendering;
   - ErrGenerationTooLarge is in status.go's `refusals`, so a cap refusal reports last_apply.result refused;
   - RenderFallback works without an accepted directory (F08).

   This plan builds on exactly these, and every TestKRLAlone, TestResetDirectory and TestStatus case stays green unchanged.
4. **What 03-08e changed in this plan's files, as merged at 9ac9c12:**
   - **spool.go.** `Cap(name)` and `readCapped` (Read takes every cap from Cap). `Keep(vs, floor, above)`, the versions the fetcher keeps: Read's Floor rule with `above` versions above a floor, the newest MaxVersionsPerKind without one. `pickAbove(vs, floor, above)`, which pick calls with MaxVersionsPerKind. Read still fails the whole capture on any error from readCapped, an ENOENT included.
   - **fetch.go.** pollState runs healSpool, then pruneSpool(spool, accepted.json's versions), then the cursor. pruneSpool keeps, of the bundles and directories, `spool.Keep(complete(kind), a.<kind>, keepAbove)` with `keepAbove = MaxRounds * serverclient.MaxAgentStatePerKind` (1024); the newest complete KRL; and the policies whose document names its own version and whose SHA-256 a kept bundle names. checkCaps refuses an answer above the caps (`state_item_over_cap`) before writeState writes anything. Task 2 changes only cursor()'s doc comment there; this plan leaves pruneSpool's code unchanged.
   - **prune_test.go.** TestSpoolPrune, including `superseded_pending_target_kept` (the check's probe at 1024). This plan does not edit it, and every case stays green.
   - **cmd/keyroster-agent/apply.go.** parseApply gives `apply` run's defaults (`--state-dir /var/lib/keyroster-agent`, `--spool <state-dir>/spool`). The runbook commands this plan writes, `sudo keyroster-agent apply --once`, therefore need no path flags. The hints in apply.go, resetdir.go, heartbeat.go and hoststatus.go stay as they are.

   The read_first ranges below are found with `grep -n` on origin/main, never by line numbers.
5. **The publish values on main at 9ac9c12** (read 2026-11-01):
   - the ROADMAP's Phase 3 Plans line reads 15/23 plans executed in 22 waves;
   - STATE.md reads total_plans 58 and `Plan: 16 of 23`;
   - 03-09 has `wave: 15` and `depends_on: ["03-08e"]`;
   - 03-10 to 03-16 have waves 16 to 22.

   Task 5 computes every number from origin/main's actual values, with a guard, and checks each one.
6. **Threat IDs.** This plan adds T-03-316, T-03-317 and T-03-321. T-03-318 and T-03-319 are 03-08k's.
7. **host-setup.md.** Task 5 replaces the paragraph 03-08d's D-2 added: it starts "That does not help a host that is far behind." after the "Revocations keep applying" list, and ends "UNVERIFIED on a real host: no test or drill runs this case." 03-08d's "Run in CI (03-08d)" list is left as it is; this plan adds its own sentence. 03-08e's prune sentences in the paragraph "The fetcher keeps the spool readable too." stay as they are; Task 5 adds two sentences after that paragraph's "Run in CI (03-08e)" list.

</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a verified directory refused for its content at the newest of a host's read window → forward records it in unapplied.json and lands the KRL alone → the next apply reads past it from the record → the fixed version installs → the commit removes the record"</name>
  <reversibility rating="reversible">A new state file, <state>/unapplied.json, that only moves where the next capture reads and chains from. Deleting it at any time makes the host read from accepted/ again, as main does. No signed document, wire message or accepted/ snapshot format changes.</reversibility>
  <precondition>All of these hold:
    - `git fetch origin` succeeds.
    - `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md` exits 0.
    - 03-08e is merged (9ac9c12 or later), with the names this plan builds on. Each command prints 1:
      - `P=$(git show origin/main:internal/agent/spool/spool.go) && printf '%s\n' "$P" | grep -c 'func Cap('`;
      - `P=$(git show origin/main:internal/agent/spool/spool.go) && printf '%s\n' "$P" | grep -c '^func Keep(vs \[\]uint64, floor uint64, above int)'`;
      - `F=$(git show origin/main:internal/agent/fetch/fetch.go) && printf '%s\n' "$F" | grep -c '^func pruneSpool(dir string, a enroll.Accepted)'`;
      - `F=$(git show origin/main:internal/agent/fetch/fetch.go) && printf '%s\n' "$F" | grep -c '^const keepAbove = MaxRounds \* serverclient.MaxAgentStatePerKind'`;
      - `A=$(git show origin/main:cmd/keyroster-agent/apply.go) && printf '%s\n' "$A" | grep -c 'func parseApply('`.
    - This plan is not on main yet: `git cat-file -e origin/main:internal/agent/state/unapplied.go` exits non-zero.
  </precondition>
  <files>internal/agent/state/verify.go, internal/agent/state/unapplied.go, internal/agent/apply/apply.go, internal/agent/apply/window_test.go</files>
  <read_first>
    Read functions, not whole files. Find each with `grep -n` on the branch (03-08e may have moved line numbers) and read only that range.
    - internal/agent/state/verify.go: `func Verify(`, `func KRLAlone(`, `func storedOnly(`, `func (v *Verified) holdBundle(`, the start of `verifyBundle` and of `verifyDirectory` up to its chain loop, and `verifyKRL` up to VerifyManifest (about 9 KB).
    - internal/agent/state/state.go: `type Stored`, `func (s *Stored) Floor(` and loadSnapshot from `if s.Bundle == nil` to its end (about 3 KB).
    - internal/agent/spool/spool.go: `func Cap(`, `func readCapped(` and `func pickAbove(` (about 2 KB).
    - internal/agent/apply/apply.go: the Report struct, the epilogue of `func Apply(`, `func (e *engine) forward(`, `func (e *engine) krlAlone(`, the doc comment of `func (e *engine) pollSpool(` and `func (e *engine) finishCommit(` (about 14 KB). internal/agent/apply/layout.go: `func (e *engine) writeState(`, `remove(` and `readState(` (about 1 KB).
    - internal/agent/apply/rechain_test.go: the subtest oversize_principals_file_krl_applied and the helper mustKRLAlone. internal/agent/apply/harness_test.go: dirSpec, `func (f *fixture) directory(`, publishDir, publishKRL, apply and installed (about 6 KB together).
  </read_first>
  <action>
Create branch `p03/08j-agent-spool-window` from origin/main. Place this plan file untracked in the phase directory.

**RED first.** Add only the new symbols, with no behaviour:
- state.UnappliedFile ("unapplied.json"), state.MaxUnapplied and state.ErrUnapplied;
- type state.Unapplied;
- ParseUnapplied, and Base returning (nil, nil);
- (*Verified).Unapplied returning nil;
- VerifyAhead returning Verify(p, accepted, in);
- Report.Unapplied, of a new type apply.Unapplied {Bundle, Directory uint64} with omitempty JSON tags `bundle` and `directory`, never set.

Write the new file internal/agent/apply/window_test.go with `TestSpoolWindow` and its first two cases.
- The file starts with `//go:build linux`, like the rest of internal/agent/apply.
- The cases use the existing harness: newTestHost, h.installed, h.publishDir with h.spec, a spec with bulkRoles 17 for "above the caps" (as oversize_principals_file_krl_applied does), h.publishKRL and h.apply. Only a window's newest version is ever made above the caps, because the versions between are only chain-checked.
- The record lives at h.l.State(state.UnappliedFile).

The two cases:
- `refused_window_newest_then_fix_applies`, the tracer, in the PR #76 review's shape:
  - Setup: h.installed("role:ops", "role:old") is directory 1. Directories 2-64 carry both roles, 65 the same with bulkRoles 17, and 66 only role:ops. publishKRL(6).
  - **Apply 1** returns generation_too_large, and current revokes 6. Principals stay [role:old role:ops] and accepted/ stays at directory 1. The report has SpoolMore true and Unapplied {Directory: 65}, and the record exists.
  - **Apply 2** returns nil, with DirectoryVersion 66, principals [role:ops], BundleHeld false and Unapplied nil. The record file is gone, because the commit passed it. (BundleHeld false is a guard on verify's steps with a directory-only record; here the newest directory verifies under the bundle in force, so no hold is tried.)
  - RED on main and on the stubs: apply 2 refuses 65 again, and role:old stays granted.
- `window_control_within_reach`: directories 2-63, 64 above the caps, and 65 fixed. The first apply installs 65 and writes no record. GREEN at once: this is the review's control.

Run them, record the RED in the SUMMARY, then implement. This is the applier fix per D-2, with the design chosen under Planner decisions.

**state, verify.go.** Verify's body moves into `verify(p *Pins, chain, alone *Stored, in spool.State)`:
- the bundle, directory and KRL steps run against chain;
- a refused bundle or directory step returns KRLAlone(p, alone, in, refused);
- **the bundle in force stays a hold step.** When alone has a bundle and chain.BundleVersion is above alone.BundleVersion, alone's bundle step is v.steps[0], below chain's. Base takes a bundle part only above accepted's, so this holds exactly when the record has a bundle part (Task 2). So holdBundle can still hold the capture at the bundle in force when the newest directory carries only that policy's quorum, as main does for a host catching up across a policy rotation (TestApply/catch_up_across_policy_rotation).
  - The condition compares BundleVersion only, never pointers, bytes or a reparsed bundle. With a directory-only record, chain's bundle is accepted's, and verify's steps must be exactly main's. A duplicate step [B_a, B_a, ...] would let holdBundle hold at k = 1 with BundleChanged set.
  - In this task chain's BundleVersion is always alone's, so the step is never added; Task 2 tests it.

Verify becomes verify(p, prev, prev, in), unchanged in behaviour, so every TestKRLAlone, TestResetDirectory and apply test stays green unchanged. Verify's doc comment is unchanged except for one sentence naming VerifyAhead.

**state, unapplied.go (new).**
- **Constants.**
  - `UnappliedFile = "unapplied.json"`.
  - `MaxUnapplied = 8 << 20`. The record's largest form is four fields of spool.MaxBundle (bundle, bundle_sigs, policy, policy_sigs; 4 MiB), wire.MaxDirectory (1 MiB) and wire.MaxDirectorySigs (64 KiB). That is about 5.1 MiB raw and 6.8 MiB in base64, so 8 MiB holds it.
  - `ErrUnapplied = errors.New("unapplied_record_invalid")`.
- **The record type.** `type Unapplied struct` with the fields Bundle, BundleSigs, Policy, PolicySigs, Directory and DirectorySigs, all []byte, with omitempty JSON tags `bundle`, `bundle_sigs`, `policy`, `policy_sigs`, `directory` and `directory_sigs`.
  - The bundle part (with its policy) is present when Bundle is non-nil; the directory part when Directory is non-nil.
  - The record never holds a KRL.
- **Codec.** Encode uses trust.CanonicalJSON. `ParseUnapplied(b []byte) (*Unapplied, error)`:
  - takes at most MaxUnapplied bytes and decodes with trust.DecodeStrict;
  - checks each field against the cap spool.Read applies to the same file. bundle, bundle_sigs, policy and policy_sigs are each at most spool.MaxBundle, directory at most wire.MaxDirectory, and directory_sigs at most wire.MaxDirectorySigs;
  - requires all four fields for a bundle part and both for a directory part;
  - refuses a record with neither part, which the applier never writes.

  Its errors wrap ErrUnapplied.
- **`func (v *Verified) Unapplied(accepted *Stored) *Unapplied`** returns nil when any of these holds: v.Refused is set, accepted is nil or holds no bundle, or nothing is ahead. In this task it records the directory part only: v.Next's directory and sigs, when v.Next.DirectoryVersion is above accepted.DirectoryVersion. Task 2 adds the bundle part.
- **`func (u *Unapplied) Base(accepted *Stored) (*Stored, error)`** returns the state a capture is read and chained from:
  - It returns (nil, nil) when accepted is nil. WriteAccepted and buildStatus may call the loader before forward removes a record that no accepted/ supports.
  - Otherwise it starts as a copy of accepted. The KRL, KRL manifest, KRL sig and KRL version stay accepted's.
  - It takes the directory part when its directory.Parse version is above accepted's.
  - When no part is taken, it returns (nil, nil): a record that a commit has passed.
  - A part that does not parse is ErrUnapplied.
  - In this task a bundle part is ignored. Task 2 adds it.
- **`func VerifyAhead(p *Pins, accepted, base *Stored, in spool.State) (*Verified, error)`** is verify(p, base, accepted, in). Task 2 adds the Changed recomputation. Its doc comment cites `PR #76 review F8 (03-08j)` and says:
  - the base carries accepted/'s KRL, so the newest KRL is verified against the bundle actually put in force and against accepted/'s KRL version;
  - a refused step takes the KRL alone against accepted/ (D-R2), never against the record;
  - the versions between the record and the newest one are chain-checked and never rendered, as in Verify.

**apply, the one loader.** `loadUnapplied(l Layout, accepted *state.Stored) (*state.Stored, *state.Unapplied, error)`:
- reads <state>/unapplied.json without following links (spool.OpenDir on l.StateDir, then spool.ReadFileAt with MaxUnapplied);
- parses it and returns Base;
- returns nil, nil, nil when the file is absent.

forward, finishCommit, Apply's epilogue, and Task 2's WriteAccepted and ResetDirectory all use it, as does Task 3's buildStatus.

**No loader error ever stops an apply, a reset or a status write.** A damaged record is only ever dropped, and dropping one only makes the host read from accepted/ again. A removal that fails is logged at warning level, and the caller goes on as if there were no record. ResetDirectory is the one exception: for a record that parses, a failed rewrite or removal fails the reset before anything changes (Task 2).

**apply, forward.**
- **Loading.** After loadStored, forward calls loadUnapplied. None of the removals below happens under DryRun.
  - A record that is unreadable or ErrUnapplied is logged at warning level (`WARNING unapplied.json dropped: <error>; reading from the accepted state`) and removed.
  - A record with no part ahead is removed without a log line.
  - Before a first install (accepted/ nil), any record is removed.
- **Capturing.** With a base, the capture uses base.Floor() and state.VerifyAhead(pins, stored, base, st). Otherwise it uses stored.Floor() and state.Verify, as today. The refused-Verify warning and the rest of forward are unchanged, and krlAlone keeps stored (accepted/) as its prev.
- **Recording.** In the content-refusal branch, just before krlAlone(stored, st, v, refusal), forward calls `e.recordUnapplied(stored, v)`:
  - It writes v.Unapplied(stored) through e.writeState (0600, paths.Allowed).
  - It writes nothing under DryRun, before a first install, when v.Refused is set, or when the file already holds equal bytes.
  - It logs `recorded bundle B / directory D as unapplied: the next apply reads past them`.
  - A write that fails is logged at warning level, and the run goes on to the KRL-alone pass: a revocation never waits for the record.
- **Passing the record.** finishCommit calls loadUnapplied after Activate, under the apply lock and on every commit path, recovery's included. It removes the record when Base reports no part ahead of the new accepted/. A KRL-alone commit leaves the record ahead, so it stays.
- **The report.** Apply's epilogue sets r.Unapplied from loadUnapplied and accepted/ as they are after the run: the versions of the parts above accepted/'s, or nil. The report therefore never names a record that a commit has passed.
- **pollSpool** is unchanged. Its doc comment gains one sentence: it verifies against the pending target, and after that target's commit the next forward records a refused state if one remains.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestSpoolWindow|TestKRLAlone/(oversize_principals_file_krl_applied|ops_key_changed_krl_waits|ca_line_rejected_krl_applied)|TestResetDirectory/reset_then_newer_krl_before_directory_arrives|TestStored" ./internal/agent/apply/ ./internal/agent/state/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestSpoolWindow/refused_window_newest_then_fix_applies", "--- PASS: TestSpoolWindow/window_control_within_reach", "--- PASS: TestKRLAlone/oversize_principals_file_krl_applied", "--- PASS: TestKRLAlone/ops_key_changed_krl_waits", "--- PASS: TestKRLAlone/ca_line_rejected_krl_applied", "--- PASS: TestResetDirectory/reset_then_newer_krl_before_directory_arrives"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'func VerifyAhead(' internal/agent/state/unapplied.go` prints 1, and `grep -v '^[[:space:]]*//' internal/agent/apply/apply.go | grep -c 'state.VerifyAhead('` prints at least 1.
    - `grep -v '^[[:space:]]*//' internal/agent/state/unapplied.go | grep -c 'json:"krl'` prints 0, and `head -1 internal/agent/apply/window_test.go` prints `//go:build linux`.
    - The SUMMARY records the tracer's RED and lists these mutants. Each is applied, run against its named test, and restored byte for byte. All three are killed by `refused_window_newest_then_fix_applies`:
      - forward's recordUnapplied call removed;
      - finishCommit's removal removed, which the file assertion after apply 2 catches;
      - Base taking a part at or below accepted/'s version, which keeps the passed record.
  </acceptance_criteria>
  <done>A host whose window-newest directory is refused records it, reads past it at the next apply, installs the fixed version, and removes the record. The KRL lands meanwhile, and nothing from the record is installed unless it is the newest state a capture verified.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The record for bundles, Changed against accepted/, the merging record write, the fetcher's cursor, reset-directory, and the guard cases</name>
  <files>internal/agent/state/unapplied.go, internal/agent/apply/apply.go, internal/agent/apply/window_test.go, internal/agent/apply/installed.go, internal/agent/apply/resetdir.go, internal/agent/fetch/fetch.go (doc comment only), internal/agent/enroll/pop.go (doc comment only)</files>
  <behavior>
    TestSpoolWindow gains these cases. Each case that needs a record first asserts that the first apply wrote one. Only a window's newest version is ever made above the caps. "The bundle case's apply 1" means:
    - bundle 2 is successorWithNext of bundle 1, adding a next user CA whose line h.run.rejectCA refuses;
    - apply 1 returns ca_line_rejected and records {Bundle: 2}.

    The cases:
    - `refused_run_longer_than_a_window_reaches_fix`: directory 1, then 2-129, where 65 and 129 (each window's newest) are above the caps, and 130 is fixed.
      - Apply 1 refuses 65 and records it. Apply 2 reads 66-129, refuses 129 and records it. Apply 3 installs 130. Until apply 3 the principals stay directory 1's.
      - Expected GREEN at once on Task 1's head.
    - `unchanged_spool_still_refused`: the tracer's case without 66. Apply 2 runs on the unchanged spool.
      - It returns generation_too_large again, and outboxStatus's last_apply.result is refused. The KRL stays in force and the record stays. It asserts nothing about NoOp (refusal_without_newer_krl_is_noop pins NoOp true for the KRL-alone pass).
      - RED on Task 1's head: with Changed computed against the record, apply 2 reports ok.
    - `bundle_ca_line_window_newest_then_fixed_bundle_applies`:
      - Setup: bundles 2-64 are root-signed successors (h.f.successor, with issued_at never going back). 65 is successorWithNext of 64 with the refused line. 66 is a successor of 65 without that entry, re-signed; trust.ParseBundle and trust.VerifySuccessor must accept it. publishKRL(6).
      - **Apply 1** returns ca_line_rejected, with KRL 6 alone and Unapplied {Bundle: 65}.
      - **Apply 2** puts bundle 66 in force, and CAFile lacks the line.
      - **Fallback** if no valid successor drops the entry: 66 keeps the line, apply 2 records 66, and after clearing rejectCA apply 3 installs 66 (main would install 65). Record in the SUMMARY which shape was used.
      - RED on Task 1's head.
    - `recorded_state_installed_when_the_host_accepts_it`: the bundle case's apply 1, then h.run.rejectCA = nil. Apply 2 on the unchanged spool installs bundle 2. RED on Task 1's head.
    - `krl_only_the_recorded_bundle_signs_waits`: bundle 2 replaces the ops key (f.rotationOps) with directory 2 above the caps. Apply 1 records {Bundle: 2, Directory: 2}. Then KRL 6 is signed by the new key, and apply 2 returns generation_too_large and krl_not_verified, with nothing installed. RED on Task 1's head.
    - `policy_rotation_below_the_recorded_bundle`, table-driven over newOps (false, true) like TestApply/catch_up_across_policy_rotation, whose builders it uses:
      - Setup: bundle 2 rotates the policy (rotationOps, with a new admin, and with a new ops key when newOps). Bundle 3 is successorWithNext of 2, adding a CA line h.run.rejectCA refuses. No new directory. Apply 1 returns ca_line_rejected and records {Bundle: 3}.
      - Then directories 2-65 arrive, signed under bundle 1's policy. publishKRL(7) is signed by the new key when newOps.
      - **Apply 2** behaves as main's first capture does: DirectoryVersion 65, BundleVersion 1, BundleHeld true. With newOps, the KRL the new key signed is not taken under bundle 1.
      - The record stays {Bundle: 3}.
      - RED on Task 1's head, which records no bundle part. Without the in-force bundle as a hold step (Task 1), directory 65 fails under bundle 3's policy on every apply.
    - `held_content_refusal_keeps_the_records_bundle`: the newOps=false row, but directory 65 is above the caps.
      - Apply 2 returns generation_too_large, and the KRL lands alone.
      - The record then holds {Bundle: 3, Directory: 65}: the bundle part is kept and the directory part added.
      - RED on Task 1's head, which records no bundle part, so the "first apply wrote one" assertion fails. It is also RED against a record write that replaces instead of merging.
    - `fork_after_the_record_refused`: run apply 1 of the tracer's case without 66. Then build a re-made 65' chained to 64 and a 66' chained to 65' (h.f.directory). 65' is renderable (no bulkRoles) and carries only role:ops. Set h.state.Directories[65] to 65' and h.state.Directories[66] to 66', and publishKRL(6, 7).
      - The capture read from the record holds the spool's 65' (pick's `below`) and 66'. 66' does not chain to the record's 65.
      - Apply 2 returns directory_not_verified (state.ErrDir), and current revokes 7.
      - After the KRL-alone commit, principals stay [role:old role:ops] and accepted/'s directory stays 1. BundleHeld is false, and the record still holds exactly {Directory: 65}.
      - This is the shape in which a second capture from accepted/'s floor would install a fork: its window 2..65 ends at the renderable 65'.
      - Expected GREEN at once on Task 1's head, which already chains from the record's directory.
    - `bundle_fork_after_the_record_takes_the_krl_against_accepted`: the bundle case's apply 1, then h.run.rejectCA = nil. The spool's bundle 2 stays the record's. A bundle 3' is added that chains to a re-made 2' (h.f.successor of bundle 1 with another issued_at), and publishKRL(6).
      - Apply 2 returns bundle_not_verified, and current revokes 6.
      - accepted/'s bundle stays 1, and the record stays {Bundle: 2}.
      - This is the case where VerifyAhead's own KRL-alone result is used, while the record holds a part that differs from accepted/'s and would render.
      - RED on Task 1's head, which records no bundle part, so the "first apply wrote one" assertion fails.
    - `withheld_record_version_does_not_roll_back`: run apply 1 of the tracer's case without 66. Then remove the spool's directory-65 files, and add a directory 66 whose sigs do not verify.
      - Apply 2 returns directory_not_verified, and the KRL lands alone.
      - Principals and accepted/ stay at directory 1, and directory 64 is never installed. The record stays.
      - Expected GREEN at once: no capture is verified from accepted/ while a record exists. It stays as a regression case.
    - `spool_copy_of_the_recorded_version_ignored`: run apply 1 of the tracer's case without 66. Then set h.state.Directories[65] to a re-made 65' chained to 64, and add a 66 that chains to the original 65 and carries only role:ops.
      - The capture holds the spool's 65' (pick's `below`) and 66.
      - Apply 2 installs 66, with principals [role:ops].
      - Expected GREEN at once on Task 1's head, which already chains from the record's directory. It pins the two mutants listed below.
    - `damaged_record_dropped`: after apply 1 of the tracer's case without 66, the record is overwritten with bytes that do not parse (`{"bundle":`).
      - Apply 2 logs a warning naming unapplied.json, reads from accepted/ as main does, and records 65 anew.
      - Expected GREEN at once.
    - `removed_record_reads_from_accepted`: after apply 1 of the tracer's case without 66, the record is removed by hand. Apply 2 reads from accepted/ as main does, refuses 65 again and records it anew. Expected GREEN at once.
    - `removed_record_takes_the_remade_bundle_chain`: the bundle case's apply 1, then h.run.rejectCA = nil. The spool's bundles become a re-made chain 2' and 3' from bundle 1 (other issued_at values).
      - **Apply 2**, with the record present, returns bundle_not_verified. The KRL lands alone, and accepted/'s bundle stays 1.
      - **The record is removed by hand.** Apply 3 installs bundle 3' from accepted/, as main does.
      - This runs signer-install.md's remedy.
      - RED on Task 1's head, which records no bundle part, so the "first apply wrote one" assertion fails.
    - `fetcher_cursor_follows_the_record`: after apply 1 of the tracer's case, readAccepted gives bundle 1 and directory 65, while AcceptedVersions(h.l).Directory is still 1. After apply 2, readAccepted gives directory 66. RED on Task 1's head.
    - `reset_directory_drops_the_records_directory`: after apply 1 of the tracer's case:
      - **An interrupted reset first.** ResetDirectory(h.l, h.l.State("missing-spool")) returns an error. paths.Allowed passes, and spool.OpenDir fails after step 1 dropped accepted/'s directory, which stands in for a crash there. accepted/ then holds no directory, and no record file is left.
      - **Then the full reset.** ResetDirectory(h.l, h.cfg.Spool) leaves no record, and readAccepted's directory is 0.
      - RED on Task 1's head, which has no record step.
    - `reset_directory_keeps_the_records_bundle`: after the bundle case's apply 1, ResetDirectory leaves a record with bundle 2 and no directory, and readAccepted's bundle is 2. RED.
    - `no_record_after_a_verify_refusal_or_a_dry_run`: the bundle_step_refused_krl_applied shape writes no record, and apply 1 of the tracer's case with h.cfg.DryRun set writes none and changes nothing. GREEN at once.
    - `record_write_failure_keeps_the_krl`: a non-empty directory sits at the record's path, and apply 1 of the tracer's case runs.
      - It logs a warning for the record and still commits KRL 6 alone.
      - If CheckStateDirs refuses such a state directory, use another failure the harness offers, and record it.
      - GREEN at once.
  </behavior>
  <read_first>
    Read functions, not whole files. Task 1's edits are in context. Find each with `grep -n` on the branch.
    - internal/agent/apply/installed.go: `func AcceptedVersions(` and `func WriteAccepted(` (about 2 KB). internal/agent/apply/resetdir.go: `func ResetDirectory(` with its doc comment (about 5 KB).
    - internal/agent/fetch/fetch.go: `func (f *Fetcher) cursor(` (about 1 KB). internal/agent/enroll/pop.go: `type Accepted` and its doc comment (about 0.5 KB). internal/server/agent.go: `func (s *Server) handleAgentState(` (about 2 KB).
    - internal/agent/apply/apply_test.go: `t.Run("catch_up_across_policy_rotation"`, `func (f *fixture) successor(`, rotation and rotationOps (about 5 KB).
    - internal/agent/apply/rechain_test.go: the subtests bundle_step_refused_krl_applied, ca_line_rejected_krl_applied, ops_key_changed_krl_waits and refusal_without_newer_krl_is_noop; the helpers successorWithNext and readAccepted; and TestResetDirectory's first subtest. internal/agent/apply/status_test.go: outboxStatus (about 9 KB together).
  </read_first>
  <action>
**Tests first.** Write the cases in `<behavior>` and run them on Task 1's head. Record in the SUMMARY which were RED and which GREEN at once, with the reasons given there. Then implement. While a record exists, no capture is ever verified from accepted/: the record is the only chain base.

**state, unapplied.go.**
- **(*Verified).Unapplied** also records the bundle part: v.Next's bundle, its sigs, its policy and the policy's sigs, when v.Next.BundleVersion is above accepted.BundleVersion. After holdBundle, v.Next names the held step, so the held step is what gets recorded.
- **Base** also takes the bundle part:
  - only when the parsed bundle's version is above accepted's;
  - parsed with trust.ParseBundle and trust.ParsePolicy, and the bundle must name the policy's SHA-256, as loadSnapshot requires;
  - it then sets the parsed bundle and policy, so Floor and the chain use them.

  A bundle that does not name its policy is ErrUnapplied.
- **VerifyAhead**, when Refused is nil, recomputes BundleChanged and DirectoryChanged against accepted: v.Next's bundle or policy bytes against accepted's, and v.Next's directory bytes against accepted's. When holdBundle held the capture at the bundle in force (Task 1's lowest step), BundleChanged is false, as on main.

**apply, recordUnapplied merges, never narrows.** recordUnapplied loads the existing record with loadUnapplied and writes, per kind, the higher of two parts: the existing one, while it is still ahead of accepted/, and v.Unapplied(stored)'s.
- A part is replaced only by a higher version of the same kind.
- A held capture puts a bundle at or below the record's in force, and keeps the record's bundle part.
- Equal bytes write nothing.

The record therefore changes in exactly four ways:
- this write, which only raises parts;
- finishCommit, which removes a passed record;
- ResetDirectory, which drops the directory part;
- forward's load, which drops a damaged or passed record.

The doc comment says so.

**apply, WriteAccepted (installed.go).**
- After AcceptedVersions, loadUnapplied raises Bundle and Directory to the base's versions where those are higher. On any loader error, WriteAccepted writes accepted/'s versions, as main does. AcceptedVersions itself is unchanged.
- The doc comment says why the raise is needed and why it is safe:
  - the fetcher's cursor is min(accepted.json, the spool's newest), and one poll reaches 1024 versions above it;
  - pruneSpool keeps from accepted.json's versions, so the raise also keeps the record's version and what a capture from it reads, which 03-08e's rule counted from accepted/ alone would remove once the record is more than keepAbove above it;
  - the server uses the request's versions only to choose what to serve (handleAgentState's bundleItems, directoryItems and krlItem) and stores none of them;
  - the KRL cursor stays the KRL in force.
- Two doc comments that call accepted.json "the version the applier accepted" now say "accepted, or recorded as unapplied when higher": fetch.go's `func (f *Fetcher) cursor(` and enroll.Accepted in internal/agent/enroll/pop.go. Neither changes code.

**apply, ResetDirectory (resetdir.go).** The record step is step 0, the first step that changes anything. It runs after CheckStateDirs, paths.Allowed, LoadPins, the lock and the pending-marker check, so a reset refused with ErrResetPending leaves the record as it was.
- **Order.** ResetDirectory loads accepted/ read-only (state.LoadStored), then runs the record step, and only then drops the accepted directory and saves (step 1).
- **The record step.** It loads the record with loadUnapplied against that accepted/:
  - if its bundle part is still ahead of the accepted bundle, it rewrites the record without the directory part through e.writeState (spool.WriteFileAt, 0600, atomic);
  - otherwise it removes the record through e.remove (paths.Allowed).
- **Failures.**
  - A record that does not load (unreadable, or ErrUnapplied) is removed where possible. A failed removal is logged and never fails the reset, because forward drops such a record and no capture reads from it.
  - A record that parses but cannot be rewritten or removed fails the reset before step 1, with nothing changed. Otherwise its directory part would become the chain base over an accepted/ without a directory. No test makes this write fail; the SUMMARY lists the path as untested.
- **Why first.** A crash at any point then never leaves the record's directory part as the chain base while accepted/ holds no directory.
- **Doc comment.** Its numbered list gains this as step 0.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestSpoolWindow|TestKRLAlone/(ops_key_changed_krl_waits|bundle_step_refused_krl_applied|ca_line_rejected_krl_applied|refusal_without_newer_krl_is_noop)|TestResetDirectory|TestApply/catch_up_across_policy_rotation|TestStored" ./internal/agent/apply/ ./internal/agent/state/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestSpoolWindow/refused_window_newest_then_fix_applies", "--- PASS: TestSpoolWindow/window_control_within_reach", "--- PASS: TestSpoolWindow/refused_run_longer_than_a_window_reaches_fix", "--- PASS: TestSpoolWindow/unchanged_spool_still_refused", "--- PASS: TestSpoolWindow/bundle_ca_line_window_newest_then_fixed_bundle_applies", "--- PASS: TestSpoolWindow/recorded_state_installed_when_the_host_accepts_it", "--- PASS: TestSpoolWindow/krl_only_the_recorded_bundle_signs_waits", "--- PASS: TestSpoolWindow/policy_rotation_below_the_recorded_bundle", "--- PASS: TestSpoolWindow/held_content_refusal_keeps_the_records_bundle", "--- PASS: TestSpoolWindow/fork_after_the_record_refused", "--- PASS: TestSpoolWindow/bundle_fork_after_the_record_takes_the_krl_against_accepted", "--- PASS: TestSpoolWindow/withheld_record_version_does_not_roll_back", "--- PASS: TestSpoolWindow/spool_copy_of_the_recorded_version_ignored", "--- PASS: TestSpoolWindow/damaged_record_dropped", "--- PASS: TestSpoolWindow/removed_record_reads_from_accepted", "--- PASS: TestSpoolWindow/removed_record_takes_the_remade_bundle_chain", "--- PASS: TestSpoolWindow/fetcher_cursor_follows_the_record", "--- PASS: TestSpoolWindow/reset_directory_drops_the_records_directory", "--- PASS: TestSpoolWindow/reset_directory_keeps_the_records_bundle", "--- PASS: TestSpoolWindow/no_record_after_a_verify_refusal_or_a_dry_run", "--- PASS: TestSpoolWindow/record_write_failure_keeps_the_krl", "--- PASS: TestKRLAlone/refusal_without_newer_krl_is_noop", "--- PASS: TestApply/catch_up_across_policy_rotation"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/agent/apply/installed.go | grep -c 'loadUnapplied('` and `grep -v '^[[:space:]]*//' internal/agent/apply/resetdir.go | grep -c 'loadUnapplied('` each print at least 1.
    - `D=$(git diff origin/main -- internal/agent/fetch/fetch.go internal/agent/enroll/pop.go) && printf '%s\n' "$D" | grep -E '^[+-][^+-]' | grep -cvE '^[+-][[:space:]]*(//|$)'` prints 0: only comment lines changed there.
    - The SUMMARY lists these mutants. Each is applied, run against its named test, and restored byte for byte:
      - VerifyAhead's Changed left against the base: killed by `unchanged_spool_still_refused` and `recorded_state_installed_when_the_host_accepts_it`;
      - forward handing the base to krlAlone instead of stored: killed by `krl_only_the_recorded_bundle_signs_waits`;
      - verify's refused step taken alone against chain instead of alone: killed by `bundle_fork_after_the_record_takes_the_krl_against_accepted` (accepted/'s bundle would become 2) and by `fork_after_the_record_refused`;
      - verify no longer offering the bundle in force as the lowest step (Task 1): killed by both rows of `policy_rotation_below_the_recorded_bundle`;
      - recordUnapplied replacing the record instead of merging: killed by `held_content_refusal_keeps_the_records_bundle`;
      - forward verifying a second capture from accepted/'s floor when the one read from the record is refused: killed by `fork_after_the_record_refused` (its window 2..65 would install the renderable 65');
      - Base (or loadUnapplied) reading the recorded version's file from the spool (spool.ReadFileAt on directory-65.json) instead of the record's bytes: killed by `spool_copy_of_the_recorded_version_ignored`;
      - verifyDirectory chaining from the capture's own copy at the base's version (in.Directories[storedVersion], which Read holds as pick's `below`) instead of prev's bytes: killed by `spool_copy_of_the_recorded_version_ignored`;
      - WriteAccepted's raise removed: killed by `fetcher_cursor_follows_the_record`;
      - ResetDirectory's record step removed: killed by `reset_directory_drops_the_records_directory`;
      - ResetDirectory's record step placed after the spool removal, just before WriteAccepted: killed by `reset_directory_drops_the_records_directory` (its interrupted reset leaves the record). The harness cannot tell step 0 apart from a placement directly after step 1's save; the doc comment's step 0 and the review cover that order.
  </acceptance_criteria>
  <done>The record covers bundles too and is the only chain base while it exists. A host catching up across a policy rotation still holds at the bundle in force. The record is never lowered or narrowed. An unchanged spool still reports the refusal, the fetcher's cursor follows the record, and reset-directory drops the record's directory. No fork, rollback, spool copy, damaged or removed record gets anything installed that main would not.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: The stuck window's state fleet-wide: unapplied in the heartbeat status, its validation and keyroster host status's alert</name>
  <reversibility rating="costly">The task adds an omitempty field to the heartbeat status, which the server stores and returns. A server from before this plan decodes strictly, so it refuses a heartbeat that carries the field. The runbook therefore says to update the server first. Once stored heartbeats carry the field, rolling the server back, or removing the field again, would make those bodies unparseable.</reversibility>
  <files>internal/agent/apply/status.go, internal/agent/apply/window_test.go, internal/agent/heartbeat/heartbeat.go, internal/agent/heartbeat/heartbeat_test.go, cmd/keyroster/hoststatus.go, cmd/keyroster/hoststatus_test.go</files>
  <behavior>
    - `TestSpoolWindow/status_reports_unapplied` (window_test.go). It uses the shape of refused_window_newest_then_fix_applies:
      - After apply 1, outboxStatus(t, h).Unapplied is {Directory: 65} with Bundle 0, while the status's Directory.Version, the version in force, is 1.
      - After apply 2, Unapplied is nil.
      - RED against the stub field, which is never set.
    - `TestValidate` (heartbeat_test.go):
      - Its field-rule table (the one with the `last_apply.detail` case) gains `unapplied`: a status whose Unapplied has both versions zero is refused as field `unapplied`.
      - A status with Unapplied {Directory: 65} passes Validate and comes back equal through trust.CanonicalJSON and ParseStatus.
      - RED: the stub accepts the zero case.
    - `TestHostStatusUnapplied` (hoststatus_test.go, beside TestHostStatusDiverged):
      - A host whose stored heartbeat carries Unapplied {Directory: 65} shows `unapplied: directory v65` in its ALERTS cell, and gets the note `<name>: unapplied: it verified directory v65 but cannot apply it`.
      - A host with Unapplied {Bundle: 3, Directory: 65} shows `unapplied: bundle v3, directory v65`.
      - A host without the field shows neither.
      - RED against the stub.
  </behavior>
  <read_first>
    Read functions, not whole files. Find each with `grep -n` on the branch and read only that range. Tasks 1-2's edits are in context.
    - internal/agent/heartbeat/heartbeat.go: the Status struct, the LastApply and Pending types, `func Validate(` from its `s.Stuck` rule to its end, and ParseStatus (about 4 KB).
    - internal/agent/heartbeat/heartbeat_test.go: `func TestValidate(` with its field-rule table (about 3 KB).
    - internal/agent/apply/status.go: `func (e *engine) buildStatus(` from the accepted/ block to the `s.LastApply` assignment (about 4 KB).
    - cmd/keyroster/hoststatus.go: the per-host loop from `if h := r.Heartbeat` to the alerts join (about 4 KB). cmd/keyroster/hoststatus_test.go: `func TestHostStatusDiverged(` and the fixture helpers it uses (about 3 KB).
  </read_first>
  <action>
**RED first.** Add only the field, with no behaviour:
- `type Unapplied struct` in heartbeat.go, with Bundle and Directory uint64 (omitempty JSON tags `bundle` and `directory`);
- `Unapplied *Unapplied` with JSON `unapplied,omitempty` in Status, after KRLStale.

Nothing sets it and Validate has no rule for it. Run the three tests on Task 2's head and record the REDs, then implement. This is the stuck-window state in the host status that D-2 asks for.

**heartbeat.go.**
- **Doc comment** (cites `PR #76 review F8 (03-08j)`). Unapplied holds the newest bundle and directory versions the applier verified but could not apply for their content, and now reads past. The versions in force stay in Bundle and Directory.
- **Validate** refuses an Unapplied whose two versions are both zero, as field `unapplied`, and checks nothing else. In particular it has no rule against the versions in force: a status written while accepted/ and the record moved must never make the server refuse the heartbeat.

**status.go, buildStatus.**
- After it reads accepted/, buildStatus calls loadUnapplied (Task 1). It sets s.Unapplied to the base's versions that are above accepted/'s: the bundle, the directory, or both. With none above, it sets nothing.
- The conversion from the report's apply.Unapplied is one small helper, shared with Apply's epilogue.
- A record that does not load sets nothing. The status never fails because of the record; forward logs the warning.

**hoststatus.go.** In the per-host loop, after the `stuck` block, when st.Unapplied is non-nil:
- Build the parts `bundle vB` and `directory vD` from the non-zero versions.
- Append the alert `unapplied: ` followed by the parts joined with ", ".
- Append the note `<name>: unapplied: it verified <parts joined with " and "> but cannot apply it (its last apply error says why); revocations still apply, and it applies the next version it can (docs/runbooks/host-setup.md "Revocations keep applying")`.
- `--json` carries the field through the heartbeat as it is.

The server needs no code change. It parses the heartbeat with ParseHeartbeat, stores the body and returns the parsed value. TestParseHeartbeat and TestHostStatusUnapplied cover both ends.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestSpoolWindow/status_reports_unapplied|TestStatus|TestValidate|TestParseHeartbeat|TestHostStatus" ./internal/agent/apply/ ./internal/agent/heartbeat/ ./cmd/keyroster/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestSpoolWindow/status_reports_unapplied", "--- PASS: TestValidate", "--- PASS: TestHostStatusUnapplied", "--- PASS: TestHostStatusDiverged", "--- PASS: TestStatus/cap_refusal_is_refused"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'json:"unapplied,omitempty"' internal/agent/heartbeat/heartbeat.go` prints 1.
    - `grep -v '^[[:space:]]*//' internal/agent/apply/status.go | grep -c 'loadUnapplied('` prints at least 1.
    - The SUMMARY lists these mutants. Each is applied, run against its named test, and restored byte for byte:
      - buildStatus not setting Unapplied: killed by `status_reports_unapplied`;
      - Validate's both-zero rule removed: killed by `TestValidate`;
      - the CLI alert removed: killed by `TestHostStatusUnapplied`.
  </acceptance_criteria>
  <done>Each host's status names the versions it verified but cannot apply. The server stores and returns them, and keyroster host status shows them as an alert with a note.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 4: spool.Read recaptures once when a listed name is gone at its open, so a capture racing the fetcher's prune does not fail</name>
  <reversibility rating="reversible">Read's result is unchanged whenever no file vanishes between its listing and its reads; otherwise it captures once more from a fresh listing. No format or state changes.</reversibility>
  <files>internal/agent/spool/spool.go, internal/agent/spool/spool_test.go</files>
  <behavior>
    TestReadRecapture (spool_test.go, a top-level test without t.Parallel) has two cases:
    - `listed_name_gone_is_recaptured_once`:
      - Setup: complete bundle 3 naming policy 2, policy 2, and an orphan policy 9, which no bundle names and which lies in the policy window of floor {Bundle: 3, Policy: 2}.
      - The seam removes policy-9.json and policy-9.json.sigs after the first listing.
      - readSpool returns no error, its state lacks policy 9, and the seam ran twice.
      - RED with the seam in place and no retry: the capture fails with ENOENT.
    - `gone_again_fails_the_capture`:
      - The seam removes a listed orphan policy after every listing, and plants the next one before returning.
      - readSpool returns an error that wraps unix.ENOENT after exactly two listings.
  </behavior>
  <read_first>
    - internal/agent/spool/spool.go: `func Read(` with its doc comment and `func readCapped(` (about 4 KB). internal/agent/spool/spool_test.go: the subtest floor_selects_versions (about 1 KB).
  </read_first>
  <action>
**Tests first.** Add the seam with no retry, write the two cases, run them and record the RED in the SUMMARY. Then implement the carried PR #77 item (owner decision: fix it in spool.Read).
- Read's body becomes `readOnce(dir string, floor Floor, listed func())`. It calls listed, when non-nil, right after ListDir. This is the test seam: an unexported parameter, never a package variable.
- `readSpool(dir string, floor Floor, listed func())` runs readOnce. When readOnce's error wraps unix.ENOENT, it runs readOnce once more from a fresh listing and returns that result. ReadFileAt wraps the Openat error with %w, so errors.Is sees the ENOENT.
- `Read(dir, floor)` is `readSpool(dir, floor, nil)`.
- Read's doc comment gains this, citing `F01 (03-08e), 03-08j`:
  - a name the listing returned that is gone at its open (the fetcher's prune, between the two) makes Read capture once more;
  - a second such error fails the capture as before, and the apply retries as on main;
  - a missing spool directory also takes the one extra attempt, which fails the same way.

Why here, and why one recapture: one fresh listing covers every kind the race reaches, an orphaned policy and also an older KRL the prune drops when a newer one completes between the two listings. A wider prune rule for policies would cover policies only.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestSpool|TestReadRecapture" ./internal/agent/spool/ ./internal/agent/fetch/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestReadRecapture/listed_name_gone_is_recaptured_once", "--- PASS: TestReadRecapture/gone_again_fails_the_capture", "--- PASS: TestSpool/cap_is_what_read_enforces", "--- PASS: TestSpool/floor_selects_versions", "--- PASS: TestSpoolPrune/superseded_pending_target_kept"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c '^func readSpool(dir string, floor Floor, listed func())' internal/agent/spool/spool.go` prints 1: the seam is a parameter, not a package variable.
    - The SUMMARY lists these mutants. Each is applied, run against its named test, and restored byte for byte:
      - Read without the recapture: killed by `listed_name_gone_is_recaptured_once`;
      - Read recapturing until it succeeds: killed by `gone_again_fails_the_capture`.
    - The SUMMARY says no test races a real capture against a real prune (UNVERIFIED); the seam stands in for it.
  </acceptance_criteria>
  <done>A capture that races the fetcher's prune captures once more from a fresh listing instead of failing; a second race fails it as on main.</done>
</task>

<task type="auto">
  <name>Task 5: host-setup.md and signer-install.md, the spool-pruning todo, the publish edits, the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/host-setup.md, docs/runbooks/signer-install.md, .planning/todos/pending/2026-10-28-agent-spool-pruning.md, .planning/phases/03-linux-agent-and-revocation/03-08j-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/host-setup.md. Find each with `grep -n` (about 12 KB):
      - the paragraph "Revocations keep applying" through 03-08d's "Run in CI (03-08d)" list;
      - 03-08e's paragraph "The fetcher keeps the spool readable too." through its "Run in CI (03-08e)" list and UNVERIFIED line;
      - the **Alerts.** list.
    - docs/runbooks/signer-install.md: the bullet "**Which hosts saw a lost version.**" (about 1 KB).
    - .planning/todos/pending/2026-10-28-agent-spool-pruning.md: its frontmatter and its `## Status` and `## Remaining` sections (about 2 KB).
    - .planning/ROADMAP.md: Phase 3's Plans line and wave blocks. .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter and its Task 1 precondition. 03-10 to 03-16: their `wave:` lines.
  </read_first>
  <action>
**host-setup.md (D-20).** Label every changed or new text "Run in CI" with the test names and 03-08j, and "UNVERIFIED on a real host".
- **03-08d's far-behind paragraph.** Replace it, from its sentence about a host that is far behind to its closing UNVERIFIED line, both bullets included. The new paragraph says:
  - An apply reads at most 64 versions of each kind past the ones the host holds.
  - When the newest of those is one the host cannot apply (`generation_too_large`, `ca_line_rejected`), the applier records that verified state as unapplied, in `/var/lib/keyroster-agent/unapplied.json` (root, 0600). The next apply reads past it, so a fixed version published later arrives.
  - While the host keeps refusing, the walk moves about 64 versions per retry (60 s), and at once when the fetcher brings new versions.
  - Meanwhile only KRLs apply; the principals and CA keys stay as they are.
  - The recorded state is installed only when an apply can apply it as the newest version it verified, for example after ssh-keygen is upgraded.
  - outbox/accepted.json names the recorded versions, so the fetcher asks the server for what comes after them, and keeps the spool from them (the fetcher paragraph below).
  - The record counts as an accepted version. A different version with the same number, or a chain not built on it, is refused (`directory_not_verified` or `bundle_not_verified`), as after a signer restore (signer-install.md). A host catching up across a policy rotation still holds at its bundle in force and applies the directory, as without a record.
  - The residual, UNVERIFIED (no test builds two rotations in one gap, and none runs this remedy):
    - A directory signed only under a policy strictly between the bundle in force and the recorded bundle is refused on every apply.
    - KRLs signed by the in-force ops key still land, and the status shows `unapplied`. Publishing newer versions does not clear it.
    - Clearing it takes a hand action. On a host whose last apply error is `directory_not_verified` while its status shows an unapplied bundle, run `sudo rm /var/lib/keyroster-agent/unapplied.json`, then `sudo keyroster-agent apply --once`. `keyroster-agent reset-directory` also clears it once the newest directory then verifies standalone.
  - `keyroster-agent reset-directory` drops the record's directory along with the accepted one. Otherwise, publishing a fixed version is enough, and no reset is needed.
  - Removing unapplied.json by hand is always safe: the host then reads from its accepted state again. The next sentence says: "While the record existed the fetcher kept the spool from the recorded versions, so the next apply can report `directory_chain_gap` or `bundle_chain_gap` until the next poll fetches the versions just above the accepted state again; the KRL still lands, and nothing else is installed." That sentence is UNVERIFIED: no test combines a removed record with a pruned spool.
  - Run in CI (03-08j): TestSpoolWindow (`refused_window_newest_then_fix_applies`, `refused_run_longer_than_a_window_reaches_fix`, `bundle_ca_line_window_newest_then_fixed_bundle_applies`, `policy_rotation_below_the_recorded_bundle`, `fork_after_the_record_refused`, `withheld_record_version_does_not_roll_back`, `removed_record_reads_from_accepted`, `fetcher_cursor_follows_the_record`, `reset_directory_drops_the_records_directory`).
  - UNVERIFIED on a real host, and beyond what the tests build (at most 130 versions): no test or drill runs a host thousands of versions behind.
- **After 03-08e's fetcher paragraph** ("The fetcher keeps the spool readable too.", after its Run in CI list and UNVERIFIED line), which otherwise stays as it is, add two sentences:
  - While a host holds an unapplied record, outbox/accepted.json names the recorded versions, so the prune counts its 1024 versions from them, not from the accepted state. Run in CI: `fetcher_cursor_follows_the_record`; that the prune then keeps what the record's capture reads is reasoned from the code (UNVERIFIED).
  - An apply whose capture finds a listed spool file gone, because the prune removed it in between, captures once more, so it no longer fails on that race. Run in CI: `TestReadRecapture`.
- **Alerts.** Add a bullet after `diverged`: `unapplied: directory vN` (or a bundle).
  - The host verified that version but cannot apply it, and the last apply error says why. It reads past the version and applies the next one it can, and revocations still apply.
  - Update keyroster-server before the agents. A server from before 03-08j refuses a heartbeat whose status carries `unapplied` (`heartbeat_field_invalid`). The host's stored status then stops moving, and `keyroster host status` shows it with the `status_stale` alert until the server is updated.
  - Do not roll the server back below 03-08j once agents have sent `unapplied`: that server cannot parse the heartbeats it already stored for those hosts.
  - The keyroster CLI ignores fields it does not know, so its version does not matter.
  - Run in CI: `TestHostStatusUnapplied`, `TestValidate`, `status_reports_unapplied`. The rollout sentences are UNVERIFIED: no test runs mixed server versions.

**signer-install.md.** Two edits to "Which hosts saw a lost version":
- The sentence about outbox/accepted.json now says it names, per kind, the version the agent accepted or, when higher, the version it verified but could not apply (03-08j). Either way the host refuses a different version with that number.
- Add the remedy for a recorded version the restore lost. A host whose recorded bundle (its `unapplied` status, or accepted.json's bundle above `/var/lib/keyroster-agent/accepted/`'s) is above the restored signer's bundle version needs only `sudo rm /var/lib/keyroster-agent/unapplied.json`, then `sudo keyroster-agent apply --once`. Escalate only if the accepted bundle itself was lost. For a lost directory, reset-directory as below.
- Label: Run in CI (03-08j): `fork_after_the_record_refused`, `fetcher_cursor_follows_the_record`, and for the remedy `removed_record_takes_the_remade_bundle_chain` (a recorded bundle, a re-made chain refused while the record exists, installed after its removal); UNVERIFIED on a real host: no test runs an actual signer restore.

**The spool-pruning todo** (.planning/todos/pending/2026-10-28-agent-spool-pruning.md). Keep its format, its frontmatter and its place under pending/. Two short, neutral edits:
- `## Status` gains one sentence: since 03-08j, outbox/accepted.json names an unapplied record's versions where they are higher, so the prune's window counts from them.
- `## Remaining` gains one item: the prune's window could shrink from 1024 to 64 versions once the applier publishes, in the outbox, every floor it reads the spool from (its accepted versions, a recorded unapplied state, and the pending target of a widening wait). A host catching up must keep today's pace, so while the applier moves between polls the fetcher would keep and fetch as it does now.
- `## Remaining`'s closing sentence "Neither changes what the applier reads." refers to two items; it becomes "None of these changes what the applier reads."
- No review-source wording, no F-number beyond those the todo already names, no disk figure, and no plan number for the deferred work.

**Publish edits.** Make them in this PR, on top of origin/main, which holds 03-08e. Every number is origin/main's value + 1. The values in brackets are what main held at 9ac9c12 (read 2026-11-01): 15/23 plans in 22 waves, total_plans 58, `Plan: 16 of 23`, 03-09 at wave 15 depending on 03-08e, and 03-10 to 03-16 at waves 16 to 22.
1. Commit this plan, unchanged, as `.planning/phases/03-linux-agent-and-revocation/03-08j-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each grow by one (N/23 plans in 22 waves → N/24 in 23 waves).
   - After 03-08e's Wave 14 block, insert `**Wave 15** *(blocked on Wave 14 completion)*` with the unchecked entry `03-08j-PLAN.md — A host reads past a verified version it cannot apply and reports it (PR #76 review F8): the unapplied record, the fetcher's cursor past it, and the unapplied status`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 15–22 → 16–23), and update each block's "blocked on Wave N completion" clause with them.
   - Add nothing about any other plan.
3. STATE.md: `total_plans` +1 (58 → 59), and the Plan line's `of M` +1 (of 23 → of 24).
4. 03-09-PLAN.md:
   - `wave:` +1 (15 → 16);
   - `depends_on` becomes `["03-08j"]`;
   - Task 1's `<precondition>` gains the clause `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md` exits 0. It goes next to the 03-08c, 03-08d and 03-08e clauses, which stay.
5. The `wave:` lines of 03-10 to 03-16 each +1 (16–22 → 17–23).
6. **Guard.** If origin/main's 03-09 does not hold `wave: 15` and `depends_on: ["03-08e"]`, another plan was slotted in first. Apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY. The automated checks below compute from origin/main, so they hold either way.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record. Record internal/agent/apply's and internal/agent/spool's times under -race from CI's build-test log. Above about 400 s, two thirds of Go's 10-minute default timeout, a time is a deviation to fix before the PR (thin the slowest new cases' version counts first).

**Push and the PR.**
1. Commit by path only.
2. Push the branch.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(agent): read past a verified version a host cannot apply, and report it (PR #76 review F8)"` with a neutral body and no attribution lines. The body names the rollout order (server before agents, no server rollback) and says the recapture is an F01 (03-08e) follow-up. It refers to findings only as PR #76 review F8 and F01 (03-08e). Do not enable auto-merge.
4. Wait for the required checks.

**The SUMMARY.** Include:
- the PR number and the check run IDs;
- the RED evidence, with where each was taken;
- the mutants;
- the GREEN-at-once cases with their reasons;
- which shape the bundle case used (the dropped entry, or the fallback);
- internal/agent/apply's and internal/agent/spool's times under -race in CI, beside 164 s for apply at PR #76's head (263 s locally in WSL) and 290 s locally in WSL at 03-08e's last code commit;
- what stays UNVERIFIED: that 03-08e's prune, counted from the raised accepted.json, keeps what a capture from the record reads (reasoned, not tested with the fetcher), a removed record meeting a pruned spool, and a real capture racing a real prune;
- capslock;
- `requirements-completed` empty: AGENT-07 is complete since earlier plans, AGENT-04 stays pending, and this plan hardens both.

The SUMMARY, the commit messages and the PR body are public. Use neutral hardening wording and F-numbers only.

Then run the tracking updates once, commit `docs(03-08j): complete agent spool-window plan`, push, and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>H=$(tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md) && printf '%s\n' "$H" | grep -c 'refused_window_newest_then_fix_applies' && printf '%s\n' "$H" | grep -c 'TestHostStatusUnapplied' && printf '%s\n' "$H" | grep -c 'status_stale' && printf '%s\n' "$H" | grep -c 'policy_rotation_below_the_recorded_bundle' && test "$(printf '%s\n' "$H" | grep -c 'does not help a host that is far behind')" = 0 && printf '%s\n' "$H" | grep -c 'TestReadRecapture' && printf '%s\n' "$H" | grep -c 'While the record existed the fetcher kept the spool from the recorded versions' && T=$(tr -s '[:space:]' ' ' < .planning/todos/pending/2026-10-28-agent-spool-pruning.md) && printf '%s\n' "$T" | grep -c 'from 1024 to 64' && printf '%s\n' "$T" | grep -c 'None of these changes what the applier reads' && test "$(printf '%s\n' "$T" | grep -c 'Neither changes')" = 0 && test "$(printf '%s\n' "$T" | grep -ciE '[0-9] ?([MG]i?B|bytes)')" = 0 && S=$(tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md) && printf '%s\n' "$S" | grep -c 'fork_after_the_record_refused' && printf '%s\n' "$S" | grep -c 'removed_record_takes_the_remade_bundle_chain'</automated>
    <fails_when>non-zero exit: a runbook sentence or label is missing (including the record-removal sentence), 03-08d's far-behind paragraph is still there, or the todo lacks the read-floors item or gives a disk figure</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && ( for n in 09 10 11 12 13 14 15 16; do X=$(git show origin/main:$P/03-$n-PLAN.md) || exit 1; W=$(printf '%s\n' "$X" | sed -n 's/^wave: //p'); test -n "$W" && grep -qx "wave: $((W+1))" $P/03-$n-PLAN.md || exit 1; done ) && grep -qx 'depends_on: \["03-08j"\]' $P/03-09-PLAN.md && grep -c '03-08j-SUMMARY.md' $P/03-09-PLAN.md && ST=$(git show origin/main:.planning/STATE.md) && T=$(printf '%s\n' "$ST" | sed -n 's/^  total_plans: //p') && test -n "$T" && grep -qx "  total_plans: $((T+1))" .planning/STATE.md && O=$(printf '%s\n' "$ST" | sed -n 's/^Plan: [0-9]* of \([0-9]*\)$/\1/p') && test -n "$O" && grep -Eq "^Plan: [0-9]+ of $((O+1))$" .planning/STATE.md && RM=$(git show origin/main:.planning/ROADMAP.md) && R=$(printf '%s\n' "$RM" | grep -m1 -oE '[0-9]+/[0-9]+ plans executed in [0-9]+ waves') && M=$(printf '%s' "$R" | sed -E 's#^[0-9]+/([0-9]+) .*#\1#') && V=$(printf '%s' "$R" | sed -E 's#.* in ([0-9]+) waves#\1#') && grep -Eq "[0-9]+/$((M+1)) plans executed in $((V+1)) waves" .planning/ROADMAP.md && grep -c '03-08j-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit: a publish edit is missing or wrong. Each of these is checked against origin/main's value + 1: the waves of 03-09 to 03-16, 03-09's dependency and its new precondition clause, STATE's total_plans and `of M`, the ROADMAP Plans line's total and wave count, and the ROADMAP row</fails_when>
    <automated>RM=$(git show origin/main:.planning/ROADMAP.md) && X=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md) && W9=$(printf '%s\n' "$X" | sed -n 's/^wave: //p') && test -n "$W9" && N0=$(printf '%s\n' "$RM" | awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}') && N1=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}' .planning/ROADMAP.md) && test "$N1" -eq "$((N0+1))" && awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; n++; if (w!=n) bad=1; if (w>1 && index($0,"*(blocked on Wave " (w-1) " completion)*")==0) bad=1} END{exit bad}' .planning/ROADMAP.md && J=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-08j-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$J" | grep -q "^\*\*Wave $W9\*\*" && K=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-09-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K" | grep -q "^\*\*Wave $((W9+1))\*\*"</automated>
    <fails_when>non-zero exit: any of these fails in Phase 3 of the ROADMAP:
      - the wave headers number one more than on origin/main;
      - they run 1..N in order;
      - every block N above 1 says "blocked on Wave N-1 completion";
      - the 03-08j row sits under the wave origin/main's 03-09 had, and the 03-09 row one wave later.
    </fails_when>
    <automated>git fetch origin p03/08j-agent-spool-window && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08j-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08j-agent-spool-window --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new or rewritten runbook sentence names at least one CI test or says UNVERIFIED on a real host.
    - The SUMMARY records internal/agent/apply's and internal/agent/spool's CI times under -race; above about 400 s a time is a recorded deviation that was fixed before the PR.
    - The commit messages, the PR title and body, the SUMMARY, the runbook text and the todo are read once before the push. They use neutral hardening wording, name findings only as PR #76 review F8 and F01 (03-08e), and hold no IP address or real host name.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0, and `B=$(scripts/gh-as-bot.sh pr view p03/08j-agent-spool-window --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08j-SUMMARY.md is on its head. The PR title and every commit message use neutral wording, and name the stuck window as PR #76 review F8.
  </acceptance_criteria>
  <done>The runbooks say how a host reads past a version it cannot apply, what the unapplied alert means, how to roll it out, how to clear a recorded version a signer restore lost, and that the prune follows the record. The todo records the smaller window as a remaining item. The PR waits green, without auto-merge, with the plan and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 6: Merge gate — owner approves PR p03/08j-agent-spool-window, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. Open `gh pr view p03/08j-agent-spool-window --web`. Review:
       - state.VerifyAhead with the unapplied record;
       - verify's in-force bundle step, recordUnapplied's merge, and finishCommit's removal;
       - WriteAccepted's cursor;
       - the heartbeat field;
       - spool.Read's recapture.

       Read 03-08j-SUMMARY.md. Check especially three things:
       - nothing from the unapplied record is installed except as the newest verified state, and the KRL-alone pass stays on accepted/;
       - no capture is verified from accepted/ while a record exists, the record is never lowered, and a policy-rotation catch-up still holds at the bundle in force;
       - the server is updated before the agents.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved". After a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08j-agent-spool-window` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08j-agent-spool-window</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which the next plan's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08j-agent-spool-window --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The unapplied record, the fetcher's cursor, the unapplied status and Read's recapture are on main, and 03-08k may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08d** (merged, a70c661) and **03-08e** (merged, 9ac9c12) are this plan's base.
  - It builds on 03-08d's forward order (readCurrent, candidate, krlAlone once per capture), state.KRLAlone, RenderFallback without a directory, Render's account cap and the ErrGenerationTooLarge refusal.
  - It edits apply.go, resetdir.go and status.go after 03-08d's fix round. Every TestKRLAlone, TestResetDirectory and TestStatus case stays green unchanged.
  - It builds on 03-08e's spool.Cap and readCapped (Task 4), its pruneSpool and keepAbove, which it leaves unchanged and which then count from the raised accepted.json (Task 2), and parseApply's defaults (the runbook's `apply --once`). Task 2 changes only cursor()'s doc comment in fetch.go. 03-08e's TestFetch, TestSpoolPrune, TestSpool, TestAdopt and TestApplyFlags stay green unchanged.
  - 03-08e's T-03-299 keeps its text in 03-08e-PLAN.md, which this plan does not edit. Its ENOENT residual is closed by T-03-321 here; its bound of about 5.6 GiB stays; the spool-pruning todo records how it could shrink (Task 5).
- **The read floors, deferred (owner, 2026-11-02).** The smaller prune window is technical debt, not scheduled. Task 5's todo item records it. If it is picked up, it builds on this plan's loadUnapplied, WriteAccepted's raise and Read's recapture, and it rewrites the runbook sentence that opens "While the record existed".
- **03-08k** follows. It keeps TestSpoolWindow green, apart from changes its own plan names.
- **The todo 2026-10-28-agent-spool-pruning.** 03-08e's prune closed its pruning; Task 5 adds the read-floors idea as a remaining item, and one sentence to its Status. The record holds its own copies, so a prune that removed the record's versions would only make the fetcher ask again; Task 2's raise keeps them.
- **03-10** owns `last_apply.detail` for its probe outcomes. `unapplied` is a separate field, and 03-10 leaves it in buildStatus.
- **Any later plan that edits forward, finishCommit, WriteAccepted, ResetDirectory or Verify** keeps TestSpoolWindow green. It also keeps verify(p, chain, alone, in)'s split: the chain for the steps, accepted/ for the KRL-alone pass. **Any later plan that changes what accepted.json names** keeps the raise to the record's base, which the cursor and the prune follow.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: the fetcher is honest.** A compromised fetcher can plant or withhold spool files (T-03-225, accepted). It cannot redirect the record's chain, which starts at the record's own copies.

**Edges:**
- adjacency: `window_control_within_reach` (refused at 64, inside the window) versus `refused_window_newest_then_fix_applies` (refused at 65, the window's newest);
- two refused windows in a row: `refused_run_longer_than_a_window_reaches_fix`;
- nothing newer than the record: `unchanged_spool_still_refused`, `recorded_state_installed_when_the_host_accepts_it`;
- a policy rotation below the recorded bundle, with and without a new ops key: `policy_rotation_below_the_recorded_bundle`, `held_content_refusal_keeps_the_records_bundle`;
- fork and rollback relative to the record: `fork_after_the_record_refused`, `bundle_fork_after_the_record_takes_the_krl_against_accepted`, `withheld_record_version_does_not_roll_back`;
- old, damaged or removed state: `damaged_record_dropped`, `removed_record_reads_from_accepted`, `record_write_failure_keeps_the_krl`;
- the record's negative cases:
  - a fork after it;
  - a spool copy that differs from it;
  - a KRL only the recorded bundle signs;
  - a Verify refusal and a dry run.
- a capture racing the prune, once and twice: `TestReadRecapture`.
- not tested here: 03-08e's prune counted from the raised accepted.json, with a record more than 1024 above accepted/ (reasoned in Planner decisions).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access changes take effect across the fleet without risking lockout | Tasks 1-3 |
| REQ | AGENT-04 (principals follow the newest directory the host can apply) | Tasks 1, 2 |
| REQ | AGENT-07 (heartbeats report the applied state) | Task 3 |
| Review | PR #76 review F8: a host whose window-newest version is refused never reaches a fixed version; report the state fleet-wide | Tasks 1-3, 5 |
| CONTEXT | D-20: runbooks in the same PR, labelled run or UNVERIFIED | Task 5 |
| Owner decision | D-R2, D-2, Q1, the plan order, delivery | Owner decisions block |
| Plan check 1 | Items 2, 3, 8, 9, 10, 11, 12, 14, 15 | Ledger, Round 1 |
| Carried from PR #77 | The prune must follow the record | Task 2 (accepted.json's raise, which 03-08e's prune counts from); Planner decisions (no interim rule needed) |
| Owner decision after PR #77 | The read floors, the union prune, the 64 window, the regression probe | Split out (W3), then deferred as technical debt (owner, 2026-11-02); Task 5's todo item |
| Carried from PR #77 (low) | The ENOENT race: spool.Read recaptures once | Task 4, `TestReadRecapture` |
| Revision brief | Reconcile tasks, paths, names, lines and preconditions with main at 9ac9c12 | Revision note, Reconciliation, Task 1's precondition, read_first lists |
| Plan check 4 | W3 split; j's interim prune | Revision note, Planner decisions, Ledger Round 5 |
| Deferred | faster walks; recording during a widening wait | Ledger, with reasons |

## Artifacts this phase produces (this plan)

- state: `verify` (chain and alone), `Unapplied`, `ParseUnapplied`, `Base`, `VerifyAhead`, `UnappliedFile`, `ErrUnapplied`.
- apply:
  - `loadUnapplied`, `recordUnapplied` (merging), finishCommit's removal of a passed record, Report.Unapplied;
  - WriteAccepted's cursor and ResetDirectory's record step.
- spool: Read's one recapture (readOnce, readSpool).
- heartbeat: Status.Unapplied and its Validate rule.
- CLI: keyroster host status's `unapplied` alert and note.
- Tests:
  - twenty-two TestSpoolWindow cases;
  - TestValidate's `unapplied` row;
  - TestHostStatusUnapplied;
  - TestReadRecapture.
- Docs:
  - host-setup.md: the far-behind paragraph rewritten, the `unapplied` alert with its rollout, and two sentences after the fetcher paragraph;
  - signer-install.md: the host selection names the record, with the remedy for a recorded version a restore lost.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| spool (fetcher-writable) → applier | Every spool byte is untrusted until Verify checks it. The unapplied record is written only by the applier, from a state Verify accepted, into the root-owned state directory |
| agent heartbeat → server → CLI | The status is the host's report. `unapplied` is informational and validated as non-empty only |
| applier (root) → outbox → fetcher (unprivileged) | accepted.json is written only by root, into the outbox (root:keyroster-agent 2750, 0640), atomically, and now names the record's versions where they are higher. It only steers what the fetcher asks for and keeps; the server stores none of it, and the applier never reads it back |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-316 | Denial of service | a verified window-newest version the host cannot apply (generation_too_large, ca_line_rejected) freezing its directory or bundle for good, so grants later directories removed stay in force (PR #76 review F8) | low | mitigate | forward records the refused verified state, and the next capture reads and chains from it. verify keeps the bundle in force as a hold step, so a policy-rotation catch-up still progresses. The fetcher's cursor follows the record. The host status and keyroster host status show `unapplied`. Tests: `refused_window_newest_then_fix_applies`, `refused_run_longer_than_a_window_reaches_fix`, `bundle_ca_line_window_newest_then_fixed_bundle_applies`, `policy_rotation_below_the_recorded_bundle` (both rows), `held_content_refusal_keeps_the_records_bundle`, `fetcher_cursor_follows_the_record`, `status_reports_unapplied`, `TestHostStatusUnapplied`. **Residual:** the walk moves about 64 versions per retry, and lengths beyond 130 versions are UNVERIFIED. A directory signed only under a policy strictly between the bundle in force and the recorded bundle is refused on every apply (UNVERIFIED, accepted by the owner). KRLs signed by the in-force ops key still land, and `unapplied` shows. Clearing it takes a hand action: root removes unapplied.json, or reset-directory succeeds (the newest directory then verifies standalone). A later commit passing the record is not a realistic way out, because the refused capture only ever makes KRL-alone commits |
| T-03-317 | Tampering / Elevation of privilege | the record, or a capture read from it, used to install a state that was not fully verified, to land a KRL the bundle in force did not authorise, or to accept a forked chain | high | mitigate | Only a state Verify accepted with Refused nil is recorded, as copies in the root-owned state directory (never as hashes of spool files). Nothing from the record is rendered except as a later capture's newest verified state, and the versions between are chain-checked and never rendered. The base carries accepted/'s KRL. The KRL-alone pass, and every Verify refusal of a capture read from the record, use accepted/. The spool's newest copy at or below the record is read (pick's `below`) but never chained from or rendered: the chain starts at the record's own bytes, and a chain not built on them is refused. No capture is verified from accepted/ while a record exists, and recordUnapplied never lowers a part. A damaged or removed record only returns the host to main's behaviour, and finishCommit removes a record once a commit passes it. While the record existed, 03-08e's prune counted from it (Task 2's raise), so a removed or dropped record can meet a chain gap below it: directory_chain_gap or bundle_chain_gap is reported, the KRL lands alone, nothing else is installed, and the next poll fetches the versions again (UNVERIFIED with a real prune). The raise itself lags only if WriteAccepted fails on 16 or more applies in a row while the record keeps climbing: the record can then pass the stale accepted.json + 1024 and be pruned, which gives a false bundle_older or directory_older until a write succeeds. That needs a persistent outbox write failure on the root side, and each failure is logged at warning level (UNVERIFIED). Tests: `krl_only_the_recorded_bundle_signs_waits`, `fork_after_the_record_refused`, `bundle_fork_after_the_record_takes_the_krl_against_accepted`, `withheld_record_version_does_not_roll_back`, `held_content_refusal_keeps_the_records_bundle`, `spool_copy_of_the_recorded_version_ignored`, `unchanged_spool_still_refused`, `damaged_record_dropped`, `removed_record_reads_from_accepted`, `no_record_after_a_verify_refusal_or_a_dry_run`, and the mutants of Tasks 1 and 2 |
| T-03-321 | Denial of service | spool.Read against a concurrent prune: a name the listing returned is unlinked before its open (an orphaned policy, or an older KRL once a newer one completes), so the whole capture fails with ENOENT and the apply retries about 5 s later (03-08e's known residual) | low | mitigate | Read captures once more from a fresh listing when an error wraps unix.ENOENT; a second one fails the capture as before. The retry is bounded at one, so a fetcher that keeps unlinking cannot make the applier loop, and the second capture is a whole new listing, never a mix of two. Tests: `TestReadRecapture/listed_name_gone_is_recaptured_once`, `gone_again_fails_the_capture`. **Residual:** two races in a row still fail one apply, as on main; no test races a real capture against a real prune (UNVERIFIED) |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; capslock baseline unchanged (a new pair is a recorded deviation) |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh), the full gate passes, the PR's required checks are green, and the merge gate passes.
</verification>

<success_criteria>
- A host whose window-newest version it cannot apply reaches the next version it can apply without reset-directory. Nothing it did not fully verify as the newest state is installed, and the record's fork and rollback evidence always holds. A policy-rotation catch-up still holds at the bundle in force, and its status shows the recorded versions fleet-wide.
- An apply that races the prune captures once more instead of failing.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08j-SUMMARY.md` in Task 5, before the merge gate. `requirements-completed` is empty: AGENT-07 is complete since earlier plans, AGENT-04 stays pending, and this plan hardens both. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources

- PR #76 review F8, the stuck spool window (low), with owner decisions D-2 and Q1 (Daniel, 2026-10-30).
- The design reviews of 03-08e's revision of 2026-10-30, whose stuck-window tasks this plan takes over. Their outcomes:
  - copies, not hashes, in the record;
  - finishCommit removes a passed record;
  - no loader error stops an apply;
  - the cursor's server-side safety checked;
  - the CLI's lenient decoding checked;
  - the bundle test's fallback.

### Round 1 — plan check 1 (2026-11-01, PASS WITH FIXES), with the owner's decisions of 2026-11-01

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Item 2: a recorded bundle cuts holdBundle off from the policies below it and wedges the policy-rotation catch-up | MAJOR | Round 1: a retry from accepted/; replaced in round 2 (below) by the in-force bundle as a hold step |
| Item 3: `unchanged_spool_still_refused` asserted NoOp false, against `refusal_without_newer_krl_is_noop` | MAJOR | The NoOp clause is dropped; the case asserts the error, last_apply.result refused, the KRL and the record; truth 3 says "never ok" |
| Item 8: a recorded bundle a signer restore lost had no remedy | MINOR | signer-install.md's remove-the-record remedy; `removed_record_reads_from_accepted` |
| Item 9: the rollout covered upgrade only | MINOR | The Alerts bullet gains the old-server (status_stale) and no-rollback sentences; Task 3's reversibility |
| Item 10: ParseUnapplied's caps named three of six fields; MaxUnapplied's sum; Base(nil) | MINOR | Task 1 names each field's cap, gives the 5.1 MiB raw / 6.8 MiB base64 sum and specifies Base(nil accepted) = (nil, nil) |
| Item 11: `spool_copy_of_the_recorded_version_ignored` passes from the floor alone | MINOR | Its mutant is listed in Task 2 (rephrased in round 2, item 5). The item's premise, that Read never reads the spool's copy at the floor, was wrong; see round 3, item 1 |
| Item 12: test cost and the 10-minute timeout | WARNING | The budget uses CI's 164 s with 263 s local beside it; only each window's newest version is above the caps; the -run filters are anchored; Task 4 treats more than about 400 s as a deviation |
| Item 13: size | WARNING | Owner decision 2026-11-01: one task moved out of this plan; four auto tasks remain |
| Item 14: the reconciliation's claim about 03-08e's files | MINOR | Reconciliation 4 is corrected; Task 1's precondition checks two strings 03-08e-PLAN.md names as its artifacts (`func Cap(`, `func parseApply(`) |
| Item 15: Task 4's publish check missed most edits | MINOR | Task 4's third check computes every value from origin/main + 1 |
| Items 1, 4-7 | n/a | They concern the task that moved out of this plan (owner decision 2026-11-01) |

### Round 2 — plan check 2 (2026-11-01, FAIL: four MAJORs in round 1's retry)

The retry is removed. While a record exists, the record is the only chain base. verify offers the bundle in force as the lowest hold step, and recordUnapplied merges per kind (Planner decisions, truths 4 and 5).

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Item 1: the retry bypassed the record's fork and rollback evidence | MAJOR | No capture is verified from accepted/ while a record exists. `fork_after_the_record_refused` (re-made 65' and 66') and `withheld_record_version_does_not_roll_back` (65 withheld, a bad 66; 64 never installed) pin both shapes. The second-capture mutant dies on `fork_after_the_record_refused` once its spool holds a renderable 65' (round 3, item 1), not on the latter. Truth 6, T-03-317 and both runbooks hold as written |
| Item 2: a retry result could rewrite or narrow the record | MAJOR | recordUnapplied merges per kind and never lowers a part (truth 5); `held_content_refusal_keeps_the_records_bundle`, with the replace-instead-of-merge mutant |
| Item 3: the retry never ran when the KRL-alone pass errored, which wedged the newOps=true shape | MAJOR | There is no retry. holdBundle holds at the bundle in force inside VerifyAhead, so the new-key KRL waits under BundleHeld exactly as on main. `policy_rotation_below_the_recorded_bundle` is table-driven over newOps |
| Item 4: `fork_after_the_record_refused` could not pass; the chain-instead-of-alone mutant survived | MAJOR | The fork case now asserts what the design does. `bundle_fork_after_the_record_takes_the_krl_against_accepted` uses VerifyAhead's own KRL-alone result with a recorded bundle that would render, so the mutant would commit bundle 2 into accepted/ |
| Item 5: the spool-copy mutant could not be built | MINOR | Rephrased: Base or loadUnapplied reading the recorded version's file from the spool (spool.ReadFileAt) instead of the record's bytes. The capture does hold the spool's copy (round 3, item 1), so a second spool-copy mutant is listed too |
| Item 6: the signer-install remedy had no test | MINOR | `removed_record_takes_the_remade_bundle_chain` runs it; the actual restore stays UNVERIFIED |
| Item 7: the publish check did not look at the ROADMAP's wave blocks | MINOR | Task 4's fourth check: the header count is origin + 1, numbered 1..N; every "blocked on Wave N-1" clause; and the 03-08j and 03-09 rows each under its wave |

### Round 3 — plan check 3 (2026-11-01, PASS WITH FIXES)

With a floor, spool.Read also takes the newest version at or below it (pick's `below`, spool.go), so a capture read from the record holds the spool's copy at the record's version, or the next lower one. verify never chains from that copy: it chains from the base. The design is unchanged; the fact corrects which shapes a mutant reaches.

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Item 1: the second-capture mutant was attributed to a case that cannot kill it, and no case built the shape in which a second capture installs a fork | MINOR | `fork_after_the_record_refused` also puts a re-made, renderable 65' (only role:ops) at the spool's 65. It asserts directory_not_verified, principals and accepted/ at directory 1, BundleHeld false and a record of exactly {Directory: 65}. The second-capture mutant is attributed to it (it would install 65'). `withheld_record_version_does_not_roll_back` stays a regression case, GREEN at once. Truth 6 and T-03-317 now say that the spool's copy at or below the record is read and never chained from. `spool_copy_of_the_recorded_version_ignored` stands alone and also kills a verifyDirectory that chains from the capture's copy at the base's version |
| Item 2: Task 4's signer-install.md grep named a test its label no longer lists | MINOR | It greps for `removed_record_takes_the_remade_bundle_chain`, and host-setup.md is also grepped for `policy_rotation_below_the_recorded_bundle` |
| Item 3: the residual was stated inconsistently, and a commit passing the record is no realistic way out | MINOR | Truth 4, T-03-316, host-setup.md and the owner decisions state the same residual, UNVERIFIED: strictly between, refused on every apply, KRLs from the in-force key land, `unapplied` shows, and clearing it takes a hand action (root removes unapplied.json, or reset-directory succeeds). The runbook gives `sudo rm /var/lib/keyroster-agent/unapplied.json` for a host whose last error is directory_not_verified with an unapplied bundle |
| Item 4: three cases stated no RED or GREEN expectation, and one gave the wrong reason | MINOR | `spool_copy_of_the_recorded_version_ignored` is GREEN at once. `bundle_fork_after_the_record_takes_the_krl_against_accepted` and `removed_record_takes_the_remade_bundle_chain` are RED on Task 1's head, which records no bundle part. `held_content_refusal_keeps_the_records_bundle` is RED on Task 1's head for the same reason, and also against a replacing write |
| Item 5: ResetDirectory's record step ran after accepted/'s directory was dropped, with no named writer | WARNING | It is step 0: after the lock and the pending-marker check, and before anything changes. It writes through e.writeState (WriteFileAt, 0600) and removes through e.remove (paths.Allowed). A record that parses but cannot be rewritten or removed fails the reset with nothing changed. `reset_directory_drops_the_records_directory` first runs a reset that stops after step 1, and the earlier placement is a named mutant |
| Item 6: "chain's bundle differs from alone's" was undefined | WARNING | Defined as chain.BundleVersion above alone.BundleVersion. BundleHeld false is asserted as a guard in `refused_window_newest_then_fix_applies` and `fork_after_the_record_refused` |
| Item 10: check references sat inline in task text | INFO | Task 2's recordUnapplied heading and action, and two planner-decision lines, no longer cite a check; the references are in this ledger only |
| Items 7-9 | INFO | No change needed |

### Round 4 — revision after PR #77 (2026-11-01)

Task numbers in Rounds 1-3 are the plan's numbering then: their "Task 4" is today's Task 5, and their "Task 5" today's Task 6.

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| The plan predated pruneSpool, spool.Keep and parseApply's defaults; its anchors, precondition and reconciliation named a70c661 | MINOR | Revision note; Reconciliation 1, 4, 5 and 7 against 9ac9c12; Task 1's precondition checks `func Keep(`, `func pruneSpool(` and `keepAbove`; Task 1's spool read_first names pickAbove |
| The prune must follow the record: counted from accepted/ alone, it can delete what the applier reads from a record more than 1024 above accepted | MAJOR | Task 2's raise makes accepted.json name the record, so 03-08e's prune keeps from it (truth 7, Planner decisions) |
| Owner decision: the read floors, the union prune, the 64 window and the regression probe | MAJOR | Planned here first as Tasks 4-5; split out in Round 5, deferred on 2026-11-02 |
| The ENOENT race (low) | MINOR | spool.Read recaptures once (Task 4, T-03-321, TestReadRecapture) |

### Round 5 — plan check 4 (2026-11-01, PASS WITH FIXES), with the owner's decisions of the same day

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| W3: six auto tasks, 1.55x the budget | WARNING | Owner decision: split. The read floors, the union prune, the 64 window, the fetch limit (W1), the recheck (W2) and WriteAccepted's move under the lock were split out; the owner deferred them on 2026-11-02. This plan keeps the record, VerifyAhead, the status and Read's recapture: five auto tasks, about 115k tokens |
| j's interim prune: 03-08e's Keep(accepted.json, 1024) with a record above accepted | MINOR | Safe without an interim rule, because accepted.json names the record (Planner decisions). The cost, a chain gap after a removed record, is stated in truth 6, T-03-317 and the runbook |
| W1, W2, W4, W5, I1, I3, I4 and the probe | n/a | Went with the floors; deferred |
| The WriteAccepted move | INFO | Correct and needed, but only for the pending floor; it went with the floors |
| The R4 warning on Task 2's comment-only check | INFO | A false positive of the plan-criteria scanner: git runs inside a command substitution, and `&&` stops on its failure. Left as it is |

### Round 6 — plan check 5 (2026-11-02, PASS WITH FIXES), with the owner's decision of the same day

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| W-j1: five auto tasks and about 115k tokens | WARNING | Owner decision: keep as is, with the recapture here (Owner decisions, Budget) |
| I-j1: the raise lags if WriteAccepted fails on 16 or more applies in a row | INFO | Stated in truth 7 and T-03-317, UNVERIFIED |
| I-j2: the plan-order line of 2026-11-01 still has 03-08k at wave 16 | INFO | Left as the record of that decision; the current order is in Owner decisions |
| The read floors deferred (owner, 2026-11-02) | n/a | Forward claims removed; the prune stays 03-08e's from the raised accepted.json; Task 5 adds the todo item |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| Faster walks (catch-up continuing after a recorded refusal) | The run loop is unchanged: one window per DefaultRetry, sooner when new versions arrive. Speeding it up changes the run loop's error handling for no correctness gain |
| Recording during a widening wait (pollSpool) | The next forward after the wait's commit records a refused state if one remains |

