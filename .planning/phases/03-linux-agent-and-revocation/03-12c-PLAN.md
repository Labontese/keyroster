---
phase: 03-linux-agent-and-revocation
plan: 12c
type: execute
wave: 34
depends_on: ["03-12b"]
files_modified:
  - internal/trust/bundle.go
  - internal/trust/castate.go
  - internal/trust/bundle_test.go
  - internal/trust/castate_test.go
  - internal/trust/verify.go
  - internal/trust/vectors_test.go
  - internal/trust/fuzz_test.go
  - test/vectors/bundle_rotation_v1.json
  - internal/rootceremony/summary.go
  - internal/rootceremony/summary_test.go
  - cmd/keyroster/testdata/ceremony/
  - internal/agent/apply/render.go
  - internal/agent/apply/apply.go
  - internal/agent/apply/run.go
  - internal/agent/apply/drift.go
  - internal/agent/apply/hostcert.go
  - internal/agent/apply/probe.go
  - internal/agent/apply/adopt.go
  - internal/agent/apply/latch.go
  - internal/agent/apply/status.go
  - internal/agent/apply/render_test.go
  - internal/agent/apply/run_test.go
  - internal/agent/apply/latch_test.go
  - internal/agent/apply/drift_test.go
  - internal/agent/apply/hostcert_test.go
  - internal/agent/apply/probe_test.go
  - internal/agent/apply/status_test.go
  - internal/agent/apply/adopt_test.go
  - internal/agent/paths/paths.go
  - internal/agent/paths/paths_test.go
  - internal/agent/probe/probe.go
  - internal/agent/probe/probe_test.go
  - internal/agent/heartbeat/heartbeat.go
  - internal/agent/heartbeat/heartbeat_test.go
  - cmd/keyroster-agent/check.go
  - internal/doctor/doctor.go
  - internal/doctor/doctor_test.go
  - cmd/keyroster-signer/doctor.go
  - cmd/keyroster-signer/doctor_test.go
  - docs/runbooks/host-setup.md
  - .planning/phases/03-linux-agent-and-revocation/03-12c-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [KEY-08]

estimate:
  tokens: 238000
  raw_tokens: 238000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Early plan: scope, owner decisions and tests are fixed here; the tasks are planned out in full, and every path and line anchor reconciled against main, after 03-12b merges. Until then this file is a specification, not an executable plan"
    - "The bundle format learns the state `draining` and the field `trusted_until` (last field of CAEntry, omitempty, so every existing bundle keeps its exact bytes). `draining` requires a trusted_until in trust.TimeFormat and every other state forbids it; exactly one active and at most one next per role, any number of draining entries; a genesis bundle never carries `draining`. No successor can create one in this plan, so nothing drops in production"
    - "One rule decides who is trusted at a time t: `CAEntry.TrustedAt(t)` (active and next always; draining while t is before trusted_until; retired never). Agents, the answer sets and adoption read it; the bytes of an agent's `user_ca_keys` come from one portable function, `trust.UserCAKeysFile(b, t)`, which writes plain key lines only"
    - "An agent drops a draining CA by itself at trusted_until on its own clock, as a narrowing change through apply.Apply (swap.go unchanged), and never takes it back: a permanent per-key drop latch survives a backward clock step, a rollback and a state reset"
    - "An agent reports `bundle_behind` when the ops-signed KRL manifest names a newer bundle than the one it accepted, after a 2-hour grace; it is detection, not enforcement"
  artifacts:
    - path: "internal/agent/apply/latch.go"
      provides: "the drop latch file trust-dropped.json"
    - path: "internal/trust/castate.go"
      provides: "TrustedAt, TrustedCAs, UserCAKeysFile"
    - path: "test/vectors/bundle_rotation_v1.json"
      provides: "a bundle with one entry in each state"
  key_links:
    - from: "internal/agent/apply/render.go"
      to: "internal/trust/castate.go"
      via: "renderTrust writes trust.UserCAKeysFile(b, now) minus the latch"
      pattern: "UserCAKeysFile"
---

<objective>
The readers of D-14 (KEY-08): bundles can carry a `draining` CA with an end date, and every agent trusts it until that date and then drops it by itself, without another bundle and without ever taking it back; the agent also notices when the server withholds a bundle.

Purpose: 03-12e will make the switch produce `draining` entries. Every reader must already handle them, so the switch can ship with all its fences and nothing breaks in the fleet. Until 03-12e, `draining` is unreachable: the chain rule has no switch and a genesis bundle refuses it, so the drop is proved here on hand-built bundles and the SUMMARY labels its end-to-end proof as 03-12e's.

Output: the format and helpers in internal/trust; Summary's `trusted_until`; the time-aware agent (render with a clock, the latch, the no-op path, the timer, the answer sets, adoption); `bundle_behind`; `keyroster-agent check`'s listing; the rotation vector; the upgrade-order text in the host runbook.
</objective>

## Before execution (read this first)

This is an early plan, written with 03-12 and its siblings against kr-main at d15f044 and published in 03-12's PR. It is planned out in full by `/gsd-plan-phase`, and reconciled against main, after 03-12b merges: every path, line anchor, count, test name and threat ID is re-read there. The scope, owner decisions and the test and mutant lists below are fixed; the tasks, commands and RED routes are not. Do not execute this file as it stands.

At the reconcile, check in particular: the anchors of the agent files (forward's no-op at internal/agent/apply/apply.go:934, Run's trigger at run.go:232-237, the check closure at run.go:195-212, renderTrust at render.go:280, the answer checks at hostcert/hostcert.go:699 and probe/probe.go:504, PairUsable at probe.go:562, ParseHeartbeat at heartbeat.go:499-505); that 03-12b's castate.go is where this plan adds its helpers; and that the heartbeat field is added optional.

## Scope

**In.**
- **internal/trust.** `CAEntry` gains `TrustedUntil string json:"trusted_until,omitempty"` as its last field (the precedent is InstallationID, bundle.go:68-75); caStates gains `draining`; Validate: draining requires trusted_until (checkTimestamp, trust.TimeFormat), every other state forbids it, exactly one active and at most one next per role, any number of draining entries, entries ordered by role then increasing generation; VerifyGenesisBundle refuses a bundle with a `draining` entry permanently (a genesis has no previous key to drain). Helpers in castate.go (portable, so the linux-only agent and the cross-platform CLI share them): `(e CAEntry) TrustedAt(t time.Time) bool`, `TrustedCAs(b, role, t)` by generation, and `UserCAKeysFile(b, t) []byte`: the exact bytes of an agent's `user_ca_keys`, user role then machine role, in TrustedCAs order, each line trust.FormatKey plus a newline, plain key lines only (no options, no comments: one line sshd cannot parse hides every CA after it, and TrustedUserCAKeys takes no options). Every older parser refuses `draining` and `trusted_until` (DecodeStrict), a bundle with only `next` or `retired` entries parses on every build.
- **internal/rootceremony.** Summary prints `trusted_until` on draining entries; the Bundle reflect gate then requires it; a summary golden for draining; goldens change by additions only.
- **The vector** test/vectors/bundle_rotation_v1.json: the user role with one entry in each state plus a second draining entry whose trusted_until is past, from fixed keys; FuzzParseBundle seeds it.
- **Agent render** (internal/agent/apply): `Render(v, hostKeys, now)`, `RenderFallback(..., now)` and `renderTrust(v, now)` take the engine's clock (apply.go:52-77); renderTrust writes `trust.UserCAKeysFile(b, now)` minus every key in the latch.
- **The drop latch** `trust-dropped.json`: when a commit removes a draining key from user_ca_keys the agent records its fingerprint and trusted_until, written and fsynced in the commit's sequence (mode 0600) and read at start; render never emits a latched key; it is never pruned (every drained key stays `draining` in every later bundle, so the latch grows by one entry per rotation per role); it joins CheckStateDirs, paths.Allowed (internal/agent/paths/paths.go) and the status `refusals` list; an unreadable latch renders no draining key at all (fail-closed).
- **The no-op path and the timer:** forward's no-op (`!v.Changed() && v.DirectoryUnauthorized == nil && !held`) is skipped only for a pending narrowing, that is, when the current CA file holds a line that `UserCAKeysFile(accepted, now)` minus the latch no longer holds; a trusted line the current file lacks (a `next` line the probe gate holds) is not a trigger, so it stays on the widening path with its back-off and quiet logging. The dropped line goes through apply.Apply as a narrowing change; swap.go is unchanged; the DirectoryUnauthorized branch and 03-08d's KRL-alone rules stay. The report gains `TrustDue time.Time`: the earliest trusted_until of the accepted bundle after now; Run applies when `!Clock.Now().Before(trustDue)`, like hostDue and probeDue. Check reports a result `trust_expired` only for the pending-narrowing condition and that sets forceApply, so an operator's `--recover-to-last-good` after trusted_until heals within one check period and a held addition is never re-triggered.
- **The answer sets and adoption:** hostcert.go:403, probe.go:402 and probe PairUsable (probe.go:562) take `trust.TrustedCAs(b, role, now)`; a kept host certificate of the old host CA stays usable until it is due (renewal is lazy across a rotation); a probe pair of the old machine CA expires before the drop by the install binding (a test, not an eager-renewal rule); adopt.go's isActiveUserCA becomes "a user CA in TrustedCAs(b, user, now)", so a Phase 2 host updated by hand to `next`, or still on `draining`, is adoptable.
- **`bundle_behind`:** the agent compares the newest verified KRL manifest's `bundle_version` (krl/manifest.go:56, read at apply/status.go:261) with its accepted bundle version; when the manifest is ahead for longer than 2 hours (one KRL republish period, the fetch poll and the applier retry), the status carries `bundle_behind` {manifest_bundle_version, accepted_version, since, reason}; `since` is the first accepted manifest that named the newer version, kept in the agent state; `reason` names a held or unapplied bundle, a bundle this build refused (an older build refusing `draining` is the upgrade gate's case) or "not delivered". `keyroster-agent check` prints it and lists each draining key with its trusted_until, and `drained (ended <t>)` when past. The heartbeat field is optional (`omitempty`), after the precedent of Unapplied (heartbeat.go:178): the server's ParseHeartbeat is strict, so **the server must be upgraded before the agents**, and the runbook says so.
- **doctor's `trusted_until` display** (carried from 03-12, whose doctor shows generation and state but cannot show a field that does not exist yet): `GenerationFact` (internal/doctor) gains `TrustedUntil string`, and the `generations` OK line names it for a draining generation (`draining g<N> until <t>`); cmd/keyroster-signer/doctor.go fills it from the installed bundle's CA entry with the same key; a prepared, active or retired generation shows none.
- **The runbook** host-setup.md: the upgrade order before ceremony 2 (signer and server first, then agents, then CLIs; old agents fail closed, they keep the previous bundle, so the current CA stays active and `next` stays trusted) and what `trust_expired` and `bundle_behind` mean.

**Out.** The switch transition and every `trusted_until` rule of the chain (03-12e), the CLI readers (03-12d), the drain binding (03-12e).

## Owner decisions that bind this plan (Daniel, 2026-11-13 and 2026-11-14)

- Agents drop the old CA on their own clock and never take it back: the latch is permanent (no routine retire exists, so a drained key stays `draining` forever).
- The withheld switch (a host that never receives the switch bundle keeps the old key active with no end) is reclassified from availability to a detected freeze: `bundle_behind` from the ops-signed KRL manifest after a grace period of 2 hours; detection, not enforcement. The lease options and a pre-distributed expiry were not chosen.
- `trusted_until` is immutable (unchanged entries are byte-identical), and there is no draining-to-retired transition.
- A stopped agent narrows nothing; this residual is stated.
- Hardware is optional; every test uses software keys.

## Tests (fixed here)

- **trust:** TestTrustedAt (active and next true; retired false; draining true at trusted_until minus 1 s and minus 1 ns, false at trusted_until); TestUserCAKeysFile (golden bytes; user then machine; by generation; draining dropped at the boundary; `plain_lines_only`); edge cases `single_active_bundle_unchanged` (bundle_genesis_v1 parses, signs, installs and verifies with its bytes unchanged), `entries_ordered_role_generation`, `draining_without_trusted_until_refused`, `trusted_until_on_active_refused`, `genesis_with_draining_refused`, `many_draining_entries_ok`; the vector test and FuzzParseBundle's seed.
- **agents (linux):** drop and timing: `draining_dropped_unchanged_capture` (no spool change; the clock passes trusted_until; the next Apply drops the line as a narrowing swap), `trust_due_triggers_apply` (Run with a fake clock), `held_next_line_does_not_retrigger` (a probe-held next line raises no trust_expired, sets no forceApply and keeps its back-off), `drop_with_directory_unauthorized`, `drop_survives_rollback` (RollbackKeeping), `recover_to_last_good_then_drop_again`; the latch: `clock_step_back_keeps_drop`, `forward_jump_spares_later_rotation`, `latch_unreadable_fails_closed`, `latch_never_pruned` (two rotations, both latched keys stay); answer sets and adoption: `hostcert_answer_retired_ca_refused`, `probe_pair_retired_ca_unusable`, `pair_usable_drained_ca_refused`, `probe_pair_expires_before_drop`, `adopt_next_user_ca_ok`; rendering: `render_plain_lines_only` (a golden); bundle_behind: `withheld_switch_bundle_behind_reported` (the agent holds vN, manifests name vN+1 for longer than the grace: `bundle_behind` is set and the old key stays in user_ca_keys, documenting the residual), `behind_within_grace_quiet`, `behind_reason_unapplied`, `krl_stale_and_behind`; heartbeat: `bundle_behind_optional_roundtrip` (strict parse; absent when false).
- **doctor:** TestDoctorGenerations gains `draining_shows_trusted_until` and `other_states_show_none` (internal/doctor/doctor_test.go), and cmd/keyroster-signer/doctor_test.go gains TestDoctorDrainingTrustedUntil (a hand-built bundle with a draining entry: the `OK generations` line prints its trusted_until).
- **Keep green:** 03-08d's TestKRLAlone, TestRenderable and TestDirectoryUnderPolicyInForce; TestCeremonyGolden, TestPolicyFieldsCovered, TestSummaryFieldsCovered; TestStatusWriters; the 03-14c audit tests.

## Mutants (M135 to M148)

- M135 TrustedAt uses `<=` (the boundary test); M136 TrustedAt treats draining as trusted without its deadline; M137 render ignores now (`draining_dropped_unchanged_capture`); M138 forward's no-op ignores the pending narrowing (the same test with no spool change); M139 the trigger also fires for a missing trusted line (`held_next_line_does_not_retrigger`); M140 Run ignores TrustDue (`trust_due_triggers_apply`); M141 the drop latch is not applied (`clock_step_back_keeps_drop`); M142 the latch is matched by trusted_until instead of by key (`forward_jump_spares_later_rotation`); M143 the latch is pruned (`latch_never_pruned`); M144 PairUsable ignores trusted_until (`pair_usable_drained_ca_refused`); M145 the renderer emits an option prefix or a comment (`render_plain_lines_only`); M146 bundle_behind ignores the manifest's bundle_version (`withheld_switch_bundle_behind_reported`); M147 bundle_behind ignores the grace period (`behind_within_grace_quiet`); M148 adopt keeps "active only" (`adopt_next_user_ca_ok`).

## Inherited duties (from 03-14b, 03-14c, 03-14d), which this plan carries

- Summary prints the new field, the Bundle reflect gate requires it, and the goldens change by additions only; the file lists include the ceremony testdata and summary tests; the pointer duties of 03-14b to 03-14d are carried into every plan that changes trust.Bundle.
- Shared trust helpers stay portable; any helper used only on linux carries a build tag, or the Windows lint fails.
- Mutants continue from M135; threat IDs are the set's; the Q-09-3 test-time form, with apply's own base recorded (internal/agent/apply ran 611 to 694 s under load at d15f044, so about 200 to 290 s below the timeout before this plan's new tests); the private-term and label scan; the stop guard and ROADMAP gate.

## Why it ships safely alone

`draining` is unreachable in production: the chain rule has no switch transition and a genesis bundle refuses it. So nothing drops, and the drop is unit-tested on hand-built bundles; the SUMMARY labels its end-to-end proof as 03-12e's. `bundle_behind` is detection only. The heartbeat field is optional and the release text orders the server first.

## Size

47 files by the set's counting convention (37 code and test, 2 vector and golden, 1 doc, 7 planning), the four doctor files carried from 03-12 included; one more if `since` is kept in internal/agent/state. About 238k estimated tokens raw (low confidence); the calibration has run 2x to 5x, and this plan is near 03-14c in size, which took four sessions.

## Open owner questions

None open.

<tasks>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 1: Plan 03-12c out in full and reconcile it against main. Do not execute this file</name>
  <read_first>
    - The "Before execution" section above, and 03-12b-SUMMARY.md (the predecessor's SUMMARY, on main once it has merged)
  </read_first>
  <action>This is an early plan: a specification published in 03-12's PR so that the wave shift happens once. It carries no executable tasks. After 03-12b has merged, run the planner for it (`/gsd-plan-phase` on this plan's phase and number), which re-reads every path, line anchor, file count, test name and threat ID against main, writes the tasks with their verify commands and RED routes, and replaces this file. Do not run `/gsd-execute-phase` on this file as it stands.</action>
  <instructions>
    1. Confirm that 03-12b's SUMMARY is on origin/main.
    2. Plan this plan out in full, reconciled against main, and have it checked.
    3. Reply "planned" when the executable plan has replaced this file.
  </instructions>
  <verify>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-12b-SUMMARY.md</automated>
    <fails_when>non-zero exit: the predecessor has not merged, so this plan must not be planned out or executed yet</fails_when>
  </verify>
  <acceptance_criteria>
    - The executable plan has replaced this file, its tasks name every verify command, and its reconcile ledger records what differed from this specification at its base commit.
  </acceptance_criteria>
  <done>03-12c is planned out in full against main.</done>
  <resume-signal>Type "planned" after the executable plan has replaced this file</resume-signal>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| server → agent | the bundle and KRL manifest the server serves; a withheld bundle must be noticed |
| the host clock → the CA set | the drop is decided on the host's own clock and must not be undone by a clock step |

## STRIDE Threat Register

Each ID below is defined only in this plan; the other IDs of the set are defined in the plan named in 03-12's register.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-81 | Spoofing, then elevation of privilege | a server withholds the switch bundle (the freeze): a host keeps the old CA active with no end, and anyone holding the old key or socket keeps logging in there | high | mitigate (detection) | `bundle_behind` from the ops-signed KRL manifest after a grace period; the host-side proof after trusted_until (03-12e's runbook); key removal (03-12e) shrinks who can use the old key; `krl_stale` at 24 h when KRLs are withheld too. Residual: detection, not enforcement; no lease |
| T-03-414 | Elevation of privilege | a backward clock step re-grants a dropped CA | medium | mitigate | a permanent per-key drop latch, fail-closed when unreadable; RollbackKeeping; `trust_expired` for pending narrowings. Residual: consumers without a latch (the CLI, login, machine renew, the answer sets after a state reset) trust a drained CA again while their clock is set back; 03-13's emergency retire is the hard stop |
| T-03-418 | Denial of service | a mixed-version fleet refuses the ceremony-2 bundle | medium | mitigate | the upgrade order in the runbook (signer and server, then agents, then CLIs); old agents fail closed; the agent version in `host status` (03-12d) |
| T-03-429 | Denial of service | a user_ca_keys line sshd cannot parse hides every later CA | medium | mitigate | UserCAKeysFile writes plain key lines only, pinned by a golden |
| T-03-SC | Tampering | dependencies | low | mitigate | no module added |
</threat_model>

<success_criteria>
- A hand-built bundle with a `draining` entry is rendered with that CA until trusted_until and without it afterwards, by the agent's own clock, with no further bundle; a clock step back, a rollback and a state reset never bring it back.
- The agent's answer checks and adoption use the same trust rule; `bundle_behind` shows a withheld bundle after the grace period.
- Every Phase 1 and 2 bundle keeps its bytes.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-12c-SUMMARY.md` when the plan has been planned out and executed. Leave `requirements-completed` empty: KEY-08 completes in 03-13.
</output>
