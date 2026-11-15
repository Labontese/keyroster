---
phase: 03-linux-agent-and-revocation
plan: 12b
type: execute
wave: 33
depends_on: ["03-12"]
files_modified:
  - internal/trust/verify.go
  - internal/trust/castate.go
  - internal/trust/castate_test.go
  - internal/trust/rotation_test.go
  - internal/trust/fuzz_test.go
  - internal/trust/successor.go
  - internal/trust/successor_test.go
  - internal/signer/trust.go
  - internal/signer/trust_test.go
  - internal/audit/verify_test.go
  - internal/rootceremony/cachanges.go
  - internal/rootceremony/cachanges_test.go
  - internal/rootceremony/summary_test.go
  - cmd/keyroster/root.go
  - cmd/keyroster/root_test.go
  - cmd/keyroster/trust.go
  - cmd/keyroster/ceremony_golden_test.go
  - cmd/keyroster/runbook_test.go
  - cmd/keyroster/canext.go
  - cmd/keyroster/canext_test.go
  - cmd/keyroster/testdata/ceremony/
  - internal/agent/apply/hostcert.go
  - internal/agent/apply/probe.go
  - internal/agent/apply/hostcert_test.go
  - internal/agent/apply/probe_test.go
  - test/e2e/ca_rotation_test.go
  - .github/workflows/e2e.yml
  - .github/rulesets/main-integrity.json
  - docs/runbooks/ca-rotation.md
  - docs/runbooks/root-ceremony.md
  - docs/runbooks/ceremony-transcript-template.md
  - CONTRIBUTING.md
  - .planning/phases/03-linux-agent-and-revocation/03-12b-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [KEY-08]

estimate:
  tokens: 227000
  raw_tokens: 227000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Early plan: scope, owner decisions and tests are fixed here; the tasks are planned out in full, and every path, line anchor and count reconciled against main, after 03-12 merges. Until then this file is a specification, not an executable plan"
    - "Ceremony 1 of D-14: `keyroster-signer ca-rotate prepare` (03-12) makes generation g+1; a root-signed successor built with `keyroster root sign --prev DIR --ca-next ROLE=FILE --ca-next-fingerprint ROLE=SHA256:...` lists it as `next`; every host trusts it beside the active CA; and a `next` key that turns out wrong or compromised is withdrawn by `--ca-retire ROLE:GEN` (abort), which every host applies as a narrowing change"
    - "The chain rule gets its first CA rule: per role and per successor, entries are unchanged, or exactly one `next` entry is added, or one `next` entry becomes `retired`; anything else is ErrVersionChain naming the role and generation. No entry is ever removed, no state moves back, no key, algorithm, custody or generation changes, and no key moves between roles. The signer, every agent and audit enforce it; the CLI does not run the chain rule"
    - "An aborted key stops being accepted everywhere in this plan: the agent's host-certificate answer check and probe answer check take the active-or-next set instead of every key the role ever had"
    - "Nothing a host reads changes format: `next` and `retired` parse on every build, and `draining` does not exist yet"
  artifacts:
    - path: "internal/trust/castate.go"
      provides: "checkCATransitions (unchanged, add next, abort), ActiveCA and IssuingCAs"
    - path: "cmd/keyroster/canext.go"
      provides: "the reader of the prepare file for root sign --ca-next"
    - path: "internal/rootceremony/cachanges.go"
      provides: "the CA-change section printed by root sign and trust verify"
    - path: "docs/runbooks/ca-rotation.md"
      provides: "prepare, ceremony 1 and abort"
    - path: "test/e2e/ca_rotation_test.go"
      provides: "TestCANextAndAbort in the new rotation lane"
  key_links:
    - from: "internal/trust/verify.go"
      to: "internal/trust/castate.go"
      via: "checkSuccessorChain calls checkCATransitions after the policy parse"
      pattern: "checkCATransitions"
    - from: "internal/agent/apply/hostcert.go"
      to: "internal/trust/castate.go"
      via: "the host-certificate answer check takes trust.IssuingCAs, not every key of the role"
      pattern: "IssuingCAs"
---

<objective>
Ceremony 1 and abort of D-14 (KEY-08): an admin can add a prepared CA key as `next`, so every host trusts it beside the active one, and can withdraw it again, with the chain rule, the ceremony tool, the summaries, the agents' answer checks, the runbook and an end-to-end test that proves it.

Purpose: 03-12 ships generations and refuses to let a successor change a CA entry. This plan lets one change in exactly two ways, add `next` and abort, behind a rule that the signer, every agent and audit enforce, and withdraws an aborted key from every consumer at once. It changes no format and no host behaviour for a bundle without a `next` entry.

Output: the CA rule in the shared chain check; `root sign --ca-next --ca-next-fingerprint --ca-retire`; the CA-change section and the `Root set:` line in `root sign --prev` and `trust verify --prev`; the Bundle reflect gate; the agents' active-or-next answer sets; `docs/runbooks/ca-rotation.md`; the new required lane `e2e-rotation` with TestCANextAndAbort.
</objective>

## Before execution (read this first)

This plan is an early plan. It was written together with 03-12 and its four siblings, against kr-main at d15f044, and published in 03-12's PR so that the wave shift happens once. It is planned out in full by `/gsd-plan-phase`, and reconciled against main, after 03-12 merges: every path, line anchor, file count, test name and threat ID below is re-read there. The scope, the owner decisions and the test and mutant lists below are fixed; the task breakdown, the commands and the RED routes are not. Do not execute this file as it stands.

At that reconcile, check in particular: that 03-12's SUMMARY is on main with its R and T commits; that `keystore.KeyFor`, `signer.CheckRotationBackend`, the prepare file's pinned bytes and the marker gate are as 03-12 left them; that the wave and ROADMAP numbers still match (waves 33 to 41, `33/42` after 03-12); that the e2e main lanes still have the headroom the lane decision assumed (750 to 804 s against 900 s at d15f044); and that no other plan slotted into waves 33 to 37.

## Scope

**In.**
- **The chain rule** (internal/trust/castate.go, called from checkSuccessorChain after the policy parse): per role and per successor, at most one change:
  - unchanged: every entry of the role byte-identical (role, key, alg, custody, state, generation);
  - add `next`: exactly one new entry in state `next`, whose generation is above every generation of the role in the previous bundle, whose key equals no key of the previous bundle (any role, any state), and for a role that has no `next` there;
  - abort: a `next` entry becomes `retired`, and nothing else of the role changes.
  - Refused with ErrVersionChain naming the role and generation: an entry removed, a state moving back (retired to next, active to next), a changed key, algorithm, custody or generation, a key moving between roles, an abort of an active entry, two changes for one role. The aborted key never signed, because audit requires the active key at every issue kind.
- **Helpers** in internal/trust, portable: `ActiveCA(b, role)` and `IssuingCAs(b, role)` (active or next, by generation).
- **The signer's acceptance widens in lockstep**: checkBundleKeys additionally accepts `next` entries that equal a stored generation and `retired` entries; the active entry stays the stored generation it was; `draining` is still refused (the case becomes `draining_refused_until_switch`). internal/signer/trust.go is in this plan's file list because the rule lives there; an earlier count of the file lists omitted it.
- **The ceremony tool:** `--ca-next ROLE=FILE` (the file is 03-12's prepare output), `--ca-next-fingerprint ROLE=SHA256:...` (mandatory with `--ca-next`; a mismatch with the file's key refuses `ca_next_fingerprint_mismatch` before anything is signed), `--ca-retire ROLE:GEN` (a `next` entry only), each repeatable and at most one transition per role; `--ca-pubkeys` with `--prev` is refused with "--ca-pubkeys is for a genesis bundle; a successor changes CA entries only with --ca-next, --ca-switch and --ca-retire" (it replaces the "Phase 3" text at cmd/keyroster/root.go:409); BuildSuccessor takes a `SuccessorOptions` struct (roots, threshold, policy, issued_at, installation ID, CA changes), so 03-13 and 03-14 add fields instead of re-cutting the signature; a TestRootSignSuccessor case combines `--installation-id new` with `--ca-next`, as 03-15's v4 ceremony does.
- **The CA-change section** `rootceremony.CAChanges(prev, next)`: printed by root sign right after successorHeader and its stderr warning and before Summary (root.go:549-554), and by trust verify right after its own successor line (cmd/keyroster/trust.go:185) and before Summary; one line per changed entry, `CA <role> gen <N> <fingerprint>: <old state> -> <new state>`, otherwise `CA entries: unchanged`; no line may begin with `  webauthn`, `  pop`, `  timelock `, `installation id: `, `Policy in force:` or `signed by `, so every checkInvariants rule holds. A `Root set: unchanged` or `Root set: CHANGED (added N, removed M)` line goes in both commands, with one more checkInvariants rule (exactly one).
- **The Bundle reflect gate:** Summary's output, with the `Bundle SHA-256:` line removed, must change for every exported field of trust.Bundle and its nested types; one named exception, InstallationID, which points at installationLine (root.go:688) and 03-14c. Goldens change by additions only, visible in the diff; every existing golden gains `CA entries: unchanged` and the `Root set:` line. The ceremony tests' file lists widen to cmd/keyroster/testdata/ceremony/, ceremony_golden_test.go, internal/rootceremony/summary_test.go with its testdata and cmd/keyroster/runbook_test.go.
- **The agents' answer sets:** internal/agent/apply/hostcert.go:403 and apply/probe.go:402 take `trust.IssuingCAs(b, role)` instead of krl.RoleCAKeys, which returns every state, so an aborted key is refused by the host-certificate answer check and the probe answer check in this plan. The other consumers already ignore `retired`.
- **The runbook:** the new docs/runbooks/ca-rotation.md (when to rotate, prepare, ceremony 1, abort, the second-person check of the fingerprint, the install, the widening wait of about the LoginGraceTime bound plus 30 s, what to check on hosts), the checklist and an entry in successorSigningSections for each ceremony section (TestRootCeremonyPolicyChecks), root-ceremony.md's CA-change confirmation, and a transcript-template row "next CA fingerprint as read from the signer console by <name>". It never tells a user to re-run `keyroster init` (a rotation changes no root and no installation ID, so every CLI pin survives).
- **The e2e lane:** a new required job `e2e-rotation (9.5p1)` and `(10.5p1)` with its own build tag, `-timeout 20m` and a PASS-line check like e2e-probe, its two names in .github/rulesets/main-integrity.json, and CONTRIBUTING.md's table (28 to 30 checks). The job does not gate until the owner runs scripts/apply-rulesets.sh, which the PR states. TestCANextAndAbort: prepare with the agent backend, ceremony 1, install, the agent's live user_ca_keys gains the new line after the widening wait, abort, the line leaves at once; a generation-1 certificate logs in throughout; `audit verify --installation-id` closes the run. About 60 to 90 s (UNVERIFIED until run); the main lane has no room for it (750 to 804 s against 900 s).

**Out.** The switch and `draining` (03-12e), `trusted_until` and every time-aware reader (03-12c), the CLI readers (03-12d), key removal and the drain binding (03-12e), TPM and PIV (03-12f), log and ops keys and the emergency move (03-13).

## Owner decisions that bind this plan (Daniel, 2026-11-13 and 2026-11-14)

- The set is six plans; this is the second, at wave 33.
- Entries are never removed: every CA entry stays in every later bundle, so the chain rule sees every generation and key a role ever had without a history field.
- The rotation e2e runs in a new required job (the lane above); CONTRIBUTING goes from 28 to 30 checks; the owner runs scripts/apply-rulesets.sh.
- `--ca-next-fingerprint` is mandatory. This plan carries the pointer to 03-15: its v4 command (03-15-PLAN.md:187) and its rehearsal (:157) gain `--ca-next-fingerprint user=$KR_NEXT_CA_FP`, typed from the value read on the signer console, and its T-03-261 row (:330) names it. 03-15's numstat expectations change in that PR.
- The `Root set:` line is added with the CA-change section.
- There is no routine retire: `retired` means a deliberate end (an aborted `next` here, the emergency move in 03-13).
- Security levels: software through HSM, hardware never required; every test uses software keys or an in-process agent.

## Tests (fixed here)

- **trust:** TestCATransitions: `add_next_ok`, `add_second_next_refused`, `next_generation_not_above_prev_refused`, `next_key_equal_retired_key_refused`, `next_key_equal_other_role_key_refused`, `abort_next_ok`, `abort_active_refused`, `retired_back_to_next_refused`, `entry_removed_refused`, `custody_changed_refused`, `two_transitions_one_role_refused`, `installation_id_new_with_next_ok`. FuzzCATransitions: two CA lists built from fuzz bytes are checked against a small reference model of the rule above by enumeration, and an accepted `next` must Validate.
- **signer:** TestCheckBundleKeysGenerations additions `next_stored_accepted`, `next_not_stored_refused`, `retired_accepted` and `draining_refused_until_switch`, which replace 03-12's `non_active_entry_refused` (its assertion, that a `next` entry is refused, is the opposite of this plan's rule, so the case is deleted) while `active_not_generation_1_refused` and `generation_field_mismatch_refused` stay (M111, defined in 03-12 as the comparison of an entry's generation field with the stored generation 1, keeps its one killer `generation_field_mismatch_refused`; for a `next` entry the field is compared with the stored generation of the entry's key); TestInstallNextBundle (the signer accepts generation 1 active plus generation 2 next, and the abort bundle; it refuses a `next` entry that is not a stored generation and an admin equal to a `next` key); TestSignerRestartMixedBundle with generation 2 installed as `next`; TestSuccessorForeignCAKeyRefused now asserts the chain rule's ErrVersionChain first and keeps a direct checkBundleKeys case.
- **audit:** `issue_by_next_refused` (only the active key signs) and `abort_key_never_signed`. 03-12's `active_not_logged_refused_when_ca_init_precedes` stays a refusal but is then the chain rule's, because VerifySuccessor refuses a change of an unchanged entry before 03-12's active rule is reached; M184's killer from then on is 03-12's `genesis_active_not_ca_init_refused`, whose genesis bundle has no predecessor and so still reaches that rule.
- **agents (linux):** `hostcert_answer_aborted_ca_refused` and `probe_pair_aborted_ca_refused`.
- **CLI:** TestRootSignSuccessor (existing) gains the CA-flag cases, `ca_pubkeys_with_prev_refused` with the new text, `ca_next_fingerprint_mismatch_refused` and `installation_id_new_with_ca_next`; TestCeremonyGolden (existing) gains the next and abort goldens for root sign and trust verify (four files), with every existing golden changing by additions only; TestBundleReflectGate (new, internal/rootceremony/summary_test.go) with the InstallationID exception; TestRootCeremonyPolicyChecks covers the ca-rotation.md ceremony sections; FuzzParseCANextFile (strict JSON, the key parses, the role is known, generation at least 2).
- **e2e:** TestCANextAndAbort in the `e2e-rotation` lane.
- **Keep green:** the set's keep-green list: TestVerifyInstallationBinding, TestVerifyLeafTimeBound, TestVerifyBoundValues, TestVerifyForgetKeysOnOtherKinds, TestExportKeysLowercase, TestCeremonyGolden, TestPolicyFieldsCovered, TestSummaryFieldsCovered, TestRootCeremonyPolicyChecks, TestSignedRequestsBindInstallation, TestIssueRequestSigningVector, TestCAIssueInstallation, TestInstallationPinned, TestStatusWriters.

## Mutants (M123 to M134; each killed by a named subtest)

- M123 checkCATransitions accepts a next generation equal to the previous maximum (`next_generation_not_above_prev_refused`).
- M124 it accepts a next key equal to a retired key of the previous bundle (`next_key_equal_retired_key_refused`).
- M125 it accepts a removed entry (`entry_removed_refused`).
- M126 it accepts the abort of an active entry (`abort_active_refused`).
- M127 it accepts two transitions for one role (`two_transitions_one_role_refused`).
- M128 `--ca-next-fingerprint` is not compared (`ca_next_fingerprint_mismatch_refused`).
- M129 root sign permits `--ca-pubkeys` with `--prev` (`ca_pubkeys_with_prev_refused`).
- M130 the host-certificate answer set stays krl.RoleCAKeys (`hostcert_answer_aborted_ca_refused`).
- M131 the probe answer set stays krl.RoleCAKeys (`probe_pair_aborted_ca_refused`).
- M132 trust verify omits the CA-change section (the trust-verify next golden in TestCeremonyGolden).
- M133 the Bundle reflect gate exempts a field other than InstallationID (TestBundleReflectGate).
- M134 checkBundleKeys accepts a `next` entry that is not a stored generation (`next_not_stored_refused`, TestInstallNextBundle).

## Inherited duties (from 03-14b, 03-14c, 03-14d), which this plan carries

- Render the new states in both ceremony commands, with the carried and absent cases ("CA entries: unchanged"); add the Bundle reflect gate with its one named exception; give each new ca-rotation.md ceremony section the 03-14b checklist and an entry in successorSigningSections; change the goldens by additions only; widen the file lists (above); keep the policy block the last thing before the prompt in root sign and the block between `Bundle SHA-256:` and the first `signer` line in trust verify.
- The CA-change section sits before `Bundle SHA-256:` so the installation-line invariant holds; the successor-path foreign-key test now asserts the chain rule.
- Every `keyroster audit verify` in the new runbook passes `--installation-id` or `--any-installation`; any new audit.Options literal in cmd/ sets Now.
- The e2e `ca issue` calls pass `--installation-id` set to the bundle's ID (the goroutine's call in 03-12e; here the sites are grepped, test/systemd/smoke.sh included, and recorded); a new `keyroster/` literal or signed type is classified (none is expected: the prepare file is untagged).
- Mutants continue from M123; threat IDs are the set's; the Q-09-3 test-time form (`-timeout 15m`, a delta of at most 90 s over a quiet base at most 24 h old); the private-term and label scan before each publish commit; the stop guard and the whole-file ROADMAP gate; shared helpers portable, the agent and any linux-only helper tagged.

## Why it ships safely alone

There is no format change: `next` and `retired` parse on every build. A `next` key is trusted and unused. Abort withdraws it from every host's user_ca_keys and from the agent's answer sets in the same plan. The chain rule closes the hole that at d15f044 any root-signed successor could change a CA entry as far as the chain check was concerned, with only the signer's checkBundleKeys in the way. The new lane proves next and abort end to end.

## Size

42 files by the set's counting convention (7 planning files per plan: its own plan file, ROADMAP, STATE and 03-13 to 03-16): 27 code and test files, 4 goldens, 4 docs, 7 planning. This plan expects to change 4 planning files (its own plan, 03-15's three pointer lines, ROADMAP, STATE). About 227k estimated tokens raw (low confidence); the calibration has run 2x to 5x. The new lane may need its own runtime headroom check.

## Open owner questions

None open. A new decision found at the reconcile goes here with options, the recommended default first, and edge cases.

<tasks>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 1: Plan 03-12b out in full and reconcile it against main. Do not execute this file</name>
  <read_first>
    - The "Before execution" section above, and 03-12-SUMMARY.md (the predecessor's SUMMARY, on main once it has merged)
  </read_first>
  <action>This is an early plan: a specification published in 03-12's PR so that the wave shift happens once. It carries no executable tasks. After 03-12 has merged, run the planner for it (`/gsd-plan-phase` on this plan's phase and number), which re-reads every path, line anchor, file count, test name and threat ID against main, writes the tasks with their verify commands and RED routes, and replaces this file. Do not run `/gsd-execute-phase` on this file as it stands.</action>
  <instructions>
    1. Confirm that 03-12's SUMMARY is on origin/main.
    2. Plan this plan out in full, reconciled against main, and have it checked.
    3. Reply "planned" when the executable plan has replaced this file.
  </instructions>
  <verify>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-12-SUMMARY.md</automated>
    <fails_when>non-zero exit: the predecessor has not merged, so this plan must not be planned out or executed yet</fails_when>
  </verify>
  <acceptance_criteria>
    - The executable plan has replaced this file, its tasks name every verify command, and its reconcile ledger records what differed from this specification at its base commit.
  </acceptance_criteria>
  <done>03-12b is planned out in full against main.</done>
  <resume-signal>Type "planned" after the executable plan has replaced this file</resume-signal>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| offline roots → bundle CA entries | only root-signed successors change which CA keys hosts and clients trust |
| signer operator → the ceremony | the prepared file and its fingerprint cross from the signer host to the offline machine |

## STRIDE Threat Register

Each ID below is defined only in this plan; the other IDs of the set are defined in the plan named in 03-12's register.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-78 | Elevation of privilege | a successor sneaking in or changing a CA entry | critical | mitigate | checkCATransitions in the shared chain rule, enforced by the signer, every agent and audit; the CLI runs no chain rule, but through a correct server it receives only bundles the signer installed; the CA-change section and the second person's fingerprint check. 03-12e adds the switch to the same rule |
| T-03-79 | Tampering | a reused generation, a key moved between roles, a removed history or a changed trusted_until | medium | mitigate | no removal; a generation above every previous one; a key equal to no previous key; unchanged entries byte-identical (trusted_until included once 03-12c adds it) |
| T-03-415 | Elevation of privilege | a compromised or mistyped next key cannot be withdrawn | high | mitigate | abort is a narrowing change on every host that applies it, and the agent's answer sets refuse the key in the same plan |
| T-03-421 | Elevation of privilege | agent answer sets accept an aborted, retired or drained CA | medium | mitigate | IssuingCAs here (active or next); the time-aware TrustedCAs, PairUsable included, in 03-12c |
| T-03-SC | Tampering | dependencies | low | mitigate | no module added; no package-manager install |

(T-03-419, defined in 03-12, has its ceremony-side mitigation here: the mandatory `--ca-next-fingerprint`, compared with the prepare file's key before anything is signed (`ca_next_fingerprint_mismatch_refused`, M128), so that a key planted at prepare is caught by the second person's reading of the fingerprint from the signer console.)
</threat_model>

<success_criteria>
- A `next` CA key can be added by one root ceremony and is then trusted beside the active key by every host; an abort removes it from every host and from every answer check.
- The chain rule refuses every other CA change; the ceremony tool shows each change and the root set to the signers.
- No host, client or format outside a bundle with a `next` entry changes behaviour.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-12b-SUMMARY.md` when the plan has been planned out and executed. Leave `requirements-completed` empty: KEY-08 completes in 03-13.
</output>
