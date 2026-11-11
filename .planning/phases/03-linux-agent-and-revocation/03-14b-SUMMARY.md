---
phase: 03-linux-agent-and-revocation
plan: 14b
subsystem: root ceremony display (policy block, pop line, runbook checks)
tags: [root, ceremony, policy, pop, runbooks, goldens, hardening]
status: complete
requirements-completed: []
key-files:
  created: [cmd/keyroster/policydiff.go, cmd/keyroster/policydiff_test.go, cmd/keyroster/ceremony_golden_test.go, internal/rootceremony/summary_test.go, cmd/keyroster/testdata/ceremony (10 goldens), internal/rootceremony/testdata/summary (3 goldens)]
  modified: [internal/rootceremony/summary.go, cmd/keyroster/root.go, cmd/keyroster/trust.go, cmd/keyroster/runbook_test.go, test/e2e/audit_login_test.go, docs/runbooks/root-ceremony.md, docs/runbooks/ceremony-transcript-template.md, docs/runbooks/host-setup.md, docs/runbooks/machine-identities.md]
decisions:
  - "The policy block is an unexported helper in package main (policydiff.go); the pop line lives in rootceremony.Summary with its signature unchanged"
  - "The block's base is only loadPrev's prevPolicy, printed after BuildSuccessor or VerifySuccessor bound it to the pinned bundle"
  - "A fixed WARNING line, no new flag, for changes root successor-policy never writes (Q-B1)"
actuals:
  tasks: 3
  commits: 7
plan_head_before: b4e6b4c1c4d04427b4476b7c3a60721fa6a329e8
plan_head_after: 5d5f14e379bc21abf2fe818b1ef713450dd7fbe4
---

# Phase 3 Plan 14b: show what a root signs (F04, F14) Summary

A custodian who signs or verifies a successor now sees the policy in force, every policy field the successor changes (with a WARNING when it changes admin_quorum, admins, ca_profiles or timelock_seconds, the fields root successor-policy never writes), and the PoP switches in every ceremony summary, pinned by goldens committed failing first, reflect gates, single-field cases and runbook checks.

Written from Task 1 on and completed in Task 3. Task 4 (the owner's merge) is open. `commits` counts the plan's commits before this SUMMARY's final docs commit.

test-time base: cmd=232.981 rootceremony=25.149 at=1794353255

Re-measured in place in Task 3 (the continuation is another session; Budget, "Another session"), on a detached worktree of origin/main b4e6b4c outside the repository, with no other heavy job running; the worktree was removed. Both packages read `ok`. Task 1's first measurement read cmd=248.675 rootceremony=26.123 and is replaced by this line.

## Handover

Task 1 ran in the first session, which stopped at the planned handover point. The continuation ran Tasks 2 and 3 and stops at Task 4, the owner's merge gate (blocking-human). The orchestrator's pre-merge review (Task 3 step 5) is recorded under Pre-merge review.

## Task 1: the policy block, the pop line and the goldens

- **R1** `21106b1`: `test(root): pin the ceremony display before the fix (F04, F14)`. It holds ceremony_golden_test.go, summary_test.go and the 13 goldens, with production code unchanged.
- **T1** `9e0e753`: `fix(root): show the policy in force, each changed field and the PoP switches before a root signs (F04, F14)`. It changes summary.go, policydiff.go (new), root.go and trust.go only.
- **The goldens.** The baseline was written from today's output with `-update-golden`. The contract's literal lines were then inserted by a script that holds the contract's text, with fingerprints and successor SHA-256s read from each golden's own summary lines. This is an insert, not a regeneration. GREEN on T1 needed no golden correction.
- **Additions only** (`diff baseline golden` shows no removed line):
  - genesis_pop.root_sign: additions only (2 lines)
  - genesis_pop.trust_verify: additions only (2)
  - successor_added_admin.root_sign: additions only (17)
  - successor_added_admin.trust_verify: additions only (17)
  - successor_every_field.root_sign: additions only (25)
  - successor_pop.root_sign: additions only (13)
  - successor_pop.trust_verify: additions only (13)
  - successor_rp_only.root_sign: additions only (13)
  - successor_unchanged.root_sign: additions only (3)
  - successor_unchanged.trust_verify: additions only (3)
  - genesis: additions only (1)
  - pop_hosts_machines: additions only (2)
  - pop_machines_only: additions only (1)
- **The RED, from a detached worktree of R1** (Task 1's second verify command, exit 0):
  - `--- FAIL:` on all 11 TestCeremonyGolden leaves: successor_unchanged/root_sign, successor_unchanged/trust_verify, successor_rp_only/root_sign, successor_added_admin/root_sign, successor_added_admin/cosigner, successor_added_admin/trust_verify, successor_every_field/root_sign, successor_pop/root_sign, successor_pop/trust_verify, genesis_pop/root_sign and genesis_pop/trust_verify.
  - `--- FAIL:` on TestSummaryGolden/genesis, /pop_hosts_machines and /pop_machines_only.
  - TestSummaryFieldsCovered failed exactly Policy.PoP, PoPPolicy.Hosts and PoPPolicy.Machines; its other 15 subtests passed.
  - A `golden <name>.golden: first difference at line <n>` message for each of the 13 goldens: genesis 21, genesis_pop.root_sign 21, genesis_pop.trust_verify 21, pop_hosts_machines 21, pop_machines_only 21, successor_added_admin.root_sign 27, successor_added_admin.trust_verify 23, successor_every_field.root_sign 28, successor_pop.root_sign 26, successor_pop.trust_verify 22, successor_rp_only.root_sign 26, successor_unchanged.root_sign 26 and successor_unchanged.trust_verify 22.
  - No build or setup failure.
- **GREEN (after T1).** Task 1's first verify command exits 0. Its output has no FAIL and no DATA RACE, and every listed PASS line is present. The whole-package runs read cmd/keyroster 235.954 s, internal/rootceremony 25.436 s and internal/trust 2.201 s.
- **Other Task 1 checks.**
  - The golden-correction bound (third verify command) passes.
  - The scope check (fifth verify command) passes: T1's diff stays in cmd/keyroster, internal/rootceremony and .planning, and no verifier package or imports_test.go changed.
  - The acceptance greps (p.PoP in Summary; policyChange( in runRootSign and in verifySuccessorBundle) pass.
- **No drift.** Regenerating every golden from T1 with `-update-golden` changed no committed golden and added no untracked one.
- **Existing assertions.** None moved. TestRootSignSuccessor, TestTrustVerifySuccessor, TestRootSignTrustVerifyRoundTrip, TestRootSuccessorPolicyPoP, TestRootSignAccumulates, TestSummaryShowsWebAuthnRP, TestSignBundleAndPolicy and TestExportedAPI pass unchanged, as do all other tests of cmd/keyroster, internal/rootceremony and internal/trust, including those 03-09 to 03-11b added.
- **Reasoned, not run.** policyChange's error return at its two call sites, in runRootSign (wrapped with `; nothing was signed`) and in verifySuccessorBundle, cannot run: both documents parsed before the block is built.

### Task 1 mutants (local numbers 1-18)

Every mutant met the mutant rule:
- the unmutated command passed;
- `go vet` of the mutated package exited 0;
- the mutated command printed every listed `--- FAIL:` line, with no `[build failed]`, `[setup failed]` or timeout;
- the file was restored byte for byte (`git diff --exit-code` clean).

C is ./cmd/keyroster/ and R is ./internal/rootceremony/. "The successor root_sign leaves" are the six root_sign and cosigner leaves of the successor groups.

1. Summary's pop branch removed. R: TestSummaryGolden/genesis, /pop_hosts_machines and /pop_machines_only, and TestSummaryFieldsCovered/Policy.PoP, /PoPPolicy.Hosts and /PoPPolicy.Machines. C: all 11 TestCeremonyGolden leaves. Killed.
2. Summary's one-way note removed. R: TestSummaryGolden/pop_hosts_machines. C: genesis_pop/root_sign, genesis_pop/trust_verify, successor_pop/root_sign, successor_pop/trust_verify and successor_every_field/root_sign. Killed.
3. The one-way note printed also when only machines is set. R: TestSummaryGolden/pop_machines_only. Killed.
4. Summary's timelock line removed. R: TestSummaryFieldsCovered/Policy.TimelockSeconds, and all 3 TestSummaryGolden cases. C: all 11 leaves. Killed.
5. Summary's pop line moved after the timelock line. C: all 11 leaves, each with an `invariant:` line (the pop line outside the webauthn-to-timelock window). R: all 3 TestSummaryGolden cases. Killed.
6. runRootSign's block write removed, with the call kept and its result discarded. C: the 6 successor root_sign leaves. Killed.
7. runRootSign's block written before the summary. C: the 6 successor root_sign leaves, each with an `invariant:` line (the block does not follow the installation line, and summary lines follow its start). Killed.
8. verifySuccessorBundle's block write removed, with the result discarded. C: successor_unchanged/trust_verify, successor_added_admin/trust_verify and successor_pop/trust_verify. Killed.
9. The block's base taken from the successor itself (`_ = prevPolicy`, `policyChange(policy, policy)`). C: successor_rp_only/root_sign, successor_added_admin/root_sign and /cosigner, successor_every_field/root_sign and successor_pop/root_sign. Killed.
10. The admins comparison removed. C: successor_added_admin/root_sign, /cosigner and /trust_verify, and successor_every_field/root_sign. Killed.
11. The `+ admin` line dropped. C: the same four leaves. Killed.
12. The `max_ttl_seconds` sub-line dropped. C: the same four leaves. Killed.
13. The webauthn one-way marker dropped. C: successor_rp_only/root_sign and the four leaves of mutant 10. Killed.
14. The pop comparison removed. C: successor_pop/root_sign, successor_pop/trust_verify and successor_every_field/root_sign. Killed.
15. The diff's pop.hosts one-way line dropped. C: the same three leaves. Killed.
16. The unchanged form replaced by the changed form. C: successor_unchanged/root_sign and /trust_verify. Killed.
17. The warning line dropped. C: the four leaves of mutant 10. Killed.
18. The warning line printed for any CHANGED field. C: successor_rp_only/root_sign, successor_pop/root_sign and successor_pop/trust_verify. Killed.

## Task 2: the durable gates

- **T2** `10bf58f`: `test(root): gate every policy field, the warning rule and the base of the policy block (F04)`. It adds cmd/keyroster/policydiff_test.go and the real-binary pin in test/e2e/audit_login_test.go. No production code and no golden changed; no contract fix was needed.
- **Every case passed** (Task 2's first verify command, exit 0, no FAIL and no DATA RACE):
  - TestPolicyFieldsCovered.
  - TestPolicyChangeFields, all 17: Policy.AdminQuorum, Policy.Admins, AdminKey.Name, AdminKey.Key, CAProfile.MaxTTLSeconds, Policy.CAProfiles, CAProfile.DefaultExtensions, CAProfile.AllowedExtensions, CAProfile.AllowedCriticalOptions, Policy.TimelockSeconds, WebAuthnRP.RPID, WebAuthnRP.Origins, Policy.WebAuthn, PoPPolicy.Hosts, PoPPolicy.Machines, Policy.PoP_added and Policy.PoP_removed.
  - TestPolicyChangeAdmins: added_only, removed_only, order_only, rename_and_add and all_replaced.
  - TestPolicyChangeUnchanged: identical and version_bump_only.
  - TestPolicyChangeDurations and TestPolicyChangeInvalid.
  - TestPolicyBlockBase/root_sign and /trust_verify.
  - TestCeremonyGolden, all 11 leaves, unchanged.
- **TestPolicyBlockBase is GREEN on origin/main.** Run from a detached worktree of R1 (production code equal to origin/main b4e6b4c) with a throwaway test file holding only TestPolicyBlockBase and its two helpers: both subtests pass. There the `Policy in force` assertions pass trivially, since main prints no block; the refusal `prevPolicy is not the previous bundle's policy` comes from checkSuccessorChain in both commands. The worktree was removed.
- **The e2e pin** (TestAuditLoginAcrossPolicyChange, `(03-14b)`): the wrong-confirmation output of `root sign --prev` and the `trust verify --prev` output must hold `Policy in force: v1, sha256 <sha256 of policy v1>`, `  webauthn: CHANGED (rp_id is one-way)`, `  admins: carried over`, `  pop: carried over` and `  pop: none (host agents and machine renewals are off)`; root sign's output must hold no `WARNING: this successor changes`. `go vet -tags e2e ./test/e2e/` exits 0. Its first run is the PR's e2e workflow.
- **Other Task 2 checks.** The scope check (second verify command) and the golden-correction bound (third verify command, rerun after T2) pass. gofmt is clean, and golangci-lint reports 0 issues on cmd/keyroster.

### Task 2 mutants (local numbers 1-16)

Every mutant met the mutant rule: the unmutated command passed; `go vet` of the mutated package exited 0; the mutated command printed every listed `--- FAIL:` line, with no `[build failed]`, `[setup failed]` or timeout; the file was restored byte for byte. All commands use ./cmd/keyroster/ unless R (./internal/rootceremony/) is named.

1. The `- admin` line dropped. TestPolicyChangeFields/AdminKey.Key; TestPolicyChangeAdmins/removed_only and /all_replaced. Killed.
2. Rename detection removed. TestPolicyChangeFields/AdminKey.Name. Killed.
3. The order line dropped. TestPolicyChangeAdmins/order_only. Killed.
4. The timelock comparison removed. TestPolicyChangeFields/Policy.TimelockSeconds. Killed.
5. The allowed_critical_options comparison removed. TestPolicyChangeFields/CAProfile.AllowedCriticalOptions. Killed.
6. Only rp_id compared, not origins. TestPolicyChangeFields/WebAuthnRP.Origins. Killed.
7. changedPolicyFields without pop. TestPolicyChangeFields/PoPPolicy.Hosts, /PoPPolicy.Machines, /Policy.PoP_added and /Policy.PoP_removed. Killed.
8. pop compared only by nil-ness and Hosts. TestPolicyChangeFields/PoPPolicy.Machines. Killed.
9. The one-way line printed whenever the successor sets hosts. TestPolicyChangeFields/PoPPolicy.Machines. Killed.
10. The warning line printed for webauthn. TestPolicyChangeFields/WebAuthnRP.RPID. Killed.
11. The warning line without timelock_seconds in its set. TestPolicyChangeFields/Policy.TimelockSeconds. Killed.
12. A field `Note string` (`note,omitempty`) added to trust.Policy (go vet of ./internal/trust/ too). TestPolicyFieldsCovered (`no TestPolicyChangeFields case for Policy.Note`, and the field-list mismatch), and R TestSummaryFieldsCovered (`no Summary case for Policy.Note`). Killed.
13. (a) The pinned map's trust.WebAuthnRP entry deleted in both test files. TestPolicyFieldsCovered and R TestSummaryFieldsCovered, each with `unpinned policy type trust.WebAuthnRP`. Killed. (b) The walk made non-recursive in both test files. The same two tests, each with `pinned type not reached` for trust.AdminKey, trust.CAProfile, trust.WebAuthnRP and trust.PoPPolicy. Killed.
14. runRootSign writes the block right after successorBuilder returns. TestPolicyBlockBase/root_sign. Killed.
15. verifySuccessorBundle writes the block right after loadPrev. TestPolicyBlockBase/trust_verify. Killed.
16. The duration helper's large-value branch removed. TestPolicyChangeDurations. Killed.

Cumulative: 18 of 18 Task 1 mutants and 17 of 17 Task 2 mutant runs (16 numbered, 13 in two parts) killed.

## Task 3: the runbooks, the section helper, the publish edits and the gates

- **Commits.** `27d2cf4` `docs(runbooks): check the policy block, the roots and the pop line before a root signs (F04, F14)` (root-ceremony.md, ceremony-transcript-template.md, host-setup.md, machine-identities.md and runbook_test.go); `5d5f14e` `docs(03-14b): publish the plan, point 03-12 to 03-15 at it, and shift the later waves`.
- **Stop guard.** Re-run before the publish edits: 03-11b's SUMMARY is on origin/main b4e6b4c, origin/main's 03-12 holds `wave: 29`, and 03-11b is the only plan at `wave: 28`.
- **The runbook inventory** (`git grep -n 'root sign' origin/main -- docs/runbooks`):
  - root-ceremony.md: "4. Sign with root A, then with root B", "Rotate the roots" steps 3 to 5, "Change the policy" (paragraph, "You need", steps 3 and 4, the "What has run" note) and "Hardware-root variant": checks added, each with a helper entry.
  - host-setup.md, "Registering a host in the directory" (the pop.hosts paragraph): check added, entry `host_setup_pop`. "Binding an existing directory to the installation" (the 03-15 `root sign --prev ...` mention): describes, nothing added.
  - machine-identities.md, "Renewal needs pop.machines": check added, entry `machine_identities_pop`.
  - revoke.md ("Before you start", the installation-ID upgrade by `root sign --prev ... --installation-id new`, pointing at 03-15): defers, nothing added.
  - signer-install.md (the vTPM custody passage): describes, nothing added; the grep finds no other passage there.
  - ceremony-transcript-template.md: the Purpose row and the new `Agreed policy change` row, entry `transcript_template`.
- **TestRootCeremonyPolicyChecks.** All 11 entries pass, plus its `output_prefixes` subtest (each of the 9 quoted prefixes occurs in a helper section and in a ceremony golden). TestSectionWindowRefusals refuses each of its three fixtures (duplicated_marker, missing_marker, end_before_start). TestHostSetupSignerCheck and TestHostSetupEffectiveSshdConfig still pass.
- **The RED on origin/main's runbooks** (a detached worktree of the branch with `docs/runbooks` checked out from origin/main): every one of the 11 entries fails, and so does `output_prefixes` (8 of the 9 prefixes are quoted nowhere; `webauthn rp_id ` already was). `--- FAIL:` for genesis_step_4, rotation_step_3, rotation_step_4, change_the_policy_you_need, change_the_policy_step_3, change_the_policy_pop_item (marker `- **The PoP switches.**` occurs 0 times), change_the_policy_intro (no end line after `Before you confirm`), hardware_variant, transcript_template, host_setup_pop and machine_identities_pop. TestSectionWindowRefusals passes there. The worktree was removed.
- **The runbook mutants** (each with the unmutated run passing, `go vet` 0, the named FAIL, no build or setup failure, restored byte for byte):
  1. The pop item removed from "Change the policy": `--- FAIL: TestRootCeremonyPolicyChecks/change_the_policy_pop_item`. Killed.
  2. The step-4 check removed from "Rotate the roots": `--- FAIL: TestRootCeremonyPolicyChecks/rotation_step_4`. Killed.
  3. The independence clause removed from the transcript row and from "You need": `--- FAIL: TestRootCeremonyPolicyChecks/transcript_template` and `/change_the_policy_you_need`. Killed.
  4. The Purpose row's edit reverted: `--- FAIL: TestRootCeremonyPolicyChecks/transcript_template`. Killed.
- **The stale texts are gone.** root-ceremony.md no longer says that the RP is the only field you can change this way, and host-setup.md no longer says that no test runs `trust verify --prev` with a pop policy (the gate greps count 0).
- **Pointer sentences** inserted once each, right after their anchors: 03-12, 03-13, 03-14 and the three 03-15 pointers. Numstat against origin/main: 03-12 4 4, 03-13 2 2, 03-14 2 2, 03-15 4 4, 03-16 1 1. 03-12's `depends_on` is `["03-14b"]`, and its first precondition ends with the `MSYS_NO_PATHCONV=1` clause.
- **Totals corrected.** At b4e6b4c main held the ROADMAP's Phase 3 total `/33` against 34 plan rows and files, STATE's `total_plans: 68` against 69 PLAN files, and `Plan: 28 of 30` against 29 executed of 34. The publish edit wrote `29/35 plans executed in 34 waves`, the Progress row `29/35`, `total_plans: 70` and `Plan: 29 of 35`; after the tracking update: the Plans line `30/35 plans executed in 34 waves`, the Progress row `30/35`, `total_plans: 70`, `completed_plans: 65` and `Plan: 30 of 35`.
- **The delta gate.** Against the re-measured base: cmd/keyroster 236.239 s (+3.258 s), internal/rootceremony 25.123 s (-0.026 s). Both are under the 90 s bound.
- **The full gate.** The first run failed one test in a package this plan does not touch: `TestFetch/more_repolls_immediately` (internal/agent/fetch, a timing assertion of about one second, under the whole-module `-race` load). internal/agent is unchanged against origin/main, and the package then passed alone three times (`-count=3`). The full gate was run again from the start and passed: the whole-module tests under `-race`, every vet tag set, gofmt, golangci-lint (0 issues), capslock, dep-firewall, testonly-firewall and check-pinned-actions. In that run cmd/keyroster read 287.064 s and internal/rootceremony 31.874 s (pass or fail only).
- **capslock.** No new pair. keyroster-signer reports 91 pairs against a baseline of 92 (`internal/signer CAPABILITY_RUNTIME` no longer reported; the script asks for a reviewed baseline tightening, which is out of this plan's scope). keyroster-agent and keyroster-agent-fetch match their baselines.

## The PR and CI

- **PR #98**, `fix(root): show the policy in force, each changed field and the PoP switches before a root signs (F04, F14)`, opened by keyroster-bot without auto-merge.
- **Checks on 5d5f14e** (the head before this SUMMARY commit), all green: build-test, lint, capslock, cli-windows and cli-macos (run 42928187408, which also holds govulncheck, fuzz and dependency-firewall), e2e and e2e-probe (run 42928187670), e2e-distro (42928187937), e2e-pkcs11 (42928187234), e2e-tpm (42928187277), systemd-sandbox (42928187792), build-piv (42928188116), CodeQL (42928187719), pinned-actions (42928187471) and pr-title (42928187666).
- **The house e2e gate in MODE=pr** passed for 5d5f14e: run 42928187670 is for HEAD; main lanes go test 768.538 s (9.5p1) and 803.973 s (10.5p1), both at or under 900 s; probe lanes 297.779 s and 290.418 s, with 03-11b's PASS lines.
- **The e2e pin.** Both main lanes print `--- PASS: TestAuditLoginAcrossPolicyChange` (0.47 s on 9.5p1, 0.44 s on 10.5p1): the real binaries print the policy block and the pop line. The pin adds only assertions, so its time cost is negligible.
- The final docs commit triggers the checks again; their result on the final head is reported with the hand-back.
- **Checks on 2b6423b** (the pre-merge review's fixes, the head before this SUMMARY update), all green with no rerun: CI 42941415196 (build-test, lint, capslock, cli-windows, cli-macos, govulncheck, fuzz, dependency-firewall), E2E 42941415195 (both main and probe lanes), E2E distro 42941415008, E2E PKCS#11 42941415232, E2E TPM 42941415056, Systemd 42941414980, PIV 42941414892, CodeQL 42941415364, Workflow lint 42941415150 and PR title 42941414929.

## Pre-merge review

One round on the green PR (T-03-329 to T-03-334): four lenses, each item checked by two skeptics and a critic. Two items were fixed and one wording was tightened; the code under test is unchanged.

- **The WARNING's scope in the runbook** (`fe6107b`). root-ceremony.md said the WARNING fires for any change root successor-policy cannot make. It fires for admin_quorum, admins, ca_profiles and timelock_seconds only (Q-B1). The "Change the policy" paragraph and the "Only the agreed change" item now name those four fields, and say that a removed RP and a cleared pop.machines, which also come only from a hand-written successor, read CHANGED with no WARNING and are caught by the agreed-change, RP and PoP items. A new helper entry, `change_the_policy_paragraph`, pins the paragraph (12 entries now).
- **The values come from the agreed record** (`fe6107b`). The "Only the agreed change" item and the transcript template now take the field names from the `Agreed policy change` row and check every value (admin names and SHA256 fingerprints, renames, quorum and timelock numbers, CA profile sub-fields, the RP, the pop switches) against the record the row refers to. Pinned in `change_the_policy_step_3` and `transcript_template`. On the old runbook texts, `change_the_policy_paragraph`, `change_the_policy_step_3` and `transcript_template` fail; on the new ones all pass.
- **The policy-block gate drops no case** (`2b6423b`). checkBlock now fails when a case names a line that is not one of policyFieldLines, or changes a field but names no CHANGED line, and the new TestPolicyFieldLines derives the field lines from trust.Policy's JSON names. Mutants, each restored byte for byte:
  1. A field `Note` added to trust.Policy, pinned, compared and given a case with line `note`, but no render line. The old checkBlock passes it. The new one fails `TestPolicyChangeFields/Policy.Note` (`case line "note" is not one of the block's field lines`) and TestPolicyFieldLines. Killed.
  2. The same with the case's line empty. The old checkBlock passes it. The new one fails `Policy.Note` (`case changes note but names no CHANGED line`) and TestPolicyFieldLines. Killed.
  3. The same with `note` added to policyFieldLines: TestPolicyChangeFields fails, from `Policy.AdminQuorum` on, on the missing note line. Killed.
  4. policyChange prints an extra `  extra: CHANGED` line: 23 subtests fail on the exact comparison, which the old checkBlock already made. Killed.

CI on the fixed head: see The PR and CI.

## What stays UNVERIFIED

- Every runbook check in a real ceremony (CI only; 03-15's v4 ceremony is the first real use).
- policyChange's two error returns at its call sites in runRootSign and verifySuccessorBundle: unreachable after the chain check (both documents parsed before), reasoned, not run.
- checkBundleKeys's refusal on the successor path (tested on the genesis path only).
- A successor built by a tool other than root sign.

## Deviations from Plan

- **The full gate's first run** failed `TestFetch/more_repolls_immediately` in internal/agent/fetch, a package this plan does not touch (a one-second timing assertion under whole-module `-race` load). It passed alone three times, and the whole gate was run again from the start and passed. No code changed.
- **No 03-14b plan-head ledger existed** from Task 1; it was written at Task 3 with origin/main b4e6b4c, the branch's base, so `plan_head_before` is b4e6b4c.
- Otherwise none: no contract fix, no golden correction, no file outside files_modified.

## Golden corrections

none

