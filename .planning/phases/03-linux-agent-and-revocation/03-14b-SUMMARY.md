---
phase: 03-linux-agent-and-revocation
plan: 14b
status: draft
---

# Phase 3 Plan 14b: show what a root signs (F04, F14) Summary

Draft, written from Task 1 on. Completed in Task 3.

test-time base: cmd=248.675 rootceremony=26.123 at=1794350937

Measured in Task 1 before any edit, on the tree equal to origin/main b4e6b4c, with no other heavy job running. Both packages read `ok`; the new test files were not in that build.

## Handover (end of Task 1)

The first session stopped after Task 1's gates, as the Budget plans. The continuation starts at Task 2. Task 3 must re-measure the base first, in place, on origin/main in a detached worktree: it runs in another session, and the base above was measured on 2026-11-10.

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

## Golden corrections

none

## Deviations from Plan

None so far.
