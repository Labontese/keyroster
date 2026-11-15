---
phase: 03-linux-agent-and-revocation
plan: 12b
subsystem: trust, signer, agent, ceremony
tags: [ca-rotation, chain-rule, ceremony, e2e]
status: complete
requires: [03-12]
provides: [checkCATransitions, ActiveCA, IssuingCAs, SuccessorOptions, root sign --ca-next/--ca-next-fingerprint/--ca-retire, CAChanges, RootSetLine, e2e-rotation lane]
affects: [03-12c, 03-12d, 03-12e, 03-12f, 03-13, 03-15]
key-files:
  created: [internal/trust/castate.go, internal/trust/castate_test.go, cmd/keyroster/canext.go, cmd/keyroster/canext_test.go, internal/rootceremony/cachanges.go, internal/rootceremony/cachanges_test.go, docs/runbooks/ca-rotation.md, test/e2e/ca_rotation_test.go]
  modified: [internal/trust/verify.go, internal/trust/successor.go, internal/signer/trust.go, internal/agent/apply/hostcert.go, internal/agent/apply/probe.go, cmd/keyroster/root.go, cmd/keyroster/trust.go, .github/workflows/e2e.yml, .github/rulesets/main-integrity.json, CONTRIBUTING.md]
decisions:
  - "The chain rule matches a role's entries by generation, an identical entry first, so a repeated generation shows as an addition (only a direct call can pass one)"
  - "A pure widening (a CA line added alone) waits and swaps once with no intermediate generation; TestCANextAndAbort asserts the wait, not an intermediate"
requirements-completed: []
actuals:
  tokens: 121124
  tasks: 5
  commits: 14
plan_head_before: a624b04ddf59e0361c97520c5c39da07061f9a4b
plan_head_after: dce96ead593990aa714e3f3018b9ab8a3fd39c31
---

# Phase 3 Plan 12b: CA rotation, ceremony 1 and abort Summary

test-time base: cli=294.239 signercmd=29.999 signer=501.804 audit=100.347 apply=649.777 at=1794777137

A prepared CA key becomes `next` through one root ceremony (`root sign --prev --ca-next ROLE=FILE --ca-next-fingerprint ROLE=SHA256:...`), every host trusts it beside the active key after the widening wait, and `--ca-retire ROLE:GEN` withdraws it, under one chain rule (`checkCATransitions` in `checkSuccessorChain`) that the signer, every agent, audit and the ceremony tool run; the agents' host-certificate and probe answer sets take only active and next keys; the ceremony output shows the CA changes and the root set before anyone signs.

## PR and CI

- PR #103 (`feat(trust): add and withdraw a next CA key in CA rotation ceremony 1`), opened by keyroster-bot without auto-merge.
- First e2e run 43765030153 (head 1c95f3d): `e2e-rotation (9.5p1)` success, go test 72.307 s (TestCANextAndAbort 36.03 s); `e2e-rotation (10.5p1)` success, 58.851 s (34.96 s). The sshd line matched for the refused certificate: `Failed publickey for runner from 127.0.0.2 port`. The ruleset names and CONTRIBUTING rows (C2) were committed after both had reported success there.
- First CI run 43765030160 (head 1c95f3d): `lint` failed on two issues (an error string ending in `SHA256:...`, and a negated conjunction in the golden test's invariant), fixed in 3870fd5.

- Runs at dce96ea (C2, the last code commit): E2E 43765947044 success (e2e 9.5p1 775.400 s and 10.5p1 747.996 s against the 900 s stop; e2e-probe 276.290 s and 284.174 s; e2e-rotation 9.5p1 58.663 s and 10.5p1 63.490 s), CI 43765947010, E2E distro 43765947305, Systemd 43765947148, E2E TPM 43765947063, E2E PKCS#11 43765947084, PIV 43765947056, CodeQL 43765947016, PR title 43765946995, Workflow lint 43765947003. A SUMMARY cannot name the runs of the commit that carries it; the final head's runs are on the PR.
- TestCANextAndAbort first ran locally under WSL (both OpenSSH builds), then in CI.

## Commits

`git diff --cached` was run on every staged file, one file at a time, and read in full before every commit and amend below (S0's three mixed files were staged as S0-only blobs with `git update-index --cacheinfo`, so the staged diff held the sweep only). The plan commit's added side is byte-identical (sha256 01b637e5...) to the executable plan, which was read in full before execution; its removed side, the early plan, was read in full before that commit.

| Name | SHA | Subject |
|---|---|---|
| S0 | 145c8d5030d2d203c2fbca16e681f14d3d8a7b30 | refactor(trust): BuildSuccessor takes SuccessorOptions |
| P1 | 0035ad47f3f00af4418f4b510ff314866e625b60 | test(agent): build the rotation test bundles as chain-legal CA changes |
| R1 | 97500cff8902e73dea4297587bb725792ac91a9d | test(trust): pin the CA transitions, the builder's CA changes and ceremony 1 end to end |
| T1 | d874df30489854554ef097843ab43753d10054e5 | feat(trust): add the CA rule for next and abort to the successor chain |
| R2a | a67d64a2ea8cb369405409fac4f912cf06b209a9 | test(signer): pin the rule's refusals, the next and abort installs and the audit cases |
| R2b | 0ee731cd1536e7bb156aba1181a0a7a69ec1627f | test(agent): refuse an answer signed by an aborted CA key |
| T2b | c393302d588e85fbc15119625b5533040baf1f88 | fix(agent): take the host and probe answer sets from the active and next CA keys |
| R3 | 7547a5ec6268e26ba734775866fa122071420fd2 | test(ceremony): pin ceremony 1 and abort in root sign and trust verify |
| T3 | e59a539d46639b77ce74b5e1c84d2c62d1ed6293 | feat(ceremony): add the next CA and abort to root sign, and show the CA changes and the root set |
| plan | 962b8d9b62e725c174cc58802f4204597bee5ffc | docs(03-12b): plan out CA rotation ceremony 1 and abort and point 03-15 at it |
| A1 | f340fffbdf4dd79c83a5206d1ea648949919c997 | test(e2e): add and withdraw a next user CA through root ceremonies against real sshd |
| C1 | 1c95f3de3803357da9d93cca76fe196c29e5e2f8 | ci(e2e): add the e2e-rotation lane |
| fix | 3870fd576e72c23adcc95fe8a3dc22a55cfbaf56 | fix(ceremony): return the CA flags' usage texts as a usage error type |
| C2 | dce96ead593990aa714e3f3018b9ab8a3fd39c31 | ci(rulesets): require the e2e-rotation lane |

No T2a commit exists: 2a pins behaviour that T1 already has (the plan says so). Every commit is authored as Daniel Gustafsson, committed and SSH-signed by keyroster-bot, with no attribution line.

## Task 1

- Base: a first reading on origin/main a624b04 in the main checkout overlapped the S0 sweep and the first P1 helper edits being written into the tree (packages compiled during that run may have seen them), so it was replaced in place by a re-measure in a detached worktree of origin/main with nothing else running (the line above). Recorded deviation.
- S0: 19 call sites, not 20 (root.go 1, apply_test 2, krlsigner_test 1, policy_change_test 2, rechain_test 1, window_test 4, installation_test 1, pop_test 2, successor_test 5). Verified at S0 in a detached worktree (vet, gofmt, trust and cmd/keyroster with -race, the agent subset): pass; no golden changed.
- P1 conversions (helpers `withNextUser` at the role's next free generation, `retireNext`, `successorWithout` retires instead of deleting, `rotationDropping` refuses a prev with a next entry, new `rotationRetiring` and `rotationToBob`). Old and new bundle versions:
  - TestSpoolWindowWideningWait recordAbove: recorded bundle 3 (rotate, drop x, add the refused line) becomes 3 (rotate, retire x) plus 4 (add the refused line at gen 3): record 3 -> 4, recorded doc d3 -> d4. Cases `nothing_new`, `newer_directory_under_the_policy_in_force` (on the new record 4); `remade_chain` 2'-4' -> 2'-5' (4' retires instead of deleting, 5' above the record under policy 2); `remade_chain_under_the_old_policy` 2'-4' -> 2'-5'; `record_version_withheld` bundle-3 -> bundle-4 files; `fork_at_the_record_version` spool 3 -> 4 (a successor of the original 3).
  - `older_bundle_at_the_window_boundary`: 65, 66 -> 65, 66 (rotate, retire x), 67 (the refused line); records 65, 66 -> 65, 67.
  - TestSpoolWindow/`bundle_ca_line_window_newest_then_fixed_bundle_applies`: 66 retires instead of dropping; versions unchanged.
  - TestKRLSigner recordBelowWait: bundle 3 -> 3 (rotate, retire x, recordOps) plus 4 (the refused line, bundle 3's ops key); record 3 -> 4; aboveOps bundle 4 -> 5 (policy 3 unchanged). Cases `record_signed_krl_during_a_wait_lands` (poll, forward), `retired_key_krl_during_a_wait_from_the_record_is_refused` (poll, forward), `retired_key_krl_during_a_wait_above_the_record_is_refused` (poll, forward; withholds bundle 5 instead of 4), `retired_key_krl_after_a_poll_from_the_record_is_refused` (bundle 4 -> 5): record 3 -> 4.
  - successorWithNext (rechain_test) and successorNextUnder use `withNextUser`; every other caller's prev holds generation 1 only, so its version 2 is unchanged.
  - P1 passed without the rule (agent subset; the whole apply package with -race in a detached worktree of P1, 573.962 s) and with it (prototype, then at T1).
- R1 declarations: `ActiveCA` (zero entry), `IssuingCAs` (nil), `checkCATransitions` (nil, not called); `SuccessorOptions.CANext`, `SuccessorOptions.CARetire`, `type CARef`.
- RED (worktree of R1): the 32 named leaves failed (39 FAIL lines with the 7 parents), `BuildSuccessor ignored CANext` printed, no build or setup failure, nothing outside the named tests. Controls: TestCATransitions/unchanged_ok, add_next_ok, abort_next_ok, two_roles_one_change_each_ok, generation_gap_ok, installation_id_new_with_next_ok (the stub accepts everything); TestActiveCA/zero_for_unknown_role; TestIssuingCAs/retired_excluded (nil holds no retired entry); TestCheckBundleKeysGenerations/admin_equal_stored_generation_refused, root_equal_stored_generation_refused, generation_1_active_accepted.
- T1 verifies: verify 1 pass; verify 2 (whole apply package -race) pass at P1 (573.962 s) and T1 (516.941 s); verify 4 (signer 403.981 s, audit 94.764 s, signerdb, doctor, the signer cmd cases including TestCANextTracer) pass; verify 5 (T1 changed no test or test data; no `keyroster/` literal added) pass.
- Capslock after T1: 97 / 37 / 23 pairs, at the baselines.
- Reversibility (the tracer's rating, costly): every landed `next` or `retired` entry stays in every later bundle, so a later release that tightened this rule would refuse the chain of an installation that already rotated, and loosening it needs a new plan.

## Task 2

- R2a declares nothing; every 2a case passed on R2a (controls). FuzzCATransitions 30 s: 560841 execs, no failure (and again at T2b). Its six seeds hit accept (unchanged), accept (add), accept (abort), refuse (removed), refuse (entry changes), refuse (added twice). The model lists additions in both custodies the bytes can name: the rule binds no custody to an addition (the signer's stored-generation check does).
- R2b RED (worktree of R2b): FAIL TestHostCertStep, TestHostCertStep/hostcert_answer_aborted_ca_refused, TestProbeStep, TestProbeStep/probe_pair_aborted_ca_refused; controls passed: hostcert_answer_next_ca_accepted, probe_pair_next_ca_kept; nothing else failed.
- T2b was first committed as c340328403eabc449492232eda37d4ee0c0cffb9; its comment named `krl.RoleCAKeys`, which verify 5's added-line scan reads as an answer set still taken from it, so the comment was reworded and T2b amended to c393302 (comment only). Verifies 1, 2 and 4 ran in a detached worktree of c340328 (identical code); verify 5 at c393302.
- Verify 1: vet, gofmt, trust (2.429 s), signer (425.842 s), audit (95.990 s) with -race, the signer cmd cases (32.861 s), the fuzz: pass. Verify 2: the eleven named signer cases PASS, no FAIL. Verify 4: the whole internal/agent tree with -race (apply 584.414 s), vet, capslock (97 / 37 / 23, at the baselines), dep-firewall: pass. Verify 5: pass.

## Task 3

- R3 declarations: canext.go `parseCANextFile`, `readCANextFile` (zero entry, nil); cachanges.go `CAChanges`, `RootSetLine` (""). The flags were not declared.
- R3 was first committed as bd4a9f5e9383d43acc7e3f9136055de92b208e07. The two exported stubs broke internal/rootceremony's TestExportedAPI, which pins the exported names, so R3 was amended to 7547a5e with imports_test.go's list gaining CAChanges and RootSetLine (a file the plan does not list; recorded deviation). The RED was taken from worktrees of both: every named leaf failed (77 FAIL lines), no build or setup failure, nothing outside the named tests. Controls: TestBundleReflectGate (Summary already prints every field), TestCeremonyGolden/genesis_pop and its leaves, the five fixture subtests of TestCARotationRunbookLinkSafety, TestExportedAPI (on 7547a5e).
- T3 added the four new goldens (the one exception to "T changes no test"), generated with `-args -update-golden` and read line by line: `CA user gen 2 SHA256:/IOzXQlPE0KazWYL6P2934TM/0zU3Xn7KJQODwX4v6Q: none -> next` (seed 40) and `next -> retired` for the abort, `Root set: unchanged`, after the `signatures needed:` line (root sign) or the `Successor of trust bundle` line (trust verify).
- Verify 1 (worktree of T3): vet, gofmt, rootceremony (25.261 s), trust, cmd/keyroster (279.965 s) with -race, FuzzParseCANextFile 30 s (1313130 execs, no failure), windows and darwin builds: pass. Verify 3: both packages with -race pass, the four new golden leaves PASS. Verify 4 (T3 changed no test file, added exactly the four goldens, the eight goldens gained lines only, the genesis goldens unchanged), verify 5 (runbook phrases, checklist tests) and verify 6 (no private term or address in added lines): pass.
- The lint fix 3870fd5 (after T3) changes cmd/keyroster/canext.go and the invariant line of ceremony_golden_test.go; the Task 3 mutants ran at T3.

## Mutants

Each ran in a detached worktree of the commit named: the unmutated command passed first, `go vet` ran inside the command, the file was restored byte for byte, its sha256 was equal before and after, and `git status --short` listed only the mutated file while mutated and nothing after. Every mutant compiled (no build or setup failure). Commands: the plan's, with `-timeout 5m`; M197 ran the trust, signer and signer-cmd commands together (its killers are in three packages).

| Mutant | At | File, sha256 before = after | Killed by |
|---|---|---|---|
| M123 | R2a | castate.go 0534be7d8b25b2b0eb07636a9a9bdd595847178ea50e4f1e5e6ba52ce7212889 | TestCATransitions/next_generation_not_above_prev_refused |
| M124 | R2a | castate.go (same) | TestCATransitions/next_key_equal_retired_key_refused |
| M125 | R2a | castate.go (same) | TestCATransitions/entry_removed_refused |
| M126 | R2a | castate.go (same) | TestCATransitions/abort_active_refused |
| M127 | R2a | castate.go (same) | TestCATransitions/two_transitions_one_role_refused, two_additions_one_role_refused |
| M194 | R2a | castate.go (same) | TestCATransitions/abort_changes_key_refused |
| M195 | R2a | castate.go (same) | TestCATransitions/add_active_refused |
| M196 | R2a | castate.go (same) | TestIssuingCAs/retired_excluded (and active_and_next_by_generation) |
| M197 | R2a | trust/verify.go 8ca8742b8536c92e9f76d72311ca49b27ac4b7e349a5441a31a86836ca21317e | TestSuccessorChainRunsCARule, TestSuccessorForeignCAKeyRefused, TestCANextTracer (and more) |
| M134 | R2a | signer/trust.go a69c3f3742bdb2baa4844f599aa9b45be5972854c4fcf18ed9216e0c251df991 | TestCheckBundleKeysGenerations/next_not_stored_refused, TestInstallNextBundle/next_not_a_stored_generation_refused |
| M192 | R2a | signer/trust.go (same) | TestCheckBundleKeysGenerations/retired_not_stored_refused |
| M193 | R2a | audit/verify.go dc4d4e2105c6484bf6400813d8cc24d0b3c384c66fb9e6e11fbe15f9446aeb86 | TestVerifyCAGeneration/issue_by_next_refused, abort_key_never_signed |
| M130 | T2b | apply/hostcert.go 2c93dee796e67d20bb76330a03001b0cbef08a8a0cccbaa220ce9ff8292f3c25 | TestHostCertStep/hostcert_answer_aborted_ca_refused |
| M131 | T2b | apply/probe.go b8494e1dc3217cde22a5cef0566f7613493c6165a9febfbeadcda4a615d851f4 | TestProbeStep/probe_pair_aborted_ca_refused |
| M128 | T3 | keyroster/root.go 8082affdb397b67e131569a8cc1e5a3c6bacd3dacbab8a49227c75017e361b21 | TestRootSignSuccessor/ca_next_fingerprint_mismatch_refused |
| M129 | T3 | root.go (same) | TestRootSignSuccessor/ca_pubkeys_with_prev_refused |
| M132 | T3 | keyroster/trust.go 9c67bef2828731f974d3671717c525d6a4aea81b6e68521854cece553b8082d4 | TestCeremonyGolden/successor_ca_next/trust_verify (and every successor trust_verify leaf) |
| M133 leg 1 | T3 | rootceremony/summary_test.go 11093e741107a833e7ef24b94ac017ec0badefc27c475574e171a9e03a83258c | TestBundleReflectGate/exemptions |
| M133 leg 2 | T3 | rootceremony/summary.go c7577d826cde56eab67aec7f119813aabd936ca1fa53b8b69de4385f89097ed1 | TestBundleReflectGate/LogEntry.Origin |
| M198 | T3 | root.go (same) | TestCeremonyGolden/successor_ca_next/root_sign (and every successor root_sign leaf) |
| M199 | T3 | rootceremony/cachanges.go fbdbe2ce81ae6255f50e9bd172182c0645fc53a21cd8151b02ab018d8f596c33 | TestRootSetLine/swapped_root_changed |
| M200 | T3 | keyroster/canext.go 5c82929badcef006df733f3a8d44fb726cb0ee3de4416a6d7f418a31510237e5 | TestParseCANextFile/non_canonical_refused (and unknown_field_refused) |
| M201 legs 1-4 | T3 | docs/runbooks/ca-rotation.md a71b9e81b9b62e5a9f96a000e485cf1a5903b1d098f71c625e81797070328aa1 | TestCARotationRunbookLinkSafety/runbook_blocks_pass, each leg alone (root install one line; split by a continuation; root `cat x > .../incoming/y`; root `rm -f .../incoming/bundle.json`) |
| M202 | T3 | root.go (same) | TestRootSignSuccessor/ca_next_role_not_the_files_role_refused |

M200 adds the `encoding/json` import with the `json.Unmarshal` call, so it compiles. Threat IDs and mutant numbers: the precondition found T-03-433 to T-03-449 and M192 to M209 free on origin/main; no renumbering.

## Task 4

- TestCANextAndAbort ran first locally under WSL against the OpenSSH builds of scripts/build-openssh.sh: 10.5p1 and 9.5p1 failed on the plan's `r.Intermediate != 0` (a CA line added alone is a pure widening: the agent waited 33 s and swapped once, with no intermediate generation, which is for a change that also narrows); the assertion was dropped and both builds passed (test 39.84 s and 39.69 s). Then the PR's e2e run (above).
- `ca issue` sites: this plan adds none besides `env.issue` (through `issueAgentCert`), which passes `--installation-id`; test/systemd/smoke.sh's two sites (lines 226-228 and 243) already pass it.
- 03-15: four lines changed (`git diff --numstat` 4 4): the offline block's command, the rehearsal, the v4 command and T-03-261; its wave and depends_on unchanged; 03-12c to 03-16 untouched.
- Tracking (GSD state.advance-plan, state.update-progress, roadmap.update-plan-progress 03): ROADMAP `34/42 plans executed in 41 waves`, Progress row `| 34/42 |`, only the 03-12b row ticked (every other line byte-identical to origin/main's); STATE `total_plans: 77`, `completed_plans: 69`, `Plan: 34 of 42`.
- Publish scans: the plan file and every added line hold no private term, lab host name, design-review label or address other than loopback; the commit messages and PR text none.

- Test-time delta gate (same session as the base, 50 min after it, nothing else running locally): cli 379.383 s (+85.144 over 294.239), signercmd 42.539 s (+12.540), signer 556.786 s (+54.982), audit 97.613 s (-2.734), apply 675.168 s (+25.391); every package within 90 s, pass. cmd/keyroster's +85 s is close to the cap: TestRootSignSuccessor gained thirteen subtests (several scrypt decrypts of the software roots) and TestCeremonyGolden two groups.

- Full gate (main checkout at dce96ea plus the tracking edits): `go test -race ./...` (36 packages ok; cmd/keyroster 318.499 s, apply 616.996 s), `go vet` with no tag and with every e2e tag set (e2e; e2e e2erotation; e2e e2eprobe e2emachine; e2e systemdsmoke; e2e_pkcs11; e2e_tpm), `bash -n test/systemd/smoke.sh`, gofmt, golangci-lint (0 issues), capslock (97 / 37 / 23, at the baselines), dep-firewall, testonly-firewall, check-pinned-actions, windows and darwin builds: pass.
- `actuals.commits` is 14, measured with `git rev-list --count` from a624b04 to dce96ea (`plan_head_after`), before the final docs commit that carries this SUMMARY; `actuals.tokens` is chars/4 over `git diff origin/main...dce96ea`.

## Deviations from Plan

1. **[Rule 3] Base re-measured.** The first base overlapped edits in the main tree; replaced in place by a detached-worktree re-measure.
2. **[Rule 1] S0 count.** 19 BuildSuccessor call sites, not 20.
3. **[Rule 1] remade_chain cases need a fifth version.** With the record at 4, `remade_chain` and `remade_chain_under_the_old_policy` add a 5' above the record so the chain stays above it (the plan named only the fourth bundle's retire).
4. **[Rule 1] T2b comment.** The first T2b comment named `krl.RoleCAKeys` and tripped verify 5's added-line scan; reworded, T2b amended.
5. **[Rule 3] TestExportedAPI.** The R3 stubs are exported; internal/rootceremony/imports_test.go (not in the plan's file list) gains the two names; R3 amended.
6. **[Rule 1] The e2e widening assertion.** The plan asked for `r.Intermediate != 0` at ceremony 1; a pure widening has none, so the test asserts the 33 s wait and no reload instead (step 5).
7. **[Rule 1] Lint.** CI's golangci-lint refused the `SHA256:...` ending of a usage text (revive, staticcheck ST1005) and a negated conjunction (QF1001); fixed in 3870fd5 with a `usageError` type and a rewritten condition. The executor had not run golangci-lint before the first push.
8. **Plan commit order.** The plan and the 03-15 pointers were committed before the first push, beside the code.
9. **The pre-merge review was not run by the executor**: the owner runs it on the green PR.

## What stays UNVERIFIED

Every ca-rotation.md text on the homelab hosts and signer; the widening wait on a host with the default LoginGraceTime of 120 s (150 s); Windows OpenSSH; the manual destruction of an aborted key; the e2e-rotation lane's timing beyond the runs recorded here.

## Pre-merge review

Not run by the executor (the owner runs it on the green PR, before Task 5).

## Self-Check

Self-Check: PASSED (the ten key files exist; the fourteen commits are ancestors of HEAD).
