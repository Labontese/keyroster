---
phase: 03-linux-agent-and-revocation
plan: 11
status: complete
requirements-completed: []
commits: 9
plan_head_before: 1e5786328d4580c528cd757c34fae0327ec61047
plan_head_after: f66194f911beb64137dda469797d9e2c123abfda
actuals:
  tokens: 49000
  tasks: 4
  commits: 9
---

# Phase 3 Plan 11: machine certificates by proof of possession, signer half

## Reconcile (Task 1 Step 0)

no file moved since 1e57863

The precondition checks of Task 1 held on origin/main 1e57863: 03-10d merged, no `KindMachineIssue`, rows 13 and 0x0C reserved, no threat row T-03-397 to T-03-406.

## Test time

test-time base: signer=417.445 audit=90.637 tlog=4.204 wire=8.764 cert=10.002 directory=20.049 at=1794286787

Measured on unchanged origin/main 1e57863 in a detached worktree outside the repository, with no other job running.

## Task 1

T1: 7dafbe2

### RED evidence

The new and changed test files, copied into a detached worktree at origin/main, fail to compile in every package:
- wire: `undefined: MachineIssueRequest`
- tlog: `undefined: MachineIssueBody`
- directory: `d.MachineGrant undefined`
- cert: `undefined: MachineLifetime`
- signer: `undefined: wire.MachineIssueRequest`
- audit: `undefined: wire.MachineIssueRequest`

Before the vectors existed, `TestMachineIssueRequest/signing_vector` and `TestMachineIssueBody` failed on the missing files. They were written with `-update` from the hand-built bytes.

audit stub RED: 23 of 23 fail-direction subtests failed

Each one failed through `wantFail` with `verify = <nil>`. `key_revoked_fails` first failed on the fixture instead: its revoke leaf lacked the krl_publish the signer writes with it. The fixture now logs that publish, and the subtest fails against the stub through `wantFail` as well.

### Other existing tests changed

- `TestHostForgetBody/kinds_are_a_set` (tlog/leaf_test.go) looped over kinds 13, 14 and 17 as unused. It now loops over 14 and 17. The plan did not list this test. The file is in files_modified.

### Mutants

Each mutant was run alone on its named subtest (unmutated first, `--- PASS`), killed by that subtest's `--- FAIL` line, and restored (`git diff --quiet HEAD` on the file). None survived. None was equivalent.

mutant killed: M1 the PoP check removed (TestMachineIssue/pop_invalid_wrong_signature)
mutant killed: M2 the key-equality step removed and the PoP verified against the request's key (TestMachineIssue/pop_by_request_key_not_listed_key_is_key_mismatch)
mutant killed: M3 the namespace set to wire.HostPoPNamespace (TestMachineIssue/pop_wrong_namespace_host_pop)
mutant killed: M4 machine_key_revoked removed (TestMachineIssue/key_revoked_before_disabled)
mutant killed: M5 machine_disabled removed (TestMachineIssue/disabled_entry_refused)
mutant killed: M6 machine_disabled moved before the PoP (TestMachineIssue/disabled_entry_bad_pop_is_pop_invalid)
mutant killed: M7 machine_key_revoked moved before the PoP (TestMachineIssue/revoked_key_bad_pop_is_pop_invalid)
mutant killed: M8 a nonzero valid_for accepted (TestMachineIssue/valid_for_nonzero_refused)
mutant killed: M9 MachineGrant's TTL ignores the roles (TestMachineGrant/max_ttl_is_min_of_entry_and_roles)
mutant killed: M10 MachineGrant drops the last role's principals (TestMachineGrant/principals_sorted_union)
mutant killed: M11 a profile-default extension passed as an extra (TestMachineIssue/role_extension_default_not_duplicated)
mutant killed: M12 the installation check removed (TestMachineIssue/installation_mismatch)
mutant killed: M13 the pop.machines check removed (TestMachineIssue/pop_not_enabled)
mutant killed: M14 the answer released although the append failed, the logTx error dropped (TestMachineIssue/nothing_released_before_commit)
mutant killed: M15 machine_issue not counted in the log rebuild (TestMachineIssueRestart/counts_machine_leaf)
mutant killed: M16 the issuance-time machine_name_reserved removed (TestMachineIssue/probe_prefixed_name_refused_at_issuance)
mutant killed: M17 MachineLifetime ignores the profile cap (TestMachineLifetime/profile_cap_smallest)
mutant killed: M18 audit skips the SSHSIG (TestVerifyMachineIssue/sshsig_by_other_key_fails)
mutant killed: M19 audit skips the lifetime check (TestVerifyMachineIssue/lifetime_fails)
mutant killed: M20 audit does not compare the principals (TestVerifyMachineIssue/principals_fails)
mutant killed: M21 audit does not compare the entry's key with the request's (TestVerifyMachineIssue/key_not_listed_fails)
mutant killed: M22 audit allows a probe. name (TestVerifyMachineIssue/probe_name_fails)
mutant killed: M23 audit's machine request-ID check against the host map removed (TestVerifyMachineIssue/request_id_reused_from_other_kind_fails/host_issue)
mutant killed: M24 KindMachineIssue removed from the kinds checkForgetFields binds (TestExportMachineIssue/tampered_decoded_field_refused)
mutant killed: M47 the directory_changed guard of the tail removed (TestMachineIssue/directory_changed_before_commit)
mutant killed: M48 audit's check against the issue (kr1) map removed (TestVerifyMachineIssue/request_id_reused_from_other_kind_fails/issue)
mutant killed: M49 audit's check against the login map removed (TestVerifyMachineIssue/request_id_reused_from_other_kind_fails/login_issue)
mutant killed: M50 audit's check against the probe map removed (TestVerifyMachineIssue/request_id_reused_from_other_kind_fails/probe_issue)
mutant killed: M66 MachineRecentAdd keeps the twelve smallest instead of the twelve largest (TestMachineRecentAdd/keeps_the_twelve_largest_by_value)

### Gates on 7dafbe2

- Gate 1: every subtest of the behaviour list printed `--- PASS` under `-race`; no FAIL, panic or DATA RACE.
- Gate 2: the four fuzz targets ran 20 s each and found nothing; no new corpus file.
- Gate 3: the seven touched packages pass under `-race` (signer 398.666 s, audit 92.658 s, quiet run); the frozen paths, the workflows and the capslock baseline are unchanged; frame.go changes in one non-comment line, the new constant; the two vector files are the only changed vectors.
- Gate 4: golangci-lint for linux, windows and darwin, gofmt, the dependency and test-only firewalls.

### Deviations (Task 1)

- The signer's `machineLatest` and audit's mirror carry no `revoked` or `revokedAtDir` field yet. golangci-lint (`unused`) refuses a field nothing reads, so both fields arrive with Task 2's revoke handling.
- MachineIssue refuses `bad_principal` only for a principal union above `cert.MaxPrincipals`, as the plan says. An empty union cannot pass `directory.Validate` (every role has a principal, directory.go:309; every machine a role, hosts.go:291).
- The FuzzVerifyExport machine seed is built under the pinned fixture root. The test fails if the seed does not verify, as the login and forget seeds do.

## Task 2

T2: a037604

### RED evidence

- cert: `undefined: MachineRenewTooOften` (and MachineCertHeld, MachinePrev).
- signer: `x.revoked undefined (type machineLatest has no field or method revoked)` (sameMachineIndex compares the new fields).
- audit, against Task 1's verifier: the nine fail-direction subtests failed through `wantFail` with `verify = <nil>`. Task 1's verifier already refused a machine request ID that an earlier machine entry used, so for `machine_reuses_machine_request_id_fails` that check was removed for the stub run (not committed) and the subtest failed the same way.

audit stub RED: 9 of 9 fail-direction subtests failed

### Mutants

Run as in Task 1: the named subtest alone and unmutated first (`--- PASS`), then the mutant on it with `-timeout 5m`, killed by its `--- FAIL` line, restored with `git checkout` and proven by `git diff --quiet HEAD`. None survived and none was equivalent.

mutant killed: M25 the hold removed (TestMachineIssue/hold_after_revoke_same_dir)
mutant killed: M26 the hold released at an equal directory version, < for <= in MachineCertHeld (TestMachineIssue/hold_equal_dir_version_still_holds and TestMachineCertHeld/equal_version_held, each killed it alone)
mutant killed: M27 the bound 12 changed to 13 (TestMachineIssue/renew_bound_12_then_refused)
mutant killed: M28 the bound keyed by machine name (TestMachineIssue/rename_keeps_window)
mutant killed: M29 machine_key_unusable removed (TestMachineIssue/installation_key_unusable)
mutant killed: M30 the index ignoring key-ID entries (TestMachineIssue/hold_after_key_id_revoke)
mutant killed: M31 the window edge moved, a second exactly 3600 old counted (TestMachineRenewTooOften/window_edge)
mutant killed: M32 a recovery-carried certificate counted toward the bound (TestMachineIssueRestart/recovery_carried_unrevoked_not_counted_toward_bound)
mutant killed: M33 the classify row of machine_renew_too_often removed (TestMachineRefusalClasses/class_table)
mutant killed: M34 machine refusals logged on s.limiter (TestMachineIssueBucket/flood_does_not_drain_shared_bucket)
mutant killed: M35 the malformed 0x0C frame refused with s.refuse (TestMachineIssueBucket/malformed_frames_use_machine_bucket)
mutant killed: M36 audit skips the hold (TestVerifyMachineIssue/hold_fails)
mutant killed: M37 audit skips the bound (TestVerifyMachineIssue/bound_fails)
mutant killed: M38 audit's mirror ignoring a recovery's carried certificates (TestVerifyMachineIssue/recovery_carried_hold_fails)
mutant killed: M39 the host case not consulting machineIDs (TestVerifyMachineIssue/host_reuses_machine_request_id_fails)
mutant killed: M51 the key hold moved before the PoP (TestMachineIssue/hold_bad_pop_is_pop_invalid)
mutant killed: M52 the bound moved before the identity block (TestMachineIssue/bound_reached_bad_pop_is_pop_invalid)
mutant killed: M53 machine_key_unusable moved before the PoP (TestMachineIssue/machine_key_unusable_bad_pop_is_pop_invalid)
mutant killed: M54 the request-ID check removed (TestMachineIssue/request_id_reuse_before_bound)
mutant killed: M55 the index revoke arm ignoring serial entries (TestMachineIssue/hold_after_revoke_same_dir)
mutant killed: M56 audit's mirror counting a carried certificate toward the bound (TestVerifyMachineIssue/recovery_carried_not_counted_toward_bound_passes)
mutant killed: M57 audit's mirror moving revokedAtDir on a re-listing (TestVerifyMachineIssue/relisting_keeps_first_passes)

### Gates on a037604

- Gate 1: every subtest of Task 2's behaviour list printed `--- PASS` under `-race`; no FAIL, panic or DATA RACE.
- Gate 2: the six packages pass under `-race` (signer 391.990 s, audit 92.697 s, tlog 4.016 s, wire 9.312 s, cert 8.554 s, directory 20.402 s; a pass or fail run, not a delta reading); the frozen paths and the capslock baseline are unchanged (23 pairs); audit/hostissue.go and audit/probeissue.go are unchanged (PD8).
- Gate 3: golangci-lint for linux, windows and darwin, gofmt.

### Threat rows (Task 2)

T-03-397 (the order: the key hold, the bound and machine_key_unusable each have a bad-signature subtest and an order mutant), T-03-398, T-03-400 (the key hold; the name hold is Task 3's), T-03-401 and T-03-402 are mitigated.

### Deviations (Task 2)

- `hold_equal_dir_version_still_holds` lets the revoked certificate expire and restarts the signer at the same directory version, so it shows that neither time nor a restart releases the hold; `hold_after_revoke_same_dir` covers the plain equal case.
- `bad_pop_attempts_do_not_consume_the_bound` issues eleven certificates before the twenty refused attempts, so a counted attempt would refuse the twelfth issuance.
- The hold, bound and unusable-key subtests share three environments built on first use with the parent test (PD9); each passes alone.
- M28 changes two files: the index keys the recent list by the key ID's subject and MachineIssue reads it by the entry's name.
- `TestMachineIssueBucket/admin_refusals_still_logged` uses a refused admin issue; `flood_does_not_drain_shared_bucket` uses a refused revoke.
- audit's `installation_key_fails` logs a directory that lists the fixture's ops key as machine `opsm` (the fixture logs directories without the signer's install rules); the signer's `installation_key_unusable` stores one through `seedDirectory`.

## Task 3

T3: b5ad578

### RED evidence

- signer: `a.nameHeld undefined (type machineIndex has no field or method nameHeld)` (sameMachineIndex and `name_hold_index_matches_rebuild` read the name hold).
- audit: every `TestVerifyRevokeMachine` subtest failed, the fail-direction ones through `wantFail` with `revokes a machine subject, which this version does not resolve` in place of their own message.

### Existing tests changed (Task 3)

- Removed, as the plan says: `TestRevokeHostSubject/subject_machine_still_unsupported` (signer/revoke_host_test.go), `TestRevokeSubject/subject_kind_unsupported` (signer/revoke_test.go), the case `revoke_subject_kind_machine_refused` (audit/verify_test.go) and `TestVerifyRevokeHost/subject_machine_fails` (audit/verify_test.go). The doc comment of `TestVerifyRevokeHost` no longer says it refuses a machine subject.
- No other existing test failed.

### Mutants

Run as in Tasks 1 and 2. None survived and none was equivalent.

mutant killed: M40 subjectRole(SubjectMachine) returning the user role in internal/signer/revoke.go (TestRevokeMachine/kr3_pop_cert_included)
mutant killed: M41 the signer's subject_reserved removed (TestRevokeMachine/subject_reserved_probe)
mutant killed: M42 audit's subject_reserved removed (TestVerifyRevokeMachine/revoke_machine_subject_reserved_fails)
mutant killed: M43 audit's subjectRole(SubjectMachine) returning the user role (TestVerifyRevokeMachine/revoke_machine_rederived)
mutant killed: M44 the index moving revokedAtDir on a re-listing, the keep-first line removed (TestRevokeMachine/full_revoke_quorum1_then_renew_is_disabled)
mutant killed: M45 reservedNames ignoring probe. machines (TestInstallDirectoryMachineReservations/machine_name_reserved)
mutant killed: M46 the principal-union bound removed (TestInstallDirectoryMachineReservations/machine_principals_exceed)
mutant killed: M58 the name hold removed (TestRevokeMachine/kr1_only_revoke_holds_name)
mutant killed: M59 the name hold derived from the sweep entries instead of the logged request (TestRevokeMachine/idle_machine_revoke_holds_name)
mutant killed: M60 the name hold moved before the PoP (TestRevokeMachine/name_hold_bad_pop_is_pop_invalid)
mutant killed: M61 the name hold moved before machine_disabled (TestRevokeMachine/full_revoke_quorum1_then_renew_is_disabled)
mutant killed: M62 audit skips the name hold (TestVerifyRevokeMachine/name_hold_fails)
mutant killed: M63 audit's mirror deriving the name hold from the entries (TestVerifyRevokeMachine/idle_machine_name_hold_fails)
mutant killed: M64 nameHeld set only when absent (keep-first) in the index (TestRevokeMachine/name_hold_rearmed_by_later_sweep)
mutant killed: M65 nameHeld set only when absent (keep-first) in audit's mirror (TestVerifyRevokeMachine/name_hold_rearmed_fails)

### Gates on b5ad578

- Gate 1: every subtest of Task 3's behaviour list, the 03-10 reservation test, the host revoke tests and the registry test printed `--- PASS` under `-race`; no FAIL, panic or DATA RACE.
- Gate 2: the six packages pass under `-race` (signer 433.959 s, audit 94.426 s, tlog 3.959 s, wire 8.727 s, directory 19.897 s, cert 7.598 s; a pass or fail run); the frozen paths and the capslock baseline are unchanged; internal/wire/revoke.go changes in comment lines only.
- Gate 3: golangci-lint for linux, windows and darwin, gofmt; the registry names `machine_name_reserved`.

### Threat rows (Task 3)

T-03-399, T-03-400 (the name hold) and T-03-403 are mitigated.

### Deviations (Task 3)

- `name_hold_is_per_name` uses ci3, an active machine the test adds, because ci2 is disabled in the env; the plan names ci2.
- `name_hold_rearmed_by_later_sweep` lets the certificate issued at V+1 expire past the live margin before the second sweep, so that sweep lists nothing and only the name hold can refuse (otherwise the key hold would refuse too, and M64 could not be told apart).
- `probe_certificates_untouched` adds a host named ci to the directory and issues it a probe certificate (`sub=probe.ci`).
- `no_issue_time_cutoff` lowers the machine cap to 600 s; the stored directory is then no longer authorized, which a subject revoke does not need.
- The signer's `subject_kind_unsupported` branch stays as defence in depth and is unreachable through the wire: UNVERIFIED by a test.

## Open at T1

The hold, the bound, `machine_key_unusable` and the index's revoke handling are Task 2's. The reservations and the machine subject revoke are Task 3's.

## Stopped after Task 1 (half-context rule)

Task 1 is done, gated and pushed. Tasks 2, 3 and 4 are open, and no PR is open yet. A continuation starts Task 2 from a clean tree at the head of `p03/11-machine-signer`.

- The base line above expires 24 h after `at=1794286787`. Task 4's delta gate re-measures it when it is older.
- The plan-commit ledger base is 1e57863.
- Task 2 adds `revoked` and `revokedAtDir` to the signer's `machineLatest` and to audit's `machineLatest` (see Deviations).
- The shared `readyEnv` of `TestMachineIssue` already issues for `ci` four times, so the bound tests need their own environments.

## Continued after Task 1 (2026-11-10)

A continuation took over at Task 2 from the clean head 8f1c715 and did Tasks 2, 3 and 4 in order. The sections above are Task 1's, as written then.

## Task 4

### Plan copy

The checked plan is copied byte for byte over the early 03-11-PLAN.md (`cmp` exits 0, LF, no carriage return) and committed alone first.

### Publish

- ROADMAP, Phase 3 only: the 03-11 row is ticked with the signer-half text. 03-11b is added unticked at Wave 28. 03-12 to 03-16 move to Waves 29 to 33 with their "blocked on" clauses. The Plans line says `in 33 waves`.
- The `wave:` lines of 03-12 to 03-16 are 29 to 33. Nothing else in those files changed. 03-12 still depends on 03-11.
- REQUIREMENTS.md is not touched.

requirements-completed: []
AUTH-06: open until 03-11b
REVOKE-01: open until 03-11b
Owner answers: OQ-1 OQ-2 OQ-3 OQ-4 defaults-1-to-12
T-03-405: accepted (OQ-3); the runbook sentence is 03-11b's
T-03-406: accepted (OQ-2); the runbook sentence is 03-11b's

### Test time

The base line is Task 1's (measured at=1794286787, under 24 h old when the delta gate ran). The reading is the delta gate's separate run of the six-package command on f66194f.

| Package | Base (s) | Reading (s) | Delta (s) |
|---|---|---|---|
| signer | 417.445 | 414.416 | -3.029 |
| audit | 90.637 | 99.784 | +9.147 |
| tlog | 4.204 | 4.669 | +0.465 |
| wire | 8.764 | 10.154 | +1.390 |
| cert | 10.002 | 9.818 | -0.184 |
| directory | 20.049 | 22.913 | +2.864 |

No package added more than 90 s. The whole-module `go test -race ./...` passed. It is a pass or fail run only.

### Gate controls

gate control: files gate exits 0 on the branch as committed
gate control: files gate exits 1 on a throwaway detached worktree with one commit adding an unlisted file (`unlisted-control.txt`, the only name the gate printed; the worktree was removed and its commit never pushed)
gate control: key parser reads all six keys (the sample base line `test-time base: signer=1.5 audit=2.5 tlog=3.5 wire=4.5 cert=5.5 directory=6.5 at=1` through the same g() printed 1.5, 2.5, 3.5, 4.5, 5.5 and 6.5)
gate control: roadmap gate exits 0 on the correct edit
gate control: roadmap gate exits 1 on origin/main (a throwaway detached worktree at 1e57863: no 03-11b row, the 03-11 row unticked)
gate control: roadmap gate exits 1 on a worktree that also ticks 03-12 (a throwaway detached worktree at f66194f with one commit that ticks 03-12; removed, never pushed)

### Push, the PR and CI

- **Branch:** pushed at f66194f with `env -u GITHUB_TOKEN -u GH_TOKEN git push`.
- **PR:** #95, opened by keyroster-bot through scripts/gh-as-bot.sh with the plan's title. Auto-merge is not enabled (gate checked).
- **The PR body** names the changes, the owner decisions (OQ-1 to OQ-4, defaults 1 to 12, the name hold of 2026-11-10), the deviations (pointing here), what stays UNVERIFIED, and that no route reaches the new signer request until 03-11b and that AUTH-06 and REVOKE-01 stay open until then.
- **CI on f66194f, all green:** CI 42772897020 (lint, govulncheck, the test lanes, fuzz 32m21s), E2E 42772896958, E2E distro 42772896909 (all seven distro jobs), E2E TPM 42772897148, E2E PKCS#11 42772897049, PIV 42772896890, Systemd 42772896822 (systemd-sandbox), CodeQL 42772896907, Workflow lint 42772896918, PR title 42772896843.
- **The e2e gate** (03-10b's script, `MODE=pr`) passed on run 42772896958. Its `PROBE_PASS` list is the plan's.

| Lane | 03-10d | This PR | Limit |
|---|---|---|---|
| e2e (9.5p1) | 758.538 s | 787.355 s | 900 s; no `=== RUN   TestProbe` line |
| e2e (10.5p1) | 777.304 s | 770.902 s | 900 s; no `=== RUN   TestProbe` line |
| e2e-probe (9.5p1) | n/a | 292.151 s | 420 s |
| e2e-probe (10.5p1) | n/a | 292.386 s | 420 s |

The lanes are unchanged by this plan; the differences are runner noise.

- **Local gates on f66194f:** the files gate, the author and signature gate, the wave gate, the roadmap gate, the scrub gate, the auto-merge gate, the delta gate and the whole-module gate (`go test -race ./...`, the e2e and distro vets, gofmt, golangci-lint for three GOOS, capslock, the dependency and test-only firewalls, pinned actions) all exit 0.
- **The pre-merge review** is the orchestrator's, against T-03-70, T-03-71, T-03-72, T-03-75 and T-03-397 to T-03-403. It is not recorded here yet.

## Deviations

### From the design note (copied from the plan)

The code at 1e57863 was read against the design note. No claim of the note was contradicted by the code; the differences below are scope or placement choices, additions the code review found, and one decision the note left open.
- **The 2 of 12 budget share is not here.** The scope sentence of this plan's request listed it with the signer; it is `internal/server` code (budgetSigner, `MaxServerSignerCalls`, capacity_test rows) and the note's own file split puts it in 03-11b. The signer's refusal bucket (`s.machineLimiter`) is here.
- **Added: `machine_name_reserved` at issuance (PD5).** The note refuses a `probe.` name at install and in audit; the signer had no step for a directory stored before the rule.
- **Added: audit request-ID parity in both directions (PD8)**, with mutant M39 and five subtests. The note lists only the machine verifier's direction; the signer's `RequestIDUsed` is one table across all five issuing kinds.
- **Added: the two order mutants M6 and M7** for the signer half of T-03-397 (`machine_disabled` or `machine_key_revoked` moved before the PoP).
- **Decided: recovery-carried certificates do not count toward the 12 per hour (PD3).** The note says only that they become the latest certificate; signer and audit apply the same rule.
- **Dropped: `machine_key_type_unsupported`** and its mutant (OQ-2 = keep sk); replaced by the two sk unit tests.
- **Placement:** the wire fuzzers sit in machineissue_test.go (PD7), so wire/fuzz_test.go is not touched; MachineGrant's test sits in directory/hosts_test.go (there is no authorize_test.go); `cert.MachineLifetime` is added as the one lifetime function (PD6); the reserved-names registry row is edited in Task 3 with the rule it describes.
- **Two placements the note did not give.** The reservation tests sit in machineissue_test.go (as 03-10's sit in probeissue_test.go), so signer/directory_test.go is not touched; three existing test files whose assertions flip when machine subjects resolve are added to files_modified (the note's list had none).
- **03-11b-PLAN.md is not committed here.** The note says this task adds a 03-11b plan file; the plan is made later from the 'Not done here' table. The ROADMAP row is added, the totals follow the files on disk.
- **The wave lines of 03-12 to 03-16 are edited** (03-10's precedent), because the executor reads `wave:` from the plan files; nothing else in those files changes (03-12's dependency stays 03-11). REQUIREMENTS.md is not touched.
- **Added after plan check 1 (owner decision, 2026-11-10): the name hold** (PD11) beside the key hold, with its subtests and mutants M58 to M65; Task 3 grows by about 8k tokens.
- **Mutants:** 66 here (M1 to M66) against the note's 31 and 31a for the signer half; the note's mutant 17 (a leaf-append error ignored) is M14 with the concrete fault of `failingSigner`; 31a (the index moves `revokedAtDir` on a re-listing) is M44 and, for audit's mirror, M57; 16 (request-ID reuse allowed) is M54, built to bite at the bound, because outside the bound the issuance table's unique request_id gives the same refusal; 19 (the index ignores revoke entries) is M30 for key-ID entries and M55 for serial entries. The note's `directory_changed_refused` is `directory_changed_before_commit` with M47.
- An executor's own deviation is added to the SUMMARY's `## Deviations` section when it happens.

### The executor's

The per-task deviations are in the Deviations subsections of Tasks 1, 2 and 3 above. In short:
- Task 1: `machineLatest` got no revoke fields until Task 2 (lint); `bad_principal` is refused only above `cert.MaxPrincipals`; the export fuzzer's machine seed is built under the pinned root; `TestHostForgetBody/kinds_are_a_set` was changed too.
- Task 2: the forms of `hold_equal_dir_version_still_holds` and `bad_pop_attempts_do_not_consume_the_bound`; shared environments built on first use; M28 changes two files; the bucket subtests' refusal kinds; audit's `installation_key_fails` fixture.
- Task 3: `name_hold_is_per_name` uses ci3; `name_hold_rearmed_by_later_sweep` lets the V+1 certificate expire; the host ci in `probe_certificates_untouched`; the cap in `no_issue_time_cutoff`.
- Task 4: `roadmap.update-plan-progress` (the tracking update) also ticked the 03-11b row, apparently by matching the 03-11 prefix; the tick was undone by hand before the commit, so 03-11b stays unticked as the plan requires. The plan totals are GSD's (28/33).

## UNVERIFIED

**UNVERIFIED in this repository** (nothing named above exercises it; the SUMMARY repeats the list):
- sk machine keys with a real token: the signer's handling is tested with a software sk signer with and without the user-presence flag (`TestMachineIssueSK`); a real token's touch, the agent path and the CLI's named error are 03-11b's, and a token stays UNVERIFIED until a homelab drill.
- Anything reached through the renew route: nothing anonymous can call MachineIssue yet, so rate behaviour under an anonymous flood is tested at the signer socket and through `machineIssueOrRefuse` only (T-03-398), not end to end.
- Any newer directory version releases both holds (T-03-400); `pending_disable_renew_is_cert_revoked` and `idle_machine_revoke_holds_name` pin the window. The key hold is latest-only and keep-first, so a serial revoke of an older certificate arms nothing; the name hold (PD11) covers the subject revoke whether or not a certificate was live. A key's certificates under a former name are not swept by `revoke machine NEWNAME` (T-03-72, 03-11b).
- UNVERIFIED: a restore of the signer state loses name holds armed by lost subject revoke leaves, so after a restore `revoke machine` must be run again for every machine whose disable is still pending (03-11b runbook); a subject revoke logged after a name was re-added with a new key holds that new key until a newer directory version, so an admin sweeps before re-adding.
- `machine_name_reserved` and `machine_principals_exceed` at install are signer-only, as 03-10's `principal_reserved` and `account_reserved` are: `audit verify` does not re-check them on a directory_install and enforces their consequences at issuance (`probe_name_fails`, the principals through `checkIssue`) and at subject revoke (`subject_reserved`).
- A recovery may keep a lost non-probe machine certificate (`krl.CheckCarriedLost`); `revoke machine` cannot cover a kept one, because it is not in the issuance table (T-03-404). The recovery path is covered by unit tests only (as 03-10's R9) and UNVERIFIED end to end.
- The 12-per-hour bound counts a future issuance second after a clock step back (the safe side, PD4); the interplay with a long clock step is not exercised.
- Audit stub coverage: the rules named as "shown by the audit stub" have no individual mutant (the list is in the mutant paragraphs of Tasks 1 and 2); the mutants cover the proof of possession, the lifetime, the principals, the entry key, the `probe.` name, the request-ID namespace, the hold, the bound, the carried-certificate mirror, the export binding and the subject revoke.
- A log that already holds a machine certificate with `sub=probe.<x>`: none exist (03-10 Q4, owner-confirmed for the owner's installations); `audit verify` on any other log would now fail such a leaf. UNVERIFIED beyond those installations.
- The signer package's test time under `-race` with the 12-issuance tests: gated by the 90 s delta, measured in Task 4.
- Windows and macOS: no Windows or macOS code or CI change here; the signer is Linux-only and its tests carry `//go:build linux`.
- The signer's `subject_kind_unsupported` branch for a machine subject is unreachable through the wire and has no test (Task 3).
- The 03-11b row of ROADMAP has no plan file yet; GSD's plan totals follow the files on disk.

## For 03-11b

| Item | Where it goes |
|---|---|
| The renew route `POST /api/v1/machine/renew` (internal/server/machine.go, server.go): unauthenticated; a per-client limiter with a global backstop (30 per minute, burst 10); a 16 KiB body cap (`MaxMachineIssueBody`) and strict decoding; with pop.machines off in the cached status, 403 `machine_pop_not_enabled` and no signer call (the `popHostsEnabled` precedent, server/agent.go:161); the call through `signerAPI` to `signerclient.MachineIssue` (landed here), under `signerCallTimeout`; answers mapped as `agentSignerFailed` maps them (server/agent.go:925-943), `signer_too_old` for `unknown_message_type`, never `dropKRL` (server/revoke.go:96-101) | 03-11b |
| The server's collapse of the three identity details (`unknown_machine`, `machine_key_mismatch`, `machine_pop_invalid`) into one `machine_not_authenticated`, with the specific detail in the server's own log (default 1, T-03-397; the signer half is here) | 03-11b |
| The signer-call budget: a machine share of 2 of the 12 tokens taken before the total token (`MaxServerSignerCalls` = 12, wire/frame.go:52; agent share 6, server/signer.go:141-145; budgetSigner's named field :183-193), `signerAPI`, `socketSigner`, `budgetSigner`, `fakeSigner`, `gateSigner`; capacity_test rows (:74, :205-216, :241-244, :315-316) | 03-11b (server code; owner D6). The signer's own refusal bucket is here |
| routes_test.go `otherRoutes` entry for the new pattern with an honest reason (machine proof of possession, decided by the signer; no session, no login code, no user certificate) and the fix of its doc comment (:33-35, :36-58, :92-105); `serverclient.MachineRenewPath` and the body and answer types | 03-11b |
| `keyroster machine renew NAME (--agent-key FP \| --key FILE [--passphrase-fd N]) --out CERTFILE [--expect-principal P]... [--if-due]` and `machinekey.go`: needs `keyroster init` without `--user`; refuses early without pop.machines; F11 (T-03-244): 64 KiB bound `maxMachineKeyFileBytes` and `key_file_too_large` before parsing, `ssh.ParseRawPrivateKey`, `rootceremony.ReadPassphrase` only on a passphrase-missing error with its terminal check, buffers and the Ed25519 key cleared, no secret in any error; an sk key file gives a named error and an sk key renews only through `--agent-key` with a touch (OQ-2); the answer is checked against a machine CA key of the root-verified bundle (`krl.RoleCAKeys(bundle, "machine")`), the request's key, the kr3 key ID (ca machine, sub NAME, the request's req, pol equal to the bundle's), ValidAfter within 300 s and a lifetime between 60 s and the machine cap, and every `--expect-principal`; written by temp file plus rename, certificate only, 0644, never the private key (TestMachineRenewNeverWritesKey with a mutant); `--if-due` skips while now is before issued + 2/3 of the lifetime minus min(1 h, lifetime/10); one refusal text per detail, `machine_not_authenticated` included | 03-11b |
| `keyroster revoke machine NAME [--keys] [--yes] [--out DIR] [--reason TEXT] [--admin-key FP]` as `runRevokeHost` (cmd/keyroster/revoke.go:579-777) with SubjectMachine and the machine entry: `checkHostTrustFloor` reused as `CheckBase` (:659-663, :776-783) with `TestRevokeMachine/stale_base_refused_no_key_revoked`; `--keys` as separate TargetKey requests, a key omitted at the cap and exit 3 (:710-728, :820-843); an unknown or removed name a partial run, exit 3; the pending-proposal exit 4 whose text names the `cert_revoked` hold; `recoveryKeptNotice`; the `subject_kind_unsupported` text (:975); `machine remove` prints a hint that names `keyroster revoke machine NAME` (OQ-4) | 03-11b |
| e2e `TestMachineIdentityEndToEnd` (test/e2e/machine_test.go, both OpenSSH lanes, `-timeout 20m`, under the 900 s stop): PoPMachines merged into the PoPHosts struct of the bootstrap (bootstrap_test.go:52-55, :250-259; server_test.go:58-60, :99), the harness of revoke_test.go (a real sshd whose RevokedKeys file the test renames into place, no agent), a renew, the login, `revoke machine`, the refused login, `machine_disabled` on the next renew, `--keys` on a second machine and `machine_key_revoked`, `audit verify`; the sk-dummy step through a real ssh-agent as TestRootSK does (root_sk_test.go:24-31, :130-135) | 03-11b |
| Runbooks: machine-identities.md (:13-16 "issues nothing", :27, the rotate recipe :76-83 with a `revoke machine` step when the old key may be compromised (OQ-4), :109-119), sk keys as "interactive renewal" and unattended jobs needing Ed25519 or ECDSA (a file, an agent, or PIV through the agent), unattended renewal and passphrases (F11), an example systemd timer and cron line labelled UNVERIFIED, "After revoke machine" (what is refused, the hold, `--keys`, the kept-certificate notice); revoke.md (:318, :441, a `revoke machine` section, the `subject_reserved` row, machine wording in the explicit-key cap section); the source_address residual T-03-405 (OQ-3) and T-03-406 | 03-11b |
| `cmd/keyroster/audit.go` text line for machine certificates (as 03-10c did for probes); optional | 03-11b |
| AUTH-06 and REVOKE-01 complete: REQUIREMENTS.md ticks and traceability rows, `requirements-completed: [AUTH-06, REVOKE-01]` | 03-11b |
| The mutants of the route and the CLI: the server passes `unknown_machine` through; the server calls the signer with pop.machines off; MachineIssue in the total pool only; `dropKRL` on 5xx; the CLI writes the private key; CERTFILE written in place; a 64 KiB + 1 file parsed; a passphrase read from a non-terminal stdin; the CLI skips the CA-key check; the `--keys` omission not reported; `--if-due` sends when not due; `revoke machine` without the base floor | 03-11b |
| T-03-73's route half, T-03-74, T-03-244, T-03-397's server half, the runbook sentences of T-03-405 and T-03-406 | 03-11b |
| A renamed key's earlier-name certificates: `revoke machine NEWNAME` sweeps `sub=NEWNAME` only, so certificates the same key obtained under a former name stay live up to the cap (T-03-72, plan check 1 sec-08). The CLI's `revoke machine` output or the runbook must say that `revoke machine OLDNAME` or `--keys` is needed after a rename; optionally the CLI sweeps the former names of the key | 03-11b |
| The pending-proposal exit 4 text names both holds (the key hold and the name hold, default 2 amended) and what releases them (any newer directory version), and points to `--keys` for the permanent block; it and the runbook also say that after a restore of the signer state `revoke machine` is run again for every machine whose disable is still pending, and that a machine is swept before it is re-added with a new key | 03-11b |
| CLI tests run portably on the linux, windows and macos lanes with the environment setup of login_disk_test.go:37-56 (design G23); Windows `--agent-key` through the named pipe is UNVERIFIED unless a fake-agent case runs on the windows lane | 03-11b |
| The statement, for the SUMMARY and the runbook, that ECDSA private-key big integers cannot be cleared reliably in Go (the Ed25519 key and the buffers are cleared), with the `parse_clears_buffers` subtest | 03-11b |
| The e2e lane budget estimate (+40 to 60 s per lane, estimated, not measured) and the note that the `revoke machine` generation narrows access and so applies at once | 03-11b |
| Not planned at all: a per-name limiter on the route (it would let an anonymous caller lock a machine out); a signed client-side directory for principal checks; a per-machine source_address or force-command (OQ-3); an automatic revoke on `machine remove`, a key change or a role loss (OQ-4); a machine view in the audit report beyond Report.Certificates and the export (Phase 4); a change to `ca issue --ca machine` (kr1); clearing pop.machines; machine-only CA rotation behaviour (03-12 takes the CA set as an input); the installation-binding test over every signed request type (a later Phase 3 plan; MachineIssueRequest carries the ID, so it passes there without an exemption); the ceremony's pop.machines carry (03-15, unchanged) | Not planned or later plans, as stated |

## Self-Check: PASSED

- The commits T1 7dafbe2, T2 a037604 and T3 b5ad578, the plan copy and the wave commit f66194f are ancestors of HEAD, and the branch is pushed.
- The files the tasks created exist: internal/wire/machineissue.go, internal/signer/machineissue.go, internal/signer/machineindex.go, internal/signer/revoke_machine_test.go, internal/audit/machineissue.go, internal/cert/machinerecent.go and the two vectors.
- `commits: 9` is `git rev-list --count 1e57863..HEAD` measured at f66194f, before this docs commit.
