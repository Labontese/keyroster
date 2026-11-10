---
phase: 03-linux-agent-and-revocation
plan: 11
status: in-progress
requirements-completed: []
---

# Phase 3 Plan 11: machine certificates by proof of possession, signer half (draft)

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

## Open at T1

The hold, the bound, `machine_key_unusable` and the index's revoke handling are Task 2's. The reservations and the machine subject revoke are Task 3's.

## Stopped after Task 1 (half-context rule)

Task 1 is done, gated and pushed. Tasks 2, 3 and 4 are open, and no PR is open yet. A continuation starts Task 2 from a clean tree at the head of `p03/11-machine-signer`.

- The base line above expires 24 h after `at=1794286787`. Task 4's delta gate re-measures it when it is older.
- The plan-commit ledger base is 1e57863.
- Task 2 adds `revoked` and `revokedAtDir` to the signer's `machineLatest` and to audit's `machineLatest` (see Deviations).
- The shared `readyEnv` of `TestMachineIssue` already issues for `ci` four times, so the bound tests need their own environments.
