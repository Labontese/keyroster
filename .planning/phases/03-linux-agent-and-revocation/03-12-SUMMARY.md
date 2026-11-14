---
phase: 03-linux-agent-and-revocation
plan: 12
subsystem: signer
tags: [ca-rotation, generations, restore-gate, audit, doctor]
status: complete
requires: [03-14d]
provides:
  - ca_key_generations (migration 0006) and the ca_generation leaf (kind 14)
  - keyroster-signer ca-rotate prepare and signer.PrepareGeneration
  - keystore.GenerationProvisioner, keystore.GenerationBackend and keystore.KeyFor
  - generations_not_logged at start and in doctor; generation-based checkBundleKeys, checkPolicyAdmins and checkStoredTrust
  - audit verify and export of ca_generation; the CA generations line
  - the restore-recovery-pending gate, recover-revocations --no-recovery-needed and --migrate-only, the journal record
  - bundle_issued_in_future at install; doctor's marker, generations, unrecorded-file and issued_at results
affects: [03-12b, 03-12c, 03-12d, 03-12e, 03-12f, 03-13, 03-15, 03-16]
tech-stack:
  added: []
  patterns: [optional backend interfaces selected by KeyFor, one exempt lock variant for recovery]
key-files:
  created:
    - internal/signerdb/migrations/0006_ca_generations.sql
    - internal/signer/rotate.go
    - cmd/keyroster-signer/rotate.go
    - test/vectors/leaf_ca_generation_v1.hex
  modified:
    - internal/signer/trust.go
    - internal/signer/logstate.go
    - internal/audit/verify.go
    - cmd/keyroster-signer/lock.go
    - cmd/keyroster-signer/recover.go
    - docs/runbooks/signer-install.md
decisions:
  - "The custody of a key the backend will create (prepare without --key) is taken from the opened log key and compared with generation 1's before anything is created"
  - "TestSignerRestartMixedBundle/software writes its generation-1 key files at a low scrypt work factor so the package stays inside the 90 s test-time budget; the generation-2 file stays at the production factor"
  - "The capslock baseline of keyroster-signer records five new (package, capability) pairs; the binary's capability set is unchanged"
requirements-completed: []
metrics:
  duration: about 7.5 h
  completed: 2026-11-14
actuals:
  tokens: 176000
  tasks: 5
  commits: 13
plan_head_before: d15f04463beb850cc169a23b5367db0c7deb456a
plan_head_after: db070831623ab139cea8c6022b991508f64661ac
---

# Phase 3 Plan 12: CA key generations and the restore gate Summary

The signer holds every CA key as a numbered generation that the log records (migration 0006, kind 14, `ca-rotate prepare`, generation-addressed keys), refuses to start when the rows and the log disagree, audit verifies and exports the generations, every writer of the state refuses under a restore marker until a recovery or an explicit release, and install-bundle refuses a bundle dated more than 300 s ahead.

test-time base: cli=301.365 signercmd=2.365 signer=444.239 audit=99.311 at=1794686865

## Execution log

- Preconditions (Task 1): stop guard, base values, free names, code anchors, the 16 pointer anchors and the threat IDs all passed on origin/main d15f044; the six plan files were placed in the phase directory.
- Base: measured on the unchanged tree; the go build of the four packages ran before any source edit (the R1 test file, written while the run was going, was not compiled into it: cmd/keyroster-signer passed in 2.4 s, and with rotate_test.go it would have failed).

## Task 1

- R1 = 306caa73125f841aa13dbbee120dd196f4405b99 `test(signer): pin the ca-rotate prepare path end to end and kind 14 as a valid kind`. Declares nothing (kind 14 as `tlog.Kind(14)`).
- RED (worktree of R1): `--- FAIL: TestCARotatePrepareTracer` with `keyroster-signer: unknown command "ca-rotate"`; `--- FAIL: TestRecoveryBody/kinds_are_a_set`; `--- FAIL: TestMachineIssueBody/kind_constants`. No build or setup failure, no timeout.
- Passed on R1 (control): `TestHostForgetBody/kinds_are_a_set`, because its edit only removes 14 from the kinds that must be refused, which relaxes the test.
- T1 = 33682c4f943ef97f2aec5c1596f3d3d5552d1437 `feat(signer): record CA key generations and add ca-rotate prepare`. Changes no test and no vector (`git diff --name-only $R1 $T1 -- '*_test.go' test/vectors` is empty).
- T1 verify 1 green (tracer, TestStateDirLock, TestDoctorAfterCAInit, TestDoctorFailures, TestFormatRegistry, the three kind-14 tests, TestStatusWriters, TestStatusLockFree, TestStatusSnapshot, signerdb, keystore, tlog, TestSignedRequestsBindInstallation). Verify 3 was green (internal/signer 410.390 s, internal/audit 97.822 s, internal/signerdb 3.019 s, TestRestoreRunbookChecks) on the working tree before T1 was committed, while signer.go still routed pinnedKey through KeyFor (a behaviour-equal edit that was then reverted, so that signer.go stays outside the file list); the rerun on a clean worktree of T1 passed every package but internal/signer, which hit the clock flake below. T2a's whole-package run of internal/signer, a superset of T1's code paths, passed.
- Verify 4 as written exits 1: its `git grep '"keyroster/'` over the whole of internal/tlog/leaf.go matches two lines that are on main already (`const LeafDomain = "keyroster/log-leaf/v1"` and its doc comment). The check's stated intent (no file this task touches adds such a literal) holds: `git diff $R1 $T1 -- <the four files> | grep '^+' | grep '"keyroster/'` prints nothing. Deviation in the check's scope only; LeafDomain is unchanged.
- Schema 5 upgrades by the seed in migration 0006 (pinned by Task 2's TestMigrations/upgrade_from_v5).
- Choice not fixed by the plan: on the provisioner path (no `--key`), the custody of the key the backend will create is taken from the opened log key (the same backend holds all five keys) and compared with generation 1's custody before anything is created, so a custody mismatch leaves no file.
- One-way cost (reversibility): kind 14 and migration 0006 are allocated for good, and a database at schema 6 is refused by every older binary.
- A rerun of verify 3 on a clean worktree of T1, under heavy load from other runs, failed once in TestCheckLogAgainstLiveSigner with `unavailable: clock_regression` (the issuing goroutine saw the WSL clock behind the last leaf). It passed in the first verify 3 run and in every later whole-package run of internal/signer; the test and the clock path are untouched by this plan.

## Task 2

- R2a = ed07d6ce366b24a90cfe26e73a8661b062844caa `test(signer): pin generation checks at install, start and export`. Declarations added: `LogSnapshot.CAGenerations []CAGeneration` (not filled) and `errGenerationsNotLogged`. Vector test/vectors/leaf_ca_generation_v1.hex created under `-update`, sha256 bbdc061411eb906ab84888246099ce917c953fbe839edb38db944892a12614c8.
- RED of R2a (worktree): the nine `--- FAIL:` lines TestCheckBundleKeysGenerations/{generation_field_mismatch_refused, admin_equal_stored_generation_refused, root_equal_stored_generation_refused}, TestGenerationsLogged/{row_without_leaf_refused_at_start, leaf_without_row_refused_at_start, row_altered_refused, refused_by_check_trust, refused_by_check_log}, TestCAGenerationTables/snapshot_reads_generations; nothing else failed. Controls that passed on R2a, with why: TestCheckBundleKeysGenerations/{non_active_entry_refused, active_not_generation_1_refused, generation_1_active_accepted}, TestSuccessorForeignCAKeyRefused and TestCheckStoredTrust (d15f044's checkBundleKeys already refuses those bundles and edits); TestPrepareGeneration (all, including key_equal_earlier_root_refused, refusal_before_provision_leaves_no_file, refusal_by_log_check_before_provision_leaves_no_file, location_persisted_and_passed, row_and_leaf_one_transaction: T1's PrepareGeneration does it); TestSignerRestartAfterPrepare including restart_passes_the_rows_location (T1's loadTrust); TestGenerationsLogged/matching_rows_ok; the signerdb, keystore, tlog and cmd tests (T1 built the table, KeyAt, the body and the command).
- T2a = 470953df17995c884e0abfb2f4730d597e288b43 `feat(signer): check every generation at install, start and in doctor`. No test changed. Whole packages on the T2a tree: internal/signer 515.233 s, signerdb, tlog, keystore/..., cmd/keyroster-signer 173.742 s (under load), all ok.
- R2b = 149767455a2f29e3631b556e2e5e90fc3dd11155 `test(audit): pin the generation rules of audit verify and its export`. Declares nothing.
- RED of R2b (worktree): exactly the fifteen named `--- FAIL:` lines. Passed on R2b, with why: TestVerifyCAGeneration/{ca_generation_ok, genesis_ca_init_is_generation_1, ca_init_then_unchanged_successor_ok, ca_init_recorded_without_refusal, log_without_ca_init_still_verifies, next_logged_ok} (T1's case accepts the leaf and nothing refuses yet), /line_with_policy_version_refused (the bound-value rules already refuse a stray policy_version), TestVerifyOutputCAGenerations/no_line_when_none, and the FuzzVerifyExport seeds.
- T2b = 7ffc235dafb5ceed711f1e40d06bc62baaff12a7 `feat(audit): verify and export CA generations`. No test changed.
- Task 2 verify 1 green with every named PASS line; verify 2 (the RED gate as written, both worktrees) exits 0; verify 3: internal/signer 444.898 s, internal/audit 95.349 s, signerdb, tlog, keystore/..., cmd/keyroster 289.371 s, cmd/keyroster-signer 22.587 s, and the three fuzz targets 20 s each without a failure; verify 4 exits 0.
- Deviation, test-only commit 4b5c92c `test(signer): keep the production-factor scrypt test inside the test-time budget`, after T2b (so the R2b..T2b gate stays test-free): TestSignerRestartMixedBundle/software took 119.79 s under -race when run alone (cmd/keyroster-signer 121.3 s against a base of 2.365 s, above the delta gate's 90 s). Its five generation-1 key files are now written by the test at scrypt work factor 10, in the software backend's file format, and selected with `ca-init --key`; the generation-2 file that `ca-rotate prepare` creates stays at the production work factor, so the test is still the one of its package that runs production scrypt. After: 18.13 s under -race. Every assertion of the plan's list is unchanged. M117 was re-run against it and is still killed (below).

### Task 2 mutants (each: unmutated run ok, go vet ok, restored, sha256 equal, `git status --short` lists only .planning/config.json and 03-12-PLAN.md, which predate the run)

Unmutated commands: internal/signer set ok (1.786 s), TestProvisionGeneration ok, TestSignerRestartMixedBundle ok.

| Mutant | File (sha256 before = after) | Killed by |
|---|---|---|
| M111 generation field not compared | internal/signer/trust.go 5a27a775...6deb2 | TestCheckBundleKeysGenerations/generation_field_mismatch_refused (alone) |
| M112 admins over generation 1 only | trust.go 5a27a775...6deb2 | TestCheckBundleKeysGenerations/admin_equal_stored_generation_refused |
| M113 leaf in a separate transaction | internal/signer/rotate.go c7c679b7...ca414 | TestPrepareGeneration/row_and_leaf_one_transaction |
| M114 cross-check skipped (both sites) | internal/signer/logstate.go 76f7e123...b111e | TestGenerationsLogged/{row_without_leaf_refused_at_start, leaf_without_row_refused_at_start, row_altered_refused, refused_by_check_trust, refused_by_check_log} |
| M117 KeyAt opens generation 1's file | internal/keystore/software/software.go 0f557d34...92183 | TestProvisionGeneration/{keyat_opens_own_file_only, keyat_ignores_location}; TestSignerRestartMixedBundle/software (before and after 4b5c92c: "KeyFor generation 2: pinned CA key not present ... user.age") |
| M122 foreign-key comparison skipped | trust.go 5a27a775...6deb2 | TestSuccessorForeignCAKeyRefused/{user, host, machine} |
| M180 roots of the installed bundle only | rotate.go c7c679b7...ca414 | TestPrepareGeneration/key_equal_earlier_root_refused |
| M183 ca_keys vs generation 1 skipped | trust.go 5a27a775...6deb2 | TestCheckStoredTrust/{ca_keys_key_edited_refused, ca_keys_alg_edited_refused, ca_keys_custody_edited_refused, ca_keys_edit_refused_by_check_trust} |
| M187a provision before the log key opens | rotate.go c7c679b7...ca414 | TestPrepareGeneration/refusal_before_provision_leaves_no_file (and /refusal_by_log_check_before_provision_leaves_no_file, /location_persisted_and_passed) |
| M187b provision between openRoleKey and newLogWriter | rotate.go c7c679b7...ca414 | TestPrepareGeneration/refusal_by_log_check_before_provision_leaves_no_file (and /location_persisted_and_passed) |
| M189 empty location stored | rotate.go c7c679b7...ca414 | TestPrepareGeneration/location_persisted_and_passed |
| M190 loadTrust passes an empty location | trust.go 5a27a775...6deb2 | TestSignerRestartAfterPrepare/restart_passes_the_rows_location |
| M115 generation compared with < instead of +1 | internal/audit/verify.go dc4d4e21...aeb86 | TestVerifyCAGeneration/{ca_generation_not_increasing_refused, ca_generation_skips_a_number_refused} |
| M116 next rule skipped | verify.go dc4d4e21...aeb86 | TestVerifyCAGeneration/bundle_next_not_logged_refused |
| M184 active rule skipped | verify.go dc4d4e21...aeb86 | TestVerifyCAGeneration/{active_not_logged_refused_when_ca_init_precedes, genesis_active_not_ca_init_refused} |
| M185 role check skipped | verify.go dc4d4e21...aeb86 | TestVerifyCAGeneration/unknown_role_refused |
| M186 before-bundle check skipped | verify.go dc4d4e21...aeb86 | TestVerifyCAGeneration/before_first_bundle_refused |

Full hashes: trust.go 5a27a7752608d66e7d8d965224dc0b5238b49de68f81a2fc2ebebb6e2576deb2; rotate.go c7c679b7596cd471fd493d1db230ddc4fba8eed8f5a670dca904aee882fca414; logstate.go 76f7e1238c785173477cd54154c4c05717efb30df36bf2d65e6d721d689b111e; software.go 0f557d34bb05af258c9f63a0f977bac40618d7b47962562c8072e6ded8e92183; audit/verify.go dc4d4e2105c6484bf6400813d8cc24d0b3c384c66fb9e6e11fbe15f9446aeb86. The 2a mutants ran with HEAD at R2b (the signer code is T2a's), the 2b mutants with HEAD at T2b.

## Task 3

- InstallBundle caller inventory (before T3, `git grep -n -E 'InstallBundle\(|Bootstrap\(' -- '*_test.go'`): fixture_test.go:198 (Bootstrap) with its caller's clock; generations_test.go:95 and :139 (nil); hostissue_test.go:403 (e.clock.Now, a revokeClock started at now truncated to the second plus 500 ms, advanced 1 ms before the install); log_test.go:112 (newLogEnvClock's clock: nil, `at` = now truncated (evidence_test.go:170), stepClock at now (log_test.go:539), tickClock from now's whole second (login_test.go), tickingClock at now's whole second (krlloop_test.go), revokeClock at now truncated plus 500 ms (revoke_test.go, hostissue_test.go)); log_test.go:415, rotate_test.go:59, trust_test.go:336, :598, :671 (nil); signer_test.go:216 (ts.opts.clock: a fakeClock at now truncated, ticking). Every clock starts at the real now and moves forward; every genesis is issued at now truncated and a successor one second later. No test failed with `bundle_issued_in_future`, so no R3b commit and no test file was changed for it.
- R3 = 2045a5c24ad18a462654a68e8253ee4ffa6dbae3 `test(signer): pin the restore marker gate and the install refusal for a future issued_at`. Declarations added: in cmd/keyroster-signer `restoreMarkerName`, `errRestorePending`, `lockStateDirForRecovery` (calling lockStateDir), `applyRecovery` (which recoverRevocations now calls), `journalSocketPath` and an empty `journalNotice`; in internal/doctor the Facts fields `Generations`, `RestoreMarker`, `UnrecordedGenerationFiles`, the type `GenerationFact` and the codes `CodeRestorePending`, `CodeInstalledIssuedAfterNow`, `CodeUnrecordedGenerationFile`. restoreFilesScript gained the two marker lines; TestRestoreRecoversLostRevocations gained the marker assertions (CI only).
- RED of R3 (worktree): exactly the thirty-one named `--- FAIL:` cases (no build or setup failure, no timeout). Passed on R3, with why: TestRestoreMarker/{recover_refused_keeps_marker, recover_apply_error_keeps_marker, export_allowed_under_marker} (nothing removes a marker or blocks an export yet); TestDoctorRestoreMarker/absent_no_line, TestDoctorInstalledIssuedAt/{not_after_now_ok, unparseable_is_skipped}, TestDoctorGenerationFiles/none_no_line, TestDoctorUnrecordedGenerationFile/{recorded_file_no_warn, no_software_dir_no_warning} (no result is the expected outcome); TestInstallIssuedAtAhead/{issued_at_at_margin_ok, issued_at_sub_second_at_margin_ok} (nothing refuses yet).
- T3 = 6ab47156efefe5eed8e455b370ed1ff0f274e3d4 `feat(signer): refuse state writers after a restore until recovery, and refuse a future-dated bundle`. No test or vector changed (`git diff --name-only $R3 $T3 -- '*_test.go' test/vectors` empty), and serve.go, cainit.go, install.go, commands.go and status.go are unchanged since R1.
- T3 verify 1 green with every named PASS line (TestRestoreMarker's cases, TestStateDirLock, TestInstallIssuedAtAhead's, TestRestoreRunbookChecks), `bash -n test/systemd/smoke.sh`, go vet (also -tags e2e) and gofmt; verify 3: internal/signer 412.188 s, internal/doctor 1.059 s, cmd/keyroster-signer 25.586 s; verify 4 (choke points): `recover.go:1 serve.go:2` and `lock.go recover.go`; verify 5 exits 0.

| Mutant | File (sha256 before = after) | Killed by |
|---|---|---|
| M118 lockStateDir ignores the marker | cmd/keyroster-signer/lock.go 7ac4dc1e6d81ce20d2c12ea0ef61e30b0a2d08bc3d5700baf96635e77a72688f | TestRestoreMarker/{install_refused_under_restore_marker, serve_refused_under_restore_marker, prepare_refused_under_restore_marker, cainit_refused_under_restore_marker} (and refused_lock_is_released, marker_symlink_counts, marker_is_directory_counts, schema5_restore_migrates_under_marker) |
| M119 the marker stays after a successful recovery | cmd/keyroster-signer/recover.go 26e4636ab343be947bf7a571086d02f41f083cda18b3aaee9ab7a547aa8a946f | TestRestoreMarker/recover_allowed_and_clears_marker (and nonempty_directory_marker_says_remove_by_hand, release_is_journaled); the real-path half is TestRestoreRecoversLostRevocations in the CI e2e lanes |
| M120 bound by the clock without the margin | internal/signer/trust.go 218ff28959411dbc1b0a63126eccc0c11ccf2dc7297a51aa52d0866f9b5104af | TestInstallIssuedAtAhead/{issued_at_at_margin_ok, issued_at_sub_second_at_margin_ok} |
| M121 issued_at check skipped | trust.go 218ff289...104af | TestInstallIssuedAtAhead/{issued_at_ahead_refused, genesis_issued_at_ahead_refused} (and the two other refusals) |
| M181 --migrate-only ignored (reads stdin, applies a recovery) | recover.go 26e4636a...a946f | TestRestoreMarker/schema5_restore_migrates_under_marker (blocked on standard input, 20 s guard), and the other migrate_only cases |
| M182 --migrate-only removes the marker | recover.go 26e4636a...a946f | TestRestoreMarker/{migrate_only_writes_nothing_else, schema5_restore_migrates_under_marker} |
| M188 journalNotice returns at once | recover.go 26e4636a...a946f | TestRestoreMarker/release_is_journaled (and recover_allowed_and_clears_marker, no_recovery_needed_clears_marker); journal_unavailable_is_not_an_error passes under it |
| M191 --migrate-only skips the regular-file check | recover.go 26e4636a...a946f | TestRestoreMarker/{migrate_only_requires_existing_db, migrate_only_refuses_symlink_signer_db} |

Each: unmutated runs ok (TestRestoreMarker 2.430 s, TestInstallIssuedAtAhead 0.235 s), go vet ok, restored with `git checkout -- <file>`, sha256 equal, `git status --short` lists only .planning/config.json and 03-12-PLAN.md (both modified before the run, never staged).

## Task 4 (so far)

- Stop guard re-run after `git fetch origin`: passes (origin/main d15f044 unchanged); the pointer anchors were found exactly once each.
- Runbook commit 0bc85229b19848b4bde70d9b59992df820257f11 `docs(runbooks): record CA key generations, the restore marker and the future issued_at refusal` (signer-install.md: the upgrade paragraph, "Prepare a CA key generation", the issued_at paragraph, three doctor rows and the `OK generations` sentence, restore paragraphs 1, 1b, 1c, 1d and 2, the reworded recovery_import_invalid entry; custody.md's generation-file sentence). The runbook gate passes: every phrase, the no-downgrade paragraph with its Run in CI and UNVERIFIED labels, custody.md, the registry row 14, no added `audit verify` line, tlog and TestRestoreRunbookChecks.
- Publish commit bd66716540a2bea88a3a641d9a2627ffed2061fd `docs(03-12): publish the plan set, point 03-13 to 03-16 at it, and shift the later waves`: the six plan files (byte-identical to the reviewed set), ROADMAP by hand (32/42, 41 waves, the five new wave blocks, 03-13 to 03-16 at 38 to 41), STATE (`total_plans: 77`, `Plan: 32 of 42`), 03-13 (10 changed lines), 03-14 (1), 03-15 (3), 03-16 (3).
- Deviation in the publish commit: the pre-push scan (kr-scan) refused 03-15-PLAN.md line 183, the line the plan's second 03-15 insertion goes on, because that line already names the owner's workstation by its host name twice (text that is on main). The insertion is made as written, and on the same line both host names are replaced by "the owner's workstation"; the line count stays 3 changed lines (numstat `3 3`). The commit was amended before the first push (bd66716540a2bea88a3a641d9a2627ffed2061fd). The plan's PR-text scan (Task 4 verify 9) greps the whole diff, context and removed lines included: on this branch it matches only text that is on main (a context line of 03-15 that names the same host, the removed form of line 183, and the existing doc comment of the Result type in internal/doctor/doctor.go, next to an edit); no added line matches, which is the scoped check recorded here.
- Test-time delta gate (base cli=301.365 signercmd=2.365 signer=444.239 audit=99.311, same session and WSL boot, about 1.5 h old): cmd/keyroster 253.362 s, cmd/keyroster-signer 27.108 s (+24.7 s), internal/signer 416.295 s, internal/audit 98.372 s; every package within 90 s of its base.
- Threat IDs: T-03-76 to T-03-81, T-03-245 to T-03-247 and T-03-413 to T-03-432 are each defined in exactly one of the six plans; no renumbering. The private-term and label scans of the six plan files and of the runbook's added lines print nothing.


## Task 4: gates after the publish commit

- The full gate: `go test -race -count=1 -timeout 15m ./...` passed (internal/agent/apply 594.231 s), every `go vet` variant, `bash -n test/systemd/smoke.sh` and gofmt passed. golangci-lint then reported issues in this plan's files only (gosec G304, G302, G703 and G115 in test files, staticcheck QF1002 in software.go's keyPathAt and QF1008 in generations_test.go); fixed in e5d2d52 `style(signer): satisfy golangci-lint for the generation code and tests` (annotations with reasons, a tagged switch, a promoted method), after which golangci-lint reports 0 issues and the touched packages' tests pass again.
- capslock reported five new (package, capability) pairs for keyroster-signer: internal/signer gains CAPABILITY_READ_SYSTEM_STATE, CAPABILITY_SYSTEM_CALLS, CAPABILITY_UNANALYZED and CAPABILITY_UNSAFE_POINTER, and internal/trust gains CAPABILITY_UNSAFE_POINTER. The binary's capability set is unchanged (main already reports every one of them). The capslock graph shows new edges from this plan's code into those packages: `applyRecovery`'s closure (`init$1`) to `(*Signer).RecoverRevocations`, and `prepareFileBytes` to `trust.CanonicalJSON`; the plan's own seam and file format require both. Recorded as a deviation and written to the baseline with `scripts/capslock-check.sh --update` in db07083 `chore(capslock): record the keyroster-signer pairs of ca-rotate prepare and the issued_at bound` (the commit title names the issued_at bound as a likely cause too, which is not proven); the owner reviews the pairs in the PR. On origin/main the check reports 91 pairs against a baseline of 92 (the stale pair that 03-14c recorded); after the update the baseline holds 97.
- dep-firewall, testonly-firewall and check-pinned-actions pass. The pre-push scan passes on every new commit.
- Authorship: every commit is authored by Daniel Gustafsson <121555671+Labontese@users.noreply.github.com>, committed by keyroster-bot, has a gpgsig header and carries no attribution line.
- `ca issue` sites: this plan adds and edits none (no `ca issue` call in its files, test/systemd/smoke.sh included).

## What stays UNVERIFIED

- Every runbook text on the homelab signer.
- The marker block's `touch` and `chown` on the real units outside CI (the systemd-sandbox job runs them).
- A real recovery that carries a certificate on the homelab signer.
- The journal entry on a real journal (tests use their own unixgram listener).
- The migration of a real schema-5 backup under the marker (tested with a database reduced to schema 5 by SQL; smoke.sh runs `--migrate-only` on a current database only).
- The tpm and piv paths (03-12f; prepare refuses them by name).
- The VM-snapshot restore (it carries no marker).

## Reconcile ledger

Read at execution against origin/main d15f044: every row of the plan's reconcile ledger held as written (the hold block pinned in three places and reused for backups, no audit fixture with a ca_init entry before a bundle, no TrustedUntil in trust.CAEntry, status.go and commands.go needing no edit, the four registered backends, Provision refusing while any `.age` file exists, the anchors of InstallBundle, loadTrust and checkStoredTrust). Lines that differed: none that changed the work. 03-15-PLAN.md line 183 names the owner's workstation by its host name on main, which the pre-push scan refuses on a changed line (see the publish-commit deviation).

## PR and CI

- PR #102 `feat(signer): record CA key generations and gate state writers after a restore`, opened by the bot, without auto-merge (`autoMergeRequest` is null). The title passes scripts/check-pr-title.sh.
- CI on the code head db070831623ab139cea8c6022b991508f64661ac: CI 43645436170 (build-test, lint, capslock, dependency-firewall, govulncheck, cli-windows, cli-macos and the rest pass; its fuzz job was still running when the SUMMARY commit superseded the head), E2E 43645436171, E2E distro 43645436274, E2E TPM 43645436172, E2E PKCS#11 43645436186, PIV 43645436191, Systemd 43645436183, CodeQL 43645436283, Workflow lint 43645436219, PR title 43645436192: every completed run succeeded.
- The house e2e gate in MODE=pr passes for that head: e2e run 43645436171, main lanes e2e (9.5p1) 800.858 s and e2e (10.5p1) 788.280 s against the 900 s stop, probe lanes 299.569 s and 284.379 s with every PROBE_PASS line. TestRestoreRecoversLostRevocations passes in both main lanes (the real recovery under the marker: M119's real-path half).
- cli-windows, cli-macos and systemd-sandbox pass; the Systemd run 43645436183 logs `restore marker lifecycle: ok`.
- The run IDs of the final head (this SUMMARY's commit) are in the executor's report; the pre-merge review is the orchestrator's (Task 4 step 5) and is not recorded here.

## Totals after the tracking update

- ROADMAP: `**Plans:** 33/42 plans executed in 41 waves.`, the Progress row `| 33/42 |`, only the 03-12 row ticked (the whole-file ROADMAP gate passes).
- STATE: `total_plans: 77`, `completed_plans: 68`, `Plan: 33 of 42`.

## Deviations from the plan

1. T1 verify 4 as written fails on two lines of internal/tlog/leaf.go that are on main (`LeafDomain`); the scoped check (no added `"keyroster/` literal) passes. (Task 1)
2. signer.go was edited and then restored before T1, so it stays outside the file list; `pinnedKeyAt` lives in internal/signer/rotate.go. (Task 1)
3. Test-only commit 4b5c92c after T2b: the production-factor scrypt test took 120 s under -race; its generation-1 files are now written at a low work factor (18 s). M117 was re-run against it. (Task 2)
4. The 2a mutants ran with HEAD at R2b (the signer code equal to T2a's). (Task 2)
5. Lint fixes in e5d2d52 after the full gate. (Task 4)
6. The capslock baseline update in db07083 (five new pairs, the capability set unchanged). (Task 4)
7. 03-15-PLAN.md line 183: the owner's workstation's host name, which is on main, is replaced on the line the plan's insertion changes, because the pre-push scan refuses it; the publish commit was amended before the first push. The plan's whole-diff PR-text scan matches only text on main (context and removed lines). (Task 4)
8. Not a deviation: the R3b route was not needed: no fixture tripped `bundle_issued_in_future`. (Task 3)

## Self-Check: PASSED

- Files: internal/signerdb/migrations/0006_ca_generations.sql, internal/signer/rotate.go, internal/signer/generations_test.go, internal/signer/rotate_test.go, cmd/keyroster-signer/rotate.go, cmd/keyroster-signer/rotate_test.go and test/vectors/leaf_ca_generation_v1.hex exist.
- Commits: R1 306caa7, T1 33682c4, R2a ed07d6c, T2a 470953d, R2b 1497674, T2b 7ffc235, 4b5c92c, R3 2045a5c, T3 6ab4715, 0bc8522, bd66716, e5d2d52 and db07083 are ancestors of HEAD.
