---
phase: 03-linux-agent-and-revocation
plan: 12d
subsystem: cli
tags: [ca-rotation, known_hosts, narrowing, login, machine-renew, host-status]
status: complete
requires: [03-12c]
provides: [verifiedTrust, narrowHostTrust, issuing-set login, live count in host status]
affects: [03-12e, 03-12f, 03-13]
key-files:
  created: [cmd/keyroster/narrow.go, cmd/keyroster/hoststatus_linux_test.go]
  modified: [cmd/keyroster/knownhosts.go, cmd/keyroster/login.go, cmd/keyroster/machinerenew.go, cmd/keyroster/host.go, cmd/keyroster/init.go, cmd/keyroster/hoststatus.go, cmd/keyroster/dirpipe.go, cmd/keyroster/revoke.go, cmd/keyroster/user.go, docs/runbooks/enroll-user.md, docs/runbooks/host-setup.md, docs/runbooks/ca-rotation.md]
requirements-completed: []
---

# Phase 03 Plan 12d: CA rotation, CLI readers Summary

Every keyroster command that verifies the trust bundle narrows the managed known_hosts to the host CAs the bundle trusts at the client's clock through one statically pinned wrapper; login and machine renew read the issuing and trusted sets; host status counts the hosts whose reported user_ca_keys hash matches the verified bundle.

## Hand-over

- **Done:** Tasks 1 to 4 in the first session (R1 37fb2ea, T1 b0b05dc, R2 3c5857c, T2 e98353d, R3 6fc7482, T3 6718a3c, S4 ccdf964, R4 1093056, T4 933d848). Second session (2026-11-17): Task 5 (R5 2002895, T5 6c72906, D5 5b531d4) and Task 6 up to the PR (plan commit 91a166f, PR #109, tracking, this SUMMARY).
- **Next step:** the pre-merge review (the orchestrator's), then Task 7 (the owner's merge).
- **Open RED/mutant state:** none. No file is in a mutant state; every mutated file was restored and hash-checked.

## Test time

test-time base: keyroster=349.320 at=1794898768

Re-measured in place in the second session, immediately before the delta gate, on origin/main 4184809 in a detached worktree outside the repository: `go test -race -count=1 -timeout 15m ./cmd/keyroster/` through scripts/linux.sh, `ok ... 349.320s`. The delta run followed at once on the branch head 91a166f (code equal to the final head): `ok ... 352.147s`, **delta +2.8 s** of the 90 s allowed. Load during both: the owner's earlier single-core job had ended; one owner python process remained in WSL, mostly waiting on I/O (state D, 1 to 4 % CPU in top), no job of this session alongside.
History, replaced: the first session's base 326.871 s and this session's first re-measure 310.838 s (at 1794896183, start of the session) were both taken while an owner job used one core of 16 at about 93 to 98 %. Readings of the whole-package race run in between varied with the load: T5 gate 328.8 s (at its start a python process in state D at about 9 %), the first D5 gate 367.2 s (with the native Windows test run alongside), the second D5 gate 370.6 s (WSL idle at its start). The back-to-back pair above is the like-for-like reading.

## Preconditions (Task 1)

Stop guard, base values (ROADMAP 35/42, STATE 77/70, Plan 35 of 42, stopped_at), ruleset 30, free names, free IDs and mutant numbers, and all 27 code anchors: every check exited 0 after `git fetch origin` (origin/main 4184809).

## Commits

| Name | SHA | Subject |
|------|-----|---------|
| R1 | 37fb2ea | test(cli): pin the narrowing of a client's host CA lines and the trust rule of its writer |
| T1 | b0b05dc | feat(cli): narrow a client's host CA lines on every verified bundle and read them from the trust rule |
| R2 | 3c5857c | test(cli): pin every guard of the host CA narrowing |
| T2 | e98353d | feat(cli): narrow only with a bundle the saved state allows and write only a file nobody changed |
| R3 | 6fc7482 | test(cli): pin that every command that verifies a bundle narrows, on every path |
| T3 | 6718a3c | feat(cli): narrow on every command that verifies a bundle |
| S4 | ccdf964 | refactor(cli): hand the login its user CA keys as a set |
| R4 | 1093056 | test(cli): pin the issuing set of a login, the trusted set of a renewal and every key of host ca-key |
| T4 | 933d848 | feat(cli): accept a certificate of the issuing set, keep a cached one of a draining CA and list every trusted user CA |
| R5 | 2002895 | test(cli): pin the live count, the new host status columns and the CA entry labels |
| T5 | 6c72906 | feat(cli): count the hosts that hold the user CA keys, show the agent and bundle_behind, and label drained CAs |
| D5 | 5b531d4 | docs(cli): describe the host CA narrowing, the live count and the several-line host ca-key |

## Task 1

**Declarations R1 added (narrow.go):** `var trustClock = time.Now`; `func narrowKnownHosts(data []byte, _ []string) ([]byte, int)` returning data and 0; `func narrowHostTrust(_ *trust.Bundle, _ time.Time, _ io.Writer)` with an empty body; `func verifiedTrust(ctx, c, cfg, _ io.Writer)` returning `c.Trust(...)` only. Test helpers R1 added: `serveRotated` and `rotatedCAKey` (host_test.go), `plantHostTrust` and `hostTrustSnapshot` (role_test.go), `nkLines`, `nkSubsequence`, `nkSound`, `nkSeedKey` (knownhosts_test.go).

**Conversion:** TestHostTrustCAs/`active_and_next_sorted_by_generation_then_key` became `active_and_next_sorted_by_generation`: its two `next` entries at one generation are a bundle Validate refuses since 03-12c, so it now uses generations 1, 2 and 3 given out of order (active g1, next g2, next g3; the fixture, like every leaf of this test, is not validated, and two `next` entries at distinct generations are still not a Validate-shaped bundle: the leaf pins the order by generation, and the key tie-break of the old sort is gone with the old function). It stays a control on R1.

**RED (R1, from a worktree, the plan's second verify command: exit 0).** 20 `--- FAIL:` lines, exactly the named ones: TestHostTrustCAs and `next_and_draining_host_ca`; TestNarrowKnownHosts and `drops_untrusted_ca_line`, `drops_a_foreign_ca_line`, `drops_malformed_ca_lines`, `leading_whitespace_ca_line_is_narrowed`, `tab_separated_ca_line_is_narrowed`, `marker_case_is_not_a_bypass`, `crlf_and_a_missing_final_newline_are_preserved`, `an_empty_trusted_set_drops_every_ca_line`, `reports_the_count_removed`; FuzzNarrowKnownHosts and `seed#0`, `seed#1`, `seed#2`; TestKnownHosts and `next_and_draining_host_ca`; TestHostCAKeyNarrows and `tracer_narrows_the_drained_line`. Failure messages read: each is the assertion (hostTrustCAs keys without the draining g2; the writer's file with 2 CA lines and no draining line at the end minus 1 s; the filter returning its input; the soundness property "an untrusted or malformed CA line was kept" on each seed; the tracer failing at role_test.go:510, the stderr narrowing check, after its exit-0 and exact-stdout assertion passed, so the rotated bundle verified). No build, setup or panic failure.
Controls that passed on R1, and why: TestHostTrustCAs/`active_and_next_sorted_by_generation`, `retired_excluded`, `other_roles_excluded`, `empty_bundle_none` and `drained_and_retired_excluded` (the old rule already leaves a draining and a retired entry out); TestNarrowKnownHosts/`keeps_trusted_ca_lines`, `keeps_other_lines_byte_for_byte`, `output_lines_are_a_subset_of_input`, `idempotent` and `empty_input_is_empty` (the stub returns its input); TestKnownHosts/`writes_three_files_and_state` (existing).

**T1.** A 30 s local fuzz run of FuzzNarrowKnownHosts on T1 passed (1.09M execs, no new corpus file).

**T1 gate** (the plan's third verify command, builds with `-o /dev/null`): `go vet ./...`, gofmt clean, `go test -race -count=1 -timeout 15m ./cmd/keyroster/` ok in 301.671 s, golangci-lint `0 issues.`, windows and darwin vet and build of cmd/keyroster clean. Task 1's first verify command (R1 touched exactly the four files, T1 no test file) exits 0.

**Mutants of Task 1.** Command: the plan's, `go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -run "^(TestHostTrustCAs|TestNarrowKnownHosts|TestKnownHosts|TestHostCAKeyNarrows)$" ./cmd/keyroster/`, run with `-v` so the leaf lines show. Unmutated: `ok ... 6.357s`. Each mutant: vet exit 0, no build or setup failure, no timeout, the file restored with `git checkout -- <file>`, sha256 before = after, `git status --short` unchanged.

| Mutant | File (sha256 before = after) | FAIL lines | Named killer |
|--------|------------------------------|------------|--------------|
| M149 | knownhosts.go (06b9ebe1...c9266) | TestHostTrustCAs/`next_and_draining_host_ca`, `drained_and_retired_excluded`; TestKnownHosts/`next_and_draining_host_ca` | both named killers |
| M233 | narrow.go (608ad7a5...823cfd) | TestHostCAKeyNarrows/`tracer_narrows_the_drained_line` | yes |
| M234 | narrow.go (608ad7a5...823cfd) | TestHostCAKeyNarrows/`tracer_narrows_the_drained_line` | yes |
| M235 | narrow.go (608ad7a5...823cfd) | TestNarrowKnownHosts/`leading_whitespace_ca_line_is_narrowed` | yes |
| M236 | narrow.go (608ad7a5...823cfd) | TestNarrowKnownHosts/`drops_malformed_ca_lines` | yes |
| M237 | narrow.go (608ad7a5...823cfd) | TestNarrowKnownHosts/`crlf_and_a_missing_final_newline_are_preserved`, `output_lines_are_a_subset_of_input` | yes |
| M275 | narrow.go (608ad7a5...823cfd) | TestNarrowKnownHosts/`leading_whitespace_ca_line_is_narrowed`, `tab_separated_ca_line_is_narrowed` | yes (tab leaf) |
| M279 | narrow.go (608ad7a5...823cfd) | TestNarrowKnownHosts/`marker_case_is_not_a_bypass` | yes |

Full hashes: knownhosts.go 06b9ebe1251d86ade7460816c95b3a5f7da4573fe5b5dda2679e4df2922c9266, narrow.go 608ad7a5f2072c63b6a46c0bdb8eef385c592544686e339bc821a220a4823cfd (at T1).
M275 and M279 also name the FuzzNarrowKnownHosts seeds as killers, but the plan's exact command does not run that target, so the seeds were not observed under it. A separate run of `-run '^FuzzNarrowKnownHosts$'` under each mutant, with the same restore and hash records, showed `seed#1` killing M275 and `seed#2` killing M279.

## Task 2

Preconditions: stop guard and base values re-run after `git fetch origin` (origin/main still 4184809): both exit 0.

**Declarations R2 added (narrow.go):** `var maxNarrowFile = int64(5 * maxHostTrustNames)`, `var narrowReplace = replaceManagedFile`, `var narrowHook func()`, `var errNoHomeDir = errors.New("no home directory")`, none used by the code at R2; TestMain's error now wraps errNoHomeDir (message otherwise unchanged). Test helpers: `nhFix`, `newNHFix`, `plantState`, `at`, `khPath`, `warn`, `narrowed`, `htNarrow`, `requireFiles`, `narrowedFiles` (knownhosts_test.go).

**RED (R2, from a worktree, the plan's second verify command: exit 0).** 18 `--- FAIL:` lines, exactly the named ones: TestKnownHosts and `narrowing_skipped_for_older_served_bundle`; TestNarrowHostTrust and `skipped_for_the_equal_version_with_another_ops_key`, `skipped_for_another_installation`, `skipped_without_a_state`, `skipped_for_a_damaged_state`, `skipped_for_a_directory_at_the_name`, `skipped_for_an_oversize_file`, `stops_when_the_file_changed_meanwhile`, `stops_when_a_newer_state_appears_meanwhile`, `stops_when_a_newer_directory_state_appears_meanwhile`, `unparsable_trusted_key_narrows_nothing`, `write_failure_warns_and_changes_nothing_else`, `home_mismatch_warns`; TestNarrowHostTrustUnix and `skipped_for_a_symlink_at_the_name`, `skipped_for_a_symlinked_state`. Each failed on its stderr assertion: T1 printed the narrowing line where a warning was wanted (the directory leaf got `it cannot be read: ... is a directory`, `home_mismatch_warns` got nothing). No build, setup or panic failure.
Controls that passed on R2, and why: TestKnownHosts/`narrowing_never_adds` (T1 only filters), TestNarrowHostTrust/`narrows_with_a_newer_bundle_and_moves_no_floor`, `narrows_with_the_equal_version_and_the_same_ops_key`, `never_creates_the_file`, `narrowing_writes_no_other_file`, `no_ssh_dir_is_silent`, `no_warning_when_nothing_to_narrow` and `home_lookup_warning_uses_its_directory` (T1 already behaves so), TestKnownHosts/`writes_three_files_and_state` (existing).

**T2.** Besides narrow.go, knownhosts.go: `defaultSSHDir` wraps errNoHomeDir in its no-home error (text unchanged: `no home directory: <err>`), and `readHostTrustState` now calls a new `readHostTrustStateBytes`, which returns the bytes it parsed as well, so the narrowing's check before the rename compares the state byte for byte; the writer's behaviour is unchanged. A `readNarrowFile` helper reads the managed file bounded and refuses a file that is no longer the one Lstat described (`os.SameFile`), so a link swapped in between the Lstat and the open is never read through.

**T2 gate** (third verify command, builds with `-o /dev/null`): vet, gofmt, `go test -race` of cmd/keyroster ok in 309.921 s, golangci-lint `0 issues.`, windows and darwin vet and build clean. Task 2's first verify command exits 0.

**Mutants of Task 2.** Command: the plan's, `-run "^(TestKnownHosts|TestNarrowHostTrust|TestNarrowHostTrustUnix)$"`, with `-v`. Unmutated: `ok ... 10.073s`. All on narrow.go at T2, sha256 0b31b3750c50da575aa8de6d5ea19de8a4dfd74fb31b605dc20a5aa48f3b068e before and after each run; vet exit 0, no build or setup failure, no timeout, `git status --short` unchanged every time.

| Mutant | Mutation as applied | FAIL lines | Named killer |
|--------|---------------------|------------|--------------|
| M151 | older-bundle case made `false &&` | TestKnownHosts/`narrowing_skipped_for_older_served_bundle` | yes |
| M238 | a CA line appended for each trusted key the output lacks | TestKnownHosts/`narrowing_never_adds`; TestNarrowHostTrust/`narrows_with_a_newer_bundle_and_moves_no_floor`, `narrows_with_the_equal_version_and_the_same_ops_key`, `narrowing_writes_no_other_file`, `home_lookup_warning_uses_its_directory` | yes |
| M239 | the state written with bundle_version moved to the bundle's after the narrowing | TestKnownHosts/`narrowing_never_adds`; TestNarrowHostTrust/`narrows_with_a_newer_bundle_and_moves_no_floor`, `narrowing_writes_no_other_file`, `home_lookup_warning_uses_its_directory` | yes (both) |
| M240 | equal-version ops-key case made `false &&` | TestNarrowHostTrust/`skipped_for_the_equal_version_with_another_ops_key` | yes |
| M241 | installation case made `false &&` | TestNarrowHostTrust/`skipped_for_another_installation` | yes |
| M242 | a missing or damaged state replaced by an empty state of the bundle's installation | TestNarrowHostTrust/`skipped_without_a_state`, `skipped_for_a_damaged_state`; TestNarrowHostTrustUnix/`skipped_for_a_symlinked_state` | yes (all three) |
| M243 | regular-file case made `false &&` | TestNarrowHostTrust/`skipped_for_a_directory_at_the_name`; TestNarrowHostTrustUnix/`skipped_for_a_symlink_at_the_name` | yes (both) |
| M244 | size-bound case made `false &&` | TestNarrowHostTrust/`skipped_for_an_oversize_file` | yes |
| M245 | the file-bytes check in `check` made `false &&` | TestNarrowHostTrust/`stops_when_the_file_changed_meanwhile` | yes |
| M246 leg 1 | the state check in `check` made `false &&` | TestNarrowHostTrust/`stops_when_a_newer_state_appears_meanwhile`, `stops_when_a_newer_directory_state_appears_meanwhile` | yes |
| M246 leg 2 | the state check compares only `bundle_version` with the bundle's | TestNarrowHostTrust/`stops_when_a_newer_directory_state_appears_meanwhile` | yes |
| M247 | the ParseKey check made `false &&` | TestNarrowHostTrust/`unparsable_trusted_key_narrows_nothing` | yes |
| M248 | an absent file is created (an empty write) | TestNarrowHostTrust/`never_creates_the_file` | yes |
| M276 | every userSSHDir error returns silently | TestNarrowHostTrust/`home_mismatch_warns` | yes |
| M277 | `removed == 0` moved after the state guards | TestNarrowHostTrust/`no_warning_when_nothing_to_narrow` | yes |

Notes: under M243 the link is still not read through, because `readNarrowFile` refuses a file that is not the one Lstat described; the leaves kill the mutant on the warning text (`the file changed while it was read` and `it cannot be read: ... is a directory` instead of `it is not a regular file`). Under M242 the damaged and symlinked leaves are killed on the warning text as well (the check before the rename then refuses the damaged state), the missing-state leaf by the narrowing itself.

## Task 3

Preconditions: stop guard and base values re-run after `git fetch origin` (origin/main 4184809): both exit 0.

**R3 declares no production code.** Test helpers it added: `loginServer.root` and `(e *loginServer) serveRotated` (login_test.go; the fake server's trust route now reads its document under the lock, as dirEnv's does); `plantHostTrustFiles` (role_test.go; `plantHostTrust` now calls it); `trustRef`, `scanTrustRefs`, `rotatedHostCAs`, `hostCAsOf`, `caLineFor`, `plantHostTrustLogin`, `requireNarrowed` and `narrowCommandCases` (knownhosts_test.go; TestKnownHosts calls `narrowCommandCases(t)` first, so its leaves are TestKnownHosts leaves).

**RED (R3, from a worktree, the plan's second verify command: exit 0).** 17 `--- FAIL:` lines, exactly the named ones: TestTrustCallersUseWrapper and `every_trust_call_goes_through_the_wrapper` (it named the ten direct sites dirpipe.go:129, host.go:362, hoststatus.go:121, knownhosts.go:1064, login.go:183, machinerenew.go:112, revoke.go:116, user.go:123, :395 and :649; knownhosts.go:1064 is the plan's :1066 of 4184809, moved by T1 and T2's edits higher in the file) and `init_narrows_after_its_unpinned_trust`; TestKnownHosts; `known_hosts_narrows_when_krl_fetch_fails` and its `server_error`, `no_krl_published`, `krl_does_not_verify`; `narrows_when_the_directory_is_missing`; `login_no_known_hosts_still_narrows`; `login_refused_after_trust_still_narrows`; `narrow_failure_keeps_exit_status`; `narrows_on_any_command_with_verified_bundle` and its `host_status`, `known_hosts_sync`, `directory_show`, `machine_renew`. Every login and command leaf failed on the known_hosts or stderr assertion after its own setup assertions held (the login printed its certificate and the refresh outcome the leaf wants; the refused login was refused with `not signed by the user CA`). No build, setup or panic failure.
Controls that passed on R3, and why: TestTrustCallersUseWrapper/`narrow_callers_are_pinned` (only verifiedTrust references narrowHostTrust after T1); TestKnownHosts/`narrows_on_any_command_with_verified_bundle/host_ca_key` (Task 1 converted it), `no_narrowing_without_verified_bundle` (no verified bundle, no narrowing), `refresh_uses_the_client_clock` and `wrapper_uses_the_client_clock` (T1 reads trustClock), `clock_ahead_narrows_early_and_a_refresh_restores` and `clock_behind_keeps_the_drained_line` (the narrowing and the writer already behave so), `writes_three_files_and_state` (existing).

**T3.** Every Trust call goes through verifiedTrust (hoststatus.go, revoke.go and the admin-session paths with `s.stderr`); `runInit` calls `narrowHostTrust(b, trustClock(), stderr)` right after `TrustUnpinned`; the `--no-known-hosts` help text gains the OQ-B clause. `git grep` found no test or runbook that pins the old help text.

**T3 gate** (third verify command, builds with `-o /dev/null`): vet, gofmt, `go test -race` of cmd/keyroster ok in 281.676 s, golangci-lint `0 issues.`, `scripts/capslock-check.sh` passed, windows and darwin vet and build clean. Task 3's first verify command (R3 changed test files only, T3 no test file) exits 0.

**Capslock after T3:** keyroster-signer 94 pairs (baseline 97; the check reports the three ARBITRARY_EXECUTION pairs of internal/directory, internal/sshsig and internal/trust as no longer reported, the known looser baseline that only a reviewed PR may tighten), keyroster-agent 37 of 37, keyroster-agent-fetch 23 of 23. No pair changed; no baseline was edited.

**Mutants of Task 3.** Command: the plan's, `-run "^(TestKnownHosts|TestTrustCallersUseWrapper)$"`, with `-v`. Unmutated: `ok ... 6.794s`. Each run: vet exit 0, no build or setup failure, no timeout, every touched file restored with `git checkout -- <file>` and its sha256 equal before and after (at T3: knownhosts.go eda7441f9d668d40fe8b352531f706ef60adefd18045cbfda726cc0f259b0aa9, login.go fd4ddc641e3bfbca830e8ac6e37ea922ededc5a2ae544f9aa18ff16ea81b8f9f, hoststatus.go 9298f6125925d5f2da486185fc7acce2fb9a978fd3e44345dfdff53b46c936e7, init.go 94990d0e254e6b36777842afda5a8a279d6de4a462f40638f4cf3ffdde45d693, narrow.go 0b31b3750c50da575aa8de6d5ea19de8a4dfd74fb31b605dc20a5aa48f3b068e), `git status --short` unchanged.

| Mutant | Mutation as applied | FAIL lines | Named killers |
|--------|---------------------|------------|---------------|
| M150 | login.go calls `client.Trust`; refreshHostTrust narrows after GetKRL | TestKnownHosts/`known_hosts_narrows_when_krl_fetch_fails/server_error`, `login_no_known_hosts_still_narrows`, `login_refused_after_trust_still_narrows`; TestTrustCallersUseWrapper/`every_trust_call_goes_through_the_wrapper`, `narrow_callers_are_pinned` | all three named killers |
| M249 | hoststatus.go calls `s.client.Trust` | TestKnownHosts/`narrows_on_any_command_with_verified_bundle/host_status`; TestTrustCallersUseWrapper/`every_trust_call_goes_through_the_wrapper` | both |
| M250 | login.go calls `client.Trust` when `--no-known-hosts` is set | TestKnownHosts/`login_no_known_hosts_still_narrows`; TestTrustCallersUseWrapper/`every_trust_call_goes_through_the_wrapper` | yes |
| M251 | runInit's narrowHostTrust call removed | TestTrustCallersUseWrapper/`init_narrows_after_its_unpinned_trust` | yes |
| M252 | refreshHostTrust reads `time.Now()` | TestKnownHosts/`refresh_uses_the_client_clock` | `refresh_uses_the_client_clock` yes; `clock_ahead_narrows_early_and_a_refresh_restores` did not fail, because it drives the writer directly with `in.CAs` and not through refreshHostTrust (recorded; the other named killer kills it) |
| M272 | login.go calls `client.Trust`; the writer narrows after `krl.VerifyManifest` | TestKnownHosts/`known_hosts_narrows_when_krl_fetch_fails` (all three leaves), `login_no_known_hosts_still_narrows`, `login_refused_after_trust_still_narrows`, `narrow_failure_keeps_exit_status`; TestTrustCallersUseWrapper/`every_trust_call_goes_through_the_wrapper`, `narrow_callers_are_pinned` | `no_krl_published`, `krl_does_not_verify` yes |
| M273 | login.go calls `client.Trust`; the writer narrows only when the directory verified | as M272 plus TestKnownHosts/`narrows_when_the_directory_is_missing` | yes |
| M274 | verifiedTrust passes `time.Now()` | TestKnownHosts/`wrapper_uses_the_client_clock` | yes |

## Task 4

Preconditions: stop guard and base values re-run after `git fetch origin` (origin/main 4184809): both exit 0. Before S4, `grep` found no test that calls `checkLoginCert(` or builds a `loginRun` directly, so S4 changes login.go alone.

**S4** (login.go only): `checkLoginCert(raw, cas []ssh.PublicKey, key, ...)` compares the signature key and the CertChecker authority with `cas[0]` only; `loginRun.ca` became `cas`; `runLogin` passes `[]ssh.PublicKey{ca}`. `TestLoginRefusals`, `TestLoginFlowFakeServer` and `TestMachineRenewChecksAnswer` passed on S4 (`ok ... 2.763s`).

**Declarations R4 added:** login.go `func issuingUserCAs(b *trust.Bundle) ([]ssh.PublicKey, error)` returning `activeUserCA(b)` as a one-element slice; host.go `func caStateText(ca trust.CAEntry, _ time.Time) string` returning `ca.State`. Test helpers: `newCASigner` (login_test.go), `rotatedMachineCAs` (machinerenew_test.go), `rotatedUserCAs` (role_test.go). TestHostCAKey's existing body moved unchanged into the leaf `single_active_key_is_one_line`.

**RED (R4, from a worktree, the plan's third verify command: exit 0).** 15 `--- FAIL:` lines, exactly the named ones: TestCheckLoginCertCAs and `cert_by_next_user_ca_accepted`, `issuing_set_is_active_and_next_in_generation_order`; TestLoginFlowFakeServer and `login_by_a_next_user_ca` (refused with `it is not signed by the user CA of your root-signed trust bundle`, so the issuing rule and not the setup); TestMachineRenewIfDue and `if_due_draining_cached_kept` (exit 0 but one request sent); TestHostCAKey and `lists_every_trusted_key`, `draining_is_listed_until_its_end`, `note_on_stderr_only`; TestCAStateText and `draining_before_its_end`, `draining_at_its_end_is_drained`, `draining_after_its_end_is_drained`. No build, setup or panic failure.
Controls that passed on R4, and why: TestCheckLoginCertCAs/`cert_by_active_user_ca_accepted`, `cert_by_retired_user_ca_refused`, `cert_by_draining_user_ca_refused`, `cert_by_unknown_ca_refused`, `issuing_set_without_an_active_key_is_an_error` (the one-element stub behaves so; every refusal leaf asserts the text `not signed by the user CA` or `has no active user CA`); TestMachineRenewIfDue/`if_due_drained_cached_renewed`, `if_due_retired_cached_renewed` (a certificate of a drained or retired CA is replaced today); TestMachineRenewChecksAnswer/`answer_by_draining_refused` (served through `serveRotated` at version 2, refused with the issuing-rule text; a draining key is neither active nor next today); TestHostCAKey/`single_active_key_is_one_line`, `omits_a_drained_key`, `omits_a_retired_key`, `no_note_for_a_single_active_key` (today's output); TestCAStateText/`active_next_retired_as_the_bundle_says`.
The clocks: TestCheckLoginCertCAs fixes `loginNow` and `trustClock` at one second and every draining entry ends an hour after it; the machine cases fix `machineRenewTimeNow` (useRenewClock) near the wall clock, because the fake signer stamps its answers at wall time.

**T4.** As the plan's action, plus: `inKeySet` (login.go) is the one set test that login and machine renew share; `caKeys` parses a CA entry list for both machine sets; runHostCAKey keeps its error text `the verified trust bundle has no active user CA key` (checked first now) and writes stdout in one write after every key parsed; `activeUserCA` is removed (nothing else used it).

**T4 gate** (third verify command, builds with `-o /dev/null`): vet, gofmt, `go test -race` of cmd/keyroster ok in 315.144 s, golangci-lint `0 issues.`, windows and darwin vet and build clean. Task 4's first verify command (S4 touched login.go only, R4 production files only login.go and host.go, T4 no test file, and the login and renewal tests pass on the final tree: `ok ... 3.053s`) exits 0.

**Mutants of Task 4.** Command: the plan's, `-run "^(TestCheckLoginCertCAs|TestLoginFlowFakeServer|TestMachineRenewIfDue|TestMachineRenewChecksAnswer|TestHostCAKey|TestCAStateText)$"`, with `-v`. Unmutated: `ok ... 2.761s`. Each run: vet exit 0, no build or setup failure, no timeout, the file restored with `git checkout -- <file>`, sha256 equal before and after (at T4: login.go 26183928e7dfba433d7d240f2c54704d0cb46387d71229d177ede139ae93e637, machinerenew.go 2209efcff03556b8368fdac710005ec7304f5836db6687e76da3abb383293ee4, host.go a6a497bd5d05f1aeb0497ab3c0a323cdbbf7076efd5b874b204c86ce930ca71f), `git status --short` unchanged.

| Mutant | Mutation as applied | FAIL lines | Named killers |
|--------|---------------------|------------|---------------|
| M152 | issuingUserCAs ranges over every user entry | TestCheckLoginCertCAs/`cert_by_retired_user_ca_refused`, `cert_by_draining_user_ca_refused`, `issuing_set_is_active_and_next_in_generation_order`, `issuing_set_without_an_active_key_is_an_error` | all three |
| M153 | machineTrustedKeys built with `time.Time{}` | TestMachineRenewIfDue/`if_due_drained_cached_renewed` | yes |
| M253 | issuingUserCAs keeps the active entry only | TestLoginFlowFakeServer/`login_by_a_next_user_ca`; TestCheckLoginCertCAs/`cert_by_next_user_ca_accepted`, `issuing_set_is_active_and_next_in_generation_order` | all three |
| M254 | checkMachineCertificate checks against machineTrustedKeys | TestMachineRenewChecksAnswer/`answer_by_draining_refused` | yes |
| M255 | host ca-key skips every entry that is not active | TestHostCAKey/`lists_every_trusted_key`, `draining_is_listed_until_its_end`, `note_on_stderr_only` | both named |
| M256 leg 1 | the set is every user entry that is not retired | TestHostCAKey/`omits_a_drained_key` | yes |
| M256 leg 2 | the set is every user entry | TestHostCAKey/`omits_a_drained_key`, `omits_a_retired_key` | yes |
| M257 | the note's first line goes to stdout | TestHostCAKey/`lists_every_trusted_key`, `draining_is_listed_until_its_end`, `note_on_stderr_only` | both named |
| M271 | issuingUserCAs built from `TrustedCAs(b, user, loginNow())` | TestCheckLoginCertCAs/`cert_by_draining_user_ca_refused`, `issuing_set_is_active_and_next_in_generation_order` | both |

## Task 5

Preconditions: stop guard and base values re-run after `git fetch origin` (origin/main still 4184809): both exit 0. `initTrustDocEdit` (init_test.go) reported `TrustResponse.BundleVersion` as 1 whatever the edit, which `serverclient.Trust` refuses for an edited version; R5 fixed the helper to report the edited bundle's version, as the plan anticipates.

**Declarations R5 added:** hoststatus.go `const userCAKeysPath = "user_ca_keys"` and `renderHostsStatus(a, _ *trust.Bundle, now)` with `runHostStatus` passing the bundle `verifiedTrust` returned (the local was named `bundle`, not `b`, because the `--json` branch already declares a `b`); init.go `printTrustSummary(w, b, p, _ time.Time)` with its caller passing `trustClock()`. Test helpers: `liveFix`, `newLiveFix`, `liveUserCA`, `(*liveFix).fileHash`, `row` and `render`, and `hostStatusLiveCases` (hoststatus_test.go; TestHostStatus calls it last, so its leaves are TestHostStatus leaves).

**RED (R5, from a worktree, the plan's second verify command: exit 0).** 22 `--- FAIL:` lines, exactly the named ones: TestHostStatus and `live_count_by_trust_file_hash`, `held_addition_not_live`, `pending_swap_not_live`, `stale_host_not_live`, `drifted_host_not_live`, `check_failed_not_live`, `stuck_not_live`, `no_check_yet_not_live`, `check_older_than_apply_not_live`, `no_ca_file_not_live`, `truncated_files_not_confirmable`, `bundle_mismatch_not_counted`, `live_count_at_the_clients_clock`, `draining_keys_listed_with_their_end`, `agent_version_column`, `agent_version_escaped`, `bundle_behind_column`, `live_count_end_to_end`; TestInit and `ca_states_label_draining_and_drained`; TestHostSetupHandManagedCAKeyRule. Each failed on its output assertion (no live-count line, no AGENT or BEHIND column, no draining line, `(custody tpm, draining)` where the label was wanted, the runbook strings missing); the end-to-end leaf had already narrowed the planted file (T3) and failed on the header and draining lines. No build, setup or panic failure.
Controls that passed on R5, and why: TestHostStatus/`unknown_status_field_ignored` (serverclient decodes with json.Unmarshal today), `table`, `json` and every other existing leaf, TestInit's existing leaves, TestUserCAKeysPath (the constant is declared with the agent's value).

**T5.** As the plan's action, plus: `liveReportReason` holds the rules of the host's own report (stuck, no check yet, check failed, drift, check older than apply, in that order; each leaf sets one); the table's local `bundle` became `bv` (the parameter is `bundle`); live notes come before the row notes; two defensive branches no verified bundle reaches, because `Validate` refuses a CA key that does not parse: `user CA keys not counted: <error>` when `trust.UserCAKeysFile` fails, and the fingerprint `(a key that does not parse)` in a draining line. Neither has a test (UNVERIFIED by construction).

**T5 gate.** The plan's command at T5 failed by design on one test: `--- FAIL: TestHostSetupHandManagedCAKeyRule`, the only FAIL line, no DATA RACE, `FAIL ... 328.824s`, because the runbook text that test pins is D5's. Its remaining steps were run on their own at T5: golangci-lint `0 issues.`, `scripts/capslock-check.sh` passed, windows and darwin vet and build clean. The whole gate then ran at D5 (below).

**Capslock after T5:** keyroster-signer 94 pairs (baseline 97, the same three ARBITRARY_EXECUTION pairs reported as no longer reported), keyroster-agent 37 of 37, keyroster-agent-fetch 23 of 23. No pair changed; no baseline edited.

**Mutants of Task 5.** Command: the plan's, `go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -run "^(TestHostStatus|TestInit|TestCAStateText)$" ./cmd/keyroster/`, with `-v`. Unmutated: `ok ... 0.525s`. Each run: vet exit 0, no build or setup failure, no timeout, the file restored with `git checkout -- <file>`, sha256 before = after (at T5: hoststatus.go b0013cfa558ba15c85f768762bda7d988114f511e88ffcfb7912e1387a8e2663, host.go a6a497bd5d05f1aeb0497ab3c0a323cdbbf7076efd5b874b204c86ce930ca71f), `git status --short` unchanged.

| Mutant | Mutation as applied | FAIL lines | Named killers |
|--------|---------------------|------------|---------------|
| M154 | the hash test replaced by `st.Bundle.Version != a.Current.Bundle` | TestHostStatus/`live_count_by_trust_file_hash`, `held_addition_not_live`, `live_count_at_the_clients_clock` | both |
| M258 | `st.Pending != nil` removed from the row test | TestHostStatus/`pending_swap_not_live` | yes |
| M259 | `r.Silent`, `r.StatusStale` and `r.SeqRegressed` removed | TestHostStatus/`stale_host_not_live` | yes |
| M260 | the expected file built with `time.Time{}` | TestHostStatus/`live_count_at_the_clients_clock`, `live_count_end_to_end` | yes |
| M261 | the current-bundle check made `false && (...)` | TestHostStatus/`bundle_mismatch_not_counted` | yes |
| M262 leg 1 | a truncated status without the entry counted (`n++` after its note) | TestHostStatus/`truncated_files_not_confirmable` | `truncated_files_not_confirmable` yes; `no_ca_file_not_live` did not fail, because its host is not truncated |
| M262 leg 2 | every status without the entry counted | TestHostStatus/`no_ca_file_not_live`, `truncated_files_not_confirmable` | both |
| M263 | the AGENT cell printed without `safe` | TestHostStatus/`agent_version_escaped` | yes |
| M264 | the BEHIND cell shows `AcceptedVersion` | TestHostStatus/`bundle_behind_column` | yes |
| M265 | host.go `caStateText`: `if ca.TrustedAt(now) || true` | TestCAStateText/`draining_at_its_end_is_drained`, `draining_after_its_end_is_drained`; TestHostStatus/`draining_keys_listed_with_their_end`, `live_count_end_to_end`; TestInit/`ca_states_label_draining_and_drained` | all four named |
| M266 | the drift case made `false &&` | TestHostStatus/`drifted_host_not_live` | yes |
| M267 | the check-error case made `false &&` | TestHostStatus/`check_failed_not_live` | yes |
| M268 | the stuck case made `false &&` | TestHostStatus/`stuck_not_live` | yes |
| M269 | a nil `LastCheck` returns no reason (counted) | TestHostStatus/`no_check_yet_not_live` | yes |
| M270 | the check-older-than-apply test made `false &&` | TestHostStatus/`check_older_than_apply_not_live` | yes |
| M278 | `runHostStatus` passes `time.Now()` | TestHostStatus/`live_count_end_to_end` | yes |

Notes: the first M154 attempt did not compile (`want` unused) and is not a record; it was re-run with `_, _ = sum, want` and recorded above. M260, M266 and M267 were first refused by the mutant script because their search text occurred twice (a comment, and the existing drift column of the table); each was re-run with a text that occurs once.

**D5.** enroll-user.md item 2 gains the narrowing paragraph and its residual (cited tests checked by `cited_tests_exist`); host-setup.md step 1 the several-line `host ca-key`, the hand-managed host rule and the adoption caveat, and the `host status` sample its live-count line and AGENT and BEHIND columns with a paragraph on the count, the draining lines and the columns; ca-rotation.md the two sentences. The first D5 commit (8ee18fc, never pushed) said "`init --force` against a saved installation" as the plan's text does, and the native Windows run of the package failed TestRepinInstructionsKeepIdentity on it: that test refuses any runbook paragraph that names `keyroster init` and `--force` without `--user` and `--admin-key`. D5 was amended (5b531d4) to "`keyroster init` when it runs again against a saved installation"; the full staged diff of all three runbooks was read again before the amend.

**Native Windows run.** `go test -count=1 -timeout 15m ./cmd/keyroster/` with the Windows toolchain (go1.27.4 windows/amd64) at the first D5: one FAIL, TestRepinInstructionsKeepIdentity (above), every other test passed (104.4 s). After the amend the doc-reading tests pass natively (`ok`).

## Task 6

- **Stop guard and base values** re-run after `git fetch origin` before the publish edits (origin/main still 4184809): both exit 0.
- **Publish scan of the plan file** (the private-term scan and the design-label scan of the plan's publish verify) run before the plan commit: no match. The added lines of each push were scanned the same way: no match.
- **Plan commit** 91a166f `docs(03-12d): plan out the CA rotation CLI readers`; wave 35 and `depends_on: ["03-12c"]` unchanged; no other plan file edited.
- **PR #109** opened by the bot through scripts/gh-as-bot.sh, title `feat(cli): narrow host CA lines on every verified bundle, count hosts holding new CA keys`, no auto-merge. The CI run IDs and the house e2e gate readings of the final head are in the hand-off report (a commit cannot carry the IDs of its own run).
- **Tracking** (`state.advance-plan`, `state.update-progress`, `roadmap.update-plan-progress 3`): ROADMAP `**Plans:** 36/42 plans executed in 41 waves.`, Progress row `| 36/42 |`, only the 03-12d row ticked (the diff was read: three lines changed, every other Phase 3 row unchanged); STATE `total_plans: 77`, `completed_plans: 71`, `Plan: 36 of 42`, and by one scoped edit `stopped_at: "Completed 03-12d-PLAN.md (PR #109)"`; `last_updated` and `state_head` are what GSD wrote.
- **Delta gate:** +2.8 s (Test time, above).
- **Capslock** after T3 and T5: keyroster-signer 94 (baseline 97), keyroster-agent 37, keyroster-agent-fetch 23; no pair changed, no baseline edited.
- **Threat IDs and mutant numbers:** Task 1's check found T-03-444 to T-03-448 and M233 to M279 free, so no renumbering. Mutants recorded: M149 to M154 and M233 to M279, M246, M256 and M262 in two legs each.
- **Reconcile ledger:** every line held at execution except those recorded under Deviations (the knownhosts.go:1064 line number, the `then_key` conversion, `initTrustDocEdit`, and the D5 `init` sentence).
- **Pre-merge review:** not run by the executor; the orchestrator runs it on the green PR (Task 6 step 4). This SUMMARY records no review result yet.
- **What stays UNVERIFIED:** the narrowing and the several-line `host ca-key` against real ssh clients and hosts (no e2e in this plan), the live count against real agent heartbeats (03-12e's end-to-end test), Windows OpenSSH, and the runbook text on hosts. The two defensive branches of T5 have no test.
- **Residuals:** a client that never runs keyroster, runs no command that verifies a bundle, cannot reach the server or only runs ssh keeps a drained line; the client's clock governs and the CLI has no latch (a clock set back trusts a drained CA again); a rename right after the narrowing's check can still land behind a concurrent refresh; a host with 255 or more principals files cannot be confirmed by the live count; hand-managed hosts are outside `host status`.
- **requirements-completed** is empty: KEY-08 completes in 03-13.

## Full staged-diff reads

- R1: `git diff --cached` of narrow.go, host_test.go, role_test.go and knownhosts_test.go read in full after the last edit, before the commit.
- T1: `git diff --cached` of host.go, knownhosts.go and narrow.go read in full after the last edit, before the commit.
- R2: `git diff --cached` of narrow.go, knownhosts_test.go and knownhosts_unix_test.go read in full after the last edit (a gofmt line wrap), before the commit.
- T2: `git diff --cached` of knownhosts.go and narrow.go read in full after the last edit, before the commit.
- R3: `git diff --cached` of knownhosts_test.go, login_test.go and role_test.go read in full after the last edit, before the commit.
- T3: `git diff --cached` of dirpipe.go, host.go, hoststatus.go, init.go, knownhosts.go, login.go, machinerenew.go, revoke.go and user.go read in full after the last edit, before the commit.
- S4: `git diff --cached` of login.go read in full after the last edit, before the commit.
- R4: `git diff --cached` of host.go, login.go, login_test.go, machinerenew_test.go and role_test.go read in full; machinerenew_test.go was edited again after the first read (a helper moved above the test's doc comment), re-staged and its whole diff read again before the commit.
- T4: `git diff --cached` of host.go, login.go and machinerenew.go read in full after the last edit, before the commit.
- R5: `git diff --cached` of hoststatus.go, init.go, hoststatus_test.go, hoststatus_linux_test.go (the whole new file), init_test.go and runbook_test.go read in full; hoststatus.go was edited again after the first read (the bundle local renamed `bundle`), re-staged and its whole diff read again before the commit.
- T5: `git diff --cached` of hoststatus.go and init.go read in full after the last edit, before the commit.
- D5: `git diff --cached` of ca-rotation.md, enroll-user.md and host-setup.md read in full; enroll-user.md was reflowed after the first read, re-staged and its whole diff read again before the commit (8ee18fc). The amend (5b531d4) changed enroll-user.md once more: its staged diff and its whole diff against D5's parent were read in full before the amend; the other two files were unchanged since their full read.
- Plan commit (91a166f): `git diff --cached` of 03-12d-PLAN.md (975 lines) was saved and read: lines 1 to 419 directly, and of the rest every removed and context line directly; its added lines there are the executable plan's text, which was read in full, every line, from the identical working-tree file at the start of this session and was not edited since. Recorded so, because the remaining added text was not read a second time.
- Final docs commit: `git diff --cached` of ROADMAP.md, STATE.md (both read in full: three and five changed lines) and this SUMMARY (a new file: its staged diff was read before the commit from its start to the Task 1 heading and from the Task 6 heading to its end; the Task 1 to Task 5 sections between were read in full when written or, for the first session's text, at the start of this session, and only the SameFile deviation changed in them since).

## Deviations

- The gates' `GOOS=windows go build ./cmd/keyroster/` and `GOOS=darwin go build ./cmd/keyroster/` were run with `-o /dev/null` (T1 to T4), so the build writes no binary into the working tree; the build check itself is unchanged.
- Every mutant command was run with `-v` added, so the killing leaves show; the rest of each command is the plan's.
- M275 and M279 name FuzzNarrowKnownHosts seeds as killers, but the plan's Task 1 command does not run that target. The command was run as written (the TestNarrowKnownHosts leaves killed both) and the seeds were observed in a separate run under each mutant (`seed#1` killed M275, `seed#2` M279).
- M252: the named killer `refresh_uses_the_client_clock` killed it; the other named killer, `clock_ahead_narrows_early_and_a_refresh_restores`, did not, because that case drives the writer directly with `in.CAs` and not through refreshHostTrust.
- M243 (both leaves) and M242's damaged and symlinked-state leaves were killed on the warning text, not on a changed file: T2's `readNarrowFile` refuses a file that is not the one Lstat described, and the check before the rename refuses a state that does not read back, so even the mutated code declines.
- **Resolved: the `os.SameFile` guard in `readNarrowFile` (T2), accepted by the orchestrator on 2026-11-17.** What it is: `readNarrowFile` opens the managed file after its Lstat and refuses it, with the contract's reason `the file changed while it was read`, when `os.SameFile` says the opened file is not the one Lstat described. Why it is safe: it is the standard Lstat-then-open check, so a link or another file swapped in between the Lstat and the open is never read through; it can only make the narrowing decline, never remove more. The code is unchanged. `readHostTrustStateBytes` (knownhosts.go) returns the bytes the state read parsed, which the check before the rename compares; `readHostTrustState` now calls it and the writer's behaviour is unchanged.
- The converted TestHostTrustCAs leaf `active_and_next_sorted_by_generation` uses three distinct generations as the plan says, with two `next` entries (generations 2 and 3), which Validate would still refuse; like every leaf of that test the fixture is not validated. Any three entries of states active and next repeat a state, and a draining entry would break the leaf's role as a control on R1.
- The plan asks for a quiet base with no other heavy job; an owner job ran in WSL during the first two base readings. The base was therefore re-measured in place immediately before the delta gate and the delta run back to back with it under the same load (Test time).
- The RED of R3 names knownhosts.go:1064 where the plan says :1066 (T1 and T2 moved the line).
- R3 also touched role_test.go (`plantHostTrust` now calls the new `plantHostTrustFiles`, shared with the loginServer helper) and made the loginServer trust route read its document under the lock, so `serveRotated` can replace it race-free; both are test-only.
- T4 beyond the action's wording: a shared `inKeySet` (login.go) and `caKeys` (machinerenew.go); `activeUserCA` removed as unused; runHostCAKey checks for an active user CA first with its existing error text and writes stdout in one write after every key parsed.
- **Task 5's gate at T5 cannot pass as ordered (plan defect).** R5 adds TestHostSetupHandManagedCAKeyRule, which only D5's text makes pass, and the action runs the whole-package gate right after T5. At T5 the gate failed on that one test alone (no other FAIL, no DATA RACE); its later steps (golangci-lint, capslock, windows and darwin vet and build) were run on their own at T5, and the whole gate was run again at D5. No code was bent to fit.
- **D5's `init` sentence reworded (plan text against an existing test).** The plan's text for enroll-user.md says `init` narrows "(`init --force` against a saved installation)"; TestRepinInstructionsKeepIdentity refuses a runbook paragraph that names `keyroster init` and `--force` without `--user` and `--admin-key`. The paragraph says "`keyroster init` when it runs again against a saved installation" instead; the behaviour described is the same. Found by the native Windows run before any push; D5 amended.
- `initTrustDocEdit` (init_test.go) now reports the edited bundle's version in `TrustResponse.BundleVersion`, as the plan's Task 5 asks to check and fix.
- T5 beyond the action's wording: `liveReportReason`; the `bundle`/`bv` names; two defensive branches that no verified bundle reaches (`user CA keys not counted: <error>` and `(a key that does not parse)`), which have no test.
- M262 leg 1 (the literal mutation, a truncated status counted) is killed by `truncated_files_not_confirmable` only; `no_ca_file_not_live` kills the wider leg 2 (any status without the entry counted). Recorded, not widened.
- Every Task 5 mutant was run through a scratch script that applies one literal replacement, runs the plan's command with `-v` (and an echo after vet to record its exit), restores with `git checkout -- <file>` and compares sha256 and `git status --short`; the command is otherwise the plan's.
- The delta gate was run as a scratch script that re-measures the base on origin/main in a detached worktree and then runs the same command on the branch, back to back, with the load recorded before each; the comparison with the 90 s limit was read from the two `ok` lines.
- The gates' builds wrote no binary into the tree (`-o /dev/null` for cmd/keyroster).

## Self-Check: PASSED

Every commit named above is an ancestor of the branch head (git merge-base --is-ancestor), narrow.go and hoststatus_linux_test.go exist, and the branch holds no file outside files_modified apart from this SUMMARY.

## Pre-merge review fixes

Both fixes were approved by the owner (Daniel) in this PR. Each test was committed before its fix and failed on the code before it. Bite check: the guard was inverted, the test run, the guard restored, and the file's sha256 compared before and after.

- **A drift check is last_check only for the generation the status reports (T-03-447), af2c484 test, 9cf53bd fix.** `buildStatus` keeps the previous last_check when the report's generation is not the status's. Check takes no apply lock, so a daemon check of G that ends after `keyroster-agent apply --once` committed G+1 no longer counts the host on G+1's files. A failed check is still published, because it can only uncount. During a pending swap the status reports the from generation, so a check of the intermediate or target is not published; such a host is never counted. Test: `TestStatus/check_of_an_older_generation_is_not_published/{earlier_check_true,earlier_check_false}`. RED (WSL): `a check of generation 1 at generation 2: last_check &{At:2026-10-26T12:03:30Z Drift:false Error:}, want &{At:2026-10-26T12:00:00Z Drift:false Error:}` (and `want <nil>`). Bite check: `==` to `!=` failed both leaves (`the check of the reported generation 1 was not published: <nil>`); sha256 296ae18b… before and after. status.go and status_test.go are outside files_modified.
- **The remedy for an uncounted host, 91bfb66 test, 10a30bf fix, 1dad069 and ac3f0ab docs.** `keyroster-agent check` writes no status, so it never changes the count. For a stuck host, the host status note now names `sudo keyroster-agent apply --once --recover-to-last-good` ("Manual recovery") and then the agent's next clean check. For every other reason it names the agent's next clean check and says the manual check does not change the count. The notes stay a closed set passed through `safe`, and the files_truncated note is unchanged. host-setup.md says the same: the agent checks after every apply it runs itself and every 15 min, and a hand-run apply is counted after the next periodic check. Tests: `TestHostStatus/{drifted,check_failed,stuck,no_check_yet,check_older_than_apply}_not_live` (the stuck remedy as a literal) and `TestHostSetupLiveCountRemedy`. RED: all five leaves failed with `host status lacks "web2: user CA keys not confirmed: ...`, plus the runbook test's four errors. Bite check: `st.Stuck != ""` inverted failed all five leaves; sha256 b6e786e8… before and after. 03-12d-PLAN.md still quotes the old note; no test reads it.
- **Gates:** gofmt, vet (Windows, linux, darwin), and cmd/keyroster on Windows and in WSL all clean. internal/agent/apply passed in WSL, both plain (434 s) and with -race. golangci-lint: 0 issues.
