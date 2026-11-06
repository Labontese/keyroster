---
phase: 03-linux-agent-and-revocation
plan: 09b
subsystem: hosts
tags: [cli, known-hosts, revoke, server, signer, audit, e2e, revoke-04]
status: in-progress
---

# Phase 3 Plan 09b: CLI host trust, revoke host and the redeem directory (part b) Summary

Draft, written during execution.

## Bases (quiet, on origin/main 6cde9d0)

The test-time base was measured in a detached worktree at origin/main outside the repository, with no other heavy job running.

test-time base: cmd=159.279 signer=329.831 server=111.342 audit=87.366 at=1793987722 boot=bfc09a4c-feec-4ee4-9afe-5325f0ba28d3
e2e base: run 42205891659 9.5p1=734.884 10.5p1=720.077

## Task 1 (tracer)

e2e RED run: 42268260492

RED, before the production code:
- Unit tests: with cmd/keyroster/knownhosts.go moved aside (and restored byte for byte afterwards), `go vet ./cmd/keyroster/` fails to compile the new tests: `knownhosts_test.go:188:75: undefined: hostTrustInput`. TestHostTrustName, TestHostTrustCAs, TestKnownHosts, TestKnownHostsUnix and TestKnownHostsSync are therefore RED as compile failures.
- e2e RED from CI: run 42268260492 on the throwaway branch `p03/09b-e2e-red` (origin/main plus test/e2e/hosttrust_test.go only; `git diff --name-only origin/main...p03/09b-e2e-red` printed exactly that file; `go vet -tags e2e ./test/e2e/` passed there). Both lanes: `--- FAIL: TestHostCertNoTOFU/admin_sync_no_prompt` and `--- FAIL: TestHostTrustLongLines` (its part `a_host_line_read_whole`), each with the CLI's `unknown command "known-hosts"` (4 occurrences in the log), and no other failing top-level test. Go test elapsed: 9.5p1 745.969 s, 10.5p1 709.759 s. The branch was deleted; `git ls-remote --exit-code origin refs/heads/p03/09b-e2e-red` exits 2.
- The RED log also showed a test bug: the admin CLI wrapper was bound to the parent test, so its first failure inside a subtest ended the whole test ("subtest may have called FailNow on a parent test") and the later subtests never ran. Fixed after RED (deviation 1); the RED run met every condition of its gate.

GREEN: Task 1's verify 1 (build, vet, e2e vet, windows and darwin vet, the five test functions under -race with every named PASS line) and verify 2 (golangci-lint for linux, windows and darwin, gofmt) pass locally; verify 3 (one os.UserHomeDir call, one TestMain, commands.go unchanged) passes.

Task 1 e2e gate: run 42270936296, exit 0. Both lanes passed `TestHostCertNoTOFU/admin_sync_no_prompt`, `TestHostCertNoTOFU/name_outside_block_refused` and `TestHostTrustLongLines` with all three parts:
- (a) a Host line of 64,512 names of 61 bytes (a 4,129,016-byte state) read whole by `ssh -G`;
- (b) one `@cert-authority` line of about 1 MiB found by `ssh-keygen -F` for its first and last name;
- (c) the D7 block after the Include leaves the last name strict, and the negative control above the Include does not.

So neither CI OpenSSH needs split lines. Only Task 2's and Task 4's subtests failed, each for its own reason: `revoke: unknown subcommand "host"`, and a login that printed no refresh line. Go test elapsed: 9.5p1 742.026 s (+7.1 s against the base), 10.5p1 730.095 s (+10.0 s).

`TestHostCertNoTOFU/name_outside_block_refused` is a control: it shows the unmanaged name keeps the user's own configuration. The wildcard and prefix properties are carried by `TestHostTrustName/rejects_pattern_bytes` and `TestKnownHosts/prefix_names_exact`.

Mutants (each applied alone, run on its named subtest with `-timeout 5m`, killed by that subtest's `--- FAIL:` line, restored with `git checkout` and proven by `git diff --quiet -- cmd/keyroster/knownhosts.go`): all 11 killed.
- hostTrustName accepting `*`: TestHostTrustName/rejects_pattern_bytes
- the CA line over every entry's principals: TestKnownHosts/disabled_name_stays_in_block_without_ca_line
- the Host block from the current directory only: TestKnownHosts/removed_name_stays_in_block
- CheckStoredInstallation in place of the strict check: TestKnownHosts/directory_without_installation_id_refused
- the KRL floor equal to the stored version: TestKnownHosts/older_krl_refused_equal_accepted
- an older bundle's KRL verified under that bundle's own ops key: TestKnownHosts/older_bundle_krl_by_retired_key_refused
- the bundle floor absent: TestKnownHosts/older_bundle_freezes_ca_lines_krl_still_written
- an equal bundle with another ops key accepted: TestKnownHosts/equal_bundle_other_ops_key_refused
- the account-home check removed: TestKnownHostsUnix/home_differs_from_account_refuses
- a KRL written without VerifyManifest: TestKnownHosts/krl_other_signer_refused
- keyroster_known_hosts written before the KRL: TestKnownHosts/interrupted_write_never_widens_trust, killed by its own property ("interrupted after krl: n-r/c2/7 is accepted, which neither S nor S' accepts")

T1: 669ffaf

## Task 2 (host subject, revoke host)

RED, before the production code. The new and changed tests were run in a detached worktree at T1 with only the test files copied in:
- signerdb `TestLiveIssuanceForSubject`: FAIL `kr3_host`, `kr1_user_with_same_subject_not_found_for_host`, `prefix_exact` and `invalid_record_still_refused` (kr3 was not scanned). `kr1_host_via_ca_issue` and `user_role_unchanged` passed, as regression guards should.
- signer `TestRevokeHostSubject`: FAIL in every subtest but `subject_machine_still_unsupported`, which is a guard.
- audit: FAIL `TestVerifyRevokeHost/subject_host_matches_signer`, `TestVerifyRevokeHost/subject_host_kr1_and_kr3_both_listed` and `TestVerifyRevocations/revoke_subject_host_accepted`. `subject_host_missing_entry_fails`, `subject_machine_fails` and `revoke_subject_kind_machine_refused` passed, as guards should.
- cmd/keyroster: a compile failure (`undefined: recoveryKeptNotice`). With TestRevokeHost removed from the copy, the changed rows fail: `TestRevokeRefusalText/subject_kind_unsupported` (the old "revokes user subjects only") and `TestRevokeSerialConfirm/enforcement_by_role` (the old host sentence). `TestRevokeUser/sweep_text_unchanged` passes on T1, so it pins today's user output.

GREEN: verify 1 (the four packages' named tests under -race, every named PASS line) and verify 2 pass locally. In verify 2, `git diff origin/main` over wire, tlog, cert, the format registry, vectors and capslock is empty; vet, e2e vet and golangci-lint for linux, windows and darwin are clean; signer 335.8 s, signerdb, audit 82.1 s, wire, tlog, cert and cmd/keyroster 151.9 s all pass. The first lint run found `c.SignCert` in the new signerdb test (forbidigo: certificates are signed only by cert.Build); the helper now uses cert.Build.

Mutants, all 10 killed (same protocol as Task 1):
- the signer mapping SubjectHost to RoleUser: TestRevokeHostSubject/subject_host_kr3_and_kr1
- signerdb scanning only kr1 and kr2: TestLiveIssuanceForSubject/kr3_host
- the prefix without its closing `/`: TestRevokeHostSubject/subject_host_prefix_exact
- audit mapping host to user: TestVerifyRevokeHost/subject_host_matches_signer
- the CLI sweep checking the user CA role: TestRevokeHost/serials_checked_under_host_ca. The first application matched the identical line in runRevokeSerial and survived for that reason. Anchored to the sweep's loop, it was killed.
- the CLI returning before the directory step on a first-sweep error: TestRevokeHost/first_sweep_fails_still_disables_exit_1
- exit 4 where 3 applies: TestRevokeHost/keys_cap_with_proposal_prints_both_exit_3
- the server's keys requested (the served host's keys from the pending-hosts route appended): TestRevokeHost/keys_from_verified_entry_not_server
- the first omitted key aborting the loop: TestRevokeHost/keys_cap_revokes_serials_disables_sweeps_exit_3
- the notice dropped from revoke host: TestRevokeHost/recovery_kept_notice_printed

## Deviations

1. [Rule 1, test bug] test/e2e/hosttrust_test.go after its RED run: the admin CLI wrapper `hostTrustKR` failed the parent test from inside subtests. Each subtest now builds its own wrapper, and `hostTrustLongLines` takes no wrapper. No assertion changed.
2. The refusal connections (web2, `refused_after_refresh`, both `refused_through_*` subtests) offer `ssh-ed25519-cert-v01@openssh.com,ssh-ed25519` rather than the certificate algorithm alone, and each one uses its own loopback source. Both follow the pattern TestHostCertIssueAndServe already uses: OpenSSH 10.x drops the plain-key retry otherwise, and PerSourcePenalties would otherwise block 127.0.0.1. The positive web1 logins offer the certificate algorithm alone, as the plan says.
3. [Rule 1, test bug] test/e2e/hosttrust_test.go after the Task 1 gate: the copies of the old known-hosts and KRL were made in the revoke subtest's own temporary directory. That directory is removed when the subtest ends, so the `refused_through_*` subtests found no old KRL. The copies now live in a directory of the parent test. No assertion changed.
