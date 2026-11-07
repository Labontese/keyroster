---
phase: 03-linux-agent-and-revocation
plan: 09b
subsystem: hosts
tags: [cli, known-hosts, revoke, server, signer, audit, e2e, revoke-04]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-09 (kr3 host certificates by PoP, the host index, re-delivery, cert_revoked holds; PR #88)"
provides:
  - "cli: keyroster known-hosts sync; the one host trust writer (state, KRL, keyroster_known_hosts, keyroster_ssh_config) with its floors, bound, damaged-state rules, merge and Include check; the login refresh and --no-known-hosts"
  - "cli: keyroster revoke host NAME [--keys]; the role-generic sweepSubject; host losses revoked before every install path; directory install --yes"
  - "signer, signerdb, audit: the host subject (SubjectHost to the host role, kr1, kr2 and kr3 scanned)"
  - "server: the redeem answer's directory and directory_sigs from the mirror only (mirroredDirectory)"
  - "docs: enroll-user.md Trusting hosts without TOFU; revoke.md 4b; host-setup.md approval binding, revoke host, removals revoke first"
affects: [03-10, 03-11, 03-12, 03-16]

requirements-completed: [REVOKE-04]

actuals:
  tokens: 109788
  tasks: 5
  commits: 9
plan_head_before: 6cde9d01561386020a92eef43e805f015116b028
plan_head_after: bbe9cb24177deb0ba2a9335f17dca3d809f83421

tech-stack:
  added: []

key-files:
  created: [cmd/keyroster/knownhosts.go, cmd/keyroster/knownhosts_test.go, cmd/keyroster/knownhosts_unix_test.go, cmd/keyroster/hosttrust_runbook_test.go, internal/signer/revoke_host_test.go, test/e2e/hosttrust_test.go]
  modified: [cmd/keyroster/revoke.go, cmd/keyroster/dirpipe.go, cmd/keyroster/directory.go, cmd/keyroster/login.go, internal/signer/revoke.go, internal/signerdb/revocation.go, internal/audit/revoke.go, internal/server/login.go, internal/server/directory.go, docs/runbooks/enroll-user.md, docs/runbooks/revoke.md, docs/runbooks/host-setup.md]

metrics:
  duration: multi-session
  completed: 2026-11-06
---

# Phase 3 Plan 09b: CLI host trust, revoke host and the redeem directory (part b) Summary

Clients reach enrolled hosts with no TOFU prompt, from files the CLI writes after it has verified the directory and the KRL itself. `keyroster revoke host` ends a host's certificates and entry from one command. A version that removes a host, a principal or a key first revokes the old holder's live certificates. A login carries the signed directory from the mirror only.

REVOKE-04 is complete. It is CI-verified on OpenSSH 9.5p1 and 10.5p1 and is re-checked on real hosts in 03-16. REVOKE-01 stays open: this plan delivers its host subject, and its machine subject is 03-11's.

Owner answers: QB-1 QB-2 QB-3 QB-4 QB-5 QB-6 recovery-kept bundle-floor

QB-6 supersedes the design note's "before the Include": the D7 per-port block goes after the Include. OpenSSH reads an Include inside a non-matching Host block with NEVERMATCH, so above the Include the strict block would be inactive for every other managed name. `TestHostTrustLongLines` (c) proves the placement on both CI builds, with a negative control.

## Bases (quiet, on origin/main 6cde9d0)

The test-time base was measured in a detached worktree at origin/main outside the repository, with no other heavy job running.

test-time base: cmd=149.649 signer=332.769 server=96.365 audit=81.910 at=1793995205 boot=13c0d1f8-89c2-4f18-8f48-ee417bc52730
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

Task 2 e2e gate: run 42276644587, exit 0. Both lanes passed every subtest of `TestHostCertNoTOFU` except Task 4's `user_login_writes_files` (allowed), and `TestHostTrustLongLines`. Go test elapsed: 9.5p1 776.163 s (+41.3 s against the base), 10.5p1 744.980 s (+24.9 s). `refused_through_krl_alone` matched `\brevoked\b` in ssh's output on both lanes, but a passing subtest does not log that output, so the exact OpenSSH wording stays UNVERIFIED.

T2: 690967a (the code commit is 6a56968; 690967a records Tasks 1 and 2 in this file)

## Task 3 (losses revoked before the install)

RED: with the new tests in place, `go vet ./cmd/keyroster/` fails to compile them on T2's code (`dirpipe_test.go: undefined: hostLoss`). The changed `TestHostCommands/host_list_and_remove` needs a revoke before the install, which T2's code never sends.

GREEN: verify 1 (the seven test functions under -race, every named PASS line) and verify 2 (cmd/keyroster under -race, 146.8 s; golangci-lint for linux, windows and darwin; host.go, root.go, trust.go and runbook_test.go unchanged) pass. `TestRevokeHost/order_sweep_disable_sweep` still shows exactly revoke, directory, revoke: revoke host's own disable is no loss.

Mutants, all 10 killed (same protocol):
- hostLosses counting a disable: TestHostLosses/disable_is_not_a_loss
- hostLosses ignoring dropped keys: TestHostLosses/key_dropped
- hostLosses ignoring dropped principals: TestHostLosses/principal_dropped
- the revoke sent after the install: TestEditRevokesLossesBeforeInstall/quorum_1_remove_revokes_then_installs
- the install sent after a failed revoke: TestEditRevokesLossesBeforeInstall/no_post_after_failed_revoke
- directory install without its local quorum check: TestDirectoryInstallLosses/short_quorum_refused_nothing_revoked
- directory install revoking without consent: TestDirectoryInstallLosses/noninteractive_without_yes_refused
- a proposal revoking at propose time: TestEditRevokesLossesBeforeInstall/proposal_prints_losses_revokes_nothing
- no second sweep after the install: TestEditRevokesLossesBeforeInstall/removed_entry_second_sweep_after_install
- the notice dropped from the loss path: TestEditRevokesLossesBeforeInstall/recovery_kept_notice_printed

T3: 7bc39a0

## Task 4 (redeem directory, login refresh, the writer's edge rules)

RED. The new tests were run on T3's code in a detached worktree, with only the test files copied in:
- internal/server fails to compile them (`login_test.go: ans.Directory undefined (type loginRedeemResponse has no field or method Directory)`).
- cmd/keyroster fails to compile them (`knownhosts_test.go: undefined: maxHostTrustNames`; the login tests also need the answer's new fields).

GREEN: verify 1 (`TestLoginRedeem` and the five CLI test functions under -race, every named PASS line) passes. Verify 2 runs `FuzzHostTrustState` for 20 s (about 1.04 million executions, no crash, no corpus file written), vet, e2e vet, golangci-lint for three GOOS, and internal/server, internal/serverclient and cmd/keyroster under -race. Its first run found one lint issue in a new test: a variable named `real` shadowed the builtin.

Existing tests changed by the new behaviour, each minimally:
- `requireRedeemed` in internal/server now decodes the answer and checks the certificate, because an answer may now carry the directory. `requireRedeemedBare` keeps the exact-body check for the redeem-directory subtests.
- `TestKnownHosts/stale_manifest_warned_still_written` now checks for the KRL warning alone, because the Include advice also goes to stderr.
- `TestKnownHostsUnix/symlink_at_managed_name_replaced_not_followed` first writes a state: a managed name without a state is now the missing-state refusal.
- The login test fake now regenerates its genesis policy with an admin key the test holds, keeps the ops key, and serves the KRL route and the answer's directory.

Mutants, all 10 killed (same protocol):
- mirroredDirectory ignoring the SHA-256: TestLoginRedeem/directory_unavailable_still_returns_certificate
- mirroredDirectory calling currentDirectory: TestLoginRedeem/redeem_never_fetches_directory
- the answer failing when the mirror misses: TestLoginRedeem/directory_unavailable_still_returns_certificate
- the mirror read against a fresh Status: TestLoginRedeem/mirror_newer_than_status_misses
- the refresh failing the login when the directory is forged: TestLoginFlowFakeServer/forged_directory_in_answer_refused
- the bound dropping the oldest name: TestKnownHosts/bound_never_drops_a_name. Applied at the writer's bound check alone, it survived. The merge re-read unions the names with the state on disk and so restores the dropped name; that site cannot change behaviour on its own, the defence being in depth. Applied at both bound sites (the writer and the merge), it was killed.
- the config rewritten at the bound with the new names: TestKnownHosts/bound_freezes_config_keeps_krl_and_known_hosts
- the bound counting name bytes: TestKnownHosts/bound_state_at_cap_with_short_names_reads_back
- a missing state with managed files treated as a first run: TestKnownHosts/missing_state_with_managed_files_refuses_all_writes
- a newer concurrent state ignored: TestKnownHosts/concurrent_newer_state_writes_no_managed_file

Task 4 e2e gate: run 42281258247, exit 0. The whole e2e run is green on both lanes, with no `--- FAIL:` line. That covers `TestHostCertNoTOFU` with `user_login_writes_files`, `TestHostTrustLongLines`, `TestLoginEndToEnd`, `TestAgentEnrollEndToEnd` and `TestAgentReenrollEndToEnd`, and the e2e `host remove` sites, which now revoke before the install, needed no edit. Go test elapsed: 9.5p1 744.974 s (+10.1 s against the base), 10.5p1 771.331 s (+51.3 s). Both are under the 900 s stop, so TestHostTrustLongLines was not folded.

T4: 42cf597

## Deviations

1. [Rule 1, test bug] test/e2e/hosttrust_test.go after its RED run: the admin CLI wrapper `hostTrustKR` failed the parent test from inside subtests. Each subtest now builds its own wrapper, and `hostTrustLongLines` takes no wrapper. No assertion changed.
2. The refusal connections (web2, `refused_after_refresh`, both `refused_through_*` subtests) offer `ssh-ed25519-cert-v01@openssh.com,ssh-ed25519` rather than the certificate algorithm alone, and each one uses its own loopback source. Both follow the pattern TestHostCertIssueAndServe already uses: OpenSSH 10.x drops the plain-key retry otherwise, and PerSourcePenalties would otherwise block 127.0.0.1. The positive web1 logins offer the certificate algorithm alone, as the plan says.
3. [Rule 1, test bug] test/e2e/hosttrust_test.go after the Task 1 gate: the copies of the old known-hosts and KRL were made in the revoke subtest's own temporary directory. That directory is removed when the subtest ends, so the `refused_through_*` subtests found no old KRL. The copies now live in a directory of the parent test. No assertion changed.
4. The tracking update touches STATE.md and ROADMAP.md only. REQUIREMENTS.md, and the windows ledger `.planning/WINDOWS.md`, are outside the plan's files_modified, which the scope gate enforces. So REVOKE-04 is recorded in this file's `requirements-completed`, as 03-09 did for AGENT-06, and no stub or deviation was appended to a ledger.
5. `writeHostTrust` prints the `~/.ssh/config` Include advice on stderr, with the warnings, not on stdout. So the outcome line stays the only stdout line, which the exact-stdout tests of Tasks 1 and 4 rely on.
6. `TestKnownHosts/names_outside_charset_refused` swaps the writer's `parseHostTrustDirectory` seam for a plain JSON decode. Through Parse no directory value can fail hostTrustName (CheckHostPrincipal refuses every such byte first), so the KRL-only path for a name outside `[a-z0-9.:-]` is defence in depth, and only the seam can reach it. The bound test `bound_state_at_cap_with_short_names_reads_back` uses the same seam to feed 250,000 four-byte names per run.

## Gates that bite

- Scope gate: on a throwaway detached worktree with one extra commit adding an unlisted file, the files_modified gate exits 1.
- ROADMAP gate: on origin/main (`git diff origin/main...origin/main`) the changed-line filter is empty, so its `test -n` fails.
- Runbook test: see Task 5.

## Task 5 (runbooks, gates, PR)

The runbooks gained:
- enroll-user.md: "Trusting hosts without TOFU", items 1 to 9, and the two pointer lines in "Logging in";
- revoke.md: "4b. Revoking a host", with the box, the `--ca host` sentence, the section 4 bullet and the refusal row rewritten, and the recovery-kept sentence in section 7;
- host-setup.md: the QB-4 approval text in step 4, the Ports and "Disable versus revoke" paragraphs, and the removal text.

Nothing before `## Enrolling a host` changed: its md5 equals origin/main's, and both 03-14b anchors are unchanged. The todo host-approve-identity-binding moved to completed with `git mv`, and a Resolution was added. This plan's ROADMAP row text was updated.

`TestHostTrustRunbooks` uses only the standard library and its own `htrb` helpers. Run alone in an origin/main worktree, it builds and fails, reporting `placeholder present:` for `revoke_md_nothing_installs_yet`, `revoke_md_sync_arrives` and `revoke_md_subjects_arrive`, and for the three further rows, so it bites. On this branch all six subtests pass.

Gates, all passing:
- the runbook and anchor gate;
- the pins gate;
- the scope gate;
- authorship and signatures: every commit authored by Daniel, committed by keyroster-bot and signed;
- the ROADMAP gate;
- the scrub pre-check of the diff, the commit messages, the plan and this file.

The big gate (the whole module under -race, vet, e2e vet, the systemdsmoke vet, gofmt, golangci-lint for three GOOS, capslock, dep-firewall, testonly-firewall, pinned actions):
- First run: exit 1, for two reasons. `gofmt -l .` listed the new runbook test, a map alignment that the earlier `gofmt -l cmd` check had missed; it is fixed. And internal/signer read 434.274 s against the then-base of 329.831 s, that is +104.4 s.
- The base was then re-measured, quiet, in a fresh detached worktree at origin/main. The line above was replaced in place; the boot ID had changed, which is informational only.
- With the same four-package command as the base, HEAD reads cmd 183.137 s (+33.5 s), signer 323.037 s (−9.7 s), server 97.984 s (+1.6 s) and audit 83.527 s (+1.6 s). So this plan's own cost is about +34 s in cmd/keyroster (its new tests, about 36 s under -race; the bound tests are the heaviest at about 24 s). The rest of the first run's excess was contention under `./...`.
- Second run: exit 0. Readings under `./...` against the fresh base:

| Package | Base (s) | Reading (s) | Delta (s) |
|---|---|---|---|
| cmd/keyroster | 149.649 | 199.458 | +49.8 |
| internal/signer | 332.769 | 378.247 | +45.5 |
| internal/server | 96.365 | 143.177 | +46.8 |
| internal/audit | 81.910 | 90.859 | +8.9 |

The capslock baselines are unchanged and `scripts/capslock-check.sh` passes.

e2e budget: the e2e base is 9.5p1 734.884 s and 10.5p1 720.077 s.

| Gate | 9.5p1 (s) | Delta (s) | 10.5p1 (s) | Delta (s) |
|---|---|---|---|---|
| Task 1 | 742.026 | +7.1 | 730.095 | +10.0 |
| Task 2 | 776.163 | +41.3 | 744.980 | +24.9 |
| Task 4 | 744.974 | +10.1 | 771.331 | +51.3 |

Every run was under the 900 s stop, so no fold and no timeout change was needed.

PR: #89 (`feat(hosts): CLI host trust, revoke host and the redeem directory`), opened by keyroster-bot with auto-merge off.

All 26 required checks passed on bbe9cb2. The runs were Systemd 42288878763, CodeQL 42288878767, PIV 42288878782, E2E distro 42288878792, E2E 42288878826, CI 42288878828, Workflow lint 42288878834, E2E PKCS#11 42288878836, E2E TPM 42288878843 and PR title 42288878847. CI includes build-test, lint, cli-windows, cli-macos, fuzz, govulncheck, capslock and dependency-firewall.

The PR's e2e run 42288878826 passed `TestHostCertNoTOFU` and `TestHostTrustLongLines` on both lanes, with no `--- FAIL:`. Go test elapsed: 9.5p1 771.621 s (+36.7 s), 10.5p1 760.300 s (+40.2 s).

The tracking update then followed (STATE.md and ROADMAP.md, deviation 4) in the `docs(03-09b): complete host-trust plan` commit. That commit is the tenth, and it carries this file. `commits: 9` above was measured before it, from the plan ledger.

## UNVERIFIED (Edge Coverage)

- OpenSSH reading one `@cert-authority` line of about 1 MiB, or one Host line at the 4 MiB bound. `TestHostTrustLongLines` proves the two CI builds only (9.5p1 and 10.5p1), with a Host line of 64,512 names (4,128,768 encoded name bytes; the state file holding them is 4,129,016 bytes) and a CA line of 1 MiB.
- `~` expansion on older OpenSSH, and on any OpenSSH but the two CI builds.
- The exact OpenSSH wording when a KRL refuses a host certificate. The e2e matched `\brevoked\b` on both lanes, but a passing subtest does not log the text.
- The Windows OpenSSH client and Windows file modes. cmd/keyroster's unit tests run on the Windows and macOS CI lanes (the unix-only mode, symlink and home tests excluded), but no Windows client used the files.
- CheckHostIP at its default: it is not set in the block, and its behaviour with certificate host keys on older clients is unproven.
- That the mirror usually hits at redeem. A miss is safe, and only the unit tests and the e2e login exercise it.
- The account-home check (QB-5): skipped on Windows, and driven through the `accountHome` hook in the unit tests. A failed lookup only warns, so in the CGO_ENABLED=0 Linux release an account known only through NSS or LDAP gets no home check.
- An ops-key rotation between a restored backup and the newest bundle the client saw stalls the KRL until the bundle catches up (T-03-347 residual; rotations arrive with 03-13).
- Every runbook claim on a real host or client, until 03-16.
- OpenSSH clients below 8.5 (for example 8.0p1 on RHEL, Rocky or Alma 8) reading the managed config with its top-level `IgnoreUnknown KnownHostsCommand` (D-R4). No CI lane runs one. On 9.6p1, a keyword ssh does not know stood in for it: it was fatal inside a non-matching Host block and inside the block after an in-block IgnoreUnknown, and the top-level IgnoreUnknown made it parse.

## Decisions

- Advice on the `~/.ssh/config` Include and every warning go to stderr. The outcome line is the only stdout line of a refresh.
- At the bound the outcome is `Host trust partly refreshed: the Host block is at its bound, N new name(s) not covered (...)`, and `sync` exits 3.
- A run behind a newer state on disk writes nothing and says so. The same holds for an equal directory version with another SHA-256 on disk.
- The loss revokes carry the audit reason `directory version N drops host NAME`.

## Pre-merge review

Review run wf_be40e37a-21e: the orchestrator's full security review of PR #89, head d156c66 on base 6cde9d0, against T-03-59, T-03-60, T-03-61, T-03-100, T-03-240, T-03-241 and T-03-345 to T-03-349. Two skeptics checked each finding unless noted. Fix round 1 is commits 9fd5556 to a27bfae, on top of d156c66 (no rewrite).

Each RED below was taken locally, with the fix reverted and the new or changed test run, and the fix then restored. Windows paths are left out.

| Finding | Severity | Outcome | Commit |
|---|---|---|---|
| F1: the revocations-only path did not record a newer bundle | medium | fixed | dd7da7f |
| F2: no `KnownHostsCommand none` in the managed block | low | fixed | 5787dc7 |
| F3: `revoke host` had no directory floor | low | fixed | 1115de2 |
| F4: `directory install` did not check the installation | low (split 1/2) | fixed | 9b6fbbd |
| F5: `cited_tests_exist` read its own file | low | fixed | 9fd5556 |
| F6: STATE.md said 24 of 29 | low | fixed | e499893 |
| F7: the long-line byte label | low | fixed | e499893 |
| D-R1: concurrent refreshes | low | narrowed and documented | 39f88ca |
| D-R2: the re-revoke hold | split | documented | a27bfae |
| D-R3: host-name scope | design gap | documented, todo | a27bfae |
| Redeem answer size within the 30 s timeouts | low (split) | no action | none |

**F1 (medium): the revocations-only path did not record a newer bundle.** Where there was no verified directory and the bundle was not older, `writeHostTrust` raised only the KRL version. A KRL that had verified under a newer bundle's ops key therefore left `bundle_version` and `ops_key` at the old bundle, and a server could later serve a bundle between the two as if it were newer.
- Fix: whenever the bundle is not older, that path now records the bundle's version and ops key too. The older-bundle and equal-version rules are unchanged.
- The CA lines stay as they are. Plan line 135 settles only `bundle_version` and `ops_key` ("ops_key follows the higher bundle_version"), and without a verified directory there is no active set to write CA lines over. The next verified directory writes them under the newer bundle.
- Test: `TestKnownHosts/revocations_only_records_newer_bundle`. Bundle v1 is written in full. Then v3, with a rotated ops key and no directory, is partial and must record v3 and its key. Then v2, re-served with a newer directory, must be refused as older, and known_hosts and config must keep their bytes.
- RED: `knownhosts_test.go:806: state &{... BundleVersion:1 ...}, want bundle version 3 and its ops key recorded on the revocations-only path`.

**F2 (low): no `KnownHostsCommand none` in the managed block.** A `KnownHostsCommand` from later configuration applied to managed names.
- Fix: `hostTrustBlockOptions` now carries `KnownHostsCommand none`. There is no code-emitted D7 block: it is user-written, with Port and HostKeyAlias only. enroll-user.md item 1 names the option.
- Tests: `TestKnownHosts/ssh_config_keywords_exact` and `htConfig` now expect it. The e2e `TestHostTrustLongLines` part `c_d7_block_after_include` adds a config that has the Include, the D7 block, then `Host *` with `KnownHostsCommand /bin/true`. `ssh -G` must print no `knownhostscommand` for the first or the last managed name. As a control, it must print `knownhostscommand /bin/true` for `outside-name`.
- RED, unit: with the option line removed, `--- FAIL: TestKnownHosts/writes_three_files_and_state` and `--- FAIL: TestKnownHosts/ssh_config_keywords_exact`.
- RED, OpenSSH oracle: on WSL's OpenSSH_9.6p1, `ssh -G` over the block without the option, followed by `Host *` / `KnownHostsCommand /bin/true`, printed `knownhostscommand /bin/true` for the managed name. With the option it printed none for the managed name, and the outside name still got the command. 9.6p1 accepts `none`.
- On the CI builds (9.5p1 and 10.5p1): see the CI line below.

**F3 (low): `revoke host` had no directory floor.** `fetchVerifiedDirectory` has no version floor, and on the already-disabled branch no install POST is sent, so no `version_chain` refusal comes back either.
- Fix: `revoke host` now passes `checkHostTrustFloor` as the edit's `CheckBase`. It applies when this user's host-trust.json belongs to the bundle's installation, and it uses the writer's rule: a served version older than the recorded one is refused, and so is an equal version with another SHA-256. A served version 0 under a recorded version above 0 counts as older.
- A refused base fails the directory step. That is exit 3, per the plan's and revoke.md 4b's row "3: a partial result: the directory step failed (the host is NOT disabled)". It becomes exit 1 when the first sweep failed too ("1 beats both").
- The first sweep still runs before the check, so a revocation never waits on directory freshness.
- Both already-disabled lines now state what was observed: `Directory version N, the admin-signed version the server serves, lists NAME as disabled: no directory change. That is the server's word ...`. The final line reads `Directory version N lists NAME as disabled (the server's word), and the KRL lists ...`.
- A state that cannot be read only warns, and the floor is not checked then. That choice is open for the owner (see below).
- Tests: the new `TestRevokeHost` subtests are `stale_directory_already_disabled_refused_exit_3`, `stale_directory_active_refused_exit_3`, `equal_version_other_sha_refused_exit_3`, `floor_equal_version_same_sha_exit_0`, `floor_of_another_installation_ignored` and `unreadable_floor_warns`.
  - The three refusal subtests assert exit 3 and that only the first revoke was posted. They also assert no key request with `--keys`, nothing signed, and no "disabled" claim.
  - `already_disabled_sweeps_twice_exit_0` asserts the new texts.
- RED: with revoke.go at d156c66, `already_disabled_sweeps_twice_exit_0`, the three refusal subtests and `unreadable_floor_warns` failed. Without the floor, the stub installed a version built on the stale base and exited 0.

**F4 (low, split 1/2): `directory install` did not check the installation.**
- Fix: `runDirectoryInstall` now applies `directory.CheckInstallation` right after `checkProposalBase`, as `directory sign` does, before the losses are computed or consent is asked. The refusal ends with "Nothing was revoked or installed".
- Tests: `TestDirectoryInstallLosses/other_installation_refused_before_losses` and `unbound_refused_before_losses` run on a terminal answering y. They assert exit 1, no loss text, no prompt, no POST and no revoke.
- RED: both failed with `exit 0, stderr ""`. The stub revoked web1, installed the unbound version and swept again.
- Deviation (Rule 3): five pipeline fixtures that installed an unbound proposal against the stub now bind it to the stub's installation, as every CLI edit does and as a real signer requires. Their own assertions are unchanged. The fixtures are in `stale_proposal_install_message`, both proposals of `proposal_already_served`, `discarded_credential_install_message`, and `TestDirectoryPeerText/install_answer_mismatch`.

**F5 (low): `cited_tests_exist` read its own file.** The check read every `_test.go` file, its own included, so the subtest names that file quotes as `htrbWant` tokens satisfied it.
- Fix: it now skips hosttrust_runbook_test.go.
- RED: `older_bundle_freezes_ca_lines_krl_still_written` was renamed locally in knownhosts_test.go.
  - With the old check, `cited_tests_exist` passed.
  - With the fix it failed: `enroll-user.md Trusting hosts without TOFU cites TestKnownHosts/older_bundle_freezes_ca_lines_krl_still_written, but no test names a subtest`.
  - The rename was restored. With the real names the check passes, so no cite was broken.

**F6 (low): STATE.md said 24 of 29.** It now says "Plan: 24 of 30", which matches ROADMAP's 30 plans.

**F7 (low): the long-line byte label.** UNVERIFIED (Edge Coverage) now gives the Host line 4,128,768 encoded name bytes, per plan line 325. The 4,129,016 bytes are the state file's size.

**Owner decisions, 2026-11-06 (Daniel):**
- **D-R1: concurrent refreshes (codex, upheld low). Narrowed and documented.** There is no lock file and no new syscall kind (Lstat, ReadFile and Rename, as before).
  - `replaceManagedFile` takes a check that runs between the temporary file's close and its rename. For each managed file, `write` passes `overtaken`, which reads host-trust.json again. Before the KRL it also reads the KRL on disk and parses its header version.
  - The run stops, with no further writes, when another run has recorded a newer state, or when the KRL on disk is newer than this run's KRL bytes. It reports `Host trust not refreshed: a concurrent refresh won: ...` (hostTrustNone; `sync` exits 1, as for merge's existing stop).
  - "Newer" is merge's own predicate, now one function (`newerHostTrustState`): a higher bundle, directory or KRL version, or another SHA-256 at the same directory version.
  - Test: hostTrustFault seeds the other run's write between two renames, which is deterministic. The subtests are `TestKnownHosts/concurrent_state_after_state_step_stops_krl`, `..._after_krl_step_stops_known_hosts`, `..._after_known_hosts_step_stops_config` and `concurrent_newer_krl_on_disk_stops_krl`.
  - RED: with the check disabled, all four failed with `writer result 2, want 0`.
  - Residual, documented in enroll-user.md item 2: a rename right after the check can still land behind the other run's. An older KRL, older CA lines or an older Host block then stays in place, so a revocation the newer KRL holds is not enforced until the next refresh heals it. The window itself is UNVERIFIED.
  - Residual, the state: the state's own rename has no check (merge's re-read comes just before it), so two runs can swap their state writes. The state then keeps the slower run's floors, never below the ones it began with. The KRL file is still protected by the disk-KRL check. Until a refresh from an honest server raises the floors again, a compromised server could serve a directory version between the two runs' versions (T-03-347). A check before the state rename would need a new hook, and the decision was to narrow and document, so this is documented only.
- **D-R2: re-revoke hold (split). Documented only, no signer or audit change.** revoke.md 4b ("The hold") now says that a repeated revoke only holds if the certificate was not already revoked: `hostIndex.markRevoked` keeps the first `revokedAtDir`. Once a newer directory version is installed, running `revoke host` again does not renew `cert_revoked`. The second sweep or the next `revoke host` catches a re-issued certificate, and the hard barrier is Phase 4's issuance barrier.
  - T-03-349 residual, added by this review: a repeated `revoke host` only holds a host key whose latest certificate was not already revoked, so after a newer directory version has been installed it does not renew `cert_revoked`; a certificate re-issued in between is caught by the second sweep or the next `revoke host`, and the hard barrier is Phase 4's issuance barrier.
- **D-R3: host-name scope (critic). Refuted as a PR defect, kept as a design gap.** No code change.
  - The todo `.planning/todos/pending/2026-11-06-root-signed-host-name-scope.md` covers a root-signed host-name scope in the trust policy, enforced by the signer and the client, and resolves in Phase 4.
  - enroll-user.md ("Which names every client pins", before item 9) and host-setup.md (the approval step, after the `host approve` paragraph) now say three things: admins choose the names every client pins, an external or wrong name affects every user, and a user drops one by starting over (item 8).
  - No gate compares files_modified against the diff: scripts/, cmd/, internal/, test/ and .github/ do not name it. So the todo is not added to the plan's frontmatter.

**No action (recorded):** after the code is burned, the redeem answer can add up to about 1.4 MiB within the 30 s server WriteTimeout and client requestTimeout. This was split, low. D4 accepted the directory in the redeem answer.

**Open for the owner:** F3 lets a host-trust.json that cannot be read (damaged, a symlink) warn and skip the floor, instead of failing the directory step. The fix instruction left this case open, and the review chose the reading that does not block a revocation on local damage. A server cannot cause that damage. The other choice is to fail closed (exit 3) until the user starts over.

**Local gates after the fixes.**
- Windows: `go vet ./cmd/keyroster/` and `go test -count=1 ./cmd/keyroster/` pass.
- Linux (scripts/linux.sh): all of these pass.
  - `go build ./...`, `go vet ./...` and `go vet -tags e2e ./test/e2e/`;
  - `gofmt -l .` is empty;
  - `go test -race -count=1 ./cmd/keyroster/`;
  - golangci-lint v2.14.0 on cmd/keyroster and test/e2e, plus GOOS=windows and GOOS=darwin for cmd/keyroster, with 0 issues.
- internal/signer was not touched.

CI on the fix head a27bfae:
- e2e run 42305323004 passed on both lanes with no `--- FAIL:`. `--- PASS: TestHostTrustLongLines (` appears twice, and its part `c_d7_block_after_include` passed on 9.5p1 and 10.5p1, so 9.5p1 accepts `KnownHostsCommand none` and the new assertion holds there. `TestHostCertNoTOFU` passed on both lanes.
- Go test elapsed: 9.5p1 786.024 s (+51.1 s against the base), 10.5p1 770.000 s (+49.9 s). Both are under the 900 s stop.
- CI run 42305323153 passed build-test, lint, capslock, govulncheck, cli-windows, cli-macos and fuzz.
- The e2e-distro, e2e-pkcs11, e2e-tpm, systemd-sandbox, CodeQL, pinned-actions and pr-title checks passed too.

Commit e0fccdf (docs only) added the state-swap residual to enroll-user.md.

### Fix round 2

Fix-round check wf_e48c6ab7-676 on head 66611da: lows only. Round 2 is commits fcb6aef, 38f3231 and 4ad4638, on top of 66611da (no rewrite).

| Finding | Severity | Outcome | Commit |
|---|---|---|---|
| G1: `KnownHostsCommand` is fatal on ssh below 8.5 | low (2/2) | fixed per D-R4 | fcb6aef |
| G2: revoke host's lines claimed more than was checked | low (2/2) | fixed | 38f3231 |
| G3: names a state swap can drop | low (split 1/2) | documented | 4ad4638 |
| Unreadable host-trust.json in `revoke host` | noted | no change | none |

**G1 (low): `KnownHostsCommand` is fatal on ssh below 8.5.** `KnownHostsCommand none` came with OpenSSH 8.5. An older ssh refuses an unknown keyword even inside a Host block that does not match, so once the Include is added, every ssh would fail.
- Owner decision D-R4 (2026-11-07): an IgnoreUnknown line at the top. When the config has names, its first directive is now `IgnoreUnknown KnownHostsCommand`, at top level after the two header comments and before the Host block. A config without names stays header only. `KnownHostsCommand none` stays.
- The Include advice, the two scan notes and the managed file's header comment now say "at top level, before the first Host or Match line".
- enroll-user.md item 1 explains three things: the line, that the Include must sit at top level (IgnoreUnknown acts only where its line is active), and that ssh keeps the first IgnoreUnknown, so a user with an earlier IgnoreUnknown of their own adds KnownHostsCommand to that list. Clients below 8.5 are UNVERIFIED, listed above.
- Tests:
  - `TestKnownHosts/ssh_config_keywords_exact` and `htConfig` expect the line first.
  - e2e `TestHostTrustLongLines` part `c_d7_block_after_include` checks that the managed file has the line right before its Host line. For the first and the last managed name, `ssh -G` of the managed file must print `ignoreunknown KnownHostsCommand` and otherwise exactly what the same file without the line prints. Part (a) already requires `ssh -G -F <managed file>` to exit 0.
- RED, unit: with the line not written, `--- FAIL: TestKnownHosts/writes_three_files_and_state` and `--- FAIL: TestKnownHosts/ssh_config_keywords_exact`.
- Oracle on WSL's OpenSSH_9.6p1:
  - With and without the line, the managed file's `ssh -G` output for two managed names and one outside name differs only by the added `ignoreunknown KnownHostsCommand` line, and every run exits 0.
  - The mechanism, with a keyword 9.6p1 does not know standing in: inside a non-matching Host block it exits 255 (`Bad configuration option`), and with an IgnoreUnknown inside the block it still exits 255. With a top-level IgnoreUnknown it exits 0.

**G2 (low): revoke host's lines claimed more than was checked.** revoke.md step 2 said the output calls an already-disabled or absent NAME the server's word, but the absent line did not say so. The already-disabled line claimed the host-trust floor was checked even when no readable state existed.
- Fix: `checkHostTrustFloor` now also returns what it checked, and both lines say it is the server's word and end with one of three notes:
  - `it is not older than directory version N, which your host trust files hold`;
  - `there is no host trust state of this installation, so no version floor was checked`;
  - `your host trust state could not be read (see the warning), so no version floor was checked`.
- A served version 0 now prints `NAME is in no directory: the server serves none ...` instead of naming "directory version 0".
- revoke.md step 2 lists the three cases.
- Tests: `already_disabled_sweeps_twice_exit_0`, `unknown_name_sweeps_warns_exit_3`, `floor_equal_version_same_sha_exit_0`, `floor_of_another_installation_ignored` and `unreadable_floor_warns` pin the exact notes. The new `no_directory_served_says_so_exit_3` covers version 0.
- RED: with revoke.go at 66611da, all six failed.

**G3 (low, split 1/2; docs only): names a state swap can drop.** The D-R1 state-swap residual in enroll-user.md item 2 now also covers names. When two runs swap their state writes, the names the faster run added can be missing from the state and the Host block. They come back when a directory that lists them is served again. A name removed from the directory in between does not come back: it leaves the strict block and falls to the user's own ssh configuration (T-03-346 under this race).

**No change, noted:** an unreadable host-trust.json in `revoke host` keeps warn-and-skip. The check's skeptics refuted it as a defect: a missing file skips the floor too, and a server cannot damage the file. The lens that looked at it preferred failing closed; that is noted, not adopted.

**Local gates after round 2.**
- Windows: `go vet ./cmd/keyroster/` and `go test -count=1 ./cmd/keyroster/` pass.
- Linux (scripts/linux.sh): all of these pass.
  - `go build ./...`, `go vet ./...` and `go vet -tags e2e ./test/e2e/`;
  - `gofmt -l .` is empty;
  - `go test -race -count=1 ./cmd/keyroster/`;
  - golangci-lint v2.14.0 on cmd/keyroster and test/e2e, plus GOOS=windows and GOOS=darwin, with 0 issues.

CI on the round-2 head 4ad4638: all 27 checks passed.
- e2e run 42336954875 passed on both lanes with no `--- FAIL:`. `TestHostTrustLongLines` passed twice, its part `c_d7_block_after_include` included, so 9.5p1 and 10.5p1 both accept the top-level line, and it changes nothing else `ssh -G` prints for a managed name. `TestHostCertNoTOFU` passed on both lanes.
- Go test elapsed: 9.5p1 794.451 s (+59.6 s against the base), 10.5p1 801.425 s (+81.3 s). Both are under the 900 s stop and within 6 minutes of the base.
- CI run 42336954913 passed, fuzz included.
- The round-1 docs head 66611da was green on every workflow too: CI run 42308744617 and E2E run 42308744450.

## Self-Check: PASSED

Every created file exists (knownhosts.go and its two test files, hosttrust_runbook_test.go, revoke_host_test.go, test/e2e/hosttrust_test.go, the plan, the moved todo), and each recorded commit (859f99e, f770e17, 669ffaf, 6a56968, 690967a, 7bc39a0, 457a001, 42cf597, bbe9cb2) is an ancestor of HEAD. Pre-merge fix round 1: the todo 2026-11-06-root-signed-host-name-scope.md exists, and 9fd5556, e499893, dd7da7f, 9b6fbbd, 1115de2, 39f88ca, 5787dc7, a27bfae and e0fccdf are ancestors of HEAD. Fix round 2: 66611da, fcb6aef, 38f3231 and 4ad4638 are ancestors of HEAD.
