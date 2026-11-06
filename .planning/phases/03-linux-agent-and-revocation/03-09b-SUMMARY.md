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

## Deviations

1. [Rule 1, test bug] test/e2e/hosttrust_test.go after its RED run: the admin CLI wrapper `hostTrustKR` failed the parent test from inside subtests. Each subtest now builds its own wrapper, and `hostTrustLongLines` takes no wrapper. No assertion changed.
2. The refusal connections (web2, `refused_after_refresh`, both `refused_through_*` subtests) offer `ssh-ed25519-cert-v01@openssh.com,ssh-ed25519` rather than the certificate algorithm alone, and each one uses its own loopback source. Both follow the pattern TestHostCertIssueAndServe already uses: OpenSSH 10.x drops the plain-key retry otherwise, and PerSourcePenalties would otherwise block 127.0.0.1. The positive web1 logins offer the certificate algorithm alone, as the plan says.
