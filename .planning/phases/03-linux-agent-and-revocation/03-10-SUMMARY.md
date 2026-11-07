---
phase: 03-linux-agent-and-revocation
plan: 10
subsystem: signer, audit, server, ci
tags: [probe-certificates, krl, pop, d-06, e2e]
status: complete
requires: [03-09, 03-09b]
provides:
  - "wire.ProbeIssueRequest (frame 0x0B), leaf kind 12 probe_issue, ProbeIssueBody.RevokedEntries"
  - "Signer.ProbeIssue with probe_cert_recent, exact-retry re-delivery and the negative publish rule"
  - "verifyProbeIssue in audit verify, Report.PendingNegativeProbes, the probe_issue export line"
  - "POST /api/v1/agent/probecert on the agent share"
  - "the keyroster-probe: reservation at cert.Build and CheckIssued, principal_reserved and account_reserved at install"
  - "the e2e-probe CI job on OpenSSH 9.5p1 and 10.5p1"
affects: [03-10b, 03-10c, 03-11]
tech-stack:
  added: []
  patterns: ["one derivation of a negative probe's revoked entry", "one KRL size rule (buildKRLLocked)", "one probe window rule (certprofile.ProbeCertRecent)"]
key-files:
  created: [internal/wire/probeissue.go, internal/signer/probeissue.go, internal/signer/probeindex.go, internal/audit/probeissue.go, test/e2e/probe_certs_test.go]
  modified: [internal/tlog/leaf.go, internal/signer/logstate.go, internal/signer/krl.go, internal/cert/builder.go, internal/certprofile/certprofile.go, internal/server/agent.go, .github/workflows/e2e.yml, .github/rulesets/main-integrity.json, docs/format-registry.md]
decisions:
  - "03-10: a negative probe is its own revoked serial, derived once by ProbeIssueBody.RevokedEntries for the row, the logged set and audit"
  - "03-10: a negative row rides the hourly republish while the host keeps a published negative live for 2 h; probe-caused publishes are at least a minute apart, the prompt flag gated on the age"
  - "03-10: keyroster-probe: is reserved at the signing funnel (cert.Build and CheckIssued), the flag set only by ProbeProfile; install refuses it in role principals and as an account"
metrics:
  duration: "about 2.5 h"
  completed: 2026-11-07
actuals:
  tokens: 109800
  tasks: 5
  commits: 5
plan_head_before: 70ac72b30089b65e3502720a5ca506b8bdf98213
plan_head_after: 06042eac98d0ba3adfe71d94eb9ad26989777f87
requirements-completed: []
---

# Phase 3 Plan 10: Probe certificates by proof of possession (signer half) Summary

The signer issues, logs and revokes probe certificates by proof of possession. It uses frame 0x0B and leaf kind 12, and the certificates are machine-CA user certificates with force-command /bin/false and a loopback source-address. A negative probe is revoked by its own serial in the same transaction. The signer restarts on that log, and audit re-proves each probe. keyroster-server relays requests on the agent share. The prefix `keyroster-probe:` is reserved at the signing funnel. Real sshd (OpenSSH 9.5p1 and 10.5p1) accepts the positive certificate and refuses the negative one in a CI job of its own.

Owner answers: Q1 Q4 Q5 Q6 planner-defaults P1 P2 P3 P4 (Q2 -> 03-10b, Q3 -> 03-10c)
AGENT-04: open until 03-10b and 03-10c

The requirement AGENT-04 is not claimed complete (`requirements-completed: []`).

## Bases

The test-time base was measured in a detached worktree at origin/main (70ac72b) outside the repository, with no other heavy job running, with the one six-package command of the plan.

test-time base: signer=322.794 audit=84.708 server=116.137 cert=5.639 tlog=4.063 wire=8.549 at=1794051707
e2e base: run 42344987848 9.5p1=736.217 10.5p1=759.164

## Task 5 and the PR

PR: #90 (https://github.com/Labontese/keyroster/pull/90), opened by keyroster-bot without auto-merge. The required checks of its head, and the PR's own e2e run, are listed in the final report. They are not written here because the head moves with this SUMMARY's own commit.

The test-time readings use the one six-package command, on this branch at T4 (5bc5c42) with the base line above:

| Package | Base (s) | Reading (s) | Delta (s) |
|---|---|---|---|
| signer | 322.794 | 342.435 | +19.6 |
| audit | 84.708 | 87.101 | +2.4 |
| server | 116.137 | 124.357 | +8.2 |
| cert | 5.639 | 7.132 | +1.5 |
| tlog | 4.063 | 3.736 | -0.3 |
| wire | 8.549 | 8.083 | -0.5 |

Every delta is far below the 90 s stop. The whole-module `go test -race ./...` is a pass or fail gate only, and its times are not compared with the base.

The gates of Task 5 on the committed branch:
- The scope gate passes: no agent, CLI, trust, runbook, pinned, capslock, distro, systemd or script file changed.
- The files_modified gate passes. On a throwaway detached worktree with one commit adding an unlisted file, the same gate exits 1 ("outside files_modified: internal/zz_unlisted.txt"), so it bites.
- The later-plan wave gate passes: 03-11 to 03-16 changed only their wave lines (26 to 31), and 03-11 also its depends_on and its precondition's SUMMARY name.
- The ROADMAP gate passes. On origin/main its changed-line filter is empty, so `test -n "$RD"` fails there: the gate bites.
- The authorship gate passes: every commit is authored by Daniel, committed by keyroster-bot, and signed.

The whole-module gate (Task 5's long chain) was split. Its step `golangci-lint run --build-tags e2e,e2eprobe ./test/e2e/` exits 1 on the 16 issues that exist on origin/main (see Deviations). A single `&&` chain would then never reach the steps after it. Each step was run on its own: go test -race ./..., go vet (default, e2e, e2e e2eprobe and e2e systemdsmoke tags), gofmt -l ., the lint for linux, windows and darwin, capslock-check, dep-firewall, testonly-firewall and check-pinned-actions. The e2e lint was counted for probe_certs_test.go alone (0 issues).

The fuzz targets FuzzParseProbeIssueRequest, FuzzParseProbeIssueSigningBytes and FuzzDecodeLeaf ran for 30 s each before the PR. There was no crash and no new corpus entry.

## Task 1

T1: bd8936f

RED, before the production code: the new and changed test files were copied into a detached worktree at origin/main (70ac72b) and vetted there. Every package failed to compile on the missing symbols:
- internal/wire: `probeissue_test.go:41:38: undefined: ProbeIssueRequest`
- internal/tlog: `leaf_test.go:964:45: undefined: ProbeIssueBody`
- internal/signer: `probeissue_test.go:52:79: undefined: wire.ProbeIssueRequest` (and further undefined wire symbols)
- internal/audit: `probeissue_test.go:82:24: undefined: wire.ProbeIssueRequest`
- test/e2e (tags e2e e2eprobe): `probe_certs_test.go:103:14: undefined: wire.ProbeIssueRequest`

The audit stub came first: a verifyProbeIssue that parses the request, parses the certificate with ssh.ParsePublicKey, parses its key ID with cert.ParseKeyID, records the certificate and the negative entry, and checks nothing else. It calls neither checkIssue nor a.checkIssue. Against it, TestVerifyProbeIssue failed every fail-direction subtest except the two the plan excludes, negative_missing_from_next_publish_fails and malformed_logged_request_fails, which passed as expected:

audit stub RED: 31 of 31 fail-direction subtests failed

A first stub run showed pop_hosts_off_fails passing for the wrong reason. A successor policy may not clear pop.hosts (trust's pop_hosts_removed), so installPolicy failed on that rule and not on audit's. The subtest now runs on a fixture whose genesis policy never set pop.hosts. With that fix it failed against the stub and passes against the real verifier. (TestVerifyHostIssue/pop_hosts_off_fails on main has the same shape. It is not changed here: out of scope.)

The e2e results, on OpenSSH 9.5p1 and 10.5p1 locally (all eleven subtests passed on both builds):

FACT KRL OpenSSH_9.5p1, OpenSSL 3.0.13 30 Jan 2024: garbage file: positive refused; empty file: positive accepted
FACT KRL OpenSSH_10.5p1, OpenSSL 3.0.13 30 Jan 2024: garbage file: positive refused; empty file: positive accepted

## Task 2

T2: 13ad185

RED, before the production code: the Task 2 test files (internal/signer/probeissue_test.go and internal/audit/probeissue_test.go) were copied into a detached worktree at T1 (bd8936f) and vetted there. Both failed to compile:
- internal/signer: `probeissue_test.go:675:29: undefined: probeIndex`, `e.s.loaded.probes undefined`, `e.s.probePrompt undefined`, `e.s.lastProbePublish undefined`
- internal/audit: `probeissue_test.go:543:33: rep.PendingNegativeProbes undefined`

The size edge in TestProbeIssue/krl_too_large_refuses_issuance:
- The seed is 4176 key_id rows of 1000 bytes under the machine CA key, staged by a recursive CTE in a `bulk` table.
- An AFTER INSERT trigger on `issuance` copies them into `revocation` inside the issuance's own transaction.
- The size is linear in one tuning row's key ID length, because a key ID is length-prefixed. That length is solved directly, not bisected, and checked twice: the set encodes to exactly krl.MaxKRL, and one byte more is krl.ErrTooLarge. Only then does the signer run.
- All four subtests pass: immediate, ride, coalesced and edge_exact_fits.

## Task 3

T3: 4c5b9fa

RED, before the production code: the Task 3 test files (cert/builder_test.go, signer/probeissue_test.go, audit/probeissue_test.go, server/agent_test.go, capacity_test.go and server_test.go) were copied into a detached worktree at T2 (13ad185) and vetted there. All four packages failed to compile:
- internal/cert: `builder_test.go:663:63: unknown field ReservedPrincipals in struct literal of type Profile`
- internal/signer: `probeissue_test.go:1460:27: undefined: cert.ErrReservedPrincipal`, `undefined: cert.ReservedPrincipalPrefix`
- internal/audit: `probeissue_test.go:157:123: unknown field ReservedPrincipals in struct literal of type cert.Profile`
- internal/server: `agent_test.go:622:68: undefined: serverclient.AgentProbeCertPath`

## Task 4

T4: 5bc5c42

The CI job (e2e.yml):
- Job `e2e-probe` with the matrix 9.5p1 and 10.5p1, the e2e job's commit-pinned actions and the same OpenSSH cache path and key.
- `go test -tags "e2e e2eprobe" -run '^(TestProbeCertsAgainstSSHD|TestProbeSSHDFacts)$' -count=1 -timeout 12m`, with `timeout-minutes: 20`.
- The step `Check that both probe tests ran and passed`, and no job condition or path filter.
- The main job's lines are unchanged; only the header comment changed.
- The check step bites. The gate cuts its run script out of e2e.yml and runs it under `bash -eo pipefail`: it passes a canned log with both PASS lines and fails a log with one ("the log has no PASS line for TestProbeSSHDFacts").

The ruleset and CONTRIBUTING.md now name `e2e-probe (9.5p1)` and `e2e-probe (10.5p1)`, and CONTRIBUTING says 28 checks. scripts/apply-rulesets.sh is unchanged and was not run.

How TestProbeSSHDFacts decides that sshd stopped answering a source: the connection is closed or reset before sshd's SSH banner (an `SSH-` version line). A timeout is inconclusive and fails the subtest. OpenSSH 10.5p1 writes `Not allowed at this time` to a penalised source and resets it. That is a drop, and the subtest logs the text.

Local readings (WSL, the namespace sandbox):
- 9.5p1: no source was dropped within 12 refused queries or 12 PK_OK aborts. P7 not exercised; 127.0.0.1 accepted.
- 10.5p1: a source was dropped after 5 refused queries, and after 5 PK_OK-then-abort connections. P7 exercised: 127.0.0.2 stayed dropped, and 127.0.0.1 was accepted. 12 sshd log lines mention a penalty.

The CI RED run, on the throwaway branch p03/10-e2e-red: origin/main plus only test/e2e/probe_certs_test.go and .github/workflows/e2e.yml. `git diff --name-only origin/main...p03/10-e2e-red` listed exactly those two files. The run was dispatched by keyroster-bot, and the branch was deleted afterwards (`git ls-remote --exit-code` exits 2):

e2e RED run: 42376345720

In it:
- Both probe lanes failed to build, on `probe_certs_test.go:105:14: undefined: wire.ProbeIssueRequest`.
- Both main lanes passed (9.5p1 790.328 s, 10.5p1 790.698 s) with no `=== RUN   TestProbe` line. This is the first proof that the build tags keep the probe tests out of the main lanes.

The CI GREEN run, on p03/10-probe-certs at T4 (5bc5c42):

e2e GREEN run: 42376840753

| Lane | go test elapsed | Limit |
|---|---|---|
| e2e-probe (9.5p1) | 29.843 s | 420 s cap |
| e2e-probe (10.5p1) | 37.503 s | 420 s cap |
| e2e (9.5p1) | 799.709 s | base 736.217 s, stop 900 s |
| e2e (10.5p1) | 792.490 s | base 759.164 s, stop 900 s |

- No `=== RUN   TestProbe` line appears in either main lane.
- Every PROBE_PASS name passed, and no probe lane has a `--- FAIL:` line.
- The main lanes are 33 to 63 s above the base. Their code is unchanged, and the RED run on unchanged main code read about 790 s, so this is the main lanes' own run-to-run spread (745 to 801 s in 03-09b). It does not come from this plan's tests, which the lanes do not run.

The facts, read from the CI GREEN probe lanes. They match the local runs exactly:

A9 (9.5p1): refused queries until blocked: none within 12; PK_OK then abort until blocked: none within 12; penalty log lines: 0 (no PerSourcePenalties)
A9 (10.5p1): refused queries until blocked: 5; PK_OK then abort until blocked: 5; penalty log lines: 12; a dropped source receives "Not allowed at this time" and a reset, no SSH banner
P7 (9.5p1): not exercised
P7 (10.5p1): exercised

What this means for 03-10b, which is planned on these numbers:
- On 10.5p1, a source that fails 5 times in a row is dropped, whether the failures are refused queries or PK_OK-then-abort probes. In the local run sshd logged "activating ipv4 penalty of 19.9 seconds". sshd answered five failing connections in a row from one source and dropped the sixth, so one dedicated probe source gets at most five back-to-back probe connections before it is penalised.
- The planner default (at most six negative probes an hour, pairs at least 60 s apart) stays well below that rate, provided penalties decay between pairs. That decay was not measured here: UNVERIFIED.
- The listener's own source 127.0.0.1 is unaffected by a penalty on 127.0.0.2 (P7). The harness's readiness dial gives 127.0.0.1 a 1 s penalty for a connection without authentication, which did not block the later query.

## Mutants

How each mutant ran: applied to the committed task code, then the one named subtest alone (`-run '^Test$/^sub$'`, `-timeout 5m`). It counts as killed only by that subtest's `--- FAIL:` line; a build failure or a timeout would not count. Afterwards the file was restored with `git checkout --`, and `git diff --quiet -- <file>` proved it clean.

Task 1:
mutant killed: revokedEntriesOf without KindProbeIssue (TestProbeIssue/issues_negative_and_positive_for_listed_key)
mutant killed: ProbeIssueBody.RevokedEntries returning nothing (TestProbeIssue/negative_row_matches_entry)
mutant killed: the revocation row's valid_before in seconds (TestProbeIssue/negative_row_matches_entry)
mutant killed: the revocation row's CA key the user CA's (TestProbeIssue/negative_row_matches_entry)
mutant killed: the signer without the check that the entry lists the host key (TestProbeIssue/host_key_not_listed)
mutant killed: the signer's probe key rule removed, so the probe key may equal the host key (TestProbeIssue/probe_key_is_host_key)
mutant killed: the probe-pop item not verified (TestProbeIssue/probe_pop_invalid)
mutant killed: the host evidence verified under the host-issue namespace (TestProbeIssue/host_pop_host_issue_namespace)
mutant killed: force-command left out of the options (TestProbeIssue/cert_exact_restrictions_under_permissive_machine_profile)
mutant killed: the leaf built in internal/signer/probeissue.go with Negative always false (TestProbeIssue/leaf_fields)
mutant killed: the rebuild switch not adding b.RevokedEntries() to revoked (TestProbeLog/restart_after_negative_ok)
mutant killed: the rebuild switch not counting the probe leaf in issued (TestProbeLog/issued_counts_probe_leaf)
mutant killed: ProbeIssueBody.RevokedEntries returning the entry for a positive body too (TestProbeIssueBody/revoked_entries_negative_only)
mutant killed: audit not adding the negative entry (TestVerifyProbeIssue/negative_listed_by_next_publish)
mutant killed: audit without the entry-lists-the-key check (TestVerifyProbeIssue/key_not_listed_fails)
mutant killed: audit without verifying the probe-pop (TestVerifyProbeIssue/probe_pop_by_other_key_fails)
mutant killed: audit without the installation check (TestVerifyProbeIssue/installation_mismatch_fails)
mutant killed: audit without the machine-CA check (TestVerifyProbeIssue/wrong_ca_fails)
mutant killed: audit verifying the host-pop under the host-issue namespace (TestVerifyProbeIssue/host_pop_wrong_namespace_fails)
mutant killed: audit without the probe-key rule (TestVerifyProbeIssue/probe_key_is_host_key_fails)
mutant killed: audit comparing option names only with no value equality (TestVerifyProbeIssue/wrong_source_address_fails)

Task 2:
mutant killed: no coalescing (TestProbeIssue/coalesced_publishes_at_most_one_per_minute)
mutant killed: the 2 h margin removed (TestProbeIssue/predecessor_expiring_publishes_now)
mutant killed: the published flag ignored (TestProbeIssue/unpublished_predecessor_publishes_now)
mutant killed: published true for a krl_publish leaf at the same index or below (TestProbeIndex/published_flag_follows_krl_publish_leaf)
mutant killed: republishIfDue ignoring the prompt flag (TestProbeIssue/flag_published_at_next_tick)
mutant killed: the flag honoured without an unpublished negative (TestProbeIssue/flag_moot_after_other_publish). Held at d60663a only: since the F4 fix this mutant is equivalent (see "Pre-merge review").
mutant killed: the window taken from the previous certificate's CapSeconds (TestProbeIssue/cert_recent_window_from_new_lifetime)
mutant killed: an exact retry accepted for other signing bytes (TestProbeIssue/retry_with_other_bytes_is_duplicate)
mutant killed: an exact retry that writes a new leaf (TestProbeIssue/exact_retry_redelivers_no_leaf)
mutant killed: audit without the recent rule (TestVerifyProbeIssue/recent_rederived)
mutant killed: audit without the cross-kind request-ID check in the host_issue case (TestVerifyProbeIssue/request_id_replayed_across_kinds)
mutant killed: a probe leaf setting revs.due (TestVerifyProbeIssue/no_adjacency_needed)
mutant killed: the export line without the negative field (TestExportProbeIssue/export_fields_bound)
mutant killed: the flag branch of republishIfDue without the age gate (TestProbeIssue/coalesced_publishes_at_most_one_per_minute)
mutant killed: the ride branch without checkKRLFitsLocked (TestProbeIssue/krl_too_large_refuses_issuance/ride)
mutant killed: the coalesced branch without checkKRLFitsLocked (TestProbeIssue/krl_too_large_refuses_issuance/coalesced)
mutant killed: the shared window changed from L/3 to L/2 in certprofile.ProbeCertRecent (TestProbeCertRecent/boundary)

The L/2 mutant also fails TestProbeIssue/cert_recent_window_from_new_lifetime and TestVerifyProbeIssue/recent_cap_change_both_ways, so both callers use the one function.

Task 3:
mutant killed: the reserved check removed from Build (TestBuildReserved/refused_without_flag)
mutant killed: CheckIssued ignoring the flag (TestBuildReserved/check_issued_refuses)
mutant killed: ProbeProfile without the flag (TestProbeIssue/issues_negative_and_positive_for_listed_key)
mutant killed: the install check for the principal prefix removed (TestInstallDirectoryReserved/principal_prefix_refused)
mutant killed: the account check removed (TestInstallDirectoryReserved/account_name_refused)
mutant killed: budgetSigner.ProbeIssue on the interactive share (TestSignerBudget/total_bounded/ProbeIssue)
mutant killed: the handler without hostKeyOfAgent (TestAgentProbeCert/key_not_on_agents_entry_refused)
mutant killed: the handler without agentSlot (TestAgentInFlight/probe_cert_route_takes_agent_slot)
mutant killed: a second ReservedPrincipals: true literal in internal/signer/probeissue.go (TestReservedPrincipalsGuard/flag_set_only_in_probe_profile)

The first form of the account mutant (`&& a.Account == ""`) failed to build under vet's bools check. A build failure is not a kill, so the mutant was rewritten as `&& len(g.Accounts) == 0`. That form is behavioural and was killed.

Task 4 (run on 10.5p1, the build with PerSourcePenalties, inside the namespace sandbox):
mutant killed: the loop that drives 127.0.0.2 sends no refused queries (TestProbeSSHDFacts/listener_source_unaffected)
mutant killed: the final PK_OK query sent from 127.0.0.2 instead of 127.0.0.1 (TestProbeSSHDFacts/listener_source_unaffected)

Further Task 1 observations, not counted above:
- The user-CA-key row mutant also fails TestProbeIssue/issues_negative_and_positive_for_listed_key, because the publish refuses revocations_not_logged.
- The names-only mutant also fails TestVerifyProbeIssue/wrong_force_command_fails.
- The names-only mutant does not fail no_source_address_fails. That is correct behaviour: a missing option changes the name set, so a names-only comparison still refuses it. The plan text expected this subtest to fail as well.
- The plan's signer mutant "the probe key allowed to equal the host key" (only the equality test removed) survives probe_key_is_host_key. It is an equivalent mutant: the entry must list the host key before this rule runs, so a probe key equal to the host key is always a key the directory lists, and the directory part of the same rule refuses it with the same detail. The killable form above removes the whole rule. A deviation.

## Deviations

The plan's deviations, copied:
Q1 state-loss deviation (P4): accepted by the owner

- Q1, state loss (P4). After an agent-side state loss, the first new negative is refused `probe_cert_recent` for up to min(1 h, L/3) and then rides the hourly publish. Only a signer-side loss, a first enrolment and a machine cap under about 6 h publish at once.
- Plan totals: the totals in ROADMAP and STATE follow the plan files on disk (31 when 03-10b's plan file lands, 32 with 03-10c's), not the design note's "23/32".
- Scope the owner moved (P1, P2, P3): the matrix facts (`TestDistroProbeFacts`) and the `audit verify` CLI line are 03-10c's. The CLI edit path is unchanged, and the signer's install-time refusal is the single `keyroster-probe:` rule.
- Placement: the reservation sits at cert.Build and cert.CheckIssued, the probe CI job lives in e2e.yml, and the evidence order is fixed (host-pop, then probe-pop).
- Coalescing: the flag branch of republishIfDue is gated on the age of the last probe-caused publish.

Executor deviations, as they happened:
- **Local e2e runs inside a namespace sandbox.** This WSL no longer resolves `keyroster.localhost`, which the admin CLI dials, so the plan's local e2e commands fail before any probe step. The same commands ran instead in an unprivileged user and mount namespace with a private /etc/hosts that adds `127.0.0.1 keyroster.localhost`, nested in a user namespace that maps back to the caller's uid and gid. Nothing on the machine changes. CI runs the same tests without any wrapper.
- **The e2e lint under the probe tags is not issue-free, but none of the issues is new.** `golangci-lint run --build-tags e2e,e2eprobe ./test/e2e/` reports 16 issues, all in existing e2e files: agent_apply, agent_enroll, bootstrap, harness, restore and sshd_reread. origin/main reports the same 16 under `--build-tags e2e`. probe_certs_test.go has none. They are out of scope and not fixed here. The three GOOS lints of ./... and gofmt are clean.
- **Two existing tlog tests were fixed minimally.** TestRecoveryBody/kinds_are_a_set and TestHostForgetBody/kinds_are_a_set listed kind 12 as unknown. Kind 12 is valid now, so their loops start at 13 (as the plan allows).
- **The audit stub's pop.hosts case uses its own fixture.** A successor policy may not clear pop.hosts, so pop_hosts_off_fails runs on a fixture whose genesis policy never set it (see Task 1).
- **One planned signer mutant is equivalent.** "The probe key allowed to equal the host key" cannot be killed: the entry must list the host key before the probe key rule runs, so a probe key equal to the host key is always a directory-listed key, and the same rule refuses it with the same detail. The counted mutant removes the whole signer probe key rule. The plan's form was run as well and survived, as expected.
- **The plan's note on the names-only audit mutant is inaccurate.** It said no_source_address_fails would also fail. It does not, and should not: a missing option changes the name set, so a names-only comparison still refuses it. wrong_source_address_fails is the named killer and fails.
- **TestIssueReserved/host_issue_refused_for_prefix_principal cannot go through HostIssue.** A host entry cannot name `keyroster-probe:`: host principals must be DNS names or IP addresses (directory.CheckHostPrincipal), and the colon is neither. The subtest therefore proves the two halves separately. First, directory.CheckHostPrincipal refuses such a principal. Second, cert.Build refuses it under the signer's host profile in force, and buildRefusal maps that to bad_principal.
- **The host and probe handlers share one refusal mapping.** It is extracted as agentSignerFailed, the smaller diff the plan allows. TestAgentHostCert stays green.
- **The Task 2 signer cases are subtests of TestProbeIssue,** as the plan names them (`TestProbeIssue/<case>`). They are reached through a helper, probeIssueBoundsCases, in the same file, the way hostIssueCases is.

## UNVERIFIED

These are taken from the plan's Edge Coverage, plus what this run did not exercise:
- `POST /api/v1/agent/probecert` against the real signer. It is tested against the fake signer only; the first end-to-end run is 03-10b's TestProbeSelfTestEndToEnd.
- R1: the cost of reading and encoding the whole revocation table in every negative issuance's own transaction, and in every publish. Fine at homelab scale; not measured as a performance claim.
- R7: zeroing of the ephemeral probe key in the agent's memory (03-10b's code).
- R9: a restore that loses a negative probe leaf, end to end. The audit lookup and the recovery collection are unit-tested only (`recovery_lookup_sees_probe_certificate`, `recovery_collects_probe_certificate`).
- R9a (owner decision D-R1, pre-merge review): after a signer restore, `keyroster revoke recover` carries a lost riding negative probe certificate (one that no published KRL copy contained) as `keep`, not revoked. cmd/keyroster/recover.go revokes only user-role certificates and the serials named with `--revoke-lost`, and this plan carries probe certificates like machine certificates (`recovery_collects_probe_certificate`). The recovered KRL then does not list that negative. The exposure is bounded: the certificate is restricted to force-command /bin/false, a loopback source-address and the probe account. No code change in 03-10; 03-10c owns the fix (`.planning/todos/pending/2026-11-07-recovery-revokes-lost-negative-probe-certificates.md`). The restore is UNVERIFIED end to end, as R9 says.
- R10: that sshd checks revocation and the source-address option in the unsigned query phase. Shown by TestProbeCertsAgainstSSHD only on the two builds used here, locally and in CI.
- R14: the load of up to 60 probe-caused KRL versions an hour under machine caps below about 6 h.
- R16 (P4): the wait after an agent-side state loss is not exercised by any test.
- sshd's handling of a RevokedKeys file without the KRL magic (garbage and empty). Recorded as a fact on both builds, never asserted.
- P7 on 9.5p1. That build has no PerSourcePenalties, so it is recorded as not exercised. P7 is claimed for 10.5p1 only.
- The KRL size edge on a real fleet's row mix, and the seeding time under -race. The test uses seeded key_id rows to the byte.
- The corrupt-KRL, serial-encoding and source-address behaviour on OpenSSH builds other than 9.5p1 and 10.5p1.
- Windows: no Windows code or CI changes here.
- A restart loses the prompt flag. The waiting row then rides the hourly publish; not tested across a restart.
- The `hasUnpublishedNegative` term of republishIfDue's flag gate, since the F4 fix (see "Pre-merge review"). No test reaches a set flag without an unpublished negative.

## Pre-merge review

Review run wf_7b91fc5b-c8c: four Opus lenses and Codex on PR #90, head d60663a on base 70ac72b, with two Sonnet skeptics per finding and a critic. Nothing high or critical was found. Fix round 1 is commits f5809f7 to ff06edb plus this record, on top of d60663a (no rewrite).

Each RED below was taken locally: the mutant was applied to the committed or staged code, the named subtest alone was run (`-count=1 -timeout 5m`), and the file was restored with `git checkout --` and proved clean with `git diff --quiet`. A kill counts only by that subtest's `--- FAIL:` line, never a build failure.

| Finding | Severity | Outcome | Commit |
|---|---|---|---|
| F1: the certificate-key check was unreachable in tests | medium (2/2) | fixed (test) | f5809f7 |
| F2: the key ID pol= check was unreachable in tests | low (2/2) | fixed (test) | f5809f7 |
| F3: pos1 == neg1+1000 failed the serial_list case on correct code | low (2/2) | fixed (robustness) | e1be787, ff06edb |
| F4: a stale probe prompt flag caused an early publish | low (Codex, 2/2) | fixed | 9e249e3 |
| F5: the probe certificate's ValidAfter window was untested in audit | low (split 1/2) | fixed (test) | f5809f7 |
| F6: the probe key rule's machine branch was untested in audit | low (split 1/2) | fixed (test) | f5809f7 |
| D-R1: recovery keeps a lost riding negative probe certificate | owner decision | documented, todo for 03-10c | 2853ce7 |
| A short machine cap disables the probe throttle (Codex medium, signer-issue low) | refuted | no action | none |
| The ride rule looks only at the latest negative | refuted | no action | none |
| Audit refuses older logs that carry keyroster-probe: | refuted | no action | none |
| The relay test does not check the evidence blobs | refuted | no action | none |
| The kr3 key ID requirement is unexercised | refuted | no action | none |

**F1 (medium): the check that the certificate's key is the request's probe key could not be reached.** The fixture built the certificate subject from `p.req.ProbeKey`, and the existing probe-key cases changed the request key, the probe-pop key and the subject together.
- Test: `probeIssue.certKey` overrides the certificate's key only. `TestVerifyProbeIssue/cert_key_not_probe_key_fails` sets it to a fresh key, with the request, the evidence and everything else genuine.
- mutant killed: `if false && !bytes.Equal(c.Key.Marshal(), probeKey.Marshal())` at internal/audit/probeissue.go:126 (TestVerifyProbeIssue/cert_key_not_probe_key_fails: verify returned nil)

**F2 (low): the check that the key ID's pol= is the policy in force could not be reached.** The cases changed the key ID and the body's policy version together. checkIssue does not compare them, so the check is reachable.
- Test: `TestVerifyProbeIssue/key_id_policy_fails` changes only `keyID.Policy`.
- mutant killed: `if false && kid.Policy != a.policy.Version` at internal/audit/probeissue.go:305 (TestVerifyProbeIssue/key_id_policy_fails: verify returned nil)

**F3 (low): the serial_list case could fail on correct code.** That KRL revoked neg1-1000, neg1 and neg1+1000, while the guard only kept pos1 out of neg1 ± 1. Serials are max(last+1, now µs), so a positive issued a millisecond after the negative is neg1+1000.
- Fix: pos1 is always above neg1, so the list's upper neighbour is now pos1+1000. The range moves to neg1-2..neg1 when pos1 is neg1+1. A guard fails the test if any constructed serial, or any serial inside the range, is pos1, and the range's expected shape comes from the constructed serials.
- Each case still isolates its encoding. The list KRL holds neg1 between two serials at least 1000 away, so it encodes as a serial list with neg1 alone in its entry. The range KRL holds three consecutive serials with neg1 among them, so it encodes as one range. pos1 is outside both.
- An unintended line in e1be787: that commit also carried a change this round did not write. In TestProbeSSHDFacts, `finalSrc` went from 127.0.0.1 to 127.0.0.2, which is the Task 4 mutant "the final PK_OK query sent from 127.0.0.2 instead of 127.0.0.1". It was in the working copy when the F3 edit was committed by path; its origin is unknown. e2e-probe (10.5p1) at 2853ce7 failed on it in `TestProbeSSHDFacts/listener_source_unaffected` (run 42386627397, job 128445299238), as the mutant should. ff06edb restores 127.0.0.1. `git diff d60663a ff06edb -- test/e2e/probe_certs_test.go` now holds only the F3 change, and the whole range diff of internal/ and test/ was read hunk by hunk and holds only this round's changes.
- A robustness fix with no RED mutant, as instructed. It is verified by reasoning and by both e2e-probe CI lanes (below). Locally the package was vetted under `-tags "e2e e2eprobe"` and gofmt is clean. The e2e test itself was not run locally.

**F4 (low, Codex): a stale probe prompt flag caused an early publish.** The flag was set by a coalesced negative and cleared only when republishIfDue published because of it. An admin revoke, a recovery, a probe issuance that published at once, and the hourly republish all carry every waiting negative row too, because each publish encodes the whole revocation table, but they left the flag set. A later riding negative then made the next tick publish early, against the ride rule (Q1).
- Fix: every committed publish installs its KRL through `publishedLocked`, which stores it and clears the flag under s.mu. That covers revoke.go, recovery.go, probeissue.go and republishIfDue. `lastProbePublish` is still set only by probe-caused publishes, so the one-a-minute gap between them and the ride rule are unchanged.
- Test: `TestProbeIssue/flag_cleared_by_carrying_publish`, with variants `admin_revoke`, `probe_issuance`, `recovery` and `hourly`. web1's negative publishes at t0. web3's first negative publishes at t0+3601 s. h01's negative at t0+3611 s coalesces and sets the flag. The carrying publish comes at t0+3671 s, or at t0+7202 s for the hourly variant. After it the flag must be clear. web1's renewal 10 s later must ride, and the tick 70 s after the carrying publish must not publish. `flag_moot_after_other_publish`, `coalesced_publishes_at_most_one_per_minute` and the other flag and ride subtests stay green.
- RED before the fix: `admin_revoke` and `probe_issuance` failed with `probeissue_test.go:1123: the admin_revoke publish carried the waiting negative but left the prompt flag set` and `probeissue_test.go:1132: a stale prompt flag published the riding negative before the hourly republish`, and the same two lines for probe_issuance.
- mutant killed: revoke.go's `s.publishedLocked(published)` back to `s.krl.Store(published)` (TestProbeIssue/flag_cleared_by_carrying_publish/admin_revoke)
- mutant killed: probeissue.go's `s.publishedLocked(published)` back to `s.krl.Store(published)` (TestProbeIssue/flag_cleared_by_carrying_publish/probe_issuance)
- mutant killed: recovery.go's `s.publishedLocked(published)` back to `s.krl.Store(published)` (TestProbeIssue/flag_cleared_by_carrying_publish/recovery)
- mutant killed: republishIfDue back to the old rule, the flag cleared only by a prompted publish (TestProbeIssue/flag_cleared_by_carrying_publish/hourly)
- The hourly variant first published at t0+7201 s. The test helpers advance the clock by milliseconds, so the last publish was then just under an hour old, the tick took the prompted path, and the variant did not tell the old code from the fix. Moved to t0+7202 s, it does.
- Consequence: the mutant "the flag honoured without an unpublished negative" (Task 2, killed by flag_moot_after_other_publish at d60663a) is now equivalent. A flag is set only together with an unpublished negative, and every publish clears it, so no test can reach a set flag without one. The `hasUnpublishedNegative` term stays in the gate as defence in depth and is listed under UNVERIFIED. Rerun at ff06edb (with the four-variant test), the mutant survives `-run '^(TestProbeIssue|TestProbeLog|TestProbeIndex)$'` in internal/signer.
- Deviation from the plan: plan lines 161 and 434 said the other publishers need no clearing, because any publish clears the flag's cause. That missed a later riding negative, which brings a cause back. The other publishers now clear the flag.

**F5 (low, split 1/2): the probe certificate's ValidAfter window was untested in audit.** The `cert.CheckIssued(c, profile, from, to)` call in checkProbeCert could be removed with every test green.
- Test: `probeIssue.issued` overrides cert.Build's Now. `TestVerifyProbeIssue/valid_after_outside_issuance_fails` issues 60 s after the leaf time: inside the 300 s CreatedAt skew, outside the range from the serial to the leaf time.
- mutant killed: `if err := cert.CheckIssued(c, profile, from, to); false && err != nil` at internal/audit/probeissue.go:315 (TestVerifyProbeIssue/valid_after_outside_issuance_fails: verify returned nil)

**F6 (low, split 1/2): the probe key rule's machine branch was untested in audit.** No audit test built a directory with a machine entry.
- Test: `hostFixture.machines` puts machines into the directory the fixture publishes (nil, the default, keeps none). `TestVerifyProbeIssue/probe_key_machine_key_fails` lists the probe key on machine `ci` (role dev, 600 s). The case expects `machine "ci" (probe_key_unusable)`, so the host branch cannot satisfy it.
- mutant killed: `if false && m.Key == k` at internal/audit/probeissue.go:280 (TestVerifyProbeIssue/probe_key_machine_key_fails: verify returned nil)

**D-R1 (owner decision, Daniel, 2026-11-07): recovery keeps a lost riding negative probe certificate.** After a signer restore, `keyroster revoke recover` carries such a certificate as `keep`, because cmd/keyroster/recover.go:291 revokes only user-role certificates and named serials. No code change now. It is recorded as R9a under UNVERIFIED, next to R9. The todo `.planning/todos/pending/2026-11-07-recovery-revokes-lost-negative-probe-certificates.md`, owned by 03-10c, asks recovery to revoke lost negative probe certificates automatically, with audit parity through krl.CheckCarriedLost and tests. The plan's files_modified is unchanged: no repo gate compares it with the diff.

**No action (refuted by the skeptics):** a short machine cap disabling the probe throttle (Codex medium and signer-issue low, both refuted); the ride rule looking only at the latest negative; audit refusing older logs that carry keyroster-probe:; the relay test not checking the evidence blobs; the kr3 key ID requirement being unexercised.

**Local gates at 9e249e3:** gofmt clean for internal/audit, internal/signer and test/e2e. `go vet` passed for internal/audit and internal/signer, and `go vet -tags "e2e e2eprobe" ./test/e2e/` passed (and again at ff06edb, with gofmt). `go test -race -count=1` passed for internal/audit (82 s) and internal/signer (389 s), through scripts/linux.sh.

**CI at ff06edb (PR #90 head before this record): every check passed.** The runs were CI 42387236049, E2E 42387236110, E2E distro 42387236045, E2E PKCS#11 42387236013, E2E TPM 42387236024, PIV 42387236040, Systemd 42387236017, CodeQL 42387236050, PR title 42387236011 and Workflow lint 42387236006. The F3 lanes: e2e-probe (10.5p1), job 128447095653, and e2e-probe (9.5p1), job 128447095450. Both ran TestProbeCertsAgainstSSHD and TestProbeSSHDFacts with no `--- FAIL` line. The earlier head 2853ce7 failed e2e-probe (10.5p1) on the stray line described under F3.

