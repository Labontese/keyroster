---
phase: 03-linux-agent-and-revocation
plan: 09
subsystem: hosts
tags: [signer, server, agent, hostcert, audit, e2e, agent-06]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08i (the status snapshot, waves); 03-05 (the drop-in and apply engine); 03-07 (enrollment, host keys); 03-08 (heartbeat and host status)"
provides:
  - "wire: HostIssueRequest (keyroster/host-issue-request/v1, frame 0x0A, host-pop/v1 evidence); cert: kr3 key IDs, HostCertRecent; tlog: KindHostIssue 11"
  - "signer: HostIssue with the per-host-key index, the lifetime chosen by the signer, host_cert_recent, re-delivery, cert_revoked holds, hostLimiter"
  - "server: POST /api/v1/agent/hostcert inside the agent share of the budget"
  - "audit: verifyHostIssue rules, host_issue export"
  - "agent: the HostCerts step, DropIn(l, spec)/wantDropIn/writeDropInSpec, the record and attempts files, the served-certificate self-test, heartbeat host_certs, host_keys_skipped and host_cert_detail; fetcher postHostCerts"
  - "docs: host-setup.md Host certificates; revoke.md names 03-09b"
  - "planning: 03-09b at wave 22, 03-10 to 03-16 one wave later, 03-10 depends on 03-09b"
affects: [03-09b, 03-10, 03-16]

requirements-completed: [AGENT-06]

actuals:
  tokens: 207000
  tasks: 5
  commits: 17
plan_head_before: 5ec5ff9f581f95cb5dc464bfb1b7e028cbc2e54d
plan_head_after: 3f9267559855369d900b30cad2d4c5c0b3d0df19

tech-stack:
  added: []
---

# Phase 3 Plan 09: Host certificates by proof of possession (part a) Summary

Hosts obtain, renew and serve OpenSSH host certificates by proof of possession: a kr3 host issue request signed by the host key, issued by the signer under per-key bounds with re-delivery, relayed by the server for approved agents, installed by the agent through one persisted drop-in spec with a served-certificate self-test, crash-safe recovery and heartbeat reporting.

## Owner decision record

T-03-100 answer: redeem-directory
"Katalogen i inloggningssvaret (Rek.)"
format registry: present

## Bases (quiet, on origin/main 5ec5ff9)

The test-time base was re-measured twice, each time because the WSL boot ID had changed (idle shutdowns, no reboot), in a detached worktree at origin/main outside the repository; each re-measure replaced the line in place. Readings, apply alone / apply under ./... / signer under ./...: Task 1 337.866 / 383.890 / 386.414 s; Task 4 302.221 / 338.238 / 359.890 s (at=1793942115, the base of Task 4's gates); Task 5 377.800 / 513.511 / 439.160 s (the line below, the base of Task 5's gates). The Task 5 base read high, the machine evidently not quiet then, so Task 5's ./... deltas come out negative and bound little; Task 4's deltas against the quieter base are the informative ones.

test-time base: apply-alone=377.800 apply-all=513.511 signer-all=439.160 at=1793946037 boot=c17c3e6f-e610-49f2-977d-ef0d96923418
e2e base: run 42108769768 9.5p1=558.270 10.5p1=555.027

## Task 2 (tracer)

RED, before the production code:
- `TestHostIssue/issues_kr3_for_listed_key`, `TestAgentHostCert/relays_for_approved_host` and `TestHostCertStep/install_serves_and_survives_next_apply`: compile failures on origin/main's code (`go vet`: `undefined: wire.HostIssueRequest`, `undefined: wire.HostPoPNamespace`, `undefined: wire.EvidenceHostPoP` in internal/signer and internal/server; no package `internal/agent/hostcert` in internal/agent/apply).
- e2e RED from CI: run 42153396127 on the throwaway branch `p03/09-e2e-red` (only test/e2e/hostcert_test.go, bootstrap_test.go and agent_enroll_test.go changed; `go vet -tags e2e ./test/e2e/` passed on it). Both lanes: `--- FAIL: TestHostCertIssueAndServe` with `no HostCertificate line within 120 s`, and `--- FAIL: TestHostCertRenewAndRestart`, and no other `--- FAIL:` (4 FAIL lines in the log, two per lane). The branch was deleted; `git ls-remote --exit-code origin refs/heads/p03/09-e2e-red` exits 2.
- The structural DropIn gate's awk prints the 12 compare sites on origin/main's files (12 one-argument `DropIn(l)`/`DropIn(e.l)` calls), so the gate bites.

GREEN:
- Verify 1 (build, vet, e2e vet, the tracer tests): pass; every required `--- PASS:` line present.
- Verify 2 (the package set): pass on the rerun. The first run had two real failures in internal/tlog (`TestDecodeLeafStrict` and `TestHostIssueKind` built a kind-11 leaf through `rawKindLeaf`, which now is a valid kind; fixed to kind 12 and `EncodeLeaf`) and one timing assertion in `TestFetch/more_repolls_immediately` (2.76 s against 900 ms while the signer and apply suites ran in parallel); it passed alone and on the rerun.
- Verify 3 (the structural DropIn gate on Task 2's code): exit 0.
- Verify 4 (e2e on the branch): run 42157932753 failed three subtests on real OpenSSH details (ssh-keyscan prints a certificate without the host field; OpenSSH 10.5p1 retries a plain known key after an untrusted certificate only when the plain algorithm is in HostKeyAlgorithms); after the test fix, run 42159497405 passed `served_both_algorithms`, `no_prompt_with_ca_line`, `other_name_refused`, `existing_known_hosts_still_accepted` and `next_apply_keeps_line` on both lanes, with only `heartbeat_shows_host_certs` (Task 4) and `TestHostCertRenewAndRestart` (its `host certificates: N` line is Task 3's) failing. In that run the renewal, the 90 s lifetime and the signer restart already worked.
- The test file mechanics: the plan counted 23 `DropIn(h.l)` calls in adopt_test.go, dropin_test.go and preflight_test.go; 5 of them are `trialDropIn(h.l)`, which stays spec-less, so 18 calls changed.

T2: 8dac2da

## Task 3 (bounds, index, re-delivery, audit)

RED, against Task 2's code:
- internal/signer and internal/cert: compile failures (`undefined: hostIndex`, `e.s.loaded.hosts undefined`; `undefined: HostPrev`).
- internal/wire: `--- FAIL: TestHostIssueRequestSigningVector` (no vector yet); `TestHostIssueRequest` passed at once, including `every_field_bound` and the tampering cases, because Task 2's SigningBytes already binds every field; the SigningBytes mutant below shows the test bites.
- internal/tlog: `--- FAIL: TestHostIssueLeafVector` (no vector yet); `TestHostIssueBody` passed at once (Task 2's strict decoder).
- internal/audit: `--- FAIL:` for `revoked_key_fails`, `recent_fails`, `second_exception_same_version_fails`, `rename_entry_recent_fails`, `cert_revoked_hold_fails`, `restored_lost_revoked_cert_hold_fails` (both variants), `cap_seconds_not_policy_fails`, `replayed_request_id_fails`, `kr3_in_issue_entry_fails` and `recent_judged_by_cert_time_not_leaf_time` (rules 7, 10 and 12 and the V3 refusal); the Task 2 rules passed at once.
- internal/server and cmd/keyroster: `TestAgentHostCert`'s new cases, `TestSignerBudget/total_bounded/HostIssue` and `TestAgentInFlight`'s host cases passed at once (Task 2 built the relay and the budget); `TestVerifyOutput` was a compile failure (`undefined: printVerifyOK`).

GREEN: verify 1 (signer, every listed `--- PASS:`), verify 2 (cert, wire, tlog, audit, server, CLI, every listed `--- PASS:`), verify 3 (the three fuzz targets, 20 s each) and verify 4 (the packages) pass. internal/signer `ok` 354.469 s in verify 4.

Acceptance: `case tlog.KindHostIssue` is in logstate.go, verify.go and export.go once each; only internal/signer/hostissue.go and internal/audit/hostissue.go call `HostCertRecent(`; the vector diff names only the two host_issue vectors; the s.db allowlist gate exits 0, and on a scratch copy of hostissue.go that calls `s.db.LiveIssuanceForSubjectTx` it prints that line, so it bites.

Mutants (each applied, run on its named subtest with `-timeout 5m`, killed by the named `--- FAIL:` line, restored and proven by `git diff --quiet`): no listed-key check; the window from prev's own lifetime; the signer honouring a nonzero valid_for; HostCertRecent using only capInForce; the index outside loggedInstalls (loadLog keeps the old one); the index rebuilt without CapSeconds; the rebuild ignoring a recovery's carried certificates; HostCertRecent ignoring the principals exception; the index keyed by name and key; a re-delivery that appends a leaf; a cert_revoked hold never released; no installation check; SigningBytes without InstallationID; logstate without the KindHostIssue case; the index not rebuilt; budgetSigner.HostIssue outside the agent share; hostIssueOrRefuse on s.limiter; host_cert_recent removed from classify; audit without the principals check, accepting V3 in issue entries, without hostIDs, CreatedAt against the leaf time, HostCertRecent with the leaf time, and without the CapSeconds equality; ParseKeyID allowing 70 bytes for any kr3 subject; signer_too_old mapped to 503. All 27 killed.
- Deviation: the mutant "the exception allowed twice per version" survives `TestHostIssue/principals_exception_once_per_version`, because after the exception the latest certificate carries the entry's principals, so the signer path cannot reach a second exception under one version; it is killed by `TestHostCertRecent/principals_change_bypasses_once_per_version`. The plan notes the same for the window mutant.
- Deviation: the first form of "a re-delivery that appends a leaf" (the exact retry issuing anew) survived, because issuance inside the window re-delivers anyway; the mutant that appends a leaf inside redeliverLocked is killed.

T3: a536cd1

## Task 4 (renewal, crash safety, edge states, reporting)

RED, against Task 3's code (51e0f2c, in a detached worktree with only the new test files copied in):
- internal/agent/apply: compile failure (`go vet`: `h.status().HostCertDetail undefined (type *heartbeat.Status has no field or method HostCertDetail)`), so every new TestHostCertStep case, TestHostCertDrift, TestHostCertPreflight, TestHostCertStatus and TestRunHostCertsWhenDue were RED by compilation.
- internal/agent/hostcert: TestDecide, TestVerifyAnswer, TestRecord, TestAttempts and TestJitter passed at once: the pure core (Decide's holds, renewal, back-off, the sticky list and VerifyAnswer's bounds) was built in Task 2 and Task 3. The Decide and VerifyAnswer mutants below show the tests bite.
- internal/agent/heartbeat and cmd/keyroster: compile failures (`s.HostCerts undefined (type Status has no field or method HostCerts)`; `certs.HostCerts undefined`), so TestValidateHostCerts and TestHostStatusHostCerts were RED.
- internal/agent/fetch and internal/agent/spool: TestPostHostCerts (all 16 subtests) and TestHostCertAnswerCap passed at once: postHostCerts, the answer cap and the heal are Task 2's.

GREEN:
- Verify 1 (the PASS list): exit 0, no `FAIL` and no `DATA RACE` in the log, and every name below has its `--- PASS:` line (run on d1c540a). The list, line by line:
  TestDecide/renew_before_and_after_renew_at
  TestDecide/missing_margin_is_min_60_or_sixth
  TestDecide/principals_differ_due
  TestDecide/revoked_installed_cert_due
  TestDecide/timing_from_cert_lifetime
  TestDecide/lazy_across_ca_rotation
  TestDecide/hold_directory_unauthorized
  TestDecide/hold_host_disabled
  TestDecide/hold_host_removed
  TestDecide/hold_host_keys_rotated
  TestDecide/hold_host_keys_disagree
  TestDecide/hold_no_generation
  TestDecide/hold_apply_unfinished
  TestDecide/hold_foreign_host_certificate
  TestDecide/hold_hostcert_in_match
  TestDecide/hold_host_cert_algorithm_disabled
  TestDecide/key_not_in_entry_removed
  TestDecide/key_not_served_removed
  TestDecide/backoff_schedule
  TestDecide/sticky_list_is_closed
  TestDecide/skew_refusal_is_transient
  TestDecide/sticky_released_by_bundle
  TestDecide/sticky_released_by_policy
  TestDecide/sticky_released_by_directory
  TestDecide/sticky_not_released_by_unrelated_change
  TestDecide/sticky_refusal_retries_after_24h
  TestDecide/sticky_at_in_future_released
  TestVerifyAnswer
  TestVerifyAnswer/redelivered_req_field_accepted
  TestVerifyAnswer/stale_agent_cap_not_stranded
  TestRecord
  TestRecord/in_progress_empty_candidate_allowed
  TestAttempts
  TestJitter
  TestHostCertStep/crash_after_attempts_before_outbox_abandons
  TestHostCertStep/crash_after_cert_file_adopts
  TestHostCertStep/crash_after_cert_file_adopts_first_install
  TestHostCertStep/crash_after_answer_consumed_installs_kept
  TestHostCertStep/crash_after_outbox_removed_installs_kept
  TestHostCertStep/crash_after_candidate_rolls_back_then_installs
  TestHostCertStep/crash_after_dropin_rolls_back
  TestHostCertStep/crash_after_reload_rolls_back
  TestHostCertStep/crash_after_selftest_rolls_back
  TestHostCertStep/crash_after_commit_gcs
  TestHostCertStep/crash_in_rollback_before_reload_reloads
  TestHostCertStep/crash_in_rollback_before_record_clears
  TestHostCertStep/crash_during_gc_converges
  TestHostCertStep/crash_during_removal_converges
  TestHostCertStep/apply_after_crash_renders_committed
  TestHostCertStep/recovery_without_bundle
  TestHostCertStep/record_legacy_migrates
  TestHostCertStep/record_missing_reported_and_adopted
  TestHostCertStep/missing_detected_after_apply_first
  TestHostCertStep/record_invalid_set_aside_and_adopted
  TestHostCertStep/krl_lands_with_bad_record
  TestHostCertStep/record_symlink_is_invalid_not_error
  TestHostCertStep/check_and_preflight_leave_record_untouched
  TestHostCertStep/simultaneous_applies
  TestHostCertStep/renewal_replaces_file
  TestHostCertStep/removal_drops_line
  TestHostCertStep/remove_last_key_commits_empty_set
  TestHostCertStep/two_keys_one_algorithm
  TestHostCertStep/two_algorithms_each_served
  TestHostCertStep/reload_lag_does_not_roll_back
  TestHostCertStep/repair_keeps_extensions
  TestHostCertStep/first_install_rollback_no_lines
  TestHostCertStep/generation_rollback_keeps_section
  TestHostCertStep/hostcert_rollback_keeps_trust_files
  TestHostCertStep/foreign_cert_before_include
  TestHostCertStep/foreign_cert_after_include
  TestHostCertStep/foreign_cert_blocks_adoption_and_answers
  TestHostCertStep/include_inside_match
  TestHostCertStep/include_moved_into_match_after_install_krl_lands
  TestHostCertStep/noop_repairs_section
  TestHostCertStep/unauthorized_noop_repairs_section
  TestHostCertStep/versions_commit_repairs_section
  TestHostCertStep/dry_run_noop_does_not_repair
  TestHostCertStep/served_cert_mismatch_rolls_back
  TestHostCertStep/algorithm_disabled_reported
  TestHostCertStep/answer_for_unknown_request_ignored
  TestHostCertStep/late_answer_within_330s_installed
  TestHostCertStep/redelivered_answer_installed
  TestHostCertStep/failed_install_keeps_cert_and_retries
  TestHostCertStep/kept_file_revoked_before_retry_not_installed
  TestHostCertStep/outbox_request_abandoned_after_330s
  TestHostCertStep/adopted_file_survives_hold
  TestHostCertStep/gc_keeps_files_when_record_missing_under_hold
  TestHostCertStep/gc_leaves_unrelated_files
  TestHostCertStep/gc_never_removes_file_named_by_dropin
  TestHostCertStep/cert_file_edited_is_drift
  TestHostCertStep/check_during_install_not_drift
  TestHostCertStep/rsa_skipped_reported
  TestHostCertStep/no_request_while_directory_unauthorized
  TestHostCertStep/no_request_when_host_keys_rotated
  TestHostCertStep/no_request_when_entry_disabled
  TestHostCertStep/no_install_while_marker_pending
  TestHostCertStep/no_install_before_first_lastgood
  TestHostCertStep/hold_no_generation_writes_nothing
  TestHostCertStep/no_install_while_marker_pending_sshd_t_fails
  TestHostCertStep/no_install_while_stuck_sshd_t_fails
  TestHostCertStep/no_install_while_recover_due_sshd_t_fails
  TestHostCertStep/request_valid_for_is_zero
  TestHostCertStep/algorithm_disabled_on_one_key_installs_other
  TestHostCertStep/backoff_on_one_key_installs_other
  TestHostCertStep/krl_lands_while_hostcert_fails
  TestDropInSpec/spec_lines_sorted_after_trio
  TestHostCertConfigGraph/sibling_match_isolated
  TestHostCertDrift/spec_line_missing_in_sshd_T
  TestHostCertDrift/foreign_hostcertificate_value_reported
  TestHostCertDrift/committed_file_missing_reported
  TestHostCertPreflight/foreign_host_certificate_is_a_note
  TestHostCertPreflight/invalid_record_is_a_note
  TestHostCertPreflight/installed_with_lines_no_drift
  TestHostCertPreflight/preflightApply_skipped_when_equal
  TestHostCertPreflight/preflight_no_state_dir_foreign_dropin
  TestHostCertStatus
  TestHostCertStatus/served_false_encoded
  TestHostCertStatus/status_written_after_install
  TestRunHostCertsWhenDue
  TestRunHostCertsWhenDue/answer_replaced_under_same_name
  TestValidateHostCerts
  TestHostCertAnswerCap
  TestPostHostCerts/posts_each_request_once
  TestPostHostCerts/writes_certificate_answer
  TestPostHostCerts/writes_refusal_answer
  TestPostHostCerts/rate_limited_writes_nothing
  TestPostHostCerts/old_server_404_backs_off
  TestPostHostCerts/no_answer_on_503
  TestPostHostCerts/rate_limited_without_retry_after_writes_nothing
  TestPostHostCerts/internal_error_500_writes_nothing
  TestPostHostCerts/bad_gateway_502_writes_nothing
  TestPostHostCerts/gateway_timeout_504_writes_nothing
  TestPostHostCerts/forbidden_without_detail_is_http_403
  TestPostHostCerts/one_at_a_time
  TestPostHostCerts/prunes_answers_without_outbox_request
  TestPostHostCerts/answer_mode_0644
  TestPostHostCerts/retry_after_lost_response_gets_certificate
  TestHostStatusHostCerts
- Verify 2 (the structural DropIn gate, Git Bash): exit 0.
- Verify 3 (apply alone, against the re-measured base 302.221 s): `ok` 318.228 s, +16.0 s (limit +90 s). Run on 6f2344a.
- Verify 4 (`./...`, against the re-measured bases): the first run failed `TestPaths/writes_through_allowed` (the new record set-aside unlinked and renamed without `paths.Allowed`; fixed in 6f2344a). The rerun on 6f2344a: exit 0; apply 377.722 s (+39.5 s over 338.238), signer 369.602 s (+9.7 s over 359.890). The first run's readings were apply 376.821 s and signer 371.893 s.
- Verify 5 (FuzzParseRecord 20 s, e2e vet, gofmt): exit 0.
- Verify 6 (e2e on the branch, at 6f2344a): run 42169803597 succeeded; `--- PASS: TestHostCertIssueAndServe` and `--- PASS: TestHostCertRenewAndRestart` on both lanes, no `--- FAIL:`. Elapsed: 9.5p1 725.776 s, 10.5p1 719.310 s, against the e2e base max 558.270 s: +167.5 s (limit +360 s and 900 s).
- d1c540a (after verify 3 and 4) changed only hostcert_test.go: verify 1 was run again on it and passed.

Acceptance: `git diff --name-only origin/main -- internal/agent/apply/swap.go internal/agent/apply/render.go` prints nothing (checked).

Mutants (each applied, run alone on its named subtest with `-timeout 5m`, killed by the named `--- FAIL:` line, restored by `git checkout` and proven by `git diff --quiet`): wantDropIn rendering the candidate (apply_after_crash_renders_committed); recovery committing the candidate (crash_after_selftest_rolls_back); Recover reloading only when the drop-in differs (crash_in_rollback_before_reload_reloads); restoreDropIn with DropIn(l, DropInSpec{}) (generation_rollback_keeps_section); the host-cert rollback also moving current to last-good (hostcert_rollback_keeps_trust_files); wantDropIn returning the mode error (krl_lands_with_bad_record); missing classified from the drop-in (missing_detected_after_apply_first); the install's effectiveness check reading the committed spec (renewal_replaces_file); hostCertSelfTest without the HostKeyAlgorithms restriction (two_algorithms_each_served); one handshake without retry (reload_lag_does_not_roll_back); Decide requesting while unauthorized (no_request_while_directory_unauthorized); answers read under a hold (foreign_cert_blocks_adoption_and_answers); answers accepted for any request ID (answer_for_unknown_request_ignored); the attempts file saved before the certificate file (crash_after_answer_consumed_installs_kept); a failed install that re-requests (failed_install_keeps_cert_and_retries); the no-op return ignoring the spec (noop_repairs_section); the versions commit ignoring it (versions_commit_repairs_section); writeDropIn with DropIn(e.l, DropInSpec{}) (repair_keeps_extensions); preflight's drop-in comparison with DropIn(l, DropInSpec{}) (TestHostCertPreflight/installed_with_lines_no_drift); a foreign HostCertificate as a refusal code (TestHostCertPreflight/foreign_host_certificate_is_a_note); GC removing unrelated files (gc_leaves_unrelated_files); HostCerts on every iteration (TestRunHostCertsWhenDue); time.Now in the abandonment check (outbox_request_abandoned_after_330s); no status write after an install (TestHostCertStatus/status_written_after_install); Recover running under no_generation (hold_no_generation_writes_nothing); GC ignoring the record code (gc_keeps_files_when_record_missing_under_hold); HostCerts' pre-repair ignoring the marker (no_install_while_marker_pending_sshd_t_fails); VerifyAnswer bounding V by 86400 (TestVerifyAnswer/stale_agent_cap_not_stranded); Decide treating every refusal detail as sticky (TestDecide/skew_refusal_is_transient). All 29 killed.
- Two survived the first round and were fixed in the tests, not by weakening the mutants: versions_commit_repairs_section published a new directory version, whose render differs (the principals file changes), so it never reached the versions-only commit; it now uses a policy rotation with the CA set unchanged and asserts the generation is unchanged. TestHostCertStatus's own checks ran before its subtests, so the status mutant failed the parent instead of status_written_after_install; the checks are now the subtest `fields_from_record_and_attempts`.

Deviations (Task 4):
- [Rule 1] An injected crash in the install batch was logged and rolled back instead of stopping the step; HostCerts now returns a crash at once, as a killed process would (isCrash), so the crash table means what it says.
- [Rule 1] hostCertDue counted a renewal threshold or back-off already passed for a key that is waiting on a live request, so the run loop called the step on every iteration while an answer was outstanding. A waiting key is now due when its wait ends (found by TestRunHostCertsWhenDue).
- [Rule 2] The missing-record refill is implemented: under hostcert_record_missing or hostcert_record_invalid, when adoption finds a verified file, a new empty record is started and the batch installs it; an invalid record is first renamed to `hostcert.json.invalid` (a symlink is renamed, never followed). With nothing adoptable the record stays missing, so the code and GC's skip stand.
- [Rule 2] Preflight refused (dropin_drift) a drop-in whose only difference from wantDropIn was its own HostCertificate lines while the record was missing or invalid, against T-03-341 ("no record state is a preflight refusal"). That difference is now the record-code note only.
- [Rule 3] The test fixture's KRLs revoked user-CA serials only; `fixture.krlHostSerials` lets a KRL revoke host-CA serials (kept_file_revoked_before_retry_not_installed).
- TestHostCertAnswerCap is in internal/agent/spool as the plan says, but the heal lives in the fetcher: the spool test pins the cap and that Read takes no answer as a document, and `TestPostHostCerts/oversize_answer_healed` (an extra subtest) proves an answer of cap+1 bytes is removed and one at the cap kept.
- TestPostHostCerts uses random bytes as the relayed certificate: the fetcher never parses it, and forbidigo bans `SignCert` outside internal/cert.
- `repair_keeps_extensions` covers the no-op repair and repairDropIn after a trial; adopt's repair (adopt.go) is not exercised by it. UNVERIFIED: that adopt's repair keeps the HostCertificate lines (it calls wantDropIn, which the structural gate enforces).
- `include_inside_match` models the Include inside Match with the fake's noInclude knob (the global sshd -T shows no drop-in line), as the fake has no Match evaluation of its own.
- Attempts gained `Skipped` and `Detail` (the heartbeat's host_keys_skipped and host_cert_detail come from them), and the abandonment back-off counts from the request's CreatedAt.

T4: d1c540a

## Task 5 (runbooks, CI timeout, publish edits, gates, PR)

- Runbooks: host-setup.md gains `## Host certificates` after "Running the agent" (what is requested and when, where it lives, how to check, the codes with the closed sticky list, cert_revoked, when a host can be left without a certificate, the upgrade order, ports and HostKeyAlias, disable versus revoke); "Removing a host" says to revoke host certificates before removing and forgetting. revoke.md names 03-09b for the host subject at its three places. The joined revoke.md checks print 1 (`arrives with 03-09)`) and 2 (`arrive with 03-09 and`) on origin/main and 0 and 0 on the branch, so they bite. The 03-14b anchors are unchanged.
- CI: ci.yml:53 is `CGO_ENABLED=1 go test -race -count=1 -timeout 15m ./...`; nothing else in ci.yml changed.
- Publish edits, computed from origin/main (W9 = 21): the plan committed with `wave: 21` and `depends_on: ["03-08i"]`; ROADMAP's 03-09 row reworded, 03-09b inserted at Wave 22, Waves 22 to 28 renumbered 23 to 29 with their "blocked on" clauses, `in 28 waves` became `in 29 waves`; 03-10 to 03-16 `wave:` + 1 (all in files_modified, so no unlisted plan changed); 03-10 `depends_on: ["03-09b"]` and the 03-09b-SUMMARY clause in its precondition. The guard held: origin/main's 03-10 had `depends_on: ["03-09"]` and 03-09 `depends_on: ["03-08i"]`.
- The scope gate bites: on a throwaway detached worktree with one commit that edits a bullet line of 03-08k-PLAN.md (not in files_modified) it exits 1. The worktree was removed and the commit never pushed.
- capslock: `scripts/capslock-check.sh` reports no new (package, capability) pair (signer 92, agent 37, fetch 23 pairs, each equal to its baseline), and `--update` leaves test/capslock byte-identical. internal/agent/hostcert reaches no capability (pure code); the agent's outbox and host-directory writes go through internal/agent/apply and spool, the fetcher's new route through serverclient, the signer's new frame through wire, all of which held their pairs already. So there is no `chore(capslock)` commit and no pair to list.
- Gates on 3f92675: the publish-commit guard, the structural DropIn and s.db allowlist gate, the runbook gate, the 03-14b pins, the scope gate, the authorship and signature gate, the wave gate and the ROADMAP gate pass. Alone gate: apply 382.674 s against 377.800 s (+4.9 s). Full gate (./..., vet, e2e vets, gofmt, golangci-lint `0 issues.`, capslock, dep-firewall, testonly-firewall, pinned actions): exit 0, no FAIL or DATA RACE; apply 439.492 s (-74.0 s against 513.511), signer 372.942 s (-66.2 s against 439.160).
<!-- t5-pr -->

Deviations (Task 5):
- The capslock baselines did not change, so the capslock and CI gate's first clause (a `chore(capslock)` commit touching test/capslock) cannot hold; its ci.yml clause passes. A cosmetic baseline commit to satisfy it would misreport the capability review. Owner question: accept "no new pairs" for this plan.
- The fetcher, heartbeat, spool and host status tests were first written in new `*hostcert_test.go` files outside files_modified; 3f92675 moved them unchanged into fetch_test.go, heartbeat_test.go, spool_test.go and hoststatus_test.go, after which the scope gate passes.
- 9602a04 is typed `test(agent)` but carries two behaviour fixes besides its tests: the run loop's due time for a key waiting on a live request (hostCertDue), and preflight no longer refusing a drop-in only for its own HostCertificate lines under a record code. History was not rewritten.

Owner decisions recorded in this plan:
- Q-09-2 refined: window = min(CapSeconds at issuance, cap in force)/3 (owner-confirmed, Q-09-6, 2026-11-06)
- Q-09-5 narrowed: cert_revoked is checked against the latest certificate per host key only (owner-accepted, Q-09-9, 2026-11-06); revoke host revokes every serial

The s.db allowlist gate bites (Task 3): on a scratch copy of hostissue.go that calls `s.db.LiveIssuanceForSubjectTx` it prints that line. The scope gate bites (above).

## UNVERIFIED

- A non-root fetcher's 0644 answer read by the capability-less applier under real systemd users (agent-10): the systemd-sandbox job runs the new step but asserts nothing about host certificates; TestPostHostCerts/answer_mode_0644 covers the mode only.
- sshd serving only the first key per algorithm (`two_keys_one_algorithm`): the fake sshd's model.
- HostCertificate being fatal inside a Match block (upstream servconf.c); `include_inside_match` is modelled with the fake's noInclude knob.
- HostKeyAlias behaviour beyond the CI OpenSSH builds.
- Windows OpenSSH as a host.
- Adopt's repair keeping the HostCertificate lines (`repair_keeps_extensions` covers the no-op repair and repairDropIn after a trial).
- That the WSL boot ID changes only on a reboot: it changed twice in this plan without one.
- Every runbook claim on a real host, until 03-16.

## Pre-merge review

Pending: the orchestrator runs it on the green PR.

requirements-completed: [AGENT-06] (CI-verified, re-checked in 03-16).
