---
phase: 03-linux-agent-and-revocation
plan: 10b
subsystem: agent, ci
tags: [probe-certificates, self-test, d-06, agent-04, e2e]
status: in-progress
requires: [03-10]
requirements-completed: []
---

# Phase 3 Plan 10b: The agent's probe self-test Summary (draft)

Owner answers: Q2 Q5 Q6 P4 planner-defaults
AGENT-04: open until 03-10c

## Bases

test-time base: apply=515.806 fetch=39.539 heartbeat=1.069 serverclient=4.333 agentcmd=2.279 cmd=241.507 at=1794104446
e2e base: run 42403955637 9.5p1=779.609 10.5p1=794.258 probe9.5p1=35.006 probe10.5p1=37.983

The test-time base ran on unchanged origin/main 1260b8c in a detached worktree outside the repository, with no other heavy job, through scripts/linux.sh (go1.27.3 linux/amd64 in WSL); each time is that package's `ok` line.

## Task 1

e2e RED run: 42439277162

RED (CI): the throwaway branch p03/10b-e2e-red held test/e2e/probe_selftest_test.go and .github/workflows/e2e.yml only (`git diff --name-only origin/main...p03/10b-e2e-red` printed exactly those two). Both main lanes passed and showed no probe test; both e2e-probe lanes failed to build with `undefined:` lines in probe_selftest_test.go (16 such lines across the run's log: withGenesisMachineMaxTTL, apply.ProbeQuery, apply.ProbeTarget, apply.ProbeOutcome, apply.ProbeAccepted, apply.ProbeRefused, apply.ProbePairSpacing, ...). The branch was deleted afterwards (`git ls-remote --exit-code origin refs/heads/p03/10b-e2e-red` exits 2). After the RED run the test file changed only by two `//nolint` comments for the e2e lint.

RED (unit, compile failures): internal/agent/probe with probe.go moved aside (`undefined: Pair`, `Polarities`, `NewCert`, ...); internal/serverclient with the method reverted (`c.AgentProbeCert undefined`); internal/agent/fetch (`s.f.postProbeCerts undefined`). The first run of TestVerifyCert against the drafted core then failed for real: `TestVerifyCert/ok`, `not_yet_valid` and `expired_or_in_margin` refused a valid certificate as signature_invalid, because x/crypto's CertChecker in this version does not skip source-address; both options are now listed as supported (they are checked exactly before the signature).

The check step of the e2e-probe job, cut out of the workflow and run under `bash -eo pipefail` on a canned log, exits 0 with all four PASS lines and exits 1 with `the log has no PASS line for TestProbePairSpacing` when that line is missing: it bites.

T1: d4e19e1 (code at 039d98b; d4e19e1 only replaces the source-address defect value in TestVerifyCert with a loopback one; the green run and the mutants ran at 039d98b)

Task 1 gates, local (through scripts/linux.sh): the build, `go vet` (default, `-tags keyroster_e2e` over the agent packages, `-tags e2e` and `-tags "e2e e2eprobe"` over test/e2e) and the named unit tests with `-race` pass, with every named PASS line; the broad run `go test -race ./internal/agent/... ./internal/serverclient/ ./cmd/keyroster-agent/ ./cmd/keyroster/` passes (apply 546.4 s, fetch 43.8 s, cmd/keyroster 246.9 s; pass or fail only, not a test-time reading); golangci-lint is clean for linux, windows and darwin, gofmt is clean, and the e2e lint scoped to new and changed files (`--new-from-rev=origin/main`) reports 0 issues; `scripts/capslock-check.sh` passes with every baseline unchanged (signer 92, agent 37, fetcher 23 pairs; internal/agent/probe reaches no capability); FuzzParseRecord ran 30 s (about 744 000 executions) with no crash and no corpus file left; the tag gate lists exactly the six allowlisted files; the release-build gate passes (the untagged agent exits 2 with `probe_self_test_off_refused` and creates no state directory, the tagged one accepts the flag); `git diff --name-only origin/main -- internal/wire internal/tlog internal/cert internal/certprofile internal/signer internal/server internal/audit docs cmd/keyroster/root.go test/capslock` prints nothing.

gate control: release-build gate exits 1 with checkProbeOff mutated to return nil in cmd/keyroster-agent/probeoff.go (restored, `git diff --quiet HEAD --` clean)

e2e green run (Task 1): 42441702823 at 039d98b. The e2e gate in `green` mode passed (exit 0): main lanes 9.5p1 748.191 s (base 779.609) and 10.5p1 765.514 s (base 794.258), both successful and with no `=== RUN   TestProbe` line; probe lanes 9.5p1 300.550 s (base 35.006) and 10.5p1 300.675 s (base 37.983), under the 420 s cap. In both probe lanes `TestProbeSelfTestEndToEnd/pair_issued_and_enforced` (9.6 to 10.6 s), `TestProbePairSpacing` (120 to 124 s, run in parallel with it), `TestProbeCertsAgainstSSHD` and `TestProbeSSHDFacts` passed; `widening_passes_probes` failed after its 240 s wait, as PROBE_ALLOW expects before Tasks 3 and 4, which ended the test (the later subtests did not run). Those 240 s are most of each probe lane's time.

A9 spacing (9.5p1): FACT A9 spacing OpenSSH_9.5p1: pairs=3 spacing=60s dropped=none penalty_lines=0 listener_answered=3/3 control_dropped_after=not exercised (run 42441702823)
A9 spacing (10.5p1): FACT A9 spacing OpenSSH_10.5p1: pairs=3 spacing=60s dropped=none penalty_lines=6 listener_answered=3/3 control_dropped_after=3 pairs (run 42441702823)
P7 spacing (10.5p1): exercised
P7 spacing (9.5p1): not exercised, no PerSourcePenalties

## Task 2

First commit (e6aec5a), the test-strength fix from Task 1's handover: every TestVerifyCert defect made by editing an issued certificate is now signed again by the trusted machine CA (`SignCert`), and each subtest asserts that the defect's signature verifies (and that `signature_invalid`'s does not, so the helper is not vacuous); `key_id_ca_not_machine` now changes only the ca field. The six named defects were re-run against their removal mutants, each alone on its subtest: `extension_present`, `two_principals` and `key_id_ca_not_machine` and `key_id_subject_other_host` now fail with `VerifyCert: <nil>` (the certificate is accepted), so the removed rule shows as acceptance; `force_command_value` and `source_address_value` fail with `extra_critical_option`, because the exact-options rule (`maps.Equal` against certprofile.ProbeCriticalOptions) still refuses them; only removing both would show acceptance. The same commit renames apply/probe.go's facts struct to `probeFacts`, so the plan's `probeState` is probe-state.json's type.

RED (unit, compile failures, with heartbeat.go reverted to HEAD): internal/agent/heartbeat `undefined: ValidDetail`; cmd/keyroster `held.ProbeDetail undefined (type heartbeat.Status has no field or method ProbeDetail)`; internal/agent/apply `undefined: probeState` (and the other Task 2 symbols behind it). The production code of heartbeat.go was drafted before its tests and moved aside for this run; everything else was written after its tests.

T2: fdfb08c (e6aec5a is the VerifyCert re-signing and the rename, e372683 waives forbidigo's SignCert rule for those test doubles, as cmd/keyroster/ca_status_test.go does)

Task 2 gates, local (through scripts/linux.sh): the build, `go vet ./...` and `go vet -tags keyroster_e2e` over the agent packages pass; the named tests with `-race` pass with every named PASS line (TestProbeStateIO/foreign_owner_resets skips without root: the owner is compared like the mode); the broad run `go test -race ./internal/agent/... ./cmd/keyroster/` passes (apply 507.0 s, cmd/keyroster 221.9 s; pass or fail only); golangci-lint is clean for linux, windows and darwin after e372683, gofmt is clean; FuzzParseState ran 30 s (about 1 664 000 executions) with the list check first, no crash and no corpus file left; `git diff --name-only origin/main -- internal/server internal/signer internal/serverclient/client.go` prints nothing.

probe-state.json encoding choices (frozen with this commit): `failure` and `held` are null when absent, `alarm` is always present (`""` when none), `negatives` is always a list (a null list does not parse); the failure code, the alarm and the held reason are each checked against their closed list, the failure key is 64 lowercase hex and its count at least 1. The reader only reads (status uses it); `loadProbeState`, for the gate, rewrites a refused file once as the exhausted hour, which status then reports as probe_state_reset for an hour.

## Task 3

RED (unit, compile failures): with apply.go, probegate.go and run.go reverted to HEAD and account.go moved aside, `go test -run '^(TestProbeClassify|TestProbeAccount|TestProbeGate|TestRunHeldTrigger)$' ./internal/agent/apply/` fails to build with `undefined: classify`, `probeClass`, `classFirstInstall`, `classNarrowing` and `classTrustOnly` (the compiler stops at ten errors). The production code was drafted before the tests and moved aside for this run, as in Task 2; its RED is compile RED only.

What landed:
- **probegate.go:** `classify` and `needsGate`; `probeGate` (the account, then the probe principal, then the pair, then the back-off, then the budget); `probePair`, the one pair selector (Next, then Committed) that Task 4's probes must reuse so their failure key matches the gate's; `failureKey` (length-prefixed fields: sorted CA and principal lines, both serials, the passwd line; no KRL, no comments); `probeBackoff` (60 s doubling, capped at 1 h without overflow); `heldPresent`; `writeHeld`, which does not write when the reason and versions are unchanged; `clearHeld`, which writes only when a record exists; `gateSuperseded`; `heldOutcome`.
- **account.go:** `checkProbeAccount` and `parsePasswdLine`.
- **forward:**
  - Last-good is resolved once, at the top, where `heldPresent` also runs and rewrites a probe-state.json that does not read (outside a dry run). This is the `loadProbeState` call that every locked apply takes.
  - The no-op test carries `!held`.
  - Classification and the gate run after the DryRun return, before the equal-content commit.
  - A collapsed hold either commits only its versions through that branch (a changed capture) or returns at once (a retry).
  - A non-collapsed hold replaces g by the intermediate.
  - Clearing: clause (a) is `sameContent(cur, g)` with no hold; clause (b) is after a commit of the full candidate (`!substituted`), first install included; the idle branch clears too. None of them runs while `heldReason` is set.
  - A superseding target is classified and gated against the generation current names at the top of the next pass. A hold there installs Intermediate(from, t), or, when that collapses, commits `from` without another swap; the discarded superseding generation is removed.
- **run.go:** `heldPending` (no lock; a held record, or a file that does not read or is not 0600 of the effective uid) and `forceApply`.

T3: fffc0af (the code, the tests and the harness; the mutants ran on it)

Task 3 gates, local (through scripts/linux.sh), at T3:
- **Verify block 1**, run verbatim, passes: build, `go vet ./...`, the tagged vet, the named tests with `-race`, every named PASS line, and no FAIL, panic or race.
- **Verify block 2.** The broad run `go test -race ./internal/agent/... ./cmd/keyroster-agent/` passed once on the tree before the two lint fixes (apply 468.0 s). It passed again at T3 except one subtest (apply 503.2 s; pass or fail only).
  - `TestFetch/more_repolls_immediately` failed its wall-clock bound: `Once` took 1.03 s against 900 ms while the apply package ran beside it under `-race`.
  - It passed 5 of 5 times alone (`-race -count=5`) and in a full `-race` run of the fetch package. Task 3 does not touch internal/agent/fetch, and fetch_test.go is outside files_modified, so it stays a load-dependent flake for the review (fetch.go's `Once` gained `postProbeCerts` in Task 1).
  - FuzzParsePasswdLine ran 30 s (about 2 485 000 executions, after the list check) with no crash and no corpus file left. golangci-lint is clean for linux, windows and darwin, and gofmt is clean.
- **Gate 3** passes: `git diff --quiet origin/main --` over render.go, selftest.go, hostcert.go, preflight.go and internal/agent/hostcert.
- **The two lint fixes after the first run:** an ineffectual `reclassify = false`, and a G115 comment in the harness.

## Task 4

## Mutants

Every mutant was applied to the committed tree (T1), run alone on its named test with `-timeout 5m` (without `-race`), counted killed only on its named `--- FAIL:` line, restored with `git checkout --` and proven with `git diff --quiet HEAD --` on the mutated file. Task 1: 33 killed, 0 equivalent, 0 survived (the plan lists 31; the two clearing mutants and the checkProbeOff mutant are counted separately).

mutant killed: VerifyCert without the force-command value check (TestVerifyCert/force_command_value)
mutant killed: VerifyCert without the extension check (TestVerifyCert/extension_present)
mutant killed: VerifyCert without the key equality (TestVerifyCert/other_key)
mutant killed: VerifyCert comparing the principal by prefix only (TestVerifyCert/principal_other_host)
mutant killed: VerifyCert without the CA check (TestVerifyCert/ca_not_trusted)
mutant killed: VerifyCert not comparing the key ID subject (TestVerifyCert/key_id_subject_other_host)
mutant killed: VerifyCert without the lifetime cap (TestVerifyCert/lifetime_over_seven_days)
mutant killed: BuildRequest not clearing the private key on the success path (TestBuildRequest/ephemeral_key_cleared)
mutant killed: BuildRequest not clearing the private key on an error path (TestBuildRequest/ephemeral_key_cleared)
mutant killed: BuildRequest signing the host evidence under wire.HostPoPNamespace (TestBuildRequest/signed_under_probe_namespace)
mutant killed: a reused probe key across two requests (TestBuildRequest/fresh_key_per_request)
mutant killed: PairUsable without the negative-serial rule (TestPairUsable/negative_not_in_krl)
mutant killed: PairUsable without the positive-in-KRL rule (TestPairUsable/positive_in_krl)
mutant killed: PairUsable without the pair CA rule (TestPairUsable/ca_mismatch)
mutant killed: the missing margin 60 s instead of min(60, V/6) (TestPairUsable/margin_is_min_60_or_sixth)
mutant killed: renewal at one third (TestDecide/renew_pair_at_two_thirds)
mutant killed: the old pair dropped when a new one arrives (TestDecide/keep_old_pair_until_new_negative_listed)
mutant killed: probe_cert_recent on the sticky list (TestIsSticky)
mutant killed: host_disabled off the sticky list (TestIsSticky)
mutant killed: ProbeQuery treating a nil error as accepted (TestPKQuery/nil_error_is_inconclusive)
mutant killed: ProbeQuery treating any error as refused (TestPKQuery/inconclusive_closed_before_auth)
mutant killed: ProbeQuery dialing from 127.0.0.1 (TestPKQuery/source_is_127_0_0_2)
mutant killed: ProbeQuery accepting a host key outside HostKeys (TestPKQuery/wrong_host_key_is_inconclusive)
mutant killed: ProbeQuery without the loopback check (TestPKQuery/non_loopback_target_refused_without_dial)
mutant killed: the probe file rendered with probes off (TestRenderProbeFile/bytes_identical_with_probes_off)
mutant killed: the probe file rendered into a trust-only generation (TestRenderProbeFile/not_in_trust_only)
mutant killed: the probe file written over a mapped account (TestRenderProbeFile/mapped_account_untouched)
mutant killed: checkLimits' cap unchanged (TestCheckLimitsProbeFile/two_full_groups_install_and_read_back)
mutant killed: readGeneration's cap unchanged (TestCheckLimitsProbeFile/two_full_groups_install_and_read_back)
mutant killed: the spool prefix filter removed (TestRunProbeTrigger)
mutant killed: the fetcher posting an answered request again (TestPostProbeCerts/answered_not_posted_again)
mutant killed: the attempt saved after the outbox write (TestProbeStep/crash_points)
mutant killed: checkProbeOff returning nil in the default build (TestProbeSelfTestOffRefusedInDefaultBuild)

Task 2's first commit re-ran three Task 1 mutants on the re-signed defects (counted once, above): force_command_value (now refused as extra_critical_option), extension_present and key_id_subject_other_host (both now accepted, `VerifyCert: <nil>`); and three new removal mutants:

mutant killed: VerifyCert counting only an empty principal list as wrong, so a second principal passes (TestVerifyCert/two_principals)
mutant killed: VerifyCert without the key ID ca check (TestVerifyCert/key_id_ca_not_machine)
mutant killed: VerifyCert without the source-address value check (TestVerifyCert/source_address_value)

Task 2 (10 killed, 1 equivalent):

mutant killed: ValidDetail accepting a second colon (TestValidDetail)
mutant killed: ValidDetail without the length bound (ten times MaxDetail) (TestValidDetail)
mutant killed: buildStatus sending the detail unvalidated (TestBuildStatusDetail/invalid_detail_dropped)
mutant killed: refusals without ErrProbeHeld (TestBuildStatusDetail/held_is_refused)
mutant killed: probe_detail priority with the held reason above the alarm (TestProbeStatus/priority)
mutant killed: the reader treating a corrupt file as an empty state (TestProbeStateIO/reset_counts_an_exhausted_hour, and alone again on TestProbeStateIO/unknown_field_resets)
mutant killed: the reader following a symlink (TestProbeStateIO/symlink_resets)
mutant killed: future entries kept as they are (TestProbeStateIO/future_entries_clamped_to_now)
mutant killed: the writer without the lock check (TestProbeStateIO/never_written_outside_lock)
mutant killed: run.go suppressing a held error whose reason changed (TestRunHeldNoise)
mutant equivalent: hoststatus printing probe_detail without safe: keyroster host status validates every heartbeat (heartbeat.Validate, ValidDetail on probe_detail) before it prints, so a detail with a control byte is refused with an error naming probe_detail and never reaches the print; TestHostStatusProbeAlert asserts that refusal and the escape-free output

Running count after Task 2: 46 killed, 1 equivalent, 0 survived.

Task 3 (29 killed, 0 equivalent, 0 survived; the plan's list has 29 entries, counted as 28 in its floors). They were applied to the committed tree (T3), run by the same runner, with three of them also run on a second subtest:

mutant killed: classify treating a mixed change as narrowing (TestProbeClassify/mixed_is_widening, and again TestProbeGate/widening_held_narrow_part_lands)
mutant killed: the trust-only exemption removed (TestProbeGate/trust_only_disabled_exempt)
mutant killed: first install gated (a gate call inserted in forward's first-install branch) (TestProbeGate/first_install_exempt)
mutant killed: the probe-file-only exemption removed (TestProbeGate/probe_file_only_widening_exempt)
mutant killed: the probe-file-only exemption widened to any file (TestProbeClassify/probe_file_plus_other_line_is_widening)
mutant killed: the substitution made without the isProbeFile check on both sides (TestProbeClassify/mapped_probe_account_addition_is_widening, and again TestProbeGate/mapped_probe_account_addition_held)
mutant killed: isProbeFile accepting a file with an extra line (TestProbeClassify/probe_file_with_foreign_line_is_widening, and again TestProbeClassify/is_probe_file_exact)
mutant killed: the hold landing g instead of the intermediate (TestProbeGate/widening_held_narrow_part_lands)
mutant killed: the gate applied to a narrowing change (TestProbeGate/narrowing_lands_without_probes)
mutant killed: the gate holding a KRL-only change (TestProbeGate/krl_only_lands_while_account_missing)
mutant killed: the held record written after the commit (TestProbeGate/held_record_written_before_commit)
mutant killed: the no-op test without !held (TestProbeGate/held_retried_when_ready)
mutant killed: the held record never cleared (TestProbeGate/held_clears_when_widening_lands)
mutant killed: the held record cleared on every run (TestProbeGate/held_survives_restart)
mutant killed: the gate after allocGeneration (TestProbeGate/held_retry_writes_nothing)
mutant killed: a collapsed hold that commits on a retry (TestProbeGate/held_retry_writes_nothing)
mutant killed: the held record rewritten on every retry (TestProbeGate/held_retry_writes_nothing)
mutant killed: pair validity judged at now (TestProbeGate/pair_validity_needs_wait_margin)
mutant killed: spacing judged at now rather than at now + wait (TestProbeGate/budget_lookahead_spacing)
mutant killed: the budget with seven negatives allowed (TestProbeGate/over_budget_widening_held)
mutant killed: the failure key without the passwd line (TestProbeGate/failure_backoff_blocks_until_input_changes)
mutant killed: checkProbeAccount accepting uid 0 (TestProbeGate/account_reasons_hold)
mutant killed: checkProbeAccount accepting a shell not named nologin (TestProbeGate/account_reasons_hold)
mutant killed: a mapped account's file overwritten (TestProbeGate/mapped_account_holds_account_is_managed)
mutant killed: the superseded target not reclassified (TestProbeGate/superseded_target_reclassified)
mutant killed: forceApply never set (TestRunHeldTrigger/held_record_applies_at_once)
mutant killed: clearHeld only in the sameBytes branches (TestProbeGate/held_clears_when_widening_reverted)
mutant killed: clearHeld also called in the :899 commit of a collapsed hold (TestProbeGate/pure_addition_held_changes_nothing_on_disk)
mutant killed: cur's side tested with the exact isProbeFile only (TestProbeGate/probe_file_only_after_a_hold)

Running count after Task 3: 75 killed, 1 equivalent, 0 survived (floors: 92 killed, 97 with equivalents; Task 4 lists 27).

## Deviations

- **Stopped after Task 1 (the plan's context rule).** Budget and verify says that if Task 1 nears half the context, the executor stops after its gates and reports instead of trimming. It did: Tasks 2 to 5 (reporting, the gate and the hold, the probes in forward, the PR) are not started. No PR is open.
- **Accepted as defaults by the orchestrator (the owner may still veto):** the G21 conditional cap and the e2e `private_key_never_on_disk` exception for the fetcher's own `identity.key`/`identity.next`, both below.
- **G21 cap, conditional.** checkLimits grants the one extra principals file only when the generation holds the probe account's own file (`checkLimitsFixed(g, fixed)`, fixed `""` while the probes are off); readGeneration reads back up to MaxAccounts + 1. The plan's unconditional form would have let `rechain_test.go`'s `intermediate_union_too_large_krl_applied` intermediate (MaxAccounts + 1 files, probes off) through, and `renderable_test.go` calls `checkLimits(g)`; both files are outside files_modified, so `checkLimits(g)` keeps its signature as `checkLimitsFixed(g, "")`.
- **Decide's switch.** Next replaces Committed when Next is a complete pair PairUsable accepts and Committed is not usable, absent or at its renewal time. Step 2's parenthetical names only "not usable or absent"; the must_haves truth (kept until a newer pair's negative is listed) and the separate subtests `switch_when_next_negative_listed` and `committed_missing_and_next_usable_switches` read as including the renewal case. Next is only collected at renewal or when no pair is usable, so the two readings differ only for a renewal-due pair.
- **VerifyCert order.** Every structural rule (type, key, principals, extensions, options, key ID, lifetime) is checked before the CA key and the signature, then the time; each defect keeps its own code.
- **The e2e decodes probe.json and probe-state.json with local structs** over the frozen format: importing internal/agent/probe, which main lacks, would have made the RED run `[setup failed]` instead of `undefined:`.
- **ProbeCerts consumes a live request whose outbox file is missing or names another request** (a crash between the attempt and the outbox write) and requests again at once, instead of waiting out hostcert.RequestTTL; its probe key no longer exists, so it can never be answered usefully.
- **Import names.** Package apply imports the core as `probecert` (selftest.go's function `probe` must stay byte-unchanged) and internal/cert as `certpkg` in probe.go (interleave_test.go declares `cert`).
- **e2e `private_key_never_on_disk`** skips the fetcher's own TLS identity (`identity.key`, `identity.next` in `<root>/var/lib/keyroster-agent-fetch`), which is a PKCS #8 `PRIVATE KEY` by design and no probe key; the state directory is checked without exception. Recorded as an open question.
- **RED first was partial.** The probe core, the client and the fetcher showed compile RED before their code (the core by moving probe.go aside); pkquery.go and apply/probe.go were written before their tests, so their RED is not evidence.
- **The plan file is committed with the SUMMARY** (byte-identical, `wave: 24`, `depends_on: ["03-10"]`) instead of in Task 5, so the working tree holds only the pre-existing noise at the stop.
- **Task 2: TestRunHeldNoise tests the suppression helper**, `heldNoise.quiet(err, rc.Clock.Now())`, which Run calls for every apply: nothing returns ErrProbeHeld before Task 3 and RunConfig has no Apply seam, so the Run-level wiring is exercised once holds exist (Task 3). Suppression never touches `failedAt`, so the 60 s retry still runs (D9).
- **Task 2: the host status escaping.** The plan's behavior line says a hostile detail is escaped by `safe`; the CLI refuses such a heartbeat before printing (heartbeat.Validate), so the test asserts the refusal naming probe_detail, `safe` stays as defence in depth, and its mutant is equivalent (recorded above).
- **Task 2: heartbeat.go was drafted before its tests**; the RED run moved it aside (reverted to HEAD) and restored it after.
- **Task 2: the probes-off Report values are set at Apply's start**, so refusal paths carry them too.
- **Engine seam helper.** `engine.probeQueryFunc` (Config's seam or ProbeQuery) and its test land in Task 1, so the field is used; Task 4's probes call it.
- **Stopped after Task 3 (the plan's context rule, Budget and verify).** Task 3 is complete and pushed; Tasks 4 and 5 are not started. No PR is open.
- **Task 3: two Task 1 subtests edited (probe_test.go, in files_modified but not in Task 3's `<files>`).** With the gate in place, `TestProbeStep/host_holds_write_nothing_or_hold` and `TestRenderProbeFile/not_in_trust_only` applied a mixed change with probes on and no pair, so the gate held it. Each now accepts ErrProbeHeld at that one step, with a comment; neither tests the gate, and their own assertions are unchanged (Rule 3).
- **Task 3: the held record's versions** are the verified candidate's (`v.Next` bundle, directory, KRL). `issue_refused` releases a sticky refusal against accepted/'s bundle, policy and directory versions, as the issuance step reads them.
- **Task 3: `heldOutcome` joins** an earlier outcome error (v.Refused and the like) with the held error instead of dropping it, so `refusals` and `heldNoise` still see ErrProbeHeld.
- **Task 3: a collapsed supersede hold** commits the generation current names (`from`), with the superseding target's host status, without a further swap; the superseding generation, which nothing names, is discarded. A non-collapsed one installs and validates Intermediate(from, t) as Transition does.
- **Task 3: `heldPresent` and `heldPending` ignore the probe switch.** A held record with probes off still makes the round render, so the full candidate commits and clears it; `loadProbeState` (the reset rewrite) is skipped only in a dry run.
- **Task 3: `budget_lookahead_spacing` uses LoginGraceTime 10** (a widening wait of 40 s). The reader clamps future times to now, so "59 s at probe time" with the harness's 150 s wait would need a pair in the future. The cases are a pair 21 s ago (61 s at probe time: lands) and 19 s ago (59 s: `budget`); the mutant that judges at now is killed by the first.
- **Task 3: TestRunHeldTrigger** has three subtests. `held_record_applies_at_once`: the first hold is `issue_unanswered`, because the pair's requests are live. `no_held_record_waits`. `identical_holds_print_and_log_once`: the Run-level noise check from the Task 2 handover. It counts Out calls and log lines, proves every round applied through a counting Runner, and holds `account_missing` so the reason stays fixed while ProbeCerts requests a pair.
- **Task 3: RED was compile RED only.** The production code was drafted first and moved aside for the RED run.

## UNVERIFIED

- Local e2e: not run (the namespace wrapper of 03-10 was not used); the e2e results are CI only.
- `systemd-sandbox` with this branch's KRL activity (a first probe pair publishes a negative): no PR run yet.
- Every Edge Coverage item of the plan; and everything of Tasks 4 and 5.
- Task 3 at the e2e level: no e2e run carries Task 3 yet. Every e2e host runs with `--probe-self-test off`, so no gate runs there except TestProbeSelfTestEndToEnd's host; that test's widening steps need Task 4.
- Task 3: a host that runs with probes on before Task 4 lands (none ships: this is one PR) would let a gate-passing addition go live without the probes. That is Task 4's code, and nothing between Task 3 and Task 4 is released.
- Task 2 at the e2e level: no e2e run has carried Task 2 yet (the next e2e run is Task 4's); every e2e host now reports `probe_self_test_off` in last_apply.detail and probe_detail and shows a `probe:` alert, which no e2e assertion reads (checked by grep of test/e2e, test/distro and test/systemd).

## Resume point (for the continuation)

Task 3 handover (the current resume point):
- Next is Task 4 (the probes in forward: reserveProbe, runProbes, settleFailedAddition, opportunistic, the served certificates, TestProbeSites, TestNegativeProbeBudgetAcrossProcesses, TestForwardServedCerts, the e2e), then Task 5. Task 3 is done and pushed (T3 above).
- **Pair selection.** Pick the pair with `e.probePair(rec, at, k, caKeys)` (probegate.go): Next when PairUsable accepts it, else Committed. Use it in runProbes too, so `failureKey(g, pair, line)` (with `line` from `checkProbeAccount`) matches what the gate compares. runProbes judges at `now + SelfTestTimeout`.
- **forward state.** forward keeps `heldReason` (this pass's hold), `substituted` (the target is a hold's intermediate) and `reclassify` (set on every supersede).
  - Task 4's gated flag belongs beside them. Set it where the first pass's gate passes (in the candidate loop, `needsGate(class)` with an empty reason) and in `gateSuperseded`, where the gate passes for the new target. Clear it for a narrowing or exempt target and on a hold (Fix round 3, r2-6). `gateSuperseded` would then return it.
  - `preN` (D13) is not tracked yet. Set it after each Transition pass to `mid` when non-zero, else `from.N`.
- **forward anchors at T3** (they moved again):
  - the no-op test is at apply.go:901 with `!held`;
  - the gate block starts at `class := classify(` (about :953);
  - the equal-content commit is `if cur != nil && (sameBytes(cur, g) || heldCollapsed)`;
  - the Transition loop starts after `substituted, reclassify :=`;
  - the self-test (`e.report.SelfTest = "pass"`, apply.go:1109) and the commit are at the end of forward, followed by `if !substituted { e.clearHeld() }` and `return heldOutcome(outcome(tv), heldReason)`.
  - The required probes go between `e.report.SelfTest = "pass"` and `e.commit(target.N, tv)` when the target was gated. On a pass, the existing commit runs and then the clear.
- **The hold writes `Report.Detail` and both probe fields (`skipped:not_ready`)** through `e.hold`. `e.labelExempt` sets the `skipped:exempt_*` values only while the probes are on.
- **Fixture helpers in harness_test.go:**
  - `gateOn` (probes on, the passwd fixture, an executable nologin);
  - `signProbe`, `probeCert`, `seedPair`, `storePair` (the pair in probe.json);
  - `listMach` (KRLs list machine-CA serials);
  - `writePasswd` and `writeRootFile`.
  - probegate_test.go adds `gateHost`, `ready`, `probeStateNow`, `heldNow`, `setProbeState`, `probeDetail`, `acceptedDir`, `mustHeld`, `mustPrincipals`, `diskState` and `genNow`.
  - Scripted queries go through `h.cfg.probeQuery`.
- **The mutant runner** used for Task 3 is a shell script: `m DESC FILE PERL TEST [SUB]` applies a `perl -0pi` substitution that must change the file, runs `-run '^T$/^sub$'` through scripts/linux.sh, and counts only the `--- FAIL: T/sub (` line. It then restores with `git checkout --` and checks `git diff --quiet HEAD --`; `m2` handles a mutant over two files. When writing Go source through a Bash heredoc, the tool layer turns `\n` inside the text into a newline: use the Edit tool for any line with an escape.
- **The test-time base** (`at=1794104446`) is more than 24 h old by the time Task 5 runs: re-measure it in place first (Task 1 Step 0.2).

Earlier handovers (Tasks 1 and 2), kept for reference:
- Task 3 (the decision: classify, account.go, probeGate, the hold wiring in forward) was next after Task 2 (T2 fdfb08c). probegate.go already holds the error values, the closed hold reasons, probeState with its reader (`readProbeState`, read-only), `loadProbeState` (rewrites a reset once, locked engines only) and `writeProbeState` (refuses without `e.locked`); `WriteStatus`'s engine takes apply.lock but never sets `e.locked`, so only the engines of Apply (apply.go:435), HostCerts (hostcert.go:151) and ProbeCerts (probe.go:235), which set it, can write.
- Task 2's verify block 1 was re-run verbatim at fdfb08c (build, `go vet ./...`, the tagged vet, the named tests with `-race` and the PASS loop: all pass), with the final TestRunHeldNoise table.
- The reset state carries no held record (`Held == nil`, `reset == true`): the plan's `heldPresent` ("a held record, or a file that does not read") must test `st.reset || st.Held != nil`, and read the flag before `loadProbeState`, which clears it after the rewrite.
- Nothing calls `loadProbeState` yet, so a corrupt probe-state.json is not rewritten until Task 3 calls it on a path every locked apply takes (the `heldPresent` point fits); until then such a host reports probe_state_reset and logs a warning at each status write.
- The Run-level wiring of `heldNoise` is still to be proved once applies return ErrProbeHeld: count `Out` calls and log lines in TestRunHeldTrigger's harness.
- forward is at apply.go:840 after Task 2's edits (the plan's anchors moved by about +15 lines): the no-op test, the :876 and :899 branches, allocGeneration and the Transition loop are in that function.
- The test-time base expires 24 h after `at=1794104446`: re-measure it in place (Task 1 Step 0.2) if Task 5 runs later.
- The mutant runner used here: a shell function that applies a perl substitution, requires the file to change, runs the one named test through scripts/linux.sh, and counts only the named `--- FAIL:` line; then `git checkout --` and `git diff --quiet HEAD --`.
- Test-strength note for the review: several TestVerifyCert defects are made by editing a signed certificate, so a removed check is killed by a different code (the signature check still refuses). Building those defects validly with a permissive test profile (extension_present, two_principals, key_id_ca_not_machine, key_id_subject_other_host, force_command_value, source_address_value) would make a removed check show acceptance.
