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

## UNVERIFIED

- Local e2e: not run (the namespace wrapper of 03-10 was not used); the e2e results are CI only.
- `systemd-sandbox` with this branch's KRL activity (a first probe pair publishes a negative): no PR run yet.
- Every Edge Coverage item of the plan; and everything of Tasks 3 to 5.
- Task 2 at the e2e level: no e2e run has carried Task 2 yet (the next e2e run is Task 4's); every e2e host now reports `probe_self_test_off` in last_apply.detail and probe_detail and shows a `probe:` alert, which no e2e assertion reads (checked by grep of test/e2e, test/distro and test/systemd).

## Resume point (for the continuation)

- Next: Task 3 (the decision: classify, account.go, probeGate, the hold wiring in forward). Task 2 is done and pushed (T2 fdfb08c). probegate.go already holds the error values, the closed hold reasons, probeState with its reader (`readProbeState`, read-only), `loadProbeState` (rewrites a reset once, locked engines only) and `writeProbeState` (refuses without `e.locked`); `WriteStatus`'s engine takes apply.lock but never sets `e.locked`, so only the engines of Apply (apply.go:435), HostCerts (hostcert.go:151) and ProbeCerts (probe.go:235), which set it, can write.
- Task 2's verify block 1 was re-run verbatim at fdfb08c (build, `go vet ./...`, the tagged vet, the named tests with `-race` and the PASS loop: all pass), with the final TestRunHeldNoise table.
- The reset state carries no held record (`Held == nil`, `reset == true`): the plan's `heldPresent` ("a held record, or a file that does not read") must test `st.reset || st.Held != nil`, and read the flag before `loadProbeState`, which clears it after the rewrite.
- Nothing calls `loadProbeState` yet, so a corrupt probe-state.json is not rewritten until Task 3 calls it on a path every locked apply takes (the `heldPresent` point fits); until then such a host reports probe_state_reset and logs a warning at each status write.
- The Run-level wiring of `heldNoise` is still to be proved once applies return ErrProbeHeld: count `Out` calls and log lines in TestRunHeldTrigger's harness.
- forward is at apply.go:840 after Task 2's edits (the plan's anchors moved by about +15 lines): the no-op test, the :876 and :899 branches, allocGeneration and the Transition loop are in that function.
- The test-time base expires 24 h after `at=1794104446`: re-measure it in place (Task 1 Step 0.2) if Task 5 runs later.
- The mutant runner used here: a shell function that applies a perl substitution, requires the file to change, runs the one named test through scripts/linux.sh, and counts only the named `--- FAIL:` line; then `git checkout --` and `git diff --quiet HEAD --`.
- Test-strength note for the review: several TestVerifyCert defects are made by editing a signed certificate, so a removed check is killed by a different code (the signature check still refuses). Building those defects validly with a permissive test profile (extension_present, two_principals, key_id_ca_not_machine, key_id_subject_other_host, force_command_value, source_address_value) would make a removed check show acceptance.
