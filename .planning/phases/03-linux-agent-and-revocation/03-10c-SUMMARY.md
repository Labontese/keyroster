---
phase: 03-linux-agent-and-revocation
plan: 10c
subsystem: agent, ci, docs
tags: [probe-account, shadow, sshd-T, distro-matrix, systemd, runbook, agent-04]
status: in-progress
requires: [03-10b]
requirements-completed: []
---

# Phase 3 Plan 10c: The probe account checked completely Summary

DRAFT (Task 1 in progress). The gate's account step becomes the full check of owner answer Q3 (passwd, shadow where readable, `sshd -T -C` from the probe's own source address); preflight and drift report the same result report only.

Owner answers: Q2 Q3 Q4 Q-B P1 P2 P4 D-R1 planner-defaults Q-S
AGENT-04: open until 03-10d

## Bases

test-time base: apply=452.742 fetch=33.632 heartbeat=1.057 serverclient=4.191 agentcmd=1.924 cmd=233.517 at=1794143318

The test-time base ran on unchanged origin/main cee452a in a detached worktree outside the repository, with no other heavy job, through scripts/linux.sh (go1.27.3 linux/amd64 in WSL), with the one command of 'Budget and verify'; each time is that package's `ok` line.

e2e base: run 42472525055 9.5p1=796.727 10.5p1=795.012 probe9.5p1=304.799 probe10.5p1=311.970
distro base: e2e-distro (debian:13)=143 e2e-distro (debian:12)=156 e2e-distro (ubuntu:26.04)=160 e2e-distro (archlinux)=155 e2e-distro (almalinux:9)=164 e2e-distro (alpine)=149 e2e-distro (ubuntu:24.04)=158
systemd base: run 42472525021 TestAgentSystemdSmoke=339.37

The e2e base is the newest successful e2e.yml run on main (cee452a), each lane's `go test` elapsed time of ./test/e2e as the 03-10b e2e gate reads it. The distro base is the newest successful e2e-distro.yml run on main (42472525098, cee452a), each job's step "Run the distro tests in the image", completedAt minus startedAt. The systemd base is the smoke test's own PASS line in the newest successful systemd.yml run on main.

## Task 1

RED (unit, compile failures): the production code of account.go, exclusion.go, preflight.go, drift.go, probegate.go, apply.go and cmd/keyroster-agent's run.go, preflight.go and check.go was drafted before its tests and moved aside (each file back to origin/main) for this run, as 03-10b did for heartbeat.go; the new tests were then compiled against origin/main's code. internal/agent/apply failed to build with `account_test.go:40:74: undefined: accountResult` (the first of the undefined symbols: accountResult, checkProbeAccountFull, accountKeyInput, ParseShadowLine, ExcludedDefinite, CodeProbeAccount, DriftReport.Probe, Config.openShadow and the new reason constants). cmd/keyroster-agent compiled and `TestProbeFlags` failed for real: `TestProbeFlags/preflight_and_check_accept_probe_account` and `TestProbeFlags/invalid_account_refused_before_any_read` with `flag provided but not defined: -probe-account` (preflight); `preflight_and_check_refuse_probe_self_test` passed already, as it must.

First GREEN runs, failures fixed in the tests: `TestProbeAccountFull/excluded_by_allowgroups` (the fake dump printed two AllowGroups patterns on one line; sshd -T prints one line per entry, which the test now does), `TestPreflightProbeAccount/no_verified_state_still_runs` (the note text). Two existing tests changed, as 'Existing tests this plan changes' foresees:
- `TestProbeGate/failure_backoff_blocks_until_input_changes` (03-10b): its failure record's key now uses accountKeyInput (the passwd line, a NUL byte and the password class) instead of the bare passwd line, so the recorded key still matches the gate's.
- `TestProbeGate/held_retry_repairs_edited_dropin` (03-10b, PR #91 F6): the retry that finds the drop-in edited (RevokedKeys removed) is now held `sshd_override`, because the gate's account check runs before the held retry's repair and sshd -T -C reports the edited drop-in's revokedkeys for the probe account; the same retry still repairs the drop-in, and the test now asserts that the next retry is held `cert_missing` again.
The broad run found two more existing tests that this plan changes, in two files that are NOT in the plan's files_modified (see Deviations and the owner question):
- `TestProbeStatus/every_code_validates` (internal/agent/apply/status_test.go:753) asserted exactly 14 closed hold reasons; it now asserts 18.
- `TestForwardServedCerts/fail_widening_rolls_back_addition_only` and `fail_mixed_widening_keeps_removal` (internal/agent/apply/probe_test.go:738) removed the drop-in before a widening, so that forward rewrites it; with the drop-in gone, sshd -T -C reports none of the agent's trust settings for the probe account and the gate now holds the widening as `sshd_override` before the rewrite. The setup now edits the drop-in (an appended comment) instead, which forward rewrites just the same, so the tests still prove the served-certificate rollback.
No test counts `fakeRunner.dumps` for a gated apply (adopt_test.go:130 and preflight_test.go:101, :323, :343 count with the probes off), so none needed a new count.

Task 1 gates, local (through scripts/linux.sh, go1.27.3 linux/amd64 in WSL):
- verify 1 (the build, `go vet` default, `-tags keyroster_e2e` over the agent packages, `-tags e2e` and `-tags "e2e e2eprobe"` over test/e2e, and the named tests with `-race -v`): exit 0, every named PASS line present, no FAIL, panic or DATA RACE (149 PASS lines).
- verify 2 (`go test -race ./internal/agent/... ./cmd/keyroster-agent/ ./cmd/keyroster/`): the first run failed only in the four existing tests listed above; after their fix internal/agent/apply passed again alone (392.6 s); every other package of the run had passed (fetch 32.9 s, cmd/keyroster 239.8 s). Pass or fail only.
- golangci-lint for linux, windows and darwin: 0 issues after two fixes (staticcheck QF1001 on drift.go's skip condition, rewritten by De Morgan; gosec G306 on the e2e's 0640 shadow fixture, a nolint with its reason); gofmt clean; the e2e lint with `--new-from-rev=origin/main`: 0 issues.
- `scripts/capslock-check.sh`: pass, every baseline unchanged (the shadow open reuses `unix.Open`, already in the agent's baseline); `test/capslock` unchanged.
- FuzzParseShadowLine: the list check found exactly one target; 30 s, about 2 278 000 executions, no crash, no corpus file left under testdata/fuzz.
- The frozen-package gate and the six-file tag gate: pass.

T1 code commit: 85eae61

Local e2e wrapper: the local e2e runs ran in a detached worktree outside the repository at the commit named with each run, with the local OpenSSH builds that scripts/build-openssh.sh made in WSL (10.5p1 and 9.5p1), as `KEYROSTER_OPENSSH_PREFIX=$HOME/.cache/keyroster/openssh-<version> go test -tags "e2e e2eprobe" -run '^TestProbeSelfTestEndToEnd$' -count=1 -timeout 12m -v ./test/e2e/...`, inside the namespace wrapper of 03-10b:
- `unshare -rm` bind-mounts a copy of /etc/hosts with keyroster.localhost on 127.0.0.1;
- a nested `unshare --map-user=<caller uid> --map-group=<caller gid>` maps back to the caller's uid and gid, so the probe account (the test user) is not root.

e2e, first runs (red, at 85eae61): CI run 42486583038 (dispatched by the e2e gate, which then stopped with `run 42486583038 is not for the current HEAD` because the test-only commit 59bd530 had moved HEAD) and the first local 10.5p1 run both failed `TestProbeSelfTestEndToEnd/unusable_account_holds_widening_krl_and_narrowing_land` with `probe_selftest_test.go:709: the addition is held with probe_held:account_excluded: not within 1m30s`, on both CI probe lanes (9.5p1 and 10.5p1) and locally. The chain had shown shell_not_nologin, password_set and sshd_override on real sshd; the cause was the test helper: setSSHDCause put DenyUsers before the first Match line, which was the Match cause's own, inside that cause's comment block, so removing the Match cause removed DenyUsers too (the addition then landed with both probes passing). e18bf1a places it before the cause block. In that run both main lanes passed (9.5p1 745.745 s, 10.5p1 795.867 s, no probe test) and `positive_refused_rolls_back` passed on both probe lanes.

D5 keyword: **PubkeyAcceptedAlgorithms** (`PubkeyAcceptedAlgorithms -ssh-ed25519-cert-v01@openssh.com`, the probe certificates certify Ed25519 keys) makes sshd refuse the positive before PK_OK on 9.5p1 and 10.5p1: `positive_refused_rolls_back` passed with it in CI runs 42486583038, 42487971088, 42489177786 and every local 10.5p1 run. CASignatureAlgorithms was not needed.

e2e green run (Task 1 gate, `MODE=green`, PROBE_PASS of verify 7): **42487971088** at e18bf1a, gate exit 0. Main lanes 9.5p1 763.833 s (base 796.727) and 10.5p1 786.024 s (base 795.012), both under 900 s with no probe test; probe lanes 9.5p1 280.814 s (base 304.799) and 10.5p1 282.710 s (base 311.970), under the 420 s cap, every PROBE_PASS test passed in both (`positive_refused_rolls_back` 100.3 s and 106.8 s, `TestProbePairSpacing` 120.2 s and 124.3 s). The probe lanes are about 25 s faster than the base: the hold chain takes about 22 s and `fixing_the_account_lands_the_held_addition` about 34 s locally, where 03-10b's single hold waited longer for its retry.

Flake stress (D6), at e18bf1a, every outcome of `positive_refused_rolls_back`:
- local 10.5p1 through the wrapper: run 2 PASS (105.7 s, the green run above), runs 3, 4 and 5 PASS (107.9 s, 106.5 s, 105.7 s; TestProbeSelfTestEndToEnd 255.2 s, 257.7 s, 254.7 s);
- CI e2e.yml dispatches on the branch: 42487971088 PASS on both probe lanes, 42489177786 PASS on both probe lanes (probe lanes 279.742 s and 274.627 s), 42490370515 PASS on both probe lanes (probe lanes 291.266 s and 286.734 s).
No run showed `probe_held:budget`. Earlier data points: CI 42486583038 and local run 1 at 85eae61 passed `positive_refused_rolls_back` too (they failed later, in the hold chain). Five green runs lower the odds of the old race and prove nothing about the next (Edge Coverage).

e2e mutants (locally through the wrapper, each in the e2e worktree, applied, run alone on `^TestProbeSelfTestEndToEnd$`, restored with `git checkout --` and proven by `git diff --quiet HEAD --` in that worktree; the 9.5p1 build exists in WSL, so both versions ran):
mutant killed: e2e, the sshd -T -C stage removed from the check, on 10.5p1 (TestProbeSelfTestEndToEnd/unusable_account_holds_widening_krl_and_narrowing_land: `probe_selftest_test.go:714: the addition is held with probe_held:sshd_override: not within 1m30s`)
mutant killed: e2e, the shadow stage removed from the check, on 10.5p1 (TestProbeSelfTestEndToEnd/unusable_account_holds_widening_krl_and_narrowing_land: `probe_selftest_test.go:714: the addition is held with probe_held:password_set: not within 1m30s`)
The same two mutants on 9.5p1 were killed by the same subtest with the same lines (sshd_override, then password_set); they are the same two mutants and are not counted twice.

Unit mutants (each applied to the committed code, run alone on its named subtest with `-timeout 5m` through scripts/linux.sh, killed by the named `--- FAIL:` line, restored with `git checkout --` and proven by `git diff --quiet HEAD --`; a timeout or `[build failed]` would not count):

mutant killed: the password_set stage removed (TestProbeAccountFull/password_set)
mutant killed: an empty field accepted (TestProbeAccountFull/password_empty)
mutant killed: a ! field treated as a password (TestProbeAccountFull/password_locked_ok)
mutant killed: the shadow file opened without O_NOFOLLOW (TestProbeAccountFull/shadow_symlink_is_unreadable_note)
mutant killed: the shadow file opened without O_NONBLOCK (TestProbeAccountFull/shadow_fifo_fails_closed)
mutant killed: an oversize shadow file classed unreadable (TestProbeAccountFull/shadow_oversize_fails_closed)
mutant killed: a second shadow line ignored instead of the worst winning (TestProbeAccountFull/shadow_duplicate_worst_wins)
mutant killed: passwd field 2 not read (TestProbeAccountFull/passwd_field2_hash_holds)
mutant killed: the worst class not taken: the shadow class replaces passwd field 2's (TestProbeAccountFull/passwd_hash_with_shadow_star_holds)
mutant killed: ENOENT classed unreadable (TestProbeAccountFull/shadow_absent_x_is_no_password)
mutant killed: shadow read only when passwd field 2 is x (TestProbeAccountFull/passwd_star_with_shadow_hash_holds)
mutant killed: any other open error classed unreadable instead of unparsable (TestProbeAccountFull/shadow_other_open_error_fails_closed)
mutant killed: the trust comparison run before install (TestProbeAccountFull/trust_trio_not_compared_before_install)
mutant killed: the listener chosen without the ipv6Off rule (TestProbeAccountFull/spec_uses_probe_source_ipv6_off)
mutant killed: the no-loopback error propagated out of preflight (TestPreflightProbeAccount/no_loopback_listener_no_finding_no_error)
mutant killed: an unreadable shadow treated as no password, so permitemptypasswords yes passes (TestProbeAccountFull/permitemptypasswords_yes_with_unreadable_shadow)
mutant killed: the spec built with addr 127.0.0.1 (TestProbeAccountFull/spec_uses_probe_source; on its first run it was NOT killed, because probeSpecKey built the expected spec with probeAccountSpec itself; 59bd530 spells the spec out and the re-run killed it)
mutant killed: the pubkeyauthentication check removed (TestProbeAccountFull/sshd_override_pubkey_no)
mutant killed: the authenticationmethods check removed (TestProbeAccountFull/sshd_override_authenticationmethods)
mutant killed: the trust comparison removed (TestProbeAccountFull/sshd_override_trust_trio)
mutant killed: the principals command check removed (TestProbeAccountFull/sshd_override_principals_command)
mutant killed: the usepam rule removed (TestProbeAccountFull/usepam_no_with_bang)
mutant killed: the absent usepam keyword read as yes (TestProbeAccountFull/usepam_absent_is_no_pam)
mutant killed: a failing sshd -T -C treated as a pass (TestProbeAccountFull/sshd_failure_holds_override)
mutant killed: AllowUsers ignored (TestProbeAccountFull/excluded_by_allowusers)
mutant killed: a user@host entry treated as an exclusion (TestProbeAccountFull/excluded_user_at_host_does_not_hold)
mutant killed: definite taken from the first hit only (TestExcludedDefinite/definite_after_user_at_host)
mutant killed: the sshd stage run before the shadow stage (TestProbeAccountFull/order_passwd_then_shadow_then_sshd)
mutant killed: the failure key built from the passwd line alone (TestProbeGate/account_key_changes_with_shadow_class)
mutant killed: the key input built from the raw field (TestProbeAccountFull/key_input_has_class_not_hash)
mutant killed: the raw field written into probe-state.json (the hold reason carries the raw passwd line) (TestProbeGate/hash_never_in_state_or_log)
mutant killed: the raw field written into a Finding (preflight and drift: the raw passwd line appended to the Fix) (TestPreflightProbeAccount/hash_never_in_report, TestDriftProbeAccount/hash_never_in_report)
mutant killed: the probe-account finding left out of ReportOnly (TestPreflightProbeAccount/reports_each_reason_report_only)
mutant killed: preflightApply refusing on the finding (the probe account evaluated there and its findings marked refusals) (TestPreflightProbeAccount/apply_not_refused)
mutant killed: the drift finding counted by Drift() (TestDriftProbeAccount/finding_is_not_drift)
mutant killed: the generic drift loop not skipping the probe account's Excluded append (TestDriftProbeAccount/generic_excluded_not_duplicated)
mutant killed: the generic drift loop skipping the probe account entirely (TestDriftProbeAccount/probe_trust_override_still_drifts)
mutant killed: a narrowing change held by the account check (narrowing sent through the gate, whose first step is the account check) (TestProbeGate/narrowing_with_password_set_lands_not_held)
mutant killed: the gate path calling the check for an exempt class (TestProbeGate/gate_path_runs_no_account_check_for_exempt_and_narrowing)
mutant killed: preflight and check not registering the flag (preflight's registered on a throwaway flag set) (TestProbeFlags/preflight_and_check_accept_probe_account)

The failure line of each (the first message under its `--- FAIL:` line, cut at 230 characters):

17 (re-run at 59bd530) the spec built with addr 127.0.0.1 :: killed by --- FAIL: TestProbeAccountFull/spec_uses_probe_source: account_test.go:402: sshd -T -C runs map[user=keyroster-probe,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport=37803:1], want one for the pro
```
01 the password_set stage removed :: killed by --- FAIL: TestProbeAccountFull/password_set: account_test.go:118: reason "", want "password_set" (class "hash", notes [])
02 an empty field accepted :: killed by --- FAIL: TestProbeAccountFull/password_empty: account_test.go:112: reason "", want "password_empty" (class "empty", notes [])
03 a ! field treated as a password :: killed by --- FAIL: TestProbeAccountFull/password_locked_ok: account_test.go:127: reason "password_set", want "" (class "hash", notes [])
04 the shadow file opened without O_NOFOLLOW :: killed by --- FAIL: TestProbeAccountFull/shadow_symlink_is_unreadable_note: account_test.go:151: reason "password_set", want "" (class "hash", notes [])
05 the shadow file opened without O_NONBLOCK :: killed by --- FAIL: TestProbeAccountFull/shadow_fifo_fails_closed: account_test.go:184: the check blocked on a FIFO at /tmp/TestProbeAccountFullshadow_fifo_fails_closed1035956878/001
06 an oversize shadow file classed unreadable :: killed by --- FAIL: TestProbeAccountFull/shadow_oversize_fails_closed: account_test.go:160: reason "", want "account_unparsable" (class "unreadable", notes [])
07 a second shadow line ignored instead of the worst winning :: killed by --- FAIL: TestProbeAccountFull/shadow_duplicate_worst_wins: account_test.go:197: reason "", want "password_set" (class "star", notes [])
08 passwd field 2 not read :: killed by --- FAIL: TestProbeAccountFull/passwd_field2_hash_holds: account_test.go:246: reason "", want "password_set" (class "absent", notes [])
09 the worst class not taken: the shadow class replaces passwd field 2's :: killed by --- FAIL: TestProbeAccountFull/passwd_hash_with_shadow_star_holds: account_test.go:231: reason "", want "password_set" (class "star", notes [])
10 ENOENT classed unreadable :: killed by --- FAIL: TestProbeAccountFull/shadow_absent_x_is_no_password: account_test.go:204: reason "sshd_override", want "" (class "unreadable", notes [probe_shadow_unreadable])
11 shadow read only when passwd field 2 is x :: killed by --- FAIL: TestProbeAccountFull/passwd_star_with_shadow_hash_holds: account_test.go:224: reason "", want "password_set" (class "star", notes [])
12 any other open error classed unreadable instead of unparsable :: killed by --- FAIL: TestProbeAccountFull/shadow_other_open_error_fails_closed: account_test.go:212: reason "", want "account_unparsable" (class "unreadable", note
13 the trust comparison run before install :: killed by --- FAIL: TestProbeAccountFull/trust_trio_not_compared_before_install: account_test.go:421: reason "sshd_override", want "" (class "absent", notes [])
14 the listener chosen without the ipv6Off rule :: killed by --- FAIL: TestProbeAccountFull/spec_uses_probe_source_ipv6_off: account_test.go:414: sshd -T -C runs map[user=keyroster-probe,host=::1,addr=::1,laddr=::1,lport=45101:1],
15 the no-loopback error propagated out of preflight :: killed by --- FAIL: TestPreflightProbeAccount/no_loopback_listener_no_finding_no_error: preflight_test.go:592: preflight: no_loopback_listener: sshd listens on no loopback-re
16 an unreadable shadow treated as no password, so permitemptypasswords yes passes :: killed by --- FAIL: TestProbeAccountFull/permitemptypasswords_yes_with_unreadable_shadow: account_test.go:273: reason "", want "sshd_override" (
17 the spec built with addr 127.0.0.1 :: NOT KILLED TestProbeAccountFull/spec_uses_probe_source:
18 the pubkeyauthentication check removed :: killed by --- FAIL: TestProbeAccountFull/sshd_override_pubkey_no: account_test.go:288: reason "", want "sshd_override" (class "absent", notes [])
19 the authenticationmethods check removed :: killed by --- FAIL: TestProbeAccountFull/sshd_override_authenticationmethods: account_test.go:310: authenticationmethods "password": reason "", want "sshd_override"
20 the trust comparison removed :: killed by --- FAIL: TestProbeAccountFull/sshd_override_trust_trio: account_test.go:320: reason "", want "sshd_override" (class "absent", notes [])
21 the principals command check removed :: killed by --- FAIL: TestProbeAccountFull/sshd_override_principals_command: account_test.go:327: reason "", want "sshd_override" (class "absent", notes [])
22 the usepam rule removed :: killed by --- FAIL: TestProbeAccountFull/usepam_no_with_bang: account_test.go:334: reason "", want "sshd_override" (class "locked", notes [])
23 the absent usepam keyword read as yes :: killed by --- FAIL: TestProbeAccountFull/usepam_absent_is_no_pam: account_test.go:354: reason "", want "sshd_override" (class "locked", notes [])
24 a failing sshd -T -C treated as a pass :: killed by --- FAIL: TestProbeAccountFull/sshd_failure_holds_override: account_test.go:359: reason "", want "sshd_override" (class "absent", notes [])
25 AllowUsers ignored :: killed by --- FAIL: TestProbeAccountFull/excluded_by_allowusers: account_test.go:368: reason "", want "account_excluded" (class "absent", notes [])
26 a user@host entry treated as an exclusion :: killed by --- FAIL: TestProbeAccountFull/excluded_user_at_host_does_not_hold: account_test.go:391: reason "account_excluded", want "" (class "absent", notes [])
27 definite taken from the first hit only :: killed by --- FAIL: TestExcludedDefinite/definite_after_user_at_host: preflight_test.go:502: "denyusers deploy@remote.example\ndenyusers dep*\n": ("DenyUsers deploy@remote.example refus
28 the sshd stage run before the shadow stage :: killed by --- FAIL: TestProbeAccountFull/order_passwd_then_shadow_then_sshd: account_test.go:434: reason "sshd_override", want "password_set" (class "hash", notes [])
29 the failure key built from the passwd line alone :: killed by --- FAIL: TestProbeGate/account_key_changes_with_shadow_class: probegate_test.go:1241: apply: probe_held: failure_backoff (report &{BundleVersion:1 DirectoryVersion:
30 the key input built from the raw field :: killed by --- FAIL: TestProbeAccountFull/key_input_has_class_not_hash: account_test.go:457: key input "keyroster-probe:$6$Zq9MarkerSalt$Zq9MarkerHashValue:990:990::/nonexistent:/usr/sbi
31 the raw field written into probe-state.json (the hold reason carries the raw passwd line) :: killed by --- FAIL: TestProbeGate/hash_never_in_state_or_log: probegate_test.go:1336: want held password_set: err probe-state.json: he
32 the raw field written into a Finding (preflight and drift: the raw passwd line appended to the Fix) :: killed by --- FAIL: TestPreflightProbeAccount/hash_never_in_report: preflight_test.go:660: the report carries the hash (in p
33 the probe-account finding left out of ReportOnly :: killed by --- FAIL: TestPreflightProbeAccount/reports_each_reason_report_only: preflight_test.go:566: account_missing: probe findings [{Code:probe_account Refusal:true Message
34 preflightApply refusing on the finding (the probe account evaluated there and its findings marked refusals) :: killed by --- FAIL: TestPreflightProbeAccount/apply_not_refused: preflight_test.go:672: the first apply with a broke
35 the drift finding counted by Drift() :: killed by --- FAIL: TestDriftProbeAccount/finding_is_not_drift: drift_test.go:198: a probe account with a password: &{Generation:1 Settings:[] Files:[] Excluded:[] Probe:[{Code:probe_acco
36 the generic drift loop not skipping the probe account's Excluded append :: killed by --- FAIL: TestDriftProbeAccount/generic_excluded_not_duplicated: drift_test.go:213: the probe account is in Excluded too: [{Code:account_exclu
37 the generic drift loop skipping the probe account entirely :: killed by --- FAIL: TestDriftProbeAccount/probe_trust_override_still_drifts: drift_test.go:224: a Match block overriding the probe account's principals file: &{Gener
38 a narrowing change held by the account check (narrowing sent through the gate, whose first step is the account check) :: killed by --- FAIL: TestProbeGate/narrowing_with_password_set_lands_not_held: probegate_test.go:1308: appl
39 the gate path calling the check for an exempt class :: killed by --- FAIL: TestProbeGate/gate_path_runs_no_account_check_for_exempt_and_narrowing: probegate_test.go:1299: first_install: 1 probe-account runs before the commit, 1
40 preflight and check not registering the flag (preflight's registered on a throwaway flag set) :: killed by --- FAIL: TestProbeFlags/preflight_and_check_accept_probe_account: probeoff_test.go:58: preflight --probe-account probe1
```

T1: 80b0180 (code at 85eae61; 59bd530 spells out the spec the tests expect, e18bf1a fixes the e2e helper, 80b0180 builds the IPv4 wildcard address of `spec_uses_probe_source_ipv6_off` at run time so that no added line names an address outside loopback, the plan's scrub gate. `git diff --name-only e18bf1a..80b0180` is internal/agent/apply/account_test.go only. The green run, the stress runs and the e2e mutants ran at e18bf1a, the unit mutants at 85eae61, mutant 17's re-run at 59bd530, and mutant 14 was re-run at 80b0180 and killed again: `account_test.go:419: sshd -T -C runs map[user=keyroster-probe,host=::1,addr=::1,...]`)

## Deviations from Plan (Task 1)

1. **RED by moving the drafted code aside.** The production code was drafted before its tests; RED was taken by putting every changed production file back to origin/main and compiling the new tests (above), as 03-10b did for heartbeat.go.
2. **accountKeyInput is an engine method,** `e.accountKeyInput(account)`, not `accountKeyInput(root, account)`: it must use the shadow open seam (`Config.openShadow`) that the full check uses, so that a test's EACCES reaches both.
3. **The key's class is the worst of both sources.** Step 2 says the key input carries "passwd field 2 when it is not `x`, else the shadow class"; the frozen contract ('Password classes', Fix round 2) says both sources are combined and the worst wins, and `passwd_star_with_shadow_hash_holds` needs that. accountKeyInput calls the same passwordClass as the gate, so `failure_backoff` matches its own record.
4. **The key's passwd line has field 2 replaced by its class** (`keyLine`; `x` is kept). `key_input_has_class_not_hash` requires that a hash in passwd field 2 never enters the key input, and the raw line would carry it. checkProbeAccount's returned line is unchanged (03-10b's TestProbeAccount compares it).
5. **`unparsable` ranks highest** of the classes (above hash), so a shadow file the agent cannot read safely always fails closed as account_unparsable whatever passwd field 2 says. The contract names the order hash, empty, locked, star and puts absent and unreadable below star; it does not rank unparsable.
6. **`TestProbeGate/account_key_changes_with_shadow_class` uses locked then star**, not hash: a hash holds `password_set` before the back-off is reached, so a failure recorded under `hash` cannot back off. The test records the failure under `locked` (with `usepam yes`) and shows the immediate retry after the field becomes `*`.
7. **`TestProbeGate/held_retry_runs_account_check_each_round` holds `cert_missing`**: a `password_set` hold stops before the sshd stage and runs no `sshd -T -C`, so the test uses a healthy account without a pair, where every held round runs the whole account check (one probe-account `sshd -T -C` a round).
8. **Some mutants are insertions,** not edits of a line: preflightApply refusing on the finding (the probe account evaluated inside preflightApply and its findings marked refusals), the raw field written into probe-state.json (the hold reason extended with the raw passwd line) and into a Finding (the raw passwd line appended to the Fix in preflight and drift), the gate path calling the check for an exempt class (a call added before the gate block), and the generic drift loop skipping the probe account (a `continue` added). Each changes behaviour and was killed by its named subtest.
9. **Behaviour change for the pre-merge review** (03-10d reconciles these lines): a widening on a host whose drop-in is edited or missing at the start of the run is now held for one round as `sshd_override`, because the gate's account check compares sshd -T -C's trust settings for the probe account with the agent's before that run repairs the drop-in; the narrowing part and the repaired drop-in land in that run, and the next round passes. `held_retry_repairs_edited_dropin` asserts this; the two served-certificate tests now edit the drop-in instead of removing it (both cases are the same behaviour).
10. **Two files outside files_modified.** internal/agent/apply/status_test.go and internal/agent/apply/probe_test.go needed the edits listed under Task 1 (an existing count of 14 hold reasons; a setup that removed the drop-in). The plan says "a file needed by a fix is added to files_modified first", but the plan file is to be committed byte-identical, so files_modified was NOT edited: Task 4's files gate (`git diff --name-only origin/main...HEAD` against files_modified) will exit 1 on this branch as it stands. Owner question below.
11. **The e2e mutants and stress runs on 9.5p1:** the 9.5p1 build exists in WSL (scripts/build-openssh.sh), so the two e2e mutants ran on both versions.

## Owner questions

- **files_modified (blocks Task 4's files gate only).** The branch changes internal/agent/apply/status_test.go and internal/agent/apply/probe_test.go, which the plan's files_modified does not list (Deviation 10). Either the plan's files_modified gains these two entries when it is committed (then it is no longer byte-identical to the checked plan), or Task 4's files gate is run with them allowed as a recorded exception. Which?

## Resume point

- Branch p03/10c-probe-account, pushed. Task 1 is complete: T1 80b0180 (e2e evidence at e18bf1a), this SUMMARY committed after it (docs only). Tasks 2, 3 and 4 are not started.
- Commits: 85eae61 (the full check, preflight, drift, flags, the e2e), 59bd530 (test: the spec the tests expect, spelled out), e18bf1a (test(e2e): the DenyUsers cause outside the Match cause block), 80b0180 (test: the IPv4 wildcard built at run time), then the docs commit of this SUMMARY.
- The plan files 03-10c-PLAN.md and 03-10d-PLAN.md lie untracked in the phase directory, byte-identical to the checked plans; Task 4 commits them.
- Next: Task 2 (the distro matrix). Its precondition holds: Task 1's verify passed (unit gate, and the e2e gate green in 42487971088) and the SUMMARY records T1 and the `distro base:` line.
- Facts for Task 2: Docker is NOT available in WSL, so the matrix and its mutants run only in CI (`workflow_dispatch` on the branch, throwaway branches for the mutants, deleted afterwards). e2e-distro.yml and systemd.yml run on `pull_request` and `workflow_dispatch` (no PR is open yet). The distro tests call `keyroster-agent check` (distro_test.go:397, :404, :421, :436, :447; refusals_test.go:245) and require exit 0 or 3 only: the new `probe` field of the check report is report only and does not change the exit (no distro test decodes the check JSON strictly). The two preflight finding counts of refusals_test.go (:149-151, :213) need `withoutProbeAccount` before any distro run (Task 2, as planned): the images have no probe account, so preflight now reports `probe_account` with `account_missing`.
- The test-time base was measured at at=1794143318; it expires at 1794229718, after which Task 4 re-measures it in place in the detached worktree outside the repository at origin/main (the same one is still checked out for that).
- The plan's commit ledger (gsd-plan-head-before-03-10c in the git directory) holds cee452a.
- Owner question open: files_modified (Deviation 10); it blocks only Task 4's files gate.
