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

- Resolved (Task 2 executor, 2026-11-08): the orchestrator added internal/agent/apply/status_test.go and internal/agent/apply/probe_test.go to the plan's files_modified (now 40 entries) after Task 1, so the question below no longer blocks Task 4's files gate; it is kept as Task 1 recorded it.

- **files_modified (blocks Task 4's files gate only).** The branch changes internal/agent/apply/status_test.go and internal/agent/apply/probe_test.go, which the plan's files_modified does not list (Deviation 10). Either the plan's files_modified gains these two entries when it is committed (then it is no longer byte-identical to the checked plan), or Task 4's files gate is run with them allowed as a recorded exception. Which?

## Task 2

Docker is not available on this workstation (neither in WSL nor on the Windows side), so the matrix and its mutants ran only in CI, through `workflow_dispatch` of e2e-distro.yml on the pushed branch and on throwaway branches (deleted afterwards). shellcheck is not installed locally and no workflow of the repository runs it: `sh -n` (and `dash -n`) of probe-account.sh and run-in.sh and `bash -n` of run.sh passed; shellcheck was NOT run (UNVERIFIED).

RED (CI run 42493109956 at f8b71c3, the tests, the refusals_test.go edit and the run-in.sh exports committed, no probe-account.sh and no copy in run.sh): on all seven images TestDistroProbe, TestDistroProbeAccountBang and TestDistroProbeFacts failed and every other test passed (TestDistroRefusals and TestDistroAdoptPhase2 included, so withoutProbeAccount holds). The literal line per shell: dash (debian:12, debian:13, ubuntu:24.04, ubuntu:26.04) `sh: 0: cannot open /k/probe-account.sh: No such file`; bash as sh (almalinux:9, archlinux) `sh: /k/probe-account.sh: No such file or directory`; busybox (alpine) `sh: can't open '/k/probe-account.sh': No such file or directory`.

First green attempt (CI run 42493591029 at 0c07596): six images passed; archlinux failed every query cell with `probe_test.go:218: /etc/ssh/ssh_host_mldsa44_ed25519_key.pub: ssh: no key found` (archlinux's OpenSSH 10.6p1 writes an ML-DSA hybrid host key that x/crypto/ssh cannot parse or negotiate). 0343fa8 skips such keys (and drops the trailing comma of the version in the FACT line).

distro run: 42494372799

The dispatch gate (Task 2 verify 3) passed on run 42494372799, head 0343fa8 (headSha checked against HEAD): seven jobs, each `success`, each with `--- PASS:` of TestDistroProbe, TestDistroProbeAccountBang and TestDistroProbeFacts and a `FACT probe image=` line. Verify 1 (vet and lint of the tagged package, gofmt, the script syntax) and verify 2 (detect_test.go, world_test.go and e2e-distro.yml unchanged; the tag in its six files) exit 0.

Per-image time of the step "Run the distro tests in the image" (completedAt minus startedAt) against `distro base:`; the cap is +480 s on an image whose FACT shows persourcepenalties=yes, +180 s on the others:
- e2e-distro (alpine) 332 (base 149, +183, cap +480)
- e2e-distro (almalinux:9) 378 (base 164, +214, cap +480)
- e2e-distro (ubuntu:26.04) 368 (base 160, +208, cap +480)
- e2e-distro (debian:12) 227 (base 156, +71, cap +180)
- e2e-distro (archlinux) 369 (base 155, +214, cap +480)
- e2e-distro (debian:13) 364 (base 143, +221, cap +480)
- e2e-distro (ubuntu:24.04) 228 (base 158, +70, cap +180)
TestDistroProbeFacts takes about 136 s on a penalty image (two 60 s spacings) and 5 s on the others; TestDistroProbe about 53 s (32 s on alpine, one variant); TestDistroProbeAccountBang 21 s (11 s on alpine, one column).

FACT lines (run 42494372799, verbatim):
FACT probe image=alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a sshd=OpenSSH_10.3p1 persourcepenalties=yes persourcenetblocksize=32:128 usepam=absent shadow_mode=0640 casignaturealgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256 control_dropped_after=5 mechanism=exercised spacing=60s,pairs=3,dropped=none
FACT probe image=almalinux@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16 sshd=OpenSSH_9.9p1 persourcepenalties=yes persourcenetblocksize=32:128 usepam=yes shadow_mode=0000 casignaturealgorithms=ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-256,rsa-sha2-512 control_dropped_after=5 mechanism=exercised spacing=60s,pairs=3,dropped=none
FACT probe image=ubuntu@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 sshd=OpenSSH_10.2p1 persourcepenalties=yes persourcenetblocksize=32:128 usepam=yes shadow_mode=0640 casignaturealgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256 control_dropped_after=5 mechanism=exercised spacing=60s,pairs=3,dropped=none
FACT probe image=debian@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 sshd=OpenSSH_9.2 persourcepenalties=no persourcenetblocksize=32:128 usepam=yes shadow_mode=0640 casignaturealgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256 control_dropped_after=none mechanism=not_exercised spacing=not_exercised
FACT probe image=archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0 sshd=OpenSSH_10.6p1 persourcepenalties=yes persourcenetblocksize=32:128 usepam=yes shadow_mode=0600 casignaturealgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256 control_dropped_after=5 mechanism=exercised spacing=60s,pairs=3,dropped=none
FACT probe image=debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308 sshd=OpenSSH_10.0p2 persourcepenalties=yes persourcenetblocksize=32:128 usepam=yes shadow_mode=0640 casignaturealgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256 control_dropped_after=5 mechanism=exercised spacing=60s,pairs=3,dropped=none
FACT probe image=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac sshd=OpenSSH_9.6p1 persourcepenalties=no persourcenetblocksize=32:128 usepam=yes shadow_mode=0640 casignaturealgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256 control_dropped_after=none mechanism=not_exercised spacing=not_exercised

The `!` cells (run 42494372799, verbatim):
FACT probe_bang image=alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a usepam=no field=star outcome=accepted
FACT probe_bang image=alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a usepam=no field=bang outcome=refused
FACT probe_bang image=almalinux@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16 usepam=yes field=star outcome=accepted
FACT probe_bang image=almalinux@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16 usepam=yes field=bang outcome=accepted
FACT probe_bang image=almalinux@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16 usepam=no field=star outcome=accepted
FACT probe_bang image=almalinux@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16 usepam=no field=bang outcome=refused
FACT probe_bang image=ubuntu@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 usepam=yes field=star outcome=accepted
FACT probe_bang image=ubuntu@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 usepam=yes field=bang outcome=accepted
FACT probe_bang image=ubuntu@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 usepam=no field=star outcome=accepted
FACT probe_bang image=ubuntu@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944 usepam=no field=bang outcome=refused
FACT probe_bang image=debian@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 usepam=yes field=star outcome=accepted
FACT probe_bang image=debian@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 usepam=yes field=bang outcome=accepted
FACT probe_bang image=debian@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 usepam=no field=star outcome=accepted
FACT probe_bang image=debian@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61 usepam=no field=bang outcome=refused
FACT probe_bang image=archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0 usepam=yes field=star outcome=accepted
FACT probe_bang image=archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0 usepam=yes field=bang outcome=accepted
FACT probe_bang image=archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0 usepam=no field=star outcome=accepted
FACT probe_bang image=archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0 usepam=no field=bang outcome=refused
FACT probe_bang image=debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308 usepam=yes field=star outcome=accepted
FACT probe_bang image=debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308 usepam=yes field=bang outcome=accepted
FACT probe_bang image=debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308 usepam=no field=star outcome=accepted
FACT probe_bang image=debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308 usepam=no field=bang outcome=refused
FACT probe_bang image=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac usepam=yes field=star outcome=accepted
FACT probe_bang image=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac usepam=yes field=bang outcome=accepted
FACT probe_bang image=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac usepam=no field=star outcome=accepted
FACT probe_bang image=ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac usepam=no field=bang outcome=refused

Matrix facts:
- Five images have PerSourcePenalties, not four: almalinux:9 ships OpenSSH 9.9p1. On each the control from 127.0.0.3 was dropped after 5 refused queries (mechanism exercised), and the three pairs at the production spacing were never dropped, with the listener handshake from 127.0.0.1 answered each time.
- `usepam`: sshd -T prints `usepam yes` on the six PAM images and no usepam line at all on alpine (a build without PAM): the fact that Reconcile row 7 left UNVERIFIED. On alpine `TestDistroProbe/usepam_no` was skipped as a duplicate (the packaged variant is the no-PAM case) and TestDistroProbeAccountBang ran the no-PAM column only.
- D4's premise holds on all seven: a `!` field under UsePAM no is refused at the unsigned query; under UsePAM yes it is accepted on all six PAM images (a fact only). `*` is accepted in every cell.
- The shadow file's mode: 0640 on debian, ubuntu and alpine, 0600 on archlinux, 0000 on almalinux:9 (root reads it in each; a capability-less root on mode 0000 stays UNVERIFIED, 03-16).
- The positive probe certificate's login runs no command on every image: with the nologin shell the output is `Could not chdir to home directory /nonexistent: No such file or directory` followed by nologin's message (`This account is currently not available.`, or `This account is not available` on alpine) or by nothing, exit status 1; with /bin/sh the force-command /bin/false gives exit status 1 and no `uid=`.

Task 2 mutants (each on its own throwaway branch from 0343fa8, with run-in.sh narrowed to the named test or subtest by `-test.run`, which is harness, not product; each branch pushed, dispatched, its target job read, then deleted on origin and locally; the worktree removed; `git diff --quiet HEAD -- test/distro` on this branch afterwards):
mutant killed: the alpine arm leaving the field `!` (TestDistroProbe/usepam_packaged/shadow_line, alpine, run 42494507952 at bf801a1: `probe_test.go:155: the shadow line has 9 fields and the field is "locked", want probe1:*: and the aging fields`)
mutant killed: the KRL not written (TestDistroProbe/usepam_packaged/positive_accepted_negative_refused, debian:12, run 42494511072 at 735a8c9: `probe_test.go:222: the negative, serial 1002 in the KRL, from 127.0.0.2: accepted (<nil>), want refused`)
mutant killed: the minted certificate without its force-command (TestDistroProbe/usepam_packaged/positive_has_no_session/sh_shell, debian:12, run 42494513455 at 22706e1: `probe_test.go:235: the requested command ran: exit status 0, output "Could not chdir to home directory /nonexistent: No such file or directory uid=999(probe1) gid=999(probe1) groups=999(probe1)"`, newlines shown as spaces)
mutant killed: ProbePairSpacing replaced by 2 s in the spacing loop of TestDistroProbeFacts (TestDistroProbeFacts/pairs_at_production_spacing_never_dropped, debian:13, run 42494516329 at 1529b06: `probe_test.go:395: at the production spacing: [pair 3 positive: inconclusive (ssh: handshake failed: read tcp 127.0.0.2:48437->127.0.0.1:22: read: connection reset by peer) pair 3 negative: inconclusive (...)]`; the other penalty images failed the same way, debian:12 and ubuntu:24.04 passed, having no PerSourcePenalties)
mutant killed: the `!` cell asserted accepted instead of refused (TestDistroProbeAccountBang/usepam_no/bang, debian:12, run 42494518893 at de49a9e: `--- FAIL: TestDistroProbeAccountBang/usepam_no/bang`, its message `probe_test.go:323: the field ! under UsePAM no: refused (<nil>), want refused: ...` being the unchanged text beside the mutated condition)

T2: 0343fa8 (f8b71c3 the tests, 0c07596 the script and run.sh, 0343fa8 the host-key fix)

### Deviations (Task 2)

1. **The matrix's account name is `probe1`**, passed in KEYROSTER_PROBE_NAME, so that the script's parameter and `--probe-account` are both exercised; the systemd smoke (Task 3) uses the default `keyroster-probe`.
2. **probeHost does each subtest's setup itself** (newHost, enrolment, the script, a probes-on first install), so that each subtest runs alone, as the mutants did; the account databases (/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow) are restored byte for byte at each test's cleanup, since newHost restores only /etc/ssh.
3. **hostKeys skips host keys that x/crypto/ssh cannot parse** (archlinux's ML-DSA hybrid key; first green attempt above).
4. **The FACT line carries `mechanism=` and `spacing=`** beside the frozen fields, and `control_dropped_after` counts the refused queries before the first answer that was not a refusal.

## Task 3

RED (local, through scripts/linux.sh, the tests written before the code, the runbook section and the audit change absent):
- `TestProbeHoldReasonsDocumented` failed with 18 lines, the first `account_test.go:522: docs/runbooks/host-setup.md does not document probe_held:cert_missing`.
- `TestProbeAccountRunbook` failed with `probeaccount_runbook_test.go:84: host-setup.md has no section ## The probe account`.
- `TestAuditVerifyProbeLine/line_counts_probe_certificates_and_pending_negatives` failed with `audit_test.go:59: output ["OK: 0 entries, ... log key " "host certificates: 2"], want the probe certificates line after the host certificate line`, and `TestAuditVerifyProbeLine/json_has_pending_negative_probes` with `audit_test.go:77: --json {"ok":true,...,"kinds":{"probe_issue":7},...}, want pending_negative_probes 3`; `no_line_without_probe_entries` and `existing_output_unchanged` passed already, as they must.
The smoke edit cannot run locally (it needs a systemd host as root); `go vet -tags "e2e systemdsmoke" ./test/e2e/` and its lint passed.

Task 3 gates, local (through scripts/linux.sh): verify 1 (build, vet, the smoke's vet, the four tests with `-race -v`, every named PASS line, no FAIL, panic or DATA RACE; TestHostTrustRunbooks still passes with the new section inside its 'Ports to Manual recovery' span) exit 0; verify 2 (golangci-lint for linux, windows and darwin, the smoke's lint with `--new-from-rev=origin/main`: 0 issues each; gofmt clean; `bash -n` of agent-smoke.sh; shellcheck not installed, so not run) exit 0; verify 3 (the test-build tag in no document, workflow, command file or smoke script; no address outside 127.0.0.0/8 in the section) exit 0.

systemd run: 42495385525 at a2492f8 (headSha checked against HEAD), conclusion success, the gate (Task 3 verify 4) exit 0: `--- PASS: TestAgentSystemdSmoke (505.63s)`, `--- PASS: TestAgentSystemdSmoke/revocation_lands (60.79s)` (`the revocation of serial 1794152491738350 landed in 1m0s`), `--- PASS: TestAgentSystemdSmoke/probe_pair_ready (0.00s)` (the pair was committed by then), `--- PASS: TestAgentSystemdSmoke/role_addition_passes_probes (55.07s)` (`the role addition landed with both probes passing in 55s`). The script's probe account step printed `keyroster-probe:x:997:983::/nonexistent:/usr/sbin/nologin` and `keyroster-probe: shadow field class star`.

Smoke time: TestAgentSystemdSmoke 505.63 s against its base 339.37 s (run 42472525021), +166 s, inside the 4 to 6 minutes the plan expected and far below the 35m timeout.

LoginGraceTime 10: applied, inferred from the timing only. The role addition landed 55 s after the directory change, fetch poll included, and LoginGraceTime 120 would have imposed a 150 s widening wait. The script's own `sshd -T` line printed `Missing privilege separation directory: /run/sshd` (the runner's ssh.service is socket-activated and had not run yet), so it shows no value. The unit journal, which would name the wait, is printed only on a failure.

T-03-381: IPAddressAllow=localhost admitted 127.0.0.2 under the real unit (run 42495385525: probe_positive and probe_negative `pass` with an empty detail, the queries from the probe source 127.0.0.2 under keyroster-agent.service)

Task 3 mutants (each applied to the committed code at a2492f8 by C:/Users/labon/kr-10c-logs/run_mutants.py, run alone on its named subtest with `-timeout 5m` through scripts/linux.sh, killed by the named `--- FAIL:` line, restored with `git checkout --` and proven by `git diff --quiet HEAD --`; the tag mutant joins the tag's two parts in the mutation script, so no literal was written to a committed file):
mutant killed: a command line of the debian block edited in host-setup.md (TestProbeAccountRunbook/commands_match_ci: `probeaccount_runbook_test.go:104: the runbook's block probe-account debian: ...`)
mutant killed: an arm of probe-account.sh edited, the arch arm's useradd line (TestProbeAccountRunbook/commands_match_ci: `probeaccount_runbook_test.go:104: the runbook's block probe-account arch: ...`)
mutant killed: one hold reason removed from the runbook, probe_held:ca_mismatch (TestProbeHoldReasonsDocumented: `account_test.go:522: docs/runbooks/host-setup.md does not document probe_held:ca_mismatch`)
mutant killed: the upgrade-order sentence removed (TestProbeAccountRunbook/upgrade_order: `probeaccount_runbook_test.go:133: the upgrade order lacks "the signer first, then the server, then the agents"`)
mutant killed: the test-build tag name written into the section (TestProbeAccountRunbook/ci_labels: `probeaccount_runbook_test.go:156: the section names the test-build tag`)
mutant killed: the audit line not printed (TestAuditVerifyProbeLine/line_counts_probe_certificates_and_pending_negatives: `audit_test.go:59: output ["OK: 0 entries, ..." "host certificates: 2"], want the probe certificates line after the host certificate line`)
mutant killed: the JSON field not omitted when zero (TestAuditVerifyProbeLine/json_has_pending_negative_probes: `audit_test.go:79: --json {"ok":true,...,"pending_negative_probes":0}, want pending_negative_probes omitted when zero`)

T3: a2492f8 (dcd48f9 the audit line, 64617a7 the runbook section and its gates, a2492f8 the smoke)

### Deviations (Task 3)

1. **revocation_lands revokes a fresh certificate**, not the login certificate of the earlier step: that one has a 10-minute lifetime and can expire during the earlier waits (up to about 10 minutes), which would make the refused login after the revocation prove nothing. The fresh one logs in first, is revoked through the signer, and must then appear in current/revoked.krl under the CA key that signed it and fail to log in.
2. **The runbook section does not cite TestProbeAccountRunbook by name** ("a runbook gate keeps it equal"), since its own cited_tests_exist leaves its file out, as TestHostTrustRunbooks does.
3. **every_reason_documented** requires each reason as a list item `` - `probe_held:<reason>` `` with a `Fix:` sentence; the item ends at the next item or at a blank line.

## Resume point

- Branch p03/10c-probe-account, pushed. Task 1 is complete: T1 80b0180 (e2e evidence at e18bf1a), this SUMMARY committed after it (docs only). Tasks 2, 3 and 4 are not started.
- Commits: 85eae61 (the full check, preflight, drift, flags, the e2e), 59bd530 (test: the spec the tests expect, spelled out), e18bf1a (test(e2e): the DenyUsers cause outside the Match cause block), 80b0180 (test: the IPv4 wildcard built at run time), then the docs commit of this SUMMARY.
- The plan files 03-10c-PLAN.md and 03-10d-PLAN.md lie untracked in the phase directory, byte-identical to the checked plans; Task 4 commits them.
- Next: Task 2 (the distro matrix). Its precondition holds: Task 1's verify passed (unit gate, and the e2e gate green in 42487971088) and the SUMMARY records T1 and the `distro base:` line.
- Facts for Task 2: Docker is NOT available in WSL, so the matrix and its mutants run only in CI (`workflow_dispatch` on the branch, throwaway branches for the mutants, deleted afterwards). e2e-distro.yml and systemd.yml run on `pull_request` and `workflow_dispatch` (no PR is open yet). The distro tests call `keyroster-agent check` (distro_test.go:397, :404, :421, :436, :447; refusals_test.go:245) and require exit 0 or 3 only: the new `probe` field of the check report is report only and does not change the exit (no distro test decodes the check JSON strictly). The two preflight finding counts of refusals_test.go (:149-151, :213) need `withoutProbeAccount` before any distro run (Task 2, as planned): the images have no probe account, so preflight now reports `probe_account` with `account_missing`.
- The test-time base was measured at at=1794143318; it expires at 1794229718, after which Task 4 re-measures it in place in the detached worktree outside the repository at origin/main (the same one is still checked out for that).
- The plan's commit ledger (gsd-plan-head-before-03-10c in the git directory) holds cee452a.
- Owner question open: files_modified (Deviation 10); it blocks only Task 4's files gate.
