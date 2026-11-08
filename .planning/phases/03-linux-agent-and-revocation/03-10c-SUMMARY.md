---
phase: 03-linux-agent-and-revocation
plan: 10c
subsystem: agent, ci, docs
tags: [probe-account, shadow, sshd-T, distro-matrix, systemd, runbook, agent-04]
status: complete
requires: [03-10b]
provides: [probe-account-full-check, probe-account-runbook, distro-probe-matrix, systemd-probe-smoke, audit-pending-negatives]
requirements-completed: []
commits: 27
plan_head_before: cee452aa4b047d71e2a9c4076ca7363e05712a1e
plan_head_after: aaa9a9e9133e6713126e303dbe77c1eb43880845
actuals:
  tokens: 118537  # chars/4 over git diff cee452a..aaa9a9e (the plan files included; fix round 1 included)
  tasks: 4
  commits: 27  # git rev-list --count cee452a..aaa9a9e: 15 of Tasks 1 to 4, the SUMMARY commit 48590af, 11 of fix round 1
---

# Phase 3 Plan 10c: The probe account checked completely Summary

The gate's account step is the full check of owner answer Q3 (passwd, shadow where readable, `sshd -T -C` from the probe's own source address, definite Allow and Deny rules), preflight and drift report it report only, the seven distro images and the real systemd units prove the runbook's account, and host-setup.md documents every hold reason, kept equal to what CI runs.

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

T-03-381: IPAddressAllow=localhost admitted 127.0.0.2 under the real unit, observed in run 42506650844 at e14b5b9 (fix round 1): with ListenAddress 127.0.0.1 as sshd's only listen address, sshd's VERBOSE lines name `keyroster-probe from 127.0.0.2` for the positive probe (Postponed publickey) and the negative probe (Failed publickey), and both probes pass under keyroster-agent.service. The first record here (run 42495385525) proved the two passes only; the probe source was not observed then and may have been ::1.

Task 3 mutants (each applied to the committed code at a2492f8 by the mutant runner outside the repository, run alone on its named subtest with `-timeout 5m` through scripts/linux.sh, killed by the named `--- FAIL:` line, restored with `git checkout --` and proven by `git diff --quiet HEAD --`; the tag mutant joins the tag's two parts in the mutation script, so no literal was written to a committed file):
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

## Resume point after Task 1 (kept as recorded; superseded by Where to resume)

- Branch p03/10c-probe-account, pushed. Task 1 is complete: T1 80b0180 (e2e evidence at e18bf1a), this SUMMARY committed after it (docs only). Tasks 2, 3 and 4 are not started.
- Commits: 85eae61 (the full check, preflight, drift, flags, the e2e), 59bd530 (test: the spec the tests expect, spelled out), e18bf1a (test(e2e): the DenyUsers cause outside the Match cause block), 80b0180 (test: the IPv4 wildcard built at run time), then the docs commit of this SUMMARY.
- The plan files 03-10c-PLAN.md and 03-10d-PLAN.md lie untracked in the phase directory, byte-identical to the checked plans; Task 4 commits them.
- Next: Task 2 (the distro matrix). Its precondition holds: Task 1's verify passed (unit gate, and the e2e gate green in 42487971088) and the SUMMARY records T1 and the `distro base:` line.
- Facts for Task 2: Docker is NOT available in WSL, so the matrix and its mutants run only in CI (`workflow_dispatch` on the branch, throwaway branches for the mutants, deleted afterwards). e2e-distro.yml and systemd.yml run on `pull_request` and `workflow_dispatch` (no PR is open yet). The distro tests call `keyroster-agent check` (distro_test.go:397, :404, :421, :436, :447; refusals_test.go:245) and require exit 0 or 3 only: the new `probe` field of the check report is report only and does not change the exit (no distro test decodes the check JSON strictly). The two preflight finding counts of refusals_test.go (:149-151, :213) need `withoutProbeAccount` before any distro run (Task 2, as planned): the images have no probe account, so preflight now reports `probe_account` with `account_missing`.
- The test-time base was measured at at=1794143318; it expires at 1794229718, after which Task 4 re-measures it in place in the detached worktree outside the repository at origin/main (the same one is still checked out for that).
- The plan's commit ledger (gsd-plan-head-before-03-10c in the git directory) holds cee452a.
- Owner question open: files_modified (Deviation 10); it blocks only Task 4's files gate.

## Task 4

Tracking (owner decision Q-S): 635a039 commits this plan (wave 25, depends on 03-10b) and 03-10d-PLAN.md (wave 26, depends on 03-10c), both byte-identical (`cmp`) to the checked plans and LF; the next commit ticks 03-10c in ROADMAP.md, adds the 03-10d row under a new `**Wave 26**` block, renumbers the blocks of 03-11 to 03-16 to waves 27 to 32 with their 'blocked on' headers, and changes only the `wave:` line of 03-11 to 03-16 (27 to 32) and, in 03-11, `depends_on: ["03-10d"]` and its precondition line, which now names 03-10d-SUMMARY.md, so that 03-11 cannot start before 03-10d. GSD's `roadmap.update-plan-progress 3` recomputed the Plans line and the Progress row to 26/33 (33 plan files: 03-10c and 03-10d are now counted); it left the wave count at 31, which was corrected by hand to 32. AGENT-04 is not ticked in REQUIREMENTS.md.

Gates (local through scripts/linux.sh unless named):
- verify 2 (`go test -race -count=1 -timeout 15m ./...`, every `go vet` build-tag set, gofmt, golangci-lint for linux, windows and darwin, capslock, dep-firewall, testonly-firewall, pinned actions; test/capslock unchanged against origin/main): exit 0. Pass or fail only.
- verify 3 (the test-time delta): see the readings below and Deviation T4-1.
- verify 4 (the tag in its six files; the release-built agent refuses `--probe-self-test off` with exit 2, `probe_self_test_off_refused`, and writes no state directory): exit 0.
- verify 5 (the files gate): exit 0 on the branch, 39 changed files, all in files_modified or the SUMMARY.
- verify 6 (every commit of origin/main..HEAD authored as Daniel, committed by keyroster-bot, with a gpgsig header): exit 0.
- verify 7 (waves and dependencies, ROADMAP lines, the Wave 26 row, Waves 27 to 32): exit 0.
- verify 9 (no address outside 127.0.0.0/8, no private-workspace term, no attribution line in the added diff lines, the commit messages, the PR body, this plan and this SUMMARY): exit 0.
- verify 11 (no auto-merge on the PR): exit 0.

gate control: files gate exits 0 on the branch as committed
gate control: files gate exits 1 on a throwaway detached worktree with one commit adding an unlisted file (`unlisted-control.txt`, X printed as that one name; the worktree was removed and its commit was never pushed)

Test-time readings (the command of 'Budget and verify', a separate run after verify 2, no other heavy local job), base, reading and delta per package:
- apply: base 452.742, reading 432.637, delta -20.105
- fetch: base 33.632, reading 32.648, delta -0.984
- heartbeat: base 1.057, reading 1.062, delta +0.005
- serverclient: base 4.191, reading 4.105, delta -0.086
- agentcmd (cmd/keyroster-agent): base 1.924, reading 1.848, delta -0.076
- cmd (cmd/keyroster): base 233.517, reading 222.694, delta -10.823
The reading ran at 1794153354 (the base at 1794143318, so 2.8 h old, under 24 h); every package stays far below the +90 s stop. The readings are lower than the base although this plan adds tests: load noise on this workstation of about 5 %, not a speed-up.

PR: #92 (https://github.com/Labontese/keyroster/pull/92), opened by keyroster-bot against main, no auto-merge.

### Deviations (Task 4)

T4-1. **The delta gate's parser cannot read the first key of the base line.** Its key pattern is `^test-time base: .* $1=`, which needs a space between `test-time base:` and the key, so `apply=` (which comes first, the format 'Budget and verify' prescribes) parses as empty, and the gate exits 1 before any test runs (observed: `gate3 exit 1`, no `ok` line). The gate was run once more with only that pattern changed to `^test-time base: \(.* \)\{0,1\}$1=` (the six values then parse as the base line says), and its result is recorded above. The plan file is unchanged; the same parser sits in the plan's text for later plans to copy, so this is a question for the owner (below).

## Fix round 1 (PR #92 review)

The pre-merge review of head 48590af raised eight points. Each fix below is its own commit (or a small group), authored as Daniel, committed by keyroster-bot and signed; every file is in files_modified.

| Commit | Message | Point |
|---|---|---|
| f438a3c | fix(apply): match each AllowGroups and DenyGroups entry as one pattern | group entries as single patterns |
| 6aad1e1 | fix(apply): report possible probe-account exclusions and read NSS group sources | possible exclusions in check; NSS group sources |
| b8ba39b | test(apply): prove preflight compares the probe account's trust on an installed host | preflight's trust comparison |
| e01e45e | test(systemd): prove the probes come from 127.0.0.2 under the real unit | the probe source under the real unit |
| bc1bc14 | fix(apply): log once that the probe password check is off on an unreadable shadow | the shadow note under the applier |
| d1f8809 | docs(03-10c): untick the 03-10d plan in the roadmap | the ROADMAP tick |
| e02eba7 | test(systemd): create sshd's privilege separation directory before sshd -T | the probe source (CI fix) |
| 32d5469 | fix(apply): read every group and initgroups line of nsswitch.conf | NSS group sources (refined) |
| 31b5320 | test(apply): cover the shadow note from the opportunistic pair and a passwd stop | the shadow note (two survivors closed) |
| e14b5b9 | test(systemd): rebind the socket-activated sshd to its new listen address | the probe source (CI fix) |
| aaa9a9e | test(apply): write the probe account's passwd line back without reading the file | the shadow note (gosec G703 on the test) |

**Group matching (sshd semantics).** Each AllowGroups and DenyGroups entry is now matched as one pattern: a comma is part of the pattern and `!` negates nothing. The OpenSSH sources are not in the local cache (only the install prefixes), so no source line was checked; the behaviour was measured instead by running the locally built sshd unprivileged in WSL and logging in as the WSL user, one connection per variant (`sshd -d`, the user's primary group `g`):

| sshd | Variant | Result |
|---|---|---|
| 10.5p1 and 9.5p1 | no rule | login |
| 10.5p1 and 9.5p1 | `DenyGroups g` | refused, "not allowed because a group is listed in DenyGroups" |
| 10.5p1 and 9.5p1 | `DenyGroups g,zzz-none` | login |
| 10.5p1 and 9.5p1 | `DenyGroups *,!g` | login |
| 10.5p1 and 9.5p1 | `AllowGroups g` | login |
| 10.5p1 and 9.5p1 | `AllowGroups g,zzz-none` | refused, "not allowed because none of user's groups are listed in AllowGroups" |

`sshd -T` printed the comma entry whole (`allowgroups g,zzz-none`). TestExcluded and TestExcludedDefinite had the old reading (`denygroups *,!adm` refusing `deploy`); both now expect what sshd does, with cells for `DenyGroups adm,wheel` (no refusal), `AllowGroups adm,wheel` (no match) and `DenyGroups ad?`. The unused list matcher is removed.

**NSS group sources.** An AllowGroups list that names none of the account's groups in `<root>/etc/group` is definite only when every `group:` and `initgroups:` line of `<root>/etc/nsswitch.conf` lists `files` and at most `systemd` beside it (action items and comments skipped, names compared in lower case), or when the file is missing or unreadable. Otherwise nothing is held, the positive probe decides, and the reason text adds that sshd may still admit the account. A local DenyGroups match stays definite. Every duplicate line is read, so both readings of a second `group:` line are covered (the stricter one wins, in the no-hold direction).

**Possible exclusions in check (option chosen: keep the generic entry).** check's account loop now keeps the generic `account_excluded` entry for the probe account unless the probe findings already carry `account_excluded` for it. So a `user@host` entry and an AllowGroups list that NSS may satisfy show up under `excluded`, report only; Drift() and the exit code count what they counted before (Drift reads only Settings, Files and Foreign). This was chosen over a new probe-finding note because the field exists, is report only and needs no new wording for later readers (03-16 reads `probe_account` and the reason). preflight still lists no possible exclusion of the probe account, as before this round (see 'For later plans').

**Preflight's trust comparison.** TestPreflightProbeAccount/installed_host_compares_trust: on an installed, gated host a Match override of authorizedprincipalsfile, and in a second host a principals command, for the probe account each give exactly one report-only `probe_account` finding starting `sshd_override:` and no refusal.

**The shadow note under the running applier.** probeGate, the opportunistic pair and the drift check call `noteAccount` after the full check: the note `probe_shadow_unreadable` is logged (`probe: note: ...`, a note, never an error) when the shadow file becomes unreadable, keyed per state directory on change in this process (a package-level `sync.Map`), so a held retry or a periodic check does not repeat it; a readable round clears it, a result that stopped at passwd leaves it, and a restart logs it again. No capability was added to the unit (owner decision Q3), and nothing was added to a report or to the wire. Preflight keeps its own note.

**The probe source under the real unit (T-03-381).** The smoke's drop-in is now `LoginGraceTime 10`, `ListenAddress 127.0.0.1` and `LogLevel VERBOSE`. Before it, sshd listened on the runner's default addresses, so the agent's first loopback target, and with it the probe source, could be `::1` (probeSource returns `::1` for an IPv6 target), and nothing in the smoke showed which. The script creates `/run/sshd` (sshd -T needs it before socket activation has started ssh.service), checks that sshd -T reports `listenaddress 127.0.0.1:22` and nothing else, reloads systemd and restarts ssh.socket (without the restart the first apply's self-test found nothing accepting on 127.0.0.1:22: run 42506010945 at e02eba7), prints `ss -ltn` and fails when 127.0.0.1:22 does not accept. role_addition_passes_probes then requires sshd's journal lines for the probe account (identifiers sshd and sshd-session) to name 127.0.0.2 and never `::1`, and prints them.

Seen in run 42506650844 at e14b5b9 (systemd-sandbox green): `listenaddress 127.0.0.1:22`, `logingracetime 10`, `loglevel VERBOSE`, `LISTEN 0 4096 127.0.0.1:22`, then

```
sshd: Postponed publickey for keyroster-probe from 127.0.0.2 port 54609 ssh2 [preauth]
sshd: Connection closed by authenticating user keyroster-probe 127.0.0.2 port 54609 [preauth]
sshd: Failed publickey for keyroster-probe from 127.0.0.2 port 35751 ssh2: ED25519-CERT SHA256:bSte9Rzmj0v2maQoqpZbiHs6KsuzrgKTUs8/r/9lbsg ID kr3/ca=machine/sub=probe.runner/...
--- PASS: TestAgentSystemdSmoke/role_addition_passes_probes (70.09s)
```

The positive probe (Postponed, PK_OK) and the negative probe (Failed, KRL) both came from 127.0.0.2 under keyroster-agent.service with IPAddressAllow=localhost, so T-03-381 is proven by an observed source and stays closed. The earlier record (run 42495385525) proved the passes but not the source; the T-03-381 line in Task 3 is corrected below. CI mutant of the smoke: a throwaway branch (p03/10c-f2-mutant, commit 6f16525, deleted after the run, never part of the PR) put `ListenAddress ::1` before `ListenAddress 127.0.0.1`; workflow_dispatch run 42506871234 showed `listenaddress [::1]:22` first, the probe lines `from ::1`, and died on `--- FAIL: TestAgentSystemdSmoke/role_addition_passes_probes (100.16s)` with `agent_systemd_test.go:334: sshd's lines for keyroster-probe do not show the probe source 127.0.0.2 alone (4 lines above)`. That run also confirms the review's reading: with `::1` listed first the probes do use `::1`.

**The ROADMAP tick.** 03-10d is unticked again. verify 7 (the ROADMAP gate) exits 0 on the fixed branch; it also exited 0 on 48590af with the stray `[x]` (run once more in a throwaway detached worktree at 48590af, removed afterwards), because the gate accepts both `[ ]` and `[x]` on the 03-10d row. A stray tick passes it.

**CodeQL.** The CodeQL alert check (not required) fails on alert #25, go/weak-sensitive-data-hashing at probegate.go:472. It is a false positive: keyLine replaces passwd field 2 with a class constant from ParseShadowLine before the line is hashed, and only class constants are appended, so no password or hash text reaches SHA-256. The review and the orchestrator both confirmed this; the orchestrator dismisses the alert, this round does not.

**Process note.** 0ddb2f2 and 64617a7 were staged with only a partial `git diff --cached` review (the executor's own note in Task 1 and Task 3). This round looked at the committed diffs of both commits after the fact, but only partly: the TestProbeHoldReasonsDocumented part of 64617a7's account_test.go was read in full; its probeaccount_runbook_test.go was read through a filter that dropped comments, blank lines and closing braces, cut at 170 columns and 120 lines (it ends inside cited_tests_exist); its runbook text and 0ddb2f2's SUMMARY text were only scanned mechanically over the added lines (no address outside 127.0.0.0/8, no workspace term, no attribution line, no TODO or FIXME, no trailing whitespace; all clean) and were not read through. So the partial review of those two commits is narrowed, not closed. Every commit of this round was staged by name; its full `git diff --cached` was read before the commit, with three exceptions: f438a3c (after the full read two comments were reworded and restaged, and only the two changed lines were re-read), 6aad1e1 (the runbook reflow was restaged and checked with the first 20 lines of its diff) and 843d792, the first SUMMARY commit of this round (read through a filter that left out the mutant lines and cut long lines at 220 columns). The commit that adds this correction was read in full.

Mutants of this round (the mutant runner outside the repository, each applied to the committed code, run alone with `-timeout 5m` through scripts/linux.sh, restored with `git checkout --` per file; numbers 1 to 22 ran at 32d5469, numbers 7, 9, 14, 23 and 24 at 31b5320 after their specifications or tests were fixed). The working tree check after each batch is `git diff --quiet HEAD -- . ':!.planning/config.json'` (exit 0): .planning/config.json was already modified in the working tree before this round started (not by this round), so a plain `git diff --quiet HEAD --` exits 1 regardless and the file is never touched or staged.
mutant killed: check drops every exclusion of the probe account while the probes are on (the old rule) (round 1, #1; --- FAIL: TestDriftProbeAccount/possible_exclusion_stays_visible: `drift_test.go:229: a user@host DenyUsers entry for the probe account: &{Generation:1 Settings:[] Files:[] Excluded:[] Probe:[] Foreign:[] Lo ...`)
mutant killed: check lists a definite probe-account exclusion twice (no dedupe against the probe findings) (round 1, #2; --- FAIL: TestDriftProbeAccount/generic_excluded_not_duplicated: `drift_test.go:213: the probe account is in Excluded too: [{Code:account_excluded Refusal:false Message:account keyroster-probe: DenyUsers ke ...`)
mutant killed: preflight never compares the probe account's trust settings (round 1, #3; --- FAIL: TestPreflightProbeAccount/installed_host_compares_trust: `preflight_test.go:676: sshd_override: probe findings []`)
mutant killed: an AllowGroups non-match is definite whatever nsswitch.conf says (round 1, #4; --- FAIL: TestExcludedDefinite/nss_group_sources/files_sss: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm) in <tmp>/etc/group; <tmp>/etc/nss ...`)
mutant killed: a DenyGroups match is only possible while NSS has another source (round 1, #5; --- FAIL: TestExcludedDefinite/nss_group_sources/files_sss: `preflight_test.go:543: "denygroups adm\n": ("DenyGroups adm refuses its group adm", false), want ("DenyGroups adm refuses its group adm", tr ...`)
mutant killed: systemd beside files makes the non-match only possible (round 1, #6; --- FAIL: TestExcludedDefinite/nss_group_sources/files_systemd: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm) in <tmp>/etc/group; <tmp>/etc/nss ...`)
mutant killed: action items are read as sources (round 1, #7; --- FAIL: TestExcludedDefinite/nss_group_sources/files_action_systemd: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm) in <tmp>/etc/group; ...`)
mutant killed: an action item that spans fields ends at its first field (round 1, #8; --- FAIL: TestExcludedDefinite/nss_group_sources/files_spaced_action: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm) in <tmp>/etc/group; <tmp>/etc/nss ...`)
mutant killed: a missing nsswitch.conf counts as another source (round 1, #9; --- FAIL: TestExcludedDefinite: `preflight_test.go:502: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm) in <tmp>/etc/group; ...`)
mutant killed: an initgroups: line is ignored (round 1, #10; --- FAIL: TestExcludedDefinite/nss_group_sources/initgroups_sss: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm)", true), want ("AllowGroups (whee ...`)
mutant killed: comments are not stripped (round 1, #11; --- FAIL: TestExcludedDefinite/nss_group_sources/comment_ignored: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm) in <tmp>/etc/group; <tmp>/etc/nss ...`)
mutant killed: only the first group: line is read (round 1, #12; --- FAIL: TestExcludedDefinite/nss_group_sources/second_group_line: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm)", true), want ("AllowGroups (whee ...`)
mutant killed: names are compared case-sensitively (round 1, #13; --- FAIL: TestExcludedDefinite/nss_group_sources/upper_case: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm)", true), want ("AllowGroups (whee ...`)
mutant killed: a group: line without files counts as files only (round 1, #14; --- FAIL: TestExcludedDefinite/nss_group_sources/systemd_only: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm)", true), want ...`)
mutant killed: the text of a possible AllowGroups exclusion lacks the NSS clause (round 1, #15; --- FAIL: TestExcludedDefinite/nss_group_sources/files_sss: `preflight_test.go:542: "allowgroups wheel\n": ("AllowGroups (wheel) lists none of its groups (deploy, adm)", false), want ("AllowGroups (whe ...`)
mutant killed: excludedDefinite splits a group entry on commas again (round 1, #16; --- FAIL: TestExcludedDefinite: `preflight_test.go:502: "denygroups *,!adm\n": ("", true), want ("", false)`)
mutant killed: the DenyGroups text splits a group entry on commas again (round 1, #17; --- FAIL: TestExcluded: `preflight_test.go:447: "denygroups *,!adm\n": "DenyGroups *,!adm refuses its group deploy", want ""`)
mutant killed: the AllowGroups text splits a group entry on commas again (round 1, #18; --- FAIL: TestExcluded: `preflight_test.go:447: "allowgroups adm,wheel\n": "", want "lists none of its groups"`)
mutant killed: the shadow note is logged on every round (round 1, #19; --- FAIL: TestProbeGate/shadow_unreadable_noted_once: `probegate_test.go:1213: held round 2: 2 notes in "keyroster-agent: probe account keyroster-probe: sshd_override: sshd -T -C reports pubkeyau ...`)
mutant killed: the memory is never cleared when shadow reads again (round 1, #20; --- FAIL: TestProbeGate/shadow_unreadable_noted_once: `probegate_test.go:1226: unreadable again: <nil>, 1 notes in "keyroster-agent: probe account keyroster-probe: sshd_override: sshd -T -C repor ...`)
mutant killed: the gate does not note (round 1, #21; --- FAIL: TestProbeGate/shadow_unreadable_noted_once: `probegate_test.go:1213: held round 1: 0 notes in "keyroster-agent: probe account keyroster-probe: sshd_override: sshd -T -C reports pubkeyau ...`)
mutant killed: the drift check does not note (round 1, #22; --- FAIL: TestProbeGate/shadow_unreadable_noted_once: `probegate_test.go:1226: unreadable again: <nil>, 1 notes in "keyroster-agent: probe account keyroster-probe: sshd_override: sshd -T -C repor ...`)
mutant killed: the opportunistic pair does not note (round 1, #23; --- FAIL: TestProbeGate/shadow_unreadable_noted_by_opportunistic: `probegate_test.go:1256: the opportunistic pair logged 0 notes in "keyroster-agent: ...`)
mutant killed: a result that stopped before the password stage clears the memory (round 1, #24; --- FAIL: TestProbeGate/shadow_unreadable_noted_once: `probegate_test.go:1235: the account back, shadow still unreadable: <nil>, 3 notes in "keyroster-agent: ... (rerun at aaa9a9e)`)
mutant killed: the smoke lets the probes use ::1 by listing it first (round 1, #25, CI run 42506871234 on a throwaway branch; --- FAIL: TestAgentSystemdSmoke/role_addition_passes_probes: `agent_systemd_test.go:334: sshd's lines for keyroster-probe do not show the probe source 127.0.0.2 alone (4 lines above)`)

Three specifications were wrong on their first run and were corrected, not counted as survivors: #7 and #14 removed the only use of a variable (a build failure, so no test ran) and now disable the branch with `false &&`; #9 died on the parent `--- FAIL: TestExcludedDefinite` (its table cells fail before the subtest runs) and now names that line. Two mutants survived their first run, #23 (the opportunistic pair's note) and #24 (a passwd-stage result clearing the memory), because no test reached them; 31b5320 added shadow_unreadable_noted_by_opportunistic and the passwd-stop cells, and both then died. 25 mutants in all, 25 killed, none equivalent.

CI of this round, by head:
- e01e45e: systemd-sandbox run 42505585523 failed in 1m16s: the script's new listen check saw nothing, because sshd -T stopped at `Missing privilege separation directory: /run/sshd` (fixed in e02eba7). The other workflows of that head were superseded.
- e02eba7: systemd-sandbox run 42506010945 failed: `no first apply under the unit within 150 s`, the self-test found `127.0.0.1:22: connect: connection refused` after ListenAddress 127.0.0.1 (fixed in e14b5b9).
- e14b5b9: systemd-sandbox run 42506650844 success (TestAgentSystemdSmoke 505.62 s, role_addition_passes_probes 70.09 s; the probe-source lines above).
- 6f16525 (throwaway mutant branch, not in the PR): systemd-sandbox run 42506871234 failure, as intended (mutant #25).
- aaa9a9e (the code head of this round), every required check green: CI 42507856048, E2E 42507856056, E2E distro 42507856060, Systemd 42507856051, E2E PKCS#11 42507856054, E2E TPM 42507856087, PIV 42507856093, CodeQL workflow 42507856057, Workflow lint 42507856080, PR title 42507856097. The separate `CodeQL` alert check fails on alert #25 (not required; see CodeQL above).
- Lanes at aaa9a9e (`go test` elapsed of ./test/e2e): e2e 9.5p1 751.584 s and 10.5p1 773.107 s (cap 900), e2e-probe 9.5p1 279.601 s and 10.5p1 286.412 s (cap 420); systemd-sandbox TestAgentSystemdSmoke 511.30 s (role_addition_passes_probes 60.11 s, the probe lines again `from 127.0.0.2`, none from ::1); e2e-distro jobs 3m58s to 6m33s.
- The SUMMARY commit that records this round is docs only; its required checks and the e2e gate in `pr` mode on it are reported with the hand-off, not here.

Test-time reading of this round (the command of 'Budget and verify', at 1794160016, after f438a3c..e14b5b9; the base line above is 4.6 h old), base, reading and delta:
- apply: base 452.742, reading 520.676, delta +67.934
- fetch: base 33.632, reading 33.494, delta -0.138
- heartbeat: base 1.057, reading 1.060, delta +0.003
- serverclient: base 4.191, reading 4.235, delta +0.044
- agentcmd (cmd/keyroster-agent): base 1.924, reading 1.845, delta -0.079
- cmd (cmd/keyroster): base 233.517, reading 298.735, delta +65.218
Both large deltas stay under the +90 s stop, but the reading was not quiet: the tagged `go vet` runs overlapped its first minutes, and a shell wait loop of this round spun one core on the Windows side for about three minutes during it. cmd/keyroster gained no test this round (only the runbook text its gate reads), so its +65 s is load, not cost. apply gained about ten subtests.

Local gates of this round (scripts/linux.sh), on aaa9a9e unless named: `go vet ./internal/agent/apply/`, `go vet` with the tags keyroster_e2e, e2e, `e2e e2eprobe`, `e2e systemdsmoke` and e2edistro, gofmt over the module, golangci-lint for linux, windows and darwin (0 issues each; the first linux run at 31b5320 found gosec G703 in harness_test.go:1020, reached through the new test's read of passwd, which aaa9a9e removed), the e2e lints with `--new-from-rev=origin/main` for `e2e,e2eprobe` and `e2e systemdsmoke` and the distro lint (0 issues), capslock-check, dep-firewall, testonly-firewall and check-pinned-actions (all exit 0), test/capslock unchanged against origin/main, `bash -n test/systemd/agent-smoke.sh`. The `-race` run above (all six packages `ok`, no race) ran at e14b5b9's tree. A second `-race` run at aaa9a9e, with no other local job, of the three packages this round touches: apply 418.155 (base 452.742, delta -34.587), agentcmd 1.726 (delta -0.198), cmd 216.470 (delta -17.047), all `ok`, no race; so the first reading's +68 s and +65 s were load. Plan gates re-run on aaa9a9e: verify 4 (the tag in its six files) exit 0, verify 5 (files gate) exit 0, verify 6 (authors and signatures) exit 0, verify 7 (ROADMAP) exit 0. shellcheck is still not installed (UNVERIFIED as before).

## For later plans

- 03-10d: Task 1 Deviation 9's behaviour change (a widening on a host whose drop-in is edited or missing at the start of a run is held one round as `sshd_override`, because the account check compares sshd -T -C's trust settings for the probe account before that run repairs the drop-in) is one of the lines 03-10d reconciles, with the served-certificate site, the gate and the hold reasons (Planner decisions D1).
- 03-12: a CA rotation waits on a host with a broken probe account (R11), now with the reasons password_empty, password_set, sshd_override and account_excluded as well; 03-12 must say so.
- 03-14 mirrors account.go (the minimal check and the full check's stages).
- 03-16 proves a capability-less root on a shadow file of mode 0000 (almalinux:9 ships mode 0000; the matrix runs as root with capabilities), and the other service managers.
- 03-16's probe-account handling must read the report-only code `probe_account` and the reason at the start of its Message, as a warning that does not block, and not the two refusal codes probe_account_unparsable and probe_account_is_managed that 03-16-PLAN.md:150 and :391 name (03-16 revises its instruction 3 at its own check; cover-7).
- Older follow-ups of 'Not done here', unchanged: the sshd `Match User` lockdown for the probe account (later, no plan); a live revocation set for fleets above about 1000 hosts (later, no plan); `TestFetch/more_repolls_immediately` under a parallel `-race` load (a one-file chore); the 16 e2e lint issues under build tags CI never lints (a chore); `pop_hosts_off_fails` of 03-09 (owned by 03-10d, conditional).
- The delta gate's key pattern (Deviation T4-1) is in this plan's text; a later plan that copies the gate copies the defect.
- A chore outside this plan: TestRevokeHost/success_line_says_agent_keeps_state (cmd/keyroster/revoke_test.go:1290) fails when a random SHA-256 in the command's output contains the substring 403 (`revoke_test.go:1290: output names "403":`, seen on cli-windows at 843d792, CI run 42510762650 attempt 1; attempt 2 passed). The test should match the status code as a word, not as a substring.
- Task 4's ROADMAP gate (verify 7) accepts `[ ]` and `[x]` on the 03-10d row, so a stray tick passes it (fix round 1); a later plan that reuses it should pin the expected box.
- preflight lists no exclusion of the probe account that is only possible (a `user@host` entry, an AllowGroups list NSS may satisfy); check lists them since fix round 1. 03-10d or 03-16 can add them to preflight as a report-only note.

## UNVERIFIED

- shellcheck was not run on probe-account.sh, run-in.sh, run.sh or agent-smoke.sh: it is not installed locally and no workflow of the repository runs it (only `sh -n`, `dash -n` and `bash -n` were).
- systemd's `IPAddressAllow=localhost` admitting 127.0.0.2 is proven, with the source observed in sshd's log, on the ubuntu-24.04 runner's systemd only (run 42506650844, fix round 1); other systemd versions and OpenRC stay UNVERIFIED until 03-16.
- A shadow file that the unit's root cannot read: the unit has no capabilities; almalinux:9 ships mode 0000 (a FACT now), but the matrix runs as root with capabilities and the real unit read Ubuntu's 0640 file. A password that root sets later on such a host goes unseen (owner answer Q3).
- Accounts that exist only in NSS or LDAP (`account_missing` by design; the runbook says so; no test uses a real NSS source).
- `Match Group` evaluated by `sshd -T -C` through the system's NSS, and Match criteria that the specification cannot reproduce (`Match RDomain`, `Match Host` under UseDNS yes); sshd settings the check does not read are left to the positive probe (the T-03-66 residual).
- Which of passwd field 2 and the shadow file sshd and PAM read in each case is recalled, not verified; neither is trusted over the other.
- The shadow expiry fields are not read (sec-11): an expired account is refused only by the positive probe, after the addition is live, and `failure_backoff` stops the loop.
- That sshd -T omits `usepam` on a build without PAM is now a fact on alpine only (the one image without PAM).
- PerSourcePenalties beyond three pairs at the production spacing; an IPv6-only listener and a `persourcenetblocksize` of /30 or wider (all seven images report 32:128).
- (No longer UNVERIFIED, fix round 1: the smoke's `LoginGraceTime 10` applied; sshd -T printed `logingracetime 10` in run 42506650844 once `/run/sshd` existed.)
- The flake fix of D6: five green runs (Task 1) lower the odds and prove nothing about the next.
- The unit override for another account name: the runbook text is gated, no test starts a unit with an override.
- An AllowGroups list that a group from SSSD, LDAP or winbind satisfies on a real host (fix round 1): the nsswitch.conf reading is unit-tested only. That glibc's group-list lookup prefers an `initgroups:` line, and how it treats a duplicate `group:` line, is from its documentation, not measured; the check reads every such line and holds only when all list files alone, the no-hold direction. musl hosts (alpine) have no nsswitch.conf and are read as files only.
- AllowGroups and DenyGroups as single patterns: measured by running the locally built sshd 10.5p1 and 9.5p1 (fix round 1); the OpenSSH source was not available locally, so no source line was checked.
- The note `probe_shadow_unreadable` from the running applier is unit-tested only: the smoke's Ubuntu shadow file (0640) is readable, so the real unit never logged it (a mode-0000 host is 03-16's).
- Every host that is not a CI image.

## Where to resume

- Branch p03/10c-probe-account, pushed; PR #92 open against main, no auto-merge. Tasks 1 to 4 are done up to the owner's merge gate.
- Fix round 1 of the pre-merge review is done (section 'Fix round 1'); the orchestrator re-reviews and dismisses CodeQL alert #25 (false positive).
- Next: the owner's merge gate, after the orchestrator's re-review. Before the merge only `bash scripts/merge-gate.sh --check p03/10c-probe-account` runs. If main moves first: `git rebase --gpg-sign origin/main`, take origin/main's tracking files, re-apply only this plan's entries, push with lease, and re-run the gates.
- The test-time base was measured at at=1794143318 and expires at 1794229718; a re-run of the delta gate after that re-measures it first, in the detached worktree outside the repository at origin/main.
- Owner question: the delta gate's key pattern (Deviation T4-1).

## Self-Check: PASSED

The key files exist (account.go with checkProbeAccountFull, probe_test.go with TestDistroProbeFacts, probeaccount_runbook_test.go with TestProbeAccountRunbook, probe-account.sh, the runbook, both plan files), and every commit this SUMMARY names (85eae61 to 0309661) is an ancestor of HEAD.

Fix round 1 self-check: PASSED. The eleven commits of the round (f438a3c to aaa9a9e) are ancestors of HEAD, the throwaway mutant commit 6f16525 is not, its branch is deleted on origin, and the files the round changed exist (exclusion.go with groupsFilesOnly, account.go with noteAccount, drift.go, probegate.go, the four test files, agent_systemd_test.go, agent-smoke.sh, host-setup.md, ROADMAP.md).
