---
phase: 03-linux-agent-and-revocation
plan: 12f2
subsystem: e2e
tags: [ca-rotation, host-ca, known-hosts, e2e, runbook]
status: complete
requires: [03-12f]
provides: [TestHostCARotation in the e2e-rotation lane on OpenSSH 9.5p1 and 10.5p1, caRotRetireKey and caRotDrainRE by role, the lane's -run list and PASS loop, the host-CA gate in ca-rotation.md with enroll-user.md item 4a and the machine-identities.md and signer-install.md sentences, TestCARotationSwitchRunbook/host_ca_gate and the shrunk no_plan_numbers allowlist, item 4a's pin in TestHostTrustRunbooks, this plan's text]
affects: [03-13, 03-16]
key-files:
  created: [test/e2e/hostca_rotation_test.go]
  modified: [test/e2e/ca_rotation_test.go, .github/workflows/e2e.yml, CONTRIBUTING.md, docs/runbooks/ca-rotation.md, docs/runbooks/enroll-user.md, docs/runbooks/machine-identities.md, docs/runbooks/signer-install.md, cmd/keyroster/runbook_test.go, cmd/keyroster/hosttrust_runbook_test.go, .planning/phases/03-linux-agent-and-revocation/03-12f2-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md]
requirements-completed: []
actuals:
  tokens: 137400   # chars/4 over the realized diff against c6c632d without this SUMMARY (107,710) plus this SUMMARY (about 29,700)
  tasks: 4         # Tasks 1 to 4 up to the green PR and its fix round; Task 4's step 6 (the pre-merge review) is the orchestrator's and Task 5 the owner's merge
  commits: 12      # git rev-list --count c6c632d..HEAD with this commit: G2, R3, W3, P4, the first SUMMARY commit, X1 to X6 and this commit
plan_head_before: c6c632d130450e24fe432dfd68bcf00420dc2231
---

plan file size: 328818 bytes
plan file sha256: 8e7359287f9719030a35fde4023b39d1ffb6a708373965e648b48c94b15d5033

# Phase 03 Plan 12f2: CA rotation, the host-CA end-to-end test Summary

TestHostCARotation runs in the e2e-rotation lane against real sshd, a real keyroster-agent and a real `keyroster known-hosts sync`: one host at a 90 s host cap, a client that refreshed after ceremony 1 reaches the host by its generation-1 certificate right after the switch and by its generation-2 certificate after the host's own renewal, the host asks for nothing in between, and a client that did not refresh reaches it right after the switch and is refused with `Host key verification failed` after the renewal. ca-rotation.md, enroll-user.md item 4a, machine-identities.md and signer-install.md state the owner's host-CA gate with the tools as they are, every new sentence pinned but two. No product code changed. PR #118.

## Hand-over

- **Sessions 1 and 2:** Task 1 (preconditions, branch, base values, test-time base, anchors), Task 2 (the wrapper and its self-check, local check 1, the pre-check on 10.5p1 and 9.5p1 with the fourth verify command, G2, Task 2's five verify commands, M371, M372 and M373 with M373's unit run, and the PASS loop's negative proof) and Task 3 (its precondition, the anchors read before any sentence was written, R3 and its RED from a detached worktree of R3, W3, Task 3's four verify commands, and the 70 document mutants, all killed by their named leaf). The orchestrator's check of G2 and its rulings on deviations 1 to 5 are recorded where they belong.
- **Session 3 (2026-11-22): Task 4, steps 1 to 5.** The precondition; P4 4e058f8073494945f774db64cf07ff3fe11cdc89 after a full read of its staged diff and the publish scan; the test-time base re-measured and replaced in place; the delta gate; the full gate (one unchanged re-run under the clock-flake rule, deviation 6); the push; PR #118 without auto-merge; the tracking update; this SUMMARY's commit. See "Task 4 (session 3)".
- **Session 4 (2026-11-22 and 2026-11-23): the pre-merge review recorded, its fix round, and this record.** The orchestrator's pre-merge review of head 4869fde, recorded from its run record; the fix round X1 to X6 (part A: X1 to X3, part A2: X4 to X6, each read and checked by the orchestrator before the next part), with two REDs, 34 document mutants, the end-to-end runs at X3 and X6 and the narrowing mutant; part B: the test-time base re-measured in place, the delta and full gates, this record's commit, the push and the PR text. See "Pre-merge review", "The fix round" and "The check of the fix round".
- **Left:** CI on this record's commit and Task 4's verify commands on it (a commit cannot name its own runs; their results go in the orchestrator's record), then Task 5 (the owner's merge).

## Task 1

- BASE: c6c632d130450e24fe432dfd68bcf00420dc2231
- origin/main at execution (after `git fetch origin`): c6c632d130450e24fe432dfd68bcf00420dc2231 (origin/main is BASE)
- Branch `p03/12f2-ca-rotation-host-ca-e2e` existed at dispatch, pointing at origin/main, with no upstream; it was checked out and nothing was created (the Delivery protocol's rule for an existing branch at origin/main).
- The ten checks of Task 1's verify block, each extracted byte for byte from its plan line and run in order: all ten exit 0.
  1. Placement (line 673, `D` set to the dispatch's sha256): exit 0.
  2. Stop guard (line 675): exit 0.
  3. ROADMAP and STATE base values (line 677): exit 0; printed `stopped_at: "Completed 03-12f-PLAN.md (PR #113)"`.
  4. Ruleset and rotation job lines (line 679): exit 0.
  5. WSL tools (line 681): exit 0.
  6. The owner's two private pattern files (line 683): exit 0.
  7. Anchors and free names (line 685): exit 0.
  8. Free mutant and threat numbers (line 687): exit 0.
  9. Clean tree against origin/main (line 689): exit 0.
  10. The lane gate's legs on the base push run 44867318533 (line 691): exit 0, with the three outcomes `9.5p1: not exactly one PASS line for TestHostCARotation`; `e2e-rotation (9.5p1): go test 540.411 s` and `e2e-rotation (10.5p1): go test 527.927 s`; `9.5p1: not exactly one fixed line`.
- Base values as read on origin/main:
  - ROADMAP: `**Plans:** 39/44 plans executed in 43 waves.`; `| 3. Linux Agent and Revocation | 39/44 |`; `- [ ] 03-12f2-PLAN.md — CA rotation, host-CA end-to-end test (D-14, KEY-08): TestHostCARotation in the e2e-rotation lane and the host-CA runbook gate` under `**Wave 39** *(blocked on Wave 38 completion)*`.
  - STATE: `stopped_at: "Completed 03-12f-PLAN.md (PR #113)"`, `  total_plans: 79`, `  completed_plans: 74`, `Plan: 39 of 44`.

test-time base: keyroster=303.005 at=1795391117

- The base above was re-measured in session 4 (2026-11-23, the fix round's part B), replacing in place session 3's line (keyroster=281.238 at=1795377427), which had replaced session 1's (keyroster=299.632 at=1795370396), each time because the gates ran in another session than the one that measured the line before; session 4 measured it the same way as session 3, on origin/main c6c632d130450e24fe432dfd68bcf00420dc2231, under a temporary directory of its own. Session 3's measurement, for the record: a detached worktree of origin/main c6c632d130450e24fe432dfd68bcf00420dc2231 outside the repository, the Budget command `bash scripts/linux.sh 'exec 2>&1; go test -race -count=1 -timeout 15m ./cmd/keyroster/'` run from it in the background with nothing else running in WSL; exit 0, one `ok` line, no FAIL, DATA RACE or SKIP; `at=` is `date +%s` at its end. The worktree was removed afterwards. Session 1 had measured its base the same way on the unchanged tree (exit 0).
- Anchors of "Anchors re-read at c6c632d", re-read at origin/main by content (`git grep -n -F` of each quoted fragment in its file): 196 anchors, 196 at their stated line, 0 moved, 0 gone. No task text needs a corrected line.

## Task 2

### Precondition

After `git fetch origin`, Task 1's first three checks exit 0 again; origin/main is still BASE.

### The namespace wrapper (local check 2)

A small script outside the repository, never committed. It runs its arguments inside an unprivileged user and mount namespace: it copies WSL's /etc/hosts to a private temporary file with the line `127.0.0.1 keyroster.localhost` added and binds that copy over /etc/hosts; it binds a new empty 0700 directory over `$HOME/.ssh` (after checking that `$HOME/.ssh` is a directory, which it neither lists nor reads); it sets `KEYROSTER_E2E_REAL_HOME=1`, unsets `GITHUB_ACTIONS`, and runs the command through an inner user namespace that maps the caller's own uid and gid back, so the account lookup and `$HOME` agree. The binds exist only inside the namespace and vanish with it; the private copies are removed when it ends. It changes no system file and never touches the real `~/.ssh`. It is the orchestrator's prototype, used unchanged (its sha256 checked before use).

Self-check (the action's item 2 command, extracted byte for byte, `W` set to the wrapper's absolute WSL path, run through scripts/linux.sh): exit 0.

### Commands taken from the action text

The self-check, the pre-check, the mutants' e2e control and M373's unit run stand in the action text between backquotes, not in `<automated>`. Each was extracted from the raw plan bytes; each placeholder (`<the wrapper>`, `<the output directory>`) was asserted to occur exactly once before it was filled and zero times after, filled with the wrapper's absolute WSL path and the pre-check's output directory outside the repository. The verify commands' `<the SHA of G2>` and `<the output directory of the pre-check>` are filled the same way.

### Local check 1 (the third verify command, before the pre-check)

- First run: exit 1, one golangci-lint issue in the tagged pass: `test/e2e/hostca_rotation_test.go:40:2: time-naming: var hcrRenewMin is of type time.Duration; don't use unit-specific suffix "Min" (revive)`. The plan names the constant `hcrRenewMin`, so the name stays and the line carries `//nolint:revive // time-naming: Min is the minimum, not minutes` (deviation 1).
- Second run, after that edit: exit 0 (four `0 issues.` lines; `check-pinned-actions: all 55 uses: references in .github/workflows are pinned to commit SHAs`; the `go list` tag legs and every vet pass).
- Before the pre-check, each of M371, M372 and M373 was applied once by its exact replacement (asserted unique), vetted under its tags (exit 0), and restored; the sha256 after the restore equalled the one before, so each mutant compiles and is unique before G2.

### Local check 3: the pre-check

Run in the background, nothing else in WSL, the action's command byte for byte with the wrapper and the output directory filled.

**10.5p1, TestHostCARotation alone:** exit 0, `--- PASS: TestHostCARotation (144.53s)`, `ok  	github.com/Labontese/keyroster/test/e2e	175.556s`, the fixed line once, no SKIP, FAIL or build failure, no `WARNING host certificate answer for` line; every login assertion passed, so no login from loopback failed. A passing run cannot show more than that for the plan's per-source-penalty stop: the test retries a failed keyscan try without a log line, and sshd's log is dumped only on a failure (the dumped sshd logs of the mutant runs, under "Mutants", show the penalties that sshd records).
- Serials: c1 1795371381521487 (issued 18:16:21, anchored 1.512 s after its issuance); r1 1795371435734367 (issued 18:17:15, 54 s after c1, anchored 1.826 s after its issuance); r2 1795371495613931 (issued 18:18:15, 60 s after r1, observed 1.486 s after its issuance). No re-anchor.
- Stop windows: prepare down 54 ms (stopped 18:16:22.660, bound 18:17:01.000; up 18:16:22.715, bound 18:17:11.000); the install of ceremony 1 down 47 ms (stopped 18:16:22.755; up 18:16:22.802, same bounds); the switch down 97 ms (stopped 18:17:16.866, bound 18:17:34.000; up 18:17:16.962, bound 18:17:38.000).
- Commit lags: bundle 2 committed 16.315 s after the install and 16.293 s after the signer served again (bound 45 s); bundle 3 committed 8.639 s after the install and 8.569 s after the signer served again (seen by r1 + about 10.5 s; bound r1 + 44 s).
- Ceremony 2 ended at r1 + 1.866 s; step 6 ended at r1 + 2.361 s (bound + 28 s).
- Step 6a: the attempts file held r1's request (created 1795371435, r1's issuance 1795371435) and c1's (1795371379), none after r1's issuance, no failure and no last code; the drop-in named r1 alone; sshd served r1; no refused answer.
- An observation: step 6a logged `the check ended at r1 + 43.913s`, although the check sleeps until r1 + 45 s before it starts. `time.Sleep` runs on the monotonic clock and the bound is a wall-clock time, so the WSL wall clock fell about 1.1 s behind the monotonic clock during the sleep (the WSL clock effect of 03-12f's deviations 6, 11 and 19). By the wall clock, which anchors every bound of the test, the check therefore ran at about r1 + 43.9 s and not at r1 + 45 s: after the bundle-3 commit had been seen (r1 + about 10.5 s) and before the earliest renewal request at r1 + 52 s. No assertion failed or depended on it.
- The `Server host certificate` lines name the signing CA's fingerprint on 10.5p1, for example `debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com SHA256:<host key>, serial 1795371381521487 ID "kr3/ca=host/sub=web1/req=.../pol=1/dir=4/ser=1795371381521487" CA ssh-ed25519 SHA256:<the generation-1 host CA> valid ...`; every accepted login and B's refusal required that fingerprint and passed.
- Doctor after retire-key exited 0 and printed `OK switch_floor: host generation 2: the log records no certificate of this key; the earliest is the floor`.

**9.5p1, the lane's three tests:** exit 0, `--- PASS: TestCANextAndAbort (40.24s)`, `--- PASS: TestCARotationNoFailedLogin (493.57s)`, `--- PASS: TestHostCARotation (145.74s)`, `ok  	github.com/Labontese/keyroster/test/e2e	696.376s` (at or below 900 s), the fixed line once, TestCARotationNoFailedLogin's final `login failures: 0` once, no SKIP or FAIL, no `WARNING host certificate answer for` line; every login assertion passed, so no login from loopback failed; as on 10.5p1, a passing run cannot show whether a keyscan try failed.
- Serials: c1 1795372043386925 (issued 18:27:23, anchored 1.581 s after); r1 1795372105094920 (issued 18:28:25, 62 s after c1, anchored 1.178 s after); r2 1795372167794244 (issued 18:29:27, 62 s after r1, observed 1.162 s after). No re-anchor.
- Stop windows: prepare down 50 ms (stopped 18:27:24.745, bound 18:28:03.000; up 18:27:24.794, bound 18:28:13.000); the install of ceremony 1 down 44 ms (stopped 18:27:24.834; up 18:27:24.879); the switch down 98 ms (stopped 18:28:26.218, bound 18:28:44.000; up 18:28:26.316, bound 18:28:48.000).
- Commit lags: bundle 2 committed 10.241 s after the install and 10.219 s after the signer served again; bundle 3 committed 12.898 s after the install and 12.826 s after the signer served again (seen by about r1 + 14.1 s, bound r1 + 44 s).
- Ceremony 2 ended at r1 + 1.218 s; step 6 ended at r1 + 1.928 s; step 6a passed and logged `the check ended at r1 + 43.886s` (the same WSL clock effect as on 10.5p1).
- Every `Server host certificate` line names the CA the test expects (generation 1 for the logins after ceremony 1 and right after the switch, generation 2 for A after the renewal, B's refusal and B after its remedy); B's refusal exited 255.

**The WSL clock, measured** (read-only, after the pre-check): over a 40 s `sleep`, WSL's wall clock advanced 38.792 s against 40.02 s of `/proc/uptime`, 1.228 s behind. This fits step 6a's `r1 + 43.9 s` in both runs: the test sleeps by the monotonic clock until a wall-clock moment, and in WSL the wall clock falls behind it. Whether it does so at a slow rate or in steps back was not determined: in M373's run the wall clock read earlier at the end of step 6 (`r1 + 768ms`) than at the end of ceremony 2 (`r1 + 1.492s`), which is a step back. The figures of this measurement were read from the command's output and are in no saved log. Every process of the test reads the same wall clock, so the issuance gaps and bounds are consistent with each other; no assertion depended on the difference. One limit follows for the local runs: step 6a's attempts check compares whole seconds of the wall clock, so a step back larger than the lag between r1's request and an early request (at least 4.17 s, by the plan's reading of the fetch poll) would let such a request count as r1's own; the steps seen in WSL were about 1.2 s, and the drop-in check, the log check of the same step and step 8's check of refused answers stand beside it. The CI runners' clock was not measured.

**The fourth verify command** on `O`: exit 0, printing `9.5p1 go test 696.376 s`, `--- PASS: TestHostCARotation (144.53s)` and `--- PASS: TestHostCARotation (145.74s)`.

No pre-check run failed; no run was repeated.

### G2

- Staged by path: test/e2e/hostca_rotation_test.go (new), test/e2e/ca_rotation_test.go, .github/workflows/e2e.yml, CONTRIBUTING.md.
- `git diff --cached` was read in full, one file at a time, after the last edit and before the commit (the new file read whole, all 653 lines).
- Before the commit, the hunk check of the first verify command, run on the working diff of ca_rotation_test.go, exited 0 (hunks at old lines 526, 540, 548, 550, 554, 566, 569, 599, 787, 806).
- The staged-lines scan (plan line 902's command, with both pattern-file variables on its command line): exit 0.
- Commit ac6206936b4ad50cb0eea8d291f6c74977caf286 `test(e2e): rotate the host CA end to end with a refreshed and a stale client`, signed (SSH signature present), author Daniel Gustafsson, committer keyroster-bot; no file deleted.
- Task 2's first verify command (G2 filled): exit 0. Second (CONTRIBUTING's rows): exit 0.
- Third verify command again after G2 (the Delivery protocol's lint after G2): exit 0, `0 issues.` for linux, windows, darwin and the tagged `--new-from-rev=origin/main` pass on test/e2e, the pinned-actions check and every vet and `go list` leg. No lint issue on a line this plan did not change was reported.
- Fourth verify command: exit 0 (above). Fifth: exit 0 (below).
- TestHostCARotation's durations: 144.53 s (10.5p1 pre-check), 145.74 s (9.5p1 pre-check), 153.67 s (the mutants' control); the plan's typical figure is about 141 s.

### The PASS loop's negative proof (fifth verify command, G2 filled)

Exit 0, printing `1 [the log has no PASS line for TestHostCARotation] 1 [the log has no PASS line for TestHostCARotation] 0`: the loop exits 1 on a log without TestHostCARotation's PASS line, 1 on a log with only an indented one, and 0 with all three column-0 PASS lines.

### The orchestrator's check of G2 (2026-11-22, after Task 2)

After Task 2 the orchestrator checked the commit itself (the local head against the remote's, the signature as GitHub verifies it, the four files) and read the new test and the three smaller diffs in full. It then had G2 read independently, read-only and with nothing run: one reader (Opus, high effort) compared the test with the plan's fixed test, its timing and Task 2, and the three mutants as they were made; one reader (Sonnet, high effort) compared the session's report and this record with the run logs and the commit; two skeptics (Sonnet, high effort) each judged the one item rated major, and one batch skeptic (Sonnet, high effort) the other eight. The run was workflow wf_0ee4fc6c-589: five agents, 768,152 tokens, 110 tool uses, about 16 minutes; no Codex.

- The first reader's statement: it found no path on which TestHostCARotation passes while a property the plan requires is false.
- Nine items, all upheld, none asking for a change of the test. Four are about this record and are corrected in it: the two sentences that said no keyscan from loopback failed (major: a passing run cannot show that), the explanation of step 6a's logged time (reported by both readers) and the mutants' line numbers.
- Five are notes. Four are stated where they belong: the whole seconds of the attempts check and the penalty lines (above and under "Mutants"), and the two that follow. B's refusal comes from 127.0.0.2 and its controls and its remedy from 127.0.0.1, as the plan's step table fixes it; the plan's sentence that B logs in again "with nothing else changed" is looser than its table. The source cannot cause the refusal the test requires: `Host key verification failed` after a `Server host certificate` line that names generation 2 is the client's own decision from its known_hosts file. And `caRotRetireKey`'s certificate-line branch printed no line in any run (each run logged `0 certificate lines`), so in that branch the role parameter is checked only by its strings for the role `user` being the same as before. The fifth note asked for nothing.
- Not checked by that run: nothing was executed, the CI runners' clock, and OpenSSH's penalty thresholds.
- The orchestrator checked the items it relies on in the logs itself: the penalty lines' counts and wording, the two readings of M373's log, the logged ends of step 6a in every run, and the lines of G2 that the mutants' messages come from.

## Task 3

### Precondition

After `git fetch origin`, Task 1's first three checks (lines 673, 675 and 677, each extracted byte for byte; `D` filled with the dispatch's sha256, the placeholder asserted present before and gone after) exit 0; the third printed `stopped_at: "Completed 03-12f-PLAN.md (PR #113)"`. origin/main was c6c632d130450e24fe432dfd68bcf00420dc2231 (BASE) at that moment. HEAD was G2 (ac6206936b4ad50cb0eea8d291f6c74977caf286) on `p03/12f2-ca-rotation-host-ca-e2e`.

### The anchors, checked before any sentence was written

Before R3 and W3, every sentence of "The sweep" that states what the code or the test does was read against its anchor in the anchor table, in the code at G2:
- cmd/keyroster: knownhosts.go (`defaultSSHDir` :125-140, `hostTrustCAs` :173-179, the Include advice :749-751, `knownHostsFile` :843-858, sync :1044-1090 with `openAdminSession` first and `hostTrustExit`), the two callers of `refreshHostTrust` (login.go:390 and knownhosts.go:1076, found by grep), login.go (:164, :183-191, :383-390), narrow.go (:1-14, :58-68), dirpipe.go:60-80, user.go:38-40, hoststatus.go (:186-236, :258-292), ca.go:59-66, root.go (:143-145, :181-194, :811), canext.go, trust.go:189 and root.go:623 (the two printers of the CA-change section).
- internal: agent/hostcert/hostcert.go (:544-601, :690-700, :893-922), agent/apply/hostcert.go (:403-420, :592-640), trust/castate.go (:50-105, :118-150), trust/successor.go:150-162, signer/drain.go:52-78, signer/hostissue.go (:25-31, :140-148), signer/issue.go (:84-88, :140-151), signer/login.go:58-67, the machine and probe issuers' machine CA, cert/builder.go:128-143, rootceremony/cachanges.go:52-90, doctor/doctor.go:344-371, server/server.go:323-344, server/signer.go (:370-373, :435-443, :505-515) with `dropStatus`'s callers (directory.go:258, :451 only); the five callers of `cert.Build` in internal/signer (issue.go:145, login.go:127, hostissue.go:200, machineissue.go:224, probeissue.go:197), each with its role's profile of the policy in force (`s.profiles[req.CARole]`, the user, host and machine profiles, and `certprofile.ProbeProfile`, the machine cap), for the "Pre-switch check" sentence; cmd/keyroster/narrow.go:108-205, whose filter keeps only the lines of `trust.TrustedCAs(b, trust.RoleHost, now)` at the client's clock, for "The drain.".
- The cited unit tests exist with the cited names: `TestVerifyAnswer` and its `unpinned_ca` case, `TestDecide/backoff_schedule`, `TestHostCertStep/hostcert_answer_drained_ca_refused` (it starts with no installed certificate, as the UNVERIFIED label says).
- The sentences about TestHostCARotation, against test/e2e/hostca_rotation_test.go as committed in G2: the 90 s host cap (`withGenesisHostMaxTTL(t, hcrCap)`), two clients on loopback (127.0.0.1, and 127.0.0.2 for B's refusal); the heartbeat wait for ceremony 1's bundle before the switch (`hcrCommitted(..., 2, ...)` at step 2); "a sync the test checks line by line" (`hcrSync` compares the managed file's CA lines with the expected keys, web1 alone); A by generation 1 right after the switch and by generation 2 after the renewal (steps 6 and 8); "asks for no certificate, installs no other and its agent refuses no answer" (step 6a: `hcrAttempts`, the drop-in naming r1 alone, `hcrNoRefusal`); B reaches the host right after the switch, is refused with `Host key verification failed` after the renewal, and reaches it again after a fresh sync whose file is copied to B's known_hosts (step 8's remedy); the test waits neither the gate's time nor the host drain.
Every sentence was borne out; none needed a second look that changed it, and none was reworded.

### R3

- Edits: cmd/keyroster/runbook_test.go, TestCARotationSwitchRunbook: the leaf `host_ca_gate` after `no_plan_numbers` (one table of seven windows, one `t.Errorf` per missing or forbidden phrase naming window and phrase; the header window is `data` up to the first line that starts `## `; the four ca-rotation.md section windows through `caRotationWindow`; machine-identities.md and signer-install.md through `sectionWindow` with the two `signingSection` literals of "The pins", read with `readTestFile`, `t.Fatalf` if a window does not resolve); `no_plan_numbers`: the allowlist `[]string{"03-13", "03-16"}` and the two dictated comment lines. cmd/keyroster/hosttrust_runbook_test.go: the one `htrbWant` line for item 4a, the leaf's last, after the "Logging in" line, with the 14 tokens. Nothing else changed in either file.
- The phrases were taken from the plan's bytes by a parser of the code spans of "The pins" (plan lines 559-565), not retyped: 82 required and 6 forbidden phrases for ca-rotation.md, machine-identities.md and signer-install.md (see deviation 3 on the plan's count of 83), plus the 14 item-4a tokens.
- Before the commit, in the main tree: `gofmt -l cmd/keyroster` empty, `go vet ./cmd/keyroster/` exit 0; the two tests failed on the base documents with exactly the five FAIL lines below and 86 phrase messages (81 required phrases missing, `clients have refreshed` already present, and the 5 forbidden phrases present at the base); with the W3 documents applied to the working tree (then restored with `git checkout --` before staging) both tests passed, so R3 needed no amend.
- golangci-lint on R3's tree: `0 issues.` for linux, windows and darwin.
- Staged by path: the two test files. `git diff --cached` of each was read in full, one file at a time, after the last edit and before the commit.
- The staged-lines scan (plan line 902's command, the owner's two private pattern files passed through their variables): exit 0.
- Commit ce7f58416fdc1f289bdb99efd0556a45e720c838 `test(cli): pin the host-CA gate, its test and the end-state plan numbers of the rotation runbook`, signed (SSH signature present), author Daniel Gustafsson, committer keyroster-bot; two files, no deletion.

### The RED (the second verify command, from a detached worktree of R3)

- The command, extracted byte for byte with `<the SHA of R3>` filled (asserted present before, gone after), run verbatim: exit 0. It adds the worktree under a fresh `mktemp -d` directory outside the repository and removes it again; `git worktree list` afterwards lists no temporary worktree.
- Because the verbatim command deletes its log, it was run a second time, as an evidence-only copy that differs by one `cp` of the log before the worktree's removal (exit 0 too). That run printed:
  - `--- FAIL: TestHostTrustRunbooks`, `--- FAIL: TestHostTrustRunbooks/enroll_user_trusting_hosts` (`hosttrust_runbook_test.go:123: item 4a, host-CA rotation: the section is missing`);
  - `--- FAIL: TestCARotationSwitchRunbook`, `--- FAIL: TestCARotationSwitchRunbook/no_plan_numbers` (`runbook_test.go:1129: ca-rotation.md names plan 03-12f2 outside a code span; describe the rotation in its end state`, twice: :637 and :695), `--- FAIL: TestCARotationSwitchRunbook/host_ca_gate` (86 `lacks`/`still holds` messages).
  - The controls passed: `required_phrases`, `audit_verify_pins_both_roots`, `exports_leave_the_box`, `refusal_restarts_the_signer`, `retire_files_in_a_private_directory`; and `revoke_revoking_a_host`, `revoke_placeholders_gone`, `host_setup_approval_and_removal`, `labels_on_new_sections`, `cited_tests_exist`. In `enroll_user_trusting_hosts` the item-4a line is the last, so items 1 to 9 and "Logging in" were checked first and raised no message.
  - No `[build failed]`, `[setup failed]` or `--- SKIP` line.

### W3

- Edits, by a script that strips one `> ` level from the plan's quoted blocks (a bare `>` becomes an empty line) and asserts every base line it replaces or inserts beside at its stated line number first: ca-rotation.md the header (plan lines 284-289 over base :10-14), the clients' paragraph after "**The hosts.**" (293-302), the seven "Pre-switch check" lines over base :333-335 (306-312; :336 unchanged), "The host CA" over base :632-637 (316-461); enroll-user.md item 4a between item 4 and `**5. The costs.**` with one blank line before and after (506-535); machine-identities.md the paragraph after the ssh login line with one blank line before and after (539-546); signer-install.md base :602-603 replaced by the four dictated lines (550-553), :604-612 unchanged. The dictated line breaks were kept as the plan has them (deviation 4).
- The three edits whose words the plan gives as a sentence but not as wrapped lines, wrapped at most 74 columns (deviation 4):
  - "Run in CI": `TestHostCARotation` joins the list after `TestCARotationNoFailedLogin`'s parenthesis with a comma and nothing else: `` key, the drain and the host's drop), `TestHostCARotation` (the same `` / `job: what the host CA's gate prevents, a client that refreshed and one` / `` that did not across the host's renewal), with `TestCANextAndAbort`, ``.
  - "Run in CI": the UNVERIFIED sentence as dictated, base :695-697 re-filled: `real hosts of a fleet, the machine CA, the host drain's end on a real` / `host and client (unit-tested only), every physical TPM, the homelab` / `vTPM signer, every YubiKey, and every homelab signer; a real client run` / `is 03-16's.`
  - "What changes for nobody": the dictated sentence after the user-role sentence, base :745 re-filled: `hosts trust the old key until its end. A switch of the host role needs` / `no configuration change either, but a client must have refreshed` / `first, as "The host CA" says.`
- Widths: no added line is over its file's figure but the dictated signer-install.md line of 75 columns (its figure is 75). Carriage returns: 0 in each of the four files.
- The third verify command on the W3 tree (before the commit, the tree that was then committed; the four documents' sha256 equal to the scratch copies tested with R3): exit 0; every runbook test of its `-run` pattern passed (TestCARotationSwitchRunbook, TestHostTrustRunbooks, TestCARotationBackendSteps and the rest), `ok`, and `0 issues.` for linux, windows and darwin.
- Staged by path: the four runbooks. `git diff --cached` of each was read in full, one file at a time, after the last edit and before the commit.
- The staged-lines scan: exit 0.
- Commit 136163f6da3f70081c48cd4e358e89ff84d90e9e `docs(runbooks): state the host-CA rotation gate, who can refresh, and what a client that never refreshes meets`, signed (SSH signature present), author Daniel Gustafsson, committer keyroster-bot; four files, no deletion.
- The first verify command (R3 and W3 filled): exit 0. The fourth verify command (R3 and W3 filled): exit 0.

- An extra run, not a plan gate: `go test -count=1 -timeout 15m ./cmd/keyroster/ ./internal/...` through scripts/linux.sh on the W3 tree before the commit, in the background: exit 0, 34 packages `ok` (cmd/keyroster 96.171 s), so no test outside the third verify command's `-run` pattern reads the changed runbooks and fails.

### The document mutants

Under the mutant rule, at W3 (136163f6da3f70081c48cd4e358e89ff84d90e9e), each with Task 3's command `bash scripts/linux.sh 'exec 2>&1; go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -v -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/'`, one command per call.

- **Unmutated control** (the same command, the tree at W3, `git status --short -- cmd internal test docs .github` empty): exit 0, every leaf of both tests `--- PASS`, `ok  	github.com/Labontese/keyroster/cmd/keyroster	1.284s`.
- **The driver.** A small script outside the repository, one mutant at a time: it checks that the tree under cmd, internal, test, docs and .github is clean, takes the file's sha256, applies the mutant as one replacement of the raw (wrapped) text (the plan's span with each run of white space matching a run of white space or a line break, a blockquote marker as well for M392's header span, and M397 as the exact seven lines replaced by the base's exact three), after asserting that the span occurs exactly once in the file (all 70 checked before the first run, and again at each apply), runs the command, restores with `git checkout -- <file>`, compares the sha256 with the one before and requires `git status --short -- cmd internal test docs .github` to be empty, and stops at once on a build or setup failure, a SKIP, a timeout, a missing top-level test line, a restore whose sha256 differs or a non-empty status. For "the sentence that starts X deleted" and "the paragraph deleted", the span was written out from W3's text as the whole sentence or paragraph (with its one separating space or blank line). Each mutant's result (its FAIL lines and every message) was read; the table below holds them all.
- **Result: 70 of 70 killed by their named leaf, each with exactly the expected FAIL lines and no other** (the parent test's FAIL line plus `host_ca_gate`, `no_plan_numbers` or `enroll_user_trusting_hosts`; for M398 also `required_phrases`, as the plan expects). No survivor, no kill by another leaf, no further FAIL line, no `[build failed]`, `[setup failed]`, `--- SKIP` or timeout. `go vet ./cmd/keyroster/` ran first in every call and passed (the command's `&&`).
- **Restores:** after every mutant the file's sha256 equalled the one before (ca-rotation.md e7c403fce0870242081e0689f5064162226d4455ce04aa29bebd4b97a0002eb0, enroll-user.md 1e9044f0de43a1bdeab61ecbd2ccf4d07a6701515cf422ae7ccec3767a53362f, machine-identities.md f924aa824ce78688eb2578f020adac5b0567686c290b0d3236e3b886ca68f06b, signer-install.md 82a68d39cf630a7825a2c448426124c3f9fea441fae8ab5bb36a216d39166310, each as at W3) and `git status --short -- cmd internal test docs .github` was empty.
- **M352's definition:** M352 is defined in this plan alone; the planning brief's M352 row is the earlier text of the same mutant, not a second definition.

**No file is left in a mutant state.** After the last mutant the four runbooks hash as at W3 (`git hash-object` equals W3's blob for each) and `git status --short -- cmd internal test docs .github` is empty.

| Mutant | File | FAIL lines (each with its parent) | Messages that fired |
|---|---|---|---|
| M352 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "no earlier than ceremony 1's install plus the user profile's max TTL"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "of the policy in force at ceremony 1's install and of every policy installed since" |
| M361 | ca-rotation.md | `no_plan_numbers` | runbook_test.go:1129 ca-rotation.md names plan 03-12f2 outside a code span; describe the rotation in its end state |
| M362 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "cannot be rotated safely" |
| M368 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "is refreshed only by an admin who runs `keyroster known-hosts sync` as that account after ceremony 1's install and before ceremony 2's install"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "who then checks that account's file for the line"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "it is a client that never refreshes"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "no test runs sync for another account" |
| M369 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "No tool counts the clients that have refreshed"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "the gate is the operator's" |
| M370 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "at least the user profile's max TTL after ceremony 1's install"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "a user who always passes `--no-known-hosts` included"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "gets the line from an admin who runs `keyroster known-hosts sync` as that account"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "`bundle v<N> on <M>/<M> hosts` for the server's current bundle N"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "ceremony 1's or a later one that still lists the new host CA"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "no earlier than the gate of \"The host CA\" allows"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "of every account whose ssh reads the managed files holds the new host CA's line" |
| M374 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "It needs an admin key from the root-signed policy, loaded in ssh-agent" |
| M375 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "The file shows whether it wrote the line"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "the login succeeds whatever its host trust outcome"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "one that ran with `--no-known-hosts` adds no host CA line: it only narrows the file" |
| M376 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "one that ran with `--no-known-hosts` adds no host CA line: it only narrows the file" |
| M377 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "(a bundle installed in between still lists it when its ceremony printed no `CA host` line"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "`bundle v<N> on <X>/<M> hosts` of `keyroster host status`"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "a host removed from the directory stays in M until `keyroster host forget`" |
| M378 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "uses the host profile's `max_ttl_seconds`" |
| M379 | machine-identities.md | `host_ca_gate` | runbook_test.go:1255 machine-identities.md "Renew a machine certificate" lacks "`keyroster machine renew` does not refresh the host trust files"; runbook_test.go:1255 machine-identities.md "Renew a machine certificate" lacks "is refreshed only by an admin who runs"; runbook_test.go:1255 machine-identities.md "Renew a machine certificate" lacks "checked by the new host CA's line in that account's"; runbook_test.go:1255 machine-identities.md "Renew a machine certificate" lacks "after ceremony 1's install and before ceremony 2's install" |
| M380 | signer-install.md | `host_ca_gate` | runbook_test.go:1255 signer-install.md "Install a CA switch" lacks "for the host role by the clients, and by the agents, which accept host certificates signed by it until then"; runbook_test.go:1260 signer-install.md "Install a CA switch" still holds "trusted by hosts until" |
| M381 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "after ceremony 1's install and before ceremony 2's install" |
| M382 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "unless the agent replaces it earlier" |
| M383 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "The gate concerns every account whose ssh reads keyroster's managed trust files" |
| M384 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "The wait does not show that a login refreshed" |
| M385 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "refuses the certificate the signer issues it after the switch (`answer_unpinned_ca`"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "`TestDecide/backoff_schedule`" |
| M386 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "Watching for failures right after the switch shows little" |
| M387 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "No file that sshd reads lists a host CA key"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "removes its line from `keyroster_known_hosts` once its `trusted_until` has passed on the client's clock"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "each agent stops accepting answers signed by it at its `trusted_until`"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "key's `trusted_until`, the earliest moment a client stops trusting it" |
| M388 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "and a sync run for another account" |
| M389 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "at most about 20 days after the switch, and for many hosts sooner" |
| M390 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "The test does not wait the gate's time" |
| M391 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "What changes for nobody" lacks "a client must have refreshed first" |
| M392 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md before its first "## " line lacks "`TestHostCARotation` for what the host CA's gate prevents" |
| M393 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "Run in CI" lacks "`TestHostCARotation` (the same job: what the host CA's gate prevents" |
| M394 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "an account has refreshed once its managed `keyroster_known_hosts` holds the new host CA's line" |
| M395 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "at most about 20 days after the switch" |
| M396 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "of every account whose ssh reads the managed files holds the new host CA's line" |
| M397 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "`keyroster ca issue --ca host` lives as long as its `--ttl`, up to the host profile's `max_ttl_seconds`, which the floor of \"Ceremony 2\" covers"; runbook_test.go:1255 ca-rotation.md "Before ceremony 2" lacks "lies past a role's floor only when a certificate was issued under an earlier policy whose cap for its role was larger"; runbook_test.go:1260 ca-rotation.md "Before ceremony 2" still holds "has no cap on its validity"; runbook_test.go:1260 ca-rotation.md "Before ceremony 2" still holds "can make the switch of the host role wait" |
| M398 | ca-rotation.md | `host_ca_gate`, `required_phrases` | runbook_test.go:1108 ca-rotation.md lacks "clients have refreshed"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "clients have refreshed" |
| M399 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "into the `~/.ssh` of the account they run as"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "before its first Host or Match line" |
| M400 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "Such an account gains a host CA line only when it refreshes"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "one `@cert-authority` line for each host CA the trust bundle trusts at the client's clock" |
| M401 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "An account that never had these files keeps its own configuration" |
| M402 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "every user certificate issued before ceremony 1's install under the policy then in force has expired"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "one issued before the install under an earlier policy with a larger user cap may still be valid"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "so a user whose only certificates were issued before that install under the policy then in force needs a new one, from a login or from an admin" |
| M403 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "Before ceremony 2's install, every account whose ssh reads the managed files has refreshed"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "a user who always passes `--no-known-hosts` included" |
| M404 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "run as the account ssh runs as and on the computer it runs from" |
| M405 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "A user who always passes `--no-known-hosts` runs one `keyroster login` without it" |
| M406 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "which exits 0 when it refreshed"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "the file, not the exit, shows the new line" |
| M407 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "which a bundle that changes only the host role leaves as it is" |
| M408 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "no test shows a kept certificate surviving that refusal" |
| M409 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "until it takes that bundle or the old certificate runs out, after which clients refuse it" |
| M410 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "each host whose certificate keyroster-agent renews keeps serving its certificate by the old host CA" |
| M411 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "A certificate the agent obtains lives the smaller of 30 days and the host cap" |
| M412 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "moves to the new host CA only when an admin issues it a new one after the switch"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "no test issues a host certificate by hand across a host-CA switch" |
| M413 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "holds both host CA lines and accepts either certificate" |
| M414 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "holds only the old host CA's line: it reaches each host until that host moves"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "`Host key verification failed` from then on" |
| M415 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "is never rewritten by a full refresh cannot be rotated safely" |
| M416 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "each agent stops accepting answers signed by it at its `trusted_until`" |
| M417 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "key's `trusted_until`, the earliest moment a client stops trusting it" |
| M418 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "Run in CI: `TestHostCARotation`" |
| M419 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "waits for the host's heartbeat to report ceremony 1's bundle before the switch" |
| M420 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "the host asks for no certificate, installs no other and its agent refuses no answer"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "is refused with `Host key verification failed` after the renewal" |
| M421 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "the host drain's end on a real host and client" |
| M422 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1260 ca-rotation.md "The host CA" still holds "UNVERIFIED until" |
| M423 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "Run in CI" lacks "the host drain's end on a real host and client" |
| M424 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1260 ca-rotation.md "Run in CI" still holds "the host CA end to end" |
| M425 | machine-identities.md | `host_ca_gate` | runbook_test.go:1255 machine-identities.md "Renew a machine certificate" lacks "after ceremony 1's install and before ceremony 2's install"; runbook_test.go:1260 machine-identities.md "Renew a machine certificate" still holds "before a host-CA rotation" |
| M426 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "T-03-417" |
| M427 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "only through a refresh"; hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "an account has refreshed once its managed `keyroster_known_hosts` holds the new host CA's line"; hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "narrowing never adds one" |
| M428 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "Each host whose certificate keyroster-agent renews" |
| M429 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "moves only when an admin issues it a new certificate" |
| M430 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "refuses each host from that host's move on" |
| M431 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "`TestHostCARotation`" |
| M432 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "UNVERIFIED on a real client and on Windows" |
| M433 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "so a user whose only certificates were issued before that install under the policy then in force needs a new one, from a login or from an admin" |
| M434 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "An account has refreshed when its managed `~/.ssh/keyroster_known_hosts` holds the new host CA's line"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "the `@cert-authority` line that ends `keyroster host CA generation <g>`" |
| M435 | ca-rotation.md | `host_ca_gate` | runbook_test.go:1255 ca-rotation.md "The host CA" lacks "Whichever way, the line is the check"; runbook_test.go:1255 ca-rotation.md "The host CA" lacks "so a refresh that wrote only the old line is repeated until the file holds the new one" |
| M436 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "and the file then holds the new host CA's line" |
| M437 | enroll-user.md | `enroll_user_trusting_hosts` | hosttrust_runbook_test.go:123 item 4a, host-CA rotation lacks "so a refresh that wrote only the old line is repeated" |

## Task 4 (session 3): the publication, the gates, the PR and the tracking update

**The orchestrator's corrections, first.** Before anything else in session 3, the orchestrator's twelve corrections to the draft were applied by its script, which refuses unless each old text occurs exactly once: a dry run reported 12 replacements, then the applied run wrote them; the draft went from 52,456 bytes (sha256 eca08fab63ec7eeca530c42e7f7487e06fe3408deb1548fea4d63490d5263788) to 58,339 bytes (sha256 d799e04d4269f1978daad08c7083a9c168e67e0cf6a4603ffcfd9cc4d3cb133a), the expected values. The corrected sentences stand word for word.

**Precondition** (2026-11-22): HEAD was W3 136163f6da3f70081c48cd4e358e89ff84d90e9e on `p03/12f2-ca-rotation-host-ca-e2e`, equal to the remote head; after `git fetch origin`, origin/main was still BASE c6c632d130450e24fe432dfd68bcf00420dc2231; Task 1's first three checks (plan lines 673, 675 and 677, each extracted byte for byte from the plan file read in binary mode; `D` filled with the dispatch's sha256, the placeholder asserted present once before and gone after) exit 0, the third printing `stopped_at: "Completed 03-12f-PLAN.md (PR #113)"`. Every verify command of Task 4 (plan lines 922 to 942) was extracted the same way and is run unchanged from the repository's root, with the owner's two pattern files named through their variables on the command line where a command reads them; which of them ran before this SUMMARY's first commit and which after its push is under "Verify commands of Task 4".

### P4 (4e058f8)

- The placement check and the stop guard were run again first: exit 0.
- Only 03-12f2-PLAN.md was staged; `git show :<path> | sha256sum` equals the `plan file sha256:` line above (8e735928...).
- The staged diff (1,498 lines; 1,316 insertions and 82 deletions) was saved to a file outside the repository, folded at 1,400 columns (1,541 lines) and read whole, every added, removed and context line, after the last edit.
- The publish scan: the seventh verify command, run verbatim and in full (deviation 7), exited 0 before the commit; its whole-file legs on the plan file are its first legs. After the commit it was run again, its `git cat-file` leg then reading the new text at HEAD: exit 0.
- Committed signed, authored as Daniel; one file, no deletion. The plan file at HEAD hashes to the dispatch's value.

### Gates

- **The base**, re-measured first (see "Task 1"): `keyroster=281.238 at=1795377427`.
- **The delta gate** (the fifth verify command, in the background, nothing else running in WSL): exit 0, `ok  	github.com/Labontese/keyroster/cmd/keyroster	289.999s`, +8.761 s over the base, no FAIL or DATA RACE. That is under +60 s, so no warning, and above the plan's expected +0 to +3 s; the package's own spread is wider than the difference (session 1's base read 299.632 s, and the package read 343.085 s and 326.803 s in the two whole-module runs below).
- **The full gate** (the sixth verify command, in the background, nothing else running in WSL). The first run exited 1 after 719 s: in internal/signer, `--- FAIL: TestCheckLogAgainstLiveSigner (0.30s)` with `log_test.go:454: unavailable: clock_regression` (`FAIL	github.com/Labontese/keyroster/internal/signer	555.241s`), the other 35 packages `ok`; the command's chain stops at a failing `go test`, so vet, gofmt, lint, capslock and the firewalls did not run in it. The message names `clock_regression`, so the run was repeated once unchanged under the plan's rule for clock flakes (deviation 6): exit 0 after 861 s, 36 `ok` lines (internal/signer 463.152 s, cmd/keyroster 326.803 s), no FAIL, DATA RACE or SKIP; every `go vet` tag set clean; gofmt clean; golangci-lint `0 issues.` under linux, windows, darwin and the `e2e,e2erotation` pass on the new lines; capslock v0.3.3: keyroster-signer 97 pairs (baseline 97), keyroster-agent 37 (37), keyroster-agent-fetch 23 (23), no pair new against a baseline; dep-firewall clean (EXEC leaves keyroster-agent only through internal/agent/execsite; `os/exec <- modernc.org/libc` the documented exception for keyroster-signer; no banned packages); testonly-firewall clean (6 GOOS/tag combinations); check-pinned-actions: all 55 `uses:` references pinned to commit SHAs.

### Push and the PR

- Before the push: `git fetch origin` (origin/main still c6c632d), the eighth verify command (authorship) exit 0 and the seventh (the publish scan) exit 0. `env -u GITHUB_TOKEN -u GH_TOKEN git push -u origin p03/12f2-ca-rotation-host-ca-e2e`: 136163f..4e058f8, accepted by the pre-push hook.
- **PR #118** (https://github.com/Labontese/keyroster/pull/118), opened by keyroster-bot through scripts/gh-as-bot.sh, base main, title `test(e2e): prove the host-CA rotation gate against real sshd and real clients`, auto-merge off (`autoMergeRequest` null). Its body holds the plan's lines of step 2, each on one line, under "Changes" and "Limits"; it was written to a file outside the repository, scanned before use (refused words, dotted quads, the owner's patterns, CR bytes, attribution lines: clean) and passed with `--body-file`; the body GitHub holds equals the file.
- CI runs for head 4e058f8 (pull_request) that existed when this SUMMARY was written: CI 45067000825, E2E 45067000928, E2E TPM 45067000784, PIV 45067000794, E2E distro 45067000821, E2E PKCS#11 45067000805, Systemd 45067000964, CodeQL 45067000764, Workflow lint 45067000802 (success), PR title 45067000919 (success). The runs for this SUMMARY's own commit cannot be named here; their IDs, the lane gate's output, the five lanes' `go test` times against the base readings, TestHostCARotation's duration in each rotation lane and the commit lags of bundles 2 and 3 from both CI lanes enter this SUMMARY with the review's record.

### The tracking update

After the PR existed, once: GSD's `state.advance-plan`, `state.update-progress` and `roadmap.update-plan-progress 3`, with ROADMAP.md and STATE.md copied outside the repository first and both diffs read in full afterwards.
- The commands wrote, in ROADMAP.md, exactly the three intended lines: `**Plans:** 40/44 plans executed in 43 waves.`, this plan's row ticked (`- [x] 03-12f2-PLAN.md — ...`) and `| 3. Linux Agent and Revocation | 40/44 | In Progress | - |`; and in STATE.md `completed_plans: 75`, `Plan: 40 of 44`, `last_updated` and `state_head` (4e058f8). `total_plans` stays 79; the percentage (17) and the progress bar did not change. The wave count and the plan total came out right, so no scoped edit was needed for them.
- One scoped edit: `stopped_at: "Completed 03-12f-PLAN.md (PR #113)"` became `stopped_at: "Completed 03-12f2-PLAN.md (PR #118)"`, the number read with `scripts/gh-as-bot.sh pr view p03/12f2-ca-rotation-host-ca-e2e --json number --jq .number`.
- Of the 44 Phase 3 rows `- [.] 03-`, only 03-12f2's differs from the copy (03-12f's deviation 20 did not recur here: no other row starts with `03-12f2`). Neither file holds a carriage return. REQUIREMENTS.md is not touched: KEY-08 completes in 03-13. GSD also rewrote the untracked `.planning/state.json`, which is never staged.
- Totals after the update: `**Plans:** 40/44 plans executed in 43 waves.`, `| 3. Linux Agent and Revocation | 40/44 |`, `total_plans: 79`, `completed_plans: 75`, `Plan: 40 of 44`, `stopped_at: "Completed 03-12f2-PLAN.md (PR #118)"`.

### This commit

Staged by path: .planning/ROADMAP.md, .planning/STATE.md and this SUMMARY. `git diff --cached` of each was read in full, one file at a time, after the last edit; the staged-lines scan of plan line 902 (the owner's two pattern files passed through their variables) exited 0 before the commit.

### Verify commands of Task 4

- Before this commit: the 5th (delta gate) exited 0; the 6th (full gate) exited 0 on its second run (deviation 6); the 7th (publish scan) exited 0 before P4, after P4 and before the push; the 8th (authorship) exited 0 before the push.
- The 1st (required checks, the five named checks and the house e2e gate in MODE=pr), the 2nd (the lane gate), the 3rd (ROADMAP and STATE), the 4th (files, plan bytes, mutant and threat rows) and the 9th to 11th run on this commit's head after its push; their results cannot be named in the commit they are about and enter this SUMMARY with the review's record. Nothing outside .planning changed after the 5th and the 6th, so they need no second run.
- Since then: session 3 ran the 1st to 4th and the 9th to 11th on head 4869fde after its push and CI. Its saved logs show two things: the 1st exited 0 (its log lists every required check as `pass`, names the E2E run 45067471042 and both probe lanes' `go test` times, 300.039 s and 281.009 s, and ends `exit 0`); and the 2nd's readings of the four rotation and main lanes (`go test` 660.758 s, 657.877 s, 737.658 s and 773.829 s), with no exit code in that log. The 2nd's exit code and the results of the 3rd, 4th, 9th, 10th and 11th exist only as that session's report: no log of them was saved. The fix round changed files outside .planning, so the 5th and the 6th ran again in part B (under "The fix round"), and every verify command of Task 4 runs again on the fix round's head after its push and CI, with the results in the orchestrator's record, because a commit cannot name its own runs.

### What stays UNVERIFIED (in the words of the plan)

> The test proves the gate's failure and success on one host and two clients on loopback, against OpenSSH 9.5p1 and 10.5p1 built by the lane. UNVERIFIED after it: the host drain's end on a real host and client (unit-tested only), a real fleet, a client on Windows, clients older than OpenSSH 8.5, real clients that never refresh, a `known-hosts sync` that an admin runs for another account, a host that has not taken the bundle naming the new host CA when it renews (unit-tested only, and no test shows that it keeps its certificate through that refusal), and a host certificate issued by hand with `keyroster ca issue --ca host` across a host-CA switch; 03-16 runs a real client.

The test does not wait for the gate's own time (the user profile's max TTL): it shows what the gate prevents, not the wait. No tool counts refreshed clients, so whether a fleet's clients have refreshed is the operator's to know.

## Pre-merge review

**The run.** On 2026-11-22 the orchestrator had the green PR read at head 4869fde5904361f44e8d71ea13b90a716841ccee against base c6c632d130450e24fe432dfd68bcf00420dc2231 (workflow wf_42dd7384-2bf: seven agents, 1,249,643 tokens, 255 tool calls, about 21 minutes). Before it the orchestrator ran TestHostCARotation once from a plain copy of that head's tree, through the namespace wrapper, on OpenSSH 10.5p1: PASS in 143.38 s. The readers, each read-only on a detached worktree of the head:

- **The test** (Opus, high effort): the test, its helpers, the lane and both rotation job logs. It ran the test twice on a private copy of the tree, each time with a mutant of its own (below).
- **The runbook text** (Opus, high effort): the changed sections of the four runbooks against the code, the pins and the sweep. It ran eight document mutants of its own on a private copy.
- **This record** (Sonnet, high effort): this SUMMARY's text on Tasks 3 and 4, the commits table and the PR text against the saved logs, the git log and the job logs.
- **Codex** (gpt-6-astra, high effort; 324 s, 143,975 tokens), started by a thin runner agent (Sonnet, low effort): the diff outside .planning and the PR text.
- **The skeptics** (Sonnet, high effort): two for the one item rated high, one batch skeptic for the other fourteen.

**Results: 15 items; 8 upheld, none split, 7 refuted.** None says that the test passes while a client that did not refresh is accepted, and none is about product code. One item came from the test reader, ten from the runbook reader, two from the record reader and two from Codex. The batch skeptic upheld eight and rated each of them low (the readers had rated five of them medium).

Upheld, and acted on in the fix round below:

1. (Codex) The item-4a pin read the whole of enroll-user.md, so the paragraph could leave its section unnoticed.
2. (Runbook reader; its mutants Ma2 and Mb survived) Item 4a's two mentions of the admin were held by no pin.
3. (Runbook reader; its mutant Mh survived) "the largest user `max_ttl_seconds`" in the gate's wait was held by no pin: "smallest" passed.
4. (Runbook reader; its mutant Mc survived) The first refresh route, "A user refreshes with a `keyroster login` without `--no-known-hosts`", was held by no pin.
5. (Runbook reader) Item 4a stated a hand-issued host's move with no UNVERIFIED label, beside its "Run in CI" line.
6. (Runbook reader; its mutants Mp and Mg survived) Four entries of the UNVERIFIED list of "The host CA" and the words "possibly weeks after the switch" were held by no pin.
7. (Runbook reader) signer-install.md, in the subsection this plan corrected, still said that the switch binding keeps a certificate from outliving "the hosts' trust" in the old key, which is false for the host role; the plan's sweep had not listed that sentence.
8. (Record reader) The folded staged diff of P4 has 1,541 lines, not 1,542.

Refuted:

9. (Codex, rated high; both skeptics refuted it) A renewal request made after the quiet check at r1 + 45 s and before the scheduled renewal's earliest moment at r1 + 52 s is not told apart from a scheduled one.
10. (Test reader, rated medium; its mutant MN survived) Client A is not checked between the first keyroster command after the switch, which narrows its file, and the host's renewal.
11. (Runbook reader, rated medium) The route "an admin runs `keyroster known-hosts sync` as that account" names no flag and does not say what that run opens to the account.
12. (Runbook reader) machine-identities.md gives that route with no UNVERIFIED label of its own.
13. (Runbook reader) Only the login route says that a refresh is per computer.
14. (Runbook reader) The corrected "Pre-switch check" sentence ("only when") does not hold when the ceremony machine's clock is behind the signer's.
15. (Record reader) Deviation 6 states the cause of the first full-gate failure where the log shows the error's name.

**The test reader's two mutants** (each one run of the test on OpenSSH 10.5p1, on its private copy):

- MF, a host that asks at the switch with its trust set intact (`hostcert.Due` renews whenever a draining host CA is in force): killed by step 6a's attempts check (the call at hostca_rotation_test.go:619 of that head, the check at :231) with `step 6a: the host asked for a certificate at 2026-11-22T21:42:30Z, after r1's issuance 1795383744`, the attempts file holding `failures` 1 and `last_code` `answer_not_newer`. It is a second product mutant, beside M373, that this check kills.
- MN, narrowing that drops a draining host CA's line at once (cmd/keyroster/narrow.go made to skip draining entries): **it survived**, PASS in 130.87 s, with client A's live file holding one CA line after the bundle-3 commit. That is item 10.

**Rulings (the orchestrator).**

- Items 1 to 8 are acted on.
- Item 10 is taken up although refuted. The survivor is a fact, and that a client which refreshed keeps reaching a host that still serves the old host CA's certificate is the gate's promise to the operator. The skeptic's reasons stand as far as they go: narrowing's handling of a draining host CA is unit-tested in cmd/keyroster, and the plan's step table does not name this misbehaviour. The test gains one login of client A in step 6a.
- Item 11 is taken up although refuted. The route is the orchestrator's own ruling of 2026-11-21, and by the code the account reaches an ssh-agent that holds the admin key for that run: `known-hosts sync` opens an admin session (cmd/keyroster/knownhosts.go:1059), which finds the key named by `--admin-key` in the agent at `SSH_AUTH_SOCK` (cmd/keyroster/user.go:203-224, agentconn_unix.go:12-17), and a `$HOME` that is not the account's home is refused (knownhosts.go:120-141), so the command runs as that account. "The host CA" now says what follows from that.
- Items 12 and 13 are taken up although refuted, each with one sentence: the label, as in item 5, and the check of the file on each computer.
- Item 9 stands refuted, no change. Its mechanics are as Codex says, but the misbehaviour that step 6a names is a request at the switch, which M373 and MF show caught; the agent's own schedule is unit-tested (`TestDecide`, `TestJitter`), and the issuance gap of 51 s to 75 s bounds the rest.
- Items 14 and 15 stand refuted, no change: for item 14 the text's instruction is to wait in either case, and for item 15 `clock_regression` is the signer's own name for a clock that read earlier than before.

**Not checked by that run.** The CI runners' wall clock against their monotonic clock, and OpenSSH's penalty thresholds on runners; signer-install.md and enroll-user.md outside the sections around this plan's edits (the runbook reader read those two files in sections); the plan's anchors line by line (the runbook reader opened the code instead, and the record reader compared about 12 of the 196); the run IDs of head 4e058f8 (the record reader had no access to them); and what this record says without a saved log (that staged diffs were read in full, and the lint and vet legs inside verify commands). The skeptics were brief (36 s and 42 s for the item rated high, 86 s for the other fourteen), so the orchestrator read every item itself and checked in the files what it relies on: items 1, 7 and 8, the code behind item 11, and the helpers of step 6a for item 10.

### The fix round

The fix round ran in session 4 (2026-11-22 and 2026-11-23), in three parts: part A (X1 to X3) and part A2 (X4 to X6) as local commits, each read and checked by the orchestrator before the next part; part B (this record, the gates, the push). No product code changed in it: every product mutant was restored before anything else happened.

**The six commits**, each signed (SSH signature present), authored as Daniel Gustafsson, committed by keyroster-bot, with no message body. Before each, `git diff --cached` of every staged file was read in full, one file at a time, after the last edit (for X6 see deviation 10), and the staged-lines scan of plan line 902 (the owner's two pattern files passed through their variables) exited 0.

| Name | SHA | Subject | Files |
|------|-----|---------|-------|
| X1 | c824af94bfda26cf8cddcb4f8681548a929c1074 | test(cli): pin the rest of the host-CA gate and hold item 4a to its section | cmd/keyroster/runbook_test.go, cmd/keyroster/hosttrust_runbook_test.go |
| X2 | 029da1b17bb0606417ddffa5b4197f1124b05d49 | docs(runbooks): say what an admin's sync for another account opens, and label what no test shows | docs/runbooks/ca-rotation.md, enroll-user.md, machine-identities.md, signer-install.md |
| X3 | 459b8260b4e204cbad0702c1f293796efaff5956 | test(e2e): log the refreshed client in after the host committed the host-CA switch | test/e2e/hostca_rotation_test.go |
| X4 | ace104b28c5cd20820ae8ce5cd8e805b49d500bd | test(cli): pin the UNVERIFIED labels with their sentences and item 4a between its neighbours | cmd/keyroster/runbook_test.go, cmd/keyroster/hosttrust_runbook_test.go |
| X5 | 80fd108431eef948da72603eb1f2217f17dddfc6 | docs(runbooks): say what the admin's agent signs and what one admin signature authorises | docs/runbooks/ca-rotation.md |
| X6 | 85d0ec4206e31d6295a25b069f564420c019df97 | test(e2e): say which polls narrowed the file and name a late login | test/e2e/hostca_rotation_test.go |

**The items and what each answers** (the review's items are numbered as above; the round check's as under "The check of the fix round"):
- F1 (review item 1): the item-4a pin reads the section "Trusting hosts without TOFU", not the whole file; `**4a. ` must occur once there and `**5. The costs.**` follow it (X1).
- F2 (item 2): two more item-4a tokens, the admin's sync in the item's first sentence and in its last but one (X1).
- F3 (item 3): the gate's wait pinned from `the largest user `max_ttl_seconds`` on (X1).
- F4 (item 4): the first refresh route pinned (X1); G1 completes it.
- F5 (item 6): the UNVERIFIED list of "The host CA" and `possibly weeks after the switch, until it refreshes` pinned (X1).
- F6 (item 5): item 4a's UNVERIFIED sentence also names a host certificate issued by hand across a host-CA switch (X1 pin, X2 text).
- F7 (item 7): signer-install.md says `outlives the trust in that key`, and `the hosts' trust in it` is a forbidden phrase (X1 pin, X2 text).
- F8 (item 12): machine-identities.md labels the admin's sync for another account UNVERIFIED (X1 pin, X2 text).
- F9 (item 11): "The host CA" says what that sync opens to the account: it signs with the admin key through the ssh-agent the account reaches, given with `--admin-key`, and every process of the account can ask that agent to sign (X1 pin, X2 text); G5 and G6 complete it.
- F10 (item 13): an account that runs ssh from several computers has refreshed when the file on each of them holds the line (X1 pin, X2 text).
- F11 (item 10): step 6a logs client A in once more, between the drop-in check and the keyscan, after the commit wait's host status polls have narrowed its live file (X3).
- Review item 8 (the folded P4 diff has 1,541 lines) is corrected in "P4" above.
- G1 (the orchestrator's own: F4's pin stopped before the flag): the route's pin ends with ``without `--no-known-hosts` `` (X4).
- G2 (the round check's item 1): every UNVERIFIED statement of the windows is pinned together with its label: item 4a's one sentence, "The host CA"'s list, its three bracketed labels and the label after `hostcert_answer_drained_ca_refused`, and "Run in CI"'s sentence (X4).
- G3 (its item 3): F7's phrase is the whole clause `so that no certificate the signer issued under the old key outlives the trust in that key` (X4).
- G4 (its item 4): item 4's marker `**4. ` must occur once in the section and come before `**4a. ` (X4).
- G5 and G6 (its item 2): the sentence says that the agent signs with any key it holds, that at an admin quorum of 1, the default, one admin signature authorises a new directory, and that the agent should hold the admin key alone (X4 pins, X5 text).
- G7 (its item 5): the two comments of step 6a say only what the code shows (deviation 9), and a login that returns after r1 + 50 s fails with a message of its own (X6).

**The REDs.**
- At X1 (HEAD X1, `git status --short -- cmd internal test docs .github` empty; part A's RED command `bash scripts/linux.sh 'exec 2>&1; go test -count=1 -timeout 15m -v -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/'`): exactly `--- FAIL: TestCARotationSwitchRunbook`, `--- FAIL: TestCARotationSwitchRunbook/host_ca_gate`, `--- FAIL: TestHostTrustRunbooks` and `--- FAIL: TestHostTrustRunbooks/enroll_user_trusting_hosts`, with nine messages: `hosttrust_runbook_test.go:132: item 4a, host-CA rotation lacks "and a host certificate issued by hand across a host-CA switch"` (F6); at runbook_test.go:1264 seven `lacks`, five of "The host CA" (F10's sentence and F9's four phrases), machine-identities.md's `UNVERIFIED: no test runs sync for another account` (F8) and signer-install.md's `outlives the trust in that key` (F7); and `runbook_test.go:1269: signer-install.md "Install a CA switch" still holds "the hosts' trust in it"` (F7). The F1 to F5 pins passed on the unchanged text. Controls: every other leaf of both tests passed. No build failure, setup failure or SKIP.
- At X4 (HEAD X4, the status empty; the same command): exactly `--- FAIL: TestCARotationSwitchRunbook` and `--- FAIL: TestCARotationSwitchRunbook/host_ca_gate`, with three messages, `runbook_test.go:1264: ca-rotation.md "The host CA" lacks` `every one of its processes can ask it to sign with any key it holds`, `at an admin quorum of 1, the default, one admin signature authorises a new directory` and `use an agent that holds the admin key alone, run the sync while nothing else runs as that account, and end the agent's reach right after` (G5). TestHostTrustRunbooks passed with all six leaves (G2's token and G4's check held on the text as it was), and so did the other six leaves of TestCARotationSwitchRunbook. No build failure, setup failure or SKIP. (The same command was also run once on X4's staged tree before its commit, with the same three messages.)

**The text and the GREEN runs.** X2 and X5 were applied by the orchestrator's applier (a dry run, then `--apply`; it refuses unless each old text occurs exactly once), from the repository's root, with nothing edited by hand; each `git diff` was read in full.
- X2: ca-rotation.md 51,430 bytes, sha256 7005d4c1371e91706cf2c6fb65da613b96678cdedc519c47f077db5c4b9678fa; enroll-user.md 46,799 bytes, a1cf47059d947cc8e1ac452cb12721d829ddb64b1a0a9d7e7794ec1ad1af0a56; machine-identities.md 13,279 bytes, 66a56ef1e8ddb191fcc7dbea9ece8bbc7adcdd1a19f6d97cc6236f6d04dd309a; signer-install.md 133,574 bytes, 5a3ad62726dc2eeddb79cdfb79ed362578fa6201e31fe9f28f35d593af4bdae3; no carriage return.
- X5: ca-rotation.md 51,578 bytes, sha256 c9ad26e38a9e81f9328111986b5a235cd17f587e92373df88cde08d5ff0e34bf; no carriage return.
- GREEN on X2's and on X5's tree: the RED command exited 0 with every leaf of both tests passing (15 PASS lines), and `bash scripts/linux.sh 'exec 2>&1; go test -count=1 -timeout 15m -run "Runbook|CARotation|HostTrust|SignerInstall|MoveAside|Restore|SecurityDocs|Docs" ./cmd/keyroster/'` printed `ok`.
- gofmt and `go vet ./cmd/keyroster/` were clean before X1 and X4; gofmt and `go vet -tags "e2e e2erotation" ./test/e2e/` before X3 and X6, and the plan's goroutine and `t.Parallel` grep found nothing in the test file.

**The document mutants.** Under the mutant rule, with `bash scripts/linux.sh 'exec 2>&1; go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -v -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/'`, the unmutated run first (at X2 and again at X5: exit 0, 15 PASS lines), then each mutant as one exact replacement of the raw text whose old text occurs exactly once (all checked before the first run and again at each apply), vet passing on the mutated tree, the file restored with `git checkout --`, its sha256 equal to the one before and `git status --short -- cmd internal test docs .github` empty after each. Each was killed by its named leaf with exactly the parent test's FAIL line and the leaf's, and no other FAIL, build failure, setup failure or SKIP. XM1 to XM20 ran at X2; XM21 to XM34 at X5. `gate` is TestCARotationSwitchRunbook/host_ca_gate, `item` is TestHostTrustRunbooks/enroll_user_trusting_hosts; the messages of XM1 to XM20 are those of the run at X2.

| Name | Item | File | Replacement | Leaf | Message |
|------|------|------|-------------|------|---------|
| XM1 | F1 | enroll-user.md | item 4a's paragraph moved to the end of the file (one replacement of the span from its marker to the end) | item | hosttrust_runbook_test.go:127 the section holds `**4a. ` 0 times, want once |
| XM2 | F1 | enroll-user.md | a second line `**4a. A second item 4a.** Added after item 5.` inserted after item 5's paragraph | item | :127 the section holds `**4a. ` 2 times, want once |
| XM3 | F2 | enroll-user.md | `or an admin's` becomes `or a` in item 4a | item | :132 lacks "a `keyroster login` without `--no-known-hosts` or an admin's `keyroster known-hosts sync` writes its `@cert-authority` line" |
| XM4 | F2 | enroll-user.md | `unless an admin runs` becomes `unless it runs` | item | :132 lacks "unless an admin runs `keyroster known-hosts sync` as that account" |
| XM5 | F2 | enroll-user.md | in item 4a, `` `keyroster login` without `` becomes `` `keyroster login` with `` (anchored on `only through a refresh: a`) | item | :132 lacks the F2 token of XM3 |
| XM6 | F3 | ca-rotation.md | `the largest user` becomes `the smallest user` | gate | runbook_test.go:1264 "The host CA" lacks the F3 phrase |
| XM7 | F4 | ca-rotation.md | the first refresh route's `without` becomes `with` (anchored on `A user refreshes with a`) | gate | :1264 "The host CA" lacks "A user refreshes with a `keyroster login` without" |
| XM8 | F5 | ca-rotation.md | `a client on Windows, clients older than OpenSSH 8.5, ` deleted from the UNVERIFIED list (with the line break inside it) | gate | :1264 "The host CA" lacks the F5 list phrase |
| XM9 | F5 | ca-rotation.md | `a real fleet, ` deleted there | gate | :1264 "The host CA" lacks the F5 list phrase |
| XM10 | F5 | ca-rotation.md | `possibly weeks after` becomes `right at` | gate | :1264 "The host CA" lacks "`Host key verification failed` from then on, possibly weeks after the switch, until it refreshes" |
| XM11 | F6 | enroll-user.md | ` and a host certificate issued by hand across a host-CA switch` deleted (with its line break) | item | :132 lacks "and a host certificate issued by hand across a host-CA switch" |
| XM12 | F7 | signer-install.md | `outlives the trust in that key` put back to `outlives the hosts' trust in it` | gate | :1264 lacks "outlives the trust in that key" and :1269 still holds "the hosts' trust in it" |
| XM13 | F8 | machine-identities.md | ` UNVERIFIED: no test runs sync for another account.` deleted | gate | :1264 machine-identities.md lacks "UNVERIFIED: no test runs sync for another account" |
| XM14 | F9 | ca-rotation.md | the sentence from `That sync signs` to `reach right after.` deleted | gate | :1264 four `lacks`, F9's four phrases |
| XM15 | F9 | ca-rotation.md | `every one of its processes can ask it to sign as the admin` becomes `no other process can use it` | gate | :1264 lacks "every one of its processes can ask it to sign as the admin" |
| XM16 | F9 | ca-rotation.md | `while nothing else runs as that account` becomes `at any time` | gate | :1264 lacks "run the sync while nothing else runs as that account, and end the agent's reach right after" |
| XM17 | F9 | ca-rotation.md | `` `--admin-key` `` becomes `` `--key` `` | gate | :1264 lacks "its fingerprint given with `--admin-key`" |
| XM18 | F10 | ca-rotation.md | the several-computers sentence deleted | gate | :1264 lacks the F10 sentence |
| XM19 | F10 | ca-rotation.md | `the file on each of them` becomes `the file on one of them` (`on each of them` alone also occurs at :247) | gate | :1264 lacks the F10 sentence |
| XM20 | F1 | enroll-user.md | item 4a moved after item 5 inside the section (an addition: the only mutant that reaches F1's second check) | item | :130 no `**5. The costs.**` follows it in the section |
| XM21 | G1 | ca-rotation.md | in the first refresh route, `--no-known-hosts` becomes `--known-hosts` | gate | :1264 lacks "A user refreshes with a `keyroster login` without `--no-known-hosts`" |
| XM22 | G2 | enroll-user.md | `, and so are a sync that an admin runs for another account and a host certificate` becomes `, and a host certificate` | item | hosttrust_runbook_test.go:137 lacks the merged UNVERIFIED token |
| XM23 | G2 | enroll-user.md | the two entries moved in front of the label: the sentence before it ends `clients on loopback), a sync that an admin runs for another account and a host certificate issued by hand across a host-CA switch.` and the label reads `UNVERIFIED on a real client and on Windows.` | item | :137 lacks the merged UNVERIFIED token |
| XM24 | G2 | ca-rotation.md | in "The host CA", `UNVERIFIED: the host drain's` becomes `It also shows the host drain's` | gate | :1264 "The host CA" lacks "UNVERIFIED: the host drain's end on a real host and client (unit-tested only), a real fleet, a client on Windows, clients older than OpenSSH 8.5, real clients that never refresh, and a sync run for another account" |
| XM25 | G2 | ca-rotation.md | `(UNVERIFIED: no test runs sync for another account.)` becomes `(No test runs sync for another account.)` | gate | :1264 lacks "(UNVERIFIED: no test runs sync for another account.)" |
| XM26 | G2 | ca-rotation.md | `(UNVERIFIED: no test shows` becomes `(no test shows` | gate | :1264 lacks "(UNVERIFIED: no test shows a kept certificate surviving that refusal)" |
| XM27 | G2 | ca-rotation.md | `(UNVERIFIED: no test issues` becomes `(no test issues` | gate | :1264 lacks "(UNVERIFIED: no test issues a host certificate by hand across a host-CA switch)" |
| XM28 | G2 | ca-rotation.md | `; UNVERIFIED end to end` deleted | gate | :1264 lacks "an answer by a host CA outside the agent's trusted set; UNVERIFIED end to end" |
| XM29 | G2 | ca-rotation.md | in "Run in CI", `UNVERIFIED: the drain on` becomes `Also run: the drain on` | gate | :1264 "Run in CI" lacks "UNVERIFIED: the drain on real hosts of a fleet, the machine CA, the host drain's end on a real host and client (unit-tested only)" |
| XM30 | G3 | signer-install.md | `so that no certificate the signer issued` becomes `so that a certificate the signer issued` | gate | :1264 lacks "so that no certificate the signer issued under the old key outlives the trust in that key" |
| XM31 | G4 | enroll-user.md | item 4a moved, whole, to before item 4 inside the section (one replacement of the span from item 4's marker to item 5's) | item | hosttrust_runbook_test.go:132 the section holds `**4. ` 1 times, want once and before `**4a. ` |
| XM32 | G5 | ca-rotation.md | `with any key it holds` becomes `with the admin key only` | gate | :1264 lacks "every one of its processes can ask it to sign with any key it holds" |
| XM33 | G6 | ca-rotation.md | `at an admin quorum of 1, the default, one admin signature` becomes `at any admin quorum, two admin signatures` | gate | :1264 lacks "at an admin quorum of 1, the default, one admin signature authorises a new directory" |
| XM34 | G5 | ca-rotation.md | `use an agent that holds the admin key alone, ` deleted | gate | :1264 lacks "use an agent that holds the admin key alone, run the sync while nothing else runs as that account, and end the agent's reach right after" |

XM1 to XM20 ran again at X5, each killed by its named leaf with exactly the expected FAIL lines (the hosttrust messages now at :128, :135 and :137, the runbook ones at :1264 and :1269). Two were adapted to X5's text, which changed the words they mutate: XM14 deletes X5's whole sentence, from `That sync signs` to `the agent's reach right after.`, and five `lacks` fire (F9's first two phrases and G5's three); XM15 turns `every one of its processes can ask it to sign with any key it holds` into `no other process can use it`. XM16 is unchanged and is now caught by G5's third phrase; XM7 by G1's phrase; XM8 and XM9 by G2's merged list; XM11 by G2's merged item-4a token. XM31's message names the count and the order in one sentence; it stays so (the orchestrator's ruling).

**The end-to-end runs**, each through the orchestrator's runner of the namespace wrapper (`-timeout 12m`, TestHostCARotation alone), in the background, one at a time, nothing else running in WSL.

| Tree | Build | Result | Test (s) | `go test` (s) | Step 6a's logged end | r1, r2 gap | Bundle 2, bundle 3 committed after the install (s) |
|------|-------|--------|----------|---------------|----------------------|------------|-----------------------------------------------------|
| X3 (deviation 8) | 10.5p1 | PASS | 155.03 | 188.691 | r1 + 43.157 s | 64 s, 54 s | 10.373, 10.844 |
| X3 (deviation 8) | 9.5p1 | PASS | 148.08 | 166.734 | r1 + 43.166 s | 55 s, 56 s | 10.159, 8.863 |
| X6 | 10.5p1 | PASS | 179.36 | 202.274 | r1 + 43.117 s | 62 s, 62 s | 10.665, 15.087 |
| X6 | 9.5p1 | PASS | 145.56 | 162.379 | r1 + 43.238 s | 56 s, 53 s | 10.219, 8.832 |

- In each passing run the new login's line names generation 1's CA as expected and as served, for example at X3 on 10.5p1 `client A after the host committed the switch: ssh exited 0; expected CA SHA256:HQCgqSUdc8rv5Ns9JbYp4SFC3T+HhkBQxY5+ahWfsQA; debug1: Server host certificate: ... serial 1795387188549602 ... CA ssh-ed25519 SHA256:HQCgqSUdc8rv5Ns9JbYp4SFC3T+HhkBQxY5+ahWfsQA` (r1); each logged `re-anchored: false` and the fixed last line once, with no SKIP or FAIL line.
- **The narrowing mutant** (the review's MN): in cmd/keyroster/narrow.go, `if ca.State == "draining" { continue }` as the first statement of the loop over `trust.TrustedCAs(b, trust.RoleHost, now)`, one exact replacement asserted unique; `go vet ./cmd/keyroster/` exit 0 on the mutated tree. At X3 on 10.5p1: `--- FAIL: TestHostCARotation (132.64s)`, after step 6a's attempts and drop-in checks passed, at the new login: `client A after the host committed the switch: ssh to web1 exited 255, want 0 with Server host certificate by SHA256:DP1dQr33O7Ozyy6YkbrrnY1sKDN4XEIlWKQS/98vCWA`, ssh printing `No matching CA found. Retry with plain key` and `Host key verification failed.` At head 4869fde the same mutant had survived (the review's run). At X6 on 10.5p1 its first try stopped earlier, at step 5: `doctor after retire-key exited 1`, doctor printing `FAIL clock_regression: the wall clock is 1s (1 s) behind the serial high-water mark` (89.42 s); under the plan's rule for clock flakes, as the orchestrator ruled, it was re-run once unchanged (the same replacement, vet again exit 0; deviation 11) and was killed as at X3: `--- FAIL: TestHostCARotation (137.32s)`, the same message at the new login with that run's generation-1 fingerprint (SHA256:GGq5KYSQjj386ZsZuXGAQUtltakv9H29WGDdar1LMCI), and the same two ssh lines. After each run narrow.go was restored (sha256 0b31b3750c50da575aa8de6d5ea19de8a4dfd74fb31b605dc20a5aa48f3b068e before and after) and the status was empty.
- **M373 again** at X3 on 10.5p1 (its replacement as in Task 2; `go vet ./internal/agent/apply/` exit 0): `--- FAIL: TestHostCARotation (135.78s)` at step 6a's attempts check, `step 6a: the host asked for a certificate at 2026-11-22T22:50:04Z, after r1's issuance 1795387798`, before the new login (the log has no line of it). Restored: sha256 da93def1aa4a33c6a34f7f8d0d5bac256986e0dd989e50845853c375d58428c0 before and after; the status empty. M373 was not run at X6, which changes nothing before the login.
- M371 and M372 were not run again: their assertions are step 8's, which neither X3 nor X6 touches.
- A login that returns after r1 + 50 s: at X3 it failed inside `hcrServes`, whose time left is worked out after the login returns and which makes no try once it is at or below zero (hostca_rotation_test.go:110-113) and then fails (:148); since X6 it fails at once with `step 6a: client A's login returned at <t>, after r1 + 50 s (<bound>)`, the check `!now.Before(...)` matching `hcrServes`'s treatment of no time left. That branch is read, not run: no run here reaches it without a changed bound.
- **What the local readings of step 6a's end show.** The check sleeps until r1 + 45 s by the monotonic clock and logs its end by the wall clock. These four runs logged its end at about r1 + 43.1 s to 43.2 s, so the WSL wall clock fell about 1.8 s to 1.9 s behind the monotonic clock during the sleep, a larger lag than the 1.1 s recorded above for the earlier local runs, and still far below the 4.17 s that the attempts check's whole seconds allow for. No assertion failed on it, and no bound was changed.

**What `/trust` answers from** (read for G7): `handleTrust` (internal/server/server.go:323-324) answers from `currentStatus`, which serves a cached signer status younger than `statusTTL`, 5 s (internal/server/signer.go:372, :435-443), timed from the moment its refresh started; a failed refresh is never cached. `keyroster host status` verifies the bundle and narrows (cmd/keyroster/hoststatus.go:130, through `verifiedTrust`, narrow.go:61-66) before it asks for the host status (:134).

**The counts of the leaf's phrases** (required, then forbidden, by window: "The host CA", the header, "Run in CI", "Before ceremony 2", "What changes for nobody", machine-identities.md, signer-install.md; holds counted by a parser of the leaf's table, forbidden phrases by a grep of its `holdsNot` lists, both checked against the base first):

| | Required | Forbidden | Item-4a tokens |
|---|---|---|---|
| Before the round (4869fde) | 82 (64, 1, 2, 9, 1, 4, 1) | 6 (1, 0, 1, 2, 0, 1, 1) | 14 |
| After X3 | 91 (71, 1, 2, 9, 1, 5, 2) | 7 (1, 0, 1, 2, 0, 1, 2) | 17 |
| After X6 | 91 (71, 1, 2, 9, 1, 5, 2) | 7 (1, 0, 1, 2, 0, 1, 2) | 16 |

"The host CA" stays at 71 from X3 to X6 because X4's changes cancel: G5 adds one phrase, the new label phrase one, and G2's merge of three phrases into one removes two. Item 4a loses one token by G2's merge of two into one. Besides the tokens, item 4a's window is held by three checks: `**4a. ` once in the section, `**4. ` once and before it, `**5. The costs.**` after it.

**Lint.** After X3 and again after X6: `$HOME/go/bin/golangci-lint run ./cmd/keyroster/` and `$HOME/go/bin/golangci-lint run --build-tags "e2e,e2erotation" --new-from-rev=origin/main ./test/e2e/` (origin/main c6c632d), each `0 issues.`; `gofmt -l cmd/keyroster test/e2e` empty. The full gate below runs every leg of the sixth verify command.

**The gates of part B** (each in the background with nothing else running in WSL; origin/main c6c632d130450e24fe432dfd68bcf00420dc2231 after `git fetch origin` at the start of part B, so no rebase):
- **The base**, re-measured in place (see "Task 1"): `keyroster=303.005 at=1795391117`, from a detached worktree of origin/main under a temporary directory outside the repository, removed afterwards (`git worktree list` then lists no temporary worktree).
- **The delta gate** (the fifth verify command, extracted byte for byte from plan line 930 and run unchanged): exit 0, `ok  	github.com/Labontese/keyroster/cmd/keyroster	284.858s`, 18.147 s under the base, no FAIL or DATA RACE.
- **The full gate** (the sixth verify command, plan line 932, extracted byte for byte and run unchanged). The first run exited 1 after 670 s with two failing packages, neither touched by this branch: internal/signer, `--- FAIL: TestCheckLogAgainstLiveSigner (0.65s)` with `log_test.go:454: unavailable: clock_regression`, and internal/agent/fetch, `--- FAIL: TestFetch/more_repolls_immediately (1.89s)` with `fetch_test.go:278: requests ["GET /api/v1/agent/state" "GET /api/v1/agent/state?bundle=1"] in 1.456053679s, want two at once, the second with the new bundle version` (the pre-existing timing flake under whole-module `-race` load of deferred-items.md and 03-14b); the other 34 packages `ok`, and the command's chain stopped at the failing `go test`. Under the plan's rule for clock flakes it was run again once, unchanged (deviations 11 and 12): exit 0 after 799 s, 36 `ok` lines (cmd/keyroster 322.607 s, internal/signer 508.358 s, internal/agent/apply 621.126 s, internal/agent/fetch 44.569 s), no FAIL, DATA RACE or SKIP; every `go vet` tag set clean; gofmt clean; golangci-lint `0 issues.` under linux, windows, darwin and the `e2e,e2erotation` pass on the new lines; capslock v0.3.3: keyroster-signer 97 pairs (baseline 97), keyroster-agent 37 (37), keyroster-agent-fetch 23 (23), no pair new against a baseline; dep-firewall clean (EXEC leaves keyroster-agent only through internal/agent/execsite; `os/exec <- modernc.org/libc` the documented exception for keyroster-signer; no banned packages); testonly-firewall clean (6 GOOS/tag combinations); check-pinned-actions: all 55 `uses:` references pinned to commit SHAs.

### The check of the fix round

After X1 to X3 existed as local commits, and before anything was pushed, the orchestrator read their whole diff, recounted the RED, the twenty mutant logs and the four e2e logs, and had the round read once more: one reader (Opus, high effort; 249,152 tokens, 60 tool calls, about 12 minutes), read-only on a detached worktree of X3, with a private copy of the tree for the pins. No skeptic judged its items: each came with a mutant of the reader's own that survived, or with the code lines, and the orchestrator checked the code it relies on itself. No Codex.

What the reader found to hold: the RED and the kills of XM1 to XM20 are in the logs as recorded; "outlives the trust in that key" is true for every role (internal/signer/drain.go:250-287 applies the binding to every newly draining entry); between the switch install and the new login the only keyroster calls are the commit wait's `host status` polls, and each narrows A's live file; the narrowing mutant fails at the new login and M373 at the attempts check before it; one login takes about 0.1 s to 0.3 s, which by the CI readings of 4869fde leaves about 4.5 s before the keyscan's bound; and the login cannot pass wrongly, because the managed file holds `@cert-authority` lines only.

Its five items, all acted on in X4 to X6:

1. UNVERIFIED labels were pinned by their words and not as labels: its mutants RM1 and RM2 (item 4a) and RM3 ("The host CA") survived. Answered by G2.
2. The new sentence on an admin's sync as another account was true by the code and incomplete: an agent signs with every key it holds, and the text did not say what one admin signature is worth. Answered by G5 and G6; the orchestrator read both facts in the code (`--admin-quorum` defaults to 1 in `root genesis-policy`, cmd/keyroster/root.go:142; a directory needs that many admin signatures, internal/directory/verify.go:34).
3. The pin of "outlives the trust in that key" was met by the negated sentence: RM4 survived. Answered by G3.
4. Item 4a moved to before item 4, inside its section, passed: RM5 survived. Answered by G4.
5. Two comments of the new login said more than the code shows, and a login that returned late failed with a message that blames sshd. Answered by G7; the executor then found that the clause the orchestrator dictated for the comment said more than the code shows as well, and wrote what the code shows (deviation 9).

G1 is the orchestrator's own: the login route's pin stopped before its flag, because the brief's markup was ambiguous.

Not taken from item 2: what the reader says of the Windows OpenSSH agent rests on that agent's behaviour, which this repository does not show; a client on Windows stays UNVERIFIED. Not checked by the reader: it ran no e2e test, the round was not pushed and had no CI, and nothing on Windows. X4 to X6 were read by the orchestrator (their whole diff, the RED, the 34 mutant logs and the e2e logs) and by no further reader.

### CI on 4869fde, the head the review read

Every run of that head succeeded at its first attempt and none was run again: CI 45067470990, E2E 45067471042, E2E TPM 45067470971, PIV 45067470980, E2E distro 45067471131, E2E PKCS#11 45067471059, Systemd 45067470972, CodeQL 45067470987, Workflow lint 45067471013, PR title 45067470967. All 30 required checks passed. The orchestrator read the figures below from the six job logs of the E2E run.

`go test` in each lane, beside the larger of the two base readings of that lane (the plan's "The budget"):

| Lane | Base (s) | 4869fde (s) | Difference (s) |
|------|----------|-------------|----------------|
| e2e-rotation (9.5p1) | 540.411 | 660.758 | +120.347 |
| e2e-rotation (10.5p1) | 530.958 | 657.877 | +126.919 |
| e2e (9.5p1) | 787.868 | 737.658 | -50.210 |
| e2e (10.5p1) | 798.716 | 773.829 | -24.887 |
| e2e-probe (9.5p1) | 292.476 | 300.039 | +7.563 |
| e2e-probe (10.5p1) | 290.372 | 281.009 | -9.363 |

Both rotation lanes are under the owner's 900 s and under the plan's typical figures (about 681 s and 672 s). The main and probe lanes compile nothing of this plan, so their differences are run-to-run spread; neither main lane's log names TestHostCARotation.

TestHostCARotation in the two rotation lanes:

| | 9.5p1 | 10.5p1 |
|---|---|---|
| Duration | 131.97 s | 125.75 s |
| c1 observed after its issuance (bound 15 s) | 1.698 s | 1.674 s |
| Signer down: prepare, the install of ceremony 1, the switch | 28, 27 and 51 ms | 28, 27 and 50 ms |
| Bundle 2 committed after its install, and after the signer served again (bound 45 s) | 14.097 s, 14.077 s | 16.110 s, 16.089 s |
| r1 and r2, each after the previous issuance (51 s to 75 s) | 56 s, 59 s | 55 s, 54 s |
| Step 6 ended at (bound r1 + 28 s) | r1 + 1.549 s | r1 + 2.162 s |
| Bundle 3 committed after its install, and after the signer served again | 10.622 s, 10.579 s | 10.435 s, 10.393 s |
| Step 6a ended at (bound r1 + 50 s) | r1 + 45.107 s | r1 + 45.053 s |
| Re-anchored | no | no |
| Client B after the renewal, then after its remedy | exit 255, then exit 0 | exit 255, then exit 0 |

In both lanes every login's `Server host certificate` line names the expected host CA: generation 1 for A and B after ceremony 1 and right after the switch, generation 2 for A after the renewal, for B's refused login and for B after its remedy. Step 6a ended at about r1 + 45.1 s in both lanes, without the shortfall of about 1.1 s that the local runs show; that is one observation, not a measurement of the runners' clock. `login failures: 0` stands in both lanes' TestCARotationNoFailedLogin.

## Commits

| Name | SHA | Subject | Full staged read before it |
|------|-----|---------|----------------------------|
| G2 | ac6206936b4ad50cb0eea8d291f6c74977caf286 | test(e2e): rotate the host CA end to end with a refreshed and a stale client | yes, all four files, one at a time, after the last edit |
| R3 | ce7f58416fdc1f289bdb99efd0556a45e720c838 | test(cli): pin the host-CA gate, its test and the end-state plan numbers of the rotation runbook | yes, both files, one at a time, after the last edit |
| W3 | 136163f6da3f70081c48cd4e358e89ff84d90e9e | docs(runbooks): state the host-CA rotation gate, who can refresh, and what a client that never refreshes meets | yes, all four files, one at a time, after the last edit |
| P4 | 4e058f8073494945f774db64cf07ff3fe11cdc89 | docs(03-12f2): plan out the host-CA end-to-end test | yes, the one file, after the last edit (the staged diff saved outside the repository and read whole, folded at 1,400 columns) |
| the first SUMMARY commit | 4869fde5904361f44e8d71ea13b90a716841ccee | docs(03-12f2): complete ca-rotation-host-ca-e2e plan | yes, ROADMAP.md, STATE.md and this SUMMARY, one at a time, after the last edit |
| X1 | c824af94bfda26cf8cddcb4f8681548a929c1074 | test(cli): pin the rest of the host-CA gate and hold item 4a to its section | yes, both files, one at a time, after the last edit |
| X2 | 029da1b17bb0606417ddffa5b4197f1124b05d49 | docs(runbooks): say what an admin's sync for another account opens, and label what no test shows | yes, all four files, one at a time, after the last edit |
| X3 | 459b8260b4e204cbad0702c1f293796efaff5956 | test(e2e): log the refreshed client in after the host committed the host-CA switch | yes, the one file, after the last edit |
| X4 | ace104b28c5cd20820ae8ce5cd8e805b49d500bd | test(cli): pin the UNVERIFIED labels with their sentences and item 4a between its neighbours | yes, both files, one at a time, after the last edit |
| X5 | 80fd108431eef948da72603eb1f2217f17dddfc6 | docs(runbooks): say what the admin's agent signs and what one admin signature authorises | yes, the one file, after the last edit |
| X6 | 85d0ec4206e31d6295a25b069f564420c019df97 | test(e2e): say which polls narrowed the file and name a late login | the working-tree diff in full right before `git add`, with no edit between, and the committed diff in full right after the commit (deviation 10) |
| this commit | (cannot name itself) | docs(03-12f2): record the pre-merge review and its fix round | yes, this SUMMARY, after the last edit |

Every commit is signed with keyroster-bot's SSH key (a `gpgsig` header in each), authored as Daniel Gustafsson and committed by keyroster-bot.

## Mutants

The fix round's mutants (the document mutants XM1 to XM34, the narrowing mutant at X3 and X6, and M373's second run at X3) are recorded in one place, under "The fix round" above. What follows are Task 2's.

Under the mutant rule, at G2, on 10.5p1 through the wrapper, each with the action's e2e command (`-timeout 12m`), applied by one exact replacement asserted unique, vetted, restored with `git checkout --` and hash-checked.

**Unmutated control** (the action's control command, `-timeout 12m`): exit 0, `--- PASS: TestHostCARotation (153.67s)`, `ok  	github.com/Labontese/keyroster/test/e2e	175.987s`, the fixed line once; serials c1 1795372460636853, r1 1795372522806050, r2 1795372583023530, no re-anchor.

**M371** (B refreshed after all): after step 3's `hcrSync(t, kr, kh, gen1, gen2)` one more line `copyFile(t, kh, bKH, 0o600)`.
- sha256 of test/e2e/hostca_rotation_test.go before: cb2d0079f75e31cc340003c7649cc0bb986275fa4c8b42741d1dd9483579e358; `go vet -tags "e2e e2erotation" ./test/e2e/`: exit 0.
- Killed by the named assertion: `--- FAIL: TestHostCARotation (148.70s)` with `hostca_rotation_test.go:631: client B after the renewal: ssh to web1 exited 0, want a refusal with Host key verification failed` (line 631 of the mutated file, which has one more line above it; in G2 the call is at :630 and the failing check at :399). Every step before it passed (B's logins after ceremony 1 and right after the switch, step 6a, r2, A after the renewal). No `[build failed]`, `[setup failed]` or SKIP line.
- Restored: sha256 after equal to before; `git status --short -- cmd internal test docs .github` empty.

**M372** (A lacks the generation-2 line): before `previous := sg.exportLog(t)`, after step 3's sync check and logins, a block that rewrites the live managed `keyroster_known_hosts` (inside the namespace) without the line holding generation 2's key.
- sha256 before: cb2d0079f75e31cc340003c7649cc0bb986275fa4c8b42741d1dd9483579e358; vet with the rotation tags: exit 0.
- Killed by the named assertion: `--- FAIL: TestHostCARotation (144.64s)` with `hostca_rotation_test.go:640: client A after the renewal: ssh to web1 exited 255, want 0 with Server host certificate by SHA256:/yCNGvLMRduZazvJmvF0eh7rao0HBFtjua8/t9DfXUs` (generation 2's fingerprint in that run; line 640 is a line of the mutated file, which has eleven more lines above it: in G2 the call is at :629 and the failing check at :387). Step 6's logins passed (they met generation 1), as did step 6a and r2; the admin calls that narrow the edited file did not fail. No build, setup or SKIP line.
- Restored: sha256 equal; `git status --short -- cmd internal test docs .github` empty.

**M373**: unit control first, unmutated: the action's unit command exited 0 with `--- PASS: TestHostCertStep (42.37s)` and its three named subtests passing.
- Mutation: internal/agent/apply/hostcert.go, `if ca.State == "draining" { continue }` as the first statement of the loop body of `for _, ca := range trust.TrustedCAs(bundle, trust.RoleHost, st.now) {` (line 414 at G2; the target asserted unique).
- sha256 before: da93def1aa4a33c6a34f7f8d0d5bac256986e0dd989e50845853c375d58428c0; `go vet ./internal/agent/apply/`: exit 0.
- e2e: killed by the named assertion, step 6a's attempts check: `--- FAIL: TestHostCARotation (147.15s)` with `hostca_rotation_test.go:619: step 6a: the host asked for a certificate at 2026-11-22T18:45:52Z, after r1's issuance 1795373147: <the file>` (the call at :619 of G2; the failing check is at :231). r1 was issued at 18:45:47, the switch ended 18:45:48.607, so the mutated agent asked about 5 s after r1's issuance and 3 to 4 s after the signer served again (the request's time is a whole second), consistent with the applier pass that applied bundle 3 (bundle 3 committed 10.745 s after its install). The agent's run log, dumped at the failure, holds one `WARNING host certificate answer for ... refused: answer_unpinned_ca` line, the refusal the later log assertion of the same step would have met. No build, setup or SKIP line.
- Unit run (the action's command, mutated): exit 1, `--- FAIL: TestHostCertStep (39.41s)` with exactly three failing subtests, `TestHostCertStep/hostcert_answer_draining_ca_accepted`, `/hostcert_kept_cert_of_draining_ca_kept_until_due` and `/hostcert_kept_cert_of_drained_ca_replaced`, each with `installedByOld`'s message `an answer signed by the draining host CA key before its end: ... want it installed` (reported at hostcert_test.go:464, :500 and :508 through `t.Helper`); every other subtest passed.
- Restored with `git checkout --`: sha256 equal; `git status --short -- cmd internal test docs .github` empty.

**What the dumped sshd logs show.** A failing run dumps sshd's log, so the three mutant runs show what a passing run does not: 6, 6 and 4 lines `srclimit_penalise: ipv4: new 127.0.0.1/32 deferred penalty of 1.000 seconds for penalty: connections without attempting authentication` (M371, M372 and M373) and no other penalty line. sshd on 10.5p1 thus records a penalty of one second for a connection from loopback that does not attempt authentication, and the test's keyscans are such connections; no line shows a connection refused for a penalty. The plan's stop for a login or keyscan that fails beside a named penalty can therefore be ruled out from a passing run for the logins only. A penalty that grew into a refusal could fail a run that should pass, never pass one that should fail.

**No file is left in a mutant state.** After the last mutant, test/e2e/hostca_rotation_test.go has sha256 cb2d0079f75e31cc340003c7649cc0bb986275fa4c8b42741d1dd9483579e358 and internal/agent/apply/hostcert.go da93def1aa4a33c6a34f7f8d0d5bac256986e0dd989e50845853c375d58428c0, both as at G2, and `git status --short -- cmd internal test docs .github` is empty.

## Deviations

1. **[Rule 3, lint] `hcrRenewMin` keeps its name with a scoped `nolint`.** The tagged golangci-lint pass of Task 2's third verify command reported revive's time-naming rule on `hcrRenewMin` (it reads the suffix `Min` as minutes). The plan fixes the constant's name (Task 2's action, the constants of the new file), so the name stays and the line carries `//nolint:revive // time-naming: Min is the minimum, not minutes`. No behaviour, bound or assertion changed; the third verify command then exited 0. The edit came before the pre-check, which ran on the committed text.
2. **[Additions to the plan's list of declarations] Three small helpers of the new file beyond the plan's list:** `hcrCert` (the CA, the 90 s and the served check, shared by step 0 and `hcrNext`, so the checks exist once), `hcrNamesCA` (the `Server host certificate` line check, shared by `hcrAccepted` and `hcrRefused`) and the constant `hcrClock` (the layout of logged times). All carry the free `hcr` prefix and narrow nothing: `hcrNamesCA` requires at least one such line and that every such line names the expected CA's fingerprint.
3. **[Plan count, no change to a pin] "The pins" lists 82 required phrases, not 83.** The gate base values (plan line 592) count "89 phrases ... (83 required ... and 6 forbidden)" for ca-rotation.md, machine-identities.md and signer-install.md. A parser of the code spans of "The pins" (plan lines 559-565) finds 93 spans: 82 required phrases, 6 forbidden ones, and 5 that are no phrase (the `caRotationWindow` call, the two `sectionWindow` calls, `## `, and the bare `"The host CA"`, which the plan names only to say that it "would not do"). 82 + 6 + the bare `"The host CA"` gives the plan's 89 and 83, so the plan's count most likely took that note for a phrase. The leaf pins the 82 and 6 that "The pins" names; nothing was added or dropped, and the bare `"The host CA"` stays unpinned, as the plan says.
4. **[Wrapping] The dictated quote blocks keep the plan's line breaks; three edits are wrapped by the executor.** Every block the plan dictates as quoted lines was copied with its own breaks, including three short lines that come from the plan's text (in "The host CA", its Run in CI paragraph: `host by the old host CA's certificate right after the` and `no answer; a client that did not refresh reaches it`; in item 4a: `repeated. Each host whose`); every line is within its file's width. The plan gives the "Run in CI" insertion, the "Run in CI" UNVERIFIED sentence and the "What changes for nobody" sentence as sentences, not lines; they were wrapped at most 74 columns, touching only the base lines they change (:685, :695-697, :745), and the "Run in CI" insertion joins the list with a comma only (the words are above under W3). The fourth verify command's hunk and width checks pass.
5. **[Evidence only] The RED was run twice.** Task 3's second verify command writes its log into its temporary directory and removes the directory before it exits, so its verbatim run (exit 0, the gate) leaves no FAIL lines or messages to record. A second run of the same command, differing only by one `cp` of the log before the worktree's removal, gave the records under "The RED" (exit 0 as well). The gate itself was not changed.

**Rulings on deviations 1 to 5** (the orchestrator, 2026-11-22). All five stand as they are. 1: the comment has the repository's own form for a scoped exception, and the plan fixes the name. 2: the three declarations narrow nothing, and `hcrNamesCA` is the stricter form of the check. 3: the leaf pins every phrase that "The pins" lists; the orchestrator compared the leaf's strings with the code spans of plan lines 559 to 565 by a script of its own (93 spans: 88 are phrases of the leaf, 82 required and 6 forbidden; the other five are the three window calls, `## ` and the bare `"The host CA"`). The plan's count of 83 is one too high, and the published plan keeps it. 4: the seven dictated blocks stand in the four files line for line, and the three sentences the executor wrapped read word for word as the plan gives them (both compared by a script of the orchestrator's). 5: the verbatim run is the gate; the second run only kept the log. The orchestrator also recounted the 70 document mutants from their logs: each log holds exactly its expected FAIL lines, and no build failure, setup failure or SKIP.

6. **[Clock flake, the plan's rule] The full gate's first run failed on `clock_regression` and was re-run once, unchanged.** The sixth verify command's first run exited 1 on `--- FAIL: TestCheckLogAgainstLiveSigner (0.30s)` with `log_test.go:454: unavailable: clock_regression`, in internal/signer, a package this branch does not touch; the WSL clock read earlier than a moment before it (03-12f's deviations 6, 11 and 19). The plan's "One rule for clock flakes" covers a first failure of the full gate whose message names `clock_regression`: the same command was run again unchanged and exited 0 (both runs under "Gates"). No bound, timeout or assertion was changed.
7. **[Form, nothing loosened] The publish scan before P4 ran in full.** Task 4's action asks for the whole-file legs of the publish scan, the seventh verify command up to its `git cat-file` leg, before P4. The command was run verbatim and in full rather than cut at that leg, so that no plan command was edited: its whole-file legs on the plan file come first and its exit 0 covers them; its later legs read main's early text at HEAD and the added lines of G2 to W3, and passed as well. After P4 it ran again in full, its `git cat-file` leg then reading the committed text.
8. **[Order, fix round part A] X3's two unmutated end-to-end runs ran before X3 was committed.** They ran on the working tree, and the file was then committed with no edit between: the staged diff read `index 9a48989..5274c34`, and `git rev-parse HEAD:test/e2e/hostca_rotation_test.go` is 5274c348e6298e387a14ae4ab3a587ba802c4db9, so both runs ran X3's text. The two product mutants of part A ran after the commit. **Ruling** (the orchestrator): accepted; the unmutated runs ran on the file as committed.
9. **[A comment says less than dictated, fix round part A2] Step 6a's comments do not say that the last poll narrowed under bundle 3.** The dispatch for X6 asked the comments to say that the commit wait's polls narrowed A's live file, "the last of them at least under bundle 3 (the host took bundle 3 from the same server before it could commit it)". The code does not order it so: `keyroster host status` verifies the bundle and narrows (cmd/keyroster/hoststatus.go:130, through `verifiedTrust`, narrow.go:61-66) before it asks for the host status (:134), and `/trust` answers from a signer status cached for up to 5 s (internal/server/server.go:323-324, internal/server/signer.go:372, :435-443); so the poll that saw the commit narrowed under whatever `/trust` gave it when it started, which can, by the code, come before the host fetched bundle 3. The comments say instead that each poll verifies the bundle and narrows A's live file under it before it asks for the host status, that a poll soon after the switch may still have verified bundle 2, and that A's login shows the old host CA's line survived those narrowings. That a narrowing under bundle 3 did come before the login in these runs is shown by the narrowing mutant's kill, not by the code. **Ruling** (the orchestrator): accepted; the comment says what the code shows, the orchestrator read `statusTTL` at internal/server/signer.go:372 itself, and the clause it had dictated said more than the code shows.
10. **[Staged read, fix round part A2] X6's staged diff was not read with `git diff --cached` before its commit.** Its `git diff` was read in full right before `git add`, with no edit between, and before the commit only the line count of `git diff --cached` (48 lines) was printed; right after the commit `git show HEAD` was read in full: the same diff, `index 5274c34..bfd2793`. **Ruling** (the orchestrator): accepted; the diff was read in full before the add and again in the commit, recorded as it happened.
11. **[Clock flake, the plan's rule] The narrowing mutant's first try at X6 stopped at step 5 on `clock_regression` and was re-run once, unchanged.** Doctor after retire-key exited 1 with `FAIL clock_regression: the wall clock is 1s (1 s) behind the serial high-water mark`, the WSL clock having read earlier than a moment before it, as in deviation 6. The plan's "One rule for clock flakes" lists a mutant's unmutated run, not its mutated one; the orchestrator ruled that this first try falls under the rule all the same. The same mutant was applied again by the same replacement, vetted and run unchanged, and was killed at the new login (both runs under "The fix round"). No bound, timeout or assertion was changed. **Ruling** (the orchestrator): it falls under the plan's clock rule; both runs are recorded.
12. **[Clock flake and a known timing flake in one run] The full gate of part B was re-run once, unchanged, after a first run with two failures.** One failure named `clock_regression` (internal/signer, `TestCheckLogAgainstLiveSigner`), which the plan's rule for clock flakes covers; the other was `TestFetch/more_repolls_immediately` in internal/agent/fetch, a wall-clock bound that whole-module `-race` load exceeds, recorded as a pre-existing flake in deferred-items.md and met before in 03-08c, 03-09, 03-10b and 03-14b, and not a clock reading the rule names. Both packages are untouched by this branch. The re-run the clock rule asks for was the one re-run: it exited 0 (both runs under "The fix round"). No bound, timeout or assertion was changed. Not yet ruled on: whether the rule's one re-run may cover a failure in the same run that its text does not name.
