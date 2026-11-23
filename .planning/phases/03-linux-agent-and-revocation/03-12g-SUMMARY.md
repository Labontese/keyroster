---
phase: 03-linux-agent-and-revocation
plan: 12g
subsystem: cli
tags: [ca-rotation, host-ca, known-hosts, machine-identity, automation, runbook]
status: complete
requires: [03-12f2]
provides: [keyroster machine renew adds the line of each active or next host CA that the managed keyroster_known_hosts lacks over the names its trusted lines carry and moves the bundle floor, exit 4 when it cannot, the --no-known-hosts flag of machine renew, hostCALine, TestAddHostCALines, TestMachineHostTrust, TestMachineHostTrustCaller, FuzzAddHostCALines, client C in TestHostCARotation, the automation text of ca-rotation.md, enroll-user.md items 4 and 4a and machine-identities.md with their pins, note N1 in 03-12d-PLAN.md, this plan's text]
affects: [03-13, 03-16]
key-files:
  created: [cmd/keyroster/machinehosttrust.go, cmd/keyroster/machinehosttrust_test.go, .planning/phases/03-linux-agent-and-revocation/03-12g-PLAN.md]
  modified: [cmd/keyroster/machinerenew.go, cmd/keyroster/knownhosts.go, cmd/keyroster/knownhosts_test.go, cmd/keyroster/runbook_test.go, cmd/keyroster/hosttrust_runbook_test.go, test/e2e/hostca_rotation_test.go, docs/runbooks/ca-rotation.md, docs/runbooks/enroll-user.md, docs/runbooks/machine-identities.md, .planning/phases/03-linux-agent-and-revocation/03-12d-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md]
requirements-completed: []
actuals:
  tokens: 96994    # chars/4 over the realized diff against a49a214 without this SUMMARY (322,016) plus this SUMMARY (65,963), at S7
  tasks: 5         # Tasks 1 to 5 up to the PR, its red rotation lanes on the first two heads and the fix round; Task 5's step 6 (the pre-merge review) is the orchestrator's and Task 6 the owner's merge
  commits: 9       # git rev-list --count a49a214..HEAD with S7: R2, G2, C3, R4, W4, P5, the first SUMMARY commit, F6 and S7
plan_head_before: a49a214604600c3bc2818584acdde47c5bf2315c
---

plan file size: 217138 bytes
plan file sha256: 2bdb0c0811ef2b3d9cd28ec81d1d4702262dcd57660e8d1da095c20443a3afc9

# Phase 03 Plan 12g: machine renew adds a new host CA's line Summary

`keyroster machine renew` now adds, right after its trust bundle verifies, the line of each active or next host CA that an automation account's managed `keyroster_known_hosts` lacks, over the host names the file's own lines for trusted host CAs already carry, and moves the bundle floor of `host-trust.json`; it exits 4 when the certificate is in place but host trust could not be refreshed, and `--no-known-hosts` turns the step off. TestHostCARotation gains a third client refreshed this way in the e2e-rotation lane, and ca-rotation.md, enroll-user.md and machine-identities.md say what the step does and does not do, each new sentence pinned. Pull request #120; the pre-merge review is pending.

## Hand-over

Draft, after session 1 (Tasks 1 and 2). Done: Task 1, and Task 2 complete: R2 and its RED
from a worktree, G2, Task 2's four verify commands (all exit 0), the 60 s fuzz run, lint under
linux, windows and darwin, and the 25 code mutants M438 to M459 and M498 to M500, each killed
by its named leaf. The branch is pushed with R2 and G2 at its head (262e08ee). No file is in a
mutant state; the working tree differs from the branch head only by the untracked plan file,
this SUMMARY draft and the pre-existing files that are never staged. The tracer gate of Task 2:
its four verify commands passed on the committed G2 head, so Task 3 can build on it.

After session 2 (Tasks 3 and 4). Done: Task 3 (C3, the wrapper's self-check with deviation 4,
Task 3's three verify commands with exit 0, the pre-check on 10.5p1 and 9.5p1, M460 killed at
step 3, lint) and Task 4 (R4 and its RED from a worktree, W4, Task 4's three verify commands
with exit 0, the third after W4's commit (deviation 5), lint, the 42 document mutants, each
killed by its named phrase). The branch is pushed with R2, G2, C3, R4 and W4 at its head
(8f78bb1a); no pull request. No file is in a mutant state; the working tree differs from the
branch head only by the untracked plan file, this SUMMARY draft and the pre-existing files that
are never staged.

After session 3 (Task 5, steps 1 to 5). Done: the precondition; P5 after a full read of its
staged diff and the publish scan; the test-time base re-measured and replaced in place; the
delta gate and the full gate (each exit 0 on its first run); the push; PR #120 opened by
keyroster-bot without auto-merge; the tracking update; the first SUMMARY commit, pushed. See
"Task 5 (session 3)". The e2e-rotation lanes were red on the PR's first two heads (P5 and the
first SUMMARY commit), so step 5 was not complete there; on the orchestrator's ruling the fix
round added F6 (a fixed wait after client C's setup) and S7 (this record). See "The rotation
lanes' red runs on the first two heads, and the fix". Next: the orchestrator's pre-merge review
(Task 5, step 6) on a green PR, then the owner's merge gate (Task 6).

## Task 1: preconditions and base

- BASE: 34925dd6ec65f33179719eca1f935959270118b6.
- origin/main: a49a214604600c3bc2818584acdde47c5bf2315c.
- `git log --oneline 34925dd6ec65f33179719eca1f935959270118b6..origin/main`:
  `a49a214 test(serverclient): look for the peer's digits outside the request URL (#117)`,
  PR #117's squash merge, an expected move (it touched only internal/serverclient/admin_test.go,
  internal/serverclient/client_test.go and two files under
  .planning/quick/261122-qcp-fix-serverclient-decode-test-port-flake/). No other move.
- The branch `p03/12g-machine-renew-host-trust` existed at dispatch, created from origin/main =
  BASE. PR #117 merged on main while the first run of Task 1's checks was under way; the
  orchestrator fast-forwarded the still empty branch to a49a214 (= origin/main) before any edit
  of this session.
- Task 1's checks, run in order on the fast-forwarded branch (plan lines 590 to 608, each
  extracted byte for byte): all ten exit 0. The third printed
  `stopped_at: "Completed 03-12f2-PLAN.md (PR #118)"`; the second printed the one move above;
  the tenth printed `e2e-rotation (9.5p1): go test 677.859 s`,
  `e2e-rotation (10.5p1): go test 657.828 s` and
  `9.5p1: not exactly one fixed line: host CA rotation: machine renew added the generation 2 line to the third client, which accepted generation 1 and generation 2`.
  (A first pass of the checks, before the fast-forward, ran checks 1 to 8 with exit 0 and
  check 9 with exit 1, because main had moved to a49a214 between check 2's fetch and check 9's
  fetch while the branch was still at BASE; it was reported, nothing was edited, and the
  whole sequence was re-run after the fast-forward.)
- Base values as read on origin/main (Task 5 starts from them): ROADMAP
  `**Plans:** 40/44 plans executed in 43 waves.` (:163),
  `- [x] 03-12f2-PLAN.md — CA rotation, host-CA end-to-end test (D-14, KEY-08): TestHostCARotation in the e2e-rotation lane and the host-CA runbook gate` (:282),
  `**Wave 40**` to `**Wave 43**` (:284, :287, :290, :293),
  `| 3. Linux Agent and Revocation | 40/44 | In Progress | - |` (:364); STATE
  `stopped_at: "Completed 03-12f2-PLAN.md (PR #118)"` (:6), `  total_plans: 79` (:14),
  `  completed_plans: 75` (:15), `Plan: 40 of 44` (:31).
- The test-time base, measured on a49a214 in the background with nothing else running in WSL
  (`bash scripts/linux.sh 'exec 2>&1; go test -race -count=1 -timeout 15m ./cmd/keyroster/'`,
  `ok  github.com/Labontese/keyroster/cmd/keyroster 280.230s`, started at epoch 1795458468,
  ended at 1795458760). R2's edits were written to the working tree while it ran, from epoch
  1795458749 on, after the test binary had been built (the run's test time is 280.23 s of its
  292 s): the measured binary is a49a214's.

test-time base: keyroster=264.218 at=1795469558
Re-measured in session 3 (Task 5) and replaced in place, because session 1's base (280.230 s at epoch 1795458760) came from another session and another WSL boot: on origin/main a49a214 in a detached worktree outside the repository, removed afterwards; Budget's command (`bash scripts/linux.sh 'exec 2>&1; go test -race -count=1 -timeout 15m ./cmd/keyroster/'`, with a read of the WSL boot id put before it), in the background with nothing else running in WSL; started at epoch 1795464069, `ok  github.com/Labontese/keyroster/cmd/keyroster 271.776s`, exit 0; WSL boot id 4974cc49-ddca-4836-a015-2032127a83e3 before and after the run. For the fix round WSL had booted again (boot id 011372f6-9963-4a98-9bdb-83ce959b9cce), so the base was measured once more the same way and replaced in place: started at epoch 1795469275, `ok  github.com/Labontese/keyroster/cmd/keyroster 264.218s`, exit 0, the same boot id before and after the run.

## Task 2

### Commits

| Name | SHA | Subject |
|------|-----|---------|
| R2 | 20447509aea963a36eff89f0c86cff7ec5e4a114 | test(cli): pin machine renew's refresh of the host CA lines and its exit status |
| G2 | 262e08ee0ce469cb4521c2b424e6d232461a435a | feat(cli): machine renew adds a new host CA's line to the managed known_hosts |

### R2

- Staged by path: cmd/keyroster/knownhosts.go, cmd/keyroster/knownhosts_test.go,
  cmd/keyroster/machinehosttrust.go, cmd/keyroster/machinehosttrust_test.go,
  cmd/keyroster/machinerenew.go. Before the commit, `git diff --cached <file>` of each of the
  five files was read in full, each file by its own command: four of them in one tool call, and
  the new test file's 956-line diff in two consecutive ranges (lines 1 to 480 and 481 to 956),
  nothing skipped (the two new files whole: 41 and 950 lines).
- gofmt clean, `go vet ./cmd/keyroster/` exit 0; carriage returns 0 in each file.
- The staged-lines scan (03-12f2-PLAN.md's, unchanged), with the owner's private pattern files:
  exit 0.
- Signed (SSH signature present), authored as Daniel Gustafsson, committed by keyroster-bot.
- The RED (Task 2's second verify command, plan line 646, from a detached worktree of R2 outside
  the repository): exit 0. Its log, kept by one re-run of the same command that only copies
  red.log out before the worktree is removed: 54 `--- FAIL:` lines, 54 distinct names: the 46
  leaves the plan lists, the 5 parents (TestAddHostCALines,
  TestAddHostCALines/not_writer_form_refused, TestMachineHostTrust,
  TestMachineHostTrust/failures_exit_4, TestMachineHostTrustCaller) and the fuzz seeds
  FuzzAddHostCALines/seed#0, seed#2 and seed#3 (seed#1, the disagreeing input, passes on the
  stub, since both its lines are present). No `[build failed]`, `[setup failed]` or
  `--- SKIP` line. The controls pass: TestAddHostCALines/never_adds_a_draining_or_retired_key,
  nothing_to_add_returns_the_input, no_trusted_line_adds_nothing;
  TestMachineHostTrust/no_known_hosts_adds_nothing, no_managed_file_is_silent,
  unchanged_is_silent, home_mismatch_without_file_is_0; TestKnownHosts (with the changed
  narrowing leaf `narrows_on_any_command_with_verified_bundle/machine_renew`). Every failure is
  an assertion; `stale_bundle_after_the_floor_moved_adds_nothing` fails at run 1's file check.

### G2

- Staged by path: cmd/keyroster/knownhosts.go, cmd/keyroster/machinehosttrust.go,
  cmd/keyroster/machinerenew.go; no test file. Before the commit, `git diff --cached <file>` of
  each of the three files was read in full, each file by its own command (knownhosts.go and
  machinerenew.go in one tool call, then machinehosttrust.go), nothing skipped.
- gofmt clean, `go vet ./cmd/keyroster/` exit 0; carriage returns 0 in each file.
- The staged-lines scan, with the owner's private pattern files: exit 0.
- Signed (SSH signature present), authored as Daniel Gustafsson, committed by keyroster-bot.
- Every test of R2 passed on G2 at the first run; no test was changed.
- Task 2's first verify command (plan line 644, R2 and G2 set): exit 0.
- Task 2's third verify command (plan line 648): exit 0. The named tests under `-race`:
  `ok  github.com/Labontese/keyroster/cmd/keyroster 64.342s`; the fuzz run of
  FuzzAddHostCALines for 60 s, last line `fuzz: elapsed: 1m1s, execs: 3543878 (0/sec), new interesting: 61 (total: 65)`,
  then `PASS` and `ok ... 61.213s`, no failing input; `git status --short` afterwards shows no
  new file under cmd/keyroster/testdata (no corpus file is staged or committed);
  golangci-lint `0 issues.` under linux, `GOOS=windows` and `GOOS=darwin`.

- Task 2's fourth verify command (plan line 650, the whole package under `-race`): exit 0,
  `ok  github.com/Labontese/keyroster/cmd/keyroster 315.024s`. Against the test-time base of
  280.230 s that is +34.8 s; the plan expected +3 s to +10 s, and Task 5's delta gate (at most
  +90 s, measured again there) decides.

### The code mutants (M438 to M459, M498 to M500)

The command of every mutant, as Task 2 gives it:
`bash scripts/linux.sh 'exec 2>&1; go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -run "^(TestAddHostCALines|TestMachineHostTrust|TestMachineHostTrustCaller|TestKnownHosts)$" ./cmd/keyroster/'`.
Its unmutated run on G2 passed first: once with `-v` added (150 `--- PASS:` lines, among them
`--- PASS: TestKnownHosts`, `--- PASS: TestAddHostCALines`, `--- PASS: TestMachineHostTrust`,
`--- PASS: TestMachineHostTrustCaller`; no FAIL or SKIP line; `ok ... 7.985s`) and once exactly
as given (`ok ... 8.493s`). For every mutant: the file's sha256 before; one exact replacement,
asserted to occur exactly once in its file (a script that refuses any other count); the command
above, in which `go vet` ran first and passed (the tests ran); the log checked for
`[build failed]`, `[setup failed]`, `--- SKIP`, a timeout, a vet or compile line (0 in every
log); `git checkout -- <file>`; the sha256 after the restore equal to the one before; and
`git status --short -- cmd internal test docs .github` empty. Every run exited 1 with the named
`--- FAIL:` lines below. sha256 before and after: machinerenew.go
9fdbd661ef4910137b90f030d50ff8cfe1a290e633fe1518ce8a2c5e610cb1a8, machinehosttrust.go
821ca964a2750356501e777e939eeeb42cac880fbc5c2bc567b9e05bd2aa8e4b, login.go
26183928e7dfba433d7d240f2c54704d0cb46387d71229d177ede139ae93e637. No file is left in a
mutant state.

| Mutant | File: exact replacement (`\n`, `\t` as escapes) | Named leaf failed, with its assertion | Other leaves that also failed |
|--------|-----------------------------------------------|---------------------------------------|-------------------------------|
| M438 | machinerenew.go: `hostTrust = machineHostTrust(bundle, trustClock(), stderr)` -> `hostTrust = nil` | TestMachineHostTrust/adds_the_next_line_and_moves_the_floor (`machinehosttrust_test.go:536: stderr: ... want "Host trust: added the CA line of host CA generation 2 ..." once`); TestMachineHostTrustCaller/only_machine_renew_calls_it_after_verified_trust (`:944: machineHostTrust is referenced 0 times outside its declaration ([]), want once, in runMachineRenew`) | every other TestMachineHostTrust leaf that expects the step |
| M439 | machinerenew.go: `\t\t\treturn hostTrust\n` -> `\t\t\treturn nil\n` (the not-due branch) | TestMachineHostTrust/not_due_failure_exits_4 (`:799: exit 0, 0 sent, stdout: ... want exit 4, not due and nothing sent`) | none |
| M440 | machinerenew.go: `\n\treturn hostTrust\n` -> `\n\treturn nil\n` (the renewed path) | TestMachineHostTrust/failures_exit_4, all 15 subtests (`:775: exit 0, want 4`) | stale_bundle_after_the_floor_moved_adds_nothing (`:880: run 3: exit 0`) |
| M441 | machinerenew.go: `if !*noKnownHosts {` -> `if !*noKnownHosts \|\| true {` | TestMachineHostTrust/no_known_hosts_adds_nothing (`:626: stderr: ... want no line of the host trust step`) | TestKnownHosts/narrows_on_any_command_with_verified_bundle/machine_renew (`knownhosts_test.go:2754: host-trust.json changed`), the leaf this plan gave `--no-known-hosts` |
| M442 | machinehosttrust.go: `for _, e := range issuing {` -> `for _, e := range trusted {` | TestAddHostCALines/never_adds_a_draining_or_retired_key (`:114: addHostCALines(...) = ... want ...`); TestMachineHostTrust/never_adds_a_draining_line (`:570: stderr: ... want no line of the host trust step`) | none |
| M443 | machinehosttrust.go: `if i < 0 {\n\t\t\tcontinue\n\t\t}` -> `if i < 0 {\n\t\t\ti = 0\n\t\t}` | TestAddHostCALines/untrusted_lines_give_no_names (`:133: addHostCALines(...): a CA line of a host CA the trust bundle trusts is not in the form keyroster writes`) | TestAddHostCALines/no_trusted_line_adds_nothing (`:126`, the same refusal of its untrusted line) |
| M444 | machinehosttrust.go: `if len(have) > 0 && f[1] != names {` -> `if len(have) > 0 && f[1] != names && false {` | TestAddHostCALines/disagreeing_lines_refused (`:137: ...: error <nil>, want "its CA lines ... name different hosts"`); TestMachineHostTrust/failures_exit_4/lines_disagree (`:775: exit 0, want 4`) | none |
| M445 | machinehosttrust.go: `if line != hostCALine(f[1], trusted[i]) {` -> `if line != hostCALine(f[1], trusted[i]) && false {` | TestAddHostCALines/not_writer_form_refused/tab_separated, upper_case_marker, wrong_generation, crlf, extra_field, no_final_newline (each `:159: ...: error <nil>, want "a CA line of a host CA the trust bundle trusts is not in the form keyroster writes"`); TestMachineHostTrust/failures_exit_4/not_writer_form (`:775: exit 0, want 4`) | not_writer_form_refused/no_comment |
| M446 | machinehosttrust.go: `if !hostTrustName(n) {` -> `if !hostTrustName(n) && false {` | TestAddHostCALines/not_writer_form_refused/wildcard_name, negated_name, hashed_name (each `:159: ...: error <nil>, want "a CA line ... not in the form keyroster writes"`) | none |
| M447 | machinehosttrust.go: `if j > 0 && hosts[j-1] >= n {` -> `if j > 0 && hosts[j-1] >= n && false {` | TestAddHostCALines/not_writer_form_refused/unsorted_names, duplicate_name (each `:159`, as above) | none |
| M448 | machinehosttrust.go: `if len(out) > 0 && out[len(out)-1] != ` -> `if false && len(out) > 0 && out[len(out)-1] != ` | TestAddHostCALines/missing_final_newline_gets_one (`:167: addHostCALines(...) = ... want ...`) | none |
| M449 | machinehosttrust.go: `if b.Version > st.BundleVersion {` -> `if b.Version > st.BundleVersion && false {` | TestMachineHostTrust/stale_bundle_after_the_floor_moved_adds_nothing (`:854: host-trust.json: ... want ...`, run 1's floor check) and adds_the_next_line_and_moves_the_floor (`:538: host-trust.json`) | every leaf that expects the floor at 3: adds_the_active_line_beside_a_draining_one, never_adds_a_draining_line, narrows_and_moves_the_floor, not_due_adds_the_line, renewal_refused_still_adds_and_exits_1, failures_exit_4/file_write_failure, state_write_failure, file_changed_meanwhile, home_lookup_warning_uses_its_dir, adds_the_line_from_a_config_without_a_user |
| M450 | machinehosttrust.go: `case b.Version < st.BundleVersion:` -> `case b.Version < st.BundleVersion && false:` | TestMachineHostTrust/failures_exit_4/older_bundle (`:775: exit 0, want 4`) | stale_bundle_after_the_floor_moved_adds_nothing (`:880: run 3: exit 0`) |
| M451 | machinehosttrust.go: `case b.Version == st.BundleVersion && b.OpsKey.Key != st.OpsKey:` -> `... && b.OpsKey.Key != st.OpsKey && false:` | TestMachineHostTrust/failures_exit_4/equal_version_other_ops_key (`:775: exit 0, want 4`) | none |
| M452 | machinehosttrust.go: `case st.InstallationID != b.InstallationID:` -> `case st.InstallationID != b.InstallationID && false:` | TestMachineHostTrust/failures_exit_4/other_installation (`:775: exit 0, want 4`) | none |
| M453 | machinehosttrust.go: `return fail(p, "the host trust state is missing")` -> `return nil` | TestMachineHostTrust/failures_exit_4/missing_state (`:775: exit 0, want 4`) | none |
| M454 | machinehosttrust.go: `err != nil \|\| !bytes.Equal(got, data) {` -> `(err != nil \|\| !bytes.Equal(got, data)) && false {` | TestMachineHostTrust/failures_exit_4/file_changed_meanwhile (`:775: exit 0, want 4`) | none |
| M455 | machinehosttrust.go: `err != nil \|\| !bytes.Equal(got, stateBytes) {` -> `(err != nil \|\| !bytes.Equal(got, stateBytes)) && false {` | TestMachineHostTrust/failures_exit_4/state_changed_meanwhile (`:775: exit 0, want 4`) | none |
| M456 | machinehosttrust.go: `if herr != nil {` -> `if herr != nil \|\| true {` | TestMachineHostTrust/failures_exit_4/home_mismatch_with_file (`:775: exit 0, want 4`) | none |
| M457 | machinehosttrust.go: `return fail(p, "it is not a regular file")` -> `return nil` | TestMachineHostTrust/failures_exit_4/not_a_regular_file (`:775: exit 0, want 4`) | none |
| M458 | login.go: `l := &loginRun{` -> `_ = machineHostTrust\n\tl := &loginRun{` | TestMachineHostTrustCaller/only_machine_renew_calls_it_after_verified_trust (`:944: machineHostTrust is referenced 2 times outside its declaration ([{runLogin login.go:191:6 ...} {runMachineRenew machinerenew.go:123:15 ...}]), want once, in runMachineRenew`) | none |
| M459 | machinehosttrust.go: `machineHostTrustExit = 4` -> `machineHostTrustExit = 1` | TestMachineHostTrust/failures_exit_4, all 15 subtests (`:775: exit 1, want 4`) | not_due_failure_exits_4; stale_bundle_after_the_floor_moved_adds_nothing (`:880: run 3: exit 1`) |
| M498 | machinehosttrust.go: `err != nil \|\| !bytes.Equal(got, onDisk) {` -> `(err != nil \|\| !bytes.Equal(got, onDisk)) && false {` | TestMachineHostTrust/failures_exit_4/state_changed_at_equal_floor (`:775: exit 0, want 4`) | none |
| M499 | machinehosttrust.go: `if errors.As(err, &lw) {` -> `if errors.As(err, &lw) && false {` | TestMachineHostTrust/home_lookup_warning_uses_its_dir (`:813: host-trust.json: ... want ...`) | none |
| M500 | machinehosttrust.go: `case int64(len(data)) > maxNarrowFile:` -> `case int64(len(data)) > maxNarrowFile && false:` | TestMachineHostTrust/failures_exit_4/too_large (`:775: exit 0, want 4`) | none |

No mutant survived, none was killed by a build failure or a timeout, and every named leaf
failed on an assertion. Kills beyond the named leaves are listed in the last column; no
mutant was killed only by another assertion than the named leaf's.

## Task 3

### C3

| Name | SHA | Subject |
|------|-----|---------|
| C3 | a7381a36a136f46cf71cc74dc49061126d4adb10 | test(e2e): refresh a third client's host CA lines with machine renew across the host-CA switch |

- The additions of the plan's C3 table, in that order and nowhere else, in
  test/e2e/hostca_rotation_test.go only: `hcrMachineLine` after `hcrLine` with its dictated
  comment; `PoPMachines: true` in the `startServerEnv` line; the setup between `hostTrustKR` and
  `joinHostCert` (`mKey`, the role and machine calls, `renew`, the first renewal and its checks,
  the logged duration); step 3's two not-due renewals before A's sync, with `f1`, `st0`, `cKH`
  and `cfgC`, and the check after A's sync that the real file no longer equals `cKH`; C's login
  after B's at step 6 and after A's at step 8; `t.Log(hcrMachineLine)` before `t.Log(hcrLine)`;
  the doc comment's one sentence. `renew` fails with its stdout, stderr and the server log on a
  non-zero exit. The state comparison decodes both states as JSON objects, sets
  `bundle_version` to 2 in the earlier one and compares the two re-encoded objects. No helper of
  another file changed; no bound, anchor, assertion or source address of A or B changed.
- Staged by path: test/e2e/hostca_rotation_test.go only. Before the commit, `git diff --cached`
  of that file was read in full (one command, nothing skipped). Carriage returns 0.
- Task 3's second verify command (vet under both tag sets, gofmt, the two `go list` checks, the
  tagged lint against origin/main and the linux lint): exit 0, `0 issues.` twice; then
  golangci-lint under `GOOS=windows` and `GOOS=darwin`: `0 issues.` each.
- The staged-lines scan, with the owner's private pattern files: exit 0.
- Signed (SSH signature present), authored as Daniel Gustafsson, committed by keyroster-bot; no
  attribution line.
- Task 3's first verify command (plan line 678, C3 and G2 set): exit 0.

### The namespace wrapper

The wrapper is the orchestrator's prototype, copied unchanged (sha256 begins bd0d87c0cee3c9c9)
to a scratch directory outside the repository and never committed. It runs its arguments in an
unprivileged user and mount namespace (`unshare --user --map-root-user --mount`) in which a
private copy of `/etc/hosts` with the line `127.0.0.1 keyroster.localhost` is bound over
`/etc/hosts` and a private empty 0700 directory is bound over `$HOME/.ssh`, and then through an
inner `unshare --user` that maps the caller's own uid and gid back; `KEYROSTER_E2E_REAL_HOME=1`
is set and `GITHUB_ACTIONS` unset. It changes no system file, and the real `~/.ssh` was never
listed, read or written. The self-check of 03-12f2-PLAN.md, Task 2, item 2 failed as worded on
its first leg and passed with that leg corrected (deviation 4): exit 0 before any end-to-end run.

### The local pre-check (plan line 673, verbatim, in the background, nothing else in WSL)

Started 19:18:51 UTC (epoch 1795461531), ended 19:32:56 UTC (epoch 1795462376): 845 s for both
runs. Task 3's third verify command on the output directory: exit 0. No `WARNING host
certificate answer for` line in either log; every `Server host certificate` line names the
signing CA's `SHA256:` fingerprint, the one the login expected.

| Reading | 10.5p1 (`hostca-10.5p1.log`) | 9.5p1 (`rotation-9.5p1.log`) |
|---|---|---|
| exit | `exit 0` | `exit 0` |
| `go test` | `ok ... 171.061s` | `ok ... 664.565s` (the lane's three tests; below 900 s) |
| PASS lines | `--- PASS: TestHostCARotation (149.20s)` | `--- PASS: TestCANextAndAbort (39.80s)`, `--- PASS: TestCARotationNoFailedLogin (475.38s)`, `--- PASS: TestHostCARotation (132.05s)` |
| setup additions (logged) | 75 ms | 78 ms |
| step 3's two renewals (logged) | 30 ms | 29 ms |
| c1 observed after its issuance | 1.213 s | 1.195 s |
| r1 | 61 s after c1, observed 1.55 s after its issuance | 54 s after c1, observed 1.752 s after its issuance |
| late anchor / re-anchor | none / `re-anchored: false` | none / `re-anchored: false` |
| bundle 2 committed after its install | 10.129 s | 14.167 s |
| bundle 3 committed after its install | 14.737 s | 10.998 s |
| step 6 ended | r1 + 2.194 s (bound r1 + 28 s) | r1 + 2.701 s (bound r1 + 28 s) |
| C right after the switch | `ssh exited 0`, CA `SHA256:ILGZtmYI+5UEaL6txUV1lK9ShNTAfs9hn8KvmbGl3y0` (generation 1, as expected) | `ssh exited 0`, CA `SHA256:a6LHgV8EU14syzFbh9WwWiiREvTXtTPA9giBFQ2aY78` (generation 1, as expected) |
| C after the renewal | `ssh exited 0`, CA `SHA256:y9Nsj1SBGiLERw1rO5Tbfglwp04unanM9Ocp7UpxN9Y` (generation 2, as expected) | `ssh exited 0`, CA `SHA256:jFR5Zj/b4ztf3cJK+SQovSSWK9xZWQjq4LP12TW7QaM` (generation 2, as expected) |
| B after the renewal | `ssh exited 255`, Host key verification failed, CA of generation 2 | `ssh exited 255`, CA of generation 2 |
| both fixed lines | once each (`hcrMachineLine`, then `hcrLine`) | once each |

No run failed; no clock flake.

### M460

- The unmutated control (plan line 675's command, `-timeout 12m`, through the wrapper on
  10.5p1, in the background): `--- PASS: TestHostCARotation (141.89s)`, both fixed lines,
  `ok ... 160.757s`, exit 0.
- sha256 of cmd/keyroster/machinehosttrust.go before:
  821ca964a2750356501e777e939eeeb42cac880fbc5c2bc567b9e05bd2aa8e4b. The exact replacement,
  asserted unique: `func machineHostTrust(b *trust.Bundle, now time.Time, stderr io.Writer) error {\n`
  -> the same line followed by `\tif machineHostTrustExit > 0 {\n\t\treturn nil\n\t}\n`.
  `go vet ./cmd/keyroster/`: exit 0.
- The same command: exit 1, `hostca_rotation_test.go:590: step 3: machine renew --if-due added
  no line; stderr:` (an empty stderr), `--- FAIL: TestHostCARotation (40.83s)`; no
  `[build failed]`, `[setup failed]`, SKIP or timeout line.
- Restored with `git checkout --`; sha256 after equal to the one before;
  `git status --short -- cmd internal test docs .github` empty.

## Task 4

Precondition: `git diff --quiet origin/main -- docs` exit 0, origin/main still
a49a214604600c3bc2818584acdde47c5bf2315c.

### Commits

| Name | SHA | Subject |
|------|-----|---------|
| R4 | 771d29e7c0246c9947fd9cde61ba436c866c70fc | test(cli): pin the runbook text of machine renew's host CA refresh |
| W4 | 8f78bb1a9a975f425b351b32885937f1b16fd9b9 | docs(runbooks): say that machine renew refreshes an automation account's host CA lines |

### R4

- The pins were taken from the plan's bytes by a script that parses the `- P<n> ``...``` lines
  (plan lines 496 to 537), asserts P1 to P42 each once, and drops the one trailing space before
  the closing double backtick of P22, P30 and P32 only (the plan's note); no phrase holds a `"`
  or a backslash, so each is written as a Go string literal as it stands. Counts: 42 new
  phrases (P1 to P42); 3 replaced (P12 for runbook_test.go:1216, P16 for :1226, P23 for
  hosttrust_runbook_test.go:143's token); 4 dropped from the machine window (:1250, :1251, :1252,
  :1254; :1253 stays); 7 new forbidden phrases (`is never rewritten by a full refresh` and
  `(an automation account, or a host that ssh connects onward from)` in "The host CA";
  `` `keyroster machine renew` does not refresh the host trust files ``,
  `It writes only the certificate`, `is refreshed only by an admin who runs`,
  `0 when the certificate was written or is not due, 1` and `before it writes anything` in the
  machine window, where `before a host-CA rotation` stays forbidden). Each new group has a
  comment citing (03-12g). No document changed.
- Phrase counts on the base runbooks (whitespace runs joined): P1 to P42 each 0; the three
  leaving phrases 1 each; the seven new forbidden phrases 1 each; `before a host-CA rotation` 0;
  `after ceremony 1's install and before ceremony 2's install` 1 in machine-identities.md. The
  same after W4: P1 to P42 each 1; the three leaving phrases and the seven forbidden phrases 0;
  `before a host-CA rotation` 0; the kept phrase 1.
- gofmt clean, `go vet ./cmd/keyroster/` exit 0; carriage returns 0 in both files;
  golangci-lint `0 issues.` under linux, `GOOS=windows` and `GOOS=darwin`.
- Staged by path: the two test files. Before the commit, `git diff --cached` of each was read in
  full, each file by its own command, nothing skipped.
- The staged-lines scan, with the owner's private pattern files: exit 0.
- Signed (SSH signature present), authored as Daniel Gustafsson, committed by keyroster-bot.
- The RED (Task 4's second verify command, plan line 714, from a detached worktree of R4 outside
  the repository): exit 0. As in session 1 (deviation 2) it was run a second time from a copy
  whose only change is `cp "$W/red.log" <scratch file>;` before `rm -rf "$W"`; exit 0 too. Its
  log: exactly four `--- FAIL:` lines, `TestHostTrustRunbooks`,
  `TestHostTrustRunbooks/enroll_user_trusting_hosts`, `TestCARotationSwitchRunbook`,
  `TestCARotationSwitchRunbook/host_ca_gate`; every other subtest of the two tests passes; no
  build, setup or SKIP line. 49 messages: 42 `lacks` (one per new phrase) and 7 `still holds`
  (one per new forbidden phrase), among them the four the command names:
  `ca-rotation.md "The host CA" lacks "An automation account that has the managed files refreshes itself ...`,
  `machine-identities.md "Renew a machine certificate" still holds "`keyroster machine renew` does not refresh the host trust files"`,
  `item 4, the lag lacks "An automation account's ...` and
  `item 4a, host-CA rotation lacks "one host and three clients on loopback, one of them refreshed by `keyroster machine renew`"`.
  The worktree was removed by the command.

### W4

- Blocks B1 to B11 were applied by a script that takes each block from the plan's quoted lines
  (one `> ` stripped; the plan lines around each block are not quoted), and before any edit
  asserts, for each of the 13 replaced ranges (B8 has three), the first base line's start and
  the last base line's end at the stated line numbers (the plan's "from"/"to" text where it gives
  one), the line before and after (blank where the range is a paragraph, otherwise its text),
  that the ranges do not overlap, and that the old text occurs exactly once in its file; then it
  replaced the ranges bottom-up within each file, with the dictated line breaks, LF only. A dry
  run passed every assertion before the real one. Ranges: ca-rotation.md :318-327 (B1), :659-661
  (B2), :695-709 (B3), :773-774 (B4), :788-803 (B5), :853 (B6); enroll-user.md :646-651 (B7),
  :653-658, :673-676, :679-683 (B8); machine-identities.md :98-103 (B9), :112-119 (B10),
  :121-124 (B11). The widest added line is 74 columns (B3, B9). Carriage returns 0 in each file.
- No test changed. Staged by path: the three runbooks. Before the commit, `git diff --cached` of
  each was read in full, each file by its own command, nothing skipped.
- The staged-lines scan, with the owner's private pattern files: exit 0.
- Signed (SSH signature present), authored as Daniel Gustafsson, committed by keyroster-bot.
- Task 4's third verify command (plan line 716): exit 1 when run before the commit, as the
  action orders it, exit 0 after the commit (deviation 5); in both runs every runbook test
  passed (`ok ... 17.478s`, then `ok ... 4.064s`) and golangci-lint printed `0 issues.` under
  linux, windows and darwin.
- Task 4's first verify command (plan line 712, R4, W4 and C3 set): exit 0.

### The document mutants (M461 to M497, M501 to M505)

The command, as Task 4 gives it:
`bash scripts/linux.sh 'exec 2>&1; go test -count=1 -timeout 5m -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/'`.
Its unmutated run on W4 passed first (`ok ... 1.345s`; with `-v` added,
`--- PASS: TestHostTrustRunbooks` and `--- PASS: TestCARotationSwitchRunbook`). The mutant
rule's `go vet` leg: `go vet ./cmd/keyroster/` exited 0 on W4 (inside the third verify
command), and no document mutant touches a Go file. A script parsed
each row of the plan's table (lines 858 to 902, the three code rows skipped): the line it
mutates, its replacement and its pin (`lacks P<n>`). Where a row elides with `...`, the script
holds the full replacement line and checks that the row's text, each `...` read as any text,
matches it whole; the line's indentation in the file is kept. For every mutant: the line occurs
exactly once in its file, as a whole line and as text; sha256 of the file before; the one
replacement; the command; the log kept; `git checkout --` of the file; sha256 after equal to the
one before; `git status --short -- cmd internal test docs .github` empty. Each run exited 1, with
no `[build failed]`, `[setup failed]`, `--- SKIP` or timeout line, and its log holds the named
leaf's `--- FAIL:` line (with its parent) and the message `... lacks "<the pin>"`.

| Mutant | Line | Pin | Failing leaf |
|--------|------|-----|--------------|
| M461 | ca-rotation.md:324 | P1 | host_ca_gate ("Before ceremony 2") |
| M462 | ca-rotation.md:663 | P2 | host_ca_gate ("The host CA") |
| M463 to M476 | ca-rotation.md:699, 701, 705, 706, 708, 710, 713, 716, 729, 795, 812, 822, 825, 831 | P3 to P16 | host_ca_gate ("The host CA") |
| M477 | ca-rotation.md:884 | P17 | host_ca_gate ("Run in CI") |
| M478, M479 | enroll-user.md:650, 652 | P18, P19 | enroll_user_trusting_hosts (item 4) |
| M480 to M483 | enroll-user.md:663, 682, 689, 691 | P20 to P23 | enroll_user_trusting_hosts (item 4a) |
| M484 to M497 | machine-identities.md:103, 113, 115, 118, 123, 124, 125, 127, 132, 134, 143, 147, 149, 151 | P24 to P37 | host_ca_gate ("Renew a machine certificate") |
| M501 | ca-rotation.md:833 | P38 | host_ca_gate ("The host CA") |
| M502 | enroll-user.md:694 | P39 | enroll_user_trusting_hosts (item 4a) |
| M503 | machine-identities.md:138 | P40 | host_ca_gate ("Renew a machine certificate") |
| M504 | machine-identities.md:99 | P41 | host_ca_gate ("Renew a machine certificate") |
| M505 | machine-identities.md:154 | P42 | host_ca_gate ("Renew a machine certificate") |

All 42 were killed by the named leaf with the message of their own pin; each log holds exactly
that one message, except M504's, which also holds
`machine-identities.md "Renew a machine certificate" still holds "before it writes anything"`
(the mutant writes `anything:` back, a phrase of the same sentence that W4 made forbidden). No
mutant survived; none was killed only by another phrase. sha256 after the last restore:
ca-rotation.md eb8148c0c5e784f53e5e1723d1140587f388e2074d9e90f7940320583d6d6fcf (equal to W4's
blob), enroll-user.md 11e4c4084ba4fd4f81761cd1fb4d1b83c7afce21b66b1a66201fe91ea1d424d7,
machine-identities.md ac29d6ace91ac8d03f06dbfe6081522a0abd9e76d457c03da2f680e1470e0e2c. No file
is left in a mutant state.

## Task 5 (session 3): the publication, the gates, the PR and the tracking update

**Precondition** (2026-11-23): HEAD was W4 8f78bb1a9a975f425b351b32885937f1b16fd9b9, equal to
the remote head; after `git fetch origin`, origin/main was still
a49a214604600c3bc2818584acdde47c5bf2315c (no move since Task 1; PR #119 had not merged, and it
had not merged when this SUMMARY was written). Task 1's first three checks (plan lines 590, 592
and 594, each extracted byte for byte from the plan file by a script; `D` filled with the
dispatch's sha256) exited 0, 0 and 0; the second printed
`a49a214 test(serverclient): look for the peer's digits outside the request URL (#117)` and the
third `stopped_at: "Completed 03-12f2-PLAN.md (PR #118)"`. Every verify command of Task 5 (plan
lines 760 to 780) was extracted the same way and is run with `bash <file>` from the repository's
root, with the owner's two private pattern files named through their variables on the command
line where a command reads them.

### Commits

| Name | SHA | Subject |
|------|-----|---------|
| P5 | 1c2c3e0450804d8ee26922df08684765b9e07223 | docs(03-12g): plan machine renew's own refresh of host trust |

### P5

- The placement check and the stop guard were run again first: exit 0 each.
- 03-12d-PLAN.md: note N1 inserted after :186 by one `Edit`, as a blank line and N1's one line,
  nothing else; N1's bytes were taken from the plan with the third verify command's own `sed`.
  That command's 03-12d leg (a `cmp` against origin/main's first 186 lines, a blank line, N1 and
  origin/main's lines from :187 on) exited 0 before staging; carriage returns 0.
- Staged by path: the plan file and 03-12d-PLAN.md. `git show :<the plan> | sha256sum` printed
  2bdb0c0811ef2b3d9cd28ec81d1d4702262dcd57660e8d1da095c20443a3afc9, the `plan file sha256:` line
  above.
- The staged diffs were saved to files outside the repository and read in full after the last
  edit, each file by its own command: 03-12d-PLAN.md's (13 lines) in one read, and the plan's
  (1,019 lines, 218,435 bytes; folded at 1,400 columns to 1,038 lines) in nine consecutive
  ranges, lines 1-180, 181-310, 311-440, 441-590, 591-650, 651-740, 741-820, 821-960 and
  961-1038, nothing skipped.
- The publish scan: the seventh verify command, run whole and verbatim (deviation 6), exited 0
  before the commit; after the commit, its `git cat-file` leg then reading the plan at HEAD, it
  exited 0 again.
- Committed signed (SSH signature present), authored as Daniel Gustafsson, committed by
  keyroster-bot; 2 files, 1,015 insertions, no deletion. The plan file at HEAD hashes to the
  dispatch's value.

### Gates

- **The base**, re-measured first in this session's WSL boot (see "Task 1", the line under
  `test-time base:`): 271.776 s.
- **The delta gate** (the fifth verify command, in the background, nothing else running in WSL;
  the WSL boot id was the base's before and after it): exit 0,
  `ok  github.com/Labontese/keyroster/cmd/keyroster 281.971s`, +10.195 s over the base, no FAIL
  or DATA RACE; within the gate's 90 s. The plan expected +3 s to +10 s.
- **The full gate** (the sixth verify command, in the background, nothing else running in WSL):
  exit 0 on its first run, 813 s; 36 `ok` lines (cmd/keyroster 346.683 s,
  internal/agent/apply 629.176 s, internal/signer 515.836 s), no FAIL, DATA RACE or SKIP; every
  `go vet` tag set clean; gofmt clean; golangci-lint `0 issues.` under linux, windows, darwin and
  the `e2e,e2erotation` pass on the new lines; capslock v0.3.3: keyroster-signer 97 pairs
  (baseline 97), keyroster-agent 37 (37), keyroster-agent-fetch 23 (23), no pair new against a
  baseline; dep-firewall clean (EXEC leaves keyroster-agent only through
  internal/agent/execsite, 2 edges; `os/exec <- modernc.org/libc` the documented exception for
  keyroster-signer under both tag sets; no banned packages); testonly-firewall clean (6 GOOS/tag
  combinations); check-pinned-actions: all 55 `uses:` references pinned to commit SHAs. No clock
  flake and no re-run.

### Push and the PR

- Before the push: `git fetch origin` (origin/main still a49a214), the seventh verify command
  (the publish scan) exit 0 and the eighth (authorship) exit 0.
  `env -u GITHUB_TOKEN -u GH_TOKEN git push -u origin p03/12g-machine-renew-host-trust`:
  8f78bb1..1c2c3e0, accepted by the pre-push hook.
- **PR #120** (https://github.com/Labontese/keyroster/pull/120), opened by keyroster-bot through
  scripts/gh-as-bot.sh, base main, not a draft, title
  `feat(cli): machine renew adds a new host CA's line to the managed known_hosts`. Its body is
  the nine lines of Task 5's step 2, taken from the plan's bytes by a script (the list indent
  removed, each line one bullet), written to a file outside the repository, scanned before use
  with the tenth verify command's pattern legs (dotted quads, private terms, the owner's pattern
  files) and for carriage returns and attribution lines: clean (a planted dotted quad made the
  same scan exit 1); passed with `--body-file` (deviation 8). Read back after creation: the
  title as dictated, the body GitHub holds equal to the file, `autoMergeRequest` null (the
  eleventh verify command exit 0).
- CI runs for head 1c2c3e0 (pull_request) that existed when this SUMMARY was written: CI
  45259203956, E2E 45259204738, E2E TPM 45259203884, PIV 45259203933, E2E distro 45259203928,
  E2E PKCS#11 45259204097, Systemd 45259204029, CodeQL 45259204055, Workflow lint 45259205814,
  PR title 45259204987. The runs for this SUMMARY's own commit cannot be named in it: their IDs,
  the lane gate's output, both rotation lanes' and both main lanes' `go test` times beside the
  readings of "The budget", TestHostCARotation's duration in each rotation lane, the durations
  its setup additions and step 3's runs logged and whether it re-anchored enter this SUMMARY with
  the review's record.

### The tracking update

After the PR existed, once, by scoped `Edit`s only (no GSD command, never a whole-file write);
every file's diff was read in full afterwards.
- ROADMAP.md: the four wave heads of 03-13 to 03-16 were renamed top-down (43 to 44, 42 to 43,
  41 to 42, 40 to 41), each edit anchored on the head and its plan row; then, after 03-12f2's
  row, a blank line, `**Wave 40** *(blocked on Wave 39 completion)*` and
  `- [x] 03-12g-PLAN.md — CA rotation, host trust for automation (D-14, REVOKE-04, KEY-08): keyroster machine renew adds the line of a new host CA, exit 4 when it cannot`;
  the Plans line to `41/45 plans executed in 44 waves`; the progress row to `| 41/45 |`. No
  other row changed (no tool touched the file, so 03-12f's deviation 20 cannot recur).
- STATE.md, its six lines: `stopped_at: "Completed 03-12g-PLAN.md (PR #120)"` (the number read
  with `scripts/gh-as-bot.sh pr view p03/12g-machine-renew-host-trust --json number --jq .number`),
  `last_updated: "2026-11-23T20:26:05.108Z"` (printed by `date -u +%Y-%m-%dT%H:%M:%S.%3NZ` at
  the edit), `state_head: 1c2c3e0450804d8ee26922df08684765b9e07223` (P5, HEAD at the edit),
  `  total_plans: 80`, `  completed_plans: 76`, `Plan: 41 of 45`. The percentage, the progress
  bar and `Status:` are unchanged.
- The `wave:` lines of 03-13, 03-14, 03-15 and 03-16 became 41, 42, 43 and 44, each edit
  anchored on the lines around it; their `depends_on` stay.
- Carriage returns 0 in each file. REQUIREMENTS.md is not touched: REVOKE-04 and KEY-08 stay
  pending.
- Before this commit, a copy of the third verify command with P5 filled in and only its last
  leg dropped (the PLAN and SUMMARY counts at HEAD, which need this commit) exited 0: ROADMAP
  equals the intended file, STATE differs from origin/main's only in its six lines, each later
  plan only in its wave line, and 03-12d-PLAN.md is byte for byte origin/main's with N1.
- Totals after the update: `**Plans:** 41/45 plans executed in 44 waves.`,
  `| 3. Linux Agent and Revocation | 41/45 |`, `total_plans: 80`, `completed_plans: 76`,
  `Plan: 41 of 45`, `stopped_at: "Completed 03-12g-PLAN.md (PR #120)"`; 80 PLAN and 76 SUMMARY
  files under .planning/phases at this commit.

### This commit

Staged by path: .planning/ROADMAP.md, .planning/STATE.md, the four later plans and this
SUMMARY. `git diff --cached` of each was read in full, one file at a time, after the last edit
(this SUMMARY, a new file, whole); the staged-lines scan of 03-12f2-PLAN.md's Task 4, step 1,
with the owner's two pattern files passed through their variables, exited 0 before the commit.

### Verify commands of Task 5

- Before this commit: the 5th (delta gate) exit 0; the 6th (full gate) exit 0; the 7th (publish
  scan) exit 0 before P5, after P5 and before the push; the 8th (authorship) exit 0 before the
  push; the 11th (auto-merge) exit 0 after the PR's creation. Nothing outside .planning changed
  after the 5th and the 6th ran (they ran on P5, whose tree outside .planning is W4's).
- The 1st (required checks, the five named checks and the house e2e gate in MODE=pr), the 2nd
  (the lane gate), the 3rd (ROADMAP, STATE, waves, N1 and the file counts), the 4th (files,
  plan bytes, mutant and threat rows) and the 7th to 11th run in order on this commit's head
  after its push and CI; their results cannot be named in the commit they are about and enter
  this SUMMARY with the review's record.

### What stays UNVERIFIED (in the words of the plan)

> The step is tested at the command level against a stub server, from configurations with and without a user, and end to end on loopback on OpenSSH 9.5p1 and 10.5p1, where the renewal runs from an account that also holds an administrator's configuration, not from an automation account of its own. UNVERIFIED after it: a `keyroster machine renew` that a real cron job or timer runs, an automation account whose renewal runs as another OS account or with another `$HOME` than its ssh (unit-tested only: exit 4 when the account's home holds the file), a real automation host, Windows (the unit tests run on the cli-windows job; a Windows ssh reading the file does not), a sync that an admin runs for another account, and the host drain's end on a real client. Paths of the step no test reaches, each with its reason: the refusal of a file swapped between its `Lstat` and its open (`readNarrowFile`'s `errNarrowFileChanged`, narrow.go:211-221), because no seam lies between the two calls (the narrowing's same check is untested for the same reason, and the step reuses it unchanged); step 2's `Lstat` error other than "not existing" and its read error, and step 1's `Lstat` of the account home's file failing other than "not existing" (which returns 0), because no fixture makes `Lstat` or a read fail portably (a directory without search permission does not stop root and has no such meaning on the cli-windows job); step 3's key that does not parse, because `verifiedTrust` returns only a bundle whose every CA key passed `ParseKey` (internal/trust/bundle.go:230 and :363-366), so the check is defence in depth; and step 4's `hostTrustStatePath()` error, because it fails only when `configPath()` fails, and `loadConfig` has already failed then (cmd/keyroster/config.go:48-54 and :70-73). The test does not wait the gate's time.

The open questions of the planning work, each carried: whether OpenSSH falls back to a plain host key in the account's own `~/.ssh/known_hosts` when a host presents a certificate by an unknown CA is out of scope (it concerns accounts without the managed files, which this plan does not touch; the managed block names only the managed file, hosttrust_test.go:36-44 and knownhosts.go:80-86, so B's refusal shows no fallback for a managed name; 03-12f2's mutant run on 10.5p1 printed `No matching CA found. Retry with plain key` before its refusal, 03-12f2-SUMMARY.md:465, which says nothing about an unmanaged name with a known plain key) and stays UNVERIFIED; whether the renewal runs as the account and `$HOME` that ssh uses in real installations stays UNVERIFIED, made visible by exit 4 where it can be seen; Windows stays UNVERIFIED.

## Notes for later tasks

- `addHostCALines` follows "The step" literally: with a source line, `out` is `data`, a newline
  when `data` does not end in one, and the added lines; so a file with source lines and a last
  line without a newline gets the newline even when nothing is added. The step writes the file
  only when a line is added (step 7), so the command's behaviour is the same either way.
- The whole-package time on G2 (315.024 s) is 34.8 s above the base (280.230 s), more than the
  plan's expected +3 s to +10 s and below Task 5's 90 s gate; the new tests themselves take
  about 1.2 s (TestMachineHostTrust 1.09 s, TestMachineHostTrustCaller 0.12 s in the -v run);
  the rest of the difference is not isolated here. Task 5 re-measures the base as "Budget" says
  and applies its 90 s gate.
- No test of the package that runs `keyroster machine renew` makes `userSSHDir` return an error
  other than `errNoHomeDir` while `accountHome` is the real one: the only other override with a
  plain error (knownhosts_test.go:2376, `home_mismatch_warns`) calls the narrowing directly,
  never the step, and TestMachineHostTrust replaces `accountHome` in every test that sets such
  an error. So the package runs never stat the real home's `.ssh`.

## UNVERIFIED (in addition to the plan's list under "What stays UNVERIFIED")

- Step 6's failure of `encode()` on the moved state: no test reaches it (a state that
  `readHostTrustStateBytes` parsed and validated encodes again), so the branch and its reason
  text (deviation 3) are defence in depth, untested.

## Deviations

1. **The RED's fuzz seed lines.** R2's RED log holds, besides the plan's 46 named leaves and
   their 5 parents, the fuzz target's seed subtests, as Go names them:
   `--- FAIL: FuzzAddHostCALines (0.00s)`, `--- FAIL: FuzzAddHostCALines/seed#0 (0.00s)`,
   `--- PASS: FuzzAddHostCALines/seed#1 (0.00s)`, `--- FAIL: FuzzAddHostCALines/seed#2 (0.00s)`,
   `--- FAIL: FuzzAddHostCALines/seed#3 (0.00s)`. The plan names `FuzzAddHostCALines` only; the
   verify command's filter accepts the `FuzzAddHostCALines/...` names, and the command exited 0.
   seed#1 (the disagreeing input) passes on the stub, because both its lines are present; the
   plan's "the last property fails on the first seed" holds (seed#0).
   **Ruling (orchestrator): accepted.** The names Go prints for the fuzz seeds are the RED's own
   lines, and the verify command accepts them.
2. **The RED was run twice.** The RED verify command (plan line 646) ran verbatim first and
   exited 0. Because it removes its log with its worktree, it was then run a second time from a
   copy whose only change is `cp "$W/red.log" <scratch file>;` inserted before `rm -rf "$W"`;
   that run exited 0 too, and the 54 `--- FAIL:` lines above are counted from its log.
   **Ruling (orchestrator): accepted.** The second run of the RED changed only where its log is
   kept.
3. **An undictated reason text.** "The step" gives no reason for a failure of `encode()` in
   step 6; the code uses step 6's write reason, `writing the host trust state failed: <err>`.
   No test reaches the branch (see UNVERIFIED).
   **Ruling (orchestrator): accepted.** The reason text for a failed encoding of the state is the
   step's write reason; no test reaches that branch, and this SUMMARY lists it among the paths no
   test reaches.
4. **The wrapper's self-check, first leg.** As worded in 03-12f2-PLAN.md, Task 2, item 2, the
   self-check exited 1: its first leg, `"$W" getent hosts keyroster.localhost | grep -q
   "^127\.0\.0\.1[[:space:]]"`, read `::1 keyroster.localhost`. The cause is WSL's resolver in
   this boot (booted 2026-11-23 20:12:35 local time, boot_id
   e8028bb8-4029-455c-95c0-6f1167853fb0): DNS now answers names under `.localhost`, `::1` for
   IPv6 and `127.0.0.1` for IPv4, and `getent hosts` asks for IPv6 first; the private hosts copy
   holds only the IPv4 line, so the IPv6 answer comes from DNS. In 03-12f2's run DNS did not
   answer the name. Evidence: outside the wrapper `getent -s files hosts keyroster.localhost`
   exits 2 and `getent ahosts` gives both families; inside it `getent -s files hosts` gives
   `127.0.0.1` and `getent ahosts` (getaddrinfo, the path programs and Go's resolver take, files
   first) gives `127.0.0.1` alone. The leg was corrected to
   `test "$("$W" getent ahosts keyroster.localhost | awk '{print $1}' | sort -u)" = 127.0.0.1`
   (at least one answer, and every answer `127.0.0.1`), every other leg byte for byte; the
   corrected self-check, written to a file and run as `bash scripts/linux.sh "$(cat <file>)"`
   (inside the usual single-quoted form the leg's awk program is written `awk "{print \$1}"`),
   exited 0 before any end-to-end run. The wrapper is unchanged. The
   correction does not loosen the check: it asks what a process inside the wrapper resolves, and
   refuses any `::1` answer.
   **Ruling (orchestrator): accepted.** The wrapper's self-check as 03-12f2's plan words it failed
   on its first leg after a restart of WSL, because the resolver then answered the name with the
   IPv6 loopback address first while the wrapper's private hosts file holds only the IPv4 line.
   The corrected leg requires that every address the name resolves to inside the wrapper is
   127.0.0.1, which asks more than the worded leg did; every other leg ran as worded, and the
   self-check exited 0 before any end-to-end run. The orchestrator read the commands and their
   output.
5. **Task 4's third verify command, run before W4's commit.** The action orders "the third
   verify command, the full staged read, commit", but the command's last leg reads
   `git diff -U0 origin/main...HEAD -- docs/runbooks`, which is empty while the documents are
   not committed (HEAD was R4), so `test -n "$D"` failed and the command exited 1 after its test
   and lint legs had passed. Nothing was changed: the full staged read and the commit followed,
   and the command, run unchanged on W4, exited 0 (its plan-number leg read the added runbook
   lines then; checked before the commit on the working tree's diff against origin/main as
   well: 0 lines with a plan number besides `Run in CI e2e (03-09b):`).
   **Ruling (orchestrator): accepted.** Task 4's third verify command reads the branch's committed
   runbook diff, so it cannot pass before W4 exists; it passed unchanged on W4.
6. **The publish scan before P5 ran whole.** Task 5's action asks for "the whole-file legs of
   the publish scan (the seventh verify command, up to its `git cat-file` leg)" on the plan file
   before P5. Cutting the command at that leg would mean retyping it, so the seventh verify
   command ran whole and verbatim instead: its whole-file legs on the plan file first, then its
   `git cat-file` leg (skipped by its own `if` while the plan was not yet at HEAD) and its legs
   on the branch's added lines (R2 to W4). It exited 0. This asks more than the cut command
   would, never less; it ran again after the commit, with exit 0.
7. **The base command was prefixed with a read of the WSL boot id.** The base run was
   `bash scripts/linux.sh 'cat /proc/sys/kernel/random/boot_id; exec 2>&1; go test -race -count=1 -timeout 15m ./cmd/keyroster/'`,
   so that the base and the delta gate are shown to share one WSL boot (the plan's rule re-measures
   a base from another boot). The `go test` command is Budget's, unchanged.
8. **The PR's creation command.** The plan gives
   `scripts/gh-as-bot.sh pr create --title "feat(cli): machine renew adds a new host CA's line to the managed known_hosts"`
   and a body; the command run added `--base main --head p03/12g-machine-renew-host-trust` and
   `--body-file <the body file>`, and read its stdin from `/dev/null` so that it could not wait on
   a prompt. The title and the body are the plan's.
9. **F6 changes test text the plan dictates.** The plan's C3 table (plan line 251) places client
   C's setup between `hostTrustKR` and `joinHostCert` and adds no wait. F6 inserts, on the
   orchestrator's ruling after the red rotation lanes, the constant `hcrSetupPayback` with its
   comment and one `time.Sleep(hcrSetupPayback)` with its comment right after the setup's log
   line, so the host joins with the admin bucket it has on main (see "The rotation lanes' red
   runs on the first two heads, and the fix"). Nothing else in the file changes; the setup's
   logged duration stays the duration of the work, without the wait.
10. **There is now one fixed wait in the e2e test.** The plan's "The budget" says the e2e
    additions add no wait, and the PR text said "no new wait in the e2e test". There is now one
    fixed wait of 4 s in the setup, outside every window. The budget, plainly: the plan's
    slowest passing figures (about 878 s and 874 s) include an allowance of 15 s for tool time;
    the lanes measured the setup additions at 34 ms, 30 ms and 32 ms and step 3's two runs at
    12 ms, so the 4 s wait fits inside that allowance, and the figures and the 900 s rule stand;
    the typical figure moves by about 4 s.
11. **The PR body's budget line was replaced.** After F6 and S7 were pushed, the bot replaced
    only the body's line that began `- the budget: no new wait in the e2e test;` with
    `- the budget: one new fixed wait of 4 s in the e2e test's setup, outside every window (it pays back the admin requests the third client's setup spends before the host joins); the rotation lanes' slowest passing figure stays about 874 s to 878 s against the owner's 900 s, which applies to the measured run.`
    (`scripts/gh-as-bot.sh pr edit 120 --body-file <file>`); every other line of the body is
    unchanged.

### The plan's wording of one owner decision

The owner's answer of 2026-11-23 on the directory was the option text that the plan quotes in "Owner decisions": `machine renew` only adds the new host CA's line for the host names the account's file already trusts; no new way in; a stolen machine key gains nothing new; a brand-new automation account still needs a first sync by an admin, and hosts added later do not reach it until an admin syncs again. The sentence that follows the quotation in the plan ("So: no new route, credential, wire change, server or signer change; no bootstrap and no new host names through this path") and the same words in the plan's first truth are the plan's reading of the design that option describes, not the owner's words. The delivered change agrees with both: it changes the CLI only. The plan file is not edited for this; this paragraph is the correction.

## The rotation lanes' red runs on the first two heads, and the fix

**The red runs.** No CI re-run was made on either head.

| Run (head) | Lane | `go test` | TestHostCARotation | Readings |
|---|---|---|---|---|
| E2E 45259204738 (P5, 1c2c3e0) | e2e-rotation (9.5p1) | FAIL, 547.552 s | FAIL, 15.99 s | refused at `joinHostCert`'s `keyroster host approve` (below) |
| E2E 45259204738 (P5, 1c2c3e0) | e2e-rotation (10.5p1) | ok, 668.170 s | PASS, 138.92 s | setup 32 ms; step 3's two runs 12 ms; c1 observed 1.832 s and r1 1.924 s after issuance; `re-anchored: false`; both fixed lines once; client C right after the switch and after the renewal `ssh exited 0`, client B after the renewal `ssh exited 255` |
| E2E 45259904937 (first SUMMARY commit, 07a7a2e) | e2e-rotation (9.5p1) | FAIL, 545.296 s | FAIL, 15.98 s | setup 34 ms; refused at `keyroster host approve` |
| E2E 45259904937 (first SUMMARY commit, 07a7a2e) | e2e-rotation (10.5p1) | FAIL, 542.230 s | FAIL, 16.47 s | setup 30 ms; refused at `keyroster host approve` |

TestCANextAndAbort and TestCARotationNoFailedLogin passed in every one of these lanes. On
07a7a2e every other required check passed; its main lanes read 774.532 s and 777.342 s and its
probe lanes 278.300 s and 280.183 s.

**The cause.** Each failing log shows `keyroster host approve web1 ... exit 1` at
hostca_rotation_test.go:494 with `the server is rate-limiting requests from this address; try
again in 1 s`, and the server logged `rate limited` for `POST /api/v1/admin/directory` from
127.0.0.1 every 2 s, while `pending hosts listed` kept succeeding.
- `keyroster host approve` spends three admin requests: GET hosts/pending
  (cmd/keyroster/host.go:577), GET directory (cmd/keyroster/dirpipe.go:137), POST directory. A
  directory change (`role add`, `machine add`, `host-group add`, `host-group map`) spends two:
  the GET and the POST. `machine renew` is on its own limiter (internal/server/server.go:248) and
  spends none.
- The admin bucket is per client, 20 requests, one more a second
  (internal/server/ratelimit.go:60-61, server.go:189).
- The 9.5p1 lane of 07a7a2e: the first admin request at 20:44:13.9, the approval's POST at
  20:44:19.632. Before that POST the test had sent 25 admin requests: client C's setup 4,
  joinHostCert's three directory changes 6, the join token 1, twelve polls of host pending, the
  approval's two reads. 20 + 5.73 refilled - 25 = 0.73, under one request: refused. Without
  client C's four it is 4.73: main's state, which passes.
- The retry cannot recover: its 2 s wait refills two requests, the retry's two reads spend them,
  and the POST is refused again with 0.7 left; the log shows six refusals 2.01 s apart.
- The server binary has no setting for the limit (Limits is set in-process only), so the test
  cannot raise it. It passed locally (three times in session 2) and on P5's 10.5p1 lane because
  the count depends on how many polls run before the host enrolls; the branch's four requests
  are what took the margin away.

**The fix (F6).** The orchestrator ruled the fix: F6 50bc0df33ea4deaf096dc5537e7f2642bf7ac3a7,
`test(e2e): pay back the admin requests of the third client's setup before the host joins`,
two insertions in test/e2e/hostca_rotation_test.go only (14 added lines, none removed): in the
const block, between `hcrMachineLine` and the comment of `hcrClock`, the constant
`hcrSetupPayback = 4 * time.Second` with its eight-line comment; and right after the setup's
`t.Logf("setup: ...")` line, before the comment of `joinHostCert`, a four-line comment and
`time.Sleep(hcrSetupPayback)`. The wait is outside every window, so the host joins with the
bucket it has on main. The helpers hostTrustKR and hostCertKR are not changed. `git diff` of the
file was read in full before staging (exactly the two insertions); gofmt clean, `go vet` with the
rotation tags exit 0, carriage returns 0. No mutant is added: no test can tell the wait from its
absence except the CI lanes.

**The local pre-check** (not the proof), through the namespace wrapper only (session 2's
wrapper copied unchanged into this session's scratch directory, sha256 begins
bd0d87c0cee3c9c9; the corrected self-check of deviation 4 exit 0 first), nothing else running in
WSL, TestHostCARotation alone (`-run "^TestHostCARotation$"`, the plan's line 673 command form)
on 10.5p1 and then on 9.5p1, started at epoch 1795468917, ended at 1795469252:

| Reading | 10.5p1 | 9.5p1 |
|---|---|---|
| exit | `exit 0` | `exit 0` |
| `go test` | `ok ... 176.555s` | `ok ... 152.147s` |
| PASS | `--- PASS: TestHostCARotation (155.82s)` (session 2: 149.20 s) | `--- PASS: TestHostCARotation (137.84s)` (session 2: 132.05 s) |
| setup line | 72 ms | 76 ms |
| step 3's two runs | 29 ms | 31 ms |
| c1 / r1 observed after issuance | 841 ms / 1.177 s | 925 ms / 1.475 s |
| re-anchored | false | false |
| both fixed lines | once each | once each |
| client C right after the switch / after the renewal | `ssh exited 0` / `ssh exited 0` | `ssh exited 0` / `ssh exited 0` |
| client B after the renewal | `ssh exited 255` | `ssh exited 255` |

No SKIP, FAIL, build or setup failure, and no `WARNING host certificate answer for` line.

**The gates, re-run on F6's tree** (the working tree equal to F6, before its commit). WSL had
booted again (boot id 011372f6-9963-4a98-9bdb-83ce959b9cce), so the base was re-measured first
and replaced in place (see "Task 1"): 264.218 s. The fifth verify command (delta gate): exit 0,
`ok  github.com/Labontese/keyroster/cmd/keyroster 262.677s`, -1.541 s against the base, the same
boot id after it. The sixth verify command (full gate): exit 0 on its first run, 754 s (epoch 1795469846 to
1795470600); 36 `ok` lines (cmd/keyroster 298.101 s, internal/agent/apply 563.190 s,
internal/signer 453.168 s), no FAIL, DATA RACE or SKIP; every `go vet` tag set clean; gofmt
clean; golangci-lint `0 issues.` under linux, windows, darwin and the `e2e,e2erotation` pass;
capslock keyroster-signer 97 (baseline 97), keyroster-agent 37 (37), keyroster-agent-fetch 23
(23), no new pair; dep-firewall, testonly-firewall and check-pinned-actions clean. No clock flake
and no re-run.

**The proof** of the wait is the rotation lanes of the heads from F6 on; their readings enter
the section "Pre-merge review" when it is written.

**Open item.** The retry of hostTrustKR (test/e2e/hosttrust_test.go:104-107) and hostCertKR
(test/e2e/hostcert_test.go:36-39) cannot recover a drained bucket for a command of three
requests; it is on main, and this plan does not change it.

## Pre-merge review

Pending.
