---
phase: quick-261124-nhm
plan: 01
subsystem: cli-machine-renew
tags: [cli, machine-renew, host-trust, exit-status, runbook]
status: complete
requires: []
provides: ["keyroster machine renew without $HOME exits 4 when the home the account database names holds the managed keyroster_known_hosts", "a TestMain that keeps every test of cmd/keyroster out of the real account's home", "runbook text and pins on a run without $HOME and on what --no-known-hosts turns off"]
affects: []
key-files:
  modified: [cmd/keyroster/machinehosttrust.go, cmd/keyroster/knownhosts_test.go, cmd/keyroster/machinehosttrust_test.go, cmd/keyroster/runbook_test.go, docs/runbooks/machine-identities.md]
decisions:
  - "Without $HOME the host trust step looks up the account's home, as it already did for a $HOME that is not the account's home, and exits 4 when that home's .ssh holds the file (the owner's decision of 2026-11-24)."
  - "An account home that is not an absolute path counts as no home, so an account entry with an empty home never sends the check to the working directory."
  - "The narrowing stays silent without $HOME: it never changes an exit status."
requirements: []
metrics:
  completed: 2026-11-24
actuals:
  tasks: 4
  commits: 10
plan_head_before: 2d61b55
---

# Quick 261124-nhm Plan 01: keyroster machine renew without $HOME exits 4 when the account's home holds the managed file Summary

`keyroster machine renew` refreshes an automation account's host CA lines and exits 4 when the certificate is in place but that step failed. A run without `$HOME` (unset or empty) skipped the step silently, even when the home the account database names held `~/.ssh/keyroster_known_hosts`, the file the account's ssh reads. It now looks up that home and exits 4 when the file is there, as it already did for a `$HOME` that is not the account's home. In the same runbook paragraph, the sentence on `--no-known-hosts` now says what the flag turns off.

## Before and after

Before (cmd/keyroster/machinehosttrust.go at 2d61b55): step 1 of `machineHostTrust`, lines 148 to 167, was a `switch` on the error of `userSSHDir()`. Its first case, `case errors.Is(err, errNoHomeDir): return nil` (lines 155 and 156), ended the step at once when `$HOME` was unset or empty: `defaultSSHDir` (cmd/keyroster/knownhosts.go:128-132) wraps the error of `os.UserHomeDir` in `errNoHomeDir`. The run exited 0 and printed nothing of the step. Its second case, any other error (a `$HOME` that is not the account's home), looked up `accountHome()` and returned `fail(p, err.Error())` when `<account home>/.ssh/keyroster_known_hosts` existed: one warning line and exit 4. The doc comment's first bullet (lines 121 to 124) said "no home directory is nil". The leaf `TestMachineHostTrust/no_home_changes_nothing` (cmd/keyroster/machinehosttrust_test.go:958) pinned the exit 0.

After: every error of `userSSHDir()` except a `*homeLookupWarning` takes the second path. With no `$HOME`, the run exits 4 with the line `Warning: host trust not refreshed in <home>/.ssh/keyroster_known_hosts: no home directory: <the standard library's reason>.`, when the home the account database names is an absolute path whose `.ssh` holds the file. It returns nil (exit 0, nothing of the step) when the account lookup fails, when that home is not an absolute path, or when it holds no file. A `*homeLookupWarning` still uses the directory it carries.

Who that reaches, exactly:
- A run without `$HOME` reaches the step only when its configuration is still found, as through `XDG_CONFIG_HOME`. Without one, `loadConfig` (cmd/keyroster/machinerenew.go:106) fails and the run exits 1 before the step, before and after this change.
- It gets 4 only when the CLI can look the account up and that home holds the file.
- An account known only through NSS or LDAP gets 0 there: the CGO_ENABLED=0 Linux release's `os/user` reads only `/etc/passwd` (docs/runbooks/enroll-user.md, item 9), so the lookup fails.
- Windows does not get this 4 either. The home there is `%USERPROFILE%`, not `$HOME`, and `defaultSSHDir` returns it before any account lookup (cmd/keyroster/knownhosts.go:134-136), so a run refreshes the file in that home as on any other run.

The owner decided on 2026-11-24 that the command looks up the account's home also when `$HOME` is missing and exits 4 when the file is there; a job that deliberately runs without `$HOME` then gets 4 after an upgrade.

## The code

```go
	if err != nil {
		// No $HOME, or a $HOME that is not the account's home: ssh reads
		// the account database's home, so the step looks there. A home
		// that is no absolute path is no home.
		home, herr := accountHome()
		if herr != nil || !filepath.IsAbs(home) {
			return nil
		}
		p := filepath.Join(home, ".ssh", hostTrustKnownHosts)
		if _, serr := os.Lstat(p); serr != nil {
			return nil
		}
		return fail(p, err.Error())
	}
```

The doc comment's first bullet now reads: "~/.ssh: a failed account lookup uses the directory it carries; no $HOME, or a $HOME that is not the account's home, fails only when the home the account database names, an absolute path, holds the file in its .ssh, and is nil otherwise". Nothing else in the file changes. `errNoHomeDir` is still used by `defaultSSHDir` and by the narrowing (cmd/keyroster/narrow.go:115), and `go vet ./cmd/keyroster/` exits 0.

## Why TestMain changed

`TestMain` (cmd/keyroster/knownhosts_test.go) makes `userSSHDir` return an error that wraps `errNoHomeDir` for every test that does not install its own, so that no test touches a real home. Before the change that error ended the step. After it, the step calls `accountHome`, which is `user.LookupId` of the running uid. Without a stub, every test that runs `machine renew` without its own `userSSHDir` would look for the real account's `~/.ssh/keyroster_known_hosts`, and it would exit 4 on a computer whose real home holds that file. `TestMain` now also sets `accountHome` to a function that returns an error, and its comment says why.

Checked by grep at the base before the change. `accountHome` is replaced in tests only by `useHome` (cmd/keyroster/knownhosts_unix_test.go:17-23) and `mhtUseAccountHome` (cmd/keyroster/machinehosttrust_test.go:477-483). No test calls `accountHome` itself. `defaultSSHDir`, the other caller of `accountHome`, runs in tests only through `useHome`, which installs its own account home. So no test relied on the real one, and the stub changes no test's outcome on the old code. Every test of the mutant runs' pattern (`TestAddHostCALines`, `TestMachineHostTrust`, `TestMachineHostTrustCaller`, `TestKnownHosts`) runs under `TestMain`, so no mutant run looked into the real account's home either.

## The leaves (TestMachineHostTrust)

- `no_home_with_the_file_exits_4` (was `no_home_changes_nothing`). It uses the same fixture: the files planted under `<home>/.ssh`, `accountHome` that home, and `userSSHDir` an error that wraps `errNoHomeDir` as `defaultSSHDir` builds it. It requires:
  - exit 4 and the renewed summary on stdout;
  - exactly one warning of the step, `Warning: host trust not refreshed in <home>/.ssh/keyroster_known_hosts: no home directory: $HOME is not defined (a test).`, and the exit line, both through the helpers the leaves of `failures_exit_4` use;
  - no `Host trust: added` line, no narrowing line and no narrowing warning;
  - the four files' bytes unchanged.
- `no_home_without_the_file_is_0`: `accountHome` is a fresh temporary directory with no `.ssh`. It requires exit 0, the renewed summary and no line of the step.
- `no_home_without_an_account_home_is_0`: `accountHome` returns an error. Its stub returns the fixture's home, which holds the file, together with that error. With the empty string, `filepath.IsAbs` alone would have returned nil, so Q2 below could not have failed the leaf. It requires exit 0, the renewed summary and no line of the step.
- `no_home_with_a_relative_account_home_is_0`: the test writes `.ssh/keyroster_known_hosts` into a fresh temporary directory, changes into it with `t.Chdir`, and `accountHome` returns the empty string. It requires exit 0, the renewed summary, no line of the step and the file's bytes unchanged. The temporary directory is made before `t.Chdir`, so the directory change is undone before the directory is removed.

## RED

- **The tests, on the old code.** From a detached worktree of the tests' commit (41553f1), outside the repository: `go test -count=1 -timeout 5m -v -run '^TestMachineHostTrust$' ./cmd/keyroster/` exited 1. Its only `--- FAIL:` lines were `TestMachineHostTrust` and `TestMachineHostTrust/no_home_with_the_file_exits_4`, failing on the exit status: `machinehosttrust_test.go:966: exit 0, want 4`. `no_home_without_the_file_is_0`, `no_home_without_an_account_home_is_0` and `no_home_with_a_relative_account_home_is_0` passed (the old code's controls), as did the other leaves (37 `--- PASS` lines). The run had no build, setup, SKIP or timeout line.
- **The pins, on the old runbook.** From a detached worktree of the pins' commit (a6f6cff): `go test -count=1 -timeout 5m -v -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/` exited 1. `TestCARotationSwitchRunbook` and `TestCARotationSwitchRunbook/host_ca_gate` failed with exactly four messages:
  - two `runbook_test.go:1334:` messages, `machine-identities.md "Renew a machine certificate" lacks` followed by each of the two new sentences;
  - two `runbook_test.go:1339:` messages, one `still holds` for each of the two forbidden phrases, "turns it off" and "neither does a run without `$HOME`".

  `TestHostTrustRunbooks` and its six leaves passed.

Each worktree was removed with `git worktree remove` afterwards.

## The runbook

docs/runbooks/machine-identities.md, "Renew a machine certificate". Both blocks were applied by a script that asserted that the old text occurs once; the old text's line breaks matched the file.

- "and `--no-known-hosts` turns it off" became "and `--no-known-hosts` turns off the adding and the version record, not the removal". By the code, the flag skips only `machineHostTrust` (cmd/keyroster/machinerenew.go:121-124). `verifiedTrust` and its narrowing run before it whatever the flag says, and the flag's help says "CA lines the trust bundle no longer trusts are still removed from it".
- The sentence on exit 4 now reads: "An account whose home holds no `~/.ssh/keyroster_known_hosts`, or a run with `--no-known-hosts`, never gets 4; one whose home holds it gets 4 on every run while the server serves an older trust bundle than the account verified before, while its managed file is damaged or its state is missing, damaged or of another installation, or while `$HOME` is unset, empty or not the account's home (such a run changes no host CA line)."

"Its home" in the paragraph is the home the account database names, as its earlier sentences say. No sentence of the section contradicts the new one: the UNVERIFIED sentence, the "What to do" pointer and its "item 9 for `$HOME`" stay.

The pins of `TestCARotationSwitchRunbook/host_ca_gate`, window `machine-identities.md "Renew a machine certificate"`, were taken from the task's text by script. Counted on the runbook before the change, with whitespace runs joined:
- the two new phrases: 0 each;
- the two required phrases that leave: 1 each;
- the two new forbidden phrases: 1 each.

After the change, the two new phrases count 1 each, the leaving and forbidden phrases 0. "An account whose home holds no `~/.ssh/keyroster_known_hosts`, or a run with `--no-known-hosts`, never gets 4", the pointer's lead-in and the pointer's long phrase still count 1.

## Mutants

The rule for each:
- the unmutated narrow run passes first;
- one exact replacement, the old string asserted by script to occur once in its file;
- `go vet ./cmd/keyroster/` exits 0 (it runs first in the narrow command, joined by `&&`);
- the narrow run fails with the named leaf's `--- FAIL:` line and no `[build failed]`, `[setup failed]`, `--- SKIP` or timeout line;
- `git checkout --` of the file, the sha256 equal before and after, and `git status --short -- cmd internal test docs .github` empty.

The code mutants' narrow command: `go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -run "^(TestAddHostCALines|TestMachineHostTrust|TestMachineHostTrustCaller|TestKnownHosts)$" ./cmd/keyroster/`. The unmutated run: ok (7.5 s). machinehosttrust.go's sha256 at the fix's commit, before and after each code mutant: 65988bc01ff5aeb77ea68f6ed8e54cab5c8e597f65b2e97ebf1c83914a5e2e20.

- **Q1, the removed case back.** `if err != nil {` followed by the new comment's first line becomes `if err != nil && !errors.Is(err, errNoHomeDir) {`. The comment is part of the matched string, so that it occurs once. Result: `--- FAIL: TestMachineHostTrust/no_home_with_the_file_exits_4`, `machinehosttrust_test.go:966: exit 0, want 4`.
- **Q2, the account lookup's error ignored.** `if herr != nil || !filepath.IsAbs(home) {` becomes `if _ = herr; !filepath.IsAbs(home) {`. The task's form `if !filepath.IsAbs(home) {` leaves `herr` unused, which does not compile, so the error is discarded in the `if`'s init statement instead. Result: `--- FAIL: TestMachineHostTrust/no_home_without_an_account_home_is_0`, `machinehosttrust_test.go:1008: exit 4, want 0`.
- **Q3, the absolute-path check dropped.** `if herr != nil || !filepath.IsAbs(home) {` becomes `if herr != nil {`. Result: `--- FAIL: TestMachineHostTrust/no_home_with_a_relative_account_home_is_0`, `machinehosttrust_test.go:1029: exit 4, want 0`.
- **Q4, the `os.Lstat` check of the branch ignored.** `if _, serr := os.Lstat(p); serr != nil {` becomes `if _, serr := os.Lstat(p); serr != nil && false {`. Result: `--- FAIL: TestMachineHostTrust/no_home_without_the_file_is_0`, `machinehosttrust_test.go:995: exit 4, want 0`. It also fails `--- FAIL: TestMachineHostTrust/home_mismatch_without_file_is_0` (`machinehosttrust_test.go:839: an account home without the file: exit 4`).

The document mutants' narrow command: `go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/`. The unmutated run: ok. machine-identities.md's sha256 at the runbook's commit, before and after each: 7b3fe5b07c86a17f317c4ec083934ab840255095b849a02e4aeab029ef2dba31.

- **Q5, one word of the sentence on `--no-known-hosts`.** The line "`--no-known-hosts` turns off the adding and the version record, not" becomes "... the version floor, not". Result: `--- FAIL: TestCARotationSwitchRunbook/host_ca_gate`, ``runbook_test.go:1334: machine-identities.md "Renew a machine certificate" lacks "and `--no-known-hosts` turns off the adding and the version record, not the removal"``.
- **Q6, one word of the sentence on exit 4.** The line "another installation, or while `$HOME` is unset, empty or not the" becomes "... is missing, empty or not the". Result: `--- FAIL: TestCARotationSwitchRunbook/host_ca_gate`, ``runbook_test.go:1334: ... lacks "one whose home holds it gets 4 on every run ... or while `$HOME` is unset, empty or not the account's home (such a run changes no host CA line)"``.

In neither run did `TestHostTrustRunbooks` fail (no `--- FAIL` line of it; the narrow command has no `-v`).

### The earlier mutants of this branch (03-12g), read from its SUMMARY

- 03-12g's M456, `if herr != nil {` to `if herr != nil || true {`, was killed by `failures_exit_4/home_mismatch_with_file` (exit 0, want 4). The line is now `if herr != nil || !filepath.IsAbs(home) {`. By reading, the same mutant on it would return nil for every error of `userSSHDir`, so it would fail `home_mismatch_with_file` and now also `no_home_with_the_file_exits_4`. It was not run here.
- 03-12g's M509, which made the then-product `errNoHomeDir` case false (`case errors.Is(err, errNoHomeDir) && false:`), was killed by `no_home_changes_nothing` (exit 4, want 0). That mutant's behaviour is now the product's. Q1 above is its reverse, and the renamed leaf kills it.

The narrowing's silence without `$HOME` is still pinned by `TestNarrowHostTrust/no_ssh_dir_is_silent` (cmd/keyroster/knownhosts_test.go), and by the check in `no_home_with_the_file_exits_4` that no narrowing line or narrowing warning appears.

## Gates

All runs went through `scripts/linux.sh` (WSL, Linux amd64).

- The narrow runs: each unmutated run before the mutants passed, as did the runbook tests after the runbook's change and gofmt and `go vet ./cmd/keyroster/` before every commit of Go code.
- `CGO_ENABLED=1 go test -race -count=1 -timeout 15m ./cmd/keyroster/` on the runbook's commit (9112e5e): `ok` (268.3 s).
- The full gate, the sixth `<automated>` line of Task 5 in the 03-12g PLAN, taken from the file's bytes by script and run once on the tree of 9112e5e with nothing else running in WSL:
  - `CGO_ENABLED=1 go test -race -count=1 -timeout 15m ./...`: 36 `ok` lines, no `FAIL` line and no flake (cmd/keyroster: 335.0 s). The vet runs with every e2e tag, `bash -n test/systemd/smoke.sh` and `gofmt -l .` passed.
  - `golangci-lint run ./...` for linux, windows and darwin: `0 issues.` three times.
  - The fourth lint, `golangci-lint run --build-tags "e2e,e2erotation" --new-from-rev=origin/main ./test/e2e/`, reported 17 issues, all in test/e2e files that this branch does not touch. golangci-lint logged `Can't process results by diff processor: can't prepare diff by revgrep: no version control repository found`. In WSL, git cannot open this checkout: it is a linked worktree whose `.git` file names its git directory by a Windows path, and `git rev-parse HEAD` there gives `fatal: not a git repository`. So `--new-from-rev` had no base to filter by, and the chain stopped there.
  - The rest of the chain (that fourth lint, capslock, the two firewalls and the pinned-actions check) was therefore run verbatim on the same commit, 9112e5e, in an independent clone outside the repository. There, `refs/remotes/origin/main` was set to 2d61b55 and git worked in WSL: `git rev-parse HEAD origin/main` gave both commits, `git status --short` was empty, `git diff --name-only origin/main HEAD -- test/e2e` was empty and no `.go` file held a carriage return. Results:
    - the fourth lint: `0 issues.`;
    - capslock: 97, 37 and 23 pairs, each equal to its baseline, so no new pair;
    - dep-firewall: no banned package outside the documented exception;
    - testonly-firewall: clean (6 GOOS/tag combinations);
    - check-pinned-actions: all 55 `uses:` references pinned to commit SHAs.

    The whole chain exited 0, and the clone was removed afterwards.
- `git diff --name-only origin/main...HEAD` lists only the files this task changes.
- The publish scan over the staged added lines exited 0 before each commit, and every staged diff was read whole before it.
- Authorship and signatures over `git log origin/main..HEAD`: each commit is authored by Daniel Gustafsson, committed by keyroster-bot and carries a signature.

## Commits

- 6bf2ec3 `docs(quick-261124-nhm): plan machine renew's exit 4 without HOME` (the PLAN)
- 41553f1 `test(cli): pin machine renew's exit 4 without HOME and keep the tests out of the account's home` (knownhosts_test.go, machinehosttrust_test.go)
- 4ef5443 `fix(cli): machine renew exits 4 without HOME when the account's home holds the managed file` (machinehosttrust.go)
- a6f6cff `test(cli): pin the runbook text on a run without HOME and on what --no-known-hosts turns off` (runbook_test.go)
- 9112e5e `docs(runbooks): say that a run without HOME gets exit 4 and what --no-known-hosts turns off` (machine-identities.md)
- 169ef64 `docs(quick-261124-nhm): record the change` (this SUMMARY)
- 8d21201 `test(cli): correct the comment on which errors reach the account lookup` (machinehosttrust_test.go)
- 18ed468 `test(cli): pin which accounts the HOME case of exit 4 reaches` (runbook_test.go)
- 12953aa `docs(runbooks): say which accounts the HOME case of exit 4 reaches` (machine-identities.md)
- `docs(quick-261124-nhm): record the review's fix round` (this SUMMARY)

## Deviations from Plan

- Q2's replacement is `if _ = herr; !filepath.IsAbs(home) {`, not `if !filepath.IsAbs(home) {`: the latter leaves `herr` unused and does not compile, which would have been a build failure, not a killed mutant.
- The stub of `no_home_without_an_account_home_is_0` returns the fixture's home, which holds the file, together with its error, from the start. With the empty string Q2 could not have failed the leaf, since `filepath.IsAbs("")` is false. The leaf still passed on the old code, which returned at the `errNoHomeDir` case.
- The full gate's tail ran in an independent clone of the same commit, since git does not work in WSL in this linked worktree (see "Gates").

## UNVERIFIED

- Windows. The unit tests run on the cli-windows job. That the account lookup fails there, so that a run without the home variable stays exit 0, is read from the code and the standard library: `accountHome` is `user.LookupId(strconv.Itoa(os.Getuid()))`, and `os.Getuid()` is -1 on Windows. No test of its own shows it.
- A uid without an entry in the account database, or an account known only through NSS or LDAP: `user.LookupId` returns an error, so the run stays exit 0. This too is read from the code and the standard library, not shown by a test of its own.
- A real cron job or timer that runs `keyroster machine renew` without `$HOME`.
- A real ssh that reads the file from the account database's home.

## Not changed here

- The narrowing (cmd/keyroster/narrow.go) stays silent without `$HOME`: it never changes a command's exit status.
- No other runbook: docs/runbooks/ca-rotation.md already says the account runs the command "with `$HOME` its home".
- ROADMAP.md and STATE.md are not edited.

## Self-Check: PASSED

The five changed files and this task's PLAN exist on the branch, the five commits above are ancestors of HEAD, and the two REDs, six mutants and gates above were read from their own runs' output.
