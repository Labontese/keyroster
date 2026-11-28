---
phase: quick-261124-nhm
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - cmd/keyroster/machinehosttrust.go
  - cmd/keyroster/knownhosts_test.go
  - cmd/keyroster/machinehosttrust_test.go
  - cmd/keyroster/runbook_test.go
  - docs/runbooks/machine-identities.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "keyroster machine renew without $HOME (unset or empty) exits 4, with the host trust step's one warning line, when the home the account database names is an absolute path whose .ssh holds keyroster_known_hosts; it stays exit 0 and prints nothing of the step when the account lookup fails, when that home is not an absolute path, or when it does not hold the file."
    - "A $HOME that is not the account's home, a failed account lookup that carries a directory, and every later step of the host trust step behave as before."
    - "No test of the cmd/keyroster package looks into the real account's home: TestMain also replaces accountHome with a function that returns an error."
    - "The runbook's section \"Renew a machine certificate\" says that a run without $HOME gets 4 when the account's home holds the file, and that --no-known-hosts turns off the adding and the version record, not the removal; runbook_test.go pins both sentences and forbids the earlier wordings."
    - "The narrowing stays silent without $HOME. No other runbook changes. No ROADMAP or STATE change."
---

<objective>
`keyroster machine renew` refreshes an automation account's host CA lines and exits 4 when the certificate is in place but that step failed, so that a timer's monitoring notices. Without `$HOME`, `userSSHDir()` returns an error that wraps `errNoHomeDir`, and step 1 of `machineHostTrust` (cmd/keyroster/machinehosttrust.go) returns nil at once: exit 0 and nothing printed, also when the home that the account database names holds `~/.ssh/keyroster_known_hosts`, the file the account's ssh reads. The owner decided that the command looks up the account's home also when `$HOME` is missing and exits 4 when the file is there, as it already does for a `$HOME` that is not the account's home. In the same runbook paragraph, "`--no-known-hosts` turns it off" can be read as turning off the removal of untrusted lines; the flag turns off the adding and the version record only.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: pin the exit 4 without $HOME and keep the tests out of the account's home</name>
  <files>cmd/keyroster/knownhosts_test.go, cmd/keyroster/machinehosttrust_test.go</files>
  <action>TestMain also sets accountHome to a function that returns an error, and its comment says why. The leaf no_home_changes_nothing becomes no_home_with_the_file_exits_4 (exit 4, one warning line of the step for the fixture home's file, the exit line, no line added, no narrowing line or warning, the four files unchanged). Three leaves after it, each exit 0 with the renewed summary and no line of the step: no_home_without_the_file_is_0, no_home_without_an_account_home_is_0, no_home_with_a_relative_account_home_is_0. RED from a detached worktree of this commit: only TestMachineHostTrust and its leaf no_home_with_the_file_exits_4 fail, on the exit status; the three new leaves pass on the old code.</action>
  <verify><automated>go test -count=1 -timeout 5m -v -run '^TestMachineHostTrust$' ./cmd/keyroster/</automated></verify>
</task>

<task type="auto">
  <name>Task 2: machine renew exits 4 without $HOME when the account's home holds the file</name>
  <files>cmd/keyroster/machinehosttrust.go</files>
  <action>In step 1 of machineHostTrust the errNoHomeDir case goes, so that every error of userSSHDir but a *homeLookupWarning looks up the account's home; a home that is not an absolute path counts as none. The doc comment's first bullet says so. Mutants Q1 to Q4 of this branch must each fail a named leaf.</action>
  <verify><automated>go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -run "^(TestAddHostCALines|TestMachineHostTrust|TestMachineHostTrustCaller|TestKnownHosts)$" ./cmd/keyroster/ && test -z "$(gofmt -l cmd/keyroster)"</automated></verify>
</task>

<task type="auto">
  <name>Task 3: pin the runbook's two sentences</name>
  <files>cmd/keyroster/runbook_test.go</files>
  <action>In TestCARotationSwitchRunbook/host_ca_gate, window machine-identities.md "Renew a machine certificate": the pin of "turns it off" and the pin of the exit 4 cases are replaced by the new sentences, the pin of the run without $HOME is removed, and "turns it off" and "neither does a run without `$HOME`" are forbidden. RED from a detached worktree of this commit: exactly two "lacks" and two "still holds" messages; TestHostTrustRunbooks passes.</action>
  <verify><automated>go test -count=1 -timeout 5m -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/</automated></verify>
</task>

<task type="auto">
  <name>Task 4: the runbook says what a run without $HOME gets and what --no-known-hosts turns off</name>
  <files>docs/runbooks/machine-identities.md</files>
  <action>Two sentences of "Renew a machine certificate", each applied by a script that asserts the old text occurs once. Mutants Q5 and Q6, one word of each new sentence, must each fail host_ca_gate. Then the whole package with the race detector and the full gate.</action>
  <verify><automated>go test -count=1 -timeout 5m -run "^(TestCARotationSwitchRunbook|TestHostTrustRunbooks)$" ./cmd/keyroster/ && CGO_ENABLED=1 go test -race -count=1 -timeout 15m ./cmd/keyroster/</automated></verify>
</task>

</tasks>
