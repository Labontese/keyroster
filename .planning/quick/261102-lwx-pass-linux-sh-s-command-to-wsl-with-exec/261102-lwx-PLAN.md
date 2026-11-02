---
phase: quick-261102-lwx
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/linux.sh
  - .planning/STATE.md
autonomous: true
requirements: []
must_haves:
  truths:
    - "On Windows, scripts/linux.sh starts the command with `wsl.exe --exec bash -lc`, not `-- bash -lc`, so the command string reaches the login shell unexpanded."
    - "`bash scripts/linux.sh 'test -z \"$(gofmt -l .)\"'` is a real check: it fails when a .go file in the current directory is unformatted."
    - "The header comment says the string is passed unexpanded to a login shell and that $(...) and $VAR expand inside WSL's login shell."
    - "The exit status of the inner command still propagates, and the non-Windows branch is unchanged."
    - "One keyroster-bot PR, opened without auto-merge, with every required check green. Its commit is authored by the owner and committed and signed by keyroster-bot."
---

<objective>
`wsl.exe -- bash -lc "$1"` hands the command line to the distro's default shell first. That non-login shell has no Go on PATH and expands `$(...)` and `$VAR` before `bash -lc` runs, so every local gate of the form `test -z "$(gofmt -l .)"` has passed vacuously. Replace `--` with `--exec` in scripts/linux.sh and say so in the header. Change nothing else.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: linux.sh passes the string to the login shell with --exec</name>
  <files>scripts/linux.sh</files>
  <action>Replace `--` with `--exec` in the wsl.exe call. Update the header comment: the command string is passed unexpanded to a login shell, so `$(...)` and `$VAR` expand inside WSL's login shell.</action>
  <verify><automated>bash -n scripts/linux.sh && bash scripts/linux.sh 'command -v gofmt' && bash scripts/linux.sh 'go version' && ! bash scripts/linux.sh 'exit 3'</automated></verify>
</task>

<task type="auto">
  <name>Task 2: prove the gofmt check is real</name>
  <action>In a scratch copy outside the repo (a go.mod and an unformatted .go file), run `bash <repo>/scripts/linux.sh 'test -z "$(gofmt -l .)" && echo ok'` before and after the change. Before it must print `ok`; after it must fail. Record the results in the SUMMARY. Also run `echo "[$(command -v gofmt)]"` and `exit 3` before and after.</action>
  <verify><automated>test "$(bash scripts/linux.sh 'exit 3'; echo $?)" = 3</automated></verify>
</task>

<task type="auto">
  <name>Task 3: deliver</name>
  <action>Push as keyroster-bot, open the PR with `scripts/gh-as-bot.sh pr create` without auto-merge, write the SUMMARY and the STATE.md quick-task row, push, and wait for the required checks. Never approve or merge.</action>
  <verify><automated>test "$(bash scripts/gh-as-bot.sh pr view chore/linux-sh-wsl-exec --json autoMergeRequest --jq '.autoMergeRequest == null')" = true && bash scripts/gh-as-bot.sh pr checks chore/linux-sh-wsl-exec --required</automated></verify>
</task>

</tasks>
