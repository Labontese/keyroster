---
phase: quick-261102-lwx
plan: 01
subsystem: tooling
tags: [wsl, scripts, gofmt, local-gate]
status: complete
requires: []
provides: ["scripts/linux.sh that passes the command string unexpanded to WSL's login shell, so $(...) checks such as gofmt -l run for real"]
affects: ["every plan's local gate that runs through bash scripts/linux.sh"]
tech-stack:
  added: []
  patterns: []
key-files:
  created: []
  modified: [scripts/linux.sh, .planning/STATE.md]
decisions:
  - "scripts/linux.sh uses `wsl.exe --exec bash -lc`: the command string is not expanded by wsl.exe's default shell, and Go is on PATH where $(...) and $VAR expand."
requirements: []
metrics:
  completed: 2026-11-02
actuals:
  tasks: 3
  commits: 2
plan_head_before: 682782ee434f2e72053f0b7853525925edaa3c44
---

# Quick 261102-lwx Plan 01: pass linux.sh's command to WSL with --exec Summary

`scripts/linux.sh` now runs `wsl.exe --cd <dir> --exec bash -lc "$1"` on Windows. Before, `--` made wsl.exe hand the line to the distro's default shell, which has no Go on PATH and expanded `$(...)` and `$VAR` before `bash -lc` ran. So `bash scripts/linux.sh 'test -z "$(gofmt -l .)"'` passed vacuously, and the gofmt step of every local gate never checked anything. PR [#81](https://github.com/Labontese/keyroster/pull/81), opened by keyroster-bot without auto-merge.

CI runs gofmt on its own (ci.yml) and `main` is clean (`gofmt -l .` reports 0 files), so the bug hid no misformatted code.

## Commits

- `5d27383` fix(scripts): pass linux.sh's command to WSL with --exec so it is not expanded early
- the docs commit carrying this PLAN, this SUMMARY and the STATE.md row

The owner (Labontese) is the author of each commit, and keyroster-bot is the committer, with an SSH signature.

## What changed in linux.sh

- `-- bash -lc "$1"` became `--exec bash -lc "$1"`.
- The header says the command string reaches the login shell unexpanded, and that `$(...)` and `$VAR` expand inside WSL's login shell.
- Unchanged: the argument check, `KEYROSTER_WSL_DISTRO`, `--cd "$(pwd -W)"`, `MSYS_NO_PATHCONV`, `exec` (so the exit status is the inner command's) and the non-Windows branch.

## Verification (Windows, Git Bash, WSL)

The scratch copy holds a `go.mod` and an unformatted `bad.go`, outside the repo. `$L` is the repo's `scripts/linux.sh`.

| Command | Before (`--`) | After (`--exec`) |
|---|---|---|
| scratch: `bash $L 'test -z "$(gofmt -l .)" && echo ok'` | prints `ok`, exit 0 (vacuous) | no output, exit 1 |
| scratch: `bash $L 'echo "[$(command -v gofmt)]"'` | `[]` | `[/home/daniel/sdk/go1.27.1/bin/gofmt]` |
| scratch: `bash $L 'gofmt -l .'` (no `$(...)`) | `bad.go` | `bad.go` |
| scratch, after `gofmt -w bad.go`: the `test -z` check | n/a | `ok`, exit 0 |
| repo: `bash scripts/linux.sh 'command -v gofmt'` | `/home/daniel/sdk/go1.27.1/bin/gofmt` | same |
| repo: `bash scripts/linux.sh 'test -z "$(gofmt -l .)" && echo ok'` | n/a (vacuous) | `ok`, exit 0 |
| repo: `bash scripts/linux.sh 'go version'` | `go version go1.27.3 linux/amd64` | same |
| repo: `bash scripts/linux.sh 'exit 3'; echo $?` | 3 | 3 |
| repo: `bash scripts/linux.sh 'echo "a b" "$HOME" '"'x y'"' \| cat; test -n "$HOME"'` | n/a | `a b /home/daniel x y`, exit 0 |

Note: a bare `command -v gofmt` already worked before the change, because the string has nothing for the default shell to expand. The `$(command -v gofmt)` form is the one that failed before. `bash scripts/linux.sh 'gofmt -l .'` also worked before, so only the `$(...)` form was vacuous.

- **UNVERIFIED:** the non-Windows branch (`exec bash -c`). This change does not touch it, and this machine is Windows.
- **UNVERIFIED:** a distro chosen with `KEYROSTER_WSL_DISTRO`. Only the default distro was run.

## Deviations from Plan

None. The PLAN was written for this brief and executed as written.

## Notes

Earlier PLANs say the command string "must contain no `$VAR` and no inner quotes" (261006-ixz) and route such commands through script files. That was the workaround for this bug. They are history and are not edited. From this PR on, `$(...)`, `$VAR` and inner quotes are fine.
