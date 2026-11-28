---
phase: quick-261128-pv3
plan: 01
type: summary
subsystem: piv-backend-docs
tags: [docs, piv, runbook, signer, secret-files, terminal-echo]
status: complete
requires: []
provides: ["steps 3 and 5 of docs/backends/piv.md enter the PIN and the management key twice with the terminal's echo off, as the signer's user, with root creating only the directory", "step 1 ends by removing the management key file from the administrator's machine", "pins of the new text of steps 1, 3 and 5 in cmd/keyroster/runbook_test.go", "TestPIVSecretEntryScript, which runs the guide's script with sh and no terminal"]
affects: []
key-files:
  modified: [docs/backends/piv.md, docs/security/needs-hardware.md, cmd/keyroster/runbook_test.go]
  created: [cmd/keyroster/pivscript_unix_test.go]
decisions:
  - "Step 3 writes the PIN file and the management key file as the signer's user, with `sudo runuser`, so root creates only the directory (the owner's decision of 2026-11-28)."
  - "Steps 3 and 5 enter the secret twice with the terminal's echo off, through one script that refuses an existing path before it asks (the owner's decision of 2026-11-28)."
  - "The text says that the backend does not check the owner, instead of saying that the files must be owned by the signer user."
  - "Step 1 removes the management key file from the administrator's machine, and step 3 pastes the key from the password manager, so no file with the key is carried to the signer host."
  - "Step 4 of piv.md (who runs ca-init, and the state directory) is not touched here."
requirements: []
metrics:
  completed: 2026-11-28
actuals:
  tasks: 6
  commits: 7
plan_head_before: 1ad5fb2
---

# Quick 261128-pv3 Plan 01: steps 3 and 5 of the PIV setup enter the PIN and the key as the signer's user, twice, without echo

Step 3 of docs/backends/piv.md creates `/etc/keyroster-signer/piv` as root and writes the PIN file and the management key file as the signer's user, each through one script that asks for the secret twice with the terminal's echo off. The fourth line of step 5's block, which places the management key for a CA rotation, uses the same script. Step 1 ends by shredding the management key file on the administrator's machine, and step 5 no longer calls step 3's root form an exception. The text is pinned by tests, and the script itself runs in a test without a terminal. No product code changed.

## Before and after

Before (docs/backends/piv.md at 1ad5fb2):

- Step 1 (:180-208) created the file `mgmt-key` "On an administrator's machine (not the signer host if you can avoid it)" (:184-185, :200) and ended with "Keep the PIN, PUK and management key in your password manager." (:208). The file stayed where it was made.
- Step 3 (:231-247) said the files must be "owned by the signer user" (:235). Its block (:238-244) installed `mgmt-key` from the working directory of the signer host (`sudo install ... mgmt-key /etc/keyroster-signer/piv/mgmt-key`, :241) and shredded it there (:243). No step moved the file from the administrator's machine to the signer host, and the copy on the administrator's machine was never removed. The block also gave the directory to the signer's user (`sudo install -d`, :239) and then wrote below it three times as root: `sudo install ... /dev/null .../pin` (:240), the install of `mgmt-key` (:241) and `sudoedit .../pin` (:242).
- Step 5 (:272-333) said that every command naming that directory runs as the signer's user, "never as root below that directory" (:276-278), and excused step 3: "Step 3's root `sudo install` form is for the first setup only, while root has just created the directory, and is never used again." (:284-285). `install -d` also succeeds on a directory that existed before, and nothing checked that. Its block placed the management key with `sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$K"` (the fourth line), and the paragraph after the block told the operator to paste the key "into the `cat` of the fourth line and end it with Ctrl-D".

What the task first wrote, and then replaced: its first version of step 3 used the same `cat >"$1"` form for both files. What the operator typed or pasted was then shown by the terminal and stayed in its scrollback and in any recording of its output, and `set -C` stops only an existing regular file (and a link to none), not a FIFO or a device. The owner decided that both steps enter the secret with the echo off, and the text now says that a path that already exists is refused whatever it is.

After:

- Step 1 ends with: "Once the management key is there, remove its file from this machine; step 3 pastes the key from the password manager and reads no file:", the line `shred -u mgmt-key`, and a pointer to step 5 for what `shred` cannot promise on an SSD or a copy-on-write filesystem.
- Step 3 says that both must be regular files (not symlinks) with mode 0600 or stricter, that the backend refuses a file with any group or other permission bit and does not check the owner, and so the files are written as the signer's user on the signer host, with root creating only the directory. Its block is three lines: `sudo install -d -o keyroster-signer -g keyroster-signer -m 0700 /etc/keyroster-signer/piv`, then `sudo runuser -u keyroster-signer -- sh -c '<script>' sh /etc/keyroster-signer/piv/pin`, then the same with `/etc/keyroster-signer/piv/mgmt-key`. The text tells the operator to run the lines one at a time and to enter the PIN, then the management key from the password manager, at `enter:` and again at `again:`, each followed by Enter; says that the echo is off while it asks, that the file is written only when both entries are equal and not empty (and then `written:` and the path are printed), that after `nothing written`, or with neither line, the line is run again, and that a path that already exists is refused whatever it is, before it asks (to replace a file, remove it first as the signer's user). It ends with "Nothing is written as root below the signer's directory, and no file with the key lies in a working directory of the signer host." A further paragraph says that with the echo off the secret does not reach the terminal's scrollback or a recording of its output, that a recorder of the terminal's input still sees it (sudo's I/O log does with `log_input`), and that steps 3 and 5 are to be run in a session no such recorder follows.
- Step 5's fourth line is `sudo runuser -u keyroster-signer -- sh -c '<script>' sh "$K"`; the block is still five lines. The paragraph after it says to run the lines one at a time, that the fourth line asks for the key twice with the echo off as step 3 does, to go on to the last line only after the fourth has printed `written:` and the path, and to run the fourth line again after `nothing written`. Step 5's sentence on step 3 reads: "Step 3 writes both files the same way: root creates the directory and nothing below it."
- docs/security/needs-hardware.md gains one checklist item, after the item on steps 1-3: the entry lines of steps 3 and 5, run through `sudo runuser` on the signer host's terminal; nothing typed or pasted is shown, `written:` appears only after two equal entries, and the terminal's echo is on again afterwards, also after Ctrl-C.

The owner decided on 2026-11-28 that step 3 is written in the form step 5 already used, so that root creates only the directory, and later the same day that both steps enter the secret twice with the echo off.

## The script

One script, the same in the three lines (it holds no apostrophe, so it stays inside the single quotes of the line, and no backquote):

```
umask 077 && set -C && [ ! -e "$1" ] && [ ! -L "$1" ] && trap "stty echo" EXIT && trap "exit 1" HUP INT TERM && stty -echo && printf "enter: " >&2 && IFS= read -r a && printf "\nagain: " >&2 && IFS= read -r b && printf "\n" >&2 && [ -n "$a" ] && [ "$a" = "$b" ] && printf "%s\n" "$a" >"$1" && printf "written: %s\n" "$1" >&2 || { printf "nothing written\n" >&2; exit 1; }
```

What each part is there for:

- `umask 077` gives the new file mode 0600; `set -C` makes the shell create it only if it does not exist, a second guard behind the check.
- `[ ! -e "$1" ] && [ ! -L "$1" ]` refuses every path that already exists (a regular file, a FIFO, a device, a link, a link to nothing) before the script asks and before it changes the terminal. `set -C` alone stops only an existing regular file and a link to none.
- `trap "stty echo" EXIT` turns the echo on again however the script ends; `trap "exit 1" HUP INT TERM` makes a signal end it through that trap.
- `stty -echo` turns the echo off. Without a terminal it fails, and the script then writes nothing.
- The two `IFS= read -r` entries, at `enter:` and `again:`, keep leading and trailing spaces and backslashes as typed; `[ -n "$a" ] && [ "$a" = "$b" ]` lets only two equal, non-empty entries through.
- `printf "%s\n" "$a" >"$1"` writes the entry as one line; `written:` and the path follow. Anything else prints `nothing written` and exits 1.

## What the backend checks

internal/keystore/piv/piv.go, `checkSecretFile` (:742-754): `os.Lstat` of the path; refused when the mode is not a regular file (so a symlink is refused, :747-749); refused when `Perm()&0o077 != 0` (any group or other bit, :750-752); then `os.ReadFile`. It compares the file's owner with nothing, and nothing else in the package reads an owner (a search of internal/keystore/piv for `Stat_t`, `Uid`, `Getuid` and `syscall.` returns nothing). `readSecretFile` (:731-738) wraps it for the PIN file; `parseOptions` trims the PIN's line end with `strings.TrimRight(..., "\r\n")` (:247), and `checkManagementKey` trims the key's whitespace with `strings.TrimSpace` before hex decoding (:290). The file's mode comes from `umask 077` alone; a directory that widens new files (a default ACL) is caught only by this refusal at `ca-init`, which was read from `checkSecretFile` and not measured here.

## The pins (cmd/keyroster/runbook_test.go, TestCARotationBackendSteps)

- `pivSecretEntryScript` is a constant that holds the script, with a comment that says what it does and that steps 3 and 5 carry it word for word; `pivEntryLine(path)` builds an entry line from it; `pivMgmtKeyBlock`'s fourth line is `pivEntryLine("$K")`. The fixtures and rules of `pivMgmtKeyBlockProblems` are unchanged, and `sudoRunuserScript` still masks the script.
- Leaf `piv_step_3_files`:
  - step 1's window (from `### 1. Prepare the YubiKey: no default credentials` up to the line that starts `### 2.`) holds `remove its file from this machine` and the whole line `shred -u mgmt-key`;
  - step 3's window (from `### 3. Store the PIN and management key for the signer` up to, not including, `### 4. Initialise the CA`) holds exactly one fenced block, whose trimmed lines are exactly the three lines above, in order (compared whole, so a further root line such as a `sudo tee` onto the key's path, or another owner in the `install -d` line, fails it); no line that begins `sudo install` other than the `install -d` line and no line that holds `sudoedit`, each with its own message; and the phrases (whitespace runs joined) `It does not check the owner`, `Root creates only the directory`, `The terminal's echo is off while it asks`, `The file is written only when both entries are equal and not empty`, `It refuses a path that already exists, whatever it is, before it asks`, `Nothing is written as root below the signer's directory`, `no file with the key lies in a working directory of the signer host` and `A recorder of the terminal's input still sees them`.
- Leaf `piv_mgmt_key_round_trip`: the five-line block with the new fourth line; the phrases `Step 3 writes both files the same way`, `The fourth line asks for the key twice` and ``only after the fourth has printed `written:` ``; and refusals, each with its own message, of `for the first setup only`, ``the `cat` of the fourth line`` and `end it with Ctrl-D` in step 5's window.
- Counted on piv.md as it stood before the pins were written: every new required phrase 0, the line `shred -u mgmt-key` 1 (in step 3, outside step 1's window), `for the first setup only` 1.

## The script's own test (cmd/keyroster/pivscript_unix_test.go, build constraint `unix`)

`TestPIVSecretEntryScript` runs the constant with the system's `sh`, never with a terminal, on a path in a temporary directory, with a pipe on stdin that holds two equal lines. Its leaves: `parses` (`sh -n -c` exits 0); `no_terminal_writes_nothing` (new path: exit status 1, the path still absent, stderr holds the line `nothing written` and at least one other line, which are `stty`'s complaints and are not compared); and three existing-path leaves, `existing_regular_file` (content unchanged), `existing_fifo` (made with `syscall.Mkfifo`, still a FIFO) and `link_to_nothing` (a link to a path that does not exist, unchanged, target not created), each with exit status 1 and stderr exactly `nothing written` and a line end, so the refusal came before `stty` ran. The leaves that run `sh` carry a `//nolint:gosec` comment with G204, as the package's other tests that run a tool do; the constant carries one with G101 (its name holds "Secret"), and one `os.ReadFile` of a path in the test's own temporary directory carries G304.

## The RED (test commit c7a1694, detached worktree outside the repository)

`-run "Runbook|CARotation|HostTrust|SignerInstall|MoveAside|Restore|SecurityDocs|TestPIVSecretEntryScript"`: exit 1; no `[build failed]`, `[setup failed]`, `--- SKIP` or timeout line. The only `--- FAIL:` lines were `TestCARotationBackendSteps` (the parent), `piv_mgmt_key_round_trip` and `piv_step_3_files`. `TestPIVSecretEntryScript` and its five leaves passed (the test reads no document). Messages:

- `piv_mgmt_key_round_trip`: `piv.md step 5: consecutive: no fenced block holds the five lines of the management key's round trip as consecutive whole lines, in order`; step 5 lacks `The fourth line asks for the key twice` and ``only after the fourth has printed `written:` ``; it still tells the operator to paste the key into the `cat` of the fourth line and to end the entry with Ctrl-D.
- `piv_step_3_files`: the block of step 3 is the old three lines, not the wanted ones; step 3 lacks `The terminal's echo is off while it asks`, `The file is written only when both entries are equal and not empty`, `It refuses a path that already exists, whatever it is, before it asks` and `A recorder of the terminal's input still sees them`.

## The mutants (docs/backends/piv.md after the document commit)

Each: the unmutated narrow run (`^(TestCARotationBackendSteps|TestSecurityDocs|TestPIVSecretEntryScript)$`) passed first; one exact replacement, asserted to occur once (Q11: once in the test file and three times in piv.md); the narrow run failed with the named leaf's `--- FAIL:` line; `git checkout --` of the file(s); sha256 equal to the one before; `git status --short -- cmd internal test docs .github` empty. sha256 before every mutant: piv.md `661a65ee3413d37fd42774f5652c76e58349549933fa54e47ce62457fbce472a`, runbook_test.go `ef58edc5090b67f80c5f4ee1e2fb699b7edee34a9baab518a0ee4c1f88aed74e`; after every mutant the same two values. "L-pin", "L-key" and "L-K" below are the three entry lines of step 3 (pin, key) and step 5.

| Mutant | Exact replacement | Failing line | sha256 mutated |
| --- | --- | --- | --- |
| Q1 | step 3's L-key line becomes `sudo install -o keyroster-signer -g keyroster-signer -m 0600 mgmt-key /etc/keyroster-signer/piv/mgmt-key` | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the block differs; the root install refused) | `9fee2ae4dcc2f8d7381a05d67a6a877da33b7210080ae8202c791337c1196b9a` |
| Q2 | the line `sudoedit /etc/keyroster-signer/piv/pin` added after step 3's last command line | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the block differs; the `sudoedit` refusal) | `b74438b6c6cd2257e483a722b768b5e1c10e072fd3cf93675dee98b97ff5ebe2` |
| Q3 | ` && set -C` removed from step 3's L-pin only | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the block differs) | `985fa8660be70be6d26c8dd932b11523434015d6837ce88d0d9724781c9bd722` |
| Q4 | step 5's two-line sentence "Step 3 writes both files the same way: ..." replaced by "Step 3's root `sudo install` form is for the first setup only, ..." | `--- FAIL: TestCARotationBackendSteps/piv_mgmt_key_round_trip` (the phrase lacking and the refusal) | `c92904ef47f7f868adeefb1deb149ba6b081f270bc02a01a6edefe7a3db234ad` |
| Q5 | step 1's `"\nshred -u mgmt-key\n"` becomes `"\n"` (the fence around it stays, empty) | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (step 1 lacks the line) | `092067cd2a47582a25e2564bbaa604982d0bd278294d2775321e098a05104ea5` |
| Q6 | ` && stty -echo` removed from step 3's L-pin only | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the block differs) | `caec6f14381b0de9de8b357fa9a65360e54edac350d74be7e8c8fce6fb7d94d7` |
| Q7 | the line `sudo tee /etc/keyroster-signer/piv/mgmt-key` added after step 3's L-key | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the block differs) | `ec66900157f4a2e23a57bbeba7c93d8c8af855a7c5abb2ecad795403947a5630` |
| Q8 | `sudo install -d -o keyroster-signer` becomes `sudo install -d -o root` in step 3 | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the block differs; the `sudo install` refusal) | `cd24e785d5470c450c0cb198a1d9c7bb245bf6796e5a8d8d6d09365f9f4f18b8` |
| Q9 | step 5's L-K becomes `sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$K"` | `--- FAIL: TestCARotationBackendSteps/piv_mgmt_key_round_trip` (`consecutive: no fenced block holds the five lines ...`) | `f4b0086fa112de802b0d19db93ce85a9af734523d7afd64a20a7de2e873fa486` |
| Q10 | step 5's paragraph after the block (the new sentences from "Run the lines one at a time." on) replaced by the old ones ("Paste the key from the password manager into the `cat` of the fourth line and end it with Ctrl-D.") | `--- FAIL: TestCARotationBackendSteps/piv_mgmt_key_round_trip` (two phrases lacking, two refusals) | `2f0efce7c672a92593e9d0638db310d78eef255083acb5da18845f42eb2007b9` |
| Q11 | `[ ! -e "$1" ] && [ ! -L "$1" ] && ` removed from the constant in runbook_test.go and from the three lines of piv.md | `--- FAIL: TestPIVSecretEntryScript/existing_regular_file`, `/existing_fifo` and `/link_to_nothing` (stderr holds `stty`'s complaints around the message, not only `nothing written`) | runbook_test.go `d79718428f02918f0b3aee35a576058e8d35a06db0428d6603a2e5ff424dcedd`, piv.md `a71a828046a8615eecf87eaee55fb49e3f036bca06527d99eea4180240ba62c9` |

Under Q11 the document leaves passed (the constant and the document were changed together), so only the script's own test catches a script without the check.

## The script under a pseudo-terminal, measured

As the own user in WSL (dash, bash 5.2.21 and `bash --posix`), no sudo and no `runuser`, in a temporary directory that the harness removes; the script cut from step 3's L-pin is byte-equal to the script file the harness holds. Eleven cases, and the three shells gave the same line for every case. In every case the terminal's echo was on again afterwards, and the secret was not in the captured terminal output.

| Case | Exit status | The path afterwards | Output |
| --- | --- | --- | --- |
| two equal entries | 0 | regular file, mode 0600, the entry and a line end | `enter:`, `again:`, `written:` and the path |
| unequal entries | 1 | absent | `enter:`, `again:`, `nothing written` |
| empty entry twice | 1 | absent | `enter:`, `again:`, `nothing written` |
| existing regular file | 1 | as it was (content `old`, mode 0644) | `nothing written` only |
| existing FIFO | 1 | still the FIFO | `nothing written` only |
| link to nothing | 1 | still the link | `nothing written` only |
| stdin a pipe, inside a pseudo-terminal | 1 | absent | `stty`'s complaint, `nothing written`, `stty`'s complaint |
| Ctrl-C at the first prompt | 1 | absent | `enter:` only, neither `written:` nor `nothing written` |
| Ctrl-C at the second prompt | 1 | absent | `enter:`, `again:` only |
| Ctrl-D at the first prompt | 1 | absent | `enter:`, `nothing written` |
| entry with leading and trailing spaces and a backslash, twice | 0 | regular file, mode 0600, the entry verbatim | `enter:`, `again:`, `written:` and the path |

What a recorder sees: util-linux 2.39.3 `script` with separate output and input logs (`script -q -O <out> -I <in>`), itself inside a pseudo-terminal, the script under dash on a temporary path, two equal entries. The outer terminal's output and the output log do not hold the secret (the output log holds `enter:`, `again:` and `written:` with the path); the input log holds it; the file holds it.

What sudo's manual page says (the `sudoers(5)` page installed in WSL, sudo 1.9.15p5):

- `log_passwords`: "Most programs that require a user's password will disable echo before reading the password to avoid displaying the plaintext password on the screen. However, if terminal input is being logged (see “I/O LOGGING”), the password will still be present in the I/O log." It is on by default; when it is off, sudoers only tries to hide a password after a prompt that matches `passprompt_regex`.
- `log_input`: "If set, sudo will run the command in a pseudo-terminal (if sudo was run from a terminal) and log all user input." It is off by default.
- I/O log format: "User input may contain sensitive information such as passwords (even if they are not echoed to the screen), which will be stored in the log file unencrypted."

busybox `sh` is not installed and was not measured.

## The gates

Run through `bash scripts/linux.sh` from this worktree, on the head after the document commit:

- narrow run (`^(TestCARotationBackendSteps|TestSecurityDocs|TestPIVSecretEntryScript)$`): passes;
- `CGO_ENABLED=1 go test -race -count=1 -timeout 15m ./cmd/keyroster/`: `ok`, 344 s;
- `go vet ./cmd/keyroster/` (also with `GOOS=windows`, run before the test commit): no output; `gofmt -l cmd/keyroster`: no output;
- `golangci-lint run ./...` under linux, `GOOS=windows` and `GOOS=darwin`: 0 issues each (the new file does not build on Windows);
- `git diff --name-only origin/main...HEAD`: this plan and its summary, cmd/keyroster/runbook_test.go, cmd/keyroster/pivscript_unix_test.go, docs/backends/piv.md and docs/security/needs-hardware.md only;
- no test counts or pins the checklist of needs-hardware.md in a way the new item breaks: the one test that reads it (securitydocs_test.go) windows the block that starts at "CA key generations", which follows the new item;
- a search of docs, README.md, CONTRIBUTING.md, scripts, .github and the comments under cmd and internal for the old way of entering the key (`Ctrl-D`, "into the `cat`", "paste the key", the old fourth line) found it only in step 3 and step 5 of piv.md, which the round rewrote. The runbooks that name "the block of piv.md step 5" and ca-rotation.md's "with no key pasted" stay true.

The full gate was not run. The task changes two documents and the text pins and the script test of one package, and the pull request's checks run everything. Its fourth lint cannot run in a linked worktree on this host in any case.

## Commits

- 81b8d49 docs(quick-261128-pv3): plan step 3 of the PIV setup as the signer's user
- 58715fd test(cli): pin that step 3 of the PIV setup writes its files as the signer's user
- 3d9c780 docs(piv): write the PIN and management key files as the signer's user in step 3
- 7a55a93 docs(quick-261128-pv3): record the change
- c7a1694 test(cli): pin the echo-off entry of the PIV guide's steps 3 and 5 and run its script without a terminal
- 05d42f4 docs(piv): enter the PIN and the management key twice without echo in steps 3 and 5
- the commit of this record: docs(quick-261128-pv3): record the echo-off entry and its proofs

## UNVERIFIED

- The three entry lines under a real `sudo runuser` on a terminal (sudo or sudo-rs), on a real signer host and with the card; `ca-init` reading the files so written.
- A terminal left without echo after SIGKILL or a lost session (the traps cannot run then).
- busybox `sh`.
- `install -d` on a directory that existed before.
- That the files' mode comes from `umask 077` alone: a directory that widens new files (a default ACL) is caught only by the backend's refusal at `ca-init`.

As a fact, not an unknown: nothing in CI runs step 1, 3 or 5 of piv.md with a terminal; CI runs the script only without one (`TestPIVSecretEntryScript`, in the jobs that run the package's tests on Unix, the macOS job among them). piv.md's own banner already says the guide is not validated on hardware.

## Not changed here

- Step 4 of piv.md (who runs `ca-init`, and the state directory): a task of its own.
- Step 5's other lines and rules (the shred on every exit status, the start of the signer only after the shred and only when the command exited 0, the pins on them).
- Every other backend's guide.
- Product code.
