---
phase: quick-261128-pv3
plan: 01
subsystem: piv-backend-docs
tags: [docs, piv, runbook, signer, secret-files]
status: complete
requires: []
provides: ["step 3 of docs/backends/piv.md writes the PIN file and the management key file as the signer's user, with root creating only the directory", "step 1 ends by removing the management key file from the administrator's machine", "pins of the new text of steps 1, 3 and 5 in cmd/keyroster/runbook_test.go"]
affects: []
key-files:
  modified: [docs/backends/piv.md, cmd/keyroster/runbook_test.go]
decisions:
  - "Step 3 is written in the form step 5 already uses (`sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >\"$1\"' sh <file>`), so root creates only the directory (the owner's decision of 2026-11-28)."
  - "The text says that the backend does not check the owner, instead of saying that the files must be owned by the signer user."
  - "Step 1 removes the management key file from the administrator's machine, and step 3 pastes the key from the password manager, so no file with the key is carried to the signer host."
requirements: []
metrics:
  completed: 2026-11-28
actuals:
  tasks: 3
  commits: 4
plan_head_before: 1ad5fb2
---

# Quick 261128-pv3 Plan 01: step 3 of the PIV setup writes its files as the signer's user Summary

Step 3 of docs/backends/piv.md now creates `/etc/keyroster-signer/piv` as root and writes the PIN file and the management key file with `sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh <path>`, the form step 5 already used. Step 1 ends by shredding the management key file on the administrator's machine, and step 5 no longer calls step 3's root form an exception. Three document blocks changed and the text is pinned by a test; no product code changed.

## Before and after

Before (docs/backends/piv.md at 1ad5fb2):

- Step 1 (:180-208) created the file `mgmt-key` "On an administrator's machine (not the signer host if you can avoid it)" (:184-185, :200) and ended with "Keep the PIN, PUK and management key in your password manager." (:208). The file stayed where it was made.
- Step 3 (:231-247) said the files must be "owned by the signer user" (:235). Its block (:238-244) installed `mgmt-key` from the working directory of the signer host (`sudo install ... mgmt-key /etc/keyroster-signer/piv/mgmt-key`, :241) and shredded it there (:243). No step moved the file from the administrator's machine to the signer host, and the copy on the administrator's machine was never removed. The block also gave the directory to the signer's user (`sudo install -d`, :239) and then wrote below it three times as root: `sudo install ... /dev/null .../pin` (:240), the install of `mgmt-key` (:241) and `sudoedit .../pin` (:242).
- Step 5 (:272-333) said that every command naming that directory runs as the signer's user, "never as root below that directory" (:276-278), and excused step 3: "Step 3's root `sudo install` form is for the first setup only, while root has just created the directory, and is never used again." (:284-285). `install -d` also succeeds on a directory that existed before, and nothing checked that.

After:

- Step 1 ends with: "Once the management key is there, remove its file from this machine; step 3 pastes the key from the password manager and reads no file:", the line `shred -u mgmt-key`, and a pointer to step 5 for what `shred` cannot promise on an SSD or a copy-on-write filesystem.
- Step 3 says that both must be regular files (not symlinks) with mode 0600 or stricter, that the backend refuses a file with any group or other permission bit and does not check the owner, and so the files are written as the signer's user on the signer host, with root creating only the directory:

```
sudo install -d -o keyroster-signer -g keyroster-signer -m 0700 /etc/keyroster-signer/piv
sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh /etc/keyroster-signer/piv/pin
sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh /etc/keyroster-signer/piv/mgmt-key
```

  The text tells the operator to type the PIN into the `cat` of the second line and paste the key into the `cat` of the third, ending each with Enter and Ctrl-D; that `set -C` refuses a file that already exists, so a second run changes nothing; and to remove a file first, as the signer's user, to replace it. It ends with "Nothing is written as root below the signer's directory, and no file with the key lies in a working directory of the signer host."
- Step 5's sentence reads: "Step 3 writes both files the same way: root creates the directory and nothing below it."

The owner decided on 2026-11-28 that step 3 is written in the form step 5 already uses, so that root creates only the directory.

## What the backend checks

internal/keystore/piv/piv.go, `checkSecretFile` (:742-754): `os.Lstat` of the path; refused when the mode is not a regular file (so a symlink is refused, :747-749); refused when `Perm()&0o077 != 0` (any group or other bit, :750-752); then `os.ReadFile`. It compares the file's owner with nothing, and nothing else in the package reads an owner (a search of internal/keystore/piv for `Stat_t`, `Uid`, `Getuid` and `syscall.` returns nothing). `readSecretFile` (:731-738) wraps it for the PIN file; `parseOptions` trims the PIN's line end with `strings.TrimRight(..., "\r\n")` (:247), and `checkManagementKey` trims the key's whitespace with `strings.TrimSpace` before hex decoding (:290).

## The pins (cmd/keyroster/runbook_test.go, TestCARotationBackendSteps)

- New leaf `piv_step_3_files`:
  - step 1's window (from `### 1. Prepare the YubiKey: no default credentials` up to the line that starts `### 2.`) holds `remove its file from this machine` and the whole line `shred -u mgmt-key`;
  - step 3's window (from `### 3. Store the PIN and management key for the signer` up to, not including, `### 4. Initialise the CA`) holds the two `sudo runuser` lines as whole lines (compared as lines, not substrings), the phrases `It does not check the owner`, `Root creates only the directory`, "`set -C` refuses a file that already exists", `Nothing is written as root below the signer's directory` and `no file with the key lies in a working directory of the signer host` (whitespace runs joined), exactly one line that begins `sudo install -d `, no other line that begins `sudo install`, and no line that holds `sudoedit`. Each rule has its own message.
- In `piv_mgmt_key_round_trip`: the required phrase `Step 3 writes both files the same way` and a refusal of `for the first setup only` in step 5's window.
- Counted on piv.md at 1ad5fb2 before the pins were written: every new required phrase 0, the line `shred -u mgmt-key` 1 (in step 3, outside step 1's window), `for the first setup only` 1.

## The RED

R1 (58715fd) run from a detached worktree outside the repository, `-run "Runbook|CARotation|HostTrust|SignerInstall|MoveAside|Restore|SecurityDocs"`: exit 1; no `[build failed]`, `[setup failed]`, `--- SKIP` or timeout line; 154 passing leaf and test lines. The only `--- FAIL:` lines:

- `TestCARotationBackendSteps` (the parent), `TestCARotationBackendSteps/piv_mgmt_key_round_trip` with `piv.md step 5 lacks "Step 3 writes both files the same way"` and `piv.md step 5 still says that step 3's root form is "for the first setup only"` (one `lacks` and one refusal);
- `TestCARotationBackendSteps/piv_step_3_files` with: step 1 lacks `remove its file from this machine`; step 1 lacks the line `shred -u mgmt-key`; two refusals for the old `sudo install ... pin` and `sudo install ... mgmt-key` lines; one refusal for the `sudoedit` line; the two `sudo runuser` lines lacking; the five phrases lacking.

## The mutants (docs/backends/piv.md after W1)

Each: the unmutated narrow run (`^(TestCARotationBackendSteps|TestSecurityDocs)$`) passed first; one exact replacement, asserted to occur once; the narrow run failed with the named leaf's `--- FAIL:` line; `git checkout --` of the file; sha256 equal to the one before; `git status --short -- cmd internal test docs .github` empty. sha256 before and after every mutant: `fa45ab55da44d8cbd6acf24a68faf7f00d545570b43aab8a708e622071014920`.

| Mutant | Exact replacement | Failing line | sha256 mutated |
| --- | --- | --- | --- |
| Q1 | step 3's management key `sudo runuser ... sh /etc/keyroster-signer/piv/mgmt-key` line becomes `sudo install -o keyroster-signer -g keyroster-signer -m 0600 mgmt-key /etc/keyroster-signer/piv/mgmt-key` | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the root install refused; the runuser line lacking) | `d7c8ba3117aae16828bd8b71883c5e2fc2f7c5492b7d12b52c17ffeb2ae4f88f` |
| Q2 | the line `sudoedit /etc/keyroster-signer/piv/pin` added after step 3's third command line | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the `sudoedit` refusal) | `438b2eb18446fe39d34af884e007876b33252b76959aa79cf6ded66a91e74d2b` |
| Q3 | ` && set -C` removed from the PIN's `sudo runuser` line of step 3 (not from step 5's block) | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (the PIN line lacking) | `9bd052adfafa9f659e7c38ef8e300a8745cb287749b2974290a3ed39816bb32c` |
| Q4 | step 5's new two-line sentence replaced by the old two-line sentence | `--- FAIL: TestCARotationBackendSteps/piv_mgmt_key_round_trip` (the phrase lacking and the refusal) | `1aff8146d40cc86ce7246b1a8b5bd3fcf698600aa31931844788e81de925aa00` |
| Q5 | step 1's line `shred -u mgmt-key` replaced by nothing (`"\nshred -u mgmt-key\n"` became `"\n"`; the fence around it stays, empty) | `--- FAIL: TestCARotationBackendSteps/piv_step_3_files` (step 1 lacks the line) | `aeda582d275a0fb0d34b4ce944df2ddba33fdfeb4d8678b51d527b059e5f2322` |

## The shell form, measured

As the own user in WSL, without sudo and without `runuser`, in a fresh `mktemp -d` directory on the WSL ext4 root filesystem, for each shell: `<shell> -c 'umask 077 && set -C && cat >"$1"' sh "$f"` with a line on stdin. dash (`/usr/bin/dash`) and bash 5.2.21 were measured; busybox is not installed, so it was not measured.

| Reading | dash | bash |
| --- | --- | --- |
| 1. creates `$f` | exit 0, mode 600, content is the line | exit 0, mode 600, content is the line |
| 2. run again on the same `$f` | exit 2, content unchanged, `cannot create ...: File exists` | exit 1, content unchanged, `cannot overwrite existing file` |
| 3. link to a path that does not exist (recorded only) | refused, exit 2, `File exists`; the target was not created | refused, exit 1, `cannot overwrite existing file`; the target was not created |
| 4. link to an existing file | exit 2, the file unchanged | exit 1, the file unchanged |

Readings 1, 2 and 4 are what step 3's text claims about `set -C`; they held under both shells.

## The gates

Run through `bash scripts/linux.sh` from this worktree, on the head after W1:

- narrow run (`^(TestCARotationBackendSteps|TestSecurityDocs)$`): passes, including `piv_step_3_files` and `piv_mgmt_key_round_trip`;
- `CGO_ENABLED=1 go test -race -count=1 -timeout 15m ./cmd/keyroster/`: `ok`, 280 s;
- `go vet ./cmd/keyroster/`: no output; `gofmt -l cmd/keyroster`: no output;
- `golangci-lint run ./...` under linux, `GOOS=windows` and `GOOS=darwin`: 0 issues each;
- `git diff --name-only origin/main...HEAD`: this plan, the test file and docs/backends/piv.md only;
- `grep -rnF` of the old strings (`for the first setup only`, `sudoedit /etc/keyroster-signer/piv/pin`, the two old `sudo install -o keyroster-signer ... /etc/keyroster-signer/piv/` lines) over docs, cmd, internal, test and .github: only the new refusal in the test file holds the first one; the others are empty;
- the pull request's title passes `scripts/check-pr-title.sh`.

The full gate was not run. The task changes one document and the text pins of one test file, and the pull request's checks run everything. Its fourth lint cannot run in a linked worktree on this host in any case.

## Commits

- 81b8d49 docs(quick-261128-pv3): plan step 3 of the PIV setup as the signer's user
- 58715fd test(cli): pin that step 3 of the PIV setup writes its files as the signer's user
- 3d9c780 docs(piv): write the PIN and management key files as the signer's user in step 3
- the commit of this record: docs(quick-261128-pv3): record the change

## UNVERIFIED

- Step 3 on a real signer host: the `sudo runuser` lines with a terminal on stdin, under sudo or sudo-rs; the card; `ca-init` reading the files so written.
- `install -d` on a directory that existed before.
- That nothing in CI runs step 1, 3 or 5 of piv.md. piv.md's own banner already says the guide is not validated on hardware.

## Not changed here

- Step 5's block and its rules (the five-line round trip, the shred on every exit status, the pins on them).
- docs/security/needs-hardware.md, whose "write the 0600 PIN and management key files" stays true.
- Every other backend's guide.
- Product code.
