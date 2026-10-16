---
phase: 02-passkey-login-mvp
plan: 02
subsystem: cli
tags: [windows, ssh-agent, named-pipe, go-winio, winagent, macos, ci, auth-03, plat-05, d-15, d-16]

requires:
  - phase: 01-trust-core
    provides: "keyroster CLI dispatcher, dialAgent hook and agentSigner for admin SSHSIG signing, internal/cert.Build, KEYROSTER_REQUIRE_ORACLE pattern"
  - phase: 02-passkey-login-mvp (02-01)
    provides: "phase 02 branch base on main (signer login, directory, webauthn)"
provides:
  - "internal/winagent (Windows only): PipePath, SDDL, OpenSSHSpelling, Serve + Options{Poll, IdleExit}, VerifyServerOwner, ErrOwnerUnverifiable, Ensure; unexported checkOwner and ensure"
  - "keyroster agent (Windows only): in-memory x/crypto keyring on \\\\.\\pipe\\keyroster-agent-<SID>, lifetimes honoured, exits when its last key expired or 5 min without a key"
  - "dialAgent split: agentconn_unix.go (SSH_AUTH_SOCK Unix socket, unchanged) and agentconn_windows.go (go-winio, SSH_AUTH_SOCK else the inbox agent pipe) for admin SSHSIG signing"
  - "CI jobs cli-windows and cli-macos (not required yet); KEYROSTER_REQUIRE_SSH_AGENT in build-test and cli-macos; KEYROSTER_REQUIRE_INBOX_SSH in cli-windows when the image has the inbox ssh.exe"
  - "TestAgentLifetime (Unix, real OpenSSH ssh-agent) and TestInboxSSHOffersAgentCert (Windows, inbox ssh.exe/ssh-add.exe)"
  - "docs/security/needs-hardware.md section Platform verification (D-16)"
affects: [02-12, 02-14, AUTH-03, PLAT-05]

actuals:
  tokens: 14000   # chars/4 over the added lines of the code, test, CI and doc diff (55885 chars); planning docs excluded
  tasks: 3        # Tasks 1-3; Task 4 is the owner merge gate
  commits: 4      # git rev-list --count plan_head_before..HEAD before this SUMMARY update: 0a454a1, c66306b, 4b32003 (first docs commit), a65e4dd (CI fix); Task 1 committed nothing; this docs update follows
plan_head_before: 133704e061a3800c959b3afd25512c23203df8a1
plan_head_after: a65e4ddaa017b997e2bfc94334b49721e2b9fdcf

tech-stack:
  added: ["github.com/Microsoft/go-winio v0.6.2 (Windows build of keyroster only)"]
  patterns:
    - "Per-OS hook variables: dialAgent lives in agentconn_unix.go / agentconn_windows.go, so tests keep replacing one variable"
    - "An x/crypto agent client that must not outlive one request gets the conn as a plain io.ReadWriter (serial path, no background reader); NewClient on a net.Conn starts a pipelined reader goroutine"
    - "Exit decision and connection accounting share one mutex; a server that closes its listener never listens again (no new squatting window)"
    - "Windows tests that hand key files to inbox OpenSSH set an owner-only protected DACL first"
    - "Tests mint certificates through internal/cert.Build, never a direct SignCert (forbidigo)"

key-files:
  created:
    - internal/winagent/winagent_windows.go
    - internal/winagent/owner_windows.go
    - internal/winagent/ensure_windows.go
    - internal/winagent/winagent_windows_test.go
    - internal/winagent/offer_windows_test.go
    - cmd/keyroster/agent_windows.go
    - cmd/keyroster/agentconn_unix.go
    - cmd/keyroster/agentconn_windows.go
    - cmd/keyroster/agentconn_unix_test.go
  modified:
    - cmd/keyroster/root.go
    - go.mod
    - go.sum
    - .github/workflows/ci.yml
    - docs/security/needs-hardware.md

key-decisions:
  - "A2 passed: the inbox ssh.exe honours a named-pipe agent only as //./pipe/<name> in IdentityAgent; \\\\.\\pipe\\<name> fails there (OpenSSH reads backslashes as escapes). SSH_AUTH_SOCK accepts both. keyroster agent prints the //./pipe/ spelling; go-winio calls keep \\\\.\\pipe\\"
  - "A3 moved to 02-14: the laptop was offline (Tailscale last seen 2 days earlier, LAN address timed out); 02-12 ships no gcr check"
  - "Serve tracks 'a key was ever added' by wrapping Add, not by watching List at polls, so a 1 s key between two 5 s polls still ends the agent"
  - "ensure confirms the connection with one List through a serial client (no background reader), and retries once only on a transport error that means the agent closed the connection"
  - "Exported winagent.OpenSSHSpelling for the printed IdentityAgent/SSH_AUTH_SOCK lines (02-12 reuses it)"

patterns-established:
  - "KEYROSTER_REQUIRE_SSH_AGENT / KEYROSTER_REQUIRE_INBOX_SSH: a missing external binary fails CI instead of skipping (same shape as KEYROSTER_REQUIRE_ORACLE)"

requirements-completed: []  # AUTH-03 and PLAT-05 are decided in 02-14 (plan output section)

coverage:
  - id: D1
    description: "keyroster agent on Windows: per-user pipe, lifetimes honoured, inbox ssh.exe offers the certificate, gone at expiry, agent exits"
    requirement: AUTH-03
    verification:
      - kind: integration
        ref: "internal/winagent/offer_windows_test.go#TestInboxSSHOffersAgentCert (Daniel-PC, KEYROSTER_REQUIRE_INBOX_SSH=1)"
        status: pass
      - kind: integration
        ref: "internal/winagent/winagent_windows_test.go#TestAgent/ensure_starts_real_agent"
        status: pass
      - kind: unit
        ref: "internal/winagent/winagent_windows_test.go#TestAgent/lifetime_expiry_exit"
        status: pass
    human_judgment: false
  - id: D2
    description: "Pipe-squatting guard and ACL: VerifyServerOwner/checkOwner, fail-closed ensure, ErrOwnerUnverifiable for elevated agents, live pipe DACL"
    requirement: AUTH-03
    verification:
      - kind: unit
        ref: "internal/winagent/winagent_windows_test.go#TestAgent/{owner_mismatch_refused,owner_access_denied_names_elevation,ensure_fails_closed,verify_own_pipe,sddl_single_allow,second_serve_refused}"
        status: pass
    human_judgment: false
  - id: D3
    description: "Exit is atomic with connection handling; ensure retries once on a closing agent"
    requirement: AUTH-03
    verification:
      - kind: unit
        ref: "internal/winagent/winagent_windows_test.go#TestAgent/{exit_waits_for_open_connection,add_races_expiry_exit,ensure_retries_once_on_closing_agent,idle_exit}"
        status: pass
    human_judgment: false
  - id: D4
    description: "Admin SSHSIG signing on Windows reaches the inbox agent through go-winio"
    verification:
      - kind: manual_procedural
        ref: "keyroster.exe ca issue --admin-key <ed25519 key in the inbox agent> on Daniel-PC: signed, then stopped only at the absent signer socket"
        status: pass
    human_judgment: false
  - id: D5
    description: "CLI on Linux, macOS and Windows in CI; real ssh-agent lifetime test on Linux and macOS"
    requirement: PLAT-05
    verification:
      - kind: unit
        ref: "cmd/keyroster/agentconn_unix_test.go#TestAgentLifetime (WSL, KEYROSTER_REQUIRE_SSH_AGENT=1; failing branch with PATH=/nonexistent)"
        status: pass
      - kind: other
        ref: "PR #36 first run: cli-macos and build-test ok cmd/keyroster with KEYROSTER_REQUIRE_SSH_AGENT=1; cli-windows ran the offer test with KEYROSTER_REQUIRE_INBOX_SSH=1 (only sddl_single_allow failed, fixed in a65e4dd)"
        status: pass
    human_judgment: true
    rationale: "The run on the final head is read from PR #36's checks; the owner confirms it is green at the merge gate"

duration: 40min
completed: 2026-10-16
status: complete
---

# Phase 2 Plan 02: Windows Agent Summary

**keyroster's own in-memory ssh-agent on a per-user `//./pipe/keyroster-agent-<SID>` pipe. It is proven end to end with the inbox OpenSSH_for_Windows 9.5p2: a key plus certificate are loaded with a lifetime, the certificate is offered, both are gone at expiry and the agent exits. The plan also adds the go-winio admin-signing dial, and CLI test jobs on Windows and macOS.**

## Performance

- **Duration:** about 40 min
- **Started:** 2026-10-16T20:28Z (approximate)
- **Completed:** 2026-10-16T21:10Z
- **Tasks:** 3 of 3 implementation tasks; Task 4 is the owner merge gate
- **Files modified:** 14

## Probe evidence (Task 1)

### A2: inbox ssh.exe and ssh-add.exe against a go-winio pipe agent (Daniel-PC)

Throwaway module in the session scratchpad (go-winio v0.6.2, x/crypto v0.57.0). It served `agent.NewKeyring()` on `\\.\pipe\keyroster-probe-<8 hex>` with SDDL `D:P(D;;GA;;;NU)(A;;GA;;;<user SID>)`, plus an x/crypto/ssh server on 127.0.0.1 that recorded offers and refused them. Client: inbox `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2`.

The first ssh-add run was refused with `UNPROTECTED PRIVATE KEY FILE`, because the scratchpad tree inherits an ACE for a local sandbox group. The second run gave the key files an owner-only protected DACL. Evidence from the second run (paths and fingerprints scrubbed):

```text
$ SSH_AUTH_SOCK=\\.\pipe\keyroster-probe-45f10b8a ssh-add.exe -t 30 <scratch>/probe_key
Identity added: <scratch>/probe_key (a2-probe-key)
Lifetime set to 30 seconds
Certificate added: <scratch>/probe_key-cert.pub (a2-probe-cert)
Lifetime set to 30 seconds
$ SSH_AUTH_SOCK=\\.\pipe\keyroster-probe-45f10b8a ssh-add.exe -l
256 SHA256:<fp> a2-probe-key (ED25519)
256 SHA256:<fp> a2-probe-key (ED25519-CERT)
$ SSH_AUTH_SOCK=//./pipe/keyroster-probe-45f10b8a ssh-add.exe -l
256 SHA256:<fp> a2-probe-key (ED25519)
256 SHA256:<fp> a2-probe-key (ED25519-CERT)

$ ssh.exe -v -n -F none -o IdentityAgent=\\.\pipe\keyroster-probe-45f10b8a ... probe@127.0.0.1 exit
debug1: get_agent_identities: ssh_get_authentication_socket: No such file or directory
SERVER OFFERS: ["ecdsa-sha2-nistp256" "ssh-ed25519"]          (only the account's own key files)

$ ssh.exe -v -n -F none -o IdentityAgent=//./pipe/keyroster-probe-45f10b8a ... probe@127.0.0.1 exit
debug1: get_agent_identities: agent returned 2 keys
debug1: Offering public key: a2-probe-key ED25519-CERT SHA256:<fp> agent
SERVER OFFERS: ["ssh-ed25519" "ssh-ed25519-cert-v01@openssh.com keyid=a2-probe-cert" ...]

$ ssh.exe -v -n -F <scratch>/ssh_config ...        (file holds: IdentityAgent //./pipe/keyroster-probe-45f10b8a)
SERVER OFFERS: ["ssh-ed25519" "ssh-ed25519-cert-v01@openssh.com keyid=a2-probe-cert" ...]
$ SSH_AUTH_SOCK=\\.\pipe\keyroster-probe-45f10b8a ssh.exe -v -n -F none ...
SERVER OFFERS: ["ssh-ed25519" "ssh-ed25519-cert-v01@openssh.com keyid=a2-probe-cert" ...]
$ SSH_AUTH_SOCK=//./pipe/keyroster-probe-45f10b8a ssh.exe -v -n -F none ...
SERVER OFFERS: ["ssh-ed25519" "ssh-ed25519-cert-v01@openssh.com keyid=a2-probe-cert" ...]

(after 35 s)
$ SSH_AUTH_SOCK=\\.\pipe\keyroster-probe-45f10b8a ssh-add.exe -l
The agent has no identities.
```

**Result: A2 passed.** The working spelling is `//./pipe/<name>`. It works in `IdentityAgent`, both as `-o` and in a config file, and in `SSH_AUTH_SOCK`. `\\.\pipe\<name>` works in `SSH_AUTH_SOCK` but fails in `IdentityAgent`. `keyroster agent` prints `IdentityAgent //./pipe/keyroster-agent-<SID>` and `$env:SSH_AUTH_SOCK = '//./pipe/keyroster-agent-<SID>'`. The probe key files were overwritten and deleted, and the probe module and raw output were removed from the scratchpad.

### A3: GNOME gcr-ssh-agent on the laptop

The laptop could not be reached. `ssh ub-daniel` timed out on port 22, Tailscale reported the node offline (last seen 2 days earlier), and the LAN address timed out on ssh and ping. The gcr version and listings were therefore not collected. The probe script was written but not run, and it was deleted from the scratchpad. 02-14 Task 1 runs the same probe with the laptop on and the owner logged in.

A3: moved to 02-14

Consequence for 02-12: no gcr check ships. gcr-ssh-agent stays UNVERIFIED until 02-14 Task 1 has run the probe, and needs-hardware.md says "UNVERIFIED: A3 moved to 02-14".

## go-tpm check

`go list -m github.com/google/go-tpm` printed `v0.9.9-0.20260124013517-8f8f42cba0de` before and after `go get github.com/Microsoft/go-winio@v0.6.2`, so the version is unchanged. go-winio is a direct requirement in go.mod.
- `GOOS=windows go list -deps ./cmd/keyroster` lists 5 go-winio packages.
- `GOOS=linux go list -deps ./cmd/keyroster ./cmd/keyroster-signer` lists none.
- `scripts/dep-firewall.sh` passes with the signer graph unchanged (227 / 231 packages, the documented exception only).
- `scripts/capslock-check.sh` passes with 73 pairs, equal to the baseline.

## Accomplishments

- `internal/winagent` (Windows only):
  - `Serve` serves one x/crypto keyring on `\\.\pipe\keyroster-agent-<SID>`. The pipe DACL is protected, denies network logons and grants only the user's SID; the live DACL is checked in a test. It uses first-instance creation, so a second agent or a squatter is refused.
  - Every poll expires keys. The agent exits once a key was ever added and the keyring is empty, or after IdleExit without a key, and in both cases only when no connection is open (one mutex, a set of open connections and an `exiting` flag).
  - `VerifyServerOwner` resolves the pipe server's PID, opens its process and token, and compares SIDs only in `checkOwner`. Access denied maps to `ErrOwnerUnverifiable` with the elevated-shell guidance.
  - `Ensure` dials or starts `keyroster agent` (detached), verifies the owner, and confirms the connection with one List. It retries once when the agent was closing, and never dials the inbox agent.
- `keyroster agent` (Windows only) prints the pipe and the two ways to use it, in the proven spelling. The help covers per-SID agents for `runas` accounts and the elevated-shell refusal.
- `dialAgent` is split per OS. On Windows, admin SSHSIG signing reaches the inbox agent through go-winio. This ran on Daniel-PC: `keyroster.exe ca issue --admin-key <ed25519 key in the inbox agent>` with SSH_AUTH_SOCK unset listed the agent, signed, and stopped only at the absent signer socket. With SSH_AUTH_SOCK set to a missing pipe, the error names the pipe.
- CI: `cli-windows` (windows-2025) and `cli-macos` (macos-15) run the CLI packages; neither is a required check. `KEYROSTER_REQUIRE_SSH_AGENT=1` is set in build-test and cli-macos. cli-windows sets `KEYROSTER_REQUIRE_INBOX_SSH=1` when the image has the inbox ssh.exe.
- `TestAgentLifetime` runs against real OpenSSH ssh-agent. In WSL it passed with the switch set; with `PATH=/nonexistent` it failed with "ssh-agent not found and KEYROSTER_REQUIRE_SSH_AGENT=1".
- docs/security/needs-hardware.md has a new section, "Platform verification (D-16)".

## Verification run on Daniel-PC and in WSL

- `KEYROSTER_REQUIRE_INBOX_SSH=1 go test -count=1 -v ./internal/winagent/...` passed with no skips.
  - Passing tests: TestInboxSSHOffersAgentCert, plus TestAgent with lifetime_expiry_exit, idle_exit, second_serve_refused, verify_own_pipe, sddl_single_allow, openssh_spelling_dials, owner_mismatch_refused, owner_access_denied_names_elevation, ensure_fails_closed, exit_waits_for_open_connection, ensure_retries_once_on_closing_agent, add_races_expiry_exit and ensure_starts_real_agent.
  - The real agent exited 5.0 s after its 1 s key (ensure_starts_real_agent), and 9.95 s after the 4 s key in the offer test.
  - add_races_expiry_exit started 12-14 agents over 8 loops per run. The timing subtests passed 3 times in a row.
- `CGO_ENABLED=0 go build` of ./cmd/keyroster passed for windows, linux and darwin.
- In WSL:
  - `go test ./cmd/keyroster/...`, dep-firewall, capslock, testonly-firewall, `go vet ./...` and gofmt all passed.
  - `-race` on ./cmd/keyroster passed.
  - `go test ./internal/winagent/...` on Linux only warns "matched no packages" and exits 0, so cli-macos can list the package.
- On Windows, the full cli-windows package list passed locally.
- `bash scripts/check-pinned-actions.sh` passed: 43 pinned references.
- Task 1 verify passed: the inbox ssh.exe is present and nothing outside `.planning` changed.

## CI and PR

- **PR #36** (`feat(cli): in-memory ssh agent for Windows and CLI CI on Windows and macOS`). It was opened without auto-merge, which is enabled only after this SUMMARY update is pushed.
- **First run, on head 4b32003:** 17 checks passed and 2 failed, both caused by this plan and both fixed in a65e4dd (deviation 10):
  - lint: gosec G204.
  - cli-windows: `sddl_single_allow` compared rendered SDDL strings.
- **cli-windows runner (windows-2025):** the inbox `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` is present, and the job set `KEYROSTER_REQUIRE_INBOX_SSH=1`, so a skip of TestInboxSSHOffersAgentCert would have failed.
  - In the first run only `sddl_single_allow` failed in internal/winagent. TestInboxSSHOffersAgentCert and `ensure_starts_real_agent` therefore ran and passed on the runner.
  - The runner account is the built-in Administrator in an elevated session. Agent and client share that token, so this does not exercise the mixed elevated/normal case.
- **cli-macos (image macos-15-arm64):** `ok cmd/keyroster` with `KEYROSTER_REQUIRE_SSH_AGENT=1`, so TestAgentLifetime ran and passed against the runner's ssh-agent.
- **build-test (ubuntu-24.04):** `ok cmd/keyroster` with `KEYROSTER_REQUIRE_SSH_AGENT=1` under `-race`.
- **The run on the head that carries this update:** see PR #36's checks. This SUMMARY records pre-merge evidence only.

## Task Commits

1. **Task 1: Gating probes A2/A3**: no commit (scratchpad only, by design)
2. **Task 2: keyroster agent tracer**: `0a454a1` (feat)
3. **Task 3: CI jobs, Unix lifetime test, platform record**: `c66306b` (ci); CI fix `a65e4dd` (fix)

**Plan metadata:** `4b32003` (`docs(02-02): complete windows-agent plan`), plus the PR #36 update in the same push as a65e4dd

## Files Created/Modified

- `internal/winagent/winagent_windows.go`: PipePath, SDDL, OpenSSHSpelling, Options, Serve
- `internal/winagent/owner_windows.go`: VerifyServerOwner, checkOwner, ErrOwnerUnverifiable
- `internal/winagent/ensure_windows.go`: Ensure, ensure, dial/start, serial List confirmation
- `internal/winagent/winagent_windows_test.go`: TestMain (builds keyroster.exe), pipeInUse, TestAgent subtests
- `internal/winagent/offer_windows_test.go`: TestInboxSSHOffersAgentCert
- `cmd/keyroster/agent_windows.go`: `keyroster agent`
- `cmd/keyroster/agentconn_unix.go`, `cmd/keyroster/agentconn_windows.go`: per-OS dialAgent
- `cmd/keyroster/agentconn_unix_test.go`: TestAgentLifetime
- `cmd/keyroster/root.go`: dialAgent moved out
- `go.mod`, `go.sum`: go-winio v0.6.2
- `.github/workflows/ci.yml`: cli-windows, cli-macos, KEYROSTER_REQUIRE_SSH_AGENT
- `docs/security/needs-hardware.md`: Platform verification (D-16)

## Decisions Made

See `key-decisions` in the frontmatter. No owner decision was needed: A2 passed, and A3 moved to 02-14 rather than failing.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] ensure's List would leave a background reader on the returned connection**
- **Found during:** Task 2
- **Issue:** The plan says to confirm with `agent.NewClient(conn).List()`. In x/crypto v0.57, `NewClient` on an `io.ReadWriteCloser` starts a pipelined client with a `readLoop` goroutine. That goroutine keeps reading `conn` after List, so it would race the caller's own client (02-12) on the same connection. The client also wraps transport errors with `%v`, so `errors.Is` cannot tell a closing agent apart.
- **Fix:** `listOnce` hands the client `conn` as a plain `io.ReadWriter`, which takes the serial path and starts no goroutine, through a recorder that keeps the first transport error. `agentClosing` classifies that error (EOF, closed, broken pipe, no data, not connected) for the single retry.
- **Files modified:** internal/winagent/ensure_windows.go
- **Commit:** 0a454a1

**2. [Rule 1 - Bug] Offer test raced the agent's own exit**
- **Found during:** Task 2
- **Issue:** The 4 s key expires at add+4 s. The agent's default 5 s poll can run before add+5 s, so it exits and `ssh-add.exe -l` at add+5 s cannot connect (exit 2) instead of listing "no identities".
- **Fix:** The test holds one idle connection from before the add until after that listing (by design, an open connection keeps the agent alive, F5). It then closes the connection and waits for the exit within the plan's add+19 s deadline.
- **Files modified:** internal/winagent/offer_windows_test.go
- **Commit:** 0a454a1

**3. [Rule 1 - Bug] Offer test cleanup deadlock**
- **Found during:** Task 2
- **Issue:** The cleanup received a second time from a channel the test had already drained, and hung until the 10-minute test timeout.
- **Fix:** A closed-channel signal plus a stored wait error, and a mutex-protected output buffer, because the test read the agent's output while the copier was still writing it.
- **Commit:** 0a454a1

**4. [Rule 3 - Blocking] Inbox OpenSSH refuses key files with inherited ACLs**
- **Found during:** Task 1 (A2 probe)
- **Issue:** `ssh-add.exe` rejected the key file as `UNPROTECTED PRIVATE KEY FILE`, because %TEMP% on Daniel-PC carries an inherited ACE for a local sandbox group.
- **Fix:** The probe and TestInboxSSHOffersAgentCert give the key files an owner-only protected DACL.

**5. [Rule 2 - Correctness] "A key was ever added" tracked at Add**
- **Issue:** A key whose lifetime is shorter than the poll interval can expire unseen between polls. The agent would then fall through to the 5-minute IdleExit and miss the 16 s / 19 s test deadlines (and the D-15 exit promise).
- **Fix:** Serve wraps the keyring's Add (`trackingAgent`, an `agent.ExtendedAgent`, so sign-with-flags still works).

**6. [Rule 2 - Correctness] Serve on context cancellation**
- **Issue:** The plan does not say what happens on cancel, and waiting for open clients there could block forever.
- **Fix:** On cancel or on a listener failure, Serve closes the open connections (`stopNow`) and returns `ctx.Err()`. The normal exit rule never closes an open connection.

**7. Test adjustments, same intent and stricter where possible**
- The "within N polls" deadlines get a fixed 250 ms scheduling slack (`schedSlack`) for Windows timer granularity and loaded CI runners.
- add_races_expiry_exit: one loop that adds continuously never lets a key expire, so the agent would never race its exit. Instead, 8 loops on their own test pipes each sleep about 1 s, swept ±10 ms around the key's expiry, so their next ensure lands on a live, an exiting or a gone agent. The test asserts more agents started than loops.
- New deterministic subtest ensure_retries_once_on_closing_agent: one closed connection is retried and succeeds; two fail.
- Other new subtests: openssh_spelling_dials (go-winio reaches the pipe in the printed spelling) and a live pipe DACL check inside sddl_single_allow.
- Test certificates come from `internal/cert.Build`, because `.SignCert` is banned outside internal/cert by forbidigo.
- The offer test asserts the certificate's real key ID.

**8. Exported `winagent.OpenSSHSpelling`**
- Not in the plan's artifact list. It converts `\\.\pipe\x` to `//./pipe/x`, the spelling A2 proved, for the agent output and 02-12's login output.

**9. PR order**
- The PR number and CI results cannot be known before the push. The first pushed head (4b32003) carried the complete SUMMARY with those facts pending. This update fills them in, in the same push as the CI fix, and auto-merge is enabled only after that, so the owner cannot squash a head that lacks them.

**10. [Rule 1 - Bug] Two CI failures on PR #36's first run**
- **Found during:** Task 3 (publish)
- **Issue 1:** cli-windows `sddl_single_allow` compared rendered SDDL strings. On windows-2025 the account is the built-in Administrator (RID 500), and SDDL renders its SID as the alias `LA`, so the string check failed although the DACL was right (`D:P(D;;FA;;;NU)(A;;FA;;;LA)`).
- **Fix 1:** the test walks the live DACL's ACEs and checks that the DACL is protected, has exactly one allow ACE whose SID `Equals` ours, and has one deny ACE for the network logon SID.
- **Issue 2:** lint (gosec G204) flagged TestAgentLifetime's `exec.Command` of the ssh-agent found on PATH.
- **Fix 2:** a `//nolint:gosec // G204` annotation, as the other oracle tests in the repo use.
- **Commit:** a65e4dd

**Total deviations:** 7 auto-fixed (4 bugs, 1 blocking, 2 correctness) plus test adjustments and one small API addition. **Impact:** no scope change. Each fix closes a defect in the plan's literal instructions, which would otherwise have broken 02-12 or produced false test results.

## UNVERIFIED

- GNOME gcr-ssh-agent lifetime and certificate handling: A3 moved to 02-14 (laptop offline).
- A browser and passkey login on macOS: there is no Mac.
- The mixed elevated case (agent started elevated, client in a normal shell): not run on Daniel-PC. The CI runner is elevated on both sides, which is a different case. Only the access-denied mapping is unit-tested.
- The t.Fatalf in the real-binary tests when a foreign agent already serves the account's pipe: no run arranged that (both answers of pipeInUse are asserted).
- The 02-12 caller of Ensure does not exist yet. Ensure is exercised by ensure_starts_real_agent and the in-package cases.

## Known Stubs

None.

## Threat Flags

None. The new surface (a named pipe per user) is the subject of the plan's own threat model, T-02-07 to T-02-10, T-02-79 and T-02-80.

## Next Phase Readiness

- 02-12 uses `winagent.Ensure` (through its own `connectLoginAgent` variable) and `winagent.OpenSSHSpelling` for the login output. It ships no gcr check, because A3 moved.
- 02-14 Task 1 runs the A3 probe on the laptop, and Task 5/6 make cli-windows and cli-macos required.

## Self-Check: PASSED

- All 9 created files exist; task commits 0a454a1 and c66306b are ancestors of HEAD.
- Exactly one `A3:` line, in the form `A3: moved to 02-14`.
- No 10.x, 100.x or 192.168.x address, account name or user SID in this file or in needs-hardware.md.
