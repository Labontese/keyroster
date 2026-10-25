---
phase: 03-linux-agent-and-revocation
plan: 02
subsystem: auth
tags: [login, ssh-agent, passkey, webauthn, routes, restore, audit-export, requirements]

requires:
  - phase: 02-passkey-login-mvp
    provides: keyroster login (D-12 loopback flow), the login redeem route, the web sign-in routes, the directory install pipeline, the audit export
  - phase: 03-linux-agent-and-revocation
    provides: 03-01's revoke and KRL routes in New's mux
provides:
  - keyroster login connects to the ssh-agent before the begin and computes the agent lifetime at the add (E-IN-01, E-IN-02)
  - the login redeem reads the clock again after currentStatus and sends the signer request by CreatedAt + 295 s; the answer is read for up to signerCallTimeout after the send (C-IN-01, round 2)
  - newRouteMux, a ServeMux that records its patterns, and Server.patterns
  - TestNoNonPasskeySignInRoute and TestLoginNeverWritesKey (the two Phase 2 prohibitions)
  - directory_install export lines carry the directory and its signatures; restore step 3 replays lost versions (A-IN-01)
  - AGENT-01, REVOKE-01 and PLAT-01 reworded; UI-02 note; RHEL 8 / FIPS out-of-scope row; ROADMAP Phase 3 criterion 1 and Phase 4 line
affects: [03-04, 03-05, 03-07, 03-15, 03-16, 04]

actuals:
  tokens: 22086
  tasks: 3
  commits: 7
plan_head_before: 9fc497c157a83d3e14238c0822dfb42177d612dc
plan_head_after: b2cc53783c1055713be66bb1e048d1f89cbcde1d

tech-stack:
  added: []
  patterns:
    - "Every internal/server mux is built with newRouteMux, which records each pattern before it registers it"
    - "A deadline on an injected clock is applied to a context as the time left to it, measured on that clock"
    - "A runbook command that a test runs is kept verbatim in the test and checked against the runbook text"

key-files:
  created:
    - internal/server/routes_test.go
    - cmd/keyroster/login_disk_test.go
    - test/e2e/restore_test.go
  modified:
    - cmd/keyroster/login.go
    - cmd/keyroster/loginagent_unix.go
    - cmd/keyroster/loginagent_windows.go
    - cmd/keyroster/login_test.go
    - cmd/keyroster/login_unix_test.go
    - cmd/keyroster/login_windows_test.go
    - internal/server/login.go
    - internal/server/login_test.go
    - internal/server/server.go
    - internal/audit/export.go
    - internal/audit/export_test.go
    - docs/runbooks/signer-install.md
    - docs/security/needs-hardware.md
    - .planning/REQUIREMENTS.md
    - .planning/ROADMAP.md

key-decisions:
  - "keyroster login connects to and lists the agent right after planning, before the begin, on every OS; the one connection is held for the add, and the lifetime is computed immediately before the add"
  - "The login redeem refuses a code past its expiry or past CreatedAt + 295 s before RedeemLogin; the signer context's wall-clock deadline is the time left to that limit on the server clock"
  - "Every internal/server mux is built with newRouteMux; a keyword route needs an entry in passkeyRoutes (03-07's agent mux included)"
  - "Export lines of directory_install carry the directory and sigs (decoded, unverified); a restore replays them, and the post-replay export is the next --previous baseline"
  - "The plan-drift todo is closed with the note option; the live main-integrity ruleset equals .github/rulesets/main-integrity.json (19 checks, cli-windows included), checked 2026-10-25"

patterns-established:
  - "newRouteMux: a new server mux records its own patterns, so route tests read what is registered"
  - "Restore replay: proposals are written from the saved export's decoded directory_install line and installed in log order"

requirements-completed: []

coverage:
  - id: D1
    description: "keyroster login with no usable agent stops before the begin: no begin, no redeem, no certificate (E-IN-01)"
    verification:
      - kind: unit
        ref: "cmd/keyroster/login_test.go#TestLoginFlowFakeServer/no_agent_no_begin"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/login_unix_test.go#TestLoginAgentUnix/ssh_auth_sock_unset_refused"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/login_test.go#TestLoginFlowFakeServer/agent_lost_after_preflight"
        status: pass
    human_judgment: false
  - id: D2
    description: "The agent lifetime is computed from a fresh clock reading immediately before the add and refused below 60 s (E-IN-02)"
    verification:
      - kind: unit
        ref: "cmd/keyroster/login_test.go#TestLoginFlowFakeServer/lifetime_recomputed_at_add"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/login_test.go#TestLoginFlowFakeServer/too_little_left_at_add_refused"
        status: pass
    human_judgment: false
  - id: D3
    description: "A redeemed login code reaches the signer before CreatedAt + 295 s or is refused unburnt (C-IN-01)"
    verification:
      - kind: unit
        ref: "internal/server/login_test.go#TestLoginRedeem/redeem_status_stall"
        status: pass
    human_judgment: false
  - id: D4
    description: "No sign-in or session route but the passkey ceremony's is registered, and no mux bypasses the record (02-10 prohibition)"
    verification:
      - kind: unit
        ref: "internal/server/routes_test.go#TestNoNonPasskeySignInRoute"
        status: pass
    human_judgment: false
  - id: D5
    description: "keyroster login writes its ephemeral key to no file (02-12 prohibition)"
    verification:
      - kind: unit
        ref: "cmd/keyroster/login_disk_test.go#TestLoginNeverWritesKey"
        status: pass
    human_judgment: false
  - id: D6
    description: "Restore step 3 replays a lost directory version from the saved export with keyroster directory install (A-IN-01, D-20)"
    verification:
      - kind: e2e
        ref: "test/e2e/restore_test.go#TestRestoreReplaysLostDirectory (local WSL, OpenSSH 10.5p1, namespace hosts entry)"
        status: pass
      - kind: unit
        ref: "internal/audit/export_test.go#TestDecodeLoginIssue/directory_install"
        status: pass
    human_judgment: false
  - id: D7
    description: "needs-hardware.md records the timed Windows expiry run; the requirement texts, the ROADMAP lines and the closed todos match the owner's decisions"
    verification: []
    human_judgment: true
    rationale: "Wording against the owner's decisions and against 02-VERIFICATION.md needs a human reader; the greps only show the phrases are present"

duration: 47min
completed: 2026-10-25
status: complete
---

# Phase 3 Plan 02: Phase 2 Follow-ups Summary

**`keyroster login` now checks the ssh-agent before the login begins and computes the agent lifetime at the add. A redeemed login code reaches the signer inside its window or is refused unburnt. Two named tests enforce the Phase 2 prohibitions (passkey-only sign-in routes, no key on disk). A signer restore can replay lost directory versions from the saved export, and the run is in CI e2e. AGENT-01, REVOKE-01 and PLAT-01 are reworded as the owner decided.**

## Performance

- **Duration:** about 47 min
- **Started:** 2026-10-25T05:44:37Z
- **Completed:** 2026-10-25T06:31Z (before the PR; CI and the merge gate follow)
- **Tasks:** 3 executed. Task 4 is the merge gate.
- **Files modified:** 26 (plus this file and STATE.md)

## Accomplishments

- **The agent before the begin (E-IN-01).**
  - `run()` calls `connectLoginAgent` right after `plan()` and sends one `List` on the connection. On Windows, `winagent.Ensure` runs first, with its owner check and its own List.
  - With no usable agent, the login stops with the agent's instructions. No begin and no redeem reach the server.
  - The connection is held until the add and the listing check. `addLoginToAgent` takes the agent client and no longer connects.
- **The lifetime at the add (E-IN-02).**
  - `remainingOnServer` is the one computation: now + skew + 1 s, rounded up.
  - `checkLoginCert` uses it for the 60 s check. `addLoginToAgent` calls it again with a fresh `loginNow()` immediately before `ag.Add`, refuses below 60 s with the existing "less than 60 s left" error, and passes the result as `LifetimeSecs`.
  - Connecting first also moves a Windows cold start before the certificate exists. That removes E-IN-02's original cause; the recompute guards whatever time is left between the check and the add.
- **The redeem window (C-IN-01).**
  - After `currentStatus`, the handler reads `s.clock()` again. It refuses a code past `CodeExpires`, or at or past CreatedAt + `loginSignerWindow` (295 s), with the existing expired answer, before `RedeemLogin` burns it.
  - The signer call's context ends at the 10 s call timeout or at that limit, whichever comes first (`context.WithDeadline`).
  - The timing comment now says that the window holds because the deadline is enforced.
- **TestNoNonPasskeySignInRoute.**
  - `newRouteMux` (internal/server/server.go) embeds `*http.ServeMux`. Its `Handle` and `HandleFunc` append the pattern to that mux's own list, then delegate. New copies the list into `Server.patterns`, and the registration lines are unchanged.
  - Subtests:
    - `keyword_route_not_allowlisted`: login, signin, sign-in, session, password, totp, otp, recovery, magic.
    - `allowlist_entry_not_registered`: the eight exact `passkeyRoutes` patterns, each with its reason.
    - `single_mux`: an AST scan of the package's non-test files. It refuses `http.NewServeMux` outside `newRouteMux`, `http.ServeMux` literals, `new(http.ServeMux)`, and `x.ServeMux.Handle`/`HandleFunc` outside routeMux's methods.
    - `probes`: GET and POST to /login/password, /totp, /recovery and /magic, and a form POST of `password=x` to /login. Each gets 404 or 405 and no Set-Cookie.
- **TestLoginNeverWritesKey.**
  - A full login runs with HOME/USERPROFILE, XDG_CONFIG_HOME, APPDATA, TMPDIR/TMP/TEMP and the working directory (`t.Chdir`) all fresh. It uses the real `os.UserConfigDir`, with the config copied in.
  - The test takes the key from the agent add. It then searches every file for the seed (raw, hex, base64, base64url), its PKCS#8 DER and PEM body, its OpenSSH blob, the OpenSSH PEM first line, and `PRIVATE KEY`.
- **Restore replay (A-IN-01).**
  - Export lines of `directory_install` entries now carry `directory` and `sigs` (standard base64) in `decoded`.
  - signer-install.md step 3 writes each lost version's `directory.json` and `directory.json.sigs` from the saved export with stock tools (grep, cut, base64) and replays them in log order with `keyroster directory install`.
  - It also covers:
    - the exposure window (keep users away from the server meanwhile);
    - the 5 s server status cache (wait or restart the server);
    - the trust boundary: decoded is unverified, and the signer re-checks quorum signatures and prev;
    - the 409 `credential_not_pending` limit (re-invite, then redo later changes by hand);
    - the post-replay export as the new `--previous` baseline.
  - `TestRestoreReplaysLostDirectory` runs those commands verbatim and checks that they are still in the runbook.
- **Docs and planning.**
  - needs-hardware.md records the 2026-10-23 run in 02-VERIFICATION.md's words, with its limits and that E-IN-02 is fixed but not re-timed on Windows.
  - REQUIREMENTS.md and ROADMAP.md carry the owner-approved texts.
  - The eight todos are in `.planning/todos/completed/`, each with a Resolution section.

## Task Commits

1. **Task 1 (tracer): the agent before the begin, the lifetime at the add.** `133b288` (fix). Tracer gate: interactive, `end-of-phase`, automated-only verify. The verify was re-run green on Windows and in WSL after the commit, so the plan continued to Task 2.
2. **Task 2 (tdd): the redeem window and the two negative tests.**
   - `79e3ad4` (test): RED for `redeem_status_stall`.
   - `52fe1eb` (feat): GREEN.
   - `7039844` (test): newRouteMux, routes_test.go and login_disk_test.go.
   - `b2cc537` (test): the embedded-ServeMux check, added in self-review.
3. **Task 3: restore replay, docs, planning, todos.**
   - `b66d336` (feat): export fields, restore e2e and runbook.
   - `72e5e3d` (docs): needs-hardware, REQUIREMENTS, ROADMAP and the todo moves.

**Plan metadata:** the `docs(03-02): complete phase2-followups plan` commit that carries this file.

## Mutant results

Each mutant was applied by hand, run, and restored. `git status` was checked to be clean after each one.

| Mutant | Test | Result |
|---|---|---|
| connect moved back after the redeem (the old order) | `TestLoginFlowFakeServer/no_agent_no_begin` | FAIL: the login began ("Approve this login in your browser" printed) and did not exit within 60 s |
| lifetime taken from the check's clock reading | `lifetime_recomputed_at_add`, `too_little_left_at_add_refused` | FAIL: "agent lifetime 299 s, want 295 s"; the 60 s-later add exited 0 |
| redeem without the fix (RED, `79e3ad4`) | `redeem_status_stall`, all three cases | FAIL: 200 instead of 400 twice; "the signer call had 10s left, want at most 7 s" |
| no clock re-read after `currentStatus` | `expired_after_stall_not_burnt`, `inside_window_deadline` | FAIL |
| no CreatedAt + 295 s check | `deadline_passed_not_burnt` | FAIL: 200 |
| `mux.HandleFunc("POST /login/password", ...)` in New | `keyword_route_not_allowlisted`, `probes` | FAIL: route named; POST /login/password = 200 |
| a second `http.NewServeMux()` in New | `single_mux` | FAIL: server.go position named |
| a stale `passkeyRoutes` entry | `allowlist_entry_not_registered` | FAIL |
| `mux.ServeMux.HandleFunc("POST /login/password", ...)` (unrecorded) | `single_mux`, `probes` | FAIL; `keyword_route_not_allowlisted` cannot see it, which is why the AST check exists |
| `os.WriteFile(TMP/k, seed)` in runLogin | `TestLoginNeverWritesKey` | FAIL (raw seed) |
| OpenSSH PEM of the key to `./id_login` | `TestLoginNeverWritesKey` | FAIL (`PRIVATE KEY` header, OpenSSH PEM line) |
| export without the `directory` and `sigs` fields | `TestRestoreReplaysLostDirectory` | FAIL: "the extracted proposal is not the directory and signatures the signer installed as v2" |

## E-IN-01 residual

`agent_lost_after_preflight` pins it. The agent answers the preflight List and is gone at the add. The login was begun and redeemed, so the signer issued and logged a certificate. The add fails with the existing add-failure error, and the command exits non-zero, with begin and redeem counted once each. That certificate is unusable, because its ephemeral key dies with the process. The window is now the time from the preflight to the add (the user's approval), not every run without an agent.

## Ruleset check (plan-drift todo)

- `scripts/gh-as-bot.sh api repos/Labontese/keyroster/rulesets` returns `main-integrity` (24454165, active) and `main-review` (24454166, active).
- The live main-integrity required checks equal `.github/rulesets/main-integrity.json`: the same 19 contexts, `cli-windows` and `cli-macos` included. Checked 2026-10-25, read-only. Claude applies no ruleset (D2).
- The 02-13 and 02-14 plans stay unedited. `git diff origin/main -- .planning/phases/02-passkey-login-mvp/` is empty.

## What ran and what did not

**Ran (2026-10-25):**
- **Windows:** `go test` of cmd/keyroster (the whole package), internal/server and internal/audit. `go vet` for windows, linux and darwin. `CGO_ENABLED=0` builds of cmd/keyroster for windows, linux and darwin.
- **WSL, full gate:**
  - `go test -race -count=1 ./...`, PASS.
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/`, plus gofmt.
  - golangci-lint: 0 issues, linux; also GOOS=windows for cmd/keyroster.
  - capslock: 91 pairs against a baseline of 91. dep-firewall: OK, with only the documented libc exception.
  - go.mod and go.sum are unchanged.
- **WSL, full e2e suite on OpenSSH 10.5p1.** It ran in the uncommitted namespace workaround from 03-01: nested user namespaces, with a bind-mounted /etc/hosts entry for keyroster.localhost, as uid 1000.
  - 33 top-level tests passed, including `TestRestoreReplaysLostDirectory`, `TestLoginEndToEnd`, `TestLoginRefusals`, `TestLoginSignerEndToEnd`, the audit tests and the approve tests.
  - The one failure is `TestSSHDRejects/pty_allowed`, which fails only inside that namespace (03-01 recorded the same).
- **Mutants:** the table above.

**Not run here (UNVERIFIED locally):**
- **CI.** Both e2e matrix lanes, cli-windows and cli-macos run on the PR. The results go in the merge-gate return, not in this file.
- **e2e on OpenSSH 9.5p1.**
- **A Windows re-timing of the expiry after the E-IN-02 fix.** needs-hardware.md says so.
- **A long approval wait with a held agent connection.** The login now holds its agent connection across the browser approval, up to the approval window. This is covered with OpenSSH ssh-agent and keyroster agent only for short test flows. A held connection to GNOME gcr-ssh-agent over a minutes-long approval is UNVERIFIED.
- **The restore cases that were not run:**
  - a VM snapshot restore;
  - the replay of a lost bundle_install;
  - a lost version that binds a passkey (409) and the re-invite after it;
  - blocking users at the network.

  The runbook labels each of these UNVERIFIED.
- **The e2e_pkcs11 and e2e_tpm tags.**

## Decisions Made

- **A preflight List on every OS.** On Unix, the connect only dialed SSH_AUTH_SOCK. A List is what makes the agent "usable", and it is what `agent_lost_after_preflight`'s fake answers.
- **The signer deadline across clocks.** `WithDeadline(tctx, time.Now().Add(signerLimit.Sub(now)))`. In production `s.clock` is `time.Now`, so this is CreatedAt + 295 s. Under the test clock (t0, in the past), the literal `WithDeadline(created+295s)` would have expired every redeem's context.
- **The export carries the bytes.** See deviation 1.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The export's decoded line did not carry the directory**
- **Found during:** Task 3 (restore replay).
- **Issue:** The plan writes the proposal "from the export's decoded directory_install line", but `audit.Decode` rendered only `version` and `policy_version` there. The bytes were only inside the binary leaf, so no operator command could write the proposal.
- **Fix:**
  - `decodeLeaf` adds `directory` and `sigs` ([]byte, standard base64) for kind 7, and `export_test.go` checks both.
  - `audit verify` never reads `decoded`. Its 16 MiB line cap covers the larger line: the leaf at most 1 MiB + 64 KiB, base64 about 1.5 MiB, twice.
  - No golden export exists under test/vectors.
- **Files modified:** internal/audit/export.go and internal/audit/export_test.go. Both are outside `files_modified`.
- **Verification:** the export unit test. The restore e2e. A mutant without the fields fails the e2e.
- **Committed in:** b66d336.

**2. [Plan detail] The lifetime test steps the clock instead of slowing the connect**
- **Found during:** Task 1.
- **Issue:** The connect now happens before the begin, so a slow connect no longer falls between the check and the add.
- **Fix:** The fake server arms a stepped clock once it has built the certificate. checkLoginCert reads T, and the add reads T + 4 s. The test requires the lifetime to equal the check-time value minus 4.
- **Committed in:** 133b288.

**3. [Rule 2 - Missing critical] Extra cases beyond the plan**
- **Added:**
  - `too_little_left_at_add_refused`: the 60 s refusal at the add.
  - `deadline_passed_not_burnt`: the CreatedAt + 295 s branch, reached by storing a code valid to +299 s. No handler writes one past +290 s, so without this the branch would be unexercised.
  - The `single_mux` check for registrations through the embedded ServeMux, found in self-review.
  - The restore test's check that the runbook still has its commands.
- **Committed in:** 133b288, 79e3ad4, b2cc537, b66d336.

**4. [Plan detail] Files outside the list**
- **Files:** cmd/keyroster/login_windows_test.go (the Windows `useUnusableLoginAgent`), internal/audit/export.go and internal/audit/export_test.go.
- **Count:** 26 files instead of 23.

**5. [Plan detail] T-02-107**
- **Issue:** The threat row lives in the Phase 2 plan, which this plan must not edit.
- **Fix:** Only the code comment in internal/server/login.go is corrected. The todo's Resolution says so.

**6. [Plan detail] No PR number in the todos or here**
- **Issue:** The orchestrator has this file committed and pushed before the PR opens.
- **Fix:** The todos name the branch `p03/02-phase2-followups`. The PR number is in the merge-gate return.

**7. [Plan detail] Commit types**
- **Detail:** Task 2's GREEN commit uses `feat(03-02)`, following the TDD gate convention, although the change is a fix. The squash merge takes the PR title.

---

**Total deviations:** 7. Of these, 2 were auto-fixed (Rules 2 and 3) and 5 are plan details.
**Impact on plan:** One small additive format change in the informational export (deviation 1), flagged for the owner's review. No new module. No change to a signed format or the wire.

## TDD Gate Compliance

- **RED.**
  - The target: `TestLoginRedeem/redeem_status_stall`, run against the unfixed handler.
  - The result: exit 1, failing on the planned assertions, with no build or setup error:
    - "redeem after the stall = 200 ..., want 400";
    - "the signer call had 10s left ..., want at most 7 s";
    - "redeem past the signer window = 200".
  - Commit: `79e3ad4`.
- **GREEN.** `52fe1eb`; all three cases pass.
- **No REFACTOR commit.**
- **Not genuinely RED.** The route test and the disk test guard behaviour that already held. The route test also needs `Server.patterns` to compile, and a compile failure is not RED. Their mutants (above) stand in for RED evidence.
- **The classifier was not used.** Go output is not a format `gsd-tools check tdd-red-evidence` reads, and `workflow.tdd_mode` is off (01-04 precedent).

## Issues Encountered

- **WSL still does not resolve `keyroster.localhost`.**
  - A single `unshare --user --map-current-user --mount` could not bind-mount /etc/hosts ("must be superuser").
  - Nested namespaces worked: an outer one with `--map-root-user --mount`, then an inner `--map-user=1000`. The script stayed in the session scratchpad and was not committed.
- **The first two Task 3 commits had their contents swapped.** The staged todo renames landed in the restore commit. They were rebuilt locally with `git reset HEAD~2` (no `--hard`; the branch was not yet pushed), so each commit holds its own files.

## Known Stubs

None.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: export content | internal/audit/export.go | The informational `decoded` part of a directory_install export line now carries the directory document and its signatures. Both are already in the leaf; the line is about twice as long. The runbook states that `decoded` is unverified and that the signer re-verifies a replay. |

## User Setup Required

None.

## Next Phase Readiness

- **03-07's agent mux** must be built with `newRouteMux`, or `single_mux` fails. Its recorded list stays separate from the browser list.
- **A homelab restore** can now replay lost directory versions. Only exports written by a build with this plan carry the bytes.
- **E-IN-02 on Windows:** a re-timed cold-start run would turn its UNVERIFIED into a measurement.

## Self-Check: PASSED

- **Files:** internal/server/routes_test.go, cmd/keyroster/login_disk_test.go and test/e2e/restore_test.go exist. The eight todos are under .planning/todos/completed/, and none is left under pending/.
- **Commits:** 133b288, 79e3ad4, 52fe1eb, 7039844, b66d336, 72e5e3d and b2cc537 are ancestors of HEAD, each SSH-signed.
- **Acceptance greps:**
  - `connectLoginAgent(` (line 243) comes before the begin call (line 300), and `addLoginToAgent` does not connect.
  - `WithDeadline` is in internal/server/login.go.
  - `newRouteMux` is in server.go and routes_test.go, and `registeredPatterns` appears 0 times.
  - `http.NewServeMux(` appears once outside comments in server.go.
  - `not in FIPS mode` appears once each in REQUIREMENTS.md and ROADMAP.md, along with `installation ID at enrollment` and `UI moves to Phase 4`.
  - `until plan 02-09` appears 0 times in signer-install.md, and `keyroster directory install` 3 times.
  - needs-hardware.md has "3.9 s" and "1.1 s".
  - The diff against origin/main for `.planning/phases/02-passkey-login-mvp/` is empty.

## Pre-merge review fixes

PR #59 review, on head 0db3f9c. Each test marked **(fails before)** was run against the code before its fix and failed: either the fix was reverted, or the new check was temporarily disabled, and the code was restored afterwards. Adjusted fixtures and the e2e additions are listed apart from those tests; none of the e2e additions has been run.

**Fixed**

- **The login preflight passed a locked agent, or one that refuses the lifetime constraint** (medium). Fixed in `448abd6`.
  - Before the begin, `probeLoginAgent` adds a throwaway Ed25519 key with a 30 s lifetime constraint, then removes it. If either step fails, the login stops with "(it is locked, or refuses such keys), so no login was started".
  - The add error after the redeem no longer blames only the constraint.
  - Tests:
    - `locked_agent_no_begin` (new; `agent.NewKeyring` locked) **(fails before)**: with the probe disabled, the login goes on to the browser wait and times out after 60 s.
    - `constrained_add_refused_no_retry`, which now requires `requireCalls(0,0)` and one constrained probe **(fails before)**, the same way.
    - `probe_key_removed` (new) **(fails before)**: with the Remove skipped, it fails with "the preflight's test key is still in the agent".
  - Adjusted fixture: `agent_lost_after_preflight`'s fake agent now answers the probe's add and remove too, and the expected error text follows the reworded message.
  - The E-IN-01 residual above is now only the agent being lost, locked or stopped between the probe and the add.
- **The redeem's signer deadline drifted by the time RedeemLogin took** (medium; this and the Codex finding "Anchor the redeem deadline before the database write" are one bug). Fixed in `d93e442`.
  - The time left to CreatedAt + 295 s is turned into a wall-clock instant right after the second clock check.
  - RedeemLogin and the signer call both run under that instant. A burn still waiting when it passes is abandoned unburnt and logged as `expired`.
  - Tests use a second connection that holds `BEGIN IMMEDIATE`:
    - `database_wait_counts_against_deadline` **(fails before)**: with a 2 s lock, the signer gets about 5 s, not 7 s. The old code gave "7s left".
    - `database_wait_past_deadline_not_burnt` **(fails before)**: with a 3 s lock against 2 s left, the code stays approved and the signer is not called. The old code answered 200.
  - On modernc, the cancelled UPDATE is abandoned once the lock is free, not at the deadline itself. The test comment says so.
- **The restore replay installed bytes nobody verified, and the runbook said step 2 had verified them** (medium; this and the Codex finding "Extract restore proposals from authenticated leaf bytes" are one bug). Fixed in `c1767bd`, then narrowed in `649408d`.
  - `c1767bd` compared the whole line with what Export writes. That froze `Decode`'s output: any field a later binary added would make every saved export since 03-02 fail. `649408d` replaced it with `checkReplayFields`.
  - `checkReplayFields` refuses a line whose text carries a `"directory":` or `"sigs":` key unless all three hold: the line is a directory_install line, each key occurs exactly once, and each value is the standard base64 of the leaf's own document or signatures. The other decoded fields stay informational.
  - Lines without these keys, as in exports from before 03-02, are not checked.
  - This corrects the threat-flag row above: the runbook no longer calls the `directory` and `sigs` fields unverified.
  - Runbook step 3, first item:
    - Run `audit verify` on the saved export itself.
    - Run `audit verify --previous /tmp/restored.jsonl /root/latest-saved.jsonl` to prove the restored log is a prefix of the saved one.
    - The false "step 2 does this" sentence is gone.
    - The extraction adds `test -s` for both files.
    - The residual paragraph now names the remaining case: a saved export written by someone who holds the log key.
  - Tests: `TestVerifyReplayFields` **(fails before)**. With the check disabled, five cases fail: swapped directory, swapped sigs, missing sigs, a nested decoy, and a decoy on another kind. `other_decoded_field_ok` and `pre_03_02_line_ok` pass with the check on.
  - e2e addition, not run (no Linux e2e environment here; it compiles under `go vet -tags e2e` for windows and linux): `TestRestoreReplaysLostDirectory` now exports the restored log while the signer is stopped, requires `--previous restored saved` to pass, and runs the `test -s` lines.
- **The post-replay baseline was not anchored to the restored export** (low, split verdict; real, since an available anchor went unused). Fixed in `0c8dd46`, docs. `b6068a4` adds the export command for the file those checks name, `/tmp/after-replay.jsonl`, which no step wrote before.
  - Before the new export becomes the baseline, it must also pass `audit verify --previous /tmp/restored.jsonl /tmp/after-replay.jsonl`. Keep `/tmp/restored.jsonl` with the record of the restore.
  - e2e addition, not run: `TestRestoreReplaysLostDirectory` asserts the same check.
- **`TestNoNonPasskeySignInRoute` missed a sign-in route that matches no keyword** (low, split verdict; a cheap test-only fix). Fixed in `92a5665`.
  - New subtest `every_route_reviewed`: every recorded pattern must be in `passkeyRoutes` or the new `otherRoutes`, each entry with its reason, and stale entries fail.
  - **(fails before)**: the mutant `GET /auth/email/{token}` in server.go made it fail. The mutant was then removed.
  - For later plans: every new server route must now be added to `otherRoutes` (or `passkeyRoutes`) with its reason, or this test fails. 03-10's `POST /api/v1/agent/probecert` is one such route, and so is any agent route of 03-07 that is recorded in the same list.

**Skipped**

- **The short signer deadline also limits reading the reply** (low, split verdict). No code change. The plan's must_have puts the deadline on the signer call. Giving the send and the read separate deadlines changes `signerclient`'s contract, so it is the owner's decision.
  - What `d93e442` did instead: a comment at the signer call records this as the accepted lost-answer case (T-02-108, not retried).
  - The 03-02 fixes make the case more likely. The signer's time can now drop below 5 s when the second check or the burn falls late in the window.
  - Options for the owner:
    - (a) Add a `signerclient` variant that applies the CreatedAt + 295 s deadline to the dial and the write, and `signerCallTimeout` to the read. This closes the gap; it costs one more client entry point.
    - (b) Keep it as it is, as a documented residual.

**Checks run:** `gofmt -l` (empty), `go vet ./...` (with `GOOS=linux` and `GOOS=darwin` too), `go vet -tags e2e ./test/e2e` (windows and linux), `go test -count=1` on every package touched, and `go test ./...` once. All passed on Windows.
- The Unix-only tests (`login_unix_test.go`, the real ssh-agent `happy_path`) were only compiled, through the GOOS vets; they were not run.
- `-race` was not run, because there is no cgo toolchain.

## Pre-merge review fixes, round 2

PR #59 review, on head 48e4a8f. Each test failed with its fix disabled or reverted and passed once the fix was restored.

- **Item 1, decoded `kind` (Codex medium) and the e2e baseline check (Codex low):** `62f9002`. Owner decision (2026-10-25): `audit verify` requires on every line that the decoded `kind` is the leaf's own. `checkGrepFields` also covers the runbook's other grepped fields: `bundle_version` on every bundle_install line, and `version` where a directory_install line carries it (written only since 02-12). The runbook now verifies the saved export in step 2, before its counts are read. Tests:
  - `TestVerifyGrepFields`, with `hidden_final_install_refused`: all 12 refusal cases failed with the check disabled.
  - `TestRestoreRunbookChecks`: the 0db3f9c "After the replay" paragraph failed it 3 times, and dropping the step-2 block 2 times.
- **Item 2, redeem read deadline (low):** `0877449`. Owner decision (2026-10-25): a separate read deadline. `signerclient.LoginSend` bounds the dial and the write by ctx, and reads for `signerCallTimeout` after the write. Tests:
  - `TestLoginSendReadDeadline`: `answer_after_send_deadline_received` and `read_bounded_by_read_timeout` failed with the read on ctx's deadline. `past_send_deadline_never_sent` failed when ctx bounded no part of the send.
  - `TestSocketSignerLoginReadsPastSendDeadline` failed with `signerclient.Login`.
  - Not exercised: removing only the dial bound or only the write bound, because each still blocks the send alone.
- **Item 3, QF1008 lint:** `6063e7a`. `a.Agent.Lock` became `a.Lock`, since `recordingAgent` does not override `Lock`. golangci-lint reported QF1008 on the old line and 0 issues after the fix.

**Checks run:**
- `gofmt -l` reported nothing.
- `go vet ./...` passed for windows, linux and darwin, and `go vet -tags e2e ./test/e2e/` for linux and windows.
- In WSL: `go test -race -count=1 ./...` passed, and golangci-lint reported 0 issues for linux, windows and darwin.
- The e2e suite ran in WSL under the uncommitted namespace hosts workaround with OpenSSH 10.5p1: 34 passed. `TestSSHDRejects/pty_allowed` failed, in a test no change here touches. The likely cause is PTY allocation in the user namespace, but that is unconfirmed; CI is the authoritative run.

## Pre-merge review fixes, round 3

PR #59 review, on head 894a6c3. Each test failed against its mutant or the pre-fix text and passed once the fix was restored.

- **Item 1, saved export read unverified after `log rewritten` (medium), with item 2, the runbook check's order and condition (low):** `095294c`. Step 2 now runs both `audit verify` runs of the saved export whenever its first command fails, whatever it reports, before any grep of the saved export. If either fails, the operator stops, keeps the signer stopped and escalates. A restored signer that logged entries after the restore, for example one that auto-started, also ends there, because its log is no prefix of the saved one. `TestRestoreRunbookChecks` pins the condition, refuses the 894a6c3 gate sentence, and requires the verify block and the stop rule before every grep of the saved export. Proof: it failed on the 894a6c3 runbook (the gate) and on the 48e4a8f runbook. A copy of the fixed runbook with step 2's greps moved before the verify block failed it on the order alone. `7b5809d` (docs only) adds the `log rewritten` case to the runbook's UNVERIFIED list: no test runs it.
- **Item 3, the `k != key` branch of checkGrepFields (low):** `eb9e52a`. `TestVerifyGrepFields` adds a login_issue line and four colliding cases: `bundle_version` 3 on directory v3, `version` 1 on bundle v1, and `version` 0 and `bundle_version` 0 on the login line. Proof: with `k != key` dropped, exactly these four failed.
- **Item 4, 03-03's revoke rendering (low):** `5b0bfe7`, docs only. 03-03-PLAN.md renders an entry's kind as `entry_kind`, keeps `bundle_version` and `version` keys off revoke and krl_publish lines, and adds an acceptance line: as-exported revoke (two or more entries) and krl_publish lines pass Verify. `f92a697` words that line without a grep that always matches.
- **Item 5, Verify's doc comment (low):** `3742441`, comment only. It now names the decoded fields Verify checks instead of saying the decoded objects are ignored.
- **Item 6, the extraction block without `set -e` (low):** `73b8399`. The runbook's block is a `bash -eu <<'EOF'` heredoc that ends with a `wrote the proposal` line, so a paste stops at the first failing line as CI's run does, and the operator's shell stays open. The e2e test runs the same script in `bash -eu`, and `requireReplayBlock` pins the whole block, wrapper included, in `TestRestoreRunbookChecks`. Proof: the test failed with the wrapper line removed from the runbook. A paste test in WSL bash against a small fake export wrote both files for version 2; for a missing version 3 it stopped with status 1, printed no success line, and the outer shell went on.
- **Item 7, the login signer-call wording (low):** `0e5e44f`, comment and docs only. `signerCallTimeout`'s comment (internal/server/admin.go) and this file's `provides` line now say that the request is sent by CreatedAt + 295 s and the answer is read for up to signerCallTimeout after the send (C-IN-01, round 2).
  - Round 2's item 2 supersedes the round-1 "Skipped" item (the reply read). It also supersedes the plan's must_have wording that puts the deadline on the whole signer call: since `0877449` that deadline bounds only the send.

**Checks run:**
- `gofmt -l` reported nothing.
- `go vet ./...` passed for windows, linux and darwin, and `go vet -tags e2e ./test/e2e/` for windows and linux.
- `go test -tags e2e -run TestRestoreRunbookChecks ./test/e2e/` passed on Windows.
- In WSL: `go test -race -count=1 ./internal/audit/... ./internal/server/... ./internal/signerclient/...` passed, and golangci-lint reported 0 issues for linux, windows and darwin.
- `TestRestoreRunbookChecks` and `TestRestoreReplaysLostDirectory` passed in WSL under the namespace hosts workaround, with OpenSSH 10.5p1.
- The full e2e suite ran there too: 34 passed. `TestSSHDRejects/pty_allowed` failed, as in round 2, in a test no change here touches. CI is the authoritative run.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-25*
