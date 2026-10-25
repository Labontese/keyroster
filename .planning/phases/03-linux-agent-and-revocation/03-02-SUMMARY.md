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
  - the login redeem reads the clock again after currentStatus and bounds the signer call at CreatedAt + 295 s (C-IN-01)
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
    requirement: "AUTH-03"
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
    requirement: "AUTH-03"
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
        ref: "internal/audit/export_test.go#TestDecode/directory_install"
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

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-25*
