---
phase: 03-linux-agent-and-revocation
plan: 03b
subsystem: revocation
tags: [krl, revocation, cli, second-sweep, krl-parse, sshd-e2e, runbooks]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-03: wire targets key_id, key and subject, RevokeResponse.SerialCount and Serials, krl.Parse with RevokesSerial/RevokesKeyID/RevokesKey, krl.RoleCAKeys, the signer's subject resolution with re-listing, v2 revoke requests bound to the installation ID"
provides:
  - "keyroster revoke key-id, revoke key and revoke user (revoke, disable, second sweep; exit 3 partial, exit 4 disable pending)"
  - "the KRL listing check: every revoke command parses the verified KRL (krl.Parse) and exits non-zero unless it lists every target it revoked; the 03-01 Not checked line is gone"
  - "serverclient.RevokeAnswer serial_count and serials, decoded strictly; keyroster-server copies them and logs the target kind"
  - "editDirectoryOutcome (install versus proposal) for the directory pipeline"
  - "runbooks: revoke.md sections for the three commands; enroll-user.md and host-setup.md say disable stops only new certificates (todo F-IN-01 closed)"
affects: [03-04, 03-05, 03-07, 03-09, 03-11, 03-13, 03-16, phase-4-issuance-barrier]

actuals:
  tokens: 41074
  tasks: 3
  commits: 10
plan_head_before: f3bcc34cb40dbacb7c405fff7ecca807c4159fa3
plan_head_after: 89b237881c1eb68808a87ac4efca3d2033ad321d

tech-stack:
  added: []
  patterns:
    - "Every revoke command goes through one send path: sign the v2 request, post it, confirm the answer against the root-pinned manifest, krl.Parse the same bytes, then a per-target listing check; an absent entry is never reported as revoked"
    - "A command that must not stop half-way checks its preconditions (here --yes or a terminal) before its first irreversible step"

key-files:
  created:
    - .planning/todos/completed/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md
  modified:
    - cmd/keyroster/revoke.go
    - cmd/keyroster/revoke_test.go
    - cmd/keyroster/dirpipe.go
    - cmd/keyroster/dirpipe_test.go
    - internal/server/revoke.go
    - internal/server/revoke_test.go
    - internal/serverclient/admin.go
    - internal/serverclient/admin_test.go
    - internal/serverclient/client.go
    - internal/signer/revoke_test.go
    - internal/wire/wire_test.go
    - test/e2e/revoke_test.go
    - docs/runbooks/revoke.md
    - docs/runbooks/enroll-user.md
    - docs/runbooks/host-setup.md
    - docs/runbooks/signer-install.md
    - .planning/phases/03-linux-agent-and-revocation/03-03-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-03b-PLAN.md

key-decisions:
  - "keyroster revoke user refuses before revoking anything when stdin is not a terminal and --yes is not given: the disable signs a directory version, and a scripted run would otherwise revoke and stop at exit 3"
  - "A user not in the installed directory is treated like one already disabled (one revocation, no directory change, exit 0): no passkey login can issue that name a certificate"
  - "RevokeAnswer decoding applies wire.RevokeResponse's exact rule (exactly min(serial_count, 4096) serials, ascending, unique), stricter than the plan's count-below-the-list rule"
  - "Refusal details are matched by name whatever the HTTP status; unknown_serial names keyroster revoke key-id and keyroster revoke key, with key-id only for key IDs this signer issued (key_id_not_issued since PR #61)"
  - "revoke.md is renumbered so the commands come first (1 serial, 2 key-id, 3 key, 4 user; 5 refusals, 6 KRL, 7 audit, 8 homelab); signer-install.md's anchor follows"

patterns-established:
  - "Stub-server tests that check request order log every admin POST (dirEnv.calls) and answer revocations in sequence (serveRevokes)"

requirements-completed: []

coverage:
  - id: D1
    description: "keyroster revoke user against real sshd: both of alice's certificates refused after the KRL swap, bob's accepted, alice's next login refused user_disabled, each sweep reporting both serials and the CLI confirming them in the KRL, audit verify passing with two revoke entries of the same two serials, each followed by krl_publish"
    requirement: "REVOKE-01"
    verification:
      - kind: e2e
        ref: "CI E2E run 40271914977 (8cafae4), e2e (9.5p1) and e2e (10.5p1): test/e2e/revoke_test.go#TestRevokeUserEndToEnd"
        status: pass
    human_judgment: false
  - id: D2
    description: "keyroster revoke key and revoke key-id against real sshd: the plain key from authorized_keys, a certificate for it and the key ID's certificate refused, a control certificate accepted"
    requirement: "REVOKE-01"
    verification:
      - kind: e2e
        ref: "CI E2E run 40271914977 (8cafae4), both lanes: test/e2e/revoke_test.go#TestRevokeKeyEndToEnd"
        status: pass
      - kind: e2e
        ref: "CI E2E run 40271914977, both lanes: test/e2e/revoke_test.go#TestRevokeSerialEndToEnd (new KRL-check line)"
        status: pass
    human_judgment: false
  - id: D3
    description: "revoke user outcomes against a stub server: request order revoke, install, revoke; exits 3 and 4 with the re-run; already disabled; none found; failed first revocation still disables (exit 1); truncated answer; no terminal refused before revoking"
    verification:
      - kind: unit
        ref: "cmd/keyroster/revoke_test.go#TestRevokeUser"
        status: pass
    human_judgment: false
  - id: D4
    description: "The KRL listing check for serial, key ID, key and the user's reported serials, and a signed KRL that does not parse; bypass mutant killed"
    verification:
      - kind: unit
        ref: "cmd/keyroster/revoke_test.go#TestRevokeKRLCheck"
        status: pass
    human_judgment: false
  - id: D5
    description: "03-03's refusal details in the CLI's words (RED then GREEN)"
    verification:
      - kind: unit
        ref: "cmd/keyroster/revoke_test.go#TestRevokeRefusalText"
        status: pass
    human_judgment: false
  - id: D6
    description: "The answer's serials through keyroster-server and the strict client decode"
    verification:
      - kind: unit
        ref: "internal/server/revoke_test.go#TestRevokeAnswerSerials"
        status: pass
      - kind: unit
        ref: "internal/serverclient/admin_test.go#TestRevokeAnswerDecode"
        status: pass
    human_judgment: false
  - id: D7
    description: "Carry-overs: a v2-layout body with an empty installation ID refused; an already-revoked explicit key re-revoked at the cap"
    verification:
      - kind: unit
        ref: "internal/wire/wire_test.go#TestRevokeRequest/v2_layout_empty_installation_id"
        status: pass
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestRevokeSubject/explicit_key_cap_relist_accepted"
        status: pass
    human_judgment: false
  - id: D8
    description: "Runbooks: revoke.md's three command sections, enroll-user.md and host-setup.md on disable versus revoke"
    verification: []
    human_judgment: true
    rationale: "A runbook's wording needs a human reader; only its greps and the CI-run commands it describes are checked"

duration: 67min
completed: 2026-10-26
status: complete
---

# Phase 3 Plan 03b: Revoke CLI Summary

**`keyroster revoke key-id`, `revoke key` and `revoke user` (revoke, disable, second sweep, with exits 3 and 4) now run against real sshd in CI. Every revoke command, `revoke serial` included, parses the KRL it verified and exits non-zero unless that KRL lists what it revoked. The runbooks now say that disabling a user stops only new certificates.**

## Performance

- **Duration:** about 67 min of executor time (2026-10-26T04:23Z to 05:30Z, CI waits included). PR checks follow.
- **Tasks:** 3 of 4. Task 4 is the merge gate.
- **Files modified:** 19. The plan named 11; the deviations below cover the other 8.
- **PR:** opened from branch `p03/03b-revoke-cli` after this file is pushed. Its number is in the handback; this file carries no merge facts.

## Accomplishments

- **CLI.** Three new subcommands share one send path: v2 request bound to the bundle's installation ID, signature, post, manifest confirmation, `krl.Parse` of the same bytes, then a per-target listing check.
  - `revoke key-id KEY_ID --ca ROLE` revokes the key ID under the role's CA keys.
  - `revoke key FILE` takes an authorized_keys-format file. A certificate file revokes its key, with a note.
  - `revoke user NAME [--yes] [--out DIR]` sends the subject revocation and prints its serials. It then disables NAME through the directory pipeline: installed at admin quorum 1, a proposal above. Once the install is reported, it sends the second subject revocation.
- **Exit codes of `revoke user`:**
  - 3 when revoked but NAME is NOT disabled, or when the second sweep failed;
  - 4 when the disable is only a proposal;
  - 1 when the first revocation failed: the disable still runs, and nothing is reported revoked;
  - 0 when NAME was already disabled or is not in the directory. Only one sweep runs then.
  - Each partial outcome names `keyroster revoke user NAME` as the way to finish.
- **KRL listing check.** It replaces 03-01's `Not checked:` line. An absent entry is refused with both causes named (not effective, or pruned). A KRL that is signed but does not parse is also refused.
- **Server and client.**
  - `RevokeAnswer` carries `serial_count` and `serials`. The client refuses any list the signer would not send.
  - keyroster-server copies both fields. Its log lines carry `target`, and the serial only for a serial target.
- **Refusal advice:**
  - `unknown_serial` now names `revoke key-id` and `revoke key`, not "a later version";
  - new advice for `key_id_not_issued`, `explicit_key_cap_reached`, `key_is_ca_of_this_installation` (the emergency CA rotation, 03-13), `subject_kind_unsupported`, `revoke_installation_missing` and `revoke_installation_mismatch`.
- **Runbooks.**
  - revoke.md has a section per command, the user command's exit table and the second sweep's two revoke entries. It also covers `ssh-keygen -Q -l`, the audit counts and the new refusals.
  - enroll-user.md and host-setup.md say that disable, role revoke, group member removal and unmap stop only new certificates, and name `keyroster revoke user`. The F-IN-01 todo is closed.
- **Carry-overs from the PR #61 fix check:**
  - (a) the wire test for an empty installation ID in a v2 layout;
  - (b) 03-03-PLAN's key-ID rule after a16c6db;
  - (c) the signer test for re-revoking at the explicit-key cap;
  - (d) the 03-03b ledger row now records the owner's acceptance.

## Task Commits

1. **Task 1 (tracer): revoke by key ID, key and user from the CLI, with a KRL listing check.** `e2f45eb` (feat). Follow-up `8cafae4` (fix): the e2e controls run before the refusals.
2. **Task 2: CLI outcomes and refusals, each a named test.** `8d04702` (test, RED) and `9b4f834` (feat, GREEN). Follow-up `89b2378` (fix): the test certificate is built with `cert.Build`.
3. **Task 3: runbooks and todo.** `41a57ba` (docs).
4. **Carry-overs:**
   - (a) `77c353c` (test)
   - (c) `d6a246e` (test)
   - (b) `032ef7e` (docs)
   - (d) `8c9b672` (docs)

**Plan metadata:** the `docs(03-03b): complete revoke-cli plan` commit that carries this file, STATE.md and ROADMAP.md.

## Tracer gate (Task 1)

- **Unit verify.** Passed in WSL with `-race` for `./internal/server/... ./internal/serverclient/... ./cmd/keyroster/...`.
- **First E2E run** (`workflow_dispatch` on `e2f45eb`): **run 40271389420**.
  - `e2e (9.5p1)` passed.
  - `e2e (10.5p1)` failed `TestRevokeKeyEndToEnd`. Every revocation had worked (sshd logged `revoked by file` for the plain key and both certificates). The control login after three failed authentications hit OpenSSH 10.x's `PerSourcePenalties` (`kex_exchange_identification: Connection reset by peer`).
- **Fix** (`8cafae4`): the control and bob's login now run right after the swap.
- **Second E2E run:** **run 40271914977** on `8cafae4`. Both lanes passed, and each job's log has `--- PASS` for `TestRevokeUserEndToEnd`, `TestRevokeKeyEndToEnd` and `TestRevokeSerialEndToEnd` and no `--- FAIL`. Task 2 started only after that.

## Mutant results

Each mutant was applied, run and reverted, and `git diff` of the file was empty afterwards.

- **The listing check bypassed** (`send` skips `listed`). Killed by five `TestRevokeKRLCheck` cases: `revoke_krl_lacks_serial`, `revoke_krl_lacks_serial_under_role`, `revoke_krl_lacks_key_id`, `revoke_krl_lacks_key` and `revoke_user_krl_lacks_reported_serial`. This is the plan's bypass mutant (owner decision 2026-10-25, PR #58 review).
- **The second revocation never sent** (return before step 3). Killed by `TestRevokeUser/revoke_user_login_between_revoke_and_disable`.
- **Carry-over (a): ParseRevokeRequest without its empty-ID refusal.** Killed by `TestRevokeRequest/v2_layout_empty_installation_id` ("ParseRevokeRequest: <nil>, want ErrMalformed"). The older `v1_body_refused` case does not catch it.
- **Carry-over (c): CheckExplicitKeys counting duplicates.** Killed by `TestRevokeSubject/explicit_key_cap_relist_accepted` ("revoke refused: explicit_key_cap_reached").

## TDD Gate Compliance

- **RED.** Task 2 is `tdd="true"`. RED commit `8d04702` holds the new tests.
  - Run before GREEN, exactly the seven refusal-mapping cases of `TestRevokeRefusalText` failed, each on the planned text: `unknown_serial` (it still said "arrives in a later version"), `key_id_not_issued`, `explicit_key_cap_reached`, `key_is_ca_of_this_installation`, `subject_kind_unsupported`, `revoke_installation_missing` and `revoke_installation_mismatch`.
  - The other 37 subtests passed. The evidence file was in the scratchpad.
  - Semantic assessment: the target cases ran and failed on their own assertions. There was no build, setup or fixture failure.
- **GREEN.** Commit `9b4f834`; every case passes.
- **Exception.** The `TestRevokeUser` and `TestRevokeKRLCheck` cases test code that Task 1, the tracer, already wrote, so they did not fail first. The mutants above show they check the behaviour they name.
- **Classifier not used.** `gsd-tools check tdd-red-evidence` reads none of Go's test output formats, and `workflow.tdd_mode` is off. This is the same as in 03-03.

## What ran and what did not

**Ran (2026-10-26):**

- **CI E2E run 40271914977**, OpenSSH 9.5p1 and 10.5p1: `TestRevokeUserEndToEnd`, `TestRevokeKeyEndToEnd`, `TestRevokeSerialEndToEnd` and the rest of the e2e suite.
- **WSL gates (Ubuntu, Go 1.27.1):**
  - `go test -race -count=1 ./...`
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/`
  - gofmt
  - golangci-lint for linux, windows and darwin: 0 issues
  - `scripts/capslock-check.sh`: 91 pairs against a baseline of 91
  - `scripts/dep-firewall.sh`: OK
  - go.mod unchanged, no new module
- **Windows unit tests** of the touched packages.
- **`ssh-keygen -Q -l`** run locally with OpenSSH 10.5p1 on `test/vectors/krl_full_v1.hex` (a KRL our encoder wrote). It lists both CA sections, the serials 5-6 and 9, both key IDs and the explicit key.

**Not run here (UNVERIFIED):**

- **Exits 1, 3 and 4 against a real server and signer.** Only the stub server runs them (`TestRevokeUser`); TestRevokeUserEndToEnd covers exit 0 at quorum 1.
- **Every homelab step.** UNVERIFIED until 03-16; revocation there is refused until the v4 bundle (03-15).
- **A KRL installed on a host by hand.** No runbook step or command does it, and revoke.md now says so.
- **A revoked host key or host certificate refused by SSH clients.**
- **Other lanes.** The required checks on the final head, including the e2e_pkcs11 and e2e_tpm lanes, run on the PR, so their result is in the merge-gate return.

## Decisions Made

See `key-decisions` in the frontmatter. The two that go beyond the plan:

- **The early refusal when stdin is not a terminal.** Without `--yes`, a scripted `revoke user` would revoke and then stop at exit 3.
- **A user not in the directory counts as already disabled.** The signer issues no login certificate to a name that is not in the directory, so this run needs no disable and no second sweep.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] The e2e controls were penalised by OpenSSH 10.x**
- **Found during:** Task 1, tracer verify (CI run 40271389420).
- **Issue:** sshd's `PerSourcePenalties` (authfail 5 s, applied from 15 s) refused `TestRevokeKeyEndToEnd`'s control login from 127.0.0.1 after the third failed authentication. OpenSSH 9.5p1 has no such feature.
- **Fix:** `TestRevokeKeyEndToEnd`'s control and `TestRevokeUserEndToEnd`'s bob now log in right after the KRL swap, before the refusals.
- **Verification:** run 40271914977, both lanes.
- **Committed in:** `8cafae4`.

**2. [Rule 2 - Missing critical] `revoke user` refuses before revoking without consent to sign**
- **Found during:** Task 1.
- **Issue:** The disable signs a directory version, and `confirmSign` refuses when there is no terminal and no `--yes`. A scripted run would therefore revoke and then stop at exit 3.
- **Fix:** The command refuses up front ("Nothing was revoked"). It also passes `--yes` and `--out` through to the disable.
- **Verification:** `TestRevokeUser/revoke_user_not_a_terminal_refused_before_revoking`.
- **Committed in:** `e2f45eb`.

**3. [Rule 3 - Blocking] Files outside the plan's list**
- **cmd/keyroster/dirpipe.go:** `editDirectoryOutcome`, because `editDirectory` returned nil both for an install and for a proposal.
- **cmd/keyroster/dirpipe_test.go:** the stub server's ordered POST log.
- **internal/serverclient/client.go:** `decodeError` keeps the CLI's own refusal of the serials instead of wrapping it as peer text.
- **docs/runbooks/signer-install.md:** its link to revoke.md's audit section follows the renumbering.
- **Committed in:** `e2f45eb`, `8d04702` and `41a57ba`.

**4. [Rule 3 - Blocking] The test certificate was built with SignCert**
- **Issue:** forbidigo allows `SignCert` only in `internal/cert.Build`.
- **Fix:** `revoke_key_of_certificate_file` builds its certificate with `cert.Build`.
- **Committed in:** `89b2378`.

**5. [Orchestrator] Requests are v2, and the new refusals have advice**
- Every revoke command names the installation of the root-pinned bundle.
- `key_id_not_issued`, `explicit_key_cap_reached`, `revoke_installation_missing` and `revoke_installation_mismatch` are mapped to CLI advice next to the plan's three details.
- Because `key_id_not_issued` exists since PR #61, the `unknown_serial` advice offers `revoke key-id` and points a certificate this signer did not issue to `revoke key`.

**6. [Orchestrator] The carry-overs (a) to (d), one commit each**
- (b) also corrects the same stale "or 0" in 03-03-PLAN's audit paragraph (Task 1 action), not only the must_haves line.
- (d) also removes two stray markup lines (`</content>`, `</invoke>`) inside that ledger table.

**7. [Plan detail] Stricter or extra than written**
- **Client decode.** It refuses any list whose length is not exactly min(serial_count, 4096). That is the wire rule, stricter than "a count below the list".
- **A user not in the directory** is handled like an already disabled one.
- **Extra named cases:**
  - in `TestRevokeKRLCheck`: `revoke_krl_lacks_serial_under_role`, `revoke_key_id_listed`, `revoke_key_listed` and `revoke_key_of_certificate_file`;
  - in `TestRevokeUser`: `revoke_user_not_a_terminal_refused_before_revoking`;
  - in `TestRevokeAnswerSerials`: `refusal_names_target`.
- **Test timing.** `TestRevokeAnswerSerials` and `TestRevokeAnswerDecode` are in the Task 1 commit, where the plan's Task 1 action puts the server and client tests.
- **revoke.md order.** The sections are renumbered so that the commands come first. 03-03's "sections 3 and 4" are now 6 and 7.

**8. [Plan detail] The todo's resolution names the branch, not "PR #N"**
- **Why:** The SUMMARY must be pushed before the PR opens. The 03-02 todo set the precedent ("Resolved in 03-02 (PR from branch ...)").
- **Where the number is:** in the handback.

---

**Total deviations:** 8. Of these, 1 is Rule 1, 1 Rule 2, 2 Rule 3, 2 orchestrator-directed and 2 plan details.
**Impact on plan:** No scope creep and no new module. The extra files hold one helper each, or a one-line link fix.

## Issues Encountered

- **Shell quoting.** The Bash tool halves backslashes in heredocs (`\\n` arrived as a newline), which broke two Go string literals. They were fixed with the Edit tool before any commit, and later edits went through files written with the Write tool.
- **A stuck gate run.** A stray `cat` reading stdin hung the first gate run for 10 minutes. It ran nothing and changed nothing.

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat model. `revoke key FILE` reads a local file named by the admin, bounded to 64 KiB, and parses one authorized_keys line. No new endpoint, route or stored field.

## User Setup Required

None.

## Next Phase Readiness

- **03-04** can start once this merges.
- **03-05 and 03-07** can rely on `revoke user` and `revoke key` producing the KRL entries that agents distribute.
- **Hand-set hosts** stay without an enforced KRL until the agent (03-07); the runbooks say so.
- **Open until Phase 4** (T-03-19): the quorum-above-1 window and a server reporting an install early. Todos: `2026-10-25-signer-issuance-barrier-after-subject-revoke.md` and `2026-10-21-cli-verifies-directory-install-receipts.md`.

## Self-Check: PASSED

- **Files.** Every key-files entry exists, and the pending todo is gone (`test ! -e`).
- **Commits.** The 10 commits from `e2f45eb` to `89b2378` are ancestors of HEAD, and `git rev-list --count f3bcc34..HEAD` is 10.
- **Task 1 acceptance:**
  - `grep -c 'Serials' internal/serverclient/admin.go` and `grep -c '"target"' internal/server/revoke.go` are both at least 1;
  - the comment-stripped `krl.Parse(` count in cmd/keyroster/revoke.go is 1;
  - TestRevokeUserEndToEnd's CI log shows two refusals for alice and bob accepted after the swap;
  - the e2e evidence is run 40271914977.
- **Task 2 acceptance:**
  - `this version cannot read a KRL` and `arrives in a later version` each count 0 in cmd/keyroster/revoke.go;
  - every named PASS line of the plan's verify is present;
  - the bypass mutant is recorded above.
- **Task 3 acceptance:**
  - the awk section check prints 3;
  - the squashed greps for `arrives with 03-03`, `which 03-03 adds` and `this version cannot read a KRL` each print 0;
  - `exit 3` and `exit 4` each appear at least once;
  - both runbooks grep `keyroster revoke user`;
  - the todo is in completed/.

## Pre-merge review fixes

PR #64 review (Claude lenses plus Codex; each finding upheld by two skeptics):

1. **`7dec8fb`** (low): `revoke user` now runs the second sweep, with the KRL check, when the served directory already shows the user disabled or absent; a failure there exits 3. Test: `TestRevokeUser/revoke_user_already_disabled` (a login between the first sweep and another admin's installed disable gets serial 7, and the second sweep revokes and checks it), plus `revoke_user_not_in_directory` and `revoke_user_not_in_directory_second_sweep_not_listed`. Proof: with revoke.go reverted, all three fail (one revoke request, no serial 7, exit 0 instead of 3); restored, they pass. A failed first sweep still exits 1 without a second sweep, by design: the re-run it names sweeps again, and a sweep there would make "nothing is reported revoked" false.
2. **`ee3422c`** (split, low): the already-disabled or absent output and the revoke.md exit-0 row say it is the server's word: the version the server serves, admin-signed but possibly older than the signer's, or none at all. The closing and exit-3 lines say "(the server's word)" too. Proof: the same subtests assert the caveat; with revoke.go reverted they fail, and restored they pass.
3. **`7866363`** (low/medium, docs-only): host-setup.md and enroll-user.md now say the host-setup drop-in sets no `RevokedKeys`. So in this version a hand-set host enforces no revocation unless the operator adds `RevokedKeys` and installs the KRL by hand (UNVERIFIED); otherwise `revoke user` stops only new certificates there.
4. **`659f58f`** (low, docs-only): the revoke.md exit-1 row lists each directory outcome the CLI names: disabled, already disabled or absent (re-run); a proposal at admin quorum above 1 or with `--out DIR` (sign, install, then re-run); the directory step failed (`user disable`, then `revoke user`). The exit-4 row also names `--out DIR`.

Gates:

- `gofmt -l` is empty.
- `go vet ./...` passes for windows, linux and darwin, and `GOOS=linux go vet -tags e2e ./test/e2e/` passes.
- `go test ./cmd/keyroster/...` passes on Windows.
- In WSL, `go test -race` passes on cmd/keyroster, internal/server and internal/serverclient, and golangci-lint for linux, windows and darwin reports 0 issues.
- e2e is CI's.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-26*
