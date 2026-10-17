---
phase: 02-passkey-login-mvp
plan: 03
subsystem: signer
tags: [signer, webauthn, directory, wire, framing, fuzz, refusal-matrix, concurrency, key-02, sc4]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-01: LoginIssue, InstallDirectory, loadDirectory, the webauthn verifier and soft authenticator, tlog kinds 7 and 8, and the 02-01 post-merge fixes (#35)"
provides:
  - "wire: TypeGetDirectory (0x03) -> TypeGetDirectoryResponse (0x83), GetDirectoryResponse and ParseGetDirectoryResponse (version 0 has one encoding only)"
  - "Signer.GetDirectory and signerclient.GetDirectory: version, canonical bytes, signatures and the authorized flag, as the signer holds them"
  - "Per-type frame caps: MaxDirectoryFrame for InstallDirectory and GetDirectoryResponse, MaxFrame for every other type, ErrShortFrame, unexported maxBodyFor and headerLen"
  - "The start-up cross-check: the signer refuses to start when the latest stored directory is not the one the last directory_install leaf records (T-02-14: the directory table rolled back or substituted alone; the log and tables rolled back together, or an older signer.db restored, is the C-WR-01 residual owned by Phase 4)"
  - "TestLoginRefusals (SC4 through the real socket, six cases with controls) and the unit refusal matrix, restart, log-consistency and concurrency suites"
  - "10 new fuzz targets (FuzzReadMessage replaces FuzzReadFrame); scripts/fuzz.sh runs 19, up from 10"
affects: [02-04, 02-05, 02-06, 02-08, 02-13, KEY-02]

actuals:
  tokens: 29100   # chars/4 over the added lines of the code and test diff (116285 chars); planning docs excluded
  tasks: 3        # Tasks 1-3; Task 4 is the owner merge gate
  commits: 6      # git rev-list --count plan_head_before..HEAD at SUMMARY write; the docs commit follows
plan_head_before: fe755c60ea9aaf5309f0e994ebde0017bd42e341
plan_head_after: c984266e16631bf348c1c71f49f1c1ce1d5c105a

tech-stack:
  added: []
  patterns:
    - "A frame cap limits the frame length, which counts the 2 header bytes; ReadMessage reads 4 bytes, then 2, and checks the type's cap before allocating the body"
    - "Every stored table the signer trusts at start is cross-checked against the last log leaf that wrote it (bundle_install since 01-17, directory_install now)"
    - "Unit refusal cases go through the dispatch helpers (loginOrRefuse, installDirectoryOrRefuse), each on a fresh signer, and assert detail, class, digest and a control"

key-files:
  created:
    - test/e2e/login_refusal_test.go
    - internal/signer/directory_test.go
    - internal/signer/directory_socket_test.go
    - internal/webauthn/fuzz_test.go
    - internal/directory/fuzz_test.go
    - internal/cert/fuzz_test.go
  modified:
    - internal/wire/frame.go
    - internal/wire/directory.go
    - internal/wire/wire_test.go
    - internal/wire/fuzz_test.go
    - internal/signer/directory.go
    - internal/signer/logstate.go
    - internal/signer/server.go
    - internal/signer/signer.go
    - internal/signer/login_test.go
    - internal/signerclient/client.go
    - internal/webauthn/verify_test.go
    - internal/tlog/fuzz_test.go
    - internal/tlog/leaf_test.go
    - internal/cert/keyid_test.go
    - test/e2e/login_signer_test.go

key-decisions:
  - "ReadFrame and WriteFrame are removed, not unexported: after the per-type rework nothing in production calls them, and an unexported copy would be dead code kept only for tests"
  - "The start-up directory cross-check compares version, policy version, document and signatures with the last directory_install leaf and wraps errLogMismatch; no row and no leaf is the fresh state"
  - "credential_mismatch and unsupported_algorithm cannot be reached through LoginIssue (the credential is looked up by the assertion's own ID; a directory binding another algorithm does not validate); their mapping is unit-tested in TestLoginRefusalClasses and no test hook was added"
  - "A GetDirectory request must have an empty body; any body is refused malformed_request"
  - "requirements-completed is empty: KEY-02 completes in 02-04"

patterns-established:
  - "A bite test proves that a refusal suite depends on the check it guards: discard the check, see the suite fail, restore with git diff --exit-code"

requirements-completed: []

coverage:
  - id: D1
    description: "SC4 through the real socket: missing assertion, replayed request, wrong digest, a directory not signed by the admin quorum, a policy without an RP and admin evidence on a login request are each refused with their detail, each with a succeeding control. The exported-log check covers the RP signer only: its log records the four refusals made on it (missing_assertion, replayed_request, wrong_digest, wrong_evidence_type) with their request digests and, since the pre-merge review, no login_issue entry for them beyond the controls' certificates; the two cases on their own signers (directory_not_quorum_signed, policy_without_rp) are checked through the socket only"
    requirement: KEY-02
    verification:
      - kind: e2e
        ref: "test/e2e/login_refusal_test.go#TestLoginRefusals (local WSL, sshd 10.5p1, 6/6 subtests; full e2e suite 18/18 top-level tests)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every LoginIssue refusal detail of 02-01 (except the two unreachable ones, mapped in TestLoginRefusalClasses) has a named unit case with real soft assertions, a refusal leaf with the exact detail, class and digest, and a control login"
    requirement: KEY-02
    verification:
      - kind: unit
        ref: "internal/signer/login_test.go#TestLoginRefusalMatrix, TestLoginRefusalLeaves, TestLoginRefusalClasses, TestEvidenceMix (go test -race, WSL)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Policy clause: an RP policy in a successor bundle not signed by the previous root is refused at install (trust.ErrThreshold), logins stay refused no_webauthn_policy before and after a restart; the root-signed successor installs and the same login issues after a restart"
    requirement: KEY-02
    verification:
      - kind: unit
        ref: "internal/signer/login_test.go#TestLoginPolicyClause/policy_not_root_signed"
        status: pass
    human_judgment: false
  - id: D4
    description: "Concurrency: 16 identical login requests give one certificate and 15 logged duplicate_request refusals; two successors of v1 install exactly once; a directory row written before commit refuses directory_changed through the dispatch path with nothing issued (no issuance row, serial or login_issue leaf) and the refusal logged with its digest"
    requirement: KEY-02
    verification:
      - kind: unit
        ref: "internal/signer/login_test.go#TestLoginConcurrency; internal/signer/directory_test.go#TestDirectoryConcurrent (go test -race, WSL)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Restart under a successor policy with new admins: the signer starts, logins are refused directory_not_authorized, the admin path still issues, a directory signed by the new admin restores logins; GetDirectory reports version 1/1/2 and authorized true/false/true with the exact bytes"
    verification:
      - kind: unit
        ref: "internal/signer/directory_test.go#TestDirectoryRestart/restart_under_new_admins"
        status: pass
    human_judgment: false
  - id: D6
    description: "Start-up cross-check (T-02-14, the directory table alone): a stored directory row overwritten, with replaced signatures or policy version, the newest row deleted, the table wiped, or a row without a log entry stops the signer; the fresh state starts. Not covered: the log rolled back with the table to an earlier signed prefix, or an older signer.db restored (C-WR-01 residual, Phase 4)"
    verification:
      - kind: unit
        ref: "internal/signer/directory_test.go#TestDirectoryLogConsistency (RED before the change, GREEN after)"
        status: pass
    human_judgment: false
  - id: D7
    description: "Install refusals: directory_invalid, directory_version_chain, directory_quorum_not_met, directory_exceeds_policy and trust_changed store nothing and write no directory_install leaf, each with a control install"
    verification:
      - kind: unit
        ref: "internal/signer/directory_test.go#TestDirectoryInstallRefusals, TestDirectoryRefusalLeaves"
        status: pass
    human_judgment: false
  - id: D8
    description: "Per-type frame caps in both directions at exactly each cap and cap + 1, the length-1 frame that must not consume the next frame, and a directory above 64 KiB installed and read back through the socket"
    verification:
      - kind: unit
        ref: "internal/wire/wire_test.go#TestReadMessageCaps, TestWriteMessageCaps, TestReadFrame, TestParseGetDirectoryResponse; internal/signer/directory_socket_test.go#TestDirectoryOverSocket; internal/tlog/leaf_test.go#TestDirectoryLimitsMatchWire"
        status: pass
    human_judgment: false
  - id: D9
    description: "The webauthn verifier refuses every mutation with its own sentinel for EdDSA, ES256 and RS256, accepts clientDataJSON with extra members, and refuses P-384 for ES256 and RSA-1024 for RS256"
    requirement: KEY-02
    verification:
      - kind: unit
        ref: "internal/webauthn/verify_test.go#TestWebAuthnMutationMatrix, TestWebAuthnClientDataExtraMembers, TestWebAuthnParsePublicKeyRefusals"
        status: pass
    human_judgment: false
  - id: D10
    description: "Every new parser is fuzzed: 10 new targets (one replaces FuzzReadFrame), 19 in all, each 10 s locally"
    verification:
      - kind: other
        ref: "FUZZTIME=10s bash scripts/fuzz.sh (WSL): fuzz: all 19 targets passed (10s each)"
        status: pass
    human_judgment: false

duration: 40min
completed: 2026-10-17
status: complete
---

# Phase 2 Plan 03: Signer Boundary Summary

**The signer now refuses every unauthorized login path, through the real socket and in a named unit matrix, with a succeeding control for each. It refuses to start on a directory table the log does not record. GetDirectory lets the server mirror exactly what the signer holds, frames are capped per message type before allocation, and every new parser is fuzzed.**

## Performance

- **Duration:** about 40 min
- **Started:** 2026-10-17T04:18:05Z
- **Completed:** 2026-10-17T04:57Z (SUMMARY write)
- **Tasks:** 3 of 4 (Task 4 is the owner merge gate)
- **Files modified:** 21 code and test files, plus planning docs

## Delivery

- **Branch:** `p02/03-signer-boundary`, cut from origin/main `a641cc1`. It also carries the orchestrator's `fe755c6 docs(phase-02): mark 02-02 complete in roadmap`.
- **PR:** #38, opened by keyroster-bot at 2026-10-17T05:03:45Z with the title `test(signer): refuse every unauthorized login path and fuzz the new parsers`, after the single push that carried this SUMMARY (see Deviation 7). At head `ae57f1a` all 20 checks passed (read from GitHub before the review fixes): Analyze (actions), Analyze (go), CodeQL, build-piv, build-test, capslock, cli-macos, cli-windows, dependency-firewall, e2e (10.5p1), e2e (9.5p1), e2e-pkcs11 (10.5p1-ed25519), e2e-pkcs11 (distro-p256), e2e-tpm, fuzz, govulncheck, lint, pinned-actions, pr-title, systemd-sandbox. The pre-merge review fixes below change the head; the checks on the new head and the merge itself are reported in the merge-gate checkpoint, not committed (Delivery Protocol step 4).
- **Commits:** signed by keyroster-bot (each carries an SSH signature; GitHub verifies them, locally `%G?` shows N because no allowedSignersFile is configured).

## Accomplishments

- **GetDirectory (Task 1).**
  - The request is 0x03 with an empty body (any body is refused `malformed_request`). The response is 0x83: u64 version, u24-prefixed directory, u24-prefixed signatures and a u8 0/1.
  - Version 0 has exactly one encoding: no bytes, no signatures, not authorized.
  - A stored directory that no longer verifies is reported with its bytes and `Authorized=false`.
  - `Signer.GetDirectory` runs under `s.mu`. `directoryState` now keeps the installed signatures (`directorySigs`), from `loadDirectory` and after an install's COMMIT.
- **SC4 through the socket (Task 1).** `TestLoginRefusals` covers six cases, and each asserts the refusal detail. (Its "no certificate came back" check was vacuous, since `signerclient.Login` never returns a response with an error; since the pre-merge review the RP signer's exported log must hold no login_issue entry for a refused request beyond the controls' certificates.)
  - `missing_assertion` gives `missing_evidence`. Control: the same request approved, with a fresh request id.
  - `replayed_request`: the identical bytes are sent twice and the second is refused `duplicate_request`.
  - `wrong_digest`: only the request id changes after approval, giving exactly `challenge_mismatch`. Control: an assertion over the changed request.
  - `directory_not_quorum_signed`, on its own signer: an install signed only by a non-admin is refused `directory_quorum_not_met`. GetDirectory then reports version 0, empty, empty and false, and a login is refused `directory_not_installed`. Control: the admin-signed install, after which GetDirectory reports version 1, the exact sent bytes and signatures, and true; the login then issues.
  - `policy_without_rp`: a signer without an RP accepts the directory and refuses the login `no_webauthn_policy`.
  - `wrong_evidence_type`: admin SSHSIG evidence on a login request is refused `unknown_evidence_type`. Control: `keyroster ca issue` by the same admin.
  - The RP signer's export-log records every request refused on it with its digest and detail as an individual refusal leaf. The two cases on their own signers are not checked in an exported log.
- **Named unit matrix (Task 2).** `TestLoginRefusalMatrix` has 38 table cases and 3 state cases (41 subtests). Each runs on a fresh signer through `loginOrRefuse` with real soft-authenticator assertions and an admin-signed directory. Each asserts the detail, a class other than internal, exactly one new refusal leaf carrying `req.Digest()`, nothing issued, and then a control login on the same signer. The table cases cover:
  - the evidence checks;
  - user and credential: unknown, disabled, role not granted, another user's credential;
  - authenticator data: 36 bytes, 38 bytes, AT set, ED set, RP, UP, UV;
  - client data: duplicate type, invalid UTF-8, crossOrigin `"false"`, trailing data, `webauthn.create`, challenge, origin (http scheme, other host, extra port), crossOrigin true, topOrigin;
  - a flipped signature bit for EdDSA, ES256 and RS256;
  - principals: subset, superset, unsorted;
  - role TTL + 1 s and an extension not granted;
  - ±301 s skew (on a whole-second tick clock, so the boundary is exact);
  - `duplicate_request` after a login and after an admin issuance with the same id.
- **Policy clause, evidence mixing, concurrency (Task 2).** See coverage D3 and D4, plus `TestEvidenceMix` (webauthn evidence on an admin IssueRequest, and admin evidence on a login request, are both refused `unknown_evidence_type`, each with a control).
- **Restart and log consistency (Task 2).** See D5 and D6. `loadDirectory` now calls `checkDirectoryLogged` against `loggedInstalls.lastDirectory`, which `rebuildLogFrom` records for every `directory_install` leaf. This is the only production behaviour change in Task 2. Re-verification under the policy in force and installing a successor while unauthorized already worked since 02-01; they are now tested. **Correction (pre-merge review):** the error log naming the policy version was not asserted by any test at SUMMARY time (every test logger discarded its output), and the CheckPolicy branch of the re-verification had no test; both are tested since the review fixes (`deb1069`, `1b13c8c`).
- **Frame caps (Task 3).**
  - `MaxDirectoryFrame = MaxDirectory + 64 KiB + 64` (1,114,176 bytes) applies to InstallDirectory and GetDirectoryResponse. `MaxFrame` (64 KiB) applies to every other type, unknown types included.
  - `ReadMessage` reads the 4-byte length and refuses 0 (`ErrEmptyFrame`) and 1 (`ErrShortFrame`) before reading on. It then reads the 2 header bytes, checks the version, and checks `uint64(n) - 2` against `maxBodyFor` before allocating.
  - `WriteMessage` refuses before writing any byte, and writes in one `Write`.
  - Issue and login frames keep the Phase 1 limit byte for byte.
  - **New memory bound:** 32 connections × MaxDirectoryFrame ≈ 34 MiB bounds the request frame buffers only, not the signer's memory: a GetDirectory reply makes three to four short-lived copies of the directory (the pre-merge review measured about 34 MiB in steady state with 32 connections). Documented on `maxConns` (T-02-12). Since the review, the signer reads only InstallDirectory at MaxDirectoryFrame and every other type at MaxFrame.

### Refusal details and their class

| Class | Details |
|---|---|
| unauthorized | missing_evidence, too_many_evidence, unknown_evidence_type, bad_evidence, no_webauthn_policy, directory_not_installed, directory_not_authorized, unknown_user, user_disabled, role_not_granted, unknown_credential, credential_mismatch, bad_authenticator_data, rp_mismatch, user_presence_missing, user_verification_missing, bad_client_data, type_mismatch, challenge_mismatch, origin_mismatch, cross_origin_refused, assertion_signature_invalid, unsupported_algorithm, directory_version_chain, directory_quorum_not_met, directory_exceeds_policy |
| bad_principal | principals_mismatch |
| ttl_exceeded | ttl_exceeds_role |
| extension_not_allowed | extension_not_allowed |
| stale_request | request_time_skew |
| duplicate_request | duplicate_request |
| malformed | directory_invalid, malformed_request (GetDirectory with a body), malformed_frame (a frame above its cap) |
| unavailable | directory_changed, trust_changed |

`TestLoginRefusalClasses` asserts that none of these is internal.

### Fuzz targets

- **New:** FuzzReadMessage (replaces FuzzReadFrame), FuzzParseLoginIssueRequest, FuzzParseWebAuthnAssertion, FuzzParseInstallDirectory and FuzzParseGetDirectoryResponse (internal/wire); FuzzParseClientData and FuzzVerifyAssertion (internal/webauthn); FuzzParseDirectory (internal/directory); FuzzDecodeDirectoryInstallBody and FuzzDecodeLoginIssueBody (internal/tlog).
- **Moved:** FuzzParseKeyID, from internal/cert/keyid_test.go to the new internal/cert/fuzz_test.go, with kr2 seeds added.
- **Unchanged:** FuzzDecodeLeaf keeps its `case KindDirectoryInstall` and `case KindLoginIssue` (the grep count is 2).
- **Run:** `FUZZTIME=10s bash scripts/fuzz.sh` in WSL ended with `fuzz: all 19 targets passed (10s each)`, against 10 targets before this plan (10 new names, one of which replaces FuzzReadFrame).
- **Seeds:** FuzzReadMessage's seeds include a length-1 frame followed by a valid frame, a length-2 frame, and frames at exactly MaxFrame and MaxDirectoryFrame. FuzzParseClientData's seeds include the extra-members JSON (`webauthn.ClientDataExtraMembers`, shared with the accept test).

## Where the three 02-01 review findings this plan owns are covered

1. **The start-up cross-check (T-02-14)** is in `internal/signer/directory_test.go#TestDirectoryLogConsistency`. Each case first restarts once as a control. It covers the directory table rolled back or substituted **alone**, with the log left as it is. The log and its tables rolled back together to an earlier signed prefix, or an older signer.db restored, reinstate the older directory (and trust bundle) without any local check noticing: that is the C-WR-01 residual, owned by Phase 4 (owner decision 2026-10-17: serve will refuse to start without a witnessed checkpoint at least as new as the local one; `.planning/todos/pending/2026-10-17-serve-refuses-without-witnessed-checkpoint.md`).
   - The newest row deleted, leaving an older validly signed directory: `newest_row_deleted`.
   - The row overwritten at the same version: `stored_directory_tampered`, with another validly admin-signed v1; also `signatures_replaced` and `policy_version_replaced`.
   - The whole table wiped while the log holds a directory_install leaf: `table_wiped`.
   - Also a row with no leaf: `unlogged_row`.
   - No row and no leaf, the legitimate fresh state, starts: `fresh_state_starts`.
   - These five cases failed before the change (RED, see the TDD record) and pass after it.
2. **Removing the WebAuthn check from LoginIssue fails the tests.** The refusal tests are `TestLoginRefusalMatrix` (unit) and `TestLoginRefusals` (e2e: `missing_assertion`, `wrong_digest`, `replayed_request`, ...). Bite test: with the `VerifyAssertion` result in `verifyLoginEvidence` discarded (`err =` changed to `_ =`), 21 cases of `TestLoginRefusalMatrix` failed (every authenticator-data, client-data, origin, cross-origin, challenge and signature case) and the e2e `TestLoginRefusals/wrong_digest` failed with "a certificate came back". After `git checkout -- internal/signer/login.go`, `git diff --exit-code` was clean.
3. **authenticatorData "exactly 37 bytes, AT and ED clear"** is covered at two levels:
   - the verifier matrix `internal/webauthn/verify_test.go#TestWebAuthnMutationMatrix` (`auth_data_36_bytes`, `auth_data_38_bytes`, `at_flag_set`, `ed_flag_set`, for EdDSA, ES256 and RS256);
   - the signer matrix `bad_authenticator_data/{36_bytes,38_bytes,at_set,ed_set}`.

## Task Commits

1. **Task 1: SC4 through the real socket, GetDirectory.** `6b1fcae` (test). Tracer gate: the verify was re-run after the commit and passed (6/6 subtests, no checkpoint, per `end-of-phase` with an automated-only verify).
2. **Task 2: refusal matrix, restart, log consistency, concurrency.**
   - `2546e34` (test, RED)
   - `1f398f8` (feat, GREEN)
   - `c0d449d` (test: the GetDirectory body rule and the policy_version tamper case, added before the SUMMARY under the no-unexercised-paths rule)
   - `c984266` (test: `directory_changed_before_commit` runs through `loginOrRefuse` and asserts the refusal leaf, so this detail too is shown to be logged)
3. **Task 3: frame caps, fuzz targets.** `af267dc` (feat).
4. **Task 4: merge gate.** Not attempted. It is the owner's `checkpoint:human-action`.

**Plan metadata:** the docs commit `docs(02-03): complete signer-boundary plan` (this file, STATE.md, deferred-items.md).

## TDD record (Task 2, tdd="true"; workflow.tdd_mode is false, so the gate sequence is advisory)

- **RED (`2546e34`).** `go test -count=1 -v -run 'TestDirectory' ./internal/signer/` failed only in `TestDirectoryLogConsistency`. `stored_directory_tampered`, `signatures_replaced`, `newest_row_deleted`, `table_wiped` and `unlogged_row` each failed at `directory_test.go:325: start with a directory table the log does not record = <nil>, want errLogMismatch naming the directory_install entry`. `fresh_state_starts` and every other test passed.
  - Semantic assessment: the target assertion failed for the planned reason. New started on a tampered table, which is the missing behaviour. It was not a compile, fixture or setup failure.
  - The GSD classifier has no Go adapter, so this is a recorded semantic assessment and not a classifier verdict.
  - `policy_version_replaced` was added after GREEN (`c0d449d`) and has no RED run.
- **GREEN (`1f398f8`).** The same command and the full signer package pass. Under `-race` in WSL, the plan's verify pattern passed with no DATA RACE.
- **Unexpected green (recorded, not dressed up as RED).** Everything else in Task 2 passed on its first run, because it tests code 02-01 built: the login matrix, policy clause, evidence mix, concurrency, restart, install refusals and the webauthn matrix. The bite test above shows that the matrix depends on the check it guards.

## Verification run

| Check | Where | Result |
|---|---|---|
| Task 1 verify: e2e `TestLoginRefusals\|TestLoginSignerEndToEnd`, sshd 10.5p1 | WSL | PASS, 6/6 subtests; re-run after the commit: PASS |
| Full e2e suite, sshd 10.5p1 | WSL | PASS, 18 top-level tests, 0 skipped |
| Task 2 verify: `go test -race -v -run "Login\|Directory\|Concurrent\|Restart\|EvidenceMix" ./internal/signer/...` | WSL | PASS, no DATA RACE, both digest-leaf cases in the PASS lines |
| Task 2 verify: `go test -run 'Mutation\|ParsePublicKey\|ClientData' ./internal/webauthn/...` | Windows | PASS, `client_data_extra_members_accepted` for eddsa, es256, rs256 |
| Task 3 verify: wire boundary tables | Windows | PASS, every named case in the PASS lines |
| Task 3 verify: `FUZZTIME=10s bash scripts/fuzz.sh` | WSL | `fuzz: all 19 targets passed (10s each)` |
| Task 3 verify: `go test -race ./...`, `go vet ./...`, `go vet -tags e2e`, gofmt, golangci-lint, capslock-check, dep-firewall | WSL, from a script file so gofmt really runs | all passed; lint 0 issues; capslock 73 pairs, baseline 73 |
| Required CI checks on the PR head | GitHub | pending at SUMMARY time, reported in the checkpoint |

## Pre-merge review fixes

The pre-merge review of PR #38 at `ae57f1a` verified eight findings (each with a probe or a mutant) and one MEDIUM finding that the owner decided on. The fixes are the commits from `ae57f1a` to this docs commit, each SSH-signed by keyroster-bot. Fails-before evidence was taken on the code before each fix; for test gaps, a mutant of the checked line was run and the production file restored (`git diff --exit-code` clean after each).

| # | Finding | Commit | Test | Fails before / bite |
|---|---|---|---|---|
| 1 | The frame cap was keyed on the declared type only, so a hostile socket answering Issue with a 0x83 frame of MaxDirectoryFrame made the client read 1.06 MiB | `a9c1dab` fix(wire) | `internal/signerclient/client_test.go#TestReadResponseRefusesUnexpectedType`; `internal/wire/wire_test.go#TestReadMessageCaps` (new response-side rows); FuzzReadMessage under three cap sets | before: `readResponse read 1114180 bytes of a refused 0x83 frame, want only the 6 bytes`; after: 6 bytes, `wire.ErrUnexpectedType` |
| 2 | An unsigned InstallDirectory held s.mu for over a second (parse before signatures, quadratic role computation) | `5e3821d` fix(signer), `e5ed200` test(trust) | `directory_quorum_not_met/unparsable_signed_by_non_admin` in `TestDirectoryInstallRefusals`; `internal/directory#TestValidateLinear`, `TestValidateRoleBounds`; `internal/trust#TestCountPinnedSignersForgedBlocks` | before: `directory_invalid; want directory_quorum_not_met`; Validate of 20000 users `7.9176355s, want well under 1 s` (after 0.08 s); 203 junk blocks over 1 MiB `342.7042ms, want well under 150 ms` (after 0.03 s); with the bound made relative in `e5ed200`, `334.9705ms, want less than 60 hashes of the document (90.5719ms)` before, about 15 ms against about 90 ms after |
| 3 | Ten cheap malformed frames drained the single refusal bucket, hiding a forged install in the next refusal_summary | `c13534b` fix(signer) | `internal/signer#TestDirectoryRefusalBudget` | before: `0 new leaves after the refusal, want exactly one refusal leaf` |
| 4 | doctor did not run the start-up directory cross-check | `cd92070` fix(signer) | the CheckTrust assertions in `TestDirectoryLogConsistency` (every tamper case, `table_wiped` is `DELETE FROM directory`); `cmd/keyroster-signer#TestDoctorFailures/directory_row_without_a_log_entry` | before: `CheckTrust (doctor) with a directory table the log does not record = <nil>` in all six cases; doctor `exited 0, want 1` |
| 5 | Start-up CheckPolicy re-verification untested (T-02-15) | `1b13c8c` test | `TestDirectoryRestart/restart_under_tighter_cap` (user cap 1800 s below the roles' 3600 s; a conforming v2 as control) | mutant `false && err != nil` on the CheckPolicy branch: `GetDirectory = ... authorized true; want ... false` |
| 6 | The Doc and Version comparisons of checkDirectoryLogged not tested on their own | `932d703` test | `TestDirectoryLogConsistency/doc_only_replaced`, `/version_only_replaced` | dropping `body.Version != stored.Version` fails only `version_only_replaced`; dropping the Directory comparison fails only `doc_only_replaced` |
| 7 | The SUMMARY claimed the policy_version error log was tested, but every test logger discarded | `deb1069` test | `wantStartLog` in both TestDirectoryRestart cases, through `logEnv.logOut` (a TextHandler on a buffer, the pattern of refusalcause_test.go; `captureHandler` is in the Linux-only external test package, so it was not used) | dropping `policy_version` from either log line fails its case |
| 8 | INFO: counts, D1 scope, PR facts, the vacuous e2e check, the maxConns comment | `6ecf9f6` test(e2e), `8fea286` docs(signer), this commit | `test/e2e#TestLoginRefusals` exported-log check | comparing the login_issue count with 0 instead of the controls' count fails for the two digests the controls issued, so the check reads real entries |
| M | T-02-14 claimed rollback is mitigated; the log and tables rolled back together, or an older signer.db restored, reinstate the older directory and trust bundle (C-WR-01 residual). Owner decision 2026-10-17: document now, and in Phase 4 serve refuses to start without a witnessed checkpoint | `ed105bd` docs(02-03), `70acb79` docs(runbooks), and this commit (the runbook's directory step: start the signer with no login peer on its allowlist until the lost directory versions are back) | none (docs and comments only, no behaviour change) | n/a |

Notes on the fixes:

- **1.** `wire.ReadMessage(r, caps)` takes the reader's `wire.Caps`. The signer passes `wire.RequestCaps`: InstallDirectory up to MaxDirectoryFrame, every other type (responses and unknown types included) up to MaxFrame, so `unknown_message_type` still answers. A client passes `wire.ResponseCaps(want)`, which accepts only `want` and TypeError. The client's old "unexpected message type in response" branch could no longer be reached and was removed.
- **2.** Signatures are now verified before the document is parsed, so an unsigned invalid document is refused `directory_quorum_not_met` instead of `directory_invalid`; admin-signed `directory_invalid` cases are unchanged. `roleGrants` computes every user's roles in one pass and stops as soon as one user holds more than MaxRolesPerUser; Authorize uses it too. **Deviation from the finding's wording:** CountPinnedSigners does not stop at one verification attempt per fingerprint, which would let a stale invalid signature block a later valid one by the same key. Instead it hashes the document once (`sshsig.DigestOf`, `VerifyDigest`) and skips keys that already count, which bounds the junk-block cost to one small signature check per block. The two timing assertions are skipped under `-race`. The forged-block bound is relative to 60 hashes of the document measured in the same test (`e5ed200`), because cli-windows and cli-macos run `./internal/trust` without `-race` on slower runners.
- **3.** Refused installs draw on `installLimiter`, a bucket of the same rate. Unlogged refusals of either bucket are still counted in the shared limiter. **The tlog format and the reason classes are unchanged**, so 02-04's verifier is not affected. A frame that does not decode as an install request stays on the shared bucket, so it cannot drain the install bucket.
- **4.** `signerdb.LogSnapshot.Directory` is read in the same read transaction; `CheckTrust` calls `checkDirectoryLogged`. It is not in `rebuildLogFrom`, because `logTx`'s reload path calls that. doctor's `trust_mismatch` message and the runbook row now name the directory. The deferred-items entry and the "Not exercised" bullet for this gap are removed.
- **M.** T-02-14 (plan and this SUMMARY) is narrowed to the directory table rolled back or substituted alone. The logstate.go comments, Phase 1's C-WR-01 entry, a blocker todo (`.planning/todos/pending/2026-10-17-serve-refuses-without-witnessed-checkpoint.md`), STATE.md and the runbook's "Snapshot restore" section record the residual and the decision. Also recorded for 02-12 (phase 02 deferred-items): its false-fingerprint claim holds against page tampering, not against a compromised server.

Local runs after the fixes (code at `8fea286`; the later commits change comments, docs and one test, re-checked as listed below the table):

| Check | Where | Result |
|---|---|---|
| `gofmt -l .` | WSL, from a script file; Windows | empty |
| `go vet ./...` for linux, windows, darwin; `go vet -tags e2e ./...` | WSL; Windows | clean |
| `go test -count=1 ./...` | Windows | PASS, 16 packages with tests (the Linux-tagged signer tests do not build there) |
| `go test -race -count=1 ./...` and `./internal/signer/... ./internal/wire/... ./internal/signerclient/... ./internal/directory/...` | WSL | PASS, no DATA RACE |
| e2e suite (`-tags e2e`), sshd 10.5p1 and 9.5p1 | WSL | PASS both |
| golangci-lint v2 (GOOS linux, windows, darwin) | WSL | 0 issues each |
| dep-firewall, testonly-firewall, capslock-check | WSL | clean; capslock 73 pairs, baseline 73 |
| `FUZZTIME=5s bash scripts/fuzz.sh` (FuzzReadMessage changed) | WSL | `fuzz: all 19 targets passed (5s each)` |

After `8fea286`: `e5ed200` (the relative forged-block bound) ran 3 times on Windows and passed (about 15 ms against about 90 ms). On `e5ed200` in WSL: `gofmt -l .` empty, `go vet ./...` clean for linux, windows and darwin, golangci-lint 0 issues for all three, and `go test ./internal/trust/... ./internal/signer/...` PASS. This last docs commit changes no Go file.

Not run or not verified:

- **CI on the new head.** The required checks have not run on the fixed head when this is written; they are reported in the merge-gate checkpoint.
- **The restore procedure in the runbook** is UNVERIFIED: it was not run against a restored database. Its `grep` patterns match the export decoder's output (checked for `directory_install` only).
- **Rolling back the root set** by the same database cut is UNVERIFIED (from the review).
- **The finding-2 timing bounds** are measured on this workstation only and skipped under `-race`; the timing-independent check is the refusal order.
- The e2e-pkcs11 and e2e-tpm lanes ran only in CI (at `ae57f1a`), not locally.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Interpretation] ReadFrame and WriteFrame removed instead of unexported**
- **Found during:** Task 3.
- **Issue:** after the per-type rework, ReadMessage and WriteMessage no longer call them. Unexported, they would remain as production code used only by tests.
- **Fix:**
  - Both functions are deleted.
  - Their cases (1 GiB length refused before allocation, empty frame, truncations) moved onto ReadMessage. The test name `TestReadFrame` is kept so the verify pattern still matches.
  - `FuzzReadFrame` is replaced by `FuzzReadMessage`.
- **Files modified:** internal/wire/frame.go, internal/wire/wire_test.go, internal/wire/fuzz_test.go.
- **Committed in:** af267dc

**2. [Rule 2 - No unexercised paths] Paths that no planned test reached**
- **Issue:** the plan's tests did not reach three paths:
  - a directory above MaxFrame through the real socket (the point of the cap);
  - the GetDirectory empty-body rule;
  - a tampered `policy_version`.
- **Fix:**
  - `internal/signer/directory_socket_test.go#TestDirectoryOverSocket`, a new Linux-tagged file outside the plan's list. A 2000-user directory above 64 KiB installs and reads back byte for byte. A frame of MaxDirectoryFrame + 1 is refused `malformed_frame` after its header. A GetDirectory request with a body is refused `malformed_request`. Each has a control.
  - The `policy_version_replaced` case.
- **Committed in:** af267dc, c0d449d

**3. [Interpretation] credential_mismatch and unsupported_algorithm have no LoginIssue case**
- **Issue:** the plan lists `credential_mismatch` as a LoginIssue case, and the must-have asks for every 02-01 detail. Neither of these two can be reached through the signer:
  - `directory.Credential` returns the ID it matched, so the ID check in VerifyAssertion always passes;
  - `Validate` refuses a credential with an unsupported algorithm.
- **What was done:**
  - No test-only production hook was added.
  - `TestLoginRefusalClasses` asserts `assertionRefusal` maps `ErrCredentialID` and `ErrAlgorithm` to their details, and that `classify` is not internal for either.
  - `TestWebAuthnSignatureAndCredential` (02-01) covers ErrCredentialID at the verifier.
- **Committed in:** 2546e34

**4. [Observation, no code change] An install refused `trust_changed` is counted in a refusal_summary, not an individual leaf**
- **Issue:** the successor bundle written by another process moved the log ahead of the live signer's in-memory tree. The refusal leaf's append therefore fails, and the refusal is counted for the next `refusal_summary`. That is the D-14 fallback, and the failed transaction reloads the log.
- **What was done:** the `trust_changed` case asserts the refusal, that nothing is stored and no leaf is written, and then a `refusal_summary` counting it with class unavailable after `flushSummaries`. Control: after a restart the same directory installs. This was 02-01's UNVERIFIED Deviation 2; it is now tested.
- **Committed in:** 2546e34

**5. [Rule 3 - Blocking] Two lint findings from the full gate**
- **Issue:** gosec G115 on the cap comparison in ReadMessage, and revive unused-parameter in a test closure.
- **Fix:** a `//nolint:gosec` with a reason, in the existing style, and `_` for the parameter.
- **Committed in:** af267dc

**6. [Scope] Small edits outside the plan's file list**
- `test/e2e/login_signer_test.go`: `loginRequest` is split into `unsignedLoginRequest` and `withAssertion`, which the refusal suite reuses. The behaviour is unchanged and the tracer still passes.
- `internal/signer/signer.go`: New's doc comment names the directory check.
- `internal/signer/server.go`: `maxConns` documents the memory bound, and handle dispatches GetDirectory.
- `internal/cert/keyid_test.go`: FuzzParseKeyID moved out to fuzz_test.go.
- `ClientDataExtraMembers` is exported from the internal test file `internal/webauthn/fuzz_test.go` (the export_test idiom), so the accept test and the fuzz seed share one literal.

---

**7. [Process] The branch was pushed, and the PR opened, after the SUMMARY commit**
- **Issue:** the SUMMARY was committed before the single push, so it could not name PR #38 or its check results; this file first said they were unknown.
- **What was done:** the pre-merge review fixes record PR #38 and the 20 check results at `ae57f1a` under Delivery.

**Total deviations:** 7 (1 interpretation of the unexport rule, 1 coverage addition, 1 unreachable-detail interpretation, 1 observation, 1 lint fix, 1 scope note, 1 process note).
**Impact on plan:** no new dependency and no production code path added for tests. The one production behaviour change of Task 2 is the cross-check the plan asked for.

## Issues Encountered

- **Shell heredocs.** In this session's Git Bash wrapper, long quoted heredocs failed with "unexpected EOF". Long test blocks were written to the session scratchpad and appended with `cat`.
- **WSL command quoting.** As in 02-01, every WSL command with `$` or `$(...)` ran from a script file under `.git/` (never committed), so gofmt really ran in the gate.

## Not exercised (UNVERIFIED)

- **CI.** At SUMMARY time none of the required checks has run on this branch: build-test, lint, fuzz, e2e (9.5p1), e2e (10.5p1), e2e-pkcs11, e2e-tpm, Windows/macOS CLI and the rest. In particular, **the e2e suite against sshd 9.5p1 ran only in CI**, never locally. Their results go in the merge-gate checkpoint.
- **Real authenticators and browsers.** Every assertion comes from the soft authenticator, as in 02-01. That includes the 37-byte authenticatorData rule and the extra-members accept case modelled on Chrome's clientDataJSON. **UNVERIFIED** until the 02-13/02-14 dogfood.
- **credential_mismatch and unsupported_algorithm through LoginIssue.** Unreachable by construction (Deviation 3). Only the mapping is tested.
- **A directory at the full 1 MiB through the socket.** The socket test uses about 100 KiB. Exactly MaxDirectoryFrame is covered by the wire tables only.

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat model. GetDirectory is a new read-only message type for peers on the socket allowlist (the plan's GetDirectory section). It returns the directory and signatures the log already records, and no new network surface exists: depguard and dep-firewall are clean.

## User Setup Required

None.

## Next Phase Readiness

- 02-04 (audit checks for kinds 7 and 8) and 02-05 (Status cap under the same `maxBodyFor` rule, using countingReader, frameHeader and a bytes.Buffer) can start from these names.
- **API change from the pre-merge review, for 02-05 and later:** `wire.ReadMessage(r, caps)` takes the reader's `wire.Caps`. The signer passes `wire.RequestCaps` (InstallDirectory at MaxDirectoryFrame, everything else at MaxFrame); a client passes `wire.ResponseCaps(want)`, which accepts only `want` (at `maxBodyFor(want)` plus the header) and TypeError. A Status response cap therefore still goes into `maxBodyFor` only; 02-05's tests that call `ReadMessage` must pass caps. New exported names: `wire.Caps`, `RequestCaps`, `ResponseCaps`, `ErrUnexpectedType`, `sshsig.Digest`, `DigestOf`, `(*Signature).VerifyDigest`.
- 02-06 onwards (the server mirror) uses `signerclient.GetDirectory`.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in key-files.created exists.
- Commits `6b1fcae`, `2546e34`, `1f398f8`, `af267dc`, `c0d449d` and `c984266` are ancestors of HEAD, and each carries an SSH signature.
- Task 1 acceptance:
  - the six subtest names are present;
  - `wrong_digest` asserts exactly `challenge_mismatch`;
  - both GetDirectory checks of `directory_not_quorum_signed` assert all four fields.
- Task 2 acceptance:
  - all nine login_test.go and four directory_test.go case names are present;
  - the non-comment GetDirectory count in directory_test.go is 9;
  - the refusal.go grep count is 3;
  - `client_data_extra_members_accepted` sits in TestWebAuthnClientDataExtraMembers and passes for all three algorithms.
- Task 3 acceptance:
  - `go test -list '^Fuzz'` lists the 10 new targets and FuzzDecodeLeaf;
  - the fuzz_test.go case grep count is 2;
  - maxBodyFor is defined and used in ReadMessage and WriteMessage;
  - ErrShortFrame is defined and used in ReadMessage;
  - every boundary case is present;
  - `get_directory_installed_round_trips` runs with Authorized true and false.
- The PR acceptance (open, auto-merge, green, SUMMARY on its head) is checked after the push and reported in the checkpoint.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-17 (before the merge gate)*
