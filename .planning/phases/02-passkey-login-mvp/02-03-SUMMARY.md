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
  - "The start-up cross-check: the signer refuses to start when the latest stored directory is not the one the last directory_install leaf records (T-02-14)"
  - "TestLoginRefusals (SC4 through the real socket, six cases with controls) and the unit refusal matrix, restart, log-consistency and concurrency suites"
  - "11 new fuzz targets; scripts/fuzz.sh now runs 19"
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
    description: "SC4 through the real socket: missing assertion, replayed request, wrong digest, a directory not signed by the admin quorum, a policy without an RP and admin evidence on a login request are each refused with their detail and no certificate, each with a succeeding control; the exported log records each refusal with its request digest"
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
    description: "Start-up cross-check (T-02-14): a stored directory row overwritten, with replaced signatures or policy version, the newest row deleted, the table wiped, or a row without a log entry stops the signer; the fresh state starts"
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
    description: "Every new parser is fuzzed: 11 new targets, 19 in all, each 10 s locally"
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
- **PR:** opened by keyroster-bot with the title `test(signer): refuse every unauthorized login path and fuzz the new parsers` after the single push that carries this SUMMARY. The PR number and the required-check results are not known when this file is written. They are reported in the merge-gate checkpoint, read from GitHub (Delivery Protocol step 4: merge facts are never committed).
- **Commits:** signed by keyroster-bot (each carries an SSH signature; GitHub verifies them, locally `%G?` shows N because no allowedSignersFile is configured).

## Accomplishments

- **GetDirectory (Task 1).**
  - The request is 0x03 with an empty body (any body is refused `malformed_request`). The response is 0x83: u64 version, u24-prefixed directory, u24-prefixed signatures and a u8 0/1.
  - Version 0 has exactly one encoding: no bytes, no signatures, not authorized.
  - A stored directory that no longer verifies is reported with its bytes and `Authorized=false`.
  - `Signer.GetDirectory` runs under `s.mu`. `directoryState` now keeps the installed signatures (`directorySigs`), from `loadDirectory` and after an install's COMMIT.
- **SC4 through the socket (Task 1).** `TestLoginRefusals` covers six cases, and each asserts the refusal detail and that no certificate came back:
  - `missing_assertion` gives `missing_evidence`. Control: the same request approved, with a fresh request id.
  - `replayed_request`: the identical bytes are sent twice and the second is refused `duplicate_request`.
  - `wrong_digest`: only the request id changes after approval, giving exactly `challenge_mismatch`. Control: an assertion over the changed request.
  - `directory_not_quorum_signed`, on its own signer: an install signed only by a non-admin is refused `directory_quorum_not_met`. GetDirectory then reports version 0, empty, empty and false, and a login is refused `directory_not_installed`. Control: the admin-signed install, after which GetDirectory reports version 1, the exact sent bytes and signatures, and true; the login then issues.
  - `policy_without_rp`: a signer without an RP accepts the directory and refuses the login `no_webauthn_policy`.
  - `wrong_evidence_type`: admin SSHSIG evidence on a login request is refused `unknown_evidence_type`. Control: `keyroster ca issue` by the same admin.
  - The RP signer's export-log records every refused request's digest with its detail as an individual refusal leaf.
- **Named unit matrix (Task 2).** `TestLoginRefusalMatrix` has 39 table cases and 3 state cases. Each runs on a fresh signer through `loginOrRefuse` with real soft-authenticator assertions and an admin-signed directory. Each asserts the detail, a class other than internal, exactly one new refusal leaf carrying `req.Digest()`, nothing issued, and then a control login on the same signer. The table cases cover:
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
- **Restart and log consistency (Task 2).** See D5 and D6. `loadDirectory` now calls `checkDirectoryLogged` against `loggedInstalls.lastDirectory`, which `rebuildLogFrom` records for every `directory_install` leaf. This is the only production behaviour change in Task 2. Re-verification under the policy in force, the error log naming the policy version, and installing a successor while unauthorized already worked since 02-01; they are now tested.
- **Frame caps (Task 3).**
  - `MaxDirectoryFrame = MaxDirectory + 64 KiB + 64` (1,114,176 bytes) applies to InstallDirectory and GetDirectoryResponse. `MaxFrame` (64 KiB) applies to every other type, unknown types included.
  - `ReadMessage` reads the 4-byte length and refuses 0 (`ErrEmptyFrame`) and 1 (`ErrShortFrame`) before reading on. It then reads the 2 header bytes, checks the version, and checks `uint64(n) - 2` against `maxBodyFor` before allocating.
  - `WriteMessage` refuses before writing any byte, and writes in one `Write`.
  - Issue and login frames keep the Phase 1 limit byte for byte.
  - **New memory bound:** 32 connections × MaxDirectoryFrame ≈ 34 MiB of request buffers (documented on `maxConns`, T-02-12).

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
- **Run:** `FUZZTIME=10s bash scripts/fuzz.sh` in WSL ended with `fuzz: all 19 targets passed (10s each)`, against 10 targets before this plan.
- **Seeds:** FuzzReadMessage's seeds include a length-1 frame followed by a valid frame, a length-2 frame, and frames at exactly MaxFrame and MaxDirectoryFrame. FuzzParseClientData's seeds include the extra-members JSON (`webauthn.ClientDataExtraMembers`, shared with the accept test).

## Where the three 02-01 review findings this plan owns are covered

1. **The start-up cross-check (T-02-14)** is in `internal/signer/directory_test.go#TestDirectoryLogConsistency`. Each case first restarts once as a control.
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

**Total deviations:** 6 (1 interpretation of the unexport rule, 1 coverage addition, 1 unreachable-detail interpretation, 1 observation, 1 lint fix, 1 scope note).
**Impact on plan:** no new dependency and no production code path added for tests. The one production behaviour change of Task 2 is the cross-check the plan asked for.

## Issues Encountered

- **Shell heredocs.** In this session's Git Bash wrapper, long quoted heredocs failed with "unexpected EOF". Long test blocks were written to the session scratchpad and appended with `cat`.
- **WSL command quoting.** As in 02-01, every WSL command with `$` or `$(...)` ran from a script file under `.git/` (never committed), so gofmt really ran in the gate.

## Not exercised (UNVERIFIED)

- **CI.** At SUMMARY time none of the required checks has run on this branch: build-test, lint, fuzz, e2e (9.5p1), e2e (10.5p1), e2e-pkcs11, e2e-tpm, Windows/macOS CLI and the rest. In particular, **the e2e suite against sshd 9.5p1 ran only in CI**, never locally. Their results go in the merge-gate checkpoint.
- **Real authenticators and browsers.** Every assertion comes from the soft authenticator, as in 02-01. That includes the 37-byte authenticatorData rule and the extra-members accept case modelled on Chrome's clientDataJSON. **UNVERIFIED** until the 02-13/02-14 dogfood.
- **credential_mismatch and unsupported_algorithm through LoginIssue.** Unreachable by construction (Deviation 3). Only the mapping is tested.
- **`keyroster-signer doctor` does not run the directory cross-check.** serve refuses to start on a tampered directory table, but doctor would report it healthy. Logged in deferred-items.md.
- **A directory at the full 1 MiB through the socket.** The socket test uses about 100 KiB. Exactly MaxDirectoryFrame is covered by the wire tables only.

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat model. GetDirectory is a new read-only message type for peers on the socket allowlist (the plan's GetDirectory section). It returns the directory and signatures the log already records, and no new network surface exists: depguard and dep-firewall are clean.

## User Setup Required

None.

## Next Phase Readiness

- 02-04 (audit checks for kinds 7 and 8) and 02-05 (Status cap under the same `maxBodyFor` rule, using countingReader, frameHeader and a bytes.Buffer) can start from these names.
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
  - `go test -list '^Fuzz'` lists the 11 targets and FuzzDecodeLeaf;
  - the fuzz_test.go case grep count is 2;
  - maxBodyFor is defined and used in ReadMessage and WriteMessage;
  - ErrShortFrame is defined and used in ReadMessage;
  - every boundary case is present;
  - `get_directory_installed_round_trips` runs with Authorized true and false.
- The PR acceptance (open, auto-merge, green, SUMMARY on its head) is checked after the push and reported in the checkpoint.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-17 (before the merge gate)*
