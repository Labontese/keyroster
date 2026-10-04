---
phase: 01-trust-core
plan: 16
subsystem: testing
tags: [refusal-suite, table-tests, go-fuzz, race-detector, ssh-agent, sqlite, unix-socket, so_peercred, x-crypto-ssh, tdd]

requires:
  - phase: 01-02
    provides: "internal/cert, internal/serial, internal/wire, internal/keystore (+agent backend), internal/signerdb, internal/signer, internal/signerclient, cmd/keyroster ca issue"
  - phase: 01-01
    provides: "SHA-pinned CI (build-test, lint, govulncheck, pr-title), keyroster-bot, scripts/gh-as-bot.sh, scripts/merge-gate.sh, scripts/linux.sh"
provides:
  - "newTestSigner fixture (internal/signer, linux): real Unix socket, keyring-backed agent backend, temp state DB, captured slog records, stop/start for restart and restore tests"
  - "TestRefusalEndToEnd tracer: out-of-policy request through signerclient.Issue -> refused bad_principal, no state change, one reason-coded record, next request served"
  - "Named refusal tables for principals, key IDs, extensions, validity, serials, subject and CA keys, wire decoding, agent backend, state DB constraints, signer refusals, concurrency, peer allowlist, restore, CLI private-key refusal"
  - "Four seeded decoder fuzz targets: FuzzParseIssueRequest, FuzzReadFrame (internal/wire), FuzzParseKeyID, FuzzValidatePrincipals (internal/cert) for plan 01-04's fuzz job"
  - "Two 01-02 defect fixes: SigningBytes starts with the raw domain tag; the agent backend skips certificate entries by wire key type"
affects: [01-04, 01-05, 01-07, 01-13]

actuals:
  tokens: 22852
  tasks: 3
  commits: 5
plan_head_before: 48a4cdaf664e0d73f53951785b00edcb721f2111
plan_head_after: 143d2f8787cef7c07a0c951139d6f94fc5a707e8

tech-stack:
  added: []
  patterns:
    - "Every refusal case asserts its specific sentinel (errors.Is), ErrorResponse code + reason, or SQLite extended result code; signer refusals also assert unchanged LastSerial/issuance rows and exactly one reason-coded slog record"
    - "Tests that need a certificate build it through cert.Build, so the forbidigo SignCert rule holds in test files too"
    - "Unix-socket fixtures use short os.MkdirTemp directories (108-byte sun_path limit)"
    - "Fuzz targets check that encoding a successfully parsed input gives back the same bytes, or compare against an independent byte-wise statement of the rule"

key-files:
  created:
    - internal/signer/signer_test.go
    - internal/cert/builder_test.go
    - internal/cert/keyid_test.go
    - internal/serial/serial_test.go
    - internal/wire/wire_test.go
    - internal/wire/fuzz_test.go
    - internal/keystore/agent/agent_test.go
    - internal/signerdb/db_test.go
    - cmd/keyroster/ca_test.go
  modified:
    - internal/wire/issue.go
    - internal/keystore/agent/agent.go

key-decisions:
  - "IssueRequest.SigningBytes now starts with the raw bytes of keyroster/issue-request/v1 (no uint16 length prefix), as the 01-02 contract specifies; no signature over these bytes exists before 01-07"
  - "The agent backend identifies certificate entries by the -cert-v01@openssh.com key type as well as by *ssh.Certificate, because x/crypto's agent client returns every entry as *agent.Key"
  - "GSD's tdd-red-evidence checker parses only TAP and Surefire XML, not go test output, so the RED evidence for this plan is recorded in this SUMMARY (command, exit code, failing test, assertion)"

patterns-established:
  - "newTestSigner is the reusable in-process signer fixture for later signer tests (01-05, 01-07)"
  - "A refusal test never passes on an unspecified error"

requirements-completed: [CA-02, CA-03, CA-04, CA-05, CA-06, CA-07, KEY-01, REPO-02]

coverage:
  - id: D1
    description: "Tracer: an out-of-policy request through the real client and socket is refused (refused: bad_principal), leaves LastSerial and the issuance rows unchanged, logs exactly one reason-coded record without request bytes, and the next valid request is served"
    requirement: KEY-01
    verification:
      - kind: integration
        ref: "bash scripts/linux.sh 'go test -race -count=1 -run TestRefusalEndToEnd -v ./internal/signer/' -> --- PASS: TestRefusalEndToEnd"
        status: pass
    human_judgment: false
  - id: D2
    description: "Principal allowlist (empty, encoding, homoglyphs, NFC/NFD, 128-byte limit, duplicates, 33 principals), extensions (permit-pty only, host certs none, critical options), validity and serial refusals in cert.Build"
    requirement: CA-02
    verification:
      - kind: unit
        ref: "go test -count=1 -v ./internal/cert/ (TestValidatePrincipals incl. nfd_e_acute, cyrillic_a; TestBuildPrincipals; TestBuildExtensions; TestBuildValidityAndSerial)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Subject keys (certificate, DSA, RSA-2048 refused; RSA-3072, Ed25519, ECDSA 256/384/521, sk-ed25519, sk-ecdsa accepted; subject = CA refused) and CA keys (certificate_as_ca, RSA, P-384, P-521 refused; Ed25519 and P-256 sign and verify)"
    requirement: CA-07
    verification:
      - kind: unit
        ref: "go test -count=1 -v ./internal/cert/ (TestBuildSubjectKeys, TestBuildCAKeys incl. certificate_as_ca)"
        status: pass
    human_judgment: false
  - id: D4
    description: "kr1 key ID grammar: round trip, fixed field order, / and = refused, empty fields, uppercase hex, leading zeros, reordered/missing/extra fields, kr2 prefix; Build refuses a KeyID serial that differs from the certificate serial"
    requirement: CA-04
    verification:
      - kind: unit
        ref: "go test -count=1 -v ./internal/cert/ (TestKeyIDRoundTrip, TestParseKeyIDRefusals incl. kr2_prefix, TestBuildKeyID, key_id_serial_differs)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Serial allocator: fresh DB gives now_us, same_microsecond gives last+1 after the clock reaches it, clock_regression, epoch clock never yields 0, stalled clock; signer refuses with clock_regression when the stored high-water mark is ahead; serials strictly increase and stay above every pre-restore serial after restoring an older DB"
    requirement: CA-03
    verification:
      - kind: unit
        ref: "go test -count=1 -v ./internal/serial/ (TestNext incl. same_microsecond, clock_regression; TestNextAdjacentSerials)"
        status: pass
      - kind: integration
        ref: "bash scripts/linux.sh 'go test -race -count=1 -v ./internal/signer/' (TestSignerRestore/restore_older_db, TestSignerClockBehindHighWaterMark)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Strict wire decoding: trailing bytes, truncation, every over-limit field, unknown version and CA role; 1 GiB frame header refused after 4 bytes with < 1 MiB allocated; signing bytes start with the domain tag and exclude evidence"
    requirement: REPO-02
    verification:
      - kind: unit
        ref: "go test -count=1 -v ./internal/wire/ (TestParseIssueRequestRefusals, TestReadFrame/one_gib_header_refused_before_body, TestSigningBytes)"
        status: pass
    human_judgment: false
  - id: D7
    description: "Four seeded decoder fuzz targets exist and run clean: FuzzParseIssueRequest, FuzzReadFrame, FuzzParseKeyID, FuzzValidatePrincipals"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "go test -run '^$' -fuzz '^FuzzParseIssueRequest$' -fuzztime 15s ./internal/wire/ and -fuzz '^FuzzParseKeyID$' -fuzztime 15s ./internal/cert/ (PASS); FuzzReadFrame and FuzzValidatePrincipals 10 s each (PASS); go test -list '^Fuzz' lists all four"
        status: pass
    human_judgment: false
  - id: D8
    description: "Agent backend (decoy first, certificate entry skipped, absent pinned key, RSA/P-384 refused at load, Ed25519 and P-256 sign through it, custody, options), state DB (migrations once, newer schema, 0600, ErrDuplicateRequest, PRIMARY KEY and CHECK constraints), signer refusals with one record each, duplicate_request_race, sixteen_clients, half_frame_close, peer_not_allowed"
    requirement: KEY-01
    verification:
      - kind: integration
        ref: "bash scripts/linux.sh 'go test -race -count=1 -v ./internal/signer/... ./internal/signerdb/... ./internal/keystore/...' -> all PASS, no DATA RACE; signer package also -count=10"
        status: pass
    human_judgment: false
  - id: D9
    description: "keyroster ca issue given a private key file as --pubkey exits 1 with the private-key refusal before dialing a non-existent signer socket"
    requirement: CA-06
    verification:
      - kind: unit
        ref: "go test -count=1 -run TestCAIssue -v ./cmd/keyroster/ (private_key_as_pubkey, pkcs8_private_key_as_pubkey, public_key_dials_signer control)"
        status: pass
    human_judgment: false
  - id: D10
    description: "PR #4 is green with auto-merge on and waits for the owner's approval at the merge gate"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 4 --required --watch -> build-test, lint, govulncheck, pr-title pass (run 37205398902, head 143d2f8)"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 4 blocking-human merge gate, after this SUMMARY is written"

duration: 22min
completed: 2026-10-04
status: complete
---

# Phase 1 Plan 16: Signing-Boundary Refusal Suite Summary

**Every refusal rule and edge case of the 01-02 signing boundary is now pinned by a named test that asserts its specific error, reason code or SQLite constraint. This includes a tracer that crosses the real socket and checks that nothing changes, plus four seeded decoder fuzz targets for plan 01-04. Writing the tests exposed two defects in 01-02 code, and both are fixed: `SigningBytes` did not start with its domain tag, and the agent backend never skipped certificate entries. PR #4 is green and waits for the owner.**

## Performance

- **Duration:** 22 min
- **Started:** 2026-10-04T13:03:59Z
- **Completed:** 2026-10-04T13:25:20Z
- **Tasks:** 3 of 4 executed before the merge gate (Task 4 is the owner's approval)
- **Files modified:** 11 (9 test files created, 2 source files fixed), 2662 insertions, 5 deletions

## Accomplishments

- **Task 1 (tracer):** the `newTestSigner` fixture and `TestRefusalEndToEnd`. Principal `*` goes through `signerclient.Issue` and comes back as `*wire.ErrorResponse{Refused, "bad_principal"}`. `LastSerial` and the issuance row count stay the same. Exactly one reason-coded record is logged, and neither the subject key's base64 nor the principal appears in it. The next request for `alice` returns a certificate that `ssh.CertChecker` verifies against the CA key. The tracer feedback gate re-ran `<verify>` (green) before the expansion tasks started.
- **Task 2:** pure-Go tables in `internal/cert`, `internal/serial` and `internal/wire`, plus the four fuzz targets. Subject keys include hand-assembled sk-ed25519, sk-ecdsa and ssh-dss blobs. The ssh-dss blob is a parseable 1024-bit key, so the refusal comes from `CheckSubjectKey`. The 1 GiB frame header test shows that `ReadFrame` reads only the 4-byte header and allocates less than 1 MiB.
- **Task 3:** stateful tables for the agent backend, the state DB, the signer (refusal table, raw frames, a clock behind the high-water mark, concurrency, the peer allowlist, restore) and the CLI. The tests were published as PR #4 with auto-merge, and all four required checks pass.

## PR

- **PR #4** `test(signer): pin every refusal rule of the signing boundary with tables and fuzz targets` (https://github.com/Labontese/keyroster/pull/4), branch `p01/16-refusal-suite`, opened by keyroster-bot, auto-merge squash enabled.
- Required checks on implementation head `143d2f8` (run 37205398902) all pass: `build-test` (1m55s), `lint`, `govulncheck` and `pr-title`. All five commits show `verified: true` (GitHub API).

## Recorded Facts

| Item | Value |
|---|---|
| Race-detector run time, `internal/signer` (WSL, `go test -race -count=1`) | 1.85 s (2.01 s inside the full `./...` run); `-count=10` 9.0 s, no DATA RACE |
| Fuzz seeds: `FuzzParseIssueRequest` | 8 (valid body, no evidence, no principals, CA role 0, 5 evidence items, trailing byte, half body, empty) |
| Fuzz seeds: `FuzzReadFrame` | 7 (valid frame, 0 length, 1 GiB header, MaxFrame+1, version/type-only payload, short payload, short header) |
| Fuzz seeds: `FuzzParseKeyID` | 9 (user/host/machine valid IDs, kr2 prefix, `/` in subject, empty fields, leading zero, empty, bare `kr1/`) |
| Fuzz seeds: `FuzzValidatePrincipals` | 19 (valid, 128/129 bytes, empty, `* ? , !`, whitespace, newline, uppercase, NUL, Cyrillic, NFC/NFD é, all symbols, leading dot, invalid UTF-8) |
| Local fuzz runs (Windows, go1.27.1) | FuzzParseIssueRequest 15 s / 3.76 M execs; FuzzParseKeyID 15 s / 2.01 M execs; FuzzReadFrame and FuzzValidatePrincipals 10 s each; no failing input |
| e2e regression after the agent fix | `TestIssueAcceptedBySSHD` passes against OpenSSH 10.5p1 (WSL) |
| `go.mod` / `go.sum` | identical to `origin/main` (no module added) |
| golangci-lint v2.14.0 (WSL, all files incl. tests) | 0 issues |

## Task Commits

1. **Task 1: tracer, refusal end to end through the real socket.** `5df1de3` (test)
2. **Task 2: pure-Go refusal tables and fuzz targets.** RED `e336744` (test), GREEN `9e204ec` (fix)
3. **Task 3: stateful refusal tables, and PR.** RED `8750ee2` (test), GREEN `143d2f8` (fix)
4. **Task 4: merge gate.** No commit (owner approval; squash merge by GitHub)

**Plan metadata:** the `docs(01-16): complete refusal suite plan` commit on the same PR branch.

### TDD evidence (RED before GREEN)

| Gate | Command | Exit | Failing test | Assertion |
|---|---|---|---|---|
| Task 2 RED (`e336744`) | `go test -count=1 -v ./internal/cert/... ./internal/serial/... ./internal/wire/...` | 1 | `TestSigningBytes` (only failure) | `SigningBytes starts with "\x00\x1akeyroster/issue-request/v1...", want the domain tag "keyroster/issue-request/v1"` |
| Task 2 GREEN (`9e204ec`) | same | 0 | none | |
| Task 3 RED (`8750ee2`) | `bash scripts/linux.sh 'go test -race -count=1 -v ./internal/keystore/...'` | 1 | `TestKeySelection/certificate_entry_skipped` (only failure) | `certificate_fingerprint: Key = <nil>, keystore agent: pinned key for role user: cert: a certificate cannot be used as a key; want ErrKeyNotPresent` |
| Task 3 GREEN (`143d2f8`) | same, plus the full `go test -race ./...` | 0 | none | |

## Files Created/Modified

- `internal/signer/signer_test.go` - fixture, tracer, signer refusal/framing/clock/concurrency/peer/restore tests
- `internal/cert/builder_test.go` - principal, extension, validity, serial, key-ID-in-Build, subject-key and CA-key tables; `FuzzValidatePrincipals`
- `internal/cert/keyid_test.go` - kr1 round trip and refusal table; `FuzzParseKeyID`
- `internal/serial/serial_test.go` - fake-clock allocator table and adjacent-serial test
- `internal/wire/wire_test.go` - round trip, refusal, over-limit, signing-bytes, frame, message, error/issue response tests
- `internal/wire/fuzz_test.go` - `FuzzParseIssueRequest`, `FuzzReadFrame`
- `internal/keystore/agent/agent_test.go` - key selection, CA algorithms through the backend, options
- `internal/signerdb/db_test.go` - migrations, file mode, constraints, high-water mark
- `cmd/keyroster/ca_test.go` - `TestCAIssueRefusesPrivateKey`
- `internal/wire/issue.go` - `SigningBytes` raw domain tag (fix)
- `internal/keystore/agent/agent.go` - `isCertificate` by wire key type (fix)

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

### Auto-fixed Issues (01-02 defects the tests exposed)

**1. [Rule 1 - Bug] `SigningBytes` did not start with the domain tag**
- **Found during:** Task 2 (`TestSigningBytes`)
- **Issue:** `internal/wire/issue.go` wrote `keyroster/issue-request/v1` with a uint16 length prefix (`\x00\x1a`), so the signing bytes did not begin with the tag that the 01-02 contract and this plan specify.
- **Fix:** `internal/wire/issue.go`: write the tag with `b.AddBytes`, followed by every non-evidence field. The tag is fixed and the CA role byte that follows is 1-3, so the encoding stays unambiguous.
- **Files modified:** internal/wire/issue.go
- **Verification:** `TestSigningBytes` (prefix, evidence excluded, every other field bound to the digest) passes; full suite green.
- **Committed in:** `9e204ec`

**2. [Rule 1 - Bug] The agent backend never skipped certificate entries**
- **Found during:** Task 3 (`TestKeySelection/certificate_entry_skipped`)
- **Issue:** `internal/keystore/agent/agent.go` skipped entries with `pub.(*ssh.Certificate)`, but x/crypto's agent client returns every entry as `*agent.Key`. A certificate entry with the requested fingerprint therefore reached `cert.CheckCAKey`, which returned `ErrCertificateKey` instead of skipping the entry. It still failed closed, but the documented skip (CA-07) was dead code.
- **Fix:** `internal/keystore/agent/agent.go`: `isCertificate` also matches the `-cert-v01@openssh.com` key type.
- **Files modified:** internal/keystore/agent/agent.go
- **Verification:** the agent tables pass under `-race`; `TestIssueAcceptedBySSHD` still passes against OpenSSH 10.5p1.
- **Committed in:** `143d2f8`

**3. [Rule 3 - Blocking] Test hygiene for the existing lint rules**
- **Found during:** Tasks 2-3
- **Issue:** The test files are subject to the repo's forbidigo `SignCert` rule and to gosec.
- **Fix:** Every test certificate is built through `cert.Build`, never through `SignCert`. Bounded G115 conversions and one G703 test-file write carry justified `//nolint:gosec` comments. The DSA case uses a string literal instead of the deprecated `ssh.KeyAlgoDSA`.
- **Files modified:** test files only
- **Verification:** golangci-lint v2.14.0: 0 issues; CI `lint` pass
- **Committed in:** `e336744`, `8750ee2`

---

**Total deviations:** 3 auto-fixed (2 Rule 1, 1 Rule 3). **Impact:** both bugs were in 01-02 code inside this plan's scope (the plan says to fix exposed defects in the owning file). No scope creep, and no module was added.

## Issues Encountered

- A `cat <<'EOF'` append to `signer_test.go` failed with a shell quoting error before writing anything; the content was added with the Edit tool instead.
- The first RED commit for Task 2 contained a gofmt deviation in `wire_test.go`; it was reformatted and amended before anything was pushed.
- `gsd-tools check tdd-red-evidence` cannot classify Go test output (TAP/Surefire only); the RED evidence is in the table above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The owner approves PR #4 at the Task 4 merge gate; `bash scripts/merge-gate.sh p01/16-refusal-suite` then waits for the auto-merge and fast-forwards local `main`.
- Plan 01-04 can then start. Its fuzz job finds the four targets with `go test -list '^Fuzz'`.
- Plan 01-07 signs `req.SigningBytes()`, which now starts with the raw domain tag.
- Plans 01-05 and 01-07 can reuse `newTestSigner` (stop/start already supports restart and restore).

## Self-Check: PASSED

- Files present: all 11 files of `git diff --name-only 48a4cda..143d2f8`, including `internal/signer/signer_test.go`, `internal/wire/fuzz_test.go`, `internal/keystore/agent/agent_test.go`, `cmd/keyroster/ca_test.go`.
- Commits present: `5df1de3`, `e336744`, `9e204ec`, `8750ee2`, `143d2f8` on `origin/p01/16-refusal-suite`; `git rev-list --count 48a4cda..HEAD` = 5 before the docs commit.
- Required checks on PR #4 head `143d2f8`: all four pass.
