---
phase: 01-trust-core
plan: 02
subsystem: signer
tags: [ssh-ca, x-crypto-ssh, ssh-agent, unix-socket, so_peercred, sqlite, modernc, openssh, e2e, golangci-lint, depguard, forbidigo]

requires:
  - phase: 01-01
    provides: "Go module, CLI register/dispatch registry, SHA-pinned CI (build-test, lint, govulncheck, pr-title), keyroster-bot, scripts/gh-as-bot.sh, scripts/merge-gate.sh, scripts/linux.sh"
provides:
  - "keyroster-signer serve: Linux-only signer process on a 0660 Unix socket with SO_PEERCRED/SO_PEERGROUPS uid/gid allowlist checked before any frame is read"
  - "keyroster ca issue: CLI that sends one framed IssueRequest and writes the returned user certificate"
  - "internal/wire: framed IssueRequest/IssueResponse/ErrorResponse, strict cryptobyte decoding, SigningBytes domain-separated with keyroster/issue-request/v1, Digest"
  - "internal/cert: CheckCAKey, CheckSubjectKey, ValidatePrincipals, Profile/DefaultUserProfile (permit-pty only, 12h max), kr1 KeyID grammar, Build (the only SignCert call site, re-verifies the signature)"
  - "internal/serial: clock-floor serial allocator Next with ErrClockRegression"
  - "internal/keystore: Custody/Role/CAKey/Backend/Provisioner contracts and backend registry; internal/keystore/agent backend selecting the CA key only by pinned SHA-256 fingerprint"
  - "internal/signerdb: SQLite state DB (WAL, synchronous=FULL, immediate tx) with serial_state and issuance tables, embedded migrations tracked by PRAGMA user_version"
  - "internal/signer, internal/signerclient: Signer.Serve/Issue, Listen, peer check; client Issue"
  - "scripts/build-openssh.sh: SHA-256-pinned, GPG-verified, cached non-root OpenSSH 9.5p1/10.5p1 builds; refuses 9.5p2"
  - "test/e2e harness (agent, sshd, signer, ssh login helpers) and TestIssueAcceptedBySSHD"
  - "Signing-boundary guards: TestSignCertOnlyInBuild, TestNoGenerateKeyOnSigningPath, TestGuardMatcherSelfCheck; forbidigo SignCert rule; depguard signer-no-network"
affects: [01-16, 01-04, 01-05, 01-06, 01-07, 01-13, 01-15, phase-2 server and enrollment]

actuals:
  tokens: 29043
  tasks: 2
  commits: 2
plan_head_before: 372f672023a5f5274e306139f2d3e4d47da8280c
plan_head_after: 14ec2595aa4634129438b7582b646d435e5a4a7b

tech-stack:
  added: [golang.org/x/crypto v0.57.0, golang.org/x/sys v0.48.0, modernc.org/sqlite v1.60.1, OpenSSH 10.5p1 and 9.5p1 (test oracle, built from source)]
  patterns:
    - "Signer is a separate Linux-only binary reached over a path-based Unix socket; authorization in this plan is the peer-credential allowlist (01-07 adds mandatory admin-sshsig/v1 evidence)"
    - "One framed request, one framed response, then close; 64 KiB frame cap before allocation; 10 s connection deadline"
    - "CA key chosen only by pinned SHA-256 fingerprint; certificate entries in the agent skipped; never a positional fallback"
    - "Serial = max(last+1, now in microseconds) from the DB high-water mark; issuance row and serial high-water mark commit in one transaction"
    - "Structural invariants enforced twice: a self-checking module-walking guard test plus a golangci-lint rule"

key-files:
  created:
    - internal/wire/frame.go
    - internal/wire/issue.go
    - internal/cert/builder.go
    - internal/cert/validate.go
    - internal/cert/keyid.go
    - internal/cert/signcert_guard_test.go
    - internal/serial/serial.go
    - internal/keystore/keystore.go
    - internal/keystore/registry.go
    - internal/keystore/agent/agent.go
    - internal/signerdb/db.go
    - internal/signerdb/migrate.go
    - internal/signerdb/issuance.go
    - internal/signerdb/migrations/0001_issuance.sql
    - internal/signer/signer.go
    - internal/signer/issue.go
    - internal/signer/server.go
    - internal/signer/peercred_linux.go
    - internal/signer/peercred_other.go
    - internal/signerclient/client.go
    - cmd/keyroster-signer/main.go
    - cmd/keyroster-signer/main_other.go
    - cmd/keyroster-signer/commands.go
    - cmd/keyroster-signer/serve.go
    - cmd/keyroster-signer/backends_linux.go
    - cmd/keyroster/ca.go
    - test/e2e/harness_test.go
    - test/e2e/issue_test.go
    - scripts/build-openssh.sh
  modified:
    - go.mod
    - go.sum
    - .golangci.yml

key-decisions:
  - "Wire length prefixes for variable fields are uint16 (cryptobyte has no uint32 length-prefixed reader); all field limits fit, the 64 KiB frame cap is unchanged"
  - "keyroster-signer serve applies syscall.Umask(0o077) at start, refuses an empty allowlist, caps concurrent connections at 32, and uses a single DB connection; SetLastSerial only ever raises the high-water mark"
  - "The socket's group is the first --allow-group; keyroster ca issue requires --subject and defaults --ttl to 1h"
  - "serial.Next waits a bounded time for the clock to reach the next serial and returns serial.ErrClockStalled instead of sleeping indefinitely"
  - "Finding for 01-13: go list -deps ./cmd/keyroster-signer (GOOS=linux) has no net/http or crypto/tls, but contains os/exec transitively via modernc.org/libc; depguard only catches direct imports, so the capslock/deps check in 01-13 must allowlist or examine that path"

patterns-established:
  - "Every certificate is produced by internal/cert.Build; adding another SignCert call fails TestSignCertOnlyInBuild and forbidigo"
  - "Signer packages (internal/signer, keystore, cert, serial, signerdb, wire, cmd/keyroster-signer) may not import net/http, net/rpc, net/smtp, crypto/tls, os/exec, html/template, text/template"
  - "e2e tests never skip silently: KEYROSTER_OPENSSH_PREFIX unset is t.Fatal"
  - "Linux-only binaries carry a //go:build !linux main_other.go that exits 1 with a clear message, so GOOS=windows go build ./... stays green"

requirements-completed: [CA-02, CA-03, CA-04, CA-05, CA-06, CA-07, CA-08, KEY-01, KEY-03, REPO-02]

coverage:
  - id: D1
    description: "keyroster ca issue -> Unix socket -> keyroster-signer -> user certificate signed by the pinned agent-held CA key (decoy loaded first) and accepted by real sshd 10.5p1"
    requirement: CA-08
    verification:
      - kind: e2e
        ref: "bash scripts/linux.sh 'bash scripts/build-openssh.sh 10.5p1 && KEYROSTER_OPENSSH_PREFIX=$HOME/.cache/keyroster/openssh-10.5p1 go test -tags e2e -count=1 -run TestIssueAcceptedBySSHD -v ./test/e2e/' -> --- PASS: TestIssueAcceptedBySSHD (Signing CA fingerprint == pinned, never the decoy)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Default user certificate carries exactly permit-pty, serial > 0, kr1/ca=user/ key ID"
    requirement: CA-05
    verification:
      - kind: e2e
        ref: "test/e2e/issue_test.go#TestIssueAcceptedBySSHD (ssh-keygen -L assertions)"
        status: pass
    human_judgment: false
  - id: D3
    description: "internal/cert.Build is the only SignCert call site and no signing-path file calls GenerateKey, with a matcher self-check"
    requirement: CA-06
    verification:
      - kind: unit
        ref: "go test -count=1 -run 'TestSignCertOnlyInBuild|TestNoGenerateKeyOnSigningPath|TestGuardMatcherSelfCheck' -v ./internal/cert/ (all three PASS; a temporary file in internal/signer referencing SignCert/GenerateKey failed both guards)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Lint rules forbidigo SignCert (excluded for internal/cert/) and depguard signer-no-network run in the required lint check"
    requirement: KEY-01
    verification:
      - kind: other
        ref: "golangci-lint config verify + 0 issues locally; PR #2 run 37202133865: build-test, lint, govulncheck, pr-title pass"
        status: pass
    human_judgment: false
  - id: D5
    description: "scripts/build-openssh.sh builds verified OpenSSH 10.5p1 non-root and refuses 9.5p2"
    requirement: CA-08
    verification:
      - kind: other
        ref: "bash scripts/linux.sh 'bash scripts/build-openssh.sh 9.5p2' exits 1; 10.5p1 build 177 s cold, 0 s cached"
        status: pass
    human_judgment: false
  - id: D6
    description: "Signer refusal rules (peer allowlist, principals, TTL, CA/cert/private-key subjects, duplicate request id, serial regression, missing pinned key, unknown backend option, newer schema)"
    requirement: CA-03
    verification:
      - kind: manual_procedural
        ref: "Ad-hoc refusal checks during Task 1 (not committed); named test tables and fuzz targets are plan 01-16's artifacts"
        status: pass
    human_judgment: true
    rationale: "Refusal behaviour was checked by hand only; plan 01-16 pins it with named tests before plan 01-04 starts"
  - id: D7
    description: "PR #2 is green with auto-merge on and waits for the owner's approval at the merge gate"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "bash scripts/merge-gate.sh p01/02-signer-skeleton -> exit 2 (awaiting owner approval)"
        status: pass
    human_judgment: true
    rationale: "The owner's approval and the squash merge happen at the Task 3 blocking-human merge gate, after this SUMMARY is written"

duration: 31min
completed: 2026-10-04
status: complete
---

# Phase 1 Plan 02: Signer Skeleton Summary

**`keyroster ca issue` talks over a peer-credential-checked Unix socket to a Linux-only `keyroster-signer`, which validates the request strictly, allocates a clock-floor serial in SQLite, signs through `internal/cert.Build` with the agent-held CA key chosen by pinned SHA-256 fingerprint, and returns a permit-pty-only user certificate that real sshd 10.5p1 accepts. A guard test and two lint rules lock the single SignCert call site and the network-free signer from the first merge. PR #2 is green and waits for the owner.**

## Performance

- **Duration:** 31 min (wall clock across the agent runs, from the recorded start)
- **Started:** 2026-10-04T12:05:08Z
- **Completed:** 2026-10-04T12:36:40Z
- **Tasks:** 2 of 3 executed before the merge gate (Task 3 is the owner's approval)
- **Files modified:** 32 (29 created, 3 modified), 3451 insertions

## Accomplishments

- Task 1 (tracer): the whole path from CLI to sshd login works. `TestIssueAcceptedBySSHD` loads a decoy Ed25519 key into the agent before the CA key, issues a certificate through the signer, logs in to OpenSSH 10.5p1 in WSL, and checks with `ssh-keygen -L` that the serial is above 0, the key ID starts `kr1/ca=user/`, `permit-pty` is the only extension, and the signing CA fingerprint is the pinned one and never the decoy's.
- Task 2: `internal/cert/signcert_guard_test.go` (three tests, one shared matcher, a self-check, non-zero-files assertions) and the `.golangci.yml` rules. A mutation check (a temporary file in `internal/signer` referencing SignCert and GenerateKey) made both guards fail as intended.
- PR #2 opened by keyroster-bot with auto-merge (squash); all four required checks pass.

## PR

- **PR #2** `feat(signer): issue certificates through keyroster-signer accepted by real sshd` (https://github.com/Labontese/keyroster/pull/2), branch `p01/02-signer-skeleton`, opened by keyroster-bot, auto-merge squash enabled.
- Required checks on the implementation head `14ec259` (run 37202133865): `build-test` pass, `lint` pass, `govulncheck` pass, `pr-title` pass.

## Recorded Facts

| Item | Value |
|---|---|
| OpenSSH 10.5p1 build (WSL, `scripts/build-openssh.sh 10.5p1`) | 177 s cold; 0 s with the `.keyroster-build` stamp cached |
| `build-openssh.sh 9.5p2` | exits 1, points to the manual Windows check in plan 01-15 |
| e2e oracle | OpenSSH 10.5p1, non-root sshd, `TrustedUserCAKeys` + `AuthorizedPrincipalsFile` |
| Signer DB | `journal_mode=WAL`, `synchronous=FULL`; refuses a schema newer than the binary |
| `go list -deps ./cmd/keyroster-signer` (GOOS=linux) | no `net/http`, no `crypto/tls`; `os/exec` present transitively via `modernc.org/libc` |

depguard rule (as committed in `.golangci.yml`):

```yaml
signer-no-network:
  list-mode: lax
  files:
    - "**/internal/signer/**"
    - "**/internal/keystore/**"
    - "**/internal/cert/**"
    - "**/internal/serial/**"
    - "**/internal/signerdb/**"
    - "**/internal/wire/**"
    - "**/cmd/keyroster-signer/**"
    - "!$test"
  deny:
    - pkg: net/http
      desc: the signer is network-less (KEY-01)
    - pkg: net/rpc
      desc: the signer is network-less (KEY-01)
    - pkg: net/smtp
      desc: the signer is network-less (KEY-01)
    - pkg: crypto/tls
      desc: the signer is network-less (KEY-01)
    - pkg: os/exec
      desc: the signer never runs other programs (KEY-01)
    - pkg: html/template
      desc: no templates in the signer (KEY-01)
    - pkg: text/template
      desc: no templates in the signer (KEY-01)
```

forbidigo: pattern `'\.SignCert\b'` (msg "certificates are signed only by internal/cert.Build (CA-06, CA-07)"), excluded by an `exclusions.rules` entry for `path: ^internal/cert/`, `linters: [forbidigo]`, `text: SignCert`.

## Task Commits

1. **Task 1: End-to-end keyroster ca issue -> keyroster-signer -> cert accepted by real sshd 10.5p1** - `70a5f61` (feat)
2. **Task 2: Structural guards of the signing boundary, and PR** - `14ec259` (test)
3. **Task 3: Merge gate** - no commit (owner approval; squash merge by GitHub)

**Plan metadata:** the `docs(01-02): complete signer skeleton plan` commit on the same PR branch.

## Files Created/Modified

- `internal/wire/{frame,issue}.go` - framing (64 KiB cap), message types, strict IssueRequest/IssueResponse/ErrorResponse codecs, SigningBytes/Digest
- `internal/cert/{builder,validate,keyid}.go` - Build (only SignCert site, post-sign verification), key and principal checks, kr1 key ID
- `internal/cert/signcert_guard_test.go` - module-wide SignCert/GenerateKey guard with matcher self-check
- `internal/serial/serial.go` - clock-floor serial allocator
- `internal/keystore/{keystore,registry}.go`, `internal/keystore/agent/agent.go` - CA key contracts, backend registry, ssh-agent backend
- `internal/signerdb/{db,migrate,issuance}.go`, `migrations/0001_issuance.sql` - state DB, migrations, issuance index
- `internal/signer/{signer,issue,server,peercred_linux,peercred_other}.go` - signer core, socket server, peer credentials
- `internal/signerclient/client.go` - client used by the CLI
- `cmd/keyroster-signer/*` - signer binary (`serve`, `version`; `!linux` stub)
- `cmd/keyroster/ca.go` - `keyroster ca issue`
- `test/e2e/{harness,issue}_test.go` - e2e harness and the sshd acceptance test
- `scripts/build-openssh.sh` - verified OpenSSH builds
- `.golangci.yml` - forbidigo SignCert rule, depguard signer-no-network
- `go.mod`, `go.sum` - x/crypto v0.57.0, x/sys v0.48.0, modernc.org/sqlite v1.60.1

## Decisions Made

See `key-decisions` above. In short: uint16 wire length prefixes; umask 0077, non-empty allowlist, 32-connection cap and a single DB connection in the signer; socket group from the first `--allow-group`; `--subject` required and `--ttl` 1h by default in the CLI; bounded clock wait in `serial`; the transitive `os/exec` finding is handed to 01-13.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Lint hygiene] Task 1 files adjusted in the Task 2 commit**
- **Found during:** Task 2 (running golangci-lint with the new rules)
- **Issue:** The existing linters flagged Task 1 code: a gosec G115 integer conversion, an `==` comparison against `ERANGE`, error strings without package prefixes, a nested key-ID check.
- **Fix:** justified `//nolint:gosec` on the bounded G115 conversion, `errors.Is` for ERANGE, package-prefixed errors, outdented key-ID check. No behaviour change.
- **Files modified:** Task 1 files in internal/ and cmd/
- **Verification:** golangci-lint 0 issues; CI lint pass
- **Committed in:** `14ec259`

**2. [Rule 3 - Blocking] go directive normalized to `1.26.0`**
- **Found during:** Task 1 (`go get` of the three modules)
- **Issue:** `go get` rewrote the `go 1.26` directive to `go 1.26.0`.
- **Fix:** accepted; same language version, toolchain still go1.27.1.
- **Files modified:** go.mod
- **Committed in:** `70a5f61`

**3. [Rule 2 - Missing critical] Additive helpers beyond the listed signatures**
- **Found during:** Task 1
- **Issue:** The contract needed small pieces it did not name.
- **Fix:** `wire.WriteMessage`/`ReadMessage`, `ParseIssueResponse`/`ParseErrorResponse`; `keystore.CheckOptions`/`Backends`; `serial.ErrClockStalled` with a bounded wait; sentinel errors in `internal/cert`; `signer.UserCAPublicKey`; signer hardening (umask 0077, empty allowlist refused, 32 concurrent connections, single DB connection, `SetLastSerial` only raises). All listed signatures are unchanged.
- **Files modified:** internal/wire, internal/keystore, internal/serial, internal/cert, internal/signer, internal/signerdb, cmd/keyroster-signer
- **Verification:** build, vet, unit tests, e2e pass
- **Committed in:** `70a5f61`

---

**Total deviations:** 3 auto-fixed (2 Rule 2, 1 Rule 3). **Impact:** no scope creep; the contract signatures other plans rely on are as planned.

## Issues Encountered

- `scripts/linux.sh` expands `$VAR` in the outer WSL shell, so multi-step Linux checks were run from script files.
- Read-only measurement commands for this SUMMARY were first denied by the permission classifier; the owner authorized them ("tillat-matning") and they ran in this continuation.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The owner approves PR #2 at the Task 3 merge gate; `bash scripts/merge-gate.sh p01/02-signer-skeleton` then waits for the auto-merge and fast-forwards local `main`.
- Plan 01-16 (wave 3) pins every refusal rule and edge case of this contract with named tests and four decoder fuzz targets; plan 01-04 adds the 9.5p1/10.5p1 CI matrix and sshd negative cases.
- Plan 01-13 must account for `os/exec` reaching the signer transitively via `modernc.org/libc`.

## Self-Check: PASSED

- Files present: all 32 files of the plan diff (`git diff --name-only 372f672..14ec259`), including `internal/cert/builder.go`, `internal/cert/signcert_guard_test.go`, `scripts/build-openssh.sh`, `test/e2e/issue_test.go`.
- Commits present: `70a5f61`, `14ec259` (both on origin/p01/02-signer-skeleton; `git rev-list --count 372f672..HEAD` = 2).
- Required checks on PR #2 head `14ec259`: all four pass.
