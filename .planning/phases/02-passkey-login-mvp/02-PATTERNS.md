# Phase 2: Passkey Login MVP - Pattern Map

**Mapped:** 2026-10-10
**Files analyzed:** 30 (new + modified, grouped by package)
**Analogs found:** 26 / 30

All analog paths below are git-tracked (checked with `git ls-files`). No `internal/server`, `internal/serverdb`, `internal/webauthn`, `internal/directory`, `internal/keystore/software` or `cmd/keyroster-server` exists yet.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/directory/directory.go` (Directory, Validate, Parse, Canonical) | model (signed doc) | transform | `internal/trust/policy.go` + `internal/trust/canonical.go` | exact |
| `internal/directory/verify.go` (quorum + successor chain) | utility | transform | `internal/trust/verify.go` (`CountPinnedSigners`, `checkSuccessorChain`) + `internal/trust/successor.go` | exact |
| `internal/directory/principals.go` (Principals(), RenderPrincipalsFile) | utility | transform | `internal/cert/validate.go` (`ValidatePrincipals`, `principalRE`) | role-match |
| `internal/directory/*_test.go`, `fuzz_test.go` | test | — | `internal/trust/fuzz_test.go`, `internal/trust/successor_test.go`, `internal/trust/vectors_test.go` | exact |
| `internal/webauthn/verify.go` (assertion verifier, stdlib) | utility (parser+verifier) | transform | `internal/signer/evidence.go` (shape) + RESEARCH Code Example | partial |
| `internal/webauthn/clientdata.go` (json Token walk) | utility (parser) | transform | none in repo (strictness idea from `internal/trust/canonical.go` `decodeStrict`) | partial |
| `internal/webauthn/fuzz_test.go`, oracle test | test | — | `internal/wire/fuzz_test.go`, `internal/sshsig/oracle_test.go` | exact |
| `internal/wire/frame.go` (new types, per-type cap) | model (wire) | request-response | itself | modify |
| `internal/wire/login.go` (LoginIssueRequest), `directory.go`, `status.go` | model (wire) | request-response | `internal/wire/issue.go` | exact |
| `internal/wire/fuzz_test.go` (new targets) | test | — | `internal/wire/fuzz_test.go` `FuzzParseIssueRequest` | exact |
| `internal/signer/evidence_webauthn.go` | service (authz) | request-response | `internal/signer/evidence.go` `verifyAdminEvidence` | exact |
| `internal/signer/server.go` (dispatch by msgType) | controller | request-response | itself, `handle` lines 130-182 | modify |
| `internal/signer/login.go` (LoginIssue) | service | request-response | `internal/signer/issue.go` `Issue` lines 49-~210 | exact |
| `internal/signer/directory.go` (online install, get) | service | CRUD | `internal/signer/trust.go` + `checkTrustCurrent` (issue.go:220) | role-match |
| `internal/signer/status.go` (custody report) | service | request-response | `internal/signer/trust.go` openRoleKey (~362-380) | role-match |
| `internal/signerdb/migrations/0004_directory.sql` + `directory.go` | migration / model | CRUD | `internal/signerdb/migrations/0003_trust.sql`, `internal/signerdb/trust.go` | exact |
| `internal/tlog/leaf.go` (KindDirectoryInstall=7, KindLoginIssue=8) | model | transform | itself, lines 36-67 | modify |
| `internal/cert/keyid.go` (kr2) | utility | transform | itself | modify |
| `internal/audit/verify.go` (directory chain, login leaf checks) | service | batch | itself (around 303-310) | modify |
| `internal/keystore/software/software.go` | provider (backend) | file-I/O | `internal/keystore/registry.go` + `internal/rootceremony/keygen.go` (age) + `internal/keystore/tpm/tpm.go` | role-match |
| `internal/trust/policy.go` (`WebAuthn *WebAuthnRP` omitempty) | model | transform | itself | modify |
| `internal/signerclient/client.go` (Login, InstallDirectory, GetDirectory, Status) | service (client) | request-response | itself, `Issue` | exact |
| `internal/serverdb/db.go`, `migrate.go`, `migrations/0001_*.sql` | model / migration | CRUD | `internal/signerdb/db.go`, `internal/signerdb/migrate.go` | exact |
| `cmd/keyroster-server/main.go` | config/entry | request-response | `cmd/keyroster-signer/main.go`, `serve.go` | role-match |
| `internal/server/*.go` (handlers, sessions, headers, TLS reload) | controller | request-response | none (no HTTP in repo) | none |
| `internal/server/web/templates/*.html`, `static/app.js`, `app.css` | component | request-response | none | none |
| `cmd/keyroster/{login,init,user,role,group,host}.go` | controller (CLI) | request-response | `cmd/keyroster/trust.go` (subcommand group), `cmd/keyroster/ca.go` (agent signing) | exact |
| `cmd/keyroster/agent_unix.go` / `agent_windows.go`, `browser_*.go` | utility (platform) | event-driven | `cmd/keyroster/root.go` `dialAgent`/`agentSigner` (~40, 636-654); `internal/rootceremony/readfd_{unix,windows,other}.go` (build-tag split) | role-match |
| `.golangci.yml`, `scripts/dep-firewall.sh`, `test/capslock/keyroster-signer.json`, `scripts/fuzz.sh` | config | — | themselves | modify |
| `test/e2e/login_test.go` (+ `harness_test.go` addLogKey removal) | test | — | `test/e2e/issue_test.go`, `test/e2e/harness_test.go` | exact |
| `docs/security/custody.md`, `docs/security/needs-hardware.md`, runbook for server | docs | — | themselves, `docs/runbooks/signer-install.md` | modify |

## Pattern Assignments

### `internal/directory/directory.go` (signed document)

**Analog:** `internal/trust/policy.go` lines 11-80, `internal/trust/canonical.go` lines 14-47.

Struct + namespace constant + Parse/Canonical/Validate trio (policy.go):
```go
type Policy struct {
	Version         uint64      `json:"version"`
	Prev            string      `json:"prev"`
	AdminQuorum     uint32      `json:"admin_quorum"`
	...
}
const NamespacePolicy = "keyroster/policy/v1"

func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := decodeStrict(data, &p); err != nil { return nil, err }
	if err := p.Validate(); err != nil { return nil, err }
	return &p, nil
}
func (p *Policy) Canonical() ([]byte, error) { return canonical(p) }
func (p *Policy) Validate() error {
	if p.Version < 1 { return fmt.Errorf("%w: policy version must be >= 1", ErrInvalid) }
	if !isHash(p.Prev) { return fmt.Errorf("%w: policy prev must be 64 lowercase hex digits", ErrInvalid) }
```
Strict decode (canonical.go:33-46) — byte equality against re-encoding:
```go
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil { return fmt.Errorf("%w: %w", ErrNotCanonical, err) }
	c, err := canonical(v)
	...
	if !bytes.Equal(c, data) { return ErrNotCanonical }
	return nil
}
```
`canonical`/`decodeStrict`/`isHash` are unexported in `internal/trust`. Planner choice: either export them (e.g. `trust.DecodeStrict`, `trust.Canonical`) or put the directory in a sibling file inside `internal/trust`. Do not copy the helper (one canonical rule). Lists non-null and sorted (01-06 decision), so validate sort order and duplicates in `Validate`.

### `internal/directory/verify.go` (quorum + chain)

**Analog:** `internal/trust/verify.go:23-57` `CountPinnedSigners` — reuse directly, do not reimplement:
```go
func CountPinnedSigners(doc, sigs []byte, namespace string, pinned map[string]ssh.PublicKey) ([]string, error)
```
Build `pinned` from `pol.Admins` the same way `verifyAdminEvidence` does (evidence.go:27-34: `trust.ParseKey(a.Key)`, key by `ssh.FingerprintSHA256(pub)`). Chain rule: copy `BuildSuccessor`/`checkSuccessorChain` shape from `internal/trust/successor.go:22-47` (`Version: prev.Version + 1`, `Prev: SHA256Hex(prevCanonical)`, Validate first, chain second, reuse sentinel `ErrVersionChain`-style errors).

### `internal/directory/principals.go`

**Analog:** `internal/cert/validate.go` — `principalRE` (line 37) and `MaxPrincipals = 32` (line 30). Call `cert.ValidatePrincipals`; never a second regex. `RenderPrincipalsFile` is shared by `keyroster host principals` and the Phase 3 agent.

### `internal/webauthn/*` (signer-safe verifier)

**Analog for shape:** `internal/signer/evidence.go` — default deny, one named reason per failure. In `internal/webauthn` return typed sentinel errors (`errRPMismatch`, `errNoUV`, ...); the signer maps each to `refusalErr(wire.CodeRefused, "<name>", err)` exactly like evidence.go:36-62. Core verify body: RESEARCH.md "Signer-side assertion check" (lines 762-822). Imports stdlib only; add the package to depguard `signer-no-network`.

**Tests:** fuzz like `internal/wire/fuzz_test.go:9-40` (seed corpus from a valid vector plus mutations, assert only sentinel errors). Differential oracle against go-webauthn in a test outside the signer graph, modelled on `internal/sshsig/oracle_test.go` (oracle vs. own implementation). Soft authenticator helper: RESEARCH.md lines 824-837.

### `internal/wire/login.go`, `directory.go`, `status.go`

**Analog:** `internal/wire/issue.go`.
- Domain constant pattern (lines 11-23): `const LoginRequestDomain = "keyroster/login-request/v1"`, `const EvidenceWebAuthnAssertion = "webauthn-assertion/v1"`.
- Limits block (lines 25-39) — reuse `MaxPrincipals`, `MaxEvidenceBlob` etc.
- Methods to mirror: `check()` (95), `addFields` (129) using `addBytes16`, `Marshal` (150), `SigningBytes` (168, raw domain tag then fields minus Evidence), `Digest` (183), `ParseIssueRequest` (189) using `readBytes16(&s, &x, Max...)` and `!s.Empty()`, errors wrapped in `ErrMalformed`.
- Do NOT change `IssueRequest`, `TypeIssueRequest` or `IssueRequestDomain` bytes.

**`internal/wire/frame.go` modify:** add types after line 26-28 (`0x02/0x82`, `0x03/0x83`, `0x04/0x84`, `0x05`). `ReadFrame` (38-56) currently refuses `n > MaxFrame` before allocating; per-type cap needs the 2-byte header read first, still before allocating the body.

### `internal/signer/evidence_webauthn.go`

**Analog:** `internal/signer/evidence.go` lines 23-70 (copied structure):
```go
func verifyAdminEvidence(req *wire.IssueRequest, pol *trust.Policy) ([]string, error) {
	if pol == nil || pol.AdminQuorum < 1 {
		return nil, refusalErr(wire.CodeRefused, "no_policy", nil)
	}
	...
	if len(req.Evidence) == 0 {
		return nil, refusalErr(wire.CodeRefused, "missing_evidence", nil)
	}
	for _, ev := range req.Evidence {
		if ev.Type != wire.EvidenceAdminSSHSIG {
			return nil, refusalErr(wire.CodeRefused, "unknown_evidence_type", nil)
		}
```
Refusal names and check order: RESEARCH.md Pattern 2 (lines 566-594).

### `internal/signer/login.go` (LoginIssue)

**Analog:** `internal/signer/issue.go` `Issue` (from line 49). Copy the sequence verbatim after the evidence step:
```go
s.mu.Lock(); defer s.mu.Unlock()
now := s.clock()
created := time.Unix(int64(min(req.CreatedAt, uint64(1)<<62)), 0) //nolint:gosec
if d := now.Sub(created); d > maxClockSkew || d < -maxClockSkew {
	return nil, refusalErr(wire.CodeRefused, "request_time_skew", nil)
}
// evidence -> CA key/profile -> parse SubjectKey -> extensions dedupe
if err := s.checkTrustCurrent(s.db.LatestBundleVersion(ctx)); err != nil { return nil, err }
switch used, err := s.db.RequestIDUsed(ctx, req.RequestID); { ... "duplicate_request" ... }
last, err := s.db.LastSerial(ctx) ; ser, err := serial.Next(last, s.clock, time.Sleep)
```
Add a `checkDirectoryCurrent` alongside `checkTrustCurrent` (issue.go:220) and re-check inside the issuance transaction. Refusals go through `buildRefusal` (issue.go:233) / `s.refuse` (logged, P1 D-14).

### `internal/signer/server.go` (modify `handle`)

Current single-type gate (lines 150-156 of file):
```go
msgType, body, err := wire.ReadMessage(conn)
if err != nil { s.reply(conn, s.refuse(ctx, peer, [32]byte{}, tlog.ReasonMalformed, "malformed_frame")); return }
if msgType != wire.TypeIssueRequest {
	s.reply(conn, s.refuse(ctx, peer, [32]byte{}, tlog.ReasonMalformed, "unknown_message_type"))
	return
}
```
Replace with a `switch msgType`; keep peer allowlist before any read, keep `unknown_message_type` default, keep "request bytes are never echoed" in `reply`.

### `internal/signer/directory.go`, `status.go`; `internal/signerdb/` additions

**Analogs:** `internal/signerdb/migrations/0003_trust.sql` (table-per-document with canonical bytes + detached sigs, comment header per table), `internal/signerdb/trust.go` (store/load), `internal/signerdb/migrate.go:24-53` (NNNN_ names, no gaps; new file must be `0004_*.sql`). Online install under `s.mu`, one transaction for store + `KindDirectoryInstall` leaf + checkpoint (RESEARCH Pattern 1 steps 1-6). Custody for status comes from `ca_keys.custody` (0003_trust.sql) / openRoleKey in `internal/signer/trust.go`.

### `internal/tlog/leaf.go` (modify)

Lines 36-67: add `KindDirectoryInstall Kind = 7`, `KindLoginIssue Kind = 8`, extend `String()` and `valid()` (`k <= KindLoginIssue`), update the "complete for format v1" comment. Use `MaxDocument` (1<<20) and `MaxKeyID` (1024). Add golden vectors in `test/vectors/` like `leaf_issue_v1.hex` and fuzz seeds in `internal/tlog/fuzz_test.go`.

### `internal/cert/keyid.go` (modify, kr2)

Copy the strict parser shape (lines 40-82): `CutPrefix`, `strings.Split(rest, "/")`, fixed `names` array, `Cut(part, "=")`, regex per field, `parseDecimal`. Add a `kr2/` branch with names `ca, sub, req, pol, dir, roles, ser`; keep `kr1` untouched. Tests extend `internal/cert/keyid_test.go`.

### `internal/keystore/software/software.go` (KEY-06)

- Registration: `keystore.Register("software", factory)` from `init` (registry.go:22-32); factory calls `keystore.CheckOptions(opts, ...)` (64-76); `OptStateDir` gives `{state-dir}/software/{role}.age`.
- Interface: `Backend{Key(role, fingerprint) (CAKey, error); Close() error}`, `Provisioner{Provision(roles) (map[Role]ssh.PublicKey, error)}`, `CAKey{ssh.Signer; Custody(); Algorithm()}` (keystore.go:51-84). `Custody()` returns `keystore.CustodySoftware`.
- age encrypt/decrypt: copy from `internal/rootceremony/keygen.go` lines 49-66 (scrypt recipient + armor writer) and 89-100 (`age.NewScryptIdentity`, `armor.NewReader`, `io.LimitReader`, `defer clear(plain)`). Do NOT import `internal/rootceremony` (KEY-07 import rule enforced by `internal/rootceremony/imports_test.go`).
- Wire into signer: `cmd/keyroster-signer/backends_linux.go` (blank import, like the TPM/agent backends).

### `internal/trust/policy.go` (modify)

Append `WebAuthn *WebAuthnRP \`json:"webauthn,omitempty"\`` as the LAST field of `Policy` (after `TimelockSeconds`, line 21). Validation in `Validate()` with `ErrInvalid` wrapping like lines 75-80. Regression test: `test/vectors/policy_genesis_v1.json` must still pass `ParsePolicy` (see `internal/trust/vectors_test.go`).

### `internal/signerclient/client.go` (extend)

Copy `Issue` (lines 21-60) per message: default timeout, `DialContext("unix")`, `SetDeadline`, `WriteMessage`, `ReadMessage`, switch on response type with `TypeError -> ParseErrorResponse`. Factor the dial/send/receive into one private `roundTrip(ctx, socket, msgType, body)` helper rather than copying four times.

### `internal/serverdb/*`

**Analog:** `internal/signerdb/db.go` + `migrate.go` (embedded `migrations/*.sql`, `PRAGMA user_version`, refuse newer DB). Separate file from the signer DB; tables: pending users/invites (token hash only), pending credentials, web sessions, login sessions (code hash, code_challenge, state, port, expiry, used). Non-authoritative.

### `cmd/keyroster/{login,init,user,role,group,host}.go`

**Analog:** `cmd/keyroster/trust.go` lines 20-45 (one file per command group, `init()` → `register(command{...})`, `switch args[0]` subcommands, `flag.NewFlagSet(..., flag.ContinueOnError)` + `fset.SetOutput(stderr)`, unknown subcommand → `errUsage`):
```go
func init() {
	register(command{Name: "trust", Summary: "trust bundle operations (verify)", Run: runTrust})
}
func runTrust(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 { _, _ = fmt.Fprintln(stderr, "usage: keyroster trust verify [flags]"); return errUsage }
	switch args[0] {
	case "verify": return runTrustVerify(ctx, args[1:], stdout, stderr)
	default: _, _ = fmt.Fprintf(stderr, "keyroster trust: unknown subcommand %q\n", args[0]); return errUsage
	}
}
```
Registry/dispatch in `cmd/keyroster/commands.go` needs no change. Admin signing of directory versions: reuse `agentSigner(pub)` (`cmd/keyroster/root.go:636-654`) and the admin-key selection flags in `cmd/keyroster/ca.go` (~67, 134-146) with `sshsig.Sign`. Local bundle verification reuses `runTrustVerify`/`loadPrev`/`verifySuccessorBundle` helpers in `cmd/keyroster/trust.go`. Tests: `cmd/keyroster/trust_test.go`, `commands_test.go`.

### `cmd/keyroster/agent_*.go`, `browser_*.go`

**Analog:** `cmd/keyroster/root.go` `dialAgent` (SSH_AUTH_SOCK, ~line 40) — move it into `agent_unix.go` and add `agent_windows.go` (`//go:build windows`, go-winio `DialPipe(\\.\pipe\openssh-ssh-agent)`). Build-tag file split pattern: `internal/rootceremony/readfd_unix.go` / `readfd_windows.go` / `readfd_other.go`. Never retry `Add` without `LifetimeSecs` (RESEARCH Pitfall 1).

### `test/e2e/login_test.go`

**Analog:** `test/e2e/issue_test.go` + harness helpers in `test/e2e/harness_test.go` (`startDaemon` 128, `startAgent` 199, `startSSHD` 270, `sshLogin` 332, `waitFor` 159). Every refusal case paired with a succeeding control (01-04 rule). Remove unused `addLogKey` (line 235) in the same plan (deferred debt).

## Shared Patterns

### Refusals (signer)
**Source:** `internal/signer/issue.go:36` `refusalErr(code, reason, cause)`, `buildRefusal` (233), `s.refuse` in `server.go`. **Apply to:** all new signer paths (login, directory install, status). Every refusal logged and rate-limited (P1 D-14); only the code leaves the process.

### Canonical signed JSON + SSHSIG quorum
**Source:** `internal/trust/canonical.go`, `internal/trust/verify.go:29` `CountPinnedSigners`, `internal/sshsig`. **Apply to:** directory, policy RP change, admin CLI.

### Strict binary wire parsing
**Source:** `internal/wire/issue.go` `addBytes16`/`readBytes16` (373-386), `ErrMalformed`, `!s.Empty()`. **Apply to:** all new wire messages, the `webauthn-assertion/v1` evidence blob.

### Fuzz every parser
**Source:** `internal/wire/fuzz_test.go`, `internal/trust/fuzz_test.go`, `internal/tlog/fuzz_test.go`; register targets in `scripts/fuzz.sh`. **Apply to:** wire login/directory/status parsers, directory parser, clientDataJSON parser, assertion verifier, kr2 key ID.

### Dependency gates
**Source:** `.golangci.yml` lines 38-53 (`signer-no-network` file list), `scripts/dep-firewall.sh` (`go list -deps ./cmd/keyroster-signer`), `test/capslock/keyroster-signer.json` via `scripts/capslock-check.sh`. **Apply to:** add `**/internal/webauthn/**`, `**/internal/directory/**` (keystore/software already covered by `**/internal/keystore/**`); go-webauthn only under `cmd/keyroster-server`/`internal/server`; go-winio only in `//go:build windows` CLI files.

### Custody warning text
**Source:** `internal/doctor/doctor.go` `CodeSoftwareKey` (85) and the `SOFTWARE ROOT` message style (271-273). **Apply to:** one Go constant quoted by server banner and CLI stderr; wording added to `docs/security/custody.md` first.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `internal/server/*.go` (HTTP handlers, CSP headers, `CrossOriginProtection`, sessions, rate limits, TLS reload via `GetCertificate` + `atomic.Pointer`) | controller | request-response | No HTTP code exists in repo (signer is network-less). Use RESEARCH.md Pattern/Pitfalls 3-8, 12 and STACK.md "Web UI" headers. |
| `internal/server/web/templates/*.html`, `static/app.js`, `app.css` | component | request-response | No UI exists. Use RESEARCH Pitfalls 3-5 (connect-src 'self', JSON data block, fetch then `location.assign`). |
| `internal/webauthn/clientdata.go` | parser | transform | No json Token-walk parser in repo; RESEARCH Q3 specifies it. |
| CLI loopback listener (`cmd/keyroster/login.go` part) and Windows option-A in-memory agent | utility | event-driven | No listener code in CLI; RESEARCH Pitfall 12 and Q5 option A. |

## Metadata

**Analog search scope:** `cmd/`, `internal/`, `test/`, `scripts/`, `.golangci.yml`, `docs/`
**Files scanned:** ~25 read/grepped
**Pattern extraction date:** 2026-10-10
