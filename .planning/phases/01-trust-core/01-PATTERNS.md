# Phase 1: Trust Core - Pattern Map

**Mapped:** 2026-10-04
**Files analyzed:** 22 (package/file groups from 01-RESEARCH.md "Recommended Project Structure" and CONTEXT.md D-01..D-15)
**Analogs found:** 0 / 22 in-repo (greenfield: repo holds only `.planning/` and `.claude/`, no Go source)

## File Classification

| New File / Package | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `go.mod` (`github.com/Labontese/keyroster`, go 1.26) | config | n/a | none | no in-repo analog |
| `tools/go.mod` | config | n/a | none | no in-repo analog |
| `LICENSE` (Apache-2.0), `README.md` (pre-alpha), `SECURITY.md`, `CONTRIBUTING.md` (bypass policy, D-05), `.github/CODEOWNERS`, `.github/dependabot.yml` | config/docs | n/a | none | no in-repo analog |
| `.github/workflows/ci.yml`, `codeql.yml`, `scorecard.yml`, `e2e.yml` | config (CI) | batch | none | no in-repo analog |
| `.golangci.yml` (forbidigo/depguard: only `internal/cert` calls `SignCert`) | config | n/a | none | no in-repo analog |
| `cmd/keyroster/` (ca init/issue, root init/sign, audit verify/export, doctor) | controller (CLI) | request-response | none | no in-repo analog |
| `cmd/keyroster-signer/` (serve, install-bundle) | controller (daemon) | request-response over UDS | none | no in-repo analog |
| `internal/wire/` | utility | transform (strict encode/decode, fuzzed) | none | no in-repo analog |
| `internal/cert/` (Builder) | service | transform | none | no in-repo analog |
| `internal/keystore/` (CAKey interface) | model/interface | request-response | none | no in-repo analog |
| `internal/keystore/agent/` | service | request-response (ssh-agent) | none | no in-repo analog |
| `internal/keystore/tpm/` | service | request-response (TPM) | none | no in-repo analog |
| `internal/keystore/piv/` (`//go:build piv`) | service | request-response | none | no in-repo analog |
| `internal/keystore/soft/` | service | file-I/O (age-encrypted key) | none | no in-repo analog |
| `internal/sshsig/` | utility | transform | none | no in-repo analog |
| `internal/trust/` (bundle + genesis policy, threshold verify) | model | transform | none | no in-repo analog |
| `internal/tlog/` (leaf, compact range, checkpoint, ECDSA 0x02 note signer) | service | append-only/CRUD | none | no in-repo analog |
| `internal/serial/` | utility | transform (pure, injectable clock) | none | no in-repo analog |
| `internal/signer/` (evidence check, log-before-release tx, refusal rate-limit D-14, UDS server) | service | request-response + event (audit) | none | no in-repo analog |
| `internal/signerdb/` + embedded `migrations/*.sql` | migration/model | CRUD | none | no in-repo analog |
| `internal/rootceremony/` (must not import `internal/cert`) | service | file-I/O | none | no in-repo analog |
| `test/e2e/` (`//go:build e2e`), `test/vectors/`, `deploy/systemd/keyroster-signer.service` | test / config | batch | none | no in-repo analog |

## Pattern Assignments

No in-repo analogs exist. Planner should take patterns from the external references already cited (with line numbers) in `01-RESEARCH.md`; do not invent internal conventions beyond those:

| Package | External pattern source (per RESEARCH.md) |
|---|---|
| `internal/cert` | `golang.org/x/crypto` v0.57.0 `ssh/certs.go` (`SignCert` 470-510, cert-authority refusal 475-480, tuple sort 130-135; do NOT use `CertChecker` for policy, see 422) |
| `internal/keystore/agent` | x/crypto `ssh/keys.go:1206` `NewSignerFromSigner`, `ssh/agent` client `Signers()`; `smallstep/crypto/kms` sshagentkms as reference design only |
| `internal/keystore/tpm` | `foxboron/go-tpm-keyfiles` (`NewLoadableKey`, `Signer`, `SignASN1` DER at tpm.go:436), `google/go-tpm` `linuxtpm.Open` |
| `internal/keystore/piv` | `go-piv/piv-go/v2` v2.6.0 (cgo, build-tagged) |
| `internal/sshsig` | OpenSSH `PROTOCOL.sshsig`; oracle `ssh-keygen -Y sign/verify` |
| `internal/tlog` | `transparency-dev/merkle` (D-15), `x/mod/sumdb/note` (note.go:86, 192-213 interfaces), C2SP signed-note/checkpoint specs (ECDSA type 0x02 key ID) |
| `internal/trust` | C2SP signed-note; OpenSSH `PROTOCOL.krl` (KRL authority only; encoder deferred to Phase 3; reference `go-authn/krl`, OpenSSH `krl.c`) |
| `internal/signerdb` | `modernc.org/sqlite` driver `"sqlite"`, DSN `_pragma`/`_txlock`; in-house `PRAGMA user_version` migrations |
| `internal/rootceremony`, `keystore/soft` | `filippo.io/age` v1.3.2 |
| `test/e2e` | OpenSSH portable 9.5p1 + 10.5p1 (SHA-256 pinned), `regress/` tests; SoftHSM2 via `ssh-pkcs11-helper`; swtpm |

## Shared Patterns

Conventions to be established in this phase (from RESEARCH.md/CLAUDE.md, not from code):
- Domain-separation strings prefixed `keyroster/` (D-01), e.g. `keyroster/trust-bundle/v1`; SSHSIG namespace under same prefix (D-13).
- Algorithm recorded in every bundle/log entry (D-09): Ed25519 or ECDSA P-256.
- `CGO_ENABLED=0` everywhere except `-tags piv`.
- Signer dependency firewall: `go list -deps ./cmd/keyroster-signer` excludes `net/http`, `crypto/tls`, templates, `os/exec`.
- Logging via `log/slog`; randomness only `crypto/rand`.
- Every parser fuzzed; golden vectors under `test/vectors/`.
- GitHub Actions pinned by SHA, `permissions: {}` default.

## No Analog Found

All 22 entries above. Reason: greenfield repository with no source code.

## Metadata

**Analog search scope:** repository root (only `.planning/`, `.claude/` present)
**Files scanned:** 2 (01-CONTEXT.md, 01-RESEARCH.md)
**Pattern extraction date:** 2026-10-04
