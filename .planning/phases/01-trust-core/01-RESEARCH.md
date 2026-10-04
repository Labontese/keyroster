# Phase 1: Trust Core - Research

**Researched:** 2026-10-04
**Domain:** Go SSH certificate authority core: a network-less signer with hardware keystores, an offline trust root, a Merkle audit log, a real-sshd test oracle, and GitHub supply-chain hygiene
**Confidence:** MEDIUM-HIGH. Library APIs and versions are HIGH: module sources were downloaded from proxy.golang.org and read. OpenSSH facts are HIGH: release notes, tarballs and the regress source were checked. GitHub settings are MEDIUM (docs fetched). The swtpm transport and Windows-runner details are LOW or ASSUMED and are flagged for a spike.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

#### Project identity and repository
- **D-01:** The final project name is **keyroster** (it replaces the working names "ssh-cert-manager" and "sshcm"). The Go module is `github.com/Labontese/keyroster`. Binaries are `keyroster` (CLI), `keyroster-signer`, `keyroster-server` and `keyroster-agent`; every `sshcm*` name in the research docs maps to these. Domain-separation strings in signed formats use the `keyroster/` prefix (e.g. `keyroster/trust-bundle/v1`). — **Reversibility:** one-way — agents pin signed formats containing the domain-separation strings, and the Go module path is a published import path.
- **D-02:** A collision search was done on 2026-10-04. `keyward` is an existing SSH-key TUI, `keysteward` is a commercial KMS (PRONIT), `sshledger` conflicts with Ledger's SSH agent, and "ssh" in the product name was avoided because SSH Communications Security holds the "SSH" trademark. `keyroster` had no same-name repos and no products found. The GitHub *user* `keyroster` exists (inactive), so the repo lives under `Labontese`.
- **D-03:** The license is **Apache-2.0**. — **Reversibility:** costly — relicensing needs consent from every contributor once outside contributions arrive.
- **D-04:** The repo is **public from the first commit** at `github.com/Labontese/keyroster`. The README states clearly that the project is pre-alpha and must not be used in production. Public visibility is what makes CodeQL, secret scanning with push protection, private vulnerability reporting, rulesets and Scorecard available for free (REPO-01, REPO-03).
- **D-05:** **Required review uses a separate bot account for Claude** (e.g. `keyroster-bot`, final name at the planner's discretion) with its own SSH signing key. Claude commits, pushes and opens PRs from that account, and the owner (Labontese) reviews and approves them, so the two identities are real. The owner's own PRs merge through a documented ruleset bypass for the admin role, which GitHub logs. Document the bypass policy in CONTRIBUTING.md. The bot needs only the minimal repo permissions (write to branches, open PRs) and must not be able to bypass rulesets.
- **D-06:** **Commits are signed with SSH signing using regular ed25519 keys** held in ssh-agent (no FIDO touch per commit): the owner's existing key, and a separate key for the bot. Add both as signing keys on their GitHub accounts and require signed commits in the ruleset. Release signing is a separate concern (Phase 6: cosign plus a maintainer SSHSIG).

#### Hardware, custody and CA algorithm
- **D-07:** The owner's homelab has **only TPM 2.0**, with no YubiKey, YubiHSM or other token. Dogfooding of hardware custody in Phase 1 therefore means TPM.
- **D-08:** **`keyroster-signer` runs in a Proxmox VM with a vTPM** in the homelab, holding the online CA keys in the vTPM. This is a known, accepted weakness: vTPM state is a file on the Proxmox host, so whoever controls the host controls the keys. Document it as weaker than a physical TPM but stronger than a software key, and have `doctor`/docs state it. Signer sandboxing (own OS user, systemd hardening, UDS) applies inside the VM.
- **D-09:** **The CA algorithm depends on the backend.** It is Ed25519 when the backend supports it (software, YubiHSM 2 via PKCS#11, YubiKey PIV with firmware ≥ 5.7) and ECDSA P-256 on TPM. The signer, the cert builder and the bundle format are algorithm-agnostic, and each CA's algorithm is recorded in the trust bundle and the audit log. The homelab's user, host and machine CAs are therefore P-256. — **Reversibility:** costly — the bundle and policy formats must carry the algorithm from day one, and adding it later would mean a format version bump and re-pinning.
- **D-10:** **The offline trust root is a software root on offline media**, a deliberate deviation from the "M-of-N hardware keys" wording in success criterion 2 *for the homelab only*. The ceremony generates **two independent Ed25519 root keys**, each age-encrypted with its own passphrase and stored on its own USB stick. The root threshold is **1-of-2**: agents accept a bundle signed by either key. This is the same M-of-N model the hardware path uses (independent keys plus a threshold), so moving to YubiKeys (ed25519-sk or PIV) later is a ceremony and re-sign, not a format change. Shamir secret-sharing was rejected because it would be a second, incompatible model.
- **D-11:** The tooling must still **support hardware root keys** (ed25519-sk / PIV) so that success criterion 2 holds for the product. Verify this in CI with a software FIDO/PIV stand-in. The homelab's use of a software root is the only deviation, and it must be visible: ceremony output and `doctor` flag the root as software-held.
- **D-12:** **The PKCS#11/YubiHSM backend (KEY-03) and the PIV backend (KEY-05) are verified in CI only in Phase 1.** PKCS#11 runs against SoftHSM2 through OpenSSH `ssh-agent` + `ssh-pkcs11-helper`. PIV is built behind a build tag and unit-tested against the `Signer` interface. Track real-hardware tests for both (and a hardware root ceremony) as an explicit "needs hardware" item for the Phase 6 review. KEY-05 stays in Phase 1 and is not deferred.

Also locked (CONTEXT.md §Phase Boundary): Go with `CGO_ENABLED=0`, SQLite with the signer as the only log writer, "the server proposes, the signer disposes", separate user, host and machine CAs, a root that signs only bundles, KRL authority and policy (never certificates), backend build order (software → ssh-agent/PKCS#11 → TPM → build-tagged PIV), and a KRL encoder deferred to Phase 3 (Phase 1 only defines the KRL authority in the bundle format).

### Claude's Discretion
- How the offline root ceremony is executed (offline machine or live USB, the exact steps, how the root public keys and genesis policy are distributed). The owner did not select this area. Stay within D-10/D-11, and prefer a design a single admin can run safely from a runbook.
- Signer operations and admin CLI ergonomics: the `keyroster ca init` flow, and the output and export format of `keyroster audit verify`. The owner did not select this area. Follow the research (UDS, own OS user, C2SP checkpoints, `sumdb/note`).
- The CI OpenSSH version matrix (it must include 9.5p2 and the latest release, per CA-08), the Dependabot cadence, and the CODEOWNERS layout.
- The bot account's exact name and permission set (within D-05).

### Deferred Ideas (OUT OF SCOPE)
- Buying two FIDO2 security keys to move the root, and later passkeys, to hardware. The owner chose a software root for now, so this is a possible future ceremony rather than a roadmap item.
- Real-hardware verification of YubiHSM 2 and YubiKey PIV backends, plus a hardware root ceremony, belongs in the Phase 6 security-review checklist.
- Updating PROJECT.md and `.claude/CLAUDE.md` from the working name "ssh-cert-manager" to keyroster (and the "hash chain" wording to the Merkle log). Do this at the Phase 1 transition or as part of repo bootstrap.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REPO-01 | Protected `main` via rulesets: PR only, required checks, required review, signed commits, linear history, no force-push | Two-ruleset design (integrity ruleset with no bypass; review ruleset with an admin bypass in `pull_request` mode); squash-only merging; SSH signing setup for owner and bot (Pattern 9, Pitfalls 10-12) |
| REPO-02 | CI: build, test, lint, govulncheck, fuzzing, e2e against real sshd; SHA-pinned actions with least privilege | Action SHAs resolved 2026-10-04; workflow skeleton; OpenSSH-from-source e2e harness running a non-root sshd; fuzz loop (Pattern 8, Code Examples) |
| REPO-03 | CodeQL, Dependabot (gomod + actions), secret scanning with push protection, Scorecard | Advanced CodeQL workflow for Go; Dependabot config; Scorecard action v2.4.4; API calls to enable the security features |
| REPO-04 | SECURITY.md with private vulnerability reporting; README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS, templates | File list, plus the `PUT .../private-vulnerability-reporting` call; CONTRIBUTING documents the bypass policy (D-05) |
| CA-01 | Separate user, host and machine CAs, each with its own key | `keyroster ca init` creates user, host, machine, ops and log keys in one backend; each key is listed in the bundle with role, algorithm and custody (Pattern 5) |
| CA-02 | Refuse empty, wildcard, comma, whitespace and control-character principals | An allowlist validator inside the cert builder, the only path to `SignCert` (Pattern 2) |
| CA-03 | Unique, non-zero, monotonic serials, never reused even after restore | Clock-floor high-water-mark serials: `serial = max(last+1, now_µs)` with the invariant `serial ≤ issue time`, and fail-closed on clock regression (Pattern 3) |
| CA-04 | Structured key ID (user/host, request, policy version) | Key ID grammar `kr1/ca=…/sub=…/req=…/pol=…/ser=…` with a restricted character set (Pattern 2) |
| CA-05 | User certs default to `permit-pty` only | Per-CA extension profile in the genesis policy; x/crypto sorts extensions (verified) |
| CA-06 | Signer signs only client-generated public keys | The signer API takes an SSH public-key blob only and has no subject-keygen path; it refuses cert-type and weak subject keys |
| CA-07 | Signer refuses certificate-type keys as CA keys | x/crypto `SignCert` already refuses (verified at certs.go:475-480); add our own check at `ca init`/load plus filtering of agent signers |
| CA-08 | Accepted/rejected by real sshd on 9.5p2 (Windows inbox) and latest | **No upstream 9.5p2 exists.** Build portable 9.5p1 and 10.5p1 from verified tarballs; Windows 9.5p2 is checked manually on Daniel-PC, with an optional Win32-OpenSSH job (Pitfall 1) |
| KEY-01 | CA keys in a separate network-less signer behind a `Signer` interface | `keyroster-signer` over a UDS with an `SO_PEERCRED` allowlist; systemd `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`; a CI dependency firewall (Patterns 6-7) |
| KEY-03 | CA keys in a PKCS#11 HSM via ssh-agent | ssh-agent backend via `x/crypto/ssh/agent`; SoftHSM2 in CI with P-256 (Ed25519 over PKCS#11 needs OpenSSH ≥ 10.1) (Pattern 1) |
| KEY-04 | CA keys in a TPM 2.0 | go-tpm + go-tpm-keyfiles `NewLoadableKey(…, TPMAlgECC, 256, …)`; swtpm in CI (transport spike) (Pattern 1) |
| KEY-05 | CA keys in a YubiKey PIV slot | piv-go/v2 behind `//go:build piv` (cgo on Linux); unit tests through a small card interface |
| KEY-07 | Offline trust-root ceremony (M-of-N) signing only bundles, KRL authority and policy | Two age-encrypted Ed25519 roots, threshold SSHSIG over typed documents, verified against *pinned* root fingerprints; hardware-root CI stand-in via OpenSSH `sk-dummy.so` (Pattern 5, ceremony runbook) |
| VIS-01 | Every issuance in the Merkle log before release | Sign in memory, append the entry and a new signed checkpoint in one SQLite transaction (`synchronous=FULL`), then release (Pattern 4) |
| VIS-03 | `audit verify` end to end, plus export | Recompute the RFC 6962 root from all leaves, check the checkpoint signature against the bundle-pinned log key, re-verify every cert; JSONL export (Pattern 4) |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

These come from `./.claude/CLAUDE.md` (the project file) and `C:\Users\labon\CLAUDE.md` (the user workflow file). They carry the same weight as locked decisions.

- **Security first**: above convenience and speed. The threat model covers a compromised CA server, stolen client keys, a malicious insider/admin, and supply-chain attacks.
- **Simplicity**: small, auditable codebase, one binary per role, every feature is attack surface. The stack expects about 6-10 direct dependencies.
- **Self-hosted**: no external service in the core path.
- **Stock OpenSSH only**: no patched sshd.
- **Process**: all changes go by PR to protected `main`, CI must pass, Conventional Commits, signed commits and releases.
- **Locked stack** (CLAUDE.md "Recommended Stack"): Go 1.27.1 toolchain with a `go 1.26` directive, `CGO_ENABLED=0`; `golang.org/x/crypto` v0.57.0 (ssh, ssh/agent); `modernc.org/sqlite` v1.60.1; `golang.org/x/mod/sumdb/note` (x/mod v0.41.0); `github.com/transparency-dev/merkle` v0.0.2; `filippo.io/age` v1.3.2; `github.com/google/go-tpm` v0.9.8 plus `github.com/foxboron/go-tpm-keyfiles`; `github.com/go-piv/piv-go/v2` v2.6.0 (build-tagged, cgo); `golang.org/x/sys`, `golang.org/x/term`; stdlib `flag` with a tiny subcommand dispatcher (not cobra); `log/slog`; in-house migrations using `PRAGMA user_version`; no `goose`.
- **What NOT to use** (CLAUDE.md): `stripe/krl`; `mattn/go-sqlite3`; `go-tpm-tools/simulator` in the main module (cgo; use swtpm); vendor PKCS#11 `.so` linked into the CA (use ssh-agent + `ssh-pkcs11-helper`); RSA or SHA-1 CA keys; X.509-style intermediates; `math/rand`; JWT; shelling out to `ssh-keygen` to sign in production (it is a test oracle only).
- **Dev tools**: govulncheck v1.8.0, golangci-lint v2.14.0 (enable gosec, staticcheck, bodyclose, errorlint, forbidigo), capslock v0.3.3, native Go fuzzing (mandatory for every parser), and `ssh-keygen`/`sshd` as the integration oracle. GitHub Actions are pinned by commit SHA; never set `GONOSUMDB` or `GOFLAGS=-insecure`.
- **GSD workflow**: file changes go through GSD commands (`/gsd-execute-phase`).
- **User workflow** (`C:\Users\labon\CLAUDE.md`): plan before non-trivial work; verify before done (run tests and show proof); seek root causes, not temporary fixes; keep changes minimal. Lessons go in memory or `tasks/lessons.md`.
- **Language**: Daniel writes Swedish. Artifacts like this one are English, per the orchestrator.

## Summary

Phase 1 builds the part of keyroster that cannot be retrofitted: a small `keyroster-signer` process. It holds the CA keys behind one keystore interface, validates every certificate field itself, allocates serials, and appends a signed Merkle-log entry before any certificate leaves the process. Around it sit an offline root that signs only typed documents (the trust bundle and genesis policy), and a repository that enforces signed, reviewed, CI-gated changes from the first commit. The locked stack held up under source inspection. `x/crypto/ssh` v0.57.0 already refuses certificate authorities in `SignCert` and sorts extensions. `go-tpm-keyfiles` returns ASN.1 ECDSA signatures that plug directly into `ssh.NewSignerFromSigner`. `sumdb/note` exposes `Signer`/`Verifier` interfaces, so a P-256 log key works with C2SP signature type 0x02. `transparency-dev/merkle` provides `rfc6962.DefaultHasher`, `compact.Range` and the proof verifiers.

Four findings change the plan.
1. **There is no upstream OpenSSH 9.5p2.** Windows' `OpenSSH_for_Windows_9.5p2` is Microsoft's build. CI must use portable **9.5p1** as the proxy and add a manual check on Daniel-PC (optionally a Win32-OpenSSH job).
2. **The ssh-agent backend is the thinnest real keystore.** A plain key loaded with `ssh-add` exercises the exact code path that PKCS#11/SoftHSM2 (KEY-03), and later YubiHSM 2 and PIV-via-ykcs11, use. The walking skeleton therefore needs no separate software keystore.
3. **Root signatures should be SSHSIG, not signed notes.** Hardware root keys (`sk-ssh-ed25519`, PIV via PKCS#11) produce SSH signatures that `sumdb/note` cannot express, while SSHSIG verifies all of them with stock `ssh-keygen -Y verify`. Signed notes stay for log checkpoints.
4. **A restore-safe serial needs no external state.** A clock-floor high-water mark (`serial = max(last+1, now_µs)`, never ahead of the clock) gives monotonic, never-reused serials after any rollback of signer state, provided the wall clock does not also roll back. That residual risk is detected later by witnesses (Phase 4).

The environment is the main execution risk. Go is not installed on Daniel-PC or in its WSL Ubuntu 24.04. Docker Desktop is installed but stopped. sshd, SoftHSM2 and swtpm e2e tests are realistic only in Linux CI or WSL. Nothing exists on GitHub yet: no `Labontese/keyroster` repo, no SSH signing keys registered, and git is not configured to sign. The existing local commits are unsigned.

**Primary recommendation:** Build a walking skeleton first. It consists of repo bootstrap and minimal pinned CI; a strict cert builder; `keyroster-signer` over a UDS using the **ssh-agent keystore**; clock-floor serials; a SQLite Merkle log with a signed checkpoint per append; `keyroster ca issue`; minimal `keyroster audit verify`; and an e2e job proving that real sshd 9.5p1 and 10.5p1 accept the certificate and reject bad variants. Then expand in this order: root ceremony and trust bundle (SSHSIG + age); SoftHSM2 PKCS#11; TPM (swtpm); build-tagged PIV; audit export and tamper suite; full GitHub hygiene; systemd sandbox; `doctor`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| CA private keys and signing | Signer process (`keyroster-signer`) | Hardware (TPM / PKCS#11 HSM via ssh-agent / PIV) | KEY-01: only the network-less signer touches key handles; hardware stops exfiltration |
| Cert field validation (principals, key ID, extensions, validity, subject key) | Signer process (`internal/cert`) | — | CA-02/04/05/06 must hold whatever the caller sends, so validation lives inside the signing boundary (Pitfalls 3 and 10 in PITFALLS.md) |
| Serial allocation | Signer process + its SQLite DB | Wall clock (floor) | CA-03; the signer is the single writer |
| Audit log sequencing, checkpoint signing | Signer process + its SQLite DB | Log key in the same backend | VIS-01: log-before-release can only be enforced by whoever releases |
| Audit verification and export | CLI (`keyroster audit verify/export`) | — | VIS-03: must run anywhere, against an export, without trusting the signer |
| Root key custody and root signing | Offline machine (CLI `keyroster root …`) | USB media (age files) | KEY-07: never online, never on the CA host |
| Trust-bundle and genesis-policy verification | Signer (refuses to operate without a valid bundle) | CLI (`audit verify`, `doctor`) | Agents (Phase 3) will be a third verifier, so the format is fixed now |
| Admin requests to the signer (Phase 1 has no server) | CLI on the signer host over the UDS | — | The server arrives in Phase 2; the UDS peer-cred allowlist names the admin group now and the server uid later |
| Real-sshd acceptance oracle | CI (Linux runner, OpenSSH built from source) | Manual check on Daniel-PC (Windows 9.5p2) | CA-08 |
| Branch protection, scanning, reporting | GitHub (rulesets, security features) | CI workflows | REPO-01..04 |

## Standard Stack

All versions were checked against `proxy.golang.org/<module>/@latest` on 2026-10-04 [VERIFIED: proxy.golang.org]. Source was downloaded and read for x/crypto, x/mod, go-tpm, go-tpm-keyfiles, merkle, piv-go and age.

### Core
| Library | Version (published) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go toolchain | go1.27.1 (go.dev/dl JSON) | All binaries; `go 1.26` directive | Locked (CLAUDE.md) |
| `golang.org/x/crypto` | v0.57.0 (2026-09-08) | `ssh` (Certificate, SignCert, NewSignerFromSigner), `ssh/agent` (agent client), `cryptobyte` (strict wire encoding) | Locked; `SignCert` refuses cert authorities (certs.go:475-480) |
| `modernc.org/sqlite` | v1.60.1 (2026-09-29) | Signer DB: log entries, checkpoints, serial state | Locked; pure Go; driver name `"sqlite"`; DSN `_pragma`, `_txlock` [CITED: pkg.go.dev/modernc.org/sqlite] |
| `github.com/transparency-dev/merkle` | v0.0.2 (2023-05-05) | `rfc6962.DefaultHasher`, `compact.Range`, `proof.VerifyInclusion/VerifyConsistency` | Locked; small and stable |
| `golang.org/x/mod` (`sumdb/note`) | v0.41.0 (2026-08-24) | C2SP signed-note checkpoints | Locked; `Signer`/`Verifier` interfaces allow an ECDSA type 0x02 implementation |
| `filippo.io/age` | v1.3.2 (2026-08-29) | Passphrase (scrypt) encryption of the software root keys (D-10) | Locked; `NewScryptRecipient` / `NewScryptIdentity` |
| `github.com/google/go-tpm` | v0.9.8 tag; **resolved to `v0.9.9-0.20260124013517-8f8f42cba0de` by MVS** because go-tpm-keyfiles requires it | TPM 2.0 commands, `transport/linuxtpm` (`/dev/tpmrm0`) | Locked; pure Go |
| `github.com/foxboron/go-tpm-keyfiles` | `v0.0.0-20260902202739-8c9c2d1005f4` (no tags) | TSS2 PEM key files, `NewLoadableKey`, `TPMKey.Signer` → `crypto.Signer` with ASN.1 ECDSA output | Locked; [WARNING: pseudo-version only, single maintainer; pin it and review the diff on every bump] |
| `golang.org/x/sys` | v0.48.0 | `unix.GetsockoptUcred` (SO_PEERCRED), file perms | Locked |
| `golang.org/x/term` | v0.46.0 | Passphrase prompts in the root ceremony | Locked |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/go-piv/piv-go/v2` | v2.6.0 (2026-04-15) | YubiKey PIV keystore (KEY-05) | Only in `-tags piv` builds with `CGO_ENABLED=1`. `pcsc_linux.go`, `pcsc_darwin.go`, `pcsc_freebsd.go`, `pcsc_openbsd.go` and `pcsc_unix.go` contain `import "C"` [VERIFIED: piv-go v2.6.0 source] |
| `golang.org/x/vuln` (govulncheck) | v1.8.0 | CI vulnerability scan | Every PR + nightly |
| `github.com/golangci/golangci-lint/v2` | v2.14.0 | Lint | CI |
| `github.com/google/capslock` | v0.3.3 | Capability diff of the signer | CI, on dependency bumps |

**Do not add** `transparency-dev/formats` (v0.1.1) in Phase 1. A checkpoint is three lines of text inside a signed note, and `sumdb/note` already parses notes. Revisit it in Phase 4 when witnesses arrive.

### Test-only external tools (not Go deps)
| Tool | Version | Purpose |
|------|---------|---------|
| OpenSSH portable | **9.5p1** (SHA-256 `f026e7b79ba7fb540f75182af96dc8a8f1db395f922bbc9f6ca603672686086b`), **10.5p1** (SHA-256 `d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11`, released 2026-08-11) | sshd/ssh/ssh-keygen/ssh-agent oracle; `regress/misc/sk-dummy/sk-dummy.so` as the FIDO stand-in. Hashes computed this session; tarballs are signed by RSA key `7168B983815A5EEF59A4ADFD2A3F414E736060BA`, so CI should also check the `.asc` [VERIFIED: cdn.openbsd.org download + sha256sum] |
| SoftHSM2 | 2.6.1 (Ubuntu 24.04 `2.6.1-2.2ubuntu3`) | PKCS#11 stand-in for YubiHSM 2 | [VERIFIED: apt-cache policy in WSL Ubuntu 24.04] |
| swtpm | 0.7.3 (Ubuntu 24.04) | TPM stand-in | [VERIFIED: apt-cache policy] |
| opensc (`pkcs11-tool`) | 0.25.0~rc1 | Create keys in SoftHSM2 | [VERIFIED: apt-cache policy] |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `transparency-dev/merkle` | `golang.org/x/mod/sumdb/tlog` (already pulled in by `sumdb/note`) | Would remove one dependency, since tlog has `RecordHash`, `TreeHash`, `ProveRecord`, `CheckRecord`, `ProveTree`, `CheckTree` (tlog.go). It is locked in CLAUDE.md, so keep merkle unless the owner agrees (Open Question 3) |
| Signed notes for root documents | SSHSIG (recommended) | Notes cannot carry `sk-ssh-ed25519` or PKCS#11/PIV signatures without custom types, while SSHSIG covers every root custody in D-10/D-11 and is verifiable with stock `ssh-keygen -Y verify` |
| Own SSHSIG (~150 LOC) | `github.com/hiddeco/sshsig` [ASSUMED] | Owning a small, spec'd, security-critical format matches the KRL decision; `ssh-keygen -Y` is the differential oracle |
| testcontainers-go for e2e | Plain `os/exec` driving a non-root sshd | Testcontainers adds a large dependency tree. OpenSSH's own regress suite runs sshd as a normal user (`regress/test-exec.sh`) |
| Dev tools via the `tool` directive in the main `go.mod` | Separate `tools/go.mod` | Keeps govulncheck, golangci-lint and capslock dependencies out of the product's module graph, so capslock and govulncheck see only real dependencies [ASSUMED best practice] |

**Installation:**
```bash
go mod init github.com/Labontese/keyroster
go get golang.org/x/crypto@v0.57.0 golang.org/x/mod@v0.41.0 golang.org/x/sys@v0.48.0 golang.org/x/term@v0.46.0
go get modernc.org/sqlite@v1.60.1 github.com/transparency-dev/merkle@v0.0.2 filippo.io/age@v1.3.2
go get github.com/foxboron/go-tpm-keyfiles@v0.0.0-20260902202739-8c9c2d1005f4   # pulls go-tpm pseudo-version
go get github.com/go-piv/piv-go/v2@v2.6.0          # only imported from //go:build piv files
# tools module
(cd tools && go mod init github.com/Labontese/keyroster/tools && go get golang.org/x/vuln/cmd/govulncheck@v1.8.0 github.com/google/capslock/cmd/capslock@v0.3.3)
```

## Package Legitimacy Audit

The `package-legitimacy` seam supports only npm, PyPI and crates; it rejected `--ecosystem go`. Go modules were checked instead through proxy.golang.org (`@latest` with VCS origin and commit hash, served via sumdb). Source was downloaded and inspected. Every module below is named in the locked stack (CLAUDE.md, from the earlier research session).

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| golang.org/x/crypto | Go proxy | 10+ yrs | very high | go.googlesource.com/crypto | OK (Go team) | Approved |
| golang.org/x/mod | Go proxy | 7+ yrs | very high | go.googlesource.com/mod | OK (Go team) | Approved |
| golang.org/x/sys, x/term, x/vuln | Go proxy | 7+ yrs | very high | go.googlesource.com | OK (Go team) | Approved |
| modernc.org/sqlite | Go proxy | 6+ yrs | high | gitlab.com/cznic/sqlite | OK | Approved |
| github.com/transparency-dev/merkle | Go proxy | 3+ yrs (last tag 2023) | high (Tessera/Trillian) | github.com/transparency-dev/merkle | OK | Approved |
| filippo.io/age | Go proxy | 5+ yrs | high | github.com/FiloSottile/age | OK | Approved |
| github.com/google/go-tpm | Go proxy | 8+ yrs | high | github.com/google/go-tpm | OK | Approved |
| github.com/foxboron/go-tpm-keyfiles | Go proxy | ~2 yrs, **untagged** | moderate | github.com/foxboron/go-tpm-keyfiles | SUS-lite (pseudo-version only) | Flagged: planner adds a `checkpoint:human-verify` before first `go get` (confirm the commit hash `8c9c2d1005f4` and skim the diff) |
| github.com/go-piv/piv-go/v2 | Go proxy | 6+ yrs | high | github.com/go-piv/piv-go | OK | Approved (build-tagged only) |
| github.com/google/capslock | Go proxy | 2+ yrs | moderate | github.com/google/capslock | OK | Approved (tools module) |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** `github.com/foxboron/go-tpm-keyfiles` (untagged; it is still the locked choice, so the gate is a human check of the pinned commit rather than removal).

## Architecture Patterns

### System Architecture Diagram

```
 OFFLINE (live USB, no network)                        SIGNER HOST (Proxmox VM, vTPM)
 ┌───────────────────────────────┐                     ┌──────────────────────────────────────────────┐
 │ keyroster root init  ×2       │                     │  keyroster ca init --backend tpm|agent|piv   │
 │  → root-a.age, root-b.age     │                     │   → creates user/host/machine/ops/log keys   │
 │  → root fingerprints (paper)  │◄── ca-pubkeys.json ─┤   → ca-pubkeys.json (unsigned, to USB)       │
 │ keyroster root sign           │                     │                                              │
 │  bundle.json + genesis policy │── bundle + sigs ───►│  keyroster-signer install-bundle             │
 │  (SSHSIG, typed namespaces)   │   (USB)             │   verify SSHSIG ≥ threshold vs PINNED root fps│
 └───────────────────────────────┘                     │   → log entry #0 (bundle), checkpoint #1     │
                                                       │                                              │
   admin CLI (same host, group keyroster-admin)        │  ┌─────────── keyroster-signer ───────────┐  │
   keyroster ca issue --pubkey k.pub --principal r:x ──┼─►│ UDS /run/keyroster-signer/sock         │  │
        request + admin SSHSIG evidence (Phase 1)      │  │  SO_PEERCRED uid/gid allowlist         │  │
                                                       │  │  decode (strict, fuzzed)               │  │
                                                       │  │  verify evidence vs genesis policy ──X─┼──┼─► refuse (default deny)
                                                       │  │  cert builder: validate principals,    │  │
                                                       │  │   key ID, extensions, validity, subject│  │
                                                       │  │  serial = max(last+1, now_µs) ≤ now    │  │
                                                       │  │  SignCert via keystore ───────────────┼──┼─► TPM /dev/tpmrm0 | ssh-agent (PKCS#11) | PIV
                                                       │  │  BEGIN IMMEDIATE tx:                   │  │
                                                       │  │   append leaf(cert) → new root         │  │
                                                       │  │   sign checkpoint (log key)            │  │
                                                       │  │   update serial high-water             │  │
                                                       │  │  COMMIT (synchronous=FULL) ──fail──────┼──┼─► cert discarded, never released
                                                       │  │  release cert + leaf index             │  │
                                                       │  └────────────────────────────────────────┘  │
   ◄───────────────────────── cert ────────────────────┤                                              │
                                                       └──────────────────────────────────────────────┘
   keyroster audit export → log.jsonl ─► keyroster audit verify (anywhere): root recompute, checkpoint
        signature vs bundle log key, bundle SSHSIG vs pinned roots, each cert's signature/serial/key ID

 CI (Linux): OpenSSH 9.5p1 + 10.5p1 built from verified tarballs → non-root sshd on 127.0.0.1
            TrustedUserCAKeys = CA pub, AuthorizedPrincipalsFile → ssh -i k -o CertificateFile=… true
```

### Recommended Project Structure
```
cmd/
├── keyroster/            # CLI: ca init|issue, root init|sign, audit verify|export, doctor
└── keyroster-signer/     # signer daemon (linux only), install-bundle, serve
internal/
├── wire/                 # strict length-prefixed encoding (x/crypto/cryptobyte), domain tags; fuzzed
├── cert/                 # Builder: the ONLY path to SignCert; principal/keyID/extension validation
├── keystore/             # CAKey interface + backends: agent/, tpm/, piv/ (//go:build piv), soft/ (tests/dev)
├── sshsig/               # SSHSIG sign/verify (PROTOCOL.sshsig); differential vs ssh-keygen -Y
├── trust/                # bundle + policy documents, canonical JSON, threshold verification
├── tlog/                 # leaf encoding, compact range, checkpoint (note) incl. ECDSA 0x02 signer/verifier
├── serial/               # clock-floor allocator (pure, injectable clock)
├── signer/               # request handling, evidence check, log-before-release transaction, UDS server
├── signerdb/             # SQLite schema + PRAGMA user_version migrations (embedded .sql)
└── rootceremony/         # root key gen (age), typed document signing; no import of internal/cert
test/
├── e2e/                  # //go:build e2e — drives sshd/ssh/ssh-keygen/ssh-agent/softhsm/swtpm via os/exec
└── vectors/              # golden bundle/policy/leaf/checkpoint encodings
tools/go.mod              # govulncheck, capslock (separate module)
.github/workflows/        # ci.yml, codeql.yml, scorecard.yml, e2e.yml (or a job in ci.yml)
deploy/systemd/           # keyroster-signer.service (+ keyroster-signer-agent.service for the agent backend)
```

### Walking Skeleton (MVP mode: thinnest real end-to-end slice)
1. **Repo bootstrap.** Public GitHub repo, `go.mod`, LICENSE (Apache-2.0), README with the pre-alpha warning, minimal SECURITY.md, and one CI workflow (build, unit test, golangci-lint, govulncheck) with SHA-pinned actions and `permissions: {}`. Owner and bot SSH signing configured, then the rulesets.
2. **`internal/cert` Builder + `internal/serial` + `internal/tlog` + `internal/keystore/agent`.**
3. **`keyroster-signer serve`** on a UDS with peer-cred, plus a minimal evidence check.
4. **`keyroster ca issue`** returns a cert. **`keyroster audit verify`** recomputes the root and checks the checkpoint.
5. **The e2e job** builds OpenSSH 9.5p1 and 10.5p1, loads a CA key into ssh-agent, issues through the signer, logs in to a real sshd, and runs the negative cases.

**Expansion waves after the skeleton:** (a) trust bundle, genesis policy and root ceremony (age + SSHSIG; sk-dummy stand-in); (b) SoftHSM2 via ssh-agent/PKCS#11; (c) TPM backend + swtpm + homelab vTPM dogfood; (d) PIV build tag; (e) audit export, tamper/removal test suite, fuzz targets for every decoder; (f) CodeQL, Scorecard, Dependabot, secret scanning, private vulnerability reporting, community files, CODEOWNERS, templates; (g) systemd unit and sandbox + `doctor` (software-root and vTPM warnings); (h) the manual Windows 9.5p2 check on Daniel-PC.

### Pattern 1: One keystore interface, built on `ssh.Signer`
**What:** Each backend yields an `ssh.Signer` plus custody metadata. `ssh.NewSignerFromSigner(crypto.Signer)` adapts TPM and PIV keys; the agent client yields `ssh.Signer`s directly.
**When to use:** Every CA, ops and log key.
```go
// Source: x/crypto v0.57.0 ssh/keys.go:1206 NewSignerFromSigner; ssh/agent client Signers()
type Custody string // "tpm" | "vtpm" | "pkcs11-agent" | "agent" | "piv" | "software"

type CAKey interface {
    ssh.Signer                 // PublicKey() + Sign(); MUST NOT be a *ssh.Certificate (CA-07)
    Custody() Custody
    Algorithm() string         // "ssh-ed25519" | "ecdsa-sha2-nistp256" (D-09)
}

// agent backend: select by pinned fingerprint, never "first key"; drop certificate signers.
func AgentKey(sock string, wantFP string) (CAKey, error) {
    c, err := net.Dial("unix", sock)          // private socket owned by the signer user
    if err != nil { return nil, err }
    signers, err := agent.NewClient(c).Signers()
    if err != nil { return nil, err }
    for _, s := range signers {
        if _, isCert := s.PublicKey().(*ssh.Certificate); isCert { continue } // CA-07
        if ssh.FingerprintSHA256(s.PublicKey()) == wantFP { return wrapAgent(s), nil }
    }
    return nil, errors.New("keystore: pinned CA key not present in agent")
}
```
- **TPM:** `keyfile.NewLoadableKey(tpm, tpm2.TPMAlgECC, 256, ownerAuth)` creates a P-256 key under the SRK; persist `keyfile.Encode(...)` to the signer's state dir. Then `k.Signer(tpm, ownerAuth, auth)` gives a `crypto.Signer`, and `ssh.NewSignerFromSigner` wraps it. `SignASN1` returns DER (tpm.go:436), which is what `wrappedSigner` expects for ECDSA [VERIFIED: go-tpm-keyfiles source]. Open the device with `linuxtpm.Open("/dev/tpmrm0")`.
- **PIV (`//go:build piv`):** `yk.PrivateKey(piv.SlotSignature, pub, piv.KeyAuth{PIN: …})` returns `crypto.PrivateKey`; type-assert to `crypto.Signer`. Unit-test behind a 3-method interface (`PrivateKey`, `Attest`, `Close`) with a fake.
- **Algorithm (D-09):** TPM → P-256. Agent/PKCS#11 → whatever the token holds: P-256 on SoftHSM2 with the distro OpenSSH 9.6; Ed25519 only with an ssh-agent ≥ 10.1 ("support ed25519 keys hosted on PKCS#11 tokens", release-10.1) [VERIFIED: openssh.org release-10.1].

### Pattern 2: A cert Builder that cannot sign zero values
**What:** `internal/cert.Builder` is the only package that calls `(*ssh.Certificate).SignCert`. A `forbidigo` or depguard rule plus a test grep enforce that. `Build()` refuses unless every field was set explicitly and validated.
```go
// principal allowlist (CA-02): stricter than the denylist; no * ? , ! whitespace, controls, '/'.
var principalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@:+-]{0,127}$`) // lowercase helps Windows (Phase 5)

func ValidatePrincipals(ps []string) error {
    if len(ps) == 0 { return ErrEmptyPrincipals }
    seen := map[string]bool{}
    for _, p := range ps {
        if !principalRE.MatchString(p) || seen[p] { return fmt.Errorf("cert: bad principal %q", p) }
        seen[p] = true
    }
    return nil
}

// key ID (CA-04): fixed grammar, restricted charset, parsed back in audit verify.
// kr1/ca=user/sub=u:alice/req=01JAB…/pol=1/ser=1759600000000001
```
- **Extensions (CA-05):** user CA default `{"permit-pty": ""}` only. Critical options are empty unless the policy grants `force-command`, which then also requires no forwarding extensions. x/crypto sorts tuple keys (`sort.Strings(keys)`, certs.go:130-135), so ordering is canonical [VERIFIED].
- **Validity:** `ValidAfter = now - 5m`; `ValidBefore` is required and capped per CA by policy; reject `ssh.CertTimeInfinity`.
- **Subject key (CA-06):** the input is an SSH wire public-key blob only. Reject `*ssh.Certificate`, DSA, and RSA < 3072; accept Ed25519, ECDSA P-256/384/521 and sk-* keys. No function in the signer generates subject keys (enforce with a grep test for `GenerateKey` under `internal/signer`).
- **Do not use `ssh.CertChecker` for policy.** It treats empty principals as "any" (`if len(cert.ValidPrincipals) > 0 {`, certs.go:422) [VERIFIED]. Our verifiers check principals explicitly.

### Pattern 3: Restore-safe serials via a clock floor (CA-03)
**What:** `next = max(last+1, nowMicros())`. If `next > nowMicros()` (more than one issuance per µs), wait until the clock catches up, so the invariant `serial ≤ issuance time (µs)` always holds. After restoring an older DB copy, `last` is stale but `now` is not, so every new serial exceeds every serial issued before the restore.
**Fail-closed:** if `nowMicros() < last` at startup or issuance, the clock went backwards. Refuse to issue and log a `clock_regression` event; an admin must override.
**Residual risk:** a restore *combined with* a wall-clock rollback. Document it, and detect it in Phase 4 (witnessed checkpoints carry size and timestamps). Optional TPM hardening: also take the floor from a TPM NV counter (`TPM_NT_COUNTER` cannot decrement). This does not survive vTPM snapshot restore, which is another reason D-08 is documented as weaker [ASSUMED].
**Serial 0 is impossible** because `now_µs` > 0. Uniqueness is global across all CAs, which is simpler and stronger than per-CA.

### Pattern 4: Log-before-release in one SQLite transaction (VIS-01, VIS-03)
1. Build the TBS cert and sign it in memory (the cert stays inside the signer).
2. `BEGIN IMMEDIATE`. Insert the leaf (domain-separated canonical bytes containing the full signed cert, the request digest, the evidence and the policy version). Append its hash to the `compact.Range` and compute the new root. Build the checkpoint body `<origin>\n<size>\n<base64 root>\n` and sign it with the log key (`note.Sign` with our ECDSA-0x02 or Ed25519 signer). Store the checkpoint and the serial high-water mark.
3. `COMMIT` with `journal_mode=WAL`, `synchronous=FULL`. Only on success return the cert and leaf index. On any error, return an error; the in-memory cert is dropped.

**`audit verify`:**
- (a) Verify the bundle SSHSIGs against **pinned** root fingerprints (a flag or file, never taken from the bundle itself).
- (b) Verify the checkpoint signature with the log key listed in the bundle.
- (c) Recompute the root from every leaf with `rfc6962.DefaultHasher` and require `size == count` and an exact root match.
- (d) Per issue entry, parse the cert, verify its signature with the CA key from the bundle, check that the serial is strictly increasing and unique, and re-parse the key ID.
- (e) Optional `--previous checkpoint.txt`: verify a consistency proof (prepares VIS-02).

A tampered leaf fails (c). A removed leaf fails (c) on size or root. A rewritten tail without the log key fails (b).
**Export:** JSONL. Each line is `{"index":N,"leaf":"<base64 canonical bytes>","decoded":{…informational…}}`, and the last line is `{"checkpoint":"<signed note text>"}`. Verify reads only `leaf` and `checkpoint`, never `decoded`.

### Pattern 5: Trust bundle and genesis policy, signed by root SSHSIG with a threshold
- **Documents:** `keyroster/trust-bundle/v1` and `keyroster/policy/v1`, as canonical JSON. Structs only, no maps or floats, unknown fields rejected, and **`bytes.Equal(reMarshal(parsed), input)` required**, which also catches duplicate keys and whitespace games.
- **Bundle fields:** `version`, `prev` (SHA-256 of the previous bundle, zero for genesis), `issued_at`, `root {keys:[{key, custody}], threshold}`, `cas:[{role: user|host|machine, key, alg, custody, state: active|next|retired, generation}]`, `ops_key` (KRL authority, unused until Phase 3), `log {key, alg, origin}`, `policy_sha256`.
- **Genesis policy:** `version:1`, `prev:0`, `admin_quorum:1`, `admins:[bootstrap admin SSH pubkeys]`, `ca_profiles` (max TTL, default extensions), `timelock:"0s"`. Phase 4 changes values, not the format.
- **Signatures:** detached armored SSHSIG per root key, namespaces `keyroster/trust-bundle/v1` and `keyroster/policy/v1`, `hash_algorithm` `sha512`. Verification counts **distinct pinned root keys** with valid signatures and requires `≥ threshold`. For genesis, the pinned set comes from out-of-band fingerprints; for later bundles, from the *previous* accepted bundle (TUF rule).
- **Root never signs certs:** `internal/rootceremony` exposes only `SignBundle` and `SignPolicy`. A test asserts it does not import `internal/cert`. The signer refuses any CA key whose fingerprint appears in `bundle.root.keys`. SSHSIG's signed data starts with the raw bytes `SSHSIG` and a cert TBS starts with a uint32 length, so the two cannot be confused [CITED: PROTOCOL.sshsig].

### Pattern 6: Signer IPC over a UDS with a peer-credential allowlist (KEY-01)
- **Socket:** path-based (not abstract), `/run/keyroster-signer/signer.sock`, mode 0660, group `keyroster-admin` (Phase 2 adds the server uid).
- **Peer check:** on accept, `unix.GetsockoptUcred(fd, SOL_SOCKET, SO_PEERCRED)`, then check the uid/gid allowlist; otherwise close.
- **Framing:** uint32 length (max 64 KiB) + version byte + message type + `cryptobyte`-encoded body. Every decoder has a fuzz target. Unknown type or version means close.
- Build the signer `//go:build linux`. The CLI still cross-compiles for Windows/macOS (PLAT-05 is Phase 2).

### Pattern 7: Network-less by construction and by sandbox
- **CI dependency firewall:** `go list -deps ./cmd/keyroster-signer` must not contain `net/http`, `net/rpc`, `crypto/tls`, `html/template`, `text/template`, `os/exec` (tune empirically). `x/crypto/ssh` imports `net`, and the signer itself uses `net.Listen("unix")`, so `net` is allowed. depguard catches direct imports early.
- **capslock:** commit a baseline of the signer's capabilities and fail on new ones.
- **systemd:** `User=keyroster-signer`, `PrivateNetwork=yes` (path-based UDS still works across the netns), `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `StateDirectory=keyroster-signer`, `RuntimeDirectory=keyroster-signer`, `DevicePolicy=closed`, `DeviceAllow=/dev/tpmrm0 rw` (TPM backend; the user is in group `tss`), `NoNewPrivileges=yes`, `CapabilityBoundingSet=`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `LimitCORE=0`, `UMask=0077`, `LockPersonality=yes`, `ProtectHome=yes`.
- **Agent backend:** a sibling unit `ssh-agent -D -a /run/keyroster-signer/agent.sock -P '/usr/lib/softhsm/*,/usr/lib/x86_64-linux-gnu/libykcs11*'` runs as the same user. Never forward this agent: OpenSSH 10.5 fixed a bug where a locked, forwarded agent could be made to add PKCS#11 tokens remotely [VERIFIED: release-10.5].

### Pattern 8: Real-sshd e2e without containers
Build OpenSSH from verified tarballs into `/opt/openssh-$V` and cache it, keyed on version + SHA-256. Run a **non-root** sshd on 127.0.0.1 the way OpenSSH's regress suite does. Cases:
- **Accept:** valid cert + principal in `AuthorizedPrincipalsFile`.
- **Reject:** principal not listed; expired; not-yet-valid; signed by an untrusted CA. Also `-L` forwarding with `ExitOnForwardFailure=yes` and agent forwarding (must fail with a default cert); `-tt` pty (must succeed).
- **Signer-side refusals** (no cert produced): empty, wildcard and comma principals; a cert-type subject; a cert-type CA.

Run the matrix on 9.5p1 and 10.5p1. Clear `SSH_AUTH_SOCK` for the client.

### Pattern 9: Repository protection with two rulesets (REPO-01, D-05)
- **Ruleset A "main-integrity"** (no bypass actors): `deletion`, `non_fast_forward`, `required_linear_history`, `required_signatures`, `required_status_checks` (strict, with the CI job names and `integration_id` 15368 for GitHub Actions [ASSUMED id]).
- **Ruleset B "main-review"**: `pull_request` with `required_approving_review_count:1`, `dismiss_stale_reviews_on_push:true`, `require_code_owner_review:true`, `require_last_push_approval:true`, `required_review_thread_resolution:true`, `allowed_merge_methods:["squash"]`. Bypass: `{actor_type:"RepositoryRole", actor_id:5 /*admin, ASSUMED*/, bypass_mode:"pull_request"}`.

The owner's bypass then skips **only review**, never signatures or CI. `pull_request` mode means "an actor can only bypass rules on pull requests" [CITED: docs.github.com REST rulesets], so the admin still cannot push directly. **Never use `exempt`**: "a bypass audit entry will not be created" [CITED].
- **Squash only:** GitHub cannot sign rebase-merged commits ("GitHub doesn't have access to the committer's private signing keys") [CITED: docs.github.com commit signature verification]. Unsigned commits on the head branch block squash merges too [CITED: docs.github.com available rules].
- **Bot (D-05):** one free machine account is allowed per person [CITED: GitHub ToS]. Add it as a collaborator (write); on a personal repo it cannot administer rulesets. It commits with its own ed25519 signing key and its `ID+login@users.noreply.github.com` email; authenticate with a fine-grained PAT scoped to this repo (Contents RW, Pull requests RW, Workflows RW only if it must edit workflows).

### Anti-Patterns to Avoid
- **Verifying a bundle against the root keys it contains.** That is self-signed and proves nothing. Pin the fingerprints out of band.
- **Picking "the first key in the agent"** as the CA. Pin by fingerprint and skip certificate signers.
- **A software keystore in production paths.** It is for tests and dev, and KEY-06 warnings come in Phase 2. The skeleton uses the agent backend instead.
- **Logging only the TBS and signing after the commit.** The log then lacks the exact cert bytes, so `audit verify` cannot check signatures or reconcile serials. Sign first, log the full cert, release after the commit.
- **A test-only bypass of evidence checks** (a build tag that skips verification). Tests must produce real evidence (a test admin key).
- **`ssh-keygen -s` in product code.** It is an oracle in tests only (CLAUDE.md).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SSH cert encoding/signing | Own cert marshaller | `x/crypto/ssh` `Certificate.SignCert` | Sorting, nonce and cert-authority refusal are already correct (certs.go:470-510) |
| ECDSA/Ed25519 signing adapters | Own DER→SSH conversion | `ssh.NewSignerFromSigner` | Handles hash choice and ASN.1→SSH blob |
| PKCS#11 in-process | dlopen/cgo PKCS#11 | OpenSSH `ssh-agent` + `ssh-pkcs11-helper` via `x/crypto/ssh/agent` | Process isolation of vendor code; no cgo |
| TPM key files | Own TPM blob persistence | `go-tpm-keyfiles` (TSS2 PEM) | Interoperable with `tpm2-openssl` and `ssh-tpm-agent` tooling |
| Merkle hashing and proofs | Own RFC 6962 tree | `transparency-dev/merkle` | Subtle off-by-one in consistency proofs |
| Signed-note parsing | Own note parser | `sumdb/note.Open/Sign` with custom Signer/Verifier for ECDSA | Spec-conformant key IDs and line rules |
| Passphrase key encryption | Own KDF/AEAD | `filippo.io/age` scrypt recipient | Audited format |
| Strict binary parsing | `encoding/binary` + manual bounds | `x/crypto/cryptobyte` | Bounds-checked, no reflection, fuzz-friendly |
| SQL migrations | goose | ~50 LOC with embedded `.sql` + `PRAGMA user_version` | Locked in CLAUDE.md |
| SSHSIG | — (small, own it) | In-house `internal/sshsig`, differential vs `ssh-keygen -Y sign/verify` | ~150 LOC spec; avoids a dependency in the root path |

**Key insight:** the crypto primitives and formats all exist. What keyroster owns is *policy at the signing boundary*: validation, serials, log-before-release and threshold verification. That is where the review effort should go.

## Runtime State Inventory

Phase 1 is greenfield. The only "rename" is documentary (sshcm → keyroster, D-01).

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None. No DBs or services exist (verified: no source code, no repo on GitHub) | none |
| Live service config | None. `gh repo view Labontese/keyroster` returns "Could not resolve"; user `keyroster-bot` does not exist (404) | Create the repo and bot in Phase 1 |
| OS-registered state | None on Daniel-PC; the signer VM does not exist yet | Create the VM and units in the dogfood task |
| Secrets/env vars | `GH_TOKEN` with scopes `admin:ssh_signing_key, repo, user, workflow` is present; **no SSH signing keys registered** on Labontese (`user/ssh_signing_keys` → `[]`); git `gpg.format`/`user.signingkey` unset | Register the owner's signing key and configure git (`gpg.format ssh`) before the first push |
| Build artifacts | Local git repo at `C:\Users\labon\ssh-cert-manager` with 5+ **unsigned** commits, no remote; directory name differs from the repo name | Re-sign history before the first push (`git rebase --root --exec 'git commit --amend --no-edit -S'`) or accept unsigned genesis commits; set remote `github.com/Labontese/keyroster` |

## Common Pitfalls

### Pitfall 1: "OpenSSH 9.5p2" does not exist upstream
**What goes wrong:** A CI job tries to download `openssh-9.5p2.tar.gz` and gets a 404 (verified), or someone quietly substitutes 9.6.
**Why:** Windows' inbox `OpenSSH_for_Windows_9.5p2` (verified on Daniel-PC) is Microsoft's own build. The upstream 9.x tarballs are 9.0p1…9.9p2, with 9.3p2 and 9.9p2 but no 9.5p2. Win32-OpenSSH's public release for that line is `v9.5.0.0p1-Beta` (2023-12-18) [VERIFIED: gh api releases].
**How to avoid:** CI matrix = portable **9.5p1** (closest upstream code) + **10.5p1** (latest). Add a manual `checkpoint:human-verify` on Daniel-PC with the inbox 9.5p2 sshd. Optionally add a windows-runner job installing the Win32-OpenSSH `v9.5.0.0p1-Beta` zip [ASSUMED feasible on hosted runners].
**Warning signs:** The plan says "9.5p2" in a download URL.

### Pitfall 2: Ed25519 via PKCS#11 needs OpenSSH ≥ 10.1 in the agent
**What goes wrong:** A YubiHSM 2 or SoftHSM2 Ed25519 key is invisible or fails in ssh-agent 9.6 (Ubuntu 24.04).
**How to avoid:** Use P-256 for the SoftHSM2 CI lane with the distro agent. Add an Ed25519 lane using the self-built 10.5p1 `ssh-agent`. Have `doctor` print the agent version. ssh-keygen also had PKCS#11 download and agent-CA-signing bugs until 10.2 [VERIFIED: release-10.2]. That matters only for oracles, since we sign natively.

### Pitfall 3: ssh-add PIN prompt hangs CI
**What goes wrong:** `ssh-add -s libsofthsm2.so` waits on a TTY.
**How to avoid:** `SSH_ASKPASS=./pin.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0 ssh-add -s …`. The agent must allow the provider path via `-P` (OpenSSH's own regress suite uses `-P/*` for sk-dummy [VERIFIED: regress/test-exec.sh:723-725]).

### Pitfall 4: Bundle verification against the wrong key set
**What goes wrong:** The signer or CLI accepts any bundle whose own `root.keys` signed it.
**How to avoid:** Genesis pins come from operator-supplied fingerprints. Later bundles are checked against the previous accepted bundle's root set and threshold, with `version` strictly increasing and `prev` matching. Add a negative test: a bundle signed by a fresh key that lists itself as root → refused.

### Pitfall 5: Go `encoding/json` accepts duplicate keys (last wins)
**What goes wrong:** Two parsers (ours now, and a different one in a later agent) disagree on a signed document.
**How to avoid:** Canonical re-marshal equality check on every parse. Fuzz the parse → marshal round trip.

### Pitfall 6: `sumdb/note` only knows Ed25519
**What goes wrong:** `note.NewSigner/NewVerifier` reject the P-256 TPM log key. The code says "There is only one key type, Ed25519 with algorithm identifier 1." (note.go:86) [VERIFIED].
**How to avoid:** Implement `note.Signer`/`note.Verifier` (note.go:192-213) for C2SP type **0x02 ECDSA**. Its key ID is the "truncated SHA-256 hash of the DER encoded public key in SPKI format" [CITED: C2SP signed-note], which is not the Ed25519 key-hash formula. Golden-vector it.

### Pitfall 7: swtpm transport is not the production transport
**What goes wrong:** Tests pass against a simulator path (`transport/simulator` is cgo via go-tpm-tools) that production never uses.
**How to avoid:** Run a Wave-0 spike. Option A: `swtpm socket --tpm2 --server type=unixio,path=… --flags not-need-init,startup-clear` + go-tpm `linuxudstpm.Open` ("provides access to a TPM device via a Unix domain socket", linuxudstpm.go:3) [VERIFIED package; protocol compatibility ASSUMED]. Option B (preferred if it works on runners): `swtpm chardev --vtpm-proxy` → `/dev/tpmrm1` → `linuxtpm.Open`, which is the production path [ASSUMED: kernel module `tpm_vtpm_proxy` available on hosted runners]. Never import `tpm2/transport/simulator`.

### Pitfall 8: vTPM and software root are weaker, and must say so
**What goes wrong:** The homelab looks like "hardware custody".
**How to avoid:** Record the custody declared in the bundle (`vtpm`, `software`). `doctor` reads the TPM manufacturer and vendor strings (`TPM2_GetCapability`, `TPM_PT_MANUFACTURER`/`VENDOR_STRING_*`) and flags swtpm/vTPM [ASSUMED: Proxmox vTPM is swtpm and identifiable]. The ceremony prints a banner for the software root (D-08, D-10, D-11).

### Pitfall 9: Serial floor and clock trust
**What goes wrong:** An NTP step backwards or a VM restored with an old clock gives `now < last`.
**How to avoid:** Fail-closed (Pattern 3). Note in the runbook that restoring the signer VM from a snapshot requires checking the clock first.

### Pitfall 10: Required status checks need existing check names
**What goes wrong:** A ruleset that references job names before any run exists blocks or misbehaves; renaming a job silently blocks merges.
**How to avoid:** Push the CI workflow, let it run once on a PR, then create ruleset A with the exact `context` names. Keep job names stable and document them in CONTRIBUTING.

### Pitfall 11: The bot's commits show "Unverified"
**What goes wrong:** The signing key is registered but the commit email is not a verified email of the bot account, or the key was added as an *authentication* key only.
**How to avoid:** Add it as a **signing** key (`gh ssh-key add --type signing`). Set `user.email` to the bot's noreply address and configure `gpg.format=ssh`, `user.signingkey`, `commit.gpgsign=true` per identity. Persistent verification means old commits stay verified after key rotation [CITED: docs.github.com].

### Pitfall 12: Public repo leaks homelab details
**What goes wrong:** `.planning/research/PITFALLS.md` contains a Tailscale address and homelab hostnames; CONTEXT mentions the VM layout.
**How to avoid:** Review `.planning/` before the first public push (D-04 makes it public). Tailscale IPs are not internet-routable, so the risk is low, but scrub IPs anyway.

### Pitfall 13: sshd 10.x layout when built to a prefix
**What goes wrong:** sshd 10.0+ execs `sshd-session` and `sshd-auth` from libexec. A partial copy of binaries fails at login.
**How to avoid:** `make install` into the prefix and cache the whole prefix. Run `sshd -t -f cfg` before `-D`.

### Pitfall 14: Squash-merge message is not Conventional
**What goes wrong:** The squash commit message defaults to the PR title or commit list.
**How to avoid:** Set the repo default squash message to "PR title" and lint PR titles (Conventional Commits) in CI with a tiny in-repo script rather than a third-party action.

## Code Examples

### SSHSIG verify (PROTOCOL.sshsig)
```go
// Source: openssh-portable PROTOCOL.sshsig (blob + signed-data layouts)
func signedData(ns string, msg []byte) []byte {
    h := sha512.Sum512(msg)
    var b cryptobyte.Builder
    b.AddBytes([]byte("SSHSIG"))
    for _, f := range [][]byte{[]byte(ns), nil, []byte("sha512"), h[:]} {
        b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
    }
    return b.BytesOrPanic()
}
// Verify: parse armored blob → magic "SSHSIG", version==1, pubkey, namespace (must equal expected,
// non-empty), reserved (ignore), hash_algorithm ∈ {"sha512"} (we only emit sha512), signature
// (ssh.Unmarshal into ssh.Signature keeps Rest for sk-* flags/counter) → pub.Verify(signedData(...), &sig).
```

### Clock-floor serial allocator
```go
type Clock func() time.Time
func Next(last uint64, now Clock) (uint64, error) {
    n := uint64(now().UnixMicro())
    if n < last { return 0, ErrClockRegression }        // fail closed
    next := max(last+1, n)
    for uint64(now().UnixMicro()) < next { time.Sleep(time.Microsecond) } // keep serial ≤ issue time
    return next, nil
}
```

### Non-root sshd for e2e
```
# sshd_config (generated per test in t.TempDir())
Port 2222
ListenAddress 127.0.0.1
HostKey {{.Dir}}/ssh_host_ed25519_key
PidFile {{.Dir}}/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
TrustedUserCAKeys {{.Dir}}/user_ca.pub
AuthorizedPrincipalsFile {{.Dir}}/principals/%u
LogLevel VERBOSE
# run: /opt/openssh-$V/sbin/sshd -t -f cfg && /opt/openssh-$V/sbin/sshd -D -e -f cfg
# client: env -u SSH_AUTH_SOCK /opt/openssh-$V/bin/ssh -F none -i k -o CertificateFile=k-cert.pub \
#   -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
#   -p 2222 "$USER"@127.0.0.1 true
```

### Ruleset A via gh
```bash
gh api -X POST repos/Labontese/keyroster/rulesets --input - <<'JSON'
{"name":"main-integrity","target":"branch","enforcement":"active",
 "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
 "rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"required_linear_history"},
  {"type":"required_signatures"},
  {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,
   "required_status_checks":[{"context":"build-test"},{"context":"lint"},{"context":"govulncheck"},
   {"context":"fuzz"},{"context":"e2e (9.5p1)"},{"context":"e2e (10.5p1)"}]}}]}
JSON
```

### Pinned action references (resolved 2026-10-04; re-resolve at execution)
```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1        # v7.0.1
  with: { persist-credentials: false }
- uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e        # v7.0.0
- uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9           # v6.1.0
- uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
- uses: github/codeql-action/init@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
- uses: ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc   # v2.4.4
- uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0
- uses: golang/govulncheck-action@032d45514ae346b1db93c04b0c90b841c370344f   # v1.1.0
- uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1 (optional)
```
[VERIFIED: `gh api repos/<r>/releases/latest` + `git/ref/tags` with annotated tags dereferenced]. Top-level `permissions: {}`; per job `contents: read`; CodeQL adds `security-events: write`; Scorecard adds `security-events: write, id-token: write`. Run the fuzz job as a loop: `go test -run=^$ -fuzz=^FuzzX$ -fuzztime=30s ./pkg` per target, because `-fuzz` accepts one target per invocation.

## Offline Root Ceremony Runbook (Claude's discretion, recommended)

1. **Prepare.** Boot a Debian/Ubuntu live USB with networking disabled (no Wi-Fi driver; check that `ip -br link` shows only `lo` up). Copy the `keyroster` binary built from a tagged commit and compare its SHA-256 on a second machine.
2. **Generate the roots.** `keyroster root init --out /media/usbA/root-a.age` prompts for passphrase A twice (age scrypt) and prints the `ssh-ed25519` pubkey and `SHA256:` fingerprint with a **SOFTWARE ROOT** banner (D-11). Repeat for USB B / passphrase B.
3. **Record pins out of band.** Write both fingerprints on paper and copy `roots.pub` to a transfer USB.
4. **Initialise the CAs.** On the signer VM, `keyroster ca init --backend tpm` creates the user, host, machine, ops and log keys and writes `ca-pubkeys.json` (unsigned, with algorithm and custody) to the transfer USB.
5. **Sign offline.** `keyroster root sign --bundle-from ca-pubkeys.json --policy genesis.json --roots roots.pub --threshold 1 --key /media/usbA/root-a.age` renders a human-readable summary (every fingerprint, role, algorithm, custody, threshold) and requires typing the bundle hash prefix. **Then sign with root B as well.** Only one signature is required, but this proves now, not during an emergency, that USB B and passphrase B work.
6. **Install.** `keyroster-signer install-bundle --pin SHA256:A --pin SHA256:B bundle.json bundle.sigs policy.json policy.sigs` verifies and logs entry #0.
7. **Store.** Keep the USBs in two locations and the passphrases separately. Keep a ceremony transcript (artifact hashes, date, operator) in the repo docs, without secrets.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Empty cert principals = wildcard (authorized_keys `principals=`) | Empty never matches; wildcards unsupported in user certs | OpenSSH 10.3 | Windows 9.5p2 still has the old behaviour, so the CA must refuse empty principals itself |
| ssh-agent socket in /tmp | `~/.ssh/agent/` by default | OpenSSH 10.1 | Always pass `-a` explicitly for the signer's agent |
| No Ed25519 over PKCS#11 | Supported in ssh/ssh-agent | OpenSSH 10.1 | Ed25519 HSM CAs need a new agent |
| ssh-keygen CA signing via agent broken | Fixed | OpenSSH 10.2 | Oracle-only concern |
| Signed notes Ed25519-only (x/mod) | C2SP defines ECDSA 0x02 | C2SP signed-note | Custom note signer for TPM P-256 log keys |

**Deprecated/outdated:** `stripe/krl` (archived), `slsa-github-generator` as the primary provenance path (Phase 6), the "9.5p2" tarball assumption.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | swtpm `--server type=unixio` speaks raw TPM commands compatible with go-tpm `linuxudstpm` | Pitfall 7 | TPM CI lane needs Option B or the TCP transport; spike first |
| A2 | `tpm_vtpm_proxy` can be loaded on GitHub-hosted Ubuntu runners | Pitfall 7 | Fall back to A1 |
| A3 | Ruleset bypass actor `RepositoryRole` id 5 = admin, and is available on a personal-account repo | Pattern 9 | Bypass mis-targeted; check with `gh api …/rulesets` after creation |
| A4 | Required-status-check `integration_id` 15368 = GitHub Actions | Pattern 9 | Use context-only checks if wrong |
| A5 | A Win32-OpenSSH 9.5.0.0p1 zip can be installed and run on windows-latest runners | Pitfall 1 | Keep the manual Daniel-PC check as the only Windows evidence |
| A6 | Proxmox vTPM is swtpm and identifiable by manufacturer/vendor string | Pitfall 8 | `doctor` relies on the declared custody instead |
| A7 | `synchronous=FULL` in WAL mode makes each commit durable before return | Pattern 4 | Weaker durability; verify in the SQLite docs during implementation |
| A8 | Phase 1 issuance evidence = admin SSHSIG over the request digest, with admin keys in the root-signed genesis policy | Open Q1 | Owner may prefer a different Phase 1 authorization model |
| A9 | `hiddeco/sshsig` exists as an alternative | Alternatives | None (not recommended) |
| A10 | A separate `tools/go.mod` is preferable to the `tool` directive in the main module | Alternatives | Minor; CLAUDE.md mentions the tool directive, so the owner decides |
| A11 | TPM NV counters do not survive vTPM snapshot restore | Pattern 3 | Only affects optional hardening |

## Open Questions (RESOLVED)

All four questions were answered by the owner on 2026-10-04 (01-CONTEXT.md D-13..D-15) or settled within the planner's discretion; the plans implement each resolution.

1. **What authorizes issuance in Phase 1, before WebAuthn (KEY-02, Phase 2)?**
   - What we know: the signer must be default-deny and must verify evidence itself; success criterion 4 needs an issued cert.
   - What's unclear: whether the owner accepts a Phase 1 "bootstrap admin SSHSIG" evidence type (admin pubkeys in the root-signed genesis policy, CLI signs via ssh-agent).
   - Recommendation: adopt it as an explicit, logged evidence type `admin-sshsig/v1`. Phase 2 adds `webauthn/v1` and policy decides which CAs accept which. Confirm with the owner.
   - RESOLVED: D-13. Issuance requires `admin-sshsig/v1` evidence over the request digest from an admin key in the root-signed genesis policy; implemented in plan 01-07 (assumption A8 confirmed).
2. **Should log refusals be logged?** Logging every refused request is good visibility but is DoS-able. Recommendation: log refusals rate-limited and aggregated; always log `clock_regression`, bundle installs and `ca_init`.
   - RESOLVED: D-14. Every refusal goes to slog; refusals enter the Merkle log under a rate limit, and suppressed ones are counted in periodic summary entries; implemented in plan 01-05.
3. **merkle vs sumdb/tlog** (one fewer dependency). Recommendation: keep the locked merkle unless the owner opts in.
   - RESOLVED: D-15. `github.com/transparency-dev/merkle` stays; `x/mod/sumdb/tlog` was considered and rejected; plan 01-05 uses merkle for hashing and `sumdb/note` only for checkpoints.
4. **Bot name.** `keyroster-bot` is free (404 on 2026-10-04). Recommendation: use it.
   - RESOLVED: planner's discretion under D-05 (01-CONTEXT "Claude's Discretion"). The account is `keyroster-bot`, created by the owner in plan 01-01 Task 2.

Related assumptions settled by the plans rather than by an owner answer: A1/A2 (swtpm transport) by the CI spike order vtpm-proxy → unixio → tcp in plan 01-11, which records the transport it keeps; A3/A4 (ruleset admin role id 5, Actions integration id 15368) by the live API checks and the documented fallback in plan 01-01 Task 3; A5 by keeping the manual Windows 9.5p2 run (plan 01-15) as the Windows evidence.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | Everything | ✗ (not on Daniel-PC PATH, not in WSL) | — | Install go1.27.1 (Windows MSI and/or WSL tarball) as the first task |
| git | Repo | ✓ | 2.55.0.windows.5 | — |
| gh CLI (authenticated as Labontese) | Repo, rulesets, bot setup | ✓ | 2.87.3; scopes `admin:ssh_signing_key, repo, user, workflow` | — |
| Owner SSH signing key registered | REPO-01 | ✗ (none registered; git signing unconfigured) | — | Register and configure in bootstrap |
| Bot account | D-05 | ✗ (must be created by the owner, with email verification) | — | Human task; until then the owner bypass covers the bootstrap PRs |
| WSL Ubuntu | Local e2e (sshd, softhsm2, swtpm) | ✓ (stopped) | Ubuntu 24.04.3, OpenSSH 9.6p1 | CI only |
| softhsm2 / swtpm / opensc | KEY-03/04 tests | apt candidates only (not installed) | 2.6.1 / 0.7.3 / 0.25.0~rc1 | `apt install` in CI/WSL |
| Docker | Not required (non-root sshd approach) | Installed, engine stopped | 29.7.2 | — |
| Windows inbox OpenSSH | CA-08 manual check | ✓ | `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` | — |
| Git-for-Windows OpenSSH | Local oracle only | ✓ | OpenSSH_10.5p1 | — |
| Proxmox VM with vTPM | D-08 dogfood | Not verified (the TPM probe timed out during discuss) | — | Owner creates the VM; human-verify task |

**Missing dependencies with no fallback:** Go toolchain (install it), the bot account (only the owner can create it), and the owner's signing key (owner action).
**Missing dependencies with fallback:** softhsm2/swtpm/sshd builds run in CI, with WSL optional.

## Validation Architecture

Skipped: `workflow.nyquist_validation` is `false` in `.planning/config.json`. Test expectations are folded into the Patterns and Pitfalls above (negative sshd matrix, tamper/removal audit tests, fuzz targets per decoder, differential SSHSIG vs `ssh-keygen -Y`).

## Security Domain

Required: `security_enforcement: true`, ASVS level 1, `security_block_on: high`.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Partly (admin evidence for issuance; root passphrases) | Admin SSHSIG verified in the signer; age scrypt for roots; WebAuthn in Phase 2 |
| V3 Session Management | No (no web/session in Phase 1) | — |
| V4 Access Control | Yes | UDS `SO_PEERCRED` allowlist; default-deny request dispatch; root cannot sign certs; GitHub rulesets |
| V5 Input Validation | Yes | Principal allowlist regex; strict `cryptobyte` decoding; canonical-JSON re-marshal equality; fuzzing |
| V6 Cryptography | Yes | x/crypto/ssh, stdlib ECDSA/Ed25519, age, RFC 6962 hashing; no custom primitives; no RSA/SHA-1 CA |
| V7 Error handling and logging | Yes | Every error = deny; `errcheck`/`errorlint`; log-before-release; restricted key-ID charset (log injection) |
| V10 Malicious code / V14 Config (supply chain) | Yes | SHA-pinned actions, `permissions: {}`, govulncheck, capslock, Dependabot, CodeQL, Scorecard, signed commits |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Empty/wildcard principals (Vault CVE-2024-7594 class) | Elevation | Builder refuses; negative sshd tests on 9.5p1 + 10.5p1 |
| Cert used as CA (Teleport CVE-2025-49825 class) | Elevation | `SignCert` refusal (verified) + `ca init` check + agent-signer filter |
| Authz error ignored on an error path (step-ca CVE-2025-44005 class) | Elevation | Default-deny dispatch; errcheck in CI; explicit handler per message type |
| Serial reuse after restore | Repudiation/Tampering | Clock-floor allocator; fail-closed on clock regression |
| Log rewrite by DB-level attacker | Tampering | Signed checkpoints with the log key; `audit verify`; witnesses in Phase 4 |
| Self-signed bundle accepted | Spoofing | Out-of-band pinned root fingerprints; previous-bundle threshold |
| Compromised CI action (tj-actions class) | Tampering | SHA pinning, harden-runner (optional), least-privilege tokens, `persist-credentials: false` |
| Signer network exposure | Information disclosure | No HTTP/TLS packages (CI firewall), `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` |
| Forwarded/locked agent abuse of the signer's ssh-agent | Elevation | Dedicated private agent socket, never forwarded; OpenSSH ≥ 10.5 where possible |

## Sources

### Primary (HIGH confidence)
- proxy.golang.org `@latest` + module zips (2026-10-04): x/crypto v0.57.0 (`ssh/certs.go` 57-145, 422, 470-527; `ssh/keys.go` 1206-1230), x/mod v0.41.0 (`sumdb/note/note.go` 84-90, 190-215; `sumdb/tlog/tlog.go`), go-tpm v0.9.8 (`tpm2/transport/{linuxtpm,linuxudstpm,tcp,simulator}`), go-tpm-keyfiles @8c9c2d1005f4 (`go.mod`, `signer.go`, `loadablekey.go`, `tpm.go:436`), merkle v0.0.2 (`rfc6962.go:30`, `compact/range.go`, `proof/verify.go`), piv-go v2.6.0 (`piv/key.go` 477-479, 1051, 1176; cgo files), age v1.3.2 (`go.mod`, `scrypt.go`)
- go.dev/dl JSON: go1.27.1
- cdn.openbsd.org portable listing + tarball download/sha256 (9.5p1, 10.5p1; no 9.5p2)
- openssh.org release notes 10.1, 10.2, 10.3, 10.4, 10.5 (fetched with curl)
- openssh-portable `PROTOCOL.sshsig` (master); openssh-10.5p1 `Makefile.in` 760-775, `regress/test-exec.sh` 711-728
- `gh api`: Win32-OpenSSH releases; action release tags and SHAs; repo/user existence; signing-key scopes
- Local probes: Daniel-PC tools, WSL Ubuntu 24.04 packages

### Secondary (MEDIUM confidence)
- C2SP signed-note spec (signature types 0x01/0x02/0x04/0x05/0x06; ECDSA key ID) — github.com/C2SP/C2SP signed-note.md
- docs.github.com: rulesets REST API (bypass modes), available rules (signed commits/squash), commit signature verification (rebase merge unsigned), GitHub Terms of Service (machine accounts)
- pkg.go.dev/modernc.org/sqlite (DSN parameters, driver name)

### Tertiary (LOW confidence)
- swtpm man page (server types; protocol not stated); web search on linuxudstpm + swtpm (inconclusive)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Versions come from the registry and APIs were read in source.
- Architecture: MEDIUM-HIGH. The patterns are synthesis, but every library seam they rely on was verified.
- Pitfalls: HIGH for OpenSSH and x/crypto items (primary sources); MEDIUM for GitHub settings; LOW for swtpm transport and Windows runners (spike items).

**Research date:** 2026-10-04
**Valid until:** 2026-11-03 (30 days; re-resolve action SHAs and the go-tpm-keyfiles pseudo-version at execution)
