# Stack Research

**Domain:** Self-hosted, security-first SSH certificate authority and access manager (server, CLI, web UI, host agent for Linux/Windows/macOS/FreeBSD)
**Researched:** 2026-10-04
**Confidence:** HIGH for language choice and versions; MEDIUM for the audit-log and key-protection design

> **How versions and confidence were checked.** Every version below was read straight from the
> official registries on 2026-10-04: `proxy.golang.org/<module>/@latest`, the crates.io API,
> the npm registry, `go.dev/dl` and GitHub releases. Treat them as HIGH confidence. Library
> capabilities (cgo needs, algorithm support, missing KRL support) were checked in source code or
> official READMEs where noted. The GSD `classify-confidence` seam rates plain web fetches and
> searches as LOW (MEDIUM when cross-checked), so any claim that rests only on web search is
> tagged that way below.

---

## TL;DR (the decisions)

1. **Language: Go 1.27.x** (`go 1.26` directive, toolchain pinned to `go1.27.1`). Build pure Go with `CGO_ENABLED=0` for every binary except an optional hardware-signer build. **Not Rust.** HIGH confidence.
2. **SSH:** `golang.org/x/crypto/ssh` v0.57.0, used only for parsing and signing, plus `x/crypto/ssh/agent`. **KRL is not in x/crypto.** We write and own a small KRL encoder, tested against `ssh-keygen` as the oracle. HIGH.
3. **CA key protection:** keep the **online user/host CA key** behind a small `crypto.Signer` interface with these backends, in priority order:
   1. **TPM 2.0**: `google/go-tpm`, pure Go, ECDSA P-256 key that cannot be exported.
   2. **YubiHSM 2 or another PKCS#11 HSM**, reached through **OpenSSH's own `ssh-agent` + PKCS#11 provider**. Our binary stays cgo-free.
   3. **YubiKey PIV**: `piv-go/v2`. Needs cgo on Unix.
   4. **age-encrypted software key**: the documented fallback. It does not hold up if the server is compromised.

   A separate **offline Ed25519 "trust root" key** signs the CA key set and KRL bundles that host agents accept. OpenSSH certificates do not chain, so a classic offline-root/intermediate setup does not apply. MEDIUM.
4. **Identity:** `github.com/go-webauthn/webauthn` v0.18.2 (passkeys / FIDO2) and `x/crypto/argon2` (argon2id) for passwords. TOTP is optional and in-house (RFC 6238, about 80 LOC), or skipped entirely in favour of WebAuthn plus recovery codes. HIGH.
5. **Storage: SQLite only**, via `modernc.org/sqlite` v1.60.1 (pure Go). No Postgres or bbolt in v1. HIGH.
6. **Audit log:** a Merkle tree log (RFC 6962 / C2SP tlog) **stored in the same SQLite transaction as each state change**. It publishes C2SP signed-note checkpoints (`golang.org/x/mod/sumdb/note`) and uses `transparency-dev/merkle` for proofs. Host agents and the CLI act as witnesses that store checkpoints. No Trillian, and no Tessera in v1. MEDIUM.
7. **Web UI:** server-rendered stdlib `html/template` plus a few hundred lines of our own vanilla JS (WebAuthn ceremony only), embedded with `embed.FS` and served under a strict CSP. **No SPA, no npm, no build step.** HIGH.
8. **Supply chain:** GoReleaser v2.18.2 for reproducible builds (`-trimpath`, `CGO_ENABLED=0`, commit-timestamp mtime). Keyless signing with cosign v3.1.3 plus an SSHSIG signature from a maintainer hardware key. GitHub `actions/attest-build-provenance` v4.2.2 for SLSA provenance. Syft v1.54.0 or cyclonedx-gomod v1.12.0 for the SBOM. govulncheck v1.8.0, capslock v0.3.3, golangci-lint v2.14.0 and native fuzzing in CI. HIGH.

---

## 1. Implementation Language: Go vs Rust → **Go**

| Criterion | Go (1.27) | Rust (1.8x) | Winner |
|---|---|---|---|
| SSH certificate signing / parsing | `x/crypto/ssh` v0.57.0: `ssh.Certificate`, `SignCert`, `MultiAlgorithmSigner`, sk-ed25519/sk-ecdsa public keys, `CertChecker`. The de facto library behind Teleport, step-ca, Vault SSH, BLESS-era tools. Maintained by the Go security team. | `ssh-key` (RustCrypto) has certificate builder/signer, sk keys and SSHSIG. **Stable is 0.6.7; 0.7.0 has sat in rc (rc.11) for a long time**, and all of RustCrypto is pre-1.0. `russh` 0.63.3 is a protocol library we don't need (no proxy). | **Go**. More mature and battle-tested in exactly this product category. |
| KRL (OpenSSH Key Revocation List) | **Not in x/crypto.** `stripe/krl` is **archived** (last push 2025-04). `go-authn/krl` (BSD-3, created 2026-09-30, 0 stars) builds, parses and checks KRLs and tests against `ssh-keygen`. Too new to depend on, but a useful reference. | Not in `ssh-key` either (not even listed as a TODO). | Tie. **Both need us to own a KRL encoder**: about 400-600 LOC against `PROTOCOL.krl`, fuzzed, with `ssh-keygen -Q -f` as the test oracle. |
| ssh-agent client (put certs into the user's agent; use an agent as CA signer) | `x/crypto/ssh/agent`: add keys with lifetime and confirm constraints, add certificates, get a signer from an agent key. Windows named pipe `\\.\pipe\openssh-ssh-agent` via `Microsoft/go-winio` v0.6.2. | `ssh-agent-lib` 0.6.0: workable, smaller user base. | **Go** |
| Static cross-platform binaries | `GOOS=windows/darwin/freebsd/linux GOARCH=amd64/arm64 CGO_ENABLED=0 go build` from one Linux runner. FreeBSD binaries run on OPNsense/pfSense. Zero toolchain setup. | Needs a target toolchain per OS and a linker/SDK for macOS and FreeBSD (`cross`, zig-cc, osxcross). Workable, but more CI surface. | **Go**, clearly |
| Dependency footprint / auditability | The stdlib covers HTTPS server, TLS 1.3 (PQ hybrid by default since 1.26), X.509, Ed25519/ECDSA, HKDF, `html/template` (contextual auto-escaping), `net/http.CrossOriginProtection` (CSRF), method-pattern `ServeMux`, `log/slog`, `embed`, `database/sql`. The Go crypto stdlib was audited by Trail of Bits (2025). **Realistic direct deps: about 6-10 modules.** | An equivalent server needs tokio + hyper + axum (0.8.9) + rustls (0.23.45) + aws-lc-rs/ring + serde + a template engine: usually **150-300 crates** in the lockfile. `cargo-vet` makes that auditable, but it is far more to audit. | **Go**. "Minimal auditable attack surface" is a headline differentiator. |
| Memory safety | Memory-safe apart from data races and `unsafe`; GC'd. The race detector runs in CI. | Stronger guarantees (no data races in safe code). | Rust. But the security-critical crypto here is in Go's audited stdlib, and our code is mostly policy and plumbing, so the real-world gap is small. |
| Reproducible builds | The Go toolchain has been perfectly reproducible since Go 1.21. `CGO_ENABLED=0 -trimpath` gives bit-for-bit identical binaries across hosts with no extra work. | Achievable (`--remap-path-prefix`, pinned toolchain, `SOURCE_DATE_EPOCH`), but more fiddly, especially once C deps (aws-lc) are involved. | **Go** |
| Vulnerability scanning | `govulncheck` does **symbol-level reachability**: it only flags vulnerable functions you actually call, so there is little noise. The Go checksum database (sumdb) is itself a transparency log for module downloads. | `cargo-audit` 0.22.2 / `cargo-deny` 0.20.2 match at crate level, without reachability. | **Go** |
| WebAuthn | `go-webauthn/webauthn` v0.18.2 (used by Authelia, Gitea and others; maintained, last release 2026-09-19). | `webauthn-rs` 0.5.5 (kanidm), excellent and security-reviewed. | Tie |
| Ecosystem precedent | Teleport, step-ca, Vault, Boundary, Tailscale (tailssh) are all Go. | Few SSH-CA products. | **Go** |

**Recommendation: Go.** It wins on every criterion except memory-safety theory. The decisive factors match the project's constraints: one static binary per role for 4 OSes from a single CI job, a security-critical core that sits almost entirely in the audited stdlib (so there is little code to audit), symbol-level vuln scanning, and the most mature OpenSSH-certificate library in any language. Rust's advantage doesn't buy much here: OpenSSH (C) does the verification, and our code is policy logic.

**Security note on x/crypto/ssh (verified via pkg.go.dev/vuln, MEDIUM):** the 2026 advisories GO-2026-5013/5014/5015/5016/5018/5023 include an agent-client panic (5014) and a *certificate-restriction bypass in x/crypto's server-side CertChecker* (5015). All are fixed by v0.52.0. **Pin `golang.org/x/crypto >= v0.57.0`** and run `govulncheck` on every PR. Our design does **not** use x/crypto as an SSH server: stock OpenSSH verifies certificates. That keeps us out of most of that CVE class.

---

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended | Confidence |
|---|---|---|---|---|
| Go toolchain | **1.27.1** (go directive `1.26`) | Language/runtime for all binaries | See section 1. Go 1.27 adds ML-DSA and runtime/secret refinements; 1.26 adds PQ-hybrid TLS by default, randomized heap base, `crypto/hpke`, and mandatory secure randomness in crypto APIs. A `go 1.26` directive keeps us building on both supported Go releases. | HIGH |
| `golang.org/x/crypto` | **v0.57.0** | `ssh` (cert build/sign/parse), `ssh/agent`, `argon2`, `acme/autocert` (optional) | Canonical SSH implementation; maintained by the Go team. v0.52.0 or later is required for the 2026 SSH CVE fixes. | HIGH |
| Own `krl` package (internal) | n/a | Build the binary KRL per `PROTOCOL.krl` (serial ranges, key IDs, key blobs, SHA-256 fingerprints) | No maintained Go library: `stripe/krl` is archived and `go-authn/krl` is 4 days old. KRL is a small, well-specified format, and owning it keeps a security-critical path in our audited code. Use `go-authn/krl` (BSD-3) and OpenSSH `krl.c` as references. Test oracle: `ssh-keygen -Q -f revoked.krl cert.pub`. | HIGH (need) / MEDIUM (effort estimate) |
| SQLite via `modernc.org/sqlite` | **v1.60.1** | The only datastore: users, credentials, roles, hosts, issued-cert index, approvals, audit log | Pure Go (machine-translated SQLite C), so `CGO_ENABLED=0` holds and cross-compiles. One file, WAL mode, online backup via `VACUUM INTO`. Fits "one binary, up in minutes". | HIGH |
| `net/http` + `html/template` + `embed` (stdlib) | Go 1.27 | HTTPS API for CLI and agents; server-rendered web UI | Contextual auto-escaping stops most XSS. `http.CrossOriginProtection` (Go 1.25+) provides Fetch-Metadata CSRF defence. Go 1.22+ `ServeMux` method/wildcard routing removes the need for a router dependency. | HIGH |
| `github.com/go-webauthn/webauthn` | **v0.18.2** | Passkey/FIDO2 registration and assertion; also binds WebAuthn assertions to signing requests | Most widely used Go WebAuthn relying-party library, actively maintained. Requires go ≥ 1.26. Deps: fxamacker/cbor, go-webauthn/x, golang-jwt (for MDS), google/go-tpm (for TPM attestation), uuid, msgp. | HIGH |
| `golang.org/x/mod/sumdb/note` | **x/mod v0.41.0** | C2SP signed-note format: audit-log checkpoints and signed trust bundles (CA key set + KRL) for host agents | The Go module mirror uses the same Ed25519 signed-note format, and so do the C2SP witness ecosystem, Sigsum and Tessera. Tiny and stdlib-adjacent. | HIGH |
| `github.com/transparency-dev/merkle` | **v0.0.2** | RFC 6962 Merkle hashing, compact ranges, inclusion/consistency proofs for the audit log | Small and stable (the version number undersells it). It is the proof library Tessera and the transparency-dev ecosystem use. | MEDIUM |
| `filippo.io/age` | **v1.3.2** | At-rest encryption of the software CA key (fallback backend), encrypted backups and exports | Modern, small, audited format. Supports passphrase (scrypt), X25519 and post-quantum hybrid recipients, plus plugins (`age-plugin-yubikey`, `age-plugin-tpm`), so a backup can be unlocked with a hardware token. | HIGH |

### CA Key Protection: Signer Backends

All backends implement one internal `Signer` interface (`crypto.Signer` → `ssh.Signer` via `ssh.NewSignerFromSigner`). Selection is a URI in config, e.g. `tpm:handle=0x81000001`, `agent:/run/sshca/agent.sock`, `piv:slot=9c`, `file:/var/lib/sshca/ca.age`.

| Backend | Library / Version | cgo? | CA algorithm | Use when | Confidence |
|---|---|---|---|---|---|
| **TPM 2.0 (default when available)** | `github.com/google/go-tpm` **v0.9.8** (TPM 2.0 `tpm2` package); `github.com/foxboron/go-tpm-keyfiles` (pseudo-version 2026-09-02) for the standard TSS2 PEM key-file format | **No.** Pure Go; Linux `/dev/tpmrm0`, Windows TBS | **ECDSA P-256** (TPMs practically never implement Ed25519) | The CA server has a TPM (most servers and mini-PCs, plus vTPM in Proxmox). The key is created inside the TPM and cannot be exported. Add an authValue/PIN policy. | HIGH (lib) / MEDIUM (hardware variance) |
| **Any PKCS#11 HSM via ssh-agent** (YubiHSM 2, Nitrokey HSM 2, SmartCard-HSM, SoftHSM2 for tests) | `x/crypto/ssh/agent` against OpenSSH `ssh-agent` loaded with `ssh-add -s /usr/lib/.../pkcs11.so` | **No** | Ed25519 (YubiHSM 2), P-256/P-384, RSA | You want HSM-grade protection without linking C into the CA. OpenSSH's `ssh-pkcs11-helper` already isolates the vendor PKCS#11 module in a separate process, which is better isolation than dlopen'ing it into our server. | MEDIUM |
| YubiKey 5 PIV (direct) | `github.com/go-piv/piv-go/v2` **v2.6.0** | **Yes on Linux/macOS/FreeBSD** (pcsc-lite via cgo; verified in source: `pcsc_unix.go` has `import "C"`). No on Windows (winscard via syscall) | Ed25519 (firmware ≥ 5.7, `AlgorithmEd25519` present in source), P-256/P-384, RSA | Small teams with a YubiKey on the CA host who want touch/PIN policy per signature. Ship as a separate `-tags piv` build or route through `yubikey-agent`/ssh-agent instead. | HIGH |
| PKCS#11 (direct, optional build) | `github.com/miekg/pkcs11` **v1.1.2** + `github.com/ThalesGroup/crypto11` **v1.6.8** | **Yes** (dlopen) | depends on token | Only if the ssh-agent route proves inadequate, e.g. you need key-generation automation. Build-tag-gated, never in the default binary. | HIGH (libs) |
| age-encrypted software key (fallback) | `filippo.io/age` v1.3.2; Ed25519 via stdlib | No | **Ed25519** | Homelab or evaluation without hardware. The key is decrypted into memory at start. Optionally run signing under `runtime/secret` (`GOEXPERIMENT=runtimesecret`, Linux amd64/arm64, experimental since 1.26). **Must be documented as NOT meeting the "CA server compromised" threat model.** | HIGH |

**Key design facts the roadmap must absorb (MEDIUM; these follow from OpenSSH semantics):**
- **OpenSSH certificates do not chain.** sshd trusts exactly the keys in `TrustedUserCAKeys` / `@cert-authority`. An "offline root + online intermediate" design therefore cannot work the X.509 way. Use instead:
  - an **online CA key** (hardware-backed, as above) that signs certificates;
  - a separate **offline trust-root key** (Ed25519 on a YubiKey or an air-gapped machine) that signs **trust bundles**: the list of valid CA public keys and the current KRL, in signed-note format. Host agents pin the trust-root public key at enrollment and refuse unsigned CA-set changes. This prevents a compromised server from adding a rogue CA key to every host, and it makes CA rotation (old and new key both listed) safe.
- OpenSSH KRL files can carry signatures, but **sshd ignores them**. Integrity in transit must therefore come from our bundle signature, checked by the host agent before it writes the file `RevokedKeys` points to.
- **No backend survives a server compromise in the "signing oracle" sense.** Hardware only guarantees non-exportability, so an attacker can sign only while they are present. To actually hold under the threat model, run the signer as a **separate small process/binary** (`sshca-signer`, separate OS user, Unix socket / named pipe, narrow protocol). It **refuses to sign unless the request carries a WebAuthn assertion whose challenge is the hash of the exact certificate request**, plus, for sensitive principals, a second approver's assertion. A compromised API/web process then cannot mint certificates on its own. The signer also writes the audit entry. This is the most important architectural consequence of the stack choice. Flag it for the architecture/roadmap phase.

### Supporting Libraries

| Library | Version | Purpose | When to Use | Confidence |
|---|---|---|---|---|
| `golang.org/x/sys` | v0.48.0 | `windows` (services via `windows/svc`, ACLs via `SetNamedSecurityInfo` for `administrators_authorized_keys`), `unix` (file perms, `flock`) | Host agent on Windows and Unix. Prefer it over `kardianos/service`, since it is already a transitive dependency. | HIGH |
| `github.com/Microsoft/go-winio` | v0.6.2 | Windows named pipes (`\\.\pipe\openssh-ssh-agent`) for the CLI to load certs into the Windows OpenSSH agent | CLI on Windows only (build-tag file). The last release is 2024-04, but the module is stable and very widely used. | HIGH |
| `golang.org/x/term` | v0.46.0 | Hidden passphrase / PIN prompts in the CLI | CLI | HIGH |
| `golang.org/x/time/rate` | x/time v0.16.0 | Rate limiting login, WebAuthn and signing endpoints | Server | HIGH |
| `golang.org/x/crypto/argon2` | (in x/crypto v0.57.0) | argon2id password hashing | Local accounts (password plus mandatory WebAuthn) | HIGH |
| `golang.org/x/crypto/acme/autocert` | (in x/crypto) | Optional automatic TLS certificate for the web UI | Only when the server is internet-reachable. Default: self-signed with the fingerprint pinned in agent join tokens and CLI config. | HIGH |
| `github.com/BurntSushi/toml` | v1.6.0 | Human-editable config file | Zero dependencies. Alternative: JSON via stdlib if we want no dependency at all. | HIGH |
| TOTP (in-house, `internal/totp`) | n/a | RFC 6238 verification with RFC test vectors | **Only** if TOTP is kept as a non-signing second factor. Recommendation: WebAuthn mandatory, plus one-time recovery codes (stdlib `crypto/rand` + argon2id), and no TOTP (it is phishable). If a library is preferred: `github.com/pquerna/otp` v1.5.0 (stable, last release 2024-12). | HIGH |
| `github.com/transparency-dev/formats` | v0.1.1 | C2SP checkpoint (`log` package) parsing/formatting | Audit-log checkpoints, so third-party tooling (torchwood, witnesses) can verify our log | MEDIUM |
| `filippo.io/torchwood` | v0.10.0 | tlog client / witness / tile-serving helpers (Filippo Valsorda) | Reference implementation, or a dependency for the agent-side "witness" logic. Evaluate during the audit-log phase. | LOW (needs evaluation) |
| `sigsum.org/sigsum-go` | v0.14.1 | Optional: publish audit checkpoints to a public Sigsum log for external anchoring | **v2 / opt-in only.** It is an external service, so it must not be core-path. | MEDIUM |
| `sqlc` (dev tool) | v1.31.1 | Generate type-safe `database/sql` code from SQL | Optional. The generated code only imports `database/sql`, so there is no runtime dependency. Hand-written queries are equally fine at this size. | MEDIUM |

### Development Tools

| Tool | Version | Purpose | Notes |
|---|---|---|---|
| `govulncheck` (`golang.org/x/vuln`) | v1.8.0 | Reachability-aware vuln scan | Every PR plus nightly. Fail the build on reachable vulns. Also scan released binaries (`govulncheck -mode=binary`). |
| `golangci-lint` | v2.14.0 | Meta-linter (staticcheck, gosec, errcheck, revive, …) | Enable `gosec`, `staticcheck` (honnef.co/go/tools v0.8.1), `bodyclose`, `errorlint`, `forbidigo` (ban `math/rand`, `os/exec` outside allowlisted pkgs). |
| `gosec` | v2.29.0 | Security linter | Also runs inside golangci-lint. |
| `capslock` (google) | v0.3.3 | Capability analysis: which packages can reach network, exec, files, unsafe or reflect | Run on every dependency bump; diff capability sets. Good fit for "minimal auditable attack surface". |
| Native Go fuzzing (`go test -fuzz`) | Go 1.27 | Fuzz the KRL encoder/parser, cert-request parser, signed-note/bundle parser, agent protocol | Mandatory for every parser. Keep a corpus in-repo. |
| `ssh-keygen` / `sshd` (OpenSSH) | ≥ 9.x; latest portable 10.5p1 | **Integration-test oracle**: verify certs with `ssh-keygen -L`, KRLs with `ssh-keygen -Q`, real logins against a containerized sshd | Also test against Windows OpenSSH (Win11 built-in plus Win32-OpenSSH 10.0.0.0p2-Preview) on the Windows CI lane. |
| SoftHSM2 / swtpm | distro packages | PKCS#11 and TPM backends in CI without hardware | Avoid `go-tpm-tools/simulator` in the main module: it is cgo (MS reference TPM). Use `swtpm` over a socket instead. |
| `osv-scanner` | v2.6.0 | Second opinion on deps (OSV database), incl. GitHub Actions | CI |
| OpenSSF Scorecard action | v2.4.4 | Repo hygiene score (branch protection, pinned actions, token perms) | CI, published badge |

### Supply Chain & Release

| Tool | Version | Purpose | Notes | Confidence |
|---|---|---|---|---|
| GoReleaser | v2.18.2 | Cross-compile all OS/arch, archives, checksums, SBOM hook, signing hook | `CGO_ENABLED=0`, `flags: [-trimpath]`, `ldflags: -s -w -buildid=`, `mod_timestamp: "{{ .CommitTimestamp }}"`, `gomod.proxy: true`. Builds are bit-for-bit reproducible. | HIGH |
| Reproducibility check | n/a | Rebuild each tag on a second, independent runner (and later by third parties) and compare SHA-256 | Publish the instructions. Go's toolchain is itself reproducible, so the only variable is our flags. | HIGH |
| cosign (sigstore) | v3.1.3 | Keyless signing of `checksums.txt` (and container image if any) with GitHub OIDC; Rekor transparency entry | v3 writes the sigstore bundle format by default. Verify with `cosign verify-blob --bundle`. | HIGH |
| SSHSIG signature by maintainer key | OpenSSH `ssh-keygen -Y sign` (FIDO `ed25519-sk` key) | Second, sigstore-independent signature on `checksums.txt` | Fits the audience: users verify with `ssh-keygen -Y verify` and an `allowed_signers` file published in the repo. This also removes the single dependency on sigstore infrastructure. | MEDIUM |
| GitHub artifact attestations | `actions/attest-build-provenance` v4.2.2 | SLSA build provenance (in-toto, sigstore-signed) | Gives SLSA Build L2 out of the box, and L3 when the build runs in an isolated reusable workflow. Users verify with `gh attestation verify`. Prefer it over `slsa-github-generator` (last release v2.1.0, 2025-02, slower cadence). | MEDIUM |
| SBOM | `syft` v1.54.0 (via GoReleaser `sboms:`) or `cyclonedx-gomod` v1.12.0 | SPDX/CycloneDX SBOM per artifact | Go embeds module info in binaries (`go version -m`), so the SBOM is accurate by construction. `cyclonedx-gomod` gives the most precise module graph; syft is simplest in GoReleaser. Pick one. **Recommend cyclonedx-gomod (`app` mode) for binaries.** | HIGH |
| Dependency policy | `go mod verify`, sumdb (default), Renovate/Dependabot with grouped x/* updates | Integrity of module downloads | Never set `GONOSUMDB`/`GOFLAGS=-insecure`. Pin all GitHub Actions by commit SHA. | HIGH |

---

## Installation

```bash
# Toolchain
go mod init github.com/<org>/sshca
go mod edit -go=1.26 -toolchain=go1.27.1

# Core
go get golang.org/x/crypto@v0.57.0          # ssh, ssh/agent, argon2, acme/autocert
go get modernc.org/sqlite@v1.60.1
go get github.com/go-webauthn/webauthn@v0.18.2
go get golang.org/x/mod@v0.41.0              # sumdb/note (signed notes)
go get github.com/transparency-dev/merkle@v0.0.2
go get filippo.io/age@v1.3.2

# Platform / supporting
go get golang.org/x/sys@v0.48.0
go get golang.org/x/term@v0.46.0
go get golang.org/x/time@v0.16.0
go get github.com/Microsoft/go-winio@v0.6.2  # CLI, windows build tag only
go get github.com/BurntSushi/toml@v1.6.0
go get github.com/google/go-tpm@v0.9.8       # TPM signer backend (pure Go)

# Optional, build-tag-gated (cgo) hardware backends — NOT in default binaries
go get github.com/go-piv/piv-go/v2@v2.6.0     # -tags piv
go get github.com/ThalesGroup/crypto11@v1.6.8 # -tags pkcs11

# Dev tools (go 1.24+ `tool` directive keeps them versioned in go.mod)
go get -tool golang.org/x/vuln/cmd/govulncheck@v1.8.0
go get -tool github.com/google/capslock/cmd/capslock@v0.3.3
go get -tool github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0
# golangci-lint v2.14.0, goreleaser v2.18.2, cosign v3.1.3, syft v1.54.0: install as pinned CI binaries (not go.mod tools; heavy dep trees)
```

---

## Storage: why SQLite, and why not the others

| Option | Verdict | Reason |
|---|---|---|
| **SQLite (`modernc.org/sqlite`)** | **Use** | Single file, ACID, WAL. The **audit entry and the state change commit in one transaction**, which is the key property for a tamper-evident log tied to issuance. Pure Go keeps static builds. Backup with `VACUUM INTO` + age encryption. |
| `mattn/go-sqlite3` v1.14.52 | Avoid (default build) | Requires cgo, which breaks `CGO_ENABLED=0` cross-compilation and reproducibility. Slightly faster, but we are nowhere near that limit (a CA issues at most thousands of certs a day). |
| bbolt v1.5.0 | Avoid | KV only: we would hand-roll indexes, queries and migrations for relational data (users ↔ roles ↔ principals ↔ hosts). More of our own code to audit. |
| PostgreSQL (`pgx/v5` v5.11.0) | Not in v1 | Breaks "one binary, up in minutes" and adds a networked attack surface and credentials. Only consider it if HA/active-active becomes a requirement (v2+). Keep the SQL portable (no SQLite-only JSON tricks in hot paths) to leave the door open. |
| Migrations | In-house, ~50 LOC | Embedded `migrations/*.sql` + `PRAGMA user_version`. Avoid `goose` (v3.28.0) and similar: they pull extra dependencies for a trivial job. |

## Tamper-Evident Audit Log: approach

| Option | Verdict | Reason |
|---|---|---|
| Plain hash chain in a table | Insufficient alone | Someone with DB write access (a compromised server) can **recompute the whole chain**. Tamper evidence only holds when heads are **anchored outside the server**, and a chain has no efficient consistency proofs for external verifiers. |
| **Merkle log in SQLite + signed checkpoints + agent/CLI witnesses** | **Use** | RFC 6962 tree (`transparency-dev/merkle`), with entries and tree nodes written in the same transaction as the state change. Each period or batch, the signer process signs a C2SP checkpoint (`sumdb/note`). Every host agent and CLI stores the latest checkpoint and **requests a consistency proof** on the next sync. A rewritten history is detected by every agent fleet-wide. This gives "nobody can hide what they granted" without any external service. Expose a read-only tlog-tiles-compatible endpoint so standard tooling and external C2SP witnesses can cosign later. |
| Tessera v1.0.4 | Not in v1; revisit | Production-ready successor to Trillian with a POSIX driver and witness support. But it is a **second storage system**: atomicity between "cert issued" in SQLite and "entry in log" in tiles on disk becomes a distributed-commit problem. Its antispam is best-effort. Worth adopting if the log ever needs to be public or large-scale. |
| Trillian v1.8.0 | Avoid | Needs MySQL/Spanner, separate gRPC log server and signer. The maintainers call it superseded by Tessera. Massive overkill. |
| Sigsum (`sigsum-go` v0.14.1) | Optional v2 | Publishing checkpoints to a public Sigsum log gives strong external anchoring, but it is an external dependency, so it can only be opt-in. |

## Web UI: approach

- **Server-rendered `html/template` pages**, plain HTML forms, POST-redirect-GET, all assets in the binary via `embed.FS`. No npm, no bundler, no node_modules in the supply chain.
- **One small hand-written JS file** (~200-400 LOC) for the WebAuthn ceremony (`navigator.credentials.create/get`, base64url (de)serialization) and optional progressive enhancement. Do not use `@simplewebauthn/browser` (v14.0.0): it is nice, but it brings an npm dependency for something the browser API already does.
- **Headers:** `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, plus `http.CrossOriginProtection`, `SameSite=Strict; Secure; HttpOnly; __Host-` session cookies, HSTS, `Cross-Origin-Opener-Policy: same-origin`.
- htmx 2.0.11 is an *acceptable* later addition (one vendored file, CSP-compatible with `allowEval=false`), but **not in v1**. Every added script is attack surface for the most privileged UI.
- templ v0.3.1020 (type-safe templates) is a reasonable alternative to `html/template`. Rejected for v1 because it adds a code generator and a pre-1.0 runtime dependency, while `html/template` is stdlib and contextually escapes.

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|---|---|---|
| Go | Rust (`ssh-key`, `webauthn-rs`, `axum`, `rusqlite`) | If the team were Rust-native and willing to own cross-compilation and a 200+-crate audit with `cargo-vet`. Or for a tiny standalone component where memory-safety guarantees outweigh ecosystem fit (e.g. a future hardware-signer daemon). |
| Own signer abstraction | `go.step.sm/crypto` / `smallstep/crypto/kms` v0.91.0 | It already has `tpmkms`, `yubikey`, `pkcs11`, `sshagentkms` URIs. Use it as a **reference design**, not a dependency: the module also pulls cloud KMS SDKs (AWS/GCP/Azure), which explodes `go.sum`. |
| SQLite | PostgreSQL | HA/multi-node CA (v2+), or a customer mandate for an existing DB |
| Merkle-in-SQLite | Tessera (POSIX) | Public log, very high volume, or reuse of the tlog-tiles static-serving tooling |
| stdlib `ServeMux` | `go-chi/chi/v5` v5.3.2 | Only if middleware grouping gets painful. chi is zero-dep and fine, but the 1.22+ mux covers our needs. |
| stdlib `flag` + tiny subcommand dispatcher | `alecthomas/kong` v1.16.1 / `spf13/cobra` v1.10.2 | kong if CLI ergonomics (help, completion) matter more than one dependency. Cobra brings pflag and mousetrap, so prefer kong. |
| `log/slog` | zerolog v1.35.1 | Never: slog is sufficient |
| `x/sys/windows/svc` + systemd/rc.d/launchd files | `kardianos/service` v1.3.0 | If service install across 4 OSes becomes a big maintenance burden. Still small, but adds an abstraction we'd have to audit. |
| cyclonedx-gomod | syft | syft if we ship container images too (scans OS layers) |

## What NOT to Use

| Avoid | Why | Use Instead |
|---|---|---|
| `stripe/krl` | **Archived** (2025-04), no fixes | Own `internal/krl`, tested against `ssh-keygen` |
| `github.com/mattn/go-sqlite3` in default builds | cgo breaks static cross-compiles and reproducibility | `modernc.org/sqlite` |
| SPA frameworks (React/Vue/Svelte) + npm | Hundreds of transitive packages in the *most privileged* UI, a build toolchain in the supply chain, and token storage in JS | `html/template` + minimal vanilla JS |
| Trillian | Heavy (MySQL, gRPC services), superseded | Merkle-in-SQLite now, Tessera later if needed |
| Postgres in v1 | Kills single-binary simplicity; extra network attack surface | SQLite |
| RSA CA keys / `ssh-rsa` (SHA-1) signatures | SHA-1 `ssh-rsa` is disabled by default in modern OpenSSH. RSA keys are large and slow. | Ed25519 CA (software, YubiHSM 2, YubiKey ≥ 5.7), **ECDSA P-256** where hardware lacks Ed25519 (TPM, older YubiKeys) |
| X.509-style "intermediate CA" for SSH | OpenSSH certs don't chain, so it silently fails or forces every host to trust the intermediate anyway | Offline trust-root signs CA-set bundles; online CA signs certs |
| `go-tpm-tools/simulator` in the main module | cgo dependency | `swtpm` in CI |
| Linking vendor PKCS#11 `.so` into the CA server by default | Vendor C code inside our most sensitive process; cgo | OpenSSH `ssh-agent` + `ssh-pkcs11-helper` (process isolation), reached via `x/crypto/ssh/agent` |
| TOTP as a factor that can authorize certificate signing | Phishable and replayable within its window; weaker than our threat model | WebAuthn assertions bound to the signing request |
| `slsa-github-generator` as the primary provenance path | Slower release cadence (v2.1.0, 2025-02); GitHub-native attestations now cover it | `actions/attest-build-provenance` v4.2.2 |
| `math/rand`, custom crypto, JWT session tokens | Footguns. JWT adds alg-confusion risk for no benefit in a monolith. | `crypto/rand`, stdlib primitives, opaque random session IDs stored server-side |

## Stack Patterns by Variant

**Default (homelab / small team, no HSM):**
- TPM backend if `/dev/tpmrm0` or Windows TBS is present, otherwise the age-encrypted file key with a loud warning in the UI and `doctor` output.
- Offline trust root on a YubiKey (`ed25519-sk` or PIV), used only for CA rotation and bundle re-signing.

**Security-sensitive team:**
- YubiHSM 2 via `ssh-agent` + PKCS#11 (Ed25519), with the signer on its own OS user.
- Two-person approval enforced *inside the signer* (two distinct WebAuthn assertions over the request hash).

**Agent on OPNsense/pfSense (FreeBSD 14):**
- Same pure-Go `freebsd/amd64` binary, rc.d script, and config writes that survive firmware upgrades. Validate the paths per appliance in that phase.

**Agent on Windows OpenSSH:**
- Same binary as a Windows service (`x/sys/windows/svc`). It writes `TrustedUserCAKeys`/`RevokedKeys` under `C:\ProgramData\ssh\` with SYSTEM+Administrators-only ACLs (sshd refuses wider ACLs). `administrators_authorized_keys` is a special case for inventory.

## Version Compatibility

| Package | Compatible With | Notes |
|---|---|---|
| `go-webauthn/webauthn@v0.18.2` | Go ≥ 1.26 | Its go.mod declares `go 1.26.0`, so our go directive must be ≥ 1.26 |
| `go-tpm-tools@v0.4.10` (if ever used) | Go ≥ 1.26 | Avoid anyway (cgo simulator) |
| Go 1.27 | macOS ≥ 13 Ventura | Go 1.27 dropped macOS 12. Building with `go 1.26` keeps a 12-compatible fallback if anyone asks. |
| Go 1.26+ | Windows 10+/Server 2016+, FreeBSD 13+/14 amd64/arm64 | 32-bit `windows/arm` removed; `freebsd/riscv64` broken. Neither is a target. |
| `golang.org/x/crypto` | ≥ v0.52.0 mandatory | Fixes GO-2026-5013..5018 and 5023 (ssh/agent panic, certificate-restriction bypass, DoS) |
| `piv-go/v2` Ed25519 | YubiKey firmware ≥ 5.7 | Older keys: use P-256 |
| `runtime/secret` | Linux amd64/arm64, `GOEXPERIMENT=runtimesecret` | Experimental. Treat as defence-in-depth only and never rely on it. |
| OpenSSH targets | `TrustedUserCAKeys`, `RevokedKeys` (KRL), `AuthorizedPrincipalsFile`, `HostCertificate` | Present in all supported OpenSSH versions incl. Win32-OpenSSH. Verify KRL behaviour on Windows OpenSSH in the agent phase. |

## Sources

- proxy.golang.org `@latest` / `@v/list` endpoints: all Go module versions above (queried 2026-10-04). HIGH
- crates.io API: russh 0.63.3, ssh-key 0.6.7 / 0.7.0-rc.11, ssh-agent-lib 0.6.0, cryptoki 0.12.1, yubikey 0.8.0, tss-esapi 7.7.0, webauthn-rs 0.5.5, totp-rs 6.0.0, rusqlite 0.40.2, axum 0.8.9, rustls 0.23.45, cargo-audit 0.22.2, cargo-deny 0.20.2, cargo-vet 0.10.2. HIGH
- go.dev/dl JSON: Go 1.27.1 current stable. HIGH
- https://go.dev/doc/go1.26 and https://go.dev/doc/go1.27: runtime/secret, PQ TLS defaults, crypto randomness changes, FIPS module, macOS 13 minimum. HIGH (official)
- https://pkg.go.dev/net/http: `CrossOriginProtection` present. HIGH
- https://pkg.go.dev/vuln/GO-2026-5023 and the related GO-2026-501x advisories (via web search): x/crypto/ssh 2026 CVEs fixed in v0.52.0. MEDIUM
- https://github.com/advisories/GHSA-hcg3-q754-cr77, https://github.com/advisories/GHSA-j5w8-q4qc-rx2x: earlier x/crypto/ssh DoS CVEs. MEDIUM
- github.com/stripe/krl (API: `archived: true`), github.com/go-authn/krl README: no KRL support in x/crypto. HIGH
- https://docs.rs/ssh-key/0.7.0-rc.11: certificate builder, sk keys and SSHSIG supported; no KRL. MEDIUM
- go-piv/piv-go source (cloned): cgo on darwin/linux/freebsd/openbsd, pure Go on Windows; `AlgorithmEd25519` present. HIGH
- github.com/go-webauthn/webauthn go.mod: Go 1.26 requirement and dependency set. HIGH
- https://github.com/transparency-dev/tessera README: drivers (AWS/GCP/POSIX, no embedded DB), best-effort antispam, witness support, Trillian successor. MEDIUM
- GitHub releases API: cosign v3.1.3, attest-build-provenance v4.2.2, syft v1.54.0, osv-scanner v2.6.0, scorecard-action v2.4.4, slsa-github-generator v2.1.0 (2025-02), OpenSSH portable V_10_5_P1, Win32-OpenSSH 10.0.0.0p2-Preview. HIGH
- go.dev/blog/rebuild ("Perfectly Reproducible, Verified Go Toolchains", Go 1.21) and go.dev/blog/tob-crypto-audit (Trail of Bits audit of Go crypto): from prior knowledge, not re-fetched this session. MEDIUM
- OpenSSH PROTOCOL.certkeys / PROTOCOL.krl semantics (no chaining; sshd ignores KRL signatures): from prior knowledge of the OpenSSH spec. MEDIUM; re-verify against the spec in the CA-core phase.

---
*Stack research for: self-hosted security-first SSH certificate authority*
*Researched: 2026-10-04*
