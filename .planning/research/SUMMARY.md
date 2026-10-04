# Project Research Summary

**Project:** ssh-cert-manager (working name)
**Domain:** Self-hosted, security-first SSH certificate authority and access manager (no proxy; stock OpenSSH verifies)
**Researched:** 2026-10-04
**Confidence:** MEDIUM-HIGH (HIGH on language, versions, OpenSSH mechanics and competitor facts; MEDIUM on key custody, audit-log design and Windows edge cases)

## Executive Summary

This is a CA engine with a real host-side lifecycle: it signs short-lived OpenSSH certificates, and a pull-only host agent keeps `TrustedUserCAKeys`, the KRL, `AuthorizedPrincipalsFile` and host certificates in sync on each host. Approvals, a tamper-evident log and inventory of plain keys sit on top. The comparison set is step-ca/Smallstep, Vault/OpenBao SSH and Teleport's agentless-OpenSSH mode. Users won't expect session recording or a web terminal. They will expect everything a CA engine does, plus automated host lifecycle and working revocation. The open niche is concrete: two-person approval, dual authorization for admin actions, an HSM-backed CA, hardware user-key enforcement and SSH key discovery are all paid features in Teleport or Vault. Here they are free.

The recommended approach: **Go**, pure-Go static binaries (`CGO_ENABLED=0`), SQLite (`modernc.org/sqlite`), and a stdlib server-rendered UI with no npm. The defining architecture is **"the server proposes, the signer disposes"**. A small, network-less `sshcm-signer` process holds the CA keys behind a `Signer` interface. It issues only when the request carries evidence it can check itself: a WebAuthn assertion over the exact request digest, approver assertions, and a quorum-approved policy version. It writes the audit entry before releasing the certificate. OpenSSH certificates **do not chain**, so the "offline root + online intermediate" idea in PROJECT.md is replaced. An offline trust-root key signs only *trust bundles* (CA key set, KRL/ops key, policy). Agents pin that root at enrollment and refuse anything unsigned.

The main risks are side-door compromises, not key theft: an agent that applies whatever the server sends (fleet takeover without the CA key), empty or wildcard principals (Vault CVE-2024-7594 class), approvals stored as DB rows, a missing or corrupt KRL that locks out every pubkey login, and a hash-chain audit log that a DB admin can rewrite. Each has a known structural answer (signed bundles, a strict signing function, evidence verified in the signer, atomic last-good KRL handling, a Merkle log with witnesses). All of them must be decided in the first phases, because none can be retrofitted cheaply.

## Key Findings

### Recommended Stack

Go wins on every criterion except theoretical memory safety. It gives one static binary per role for 4 OSes from one CI job, a security core inside the audited stdlib, symbol-level `govulncheck`, the most mature OpenSSH-cert library, and roughly 6-10 direct dependencies against 150-300 crates for Rust. (Details: STACK.md.)

**Core technologies:**
- **Go 1.27.1** (`go 1.26` directive): all binaries, `CGO_ENABLED=0`, `-trimpath`, reproducible builds
- **`golang.org/x/crypto` ≥ v0.57.0** (`ssh`, `ssh/agent`, `argon2`): cert parse/sign only, never as an SSH server. v0.52.0+ is mandatory for the 2026 CVEs
- **Own `internal/krl` encoder** (~400-600 LOC): there is no maintained Go KRL library (`stripe/krl` is archived). Fuzzed, with `ssh-keygen -Q` as the oracle
- **`modernc.org/sqlite` v1.60.1**: the only datastore, pure Go
- **`go-webauthn/webauthn` v0.18.2**: passkeys/FIDO2, with assertions bound to signing requests. No TOTP for signing (phishable)
- **`x/mod/sumdb/note` + `transparency-dev/merkle`**: C2SP signed-note checkpoints and RFC 6962 proofs for the audit log and signed bundles
- **stdlib `net/http` + `html/template` + `embed`**: server-rendered UI, strict CSP, `CrossOriginProtection`, ~300 LOC vanilla JS for the WebAuthn ceremony only
- **`filippo.io/age`**: software-key fallback and encrypted backups
- **Release:** GoReleaser, cosign keyless + maintainer SSHSIG, `attest-build-provenance`, cyclonedx-gomod SBOM, govulncheck, capslock, golangci-lint, native fuzzing, real `sshd`/`ssh-keygen` as the integration oracle

### Expected Features

**Must have (table stakes):**
- User-cert signing of client-generated keys only; short TTLs with per-role caps; `valid_after` backdated ~5 min
- `sshcm login` → cert in ssh-agent with matching lifetime (Linux, macOS, Windows named pipe)
- Host certs plus the CLI-managed `@cert-authority` line (no TOFU); separate user, host and machine CAs
- Secure-default extensions (`permit-pty` only); unique non-zero serials; structured key IDs
- KRL revocation pushed to hosts; machine/bot certs with day-scale TTLs
- Host config automation with `sshd -t`/`sshd -T` validation and rollback; join-token enrollment
- Role → principal mapping enforced via `AuthorizedPrincipalsFile`
- Mandatory WebAuthn; admin UI with CLI parity; audit log with export; overview of certs, hosts and expiry
- CA rotation without fleet outage; break-glass path; backup/restore that never reuses serials
- Windows OpenSSH: ACLs, the `Match Group administrators` block, inbox 9.5p2 limitations

**Should have (differentiators):**
- Inventory: effective `authorized_keys` via `sshd -T -C`, weak/old/unknown/duplicate classification, **rogue CA trust detection**, sshd posture report
- Two-person approval for sensitive roles **and** for admin/policy changes (one engine)
- Tamper-evident audit log with a `verify` command; issuance transparency for users
- Hardware-backed CA free and first-class; revocation convergence view ("KRL applied on 47/48 hosts")
- **Login reconciliation**: an sshd log serial that is not in the issuance log means a cert we never issued

**Defer (v1.x / v2+):**
- v1.x: key last-used correlation, break-glass alerting (login reconciliation pulls the log-watching plumbing forward), `sk-*` user-key enforcement, host key inventory, OPNsense/pfSense
- v2+: OIDC, guided `authorized_keys` migration, LDAP/SCIM, Terraform provider, FROST threshold signing
- Never: session recording, web terminal, server-side key generation, agent remote-exec, inbound agent ports, online revocation via `AuthorizedPrincipalsCommand`, policy DSL, telemetry

### Architecture Approach

There are five processes in three trust zones. `sshcm-signer` (no network, own OS user, holds the keys, sequences the log), `sshcm-server` (API, UI, SQLite; *untrusted by the signer*), `sshcm-agent` (pull-only over mTLS, closed verb set), the `sshcm` CLI, and an optional `sshcm-witness` on another machine. The rule is **authenticate payloads, not pipes**: anything that changes who can log in is signed end to end by a key the server does not hold.

**Major components:**
1. **sshcm-signer**: verifies evidence, evaluates the pure policy function, allocates serials, logs before release, signs certs, KRLs and checkpoints. CI enforces a dependency firewall (no HTTP server, DB or templates)
2. **sshcm-server**: HTTPS API, web UI, SQLite, WebAuthn relay, serves tiles, KRLs and bundles. Holds no private keys
3. **sshcm-agent**: applies root-signed bundles, the ops-signed KRL and host policy atomically with `sshd -t` and rollback; renews host certs by proof of possession; runs inventory; tails auth logs; acts as a built-in log witness
4. **sshcm CLI**: ephemeral in-memory key, WebAuthn client, ssh-agent insertion, managed known_hosts, admin and offline ceremony commands
5. **Offline root**: M-of-N FIDO/PIV keys (homelab: 1-of-2) signing bundles with SSHSIG. Also holds the separate offline break-glass CA

**Key patterns:** verifying signer; TUF-style signed-state distribution; log-before-release; pull-only atomic apply with rollback; detection by reconciliation (signer log vs HSM audit vs sshd logins vs witnesses).

### Critical Pitfalls

1. **No chains in SSH certs.** Accepting a cert as a CA key is the Teleport CVE-2025-49825 class. The online CA key *is* the trust anchor. The offline root signs only bundles. Refuse cert-type signature keys in code.
2. **Agent as a fleet-root channel.** Pin the trust root at enrollment, use a narrow typed protocol and an allowlist of paths, and never offer exec.
3. **Empty/wildcard principals.** The signing function itself rejects empty lists and `* ? ,`, whitespace and control characters. Use a builder that can't sign zero values. Test negatively against OpenSSH 9.5p2 and the latest release.
4. **Authorization outside the signing boundary** (step-ca CVEs). The signer verifies WebAuthn evidence bound to the request hash, is default-deny, and accepts each approval once.
5. **KRL fail-closed / fail-open.** Use detached SSHSIG, a parse check, atomic rename, last-good copy and version rollback protection, and re-check `sshd -T` periodically. Serials must survive DB restore.
6. **Fleet lockout and sshd config precedence.** Have a break-glass CA, reload plus self-test plus auto-rollback, a `00-` drop-in or insertion before the first `Match`, and `sshd -T -C` checks for admin and non-admin users.

## Implications for Roadmap

### Reconciled researcher disagreements

- **CA key backend priority** (STACK: TPM first; ARCHITECTURE: YubiHSM 2 / YubiKey PIV). **Resolution:** one `Signer`/keystore interface with URI selection, and the backends are tiers:
  - **Production:** YubiHSM 2 (Ed25519, forced in-device audit log enabling HSM↔log reconciliation, M-of-N wrapped backup), reached via OpenSSH `ssh-agent` + PKCS#11 so the signer stays cgo-free.
  - **Small team / homelab:** TPM 2.0 (pure Go, P-256, no backup, so plan rotation instead of restore) or YubiKey PIV (P-256 safest).
  - **Dev/evaluation only:** age-encrypted software key with loud warnings.
  - Build order: software + ssh-agent/PKCS#11 (SoftHSM2 in CI), then TPM (swtpm), then build-tagged PIV/PKCS#11. Algorithm and custody are decided together.
- **Audit log:** all agree on a Merkle log (RFC 6962) with signed C2SP checkpoints, agents and CLI as witnesses, and an optional `sshcm-witness`. **The PROJECT.md requirement "hash chain" should be updated.** FEATURES.md's "hash chain" wording is superseded. On storage, the signer is the only writer, using its own SQLite file; the server gets a read-only replica. Tessera only if the log goes public.
- **Language:** Go (unanimous).
- **Unanimous constraints:** no cert chaining; the offline root signs only bundles, KRL authority and policy; the agent pins the root; the signer rejects empty/wildcard principals; an in-house KRL encoder; separate user, host and machine CAs; client-side keys only.
- **Open tension:** CLI WebAuthn via libfido2 needs cgo. Default to a browser loopback flow (PKCE + state, pubkey fingerprint shown on both sides), with webauthn.dll on Windows. No device-code flow.

### Phase structure (coarse: 9 → 6)

| New | ARCHITECTURE phases | Why |
|-----|-----|-----|
| 1 | 1+2 | Pre-user foundations |
| 2 | 3 | MVP checkpoint |
| 3 | 4 | Largest dependency |
| 4 | 5+6 | Approvals need the UI step-up inbox |
| 5 | 7+8 | Inventory and log watching are per-platform |
| 6 | 9 | Release |

### Phase 1: Foundations, Signer and Trust Core
**Rationale:** Every feature writes through the signer and the log; the bundle format must exist before agents pin a root.
**Delivers:** reproducible CI; `wire` encoding with vectors; strict cert builder; KRL encoder; e2e harness with several OpenSSH versions including 9.5; `sshcm-signer` over UDS; keystore (software, ssh-agent/PKCS#11, TPM); restore-safe serials; Merkle log + `sshcm audit verify`; trust-bundle format; offline root ceremony; genesis policy with `admin_quorum`/evidence fields.
**Avoids:** Pitfalls 1, 3, 9, 10, 12; serial reuse.

### Phase 2: Identity and Login Vertical Slice (MVP)
**Delivers:** server + SQLite; accounts with mandatory WebAuthn (hostname + TLS required, IP-origin guard); policy v1 with role principals, quorum = 1; `sshcm login` → ssh-agent; manual host config; minimal registration pages.
**Avoids:** Pitfalls 13, 14, 4.

### Phase 3: Linux Host Agent and Revocation
**Delivers:** join tokens with SPKI and root pins plus admin-approved names; mTLS; bundle apply; principals files from ops-signed host policy; KRL sync (SSHSIG, atomic, last-good, rollback protection); host certs by PoP; client `@cert-authority`/`RevokedHostKeys`; machine certs; heartbeats; convergence-gated rotation; break-glass CA; reload + self-test + rollback. Dogfood on the laptop, zima and Proxmox.
**Avoids:** Pitfalls 2, 5, 6, 7, 8, 15.

### Phase 4: Insider Resistance and Web UI
**Delivers:** quorum-signed policy changes (including credential binding/reset); digest-bound single-use JIT approvals with `valid_before ≤ approval expiry`; revoke-by-one, unrevoke-by-quorum; timelock; notifications; witness cosignatures; UI overview, approvals with step-up, issue/revoke, audit browser with proofs, convergence view.
**Avoids:** Pitfalls 10, 11.

### Phase 5: Visibility and Cross-Platform Agents
**Delivers:** safe inventory scanners (O_NOFOLLOW, metadata only, rogue CA, posture); ranked findings; login reconciliation (`sshd`/`sshd-session`/`sshd-auth`/Windows Operational); HSM-audit reconciliation; Windows agent (ACLs, insertion before `Match`, admin key file, lowercase names); macOS and FreeBSD agents. OPNsense/pfSense behind a spike, may slip to v1.x.
**Avoids:** Pitfalls 12, 16, 7, 5.

### Phase 6: Hardening and Release
**Delivers:** fuzzing, backup/restore ceremonies, rotation and break-glass drills per platform, threat model, reproducible signed releases with SBOM and provenance, signed agent updates, external review, the PITFALLS "looks done but isn't" checklist.

### Phase Ordering Rationale
- Signer, log and bundle format first: the alternative is re-enrolling the fleet or rewriting the issuance path.
- The MVP login slice before the agent, to validate WebAuthn UX early.
- The agent before approvals: rotation needs heartbeats.
- Platforms late, grouped with inventory, reusing the Linux machinery.
- Break-glass in Phase 3: a dogfooding lockout is the most likely early incident.

### Research Flags
Need research: **Phase 1** (Ed25519 via PKCS#11/agent, YubiHSM audit, TPM, sandboxing, KRL), **Phase 2** (CLI WebAuthn transport, Windows CTAP), **Phase 5** (Windows ACLs and principals, appliances, log formats).
Standard patterns: **Phase 3** (light check of Include variance and RevokedKeys reload via integration test), **Phase 4**, **Phase 6**.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Registry-verified versions; capabilities checked in source |
| Features | MEDIUM-HIGH | Paywall facts HIGH; Smallstep and Windows edges MEDIUM |
| Architecture | MEDIUM | OpenSSH behaviour source-verified; the design is synthesis |
| Pitfalls | MEDIUM | CVEs and release notes primary; appliance and macOS items LOW |

**Overall confidence:** MEDIUM-HIGH

### Gaps to Address
- **PROJECT.md updates:** hash chain → Merkle log + checkpoints + witnesses; replace the "offline root + online intermediate" candidate with an offline trust root signing bundles plus hardware online CAs; record Go.
- Whether `RevokedKeys` is re-read without reload (Phase 3 test).
- YubiHSM audit semantics; TPM Ed25519 (assume P-256).
- Windows: principal case, domain/Entra accounts, `verify-required` (#2156), KRL on 9.5p2.
- OPNsense/pfSense (LOW; may miss v1).
- CLI WebAuthn transport.
- Timelock and labelling for single-admin setups.
- HSM throughput under login storms.

## Sources

### Primary (HIGH confidence)
- proxy.golang.org, crates.io, npm, go.dev/dl, GitHub releases (2026-10-04)
- OpenSSH `sshd_config(5)`, `ssh-keygen(1)`, `PROTOCOL.krl`, release notes 8.2-10.5, openssh-portable source, draft-miller-ssh-cert-06
- Teleport feature matrix and CA rotation docs; Vault Control Groups; Microsoft Learn OpenSSH for Windows
- Local check: Daniel-PC `OpenSSH_for_Windows_9.5p2`

### Secondary (MEDIUM confidence)
- Teleport CVE-2025-49825, Vault CVE-2024-7594, step-ca CVE-2025-44005/2026-30836/2025-66406, x/crypto GO-2026-50xx
- C2SP tlog-witness/checkpoint, Tessera, YubiHSM 2 docs, step-ca SSHPOP, kubeadm pinning, Win32-OpenSSH issues

### Tertiary (LOW confidence)
- OPNsense/pfSense regeneration, macOS launchd, Dropbear certs, HSM throughput, Windows CTAP for non-admins

---
*Research completed: 2026-10-04*
*Ready for roadmap: yes*
