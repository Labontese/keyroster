# Roadmap: ssh-cert-manager

## Overview

Six coarse phases take ssh-cert-manager from an empty repository to a security-reviewed public release. The trust core comes first, because every later feature writes through it and none of it can be retrofitted cheaply: the network-less signer, hardware-backed CA keys, the offline trust root and the Merkle audit log, all verified against real `sshd`, in a repository run with GitHub best practice from the first commit. Phase 2 is the MVP checkpoint: a passkey login yields a short-lived certificate in ssh-agent and a real SSH session. Phase 3 hands the Linux fleet to the host agent (trusted CAs, principals, KRL revocation, host certificates, rotation and break-glass). Phase 4 makes the system insider-resistant (quorum-signed policy, two-person JIT approvals, a witnessed log) and operable from the web UI. Phase 5 completes the visibility promise with inventory of plain keys, login reconciliation and a single who-has-access overview, and brings the agent to Windows, macOS and the BSDs. Phase 6 hardens and ships: reproducible signed releases, signed agent updates, backup/restore, documentation and an external security review.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Trust Core** - Network-less signer with hardware-backed CA keys, offline trust root and Merkle audit log, verified against real sshd, in a repo run with GitHub best practice from the first commit
- [ ] **Phase 2: Passkey Login MVP** - Passkey sign-in and `sshcm login` put a short-lived certificate in ssh-agent and give the first real SSH login
- [ ] **Phase 3: Linux Agent and Revocation** - Enrolled Linux hosts stay in sync automatically: trusted CAs, principals, KRL, host certificates, rotation and break-glass
- [ ] **Phase 4: Insider Resistance and Web UI** - Quorum-signed policy, two-person JIT access and a witnessed audit log, all operable from the web UI
- [ ] **Phase 5: Visibility and Cross-Platform Agents** - Key inventory, login reconciliation and one who-has-access overview, with agents on Windows, macOS and BSD
- [ ] **Phase 6: Hardening and Release** - Reproducible signed releases, signed agent updates, backup/restore, documentation and an external security review

## Phase Details

### Phase 1: Trust Core
**Goal**: An admin can stand up a hardware-backed, auditable CA whose certificates stock OpenSSH accepts and whose signing rules cannot be bypassed, before any user or host exists.
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: REPO-01, REPO-02, REPO-03, REPO-04, CA-01, CA-02, CA-03, CA-04, CA-05, CA-06, CA-07, CA-08, KEY-01, KEY-03, KEY-04, KEY-05, KEY-07, VIS-01, VIS-03
**Success Criteria** (what must be TRUE):
  1. Every change reaches `main` only through a PR with signed commits, a review and green CI (build, test, lint, govulncheck, fuzzing, e2e against real sshd) running SHA-pinned, least-privilege actions; CodeQL, Dependabot (gomod + actions), secret scanning with push protection and OpenSSF Scorecard are active; SECURITY.md with private vulnerability reporting, README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS and issue/PR templates are published.
  2. Admin can run the offline trust-root ceremony with M-of-N hardware keys (1-of-2 in the homelab) and get a root that signs trust bundles, KRL authority and policy (starting with a genesis policy), and that the tooling refuses to use for signing certificates.
  3. Admin can initialise separate user, host and machine CAs whose keys live in a PKCS#11 HSM reached via ssh-agent (SoftHSM2 in CI, YubiHSM 2 on real hardware), a TPM 2.0 or a YubiKey PIV slot, and are only ever used by the network-less `sshcm-signer` process.
  4. A certificate issued through the signer is accepted by real `sshd` on OpenSSH 9.5p2 and on the latest release in CI. It carries a unique non-zero serial that is never reissued, even after the signer's state is restored from an older copy, plus a structured key ID and `permit-pty`-only extensions. The signer refuses empty, wildcard or malformed principals, certificate-type CA keys, and anything other than a client-supplied public key.
  5. Every issuance is in the Merkle audit log before the certificate is released; `sshcm audit verify` checks the log end to end, fails on any tampered or removed entry, and can export it.
**Plans**: TBD
**UI hint**: no
**Research**: HIGH. Ed25519 via PKCS#11/ssh-agent (OpenSSH 10.1/10.2 caveats), YubiHSM 2 forced-audit semantics, TPM key algorithm (assume P-256), signer sandboxing (own OS user, systemd hardening), restore-safe serial allocation. Decide CA key algorithm and custody together.

### Phase 2: Passkey Login MVP
**Goal**: A user signs in with a passkey and, with one command, gets a short-lived certificate in ssh-agent that lets them SSH into a host as exactly the principals their role grants: the first end-to-end login.
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: AUTH-01, AUTH-02, AUTH-03, AUTH-04, KEY-02, KEY-06, AUTHZ-01, UI-01, PLAT-05
**Success Criteria** (what must be TRUE):
  1. Admin creates a local account that stays unusable until the user registers at least one passkey/FIDO2 key; the user then signs in to the web UI with that key.
  2. User runs `sshcm login` on Linux, macOS or Windows, sees the same public-key fingerprint in the CLI and in the browser, approves, and gets a certificate (hours, capped by role) in ssh-agent that leaves the agent when the certificate expires.
  3. Admin defines roles mapping users and groups to principals on host groups; the user's certificate carries exactly those principals and logs them in to a manually configured host running stock OpenSSH.
  4. The signer refuses to sign, whatever the server sends, when the WebAuthn assertion is missing, replayed or bound to a different request digest, or when the policy version is not root/quorum-signed.
  5. Server and signer run on Linux and serve a server-rendered web UI embedded in the binary, with a strict CSP and no npm dependencies; when the CA runs on an encrypted software key, every CLI command and every UI page shows a loud evaluation-only warning.
**Plans**: TBD
**UI hint**: yes
**Research**: MEDIUM-HIGH. CLI WebAuthn transport (default: browser loopback with PKCE + state; libfido2 needs cgo), Windows webauthn.dll/CTAP for non-admin users, Windows ssh-agent named pipe, WebAuthn origin rules (hostname + TLS, IP-origin guard).

### Phase 3: Linux Agent and Revocation
**Goal**: Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout.
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: AGENT-01, AGENT-02, AGENT-03, AGENT-04, AGENT-05, AGENT-06, AGENT-07, AUTHZ-02, REVOKE-01, REVOKE-02, REVOKE-03, REVOKE-04, AUTH-06, KEY-08, BREAK-01, PLAT-01
**Success Criteria** (what must be TRUE):
  1. Admin enrolls a Linux host (Debian/Ubuntu, RHEL family, Alpine, Arch, Proxmox) with a one-time join token. The agent pins the server key and trust root, talks pull-only over mTLS with a closed set of typed operations (no inbound port, no remote exec), and applies only CA sets, host policy and KRLs signed by the pinned root or its delegated keys; unsigned or older versions are rejected.
  2. The agent writes sshd config, `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` (generated from signed host policy) and the KRL atomically, validates with `sshd -t`, reloads, self-tests and rolls back on failure. It reports drift found by periodic `sshd -T -C` checks (e.g. missing `RevokedKeys`) and sends heartbeats with hashes of the applied config, CA set and KRL version.
  3. Admin revokes a certificate (by serial or key ID) or a key from the CLI, and every enrolled host refuses it after its next pull. The KRL (own encoder, cross-checked with `ssh-keygen -Q`) is SSHSIG-signed and installed atomically with a last-good copy, older versions are refused, and a corrupt or missing KRL never locks out the fleet.
  4. Users connect to enrolled hosts without a TOFU prompt: agents obtain and renew host certificates by proof of possession of the host key, and `sshcm` manages the `@cert-authority` known_hosts line and the revoked host keys list. Machine/automation identities obtain day-scale certificates within role caps.
  5. Admin rotates a CA key with no failed logins (old and new trusted in parallel until heartbeats show every host converged), and with the server down an offline break-glass CA still grants login to the dedicated emergency account and to nothing else.
**Plans**: TBD
**UI hint**: no
**Research**: MEDIUM. KRL format and fuzzing for the in-house encoder (no maintained Go library), sshd `Include`/drop-in variance across distros, whether `RevokedKeys` is re-read without reload (settle with an integration test). Dogfood on the laptop, zima and Proxmox.

### Phase 4: Insider Resistance and Web UI
**Goal**: No single admin can grant access unobserved: policy and credential changes need a quorum, sensitive access needs a second person, and the audit log is witnessed. All of it can be operated from the web UI.
**Mode:** mvp
**Depends on**: Phase 3
**Requirements**: AUTH-05, AUTHZ-03, AUTHZ-04, AUTHZ-05, AUTHZ-06, AUTHZ-07, VIS-02, VIS-06, UI-02, UI-03, UI-04
**Success Criteria** (what must be TRUE):
  1. A change to roles, principals, credentials (including binding or resetting a user's passkey) or quorum settings takes effect only after the configured admin quorum approves it; every policy version is numbered and signed, and the signer refuses to act under a version that lacks quorum.
  2. A user requests just-in-time access to a sensitive role and another person approves it in the UI with WebAuthn step-up; the approval is bound to that exact request, works once, and the resulting certificate expires no later than the approval.
  3. Any single admin can revoke immediately, while un-revoking requires quorum; a single-admin instance is clearly labelled as such, and its sensitive changes wait out a timelock with notification.
  4. Agents and the CLI verify signed checkpoints with consistency proofs and raise an alert if the log ever shrinks or forks (e.g. a DB admin rewriting history); the UI audit browser shows each entry with its inclusion proof.
  5. Admin can issue, revoke and manage roles and policy from the UI with CLI parity, and sees convergence for the current KRL, CA set and policy (e.g. "KRL applied on 47/48 hosts").
**Plans**: TBD
**UI hint**: yes
**Research**: Standard patterns. Formalise the policy/quorum model and write threat-model tests (malicious admin, compromised server) before building.

### Phase 5: Visibility and Cross-Platform Agents
**Goal**: The admin sees in one place who has access to what right now, covering certificates and the plain keys that live outside the CA, with alerts for access we never granted, across Linux, Windows, macOS and BSD hosts.
**Mode:** mvp
**Depends on**: Phase 3, Phase 4
**Requirements**: INV-01, INV-02, INV-03, INV-04, VIS-04, VIS-05, BREAK-02, PLAT-02, PLAT-03, PLAT-04
**Success Criteria** (what must be TRUE):
  1. Each enrolled host reports the effective `authorized_keys` per account (resolved via `sshd -T -C`, including Windows `administrators_authorized_keys`), read-only, metadata only and symlink-safe, and the keys are classified as weak, old, unknown or duplicated across hosts.
  2. Admin sees rogue CA trust flagged (`cert-authority` lines in authorized_keys, unknown keys in `TrustedUserCAKeys`, unexpected `AuthorizedKeysCommand`) and each host's sshd posture (password auth, root login, weak algorithms).
  3. A login with a certificate serial that is not in the issuance log raises an alert, and every break-glass login is recorded in the audit log and visible in reconciliation.
  4. One overview shows all certificates, keys, hosts, principals and expiry: who has access to what, now.
  5. The agent's sync and inventory work on Windows OpenSSH 9.5p2+ (correct ACLs, config inserted before `Match Group administrators`, lowercase principals, admin key file; dogfooded on Daniel-PC), on macOS, and on FreeBSD, OpenBSD and NetBSD.
**Plans**: TBD
**UI hint**: yes
**Research**: HIGH. Windows ACL semantics, principal case and domain/Entra accounts, `verify-required`, KRL behaviour on 9.5p2, login log formats (`sshd`/`sshd-session`/`sshd-auth`/Windows OpenSSH Operational log), macOS launchd and paths, BSD paths.

### Phase 6: Hardening and Release
**Goal**: Anyone can verify and safely run a release (reproducible, signed, documented, externally reviewed), and an admin can recover from disaster without breaking serial or audit guarantees.
**Mode:** mvp
**Depends on**: Phase 5
**Requirements**: REPO-05, REPO-06, REPO-07, OPS-01, OPS-02, OPS-03
**Success Criteria** (what must be TRUE):
  1. Anyone can rebuild a tagged release from source and get byte-identical static (`CGO_ENABLED=0`) binaries for every target platform.
  2. Releases are published on GitHub Releases with cosign signatures, an SBOM and SLSA provenance, versioned by semver from Conventional Commits; agents self-update only to releases signed by the project release key and refuse anything else.
  3. Admin can back up and restore server state (encrypted); after a restore no serial is reissued and the audit log is intact and still verifies.
  4. A new admin can install from the install guide and follow published runbooks for CA rotation, break-glass and restore, backed by a documented threat model.
  5. An external security review is completed and its findings are resolved or documented before the first public release.
**Plans**: TBD
**UI hint**: no
**Research**: Standard patterns (GoReleaser, cosign, SLSA provenance, cyclonedx-gomod). Also run the PITFALLS "looks done but isn't" checklist and per-platform rotation and break-glass drills.

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Trust Core | 0/TBD | Not started | - |
| 2. Passkey Login MVP | 0/TBD | Not started | - |
| 3. Linux Agent and Revocation | 0/TBD | Not started | - |
| 4. Insider Resistance and Web UI | 0/TBD | Not started | - |
| 5. Visibility and Cross-Platform Agents | 0/TBD | Not started | - |
| 6. Hardening and Release | 0/TBD | Not started | - |
