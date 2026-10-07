# Requirements: ssh-cert-manager

**Defined:** 2026-10-04
**Core Value:** Full visibility — at any moment you know exactly who has access to what, and can revoke it immediately.

## v1 Requirements

Requirements for the first public release. Each maps to roadmap phases.

### Certificate Authority (CA)

- [x] **CA-01**: Admin can initialise separate user, host and machine CAs, each with its own key
- [x] **CA-02**: Signer refuses to sign a certificate with empty principals or principals containing wildcards, commas, whitespace or control characters
- [x] **CA-03**: Every certificate gets a unique, non-zero, monotonically increasing serial that is never reused, including after restore from backup
- [x] **CA-04**: Every certificate gets a structured key ID identifying user/host, request and policy version
- [x] **CA-05**: User certificates default to secure extensions (`permit-pty` only); other extensions are granted only by role
- [x] **CA-06**: Signer only signs client-generated public keys; the server never generates or sees user private keys
- [x] **CA-07**: Signer refuses certificate-type keys as CA keys (no chaining)
- [ ] **CA-08**: Certificates are verified as accepted/rejected by real `sshd` on OpenSSH 9.5p2 (Windows inbox) and the latest OpenSSH release in automated tests

### Key Custody (KEY)

- [x] **KEY-01**: CA keys live in a separate, network-less signer process behind a `Signer` interface
- [ ] **KEY-02**: Signer only issues when the request carries evidence it verifies itself (WebAuthn assertion over the request digest, required approvals, quorum-signed policy version)
- [x] **KEY-03**: Admin can store CA keys in a PKCS#11 HSM (e.g. YubiHSM 2) via ssh-agent
- [x] **KEY-04**: Admin can store CA keys in a TPM 2.0
- [x] **KEY-05**: Admin can store CA keys in a YubiKey PIV slot
- [ ] **KEY-06**: Admin can use an encrypted software CA key for evaluation, with a loud warning in CLI and UI
- [ ] **KEY-07**: Admin can perform an offline trust-root ceremony (M-of-N hardware keys) producing a root that signs only trust bundles, KRL authority and policy
- [ ] **KEY-08**: Admin can rotate a CA key without fleet outage (old and new trusted in parallel until all hosts converge)

### Identity & Login (AUTH)

- [ ] **AUTH-01**: Admin can create local user accounts; every account must register at least one WebAuthn/passkey credential
- [ ] **AUTH-02**: User can log in to the web UI with a passkey/FIDO2 key
- [ ] **AUTH-03**: User can run `sshcm login` and get a short-lived certificate (hours, capped per role) loaded into their ssh-agent with matching lifetime, on Linux, macOS and Windows
- [ ] **AUTH-04**: Login flow shows the public-key fingerprint on both CLI and browser so the user can confirm the request (phishing resistance)
- [ ] **AUTH-05**: Binding or resetting a user's credential requires admin quorum
- [ ] **AUTH-06**: Machine/automation identities can obtain longer-lived (day-scale) certificates within role caps

### Authorization & Insider Resistance (AUTHZ)

- [ ] **AUTHZ-01**: Admin can define roles mapping users/groups to principals on host groups
- [ ] **AUTHZ-02**: Hosts enforce role → principal mapping via `AuthorizedPrincipalsFile` generated from signed host policy
- [ ] **AUTHZ-03**: Policy changes (roles, principals, credentials, quorum settings) require approval by a configured admin quorum, are versioned and signed
- [ ] **AUTHZ-04**: User can request just-in-time access to a sensitive role; another person must approve it, bound to that exact request, single-use and time-boxed
- [ ] **AUTHZ-05**: A JIT certificate never outlives its approval
- [ ] **AUTHZ-06**: Any single admin can revoke; un-revoking requires quorum
- [ ] **AUTHZ-07**: In single-admin mode, sensitive changes are delayed by a timelock with notification, and the instance is clearly labelled as single-admin

### Host Agent (AGENT)

- [ ] **AGENT-01**: Admin can enroll a host with a one-time join token; the agent pins the server key and trust root at enrollment
- [ ] **AGENT-02**: Agent communicates pull-only over mTLS with a closed set of typed operations — no remote exec, no inbound ports
- [ ] **AGENT-03**: Agent only applies CA sets, policy and KRLs signed by the pinned trust root / delegated keys; unsigned or older versions are rejected
- [ ] **AGENT-04**: Agent writes sshd config, trusted CA keys, principals files and KRL atomically, validates with `sshd -t`, reloads, self-tests and rolls back on failure
- [ ] **AGENT-05**: Agent verifies effective sshd config (`sshd -T -C`) periodically and reports drift (e.g. missing `RevokedKeys`)
- [ ] **AGENT-06**: Agent obtains and renews host certificates by proof of possession of the host key
- [ ] **AGENT-07**: Agent sends heartbeats with hashes of applied config, CA set and KRL version

### Revocation (REVOKE)

- [ ] **REVOKE-01**: Admin can revoke a certificate (by serial/key ID) or a key, from CLI or UI
- [ ] **REVOKE-02**: Revocation is distributed as a KRL (own encoder, verified against `ssh-keygen -Q`) to all hosts automatically
- [ ] **REVOKE-03**: KRLs are signed (detached SSHSIG), installed atomically, last-good copy kept, rollback to older versions refused — a broken KRL never locks out the fleet
- [ ] **REVOKE-04**: Clients trust hosts via a CLI-managed `@cert-authority` known_hosts entry and revoked host keys list (no TOFU)

### Emergency Access (BREAK)

- [ ] **BREAK-01**: An offline break-glass CA, distributed by the agent, can grant login to a dedicated emergency account only
- [ ] **BREAK-02**: Use of break-glass access is recorded and visible in the audit log / reconciliation

### Audit & Visibility (VIS)

- [x] **VIS-01**: Every issuance, revocation, approval and admin action is written to a Merkle audit log before the certificate/action is released
- [ ] **VIS-02**: Log checkpoints are signed; agents and CLI verify the log only grows (consistency proofs)
- [x] **VIS-03**: User/admin can run `sshcm audit verify` to verify the log end to end, and export it
- [ ] **VIS-04**: Overview shows all certificates, keys, hosts, principals and expiry — who has access to what, now
- [ ] **VIS-05**: Login reconciliation: agents report sshd login events (serial + CA); any login with a serial not in the issuance log raises an alert
- [ ] **VIS-06**: Convergence view shows which hosts have applied the current KRL, CA set and policy (e.g. 47/48)

### Inventory (INV)

- [ ] **INV-01**: Agent discovers effective `authorized_keys` files per account (via `sshd -T -C`, incl. Windows `administrators_authorized_keys`) and reports keys — metadata only, read-only, symlink-safe
- [ ] **INV-02**: Inventory classifies keys as weak (algorithm/size), old, unknown or duplicated across hosts
- [ ] **INV-03**: Inventory detects rogue CA trust: `cert-authority` lines in authorized_keys, unknown keys in `TrustedUserCAKeys`, unexpected `AuthorizedKeysCommand`
- [ ] **INV-04**: Inventory reports sshd posture (e.g. password auth enabled, root login, weak algorithms)

### Web UI (UI)

- [ ] **UI-01**: Server-rendered web UI with strict CSP, embedded in the binary, no npm dependencies
- [ ] **UI-02**: Admin can issue, revoke and manage roles/policy from the UI with CLI parity
- [ ] **UI-03**: Approver can see pending approvals and approve with WebAuthn step-up
- [ ] **UI-04**: Audit browser shows entries with inclusion proofs

### Platforms (PLAT)

- [ ] **PLAT-01**: Generic Unix agent works on any system with stock OpenSSH — major Linux distributions (Debian/Ubuntu, RHEL family, Alpine, Arch, Proxmox)
- [ ] **PLAT-02**: Agent works on FreeBSD, OpenBSD and NetBSD
- [ ] **PLAT-03**: Agent works on macOS
- [ ] **PLAT-04**: Agent works on Windows OpenSSH (9.5p2+): correct ACLs, config inserted before `Match Group administrators`, lowercase principals, admin key file
- [ ] **PLAT-05**: Server and signer run on Linux; CLI runs on Linux, macOS and Windows

### Supply Chain & Repository (REPO)

- [ ] **REPO-01**: Protected `main` via rulesets: PR only, required checks, required review, signed commits, linear history, no force-push
- [x] **REPO-02**: GitHub Actions CI: build, test, lint, govulncheck, fuzzing, e2e against real sshd; actions pinned by SHA with least-privilege permissions
- [ ] **REPO-03**: CodeQL, Dependabot (gomod + actions), secret scanning with push protection, OpenSSF Scorecard
- [x] **REPO-04**: SECURITY.md with private vulnerability reporting; README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS, issue/PR templates
- [ ] **REPO-05**: Reproducible, static builds (`CGO_ENABLED=0`) for all target platforms
- [ ] **REPO-06**: Releases via GitHub Releases with cosign signatures, SBOM and SLSA provenance; Conventional Commits + semver
- [ ] **REPO-07**: Agent self-updates only to releases signed by the project's release key

### Operations (OPS)

- [ ] **OPS-01**: Admin can back up and restore server state (encrypted) without serial reuse or audit log loss
- [ ] **OPS-02**: Documented threat model, install guide and runbooks (rotation, break-glass, restore)
- [ ] **OPS-03**: External security review completed before public release

## v2 Requirements

Deferred. Tracked but not in current roadmap.

### Identity

- **AUTH2-01**: OIDC/SSO login (WebAuthn still required for signing)
- **AUTH2-02**: LDAP/SCIM user provisioning

### Visibility

- **VIS2-01**: Last-used time per plain key via log correlation
- **VIS2-02**: Break-glass use alerting (push/email)
- **VIS2-03**: Separate `sshcm-witness` on another machine cosigning checkpoints
- **VIS2-04**: Host key inventory

### Platforms

- **PLAT2-01**: OPNsense/pfSense support via plugin (they regenerate sshd_config)
- **PLAT2-02**: Agentless mode (generated config for Ansible/manual deploy, network gear, Dropbear)

### Other

- **MIG2-01**: Guided migration from authorized_keys to certificates
- **HA2-01**: Threshold signing (FROST) for CA keys
- **TF2-01**: Terraform provider

## Out of Scope

| Feature | Reason |
|---------|--------|
| Session recording / web terminal | Requires a proxy in the data path; conflicts with simplicity and attack surface |
| Access proxy | Stock OpenSSH verifies certs; no traffic through our components |
| Server-side key generation | Private keys must never leave the client |
| Agent remote exec / inbound agent ports | Would turn the agent into a fleet-root channel |
| Hardware user-key enforcement (sk-*) | Decided not needed: WebAuthn at login + short-lived in-memory keys suffice |
| Online revocation via AuthorizedPrincipalsCommand | Makes the CA a login dependency; KRL is the revocation model |
| Policy DSL | Complexity and attack surface; structured policy instead |
| Telemetry | Self-hosted, privacy |
| SaaS offering | CA key must never leave customer environment |
| TOTP for signing | Phishable; WebAuthn only |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| CA-01 | Phase 1 | Complete |
| CA-02 | Phase 1 | Complete |
| CA-03 | Phase 1 | Complete |
| CA-04 | Phase 1 | Complete |
| CA-05 | Phase 1 | Complete |
| CA-06 | Phase 1 | Complete |
| CA-07 | Phase 1 | Complete |
| CA-08 | Phase 1 | Pending |
| KEY-01 | Phase 1 | Complete |
| KEY-02 | Phase 2 | Pending |
| KEY-03 | Phase 1 | Complete |
| KEY-04 | Phase 1 | Complete |
| KEY-05 | Phase 1 | Complete |
| KEY-06 | Phase 2 | Pending |
| KEY-07 | Phase 1 | Pending |
| KEY-08 | Phase 3 | Pending |
| AUTH-01 | Phase 2 | Pending |
| AUTH-02 | Phase 2 | Pending |
| AUTH-03 | Phase 2 | Pending |
| AUTH-04 | Phase 2 | Pending |
| AUTH-05 | Phase 4 | Pending |
| AUTH-06 | Phase 3 | Pending |
| AUTHZ-01 | Phase 2 | Pending |
| AUTHZ-02 | Phase 3 | Pending |
| AUTHZ-03 | Phase 4 | Pending |
| AUTHZ-04 | Phase 4 | Pending |
| AUTHZ-05 | Phase 4 | Pending |
| AUTHZ-06 | Phase 4 | Pending |
| AUTHZ-07 | Phase 4 | Pending |
| AGENT-01 | Phase 3 | Pending |
| AGENT-02 | Phase 3 | Pending |
| AGENT-03 | Phase 3 | Pending |
| AGENT-04 | Phase 3 | Pending |
| AGENT-05 | Phase 3 | Pending |
| AGENT-06 | Phase 3 | Pending |
| AGENT-07 | Phase 3 | Pending |
| REVOKE-01 | Phase 3 | Pending |
| REVOKE-02 | Phase 3 | Pending |
| REVOKE-03 | Phase 3 | Pending |
| REVOKE-04 | Phase 3 | Pending |
| BREAK-01 | Phase 3 | Pending |
| BREAK-02 | Phase 5 | Pending |
| VIS-01 | Phase 1 | Complete |
| VIS-02 | Phase 4 | Pending |
| VIS-03 | Phase 1 | Complete |
| VIS-04 | Phase 5 | Pending |
| VIS-05 | Phase 5 | Pending |
| VIS-06 | Phase 4 | Pending |
| INV-01 | Phase 5 | Pending |
| INV-02 | Phase 5 | Pending |
| INV-03 | Phase 5 | Pending |
| INV-04 | Phase 5 | Pending |
| UI-01 | Phase 2 | Pending |
| UI-02 | Phase 4 | Pending |
| UI-03 | Phase 4 | Pending |
| UI-04 | Phase 4 | Pending |
| PLAT-01 | Phase 3 | Pending |
| PLAT-02 | Phase 5 | Pending |
| PLAT-03 | Phase 5 | Pending |
| PLAT-04 | Phase 5 | Pending |
| PLAT-05 | Phase 2 | Pending |
| REPO-01 | Phase 1 | Pending |
| REPO-02 | Phase 1 | Complete |
| REPO-03 | Phase 1 | Pending |
| REPO-04 | Phase 1 | Complete |
| REPO-05 | Phase 6 | Pending |
| REPO-06 | Phase 6 | Pending |
| REPO-07 | Phase 6 | Pending |
| OPS-01 | Phase 6 | Pending |
| OPS-02 | Phase 6 | Pending |
| OPS-03 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 71 total
- Mapped to phases: 71
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-04*
*Last updated: 2026-10-04 after roadmap creation (traceability mapped)*
