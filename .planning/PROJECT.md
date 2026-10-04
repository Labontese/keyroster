# ssh-cert-manager (working name)

## What This Is

A stable, security-first, self-hosted SSH certificate authority and access manager for teams. It makes it easy to issue, track, renew and revoke SSH certificates — and to discover and report on the plain SSH keys that are still lying around — while steering teams from scattered `authorized_keys` toward short-lived certificates. Fully open source, with no security features locked behind an enterprise tier.

## Core Value

**Full visibility:** at any moment you know exactly who has access to what — and can revoke it immediately.

Certificates make access traceable and time-bounded, inventory surfaces access that lives outside the CA, and the tamper-evident audit log plus two-person approval ensure nobody can hide what they granted. When tradeoffs arise, the feature that preserves an accurate, complete picture of access wins.

## Requirements

### Validated

(None yet — ship to validate)

### Active

**Certificate authority**
- [ ] Issue short-lived user certificates (hours) on login, delivered into the user's ssh-agent
- [ ] Issue longer-lived certificates for machines/automation, with KRL revocation as the emergency brake
- [ ] Host certificates (host CA) so clients trust hosts without TOFU / known_hosts sprawl
- [ ] Revocation via KRL, distributed to hosts automatically and quickly
- [ ] CA private key protection that holds even if the CA server is compromised: network-less signer process that only signs with verifiable evidence (WebAuthn assertion over the request digest, approvals, quorum-signed policy); CA keys in hardware (YubiHSM 2 / TPM / YubiKey PIV; software key for dev only); offline trust root that signs only trust bundles/KRL authority/policy — never certificates (OpenSSH certs do not chain)

**Authorization**
- [ ] Roles and principals: map users/groups to which accounts they may log in as on which hosts
- [ ] Two-person approval / just-in-time access for sensitive principals, time-boxed
- [ ] No single admin can grant themselves access unobserved

**Identity**
- [ ] Local user accounts with mandatory MFA
- [ ] WebAuthn / passkey (FIDO2) authentication

**Visibility**
- [ ] Tamper-evident audit log (Merkle log with signed checkpoints, verified by agents/CLI/witness — a plain hash chain is rewritable by a DB admin) of every issuance, revocation and admin action
- [ ] Login reconciliation: sshd login records (serial + CA) checked against the issuance log to detect certificates never issued by us
- [ ] Overview of all certificates, keys, hosts, principals and expiry
- [ ] Inventory: host agent discovers existing `authorized_keys` and SSH keys per account/host and reports old, weak or unknown keys

**Components**
- [ ] Server/daemon: central CA service
- [ ] CLI: e.g. `login` → short-lived cert in ssh-agent; admin operations
- [ ] Web UI: overview, issue/revoke, approvals
- [ ] Host agent: keeps TrustedUserCAKeys, KRL, host certs and sshd config in sync; runs inventory
- [ ] Agent platforms: Linux, Windows OpenSSH, macOS, BSD / network appliances (FreeBSD, OPNsense/pfSense)

**Supply chain & release**
- [ ] Signed releases, reproducible builds, SBOM, minimal dependencies
- [ ] Public, documented, security-reviewed release

**GitHub best practice (repo & process)**
- [ ] Protected `main` (rulesets): PRs only, required status checks, required review, signed commits, linear history, no force-push
- [ ] GitHub Actions CI: build, test, lint, govulncheck, fuzzing, e2e against real sshd; actions pinned by SHA, least-privilege `permissions:`
- [ ] Security hygiene: SECURITY.md + private vulnerability reporting, CodeQL, Dependabot (gomod + actions), secret scanning + push protection, OpenSSF Scorecard
- [ ] Community files: README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS, issue/PR templates
- [ ] Conventional Commits + semver; releases via GitHub Releases with signed artifacts, SBOM and provenance attestations

### Out of Scope

- OIDC / SSO login — deferred to v2; v1 stays self-contained (local accounts + WebAuthn) to minimize attack surface; WebAuthn should remain required for signing even once OIDC lands
- Guided migration and long-term management of plain SSH keys — v1 only discovers and reports; migration tooling comes later
- SaaS / hosted offering — self-hosted only; the CA key never leaves the customer's environment
- Access proxy / traffic in the data path (Teleport-style) — conflicts with simplicity and minimal attack surface; certificates are verified by stock OpenSSH
- Session recording — not part of the visibility promise for v1; implies a proxy

## Context

- Competitive landscape: Teleport (powerful, but heavy and proxy-based, key features in enterprise tier), Smallstep step-ca (CA-focused), HashiCorp Vault SSH secrets engine (part of a large platform, BSL licence), Netflix BLESS (archived). Differentiation: **simplicity** (one binary, up in minutes, no proxy), **inventory** of existing keys, **minimal auditable attack surface**, and **fully open** with no paywalled security features.
- Builds on native OpenSSH certificate support (`TrustedUserCAKeys`, `HostCertificate`, `@cert-authority`, `RevokedKeys`/KRL, `AuthorizedPrincipalsFile`).
- Owner runs a homelab (Windows Daniel-PC with OpenSSH Server, Ubuntu laptop, ZimaBoard, Proxmox, all on Tailscale) — a natural dogfooding environment, including the Windows `administrators_authorized_keys` special case.
- Research completed 2026-10-04 (`.planning/research/`): Go, pure-Go static binaries, SQLite, stdlib server-rendered UI; architecture "the server proposes, the signer disposes". No maintained Go KRL library exists — we own a fuzzed KRL encoder. Windows inbox OpenSSH is 9.5p2 (verified on Daniel-PC) and lacks 10.3 fixes.
- Hosted on GitHub (account `Labontese`), developed with GitHub best practices from the first commit.

## Constraints

- **Security**: Top priority, above convenience and speed — threat model covers a compromised CA server, stolen client keys, a malicious insider/admin, and supply-chain attacks
- **Simplicity**: Small, auditable codebase; one binary per role where possible; no unnecessary features — every feature is attack surface
- **Deployment**: Self-hosted, open source; no dependency on external services for core function
- **Compatibility**: Must work with stock OpenSSH on all target platforms — no patched sshd
- **Team**: Owner + Claude, no deadline — quality and security review take the time they take
- **Process**: GitHub best practice — all changes via PR to protected `main`, CI must pass, Conventional Commits, signed commits/releases

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Self-hosted open source only | CA key must never leave customer environment; openness is a differentiator | — Pending |
| No proxy in the data path | Simplicity and minimal attack surface; rely on native OpenSSH cert verification | — Pending |
| Short-lived certs for humans, longer + KRL for machines | Short lifetimes make revocation rarely needed; KRL covers automation and emergencies | — Pending |
| Local accounts + WebAuthn in v1, OIDC in v2 | Self-contained, smaller attack surface for first release | — Pending |
| Inventory = discover + report only in v1 | Delivers the visibility core value without the risk of automated key changes | — Pending |
| CA key model: verifying signer + HW-backed online CAs + offline trust root (bundles only) | OpenSSH certs don't chain; HW stops theft but not misuse, so signer must verify evidence itself | — Pending |
| Go (CGO_ENABLED=0), SQLite, stdlib UI | Most mature SSH cert lib, static cross-builds, ~6–10 deps, govulncheck (research) | — Pending |
| Merkle audit log with witnesses, not hash chain | Hash chain can be recomputed by anyone with DB write access | — Pending |
| GitHub best practice from day one | Security product must model the supply-chain hygiene it preaches | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-10-04 after research*
