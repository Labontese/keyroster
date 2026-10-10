# Phase 2: Passkey Login MVP - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-10-10
**Phase:** 02-passkey-login-mvp
**Areas discussed:** none interactively. The owner delegated all four presented areas to Claude.

---

## Area selection

| Option | Description | Selected |
|--------|-------------|----------|
| Who signs users/roles | Root-signed vs admin-SSHSIG-signed user/credential/role data; first-admin bootstrap | ✓ (delegated) |
| Principal format | Role principals (`role:x`) vs account-name principals; meaning of groups/host groups before the agent | ✓ (delegated) |
| Hostname, TLS and RP ID | One-way RP ID choice; TLS source (own cert, tailscale cert, ACME, self-signed) | ✓ (delegated) |
| keyroster login flow | Default TTL, fingerprint display, who computes principals, headless, Windows agent pipe | ✓ (delegated) |

**User's choice:** "ta det som är bäst" (take what is best). All areas were decided by Claude with the recommended option.

## Decisions taken on the owner's behalf (summary)

| Area | Alternatives considered | Chosen |
|------|------------------------|--------|
| Authority | (a) users/roles in the root-signed policy (an offline ceremony per user); (b) a server-trusted directory (violates KEY-02); (c) a two-layer model: root signs admins, the admin quorum signs the directory | (c) |
| Admin signing | Passkey step-up in the UI vs SSH admin key via CLI | SSH admin key via CLI (reuses Phase 1 SSHSIG; admin UI is UI-02) |
| Enrollment | Admin-set credential, self-service, or invite plus admin approval with a fingerprint check | Invite plus admin-signed approval |
| Passkey types | Device-bound only (attestation) vs any credential with UV | Any credential, UV required, BE/BS recorded (hardware optional) |
| Principals | Account names vs role principals | Role principals (`role:<name>`, `u:<user>`) |
| Principal authority | Server computes vs signer recomputes and checks equality | Signer recomputes |
| RP ID | Fixed hostname in server config vs in root-signed policy | Root-signed policy, DNS name only |
| TLS | Built-in ACME, self-signed with pin, operator-provided cert | Operator-provided cert (homelab: `tailscale cert`), CLI SPKI pin |
| CLI transport | libfido2/webauthn.dll (cgo), device-code polling, browser loopback with PKCE | Browser loopback with PKCE |
| Headless | Device-code fallback now vs defer | Defer (loses anti-phishing property) |
| Signer verifier | go-webauthn in the signer vs a minimal in-house verifier | Minimal in-house verifier; go-webauthn in the server only |

## Claude's Discretion

- Directory schema and domain string, CLI command names, server mirroring of the directory
- Invite expiry and token format, session lifetime, UI layout and wording
- Server config format, SQLite schema, rate limits
- Key ID format, warning banner text, TLS reload mechanism
- Policy v2 domain string vs successor version for the RP fields
- Picking up Phase 1 CI debt (capslock piv target, `addLogKey`)

## Deferred Ideas

- Headless/device-code login with second-device fingerprint confirmation
- Per-role "require device-bound credential"
- Native CTAP2 (libfido2 / webauthn.dll)
- Admin actions in the web UI (UI-02)
- Built-in ACME in keyroster-server
