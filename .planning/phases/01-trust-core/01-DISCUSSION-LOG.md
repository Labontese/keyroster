# Phase 1: Trust Core - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md. This log preserves the alternatives considered.

**Date:** 2026-10-04
**Phase:** 01-trust-core
**Areas discussed:** Repo, name and license; Hardware and CA algorithm
**Areas offered but not selected:** Root ceremony; Signer operations and admin CLI (left to Claude's discretion)

---

## Repo, name and license

| Option | Description | Selected |
|--------|-------------|----------|
| Apache-2.0 | Permissive with an explicit patent grant; standard for security infrastructure | ✓ |
| AGPL-3.0 | Network copyleft | |
| MPL-2.0 | File-level copyleft | |

| Option | Description | Selected |
|--------|-------------|----------|
| Keep "sshcm" for now | Choose the real name before Phase 6 | |
| Decide the final name now | It goes into the module path and signed-format strings | ✓ |

**Name brainstorm and collision search.** Searched GitHub repos and users, and the web.
- Rejected: keyward (an existing SSH-key TUI, 50★), keysteward (PRONIT KMS), sshledger (Ledger SSH agent), keyledger, castellan (OpenStack), warrant, warden, porter, latch, tumbler, ostiary, keymarshal (confusing with Go "marshal"), and any "ssh"-prefixed name (SSH trademark).
- Clean: keyroster, accessroll, certroll.

**User's choice:** keyroster

| Option | Description | Selected |
|--------|-------------|----------|
| Bot account for Claude | A separate identity; the owner approves Claude's PRs, and the owner's PRs use a logged admin bypass | ✓ |
| Required reviews = 0 for now | Raise it when a second human joins | |
| Claude reviews via a CI check, the owner merges | One identity | |

| Option | Description | Selected |
|--------|-------------|----------|
| SSH signing with a FIDO key | ed25519-sk, one touch per commit | |
| SSH signing with a regular key | ed25519 in ssh-agent | ✓ |
| GPG | Classic | |

| Option | Description | Selected |
|--------|-------------|----------|
| Public from the start | Free CodeQL, secret scanning, rulesets and Scorecard | ✓ |
| Private until Phase 6 | Would need paid plans for REPO-01/03 | |

| Option | Description | Selected |
|--------|-------------|----------|
| Under the Labontese account | github.com/Labontese/keyroster | ✓ |
| A new organization | keyroster is taken as a user name | |

---

## Hardware and CA algorithm

| Option | Description | Selected |
|--------|-------------|----------|
| YubiKey 5 (firmware ≥ 5.7) | Ed25519 PIV + ed25519-sk | |
| YubiKey 5 (older firmware) | P-256 PIV | |
| YubiHSM 2 | A real HSM | |
| Only TPM | P-256, no backup | ✓ |

**Note:** An attempt to probe TPM presence on zima and the laptop over ssh timed out, so this was not verified.

| Option | Description | Selected |
|--------|-------------|----------|
| Buy two FIDO2 keys | ed25519-sk 1-of-2 root | |
| Software root on offline media | age-encrypted Ed25519 on USB | ✓ |
| Other hardware | | |

| Option | Description | Selected |
|--------|-------------|----------|
| zima (physical TPM, if present) | | |
| Proxmox VM with a vTPM | vTPM state lives on the Proxmox host | ✓ |
| Decide in research | | |

| Option | Description | Selected |
|--------|-------------|----------|
| Per backend | Ed25519 where supported, P-256 on TPM | ✓ |
| P-256 everywhere | | |
| Ed25519 everywhere | Excludes TPM | |

| Option | Description | Selected |
|--------|-------------|----------|
| Two independent root keys, 1-of-2 | The same model as hardware | ✓ |
| One key split with Shamir | A second model | |
| One key, two copies | Not M-of-N | |

| Option | Description | Selected |
|--------|-------------|----------|
| CI is enough for Phase 1 (PKCS#11/PIV) | SoftHSM2 + build-tagged PIV; hardware tests go to Phase 6 | ✓ |
| Move PIV to a later phase | | |

---

## Claude's Discretion

- Root ceremony execution details (within D-10/D-11)
- Signer operations, `keyroster ca init`, and the `audit verify` output and export format
- The CI OpenSSH matrix, the Dependabot cadence, CODEOWNERS
- The bot account's name and permissions

## Deferred Ideas

- Buying FIDO2 keys and a hardware root ceremony (a possible future step)
- Real-hardware YubiHSM 2 and PIV verification (Phase 6 review)
- Renaming ssh-cert-manager to keyroster in PROJECT.md and `.claude/CLAUDE.md`
