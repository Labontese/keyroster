# Phase 1: Trust Core - Context

**Gathered:** 2026-10-04
**Status:** Ready for planning

<domain>
## Phase Boundary

An admin can stand up a hardware-backed, auditable CA whose certificates stock OpenSSH accepts and whose signing rules cannot be bypassed, before any user or host exists. The repository runs with GitHub best practice from the first commit.

Requirements in scope: REPO-01..04, CA-01..08, KEY-01, KEY-03, KEY-04, KEY-05, KEY-07, VIS-01, VIS-03 (see `.planning/ROADMAP.md` Phase 1 for the five success criteria).

Already locked by research and roadmap, and not re-discussed: Go with `CGO_ENABLED=0`, SQLite with the signer as the only log writer, "the server proposes, the signer disposes", separate user, host and machine CAs, a root that signs only bundles, KRL authority and policy (never certificates), backend build order (software → ssh-agent/PKCS#11 → TPM → build-tagged PIV), and a KRL encoder deferred to Phase 3 (Phase 1 only defines the KRL authority in the bundle format).

</domain>

<decisions>
## Implementation Decisions

### Project identity and repository
- **D-01:** The final project name is **keyroster** (it replaces the working names "ssh-cert-manager" and "sshcm"). The Go module is `github.com/Labontese/keyroster`. Binaries are `keyroster` (CLI), `keyroster-signer`, `keyroster-server` and `keyroster-agent`; every `sshcm*` name in the research docs maps to these. Domain-separation strings in signed formats use the `keyroster/` prefix (e.g. `keyroster/trust-bundle/v1`). — **Reversibility:** one-way — agents pin signed formats containing the domain-separation strings, and the Go module path is a published import path.
- **D-02:** A collision search was done on 2026-10-04. `keyward` is an existing SSH-key TUI, `keysteward` is a commercial KMS (PRONIT), `sshledger` conflicts with Ledger's SSH agent, and "ssh" in the product name was avoided because SSH Communications Security holds the "SSH" trademark. `keyroster` had no same-name repos and no products found. The GitHub *user* `keyroster` exists (inactive), so the repo lives under `Labontese`.
- **D-03:** The license is **Apache-2.0**. — **Reversibility:** costly — relicensing needs consent from every contributor once outside contributions arrive.
- **D-04:** The repo is **public from the first commit** at `github.com/Labontese/keyroster`. The README states clearly that the project is pre-alpha and must not be used in production. Public visibility is what makes CodeQL, secret scanning with push protection, private vulnerability reporting, rulesets and Scorecard available for free (REPO-01, REPO-03).
- **D-05:** **Required review uses a separate bot account for Claude** (e.g. `keyroster-bot`, final name at the planner's discretion) with its own SSH signing key. Claude commits, pushes and opens PRs from that account, and the owner (Labontese) reviews and approves them, so the two identities are real. The owner's own PRs merge through a documented ruleset bypass for the admin role, which GitHub logs. Document the bypass policy in CONTRIBUTING.md. The bot needs only the minimal repo permissions (write to branches, open PRs) and must not be able to bypass rulesets.
- **D-06:** **Commits are signed with SSH signing using regular ed25519 keys** held in ssh-agent (no FIDO touch per commit): the owner's existing key, and a separate key for the bot. Add both as signing keys on their GitHub accounts and require signed commits in the ruleset. Release signing is a separate concern (Phase 6: cosign plus a maintainer SSHSIG).

### Hardware, custody and CA algorithm
- **D-07:** The owner's homelab has **only TPM 2.0**, with no YubiKey, YubiHSM or other token. Dogfooding of hardware custody in Phase 1 therefore means TPM.
- **D-08:** **`keyroster-signer` runs in a Proxmox VM with a vTPM** in the homelab, holding the online CA keys in the vTPM. This is a known, accepted weakness: vTPM state is a file on the Proxmox host, so whoever controls the host controls the keys. Document it as weaker than a physical TPM but stronger than a software key, and have `doctor`/docs state it. Signer sandboxing (own OS user, systemd hardening, UDS) applies inside the VM.
- **D-09:** **The CA algorithm depends on the backend.** It is Ed25519 when the backend supports it (software, YubiHSM 2 via PKCS#11, YubiKey PIV with firmware ≥ 5.7) and ECDSA P-256 on TPM. The signer, the cert builder and the bundle format are algorithm-agnostic, and each CA's algorithm is recorded in the trust bundle and the audit log. The homelab's user, host and machine CAs are therefore P-256. — **Reversibility:** costly — the bundle and policy formats must carry the algorithm from day one, and adding it later would mean a format version bump and re-pinning.
- **D-10:** **The offline trust root is a software root on offline media**, a deliberate deviation from the "M-of-N hardware keys" wording in success criterion 2 *for the homelab only*. The ceremony generates **two independent Ed25519 root keys**, each age-encrypted with its own passphrase and stored on its own USB stick. The root threshold is **1-of-2**: agents accept a bundle signed by either key. This is the same M-of-N model the hardware path uses (independent keys plus a threshold), so moving to YubiKeys (ed25519-sk or PIV) later is a ceremony and re-sign, not a format change. Shamir secret-sharing was rejected because it would be a second, incompatible model.
- **D-11:** The tooling must still **support hardware root keys** (ed25519-sk / PIV) so that success criterion 2 holds for the product. Verify this in CI with a software FIDO/PIV stand-in. The homelab's use of a software root is the only deviation, and it must be visible: ceremony output and `doctor` flag the root as software-held.
- **D-12:** **The PKCS#11/YubiHSM backend (KEY-03) and the PIV backend (KEY-05) are verified in CI only in Phase 1.** PKCS#11 runs against SoftHSM2 through OpenSSH `ssh-agent` + `ssh-pkcs11-helper`. PIV is built behind a build tag and unit-tested against the `Signer` interface. Track real-hardware tests for both (and a hardware root ceremony) as an explicit "needs hardware" item for the Phase 6 review. KEY-05 stays in Phase 1 and is not deferred.

### Post-research decisions (2026-10-04, owner answers to 01-RESEARCH.md open questions)
- **D-13:** **Phase 1 issuance is authorized by an admin SSHSIG over the request digest.** The signer refuses a request unless it carries a valid SSHSIG (namespace under the `keyroster/` prefix) by an admin key listed in the root-signed genesis policy. WebAuthn-bound authorization (later phase) replaces or extends this through a policy update, not a signer bypass. — **Reversibility:** costly — the request wire format and genesis-policy schema carry the admin-key list from day one.
- **D-14:** **Refused signing requests are written to the audit log, rate-limited.** Every refusal is logged locally (slog). Refusals are appended to the Merkle log under a rate limit, so an attacker cannot flood it, and suppressed refusals are summarized in a periodic count entry rather than silently dropped.
- **D-15:** **The audit log keeps `github.com/transparency-dev/merkle`** as locked in the stack; switching to `x/mod/sumdb/tlog` was considered and rejected.
- **CA-08 correction (from research):** OpenSSH 9.5p2 does not exist upstream (only Microsoft's Win32-OpenSSH build). The CI matrix builds portable 9.5p1 and the latest release (10.5p1) from source with pinned SHA-256; the 9.5p2 check is a documented manual step against Windows OpenSSH on Daniel-PC (an optional Windows-runner job is at the planner's discretion).

### Claude's Discretion
- How the offline root ceremony is executed (offline machine or live USB, the exact steps, how the root public keys and genesis policy are distributed). The owner did not select this area. Stay within D-10/D-11, and prefer a design a single admin can run safely from a runbook.
- Signer operations and admin CLI ergonomics: the `keyroster ca init` flow, and the output and export format of `keyroster audit verify`. The owner did not select this area. Follow the research (UDS, own OS user, C2SP checkpoints, `sumdb/note`).
- The CI OpenSSH version matrix (it must include 9.5p2 and the latest release, per CA-08), the Dependabot cadence, and the CODEOWNERS layout.
- The bot account's exact name and permission set (within D-05).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Scope and requirements
- `.planning/ROADMAP.md` §"Phase 1: Trust Core": goal, five success criteria and research flags
- `.planning/REQUIREMENTS.md`: REPO-01..04, CA-01..08, KEY-01/03/04/05/07, VIS-01, VIS-03
- `.planning/PROJECT.md`: core value, constraints and key decisions. It still says "working name" and "hash chain"; D-01 and the research supersede those.

### Research (2026-10-04)
- `.planning/research/SUMMARY.md`: reconciled decisions, backend tiers, Phase 1 deliverables, gaps
- `.planning/research/STACK.md`: library versions, signer backends table, what not to use
- `.planning/research/ARCHITECTURE.md`: signer, server, agent and witness trust zones; bundle format; serial allocation; Merkle log
- `.planning/research/PITFALLS.md`: pitfalls 1, 3, 9, 10 and 12, plus serial reuse (the Phase 1 "avoids" list)
- `.planning/research/FEATURES.md`: feature expectations ("hash chain" wording superseded by the Merkle log)

### Project instructions
- `.claude/CLAUDE.md`: technology stack and constraints (GitHub best-practice process, Conventional Commits, signed commits)

### External specs (read from upstream during research)
- OpenSSH `PROTOCOL.certkeys` and `PROTOCOL.krl`: certificate format, no chaining, KRL authority
- C2SP signed-note and checkpoint specs: audit-log checkpoints and trust bundles

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- None. This is a greenfield project: no source code exists, and the directory is not yet a git repository. Phase 1 creates the repository itself (`git init`, the GitHub repo, rulesets and the bot account).

### Established Patterns
- None yet. Conventions get established in this phase, and the research docs are the only guidance.

### Integration Points
- The homelab provides the dogfooding target: a Proxmox VM with a vTPM for the signer; Daniel-PC (Windows OpenSSH 9.5p2) and the Ubuntu laptop as real sshd targets for the CA-08 checks outside CI.

</code_context>

<specifics>
## Specific Ideas

- The name "roster" deliberately echoes the core value: a roster of who holds keys and access, covering both certificates and the plain keys that inventory finds.
- Whenever the homelab runs a weaker-than-product configuration, it must say so loudly: the software root (D-10) and the vTPM (D-08). This mirrors the "loud warning" philosophy for software CA keys (KEY-06).

</specifics>

<deferred>
## Deferred Ideas

- Buying two FIDO2 security keys to move the root, and later passkeys, to hardware. The owner chose a software root for now, so this is a possible future ceremony rather than a roadmap item.
- Real-hardware verification of YubiHSM 2 and YubiKey PIV backends, plus a hardware root ceremony, belongs in the Phase 6 security-review checklist.
- Updating PROJECT.md and `.claude/CLAUDE.md` from the working name "ssh-cert-manager" to keyroster (and the "hash chain" wording to the Merkle log). Do this at the Phase 1 transition or as part of repo bootstrap.

</deferred>

---

*Phase: 01-trust-core*
*Context gathered: 2026-10-04*
