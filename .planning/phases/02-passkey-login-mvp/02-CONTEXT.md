# Phase 2: Passkey Login MVP - Context

**Gathered:** 2026-10-10
**Status:** Ready for planning

<domain>
## Phase Boundary

A user signs in with a passkey. With one command (`keyroster login`) the user gets a short-lived certificate in ssh-agent that logs them in to a manually configured host running stock OpenSSH, carrying exactly the principals their roles grant. This is the first end-to-end login.

Requirements in scope: AUTH-01, AUTH-02, AUTH-03, AUTH-04, KEY-02, KEY-06, AUTHZ-01, UI-01, PLAT-05. The five success criteria are in `.planning/ROADMAP.md` §"Phase 2".

**Not in this phase:**
- Host agent, `AuthorizedPrincipalsFile` generation on hosts, KRL and revocation (Phase 3).
- Quorum-gated policy changes and credential binding (AUTHZ-03 and AUTH-05), JIT approvals and timelock (Phase 4).
- Admin web UI with CLI parity, approvals inbox, audit browser (UI-02..04).
- Machine identities (AUTH-06, Phase 3).

**Carried forward and not re-discussed:**
- **Names.** The project is keyroster (P1 D-01). The roadmap's `sshcm login` is `keyroster login`, and the new binary is `keyroster-server`.
- **Static binaries.** Every binary builds with `CGO_ENABLED=0`. libfido2 would need cgo, so the CLI does WebAuthn through the user's browser, not through CTAP directly.
- **Web UI stack.** stdlib `html/template` plus `embed`, strict CSP, no npm, and one small hand-written JS file for the WebAuthn ceremony (research STACK.md "Web UI").
- **The server proposes, the signer disposes.**
  - The signer stays network-less on its Unix socket, and the server talks to it over that socket on the same host.
  - New kinds of evidence are added through policy, never through a signer bypass (P1 D-13).
- **Replay protection.** `RequestID` and `CreatedAt` are inside the signing bytes, and the signer already refuses `duplicate_request` and requests outside its clock-skew window.
- **Hardware is optional at every level** (project memory, 2026-10-08). Nothing in this phase may make a hardware authenticator or hardware custody mandatory.

</domain>

<decisions>
## Implementation Decisions

The owner delegated every gray area to Claude ("ta det som är bäst", 2026-10-10). The decisions below are Claude's recommendations, locked for research and planning. The one-way items get a `checkpoint:decision` before implementation, where the owner can still veto them.

### Authority over users, credentials and roles
- **D-01: Two signed layers.**
  - **Root-signed policy** (`keyroster/policy/v1` today) keeps the admin set, the admin quorum, the CA profiles (outer TTL caps) and the timelock. It gains the WebAuthn relying-party settings (D-09).
  - A new **directory** document holds users, their bound WebAuthn credentials, groups, roles and host groups. An admin quorum signs it with SSHSIG, under the admin keys the root-signed policy lists.
  - Directory versions are canonical JSON, like the other signed documents. They are numbered, chained by the SHA-256 of the previous version, and installed into the signer, which verifies them and logs each install as an audit leaf. The pattern is `install-bundle` and `trust.VerifySuccessor`.
  - The signer refuses any login issuance unless the directory in force is admin-quorum-signed under the policy in force. That is how success criterion 4 ("root/quorum-signed") holds without an offline root ceremony per new user.
  - Phase 2 runs at whatever `admin_quorum` the policy sets (1 in the homelab). Phase 4 (AUTHZ-03, AUTH-05) raises the value, not the format.
  - — **Reversibility:** costly — agents in Phase 3 and auditors will verify this two-layer chain. Folding the directory into the root policy later would mean a format version bump and a re-sign of every deployed directory.
- **D-02: Admins sign directory changes with their existing SSH admin keys through the CLI.** These are the same keys and the same SSHSIG machinery as the Phase 1 admin evidence (`internal/sshsig`, keys held in ssh-agent, `sk-*` keys allowed).
  - Example commands: `keyroster user add`, `keyroster user approve`, `keyroster role ...`.
  - Admin actions in the web UI are UI-02 (later phase). The Phase 2 web UI is limited to registration, login, the login-approval page and a read-only view of the user's own account.
  - An admin's SSH admin key and that admin's passkey are separate credentials. An admin who wants to `keyroster login` is also a directory user with a bound passkey.
- **D-03: Enrollment is invite-based, and a credential counts only once an admin signs it into the directory.**
  1. `keyroster user add <name>` creates a pending account on the server and prints a single-use invite URL with a short expiry. The default is 24 h; Claude picks the exact value.
  2. The user opens the link and registers a passkey. The registration page shows a short fingerprint of the new credential.
  3. `keyroster user approve <name>` fetches the pending credential and shows the same fingerprint. The admin compares it with the user out of band and then signs a new directory version that binds the credential.
  - Until a bound credential is in the installed directory, the account cannot sign in or get a certificate (AUTH-01, success criterion 1).
  - A server-side "pending" row is never authority. This closes the classic insider path ("register my own key on Alice's account"), because every binding is an admin signature in the log.
- **D-04: The first admin bootstraps the same way.** The admin's SSH admin key is already in the root-signed policy. The admin adds themself as a user, registers a passkey through the invite, and approves it with the SSH admin key. There is no special first-user path.
- **D-05: Any WebAuthn credential is accepted, with user verification required.**
  - Platform authenticators, synced passkeys and security keys all count.
  - `userVerification: required`. The signer checks both the UP and the UV flag.
  - Attestation is `none` and is not required, in line with the hardware-is-optional rule.
  - The directory records each credential's backup-eligible and backed-up flags (BE/BS), so later visibility work can show synced against device-bound credentials.
  - Sign counters are not relied on, since synced passkeys report 0.
  - A per-role "require device-bound" rule is deferred.

### Roles, principals and host groups
- **D-06: Certificates carry role principals, not account names.**
  - Each role lists the principal strings it grants. The convention is `role:<name>`, plus `u:<username>` for a personal account.
  - Principal strings are validated with the existing signer rules: no empty values, wildcards, commas, whitespace or control characters.
  - A Phase 2 host needs a hand-written `AuthorizedPrincipalsFile` per account, and that is exactly what the Phase 3 agent will generate. Account-name principals were rejected: they work with sshd defaults, but they stop working once the agent arrives, and they are anti-pattern 5 in research ARCHITECTURE.md.
  - — **Reversibility:** one-way — the principal format is baked into issued certificates and into every host's principals files. Changing it means reconfiguring every host and re-issuing.
- **D-07: Groups, roles and host groups each have a narrow job.**
  - **Groups** are named sets of users in the directory.
  - **Roles** map users and groups to principals, and carry their own max TTL. A role's max TTL must not exceed the user CA profile cap.
  - **Host groups** map each local account to the role principals it accepts. In Phase 2 they enforce nothing by themselves, because certificates are not host-scoped.
  - A CLI command renders the principals file for a given host group and account (for example `keyroster host principals <group> <account>`). Manual host setup then uses exactly the content the Phase 3 agent will write later, through one shared renderer.
- **D-08: The signer, not the server, decides the principals and the TTL cap.**
  - The request names the user and, optionally, a subset of the user's roles. If none are named, all of the user's roles apply.
  - The signer recomputes the principal set from the installed directory and refuses unless the request's principals equal it exactly.
  - It also refuses a TTL above the smallest max TTL among the selected roles. Sensitive or JIT roles do not exist until Phase 4.
  - The certificate key ID identifies the user and the roles. Claude picks the exact format, and audit verify must be able to re-check it.

### Server identity: hostname, TLS and RP ID
- **D-09: The RP ID is one DNS hostname set by the operator, and it lives in the root-signed policy together with the allowed origin(s).**
  - IP addresses are refused at configuration time, because WebAuthn rejects IP origins.
  - The signer checks `rpIdHash`, the `clientDataJSON` origin, the type (`webauthn.get`) and the challenge itself. A compromised server therefore cannot swap the relying party.
  - — **Reversibility:** one-way — passkeys are bound to the RP ID, so changing the hostname later invalidates every enrolled credential. Docs and `keyroster-server` setup must say so loudly.
- **D-10: TLS uses an operator-provided certificate and key file.**
  - The certificate can come from `tailscale cert`, an internal CA or the operator's own ACME client.
  - `keyroster-server` does no ACME itself in Phase 2. That keeps core function free of external services and outbound network code.
  - Self-signed certificates are not a supported path. Browsers refuse WebAuthn on certificate errors, so the docs must say the certificate has to be trusted by the user's browser.
  - The server reloads the certificate without a restart, because Tailscale certificates expire after 90 days. Claude picks the mechanism.
  - The CLI also pins the server's TLS identity. The pin is delivered in the invite or by `keyroster init` (research ARCHITECTURE.md trust boundary B1).
  - **Open research question.** Does `tailscale cert` renewal (and typical ACME renewal) keep the same key? If not, a plain SPKI pin breaks every renewal. The researcher decides between pinning a key the operator keeps across renewals, pinning a CA or a key set, and a signed pin-rotation path.
- **D-11: Homelab dogfood uses the signer VM's Tailscale MagicDNS name with a `tailscale cert` certificate.** The exact hostname is fixed at the dogfood step, and the owner confirms it there because of D-09.
  - The root-signed policy change (new schema with RP settings, D-01) is signed for the homelab by TEST root C or D. The homelab stays dogfood-only until the owed v3 offline ceremony (KEY-07).

### `keyroster login` flow
- **D-12: The login uses a browser loopback with `state` and PKCE.**
  1. The CLI makes an ephemeral Ed25519 key in memory, builds the issue request, starts a 127.0.0.1 listener and opens the server's approval page in the browser. It also prints the URL.
  2. The page performs `navigator.credentials.get` with challenge = SHA-256(domain tag ‖ request signing bytes).
  3. The result comes back to the CLI by a redirect to the loopback listener on the browser's machine. The server releases the certificate only to the holder of the code and the PKCE verifier.
  - **What this does and does not protect.** The primary anti-phishing control is the fingerprint comparison (D-13), not the loopback. A certificate is public data, and an attacker who started the request already holds the ephemeral private key.
    - Today every issue leaf carries the full certificate (`internal/signer/issue.go`: "log leaf holding the full certificate"), and the log will be served as tiles and to witnesses.
    - So if the signer mints at assertion time, a phished approval yields a certificate the attacker can fetch from the log. Loopback plus PKCE is at best a server-enforced control, and a compromised server can hand over the certificate anyway.
  - **Open research question.** The researcher must settle minting at redemption (the code and PKCE verifier reach the signer path) against minting at assertion. They must also settle whether the log may expose a certificate before it is redeemed, and what that costs the Merkle log's completeness.
  - **Headless.** A device-code or polling flow is deferred, to keep Phase 2 small. It is not ruled out on security grounds: its phishing exposure relative to loopback depends on the research question above, and the fingerprint check applies to both. Users on remote machines log in locally and forward their agent.
- **D-13: The fingerprint is shown before the user touches the key (AUTH-04).**
  - The CLI prints the SHA-256 fingerprint of the ephemeral key, plus the principals and TTL.
  - The approval page shows the same fingerprint, principals and TTL before it calls WebAuthn.
  - The fingerprint is inside the signed request digest, so a mismatch cannot be hidden by the server.
- **D-14: The TTL defaults to the effective cap.**
  - The default is the smallest max TTL among the selected roles, bounded by the CA profile.
  - `--ttl` may only shorten it.
  - `valid_after` is backdated by the existing clock-skew rule.
- **D-15: The key and certificate go into the running ssh-agent with a lifetime constraint equal to the certificate's remaining validity.** That covers success criterion 2 ("leaves the agent when the certificate expires").
  - The private key is never written to disk.
  - If no agent is reachable, the command fails with instructions rather than falling back to a file.
  - On Windows the CLI uses `\\.\pipe\openssh-ssh-agent` through `github.com/Microsoft/go-winio`, a new dependency that is already in the locked stack. It is limited to Windows build tags, and the dependency-firewall and capslock baselines are updated in the same plan.
- **D-16: Platform verification follows the no-unexercised-paths rule.**
  - CI builds and tests the CLI for Linux, macOS and Windows.
  - Real logins run on the homelab: the Linux laptop, and Windows on Daniel-PC.
  - Any platform not exercised end to end (likely macOS) is labelled UNVERIFIED in docs and in the SUMMARY, and is put on the needs-hardware or needs-platform list. It is never shown as verified.

### Signer-side WebAuthn verification
- **D-17: A new evidence type, `webauthn-assertion/v1`, is verified inside the signer by a minimal in-house verifier.**
  - The verifier parses authenticatorData and clientDataJSON, checks the RP, origin, type, challenge and the UP and UV flags, and verifies the COSE signature with stdlib crypto.
  - It is fuzzed like every other parser.
  - `go-webauthn/webauthn`, with its JWT, TPM and CBOR dependencies, may be used **only in `keyroster-server`**. It must not appear in the signer's dependency graph, which the dependency firewall and the capslock baseline check.
  - The algorithms are at least ES256 and EdDSA. The researcher decides whether RS256 is needed for Windows Hello, and fixes the minimal COSE/CBOR subset.
  - The Phase 1 `admin-sshsig/v1` issuance path stays as it is.

### Software CA key warning (KEY-06)
- **D-18: The warning is driven by custody the signer reports.**
  - The signer reports its CA custody over the socket.
  - When any CA is held by the encrypted software key, `keyroster-server` shows a loud evaluation-only banner on every UI page, and every `keyroster` CLI command that talks to the server prints the same warning.
  - Custody comes from the signer, never from server config, so the server cannot hide it.

### Claude's Discretion
- The directory's exact schema and domain-separation string (for example `keyroster/directory/v1`), its CLI command names, and how the server mirrors the installed directory.
- The invite expiry and token format, the session cookie lifetime, and the UI page layout and wording, within strict CSP and research STACK.md "Web UI" headers.
- Server config format (TOML or flags), the SQLite schema for server-side state, and rate limits on login and WebAuthn endpoints.
- The key ID format (within D-08), the exact banner text (D-18), and the TLS reload mechanism (D-10).
- Whether the root-policy RP fields come as a policy v2 domain string or as a successor policy version, given the `DisallowUnknownFields` canonical-JSON rule.
- Deferred CI debt that this phase's CI edits may pick up: the capslock `-tags piv` target and the unused `addLogKey` harness helper (`.planning/phases/01-trust-core/deferred-items.md`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Scope and requirements
- `.planning/ROADMAP.md` §"Phase 2: Passkey Login MVP": goal, five success criteria, research flags (CLI WebAuthn transport, Windows CTAP and the ssh-agent pipe, WebAuthn origin rules)
- `.planning/REQUIREMENTS.md`: AUTH-01..04, KEY-02, KEY-06, AUTHZ-01, UI-01, PLAT-05. AUTH-05, AUTH-06, AUTHZ-02..07 and UI-02..04 are explicitly later.
- `.planning/PROJECT.md`: core value and constraints

### Prior phase decisions
- `.planning/phases/01-trust-core/01-CONTEXT.md`: P1 D-01 naming, D-09 algorithm agility, D-13 admin SSHSIG evidence, D-14 refusal logging
- `.planning/phases/01-trust-core/01-VERIFICATION.md`: what Phase 1 actually delivered, and the owner overrides
- `.planning/phases/01-trust-core/deferred-items.md`: open CI debt
- `.planning/STATE.md` §Decisions: the Phase 1 implementation decisions (canonical JSON, evidence refusal classes, bundle install rules)

### Research
- `.planning/research/ARCHITECTURE.md`:
  - §"Trust boundaries" (B1, B2, and the "authenticate payloads, not pipes" rule)
  - The policy model (users, roles, host_groups; the signing-function pseudocode)
  - §6 "Data flow: short-lived user cert login"
  - "Host-side principal mapping"
  - Anti-patterns 4 and 5
- `.planning/research/STACK.md`: go-webauthn v0.18.2 (server only, per D-17), go-winio v0.6.2, Web UI headers, the what-not-to-use list
- `.planning/research/PITFALLS.md`: the empty/wildcard principal and authorization-outside-the-signer pitfalls
- `.planning/research/SUMMARY.md`: reconciled decisions

### Existing docs
- `docs/security/custody.md`: custody levels and the wording the software-key warning must match
- `docs/security/needs-hardware.md`: where unexercised platforms and hardware go (D-16)
- `docs/runbooks/signer-install.md`: the homelab signer install that the server will sit next to

### External specs
- W3C WebAuthn Level 2/3: authenticatorData layout, clientDataJSON, rpIdHash, the UP and UV flags, BE/BS flags
- RFC 8152/9053 COSE key and algorithm encodings (the ES256 and EdDSA subset); RFC 8949 CBOR (the subset the verifier needs)
- RFC 8252 (OAuth for native apps: loopback redirect) and RFC 7636 (PKCE), for the D-12 pattern
- OpenSSH `sshd_config(5)`: `AuthorizedPrincipalsFile`, `TrustedUserCAKeys`; `ssh-add -t` and agent lifetime constraints

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `internal/wire/issue.go`: `IssueRequest` with `Subject`, `Principals`, `ValidForSeconds`, `RequestID`, `CreatedAt`, `Extensions` and `Evidence{Type, Blob}` (max 4 items, 8 KiB blob). The new `webauthn-assertion/v1` evidence type fits as is. Check the blob cap against real assertions.
- `internal/signer/evidence.go`: `verifyAdminEvidence`, the default-deny evidence pattern with named refusal details. The WebAuthn verifier follows the same shape and refusal classes.
- `internal/trust/policy.go` and `canonical.go`: canonical JSON with `DisallowUnknownFields`, plus `Policy`, `AdminKey` and `CAProfile`. Adding RP settings is a schema change. The directory document reuses the canonical-JSON and SSHSIG helpers.
- `internal/trust/successor.go`: the prev-hash chain and successor verification, which is the model for directory version chaining.
- `internal/sshsig`: SSHSIG sign and verify for admin signatures on directory versions.
- `internal/certprofile`: role-based caps, which roles' TTLs must stay within.
- `internal/signerclient`: the server's client to the signer socket.
- `internal/doctor`: custody reporting, the source for the D-18 warning.
- `cmd/keyroster`: the existing CLI and its subcommand dispatcher, where the new `login`, `user`, `role` and `host` commands go.

### Established Patterns
- Every signed document is canonical bytes with a `keyroster/...` domain tag. Every refusal is logged and rate-limited into the Merkle log (P1 D-14).
- The dependency firewall (`scripts/dep-firewall.sh`) and the capslock baseline (`test/capslock/`) gate every new dependency. Adding go-webauthn to the server and go-winio to the CLI means updating both, and the signer's graph must not change.
- e2e tests run against real sshd builds (9.5p1 and the latest); every refusal case has a control that succeeds (01-04).
- Changes go through PRs to protected `main` from keyroster-bot. Admin-only settings are owner-run scripts. A required check that changes content must run on `main` first (Pitfall 10).

### Integration Points
- `keyroster-server` is a new binary (`cmd/keyroster-server`). It runs on the signer host and reaches the signer over its Unix socket, as a member of the allowed group.
- The homelab signer VM (`keyroster-signer-vm`, vTPM, bundle v2 under TEST roots C and D) is the dogfood target. The laptop (Linux) and Daniel-PC (Windows OpenSSH 9.5p2) are the real sshd and CLI targets.

</code_context>

<specifics>
## Specific Ideas

- The homelab keeps saying loudly when it runs weaker than the product: TEST roots, vTPM, and now possibly a software CA key (KEY-06 banner).
- The RP ID decision (D-09) is the one choice in this phase that cannot be undone without re-enrolling every passkey. Surface it to the owner at the checkpoint, with the concrete hostname.

</specifics>

<deferred>
## Deferred Ideas

- **Headless login.** A device-code or polling flow for machines without a local browser. Deferred to keep Phase 2 small. Its phishing exposure relative to loopback depends on the D-12 research question.
- **Per-role "require device-bound credential".** Enforcement based on the BE/BS flags or on attestation. A hardening option for later, never a default.
- **Native CTAP2.** Via libfido2 or webauthn.dll, if a cgo-free path appears or a build-tagged variant is wanted.
- **Admin actions in the web UI.** UI-02, a later phase.
- **Built-in ACME.** In `keyroster-server`, if operators ask for it.

</deferred>

---

*Phase: 02-passkey-login-mvp*
*Context gathered: 2026-10-10*
