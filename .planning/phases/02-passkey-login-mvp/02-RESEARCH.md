# Phase 2: Passkey Login MVP - Research

**Researched:** 2026-10-10
**Domain:** WebAuthn relying party split across an untrusted web server and a network-less signer; CLI browser-loopback login; ssh-agent on Linux, macOS and Windows; signed directory (users, credentials, roles); server-rendered web UI
**Confidence:** MEDIUM-HIGH overall. HIGH for the in-repo integration points and the spec-level WebAuthn checks. MEDIUM for browser and agent behaviour that only real platforms can confirm. Windows agent behaviour is verified from source; the owner chose option A (2026-10-10, Open Questions Q2).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

The owner delegated every gray area to Claude ("ta det som är bäst", 2026-10-10). The decisions below are Claude's recommendations, locked for research and planning. The one-way items get a `checkpoint:decision` before implementation, where the owner can still veto them.

#### Authority over users, credentials and roles
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

#### Roles, principals and host groups
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

#### Server identity: hostname, TLS and RP ID
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

#### `keyroster login` flow
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

#### Signer-side WebAuthn verification
- **D-17: A new evidence type, `webauthn-assertion/v1`, is verified inside the signer by a minimal in-house verifier.**
  - The verifier parses authenticatorData and clientDataJSON, checks the RP, origin, type, challenge and the UP and UV flags, and verifies the COSE signature with stdlib crypto.
  - It is fuzzed like every other parser.
  - `go-webauthn/webauthn`, with its JWT, TPM and CBOR dependencies, may be used **only in `keyroster-server`**. It must not appear in the signer's dependency graph, which the dependency firewall and the capslock baseline check.
  - The algorithms are at least ES256 and EdDSA. The researcher decides whether RS256 is needed for Windows Hello, and fixes the minimal COSE/CBOR subset.
  - The Phase 1 `admin-sshsig/v1` issuance path stays as it is.

#### Software CA key warning (KEY-06)
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

### Deferred Ideas (OUT OF SCOPE)
- **Headless login.** A device-code or polling flow for machines without a local browser. Deferred to keep Phase 2 small. Its phishing exposure relative to loopback depends on the D-12 research question.
- **Per-role "require device-bound credential".** Enforcement based on the BE/BS flags or on attestation. A hardening option for later, never a default.
- **Native CTAP2.** Via libfido2 or webauthn.dll, if a cgo-free path appears or a build-tagged variant is wanted.
- **Admin actions in the web UI.** UI-02, a later phase.
- **Built-in ACME.** In `keyroster-server`, if operators ask for it.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| AUTH-01 | Admin can create local user accounts; every account must register at least one WebAuthn/passkey credential | Invite + go-webauthn registration on the server (§Standard Stack); credential bound only by an admin-signed directory version (§Pattern 1); server refuses login for users with no bound credential in the installed directory |
| AUTH-02 | User can log in to the web UI with a passkey/FIDO2 key | In-house verifier `internal/webauthn` used by the server for web sessions against directory credentials (§Pattern 2); `__Host-` session cookie (§Security Domain) |
| AUTH-03 | `sshcm login` (= `keyroster login`) gets a short-lived cert into ssh-agent with matching lifetime on Linux, macOS, Windows | Loopback + PKCE flow, mint at redemption (§Resolved Q2); agent add with `LifetimeSecs` (§Pattern 5). **Windows inbox agent refuses lifetime constraints and persists keys to the registry** (§Resolved Q5): the owner chose option A, keyroster's own in-memory agent (2026-10-10; 02-02) |
| AUTH-04 | Fingerprint shown on CLI and in browser | Fingerprint of the ephemeral key computed from the request's `SubjectKey` on both sides; the challenge is the request digest, so the server cannot change it unseen (§Pattern 3) |
| KEY-02 | Signer issues only on evidence it verifies itself (WebAuthn assertion over the request digest, quorum-signed policy version) | `webauthn-assertion/v1` evidence verified in the signer with stdlib only; directory install verified against admin quorum of the policy in force (§Pattern 1, §Pattern 2) |
| KEY-06 | Encrypted software CA key for evaluation with a loud warning in CLI and UI | **No software keystore backend exists yet** (`CustodySoftware` is only a constant). New `internal/keystore/software` backend on `filippo.io/age` (already a dependency); custody reported over a new signer status message (§Pattern 6) |
| AUTHZ-01 | Roles mapping users/groups to principals on host groups | Directory schema with groups, roles, host groups (§Pattern 1); shared principals-file renderer (D-07) |
| UI-01 | Server-rendered web UI, strict CSP, embedded, no npm | `html/template` + `embed` + one JS file; CSP must add `connect-src 'self'`; loopback hand-off by JS top-level navigation, not a form redirect (§Pitfalls 3-4) |
| PLAT-05 | Server and signer on Linux; CLI on Linux, macOS, Windows | New Windows and macOS CI test jobs; per-OS agent dial; browser opener per OS; macOS stays UNVERIFIED unless exercised (D-16) |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

From `.claude/CLAUDE.md` (project) and the user's global and project instructions:

- **Security first**, above convenience and speed. Threat model: compromised CA server, stolen client keys, malicious insider/admin, supply-chain attacks.
- **Simplicity:** small auditable codebase, one binary per role, no unnecessary features. Every feature is attack surface.
- **Self-hosted, no external services for core function.** (This is why D-10 rules out built-in ACME.)
- **Stock OpenSSH only**, no patched sshd.
- **Static binaries:** `CGO_ENABLED=0` for every default binary. Hence no libfido2 and no native CTAP.
- **Go stack locks (STACK.md):** stdlib `net/http`, `html/template`, `embed`, `log/slog`; `modernc.org/sqlite`; `go-webauthn/webauthn` v0.18.2 (server only, per D-17); `Microsoft/go-winio` v0.6.2 (CLI, Windows build tag only); `golang.org/x/time/rate` for rate limits; `filippo.io/age` v1.3.2; no SPA, no npm, no `@simplewebauthn/browser`; no JWT sessions; no `math/rand`; `crypto/rand` only.
- **Web UI headers (STACK.md):** `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, plus `http.CrossOriginProtection`, `SameSite=Strict; Secure; HttpOnly; __Host-` cookies, HSTS, `Cross-Origin-Opener-Policy: same-origin`. **This research adds `connect-src 'self'`** (see Pitfall 3).
- **Dependency gates:** `scripts/dep-firewall.sh` (signer graph bans `net/http`, `net/rpc`, `crypto/tls`, `html/template`, `text/template`, `os/exec`, `net/smtp`, `plugin`, TPM simulators); `scripts/capslock-check.sh` baseline `test/capslock/keyroster-signer.json`; depguard `signer-no-network` file list in `.golangci.yml`; `forbidigo` bans `.SignCert` outside `internal/cert`.
- **Every parser is fuzzed** (`scripts/fuzz.sh`).
- **Process:** all changes via PR to protected `main` from keyroster-bot; CI must pass; Conventional Commits; signed commits. A required check that changes content must run on `main` first (Pitfall 10); rulesets are applied by the owner, never by Claude.
- **GSD workflow:** edits only through GSD commands.
- **User memory:** untested code or doc paths are removed or labelled UNVERIFIED, never shown as verified. Hardware is optional at every security level and never required.
- **Language:** planning artifacts in English; user-facing summaries to the owner in Swedish.

## Summary

Phase 2 is the first phase where an untrusted web server talks to users, so the design rests on one rule from Phase 1: **the server proposes, the signer disposes.** Everything that grants access (credential bindings, role-to-principal mappings, RP identity, the user's approval of one exact request) reaches the signer as a payload signed by someone the server cannot impersonate. The admin quorum signs the directory, the roots sign the policy with the RP ID, and the user's authenticator signs the request digest. The signer re-derives principals and the TTL cap itself.

The research settles the open questions in CONTEXT.md:

- **D-10 (TLS pin):** `tailscale cert` makes a fresh P-256 key on every issuance and renews at 2/3 of a 90-day lifetime. A leaf-SPKI pin therefore breaks about every 60 days, so pin the issuing root instead (Resolved Q1).
- **D-12 (mint timing):** mint at redemption. The phisher started the request, so they hold the PKCE verifier and the ephemeral key. The only thing they lack is presence on the victim's loopback, so nothing that leads to a certificate may exist before the code has reached that loopback (Resolved Q2).
- **D-17 (algorithms):** accept ES256, EdDSA and RS256, because Windows Hello needs RS256. Store each credential in the directory as SPKI DER, so the signer needs **no CBOR at all**. go-webauthn handles the CBOR once, at registration on the server (Resolved Q3).
- **Policy RP fields:** add them as an `omitempty` pointer field. Installed v1 policies then still round-trip byte-for-byte, as tested this session (Resolved Q4).

The largest new finding is about Windows. The Win32-OpenSSH agent **refuses** any add-identity request with a lifetime constraint (`SSH_ERR_FEATURE_UNSUPPORTED`, so the CLI gets `SSH_AGENT_FAILURE`). This was reproduced on Daniel-PC's inbox 9.5p2: `agent refused operation`. It also **stores every added private key DPAPI-encrypted in the registry**, where it survives reboots. Both break D-15 and success criterion 2 on Windows, so the owner decided at a checkpoint: option A (Resolved Q5; Open Questions Q2, 2026-10-10).

Two scope items are easy to miss. First, KEY-06 needs a whole new software keystore backend: `CustodySoftware` is only a constant today. Second, the signer protocol has one message type today. Phase 2 needs at least directory install, directory fetch and a status/custody message, and directory installs must work **online**: the current install-bundle pattern requires a signer restart.

**Primary recommendation:** Build in this order:
1. Shared signer-safe packages: `internal/webauthn` (stdlib-only assertion verifier, fuzzed and differentially tested against go-webauthn) and `internal/directory` (canonical document, quorum verification, principal computation and the principals-file renderer).
2. The signer: new evidence path, online directory install, new leaf kinds, key ID `kr2`, status message, software backend.
3. `keyroster-server`.
4. The CLI: `login`, `init`, admin `user`/`role`/`group`/`host` commands.
5. Dogfood on the homelab.

Surface D-09 (hostname) and the Windows agent choice as owner checkpoints before any code depends on them. Both are now resolved (Open Questions Q1 and Q2): the Windows agent is option A, and the concrete hostname is confirmed at 02-13 Task 1.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Verify WebAuthn assertion for issuance | Signer (`internal/webauthn`, stdlib only) | Server (pre-flight for UX) | Authority must sit where the CA key is (Pitfall 10); the server check only gives early error messages |
| Verify WebAuthn assertion for web session login | Server (`internal/webauthn`, same code) | — | Read-only session, not authority; reusing the signer's verifier keeps one semantics |
| Parse registration (attestationObject, COSE key) | Server (go-webauthn) | Admin CLI (displays SPKI fingerprint) | CBOR/COSE parsing stays out of the signer; signer sees only SPKI DER |
| Bind credentials, define roles/groups/host groups | Admin CLI (SSHSIG with admin keys) | Signer (verifies quorum) | D-01/D-02: authority is admin signatures, never server rows |
| Store pending accounts, invites, sessions, login sessions | Server SQLite | — | Non-authoritative state; losing it never grants access |
| Compute principals and TTL cap | Signer (from installed directory) | CLI/server (display only) | D-08 |
| Mint and log certificate | Signer | — | Unchanged from Phase 1 (log before release) |
| Release certificate to the CLI | Server (code + PKCE check) | CLI (verifies cert against pinned CA) | RFC 8252/7636; server-enforced control (Resolved Q2) |
| Hold ephemeral private key | CLI process memory → ssh-agent | — | CA-06; never on disk (D-15) |
| RP ID and origins | Root-signed policy | Server reads them from signer status | Server config can never move the RP (D-09) |
| CA custody banner | Signer reports | Server UI + CLI display | D-18 |
| TLS termination and cert reload | Server | Operator timer (`tailscale cert`) | D-10 |

## Resolved Research Questions

### Q1 (D-10): What should the CLI pin, given certificate renewal?

**Finding:** `tailscale cert` generates a brand-new ECDSA P-256 key for every issuance: `certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` [VERIFIED: github.com/tailscale/tailscale `feature/acme/cert.go` line 578, main branch, file last changed 2026-08-12]. Renewal is due at 2/3 of the lifetime (`renewalDuration := certLifetime * 2 / 3`, same file, `domainRenewalTimeByExpiry`), and Tailscale's docs say the certificates have "a 90 day expiry" and "for any certificates that you create using `tailscale cert`, you are responsible for renewing the certificate" [CITED: tailscale.com/kb/1153/enabling-https]. A leaf SPKI pin would therefore break about every 60 days on the D-11 homelab path. certbot also generates a new key by default unless `--reuse-key` is set [CITED: community.letsencrypt.org threads, MEDIUM].

**Recommendation: pin the trust anchor, not the leaf.**
- `keyroster init` stores a small **pin set of root-CA SPKI SHA-256 hashes**, delivered in the invite or confirmed interactively at init, plus the server hostname (= the RP ID).
- **Servers do not send the root**, so init cannot read it from the handshake. Instead:
  1. Verify the presented chain against the **system roots** with the hostname.
  2. Take the root of each chain in `tls.ConnectionState.VerifiedChains`.
  3. Show their SPKI hashes for out-of-band confirmation against the invite, and store the root certificates together with the pins.
- Afterwards the CLI verifies with `crypto/x509` against a pool built **only** from the stored roots, then checks the hostname.
- Accept the connection if **any** verified chain ends in a pinned root. Windows and Linux can build different chains to the same leaf (for example ISRG Root X2 self-signed, or X2 cross-signed by X1), so pin every root seen at init.
- **Invite contents:** the invite, or the `init` dialogue, carries both:
  - the TLS root pins and the hostname;
  - the **trust-root fingerprints and threshold** for the trust bundle. The CLI needs these to verify the bundle (existing `trust verify` logic) and from it the user CA key, which it checks every issued certificate against.

  The invite token itself only authorizes registration; it is not authority.
- This survives every leaf-key rotation and intermediate rotation. It breaks only when the CA moves to a new root, and it breaks closed: `keyroster init --repin` with an out-of-band check.
- [ASSUMED] Let's Encrypt has announced a new root generation. A root pin will eventually need a re-pin, so the CLI must support more than one pin and give a clear error.

**Why not the alternatives:**
- An operator-kept key is impossible with `tailscale cert`.
- A signed pin-rotation path would need a new signer signing operation (ops key over a TLS SPKI), which adds signer surface for a weak threat (a network attacker holding a misissued WebPKI cert).

**Defence in depth that matters more (authenticate payloads, not pipes):** the CLI must verify every certificate it receives:
- the signature key is the user CA from the trust bundle verified against root pins at init;
- `Key` equals the ephemeral public key;
- the principals equal what the CLI displayed;
- `ValidBefore - ValidAfter` is no more than the requested TTL plus the clock-skew backdate.

The browser leg uses WebPKI anyway, so the CLI pin only protects the CLI leg.

### Q2 (D-12): Mint at assertion or at redemption?

**Threat analysis:**
- In consent phishing, the attacker runs `keyroster login` on their own machine. They therefore hold the ephemeral private key **and** the PKCE verifier, and they send the victim the approval URL.
- The victim's browser is at the genuine origin (WebAuthn binds the origin), so the victim produces a valid assertion over the attacker's request.
- The one thing the attacker lacks is the **loopback on the victim's machine**: the code (or anything that leads to issuance) is delivered there.

Hence:

1. **Mint at redemption.**
   - The signer is called only when the CLI presents `code` + `code_verifier` to the server.
   - If the signer minted at assertion time, the full certificate would land in an issue leaf (`internal/signer/issue.go`, which commits "the log leaf holding the full certificate"). Once the log is served (tiles, witnesses, Phase 4), the phisher fetches the certificate and uses it with the private key they already hold.
   - Minting at redemption means a phished, unredeemed approval never produces a certificate, a serial or a log leaf.
2. **The log never holds an unredeemed certificate.** Log completeness is unaffected: every certificate that exists is logged before release (VIS-01 unchanged). An approval that is never redeemed is not an issuance; the server just records it as an expired login session.
3. **Server-enforced, not signer-enforced.**
   - A compromised server sees the assertion and can mint at any time. It holds no secret the signer could demand.
   - Putting the PKCE challenge into the signed request and the verifier into evidence would add nothing: the phisher holds the verifier. So **do not** add PKCE to the wire format.
   - The residual (a compromised server plus a phished or unwitting user) is bounded by the signer: only that user's directory principals and role TTL, logged with the user's identity. Document it.
4. **Inherent WebAuthn residual (document it in the threat model):**
   - A compromised server can set the challenge of **any** ceremony the user performs at the RP origin, including an ordinary web-UI login, to the digest of an attacker's issue request.
   - `clientDataJSON` carries only `type`, `challenge`, `origin`, `crossOrigin` and `topOrigin`. No field separates "web login" from "approve this request", and WebAuthn has no transaction confirmation.
   - So a compromised server can get a signer-acceptable assertion whenever the user touches their authenticator at the origin.
   - The defences are visibility (every issuance logged with user, roles and key fingerprint; Phase 4 witnesses) and the D-08 bounds.
   - [ASSUMED] A native CTAP client could close this gap, because it can set an origin a browser cannot produce, such as `keyroster-cli:`. Record it with the deferred "Native CTAP2" idea.

**Recommended shape (honours locked D-12):**
- **Login begin.** The CLI POSTs `/api/v1/login/begin` with:
  - the request signing bytes;
  - `code_challenge` (S256) and `state`;
  - `redirect_port`, used only to build `http://127.0.0.1:<port>/callback`;

  The server stores the login session and returns `login_id` and the approval URL.
- **Approval page** (`GET /login/<login_id>`) shows the fingerprint, principals, TTL and expiry countdown, then calls `navigator.credentials.get`:
  - challenge = the request digest;
  - `allowCredentials` = the subject user's bound credential IDs from the installed directory;
  - `userVerification: "required"`.
- **Posting the assertion.** JS POSTs the assertion with `fetch()` to `/api/v1/login/<login_id>/assertion` (same origin).
  - The server pre-verifies it with `internal/webauthn` for good error messages, stores it, and creates a single-use `code` (32 random bytes; only its SHA-256 is stored; 120 s TTL).
  - It returns the loopback URL, and JS does `window.location.assign(loopbackURL)`.
- **Redemption.** The CLI loopback handler checks `state` and the `Host` header, then POSTs `/api/v1/login/<login_id>/redeem` with `{code, code_verifier}`.
  - The server checks `SHA-256(code_verifier) == code_challenge`, the code hash, expiry and single use.
  - Only then does it send `LoginIssueRequest + webauthn-assertion/v1 evidence` to the signer, and it returns the certificate.

*Equivalent alternative, only via owner checkpoint:* the page sends the assertion itself to the loopback (no server-held assertion, no code table), and the CLI submits `{request, assertion}`. The security is the same and there is less server state, but it changes D-12's "code and PKCE verifier" wording.

**Challenge definition.**
- The login uses its own request message (Pattern 4), whose `SigningBytes()` start with its own raw domain tag, proposed as `keyroster/login-request/v1`. This copies the existing pattern, where the admin request's signing bytes start with the raw tag `"keyroster/issue-request/v1"` [VERIFIED: internal/wire/issue.go:13 `const IssueRequestDomain = "keyroster/issue-request/v1"`, :165-170 "SigningBytes returns the domain tag IssueRequestDomain, as raw bytes, followed by every field except Evidence"].
- `challenge = SHA-256(login request SigningBytes())`. That is literally D-12's "SHA-256(domain tag ‖ request signing bytes)".
- Audit verify can re-check the challenge in two ways:
  - The login leaf (Pattern 5) carries the full signing bytes, so audit verify recomputes the hash and compares it with the assertion's challenge.
  - The Phase 1 issue leaf type also stores a digest, `RequestDigest [32]byte` [VERIFIED: internal/tlog/leaf.go:163-171 `IssueBody`]. The same check against that digest would work even without the full request.

### Q3 (D-17): Algorithms and the COSE/CBOR subset

- **RS256 is needed.** Chromium's guidance: "RS256 is necessary for compatibility with Microsoft Windows platform authenticators" and "a Relying Party that uses an algorithm identifier list that omits either of those values will see registration failures" [CITED: chromium.googlesource.com/chromium/src/+/cff8ad5/content/browser/webauth/pub_key_cred_params.md]. go-webauthn ships `CredentialParametersRecommendedL3()` = EdDSA, ES256, RS256 "the minimal set recommended by the specification" [VERIFIED: go-webauthn v0.18.2 `webauthn/registration_credential_parameters.go`].
- **Signer accepts exactly:** `-7` ES256, ECDSA P-256 with SHA-256, signature ASN.1 DER (`ecdsa.VerifyASN1`); `-8` EdDSA, Ed25519 raw 64-byte signature (`ed25519.Verify`); `-257` RS256, RSASSA-PKCS1-v1_5 with SHA-256, signature not ASN.1-wrapped (`rsa.VerifyPKCS1v15`), modulus ≥ 2048 bits [CITED: W3C WebAuthn L3, "Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures"]. Refuse everything else (PS256, ES384, ES512, ML-DSA and so on), and offer only these three in `pubKeyCredParams`.
- **Minimal CBOR subset in the signer: none.**
  - The server extracts the COSE key once at registration (go-webauthn `webauthncose.ParsePublicKey`, then `EC2PublicKeyData.ToECDSA()`, the OKP `XCoord` for Ed25519, or RSA `Modulus` + `ParseRSAPublicKeyDataExponent` [VERIFIED: go-webauthn v0.18.2 `protocol/webauthncose/webauthncose.go`]).
  - It converts the key to **SPKI DER** with `x509.MarshalPKIXPublicKey`. The directory stores `{alg, spki}`, and the signer uses `x509.ParsePKIXPublicKey` plus a type switch matching `alg`.
  - For assertions, the signer requires `authenticatorData` to be exactly 37 bytes, with AT (bit 6) and ED (bit 7) clear, because no extensions are requested. So no CBOR is ever parsed in the signer. This also follows PITFALLS.md Pitfall 13 ("use a maintained library ... rather than hand-rolled CBOR/COSE").
- **Fingerprints:** the registration page, `keyroster user approve` and the directory all show `SHA256:` + base64 (unpadded) of the SPKI DER bytes, the same style as SSH fingerprints. All three compute it over the same bytes.
- **clientDataJSON parsing:**
  - `encoding/json/v2`, which rejects duplicate names and is case-sensitive, is **new in Go 1.27** [CITED: go.dev/doc/go1.27 §"New encoding/json/v2 and encoding/json/jsontext packages"; the go1.26 notes have no such section]. The module's directive is `go 1.26.0` with `toolchain go1.27.1` [VERIFIED: go.mod:3-5], and STACK promises builds on both supported releases, so it cannot be used in the signer without raising the directive.
  - Use `encoding/json` v1 `Decoder.Token()` streaming instead: walk exactly one top-level object; refuse duplicate member names, non-string values for `type`, `challenge`, `origin` and `topOrigin`, and a non-boolean `crossOrigin`; ignore other members, since Chrome deliberately injects `other_keys_can_be_added_here`.
  - Test that the parse refuses invalid UTF-8.
  - This session showed that json/v2 under 1.27.1 refuses duplicates and is case-sensitive, so it is a fine choice once the directive moves to 1.27.

### Q4: How do the RP fields enter the root-signed policy?

**Recommendation: add one pointer field, `WebAuthn *WebAuthnRP` with `json:"webauthn,omitempty"`, appended to `trust.Policy`, and keep namespace `keyroster/policy/v1`.**
- Tested this session with the same strict-decode pattern as `internal/trust/canonical.go`:
  - an installed v1 document without the field still decodes and re-encodes byte-identically;
  - a document with `"webauthn":null` is refused as non-canonical (one encoding per meaning);
  - a document carrying the object round-trips.
- Old binaries refuse new policies (`DisallowUnknownFields`), which fails closed.
- `audit verify` parses both, because both are the same type.
- The signer refuses WebAuthn issuance when `policy.WebAuthn == nil` (`no_webauthn_policy`).
- **A non-pointer field would break the installed v1 policy:** the encoder would emit the zero value, the byte equality in `decodeStrict` would fail, the signer would refuse to start and Phase 1 logs would stop verifying [VERIFIED: internal/trust/canonical.go:33-46 `decodeStrict` requires `bytes.Equal(c, data)`].

**Validation for the new fields:**
- `rp_id` is a lowercase DNS hostname, is not an IP literal (`net.ParseIP` == nil, also with the IPv6 brackets stripped), has no port, and has at least one dot.
- `origins` is a non-empty, sorted, duplicate-free list. Each entry is `https://` + host, optionally `:port`, with host == `rp_id`. No path, no trailing slash, no uppercase. Exact match is what the signer compares.

**Homelab:**
- The change is a policy successor (version 2, `prev` = SHA-256 of policy v1) inside a **bundle successor**, built with `keyroster root sign --prev` and signed by TEST root C or D (D-11).
- The signer must then be restarted, because it refuses with `trust_changed` until restart [VERIFIED: internal/signer/issue.go:209-230].
- Note for KEY-07 bookkeeping: this successor becomes bundle v3, so the owed offline ceremony becomes v4. Tell the owner.

### Q5: Windows ssh-agent (D-15)

**Finding (source read, and the refusal reproduced on Daniel-PC):**
- In upstream Win32-OpenSSH (`PowerShell/openssh-portable`, branch `latestw_all`, file last changed 2025-04-08), `parse_key_constraints` accepts only `SSH_AGENT_CONSTRAIN_EXTENSION`. Any other constraint (lifetime, confirm) hits `default: error("Unknown constraint %d", ctype); return SSH_ERR_FEATURE_UNSUPPORTED;`. `process_add_identity` then answers `SSH_AGENT_FAILURE` [VERIFIED: raw `contrib/win32/win32compat/ssh-agent/keyagent-request.c` lines 264-317, read this session].
- On success it encrypts the private key blob with DPAPI (`convert_blob(...)`) and writes it with `RegSetValueExW` under `SSH_KEYS_ROOT` [VERIFIED: same file lines 319-331], where it persists across reboots [CITED: Win32-OpenSSH issue #1056, open, "keeps added keys across reboots"].
- **Inbox 9.5p2 refuses the lifetime constraint.**
  - Daniel-PC runs `OpenSSH_for_Windows_9.5p2` with the `ssh-agent` service running.
  - A throwaway Ed25519 key made with `C:\Windows\System32\OpenSSH\ssh-keygen.exe` was added with the inbox `ssh-add.exe -t 60`. `SSH_AUTH_SOCK` was unset, so the default pipe `\\.\pipe\openssh-ssh-agent` was used.
  - Output: `Could not add identity "probe": agent refused operation`, exit status 1. `ssh-add -l` then listed 0 entries with the key's comment, so nothing was added.
  - The key files were deleted afterwards. [VERIFIED: probe run this session.]
  - Registry persistence of keys added *without* a constraint is verified from source only; it was not reproduced, to avoid writing to the owner's agent store.

**Consequence:**
- With the inbox agent, D-15 cannot hold on Windows: there is no lifetime constraint, and the key is written to disk (registry).
- The CLI **must never** retry without the constraint after a refusal. That is the OpenSSH bug 1612 pattern of `ssh-add` silently dropping constraints [CITED: lists.mindrot.org openssh-bugs 2009-06 Bug 1612].

**Options for the owner (`checkpoint:decision`, before the Windows plan):**

| Option | Meets D-15 / SC2 | Cost |
|--------|------------------|------|
| A. **keyroster's own in-memory agent on Windows.**<br>`keyroster login` hands the key to a small agent process it starts.<br>That process serves `x/crypto/ssh/agent.NewKeyring()` on a per-user named pipe (go-winio `ListenPipe`, SDDL limited to the user's SID) and exits when its last key expires.<br>The user points `ssh` at it (`IdentityAgent` in `~/.ssh/config` or `SSH_AUTH_SOCK`). | Yes. The x/crypto keyring honours `LifetimeSecs` (`expireKeysLocked`) [VERIFIED: x/crypto v0.57.0 `ssh/agent/keyring.go` lines 116-188], and keys stay in memory. | More code (detached process, pipe ACL). Win32-OpenSSH honouring `IdentityAgent`/`SSH_AUTH_SOCK` with a pipe path is [ASSUMED]: verify on Daniel-PC |
| B. Inbox agent, no constraint, plus cleanup of expired keyroster entries on each run and a `keyroster logout` | No (registry persistence; the key outlives the certificate) | Owner override of D-15 on Windows; must be documented as a residual. Stale entries cause `Too many authentication failures` if not cleaned |
| C. Refuse on Windows unless a lifetime-capable agent answers | Fails closed | AUTH-03 Windows unmet in Phase 2 |

The recommendation is **A**. It is the only option that meets the locked decision and SC2. Its pipe server reuses go-winio, which D-15 already allows.

**Owner decision (2026-10-10): option A.** A2 is probed first, in 02-02 Task 1 (Open Questions Q2).

### Q6: Windows CTAP for non-admin users (research flag)

Closed for Phase 2. The browser does WebAuthn through the Windows WebAuthn API (`webauthn.dll`). Since Windows 10 1903, non-admin processes can reach FIDO devices only through that API [CITED: learn.microsoft.com/en-us/windows/win32/webauthn/-webauthn-portal; corroborated by DSInternals WebAuthn interop docs]. keyroster never touches CTAP, so non-admin users are covered. Native CTAP stays deferred.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Go stdlib `crypto/ecdsa`, `crypto/ed25519`, `crypto/rsa`, `crypto/x509`, `crypto/sha256`, `encoding/json` (v1 Token API), `encoding/base64` | Go 1.26/1.27 | `internal/webauthn` assertion verifier in the signer | No new signer dependency; audited stdlib crypto [VERIFIED: go1.27.1 local] |
| `github.com/go-webauthn/webauthn` | v0.18.2 (latest, 2026-09-19) | Server only: registration ceremony (attestation `none`), COSE key extraction; also a **test oracle** for `internal/webauthn` | Locked in STACK/D-17 [VERIFIED: proxy.golang.org @latest]. go.mod requires `go 1.26.0`, `fxamacker/cbor/v2 v2.9.4`, `golang-jwt/jwt/v5 v5.3.1`, `google/go-tpm v0.9.8`, `google/uuid v1.6.0`, `tinylib/msgp v1.6.4`, `go-viper/mapstructure/v2 v2.5.0`, `go-webauthn/x v0.3.1` [VERIFIED: proxy .mod] |
| `net/http`, `html/template`, `embed`, `crypto/tls`, `log/slog` | stdlib | `keyroster-server` | STACK "Web UI" lock |
| `modernc.org/sqlite` | v1.60.1 (already in go.mod) | Server state DB (separate file from the signer DB) | Already locked and in use [VERIFIED: go.mod] |
| `golang.org/x/crypto/ssh/agent` | v0.57.0 (already) | CLI: add key and cert with `LifetimeSecs`; Windows option A keyring | [VERIFIED: x/crypto v0.57.0 source] |
| `filippo.io/age` (+ `/armor`) | v1.3.2 (already) | KEY-06 software keystore for online CA keys | Already a dependency; root package + armor import neither `os/exec` nor `net/http` [VERIFIED: `go list -deps ./internal/rootceremony` this session] |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/Microsoft/go-winio` | **v0.6.2** (locked; v0.6.3 exists since 2026-10-08) | Windows: dial `\\.\pipe\openssh-ssh-agent`; option A `ListenPipe` | `//go:build windows` files in the CLI only. The root package imports only `golang.org/x/sys/windows` + internal packages, not logrus [VERIFIED: v0.6.2 and v0.6.3 sources]. Stay on v0.6.2; v0.6.3 is two days old and raises its go directive to 1.26 |
| `golang.org/x/time/rate` | v0.16.0 (latest, 2026-08-19) | Server rate limits (login begin, assertion POST, invite, web login) | Locked in STACK [VERIFIED: proxy @latest] |
| `golang.org/x/term` | v0.46.0 (already) | CLI prompts (admin confirmations) | Already in go.mod |
| `golang.org/x/sys/windows` | v0.48.0 (already) | Windows user SID for the pipe ACL (option A), opening a browser | Already in go.mod |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| go-webauthn for registration | Browser `AuthenticatorAttestationResponse.getPublicKey()` (SPKI) + `getAuthenticatorData()`, so no CBOR anywhere | Zero new deps, but [ASSUMED] password-manager extensions and older browsers may not implement these methods; nothing at registration is signed under attestation `none` anyway. Keep it as a fallback idea only |
| CA-root pin set | Leaf SPKI pin | Breaks on every `tailscale cert` renewal (Resolved Q1) |
| `encoding/json` v1 Token parser | `encoding/json/v2` | Needs go directive 1.27 (Resolved Q3) |
| Flags for server config | `BurntSushi/toml` | Flags plus a systemd unit need no new dependency, and the RP comes from the policy, not config. Recommend flags |
| Own `openBrowser` (~20 LOC per OS) | `github.com/pkg/browser` | Not worth a dependency |

**Installation (server and CLI only; nothing new in the signer graph except `internal/*` packages and the age packages for KEY-06):**

```bash
go get github.com/go-webauthn/webauthn@v0.18.2
go get github.com/Microsoft/go-winio@v0.6.2
go get golang.org/x/time@v0.16.0
go mod tidy
bash scripts/dep-firewall.sh       # signer graph must stay clean
bash scripts/capslock-check.sh     # expect new pairs only from age (KEY-06) and new internal packages; review, then --update in the same PR
```

go-webauthn requires `google/go-tpm v0.9.8`. Our go.mod pins `v0.9.9-0.20260124013517-8f8f42cba0de`, which minimal version selection keeps (a pre-release of v0.9.9 sorts above v0.9.8), so the signer's TPM backend is unchanged. Confirm with `go list -m github.com/google/go-tpm` after `go get` [ASSUMED until run].

## Package Legitimacy Audit

The GSD `package-legitimacy` seam supports only npm, PyPI and crates (`Usage: ... --ecosystem <npm|pypi|crates>`), so there is **no seam verdict** for Go modules. The evidence below comes from proxy.golang.org (versions, go.mod) and the GitHub API (age, stars, archived flag), queried this session. Go module downloads are also integrity-checked against sum.golang.org, the Go checksum database.

| Module | Registry | Repo age | Signals | Source Repo | Verdict | Disposition |
|--------|----------|----------|---------|-------------|---------|-------------|
| github.com/go-webauthn/webauthn v0.18.2 | proxy.golang.org | since 2021-12 | 1344 stars, pushed 2026-10-10, BSD-3, not archived | github.com/go-webauthn/webauthn | no seam verdict (Go unsupported) | Approved by **owner lock** (STACK.md, D-17), server only |
| github.com/Microsoft/go-winio v0.6.2 | proxy.golang.org | since 2016-01 | 1084 stars, MIT, Microsoft org | github.com/microsoft/go-winio | no seam verdict | Approved by **owner lock** (STACK.md, D-15), CLI Windows only |
| golang.org/x/time v0.16.0 | proxy.golang.org | Go project | official x/ repo | go.googlesource.com/time | no seam verdict | Approved by **owner lock** (STACK.md supporting libs), server only |
| github.com/fxamacker/cbor/v2 (transitive) | proxy | since 2019-05 | 1093 stars, MIT | github.com/fxamacker/cbor | no seam verdict; not locked | Named in STACK.md as a go-webauthn dep; review in PR |
| github.com/golang-jwt/jwt/v5 (transitive) | proxy | since 2021-05 | 9234 stars, MIT | github.com/golang-jwt/jwt | no seam verdict; not locked | Named in STACK.md as a go-webauthn dep; review in PR |
| github.com/google/uuid (transitive) | proxy | — | already in go.mod (indirect) | github.com/google/uuid | already present | No change |
| github.com/tinylib/msgp (transitive) | proxy | since 2014-09 | 1951 stars, MIT | github.com/tinylib/msgp | no seam verdict; **not locked** | **checkpoint:human-verify** (dependency review) |
| github.com/go-viper/mapstructure/v2 (transitive) | proxy | since 2023-12 | 485 stars, MIT | github.com/go-viper/mapstructure | no seam verdict; **not locked** | **checkpoint:human-verify** |
| github.com/go-webauthn/x (transitive) | proxy | since 2023-02 | **2 stars**; same org as go-webauthn | github.com/go-webauthn/x | no seam verdict; **not locked**; low popularity | **checkpoint:human-verify** |
| github.com/philhofer/fwd, github.com/x448/float16 (transitive) | proxy | 2014 / 2019 | 80 / 100 stars, MIT | github.com/philhofer/fwd, github.com/x448/float16 | no seam verdict; **not locked** | **checkpoint:human-verify** |

Facts in this table (versions, go.mod requirements, repo age, stars, licence) were verified this session via proxy.golang.org and the GitHub API. **Legitimacy** for the three direct modules rests on the owner's stack lock, not on a seam verdict.

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none.
**Planner action:** one `checkpoint:human-verify` task, the owner's dependency review, before the `go get` of go-webauthn lands. It should list the transitive modules nobody locked (`tinylib/msgp`, `go-viper/mapstructure/v2`, `go-webauthn/x`, `philhofer/fwd`, `x448/float16`) together with the `go mod graph` diff. Server-only scope is confirmed by `scripts/dep-firewall.sh` passing unchanged.

## Architecture Patterns

### System Architecture Diagram

```
 ┌──────────── user's machine ────────────┐                 ┌──────────── signer host (Linux) ─────────────────────────┐
 │                                        │                 │                                                          │
 │ keyroster login                        │  HTTPS (pinned  │  keyroster-server (non-root user,                        │
 │  1 ephemeral Ed25519 key (memory)      │  root CA set)   │   member of signer allow-group)                          │
 │  2 GET /api/v1/login/options ──────────┼────────────────►│   reads directory mirror: principals, TTL cap (display)  │
 │  3 build LoginIssueRequest (user,roles,│                 │                                                          │
 │    principals, ttl, reqID, createdAt)  │                 │                                                          │
 │    print fingerprint + principals + TTL│                 │                                                          │
 │  4 POST /login/begin {signing bytes,   │                 │                                                          │
 │    S256(verifier), state, port} ───────┼────────────────►│   store login session (SQLite)                           │
 │  5 listen 127.0.0.1:port; open browser │                 │                                                          │
 │                                        │                 │                                                          │
 │ browser ── GET /login/<id> ────────────┼────────────────►│   approval page: same fingerprint/principals/TTL         │
 │   navigator.credentials.get            │                 │                                                          │
 │   (challenge = request digest,         │                 │                                                          │
 │    allowCredentials, UV required)      │                 │                                                          │
 │   fetch POST assertion ────────────────┼────────────────►│   pre-verify (internal/webauthn), store, mint code       │
 │   location.assign(127.0.0.1:port/cb?   │◄────────────────┼── loopback URL                                           │
 │     code&state)                        │                 │                                                          │
 │ CLI callback: check state, Host        │                 │                                                          │
 │  6 POST /login/<id>/redeem {code,      │                 │   check S256(verifier), code, expiry, single use         │
 │     verifier} ─────────────────────────┼────────────────►│── Unix socket: LoginIssueRequest + webauthn-assert. ──┐  │
 │                                        │                 │                                                       ▼  │
 │                                        │                 │  keyroster-signer (network-less)                         │
 │                                        │                 │   policy (root-signed, RP ID/origins) ─┐                 │
 │                                        │                 │   directory (admin-quorum-signed) ─────┤                 │
 │                                        │                 │   verify assertion: rpIdHash, origin, type, challenge,   │
 │                                        │                 │     UP+UV, credential ∈ user, signature (stdlib)         │
 │                                        │                 │   principals == f(directory,user,roles); ttl ≤ min cap   │
 │                                        │                 │   serial → cert.Build → LOG (request bytes + evidence    │
 │                                        │                 │     + cert) → COMMIT → release                           │
 │  7 verify cert (user CA, key, princ.)  │◄────────────────┼── certificate ◄──────────────────────────────────────────┘
 │  8 ssh-agent ADD key+cert, lifetime    │                 │                                                          │
 │ ssh host ─────────────────────────────►│ sshd: TrustedUserCAKeys + AuthorizedPrincipalsFile (rendered by           │
 └────────────────────────────────────────┘   `keyroster host principals`)                                            │
                                                                                                                       │
 Admin CLI: user add → invite URL │ user approve → fetch pending SPKI, compare fingerprint, sign directory v(n+1)       │
            with SSHSIG (admin key in ssh-agent) → server → signer InstallDirectory (verify quorum, chain, log) ─────────┘
```

### Recommended Project Structure

```
cmd/
├── keyroster/            # CLI: + init, login, user, role, group, host (new files per command group)
│   ├── agent_unix.go     # SSH_AUTH_SOCK dial
│   ├── agent_windows.go  # go-winio pipe dial (+ option A agent, chosen 2026-10-10)
│   └── browser_*.go      # open URL per OS
├── keyroster-server/     # NEW binary (Linux)
└── keyroster-signer/     # + software backend registration, status
internal/
├── webauthn/             # NEW, signer-safe: assertion verify, clientDataJSON Token parser, SPKI fingerprint (stdlib only; fuzzed)
├── directory/            # NEW, signer-safe: canonical Directory, Validate, quorum verify, successor chain, Principals(), RenderPrincipalsFile()
├── keystore/software/    # NEW, signer-safe: age-encrypted online keys (KEY-06)
├── server/               # NEW: HTTP handlers, sessions, login sessions, invites, security headers
│   └── web/              # templates/*.html, static/app.js, static/app.css (embed)
├── serverdb/             # NEW: server SQLite (migrations like signerdb)
├── wire/                 # + new message types
├── signer/               # + evidence dispatch, directory state, status
├── tlog/                 # + leaf kinds directory_install, issue_request
├── cert/                 # + key ID kr2
└── audit/                # + verify directory chain and WebAuthn issuance
```

Add `internal/webauthn`, `internal/directory` and `internal/keystore/software` to the `signer-no-network` depguard file list in `.golangci.yml` (currently `internal/signer`, `keystore`, `cert`, `certprofile`, `serial`, `signerdb`, `wire`, `cmd/keyroster-signer`, `doctor`).

### Pattern 1: The directory document (proposed; names are Claude's discretion)

**What:** a canonical-JSON document, `keyroster/directory/v1` SSHSIG namespace, version-chained like the policy, signed by ≥ `admin_quorum` distinct admins of the policy in force.

```go
// Proposed shape (not in repo yet). Canonical = json.Marshal + "\n", strict decode,
// every list non-null and sorted, like internal/trust (01-06 decision).
type Directory struct {
	Version    uint64      `json:"version"`
	Prev       string      `json:"prev"` // SHA-256 hex of previous canonical directory; all-zero for version 1
	Users      []User      `json:"users"`       // sorted by Name
	Groups     []Group     `json:"groups"`      // sorted by Name
	Roles      []Role      `json:"roles"`       // sorted by Name
	HostGroups []HostGroup `json:"host_groups"` // sorted by Name
}
type User struct {
	Name        string       `json:"name"`   // same charset as cert key ID subject
	Status      string       `json:"status"` // "active" | "disabled"
	Credentials []Credential `json:"credentials"`
}
type Credential struct {
	ID             string `json:"id"`  // base64url (no padding) credential ID
	Alg            int64  `json:"alg"` // -7, -8 or -257 only
	SPKI           string `json:"spki"` // base64 std of SPKI DER
	BackupEligible bool   `json:"backup_eligible"`
	BackedUp       bool   `json:"backed_up"`
}
type Group struct{ Name string `json:"name"`; Members []string `json:"members"` }
type Role struct {
	Name          string   `json:"name"`
	Principals    []string `json:"principals"` // each must pass cert.ValidatePrincipals
	MaxTTLSeconds uint64   `json:"max_ttl_seconds"` // <= user CA profile cap
	Extensions    []string `json:"extensions"` // subset of user CA profile allowed_extensions
	Users         []string `json:"users"`
	Groups        []string `json:"groups"`
}
type HostGroup struct{ Name string `json:"name"`; Accounts []AccountMap `json:"accounts"` }
type AccountMap struct{ Account string `json:"account"`; Roles []string `json:"roles"` }
```

**Validation rules:**
- Every referenced user, group or role exists.
- No credential ID appears twice anywhere.
- SPKI parses and matches `alg` (RSA ≥ 2048).
- Role principals pass `principalRE` `^[a-z0-9][a-z0-9._@:+-]{0,127}$` [VERIFIED: internal/cert/validate.go:37]. `role:<name>` and `u:<user>` both fit.
- The union of a user's principals is ≤ 32 [VERIFIED: internal/cert/validate.go:30 `const MaxPrincipals = 32`].
- Role `MaxTTLSeconds` is ≤ the user CA profile's `max_ttl_seconds`. Check this at install time **and** at issuance, because the policy can change afterwards.
- Windows account names in host groups are lowercase (PITFALLS "AuthorizedPrincipalsFile / Windows username matching").

**Install (signer, online, no restart):** new message `InstallDirectory{directory, sigs}`. Under `s.mu` the signer:
1. strict-parses the directory;
2. checks the version is the installed version + 1 (or 1) and `prev` is the SHA-256 of the installed canonical bytes;
3. counts distinct admin signers with `trust.CountPinnedSigners(doc, sigs, "keyroster/directory/v1", admins)` [VERIFIED: internal/trust/verify.go:23-57 signature] and requires ≥ `admin_quorum`;
4. runs semantic validation against the policy in force;
5. in one transaction, stores the directory and appends a `directory_install` leaf carrying the directory and its signatures, with a checkpoint;
6. swaps the in-memory directory.

Issuance checks inside its transaction that the directory version is still the one it used, like `checkTrustCurrent`.

**On a policy change** (signer restart after install-bundle), re-verify the installed directory's signatures against the **new** admin set. If they no longer meet quorum, the signer starts but refuses login issuance with `directory_not_authorized` until a re-signed version is installed. That is D-01's "signed under the policy in force".

**Admin CLI safety:**
- `keyroster user approve` and the role and group commands fetch the installed directory from the server and **verify its signatures and chain locally** against the admins in the trust bundle. The bundle is verified against the root pins with the existing `trust verify` machinery.
- Only then do they build v(n+1), show a diff, sign with the admin key in ssh-agent (reuse `agentSigner`/`sshsig.Sign`), and upload.
- A server that feeds a fake base cannot get it installed, because `prev` would mismatch. The local check is what makes the diff the admin sees trustworthy.

### Pattern 2: Signer-side `webauthn-assertion/v1` verification

Evidence blob (proposed, cryptobyte, uint16 length-prefixed fields): `credential_id`, `authenticator_data`, `client_data_json`, `signature`. The blob must fit `MaxEvidenceBlob = 8 << 10` [VERIFIED: internal/wire/issue.go:36]. A real assertion is roughly 0.4-1.5 KiB: 37 B authData, ~150-350 B clientDataJSON, up to 512 B RSA signature, and a credential ID of up to 1023 B by spec [ASSUMED sizes; measure with real authenticators].

Order of checks (default deny; each failure is a named refusal detail under `ReasonUnauthorized`):
1. **The message type selects the evidence path** (Pattern 4).
   - `LoginIssueRequest` must carry exactly one `webauthn-assertion/v1` item; anything else is refused (`missing_evidence`, `unknown_evidence_type`, `too_many_evidence`).
   - The Phase 1 `IssueRequest` path is untouched.
2. Request preconditions:
   - `policy.WebAuthn != nil` (`no_webauthn_policy`);
   - a directory is installed and quorum-valid (`directory_not_installed` / `directory_not_authorized`);
   - `CARole == user` (`ca_not_allowed_for_login`);
   - the subject is an active user (`unknown_user`, `user_disabled`);
   - the credential ID is one of that user's (`unknown_credential`).
3. authenticatorData:
   - length exactly 37 (`bad_authenticator_data`);
   - `rpIdHash == SHA-256(policy.WebAuthn.RPID)` (`rp_mismatch`);
   - flags: UP (bit 0) and UV (bit 2) set (`user_presence_missing`, `user_verification_missing`); AT (bit 6) and ED (bit 7) clear.

   [CITED: W3C WebAuthn L3 §6.1 authenticator data: rpIdHash 32 bytes, flags 1 byte (Bit 0 UP, Bit 2 UV, Bit 3 BE, Bit 4 BS, Bit 6 AT, Bit 7 ED), signCount 4 bytes]
4. clientDataJSON (Token parser):
   - `type == "webauthn.get"` (`type_mismatch`);
   - `challenge` decodes as base64url without padding and equals SHA-256 of the login request's signing bytes (`challenge_mismatch`);
   - `origin` is exactly one of `policy.WebAuthn.Origins` (`origin_mismatch`);
   - `crossOrigin` is absent or false and `topOrigin` is absent (`cross_origin_refused`).
5. Signature: verify over `authenticatorData ‖ SHA-256(clientDataJSON)` with the credential's SPKI key per `alg` (`assertion_signature_invalid`).
6. Authorization (D-08):
   - roles = request roles, or all of the user's roles;
   - every named role must belong to the user (`role_not_granted`);
   - `req.Principals` must equal the sorted union exactly (`principals_mismatch` → `ReasonBadPrincipal`);
   - `ValidForSeconds` ≤ min(role TTL) and ≤ the CA cap (`ttl_exceeds_role` → `ReasonTTLExceeded`);
   - `Extensions` ⊆ union(role extensions) (`extension_not_allowed`).
7. Then the existing Phase 1 sequence: duplicate `RequestID`, serial, `cert.Build`, log, commit.

The signcount is ignored (D-05), and BE/BS are not enforced (deferred). The freshness window stays `maxClockSkew = 300 * time.Second` [VERIFIED: internal/signer/issue.go:22], which bounds approve-to-redeem to about 5 minutes minus clock skew.

### Pattern 3: Fingerprint parity (AUTH-04)

- Both sides compute `ssh.FingerprintSHA256(ephemeralPub)` from the request's `SubjectKey`.
- The CLI uses its own key. The approval page is rendered by the server from the stored signing bytes; parse them with `wire` and re-derive the fingerprint, never from a separate field.
- The digest the authenticator signs covers `SubjectKey`, so a server showing a false fingerprint while forwarding a different key gets a signer refusal, because the challenge would not match.
- Show the fingerprint large, with a "only approve if this matches your terminal" line, and show the expiry countdown.

### Pattern 4: Wire protocol additions

Today: `TypeIssueRequest byte = 0x01`, `TypeIssueResponse byte = 0x81`, `TypeError byte = 0xFF`, `MaxFrame = 64 << 10` [VERIFIED: internal/wire/frame.go:19, 24-29].

Proposed:
- `0x02 InstallDirectory` → `0x82` (installed version + leaf index).
- `0x03 GetDirectory` → `0x83` (installed directory + sigs, so the server mirrors exactly what the signer holds).
- `0x04 Status` → `0x84`: custody per role, policy version, `rp_id`, origins, directory version and SHA-256, signer build version.

**Frame size:** a directory can outgrow 64 KiB (each RSA-2048 SPKI alone is about 400 base64 characters). Read the 4-byte length plus the 2-byte version/type header first, then apply a **per-type cap**: issue 64 KiB; directory install and response at most `tlog.MaxDocument = 1 << 20` [VERIFIED: internal/tlog/leaf.go:77]. Keep `ReadFrame` refusing before allocation. With `maxConns = 32` this bounds memory at about 32 MiB.

**A separate login request message (honours D-17: "The Phase 1 `admin-sshsig/v1` issuance path stays as it is").**
- D-08's optional role subset needs a signed field. Adding it to `IssueRequest` would change the admin path's signing bytes.
  - Under the same domain, that would make logged admin signatures ambiguous.
  - With a domain bump, the admin SSHSIG namespace would change too, because `AdminSSHSIGNamespace` equals the domain [VERIFIED: internal/wire/issue.go:23 `const AdminSSHSIGNamespace = IssueRequestDomain`].
  - Both violate the lock.
- So **leave `TypeIssueRequest` (0x01), `IssueRequest` and `keyroster/issue-request/v1` byte-for-byte unchanged**, and add:
  - `0x05 LoginIssueRequest` → `0x81 IssueResponse` (reused), with its own raw domain tag `keyroster/login-request/v1` at the start of its signing bytes.
  - Fields: `SubjectKey`, `Subject` (user), `Roles` (empty means all of the user's roles), `Principals`, `ValidForSeconds`, `RequestID`, `CreatedAt`, `Extensions`, then `Evidence`. The CA role is implicitly `user`, so there is no field for it.
  - Reuse the `wire` limits and the `addBytes16`/`readBytes16` helpers. Strict parsing and a fuzz target are mandatory.
- The login handler accepts **only** `webauthn-assertion/v1` evidence (exactly one item). The admin handler keeps refusing every other evidence type as today (`unknown_evidence_type`) [VERIFIED: internal/signer/evidence.go:41-43]. So a request can never mix the two evidence types: each message type has one evidence path.
- Route both message types through the same `s.db.RequestIDUsed` check and the UNIQUE backstop inside the issuance transaction [VERIFIED: internal/signer/issue.go:87-95], so a login request ID can never replay an admin one.

### Pattern 5: Log and key-ID format changes

- **Leaf kinds** today: `KindIssue Kind = 1` … `KindBundleInstall Kind = 6`, with `valid()` = `k >= KindIssue && k <= KindBundleInstall` and the comment "The set is complete for format v1" [VERIFIED: internal/tlog/leaf.go:36-45, 67].
  - Add `KindDirectoryInstall = 7`, with body `{version, directory, sigs}` up to `MaxDocument`.
  - Add `KindLoginIssue = 8`, the issue leaf for `LoginIssueRequest`. It carries the full login request `SigningBytes` instead of only the digest, plus the directory version, evidence, certificate and key ID. Phase 1 admin issuance keeps writing `KindIssue`.
- **Why log the full request:** today `audit verify` "does not check that an issuance was authorized" because "an issue leaf ... only [has] a SHA-256 digest of the request" [VERIFIED: internal/audit/verify.go:303-310]. With the request bytes, the directory history and the assertion, audit verify can prove for every login certificate that:
  - the user's bound credential signed this exact request (challenge == SHA-256(request bytes));
  - the certificate key == the request `SubjectKey`;
  - the principals == the directory computation;
  - the TTL is within the role cap.

  A compromised signer then cannot log an unauthorized issuance that passes audit, because it cannot forge a user assertion. That serves the core value ("full visibility").
- **Old verifiers:** `audit verify` binaries from Phase 1 will refuse logs with the new kinds (unknown kind). That fails closed and is acceptable; say so in the release note.
- **Key ID:** `ParseKeyID` requires exactly five fields after `kr1/` [VERIFIED: internal/cert/keyid.go:12 format `kr1/ca={ca}/sub={subject}/req={request id}/pol={policy}/ser={serial}`, :48-51].
  - Proposed for WebAuthn issuance: `kr2/ca=user/sub=<user>/req=<32 hex>/pol=<n>/dir=<n>/roles=<r1>+<r2>/ser=<n>`. Role names use `validName` [a-z0-9._-], so `+` is an unambiguous separator.
  - The Phase 1 admin path keeps issuing `kr1`.
  - `ParseKeyID` accepts both, and audit verify checks `pol` and `dir` against the documents in force at that leaf.
  - The key ID must fit `MaxKeyID = 1024` [VERIFIED: internal/tlog/leaf.go:73].

### Pattern 6: KEY-06 software keystore and custody report

- `internal/keystore/software` registers backend `software`, which implements `keystore.Backend` (`Key(role, fingerprint)`, `Close`) and `Provisioner`.
  - The keys are five Ed25519 keys, one armored age file per role (`{state-dir}/software/{role}.age`, scrypt recipient, mode 0600), mirroring the 01-09 root-file format but **without** importing `internal/rootceremony` (its KEY-07 import rule).
  - `Custody()` returns `CustodySoftware` [VERIFIED: internal/keystore/keystore.go:33 `CustodySoftware    Custody = "software"`].
- **Passphrase at `serve`:** read from `$CREDENTIALS_DIRECTORY/keyroster-software-passphrase` (systemd `LoadCredential=`/`LoadCredentialEncrypted=`), from `--passphrase-fd`, or from a TTY. Docs must say that a passphrase stored on the same host makes the key equivalent to plaintext, which is why it is evaluation-only.
- The capslock baseline gains the age and scrypt packages; review them, then `--update` in the same PR.
- **Custody report:** the `Status` response lists each role's custody as recorded at ca-init and re-checked by `openRoleKey` at start [VERIFIED: internal/signer/trust.go:362-380].
  - The server renders the banner from it on every page (`base.html` layout).
  - The CLI prints it to stderr on every server-talking command. The server includes the custody in an `X-Keyroster-Custody` response header or the JSON body, which the CLI reads after TLS verification.
  - `doctor` already has `CodeSoftwareKey           = "software_key"` [VERIFIED: internal/doctor/doctor.go:85].
  - [ASSUMED] A server that lies about custody to the CLI is in scope only for a compromised server, which can do worse. The banner is a UX safeguard for honest deployments.
- **Banner wording.**
  - CONTEXT names `docs/security/custody.md` as the wording source. Today it only says, for `software`: "For online keys: Phase 2 (KEY-06, with loud UI warnings)" [VERIFIED: docs/security/custody.md:19, table row `software`]. There is no banner text to copy yet.
  - The KEY-06 plan must first add a "Software CA keys (KEY-06)" section to custody.md, and the UI and CLI must then quote it verbatim from one Go constant.
  - Proposed text, mirroring the existing `SOFTWARE ROOT` banner style: **"EVALUATION ONLY - SOFTWARE CA KEY: the {roles} CA keys are software keys (custody software). Anyone who copies the key files and their passphrase can issue certificates. Do not use this instance for real access (docs/security/custody.md)."**
  - Owner wording review happens at the plan's checkpoint.

### Anti-Patterns to Avoid
- **Treating a server DB row as authority** (pending credential, "approved" flag): only the installed directory counts (Anti-Pattern 2, ARCHITECTURE.md).
- **Taking the RP ID or origins from server config:** they come from the root-signed policy via signer `Status`. The server only checks at start that its TLS certificate covers the RP hostname.
- **Silently retrying an agent add without the lifetime constraint** (Resolved Q5).
- **Form POST followed by a 302 to `http://127.0.0.1`** (Pitfall 4).
- **`fetch()` to the loopback from the page** (Pitfall 5).
- **Loading the directory only at signer start** (the install-bundle pattern): every user approval would need a restart.
- **CBOR in the signer:** store SPKI DER instead (Resolved Q3).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Attestation object / COSE key parsing at registration | Own CBOR decoder | go-webauthn `FinishRegistration`/`CreateCredential` + `webauthncose.ParsePublicKey` (server only) | CBOR parsers are a classic bug source (PITFALLS Pitfall 13); many authenticator quirks |
| Signature primitives | Any custom crypto | `ecdsa.VerifyASN1`, `ed25519.Verify`, `rsa.VerifyPKCS1v15`, `x509.ParsePKIXPublicKey` | Audited stdlib |
| ssh-agent protocol | Own agent wire code | `x/crypto/ssh/agent` client and `NewKeyring` | Lifetime handling exists and is tested |
| Named pipes on Windows | syscall CreateNamedPipe code | go-winio `DialPipe` / `ListenPipe` with SDDL | Overlapped I/O, `ERROR_PIPE_BUSY` handling |
| CSRF | Tokens in forms | `http.CrossOriginProtection` (Sec-Fetch-Site / Origin) [VERIFIED: `go doc net/http.CrossOriginProtection`, Go 1.27.1] plus SameSite=Strict | Stdlib, no state |
| Rate limiting | Ad-hoc counters | `golang.org/x/time/rate` keyed per IP and per user | Locked in STACK |
| TLS cert reload | Restart the server | `tls.Config.GetCertificate` returning an `atomic.Pointer[tls.Certificate]`, swapped by a reload loop | Stdlib |
| Canonical signed JSON, SSHSIG quorum counting | New helpers | `internal/trust` canonical/decodeStrict pattern, `trust.CountPinnedSigners`, `internal/sshsig` | Already reviewed, fuzzed |
| Principal validation | Second regex | `cert.ValidatePrincipals` | One rule for signer, directory and renderer |

**Key insight:** the only new security-critical parser in the signer is the WebAuthn assertion check (37-byte authData, a clientDataJSON token walk, stdlib signature verification). Moving CBOR to the server at registration time keeps it that small.

## Common Pitfalls

### Pitfall 1: Windows agent drops the lifetime and persists the key
**What goes wrong:** `AddedKey{LifetimeSecs: n}` gets `SSH_AGENT_FAILURE` from the Win32-OpenSSH agent. Code that "falls back" adds the key without a lifetime, and the key then lives DPAPI-encrypted in the registry across reboots.
**How to avoid:** take the owner's decision (Resolved Q5). Never fall back. Add an integration test on the Windows CI runner that runs against the inbox agent, if the runner image has the service, and asserts the refusal.
**Warning signs:** `ssh-add -l` on Windows lists keyroster keys days later; `Too many authentication failures`.

### Pitfall 2: Linux desktop agents and certificates
**What goes wrong:** Ubuntu 26.04 GNOME exports `SSH_AUTH_SOCK` for `gcr-ssh-agent`. Whether that proxy honours lifetime constraints and stores certificates is [ASSUMED] untested (older gnome-keyring famously ignored constraints [CITED: Launchpad bug 209447]).
**How to avoid:**
- After adding, the CLI lists identities and requires the certificate to be present.
- Put "add with 60 s lifetime, check that it is gone after expiry" on the laptop dogfood list.
- Document `ssh-agent` fallback instructions.

### Pitfall 3: CSP blocks the page's own `fetch()`
**What goes wrong:** the STACK CSP has `default-src 'none'` and no `connect-src`, so `fetch('/api/...')` from `app.js` is blocked.
**How to avoid:** add `connect-src 'self'`. Embed WebAuthn options as JSON in a `<script type="application/json" id="opts">` element. A non-executable data block is allowed under `script-src 'self'`, since it is never executed [ASSUMED; verify in Chrome, Edge and Firefox].

### Pitfall 4: `form-action 'self'` blocks the loopback redirect
**What goes wrong:** "Chrome 63 does block redirects after form submission" to destinations outside `form-action` [CITED: MDN/CSP form-action notes and composr tracker #5770]. So POST, then 303 to `http://127.0.0.1:port` fails in Chrome.
**How to avoid:** submit the assertion by `fetch()` and navigate with `window.location.assign(url)`. CSP does not restrict top-level navigation. The server builds the URL only from the stored port: `http://127.0.0.1:<port>/callback?code=…&state=…`. Never take a free-form redirect URI (open redirect).

### Pitfall 5: Chrome Local Network Access
**What goes wrong:** since Chrome 142, requests from public origins to local or loopback addresses need user permission. This covers "requests initiated using the JavaScript fetch() API, subresource loading, and subframe navigation" [CITED: developer.chrome.com/blog/local-network-access, update 2025-09-29]. Top-level navigation is not listed, and Chrome "plan[s] to extend these protections".
**How to avoid:** never `fetch()` or iframe the loopback. Use a top-level navigation only. The CLI also prints the URL. Label every browser not exercised end to end UNVERIFIED (Chrome and Edge exist on Daniel-PC; Firefox is not installed there).

### Pitfall 6: RP ID is the full hostname, forever
**What goes wrong:** `ts.net` is on the Public Suffix List (`ts.net` and `*.c.ts.net`) [VERIFIED: publicsuffix.org list this session], so the registrable domain is `<tailnet>.ts.net`. Using the tailnet domain as the RP ID would let **any** tailnet machine with `tailscale cert` act as RP for these passkeys. Renaming the machine or the tailnet invalidates every passkey. The machine name is published in CT logs [CITED: tailscale.com/kb/1153].
**How to avoid:**
- `rp_id` = the exact FQDN of the server, and origins = `https://<fqdn>` only.
- Put all three facts in the D-09 owner checkpoint.

### Pitfall 7: `tailscale cert` files do not renew themselves
**What goes wrong:** the files on disk change only when `tailscale cert` runs again [CITED: tailscale.com/kb/1153].
**How to avoid:**
- Ship a systemd timer (daily `tailscale cert --cert-file … --key-file …`).
- The server reloads on file change: a ticker every 60 s plus SIGHUP, validating cert/key match, hostname coverage and expiry before swapping, and keeping the last good certificate on failure.
- Log a warning when the remaining validity drops below 14 days.

### Pitfall 8: Clock skew eats the approval window
**What goes wrong:** `CreatedAt` comes from the CLI clock, and the signer allows ±300 s. A laptop 4 minutes off leaves about 1 minute.
**How to avoid:** `login/options` returns the server time. The CLI refuses with "fix your clock" when the skew is above 60 s. The page shows a countdown.

### Pitfall 9: Policy schema change breaks installed state
See Resolved Q4: use only the `omitempty` pointer field. Test that the homelab's installed policy v1 bytes still parse.

### Pitfall 10: Directory TTL vs. later policy change
A role TTL validated at install time can exceed a CA cap that a later policy lowers. Re-check at issuance (min of role TTLs and CA cap).

### Pitfall 11: Required-check ordering for new CI jobs
New Windows and macOS test jobs that become required checks must run green on `main` first, and the owner applies the ruleset from the PR branch (Phase 1 Pitfall 10 / 01-04 decision).

**Deferred CI debt (Discretion item), recommendation:**
- **Pick up `addLogKey` removal** in the e2e plan. It already edits `test/e2e/harness_test.go`, so this is a one-line deletion [VERIFIED: .planning/phases/01-trust-core/deferred-items.md, "Remove it in the next plan that is allowed to edit the harness"].
- **Pick up the capslock `-tags piv` target** in the plan that re-baselines capslock for KEY-06. That plan changes the capslock baseline content anyway.
  - It needs `libpcsclite-dev` in the `capslock` job and a baseline generated on a host with the headers. WSL lacks them; the deferred-items file says so.
  - Because `capslock` is already a required check, the content change must follow Pitfall 10: green on the PR, owner-applied if the ruleset changes.
  - If that host is not available, defer again explicitly. Never ship an un-generated baseline.

### Pitfall 12: Loopback listener hygiene
**How to avoid:**
- Bind `127.0.0.1:0`, not `localhost` (RFC 8252 §8.3: localhost is "NOT RECOMMENDED").
- Accept only `GET /callback` with `Host: 127.0.0.1:<port>`, which defends against DNS rebinding.
- Require state equality in constant time.
- Serve one response with `Cache-Control: no-store` and a "you can close this tab" page.
- Close the listener after the first valid callback or after the timeout [CITED: RFC 8252 §7.3, §8.3].

### Pitfall 13: Enrollment under a compromised server
The registration page and its fingerprint are served by the server. With attestation `none`, nothing at registration is signed. A compromised server can therefore show the user and the admin the fingerprint of an attacker's credential. The out-of-band comparison catches a stolen invite on an honest server, **not** a compromised server. Detection: the user's own first `keyroster login` then fails. Document this as a residual next to Q2's.

## Code Examples

### Signer-side assertion check (skeleton; stdlib only)
```go
// Source: W3C WebAuthn L3 §6.1 (authenticator data), §7.2 (verifying an assertion);
// Go stdlib crypto. Names are proposals.
const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagAT = 1 << 6
	flagED = 1 << 7
)

func VerifyAssertion(cred Credential, rpID string, origins []string, challenge [32]byte,
	authData, clientDataJSON, sig []byte) error {
	if len(authData) != 37 {
		return errBadAuthData
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(authData[:32], rpHash[:]) != 1 {
		return errRPMismatch
	}
	flags := authData[32]
	switch {
	case flags&flagUP == 0:
		return errNoUP
	case flags&flagUV == 0:
		return errNoUV
	case flags&(flagAT|flagED) != 0:
		return errBadAuthData
	}
	cd, err := parseClientData(clientDataJSON) // encoding/json v1 Token walk, duplicate names refused
	if err != nil {
		return err
	}
	if cd.Type != "webauthn.get" { return errType }
	got, err := base64.RawURLEncoding.Strict().DecodeString(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge[:]) != 1 { return errChallenge }
	if !slices.Contains(origins, cd.Origin) { return errOrigin }
	if cd.CrossOrigin || cd.HasTopOrigin { return errCrossOrigin }

	cdHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	pub, err := x509.ParsePKIXPublicKey(cred.SPKIDER)
	if err != nil { return err }
	switch cred.Alg {
	case -7: // ES256
		k, ok := pub.(*ecdsa.PublicKey)
		h := sha256.Sum256(signed)
		if !ok || k.Curve != elliptic.P256() || !ecdsa.VerifyASN1(k, h[:], sig) { return errSig }
	case -8: // EdDSA (Ed25519)
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, signed, sig) { return errSig }
	case -257: // RS256
		k, ok := pub.(*rsa.PublicKey)
		h := sha256.Sum256(signed)
		if !ok || k.N.BitLen() < 2048 || rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) != nil { return errSig }
	default:
		return errAlg
	}
	return nil
}
```

### Test-side "soft authenticator" (CI without a browser)
```go
// Builds what a browser+authenticator would return, for server/signer/e2e tests.
func softAssert(t *testing.T, key ed25519.PrivateKey, rpID, origin string, challenge [32]byte) (authData, cdj, sig []byte) {
	rp := sha256.Sum256([]byte(rpID))
	authData = append(rp[:], 0x05 /* UP|UV */, 0, 0, 0, 0)
	cdj = fmt.Appendf(nil, `{"type":"webauthn.get","challenge":%q,"origin":%q,"crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge[:]), origin)
	h := sha256.Sum256(cdj)
	sig = ed25519.Sign(key, append(append([]byte{}, authData...), h[:]...))
	return
}
```
Use the same helper with ES256 and RS256 keys, and feed every vector to **both** `internal/webauthn` and go-webauthn's assertion validation in a test outside the signer graph (a differential oracle). Mutation cases must each be refused: flip UV, rpIdHash, origin, type, challenge, duplicate `"type"`, `crossOrigin:true`, AT set, a trailing byte on authData, and a wrong alg for the key.

### Agent add with lifetime (CLI)
```go
// Source: golang.org/x/crypto/ssh/agent (AddedKey.LifetimeSecs, client.go:115-117 in v0.57.0)
life := time.Until(time.Unix(int64(cert.ValidBefore), 0))
if life <= 0 || life > 24*time.Hour { return errors.New("certificate validity out of range") }
err := agent.NewClient(conn).Add(agent.AddedKey{
	PrivateKey:   ephemeralPriv, // ed25519.PrivateKey, memory only
	Certificate:  cert,
	LifetimeSecs: uint32(life / time.Second),
	Comment:      cert.KeyId,
})
if err != nil {
	return fmt.Errorf("ssh-agent refused the key with a lifetime constraint (%w); not retrying without it", err)
}
```

### Security headers (server)
```go
// STACK.md "Web UI" CSP plus connect-src 'self' (Pitfall 3).
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
func secure(h http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	return cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("Strict-Transport-Security", "max-age=63072000")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer") // invite tokens in paths must not leak
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	}))
}
```

### TLS reload
```go
var cur atomic.Pointer[tls.Certificate]
cfg := &tls.Config{MinVersion: tls.VersionTLS13,
	GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cur.Load(), nil }}
// reload loop: on SIGHUP or every 60 s, if the mtime changed: tls.LoadX509KeyPair,
// x509 leaf VerifyHostname(rpID), check NotAfter > now; then cur.Store(&c); else keep the old one and log.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Template-match the whole clientDataJSON | Parse it (or L3's limited prefix check); browsers inject random extra keys (`other_keys_can_be_added_here`) | WebAuthn L2/L3 | Parse members; ignore unknown ones |
| `pubKeyCredParams` ES256 only | EdDSA, ES256, RS256 (L3 recommendation; go-webauthn `CredentialParametersRecommendedL3`) | L3 | RS256 needed for Windows Hello |
| Sign-counter clone detection as a hard rule | Counters ignored for synced passkeys (counter 0); BE/BS flags recorded | Passkeys era | D-05 |
| JSON v1 with case-insensitive keys | `encoding/json/v2` strict | Go 1.27 GA | Usable after the go directive moves to 1.27 |
| Loopback from fetch/XHR | Chrome 142 LNA prompts for fetch, subresources and subframes to loopback | Chrome 142 | Use only top-level navigation |

**Deprecated/outdated:**
- `stripe/krl`: archived. Not relevant here.
- Leaf SPKI pinning for short-lived ACME certificates: breaks on rotation (Q1).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Inbox 9.5p2 agent persists keys added *without* a constraint to the registry (the lifetime refusal itself is VERIFIED by the probe) | Resolved Q5 | Affects only how bad option B is; option A avoids the inbox agent entirely |
| A2 | Win32-OpenSSH `ssh` honours `IdentityAgent` / `SSH_AUTH_SOCK` pointing to a named pipe | Q5 option A | Option A unusable without it |
| A3 | `gcr-ssh-agent` (Ubuntu 26.04 GNOME) honours lifetime constraints and certificates | Pitfall 2 | Linux SC2 broken on the laptop unless the user runs plain ssh-agent |
| A4 | Let's Encrypt will move to new roots, so root pins need re-pin support | Q1 | Low: re-pin path exists anyway |
| A5 | Top-level navigation from an https page to `http://127.0.0.1:port` keeps working in Chrome, Edge (and Firefox, Safari) | Pitfall 5 | Login hand-off fails; fallback needed (print and paste is phishable, so avoid it) |
| A6 | Real assertions fit 8 KiB evidence blobs and have authData exactly 37 bytes with ED clear for Windows Hello, YubiKey, iCloud/Google/1Password passkeys | Pattern 2 | Refusals in dogfood; widen to "ED allowed, extensions ignored" only after seeing real data |
| A7 | go-tpm stays at our pseudo-version after `go get go-webauthn` | Standard Stack | Signer TPM backend would change; check `go list -m` |
| A8 | `<script type="application/json">` data blocks are not blocked by `script-src 'self'` | Pitfall 3 | Use a `data-` attribute instead |
| A9 | A native CTAP client could use an origin browsers cannot produce, closing the web-login harvesting gap | Q2 | Affects only the deferred native CTAP idea |
| A10 | Server-reported custody to the CLI is trusted only as UX | Pattern 6 | None beyond the compromised-server case |

## Open Questions (RESOLVED)

These were the owner checkpoints. The owner decided Q1 and Q2 during plan-phase on 2026-10-10; the others needed no owner decision. Each one names the plan and task that carries it out.

1. **D-09 hostname (one-way)** — RESOLVED: the rule is locked. The RP ID is the exact FQDN, set in the root-signed policy together with the allowed origins. IP addresses are refused, the tailnet domain is never used (`ts.net` is a public suffix), and docs and tooling warn that renaming invalidates every passkey and that the name appears in CT logs.
   - The concrete MagicDNS hostname is confirmed by the owner at the `checkpoint:decision` in 02-13 Task 1, before any RP policy is root-signed.
   - What we knew: RP ID = the exact FQDN; `ts.net` is a public suffix; renaming invalidates passkeys; the name is visible in CT logs.
2. **Windows agent (D-15)** — RESOLVED: option A. keyroster runs its own in-memory agent on a per-user named pipe, and the inbox agent is never used for login keys.
   - Assumption A2 (the inbox `ssh` honours a pipe in `IdentityAgent` / `SSH_AUTH_SOCK`) is probed first, in 02-02 Task 1. If the probe fails, the owner decides at a blocking-human checkpoint, with no silent fallback.
   - What we knew: the inbox 9.5p2 agent on Daniel-PC refused `ssh-add -t 60` with "agent refused operation" (probe this session). Upstream source also shows DPAPI registry persistence.
3. **Login request format (D-08 role subset vs D-17 lock)** — RESOLVED without touching the lock: a separate `LoginIssueRequest` message with its own domain (Pattern 4), built in 02-01 Task 1. No owner action was needed.
4. **D-12 shape** — RESOLVED: the server-held assertion plus code plus PKCE, as locked, with minting at redemption (Resolved Q2). Built in 02-12 Task 1; the loopback-assertion alternative is not pursued.
5. **macOS** — RESOLVED as UNVERIFIED (D-16): there is no Mac in the homelab.
   - CI builds and tests the CLI on macOS, and the needs-hardware record labels the browser-and-passkey leg UNVERIFIED (02-02 Task 3).
   - The honest platform record is written in 02-14 Task 5.

Owner checkpoints that stay inside the plans (decided at execution, not open research):
- KEY-06 banner wording: 02-05 Task 2.
- go-webauthn dependency review before install: 02-08 Task 1.
- D-06 principal convention: 02-11 Task 1.
- Bundle v3 / KEY-07 v4 renumbering: 02-13 Task 1, together with the D-09 hostname.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | all | ✓ (Windows and WSL) | go1.27.1 | — |
| WSL Ubuntu (scripts/linux.sh) | Linux tests from Daniel-PC | ✓ | Ubuntu, WSL 2 | CI |
| OpenSSH client (Windows inbox) | Windows login target | ✓ | OpenSSH_for_Windows_9.5p2 | — |
| Windows ssh-agent service | Windows CLI (D-15) | ✓ Running | 9.5p2 | Option A agent |
| Windows sshd | real Windows login target | ✓ Running | 9.5p2 | — |
| OpenSSH in WSL | Linux tooling | ✓ | OpenSSH_9.6p1 (sshd not in PATH) | CI builds sshd (scripts/build-openssh.sh) |
| Chrome, Edge | browser dogfood on Daniel-PC | ✓ | installed | — |
| Firefox | browser coverage | ✗ on Daniel-PC | — | Laptop (Ubuntu) or label UNVERIFIED |
| macOS machine | D-16 macOS login | ✗ | — | UNVERIFIED label, CI build and test only |
| Homelab signer VM, laptop | dogfood | not probed this session (remote) | — | — |
| `gh` | PR flow | ✓ | 2.87.3 | — |

**Missing dependencies with no fallback:** none blocking. macOS end-to-end is impossible, so it is labelled UNVERIFIED.
**Missing dependencies with fallback:** Firefox (laptop), macOS (CI-only).

## Validation Architecture

Skipped: `"nyquist_validation": false` [VERIFIED: .planning/config.json:24]. Testing guidance is in Pitfalls, Code Examples (soft authenticator, differential oracle, mutation cases) and the suggested plan list below.

## Security Domain

`"security_enforcement": true`, `"security_asvs_level": 1`, `"security_block_on": "high"` [VERIFIED: .planning/config.json:48-50].

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | WebAuthn with UV required; no passwords; credential binding only by admin-signed directory; invite single-use, 24 h, 32 random bytes, hash stored |
| V3 Session Management | yes | Opaque 32-byte session ID, SHA-256 stored server-side; `__Host-` cookie, Secure, HttpOnly, SameSite=Strict; 12 h absolute / 1 h idle (recommended); logout deletes server row |
| V4 Access Control | yes | Signer decides principals and TTL (D-08); the web UI shows only the user's own account; admin actions only via CLI with SSHSIG |
| V5 Input Validation | yes | Strict cryptobyte wire decoding; canonical JSON with `DisallowUnknownFields`; clientDataJSON token parser; `cert.ValidatePrincipals`; fuzz every parser |
| V6 Cryptography | yes | Stdlib only; `crypto/rand`; no custom primitives |
| V7 Error handling / logging | yes | Refusals logged with named details (D-14); no request bytes echoed; never log invite tokens, codes or verifiers |
| V8 Data protection | yes | `Cache-Control: no-store`; ephemeral private key never on disk; server DB holds no secrets that grant access |
| V9 Communications | yes | TLS 1.3 minimum, HSTS; CLI root-CA pin set; signer over a Unix socket with peer-credential allowlist |
| V13 API | yes | `CrossOriginProtection` for browser POSTs; JSON APIs with size limits; rate limits per IP and per user |
| V14 Configuration | yes | RP from the signed policy, not config; CSP; systemd hardening for the server unit (separate user, `NoNewPrivileges`, `ProtectSystem=strict`) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Consent phishing of `login` (attacker's key) | Spoofing / Elevation | Fingerprint on both sides; mint at redemption; code delivered only to the browser's loopback (Q2) |
| Compromised server harvests an assertion from any ceremony | Elevation | Inherent to browser WebAuthn; bounded by D-08, logged with full request (Pattern 5); witnesses in Phase 4 |
| Server adds a credential to a user | Elevation | Only admin-quorum-signed directory binds (D-03) |
| Server swaps the RP or origin | Spoofing | Signer checks rpIdHash and origin against the root-signed policy |
| Assertion replay | Replay | Challenge = request digest; `RequestID` single-use; `CreatedAt` ±300 s |
| Authorization code injection or interception | Spoofing | PKCE S256 + state; code single-use, 120 s, stored hashed |
| CSRF on the web UI | Tampering | `CrossOriginProtection` + SameSite=Strict |
| XSS | Tampering | `html/template` auto-escaping, no inline script, strict CSP |
| DNS rebinding against the loopback listener | Spoofing | Host header check, state check |
| Open redirect | Spoofing | Loopback URL built only from the stored port |
| Brute force or enumeration of invites, logins | DoS / Info disclosure | x/time/rate; uniform errors |
| Directory rollback or fork | Tampering | Version + prev hash; signer refuses non-successors; logged |
| Downgrade to the admin-sshsig path | Elevation | Evidence types cannot be mixed; admin path needs admin keys only |
| Software CA key hidden from users | Repudiation | Custody from the signer, banner on every page and command (D-18) |

## Suggested Plan Decomposition (for the planner; coarse granularity)

1. **Shared signer-safe libraries:**
   - `internal/webauthn`: verifier, Token parser, fingerprint, fuzz targets, soft authenticator, go-webauthn differential test;
   - `internal/directory`: schema, canonical form, validation, quorum, successor, principals, renderer, fuzz;
   - depguard list update.
2. **Policy RP field + homelab policy successor tooling** (`root genesis-policy` / successor policy editing), plus the D-09 checkpoint.
3. **Signer:**
   - wire: new `LoginIssueRequest` (own domain, roles) and the directory and status message types, with per-type frame caps; `IssueRequest` unchanged;
   - evidence dispatch and the WebAuthn issuance path;
   - online directory install and fetch;
   - status/custody;
   - leaf kinds 7 and 8;
   - key ID kr2;
   - refusal details;
   - `audit verify` support;
   - capslock and dep-firewall re-baseline.
4. **KEY-06 software keystore backend** + doctor + docs/security/custody.md update.
5. **`keyroster-server` core:**
   - flags, TLS reload, SQLite state, signer client additions;
   - security headers, templates, embed, banner;
   - invites and registration (go-webauthn), web login sessions, account page;
   - systemd unit.
6. **Login API + approval page + CLI `init`/`login`** (pin set, loopback, PKCE, browser opener, cert verification, agent add), Linux and macOS agent.
7. **Admin CLI:** `user add/approve/list/disable`, `group`, `role`, `host principals`, directory diff, sign and upload.
8. **Windows:** go-winio agent dial, the chosen Q5 option, and Windows plus macOS CI test jobs (owner applies the ruleset).
9. **e2e in CI:** soft authenticator through the server and signer to real sshd (9.5p1 and latest), with a refusal case plus a succeeding control for every SC4 refusal.
10. **Dogfood (human):**
    - homelab policy successor (bundle v3, TEST root C or D);
    - server install, `tailscale cert` timer;
    - enroll the owner as the first admin-user (D-04);
    - log in from the laptop (Linux) and Daniel-PC (Windows) with Chrome, Edge and Firefox, using whatever authenticators the owner has (any one suffices; hardware optional);
    - UNVERIFIED list for the rest.

## Sources

### Primary (HIGH confidence)
- Repository code read this session: `internal/wire/issue.go`, `internal/wire/frame.go`, `internal/signer/{issue,evidence,signer,trust,server}.go`, `internal/signerclient/client.go`, `internal/trust/{policy,canonical,successor,verify}.go`, `internal/cert/{keyid,validate}.go`, `internal/certprofile/certprofile.go`, `internal/tlog/leaf.go`, `internal/audit/verify.go`, `internal/keystore/{keystore,registry}.go`, `internal/doctor/doctor.go`, `cmd/keyroster/{commands,root,ca}.go`, `scripts/dep-firewall.sh`, `scripts/capslock-check.sh`, `.golangci.yml`, `go.mod`, `.planning/config.json`
- Local experiments (Go 1.27.1): json/v2 strictness; `omitempty` pointer round-trip under the strict-decode pattern; `go list -deps` for signer and rootceremony (age has no os/exec)
- proxy.golang.org: go-webauthn v0.18.2 (@latest, .mod), go-winio v0.6.2 / v0.6.3 (.mod, sources), x/time v0.16.0
- go-webauthn v0.18.2 source (module cache): `webauthn/types.go` Config, `registration_credential_parameters.go`, `protocol/webauthncose/webauthncose.go`
- x/crypto v0.57.0 source: `ssh/agent/keyring.go` (lifetime expiry), `ssh/agent/client.go` (AddedKey)
- github.com/tailscale/tailscale `feature/acme/cert.go` (raw, main branch)
- github.com/PowerShell/openssh-portable `latestw_all` `contrib/win32/win32compat/ssh-agent/keyagent-request.c` (raw)
- publicsuffix.org `public_suffix_list.dat` (ts.net entries)
- go.dev/doc/go1.27 (json/v2 GA), go.dev/doc/go1.26 (no json/v2)
- `go doc net/http.CrossOriginProtection`, `go doc crypto/tls.Config.GetCertificate` (Go 1.27.1)

### Secondary (MEDIUM confidence)
- W3C WebAuthn Level 3 (w3.org/TR/webauthn-3): authenticator data layout and flags, §7.2 assertion verification, limited verification algorithm, signature formats, RP ID rules (read via a summarizing fetch; key facts consistent with prior knowledge)
- RFC 8252 §7.3, §8.1, §8.3 (rfc-editor.org)
- Chromium `pub_key_cred_params.md` (RS256 for Windows platform authenticators)
- developer.chrome.com/blog/local-network-access (Chrome 142 LNA scope)
- tailscale.com/kb/1153/enabling-https (renewal responsibility, CT exposure, name format)
- learn.microsoft.com WebAuthn API portal (webauthn.dll, Windows 10 1903)
- Win32-OpenSSH issues #1056 (open; registry persistence) and #1510
- MDN CSP `form-action` and related trackers (Chrome blocks post-submission redirects)

### Tertiary (LOW confidence)
- gnome-keyring / gcr-ssh-agent constraint behaviour (Launchpad bug 209447, GNOME discourse), to be tested on the laptop
- Let's Encrypt root transition timing (training knowledge)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH. Versions checked against the proxy this session; only server and CLI gain dependencies.
- Architecture: HIGH for signer and log integration (read from code). MEDIUM for the server and login shape (standards-based, not yet built).
- Pitfalls: HIGH for Windows agent, Tailscale key rotation, PSL and policy canonical form (verified from source or experiment). MEDIUM for browser CSP and LNA behaviour (docs; needs real browsers).

**Research date:** 2026-10-10
**Valid until:** 2026-11-10 for the stack and browser behaviour (fast-moving: Chrome LNA, go-webauthn releases); the in-repo findings hold until the code changes.
