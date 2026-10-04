# Feature Research

**Domain:** Self-hosted, security-first SSH certificate authority and access manager for teams (no proxy, stock OpenSSH)
**Researched:** 2026-10-04
**Confidence:** MEDIUM-HIGH overall. HIGH for OpenSSH mechanics and Teleport/Vault paywall facts (official docs). MEDIUM for Smallstep commercial tiers and Windows OpenSSH edge cases. LOW items are marked inline.

---

## How the Category Divides

Products that solve "who can SSH where" fall into four groups. The project's place in that picture determines which features count as table stakes:

| Group | Examples | Model | What users have learned to expect from it |
|-------|----------|-------|----------------------------|
| **Access platforms (proxy in the data path)** | Teleport, Boundary, Cloudflare Access for Infrastructure, Tailscale SSH, JumpServer, Warpgate | Traffic goes through a gateway or a custom sshd | JIT requests, session recording, web terminal, SSO, access graph |
| **CA engines (sign a public key, nothing else)** | step-ca (OSS), Vault/OpenBao SSH secrets engine, BLESS (archived), Uber USSHCA | API that signs keys. Policy is shallow and there is no host-side lifecycle | Short-lived certs, TTL limits, principal allow-lists, extension control |
| **Key managers (authorized_keys distribution)** | Bastillion, SSH KeyBox, Keyper, Venafi/CyberArk SSH Manager, SSH.com UKM | Push plain keys to hosts, or discover them | Key inventory, key distribution, 2FA on the admin UI |
| **Commercial CA + lifecycle** | Smallstep SSH (commercial), Teleport agentless OpenSSH mode | CA plus host enrollment plus IdP sync | Host certs, group-to-principal mapping, user provisioning |

**This project's niche:** a CA engine with a real host-side lifecycle (agent), approvals and a tamper-evident audit log, plus key-manager-style discovery. It has no proxy. The relevant comparison set is step-ca + Smallstep SSH, Vault/OpenBao SSH, and Teleport's agentless-OpenSSH mode, together with the Venafi/Teleport Identity Security discovery features. Users will not expect session recording or a web terminal from a product that says "no proxy" up front. They will expect everything a CA engine does, and they will expect host lifecycle to be automated.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Without these, a team evaluating the tool goes back to step-ca or Teleport.

#### A. Certificate Authority Core

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **User certificate issuance (sign client-generated public key)** | Every competitor does it. It is the basic operation | LOW | Sign only. **Never generate user private keys server-side.** Ed25519 default, ECDSA accepted, RSA ≥3072 accepted only with `rsa-sha2-*` signatures. DSA is gone from OpenSSH 10.0+. HIGH |
| **Short-lived user certs (hours), TTL caps per role** | step-ca, Vault, Teleport, Cloudflare all default to short TTLs. It is the reason to use certs at all | LOW | Role-level `max_ttl`. Allow a small negative clock-skew backdate on `valid_after` (e.g. -5 min), as step-ca does. HIGH |
| **`login` CLI → cert in ssh-agent with matching expiry** | `tsh login`, `step ssh login` and `cloudflared access ssh-gen` all do this. Users expect one command | MEDIUM | Add the key+cert with `ssh-add -t <remaining lifetime>` so the agent drops it when it expires. Must work with Windows OpenSSH agent (named pipe `\\.\pipe\openssh-ssh-agent`), macOS and Linux agents. HIGH |
| **Host certificates + `@cert-authority` known_hosts line** | Removing TOFU is half the value proposition in step-ca/Smallstep/Teleport docs | MEDIUM | Host cert principals = FQDN, short name, IPs. Agent renews well before expiry. CLI writes the `@cert-authority *.example ...` line for users. OpenSSH 10.3 made wildcards valid only in **host** cert principals. HIGH |
| **Cert extensions & critical options per role** | Vault (`allowed_extensions`, `default_extensions`) and Teleport roles expose these | LOW | `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`, `permit-X11-forwarding`, `permit-user-rc`. Critical options `force-command`, `source-address`, `verify-required`. **Secure defaults:** agent/X11 forwarding OFF unless the role grants it. Vault <1.9 shipped permissive defaults, which was a known foot-gun. HIGH |
| **Machine / automation certs (longer-lived)** | Vault, step-ca provisioners and Teleport Machine ID all cover CI/Ansible | MEDIUM | Separate identity type ("bot") with its own credential (enrollment token → bot key) and TTL cap (days, not years). KRL is the emergency brake, per PROJECT.md. HIGH |
| **Meaningful Key ID + unique serial on every cert** | sshd logs `ID <keyid> (serial N) CA ...` on each accepted login, and auditors expect to trace a login back to an issuance | LOW | Key ID = `user:<name>/req:<id>` or similar. Serials must be unique and monotonic (KRL revokes by serial range). HIGH |
| **Revocation via KRL, pushed to hosts** | Vault/step-ca users repeatedly ask for it (step-ca issue #256). step-ca only does *passive* revocation (blocks renewal). Machine certs need an active brake | MEDIUM | KRL supports revoke-by-serial, serial range, key ID, key hash and explicit key. Generate with a native library or `ssh-keygen -k`. **sshd refuses ALL pubkey auth if the RevokedKeys file is unreadable** (man page). The agent must write it atomically and never delete it. sshd re-reads it per connection, so no reload is needed. HIGH |
| **Host-side config automation (TrustedUserCAKeys, RevokedKeys, AuthorizedPrincipalsFile, HostCertificate)** | Smallstep's host tooling and Teleport's `teleport join openssh` do this. Doing it by hand across a fleet is the main pain point | HIGH | Validate with `sshd -t` before reload and roll back on failure. Manage only the lines it owns (drop-in `sshd_config.d/` where supported). Windows has no `Include` in older builds, so edit carefully (see Windows section). HIGH |
| **Principals / role mapping (user/group → login accounts on host sets)** | Vault `allowed_users`, Teleport roles (`logins` + labels), Smallstep groups → principals | MEDIUM | Model: Role = {principals, host selector (labels), max TTL, extensions, requires_approval}. Enforce on the host with `AuthorizedPrincipalsFile` per account, so a cert for principal `deploy` only works where the agent wrote `deploy` into that account's principals file. That gives per-host scoping without a proxy. HIGH |
| **Admin web UI + CLI parity** | Every competitor has a UI. Admins expect overview/issue/revoke/approve | MEDIUM | UI is a client of the same API as the CLI. No UI-only operations. MEDIUM |
| **MFA on login (TOTP minimum, WebAuthn preferred)** | Teleport per-session MFA (free tier), Tailscale check mode, Bastillion 2FA | MEDIUM | PROJECT.md makes MFA mandatory and WebAuthn first-class. Good choice. HIGH |
| **Audit log of issuance, revocation, admin actions; export** | Teleport CE exports to SIEM. Smallstep commercial sells "event activity logging". Auditors require it | MEDIUM | JSON lines plus syslog/file export. The tamper-evident part is a differentiator (below). The log itself is table stakes. HIGH |
| **Overview: active certs, expiry, hosts, principals** | Smallstep and Teleport UIs. Core Value is "who has access to what" | MEDIUM | Derived from the issuance DB plus agent heartbeats. MEDIUM |
| **CA key rotation without fleet outage** | Teleport has a 5-phase rotation (standby → init → update_clients → update_servers → standby, plus rollback). Vault/step-ca leave it to you, and users complain | HIGH | OpenSSH supports multiple keys in `TrustedUserCAKeys` and multiple `@cert-authority` lines, so rotation is: (1) publish new CA as trusted everywhere, (2) wait for agent convergence and confirm via heartbeats, (3) sign with new, (4) after max TTL, remove old. Host CA rotation is the same on the client side. Needs agent convergence tracking. HIGH |
| **Host enrollment without TOFU (one-time join token)** | Teleport join tokens, step-ca provisioners (JWK/X5C/cloud IID/SSHPOP) | MEDIUM | Single-use, short-TTL token, bound to an expected hostname. The agent generates its own identity key, which never leaves the host. HIGH |
| **Break-glass / emergency access path** | Every serious deployment asks "what if the CA is down/compromised?" Teleport docs recommend local fallback users | MEDIUM | See dedicated section below. Documented procedure plus tooling. Must be audited. HIGH |
| **Backup/restore of CA state + DB** | Ops expectation. step-ca docs cover it | LOW-MEDIUM | Restore must not let you resurrect revoked serials (keep the serial counter monotonic). MEDIUM |

#### B. Windows OpenSSH (Table Stakes, because PROJECT.md lists Windows as a target)

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Agent manages `C:\ProgramData\ssh\sshd_config` + CA/KRL/principals files with correct ACLs** | Windows sshd refuses files with loose ACLs. That is the No. 1 Windows SSH support issue | MEDIUM | ACL = SYSTEM + Administrators only (same rule as `administrators_authorized_keys`). Restart via the `sshd` service. HIGH |
| **Handle the `Match Group administrators` block** | Default Windows sshd_config redirects admins' `AuthorizedKeysFile` to `__PROGRAMDATA__/ssh/administrators_authorized_keys` | MEDIUM | Certificate auth via `TrustedUserCAKeys` is global and unaffected. **Inventory must read this file for admin accounts, not `~\.ssh\authorized_keys`.** Dogfooding environment (Daniel-PC) is exactly this case. HIGH |
| **Version awareness** | Inbox Windows OpenSSH lags upstream badly | LOW | **Verified locally:** Windows 11 build 26200 ships `OpenSSH_for_Windows_9.5p2`. Win32-OpenSSH GitHub is at 10.0p2-Preview. So features like multiple `RevokedKeys` files (10.3) are **not** available on Windows. Use one KRL file. The agent should report sshd version and gate features on it. HIGH |
| **Principal naming for local vs domain accounts** | Domain users log in as `user@domain` / `DOMAIN\user`, and cert principals must match what sshd resolves | MEDIUM | Historic `AuthorizedPrincipalsFile` matching bug (#1224, fixed). Domain-account caveats before v7.7. Case-sensitivity of principal matching on Windows is **LOW confidence** and needs a spike. |
| **Windows Event Log as auth log source** | Usage correlation (differentiator below) needs it | MEDIUM | `OpenSSH/Operational` channel. MEDIUM |
| **FIDO `verify-required` on Windows** | Known Win32-OpenSSH issue #2156 (login fails with `verify-required`) | LOW | Don't enforce `verify-required` on Windows targets until verified. MEDIUM |

---

### Differentiators (Competitive Advantage)

These follow from the Core Value ("full visibility, revoke immediately") and the "fully open" positioning. Several are paid-only in competitors (see Paywall table).

#### C. Inventory and Discovery (the main differentiator)

The only comparable features are **Teleport Identity Security SSH Key Scanning (Enterprise + Identity Security add-on, requires Device Trust)** and **Venafi/CyberArk SSH Manager (enterprise PKI suite)**. No free, self-hosted tool combines discovery with a CA. HIGH confidence on the competitive gap.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Enumerate authorized keys per account per host** | Shows the access that bypasses the CA, which is the "visibility" promise | MEDIUM | Resolve the **effective** `AuthorizedKeysFile` per user with `sshd -T -C user=<u>,host=,addr=` instead of assuming `~/.ssh/authorized_keys`. Include `authorized_keys2`, root, service accounts, Windows `administrators_authorized_keys`, and LDAP/NSS users that have a home dir. Send fingerprints + metadata only, never full files (Teleport does the same). HIGH |
| **Classify keys: weak / old / unknown / duplicated** | Turns a raw list into findings | MEDIUM | Weak: DSA, RSA <2048 (<3072 warn), `ssh-rsa`-only. Old: file mtime / first-seen date. Unknown: fingerprint not registered to any known user. Duplicated: same key on many hosts/accounts (shared key). MEDIUM |
| **Detect rogue CA trust (backdoor detection)** | An attacker who adds a `cert-authority` line in authorized_keys, an extra `TrustedUserCAKeys` key, or an `AuthorizedKeysCommand` gets persistent access that a key-only scan misses | MEDIUM | Flag: `cert-authority` options in authorized_keys, CA keys in `TrustedUserCAKeys` that aren't ours, unexpected `AuthorizedKeysCommand`/`AuthorizedPrincipalsCommand`, `PermitUserEnvironment`, `command=`/`from=` options. Competitors do not market this. Strong security story. MEDIUM (originality claim) |
| **Key last-used correlation from sshd auth logs** | Separates keys that are in use from dead keys ("never used in 90 days → safe to remove later") | MEDIUM-HIGH | sshd logs `Accepted publickey for U from IP port P ssh2: ED25519 SHA256:<fp>`, and for certs `ID <keyid> (serial N) CA <type> <fp>`. Agent tails journald/auth.log/Windows Event Log and reports (fingerprint, account, timestamp). It also confirms which issued certs were actually used. Fits "visibility" without a proxy. MEDIUM |
| **sshd posture report** | Cheap, high value: PasswordAuthentication, PermitRootLogin, KbdInteractive, weak algorithms, missing RevokedKeys | LOW | Read from `sshd -T`. Report only. MEDIUM |
| **Host key inventory** | Weak/duplicated host keys (cloned VMs share host keys) undermine host certs | LOW | Agent reports host key fingerprints. Duplicates across hosts mean the VM template was cloned. MEDIUM |
| **Drift detection** | Someone edited sshd_config or added a key after the last scan | LOW-MEDIUM | Diff against last report, emit audit event. MEDIUM |
| **Private key discovery on servers (optional, off by default)** | Unencrypted `id_*` files on servers are lateral-movement fuel | MEDIUM | Report path hash + fingerprint + "encrypted?" flag only. Off by default for privacy/attack-surface reasons. Teleport scans laptops. This project should scan servers only in v1. MEDIUM |

#### D. Governance and Integrity

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Two-person approval for sensitive roles (JIT, time-boxed)** | Teleport CE has CLI-only requests and **no approval rules**. Full JIT and dual authorization are Enterprise. Vault Control Groups are Enterprise. Free here | HIGH | Request → approver(s) ≠ requester → cert with TTL ≤ approved window. Approval is bound to (requester, role, max duration, reason) and is single-use. Requester cannot approve. Approver set is configurable (N of M). HIGH (competitor facts) |
| **Two-person rule for admin actions** (role changes, CA config, adding trusted CA, disabling audit export) | Covers the malicious-insider threat model: "no single admin can grant themselves access unobserved". Teleport "dual authorization / MFA for admin actions" is Enterprise-only | HIGH | Same approval engine as JIT, applied to config mutations. Pending changes are visible to all admins. Break-glass bypass is possible only through the sealed emergency path (audited loudly). HIGH |
| **Tamper-evident audit log (hash chain + signed checkpoints)** | Competitors log, but none advertise cryptographic tamper evidence for SSH issuance. Addresses the compromised-server threat | MEDIUM-HIGH | Each entry contains hash(prev). Periodic checkpoints are signed with a key distinct from the CA key. **External anchoring** (push checkpoint hashes to agents, syslog, or a second machine) is what makes truncation detectable, because a hash chain alone can be rewritten by whoever holds the DB. Ship a `verify` CLI. MEDIUM |
| **Issuance transparency for users** ("certs issued in your name") | A user sees every cert issued for their identity, which detects a CA operator misusing it | LOW-MEDIUM | Cheap once the audit log exists. Similar in spirit to Certificate Transparency monitoring. LOW (novelty) |
| **CA key in hardware (PKCS#11/YubiKey/TPM) or offline-root model, free** | Teleport HSM/KMS for CA keys is **Enterprise-only**. Vault managed keys/HSM seal is Enterprise. Free and first-class here | HIGH | Storage model chosen in STACK/ARCHITECTURE research. Feature-wise: signing never exposes key material, and the key cannot be exported via UI/API (see anti-features). HIGH (competitor facts) |
| **Require hardware-backed user keys (`sk-ssh-ed25519`) for privileged roles** | Teleport hardware key enforcement is Enterprise-only | MEDIUM | Role flag: only sign `sk-*` public keys. Optionally add `verify-required` (not on Windows targets yet). OpenSSH 10.3 completed FIDO/webauthn signature handling for certs. MEDIUM |
| **Usage-confirmed revocation status** | "Revoked at T, KRL applied on 47/48 hosts, host X stale since T-2h" makes "revoke immediately" provable | MEDIUM | Agents report KRL version/hash in their heartbeat. The UI shows convergence. Unique among CA engines. MEDIUM |
| **One binary per role, up in minutes** | step-ca is simple but lacks lifecycle. Teleport/Vault are heavy | MEDIUM | This is a product property, not a feature. It constrains every other feature. HIGH |

#### E. Break-Glass / Emergency Access

There is no consensus pattern in the market. Teleport recommends local users, and Vault/step-ca say nothing. Having a designed answer is a differentiator.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Offline emergency CA or pre-issued sealed break-glass cert** | Access survives CA server outage or compromise | MEDIUM | Option A: a separate break-glass CA key held offline (HW token in a safe) whose pubkey the agent always deploys, with principals limited to an emergency account and use alerting. Option B: pre-signed cert in an envelope (worse, because it is long-lived). **Recommend A.** MEDIUM |
| **Break-glass usage alerting** | Using break-glass must be loud | LOW | Agent detects login by the break-glass CA (via log correlation) → high-severity audit event + notification. Depends on log correlation. MEDIUM |
| **KRL fail-safe** | A corrupt/missing KRL locks everyone out (sshd refuses all pubkey auth) | LOW | Agent keeps the last-good KRL, writes atomically, and refuses to install an older KRL version (rollback protection). HIGH |
| **Emergency "revoke everything from CA X"** | Response to CA compromise | MEDIUM | Remove the CA from `TrustedUserCAKeys` fleet-wide (faster and stronger than KRL) plus a KRL entry for the CA key itself. Combined with rotation. HIGH |

---

### Anti-Features (Commonly Requested, Often Problematic)

Each item adds attack surface or conflicts with "no proxy, stock OpenSSH, small auditable codebase".

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **Session recording / command logging** | Teleport, Cloudflare and Tailscale all have it, and compliance checklists ask for it | Requires a proxy or custom sshd, which puts the project in the data path. Tailscale itself is deprecating its tsrecorder recording in favor of a paid PAM product. Already Out of Scope | Login-level audit (who, which cert, which host, when) via log correlation. Point users to `auditd`/`tlog` for host-side command auditing |
| **Web terminal / browser SSH** (Bastillion, Teleport, Cloudflare) | Convenient, works from anywhere | A web shell on the CA server is the highest-value target in the system. Adds terminal emulation, websockets, CSRF/XSS exposure | CLI `login` + native ssh |
| **Server-side generation of user key pairs** (Vault dynamic keys / "give me a keypair") | Easier onboarding | Private keys transit and briefly live on the server, which breaks the threat model. Vault deprecated its dynamic-key mode | Client generates the key (or uses FIDO). CA only signs public keys |
| **Long-lived or non-expiring user certs** | "Users hate re-logging in" | Defeats short-lived certs. Makes KRL mandatory for humans | Hours-long TTL plus fast WebAuthn re-login. Hard cap on human TTL (e.g. ≤24h), enforced in code |
| **Wildcard / empty principals in user certs** | "Let admins log in as anything" | OpenSSH 10.3 changed semantics (empty = never matches, no wildcards in user certs). Older sshd treated empty principals as "any". Dangerous across versions | Always ≥1 explicit principal. Reject empty principal lists at signing |
| **CA private key export / download in UI or API** | Backup convenience | One API bug or stolen admin session leaks the CA | Backup via HW token duplication / offline ceremony, documented. No code path returns key material |
| **Automatic removal/rewrite of authorized_keys (v1)** | "You found the bad keys, just delete them" | Locks people and automation out. A bug becomes a fleet-wide outage. Already deferred in PROJECT.md | Report + export a remediation list. Migration tooling in a later milestone, with approval + dry-run |
| **Remote command execution via host agent** ("run on all hosts", ad-hoc scripts) | Agents are already on every host, so it is tempting | Turns the agent fleet into a botnet-in-waiting if the server is compromised. Contradicts the "compromised CA server" threat model | Agent has a closed set of verbs (write CA/KRL/principals/host cert, reload sshd, report). No shell, no plugins |
| **Agent accepts inbound connections** | Push is "faster" | Opens a listening port on every host | Agent pulls/long-polls over outbound TLS. Push latency is achieved with long-poll, not listeners |
| **Online revocation check by sshd calling the CA** (AuthorizedPrincipalsCommand → CA API) | "Real-time revocation" | Makes the CA a login dependency (outage = lockout). Adds a network path from every sshd to the CA | KRL files distributed by the agent. Short TTLs for humans |
| **Proxy / bastion mode** | Teleport parity | Out of Scope by decision. Doubles the codebase | Native OpenSSH. Users can still use `ProxyJump` themselves |
| **Policy language (Rego/Sentinel/CEL) in v1** | Flexibility | Hard to audit. Policy bugs become access bugs | Declarative roles (principals × host labels × TTL × approval). Revisit after real use |
| **LDAP/AD/SCIM sync in v1** | Enterprise checkbox | Large attack surface. OIDC is already deferred to v2 | Local accounts + WebAuthn. Directory sync after OIDC |
| **Multi-protocol scope (Kubernetes, DB, RDP, HTTP apps)** | Teleport does it | Scope creep that cannot be audited by a team of one plus AI | SSH only |
| **Access graph / AI threat analytics dashboards** | Teleport Identity Security markets it | Heavy, analytics-first. Not needed for "who has access to what" | Plain tables + filters + export (CSV/JSON) |
| **Telemetry / phone-home / license check** | Vendor metrics | Violates self-hosted trust model. Teleport v16 added an honor-system license prompt | None. Zero outbound calls except those the operator configures |
| **Plugin system / webhooks with arbitrary code** | Extensibility | Code-execution surface | Outbound notification webhooks (signed, data-only) at most, and only later |
| **Self-approval or admin override of two-person rule** | "Emergencies" | Breaks the core governance guarantee | Break-glass path, which is separate, offline and loudly audited |

---

## Feature Dependencies

```
CA signing core (user certs)
    ├──requires──> CA key storage model (HW/offline decision)
    ├──requires──> Identity: local accounts + MFA/WebAuthn
    └──requires──> Audit log (every issuance logged from day one)

Roles/principals mapping
    └──requires──> CA signing core
    └──enforced-by──> Host agent writes AuthorizedPrincipalsFile

Host agent (core: enroll + write CA/KRL/principals + sshd -t + reload)
    ├──requires──> Host enrollment (join tokens)
    ├──requires──> Agent↔server mutual auth (agent identity key)
    └──enables──> Host certs, KRL distribution, CA rotation, Inventory, Log correlation

Host certificates ──requires──> Host agent (renewal) + Host CA key
KRL distribution ──requires──> Host agent + monotonic serials + Key IDs
CA key rotation ──requires──> Host agent convergence tracking (heartbeat w/ config hash)
Revocation convergence view ──requires──> KRL distribution + heartbeats

JIT / two-person approval
    ├──requires──> Roles/principals + Identity (distinct approver identities)
    └──requires──> Audit log
Two-person admin actions ──requires──> Approval engine (same as JIT)

Tamper-evident audit (hash chain + signed checkpoints)
    └──enhanced-by──> External anchoring (agents/syslog store checkpoint hashes)

Inventory: authorized_keys scan ──requires──> Host agent
Inventory: "unknown key" classification ──requires──> user↔public-key registry (from CA usage)
Key last-used / cert-usage correlation ──requires──> Host agent log reader (journald / auth.log / Windows Event Log)
Break-glass alerting ──requires──> Log correlation
Break-glass CA ──requires──> Host agent (deploys extra trusted CA) + CA rotation logic (multi-CA trust)

Hardware-backed key enforcement (sk-*) ──enhances──> Roles
Issuance transparency for users ──enhances──> Audit log

Automatic authorized_keys remediation ──conflicts──> v1 "discover+report only" (deferred)
Session recording / web terminal ──conflicts──> No-proxy decision
Online revocation via AuthorizedPrincipalsCommand ──conflicts──> CA-outage resilience
```

### Dependency Notes

- **The host agent unlocks most of the product.** Host certs, KRL distribution, rotation, inventory, log correlation and break-glass all depend on it. Build a minimal agent early (enroll, write files, `sshd -t`, reload, heartbeat), then add verbs one at a time.
- **The audit log must exist before the first cert is issued.** Adding a hash chain to an existing log later means the history before that point cannot be verified. Make it a foundation phase item.
- **Monotonic serials and structured Key IDs are a schema decision made at the first issuance.** KRL by serial range and log correlation both rely on them. Retrofitting them is painful.
- **CA rotation needs convergence tracking.** You cannot safely drop the old CA without knowing every host trusts the new one. Heartbeats must report a hash of the trusted-CA set, the KRL version and the sshd version from the start.
- **The approval engine is shared** by JIT access and two-person admin actions. Build it once and generically: (actor, action, params, approvers, expiry, single-use).
- **"Unknown key" classification needs a user↔key registry.** Without knowing which keys belong to whom, every discovered key is "unknown". Record public-key fingerprints at cert issuance and allow users to register legacy keys.
- **Windows support is a cross-cutting constraint, not a late phase.** File ACLs, the `administrators_authorized_keys` redirect, the 9.5p2 inbox version and Event Log parsing affect agent design. Dogfood on Daniel-PC early.

---

## MVP Definition

### Launch With (v1)

- [ ] CA signing core (user + host CA), Ed25519 default, secure-default extensions. This is the core function
- [ ] CA key protection model (HW token / offline root per STACK decision), with no export path. Threat model: compromised server
- [ ] Local accounts + mandatory WebAuthn (TOTP fallback optional). Identity for issuance and approvals
- [ ] `login` CLI → short-lived cert in ssh-agent with matching agent lifetime. Primary UX
- [ ] Roles: principals × host labels × max TTL × extensions × requires_approval. Authorization
- [ ] Host agent (Linux + Windows): enroll via one-time token, manage TrustedUserCAKeys/RevokedKeys/AuthorizedPrincipalsFile/HostCertificate, `sshd -t` + rollback, heartbeat with config hashes. Enforcement + delivery
- [ ] Host certs with auto-renew + CLI known_hosts `@cert-authority` setup. No TOFU
- [ ] KRL generation + atomic distribution + last-good fallback + rollback protection + convergence view. "Revoke immediately"
- [ ] Machine/bot certs with day-scale TTL caps. Automation
- [ ] Hash-chained audit log with signed checkpoints + `verify` command + JSON/syslog export. Tamper evidence
- [ ] Two-person approval for sensitive roles and for admin config changes (one engine). Insider threat
- [ ] Inventory v1: effective authorized_keys per account (incl. Windows admin file), weak/old/unknown/duplicate classification, rogue-CA-trust detection, sshd posture. Main differentiator
- [ ] Overview UI: certs, expiry, hosts, principals, inventory findings, pending approvals. Visibility
- [ ] CA rotation (multi-CA trust, convergence-gated). Without it, the first key incident is a fleet outage
- [ ] Break-glass: offline emergency CA deployed by agent + documented procedure. Resilience

### Add After Validation (v1.x)

- [ ] Key last-used / cert-usage log correlation (journald, auth.log, Windows Event Log). Trigger: inventory reports are in use and users ask "is this key still used?"
- [ ] Break-glass usage alerting (depends on log correlation)
- [ ] Hardware-backed user key enforcement (`sk-*`, `verify-required` on non-Windows). Trigger: first security-sensitive adopter
- [ ] macOS and FreeBSD agents. Trigger: Linux/Windows agents stable
- [ ] Issuance transparency view for end users
- [ ] Host key inventory + duplicate host key detection
- [ ] Optional server-side private key discovery (off by default)
- [ ] Signed, data-only notification webhooks (approval requests, break-glass use)
- [ ] OPNsense/pfSense support. Trigger: demand. These appliances regenerate sshd_config from their own config.xml, so they need a plugin or a config.xml-aware approach. Needs its own research spike

### Future Consideration (v2+)

- [ ] OIDC/SSO login (WebAuthn still required to sign). Per PROJECT.md
- [ ] Guided authorized_keys → cert migration with dry-run + approval. Per PROJECT.md. Highest-risk automation
- [ ] Directory sync (LDAP/SCIM) after OIDC
- [ ] Terraform provider / declarative config-as-code for roles
- [ ] Network appliances beyond OPNsense/pfSense

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| CA signing core + secure defaults | HIGH | LOW | P1 |
| CA key protection (HW/offline) | HIGH | HIGH | P1 |
| Local accounts + WebAuthn | HIGH | MEDIUM | P1 |
| `login` CLI → ssh-agent | HIGH | MEDIUM | P1 |
| Roles / principals mapping | HIGH | MEDIUM | P1 |
| Host agent core (Linux + Windows) | HIGH | HIGH | P1 |
| Host certs + auto-renew | HIGH | MEDIUM | P1 |
| KRL distribution + fail-safe | HIGH | MEDIUM | P1 |
| Hash-chained audit + verify | HIGH | MEDIUM | P1 |
| Two-person approval (JIT + admin) | HIGH | HIGH | P1 |
| Inventory v1 (authorized_keys, classification, rogue CA) | HIGH | MEDIUM | P1 |
| CA rotation (convergence-gated) | HIGH | HIGH | P1 |
| Break-glass emergency CA | HIGH | MEDIUM | P1 |
| Machine/bot certs | MEDIUM | MEDIUM | P1 |
| Overview UI | HIGH | MEDIUM | P1 |
| Revocation convergence view | MEDIUM | LOW | P1 (falls out of heartbeats) |
| Log correlation (last-used, cert usage) | HIGH | MEDIUM-HIGH | P2 |
| Hardware user key enforcement | MEDIUM | LOW-MEDIUM | P2 |
| Break-glass alerting | MEDIUM | LOW (after correlation) | P2 |
| macOS / FreeBSD agents | MEDIUM | MEDIUM | P2 |
| Issuance transparency for users | MEDIUM | LOW | P2 |
| Host key inventory | MEDIUM | LOW | P2 |
| OPNsense/pfSense | LOW-MEDIUM | HIGH | P3 |
| Notification webhooks | MEDIUM | LOW | P3 |
| OIDC | HIGH (for adoption) | MEDIUM | P3 (v2 by decision) |
| Guided migration | HIGH | HIGH | P3 (v2 by decision) |

---

## Competitor Feature Analysis

### Feature Coverage

| Feature | Teleport | step-ca (OSS) / Smallstep SSH (commercial) | Vault / OpenBao SSH engine | Tailscale SSH / Cloudflare Access | Bastillion / key managers | **Our Approach** |
|---------|----------|------------------------|-----------------------------|-----------------------------------|---------------------------|------------------|
| User certs, short-lived | Yes | Yes | Yes (`ttl`, `allowed_users`) | Tailscale: no certs (own sshd). Cloudflare: yes, **Cloudflare-managed CA** | No (plain keys) | Yes, client-generated keys only |
| Host certs | Yes | Yes | Yes (separate mount) | N/A / partial | No | Yes, agent auto-renew |
| Active revocation (KRL) | Locks (proxy/agent enforced) | **No**, passive only (blocks renewal) | No built-in KRL distribution | Control-plane enforced | Key removal | KRL with convergence tracking |
| Host-side lifecycle | Agent or `join openssh` | Commercial host tooling | None (DIY) | Own daemon | Push keys | Agent with closed verb set |
| Role → principal mapping | Rich roles + labels | Provisioner claims (OSS). IdP groups (commercial) | Per-role `allowed_users` | ACL policy file | Profiles | Roles × host labels, enforced via AuthorizedPrincipalsFile |
| JIT / approvals | **CE: CLI-only, no approval rules. Enterprise: full** | None (OSS) | **Control Groups = Enterprise** | Tailscale check mode = re-auth, not approval | None | Free, two-person, time-boxed |
| Dual authorization for admin actions | **Enterprise only** | No | Control Groups (**Enterprise**) | No | No | Free |
| HSM / KMS for CA key | **Enterprise only** | Yes (OSS supports PKCS#11/KMS) | **Managed keys / HSM seal = Enterprise** (Vault). OpenBao: MPL, PKCS#11 status to verify | Vendor-held | N/A | Free, first-class |
| Hardware user key enforcement | **Enterprise only** | No | No | No | No | Free (v1.x) |
| SSH key discovery / shadow access | **Enterprise + Identity Security add-on + Device Trust** | No | No | No | Venafi/CyberArk: enterprise PKI suite | Free, core feature |
| Audit log | Yes. SIEM export in CE | Commercial only ("event activity logging") | Audit devices (yes) | SaaS logs | Basic | Hash-chained + signed checkpoints + verify |
| Tamper evidence | Not advertised | No | No (audit HMACs fields, no chain) | No | No | Yes |
| CA rotation | 5-phase automated w/ rollback | Manual | Manual (new mount / re-key) | Vendor | N/A | Convergence-gated multi-CA rotation |
| Session recording | Yes (CE) | No | No | Cloudflare yes. Tailscale deprecating tsrecorder for paid PAM | Web shell logs | **No** (anti-feature) |
| Web terminal | Yes | No | No | Cloudflare browser SSH | Yes | **No** (anti-feature) |
| Self-hosted, no vendor dependency | Yes, but CE binaries are commercial-licensed since v16 | Yes (OSS) | Vault BSL. OpenBao MPL | **No** (SaaS control plane) | Yes | Yes, fully open |
| Licence | AGPL source. **CE binaries free only for <100 employees AND <$10M ARR** | Apache-2.0 (OSS) | BSL 1.1 (Vault) / MPL-2.0 (OpenBao) | Proprietary SaaS | Various OSS | Fully open, no tiers |

### Paywall Summary (what competitors charge for that this project gives away)

| Security feature | Who paywalls it | Confidence |
|------------------|-----------------|------------|
| Just-in-time access requests with approval rules | Teleport Enterprise (CE = CLI preview, tctl-only approvals) | HIGH (Teleport feature matrix + docs) |
| Dual authorization / MFA for admin actions | Teleport Enterprise | HIGH |
| Two-person approval of secrets/cert requests | Vault Enterprise (Control Groups) | HIGH |
| HSM/KMS protection of CA keys | Teleport Enterprise. Vault Enterprise (managed keys / HSM seal) | HIGH (Teleport), MEDIUM (Vault specifics) |
| Hardware-backed user key enforcement | Teleport Enterprise | HIGH |
| Device trust | Teleport Enterprise | HIGH |
| SSH key scanning / shadow access discovery | Teleport Enterprise + Identity Security add-on. Venafi/CyberArk | HIGH |
| Access lists and periodic access reviews | Teleport Enterprise | HIGH |
| SSO beyond GitHub (OIDC/SAML) | Teleport Enterprise | HIGH |
| IdP-driven user lifecycle, activity logging/reporting | Smallstep SSH commercial (SSO at Professional+Team tier) | MEDIUM |
| SSH certificate credential injection | Boundary HCP/Enterprise | MEDIUM |
| Commercial use at all (>100 employees or >$10M ARR) | Teleport CE binaries (v16+) | HIGH |

**Positioning implication:** "Approvals, dual authorization, HSM-backed CA, hardware key enforcement and key discovery are free" is a concrete, verifiable message. Each item maps to a line in Teleport's feature matrix.

---

## Specific Topic Notes (requested focus areas)

**User vs host certs.** Use separate CA keys for user and host signing, as Vault does with separate mounts. Then compromise or rotation of one does not affect the other. Host certs are longer-lived (weeks to months, auto-renewed). User certs last hours. Never sign a host cert from the user CA.

**Short-lived issuance flow.** `login` → WebAuthn assertion → server checks role and approval status → signs client public key with TTL = min(role max, approval window) → CLI adds to agent with `-t`. With FIDO user keys (`sk-ssh-ed25519`), the private key never exists on disk.

**KRL distribution.** Agents pull/long-poll a signed, versioned KRL. They reject versions older than the current one, write atomically, and keep last-good. Revoke by serial (certs), by key hash (plain keys), and by CA key (emergency). Windows inbox 9.5p2 accepts only one RevokedKeys file. Multiple files need OpenSSH ≥10.3.

**Principals/role mapping.** Put opaque role principals in certs (e.g. `role-web-admin`) rather than raw account names. The agent writes per-account `AuthorizedPrincipalsFile` entries mapping role principals to local accounts on hosts matching the role's labels. This yields host-scoped authorization with stock sshd. Account-name principals stay supported for simple setups.

**JIT and two-person approval.** Use a single generic approval object. Approvals are bound to parameters and are single-use. The approver must be a distinct identity with fresh WebAuthn. Approvals expire if unused. Every state transition goes into the audit log.

**Tamper-evident audit.** A hash chain alone does not stop a fully compromised server from rewriting the entire chain. Add signed checkpoints and external copies of checkpoint hashes (agents are a natural witness set, since every heartbeat can carry the latest checkpoint hash).

**Discovery/inventory.** See section C. The rogue-CA-trust check and the `sshd -T`-based effective-path resolution set it apart from naive `~/.ssh/authorized_keys` scanners.

**Host agent capabilities.** Closed verb set, no inbound port, outbound mutual-TLS (or equivalent) to the server, minimal privileges where possible (root/SYSTEM is needed to write sshd files), `sshd -t` before every reload, rollback, and a heartbeat carrying sshd version, config hash, trusted-CA hash, KRL version and inventory delta.

**Break-glass.** Offline emergency CA (preferred), agent-deployed. Principals are limited to an emergency account. Usage is detected and alerted. The procedure is documented and rehearsed. Keep a console/password path per host as the last resort; the product documents it but does not manage it.

**CA key rotation.** Multi-CA trust, then convergence gate, then switch signer, then wait max TTL, then remove old. Use the same machinery for emergency CA removal. Model it on Teleport's phases (including rollback) without the proxy-side parts.

**Windows OpenSSH.** See section B. Most important points: the ACL rules, the `administrators_authorized_keys` redirect, inbox version 9.5p2 (verified on Windows 11 build 26200), Event Log for correlation, and the unverified principal case-sensitivity for domain accounts.

---

## Sources

- Teleport Feature Matrix (edition comparison, CE commercial terms): https://goteleport.com/docs/feature-matrix/ (HIGH)
- Teleport CE role access requests (CLI-only, no approval rules in CE): https://goteleport.com/docs/identity-governance/access-requests/oss-role-requests/ (HIGH)
- Teleport JIT access requests: https://goteleport.com/docs/identity-governance/access-requests/ (HIGH)
- Teleport v16 licensing change discussion: https://github.com/gravitational/teleport/discussions/39158 (HIGH)
- Teleport SSH key scanning (Identity Security, Enterprise): https://goteleport.com/docs/identity-security/integrations/ssh-keys-scan/ (HIGH)
- Teleport CA rotation phases: https://goteleport.com/docs/zero-trust-access/management/security/ca-rotation/ (HIGH)
- Smallstep SSH docs (commercial product, tiers): https://smallstep.com/docs/ssh/ (MEDIUM)
- step-ca passive revocation / `step ssh revoke`: https://smallstep.com/docs/step-cli/reference/ssh/revoke/ , https://prof.infra.smallstep.com/docs/step-ca/revocation (HIGH)
- step-ca KRL feature request: https://github.com/smallstep/certificates/issues/256 (MEDIUM)
- Vault signed SSH certificates: https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates (HIGH)
- Vault Control Groups (Enterprise): https://developer.hashicorp.com/vault/docs/enterprise/control-groups (HIGH)
- OpenBao SSH secrets engine: https://openbao.org/docs/secrets/ssh/ (MEDIUM)
- Netflix BLESS (archived): https://github.com/Netflix/bless (HIGH)
- Uber/Netflix/Facebook SSH approaches: https://goteleport.com/blog/how-uber-netflix-facebook-do-ssh/ (MEDIUM)
- Tailscale SSH and check mode: https://tailscale.com/docs/features/tailscale-ssh (HIGH). Session recording deprecation: https://tailscale.com/kb/1246/tailscale-ssh-session-recording (MEDIUM)
- Cloudflare Access for Infrastructure SSH: https://blog.cloudflare.com/intro-access-for-infrastructure-ssh/ (HIGH)
- Boundary SSH cert injection (HCP/Enterprise): https://developer.hashicorp.com/boundary/tutorials/credential-management/hcp-certificate-injection (MEDIUM)
- Venafi/CyberArk SSH key discovery: https://venafi.com/ssh-protect/ (MEDIUM)
- OpenSSH sshd_config(5) (RevokedKeys fail-closed, TrustedUserCAKeys, AuthorizedPrincipals*): https://man.openbsd.org/sshd_config (HIGH)
- OpenSSH 10.3 release notes (principal semantics, multiple RevokedKeys, FIDO cert fixes): https://www.openssh.org/txt/release-10.3 (HIGH)
- OpenSSH PROTOCOL.u2f / verify-required: https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f (HIGH)
- Win32-OpenSSH certificate auth wiki: https://github.com/PowerShell/Win32-OpenSSH/wiki/Certificate-Authentication (MEDIUM)
- Win32-OpenSSH AuthorizedPrincipalsFile bug #1224 (fixed): https://github.com/PowerShell/Win32-OpenSSH/issues/1224 (MEDIUM)
- Win32-OpenSSH verify-required issue #2156: https://github.com/PowerShell/Win32-OpenSSH/issues/2156 (MEDIUM)
- Microsoft OpenSSH server configuration (administrators_authorized_keys): https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration (HIGH)
- Local verification on Daniel-PC (Windows 11 build 26200): `sshd.exe -V` → `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` (HIGH, first-hand)

---
*Feature research for: self-hosted SSH certificate authority & access manager*
*Researched: 2026-10-04*
