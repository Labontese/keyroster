# Pitfalls Research

**Domain:** Self-hosted, security-first SSH certificate authority and access manager (CA + host agent + CLI + web UI, no proxy, stock OpenSSH verifies)
**Researched:** 2026-10-04
**Confidence:** MEDIUM overall (the tier the classify-confidence seam assigns to verified web sources). The core OpenSSH behaviour was checked directly against primary sources: man.openbsd.org `sshd_config(5)`/`ssh-keygen(1)`, the openssh.com release notes up to 10.5 (2026-08-11), draft-miller-ssh-cert-06, the OSV advisory database, vendor GHSA advisories and Microsoft Learn. Claims marked *(LOW)* are from memory or a single secondary source and need checking before they are built on.

**Suggested phase vocabulary used below** (the roadmapper can rename these; the mapping is what matters):

| Tag | Phase meaning |
|-----|---------------|
| P-Threat | Threat model + trust architecture (before any code) |
| P-Core | Certificate issuance core (signing, cert policy, key custody) |
| P-Trust | Host agent + trust distribution (TrustedUserCAKeys, host certs, sshd config) |
| P-KRL | Revocation (KRL build + distribution) |
| P-Ident | Identity: local accounts, WebAuthn, CLI login |
| P-Authz | Roles/principals, approvals, JIT |
| P-Audit | Tamper-evident audit log + reconciliation |
| P-Inv | Inventory (discover + report) |
| P-Plat | Platform ports: Windows, macOS, FreeBSD/OPNsense/pfSense |
| P-Rel | Release engineering, supply chain, self-update |

---

## Critical Pitfalls

### Pitfall 1: "Offline root + online intermediate" doesn't work for SSH certs, so the key-custody decision rests on a false premise

**What goes wrong:**
Teams copy the X.509 pattern: an offline root signs an online intermediate, and hosts trust the root. OpenSSH certificates have **no chain**. `TrustedUserCAKeys` and `@cert-authority` hold a flat list of CA public keys, and draft-miller-ssh-cert says "Implementations MUST NOT accept certificate keys as CA keys." A certificate signed by an "intermediate" certificate is invalid on stock OpenSSH. In software that accepted one anyway, that acceptance was the bug. **Teleport CVE-2025-49825** (CVSS 9.8, fixed in 17.5.2) happened because Teleport's own code accepted an SSH certificate as a signer, and x/crypto/ssh's `IsUserAuthority`/`IsHostAuthority` did the same. User certificates could mint new certificates.

**Why it happens:**
X.509 habits, plus PROJECT.md lists "offline root + online intermediate" as a candidate storage model.

**How to avoid:**
- Decide in P-Threat that the **online signing key is the CA as far as every host is concerned**. An offline key can only sign *trust-configuration artifacts* that your own agent checks: the set of trusted CA public keys, KRLs, principal maps and agent updates. It cannot sign certificates.
- Pre-publish the **next** CA public key next to the current one in `TrustedUserCAKeys` and `@cert-authority`, since both accept several keys. Rotation then means switching which key signs, not a fleet-wide push.
- Never write code that treats a certificate as an authority. If you parse certificates, refuse any `SignatureKey` that is itself a certificate type.

**Warning signs:** design docs that say "intermediate", "chain" or "sub-CA" for SSH. Any code path that calls a verify function with a cert as the CA key.

**Phase to address:** P-Threat (architecture decision), P-Core (enforced in code).

---

### Pitfall 2: The host agent becomes root-on-every-host for whoever owns the server, which makes CA key protection pointless

**What goes wrong:**
The CA private key sits in an HSM, but the host agent runs as root/SYSTEM and accepts whatever the server sends: new `TrustedUserCAKeys` lines, new `AuthorizedPrincipalsFile` contents, sshd config edits, "run inventory script X". An attacker who owns the server never needs the CA key. They push their own CA public key to every host, or map their principal to `root`, and log in everywhere with self-signed certificates. The requirement "CA key protection that holds even if the CA server is compromised" is defeated through the side door.

**Why it happens:**
Convenience. "The agent keeps sshd config in sync" turns into a generic config-push or remote-exec channel.

**How to avoid:**
- Pin trust at enrollment: the agent stores a **trust-root public key** (offline, hardware-backed, ideally held by several people). Any change to the trusted-CA set, the principal maps, or the agent binary must carry a signature from that trust root. The server only relays these artifacts.
- Make the agent protocol **narrow and typed**: fetch KRL, fetch host certificate, fetch signed trust bundle, upload inventory report. No arbitrary commands, no arbitrary file writes, no templated shell.
- The agent writes only a fixed, allowlisted set of paths.

**Warning signs:** an agent API with "exec", "script" or "file" endpoints. A trust bundle that is not signed by a key the server lacks. An agent that accepts a new CA key without a human-signed artifact.

**Phase to address:** P-Threat, P-Trust.

---

### Pitfall 3: Empty or wildcard principals produce "log in as anyone" certificates

**What goes wrong:**
- **Vault CVE-2024-7594** (1.7.7 to 1.17.5): with neither `valid_principals` nor `default_user` set, an authenticated user could get a certificate with an **empty principals list** that authenticated as **any user** on the host. The fix added `allow_empty_principals=false` as the default.
- Older SSH certificate semantics (the pre-draft PROTOCOL.certkeys) said a zero-length principals field means "valid for any principal". x/crypto/ssh's `CertChecker` historically followed that rule (`if len(cert.ValidPrincipals) > 0 { … }`).
- **OpenSSH before 10.3** treated an empty-principals certificate as a wildcard when the CA was trusted via `authorized_keys cert-authority,principals="…"`. 10.3 (2026-04-02) changed this and also stopped treating wildcard characters in *user*-certificate principals as patterns. 10.3 additionally fixed comma-in-principal mis-matching on that same path. The `TrustedUserCAKeys` path was not affected.
- **Windows inbox OpenSSH is 9.5p2** (checked on Daniel-PC), so it has none of the 10.3 fixes, and appliances lag further.

**Why it happens:**
Zero-value structs. A Go `ssh.Certificate{}` has `ValidPrincipals == nil`, and Rust builders have similar defaults. Optional "principals" fields in the API also contribute.

**How to avoid:**
- The CA **refuses to sign** when principals are empty, and also when any principal contains `*`, `?`, `,`, whitespace, control characters or non-printable UTF-8. Enforce this in the signing function itself, not in the API layer.
- Use a cert builder type that cannot be signed unless serial, key ID, principals, validity and extensions are all set explicitly (a typestate/builder pattern with no zero-value signing).
- Add regression tests covering the empty-principals, wildcard and comma cases. Run them against **OpenSSH 9.5 (Windows) and the newest OpenSSH** in CI.

**Warning signs:** a `principals` field that is optional anywhere in the code path. Tests that only check "the certificate verifies", never "the certificate is rejected".

**Phase to address:** P-Core.

---

### Pitfall 4: The default principal model (cert principal = username) grants every host

**What goes wrong:**
Without `AuthorizedPrincipalsFile`, sshd accepts a certificate whenever **the username appears in its principals**. A certificate carrying `root`, `ubuntu` or `admin` then works on **every host that trusts the CA**. "Roles on which hosts" can't be expressed. Each shared account name becomes a global master key.

**Why it happens:**
It's the zero-config path and it works in demos.

**How to avoid:**
- Certificates carry **identity and role principals** (`u:daniel`, `r:db-admin`), never raw account names. Each host maps account to allowed principals with `AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u`. A missing file means deny.
- The host agent writes those files **only from a signed policy artifact** (see Pitfall 2).
- Windows: `AuthorizedPrincipalsCommand` is **not supported** (Microsoft Learn list of unsupported options), so use `AuthorizedPrincipalsFile` there. Note that `AuthorizedPrincipalsFile` is only consulted for CAs in `TrustedUserCAKeys`, not for `cert-authority` lines in authorized_keys.

**Warning signs:** issued certificates contain `root`. Hosts have `TrustedUserCAKeys` but no `AuthorizedPrincipalsFile`.

**Phase to address:** P-Authz (model), P-Trust (deployment).

---

### Pitfall 5: A broken or missing KRL locks everyone out, and a reverted KRL directive silently fails open

**What goes wrong:**
- `sshd_config(5)`: *"if this file is not readable, then public key authentication will be refused for all users."* A truncated download, a wrong ACL on Windows, or a missing file after a partial deploy blocks **all** pubkey logins, including break-glass keys and plain `authorized_keys`.
- The opposite failure: config drift (OPNsense/pfSense regenerating `sshd_config`, an OS upgrade replacing it, cloud-init) removes the `RevokedKeys` line. Revoked machine certificates then work again, and nobody notices.
- OpenSSH **9.4 removed KRL signature verification**; signature sections are ignored. sshd checks no integrity at all.
- KRL **serials are 64-bit and exclude zero** (`ssh-keygen(1)`), and `ssh-keygen`'s default serial *is* zero. A certificate with serial 0 can only be revoked by key ID or by the key itself.

**Why it happens:**
KRL is treated as "just a file we copy", and the failure modes of revocation are never tested.

**How to avoid:**
- Sign the KRL at the application layer (trust root or CA-ops key) and verify it in the agent. Parse and validate it before installing: check the format, a monotonic version number, and that the CA keys are the expected ones. Write a temp file, fsync, then **atomic rename**. Keep the last-known-good copy. Never write an empty file.
- Before reloading sshd, run `sshd -t`, then check the **effective** config with `sshd -T` and confirm `revokedkeys` is set. The agent re-verifies this periodically and raises a high-severity alert if the directive has vanished.
- Serials: generate **random non-zero 64-bit** values, or a DB sequence that is safe across backup/restore. A monotonic counter that rolls back after a DB restore **reuses serials**, so revoking a new certificate also revokes an old one, or post-restore certificates are already "revoked".
- Pruning: entries may only be removed after `valid_before` has passed, computed by the server from issuance records. Pruning early **un-revokes** a certificate.
- Revoke by serial for precision. Revoking by key ID over-revokes if IDs aren't unique.
- Freshness: the agent reports KRL age. Revocation latency = poll interval + propagation, and it should be shown in the UI as an SLO.

**Warning signs:** no test that deletes or corrupts the KRL on a test host. No alert on "KRL older than X". `RevokedKeys` missing from `sshd -T` output on any host.

**Phase to address:** P-KRL (primary), P-Trust (config verification), P-Plat (appliance drift).

---

### Pitfall 6: Locking yourself out of the whole fleet (no break-glass, unsafe sshd reloads)

**What goes wrong:**
A bad trust bundle, a botched CA rotation, a KRL incident, a config that fails `sshd -t`, or the CA being down while short-lived certificates expire. Every host becomes unreachable, including the CA host itself if it is managed by the same system.

**Why it happens:**
Short-lived certificates make the CA a hard availability dependency. Agents restart sshd after writing config. Config ordering surprises (Pitfall 7) are another cause.

**How to avoid:**
- Keep a **break-glass CA** that is separate and offline (hardware tokens in a safe, ideally split across two people). It is trusted on every host for a dedicated break-glass principal. Any login with it triggers an alert, because host agents report the key ID they see in sshd logs.
- The agent **never** deletes existing `authorized_keys` or disables password/console access in v1.
- Apply sshd changes with a **dead-man switch**: validate with `sshd -t`, reload (not restart), then self-test with a loopback login using a test certificate. If that fails, roll back automatically within N seconds.
- Hosts with the CA offline: the user-side CLI can keep working until expiry. Document a runbook for "CA down for 24h".
- Leave the CA server itself out of CA-only access, or give it its own break-glass path.

**Warning signs:** no documented, tested break-glass procedure. The agent restarts sshd instead of reloading it. No automatic rollback.

**Phase to address:** P-Threat (design), P-Trust (implementation), with a tested runbook before any "v1 release" milestone.

---

### Pitfall 7: sshd_config semantics: "first value wins", Include order, and trailing Match blocks swallowing your directives

**What goes wrong:**
- `sshd_config(5)`: for most keywords, **"the first obtained value will be used."** Ubuntu's `sshd_config` starts with `Include /etc/ssh/sshd_config.d/*.conf`. A drop-in named `50-certs.conf` loses to an earlier `10-*.conf` or to cloud-init's `50-cloud-init.conf` for single-valued keywords such as `TrustedUserCAKeys`, `RevokedKeys` and `AuthorizedPrincipalsFile`.
- **Appending to the end of the file**: Windows' default `sshd_config` ends with `Match Group administrators` / `AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`. Anything appended after that line belongs **inside the Match block** and applies only to administrators (or only to non-admins, depending on the block). This is a classic silent misconfiguration on any host with trailing Match blocks.
- `TrustedUserCAKeys`, `RevokedKeys`, `AuthorizedPrincipalsFile` and `CASignatureAlgorithms` are all valid inside `Match`. A pre-existing Match block can therefore override your global settings for some users.

**How to avoid:**
- Write a dedicated drop-in that sorts **first** (`00-sshcm.conf`) where `Include` exists. Where it doesn't (Windows, appliances), insert the directives **before the first `Match` line**.
- Always verify the **effective** config: `sshd -T`, plus `sshd -T -C user=<u>,host=<h>,addr=<a>` for representative users, administrators included. Treat a mismatch as a deploy failure.
- Inventory reports any other `Match` blocks that touch auth keywords.

**Warning signs:** a deploy step that "succeeds" without a check through `sshd -T`. Certificates work for some users on a host but not others.

**Phase to address:** P-Trust, P-Plat.

---

### Pitfall 8: Host certificate principals that don't match what clients type, plus agent-claimed hostnames

**What goes wrong:**
- `ssh` checks the host certificate against the **host name it actually connects to**: the `HostName` after `ssh_config` substitution, or `HostKeyAlias`. Users type `zima`, `zima.tailnet.ts.net`, `192.0.2.10` or a LAN IP. Any name missing from the certificate gets "Certificate invalid: name is not a listed principal". OpenSSH then **falls back to plain host-key checking (TOFU)** by default (9.8 added a way to disable the fallback via `HostKeyAlgorithms`), so users learn to click "yes".
- **IP principals and DHCP**: the zima LAN address has already changed via DHCP. A long-lived host certificate for a reused IP lets the old machine impersonate whatever host now holds that IP.
- **Agent-claimed names**: if the CA signs whatever hostname the agent reports, one compromised host can get a certificate for `db1.example.com` and impersonate any server.
- `@cert-authority *` in clients' `known_hosts` trusts the host CA for **every** name. One mis-issued host certificate then compromises everything.

**How to avoid:**
- The **server** binds host principals to the enrolled host identity, approved at enrollment (admin-approved name set). Agents never supply them.
- Scope client trust: `@cert-authority *.example.com,*.tailnet.ts.net`, not `*`.
- Prefer stable DNS names (MagicDNS, FQDN). Use IP principals only for stable addresses (Tailscale) and keep host certificates short-lived (weeks) with automatic renewal.
- The CLI manages `known_hosts` `@cert-authority` and `@revoked` lines, including the pre-published next host CA.

**Warning signs:** TOFU prompts on enrolled hosts. Host certificate principals sourced from agent requests.

**Phase to address:** P-Trust (enrollment + host certs), P-Ident (CLI known_hosts management).

---

### Pitfall 9: Unsafe defaults for extensions and critical options (agent forwarding, force-command that doesn't restrict)

**What goes wrong:**
- `ssh-keygen` grants `permit-X11-forwarding`, `permit-agent-forwarding`, `permit-port-forwarding`, `permit-pty` and `permit-user-rc` by default, and CAs often copy that. With agent forwarding, a compromised jump host can use the user's agent (and the certificate in it) to reach other hosts while the certificate is valid.
- `force-command` does **not** disable forwarding. OpenSSH 10.0 added a doc warning that "forcing a command doesn't automatically disable forwarding". A `force-command=/usr/bin/backup` certificate that still has `permit-port-forwarding` is a tunnel into the network.
- `source-address` CIDRs break behind NAT, IPv4/IPv6 dual stack and Tailscale (sshd sees `100.x` addresses). When it fails, people "temporarily" drop it.
- Unknown **critical options make OpenSSH reject the certificate** (spec: MUST refuse), while unknown extensions are ignored. Non-OpenSSH verifiers have historically **dropped restrictions**: x/crypto/ssh CVE-2026-39828 (force-command dropped after `PartialSuccessError`), CVE-2026-46595 and CVE-2026-56854 (source-address not enforced on non-pubkey callbacks). A restriction is only as strong as the verifier on that host.
- Spec: critical options and extensions "MUST be ordered lexically by key name". Unsorted or duplicate entries may be rejected or misinterpreted.

**How to avoid:**
- Default to minimal privileges per role: `permit-pty` only. Port and agent forwarding are explicit role grants that show up in the UI and the audit log.
- A role with `force-command` must also have no forwarding extensions. Validate that combination server-side.
- Canonicalise and sort options and extensions in one encoder. Reject duplicates.
- Document that restrictions are guaranteed only on stock OpenSSH. Inventory flags hosts running other SSH servers.

**Warning signs:** a cert profile that copies `ssh-keygen` defaults. A role editor that lets you set force-command without warnings about forwarding.

**Phase to address:** P-Core (encoder + profiles), P-Authz (role validation).

---

### Pitfall 10: Signing and approval checks live outside the signing boundary, so a compromised API or DB can mint certificates

**What goes wrong:**
The web/API tier checks MFA and approvals, writes "approved" rows to the DB, and the signer signs whatever the API asks. Anyone with DB write access or API-process compromise, including a malicious admin, can then mint certificates. Real-world authorization failures in this class:
- **step-ca CVE-2025-44005** (CVSS 10): `UseToken` ignored an error from `GetTokenID` for ACME/SCEP provisioners, so authorization proceeded on an error path.
- **step-ca CVE-2026-30836**: unsupported SCEP message types parsed fine but skipped authorization.
- **step-ca CVE-2025-66406**: the SSHPOP revocation token was not bound to a serial, so any SSH certificate could be revoked.
- **Teleport 2023**: Access List owners could escalate their own privileges.

**How to avoid:**
- Make the **signer a separate process** (ideally a separate host, user or service account) with the CA key. It is the policy enforcement point and verifies **cryptographic evidence**, not DB rows: a fresh WebAuthn assertion bound to the request hash, and approver WebAuthn signatures over the same request hash.
- Default-deny dispatch. Every error is a deny, and every request type has an explicit authorization handler (the step-ca lesson).
- Bind every token or approval to **one specific object**: request hash, pubkey fingerprint, principals, validity window, and single use (the SSHPOP lesson).
- Rate limits and max validity enforced in the signer.

**Warning signs:** the signer accepts a "pre-authorized" request without verifiable signatures. `err` ignored or logged-and-continued in any auth path. Linters (`errcheck`, `clippy::let_underscore_must_use`) not enforced.

**Phase to address:** P-Threat (boundary), P-Core (signer), P-Authz (approval evidence format).

---

### Pitfall 11: Ways around two-person approval and JIT

**What goes wrong:**
- **Self-approval through a second account** (the admin creates a sockpuppet), or requester and approver being the same human.
- **TOCTOU**: the request is approved, then its parameters are edited (principals, duration, target pubkey) before issuance.
- **Approval reuse**: one approval used to mint several certificates.
- **Validity outliving the window**: a 1h JIT approval, but the certificate is requested at minute 59 with 8h validity.
- **Changing policy instead of using it**: the admin edits role mappings, the approval policy itself, or the "sensitive principal" flag, without two-person control.
- **Break-glass as the routine path**, or MFA reset done by one admin. Resetting someone's WebAuthn and logging in as them is a self-grant.
- **Silent renewal**: refresh tokens let a stolen laptop renew short-lived certificates indefinitely.

**How to avoid:**
- Approval = signature over the canonical request hash, single use, and the requester ≠ approver check is enforced in the signer. Account creation and MFA resets also go through two-person control, which prevents sockpuppets.
- `valid_before ≤ approval_expiry` is enforced in the signer.
- Policy changes (roles, principal maps, approval rules, trusted CAs) are **themselves** two-person, signed, and audited.
- Each issuance needs a fresh WebAuthn user-verification ceremony, or renewal is capped by a maximum session age that requires re-authentication.

**Warning signs:** the approver list can include the requester. Approved requests are mutable. A single admin can change role mappings.

**Phase to address:** P-Authz, P-Ident.

---

### Pitfall 12: A hash chain alone isn't tamper-evidence, and the log only covers what goes through the app

**What goes wrong:**
- Someone with DB write access rewrites history and **recomputes the whole chain**, or truncates the tail. A hash chain stored only in the same DB as the data detects neither.
- Issuance done outside the app (someone with CA key access running `ssh-keygen -s`, or a compromised signer) is never logged. Hosts still accept those certificates, so the "full visibility" promise silently breaks.
- Log injection: key IDs and usernames containing newlines or control characters end up in sshd logs and the audit UI.

**How to avoid:**
- **Anchor the chain externally**: sign periodic checkpoints (head hash + sequence number) with a key the DB admin doesn't have. Publish them somewhere independent (agents keep the last-seen head, emailed or offsite copies, or a witness). Verify continuously, not only on demand.
- **Log before delivering**: the signer appends the record and the certificate is released only after the append commits.
- **Reconcile from the host side**: sshd logs "Accepted publickey … ID <keyid> (serial N) CA …". Agents ship those lines, and the server flags any (CA, serial) pair **not in the issuance log**. This is the only control that detects issuance outside the app, and it fits the "full visibility" core value well.
- Key ID = structured, sanitised, unique (`<user>/<request-id>`). Only `[A-Za-z0-9._@/-]` allowed.

**Warning signs:** the audit table is in the app DB with no external checkpoints. No host-side certificate-usage ingestion.

**Phase to address:** P-Audit (log + anchoring), P-Inv/P-Trust (sshd log ingestion).

---

### Pitfall 13: WebAuthn implementation mistakes

**What goes wrong:**
- Not checking `rpIdHash`, the exact origin (scheme + host + port), the `type` field, or one-time challenge expiry, which leaves replay possible.
- Accepting UP (presence) without **UV (user verification)** for signing operations.
- **The RP ID can't be an IP address.** Self-hosters on `https://192.0.2.5:8443` find WebAuthn simply fails. A DNS name and a real TLS certificate are needed (MagicDNS + `tailscale cert` works). This hits the "up in minutes" goal directly.
- Treating a counter regression as a hard error. Synced passkeys report `signCount = 0`.
- Adding a new authenticator with only a session cookie (session theft → persistent backdoor key).
- Recovery codes or admin reset as the weakest link.
- Synced passkeys (BE/BS flags) for admin roles: the security of the cloud account becomes the security of the CA.

**How to avoid:** use a maintained library (go-webauthn/webauthn or webauthn-rs) rather than hand-rolled CBOR/COSE. Require UV. Store challenges server-side, single use, 2–5 min TTL. Registering a new credential requires an existing credential plus a notification. Optionally require device-bound credentials (BE=0) for admin/approver roles. Ship a setup check that refuses IP-address origins with a clear message.

**Warning signs:** WebAuthn tests only cover the happy path. Login works over `localhost` in dev but nobody has tried a LAN IP.

**Phase to address:** P-Ident.

---

### Pitfall 14: CLI login handoff gets phished (certificate issued for the attacker's key)

**What goes wrong:**
`login` opens a browser, or uses a device code. An attacker starts a login with **their own public key** and sends the victim the link or code. The victim completes WebAuthn, and the attacker gets a certificate with the victim's principals. Device-code flows are phishable by design.

**How to avoid:** no device-code flow in v1. Use a loopback redirect with PKCE and state, bound to the CLI process. The browser approval page shows the **pubkey fingerprint, requesting host and principals**, and the CLI shows the same fingerprint. The WebAuthn challenge commits to the request hash, which includes the pubkey. Generate user keys **on the client** (ephemeral, in-memory, added to ssh-agent with a lifetime). Never generate them on the server, unlike Vault's `/issue` and BLESS-style designs.

**Phase to address:** P-Ident.

---

### Pitfall 15: Agent enrollment and bootstrap trust

**What goes wrong:** reusable or long-lived join tokens end up in shell history, cloud-init user-data and CI logs. The agent TOFU-trusts the server's TLS certificate on first contact. Anyone with a token can enroll a fake host, receive a host certificate for a name it doesn't own (Pitfall 8), and see the KRL and policy.

**How to avoid:** single-use, short-TTL tokens scoped to an expected hostname. The token embeds the server's TLS/trust-root fingerprint so the agent can pin it. **New hosts need admin approval** before a host certificate is issued (show the host key fingerprint). Agent identity = its own keypair (and the host key fingerprint), not the token. Token use is audited.

**Phase to address:** P-Trust.

---

### Pitfall 16: Inventory that reads hostile files as root

**What goes wrong:** a root agent walks every `~/.ssh`. User-controlled symlinks (`authorized_keys → /etc/shadow`) make it read and **upload** privileged files. Attacker-controlled `authorized_keys` content hits the parser. Reading *private* keys to "check strength" puts key material in the server DB. Inventory also misses real access paths:
- custom `AuthorizedKeysFile` paths, `authorized_keys2`, `AuthorizedKeysCommand`
- Windows `administrators_authorized_keys`
- **`cert-authority` lines in a user's own `authorized_keys`**: users can trust their own private CA and bypass central control
- extra or forgotten CA lines in `TrustedUserCAKeys`

**How to avoid:**
- Open files with `O_NOFOLLOW`/no reparse-point following, and check owner and mode.
- Ship only **parsed public metadata** (type, bits, fingerprint, comment, options), never raw files.
- For private keys, report path, type and "encrypted yes/no" from the header only. Never read or ship the key itself.
- Derive paths from `sshd -T -C user=…`.
- Flag `cert-authority` lines, unknown CA keys and `command=`/`from=` options as high-severity findings.

**Phase to address:** P-Inv.

---

## Moderate Pitfalls

### Signature algorithms and key types
- OpenSSH **8.2 removed `ssh-rsa` (SHA-1) from `CASignatureAlgorithms`**, and 8.8 disabled `ssh-rsa` signatures generally. An RSA CA that signs with SHA-1 produces certificates modern sshd rejects. **Prevention:** an Ed25519 CA by default; if it must be RSA, pin `rsa-sha2-512` explicitly in the signer instead of relying on library defaults (check what your library's `SignCert` defaults to; *(LOW)* older x/crypto defaulted to SHA-1 for RSA).
- **HSM/token constraint**: many PKCS#11 HSMs and older YubiKey PIV firmware don't do Ed25519 *(LOW: YubiKey 5.7+ PIV adds Ed25519)*. The custody choice can force ECDSA P-256/P-384. Decide algorithm and custody together in P-Core.
- Mixed fleets: Ed25519 certs need OpenSSH ≥ 6.5 and rsa-sha2 needs ≥ 7.2. Dropbear (OpenWrt) *(LOW)* historically has no OpenSSH certificate support. Inventory should report sshd implementation and version.

### Validity, clock skew and "forever" certs
- `ssh-keygen`'s default validity is **forever**. A missing `valid_before` in your encoder means a permanent credential. **Prevention:** the signer enforces a per-role max TTL and has no "infinite" option for humans.
- Hosts with skewed clocks (Windows w32time drift, appliances without NTP, VMs restored from snapshot) reject fresh certificates as "not yet valid". **Prevention:** backdate `valid_after` by about 5 minutes. Agents report clock offset and inventory flags skew > 60s.
- OpenSSH 10.1 `ssh-add` drops certificates from the agent at expiry + 5 min. Older agents keep expired certificates around, which is confusing but harmless.

### Serial and key ID uniqueness
- Use unique non-zero serials per CA (see Pitfall 5). Make key IDs unique and structured, because they are the join key between host logs and the issuance log. Never reuse a request ID after a DB restore. Include a CA generation tag in the key ID so you can tell which CA key signed what during rotation.

### CA rotation pain
- Rotating is usually unplanned, so hosts that were offline during rotation get locked out, and client `known_hosts` on laptops keep only the old host CA. **Prevention:** always pre-publish N+1 keys and rehearse rotation regularly (a scheduled drill in the homelab). Revoking a CA = put the CA public key in the KRL (revokes everything it signed) *and* remove it from the trust bundle.

### CA key in backups, memory and logs
- Backups of the server dir or DB contain the CA key in plaintext. Core dumps, swap and debug logs can too. **Prevention:** the key lives in the token/HSM or an encrypted keystore. Separate backup handling for key material. Disable core dumps; mlock where available.
- *An HSM is a signing oracle during a compromise.* Non-extractability limits damage after a breach, not during one. Only the signer's policy checks plus host-side reconciliation (Pitfall 12) limit what happens while the attacker is in. State this honestly in the threat model.

### AuthorizedPrincipalsFile / Windows username matching
- Windows: user and group names must be **lowercase**. Domain users resolve to `domain\user` (NameSamCompatible). Principal-to-username matching for domain accounts has had issues (Win32-OpenSSH #1055). **Entra ID administrators silently skip `Match Group administrators`** (Win32-OpenSSH #2466), so their keys and any Match-scoped restrictions don't apply. Use lowercase principal and username mapping, test domain accounts explicitly, and document that Entra ID accounts are unsupported.

### Embedding SSH transport you don't need
- The project doesn't need an SSH server or client implementation. Stock OpenSSH verifies certificates. Embedding x/crypto/ssh or russh transport (for agent comms, inventory over SSH, or a "web terminal") imports their CVE stream:
  - Terrapin CVE-2023-48795
  - x/crypto/ssh: 15+ advisories in 2026 alone (GO-2026-5005 … GO-2026-6355)
  - russh: ~20 advisories in 2026
- **Prevention:** use the SSH library only for **certificate/key encoding and signing**. Run the control plane over HTTPS/mTLS.

## Minor Pitfalls

- **`known_hosts` hashing**: hashed entries make CLI management of `@cert-authority`/`@revoked` lines harder. Manage a dedicated `known_hosts` file (`UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts.sshcm`).
- **`ForceCommand` + `SSH_ORIGINAL_COMMAND` wrapper scripts** that run in a shell have injection problems. Ship none; document the risk.
- **OpenSSH version-string parsing**: 10.0 announces `OpenSSH_10.0`, which breaks naive `OpenSSH_1*` or `OpenSSH_[5-9]` matches in inventory.
- **OpenSSH 10.0 split auth into `sshd-auth`**, so log lines move from `sshd-session` to `sshd-auth`. Log parsers for host-side reconciliation must handle both.
- **macOS** *(LOW)*: sshd is launchd-activated per connection, so config changes apply on the next connection without a reload. OS updates may restore `/etc/ssh/sshd_config`, so use `sshd_config.d` drop-ins and re-verify after updates. "Remote Login" toggling controls the service.
- **FreeBSD**: base OpenSSH lags upstream. OpenSSH from ports (`/usr/local/etc/ssh`) is a different path. Detect which sshd is actually running.

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Cert principal = Unix username (no AuthorizedPrincipalsFile) | Zero host config | Global master principals; can't express "which hosts" | Never beyond a single-host demo |
| Monotonic serial counter in DB | Simple, readable | Serial reuse after restore breaks KRL semantics | Only if restore procedure bumps counter by a large offset (document it) |
| Hash chain in same DB, no external anchor | Easy | Not tamper-evident against the threat model's malicious admin | MVP internal builds only; never in a release |
| Agent restarts sshd after edits | Simple | Fleet lockout on bad config | Never; reload + self-test + rollback |
| Signer in same process as API | One binary, fewer moving parts | API RCE = arbitrary signing | Acceptable in P-Core prototype only if the signer API is already a separate interface that can be split out without a redesign |
| Unsigned KRL over TLS | Works | Compromised server/MITM can ship empty KRL (un-revoke) | Never once KRL distribution ships |
| Refresh tokens for silent cert renewal | Smooth UX | Stolen laptop = indefinite access | Only with a hard max session age requiring WebAuthn re-auth |
| Agent auto-update without pinned signature | Easy updates | Update channel = fleet RCE | Never |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Windows OpenSSH (inbox 9.5p2) | Appending directives after `Match Group administrators` | Insert before the first `Match`; verify with `sshd -T -C user=<admin>` and a non-admin |
| Windows OpenSSH | Wrong ACLs on CA/KRL/principals files (sshd refuses or, worse, users can edit) | ACL: SYSTEM + Administrators only, inheritance removed (same model as `administrators_authorized_keys`: `icacls … /inheritance:r /grant Administrators:F /grant SYSTEM:F`) |
| Windows OpenSSH | Relying on `AuthorizedPrincipalsCommand`/`AuthorizedKeysCommand` | Unsupported on Windows; use files. Use absolute `__PROGRAMDATA__/ssh/...` paths |
| Windows OpenSSH | Assuming upstream fixes (10.3 principals) are present | Test the issuer against 9.5p2; the CA must be safe regardless of verifier version |
| OPNsense / pfSense | Editing `/etc/ssh/sshd_config` directly | Regenerated from GUI config on save/reboot *(LOW: verify per version)*; use the platform's template/plugin mechanism and re-verify `sshd -T` after every boot |
| Ubuntu / cloud-init | Drop-in loses to earlier-sorted file | `00-` prefix + `sshd -T` verification |
| Tailscale | `source-address` with LAN CIDRs; host certs lacking MagicDNS/100.x names | Include Tailscale CGNAT range where intended; include MagicDNS FQDN + 100.x in host principals |
| ssh-agent | Writing user private key to disk | Ephemeral in-memory key, `ssh-add -t <ttl>`, certificate added alongside |
| sshd logs (reconciliation) | Parsing only `sshd` program name | Handle `sshd`, `sshd-session`, `sshd-auth` (10.0+), Windows ETW/`LOCAL0` file logs under `%programdata%\ssh\logs` |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| HSM/USB-token signing throughput *(LOW: device-specific)* | Login storms at 09:00 time out | Measure early; queue + per-user rate limit; pick token with adequate ECDSA/Ed25519 ops/s | Tens of concurrent logins on YubiKey-PIV-class tokens |
| Full audit-chain verification on page load | Slow UI | Verify incrementally from last signed checkpoint | ~10^5–10^6 records |
| Agents polling KRL too often / all at once | Server load spikes | ETag/version check, jittered polling | Hundreds+ hosts at sub-minute intervals |
| KRL growth from long-lived machine certs | Large KRL, slow distribution | Use serial ranges, prune strictly after expiry, keep machine cert TTL bounded (days–weeks) | Thousands of revocations |
| Single serialized hash-chain head | Write contention | Fine at team scale; batch appends if needed | Unlikely below thousands of issuances/minute |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Accepting a certificate as a CA key (Teleport CVE-2025-49825 class) | Users mint their own certs | Refuse cert-type signature keys everywhere |
| Ignoring errors in authz path (step-ca CVE-2025-44005) | Unauthenticated issuance | Default-deny; errcheck/clippy gates in CI |
| Revocation/approval tokens not object-bound (step-ca CVE-2025-66406) | Revoke/approve arbitrary objects | Bind to serial/request hash, single use |
| Empty-principal issuance (Vault CVE-2024-7594) | Login as any user | Signer refuses empty/wildcard principals |
| Server can push new trusted CA keys | Server compromise = fleet compromise | Trust-root-signed bundles, pinned at enrollment |
| Users' own `cert-authority` lines in authorized_keys | Shadow CA outside central control | Inventory flags; optionally `AuthorizedKeysFile` restriction documented |
| Unsigned agent self-update | Fleet RCE via update channel | Pinned signature keys (consider TUF-style threshold), no update without verification |
| CI supply chain: unpinned GitHub Actions (tj-actions/changed-files compromise, 2025), typosquatted modules lingering in module proxy caches *(LOW)*, xz-utils (CVE-2024-3094) targeting sshd through linked libraries | Backdoored release | Pin actions by commit SHA; minimal deps with `go mod verify`/`cargo vet`/`cargo deny`; reproducible builds verified by a second builder; never ship PAM/NSS modules or sshd plugins that run inside the sshd auth path |
| Release signing key stored in CI secrets | Signed malware | Keyless signing with transparency log (Sigstore) or offline hardware key; publish SBOM + provenance |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Host cert principals incomplete → TOFU fallback prompts | Users trained to click "yes", defeating host CA | Enrollment UI shows every name/IP; CLI test `sshcm doctor <host>` checks name coverage |
| Cryptic sshd rejections ("name is not a listed principal") | Support burden, people revert to keys | CLI `doctor` command that decodes local cert (`ssh-keygen -L` equivalent) and explains mismatch against host policy |
| WebAuthn failing on IP-address URL | First-run failure, "doesn't work" | Setup wizard requires a hostname + TLS; detect and explain |
| Too-short cert TTL with no smooth renewal | Constant re-login | Default human TTL ~8–12h (one workday), WebAuthn per issuance, fast CLI path |
| Inventory dumps thousands of findings unranked | Alert fatigue, feature ignored | Severity ranking: shadow CAs, root keys, keys with no owner, weak types first |
| "Fix it for me" buttons in inventory | Lockouts, broken automation | v1: report + copy-pasteable command; no automatic key removal (keeps PROJECT.md decision) |

## Product / Scope Pitfalls

- **Teleport drift.** Proxy, session recording, Kubernetes/DB access and SSO all get added "because users ask", and each one adds attack surface and maintenance. The differentiator is *one binary, no proxy, auditable*. Keep a written "not doing" list (PROJECT.md Out of Scope) and review it at every milestone.
- **Inventory that edits.** Automatic removal or rotation of discovered keys removes break-glass keys and backup-job keys and causes outages. Keep v1 read-only, as already decided. Any future remediation needs per-host approval, a dry run and a rollback.
- **A generic agent.** Each "while we're on the host, also do X" turns the agent into a config-management or RCE tool (Pitfall 2). The agent's capability list should be short enough to fit on one screen.
- **Policy language creep.** A Turing-complete policy DSL is unauditable. Use declarative roles: principal sets, host labels, max TTL, approval requirement.
- **Multi-platform too early.** Windows, macOS and appliances each have distinct config semantics. Get Linux right, including the drift and verification machinery, and treat each platform as a separate phase with its own test host. Daniel-PC (Windows 9.5p2), the Ubuntu laptop, zima and Proxmox are natural targets.

## "Looks Done But Isn't" Checklist

- [ ] **Issuance:** rejects empty principals, wildcard and comma principals, missing `valid_before` and serial 0. Verify with negative tests against OpenSSH 9.5p2 *and* latest.
- [ ] **Issuance:** the CA signs with Ed25519 or `rsa-sha2-512`. Verify with `ssh-keygen -L` output and an sshd with default `CASignatureAlgorithms`.
- [ ] **Extensions:** the default profile grants only `permit-pty`. Verify agent and port forwarding fail with a default certificate.
- [ ] **KRL:** delete the KRL on a test host, then confirm the agent restores last-known-good *and* alerts. Corrupt it and confirm it is rejected before install. Remove `RevokedKeys` from config and confirm an alert fires.
- [ ] **KRL:** time from revocation to rejection on a host is measured and shown.
- [ ] **Trust bundle:** a compromised-server simulation pushes a new CA key and the agent refuses it.
- [ ] **sshd config:** `sshd -T -C user=<admin>` and `user=<normal>` both show the expected TrustedUserCAKeys/RevokedKeys/AuthorizedPrincipalsFile (Windows especially).
- [ ] **Break-glass:** an actual login with the break-glass CA on every platform, with an alert raised.
- [ ] **Host certs:** connecting by every documented name/IP shows no TOFU prompt.
- [ ] **Approvals:** requester-as-approver, edit-after-approval, approval reuse and TTL-beyond-window are all rejected *by the signer*, with tests that bypass the API.
- [ ] **Audit:** rewriting a DB row and recomputing the chain is detected against an external checkpoint.
- [ ] **Reconciliation:** a certificate signed out-of-band with the CA key shows up as "unlogged issuance" after one login.
- [ ] **WebAuthn:** replayed assertion, wrong origin, UV=0 and IP-origin setup are all rejected with clear errors.
- [ ] **Inventory:** a symlink from `authorized_keys` to `/etc/shadow` is not followed. Private-key contents never leave the host. A `cert-authority` line in a user's authorized_keys is flagged.
- [ ] **Release:** an independent rebuild reproduces the release hash. The agent refuses an unsigned or wrongly signed update.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| User CA key compromise | HIGH | Put CA pubkey in KRL everywhere; promote pre-published next CA; reissue; reconcile host logs for unlogged serials since suspected compromise; rotate trust-root if signer host compromised |
| Host CA compromise | HIGH | `@revoked` old host CA on clients via CLI; reissue host certs from next CA; investigate mis-issued host principals |
| Fleet lockout (bad KRL/config) | MEDIUM–HIGH | Break-glass CA login → agent rollback to last-known-good; console access for hosts without break-glass |
| Empty/wildcard-principal certs issued | MEDIUM | KRL by serial for every affected cert; audit host logs for their use |
| Serial reuse after DB restore | MEDIUM | Bump serial space; reissue all certs issued after backup point; rebuild KRL from authoritative issuance records |
| Audit log tampering detected | MEDIUM | Freeze writes; compare against external checkpoints and agent-held heads; reconstruct from host sshd logs; treat as insider incident |
| Config drift removed RevokedKeys (appliance) | LOW–MEDIUM | Agent re-applies via platform mechanism; review sshd logs for use of revoked serials during gap |

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| 1. No chains in SSH certs (custody premise) | P-Threat, P-Core | ADR states online CA = trust anchor; offline key signs bundles only |
| 2. Agent as fleet-root channel | P-Threat, P-Trust | Compromised-server test: rogue CA push refused |
| 3. Empty/wildcard principals | P-Core | Negative tests vs OpenSSH 9.5p2 + latest |
| 4. Username-as-principal | P-Authz, P-Trust | No `root`/account names in issued certs; AuthorizedPrincipalsFile everywhere |
| 5. KRL fail-closed / fail-open | P-KRL, P-Trust, P-Plat | Delete/corrupt/drift drills |
| 6. Fleet lockout / break-glass | P-Threat, P-Trust | Tested break-glass login per platform; auto-rollback drill |
| 7. sshd_config precedence / Match | P-Trust, P-Plat | `sshd -T -C` checks for admin + non-admin |
| 8. Host cert principals / claimed names | P-Trust, P-Ident | Server-bound names; no TOFU on enrolled hosts |
| 9. Extensions/critical options defaults | P-Core, P-Authz | Default cert can't forward; force-command roles have no forwarding |
| 10. Signer outside policy boundary | P-Threat, P-Core, P-Authz | API-bypass tests against signer |
| 11. Approval/JIT bypasses | P-Authz, P-Ident | Bypass test suite at signer level |
| 12. Audit tampering / unlogged issuance | P-Audit, P-Inv | Rewrite detection + out-of-band cert detection |
| 13. WebAuthn mistakes | P-Ident | Negative ceremony tests; IP-origin guard |
| 14. CLI login phishing | P-Ident | Fingerprint shown both sides; no device code |
| 15. Enrollment trust | P-Trust | Token single-use/TTL; admin approval before host cert |
| 16. Hostile-file inventory | P-Inv | Symlink/oversize/malformed fixtures; no private key egress |
| Supply chain / self-update | P-Rel (but design signing keys in P-Threat) | Reproducible rebuild; signed-update refusal test |
| Windows specifics | P-Plat (Windows) | Daniel-PC dogfood: admin + non-admin cert login, ACL check |

**Ordering implications for the roadmap:**
1. **P-Threat must come first and decide the trust architecture**: signer boundary, trust-root-signed bundles, break-glass CA, custody without chains. Pitfalls 1, 2, 6 and 10 can't be retrofitted cheaply.
2. **P-KRL and P-Trust share verification machinery** (`sshd -T`, atomic writes, rollback). Build that machinery once, early, on Linux.
3. **P-Audit's host-side reconciliation depends on the agent shipping sshd logs**, so the agent's report channel should be designed with that in mind from P-Trust onward.
4. **Platform phases come late and one at a time.** Windows (9.5p2, Match-block placement, ACLs, lowercase names, no `*Command` options) deserves its own phase and probably targeted research.

## Sources

- OpenSSH release notes, 8.2 → 10.5 (empty principals 10.3; comma principal fix 10.3; KRL signature removal 9.4; `sshd-auth` split 10.0; ForceCommand forwarding warning; host-cert fallback control 9.8; ssh-add cert expiry 10.1; ssh-rsa CA removal 8.2): https://www.openssh.com/releasenotes.html
- `sshd_config(5)` (RevokedKeys unreadable → all pubkey refused; first-value-wins; Match keywords; AuthorizedPrincipalsFile semantics): https://man.openbsd.org/sshd_config.5
- `ssh-keygen(1)` (KRL serials exclude zero; default serial zero): https://man.openbsd.org/ssh-keygen.1
- draft-miller-ssh-cert-06 (MUST NOT accept certs as CA keys; lexical ordering; unknown critical option → refuse): https://datatracker.ietf.org/doc/html/draft-miller-ssh-cert
- Teleport CVE-2025-49825 advisory (GHSA via `gh api`) and post-mortem: https://goteleport.com/blog/ncc-cryptography-audit-go-ssh/ ; https://www.securityweek.com/critical-authentication-bypass-flaw-patched-in-teleport/
- Vault CVE-2024-7594 / HCSEC-2024-20: https://discuss.hashicorp.com/t/hcsec-2024-20-vault-ssh-secrets-engine-configuration-did-not-restrict-valid-principals-by-default/70251 ; https://nvd.nist.gov/vuln/detail/cve-2024-7594
- step-ca advisories CVE-2025-44005, CVE-2026-30836, CVE-2025-66406 (GHSA via `gh api repos/smallstep/certificates/security-advisories`): https://github.com/advisories/ghsa-h8cp-697h-8c8p
- x/crypto/ssh advisories via OSV API (CVE-2024-45337; GO-2026-5005…5033; GO-2026-6303 source-address; GO-2026-5021 knownhosts @revoked CA): https://osv.dev ; https://seclists.org/oss-sec/2024/q4/151
- russh advisories via OSV API (crates.io)
- Microsoft Learn, OpenSSH Server configuration for Windows (unsupported options, lowercase names, domain\user, administrators_authorized_keys ACL): https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration
- Win32-OpenSSH issues #2466 (Entra ID skips Match Group), #1055 (domain principals), Certificate Authentication wiki: https://github.com/PowerShell/Win32-OpenSSH/issues/2466 ; https://github.com/PowerShell/Win32-OpenSSH/wiki/Certificate-Authentication
- Local verification: Daniel-PC inbox `OpenSSH_for_Windows_9.5p2`; Win32-OpenSSH latest release `10.0.0.0p2-Preview` (2025-10-27)
- *(LOW, from memory, verify in the relevant phase)*: OPNsense/pfSense sshd_config regeneration, macOS launchd/sshd_config.d behaviour, Dropbear certificate support, YubiKey 5.7 PIV Ed25519, HSM throughput figures, x/crypto `SignCert` RSA default history, tj-actions and Go-module-proxy typosquat incidents.

---
*Pitfalls research for: self-hosted SSH certificate authority & access manager*
*Researched: 2026-10-04*
