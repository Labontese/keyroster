# Architecture Research

**Domain:** Self-hosted, security-first SSH certificate authority and access manager (no proxy in the data path; stock OpenSSH verifies)
**Researched:** 2026-10-04
**Confidence:** MEDIUM overall. OpenSSH behaviour claims were checked against man pages and the openssh-portable source and are tagged *[source-verified]*. Design recommendations are opinionated synthesis and are labelled as such. Confidence tiers come from the classify-confidence seam: web sources cross-checked against each other are MEDIUM, single web sources are LOW.

---

## TL;DR (the decisions this file recommends)

1. **Five processes, three trust zones.** `sshcm-signer` (tiny, no network, owns the CA keys and the audit log), `sshcm-server` (API, web UI, DB; *treated as untrusted* by the signer), `sshcm-agent` (one per host, pull-only, no listening port), the `sshcm` CLI (users and admins), and an optional `sshcm-witness` running on a *different* machine.
2. **"The server proposes, the signer disposes."** The signer issues a certificate only when the request carries cryptographic evidence it can check on its own: the user's WebAuthn assertion over the exact request digest, approver assertions for sensitive roles, and a policy version approved by an admin quorum. A compromised API server or DB cannot mint certificates.
3. **CA key model: layered.** (a) An **offline root of trust**: M-of-N FIDO/PIV keys that never sign certificates. They sign the *trust bundle*, which says which online CA keys hosts must trust. (b) **Online CA keys held in hardware** (YubiHSM 2 recommended; YubiKey PIV acceptable for small or homelab setups; software keys only in dev mode, with loud warnings). (c) **Signer process isolation.** (d) **Detection as a first-class control**: log-before-release, reconciliation against the HSM's own audit log, and *login reconciliation* (every login serial seen by sshd must exist in the log). Threshold signing (FROST) is technically possible but deferred to post-v1.
4. **OpenSSH has no certificate chains.** An "intermediate" is just an online CA key that the root *delegates to* by listing it in a root-signed trust bundle. Agents apply that bundle to `TrustedUserCAKeys` and `@cert-authority`. Rotation means trusting the old and new key at the same time. In an emergency you revoke the CA key itself through the KRL, which sshd checks *[source-verified]*.
5. **The audit log is a Merkle tree, not just a hash chain.** It uses RFC 6962/9162 hashing and C2SP signed-note checkpoints. Every agent and CLI checks consistency on each poll, and at least one independent witness cosigns. Log entries *embed the authorization evidence*, so anyone can re-verify that every certificate was authorized.
6. **Build order:** foundations and test harness → signer, keystore and log → identity and CLI login slice → Linux agent (trust, KRL, host certs) → insider resistance (quorum and two-person approval) → web UI → inventory and login reconciliation → other agent platforms → hardening and release.

---

## Standard Architecture

### How existing systems are shaped (context)

| System | Shape | Lesson for us |
|--------|-------|---------------|
| Teleport | Auth service (CA) + Proxy + node agents; certs via `tsh login` with WebAuthn (libfido2) | Good login UX and CA rotation phases (standby → init → update_clients → update_servers → standby). But it sits in the data path, and HSM support plus dual authorization are Enterprise/Pro-only. [MEDIUM] |
| Smallstep step-ca | General CA with SSH support; provisioners; `step ssh renew` for host certs via the SSHPOP provisioner (proof of possession of the current host cert) | Host-cert renewal by proving possession of the current host key/cert is the standard pattern. [MEDIUM] |
| Vault SSH engine | Signing endpoint inside a large platform; approvals via Control Groups, policy via Sentinel | Control Groups and Sentinel are Enterprise-only. Approvals are server-side state, so they are not verifiable by an independent signer. [MEDIUM] |
| Netflix BLESS (archived) | Lambda signer behind a bastion; KMS-encrypted CA key | Separating signing from everything else is the core idea, and it is still valid. |

None of these makes the **signer independently verify human approvals**, and none ships **login reconciliation** or **witnessed logs**. That is the architectural gap this project fills.

### System Overview

```
 TRUST ZONE A: OFFLINE (ceremony only)          TRUST ZONE C: INDEPENDENT
 ┌──────────────────────────────────┐            ┌──────────────────────────┐
 │ Root keys (M-of-N FIDO/PIV)      │            │ sshcm-witness (other box)│
 │  - sign trust bundles (SSHSIG)   │            │  - cosigns checkpoints   │
 │  - sign genesis policy           │            │  - keeps latest tree head│
 │  - break-glass CA key (offline)  │            └────────────▲─────────────┘
 └───────────────┬──────────────────┘                         │ HTTPS (C2SP tlog-witness)
                 │ signed bundle carried by admin (file/USB)  │
 TRUST ZONE B: CA HOST ───────────────────────────────────────┼──────────────
 ┌───────────────▼──────────────────────────────────────────────────────────┐
 │  ┌────────────────────────────┐  UDS/named pipe  ┌─────────────────────┐ │
 │  │ sshcm-server (UNTRUSTED    │  (peer-cred      │ sshcm-signer        │ │
 │  │  by signer)                │◄────────────────►│ (no network, own    │ │
 │  │ - HTTPS API + web UI       │   canonical      │  OS user)           │ │
 │  │ - SQLite: users, hosts,    │   binary msgs    │ - verifies evidence │ │
 │  │   inventory, requests      │                  │ - policy evaluation │ │
 │  │ - WebAuthn ceremonies      │                  │ - serial allocation │ │
 │  │   (relay only)             │                  │ - log sequencer     │ │
 │  │ - serves log tiles, KRL,   │                  │ - signs certs, KRLs,│ │
 │  │   bundles (read-only copy) │                  │   checkpoints       │ │
 │  └──────────▲─────────▲───────┘                  └─────────┬───────────┘ │
 │             │         │                                    │ PKCS#11/USB │
 │             │         │                          ┌─────────▼───────────┐ │
 │             │         │                          │ HSM (YubiHSM2/PIV)  │ │
 │             │         │                          │ user/host/machine CA│ │
 │             │         │                          │ ops key, log key    │ │
 │             │         │                          │ (+ forced audit log)│ │
 │             │         │                          └─────────────────────┘ │
 └─────────────┼─────────┼──────────────────────────────────────────────────┘
               │ HTTPS   │ HTTPS + mTLS (agent identity)
               │ (TLS    │ pull / long-poll; no inbound ports on hosts
               │ pinned) │
 ┌─────────────┴───┐  ┌──┴──────────────────────────────────────────────────┐
 │ sshcm CLI       │  │ sshcm-agent (Linux/Windows/macOS/FreeBSD)           │
 │ - ephemeral key │  │ - applies root-signed trust bundle                  │
 │ - WebAuthn      │  │   (TrustedUserCAKeys, principals files)             │
 │   (libfido2 /   │  │ - KRL (SSHSIG-verified, atomic write)               │
 │   webauthn.dll) │  │ - host cert renewal (proof of host key)             │
 │ - ssh-agent     │  │ - inventory scan; sshd auth-log watch               │
 │ - known_hosts   │  │ - verifies log consistency (built-in witness)       │
 │   @cert-auth    │  └──────────────────────┬──────────────────────────────┘
 └───────┬─────────┘                         │ manages files, reloads sshd
         │  SSH (stock)                       ▼
         └──────────────────────────────►  stock sshd   (no proxy)
```

### Component Responsibilities

| Component | Owns | Must never | Typical implementation |
|-----------|------|------------|------------------------|
| **sshcm-signer** | CA key handles, serial counter, nonce store, current policy version, audit-log sequencing, KRL and checkpoint signing | Listen on the network; trust anything the server says without evidence; hold an HTTP stack, DB driver or template engine | Single small binary, its own OS user, systemd sandbox (`PrivateNetwork=yes`, `ProtectSystem=strict`, `NoNewPrivileges`, seccomp filter, `DeviceAllow` limited to the HSM). Talks PKCS#11 (or the native YubiHSM protocol) |
| **sshcm-server** | HTTPS API, web UI, sessions, SQLite (users, hosts, requests, inventory, notifications), WebAuthn ceremony relay, rate limiting, serving tiles, KRL and bundles | Hold any private CA, ops or log key; decide whether a cert is issued | One binary with embedded UI assets, TLS 1.3, SQLite in WAL mode |
| **sshcm-agent** | Host enrollment identity (mTLS client cert), managed sshd drop-in, `TrustedUserCAKeys`, principals files, `RevokedKeys` KRL, `HostCertificate`, inventory snapshots, auth-log watching | Open a listening port; apply anything unsigned; ship private-key material; leave sshd in an unreadable or invalid state | Small static binary as a service (systemd, Windows service, launchd, rc.d) running as root/SYSTEM; pull model |
| **sshcm CLI** | Ephemeral user keypair, WebAuthn client, ssh-agent insertion, client trust (`@cert-authority`, `RevokedHostKeys`), admin commands (proposals, approvals, revocation), offline ceremony commands | Write the user's private key to disk; trust the server's TLS without a pin | Static binary. CTAP2 via libfido2 on Linux/macOS/BSD and the Windows WebAuthn API (webauthn.dll) on Windows; browser loopback as fallback |
| **sshcm-witness** (optional, recommended) | Latest checkpoint seen per log; cosignature key | Run on the CA host | Tiny C2SP tlog-witness implementation, deployed on another admin's machine or another box |
| **Offline root** | M-of-N root keys; trust bundle signing; genesis policy; break-glass CA | Be connected while the server is online, except during ceremonies | FIDO2 (`sk-ssh-ed25519`) or PIV keys signing with **SSHSIG** (`ssh-keygen -Y sign`), which can also be verified with stock `ssh-keygen -Y verify` |

---

## 1. Trust boundaries and protocols

### Boundary table

| # | From → To | Protocol | Authentication | What crossing it can do | Compromise of the *source* allows |
|---|-----------|----------|----------------|-------------------------|-----------------------------------|
| B1 | CLI → server | HTTPS (TLS 1.3), JSON | Server: TLS cert **pinned** by SPKI hash (pin delivered in the invite / `sshcm init`). User: WebAuthn assertion per action (not just a session cookie) | Start or finish login; propose, approve, revoke | Nothing beyond what that user's authenticator could already approve |
| B2 | Browser → server | HTTPS | Session cookie (SameSite=Strict, short TTL) for *viewing*; **fresh WebAuthn assertion bound to the action digest** for every state change | View; approve, revoke, propose (step-up) | Read-only exposure from a stolen session; no grants |
| B3 | Server → signer | Unix domain socket (Linux/BSD) with `SO_PEERCRED` uid check | Peer uid plus filesystem permissions. *The signer does not trust message content*: everything is re-verified | Request signatures, which succeed only with valid evidence | A DoS; requests carrying evidence it cannot forge are its only path |
| B4 | Signer → HSM | PKCS#11 over USB (or the YubiHSM native protocol) | HSM auth key or PIN held by the signer user only | Sign | **Misuse of keys while the compromise lasts** (no exfiltration). Mitigated by detection (§2, §4) |
| B5 | Agent → server | HTTPS + **mTLS** (agent client cert from an internal *agent CA*, separate from the SSH CAs) | Server: pinned SPKI from the join token. Agent: client cert, plus proof of host-key possession for host-cert renewal | Fetch bundles, KRL, host policy and tiles; upload inventory and login events; renew host cert | Fake inventory or login events for *that host only* |
| B6 | Server → agent (content) | Payload over B5 | **Payload signatures**, not the channel: bundle = M-of-N root SSHSIG; KRL and host policy = ops-key SSHSIG; checkpoints = log key plus witness cosignature | Change sshd trust | A compromised server can withhold updates (detected through staleness alerts) but **cannot inject a CA or remove revocations unnoticed** |
| B7 | Root ceremony → system | Signed files (USB, copy-paste) | M-of-N SSHSIG under namespace `sshcm-trust@v1` | Change the CA set, reset policy, recover | — (offline) |
| B8 | Log → witness | HTTPS, C2SP `add-checkpoint` with a consistency proof | Witness verifies the log key signature and the consistency proof | Obtain cosignatures | Forking the log is detected |
| B9 | ssh client → sshd | SSH (stock) | Cert signed by a CA in `TrustedUserCAKeys`, not in the KRL, principal permitted by `AuthorizedPrincipalsFile` | Login | — (OpenSSH) |

**Rule: authenticate payloads, not pipes.** Anything that changes who can log in (the CA set, revocations, principal mappings) is signed end to end by a key the server does not hold. TLS and mTLS give confidentiality and keep out noise. They are not the authority.

### Agent enrollment and host identity bootstrap (recommended)

The pattern is the kubeadm "join token plus CA public-key pin" (RFC 7469-style SPKI pin) [MEDIUM], adapted to SSH:

```
Admin (UI/CLI)                 Server                  Signer             New host
     │ create join token         │                        │                   │
     │ (single-use, TTL ≤ 1h,    │                        │                   │
     │  expected hostname(s),    │                        │                   │
     │  host group)              │                        │                   │
     │──────────────────────────►│ store H(token)         │                   │
     │◄── join string: token + server SPKI pin + root-key fingerprints ──────│
     │                                 (copied to host out of band)          │
     │                           │   sshcm-agent enroll <join string>        │
     │                           │◄── TLS (verify SPKI pin) ────────────────│
     │                           │◄── token, host pubkeys, agent CSR, ───────│
     │                           │    facts (OS, sshd -V, hostname, IPs),    │
     │                           │    signature over all of it by each       │
     │                           │    host key (proof of possession)         │
     │  (optional) approve host  │                        │                   │
     │  + confirm cert principals│                        │                   │
     │──────────────────────────►│── issue request + ────►│ verify, log,      │
     │                           │   admin assertion      │ sign host cert,   │
     │                           │◄───────────────────────│ sign agent cert   │
     │                           │── host cert, agent cert, current trust ──►│
     │                           │   bundle (root-signed), KRL, host policy  │
     │                           │                        │  agent verifies   │
     │                           │                        │  bundle against   │
     │                           │                        │  pinned root fps, │
     │                           │                        │  applies, sshd -t,│
     │                           │                        │  reloads sshd     │
```

Design points:
- **The join string carries the root-key fingerprints.** From that moment the agent trusts root signatures, not the server. This is TOFU-free bootstrap.
- **Host-cert principals (hostnames/IPs) come from the admin-approved token**, not from what the agent claims. Otherwise a compromised host could request a cert for `db1.prod`.
- The agent identity (mTLS client cert) and the SSH host cert are **separate credentials**. The agent cert is renewed over mTLS, and the host cert is renewed with proof of possession of the host key (the same idea as step-ca's SSHPOP).
- The agent CA (X.509, internal) is a fourth online key. It can live in the signer as a software key, because it only gates transport and not authority (see B6).

---

## 2. CA private key protection under "the CA server is compromised"

### What "compromised" means, and what is achievable

| Attacker capability | Can any design prevent it? | Realistic goal |
|---------------------|---------------------------|----------------|
| Read disk or memory of the server process (web RCE) | Yes | Server holds no keys, and the signer verifies evidence, so **zero issuance capability** |
| Root on the CA host while the HSM is attached | **Not fully.** Root can drive the HSM | **No key exfiltration** (the compromise ends when the box is reclaimed), **every signature detected**, **recovery without touching every host by hand** |
| Steal a backup or the DB | Yes | Backups contain only wrapped keys (M-of-N to unwrap) and public data |
| Insider admin acting alone | Yes, in grant direction | Quorum plus independently verified approvals (§3) |

Be honest in the docs: **hardware stops theft, not misuse. Isolation stops misuse by everything except root on the signer host. Detection and the offline root bound the damage from root.**

### OpenSSH has no chain, so how can an "intermediate" work?

- When sshd parses the cert, the signature key must be a *plain key*. `sshkey_from_blob_internal(..., allow_cert=0)` and `sshkey_type_is_valid_ca()` ("All non-certificate types may act as CAs") return `SSH_ERR_KEY_CERT_INVALID_SIGN_KEY` otherwise. **Certificates cannot sign certificates** *[source-verified, openssh-portable sshkey.c]*.
- `TrustedUserCAKeys` accepts **multiple CA keys, one per line** *[source-verified, sshd_config(5)]*. Clients accept multiple `@cert-authority` lines.
- sshd checks **both the presented key and the certificate's CA key** against `RevokedKeys` (`auth_key_is_revoked(key->cert->signature_key)` in auth2-pubkey.c) *[source-verified]*. **Putting a CA key in the KRL instantly kills every cert it ever signed.**
- Any non-cert key type, including FIDO `sk-ssh-ed25519`, can act as a CA *[source-verified]*.

So the "intermediate" is a **delegation recorded in a root-signed trust bundle**:

```
TrustBundle {
  version: 17, prev: sha256(bundle 16), issued_at, expires_at (soft: alert, don't remove)
  root:        { keys: [fp1, fp2, fp3], threshold: 2 }
  user_ca:     [ {key: A, state: active},  {key: B, state: next} ]       # both written to TrustedUserCAKeys
  machine_ca:  [ {key: M1, state: active} ]
  host_ca:     [ {key: H1, state: active}, {key: H0, state: retired} ]   # retired ⇒ also KRL'd
  breakglass_ca: { key: G, state: active }                                # offline, FIDO, touch
  ops_key: O1        # signs KRLs + host policy
  log_key: L1        # signs checkpoints
  witnesses: { keys: [W1], threshold: 1 }
  server_tls_pins: [spki1, spki2]
  agent_ca: X1
}
signatures: SSHSIG(namespace="sshcm-trust@v1") by ≥ threshold root keys
```

Agents verify the signatures (and that `version` is greater than the current one and `prev` matches), then render `TrustedUserCAKeys`, the host-CA list for clients, and pins. This is TUF's root-metadata idea applied to SSH.

### Option comparison

| Option | Stops key theft on root compromise | Stops misuse during compromise | Ed25519 | Cost / ops | Verdict |
|--------|-----------------------------------|-------------------------------|---------|------------|---------|
| Software key on the server | No | No | Yes | Free | **Dev mode only**, with a loud banner and a log flag |
| Software key in an isolated signer process | No (root reads it) | Yes against non-root server compromise | Yes | Free | Acceptable floor for evaluation; v1 default only with a warning |
| **YubiKey PIV / smartcard (PKCS#11)** | Yes (non-exportable) | No (root can drive it; the PIN sits in memory) | Since firmware 5.7. OpenSSH added Ed25519 PKCS#11 only in 10.1, and `ssh-keygen -D` enumeration was buggy until 10.2 [MEDIUM]. P-256 is the safe choice | ~$50–90 | **Small teams and homelab tier.** Use ECDSA P-256 CA keys for maximum compatibility, or Ed25519 when signing natively (not via ssh-keygen) |
| **YubiHSM 2** | Yes | No, but it has a **forced, hash-chained audit log in the device** (commands fail until logs are read) and **M-of-N wrap-key backup** [MEDIUM] | Yes | ~$650 | **Recommended production tier.** Its audit log enables HSM↔log reconciliation |
| TPM 2.0 | Yes (bound to the machine) | No | Typically not (RSA/P-256) [LOW] | Free if present | Optional backend (P-256). No backup by design, so plan rotation instead of restore |
| Network HSM / cloud KMS | Yes | No | Varies | High / external dependency | Out of scope for v1 (violates "no external services"). PKCS#11 abstraction keeps the door open |
| **Offline root + online CAs (delegation)** | The root is never online | Bounds damage: root re-keys and revokes without touching hosts | Yes | Ceremonies | **Adopt.** It is the recovery mechanism |
| Separate signer on its own hardware | Yes (different box) | Yes against CA-host compromise | Yes | Extra device | Supported later by the same IPC protocol over a serial or mTLS link. Not v1 |
| Threshold FROST (RFC 9591) | Yes | **Yes: needs t-of-n parties** | FROST(Ed25519, SHA-512) produces standard RFC 8032 signatures, so sshd accepts them [MEDIUM] | Two rounds, stateful nonces, few audited implementations (ZF `frost` in Rust); WebAuthn approvers cannot take part | **Defer to v2+** (e.g. 2-of-3 signer nodes). Note it as the long-term answer to "root on one box" |
| Multisig at the policy layer (quorum of human signatures verified by the signer) | n/a | Yes against everything except signer root | n/a | Low | **Adopt.** Gives most of the insider value of threshold crypto at a fraction of the complexity |

### Recommended model

```
Tier 0  OFFLINE ROOT  (2-of-3 FIDO/PIV keys; homelab: 1-of-2, primary + safe backup)
        signs: trust bundles, genesis policy, policy reset, break-glass CA activation
        never signs certificates; never touches the CA host
           │ delegates (bundle)
Tier 1  ONLINE KEYS in HSM, used only by sshcm-signer
        user CA (human, hours) │ machine CA (automation, days, KRL brake) │ host CA (weeks)
        ops key (KRL + host policy) │ log key (checkpoints)
        separate keys ⇒ independent rotation/revocation and blast radius
Tier 2  BREAK-GLASS CA  (offline FIDO key, touch-required, listed in TrustedUserCAKeys)
        issues ≤1h certs with principal "breakglass"; any login with it ⇒ alert
Detect  log-before-release ─ HSM audit reconciliation ─ login reconciliation ─ witnesses
```

**CA rotation** follows Teleport's phases adapted to bundles:
1. `init`: generate the new key in the HSM. The root signs a bundle with the new key in state `next`. Agents add it, so hosts trust old and new.
2. `switch`: the signer issues with the new key once ≥N% of agents report the bundle version. Fleet bundle-version reporting is therefore a dependency.
3. `drain`: wait the maximum cert TTL for that CA (hours for users, weeks for hosts).
4. `retire`: the root-signed bundle drops the old key and marks it retired. The ops-signed KRL adds the old CA key, belt and braces.

**Emergency rotation** (CA host compromised): the root signs a bundle that removes the old CA and activates a pre-provisioned spare from a separate offline token. The KRL revokes the old CA key. Agents apply within one poll interval. No host is touched by hand.

---

## 3. Two-person approval and insider resistance

### Principles (opinionated)

1. **Authority = signatures by hardware-bound human credentials, verified at the signer.** DB rows saying "approved" are worthless as authority.
2. **Approvals are bound to the exact action.** The WebAuthn challenge is `H(domain_tag ‖ canonical(action) ‖ signer_nonce)`. An approval cannot be replayed onto a different request, key, principal set or TTL.
3. **Granting needs two; revoking needs one.** Revocation is the fail-safe direction. *Un*-revoking and widening access require quorum.
4. **Policy is versioned, hash-linked, signed state.** It is not mutable config.
5. **Single-admin deployments are allowed but labelled.** With quorum = 1 the guarantee degrades to "every action is witnessed and undeletable". The UI and log say so. An optional **timelock** (a policy change takes effect after N hours, notifications go out, any admin or the root can veto) gives small teams most of the benefit.

### Policy and request model

```
Policy v(n) { prev: H(v(n-1)), admins: [cred pubkeys...], admin_quorum: 2,
              users: [{id, creds:[webauthn pubkey, ...]}],
              roles: [{name, principals:[...], max_ttl, approvers_group?, approvals_required?}],
              host_groups: [{selector, account_map: {"root": ["role:prod-admin"], ...}}],
              timelock: 0h }
Accepted by signer iff: assertions from ≥ admin_quorum distinct admins of v(n-1)
                        over H("sshcm-policy@v1" ‖ canonical(v(n)))
                        OR root-signed reset (recovery)
```

Every one of these is a **policy change and goes through quorum**: creating a user, **binding or resetting a user's WebAuthn credential**, adding admins, changing role mappings, changing approver groups. Credential binding and reset is the classic insider path ("reset Alice's passkey, register mine"), so it *must* be quorum-gated.

### Certificate request evaluation (in the signer, pure function)

```
issue(req, user_assertion, approvals[], policy_version):
  require policy_version == signer.current_policy             # no downgrade
  require verify_webauthn(user_cred(req.user), user_assertion,
                          challenge = H("sshcm-issue@v1" ‖ canonical(req) ‖ nonce))
  require nonce fresh & single-use; UV flag set
  role = policy.role(req.role); require req.user ∈ role.members
  require req.ttl ≤ role.max_ttl ∧ principals ⊆ role.principals
  if role.approvals_required > 0:
     require |{a ∈ approvals : valid(a, same digest) ∧ a.approver ∈ role.approvers
                               ∧ a.approver ≠ req.user}| ≥ role.approvals_required
     require req.created_at + request_ttl > now
  serial = next_serial(CA)
  entry  = LogEntry{type: issue, req, evidence: [user_assertion, approvals], serial, cert_tbs}
  log.append_durable(entry)          # LOG BEFORE RELEASE
  cert = hsm.sign(cert_tbs)
  return cert, inclusion_index
```

Because the **evidence is stored in the log entry**, `sshcm audit verify` (run by anyone holding the log) can replay policy history and prove every issued cert was authorized by the policy in force at the time.

### Notifications as a second line

Every grant, policy change and break-glass use fans out to all admins through the web UI inbox plus optional SMTP or webhook. Notifications are not authority, but they turn "unobserved" into "observed within minutes".

---

## 4. Tamper-evident audit log

### Why not "just a hash chain"

A plain hash chain proves internal consistency, but **truncation, rollback and showing different views to different readers are undetectable without an external anchor**, and verification needs a full replay. A Merkle-tree log (RFC 6962/9162 hashing) gives O(log n) **inclusion proofs** ("this cert is in the log") and **consistency proofs** ("today's log extends yesterday's"). Those proofs are what make cheap, distributed witnessing possible.

### Design

| Element | Recommendation |
|---------|---------------|
| Sequencer | **The signer.** It is the only writer, so a compromised server cannot drop or reorder entries |
| Entries | Canonical, domain-separated binary encoding (see Patterns). Types: `issue`, `revoke`, `policy`, `bundle`, `krl_publish`, `enroll_host`, `login_anomaly`, `hsm_audit_batch`, `admin_session` (optional) |
| Hashing / proofs | RFC 6962-style. In Go, `golang.org/x/mod/sumdb/tlog` (hashing, inclusion and consistency proofs, tiles) is a small, Go-team-maintained option [MEDIUM]. Trillian **Tessera** (GA, C2SP tlog-tiles, POSIX backend) is the heavier alternative [MEDIUM] |
| Checkpoint | C2SP `tlog-checkpoint` signed note (origin, size, root hash) signed by the **log key in the HSM** |
| Storage | Tiles on local disk (append-only files) plus an entry bundle store. The server gets a read-only replica to serve `/log/tile/...` |
| Durability | `fsync` the entry and the new checkpoint **before** the signer returns the cert. If the append fails, the cert is never released |

### Witnessing and anchoring (layered)

1. **Built-in witnesses: every agent and CLI.** Each stores the last checkpoint it verified and asks for a consistency proof on every poll. Rollback or fork is detected locally and raised as an alert. This is free and gives many independent vantage points.
2. **Dedicated witness (`sshcm-witness`)** on a different machine and admin account, implementing C2SP `tlog-witness` (add-checkpoint plus consistency proof, returns a timestamped cosignature) [MEDIUM]. Clients require ≥ `witnesses.threshold` cosignatures on checkpoints.
3. **Optional public witness network.** Only tree heads leave the site (size plus hash), revealing issuance rate and nothing else. Off by default; document it.
4. **Off-site entry export** (rsync or syslog to a separate box) so the *content* survives destruction of the CA host.

### Cross-checks that catch "root on the signer host"

- **HSM reconciliation.** The YubiHSM 2 forced-audit log records every signing operation, hash-chained in the device [MEDIUM]. The signer ingests it into `hsm_audit_batch` entries. The number of signing ops must equal the number of logged issuances, KRLs and checkpoints. A signature made by driving the HSM directly shows up as a mismatch or a chain gap at the next read. Exact semantics need phase-level research.
- **Login reconciliation (headline visibility feature).** On every accepted cert login sshd logs `ID <key_id> (serial <n>) CA <type> <fp>` *[source-verified, auth.c]*. Agents tail that line (journald or auth.log on Unix, the `OpenSSH/Operational` event log on Windows) and report it. The server checks `(CA fp, serial, key_id)` against the log, and **an unknown serial means a cert we never issued**: CA key misuse, leak or break-glass. This detects CA misuse *even if the signer was fully owned*, as long as hosts are not. It maps directly onto the core value: "know exactly who has access".

---

## 5. KRL, host certs, inventory: data flows

### KRL generation and distribution

```
revoke action (1 admin, WebAuthn-bound) ─► server ─► signer
   signer: verify; log `revoke` entry; rebuild KRL from revocation set
           (serials/ranges per CA, key IDs, explicit keys, CA keys for retired/compromised CAs)
           KRL.version := log index of this revocation (monotonic)
           sig := SSHSIG(ops_key, namespace "sshcm-krl@v1", krl_bytes)   # NOT embedded
           log `krl_publish` {version, sha256(krl)}
   server: store {krl, sig}; wake long-pollers (ETag = version)
agent (long-poll, fallback ≤60 s poll):
   fetch ─► verify SSHSIG against bundle.ops_key ─► version > current?
         ─► parse KRL locally (refuse if malformed) ─► write tmp, fsync, rename (atomic)
         ─► report applied version (server shows fleet KRL freshness)
CLI: fetch host-CA KRL ─► client's RevokedHostKeys file (revokes hosts for users)
```

Facts that drive this design:
- **OpenSSH ≥ 9.4 refuses KRLs that contain embedded signatures.** The upstream advice is SSHSIG (`ssh-keygen -Y sign`) out of band *[source-verified, PROTOCOL.krl]*.
- **If the `RevokedKeys` file is unreadable, sshd refuses public-key auth for all users** *[source-verified, sshd_config(5)]*. Hence atomic replace, never delete, a parse check before install, and a break-glass path.
- The KRL can revoke by serial, serial range, key ID (all certs for an identity), explicit key, or SHA-1/SHA-256 fingerprint, and a CA section with an empty CA applies to all CAs *[source-verified]*.
- sshd reads `RevokedKeys` at authentication time, so no reload should be needed after a KRL update [LOW; verify in phase research with an integration test].
- Short-lived user certs rarely need KRL entries. Serial entries can be pruned after the cert's `valid_before`. **Key and CA-key revocations are never pruned.**
- `stripe/krl` (Go) is **archived (April 2025)**. Implement KRL writing in-house (the format is small) and differential-test it against `ssh-keygen -Q` and a real sshd in CI [MEDIUM].

### Host cert issuance and renewal

```
enroll (see §1) ─► host cert: principals = admin-approved names, TTL 30–90 d
agent timer: at 2/3 of lifetime ─► mTLS to server ─► POST /host/renew
     {current host cert, challenge signed by host private key}
server ─► signer: verify host key PoP, cert matches enrolled host, names unchanged, host not revoked
     ─► log `issue(host)` ─► sign ─► agent writes HostCertificate (atomic), sshd -t, reload
name change ⇒ new admin-approved request (not automatic)
```

Clients trust hosts through `@cert-authority <pattern> <host CA>` lines that the CLI writes to a managed known_hosts file, sourced from the root-signed bundle. Host KRL goes to `RevokedHostKeys`. This removes TOFU and known_hosts sprawl.

### Host-side principal mapping (recommended pattern)

Certs carry **role principals** (e.g. `role:prod-admin`, plus `u:alice` for personal accounts), not hostnames. Each host maps local accounts to accepted role principals through `AuthorizedPrincipalsFile /etc/ssh/sshcm/principals/%u`, rendered by the agent from the **ops-key-signed host policy**. The signer derives that policy from quorum-approved policy. One cert then works on every host the role permits, without per-host cert explosion, and access is still decided centrally.

Fully decentralised verification (agents checking the admin-quorum chain themselves) is a possible v2 hardening. It adds little against a compromised signer, which could mint role principals anyway, so v1 trusts the ops key.

### Inventory data flow

```
agent (hourly + on demand):
  sshd -T [-C user=...]  ─► effective AuthorizedKeysFile, AuthorizedKeysCommand,
                            TrustedUserCAKeys, Match blocks (never assume defaults)
  for each local account: parse authorized_keys (keys, options from=/command=/cert-authority)
  Windows: C:\ProgramData\ssh\administrators_authorized_keys (applies to all admins)
  ~/.ssh/id_* : type, bits, encrypted?, public fingerprint (OpenSSH format keeps the
               public key in the clear), perms, mtime  ── NEVER private material
  host keys, sshd version, config hash
  ─► canonical snapshot ─► hash; send full snapshot or diff over mTLS
server: store snapshot + history ─► analyzer:
  weak (DSA, RSA < 3072, short ECDSA), unknown (fingerprint not attributed to a user),
  shared (same fingerprint on many hosts/accounts), stale (mtime/age), bypass
  (authorized_keys on hosts that are "cert-only")
  ─► overview + "access outside the CA" report
```

---

## 6. Data flow: short-lived user cert login (CLI + WebAuthn → ssh-agent)

```
User            sshcm CLI                    server                 signer + HSM
 │ sshcm login     │                            │                         │
 │────────────────►│ gen ephemeral Ed25519      │                         │
 │                 │ (memory only)              │                         │
 │                 │── POST /login/begin ──────►│ (TLS pin verified)      │
 │                 │   {user, pubkey, role?,    │── nonce request ───────►│
 │                 │    ttl?}                   │◄── nonce (single-use) ──│
 │                 │                            │ req := canonical{user, pubkey fp,
 │                 │                            │   principals, ttl, nonce, ts}
 │                 │◄── challenge = H(tag‖req‖nonce), allowCredentials ──│
 │ touch + PIN     │ CTAP2 getAssertion         │                         │
 │◄───────────────►│ (libfido2 / webauthn.dll;  │                         │
 │                 │  browser-loopback fallback │                         │
 │                 │  for passkeys)             │                         │
 │                 │── POST /login/finish ─────►│ rate-limit, relay ─────►│ verify assertion
 │                 │   {assertion}              │                         │ vs policy creds,
 │                 │                            │                         │ evaluate role,
 │                 │                            │                         │ approvals?,
 │                 │                            │                         │ serial, LOG, sign
 │                 │◄── cert + checkpoint + inclusion proof ─────────────│
 │                 │ verify cert (CA ∈ bundle,  │                         │
 │                 │ pubkey match), verify      │                         │
 │                 │ inclusion + consistency    │                         │
 │                 │ ssh-agent ADD key+cert,    │                         │
 │                 │ lifetime = valid_before-now│                         │
 │ ssh host ──────────────────────────────────────────────────────────► sshd (stock)
 │                 │      TrustedUserCAKeys ✓  RevokedKeys ✓  principals ✓  → logs serial
 │                 │                                            agent ─► login event ─► reconciliation
```

Details:
- **Key binding:** the challenge commits to the ephemeral public-key fingerprint, so a captured assertion cannot be used to certify an attacker's key.
- **valid_after = now − 5 min** (clock skew). TTL defaults to 8–12 h for humans, ≤1 h for approved sensitive roles. `ssh-add` since OpenSSH 10.1 already sets agent expiry to the cert expiry plus a 5-minute grace [MEDIUM]. The CLI should set the lifetime constraint explicitly anyway.
- **Windows CLI:** non-admin processes cannot talk CTAP HID directly and must use the Windows WebAuthn API (webauthn.dll) [LOW; verify]. The OpenSSH agent sits at `\\.\pipe\openssh-ssh-agent`.
- **libfido2 means cgo**, which conflicts with fully static binaries on some platforms. Flag this for STACK and phase research. The browser-loopback flow also covers platform passkeys (Touch ID, Windows Hello, synced passkeys) that CTAP-over-HID cannot reach.
- **Sensitive role (JIT):** `sshcm request role:prod-root --reason ...` creates a request with digest D. Approvers approve D with WebAuthn in the UI or CLI. The requester runs `sshcm login --request <id>`, and the signer verifies the user assertion plus k approvals over D.
- **Optional hardening:** issue certs to an `sk-ssh-ed25519` user key instead of an ephemeral one, and set `PubkeyAuthOptions verify-required` on sshd for per-connection UV [source-verified option]. Make it opt-in per role.

---

## Recommended Project Structure

Language-neutral intent, shown Go-flavoured because Go is a front-runner; STACK.md decides.

```
cmd/
├── sshcm/              # CLI (user + admin + offline ceremony subcommands)
├── sshcm-server/       # API, web UI, SQLite
├── sshcm-signer/       # minimal signer; dependency allowlist enforced in CI
├── sshcm-agent/        # host agent
└── sshcm-witness/      # optional C2SP witness
internal/
├── wire/               # canonical encoding + domain-separation tags (shared, tiny)
├── policy/             # policy model + PURE evaluator (signer authoritative; UI uses for preview)
├── trust/              # trust bundle format, SSHSIG multi-sig verification
├── evidence/           # WebAuthn assertion verification (signer-side, no HTTP deps)
├── cert/               # cert templates, validity, extensions
├── krl/                # KRL writer/parser (differential-tested vs ssh-keygen)
├── tlog/               # entries, checkpoints, proofs, witness client
├── keystore/           # Signer interface: software | pkcs11 | yubihsm | tpm
├── signer/             # request handling, serials, nonces, log-before-release
├── server/             # api/, store/ (sqlite, migrations), ui/, webauthn ceremony relay
└── agent/
    ├── apply/          # atomic file writes, sshd -t, reload, rollback
    ├── sshdconf/       # drop-in rendering, `sshd -T` parsing
    ├── inventory/      # scanners
    ├── logwatch/       # auth-log readers per platform
    └── platform/       # linux, windows, darwin, freebsd (service mgmt, ACLs, paths)
test/
├── e2e/                # containers with real sshd (multiple OpenSSH versions); Windows runner later
└── vectors/            # canonical encodings, KRLs, checkpoints (golden files)
web/                    # UI source (built + embedded)
```

### Structure Rationale

- **The `signer` dependency firewall** is the most important structural rule. CI fails if `cmd/sshcm-signer` transitively imports net/http servers, DB drivers, template engines or the UI. A small auditable surface is a product claim, so make it a test.
- **`policy/` is pure** (no I/O). The signer is authoritative, and the UI reuses the same code for "what would this grant?" previews, so the two cannot drift.
- **`wire/` is shared and tiny.** Every signed thing (WebAuthn challenges, log entries, bundles, policies) is canonical bytes with a domain tag.
- **`agent/platform/`** isolates OS specifics. Windows ACLs and OPNsense config regeneration are hard enough to deserve their own packages and test runners.

---

## Architectural Patterns

### Pattern 1: Untrusted front end, verifying signer ("server proposes, signer disposes")

**What:** All state-changing authority is carried as end-user signatures that the signer verifies itself. The server is a relay plus UX.
**When to use:** Always, for issuance, policy, and revocation (revocation also needs one valid admin assertion).
**Trade-offs:** The signer grows (WebAuthn verify, policy evaluation, log), but stays far smaller than the server. You also cannot "just add an admin button" without defining its evidence.

```go
// signer: the only function that can produce a user certificate
func (s *Signer) Issue(ctx context.Context, r IssueRequest) (*ssh.Certificate, LogIndex, error) {
    if r.PolicyVersion != s.policy.Version { return nil, 0, ErrStalePolicy }
    if err := s.nonces.Consume(r.Nonce); err != nil { return nil, 0, err }
    digest := wire.Digest("sshcm-issue@v1", r.Canonical())
    if err := evidence.VerifyAssertion(s.policy.UserCreds(r.User), r.UserAssertion, digest); err != nil {
        return nil, 0, err
    }
    dec, err := policy.Evaluate(s.policy, r, r.Approvals, digest) // pure
    if err != nil { return nil, 0, err }
    tbs := cert.Template(r.PubKey, dec.Principals, dec.ValidAfter, dec.ValidBefore, s.serials.Next(dec.CA), r.User)
    idx, err := s.log.AppendDurable(tlog.IssueEntry(r, tbs, dec)) // log BEFORE release
    if err != nil { return nil, 0, err }
    if err := tbs.SignCert(rand.Reader, s.keys.CA(dec.CA)); err != nil { // crypto.Signer → HSM
        return nil, 0, err // logged-but-unsigned entry is fine; unlogged-but-signed is not
    }
    return tbs, idx, nil
}
```

(Go's `ssh.NewSignerFromSigner` plus `Certificate.SignCert` work with any `crypto.Signer`, PKCS#11 included [MEDIUM].)

### Pattern 2: Signed-state distribution (TUF-style)

**What:** Trust config (bundle), revocation (KRL) and host policy are versioned, monotonic, signed documents. Agents verify signature, version and log inclusion before applying.
**When to use:** Anything that changes sshd's trust decisions.
**Trade-offs:** Needs key management for root and ops keys, and needs freeze and staleness alerts (a server that withholds updates is detected, not prevented).

### Pattern 3: Log-before-release

**What:** An entry is durably appended (and ideally cosigned within seconds) before the artifact (cert, KRL) leaves the signer.
**When to use:** Issuance, KRL publication, policy acceptance.
**Trade-offs:** Adds fsync latency to login (milliseconds). A log outage halts issuance by design, which is consistent with "security over convenience".

### Pattern 4: Pull-only agents with validated atomic apply and rollback

**What:** The agent polls or long-polls. It writes files via tmp + fsync + rename, validates with `sshd -t` (and parses the KRL itself), reloads sshd, checks sshd is still running, and rolls back on failure. It never opens a listening port.
**When to use:** All host mutations.
**Trade-offs:** Revocation latency is bounded by the poll interval (seconds with long-poll). No inbound attack surface on hosts and NAT-friendly (Tailscale homelab).

```go
func ApplyKRL(path string, krl []byte, verify func([]byte) error) error {
    if err := verify(krl); err != nil { return err }          // SSHSIG + version + parse
    tmp := path + ".sshcm-new"
    if err := writeFileSync(tmp, krl, 0o644); err != nil { return err }
    return os.Rename(tmp, path) // atomic; never leave RevokedKeys missing or partial
}
```

### Pattern 5: Detection by reconciliation

**What:** Compare independent records that an attacker would have to falsify all at once: the signer log vs the HSM audit log vs sshd login lines vs witness checkpoints.
**When to use:** Continuously, as a background job in the server, with results logged.
**Trade-offs:** It only detects; it does not prevent. But it is the only control that still works when the signer host itself is compromised.

---

## Scaling Considerations

Target: teams of 2–500 people, 10–5,000 hosts. A single node is fine.

| Scale | Architecture adjustments |
|-------|--------------------------|
| Homelab, 1–10 users, <50 hosts | Single host; YubiKey PIV or software signer with a warning; quorum 1 with timelock; witness on a second machine (e.g. a laptop or ZimaBoard) |
| 10–500 users, <5k hosts | YubiHSM 2; SQLite WAL; long-poll with ETag for KRL and bundles; inventory diffs, not full snapshots; agents' poll jitter |
| 5k–50k hosts | Static KRL, bundles and tiles behind a cache or CDN-free mirror (signed content allows untrusted mirrors); optional Postgres; signer stays single (throughput is HSM-bound, still fine) |

### Scaling priorities

1. **First bottleneck: agent fan-in** (long-poll connections, inventory uploads). Fix with diffs, jitter, and serving signed static artifacts from any mirror.
2. **Second: availability, not throughput.** Short-lived certs make the CA a login dependency. Mitigate with a workday TTL, the break-glass CA, a documented restore (wrapped-key backup, M-of-N), and possibly a warm-standby signer later.

---

## Anti-Patterns

### Anti-Pattern 1: CA key reachable by the web/API process
**What people do:** Load the CA key from a config file or DB into the API server.
**Why it's wrong:** Any web RCE becomes permanent, silent CA compromise.
**Do this instead:** Run a separate signer process; keep keys in hardware; give the server zero key material.

### Anti-Pattern 2: Approvals as database rows
**What people do:** `UPDATE requests SET approved=true` after an approver clicks a button.
**Why it's wrong:** A DB or admin compromise forges approvals; two-person control becomes theatre.
**Do this instead:** Approvals are WebAuthn assertions over the request digest, verified by the signer and embedded in the log.

### Anti-Pattern 3: Embedding signatures in the KRL, or writing it non-atomically
**What people do:** Use the KRL signature section, or `open(O_TRUNC)` and write in place.
**Why it's wrong:** OpenSSH ≥ 9.4 refuses signed KRLs, and an unreadable or missing RevokedKeys file locks out *all* public-key logins.
**Do this instead:** Detached SSHSIG, atomic rename, parse-before-install, break-glass.

### Anti-Pattern 4: One CA key for everything
**Why it's wrong:** You cannot rotate or revoke host trust without breaking user logins, and the blast radius is total.
**Do this instead:** Separate user, machine and host CAs, plus separate ops and log keys.

### Anti-Pattern 5: Hostnames as user-cert principals, or per-host certs
**Why it's wrong:** Cert explosion, and policy gets encoded in certs that cannot be changed until expiry.
**Do this instead:** Role principals in certs; per-host `AuthorizedPrincipalsFile` mapping from signed host policy.

### Anti-Pattern 6: Shelling out to `ssh-keygen` to sign in production
**Why it's wrong:** Behaviour varies by version (e.g. OpenSSH 10.1 broke CA signing via ssh-agent and 10.2 fixed it [MEDIUM]), it adds parsing of human-oriented output, and it adds a runtime dependency.
**Do this instead:** Sign natively; use `ssh-keygen` and real `sshd` as the **test oracle** in CI.

### Anti-Pattern 7: Agents that listen, or that apply unsigned config
**Why it's wrong:** Every host becomes an attack surface, and server compromise becomes fleet compromise.
**Do this instead:** Pull only; apply only payloads signed by keys the server does not hold.

### Anti-Pattern 8: Hash chain with no external anchor
**Why it's wrong:** The operator, or an attacker, can truncate or rewrite and re-hash. Nobody outside can tell.
**Do this instead:** Merkle log, signed checkpoints, agent and CLI consistency checks, an independent witness.

### Anti-Pattern 9: No break-glass
**Why it's wrong:** CA outage or bad KRL means lockout from the fleet that hosts the CA.
**Do this instead:** An offline break-glass CA in `TrustedUserCAKeys` (touch-required, ≤1h certs, alerting principal), plus console-access runbooks.

---

## Integration Points

### External services

| Service | Integration pattern | Notes |
|---------|---------------------|-------|
| OpenSSH sshd (all platforms) | Managed drop-in (`/etc/ssh/sshd_config.d/` where Include exists; otherwise one managed block), files, `sshd -t`, reload | Effective config via `sshd -T`. On Windows, `C:\ProgramData\ssh\sshd_config` with strict ACLs on referenced files. OPNsense/pfSense regenerate sshd_config from their own config, so the agent must hook their mechanism **(needs phase research)** |
| OpenSSH client | Managed `known_hosts` with `@cert-authority`, `RevokedHostKeys`, ssh-agent protocol | Windows agent named pipe `\\.\pipe\openssh-ssh-agent` |
| HSMs | PKCS#11 (generic), YubiHSM native (better audit-log access) | The PKCS#11 module loads into the signer process, so treat the module as part of the TCB |
| FIDO authenticators | Server: WebAuthn RP verification (signer-side verifier). CLI: libfido2 / webauthn.dll / browser loopback | Synced passkeys report signCount 0, so do not rely on counters for clone detection |
| Witnesses | C2SP tlog-witness over HTTPS | Optional public witnesses leak only tree size and hash |
| Notifications | SMTP / webhook (optional) | Never required for core function |

### Internal boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| server ↔ signer | UDS, length-prefixed canonical binary messages, peer-cred check | Versioned protocol. Fuzz the signer's decoder. Later the same protocol can run over a serial or mTLS link to a separate signer box |
| server ↔ agent | HTTPS + mTLS; JSON for telemetry; signed opaque blobs for authority | Agent-side verification never depends on the server's JSON |
| server ↔ CLI/browser | HTTPS; WebAuthn ceremonies | Per-action step-up; CSRF-safe; strict CSP for the UI |
| signer ↔ log storage | Local append-only files, fsync | Server gets read-only replicas |
| root ceremony ↔ system | Signed files | Root keys verify with stock `ssh-keygen -Y verify`, so the ceremony is auditable without our code |

---

## 7. Suggested build order (coarse phases)

The dependency graph drives the order:

```
wire/encoding ─► cert issuance ─► keystore ─► signer + tlog ─► trust bundle/root ceremony
                      │                              │
                      ▼                              ▼
                 KRL builder ───────────────► Linux agent (apply, KRL, host certs) ─► other platforms
                                                     ▲
identity (accounts, WebAuthn) ─► CLI login ─► policy v1 ─► quorum + JIT approvals ─► web UI approvals
                                                                       │
                                     inventory + login reconciliation ◄┘ (needs agent + log)
```

| # | Phase | Delivers | Depends on | Research flag |
|---|-------|----------|-----------|---------------|
| 1 | **Foundations and oracle harness** | Repo, reproducible build, SBOM and signing skeleton in CI; `wire` canonical encoding plus vectors; cert templates signed by a software key; KRL writer; **e2e harness running real sshd (several OpenSSH versions) in containers**, with `ssh-keygen` as oracle | — | Low (standard), but decide the language first (STACK) |
| 2 | **Signer, keystore and audit log** | `sshcm-signer` process, UDS protocol, keystore backends (software, PKCS#11 YubiKey/YubiHSM), serials and nonces, tlog with checkpoints, log-before-release, `sshcm audit verify`, trust-bundle format, offline root ceremony commands (SSHSIG M-of-N), genesis policy | 1 | **High**: Ed25519-via-PKCS#11 maturity, YubiHSM audit-log semantics, systemd sandboxing |
| 3 | **Identity and login vertical slice (MVP)** | Server plus SQLite; local accounts with mandatory WebAuthn (registration via minimal web page); policy v1 (roles to principals, quorum = 1); `sshcm login` putting a cert in ssh-agent; manual host config. First end-to-end SSH login | 2 | **Medium-high**: CLI WebAuthn on Windows, cgo vs static builds, browser-loopback design |
| 4 | **Linux host agent** | Join-token enrollment with pins; mTLS; bundle apply (`TrustedUserCAKeys`, principals files); KRL sync with SSHSIG and atomic apply; host-cert issuance and renewal; client `@cert-authority` and `RevokedHostKeys`; rotation phases; fleet version reporting; break-glass CA. Machine and automation certs reuse this renewal machinery | 2, 3 | Medium: sshd drop-in and Include variance across distros, reload semantics |
| 5 | **Insider resistance** | Quorum-signed policy changes (users, credential binding and reset, admins, roles); JIT and two-person requests bound to digests; revoke-by-one, unrevoke-by-quorum; timelock; notifications; `sshcm-witness` plus cosignature requirement | 3, 4 | Medium: formalise the policy model; write threat-model tests |
| 6 | **Web UI** | Overview (certs, hosts, principals, expiry), approvals inbox with WebAuthn step-up, issue and revoke, audit browser with proof display | 3, 5 (minimal UI exists from 3) | Low-medium (UI phase) |
| 7 | **Visibility: inventory and reconciliation** | Agent inventory scanners, snapshot and diff pipeline, analyzer (weak, unknown, shared, bypass); login reconciliation from sshd logs; HSM-audit reconciliation | 4, 2 | Medium: per-platform log formats, `sshd -T -C` coverage |
| 8 | **Cross-platform agents** | Windows (service, ACLs, `administrators_authorized_keys`, Event Log), macOS (launchd, paths), FreeBSD, OPNsense/pfSense | 4, 7 | **High**: appliance config regeneration, Windows ACL and permission semantics |
| 9 | **Hardening and release** | Fuzzing (wire, KRL, WebAuthn, cert parsers), backup and restore ceremonies (wrapped keys M-of-N), rotation drills, docs and threat model, reproducible signed releases, external security review | all | Medium |

**Ordering rationale:**
- **The signer and the log come before any user-facing feature** because every later feature (login, approvals, revocation, inventory alerts) writes through them. Retrofitting log-before-release or evidence verification is a rewrite.
- **The trust-bundle format and root ceremony belong in phase 2, not later**, because agents (phase 4) pin root fingerprints at enrollment. Changing the trust model after hosts are enrolled means re-enrolling the fleet.
- **The real-sshd oracle harness comes first**, because the project's correctness is defined by stock OpenSSH behaviour across versions and platforms.
- **Quorum (phase 5) comes after a working single-admin slice (3–4)**, but the policy *format* already carries `admin_quorum` and evidence fields from phase 2/3, so phase 5 changes values rather than formats.
- **Inventory and reconciliation come after the agent and the log**, because both are inputs.
- **Non-Linux agents come late** because they are the riskiest platform work and share all logic with the Linux agent. Windows is dogfoodable early on Daniel-PC if desired; a Windows CI runner can come during phase 4.

---

## Sources

Primary or official (checked directly):
- OpenSSH `ssh-keygen(1)`: CA signing with `-D` PKCS#11 and `-U` ssh-agent, KRL spec directives, cert options. https://man.openbsd.org/ssh-keygen
- OpenSSH `sshd_config(5)`: `TrustedUserCAKeys` multiple keys, `RevokedKeys` unreadable means all pubkey auth refused, `AuthorizedPrincipalsFile`/`Command`, `PubkeyAuthOptions`. https://man.openbsd.org/sshd_config
- openssh-portable source: `sshkey.c` (CA must be a non-cert key, no chaining), `auth2-pubkey.c` (CA key checked against RevokedKeys), `auth.c` (login log line with key ID, serial and CA fingerprint). https://github.com/openssh/openssh-portable
- openssh-portable `PROTOCOL.krl`: sections; OpenSSH ≥ 9.4 refuses KRLs with signatures; use SSHSIG. https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl
- OpenSSH 10.1 release notes (Ed25519 PKCS#11, agent socket move, ssh-add cert expiry) and 10.2 notes (PKCS#11 download and agent CA-signing fixes). https://www.openssh.org/txt/release-10.1, https://www.openssh.org/txt/release-10.2
- Ed25519 PKCS#11 enumeration issue on 10.1p1. http://lists.mindrot.org/pipermail/openssh-unix-dev/2025-October/042184.html
- RFC 9591 FROST, whose Ed25519 ciphersuite is RFC 8032 compatible. https://www.rfc-editor.org/info/rfc9591/
- C2SP tlog-witness / tlog-checkpoint. https://c2sp.org/tlog-witness@v1.0.0, https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md
- `golang.org/x/mod/sumdb/tlog`. https://pkg.go.dev/golang.org/x/mod/sumdb/tlog
- Trillian Tessera. https://github.com/transparency-dev/tessera, https://blog.transparency.dev/introducing-trillian-tessera

Web, cross-checked (MEDIUM):
- Teleport CA rotation phases. https://goteleport.com/docs/zero-trust-access/management/security/ca-rotation/
- Teleport HSM support (Enterprise-only). https://goteleport.com/docs/installation/self-hosted/private-keys/hsm/ ; RFD 0025 https://github.com/gravitational/teleport/blob/master/rfd/0025-hsm.md
- step-ca SSHPOP and `step ssh renew`. https://smallstep.com/docs/step-ca/provisioners/, https://smallstep.com/docs/step-cli/reference/ssh/renew/
- Vault Control Groups (Enterprise). https://developer.hashicorp.com/vault/docs/enterprise/control-groups
- YubiHSM 2 audit log, force-audit, M-of-N wrap. https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html, https://www.yubico.com/product/yubihsm-2/
- YubiKey PIV Ed25519 (firmware 5.7+). https://developers.yubico.com/yubico-piv-tool/Release_Notes.html
- kubeadm discovery-token CA pinning. https://github.com/kubernetes/kubernetes/pull/49520
- Go `ssh.NewSignerFromSigner` / `SignCert`. https://pkg.go.dev/golang.org/x/crypto/ssh
- stripe/krl archived; go-authn/krl alternative (maturity unknown, LOW). https://github.com/stripe/krl, https://github.com/go-authn/krl
- Win32-OpenSSH certificate auth wiki. https://github.com/PowerShell/Win32-OpenSSH/wiki/Certificate-Authentication

Unverified or LOW (needs phase research): sshd reading RevokedKeys per auth without reload; Windows blocking non-admin CTAP HID access; TPM Ed25519 availability; exact YubiHSM forced-audit reconciliation semantics.

---
*Architecture research for: self-hosted SSH CA and access manager (ssh-cert-manager)*
*Researched: 2026-10-04*
