# Phase 3: Linux Agent and Revocation - Research

**Researched:** 2026-10-22
**Domain:** host agent (enrollment, pull-only mTLS, signed state, atomic sshd apply), KRL revocation, host certificates, CA rotation, break-glass, machine identities
**Confidence:** MEDIUM overall. The sshd behaviour that drives the design is HIGH (read in OpenSSH source at a pinned commit). Distro packaging is HIGH for the files fetched and MEDIUM elsewhere. The protocol and format proposals are Claude's recommendations, to be decided in discuss-phase.

There is no `03-CONTEXT.md` yet. The constraints below come from ROADMAP.md (Phase 3), REQUIREMENTS.md, PROJECT.md, STATE.md decisions, the Phase 1 and 2 CONTEXT and RESEARCH files, both `deferred-items.md` files and the code on `origin/main` (ff87054). The owner settles the open questions (end of this file and `03-DISCUSS-PREP.md`) in `/gsd-discuss-phase 3`, before planning.

**Evidence labels used below.**
- **VERIFIED:** read in a primary source this session, with the location given.
- **CITED:** from documentation or a secondary source, not checked against code.
- **ASSUMED:** Claude's knowledge or inference, not checked this session.

OpenSSH source references are to openssh-portable `master` at commit `26b1363c7cbf5d01c730f45fc0b4abc5686beaf7` (2026-10-18, `version.h` = OpenSSH_10.6) unless a release tag is named. An independent source check (2026-10-23) also read the tags `V_9_2_P1` (bookworm), `V_9_6_P1` (noble) and `V_10_2_P1` (Ubuntu 26.04) for the re-read behaviour, the KRL parser and the Match copy rules; those results are labelled per tag below. Releases nobody read (9.9p1 c9s, 10.0p1 trixie) stay ASSUMED to match, and every target still needs the integration test in "Validation Architecture".

---

## User Constraints (no CONTEXT.md yet)

### Locked by earlier phases (not re-discussed)

- **The server proposes, the signer disposes.** The signer stays network-less on its Unix socket. New kinds of evidence enter only through the root-signed policy, never through a signer bypass (P1 D-13, P2 CONTEXT).
- **Authority is a payload signature, not the channel** (research ARCHITECTURE.md B5 and B6). mTLS keeps out noise. A change to who can log in is signed by a key the server does not hold.
- **Two signed layers** (P2 D-01).
  - The root-signed policy holds the admins, the quorum, the CA profiles and the WebAuthn RP.
  - The admin-quorum-signed directory holds users, groups, roles and host groups.
  - P2 D-01 says outright that "agents in Phase 3 and auditors will verify this two-layer chain".
- **Principals.**
  - The convention is `role:<name>` and `u:<user>` (P2 D-06, one-way).
  - `internal/directory.RenderPrincipalsFile` is the one renderer, and the agent must use it (P2 D-07).
- **Bundle format.**
  - CA roles are `user`, `host` and `machine`, with states `active`, `next` and `retired` and a generation number (`internal/trust/bundle.go`).
  - The ops key is labelled "KRL authority" (`internal/rootceremony/summary.go:38`).
  - Today `checkBundleKeys` (`internal/signer/trust.go`) requires exactly one active key per role, equal to the key ca-init made. Phase 1 recorded that this changes for rotation in Phase 3 (STATE, 01-07).
- **The KRL encoder is our own** (Roadmap decision; STACK.md), fuzzed and checked against `ssh-keygen -Q`.
- **Audit verify refuses unknown leaf kinds** (02-01). Every new leaf kind needs its verify rule in the same phase.
- **Format conventions.**
  - Signed documents are canonical JSON: `json.Marshal` plus a newline, decoded strictly with `DisallowUnknownFields` (01-06).
  - Additive fields follow the `WebAuthn *WebAuthnRP 'json:",omitempty"'` last-field pattern, so older documents keep their exact bytes (`internal/trust/policy.go`).
- **TLS pinning** (P2 Q1).
  - Clients pin the TLS root CA SPKI set plus the hostname, not the leaf, because `tailscale cert` makes a new key at every renewal.
  - Clients also pin the trust-root fingerprints and threshold.
- **Hardware is optional at every level.**
- **Static Go and process.** `CGO_ENABLED=0`, Go 1.27.3 toolchain, `go 1.26` directive. One binary per role.
- **Process rules.**
  - Repo docs are in English, Conventional Commits, signed commits, PRs to protected `main`.
  - The permission classifier refuses agent runs of admin-signed and credential-minting commands. The owner runs those himself (02-13 deferred item).
- **Unexercised paths are labelled UNVERIFIED** (owner memory).

### Owed work that couples to Phase 3

- **The real offline root ceremony is owed as the v4 rotation from TEST roots C and D** (01-20/01-21, renumbered in 02-13). Phase 3 also needs a root-signed successor: a break-glass CA in the bundle, `next` CA entries, and policy for the new evidence types. See Open Question 1.
- **Phase 4 blockers that touch agents.**
  - Signed install receipts (2026-10-21 todo).
  - Witnessed checkpoints (VIS-02, 2026-10-17 todo).
  - These are not Phase 3 scope, but the agent's local state (last bundle, directory and KRL versions) should be stored so Phase 4 can add checkpoint witnessing without a migration.
  - Binding admin-signed directories to a deployment (2026-10-16 todo, blocker for Phase 4). Agents make it a Phase 3 concern, because an agent pins its trust at enrollment (§Binding the agent to one deployment, OQ22).

---

## Phase Requirements

| ID | Description (REQUIREMENTS.md) | Research support |
|----|-------------------------------|------------------|
| AGENT-01 | Enroll a host with a one-time join token; the agent pins the server key and trust root | §Enrollment and transport. **Reinterpretation:** "server key" is read as the TLS root-CA SPKI pin set plus the hostname (the P2 Q1 rule), because `tailscale cert` rotates the leaf key at every renewal. The owner confirms this reading or rewords the requirement (OQ18) |
| AGENT-02 | Pull-only mTLS, closed set of typed operations, no remote exec, no inbound ports | §Enrollment and transport, the closed operation set |
| AGENT-03 | Apply only CA sets, policy and KRLs signed by the pinned root or delegated keys; refuse unsigned or older | §Signed state the agent applies |
| AGENT-04 | Write sshd config, CA keys, principals and KRL atomically; `sshd -t`; reload; self-test; roll back | §Atomic apply, §Distro variance, §Self-test |
| AGENT-05 | Periodic `sshd -T -C` drift checks | §Drift detection |
| AGENT-06 | Host certificates by proof of possession of the host key | §Host certificates |
| AGENT-07 | Heartbeats with hashes of the applied config, CA set and KRL version | §Heartbeats and convergence |
| AUTHZ-02 | `AuthorizedPrincipalsFile` generated from signed host policy | §Signed state (the directory), renderer reuse |
| REVOKE-01 | Revoke by serial or key ID, or a key, from the CLI or UI | §Revocation model (CLI only). **Proposed rewording:** the UI part moves to Phase 4, the web UI phase; the owner approves (OQ20) |
| REVOKE-02 | KRL from our own encoder, checked with `ssh-keygen -Q`, distributed automatically | §KRL encoder |
| REVOKE-03 | KRL signed with detached SSHSIG, atomic install, last-good copy, rollback refused, no fleet lockout | §KRL encoder, §Atomic apply, Pitfalls 1-3 |
| REVOKE-04 | Clients trust hosts via a CLI-managed `@cert-authority` line and a revoked host keys list | §Client side |
| AUTH-06 | Machine identities get day-scale certificates within role caps | §Machine identities |
| KEY-08 | Rotate a CA key without fleet outage | §CA rotation, including log-key rotation (`anchor.install`, `activeCA`) and lifting the `root sign --prev --ca-pubkeys` refusal |
| BREAK-01 | An offline break-glass CA, distributed by the agent, grants login to a dedicated emergency account only | §Break-glass |
| PLAT-01 | Generic Unix agent on Debian/Ubuntu, RHEL family, Alpine, Arch and Proxmox | §Distro variance, §Migrating Phase 2 hosts. **Proposed rewording:** "RHEL family" becomes "RHEL family 9 and later, not in FIPS mode", here and in success criterion 1; the owner approves (OQ21) |

---

## Project Constraints (from CLAUDE.md)

Security comes before convenience. The threat model covers a compromised CA server, stolen client keys, a malicious insider and the supply chain. The codebase stays small and auditable, with stock OpenSSH only (no patched sshd) and no external services in the core path. Every change goes through a PR to protected `main` with CI passing. GSD workflow applies. The agent is the most privileged new component (root on every enrolled host), so Pitfall 2 of PITFALLS.md ("the agent becomes root-on-every-host for whoever owns the server") is the governing risk of this phase.

---

## Summary

Phase 3 adds a fourth binary, `keyroster-agent`. It enrolls a host with a join token, pulls signed state over mTLS, and makes sshd enforce it.

What it pulls and checks:
- the root-signed bundle and policy;
- the admin-signed directory;
- an ops-key-signed KRL.

It verifies every signature itself against the trust-root fingerprints pinned at enrollment.

What it writes:
- `TrustedUserCAKeys`;
- one `AuthorizedPrincipalsFile` per account;
- the KRL;
- a host certificate;
- a single sshd drop-in.

Files are swapped in atomically. sshd is reloaded only when the drop-in or the host certificate changes. The agent then proves the result with a self-test and rolls back on failure.

**Primary findings** (each is detailed below):

1. **sshd re-reads all three trust files on every authentication attempt** [VERIFIED in source for master, 9.2p1, 9.6p1 and 10.2p1; the runtime integration test is still required]. So CA-set, principal and KRL updates need **no reload**: a reload is a risk we can avoid for the most frequent change.
   - `TrustedUserCAKeys` is `fopen`ed by `sshkey_in_file` (authfile.c:383, body read in master), called from auth2-pubkey.c:564 in master, :504 in 9.2p1, :500 in 9.6p1 and :535 in 10.2p1.
   - The `RevokedKeys` file is loaded by `ssh_krl_file_contains_key` (krl.c:1305) through `auth_key_is_revoked` (auth.c:548), for the presented key **and** its CA key: auth2-pubkey.c:833/836 in master, 767/770 in 9.2p1, 763/766 in 9.6p1, 804/807 in 10.2p1.
   - **Only master takes several `RevokedKeys` files** (`SSHCONF_STRARRAY`, servconf.h:226). 9.2p1, 9.6p1 and 10.2p1 hold a single string (`char *revoked_keys_file`, copied with `M_CP_STROPT`). Our drop-in therefore names exactly one KRL path per scope.
   - Principals files are opened by `auth_openfile` (auth2-pubkeyfile.c:455) in master, and by `auth_openprincipals` from auth2-pubkey.c (9.2p1:334, 9.6p1:328, 10.2p1:350) in the tags.
   - sshd_config(5) agrees: the RevokedKeys file "may be consulted for each public key authentication attempt ... it should only be atomically replaced".
   - **Host certificates are loaded once, by the listener** (sshd.c:1719, `sshkey_load_public(options.host_cert_files[i] ...)`). A host certificate renewal therefore **does** need a reload.
   - Changing a **path** in the config also needs a reload: the listener passes its parsed config to `sshd-session`.
2. **An unreadable or unparseable KRL refuses every public key** [VERIFIED].
   - `auth_key_is_revoked` returns 1 for any error other than "not revoked" (auth.c:586).
   - That covers plain `authorized_keys` keys and a break-glass certificate whose account uses the same `RevokedKeys`.
   - A file without the KRL magic is parsed as a plain key list (authfile.c:444-461), so an *empty* file revokes nothing.
   - The agent must therefore check every new KRL **with the host's own `ssh-keygen -Q`** before the swap, not only with our parser.
   - **The CA file has the same failure mode, for certificate logins** [VERIFIED, source check 2026-10-23]. `sshkey_in_file` (authfile.c:371-421) jumps to `out` on the first line `sshkey_read` cannot parse and returns that error, so one unparsable line in `TrustedUserCAKeys` fails **every** certificate login for the scope that names the file, even when a valid CA key sits on a later line. The one exception is `SSH_ERR_KEY_LENGTH`, which skips the line (authfile.c:410). Plain `authorized_keys` keys never consult the CA file and are unaffected.
   - So the agent validates every line of every CA file before the swap, just as it does the KRL. It renders each line from a parsed bundle key (`ssh.MarshalAuthorizedKey`, no comments it did not write), and checks every key with the host's own `ssh-keygen -l` on a one-key file, because the host's OpenSSH may lack a key type our Go code accepts. The exact command is a planner detail; whether `ssh-keygen -l` on a multi-line file fails on one bad line is UNVERIFIED, hence one key per check.
3. **`Match` blocks can scope trust per account, and an `Include`d file cannot leak a `Match` into the main file** [VERIFIED].
   - `TrustedUserCAKeys`, `RevokedKeys` and `AuthorizedPrincipalsFile` are all `SSHCFG_COPY_MATCH` (servconf.h:226-230).
   - Values set by a matching block override the global ones (`parse_server_match_config`, servconf.c:2716-2725, with lines outside Match inactive during the re-parse, servconf.c:4139).
   - `Include` restores the containing file's Match state after each included file ("Don't let included files clobber the containing file's Match state", servconf.c:2199-2219).
   - This is what makes a safe break-glass design possible: a `Match User <emergency>` block in our drop-in, with its own CA file, principals file and KRL.
4. **KRL signatures belong outside the file.**
   - PROTOCOL.krl (rev 1.7) says OpenSSH ≥ 9.4 "will refuse to load KRLs that contain signatures" and recommends SSHSIG.
   - **The code does not match that sentence in the versions checked** [VERIFIED, source check 2026-10-23]. 9.6p1 (krl.c:1124) and 10.2p1 (krl.c:1129) parse a signature section without error, and master skips it (krl.c:1149). This does not matter to us: our encoder never writes a signature section, and our strict parser refuses one, so the agent never installs a KRL that carries one.
   - Our KRL travels with a detached SSHSIG by the ops key over a small signed manifest.
5. **A KRL cannot revoke "a user".**
   - kr1/kr2 key IDs embed the request ID (`internal/cert/keyid.go`), so a key-ID entry revokes exactly one certificate.
   - KRL has no revoke-by-principal.
   - "Revoke user X" therefore means: disable X in the directory, which stops new certificates, plus revoke every unexpired serial issued to X. The signer has those serials, so it should resolve them (Open Question 6).
6. **Pull-only state can be frozen.** A compromised server can keep serving the last valid KRL forever; monotonic version checks stop rollback, not freeze. Recommendation: the signed KRL manifest carries `issued_at`, the signer re-publishes on a schedule, and the agent alerts locally and in heartbeats when the KRL is stale. The agent never fails closed on staleness, because that would turn a server outage into a fleet lockout.
7. **Distros differ in ways that break naive reloads.**
   - Arch's unit is `Type=notify-reload`, so `systemctl reload` sends SIGHUP with **no** `sshd -t`.
   - Debian and Ubuntu run `sshd -t` in `ExecReload`, and so does Alpine's OpenRC `reload()`.
   - RHEL and Fedora send a plain `kill -HUP`.
   - SIGHUP makes the listener `execv` itself (sshd.c:515-527). A broken config at that moment means **no listener**. Existing sessions survive because the units set `KillMode=process`.
   - The agent therefore always runs `sshd -t` itself, with the exact binary the service runs (Alpine can run `/usr/sbin/sshd.pam`).
8. **RHEL 8 has no drop-in directory.**
   - c8s ships OpenSSH 8.0p1, and its spec has no `sshd_config.d` [VERIFIED, c8s `openssh.spec`].
   - c9s ships 9.9p1 and installs `50-redhat.conf` into `sshd_config.d` (c9s spec line 655), and its `%post` may create `25-permitrootlogin.conf` (line 714) [VERIFIED, c9s spec]. `40-redhat-crypto-policies.conf` is **Fedora only** (Fedora spec line 360), not c9s. That the `Include` comes first on c9s rests only on the changelog line "Move sshd_config include before any other definitions" (c9s spec line 1246); the patch text was not seen [MEDIUM].
   - Debian, Ubuntu, Arch (prepended by its PKGBUILD) and Alpine (`include-config-dir.patch`) all put `Include /etc/ssh/sshd_config.d/*.conf` first [VERIFIED for Arch and Alpine; Debian/Ubuntu CITED from packaging and the Phase 2 host-setup runbook].
   - Recommendation: Phase 3 supports only hosts whose effective config honours our drop-in, which `sshd -T` checks, and never edits `sshd_config` itself (Open Question 9).
9. **Host certificate names must come from an admin signature, not from the agent or the server** (Pitfall 8, ARCHITECTURE.md §1). Recommendation: the directory gains a `hosts` section (host name, host key fingerprints, host group, approved certificate principals). The signer issues a host certificate only to a key listed there, and only when the request carries a proof-of-possession signature by that key.

**Primary recommendation:** build the KRL encoder and the signer revocation path first. Then build the agent's apply engine, tested against a container matrix of real sshd versions with no network code involved, and only then the enrollment and transport layer. The apply engine is where lockouts happen, and it can be fully tested offline.

---

## Architectural Responsibility Map

| Responsibility | Component | Authority (who signs) | Notes |
|----------------|-----------|----------------------|-------|
| Trust bundle (CA set incl. `next`, break-glass CA, ops key) | offline root | root threshold SSHSIG (`keyroster/trust-bundle/v1`) | Agent verifies against root pins from the join token |
| Policy (CA profiles, evidence types enabled) | offline root | root SSHSIG (`keyroster/policy/v1`) | Successor needed for new evidence types (OQ1) |
| Directory (users, roles, host groups, **hosts**, **machines**) | admins | admin quorum SSHSIG (`keyroster/directory/v1`) | Agent verifies the chain root → policy → admins → directory |
| Revocation set and KRL | signer | ops key SSHSIG over a KRL manifest (new namespace, e.g. `keyroster/krl/v1`) | Revoke request carries admin evidence (one admin) |
| Host certificate | signer (host CA) | admin-signed host entry plus a host-key PoP evidence | New evidence type and leaf kind |
| Machine certificate | signer (machine CA) | admin-signed machine entry plus a machine-key PoP | New evidence type and leaf kind (OQ12) |
| Transport, storage, fan-out | keyroster-server | none (TLS only) | Stores and serves signed blobs; records heartbeats (its word only) |
| Applying state to sshd | keyroster-agent | verifies everything itself | Only writes an allowlist of paths |
| Client host trust (`@cert-authority`, revoked host keys) | keyroster CLI | root-verified bundle plus ops-signed KRL | REVOKE-04 |

---

## Signed state the agent applies (AGENT-03, AUTHZ-02)

The agent keeps one local state record: pins, last accepted bundle and policy (bytes and signatures), last directory, last KRL manifest, last applied generation, and its host identity. It then applies the following rules.

- **Bundle and policy.** The existing `trust.Verify` / `trust.VerifySuccessor` code applies unchanged.
  - A genesis bundle is checked against the pins.
  - Each later bundle needs `version = prev+1`, the previous hash, and the threshold of the previous **and** new roots.
  - The agent refuses a version that is not newer, and also a successor that skips a version.
  - **Gap:** the server must therefore serve the whole chain since the agent's last version, not only the newest bundle. `handleTrust` serves only the current bundle and policy from the signer's Status today (`internal/server/server.go:196-216`) [VERIFIED].
- **Directory.** The agent verifies it against the policy in force: admin quorum SSHSIG under `keyroster/directory/v1`, version chained by hash (`internal/directory/verify.go`).
  - Today the directory GET endpoint is admin-authenticated (`internal/server/server.go:131`).
  - Agents need their own read path over mTLS.
  - The directory contains every user name, role, WebAuthn credential ID and SPKI. Sending it whole to every host exposes the user list to every host's root. See Open Question 4: full directory, or a per-host projection signed by the ops key.
- **KRL.** The agent verifies the SSHSIG by the bundle's ops key over a canonical manifest:
  - **Manifest fields:** `{krl_version, krl_sha256, issued_at, bundle_version, log_index}`.
  - **Version checks:** `krl_version` must be strictly greater than the stored version. The equal case is allowed only for a re-publish that carries a newer `issued_at`.
  - **Byte checks:** `krl_sha256` must match the bytes, and our parser must parse them.
  - **Pre-swap oracle:** `ssh-keygen -Q -f <candidate> <probe key>` must exit 0 on the host (Pitfall 1).

**Why the agent verifies the admin-signed directory instead of an ops-signed "host policy"** (which ARCHITECTURE.md §5 proposed before the directory existed):
- With the directory, principal mappings are protected even against a compromised signer: the signer cannot forge an admin quorum.
- ARCHITECTURE.md argued the gain is small, because a compromised signer can mint certificates with any principals anyway. But it **cannot** make a host accept a principal that no admin mapped, nor add a CA to `TrustedUserCAKeys`. So the gain is real for the host-side half.
- The cost is the directory exposure in OQ4.

---

## KRL encoder (REVOKE-02, REVOKE-03)

### Format facts [VERIFIED: PROTOCOL.krl rev 1.7, krl.c at the pinned commit]

- **Header.** `uint64 magic "SSHKRL\n\0"`, `uint32 format_version = 1`, `uint64 krl_version`, `uint64 generated_date`, `uint64 flags = 0`, `string reserved`, `string comment`. Then a sequence of `byte type, string data` sections.
- **Section types.** 1 certificates, 2 explicit key, 3 SHA-1 fingerprint, 4 signature (never emit), 5 SHA-256 fingerprint, 255 extension.
- **Certificate section.** `string ca_key` (empty string = all CAs), `string reserved`, then subsections:
  - 0x20 serial list (uint64s);
  - 0x21 serial range (`min ≤ max`; `lo == 0` is refused, krl.c:342);
  - 0x22 bitmap;
  - 0x23 key IDs (one or more strings);
  - 0x39 extension.
- **Serial 0.** A certificate with serial 0 is never matched by serial (krl.c:1199). Our serials come from `internal/serial` (a microsecond clock floor), so they are never 0 [VERIFIED, `serial.go`].
- **Fingerprint sections.** The spec requires hashes in numeric order. The master parser does not appear to enforce it (`blob_section` checks only the length), but older parsers may. The encoder must sort them anyway.
- **Critical extensions.** An unknown critical extension, at section or certificate-subsection level, fails parsing (krl.c:874, krl.c:1053). We emit no extensions.
- **Older parsers.** Unknown section types fail parsing (krl.c:1158). SHA-256 sections need OpenSSH ≥ 7.9 (ssh-keygen(1)). Every Phase 3 target is newer, so this is no constraint.

### What to own

- **`internal/krl`.** Packages are stdlib plus `x/crypto/ssh` (wire encoding of keys) and `cryptobyte`.
  - **Encode:** deterministic output from a sorted revocation set.
    - One certificate section per CA key that has entries, in a fixed CA order.
    - Within a section, serials coalesced into ranges, with no bitmaps. Bitmaps are an optimisation that adds parser surface on old versions; at homelab scale a few hundred serial ranges cost nothing.
    - One key-ID subsection per CA.
    - Explicit-key and SHA-256 sections with sorted entries.
    - Deterministic output means `audit verify` can rebuild the KRL from the log and compare hashes.
  - **Parse:** strict, used by the agent and by fuzzing. It refuses signature sections, extensions, unknown types, trailing data, unsorted hashes, `lo == 0` and `lo > hi`.
  - **Size cap:** for example 4 MiB, checked before parsing.
- **Test oracle** (the Phase 1 pattern, like `internal/sshsig/oracle_test.go`):
  1. Generate random revocation sets.
  2. Encode them.
  3. For each test certificate, `ssh-keygen -Q -f krl cert.pub` must exit non-zero exactly when the set revokes it.
  4. Also dump with `ssh-keygen -Q -l -f krl` and compare the listing with the set.
  - **Reverse direction:** parse KRLs produced by `ssh-keygen -k -s ca.pub spec` (spec lines `serial:`, `id:`, `key:`, `sha256:` from ssh-keygen(1)) and compare semantics, not bytes. ssh-keygen picks bitmaps and ranges by its own heuristics, and `generated_date` differs.
- **Fuzzing:** `FuzzParseKRL` (parse never panics; parse(encode(x)) == x) and `FuzzEncodeKRL` (any valid set encodes to bytes that our parser and the oracle accept), with a corpus in-repo per `scripts/fuzz.sh`.
- **Reference only, not a dependency:** `github.com/go-authn/krl` is now v0.6.1 (proxy.golang.org, 2026-10-12; it was 4 days old at project research). `stripe/krl` is still archived (last pseudo-version 2025-04-03). The STACK.md decision to own the encoder stands.

### Pruning

- A serial or key-ID entry may be removed only after the certificate's `valid_before` (plus the 300 s skew) has passed. The signer computes this from its issuance records.
- Key, host-key and CA-key entries are never pruned.
- Pruning is a new KRL version and needs no special treatment.
- Pitfall 5 of PITFALLS.md: removing an entry early un-revokes the certificate.

---

## Revocation model (REVOKE-01)

- **Request.** A `RevokeRequest` in the existing wire style: tag `keyroster/revoke-request/v1`, request ID, created-at, a target, and admin SSHSIG evidence. The target is one of:
  - `serial(ca_role, serial)`;
  - `key_id(string)`;
  - `key(public key)`: user key, host key, or a CA key;
  - `subject(user | host | machine name)`, resolved by the signer (OQ6).
- **Authority:** **one** admin signature suffices in Phase 3. Revocation is the fail-safe direction (ARCHITECTURE.md §3, principle 3). Un-revoke is not offered in Phase 3; quorum-gated un-revoke is Phase 4 success criterion 3. A mistaken revocation is undone by issuing a new certificate.
- **Signer, in one transaction:**
  1. Verify the evidence.
  2. Append a `revoke` leaf.
  3. Rebuild the KRL from the revocation set.
  4. Sign the manifest with the ops key.
  5. Append a `krl_publish` leaf with `{krl_version, sha256}`.
- **Audit verify:** checks both new leaf kinds, re-derives the revocation set, and recomputes the KRL hash from the log, which the deterministic encoder allows.
- **Server:** stores `{krl, manifest, sig}` and serves them (ETag = `krl_version`).
- **Re-publish for freshness:** a timer sends the signer a `RepublishKRL` request, which carries no evidence and changes nothing but `issued_at`. It is logged in the `krl_publish` leaf, rate-limited and refused when nothing changed and the last publish is younger than the period.
- **Latency SLO:** revocation reaches a host within poll interval + jitter (recommendation: 60 s poll with ±10 s jitter; long-poll is a later optimisation).

---

## Enrollment and transport (AGENT-01, AGENT-02)

### Join token

- **Minting.** An admin mints it with an admin-signed request (the existing admin-api/v1 SSHSIG, 02-07). It records a host group and the expected host name. It is single-use with a TTL of at most 1 h, and the server stores only its SHA-256.
- **Join string contents.** The token, the server URL, the TLS root SPKI pin set (the P2 Q1 rule) and the trust-root fingerprints with threshold, so the agent's first contact is TOFU-free.
- **Format.** One opaque line, base64url of canonical JSON, with a `kr-join-v1:` prefix so tooling can recognise it as a secret. It must never be logged; the classifier rule means the owner handles it.

### Binding the agent to one deployment (OQ22)

The 2026-10-16 todo "Bind admin-signed directories to a deployment" (`.planning/todos/pending/`, `severity: blocker`, `resolves_phase: 4`) found that a directory carries nothing that names the instance it was signed for. The namespace `keyroster/directory/v1` is global, and a v1 directory (all-zero prev) signed for one instance is a valid genesis on any instance whose policy admins overlap (for example staging and prod sharing the owner's admin keys).

Agents inherit this. An agent that accepts "a v1 directory" at enrollment can be handed the genesis directory of another deployment whose admin set overlaps. The root pins in the join token do not prevent it, because they bind the bundle and policy, and the directory carries no field that ties it to them.

Options:
- (a) Leave it to Phase 4, as the todo says. Phase 3 agents then ship with the gap, and Phase 4 must migrate enrolled agents.
- (b) Pull the format part of the todo into Phase 3: add a deployment binding to the directory's signed bytes (the todo's options: SHA-256 of the genesis bundle, of the root set or policy, or the audit log origin; or a per-deployment namespace). The agent pins it at enrollment, next to the root pins, and refuses any directory, KRL manifest or bundle chain that names another.
- (c) Agent-only mitigation: the agent pins the hash of the genesis bundle and the first directory it accepts, and refuses a different genesis later. This stops a later swap, but not a wrong directory at first contact.

**Recommendation: (b).** The agent pins a deployment identity at enrollment: the root pin set plus a deployment ID carried in the root-signed bundle (so it is fixed by the root ceremony of OQ1) and repeated in every directory and KRL manifest. This needs the directory format change from the todo, so it must be defined in Phase 3, not only in Phase 4. The same field is most of what the todo needs on the signer side, so the todo would then shrink to its signer install check. The trade-offs the todo lists (restore, re-bootstrap, promoting staging to prod, and migrating directories already signed) are settled in discuss-phase.

### Enrollment request

The agent:
1. Generates its own Ed25519 identity key, kept root-only under `/var/lib/keyroster-agent/`.
2. Reads the host public keys.
3. Signs `H(tag ‖ token ‖ identity pubkey ‖ host keys ‖ facts)` with **each host key** (SSHSIG, namespace e.g. `keyroster/host-pop/v1`). This proves possession at enrollment.
4. Sends facts: `sshd -V`, distro, the host name as reported, and `sshd -T` excerpts.

The server records a **pending host**. Like `user approve` (P2 D-03), an admin then runs `keyroster host approve <name>`. It shows the host key fingerprints for out-of-band comparison and signs a directory version with the new `hosts` entry: name, host key fingerprints, host group, and approved certificate principals typed by the admin, never taken from the agent. Only then can a host certificate be issued (§Host certificates).

### mTLS without an agent CA (recommendation; OQ3)

- The agent presents a **self-signed** client certificate for its identity key. The server matches the SPKI SHA-256 against the enrolled host record in `tls.Config.VerifyPeerCertificate` (`ClientAuth: RequireAnyClientCert`).
- This needs no agent CA, so there is no fifth online key and no agent-cert renewal.
- Identity key rotation is a typed operation signed by the old key.
- ARCHITECTURE.md B5 proposed an internal X.509 agent CA. The CA adds a key and a renewal loop without adding authority, because B6 puts authority in payload signatures.
- The agent verifies the server with the P2 Q1 rule: a pool built only from the pinned root certificates, plus the hostname.

### The closed operation set (AGENT-02)

All of these are agent-initiated, over HTTPS with mTLS:

| Op | Method/path (proposal) | Payload authority |
|----|------------------------|-------------------|
| enroll | `POST /api/v1/agent/enroll` | join token plus host-key PoP |
| state | `GET /api/v1/agent/state?since=<versions>` | returns bundle chain, policy, directory chain (or projection), KRL plus manifest plus sig; every item signed |
| host-cert challenge | `POST /api/v1/agent/hostcert/begin` | server returns a signer-bound nonce |
| host-cert renew | `POST /api/v1/agent/hostcert/finish` | host-key SSHSIG over the request; the signer verifies |
| heartbeat | `POST /api/v1/agent/heartbeat` | agent identity (mTLS); informational only |
| rotate identity | `POST /api/v1/agent/identity` | old identity key signature |

- There is no endpoint that carries commands, scripts, file paths or templates.
- The agent writes only its allowlist:
  - `/etc/ssh/keyroster/` (generations directory and `current` link);
  - `/etc/ssh/sshd_config.d/<our drop-in>`;
  - the host certificate path;
  - `/var/lib/keyroster-agent/`.
- An `internal/agent/paths` test pins the allowlist, in the spirit of `rootceremony/imports_test.go`.

### Privilege split (OQ2)

The agent needs root to write `/etc/ssh`, read host private keys (for PoP), and reload sshd. Recommendation, following the signer pattern:
- **`keyroster-agent fetch`**, unprivileged (user `keyroster-agent`). It does all network I/O and writes candidate blobs into a staging directory.
- **`keyroster-agent apply`**, root, with no network access (systemd `PrivateNetwork=yes`, `IPAddressDeny=any`). It re-verifies every signature against the pins it alone stores, renders, swaps, reloads and self-tests. It answers PoP challenges through a narrow file or socket protocol: sign this exact canonical request with the host key, under one namespace.

A compromised fetcher or server can then only withhold or delay. Phase 1 already validated the signer's systemd hardening (`systemd-analyze security` threshold 2.0, 01-13), and the apply unit can reuse that approach.

---

## Atomic apply (AGENT-04)

### Layout

```
/etc/ssh/keyroster/                         root:root 0755
  gen/<N>/                                  root:root 0755, never modified after creation
    user_ca_keys                            active+next user CAs + machine CAs (0644)
    revoked.krl                             (0644)
    principals/<account>                    one per mapped account (0644; header-only when unmapped)
    breakglass_ca_keys                      break-glass CA only (0644)
    breakglass_principals                   (0644)
  current -> gen/<N>                        symlink, swapped with rename(2)
  last-good -> gen/<M>
/etc/ssh/sshd_config.d/<prefix>-keyroster.conf   static; references only current/... paths
```

- **One swap, one consistent state.** A new CA set, principals and KRL become visible together with a single `rename(2)` of a new symlink over `current`.
  - The new symlink is created as a temporary name in the same directory first.
  - The agent fsyncs the new directory, renames, then fsyncs `/etc/ssh/keyroster`.
  - sshd opens the files fresh on each authentication, so it sees either the old or the new generation, never a mix (finding 1).
- **When the drop-in changes.** Its content is static and references only `current/...` paths. It changes only when the agent itself is upgraded or break-glass is turned on. Only a drop-in change or a host-certificate change triggers `sshd -t` and a reload.
- **StrictModes.** Principals files go through `safe_path_fd` when `StrictModes` is on (auth2-pubkeyfile.c:488), so every path component must be root-owned and not group- or world-writable. The layout above satisfies this [VERIFIED code path; behaviour through a symlinked directory ASSUMED, so the integration test covers it].
- **SELinux (RHEL family).** Create temporary files **in the target directory**, never in `/tmp`, so they inherit the directory's label. A file renamed from `/tmp` keeps `user_tmp_t`, and sshd would be denied, which is a lockout [ASSUMED from SELinux semantics; verify on Alma or Rocky].

### Apply sequence (dead-man switch)

1. Verify all signed inputs (§Signed state).
2. Render a new generation directory.
3. Validate it:
   - our KRL parser;
   - `ssh-keygen -Q -f revoked.krl <probe.pub>`, which must report not revoked;
   - every line of every CA file (`user_ca_keys`, `breakglass_ca_keys`) parses, with our code and with the host's `ssh-keygen` (finding 2: one bad line fails every certificate login);
   - principals render through `directory.RenderPrincipalsFile`.
4. Write a pending marker `{from: M, to: N, deadline}` to `/var/lib/keyroster-agent/`.
5. Swap `current`.
6. If the drop-in or host certificate changed:
   - run `<sshd binary> -t -f /etc/ssh/sshd_config`;
   - then check `sshd -T` for the expected `trustedusercakeys`, `revokedkeys`, `authorizedprincipalsfile` and `hostcertificate` values (§Drift);
   - then reload (§Distro variance).
7. Self-test (§Self-test).
8. On success, point `last-good` at N and clear the marker. On failure, swap `current` back to M, restore the previous drop-in or host certificate, reload if needed, re-test, and report the failure in the next heartbeat.
9. **Agent start:** if a pending marker exists (the agent crashed mid-apply), roll back to `last-good` before doing anything else.

The agent **never** deletes `authorized_keys`, never changes `PasswordAuthentication`, `AuthorizedKeysFile`, `Port` or `ListenAddress`, and never edits `/etc/ssh/sshd_config` (Pitfall 6).

### First enrollment ordering

Write a generation that already contains a valid (possibly empty) KRL and the CA file **before** the drop-in that names them first appears. Otherwise there is a window where `RevokedKeys` names a missing file, and every public key is refused (finding 2).

### Migrating Phase 2 hosts (OQ19)

Hosts set up by hand with `docs/runbooks/host-setup.md` already set two of our keywords, so OQ10(a) as written would refuse every one of them. The runbook has **two** layouts:
- **Drop-in** (its step 2 under "Where the sshd settings go"): `/etc/ssh/sshd_config.d/50-keyroster.conf` with `TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub` and `AuthorizedPrincipalsFile /etc/ssh/principals/%u`, plus `/etc/ssh/keyroster_user_ca.pub` and one file per account under `/etc/ssh/principals/`.
- **In `sshd_config` itself** (its step 3, for hosts without an `Include` first): the same two lines above the first `Match`.

Options:
- (a) Refuse every host that sets our keywords, and tell the owner to undo the Phase 2 setup first. Simple, but the undo opens a window with no certificate login.
- (b) Adopt the exact Phase 2 drop-in layout, and refuse everything else. The agent recognises it only when every piece matches: the file names above, the drop-in's content equal to the two runbook lines, the CA file holding exactly the active user CA key of the installed bundle (the key compared, not the `(bundle vN)` comment, which `keyroster host ca-key` writes with the bundle version of the day), and each principals file equal byte for byte to `directory.RenderPrincipalsFile` for the installed directory. A principals file rendered from an older directory version does not match; the agent then refuses and tells the owner to re-render first (or to run the agent's dry run, which shows the diff).
- (c) Adopt anything that looks similar. Too loose: it would take over foreign settings, which OQ10 forbids.

**Recommendation: (b).** The sequence is:
1. Write the agent's first generation.
2. Write `00-keyroster.conf`, which wins because it sorts first.
3. Confirm with `sshd -T` and `sshd -T -C` per account that our values are in force.
4. Self-test.
5. Only then remove `50-keyroster.conf`, `/etc/ssh/keyroster_user_ca.pub` and `/etc/ssh/principals/`.

This needs one-time allowlist entries for exactly those three Phase 2 paths, pinned by the path test. The `sshd_config` layout (runbook step 3) cannot be adopted, because the agent never edits `sshd_config` (OQ9); the agent refuses it and prints the lines to remove. The runbook gains a "moving to the agent" section.

---

## Does sshd re-read the files without reload? (the Phase 3 STATE blocker)

**Answer from source: yes for content, no for paths and host certificates.** The table cites master; the source check of 2026-10-23 found the same call sites in 9.2p1, 9.6p1 and 10.2p1 (finding 1 gives the line numbers per tag). That settles the code, not the runtime behaviour on the packaged builds, so the test below stays required.

| Setting | Read when | Source |
|---------|-----------|--------|
| `TrustedUserCAKeys` file content | every cert authentication attempt (`fopen` per call) | auth2-pubkey.c:564 → authfile.c:371-384 `sshkey_in_file` |
| `RevokedKeys` file content | every public key authentication attempt, for the key and for `key->cert->signature_key` | auth2-pubkey.c:833-836 → auth.c:548-587 → authfile.c:438 → krl.c:1297-1305 `sshbuf_load_file` |
| `AuthorizedPrincipalsFile` content | every cert authentication attempt (`open` per call) | auth2-pubkey.c:576-577, 350-379 → auth2-pubkeyfile.c:455-498 |
| `HostCertificate` | once, when the listener starts or re-execs on SIGHUP | sshd.c:1719-1744 |
| any directive or path in sshd_config | listener start or SIGHUP (the listener `execv`s itself, sshd.c:515-527, and passes config to `sshd-session` via rexec state) | sshd.c:776 `send_rexec_state` |

The man page states the design intent for `RevokedKeys` [VERIFIED, sshd_config.5]: "This file may be consulted for each public key authentication attempt ... its contents must be consistent at all times, therefore it should only be atomically replaced and never modified in place while the server is running."

The query path (`have_sig = 0`, PK_OK) also runs `user_key_allowed` (auth2-pubkey.c:290-300), so a revoked key is refused even at the query stage [VERIFIED].

**Integration test that settles it on every target version** (proposed: `test/e2e/noreload_test.go`, run inside each distro container of the matrix):

1. Start the distro's sshd (`sshd -D -e -f cfg`), with `TrustedUserCAKeys`, `RevokedKeys` and `AuthorizedPrincipalsFile` pointing through `current/`. Record its PID.
2. Issue certificate A (CA1, principal `role:t`, serial s1). The login succeeds.
3. Swap to a generation whose KRL revokes s1, with no signal. A new connection with A is refused, and the log shows "revoked by file".
4. Swap to a generation where the principals file lacks `role:t`. Refused. Swap back. Accepted.
5. Swap to a generation where `user_ca_keys` lacks CA1. Refused ("not listed").
6. Swap to a generation whose `revoked.krl` is corrupt (bad section). **Every** public key is refused, including a plain `authorized_keys` key. This pins finding 2 as a regression test of our assumptions.
7. Swap to an empty `revoked.krl`. Accepted (finding 2: non-KRL magic is parsed as a key list).
8. Assert that the sshd PID is unchanged and no SIGHUP was sent.
9. Host-certificate variant: replace the `HostCertificate` file without SIGHUP. `ssh-keyscan -c` still shows the old certificate. After SIGHUP it shows the new one.

Each refusal case gets its own sshd instance or a reset, as already required by 01-04 for `PerSourcePenalties` (OpenSSH ≥ 9.8).

---

## Distro variance (PLAT-01, AGENT-04)

| Distro (current) | OpenSSH | Drop-in `Include` first | Service | Reload behaviour | Notes |
|---|---|---|---|---|---|
| Debian 12 bookworm | 9.2p1 [VERIFIED sources.debian.org] | yes [CITED] | `ssh.service` (`Alias=sshd.service` only when enabled) | `ExecReload=sshd -t` then `kill -HUP` [VERIFIED salsa `ssh.service`] | |
| Debian 13 trixie | 10.0p1 [VERIFIED] | yes [CITED] | as above | as above | `sshd-session` split (≥ 9.8) |
| Ubuntu 24.04 noble | 9.6p1 [VERIFIED Launchpad] | yes [CITED] | **`ssh.socket` activation** (since 22.10) + `ssh.service` [CITED Ubuntu Discourse] | `ExecReload=sshd -t` + HUP [VERIFIED ubuntu/devel `ssh.service`] | `ssh.service` may be inactive until the first connection. A new connection starts it with `ExecStartPre=sshd -t`, so "reload" means: if inactive, do nothing; if active, reload. Never touch `Port`/`ListenAddress` (a generator rewrites the socket) |
| Ubuntu 26.04 | 10.2p1 [VERIFIED Launchpad release pocket] | yes [ASSUMED] | as noble [ASSUMED] | as noble | the owner's laptop, and the Proxmox test VM that 02-14 used as its target host (OpenSSH 10.2p1) while the ZimaBoard was offline |
| RHEL/Alma/Rocky 9 (c9s) | 9.9p1 [VERIFIED c9s spec] | yes [MEDIUM: only the changelog line "Move sshd_config include before any other definitions", spec line 1246; patch text unseen]; installs `50-redhat.conf` (spec line 655), and `%post` may create `25-permitrootlogin.conf` (line 714) [VERIFIED] | `sshd.service` | `kill -HUP`, **no `-t`** [VERIFIED c9s `sshd.service`] | crypto-policies may restrict `CASignatureAlgorithms`, and FIPS mode excludes Ed25519 [ASSUMED]; SELinux labels. `25-permitrootlogin.conf` sorts after `00-` and sets none of our keywords |
| RHEL 8 (c8s) | 8.0p1 [VERIFIED c8s spec] | **no** `sshd_config.d` [VERIFIED] | `sshd.service` | HUP | Unsupported in Phase 3 unless the owner adds `Include` by hand (OQ9) |
| Fedora | current | yes; the include was moved before all other definitions in 8.3p1-3 (2020) [VERIFIED spec changelog]; installs `40-redhat-crypto-policies.conf` and `50-redhat.conf` (Fedora spec lines 360-361) [VERIFIED] | `sshd.service` | HUP, no `-t` | `40-redhat-crypto-policies.conf` is Fedora only, not c9s |
| Alpine (edge) | 10.6p1 [VERIFIED APKBUILD] | yes, via `include-config-dir.patch` [VERIFIED] | OpenRC `sshd` | `reload()` runs `checkconfig` (`sshd -t`) then HUP [VERIFIED `sshd.initd`] | Binary may be `/usr/sbin/sshd.pam`; `ssh-keygen` is in a separate `openssh-keygen` package [ASSUMED], so the agent's pre-swap oracle needs it as a dependency |
| Arch | 10.6p1 [VERIFIED PKGBUILD] | yes, prepended by the PKGBUILD; ships `99-archlinux.conf` [VERIFIED] | `sshd.service` | **`Type=notify-reload`: systemd sends SIGHUP itself with no `-t`** [VERIFIED] | Always run `-t` first ourselves |
| Proxmox VE 8 / 9 | Debian 12 / 13 packages [ASSUMED] | as Debian | `ssh.service` | as Debian | Cluster nodes ssh as root with keys under `/etc/pve/priv/` (root's `authorized_keys` is a symlink) [CITED, MEDIUM]. The agent must not touch `AuthorizedKeysFile`, root's keys or known_hosts. Adding `TrustedUserCAKeys` does not affect plain-key auth |

**Detection rules (recommendation):**
- Find the sshd binary and config from the running service: `systemctl show -p ExecStart,Id ssh.service sshd.service`, or OpenRC `/etc/init.d/sshd` plus `/etc/conf.d/sshd`.
- Never assume `/usr/sbin/sshd`.
- Reload through the service manager when it runs `-t` itself (Debian, Ubuntu, Alpine). Otherwise run `-t` first and then reload (RHEL family, Arch).
- **Drop-in prefix.**
  - Because the first value wins, the drop-in must sort before every other drop-in that sets our keywords: `00-keyroster.conf`.
  - Correctness never rests on the name: after every apply, `sshd -T` must show our values, or it is a failed apply that rolls back.
  - If any other file sets `TrustedUserCAKeys`, `RevokedKeys` or `AuthorizedPrincipalsFile` (outside our break-glass `Match` block), the agent refuses to manage the host and reports it (OQ10). The one exception is the exact Phase 2 runbook layout, which the agent adopts (§Migrating Phase 2 hosts, OQ19).
  - The agent also refuses (or reports) a host whose effective config, for any managed account, the probe account or the break-glass account, has `AllowUsers`, `AllowGroups`, `DenyUsers` or `DenyGroups` that excludes that account (§Self-test, OQ8). It checks with `sshd -T -C user=<account>,...` per account, because these lists can sit inside `Match` blocks.

---

## Drift detection (AGENT-05)

Every apply, plus a timer (recommendation: 15 min), runs:
- `sshd -T`;
- `sshd -T -C user=<u>,host=<h>,addr=<a>,laddr=<l>,lport=<p>` for each mapped account, plus the emergency account. The `-C` spec keywords are VERIFIED in `parse_server_match_testspec`, servconf.c:2729+.

It checks that `trustedusercakeys`, `revokedkeys` and `authorizedprincipalsfile` equal our paths, plus `hostcertificate` when host certificates are on. This catches:
- a `Match` block elsewhere that overrides our values for some users;
- an OS upgrade that drops the `Include`;
- a cloud-init drop-in that sorts first.

Drift is reported in heartbeats with the offending keyword and source. The agent does not "fix" foreign files.

Separately, the agent re-hashes the files of the `current` generation and compares them with its record, to detect local tampering.

---

## Self-test (AGENT-04)

After a change, the agent needs evidence that sshd still accepts what it should and refuses what it should.

- **Listener check.** TCP connect to each sshd listen address from `sshd -T`, read the banner, then an `x/crypto/ssh` handshake that offers certificate host-key algorithms.
  - When a host certificate is installed, the agent checks that the served certificate equals the installed one.
  - This needs no credentials and proves sshd survived the reload.
- **Acceptance probe (optional; OQ8): PK_OK query.**
  - An `x/crypto/ssh` client sends a `publickey` request with `have_sig = 0` for a probe certificate.
  - sshd answers `SSH_MSG_USERAUTH_PK_OK` only if `user_key_allowed` passes: CA listed, not revoked, principal accepted (auth2-pubkey.c:290-300) [VERIFIED].
  - No private key is used, and no session opens.
  - It needs a probe certificate from a trusted CA:
    - the signer issues it at enrollment for principal `keyroster-probe:<host>`;
    - it is mapped only to a dedicated account `keyroster-probe` (see "The probe account" below);
    - it uses a key whose private half the agent holds.
  - A second, **revoked** probe certificate must be refused. That proves the KRL is enforced, which nothing else proves.
- **The probe account, as first described, does not work** [VERIFIED, source check 2026-10-23].
  - PK_OK is sent only when `authctxt->valid` is set (auth2-pubkey.c:298). `valid` comes from `allowed_user` (auth.c).
  - With `UsePAM no` (Alpine's default sshd), `allowed_user` rejects a **locked** account (auth.c:108, `platform_locked_account`, which also counts an expired shadow account as locked).
  - With or without PAM, it rejects an account whose shell **does not exist or is not executable** (auth.c:115-136), and one excluded by `AllowUsers`, `AllowGroups`, `DenyUsers` or `DenyGroups` (auth.c:136 onward).
  - So a "locked account with no shell" never gets PK_OK. On Alpine the positive probe would fail on every apply, and the dead-man switch would **roll back every apply forever**. That is why the design is broken, not merely weak.
  - Hardened hosts with `AllowUsers`/`AllowGroups` lists block the probe account, and also the break-glass account, the same way.
- **Redesign (recommendation).**
  - The probe account must count as valid to sshd while being useless for a login:
    - a shell that exists and is executable but refuses a session, such as `/usr/sbin/nologin` (the path differs by distro, for example `/sbin/nologin` on Alpine, so the agent resolves it and checks it is executable);
    - a password field that is not a lock marker but matches no password, such as `*` rather than `!`. Which strings `platform_locked_account` treats as locked depends on the build (`LOCKED_PASSWD_STRING`/`_PREFIX`/`_SUBSTR`, platform-misc.c:159+), so the matrix tests the chosen value per distro;
    - no shadow expiry date.
  - A certificate accepted for this account still cannot open a shell, and the probe never completes a login anyway (PK_OK only).
  - The agent detects `AllowUsers`, `AllowGroups`, `DenyUsers` and `DenyGroups` with `sshd -T -C user=<account>,...` for the probe and the break-glass account, and refuses to manage the host (or reports that break-glass is excluded) rather than self-testing against a host that can never pass. It never edits these lists.
  - **Who creates the account.** `/etc/passwd` and `/etc/shadow` are outside the agent's path allowlist. Either the runbook or the host's configuration management creates `keyroster-probe` (as for break-glass), and the agent only checks it; or the exec allowlist gains `useradd` with fixed arguments. Recommendation: the runbook creates it and the agent checks it (OQ8).
- **Open: do PK_OK probes cost penalties?** Whether a refused PK_OK query counts as `PerSourcePenalties` authfail is still undetermined (A9). The source check also found that master (not the released versions checked) has a new `PubkeyOptions` option `max-pk-ok`, default 6: the number of public key queries permitted before further queries count as failed authentications against `MaxAuthTries` (sshd_config.5, master). Whether those counted queries also feed `PerSourcePenalties` is undetermined. Two probes per connection stay well under 6. Both are settled by the probe test with `-d` logging, not by reading.
- **The probe certificates are a new issuance path.**
  - The signer must issue user-type certificates *to hosts*. That means its own evidence type (host PoP, as for host certificates), its own leaf kind and audit-verify rule, and a renewal loop.
  - Recommendation: issue them from the **machine** CA, not the user CA. The user CA cap is hours, and a probe for every host would then renew constantly.
  - Principal `keyroster-probe:<host>`, accepted only by the probe account (valid to sshd, nologin shell, unusable password). A compromised host gains nothing from its own probe certificate.
  - This needs a threat-table row (T3-11).
- **The negative probe must not expire into "proof".**
  - A revoked-*serial* probe that has expired is refused for expiry too, and PK_OK does not say why. The refusal would then prove nothing about the KRL.
  - Instead, revoke the probe **key** with an explicit-key KRL entry, which is never pruned, so the refusal can come only from the KRL.
  - Confirm on the host by sshd's "revoked by file" log line (auth.c:569-571) if the agent can read the journal.
  - The matrix must test that an explicit-key entry refuses a *certificate* for that key. `user_key_allowed` checks the certificate key itself (auth2-pubkey.c:833), and `ssh_krl_check_key` checks the plain key for certificates, so this is expected but UNVERIFIED end to end.
- **Cost.** Failed probe attempts count toward `PerSourcePenalties` (OpenSSH ≥ 9.8; authfail 5 s, enforcement after `min:15s` accrues, sshd_config.5) [VERIFIED defaults]. So the negative probe must be rare (once per apply, at most a few per hour) or run against `addr=` loopback with an exemption. Adding `PerSourcePenaltyExemptList` would mean editing global sshd config, so the recommendation is low frequency instead.

---

## Host certificates (AGENT-06)

- **Precondition.** The directory `hosts` entry (admin-signed) lists the host key fingerprints and the approved principals.
- **Renewal.**
  1. The agent asks for a challenge, which is a signer nonce through the server.
  2. It builds a canonical `HostIssueRequest` `{host name, host public key, requested TTL, nonce, created_at}`.
  3. The **apply** process signs it with the host private key (SSHSIG, namespace `keyroster/host-pop/v1`).
  4. The signer checks:
     - the key is listed for that host in the installed directory;
     - the principals equal the directory's list exactly;
     - TTL ≤ the host CA profile cap;
     - the nonce is fresh;
     - then it logs a `host_issue` leaf and signs with the active host CA.
- **Initial issuance.** The first certificate needs nothing more than the approved directory entry plus PoP, because the admin's directory signature is the approval.
- **Lifetime.** Recommendation: 30 d TTL, renewal at 2/3 of the lifetime, with jitter. One certificate per host key type the host serves. `cert.ValidateSubjectKey` accepts Ed25519, ECDSA, sk keys and RSA of at least 3072 bits (`internal/cert/validate.go:66-89`) [VERIFIED]. So an RSA-3072 host key can be certified, and a shorter RSA host key is refused. Whether to certify RSA host keys at all is a planner detail; recommendation: Ed25519 and ECDSA only.
- **Install.** Write `HostCertificate` next to the keys (`/etc/ssh/keyroster/host/<type>-cert.pub`), then `sshd -t`, reload (finding 1), and check the served certificate.
- **Key ID.** A new format is needed. kr2 requires 1-16 roles, which a host or machine certificate does not have. Proposal: `kr3/ca=host/sub=<host>/req=…/pol=…/dir=…/ser=…`. `audit verify` re-proves it from the directory entry, like `login_issue`.
- **Why PoP matters when root on the host already holds the key.** PoP stops anyone who merely *knows* a host's public key (the server, another host) from getting a certificate for it. Combined with admin-signed names, a compromised host can at most renew its own certificate for its own approved names.

---

## Client side (REVOKE-04)

- `keyroster known-hosts sync` writes a managed file (for example `~/.ssh/keyroster_known_hosts`) with one `@cert-authority <patterns> <host CA key>` line per active or `next` host CA, taken from the root-verified bundle.
- It writes a revoked host keys KRL (`~/.ssh/keyroster_revoked_hosts.krl`), verified against the ops key.
- It prints (or, with consent, writes) a `Host` block that adds the managed file via `UserKnownHostsFile` (keeping the default as a second entry) and `RevokedHostKeys`.
- **Patterns** (OQ11): recommendation is the **exact** names from the directory `hosts` entries, not wildcards, so one mis-issued host certificate cannot impersonate arbitrary names (Pitfall 8).
- **`RevokedHostKeys` caveat** [VERIFIED ssh_config.5]: "if this file does not exist or is not readable, then host authentication will be refused for all hosts". Scope it inside the keyroster `Host` block only, and write the file before the block.
- Windows client behaviour on inbox 9.5p2 is UNVERIFIED (Phase 5 territory for the agent; the CLI part runs on Windows now).

---

## CA rotation (KEY-08)

The bundle already has generations and the states `active`, `next` and `retired`.

### Proposed flow (OQ7 settles the number of root ceremonies)

1. **Prepare.** `keyroster-signer ca-rotate prepare --role user` creates generation g+1 in the backend.
   - A root ceremony signs bundle N+1 with g+1 `next`.
   - Agents write active + next into `user_ca_keys`; the CLI adds the next host CA to `@cert-authority`.
   - Heartbeats report bundle N+1 (the server's convergence view).
2. **Switch.** Once every host reports N+1, a root-signed bundle N+2 makes g+1 `active` and g **`draining`**, with `trusted_until` = switch time + role max TTL.
   - The signer issues with g+1 from install time.
   - Agents keep trusting g until `trusted_until`, then drop it locally without another bundle.
3. **Retire.** Optionally, a later bundle marks g `retired`, and the KRL adds the g key (belt and braces).

### Format and code consequences

- `draining` is a new state. Alternatively, keep g as `next` after the switch, which is ambiguous.
- `trusted_until` is a new optional field.
- `checkBundleKeys` must accept several entries per role, with exactly one `active` that the keystore holds.
- `cert.Build` / audit verify must check certificates against the generation active at issue time; the bundle_install leaves already provide this history.
- **Audit verify's anchor** (01-08 SUMMARY, "Next Phase Readiness") needs two changes [VERIFIED in code]:
  - `anchor.install` refuses any log-key change today ("log key change unsupported", `internal/audit/verify.go`, in `install`). It must accept a log-key change that arrives through a valid root-signed successor, so log-key rotation is possible at all. Log-key rotation belongs under KEY-08 for the same reason as CA rotation: the log key is a bundle key, and a compromised or lost log key otherwise forces a new deployment.
  - `activeCA` holds exactly one key per role, the `active` one (`internal/audit/verify.go:83`). It must also cover `next` and `draining`/`retired` entries for as long as certificates from those generations can still be valid, or audit verify will reject issuance leaves signed by the old generation after the switch.
- **`keyroster root sign --prev` refuses `--ca-pubkeys`** with the usage error "a successor carries the CA, ops and log keys of the previous bundle unchanged (CA rotation is Phase 3)" (`cmd/keyroster/root.go:332`, from 01-17/01-18). KEY-08 must lift this: a successor must be able to add `next` CAs, switch states and change the log key, with the ceremony summary showing every key change for the root holders to confirm.
- **Emergency rotation** (CA key compromised) skips step 1. The root signs a bundle with a pre-provisioned spare `active` and the old key `retired`, and the ops key adds the old CA key to the KRL. That KRL entry kills every certificate it signed at once (auth2-pubkey.c:836 checks the CA key against `RevokedKeys`).
- **Convergence is the server's word.** Heartbeats prove nothing to the admin if the server lies. The failure mode is availability only, a premature switch. The integrity direction is protected by root signatures.

---

## Break-glass (BREAK-01)

### Recommended design (OQ5)

- **The CA.** An offline break-glass CA key (FIDO `sk-ssh-ed25519`, PIV, or an age-encrypted software key on offline media, per the hardware-optional rule) is named in the root-signed bundle as a new optional `breakglass` field (the omitempty last-field pattern).
  - `sk-ssh-ed25519@openssh.com` is in the default `CASignatureAlgorithms` [VERIFIED sshd_config.5]. RHEL crypto-policies may differ [ASSUMED].
- **The account.** A dedicated local account (for example `keyroster-breakglass`) with a real shell and the sudo rights the owner decides (OQ5b). It is created by the runbook or the host's configuration management, **not by the agent**.
- **The drop-in block** the agent writes:

  ```
  Match User keyroster-breakglass
      TrustedUserCAKeys /etc/ssh/keyroster/current/breakglass_ca_keys
      AuthorizedPrincipalsFile /etc/ssh/keyroster/current/breakglass_principals
      RevokedKeys /etc/ssh/keyroster/current/breakglass.krl
  ```

  - The global `user_ca_keys` never contains the break-glass CA, so it grants nothing to other accounts.
  - The block replaces the user CA for this account, so normal certificates do not work on it.
  - It has its own small KRL, built only from root-signed data (an empty or tiny KRL), so a broken main KRL cannot lock it out (finding 2).
  - Its own CA file also isolates it from a bad line in the main `user_ca_keys` (finding 2: one unparsable line fails every certificate login for the scope that names the file).
  - The `Match` cannot leak into the main config (finding 3).
  - The account must be valid to sshd (an existing, executable shell; not locked under `UsePAM no`) and must not be excluded by `AllowUsers`, `AllowGroups`, `DenyUsers` or `DenyGroups`, or break-glass fails silently (§Self-test, the probe account). The agent checks this with `sshd -T -C user=keyroster-breakglass,...` and reports it.
  - [VERIFIED: COPY_MATCH and Include scoping. UNVERIFIED end to end, so the integration matrix must test, **per OpenSSH version**: the break-glass cert works for the emergency account, fails for every other account, and keeps working with a corrupt main KRL and a corrupt main CA file. Match handling does regress between releases: the source check of 2026-10-23 found that 10.4 could no longer set `PAMServiceName` inside `Match` after a rewrite of the config code (commit of 2026-08-06). We do not set `PAMServiceName`, but the same kind of regression in the keywords we do set would break break-glass on one version only.]
- **Issuing.** Certificates are issued offline (`keyroster breakglass sign`, on the ceremony machine) with principal `breakglass`, TTL ≤ 1 h. The emergency login is logged by sshd with the CA fingerprint. Detection and alerting is BREAK-02 (Phase 5); in Phase 3 the agent only reports the presence and state of the account.

---

## Machine identities (AUTH-06)

### Options (OQ12)

- **(a) Directory `machines` entries** (admin-signed): name, the automation's SSH public key, granted roles, max TTL ≤ min(role TTL, machine CA cap).
  - The machine renews with a PoP signature by that key (`keyroster/machine-pop/v1`), through an API the CLI exposes (`keyroster machine renew`).
  - The signer issues from the machine CA with a kr3 key ID.
  - Stolen-key risk is bounded by the day-scale TTL plus an explicit-key KRL entry, which also blocks renewal at the signer.
- **(b) Host-bound.** Only the enrolled agent on host X can obtain machine certificates for identities bound to X (mTLS plus host PoP). Tighter, but couples automation to enrolled hosts.
- **(c) Admin-issued only.** The existing `keyroster ca sign --ca machine` (kr1, admin evidence, no roles). It already works, but needs a human every day.

**Recommendation:** (a), with role caps checked against the machine CA profile.

**Gap:** today a role's max TTL is validated against the **user** CA cap (P2 D-07). Machine use needs either machine-only roles or the check against the issuing CA. Planner detail once the owner picks.

---

## Heartbeats and convergence (AGENT-07)

**Heartbeat body** (proposal), signed implicitly by the mTLS identity:
- agent version;
- bundle `{version, sha256}`, policy `{version, sha256}`, directory `{version, sha256}`, KRL `{version, sha256, issued_at}`;
- current generation number and the SHA-256 of each file in it;
- drop-in SHA-256;
- `sshd -V`;
- the relevant `sshd -T` values;
- host certificate `{serial, valid_before}`;
- clock offset against the server's `Date` header;
- the last apply result and last drift result;
- pending-marker state.

**Server side.** Store the latest heartbeat per host and show convergence: "KRL v17 on 3/3 hosts". The UI view is Phase 4 (UI-03); Phase 3 delivers a CLI view, `keyroster host status`.

**Staleness.**
- The agent raises a local alert (journal at `err` level) and flags it in the heartbeat when the KRL manifest's `issued_at` is older than a policy value (recommendation: 24 h, against a 1 h re-publish).
- The server flags hosts whose heartbeat is older than 3 × the poll interval.

---

## Standard Stack

### No new third-party module is needed (recommendation)

| Need | Use | Version | Status |
|------|-----|---------|--------|
| mTLS server and client, pinning | stdlib `crypto/tls`, `crypto/x509` | Go 1.27.3 | in use |
| SSH wire, certs, PoP client probe | `golang.org/x/crypto/ssh` | pinned v0.57.0; **v0.58.0 available** (proxy.golang.org, 2026-10-09) | Check with govulncheck whether the bump is needed; it is a separate quick task if so |
| SSHSIG | `internal/sshsig` | in-repo | reuse |
| KRL | **own `internal/krl`** | n/a | new; oracle `ssh-keygen` |
| systemd notify, journald | do without; `systemctl` via `os/exec` in the apply binary only, with a forbidigo allowlist entry | n/a | `github.com/coreos/go-systemd/v22` v22.7.0 exists but is not needed |
| Unix syscalls (rename, fsync dirs, flock) | `golang.org/x/sys/unix` | pinned v0.48.0 (v0.49.0 available) | in use |

**Package legitimacy.** No new dependency is proposed. If the planner wants `go-authn/krl` as a **test-only** differential oracle, it still enters `go.sum`, `capslock` and Dependabot. The recommendation is to use `ssh-keygen` as the oracle instead, as Phase 1 did for SSHSIG.

**`os/exec` in the agent.**
- The apply binary must run `sshd -t/-T`, `ssh-keygen -Q` and the service manager.
- That is the exact pattern the dependency firewall forbids elsewhere (01-13). It needs an explicit, narrow allowlist: fixed argv, absolute paths resolved once from the service unit, no shell, and a test that pins every exec site.
- The fetch binary gets no `os/exec`.

---

## Threat Model Deltas

| # | New threat | Mitigation in Phase 3 | Residual |
|---|-----------|----------------------|----------|
| T3-1 | Server compromise pushes a CA, principal or KRL removal to hosts | Agent verifies root, admin and ops signatures against pins; allowlisted paths; no exec ops | Server can **withhold or freeze**. Signed `issued_at` + staleness alerts detect it but cannot prevent it |
| T3-2 | Server lies about convergence, so the admin retires the old CA early | `trusted_until` drain in the bundle; the agent drops CAs on its own clock | Availability only |
| T3-3 | Signer compromise publishes a KRL that omits entries (un-revoke) | Logged `krl_publish` with deterministic KRL hash, so audit verify detects it | Detection only until Phase 4 witnesses. Agent-side "never shrink unexpired entries" is not possible without expiry data in the manifest (possible extension) |
| T3-4 | Join token leak lets an attacker enroll a fake host | Single-use, ≤ 1 h, admin approval with host key fingerprints before any host certificate or directory entry | The fake host could read the directory until it is rejected (OQ4) |
| T3-5 | Compromised enrolled host | Can renew only its own host certificate for admin-signed names; can fake its own heartbeats; can read the directory | Directory exposure (OQ4) |
| T3-6 | Agent bug locks out the fleet | Dead-man apply, pre-swap `ssh-keygen -Q`, `sshd -t` with the service's binary, rollback, break-glass with its own KRL, never touch `authorized_keys`/passwords | Console access is the last resort; runbook |
| T3-7 | Local non-root tampering with generation files | Root-owned 0755/0644 tree; hash re-check in drift | none beyond root |
| T3-8 | Network attacker with a mis-issued WebPKI certificate | Root-SPKI pinning (P2 Q1) plus payload signatures | none for authority |
| T3-9 | Agent becomes a remote-exec channel | Closed operation set, allowlisted paths, exec allowlist test, privilege split (OQ2) | Agent supply chain → Phase 6 signed agent updates |
| T3-10 | Break-glass CA misuse | Offline custody, the `Match` scope keeps it to one account, TTL ≤ 1 h | Login alert is Phase 5 (BREAK-02) |
| T3-11 | Probe certificates (if OQ8 b/c) are user-type certificates held by every host | Machine CA, principal `keyroster-probe:<host>` accepted only by the probe account, which sshd counts as valid (so PK_OK works) but which cannot log in: a nologin shell, a non-lock but unusable password (`*`), no expiry; host PoP required; explicit-key revocation of the negative probe; `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` detected with `sshd -T -C`, and such hosts refused or reported | A host's root can use its own probe certificate only against its own probe account on hosts that map it (none, by design). A probe account misconfigured with a real shell would accept a full login with that certificate; the agent checks the shell before every self-test |

---

## Common Pitfalls

1. **A corrupt KRL locks out every key on the host,** including plain `authorized_keys` keys (auth.c:586). Validate with the host's own `ssh-keygen -Q` before the swap, keep last-good, and give break-glass its own KRL.
2. **An empty `RevokedKeys` path or a missing file locks everyone out** (sshd_config.5). Write the file before the directive exists, and never delete a generation that `current` or `last-good` points to.
3. **A reload with broken config kills the listener.** SIGHUP re-execs sshd (sshd.c:515). Arch and RHEL reload without `-t`. Always run `-t` first, with the service's binary.
4. **First value wins and drop-in order.** A `00-` prefix helps, but only `sshd -T` proves it. `50-cloud-init.conf`, `40-redhat-crypto-policies.conf` (Fedora), `50-redhat.conf` and `25-permitrootlogin.conf` (c9s and Fedora) and `99-archlinux.conf` exist.
5. **A `Match` block elsewhere overrides our values for some users.** Run `sshd -T -C` for every managed account.
6. **Ubuntu socket activation.** `ssh.service` can be inactive, so `systemctl reload ssh` fails. Treat inactive as "next connection reads fresh config". Never touch the port settings.
7. **SELinux labels.** Create temporary files in the target directory.
8. **Host certificate needs a reload; KRL does not.** Do not reload for KRL updates (it adds risk for no gain), and do reload for host certificates.
9. **Serial and key-ID semantics.** Key-ID revocation hits one certificate, because IDs embed the request ID. Revoking a user needs signer-side serial resolution.
10. **Pruning early un-revokes.** Prune only after `valid_before` + skew, computed by the signer.
11. **PerSourcePenalties on loopback probes.** Keep negative probes rare.
12. **`RevokedHostKeys` missing on clients refuses all host authentication.** Scope it to the keyroster `Host` block.
13. **A bundle chain gap.** An agent offline across two bundle versions needs the whole chain; the server must serve it.
14. **Proxmox.** Do not touch root's `authorized_keys` or the cluster's known_hosts under `/etc/pve`.
15. **Alpine.** `sshd.pam` vs `sshd`, and the `ssh-keygen` package.
16. **The classifier refuses agent runs of admin-signed commands.** `host approve`, `host-group` changes and join-token minting are owner-run during dogfood. Plan the dogfood steps as owner checkpoints.
17. **One bad line in the CA file fails every certificate login** for its scope (authfile.c `goto out`). Validate every CA key line before the swap, as for the KRL.
18. **A locked or shell-less account never gets PK_OK** under `UsePAM no`, and an `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` exclusion never gets it at all. That breaks the probe self-test (endless rollback) and break-glass. Make the probe account valid to sshd and detect the lists with `sshd -T -C`.
19. **Phase 2 hosts already set our keywords** in `50-keyroster.conf` or in `sshd_config`. Adopt only the exact runbook drop-in; refuse the rest with instructions (OQ19).

---

## Validation Architecture

| Layer | What | Where |
|-------|------|-------|
| Unit and fuzz | `internal/krl` encode and parse (round trip, determinism, refusals); manifest canonical form; directory `hosts`/`machines` validation; apply renderer; path allowlist; exec-site allowlist | `go test`, `scripts/fuzz.sh` |
| Oracle | KRL vs `ssh-keygen -Q`, `-Q -l`, `-k` (both directions) | CI `e2e` job (needs OpenSSH) |
| sshd behaviour matrix | the no-reload test above; a corrupt line in the CA file fails every certificate login; break-glass `Match` (works for the emergency account only, survives a corrupt main KRL and a corrupt main CA file), **run per OpenSSH version** because Match handling regresses between releases (10.4 lost `PAMServiceName` inside `Match` after a config-code rewrite, commit of 2026-08-06); StrictModes through the symlinked generation; PK_OK probe against the redesigned probe account (nologin shell, `*` password) under both `UsePAM yes` and `UsePAM no`, and refusal when `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` exclude it; host certificate reload | Containers: debian:12, debian:13, ubuntu:24.04, ubuntu:26.04, almalinux:9 (or c9s), alpine, archlinux. Sshd started directly (`-D -e`), with no systemd in the container |
| Service-manager reload paths | systemd (`reload` with and without `-t`), OpenRC, Ubuntu socket activation | **UNVERIFIED in CI**: dogfood hosts only (systemd-in-container is possible but adds surface); each path labelled UNVERIFIED until run |
| Signer | revoke, krl_publish, host_issue, machine_issue leaves; audit verify re-derives the revocation set and KRL hash; bundle with `next`/`draining` accepted; break-glass field | existing signer test harness |
| End to end | signer + server + agent in one CI job: enroll → approve (test admin key) → apply → login → revoke → refused after the next poll → rotate CA (prepare/switch) with no failed login | CI e2e |
| Dogfood | owner's Ubuntu 26.04 laptop, a Proxmox test VM (Ubuntu 26.04, OpenSSH 10.2p1, as used in 02-14), the ZimaBoard when it is online (distro to confirm), Proxmox itself; Phase 2 host migration (OQ19); break-glass drill; CA rotation drill; deliberate corrupt-KRL drill on one host | owner checkpoints |

The containerised sshd tests extend the Phase 1 e2e harness (real sshd, `PerSourcePenalties` reset per refusal case, 01-04).

## Environment Availability

The matrix has two halves, and they test different things:
- **Version builds** test sshd *code* across versions.
- **Distro containers** test packaged *config layout* (Include, drop-ins, crypto-policies, binary names).

| Item | Status |
|------|--------|
| CI runners | `ubuntu-24.04` (distro OpenSSH 9.6p1) [VERIFIED `.github/workflows/ci.yml`, `e2e-pkcs11.yml`] |
| Self-built OpenSSH in CI | `scripts/build-openssh.sh` already builds 10.5p1 for e2e [VERIFIED `e2e-pkcs11.yml`]. The same script can build 8.7p1 / 9.2p1 / 9.9p1 for the no-reload test without containers |
| Docker on GitHub-hosted Ubuntu runners | preinstalled [CITED, GitHub runner images; not checked this session] |
| systemd or OpenRC inside CI containers | not available by default, so the reload paths are UNVERIFIED in CI |
| SELinux enforcing | not available in containers; needs an EL9 VM (dogfood or a later lane) |
| Owner hosts | Ubuntu 26.04 laptop (OpenSSH 10.2p1 per Launchpad); a Proxmox test VM with Ubuntu 26.04 and OpenSSH 10.2p1, which 02-14 used as its target host because the ZimaBoard was offline; ZimaBoard **distro unconfirmed**; Proxmox **VE 8 or 9 unconfirmed** |

---

## Open Questions (for discuss-phase; each with options and a recommendation)

1. **Root-signed successor and the owed real ceremony.** Phase 3 needs a root-signed bundle and policy successor: the break-glass CA field, `next` CAs for the rotation drill, and policy enabling host and machine PoP evidence.
   - (a) Fold this into the owed v4 real offline ceremony.
   - (b) Sign it with TEST root C now and keep v4 separate.
   - (c) Do two ceremonies.
   - **Recommendation:** (a). One ceremony both moves the homelab onto real offline roots and adds the Phase 3 fields. Plan it as the phase's last owner checkpoint, with TEST-root rehearsals in CI.
2. **Agent privilege model.**
   - (a) One root daemon with systemd sandboxing.
   - (b) An unprivileged fetcher plus a root, network-less applier.
   - **Recommendation:** (b). It mirrors the signer split, and a fetcher compromise can only delay.
3. **mTLS client identity.**
   - (a) Self-signed client certificate pinned by SPKI at enrollment, with no agent CA.
   - (b) An internal X.509 agent CA held by the server.
   - (c) An agent CA in the signer.
   - **Recommendation:** (a). It has the fewest keys, and authority is in payload signatures anyway.
4. **What host policy the agent receives.**
   - (a) The full admin-signed directory: strongest, but every host's root sees all users and credentials.
   - (b) A per-host projection signed by the ops key: private, but the signer becomes trusted for mappings.
   - (c) The full directory with credentials stripped: needs a second signed form, so it costs as much as (b).
   - **Recommendation:** (a) for Phase 3. Credential SPKIs are public keys, and the homelab is single-tenant. Revisit before multi-team use (Phase 4/6).
5. **Break-glass design.**
   - (a) A `Match User` block with its own CA, principals and KRL files.
   - (b) The break-glass CA in the global CA file with a principal only the emergency account accepts: simpler, but the main KRL can lock it out and its scope rests on the principals file alone.
   - Sub-question 5b: does the emergency account get passwordless sudo, sudo with a password, or no sudo?
   - **Recommendation:** (a), and sudo with a password stored offline next to the break-glass key.
6. **Revoking a user, host or machine.**
   - (a) The signer resolves every unexpired serial of the subject from its issuance table (new `subject` target).
   - (b) The CLI lists serials from an audit export and submits them.
   - (c) Directory disable only, relying on short TTLs.
   - **Recommendation:** (a), plus the directory disable. A user certificate lives hours, but a machine certificate lives days.
7. **CA rotation ceremonies.**
   - (a) Three root-signed bundles (prepare, switch, retire).
   - (b) Two: prepare, then switch with `draining` + `trusted_until`, so agents drop the old CA themselves.
   - (c) A signer-driven switch inside one root-signed plan.
   - **Recommendation:** (b). It is two ceremonies, and the agent drops the old CA on its own.
8. **Self-test depth.**
   - (a) Listener and host certificate check only.
   - (b) Add the positive PK_OK probe certificate.
   - (c) Add the positive and the revoked probe, proving KRL enforcement.
   - **Recommendation:** (c) at apply time only, once per apply, rate-limited (PerSourcePenalties; whether PK_OK queries count is still undetermined, A9).
   - It needs a `keyroster-probe` account and probe certificates, which are a **new signer issuance path**: machine CA, host PoP, a leaf kind and a renewal loop. The negative probe is revoked by key, not by serial.
   - **The account must be valid to sshd, not locked.** A locked or shell-less account never gets PK_OK under `UsePAM no` (Alpine), and the self-test would then roll back every apply (§Self-test). Use a nologin shell that exists and is executable, a password field like `*` (unusable, but not a lock marker), and no expiry. Hosts whose `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` exclude the probe or break-glass account are detected with `sshd -T -C` and refused or reported.
   - Sub-question: who creates the account? (i) The runbook or config management, and the agent only checks it; (ii) the agent runs `useradd` from its exec allowlist. **Recommendation: (i)**, as for break-glass; `/etc/passwd` stays outside the agent's paths.
   - If that path is too much for Phase 3, choose (a) now and add (c) later.
9. **Hosts without a drop-in directory (RHEL 8) or with a non-standard config.**
   - (a) Unsupported in Phase 3: the agent refuses and prints instructions.
   - (b) The agent inserts an `Include` line into `sshd_config`.
   - **Recommendation:** (a). The agent never edits `sshd_config`.
10. **A host that already sets `TrustedUserCAKeys`, `RevokedKeys` or `AuthorizedPrincipalsFile`.**
    - (a) Refuse to manage the host and report.
    - (b) Override through drop-in order.
    - (c) Merge.
    - **Recommendation:** (a). The owner removes the foreign setting, and `sshd -T` proves it. The exception is the exact Phase 2 runbook drop-in, which the agent adopts (OQ19).
11. **Client `@cert-authority` patterns.**
    - (a) The exact host names from directory `hosts` entries.
    - (b) Admin-signed wildcard patterns per host group.
    - (c) `*`.
    - **Recommendation:** (a).
12. **Machine identities.** (a) Directory entries with key PoP renewal; (b) host-bound; (c) admin-issued only. Sub-question: separate machine roles, or check role TTLs against the issuing CA?
    - **Recommendation:** (a), with a role TTL cap checked against the issuing CA's profile.
13. **Host certificate TTL, renewal point and principals.**
    - **Recommendation:** 30 d TTL, renew at 2/3. Principals are the short name, the FQDN and the tailnet name, all admin-typed. No DHCP LAN IPs, because the LAN address of one homelab host already changed via DHCP. Stable tailnet IPs are allowed only if the owner wants them.
14. **Poll interval, re-publish period and staleness threshold.**
    - **Recommendation:** 60 s ± 10 s poll, KRL re-published hourly, agent alert at 24 h, server flags heartbeats older than 3 min.
15. **Host group cardinality.**
    - (a) Exactly one host group per host.
    - (b) Several, with the union rendered.
    - **Recommendation:** (a) for Phase 3. It matches the renderer's signature and keeps mappings legible.
16. **Supported distro floor and the CI matrix.**
    - **Recommendation:** Debian 12+, Ubuntu 24.04+, EL9+, current Alpine, Arch, Proxmox VE 8+. CI tests sshd behaviour in containers; service-manager paths stay UNVERIFIED until dogfood.
    - "EL9+" includes older EL9 minor releases, which shipped OpenSSH 8.7p1 [ASSUMED; c9s is now 9.9p1, VERIFIED]. Either the matrix also builds 8.7p1 (with `scripts/build-openssh.sh`, as e2e does for 10.5p1) or the floor is "current EL9 minor".
17. **CA algorithm for RHEL FIPS hosts.**
    - FIPS mode is expected to reject Ed25519 CAs [ASSUMED]. Either a P-256 user CA generation is available, or FIPS hosts are unsupported.
    - **Recommendation:** document FIPS hosts as unsupported in Phase 3. Verify the crypto-policies `CASignatureAlgorithms` value on a stock EL9 container.
18. **AGENT-01 wording ("pins the server key").**
    - (a) Read it as the TLS root-CA SPKI set plus the hostname, as the CLI does (P2 Q1), and reword the requirement.
    - (b) Pin the leaf key. That breaks at every `tailscale cert` renewal, because it makes a new key each time.
    - **Recommendation:** (a).
19. **Hosts set up by hand in Phase 2** (`docs/runbooks/host-setup.md`: `50-keyroster.conf`, or the same lines in `sshd_config`). OQ10(a) would refuse them all. See §Migrating Phase 2 hosts.
    - (a) Refuse; the owner undoes the Phase 2 setup first.
    - (b) Adopt the exact Phase 2 drop-in layout (names and contents match the rendered files byte for byte, the CA by key), write `00-keyroster.conf`, prove it with `sshd -T`, self-test, then remove the old files. Refuse every other layout, including the `sshd_config` variant, with instructions.
    - (c) Adopt anything similar.
    - **Recommendation:** (b).
20. **REVOKE-01 says "from CLI or UI".** This research covers the CLI only (`keyroster revoke ...`). The web UI arrives in Phase 4.
    - (a) Build a revoke page in Phase 3 on the current minimal UI.
    - (b) Reword REVOKE-01 to "from the CLI" for Phase 3, and add the UI revoke action to the Phase 4 UI requirements (UI-03 or a new ID).
    - **Recommendation:** (b). It is a requirement wording change, so the owner must approve it; the traceability table in REQUIREMENTS.md changes with it.
21. **PLAT-01 and Phase 3 success criterion 1 say "RHEL family".** OQ9 (no RHEL 8, no `sshd_config.d`) and OQ17 (no FIPS mode) narrow that, and OQ16 may narrow EL9 to current minors.
    - (a) Keep the wording and support RHEL 8 and FIPS too (agent edits `sshd_config`, P-256 CA generation).
    - (b) Reword PLAT-01 and success criterion 1 to "RHEL family 9 and later, not in FIPS mode" (plus the EL9 floor from OQ16), with RHEL 8 and FIPS listed as out of scope for Phase 3.
    - **Recommendation:** (b). It is a requirement and roadmap wording change, so the owner must approve it.
22. **Binding agents to one deployment** (the 2026-10-16 todo, a Phase 4 blocker). An agent that accepts a v1 directory at enrollment inherits the genesis-replay-across-installs risk. See §Binding the agent to one deployment.
    - (a) Leave it to Phase 4.
    - (b) Define the deployment binding in Phase 3: a deployment ID in the root-signed bundle, repeated in every directory and KRL manifest; the agent pins it with the root pins at enrollment and refuses anything else.
    - (c) The agent pins only the first genesis it sees.
    - **Recommendation:** (b). It pulls the directory format change of the todo into Phase 3.

---

## Assumptions Log

| # | Assumption | Confidence | How to settle |
|---|-----------|-----------|---------------|
| A1 | Older OpenSSH re-reads the three files per attempt as master does | **Confirmed in source** for master, 9.2p1, 9.6p1 and 10.2p1 (auth2-pubkey.c 767/770, 763/766, 804/807 for the KRL; `sshkey_in_file` for the CA file; `auth_openprincipals` for principals), source check 2026-10-23. 9.9p1 and 10.0p1 not read, ASSUMED. `RevokedKeys` takes several files only in master (STRARRAY); 9.2p1-10.2p1 take one | no-reload integration test per container, still required for runtime behaviour |
| A2 | `safe_path_fd` accepts a principals file reached through the `current` symlink | MEDIUM | integration test with `StrictModes yes` |
| A3 | Match-scoped `TrustedUserCAKeys`/`RevokedKeys` apply before `user_key_allowed` for the emergency account | HIGH from servconf code, UNVERIFIED end to end | break-glass matrix test |
| A4 | Ubuntu 26.04 keeps `ssh.socket` activation | MEDIUM | dogfood laptop (`systemctl status ssh.socket`) |
| A5 | RHEL crypto-policies (DEFAULT) allow Ed25519 CA signatures; FIPS does not | MEDIUM | `sshd -T | grep casignaturealgorithms` in alma:9 |
| A6 | Proxmox root and cluster SSH keys live under `/etc/pve/priv` | MEDIUM | inspect the Proxmox host (owner) |
| A7 | Alpine ships `ssh-keygen` in a separate package | MEDIUM | `apk info -L` in the alpine container |
| A8 | Temp files created in `/etc/ssh/keyroster` get a label sshd can read under SELinux | MEDIUM | alma:9 test with SELinux enforcing (VM, not container) |
| A9 | `PerSourcePenalties` counts a refused PK_OK query as authfail | LOW; **still undetermined** after the source check. Master adds `PubkeyOptions max-pk-ok` (default 6), after which queries count against `MaxAuthTries`; how that interacts with penalties is also undetermined | probe test with `-d` logging |
| A10 | `*` (not `!`) in the probe account's password field is not treated as locked by `platform_locked_account` on every target | MEDIUM (depends on `LOCKED_PASSWD_*` per build) | probe test under `UsePAM no` per distro |
| A11 | The c9s `Include` comes before all other definitions | MEDIUM (changelog line only, patch unseen) | `sshd -T` in an alma:9 container with a test drop-in |

---

## Suggested Plan Decomposition (coarse; for the planner after discuss-phase)

1. `internal/krl` encoder and parser, fuzz targets, `ssh-keygen` oracle tests.
2. Signer: revoke request (wire), revocation store, `revoke` and `krl_publish` leaves, KRL signing with the ops key, re-publish, audit verify rules; CLI `keyroster revoke ...`.
3. Format successors:
   - bundle: break-glass field, `draining` + `trusted_until`, `checkBundleKeys` for generations;
   - policy: host and machine PoP enablement;
   - directory: `hosts` and `machines`;
   - CLI `host approve`, `machine add`.
4. Apply engine (`internal/agent/apply`): generation layout, renderer reuse, pre-swap checks, dead-man, rollback, drift, self-test, distro detection. Container matrix tests including the no-reload test. This plan has no network code.
5. Transport: join token, enrollment, mTLS with SPKI-pinned client certs, agent endpoints on the server, fetch/apply split, heartbeats, `keyroster host status`.
6. Host certificates by PoP (signer evidence, `host_issue` leaf, kr3 key ID, agent renewal and reload).
7. Client side: `keyroster known-hosts sync`, `RevokedHostKeys`.
8. Machine identities (AUTH-06).
9. CA rotation drill (prepare/switch) end to end in CI.
10. Break-glass: offline signing command, agent `Match` block, runbook, drill.
11. Dogfood and the ceremony checkpoint (OQ1): laptop, a Proxmox test VM, the ZimaBoard when online, Proxmox; Phase 2 host migration (OQ19); corrupt-KRL drill; rotation drill; owner-run admin steps.

---

## Sources

### Primary (HIGH)

- **openssh-portable master `26b1363`** (2026-10-18, OpenSSH_10.6):
  - auth.c (`auth_key_is_revoked`, 546-587);
  - auth2-pubkey.c (290-300, 350-379, 545-600, 820-836);
  - auth2-pubkeyfile.c (455-511);
  - authfile.c (`sshkey_in_file` 371-401, `sshkey_check_revoked` 438-461);
  - krl.c (342, 1000-1025, 1085-1170, 1190-1210, 1297-1319);
  - servconf.c (2180-2270, 2716-2738, 4106-4140);
  - servconf.h (226-230);
  - sshd.c (495-527, 776, 1719-1744);
  - PROTOCOL.krl rev 1.7;
  - sshd_config.5 (`RevokedKeys`, `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `Include`, `HostCertificate`, `CASignatureAlgorithms`, `PerSourcePenalties`);
  - ssh_config.5 (`RevokedHostKeys`);
  - ssh-keygen.1 (`-Q`, `-k`, KEY REVOCATION LISTS);
  - auth.c (`allowed_user`, 108, 115-136), platform-misc.c (`platform_locked_account`, 159+), auth2-pubkey.c:298 (PK_OK only when `authctxt->valid`), authfile.c:405-421 (`goto out` on an unparsable CA line), sshd_config.5 (`PubkeyOptions max-pk-ok`) — independent source check, 2026-10-23.
- **openssh-portable release tags `V_9_2_P1`, `V_9_6_P1`, `V_10_2_P1`** (independent source check, 2026-10-23): auth2-pubkey.c (CA file, principals and `auth_key_is_revoked` call sites), servconf.h (`revoked_keys_file` single string), krl.c (signature section parsed: 9.6p1:1124, 10.2p1:1129).
- **The 10.4 `PAMServiceName`-in-`Match` regression** (config-code rewrite, commit of 2026-08-06): as reported by the source check; the commit text was not read for this document.
- **Distro packaging, fetched 2026-10-22:**
  - Debian salsa `debian/systemd/ssh.service`, `ssh.socket`;
  - Ubuntu Launchpad `ubuntu/devel` `ssh.service`, `ssh.socket`;
  - Arch `PKGBUILD` (10.6p1-2), `sshd.service`;
  - Alpine `APKBUILD` (10.6_p1-r1), `sshd.initd`, `include-config-dir.patch`;
  - Fedora rawhide `openssh.spec`, `sshd.service`;
  - CentOS Stream c9s `openssh.spec` (9.9p1; lines 655, 714, 1246), `sshd.service`;
  - CentOS Stream c8s `openssh.spec` (8.0p1).
- **Package version indexes:** sources.debian.org API (openssh per suite); Launchpad `getPublishedSources` (openssh per Ubuntu series).
- **proxy.golang.org `@latest`:** x/crypto v0.58.0, x/sys v0.49.0, go-authn/krl v0.6.1, stripe/krl pseudo-version 2025-04-03, coreos/go-systemd v22.7.0.
- **This repository at ff87054:**
  - `internal/trust` (bundle.go, policy.go);
  - `internal/signer/trust.go` (`checkBundleKeys`);
  - `internal/directory` (directory.go, render.go);
  - `internal/certprofile`;
  - `internal/cert/keyid.go`;
  - `internal/tlog/leaf.go`;
  - `internal/wire`;
  - `internal/serial`;
  - `internal/server/server.go`;
  - `docs/runbooks/host-setup.md`;
  - `.planning` files listed above.

### Secondary (MEDIUM)

- Ubuntu Discourse, "SSHd now uses socket-based activation (Ubuntu 22.10 and later)"; Launchpad bug 2103633 (generator and `AddressFamily`).
- Research ARCHITECTURE.md and PITFALLS.md (2026-10-04), whose source-verified claims were re-checked above where they matter.

### Tertiary (LOW)

- Proxmox `/etc/pve/priv` SSH layout, FIPS/crypto-policies CA algorithm behaviour, PerSourcePenalties accounting for PK_OK queries: from prior knowledge, flagged in the Assumptions Log.

## Metadata

- Research date: 2026-10-22. Updated 2026-10-23 with an independent check against OpenSSH source (master and three release tags) and distro packaging, and with the coverage gaps it found (Phase 2 migration, log-key rotation, requirement wording, deployment binding). Valid until the next OpenSSH release or a change to the bundle or directory formats.
- Inputs not available: no `03-CONTEXT.md`; the owner has not discussed Phase 3.
- No code was changed. No command touched a homelab host.
