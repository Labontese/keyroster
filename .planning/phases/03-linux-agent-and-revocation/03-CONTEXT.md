# Phase 3: Linux Agent and Revocation - Context

**Gathered:** 2026-10-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Enrolled Linux hosts are kept in sync automatically: trusted user CAs, principals files, the KRL and host certificates. Access that is granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. The phase also delivers revocation (certificates, keys, people, hosts, machines) from the CLI, host certificates that remove the TOFU prompt, machine identities for automation, CA rotation without failed logins, and an offline break-glass path.

Requirements: AGENT-01..07, AUTHZ-02, REVOKE-01..04, AUTH-06, KEY-08, BREAK-01, PLAT-01 (two of them reworded by the owner, see D-17 and D-18).

Out of scope: any web UI for revocation or host management (Phase 4), Windows/macOS/BSD agents (Phase 5), several host groups per host, a P-256 CA generation for FIPS.

</domain>

<decisions>
## Implementation Decisions

All decisions below were made by the owner on 2026-10-23. Each is the option `03-RESEARCH.md` recommended (its Open Questions section gives the reasoning). The owner's choices, verbatim in Swedish, are in `03-DISCUSSION-LOG.md`.

### Trust and enrollment

- **D-01: One real offline v4 root ceremony carries the Phase 3 fields (OQ1).** The root-signed successor bundle and policy for Phase 3 (break-glass CA, `next`/`retired` CA states, the new proof-of-possession evidence types for hosts and machines, the installation ID of D-04) are signed in the owed real offline ceremony, the v4 rotation from TEST roots C and D. That ceremony also closes KEY-07. Phase 3's homelab dogfood that needs these fields waits for it; the ceremony is owner-run. — **Reversibility:** one-way — real root material is created and the homelab's trust moves to it; undoing means another root rotation.
- **D-02: The agent's mTLS identity is a self-signed client certificate pinned at enrollment; there is no agent CA (OQ3). The agent pins the server's TLS root CA set plus the hostname, as the CLI does (OQ18).** AGENT-01's "pins the server key" is reworded accordingly (owner-approved): the agent pins the TLS root SPKI set and hostname, plus the trust-root fingerprints and threshold. — **Reversibility:** costly — changing it later re-enrolls every agent.
- **D-03: Hosts receive the full admin-signed directory (OQ4)** and verify the chain root → policy → admins → directory themselves before rendering principals with `internal/directory.RenderPrincipalsFile`. Root on every enrolled host can read the whole user and role list; revisit before several teams share one installation (deferred idea). — **Reversibility:** costly — a per-host extract would add a new signed format and move trust to a signer key.
- **D-04: An installation ID binds agents to one installation (OQ22).** It is set in the root-signed bundle, repeated in every directory and every KRL manifest, and pinned by the agent at enrollment together with the root pins. A document whose installation ID differs is refused. This pulls the directory format change of the 2026-10-16 todo ("Bind admin-signed directories to a deployment") into Phase 3. — **Reversibility:** one-way — it changes signed document formats (bundle, directory, KRL manifest) that are then deployed and pinned.

### The agent on the host

- **D-05: Two processes: an unprivileged network fetcher and a root applier without network access (OQ2).** The applier re-verifies everything the fetcher hands it and writes only an allowlist of paths. Only the applier may exec (`sshd -t/-T`, `ssh-keygen -Q`, the service manager), with fixed argv and absolute paths, under a narrow dependency-firewall allowlist with a test that pins every exec site. The fetcher gets no `os/exec`. — **Reversibility:** costly — merging or splitting processes later changes units, IPC and the threat model.
- **D-06: Full self-test after every apply, with a probe account the runbook creates (OQ8).** After each change the agent checks that sshd answers with the right host certificate, that a probe certificate is accepted and that a revoked probe certificate is refused (proving the KRL is enforced); otherwise it rolls back. Probe certificates come from the machine CA, issued to each host by proof of possession (a new signer path). The local account `keyroster-probe` is created by the host-setup runbook and only checked by the agent; it has a nologin shell that exists and is executable and a password field of `*` (not `!`, not locked, no expiry), so sshd answers the probe but nobody can log in. Hosts whose `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` shut out the probe or break-glass account are detected with `sshd -T -C` and refused or reported. Whether probes count toward `PerSourcePenalties` is unknown and settled by a test.
- **D-07: Unsupported or conflicting sshd configurations are refused with an explanation (OQ9, OQ10).** The agent never edits `sshd_config`; it works only through a drop-in. A host without `sshd_config.d` (RHEL 8) or one that already sets its own `TrustedUserCAKeys`, `RevokedKeys` or `AuthorizedPrincipalsFile` is refused and the report says what is in the way and how to fix it. The only exception is D-08.
- **D-08: Hosts set up by hand in Phase 2 are taken over only when their layout is exactly the Phase 2 runbook's (OQ19).** Every file must match what the runbook wrote (`50-keyroster.conf`, `keyroster_user_ca.pub`, `/etc/ssh/principals/*`). The agent proves with `sshd -T -C` that its own settings win, self-tests, and only then removes the old files. Any other layout, including settings placed directly in `sshd_config`, is refused with instructions. The two dogfood hosts set up in 02-14 (the Proxmox test VM and zima-srv) are the test cases.

### Revocation and timing

- **D-09: Revoking a person, host or machine revokes all their unexpired certificates (OQ6).** The signer finds every live serial for the subject in its own log and adds them to the revocation set; the directory disables the subject so nothing new is issued. One CLI command. A KRL entry by key ID matches exactly one certificate (our key IDs contain the request ID), so revocation by subject works by serials. The revoke request carries admin evidence.
- **D-10: Revocation delay of about one minute (OQ14).** The agent polls every 60 s ± 10 s (pull-only, no inbound port). The KRL is re-signed hourly even without changes, with a signed issue time; the host alerts when its KRL is 24 h old and never locks out because of age; the server flags hosts silent for 3 minutes.
- **D-11: A host belongs to exactly one host group in Phase 3 (OQ15).** Several groups per host is a deferred idea.
- **D-12: REVOKE-01 is CLI-only in Phase 3; the UI part moves to Phase 4 (OQ20).** Owner-approved requirement change: REVOKE-01 is reworded for Phase 3 and the "or UI" part is added to Phase 4's scope (the web UI phase).

### Certificates, break-glass and platforms

- **D-13: Break-glass uses a `Match User` block with its own files, and sudo with a password kept offline (OQ5).** The emergency account gets its own `TrustedUserCAKeys` (the offline break-glass CA only), its own principals file and its own KRL inside a `Match User` block in the agent's drop-in, so a broken main KRL or CA file cannot lock it out and the break-glass CA grants nothing else. Its sudo needs a password stored offline with the break-glass key. The break-glass test runs on every OpenSSH version in the CI matrix (OpenSSH 10.4 broke a `Match` setting once).
- **D-14: CA rotation takes two root ceremonies (OQ7).** The first adds the `next` CA, which every host trusts alongside the active one; the second switches to it with a "draining" state and an end date, after which agents drop the old CA by themselves. Heartbeats show when every host has converged. Rotation also covers the audit log key: audit verify must accept a log-key change through a root-signed successor and keep checking certificates from both generations, and `keyroster root sign --prev` must stop refusing new CA keys.
- **D-15: Machine identities are admin-signed directory entries that renew by proof of possession (OQ12).** A machine renews its day-scale certificate by proving it holds its key. Role TTL caps are checked against the issuing CA (machine CA) instead of introducing separate machine roles.
- **D-16: Host certificates last 30 days and are renewed at two thirds of their life (OQ13)** by proof of possession of the host key. Their names are typed by the admin when approving the host: short name, FQDN and tailnet name. No DHCP LAN addresses; stable tailnet addresses only if the admin adds them. Client trust uses exact host names (D-19).
- **D-17: Platform floor: Debian 12+, Ubuntu 24.04+, RHEL/Alma/Rocky 9+, current Alpine and Arch, Proxmox VE 8+ (OQ16).** CI tests sshd behaviour in distro containers. The systemd and OpenRC reload paths stay UNVERIFIED until they have run on the dogfood hosts.
- **D-18: RHEL 8 and RHEL in FIPS mode are not supported in Phase 3 (OQ17, OQ21).** Owner-approved requirement change: PLAT-01 and Phase 3 success criterion 1 are reworded from "RHEL family" to "RHEL family 9 and later, not in FIPS mode". Both exclusions are documented.
- **D-19: The client's `@cert-authority` line lists the exact host names of enrolled hosts (OQ11)**, from the directory's host entries, and is rewritten when a host is added or removed. No wildcards, no `*`.

### Documentation

- **D-20: Every plan that changes a step an operator or user performs updates its runbook in the same PR**, labelled as run (where and when) or UNVERIFIED (the documentation convention in ROADMAP.md, 2026-10-23). After Phase 3 is verified, a short README with a quickstart (server, signer, agent, first certificate) is written.

### Claude's Discretion

The planner and researcher decide, within the decisions above: the join-token format and lifetime, the IPC between fetcher and applier, the drop-in file names and layout, the heartbeat payload, the KRL manifest format and namespace, the leaf kinds and verify rules for the new audit entries, plan decomposition and waves.

### Folded Todos

These pending todos are folded into Phase 3's plans (owner choice, 2026-10-23). Each todo file holds the full problem statement.

- **Phase 2 code follow-ups:**
  - `.planning/todos/pending/2026-10-23-recompute-agent-lifetime-before-add.md` (review E-IN-02: the Windows agent lifetime is computed before the agent starts).
  - `.planning/todos/pending/2026-10-23-cli-checks-the-agent-before-issuance.md` (review E-IN-01: a failed agent check after issuance leaves a logged certificate nobody holds).
  - `.planning/todos/pending/2026-10-23-login-redeem-fits-the-signer-window.md` (review C-IN-01: a redeemed code can reach the signer after its 300 s window).
- **Negative tests** (the condition under which the owner accepted the Phase 2 prohibitions):
  - `.planning/todos/pending/2026-10-23-negative-test-login-never-writes-the-key-to-disk.md`
  - `.planning/todos/pending/2026-10-23-negative-test-no-non-passkey-sign-in-route.md`
- **Documentation fixes:**
  - `.planning/todos/pending/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md` (largely answered by D-09 once revocation by subject exists; the runbooks must say so).
  - `.planning/todos/pending/2026-10-23-restore-runbook-replays-lost-directory-versions.md`
  - `.planning/todos/pending/2026-10-23-record-the-timed-windows-expiry-in-needs-hardware.md`
  - `.planning/todos/pending/2026-10-23-correct-02-13-and-02-14-plan-text-drift.md`
- **Pulled in by D-04:** `.planning/todos/pending/2026-10-16-bind-admin-signed-directories-to-a-deployment.md` (filed for Phase 4; its directory format change now happens in Phase 3).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 3 research and decisions
- `.planning/phases/03-linux-agent-and-revocation/03-RESEARCH.md` — the full research: KRL format, sshd re-read behaviour, distro variance, apply sequence, self-test, host certificates, rotation, break-glass, machine identities, heartbeats, threat model deltas, pitfalls, validation architecture, suggested plan decomposition.
- `.planning/phases/03-linux-agent-and-revocation/03-DISCUSS-PREP.md` — the 22 questions and the facts that framed them.
- `.planning/phases/03-linux-agent-and-revocation/03-DISCUSSION-LOG.md` — the owner's choices, verbatim.

### Scope and requirements
- `.planning/ROADMAP.md` §Phase 3 — goal, success criteria, research notes, documentation convention.
- `.planning/REQUIREMENTS.md` — AGENT-01..07, AUTHZ-02, REVOKE-01..04, AUTH-06, KEY-08, BREAK-01, PLAT-01 (AGENT-01, REVOKE-01, PLAT-01 get reworded per D-02, D-12, D-18).
- `.planning/PROJECT.md` — core value, threat model, constraints.

### Locked decisions from earlier phases
- `.planning/phases/02-passkey-login-mvp/02-CONTEXT.md` — D-01 (two signed layers; agents verify the chain), D-06 (`role:<name>` and `u:<user>` principals, one-way), D-07 (one principals renderer), D-08 (the signer decides principals and TTL caps), D-18 (custody warnings).
- `.planning/STATE.md` §Decisions — Phase 1 and 2 decisions (bundle format, TLS pinning, root rotation, owner-run commands).
- `.planning/research/STACK.md`, `.planning/research/ARCHITECTURE.md`, `.planning/research/PITFALLS.md` — project-wide stack, architecture (authority is a payload signature) and pitfalls.

### Runbooks the phase changes or replaces
- `docs/runbooks/host-setup.md` — the Phase 2 manual layout the agent takes over (D-08); becomes the agent install and probe-account runbook.
- `docs/runbooks/root-ceremony.md` and `docs/runbooks/ceremony-transcript-template.md` — the v4 ceremony (D-01) and the rotation ceremonies (D-14).
- `docs/runbooks/enroll-user.md` — revocation by subject (D-09) and the folded documentation todos.
- `docs/runbooks/signer-install.md`, `docs/runbooks/server-install.md` — signer and server changes (new evidence types, KRL signing, agent endpoints).

### External specifications
- OpenSSH `PROTOCOL.krl` (rev 1.7) and `PROTOCOL.certkeys` — the KRL encoder and host/user certificates; `ssh-keygen -Q` is the test oracle.
- `sshd_config(5)` — `TrustedUserCAKeys`, `RevokedKeys`, `AuthorizedPrincipalsFile`, `HostCertificate`, `Match`, `Include`, `PerSourcePenalties`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `internal/trust` (bundle.go, policy.go): root-signed bundle and policy with CA roles `user`/`host`/`machine`, states `active`/`next`/`retired` and generations; additive fields use the omitempty last-field pattern so old documents keep their bytes.
- `internal/directory`: the admin-signed directory, `Authorize`, and `RenderPrincipalsFile` (the one principals renderer the agent must use, P2 D-07).
- `internal/sshsig`: SSHSIG signing and verification for new namespaces (KRL manifest, agent documents).
- `internal/signer`: the network-less signer with evidence dispatch per type; new evidence types (host and machine proof of possession, revoke requests) plug in here; `checkBundleKeys` (`internal/signer/trust.go`) must change for rotation.
- `internal/audit` and `internal/tlog`: the Merkle audit log; every new leaf kind needs its verify rule in the same phase.
- `internal/serverclient`, `internal/signerclient`: client patterns for the server API and the signer socket.
- `cmd/keyroster` `host ca-key` / `host principals`: the Phase 2 manual renderers whose output the agent must reproduce byte for byte (D-08).

### Established Patterns
- Canonical JSON plus newline, decoded with `DisallowUnknownFields`; signed documents are versioned and refuse rollback.
- TLS: pin the root CA SPKI set plus hostname, never the leaf (`tailscale cert` rotates keys).
- Static Go, `CGO_ENABLED=0`, Go 1.27.3; dependency firewall and capslock gate new capabilities; `os/exec` is forbidden outside explicit allowlists.
- Dependencies moved since the research: `golang.org/x/crypto` is v0.58.0 (#37), `golang.org/x/sys` v0.49.0, go-winio v0.6.4 (#41). No new third-party module is planned.

### Integration Points
- New binary or binaries for the agent (fetcher and applier, D-05), with systemd and OpenRC units.
- keyroster-server: enrollment with join tokens, mTLS endpoints for agents, heartbeat storage, serving signed blobs (bundle, policy, directory, KRL manifest).
- keyroster-signer: KRL signing with the ops key, revocation by subject from its own log, host and machine certificate issuance by proof of possession, probe certificates.
- keyroster CLI: revoke commands, host approval, `@cert-authority` and revoked-host-keys management on the client (REVOKE-04).
- Dogfood hosts: the laptop (Ubuntu 26.04, GNOME), the Proxmox test VM (Ubuntu 26.04, OpenSSH 10.2p1), zima-srv (Ubuntu 26.04.1, OpenSSH 10.2p1, seen 2026-10-23; often offline) and Proxmox itself (VE 9.2.18 on Debian 13, OpenSSH 10.0p2, read 2026-10-23).

</code_context>

<specifics>
## Specific Ideas

- The owner accepted every recommendation in `03-DISCUSS-PREP.md`; when in doubt, the research's reasoning for that recommendation is the intent.
- Owner-run steps (the permission classifier refuses them for agents): minting join tokens, `host approve` and other directory signing, the v4 and rotation ceremonies, and the dogfood steps on the hosts. Plans must hand these to the owner with exact commands, PowerShell syntax for Daniel-PC.
- Token economy (owner preference, 2026-10-23): reviews are scaled by risk; security code keeps the full review.

</specifics>

<deferred>
## Deferred Ideas

- **A per-host directory extract** signed by the signer instead of the full directory: revisit before several teams share one installation (D-03).
- **Several host groups per host** (D-11).
- **A revoke page in the web UI**: Phase 4 (D-12).
- **A P-256 CA generation for RHEL in FIPS mode** (D-18): a later phase if anyone needs it.

### Reviewed Todos (not folded)
- `2026-10-17` witnessed checkpoints, `2026-10-21` signed install receipts, recovery after an admin-set or quorum change, the custody banner on error pages and from the root-signed bundle, the re-keyed credentials pending check: Phase 4 (their `resolves_phase`). The agent's local state (last bundle, directory and KRL versions) is stored so Phase 4 can add checkpoint witnessing without a migration (03-RESEARCH.md).
- Capping keyroster-server's connections and memory, the software passphrase source: Phase 6.

</deferred>

---

*Phase: 03-linux-agent-and-revocation*
*Context gathered: 2026-10-23*
