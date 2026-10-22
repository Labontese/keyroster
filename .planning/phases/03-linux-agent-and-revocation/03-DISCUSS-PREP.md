# Phase 3: Linux Agent and Revocation - Discussion Prep

These are the questions for `/gsd-discuss-phase 3`. Each has a short set of options and Claude's recommendation. The reasoning and sources are in `03-RESEARCH.md` (the section of the same number under "Open Questions").

## Facts that frame the questions

1. **OpenSSH re-reads the CA file, the KRL and the principals files on every login attempt.**
   - Confirmed in the source of the current development version and of 9.2p1, 9.6p1 and 10.2p1. A container test must still show it at runtime on each target.
   - Revocations and principal changes need no sshd reload.
   - Host certificate renewals and sshd config changes do need one.
   - Only the development version accepts several KRL files; the released versions take one.
2. **A corrupt or unreadable KRL makes sshd refuse every public key on that host,** including plain `authorized_keys` keys. The agent must test each new KRL with the host's own `ssh-keygen` before installing it.
   - **The CA file is just as fragile:** one unreadable line in it makes every certificate login fail, even with a valid CA key on another line. The agent checks every CA key line before installing, too.
3. **sshd can scope trust to one account** with a `Match User` block, and a `Match` inside our drop-in cannot spill into the main config. Break-glass can therefore be isolated.
4. **A KRL entry by key ID revokes exactly one certificate,** because our key IDs contain the request ID. Revoking a person means revoking all their live serials.
5. **RHEL 8 has no `sshd_config.d`.**
   - Alpine and Arch packaging read drop-ins first (verified in their package sources).
   - For RHEL 9 the only evidence is a changelog line saying the include was moved first; the change itself was not seen (medium confidence).
   - Debian, Ubuntu and Proxmox are documented to do the same, but this is not yet tested.
6. **The probe account as first proposed would not work.** sshd never answers a probe for a locked account or one without a working shell (on hosts without PAM, such as Alpine), nor for an account shut out by `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups`. The self-test would then fail and roll back every change. The account must look valid to sshd but be unable to log in (see question 8). The same lists can also shut out the break-glass account.
7. **Hosts set up by hand in Phase 2 already have our sshd settings** (`50-keyroster.conf`). As planned, the agent would refuse them (see question 19).

## Questions

1. **Root ceremony.** Phase 3 needs a new root-signed bundle and policy: a break-glass CA, the CA rotation states, and permission for host and machine proof-of-possession. Should this be the owed real offline ceremony (v4)?
   - (a) Yes, one ceremony does both.
   - (b) Sign with TEST root C now and do v4 separately.
   - (c) Two ceremonies.
   - *Recommended: (a).*
2. **Agent process model.**
   - (a) One root daemon.
   - (b) An unprivileged network fetcher plus a root applier with no network, which re-verifies everything.
   - *Recommended: (b).*
3. **Agent identity for mTLS.**
   - (a) Self-signed client certificate, pinned at enrollment, with no agent CA.
   - (b) An agent CA on the server.
   - (c) An agent CA in the signer.
   - *Recommended: (a).*
4. **What hosts receive.**
   - (a) The full admin-signed directory (strongest; every host's root sees all users).
   - (b) A per-host extract signed by the signer's ops key (private; the signer becomes trusted for mappings).
   - *Recommended: (a) for now. Revisit before multi-team use.*
5. **Break-glass.**
   - (a) A `Match User` block with its own CA, principals and KRL files.
   - (b) The break-glass CA in the global CA file, with a special principal.
   - *Recommended: (a).*
   - Also: should the emergency account have no sudo, sudo with a password, or passwordless sudo? *Recommended: sudo with a password kept offline with the break-glass key.*
6. **Revoking a person, host or machine.**
   - (a) The signer finds and revokes all their unexpired certificates, and the directory disables them.
   - (b) The CLI lists the serials.
   - (c) Disable only, and wait for expiry.
   - *Recommended: (a).*
7. **CA rotation ceremonies.**
   - (a) Three (add next, switch, retire).
   - (b) Two (add next; switch with a "draining" state and an end date, after which agents drop the old CA by themselves).
   - *Recommended: (b).*
8. **Self-test after each change.**
   - (a) Check only that sshd is up and serves the right host certificate.
   - (b) Also check that a probe certificate would be accepted.
   - (c) Also check that a revoked probe is refused, which proves the KRL is enforced.
   - *Recommended: (c), once per apply.*
   - (c) costs a new signer path: probe certificates from the machine CA, issued to each host by proof of possession, plus a local account `keyroster-probe`. If that is too much for Phase 3, take (a) now and (c) later.
   - The account must **not** be locked: it gets a "nologin" shell and a password field that matches no password (`*`), so sshd answers the probe but nobody can log in. Hosts whose allow/deny lists shut out the probe or break-glass account are detected and refused or reported.
   - Also: should the runbook create the account (the agent only checks it), or the agent itself? *Recommended: the runbook.*
   - Still unknown: whether probes count toward sshd's penalties for failed logins. A test will show it.
9. **Hosts without drop-in support (RHEL 8) or with an unusual config.**
   - (a) Not supported; the agent refuses and explains.
   - (b) The agent edits `sshd_config`.
   - *Recommended: (a). The agent never edits `sshd_config`.*
10. **A host that already sets its own CA, KRL or principals file.**
    - (a) Refuse to manage the host and report it.
    - (b) Override.
    - (c) Merge.
    - *Recommended: (a).* The exception is a host set up with the Phase 2 runbook (question 19).
11. **Client host trust (`@cert-authority` patterns).**
    - (a) The exact host names from enrolled host entries.
    - (b) Wildcards per host group.
    - (c) `*`.
    - *Recommended: (a).*
12. **Machine identities (automation).**
    - (a) Admin-signed machine entries; the machine renews by proving it holds its key.
    - (b) Only through an enrolled host's agent.
    - (c) Admin issues each certificate by hand.
    - *Recommended: (a).*
    - Also: use separate machine roles, or check role TTLs against the machine CA? *Recommended: check against the issuing CA.*
13. **Host certificates.**
    - *Recommended:* 30-day lifetime, renewed at 2/3. Names are typed by the admin at approval: short name, FQDN and tailnet name. No DHCP LAN addresses. Stable tailnet addresses only if you want them.
14. **Timing.**
    - *Recommended:* poll every 60 s ± 10 s; KRL re-signed hourly; host alert when the KRL is 24 h old; the server flags hosts silent for 3 minutes.
    - What revocation delay is acceptable to you?
15. **Host groups per host.**
    - (a) Exactly one.
    - (b) Several.
    - *Recommended: (a) for Phase 3.*
16. **Supported platforms and CI.**
    - *Recommended:* Debian 12+, Ubuntu 24.04+, RHEL/Alma/Rocky 9+, current Alpine and Arch, Proxmox VE 8+.
    - CI tests sshd behaviour in containers. The systemd and OpenRC reload paths stay UNVERIFIED until they run on the dogfood hosts.
17. **RHEL in FIPS mode,** which is expected to reject Ed25519 CAs.
    - (a) Unsupported in Phase 3.
    - (b) Add a P-256 CA generation.
    - *Recommended: (a), documented.*
18. **AGENT-01 says the agent "pins the server key".**
    - (a) Read it as pinning the TLS root CA plus the hostname, as the CLI already does, and reword the requirement.
    - (b) Pin the server's own key, which breaks at every `tailscale cert` renewal.
    - *Recommended: (a).*
19. **Hosts set up by hand in Phase 2.**
    - (a) Refuse them; you undo the Phase 2 setup first.
    - (b) The agent takes over the exact Phase 2 drop-in layout when every file matches what it would write, proves its own settings win, self-tests, and only then removes the old files. Any other layout, including settings placed directly in `sshd_config`, is refused with instructions.
    - (c) Take over anything that looks similar.
    - *Recommended: (b).*
20. **REVOKE-01 says revocation works "from CLI or UI".** The research covers the CLI only.
    - (a) Build a revoke page in Phase 3.
    - (b) Reword REVOKE-01 to the CLI for Phase 3 and move the UI part to Phase 4, the web UI phase.
    - *Recommended: (b). This changes a requirement, so it needs your approval.*
21. **PLAT-01 and the Phase 3 success criterion say "RHEL family".** Questions 9 and 17 exclude RHEL 8 and FIPS mode.
    - (a) Keep the wording and support both.
    - (b) Reword to "RHEL family 9 and later, not in FIPS mode".
    - *Recommended: (b). This changes a requirement and the roadmap, so it needs your approval.*
22. **Binding agents to one installation.** The open blocker from 2026-10-16 (a directory signed for one installation can be replayed as the first directory of another that shares admin keys) also hits agents, which accept their first directory at enrollment.
    - (a) Leave it to Phase 4.
    - (b) Put an installation ID in the root-signed bundle, repeat it in every directory and KRL, and let the agent pin it at enrollment with the root pins.
    - (c) The agent remembers only the first directory it saw.
    - *Recommended: (b). It moves the directory format change of that todo into Phase 3.*

## Also folded in (no decision needed)

- CA rotation (KEY-08) also covers rotating the audit log key: audit verify must accept a log-key change through a root-signed successor and must keep checking certificates from the old and next CA generations. `keyroster root sign --prev` must stop refusing new CA keys ("CA rotation is Phase 3").
- The break-glass test must run on every OpenSSH version in the matrix: OpenSSH 10.4 broke one `Match` setting after a rewrite of its config code.

## Owner actions this phase will need

These are owner-run because the permission classifier refuses them for agents:
- minting join tokens;
- `host approve` and other directory signing;
- the root ceremony;
- the dogfood steps on the laptop, a Proxmox test VM (Ubuntu 26.04, as used in 02-14), the ZimaBoard when it is online (please confirm its distro) and Proxmox itself (please confirm VE 8 or 9);
- approving the requirement rewordings in questions 20 and 21.
