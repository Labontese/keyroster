# Phase 3: Linux Agent and Revocation - Discussion Prep

These are the questions for `/gsd-discuss-phase 3`. Each has a short set of options and Claude's recommendation. The reasoning and sources are in `03-RESEARCH.md` (the section of the same number under "Open Questions").

## Facts that frame the questions

1. **Current OpenSSH re-reads the CA file, the KRL and the principals files on every login attempt.** A container test will settle older versions.
   - Revocations and principal changes need no sshd reload.
   - Host certificate renewals and sshd config changes do need one.
   - Source: OpenSSH source, verified.
2. **A corrupt or unreadable KRL makes sshd refuse every public key on that host,** including plain `authorized_keys` keys. The agent must test each new KRL with the host's own `ssh-keygen` before installing it.
3. **sshd can scope trust to one account** with a `Match User` block, and a `Match` inside our drop-in cannot spill into the main config. Break-glass can therefore be isolated.
4. **A KRL entry by key ID revokes exactly one certificate,** because our key IDs contain the request ID. Revoking a person means revoking all their live serials.
5. **RHEL 8 has no `sshd_config.d`.**
   - RHEL 9, Alpine and Arch packaging read drop-ins first (verified in their package sources).
   - Debian, Ubuntu and Proxmox are documented to do the same, but this is not yet tested.

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
   - (c) costs a new signer path: probe certificates from the machine CA, issued to each host by proof of possession, plus a locked local account `keyroster-probe`. If that is too much for Phase 3, take (a) now and (c) later.
9. **Hosts without drop-in support (RHEL 8) or with an unusual config.**
   - (a) Not supported; the agent refuses and explains.
   - (b) The agent edits `sshd_config`.
   - *Recommended: (a). The agent never edits `sshd_config`.*
10. **A host that already sets its own CA, KRL or principals file.**
    - (a) Refuse to manage the host and report it.
    - (b) Override.
    - (c) Merge.
    - *Recommended: (a).*
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

## Owner actions this phase will need

These are owner-run because the permission classifier refuses them for agents:
- minting join tokens;
- `host approve` and other directory signing;
- the root ceremony;
- the dogfood steps on the laptop, the ZimaBoard (please confirm its distro) and Proxmox (please confirm VE 8 or 9).
