---
phase: 02-passkey-login-mvp
plan: 14
subsystem: homelab-dogfood
tags: [homelab, dogfood, webauthn, login, ssh-agent, audit, windows]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-13 (#53): homelab under bundle v3, keyroster-server with the RP, the owner enrolled with a synced Chrome passkey, role homelab-admin (8 h), homelab.export (12 entries) as the audit baseline"
provides:
  - "A stock OpenSSH host (a Proxmox test VM) trusting the keyroster user CA for account daniel through one sshd drop-in"
  - "The first real end-to-end logins on Windows, corroborated by the signer's log and the host's sshd journal"
  - "Runbook labels for host-setup.md steps 1-4 and for 'Logging in' on Windows"
affects: [AUTH-02, AUTH-03, AUTH-04, PLAT-05, UI-01]

key-files:
  created:
    - .planning/phases/02-passkey-login-mvp/02-14-SUMMARY.md
  modified:
    - docs/runbooks/host-setup.md
    - docs/runbooks/enroll-user.md

plan_head_before: ff87054
completed: null
status: in-progress   # Tasks 1-3 done for Windows; the laptop parts of Task 1 and Tasks 4-6 are pending
---

# Phase 2 Plan 14: Homelab Logins Summary (DRAFT, in progress)

**Status.** Tasks 1-3 are done for Daniel-PC (Windows). The laptop is
offline, so Task 1's laptop steps (CLI install, `keyroster init`, the
`SSH_AUTH_SOCK` record, the GNOME probe if needed) and Tasks 4, 5 and 6
are pending. This draft holds the evidence gathered so far. Addresses,
host names and the RP name are kept only outside the repository, under the
evidence directory `P=$HOME/keyroster-ceremony/phase2`.

## Deviations already decided (STATE.md, commit 1f138f3)

1. **SSH target.** zima-srv has been offline for 16 days. The owner chose a
   Proxmox test VM (Ubuntu 26.04, OpenSSH 10.2p1) as the stock-OpenSSH
   host. Its account is `daniel`, mapped to role homelab-admin in host group
   homelab by directory v6, which the owner signed himself. Where the plan
   says zima, read that VM: `KR_TARGET_SINCE` in kr.env replaces
   `KR_ZIMA_SINCE`, the journal unit is `ssh`, and the accepted line is
   `Accepted publickey for daniel`.
2. **Anchor version.** The plan's `anchor_bundle_version==3` is the 02-13
   plan defect (deferred-items.md). The checks below use
   `bundle_version==3 and anchor_bundle_version==2`.
3. **Laptop.** Offline. Task 4 and 5 wait for it.
4. **Laptop credential.** 02-13 recorded a synced Chrome passkey, not one
   bound to Daniel-PC, so Task 1 step 4 made no invite and Task 3 step 5
   (bind a laptop credential) is N/A: the same credential is meant for the
   laptop.

## Task 1: host preparation (Daniel-PC side)

- `keyroster.exe host ca-key` and `keyroster.exe host principals homelab
  daniel` were rendered on Daniel-PC and copied to the host. The installed
  files are byte-identical to the rendered ones (SHA-256):
  - `/etc/ssh/keyroster_user_ca.pub`
    `5bb94b6f7a7ec078225c0bde8566b19f091cab929ca3934a95459bce85fb6689`
  - `/etc/ssh/principals/daniel`
    `ee09cb0473dbc41c9971d804c743be38517676a0fe277d1f7e76d55faf6cbb44`,
    header `host group homelab, account daniel, directory version 6`,
    principal `role:homelab-admin`.
- `/etc/ssh/sshd_config.d/50-keyroster.conf` holds `TrustedUserCAKeys
  /etc/ssh/keyroster_user_ca.pub` and `AuthorizedPrincipalsFile
  /etc/ssh/principals/%u`, root:root 0644; `/etc/ssh/principals` is
  root:root 0755.
- Files with a `Match` block under `/etc/ssh/sshd_config` and
  `sshd_config.d/`: **0**.
- `sshd_config`'s first setting is `Include /etc/ssh/sshd_config.d/*.conf`.
- `sudo sshd -t` exits 0. `sudo sshd -T -C user=daniel,host=<a>,addr=<a>`
  shows both settings for Daniel-PC's address as the host sees it; in Task 3
  the same check also ran with `laddr` and `lport` from `$SSH_CONNECTION`,
  same result. The laptop's address was not checked (laptop offline).
- sshd was reloaded with `sudo systemctl reload ssh` right after `sshd -t`.
- The key-based control login (`ssh.exe -n -o BatchMode=yes <target> true`)
  still exits 0.
- The host-side output (CA file hash, `sshd -T -C` lines, Match count,
  include line) is kept in `$P/host-prep-windows.txt`, with addresses
  masked, copied from the orchestrator's session output.
- kr.env holds `KR_TARGET_SINCE` (the target VM's clock, CEST) and
  `KR_VM_SINCE` (the signer VM's clock, UTC).

## Task 2: owner on Daniel-PC (owner's answers, `$P/owner-reply-windows.txt`)

- Web sign-in at `/login` in **Chrome** worked; `/account` showed role
  homelab-admin. Edge was not tried.
- Authenticator: a **synced Chrome passkey**, unlocked with **Windows Hello
  face recognition**.
- `order=ok` for both approvals: the page showed the fingerprint first, and
  the Windows Hello prompt appeared only after Approve.
- `ssh ... whoami` through keyroster agent printed `daniel`.
- Listings: the owner ran `ssh-add -l` three times after the 5 m login and
  pasted all three verbatim in the chat; `$P/listing-windows-a.txt` (#1) and
  `$P/listing-windows-b.txt` (#3) are copies of those pasted lines.
  #1 (listing A) and #2 showed both certificates, #3 (listing B) only the
  8 h one.

## Task 3: corroboration

### 1. Signer log

`$P/homelab-after-windows.export` (15 entries, identical to the export
taken right after the logins). `audit verify --json --previous
homelab.export` with pins C and D, threshold 1: `ok` true, 15 entries,
`bundle_version` 3, `policy_version` 2, `anchor_bundle_version` 2,
`kinds`: bundle_install 3, ca_init 1, directory_install 6, issue 3,
login_issue 2; refusals 0. Baseline (homelab.export): login_issue 0. The
`--previous` check proves the new export extends the 02-13 one.

New login_issue entries of the owner (`$P/serials-windows.txt`):

| # | Key ID | Serial | Key fingerprint | valid_after .. valid_before (Unix) | Length |
|---|---|---|---|---|---|
| 13 | `kr2/ca=user/sub=owner/req=d1e7fe3c4758978ebccf922e3ed1b32a/pol=2/dir=6/roles=homelab-admin/ser=1792704938150899` | 1792704938150899 | `SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI` | 1792704638 .. 1792733738 | 8 h + 300 s backdate |
| 14 | `kr2/ca=user/sub=owner/req=0e094411cdbcdd31118322b8d44e6739/pol=2/dir=6/roles=homelab-admin/ser=1792704994430748` | 1792704994430748 | `SHA256:H5CLDznPL8Vy8sZOOC8SivtiZlJDP1BBLS3zdL/lGd8` | 1792704694 .. 1792705294 | 5 m + 300 s backdate |

Both: principals `role:homelab-admin`, directory v6, policy v2, CA
`ecdsa-sha2-nistp256` `SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0`,
evidence `webauthn-assertion/v1`.

### 2. Host sshd journal

`sudo journalctl -u ssh -u sshd --since "$KR_TARGET_SINCE"` on the target,
filtered to `Accepted publickey for daniel` with an owner kr2 key ID, gives
one line (`$P/journal-kr.txt`):

- 2026-10-22 23:35:49 CEST, `ED25519-CERT SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI`,
  key ID `.../ser=1792704938150899`, `(serial 1792704938150899) CA ECDSA
  SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0`. Browser: Chrome.

The 5 m certificate was not used for an SSH login, so it has no journal
line; its corroboration is the export and the agent listings (step 3).

### 3. Expiry

`$P/expiry-windows.env`: FP5M `SHA256:H5CLDznPL8Vy8sZOOC8SivtiZlJDP1BBLS3zdL/lGd8`,
SERIAL5M 1792704994430748, KID5M (taken from the export, exactly one
match) `kr2/ca=user/sub=owner/req=0e094411cdbcdd31118322b8d44e6739/pol=2/dir=6/roles=homelab-admin/ser=1792704994430748`.

Listing A (kr2 lines):

```
256 SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI kr2/ca=user/sub=owner/req=d1e7fe3c4758978ebccf922e3ed1b32a/pol=2/dir=6/roles=homelab-admin/ser=1792704938150899 (ED25519-CERT)
256 SHA256:H5CLDznPL8Vy8sZOOC8SivtiZlJDP1BBLS3zdL/lGd8 kr2/ca=user/sub=owner/req=0e094411cdbcdd31118322b8d44e6739/pol=2/dir=6/roles=homelab-admin/ser=1792704994430748 (ED25519-CERT)
```

Listing B (kr2 lines):

```
256 SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI kr2/ca=user/sub=owner/req=d1e7fe3c4758978ebccf922e3ed1b32a/pol=2/dir=6/roles=homelab-admin/ser=1792704938150899 (ED25519-CERT)
```

KID5M is in A and not in B, B still lists the 8 h certificate, and the
export line for FP5M/SERIAL5M/KID5M spans 600 s. Informational: FP5M
appears in listing A, so this OpenSSH prints the plain key's fingerprint on
a certificate entry.

Caveat: the wall-clock times of listings #2 and #3 (B) were not recorded.
The plan asks for listing B at least one minute after expiry; that margin
is not evidenced, and neither is removal *at* expiry. #2 still showed both
certificates: if #2 was taken after the 5 m certificate's expiry (valid
before 1792705294), the key outlived its certificate in the agent, which
would be a defect. VERIFY3 only proves the key was gone by #3.

**Open question for the owner:** when were listings #2 and #3 taken
relative to the 5 m expiry? Until answered it stays open for Task 5 and the
phase verifier; the laptop run (Task 4) should record listing times.

### 4. Authenticator data (A6)

- Accepted, Chrome on Windows 11, synced Chrome passkey with Windows Hello:
  `authenticator_data_len` 37, `authenticator_flags` 0x1d (UP, UV, BE, BS
  set; AT and ED clear) in both login_issue entries. BE and BS confirm a
  backup-eligible, backed-up (synced) credential.
- keyroster-server journal since `KR_VM_SINCE` (UTC, `$P/journal-server-windows.txt`):
  **no `bad_authenticator_data`**, so no STOP. It holds one
  `web sign-in begin_refused reason=no_usable_passkey` for the user name
  `homelab-admin` (the role name typed as user name, it appears),
  followed by `signin_ok` for `owner`, then two complete `cli login`
  sequences (options, begin, page, approve, redeem). This refusal is the
  server's, not the signer's: audit verify's `refusals 0` counts signer
  refusals only.

### 5. Laptop credential

N/A: no laptop credential was registered (deviation 4).

### 6. enroll-user.md

"Logging in" is labelled as run on Windows in 02-14 with Chrome and a
synced passkey unlocked by Windows Hello. Edge and other browsers, Linux,
macOS, gcr-ssh-agent, the browser opener and the agent auto-start stay
UNVERIFIED.

### 7. Approval order (02-12-R2-F3)

Windows, Chrome: `order=ok` for both approvals. This is the owner's
observation of two approvals in one browser, not a measurement. Every other
browser stays UNVERIFIED for this point.

## Task 1 step 5: host-setup.md

Steps 1-4 are labelled as run on a homelab host in 02-14. "Where the sshd
settings go" is labelled for the drop-in case only (Ubuntu with the
include line, no `Match` block); the other cases stay UNVERIFIED. Step 5
keeps its 02-11 label.

## Verification run (adapted)

| Check | Result |
|---|---|
| T1: per-connection `sshd -T -C` for Daniel-PC's address, principals file is keyroster-rendered | exit 0 (laptop address not checked: laptop offline) |
| T1: `KR_TARGET_SINCE` and `KR_VM_SINCE` in kr.env | exit 0 |
| T1: key-based control login | exit 0 |
| T1: laptop `keyroster version` | not run (laptop offline) |
| T2: `systemctl is-active keyroster-server keyroster-signer` | active, active (run after the logins, not during them) |
| T3-1: audit verify `ok`, `bundle_version` 3, `anchor_bundle_version` 2, login_issue ≥ baseline + 2 | exit 0 |
| T3-2: a Windows serial appears as `(serial <n>) CA` in an owner certificate login in the host journal | exit 0 |
| T3-3: expiry by key ID, listing B keeps a kr2 entry, export line ≤ 600 s | exit 0 |

## Not exercised (UNVERIFIED)

Edge and every browser other than Chrome; a hardware or device-bound
authenticator; Linux and macOS logins; gcr-ssh-agent; the browser opener;
`keyroster login` starting keyroster agent itself; a `Match` block on the
target; host-setup.md step 5 on a real host.

## Pending

- Task 1 laptop steps: CLI install and `keyroster init` on the laptop, its
  TLS pin, `SSH_AUTH_SOCK`, the `sshd -T -C` check for its address, the A3
  probe if 02-02 moved it here.
- Task 4 (owner on the laptop), Task 5 (Linux corroboration,
  needs-hardware.md, ruleset, PR), Task 6.
