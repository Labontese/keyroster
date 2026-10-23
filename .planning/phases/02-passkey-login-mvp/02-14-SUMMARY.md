---
phase: 02-passkey-login-mvp
plan: 14
subsystem: homelab-dogfood
tags: [homelab, dogfood, webauthn, login, ssh-agent, gcr, audit, windows, linux, ruleset]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-13 (#53): homelab under bundle v3, keyroster-server with the RP, the owner enrolled with a synced Chrome passkey, role homelab-admin (8 h), homelab.export (12 entries) as the audit baseline"
provides:
  - "Two stock OpenSSH hosts trusting the keyroster user CA through one sshd drop-in each: a Proxmox test VM (account daniel) and zima-srv (account zima)"
  - "The first real end-to-end logins, on Windows 11 and on Ubuntu 26.04 GNOME, each corroborated by the signer's audit-verified log and the host's sshd journal"
  - "A3 (gcr-ssh-agent lifetime and certificate probe) run and passed on the laptop"
  - "The platform record in needs-hardware.md (verified vs UNVERIFIED per OS, browser, authenticator and agent)"
  - "cli-macos in main-integrity.json and CONTRIBUTING.md, for the owner to apply from main after the merge (deviation 11); cli-windows stays unrequired until its intermittent TestAgent hang is fixed (owner decision D1)"
affects: [AUTH-02, AUTH-03, AUTH-04, PLAT-05, UI-01]

tech-stack:
  added: []
  patterns:
    - "A login is claimed only when a login_issue entry in an audit-verified export and an ED25519-CERT journal line on the host carry the same serial"

key-files:
  created:
    - .planning/phases/02-passkey-login-mvp/02-14-SUMMARY.md
  modified:
    - docs/security/needs-hardware.md
    - docs/runbooks/host-setup.md
    - docs/runbooks/enroll-user.md
    - .github/rulesets/main-integrity.json
    - CONTRIBUTING.md
    - .planning/REQUIREMENTS.md
    - .planning/STATE.md

key-decisions:
  - "Owner, 2026-10-22: the Windows login's SSH target is a Proxmox test VM (zima-srv was offline then); the Linux login used zima-srv, which was back online"
  - "UI-01 is marked complete (pre-merge review): every one of the six pages has been opened in a real browser under the strict CSP; the owner checked the index page, the error page and sign-out in Chrome after Task 5"
  - "AUTH-03 and PLAT-05 stay Pending: macOS browser leg UNVERIFIED"

requirements-completed: [AUTH-02, AUTH-04, UI-01]  # AUTH-02: web sign-in and /account in Chrome on Windows; AUTH-04: fingerprint on CLI and approval page, order=ok on both OSes; UI-01: all six pages in a real browser, strict CSP on each (pre-merge review). Not AUTH-03, PLAT-05 (see "Requirements")

plan_head_before: ff87054
completed: 2026-10-23
status: complete   # Tasks 1-5; Task 6 is the owner's merge gate
---

# Phase 2 Plan 14: Homelab Logins Summary

**The owner signed in to the web UI with a passkey, then ran `keyroster
login` on Windows 11 (keyroster agent) and on the Ubuntu laptop
(gcr-ssh-agent). On both, the owner compared fingerprints, approved in
Chrome, and logged in to a stock OpenSSH host with the certificate. Each
certificate login is matched by serial between the signer's audit-verified
log and the host's sshd journal. A `--ttl 5m` certificate left the agent on
both machines while the 8 h one stayed. On Linux this was shown 57 s after
expiry. On Windows the listing times were not recorded. macOS stays
UNVERIFIED. cli-macos becomes a required check once the owner applies the
ruleset; cli-windows does not yet (deviation 10).**

Addresses, host names other than the SSH aliases, the RP name and its hash
are kept only outside the repository, under the evidence directory
`P=$HOME/keyroster-ceremony/phase2`.

## Deviations from Plan

1. **SSH target for Windows.** zima-srv had been offline for 16 days when
   the Windows part ran (2026-10-22). The owner chose a Proxmox test VM
   (Ubuntu 26.04, OpenSSH 10.2p1) as the stock-OpenSSH host for it. Its
   account is `daniel`, mapped to role homelab-admin in host group homelab
   by directory v6, which the owner signed himself. For the Windows checks,
   read that VM where the plan says zima: `KR_TARGET_SINCE` in kr.env
   instead of `KR_ZIMA_SINCE`, journal unit `ssh`, and the accepted line
   `Accepted publickey for daniel`.
2. **SSH target for Linux.** zima-srv was back online on 2026-10-23. Task 1
   prepared it as the plan describes (account `zima`, `KR_ZIMA_SINCE` in
   kr.env), and the laptop login went to zima-srv. The adapted Task 5
   journal verify therefore reads the Windows serials from the test VM's
   journal and the Linux serials from zima-srv's journal. The plan reads
   both from zima's.
3. **Anchor version.** The plan's `anchor_bundle_version==3` is the 02-13
   plan defect (deferred-items.md). Every audit check below uses
   `bundle_version==3 and anchor_bundle_version==2`.
4. **Laptop credential.** 02-13 recorded a synced Chrome passkey, which is
   not bound to Daniel-PC. So Task 1 step 4 made no invite, and Task 3 step
   5 does not apply. The laptop used the same credential.
5. **The first Linux `ssh` did not use the certificate.** The plan's
   `ssh zima@<zima> whoami` printed `zima`, but zima-srv's journal shows
   that login (03:32:29 UTC) with the laptop's own plain ED25519 key, which
   zima-srv also has in `authorized_keys`. The certificate login was shown
   by a re-run that offered only certificates (`-o
   PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com`, plus
   password and keyboard-interactive off), at 05:41:52 CEST on the laptop.
   The journal records it as `ED25519-CERT` with serial 1792726285487553 at
   03:41:53 UTC. enroll-user.md now carries a short user-facing note about
   this.
6. **Linux listing B margin: 57 s, not 60 s.** The plan asks for listing B
   at least one minute after the 5 m certificate's expiry. The owner took it
   at 05:39:50 CEST. The certificate expired at 05:38:53, so the margin was
   57 s. An earlier listing at 05:36:19, before expiry, still showed both
   certificates.
7. **Windows listing times were not recorded.** The owner ran `ssh-add -l`
   three times after the 5 m login on Windows. #1 (A) and #2 showed both
   certificates, #3 (B) only the 8 h one. Their wall-clock times were not
   recorded. Removal *at* expiry is therefore not shown for keyroster agent,
   only that the key was gone by #3. If #2 was taken after expiry
   (valid_before 1792705294), the key outlived its certificate there. This
   stays an open item (below). The Linux result does not cover keyroster
   agent.
8. **Web sign-in on Linux was not done.** The laptop used only the approval
   page in Chrome. AUTH-02 rests on the Windows sign-in.
9. **The plan's `ssh.exe -n zima` precondition and the Task 1 `sshd -T -C`
   check for zima-srv** were re-run in Task 5 (after the logins). Both exit
   0; see "Hosts".
10. **Required checks: cli-macos only (owner decision D1, 2026-10-23,
    pre-merge review).** The plan's must-have says cli-windows and cli-macos
    "have run green on main since 02-02", and Task 5 step 3 checked only the
    check runs of main's tip. That holds for cli-macos. It does not hold for
    cli-windows: 7 of its last 100 runs failed, three of them on main, each
    of those with a 10-minute hang in `TestAgent/ensure_retries_once_on_closing_agent`
    (go-winio v0.6.2's listener `Close` race). Made required, it would fail
    correct PR heads. The owner chose "macOS nu, Windows sen": the ruleset
    and CONTRIBUTING.md require cli-macos only, and the ci.yml comment says
    why cli-windows is not required yet. deferred-items.md records when it
    becomes required (after Dependabot PR #41, go-winio v0.6.4).
11. **The ruleset is applied after the merge, from main (owner decision
    D2, "Efter merge, från main", pre-merge review).** Task 6 step 1 has
    the owner check out the PR branch and run `scripts/apply-rulesets.sh`
    from it, with admin rights, before approving. That runs a PR branch's
    script and JSON, which can change after review, with the owner's
    authority. Instead, after the merge the owner runs the script from an
    up-to-date `main` checkout (the reviewed script and JSON). cli-macos
    has already reported success on this PR's head, so applying after the
    merge loses nothing. CONTRIBUTING.md "Changing the rulesets" now says
    this. The PLAN text is left as it is.
12. **Laptop binary (pre-merge review).** Task 1 step 3.1 says to copy
    "the linux `keyroster` binary from 02-13's build" and check its SHA-256,
    and T-02-SC accepts on "binaries from 02-13's recorded build". The
    laptop instead ran `c98749ba…`, a fresh build of main `ff87054` made on
    2026-10-23 before the laptop part. Its build info records go1.27.3,
    `CGO_ENABLED=0`, `-trimpath`, `vcs.revision=ff87054a8f6f`,
    `vcs.modified=false` and no `-ldflags`. The file has no symbol table or
    DWARF sections, though, so it was stripped in a way the build info does
    not record, and who built it is not recorded either. Between 99c2795
    and ff87054 the only Go file that changed is `cmd/keyroster/runbook_test.go`
    (a test), and no file under an embed root changed, so the code that ran
    is 02-13's. T-02-SC's "binaries from 02-13's recorded build" holds for
    the Windows CLI and not for the laptop CLI.

## Hosts (Task 1)

**Proxmox test VM (Windows target), 2026-10-22.**
- `host ca-key` and `host principals homelab daniel` were rendered on
  Daniel-PC and installed byte-identical (SHA-256):
  - `/etc/ssh/keyroster_user_ca.pub`
    `5bb94b6f7a7ec078225c0bde8566b19f091cab929ca3934a95459bce85fb6689`;
  - `/etc/ssh/principals/daniel`
    `ee09cb0473dbc41c9971d804c743be38517676a0fe277d1f7e76d55faf6cbb44`,
    header `host group homelab, account daniel, directory version 6`,
    principal `role:homelab-admin`.
- `/etc/ssh/sshd_config.d/50-keyroster.conf` holds `TrustedUserCAKeys
  /etc/ssh/keyroster_user_ca.pub` and `AuthorizedPrincipalsFile
  /etc/ssh/principals/%u`, root:root 0644. `/etc/ssh/principals` is
  root:root 0755.
- `sshd -t` exits 0, and sshd was reloaded. `sshd -T -C
  user=daniel,host=<a>,addr=<a>` shows both settings for Daniel-PC's
  address. The laptop does not log in to this VM, so its address was not
  checked here.
- `Match` files under `/etc/ssh/sshd_config` and `sshd_config.d/`: **0**.
- The key-based control login exits 0 before and after.

**zima-srv (Linux target), 2026-10-23.**
- `/etc/ssh/keyroster_user_ca.pub` is the same file
  (`5bb94b6f...fb6689`). `/etc/ssh/principals/zima`
  `e8d89762d6c3869239f0f8513357ddff82e88efbdab26e12cc273da3cb855f5d` is
  byte-identical to `host principals homelab zima`: header `host group
  homelab, account zima, directory version 6`, principal
  `role:homelab-admin`.
- The same drop-in, root:root 0644. sshd is `OpenSSH_10.2p1
  Ubuntu-2ubuntu3.6`.
- **`sshd -T -C user=zima,host=<a>,addr=<a>`** shows both settings for
  Daniel-PC's address (`$SSH_CLIENT`) and for the laptop's Tailscale IPv4:
  the plan's Task 1 verify, exit 0 (re-run in Task 5).
- `Match` files: **0**.
- The key-based control login (`ssh.exe -n -o BatchMode=yes zima true`)
  exits 0.

**Laptop (ub-daniel), 2026-10-23.**
- `~/.local/bin/keyroster` SHA-256
  `c98749bae5e589c6876f51cadfc0324be012beeff357387b87f376c29da57642`
  (`$P/bin-linux/keyroster`). This is **not** 02-13's linux build
  (`d75b9caa…`, commit 99c2795) but a fresh build of main `ff87054`
  (deviation 12). `keyroster version` reports `ff87054a8f6f`, go1.27.3.
- `keyroster init` for user `owner`. The server, TLS pin, root pins and
  threshold equal Daniel-PC's config (compared by hash, field by field).
- The GNOME session's `SSH_AUTH_SOCK` is `/run/user/1000/gcr/ssh`. The
  client is `OpenSSH_10.2p1 Ubuntu-2ubuntu3.8`.

**Daniel-PC (Windows CLI).** The owner ran `$P/bin/keyroster.exe`, 02-13's
recorded build: SHA-256 `da3bd5dd…` (02-13-SUMMARY "Build"), and its build
info and `keyroster version` report commit `99c2795e7d05`, go1.27.3.

**A3 (moved here from 02-02).** The 02-02 probe ran on the laptop over
`ssh.exe -n ub-daniel`, base64-encoded (`$P/a3-probe.out`):

A3 (02-14): passed

The gcr socket is present (Ubuntu packages gcr 3.41.2-6 and gcr4, version
4.4). `ssh-add -t 20` added a probe key and its certificate. Listing 1 showed
both plus the owner's own key. Listing 2, 25 s later, showed only the
owner's key. gcr-ssh-agent therefore honours the lifetime constraint for a
key and its certificate, and keeps the certificate. The laptop login
(Task 4) used gcr-ssh-agent.

**host-setup.md** (Task 1 step 5, commit a81ba29): steps 1-4 are labelled
as run on a homelab host in 02-14. "Where the sshd settings go" is labelled
for the drop-in case only (Ubuntu with the include line, no `Match`
block). Step 5 keeps its 02-11 label. Both hosts match that case.

## Owner's answers (Tasks 2 and 4)

| OS | Browser | Authenticator | Agent | order= | Web sign-in |
|---|---|---|---|---|---|
| Windows 11 (Daniel-PC) | Chrome | synced Chrome passkey, Windows Hello face recognition | keyroster agent | ok (both approvals) | `/login` in Chrome worked; `/account` showed role homelab-admin. Edge not tried |
| Ubuntu 26.04 GNOME (laptop) | Chrome | the same synced passkey, unlocked through Google Password Manager | gcr-ssh-agent | ok (both approvals) | not done |

`$P/owner-reply-windows.txt`, `$P/owner-reply-linux.txt` and
`$P/owner-terminal-linux.txt` (the owner's full laptop terminal paste, with
times) hold the answers.

## Login evidence

Signer log: `audit verify --json` with pins C and D, threshold 1.
- `homelab-after-windows.export` with `--previous homelab.export`: ok, 15
  entries, bundle_version 3, policy_version 2, anchor_bundle_version 2,
  login_issue 2 (baseline 0), refusals 0.
- `homelab-after-linux.export` with `--previous
  homelab-after-windows.export`: ok, 17 entries, bundle_version 3,
  policy_version 2, anchor_bundle_version 2, login_issue 4, refusals 0.

The `--previous` chain proves that each export extends the one before it.

All four certificates carry principals `role:homelab-admin`, directory v6
and policy v2. They are signed by user CA `ecdsa-sha2-nistp256`
`SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0`, with evidence
`webauthn-assertion/v1`.

| OS | Key ID | Serial | Key fingerprint | valid_after .. valid_before (Unix) | Host journal |
|---|---|---|---|---|---|
| Windows | `kr2/ca=user/sub=owner/req=d1e7fe3c4758978ebccf922e3ed1b32a/pol=2/dir=6/roles=homelab-admin/ser=1792704938150899` | 1792704938150899 | `SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI` | 1792704638 .. 1792733738 (8 h + 300 s) | test VM, 2026-10-22 23:35:49 CEST, `Accepted publickey for daniel`, `ED25519-CERT`, `(serial 1792704938150899) CA` |
| Windows | `kr2/ca=user/sub=owner/req=0e094411cdbcdd31118322b8d44e6739/pol=2/dir=6/roles=homelab-admin/ser=1792704994430748` | 1792704994430748 | `SHA256:H5CLDznPL8Vy8sZOOC8SivtiZlJDP1BBLS3zdL/lGd8` | 1792704694 .. 1792705294 (5 m + 300 s) | not used for SSH |
| Linux | `kr2/ca=user/sub=owner/req=d885bde4cc11e6ddd3f61ed90e29cf18/pol=2/dir=6/roles=homelab-admin/ser=1792726285487553` | 1792726285487553 | `SHA256:nFMutDzbkr3RJ4mttHCT0pL8eKbWPTMq7A1gxu0InUc` | 1792725985 .. 1792755085 (8 h + 300 s) | zima-srv, 2026-10-23 03:41:53 UTC, `Accepted publickey for zima`, `ED25519-CERT`, `(serial 1792726285487553) CA` |
| Linux | `kr2/ca=user/sub=owner/req=19b45b088abbc222fd2c2bf84cd318cf/pol=2/dir=6/roles=homelab-admin/ser=1792726433708697` | 1792726433708697 | `SHA256:F2bchbf+T6p6/1LqghxN0mIGIHanXqtimENiv2QK33U` | 1792726133 .. 1792726733 (5 m + 300 s) | not used for SSH |

`$P/serials-windows.txt` and `$P/serials-linux.txt` hold the serials.
`$P/journal-kr-target.txt` and `$P/journal-kr-zima.txt` hold the matching
journal lines, with client addresses, outside the repository. The Windows
`ssh ... whoami` printed `daniel`, and the Linux certificate-only run
printed `zima`.

zima-srv's other `Accepted publickey for zima` lines since `KR_ZIMA_SINCE`
are plain ED25519 key logins: Claude's own control and check sessions, and
the owner's first laptop `ssh` (deviation 5).

## Expiry evidence

**Windows (keyroster agent).** `$P/expiry-windows.env`:
- FP5M `SHA256:H5CLDznPL8Vy8sZOOC8SivtiZlJDP1BBLS3zdL/lGd8`;
- SERIAL5M 1792704994430748;
- KID5M from the export (exactly one match)
  `kr2/ca=user/sub=owner/req=0e094411cdbcdd31118322b8d44e6739/pol=2/dir=6/roles=homelab-admin/ser=1792704994430748`.

Listing A (kr2 lines):

```
256 SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI kr2/ca=user/sub=owner/req=d1e7fe3c4758978ebccf922e3ed1b32a/pol=2/dir=6/roles=homelab-admin/ser=1792704938150899 (ED25519-CERT)
256 SHA256:H5CLDznPL8Vy8sZOOC8SivtiZlJDP1BBLS3zdL/lGd8 kr2/ca=user/sub=owner/req=0e094411cdbcdd31118322b8d44e6739/pol=2/dir=6/roles=homelab-admin/ser=1792704994430748 (ED25519-CERT)
```

Listing B (kr2 lines; time not recorded, deviation 7):

```
256 SHA256:eItHAZYVKl0zxYFvT+cvn4WeSYIkUpG+QSvs233PrgI kr2/ca=user/sub=owner/req=d1e7fe3c4758978ebccf922e3ed1b32a/pol=2/dir=6/roles=homelab-admin/ser=1792704938150899 (ED25519-CERT)
```

FP5M appears in listing A, so inbox OpenSSH 9.5p2's `ssh-add -l` prints the
plain key's fingerprint on a certificate entry (informational).

**Linux (gcr-ssh-agent).** `$P/expiry-linux.env`:
- FP5M `SHA256:F2bchbf+T6p6/1LqghxN0mIGIHanXqtimENiv2QK33U`;
- SERIAL5M 1792726433708697;
- KID5M from the export (exactly one match)
  `kr2/ca=user/sub=owner/req=19b45b088abbc222fd2c2bf84cd318cf/pol=2/dir=6/roles=homelab-admin/ser=1792726433708697`.

The CLI printed `Valid until: 2026-10-23 05:38:53 CEST`, which is
valid_before 1792726733.

Listing A, 05:33:54 CEST (kr2 lines):

```
256 SHA256:nFMutDzbkr3RJ4mttHCT0pL8eKbWPTMq7A1gxu0InUc kr2/ca=user/sub=owner/req=d885bde4cc11e6ddd3f61ed90e29cf18/pol=2/dir=6/roles=homelab-admin/ser=1792726285487553 (ED25519-CERT)
256 SHA256:F2bchbf+T6p6/1LqghxN0mIGIHanXqtimENiv2QK33U kr2/ca=user/sub=owner/req=19b45b088abbc222fd2c2bf84cd318cf/pol=2/dir=6/roles=homelab-admin/ser=1792726433708697 (ED25519-CERT)
```

An extra listing at 05:36:19 CEST, before expiry, showed the same two kr2
lines.

Listing B, 05:39:50 CEST, 57 s after expiry (kr2 lines):

```
256 SHA256:nFMutDzbkr3RJ4mttHCT0pL8eKbWPTMq7A1gxu0InUc kr2/ca=user/sub=owner/req=d885bde4cc11e6ddd3f61ed90e29cf18/pol=2/dir=6/roles=homelab-admin/ser=1792726285487553 (ED25519-CERT)
```

KID5M is in A and not in B. B still lists the 8 h certificate. The export
line for FP5M, SERIAL5M and KID5M spans 600 s. FP5M also appears in listing
A (gcr-ssh-agent with OpenSSH 10.2p1's `ssh-add`), informational.

## A6: authenticator data

| Authenticator | Browser | authenticator_data_len | authenticator_flags | Source |
|---|---|---|---|---|
| synced Chrome passkey via Windows Hello | Chrome, Windows 11 | 37 | 0x1d (UP, UV, BE, BS; AT and ED clear) | both Windows login_issue lines |
| the same synced passkey via Google Password Manager | Chrome, Ubuntu 26.04 | 37 | 0x1d (UP, UV, BE, BS; AT and ED clear) | both Linux login_issue lines |

The keyroster-server journal holds **no `bad_authenticator_data`**, so
there was no STOP and no owner decision was needed:
- since `KR_VM_SINCE` (Windows, `$P/journal-server-windows.txt`);
- since 03:00 UTC on 2026-10-23 (Linux, `$P/journal-server-linux.txt`).

The Windows window holds one `web sign-in begin_refused
reason=no_usable_passkey` for the user name `homelab-admin`: the role name
was typed as the user name. It is followed by `signin_ok` for `owner`. Each
window holds two complete `cli login` sequences (options, begin, page,
approve, redeem).

## Approval order (02-12-R2-F3)

| OS | Browser | order= |
|---|---|---|
| Windows 11 | Chrome | ok, both approvals |
| Ubuntu 26.04 GNOME | Chrome | ok, both approvals |

Every answer is `ok`. This is the real-browser evidence for 02-12's
prohibition on the approval script: the fingerprint is on the page before
any passkey prompt, and the prompt comes only after Approve. It is the
owner's observation of four approvals in Chrome, not a measurement. Every
other browser stays UNVERIFIED on this point.

## Platform record

`docs/security/needs-hardware.md` "Platform verification (D-16)" now has a
table with an UNVERIFIED row for macOS, one for Edge and Firefox on
Windows, and two verified rows:
- Windows 11, Chrome, synced passkey via Windows Hello, keyroster agent,
  inbox OpenSSH 9.5p2;
- Ubuntu 26.04 GNOME, Chrome, the same passkey via Google Password Manager,
  gcr-ssh-agent, OpenSSH 10.2p1.

Both targets are stock OpenSSH 10.2p1.

UNVERIFIED:
- macOS (browser and passkey);
- Safari, Firefox, Edge and every browser other than Chrome;
- a hardware or device-bound authenticator;
- OpenSSH `ssh-agent` in a real login (CI only);
- headless login (D-12);
- Windows sshd as a target (Phase 5).

The gcr-ssh-agent line records A3 as passed and the laptop login as done
through it. enroll-user.md "Logging in" labels the Linux login as run in
02-14. It also adds the note that ssh may log in with a plain key first,
and the option that offers only certificates. Its `-o` form was run on
Linux. The same setting in a `Host` block, and either form with the Windows
inbox client, are UNVERIFIED.

## Required checks (Task 5 step 3)

- `gh api repos/Labontese/keyroster/commits/main/check-runs` on main
  `ff87054` shows `cli-windows` and `cli-macos` completed with success, app
  id 15368. That is the tip only; cli-windows has failed on earlier main
  runs (deviation 10).
- `cli-macos` (integration_id 15368) is added to
  `.github/rulesets/main-integrity.json`, and CONTRIBUTING.md's list grows
  from 17 to 18 checks. `cli-windows` was added too and taken out again in
  the pre-merge review (owner decision D1); CONTRIBUTING.md says it runs on
  every PR but is not required yet.
- The live ruleset is unchanged: the owner applies it after the merge,
  from an up-to-date `main` (deviation 11).

## Requirements

- **AUTH-02 complete.** Web sign-in with the passkey in a real browser
  (Chrome on Windows), and `/account` showed the role.
- **AUTH-04 complete.** The fingerprint was compared on CLI and approval
  page on both OSes, with `order=ok` from Task 2 and Task 4.
- **UI-01 complete** (pre-merge review, 2026-10-23). Task 5 step 5's rule
  is "every page exercised in a real browser". The UI has six pages
  (`pageNames` in `internal/server/render.go`), and each has been:
  - `enroll` in 02-13 (Chrome on Daniel-PC);
  - `login`, `account` and `login_approve` in Tasks 2-4 (Chrome, both OSes
    for the approval page);
  - `index`, the `error` page (an unknown login ID, 404) and sign-out by
    the owner on 2026-10-23, after Task 5, in Chrome on Daniel-PC with
    DevTools open. The keyroster-server journal shows `signin_ok` for owner
    and `logout` three seconds later, and the browser then showed `/login`.

  curl from Daniel-PC at the same time shows the strict
  `Content-Security-Policy` (`default-src 'none'; script-src 'self'; ...;
  frame-ancestors 'none'; base-uri 'none'`) on `/`, `/login`, the 404 page
  and `/account`, and the console showed no CSP violation on any of the
  three pages. DevTools showed "1 issue" on the error page and on `/login`;
  its text was not captured (open item). The pages and assets are embedded
  in the binary and there is no npm dependency. Evidence:
  `$P/owner-ui-check.txt`; the screenshots were not kept, because they show
  the RP name.
- **AUTH-03 and PLAT-05 stay Pending.** The macOS browser leg is
  UNVERIFIED. On Windows, AUTH-03's "matching lifetime" is shown only in
  part: the 5 m certificate was gone from keyroster agent at a later
  listing, but the listing times were not recorded, so removal at expiry
  is not shown (deviation 7, open item). REQUIREMENTS.md carries the note
  "Linux and Windows verified end to end (02-14); macOS browser leg
  UNVERIFIED; Windows removal at expiry not timed".

## Task Commits

1. **Task 1:** `a81ba29` docs(runbooks): label host setup and Windows login
   as run on the homelab in 02-14. The orchestrator's `1f138f3` records the
   target-host decision.
2. **Task 2** (owner, Windows): no commit.
3. **Task 3:**
   - `c547a7a` docs(02-14): draft summary with the Windows login evidence
     (Tasks 1-3)
   - `effe47e` docs(02-14): do not claim removal at expiry while the
     listing times are unrecorded
   - `72eb187` docs(02-14): narrow the Windows login claims and record the
     host-side evidence
4. **Task 4** (owner, laptop): no commit.
5. **Task 5:**
   - `4333758` docs(02-14): record the laptop login and require the CLI OS
     checks
   - `e576a2c` docs(02-14): complete homelab-logins plan (the SUMMARY,
     REQUIREMENTS.md and STATE.md)
   - `f75bb64` docs(02-14): state the observed Linux expiry window instead
     of removal at expiry
   - the follow-up commit `docs(02-14): add the UNVERIFIED platform rows and
     scope the Linux login notes`

## Verification run (adapted)

| Check | Result |
|---|---|
| T1: per-connection `sshd -T -C` on zima-srv for Daniel-PC's and the laptop's address; principals file is keyroster-rendered | exit 0 (re-run in Task 5) |
| T1: `KR_ZIMA_SINCE` and `KR_VM_SINCE` in kr.env (plus `KR_TARGET_SINCE`) | set |
| T1: key-based control login to zima-srv | exit 0 |
| T1: laptop `keyroster version` | exit 0 |
| T2/T4: `systemctl is-active keyroster-server keyroster-signer` | active, active (checked after the logins, not during them) |
| T3-1: Windows export, audit verify ok, bundle 3, anchor 2, login_issue ≥ baseline + 2 | exit 0 |
| T3-2: a Windows serial as `(serial <n>) CA` in the test VM's journal | exit 0 |
| T3-3: Windows expiry by key ID | exit 0 |
| T5-1: Linux export extends the Windows one, ok, bundle 3, anchor 2, login_issue ≥ Windows + 2 | exit 0 |
| T5-2: a Windows serial in the test VM's journal and a Linux serial in zima-srv's journal (adapted, deviation 2) | exit 0 |
| T5-3: Linux expiry by key ID | exit 0 |
| T5-4 (adapted, deviation 10): ruleset JSON holds cli-macos with integration_id 15368 and no cli-windows (the plan expects both); needs-hardware.md has UNVERIFIED | exit 0 |
| T5-5: diff guard (pattern plus guard-literals.txt) | exit 0 before each commit |
| T5-6: FETCH_HEAD equals HEAD with this SUMMARY | run after the push |
| T5-7: exactly one `A3 (02-14): …` line | exit 0 |
| T5-8: `pr checks --watch` | run after the push |

## Open items

- **Windows expiry timing (deviation 7).** Removal close to expiry (still
  listed 2 min 34 s before it, gone 57 s after it) is shown on Linux
  (gcr-ssh-agent) only. For keyroster agent on Windows, a re-run with
  recorded listing times would close it. Until then it stays open for the
  phase verifier.
- **UI-01 DevTools issue.** DevTools showed "1 issue" on the error page
  and on `/login`, and its text was not captured. The console showed no
  CSP violation, so it is not a CSP refusal; what it is stays unknown.
- **macOS** (AUTH-03, PLAT-05): no Mac in the homelab.
- **cli-windows as a required check** (deviation 10): after Dependabot PR
  #41 has merged and the job is green on main (deferred-items.md).

## Not exercised (UNVERIFIED)

- Every browser other than Chrome.
- A hardware or device-bound authenticator.
- Web sign-in on Linux.
- macOS.
- OpenSSH `ssh-agent` in a real login.
- gcr-ssh-agent in any version other than Ubuntu 26.04's packages.
- The browser opener: whether `keyroster login` opened the page itself was
  not recorded.
- `keyroster login` starting keyroster agent itself.
- A `Match` block on the target.
- host-setup.md step 5 on a real host.
- The certificate-only ssh option in a `Host` block, or with the Windows
  inbox client.
