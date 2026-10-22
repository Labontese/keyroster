---
phase: 02-passkey-login-mvp
plan: 13
subsystem: homelab-dogfood
tags: [homelab, dogfood, webauthn, rp-id, tailscale-cert, enrollment, audit, key-07]

requires:
  - phase: 01-trust-core
    provides: "01-20/01-21 homelab vTPM signer under bundle v2 (TEST roots C and D, threshold 1), owner admin key, 01-21 log export (6 entries)"
  - phase: 02-passkey-login-mvp
    provides: "02-01..02-12 at origin/main 2788397: successor-policy with the WebAuthn RP, keyroster-server and its systemd and tailscale-cert units (02-06), enrollment and approval (02-07..02-09), roles and host groups (02-11), the CLI (02-12)"
provides:
  - "Homelab under trust bundle v3 (policy v2 with the RP hostname), keyroster-server serving HTTPS with a tailscale cert, the tailscale-cert timer active"
  - "The owner enrolled like any user (D-04): directory v5 with the owner active, role homelab-admin (8 h) granted to owner, host group homelab mapping account zima to homelab-admin"
  - "homelab.export (12 entries) as the 02-14 audit baseline, kept outside the repository"
  - "Runbook labels for the steps that ran on the homelab; KEY-07 owed ceremony renumbered to v4"
affects: [02-14, KEY-07, AUTH-01, PLAT-05, UI-01]

tech-stack:
  added: []
  patterns:
    - "Admin-signed directory commands that a permission classifier refuses for an agent are run by the owner, and the agent checks their effect read-only (user pending, user list, directory show, host principals, audit verify)"

key-files:
  created:
    - .planning/phases/02-passkey-login-mvp/02-13-SUMMARY.md
  modified:
    - docs/runbooks/server-install.md
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/signer-install.md
    - docs/runbooks/enroll-user.md
    - .planning/phases/01-trust-core/deferred-items.md
    - .planning/phases/02-passkey-login-mvp/deferred-items.md
    - .planning/ROADMAP.md
    - .planning/STATE.md

key-decisions:
  - "D-09 (owner, 2026-10-22): the homelab RP ID is the signer VM's full MagicDNS FQDN; the name and its hash stay outside the repository (kr.env)"
  - "Bundle v3 is the RP policy successor signed by TEST root C; the owed real offline ceremony becomes the v4 rotation and KEY-07 stays open"
  - "The owner's keyroster user name is owner; the owner registered a synced passkey in Chrome as his only credential (open choice: add a hardware or device-bound second passkey)"
  - "audit verify anchors on the first bundle whose root set equals the pins, so C and D anchor on v2; the plan's anchor==3 assertion was a plan defect and is replaced by bundle_version==3 and anchor_bundle_version==2"

patterns-established:
  - "Owner-run admin commands: the agent never sees the invite token or the diff; it records what landed from read-only commands and the signer's audit log"

requirements-completed: [AUTH-01]  # registration in a real browser (Task 3) and an admin-signed approval (Task 4) both landed; PLAT-05 and UI-01 are decided in 02-14

actuals:
  tokens: 8300   # chars/4 over the 99c2795..HEAD diff plus this SUMMARY; the homelab operations themselves are not in the diff
  tasks: 4
  commits: 4     # measured at SUMMARY write (git rev-list --count 99c2795..162478d); the SUMMARY commit follows
plan_head_before: 99c2795e7d05ddf6858c680588d8ee64297c6a88
plan_head_after: 162478dd22e1f0acd4f125f52e20db109fbbf92d

duration: Task 2 to Task 4 about 2026-10-22T20:06Z to 20:45Z, plus the owner's checkpoints in between
completed: 2026-10-22
status: complete
---

# Phase 2 Plan 13: Homelab Server Install and First Enrollment Summary

**The homelab signer runs trust bundle v3, a policy successor that adds the confirmed WebAuthn RP hostname and is signed by TEST root C. keyroster-server runs next to it with a `tailscale cert` certificate that the timer keeps current, and answers healthz over the tailnet with a certificate the system roots trust. The owner enrolled through the same path as any user: invite, registration of a synced Chrome passkey in a real browser, and an approval signed with his own admin key. A role and a host group followed. The signer's log verifies with 5 directory installs, and the owed KEY-07 offline ceremony is now the v4 rotation.**

## Performance

- **Duration:** Task 2 started at 2026-10-22T20:06Z (build) and Task 4 ended at about 20:45Z. The owner's checkpoints lie in between: D-09, the user name, `user add`, registration, and the directory commands.
- **Tasks:** 4 of 5. Task 5 is the owner's merge gate.
- **Files:** 4 runbooks and 4 planning files.

## Delivery

- **Branch:** `p02/13-homelab-enroll`, from origin/main `2788397` plus the orchestrator's `99c2795` (docs only).
- **PR:** opened by keyroster-bot after the push that carries this SUMMARY. The number and the check results go in the merge-gate checkpoint.
- **Auto-merge is not enabled.** This is an environment rule, so the plan's "enable auto-merge" step is deliberately unmet.

## Build (Task 2 step 1)

Commit `99c2795`, go1.27.3, `CGO_ENABLED=0 -trimpath`, `vcs.modified=false`.

| Artifact | SHA-256 |
|---|---|
| keyroster (linux) | `d75b9caa57de8d1845317c9be1b1ea54a3413166d35db6edf8bfa4e7e94738d4` |
| keyroster-server | `791926d1864ee9a9b3acf6e924b504733ea02adfe0feb5fea69a3f5f0bddd420` |
| keyroster-signer | `c74ec0ed2efbbd476bdf247dfb25e9b45c86da471ee42809df241d186e94d36b` |
| keyroster.exe | `da3bd5ddc37cf5f2691e08cf06fc667757f752b160f0f1040223963d23cba98e` |
| keyroster-server.service | `28fc66388b7d993541e6874c8dbfdf8706a9d31abfe0fc6766d67afd2900ffb8` |
| keyroster-tailscale-cert.service | `34f0cb950de78bb1a2fb3246cf6b1e4d078ba1adbf6b5ede4054f7f088458ea4` |
| keyroster-tailscale-cert.timer | `788df26e29e11bf1b8facf5ca805ea53f28543ae8b84e1cb8ef95999a9393038` |
| sysusers.d/keyroster.conf | `2ad5bab81ba99a05af8cbac0b8e226a2c4e38cedc5d69f3a4baec005fa1ca0be` |
| keyroster-signer.service (unchanged) | `24058153fff8a3e935d67698b9ba41ff3292ef2bf04c9b123eeea7dfe02bd41b` |
| keyroster-signer.service.d/tpm.conf (unchanged) | `ff2b620a235c20db8af656e7d6b02eeea6dec10899fbe3dfe0122b5a9ea295bf` |

## Rollback copies (`.pre-02-13`, taken before the upgrade)

- `/var/lib/keyroster-signer.pre-02-13` was made with `cp -a`, and its `signer.db` compared identical with `cmp`.
  - The directory is 981:981, `drwx------`.
  - It holds `ca-pubkeys.json`, `signer.db`, `signer.lock` (all `-rw-------`).
  - It holds `incoming/` (bundle and policy plus sigs, `-rw-r-----`).
  - It holds `tpm/` (host, log, machine, ops and user `.auth`/`.tpmkey`, `-rw-------`).
- `/usr/local/bin/keyroster-signer.pre-02-13`: `33f0125eceb5a680abfe60cf7731664ac4f345d275ec875af90d3e048486c891` (build d623927f7ffa)
- `/usr/local/bin/keyroster.pre-02-13`: `529c52b47878ac054a39dfb91975d9db73f59ecc80f3fe2bbfbe734b5945d0d6`
- `/etc/systemd/system/keyroster-signer.service.pre-02-13`: `24058153…e1ebe4`
- `/etc/systemd/system/keyroster-signer.service.d/tpm.conf.pre-02-13`: `ff2b620a…95bf`
- Extra, not in the plan: `/etc/sysusers.d/keyroster.conf.pre-02-13`. systemd-sysusers reads only `*.conf`, so the backup is inert.

The rollback window closed when Task 3 registered a passkey. From then on the plan fixes forward (02-13-F1).

## Policy v2 and bundle v3 (Tasks 1-2)

**RP hostname hash recorded in kr.env, outside the repository.** The owner confirmed the exact RP hostname at the D-09 checkpoint (Task 1).

**Policy field comparison** (canonical JSON, `python -I`):
- v1 has the keys `admin_quorum`, `admins`, `ca_profiles`, `prev`, `timelock_seconds` and `version`. v2 adds `webauthn`.
- The differing fields are exactly `prev`, `version` and `webauthn`:
  - `version` goes from 1 to 2;
  - `prev` is the SHA-256 of the v1 bytes;
  - `webauthn.rp_id` is the confirmed RP hostname, and `origins` is `[https://<RP hostname>]`.

**Hash equality, bundle v3** (`44faa7bc1bd4702d398bb234030cc6215f8ab8d2aff3f604c3a02cca087a2ab3`):

| Where | Bundle v3 | Policy v2 |
|---|---|---|
| `root successor-policy` (WSL) | - | `277121ee…429c` |
| `root sign` dry run and `--confirm 44faa7bc` | `44faa7bc…2ab3` | `277121ee…429c` |
| `trust verify --prev`, pins C and D, threshold 1: `OK: successor of trust bundle v2` | `44faa7bc…2ab3` | (rp line checked) |
| `sha256sum` of `incoming/` on the VM | `44faa7bc…2ab3` | `277121ee…429c` |
| `install-bundle` output | `44faa7bc…2ab3` | `277121ee…429c` |

- Bundle v3 succeeds v2 (`92dc8ef4…b295`).
- The roots stay C and D at threshold 1.
- The CA, ops and log keys are unchanged (vTPM).
- The admin stays `owner` (`SHA256:BUJx6C2+…`), quorum 1 of 1.
- Bundle v3 was issued at 2026-10-22T20:07:46Z.

After install the signer logged `serving backend=tpm policy_version=2`, with NRestarts 0. Doctor reported `trust bundle version 3 installed (2 roots, threshold 1)` and no FAIL. It warned `software_root` twice (C, D) and `vtpm_custody`.

## keyroster-server and the certificate unit (Task 2 step 5, 02-13-R2-F4)

- systemd-sysusers created `keyroster-server` (uid/gid 980), with groups `keyroster-server` and `keyroster-admin`.
- The state directory `/var/lib/keyroster-server` is 980:980 0700, created by StateDirectory under `ProtectSystem=strict`.
- `ExecStartPost=/usr/bin/systemctl try-reload-or-restart` appears exactly once in the installed unit.
- **First run** (server not started, 20:09:32Z): `Result=success`, ExecMainStatus 0. `tailscale cert` wrote the cert and the key. `key.pem` is `root:keyroster-server`, `-rw-r-----`.
- **fullchain.pem** holds **4** certificates: the leaf, the Let's Encrypt intermediate, and two cross-signed roots, the last one issued by ISRG Root X1.
- **Timer:** `is-active` printed `active`. Next run: Fri 2026-10-23 00:41:44 UTC.
- **Server start:** `tls certificate loaded` with trigger `start`, then `serving` with policy_version 2 and bundle_version 3, at 20:10:30Z. NRestarts 0.
- **Second run** (against the running server, VM time 2026-10-22 20:10:31 UTC): `Result=success`. `tailscale cert` printed `Public cert unchanged` and `Private key unchanged`.
- The keyroster-server journal logged `tls certificate loaded` with trigger `sighup` at 20:10:32Z. Its fingerprint was equal to the certificate on disk.
- **A renewal started by the timer itself is UNVERIFIED.** This plan started the unit by hand, and a renewal that writes a new certificate and key that the server then loads has not run.
- **Exposure:** `systemd-analyze security keyroster-server.service` scored 2.1 OK on the host.
- **healthz** from Daniel-PC over the tailnet answered `{"status":"ok"}` with rc 0, with no `-k` and verified against the system roots. Both Git Bash curl and Windows curl.exe (Schannel) were tried.

## Windows admin CLI (Task 2 step 6)

- `keyroster init` without `--tls-pin` printed one root, ISRG Root X1, `sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=`, and exited 2.
- The pin computed on the VM from `/etc/ssl/certs/ISRG_Root_X1.pem` (OpenSSL 3.5.5) was equal.
- `init --force --tls-pin … --root-pin C --root-pin D --threshold 1 --admin-key SHA256:BUJx6C2+… --user owner` exited 0. It reported "trust bundle version 3, policy version 2 (verified against your root pins)", with the CA, ops and log keys in vTPM custody and the roots in software custody. It printed no evaluation banner.
- The admin key is the plain Ed25519 key `SHA256:BUJx6C2+…` in the Windows ssh-agent.

## Enrollment (Tasks 2 step 7, 3 and 4 step 1)

| Step | Who ran it | Checked by Claude |
|---|---|---|
| `user add owner` | Owner, in his own terminal. The classifier refused it for the agent, and the invite token never entered a transcript | `user pending owner` listed exactly the replied credential |
| Registration | Owner: Chrome on Daniel-PC (Windows); authenticator reported as `chrome` | `user pending owner`: `SHA256:GKHjxrvAR/mDLNvY9SAb8vw0Xeiw7XlT5VwEizpxJE4`, ES256, backup eligible and synced, registered 2026-10-22T20:18:33Z |
| `user approve owner --fingerprint SHA256:GKHj…` | Owner, interactively. The classifier refused it for the agent | `user list`: owner active with exactly that passkey |
| `role add homelab-admin --max-ttl 8h`, `role grant homelab-admin --user owner`, `host-group add homelab`, `host-group map homelab zima homelab-admin` | Owner, interactively. The first round left the grant out (directory v4 had `users=[]`; the cause was not recorded). The owner ran the grant again | below |

**Read back after the owner's "grant done":**
- `user list`: directory version 5; `owner active`; `passkey SHA256:GKHjxrvAR/mDLNvY9SAb8vw0Xeiw7XlT5VwEizpxJE4 ES256 synced yes`; no pending accounts.
- `directory show`: version 5, SHA-256 `d867f389ebf4fe91d82f225e615834a434bd1feca9781c90853aa163b70dc9da`. It is signed by 1 of the policy's admins (quorum 1), owner `SHA256:BUJx6C2+6jWWCcMiC125cSPtnGCly5QhpRR9EERu2e4`, under policy v2. Contents:
  - `user owner (active)`;
  - the credential (`backup_eligible=true synced=true`);
  - `role homelab-admin principals=[role:homelab-admin] max_ttl_seconds=28800 extensions=[] users=[owner] groups=[]`;
  - `host_group homelab accounts=[zima:homelab-admin]`.
- `host principals homelab zima` renders `role:homelab-admin` (directory v5).

## Audit (Task 4 step 2)

- On the VM, `export-log` ran as keyroster-signer through `runuser`, with a read-only open while the signer kept running. It printed `exported 12 entries`.
- The export's SHA-256 is `ca38b1e8b9a61bda02ad2403ef7ae6b9edef4f67fe47fd38a4fda89f5ba335dd`. It was copied to `$HOME/keyroster-ceremony/phase2/homelab.export`, outside the repository, as the baseline for 02-14.

**`audit verify --json`, pins C and D, threshold 1 (rc 0):**

```
{"ok": true, "entries": 12, "root": "QFn6eZqnfQiU84l2QrlZ4xwK1v6MSNaMzSasBUCZLd0=", "issued": 3, "refusals": 0,
 "kinds": {"bundle_install": 3, "ca_init": 1, "directory_install": 5, "issue": 3}, "issued_by_ca": {"user": 3},
 "bundle_version": 3, "policy_version": 2, "log_key": "SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU",
 "anchor_bundle_version": 2}
```

The human output reads:

```
OK: 12 entries, root QFn6eZqnfQiU84l2QrlZ4xwK1v6MSNaMzSasBUCZLd0=, issued 3 (user 3, host 0, machine 0), login certificates 0, directory installs 5, refusals 0, trust bundle v3, policy v2, log key SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU
anchored: the pinned roots are the root set of trust bundle v2
```

- **Pinned to TEST roots A and B** (`SHA256:rLH3utx6…`, `SHA256:aIDlGVSb…`): the same OK line, and `anchored: the pinned roots are the root set of trust bundle v1`.
- **Against 01-21:** `--previous rotation-v2/signer-log-after-pr27.export` (6 entries, `cc01648e…4f77`) gave rc 0. The new log extends the 01-21 log.
- **Directory installs:** 5, which equals directory version 5 (approve, role add, role grant, host-group add, host-group map).
- **The log is anchored on v2, and bundle v3 is in force.** C and D became the root set in v2, and v3 kept them. See deviation 1.

## KEY-07 renumbering (Task 4 step 3, commit 28601c0)

- Bundle v3 is the RP policy successor signed by TEST root C. The owed real offline ceremony is now the **v4 rotation**, co-signed by C or D, after which C and D are destroyed.
- KEY-07 stays open.
- `deferred-items.md` was updated in the 01-21 entry and in the 01-14 "Owed" sub-bullet. The second edit keeps the two consistent, because both said v3.
- In `ROADMAP.md`, only the Phase 1 plans line changed.

## Task Commits

1. **Task 1** (D-09 checkpoint): no commit. The owner's decision is recorded in STATE.md by the orchestrator (`99c2795`).
2. **Task 2:** `66531d6` docs(02-13): record the homelab server install and RP policy successor runs.
3. **Task 3** (registration checkpoint): no commit.
4. **Task 4:**
   - `28601c0` docs(02-13): renumber the owed KEY-07 offline ceremony to the v4 rotation
   - `3f3caff` docs(02-13): label the enrollment steps that ran on the homelab
   - `162478d` docs(02-13): record that 02-14 expects the wrong audit anchor version
   - the SUMMARY commit `docs(02-13): complete homelab-enroll plan`

## Verification run

- **Task 2 verify** (tracer gate, after 66531d6): V1 to V5 rc 0. V3 ran from a script file, because of the known 01-20 quoting issue with an inline `scripts/linux.sh` string. V5's planted-literal negative check caught the literal.
- **Task 4 verify 1** (the plan's literal assertion, `anchor_bundle_version==3`): **rc 1** on a valid log (deviation 1).
- **Task 4 verify 1, corrected:** `ok is True and bundle_version==3 and policy_version==2 and anchor_bundle_version==2 and kinds.directory_install==5` gave rc 0.
- **Task 4 verify 2** (`v4` in deferred-items.md, `v4 rotation` in ROADMAP.md): rc 0.
- **Task 4 verify 3** (diff guard, the pattern plus guard-literals.txt against origin/main): rc 0, before each commit.
- **Task 4 verify 4 and 5** (FETCH_HEAD equals HEAD with this SUMMARY; `pr checks --required --watch`): run after the push. The results are in the merge-gate checkpoint.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - plan verify defect] The audit anchors on bundle v2, not v3**
- **Found during:** Task 4 step 2.
- **Issue:** The plan's must-have truth and Task 4 verify 1 expect `anchor_bundle_version` 3. `audit verify` anchors on the first accepted bundle whose root set and threshold equal the pins (`internal/audit/verify.go`, `anchor.install`). C and D became the root set in v2, and v3 kept them. So the anchor is 2 by design, and the assertion returned 1 on a valid log. 01-21 shows the same rule: A and B anchor on v1, and C and D on v2.
- **Fix:** No code change. The corrected assertion is recorded above with rc 0. 02-14-PLAN.md makes the same assertion at four places, so it is logged in the phase 02 `deferred-items.md` to be fixed before 02-14 runs.
- **Commit:** 162478d.

**2. [Rule 3] `--prev-sha256` passed to `root sign --prev` and `trust verify --prev`.** The build requires the flag, and the plan's commands lacked it. The value, `92dc8ef4…b295`, is V2_SHA256 in pins.env, the plan's literal, and the 01-20 transcript.

**3. [Rule 3] The `root sign` dry run writes unsigned `bundle.json` and `policy.json` into `--out-dir` before the confirmation prompt.** The `--confirm` run reuses them, so `issued_at` stays the same. A note was added to the runbook (66531d6).

### Other deviations

4. **The owner ran `user add` himself** (Task 2 step 7). The Claude Code permission classifier refused it for the agent (credential materialization). Task 2's acceptance line ("user add exited 0 and printed an invite URL") was therefore not observed by Claude. Its effect was checked with `user pending`.
5. **The owner ran the directory commands himself** (Task 4 step 1): approve, role add, role grant, host-group add and host-group map. The classifier refused them for the agent (Permission Grant), and they were not worked around. Claude did not see the approve diff. The contents were checked with `directory show` instead. The first round left the role grant out (directory v4). The owner ran it again, which gave v5.
6. **No auto-merge** (environment rule). Task 4 step 5 and its acceptance criterion "open with auto-merge" are deliberately unmet.
7. **KEY-07 wording:** the 01-14 "Owed" sub-bullet in `deferred-items.md` was renumbered too, for consistency with the 01-21 entry the plan named.
8. **Extra backup** `/etc/sysusers.d/keyroster.conf.pre-02-13`, not in the plan.
9. **healthz body:** the plan says it prints "ok". The actual body is `{"status":"ok"}`.
10. **Unit comments:** `deploy/systemd/keyroster-tailscale-cert.service` and `.timer` still say "UNVERIFIED until the homelab install (02-13)" about runs that have now run. They were not edited: the deploy files are not in this plan, and an edit would make the installed unit's hash differ from the repository. This is a follow-up.
11. **New Linux keyroster** in the rehearsal's `transfer/bin-0213/`. The 01-20 `transfer/keyroster` was kept as recorded in its SHA256SUMS.
12. **Tailscale** was installed on the VM by the orchestrator before Task 2: official apt repository, 1.104.2, `--accept-routes false`. The owner enabled HTTPS certificates on 2026-10-22.

## Open choices for the owner

- **A synced passkey is the owner's only credential.** It is a Chrome passkey, backup eligible and synced, so the copy in Google's passkey store can unlock the homelab admin's login. Options: add a hardware or device-bound passkey as a second credential and later disable the synced one, or keep it for dogfood. Hardware stays optional.
- **02-14's audit assertions** should become `bundle_version==3 and anchor_bundle_version==2` before 02-14 runs (deferred-items.md).
- **The deploy unit comments** (deviation 10) need a follow-up plan or quick task.

## Not exercised (UNVERIFIED)

- A renewal started by the timer, which writes a new certificate and key that the server then loads.
- Login of any kind (02-14), including the approval page's assertion in a real browser.
- Another browser, a hardware authenticator, and `user disable` and `user enable` on a real server.
- The output of the owner-run commands (invite URL, diff, the `Sign directory version N?` prompt). Only their effect was checked.
- The offline steps of the root ceremony (KEY-07, now v4).

## Known Stubs

None. This plan changes documentation and operational state only.

## Threat Flags

None. keyroster-server's network endpoint is part of the plan's threat model (D-10, D-11). The certificate's hostname in CT logs is accepted as T-02-69.

## User Setup Required

None beyond what was done: Tailscale MagicDNS and HTTPS Certificates were enabled by the owner.

## Next Phase Readiness

- 02-14 can use `homelab.export` (12 entries, `ca38b1e8…35dd`) as its `--previous` baseline.
- Directory v5 grants owner `role:homelab-admin` (8 h) on account `zima` in host group `homelab`.
- Fix 02-14's anchor assertions first.

## Self-Check: PASSED

- The files exist: enroll-user.md, server-install.md (5 mentions of 02-13), this SUMMARY, and `$HOME/keyroster-ceremony/phase2/homelab.export` (outside the repository).
- The commits are ancestors of HEAD: 66531d6, 28601c0, 3f3caff and 162478d.
