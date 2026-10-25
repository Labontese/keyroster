---
created: 2026-10-25T12:00:00.000Z
title: Harden the signer restore runbook
area: docs
severity: minor
resolves_phase: 4
files:
  - docs/runbooks/signer-install.md
  - test/systemd/smoke.sh
  - test/e2e/restore_test.go
  - internal/audit/verify.go
---

## Problem

The pre-merge review of PR #59 (plan 03-02) checked the signer restore procedure in docs/runbooks/signer-install.md ("A restore brings back the older trust bundle, policy and directory") over several fix rounds. Along the way it collected hardening ideas that the PR deliberately did not fix. None is an open defect: each path either fails closed or is already labelled UNVERIFIED in the runbook. They are collected here so they are not lost. Everything was checked against main at 4aaa62e, and anything main already does is left out.

Owner: Phase 4, next to [Serve refuses to start without a witnessed checkpoint](2026-10-17-serve-refuses-without-witnessed-checkpoint.md). That change removes the rolled-back-signer problem structurally, because a rolled-back signer never serves. Several items below then become operator ergonomics rather than safety.

"Round N" is the review's check of fix round N. The findings of check round N were fixed in the "Pre-merge review fixes, round N+1" section of 03-02-SUMMARY.md. Each item says when it was reproduced. Items not marked as reproduced come from reading the code or the runbook.

## Solution

### Disasters and forks

- **A TPM-backed signer VM lost for good.** The fresh-VM fallback (signer-install.md:496-510) needs the same CA keys. For a physical TPM, or a vTPM whose state is gone, the only way back is therefore a CA rotation, and no runbook covers it. Write one that covers:
  - a fresh signer with new CA, ops and log keys;
  - a root-signed bundle that trusts those keys;
  - the hosts' move to the new user and host CAs;
  - how the break is recorded in the audit log and in the hosts' KRL state (installation ID, last krl_version).

  03-12/03-13's `ca-rotate prepare` does not cover this case. It runs on the existing signer's state: it creates the next key generation in that signer's keystore and records a ca_generation leaf in its log. (Sources: 03-02-SUMMARY fix round 5, "Open for the owner"; round 5, point 8 for the owner.)
- **The vTPM wording.** "Keys in a TPM cannot leave the old VM's TPM" (signer-install.md:507-509) overstates the case for a Proxmox vTPM. Its state is a file on the Proxmox host (signer-install.md:37-43, docs/security/custody.md). Say that moving that state to another VM is a custody decision outside this runbook, and keep the escalation. The rotation item above then covers a physical TPM, or a vTPM whose state is lost. (round 5)
- **The fresh-VM fallback's own steps** (signer-install.md:496-510). Three gaps:
  - It points to this runbook's steps 1-3, but it applies only to the non-TPM backends. Followed literally, those steps run the TPM check and install tpm.conf, which stops the unit from starting where there is no `tss` group. The export in the restore's own step 1 (signer-install.md:526) also uses `runuser -G tss`.
  - It gives no command or file modes for copying the software backend's `software` directory and its passphrase file.
  - It does not say to keep the old VM from ever starting again. Two signers on the same HSM or agent keys fork the log.

  (round 5)
- **Proxmox backup restores.** Name vzdump and Proxmox Backup Server restores next to snapshots, so that the never-boot rule visibly covers them too. (round 5)
- **A fork-report mode in `keyroster audit verify`.** Today, when step 2 finds a fork, the operator can only stop and escalate.
  - Both forked exports verify on the pins (shown in a scratch test), so their common prefix is the run of byte-equal verified leaves.
  - A report mode could list the lost entries and the entries logged after the restore, for example logins by users disabled in a lost version.
  - It could also say whether a replay is still possible, which is only when no install followed the restore.

  This is new verifier surface. An equivocating signer produces the same fork, so escalation should still decide. (round 3)

### File restore and backups

- **Keep the current database.** The file restore block removes the live `signer.db`, `-wal` and `-shm` (signer-install.md:451) without keeping a copy. Move the current set aside instead. If it still opens, export its log under the hold: that is the freshest saved export available. (round 5)
- **Root acting inside the signer's state directory.** `exec 9<"$S/signer.lock"` (signer-install.md:445) has root open a path that the keyroster-signer account controls. It follows links and opens without O_NONBLOCK, so a planted FIFO hangs the restore and a planted link moves the lock to another file. The block's `rm` and `install` in `$S` have the same problem. Apply step 3.2's rule here too: root reads only its own files, and the lock and the writes run as keyroster-signer (`runuser`), on a lock path checked to be a regular file. (round 5; not reproduced)
- **Lock the backup copy too.** The backup paragraph (signer-install.md:413-424) copies the set under the hold but does not take `signer.lock` as the restore does, so a manual `install-bundle` started outside systemd can still write during the copy. Take the same `flock`. Also say whether the TPM `{role}.auth` files and the software backend's `software` directory belong in the backup. (round 5)
- **Check the restored set before step 1.** Run `doctor` (its `db_integrity` check) under the hold right after the file restore. A torn backup is then reported as torn, instead of surfacing later as a refusal from step 1's export or step 2's `audit verify`. (round 4)

### Hold and copy blocks

- **Check every unit name before writing any drop-in.** The hold block (signer-install.md:366-387) writes and loads both drop-ins before it stops anything, and it checks LoadState only after the stops. Suppose the first name is wrong or not installed, for example `keyroster-server` pasted on a signer-only host. Then:
  - the block exits 5 at the first `systemctl stop`;
  - the signer keeps running, or keeps waiting in auto-restart, with the drop-in loaded;
  - a stray `.service.d` directory is left behind;
  - no `held:` line is printed.

  Require every name to be `loaded` before the first `install -d`, so that a bad name changes nothing. (round 4; reproduced with throwaway units in the WSL systemd 255 user manager)
- **Give the admin's `mkdir` no stdin.** In step 3.2's copy block, the `mkdir` line (signer-install.md:735) passes root's heredoc script, on stdin, to a process that runs as the admin. That process could consume the rest of the script through /proc/<pid>/fd/0. The worst outcome found is an aborted run or a false `copied` line. Append `</dev/null`. (round 5)

### VM snapshot path

- **The helper VM** (signer-install.md:472-492). Three additions:
  - Make the helper operator-only: the disk copy carries the TPM `{role}.auth` files and the age-encrypted keys.
  - Watch for an LVM volume-group name clash with the helper's own volumes.
  - Mount so that nothing is written. A `mount -o ro` of a dirty ext4 still replays its journal on a writable copy, so use `ro,noload`; XFS needs `ro,norecovery`.

  (round 5; none of it run)
- **The clock section still describes a booted snapshot.** signer-install.md:312-314 says that a VM restored from a snapshot starts with the snapshot's clock. Reword it for the never-boot rule, under which the files are restored on the current VM. (round 5)

### Tests and drills

- **A committed-frame WAL recovery drill.** CI's backup `-wal` is empty (smoke.sh:379-383), so CI runs only the file handling, and the runbook labels a `-wal` with committed frames UNVERIFIED (signer-install.md:868-869).
  - Build a backup set whose `-wal` holds committed frames, for example after `systemctl kill -s KILL` of the signer, or from a copy made while a reader holds the WAL.
  - Restore it with the block.
  - Require `doctor` to pass and the frames' entries to appear in the restored export.

  (Sources: round 5 Codex; round 4 for how to build the set.)
- **Removing a stale `-wal` when the backup has none.** smoke.sh always gives the backup set a `-wal` (smoke.sh:383), and `install` writes it over the stale one. So a block whose `rm` line no longer lists `"$S/signer.db-wal"` still passes CI. In production, a backup taken under the hold usually has no `-wal`, and that broken block would leave a crashed signer's newer WAL behind, for SQLite to replay onto the older file.
  - Under the hold, run the file restore a second time with a backup of only `signer.db`, over freshly planted stale `-wal` and `-shm` files, and require both to be gone.
  - Optionally, give one backup a `-shm` and `cmp` it after the restore.
  - Otherwise, label this branch UNVERIFIED.

  (round 5; the broken block passing was reproduced in WSL)
- **The start limit in smoke.sh.** The crash loop proves the start limit only through `ActiveState=failed` (smoke.sh:341), which depends on `Restart=on-failure`. Also assert on `NRestarts`, or on the journal line `Start request repeated too quickly`. (round 5)
- **Two refusals CI does not run.** Both behaved correctly in WSL but have no CI coverage:
  - the file restore's refusal of an `activating` signer (labelled UNVERIFIED at signer-install.md:866-867);
  - the admin swapping `replay-v2` for a link right after the `mkdir`.

  Add both to smoke.sh. (round 5)
- **Wider patterns in restore_test.go.**
  - `restoreAdminPathWrite` (restore_test.go:112) matches only a literal `<admin>` or `/home/`, so a root write through `"$H/..."` would pass it. Today the exact-text check of the copy block covers that case.
  - `restoreVMBooted` (restore_test.go:224) catches only the `<id>` placeholder forms, not a command with a numeric VM ID (`qm start` followed by a number).

  Match the variables and any VM ID. (round 5)
- **Order checks in `TestRestoreRunbookChecks`.** The test checks that the copy and the firewall reminder are present, not where they are. It places the release block only between the saved-export stop rule and step 3, not after the clock check or the version greps. Check those positions too. (round 4: a lens note, and a Codex claim that was refuted as a defect)
- **A restore drill on a real signer host.** Run the hold, the file restore and the release once on the homelab signer. Cover what the runbook labels UNVERIFIED there: a running keyroster-server, the TPM drop-in beside the hold, and the firewall rule. Round 4 only reasoned about two more cases; cover them too:
  - a reboot while the hold is in force (the drop-ins in /etc persist);
  - the keyroster-tailscale-cert timer's `try-reload-or-restart` on a held keyroster-server (a no-op on an inactive unit, according to the systemd manual).

  (round 4)

### Not tracked here

- **Already on main, or superseded by it:**
  - the hold drop-in and the release's reset;
  - the file restore's `inactive`/`failed` guard and its lock;
  - the admin copy, which now runs as the admin;
  - the backup method;
  - the rule for where the saved export comes from;
  - the RAM-snapshot rule and the never-boot rule.

  The never-boot rule also makes several earlier options moot: round 3's `link_down`, GRUB `systemd.mask=` and "do not enable at boot" options, and round 4's krlLoop boot-window options (A)-(G). Round 3's alternative of installing the units under /usr/local/lib/systemd/system, so that `systemctl mask` works, is not needed with the tested hold.
- **Lost revocations and the KRL version after a restore** are no longer 03-03's (owner decisions 2026-10-25 on the 03-03 plan check). The krl_version is time-derived (Q1), so no floor is needed. Recovering lost revocations is its own Phase 3 plan, gated before 03-07 (Q2), in the todo [Plan the recovery of revocations that a signer restore lost](2026-10-25-plan-signer-restore-revocation-recovery.md). Until it merges, 03-03's restore stops with the hold in force when the saved export has more `revoke` entries than the restored one.
