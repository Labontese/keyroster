---
phase: 01-trust-core
plan: 14
subsystem: infra
tags: [homelab, vtpm, tpm, systemd, sandbox, doctor, root-ceremony, software-root, audit, dogfood, runbook]

requires:
  - phase: 01-09
    provides: keyroster root init/sign with --passphrase-fd and --confirm, trust verify, software roots (custody=software)
  - phase: 01-11
    provides: TPM backend, vtpm custody from the TPM manufacturer, custody.md
  - phase: 01-13
    provides: sandboxed signer unit plus tpm.conf, sysusers, doctor, signer-install.md
  - phase: 01-08
    provides: export-log and keyroster audit verify --pin --threshold
provides:
  - Homelab signer VM running keyroster-signer under the sandboxed unit with the tpm.conf drop-in, five ECDSA P-256 keys in the vTPM (custody vtpm), bundle v1 installed (operational state, not in the repo)
  - TEST software roots A and B (threshold 1 of 2) and a root-signed genesis bundle and policy (operational state; must be replaced by a real offline ceremony and a successor rotation)
  - Runbook corrections - transcript is kept, not committed; /media mount-path hint; signer-install.md records what ran on the VM
affects: [01-15]

actuals:
  tokens: 5000
  tasks: 3
  commits: 1
plan_head_before: 24e0ada697a20b10cc6eacd0ec925c19b9a97677
plan_head_after: 847db5f72c068734e1a88cb6311098ef87b6175a

tech-stack:
  added: []
  patterns:
    - "Ceremony commands without a TTY: --passphrase-fd for the passphrase, a dry run with empty stdin to print the summary (signs nothing), compare, then --confirm with the computed prefix"
    - "Offline-ish execution on a networked host: unshare -r -n (unprivileged user and network namespace, only lo) around every keyroster ceremony command"

key-files:
  created:
    - .planning/phases/01-trust-core/01-14-SUMMARY.md
  modified:
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/ceremony-transcript-template.md
    - docs/runbooks/signer-install.md
    - .planning/phases/01-trust-core/deferred-items.md

key-decisions:
  - "01-14: owner decision 'Testceremoni nu, riktig sen' - Claude ran a TEST software-root ceremony on the networked workstation (WSL, unshare -r -n per command) instead of the offline USB ceremony; the homelab signer is dogfood only until a real offline ceremony and a successor bundle signed by a test root replace these roots"
  - "01-14: KEY-07 is not marked complete and must-have truth 2 is recorded as unmet; only KEY-04 and VIS-03 are marked complete"
  - "01-14: the ceremony transcript is kept with the owner's records and not committed (runbook step 7 and the template now say so, matching the plan)"
  - "01-14: no admin-signed issuance in this plan (Task 3 does not call for one); the first issuance against the homelab signer belongs to 01-15"

patterns-established:
  - "Dogfood evidence lists the exact command form that ran (runuser -G tss vs sudo -u) and its warning codes, never a paraphrase"

requirements-completed: [KEY-04, VIS-03]

coverage:
  - id: D1
    description: "keyroster-signer runs in the homelab VM under the sandboxed unit with the tpm.conf drop-in; ca-init --backend tpm created five ecdsa-sha2-nistp256 keys in the vTPM, custody vtpm (TPM manufacturer IBM)"
    requirement: KEY-04
    verification:
      - kind: manual_procedural
        ref: "VM: ca-init (Task 1), systemctl is-active -> active, journal 'serving ... backend=tpm', nsenter ip -br link -> lo only, CapEff 0 / NoNewPrivs 1 / Seccomp 2, systemd-analyze security 0.7 SAFE with the drop-in"
        status: pass
    human_judgment: false
  - id: D2
    description: "doctor on the VM after install-bundle: no FAIL; WARN software_root x2 (text 'SOFTWARE ROOT:'), WARN vtpm_custody; OK tpm (IBM -> vtpm)"
    requirement: KEY-04
    verification:
      - kind: manual_procedural
        ref: "runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer doctor --state-dir /var/lib/keyroster-signer (rc 0); plan form sudo -u ... doctor rc 0 with an extra WARN tpm_unavailable"
        status: pass
    human_judgment: false
  - id: D3
    description: "Exported signer log verifies on a second machine against the two pinned roots; entries 0 and 1 are ca_init and bundle_install"
    requirement: VIS-03
    verification:
      - kind: manual_procedural
        ref: "keyroster audit verify --pin A --pin B --threshold 1 signer-log.export -> 'OK: 2 entries ... trust bundle v1, policy v1'; a CA-key pin exits 1"
        status: pass
    human_judgment: false
  - id: D4
    description: "Offline two-root ceremony on separate USB media checked against paper fingerprints (must-have truth 2)"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "not run: a TEST ceremony on a networked workstation replaced it by owner decision (deferred-items.md 01-14)"
        status: fail
    human_judgment: true
    rationale: "Only the owner can run the offline ceremony; it is owed together with a successor rotation."

duration: ~45min (Task 1 by the previous executor, Tasks 2-3 13:10Z-13:25Z)
completed: 2026-10-06
status: complete
---

# Phase 1 Plan 14: Homelab vTPM Signer Summary

**The sandboxed keyroster-signer runs in the homelab Proxmox VM with five vTPM-held ECDSA P-256 keys (custody vtpm) under a root-signed bundle v1. doctor reports no FAIL and warns about the vTPM and the software roots. The exported log verifies on a second machine against both pinned roots (`ca_init`, then `bundle_install`). The roots are TEST roots, made by Claude on a networked workstation at the owner's request, so the signer is dogfood only until a real offline ceremony and a successor rotation are done.**

## Performance

- **Duration:** about 45 min. Task 1 was run by the previous executor; Tasks 2 and 3 ran from about 13:10Z to 13:25Z on 2026-10-06.
- **Tasks:** 3 of 4. Task 4 is the merge gate.
- **PR:** #17 (`docs(runbooks): verify signer install and root ceremony on the homelab vTPM signer`), auto-merge (squash) enabled. Code head `847db5f`.

## Build (Task 1)

- Commit `24e0ada697a20b10cc6eacd0ec925c19b9a97677`, go1.27.1, `CGO_ENABLED=0 -trimpath`, linux/amd64.
- `keyroster`: `dd542ba256bbed51d29bb2b8b403869b9ff75d41f40c96191c6064140fc5f287`. Independently rebuilt on a second machine with the same hash.
- `keyroster-signer`: `69b8290b4133cc4867c6167b40532ac07a36dd123f00bf7cf1f357767c0830ba`.
- The SHA-256 of both binaries was checked on the VM before install.

## ca-init (Task 1, codes only)

- TPM manufacturer `IBM` → custody `vtpm`.
- Five keys, all `ecdsa-sha2-nistp256`, custody `vtpm`:

  | Role | Fingerprint |
  |---|---|
  | user | `SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0` |
  | host | `SHA256:2eKsbePyjgcghoXlRRVHacPxtGfV4/zxpbXdeLKenh8` |
  | machine | `SHA256:39MRSSTQzkrovCWjBgTtqRv4QsnS7x5Dc/TCrhNT6Sk` |
  | ops | `SHA256:CIUep2KZbpAtpqzDFz2NaE0gDmSyQDyqNXuLHBmv/x0` |
  | log | `SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU` |

- `ca-pubkeys.json` SHA-256 `cf65201a109c964247096b2e6605ada6fb6cfa21a803211adcce2026d9a0416e`.
- Genesis policy SHA-256 `32df4171f99138c95ae09839c747cc275e2722650d7c3b27d47d001704e0a817`: admin `owner` `SHA256:BUJx6C2+6jWWCcMiC125cSPtnGCly5QhpRR9EERu2e4`, quorum 1, max TTL 12h (user), 720h (host) and 24h (machine).

## TEST root ceremony (Task 2, replaced by owner decision)

- **Where it ran.** WSL (Ubuntu 24.04) on the owner's workstation, in a private 0700 directory outside the repo. Every `keyroster` ceremony command ran under `unshare -r -n`; inside, `/proc/net/dev` listed only `lo`. The host itself was online.
- **Inputs.** Verified with `sha256sum -c SHA256SUMS`: the binary, `ca-pubkeys.json` and `policy.json` all OK.
- **Roots.** `root init --passphrase-fd` with two independent 48-character random passphrases. They were never printed and exist only as 0600 files next to the keys.
  - Root A: `SHA256:rLH3utx6DsJeORfSrjkDK9bxFTHjebeJnVog0sX1WbA`, `ssh-ed25519`, `custody=software`.
  - Root B: `SHA256:aIDlGVSbtZuDo5wIm6yzA1XGtFk8hb4eFas6qnDjD8M`, `ssh-ed25519`, `custody=software`.
  - `root init` has no label flag, so nothing inside the keys or the bundle says "TEST". Only this SUMMARY, `deferred-items.md` and the owner's private transcript mark them as test roots.
- **Signing.** For each root, a dry run with empty stdin printed the summary and signed nothing. Claude compared the summary with `ca-pubkeys.json` (all five keys byte-identical, fingerprints recomputed with `ssh-keygen`) and with the policy. Then `root sign --confirm 2b63fb6d` ran with A and then B. Both printed `Bundle SHA-256: 2b63fb6dbec9fa13ced75e05480ce93909dfcddbb0903fb93ce94bfdc3fb284a`.
- **Verification.** `trust verify --pin A --pin B --threshold 1` printed `OK: signed by 2 of 2 pinned roots (threshold 1)`. `find ceremony -name '*.age'` was empty.
- **Public outputs** (SHA-256):
  - `bundle.json` `2b63fb6d…b284a`
  - `bundle.json.sigs` `a96d3cdd…4ec037`
  - `policy.json` `32df4171…0a817`
  - `policy.json.sigs` `adc9bf8e…819532`
  - `roots.pub` `83216873…c4d898`
- **Transcript.** Filled in privately next to the keys. It is not committed.

## Install, start, doctor, audit (Task 3)

- **install-bundle** (runbook form, `runuser -G tss`, pins A and B, threshold 1): `installed bundle version 1 (... sha256 2b63fb6d…)`, `roots: 2, threshold 1`, and all five keys `vtpm`.
- **Start.** `systemctl enable --now keyroster-signer.service` is the first real `serve` under the unit with the `tpm.conf` drop-in.
  - The unit is enabled and active, with Drop-In `tpm.conf`.
  - The journal shows `msg=serving ... backend=tpm policy_version=1` and the three CA fingerprints above.
  - The socket is `srw-rw---- keyroster-signer keyroster-admin`.
  - The process groups are `keyroster-signer,keyroster-admin,tss`.
  - `nsenter -n ip -br link` shows only `lo`.
  - `CapEff 0000000000000000`, `NoNewPrivs 1`, `Seccomp 2`.
  - `systemd-analyze security` scores **0.7 SAFE**.
- **doctor** (runbook form, `runuser -u keyroster-signer -g keyroster-signer -G tss`), rc 0, no FAIL:
  - OK: `user`, `state_dir`, `db_permissions`, `db_integrity`, `log`, `clock`, `bundle` (v1, 2 roots, threshold 1), and `tpm` (IBM maps to vtpm, as recorded).
  - WARN `software_root` ×2. The text starts with `SOFTWARE ROOT:`, as the plan requires.
  - WARN `vtpm_custody`.
- **doctor in the plan's verify form** (`sudo -u keyroster-signer`, without `tss`): rc 0 with the same lines plus `WARN tpm_unavailable` (permission denied on `/dev/tpmrm0`). The difference is known from Task 1.
- **export-log**: `exported 2 entries`, export SHA-256 `12ef487c9448989665a4b5bc6696c9c6f4e7f1a15f5e277ebfcb10bd6d367e65`. Index 0 is `ca_init` and index 1 is `bundle_install`.
- **audit verify**, run on the workstation with the hash-checked `keyroster`:
  - `--pin A --pin B --threshold 1` printed `OK: 2 entries, root 3ZsvI4dFV2bNh8acBhwLh/4VLWijiWLXJ5TZMkw03Vc=, issued 0 (user 0, host 0, machine 0), refusals 0, trust bundle v1, policy v1, log key SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU`.
  - The `--json` output shows `kinds: {ca_init: 1, bundle_install: 1}`.
  - A negative run that pins a CA key instead of a root exited 1 (`bundle_install is not anchored in the pinned roots`).

## Runbook corrections

- **`root-ceremony.md` step 7 and `ceremony-transcript-template.md`:** keep the filled-in transcript with your own records; do not commit it. The runbook and the template said "commit"; the plan says "not committed", and the storage section names where the media and passphrases are kept.
- **`root-ceremony.md` step 1.5:** the `/media/transfer`, `/media/usbA` and `/media/usbB` paths are placeholders. Live sessions usually mount under `/media/<user>/<LABEL>`, and `lsblk -o NAME,LABEL,MOUNTPOINT` shows where. This is a hint and was **not exercised**, because no live USB was used.
- **`signer-install.md`:** the CI caveat now records that the TPM path ran by hand on the homelab VM in 01-14 (steps 1 to 9, except the issuance example), and that the agent unit's PKCS#11 path still has not run anywhere.

`signer-install.md` steps 6, 7 and 9 worked as written. The offline steps of `root-ceremony.md` (live USB, `rfkill`, separate sticks, paper fingerprints, `ip -br link`) were **not** exercised. Its `root init`, `root sign` and `trust verify` commands ran as written apart from the non-interactive flags.

## Deviations from Plan

### Owner-decided deviations

**1. TEST root ceremony instead of the owner's offline ceremony (Task 2)**
- **Why:** the owner could not run the ceremony today. The laptop was packed, and the USB attempt failed because Step A was copied to fixed disk E: instead of a stick. After being told the consequences, the owner chose "Testceremoni nu, riktig sen".
- **What ran:** Claude generated both roots and passphrases on a networked machine. The passphrases are on the same disk as the keys. No paper fingerprints exist; the pins came from the `root init` output.
- **Consequences:**
  - Must-have truth 2 (offline ceremony, USB media, paper fingerprints) is **unmet**.
  - The prohibition "Root passphrases, root key files and the root USB media must never touch the Claude session, the workstation's disks or any networked machine" (plan wording, workstation name elided) was **violated, with the owner's consent**. Neither passphrase was ever printed, logged or committed.
  - KEY-07 is **not** marked complete.
  - The homelab signer must not be treated as a trusted CA.
- **Follow-up (owner action):** a real offline ceremony, then a successor bundle naming the real roots, signed by a test root. Keep the test roots until then. See `deferred-items.md`.
- **Gap (found while closing the plan, not exercised):** `install-bundle` already accepts successors (`trust.VerifySuccessor`), but no `keyroster` command builds one; `root sign` produces genesis bundles only (version 1, all-zero `prev`). Either a successor-signing command is added first, or the homelab signer is started over (wipe state, `ca-init` again, real genesis bundle), which does not need the test roots.

**2. Second build machine (Task 1)**
- The independent `keyroster` rebuild ran on another homelab machine instead of the laptop. The source was carried as a git bundle because that machine has no github.com egress, and the Go toolchain hash was checked against go.dev. The hashes are identical.

### Auto-fixed issues

**1. [Rule 1 - Doc bug] The transcript template also said "commit it"**
- **Found during:** Task 2.
- **Issue:** fixing only runbook step 7 would have left the template contradicting the plan.
- **Fix:** the template intro now says to keep the transcript, not commit it. This file is outside the plan's `files_modified`.
- **Commit:** `847db5f`.

### Plan-check notes

- **The plan's doctor form** (`sudo -u keyroster-signer ... doctor`) adds `WARN tpm_unavailable`, because that user is not in `tss` outside the unit. The runbook's `runuser -G tss` form is the correct one, and both forms exit 0 without FAIL.
- **No admin-signed issuance.** Task 3 does not call for one, and the admin key is in the Windows agent. The first issuance against this signer belongs to 01-15.
- **The audit was verified only on the workstation.** An extra attempt on the VM failed because the copied `keyroster` there is not executable (Permission denied). It was informational only and had no effect.
- **The WINDOWS ledger was not updated.** `.planning/WINDOWS.md` does not exist in this project, so the unmet truth is recorded in `deferred-items.md` instead.

## Not exercised

- The offline ceremony path: live USB, network disabled with `rfkill`, separate sticks, paper fingerprints, and the mount-path hint.
- Issuance through the homelab signer, which is owed to 01-15.
- The agent unit's PKCS#11 path under the sandbox.

## Threat Flags

None. No code changed. The only new surface is operational: a running signer socket on the VM, reachable by `keyroster-admin` members only, as designed in 01-13.

## Next

- **01-15:** Windows OpenSSH 9.5p2 check against this signer.
- **Owner:**
  - Remove passwordless sudo on the VM after 01-15.
  - Decide what to do with the six public ceremony files left on fixed disk E:.
  - Move the test-root passphrases into the password manager and the `.age` files onto USB, then delete them from the workstation. Keep them until the successor rotation is done.

## Self-Check: PASSED

- The three runbook files and this SUMMARY exist, and commit `847db5f` is on `p01/14-homelab`.
- Required checks are green on `847db5f`: build-test, e2e (9.5p1), e2e (10.5p1), fuzz, govulncheck, lint and pr-title.
- The private test-root files (two `.age` files, two passphrase files and the transcript) exist with mode 0600 outside the repo. None of them is in git.
