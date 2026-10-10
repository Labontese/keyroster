---
phase: 01-trust-core
plan: 21
subsystem: trust
tags: [trust-bundle, root-rotation, test-roots, retirement, homelab, audit, rehearsal, key-07]

requires:
  - phase: 01-trust-core
    provides: "The homelab vTPM signer under trust bundle v2 anchored on TEST roots C and D (01-20, PR #25); audit verify anchored on any bundle in the chain (01-18, PR #24); TEST roots A and B and bundle v1 (01-14)"
provides:
  - "TEST roots A and B retired: the WSL copies of their key and passphrase files removed with shred -u and checked by Claude; no other copy, as attested by the owner"
  - "Evidence that the destruction removed no audit capability: the post-destruction export is byte-identical to the pre-destruction one and verifies anchored on v2 under C and D and on v1 under the public fingerprints of A and B"
  - "deferred-items.md: the real offline ceremony recorded as owed by the owner as a v3 rotation co-signed by C or D, after which C and D are destroyed; KEY-07 stays open until then"
  - "root-ceremony.md: step 8 of 'Rotate the roots' recorded as run for networked-workstation TEST roots only; step 7 as written and the offline steps stay UNVERIFIED"
affects: [KEY-07, phase-01-reverification]

actuals:
  tokens: 6200
  tasks: 3
  commits: 1
plan_head_before: ef0e74d9b2863d405d960b403a6c69fa6d6ab639
plan_head_after: 9061090037b48a924ff7b21b3e5031545eb2b6ea

tech-stack:
  added: []
  patterns:
    - "Guard list before a destructive step: hash the keys that must survive (mode 0600, never printed) before the owner destroys their siblings, and check it again afterwards"
    - "Prove no loss of audit capability by re-exporting after the destruction and comparing bytes with the pre-destruction export, then verifying under both pin sets"

key-files:
  created:
    - .planning/phases/01-trust-core/01-21-SUMMARY.md
  modified:
    - .planning/phases/01-trust-core/deferred-items.md
    - docs/runbooks/root-ceremony.md
    - .planning/STATE.md
    - .planning/ROADMAP.md

key-decisions:
  - "KEY-07 stays open (owner decision 2026-10-09): requirements-completed is empty and requirements.mark-complete is skipped; the real offline ceremony is owed as a v3 rotation co-signed by C or D, followed by the destruction of C and D"
  - "TEST roots C and D are kept in the rehearsal directory: they are the only keys that can authorize a successor on the homelab signer"
  - "The owner keeps the 01-14 ceremony transcript in the TEST-root directory; it is never committed"

patterns-established:
  - "A destruction is recorded by who checked what: Claude's own checks (WSL by name, the guard list, the audit) separately from the owner's attestation (location kinds only, no paths)"

requirements-completed: []

coverage:
  - id: D1
    description: "Before anything is destroyed: doctor on the homelab signer shows bundle v2 (2 roots, threshold 1, no FAIL); trust verify --prev of v2 pinned to C and D prints OK; a fresh export verifies anchored on v2 under C and D and on v1 under A and B"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "Task 1 verifies 1-3: doctor 'trust bundle version 2 installed (2 roots, threshold 1)', WARN software_root (C, D) and vtpm_custody, no FAIL; 'OK: successor of trust bundle v1: ...'; pre-destruction export 6 entries, sha256 cc01648e...4f77, anchored v2 (C, D) and v1 (A, B)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every known copy of the private files of TEST roots A and B is destroyed; no copy remains in the WSL home outside the rehearsal directory"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "Task 2 verify 1 (no .age or pass* file in the TEST-root directory; home-wide search for the four names, pruning the rehearsal directory, finds nothing): pass. Other location kinds: owner attested"
        status: pass
    human_judgment: true
    rationale: "Copies outside WSL (USB, password manager, a second local drive) cannot be checked by Claude; the owner attested that none existed. shred on a virtual disk is not a guaranteed erase."
  - id: D3
    description: "Roots C and D and their passphrase files are untouched"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "Task 2 verify 2: sha256sum -c --quiet cd-files.sha256 (taken in Task 1) passes and transfer/pins.env is non-empty"
        status: pass
    human_judgment: false
  - id: D4
    description: "After the destruction, a fresh export still verifies under the public fingerprints of A and B (anchor v1) and under C and D (anchor v2)"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "Task 3 verify 1: post-destruction export byte-identical to the pre-destruction one (6 entries, sha256 cc01648e...4f77); 'anchored: the pinned roots are the root set of trust bundle v2' (C, D) and '... v1' (A, B)"
        status: pass
    human_judgment: false
  - id: D5
    description: "The real offline ceremony (live USB, separate sticks, paper fingerprints, offline machine) and the destruction of roots held on offline media"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "not run: owed by the owner as a v3 rotation from C and D (deferred-items.md, 01-14 entry)"
        status: fail
    human_judgment: true
    rationale: "Only the owner can run the offline ceremony. KEY-07 stays open until it is done."
  - id: D6
    description: "Passwordless sudo removed from the VM (/etc/sudoers.d/90-cloud-init-users)"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "owed at the Task 4 merge gate (owner action); checked there by Task 4 verify 1 (sudo -n true must fail over SSH)"
        status: pending
    human_judgment: true
    rationale: "The owner removes it at the merge gate, after both fresh exports, which needed it."

duration: "Task 1 (previous executor) ended about 04:40Z on 2026-10-10 (pre-destruction export 04:36Z); Task 3 ran 05:33Z-05:50Z; the owner's Task 2 checkpoint lay between"
completed: 2026-10-10
status: complete
---

# Phase 1 Plan 21: Retire the Homelab TEST Roots Summary

**TEST roots A and B of 01-14 are retired. Before the destruction, the homelab signer was shown to rest on bundle v2 with TEST roots C and D alone, its log verified under both pin sets, and the files of C and D were fingerprinted. The owner then removed the WSL copies of A and B and their passphrase files with `shred -u`, and attested that no other copy existed. Afterwards Claude found no trace of A or B in the WSL home. The C and D fingerprint list still checks, and a fresh export, byte-identical to the one before, still verifies anchored on v2 under C and D and on v1 under the public fingerprints of A and B. KEY-07 stays open: the real offline ceremony is owed as a v3 rotation co-signed by C or D, after which C and D are destroyed.**

## Performance

- Task 1 was run by the previous executor and ended about 04:40Z on 2026-10-10 (pre-destruction export at 04:36Z). Task 3 ran 05:33Z-05:50Z, after the owner's Task 2 reply.
- Tasks: 3 of 4 (Task 4 is the merge gate).
- PR: #26 (`docs(01): retire the homelab TEST roots A and B`), with auto-merge (squash) enabled. On head 9061090, before this SUMMARY commit, all 17 required checks passed.

## Public values

| Item | Value |
|------|-------|
| TEST root A (retired) | `SHA256:rLH3utx6DsJeORfSrjkDK9bxFTHjebeJnVog0sX1WbA` |
| TEST root B (retired) | `SHA256:aIDlGVSbtZuDo5wIm6yzA1XGtFk8hb4eFas6qnDjD8M` |
| TEST root C (kept) | `SHA256:fKgl1U8SYbnt5F+CRI27PxZ6B2tSvdy2GEzUpIjCOf8` |
| TEST root D (kept) | `SHA256:Om9ywmZu/uvd2+Ad06hJv0cE5tWVUg9OzyGDgBpecTk` |
| Bundle v2 SHA-256 (in force) | `92dc8ef4fcddd35ee965fe3741827d545c75f64fb5ef49240077e8975a09b295` |
| Log export SHA-256, before and after | `cc01648e21df2815c4f304c731e6d54ddd2fa602bccece6bf018a83f6faf4f77` (6 entries) |

## Before the destruction (Task 1)

1. **Signer state.** Doctor in the runbook form: `trust bundle version 2 installed (2 roots, threshold 1)`, no FAIL. WARN `software_root` for C and for D, and WARN `vtpm_custody`. The service was active.
2. **Root set of v2.** `trust verify --prev`, pinned to `PIN_C` and `PIN_D` from the rehearsal `pins.env` at threshold 1, printed `OK: successor of trust bundle v1: ...`. The verified bundle hashes to `V2_SHA256` (`92dc8ef4…b295`).
3. **Fresh audit.** `export-log` wrote 6 entries (sha256 `cc01648e…4f77`), byte-identical to 01-20's v2 export. `audit verify --threshold 1`:
   - pinned to C and D: `OK: 6 entries, ... issued 3 (user 3, host 0, machine 0), refusals 0, trust bundle v2, policy v1, ...` and `anchored: the pinned roots are the root set of trust bundle v2`;
   - pinned to A and B: the same OK line and `anchored: the pinned roots are the root set of trust bundle v1`.
4. **Guard list for C and D.** `cd-files.sha256` covers the key files of C and D and their two passphrase files: 4 lines, relative paths, mode 0600. It was written with umask 077 and noclobber, was never printed, and is not committed.
5. **Inventory.** The only copies of the private files of A and B were the four files in the TEST-root directory in WSL (two `.age` keys, two passphrase files).
   - Searched by name and by content: the WSL home (pruning the rehearsal directory) and `/tmp`, the Windows profile, the VM root filesystem, and the temp area (as reported by the Task 1 executor). No other copy was found.
   - A second local drive was not searched by Claude (the search timed out); the owner attests nothing is there.
   - The public files in the TEST-root directory were marked "may stay". The transcript was marked "owner decides", and the rehearsal directory "keep, do not touch".

## Destruction (Task 2, owner)

The owner ran `shred -u` on the four named files in an interactive WSL shell and replied `destroyed` on 2026-10-10.

**Owner attested, by location kind:**

| Location kind | Outcome |
|---------------|---------|
| WSL TEST-root directory (the four private files) | Destroyed with `shred -u` by the owner |
| USB copy | None ever existed |
| Password-manager entries | None existed |
| Second local drive | Nothing there |
| 01-14 ceremony transcript | Kept by the owner in the TEST-root directory, never committed |

**Checked by Claude (Task 2 verifies, rerun from script files):**
- verify 1: the TEST-root directory still exists and holds no `.age` or `pass*` file, and the home-wide search for `root-[ab].age` and `pass[AB].txt`, pruning the rehearsal directory, finds nothing. Pass.
- verify 2: `sha256sum -c --quiet cd-files.sha256` passes in the rehearsal directory, and `transfer/pins.env` is non-empty. Pass. Roots C and D and their passphrase files are byte-identical to Task 1.

`shred` on WSL's virtual disk is not a guaranteed erase, so A and B stay treated as exposed. What protects the homelab is the rotation: v2 needs C or D for any successor, and auditors pin C and D.

## After the destruction (Task 3)

1. **Fresh export.** `export-log` (as keyroster-signer) printed `exported 6 entries`. Its SHA-256 is `cc01648e21df2815c4f304c731e6d54ddd2fa602bccece6bf018a83f6faf4f77`, byte-identical to the pre-destruction export, so there are no new entries.
2. **audit verify, `--threshold 1`:**
   - pinned to C and D:
     ```
     OK: 6 entries, root N63BXCkiwmfJvh60FkSWXUf6w+6mtt8Hm9UGMwzC8N8=, issued 3 (user 3, host 0, machine 0), refusals 0, trust bundle v2, policy v1, log key SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU
     anchored: the pinned roots are the root set of trust bundle v2
     ```
   - pinned to the public fingerprints of A and B:
     ```
     OK: 6 entries, root N63BXCkiwmfJvh60FkSWXUf6w+6mtt8Hm9UGMwzC8N8=, issued 3 (user 3, host 0, machine 0), refusals 0, trust bundle v2, policy v1, log key SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU
     anchored: the pinned roots are the root set of trust bundle v1
     ```
   Destroying the private keys removed no audit capability.
3. **deferred-items.md (additions only, 6 lines added, 0 deleted).**
   - Under the 01-14 TEST-root entry, a sub-bullet `Rehearsal rotation, not the real ceremony (owner decision 2026-10-09; plans 01-20 and 01-21)`. It supersedes the three "planned" lines of the "Gap closure planned" sub-bullet and records the rehearsal (01-20), the destruction of A and B (01-21) and the owed v3 rotation. It also records that KEY-07 and 01-14 must-have truth 2 stay open.
   - A new entry, `01-20/01-21: the real offline root ceremony is owed as a v3 rotation from TEST roots C and D (owner action)`, after the 01-15 reconciliation entry.
4. **root-ceremony.md.** The closing blockquote of "Rotate the roots" now records that 01-21 ran step 8 for TEST roots A and B only, which were held on a networked workstation. The WSL copies were removed with `shred -u` and checked, and the owner attested to the rest; this is not a guaranteed erase. Destroying roots on offline media, step 7 as written (pins from paper) and the offline steps stay **UNVERIFIED**. The previous wording, "steps 7 and 8 as written" UNVERIFIED, was narrowed accordingly.

## KEY-07: still open

This plan does not close KEY-07, and `requirements-completed` is empty. C and D, like A and B, are TEST roots made on a networked workstation. The real offline ceremony is owed by the owner as a **v3 rotation**:

1. On a live USB, with no network, two new roots are made on separate USB sticks. Their fingerprints are written on paper.
2. Successor bundle v3 names the new roots. One of TEST roots C or D co-signs v3 where it is kept, under the successor rule ("Rotate the roots", step 4).
3. `trust verify --prev` is checked against the paper fingerprints. v3 is installed on the homelab signer with stop, `install-bundle` and start, and the audit is pinned to the new roots from the paper.
4. Then C and D, and their passphrase files, are destroyed.

Until then KEY-07 and 01-14 must-have truth 2 stay open, and the homelab signer is dogfood only. REQUIREMENTS.md is unchanged for KEY-07 (`- [ ] **KEY-07**`, `| KEY-07 | Phase 1 | Pending |`).

## Owed at the merge gate (Task 4)

The owner removes the VM's cloud-init passwordless sudo rule, `/etc/sudoers.d/90-cloud-init-users`, from an open root shell, after confirming a usable password and `sudo` group membership. Password sudo is tested in a second session before that shell closes. Task 4 verify 1 checks over SSH that `sudo -n true` now fails. From then on, any VM check needs the owner's sudo password.

## Deviations from Plan

### Auto-fixed Issues

None.

### Other notes

- **WSL verifies ran from script files.** Task 1 verify 2, run inline through `scripts/linux.sh`, lost its variables (the known quirk from 01-20); it was read-only and wrote nothing. Its verbatim body then passed from a script file. Task 2's two verifies were run from script files from the start.
- **Runbook wording narrowed, not added.** The 01-20 blockquote listed "steps 7 and 8 as written" as UNVERIFIED. Step 8 has now run for TEST roots on a networked workstation, so the blockquote keeps UNVERIFIED for step 7 as written and adds a separate 01-21 paragraph for step 8. The heading line now names steps 6 and 8.
- **Tracking.** GSD's tracking updates ran once, without `requirements.mark-complete` (01-18 to 01-20 precedent).

## Issues Encountered

None. Every check passed on the first run from a script file, and the post-destruction export matched the pre-destruction one byte for byte.

## Not exercised

- The real offline ceremony and the destruction of roots held on offline media (owed as v3).
- Copies outside WSL: there were none to check, and the owner's attestation is the evidence.
- The removal of passwordless sudo (Task 4, owner).

## Threat Flags

None. No code changed, and no new network endpoint, auth path or schema change.

## Next

- Task 4 (merge gate): the owner removes the VM's passwordless sudo, then approves PR #26 in the GitHub UI, and auto-merge squash-merges it.
- After that, phase 1 re-verification (`/gsd-verify-work 1`) may run. It will find KEY-07 open, owed to the owner's v3 ceremony.
- Keep roots C and D and their passphrase files in the rehearsal directory until v3 is co-signed.

## Self-Check: PASSED

- Files: `01-21-SUMMARY.md`, `deferred-items.md` and `docs/runbooks/root-ceremony.md` exist.
- Commits on the branch: 9061090 (deferred items and runbook) and the commit that adds this SUMMARY and the tracking updates.
- Gates: Task 2 verifies 1 and 2, and Task 3 verifies 1 (post-destruction audit under both pin sets), 2 (KEY-07 Pending, `requirements-completed: []`), 3 (additions only, runbook labels) and 4 (hygiene) passed before this commit. Verify 5 and the required checks run after the push.
