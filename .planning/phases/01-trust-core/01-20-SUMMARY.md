---
phase: 01-trust-core
plan: 20
subsystem: trust
tags: [trust-bundle, root-rotation, successor, vtpm, homelab, audit, rehearsal, key-07, vis-03]

requires:
  - phase: 01-trust-core
    provides: "root sign --prev (01-17, PR #22); trust verify --prev, audit verify anchored on any bundle in the chain, and the 'Rotate the roots' runbook (01-18, PR #24); the homelab vTPM signer under bundle v1 and TEST roots A and B (01-14); PR #20's signer lock, trust_changed and policy-chain checks"
provides:
  - "The homelab vTPM signer runs the origin/main 69563926 build under trust bundle v2 (sha256 92dc8ef4fcddd35ee965fe3741827d545c75f64fb5ef49240077e8975a09b295), anchored on TEST roots C and D at threshold 1; TEST roots A and B no longer authorize a successor"
  - "Real-system evidence of a successor co-signed across two root sets, stop/install-bundle/start on a vTPM, PR #20's signer serving on a vTPM, and audit anchoring on the new roots of a real signer's log"
  - "Runbooks: step 6 of 'Rotate the roots' and the successor stop, install and start sequence recorded as run on the homelab signer; the offline steps stay UNVERIFIED"
affects: [01-21, KEY-07, VIS-03]

actuals:
  tokens: 25400
  tasks: 3
  commits: 2
plan_head_before: 69563926eb196232f88d235e85ae49bf1ec35642
plan_head_after: e59110a234076f99458f9e9b25d127c1cde35547

tech-stack:
  added: []
  patterns:
    - "One-way door bound to a hash: the owner's reply carries the first 8 hex digits of the bundle SHA-256, and the executor compares it with the recorded hash before the last signature and before anything reaches the signer"
    - "Every WSL ceremony step runs from a script file with explicit PATH, never from an inline scripts/linux.sh string (01-20 Task 1 lost $T inline)"

key-files:
  created:
    - .planning/phases/01-trust-core/01-20-SUMMARY.md
  modified:
    - .planning/phases/01-trust-core/01-20-PLAN.md
    - .planning/phases/01-trust-core/01-21-PLAN.md
    - .planning/ROADMAP.md
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/signer-install.md
    - .planning/phases/01-trust-core/deferred-items.md

key-decisions:
  - "Rehearsal rotation (owner decision 2026-10-09): roots C and D are TEST roots made in WSL on the networked workstation with simulated USB media; the offline ceremony is UNVERIFIED and KEY-07 stays open until a later v3 rotation from C and D onto offline roots"
  - "v2 carries v1's policy unchanged (policy v1, sha256 32df4171...0a817); authoring a new policy is Phase 4"
  - "requirements-completed lists VIS-03 only, and requirements.mark-complete is skipped: KEY-07 stays Pending, and VIS-03's phase-level status is set at re-verification (same handling as 01-18 and 01-19)"
  - "signer-install.md: the 'signer.lock is covered only by the CI smoke check' sentence no longer held (the sandboxed serve on the homelab signer created it), so it now records that; the refusal while the lock is held stays UNVERIFIED there"

patterns-established:
  - "A rehearsal records exactly which runbook steps ran where, and keeps UNVERIFIED on every step it only simulated"

requirements-completed: [VIS-03]

coverage:
  - id: D1
    description: "Successor v2 names exactly TEST roots C and D at threshold 1 (neither A nor B), carries v1's CA, ops and log keys and policy unchanged, is signed by C, D and TEST root A, and verifies with trust verify --prev pinned to the fingerprints root init printed"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "Task 1 summary checks (5 of 5); Task 3 step 2: 'OK: successor of trust bundle v1: previous roots 1 of 2 signed both documents (threshold 1); new roots 2 of 2 signed both documents (threshold 1, pinned)', sha256sum of the verified file = V2_SHA256"
        status: pass
    human_judgment: false
  - id: D2
    description: "The homelab vTPM signer, upgraded to the origin/main 69563926 build, accepts v2 through stop, install-bundle (no pins) and start; doctor shows v2 with no FAIL"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "install-bundle: 'installed bundle version 2 (issued 2026-10-09T13:05:55Z, sha256 92dc8ef4...b295)'; journal msg=serving backend=tpm policy_version=1; NRestarts 0; doctor 'trust bundle version 2 installed (2 roots, threshold 1)', WARN software_root x2 (C, D), WARN vtpm_custody, rc 0"
        status: pass
    human_judgment: false
  - id: D3
    description: "One user certificate issued under v2 from the unchanged vTPM user CA"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "ssh-keygen -L: Key ID kr1/ca=user/sub=u:rotation-check/req=7aa6813e4f978d251ac3a1a0b4f92dc1/pol=1/ser=1791563904373520, Signing CA ECDSA SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0, log leaf 5"
        status: pass
    human_judgment: false
  - id: D4
    description: "audit verify of the exported homelab log anchors on v2 when pinned to C and D, and on v1 when pinned to TEST roots A and B"
    requirement: VIS-03
    verification:
      - kind: manual_procedural
        ref: "'OK: 6 entries, root N63BXCkiwmfJvh60FkSWXUf6w+6mtt8Hm9UGMwzC8N8=, issued 3 ..., trust bundle v2, policy v1' with 'anchored: ... trust bundle v2' (pins C, D) and '... trust bundle v1' (pins A, B); --json anchor_bundle_version 2 and 1"
        status: pass
    human_judgment: false
  - id: D5
    description: "Offline ceremony: live USB, roots on separate physical sticks, paper fingerprints, offline machine (D-10, 01-14 must-have truth 2)"
    requirement: KEY-07
    verification:
      - kind: manual_procedural
        ref: "not run: a rehearsal in WSL on the networked workstation replaced it by owner decision 2026-10-09 (section 'Offline ceremony: UNVERIFIED (rehearsal)')"
        status: fail
    human_judgment: true
    rationale: "Only the owner can run the offline ceremony; it is owed as a later v3 rotation from C and D, which 01-21 records."

duration: "Task 1 by the previous executor ended about 13:06Z (upgrade 13:04Z, v2 issued 13:05:55Z); Task 3 16:30Z-17:10Z; the owner's Task 2 checkpoint lay between"
completed: 2026-10-09
status: complete
---

# Phase 1 Plan 20: Rehearsal Root Rotation Summary

**The homelab vTPM signer moved from TEST roots A and B to TEST roots C and D through successor bundle v2 (`92dc8ef4…b295`). It had first been upgraded to the current main build. v2 was signed by C and D in a WSL rehearsal, approved by the owner by hash, co-signed by A, verified against the printed fingerprints of C and D, and installed with stop, `install-bundle` and start. The signer then issued a `pol=1` certificate. Its exported log verifies anchored on v2 under C and D, and on v1 under A and B. This was a rehearsal on a networked machine, so the offline ceremony is UNVERIFIED and KEY-07 stays open.**

## Performance

- Task 1 (previous executor) ended about 13:06Z on 2026-10-09; its start time is not recorded here. Task 3 ran 16:30Z-17:10Z, after the owner replied at the Task 2 checkpoint.
- Tasks: 3 of 4 (Task 4 is the merge gate)
- PR: #25 (`docs(runbooks): rehearse a root rotation on the homelab signer`), with auto-merge (squash) enabled. On head e59110a, before this SUMMARY commit, all 17 required checks passed.

## Fingerprints and hash (public values)

| Item | Value |
|------|-------|
| TEST root C (new) | `SHA256:fKgl1U8SYbnt5F+CRI27PxZ6B2tSvdy2GEzUpIjCOf8` |
| TEST root D (new) | `SHA256:Om9ywmZu/uvd2+Ad06hJv0cE5tWVUg9OzyGDgBpecTk` |
| TEST root A (previous, co-signed) | `SHA256:rLH3utx6DsJeORfSrjkDK9bxFTHjebeJnVog0sX1WbA` |
| TEST root B (previous, did not sign) | `SHA256:aIDlGVSbtZuDo5wIm6yzA1XGtFk8hb4eFas6qnDjD8M` |
| Bundle v2 SHA-256 | `92dc8ef4fcddd35ee965fe3741827d545c75f64fb5ef49240077e8975a09b295` |
| Bundle v1 SHA-256 (prev) | `2b63fb6dbec9fa13ced75e05480ce93909dfcddbb0903fb93ce94bfdc3fb284a` |
| Policy v1 SHA-256 (carried unchanged) | `32df4171f99138c95ae09839c747cc275e2722650d7c3b27d47d001704e0a817` |

C and D are **TEST roots**, like A and B. They are age-encrypted software roots created on the networked workstation (see "Offline ceremony: UNVERIFIED (rehearsal)").

### Hash equality (v2 SHA-256 in every place)

| Place | Value |
|-------|-------|
| `root sign` summary, root C (dry run and sign, Task 1) | `92dc8ef4…b295` |
| `root sign` summary, root D (dry run and sign, Task 1) | `92dc8ef4…b295` |
| `root sign` summary, TEST root A (dry run and sign, Task 3) | `92dc8ef4…b295` |
| `V2_SHA256` in `pins.env` | `92dc8ef4fcddd35ee965fe3741827d545c75f64fb5ef49240077e8975a09b295` |
| Owner's reply at Task 2 | `rotate 92dc8ef4`, compared with the first 8 hex of `V2_SHA256` before A signed |
| `sha256sum` of the bundle `trust verify --prev` accepted | `92dc8ef4…b295` |
| `install-bundle` output on the signer | `installed bundle version 2 (issued 2026-10-09T13:05:55Z, sha256 92dc8ef4fcddd35ee965fe3741827d545c75f64fb5ef49240077e8975a09b295)` |

The hash was also checked in `public.sha256` on the workstation (all 6 files OK) and by `sha256sum` on the VM, both in `/tmp` and in `incoming/`.

## Build and upgrade (Task 1)

- **Build.** From a clean, detached worktree of origin/main `69563926eb196232f88d235e85ae49bf1ec35642` (go1.27.1, `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath`). `go version -m` shows that `vcs.revision` and `vcs.modified=false`.
  - `keyroster`: `d77aecdcdee106fab6d185e00d2d96f2c4934bfc5ee214e90ac2857a00eb0394`
  - `keyroster-signer`: `f474a2a407a84aef6e0d51e898fa900792da207692bd6fb3d6e36ec5ea05a1bd`
  - The unit from deploy/systemd at that commit is `24058153…d41b`. tpm.conf (`ff2b620a…95bf`) is unchanged.
- **WSL rebuild:** not comparable. The WSL build carried no VCS stamp, so its hash says nothing about reproducibility. The second-machine rebuild of runbook step 1 was not exercised.
- **Upgrade.**
  - The binaries were hash-checked on the VM. Rollback copies `/usr/local/bin/keyroster-signer.24e0ada` and `/usr/local/bin/keyroster.24e0ada` were kept (`69b8290b…0ba`, `dd542ba2…287`), and the old unit (`72e8960c…dfa9`) was set aside.
  - Sequence: stop, install binaries, unit and drop-in, daemon-reload, start. `msg=serving` appeared after about 2 s, with NRestarts 0. This was the first run of PR #20's signer on a vTPM, and no refusal appeared.
  - Unit properties: StartLimitIntervalUSec=10min, StartLimitBurst=5, RestartPreventExitStatus=78, tpm.conf drop-in active. The netns has only `lo`, with CapEff 0, NoNewPrivs 1 and Seccomp 2.
  - `signer.lock` now exists in the state directory (mode 0600, owner keyroster-signer), created when the sandboxed `serve` started.
- **Baseline under v1.**
  - doctor: rc 0, no FAIL, `trust bundle version 1 installed (2 roots, threshold 1)`, WARN `software_root` ×2 (A, B), WARN `vtpm_custody`.
  - Export: 4 entries, sha256 `7cce3203…06ed`, at `$HOME/keyroster-ceremony/rotation-v2/signer-log-v1.export`. `audit verify` pinned to A and B printed OK with `trust bundle v1` and `anchored: the pinned roots are the root set of trust bundle v1`. There were no refusal entries since 01-15.

## Rehearsal ceremony (Task 1, WSL)

- **Layout.** `~/kr-rehearsal-ceremony/` and its subdirectories are 0700. The passphrase files `pass/passC.txt` and `pass/passD.txt` are 0600, each holding 48 characters from `/dev/urandom`, and were never printed.
- **Checks before signing.**
  - `sha256sum -c SHA256SUMS` in `transfer/` passed for the binary and the two prev documents.
  - The prev documents hash to the v1 bundle and policy values above.
  - `date -u` read 2026-10-09 13:05:22Z.
- **Network namespace.** `unshare -r -n cat /proc/net/dev` listed only `lo`. Every `keyroster` ceremony command ran under `unshare -r -n`, with fd 3 opened on the passphrase file.
- **Roots.** `root init --passphrase-fd 3` created C and D. `pins.env` was written from the fingerprints `root init` printed, before any signing.
- **Signing.** v2 was issued 2026-10-09T13:05:55Z. The dry runs of C and D printed the same `Bundle SHA-256`. All five summary checks held:
  - `Successor of trust bundle v1, sha256 2b63fb6d…b284a`;
  - the new roots are exactly C and D, and neither is A or B;
  - the CA, ops and log fingerprints equal 01-14's;
  - the policy sha256 is `32df4171…0a817`;
  - `signatures needed: 1 of the 2 previous roots AND 1 of the 2 new roots, on both documents`.
- `find transfer -name '*.age' -o -name 'pass*'` printed nothing.

## Rotation (Task 3)

1. **Precondition.** The owner's reply `rotate 92dc8ef4` matches the first 8 hex of `V2_SHA256`. Task 2's verify 1 was rerun from a script file and passed, and doctor still showed bundle v1 before A signed.
2. **TEST root A co-signed** where it is kept (`~/kr-test-ceremony/`), under `unshare -r -n` with `--passphrase-fd 3`.
   - The dry run (stdin `/dev/null`) printed `Bundle SHA-256: 92dc8ef4…b295` and listed A and B as `custody=software`. It signed nothing.
   - The run with `--confirm 92dc8ef4` signed both documents. Each `.sigs` file grew from 12 to 18 lines, i.e. three signatures.
3. **trust verify --prev**, pinned to `PIN_C` and `PIN_D` from `pins.env` at threshold 1, listed `signed by previous root SHA256:rLH3…`, `signed by new root SHA256:Om9y…` and `signed by new root SHA256:fKgl…`, then ended with:
   `OK: successor of trust bundle v1: previous roots 1 of 2 signed both documents (threshold 1); new roots 2 of 2 signed both documents (threshold 1, pinned)`
4. **Public outputs.** `public.sha256` covers `pins.env`, `new-roots.pub` and the four `rotation-out` files. They were copied to `$HOME/keyroster-ceremony/rotation-v2/`, and `sha256sum -c public.sha256` passed in WSL and in Git Bash. No `.age` or passphrase file is in that folder.
5. **VM.** The four files were copied with `scp.exe`, installed with `install -o keyroster-signer -g keyroster-signer -m 0640` into `/var/lib/keyroster-signer/incoming/`, and their hashes checked there:
   - bundle `92dc8ef4…b295`;
   - bundle sigs `7f4f95f6…0156`;
   - policy `32df4171…0a817`;
   - policy sigs `4fe758ee…477b`.
6. **Stop, install, start** at 16:37:51Z, exactly in the signer-install.md form:
   - stop, then `systemctl is-active` printed `inactive`;
   - `install-bundle` without `--pin` printed `installed bundle version 2 (issued 2026-10-09T13:05:55Z, sha256 92dc8ef4…b295)`, `roots: 2, threshold 1`, the unchanged CA, ops and log keys, and `policy sha256 32df4171…0a817` (rc 0);
   - after start, the journal shows `msg=serving socket=/run/keyroster-signer/signer.sock backend=tpm policy_version=1`, with the user, host and machine CA and log key unchanged. State active/running, NRestarts 0.
7. **Doctor** (runbook form) had rc 0 and no FAIL.
   - OK: user, state_dir, db_permissions, db_integrity, log, clock, `bundle: trust bundle version 2 installed (2 roots, threshold 1)`, trust, and `tpm` (IBM, vtpm).
   - WARN `software_root` for `SHA256:fKgl1U8S…` (C) and `SHA256:Om9ywmZu…` (D).
   - WARN `vtpm_custody`.
8. **Issue.** A throwaway Ed25519 key was generated in the scratchpad, and only its public key went to the VM. One `ssh.exe -A` command ran `keyroster ca issue --ca user --principal keyroster-rotation-check --subject u:rotation-check --ttl 1h --admin-key SHA256:BUJx6C2+…` and produced:
   - Key ID `kr1/ca=user/sub=u:rotation-check/req=7aa6813e4f978d251ac3a1a0b4f92dc1/pol=1/ser=1791563904373520`;
   - Signing CA `ECDSA SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0`;
   - log leaf 5.

   The key pair and the VM copies were deleted.
9. **Audit.** `export-log` wrote 6 entries (sha256 `cc01648e21df2815c4f304c731e6d54ddd2fa602bccece6bf018a83f6faf4f77`) to `$HOME/keyroster-ceremony/rotation-v2/signer-log-v2.export`. Then `go run ./cmd/keyroster audit verify --threshold 1`:
   - pinned to C and D: `OK: 6 entries, root N63BXCkiwmfJvh60FkSWXUf6w+6mtt8Hm9UGMwzC8N8=, issued 3 (user 3, host 0, machine 0), refusals 0, trust bundle v2, policy v1, log key SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU` and `anchored: the pinned roots are the root set of trust bundle v2`;
   - pinned to A and B: the same OK line and `anchored: the pinned roots are the root set of trust bundle v1`;
   - `--json` kinds: `bundle_install` 2, `ca_init` 1, `issue` 3. `anchor_bundle_version` is 2 under C and D and 1 under A and B, and `refusals` is 0.

## Offline ceremony: UNVERIFIED (rehearsal)

By owner decision 2026-10-09, this plan ran a rehearsal instead of the offline ceremony. These items are **not met** and must not be read as met:

- **D-10's offline media.** No live USB was booted, no physical USB sticks were used, and no offline machine was used. Directories in WSL on the networked workstation stood in for the root sticks and the transfer stick, and each `keyroster` command ran under `unshare -r -n` (only `lo`).
- **01-14 must-have truth 2** (offline ceremony on USB media, checked against paper fingerprints). The fingerprints `root init` printed, written to `pins.env` before signing, stood in for paper.
- **The earlier prohibition that root keys C and D never touch the workstation.** C, D and their passphrase files live in `~/kr-rehearsal-ceremony/` on the workstation's WSL disk, so anyone who compromises the workstation or that disk holds them.
- **The runbook's live-USB, separate-stick and paper steps** ("Rotate the roots" steps 1 to 5 as written), and steps 7 and 8 as written (audit against paper, retire the old roots).
- **The second-machine binary rebuild** of runbook step 1.

**KEY-07 stays open** until the owner's real offline ceremony, which is owed as a later v3 rotation from C and D onto offline roots (01-21 records it). Until then the homelab signer is dogfood only.

## Runbook corrections

- `docs/runbooks/root-ceremony.md`: the closing blockquote of "Rotate the roots" now records that step 6 ran on the homelab vTPM signer in 01-20. It also records that steps 1 to 5 were rehearsed in WSL. The live USB, separate sticks, paper fingerprints and offline machine, and steps 7 and 8 as written, stay **UNVERIFIED**.
- `docs/runbooks/signer-install.md` ("Install a successor bundle"):
  - the note now records that the stop, install and start sequence ran on the vTPM signer;
  - the sentence saying `signer.lock` creation in the sandbox was covered only by CI now also notes the homelab signer;
  - UNVERIFIED stays for the lock refusal and `trust_changed`.
- No runbook step proved wrong. A dedicated "upgrade the binaries" section in signer-install.md is missing; this is logged in `deferred-items.md`, not added here.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Doc accuracy] Stale "covered only by CI" sentence in signer-install.md**
- **Found during:** Task 3 step 9
- **Issue:** The note said `signer.lock` creation inside the systemd sandbox was covered only by the CI smoke check. The homelab signer's sandboxed `serve` created it during the Task 1 upgrade.
- **Fix:** The note now says so, and keeps the lock refusal UNVERIFIED on the homelab signer.
- **Files modified:** docs/runbooks/signer-install.md
- **Commit:** e59110a

### Other notes

- **The plan's output-string note is stale.** It says `trust verify --prev` does not print v2's SHA-256. The 69563926 build prints the full summary, including `Bundle SHA-256: 92dc8ef4…b295`. The `sha256sum` link of the chain was taken anyway, as the plan asks. The plan is unchanged.
- **WSL steps ran from script files.** In Task 1 an inline `scripts/linux.sh` string lost `$T`: it tried `/pins.env`, was refused, and wrote nothing. Every later WSL step ran from a script file with an explicit PATH.
- **`incoming/` on the VM** held v1's copies from 01-14, and v2's files replaced them. v1's documents remain in `~/kr-test-ceremony/ceremony/` and in `transfer/prev/`.

## Issues Encountered

None beyond the inline-WSL quoting issue above. The signer refused nothing (upgrade, install-bundle, start, issue), so no rollback was needed. The 24e0ada rollback copies and the old unit are still on the VM; whether that build serves under v2 was not tested.

## Not exercised

- The offline ceremony items in the section above.
- The second-machine rebuild, and a comparable WSL rebuild (no VCS stamp).
- On the homelab signer: the lock refusal while `serve` holds `signer.lock`, and the `trust_changed` refusal (Go tests only).
- Destroying TEST roots A and B (01-21).
- Hardware roots (issue #13).

## Threat Flags

None. No new network endpoint, auth path or schema change. `-A` was used for the single `ca issue` command only (T-01-93).

## Next

- Task 4 (merge gate): the owner approves PR #25 in the GitHub UI; auto-merge squash-merges it.
- Then 01-21: audit, destroy TEST roots A and B, audit again, record the owed v3 offline rotation, and remove the VM's passwordless sudo.
- Keep roots C and D and their passphrase files in `~/kr-rehearsal-ceremony/` until v3 is co-signed.

## Self-Check: PASSED

- Files: `01-20-SUMMARY.md`, `docs/runbooks/root-ceremony.md` and `docs/runbooks/signer-install.md` exist.
- Commits on the branch: 657e33e (revised plans), e59110a (runbooks) and eb97a1f (this SUMMARY and the tracking updates).
- Gates: Task 3 verify 1 (doctor v2), 2 (trust verify --prev), 3 (public.sha256 and both audit anchors), 4 (SUMMARY, KEY-07 Pending, runbook labels) and 5 (hygiene) passed before this commit. Verify 6 and the required checks run after the push.
