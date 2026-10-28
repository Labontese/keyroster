---
phase: 03-linux-agent-and-revocation
plan: 06c
subsystem: revocation
tags: [krl, revocation, restore, recovery, runbook, e2e, systemd]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-06b: keyroster-server's krl-served.json, leaf kind 15 revocation_recovery, keyroster revoke recover, keyroster-signer recover-revocations, their output lines and refusal names (03-06b-SUMMARY.md, final state after PR #69 review rounds 1 and 2); 03-03: the restore stop this plan replaces; 03-02: the hold, file restore, release and copy blocks"
provides:
  - "signer-install.md: the capture block right after the hold's held: line (kept: or no server KRL copy), step 2b in place of 03-03's stop (clock check, copy block, keyroster revoke recover with --krl, read-back block, recover-revocations under the hold, the recovered export and its verifies, the refusal list), and the release only after step 2b"
  - "TestRestoreRecoversLostRevocations: the restore drill through the runbook's commands, with ssh-keygen -Q and sshd (CI e2e)"
  - "TestRestoreRunbookChecks: the recovery blocks pinned verbatim in the runbook and in smoke.sh, with their order; 03-03's stop must stay gone"
  - "test/systemd/smoke.sh: the capture block in three outcomes, the copy and read-back blocks and the recovery line run verbatim in systemd-sandbox"
  - "revoke.md sections 6 and 7: the server's KRL copy and its 503 answers, step 2b, and revoking a kept host or machine certificate by key"
affects: [03-07, 03-10, 03-12, 03-13, 03-16]

actuals:
  tokens: 17546    # chars/4 over the added and removed lines of the plan diff (154e6c5..5be604d)
  tasks: 3
  commits: 3
plan_head_before: 154e6c5b7d3b915c0b5c261af49a8adacb723703
plan_head_after: 5be604d2028f5ea3fc1ac21b56e3ce6cff5474cc

tech-stack:
  added: []
  patterns:
    - "A runbook block that can end in two outcomes prints exactly one of two pinned lines, and checks its preconditions on lines outside any if condition, because bash -e does not stop on a failing if condition"
    - "Each sshd refusal in an e2e drill comes from its own loopback source (BindAddress=127.0.0.N), so OpenSSH 10.x's PerSourcePenalties never touch the accepted logins"

key-files:
  created:
    - .planning/todos/pending/2026-10-28-split-one-recovery-over-several-leaves.md
  modified:
    - docs/runbooks/signer-install.md
    - docs/runbooks/revoke.md
    - docs/runbooks/server-install.md
    - test/e2e/recovery_test.go
    - test/e2e/restore_test.go
    - test/systemd/smoke.sh
    - .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md (moved from pending/)

key-decisions:
  - "03-06c: every signer restore runs step 2b under the hold, whatever step 2's counts show; the hold is released only after the recovery's two verifies passed, or after nothing to recover when the capture block printed no server KRL copy; after kept:, nothing to recover keeps the hold and escalates"
  - "03-06c: the capture block refuses, and claims neither outcome, when the server account cannot reach /var/lib/keyroster-server, when /root/recovery exists, or when the file cannot be read; root reads the server's file only as keyroster-server"
  - "03-06c: the runbook counts the recovery with grep -c '\"kind\":\"revocation_recovery\"' after audit verify, because audit verify's text report has no recovery count and binds the kind key of every line"

requirements-completed: []

duration: 29min
completed: 2026-10-28
status: complete
---

# Phase 3 Plan 06c: Restore Procedure Summary

**Every signer restore now recovers the revocations it lost, under the hold, before the restored signer serves a KRL.** The runbook keeps keyroster-server's KRL copy right after the hold. Step 2b, which replaces 03-03's stop, checks the clock and has an admin of the restored policy sign `keyroster revoke recover`. The operator then applies the request with `keyroster-signer recover-revocations`, and only then releases the hold. CI runs every block: `TestRestoreRecoversLostRevocations` in e2e, and the runbook's own blocks in systemd-sandbox.

PR: from branch `p03/06c-restore-procedure` (the SUMMARY is pushed before the PR opens, as 03-03b deviation 8 records; the PR number is in the PR itself and in the executor's report).

Lost-certificates answer the runbook follows: `revoke-users-list-others` (03-06b-SUMMARY.md). Every lost user certificate is revoked, and lost host and machine certificates are listed with their public keys and revoked only with `--revoke-lost SERIAL` or later by key. The runbook follows 03-06b's final rule (PR #69 review round 2): a user certificate is revoked whatever the clocks say, and expired host and machine certificates are counted, not carried.

## Owner attention first

- **Nothing in the restore starts the signer before step 2b.** The hold stays from `held:` until the release, and the release paragraph names its two conditions. The capture block runs right after `held:` and before the file restore. TestRestoreRunbookChecks pins both positions.
- **The server copy goes in as `--krl` whenever the capture block kept it.** The copy block copies `server-krl.json` exactly when the capture kept it, and the admin checks that the summary lists it among the imports. `nothing to recover` releases the hold only after `no server KRL copy`; after `kept:` it keeps the hold (PR #66 carry-over, pinned).
- **Look closely at** the capture block's first line (`runuser -u keyroster-server -- test -d ... -a -x ...`). It is outside the `if` on purpose. Inside an `if` condition a failing `runuser` (no such user, no state directory) would fall through to `no server KRL copy`, the false claim the carry-over forbids. smoke.sh runs that case and requires that neither line is printed.

## The runbook's blocks and their pinned positions

All of them are in "A restore brings back the older trust bundle, policy and directory". TestRestoreRunbookChecks checks the order on the section with its white space collapsed. Mutants of each order check were killed locally (section "What ran").

| # | Block | Pinned | Run verbatim in smoke.sh |
|---|---|---|---|
| 1 | Hold block (03-02), ends `held:` | before the capture | yes (03-02) |
| 2 | **Capture block**: `kept: /root/recovery/server-krl.json` or `no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist` | after the hold, before the file restore; both lines; the `--krl` rule | yes, three outcomes and the existing-directory refusal |
| 3 | File restore block (03-02) | after the capture, before step 1 | yes (03-02) |
| 4 | Step 2's verifies and counts (03-02, 03-03) | the revoke count after the saved export's verify stop | — |
| 5 | **Step 2b part 1**, clock check (`Check the clock, under the hold, before the recovery.`) | after the counts, before the copy block | — |
| 6 | **Step 2b part 2**, copy block (writes as the admin) | after the clock check | yes: planted link refused, then with and without the server copy |
| 7 | **Step 2b part 3**, `keyroster revoke recover --restored ... --saved ... --krl ... --out ...` and the `--krl` rule | after the copy block | — (the drill runs the command) |
| 8 | **Step 2b part 4**, read-back block (reads as the admin) | after the admin's command | yes |
| 9 | **Step 2b part 5**, the recovery line `runuser ... -- keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin` | after the read-back | yes, refused `recovery_malformed`, signer.db unchanged |
| 10 | The export to `/tmp/recovered.jsonl`, its two verifies and `grep -c '"kind":"revocation_recovery"'` | after the recovery line | — (the drill runs them) |
| 11 | The rule that `nothing to recover` after `kept:` keeps the hold | in the refusal list, before the release | — |
| 12 | `**Release the hold** only after step 2b, in one of two cases:` and the release block | after step 2b, before step 3 | yes (03-02) |

03-03's stop (`the restore lost a revocation: do not release the hold`) and its interim text (`Until the restore-recovery plan merges`) must not come back, and the saved-export rule must stay. restoreAdminPathWrite still finds no root write to an admin path.

## The drill's cases (TestRestoreRecoversLostRevocations)

The setup, in order:

1. Certificates A and B (user) and the control E (user, never revoked) are issued before the backup.
2. The backup: `signer.db` copied from the stopped signer.
3. After the backup: C (user, subject `carol`), D (user, subject `dave`) and H (host) are issued. A is revoked by key ID, C with `keyroster revoke user carol` (the test asserts the answer lists C's serial), and the plain key K with `keyroster revoke key`.
4. The saved export.
5. B is revoked with `keyroster revoke serial` through keyroster-server, which serves and keeps it.
6. The hold: the server and the signer are stopped, the server's copy is kept, and the backup is restored.

Then:

- step 2: the restored export on its own, the saved export on its own and with `--previous` set to the restored export;
- `keyroster revoke recover --krl`: the summary lists the server copy among the imports, revokes C and D (`(live): revoke`) and keeps H with its public key, with exactly three lost certificates and none expired;
- the pending cases:
  - refused while the test holds `signer.lock`;
  - refused `recovery_evidence_invalid` with the evidence replaced by a valid SSHSIG of a key that is no admin;
  - both with the export unchanged byte for byte;
  - the genuine file then applies once (`recovered: ... from 2 imported KRLs, 2 lost certificates revoked, 1 kept`);
  - a second run is refused `recovery_log_mismatch`;
- the recovered log adds exactly `[revocation_recovery krl_publish]` to the restored log, so no KRL lies between the restored log's end and the recovery, and it verifies on its own and with `--previous` set to the restored export;
- with both started again, `krl-served.json` holds the recovered version;
- the served KRL makes `ssh-keygen -Q` refuse A, B, C, D and K and accept E and H;
- sshd refuses A, B, C and D (each from its own loopback source, with sshd's `revoked` log line) and accepts E;
- H is revoked with `keyroster revoke key` and the public key read from the summary, and the next KRL refuses H;
- the signer restarts: the served KRL version is unchanged, and it still refuses A, B, C, D, H and K and accepts E;
- the final export verifies with `--previous` set to the restored export.

The comment names 03-10's negative-probe case as the drill's extension point.

## Performance

- **Duration:** 29 min, from the start mark (2026-10-28T05:33Z) to the last task commit, including three CI runs.
- **Tasks:** 3 of 4 (Task 4 is the owner's merge gate).
- **Files:** 6 changed in the repository's code and docs, the todo moved, and one new todo. The plan named 5 files and the move; deviations 9 and 10 add server-install.md and the new todo.
- **Estimate:** 57 000 tokens (confidence low); actual 17 546 by chars/4 over the diff's lines. The plan's estimate counted reading as well as writing.

## Task Commits

1. **Task 1 (tracer):** `d7bfaf7` (feat): the capture block, step 2b and the release in signer-install.md; the pins in restore_test.go; the smoke.sh blocks; the drill's case B with a control certificate.
2. **Task 2:** `8dc5c18` (test): the full drill; revoke.md sections 6 and 7; signer-install.md's CI note; the server-install.md pointer.
3. **Task 3:** `5be604d` (chore): the todo moved to completed/, and the new multi-leaf recovery todo.

**Plan metadata:** the `docs(03-06c): complete restore-procedure plan` commit, which carries this file, STATE.md and ROADMAP.md.

## Tracer gate (Task 1)

On `d7bfaf7`, before any expansion:

- **E2E run 40640054771:** both jobs succeeded, `e2e (9.5p1)` and `e2e (10.5p1)`. Each job's log has `--- PASS` for `TestRestoreRunbookChecks`, `TestRestoreRecoversLostRevocations`, `TestRestoreRecoveryTracer` and `TestRestoreReplaysLostDirectory`, and no `--- FAIL`.
- **systemd-sandbox run 40640057931:** succeeded. Its log prints:
  - `no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist`;
  - `kept: /root/recovery/server-krl.json`;
  - `copied restored.jsonl latest-saved.jsonl server-krl.json to /home/kradmin/recovery-in for kradmin`, then the two-file line;
  - `read the recovery request back to /root/recovery/recovery.bin`;
  - `keyroster-signer recover-revocations: refused: recovery_malformed: wire: malformed message: not a recovery request (keyroster/revoke-recovery/v1)`;
  - `=== PASS`.

## What ran and what did not

**Ran (2026-10-28):**

- **CI E2E run 40640786064 on `8dc5c18`** (the full drill): both jobs succeeded. In each job's log:
  - `--- PASS: TestRestoreRecoversLostRevocations` (13.85 s on 9.5p1, 13.23 s on 10.5p1);
  - `--- PASS` for `TestRestoreRunbookChecks`, `TestRestoreRecoveryTracer` and `TestRestoreReplaysLostDirectory`;
  - no `--- FAIL`;
  - the drill's `recovered: 5 entries from 2 imported KRLs, 2 lost certificates revoked, 1 kept; ...` line;
  - sshd's refusals of A, B, C and D from 127.0.0.2 to 127.0.0.5.
  
  On 10.5p1, sshd logged a deferred PerSourcePenalties penalty for each refusing source. The accepted logins come from 127.0.0.1, so no penalty touched them.
- **systemd-sandbox run 40640057931 on `d7bfaf7`.** The commits after it change no smoke.sh line and no block that it pins. The PR's required checks run systemd-sandbox again on the PR head.
- **Full local gate** in WSL Ubuntu (Go 1.27.3), on the tree of `8dc5c18` plus the todo files:
  - `go test -race -count=1 ./...` passed;
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/` passed;
  - gofmt is clean;
  - golangci-lint reports 0 issues;
  - capslock is unchanged (signer 92/92, agent 23/23, EXEC only through execsite);
  - dep-firewall and testonly-firewall are clean.
- **Locally in WSL:** `TestRestoreRunbookChecks` and `TestKeygenVerdict` passed, and `bash -n test/systemd/smoke.sh` passed.
- **Pin mutants**, applied by a script to the runbook or smoke.sh, run against `TestRestoreRunbookChecks` and restored byte for byte. All 7 were killed:

  | Mutant | Killed by the message |
  |---|---|
  | the `--krl` rule removed | no rule that --krl is left out only after no server KRL copy |
  | the release rule after `kept:` weakened | no rule that nothing to recover after kept: keeps the hold |
  | 03-03's stop re-added | still has 03-03's stop for a lost revocation |
  | smoke.sh's capture block without its state-directory line | smoke.sh no longer runs the capture block |
  | a release block before step 2b | the release before the release condition after step 2b |
  | the clock check moved after the recovery | the copy of the recovery inputs before the clock check |
  | the capture block moved after the file restore | does not keep the server's KRL copy right after the hold and before the file restore |

- `golangci-lint --build-tags e2e ./test/e2e/` reports nothing in recovery_test.go. The two findings in restore_test.go (G304 and G703, in `copyDB`) are older than this plan. CI does not lint with the e2e tag.

**UNVERIFIED (labelled so in the runbooks):**

- the whole procedure on a real signer host, and `recover-revocations` with the TPM and PKCS#11 backends (CI e2e runs the harness's agent backend);
- the copy of `krl-served.json` from a keyroster-server on another host;
- a fresh signer VM whose server copy died with the old VM;
- `recovery_installation_lost`, `recovery_import_invalid` under a rotated ops key (03-13) and `recovery_certificate_invalid` for a lost CA generation (03-12) in a real restore;
- the capture block's refusal of a krl-served.json that cannot be read, or of a dangling link (smoke.sh runs the missing directory, the missing file, the existing /root/recovery and the kept copy);
- `recovery_version_not_above_import`, `recovery_too_large` and the other refusals in a real restore. Their names come from 03-06b's tests: the drill waits past the imported version, as 03-06b's tracer does;
- server-install.md's remedy of moving an unverifiable copy aside (03-06b's label, unchanged).

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Where the plan's wording differs from 03-06b's final state (as the orchestrator directed)

**1. The lost-certificate rule in step 2b follows 03-06b's final state.** The plan says that live user certificates are revoked without a flag. The runbook says that every lost user certificate is revoked, whatever any clock says (PR #69 review round 2). Expired lost host and machine certificates are counted on `lost certificates expired before this request, not carried: <n>`. Certificates named with `--revoke-lost` are always carried.

**2. Step 2b's refusal list has 03-06b's final names.** That covers the plan's six cases, plus `recovery_fork`, the export that does not verify on the pins, `--out` exists, `recovery_revoke_lost_unknown`, `recovery_too_large` (the 11 MiB body cap, about 80 000 serials under P-256 and 128 000 under Ed25519), the state lock, `recovery_malformed`, `recovery_installation_mismatch`, `duplicate_request`, `recovery_certificate_not_lost`, `recovery_certificate_expired`, `recovery_user_certificate_kept` and the `unavailable:` states. This is also the carry-over "list more refusals in step 2b".

**3. revoke.md section 6 lists the server's final 503 set:**

- a KRL it could not keep;
- one that does not verify;
- a lower version;
- the same version with other bytes;
- a copy read at start that does not verify, so it is no version floor;
- an empty signer KRL after one was served.

It points to server-install.md for the remedies and keeps their UNVERIFIED label. It does not repeat them.

### Auto-fixed issues and plan details resolved

**4. [Rule 2] "The report counts one recovery".** `keyroster audit verify`'s text output has no recovery count; only `--json` has `kinds`. The runbook adds `grep -c '"kind":"revocation_recovery"' /tmp/recovered.jsonl`, which must print 1, after both verifies. `audit verify` binds the `kind` key on every line, the same argument as step 2's revoke count. audit.go is not changed.

**5. [Rule 2, PR #66 plan-check carry-over] The capture block checks its preconditions outside the `if`.**

- Its first line, `runuser -u keyroster-server -- test -d /var/lib/keyroster-server -a -x /var/lib/keyroster-server`, makes a missing account or state directory stop the block before it can print `no server KRL copy`.
- `test ! -e /root/recovery` refuses an existing directory (carry-over hardening).
- The `if` also takes a dangling link (`-o -L`), so `cat` fails on it instead of reporting no copy.
- smoke.sh runs the missing-directory and existing-`/root/recovery` cases besides the plan's two outcomes.

The plan's pinned lines (`install -d -m 0700 /root/recovery`, the `runuser ... cat`, `test -s`, both echoes) are unchanged.

**6. [PR #66 plan-check carry-over] The drill exercises A by key ID and C with `revoke user`**, with C (`carol`) a different subject from D (`dave`), and asserts that the answer of `revoke user` lists C's serial. A subject such as `u:c` would have made the sweep find nothing, because `revoke user` takes only bare names.

**7. [Rule 2] The drill adds a control certificate E**, which ssh-keygen and sshd must accept on every KRL, and gives every sshd refusal its own loopback source. Without a control, a KRL that refuses everything would pass. Task 1's case B already had E and an sshd login, which the plan left to Task 2.

**8. The evidence case uses a valid SSHSIG of a key that is no admin**, over the same request. The plan says only "the request's evidence changed". A random byte flip could stop at the SSHSIG parse, while the non-admin signature exercises the refusal step 2b names for T-03-276 (`recovery_evidence_invalid`).

**9. [Rule 3] smoke.sh creates the `tss` group when it is missing** (`getent group tss || groupadd --system tss`). The runbook's verbatim recovery line runs `runuser ... -G tss`, and the runner has no TPM packages. smoke.sh also writes two stand-in exports for the copy block, which does not parse them.

**10. Files outside files_modified (orchestrator carry-overs):**

- `docs/runbooks/server-install.md`: the pointer "the restore procedure lands with 03-06c" now points at signer-install.md step 2b.
- `.planning/todos/pending/2026-10-28-split-one-recovery-over-several-leaves.md`: the PR #69 owner decision, T-03-269.

**11. Small runbook additions within the plan's files:**

- The copy block refuses to run without `/root/recovery`, so the capture must have run. It ends in one `echo` over a list of the files it copied.
- The read-back block refuses an existing `/root/recovery/recovery.bin`.
- The backup paragraph says that a file backup needs neither the capture block nor step 2b.
- Step 2's "If it passes" path says to run step 2b all the same.
- The VM-snapshot and fresh-VM paths run the capture block.

**12. Process:**

- The PR is opened without auto-merge (orchestrator directive); the orchestrator enables it after its pre-merge review.
- `requirements mark-complete` is not run: `requirements-completed` stays empty, because REVOKE-01 completes in 03-11 and REVOKE-03 in 03-07.

**Total deviations:** 12. Of these, 3 follow 03-06b's final state, 4 are Rule 2, 1 is Rule 3, 2 are plan details, 1 is the files outside the plan and 1 is process.

## Issues Encountered

- Bash heredocs that held Go or shell quoting were mangled by the tool's shell layer. Edits went through the Edit tool and Python script files in the scratchpad instead.
- `scripts/linux.sh` and `wsl.exe bash -lc` expand `$VAR` in the outer shell (03-06b noted the same). The WSL checks ran from script files.

## Known Stubs

None.

## Threat Flags

None. The new surface is runbook text and tests:

- root reads keyroster-server's file only as keyroster-server (T-03-274);
- root writes only `/root/recovery`;
- the admin-side copy and read-back follow 03-02's rule (restoreAdminPathWrite still finds no root write to an admin path).

capslock: no new pair. T-03-SC: no module added.

## Next Phase Readiness

- 03-07's Task 1 precondition checks this SUMMARY and `.planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md` on origin/main, both of which reach main with this PR.
- 03-10 extends `TestRestoreRecoversLostRevocations` with the negative-probe case (the drill's comment names the extension point).
- 03-13 updates step 2b's escalation for an import under a rotated ops key (its cross-plan note).

## Self-Check: PASSED

- The files exist:
  - test/e2e/recovery_test.go has `func TestRestoreRecoversLostRevocations` once;
  - signer-install.md has the recovery line, `keyroster revoke recover --restored` and `krl-served.json`;
  - revoke.md has `krl-served.json` and `run in CI e2e (03-06c)`;
  - the todo is in completed/, with the resolution line;
  - the new todo is in pending/.
- `d7bfaf7`, `8dc5c18` and `5be604d` are ancestors of HEAD.
- Task 1's acceptance greps, with white space squashed:
  - 03-03's stop and `Until the restore-recovery plan merges` print 0;
  - `no server KRL copy`, `recovery_installation_lost` and `take a saved export after every revocation` each print at least 1.

## Review fix round 1 (PR #70)

A pre-merge security review of PR #70 upheld fifteen findings: two Claude lenses, Codex and a critic, each finding checked by two skeptics. F12 duplicates F1, F13 duplicates F2, and F14 overlaps F6, so each was fixed once. The fixes are on top of `d611ecf`, on 2026-10-28.

### Owner decisions (2026-10-28)

- **D-R1 (F3).** Root's release gate checks that the kept server copy was imported. Root reads the KRL version from the manifest of `/root/recovery/server-krl.json` and requires it among `import_krl_versions` on the recovered export's `revocation_recovery` line. `audit verify` now binds that field. A copy equal to the saved export's last KRL passes by version.
- **D-R2 (F4).** Accepted as a residual for now, with a check in 03-07. The new threat row T-03-277 says the server copy is only as trustworthy as the keyroster-server account; its disposition is accept-until-03-07. The runbook says the same next to the capture block, and says that a cross-check against a host's installed KRL arrives with 03-07. This round does not touch 03-07-PLAN.md; the orchestrator carries the check over.

### Per finding

| F | Fix | Commit | Tests and pins | Mutants (all RED) |
|---|---|---|---|---|
| F1, F12 | `keyroster revoke recover` verifies every input on its own and lists each one. A `--krl` document identical to an earlier input prints `import: <path>: KRL vN, issued at ...: same as <source>, imported once`, and the request still carries that manifest once. Part 3 of step 2b accepts this form (`same as saved export, log entry <n>, imported once`). | `ecf068d` (CLI), `7c28c25` (runbook) | CLI `TestRevokeRecover/server_copy_same_as_saved_listed`: a copy equal to the saved export's last KRL, two identical `--krl` files, and the saved manifest over other KRL bytes (refused). e2e `TestRestoreRecoveryAfterRecovery`. Pin `restoreImportRule`. | the duplicate line not printed; duplicates folded before verification; the import rule deleted from the runbook |
| F2, F13 | The `grep -c` count is replaced by root's **release check** (part 5). The recovered log must hold exactly two entries after the restored one: a `revocation_recovery` at the restored size and a `krl_publish` after it. Its two entries must be the `log entries <i>, <j>` of the `recovered:` line. Release case 1 now reads "the release check printed `release check passed:`". | `7c28c25` | e2e `TestRestoreRecoversLostRevocations` runs the script on the real exports: it passes on the recovered export and stops on the restored export given as the recovered one. e2e `TestRestoreRecoveryAfterRecovery`: a restored log that already holds a recovery, which leaves two in the recovered log, passes. smoke.sh, on fixtures: passes on a restored log with an earlier recovery, and stops when nothing was added. Pins `restoreReleaseCheckBlock` (runbook and smoke), `restoreReleaseCheckRule` and `restoreReleaseCheckStop`. | `-eq` changed to `-ge` (runbook, smoke); `grep -c` restored instead of the check; the rule for its line deleted; the stop rule deleted |
| F3 (D-R1) | `checkImportVersions` in `internal/audit/verify.go`. On a `revocation_recovery` line, `"import_krl_versions":` must occur exactly once, followed by the leaf's own import versions in order. On any other kind the key is refused. A leaf whose request or manifest does not decode is left to `verifyRecovery`. The release check reads the kept copy only in the form keyroster-server writes it (one line, the three fields in order). It base64-decodes the canonical manifest and requires its single `krl_version` among the versions, as an exact match. | `d037d24` (audit), `7c28c25` (runbook) | `TestVerifyRecoveryImportVersions`: edited, one left out, one added, reordered, missing, nested twice, on `krl_publish`, on `issue`. e2e: a server copy whose version the recovery did not import stops the check. smoke: v9 and v1 against `[7,19]` both stop. T-03-275 updated. | binding not called; key not required; no refusal on other kinds; the kept-copy line deleted from the runbook's check |
| F4 (D-R2) | The runbook paragraph "The copy is only as trustworthy as the keyroster-server account", next to the capture block; a sentence in revoke.md; threat row T-03-277 (accept until 03-07). The capture paragraph no longer claims the copy "holds the newest KRL any host could have fetched". | `7c28c25`; PLAN row in the docs commit | Pins `restoreServerCopyTrust` (positioned between the capture line and the file restore) and `restoreServerCopyCheck` | the paragraph deleted; the 03-07 sentence deleted |
| F5 | The capture block decides absence only from `listed=$(runuser -u keyroster-server -- find ... -name krl-served.json -print)`, outside any `if`, so a failing listing stops it under `-e`. | `7c28c25` | smoke: a state directory the server account can search but not read stops the block, which prints neither line. The capture block is pinned in the runbook and smoke. | back to `test -e ... -o -L` (runbook, smoke) |
| F6, F14 | Part 4 prints `/root/recovery/recovery.bin exists: move the refused request aside first (step 2b)`. A new **move block** moves a refused request to `/root/recovery/refused-<UTC time>/recovery.bin` and never deletes it or `/root/recovery`. `recovery_evidence_invalid` now starts again from part 2 with the other admin; the request-shape refusals start from part 3 after the move. | `7c28c25` | smoke: refusal, then the read-back stops with its reason, the move (bytes and mode checked), the admin's own move, and a new request read back and refused again. Pins `restoreArchiveBlock` (runbook, smoke), `restoreArchiveRule` and `restoreOtherAdminRule`. | the move block deleted; the never-delete rule deleted; "from part 3 on" for another admin; part 4 without its reason |
| F7 | Release of a keyroster-server held on another host. The signer host names and starts only keyroster-signer; then the server's host runs the release block naming only keyroster-server, and starts it. UNVERIFIED. | `7c28c25` | Pin `restoreRemoteRelease` | the paragraph deleted |
| F8 | Now tested, no longer UNVERIFIED. smoke.sh runs the capture block on a dangling link, a link to `/dev/zero`, a FIFO, a mode-000 file and a file one byte too large. Each case runs under `timeout 60`, and each must stop, print neither line and write at most 5 620 745 bytes. The runbook's CI list names these cases. | `7c28c25` | systemd-sandbox | covered by the F5 and F15 pins |
| F9 | Both release cases are pinned and placed between the release condition and the release block. | `7c28c25` | `restoreReleaseCase1`, `restoreReleaseCase2` | case 2 cut to plain `nothing to recover`; case 1 without the release check |
| F10 | The drill issues carol's certificate C before the backup and revokes it with `revoke user carol` after it. The post-snapshot host certificate H2 is revoked with `revoke serial --ca host` before the saved export. The summary lists D (revoke) and H and H2 (keep), and not C. The `recovered:` line reads `1 lost certificates revoked, 2 kept` at the restored size's indices. ssh-keygen -Q refuses H2 after the recovery and after the restart. | `3590a2c` | e2e, both lanes | not run (e2e runs only in CI). By construction: C is not lost and H2 is kept, so only the imported serial rows revoke them, and dropping those rows turns `requireKeygen(..., true)` RED. |
| F11 | Pinned: the clock check's two commands and its rule, found after step 2b's heading (the same lines stand in "Snapshot restore: check the clock first"); the openers `bash -eu -s <admin> <<'EOF'` (runbook) and `bash -eu -s kradmin <<'EOF'` (smoke) of copy-in and read-back; the release check's rules (F2 replaced "the count must print `1`"). | `7c28c25` | `restoreClockCommands`, `restoreClockRule`, `restoreAdminOpener`, `restoreSmokeAdminOpener` | commands deleted; rule deleted; four openers without `-e` |
| F15 | The capture block copies only when `runuser -u keyroster-server -- test -f` passes, then runs `head -c 5620745` and checks `stat -c %s` ≤ 5620744 = `krl.MaxKRLResponse`. The read-back works the same way as the admin, with the cap `wire.MaxRecoveryFile` = 9470226. The rule that "a link reaches only what that account can read" now says that a link still reaches any regular file that account can read. A FIFO swapped in between the check and the copy only makes the block wait; the runbook says to stop it and escalate. | `7c28c25` | `TestRestoreCopyCaps` ties both caps to the code constants. smoke: the read-back stops on a request planted as a FIFO, a link to `/dev/zero` or a dangling link. | capture without `test -f` (runbook); read-back without `test -f` (smoke); either cap moved off its limit in runbook, smoke and test together (TestRestoreCopyCaps) |

Mutants: 2 for the CLI, 3 for audit, and 28 for the runbook and smoke pins, all RED.
- The CLI and audit mutants ran on Windows copies.
- The pin mutants ran on a WSL copy with the e2e test binary (`TestRestoreRunbookChecks`, `TestRestoreCopyCaps`).
- Each copy was discarded afterwards.
- The release check's script was also run by hand in WSL on synthetic exports (7 cases) before the CI runs.

### Round 0 text this round supersedes

- **The key decision "the runbook counts the recovery with `grep -c`"** is replaced. The count could not tell a restored log that already held a recovery from a recovery that never ran. Root's release check now decides.
- **The UNVERIFIED item "the capture block's refusal of a krl-served.json that cannot be read, or of a dangling link"** is run in systemd-sandbox now (F8).
- **Deviation 4 (the recovery count)** and the PR body's item 4 are superseded the same way.

### What ran where (head `3590a2c`)

- **Windows:** gofmt clean; go vet linux/windows/darwin clean, and `-tags e2e` for linux; `go test ./...` passes apart from the known `internal/agent/paths` TestAllowed failure.
- **WSL:** `golangci-lint run ./...` 0 issues, and `GOOS=windows` 0 issues. `-tags e2e` lint reports only findings older than this round. In `restore_test.go` those are `copyDB`'s G304 and G703, and CI does not lint with that tag.
- **WSL:** `go test -race` passes for `./cmd/keyroster/` and `./internal/audit/`.
- **CI, dispatched on `3590a2c`:**
  - E2E run 40668513933: success. `TestRestoreRecoversLostRevocations`, `TestRestoreRecoveryAfterRecovery`, `TestRestoreRunbookChecks` and `TestRestoreCopyCaps` show `--- PASS` on both lanes, 10.5p1 and 9.5p1.
  - Systemd run 40668518276: success. The log shows the refusal and replacement, the move, and the release check's five fixture outcomes.

### UNVERIFIED after this round

- The release of a keyroster-server held on another host (F7). The copy from another host stays UNVERIFIED too.
- A request or server copy turned into a FIFO between a block's check and its copy. The block waits, and the runbook says to stop it with Ctrl-C and escalate.
- A listing that fails on a disk error. CI runs only an unreadable directory.
- The release check on a real signer host. CI e2e runs it on real exports as the test's user; smoke runs the verbatim block on fixtures.
- The other items of the list above are unchanged.

### Follow-ups (not in this round)

- The summary lists a lost host or machine certificate as `keep; ... revoke later` even when an import already revokes it (H2 in the drill). The certificate stays revoked, but the advice is misleading. The CLI could mark such lines `already revoked by an import`.
- The release check trusts the kept copy's own manifest for its version, which T-03-277 covers. 03-07's cross-check against a host's installed KRL closes that.
- The capture and read-back blocks could put `timeout` around the copy, which would turn the FIFO race into a stop rather than a wait.
- `keyroster audit verify --json` could report the recovery's import versions, so that root does not need grep and base64.
