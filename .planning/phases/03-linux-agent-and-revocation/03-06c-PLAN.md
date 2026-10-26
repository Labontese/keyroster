---
phase: 03-linux-agent-and-revocation
plan: 06c
type: execute
wave: 8
depends_on: ["03-06b"]
files_modified:
  - docs/runbooks/signer-install.md
  - docs/runbooks/revoke.md
  - test/e2e/recovery_test.go
  - test/e2e/restore_test.go
  - test/systemd/smoke.sh
  - .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md
  - .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md
autonomous: false
requirements: [REVOKE-01, REVOKE-03]

estimate:
  tokens: 57000
  raw_tokens: 57000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decision 2026-10-26, PR #66: this plan is the procedure half of the former 03-06b, split off on the owner's decision. 03-06b delivers keyroster-server's durable KRL copy, leaf kind 15, krl.RecoveryEntries, the audit rule, `keyroster revoke recover` and `keyroster-signer recover-revocations`, and this plan consumes them unchanged, with the names and output lines 03-06b-SUMMARY.md records. It runs right after 03-06b. 03-07's Task 1 precondition checks this plan's SUMMARY and the todo in completed/ on origin/main, because agents start pulling KRLs there (owner decision 2026-10-25, 03-03 plan check, Q2)"
    - "Every signer restore runs the recovery before the hold is released, whatever step 2's counts show: right after the hold's `held:` line and before the file restore, the operator keeps a copy of keyroster-server's krl-served.json, read as keyroster-server; the clock check runs under the hold before the recovery, because the recovery publishes; then step 2b: an admin of the restored policy runs `keyroster revoke recover` in their own session, and the operator runs `keyroster-signer recover-revocations` under the hold; only then is the hold released. The restored signer therefore never publishes a KRL that lacks a lost entry: its first publish after the restore is the recovery's"
    - "03-03's stop for a lost revocation and its interim text (no recovery yet, break-glass meanwhile) are replaced by step 2b in the same PR. Both revoke counts stay and go into the operations log. The operating rule 'take a saved export after every revocation' stays, with the addition that the recovery also imports keyroster-server's copy, which covers revocations after the latest saved export while that server's state directory survives the restore"
    - "PR #66 review, the runbook half: the capture block prints exactly one of two lines, `kept: /root/recovery/server-krl.json` or `no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist`. Step 2b passes the kept copy as --krl, and leaves --krl out only after `no server KRL copy`. The hold is released without a recovery file only after `keyroster revoke recover` printed `nothing to recover`, which 03-06b's CLI prints only when no --krl document is given and neither export's bundle has an installation ID; `recovery_installation_lost` keeps the hold and escalates"
    - "Each block of the recovery (the capture, the copy-in, the read-back, the recovery line) is pinned verbatim in test/e2e/restore_test.go, in the runbook and in test/systemd/smoke.sh, with its position: the capture after the hold and before the file restore, the clock check before the recovery, the recovery after the saved export's verify stop and before the release, and the release before step 3. Root reads the server's file only as keyroster-server and writes no admin path (restoreAdminPathWrite stays empty); systemd-sandbox runs every block, the capture in both outcomes"
    - "Every revocation 03-03 and 03-03b can write is recovered through the runbook's commands: serial (certificate issued before or after the snapshot), key ID, explicit key and subject, including a revocation made after the latest saved export whose KRL keyroster-server served. TestRestoreRecoversLostRevocations proves each on CI e2e with `ssh-keygen -Q` and sshd, proves that no krl_publish lies between the restored log's end and the recovery, and runs the pending-recovery cases (refused while another process holds the lock, a refused attempt writes nothing, a re-run succeeds once, a second run is refused, a restart keeps the union)"
  artifacts:
    - path: "docs/runbooks/signer-install.md"
      provides: "the capture block, the clock check under the hold, step 2b with its blocks and refusals, the release after step 2b"
      contains: "keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin"
    - path: "test/e2e/recovery_test.go"
      provides: "TestRestoreRecoversLostRevocations, the restore drill (next to 03-06b's TestRestoreRecoveryTracer)"
      contains: "func TestRestoreRecoversLostRevocations"
    - path: "test/e2e/restore_test.go"
      provides: "the recovery blocks pinned verbatim, with their positions"
    - path: "test/systemd/smoke.sh"
      provides: "the recovery blocks run verbatim in systemd-sandbox"
  key_links:
    - from: "test/e2e/restore_test.go"
      to: "docs/runbooks/signer-install.md"
      via: "TestRestoreRunbookChecks requires each recovery block verbatim and in order"
      pattern: "recover-revocations"
    - from: "test/systemd/smoke.sh"
      to: "docs/runbooks/signer-install.md"
      via: "systemd-sandbox runs the capture, copy-in and read-back blocks and the recovery line verbatim"
      pattern: "recover-revocations"
    - from: "docs/runbooks/signer-install.md"
      to: "cmd/keyroster/recover.go"
      via: "step 2b quotes 03-06b's command, its output lines and its refusal names"
      pattern: "keyroster revoke recover --restored"
  prohibitions:
    - statement: "After a signer restore, the hold is released only after step 2b's recovery committed, or after `keyroster revoke recover` printed `nothing to recover` with no server copy kept; no restored signer starts, and so none publishes a KRL, before that"
      status: resolved
      verification: test
---

<objective>
Put the recovery of the revocations a signer restore lost into the restore procedure, before agents start pulling KRLs in 03-07 (owner decision 2026-10-25, 03-03 plan check, Q2): the procedure half. After this plan, a restore no longer stops with the signer down when it lost a revocation. Under the restore hold, the operator keeps keyroster-server's KRL copy, checks the clock, and runs 03-06b's two recovery commands, and only then releases the hold. The first KRL after the restore is the recovery's, and it lists every entry any host could have seen.

Purpose: REVOKE-03 (a rollback of the revocation state never reaches the fleet) and REVOKE-01 (lost revocations stay revoked; lost live user certificates are revoked, and lost host and machine certificates are listed, per the owner's answer recorded in 03-06b-SUMMARY.md). With 03-06b, it closes the residual of threat T-03-207 (03-03) while keyroster-server's state survives the signer restore.

Output: signer-install.md's capture block, the clock check under the hold, step 2b in place of 03-03's stop, and the release after it; revoke.md sections 6 and 7; the e2e drill TestRestoreRecoversLostRevocations; the pins in test/e2e/restore_test.go; the blocks in test/systemd/smoke.sh; the todo moved to completed/; a PR.

Split from 03-06b on the owner's decision of 2026-10-26 (PR #66): 03-06b as first written had 32 files plus the todo's move and about 195k tokens. 03-06b keeps the code; this plan runs right after it (wave 8), and 03-07 waits for it. Until this plan merges, 03-03's stop stays in force, which is fail-safe: a restore that lost a revocation keeps the signer down meanwhile.
</objective>

## Budget

5 files plus the todo's move and about 57k tokens, inside the 15-file and 100k smart-zone thresholds; no exception. Growth over the owner's 55k: the capture block's second outcome and its rule (PR #66 review, about 2k).

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-06b-PLAN.md
@.planning/phases/03-linux-agent-and-revocation/03-03-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md
@.planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md
@docs/runbooks/signer-install.md
@docs/runbooks/revoke.md
@test/e2e/restore_test.go
@test/systemd/smoke.sh

Delivery protocol: 01-SKELETON.md, phase 03 names. Branch `p03/06c-restore-procedure`, SUMMARY `.planning/phases/03-linux-agent-and-revocation/03-06c-SUMMARY.md`, docs commit `docs(03-06c): complete restore-procedure plan`. `depends_on` holds 03-06b (the two commands, the server's copy, the audit rule and their final names). 03-07 depends on this plan.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "restore runbook, verbatim: hold → keep the server's KRL copy → file restore → clock check → copy-in → keyroster revoke recover (admin) → read-back → keyroster-signer recover-revocations under the hold → release → the served KRL refuses a revocation made after the saved export", pinned by TestRestoreRunbookChecks, run in systemd-sandbox and in the drill</name>
  <reversibility rating="reversible">Runbook text, test pins and smoke steps: no format or state that other code reads.</reversibility>
  <precondition>`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md` exits 0, and `git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md | grep -qx 'Lost-certificates answer: revoke-users-list-others'` exits 0 (this plan's runbook is written for that answer)</precondition>
  <files>docs/runbooks/signer-install.md, test/e2e/restore_test.go, test/systemd/smoke.sh, test/e2e/recovery_test.go</files>
  <read_first>
    - .planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md (the commands' final flags, their exact output lines `recovered: ...` and `nothing to recover: ...`, the refusal names, any deviation 03-06b lists for this plan)
    - docs/runbooks/signer-install.md "A restore brings back the older trust bundle, policy and directory" (the hold block, the file restore, steps 1 to 3, the revoke counts and the stop 03-03 added, the release block, the copy block of step 3, the CI and UNVERIFIED notes at the end of the section) and "Snapshot restore: check the clock first"
    - test/e2e/restore_test.go (restoreRunbookChecks, restoreAdminCopyScript, restoreAdminPathWrite, restoreSavedGreps, restoreRestoredGreps, the stop constant 03-03 added and its position checks in TestRestoreRunbookChecks, which also reads smoke.sh)
    - test/systemd/smoke.sh (the hold, file restore, release and copy blocks run verbatim, kradmin)
    - test/e2e/recovery_test.go (03-06b's TestRestoreRecoveryTracer: how the e2e harness drives keyroster-server, the signer, the CLI and the two recovery commands)
  </read_first>
  <action>
Create branch `p03/06c-restore-procedure` from `origin/main`.

**signer-install.md, the restore section.** Replace 03-03's stop for a lost revocation (the sentence test/e2e/restore_test.go pins as its stop constant, and the interim sentences after it saying that this runbook does not recover lost revocations yet and that access goes through break-glass meanwhile) with the recovery, which runs after every restore, whatever the counts show. Keep both revoke counts: they go into the operations log. Add, in this order:
- **Keep the server's KRL copy, right after the hold's `held:` line and before the file restore.** A block that runs as root on the host where keyroster-server runs, and reads the file as keyroster-server:
  - `install -d -m 0700 /root/recovery`;
  - when `runuser -u keyroster-server -- test -e /var/lib/keyroster-server/krl-served.json` holds: `runuser -u keyroster-server -- cat /var/lib/keyroster-server/krl-served.json > /root/recovery/server-krl.json`, then `test -s /root/recovery/server-krl.json` and `echo "kept: /root/recovery/server-krl.json"`;
  - otherwise only `echo "no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist"`.

  The block prints exactly one of the two lines, so the operator knows which form of step 2b applies (PR #66 review). With it, the rules: root reads the server's file only as keyroster-server and writes only its own directory. A file that exists but cannot be read stops the block (`bash -eu`): keep the hold and escalate. A missing file means that keyroster-server has not served a KRL since it keeps copies (03-06b). Where keyroster-server runs on another host, run the block there and copy the file over, because the hold block holds only the units on this host. Labelled run in CI (systemd-sandbox, with a fixture file and without one) and UNVERIFIED on a real host.
- **The clock check moves before the recovery,** because the recovery publishes: `timedatectl` and `doctor`, as in "Snapshot restore: check the clock first", while the hold is in force.
- **Step 2b, "Recover the revocations the restore lost (every restore, before the release)".** Four parts:
  1. A copy block in the shape of step 3's copy block, as root with `<admin>`: it creates `$H/recovery-in` as the admin and copies `/tmp/restored.jsonl`, `/root/latest-saved.jsonl` and, when the capture block kept it, `/root/recovery/server-krl.json` into it as the admin, from root's standard input, ending in one `echo` that names the files copied.
  2. The admin, in their own session with their ssh-agent and keyroster config (section 8), runs `keyroster revoke recover --restored /home/<admin>/recovery-in/restored.jsonl --saved /home/<admin>/recovery-in/latest-saved.jsonl --krl /home/<admin>/recovery-in/server-krl.json --out /home/<admin>/recovery-in/recovery.bin`, reads the summary and confirms. Only when the capture block printed `no server KRL copy` is `--krl ...` left out; when it printed `kept:`, the summary must list the server copy among the imports. Kept host and machine certificates are named with `--revoke-lost SERIAL` when the admin wants them revoked, per the owner's answer recorded in 03-06b-SUMMARY.md (`revoke-users-list-others`: live user certificates are revoked without a flag). The admin must be an admin of the restored policy, because a policy restored older can lack admins added since.
  3. A read-back block, as root: `runuser -u <admin> -- cat "$H/recovery-in/recovery.bin" > /root/recovery/recovery.bin`, then `test -s` and one `echo`.
  4. The recovery itself, as root under the hold: `runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin`. Its `recovered:` line goes into the operations log. Then step 1's export again with `--out /tmp/recovered.jsonl`, and audit verify of it on the pins on its own and with `--previous /tmp/restored.jsonl /tmp/recovered.jsonl`. Both must pass, and the report counts one recovery.

  The refusals and outcomes the operator can meet, each with its fix:
  - `recovery_log_mismatch`: the restored signer logged something, or a second run; stop and escalate as for a fork;
  - `recovery_version_not_above_import`: wait the seconds it names (T-03-208);
  - `recovery_evidence_invalid`: the admin who signed is not an admin of the restored policy; have one who is sign, and escalate when there is none (T-03-276);
  - `recovery_import_invalid` because the import is signed under another ops key (possible only after 03-13), or `recovery_certificate_invalid` for a CA generation only a lost bundle names (possible only after 03-12): keep the hold and escalate, labelled UNVERIFIED (03-12 and 03-13 own making these cases recoverable);
  - `recovery_installation_lost` from `keyroster revoke recover`: a lost bundle added the installation ID, or the server copy proves that a bundle with one was in force; keep the hold and escalate (UNVERIFIED);
  - `nothing to recover` from `keyroster revoke recover`: possible only without `--krl` (the capture block printed `no server KRL copy`) and when neither bundle has an installation ID, so no KRL was ever published and there is no recovery file to apply; release.
- **Release the hold** only after step 2b, and say so in the release paragraph's condition: after the recovery's two verifies passed, or after `nothing to recover`.
- **Step 3's baseline paragraph stays as it is:** `--previous /tmp/restored.jsonl` remains valid after the recovery, because the recovered log extends the restored one. restoreRunbookChecks and TestRestoreReplaysLostDirectory pin that line.
- The section's CI note and UNVERIFIED list:
  - the drill (TestRestoreRecoversLostRevocations, CI e2e);
  - the blocks run verbatim in systemd-sandbox;
  - UNVERIFIED: the copy from a server on another host; a real signer host; the TPM and PKCS#11 backends for the recovery command (CI e2e runs the software or agent backend of the harness); a fresh signer VM whose server copy died with the old VM, after which only the saved export's KRL is imported and revocations after the latest saved export stay lost (T-03-207's remaining residual).

Keep the operating rule "take a saved export after every revocation" and add that the recovery also imports keyroster-server's copy, which covers revocations after the latest saved export while that server's state directory survives the restore.

**test/e2e/restore_test.go.**
- Replace the stop constant and its position check with the recovery: the commands of step 2b and the post-recovery export and verifies in restoreRunbookChecks, and new constants for the capture block, the copy-in block and the read-back block, each required verbatim in the runbook and in smoke.sh (as restoreAdminCopyScript is), and the two capture lines and the rule that `--krl` is left out only after `no server KRL copy`.
- Position checks:
  - the capture comes after the hold and before the file restore;
  - the clock check comes before the recovery;
  - the recovery comes after the saved export's verify stop and before the release block;
  - the release comes before step 3.
- restoreAdminPathWrite still finds no root write to an admin path.

**test/systemd/smoke.sh.** Run the new blocks verbatim:
- the capture block twice: once against a fixture `krl-served.json` written as keyroster-server in a state directory created with the unit's owner and mode (it must print the `kept:` line, and the copy must equal the fixture byte for byte), and once with the file absent (it must print the `no server KRL copy` line and leave no copy);
- the copy-in block for kradmin, refusing first with a planted link at `~/recovery-in` (as the replay copy block does), then with the server copy kept and without it;
- the read-back block;
- the recovery line under the hold with a request that does not parse: it must exit non-zero with `recovery_malformed`, and the signer database's SHA-256 is unchanged.

**test/e2e/recovery_test.go, `TestRestoreRecoversLostRevocations` (the tracer's case).** Next to 03-06b's TestRestoreRecoveryTracer, with the same harness: certificate B (user) is issued, the snapshot is taken (signer.db copied with the signer stopped), the saved export is taken, and B is then revoked through the CLI, so keyroster-server served and kept it. The server and signer are stopped, the server's copy is kept as the capture block does, and the snapshot is restored. Then `keyroster revoke recover` with the restored and saved exports and `--krl` set to the kept copy, `keyroster-signer recover-revocations` reading its output, both started again, and the served KRL makes `ssh-keygen -Q` refuse B and sshd refuse B's login. Task 2 adds the other cases to this test.

Like 03-03 and 03-06b, the e2e evidence comes from the CI E2E lanes dispatched on the pushed branch, because WSL on the owner's workstation does not resolve `keyroster.localhost` (deferred-items.md); systemd-sandbox runs on its own workflow, dispatched the same way.
  </action>
  <verify>
    <automated>bash -n test/systemd/smoke.sh && bash scripts/linux.sh 'go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l ./test/)"'</automated>
    <fails_when>non-zero exit, or any vet or gofmt output</fails_when>
    <automated>git push -u origin p03/06c-restore-procedure && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/06c-restore-procedure && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/06c-restore-procedure --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit (the E2E run on the pushed head failed or never appeared), or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestRestoreRunbookChecks", "--- PASS: TestRestoreRecoversLostRevocations", "--- PASS: TestRestoreRecoveryTracer" or "--- PASS: TestRestoreReplaysLostDirectory", or reports any e2e test as FAIL</fails_when>
    <automated>scripts/gh-as-bot.sh workflow run systemd.yml --ref p03/06c-restore-procedure && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow systemd.yml --branch p03/06c-restore-procedure --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit (the systemd-sandbox run failed or never appeared), or its log lacks "kept: /root/recovery/server-krl.json", "no server KRL copy" or "recovery_malformed"</fails_when>
  </verify>
  <acceptance_criteria>
    - 03-03's stop is gone and its interim text with it, checked with white space squashed:
      - `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'the restore lost a revocation: do not release the hold'` prints 0;
      - `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'Until the restore-recovery plan merges'` prints 0.
    - The recovery is in the runbook:
      - `grep -c 'keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin' docs/runbooks/signer-install.md` prints at least 1;
      - `grep -c 'keyroster revoke recover --restored' docs/runbooks/signer-install.md` prints at least 1;
      - `grep -c 'krl-served.json' docs/runbooks/signer-install.md` prints at least 1;
      - `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'no server KRL copy'` and the same with `recovery_installation_lost` each print at least 1 (PR #66 review, the runbook half).
    - `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'take a saved export after every revocation'` prints at least 1 (the rule stays).
    - `TestRestoreRunbookChecks` passes in CI e2e with the capture, clock check, recovery and release in that order; systemd-sandbox passes with the new blocks, the capture in both outcomes.
    - The CI E2E and systemd-sandbox runs on the pushed head are the evidence; the SUMMARY names both run IDs.
  </acceptance_criteria>
  <done>A restore that lost a revocation made after the saved export gets it back through the runbook's own steps under the hold, before the signer serves again, and CI pins and runs every block.</done>
</task>

<task type="auto">
  <name>Task 2: The full drill (every revocation target, a kept host certificate, the pending-recovery cases, the restart) and revoke.md</name>
  <files>test/e2e/recovery_test.go, docs/runbooks/revoke.md</files>
  <read_first>
    - The files written in Task 1; .planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md (the summary's kept-certificate line and the refusal names)
    - test/e2e/revoke_test.go (TestRevokeSerialEndToEnd, TestRevokeUserEndToEnd, TestRevokeKeyEndToEnd: KRL fetch, `ssh-keygen -Q`, sshd logins, `keyroster revoke key`)
    - docs/runbooks/revoke.md sections 6 and 7 (the KRL route; "take a saved export after every revocation"), docs/runbooks/server-install.md (03-06b's paragraph on krl-served.json, which revoke.md points to)
  </read_first>
  <action>
**test/e2e/recovery_test.go, `TestRestoreRecoversLostRevocations` (the todo's drill), extended from Task 1's case.** Setup, in order:
1. A signer and keyroster-server issue certificates A (user, before the snapshot) and B (user, before the snapshot).
2. The snapshot: signer.db copied with the signer stopped.
3. Then C (user), D (user, never revoked) and H (host, admin issue path) are issued, and A, C and an explicit key K are revoked.
4. The saved export is taken.
5. B is revoked through the CLI, so the server served and kept it.
6. The server and signer are stopped, the server's copy is kept as the capture block does, and the snapshot is restored.

Then:
- The restored export and both verifies.
- Pending recovery:
  - with the test holding signer.lock, recover-revocations is refused as in use, and the export is unchanged;
  - with the request's evidence changed, it is refused and the export is unchanged;
  - the genuine file then succeeds;
  - a second run is refused `recovery_log_mismatch`.
- The recovered export:
  - the entries after the restored prefix are exactly one revocation_recovery entry and one krl_publish, so no krl_publish lies between the restored log's end and the recovery;
  - it verifies with `--previous` set to the restored export.
- Both start again: the served KRL makes `ssh-keygen -Q` refuse A, B, C, D and K, and sshd refuses A, B, C and D (D, a lost user certificate still live, is revoked under the owner's answer). H is listed as kept in the summary and is absent from the KRL; `keyroster revoke key` of H's public key then succeeds.
- The signer restarts: the KRL version is unchanged and still refuses all of them.
- audit verify of the final export passes.

The negative-probe case is 03-10's (cross-plan note in 03-10-PLAN.md); the drill names it as its extension point in a comment.

**revoke.md.** Section 6: keyroster-server keeps the last KRL document it served in krl-served.json, written before it serves it, never replaced by a lower version, and the route answers 503 rather than serve a KRL it could not keep (server-install.md, 03-06b). Labelled run in CI (internal/server tests, 03-06b). Section 7 keeps the saved-export rule, with the same addition as signer-install.md and a pointer to step 2b. A short paragraph says that a lost host or machine certificate the recovery kept is revoked by key (`keyroster revoke key` with the public key the recovery's summary prints), labelled run in CI e2e (03-06c).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l ./test/)"' && grep -c 'krl-served.json' docs/runbooks/revoke.md && tr -s '[:space:]' ' ' < docs/runbooks/revoke.md | grep -c 'take a saved export after every revocation'</automated>
    <fails_when>non-zero exit (vet or gofmt output, or revoke.md lacks krl-served.json or the saved-export rule)</fails_when>
    <automated>git push origin p03/06c-restore-procedure && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/06c-restore-procedure && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/06c-restore-procedure --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit, or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestRestoreRecoversLostRevocations", "--- PASS: TestRestoreRecoveryTracer", "--- PASS: TestRestoreRunbookChecks" or "--- PASS: TestRestoreReplaysLostDirectory", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'func TestRestoreRecoversLostRevocations' test/e2e/recovery_test.go` prints 1, and the test names each of A, B, C, D, H and K and the four pending-recovery cases (the SUMMARY lists them with the run ID).
    - `grep -c 'krl-served.json' docs/runbooks/revoke.md` prints at least 1, and `tr -s '[:space:]' ' ' < docs/runbooks/revoke.md | grep -c 'take a saved export after every revocation'` prints at least 1 (the rule stays).
    - `tr -s '[:space:]' ' ' < docs/runbooks/revoke.md | grep -c 'run in CI e2e (03-06c)'` prints at least 1.
  </acceptance_criteria>
  <done>Every revocation target, a revocation after the saved export, a kept host certificate, the pending-recovery cases and a restart are proven through the runbook's commands with sshd, and revoke.md says how the server's copy and the recovery fit together.</done>
</task>

<task type="auto">
  <name>Task 3: Gates, the todo, the PR and the SUMMARY</name>
  <files>.planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md, .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md</files>
  <read_first>
    - .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md ("Closing")
    - .planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md deviation 8 (the SUMMARY is pushed before the PR opens)
  </read_first>
  <action>
Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair: this plan changes tests and runbooks only. A new pair is a deviation to review and record in the SUMMARY.

**The todo.** This is the plan's last implementation task, and it closes the todo: move `.planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md` with `git mv` under the same name to `.planning/todos/completed/`, appending "Resolved in 03-06b (the code) and 03-06c (the restore procedure, PR from branch p03/06c-restore-procedure)". The SUMMARY is pushed before the PR opens, so it names the branch, as 03-03b's SUMMARY records (deviation 8). 03-07's precondition checks this plan's SUMMARY and the todo in completed/ on origin/main.

**The PR.** `scripts/gh-as-bot.sh pr create --title "feat(restore): recover lost revocations in every signer restore, with the e2e drill and CI pins"`, without enabling auto-merge (the orchestrator enables it after the pre-merge review); wait for the required checks.

**The SUMMARY.** Contents:
- the PR number;
- the lost-certificates answer the runbook follows (`revoke-users-list-others`, from 03-06b-SUMMARY.md);
- the runbook's blocks and their pinned positions;
- the drill's cases;
- the CI run IDs (e2e and systemd-sandbox);
- capslock;
- `requirements-completed` empty: REVOKE-01 completes in 03-11 and REVOKE-03 in 03-07, as 03-03 recorded.

D-20: this plan changes the operator's restore steps, which signer-install.md carries in the same PR. Then the tracking updates once, `docs(03-06c): complete restore-procedure plan`, push and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>test ! -e .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md && git ls-files --error-unmatch .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md && grep -q 'Resolved in 03-06b (the code) and 03-06c' .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md</automated>
    <fails_when>non-zero exit (the todo was not moved under the same name, or the resolution line is missing)</fails_when>
    <automated>git fetch origin p03/06c-restore-procedure && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-06c-SUMMARY.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)"</automated>
    <fails_when>non-zero exit (the SUMMARY is not on the pushed branch, or local commits are unpushed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/06c-restore-procedure --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported; systemd-sandbox runs the new smoke.sh blocks)</fails_when>
  </verify>
  <acceptance_criteria>
    - The todo is in completed/ under the same name with the resolution line, and no longer in pending/.
    - The PR is open without auto-merge (the orchestrator enables it after the pre-merge review), every required check green, 03-06c-SUMMARY.md on its head.
  </acceptance_criteria>
  <done>The restore procedure recovers lost revocations under the hold, CI runs it, the todo is closed and the PR waits green.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — owner approves PR p03/06c-restore-procedure, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/06c-restore-procedure --web`; review signer-install.md's restore section and 03-06c-SUMMARY.md, especially that nothing in the restore starts the signer before step 2b, that the server copy is passed as --krl whenever the capture block kept it, and that lost certificates follow your answer of 2026-10-26.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/06c-restore-procedure` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/06c-restore-procedure</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-06c-SUMMARY.md && git cat-file -e origin/main:.planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md</automated>
    <fails_when>non-zero exit (the SUMMARY or the closed todo did not reach main, which 03-07's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/06c-restore-procedure --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>Restore recovery, code and procedure, is on main, and 03-07 may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Edge Coverage (spec-less fallback, this plan)

This plan authors the procedure half of REVOKE-03 rollback (a restored, older revocation state never reaches hosts) as truths.

**Flagged assumption, no restore ever starts the signer before step 2b.** The runbook's never-boot rule for VM snapshots and the hold (03-02, 03-03) are what make "the first KRL after the restore" the recovery's. A restored signer that logged anything first is refused by `recovery_log_mismatch` (03-06b), as step 2 refuses a fork.

**Flagged assumption, the hold freezes the server's copy.** The hold stops keyroster-server, so krl-served.json holds the last KRL it served, and the capture block keeps it before anything else changes. A release without the recovery breaks the procedure, and the copy would then be replaced by the restored signer's higher version (T-03-271).

**Flagged assumption, the capture block's two outcomes (PR #66 review).** A missing krl-served.json means that keyroster-server has not served a KRL since it keeps copies. Only then is --krl left out, and only then can `nothing to recover` release the hold (03-06b's CLI refuses `recovery_installation_lost` when a copy is given under a restored bundle without an installation ID). An admin who leaves out --krl although the copy was kept imports only the saved export; the summary's import list shows it (T-03-275).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Lost revocations never reach hosts; access revoked centrally stays revoked after a signer restore | Tasks 1-2 (the procedure); the code is 03-06b's |
| REQ | REVOKE-01 (lost revocations, key IDs and certificates stay revoked or revocable) | Tasks 1, 2 (every target through the runbook's commands; the kept host certificate revoked by key) |
| REQ | REVOKE-03 (no rollback of the revocation state) | Tasks 1, 2 (no publish before the recovery; the restart keeps the union) |
| CONTEXT | D-10 (hosts keep their last KRL; never lock out) | Tasks 1, 2 (the hold keeps the signer down until the recovery; the restart publishes nothing new) |
| CONTEXT | D-20 (signer-install.md and revoke.md in the PR that changes the restore steps, run or UNVERIFIED) | Tasks 1, 2 |
| Owner decisions | Q2 (recovery merged before 03-07); 2026-10-26 (PR #66): the split, and the lost-certificates answer `revoke-users-list-others` | Task 1 precondition and step 2b's `--revoke-lost` text; this file and 03-06b-PLAN.md |
| Todo | The drill (five cases, the publish assertion, ssh-keygen and sshd, restart while pending) and "Closing" | Tasks 1-3 |
| Review | PR #66 Codex docs review, finding 1 (runbook half): no `nothing to recover` release when a server copy was kept | Task 1 (ledger, round 1) |

## Artifacts this phase produces (this plan)

- Runbook: signer-install.md's capture block (two outcomes), the clock check under the hold, step 2b with its copy-in block, the admin's command, the read-back block, the recovery line, the post-recovery export and verifies and the refusal list, and the release after step 2b; revoke.md sections 6 and 7 and the kept-certificate paragraph.
- Tests: `TestRestoreRecoversLostRevocations` (A, B, C, D, H, K, the pending-recovery cases, the restart); restore_test.go's new block constants and position checks in `TestRestoreRunbookChecks`; smoke.sh's recovery blocks.
- Tracking: the todo `2026-10-25-plan-signer-restore-revocation-recovery.md` in completed/.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| root on the signer host → admin and service accounts | The runbook's copies run as the account that owns each path |
| the operator's procedure → the restored signer | Only the hold stands between a restored, older revocation state and a published KRL; the hold is released after the recovery |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-265 | Elevation of privilege | a signer restore that drops revocations, including ones newer than the latest saved export (un-revoke on every host) | high | mitigate | Split with 03-06b (owner decision 2026-10-26, PR #66); this plan's share is the procedure. Every restore runs step 2b under the hold before the release, whatever the counts show, and imports the server's copy kept right after the hold. The hold is released without a recovery file only after `nothing to recover`, which needs no kept copy and no installation ID in either bundle (PR #66 review). TestRestoreRecoversLostRevocations covers serial (before and after the snapshot), key ID, key, subject, a revocation after the saved export, and the pending cases, through the runbook's commands with sshd. **Accepted residual:** a restore that also loses the server's state directory (a co-located VM lost for good) imports only the saved export, so revocations after it stay lost. The rule "take a saved export after every revocation" stays for that case (UNVERIFIED path in signer-install.md) |
| T-03-271 | Tampering | the server's copy replaced by a restored signer's KRL that a release without the recovery published (higher time-derived version, entries missing) | medium | mitigate | Split with 03-06b (PR #66). This plan's share: the capture block keeps a copy right after the hold's `held:` line and before the file restore (position pinned in TestRestoreRunbookChecks, run in systemd-sandbox). 03-06b's share: the server never serves a version below the one it served. **Residual:** a release without the recovery breaks the procedure; the copy taken under the hold is the evidence |
| T-03-273 | Denial of service | a recovery KRL that hosts ignore because its version is not above an imported version (a clock that ran ahead, a same-second burst) | low | mitigate | Split with 03-06b (PR #66). This plan's share: the clock check runs under the hold before the recovery (position pinned), and step 2b's refusal list says to wait the seconds `recovery_version_not_above_import` names (T-03-208) |
| T-03-274 | Elevation of privilege | root following a link planted by the admin or the server account during the runbook's copies | low | mitigate | Moved from 03-06b (PR #66). Each block writes as the account that owns the path, root reads only its own files (the step 3 rule of 03-02), and root reads the server's file only as keyroster-server. The blocks are pinned verbatim in restore_test.go (restoreAdminPathWrite still empty) and run in systemd-sandbox, with a planted link at `~/recovery-in` refused |
| T-03-275 | Elevation of privilege | an admin who runs `keyroster revoke recover` without the server's copy although the capture block kept one, so only the saved export is imported and revocations after it stay lost | medium | mitigate | PR #66 review, the runbook half. The capture block prints exactly one of `kept:` and `no server KRL copy`; step 2b's command carries `--krl`, which may be left out only after `no server KRL copy`; the copy-in block copies the kept file into the admin's directory; and the admin checks that the summary lists the server copy among the imports. Pinned in TestRestoreRunbookChecks. **Residual:** an operator error that the offline CLI cannot see (UNVERIFIED on a real host) |
| T-03-276 | Denial of service | the admin who signs the recovery is not an admin of the restored policy (a policy restored older lacks admins added since) | low | accept | The signer refuses `recovery_evidence_invalid`, nothing is written and the hold stays (fail-safe); step 2b says the admin must be an admin of the restored policy and names the refusal. **Accepted residual:** when no admin of the restored policy is available, the restore escalates |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; this plan changes runbooks and tests only; capslock baseline unchanged |
</threat_model>

<verification>
- Every verify command passes, including both CI e2e lanes and systemd-sandbox; the merge gate passes.
</verification>

<success_criteria>
- After a signer restore, the operator brings the signer back with every revocation hosts could have seen, through the runbook's own steps under the hold. That covers revocations newer than the saved export, while keyroster-server's state survives. The restored signer's first KRL is the recovery's; `nothing to recover` never releases the hold when a server copy was kept; CI pins and runs every block.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-06c-SUMMARY.md` in Task 3, before the merge gate. `requirements-completed` is empty (REVOKE-01 completes in 03-11, REVOKE-03 in 03-07). Never record merge facts.
</output>

## Review Dispositions Ledger

Rows moved from 03-06b-PLAN.md on the split (owner decision 2026-10-26, PR #66), with their history; each "How Addressed" names the plan as it read before the split, and the trailing "Since the split" points at this plan. Rows that also have a 03-06b half stay in 03-06b as well.

### Round 0 — sources (todo 2026-10-25, the 03-03 plan check's Q2 rows, the PR #61 pre-merge review) (moved from 03-06b)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Todo point 4: replaying one revocation at a time publishes N−1 unsafe intermediate KRLs | HIGH | Plan 03-06b, Task 2: one transaction, one leaf, one publish, offline under the hold. The drill asserts no krl_publish between the restored log's end and the recovery. Since the split (owner decision 2026-10-26, PR #66): the drill's assertion is this plan's TestRestoreRecoversLostRevocations (Task 2); the one transaction stays in 03-06b |
| Todo point 6: revocations newer than the saved export are in neither file (T-03-207 residual) | HIGH | Plan 03-06b, Task 2: keyroster-server's durable krl-served.json, kept before it serves and frozen by the hold; Task 4: the runbook copies it right after the hold. T-03-265 (residual narrowed to a lost server state). Since the split (owner decision 2026-10-26, PR #66): the capture block right after the hold is this plan's Task 1; the server's copy stays in 03-06b |
| Planner self-check before the PR: a restored bundle without an installation ID whose saved export's bundle has one (a lost bundle added the ID, as 03-15's v4 bundle will on the homelab) would have released the hold and published without the lost revocations | HIGH | Plan 03-06b, Task 2: `keyroster revoke recover` refuses `recovery_installation_lost`, and prints `nothing to recover` only when neither bundle has an ID. Task 4: the runbook keeps the hold for the first and releases for the second. Since the split (owner decision 2026-10-26, PR #66): the runbook half is this plan's Task 1 (step 2b's refusal list), widened in round 1; the CLI half stays in 03-06b |
| Todo "Costs": the runbook, restoreSavedGreps and TestRestoreRunbookChecks | MEDIUM | Plan 03-06b, Task 4: 03-03's stop replaced by step 2b; the counts stay; new pinned blocks with positions; smoke.sh runs them. Since the split (owner decision 2026-10-26, PR #66): this plan, Task 1 |
| Todo drill (five cases, publish assertion, ssh-keygen and sshd, restart while pending) | HIGH | Plan 03-06b, Task 4 TestRestoreRecoversLostRevocations; Task 3 the transaction-level pending cases (`recovery_rolls_back_on_publish_failure`, `recovery_second_run_refused`, `restart_after_recovery`); the negative probe through 03-10's note. Since the split (owner decision 2026-10-26, PR #66): the drill is this plan's Tasks 1 and 2; the transaction-level cases stay in 03-06b; 03-10's note names this plan's drill |
| Todo "Closing": move under the same name, "Resolved in" | — | Plan 03-06b, Task 4; it names the branch, because the SUMMARY is pushed before the PR (03-03b deviation 8). 03-07's precondition checks this plan's SUMMARY on origin/main (edited with this plan). Since the split (owner decision 2026-10-26, PR #66): this plan's Task 3, its last implementation task, moves the todo with "Resolved in 03-06b (the code) and 03-06c (the restore procedure, ...)"; 03-07's precondition checks 03-06c's SUMMARY and the todo in completed/ on origin/main |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| Harden the signer restore runbook (todo 2026-10-25, Phase 4) | Out of scope: its items are fail-closed or labelled UNVERIFIED already, and this plan's new blocks follow the rules that todo asks for (root reads only its own files). Since the split (owner decision 2026-10-26, PR #66): moved here with the runbook |

### Round 1 — PR #66 Codex docs review and owner decisions (2026-10-26)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Codex docs review, high, upheld by a skeptic as medium (PR #66): `nothing to recover` was decided from the two exports alone, before the --krl documents, and the runbook released the hold on it, bypassing the installation-loss escalation | HIGH | The CLI half is 03-06b's (row there: --krl read first, `recovery_installation_lost` when a copy is given under a restored bundle without an ID). This plan's half, Task 1: the capture block's two outcomes (`kept:` or `no server KRL copy`), step 2b's command with `--krl` whenever the copy was kept, the refusal list (`recovery_installation_lost` keeps the hold; `nothing to recover` only without a kept copy), the release condition; must_haves truth, Edge Coverage, T-03-265 and T-03-275; acceptance greps for `no server KRL copy` and `recovery_installation_lost`; smoke.sh runs the capture in both outcomes |
| Owner decision (Daniel, 2026-10-26, PR #66): split 03-06b into the code (03-06b) and the procedure (this plan), this plan right after 03-06b, 03-03's stop in force until it merges, 03-07's dependency and precondition on this plan's SUMMARY, the todo moved by this plan's last implementation task | — | This file (5 files plus the todo's move, about 57k, wave 8, depends on 03-06b): the runbook, drill, pins, smoke.sh and todo tasks of the former 03-06b Task 4, re-cut into a tracer (Task 1: the runbook blocks, pins, smoke.sh and the drill's case B), the full drill and revoke.md (Task 2), and the gates, todo and PR (Task 3); the rows above, moved with their history; T-03-274 moved here, T-03-265, T-03-271 and T-03-273 split; T-03-275 and T-03-276 new for the procedure |
| Owner decision (Daniel, 2026-10-26, PR #66): lost certificates that are still valid = `revoke-users-list-others` | — | Task 1's precondition checks the line `Lost-certificates answer: revoke-users-list-others` in 03-06b-SUMMARY.md on origin/main; step 2b's `--revoke-lost` text and the drill (D revoked, H kept) follow it |
| Planner, split (PR #66): revoke.md section 6 describes 03-06b's server copy and its 503, but lands here with the runbook, as the owner listed | LOW | D-20 interim, accepted (row in 03-06b): Task 2 writes section 6 and points at server-install.md, which 03-06b updated with the server change |
