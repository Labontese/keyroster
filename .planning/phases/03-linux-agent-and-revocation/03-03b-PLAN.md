---
phase: 03-linux-agent-and-revocation
plan: 03b
type: execute
wave: 3
depends_on: ["03-03"]
files_modified:
  - internal/server/revoke.go
  - internal/server/revoke_test.go
  - internal/serverclient/admin.go
  - internal/serverclient/admin_test.go
  - cmd/keyroster/revoke.go
  - cmd/keyroster/revoke_test.go
  - test/e2e/revoke_test.go
  - docs/runbooks/revoke.md
  - docs/runbooks/enroll-user.md
  - docs/runbooks/host-setup.md
  - .planning/todos/completed/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md
autonomous: false
requirements: [REVOKE-01, REVOKE-02]

estimate:
  tokens: 70000
  raw_tokens: 70000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decision 2026-10-25, PR #60: this plan is the CLI and runbook half of the former 03-03, split off on the owner's decision; 03-03 (krl-core) delivers the formats, the signer and audit verify, and this plan consumes them unchanged: wire.TargetKeyID, TargetKey and TargetSubject, wire.RevokeResponse.SerialCount and Serials, krl.Parse and the parsed Set, the signer's subject resolution with its re-listing rule and the second-sweep interleaving the signer test already proves"
    - "D-09: `keyroster revoke user <name>` sends the subject revoke (the signer finds every live certificate of the user, 03-03), prints the serials revoked, then disables the user in a signed directory version (installed at once when the admin quorum is 1, written as a proposal otherwise) so nothing new is issued, and once the directory pipeline reports the install it sends a second subject revoke (the second sweep), which revokes every certificate issued between the first revoke and the install (owner decision 2026-10-25, 03-03 plan check, Q3). The second sweep's answer re-lists the first sweep's certificates next to those issued in between, because no subject resolution excludes certificates already revoked (03-03, PR #60 review); the CLI prints each answer as it comes"
    - "`keyroster revoke user` revokes first and never undoes that, then runs the directory step, then the second sweep (owner decision 2026-10-25, 03-03 plan check, Q3). When the directory step fails (install refused, proposal not written, server unreachable), it prints the revoked serials, `the user is NOT disabled: <reason>` and the retry command `keyroster revoke user <name>` (a re-run revokes every live certificate again, those issued since included, then disables and sweeps again; a bare `keyroster user disable` would leave the certificates issued in between), and exits 3 (partial). At admin quorum > 1 the disable is only a proposal: it prints the revoked serials, `revoked, disable pending: <name> can still obtain certificates until the proposal is installed` and `run keyroster revoke user <name> again after the proposal is installed`, and exits 4. When the second sweep fails after the install it exits 3 with the same re-run command. When the user is already disabled it skips the directory step and the second sweep (nothing new can be issued) and says so; with zero live certificates it says so and names `keyroster revoke key` for certificates this signer holds no record of"
    - "`keyroster revoke key-id <key-id> --ca <role>` and `keyroster revoke key <public-key-file>` send the key-ID and explicit-key targets 03-03 adds to the signer; sshd refuses a certificate with that key ID, and a plain key and every certificate for that key, in CI e2e (REVOKE-01)"
    - "Owner decision 2026-10-25, PR #58 review: after every revoke the CLI parses the KRL it has confirmed (krl.VerifyManifest and the 03-01 issued_at window first, then krl.Parse from 03-03) and exits non-zero unless that KRL lists every target the command revoked: the serial under one of the trust bundle's CA keys for the role (`revoke serial`), the key ID under one of them (`revoke key-id`), the explicit key (`revoke key`), and every serial the server's answer reports (`revoke user`, both sweeps; the answer is unsigned, so the check covers exactly the reported serials and the output says so). An absent entry is never reported as revoked, even where pruning (krl.EntryLive) could explain it; the message names both causes. 03-01's output line `Not checked: that this KRL lists serial ...` is replaced"
    - "The revoke answer reaches the CLI: serverclient.RevokeAnswer gains `serial_count` and `serials` (up to wire.MaxRevokeAnswerSerials, 4096, ascending and unique, decoded strictly), internal/server/revoke.go copies both from the signer's wire.RevokeResponse (03-03) and logs the target kind instead of a serial that is 0 for every target but serial; when SerialCount is above the listed serials the CLI says the rest are not listed and names `keyroster audit verify`"
    - "docs/runbooks/enroll-user.md and host-setup.md say that disabling a user, revoking a role or unmapping an account stops only new certificates, and that `keyroster revoke user` ends the issued ones on every host that applies the KRL (todo F-IN-01; D-20)"
  artifacts:
    - path: "cmd/keyroster/revoke.go"
      provides: "`keyroster revoke key-id`, `revoke key`, `revoke user` (revoke, disable, second sweep, exits 3 and 4), the KRL listing check for every revoke command"
      contains: "krl.Parse("
    - path: "test/e2e/revoke_test.go"
      provides: "TestRevokeUserEndToEnd and TestRevokeKeyEndToEnd against real sshd"
      contains: "func TestRevokeUserEndToEnd"
  key_links:
    - from: "cmd/keyroster/revoke.go"
      to: "internal/krl/parse.go"
      via: "the CLI parses the confirmed KRL and refuses unless it lists every target it revoked"
      pattern: "krl\\.Parse"
    - from: "internal/server/revoke.go"
      to: "internal/serverclient/admin.go"
      via: "the server copies the signer's SerialCount and Serials into RevokeAnswer"
      pattern: "Serials"
  prohibitions:
    - statement: "No `keyroster revoke` command reports a target as revoked unless the KRL it verified and parsed lists it, and `keyroster revoke user` never exits 0 while the user is not disabled or a sweep after the install failed"
      status: resolved
      verification: test
---

<objective>
Revocation from the CLI (REVOKE-01, CLI half): `keyroster revoke key-id`, `revoke key` and `revoke user` with the second sweep and the partial outcomes (exit 3 and 4), the answer's serials through keyroster-server, the CLI's KRL listing check for every revoke command, e2e against real sshd, and the runbooks that tell the truth about disable versus revoke.

Purpose: an admin can cut off a person, a certificate by key ID or a key from the CLI, and the CLI never reports a revocation that the KRL it checked does not list. Also closes the folded todo `2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md`.

Output: three new `keyroster revoke` subcommands, the KRL check, server and client pass-through of the answer's serials, e2e for subject and key revocation, runbook updates, a PR through the merge gate.

Split from 03-03 on the owner's decision of 2026-10-25 (PR #60): the 03-03 revision had grown to 37 files and about 215k tokens. 03-03 (krl-core) keeps the formats, the signer, audit verify and the runbook text its audit change makes false; this plan runs right after it (wave 3) and 03-04 waits for it.
</objective>

## Budget

11 files and about 70k tokens, inside the 15-file and 100k smart-zone thresholds; no exception. Growth over the old 03-03 share of this work: none beyond the split itself; the second-sweep counts follow the PR #60 re-listing fix.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-RESEARCH.md
@.planning/phases/03-linux-agent-and-revocation/03-01-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-03-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-03-PLAN.md
@.planning/phases/01-trust-core/01-SKELETON.md
@cmd/keyroster/revoke.go
@cmd/keyroster/user.go
@cmd/keyroster/dirpipe.go
@internal/server/revoke.go
@internal/serverclient/admin.go
@.planning/todos/pending/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md

Delivery protocol: 01-SKELETON.md, phase 03 names. Branch `p03/03b-revoke-cli`, SUMMARY `.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md`, docs commit `docs(03-03b): complete revoke-cli plan`.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "keyroster revoke user alice → the server passes the answer's serials → the CLI confirms and parses the KRL → disable → second sweep → sshd refuses both of her certificates, Bob's still works → audit verify passes the log"</name>
  <reversibility rating="moderate">The CLI commands, their exit codes and the JSON fields `serial_count` and `serials` are user-facing and read by scripts; the signed formats they carry are 03-03's and do not change here.</reversibility>
  <precondition>`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-03-SUMMARY.md` exits 0</precondition>
  <files>internal/server/revoke.go, internal/server/revoke_test.go, internal/serverclient/admin.go, internal/serverclient/admin_test.go, cmd/keyroster/revoke.go, test/e2e/revoke_test.go</files>
  <read_first>
    - .planning/phases/03-linux-agent-and-revocation/03-03-SUMMARY.md (final names: wire targets, RevokeResponse.SerialCount and Serials, MaxRevokeAnswerSerials, krl.Parse and the parsed Set with SerialRange, refusal details `subject_kind_unsupported` and `key_is_ca_of_this_installation`)
    - .planning/phases/03-linux-agent-and-revocation/03-03-PLAN.md Task 1 (subject resolution and its re-listing rule, the second-sweep interleaving test on a real signer)
    - cmd/keyroster/revoke.go (the serial command, revokeRefusal, confirmRevokeAnswer at 171, the `Not checked:` output at 136), cmd/keyroster/user.go (user disable through the directory pipeline), cmd/keyroster/dirpipe.go, cmd/keyroster/commands.go (exitError)
    - internal/server/revoke.go (handleRevoke copies the signer's answer into serverclient.RevokeAnswer and logs `req.Serial`), internal/serverclient/admin.go (RevokeAnswer at 141)
    - test/e2e/revoke_test.go, test/e2e/login_signer_test.go (how a passkey login certificate is obtained in e2e)
  </read_first>
  <action>
Create branch `p03/03b-revoke-cli` from `origin/main`.

**Server and client.** `serverclient.RevokeAnswer` gains `serial_count` and `serials` (the signer's wire.RevokeResponse.SerialCount and Serials from 03-03: ascending, unique, at most wire.MaxRevokeAnswerSerials = 4096 listed, SerialCount at least the listed count); the client decodes them strictly (a count below the list, more than 4096, unsorted or duplicated serials refused). internal/server/revoke.go copies both through and logs `target` (the target kind) instead of `serial`, which is 0 for key-ID, key and subject revokes, with the serial only for the serial target (03-03 plan check: the CLI must print and KRL-check the serials of the answer, and the answer types carried none). Tests: the server's pass-through (internal/server/revoke_test.go); the client's decode (internal/serverclient/admin_test.go).

**CLI.** `keyroster revoke key-id <key-id> --ca <role>`, `keyroster revoke key <file>` (a .pub file; a certificate file revokes its key, with a note), `keyroster revoke user <name>`: sends the subject revoke, prints the serials revoked, then runs the directory pipeline to set the user `disabled` when it is still active (installed when the policy quorum is 1; else written as a proposal with the co-signing instruction), printing which of the two happened. Revocation and the directory change are separate transactions under separate authority, so the order is fixed: revoke first (it cuts off access at once and is never undone), directory second, second sweep third. **Second sweep (owner decision 2026-10-25, 03-03 plan check, Q3).** A login or issuance that completes after the first subject revoke commits and before the disable is installed gets a certificate outside the resolved set (Signer.LoginIssue authorizes against the directory installed at that moment). So once the directory pipeline reports the disable installed (quorum 1), the CLI sends a second subject revoke for the same user with a new request ID and prints its serials too; it is KRL-checked like the first. Its answer lists every live certificate of the user again (03-03's re-listing rule, PR #60 review), so it repeats the first sweep's serials and adds those issued in between; the CLI prints them as they come and does not diff the two answers (a truncated first answer could not be diffed exactly). "Reports installed" is the pipeline's install answer, the same one `keyroster user disable` prints; signer-signed install receipts are Phase 4 (todo `2026-10-21-cli-verifies-directory-install-receipts.md`), and the signer-side issuance barrier that closes the window at every quorum is Phase 4 too (todo `2026-10-25-signer-issuance-barrier-after-subject-revoke.md`). At quorum > 1 the CLI writes the proposal, prints the revoked serials, `revoked, disable pending: <name> can still obtain certificates until the proposal is installed` and `run keyroster revoke user <name> again after the proposal is installed`, and returns `&exitError{code: 4}` (distinct status; codes in use: 1 error, 2 usage and `user approve`, 3 partial). When the directory step fails after a successful revoke, the command prints the revoked serials, then `the user is NOT disabled: <reason>` and the retry command `keyroster revoke user <name>`, and returns `&exitError{code: 3}` (partial; the existing exitError in cmd/keyroster/commands.go). The retry is `revoke user`, not `user disable` as round 1 had it: a bare disable would leave the certificates issued since the first revoke, while a re-run revokes them, disables and sweeps again. When the second sweep fails after the install, the user is disabled, so nothing new is issued, but the certificates of the window may be live: exit 3 with `the second revocation failed: <reason>; run keyroster revoke user <name> again`. When the first subject revoke itself fails or cannot be confirmed, `revoke user` still runs the directory step (disabling stops new certificates, the fail-safe direction), or prints `keyroster user disable <name>` when it cannot reach it, says that nothing is reported revoked, and exits 1; the admin then re-runs `keyroster revoke user <name>` (03-03 plan check). The CLI prints the serials of each answer and its SerialCount; when SerialCount is above the listed serials it says that the rest are not listed in the answer and that `keyroster audit verify` on an export checks them all, and the KRL check covers exactly the listed serials. A user already disabled skips the directory step and the second sweep with a line saying so (one sweep, exit 0: nothing new can be issued); zero live certificates print `no live certificates of <name> in this signer's records; revoke a certificate issued elsewhere with keyroster revoke key` (addresses review concerns: Codex 03-03 partial subject revoke, REVIEWS L94@e7b3b32, L100@e7b3b32; nemotron 03-03 CLI guidance when nothing is found, L507@e7b3b32).

**CLI KRL check (owner decision 2026-10-25, PR #58 review).** 03-01's `confirmRevokeAnswer` (cmd/keyroster/revoke.go) verifies the served manifest and its issued_at window but cannot read the KRL, so a compromised server that drops a revoke can still show a genuine KRL published by another revocation in those 300 s. With 03-03's krl.Parse, every revoke command (serial, key-id, key, user) passes the verified KRL bytes to krl.Parse after krl.VerifyManifest and refuses, non-zero, unless the parsed set lists each revoked target: the serial (inside some serial interval) or key ID under a certificate section whose CA key is one of the trust bundle's CA keys for the role, the explicit key in section 2, and for `revoke user` each serial the answer of each sweep reports. A parse failure is a refusal. An absent entry is never reported as revoked, even when pruning could explain it; the message names both causes and the signer's `revoked` log line. Replace the 03-01 output line `Not checked: that this KRL lists serial ...` with a line saying what the KRL was checked to list (cmd/keyroster/revoke_test.go:158 pins the old line; Task 2 updates it), and update docs/runbooks/revoke.md's expected output in Task 3.

**e2e.** revoke_test.go `TestRevokeUserEndToEnd`: alice gets two login certificates (passkey path) and bob one; sshd with the 03-01 KRL layout accepts all three; `keyroster revoke user alice` (quorum 1) reports the same two serials from each sweep (the second sweep re-lists live certificates; nothing is issued in between here), taken from each answer's Serials and each confirmed in the served KRL (the output says so); krl.Parse of the final served KRL lists each of the two serials once under the user CA key (the duplicate rows merge); after the KRL swap both alice certificates are refused and bob's is accepted; a new login for alice is refused by the signer with `user_disabled`; `keyroster audit verify` on the exported log passes and reports exactly two revoke entries (each with the same two entries, PR #60 review) and one krl_publish after each of them, on top of the krl_publish entries written before the command (03-03's start-up publish); the round-1 text's "two revoke and two krl_publish entries" with its unexplained second revoke is replaced by these counts. `TestRevokeKeyEndToEnd`: `keyroster revoke key` with a user's plain key; sshd refuses a plain authorized_keys login with that key and a certificate for that key; and `keyroster revoke key-id` of a third certificate's key ID under the user CA, after which sshd refuses that certificate. TestRevokeSerialEndToEnd's expected CLI output follows the new KRL-check line. The e2e verify runs on the CI E2E lanes (both OpenSSH versions), dispatched on the pushed branch, because WSL on the owner's Windows workstation no longer resolves `keyroster.localhost` (03-03 plan check). keyroster-bot's token carries the `repo` and `workflow` scopes with push access, so the dispatch is allowed; if it is refused anyway (HTTP 403), treat it as an authentication gate, and the PR's required `e2e (9.5p1)` and `e2e (10.5p1)` checks in Task 3 become the e2e evidence, while the tracer gate re-runs the unit-level verify only.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/server/... ./internal/serverclient/... ./cmd/keyroster/...'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output</fails_when>
    <automated>git push -u origin p03/03b-revoke-cli && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/03b-revoke-cli && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/03b-revoke-cli --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit (the E2E run on the pushed head failed or never appeared), or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestRevokeUserEndToEnd", "--- PASS: TestRevokeKeyEndToEnd" or "--- PASS: TestRevokeSerialEndToEnd", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'Serials' internal/serverclient/admin.go` prints at least 1, and `grep -c '"target"' internal/server/revoke.go` prints at least 1 (the server logs the target kind).
    - `grep -v '^[[:space:]]*//' cmd/keyroster/revoke.go | grep -c 'krl.Parse('` prints at least 1.
    - TestRevokeUserEndToEnd's log shows two refusals for alice and an accepted login for bob after the swap.
    - The CI E2E run on the pushed head is the authoritative evidence for this task's e2e verify: WSL on the owner's Windows workstation no longer resolves `keyroster.localhost` (deferred-items.md), and the local namespace workaround fails `TestSSHDRejects/pty_allowed` (03-01-SUMMARY, 03-02-SUMMARY). A local run is optional and is not evidence; the SUMMARY names the run ID.
  </acceptance_criteria>
  <done>A person, a key ID and a key can be revoked from the CLI, sshd enforces it, and the CLI reports only what the checked KRL lists.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: CLI outcomes, the KRL listing check and the answer pass-through, each a named test</name>
  <files>cmd/keyroster/revoke.go, cmd/keyroster/revoke_test.go, internal/server/revoke_test.go, internal/serverclient/admin_test.go</files>
  <behavior>
    - CLI (cmd/keyroster/revoke_test.go, fake server): `revoke_user_partial_directory_failure` (revoke answered 200, directory install refused: exit code 3, stdout lists the serials, stderr contains `NOT disabled` and `keyroster revoke user alice`), `revoke_user_already_disabled` (no directory request and no second revoke are sent, exit 0), `revoke_user_none_found` (prints zero serials and names `keyroster revoke key`).
    - Second sweep (owner decision 2026-10-25, 03-03 plan check, Q3): `revoke_user_login_between_revoke_and_disable`, CLI half (the signer half, on a real signer, is 03-03's `TestRevokeSubject/revoke_user_login_between_revoke_and_disable`): a fake server whose second subject revoke answers the first sweep's serials plus the serial of a certificate issued in between; the requests go revoke, directory install, revoke in that order, the second sweep's serials are printed and KRL-checked, exit 0, and with the second revoke never sent the case fails (record the mutant in the SUMMARY). `revoke_user_quorum_proposal_pending` (quorum 2: the proposal is written, no second revoke is sent, exit code 4, output contains `disable pending`, `can still obtain certificates` and `run keyroster revoke user alice again after the proposal is installed`). `revoke_user_second_sweep_failed` (the install succeeds, the second revoke is refused: exit 3, stderr names `keyroster revoke user alice`).
    - CLI KRL check (owner decision 2026-10-25, PR #58 review; cmd/keyroster/revoke_test.go, fake server serving an ops-signed manifest over a real krl.Encode output): `revoke_krl_lists_serial` (exit 0, stdout says the KRL lists the serial), `revoke_krl_lacks_serial` (a correctly signed KRL of the reported version without the serial: non-zero exit, stderr names "not listed" and both causes, revoke not effective or entry pruned), `revoke_krl_lacks_key_id`, `revoke_krl_lacks_key`, `revoke_user_krl_lacks_reported_serial` (each non-zero), `revoke_krl_does_not_parse` (a signed manifest over bytes krl.Parse refuses: non-zero).
    - CLI on a failed revoke (03-03 plan check): `revoke_user_revoke_failed_still_disables` (the subject revoke is refused: the directory disable is still sent, the output says nothing is reported revoked and names `keyroster revoke user alice`, exit 1); `revoke_user_answer_truncated` (SerialCount above the listed serials: the output says the rest are not listed and names `keyroster audit verify`).
    - Pass-through: `TestRevokeAnswerSerials` in internal/server (the signer's SerialCount and Serials reach the JSON answer unchanged; the log line carries `target` and, for the serial target only, the serial) and `TestRevokeAnswerDecode` in internal/serverclient (4096 serials decode, 4097, unsorted, duplicated and a count below the list are refused).
  </behavior>
  <read_first>
    - The files written in Task 1; cmd/keyroster/revoke_test.go from 03-01 (the fake server, the `Not checked:` expectation at 158)
    - internal/krl/parse.go and the parsed Set (03-03)
  </read_first>
  <action>Write the tests in `<behavior>`; fix what they break. Replace cmd/keyroster/revoke.go's `unknown_serial` advice (`revocation by key, for a certificate this signer did not issue, arrives in a later version`, revokeRefusal) with the commands this plan adds (`keyroster revoke key-id` or `keyroster revoke key`), and map 03-03's refusal details `subject_kind_unsupported` and `key_is_ca_of_this_installation` to advice (the second names the emergency rotation of 03-13 as the path for a CA key).</action>
  <verify>
    <automated>go test -count=1 -v -run 'TestRevoke' ./cmd/keyroster/</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or a "revoke_user_partial_directory_failure", "revoke_user_login_between_revoke_and_disable", "revoke_user_quorum_proposal_pending", "revoke_user_second_sweep_failed", "revoke_krl_lacks_serial", "revoke_krl_does_not_parse" or "revoke_user_krl_lacks_reported_serial" PASS line missing</fails_when>
    <automated>go test -count=1 -v -run 'TestRevokeAnswer' ./internal/server/ ./internal/serverclient/</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or "--- PASS: TestRevokeAnswerSerials" or "--- PASS: TestRevokeAnswerDecode" missing</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'this version cannot read a KRL' cmd/keyroster/revoke.go` and `grep -c 'arrives in a later version' cmd/keyroster/revoke.go` each print 0 (revoke.md's half of this check is Task 3's, which edits that file).
    - The CLI KRL check cases in `<behavior>` fail when the listing check is bypassed (record the mutant result in the SUMMARY; owner decision 2026-10-25, PR #58 review).
  </acceptance_criteria>
  <done>Every `revoke user` outcome and every KRL-check refusal is named and tested, and the answer's serials reach the CLI intact.</done>
</task>

<task type="auto">
  <name>Task 3: Runbooks, todo closure, gates and PR</name>
  <files>docs/runbooks/revoke.md, docs/runbooks/enroll-user.md, docs/runbooks/host-setup.md, .planning/todos/completed/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md</files>
  <read_first>
    - .planning/todos/pending/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md
    - docs/runbooks/enroll-user.md (about lines 192 and 212-226, "Disabling a user"), docs/runbooks/host-setup.md (about line 236), docs/runbooks/revoke.md (as 03-03 left it: sections 3 and 4, the sample output and the saved-export rule are 03-03's)
  </read_first>
  <action>
revoke.md: add key-id, key and user commands, each in its own `## ` section whose heading names `keyroster revoke key-id`, `keyroster revoke key` or `keyroster revoke user`, what each revokes, the re-publish cadence (hourly, D-10), pruning, how to check a KRL with `keyroster audit verify` and `ssh-keygen -Q -l`; label CLI steps "run in CI e2e (03-03b)" and homelab steps "UNVERIFIED until 03-16". enroll-user.md "Disabling a user" and host-setup.md: state that disable, role revoke and unmap stop only new certificates, issued ones stay valid until ValidBefore, and `keyroster revoke user <name>` cuts them off on every host whose agent applies the KRL (agents from 03-07; hand-set hosts need the KRL installed by hand, which revoke.md describes as UNVERIFIED). Append "Resolved in 03-03b (PR #N)" to the todo and `git mv` it to .planning/todos/completed/.

revoke.md also states what `revoke user` exit 3 means and how to finish it (re-run `keyroster revoke user <name>`), what exit 4 means at admin quorum > 1 (revoked, disable pending: the user can still obtain certificates until the proposal is installed, so re-run the command after the install; Q3), and why `revoke user` writes two revoke entries (the second sweep, which re-lists the first one's certificates next to any issued in between, PR #60 review), labelled "run in CI (cmd/keyroster revoke tests, 03-03b)". revoke.md drops the texts this plan makes false: `arrives with 03-03` (the `unknown_serial` row of section 2, which names `keyroster revoke key-id` and `keyroster revoke key` instead), `which 03-03 adds` (section 1's paragraph on what the confirmation cannot catch, which now says the CLI reads the KRL for the target) and the sample output's `Not checked:` line with `this version cannot read a KRL` (replaced by the new KRL-check line of Task 1).

Run the full gate. Push, `scripts/gh-as-bot.sh pr create --title "feat(revoke): revoke by key ID, key and user from the CLI, with a KRL listing check"` without enabling auto-merge (the orchestrator enables it after the pre-merge review), wait for the required checks. SUMMARY (PR number, CI e2e run ID, mutant results; `requirements-completed` empty: REVOKE-01 completes in 03-11 when host and machine subjects exist, REVOKE-02 in 03-07 when agents distribute the KRL), tracking once, `docs(03-03b): complete revoke-cli plan`, push, wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>grep -q 'keyroster revoke user' docs/runbooks/enroll-user.md && grep -q 'keyroster revoke user' docs/runbooks/host-setup.md && test -f .planning/todos/completed/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md && test ! -e .planning/todos/pending/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md</automated>
    <fails_when>non-zero exit (a runbook lacks the revoke-user instruction, or the todo was not moved)</fails_when>
    <automated>git fetch origin p03/03b-revoke-cli && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)"</automated>
    <fails_when>non-zero exit (the SUMMARY is not on the pushed branch, or local commits are unpushed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/03b-revoke-cli --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - The new sections carry both labels (03-03 plan check: a bare `grep -c 'UNVERIFIED'` already passed at main, where revoke.md has nine). revoke.md has one `## ` section per new command, its heading naming `revoke key-id`, `revoke key` and `revoke user`, and each such section, with its white space squashed, contains both `run in CI e2e (03-03b)` and `UNVERIFIED until 03-16`: `awk '/^## /{sec=$0} {t[sec]=t[sec] " " $0} END{n=0; for(k in t){x=t[k]; gsub(/[[:space:]]+/," ",x); if(k ~ /revoke (key-id|key|user)/ && index(x,"run in CI e2e (03-03b)") && index(x,"UNVERIFIED until 03-16")) n++}; print n}' docs/runbooks/revoke.md` prints 3.
    - Texts this plan makes false are gone from revoke.md: `tr -s '[:space:]' ' ' < docs/runbooks/revoke.md | grep -c 'arrives with 03-03'`, the same with `'which 03-03 adds'` and the same with `'this version cannot read a KRL'` each print 0 (white space squashed first, so a rewrapped leftover cannot pass, as in 03-03's runbook checks; PR #60 Codex split check).
    - `grep -c 'exit 3\|exits 3' docs/runbooks/revoke.md` and `grep -c 'exit 4\|exits 4' docs/runbooks/revoke.md` each print at least 1.
    - The PR is open without auto-merge (the orchestrator enables it after the pre-merge review), every required check green, 03-03b-SUMMARY.md on its head.
  </acceptance_criteria>
  <done>The runbooks tell the truth about disable versus revoke and about the CLI's checks, the todo is closed, and the PR waits green.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — owner approves PR p03/03b-revoke-cli, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>The owner reviews and approves the PR in the GitHub web UI. The orchestrator enables auto-merge after its pre-merge review, and auto-merge then squash-merges the approved PR. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/03b-revoke-cli --web`; review code and 03-03b-SUMMARY.md.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/03b-revoke-cli` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/03b-revoke-cli</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/03b-revoke-cli --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>Revocation from the CLI is on main.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Edge Coverage (spec-less fallback, this plan)

No edge row of the phase ledger is authored here; REVOKE-02's ordering edge is 03-03's.

**Flagged assumption, REVOKE-01 (unclassified, unresolved; moved from 03-03 with the CLI).** Assumed: revoking a subject is complete when it covers every certificate the signer's own issuance table holds for that subject and CA role. A certificate issued by a restored older signer state, or by a CA key outside this installation, is not found by subject; the CLI says so when it finds none and the runbook tells the admin to revoke such a certificate by key. Host and machine subjects arrive in 03-09 and 03-11.

## Artifacts this phase produces (this plan)

- CLI: `keyroster revoke key-id`, `keyroster revoke key`, `keyroster revoke user` (revoke, disable, second sweep; exit 3 on partial success: revoked, not disabled or second sweep failed; exit 4 at quorum > 1: revoked, disable pending); the KRL listing check (krl.Parse) after every revoke command, `revoke serial` included.
- serverclient: `RevokeAnswer.SerialCount`, `.Serials` (JSON `serial_count`, `serials`); server: the revoke log line carries `target`.
- Tests: `TestRevokeUserEndToEnd`, `TestRevokeKeyEndToEnd`, `TestRevokeAnswerSerials`, `TestRevokeAnswerDecode`, the CLI cases `revoke_user_partial_directory_failure`, `revoke_user_already_disabled`, `revoke_user_none_found`, `revoke_user_login_between_revoke_and_disable` (CLI half), `revoke_user_quorum_proposal_pending`, `revoke_user_second_sweep_failed`, `revoke_user_revoke_failed_still_disables`, `revoke_user_answer_truncated`, `revoke_krl_lists_serial`, `revoke_krl_lacks_serial`, `revoke_krl_lacks_key_id`, `revoke_krl_lacks_key`, `revoke_user_krl_lacks_reported_serial`, `revoke_krl_does_not_parse`.
- Docs: revoke.md sections for `revoke key-id`, `revoke key` and `revoke user` with exits 3 and 4; enroll-user.md and host-setup.md on disable versus revoke (F-IN-01).

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| admin CLI → keyroster-server | The server relays the admin-signed request and the signer's unsigned answer; it is not trusted for either |
| served KRL → CLI parser | Bytes from the server, read with 03-03's strict krl.Parse only after krl.VerifyManifest |
| directory pipeline → signer | The disable is a separate admin-signed transaction; its install answer is the server's word until Phase 4 receipts |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-19 | Spoofing | a disabled user's new login after revoke, and a certificate issued between the subject revoke and the disable | medium | mitigate | Moved from 03-03 with the CLI (owner decision 2026-10-25, PR #60). `keyroster revoke user` also disables the user in a signed directory version (or writes the proposal when quorum > 1); once the disable is installed the CLI sends a second subject revoke that revokes every certificate issued in between, re-listing those of the first revoke, because no resolution excludes certificates already revoked (owner decision 2026-10-25, 03-03 plan check, Q3; PR #60 review; `revoke_user_login_between_revoke_and_disable` interleaves one on a real signer in 03-03 and checks the CLI order here); when a step fails the CLI exits 3 with the re-run command `keyroster revoke user <name>`, so a partial result is never reported as done. **Accepted residual until Phase 4:** at admin quorum > 1 the disable is only a proposal, so the user can still obtain certificates until the co-signers install it; the CLI exits 4, says so and tells the admin to re-run the command after the install. A server that reports an install that did not happen moves the second sweep early. The signer-side issuance barrier (todo `2026-10-25-signer-issuance-barrier-after-subject-revoke.md`) and signer-signed install receipts (todo `2026-10-21-cli-verifies-directory-install-receipts.md`) close both in Phase 4 |
| T-03-209 | Repudiation | a compromised keyroster-server that drops a revoke and answers it as done, showing a genuine KRL another revocation published within the 300 s window | medium | mitigate | Owner decision 2026-10-25, PR #58 review: every revoke command parses the verified KRL (krl.Parse) and exits non-zero unless it lists every revoked target; `revoke user` checks exactly the serials the unsigned answer reports and says so, and `keyroster audit verify` on an export checks the full set (`revoke_krl_lacks_serial`, `revoke_user_krl_lacks_reported_serial`, with a bypass mutant). **Accepted residual:** a server that under-reports a subject revoke's serials makes the CLI check fewer; detection is audit verify (03-03's subject rule) |
| T-03-15 | Denial of service | malformed KRL bytes from the server reaching the CLI | high | mitigate | 03-03's strict Parse (size cap, named refusals, fuzzing) after VerifyManifest; a parse failure is a refusal, never a pass (`revoke_krl_does_not_parse`) |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added |
</threat_model>

<verification>
- Every verify command passes, including both CI e2e matrix jobs; the merge gate passes.
</verification>

<success_criteria>
- Every revocation target of REVOKE-01 that 03-03 supports works from the CLI; no revoke command reports a revocation that the checked KRL does not list; the runbooks say that disable stops only new certificates.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md` in Task 3, before the merge gate. `requirements-completed` is empty (REVOKE-01 completes in 03-11, REVOKE-02 in 03-07). Never record merge facts.
</output>

## Review Dispositions Ledger

Rows moved from 03-03-PLAN.md on the split (owner decision 2026-10-25, PR #60), with their history; each "How Addressed" names the plan as it read before the split, and the trailing "Since the split" points at this plan. Rows that also have a 03-03 half stay in 03-03 as well.

### Round 1 — e7b3b32 (moved from 03-03)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Codex 03-03: no recovery behaviour when the revoke succeeds but the directory install or proposal fails (REVIEWS L94@e7b3b32, L100@e7b3b32) | MEDIUM | Plan 03-03, must_haves truth, Task 1 CLI: revoke first and never undone, then the directory step; on its failure the CLI prints the serials, `the user is NOT disabled`, the exact `keyroster user disable <name>` retry, and exits 3. Task 2: `revoke_user_partial_directory_failure`, `revoke_user_already_disabled`. Task 3: revoke.md explains exit 3. T-03-19 updated. Since the split: Plan 03-03b, Tasks 1-3 (the retry is `keyroster revoke user <name>` since round 2) |
| nemotron 03-03 HIGH: the CLI must point the admin elsewhere when a subject has no certificate in the signer's records (REVIEWS L507@e7b3b32) | HIGH | Plan 03-03, Task 1 CLI: zero live certificates print a line naming `keyroster revoke key`; Task 2: `revoke_user_none_found`. Since the split: Plan 03-03b, Tasks 1 and 2 |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| nemotron 03-03 LOW: are both runbooks updated in the same PR (REVIEWS L511@e7b3b32) | Already covered: Task 3's verify greps `keyroster revoke user` in both enroll-user.md and host-setup.md. Since the split: Plan 03-03b, Task 3 |

### Round 2 — 03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up) (moved from 03-03)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Q3, owner decision 2026-10-25 (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): codex high "close the issuance window between revocation and disabling the user" (both skeptics upheld; T-03-19 claimed it mitigated) | HIGH | Plan 03-03, must_haves truths (D-09, the revoke-user outcomes), Task 1 CLI "Second sweep": revoke, disable, then a second subject revoke once the install is reported; exit 4 at quorum > 1 with `disable pending`, `can still obtain certificates` and the re-run instruction; the retry after a failed directory step is `keyroster revoke user <name>`, replacing round 1's `keyroster user disable <name>`, which would leave the window's certificates. Task 2: `revoke_user_login_between_revoke_and_disable` (interleaved on a real signer and in the CLI), `revoke_user_quorum_proposal_pending`, `revoke_user_second_sweep_failed`. e2e: two revoke entries (two entries, then none; superseded in round 3: the second sweep re-lists, so two entries each). T-03-19 residual until Phase 4; barrier todo `2026-10-25-signer-issuance-barrier-after-subject-revoke.md`. The codex low "unexplained second revoke leaf" in TestRevokeUserEndToEnd is answered by the second sweep's counts. Since the split: Plan 03-03b, must_haves, Tasks 1-3 and T-03-19 (CLI and e2e); the real-signer interleaving stays in 03-03 Task 2 |
| plan-consistency medium and the split codex item "plan the response plumbing" (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): `revoke user` must print and KRL-check the answer's serials, but wire.RevokeResponse, serverclient.RevokeAnswer and internal/server/revoke.go carry none, and the server logs `req.Serial` (0 for the new targets) | MEDIUM | Plan 03-03, must_haves truth, Task 1 "Wire": `RevokeResponse.SerialCount` and up to 4096 `Serials`, strict parse; `RevokeAnswer.serial_count`/`serials`; the server copies them and logs the target kind. Since the split: the wire half stays in 03-03 (Task 1 "Wire", `TestRevokeResponse`); the server and client half is Plan 03-03b, Task 1 "Server and client" and Task 2 (`TestRevokeAnswerSerials`, `TestRevokeAnswerDecode`, `revoke_user_answer_truncated`) |
| plan-consistency medium (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): `revoke user` fails outright above tlog.MaxRevokedEntries (4096), and the CLI's behaviour on a failed revoke is unspecified | MEDIUM | Plan 03-03, Task 1 signer subject paragraph (split leaves) and Task 1 CLI (a failed first revoke still runs the disable and exits 1). Since the split: the signer half stays in 03-03; the CLI half is Plan 03-03b, Task 1 CLI and Task 2 `revoke_user_revoke_failed_still_disables` |
| codex low and plan-consistency low, merged (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): Task 3's verify passed when only one of the two runbooks had the `revoke user` instruction | LOW | Plan 03-03, Task 3 verify: `grep -q 'keyroster revoke user' docs/runbooks/enroll-user.md && grep -q 'keyroster revoke user' docs/runbooks/host-setup.md`. Since the split: Plan 03-03b, Task 3 verify |
| plan-consistency low (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): Task 2's acceptance required a revoke.md edit that Task 3 makes | LOW | Plan 03-03, Task 2 acceptance keeps cmd/keyroster/revoke.go only (plus `arrives in a later version` = 0); Task 3 acceptance checks `this version cannot read a KRL` = 0 in revoke.md. Since the split: both in Plan 03-03b (Task 2 and Task 3 acceptance) |
| plan-consistency low (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): `grep -c 'UNVERIFIED' docs/runbooks/revoke.md` already passed at main (nine labels from 03-01) | LOW | Plan 03-03, Task 3 acceptance: an awk check that the three new command sections each carry both labels, white space squashed; it prints 3. Since the split: Plan 03-03b, Task 3 acceptance, with the label `run in CI e2e (03-03b)` |
| plan-consistency low (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): stale code references and user-facing texts that 03-03 makes false | LOW | Plan 03-03: Task 2 replaces revoke.go's `arrives in a later version`; Task 3 replaces revoke.md's `arrives with 03-03` and `which 03-03 adds` (acceptance = 0 each). Since the split: these three are Plan 03-03b's (Task 2 and Task 3), because the commands they announce land here; the stale code references stay fixed in 03-03 |
| split plan-consistency low (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): Task 1's local e2e verify cannot pass on the owner's workstation (WSL no longer resolves keyroster.localhost; the namespace workaround fails TestSSHDRejects/pty_allowed). Judged: adopted: the CI e2e lanes are the authoritative evidence | LOW | Plan 03-03, Task 1 verify: push, dispatch the E2E workflow on the branch, watch it, and require the revoke PASS lines in both jobs' logs. Since the split: both plans; this plan requires TestRevokeUserEndToEnd, TestRevokeKeyEndToEnd and TestRevokeSerialEndToEnd |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| Q3 residual (03-03 plan check 2026-10-25 (Codex + Claude, PR #59 follow-up)): the window stays open at admin quorum > 1 until the co-signers install the disable | Phase 4, next to SC3's quorum and revocation-authority semantics: todo `.planning/todos/pending/2026-10-25-signer-issuance-barrier-after-subject-revoke.md`. Until then the CLI exits 4 and says so (T-03-19). Since the split: this plan's exit 4 and T-03-19 |

### Round 3 — PR #60 Codex docs review (2026-10-25)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Codex docs review, medium, upheld by a skeptic (PR #60): the second-sweep expectations contradicted the resolver and audit rules (the resolver lists every live certificate, the tests expected the second sweep to list only those issued in between) | MEDIUM | Resolved in 03-03 for re-listing (row there). This plan's half: Task 1 CLI and e2e (the same two serials from each sweep, each listed once in the KRL; two revoke entries of two entries each), Task 2 (the CLI interleave case answers the first sweep's serials plus the interleaved one), Task 3 (revoke.md explains why the second entry repeats the first), T-03-19 |
| Owner decision 2026-10-25, PR #60: split 03-03 (37 files, about 215k tokens) into 03-03 (formats and signer) and this plan (CLI and runbooks) | — | This file: the CLI commands, exits 3 and 4, the second sweep's CLI half, the KRL listing check, the server and client half of the answer's serials, TestRevokeUserEndToEnd and TestRevokeKeyEndToEnd, revoke.md's command sections, enroll-user.md, host-setup.md and the F-IN-01 todo. Deviation from the owner's list, for owner review: the signer-install.md stop for lost revocations, its `restoreSavedGreps` pin and revoke.md's sections 3 and 4 stay in 03-03, because 03-03's audit verify change ends the stop they replace (see 03-03's Budget Exception) |
</content>
</invoke>
| Codex split check (PR #60), low: the stale-runbook removal checks of Task 3 are wrap-sensitive; a phrase broken across a line passes `grep -c` falsely | LOW | Plan 03-03b, Task 3 acceptance: the three greps (`arrives with 03-03`, `which 03-03 adds`, `this version cannot read a KRL`) run on `tr -s '[:space:]' ' '` output, the idiom of 03-03's runbook checks (PR #60 Codex split check) |
