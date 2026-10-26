---
phase: 03-linux-agent-and-revocation
plan: 06b
type: execute
wave: 7
depends_on: ["03-03b", "03-06"]
files_modified:
  - internal/tlog/leaf.go
  - internal/tlog/leaf_test.go
  - internal/tlog/fuzz_test.go
  - internal/wire/recovery.go
  - internal/wire/wire_test.go
  - internal/wire/fuzz_test.go
  - internal/krl/recovery.go
  - internal/krl/krl_test.go
  - internal/signer/recovery.go
  - internal/signer/recovery_test.go
  - internal/signer/logstate.go
  - internal/audit/recovery.go
  - internal/audit/revoke.go
  - internal/audit/verify.go
  - internal/audit/export.go
  - internal/audit/verify_test.go
  - internal/server/revoke.go
  - internal/server/server.go
  - internal/server/revoke_test.go
  - cmd/keyroster-server/serve.go
  - cmd/keyroster-signer/recover.go
  - cmd/keyroster/recover.go
  - cmd/keyroster/recover_test.go
  - cmd/keyroster/revoke.go
  - test/e2e/recovery_test.go
  - test/vectors/leaf_revocation_recovery_v1.hex
  - test/vectors/recovery_request_signing_v1.hex
  - docs/runbooks/server-install.md
autonomous: false
requirements: [REVOKE-01, REVOKE-03]

estimate:
  tokens: 145000
  raw_tokens: 145000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decision 2026-10-25 (03-03 plan check, Q2): recovery of the revocations a signer restore lost is planned and merged before 03-07. Owner decision 2026-10-26 (PR #66): it is split into this plan (the code) and 03-06c (the restore procedure, the e2e drill and the CI pins), merged in that order; 03-07's Task 1 precondition checks 03-06c's SUMMARY on origin/main. The owner's direction is kept: the newest ops-signed KRL that keyroster-server served is imported as a union with the saved export's lost entries, in one admin-signed transaction, with one publish"
    - "keyroster-server keeps a durable copy of every KRL it serves: before GET /api/v1/krl (or any later route, 03-07's agent state included) serves a KRL document, refreshKRL verifies it with krl.VerifyManifest against the bundle of the status in force and that bundle's installation ID, and writes the exact serverclient.KRLDocument JSON to `<state-dir>/krl-served.json` (temporary file, fsync, rename, directory fsync, mode 0600). The copy is never replaced by a lower or equal version. A document it could not write, one that does not verify, one below the version it served before, and one with the served version but other bytes are never served: the route answers 503 and logs the reason, and hosts keep their last KRL (D-10). keyroster-server refuses to start when the copy exists and does not parse"
    - "This plan changes no restore step: signer-install.md, revoke.md, test/e2e/restore_test.go and test/systemd/smoke.sh stay as 03-03 left them, so 03-03's stop for a lost revocation stays in force until 03-06c replaces it with the recovery (a restore that lost a revocation keeps the signer down meanwhile), and no agent pulls a KRL before 03-07, which waits for 03-06c. The todo stays in pending/ for 03-06c to close"
    - "`keyroster revoke recover --restored FILE --saved FILE [--krl FILE ...] [--revoke-lost SERIAL ...] [--yes] [--admin-key FP] --out FILE` runs offline (no server call) as a policy admin: it reads all its inputs, every --krl document included, before it decides anything; it verifies both exports on the CLI config's trust pins and threshold (audit.Verify), requires one to be a prefix of the other (the --previous rule), refuses `recovery_installation_lost` when the restored bundle has no installation ID and either the saved export's bundle has one or any --krl document was given, prints `nothing to recover` and exits 0 only when neither bundle has an installation ID and no --krl document was given (PR #66 review), re-derives the saved export's last KRL document (Report.LastKRL), verifies every --krl document with krl.VerifyManifest under the restored export's bundle in force and installation ID, reads every lost certificate from the verified leaf bytes of the saved export's issue, login_issue and revocation_recovery entries after the restored log (Report.Certificates; never from the decoded fields), applies the owner's lost-certificate answer (Task 1), prints a summary, and signs one wire.RecoveryRequest under keyroster/revoke-recovery/v1 that names the installation and the restored log's size and root"
    - "`keyroster-signer recover-revocations --state-dir DIR` reads the signed request from standard input, takes the state lock, opens the signer with every start-up check (signer.New, no Serve) and in ONE transaction appends one revocation_recovery entry (leaf kind 15) listing the derived entries, writes one revocation row per entry and the request ID, and publishes one KRL; on any refusal or failure nothing is written. It refuses a request for another installation, for another log than exactly its own (size and root), without a policy-admin SSHSIG of the policy in force, with an import that does not verify under the bundle in force or holds key-hash sections, with a certificate that is not signed by a CA key of its role in the bundle in force, whose key ID does not name its serial, or whose serial is not above the restored serial high-water mark, with a used request ID, above MaxRecoveryEntries or the body cap (`recovery_too_large`), and when the publish's version would not be above every imported version (`recovery_version_not_above_import`, with the seconds to wait)"
    - "One rule derives a recovery's entries, used by the signer and by audit verify: krl.RecoveryEntries returns, in canonical order and without duplicates, every serial (ranges expanded, capped before allocation), key ID and explicit key of every import, plus one serial entry for each carried certificate marked revoke. A serial entry's ValidBefore is that of the certificate with the same serial and CA key, found in the restored issuance (signer: the issuance table; audit: the log's issue and login_issue entries; CLI: the restored export's issue and login_issue certificates) or among the request's certificates; a key-ID entry's comes from the certificate whose serial its key ID names (D-09: a key ID names one certificate) and whose key ID equals it; otherwise 0, which krl.Prunable never prunes. A certificate that the restored log knows only from an earlier revocation_recovery entry is not in the restored issuance, so its entries get 0: the fail-safe outcome, recorded in T-03-269 (PR #66 review). So the recovery only adds entries and never prunes one early"
    - "Owner decision 2026-10-25 (03-03 plan check, Q1) holds through the recovery: its publish takes krl_version = max(prev + 1, issued_at) like every publish, and audit verify additionally requires the krl_publish right after a revocation_recovery entry to be above every imported KRL version, so every host that saw a lost version accepts it"
    - "The signer's start-up check accepts a recovered database: rebuildLogFrom and appendLocked add a revocation_recovery entry's listed entries to the logged revocation multiset, so `revocations_not_logged` never fires after a recovery, at start, in doctor or at a publish; a restart after the recovery publishes nothing at start while the KRL is under an hour old, and every later publish keeps the union (TestPublishNeverDropsLiveEntry's property across a recovery)"
    - "`keyroster audit verify` checks kind 15: the request parses strictly (wire.ParseRecoverySigningBytes), names the bundle's installation, its restored size equals the entry's index and its restored root equals the root of the entries before it, its evidence is admin-sshsig/v1 by at least one admin of the policy in force under keyroster/revoke-recovery/v1, ResolvedAtSeconds × 10^6 is not after the leaf time, every import verifies (krl.VerifyManifest, krl.Parse, the KRL header version equals the manifest's, no key-hash section), every carried certificate verifies under a CA key of its role and is new to the log with a serial above its high-water mark, the owner's lost-certificate rule holds at ResolvedAtSeconds, the listed entries equal krl.RecoveryEntries over the log's certificates, and the next entry is its krl_publish, above every imported version; the export renders the kind with no `kind`, `bundle_version`, `version`, `directory` or `sigs` key of its own and never the KRL bytes"
    - "Leaf kind 15 `revocation_recovery` joins format v1 before kinds 11 to 14 exist, so tlog's Kind validity becomes an explicit set (1 to 10 and 15); 03-09 to 03-12 add 11 to 14 to that set (cross-plan notes added with this plan)"
    - "Every revocation 03-03 and 03-03b can write is recovered by the signer: serial (certificate issued before or after the snapshot), key ID, explicit key (the KRL carries the key bytes) and subject (its serial entries), including a revocation made after the latest saved export whose KRL keyroster-server served. TestRecoverRevocations proves each on a real signer with `ssh-keygen -Q`, with the transaction-level pending-recovery cases (a failed publish rolls back and a re-run succeeds once, a second run is refused, a restart keeps the union); TestRestoreRecoveryTracer runs a revocation after the saved export through the real binaries on CI e2e. The restore drill through the runbook's commands with sshd (TestRestoreRecoversLostRevocations) is 03-06c's"
    - "Certificate knowledge survives successive recoveries (PR #66 review): audit's Report.Certificates also holds every certificate a revocation_recovery entry carries, so when a later restore goes back before an earlier recovery, `keyroster revoke recover` lists and carries that recovery's certificates again: a kept host or machine certificate stays in the log and the summary, and the entries of a carried certificate keep its ValidBefore. Recovery-carried certificates never join the issuance state (the signer's issuance table, audit's issued certificates, subject and key-ID resolution)"
  artifacts:
    - path: "internal/krl/recovery.go"
      provides: "RecoveryEntries, the one rule that derives a recovery's entries for signer and audit"
      contains: "func RecoveryEntries"
    - path: "internal/signer/recovery.go"
      provides: "Signer.RecoverRevocations: the one-transaction recovery"
    - path: "internal/audit/recovery.go"
      provides: "verifyRecovery for leaf kind 15"
    - path: "cmd/keyroster/recover.go"
      provides: "keyroster revoke recover: offline, root-pinned preparation and admin signature"
    - path: "cmd/keyroster-signer/recover.go"
      provides: "keyroster-signer recover-revocations under the state lock"
    - path: "test/vectors/leaf_revocation_recovery_v1.hex"
      provides: "Golden leaf of kind 15"
  key_links:
    - from: "internal/server/revoke.go"
      to: "<state-dir>/krl-served.json"
      via: "refreshKRL writes the verified KRL document before any route serves it"
      pattern: "krl-served\\.json"
    - from: "internal/signer/recovery.go"
      to: "internal/krl/recovery.go"
      via: "the signer derives the entries it lists and writes as rows"
      pattern: "RecoveryEntries"
    - from: "internal/audit/recovery.go"
      to: "internal/krl/recovery.go"
      via: "audit re-derives the listed entries with the same rule"
      pattern: "RecoveryEntries"
    - from: "internal/signer/logstate.go"
      to: "internal/tlog/leaf.go"
      via: "the start-up rebuild adds kind 15's entries to the logged revocation multiset"
      pattern: "KindRevocationRecovery"
  prohibitions:
    - statement: "`keyroster-signer recover-revocations` never starts Serve and publishes only inside its one transaction, and the recovery never removes, shortens or replaces an entry: every restored revocation row stays, every imported entry is added, and an entry's ValidBefore comes only from a certificate with the same CA key and serial (or the serial its key ID names), else it is 0 and never pruned. (That no KRL is published after a restore before the recovery commits is the runbook's rule, 03-06c's prohibition)"
      status: resolved
      verification: test
---

<objective>
Recover the revocations that a signer restore lost, before agents start pulling KRLs in 03-07 (owner decision 2026-10-25, 03-03 plan check, Q2): the code half. After this plan, keyroster-server keeps every KRL it serves, and two offline commands import the newest KRL keyroster-server served and the saved export's last KRL, both ops-signed, plus the saved export's lost certificates, in one admin-signed transaction that publishes one KRL. That first KRL after the restore lists every entry any host could have seen. Nothing un-revokes, and `keyroster audit verify` re-derives the whole recovery from the log.

The restore procedure that runs the recovery under the hold in place of 03-03's stop, with the e2e drill and the CI pins, is 03-06c (owner decision 2026-10-26, PR #66: split), which runs right after this plan. Until 03-06c merges, 03-03's stop stays in force: a restore that lost a revocation keeps the signer down.

Purpose: REVOKE-03 (a rollback of the revocation state never reaches the fleet) and REVOKE-01 (lost revocations, including key IDs whose issuance the restore lost, todo point 11, stay revoked; lost live certificates are handled by the owner's answer in Task 1). With 03-06c, it closes the residual of threat T-03-207 (03-03): a revocation made after the latest saved export is no longer lost while keyroster-server's state survives the signer restore.

Output: keyroster-server's durable KRL copy and its server-install.md paragraph, leaf kind 15 with its audit rule and export, the recovery request format, `keyroster revoke recover`, `keyroster-signer recover-revocations`, their unit tests, golden vectors and fuzz targets, the tracer, and a PR.

**Design, with the facts from the 03-03 plan check it rests on** (todo `2026-10-25-plan-signer-restore-revocation-recovery.md`, points 1 to 11):
- **Offline, under the hold.** A 4 MiB KRL does not fit the signer socket's 64 KiB frame, and a restored signer that starts publishes at once (start-up and hourly publish, D-10). So the recovery is a `keyroster-signer` subcommand run under the state lock with the hold in force, like `install-bundle`, before the restored signer ever starts. "A pending recovery" is therefore the hold itself: there is no recovery state inside a running signer for anything to bypass (todo points 4 and 8).
- **No grep, no replay one by one.** Serial entries carry no key ID (point 1), decoded export fields are not bound (point 2) and `revoke key` exports only a fingerprint (point 3). The recovery therefore reads only signed bytes: ops-signed KRL documents (which carry serials under CA keys, key IDs and the explicit keys' bytes) and certificates taken from the verified leaf bytes. One transaction writes one leaf and one publish (point 4).
- **Durable source.** The server kept the KRL in memory only (5 s cache), so this plan gives it a durable copy, `krl-served.json` in its state directory, written before it serves. A file avoids a serverdb migration, which would collide with 03-07's 0005_agents.sql and 03-08's 0006_heartbeats.sql. The operator can also copy a file while the server is held, without the sqlite3 program the runbook does not install. A signer restore never rolls it back: the runbook takes only the signer's three database files, and the hold stops keyroster-server, which freezes the copy at the last KRL it served (point 6). An agent's accepted KRL (03-05's `<state>/accepted/`) cannot be a source for a plan gated before 03-07: no agent pulls a KRL yet. It stays a possible source later, and nothing here builds it.
- **Lost serials without an issuance** come from the imported KRL's certificate sections, under their CA key, with no issuance lookup. Their ValidBefore comes from a certificate when one is known, else it is 0 and never pruned (point "Lost serials" of the todo).
- **Leaf kind 15** is the first free number (11 to 14 are 03-09..03-12's; point 9). The numbering needs no floor (point 10, Q1).
- **03-10's negative probes** (point 7) and **03-13's start-up publish** (point 8) do not exist yet. This plan defines the contract and adds a cross-plan note to each: 03-10 keeps a recovered probe key renewable for the host whose probe certificate the recovery carried, and adds that drill case. Until 03-13 exists, every bundle copies the ops key. After it, an import signed under an ops key that only a lost bundle names is refused here: this fails closed, because the hold stays. Making that case recoverable is 03-13's design, and `install-bundle` never publishes.
- **A lost installation ID.** The homelab's bundle gains its installation ID only with 03-15's v4 bundle. When the restored bundle has none but the saved export's has one, or a server KRL copy exists, revocations may have followed that the restored signer cannot publish. `keyroster revoke recover` then refuses (`recovery_installation_lost`), the hold stays and the operator escalates. When neither bundle has one and no server copy is given, no KRL was ever published and nothing can be lost from one.

**Owner decision (Task 1), answered on 2026-10-26 (PR #66): lost certificates that are still valid** (todo point 5). The answer is `revoke-users-list-others`, the recommended option, for which this plan is written. Task 1 checks the recorded answer and carries it into the SUMMARY; nobody asks the owner again.
</objective>

## Budget Exception

**Accepted by the owner (Daniel, 2026-10-26, PR #66): 28 files (two of them generated golden vectors) and about 145k tokens**, against the 15-file and 100k smart-zone thresholds. The owner split the plan as first written (32 files plus the todo's move, about 195k, split option (b) of that version) into this plan (the code) and 03-06c (the procedure: signer-install.md, revoke.md, the e2e drill TestRestoreRecoversLostRevocations, the restore_test.go pins and smoke.sh, and the todo; 5 files plus the todo's move, about 55k, inside the thresholds), knowing that the code plan stays large. Growth over the split: the two PR #66 review fixes, about 5k (the --krl documents are read before any `nothing to recover` exit; recovery-carried certificates are collected again).

Why the code stays one plan: a recovery is safe only when the import, the one-transaction publish, the start-up check and the audit rule land together. Each part alone fails in a dangerous way:
- an audit rule without the signer path is never exercised;
- a signer path without the start-up change refuses its own database (`revocations_not_logged`);
- the commands without the audit rule write logs that every `audit verify` binary refuses ("not verifiable by this version").

The server's durable copy is the other half of the owner's direction: without it, revocations after the latest saved export stay lost (T-03-207).

Why the split is safe: this plan changes no restore step, so 03-03's stop stays in signer-install.md until 03-06c merges, and a restore that lost a revocation keeps the signer down meanwhile. No agent pulls a KRL before 03-07, which waits for 03-06c. Placed here, not in 03-06c: docs/runbooks/server-install.md's paragraph on krl-served.json, because D-20 puts it in the PR that makes keyroster-server write that file and refuse to start on a damaged one, and the start refusal's message points at it.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-03-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md
@.planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md
@internal/krl/krl.go
@internal/krl/manifest.go
@internal/krl/parse.go
@internal/signer/revoke.go
@internal/signer/krl.go
@internal/signer/logstate.go
@internal/audit/revoke.go
@internal/server/revoke.go
@docs/runbooks/server-install.md

Delivery protocol: 01-SKELETON.md, phase 03 names. Branch `p03/06b-restore-recovery`, SUMMARY `.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md`, docs commit `docs(03-06b): complete restore-recovery plan`. `depends_on` holds 03-03b (every revocation target, v2 installation-bound requests, krl.Parse, the restore stop 03-06c replaces) and 03-06 (ordering only: the owner placed this plan after 03-06 and before 03-07, 2026-10-26; no 03-06 artifact is used). 03-06c (`p03/06c-restore-procedure`) depends on this plan and reads its SUMMARY for the final names and output lines; 03-07 depends on 03-06c.
</context>

<tasks>

<task type="auto">
  <name>Task 1: Decision checkpoint, pre-answered by the owner on 2026-10-26 (PR #66) — lost certificates that are still valid: `revoke-users-list-others` (todo point 5)</name>
  <precondition>`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md` and `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-06-SUMMARY.md` both exit 0, and the first line of `$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt` is exactly `revoke-users-list-others`</precondition>
  <files>none in the repository (reads `$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt`, outside it; Task 4 writes the answer into 03-06b-SUMMARY.md)</files>
  <decision>Recorded decision (answered; do not ask again). When a restore lost issue and login_issue entries that the saved export still records, those certificates are valid in the wild, and the restored signer does not know them. Its issuance table has no row for them, so `revoke serial` refuses `unknown_serial`, `revoke key-id` refuses `key_id_not_issued` (T-03-211), and `revoke user` does not find them. The owner decided what the recovery does with them: option `revoke-users-list-others` below.</decision>
  <context>Facts:
- The recovery reads every lost certificate from the saved export's verified leaf bytes. It cannot see certificates issued after the latest saved export: they expire by their TTL (the user CA's policy cap; host certificates 30 days, D-16; machine certificates day-scale, D-15).
- A revoked user certificate's owner logs in again for a new one.
- Revoking a machine certificate stops that automation until it renews (03-11 renews by proof of possession).
- A host certificate in the KRL hosts install changes nothing for sshd, which never checks its own host certificate against RevokedKeys. Clients refuse revoked host keys through 03-09's revoked-hosts list.
- The 03-03 plan check proposed the fail-safe default: revoke the lost user certificates that are still live, and list host and machine certificates for an admin to decide.
- Every option carries all lost certificates in the signed recovery entry, so the log shows which ones existed and what was decided.

Plans that build on the answer: this plan's request format and audit rule; 03-09, 03-10 and 03-11, which add their certificate kinds to the collection.</context>
  <options>
    <option id="revoke-users-list-others">
      <name>Revoke every lost user certificate still live; list lost host and machine certificates with their public keys, and revoke one only when the admin names it (`--revoke-lost SERIAL`) (recommended; CHOSEN by the owner on 2026-10-26)</name>
      <pros>
- The check's fail-safe default.
- No authority change: the recovery only revokes, like a revoke by one admin.
- The signer and audit enforce the user rule from the certificates the request carries.
- A kept host or machine certificate stays visible in the log.
- Point 11 closes: a lost user key ID needs no revocation, because its certificate is revoked by serial.
- Small: one flag per certificate.</pros>
      <cons>
- A kept host or machine certificate can afterwards be revoked only by key (`keyroster revoke key` with the public key the summary prints) until it expires.
- Serial, key-ID and subject revocation still refuse it.
- Certificates issued after the latest saved export are unknown under every option.</cons>
    </option>
    <option id="revoke-all-lost">
      <name>Revoke every lost certificate still live, of every role</name>
      <pros>
- Simplest: no per-certificate choice and no flag.
- No lost certificate stays valid.</pros>
      <cons>
- Lost machine certificates stop their automation until it renews.
- Lost host certificates are listed in the user KRL to no effect.
- Stops this plan for a revision of Tasks 2 to 4 (the flag, the rule, the tests).</cons>
    </option>
    <option id="readopt-lost">
      <name>Revoke lost user certificates as in the first option, and also record every lost certificate as issued (issuance rows), so serial, key-ID and subject revocation work for kept ones later</name>
      <pros>
- The restored signer knows every certificate the saved export knows.
- Nothing kept is limited to revocation by key.</pros>
      <cons>
- An authority change: the recovery writes issuance state without issuing.
- Ripples into the start-up check (checkLogCovers counts issuances and the serial high-water mark), audit's issuance state and request-ID maps, and every later issuance kind (03-09 to 03-11).
- About 15k more tokens and two more files.
- Stops this plan for a revision before implementation.</cons>
    </option>
  </options>
  <read_first>
    - .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md points 5 and 11
    - .planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md D-09, D-15, D-16
    - This plan's objective and threat row T-03-272
  </read_first>
  <action>Pre-answered: the owner chose `revoke-users-list-others` on 2026-10-26 (PR #66), and the answer is recorded in `$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt` (line 1 the option id, line 2 the owner's verbatim wording, line 3 Claude's description of the option, which is not the owner's words). Do not present the options and do not ask the owner again; do not re-ask Q1 or Q2 of the 03-03 plan check either, which are recorded. Verify the file as `<verify>` says and keep, for the SUMMARY that Task 4 writes, the exact line `Lost-certificates answer: revoke-users-list-others` followed by line 2 of the file, copied byte for byte. This task stays a task of its own, typed `auto`, because every `checkpoint:*` task stops the executor and would ask the owner again (gsd-executor.md, execute_tasks step 3; owner decision 2026-10-26, PR #66: pre-answered). If the file is missing, or its first line is not exactly `revoke-users-list-others`, the precondition fails: stop before Task 2, create no branch and change no file, and report the precondition as unmet, because the plan is written for this answer only (any other answer needs a revision of Tasks 2 to 4 before implementation).</action>
  <verify>
    <automated>f="$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt" && head -n 1 "$f" | grep -qx 'revoke-users-list-others' && test -n "$(sed -n 2p "$f")"</automated>
    <fails_when>non-zero exit (the answer file is missing, its first line is not exactly `revoke-users-list-others`, or the owner's wording on line 2 is missing)</fails_when>
  </verify>
  <acceptance_criteria>
    - The first line of r06b-lost-certs-answer.txt is exactly `revoke-users-list-others` and line 2 holds the owner's wording; no question went to the owner.
    - 03-06b-SUMMARY.md (Task 4) carries the line `Lost-certificates answer: revoke-users-list-others`, followed by line 2 of the file verbatim (Task 4's acceptance checks both).
  </acceptance_criteria>
  <done>The owner's recorded answer on lost live certificates is checked before any recovery code exists, and it is carried into the SUMMARY.</done>
</task>

<task type="tracer">
  <name>Task 2: End-to-end "keyroster-server keeps the KRL it served → a signer restore loses a revocation made after the saved export → keyroster revoke recover (admin, offline) → keyroster-signer recover-revocations under the lock → one revocation_recovery entry and one krl_publish → the server serves and keeps the union → ssh-keygen -Q refuses the lost certificate → audit verify proves it"</name>
  <reversibility rating="costly">Leaf kind 15's body and the keyroster/revoke-recovery/v1 request bytes are read by every later verifier; changing them later needs a new domain tag and keeping the old rule.</reversibility>
  <precondition>Task 1's answer is recorded and `head -n 1 "$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt"` prints exactly `revoke-users-list-others`</precondition>
  <files>internal/tlog/leaf.go, internal/wire/recovery.go, internal/krl/recovery.go, internal/signer/recovery.go, internal/signer/logstate.go, internal/audit/recovery.go, internal/audit/revoke.go, internal/audit/verify.go, internal/audit/export.go, internal/server/revoke.go, internal/server/server.go, cmd/keyroster-server/serve.go, cmd/keyroster-signer/recover.go, cmd/keyroster/recover.go, cmd/keyroster/revoke.go, internal/signer/recovery_test.go, test/e2e/recovery_test.go</files>
  <read_first>
    - The todo `.planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md` (all of it, points 1 to 11) and this plan's objective
    - internal/server/revoke.go (currentKRL, refreshKRL, dropKRL; handleKRL relays and does not verify today), internal/server/server.go (Config, New, newServer), cmd/keyroster-server/serve.go (--state-dir, openStateDB)
    - internal/krl/manifest.go (Manifest with LogIndex, VerifyManifest), internal/krl/parse.go (Parsed, ParsedSection, SerialRange; SHA1 and SHA256 fields), internal/krl/krl.go (Entry, PublishSet, Prunable, RoleCAKeys, CheckExplicitKeys)
    - internal/signer/revoke.go (Revoke's one transaction, revocationRow, certCAKey, verifyAdminSignatures through verifyRevokeEvidence), internal/signer/krl.go (publishKRLLocked, republishIfDue, loadKRL), internal/signer/logstate.go (rebuildLogFrom's kind switch, loggedRevocations.add and check, appendLocked's KindRevoke branch, checkLogCovers), internal/signer/signer.go (New), internal/signerdb/revocation.go (IssuanceBySerialTx, InsertRevocation, InsertRevokeRequestTx, RevokeRequestUsed)
    - internal/tlog/leaf.go (Kind, valid, String, checkBody, RevokeBody, RevokedEntry.check, maxBody), internal/wire/revoke.go (RevokeRequestDomain = RevokeSSHSIGNamespace, SigningBytes, Marshal, ParseRevokeSigningBytes)
    - internal/audit/verify.go (Options, Report, Verify's switch, maxLine 16 MiB, issuance, checkGrepFields, checkReplayFields), internal/audit/revoke.go (revocations, loggedCert, addCert, before, finish, publishDue, verifyKRLPublish, verifyRevokeAdmins), internal/audit/export.go (decodeLeaf)
    - cmd/keyroster-signer/install.go and serve.go (openState, openStoredBackend, signer.New's Config), cmd/keyroster/audit.go (readPrevious), cmd/keyroster/dirpipe.go (openAdminSession, adminSigner), cmd/keyroster/revoke.go (runRevoke's subcommand switch)
    - test/e2e/restore_test.go (TestRestoreReplaysLostDirectory: how a test stops the signer, copies signer.db, restores it, exports and verifies), test/e2e/revoke_test.go (TestRevokeSerialEndToEnd: KRL fetch and `ssh-keygen -Q`)
  </read_first>
  <action>
Create branch `p03/06b-restore-recovery` from `origin/main`.

**keyroster-server keeps what it serves.** Config gains `KRLFile`. serve.go passes `filepath.Join(stateDir, "krl-served.json")`. New refuses an empty KRLFile. The tests' internal constructor (newServer) may leave it empty, which disables the copy, and only tests use that path.

At start, New reads an existing copy: strict JSON of serverclient.KRLDocument, then krl.ParseManifest of its manifest. It keeps the served version in memory, and refuses to start when the copy does not parse. The message says the file is the restore source for lost revocations and must be kept, and names docs/runbooks/server-install.md (Task 4).

refreshKRL, the only place the server reads the signer's KRL, handles a non-empty answer in order:
1. Verify it: krl.VerifyManifest(manifest, sig, krl, the bundle of currentStatus, that bundle's installation ID, 0).
2. Compare its version with the served one:
   - higher, or no copy yet: write the exact KRLDocument JSON that handleKRL serves to KRLFile (temporary file in the same directory with O_EXCL and mode 0600, write, fsync, rename, fsync of the directory; the directory fsync is skipped when runtime.GOOS is windows, which cannot fsync a directory handle: keyroster-server runs only on Linux, but internal/server's tests also run on the cli-windows lane), then update the in-memory version;
   - equal with byte-identical documents: write nothing;
   - anything else (lower, or equal with other bytes): refuse.
3. Only then store the cache entry.

A failed verify, a refusal and a failed write all make the refresh fail. That answer is never cached and the route answers 503 as for an unreachable signer. The log names the reason: `KRL not served: version X is below version Y this server served (a signer restored without the recovery? signer-install.md)`, `KRL not served: it does not verify ...`, or `KRL not kept: ...`.

Every route that serves a KRL must go through currentKRL; 03-07's agent state route is noted to do so (cross-plan note in 03-07). handleRevoke still only drops the cache. A 404 `no_krl` (nothing published) writes nothing.

**Leaf kind 15.** tlog: `KindRevocationRecovery Kind = 15`, String `revocation_recovery`. `valid()` becomes an explicit set: 1 to 10 and 15. Kinds 11 to 14 are added by 03-09 to 03-12, which the cross-plan notes tell. checkBody and DecodeLeaf gain the kind.

The body, per Encode and the strict `DecodeRecoveryBody`: `RecoveryBody{PolicyVersion, ResolvedAtSeconds uint64; Request []byte; Evidence []wire.Evidence; Entries []RevokedEntry}`, in that order:
- Request: uint24 length prefix, at most `wire.MaxRecoveryRequest` (9 MiB);
- Evidence: as RevokeBody's;
- Entries: uint24 length prefix, each entry encoded and checked like RevokeBody's (RevokedEntry.check), at most `MaxRecoveryEntries` (1 << 16);
- the whole body at most `MaxRecoveryBody` (11 MiB).

The export line of the largest body must still fit audit's maxLine of 16 MiB: base64 of 11 MiB is about 14.7 MiB, plus a decoded object of counts only. A test in Task 3 proves it.

**The recovery request.** In internal/wire/recovery.go:
- `RecoveryRequestDomain = "keyroster/revoke-recovery/v1"` and `RecoverySSHSIGNamespace = RecoveryRequestDomain` (the convention of RevokeRequestDomain).
- `RecoveryRequest{InstallationID string; RequestID [16]byte; CreatedAt uint64; RestoredSize uint64; RestoredRoot [32]byte; Imports []RecoveryImport; Certificates []RecoveredCertificate; Evidence []Evidence}`:
  - RecoveryImport is {KRL, Manifest, Sig []byte}, with 0 to 4 imports (MaxRecoveryImports). Each KRL is at most MaxRecoveryKRL = 4 MiB (equal to krl.MaxKRL, asserted by a test in internal/tlog, which imports both), and the manifest and signature are at most the krl manifest caps. No two imports have the same manifest bytes.
  - RecoveredCertificate is {Cert []byte; Revoke bool}, with at most 4096 certificates (MaxRecoveryCertificates), each at most 64 KiB (MaxRecoveryCert, equal to tlog.MaxCert by the same test), sorted by the certificate's serial with no serial twice.
- `SigningBytes()`: the domain tag, then every field but Evidence, in a fixed layout. At most `MaxRecoveryRequest` = 9 MiB (a wire constant, which tlog's body cap uses), so a request with large imports is refused, never truncated.
- `Marshal()` and `ParseRecoveryRequest` are the file form, the signing bytes plus the evidence. Strict: trailing bytes are refused and the result round-trips.
- `ParseRecoverySigningBytes`: the logged form, strict, round-trips with SigningBytes.

**One derivation rule.** In internal/krl/recovery.go: `RecoveryEntries(imports []*Parsed, certs []RecoveredCert, lookup CertLookup) ([]Entry, error)`.
- `RecoveredCert{CAKey []byte; Serial uint64; KeyID string; ValidBefore uint64; Revoke bool}`, built by the callers from the verified certificates.
- `CertLookup func(serial uint64) (caKey []byte, keyID string, validBefore uint64, ok bool)`: the restored issuance in the signer, the log's certificates in audit.

What it returns, as krl.Entry:
- For every import, every serial of every certificate section. Ranges are expanded with a running count that refuses above `MaxRecoveryEntries` before it allocates (ErrRecoveryTooLarge), so `[1, 2^64 − 1]` is refused, not allocated. Each serial entry has the section's CA key, with ValidBefore taken from the carried certificate or the lookup whose serial and CA key match, else 0.
- Every key ID of every section, with ValidBefore taken from the certificate whose serial cert.ParseKeyID reads from the key ID and whose key ID equals it (D-09: a key ID names one certificate), else 0.
- Every explicit key.
- One serial entry for each carried certificate with Revoke, with its own CA key and ValidBefore.

The result is in canonical order (kind, CA key bytes, serial, key ID, key) with exact duplicates removed. An import with a SHA-1 or SHA-256 section is refused ErrMalformed: this installation never publishes one, so an ops-signed KRL with one is not ours to import.

The recovery adds no explicit-key cap of its own. Its keys come from KRLs this installation published under the cap, and later `revoke key` requests count them (krl.CheckExplicitKeys over every row and audit's entries).

**Signer.** In internal/signer/recovery.go: `(*Signer).RecoverRevocations(ctx, data []byte) (*RecoveryResult, error)`, under s.mu. In order, each failure a named refusal (an error wrapping the name) with nothing written:
1. Parse (`recovery_malformed`).
2. The bundle in force has an installation ID (`krl_no_installation_id`) equal to the request's (`recovery_installation_mismatch`).
3. RestoredSize and RestoredRoot equal the committed tree's size and root (`recovery_log_mismatch`). This binds the request to exactly this restored log, so it is single-use and cannot be applied to any other state.
4. The request ID is not used (`duplicate_request`).
5. The evidence: admin-sshsig/v1 by at least one admin of the policy in force over SigningBytes under RecoverySSHSIGNamespace, through verifyAdminSignatures with quorum 1, as for revocation, because the recovery only adds revocations (`recovery_evidence_invalid`).
6. Each import: krl.VerifyManifest under the bundle in force and its installation ID with stored version 0, krl.Parse, and the KRL header version equal to the manifest's (`recovery_import_invalid`). The message for ErrSigner says that the import is signed under an ops key the restored bundle does not name. That is possible only after 03-13's ops-key rotation, and the hold stays.
7. Each certificate (`recovery_certificate_invalid`):
   - it parses as a certificate whose signature verifies under its SignatureKey;
   - that key is a CA key of the role its key ID names in the bundle in force (krl.RoleCAKeys);
   - its key ID parses and names its serial.
8. Each certificate's serial is above the restored serial high-water mark and is not in the issuance table (`recovery_certificate_not_lost`). A certificate that an earlier revocation_recovery entry carried is not issued, so this check passes for it: carrying it again (the CLI does so when the restore went back before that recovery) only adds entries.
9. The owner's answer: every carried certificate of the user CA that is live (krl.EntryLive) at the resolution time T has Revoke (`recovery_user_certificate_kept`).

T is the call's one clock reading in whole seconds, as Revoke takes it.

Then one logTx:
1. checkTrustCurrent.
2. Entries = krl.RecoveryEntries with the lookup over IssuanceBySerialTx and certCAKey. Above MaxRecoveryEntries, or a body above MaxRecoveryBody, is refused `recovery_too_large`. The lookup is the issuance table only, on purpose (PR #66 review). A certificate that the restored log knows only from an earlier revocation_recovery entry (a later restore that kept that recovery) gives its entries ValidBefore 0. The rows that earlier recovery wrote are restored with the certificate's own ValidBefore and are pruned with it; the new row with 0 keeps the entry in the KRL for good. That is over-revocation of a certificate that is already revoked, never an un-revocation (T-03-269). Taking the ValidBefore from the earlier leaf instead would make the signer's start-up rebuild, audit and the CLI decode carried certificates as a second certificate source, a new parse path at signer start that can refuse to start.
3. Append the kind-15 leaf {policy version, T, SigningBytes, Evidence, Entries}.
4. One revocation row per entry through revocationRow, with this leaf's index and the request ID.
5. InsertRevokeRequestTx.
6. publishKRLLocked. Before the transaction commits, the published version must be above every import's KRL version. Otherwise it returns `recovery_version_not_above_import`, and the error names the seconds until the clock passes the highest imported version, so the transaction rolls back.

appendLocked's revoke branch adds the entries of a kind-15 leaf to pendingRevoked, and rebuildLogFrom's switch adds them to the logged multiset (decode error: errLogMismatch as for revoke). So loggedRevocations.check passes at this publish, at every later start, in doctor (CheckLog) and at every later publish. checkLogCovers is unchanged: the recovery writes no issuance row.

RecoveryResult carries the leaf indexes, the KRL version, and the counts of entries, imports, certificates revoked and certificates kept.

**keyroster-signer recover-revocations.** In cmd/keyroster-signer/recover.go, registered like install-bundle: `--state-dir` (required) and `--backend-opt`. It reads the file form from standard input, capped at MaxRecoveryRequest plus the evidence caps. It takes the lock through openState and opens the backend through openStoredBackend. Then signer.New with that backend and the database: the start-up checks only, never Serve, so no start-up publish runs. It prints `recovered: <entries> entries from <imports> imported KRLs, <revoked> lost certificates revoked, <kept> kept; KRL v<version> (log entries <recovery leaf>, <publish leaf>)`. A refusal exits 1 with the name and reason.

**keyroster revoke recover.** In cmd/keyroster/recover.go, dispatched from runRevoke's switch as `recover`. It is offline: loadConfig and adminSigner, and no serverclient.

Every input is read before anything is decided, so no exit below can skip one (PR #66 review: a `nothing to recover` exit decided from the two exports alone skipped the server's copy).
1. Read --restored, --saved and every --krl document into memory. Each --krl document is decoded with the serverclient.KRLDocument decoder and its manifest with krl.ParseManifest, both strict; a document that does not decode is refused `recovery_import_invalid`.
2. Verify each export with audit.Verify on the config's TrustPins and TrustThreshold.
3. The prefix rule:
   - when the saved export is longer, Verify(saved) with Options.Previous set to the restored export's checkpoint (readPrevious) must pass, and the lost certificates are those at or after the restored size;
   - otherwise Verify(restored) with the saved checkpoint as Previous must pass, and there are none;
   - when neither holds, refuse: the exports are a fork, so escalate as step 2 does.
4. The installation ID, decided from all three inputs:
   - when the restored export's Report.Bundle has no installation ID, and either the saved export's has one or any --krl document was given, refuse `recovery_installation_lost`: a lost bundle added the ID and revocations may have followed, which the restored signer cannot publish (keep the hold, escalate). A --krl document is that proof on its own, without being verified (it cannot be, under a bundle without an ID): a KRL is published only under a bundle with an installation ID (the signer refuses `krl_no_installation_id`, audit verify refuses such a krl_publish), and no successor bundle drops one (trust's chain rule);
   - only when neither bundle has one and no --krl document was given, print `nothing to recover: neither export's trust bundle has an installation ID and no server KRL copy was given, so no KRL was ever published`, write no file and exit 0. The saved export then holds no krl_publish entry either, for the same two reasons.
5. Verify every --krl document with krl.VerifyManifest under the restored export's Report.Bundle and its installation ID (`recovery_import_invalid` otherwise).

audit.Options gains `CertificatesFrom *uint64`. Verify then fills `Report.Certificates`, each with its index, kind and certificate bytes from the verified leaf, at or after the index: the certificate of every issue and login_issue entry, and every certificate a revocation_recovery entry carries, read from the request bytes in its verified leaf (PR #66 review). `Report.LastKRL` is the last krl_publish entry's {KRL as verifyKRLPublish re-derived it, manifest, sig}, and `Report.Bundle` is the bundle in force at the end. A recovery command needs nothing else from audit.

Imports: Report.LastKRL of the saved export when it has one, and each verified --krl document. The same document twice is imported once.

Certificates: every lost certificate, that is every certificate of the saved export's Report.Certificates at or after the restored size, of all three kinds, one per serial (the first in log order, since the request refuses a repeated serial). A certificate that only an earlier revocation_recovery entry carries is therefore carried again when the restore went back before that recovery, so a kept host or machine certificate stays in the summary and in the log (T-03-272), and the entries of a carried certificate keep its ValidBefore. Revoke is set for each serial named by --revoke-lost, and for every user certificate that is live by krl.EntryLive at the CLI's clock minus the signer's 300 s skew bound. The skew bound is there because a workstation clock ahead of the signer's must not leave a certificate unmarked that the signer still sees as live (`recovery_user_certificate_kept`); marking one that is already expired is harmless, since its entry is pruned at the publish. A --revoke-lost serial that is not a lost host or machine certificate is refused.

The CLI computes the entries with the same krl.RecoveryEntries and a lookup over the restored export's issue and login_issue certificates (Report.Certificates from 0, without the recovery-carried ones, because the signer's lookup is its issuance table, which holds exactly those). It prints the summary:
- installation ID;
- restored size and root, and saved size;
- each import's source, version, issued_at and entry counts;
- each lost certificate with serial, role, subject, key fingerprint, ValidBefore, live or not, and revoke or keep, where each kept one ends with `revoke later with: keyroster revoke key <file with this public key>`;
- the entry count and the version the publish must exceed.

It asks for confirmation unless --yes, signs SigningBytes with the admin key under RecoverySSHSIGNamespace, and writes the file form to --out (mode 0600, O_EXCL).

**Audit.** In internal/audit/recovery.go: verifyRecovery(index, body, leafMicros, a, rs, iss, root-before). Verify's switch gains the kind and passes the root of the tree before the entry. The checks are those in must_haves.

The lookup is the log's issued certificates (issue and login_issue, rs.certs), the same set as the signer's issuance table. loggedCert gains the key ID, and addCert records it. A certificate a revocation_recovery entry carries goes into Report.Certificates only, never into rs.certs, bySubject or byKeyID, so subject and key-ID re-derivation keep reading issuance as the signer does, and a later recovery's entries for it get ValidBefore 0 as on the signer.

Then rs.add(entries), a recovery counter, and rs.due as for a revocation, carrying the highest imported version. verifyKRLPublish requires the publish right after a recovery to be above it. `before` keeps that floor for the next check, because it clears due.

Report gains `Recoveries`. export.go decodeLeaf renders kind 15 with `restored_size`, `imports` (count), `import_krl_versions`, `certificates`, `certificates_revoked`, `entries` (count) and `admins`. It has no `kind` key besides the line's own and no `bundle_version`, `version`, `directory` or `sigs` key, and never the KRL or certificate bytes (checkGrepFields and checkReplayFields stay as they are).

**Tracer tests.**
- `TestRecoveryTracer` in internal/signer/recovery_test.go:
  1. A real signer with a software CA issues alice two certificates.
  2. Its database is copied (the snapshot).
  3. The signer revokes the first by serial and publishes; that KRL document is kept as the server copy would keep it.
  4. A second signer opened on the snapshot copy is the restored one.
  5. A recovery request, built from that KRL document and signed by the policy admin key, is applied with RecoverRevocations.
  6. The restored signer's stored KRL makes `ssh-keygen -Q` refuse the first certificate and accept the second.
  7. audit.Verify of the exported restored-plus-recovered log passes and counts one recovery.
  8. A new signer opened on that database starts (no revocations_not_logged).
- `TestRestoreRecoveryTracer` in test/e2e/recovery_test.go runs the same path with the real binaries:
  1. keyroster-server serves the KRL after a `keyroster revoke serial`, and krl-served.json then exists with that version.
  2. The signer is restored to a copy of signer.db taken before the revocation, with the server stopped.
  3. `keyroster revoke recover --yes` with the server copy as --krl.
  4. `keyroster-signer recover-revocations` reading that file.
  5. Start both; the KRL the server then serves makes `ssh-keygen -Q` refuse the certificate, and krl-served.json holds the new, higher version.
  6. `keyroster audit verify` passes on the final export, with `--previous` set to the restored export.

Like 03-03, the e2e evidence comes from the CI E2E lanes dispatched on the pushed branch, because WSL on the owner's workstation does not resolve `keyroster.localhost` (deferred-items.md).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/tlog/... ./internal/wire/... ./internal/krl/... ./internal/signer/... ./internal/signerdb/... ./internal/audit/... ./internal/server/... ./cmd/keyroster/... ./cmd/keyroster-signer/... ./cmd/keyroster-server/...' && bash scripts/linux.sh 'go test -race -count=1 -v -run TestRecoveryTracer ./internal/signer/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or "--- PASS: TestRecoveryTracer" missing</fails_when>
    <automated>git push -u origin p03/06b-restore-recovery && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/06b-restore-recovery && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/06b-restore-recovery --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit (the E2E run on the pushed head failed or never appeared), or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestRestoreRecoveryTracer", "--- PASS: TestRevokeSerialEndToEnd" or "--- PASS: TestRestoreRunbookChecks", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - The derivation rule exists once and both sides call it, checked in production code with comments stripped:
      - `grep -c 'func RecoveryEntries' internal/krl/recovery.go` prints at least 1, and `grep -rl 'func RecoveryEntries' internal/` lists only internal/krl/recovery.go (one definition);
      - `grep -v '^[[:space:]]*//' internal/signer/recovery.go | grep -c 'RecoveryEntries'` prints at least 1;
      - `grep -v '^[[:space:]]*//' internal/audit/recovery.go | grep -c 'RecoveryEntries'` prints at least 1.
    - `grep -cE 'KindRevocationRecovery[[:space:]]+Kind[[:space:]]*=[[:space:]]*15' internal/tlog/leaf.go` prints at least 1, and `grep -v '^[[:space:]]*//' internal/signer/logstate.go | grep -c 'KindRevocationRecovery'` prints at least 1 (the start-up rebuild).
    - `grep -c 'case tlog.KindRevocationRecovery' internal/audit/verify.go` prints at least 1, and the default branch stays (`grep -v '^[[:space:]]*//' internal/audit/verify.go | grep -c 'not verifiable by this version'` prints at least 1).
    - `grep -c 'krl-served.json' cmd/keyroster-server/serve.go` prints at least 1, and `grep -v '^[[:space:]]*//' internal/server/revoke.go | grep -c 'VerifyManifest'` prints at least 1 (the server verifies before it keeps).
    - `grep -c '"recover"' cmd/keyroster/revoke.go` and `grep -c '"recover-revocations"' cmd/keyroster-signer/recover.go` each print at least 1.
    - No serverdb or signerdb migration is added: `git diff --name-only origin/main -- internal/serverdb/migrations internal/signerdb/migrations` prints nothing.
    - The 03-01 and 03-03 golden vectors are unchanged: `git diff origin/main -- test/vectors/` lists no existing file.
    - The CI E2E run on the pushed head is the evidence for the e2e tracer; the SUMMARY names the run ID.
  </acceptance_criteria>
  <done>A revocation lost with a restore, and newer than the saved export, is back in the first KRL the restored signer publishes, through the real server copy, the admin-signed request and the offline recovery, and audit verify proves it.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Refusals, pending-recovery cases, derivation cases, the server copy, golden vectors and fuzz targets</name>
  <files>internal/tlog/leaf_test.go, internal/tlog/fuzz_test.go, test/vectors/leaf_revocation_recovery_v1.hex, test/vectors/recovery_request_signing_v1.hex, internal/wire/wire_test.go, internal/wire/fuzz_test.go, internal/krl/krl_test.go, internal/signer/recovery_test.go, internal/audit/verify_test.go, internal/server/revoke_test.go, cmd/keyroster/recover_test.go</files>
  <behavior>
    - tlog:
      - `TestRecoveryBody` round-trips and refuses each named case: `request_too_large`, `entries_over_cap`, `body_over_cap`, `entry_kind_fields` (a serial entry with a key ID), `trailing_bytes`.
      - `kinds_are_a_set`: 11 to 14 refused by DecodeLeaf and MarshalLeaf, 15 accepted.
      - `TestRecoveryLeafGoldenVector` (leaf_revocation_recovery_v1.hex: one import, one carried certificate, three entries).
      - `TestRecoveryCaps`: wire.MaxRecoveryKRL equals krl.MaxKRL and wire.MaxRecoveryCert equals tlog.MaxCert (here, because tlog imports wire and a wire test cannot import tlog).
      - FuzzDecodeLeaf's seed loop covers kind 15.
    - wire:
      - `TestRecoveryRequest`: SigningBytes and Marshal round-trip. Refused: an empty installation ID, more than 4 imports, a KRL above MaxRecoveryKRL, two imports with the same manifest, unsorted or repeated certificate serials, more than 4096 certificates, trailing bytes, and a wrong domain tag.
      - `TestRecoveryRequestSigningVector` (recovery_request_signing_v1.hex).
      - `FuzzParseRecoveryRequest` and `FuzzParseRecoverySigningBytes` never panic; whatever parses round-trips. Seeds: the vector and one request per shape.
    - krl.RecoveryEntries, `TestRecoveryEntries`:
      - `serial_vb_from_lookup`;
      - `serial_vb_from_carried_certificate`;
      - `serial_ca_mismatch_vb_zero` (the lookup's certificate is under another CA key);
      - `key_id_vb_from_named_serial` (the key ID's ser= names a known certificate with that key ID);
      - `key_id_other_text_vb_zero`;
      - `explicit_keys_kept`;
      - `range_expanded` ([5, 9] becomes five entries);
      - `range_cap_refused_before_allocation` ([1, 2^64 − 1] refused, with testing.AllocsPerRun below a small bound);
      - `hash_section_refused`;
      - `duplicates_across_imports_once`;
      - `canonical_order` (three input orders give identical output);
      - `revoked_certificate_entry` (a carried certificate with Revoke and not in any import gives one serial entry);
      - `kept_certificate_no_entry`.
    - Signer, in internal/signer/recovery_test.go (`TestRecoverRevocations` subtests):
      - Refusals: `recovery_malformed`, `recovery_installation_mismatch`, `recovery_log_mismatch` (one leaf appended after the request was built), `recovery_evidence_invalid` (a non-admin key; a v2 revoke namespace instead of the recovery namespace), `recovery_import_invalid` (ops key of another bundle; another installation ID; KRL bytes not matching the digest; KRL header version different from the manifest), `recovery_certificate_invalid` (signed by a key not a CA key of its role; key ID naming another serial), `recovery_certificate_not_lost` (a serial at or below the restored high-water mark; a serial already in the issuance table), `recovery_user_certificate_kept` (a live user certificate without Revoke), `recovery_too_large`, `recovery_version_not_above_import` (an import whose version is ahead of the clock; the error names the seconds to wait) and `duplicate_request`.
      - For every refusal, the state database's log size, root, revocation rows and KRL state are byte-identical before and after.
      - Pending recovery:
        - `recovery_rolls_back_on_publish_failure`: an ops key that fails to sign gives `ops_key_unavailable`, with the database unchanged, and the same request then succeeds once.
        - `recovery_second_run_refused`: the same request after it committed gives `recovery_log_mismatch`.
        - `restart_after_recovery`: New on the recovered database passes, CheckLog passes, a Serve start publishes nothing while the KRL is under an hour old, and republishIfDue an hour later (injected clock) publishes a KRL that still lists every entry not krl.Prunable at its issued_at.
        - `recovered_entries_never_dropped`: TestPublishNeverDropsLiveEntry's pairwise check over the publishes before the snapshot, the recovery's and two later ones.
      - Coverage of every revocation 03-03 writes: `recovers_serial_issued_before_snapshot` (ValidBefore from the restored row, pruned only at ValidBefore + 300), `recovers_serial_issued_after_snapshot` (ValidBefore from the carried certificate), `recovers_serial_without_certificate` (ValidBefore 0, never pruned), `recovers_key_id`, `recovers_explicit_key` (bytes from the KRL; `ssh-keygen -Q` refuses the key and a certificate for it), `recovers_subject_revoke` (its serial entries), `revokes_lost_live_user_certificate`, `keeps_lost_host_certificate` (no entry; `revoke key` of its key afterwards succeeds) and `recovered_login_certificate` (a lost login_issue certificate, kr2).
      - Successive recoveries (PR #66 review): `recovery_after_recovery_vb_zero`: a first recovery carries and revokes a lost user certificate U; its recovered database is the snapshot of a second restore, whose recovery imports a KRL that lists U's serial. The new row has ValidBefore 0, the restored row keeps U's ValidBefore, a publish at an injected clock after U's ValidBefore + 300 still lists U's serial, and audit.Verify accepts the exported log. `recarried_certificate_accepted`: a second restore goes back before the first recovery, and a request that carries U and the kept host certificate H again (as the CLI builds it) succeeds, with U's entries at U's ValidBefore.
    - Audit, `TestVerifyRecovery`:
      - Accepted: `recovery_accepted`.
      - Refused: `recovery_entries_tampered` (an entry dropped), `recovery_entry_vb_tampered` (a lower ValidBefore), `recovery_entry_added_unbound` (an entry no import or certificate gives), `recovery_restored_root_mismatch`, `recovery_restored_size_mismatch`, `recovery_not_admin`, `recovery_other_installation`, `recovery_import_unsigned`, `recovery_import_hash_section`, `recovery_certificate_forged` (signature by another key), `recovery_certificate_already_logged`, `recovery_user_certificate_kept`, `recovery_unpublished_at_end`, `recovery_publish_not_above_import` and `recovery_resolved_after_leaf`.
      - Successive recoveries (PR #66 review): `recovery_after_recovery_vb_zero_accepted` (a second recovery in the same log whose entry for a certificate only the first one carried has ValidBefore 0); `recovery_after_recovery_vb_from_leaf_refused` (the same entry with the ValidBefore taken from the first recovery's carried certificate: refused, because the rule gives 0, so signer, CLI and audit agree); `recovery_carried_not_in_subject_revoke` (a later subject revoke of the user whose lost certificate a recovery carried lists only issued certificates, as the signer's resolution does).
      - `TestVerifyRecoveryExportLines`: the as-exported lines of a recovery verify and carry none of the forbidden keys.
      - `TestRecoveryLeafFitsExportLine` (in internal/audit, which owns the export; tlog's tests cannot import audit): a leaf with a body of exactly MaxRecoveryBody is written with Export's line encoder and read back by Verify's line reader (maxLine) without `token too long`.
      - `TestVerifyCertificatesFrom`: Report.Certificates holds exactly the certificates at or after the index, from the leaf bytes: those of issue and login_issue entries and every certificate a revocation_recovery entry carries, each with its entry's index and kind (`recovery_carried_listed`).
      - `TestVerifyLastKRL`: Report.LastKRL's KRL has the manifest's SHA-256.
    - Server, `TestKRLServedCopy`:
      - `kept_before_served` (the file exists with the served bytes when the first GET answers);
      - `higher_version_replaces`;
      - `equal_identical_no_write`;
      - `lower_version_not_served` (503 and the log line, file unchanged);
      - `equal_version_other_bytes_not_served`;
      - `unverified_not_served` (wrong ops key, wrong installation ID);
      - `write_failure_not_served` (KRLFile in a directory that does not exist, which fails on every platform: 503, nothing cached, served once the directory exists);
      - `corrupt_copy_refuses_start`;
      - `new_requires_krl_file`.
    - CLI, `TestRevokeRecover`:
      - `saved_longer_collects_lost_certificates`;
      - `restored_longer_no_lost_certificates`;
      - `fork_refused`;
      - `export_not_verified_refused` (another trust pin);
      - `server_copy_other_installation_refused`;
      - `user_live_revoked_by_default`;
      - `revoke_lost_names_host`;
      - `revoke_lost_unknown_serial_refused`;
      - `summary_lists_kept_with_key`;
      - `offline_no_server_call` (the config's server URL points at a closed port);
      - `out_exists_refused`;
      - `signed_bytes_verify` (the written file parses and its evidence verifies under the namespace);
      - `installation_id_lost_refused` (restored bundle without an installation ID, saved bundle with one);
      - `krl_given_without_installation_id_refused` (PR #66 review: neither export's bundle has an installation ID, and one --krl document, an ops-signed KRL document of a later bundle with an ID, is given: refused `recovery_installation_lost`, non-zero exit, no --out file, and never `nothing to recover`);
      - `krl_malformed_refused` (a --krl file that is not a KRL document: refused `recovery_import_invalid`, also when neither bundle has an installation ID, so the --krl inputs are read before any decision);
      - `no_installation_id_nothing_to_recover` (neither has one and no --krl document: exit 0, no file);
      - `restore_before_recovery_relists_carried` (PR #66 review: the saved export holds a revocation_recovery entry that carried a kept host certificate H and a revoked user certificate U, and the restored export ends before it: the summary lists H and U again, the request carries both, U with Revoke while live, and the entries for U's serial take U's ValidBefore);
      - `carried_serial_once` (one certificate carried by two revocation_recovery entries of the saved export, and lost with both, is carried once).
  </behavior>
  <read_first>
    - The files written in Task 2; internal/signer/revoke_test.go (TestPublishNeverDropsLiveEntry, TestSubjectResolutionTime's injected clock), internal/signer/krlloop_test.go (TestKRLStartupAndRepublish), internal/audit/verify_test.go (TestVerifyRevocations' log builders), internal/server/revoke_test.go (TestKRLCache, fakeSigner), cmd/keyroster/revoke_test.go (the test admin agent)
    - internal/tlog/fuzz_test.go (FuzzDecodeLeaf's seed loop), internal/wire/fuzz_test.go (FuzzParseRevokeSigningBytes), scripts/fuzz.sh (every Fuzz target runs in CI)
  </read_first>
  <action>Write the tests in `<behavior>` as table-driven tests next to the code and fix what they break. Create the two golden files once with `go test -run '<name>' -update`, read each back (the hex starts with the leaf domain tag for the leaf vector and with the domain tag `keyroster/revoke-recovery/v1` for the request), and commit them. For each refusal of the signer and of audit, run one mutant that removes the check, record that the named test fails with it and passes without it, and list the results in the SUMMARY (at least: the restored-root binding, the user-certificate rule, the ValidBefore rule in RecoveryEntries, the version floor, the server's lower-version refusal). Two more mutants for the PR #66 review fixes: the --krl condition dropped from the `nothing to recover` exit (killed by `krl_given_without_installation_id_refused`), and the revocation_recovery certificates dropped from Report.Certificates (killed by `restore_before_recovery_relists_carried` and `recovery_carried_listed`).</action>
  <verify>
    <automated>go test -count=1 -v -run 'Recovery|Recover|KRLServedCopy|CertificatesFrom|LastKRL' ./internal/tlog/ ./internal/wire/ ./internal/krl/ ./internal/audit/ ./internal/server/ ./cmd/keyroster/</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or a "--- PASS:" line missing for any of TestRecoveryBody, TestRecoveryLeafGoldenVector, TestRecoveryLeafFitsExportLine, TestRecoveryRequestSigningVector, TestRecoveryEntries/range_cap_refused_before_allocation, TestVerifyRecovery/recovery_entry_vb_tampered, TestVerifyRecovery/recovery_restored_root_mismatch, TestVerifyRecovery/recovery_after_recovery_vb_from_leaf_refused, TestVerifyCertificatesFrom/recovery_carried_listed, TestKRLServedCopy/lower_version_not_served, TestKRLServedCopy/write_failure_not_served, TestRevokeRecover/user_live_revoked_by_default, TestRevokeRecover/krl_given_without_installation_id_refused, TestRevokeRecover/restore_before_recovery_relists_carried</fails_when>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestRecoverRevocations|TestRecoveryTracer" ./internal/signer/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or "--- PASS: TestRecoverRevocations/recovery_rolls_back_on_publish_failure", "--- PASS: TestRecoverRevocations/restart_after_recovery", "--- PASS: TestRecoverRevocations/recovered_entries_never_dropped", "--- PASS: TestRecoverRevocations/recovers_explicit_key", "--- PASS: TestRecoverRevocations/recovery_after_recovery_vb_zero" or "--- PASS: TestRecoverRevocations/recarried_certificate_accepted" missing</fails_when>
    <automated>go test -run NONE -fuzz FuzzParseRecoveryRequest -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzParseRecoverySigningBytes -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzDecodeLeaf -fuzztime 20s -fuzzminimizetime 5s ./internal/tlog/</automated>
    <fails_when>non-zero exit, or "FAIL" in the output</fails_when>
  </verify>
  <acceptance_criteria>
    - `git ls-files test/vectors/leaf_revocation_recovery_v1.hex test/vectors/recovery_request_signing_v1.hex` prints both files.
    - Every named case of `<behavior>` appears in the test files (`grep -c` of each name prints at least 1).
    - The SUMMARY records each mutant with the test that killed it.
    - PR #66 review, finding 1: `TestRevokeRecover/krl_given_without_installation_id_refused` passes, and with the --krl condition dropped from the `nothing to recover` exit it fails (the mutant is in the SUMMARY): no supplied server copy is ever skipped by a `nothing to recover` exit.
    - PR #66 review, finding 2: `TestRevokeRecover/restore_before_recovery_relists_carried`, `TestVerifyCertificatesFrom/recovery_carried_listed`, `TestRecoverRevocations/recovery_after_recovery_vb_zero` and `TestVerifyRecovery/recovery_after_recovery_vb_from_leaf_refused` pass: a recovery-carried certificate is listed and carried again when the restore went back before its recovery, and a restore that kept the recovery gives its entries ValidBefore 0 on the signer and in audit alike.
  </acceptance_criteria>
  <done>Every refusal of the recovery is named and tested, the pending-recovery cases leave nothing behind, the server never serves a KRL it did not keep, certificate knowledge survives successive recoveries, and both new parsers are fuzzed.</done>
</task>

<task type="auto">
  <name>Task 4: server-install.md, the full gate, the PR and the SUMMARY (the restore procedure is 03-06c's)</name>
  <files>docs/runbooks/server-install.md</files>
  <read_first>
    - docs/runbooks/server-install.md (the state directory paragraph: "Nothing in it is authority")
    - .planning/phases/03-linux-agent-and-revocation/03-06c-PLAN.md (what the procedure plan takes from this one: both commands' flags, their output lines and refusal names, which its runbook and pins quote)
    - .planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md deviation 8 (the SUMMARY is pushed before the PR opens)
  </read_first>
  <action>
**server-install.md.** The state directory paragraph: the directory also holds krl-served.json, the last KRL document the server served, written before it serves it. Like the rest of the directory it is no authority (every reader verifies it), but it is the restore source for lost revocations (the restore procedure lands with 03-06c). Never delete it, and back it up with the directory. keyroster-server refuses to start when the file does not parse, and its KRL route answers 503 rather than serve a KRL it could not keep, one that does not verify, or one below the version it served. Labelled run in CI (internal/server tests, 03-06b). This lands here, with the code: D-20 puts the operator's text in the PR that changes the server's behaviour, and the start refusal's message points at it.

**What stays for 03-06c (owner decision 2026-10-26, PR #66: split).** docs/runbooks/signer-install.md, docs/runbooks/revoke.md, test/e2e/restore_test.go, test/systemd/smoke.sh and the todo `2026-10-25-plan-signer-restore-revocation-recovery.md` are not touched here. 03-03's stop for a lost revocation stays in force until 03-06c merges. That is fail-safe: a restore that lost a revocation keeps the signer down meanwhile, and no agent pulls a KRL before 03-07, which waits for 03-06c. 03-06c's runbook and pins quote both commands' flags, output lines and refusal names; a change to one of them here is a deviation that the SUMMARY lists for 03-06c.

Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair (the recovery adds no capability: reading standard input and the state database, and the server's file write in a package that already writes its database). A new pair is a deviation to review and record in the SUMMARY. Push.

**The PR.** `scripts/gh-as-bot.sh pr create --title "feat(signer): recover revocations a signer restore lost, from the server's KRL copy and the saved export"`, without enabling auto-merge (the orchestrator enables it after the pre-merge review); wait for the required checks.

**The SUMMARY.** Contents:
- the PR number;
- the line `Lost-certificates answer: revoke-users-list-others`, followed by line 2 of `$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt` copied byte for byte (Task 1);
- the refusal names, and the exact output lines of `keyroster revoke recover` (the summary, `nothing to recover: ...`) and `keyroster-signer recover-revocations` (`recovered: ...`), which 03-06c's runbook quotes;
- the mutant results;
- the CI run IDs;
- capslock;
- `requirements-completed` empty: REVOKE-01 completes in 03-11 and REVOKE-03 in 03-07, as 03-03 recorded.

The SUMMARY is pushed before the PR opens, so it names the branch, as 03-03b's SUMMARY records (deviation 8). D-20: this plan changes no step of the operator's restore; 03-06c carries signer-install.md's change. Then the tracking updates once, `docs(03-06b): complete restore-recovery plan`, push and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>git push origin p03/06b-restore-recovery && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/06b-restore-recovery && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/06b-restore-recovery --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit, or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestRestoreRecoveryTracer", "--- PASS: TestRevokeSerialEndToEnd", "--- PASS: TestRestoreRunbookChecks" or "--- PASS: TestRestoreReplaysLostDirectory", or reports any e2e test as FAIL</fails_when>
    <automated>git fetch origin main && git diff --quiet "$(git merge-base HEAD origin/main)" -- docs/runbooks/signer-install.md docs/runbooks/revoke.md test/e2e/restore_test.go test/systemd/smoke.sh && test -e .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md && test ! -e .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md</automated>
    <fails_when>non-zero exit (a file that 03-06c owns was changed here, or the todo moved before 03-06c)</fails_when>
    <automated>git fetch origin p03/06b-restore-recovery && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && grep -qx 'Lost-certificates answer: revoke-users-list-others' .planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md && grep -qxF "$(sed -n 2p "$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt")" .planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY is not on the pushed branch, local commits are unpushed, or the SUMMARY lacks the answer line or the owner's verbatim wording)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/06b-restore-recovery --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'krl-served.json' docs/runbooks/server-install.md` prints at least 1, and `tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -c 'run in CI (internal/server tests, 03-06b)'` prints at least 1.
    - 03-03's stop is still in force: `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'the restore lost a revocation: do not release the hold'` prints at least 1, and this branch leaves signer-install.md, revoke.md, restore_test.go and smoke.sh unchanged (compared with its merge base with origin/main, so a change that lands on main meanwhile does not count).
    - 03-06b-SUMMARY.md carries the exact line `Lost-certificates answer: revoke-users-list-others` and line 2 of r06b-lost-certs-answer.txt verbatim.
    - The PR is open without auto-merge (the orchestrator enables it after the pre-merge review), every required check green, 03-06b-SUMMARY.md on its head, the todo still in pending/.
  </acceptance_criteria>
  <done>The recovery code is complete, tested and documented for the server; the PR waits green; the restore procedure that uses it is next, in 03-06c.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — owner approves PR p03/06b-restore-recovery, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews (security code: full review) and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/06b-restore-recovery --web`; review code, 03-06b-SUMMARY.md and server-install.md, especially that lost certificates follow your Task 1 answer, that `keyroster-signer recover-revocations` never starts Serve, and that `nothing to recover` never skips a supplied server copy. The restore runbook is 03-06c's PR.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/06b-restore-recovery` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/06b-restore-recovery</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-06c's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/06b-restore-recovery --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The recovery code is on main, and 03-06c may start; 03-07 waits for 03-06c.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Edge Coverage (spec-less fallback, this plan)

This plan authors REVOKE-03 rollback (a restored, older revocation state never reaches hosts) as truths.

**Flagged assumption, the durable copy.** Assumed: keyroster-server is the only path by which a KRL reaches hosts, so the last KRL it served is a superset of the live entries of any KRL a host holds. 03-03's no-drop property covers intact rows, and hosts accept only increasing versions from 03-07 on. A KRL installed on a host by hand from another source is outside this. 03-07's agent route must use currentKRL (cross-plan note). The hold stops keyroster-server, which freezes the copy (03-06c's runbook). A release without the recovery breaks the procedure, and the copy would then be replaced by the restored signer's higher version (T-03-271).

**Flagged assumption, ValidBefore of imported entries.** Assumed: a certificate is identified by its serial under one CA key (the serial is the issuance table's primary key, and serials are microsecond timestamps that only rise, also across a restore once the clock check passed), and a key ID names exactly the certificate whose serial it carries (D-09). Entries whose certificate neither the restored log nor the saved export holds keep ValidBefore 0 and never leave the KRL (T-03-269). So do the entries of a certificate that the restored log knows only from an earlier revocation_recovery entry, because the lookup is the issuance alone (PR #66 review; fail-safe, T-03-269). A certificate an earlier recovery carried that the restore lost again is carried again from the saved export, with its ValidBefore (T-03-272).

**Flagged assumption, no restored signer logs before the recovery.** A restored signer that logged anything first is refused by `recovery_log_mismatch`, as step 2 refuses a fork. The runbook rule that no restore starts the signer before the recovery is 03-06c's.

**Flagged assumption, the installation ID.** A restore to a bundle without an installation ID is recoverable (`nothing to recover`) only when the saved export's bundle has none either and no server KRL copy is given. In that case no KRL was ever published. Otherwise `recovery_installation_lost` keeps the hold: a server copy is proof that a bundle with an ID was in force, because no KRL is published without one and no successor bundle drops it (PR #66 review). The homelab's path to an ID is 03-15's v4 bundle, and a restore across that ceremony is escalated (cross-plan note in 03-15-PLAN.md).

**Lost certificates (owner's Task 1 answer).** Certificates issued after the latest saved export are unknown under every answer and expire by their TTL (T-03-272).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Lost revocations never reach hosts; access revoked centrally stays revoked after a signer restore | Tasks 2-3 (the code); the restore procedure that runs it is 03-06c's |
| REQ | REVOKE-01 (lost revocations, key IDs and certificates stay revoked or revocable) | Tasks 1, 2, 3 |
| REQ | REVOKE-03 (no rollback of the revocation state; the recovery's version is above every import) | Tasks 2, 3; the release only after the recovery is 03-06c's |
| CONTEXT | D-04 (installation ID in the request, the imports and the server's check) | Task 2 |
| CONTEXT | D-09 (a key ID names one certificate: ValidBefore of key-ID entries) | Task 2 |
| CONTEXT | D-10 (hosts keep their last KRL; the hourly publish after a recovery keeps the union; never lock out) | Tasks 2, 3 |
| CONTEXT | D-20 (the operator's text in the PR that changes the step, run or UNVERIFIED) | Task 4: server-install.md with the server's new file and refusals. signer-install.md and revoke.md change with 03-06c, which changes the operator's restore steps; this plan changes none of them |
| Owner decisions | Q1 time-derived krl_version; Q2 own plan before 03-07; v2 installation-bound requests (T-03-210); key ID only for issued key IDs and explicit-key caps (T-03-211); 2026-10-26 (PR #66): the lost-certificates answer `revoke-users-list-others` and the split into this plan and 03-06c | Tasks 1, 2, 3 (the recorded answer; version floor; RecoveryEntries ValidBefore; no new key-ID path; caps counted by later revokes); the split: this file and 03-06c-PLAN.md |
| Todo points 1-11 | See the ledger below | Ledger |
| RESEARCH | No 03-RESEARCH item is specific to restores; its KRL encoder and pruning rules are reused unchanged | Task 2 |
| Review | PR #66 Codex docs review (2026-10-26): the --krl documents before `nothing to recover`; certificate knowledge across successive recoveries | Tasks 2, 3 (ledger, round 1) |

## Artifacts this phase produces (this plan)

- tlog: `KindRevocationRecovery` 15 (`revocation_recovery`), `RecoveryBody`, `DecodeRecoveryBody`, `MaxRecoveryEntries` (1 << 16), `MaxRecoveryBody` (11 MiB); Kind validity is an explicit set.
- wire: `RecoveryRequestDomain` = `RecoverySSHSIGNamespace` = `keyroster/revoke-recovery/v1`, `RecoveryRequest`, `RecoveryImport`, `RecoveredCertificate`, `ParseRecoveryRequest`, `ParseRecoverySigningBytes`, `MaxRecoveryRequest` (9 MiB), `MaxRecoveryImports` (4), `MaxRecoveryKRL`, `MaxRecoveryCertificates` (4096), `MaxRecoveryCert`; fuzz targets `FuzzParseRecoveryRequest`, `FuzzParseRecoverySigningBytes`.
- krl: `RecoveryEntries`, `RecoveredCert`, `CertLookup`, `ErrRecoveryTooLarge`.
- signer: `RecoverRevocations`, `RecoveryResult`; refusals `recovery_malformed`, `recovery_installation_mismatch`, `recovery_log_mismatch`, `recovery_evidence_invalid`, `recovery_import_invalid`, `recovery_certificate_invalid`, `recovery_certificate_not_lost`, `recovery_user_certificate_kept`, `recovery_too_large`, `recovery_version_not_above_import`; kind 15 in the start-up rebuild and pendingRevoked.
- audit: `verifyRecovery`, `Options.CertificatesFrom`, `Report.Certificates`, `Report.LastKRL`, `Report.Bundle`, `Report.Recoveries`; export fields `restored_size`, `imports`, `import_krl_versions`, `certificates`, `certificates_revoked`, `entries`, `admins`.
- server: `Config.KRLFile`, `<state-dir>/krl-served.json` (the last KRL document served, kept before it is served).
- CLI: `keyroster revoke recover` (refusals `recovery_installation_lost`, also when a --krl document is given under a restored bundle without an installation ID, `recovery_import_invalid` for a --krl document that does not decode or verify, and the fork of the prefix rule; `nothing to recover` only when neither bundle has an installation ID and no --krl document is given); `keyroster-signer recover-revocations`.
- Tests and vectors: `TestRecoveryTracer`, `TestRestoreRecoveryTracer`, `TestRecoverRevocations` (with `recovery_after_recovery_vb_zero` and `recarried_certificate_accepted`), `TestVerifyCertificatesFrom/recovery_carried_listed`, `TestRevokeRecover/krl_given_without_installation_id_refused` and `/restore_before_recovery_relists_carried`, `TestRecoveryEntries`, `TestVerifyRecovery`, `TestKRLServedCopy`, `TestRevokeRecover`, `TestRecoveryLeafFitsExportLine`, `test/vectors/leaf_revocation_recovery_v1.hex`, `test/vectors/recovery_request_signing_v1.hex`.
- Runbook: server-install.md's paragraph on krl-served.json. The restore runbook (signer-install.md's capture block and step 2b), its pins, smoke.sh and TestRestoreRecoversLostRevocations are 03-06c's.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| restored signer state → hosts | A restored, older revocation table must never be published as the newest KRL |
| keyroster-server's copy → recovery | The copy is no authority: every import is verified under the ops key and installation ID of the bundle in force |
| saved export → admin CLI → signed request | Only verified leaf bytes are read; the admin signs what the root-pinned CLI verified |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-265 | Elevation of privilege | a signer restore that drops revocations, including ones newer than the latest saved export (un-revoke on every host) | high | mitigate | Split with 03-06c (owner decision 2026-10-26, PR #66); this plan's share is the code, 03-06c's the runbook that runs it under the hold before the release. The recovery imports keyroster-server's krl-served.json (kept before every serve) and the saved export's last KRL, re-derived by audit verify, in one transaction with one publish whose version is above every import. TestRecoverRevocations' coverage cases and TestRestoreRecoveryTracer cover serial (before and after the snapshot), key ID, key, subject and a revocation after the saved export; the drill with sshd is 03-06c's. A restore that lost the bundle adding the installation ID is refused (`recovery_installation_lost`), also when a server copy is given while neither export's bundle has an ID, so `nothing to recover` never skips a served KRL and the hold stays (PR #66 review; `krl_given_without_installation_id_refused`). Until 03-06c merges, 03-03's stop stands: a restore that lost a revocation keeps the signer down, and T-03-207's residual is unchanged. **Accepted residual (with 03-06c):** a restore that also loses the server's state directory (a co-located VM lost for good) imports only the saved export, so revocations after it stay lost; the rule "take a saved export after every revocation" stays for that case |
| T-03-266 | Tampering | a recovery request applied to another installation, another restored state, or twice | low | mitigate | The request names the installation ID and the restored log's size and root, and the signer refuses `recovery_installation_mismatch` or `recovery_log_mismatch`. Its request ID goes into revoke_request (`duplicate_request`). Audit checks the size and root against the log at that index (`recovery_restored_root_mismatch`) |
| T-03-267 | Spoofing | a recovery by someone without an admin key, or with an import or certificate not of this installation | medium | mitigate | admin-sshsig/v1 by a policy admin under keyroster/revoke-recovery/v1 (`recovery_evidence_invalid`, audit `recovery_not_admin`). Imports must verify under the ops key of the bundle in force and its installation ID (`recovery_import_invalid`). Certificates must verify under a CA key of their role in the bundle in force (`recovery_certificate_invalid`, audit `recovery_certificate_forged`) |
| T-03-268 | Elevation of privilege | early pruning through a ValidBefore the recovery invents (un-revoke once pruned) | high | mitigate | krl.RecoveryEntries takes ValidBefore only from a certificate with the same CA key and serial, or the serial a key ID names with an equal key ID; else 0, never pruned. Signer and audit share it; audit re-derives the listed entries (`recovery_entry_vb_tampered`); `recovered_entries_never_dropped` |
| T-03-269 | Denial of service | imported entries without a known certificate stay in the KRL for good, and a huge import exhausts memory | medium | accept | Expansion is counted before allocation (`range_cap_refused_before_allocation`); MaxRecoveryEntries and MaxRecoveryBody give `recovery_too_large`; a KRL above MaxKRL is `krl_too_large` and rolls the recovery back. **Accepted residual:** entries whose certificates neither the restored log nor the saved export holds never leave the KRL. **Accepted residual, successive recoveries (PR #66 review):** a later restore that keeps an earlier recovery imports that recovery's entries again, and a certificate the restored log knows only from that recovery's entry is not in the issuance lookup, so the new row gets ValidBefore 0 and keeps the entry listed for good, while the restored rows of the earlier recovery keep its ValidBefore. This is the fail-safe outcome: over-revocation of a certificate already revoked, never an un-revocation; the cost is one KRL entry per such certificate, bounded by the certificates earlier recoveries carried (at most 4096 each). Taking the ValidBefore from the earlier leaf would add a second certificate source to the signer's start-up rebuild, audit and the CLI, with a parse path that can stop the signer from starting (`recovery_after_recovery_vb_zero`, `recovery_after_recovery_vb_from_leaf_refused`). The remedy for a full KRL is 03-13's CA replacement, as for `krl_too_large` today |
| T-03-270 | Denial of service | keyroster-server refuses to serve a KRL it cannot keep (disk full, read-only state directory) | low | accept | Fail-safe for completeness: a KRL that is not durable is never served, the route answers 503 and logs why, and hosts keep their last KRL and never lock out (D-10). A revocation's CLI check then fails visibly; agents alert at 24 h (03-08). `write_failure_not_served` |
| T-03-271 | Tampering | the server's copy replaced by a restored signer's KRL that a release without the recovery published (higher time-derived version, entries missing) | medium | mitigate | Split with 03-06c (PR #66). This plan's share: the server never serves a version below the one it served, nor the same version with other bytes (`lower_version_not_served`), and it writes the copy before it serves. 03-06c's share: the runbook keeps a copy right after the hold, before the file restore (position pinned in TestRestoreRunbookChecks). **Residual:** a release without the recovery breaks the procedure; the copy taken under the hold is the evidence |
| T-03-272 | Repudiation | lost certificates still valid that the restored signer does not know (todo point 5) | medium | mitigate | Owner's answer `revoke-users-list-others` (2026-10-26, Task 1): the recovery carries every lost certificate from the verified saved export, revokes every lost user certificate live at its resolution time (enforced by signer and audit, `recovery_user_certificate_kept`), and lists host and machine certificates, which the admin revokes by naming them. Kept ones stay visible in the log and are revoked by key later (`keeps_lost_host_certificate`). A certificate an earlier recovery carried is carried again when a later restore goes back before that recovery, so a kept one never drops out of the log or the summary (PR #66 review; `restore_before_recovery_relists_carried`, `recovery_carried_listed`). **Accepted residual:** certificates issued after the latest saved export are unknown and expire by their TTL |
| T-03-273 | Denial of service | a recovery KRL that hosts ignore because its version is not above an imported version (a clock that ran ahead, a same-second burst) | low | mitigate | The signer refuses `recovery_version_not_above_import` with the seconds to wait. Audit refuses a publish after a recovery that is not above every import (`recovery_publish_not_above_import`). The clock check before the recovery is the runbook's, 03-06c's share (T-03-208) |
| T-03-274 | Elevation of privilege | root following a link planted by the admin or the server account during the runbook's copies | low | mitigate | Moved to 03-06c with the runbook's copy blocks (owner decision 2026-10-26, PR #66: split); this plan writes no runbook block |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; the recovery reuses x/crypto/ssh, cryptobyte and the in-house krl, tlog and sshsig packages; capslock baseline unchanged |
</threat_model>

<verification>
- Every verify command passes, including both CI e2e lanes, the fuzz runs and the required checks; the merge gate passes.
</verification>

<success_criteria>
- The recovery exists and is proven in code: keyroster-server keeps every KRL it serves, and the two offline commands bring a restored signer back with every revocation hosts could have seen. That covers revocations newer than the saved export, while keyroster-server's state survives. The restored signer's first KRL lists every lost entry and is above every version hosts hold. Nothing un-revokes, lost live user certificates are revoked, a kept certificate stays in the log across successive recoveries, `nothing to recover` never skips a server copy, and `keyroster audit verify` re-derives the recovery from the log. 03-06c puts it into the restore runbook; until then 03-03's stop stands.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md` in Task 4, before the merge gate. It carries the exact line `Lost-certificates answer: revoke-users-list-others` and, below it, line 2 of r06b-lost-certs-answer.txt verbatim (Task 1), plus both commands' output lines and refusal names for 03-06c. `requirements-completed` is empty (REVOKE-01 completes in 03-11, REVOKE-03 in 03-07). Never record merge facts.
</output>

## Review Dispositions Ledger

Moved to 03-06c-PLAN.md on the split (owner decision 2026-10-26, PR #66), with their history: the todo "Costs" row on the runbook, restoreSavedGreps and TestRestoreRunbookChecks, the todo "Closing" row, and the deferred row on hardening the signer restore runbook. Split rows stay here with a "Since the split" note and have a copy there.

### Round 0 — sources (todo 2026-10-25, the 03-03 plan check's Q2 rows, the PR #61 pre-merge review)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Todo point 1 (03-03 plan check, both skeptics): a serial RevokedEntry carries no key ID or key, and `revoke serial` refuses a serial whose issuance the restore lost | HIGH | Task 2: lost serials come from the imported KRL's certificate sections under their CA key, with no issuance lookup; ValidBefore from a certificate when known (krl.RecoveryEntries). `recovers_serial_without_certificate`, `recovers_serial_issued_after_snapshot` |
| Todo point 2: issue and login_issue decoded fields are not bound by audit verify, collide with revoke fields, and are JSON-escaped | HIGH | Task 2: nothing reads a decoded field. The CLI takes certificates from verified leaf bytes (Report.Certificates) and the saved KRL from the re-derived KRL (Report.LastKRL). `TestVerifyCertificatesFrom` |
| Todo point 3: a lost `revoke key` cannot be rebuilt from the export (fingerprint only) | HIGH | Task 2: the imported KRL carries the explicit keys' bytes. `recovers_explicit_key` with `ssh-keygen -Q` |
| Todo point 4: replaying one revocation at a time publishes N−1 unsafe intermediate KRLs | HIGH | Task 2: one transaction, one leaf, one publish, offline under the hold. The drill asserts no krl_publish between the restored log's end and the recovery. Since the split (owner decision 2026-10-26, PR #66): the one transaction, leaf and publish stay here; the drill's assertion is 03-06c's TestRestoreRecoversLostRevocations (row there). |
| Todo point 5: lost but still valid certificates | MEDIUM | Owner decision in Task 1 (recommended `revoke-users-list-others`); T-03-272. Answered by the owner on 2026-10-26 (PR #66): `revoke-users-list-others`; Task 1 is pre-answered (round 1). |
| Todo point 6: revocations newer than the saved export are in neither file (T-03-207 residual) | HIGH | Task 2: keyroster-server's durable krl-served.json, kept before it serves and frozen by the hold; Task 4: the runbook copies it right after the hold. T-03-265 (residual narrowed to a lost server state). Since the split (owner decision 2026-10-26, PR #66): the server's copy and server-install.md stay here; the runbook's capture block right after the hold is 03-06c's (row there). |
| Todo point 7 (codex medium): 03-10's negative-probe revocations, their host and key provenance, a renewal after recovery | MEDIUM | Contract here: the recovery imports every explicit key (the probe key included) and carries every lost certificate (the probe certificate names the host and key). Cross-plan note in 03-10-PLAN.md: its renewal exception also accepts a probe key whose revocation row comes from a revocation_recovery entry carrying this host's probe certificate for that key. Its probe kind joins audit's certificate collection, and the drill gains "installed negative-probe key, restore, recovery, successful renewal". It cannot be built before 03-10. Since the split (owner decision 2026-10-26, PR #66): the drill that 03-10 extends is 03-06c's TestRestoreRecoversLostRevocations, and 03-10-PLAN.md's note names it. |
| Todo point 8 (split): 03-13's start-up publish after an ops-key rotation must respect a pending recovery | MEDIUM | Contract here: the pending recovery is the hold, and the recovery precedes the first start. An import under an ops key the restored bundle does not name is refused (fail-closed: the hold stays). Replaying the lost bundle first cannot work as the recovery is bound now: install-bundle appends a bundle_install entry, so the restored size and root change. Cross-plan note in 03-13-PLAN.md: making that case recoverable is 03-13's design. It can either bind the recovery to the log after a replayed bundle, or carry and chain-check the successor bundle in the request. install-bundle never publishes, and 03-13's start-up publish runs only at the first start after the release, building from every row, the recovered ones included. Since the split (owner decision 2026-10-26, PR #66): signer-install.md's step 2b, whose escalation 03-12 and 03-13 update, is 03-06c's, and their notes name it. |
| Planner self-check before the PR: a restored bundle without an installation ID whose saved export's bundle has one (a lost bundle added the ID, as 03-15's v4 bundle will on the homelab) would have released the hold and published without the lost revocations | HIGH | Task 2: `keyroster revoke recover` refuses `recovery_installation_lost`, and prints `nothing to recover` only when neither bundle has an ID. Task 4: the runbook keeps the hold for the first and releases for the second. Task 3: `installation_id_lost_refused` and `no_installation_id_nothing_to_recover`. Edge Coverage line; cross-plan note in 03-15-PLAN.md. Since the split (owner decision 2026-10-26, PR #66): the CLI half stays here (widened in round 1: a --krl document under a restored bundle without an ID is refused too); the runbook half is 03-06c's (row there). |
| Todo point 9: a new leaf kind must not collide with 11-14 (03-09..03-12) | LOW | Task 2: kind 15; Kind validity is a set. Cross-plan notes in 03-09..03-12-PLAN.md say each adds its kind to the set |
| Todo point 10: the round-5 floor is moot under Q1 | — | No floor and no exported krl_version read. The only version rule added is "the publish after a recovery is above every import", which the signer and audit both check |
| Todo point 11 (PR #61, owner decision 2026-10-26): a key ID whose issuance the restore lost cannot be revoked by key ID | MEDIUM | Lost key-ID entries come back from the imported KRL (0x23 under their CA key). The lost certificates themselves follow the Task 1 answer: user certificates are revoked by serial, so their key IDs need no revocation; kept host and machine certificates are revoked by key (summary prints the key). No new key-ID path is opened, so T-03-211 holds |
| Todo "Costs": size (MaxRequest 64 KiB, MaxKRL 4 MiB), a dedicated leaf body with a golden vector | MEDIUM | Task 2: offline, so no frame limit; kind 15 body with its own caps; Task 3: `leaf_revocation_recovery_v1.hex`, `TestRecoveryLeafFitsExportLine` |
| Todo "Costs": the audit rule (ops-key signature, installation ID, version, union equality) | HIGH | Task 2 verifyRecovery and the publish floor; Task 3 `TestVerifyRecovery` |
| Todo drill (five cases, publish assertion, ssh-keygen and sshd, restart while pending) | HIGH | Task 4 TestRestoreRecoversLostRevocations; Task 3 the transaction-level pending cases (`recovery_rolls_back_on_publish_failure`, `recovery_second_run_refused`, `restart_after_recovery`); the negative probe through 03-10's note. Since the split (owner decision 2026-10-26, PR #66): the transaction-level cases stay here (Task 3); TestRestoreRecoversLostRevocations moved to 03-06c (row there). |
| 03-03 Round 2 Deferred, Q2 rows (codex high: replay material; restore-replay highs; drill coverage mediums) | HIGH | As points 1-4 and the drill above (the drill: 03-06c since the split, PR #66) |
| 03-03 Round 2 Deferred, codex medium: negative-probe revocations left out | MEDIUM | As point 7 |
| 03-03 Round 2 Deferred, split codex medium: 03-13's start-up publish and the restore hold | MEDIUM | As point 8 |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| An agent's accepted KRL as a further import source | Not available before 03-07, which this plan precedes. The import takes any ops-signed KRL document, so a later plan can add the agent's accepted triple without a format change. Nothing here builds or documents it (no unexercised path) |
| The signer checks issuance rows against its log (todo 2026-10-26, Phase 4) | Out of scope. The recovery's lookup reads the issuance table as subject revocation does, and a row edited outside the signer can only give an entry ValidBefore 0 (never pruned) or a ValidBefore that audit's re-derivation from the log refuses |

### Round 1 — PR #66 Codex docs review and owner decisions (2026-10-26)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Codex docs review, high, upheld by a skeptic as medium (PR #66): `keyroster revoke recover` decided `nothing to recover` from the two exports alone and exited 0 before the --krl documents were read, so a server copy served under a later bundle with an installation ID could be skipped and the hold released without its revocations | HIGH | Task 2 CLI: every input, the --krl documents included, is read and decoded first (step 1); `recovery_installation_lost` also when a --krl document is given under a restored bundle without an installation ID (step 4), because a KRL is published only under a bundle with one and no successor drops it; `nothing to recover` only when neither bundle has an ID and no --krl document is given; the --krl documents are verified in step 5. must_haves truth, Edge Coverage, Artifacts, T-03-265. Task 3: `krl_given_without_installation_id_refused`, `krl_malformed_refused`, a mutant (the --krl condition dropped) and an acceptance criterion. The runbook half (no release after `nothing to recover` when a copy was captured) is 03-06c's (row there) |
| Codex docs review, medium, upheld by a skeptic as low (PR #66): successive recoveries lost certificate knowledge. ValidBefore came only from the issuance lookup and Report.Certificates held only issue and login_issue certificates, so a certificate known only from an earlier recovery's entry got ValidBefore 0 for good; while fixing it, the planner also found that a kept host or machine certificate dropped out of the log and the summary when a later restore went back before that recovery | MEDIUM | Collection, fixed: audit's Report.Certificates also holds every certificate a revocation_recovery entry carries, and the CLI carries those after the restored size again, one per serial, so a kept certificate stays visible and a re-carried certificate's entries keep its ValidBefore (Task 2 audit and CLI; Task 3 `restore_before_recovery_relists_carried`, `carried_serial_once`, `recovery_carried_listed`, `recarried_certificate_accepted`; must_haves truth; T-03-272). Lookup, the fail-safe option kept: it stays the issuance alone in signer, audit and CLI, so a restore that kept the earlier recovery gives the new rows ValidBefore 0. Task 2 and T-03-269 state why that is the intended outcome (over-revocation of an already revoked certificate, never an un-revocation; one entry per such certificate; a second certificate source in the start-up rebuild would be a new way for the signer to refuse to start). Task 3: `recovery_after_recovery_vb_zero`, `recovery_after_recovery_vb_zero_accepted`, `recovery_after_recovery_vb_from_leaf_refused`, `recovery_carried_not_in_subject_revoke`, a mutant and two acceptance criteria |
| Owner decision (Daniel, 2026-10-26, PR #66): lost certificates that are still valid = `revoke-users-list-others`, recorded in `$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt` (line 1 the id, line 2 the owner's verbatim wording, line 3 Claude's description) | — | Task 1 is pre-answered: it checks the file (line 1 exactly the id, line 2 present) and carries the line `Lost-certificates answer: revoke-users-list-others` with line 2 verbatim into the SUMMARY (Task 4 verify and acceptance); the executor does not ask again, and the branch for other answers is gone (an unexpected file fails the precondition). Deviation from "keep Task 1 as the decision checkpoint": the task keeps its place and its decision, context and options as the record, with the chosen option marked, but is typed `auto`, because every `checkpoint:*` task stops the executor in standard mode (gsd-executor.md, execute_tasks step 3; `workflow.auto_advance` is false), which would put the question to the owner again |
| Owner decision (Daniel, 2026-10-26, PR #66): split the plan into the code (this plan) and the procedure (03-06c), 03-06c right after it, 03-03's stop in force until 03-06c merges, 03-07's gate on 03-06c's SUMMARY | — | This file: frontmatter (28 files, estimate 145k), objective, Budget Exception (accepted by the owner on 2026-10-26, PR #66), must_haves (the restore-step and drill truths moved, a no-restore-step truth added, the prohibition's procedure half moved), context, Task 4 re-scoped to server-install.md, the full gate, the PR and the SUMMARY (signer-install.md, revoke.md, restore_test.go, smoke.sh and the todo must equal origin/main), Edge Coverage, Source Coverage Audit, Artifacts; T-03-274 moved, T-03-265, T-03-271 and T-03-273 split. New 03-06c-PLAN.md: signer-install.md step 2b in place of 03-03's stop and the clock check before it, revoke.md, TestRestoreRecoversLostRevocations, the restore_test.go pins, smoke.sh and the todo's move (5 files plus the todo, about 55k), with the moved ledger rows. 03-07: depends on 03-06c, and its Task 1 precondition checks 03-06c's SUMMARY and the todo in completed/ on origin/main; waves 03-06c = 8 and 03-07 to 03-16 = 9 to 18; ROADMAP and STATE count 19 plans. Cross-plan notes in 03-10, 03-12 and 03-13 name 03-06c for the drill and step 2b. Placed here, not in 03-06c: server-install.md's paragraph on krl-served.json (D-20, with the server change) |
| Planner, split (PR #66): revoke.md goes to 03-06c with the runbook, as the owner listed, although its section 6 describes the server's copy and the 503 this plan ships | LOW | D-20 interim, accepted: this plan changes no step an operator performs in revoke.md; server-install.md here describes the new file, the start refusal and the 503; 03-06c, which merges right after this plan, writes revoke.md section 6 (row there) |
