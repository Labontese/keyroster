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
  - test/e2e/restore_test.go
  - test/systemd/smoke.sh
  - test/vectors/leaf_revocation_recovery_v1.hex
  - test/vectors/recovery_request_signing_v1.hex
  - docs/runbooks/signer-install.md
  - docs/runbooks/revoke.md
  - docs/runbooks/server-install.md
  - .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md
  - .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md
autonomous: false
requirements: [REVOKE-01, REVOKE-03]

estimate:
  tokens: 195000
  raw_tokens: 195000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decision 2026-10-25 (03-03 plan check, Q2): recovery of the revocations a signer restore lost is this plan, merged before 03-07; 03-07's Task 1 precondition checks this plan's SUMMARY on origin/main. The owner's direction is kept: the newest ops-signed KRL that keyroster-server served is imported as a union with the saved export's lost entries, in one admin-signed transaction, with one publish"
    - "keyroster-server keeps a durable copy of every KRL it serves: before GET /api/v1/krl (or any later route, 03-07's agent state included) serves a KRL document, refreshKRL verifies it with krl.VerifyManifest against the bundle of the status in force and that bundle's installation ID, and writes the exact serverclient.KRLDocument JSON to `<state-dir>/krl-served.json` (temporary file, fsync, rename, directory fsync, mode 0600). The copy is never replaced by a lower or equal version. A document it could not write, one that does not verify, one below the version it served before, and one with the served version but other bytes are never served: the route answers 503 and logs the reason, and hosts keep their last KRL (D-10). keyroster-server refuses to start when the copy exists and does not parse"
    - "Every signer restore runs the recovery before the hold is released, whatever step 2's counts show: right after the hold, the operator keeps a copy of the server's krl-served.json (taken as keyroster-server); after step 2's checks and the clock check, an admin runs `keyroster revoke recover` and the operator runs `keyroster-signer recover-revocations` under the hold; only then is the hold released. The restored signer therefore never publishes a KRL that lacks a lost entry: its first publish after the restore is the recovery's"
    - "`keyroster revoke recover --restored FILE --saved FILE [--krl FILE ...] [--revoke-lost SERIAL ...] [--yes] [--admin-key FP] --out FILE` runs offline (no server call) as a policy admin: it verifies both exports on the CLI config's trust pins and threshold (audit.Verify), requires one to be a prefix of the other (the --previous rule), re-derives the saved export's last KRL document (Report.LastKRL), verifies every --krl document with krl.VerifyManifest under the restored export's bundle in force and installation ID, reads every lost certificate from the verified leaf bytes of the saved export's issue and login_issue entries after the restored log (Report.Certificates; never from the decoded fields), refuses `recovery_installation_lost` when the restored bundle has no installation ID but the saved export's has one, applies the owner's lost-certificate answer (Task 1), prints a summary, and signs one wire.RecoveryRequest under keyroster/revoke-recovery/v1 that names the installation and the restored log's size and root"
    - "`keyroster-signer recover-revocations --state-dir DIR` reads the signed request from standard input, takes the state lock, opens the signer with every start-up check (signer.New, no Serve) and in ONE transaction appends one revocation_recovery entry (leaf kind 15) listing the derived entries, writes one revocation row per entry and the request ID, and publishes one KRL; on any refusal or failure nothing is written. It refuses a request for another installation, for another log than exactly its own (size and root), without a policy-admin SSHSIG of the policy in force, with an import that does not verify under the bundle in force or holds key-hash sections, with a certificate that is not signed by a CA key of its role in the bundle in force, whose key ID does not name its serial, or whose serial is not above the restored serial high-water mark, with a used request ID, above MaxRecoveryEntries or the body cap (`recovery_too_large`), and when the publish's version would not be above every imported version (`recovery_version_not_above_import`, with the seconds to wait)"
    - "One rule derives a recovery's entries, used by the signer and by audit verify: krl.RecoveryEntries returns, in canonical order and without duplicates, every serial (ranges expanded, capped before allocation), key ID and explicit key of every import, plus one serial entry for each carried certificate marked revoke. A serial entry's ValidBefore is that of the certificate with the same serial and CA key, found in the restored issuance (signer: the issuance table; audit: the log's issue and login_issue entries) or among the request's certificates; a key-ID entry's comes from the certificate whose serial its key ID names (D-09: a key ID names one certificate) and whose key ID equals it; otherwise 0, which krl.Prunable never prunes. So the recovery only adds entries and never prunes one early"
    - "Owner decision 2026-10-25 (03-03 plan check, Q1) holds through the recovery: its publish takes krl_version = max(prev + 1, issued_at) like every publish, and audit verify additionally requires the krl_publish right after a revocation_recovery entry to be above every imported KRL version, so every host that saw a lost version accepts it"
    - "The signer's start-up check accepts a recovered database: rebuildLogFrom and appendLocked add a revocation_recovery entry's listed entries to the logged revocation multiset, so `revocations_not_logged` never fires after a recovery, at start, in doctor or at a publish; a restart after the recovery publishes nothing at start while the KRL is under an hour old, and every later publish keeps the union (TestPublishNeverDropsLiveEntry's property across a recovery)"
    - "`keyroster audit verify` checks kind 15: the request parses strictly (wire.ParseRecoverySigningBytes), names the bundle's installation, its restored size equals the entry's index and its restored root equals the root of the entries before it, its evidence is admin-sshsig/v1 by at least one admin of the policy in force under keyroster/revoke-recovery/v1, ResolvedAtSeconds × 10^6 is not after the leaf time, every import verifies (krl.VerifyManifest, krl.Parse, the KRL header version equals the manifest's, no key-hash section), every carried certificate verifies under a CA key of its role and is new to the log with a serial above its high-water mark, the owner's lost-certificate rule holds at ResolvedAtSeconds, the listed entries equal krl.RecoveryEntries over the log's certificates, and the next entry is its krl_publish, above every imported version; the export renders the kind with no `kind`, `bundle_version`, `version`, `directory` or `sigs` key of its own and never the KRL bytes"
    - "Leaf kind 15 `revocation_recovery` joins format v1 before kinds 11 to 14 exist, so tlog's Kind validity becomes an explicit set (1 to 10 and 15); 03-09 to 03-12 add 11 to 14 to that set (cross-plan notes added with this plan)"
    - "Every revocation 03-03 and 03-03b can write is recovered: serial (certificate issued before or after the snapshot), key ID, explicit key (the KRL carries the key bytes) and subject (its serial entries), including a revocation made after the latest saved export whose KRL keyroster-server served; TestRestoreRecoversLostRevocations proves each on CI e2e with `ssh-keygen -Q` and sshd, proves that no krl_publish lies between the restored log's end and the recovery, and runs the pending-recovery cases (refused while another process holds the lock, a refused attempt writes nothing, a re-run succeeds once, a second run is refused, a restart keeps the union)"
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
    - statement: "After a signer restore, no KRL is published before the recovery commits, and the recovery never removes, shortens or replaces an entry: every restored revocation row stays, every imported entry is added, and an entry's ValidBefore comes only from a certificate with the same CA key and serial (or the serial its key ID names), else it is 0 and never pruned"
      status: resolved
      verification: test
---

<objective>
Recover the revocations that a signer restore lost, before agents start pulling KRLs in 03-07 (owner decision 2026-10-25, 03-03 plan check, Q2). After this plan, a restore no longer stops with the signer down: under the restore hold the operator imports the newest KRL keyroster-server served and the saved export's last KRL, both ops-signed, plus the saved export's lost certificates, in one admin-signed transaction that publishes one KRL. That first KRL after the restore lists every entry any host could have seen. Nothing un-revokes, and `keyroster audit verify` re-derives the whole recovery from the log.

Purpose: REVOKE-03 (a rollback of the revocation state never reaches the fleet) and REVOKE-01 (lost revocations, including key IDs whose issuance the restore lost, todo point 11, stay revoked; lost live certificates are handled by the owner's answer in Task 1). It closes the residual of threat T-03-207 (03-03): a revocation made after the latest saved export is no longer lost while keyroster-server's state survives the signer restore.

Output: keyroster-server's durable KRL copy, leaf kind 15 with its audit rule and export, the recovery request format, `keyroster revoke recover`, `keyroster-signer recover-revocations`, the restore runbook with the recovery in place of 03-03's stop, the e2e drill, CI pins, and a PR.

**Design, with the facts from the 03-03 plan check it rests on** (todo `2026-10-25-plan-signer-restore-revocation-recovery.md`, points 1 to 11):
- **Offline, under the hold.** A 4 MiB KRL does not fit the signer socket's 64 KiB frame, and a restored signer that starts publishes at once (start-up and hourly publish, D-10). So the recovery is a `keyroster-signer` subcommand run under the state lock with the hold in force, like `install-bundle`, before the restored signer ever starts. "A pending recovery" is therefore the hold itself: there is no recovery state inside a running signer for anything to bypass (todo points 4 and 8).
- **No grep, no replay one by one.** Serial entries carry no key ID (point 1), decoded export fields are not bound (point 2) and `revoke key` exports only a fingerprint (point 3). The recovery therefore reads only signed bytes: ops-signed KRL documents (which carry serials under CA keys, key IDs and the explicit keys' bytes) and certificates taken from the verified leaf bytes. One transaction writes one leaf and one publish (point 4).
- **Durable source.** The server kept the KRL in memory only (5 s cache), so this plan gives it a durable copy, `krl-served.json` in its state directory, written before it serves. A file avoids a serverdb migration, which would collide with 03-07's 0005_agents.sql and 03-08's 0006_heartbeats.sql. The operator can also copy a file while the server is held, without the sqlite3 program the runbook does not install. A signer restore never rolls it back: the runbook takes only the signer's three database files, and the hold stops keyroster-server, which freezes the copy at the last KRL it served (point 6). An agent's accepted KRL (03-05's `<state>/accepted/`) cannot be a source for a plan gated before 03-07: no agent pulls a KRL yet. It stays a possible source later, and nothing here builds it.
- **Lost serials without an issuance** come from the imported KRL's certificate sections, under their CA key, with no issuance lookup. Their ValidBefore comes from a certificate when one is known, else it is 0 and never pruned (point "Lost serials" of the todo).
- **Leaf kind 15** is the first free number (11 to 14 are 03-09..03-12's; point 9). The numbering needs no floor (point 10, Q1).
- **03-10's negative probes** (point 7) and **03-13's start-up publish** (point 8) do not exist yet. This plan defines the contract and adds a cross-plan note to each: 03-10 keeps a recovered probe key renewable for the host whose probe certificate the recovery carried, and adds that drill case. Until 03-13 exists, every bundle copies the ops key. After it, an import signed under an ops key that only a lost bundle names is refused here: this fails closed, because the hold stays. Making that case recoverable is 03-13's design, and `install-bundle` never publishes.
- **A lost installation ID.** The homelab's bundle gains its installation ID only with 03-15's v4 bundle. When the restored bundle has none but the saved export's has one, revocations may have followed that the restored signer cannot publish. `keyroster revoke recover` then refuses (`recovery_installation_lost`), the hold stays and the operator escalates. When neither bundle has one, no KRL was ever published and nothing can be lost from one.

**Owner decision before implementation (Task 1): what happens to lost certificates that are still valid** (todo point 5). The plan is written for the recommended answer. Any other answer stops this plan for a revision, before any code.
</objective>

## Budget Exception

**For owner acceptance: 32 files (plus the todo's move) and about 195k tokens**, against the 15-file and 100k smart-zone thresholds. Why it is one plan: a recovery is safe only when the import, the one-transaction publish, the start-up check, the audit rule and the runbook that runs it under the hold land together. Each part alone fails in a dangerous way:
- an audit rule without the signer path is never exercised;
- a signer path without the start-up change refuses its own database (`revocations_not_logged`);
- a runbook without the code keeps the signer down;
- the code without the runbook lets an operator release the hold first.

The server's durable copy is the other half of the owner's direction: without it, revocations after the latest saved export stay lost (T-03-207).

Split options, if the owner prefers:
- **(a) The server copy alone first**, as a small plan between 03-06 and this one: internal/server/revoke.go, server.go, revoke_test.go, cmd/keyroster-server/serve.go and server-install.md, 5 files and about 25k. This plan then drops to 27 files and about 170k. The copy then starts accumulating sooner, but alone it changes nothing for a restore.
- **(b) Code and procedure apart.** 03-06b keeps the formats, signer, audit, server, the two commands, the unit tests and the tracer: 25 files, about 140k. A new 03-06c takes the runbooks, the full drill, the restore_test.go pins and smoke.sh: 7 files and the todo, about 55k. 03-07's gate then moves to 03-06c, and 03-03's stop stays in the runbook until 03-06c merges. That is fail-safe: a restore that lost a revocation keeps the signer down meanwhile.

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
@docs/runbooks/signer-install.md

Delivery protocol: 01-SKELETON.md, phase 03 names. Branch `p03/06b-restore-recovery`, SUMMARY `.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md`, docs commit `docs(03-06b): complete restore-recovery plan`. `depends_on` holds 03-03b (every revocation target, v2 installation-bound requests, krl.Parse, the restore stop this plan replaces) and 03-06 (ordering only: the owner placed this plan after 03-06 and before 03-07, 2026-10-26; no 03-06 artifact is used). 03-07 depends on this plan.
</context>

<tasks>

<task type="checkpoint:decision" gate="blocking-human">
  <name>Task 1: Lost certificates that are still valid — what the recovery does with certificates issued after the restored snapshot (todo point 5)</name>
  <precondition>`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md` and `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-06-SUMMARY.md` both exit 0</precondition>
  <decision>When a restore lost issue and login_issue entries that the saved export still records, those certificates are valid in the wild, and the restored signer does not know them. Its issuance table has no row for them, so `revoke serial` refuses `unknown_serial`, `revoke key-id` refuses `key_id_not_issued` (T-03-211), and `revoke user` does not find them. Decide what the recovery does with them.</decision>
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
      <name>Revoke every lost user certificate still live; list lost host and machine certificates with their public keys, and revoke one only when the admin names it (`--revoke-lost SERIAL`) (recommended)</name>
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
  <action>Present the three options to the owner in Swedish, with the facts from the context; do not re-ask Q1 or Q2 of the 03-03 plan check, which are recorded. Write the chosen option id as the first line of `$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt` (outside the repository; create the directory if needed) and the owner's wording verbatim below it. 03-06b-SUMMARY.md must carry a line that is exactly `Lost-certificates answer: <id>` followed by the verbatim wording. For `revoke-users-list-others`, continue with Task 2. For any other answer, stop before Task 2: create no branch and change no file under internal/, cmd/, test/ or docs/, and return `## CHECKPOINT REACHED` with the text "Lost-certificates answer <id>: revise 03-06b Tasks 2-4 before implementation", so the orchestrator runs the planner in revision mode with the recorded answer.</action>
  <verify>
    <automated>f="$HOME/keyroster-ceremony/phase3/r06b-lost-certs-answer.txt" && test -s "$f" && head -n 1 "$f" | grep -Eqx 'revoke-users-list-others|revoke-all-lost|readopt-lost'</automated>
    <fails_when>non-zero exit (the owner's answer was not recorded, or its first line is not one of the three option ids)</fails_when>
  </verify>
  <acceptance_criteria>
    - The owner's answer (an option id and the verbatim Swedish wording) is recorded before Task 2 starts, and 03-06b-SUMMARY.md carries the line `Lost-certificates answer: <id>` plus the wording.
    - Task 2 starts only when the first line of r06b-lost-certs-answer.txt is `revoke-users-list-others`; for any other id this plan stops here with no code change.
  </acceptance_criteria>
  <done>The owner has decided what happens to lost live certificates, before any recovery code exists.</done>
  <resume-signal>Reply with an option id (revoke-users-list-others, revoke-all-lost or readopt-lost) and any wording to record</resume-signal>
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

At start, New reads an existing copy: strict JSON of serverclient.KRLDocument, then krl.ParseManifest of its manifest. It keeps the served version in memory, and refuses to start when the copy does not parse. The message says the file is the restore source for lost revocations (signer-install.md) and must be kept.

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
8. Each certificate's serial is above the restored serial high-water mark and is not in the issuance table (`recovery_certificate_not_lost`).
9. The owner's answer: every carried certificate of the user CA that is live (krl.EntryLive) at the resolution time T has Revoke (`recovery_user_certificate_kept`).

T is the call's one clock reading in whole seconds, as Revoke takes it.

Then one logTx:
1. checkTrustCurrent.
2. Entries = krl.RecoveryEntries with the lookup over IssuanceBySerialTx and certCAKey. Above MaxRecoveryEntries, or a body above MaxRecoveryBody, is refused `recovery_too_large`.
3. Append the kind-15 leaf {policy version, T, SigningBytes, Evidence, Entries}.
4. One revocation row per entry through revocationRow, with this leaf's index and the request ID.
5. InsertRevokeRequestTx.
6. publishKRLLocked. Before the transaction commits, the published version must be above every import's KRL version. Otherwise it returns `recovery_version_not_above_import`, and the error names the seconds until the clock passes the highest imported version, so the transaction rolls back.

appendLocked's revoke branch adds the entries of a kind-15 leaf to pendingRevoked, and rebuildLogFrom's switch adds them to the logged multiset (decode error: errLogMismatch as for revoke). So loggedRevocations.check passes at this publish, at every later start, in doctor (CheckLog) and at every later publish. checkLogCovers is unchanged: the recovery writes no issuance row.

RecoveryResult carries the leaf indexes, the KRL version, and the counts of entries, imports, certificates revoked and certificates kept.

**keyroster-signer recover-revocations.** In cmd/keyroster-signer/recover.go, registered like install-bundle: `--state-dir` (required) and `--backend-opt`. It reads the file form from standard input, capped at MaxRecoveryRequest plus the evidence caps. It takes the lock through openState and opens the backend through openStoredBackend. Then signer.New with that backend and the database: the start-up checks only, never Serve, so no start-up publish runs. It prints `recovered: <entries> entries from <imports> imported KRLs, <revoked> lost certificates revoked, <kept> kept; KRL v<version> (log entries <recovery leaf>, <publish leaf>)`. A refusal exits 1 with the name and reason.

**keyroster revoke recover.** In cmd/keyroster/recover.go, dispatched from runRevoke's switch as `recover`. It is offline: loadConfig and adminSigner, and no serverclient.

1. Read --restored and --saved into memory.
2. Verify each with audit.Verify on the config's TrustPins and TrustThreshold.
3. The prefix rule:
   - when the saved export is longer, Verify(saved) with Options.Previous set to the restored export's checkpoint (readPrevious) must pass, and the lost certificates are those at or after the restored size;
   - otherwise Verify(restored) with the saved checkpoint as Previous must pass, and there are none;
   - when neither holds, refuse: the exports are a fork, so escalate as step 2 does.
4. The installation ID:
   - when the restored export's Report.Bundle has no installation ID and the saved export's has one, refuse `recovery_installation_lost`: a lost bundle added the ID and revocations may have followed, which the restored signer cannot publish (keep the hold, escalate);
   - when neither has one, print `nothing to recover: neither export's trust bundle has an installation ID, so no KRL was ever published`, write no file and exit 0.

audit.Options gains `CertificatesFrom *uint64`. Verify then fills `Report.Certificates`, each with its index, kind and certificate bytes from the verified leaf (issue and login_issue, at or after the index). `Report.LastKRL` is the last krl_publish entry's {KRL as verifyKRLPublish re-derived it, manifest, sig}, and `Report.Bundle` is the bundle in force at the end. A recovery command needs nothing else from audit.

Imports: Report.LastKRL of the saved export when it has one, and each --krl document, read with the serverclient.KRLDocument decoder and verified with krl.VerifyManifest under the restored export's Report.Bundle and its installation ID. The same document twice is imported once.

Certificates: every lost certificate. Revoke is set for each serial named by --revoke-lost, and for every user certificate that is live by krl.EntryLive at the CLI's clock minus the signer's 300 s skew bound. The skew bound is there because a workstation clock ahead of the signer's must not leave a certificate unmarked that the signer still sees as live (`recovery_user_certificate_kept`); marking one that is already expired is harmless, since its entry is pruned at the publish. A --revoke-lost serial that is not a lost host or machine certificate is refused.

The CLI computes the entries with the same krl.RecoveryEntries and a lookup over the restored export's certificates (Report.Certificates from 0). It prints the summary:
- installation ID;
- restored size and root, and saved size;
- each import's source, version, issued_at and entry counts;
- each lost certificate with serial, role, subject, key fingerprint, ValidBefore, live or not, and revoke or keep, where each kept one ends with `revoke later with: keyroster revoke key <file with this public key>`;
- the entry count and the version the publish must exceed.

It asks for confirmation unless --yes, signs SigningBytes with the admin key under RecoverySSHSIGNamespace, and writes the file form to --out (mode 0600, O_EXCL).

**Audit.** In internal/audit/recovery.go: verifyRecovery(index, body, leafMicros, a, rs, iss, root-before). Verify's switch gains the kind and passes the root of the tree before the entry. The checks are those in must_haves.

The lookup is the log's certificates. loggedCert gains the key ID, and addCert records it.

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
    - Audit, `TestVerifyRecovery`:
      - Accepted: `recovery_accepted`.
      - Refused: `recovery_entries_tampered` (an entry dropped), `recovery_entry_vb_tampered` (a lower ValidBefore), `recovery_entry_added_unbound` (an entry no import or certificate gives), `recovery_restored_root_mismatch`, `recovery_restored_size_mismatch`, `recovery_not_admin`, `recovery_other_installation`, `recovery_import_unsigned`, `recovery_import_hash_section`, `recovery_certificate_forged` (signature by another key), `recovery_certificate_already_logged`, `recovery_user_certificate_kept`, `recovery_unpublished_at_end`, `recovery_publish_not_above_import` and `recovery_resolved_after_leaf`.
      - `TestVerifyRecoveryExportLines`: the as-exported lines of a recovery verify and carry none of the forbidden keys.
      - `TestRecoveryLeafFitsExportLine` (in internal/audit, which owns the export; tlog's tests cannot import audit): a leaf with a body of exactly MaxRecoveryBody is written with Export's line encoder and read back by Verify's line reader (maxLine) without `token too long`.
      - `TestVerifyCertificatesFrom`: Report.Certificates holds exactly the certificates at or after the index, from the leaf bytes.
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
      - `no_installation_id_nothing_to_recover` (neither has one: exit 0, no file).
  </behavior>
  <read_first>
    - The files written in Task 2; internal/signer/revoke_test.go (TestPublishNeverDropsLiveEntry, TestSubjectResolutionTime's injected clock), internal/signer/krlloop_test.go (TestKRLStartupAndRepublish), internal/audit/verify_test.go (TestVerifyRevocations' log builders), internal/server/revoke_test.go (TestKRLCache, fakeSigner), cmd/keyroster/revoke_test.go (the test admin agent)
    - internal/tlog/fuzz_test.go (FuzzDecodeLeaf's seed loop), internal/wire/fuzz_test.go (FuzzParseRevokeSigningBytes), scripts/fuzz.sh (every Fuzz target runs in CI)
  </read_first>
  <action>Write the tests in `<behavior>` as table-driven tests next to the code and fix what they break. Create the two golden files once with `go test -run '<name>' -update`, read each back (the hex starts with the leaf domain tag for the leaf vector and with the domain tag `keyroster/revoke-recovery/v1` for the request), and commit them. For each refusal of the signer and of audit, run one mutant that removes the check, record that the named test fails with it and passes without it, and list the results in the SUMMARY (at least: the restored-root binding, the user-certificate rule, the ValidBefore rule in RecoveryEntries, the version floor, the server's lower-version refusal).</action>
  <verify>
    <automated>go test -count=1 -v -run 'Recovery|Recover|KRLServedCopy|CertificatesFrom|LastKRL' ./internal/tlog/ ./internal/wire/ ./internal/krl/ ./internal/audit/ ./internal/server/ ./cmd/keyroster/</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or a "--- PASS:" line missing for any of TestRecoveryBody, TestRecoveryLeafGoldenVector, TestRecoveryLeafFitsExportLine, TestRecoveryRequestSigningVector, TestRecoveryEntries/range_cap_refused_before_allocation, TestVerifyRecovery/recovery_entry_vb_tampered, TestVerifyRecovery/recovery_restored_root_mismatch, TestKRLServedCopy/lower_version_not_served, TestKRLServedCopy/write_failure_not_served, TestRevokeRecover/user_live_revoked_by_default</fails_when>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestRecoverRevocations|TestRecoveryTracer" ./internal/signer/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or "--- PASS: TestRecoverRevocations/recovery_rolls_back_on_publish_failure", "--- PASS: TestRecoverRevocations/restart_after_recovery", "--- PASS: TestRecoverRevocations/recovered_entries_never_dropped" or "--- PASS: TestRecoverRevocations/recovers_explicit_key" missing</fails_when>
    <automated>go test -run NONE -fuzz FuzzParseRecoveryRequest -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzParseRecoverySigningBytes -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzDecodeLeaf -fuzztime 20s -fuzzminimizetime 5s ./internal/tlog/</automated>
    <fails_when>non-zero exit, or "FAIL" in the output</fails_when>
  </verify>
  <acceptance_criteria>
    - `git ls-files test/vectors/leaf_revocation_recovery_v1.hex test/vectors/recovery_request_signing_v1.hex` prints both files.
    - Every named case of `<behavior>` appears in the test files (`grep -c` of each name prints at least 1).
    - The SUMMARY records each mutant with the test that killed it.
  </acceptance_criteria>
  <done>Every refusal of the recovery is named and tested, the pending-recovery cases leave nothing behind, the server never serves a KRL it did not keep, and both new parsers are fuzzed.</done>
</task>

<task type="auto">
  <name>Task 4: The restore runbook with the recovery, the e2e drill, CI pins, gates, the todo and the PR</name>
  <files>docs/runbooks/signer-install.md, docs/runbooks/revoke.md, docs/runbooks/server-install.md, test/e2e/recovery_test.go, test/e2e/restore_test.go, test/systemd/smoke.sh, .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md, .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md</files>
  <read_first>
    - docs/runbooks/signer-install.md "A restore brings back the older trust bundle, policy and directory" (the hold block, the file restore, steps 1 to 3, the revoke counts and the stop 03-03 added, the release block, the copy block of step 3, the CI and UNVERIFIED notes at the end of the section) and "Snapshot restore: check the clock first"
    - docs/runbooks/revoke.md sections 6 and 7 (the KRL route; "take a saved export after every revocation"), docs/runbooks/server-install.md (the state directory paragraph: "Nothing in it is authority")
    - test/e2e/restore_test.go (restoreRunbookChecks, restoreAdminCopyScript, restoreAdminPathWrite, restoreSavedGreps, restoreRestoredGreps, the stop constant 03-03 added and its position checks in TestRestoreRunbookChecks), test/systemd/smoke.sh (the hold, file restore, release and copy blocks run verbatim, kradmin)
  </read_first>
  <action>
**signer-install.md, the restore section.** Replace 03-03's stop for a lost revocation (the sentence test/e2e/restore_test.go pins as its stop constant, and the interim sentences after it saying that this runbook does not recover lost revocations yet and that access goes through break-glass meanwhile) with the recovery, which runs after every restore, whatever the counts show. Keep both revoke counts: they go into the operations log. Add, in this order:
- **Keep the server's KRL copy, right after the hold's `held:` line and before the file restore.** A block that runs as root on the host where keyroster-server runs, and reads the file as keyroster-server:
  - `install -d -m 0700 /root/recovery`;
  - `runuser -u keyroster-server -- cat /var/lib/keyroster-server/krl-served.json > /root/recovery/server-krl.json`;
  - `test -s /root/recovery/server-krl.json`;
  - an `echo` that is the only line saying the copy is kept.

  With it, the rules: root reads the server's file only as keyroster-server and writes only its own directory. A missing file means that the server never served a KRL: then continue without `--krl`. Where keyroster-server runs on another host, run the block there and copy the file over, because the hold block holds only the units on this host. Labelled run in CI (systemd-sandbox, with a fixture file) and UNVERIFIED on a real host.
- **The clock check moves before the recovery,** because the recovery publishes: `timedatectl` and `doctor`, as in "Snapshot restore: check the clock first", while the hold is in force.
- **Step 2b, "Recover the revocations the restore lost (every restore, before the release)".** Four parts:
  1. A copy block in the shape of step 3's copy block, as root with `<admin>`: it creates `$H/recovery-in` as the admin and copies `/tmp/restored.jsonl`, `/root/latest-saved.jsonl` and `/root/recovery/server-krl.json` into it as the admin, from root's standard input, ending in one `echo`.
  2. The admin, in their own session with their ssh-agent and keyroster config (section 8), runs `keyroster revoke recover --restored /home/<admin>/recovery-in/restored.jsonl --saved /home/<admin>/recovery-in/latest-saved.jsonl --krl /home/<admin>/recovery-in/server-krl.json --out /home/<admin>/recovery-in/recovery.bin`, reads the summary and confirms. Kept host and machine certificates are named with `--revoke-lost SERIAL` when the admin wants them revoked, per the owner's answer from Task 1. The admin must be an admin of the restored policy, because a policy restored older can lack admins added since.
  3. A read-back block, as root: `runuser -u <admin> -- cat "$H/recovery-in/recovery.bin" > /root/recovery/recovery.bin`, then `test -s` and one `echo`.
  4. The recovery itself, as root under the hold: `runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin`. Its `recovered:` line goes into the operations log. Then step 1's export again with `--out /tmp/recovered.jsonl`, and audit verify of it on the pins on its own and with `--previous /tmp/restored.jsonl /tmp/recovered.jsonl`. Both must pass, and the report counts one recovery.

  The refusals the operator can meet, each with its fix:
  - `recovery_log_mismatch`: the restored signer logged something, or a second run; stop and escalate as for a fork;
  - `recovery_version_not_above_import`: wait the seconds it names (T-03-208);
  - `recovery_import_invalid` because the import is signed under another ops key (possible only after 03-13), or `recovery_certificate_invalid` for a CA generation only a lost bundle names (possible only after 03-12): keep the hold and escalate, labelled UNVERIFIED (03-12 and 03-13 own making these cases recoverable);
  - `recovery_installation_lost` from `keyroster revoke recover`: keep the hold and escalate (UNVERIFIED);
  - `nothing to recover` from `keyroster revoke recover`: neither bundle has an installation ID, so there is no recovery file to apply; release.
- **Release the hold** only after step 2b, and say so in the release paragraph's condition.
- **Step 3's baseline paragraph stays as it is:** `--previous /tmp/restored.jsonl` remains valid after the recovery, because the recovered log extends the restored one. restoreRunbookChecks and TestRestoreReplaysLostDirectory pin that line.
- The section's CI note and UNVERIFIED list:
  - the drill (TestRestoreRecoversLostRevocations, CI e2e);
  - the blocks run verbatim in systemd-sandbox;
  - UNVERIFIED: the copy from a server on another host; a real signer host; the TPM and PKCS#11 backends for the recovery command (CI e2e runs the software or agent backend of the harness); a fresh signer VM whose server copy died with the old VM, after which only the saved export's KRL is imported and revocations after the latest saved export stay lost (T-03-207's remaining residual).

Keep the operating rule "take a saved export after every revocation" and add that the recovery also imports keyroster-server's copy, which covers revocations after the latest saved export while that server's state directory survives the restore.

**revoke.md.** Section 6: keyroster-server keeps the last KRL document it served in krl-served.json, written before it serves it, never replaced by a lower version, and the route answers 503 rather than serving a KRL it could not keep. Labelled run in CI (internal/server tests, 03-06b). Section 7 keeps the saved-export rule, with the same addition as signer-install.md and a pointer to step 2b. A short paragraph says that a lost host or machine certificate the recovery kept is revoked by key.

**server-install.md.** The state directory paragraph: the directory also holds krl-served.json, the last KRL document the server served. Like the rest of the directory it is no authority (every reader verifies it), but it is the restore source for lost revocations (signer-install.md, step 2b). Never delete it, and back it up with the directory.

**test/e2e/restore_test.go.**
- Replace the stop constant and its position check with the recovery: the commands of step 2b and the post-recovery export and verifies in restoreRunbookChecks, and new constants for the capture block, the copy-in block and the read-back block, each required verbatim in the runbook and in smoke.sh (as restoreAdminCopyScript is).
- Position checks:
  - the capture comes after the hold and before the file restore;
  - the clock check comes before the recovery;
  - the recovery comes after the saved export's verify stop and before the release block;
  - the release comes before step 3.
- restoreAdminPathWrite still finds no root write to an admin path.

**test/systemd/smoke.sh.** Run the three new blocks verbatim:
- the capture block, against a fixture `krl-served.json` written as keyroster-server in a state directory created with the unit's owner and mode;
- the copy-in block for kradmin, refusing first with a planted link at `~/recovery-in` (as the replay copy block does);
- the read-back block;
- the recovery line under the hold with a request that does not parse: it must exit non-zero with `recovery_malformed`, and the signer database's SHA-256 is unchanged.

**test/e2e/recovery_test.go, `TestRestoreRecoversLostRevocations` (the todo's drill).** Setup, in order:
1. A signer and keyroster-server issue certificates A (user, before the snapshot) and B (user, before the snapshot).
2. The snapshot: signer.db copied with the signer stopped.
3. Then C (user), D (user, never revoked) and H (host, admin issue path) are issued, and A, C and an explicit key K are revoked.
4. The saved export is taken.
5. B is revoked through the CLI, so the server served and kept it.
6. The server and signer are stopped and the copy and the snapshot are restored.

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
- Both start again: the served KRL makes `ssh-keygen -Q` refuse A, B, C, D and K, and sshd refuses A, B, C and D. H is listed as kept in the summary and is absent from the KRL; `keyroster revoke key` of H's public key then succeeds.
- The signer restarts: the KRL version is unchanged and still refuses all of them.
- audit verify of the final export passes.

The negative-probe case is 03-10's (cross-plan note); the drill names it as its extension point.

Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair (the recovery adds no capability: reading standard input and the state database, and the server's file write in a package that already writes its database). A new pair is a deviation to review and record in the SUMMARY. Push.

**The todo.** Move `.planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md` with `git mv` under the same name to `.planning/todos/completed/`, appending "Resolved in 03-06b (PR from branch p03/06b-restore-recovery)". The SUMMARY is pushed before the PR opens, so it names the branch, as 03-03b's SUMMARY records (deviation 8). 03-07's precondition checks this plan's SUMMARY on origin/main.

**The PR.** `scripts/gh-as-bot.sh pr create --title "feat(signer): recover revocations a signer restore lost, from the server's KRL copy and the saved export"`, without enabling auto-merge (the orchestrator enables it after the pre-merge review); wait for the required checks.

**The SUMMARY.** Contents:
- the PR number;
- the line `Lost-certificates answer: revoke-users-list-others` and the owner's wording;
- the refusal names;
- the mutant results;
- the CI run IDs;
- capslock;
- `requirements-completed` empty: REVOKE-01 completes in 03-11 and REVOKE-03 in 03-07, as 03-03 recorded.

D-20: this plan changes the operator's restore steps, which signer-install.md carries in the same PR. Then the tracking updates once, `docs(03-06b): complete restore-recovery plan`, push and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>git push origin p03/06b-restore-recovery && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/06b-restore-recovery && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/06b-restore-recovery --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit, or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestRestoreRecoversLostRevocations", "--- PASS: TestRestoreRecoveryTracer", "--- PASS: TestRestoreRunbookChecks" or "--- PASS: TestRestoreReplaysLostDirectory", or reports any e2e test as FAIL</fails_when>
    <automated>test ! -e .planning/todos/pending/2026-10-25-plan-signer-restore-revocation-recovery.md && git ls-files --error-unmatch .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md && grep -q 'Resolved in 03-06b' .planning/todos/completed/2026-10-25-plan-signer-restore-revocation-recovery.md</automated>
    <fails_when>non-zero exit (the todo was not moved under the same name, or the resolution line is missing)</fails_when>
    <automated>git fetch origin p03/06b-restore-recovery && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)"</automated>
    <fails_when>non-zero exit (the SUMMARY is not on the pushed branch, or local commits are unpushed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/06b-restore-recovery --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported; systemd-sandbox runs the new smoke.sh blocks)</fails_when>
  </verify>
  <acceptance_criteria>
    - 03-03's stop is gone and its interim text with it, checked with white space squashed:
      - `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'the restore lost a revocation: do not release the hold'` prints 0;
      - `tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'Until the restore-recovery plan merges'` prints 0.
    - The recovery is in the runbook, in both the CI pins and the text:
      - `grep -c 'keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin' docs/runbooks/signer-install.md` prints at least 1;
      - `grep -c 'keyroster revoke recover --restored' docs/runbooks/signer-install.md` prints at least 1;
      - `grep -c 'krl-served.json' docs/runbooks/signer-install.md docs/runbooks/revoke.md docs/runbooks/server-install.md` prints at least 1 for each file.
    - `tr -s '[:space:]' ' ' < docs/runbooks/revoke.md | grep -c 'take a saved export after every revocation'` and the same on signer-install.md each print at least 1 (the rule stays).
    - `TestRestoreRunbookChecks` passes in CI e2e with the capture, clock check, recovery and release in that order; systemd-sandbox passes with the new blocks.
    - The PR is open without auto-merge (the orchestrator enables it after the pre-merge review), every required check green, 03-06b-SUMMARY.md on its head, the todo in completed/.
  </acceptance_criteria>
  <done>A restore that lost revocations is recovered under the hold before the signer serves again, the runbook says how and CI runs it, and the PR waits green.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — owner approves PR p03/06b-restore-recovery, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews (security code: full review) and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/06b-restore-recovery --web`; review code, 03-06b-SUMMARY.md and signer-install.md's restore section, especially that lost certificates follow your Task 1 answer and that nothing in the restore starts the signer before step 2b.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/06b-restore-recovery` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/06b-restore-recovery</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-07's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/06b-restore-recovery --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>Restore recovery is on main, and 03-07 may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Edge Coverage (spec-less fallback, this plan)

This plan authors REVOKE-03 rollback (a restored, older revocation state never reaches hosts) as truths.

**Flagged assumption, the durable copy.** Assumed: keyroster-server is the only path by which a KRL reaches hosts, so the last KRL it served is a superset of the live entries of any KRL a host holds. 03-03's no-drop property covers intact rows, and hosts accept only increasing versions from 03-07 on. A KRL installed on a host by hand from another source is outside this. 03-07's agent route must use currentKRL (cross-plan note). The hold stops keyroster-server, which freezes the copy. A release without the recovery breaks the procedure, and the copy would then be replaced by the restored signer's higher version (T-03-271).

**Flagged assumption, ValidBefore of imported entries.** Assumed: a certificate is identified by its serial under one CA key (the serial is the issuance table's primary key and the serial high-water mark only rises), and a key ID names exactly the certificate whose serial it carries (D-09). Entries whose certificate neither the restored log nor the saved export holds keep ValidBefore 0 and never leave the KRL (T-03-269).

**Flagged assumption, no restore ever starts the signer before step 2b.** The runbook's never-boot rule for VM snapshots and the hold (03-02, 03-03) are what make "the first KRL after the restore" the recovery's. A restored signer that logged anything first is refused by `recovery_log_mismatch`, as step 2 refuses a fork.

**Flagged assumption, the installation ID.** A restore to a bundle without an installation ID is recoverable only when the saved export's bundle has none either. In that case no KRL was ever published. Otherwise `recovery_installation_lost` keeps the hold. The homelab's path to an ID is 03-15's v4 bundle, and a restore across that ceremony is escalated (cross-plan note in 03-15-PLAN.md).

**Lost certificates (owner's Task 1 answer).** Certificates issued after the latest saved export are unknown under every answer and expire by their TTL (T-03-272).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Lost revocations never reach hosts; access revoked centrally stays revoked after a signer restore | Tasks 2-4 |
| REQ | REVOKE-01 (lost revocations, key IDs and certificates stay revoked or revocable) | Tasks 1, 2, 3 |
| REQ | REVOKE-03 (no rollback of the revocation state; the recovery's version is above every import) | Tasks 2, 3, 4 |
| CONTEXT | D-04 (installation ID in the request, the imports and the server's check) | Task 2 |
| CONTEXT | D-09 (a key ID names one certificate: ValidBefore of key-ID entries) | Task 2 |
| CONTEXT | D-10 (hosts keep their last KRL; the hourly publish after a recovery keeps the union; never lock out) | Tasks 2, 3 |
| CONTEXT | D-20 (signer-install.md, revoke.md and server-install.md in the same PR, run or UNVERIFIED) | Task 4 |
| Owner decisions | Q1 time-derived krl_version; Q2 own plan before 03-07; v2 installation-bound requests (T-03-210); key ID only for issued key IDs and explicit-key caps (T-03-211) | Tasks 2, 3 (version floor; RecoveryEntries ValidBefore; no new key-ID path; caps counted by later revokes) |
| Todo points 1-11 | See the ledger below | Ledger |
| RESEARCH | No 03-RESEARCH item is specific to restores; its KRL encoder and pruning rules are reused unchanged | Task 2 |

## Artifacts this phase produces (this plan)

- tlog: `KindRevocationRecovery` 15 (`revocation_recovery`), `RecoveryBody`, `DecodeRecoveryBody`, `MaxRecoveryEntries` (1 << 16), `MaxRecoveryBody` (11 MiB); Kind validity is an explicit set.
- wire: `RecoveryRequestDomain` = `RecoverySSHSIGNamespace` = `keyroster/revoke-recovery/v1`, `RecoveryRequest`, `RecoveryImport`, `RecoveredCertificate`, `ParseRecoveryRequest`, `ParseRecoverySigningBytes`, `MaxRecoveryRequest` (9 MiB), `MaxRecoveryImports` (4), `MaxRecoveryKRL`, `MaxRecoveryCertificates` (4096), `MaxRecoveryCert`; fuzz targets `FuzzParseRecoveryRequest`, `FuzzParseRecoverySigningBytes`.
- krl: `RecoveryEntries`, `RecoveredCert`, `CertLookup`, `ErrRecoveryTooLarge`.
- signer: `RecoverRevocations`, `RecoveryResult`; refusals `recovery_malformed`, `recovery_installation_mismatch`, `recovery_log_mismatch`, `recovery_evidence_invalid`, `recovery_import_invalid`, `recovery_certificate_invalid`, `recovery_certificate_not_lost`, `recovery_user_certificate_kept`, `recovery_too_large`, `recovery_version_not_above_import`; kind 15 in the start-up rebuild and pendingRevoked.
- audit: `verifyRecovery`, `Options.CertificatesFrom`, `Report.Certificates`, `Report.LastKRL`, `Report.Bundle`, `Report.Recoveries`; export fields `restored_size`, `imports`, `import_krl_versions`, `certificates`, `certificates_revoked`, `entries`, `admins`.
- server: `Config.KRLFile`, `<state-dir>/krl-served.json` (the last KRL document served, kept before it is served).
- CLI: `keyroster revoke recover` (refusals `recovery_installation_lost` and the fork of the prefix rule; `nothing to recover` when neither bundle has an installation ID); `keyroster-signer recover-revocations`.
- Tests and vectors: `TestRecoveryTracer`, `TestRestoreRecoveryTracer`, `TestRestoreRecoversLostRevocations`, `TestRecoverRevocations`, `TestRecoveryEntries`, `TestVerifyRecovery`, `TestKRLServedCopy`, `TestRevokeRecover`, `TestRecoveryLeafFitsExportLine`, `test/vectors/leaf_revocation_recovery_v1.hex`, `test/vectors/recovery_request_signing_v1.hex`.
- Runbook: signer-install.md's capture block, step 2b and its three blocks, pinned in restore_test.go and run in smoke.sh.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| restored signer state → hosts | A restored, older revocation table must never be published as the newest KRL |
| keyroster-server's copy → recovery | The copy is no authority: every import is verified under the ops key and installation ID of the bundle in force |
| saved export → admin CLI → signed request | Only verified leaf bytes are read; the admin signs what the root-pinned CLI verified |
| root on the signer host → admin and service accounts | The runbook's copies run as the account that owns each path |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-265 | Elevation of privilege | a signer restore that drops revocations, including ones newer than the latest saved export (un-revoke on every host) | high | mitigate | Every restore runs the recovery under the hold before the release. It imports keyroster-server's krl-served.json (kept before every serve) and the saved export's last KRL, re-derived by audit verify, in one transaction with one publish whose version is above every import. TestRestoreRecoversLostRevocations covers serial (before and after the snapshot), key, a revocation after the saved export, and the pending cases. Closes T-03-207's residual while the server's state survives. A restore that lost the bundle adding the installation ID is refused (`recovery_installation_lost`), so the hold stays. **Accepted residual:** a restore that also loses the server's state directory (a co-located VM lost for good) imports only the saved export, so revocations after it stay lost. The rule "take a saved export after every revocation" stays for that case (UNVERIFIED path in signer-install.md) |
| T-03-266 | Tampering | a recovery request applied to another installation, another restored state, or twice | low | mitigate | The request names the installation ID and the restored log's size and root, and the signer refuses `recovery_installation_mismatch` or `recovery_log_mismatch`. Its request ID goes into revoke_request (`duplicate_request`). Audit checks the size and root against the log at that index (`recovery_restored_root_mismatch`) |
| T-03-267 | Spoofing | a recovery by someone without an admin key, or with an import or certificate not of this installation | medium | mitigate | admin-sshsig/v1 by a policy admin under keyroster/revoke-recovery/v1 (`recovery_evidence_invalid`, audit `recovery_not_admin`). Imports must verify under the ops key of the bundle in force and its installation ID (`recovery_import_invalid`). Certificates must verify under a CA key of their role in the bundle in force (`recovery_certificate_invalid`, audit `recovery_certificate_forged`) |
| T-03-268 | Elevation of privilege | early pruning through a ValidBefore the recovery invents (un-revoke once pruned) | high | mitigate | krl.RecoveryEntries takes ValidBefore only from a certificate with the same CA key and serial, or the serial a key ID names with an equal key ID; else 0, never pruned. Signer and audit share it; audit re-derives the listed entries (`recovery_entry_vb_tampered`); `recovered_entries_never_dropped` |
| T-03-269 | Denial of service | imported entries without a known certificate stay in the KRL for good, and a huge import exhausts memory | medium | accept | Expansion is counted before allocation (`range_cap_refused_before_allocation`); MaxRecoveryEntries and MaxRecoveryBody give `recovery_too_large`; a KRL above MaxKRL is `krl_too_large` and rolls the recovery back. **Accepted residual:** entries whose certificates neither the restored log nor the saved export holds never leave the KRL; the remedy for a full KRL is 03-13's CA replacement, as for `krl_too_large` today |
| T-03-270 | Denial of service | keyroster-server refuses to serve a KRL it cannot keep (disk full, read-only state directory) | low | accept | Fail-safe for completeness: a KRL that is not durable is never served, the route answers 503 and logs why, and hosts keep their last KRL and never lock out (D-10). A revocation's CLI check then fails visibly; agents alert at 24 h (03-08). `write_failure_not_served` |
| T-03-271 | Tampering | the server's copy replaced by a restored signer's KRL that a release without the recovery published (higher time-derived version, entries missing) | medium | mitigate | The runbook keeps a copy right after the hold, before the file restore (position pinned in TestRestoreRunbookChecks). The server never serves a version below the one it served, nor the same version with other bytes (`lower_version_not_served`). **Residual:** a release without the recovery breaks the procedure; the copy taken under the hold is the evidence |
| T-03-272 | Repudiation | lost certificates still valid that the restored signer does not know (todo point 5) | medium | mitigate | Owner's Task 1 answer `revoke-users-list-others`: the recovery carries every lost certificate from the verified saved export, revokes every lost user certificate live at its resolution time (enforced by signer and audit, `recovery_user_certificate_kept`), and lists host and machine certificates, which the admin revokes by naming them. Kept ones stay visible in the log and are revoked by key later (`keeps_lost_host_certificate`). **Accepted residual:** certificates issued after the latest saved export are unknown and expire by their TTL |
| T-03-273 | Denial of service | a recovery KRL that hosts ignore because its version is not above an imported version (a clock that ran ahead, a same-second burst) | low | mitigate | The signer refuses `recovery_version_not_above_import` with the seconds to wait. Audit refuses a publish after a recovery that is not above every import (`recovery_publish_not_above_import`). The clock check precedes the recovery in the runbook (T-03-208) |
| T-03-274 | Elevation of privilege | root following a link planted by the admin or the server account during the runbook's copies | low | mitigate | Each block writes as the account that owns the path, and root reads only its own files (the step 3 rule of 03-02). The blocks are pinned verbatim in restore_test.go (restoreAdminPathWrite still empty) and run in systemd-sandbox, with a planted link refused |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; the recovery reuses x/crypto/ssh, cryptobyte and the in-house krl, tlog and sshsig packages; capslock baseline unchanged |
</threat_model>

<verification>
- Every verify command passes, including both CI e2e lanes, the fuzz runs and systemd-sandbox; the merge gate passes.
</verification>

<success_criteria>
- After a signer restore, the operator brings the signer back with every revocation hosts could have seen. That covers revocations newer than the saved export, while keyroster-server's state survives. The restored signer's first KRL lists every lost entry and is above every version hosts hold. Nothing un-revokes, lost live user certificates are revoked, and `keyroster audit verify` re-derives the recovery from the log.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-06b-SUMMARY.md` in Task 4, before the merge gate. It carries the exact line `Lost-certificates answer: <id>` and the owner's verbatim wording (Task 1). `requirements-completed` is empty (REVOKE-01 completes in 03-11, REVOKE-03 in 03-07). Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (todo 2026-10-25, the 03-03 plan check's Q2 rows, the PR #61 pre-merge review)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Todo point 1 (03-03 plan check, both skeptics): a serial RevokedEntry carries no key ID or key, and `revoke serial` refuses a serial whose issuance the restore lost | HIGH | Task 2: lost serials come from the imported KRL's certificate sections under their CA key, with no issuance lookup; ValidBefore from a certificate when known (krl.RecoveryEntries). `recovers_serial_without_certificate`, `recovers_serial_issued_after_snapshot` |
| Todo point 2: issue and login_issue decoded fields are not bound by audit verify, collide with revoke fields, and are JSON-escaped | HIGH | Task 2: nothing reads a decoded field. The CLI takes certificates from verified leaf bytes (Report.Certificates) and the saved KRL from the re-derived KRL (Report.LastKRL). `TestVerifyCertificatesFrom` |
| Todo point 3: a lost `revoke key` cannot be rebuilt from the export (fingerprint only) | HIGH | Task 2: the imported KRL carries the explicit keys' bytes. `recovers_explicit_key` with `ssh-keygen -Q` |
| Todo point 4: replaying one revocation at a time publishes N−1 unsafe intermediate KRLs | HIGH | Task 2: one transaction, one leaf, one publish, offline under the hold. The drill asserts no krl_publish between the restored log's end and the recovery |
| Todo point 5: lost but still valid certificates | MEDIUM | Owner decision in Task 1 (recommended `revoke-users-list-others`); T-03-272 |
| Todo point 6: revocations newer than the saved export are in neither file (T-03-207 residual) | HIGH | Task 2: keyroster-server's durable krl-served.json, kept before it serves and frozen by the hold; Task 4: the runbook copies it right after the hold. T-03-265 (residual narrowed to a lost server state) |
| Todo point 7 (codex medium): 03-10's negative-probe revocations, their host and key provenance, a renewal after recovery | MEDIUM | Contract here: the recovery imports every explicit key (the probe key included) and carries every lost certificate (the probe certificate names the host and key). Cross-plan note in 03-10-PLAN.md: its renewal exception also accepts a probe key whose revocation row comes from a revocation_recovery entry carrying this host's probe certificate for that key. Its probe kind joins audit's certificate collection, and the drill gains "installed negative-probe key, restore, recovery, successful renewal". It cannot be built before 03-10 |
| Todo point 8 (split): 03-13's start-up publish after an ops-key rotation must respect a pending recovery | MEDIUM | Contract here: the pending recovery is the hold, and the recovery precedes the first start. An import under an ops key the restored bundle does not name is refused (fail-closed: the hold stays). Replaying the lost bundle first cannot work as the recovery is bound now: install-bundle appends a bundle_install entry, so the restored size and root change. Cross-plan note in 03-13-PLAN.md: making that case recoverable is 03-13's design. It can either bind the recovery to the log after a replayed bundle, or carry and chain-check the successor bundle in the request. install-bundle never publishes, and 03-13's start-up publish runs only at the first start after the release, building from every row, the recovered ones included |
| Planner self-check before the PR: a restored bundle without an installation ID whose saved export's bundle has one (a lost bundle added the ID, as 03-15's v4 bundle will on the homelab) would have released the hold and published without the lost revocations | HIGH | Task 2: `keyroster revoke recover` refuses `recovery_installation_lost`, and prints `nothing to recover` only when neither bundle has an ID. Task 4: the runbook keeps the hold for the first and releases for the second. Task 3: `installation_id_lost_refused` and `no_installation_id_nothing_to_recover`. Edge Coverage line; cross-plan note in 03-15-PLAN.md |
| Todo point 9: a new leaf kind must not collide with 11-14 (03-09..03-12) | LOW | Task 2: kind 15; Kind validity is a set. Cross-plan notes in 03-09..03-12-PLAN.md say each adds its kind to the set |
| Todo point 10: the round-5 floor is moot under Q1 | — | No floor and no exported krl_version read. The only version rule added is "the publish after a recovery is above every import", which the signer and audit both check |
| Todo point 11 (PR #61, owner decision 2026-10-26): a key ID whose issuance the restore lost cannot be revoked by key ID | MEDIUM | Lost key-ID entries come back from the imported KRL (0x23 under their CA key). The lost certificates themselves follow the Task 1 answer: user certificates are revoked by serial, so their key IDs need no revocation; kept host and machine certificates are revoked by key (summary prints the key). No new key-ID path is opened, so T-03-211 holds |
| Todo "Costs": size (MaxRequest 64 KiB, MaxKRL 4 MiB), a dedicated leaf body with a golden vector | MEDIUM | Task 2: offline, so no frame limit; kind 15 body with its own caps; Task 3: `leaf_revocation_recovery_v1.hex`, `TestRecoveryLeafFitsExportLine` |
| Todo "Costs": the audit rule (ops-key signature, installation ID, version, union equality) | HIGH | Task 2 verifyRecovery and the publish floor; Task 3 `TestVerifyRecovery` |
| Todo "Costs": the runbook, restoreSavedGreps and TestRestoreRunbookChecks | MEDIUM | Task 4: 03-03's stop replaced by step 2b; the counts stay; new pinned blocks with positions; smoke.sh runs them |
| Todo drill (five cases, publish assertion, ssh-keygen and sshd, restart while pending) | HIGH | Task 4 TestRestoreRecoversLostRevocations; Task 3 the transaction-level pending cases (`recovery_rolls_back_on_publish_failure`, `recovery_second_run_refused`, `restart_after_recovery`); the negative probe through 03-10's note |
| Todo "Closing": move under the same name, "Resolved in" | — | Task 4; it names the branch, because the SUMMARY is pushed before the PR (03-03b deviation 8). 03-07's precondition checks this plan's SUMMARY on origin/main (edited with this plan) |
| 03-03 Round 2 Deferred, Q2 rows (codex high: replay material; restore-replay highs; drill coverage mediums) | HIGH | As points 1-4 and the drill above |
| 03-03 Round 2 Deferred, codex medium: negative-probe revocations left out | MEDIUM | As point 7 |
| 03-03 Round 2 Deferred, split codex medium: 03-13's start-up publish and the restore hold | MEDIUM | As point 8 |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| An agent's accepted KRL as a further import source | Not available before 03-07, which this plan precedes. The import takes any ops-signed KRL document, so a later plan can add the agent's accepted triple without a format change. Nothing here builds or documents it (no unexercised path) |
| Harden the signer restore runbook (todo 2026-10-25, Phase 4) | Out of scope: its items are fail-closed or labelled UNVERIFIED already, and this plan's new blocks follow the rules that todo asks for (root reads only its own files) |
| The signer checks issuance rows against its log (todo 2026-10-26, Phase 4) | Out of scope. The recovery's lookup reads the issuance table as subject revocation does, and a row edited outside the signer can only give an entry ValidBefore 0 (never pruned) or a ValidBefore that audit's re-derivation from the log refuses |
