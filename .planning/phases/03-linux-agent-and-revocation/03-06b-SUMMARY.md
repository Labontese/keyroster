---
phase: 03-linux-agent-and-revocation
plan: 06b
subsystem: revocation
tags: [krl, revocation, restore, recovery, signer, audit, server, cli, golden-vectors, fuzz]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-03b: every revocation target, v2 installation-bound revoke requests, krl.Parse, the restore stop that 03-06c replaces; 03-03: krl.PublishSet, Prunable, EntryLive, the KRL manifest, publishKRLLocked and loggedRevocations; 03-06: ordering only"
provides:
  - "keyroster-server's durable copy <state-dir>/krl-served.json: verified against the signer's trust bundle and written before any route serves a KRL; a lower version, or the same version with other bytes, is never served (503); a damaged copy stops the server at start"
  - "Leaf kind 15 revocation_recovery (tlog.RecoveryBody, DecodeRecoveryBody, MaxRecoveryEntries 1<<16, MaxRecoveryBody 11 MiB); tlog Kind validity is the explicit set 1-10 and 15"
  - "wire.RecoveryRequest under keyroster/revoke-recovery/v1 (file form Marshal / ParseRecoveryRequest, logged form SigningBytes / ParseRecoverySigningBytes), RecoveryImport, RecoveredCertificate and their caps"
  - "krl.RecoveryEntries, RecoveredCert, CertLookup, ErrRecoveryTooLarge, MaxRecoveryEntries: the one derivation rule the signer, audit verify and the CLI share"
  - "Signer.RecoverRevocations and RecoveryResult; kind 15 in the start-up rebuild (rebuildLogFrom) and in appendLocked"
  - "keyroster-signer recover-revocations --state-dir DIR (stdin, state lock, signer.New, never Serve)"
  - "keyroster revoke recover --restored --saved [--krl ...] [--revoke-lost ...] [--yes] [--admin-key] --out (offline, root-pinned, admin-signed)"
  - "audit: verifyRecovery, Options.CertificatesFrom, Report.Certificates, Report.LastKRL, Report.Bundle, Report.Recoveries; the export renders kind 15 as counts only"
  - "serverclient.DecodeKRLDocument (strict)"
  - "Golden vectors test/vectors/leaf_revocation_recovery_v1.hex and recovery_request_signing_v1.hex; fuzz targets FuzzParseRecoveryRequest and FuzzParseRecoverySigningBytes; kind 15 in FuzzDecodeLeaf"
affects: [03-06c, 03-07, 03-09, 03-10, 03-11, 03-12, 03-13, 03-15]

actuals:
  tokens: 57352
  tasks: 4
  commits: 5
plan_head_before: d415817d42ad722e11502b279f61a09e84800b19
plan_head_after: c39d09c360539fb987a135c43bd643db57a155f1

tech-stack:
  added: []
  patterns:
    - "One derivation rule in internal/krl (RecoveryEntries) called by the signer that writes the entries, by audit verify that re-derives them and by the CLI that previews them"
    - "A recovery is bound to exactly one log state (installation, restored size and root), so it is single-use"
    - "The serial union is counted on merged intervals before any range is expanded"
    - "keyroster-server writes what it serves (temporary file with O_EXCL and 0600, fsync, rename, directory fsync) before it serves it"

key-files:
  created:
    - internal/wire/recovery.go
    - internal/krl/recovery.go
    - internal/signer/recovery.go
    - internal/signer/recovery_test.go
    - internal/audit/recovery.go
    - cmd/keyroster-signer/recover.go
    - cmd/keyroster/recover.go
    - cmd/keyroster/recover_test.go
    - test/e2e/recovery_test.go
    - test/vectors/leaf_revocation_recovery_v1.hex
    - test/vectors/recovery_request_signing_v1.hex
  modified:
    - internal/tlog/leaf.go
    - internal/tlog/leaf_test.go
    - internal/tlog/fuzz_test.go
    - internal/wire/wire_test.go
    - internal/wire/fuzz_test.go
    - internal/krl/krl_test.go
    - internal/signer/logstate.go
    - internal/signer/signer.go
    - internal/audit/verify.go
    - internal/audit/revoke.go
    - internal/audit/export.go
    - internal/audit/verify_test.go
    - internal/server/revoke.go
    - internal/server/server.go
    - internal/server/revoke_test.go
    - internal/serverclient/admin.go
    - cmd/keyroster-server/serve.go
    - cmd/keyroster/revoke.go
    - cmd/keyroster/dirpipe_test.go
    - docs/runbooks/server-install.md
    - test/capslock/keyroster-signer.json

key-decisions:
  - "03-06b: lost certificates still valid follow the owner's answer revoke-users-list-others (2026-10-26, PR #66): every lost user certificate live at the CLI's clock minus 300 s is revoked; host and machine certificates are carried and listed, and revoked only when --revoke-lost names them"
  - "03-06b: a key-ID entry's ValidBefore also requires the certificate's CA key to equal the entry's, besides the serial its key ID names and the equal key ID; otherwise 0 (fail-safe, the same rule in signer, audit and CLI)"
  - "03-06b: keyroster revoke recover decides the installation-ID rule in one branch: no installation ID in the restored bundle refuses recovery_installation_lost when the saved bundle has one or any --krl document was given, and prints nothing to recover otherwise"
  - "03-06b: with no KRLFile (the tests' newServer only; New refuses it) keyroster-server skips the whole keep step: verification, the version rule and the write"
  - "03-06b: the signer keeps the parsed trust bundle it loaded at start (Signer.bundle), so krl.VerifyManifest checks an import against the ops key of the bundle in force"

patterns-established:
  - "Mutants are applied by a script, run against the named test and restored byte for byte; a mutant that does not compile is rewritten until it compiles, so no kill is a build failure"

requirements-completed: []

coverage:
  - id: D1
    description: "keyroster-server keeps the KRL it serves in krl-served.json, verified and written before it is served; lower or equal-but-different versions are not served; a damaged copy stops the server"
    requirement: "REVOKE-03"
    verification:
      - kind: unit
        ref: "internal/server/revoke_test.go#TestKRLServedCopy"
        status: pass
      - kind: e2e
        ref: "test/e2e/recovery_test.go#TestRestoreRecoveryTracer (CI E2E run 40482634660, both lanes)"
        status: pass
    human_judgment: false
  - id: D2
    description: "A signer restore that lost a revocation made after the saved export is recovered: one revocation_recovery entry, one krl_publish above every import, ssh-keygen -Q refuses the certificate, audit verify proves it"
    requirement: "REVOKE-01"
    verification:
      - kind: unit
        ref: "internal/signer/recovery_test.go#TestRecoveryTracer, TestRecoverRevocations"
        status: pass
      - kind: e2e
        ref: "test/e2e/recovery_test.go#TestRestoreRecoveryTracer (CI E2E runs 40479141274 and 40482634660, both lanes)"
        status: pass
    human_judgment: false
  - id: D3
    description: "audit verify re-derives every revocation_recovery entry and refuses every field a signer could not have written; the publish after a recovery is above every import"
    requirement: "REVOKE-03"
    verification:
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyRecovery, TestVerifyRecoveryExportLines, TestRecoveryLeafFitsExportLine, TestVerifyCertificatesFrom, TestVerifyLastKRL"
        status: pass
    human_judgment: false
  - id: D4
    description: "keyroster revoke recover: offline, every input read first, prefix rule, installation-ID rule, the owner's lost-certificate answer, one admin-signed request"
    requirement: "REVOKE-01"
    verification:
      - kind: unit
        ref: "cmd/keyroster/recover_test.go#TestRevokeRecover"
        status: pass
    human_judgment: false
  - id: D5
    description: "server-install.md: krl-served.json, the start refusal and the 503"
    verification: []
    human_judgment: true
    rationale: "A runbook's wording needs a human reader; restoring the file from a backup is UNVERIFIED"

duration: 100min
completed: 2026-10-27
status: complete
---

# Phase 3 Plan 06b: Restore Recovery Summary

**Revocations that a signer restore lost can now be recovered, and the code is complete.**

- keyroster-server keeps every KRL it serves in `krl-served.json`, verified and written before it serves it.
- `keyroster revoke recover` imports two KRLs into one admin-signed request, offline: the newest KRL keyroster-server served, and the saved export's last KRL. It adds the lost certificates from the saved export.
- `keyroster-signer recover-revocations` applies the request in one transaction, under the state lock. The transaction writes one `revocation_recovery` entry and publishes one KRL, above every imported version.
- `keyroster audit verify` re-derives the whole recovery from the log.

The restore procedure that runs these commands is 03-06c. Until 03-06c merges, 03-03's stop stays in signer-install.md.

Lost-certificates answer: revoke-users-list-others
Ägarens ordagranna svar (AskUserQuestion, 2026-10-26): "Återkalla användarnas (Recommended)"

## Owner attention first

- **Lost certificates follow your Task 1 answer.** Every lost user certificate that is still live is revoked. Lost host and machine certificates are carried and listed with their public keys, and are revoked only when `--revoke-lost SERIAL` names them. The signer enforces the user rule (`recovery_user_certificate_kept`), and so does audit verify.
- **`recover-revocations` never starts Serve.** It calls `signer.New` (every start-up check) and `RecoverRevocations`, and nothing else. The only KRL it publishes is the recovery's, inside its one transaction.
- **`nothing to recover` never skips a supplied server copy.** It is printed only when neither bundle has an installation ID and no `--krl` document was given. A `--krl` document is read and decoded before anything is decided. The carry-over mutant (the `--krl` clause dropped) is killed by `TestRevokeRecover/krl_given_without_installation_id_refused`.
- **Look closely at:** the server skips its whole keep step when `KRLFile` is empty. Only the tests' `newServer` can do that; `New` refuses it. Also check the key-ID ValidBefore rule, which is stricter than the plan text (deviation 6).

## Output lines and refusal names (for 03-06c's runbook and pins)

`keyroster revoke recover` prints, on stdout, in this order:

```
installation: <installation id>
restored log: <n> entries, root <std base64>; saved log: <n> entries
import: saved export, log entry <i>: KRL v<v>, issued at <RFC 3339>: <n> serials, <n> key IDs, <n> keys
import: <--krl path>: KRL v<v>, issued at <RFC 3339>: <n> serials, <n> key IDs, <n> keys
lost certificates: none
lost certificate: serial <s>, <user|host|machine>, subject <sub>, key SHA256:<fp>, valid before <unix s> (<live|expired>): revoke
lost certificate: serial <s>, <host|machine>, subject <sub>, key SHA256:<fp>, valid before <unix s> (<live|expired>): keep; public key <authorized_keys line>; revoke later with: keyroster revoke key <file with this public key>
entries: <n>; the KRL the recovery publishes must be above v<highest imported version>
Sign this recovery? [y/N]        (on a terminal, without --yes)
wrote the signed recovery request to <out>; apply it on the signer host, under the hold, with: keyroster-signer recover-revocations --state-dir DIR < <out>
```

With neither bundle carrying an installation ID and no `--krl` document, it prints exactly this line, writes no file and exits 0:

```
nothing to recover: neither export's trust bundle has an installation ID and no server KRL copy was given, so no KRL was ever published
```

Its refusals exit 1 as `keyroster revoke: refused (<name>): <reason>`:

- `recovery_installation_lost`: the restored bundle has no installation ID, and either the saved bundle has one or a `--krl` document was given;
- `recovery_import_invalid`: a `--krl` document that does not decode, or an import that does not verify under the restored bundle and its installation ID, does not parse, or has a header version other than its manifest's;
- `recovery_fork`: neither export extends the other;
- `recovery_revoke_lost_unknown`: `--revoke-lost` names a serial that is not a lost host or machine certificate;
- `recovery_too_large`: more than 65536 entries, or a request above 9 MiB.

An export that does not verify on the saved pins exits 1 with `... does not verify on your trust pins: ...; escalate, do not release the hold`. An existing `--out` exits 1 with `--out <file> exists; ...`.

`keyroster-signer recover-revocations --state-dir DIR < request` prints on success:

```
recovered: <n> entries from <n> imported KRLs, <n> lost certificates revoked, <n> kept; KRL v<v> (log entries <recovery leaf>, <publish leaf>)
```

A refusal exits 1 as `keyroster-signer recover-revocations: refused: <name>: <reason>`. Unavailable states are written `unavailable: <name>`. The names are:

- `recovery_malformed`
- `krl_no_installation_id` (unavailable)
- `recovery_installation_mismatch`
- `recovery_log_mismatch`
- `duplicate_request`
- `recovery_evidence_invalid`
- `recovery_import_invalid`
- `recovery_certificate_invalid`
- `recovery_certificate_not_lost`
- `recovery_user_certificate_kept`
- `recovery_too_large`
- `recovery_version_not_above_import`: the reason ends `wait <n> s (until the clock passes it) and run it again`
- `ops_key_unavailable` (unavailable)
- `trust_changed` (unavailable)

keyroster-server logs these lines and answers 503:

- `KRL not served: version X is below version Y this server served (a signer restored without the recovery? signer-install.md)`
- `KRL not served: version X has other bytes than the version X this server served`
- `KRL not served: it does not verify ...`
- `KRL not kept: ...`

A damaged copy stops the start with `server: <path> does not parse: ... keep it, do not delete it, and see docs/runbooks/server-install.md`.

## Performance

- **Duration:** about 100 min
- **Started:** about 2026-10-27T08:10Z
- **Completed:** 2026-10-27
- **Tasks:** 4 of 5 (Task 5 is the owner's merge gate)
- **Files:** 32 changed (the plan named 28; deviations 1, 2, 4 and 16 add the other 4), plus this SUMMARY and the tracking files

## Task Commits

1. **Task 1 (pre-answered decision):** no commit. The answer file was verified: line 1 is `revoke-users-list-others`, and line 2 is present.
2. **Task 2 (tracer):** `5c017e1` (feat): recover revocations a signer restore lost, from the server's KRL copy. Follow-up `1325c53` (fix): the e2e tracer waits for the clock to pass the imported KRL version.
3. **Task 3:** `44be80e` (test): refusals, pending-recovery cases, derivation cases, the server copy, vectors and fuzz targets.
4. **Task 4:** `760c021` (docs): krl-served.json in the server's state directory. Follow-up `c39d09c` (chore): the capslock baseline gains `internal/krl CAPABILITY_REFLECT`.

**Plan metadata:** the `docs(03-06b): complete restore-recovery plan` commit that carries this file, STATE.md and ROADMAP.md.

## Tracer gate (Task 2)

- **Local:** `bash scripts/linux.sh 'go test -race -count=1 ./internal/tlog/... ... ./cmd/keyroster-server/...'` passed. `-run TestRecoveryTracer -v` printed `--- PASS: TestRecoveryTracer`.
- **First E2E run, 40478259328, on `5c017e1`:** `TestRestoreRecoveryTracer` failed on both lanes with `recovery_version_not_above_import: ... wait 2 s`. That is the designed refusal: KRL versions are time-derived in whole seconds, and the test ran the recovery within the second of the revocation it imported. Every other e2e test passed.
- **Fix `1325c53`:** the test now waits for the clock to pass the imported version, as the refusal asks.
- **Second E2E run, 40479141274, on `1325c53`:** both jobs succeeded, `e2e (9.5p1)` and `e2e (10.5p1)`. Each job's log has `--- PASS` for `TestRestoreRecoveryTracer`, `TestRevokeSerialEndToEnd`, `TestRestoreRunbookChecks` and `TestRestoreReplaysLostDirectory`, and no `--- FAIL`. Task 3 started only after this run.

## What ran and what did not

**Ran (2026-10-27, WSL Ubuntu and Windows 11, Go 1.27.3):**

- **Full gate** in WSL Ubuntu at `760c021`, through a script file because `scripts/linux.sh` expands `$VAR` in the outer shell:
  - `go test -race -count=1 ./...` passed;
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/` passed;
  - gofmt is clean;
  - golangci-lint reports 0 issues, and `go vet` and golangci-lint also pass with `GOOS=windows` and `GOOS=darwin`;
  - dep-firewall and testonly-firewall are clean;
  - capslock reported one new pair (deviation 16). The baseline was updated in `c39d09c`, and the check then passed: signer 92/92, agent 23/23, EXEC only through execsite.
- **Task 3's verify commands:**
  - `go test -count=1 -v -run 'Recovery|Recover|KRLServedCopy|CertificatesFrom|LastKRL'` on tlog, wire, krl, audit, server and cmd/keyroster passed on Windows, with every `--- PASS` line the plan names;
  - `bash scripts/linux.sh 'go test -race -count=1 -v -run "TestRecoverRevocations|TestRecoveryTracer" ./internal/signer/'` passed with no DATA RACE, with all six named subtests;
  - FuzzParseRecoveryRequest, FuzzParseRecoverySigningBytes and FuzzDecodeLeaf each ran 20 s with no failure.
- **CI E2E**, `workflow_dispatch`:
  - run 40479141274 on `1325c53` (the tracer gate);
  - run 40482634660 on `760c021`, the code head before the capslock baseline commit.
  Both jobs succeeded in each run, `e2e (9.5p1)` and `e2e (10.5p1)`. Each job's log has `--- PASS` for `TestRestoreRecoveryTracer`, `TestRevokeSerialEndToEnd`, `TestRestoreRunbookChecks` and `TestRestoreReplaysLostDirectory`, and no `--- FAIL`. `c39d09c` changes only `test/capslock/keyroster-signer.json`. The PR's required checks run e2e again on the PR head.
- **Mutants:** 40 were applied, run and restored (section TDD Gate Compliance).
- **03-06c's files are untouched:** signer-install.md, revoke.md, test/e2e/restore_test.go and test/systemd/smoke.sh equal their merge base with origin/main, and the todo is still in pending/.

**UNVERIFIED (not run here):**

- **The restore procedure through the runbook, with sshd.** That is 03-06c's drill (TestRestoreRecoversLostRevocations).
- **`krl_no_installation_id` in `RecoverRevocations`.** It is the first check after the parse, but no test opens a signer whose bundle has no installation ID and then calls the recovery.
- **Request-ID replay of a recovery in audit verify.** The check exists (`request ID ... replayed`), but no test logs two recoveries with one request ID.
- **Restoring `krl-served.json` from a backup** (server-install.md labels it UNVERIFIED).
- **03-13's ops-key rotation case.** An import under an ops key that only a lost bundle names is refused with a message for that case. It is tested with a foreign ops key, not a rotated one, which cannot exist before 03-13.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The signer keeps the trust bundle it loaded**
- **Found during:** Task 2.
- **Issue:** `krl.VerifyManifest` needs the bundle (its ops key) to check an import. The Signer kept only the version and the installation ID.
- **Fix:** `Signer.bundle`, set in `New` from the bundle `loadTrust` returns.
- **Files modified:** internal/signer/signer.go (not in the plan's file list).
- **Commit:** 5c017e1

**2. [Rule 3 - Blocking] A strict KRLDocument decoder in serverclient**
- **Issue:** the plan names "the serverclient.KRLDocument decoder", but serverclient decoded the document with a plain `json.Unmarshal` inside its client.
- **Fix:** `serverclient.DecodeKRLDocument`, which refuses unknown fields, trailing data, an empty field and more than `krl.MaxKRLResponse` bytes. keyroster-server reads its copy with it, and `revoke recover` reads every `--krl` file with it.
- **Files modified:** internal/serverclient/admin.go (not in the plan's file list).
- **Commit:** 5c017e1

**3. [Rule 1 - Bug] The e2e tracer ran faster than the version clock**
- **Found during:** Task 2, first E2E run 40478259328.
- **Fix:** the test waits until the clock is past the imported version. No product change: the refusal is the designed one.
- **Commit:** 1325c53

**4. [Rule 3 - Blocking] The CLI tests needed the bundle's online keys**
- **Issue:** `TestRevokeRecover` builds signed exports under the dirEnv bundle that the CLI config pins, so it needs the log, CA and ops keys. dirEnv kept only the ops key.
- **Fix:** dirEnv keeps them as `caKeys`.
- **Files modified:** cmd/keyroster/dirpipe_test.go (not in the plan's file list).
- **Commit:** 44be80e

### Plan details resolved

**5. internal/signer/recovery_test.go is `//go:build linux`.** `restart_after_recovery` starts Serve through `serveKRL`, which is Linux-only, like krlloop_test.go. Every signer verify command runs through `scripts/linux.sh`, as the plan writes them.

**6. The key-ID ValidBefore rule also requires the CA key to match.** The plan's text names the serial that the key ID names and an equal key ID. `krl.RecoveryEntries` additionally requires the certificate's CA key to equal the entry's, as for serial entries. This is stricter and fail-safe: a mismatch gives 0, which is never pruned. One function holds the rule, so signer, audit and CLI agree.

**7. Two CLI refusal names that the plan left unnamed.** The plan's "the fork of the prefix rule" refusal is named `recovery_fork`. The refusal of a `--revoke-lost` serial that is not a lost host or machine certificate is named `recovery_revoke_lost_unknown`. 03-06c quotes them (section above).

**8. The kind-15 export line carries three fields beyond the plan's list:** `policy_version`, `resolved_at` and `request_id`. None of them is a key that Verify binds (`kind`, `bundle_version`, `version`, `directory`, `sigs`). TestVerifyRecoveryExportLines checks that.

**9. `RecoveryRequest.SigningBytes` returns `([]byte, error)`.** It refuses a request above `MaxRecoveryRequest` instead of returning nil, as the plan asks ("refused, never truncated").

**10. tlog's revoke and recovery bodies share one codec** for evidence and entries (`readEvidence`, `readEntries`, `addEntries`). The revoke encoding is unchanged: the 03-03 golden vectors still pass byte for byte, and `test/vectors/` lists only the two new files.

**11. The serial high-water mark is read outside the transaction.** `signerdb` has no `LastSerialTx`, and adding one would touch signerdb. The read happens under `s.mu`; in production `recover-revocations` also holds the state lock and never serves. The issuance-table check runs inside the transaction.

**12. The two PR #66 finding-1 mutants are one clause here.** The plan names two mutants: the `--krl` clause dropped from `recovery_installation_lost` (the carry-over), and the `--krl` condition dropped from the `nothing to recover` exit. In this code both are the same condition, `saved.Bundle.InstallationID != "" || len(docs) > 0`, whose two branches are the refusal and the exit. So one mutant covers both, and `krl_given_without_installation_id_refused` kills it. The test also asserts the refusal name, not only the exit code.

**13. With an empty `KRLFile`, keyroster-server skips the whole keep step**, not only the write. Only the tests' `newServer` reaches that path; `New` refuses an empty `KRLFile`. The existing cache tests keep their unsigned fixtures that way. TestKRLServedCopy runs the whole step with real signed KRLs.

**14. Executor protocol: `requirements mark-complete` is not run.** The plan says `requirements-completed` stays empty: REVOKE-01 completes in 03-11 and REVOKE-03 in 03-07.

**15. The PR is opened without auto-merge** (orchestrator directive). The orchestrator enables it after its pre-merge review.

**16. capslock reported one new pair, `internal/krl CAPABILITY_REFLECT`.** The plan expected none. This is not a new capability of the signer binary, which already reached REFLECT through x/crypto/ssh's key parsing. Package mode lists the packages on one example path per capability. The signer now calls `krl.Parse` and `krl.RecoveryEntries` on imported KRLs, so that example path passes through internal/krl, which had no entry in the baseline before. The baseline is updated in `c39d09c`, for review in this PR, and that commit adds only this pair.

**Total deviations:** 16. Of these, 1 is Rule 1, 3 are Rule 3, 10 are plan details and 2 are process (14, 15).

## TDD Gate Compliance (mutants)

A script applied each mutant to the committed source, ran the named test and restored the file byte for byte. After the run, `git diff` showed no change to any source file. Five mutants first failed to compile (S7, S9b, A8, K2, K3: an unused import or variable). They were rewritten until they compiled, so no kill below is a build failure.

| Mutant | Removed or changed | Killed by |
|---|---|---|
| S1 | signer: the installation binding | TestRecoverRevocations/recovery_installation_mismatch |
| S2 | signer: the restored-root binding (size kept) | TestRecoverRevocations/recovery_log_mismatch (root-only case) |
| S2b | signer: the restored-size binding (root kept) | TestRecoverRevocations/recovery_log_mismatch (size-only case) |
| S3 | signer: the unused-request-ID check | **survived**: the revoke_request PRIMARY KEY refuses the same ID inside the transaction (`duplicate_request`, nothing written). This is a defence-in-depth backstop, so the mutant is equivalent |
| S4 | signer: the admin evidence | TestRecoverRevocations/recovery_evidence_invalid |
| S5 | signer: the import's manifest verification (ParseManifest only) | TestRecoverRevocations/recovery_import_invalid (ops key of another bundle, another installation) |
| S6 | signer: header version equals manifest version | TestRecoverRevocations/recovery_import_invalid/header_version_differs |
| S7 | signer: a CA key of the certificate's role | TestRecoverRevocations/recovery_certificate_invalid (not a CA key, host role under the user CA) |
| S8 | signer: the key ID names the serial | TestRecoverRevocations/recovery_certificate_invalid/key_id_names_another |
| S9 | signer: above the high-water mark | TestRecoverRevocations/recovery_certificate_not_lost/at_or_below_high_water |
| S9b | signer: not in the issuance table | **survived**: every issued serial is at or below the high-water mark, so the issuance-table check is redundant with S9. The mutant is equivalent |
| S10 | signer: the user-certificate rule | TestRecoverRevocations/recovery_user_certificate_kept |
| S11 | signer: the entry cap's name | TestRecoverRevocations/recovery_too_large |
| S12 | signer: the version floor | TestRecoverRevocations/recovery_version_not_above_import |
| K1 | krl: ValidBefore needs the same CA key (carried certificate) | TestRecoveryEntries/serial_ca_mismatch_vb_zero |
| K2 | krl: ValidBefore needs the same CA key (lookup) | TestRecoveryEntries/serial_ca_mismatch_vb_zero, key_id_other_text_vb_zero |
| K3 | krl: a key-ID entry's ValidBefore needs an equal key ID | TestRecoveryEntries/key_id_other_text_vb_zero |
| K4 | krl: fingerprint sections refused | TestRecoveryEntries/hash_section_refused |
| A1 | audit: the restored root | TestVerifyRecovery/recovery_restored_root_mismatch |
| A2 | audit: the restored size | TestVerifyRecovery/recovery_restored_size_mismatch |
| A3 | audit: the installation | TestVerifyRecovery/recovery_other_installation |
| A4 | audit: the admin evidence | TestVerifyRecovery/recovery_not_admin |
| A5 | audit: resolution time not after the leaf | TestVerifyRecovery/recovery_resolved_after_leaf |
| A6 | audit: the import's manifest verification | TestVerifyRecovery/recovery_import_unsigned |
| A7 | audit: its own fingerprint-section check | **survived**: krl.RecoveryEntries refuses the same import with the same words. audit's check only gives the earlier message, so the mutant is equivalent |
| A8 | audit: a CA key of the carried certificate's role | TestVerifyRecovery/recovery_certificate_forged |
| A9 | audit: the carried certificate is new to the log | TestVerifyRecovery/recovery_certificate_already_logged |
| A10 | audit: the user-certificate rule | TestVerifyRecovery/recovery_user_certificate_kept |
| A11 | audit: the entries re-derived | TestVerifyRecovery/recovery_entries_tampered, recovery_entry_vb_tampered, recovery_entry_added_unbound |
| A12 | audit: the krl_publish due after a recovery | TestVerifyRecovery/recovery_unpublished_at_end |
| A13 | audit: the publish above every import (floor) | TestVerifyRecovery/recovery_publish_not_above_import |
| A14 | audit: carried certificates added to the issuance (the rejected alternative) | TestVerifyRecovery/recovery_after_recovery_vb_zero_accepted |
| A15 | audit: recovery-carried certificates dropped from Report.Certificates (PR #66 finding 2) | TestVerifyCertificatesFrom/recovery_carried_listed and TestRevokeRecover/restore_before_recovery_relists_carried |
| V1 | server: the lower-version refusal | TestKRLServedCopy/lower_version_not_served |
| V2 | server: the equal-version-other-bytes refusal | TestKRLServedCopy/equal_version_other_bytes_not_served |
| V3 | server: verify before keep | TestKRLServedCopy/unverified_not_served |
| V4 | server: keep before serve | TestKRLServedCopy/write_failure_not_served |
| C1 | CLI: the `--krl` clause of `recovery_installation_lost` / the `nothing to recover` exit (PR #66 finding 1, the carry-over) | TestRevokeRecover/krl_given_without_installation_id_refused |
| C2 | CLI: live user certificates revoked by default | TestRevokeRecover/user_live_revoked_by_default |
| C3 | CLI: `--revoke-lost` names a lost host or machine certificate | TestRevokeRecover/revoke_lost_unknown_serial_refused |

All five mutants the plan requires are killed: the restored-root binding (S2), the user-certificate rule (S10, A10), the ValidBefore rule in RecoveryEntries (K1 to K3), the version floor (S12, A13) and the server's lower-version refusal (V1). So are the two PR #66 mutants (C1, A15). Three of the 40 mutants survived, and each is equivalent: a second check refuses the same input (S3, S9b, A7).

Not run as mutants: the range-cap guard in RecoveryEntries. Removing it expands [1, 2^64 - 1] and never ends. `range_cap_refused_before_allocation` covers it instead, with an allocation bound.

## Issues Encountered

- WSL started from Python did not get Go on its PATH, so the first signer mutant run reported "unclear" for all of them. The run script now sets PATH itself, and the signer mutants were re-run.

## Known Stubs

None.

## Threat Flags

None. The new surfaces are those of the threat model:

- the server's file write in its own state directory (T-03-270);
- the offline CLI command;
- the signer subcommand under the state lock.

capslock: one new (package, capability) pair, `internal/krl CAPABILITY_REFLECT` (deviation 16). It is not a new capability of the signer binary.

## Next Phase Readiness

- 03-06c can start once this PR merges. It quotes the output lines and refusal names above.
- Its pins should match `recovered: ...` and `nothing to recover: ...` exactly.
- 03-07's agent state route must serve KRLs through `currentKRL`, so that each one is kept first. Its cross-plan note says so.

## Self-Check: PASSED

- All 11 created files exist, among them the two golden vectors, which `git ls-files` lists once committed.
- All five commits are ancestors of HEAD: `5c017e1`, `1325c53`, `44be80e`, `760c021`, `c39d09c`.
- The acceptance greps of Tasks 2 to 4 print what the plan requires:
  - one `func RecoveryEntries`, called by signer and audit;
  - `KindRevocationRecovery Kind = 15`;
  - kind 15 in logstate.go, and `case tlog.KindRevocationRecovery` in verify.go, with the `not verifiable by this version` default kept;
  - `krl-served.json` in serve.go, and `VerifyManifest` in server/revoke.go;
  - `"recover"` and `"recover-revocations"`;
  - no migration;
  - no existing vector changed;
  - `krl-served.json` in server-install.md, with `run in CI (internal/server tests, 03-06b)`;
  - 03-03's stop still in signer-install.md.
