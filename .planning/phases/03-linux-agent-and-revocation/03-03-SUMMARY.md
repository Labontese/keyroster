---
phase: 03-linux-agent-and-revocation
plan: 03
subsystem: revocation
tags: [krl, revocation, audit, signer, wire, fuzz, ssh-keygen-oracle, restore]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-01: KRL encoder and manifest, revoke serial, revoke and krl_publish leaves, installation ID; 03-02: checkGrepFields, the restore runbook and restoreSavedGreps"
provides:
  - wire TargetKeyID (2), TargetKey (3), TargetSubject (4) with SubjectKind, ParseRevokeSigningBytes, RevokeResponse.SerialCount and Serials (at most 4096)
  - krl.Parse (strict, intervals, MaxParsedEntries), CertSection with key IDs, Set.Keys, EntryLive, Prunable, PublishSet, RoleCAKeys, InstallationKeys
  - signer key-ID, key and user-subject revocation; subject splits above 4096 entries; krl_version = max(prev + 1, issued_at); krlLoop (start-up publish and hourly re-publish)
  - signerdb.LiveIssuanceForSubjectTx and KeyIDValidBeforeTx
  - audit verify checks for revoke (9) and krl_publish (10) entries; export renders both kinds
  - signer-install.md stops a restore that lost a revocation (restoreSavedGreps pins the count)
affects: [03-03b, 03-05, 03-07, 03-09, 03-11, 03-12, 03-13, restore-recovery]

actuals:
  tokens: 52035
  tasks: 3
  commits: 3
plan_head_before: b4befb84e9e3c7fc01f86ac0d136c2675c320e65
plan_head_after: f8b1448cd1cc0cc564a176df10db4e805c729217

tech-stack:
  added: []
  patterns:
    - "One liveness rule (krl.EntryLive), one pruning rule (krl.Prunable) and one set builder (krl.PublishSet), called by both the signer and audit verify"
    - "Parsed KRLs keep serials as intervals; every entry is counted against MaxParsedEntries before it is appended"
    - "Every bundle-derived key set that signer and audit both need comes from one krl helper (RoleCAKeys, InstallationKeys)"

key-files:
  created:
    - internal/krl/parse.go
    - internal/krl/fuzz_test.go
    - internal/krl/testdata/fuzz/FuzzParseKRL/sshkeygen_bitmap
    - internal/audit/revoke.go
    - internal/signer/krlloop_test.go
    - test/vectors/krl_full_v1.hex
    - test/vectors/revoke_request_signing_v2.hex
  modified:
    - internal/krl/krl.go
    - internal/wire/revoke.go
    - internal/signer/revoke.go
    - internal/signer/krl.go
    - internal/signer/server.go
    - internal/signer/signer.go
    - internal/signer/refusal.go
    - internal/signerdb/revocation.go
    - internal/audit/verify.go
    - internal/audit/export.go
    - docs/runbooks/revoke.md
    - docs/runbooks/signer-install.md
    - test/e2e/revoke_test.go
    - test/e2e/restore_test.go
    - test/e2e/audit_test.go

key-decisions:
  - "The CA keys a key-ID revocation covers, and the keys a key revocation refuses (key_is_ca_of_this_installation), are every key the bundle in force names, CA keys in any state (active, next, retired); one helper each in internal/krl serves signer and audit"
  - "republishIfDue reads the immutable installation ID before it takes s.mu, so a signer without one never waits for the lock at Serve start"
  - "subject_kind_unsupported and key_is_ca_of_this_installation are classified malformed (HTTP 400 through keyroster-server), like unknown_serial"
  - "RevokeResponse lists exactly min(SerialCount, 4096) serials, ascending; any other length is refused (stricter than the plan's count-below-list rule)"
  - "krl.Parse also refuses non-zero header flags and a certificate section without a CA key (wildcard CA); ssh-keygen -k writes neither for our spec lines"

patterns-established:
  - "A test that needs a log entry no signer path can produce (ValidBefore = CertTimeInfinity) logs it through appendLocked and checks signer and audit at the PublishSet level, and says so"

requirements-completed: []

coverage:
  - id: D1
    description: "Subject revocation of a user on a real signer: both of alice's certificates refused by ssh-keygen -Q, bob's accepted, krl.Parse reads both serials back, audit verify accepts the exported log"
    requirement: "REVOKE-01"
    verification:
      - kind: integration
        ref: "internal/signer/revoke_test.go#TestRevokeSubjectTracer"
        status: pass
    human_judgment: false
  - id: D2
    description: "Key-ID, key and subject targets in wire and signer: refusals, the 4097-entry split over adjacent leaves with one publish, re-listing, the second sweep after a login between the revoke and the disable"
    requirement: "REVOKE-01"
    verification:
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestRevokeSubject"
        status: pass
      - kind: unit
        ref: "internal/wire/wire_test.go#TestParseRevokeSigningBytes"
        status: pass
      - kind: unit
        ref: "internal/wire/wire_test.go#TestRevokeResponse"
        status: pass
    human_judgment: false
  - id: D3
    description: "F9 resolution time: whole-second boundaries on both sides, a clock rollback audit still accepts (mutant at leaf time killed), an older longer TTL cap found"
    verification:
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestSubjectResolutionTime"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestEntryLive"
        status: pass
    human_judgment: false
  - id: D4
    description: "No published version drops a live entry; unknown ValidBefore and explicit keys never leave; duplicates encode once"
    verification:
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestPublishNeverDropsLiveEntry"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestPublishSetDuplicates"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestPrunable"
        status: pass
    human_judgment: false
  - id: D5
    description: "Strict krl.Parse with named refusals and bounded memory; oracle in both directions against ssh-keygen; FuzzParseKRL; ordering edge; krl_full_v1.hex"
    requirement: "REVOKE-02"
    verification:
      - kind: unit
        ref: "internal/krl/krl_test.go#TestParse"
        status: pass
      - kind: integration
        ref: "internal/krl/oracle_test.go#TestOracleForward"
        status: pass
      - kind: integration
        ref: "internal/krl/oracle_test.go#TestOracleReverse"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestKRLFullGoldenVector"
        status: pass
      - kind: other
        ref: "go test -run NONE -fuzz FuzzParseKRL -fuzztime 20s ./internal/krl/"
        status: pass
    human_judgment: false
  - id: D6
    description: "audit verify checks revoke and krl_publish entries: evidence, resolution-time bounds, entries bound to the request and logged certificates, the numbering rule of Q1, the KRL re-derived from the log; export lines pass Verify"
    requirement: "REVOKE-03"
    verification:
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyRevocations"
        status: pass
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyRevokeSplit"
        status: pass
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyRevokeExportLines"
        status: pass
    human_judgment: false
  - id: D7
    description: "Start-up publish and hourly re-publish (D-10) with the time-derived version; the e2e ripple (revoke serial with audit verify, audit, restore runbook checks) on both OpenSSH lanes"
    verification:
      - kind: unit
        ref: "internal/signer/krlloop_test.go#TestKRLStartupAndRepublish"
        status: pass
      - kind: e2e
        ref: "CI run 40238009268 (e2e 9.5p1 and 10.5p1): TestRevokeSerialEndToEnd, TestAuditVerifiesIssuance, TestRestoreRunbookChecks"
        status: pass
    human_judgment: false
  - id: D8
    description: "signer-install.md stops a restore that lost a revocation; revoke.md and signer-install.md no longer state what 03-03 made false"
    verification:
      - kind: e2e
        ref: "test/e2e/restore_test.go#TestRestoreRunbookChecks (local WSL; CI on the PR)"
        status: pass
    human_judgment: true
    rationale: "A runbook's wording needs a human reader; a restore that actually loses a revocation has not been run (UNVERIFIED)"

duration: 78min
completed: 2026-10-25
status: complete
---

# Phase 3 Plan 03: KRL Core Summary

**The signer revokes by key ID, by key and a whole user subject (its own issuance rows, live at one recorded resolution time, split over 4096-entry leaves), publishes a KRL at its first start and every hour with krl_version = max(prev + 1, issued_at), and `keyroster audit verify` now re-derives every revoke entry from the admin-signed request and every KRL from the logged revocations. A strict, fuzzed `krl.Parse` agrees with ssh-keygen in both directions.**

## Performance

- **Duration:** about 78 min (executor wall clock; CI waits not included)
- **Started:** 2026-10-25T21:17:00Z
- **Completed:** 2026-10-25T22:35Z (before the PR; CI and the merge gate follow)
- **Tasks:** 3 of 4 (Task 4 is the merge gate)
- **Files modified:** 32

## Accomplishments

- **Wire.** Targets key_id (2), key (3) and subject (4). Each target carries exactly its own fields after `Target`; the serial layout keeps its 03-01 bytes (`revoke_request_signing_v1.hex` unchanged). A key must be a plain key in canonical encoding, or a KRL would list bytes sshd never compares. `ParseRevokeSigningBytes` reads the logged request strictly and round-trips with `SigningBytes`. `RevokeResponse` gains `SerialCount` and up to 4096 ascending `Serials`.
- **krl.**
  - `CertSection` (renamed from `CertSerials`, serial-only sections byte-identical) with key IDs in one 0x23 subsection, and `Set.Keys` in one section 2.
  - `EntryLive`, `Prunable` and `PublishSet` are the shared rules.
  - `Parse` reads lists, ranges, bitmaps, key IDs, explicit keys and SHA-1/SHA-256 sections. It keeps intervals and counts every entry against `MaxParsedEntries` (1 << 20) before it appends it.
- **Signer.**
  - Subject resolution goes through `signerdb.LiveIssuanceForSubjectTx`: an exact `substr` prefix compare, `cert.ParseKeyID`, then `krl.EntryLive` at T. There is no issue-time cutoff, and certificates already revoked are re-listed.
  - Above 4096 entries, a subject revocation becomes consecutive revoke leaves of one request with one publish. Each row names the leaf that holds its entry.
  - Key-ID entries are written under every CA key of the role. Each takes the latest logged ValidBefore, or 0.
  - `publishKRLLocked` builds through `PublishSet`.
  - `krlLoop` checks once at Serve start, before the first accept, and then every 60 s.
- **Audit.** `verifyRevoke` and `verifyKRLPublish` in internal/audit/revoke.go, with the report fields `Revocations`, `RevokedEntries`, `KRLPublishes` and `KRLVersion`. Export renders the `target`, `entries` (with `entry_kind`) and `admins` fields, and `krl_version`, `krl_sha256`, `issued_at` and `krl_bundle_version`.
- **Restore stop.** signer-install.md step 2 counts `"kind":"revoke"` in both verified exports and keeps the hold when the saved export has more.

## Task Commits

1. **Task 1 (tracer): revoke by key ID, key and user subject, re-publish hourly and audit every KRL.** `32de819` (feat).
2. **Task 2: strict parser, oracle in both directions, fuzz targets and named refusals.** `ab7822b` (feat).
3. **Task 3: the restore stop and the runbook text 03-03 made false.** `f8b1448` (docs).

**Plan metadata:** the `docs(03-03): complete krl-core plan` commit that carries this file.

## Tracer gate (Task 1)

The tracer's unit verify passed in WSL with `-race`. The E2E workflow was dispatched on the pushed Task 1 head (`32de819`) as **run 40238009268**. Both jobs passed, `e2e (9.5p1)` and `e2e (10.5p1)`. Each job's log has `--- PASS` for `TestRevokeSerialEndToEnd`, `TestAuditVerifiesIssuance` and `TestRestoreRunbookChecks`, and no `--- FAIL`. Task 2 started only after that.

## Refusal details, constants, vectors

- **New signer refusal details:** `subject_kind_unsupported` and `key_is_ca_of_this_installation`. Both are classified malformed. A request that fails `RevokeRequest.Validate` is refused `malformed_request`.
- **Constants:**
  - `wire.MaxRevokeAnswerSerials` = 4096 and `wire.MaxRevokeKeyID` = 1024
  - `krl.MaxParsedEntries` = 1 << 20 and `krl.PruneMargin` = 300
  - the signer re-publishes after 1 h and checks every 60 s
- **Golden vector:** `test/vectors/krl_full_v1.hex`, starting `5353484b524c0a00`. It holds two CA keys from seeds 0x00 and 0x20, serials {5, 6, 9}, a kr1 and a kr2 key ID, and one explicit key. The 03-01 vectors are unchanged (`git diff origin/main` on them is empty).
- **Fuzz seed:** `internal/krl/testdata/fuzz/FuzzParseKRL/sshkeygen_bitmap` is the KRL that `ssh-keygen -k` wrote for a dense run of serials. It holds subsection 0x22, which `TestOracleReverse` asserts on the bytes.
- **Capslock pairs added:** none. `scripts/capslock-check.sh` reports 91 pairs against a baseline of 91, so `--update` was not run. `scripts/dep-firewall.sh` passes, and go.mod is unchanged (no new module).

## Mutant results

Each mutant was applied, run and reverted. `git diff` was empty after each.

- **Audit evaluates subject liveness at the leaf time instead of ResolvedAtSeconds** (`internal/audit/revoke.go`). Killed twice:
  - `TestSubjectResolutionTime/clock_rollback` (signer, via `audit.Verify`): "entry 5 (revoke): lists 1 entries, but the log shows 0".
  - `TestVerifyRevocations/revoke_clock_rollback_accepted` (audit): "entry 2 (revoke): lists 1 entries, but the log shows 0".
  - Both pass without the mutant.
- **Parse's entry cap disabled.** Killed by `TestParse/entry_cap` ("MaxParsedEntries + 1 entries: <nil>, want ErrTooLarge").
- **Parse's lo > hi check disabled.** Killed by `TestParse/range_lo_gt_hi`.
- **Bitmap bits read from the first byte instead of the last.** Killed by `TestOracleReverse/dense_run_bitmap` and `/serials_ids_keys`.
- **The stop sentence moved after the release block** (signer-install.md). Killed by `TestRestoreRunbookChecks` (local WSL run).

## What ran and what did not

**Ran (2026-10-25):**
- **Windows unit tests:** `go test ./...` with `-short`, plus the full krl, wire, audit and signer packages. The krl oracle and the tracer ran with Git's ssh-keygen (OpenSSH 10.5p1).
- **WSL, Ubuntu's ssh-keygen 9.6p1:**
  - `go test -race -count=1 ./...` passes. That includes `revoke_user_over_entry_cap` with 4097 login certificates, about 54 s.
  - `go vet`, `go vet -tags e2e`, gofmt and golangci-lint: 0 issues, also with GOOS=windows and GOOS=darwin.
  - capslock: no new pairs. dep-firewall: OK.
- **Fuzzing:**
  - FuzzParseKRL 20 s, PASS (119 corpus entries including the bitmap seed)
  - FuzzEncodeKRL 10 s, PASS
  - FuzzParseRevokeSigningBytes 20 s, PASS
  - FuzzParseRevokeRequest 10 s, PASS
- **Local e2e (WSL, OpenSSH 10.5p1).** Only the tests that need no keyroster-server, outside any namespace: TestAuditVerifiesIssuance, TestAuditDetectsTampering, TestRefusalsAreAudited, TestTrustFlowEndToEnd, TestServeRefusesWithoutBundle, TestDoctor*, TestAuditLoginAcrossPolicyChange, TestIssueAcceptedBySSHD, TestHostCertificateNoTOFU, TestMachineCAIsSeparate, TestHostCAIsNotUserCA, TestRootRotationLiveSigner, TestSSHDRejects (pty_allowed included), TestSignerRefuses, TestTrustRefuses, TestSoftwareCAEndToEnd, TestLoginSignerEndToEnd, TestRestoreRunbookChecks: all PASS. These are not the evidence (CI is). TestRolesHostPrincipalsEndToEnd and TestRestoreReplaysLostDirectory failed locally only because `keyroster init` cannot resolve `keyroster.localhost` in WSL (deferred-items.md).
- **CI E2E on the Task 1 head:** run 40238009268, both lanes green.

**Not run here (UNVERIFIED in this file):**
- **The e2e_pkcs11 and e2e_tpm lanes.** Their expected entry counts were raised by one for the start-up publish (and the TPM restart publishes nothing). The files compile with their tags. The lanes run as required checks on the PR, so their result is in the merge-gate return, not here.
- **The required checks on the final head.** They run on the PR, with the e2e lanes on the Task 3 commits.
- **The CLI output of `keyroster revoke serial`.** It now reports a time-derived version, `KRL v<seconds>`. Only CI e2e checks it, and the revoke.md sample is illustrative.
- **The homelab.** Every homelab step stays UNVERIFIED until 03-16, and revocations there are still refused until the v4 bundle (03-15).
- **A restore that actually loses a revocation.** Only its runbook text is checked (TestRestoreRunbookChecks). The break-glass access that signer-install.md names has no runbook and is labelled UNVERIFIED there.

## Decisions Made

- **Bundle key sets for revocation.** `krl.RoleCAKeys` (the key-ID CA set) and `krl.InstallationKeys` (the keys the key target refuses) take every key the bundle in force names: CA keys in any state, plus the ops, log and root keys.
  - Today every role has one CA key, so no test tells "active only" from "any state". The choice is deliberate.
  - For key IDs, a superset only adds entries, which is the fail-safe direction.
  - For the key target, it also refuses revoking a next or retired CA key through the user path, because an explicit-key entry on a CA key refuses every certificate it signed. That is 03-13's emergency path.
  - They live in internal/krl, not internal/trust, so signer and audit call one helper and the plan's file list holds.
- **republishIfDue checks the installation ID before it locks.** That ID is fixed for the process. See deviation 3.
- **Stricter than planned.**
  - `RevokeResponse` refuses a list shorter than min(SerialCount, 4096).
  - `Parse` refuses non-zero flags and an empty (wildcard) CA key.
  - Both are fail-closed and accept everything ssh-keygen and our encoder write.

## Deviations from Plan

### Auto-fixed Issues

**1. [Plan check LOW (a), orchestrator] Task 1's PublishSet/Prunable greps inspected comments**
- **Found during:** Task 1 acceptance.
- **Fix:** Ran the call-site greps on production files with comment lines stripped (`grep -v '^[[:space:]]*//'`). No comment can satisfy or break them.
  - `PublishSet` is found in internal/signer/krl.go and internal/audit/revoke.go.
  - `Prunable` appears 0 times in either side's production code, comments included.
  - `EntryLive` appears in internal/signerdb/revocation.go and internal/audit/revoke.go.
- **Committed in:** no file change. The checks are recorded here.

**2. [Plan check LOW (b), orchestrator] Task 1 acceptance named regression tests that Task 2 creates**
- **Fix:** Verified that criterion at Task 2, where the tests exist: TestPrunable, TestPublishSetDuplicates, key_id_unknown_valid_before_kept and valid_before_beyond_row_range_kept (signer and audit), TestPublishNeverDropsLiveEntry and revoke_subject_relist_accepted all pass.
- **Committed in:** ab7822b.

**3. [Rule 1 - Bug] Serve's start-up KRL check waited for s.mu**
- **Found during:** Task 1, WSL race run.
- **Issue:** `TestOverloadDoesNotStallAccept` failed with "connection 33 over capacity: ... i/o timeout". republishIfDue locked s.mu before it checked for an installation ID, so the accept loop never started while the test held the lock.
- **Fix:** Read the immutable `installationID` before locking.
- **Files modified:** internal/signer/krl.go.
- **Verification:** that test and TestKRLStartupAndRepublish pass 3 of 3 with `-race`.
- **Committed in:** 32de819.

**4. [Rule 3 - Blocking] Files outside the plan's list**
- internal/signer/krlloop_test.go is new. The start-up publish test needs `Serve` on a Unix socket, so it is a linux-only file, like status_test.go.
- test/e2e/ca_roles_test.go and test/e2e/trust_flow_test.go: the plan named them as users of `bootstrapLeaves`. Their messages and the kinds list needed the start-up publish.
- internal/krl/krl_test.go and oracle_test.go: changed in Task 1 for the `CertSerials` → `CertSection` rename, so Task 1 compiles.
- internal/audit/verify_test.go in Task 1: the two interim cases became `revoke_unproven_refused` and `krl_publish_unproven_refused`, since the Task 1 verify runs the audit package.
- **Committed in:** 32de819.

**5. [Plan detail] `valid_before_beyond_row_range_kept` cannot be driven through issuance**
- **Issue:** No signer issues a certificate valid until `ssh.CertTimeInfinity`: the TTL caps forbid it.
- **Fix:**
  - The signer case logs one such serial entry through `appendLocked` with its row (valid_before NULL). It republishes 100 years later and checks that krl.Parse still lists the serial.
  - It also compares the KRL built from the leaf view (ValidBefore = infinity) with the row view (0) at each time.
  - The audit case (`TestVerifyKRLPublishBeyondRowRange`) calls `verifyKRLPublish` with the leaf view on a KRL built from the row view.
  - Neither case is a full audit of such a log.

**6. [Plan detail] Additional named cases beyond the plan's list**
- **Audit:** `revoke_key_of_installation_refused`, `revoke_subject_kind_host_refused`, `revoke_not_admin_refused`, `revoke_wrong_namespace_refused`, `revoke_request_replayed_refused`, `krl_publish_early_prune_refused`, `krl_publish_log_index_refused`, `key_id_unknown_valid_before_dropped_refused`.
- **Parse:** `bad_flags`, `wildcard_ca`, `bitmap_wraps`, `bitmap_negative`, `duplicated_sha256`, `sha256_wrong_length`.
- **Signer:** `revoke_by_key_id`, `revoke_by_key`.

---

**Total deviations:** 6. Of these, 2 are orchestrator-noted plan-check fixes, 1 Rule 1, 1 Rule 3 and 2 plan details.
**Impact on plan:** No scope creep and no new module. The CLI commands, the server and client pass-through and the CLI KRL check stay 03-03b's.

## TDD Gate Compliance

- **Order.** Task 2 is `tdd="true"`, but `internal/krl/parse.go` was written before its tests, in the same session and before any Task 2 commit. So no test failed first. There is one `feat(03-03)` commit for Task 2 and no `test(03-03)` RED commit. RED was not faked.
- **Evidence instead.** Four parser mutants and two audit mutants (listed under "Mutant results") show that the named tests check the behaviour they name.
- **The classifier was not used.** Go's test output is not a format `gsd-tools check tdd-red-evidence` reads, and `workflow.tdd_mode` is off.

## Issues Encountered

- **Known limitation: audit of logs written by the 03-01 signer.** The 03-01 signer published every revocation row unpruned. Audit verify now re-derives each KRL with the pruning rule. A 03-01-era log whose later KRL still listed an entry past ValidBefore + 300 s at its issued_at therefore fails audit verify with a digest mismatch. No production log has this shape: the homelab cannot revoke before the v4 bundle (03-15), and every 03-01 e2e log revokes right after issuing. Accepting the unpruned set as an alternative would have been fail-safe, but the plan pins one rule (krl.PublishSet), so it is not done.
- **The audit verify CLI line does not print the new report fields** (revocations, KRL publishes). Its `--json` output already counts both kinds in `kinds`, and the CLI is 03-03b's.

## Known Stubs

None. `RevokeResponse.Serials` is filled by the signer. keyroster-server still copies only the 03-01 fields, which the plan assigns to 03-03b.

## Threat Flags

None beyond the plan's threat model. No new endpoint or file path. The revoke and KRL routes are 03-01's.

## User Setup Required

None.

## Next Phase Readiness

- **03-03b**
  - It carries `SerialCount` and `Serials` through serverclient and internal/server, and adds `keyroster revoke key-id/key/user` with the second sweep.
  - Its CLI KRL check uses `krl.Parse` with `RevokesSerial`, `RevokesKeyID` and `RevokesKey`.
  - It removes revoke.md's `arrives with 03-03`, `which 03-03 adds` and `this version cannot read a KRL`. These are still there on purpose.
- **03-05**
  - It can rely on the no-drop property for intact rows (TestPublishNeverDropsLiveEntry).
  - It validates candidate KRLs with `krl.Parse`.
- **The restore-recovery plan** (todo `2026-10-25-plan-signer-restore-revocation-recovery.md`) must land before 03-07. Until then, signer-install.md stops a restore that lost a revocation.

## Self-Check: PASSED

- **Files:** every file under key-files exists, including test/vectors/krl_full_v1.hex and internal/krl/testdata/fuzz/FuzzParseKRL/sshkeygen_bitmap.
- **Commits:** 32de819, ab7822b and f8b1448 are ancestors of HEAD.
- **Task 1 acceptance:**
  - the case greps print 1 and 1, and the default branch is kept (1)
  - the golden diff is empty
  - the comment-stripped PublishSet, Prunable and EntryLive greps hold (deviation 1)
  - `func ParseRevokeSigningBytes` 1, and `Serials` 16
  - `substr(key_id` 1, and ResolvedAtSeconds is in internal/audit/revoke.go
- **Task 2 acceptance:** every named refusal case is in krl_test.go; the bitmap seed is under testdata/fuzz; the mutant result is recorded above; and the wire test names print.
- **Task 3 acceptance (squashed greps):**
  - prints 0: `Before the first revocation it answers 404`, `KRL v1([^0-9]|$)`, `binary, the current one`, `From the first revocation until 03-03 merges` and `Replay every lost`
  - prints 1 in both runbooks: `take a saved export after every revocation` and `checks revoke and krl_publish entries since 03-03`
  - prints 1: `not verifiable by this version` in signer-install.md, and `the restore lost a revocation: do not release the hold`
  - the pinned count grep is in both files

## Pre-merge review fixes

Review of PR #61 at 4772322 (Claude lenses and Codex, two skeptics per finding). Each fix has a test that failed on the code before it and passes after; "proof" names how that was shown (a mutant of the fix, or the test run against the old code).

**Owner decisions (Daniel, 2026-10-26)**

- **Decision 1, KRL capacity (medium, "one admin can fill the KRL for good"), 03-03 commit a16c6db.** The signer writes a key-ID entry only under the role's CA keys under which its issuance table holds a certificate with that key ID, with that certificate's ValidBefore, so every key-ID entry leaves the KRL once it expires; otherwise `key_id_not_issued` (malformed, 400). Explicit keys never leave, so `krl.CheckExplicitKeys` caps them at `krl.MaxRevokedKeys` = 1000 distinct keys taking at most `krl.MaxRevokedKeyBytes` = 1 MiB (`explicit_key_cap_reached`; a key already revoked passes again). Audit refuses a key-ID entry the log's issuance does not support and a log above either cap. Tests: signer `TestRevokeSubject/key_id_not_issued_refused` (replaces `key_id_unknown_valid_before_kept`) and `explicit_key_cap_reached/{count,bytes}`; audit `key_id_not_issued_refused`, `key_id_not_issued_empty_refused`, `key_id_of_other_role_refused`, `explicit_key_cap_refused`, `explicit_key_cap_relist_accepted`; krl `TestCheckExplicitKeys` (with `worst_case_fits`: the keys at the byte cap plus 2.5 MiB of key IDs encode under MaxKRL). Proof: mutants dropping the vb == 0 skip or the cap call, in signer and in audit, and dropping the byte cap or the dedupe in CheckExplicitKeys, each fail those tests. Threat T-03-211; runbook `explicit_key_cap_reached` section with the residual; restore-recovery todo point 11. **Deviation (Rule 2):** the byte cap is added next to the owner's count, because a revocable key can be 8 KiB (`wire.MaxSubjectKeyLen`), so 1000 keys alone could exceed MaxKRL; the count binds for Ed25519, ECDSA, security-key and RSA keys up to 4096 bits.
- **Decision 2, installation binding (low), 03-03 commit 85538ea.** `keyroster/revoke-request/v2`: `wire.RevokeRequest.InstallationID` is in the signing bytes and the SSHSIG namespace is v2. Marshal and ParseRevokeRequest are v2 only (a 03-01 v1 body does not parse, so an old CLI gets a 400 at keyroster-server, not a named refusal); ParseRevokeSigningBytes still reads v1, only for the serial target, so audit verifies 03-01 logs under the v1 namespace. The signer refuses `revoke_installation_missing` (v1) and `revoke_installation_mismatch` before the evidence check (unauthorized, the T-03-20 pattern); `keyroster revoke serial` fills the ID from the root-pinned bundle; audit refuses a v2 entry for another installation. New golden vector `test/vectors/revoke_request_signing_v2.hex`; `revoke_request_signing_v1.hex` is unchanged. Tests: wire `TestRevokeRequest`, `TestRevokeRequestSigningVector` (v1 and v2), `TestParseRevokeSigningBytes` (v1 targets other than serial, v2 without an ID), fuzz seeds; signer `TestRevoke/installation_binding`; audit `revoke_other_installation_refused`, `revoke_v1_serial_accepted`, `revoke_v1_under_v2_namespace_refused`, `revoke_v2_under_v1_namespace_refused`, `revoke_v1_key_id_refused`; CLI `TestRevokeSerialConfirm/request_names_installation`. Proof: mutants removing each signer check, the audit check, the per-request namespace, the v1 serial-only rule and the CLI's ID each fail those tests. Threat T-03-210; 03-03b-PLAN.md builds v2 requests (one paragraph). The CLI's own refusal when the pinned bundle has no ID is covered by the signer's `no_installation_id_refused` only: no CLI fixture builds a bundle without an ID.

**Fixed without an owner decision**

- **high/medium, audit requires the KRL publication after every revocation, 26809a7.** `revocations.before` and `finish` require the krl_publish entry right after the last revoke entry of each revocation (also after a split subject revocation). Tests: `revoke_unpublished_at_end_refused`, `revoke_published_after_another_entry_refused`, `revoke_followed_by_revoke_refused`, `TestVerifyRevokeSplit/revoke_subject_split_unpublished_refused`; `revoke_clock_rollback_accepted` now publishes. Proof: mutants not setting the pending publish (single and split) or skipping the check at the end each fail them. T-03-13 updated.
- **medium, clock step back, 1ec9897.** republishIfDue treats a negative age since PublishedAt as due. Test: `TestKRLRepublishAfterClockStepBack` (clock 6 h ahead, restart, corrected clock), failed before the fix ("a last publish dated after the clock held off the re-publish"). T-03-18 updated.
- **low, restored revoke count pinned, 424d75b.** `restoreRestoredGreps` pins the three restored-export greps, and the revoke count must come after the saved export's verify and before the lost-revocation stop. Proof: with the restored revoke grep deleted from signer-install.md, the old TestRestoreRunbookChecks passes and the new one fails (run locally in WSL with `-tags e2e -run TestRestoreRunbookChecks`; it needs no sshd).
- **low, CLI and runbook wording, 4f03e00.** The `Not checked:` line, confirmRevokeAnswer's comment and revoke.md say that any genuine KRL issued after the window floor passes, including the signer's own hourly re-publish, so a compromised keyroster-server can show one without forwarding the request; 03-03b's krl.Parse serial check is the fix. Test: `TestRevokeSerialConfirm/confirmed` pins the new sentence; the old text fails it.
- **low (split), Parse as OpenSSH, 5a555c6.** Key IDs and the header comment are read with sshbuf_get_cstring's rule (a final NUL ends a key ID; a NUL inside one or inside the comment is refused); the bitmap bound is SSHBUF_MAX_BIGNUM, 2048 bytes plus one zero sign byte (it was 16385); Encode refuses a key ID with a NUL. Tests: `TestOracleCStringBignum` (ssh-keygen 9.6p1 accepts and refuses exactly the same eight KRLs, and revokes the certificate with key ID `oracle-id` through a `oracle-id\x00` entry), TestParse cases `key_id_inner_nul`, `key_id_only_nul`, `comment_inner_nul`, `bitmap_2049_bytes_nonzero_first`, `bitmap_2050_bytes`, the Encode NUL cases, and the eight KRLs as FuzzParseKRL seeds; `entry_cap` and `bitmap_runs_are_intervals` use 2048-byte bitmaps. Proof: all of them fail against the parser and encoder of the commit before. T-03-15 updated. A key ID that is only a NUL is refused although OpenSSH reads it as the empty key ID (stricter, fail-closed for a KRL gate).

**Skipped**

- **low (split), issuance rows edited while the signer runs, 8a94dc2 (todo only).** No small exact guard exists in the style of the revocation multiset: a row edited out of `LiveIssuanceForSubjectTx`'s WHERE clause cannot be seen by comparing the rows it returns, and the signer keeps only the issuance count and last serial from its log. Audit verify detects the effect after the fact (it re-derives every revoke entry from the issue leaves). Todo `2026-10-26-signer-checks-issuance-rows-against-the-log.md` (Phase 4).

**For 03-03b:** new refusal details to map to advice: `key_id_not_issued` (revoke a certificate this signer did not issue by its key), `explicit_key_cap_reached` (see revoke.md), `revoke_installation_missing` and `revoke_installation_mismatch`; every request it builds is v2 with the bundle's installation ID.

**Gates (local, WSL):** gofmt; go vet for linux, windows and darwin and `-tags e2e ./test/e2e/`; golangci-lint for linux, windows and darwin; `go test -race -count=1 ./...` with `KEYROSTER_REQUIRE_ORACLE=1`; capslock, dep-firewall and testonly-firewall; FuzzParseKRL, FuzzEncodeKRL, FuzzParseRevokeRequest and FuzzParseRevokeSigningBytes for 15 s each. The e2e lanes (sshd, both OpenSSH versions) ran only in CI.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-25*
