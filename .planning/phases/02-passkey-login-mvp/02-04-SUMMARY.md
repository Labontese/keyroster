---
phase: 02-passkey-login-mvp
plan: 04
subsystem: audit
tags: [audit, webauthn, passkey, directory, tlog, kr2, policy, successor-policy, rp_id, tamper-suite, fuzz, e2e, key-02]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-01: tlog kinds 7 and 8 with strict decoders, the interim default refusal in audit verify, kr2 key IDs, internal/directory and internal/webauthn; 02-02 and 02-03 (and #35, #38 review fixes) on main"
provides:
  - "keyroster root successor-policy --prev POLICY --out FILE --webauthn-rp-id HOST [--webauthn-origin URL]...: the root-chain successor of the policy in force with the WebAuthn RP set or changed, and the one-way rp_id warning"
  - "audit verify checks every directory_install entry (successor chain, admin quorum and user CA profile of the policy in force, recorded versions)"
  - "audit verify re-proves every login_issue entry from the log: the passkey assertion over SHA-256 of the logged request, the directory grant, TTL and extension caps, the certificate binding, the kr2 key ID, freshness, single-use request IDs and one serial sequence with issue entries"
  - "wire.ParseLoginIssueSigningBytes: strict parser of the request bytes a login_issue leaf stores"
  - "The audit verify OK line counts login certificates and directory installs; --json already carries kinds.login_issue and kinds.directory_install"
  - "TestAuditLoginAcrossPolicyChange (e2e) and TestVerifyLoginTampering (59 cases)"
  - "Runbook: root-ceremony.md 'Change the policy: successor policy' with the compatibility note; signer-install.md 'Snapshot restore' step 2 made true"
affects: [02-09, 02-11, 02-13, 02-14, KEY-02, AUTHZ-01]

actuals:
  tokens: 21500   # chars/4 over the added lines of the code, test and docs diff (85943 chars); planning docs excluded
  tasks: 2        # Tasks 1 and 2; Task 3 is the owner merge gate
  commits: 3      # git rev-list --count plan_head_before..HEAD at SUMMARY write; this docs commit follows
plan_head_before: 5d84cc2e0e7cdde2b4b2c28bff21fd68ec073d33
plan_head_after: 9273038f3d7377424e5c11bf094d826880a2e618

tech-stack:
  added: []
  patterns:
    - "The audit walk keeps the directory in force like the policy in force, with one cached authorization per (directory, policy) pair, recomputed only when either side changes"
    - "A login_issue entry reuses the issue-entry certificate checks (checkIssue, anchor.checkIssue) with the user CA role set by the caller, then adds the request binding"
    - "Tamper cases build a valid log with the real packages, change one thing, and rely on the fixture's own log key to re-sign the checkpoint, so only the entry checks can catch it"

key-files:
  created:
    - test/e2e/audit_login_test.go
  modified:
    - internal/audit/verify.go
    - internal/audit/verify_test.go
    - internal/audit/fuzz_test.go
    - internal/wire/login.go
    - internal/wire/wire_test.go
    - internal/wire/fuzz_test.go
    - cmd/keyroster/root.go
    - cmd/keyroster/root_test.go
    - cmd/keyroster/audit.go
    - internal/signer/directory_test.go
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/signer-install.md

key-decisions:
  - "audit verify caches the (directory, policy) authorization and recomputes it only at directory_install and after each bundle_install; a directory installed under an earlier policy stays in force while the new policy still authorizes it"
  - "A login request ID used by any earlier issue or login_issue entry is refused (replay); two issue entries are still not compared, so Phase 1 checks of issue entries are unchanged"
  - "A login certificate must carry exactly the profile defaults plus the requested extensions, no critical option, and span exactly ValidForSeconds + 300 s"
  - "Login freshness is |entry time - CreatedAt| <= 300 s in whole seconds of the entry time, CreatedAt's unit"
  - "successor-policy changes only the RP, prints old and new RP and the new SHA-256 on stdout and the one-way warning on stderr, and refuses a no-op"
  - "requirements-completed is [KEY-02] per the plan's output; REQUIREMENTS.md is not marked because 02-09 also declares KEY-02 and has no SUMMARY yet (shared-ID gate)"

patterns-established:
  - "A walk-state value shared by two leaf kinds gets its own variable instead of being derived from one kind's report counter"

requirements-completed: [KEY-02]

coverage:
  - id: D1
    description: "An operator adds the WebAuthn RP to a running signer through a root-signed policy successor; the signer then installs a directory and issues a login certificate that real sshd accepts, and the exported log verifies with login certificates 1, directory installs 1"
    requirement: KEY-02
    verification:
      - kind: e2e
        ref: "test/e2e/audit_login_test.go#TestAuditLoginAcrossPolicyChange (local WSL, sshd 10.5p1 and 9.5p1)"
        status: pass
    human_judgment: false
  - id: D2
    description: "audit verify refuses every tampered directory_install and login_issue entry with its named check while the checkpoint is correctly re-signed, and accepts the controls, including a directory that outlives an RP-only policy change"
    requirement: KEY-02
    verification:
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyLoginTampering (59 subtests), #TestVerifyKindsWithoutChecks"
        status: pass
    human_judgment: false
  - id: D3
    description: "successor-policy writes version + 1 with prev = SHA-256 of the policy in force and only the RP changed, prints the warning, and refuses an existing --out, a non-canonical --prev, an unchanged RP, an IP literal, a tailnet domain, an origin with a path, the last version and missing flags"
    verification:
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestRootSuccessorPolicy"
        status: pass
    human_judgment: false
  - id: D4
    description: "The logged request bytes parse strictly and round-trip; Phase 1 exports still verify unchanged"
    verification:
      - kind: unit
        ref: "internal/wire#TestParseLoginIssueSigningBytes, FuzzParseLoginIssueSigningBytes; internal/audit#TestVerifyOK, TestVerifyKindsWithoutChecks/phase1_kinds_still_verify, every existing audit test"
        status: pass
    human_judgment: false
  - id: D5
    description: "The policy-change runbook is followed by an operator on the homelab signer with offline roots and paper fingerprints"
    verification: []
    human_judgment: true
    rationale: "Only the CI-style e2e runs the commands; the homelab and offline run is plan 02-13"

duration: 50min
completed: 2026-10-17
status: complete
---

# Phase 2 Plan 04: Audit Login Summary

**`keyroster audit verify` now re-proves every login certificate from the exported log alone (the user's bound passkey signed exactly the logged request, the quorum-signed directory granted exactly those principals and that TTL, and the certificate is bound to that request), and `keyroster root successor-policy` adds the WebAuthn RP to a running installation through a root-signed policy successor.**

## Performance

- **Duration:** about 50 min
- **Started:** 2026-10-17T13:59Z (plan ledger; reading began about 15 min earlier)
- **Completed:** 2026-10-17T14:35Z (SUMMARY write)
- **Tasks:** 2 of 3 (Task 3 is the owner merge gate)
- **Files modified:** 13 code, test and docs files, plus planning docs

## Delivery

- **Branch:** `p02/04-audit-login`, cut from origin/main `d6f53b3`. It also carries the orchestrator's `5d84cc2 docs(phase-02): mark 02-03 complete in roadmap`.
- **PR:** opened by keyroster-bot with the title `feat(audit): prove every login certificate was approved by the user's passkey`, after the single push that carries this SUMMARY. Its number and the required checks are reported in the merge-gate checkpoint, not committed (Delivery Protocol step 4; the push happens after this commit).
- **Commits:** signed by keyroster-bot through the repo git config (GitHub verifies them; locally `%G?` shows N because no allowedSignersFile is configured).

## Accomplishments

- **`keyroster root successor-policy`** (cmd/keyroster/root.go).
  - It reads the canonical policy in force (`trust.ParsePolicy`), copies it with Version + 1, Prev = SHA-256 of the bytes read, and the RP set from `--webauthn-rp-id` and `--webauthn-origin` (default `https://<rp-id>`, sorted). It validates and writes the result canonically with an exclusive create.
  - stdout gets the old and new `rp_id` and origins and the new policy's SHA-256. stderr gets `WARNING: rp_id is a one-way setting. Every passkey enrolled under it works only for that exact hostname; renaming the host or changing rp_id makes every enrolled passkey unusable.`
  - It refuses, and writes nothing, on an existing `--out`, a non-canonical `--prev`, an RP equal to the one in force ("nothing to change"), an RP the policy rules refuse, and a policy at the last version. The usage text says that admins, quorum and profiles are not editable here, and that the quorum-gated policy change is Phase 4 (AUTHZ-03).
- **`wire.ParseLoginIssueSigningBytes`.** It requires the raw `keyroster/login-request/v1` prefix and parses the fields with the same limits as `ParseLoginIssueRequest` and no evidence section. It refuses trailing bytes and requires `SigningBytes()` of the result to equal the input. `ParseLoginIssueRequest` now shares the field reader (`readLoginFields`).
- **The audit walk** (internal/audit/verify.go).
  - It keeps the directory in force (bytes, signatures, parsed, version) next to the policy in force. Its authorization under the policy in force is one cached result per (directory, policy) pair. `authorizeDirectory`, the only `VerifySignatures` call site, runs at a directory_install entry and after each bundle_install entry. A login_issue entry only reads the result (review finding 02-04-F8).
  - **directory_install:** a policy in force; the recorded policy version is that policy's; the document parses; the recorded version is the document's; `directory.CheckSuccessor` against the directory in force; admin quorum and user CA profile of the policy in force. Each failure reads `audit: entry N (directory_install): <check>`.
  - **login_issue,** in this order:
    1. the logged request parses with `ParseLoginIssueSigningBytes`;
    2. the policy and directory versions in force are the ones recorded;
    3. the cached authorization holds;
    4. the policy has a WebAuthn RP;
    5. exactly one `webauthn-assertion/v1` item, which parses;
    6. `Authorize` (user active, roles held);
    7. the user's credential with the assertion's ID;
    8. `webauthn.VerifyAssertion` with the challenge SHA-256 of the logged request bytes, under the RP and origins in force;
    9. principals equal to the grant;
    10. TTL ≤ min(role cap, user CA cap);
    11. extensions named once and granted;
    12. the issue-entry certificate checks with the user CA role (`checkIssue`, `anchor.checkIssue`: canonical encoding, CA signature by the active user CA, user type, serial, key ID pol, profile and issuance-time window), and a kr2 key ID;
    13. certificate key = SubjectKey, principals = the request's, span = TTL + 300 s, extensions = profile defaults plus the requested ones, no critical option;
    14. kr2 sub, req, dir and roles;
    15. a request ID no earlier issue or login_issue entry used;
    16. CreatedAt within 300 s of the entry time.

    Each failure reads `audit: entry N (login_issue): <check>`.
  - **Serials:** one strictly increasing sequence across issue and login_issue entries. "Any serial seen" is its own walk variable (`issuance.seen`), not `rep.Serials > 0`, which counts issue entries only.
  - **The kind switch:** a case for `tlog.KindDirectoryInstall` and one for `tlog.KindLoginIssue`. The explicit case for refusal, clock_regression and ca_init is unchanged. The default refusal stays, with an `UNVERIFIED` comment: no leaf that `tlog.DecodeLeaf` accepts reaches it now, so no test runs it. It is the guard that makes a kind added later fail closed.
  - `Verify`'s doc comment now says that login issuances are re-proven from the log and admin issuances (kind 1) still are not.
  - `audit.Report` is unchanged. `Serials` and `IssuedByCA` still count issue entries only.
- **Output** (cmd/keyroster/audit.go). The `OK:` line now reads `... issued N (user N, host N, machine N), login certificates N, directory installs N, refusals N, ...`. The `anchored:` and `not checked:` lines are unchanged; `not checked:` speaks of admin issuances and stays true.
- **02-01's interim state is gone.** Kinds 7 and 8 no longer reach `not verifiable by this version`. `TestVerifyKindsWithoutChecks`'s two interim cases were converted, not deleted, into `directory_install_unproven_refused` and `login_issue_unproven_refused`. Their leaves are unchanged. They now require an error and no report, an error that starts with `audit: entry 5 (<kind>): `, and the absence of the interim text. The real checks that refuse them are `directory does not parse` and `logged request: ... not a keyroster/login-request/v1 signing encoding`. `phase1_kinds_still_verify` is unchanged.

### The tamper suite (TestVerifyLoginTampering, 59 subtests)

Every case builds a valid log in process with the real directory, webauthn (soft authenticator), wire, cert and certprofile packages. It then changes one thing. The fixture's export re-signs the checkpoint with the test's own log key over all leaves, as a compromised signer could.

| Group | Tampered cases (each fails with its named check) | Controls (verify) |
|---|---|---|
| Passkey | `login_assertion_bit_flip`, `login_principals_widened_after_approval` (challenge mismatch), `login_other_users_credential`, `login_two_evidence_items`, `login_admin_evidence`, `login_assertion_unparseable`, `login_without_rp` | `login_ok` (2 logins), `login_bob_ok` (ES256) |
| Grant | `login_principals_widened`, `login_unknown_user`, `login_disabled_user`, `login_role_not_granted`, `login_ttl_above_role`, `login_extension_not_granted`, `login_extension_twice` | `login_named_role_ok`, `login_granted_extension_ok`, `login_ttl_at_role_cap_ok` |
| Directory and policy in force | `login_under_never_installed_directory`, `login_before_any_directory`, `login_policy_version_wrong`, `login_under_unauthorized_directory` (new admins), `login_under_directory_above_new_cap` | `login_after_resigned_directory_ok`, `login_directory_survives_rp_policy_change` (dir=1 under pol=2, then dir=2 under pol=2; counts 2 and 2) |
| directory_install | `directory_install_non_admin`, `directory_prev_wrong`, `directory_version_skipped`, `directory_first_not_v1`, `directory_role_ttl_above_user_cap`, `directory_policy_version_wrong`, `directory_version_mismatch`, `directory_before_bundle` | (every login control installs one) |
| Certificate | `login_cert_key_not_subject`, `login_cert_principals_differ`, `login_cert_span_wrong`, `login_cert_extra_extension`, `login_cert_critical_option`, `login_cert_by_host_ca`, `login_kr1_key_id`, `login_kr2_roles_not_grant`, `login_kr2_subject_wrong`, `login_kr2_request_wrong`, `login_kr2_dir_wrong`, `login_kr2_pol_wrong` | |
| Freshness | `login_created_301s_before`, `login_created_301s_after` | `login_created_300s_before_ok`, `login_created_300s_after_ok` |
| Replay | `login_request_replayed`, `login_reuses_issue_request_id`, `issue_reuses_login_request_id` | `issue_request_ids_not_compared_with_each_other` (pins the Phase 1 boundary) |
| Serials | `login_serial_not_above_issue`, `login_serial_below_issue`, `issue_serial_not_above_login` | `login_after_issue_ascending_ok`, `issue_after_login_ascending_ok` |

`FuzzVerifyExport` gains three seeds: a log with a directory install and two logins under the same root as its pins (checked to verify before fuzzing), a truncation and a reordering of it.

## Task Commits

1. **Task 1: tracer, from an RP-less live signer to a verified login certificate.** `530fc93` (feat). Tracer gate (interactive, `end-of-phase`, automated-only verify): the e2e verify was re-run after the commit and passed, so the plan expanded with no checkpoint.
2. **Task 2: tamper suite, successor-policy refusals, runbook.**
   - `30aec6f` (test)
   - `9273038` (docs)
3. **Task 3: merge gate.** Not attempted. It is the owner's `checkpoint:human-action`.

**Plan metadata:** the docs commit `docs(02-04): complete audit-login plan` (this file and STATE.md).

## TDD record (Task 2, tdd="true"; workflow.tdd_mode is false, so the gate sequence is advisory)

- **Unexpected green, recorded as such.** Task 1 built every check the plan specifies, so every Task 2 test passed on its first run: the 59 tamper subtests, the fuzz seeds, `TestRootSuccessorPolicy`, the wire parser tests and the signer restart case. Two test-side mistakes were fixed before that: the replay case first reused the request with a new subject key, which failed on the key check, so it now reuses the key as a real replay would; and the two 301 s assertions were reworded.
- **The tests bite.** Each mutant was applied to internal/audit/verify.go, `TestVerifyLoginTampering` was run, and the file was restored from a byte copy (checked equal after the run):

| Mutant | Cases that failed |
|---|---|
| "serial seen" back to `rep.Serials > 0` | `issue_serial_not_above_login` |
| cached authorization not checked | `login_under_unauthorized_directory`, `login_under_directory_above_new_cap` |
| no re-check after bundle_install | the same two |
| login replay check off | `login_request_replayed` |
| issue-vs-login replay check off | `issue_reuses_login_request_id` |
| exact extension set off | `login_cert_extra_extension` |
| extension grant check off | `login_extension_not_granted` |
| VerifyAssertion result ignored | `login_assertion_bit_flip`, `login_principals_widened_after_approval` |
| principals vs grant off | `login_principals_widened` |
| freshness off | `login_created_301s_before`, `login_created_301s_after` |
| kr2 roles check off | `login_kr2_roles_not_grant` |
| subject key check off | `login_cert_key_not_subject` |
| directory quorum and profile off | `directory_install_non_admin`, `directory_role_ttl_above_user_cap` |
| directory chain off | `directory_prev_wrong`, `directory_version_skipped`, `directory_first_not_v1` |

- The GSD RED classifier has no Go adapter. This is a recorded assessment, not a classifier verdict.

## Verification run (local)

| Check | Where | Result |
|---|---|---|
| Task 1 verify: e2e `TestAuditLoginAcrossPolicyChange\|TestAudit\|TestRootRotationLiveSigner`, sshd 10.5p1 | WSL | PASS, before and after the commit (tracer gate) |
| Task 1 verify: `go test ./internal/audit/... ./internal/wire/... ./cmd/keyroster/...` | Windows | PASS |
| Task 1 verify: `-run '^TestVerifyKindsWithoutChecks$'` | Windows | PASS with all three named subtests |
| Task 2 verify: `-run 'Tamper\|Login\|Directory\|SuccessorPolicy'` | Windows | PASS; `/login_directory_survives_rp_policy_change`, `/login_serial_not_above_issue`, `/issue_serial_not_above_login` in the PASS lines |
| Task 2 verify: `go test -race ./...`, `go vet ./...`, `go vet -tags e2e`, gofmt, golangci-lint (linux, windows, darwin), capslock-check, dep-firewall, testonly-firewall | WSL, from a script file so gofmt really runs | all passed; 0 lint issues each; capslock 73 pairs, baseline 73 (unchanged); no DATA RACE |
| Full e2e suite | WSL, sshd 10.5p1 and 9.5p1 | 19 top-level PASS, 0 FAIL, 0 SKIP on each |
| Fuzz, 15 s each: FuzzVerifyExport, FuzzParseLoginIssueSigningBytes, FuzzParseLoginIssueRequest | WSL | PASS (about 0.4M, 2.6M, 2.5M execs) |
| `TestDirectoryRestart` under `-race` | WSL | PASS, including `restart_under_rp_only_policy` |
| Required CI checks | GitHub | not run at SUMMARY time; reported in the checkpoint |

The known `TestCheckLogAgainstLiveSigner` flake (deferred-items.md) did not occur in the two local `-race` runs of `./...`.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] Replay of an approved login request**
- **Found during:** Task 1 design (advisor review).
- **Issue:** without it, a compromised signer could log one approved request several times under new serials. Each copy would pass the assertion check and the 300 s window. The signer makes request IDs single-use across both paths.
- **Fix:** refuse a login_issue whose request ID an earlier issue or login_issue entry used, and an issue entry whose ID a login used. Two issue entries are still not compared, so Phase 1 checks stay as they were. `issue_request_ids_not_compared_with_each_other` pins that boundary.
- **Files modified:** internal/audit/verify.go
- **Verification:** `login_request_replayed`, `login_reuses_issue_request_id`, `issue_reuses_login_request_id`; replay mutants fail them.
- **Committed in:** 530fc93 (tests in 30aec6f)

**2. [Rule 2 - Missing critical] Extensions, critical options and span checked exactly**
- **Issue:** the plan asks for "extensions inside the grant" and the cert.Build validity window. `cert.CheckIssued` bounds extensions only by the profile, so a signer could add an allowed extension the role never granted.
- **Fix:**
  - request extensions must be unique and granted;
  - certificate extensions must be exactly the profile defaults plus the requested ones;
  - there must be no critical option;
  - the span must be exactly TTL + 300 s.
- **Committed in:** 530fc93 (tests `login_cert_extra_extension`, `login_cert_critical_option`, `login_cert_span_wrong`, `login_extension_not_granted`, `login_extension_twice` in 30aec6f)

**3. [Rule 2 - No unexercised paths] Tests outside the plan's file list**
- `internal/wire/wire_test.go#TestParseLoginIssueSigningBytes` and `internal/wire/fuzz_test.go#FuzzParseLoginIssueSigningBytes`: CLAUDE.md requires fuzzing every parser.
- `internal/signer/directory_test.go#TestDirectoryRestart/restart_under_rp_only_policy`: the runbook says a directory installed before the RP change keeps working after the restart. No signer test ran that path. The e2e installs its directory after the change.
- **Committed in:** 30aec6f

**4. [Scope] More than the plan's e2e steps**
- `TestAuditLoginAcrossPolicyChange` also runs `trust verify --prev` (runbook step 4).
- It also takes a second export after a second login and runs `audit verify --previous` in both directions: the later export verifies, and the earlier one is refused `log shrank`. This lets signer-install.md "Snapshot restore" step 2 cite a run, as the orchestrator asked.
- **Committed in:** 530fc93

**5. [Interpretation] Freshness in whole seconds**
- **What was done:** the plan's `|entry time − CreatedAt| ≤ 300 s` compares the entry time in whole seconds, CreatedAt's unit.
- **Why:** an honest signer checks CreatedAt against its clock when the request arrives and writes the entry time after signing. A strict microsecond comparison would refuse a valid log whenever the request was within a fraction of a second of the limit. With whole seconds it takes at least one second of processing at the exact boundary.
- **Residual:** that case remains; see "Not exercised". The 301 s tamper cases and the 300 s controls run on a fixture that starts on a whole second.

**6. [Interpretation] successor-policy output**
- The old and new RP and the SHA-256 go to stdout (as in `genesis-policy`), and the warning goes to stderr. The unit test asserts that the warning is on stderr only. The e2e reads the combined output.

**7. [Process] Fuzz seeds that verify**
- The kind 7 and 8 seeds come from a login fixture that shares the standard fixture's root (`newLoginFixtureRoot`), so they verify under `FuzzVerifyExport`'s pins and the fuzzer mutates an accepted log. The fuzz setup checks that the seed verifies.

---

**Total deviations:** 7 (2 missing-critical checks, 1 coverage addition, 1 scope addition, 2 interpretations, 1 process note).
**Impact on plan:** the two added checks make "every way to fake a login authorization short of forging a passkey signature fails audit" hold for replays and extra extensions too. They add no dependency and no new production path beyond audit verify. Phase 1 exports verify exactly as before.

## Issues Encountered

- **CRLF from Python edits.** Some edits after the Task 1 commit used Python text mode on Windows, which wrote CRLF. That affected verify.go, verify_test.go, fuzz_test.go and root_test.go. Every carriage return was stripped before the Task 2 commit. The committed Task 1 tree has none (checked with `git show HEAD:internal/audit/verify.go`), and `.gitattributes` (`eol=lf`) normalizes on commit anyway.
- **Git Bash heredocs.** Long quoted heredocs failed with "unexpected EOF" again, so long blocks went through scratch files.
- **WSL quoting.** As in 02-01 and 02-03, every WSL run with `$` went through a script file under `.git/`. Those files are not committed.

## Not exercised (UNVERIFIED)

- **The default refusal in the kind switch.** No leaf that `tlog.DecodeLeaf` accepts reaches it in this version, so no test runs it. It is kept as the fail-closed guard for a later kind and is labelled `UNVERIFIED` in its comment.
- **`ParseLoginIssueSigningBytes`'s canonical re-encode refusal.** It is unreachable today, because the field reader consumes every byte and the encoder is its inverse; the fuzz target asserts the round trip. It is labelled in its comment.
- **Freshness residual.** An honest signer whose issuance takes a second or more, on a request within a second of the 300 s limit, writes a log that `audit verify` refuses. Hardware signing with touch could take that long. No test covers this; it is a documented consequence of Deviation 5.
- **Real authenticators.** Every assertion comes from the soft authenticator (EdDSA, ES256). That stays UNVERIFIED until the 02-13 and 02-14 dogfood.
- **The policy-change runbook on the homelab,** offline and from paper fingerprints: UNVERIFIED. Plan 02-13 runs it. Only the e2e commands (agent root, `--confirm`, directories for sticks) ran.
- **The restore procedure** in signer-install.md is still UNVERIFIED against a restored database. Step 2's `--previous` behaviour ran on two exports of one live signer.
- **CI.** At SUMMARY time no required check has run on this branch. In particular, e2e-pkcs11, e2e-tpm, cli-windows and cli-macos run only in CI. Their results go in the merge-gate checkpoint.
- **Admin issuances (kind 1)** are still not re-proven (unchanged from Phase 1). Two issue entries with the same request ID are still not compared.

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat model. `successor-policy` writes an unsigned document only (T-02-20). audit verify reads the same export as before. No network surface, and no new module or package (T-02-SC): internal/audit now imports internal/directory and internal/webauthn, both in-repo and already in keyroster-signer's graph, and capslock is unchanged at 73 pairs.

## User Setup Required

None.

## Next Phase Readiness

- 02-13 (homelab) can add the RP with `keyroster root successor-policy` and the root-ceremony.md section, and verify the resulting logs with `audit verify`. 02-13 and 02-14 read `kinds.login_issue` and `kinds.directory_install` from `--json`.
- KEY-02 is complete from this plan's side. REQUIREMENTS.md is not marked yet, because 02-09 also declares KEY-02 (shared-ID gate). AUTHZ-01 completes in 02-11.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- `test/e2e/audit_login_test.go` exists; every key-files path exists.
- Commits `530fc93`, `30aec6f` and `9273038` are ancestors of HEAD and carry SSH signatures (keyroster-bot).
- Task 1 acceptance:
  - the `"successor-policy"` case is at root.go:60;
  - the case count for the two kinds is 2;
  - the non-comment `not verifiable by this version` count is 1;
  - the `tlog.KindCAInit` case line is present;
  - the three TestVerifyKindsWithoutChecks cases exist and none expects the interim text;
  - `UNVERIFIED` is on the default branch;
  - `login certificates` is in audit.go and asserted in the e2e.
- Task 2 acceptance:
  - all nine case names are present;
  - the non-comment `VerifySignatures(` count is 1 (`authorizeDirectory`), and `verifyLoginIssue` reads `ds.authErr`;
  - root-ceremony.md has the `successor policy` heading, `one-way` (2) and `not verifiable by this version` (1).
- The IP scrub of the docs diff is clean.

## Pre-merge review fixes

Findings from the pre-merge review of PR #39 (head 0218ee9). Each finding has one commit, and each code fix has a test that failed before the fix and passes after it. Two pairs of findings were duplicates, so each pair shares a commit.

- **Fixed `1a3c684`: a non-canonical RSA SubjectKey permanently broke audit verify** (2 findings, high).
  - Signer: Issue and LoginIssue now refuse `bad_subject_key` unless the key is in its canonical encoding.
  - Audit: verify compares the certificate key with the parsed request key, so logs that already hold such an entry still verify.
  - Tests:
    - `TestLoginRefusalMatrix/bad_subject_key/non_canonical_rsa` and `TestIssueRefusesNonCanonicalSubjectKey` (signer);
    - `TestVerifyLoginTampering/login_rsa_non_canonical_subject_key_ok`, `.../login_rsa_non_canonical_subject_key_cert_key_not_subject` and `.../login_subject_key_unparseable` (audit).
- **Fixed `4a331b0`: freshness was measured against a leaf time that appendLocked can raise** (2 findings, low and medium).
  - Verify now bounds |serial time − CreatedAt| ≤ 300 s in whole seconds. This supersedes the "entry time" wording of Deviation 5 and of the must-have.
  - What changes, for the owner: only the serial is tied to the approval now. The entry time, and with it the certificate's issuance window [serial, entry time], can lie well after CreatedAt when no other certificate comes between. This is exactly what an honest signer writes after a clock step back.
  - The "Freshness residual" below shrinks. CA signing (`cert.Build`) happens after the serial is read, so it no longer counts. What remains is the time between the signer's freshness read and `serial.Next`: evidence verification and database reads.
  - Tests:
    - `TestLoginAfterClockStepBackVerifies` (signer, the reviewers' reproducer);
    - `TestVerifyLoginTampering/login_after_leaf_time_raised_ok` and `.../login_created_at_raised_leaf_time` (audit).
- **Fixed `1b9c0ea`: the retired-root check made audit verify quadratic in bundles** (pre-existing from Phase 1).
  - The anchor keeps one `trust.RootKeySet`, and `CheckAdminsNotRoots` delegates to `CheckAdminsNotRootSet`.
  - Test: `TestVerifyBundleChainLinear`. The allocation ratio from 100 to 400 bundles was 10.1 before and 4.0 after.
  - The signer's start-up replay (`internal/signer/logstate.go`, `li.roots`) uses the same pattern over its own log. It was left as is, because the finding covers hostile exports.
- **Fixed `f3205ef`: root signers never saw the WebAuthn RP.**
  - `rootceremony.Summary` prints `webauthn rp_id ... origins [...]` or `webauthn: none (passkey logins refused)`.
  - Runbook steps 3 and 4 check that line. Step 3 now names the last `sha256:` line of step 2.
  - Test: `TestSummaryShowsWebAuthnRP`.
- **Fixed `3a9eca4`: the compatibility note gave the wrong Phase 1 error** (root-ceremony.md and signer-install.md). Docs only.
  - Check: Phase 1 (c526edf) and 02-03 (d6f53b3) binaries were run on fixture exports, one in runbook order and one with the directory first.
  - Phase 1 gave `json: unknown field "webauthn"` on the runbook-order export and `unknown kind 7` on the directory-first export. 02-03 gave `not verifiable by this version`.
- **Fixed `a5d7b23`: the policy change had no prepare step.** Docs only. Step 0 points to runbook step 1 (hash check, offline boot, only `lo` up) and the `date -u` check.
- **Fixed `659d51f`: step 6 pointed at a "must print" anchored line that does not hold.** Docs only.
  - Step 6 now names the expected `OK:` and `anchored:` lines.
  - Check: the current binary on the runbook-order export printed `trust bundle v2, policy v2` and `anchored: ... trust bundle v1`.
- **Fixed `a0700d3`: two login_issue guards in verify were never reached by a test.**
  - Tests: `TestVerifyLoginTampering/login_before_bundle` and `.../login_request_not_signing_bytes`. `login_issue_unproven_refused` now requires `logged request:`.
  - Mutation check: with either guard replaced by a no-op, the new case fails or panics.
- **Skipped:** none.

Verification:
- `gofmt -l` is empty.
- `go vet ./...` passes on windows, linux and darwin.
- `go test -count=1` passes on the signer, audit, trust, rootceremony and cmd/keyroster packages, and `go test ./...` passes, all on Windows.
- `-race` was not run (no cgo).
- The Linux-only signer socket tests (`//go:build linux`) and the e2e suite (`-tags e2e`, checked with `GOOS=linux go vet -tags e2e ./test/e2e/`) compiled, but they were not run locally because WSL was not reachable from this session. CI runs them.
