---
phase: 01-trust-core
plan: 08
subsystem: audit-trust
tags: [audit-verify, trust-bundle, pins, host-certificate, known-hosts, cert-authority, machine-ca, sshd, e2e, tdd]

requires:
  - phase: 01-07
    provides: "ca-init (user, host, machine, ops, log), install-bundle with bundle_install leaves carrying all four signed documents, admin evidence, per-role profiles, bootstrapSigner"
  - phase: 01-06
    provides: "trust.VerifyGenesisBundle, trust.VerifySuccessor, trust.ParseKey"
  - phase: 01-05
    provides: "audit export/verify, tlog leaf kinds, checkpoints"
provides:
  - "audit.Options{Pins []string; Threshold int; Previous []byte} (replaces LogKey); Report.IssuedByCA, BundleVersion, PolicyVersion, LogKey"
  - "keyroster audit verify --pin SHA256:... [--pin ...] --threshold N [--previous FILE] [--json] EXPORT.jsonl (replaces --log-key)"
  - "e2e TestHostCertificateNoTOFU, TestMachineCAIsSeparate, TestHostCAIsNotUserCA; helpers auditVerify(t, env, ...), auditVerifyPins, sshStrict, issueHostCert, caKeysFile, presentCert"
affects: [01-10, 01-11, 01-13, 01-14, 01-15, Phase 3 (successor bundles, log-key and CA rotation), Phase 4 (witnessed checkpoints)]

actuals:
  tokens: 17299
  tasks: 2
  commits: 3
plan_head_before: b13d9a481db86e6f9af8c951133c99a54d37785a
plan_head_after: 074247c32b99f242066d087aa61f24ad8c3dbdbe

tech-stack:
  added: []
  patterns:
    - "Audit verification is anchored only in the operator's pins: the first bundle_install verifies as a genesis bundle against them, later ones as root-signed successors, and the log key and the active CA key per role are read only from those verified bundles"
    - "CA role tests change one thing against a control on a fresh sshd: the same certificate is refused or accepted depending only on TrustedUserCAKeys or the known_hosts line"
    - "A certificate the OpenSSH client refuses to offer is presented through an x/crypto/ssh client, so sshd itself decides"

key-files:
  created:
    - test/e2e/ca_roles_test.go
  modified:
    - internal/audit/verify.go
    - internal/audit/verify_test.go
    - internal/audit/fuzz_test.go
    - cmd/keyroster/audit.go
    - internal/signer/log_test.go
    - test/e2e/audit_test.go
    - test/e2e/trust_flow_test.go

key-decisions:
  - "01-08: audit verify trusts only --pin/--threshold; the log key (checkpoint and --previous) and the active CA per role come only from bundle_install entries verified as genesis (pins) or successor (TUF); in Phase 1 a bundle naming another log key fails with log key change unsupported"
  - "01-08: audit verify requires each issue leaf after the first bundle_install, signed by its role's active CA in the bundle in force, a host certificate exactly for the host role, and key ID pol and leaf policy version equal to the policy in force; bundle_install's bundle_version must equal its bundle"
  - "01-08: audit verify --threshold is required (>= 1) and must equal the genesis bundle's threshold; there is no default"
  - "01-08: host-type certificates as user certificates are tested with an x/crypto/ssh client because the OpenSSH client (9.5p1 and 10.5p1) never offers a non-user certificate; sshd refuses them with Certificate invalid: not a user certificate"

patterns-established:
  - "auditVerify(t, env, export, extra...) pins env.RootFingerprints at threshold 1; auditVerifyPins for other pins"
  - "sshStrict logs in with StrictHostKeyChecking=yes, BatchMode and one explicit known_hosts file, with -v to show which host key or certificate matched"

requirements-completed: [CA-01, CA-04, CA-05, VIS-03]

coverage:
  - id: D1
    description: "audit verify anchors on --pin/--threshold: bundle_install leaves are verified against the pins (genesis) or their predecessor (successor) before their log key or CA keys are trusted; unpinned roots, mismatched pins, an unmet or mismatched threshold, issuance before any bundle, a missing bundle and a log-key change fail; editing only decoded still verifies"
    requirement: VIS-03
    verification:
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyAnchoring (unpinned_root, bundle_signed_by_unpinned_root, pins_name_other_root, threshold_not_met, threshold_above_bundle, issue_before_bundle, no_bundle, log_key_change, successor_*, decoded_only_edit_still_ok)"
        status: pass
      - kind: e2e
        ref: "test/e2e/audit_test.go#TestAuditVerifiesIssuance (pinned to another root fails), TestRefusalsAreAudited, TestAuditDetectsTampering (CI e2e 9.5p1 and 10.5p1 on PR #10)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every logged certificate is checked against the bundle and policy in force: signed by its role's active CA (host or machine CA under the user role and the user CA under the host role fail), host certificates only for the host role, key ID pol and leaf policy version equal to the policy version"
    requirement: CA-04
    verification:
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyAnchoring (host_ca_under_user_role, machine_ca_under_user_role, user_ca_under_host_role, user_cert_type_under_host_role, host_cert_type_under_machine_role, policy_version_mismatch, leaf_policy_version_mismatch, every_role_ok)"
        status: pass
    human_judgment: false
  - id: D3
    description: "A host certificate from the host CA lets ssh with StrictHostKeyChecking=yes log in through one @cert-authority line, with no TOFU message and an unchanged known_hosts; an empty known_hosts or the user CA as host CA fails"
    requirement: CA-01
    verification:
      - kind: e2e
        ref: "test/e2e/ca_roles_test.go#TestHostCertificateNoTOFU (CI e2e 9.5p1 and 10.5p1 on PR #10)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Machine-CA certificates (user type, kr1/ca=machine/, pol=1, 24 h machine cap) are refused by an sshd trusting only the user CA and accepted once the machine CA is added; host-type certificates are refused as user certificates even when the host CA is in TrustedUserCAKeys"
    requirement: CA-05
    verification:
      - kind: e2e
        ref: "test/e2e/ca_roles_test.go#TestMachineCAIsSeparate, #TestHostCAIsNotUserCA (CI e2e 9.5p1 and 10.5p1 on PR #10)"
        status: pass
    human_judgment: false
  - id: D5
    description: "PR #10 with every required check green, waiting for the owner at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 10 --required --watch on 074247c: build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz pass"
        status: pass
    human_judgment: true
    rationale: "The owner reviews and approves the PR at the merge gate (Task 3); approval is a human decision"

duration: 25min
completed: 2026-10-05
status: complete
---

# Phase 1 Plan 08: CA Roles and Anchored Audit Summary

**`keyroster audit verify --pin --threshold` now trusts only the operator's pinned roots. It takes the log key and each role's CA key from root-verified `bundle_install` entries, and checks every logged certificate against its role's active CA, certificate type and the policy in force. Real sshd (9.5p1 and 10.5p1) shows the three CAs are not interchangeable: host certificates replace TOFU, machine certificates need the machine CA, and host certificates never pass as user certificates.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-10-05T12:52:10Z
- **Completed:** 2026-10-05T13:17:00Z
- **Tasks:** 2 of 3 executed (Task 3 is the merge gate)
- **Files modified:** 8 (1 created)

## Accomplishments

- **Anchored `audit verify`:**
  - The first `bundle_install` entry is checked with `trust.VerifyGenesisBundle` against `--pin` and `--threshold`. Each later one is checked with `trust.VerifySuccessor` against the bundle in force.
  - The checkpoint and `--previous` are verified with the log key of those bundles. All bundles must name the same log key.
  - Each issue entry must come after the first bundle and be signed by its role's active CA. It must be a host certificate exactly for the host role, and its key ID `pol` and leaf policy version must equal the policy in force.
  - Nothing is read from `decoded`.
- **Report:** issuances per CA role, bundle and policy version, and the log key fingerprint. These appear in the text output and in `--json` (`issued_by_ca`, `bundle_version`, `policy_version`, `log_key`).
- **No TOFU:** a host certificate from the host CA authenticates the host to `ssh -o StrictHostKeyChecking=yes` through a single `@cert-authority [127.0.0.1]:port` line, and the client log shows `matches the ED25519-CERT host certificate`. An empty known_hosts, or the user CA in that line, fails with `Host key verification failed`.
- **Separate CAs:**
  - Machine certificates are refused where only the user CA is trusted, and accepted once the machine CA is added.
  - A host certificate presented as a user certificate is refused by sshd (`Certificate invalid: not a user certificate`), even with the host CA in `TrustedUserCAKeys`.

## PR

- PR **#10** `test(signer): prove separate user, host and machine CAs and anchor audit verify on the trust root` (https://github.com/Labontese/keyroster/pull/10). Auto-merge (squash) is enabled by keyroster-bot.
- Required checks on implementation head `074247c`: `build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)` and `fuzz` all pass. Both e2e job logs show `--- PASS` for `TestHostCertificateNoTOFU`, `TestMachineCAIsSeparate`, `TestHostCAIsNotUserCA`, `TestAuditVerifiesIssuance`, `TestRefusalsAreAudited` and `TestTrustFlowEndToEnd`.
- All three implementation commits show `verified: true` on GitHub.
- The known flaky `TestSignerRefusals/created_301s_future` did not fail, so no rerun was needed.

## Final `audit verify` Flag Set

- `keyroster audit verify --pin SHA256:... [--pin ...] --threshold N [--previous FILE] [--json] EXPORT.jsonl`
  - `--pin` is repeatable and required. The pins must be exactly the genesis bundle's root set.
  - `--threshold` is required (N >= 1) and must equal the genesis bundle's threshold.
  - `--previous` takes a checkpoint note or an earlier export, as before. It is verified with the bundle's log key.
  - Removed: `--log-key`.

## TDD Gate Compliance (Task 2)

| Gate | Commit | Command | Result |
|------|--------|---------|--------|
| RED | `5e1a511` test(01-08) | `go test -count=1 -run Verify ./internal/audit/` | Exit 1. Exactly four target cases fail on their assertion (`Verify accepted the export`): `TestVerifyAnchoring/user_cert_type_under_host_role`, `host_cert_type_under_machine_role`, `leaf_policy_version_mismatch` and `bundle_version_field_mismatch`. The other 64 tests and subtests pass. A TAP conversion of `go test -json` gave `gsd-tools check tdd-red-evidence` = `RED_EVIDENCE_OK` (target `TestVerifyAnchoring/user_cert_type_under_host_role`). |
| GREEN | `074247c` feat(01-08) | same command | Exit 0, all cases pass. The full unit suite, a 30 s `FuzzVerifyExport` run, lint and the full e2e suite on 9.5p1 and 10.5p1 also pass. |

- The seven named acceptance cases (`unpinned_root`, `threshold_not_met`, `host_ca_under_user_role`, `issue_before_bundle`, `log_key_change`, `policy_version_mismatch`, `decoded_only_edit_still_ok`) were already green at RED. The Task 1 tracer implemented every check that Task 1's action lists, and Task 2 pins them. This matches the 01-06 and 01-07 precedent. The RED failures are the hardening that Task 2's tests exposed.
- The e2e role tests in the RED commit pass on first run, because the behaviour under test belongs to sshd and needs no product code.

## Task Commits

1. **Task 1: tracer, from host certificate to `audit verify --pin`:** `ea04a78` (feat). The tracer gate (interactive, end-of-phase, automated-only `<verify>`) re-ran unit tests, lint and the full e2e suite on 9.5p1 and 10.5p1. All passed, so execution continued.
2. **Task 2: CA separation, anchoring tamper cases and PR (TDD):** `5e1a511` (test, RED), `074247c` (feat, GREEN). PR #10 opened with auto-merge.
3. **Task 3: merge gate:** pending owner approval (checkpoint).

## Files Created/Modified

- `internal/audit/verify.go`: `Options{Pins, Threshold, Previous}`, the `anchor` trust state (`install`, `checkIssue`), and the report fields.
- `cmd/keyroster/audit.go`: `--pin`/`--threshold` and the extended output.
- `internal/audit/verify_test.go`: root-anchored fixture (`newFixture`, `newBareFixture`, `genesis`, `signDocs`, `addBundle`, `addRoleIssue`, `successor`), `TestVerifyAnchoring`, `TestVerifyEmpty`, and migrated tamper and `--previous` tests. `internal/audit/fuzz_test.go`: pins.
- `internal/signer/log_test.go`: `verifyExport` pins the fixture root.
- `test/e2e/ca_roles_test.go`: the three role tests and their helpers.
- `test/e2e/audit_test.go`, `test/e2e/trust_flow_test.go`: `auditVerify(t, env, ...)` with `--pin`.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Callers of the removed `Options.LogKey` migrated**
- **Found during:** Task 1.
- **Issue:** `internal/signer/log_test.go` and `internal/audit/fuzz_test.go`, which are not in the plan's file list, verified exports with `LogKey`.
- **Fix:** Both now pin the root at threshold 1. The unused `logEnv.logPub` field was removed.
- **Committed in:** `ea04a78`.

**2. [Rule 3 - Blocking] `test/e2e/audit_test.go` switched in Task 1, not Task 2**
- **Issue:** Task 1's acceptance criterion requires no `--log-key` anywhere in `test/e2e/`, and the shared `auditVerify` helper lives in `audit_test.go`.
- **Fix:** The helper takes the `signerEnv` and pins its roots. The "other log key" assertion became "pinned to another root fails with `not anchored in the pinned roots`".
- **Committed in:** `ea04a78`.

**3. [Rule 2 - Missing critical] Certificate type, leaf policy version and bundle version checks**
- **Found during:** Task 2 (RED).
- **Issue:** Without them, a log whose CA issued a user-type certificate under the host role (or a host certificate under the machine role), whose leaf misstated the policy version, or whose `bundle_install` misstated its bundle version, still verified.
- **Fix:** `anchor.checkIssue` requires `HostCert` exactly for the host role and the leaf's `PolicyVersion` equal to the policy in force. `anchor.install` requires `BundleVersion` to equal the bundle's version.
- **Committed in:** `074247c`.

**4. [Rule 1 - Bug, test] Host-as-user test made sshd decide**
- **Found during:** Task 2, before the RED commit.
- **Issue:** The first version of `TestHostCAIsNotUserCA` presented the host certificate with the OpenSSH client. That client (9.5p1 and 10.5p1) silently ignores a non-user certificate (`pubkey_prepare: ignoring certificate ...: not a user certificate`), so the refusal came from the client. A substring check had passed on 10.5p1 only because `ED25519-CERT` appears in the `loaded identity cert` line.
- **Fix:** `presentCert` presents the certificate through `x/crypto/ssh`. A temporary log dump confirmed that sshd on both versions refuses it with `Certificate invalid: not a user certificate`. The stock-client behaviour is kept as its own subtest.
- **Committed in:** `5e1a511`.

**5. [Rule 3 - Blocking] Tamper-table cases for an empty export moved to `TestVerifyEmpty`**
- **Issue:** Every fixture export now starts with `bundle_install`, so the table could no longer express "no entries".
- **Fix:** `empty_export` and `checkpoint_without_entries` run in their own test. The table case became `no_leaf_after_bundle`.
- **Committed in:** `ea04a78`.

---

**Total deviations:** 5 auto-fixed (3 blocking, 1 missing critical, 1 test bug).
**Impact on plan:** All are needed for correctness or to complete the plan. No module was added. `test/e2e/harness_test.go` and `test/e2e/bootstrap_test.go` were not edited.

## Issues Encountered

- Heredocs passed through the Bash tool turned `\\n` in Python string literals into real newlines. Edits were made from script files instead, and every commit was checked with gofmt and vet.
- `addLogKey` in `test/e2e/harness_test.go` is now unused. Its owner forbids edits and lint does not build the `e2e` tag, so the item is logged in `deferred-items.md`.

## Known Stubs

None.

## Threat Flags

None. The new e2e helper `presentCert` uses `ssh.InsecureIgnoreHostKey` deliberately: it tests user authentication only, against a test sshd on 127.0.0.1.

## User Setup Required

None.

## Next Phase Readiness

- Every later e2e test verifies logs with `auditVerify(t, env, export)`, so 01-10 and 01-11 (TPM/PKCS#11 backends through `bootstrapSigner`) get root-anchored verification without changes.
- Phase 3 CA rotation and log-key rotation need two changes. `anchor.install` must accept a log-key change through a successor (today it refuses). `activeCA` must also cover `next`/`retired` entries if certificates from a retiring CA remain valid after rotation.
- 01-10 can start from `main` once this PR merges.

## Self-Check: PASSED

- `test/e2e/ca_roles_test.go` and all modified key files exist on disk.
- Commits `ea04a78`, `5e1a511` and `074247c` are on `origin/p01/08-ca-roles-audit` and verified on GitHub.
