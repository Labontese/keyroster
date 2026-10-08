---
phase: 01-trust-core
plan: 07
subsystem: signer-trust
tags: [trust-bundle, ca-init, install-bundle, admin-evidence, sshsig, policy-profiles, ssh-agent, sqlite, e2e, tdd]

requires:
  - phase: 01-05
    provides: "Merkle audit log in the signer DB (logState, appendLocked/logTx, refuse/D-14), tlog CAInitBody/BundleInstallBody, audit export/verify"
  - phase: 01-06
    provides: "internal/trust (Bundle, Policy, CAPubKeys, VerifyGenesisBundle, VerifySuccessor), internal/sshsig, keyroster root genesis-policy / root sign"
  - phase: 01-02
    provides: "signer skeleton, keystore agent backend, wire IssueRequest with SigningBytes, cert.Build"
  - phase: 01-04
    provides: "e2e harness and the required e2e (9.5p1) / e2e (10.5p1) jobs"
provides:
  - "signer.InitCA, signer.InstallBundle, loadTrust; verifyAdminEvidence; profileFor; ErrNotInitialised, ErrNoTrustBundle, ErrKeySelection, ErrBundleKeys, ErrBundleInstall, ErrAlreadyInitialised"
  - "signerdb migration 0003_trust (backend_config, ca_keys, trust_bundle) with SaveBackendConfig, BackendConfig, SaveCAKeys, CAKeys, InsertBundle, LatestBundle"
  - "CLI: keyroster-signer ca-init, keyroster-signer install-bundle; serve without key pins; keyroster ca issue --admin-key --extension"
  - "wire: EvidenceAdminSSHSIG (admin-sshsig/v1), AdminSSHSIGNamespace (keyroster/issue-request/v1), signed IssueRequest.Extensions"
  - "tlog refusal class ReasonUnauthorized (15, unauthorized)"
  - "e2e helper bootstrapSigner(t, bootstrapOpts) *signerEnv (plus initSigner, signGenesis, installArgs, runIssue/issue, exportLog, newRoleKeys, keyrosterWithAgent, runBin)"
  - "test fixture signer.Fixture (NewFixture, Bootstrap, SignDocs, SignRequest) for in-package and signer_test tests"
affects: [01-08, 01-10, 01-11, 01-13, 01-14, 01-15, Phase 2 (webauthn/v1 evidence joins admin-sshsig/v1 via policy), Phase 3 (successor bundles, ops key)]

actuals:
  tokens: 31150
  tasks: 3
  commits: 3
plan_head_before: 1c0df9e145e6a98f5c5b4e32a99d0970b95e996a
plan_head_after: bac7b29e43547dfaf3e5d469cdb8d730fa92440e

tech-stack:
  added: []
  patterns:
    - "Keys are configuration only at ca-init: the signer takes every CA, ops and log key and the policy from the installed root-signed bundle, and re-checks the bundle against the ca-init keys and the backend's custody at every start"
    - "Authorization is evidence in the request: admin SSHSIG over the request's exact SigningBytes (which include the requested extensions), counted per distinct admin key from the policy; any unknown or invalid item refuses the whole request"
    - "One state transition, one log entry, one transaction: ca_init and bundle_install are appended with their checkpoint in the same transaction that stores the keys or the bundle; a refusal writes nothing"
    - "e2e signers start only through bootstrapSigner (ca-init, root genesis-policy, root sign, install-bundle --pin, serve); tests authorize issuance with real admin keys in a separate agent"

key-files:
  created:
    - internal/signerdb/migrations/0003_trust.sql
    - internal/signerdb/trust.go
    - internal/signer/trust.go
    - internal/signer/evidence.go
    - internal/signer/profiles.go
    - internal/signer/fixture_test.go
    - internal/signer/trust_test.go
    - internal/signer/evidence_test.go
    - cmd/keyroster-signer/cainit.go
    - cmd/keyroster-signer/install.go
    - test/e2e/bootstrap_test.go
    - test/e2e/trust_flow_test.go
  modified:
    - internal/signer/signer.go
    - internal/signer/issue.go
    - internal/signer/refusal.go
    - internal/signer/signer_test.go
    - internal/signer/log_test.go
    - internal/wire/issue.go
    - internal/wire/wire_test.go
    - internal/wire/fuzz_test.go
    - internal/tlog/leaf.go
    - cmd/keyroster-signer/serve.go
    - cmd/keyroster/ca.go
    - cmd/keyroster/ca_test.go
    - test/e2e/harness_test.go
    - test/e2e/issue_test.go
    - test/e2e/negative_test.go
    - test/e2e/audit_test.go

key-decisions:
  - "01-07: IssueRequest gains a signed Extensions field (after CreatedAt, before Evidence) so admin evidence covers requested extensions; critical options have no request field in Phase 1"
  - "01-07: evidence refusals (missing_evidence, unknown_evidence_type, bad_evidence, evidence_not_admin, evidence_wrong_namespace, evidence_digest_mismatch, admin_quorum_not_met) log under the new refusal class unauthorized (15)"
  - "01-07: InstallBundle takes the keystore backend (the bundle_install checkpoint is signed with the log key); install-bundle and serve read the backend from backend_config and accept --backend-opt overrides, but every key must keep the custody ca-init recorded"
  - "01-07: a policy admin key may not be a CA, ops or log key; a successor bundle refuses --pin/--threshold; ca-init requires an empty audit log so ca_init is leaf 0"
  - "01-07: install-bundle requires exactly one active CA entry per role equal to the ca-init key; CA rotation (next/retired entries) is a Phase 3 change to checkBundleKeys"

patterns-established:
  - "bootstrapSigner(t, bootstrapOpts{}) is the only way an e2e test starts a signer; Provisioner backends run ca-init without --key"
  - "signer.Fixture + memBackend/keyringBackend: in-package tests bootstrap a real trust state with real SSHSIG signatures, no verification shortcuts"

requirements-completed: [CA-01, CA-04, CA-05, CA-07, KEY-01, VIS-01]

coverage:
  - id: D1
    description: "ca-init selects five distinct keys (user, host, machine CA, ops, log), refuses certificate, RSA and P-384 keys, shared keys and missing roles without writing anything, logs ca_init and writes ca-pubkeys.json in fixed order with identical bytes across runs"
    requirement: CA-01
    verification:
      - kind: unit
        ref: "internal/signer/trust_test.go#TestInitCARefusals (duplicate_key_across_roles, missing_role, certificate_key, rsa_3072_key, p384_key, second_ca_init, provisioner_*)"
        status: pass
      - kind: unit
        ref: "internal/signer/trust_test.go#TestInitCAOrdering"
        status: pass
      - kind: e2e
        ref: "test/e2e/negative_test.go#TestSignerRefuses/ca_init_certificate_as_user_ca (9.5p1, 10.5p1)"
        status: pass
    human_judgment: false
  - id: D2
    description: "install-bundle accepts only a genesis bundle signed by the pinned roots at threshold (or a valid successor), whose keys equal the ca-init keys and include no root key, and logs bundle_install with all four documents; every refusal stores nothing"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "internal/signer/trust_test.go#TestInstallBundleRefusals (unpinned_root, self_signed_bundle, threshold_not_met, bundle_swap, root_as_ca, version_not_increasing, successor_with_pins, admin_is_online_key, valid_successor_accepted, ...)"
        status: pass
      - kind: e2e
        ref: "test/e2e/negative_test.go#TestTrustRefuses/install_bundle_unpinned_root"
        status: pass
    human_judgment: false
  - id: D3
    description: "serve refuses to start without ca-init, without an installed bundle (no trust bundle installed), with any bundle key missing from the backend, or with a key whose custody differs; the --user-ca-fp and --log-key-fp flags are gone"
    requirement: KEY-01
    verification:
      - kind: unit
        ref: "internal/signer/log_test.go#TestStartRefusesWithoutTrust; internal/signer/trust_test.go#TestStartRefusesCustodyMismatch"
        status: pass
      - kind: e2e
        ref: "test/e2e/trust_flow_test.go#TestServeRefusesWithoutBundle"
        status: pass
    human_judgment: false
  - id: D4
    description: "Every issue request needs admin-sshsig/v1 evidence over its signing bytes from the policy's admin quorum; missing, unknown, malformed, wrong-namespace, mismatched and non-admin evidence and an unmet quorum are refused and logged"
    requirement: VIS-01
    verification:
      - kind: unit
        ref: "internal/signer/evidence_test.go#TestEvidence (wrong_namespace, digest_mismatch, non_admin, same_admin_twice_quorum_2, replay_duplicate_request, ...)"
        status: pass
      - kind: e2e
        ref: "test/e2e/negative_test.go#TestTrustRefuses/ca_issue_with_non_admin_key, ca_issue_without_admin_key"
        status: pass
    human_judgment: false
  - id: D5
    description: "User, host and machine requests are issued by their own CA key under their role's profile: TTL caps, user/machine exactly permit-pty by default, extras only when allowed, host certificates without extensions, key ID pol = installed policy version"
    requirement: CA-05
    verification:
      - kind: unit
        ref: "internal/signer/trust_test.go#TestProfiles; internal/signer/signer_test.go#TestSignerIssuesEveryRole"
        status: pass
      - kind: e2e
        ref: "test/e2e/issue_test.go#TestIssueAcceptedBySSHD (pol=1, permit-pty only)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Full trust flow: ca-init, root sign, install-bundle, admin-signed ca issue, sshd login, export-log, audit verify; the export starts with ca_init and bundle_install"
    requirement: CA-04
    verification:
      - kind: e2e
        ref: "test/e2e/trust_flow_test.go#TestTrustFlowEndToEnd (CI e2e (9.5p1) and e2e (10.5p1) on PR #8)"
        status: pass
    human_judgment: false
  - id: D7
    description: "PR #8 with every required check green, waiting for the owner at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 8 --required --watch on bac7b29: build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz pass"
        status: pass
    human_judgment: true
    rationale: "The owner reviews and approves the PR at the merge gate (Task 3); approval is a human decision"

duration: 35min
completed: 2026-10-05
status: complete
---

# Phase 1 Plan 07: Signer Trust Summary

**keyroster-signer now runs only under a root-signed trust bundle. `ca-init` picks five distinct keys (user, host and machine CA, plus the ops and log keys). `install-bundle` verifies the bundle and genesis policy against pinned roots. `serve` takes every key and the issuance policy from the bundle. Every certificate needs admin SSHSIG evidence from the policy (D-13).**

## Performance

- **Duration:** 35 min
- **Started:** 2026-10-05T11:09:27Z
- **Completed:** 2026-10-05T11:44:00Z
- **Tasks:** 2 of 3 executed (Task 3 is the merge gate)
- **Files modified:** 28

## Accomplishments

- **`ca-init`:** selects keys by fingerprint, or provisions them on a `Provisioner` backend. It refuses certificate keys, RSA and P-384 keys, a key shared by two roles and missing roles, and writes nothing when it refuses. It logs `ca_init` as leaf 0 and writes `ca-pubkeys.json` in the fixed role order.
- **`install-bundle`:**
  - A genesis bundle is verified against the operator's pins and threshold; a successor against the installed bundle.
  - The bundle's CA, ops and log keys, algorithms and custody must equal the ca-init keys.
  - No root key may be a CA key, and no admin key may be an online key.
  - Each install logs `bundle_install` with all four documents.
- **`serve`:** no longer has key pin flags. It refuses to start without a bundle, when a bundle key is missing from the backend, or when a key's custody changed.
- **Admin evidence:** the signer refuses every request without valid `admin-sshsig/v1` evidence from the policy's admin quorum, and logs each refusal as `unauthorized`.
- **CA roles:** all three are served. User and machine requests get user certificates, host requests get host certificates. Each is signed by its own CA under its policy profile, with `pol=1` in the key ID.
- **e2e:** `bootstrapSigner` runs the real ceremony (`ca-init` → `root genesis-policy` → `root sign` → `install-bundle --pin` → `serve`). Every e2e signer now starts this way, and `TestTrustFlowEndToEnd` proves the whole flow against real sshd.

## PR

- PR **#8** `feat(signer): run the signer under a root-signed trust bundle with admin evidence` (https://github.com/Labontese/keyroster/pull/8). Auto-merge (squash) is enabled by keyroster-bot.
- Required checks on implementation head `bac7b29`: `build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)` and `fuzz` all pass. CodeQL and `pinned-actions` pass too.
- All three implementation commits show `verified: true` on GitHub.

## Final CLI Flag Sets

- `keyroster-signer ca-init --state-dir DIR --backend NAME [--backend-opt k=v]... [--key ROLE=SHA256:...]... [--out FILE]`
  - Roles: user, host, machine, ops, log. Give all five keys, or none for a Provisioner backend.
  - `--out` defaults to `{state-dir}/ca-pubkeys.json` and must not exist.
- `keyroster-signer install-bundle --state-dir DIR --bundle FILE --policy FILE [--pin SHA256:...]... [--threshold N] [--backend-opt k=v]...`
  - Signatures are read from `FILE.sigs`.
  - `--pin` and `--threshold` apply to the genesis bundle only. `--threshold` defaults to the number of pins.
- `keyroster-signer serve --state-dir DIR [--socket PATH] [--allow-uid UID]... [--allow-group G]... [--backend-opt k=v]... [--refusal-log-per-minute N] [--refusal-log-burst N]`
  - Removed: `--backend`, `--user-ca-fp`, `--log-key-fp`.
- `keyroster ca issue --pubkey FILE --subject S --principal P... --admin-key SHA256:... [--admin-key ...] [--extension NAME]... [--ca user|host|machine] [--ttl D] [--out FILE] [--socket PATH]`
  - The admin keys sign through the ssh-agent at `SSH_AUTH_SOCK`.

## TDD Gate Compliance (Task 2)

| Gate | Commit | Command | Result |
|------|--------|---------|--------|
| RED | `3bedc13` test(01-07) | `bash scripts/linux.sh 'go test -race -count=1 -run "Trust\|Evidence\|InitCA\|Install\|Profiles\|Custody" -v ./internal/signer/...'` | Exit 1. Exactly four target cases fail on their assertions: `TestInstallBundleRefusals/admin_is_online_key` (`InstallBundle = version 1, error <nil>; want signer: bundle keys do not match the CA keys`), `TestInstallBundleRefusals/successor_with_pins` (`version 2, error <nil>; want signer: bundle refused`), `TestStartRefusesCustodyMismatch/custody_mismatch_at_start` (`New ... = <nil>, want ErrBundleKeys naming custody`) and `TestProfiles/duplicate_extension` (`err = <nil>, want duplicate_extension`). The other 81 cases pass. |
| GREEN | `bac7b29` fix(01-07) | same command | Exit 0, all cases pass. The full race suite, lint and e2e on 9.5p1 and 10.5p1 are green as well. |

- The other Task 2 behaviours were already green at RED: ca-init and install-bundle refusals, evidence, TTL and extension caps. This is expected rather than an unexpected GREEN. The Task 1 tracer implemented the checks the plan's Task 1 action lists, and Task 2 pins them. The 01-06 precedent is the same.
- `gsd-tools check tdd-red-evidence` parses only TAP and Surefire, so the Go evidence is recorded here, as decided in 01-02.

## Task Commits

1. **Task 1: tracer, the end-to-end trust flow:** `8ab01cd` (feat). The tracer gate re-ran the automated `<verify>` (audit/trust/CLI tests, race tests for signer and signerdb, full e2e on 10.5p1) and it passed, so execution continued.
2. **Task 2: refusal matrix and PR (TDD):** `3bedc13` (test, RED), `bac7b29` (fix, GREEN). PR #8 opened.
3. **Task 3: merge gate:** pending owner approval (checkpoint).

## Files Created/Modified

- `internal/signerdb/migrations/0003_trust.sql`, `internal/signerdb/trust.go`: the `backend_config`, `ca_keys` and `trust_bundle` tables and their accessors.
- `internal/signer/trust.go`: `InitCA`, `InstallBundle`, `checkBundleKeys`, `checkPolicyAdmins`, `openRoleKey`, `loadTrust`.
- `internal/signer/evidence.go`: `verifyAdminEvidence` (D-13).
- `internal/signer/profiles.go`: `profileFor`, the per-role `cert.Profile` taken from the policy.
- `internal/signer/signer.go`, `issue.go`, `refusal.go`: bundle-driven `New`, issuance for all three roles, evidence refusal classes.
- `internal/wire/issue.go`: the evidence constants and the signed `Extensions` field. `internal/tlog/leaf.go`: `ReasonUnauthorized`.
- `cmd/keyroster-signer/{cainit,install,serve}.go`, `cmd/keyroster/ca.go`: the CLI.
- `internal/signer/{fixture,trust,evidence}_test.go`, plus migrated `signer_test.go` and `log_test.go`.
- `test/e2e/bootstrap_test.go`, `trust_flow_test.go`, plus migrated `harness_test.go`, `issue_test.go`, `negative_test.go` and `audit_test.go`.

## Decisions Made

See `key-decisions` in the frontmatter. In short:
- Requested extensions are part of the signed request.
- Evidence refusals form their own `unauthorized` log class.
- Custody is re-checked against ca-init at every start and install.
- Admin keys and online keys are disjoint.
- A successor bundle is never verified against operator pins.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Requested extensions travel in the signed request**
- **Found during:** Task 1.
- **Issue:** The plan's `ca issue --extension` had no wire field to travel in. Adding one outside the signing bytes would let a caller add extensions after the admins signed.
- **Fix:** `IssueRequest.Extensions` is now part of `SigningBytes`, with a limit of 8 names of 64 bytes each. Wire tests and fuzz seeds cover it.
- **Files modified:** `internal/wire/issue.go`, `wire_test.go`, `fuzz_test.go`.
- **Committed in:** `8ab01cd`.

**2. [Rule 2 - Missing critical] Refusal class for authorization failures**
- **Found during:** Task 1.
- **Issue:** Evidence refusals had no matching D-14 reason class. They would have been logged as `internal`.
- **Fix:** Added `tlog.ReasonUnauthorized = 15` ("unauthorized"). The specific reason stays in the refusal leaf's detail.
- **Files modified:** `internal/tlog/leaf.go`, `internal/signer/refusal.go`.
- **Committed in:** `8ab01cd`.

**3. [Rule 3 - Blocking] `InstallBundle` needs the backend**
- **Issue:** The `bundle_install` entry needs a checkpoint signed with the log key.
- **Fix:** `InstallBundle(ctx, db, be, pins, threshold, docs..., clock)` takes a backend parameter. `install-bundle` opens the backend recorded at ca-init, and accepts `--backend-opt` overrides as `serve` does. `serve` lost its `--backend` flag, because the backend now comes from `backend_config`.
- **Committed in:** `8ab01cd`.

**4. [Rule 3 - Blocking] Unit tests migrated to the trusted state**
- **Issue:** `signer_test.go` and `log_test.go`, which are not in the plan's file list, built signers with the removed key pins.
- **Fix:**
  - A shared `signer.Fixture` now bootstraps real ca-init and genesis state for both.
  - Leaf indices are shifted by the two bootstrap leaves.
  - The `host_role` and `machine_role` refusal cases (`ca_not_configured`) are replaced by `TestSignerIssuesEveryRole`.
  - `TestLogKeyPinning` is replaced by `TestStartRefusesWithoutTrust`.
- **Committed in:** `8ab01cd`.

**5. [Rule 2 - Missing critical] Hardening found by the refusal matrix**
- **Found during:** Task 2 (RED).
- **Fix:**
  - A policy admin key may not be a CA, ops or log key.
  - A successor install refuses `--pin` and `--threshold` instead of ignoring them.
  - Backend key custody must match the custody ca-init recorded, at start and at install.
  - Requesting the same extension twice is refused as `duplicate_extension`.
- **Committed in:** `bac7b29`.

**6. [Rule 2] ca-init requires an empty audit log**
- **Issue:** Without this check, `ca_init` might not be leaf 0, and the export invariant "the first entries are `ca_init` and `bundle_install`" would not hold.
- **Committed in:** `8ab01cd`.

---

**Total deviations:** 6 auto-fixed (3 blocking, 3 missing critical).
**Impact on plan:** All are needed for correctness or security. No module was added and no file owned by 01-09 was edited. `cmd/keyroster/ca_test.go` reuses the `useKeyring` helper from `root_test.go` without changing it.

## Issues Encountered

- Python heredocs passed through the Bash tool turned `\n` escapes in Go string literals into real newlines. The affected literals were repaired with exact edits before each commit, and every commit builds and passes gofmt.
- `golangci-lint --build-tags e2e` reports existing gosec findings in `test/e2e/harness_test.go` (G204/G703/G301), which predate this plan. The CI lint job does not lint the e2e tag, and the new e2e files are clean.

## Known Stubs

None. Critical options in a policy profile carry into the certificate profile, but Phase 1 has no request field for them. This is intentional: the genesis policy allows none, and a later plan that needs `force-command` adds the field together with its tests.

## User Setup Required

None. No external service needs configuration.

## Next Phase Readiness

- 01-08 can prove the user, host and machine CA separation against real sshd with `bootstrapSigner`. It can also switch `audit verify` to root-anchored `--pin` verification: `bundle_install` leaves already carry the full signed documents.
- 01-10 and 01-11 reuse `bootstrapSigner` with `Backend`/`BackendOpts` and without `RoleKeys`, so a Provisioner backend creates the keys. The helper must not be edited.
- 01-09 runs next on its own branch from `main` once this PR merges.

## Self-Check: PASSED

- All 12 created key files exist on disk.
- Commits `8ab01cd`, `3bedc13` and `bac7b29` are on `origin/p01/07-signer-trust` and verified on GitHub.
- Acceptance greps:
  - `--user-ca-fp`/`--log-key-fp` appear nowhere in `cmd/`, `internal/` or `test/`.
  - `evidence.go` contains `admin-sshsig/v1` and `keyroster/issue-request/v1`.
  - The named cases exist in `evidence_test.go` and `trust_test.go`.
