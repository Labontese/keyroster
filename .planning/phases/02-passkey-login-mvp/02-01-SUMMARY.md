---
phase: 02-passkey-login-mvp
plan: 01
subsystem: signer
tags: [webauthn, passkey, directory, signer, wire, tlog, audit, kr2, sshsig, e2e, tracer, key-02, authz-01]

requires:
  - phase: 01-trust-core
    provides: "signer issuance sequence, wire framing, Merkle log, root-signed policy, CountPinnedSigners, cert.Build, e2e harness with real sshd 9.5p1/10.5p1"
provides:
  - "Policy.WebAuthn (rp_id + origins) with the D-09 rules; keyroster root genesis-policy --webauthn-rp-id/--webauthn-origin"
  - "internal/webauthn: stdlib-only assertion verifier (ES256, EdDSA, RS256) and internal/webauthn/webauthntest soft authenticator"
  - "internal/directory: admin-signed directory (keyroster/directory/v1) with Parse/Validate/Sort/Canonical, VerifySignatures, CheckSuccessor, CheckPolicy, Authorize, Credential"
  - "wire: LoginIssueRequest (0x05, keyroster/login-request/v1), webauthn-assertion/v1 blob, InstallDirectory (0x02/0x82)"
  - "signer: online InstallDirectory, LoginIssue with signer-computed principals and TTL cap, loadDirectory at start, dispatch by message type"
  - "tlog kinds 7 (directory_install) and 8 (login_issue) with exported strict decoders DecodeDirectoryInstallBody / DecodeLoginIssueBody"
  - "audit verify refuses every leaf kind it has no check for (kinds 7 and 8 until 02-04)"
  - "cert key ID kr2 (dir + roles); kr1 unchanged"
  - "TestLoginSignerEndToEnd: the Phase 2 tracer against real sshd, including a signer restart and a second login"
  - "Golden vectors for the four new persistent formats and the kr2 literal; scripts/testonly-firewall.sh in the dependency-firewall CI job"
affects: [02-02, 02-03, 02-04, 02-08, 02-11, 02-12, 02-13, KEY-02, AUTHZ-01]

actuals:
  tokens: 41100   # chars/4 over the added lines of the code, test and vector diff (164382 chars); planning docs excluded
  tasks: 2        # Tasks 1 and 2; Task 3 is the owner merge gate
  commits: 3      # git rev-list --count plan_head_before..HEAD at SUMMARY write; the docs commit follows
plan_head_before: e42f3705bfa49bafcc2c1b3d552b556b1432c79f
plan_head_after: 70bf886bc15b010e3689a68da2b6facd5d83d7ab

tech-stack:
  added: []
  patterns:
    - "One canonical JSON rule: trust.DecodeStrict and trust.CanonicalJSON are exported and the directory uses them instead of a copy"
    - "A leaf-kind reader refuses kinds it has no check for (default branch), so making a kind decodable never makes it silently verified"
    - "Signer state that is not configuration is embedded per concern (logState, directoryState) and guarded by Signer.mu"
    - "Refusals are recorded after the locked method returns (issueOrRefuse, loginOrRefuse, installDirectoryOrRefuse), never from inside s.mu"

key-files:
  created:
    - internal/webauthn/verify.go
    - internal/webauthn/clientdata.go
    - internal/webauthn/webauthntest/soft.go
    - internal/directory/directory.go
    - internal/directory/verify.go
    - internal/directory/authorize.go
    - internal/wire/login.go
    - internal/wire/directory.go
    - internal/signer/login.go
    - internal/signer/directory.go
    - internal/signerdb/directory.go
    - internal/signerdb/migrations/0004_directory.sql
    - test/e2e/login_signer_test.go
    - scripts/testonly-firewall.sh
    - test/vectors/directory_v1.json
    - test/vectors/login_request_signing_v1.hex
    - test/vectors/leaf_directory_install_v1.hex
    - test/vectors/leaf_login_issue_v1.hex
  modified:
    - internal/trust/policy.go
    - internal/trust/canonical.go
    - internal/tlog/leaf.go
    - internal/audit/verify.go
    - internal/cert/keyid.go
    - internal/cert/builder.go
    - internal/signer/server.go
    - internal/signer/refusal.go
    - internal/signer/signer.go
    - internal/signer/logstate.go
    - internal/signerclient/client.go
    - internal/wire/frame.go
    - cmd/keyroster/root.go
    - test/e2e/bootstrap_test.go
    - .golangci.yml
    - .github/workflows/ci.yml
    - test/capslock/keyroster-signer.json

key-decisions:
  - "audit verify refuses any leaf kind it has no check for (audit: entry N (<kind>): not verifiable by this version); kinds 7 and 8 reach that default until 02-04"
  - "cert.KeyID gains Directory and Roles; Roles nil means kr1. KeyID.Equal replaces struct == because Roles is a slice (cert.Build's round-trip check)"
  - "InstallDirectory re-checks the trust bundle in force inside its transaction (trust_changed), like issuance, so a directory is never logged under a stale policy"
  - "loadDirectory keeps the stored directory's bytes and version even when it does not parse or is not authorized, so the next install still has to chain to it"
  - "capslock baseline: internal/directory CAPABILITY_ARBITRARY_EXECUTION added and internal/cert CAPABILITY_ARBITRARY_EXECUTION no longer reported; the shared path is the existing ssh.PublicKey.Verify interface over-approximation reaching crypto/dsa"
  - "requirements-completed is empty: KEY-02 completes in 02-04 and AUTHZ-01 in 02-11"

patterns-established:
  - "Every new persistent format gets a golden vector built from fixed literal values, rewritten only under -update"
  - "A gate script is proved to bite (temporary violation, exit 1, restore with git diff --exit-code) before it is committed"

requirements-completed: []

coverage:
  - id: D1
    description: "A passkey assertion over the exact login request, under an admin-signed directory and a root-signed RP policy, yields a logged kr2 certificate with exactly the role's principals, which real sshd accepts (role:ops) and refuses (u:other); the signer restarts on that log and issues again"
    requirement: KEY-02
    verification:
      - kind: e2e
        ref: "test/e2e/login_signer_test.go#TestLoginSignerEndToEnd (CI e2e (10.5p1) job 117152730790 and e2e (9.5p1) job 117152731072 on bfa634f; local WSL 10.5p1)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Signer-side WebAuthn verification: ES256, EdDSA and RS256 accepted; UV/UP cleared, wrong RP, challenge, origin and type, cross-origin, duplicate clientDataJSON names, non-canonical challenge, wrong key and wrong credential refused"
    requirement: KEY-02
    verification:
      - kind: unit
        ref: "internal/webauthn/verify_test.go#TestWebAuthnVerifyAssertion, TestWebAuthnSignatureAndCredential, TestWebAuthnClientData, TestWebAuthnParsePublicKey"
        status: pass
    human_judgment: false
  - id: D3
    description: "Admin-signed directory: canonical order independent of insertion order, structural refusals, distinct-admin quorum, version chain, policy fit, and the grant computation (roles, principals, minimum TTL, roles via groups)"
    requirement: AUTHZ-01
    verification:
      - kind: unit
        ref: "internal/directory/directory_test.go#TestValidate, TestCanonicalOrder, TestVerifySignatures, TestCheckSuccessor, TestCheckPolicy, TestAuthorize, TestDirectoryGoldenVector"
        status: pass
    human_judgment: false
  - id: D4
    description: "Policy RP field: Phase 1 genesis vector byte-identical, null refused, rp_id and origin rules, genesis-policy flags"
    verification:
      - kind: unit
        ref: "internal/trust/webauthn_test.go#TestPolicyWebAuthn, TestPolicyWebAuthnRPID, TestPolicyWebAuthnOrigins; cmd/keyroster/genesis_webauthn_test.go#TestRootGenesisPolicyWebAuthn"
        status: pass
    human_judgment: false
  - id: D5
    description: "Log kinds 7 and 8 decode strictly, are pinned by golden vectors and fuzzed; audit verify refuses them until 02-04 while Phase 1 kinds verify; the start-up log check counts login_issue leaves"
    verification:
      - kind: unit
        ref: "internal/tlog#TestDirectoryInstallBody, TestLoginIssueBody, TestDirectoryInstallLeafVector, TestLoginIssueLeafVector, FuzzDecodeLeaf (seeds + 20 s run); internal/audit#TestVerifyKindsWithoutChecks"
        status: pass
      - kind: e2e
        ref: "test/e2e/login_signer_test.go#TestLoginSignerEndToEnd step 9 (restart after a login)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Phase 1 paths unchanged: IssueRequest bytes pinned, every Phase 1 e2e test passes, a populated v3 state DB upgrades to the 0004 schema"
    verification:
      - kind: unit
        ref: "internal/wire#TestIssueRequestBytesUnchanged; internal/signerdb#TestMigrations/upgrade_from_v3"
        status: pass
      - kind: e2e
        ref: "test/e2e (all 17 top-level tests, 0 skipped, local WSL 10.5p1; CI e2e 9.5p1 and 10.5p1, e2e-pkcs11, e2e-tpm)"
        status: pass
    human_judgment: false
  - id: D7
    description: "No ./cmd/... binary links a test-only helper (linux, windows, darwin; with and without piv)"
    verification:
      - kind: other
        ref: "bash scripts/testonly-firewall.sh (CI dependency-firewall job 117152731557); bite test recorded below"
        status: pass
    human_judgment: false

duration: 47min
completed: 2026-10-16
status: complete
---

# Phase 2 Plan 01: Signer Login Summary

**A network-less signer now issues a `kr2` user certificate only on a WebAuthn assertion it verified itself (stdlib crypto, no CBOR), over a request whose principals and TTL it recomputes from an admin-quorum-signed directory; real sshd 9.5p1 and 10.5p1 accept it for `role:ops` and refuse it for `u:other`.**

## Performance

- **Duration:** about 47 min
- **Started:** 2026-10-16T18:40Z (about)
- **Completed:** 2026-10-16T19:40Z (about, docs commit)
- **Tasks:** 2 of 3 (Task 3 is the owner merge gate)
- **Files modified:** 48 code, test, vector and CI files, plus planning docs

## Delivery

- **PR:** #33, `feat(signer): issue login certificates on a passkey assertion under a signed directory`. It was opened by keyroster-bot with auto-merge (squash) enabled.
- **Required checks on `bfa634f`:** all 18 passed. They are capslock, dependency-firewall (with the new test-only step), govulncheck, pinned-actions, pr-title, lint, build-test, build-piv, fuzz, e2e (9.5p1), e2e (10.5p1), e2e-pkcs11 (10.5p1-ed25519), e2e-pkcs11 (distro-p256), e2e-tpm, systemd-sandbox, CodeQL, Analyze (go) and Analyze (actions).
- **Later commits:** `70bf886` (the genesis-policy flag test) and the docs commit were pushed afterwards. Their check results are reported with the merge-gate checkpoint, not here.
- **Commit verification:** GitHub reports `1a9a754` and `bfa634f` as Verified (valid SSH signature).

## Accomplishments

- **Policy (D-09).** `trust.Policy.WebAuthn` is an omitempty pointer and the last field. `test/vectors/policy_genesis_v1.json` still parses and re-encodes byte-identically, and `"webauthn":null` is refused as non-canonical.
  - **rp_id rules:** IP literals, ports, uppercase, single labels, trailing dots, all-digit last labels and tailnet domains (fewer than 4 labels under ts.net, fewer than 5 under c.ts.net) are refused.
  - **Origin rules:** each origin is exactly `https://<rp_id>`, or that with a port other than 443. The list is sorted and duplicate-free.
- **Directory (D-01, D-08).**
  - `internal/directory` is canonical JSON. Credential IDs are decoded with strict base64url and SPKI with strict base64 (T-02-77).
  - Quorum is counted with `trust.CountPinnedSigners` against the policy admins.
  - The chain is version + 1 with prev = SHA-256 of the installed bytes.
  - `CheckPolicy` holds role TTLs and extensions to the user CA profile.
  - `Authorize` returns sorted roles, the principal and extension unions, and the minimum TTL.
- **WebAuthn (D-05, D-17).** `internal/webauthn` runs the 10 ordered checks, each with its own sentinel.
  - `clientDataJSON` is parsed with an `encoding/json` v1 token walk. It refuses duplicate names, wrong value types, invalid UTF-8 (checked explicitly) and trailing data, and skips unknown members.
  - authenticatorData must be exactly 37 bytes with AT and ED clear, so the signer never parses CBOR.
- **Signer.**
  - Message type selects the evidence path: 0x01 admin SSHSIG only, 0x05 one `webauthn-assertion/v1` only, 0x02 directory install (T-02-05).
  - `LoginIssue` follows the plan's step order. Its challenge is `req.Digest()`. It refuses unless the principals equal the grant exactly, and it refuses a TTL above min(role cap, user CA cap).
  - The certificate leaves the signer only after its `login_issue` leaf, carrying the full signing bytes, commits in the same transaction as the issuance row and the serial (VIS-01).
- **Log and audit.** Kinds 7 and 8 decode through the exported strict decoders, whose errors wrap `ErrMalformedLeaf`. `rebuildLogFrom` counts `login_issue` leaves into the issuance summary.
- **Interim behaviour of `audit verify`.** From this plan until 02-04, `audit verify` refuses a log at its first `directory_install` or `login_issue` entry with `audit: entry N (directory_install|login_issue): not verifiable by this version` and exits non-zero. A log of kinds 1-6 verifies exactly as before. The walk's default branch refuses any kind it has no case for, and does so before the leaf is hashed, appended or counted.
- **Key ID `kr2`.** The format is `kr2/ca=user/sub=<user>/req=<32 hex>/pol=<n>/dir=<n>/roles=<r1>+<r2>/ser=<n>`, with 1-16 sorted, unique roles and at most 1024 bytes. Admin issuance still emits `kr1`, and `ParseKeyID` accepts both strictly.

### Final wire type numbers

| Message | Type | Response |
|---|---|---|
| IssueRequest (admin, unchanged) | 0x01 | 0x81 IssueResponse |
| InstallDirectory | 0x02 | 0x82 InstallDirectoryResponse |
| LoginIssueRequest | 0x05 | 0x81 IssueResponse (reused) |
| Error | | 0xFF |

### Refusal details added to `classify`

- **ReasonBadPrincipal:** `principals_mismatch`
- **ReasonTTLExceeded:** `ttl_exceeds_role`
- **ReasonMalformed:** `directory_invalid`
- **ReasonUnavailable:** `directory_changed`
- **ReasonUnauthorized:**
  - Evidence and directory state: `too_many_evidence`, `no_webauthn_policy`, `directory_not_installed`, `directory_not_authorized`.
  - Grant: `unknown_user`, `user_disabled`, `role_not_granted`, `unknown_credential`.
  - Assertion checks: `credential_mismatch`, `bad_authenticator_data`, `rp_mismatch`, `user_presence_missing`, `user_verification_missing`, `bad_client_data`, `type_mismatch`, `challenge_mismatch`, `origin_mismatch`, `cross_origin_refused`, `assertion_signature_invalid`, `unsupported_algorithm`.
  - Directory install: `directory_version_chain`, `directory_quorum_not_met`, `directory_exceeds_policy`.
- **Not added:** `authorize_failed`, used only for an `Authorize` error that is none of the three sentinels. It is unreachable today and falls to the internal class.
- **Unchanged mappings:** `extension_not_allowed` and `duplicate_extension` already map.
- **Digests:** login refusals carry `req.Digest()`, directory refusals the SHA-256 of the document, and unparseable bodies a zero digest.

### e2e step 9: restart

After the first login, the log holds a `directory_install` leaf, a `login_issue` leaf and an issuance row written by a login. The signer was stopped and started again on the same state directory, and the start succeeded. That shows `rebuildLogFrom` and `checkLogCovers` accept login issuances and that `loadDirectory` authorized the stored directory. A second login then issued `kr2/.../pol=1/dir=1/roles=ops/ser=...` with a higher serial. This ran locally (WSL, sshd 10.5p1) and in both CI e2e jobs.

### Golden vectors (created once with `-update`, inspected, then unchanged by every later run)

| File | sha256 | Test |
|---|---|---|
| test/vectors/directory_v1.json | 3785ec3e181b13953c2023e93fcc1be3e5abf29d24d4e3717cd2340fffe20d2a | TestDirectoryGoldenVector |
| test/vectors/login_request_signing_v1.hex | 755ed21497aabf2c7539f26b615f21c73a471351d8972f2a48e09cae4026be45 | TestLoginRequestSigningVector (starts with hex of `keyroster/login-request/v1`) |
| test/vectors/leaf_directory_install_v1.hex | 165d699eab3715b979375a2166ec0ca1e002332baa0f101072bec4763279775c | TestDirectoryInstallLeafVector |
| test/vectors/leaf_login_issue_v1.hex | 9f44d69bdafde4822bfa5900813a27ef86fb4df4189a6e1d5fb7c135f89f7837 | TestLoginIssueLeafVector (also pins the assertion-blob encoding) |
| kr2 literal in internal/cert | `kr2/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=1/roles=admin+ops/ser=1700000000000003` | TestKeyIDKr2Golden |

### capslock pairs

- **Added:** `github.com/Labontese/keyroster/internal/directory CAPABILITY_ARBITRARY_EXECUTION`. capslock's path is `signer.New -> loadDirectory -> directory.VerifySignatures -> trust.CountPinnedSigners -> sshsig.Signature.Verify -> (ssh.dsaPublicKey).Verify -> crypto/dsa.Verify`. That is the interface-call over-approximation of `ssh.PublicKey.Verify` already baselined for internal/trust and internal/sshsig. The signer never verifies DSA: sshsig refuses RSA and DSA keys. Reviewed and baselined with `--update`; the pair is in an allowed package.
- **No longer reported:** `github.com/Labontese/keyroster/internal/cert CAPABILITY_ARBITRARY_EXECUTION`. My reading, not verified separately: capslock now attributes the same shared path through internal/directory.
- The total stays at 73 pairs, and no pair outside internal/webauthn and internal/directory is new.

### testonly-firewall bite test

With a temporary `_ "github.com/Labontese/keyroster/internal/webauthn/webauthntest"` import in cmd/keyroster/main.go, the script exited 1:

```
   TEST-ONLY: github.com/Labontese/keyroster/internal/webauthn/webauthntest linked into ./cmd/... (GOOS=linux, tags=default)
   TEST-ONLY: github.com/Labontese/keyroster/internal/webauthn/webauthntest linked into ./cmd/... (GOOS=linux, tags=piv)
   TEST-ONLY: github.com/Labontese/keyroster/internal/webauthn/webauthntest linked into ./cmd/... (GOOS=windows, tags=default)
   TEST-ONLY: github.com/Labontese/keyroster/internal/webauthn/webauthntest linked into ./cmd/... (GOOS=windows, tags=piv)
   TEST-ONLY: github.com/Labontese/keyroster/internal/webauthn/webauthntest linked into ./cmd/... (GOOS=darwin, tags=default)
   TEST-ONLY: github.com/Labontese/keyroster/internal/webauthn/webauthntest linked into ./cmd/... (GOOS=darwin, tags=piv)
testonly-firewall: a release binary links a test-only helper (see above)
```

After `git checkout -- cmd/keyroster/main.go`, `git diff --exit-code -- cmd/keyroster/main.go` succeeded and the script exited 0 with last line `testonly-firewall: clean (6 GOOS/tag combinations)`. `git diff origin/main -- cmd/keyroster/main.go scripts/dep-firewall.sh` is empty.

## Task Commits

1. **Task 1: tracer, from the RP policy to a real sshd login** `1a9a754` (feat)
2. **Task 2: unit coverage, golden vectors and the test-only helper gate** `bfa634f` (test), plus `70bf886` (test, the genesis-policy flags, see Deviations)
3. **Task 3: merge gate.** Not attempted. It is the owner's `checkpoint:human-action`.

**Plan metadata:** the docs commit `docs(02-01): complete signer-login plan` (this file, STATE.md, deferred-items.md).

## TDD record (Task 2, tdd="true"; workflow.tdd_mode is false, so the gate sequence is not enforced)

Task 2 adds tests for code Task 1 already built, so most of its tests passed on their first run. They are recorded as unexpected green, not dressed up as RED:

- **First run green:** TestPolicyWebAuthn*, the TestWebAuthn* tests, TestValidate, TestCanonicalOrder, TestVerifySignatures, TestCheckSuccessor, TestCheckPolicy, TestAuthorize, TestKeyIDKr2*, TestLoginIssueRequest, TestInstallDirectoryMessages, TestIssueRequestBytesUnchanged, TestDirectoryInstallBody, TestLoginIssueBody, TestVerifyKindsWithoutChecks, TestMigrations/upgrade_from_v3 and TestRootGenesisPolicyWebAuthn.
  - TestValidate logs each refusal reason, and each refusal hit its own rule.
  - TestVerifyKindsWithoutChecks was checked by mutation: with the default branch of `audit.Verify` removed, `directory_install_not_verifiable` and `login_issue_not_verifiable` both FAIL. The committed file was then restored.
- **Genuine RED, FuzzDecodeLeaf.** The kind-7 and kind-8 seeds and the loop bound `k <= KindLoginIssue` went in first, before the switch cases. `go test -run '^FuzzDecodeLeaf$' ./internal/tlog/` then failed on 5 seeds with `fuzz_test.go:64: DecodeLeaf accepted kind 7` and `... kind 8`. That is the target's own default-branch assertion, the intended reason. After the two cases were added it passed, and a 20 s fuzz run passed with 2.2M execs.
- **Golden vectors.** Before `-update`, the four golden tests failed with "file not found". That is a missing-fixture failure, not a behaviour RED.
- **testonly-firewall.** The bite test above serves as the gate's RED.

## Decisions Made

See `key-decisions` in the frontmatter. In short:
- `audit verify` refuses unchecked kinds by default.
- `KeyID.Equal` replaces struct comparison.
- `InstallDirectory` re-checks the trust bundle in force inside its transaction.
- `loadDirectory` keeps unauthorized bytes so the chain still holds.
- One capslock pair moved.
- `requirements-completed` stays empty.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `cert.Build` compared KeyIDs with `!=`**
- **Found during:** Task 1 (kr2).
- **Issue:** `KeyID.Roles` is a slice, so the struct is no longer comparable and `parsed != req.KeyID` in internal/cert/builder.go would not compile.
- **Fix:** Added `KeyID.Equal`. builder.go and the existing `TestKeyIDRoundTrip` now use it. builder.go was not in the plan's file list.
- **Files modified:** internal/cert/keyid.go, internal/cert/builder.go, internal/cert/keyid_test.go
- **Verification:** the cert tests, TestBuildKeyID and the e2e kr2 assertions pass.
- **Committed in:** 1a9a754

**2. [Rule 2 - Missing critical] `InstallDirectory` did not re-check the bundle in force**
- **Found during:** Task 1.
- **Issue:** the admin quorum is counted against the policy loaded at start. A bundle installed by a process that bypassed the state lock could otherwise get a directory logged under a stale policy version.
- **Fix:** `checkTrustCurrent` inside the install transaction, as issuance already does. It refuses with `trust_changed`.
- **Verification:** the full race suite and the e2e suite pass. The refusal case belongs to 02-03's refusal matrix and is **UNVERIFIED** here.
- **Committed in:** 1a9a754

**3. [Rule 3 - Blocking] Task 2's first verify command could not select the WebAuthn tests**
- **Issue:** its `-run 'WebAuthn|Directory|...'` matched no test in internal/webauthn, and "no tests to run" fails it.
- **Fix:** the four verifier tests carry a `TestWebAuthn` prefix.
- **Committed in:** bfa634f

**4. [Interpretation] "The bytes of an existing IssueRequest test vector are unchanged"**
- **Issue:** internal/wire has no IssueRequest golden file.
- **What was done:** `TestIssueRequestBytesUnchanged` pins the SHA-256 of `validRequest()`'s body and signing bytes. The hashes were computed with internal/wire/issue.go identical to origin/main (`git diff origin/main -- internal/wire/issue.go` is empty). The test also pins the admin-path constants.
- **Committed in:** bfa634f

**5. [Rule 2 - No unexercised paths] An untested CLI path**
- **Issue:** the `genesis-policy` refusal of `--webauthn-origin` without `--webauthn-rp-id` was written in Task 1 but no test ran it. The e2e exercised only the success path.
- **Fix:** `cmd/keyroster/genesis_webauthn_test.go`, a new file outside the plan's list. It covers the default origin, sorted origins, no flags, the missing RP ID refusal and the IP RP ID refusal.
- **Committed in:** 70bf886

---

**Total deviations:** 5 (2 blocking, 2 missing-critical/coverage, 1 interpretation).
**Impact on plan:** all are needed for correctness or for the plan's own verify. No scope creep and no new dependency.

## Issues Encountered

- **gofmt in the WSL gate.** In WSL, the full gate's `test -z "$(gofmt -l .)"` passes without checking anything: gofmt is not on the WSL login shell's PATH, and the command substitution expands in the outer shell. Formatting was checked with the Windows toolchain's gofmt and with `$(go env GOROOT)/bin/gofmt` from a script file in WSL; both are clean. Logged in `deferred-items.md`.
- **Command quoting.** `scripts/linux.sh` expands `$VAR` and `$(...)` in the outer shell, so WSL runs that need either went through temporary script files under `.git/`. They were never committed and are deleted.

## Not exercised (UNVERIFIED)

- **Real authenticators and browsers.** Every assertion in this plan comes from the soft authenticator (EdDSA in the e2e; EdDSA, ES256 and RS256 in unit tests). No platform authenticator, synced passkey or security key has produced an assertion for this verifier. That includes the 37-byte authenticatorData with AT and ED clear (RESEARCH assumption A6, review finding 02-01-F5). This is **UNVERIFIED** until the dogfood in 02-13 and 02-14.
- **Refusal paths without a test here.** The signer-side refusals (`directory_quorum_not_met`, `directory_version_chain`, `principals_mismatch`, `ttl_exceeds_role`, `trust_changed` on install, `directory_changed`, the start with an unauthorized stored directory, and so on) are implemented but not exercised through the signer in this plan. They are **UNVERIFIED** here. 02-03 owns the refusal matrix, restart re-verification and concurrency. The underlying checks are unit-tested in internal/directory and internal/webauthn.
- **audit verify of kinds 7 and 8 on a real exported signer log.** Only the unit fixture exercises it (`TestVerifyKindsWithoutChecks`). The e2e does not run `audit verify` on a log with those kinds, by plan.

## Known Stubs

None. The soft authenticator is test-only by design and is gated by scripts/testonly-firewall.sh.

## Threat Flags

None beyond the plan's threat model. The new socket message types are the plan's T-02-01..06. No network endpoint was added, and the signer packages stay network-less (depguard and dep-firewall are clean).

## User Setup Required

None.

## Next Phase Readiness

- 02-03 (refusal matrix, fuzz, restart, GetDirectory), 02-04 (audit checks for kinds 7 and 8) and 02-08 (servertest) can start from these names: the `tlog.DecodeDirectoryInstallBody` and `DecodeLoginIssueBody` decoders, the fixture helpers `directoryInstallVector` and `loginIssueVector`, and the `TESTONLY` list.
- Blocked on the owner's merge gate for PR #33.

## Self-Check: PASSED

- Every file in key-files.created exists on disk, and `git ls-files test/vectors` lists the four new vectors.
- Commits 1a9a754, bfa634f and 70bf886 are ancestors of HEAD and carry SSH signatures.
- Task 1 acceptance greps pass:
  - the issue.go diff against origin/main is empty;
  - one `webauthn,omitempty` line, on the last field;
  - the domain strings are present;
  - .golangci.yml count 2;
  - the ValidPrincipals, ValidAfter and 900 assertions;
  - loginOrRefuse is defined and called;
  - leaf.go cases 4, audit "not verifiable" count 1, the KindCAInit case line, the logstate KindLoginIssue case;
  - serveStoppable appears 2 times.
- Task 2 acceptance passes: the named cases exist, the decoder definitions are found by grep, the fuzz `case` count is 2, `k <= KindLoginIssue` is present, dep-firewall.sh and main.go are unchanged, the CI step is present and `check-pinned-actions` passes.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-16 (before the merge gate)*
