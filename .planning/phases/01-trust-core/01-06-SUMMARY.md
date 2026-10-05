---
phase: 01-trust-core
plan: 06
subsystem: trust-anchor
tags: [sshsig, trust-bundle, genesis-policy, canonical-json, tuf, threshold-signatures, ssh-agent, fido, sk-dummy, fuzzing]

requires:
  - phase: 01-04
    provides: "CI e2e matrix (9.5p1/10.5p1) with scripts/build-openssh.sh, test/e2e harness (startDaemon, sshKeygen, sshAdd, fingerprint), scripts/fuzz.sh and the fuzz job"
  - phase: 01-02
    provides: "keyroster CLI dispatcher (register pattern), readPublicKey, stringList; Go module and x/crypto"
provides:
  - "internal/sshsig: Sign, Parse, ParseAll, Signature.Verify, Signature.PublicKey (PROTOCOL.sshsig, sha512 only, ssh-keygen -Y compatible)"
  - "internal/trust: NamespaceBundle, NamespacePolicy, ErrNotCanonical, Bundle/RootSet/RootKey/CAEntry/KeyEntry/LogEntry, ParseBundle, Bundle.Canonical, Bundle.Validate, Policy/AdminKey/CAProfile, ParsePolicy, Policy.Validate, CAPubKeys/CAPubKey, ParseCAPubKeys, ParseRootsFile, CountPinnedSigners, VerifyGenesisBundle, VerifySuccessor, LogOrigin, FormatKey, ParseKey"
  - "internal/rootceremony: SignBundle, SignPolicy, Summary, BundleHash (the only root-signing path)"
  - "CLI: keyroster root genesis-policy, keyroster root sign (ssh-agent root, hash-prefix confirmation), keyroster trust verify"
  - "Golden vectors test/vectors/bundle_genesis_v1.json and policy_genesis_v1.json"
  - "$PREFIX/libexec/sk-dummy.so from scripts/build-openssh.sh; e2e TestRootSK (FIDO-style root in a real ssh-agent)"
affects: [01-07, 01-09, 01-10, 01-14, Phase 3 (successor bundles, ops key as KRL authority), Phase 4 (policy successors)]

actuals:
  tokens: 38000
  tasks: 3
  commits: 8
plan_head_before: 3b78b77b2e89b17223e14a2797afc9b941cbf886
plan_head_after: 850e900297277456edc61cde85b7c39d86834750

tech-stack:
  added: [OpenSSH regress/misc/sk-dummy/sk-dummy.so (test-only, built from the verified tarball)]
  patterns:
    - "Canonical JSON: a signed document is accepted only if it equals json.Marshal(parsed struct) plus one newline, byte for byte; lists are never null and extension lists are sorted, so each document has exactly one encoding"
    - "Trust anchors come only from operator pins (genesis) or the previous accepted bundle (successor); a bundle's own root set must equal the pin set"
    - "Typed SSHSIG namespaces per document type (keyroster/trust-bundle/v1, keyroster/policy/v1); a signature counts only for its own namespace and document"
    - "Oracle tests skip without ssh-keygen locally but fail in CI (KEYROSTER_REQUIRE_ORACLE=1)"

key-files:
  created:
    - internal/sshsig/sshsig.go
    - internal/trust/canonical.go
    - internal/trust/bundle.go
    - internal/trust/policy.go
    - internal/trust/capubkeys.go
    - internal/trust/roots.go
    - internal/trust/verify.go
    - internal/rootceremony/sign.go
    - internal/rootceremony/summary.go
    - cmd/keyroster/root.go
    - cmd/keyroster/trust.go
    - test/vectors/bundle_genesis_v1.json
    - test/vectors/policy_genesis_v1.json
    - test/e2e/root_sk_test.go
  modified:
    - scripts/build-openssh.sh
    - scripts/fuzz.sh
    - .github/workflows/ci.yml

key-decisions:
  - "Canonical encoding = encoding/json Marshal of the struct (declaration order, no whitespace, HTML-safe escapes, integers only) plus one trailing newline; decodeStrict requires byte equality after a DisallowUnknownFields decode, which also refuses case-folded keys, escapes that decode to the same string, a BOM, CRLF and trailing data"
  - "Lists in signed documents are never null; policy extension and critical-option lists are sorted and duplicate-free; an extension may not be both default and allowed (my reading of 'defaults a subset of allowed-or-default': allowed means requestable beyond the defaults)"
  - "Root custody fido is exactly the sk-* key types (both directions); CA, ops and log keys equal to a root key are refused with ErrKeyIsRoot at bundle validation"
  - "internal/sshsig refuses RSA (D-09) and certificate signers and a non-empty reserved field; a blob must re-marshal to itself; sk-* signatures need the user-presence flag, checked explicitly as well as by x/crypto"
  - "VerifySuccessor additionally refuses a successor issued before its predecessor; both the previous and the new root threshold must sign the bundle and the policy"
  - "keyroster trust verify reports signatures by non-pinned keys as 'ignored: ...' lines; CountPinnedSigners keeps the plan's ([]string, error) signature"
  - "keyroster root sign reaches ssh-agent through SSH_AUTH_SOCK (Unix socket) only; the Windows named-pipe agent is not supported yet (no go-winio in go.mod), so the ceremony runs on Linux"
  - "scripts/fuzz.sh passes -fuzzminimizetime 5s: with Go's 60s default, FuzzParseBundle spent its whole 30s CI budget minimizing one input (123 execs); with 5s it ran 100,935 execs in CI"

patterns-established:
  - "Root-signed document = canonical JSON + detached armored SSHSIG blocks appended to FILE.sigs"
  - "Golden vectors from deterministic test keys (Ed25519 seed bytes, P-256 scalar = SHA-256(label||n)), regenerated only with go test -run TestGoldenVectors ./internal/trust/ -args -update"

requirements-completed: [KEY-07]

coverage:
  - id: D1
    description: "SSHSIG signatures made by internal/sshsig verify with ssh-keygen -Y verify, and ssh-keygen -Y sign signatures verify with internal/sshsig, for ed25519, ecdsa-p256 and sk-ssh-ed25519; CI fails instead of skipping when ssh-keygen is missing"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "internal/sshsig/oracle_test.go#TestOracleSSHKeygenVerifiesOurSignatures (ed25519, ecdsa-p256, sk-ssh-ed25519) and #TestOracleWeVerifySSHKeygenSignatures (ed25519, ecdsa-p256): KEYROSTER_REQUIRE_ORACLE=1 in WSL and in CI build-test on 850e900"
        status: pass
      - kind: e2e
        ref: "test/e2e/root_sk_test.go#TestRootSK/fido_root_threshold_1 (ssh-keygen -Y sign with the sk-dummy key verified by internal/sshsig; root sign signature verified by ssh-keygen -Y verify): e2e (9.5p1) and e2e (10.5p1) on 850e900"
        status: pass
    human_judgment: false
  - id: D2
    description: "keyroster root sign builds a canonical genesis bundle and policy, prints the summary, requires the 8-hex hash prefix, signs through ssh-agent, refuses a second signature by the same root; keyroster trust verify accepts it against pinned fingerprints and refuses a one-byte change"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestRootSignTrustVerifyRoundTrip and #TestRootSignTwoOfTwoRoundTrip (in-process agent keyring over net.Pipe; ssh-keygen -Y verify step on Windows, WSL and CI)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Non-canonical JSON (15 variants per document) is refused with ErrNotCanonical before any signature check; each structural violation of bundle and policy is refused with its own error"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "internal/trust/bundle_test.go#TestCanonicalStrictness, #TestBundleValidation, #TestPolicyValidation, #TestCAPubKeysAndRootsFile"
        status: pass
    human_judgment: false
  - id: D4
    description: "Pinning, threshold, namespace and successor (TUF) rules: self-listed root, pin-set mismatch, same root twice, non-pinned signer, wrong namespace, policy hash mismatch, version jump, prev mismatch, only-new or only-old roots all refused; both thresholds accepted"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "internal/trust/verify_test.go#TestVerifyGenesisBundle (self_listed_root_refused, same_root_twice_counts_once, ...), #TestCountPinnedSigners, #TestVerifySuccessor"
        status: pass
    human_judgment: false
  - id: D5
    description: "The root path cannot sign certificates: rootceremony exports exactly SignBundle, SignPolicy, Summary, BundleHash, refuses non-bundle/non-policy input, and go list -deps excludes internal/cert, internal/signer, internal/keystore"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "internal/rootceremony/imports_test.go#TestRootCannotReachCertificateSigning, #TestExportedAPI; sign_test.go#TestSignRefusesOtherDocuments"
        status: pass
    human_judgment: false
  - id: D6
    description: "A FIDO-style root (sk-ssh-ed25519 via sk-dummy.so in ssh-agent, custody fido) signs a bundle that verifies in CI on both OpenSSH versions, including a 2-of-2 fido + ed25519 case where one signature is refused (D-11 stand-in)"
    requirement: KEY-07
    verification:
      - kind: e2e
        ref: "--- PASS: TestRootSK (both subtests) in e2e (9.5p1) job 111668809976 and e2e (10.5p1) job 111668810349 on 850e900; locally in WSL on both prefixes"
        status: pass
    human_judgment: false
  - id: D7
    description: "Three fuzz targets (FuzzParseBundle, FuzzParsePolicy, FuzzSSHSIGParse) run under scripts/fuzz.sh: accepted input re-marshals/re-armors to itself"
    requirement: KEY-07
    verification:
      - kind: other
        ref: "CI fuzz job 111668811587 on 850e900: 'fuzz: all 7 targets passed (30s each)'; FuzzParseBundle 100,935 execs, FuzzParsePolicy 140,603, FuzzSSHSIGParse 1,671,307"
        status: pass
    human_judgment: false
  - id: D8
    description: "PR #7 is green on every required check and waits for the owner at the merge gate"
    requirement: KEY-07
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks p01/06-trust-anchor --required --watch on 850e900: build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz all pass (11 of 11 checks green)"
        status: pass
    human_judgment: true
    rationale: "Owner approval and the squash merge happen at the Task 4 blocking-human merge gate, after this SUMMARY is written"

duration: 38min
completed: 2026-10-05
status: complete
---

# Phase 1 Plan 06: Trust Anchor Summary

**Root keys held in ssh-agent now sign a canonical trust bundle and genesis policy with detached SSHSIG signatures under typed namespaces. `keyroster trust verify` accepts them only when the bundle's root set equals the operator's pinned fingerprints and at least `threshold` distinct pinned roots signed both documents. Successor bundles follow the TUF rule. The root path cannot reach certificate signing. A FIDO-style `sk-ssh-ed25519` root, served by OpenSSH's sk-dummy provider through a real ssh-agent, passes in CI on OpenSSH 9.5p1 and 10.5p1. Stock `ssh-keygen -Y` agrees with our signatures in both directions.**

## Performance

- **Duration:** 38 min
- **Started:** 2026-10-05T07:27:41Z
- **Completed:** 2026-10-05T08:05:53Z
- **Tasks:** 3 of 4 executed before the merge gate (Task 4 is the owner's approval)
- **Files modified:** 29 (26 created, 3 modified), 4035 insertions, 5 deletions

## Accomplishments

- **Task 1 (tracer):** `internal/sshsig`, `internal/trust` (canonical JSON, bundle, policy, ca-pubkeys, roots.pub, genesis verification), `internal/rootceremony`, `keyroster root genesis-policy|sign`, `keyroster trust verify`, the golden vectors and the in-process round trip with an `agent.NewKeyring()` behind `net.Pipe`. The tracer feedback gate (`end-of-phase`, automated-only verify) re-ran both verify commands: green on Windows and in WSL with `KEYROSTER_REQUIRE_ORACLE=1`, so expansion continued.
- **Task 2 (TDD):** negative suite and successor rule. RED was `0d56e68` against a `VerifySuccessor` stub, GREEN was `41874e1`, plus three fuzz targets.
- **Task 3:** `sk-dummy.so` in `build-openssh.sh` and e2e `TestRootSK`. The branch is pushed and PR #7 is open, with auto-merge (squash) enabled by keyroster-bot. All required checks are green.

## PR

- **PR #7** `feat(trust): add root-signed trust bundle and genesis policy` (https://github.com/Labontese/keyroster/pull/7), branch `p01/06-trust-anchor`, opened by keyroster-bot. Auto-merge (squash) is enabled.
- All 8 implementation commits show `verified: true` on GitHub (keyroster-bot signature).
- PR #6 (01-05) is still open and also changes STATE.md, ROADMAP.md and REQUIREMENTS.md. Whichever PR merges second gets rebased by `scripts/merge-gate.sh`. For `.planning/` conflicts, take `origin/main` and re-apply this plan's entries.

## Recorded Facts

| Item | Value |
|---|---|
| Canonical encoding rule | `json.Marshal(struct)` + `"\n"`; parse = single value, `DisallowUnknownFields`, then byte-equal to the re-marshal, else `ErrNotCanonical` |
| `test/vectors/policy_genesis_v1.json` SHA-256 | `d18c6893440b8becc2e13548fe04dfeba6ed0d7d2e7a90e9b24b29ff6f654c63` |
| `test/vectors/bundle_genesis_v1.json` SHA-256 (= its `BundleHash`) | `745a3301f3e0d007851f23499a9593045f089b4489be60031d468d3241ceffb5` |
| Golden fixture keys | roots: Ed25519 seed 0x01 (software), P-256 n=2 (piv), threshold 1; CAs user/host/machine P-256 n=10/11/12 (vtpm); ops P-256 n=13; log P-256 n=14; admin `alice` Ed25519 seed 0x14; issued_at `2026-10-05T00:00:00Z` |
| SSHSIG | magic `SSHSIG`, version 1, hash `sha512` only, 70-column armor identical to ssh-keygen's (re-armor test against `ssh-keygen -Y sign` output) |
| sk-dummy build | `make regress/misc/sk-dummy/sk-dummy.so` in the verified tree, installed to `$PREFIX/libexec/sk-dummy.so`; stamp line now `VERSION SHA256 +sk-dummy`; works on 9.5p1 and 10.5p1 (OpenSSL 3.0.13) |
| ssh-agent for sk keys | `ssh-agent -D -a SOCK -P "$PREFIX/libexec/*"`, `SSH_SK_PROVIDER` for ssh-keygen/ssh-add; the x/crypto agent client signs sk keys unchanged (flags/counter in `Signature.Rest`) |
| CI on 850e900 | build-test 2m6s, lint 30s, govulncheck 24s, e2e 9.5p1 49s, e2e 10.5p1 39s, fuzz 4m42s (7 targets), pr-title 7s |
| Fuzz throughput before/after `-fuzzminimizetime 5s` | FuzzParseBundle 123 execs (CI, 61cf59e) -> 100,935 execs (CI, 850e900) |
| `go.mod` / `go.sum` | unchanged (no module added) |

## TDD Gate Compliance (Task 2)

| Gate | Commit | Command | Result |
|---|---|---|---|
| RED | `0d56e68` test(01-06) | `go test -count=1 ./internal/trust/... ./internal/sshsig/... ./internal/rootceremony/...` | exit 1. All 10 `TestVerifySuccessor/*` subtests fail on their assertions (`err = trust: VerifySuccessor is not implemented, want trust: bundle version or prev hash breaks the chain` / `want ... threshold not met`; the accepted cases fail with `refused: ...`). Everything else passes. |
| GREEN | `41874e1` feat(01-06) | same | exit 0 |
| REFACTOR | `2d53660`, `850e900` refactor(01-06) | full unit suite + CI | green |

- The RED commit includes a `VerifySuccessor` stub that returns "not implemented", so the tests compile and fail on assertions (a missing symbol would be a build failure, which is INVALID_RED). `gsd-tools check tdd-red-evidence` parses only TAP and Surefire, so the Go evidence is recorded here (STATE decision from 01-02).
- The other Task 2 behaviours (canonical strictness, pinning, threshold, validation, SSHSIG refusals, rootceremony guards) passed at RED. This is expected rather than an unexpected GREEN: the Task 1 tracer implemented them, and Task 2 pins them with tests. Before RED, one test bug showed up: the `escaped_string` fixture had lost its `0` escape when the file was written. It was fixed before the RED commit, and the case is refused as intended.

## Task Commits

1. **Task 1: end-to-end root sign → trust verify → ssh-keygen (tracer).** `0f26575` (feat)
2. **Task 2: negative suite, successor rule, fuzz (TDD).** `0d56e68` (test, RED), `41874e1` (feat, GREEN)
3. **Task 3: sk-dummy hardware-root stand-in and PR.** `61cf59e` (test)
4. **Follow-ups on the PR:** `2d53660` (refactor: int `--threshold`), `32b86fd` (test: errorlint/gosec findings from CI lint), `64ea353` (fix: fuzz minimization budget), `850e900` (refactor: `NamespacePolicy` declared in policy.go)
5. **Task 4: merge gate.** No commit (the owner approves; GitHub squash-merges)

**Plan metadata:** the `docs(01-06): complete trust anchor plan` commit on the same PR branch.

## Files Created/Modified

- `internal/sshsig/sshsig.go`: SSHSIG sign, parse (single block and concatenated) and verify
- `internal/trust/canonical.go`: `decodeStrict`, `canonical`, `ErrNotCanonical`
- `internal/trust/bundle.go`: `Bundle` and its validation (D-09 algorithms, custody, roles, key distinctness, log origin), `ParseKey`/`FormatKey`/`LogOrigin`
- `internal/trust/policy.go`: `Policy`, admin keys, CA profiles, `NamespacePolicy`
- `internal/trust/capubkeys.go`, `internal/trust/roots.go`: unsigned ceremony inputs
- `internal/trust/verify.go`: `CountPinnedSigners`, `VerifyGenesisBundle`, `VerifySuccessor`
- `internal/rootceremony/sign.go`, `summary.go`: the only root-signing API
- `cmd/keyroster/root.go`, `cmd/keyroster/trust.go`: CLI groups `root` and `trust`
- `test/vectors/*_genesis_v1.json`: golden vectors
- `test/e2e/root_sk_test.go`: `TestRootSK`
- Tests: `internal/sshsig/{oracle,sshsig,fuzz,helpers}_test.go`, `internal/trust/{bundle,verify,fuzz,vectors,helpers}_test.go`, `internal/rootceremony/{sign,imports}_test.go`, `cmd/keyroster/root_test.go`
- `scripts/build-openssh.sh`: sk-dummy build and stamp tag; `scripts/fuzz.sh`: minimization budget; `.github/workflows/ci.yml`: `KEYROSTER_REQUIRE_ORACLE=1`

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] CI could still skip the ssh-keygen oracle**
- **Found during:** Task 1
- **Issue:** The truth "CI turns a missing ssh-keygen into a failure, never a skip" needs CI to set `KEYROSTER_REQUIRE_ORACLE=1`. No workflow did, and `ci.yml` is not in the plan's file list.
- **Fix:** the `build-test` test step sets `KEYROSTER_REQUIRE_ORACLE: "1"`.
- **Files modified:** .github/workflows/ci.yml
- **Committed in:** `0f26575`

**2. [Rule 1 - Bug] FuzzParseBundle barely fuzzed in CI**
- **Found during:** Task 3 (CI fuzz log of 61cf59e)
- **Issue:** FuzzParseBundle ran 123 executions in 30 s, and FuzzParsePolicy stalled for 15 s. Go's default minimization budget (60 s) exceeds `FUZZTIME`, and each interesting bundle input parses seven SSH keys under coverage instrumentation, so the target spent its whole budget minimizing.
- **Fix:** `scripts/fuzz.sh` passes `-fuzzminimizetime "${FUZZMINIMIZETIME:-5s}"` (a shared script, but these targets triggered the problem). With the fix, CI ran 100,935 FuzzParseBundle executions.
- **Files modified:** scripts/fuzz.sh
- **Committed in:** `64ea353`

**3. [Rule 3 - Blocking] CI lint findings**
- **Found during:** Task 3 (CI lint on 61cf59e)
- **Issue:** errorlint flagged a `!=` comparison of sentinel errors in a test, and gosec flagged G703 on the TempDir write helper.
- **Fix:** `errors.Is`, plus an annotated `//nolint:gosec` on the helper.
- **Committed in:** `32b86fd`

**4. [Rule 1 - Acceptance criterion] `policy.go` did not contain `keyroster/policy/v1`**
- **Found during:** acceptance-criteria loop after Task 3
- **Fix:** `NamespacePolicy` moved from bundle.go to policy.go.
- **Committed in:** `850e900`

### Additions beyond the plan (documented interpretations)

- Exported helpers beyond the artifact list: `trust.GenesisPrev`, `LogOriginPrefix`, `LogOrigin`, `FormatKey`, `ParseKey`, `SHA256Hex`, `TimeFormat`, the role constants, `CAPubKeyRoles`, `CAPubKeys.Key`/`Validate`/`Canonical`, `Policy.Canonical`, and one error sentinel per refusal class. `sshsig` also exports `ErrMalformed`, `ErrNamespace`, `ErrHashAlgorithm`, `ErrKeyType` and `ErrUserPresence`. `rootceremony` exports exactly the four planned functions.
- Golden and oracle tests live in new test files (`internal/trust/vectors_test.go`, `internal/sshsig/oracle_test.go`, helpers). The Task 1 file list named no test file for them.
- Extra refusals: an RSA signer in sshsig (D-09), a non-empty SSHSIG reserved field, root custody/type mismatch (fido ⇔ sk-*), null lists, unsorted extension lists, a successor issued before its predecessor, duplicate or malformed pins.
- `root sign` checks before prompting that the agent key is a root and has not signed. A wrong confirmation leaves `bundle.json` and `policy.json` written but signs nothing. `--threshold` is an `int` in 1..number of roots.

---

**Total deviations:** 4 auto-fixed (2 Rule 1, 1 Rule 2, 1 Rule 3). **Impact:** all were needed for the plan's truths and acceptance criteria. There was no scope creep and no module was added.

## Issues Encountered

- `cryptobyte.String` has no uint32 length-prefixed reader (01-02 noted this for the wire format). `internal/sshsig` reads SSH strings with a local `readString` that is bounded by the remaining input.
- Building OpenSSH in WSL took about 4 min per version, mostly `configure`. In CI the cache keyed on the build-script hash made later runs use the cached prefix (with sk-dummy).
- `scripts/linux.sh '...'` mangles `$var` inside loops. Multi-step WSL checks ran from script files in the scratchpad.

## Known Stubs

None.

## User Setup Required

None. The owner only approves PR #7 at the merge gate.

## Next Phase Readiness

- 01-07 (signer consumes the bundle) can use `trust.VerifyGenesisBundle`, `trust.LogOrigin` (cross-check against `tlog.Origin` once 01-05 is on main), and `Bundle.Root.Keys`, so that the signer refuses CA keys that are roots.
- 01-09 (software roots, age) plugs in as another `ssh.Signer` for `rootceremony.SignBundle`/`SignPolicy`. The `custody=software` summary warning is already in place.
- KEY-07 is shared with 01-07, 01-09, 01-10 and 01-14. GSD's shared-ID gate (`requirements.ready-ids`) therefore keeps it Pending in REQUIREMENTS.md until the last of those plans completes, and REQUIREMENTS.md is unchanged in this plan.
- `keyroster root sign` on Windows needs named-pipe agent support (go-winio) before a Windows ceremony is possible.

## Self-Check: PASSED

- Files present: all 14 `key-files.created` and 3 `modified` (`git diff --name-status 3b78b77..850e900`: 29 files).
- Commits on `origin/p01/06-trust-anchor`: `0f26575`, `0d56e68`, `41874e1`, `2d53660`, `61cf59e`, `32b86fd`, `64ea353`, `850e900`, all verified. `git rev-list --count 3b78b77..HEAD` = 8 before the docs commit.
- Acceptance: `bundle.go` contains `keyroster/trust-bundle/v1` and `policy.go` contains `keyroster/policy/v1`. `root_test.go` asserts exit 0 for a valid verify and exit 1 after a one-byte change. The vectors end in exactly one newline and re-marshal to themselves. `verify_test.go` has `self_listed_root_refused` and `same_root_twice_counts_once`. `imports_test.go` asserts on `go list -deps`. Three fuzz targets run under `scripts/fuzz.sh`. `root_sk_test.go` asserts the `sk-ssh-ed25519@openssh.com` type and custody `fido`. Both e2e jobs pass `TestRootSK`.
- Plan verify commands: the Task 1 unit run and the WSL oracle run (`KEYROSTER_REQUIRE_ORACLE=1`, Oracle/RoundTrip PASS, no SKIP); the Task 2 unit run and `FuzzParseBundle` for 15 s; the Task 3 `build-openssh.sh 10.5p1` with sk-dummy.so present (9.5p1 too), `TestRootSK` on both prefixes, and the required checks green.
