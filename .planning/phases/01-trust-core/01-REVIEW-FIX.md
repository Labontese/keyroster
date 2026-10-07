---
phase: 01-trust-core
fixed_at: 2026-10-07
review_path: .planning/phases/01-trust-core/01-REVIEW.md
method: five sequential area fixers (gsd-code-fixer), one per review area, merged by the orchestrator
branch: p01/17-review-fixes
fix_scope: critical_warning
iteration: 1
findings_in_scope: 29
fixed: 25
partially_fixed: 2
skipped: 2
status: partial
---

# Phase 1 code review fixes (merged)

Scope: the 4 critical and 25 warning findings of `01-REVIEW.md`, after de-duplication.
Info findings were not in scope. Each area was fixed by its own agent, in order A to E,
on branch `p01/17-review-fixes` with one signed commit per finding. The area reports follow
below, unchanged except for their frontmatter.

## Outcome per finding

| ID | Outcome | Commits |
|----|---------|---------|
| A-CR-01 (also C-CR-01) | fixed: requires human verification | 5227172, 068ae1e |
| A-WR-01 | fixed: requires human verification | 344d212 |
| A-WR-02 (also B-WR-01, C-WR-05) | fixed: requires human verification | 2ae8aa1 |
| A-WR-03 | fixed | 50a9472 |
| A-WR-04 | fixed: requires human verification | 8c570e3 |
| A-WR-05 | fixed | 3343ed9 |
| A-WR-06 | fixed: requires human verification | 1b3eff9 |
| A-WR-07 | fixed: requires human verification | 97efc26 |
| B-CR-01 | fixed: requires human verification | cd575df |
| B-WR-02 | fixed | 39c097d |
| B-WR-03 | fixed: requires human verification | ae644ef |
| B-WR-04 | fixed: requires human verification | 8724f9a |
| C-WR-01 | partially fixed (local checks); remainder design-level, deferred to `/gsd-plan-phase 01 --gaps` | a3b2b03, eee8770 |
| C-WR-02 | fixed (also runs the A-WR-01 and B-CR-01 checks in doctor) | 7c953de, b9cc985 |
| C-WR-03 | fixed | 60c791c |
| C-WR-06 | partially fixed (profile compliance); authorization part design-level, deferred | 074086a, 49f6c9a |
| D-CR-01 | fixed: requires human verification (real YubiKey) | 806d410, b7d7eae, f111f09 |
| D-CR-02 | fixed | a685d0c |
| D-WR-01 | fixed | f111f09 |
| D-WR-02 | skipped: design-level (EK certificate verification); bounded fail-closed part committed | bbc1f03 |
| D-WR-03 (also C-WR-04) | fixed | d23d88a |
| D-WR-04 | skipped: design-level (PIV slot attestation); docs only | 22d1465 |
| D-WR-05 | fixed | 3917118 |
| D-WR-06 | fixed | e88a5fe |
| E-WR-01 | fixed (CI-only, UNVERIFIED until a PR title edit re-runs the check) | e796861 |
| E-WR-02 | fixed | 6f61025 |
| E-WR-03 | fixed (force-push path runs only on the next real gate rebase) | 06b90da |
| E-WR-04 | fixed (CodeQL piv build CI-only, UNVERIFIED) | c6b7b7e |
| E-WR-05 | fixed (agent `/proc` checks CI-only) | a490a18, b7e82be |
| lint housekeeping | 4 golangci-lint issues from A-WR-06/A-WR-07 tests | 562abfa |

## Verification gaps this closes

Of the gaps in `01-VERIFICATION.md`, A-CR-01, B-CR-01 (KEY-07), D-CR-01 and D-CR-02 now have code fixes.
Re-run verification after merge. What remains for `/gsd-plan-phase 01 --gaps`:
- **C-WR-01 remainder:** whole-database restore and trailing-entry cuts; checkpoint witnessing by agents/CLI; tlog-tiles.
- **C-WR-06 remainder:** offline verification of issuance authorization (what the issue leaf logs, leaf versioning, quorum check).
- **D-WR-02:** TPM endorsement-key certificate verification.
- **D-WR-04:** PIV slot attestation.
- **Hardware items:** `docs/security/needs-hardware.md` items 2 (YubiKey PIN retry guard, attestation) and 4 (physical TPM: noDA, imported-key refusal, exit 78).

## First CI run of changed required checks

`systemd-sandbox` (agent exposure threshold 1.4 vs 1.3 measured offline), `Analyze (go)` (piv build under CodeQL),
`build-piv` (govulncheck -tags piv) and `pr-title` (new workflow file) run for the first time on this PR.


---


# Phase 01: Code Review Fix Report, Area A (signing boundary)

**Fixed at:** 2026-10-07T04:15:38Z
**Source review:** .planning/phases/01-trust-core/01-REVIEW.md (Area A)
**Iteration:** 1
**Branch:** p01/17-review-fixes (main checkout, `workflow.use_worktrees: false`). Not pushed.

**Summary:**
- Findings in scope: 8 (A-CR-01, A-WR-01 to A-WR-07)
- Fixed: 8 (one signed commit each, plus a follow-up e2e commit for A-CR-01). Six are marked "fixed: requires human verification" because they change logic or state handling: A-CR-01, A-WR-01, A-WR-02, A-WR-04, A-WR-06 and A-WR-07.
- Skipped: 0
- Also resolved by these commits: C-CR-01 (with A-CR-01), and B-WR-01 and C-WR-05 (with A-WR-02). Later area agents should mark those three as resolved and not fix them again.

**Where verification ran:** in the main checkout. Windows: `go build ./...` and `go vet ./...`. WSL Ubuntu (Go 1.27.1 linux/amd64, via `scripts/linux.sh`): everything else, because the signer and cmd tests are `//go:build linux`.

## Fixed Issues

### A-CR-01: A running signer keeps issuing under a superseded trust bundle (also resolves C-CR-01)

**Status:** fixed: requires human verification
**Commits:** 5227172 (fix), 068ae1e (e2e tests adapted to the lock file)
**Files:** `internal/signerdb/trust.go`, `internal/signer/signer.go`, `internal/signer/issue.go`, `internal/signer/refusal.go`, `internal/signer/server.go`, `cmd/keyroster-signer/lock.go` (new), `cmd/keyroster-signer/serve.go`, `cmd/keyroster-signer/install.go`, `cmd/keyroster-signer/cainit.go`, `docs/runbooks/signer-install.md`. Tests: `internal/signer/trustchange_test.go` (new), `internal/signer/listen_test.go` (new), `cmd/keyroster-signer/lock_test.go` (new), `test/e2e/tpm_test.go`, `test/e2e/pkcs11_test.go`.

**Follow-up 068ae1e (e2e lanes not run here):**
- `TestTPMCAInitTwiceRefused` counts the files in the state directory, and the new `signer.lock` would have broken that count. The lock file is now skipped.
- `TestPKCS11CAInitTwiceRefused` ran its second `ca-init` while `serve` was running. The lock would now refuse it before the "already initialised" check the test asserts, so the test uses `prepareSigner` (no serve).

Both changes pass `go vet` with `-tags e2e_tpm` and `-tags e2e_pkcs11`. They have **not been run**, because WSL has no swtpm or SoftHSM2. They run first in the CI `e2e-tpm` and `e2e-pkcs11` lanes.

**Applied fix:**
- `New` records the version of the bundle it loaded. `Issue` reads the installed version (new `signerdb.LatestBundleVersion` / `LatestBundleVersionTx`) at two points:
  - before the CA key signs;
  - as the first statement inside the BEGIN IMMEDIATE issuance transaction. This check is authoritative.
  On a mismatch, `Issue` refuses with `trust_changed` (class unavailable) and logs an operator error. The signer never issues under the old policy, so no `pol=<old>` issue leaf follows a successor's `bundle_install`.
- `serve`, `ca-init` and `install-bundle` take an exclusive `flock(LOCK_EX|LOCK_NB)` on `{state-dir}/signer.lock`. `serve` holds it from before `signer.New` for its whole run. The other two take it before the DB or backend is opened, so a TPM is never touched. `install-bundle` refuses while the service runs, with "...in use by another keyroster-signer process ...; stop the service first". `doctor` and `export-log` take no lock. The flock is in `cmd/keyroster-signer` (stdlib `syscall`), so the capslock baseline is unchanged.
- `Listen` probes an existing socket before unlinking it:
  - a successful dial means another signer is serving there, so it refuses;
  - only `ECONNREFUSED` counts as a stale socket and is removed;
  - any other dial error refuses.
  The probe shows up in a live signer's log as one refused connection (`malformed_frame` or `peer_not_allowed`).
- `signer-install.md` has a new "Install a successor bundle: stop, install, start" section.

**Tests:**
- `TestTrustChangedUnderLiveSigner` installs v2 through a second DB handle while a `Signer` is live. It then checks:
  - three requests are refused with `trust_changed`;
  - no issue leaf follows the v2 `bundle_install`;
  - the export passes `audit.Verify`, which is the C-CR-01 property;
  - after a restart the signer issues with `pol=2` and the export still verifies.
- `TestTrustChangedDuringIssue` uses a backend hook that installs v2 while the CA key signs, after the pre-check. The in-transaction check refuses, the dropped certificate is the only signature, and there is no issuance row.
- `TestListenKeepsLiveSocket` covers three sockets: a live one is refused, a stale one is replaced, and a regular file is refused.
- `TestStateDirLock` holds the lock. `install-bundle`, `ca-init` and `serve` each exit 1 with the lock message, and `ca-init` writes no output.
- Fail-before: with the `issue.go` change stashed, both TrustChanged tests fail (`state_unavailable` on the first request; the later ones issued under v1).

### A-WR-01: `loadTrust` takes the `trust_bundle` row on faith

**Status:** fixed: requires human verification
**Commit:** 344d212
**Files:** `internal/signer/logstate.go`, `internal/signer/signer.go`, `internal/signer/trust.go`. Test: `internal/signer/trustanchor_test.go` (new).

**Applied fix:**
- The log rebuild, which is verified against the log key's checkpoint, also returns the body of the last `bundle_install` leaf.
- `checkBundleLogged` requires the stored row to match that leaf exactly: the same version, and byte-identical bundle, bundle sigs, policy and policy sigs. Missing on either side is refused too.
- `New` runs the check after `initLog` and refuses to start with `errLogMismatch`.
- `InstallBundle` runs the same check before it verifies a successor against the stored row. It also refuses a genesis install when the log already records a bundle. The log writer is therefore opened before verification.

**Tests:** `TestStoredBundleMustMatchLog` covers:
- an unlogged but internally consistent v2 row whose attacker policy names `mallory` as the only admin;
- a replaced installed policy;
- replaced signatures;
- deleted rows.
New and InstallBundle both refuse, and nothing is logged. Fail-before: all four subtests fail with the fix stashed. Before the fix, New accepted the attacker row.

### A-WR-02: Successor install does not chain the policy (also resolves B-WR-01 and C-WR-05)

**Status:** fixed: requires human verification
**Commit:** 2ae8aa1
**Files:** `internal/trust/verify.go`, `internal/signer/trust.go`, `internal/audit/verify.go`, `docs/runbooks/signer-install.md`. Tests: `internal/trust/verify_test.go`, `internal/signer/trust_test.go`, `internal/audit/verify_test.go`.

**Applied fix:** `trust.VerifySuccessor(prev, prevCanonical, prevPolicy, next, nextSigs, policy, policySigs)` gained a `prevPolicy` parameter.
- `prevPolicy` must hash to `prev.PolicySHA256` and parse.
- A successor's policy must then be byte-identical to `prevPolicy`, or be version `prev+1` with `prev == SHA256(prevPolicy)`. Anything else returns `ErrVersionChain`.
- Callers: `InstallBundle` passes `latest.Policy`; `audit.Verify` keeps the policy bytes in force in `anchor.policyDoc`.
- The runbook states the rule.

**Tests:**
- `TestVerifySuccessorPolicyChain` covers six cases:
  - unchanged policy: accepted;
  - chained v2: accepted;
  - same version with a different policy: refused;
  - v+2: refused;
  - wrong prev: refused;
  - `prevPolicy` not the bundle's: refused.
- `TestInstallBundleRefusals` has two new cases: `successor_policy_same_version` and `successor_policy_unchained`.
- `TestVerifyAnchoring` has three new cases: a chained policy that verifies with `pol=2`, a same-version policy that is refused, and an unchained policy that is refused.

Fail-before: the signer and audit cases fail with the fix stashed. The trust test does not compile against the old signature, which is expected.

### A-WR-03: `admin_quorum` > 4 makes issuance impossible

**Status:** fixed
**Commit:** 50a9472
**Files:** `internal/trust/policy.go`. Tests: `internal/trust/bundle_test.go`, `internal/signer/evidence_test.go`.

**Applied fix:**
- New `trust.MaxAdminQuorum = 4`. `Policy.Validate` refuses a larger quorum with "... the most admin signatures one issue request can carry".
- `trust` does not import `wire`, so the root ceremony's dependency graph is unchanged. A signer test keeps `trust.MaxAdminQuorum == wire.MaxEvidence`.
- `root genesis-policy` already calls `Validate`, so the ceremony, install-bundle and serve all refuse such a policy.

**Tests:** `quorum_above_max_refused`, `quorum_at_max_accepted` and `TestAdminQuorumFitsEvidence`. The last one issues a certificate at quorum 4 with 4 admins.

Fail-before was only a build failure: with the fix stashed, `MaxAdminQuorum` is undefined. It was not a behavioural failure. By reading the code: before the fix, `Validate` accepted quorum 5 with 5 admins.

### A-WR-04: A replayed request is refused only after the CA key has signed it

**Status:** fixed: requires human verification
**Commit:** 8c570e3
**Files:** `internal/signerdb/issuance.go` (`RequestIDUsed`), `internal/signer/issue.go`. Test: `internal/signer/trustchange_test.go`.

**Applied fix:** `Issue` calls `RequestIDUsed` after the evidence and policy checks and before `LastSerial`/`serial.Next`/`cert.Build`. A used ID is refused as `duplicate_request`. The UNIQUE constraint stays the backstop.

**Tests:** `TestReplayRefusedBeforeSigning` counts signatures by the user CA key through a backend wrapper. One issuance followed by three replays gives 1 signature and an unchanged serial high-water mark. Fail-before: 4 signatures.

### A-WR-05: The refusal `cause` is never logged

**Status:** fixed
**Commit:** 3343ed9
**Files:** `internal/signer/refusal.go`, `internal/signer/issue.go` (the `cause` comment). Test: `internal/signer/refusalcause_test.go` (new).

**Applied fix:** `refuseErr` adds `cause_type` (`%T`) and `cause` (its text) to the single "refused" operator log record when the refusal is internal or unavailable. That covers `state_unavailable`, `serial_unavailable`, `clock_regression`, `trust_changed`, `build_failed`, `log_encoding`, `bad_policy` and `internal_error`.

For refused-class refusals (bad key, principal, evidence and similar) nothing about the cause is logged, because its text can carry peer bytes: `ssh.ParsePublicKey` puts the peer's algorithm name in its error. The cause never reaches the peer or the audit log.

Deviation from the suggested patch: there is no separate "refusal cause" record. The cause is folded into the existing "refused" record, so the existing tests that require exactly one reason-coded record per refusal still hold. An earlier draft logged `cause_type` for refused requests too. `TestRefusalEndToEnd` caught that `*fmt.wrapError` matches the principal `"*"`, so `cause_type` is not logged for refused requests.

**Tests:**
- `TestRefusalCauseLogged`:
  - an injected checkpoint failure puts `state_unavailable` and its cause text in the log, but not in the peer message;
  - `bad_subject_key` with a peer-chosen algorithm name puts neither the cause nor the peer text in the log.
- Fail-before: the first subtest fails.

### A-WR-06: `doctor`'s log check is not snapshot-consistent

**Status:** fixed: requires human verification
**Commit:** 1b3eff9
**Files:** `internal/signerdb/log.go` (`ReadLogWithHashes`), `internal/signer/logstate.go`. Tests: `internal/signerdb/db_test.go`, `internal/signer/log_test.go`.

**Applied fix:**
- `ReadLogWithHashes` reads every leaf together with its stored hash in one query, and then the latest checkpoint, all in one `ReadOnly` transaction. On modernc, a `ReadOnly` transaction is a deferred `BEGIN`, so it reads one WAL snapshot.
- `rebuildLogFrom` (serve start-up and doctor's `CheckLog`) uses it.

**Tests:**
- `TestReadLogWithHashesSnapshot` (deterministic): another connection commits leaf 3 in the middle of the read, and the read returns exactly 3 leaves and checkpoint 3. The next read sees 4.
- `TestCheckLogAgainstLiveSigner` runs `CheckLog` on a read-only handle in a loop while the signer issues 60 certificates.
  - Fail-before: it failed in 3 of 3 runs within 17 to 312 checks ("leaf 4 has no stored hash" and "checkpoint size 3 does not match the 2 stored leaves").
  - After the fix: it passes 10 of 10 runs on Windows and 5 of 5 with `-race` in WSL.

### A-WR-07: The accept loop blocks on `s.mu` when over capacity

**Status:** fixed: requires human verification
**Commit:** 97efc26
**Files:** `internal/signer/server.go`, `internal/signer/refusal.go`, `internal/signer/signer.go`. Test: `internal/signer/overload_test.go` (new, linux).

**Applied fix:**
- Over capacity, the accept loop closes the connection, writes the same "refused" slog record (no mutex needed) and increments `Signer.overloaded`, an `atomic.Uint64`.
- Under `s.mu`, `flushSummaries` moves that counter into `limiter.counts[ReasonOverloaded]`, so every overloaded connection appears in a `refusal_summary` leaf. The final flush at shutdown included.

**Tests:** `TestOverloadDoesNotStallAccept`:
- holds `s.mu` and fills all 32 slots;
- requires each of 3 further connections to see EOF within 3 s;
- after shutdown, requires the refusal summaries to count exactly 3 overloaded connections.

Fail-before: connection 34 timed out, because the loop was blocked in `refuse` after closing connection 33.

## Commands run (at 97efc26; 068ae1e changes only `e2e_tpm` and `e2e_pkcs11` test files, which were vetted again afterwards)

| Where | Command | Result |
|---|---|---|
| Windows | `go build ./...`, `go vet ./...` | ok |
| WSL | `gofmt -l .` | clean |
| WSL | `go build ./...`, `go vet ./...` | ok |
| WSL | `CGO_ENABLED=1 go build -tags piv ./...` | ok |
| WSL | `go test -race -count=1 ./...` | all packages ok |
| WSL | `go vet -tags e2e`, `-tags e2e_tpm`, `-tags e2e_pkcs11` on `./test/e2e/` | ok |
| WSL | `KEYROSTER_OPENSSH_PREFIX=~/.cache/keyroster/openssh-10.5p1 go test -tags e2e -count=1 ./test/e2e/` | ok (12.8 s). The harness builds both binaries from the working tree. It runs `ca-init`, `install-bundle` and `serve` one after another, so it covers taking and releasing the lock without contention. Contention and the live or stale socket cases are covered only by `TestStateDirLock` and `TestListenKeepsLiveSocket`. |
| WSL | `bash scripts/capslock-check.sh` | 73 pairs, the same as the baseline |
| WSL | `bash scripts/dep-firewall.sh` | clean (only the documented libc exception) |

Before each commit, `go build`/`go vet` and `go test -race` ran on the packages it touched.

Fail-before was shown by stashing the non-test change. It failed on behaviour for A-CR-01, A-WR-01, A-WR-04, A-WR-05, A-WR-06, A-WR-07, and for the signer and audit parts of A-WR-02. It was only a build failure (an undefined constant or the old signature) for A-WR-03 and for the trust-package test of A-WR-02.

**Not run:**
- `golangci-lint`: not installed on Windows or in WSL.
- The `e2e_tpm`, `e2e_pkcs11` and systemd smoke suites: they need swtpm, SoftHSM2 or systemd, which only the CI lanes have. These lanes include the two tests adapted in 068ae1e.

## UNVERIFIED / needs-environment

- **Successor install on the homelab signer** (stop, `install-bundle`, start) has not been run on the vTPM signer. It is labelled UNVERIFIED in `docs/runbooks/signer-install.md`.
- **`signer.lock` inside the systemd sandbox:** not run here. It is covered only by the CI `systemd` smoke check (`test/systemd/smoke.sh` starts `serve` under the unit with `StateDirectory=`). The runbook says so.
- **Adapted e2e tests:** `TestTPMCAInitTwiceRefused` and `TestPKCS11CAInitTwiceRefused` (068ae1e) have only been vetted, not run. The CI lanes run them first.

No PIV or other hardware code was touched, so nothing was added to `docs/security/needs-hardware.md`.

## Notes for later area agents

- C-CR-01, B-WR-01 and C-WR-05 are resolved by 5227172 and 2ae8aa1.
- `trust.VerifySuccessor` has a new parameter (`prevPolicy`, third position). B-CR-01, which bars a root key as a policy admin, may touch the same function or `InstallBundle`.
- Not addressed here (out of scope or Info):
  - A-IN-02: the `broken` log is not fatal. `trust_changed` also keeps the process running and refusing until a restart.
  - C-WR-01: rollback to an earlier signed prefix.
  - `doctor` does not run the new stored-bundle-vs-log check (A-WR-01); only `serve` and `install-bundle` do.

---

_Fixed: 2026-10-07T04:15:38Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_

---


# Phase 01: Code Review Fix Report, Area B (trust anchor and roots)

**Fixed at:** 2026-10-07
**Source review:** .planning/phases/01-trust-core/01-REVIEW.md (section "# Area B")
**Iteration:** 1
**Branch:** p01/17-review-fixes (main checkout, `workflow.use_worktrees: false`)

**Summary:**
- Findings in scope: 5 (B-CR-01, B-WR-01..04)
- Fixed: 4
- Skipped: 1 (B-WR-01, a duplicate already fixed in area A)

**Where verification ran:** in the main checkout. The Windows Go 1.27.1 toolchain ran build, vet,
gofmt and `go test ./...`. WSL (Go 1.27.1, cgo) ran `go test -race` and the `-tags piv` build.
WSL also ran the e2e FIDO root test against the cached OpenSSH 10.5p1 build. These results are
reproducible from this tree.

## Fixed Issues

### B-CR-01: A root key is accepted as a policy admin key

**Status:** fixed: requires human verification (a security invariant enforced in three packages)
**Commit:** cd575df
**Files modified:** `internal/trust/verify.go`, `internal/trust/bundle.go`, `internal/trust/verify_test.go`, `internal/signer/trust.go`, `internal/signer/trust_test.go`, `cmd/keyroster/root.go`, `cmd/keyroster/root_test.go`, `docs/runbooks/root-ceremony.md`

**Applied fix:** a new `trust.CheckAdminsNotRoots(p, rootSets...)` refuses an admin whose key, compared by wire encoding, equals a root key. It returns `ErrKeyIsRoot`, whose message now names policy admin keys too. It is called from:
- `VerifyGenesisBundle`, against the bundle's roots.
- `VerifySuccessor`, against both the successor's roots and the previous bundle's roots. This catches three cases: an admin that is a new root, an admin that is a retired root, and an unchanged policy whose admin the successor makes a root.
- The signer's `checkPolicyAdmins`, which now takes the bundle. Both `InstallBundle` and serve start-up (`loadTrust`) run it. At start it compares admins only with the *installed* bundle's roots. A record from before this fix whose admin is a root that an *earlier* bundle retired still loads at start. Only `audit verify` catches that case, through `VerifySuccessor`. The commit message's "a stored record from before this check is refused at start" holds only for the installed bundle's roots.
- `root sign`, before `prepareBundle`, so a refused pair writes nothing to `--out-dir`.

`trust verify` and `audit verify` reach the check through the two Verify functions. The runbook now says an admin key must not be a root key.

**Tests (each confirmed failing with the fix removed):**
- `TestVerifyGenesisBundle/root_as_policy_admin_refused`.
- `TestVerifySuccessorAdminNotRoot`: one accepted control and three refusals.
- `TestInstallBundleRefusals/admin_is_root` and `/successor_admin_is_root`.
- `TestStartRefusesRootAsAdmin`: a stored record plus its log entry, written without verification, is refused by `New`.
- `TestRootSignRefusesRootAsAdmin`: `root sign` refuses and `--out-dir` is not created.

The audit path is covered only through the trust-level tests. No audit test builds a log whose bundle_install has a root as admin; producing one would need forging the log.

### B-WR-02: Appending to a `.sigs` file without a trailing newline makes it unparseable

**Status:** fixed
**Commit:** 39c097d
**Files modified:** `cmd/keyroster/root.go`, `cmd/keyroster/root_test.go`

**Applied fix:** `appendSignature` replaces `appendFile` for `.sigs` files. It adds the missing final newline, then checks that the combined bytes still parse with `sshsig.ParseAll` before writing. If they don't, it refuses and leaves the file unchanged.

**Tests:**
- `TestRootSignAppendsAfterMissingNewline`: a two-root ceremony whose `.sigs` files lose their final newline between signings still verifies at threshold 2. This failed before the fix.
- `TestAppendSignatureRefusesUnparseable`.

### B-WR-03: The two `.sigs` appends are not atomic, and a partial failure blocks the ceremony

**Status:** fixed: requires human verification (the rerun/state behaviour of root sign changed)
**Commit:** ae644ef
**Files modified:** `cmd/keyroster/root.go`, `cmd/keyroster/root_test.go`, `docs/runbooks/root-ceremony.md`

**Applied fix:**
1. **Per-document duplicate check.** `hasSignature` replaces `refuseIfSigned`. A document this root already signed is skipped and reported. The command is refused only when both documents are already signed ("... already holds a signature ... nothing to sign"). All signatures are made before any file is written.
2. **Atomic `.sigs` writes.** `replaceFile` writes to a temporary file in the same directory, sets mode 0644, syncs, closes and renames. It removes the temporary file on any error.
3. **Root key flush.** `writeExclusive` calls `f.Sync()` before `Close`. This covers the encrypted root key and its `.pub` file.

The runbook says to rerun `root sign` after a partial failure and not to edit `.sigs` by hand.

**Tests:** `TestRootSignRerunAfterPartialFailure` signs, deletes `policy.json.sigs`, then reruns. The rerun signs only the policy and leaves one signature per file. `trust verify` passes, a further rerun is refused, and no temporary file is left. On Unix (WSL) the mode is 0644. This failed before the fix.

**UNVERIFIED:**
- The failure paths are not exercised by any test: disk full, media pulled mid-write, and a `Sync` or `Rename` error. Durability across power loss is not tested either. `replaceFile`'s comment says this.
- The parent directory is not fsynced, so the rename itself can still be lost if the media is pulled without unmounting.
- The `writeExclusive` sync runs in the existing `root init` tests, but only on the success path.

### B-WR-04: `trust verify` reports a signer count that is not the number of roots that signed both documents

**Status:** fixed: requires human verification (counting logic)
**Commit:** 8724f9a
**Files modified:** `cmd/keyroster/trust.go`, `cmd/keyroster/root_test.go`, `test/e2e/root_sk_test.go`, `docs/runbooks/root-ceremony.md`

**Applied fix:** `trust verify` prints three kinds of lines:
- `signed by root X` for each root that signed both documents;
- `root X signed the bundle only` or `root X signed the policy only` for the rest;
- a final line: `OK: <both> of <N> pinned roots signed both documents (bundle <b>, policy <p>, threshold <t>)`.

Verification is unchanged: each document must meet the threshold on its own. The runbook's expected line and the transcript instruction were updated.

**Tests:** `TestTrustVerifyReportsSignersPerDocument` reproduces the review's example: pins A, B and C at threshold 2, A and B sign the bundle, B and C sign the policy. The output is "1 of 3", with A and C named as single-document signers. This failed before the fix. The existing CLI assertions and the e2e `TestRootSK` were updated; `TestRootSK` ran in WSL with `-tags e2e` and `KEYROSTER_OPENSSH_PREFIX=~/.cache/keyroster/openssh-10.5p1` and passed.

## Skipped Issues

### B-WR-01: The policy version/prev chain is never enforced

**File:** `internal/trust/verify.go:168-200`
**Reason:** skipped: duplicate of A-WR-02, fixed in 2ae8aa1
**Original issue:** A successor's policy version and prev were never checked against the policy in force.

## Commands run (final tree, 8724f9a)

- Windows: `go build ./...`, `go vet ./...` and `gofmt -l .` were clean, and `go test -count=1 ./...` passed.
- WSL: `go test -race -count=1 ./...` passed in every package. `go build -tags piv ./...` and `go vet -tags piv ./...` passed.
- `go vet -tags e2e ./test/e2e/` was clean, and so were `GOOS=linux go vet -tags e2e_pkcs11` and `-tags e2e_tpm`.
- In WSL, with `KEYROSTER_OPENSSH_PREFIX=~/.cache/keyroster/openssh-10.5p1`, every `-tags e2e` test passed:
  - TestAuditVerifiesIssuance, TestAuditDetectsTampering, TestRefusalsAreAudited;
  - TestHostCertificateNoTOFU, TestMachineCAIsSeparate, TestHostCAIsNotUserCA;
  - TestDoctorReportsTestCustody, TestIssueAcceptedBySSHD, TestSSHDRejects, TestSignerRefuses, TestTrustRefuses;
  - TestRootSK, TestTrustFlowEndToEnd, TestServeRefusesWithoutBundle.
- The `e2e_pkcs11` and `e2e_tpm` lanes were **not run** (they were compile-checked only). Their fixtures use separate root and admin keys, and they do not parse the changed output lines.
- `test/systemd/smoke.sh` was **not run**. It was read: it uses a separate admin key and does not parse the `root sign` or `trust verify` output.
- Before each commit: build, vet, gofmt, and `go test -race` on the touched packages (trust, signer, audit and cmd/keyroster for B-CR-01; cmd/keyroster for the rest).
- golangci-lint is not installed locally and was not run. CI will run it. `replaceFile`'s `f.Chmod(0o644)` and `os.CreateTemp` may need gosec annotations if the linter flags them.

## Notes for later areas

- **Area C (Merkle log, audit, doctor):**
  - `audit verify` refuses a root listed as a policy admin only through `trust.VerifyGenesisBundle`/`VerifySuccessor`. No audit-level test covers it.
  - The text of `trust.ErrKeyIsRoot` changed to "a CA, ops, log or policy admin key equals a root key".
  - `signer.checkPolicyAdmins` now takes the bundle as well: `(b, p, caKeys)`.
  - Serve now refuses at start a database whose policy lists one of the installed bundle's roots as an admin. Doctor does not report that case yet, and may need to.
- **Area D (keystores):** nothing in area B touched it.
- **Area E (CI, scripts, deploy):**
  - The output of `trust verify` changed. The final line is now `OK: <both> of <N> pinned roots signed both documents (bundle <b>, policy <p>, threshold <t>)`, with new `root ... signed the bundle only` and `... the policy only` lines.
  - `root sign` now prints one `signed <doc> with <fp>` line per document, plus `... already holds a signature by ...; not signing it again` for a skipped one.
  - Nothing in CI, scripts or deploy parses these lines today (checked by grep).
  - golangci-lint was not run locally. gosec may flag `os.CreateTemp` or `f.Chmod(0o644)` in `replaceFile`.

---

_Fixed: 2026-10-07_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_

---


# Phase 01, Area C: Code Review Fix Report

**Fixed at:** 2026-10-07T05:12:15Z
**Source review:** .planning/phases/01-trust-core/01-REVIEW.md (section "# Area C")
**Iteration:** 1
**Branch:** p01/17-review-fixes (main checkout, use_worktrees=false; nothing pushed)

**Summary:**
- Findings in scope: 7 (C-CR-01, C-WR-01..06; C-IN-* out of scope)
- Fixed: 4 (C-WR-02 and C-WR-03 fully; C-WR-01 and C-WR-06 only in their bounded local part, with the rest deferred as design-level, see below)
- Skipped: 3 (duplicates owned by other areas: C-CR-01, C-WR-04, C-WR-05)

All verification ran in the **main checkout**, under WSL (Linux, go1.27.1). Windows-native runs are noted where used.

## Fixed Issues

### C-WR-03: doctor prints OK hardware custody for TPM keys when the TPM was not inspected

**Status:** fixed
**Commit:** 60c791c
**Files modified:** `internal/doctor/doctor.go`, `internal/doctor/doctor_test.go`, `docs/runbooks/signer-install.md`
**Applied fix:** The TPM switch in `custodyResults` gets a `default` case. It covers keys recorded as `tpm` or `vtpm` when neither `TPMCustody` nor `TPMError` is set. It emits `WARN tpm_unavailable` ("the TPM was not inspected, so that custody is unconfirmed") and marks the result weak, so the `OK custody` line is not printed. The doctor table in the runbook now says this.
**Test:** `TestTPMNotInspected` (tpm and vtpm subtests). Before the fix it fails because `OK custody` is printed.

### C-WR-02: doctor checks the log against the log key in the same DB, never against the installed bundle

**Status:** fixed (also covers the two notes from areas A and B)
**Commits:** 7c953de, plus follow-up b9cc985 (doc claim qualified, ErrNotInitialised branch tested)
**Files modified:** `internal/signer/trust.go`, `internal/signer/logstate.go`, `internal/signerdb/log.go`, `internal/signerdb/trust.go`, `cmd/keyroster-signer/doctor.go`, `internal/doctor/doctor.go`, plus tests in `internal/signer/{trust_test,trustanchor_test}.go`, `internal/signerdb/db_test.go`, `internal/doctor/doctor_test.go`, `test/e2e/doctor_test.go`, and `docs/runbooks/signer-install.md`
**Applied fix:**
- The part of `loadTrust` that needs no backend is now `checkStoredTrust`. It checks:
  - record consistency;
  - `checkBundleKeys`, so the bundle's log key must be the recorded one;
  - `checkPolicyAdmins` (B-CR-01: no root and no online key as admin);
  - a profile for every CA role;
  - the log origin against the recorded log key.

  serve runs exactly the same code as before, then opens the keys.
- New `signer.CheckTrust(ctx, db)` runs `checkStoredTrust` plus `checkBundleLogged` (A-WR-01). Both run on one snapshot: `signerdb.ReadLogWithHashes` now returns a `*LogSnapshot` with the checkpoint, CA keys and latest bundle, read in the same read transaction as the leaves.
- doctor's results:
  - `FAIL trust_mismatch` when `CheckTrust` fails ("serve refuses to start");
  - `OK trust` when a bundle is installed and the checks pass;
  - no trust line when no bundle is installed and the log records none.
- The `CheckTrust` comment, the doctor package doc and the runbook state the limit. doctor has neither the backend's keys nor the root pins, so a database rewritten consistently, with keys and roots of the rewriter's choosing, passes doctor. serve refuses it only while the rewriter cannot also put their keys into the backend. With the agent backend, whoever can use the agent socket can do that. The check that holds is `keyroster audit verify --pin`. (b9cc985 qualified this; 7c953de said serve always refuses it.)

**Tests:**
- `TestCheckTrustLogKeySwapped`: the tamper the review describes, with the log key swapped and the checkpoint re-signed. `CheckLog` passes; `CheckTrust` returns `ErrBundleKeys`.
- `CheckTrust` assertions were added to the A-WR-01 tests (`TestStoredBundleMustMatchLog`, 4 tampers, `errLogMismatch`) and the B-CR-01 test (`TestStartRefusesRootAsAdmin`, `ErrKeyIsRoot`).
- doctor unit tests for `trust_mismatch` and `OK trust`.
- The snapshot test now also covers the trust tables.
- e2e `TestDoctorFailsWhenServeWouldRefuseTheBundle`, for replaced policy signatures and a deleted bundle row. Against the real binary, without the doctor wiring, doctor exits 0 (shown before the commit).

### C-WR-01: serve and doctor accept a log rolled back to an earlier signed prefix, or wiped

**Status:** partial: fixed: requires human verification; remainder skipped: `design-level: deferred to /gsd-plan-phase 01 --gaps`
**Commits:** a3b2b03, plus follow-up eee8770 (test for the "entries but no CA keys" branch; runbook says to keep exports and use `--previous <earlier export>`, the form the e2e test exercises)
**Files modified:** `internal/signer/logstate.go`, `internal/signerdb/log.go`, `internal/signerdb/db.go`, `internal/doctor/doctor.go`, `docs/runbooks/signer-install.md`, plus tests in `internal/signer/log_test.go`, `internal/signerdb/db_test.go`, `cmd/keyroster-signer/doctor_test.go`
**Applied fix:** `rebuildLogFrom` now calls `checkLogCovers`. Every caller gets it: serve start-up, the reload after a failed transaction, the ca-init and install-bundle log writers, and doctor's `CheckLog`. The values come from the same snapshot as the leaves (`LogSnapshot.LastSerial`, `Issuances`), and it requires:
- the log is empty exactly when no CA keys are recorded;
- there is one issue leaf per `issuance` row;
- the last issue leaf's serial equals `serial_state.last_serial` (0 when there is no issue leaf).

The bundle-version cross-check the review suggests is `checkBundleLogged`, already run by serve (A-WR-01) and now also by doctor (C-WR-02). These invariants hold on honest databases: `InsertIssuance` and `SetLastSerial` are called only inside the issue transaction, `SaveCAKeys` only with the ca_init leaf, and nothing in `internal/` issues `DELETE`.

The doctor messages for `log_mismatch` and `OK log`, the package doc and the runbook say what is checked and what is not.

**Tests:**
- `TestStartRefusedOnLogMismatch` has 5 new cases: truncated to a signed prefix, truncated to the bootstrap prefix, log wiped, issuance row deleted, high-water mark raised. Every case, old and new, also goes through `CheckLog`.
- `TestDoctorFailures` has 2 new cases: high-water mark raised, log wiped after ca-init.
- All 7 fail before the fix.

**Deferred (design-level, for /gsd-plan-phase 01 --gaps):** these are still undetectable locally:
- the whole `signer.db` restored from an older copy (VM snapshot or backup);
- a cut that also rolls back the issuance rows and the high-water mark;
- a cut of trailing entries that issue nothing (refusal, refusal_summary, clock_regression).

The design must decide on external anchoring:
- how host agents and the CLI witness checkpoints: keep the last checkpoint, require a consistency proof on every sync;
- where operators keep checkpoints, and whether exports must be verified with `--previous`;
- whether serve should refuse to start without a witnessed checkpoint at least as new as the local one;
- whether to publish a tlog-tiles endpoint for C2SP witnesses.

Deleting superseded checkpoints (the review's "consider") was not done. Checkpoints are public in every export, so an attacker with write access can re-insert an old one, and the protection gained is small. The `--previous` warning text belongs to C-IN-05 (out of scope).

### C-WR-06: audit.Verify checks neither profile compliance nor issuance authorization

**Status:** partial: fixed: requires human verification (part 1, profile compliance); remainder skipped: `design-level: deferred to /gsd-plan-phase 01 --gaps` (part 2, authorization)
**Commits:** 074086a, plus follow-up 49f6c9a (guard-branch subtests, gosec nolint in test)
**Files modified:** `internal/cert/builder.go`, `internal/certprofile/certprofile.go` (new), `internal/signer/profiles.go` (removed), `internal/signer/trust.go`, `internal/audit/verify.go`, `cmd/keyroster/audit.go`, `.golangci.yml`, plus tests in `internal/cert/builder_test.go`, `internal/audit/verify_test.go`, `internal/signer/trust_test.go`, `test/e2e/audit_test.go`
**Applied fix:**
- `cert.CheckIssued(c, p)` re-checks a signed certificate with Build's rules, as far as the certificate shows them:
  - certificate type;
  - subject key, and that it is not the CA key;
  - principals;
  - serial != 0;
  - validity at most MaxTTL beyond the 5-minute backdate. An honest certificate spans exactly ValidFor + 300 s, so a naive `<= MaxTTL` would wrongly refuse honest max-TTL certificates;
  - extensions only from the profile's defaults and allowed list, and none on host certificates;
  - critical options only from the allowed list.
- The policy-to-profile mapping moved from `signer.profileFor` to the new package `certprofile.ForRole`, and `audit.Verify` runs it for every issue leaf.
- The first attempt put the mapping in `internal/trust`. `internal/rootceremony/imports_test.go` caught that: KEY-07 forbids the root ceremony reaching `internal/cert`. Hence the separate package, which was also added to the signer-no-network depguard list.
- `dep-firewall.sh` and `capslock-check.sh` are unchanged (73/73 pairs).

**Tests:**
- `TestCheckIssued`: Build output at the cap and for hosts is accepted; 12 out-of-profile edits are refused.
- Four `TestVerifyChecksCertificates` cases. The three violations fail before the fix; the cap case guards the backdate.
- The e2e audit test asserts the new "not checked:" line.

**Deferred (design-level, for /gsd-plan-phase 01 --gaps), part 2, authorization:** an issue leaf records the evidence but only `RequestDigest = SHA-256(SigningBytes)`. The SSHSIG signatures (over SHA-512 of the signing bytes), the admin quorum of the policy in force, and the match between the certificate and the approved request therefore cannot be verified offline. The design must decide:
- whether to log the full request signing bytes (bounded by `wire.MaxFrame`) or selected fields;
- leaf-format versioning, and how logs written before the change are reported;
- the offline SSHSIG check under the policy in force: namespace, sha512, distinct admins >= `AdminQuorum`, no root and no online key;
- binding certificate fields to the request: subject key, principals, validity, extensions, CA role;
- size and privacy of logging full requests.

The limitation is stated now in the `audit.Verify` doc comment and in the human output of `keyroster audit verify`, which gets a second line: `not checked: that each issuance was authorized by the policy's admins ...`. The `--json` output was deliberately left unchanged, so JSON consumers do not see this limitation.

## Skipped Issues

### C-CR-01: an honest log becomes unverifiable if install-bundle runs while serve is running

**File:** `internal/audit/verify.go:140-145`, `internal/signer/signer.go`, `internal/signer/trust.go`
**Reason:** skipped: duplicate of A-CR-01. Fixed in 5227172 (trust_changed refusal plus state-dir flock) and 068ae1e (e2e adaptation). Not touched here.
**Original issue:** serve keeps the old policy after `install-bundle`, so issue leaves stamped `pol=old` after a v2 bundle_install make the log fail `audit verify` forever.

### C-WR-04: custody `pkcs11-agent` is operator-declared, yet doctor reports it as hardware custody

**File:** `internal/doctor/doctor.go:152-154,316-322`
**Reason:** skipped: duplicate of D-WR-03, owned by area D (fixed later). Not touched. Note for D: `custodyResults` was edited by C-WR-03 (new `default` case in the TPM switch), and `hardwareCustody` is unchanged.
**Original issue:** `pkcs11-agent` comes only from the `custody=` backend option, and nothing verifies it.

### C-WR-05: the policy hash chain (`Policy.Prev`, version) is never checked

**File:** `internal/audit/verify.go`, `internal/trust/verify.go`
**Reason:** skipped: duplicate of A-WR-02. Fixed in 2ae8aa1. Not touched here.
**Original issue:** a root-signed successor could carry another policy under a used version number.

## Verification

All commands ran in the main checkout, under WSL (Ubuntu, `$HOME/sdk/go1.27.1`). The repo was reached through `/mnt/c/Users/labon/ssh-cert-manager`.

- Per commit:
  - `gofmt -l` clean;
  - `go build ./...`;
  - `go vet ./...`, plus `go vet -tags e2e ./test/e2e/`;
  - `go test -race -count=1` on the touched packages;
  - each new test was shown to fail before its fix, by stashing the fix file and re-running.
- Final (re-run after the follow-up commits b9cc985, eee8770 and 49f6c9a; HEAD 49f6c9a; all 7 area-C commits are ssh-signed):
  - `go test -race -count=1 ./...`: all ok;
  - `go mod verify` ok;
  - `CGO_ENABLED=1 go vet -tags piv ./...` ok;
  - `GOOS=windows|freebsd|darwin go build ./...` ok;
  - `bash scripts/dep-firewall.sh`: exit 0, only the documented libc exception;
  - `bash scripts/capslock-check.sh`: 73 pairs, baseline 73;
  - full e2e: `KEYROSTER_OPENSSH_PREFIX=~/.cache/keyroster/openssh-10.5p1 go test -tags e2e -count=1 ./test/e2e/` ok, including TestDoctorReportsTestCustody, TestDoctorFailsWhenServeWouldRefuseTheBundle, TestAuditVerifiesIssuance, TestAuditDetectsTampering, TestTrustFlowEndToEnd and TestMachineCAIsSeparate;
  - Windows native: `go vet ./...` plus `go test` of signerdb, cert, audit, doctor, trust and signer, all ok.

## UNVERIFIED

- `-tags e2e_tpm` (TestTPMDoctor, TPM e2e) and `-tags e2e_pkcs11` did not run: there is no swtpm or SoftHSM2 in this WSL. By reading, TestTPMDoctor's assertions (`OK tpm` line, no `tpm_unavailable`, no FAIL) are compatible with the changes: with the TPM backend, `TPMCustody` is set, so the new default case is not reached, and the stored bundle passes `CheckTrust`. Not run, though.
- golangci-lint v2.14.0 (the CI version, installed into the WSL user's `~/go/bin`; the repo is unchanged) ran on `./...`. My changes are clean. **4 findings remain, all from earlier area-A commits, and they will fail the CI lint job:**
  - `internal/signerdb/db_test.go:378,381,423`: G115 `byte(idx)` (from 1b3eff9, A-WR-06; I extended that test but did not write those lines);
  - `internal/signer/overload_test.go:73`: errorlint `err != io.EOF` (from 97efc26, A-WR-07).

  I did not touch them: they are out of area C's scope. With `--build-tags e2e`, the e2e harness has 8 gosec findings and 1 unused finding, all pre-existing. None are in `doctor_test.go` or `audit_test.go`.
- Some new branches are defensive and unreachable, so no test reaches them:
  - `audit` `policy v%d: <certprofile error>`: `trust.Policy.Validate` requires exactly one valid profile per role, in order, and every policy in an export goes through `VerifyGenesisBundle` or `VerifySuccessor`;
  - `certprofile.ForRole` itself has no tests of its own: it is code moved from `signer.profileFor`, covered as before through `TestProfiles` and `profile_for_unknown_role`, and now also by the audit tests.
- `signer_test.go:603` (TestSignerClockBehindHighWaterMark) and `refusal_test.go:257` (TestRefusalClockRegressionEpisodes) still set `last_serial` directly, with no issue leaf. They pass because neither reopens the database, but they leave a database the signer would now refuse at restart (`log_mismatch`).
- The `TestDoctorFailures` case "serial high-water an hour ahead of the clock" now emits both `FAIL clock_regression` and `FAIL log_mismatch`, since the edit leaves no issue leaf. The test still passes (it requires the clock line). An honest clock regression (VM snapshot) keeps the tables consistent and gives only `clock_regression`. Tested by reading only: no test reaches a real clock regression through doctor with a consistent database.

---

_Fixed: 2026-10-07T05:12:15Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_

---


# Phase 01, Area D: Code Review Fix Report

**Source review:** `.planning/phases/01-trust-core/01-REVIEW.md` (Area D and C-WR-04)
**Branch:** `p01/17-review-fixes`, main checkout. No worktree, no push.
**Iteration:** 1

**Summary:**
- Findings in scope: 8 (D-CR-01, D-CR-02, D-WR-01 to D-WR-06), plus C-WR-04, which is covered by D-WR-03.
- Fixed: 6 (D-CR-01, D-CR-02, D-WR-01, D-WR-03 with C-WR-04, D-WR-05, D-WR-06).
- Skipped: 2 (D-WR-02, D-WR-04), both `design-level: deferred to /gsd-plan-phase 01 --gaps`. Bounded fixes for both are committed anyway: D-WR-02 got its code fix, D-WR-04 got documentation only.
- Info findings (D-IN-*) are out of scope and were not touched. D-IN-05 (the TPM key has both decrypt and sign, and no pinned scheme) is still open, even though D-WR-01 now owns the template.

Every fix has a test that failed before the change and passes after it. I captured the failing runs where I could. The exception is new API surface (`deriveCustody`, `Describe`, `syncDir`), where the "before" was a stub or a compile failure.

All gates ran in WSL (Ubuntu, Go 1.27.1) on the main checkout `/mnt/c/Users/labon/ssh-cert-manager`. The swtpm 0.7.3/libtpms and SoftHSM2/opensc packages were extracted without root under `~/.cache/keyroster/pkgs`, and OpenSSH 10.5p1 came from `~/.cache/keyroster/openssh-10.5p1`.

## Fixed Issues

### D-CR-01: A wrong PIV PIN blocks the card's PIN within seconds under the shipped systemd unit

**Status:** fixed: requires human verification (the real-card part is UNVERIFIED)
**Commits:** 806d410, b7d7eae (runbook wording), and f111f09 (adds the TPM path to the same exit status)
**Files:** `internal/keystore/keystore.go`, `internal/keystore/piv/{card.go,piv.go,yubikey.go,piv_test.go}`, `cmd/keyroster-signer/{commands.go,restart_test.go}`, `deploy/systemd/keyroster-signer.service`, `docs/backends/piv.md`, `docs/runbooks/signer-install.md`, `docs/security/needs-hardware.md`

**Applied fix:**
- New sentinel `keystore.ErrCredentialRefused`.
- PIV `newBackend` reads the card's retry counter (`card.PINRetries`, piv-go `Retries()`) before it sends the PIN:
  - fewer than 2 retries left: it refuses without trying;
  - unreadable counter: it fails closed;
  - every failed VERIFY: it wraps the sentinel.
- `dispatch` maps the sentinel to exit status 78 (`exitCredentialRefused`, EX_CONFIG).
- Unit changes:
  - `[Service]`: `RestartSec=5s` and `RestartPreventExitStatus=78`;
  - `[Unit]`: `StartLimitIntervalSec=10min` and `StartLimitBurst=5`.

**Verified here:**
- `TestPIVPINRetriesGuard`: the fake card now models the counter (it decrements, resets, blocks, and logs out on Close). Ten starts with a wrong PIN leave 1 retry. Before the fix the counter reached 0.
- `TestCredentialRefusedExitStatus` and `TestUnitRestartPolicy`: the second test parses the shipped unit and requires `RestartPreventExitStatus` to equal the Go constant.
- `systemd-analyze verify` of the unit: OK.
- A transient `systemd-run --user` service with the unit's own values gave NRestarts=0 for exit 78 and kept restarting on exit 1.

**UNVERIFIED (real card):** whether piv-go `Retries()` reads the counter of a real YubiKey in a fresh session, and whether one wrong PIN lowers it by exactly one. Both are labelled in `yubikey.go` and piv.md, and added to needs-hardware item 2.

### D-CR-02: The TPM backend accepts keys that were not generated inside the TPM

**Status:** fixed
**Commit:** a685d0c
**Files:** `internal/keystore/tpm/{tpm.go,tpm_test.go}`, `docs/security/custody.md`

**Applied fix:** `Key()` decodes the public area and calls `checkGeneratedInTPM`, which requires `fixedTPM`, `fixedParent` and `sensitiveDataOrigin`.

**Verified here (swtpm):** `TestImportedKeyRefused`:
- imports a software P-256 key with `keyfile.NewImportablekey` and `ImportTPMKey`;
- shows that the imported key loads and signs in the TPM, and that the signature verifies with the software public key;
- installs the key as `user.tpmkey`;
- asserts that `Key()` refuses it. Before the fix, `Key()` accepted it as custody vtpm.

`TestCheckGeneratedInTPM` covers each attribute on its own. The e2e_tpm lane passes.

**UNVERIFIED:** the same behaviour on a physical TPM (needs-hardware item 4).

### D-WR-01: TPM CA keys are DA-protected and a bad auth only fails at signing time

**Status:** fixed
**Commit:** f111f09
**Files:** `internal/keystore/tpm/{provision.go,tpm.go,tpm_test.go}`, `test/e2e/tpm_test.go`, `internal/keystore/keystore.go`, the unit comment, `docs/runbooks/signer-install.md`, `docs/security/{custody.md,needs-hardware.md}`

**Applied fix:**
- `Provision` uses its own template: the go-tpm-keyfiles P-256 template plus `NoDA`. It goes through the exported `GetParentHandle`, salted session and `NewTPMKey`, the same parent the library uses.
- `Key()` makes one probe signature over a fixed digest and verifies it.
- `TPM_RC_BAD_AUTH`, `TPM_RC_AUTH_FAIL` and `TPM_RC_LOCKOUT` wrap `ErrCredentialRefused`, so serve exits 78.
- doctor never calls `Key()`; it only calls `tpm.Inspect`, so the probe costs nothing per doctor run.

**Verified here (swtpm):** `TestProvisionNoDA`:
- keys from the new template have NoDA set;
- a wrong auth gives BAD_AUTH and leaves `TPM_PT_LOCKOUT_COUNTER` unchanged;
- the control, a key from the library's default template, gives AUTH_FAIL and raises the counter by 1.

Before the fix, `TestKeyRefusals` showed that `Key()` accepted a wrong auth. e2e `TestTPMWrongAuthNotRestartable` runs `serve` with a corrupt `user.auth`: exit 78, no socket.

**Limits:**
- Keys created before this change (for example on the homelab signer) keep DA protection. For them, the probe plus exit 78 limit the damage to one failure per manual start. This is documented.
- **UNVERIFIED** on a physical TPM (needs-hardware item 4).

### D-WR-03: Agent custody `pkcs11-agent` is an unverified operator assertion (also resolves C-WR-04)

**Status:** fixed
**Commit:** d23d88a
**Files:** `internal/doctor/{doctor.go,doctor_test.go}`, `internal/keystore/agent/{agent.go,agent_test.go}`, `test/e2e/pkcs11_test.go`, `docs/backends/pkcs11.md`, `docs/security/{custody.md,needs-hardware.md}`, `docs/runbooks/signer-install.md`

**Applied fix:**
- `pkcs11-agent` is removed from `hardwareCustody`.
- doctor prints `INFO pkcs11_custody_declared` (new code `CodePKCS11CustodyDeclared`) and never the `OK custody` line for it, whether it stands alone or is mixed with verified custody.
- The agent backend gains `Describe`, so ca-init prints "custody pkcs11-agent declared by the operator, not verified".
- The custody value is not renamed, because it is in signed bundles and logs.
- No comment-matching "verification" was added: whoever loads the key sets its comment, so such a check would look like verification without being one.

**Tests:**
- `TestPKCS11CustodyDeclared`. Before the fix, doctor printed `OK custody ... pkcs11-agent`.
- The agent `Describe` cases.
- The PKCS#11 e2e flow now runs doctor and expects the INFO line. It passes for p256 and ed25519.
- `TestTPMNotInspected` and `TestTPMDoctor` (area C) still pass.

### C-WR-04: custody `pkcs11-agent` is operator-declared, yet doctor reports it as hardware custody

**Status:** fixed (covered by D-WR-03)
**Commit:** d23d88a

doctor's `hardwareCustody` no longer contains `pkcs11-agent`. doctor prints `INFO pkcs11_custody_declared` and never the OK custody line for these keys. See D-WR-03.

### D-WR-05: TPM key-file creation never fsyncs the directory

**Status:** fixed
**Commit:** 3917118
**Files:** `internal/keystore/tpm/{provision.go,tpm_test.go}`

**Applied fix:**
- After all files are written, `Provision` fsyncs `{state-dir}/tpm`, and also the state directory when this run created `tpm`.
- If a sync fails, it removes the written files and returns the error.
- `syncDir` is an injectable package var.

**Test:** `TestProvisionSyncsDirectories` (swtpm) records which directories were synced. Before the fix there were none. It covers both the created-dir and existing-dir cases, and the failure path.

**Not tested:** that the fsync makes the entries survive a real power loss. That is the filesystem's guarantee.

### D-WR-06: The agent backend never reconnects; a hung agent blocks signing

**Status:** fixed
**Commit:** e88a5fe
**Files:** `internal/keystore/agent/{agent.go,export_test.go,reconnect_test.go}`, `docs/backends/pkcs11.md`

**Applied fix:**
- Every agent request (List, Sign) runs under `b.mu` with a 30 s connection deadline (`requestTimeout`; tests shorten it).
- Any failure discards the connection, so a late reply can never answer a later request.
- After a failure the request is retried once on a new connection.
- `caKey` signs by its public-key blob through the backend, so certificate entries are still never chosen.

**Tests (all failed before):**
- `TestAgentRestart` and `TestAgentDown`: the agent restarts on the same socket, and a key opened before the restart signs again.
- `TestAgentHang`: an agent that never answers gives an error after about two timeouts, then signing recovers.
- The default e2e lane and the PKCS#11 e2e lane pass.

**Not exercised:** a real `keyroster-signer-agent.service` restart under systemd with `ssh-pkcs11-helper`.

## Skipped Issues (design-level, with bounded fixes committed)

### D-WR-02: TPM custody decided fail-open from a self-reported manufacturer ID, including over swtpm-socket

**Status:** skipped: design-level: deferred to /gsd-plan-phase 01 --gaps
**Bounded-fix commit:** bbc1f03
**Files:** `internal/keystore/tpm/{vendor.go,vendor_test.go,tpm.go,inspect.go}`, `docs/security/custody.md`

**Applied fix:**
- `CustodyForManufacturer` is now an allowlist: INTC, AMD, IFX, NTC and STM map to `tpm`. Every other ID, including IBM/MSFT/GOOG and unknown IDs, maps to `vtpm`.
- `deriveCustody`, which both `open` and `Inspect` use, forces `vtpm` whenever `swtpm-socket` is set, and for `custody=vtpm`.
- `custody=tpm` is still refused unless the custody already is `tpm`. The refusal message keeps the `custody tpm refused` text that `TestOpenOptions` checks.
- custody.md has an upgrade note: a signer recorded as `tpm` on a manufacturer not on the allowlist now hits a custody mismatch.

**Tests:** `TestCustodyForManufacturer` (unknown IDs give vtpm) and `TestDeriveCustody` both failed before the fix.

**Deferred** (`design-level: deferred to /gsd-plan-phase 01 --gaps`): authenticate the TPM through its EK certificate chain to the manufacturer CA. Decisions needed:
- which vendor roots to embed;
- how to handle fTPMs without an EK cert in NV;
- whether a failed check refuses the TPM or only lowers custody to vtpm;
- where the EK evidence is recorded (bundle or `ca_init` entry).

Until then the manufacturer ID stays self-reported. custody.md says so.

### D-WR-04: PIV custody and key origin are card self-report; reader selected by name substring

**Status:** skipped: design-level: deferred to /gsd-plan-phase 01 --gaps
**Bounded-fix commit:** 22d1465 (documentation and package doc only)
**Files:** `internal/keystore/piv/piv.go` (package doc), `docs/backends/piv.md`, `docs/security/{custody.md,needs-hardware.md}`

**Applied fix:**
- The docs now say that custody `piv` is card-reported, not attested.
- The bundle signer is told to check the slot keys with `ykman piv keys info` and `ykman piv keys attest`.
- needs-hardware item 2 now collects the attestation evidence the code fix needs.

**Deferred** (`design-level: deferred to /gsd-plan-phase 01 --gaps`): slot attestation through piv-go `Attest` and `Verify` (or `Verifier{Roots}`). Decisions needed:
- which Yubico roots and intermediates to trust (newer firmware uses another hierarchy);
- whether Ed25519 slots on firmware 5.7 attest;
- whether a failed attestation refuses the key or only lowers its custody;
- how to test it without a card (fake roots through `Verifier.Roots`).

**Not done:** narrowing the reader-name match. It cannot be tested here, and a spoofed reader can use any name, so it adds no security.

## UNVERIFIED (labelled in code and docs, and on needs-hardware)

- **PIV, real YubiKey** (needs-hardware item 2):
  - piv-go `Retries()` in a fresh session;
  - one wrong PIN decrements the counter by exactly one;
  - the guard under the shipped unit;
  - which ykman command resets the counter;
  - attestation evidence for the D-WR-04 design.
- **Physical TPM** (new needs-hardware item 4):
  - noDA is honoured and the lockout counter does not move;
  - exit 78 on a wrong auth;
  - an imported key is refused;
  - the `/dev/tpmrm0` transport.
- **TPM custody:** the manufacturer ID is self-reported. EK verification is deferred.
- **PKCS#11 custody:** declared only. doctor says so.
- **Agent reconnect:** not exercised with a real `keyroster-signer-agent.service` restart and `ssh-pkcs11-helper` under systemd.
- **D-WR-05:** that the fsync survives a real power loss.

## Notes for area E (CI, scripts, deploy units)

- **Probably blocks the PR:** `golangci-lint run ./...` (what ci.yml's `lint` job runs, with no path filter) reports 4 issues in files from earlier area A/C commits on this branch. Area D did not touch them:
  - `internal/signer/overload_test.go:73` (errorlint `err != io.EOF`);
  - `internal/signerdb/db_test.go:378,381,423` (gosec G115).
- `deploy/systemd/keyroster-signer.service` changed:
  - `[Unit]`: `StartLimitIntervalSec=10min`, `StartLimitBurst=5`;
  - `[Service]`: `RestartSec=5s`, `RestartPreventExitStatus=78`.

  `cmd/keyroster-signer/restart_test.go` ties the 78 to the Go constant. `test/systemd/smoke.sh` (the systemd-sandbox job) installs this unit. It could also assert, in a real sandbox, that a credential refusal (exit 78) is not restarted, for example with a TPM or fake backend that refuses. Not done here.
- `keyroster-signer-agent.service` still has `Restart=on-failure` without `RestartSec=` or `StartLimit*`. The signer now reconnects after an agent restart (D-WR-06), so a restart-delay policy there is the remaining gap.
- New e2e coverage, with no workflow changes needed:
  - `TestTPMWrongAuthNotRestartable` in the e2e_tpm lane;
  - the PKCS#11 flow now runs `doctor` and expects `INFO pkcs11_custody_declared`;
  - new swtpm unit tests in `internal/keystore/tpm`: `TestImportedKeyRefused`, `TestProvisionNoDA` and `TestProvisionSyncsDirectories`. They run in the e2e-tpm job's `-race` unit step.
- Pre-existing lint findings under `--build-tags e2e_tpm` / `e2e_pkcs11` in `test/e2e/` (gosec in the harness, unused helpers). None are on lines changed here.
- Observation, outside area D: doctor's roots check still counts a root declared `custody=pkcs11` in `roots.pub` as hardware. That is the same "declared, not verified" pattern as C-WR-04, for roots.

## Verification (all run in WSL against the main checkout)

- `gofmt -l cmd internal test`: clean.
- `CGO_ENABLED=0 go build ./...` passes, and so do the cross builds for GOOS windows, darwin and freebsd (amd64).
- `go vet ./...`: OK.
- `KEYROSTER_TPM_REQUIRE=1 go test -race -count=1 ./...`: all packages ok, and the TPM tests ran on swtpm.
- With `-tags piv` (`CGO_ENABLED=1`): vet, `go test -race` on `./internal/keystore/piv/...` and `./cmd/keyroster-signer/...`, and `go build` of keyroster-signer all pass.
- golangci-lint v2.14.0, with and without `--build-tags piv`, on every package I touched: 0 issues.
- golangci-lint on `./...` reports 4 issues, all in files from earlier commits that I did not touch:
  - `internal/signer/overload_test.go:73` (errorlint);
  - `internal/signerdb/db_test.go:378,381,423` (gosec G115).
- golangci-lint with `--build-tags e2e_tpm` and with `--build-tags e2e_pkcs11` on `./test/e2e/` reports only pre-existing issues; none are on lines changed here.
- All nine area-D commits are SSH-signed: each has a `gpgsig` header. `%G?` shows N only because `gpg.ssh.allowedSignersFile` is not configured locally.
- e2e lanes:
  - `-tags e2e` with OpenSSH 10.5p1: ok;
  - `e2e_tpm` (swtpm via `scripts/swtpm-setup.sh`): ok, including the new `TestTPMWrongAuthNotRestartable`;
  - `e2e_pkcs11` (SoftHSM2, p256 and ed25519, ssh-agent 10.5p1): ok, including the new doctor assertion.
- systemd: `systemd-analyze verify` of the unit (ExecStart pointed at `/bin/true`): OK. Transient user unit: exit 78 gives NRestarts=0; exit 1 restarts. The script's own exit status is nonzero only because its final `systemctl --user reset-failed` fails; the measured values are as expected.

---

_Fixer: Claude (gsd-code-fixer), Area D, iteration 1_

---


# Phase 01 (Area E): Code Review Fix Report

**Fixed at:** 2026-10-07
**Source review:** .planning/phases/01-trust-core/01-REVIEW.md (Area E)
**Iteration:** 1
**Branch:** p01/17-review-fixes (main checkout, no worktree; not pushed)

**Summary:**
- Findings in scope: 5 (E-WR-01..05; E-IN-* out of scope)
- Fixed: 5. Four have parts that were never exercised locally (CI-only):
  - E-WR-01: entirely CI-only. The re-run on `edited` has not run anywhere.
  - E-WR-03: the force-push path.
  - E-WR-04: CodeQL extraction of the piv files.
  - E-WR-05: the `/proc` checks on the running agent and the agent's online exposure value.
- Skipped: 0
- Plus the lint housekeeping commit and one extra smoke-test commit for the D-CR-01 restart policy

## Fixed Issues

### Lint housekeeping (4 golangci-lint issues from earlier review-fix commits)

**Files modified:** `internal/signer/overload_test.go`, `internal/signerdb/db_test.go`
**Commit:** 562abfa `test(01): fix lint findings from review-fix commits`
**Applied fix:**
- errorlint: changed `err != io.EOF` to `!errors.Is(err, io.EOF)`.
- gosec G115 (x3): `appendOne` now takes the leaf index as a `byte` and widens it to `uint64` for the log index. The loop runs over `range byte(3)`, and the read check compares `uint64(leaf[0]) != idx`. No narrowing conversion is left, so no nolint was needed.

**Verified (WSL, golangci-lint v2.14.0):**
- Baseline before the fix: 4 issues, both default and `--build-tags piv`.
- After: 0 issues in both runs. The piv run used CGO_ENABLED=1 with the real pcsc-lite headers (see Verification).
- Both tests pass under `-race`.

### E-WR-01: Required `pr-title` check never re-ran on a title edit

**Files modified:** `.github/workflows/pr-title.yml` (new), `.github/workflows/ci.yml`, `CONTRIBUTING.md`
**Commit:** e796861
**Applied fix:**
- Moved the job, unchanged, into its own workflow with `pull_request: types: [opened, edited, synchronize, reopened]`, `permissions: {}` and job-level `contents: read`. The title still reaches the script only through `env: PR_TITLE`.
- Removed the job from ci.yml, so only one `pr-title` check run reports. A header comment points to the new file.
- The check context stays `pr-title` with integration 15368, so **the ruleset is unchanged and no admin action is needed**.
- CONTRIBUTING: the table row now names `pr-title.yml`. The re-run claim describes the `edited` trigger and is marked **UNVERIFIED** until it has been seen on a PR.

**CI-only, not exercised locally.** actionlint 1.7.12 and check-pinned-actions pass. To verify: on this branch's PR, edit the title and watch `pr-title` run again. Then drop the UNVERIFIED sentence.

### E-WR-02: merge-gate.sh ran the token-separation wrapper from the working tree

**Files modified:** `scripts/merge-gate.sh`, `scripts/gh-as-bot.sh` (comment only), `CONTRIBUTING.md`
**Commit:** 6f61025
**Applied fix:**
- Added a top-level `bot_gh()` with the same `env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR=...` command. bash parses it before `main` runs, so a branch switch cannot replace it.
- All 7 `scripts/gh-as-bot.sh` calls now use `bot_gh`.
- At start, `main` checks that `bot_gh api user --jq .login` is `keyroster-bot`. If not, it exits 1. It also exits 1, not gh's own exit code, when gh cannot answer. Without that, gh's exit 4 would have looked like the script's "rebase conflict" code.
- gh-as-bot.sh is kept for interactive use. Both copies carry a "keep the unset list in sync" note.

**Verified locally:**
- `bot_gh api user` with `GH_TOKEN=bogus GITHUB_TOKEN=bogus` answers `keyroster-bot`.
- Empty config dir: "cannot ask GitHub who gh runs as", exit 1.
- A stub `gh` that answers `Labontese`: "gh runs as 'Labontese', not keyroster-bot", exit 1. The stub also showed that both tokens arrive unset.
- `merge-gate.sh --check zz-no-such-branch-e-wr-02` against a branch with no PR: identity check passes, then "no pull requests found", exit 1.
- bash -n and shellcheck 0.11.0 are clean.
- merge-gate was never run against a real PR.

### E-WR-03: merge-gate.sh's push identity depended on local credential config

**Files modified:** `scripts/merge-gate.sh`, `CONTRIBUTING.md`
**Commit:** 06b90da
**Applied fix:**
- Added `bot_git()`. It runs `git -c credential.https://github.com.helper= -c "credential.https://github.com.helper=!env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR='<dir>' gh auth git-credential" ...`.
- The config dir is single-quoted, and a dir containing `'` is refused.
- Both `git fetch` calls and the `git push --force-with-lease` go through it.

**Verified locally:**
- Before the fix, the premise held. With `GITHUB_TOKEN=bogus`, the repo-local helper returned `username=x-access-token` and the bogus env token as the password.
- `bot_git credential fill` with both tokens set to bogus returned `username=keyroster-bot`. The password was not the bogus token, and no password was printed.
- `GIT_TRACE` shows bot_git's helper is the only one that runs. The system `manager` helper, the global owner `gh auth git-credential` helper and the repo-local helper are all cleared.
- `bot_git ls-remote origin` works.

**The force-push itself is exercised only on the next real rebase through the gate (not exercised locally).**

### E-WR-04: govulncheck and CodeQL never analysed the `-tags piv` build

**Files modified:** `.github/workflows/piv.yml`, `.github/workflows/codeql.yml`, `CONTRIBUTING.md`
**Commit:** c6b7b7e
**Applied fix:**
- piv.yml: new step `CGO_ENABLED=1 go tool -modfile=tools/go.mod govulncheck -tags piv ./...`, placed after the pcsc-lite install. Also a nightly `schedule`, like ci.yml, so a new piv-go advisory fails `build-piv` without waiting for a code change.
- codeql.yml, go matrix only:
  - installs `libpcsclite-dev` before `codeql init`, so apt is not traced;
  - adds `Build (piv)`: `CGO_ENABLED=1 go build -tags piv ./...` after the static build.
- No new actions, so no new pins. Permissions are unchanged.
- CONTRIBUTING rows updated for `govulncheck`, `build-piv` and `Analyze (go)`.

**Verified locally (WSL, Ubuntu 24.04):**
- Both commands run as written. pcsc-lite came from the Ubuntu archive (`apt-get download libpcsclite-dev libpcsclite1`, extracted without root). Builds used a fresh GOCACHE and a pkg-config shim.
- `govulncheck -tags piv ./...` exits 0 with no reachable vulnerabilities. That run does load piv-go: without the headers it failed on `PCSC/winscard.h`.
- `go build -tags piv ./...` succeeds and adds `internal/keystore/piv` and `backends_piv.go` to the build.

**CI-only / UNVERIFIED:** whether the CodeQL Go extractor picks up the piv files from the second traced build. CONTRIBUTING marks this UNVERIFIED. To confirm, check the extraction diagnostics or the extracted file list of `Analyze (go)` in the PR run.

### E-WR-05: The signer's ssh-agent unit had no sandbox gate

**Files modified:** `test/systemd/smoke.sh`, `.github/workflows/systemd.yml`, `docs/runbooks/signer-install.md`
**Commit:** a490a18
**Applied fix:**
- `systemd-analyze security --threshold=$AGENT_THRESHOLD` on keyroster-signer-agent.service. `KEYROSTER_AGENT_SECURITY_THRESHOLD`, default 14 (1.4), is passed through systemd.yml.
- `systemctl show` assertions on the agent:
  - NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, MemoryDenyWriteExecute, User, UMask and LimitCORE;
  - RestrictAddressFamilies, IPAddressAllow and IPAddressDeny, compared as sorted word sets.
- `/proc/$agent_pid/status` checks of CapEff, CapBnd, NoNewPrivs and Seccomp, plus the process user.
- The runbook and systemd.yml record the measurement.

**Verified locally (WSL, systemd 255.4, same major version as the runner):**
- Offline exposure: agent 1.3, signer 0.7. The signer's 0.7 matches CI's measured value.
- Offline exposure of weakened agent variants:
  - The threshold catches removing SystemCallFilter, ProtectSystem, NoNewPrivileges, CapabilityBoundingSet or ProtectHome, running as root, and adding AF_PACKET.
  - It does not catch removing MemoryDenyWriteExecute or setting `IPAddressAllow=any`. Removing IPAddressDeny reaches only 1.4, which the gate allows. The property assertions cover these three.
- Copies of the units were loaded, never started, into the WSL user manager:
  - The exact `systemctl show` strings were confirmed.
  - smoke.sh's assertion block passes on the real unit.
  - It fails on each of: MDWE removed, IPAddressAllow=any, IPAddressDeny removed, AF_PACKET added, ProtectSystem removed, User removed, NoNewPrivileges removed.

**CI-only / not exercised locally:**
- The `/proc` checks on the running agent. They are the same lines that already pass for the signer.
- The agent's online exposure value, marked UNVERIFIED in the runbook.
- The full smoke.sh run, which is destructive and was not run locally.

**Not fixed, still open:** the second half of the finding title, the agent unit's PKCS#11 `-P` path under systemd. It is still never exercised. That is tracked by E-IN-02 (out of scope), and the runbook already says so.

### Extra: restart policy assertion (asked for as part of E-WR-05 context)

**Files modified:** `test/systemd/smoke.sh`
**Commit:** b7e82be `test(01): assert the signer unit's restart policy in the systemd smoke test`
**Applied fix:** `systemctl show` on keyroster-signer.service must report `Restart=on-failure`, `RestartUSec=5s`, `RestartPreventExitStatus=78`, `StartLimitBurst=5` and `StartLimitIntervalUSec=10min`. A behavioural exit-78 test was not added: it needs a PIV card or a TPM, and overriding ExecStart in a required CI-only gate would be fragile.

**Verified locally (WSL user manager, unit loaded, not started):** passes on the real unit. Fails on each of: RestartPreventExitStatus removed, RestartSec removed, Restart=always, and StartLimit* moved into [Service], which systemd ignores for StartLimitIntervalSec. The run on the CI runner is CI-only.

## Verification summary

All gates ran in the **main checkout** (no worktree). Go commands ran in WSL Ubuntu 24.04 against `/mnt/c/...`.

- `gofmt -l .`: empty. `go vet ./...`: rc 0.
- `CGO_ENABLED=1 go test -race -count=1 ./...`: all packages ok.
- `golangci-lint run ./...`: 0 issues.
- `golangci-lint run --build-tags piv ./...` with CGO_ENABLED=1 and pcsc-lite headers: 0 issues.
- `go vet -tags piv` and `go test -race -tags piv` on `./internal/keystore/piv/... ./cmd/keyroster-signer/...`: ok. These used libpcsclite extracted to /tmp, through LD_LIBRARY_PATH.
- `bash scripts/check-pinned-actions.sh`: all 39 references pinned.
- actionlint 1.7.12 (built in /tmp, run with `-shellcheck=`): rc 0.
- shellcheck 0.11.0 (the VS Code extension binary) on merge-gate.sh, gh-as-bot.sh and smoke.sh: clean.
- `bash -n` on all three scripts: ok.
- All 7 new commits carry SSH signatures from the configured bot key. No `.planning/*` or `.claude/settings.local.json` file was committed.

- Lint with the e2e build tags was not run. No e2e file was touched, so any e2e-tag issues are unchanged.

## First real run: this branch's own PR

This branch's PR is the first time four changed required checks run. A red check there is not a regression in areas A to D.

- **`systemd-sandbox`:**
  - The agent threshold is 1.4. The 1.3 behind it was measured offline only, so the headroom is 0.1.
  - If the job fails only at the agent `--threshold` line, read the per-directive table in the log. If the cause is an offline-versus-online difference and no directive was weakened, set the threshold from the measured value and record that value in systemd.yml.
  - Do not loosen the property or `/proc` assertions.
- **`Analyze (go)`:** the traced `CGO_ENABLED=1 go build -tags piv` has not run under CodeQL anywhere. If it fails, drop only that step and keep the govulncheck half of E-WR-04.
- **`build-piv`:** the new govulncheck step depends on vuln.go.dev. ci.yml's `govulncheck` job already does, so this is an accepted risk.
- **`pr-title`:** edit the PR title to verify E-WR-01, then remove the UNVERIFIED sentence from CONTRIBUTING.

## Admin / owner actions

- **No ruleset or repository-setting change is needed.** The `pr-title` context name and integration are unchanged.
- Recommended, local config only: the repo-local git credential helper unsets `GH_TOKEN` but not `GITHUB_TOKEN`, so ordinary pushes outside merge-gate can still go out as the owner. It is set in `.git/config` per 01-01-PLAN.md:262. Add `-u GITHUB_TOKEN` to it. merge-gate no longer depends on it.

---

_Fixed: 2026-10-07_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
