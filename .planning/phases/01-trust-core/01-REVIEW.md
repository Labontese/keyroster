---
phase: 01-trust-core
reviewed: 2026-10-10
depth: mixed (area G deep, area F standard)
method: incremental re-review since the #19 review; two parallel gsd-code-reviewer areas, merged by the orchestrator; the earlier full review (59 findings, A-E) is in git history at 13d55c4
diff_base: 13d55c4
files_reviewed: 87
findings:
  critical: 1
  warning: 7
  info: 12
  total: 20
status: issues_found
---

# Phase 1 code re-review (after PR #20 and the KEY-07 gap plans)

| Area | Scope | Critical | Warning | Info |
|------|-------|----------|---------|------|
| F | The PR #20 review fixes (`13d55c4..582f932`, 75 files), never independently re-reviewed | 0 | 4 | 8 |
| G | The gap-plan code from 01-17 and 01-18 (`582f932..31f3eb7`, 12 files): `root sign --prev`, `trust verify --prev`, audit anchoring on a later bundle | 1 | 3 | 4 |

## Blocker

**G-CR-01:** `root sign --prev` and `trust verify --prev` never authenticate the `--prev` directory. They check neither its `.sigs` nor a pinned SHA-256. A forged prev from a compromised CA host can therefore carry attacker CA and log keys into a successor that honest new roots sign, and `audit verify --pin <new roots>` then accepts the forged history.

**The homelab rotation in 01-20 is not affected.** Prev was checked to be the real v1 (`2b63fb6d…`) before C and D signed, and `install-bundle` verified against the installed v1. **The flaw must be fixed before the owed v3 ceremony.**

## Warnings

- **G-WR-01:** a root carried over between bundles can change its custody label, for example from `software` to `piv`. That launders a software key into a hardware claim.
- **G-WR-02:** "A stolen old root cannot rotate trust alone" is false at threshold 1, the homelab shape. The comment and the runbook overstate it.
- **G-WR-03:** test gaps:
  - multi-root anchor sets are not tested;
  - a root present in both sets is not tested;
  - a foreign prev is not tested;
  - `new_root_signs_with_key` depends on the order the subtests run in.
- **F-WR-01 (C-WR-06):** `CheckIssued` checks how long the validity window is, but not where it sits. A logged certificate valid in 2030 passes `audit verify`.
- **F-WR-02 (B-CR-01):** root-as-admin is checked only against the current and the previous bundle's roots. A root retired in v2 can be an admin in v3.
- **F-WR-03 (E-WR-02):** after exit 3 or 4, `merge-gate.sh` leaves the checkout on the PR branch, so the next run executes the PR's own copy of the script.
- **F-WR-04 (C-WR-03/D-WR-04):** `doctor` prints "OK custody" for `piv` from database rows alone. It should be INFO, like `pkcs11-agent`.

The area reports follow below, each unchanged apart from its frontmatter.

---


# Phase 01, Area G: Code Review Report

**Reviewed:** 2026-10-10
**Depth:** deep (cross-file: root sign --prev -> BuildSuccessor/checkSuccessorChain -> VerifySuccessor <- trust verify --prev, audit.Verify anchor; runbook docs/runbooks/root-ceremony.md read for context)
**Files Reviewed:** 12
**Status:** issues_found

## Summary

Baseline: `go vet` is clean on the three packages, and `go test ./internal/trust ./internal/audit` and `go test ./cmd/keyroster -run Successor` pass. The e2e test was not run (it needs the build tag and sshd).

The pure verifier logic holds up under the hunt list:
- `checkSuccessorChain` is shared, so the builder and the verifier cannot drift.
- `CountPinnedSigners` dedups by fingerprint and checks the full key bytes.
- `MatchPins` requires the exact set and the exact threshold.
- The audit anchor is fail-closed (`anchorVersion == 0` is refused).
- Bundles before the anchor are content-authenticated by the anchor's `prev` hash and `policy_sha256`. Bundles after it go through `VerifySuccessor`.
- `--out-dir` writes use O_EXCL plus a byte comparison, and signatures are produced before any append. A refusal never leaves a signature behind.

The serious gap is not in the verifier. It is in what the verifier's soundness argument assumes. The new anchor rule says earlier bundles are authenticated because "the pinned roots' signatures over the anchor cover its prev hash". That only means something if the holders of the new roots signed over the real bundle in force. Neither `root sign --prev` nor `trust verify --prev` authenticates the `--prev` directory in any way: no `.sigs`, no pins, no recorded hash. The only control is a manual 64-hex comparison in the runbook.

## Narrative Findings (AI reviewer)

## Critical Issues

### G-CR-01: `--prev` is never authenticated, but the new audit anchor's soundness depends on it (not fail-closed)

**Files:**
- `cmd/keyroster/root.go:532-561` (`successorBuilder`)
- `cmd/keyroster/root.go:272-279`
- `cmd/keyroster/trust.go:98-117` (`verifySuccessorBundle`)
- `internal/audit/verify.go:26-35, 144-163, 234-243` (`Options.Pins` doc, `verifySelfSignedGenesis`, `Verify` doc)

**Issue:**
- `successorBuilder` reads `prevDir/bundle.json` and `prevDir/policy.json` and nothing else. It never reads `bundle.json.sigs` or `policy.json.sigs`, takes no pins for the current root set, and takes no recorded SHA-256.
- `verifySuccessorBundle` does the same. Its `--pin` pins only the new roots (`MatchPins(next, ...)`).
- The "previous roots" whose signatures it counts (`trust.go:129`) come from a file that nothing has authenticated.
- `trust.BuildSuccessor` then copies `CAs`, `OpsKey` and `Log` verbatim from that unauthenticated `prev` into the bundle the new roots sign (`successor.go:31-33`).

Since this diff, `audit.Verify` accepts any self-signed genesis (`verifySelfSignedGenesis`). It relies only on the anchor's `prev` hash to authenticate earlier bundles. So the whole chain of trust under new-root pins reduces to "the new-root holders signed over the genuine bundle in force", and no tool enforces that.

Attack path under the stated threat model (compromised CA server, which supplies the bundle in force that is copied to `/media/transfer/prev`):
1. The attacker places a forged `prev`: a self-signed genesis with root set {Z}, attacker CA, ops and log keys, and a matching policy.
2. `root sign --prev` builds v2 with `Prev = SHA256(forged)` and copies the attacker's CA and log keys. The new root C signs. In the runbook and in the e2e test, C signs first.
3. Z co-signs as the "previous root". `rootByFingerprint` accepts Z from `prev`.
4. `trust verify --prev forged --pin C --pin D --threshold 1` prints `OK: successor of trust bundle v1: previous roots 1 of 1 signed ...`.
5. The compromised server replaces its log with the forged v1 plus the real-signed v2. `audit verify --pin C --pin D` anchors on v2 and accepts the attacker's CA keys and log key for all history.

This is NOT the accepted `fork_under_old_pins` property. That property covers pins on exposed old roots. This attack fools pins on the honest new roots, which the runbook (step 7, lines 367-372) tells auditors to use precisely because they are supposed to refuse forks.

Evidence in-tree:
- `TestRootSignSuccessor`'s `copyPrev` copies no `.sigs`. The `previous_root_custody_mismatch_refused`, `prev_not_canonical_refused` and `prev_policy_mismatch_refused` subtests still reach their specific later refusals, so `root sign --prev` proceeds on an unsigned, edited prev.
- `rotation_new_pins_anchor_v2` in `verify_test.go` shows the audit half: whatever genesis root co-signed v2 is accepted under the C pins.

The only control is human. Runbook lines 279-280 and 310-311 say to compare the `Successor of trust bundle vN, sha256 ...` line with "the recorded SHA-256". With exposed old roots (the homelab TEST-roots case, runbook step 4), checking prev's signatures would not help either: the attacker holds those roots. So the hash comparison is the only thing that protects this case, and it is not enforced.

If the owner explicitly accepts the manual hash comparison as the control, this can be downgraded to WARNING. By the project's "must stay fail-closed" standard it is a BLOCKER.

**Fix:** make the recorded hash mandatory and machine-checked in both commands, and refuse before `prepareBundle` writes anything:

```go
// root sign / trust verify
prevSHA := fset.String("prev-sha256", "", "SHA-256 of the bundle in force, as recorded at its install (required with --prev)")
...
if *prevDir != "" && !isHash(*prevSHA) { usage }
...
// successorBuilder / verifySuccessorBundle, right after reading prevBundle:
if trust.SHA256Hex(prevBundle) != *prevSHA {
    return fmt.Errorf("%s has sha256 %s, not the recorded %s; nothing was written or signed",
        prevPath, trust.SHA256Hex(prevBundle), *prevSHA)
}
```

Defence in depth: also require `prevDir/bundle.json.sigs` and `policy.json.sigs` to meet `prev.Root.Threshold` of prev's own roots (`requireSigners`). Optionally accept `--prev-pin`/`--prev-threshold` and apply `MatchPins(prev, ...)`.

Add a regression test: a foreign, correctly self-signed genesis in `--prev`, with honest new-root pins. Both commands must refuse it.

## Warnings

### G-WR-01: A root carried into the successor can change its custody label (software to hardware) without any check

**Files:**
- `internal/trust/successor.go:22-47`
- `internal/trust/verify.go:287-333` (`checkSuccessorChain`)
- `cmd/keyroster/root.go:584-601` (`rootByFingerprint`)

**Issue:**
- Nothing compares the custody of a key that appears in both `prev.Root.Keys` and the new `roots`.
- `rootByFingerprint` searches the new set first, so the new label wins.

Concretely:
- Root K is declared `custody=software` in the signed bundle in force.
- The operator lists K again in `new-roots.pub` as `custody=piv`. `checkRootCustody` only distinguishes sk-* keys, so this passes.
- The operator then signs with `--agent-key K`. The `--key` guard (`root.go:316`) never fires, and no SOFTWARE ROOT banner is printed (`custody == "piv"`, `root.go:377`).

The successor now launders a key that was exposed in software into a hardware label. D-10/D-11 say a software root "must never pass for hardware custody".

The existing `previous_root_custody_mismatch_refused` test covers a key in prev only, never a key in both sets.

**Fix:** in `checkSuccessorChain` (so the builder and the verifier agree), refuse a root present in both sets whose custody differs, or at minimum one whose custody changes from `software` to anything else:

```go
prevCustody := map[string]string{}
for _, rk := range prev.Root.Keys { prevCustody[rk.Key] = rk.Custody }
for _, rk := range next.Root.Keys {
    if c, ok := prevCustody[rk.Key]; ok && c != rk.Custody {
        return nil, fmt.Errorf("%w: root %s keeps its key but changes custody %s -> %s; a moved key is a new root",
            ErrCustody, rk.Key, c, rk.Custody)
    }
}
```

Add a test with a key in both sets, relabelled from software to piv.

### G-WR-02: "A stolen old root cannot rotate trust alone" is false at threshold 1, which is the documented homelab shape

**Files:**
- `internal/trust/verify.go:223-231` (pre-existing claim, still the doc of the function this diff refactors)
- Restated in `docs/runbooks/root-ceremony.md:266-268` (PR #25)

**Issue:** `VerifySuccessor` counts the previous threshold and the new threshold independently, and a key can satisfy both.
- With `prev.Root.Threshold == 1`, a thief holding one current root A can make a fresh key X and build v2 with roots {X} at threshold 1. Signing with A and X passes both checks.
- The same works for {A, X} at threshold 1 signed by A alone, because A satisfies the new threshold as well.

That is correct TUF semantics: at threshold 1, A already is the authority. But the comment and the runbook tell operators the opposite. The runbook's rotation example is "two current roots at threshold 1".

A root present in both sets also lets a listed new root (X in {A, X}) be added without ever proving possession. That is not an escalation, but the doc's "at least next's own threshold of its roots must have signed" hides it.

**Fix:** correct the doc comment and the runbook. For example: "a rotation needs prev.Root.Threshold current roots; at threshold 1 any single current root can rotate trust; a root in both sets counts toward both thresholds". Consider having `root sign --prev` print a warning when `prev.Root.Threshold == 1`.

### G-WR-03: Test gaps on the exact properties this diff introduced, and one order-dependent test

**Files:**
- `internal/audit/verify_test.go` (`TestVerifyAnchorsOnLaterBundle`)
- `cmd/keyroster/root_test.go:1029-1049`
- `cmd/keyroster/trust_test.go`

**Issue:**
1. Every case in `TestVerifyAnchorsOnLaterBundle` uses single-root sets at threshold 1 (`onlyRoot`, `Threshold: 1` in the Verify call). The exact-threshold half of the audit anchor (pins equal to a later bundle's root set but at the wrong threshold) is only unit-tested in `TestMatchPins`, never through `Verify` across a rotation.
2. These cases are missing:
   - a root set that recurs (v1 {A} -> v2 {C} -> v3 {A}), to pin the "first match" rule;
   - a root shared by both sets (overlap counting);
   - duplicate signatures by one key towards a successor threshold of 2.
3. No test feeds `root sign --prev` or `trust verify --prev` a foreign or unsigned prev while the new-root pins are honest. That missing test is why G-CR-01 went unnoticed.
4. `TestRootSignSuccessor/new_root_signs_with_key` depends on `previous_root_signs_with_key` having already signed the shared `succ` directory. Verified: `go test ./cmd/keyroster -run 'TestRootSignSuccessor/new_root_signs_with_key'` fails with `bundle (previous roots) signed by 0 of 2 roots, need 1`.

**Fix:** add the listed cases. Make `new_root_signs_with_key` self-contained by giving it its own out-dir and signing with A inside it, or fold the two subtests into one.

## Info

### G-IN-01: Refusals after `prepareBundle` leave an unsigned `bundle.json` whose `issued_at` is reused later

**File:** `cmd/keyroster/root.go:295-366`

**Issue:** these refusals all come after `prepareBundle` has written `bundle.json` and `policy.json`:
- unknown signing root (`rootByFingerprint`);
- custody mismatch;
- wrong passphrase;
- wrong `--confirm`;
- agent missing the key.

Their messages say "nothing was signed", which is true, but the out-dir now pins that ceremony's `issued_at`. A corrected rerun silently reuses it, and a rerun with corrected `--roots` is refused as "does not match". No signature is left behind, so this is not a security issue.

**Fix:** resolve the signing root, the custody label and the passphrase before `prepareBundle`. The fingerprint and the label need only the roots file and prev, not the built bundle. Alternatively, say in the refusal text that `bundle.json` was written.

### G-IN-02: The `--out-dir == --prev` check uses `filepath.Abs` only

**File:** `cmd/keyroster/root.go:533-543`

**Issue:** case differences on Windows, symlinks and junctions all bypass the check. That is harmless, because `prepareBundle`'s byte comparison then refuses with the misleading "does not match --prev, --roots, --threshold and --policy" and O_EXCL prevents overwrites.

**Fix:** compare with `os.SameFile` on the two `Stat` results (after `MkdirAll` is not needed: stat `prevDir`, and stat `outDir` if it exists).

### G-IN-03: `trust.go` hardcodes the document file names

**File:** `cmd/keyroster/trust.go:99, 103, 109`

**Issue:** it uses `"bundle.json"`/`"policy.json"` literals while `root.go` (same package) defines `bundleFile`/`policyFile`.

**Fix:** use the constants.

### G-IN-04: Redundant checks and a lossy anchor-mismatch error

**Files:** `internal/audit/verify.go:268-273, 131-139, 375-377`; `cmd/keyroster/audit.go:69`

**Issue:**
- The `len(opts.Pins) == 0` check is subsumed by `trust.CheckPins` on the next line.
- `lastMismatch` keeps only the last bundle's mismatch, so a multi-rotation log refused for "no anchor" reports only the final bundle's reason (for example `trust bundle v3: 2 pins, 1 roots`), even if an earlier bundle was the near-miss.

**Fix:** drop the redundant check. Optionally collect the per-version mismatches, or say "last bundle checked" in the message.

---

_Reviewed: 2026-10-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_

---


# Phase 01, Area F: re-review of the code-review fixes (PR #20)

**Reviewed:** 2026-10-10
**Depth:** standard. Every fix in the diff was read in full, the call chains named in the brief were traced, and the dependency source was checked where a claim rested on it (modernc `_txlock` and ReadOnly, go-tpm-keyfiles error wrapping).
**Range:** `git diff 13d55c4..582f932`, one squash commit. Lines are cited at HEAD 31f3eb7, where they are unchanged from 582f932 unless a finding says otherwise. The gap-plan changes after 582f932 are out of scope. Test files were read only for reliability, as unit tests (diffs only for most `*_test.go`).
**Status:** issues_found (0 critical, 4 warning, 8 info)

## Summary

No fix introduces a blocker. The fixes the brief singled out mostly do what 01-REVIEW-FIX.md says. Four of them close their finding only partly, or contradict their own premise:

- **C-WR-06:** `cert.CheckIssued` checks only the length of the validity span, never where it sits. A logged certificate valid in 2030 passes as "within profile" (F-WR-01).
- **B-CR-01:** "no root as policy admin" is enforced against only one generation of retired roots (F-WR-02).
- **E-WR-02:** the in-file `bot_gh` copy does not help when the script itself is the PR's copy. The script's own exit-3 and exit-4 paths leave the checkout on the PR branch and ask the operator to rerun from there (F-WR-03).
- **C-WR-03 / D-WR-04:** doctor now refuses an OK for TPM custody it did not inspect, and for declared pkcs11-agent custody. It still prints OK hardware custody for `piv`, which it never inspects and which D-WR-04 documents as card-reported only (F-WR-04).

### Per-fix verdict

| Fix | Verdict |
|---|---|
| A-CR-01 flock + `trust_changed` | Closes the finding. `serve`, `ca-init` and `install-bundle` share `{state-dir}/signer.lock`, taken before the DB or backend is opened. The lock is per open file description, so the in-process test is valid, and the `*os.File` stays reachable through the closure, so no finalizer drops the lock. The in-tx check is the first statement inside `BEGIN IMMEDIATE` (`_txlock=immediate` confirmed in the DSN and in modernc `tx.go:23`), so it holds until COMMIT. A refusal returned from the tx appends nothing, so no reload. If a lock-bypassing writer advanced the log, the stale in-memory tree makes the next refusal append fail on the `AppendLeaf` index check. `logTx` then reloads and recovers. No new bug found. |
| A-WR-01 stored-bundle-vs-log | Closes the finding. Byte comparison of all four documents and the version; nil cases handled; run in `New`, `InstallBundle` and `CheckTrust`. |
| A-WR-04 replay pre-check | Closes the finding. Placed before `LastSerial`/`serial.Next`/`cert.Build` and serialized by `s.mu`; the UNIQUE constraint is still the backstop. |
| A-WR-06 snapshot read | Closes the finding. Confirmed in the modernc source: a ReadOnly `BeginTx` is a plain deferred `BEGIN`, never `BEGIN IMMEDIATE`. Every read after the first SELECT is in one WAL snapshot. No reentrancy into the single-connection pool from the callbacks. |
| A-WR-07 over-capacity | Closes the finding. The atomic counter is moved into the limiter under `s.mu`. The final flush runs after the accept loop has exited, so nothing is lost. If the append fails, the counts stay in `l.counts`. |
| B-CR-01 root-as-admin | Partial: see F-WR-02. |
| B-WR-03 atomic `.sigs` | Closes the finding: every signature is made before any write, each document is skipped once this root has signed it, and the write is temp-file + fsync + rename. One side effect, see F-IN-08. |
| C-WR-01 `checkLogCovers` | Closes the bounded part. The invariants hold on honest databases: `SetLastSerial` and `InsertIssuance` run only in the issue tx, and nothing deletes rows. |
| C-WR-02 `CheckTrust` in doctor | Closes the finding; see F-IN-02 for the multi-snapshot read. |
| C-WR-06 `CheckIssued` + `certprofile` | Partial beyond the documented deferral: see F-WR-01. `certprofile` is a faithful move of `profileFor`. KEY-07: `cmd/keyroster` already reached `internal/cert` through `internal/audit` before the fix, so this adds no new path. |
| D-CR-01 PIV guard + exit 78 | Closes the finding. Traced: `newBackend` → `newWithCard`/`open` → `keystore.Open` → `openBackend` → `openStoredBackend` → `runServe` → `dispatch`. Every hop returns the error unchanged or wraps it with `%w`, so `errors.Is(ErrCredentialRefused)` reaches exit 78. The TPM drop-in `tpm.conf` does not override `Restart*`/`StartLimit*`. Remaining caveat: F-IN-06. |
| D-CR-02 / D-WR-01 TPM attributes, noDA | Closes the finding. `fixedTPM` alone already rules out `TPM2_Import`, and the TPM refuses `fixedTPM` on a child of a non-fixedTPM parent. The attributes are bound to the private blob through the object Name. Sign errors from go-tpm-keyfiles are wrapped with `%w` (`failed to sign: %w`), so the `TPMRC*` `errors.Is` checks work. |
| D-WR-06 agent reconnect | Closes the finding. Key selection stays by public-key blob, and `cert.Build` still verifies the agent's signature against the pinned CA key, so a different process on the socket after a restart cannot forge anything. See F-IN-04 for the bounded side effects. |
| E-WR-01..05 | E-WR-01, -03, -04 and -05 close their findings. E-WR-02 is partial: see F-WR-03. |

## Warnings

### F-WR-01: `cert.CheckIssued` / `audit.Verify` accept a logged certificate whose validity window is anywhere in time (C-WR-06 incomplete)

**File:** `internal/cert/builder.go:198-207`, `internal/audit/verify.go:171-205`
**Issue:** `CheckIssued` checks only `ValidBefore - ValidAfter`, the span, against `MaxTTL + 300 s`. Neither it nor `checkIssue` relates `ValidAfter` to the issuance time: `grep ValidAfter|ValidBefore internal/audit/verify.go` finds nothing.

`cert.Build` can produce only `ValidAfter = issuedAt - 300 s`, and the log carries `issuedAt` twice: in the leaf's `TimeMicros`, and in the serial (`serial.Next` is a µs timestamp). So a certificate with a 12 h span starting in 2030, or one backdated a year, passes `keyroster audit verify` as "within the user profile of policy vN", although the signer's own rules could never produce it.

That is the case the C-WR-06 check exists for: a compromised or buggy signer pre-minting future access that outlives a revocation or a policy change. The fix claims "re-checks a signed certificate with Build's rules, as far as the certificate shows them", but the leaf next to the certificate does show the issuance time.

**Fix:** pass the issuance time to the check, and require `ValidAfter` to equal it minus the backdate, within a small slack. The slack covers the leaf time, which can be raised to the previous leaf's.

```go
// internal/cert: add an issuance-time-aware variant
func CheckIssuedAt(c *ssh.Certificate, p Profile, issued time.Time, slack time.Duration) error {
	if err := CheckIssued(c, p); err != nil {
		return err
	}
	want := issued.Add(-backdate).Unix()
	if d := int64(c.ValidAfter) - want; d < -int64(slack/time.Second) || d > int64(slack/time.Second) { //nolint:gosec
		return fmt.Errorf("%w: valid after %d, but issued at %d (expected %d)", ErrValidity, c.ValidAfter, issued.Unix(), want)
	}
	return nil
}
// internal/audit/verify.go checkIssue: also require c.Serial (µs) <= leaf.TimeMicros and
// CheckIssuedAt(c, profile, time.UnixMicro(int64(leaf.TimeMicros)), 2*time.Second)
```

Add a `TestVerifyChecksCertificates` case with a postdated certificate (span within the cap).

### F-WR-02: "no root as policy admin" holds for only one generation of retired roots (B-CR-01 incomplete)

**File:** `internal/trust/verify.go:327-331` (582f932: 252-256), `internal/audit/verify.go:103,130`, `internal/signer/trust.go:339`
**Issue:** `VerifySuccessor` calls `CheckAdminsNotRoots(p, next.Root.Keys, prev.Root.Keys)`. Its rationale comment is "A root that next retires may still exist, so it must not become an admin either". That rationale applies equally to a root retired two or more rotations ago, but only the immediate predecessor's roots are checked:

- `audit.Verify`'s `anchor` keeps only the bundle in force (`a.bundle`).
- `InstallBundle` passes only `latest`.
- `checkPolicyAdmins` at start checks only the installed bundle's roots.

Example: R is a root in v1 and is retired in v2. At v3, `VerifySuccessor(prev=v2)` checks only v2's and v3's roots, so a v3 policy can list R as an admin. Every consumer accepts it: `InstallBundle`, `serve`, `doctor`'s `CheckTrust` and `audit verify --pin`.

A retired root key (perhaps retired because it was suspected compromised) thereby becomes a routine online issuance authorizer, which is exactly what KEY-07 / B-CR-01 forbid. The fix report documents only the start-up case ("a record from before this fix ..."), not this verifier gap.

**Fix:** carry every root ever pinned or listed:

- **audit:** add `retiredRoots []trust.RootKey` to `anchor` and append `a.bundle.Root.Keys` on every install. Give `VerifySuccessor` a `historicRoots ...[]RootKey` parameter, or call `trust.CheckAdminsNotRoots(p, a.allRoots...)` after it.
- **signer:** in `InstallBundle` and `checkStoredTrust`, collect `Root.Keys` from every `trust_bundle` row (all versions are kept) and pass them.
- **tests:** add a v1→v2→v3 test where v3's admin is a v1-only root.

### F-WR-03: merge-gate still runs the PR's unreviewed copy of itself on its own documented rerun paths (E-WR-02 incomplete)

**File:** `scripts/merge-gate.sh:120-123`, `171-192`; `CONTRIBUTING.md:122-133`
**Issue:** E-WR-02 moved the `gh` wrapper into the script, because after `git switch` to the PR branch, "that file is the PR's unreviewed copy". The same premise defeats the script itself:

- `rebase_onto_main` switches to the PR branch and never switches back.
- Exit 3 ("rebased; owner must approve the new head") and exit 4 ("resolve, run `git rebase --continue`, then rerun this script") both leave the checkout on `$branch`.
- The next invocation, `bash scripts/merge-gate.sh BRANCH`, then executes the PR branch's `merge-gate.sh`. That copy may define its own `bot_gh`/`bot_git` without the token unsets or the identity check.

The same holds whenever the gate is started from the feature branch, which is the normal end-of-PR position. The identity check (`gh api user == keyroster-bot`) is part of the file being replaced, so it gives no protection here. CONTRIBUTING states the guarantee without this precondition.

**Fix:** make the gate refuse to run from anything but reviewed code, and leave the checkout on `main`:

```bash
# at the top of main(), after cd to the toplevel:
self=$(git hash-object "$0")
reviewed=$(git rev-parse origin/main:scripts/merge-gate.sh 2>/dev/null) || reviewed=
if [ "$self" != "$reviewed" ]; then
	echo "run the reviewed gate: git show origin/main:scripts/merge-gate.sh | bash -s -- $*" >&2
	return 1
fi
# in rebase_onto_main, before 'return 0' on the success path:
git switch --quiet main || return 1
```

Change the exit-4 message to: "... `git rebase --continue`, `git switch main`, then rerun". Document in CONTRIBUTING that the gate runs only from `main`, or from `origin/main`'s copy.

### F-WR-04: doctor still prints OK hardware custody for `piv` keys it never inspects (C-WR-03 / D-WR-04 inconsistency)

**File:** `internal/doctor/doctor.go:183`, `352-359`; `cmd/keyroster-signer/doctor.go:169-183`
**Issue:** The same fix set establishes two rules:

- C-WR-03 (the new `default` case): TPM custody that "nobody read" is "a claim only, never an OK".
- D-WR-03: declared custody gets no OK.

D-WR-04 then documents that custody `piv` is "card-reported, not attested". Yet `hardwareCustody` still contains `"piv"`. `readDBFacts` inspects only the TPM backend, so a set of `piv` keys yields `OK custody: every online key has hardware custody` from the `ca_keys` rows alone. Nothing at doctor time looks at the card, and nothing ever attested the slot.

doctor therefore makes exactly the unverified hardware claim that its package doc ("doctor never reports ... as hardware custody") and the C-WR-03 fix rule out. For a tool whose core value is an accurate picture of access, an operator reading doctor's output gets a stronger custody statement than the system can back.

**Fix:** either inspect the card in doctor (`piv` `KeyInfo` origin per slot, compared with the recorded keys; no PIN needed), or report `piv` the way pkcs11-agent is reported:

```go
var hardwareCustody = map[string]bool{"tpm": true}
// custodyResults:
case "piv":
	declared = true
	rs = append(rs, Result{Level: INFO, Code: CodePIVCustodyReported, Message: fmt.Sprintf(
		"keys %s are custody piv as the card reported at ca-init; slot attestation is not checked and doctor did not read the card (docs/backends/piv.md)", roles)})
```

## Info

### F-IN-01: `MaxAdminQuorum` is applied retroactively through `ParsePolicy`, making an installed quorum>4 policy unrecoverable

**File:** `internal/trust/policy.go:87-89`, `internal/trust/verify.go:301`
**Issue:** `VerifySuccessor` now parses `prevPolicy` with `ParsePolicy`, which runs `Validate`, which since A-WR-03 refuses `admin_quorum > 4`. A deployment that installed such a policy before the fix cannot issue (expected). It also cannot install a corrected successor: `previous policy: ... admin_quorum 5 is above 4`. And its log fails `audit verify` forever. The only way out is a new `ca-init` with new CA keys. This matters only for deployments that installed such a policy before the fix.
**Fix:** parse historic documents (`prevPolicy`, installed rows) with a structural-only parse that skips rules added later. Or document the one-time recovery.

### F-IN-02: doctor reads the trust facts from three separate snapshots without the state lock

**File:** `cmd/keyroster-signer/doctor.go:142-167`; `internal/signer/logstate.go:146-170`
**Issue:**

- `CheckLog`, `LatestBundle` and `CheckTrust` each open their own read.
- `CheckTrust` decodes leaf bodies without re-verifying hashes or the checkpoint in its own snapshot. It relies on the separate `CheckLog` run.
- doctor takes no lock, so an `install-bundle` run with the service stopped can interleave. doctor can then print `OK bundle: version 1` next to an `OK trust` computed against v2.

Cosmetic, because `install-bundle` and `serve` exclude each other and serve never changes trust tables, but the report then mixes two states.
**Fix:** run `CheckTrust` inside the same `ReadLogWithHashes` snapshot as `CheckLog` (one helper returning both results). Or take a shared `flock(LOCK_SH|LOCK_NB)` in doctor and report "state busy" when it fails.

### F-IN-03: merge-gate exits with `gh`'s own status on any later `gh` failure, colliding with its exit-code contract

**File:** `scripts/merge-gate.sh:95-97`, `144-146`
**Issue:** E-WR-02 maps only the identity call's failure to exit 1. Every later `view=$(bot_gh pr view ...)` runs under `set -e`, so a failure ends the script with gh's code. For example, a token revoked during the 900 s wait exits 4, which the header documents as "rebase conflict; the rebase is left in progress".
**Fix:** `view=$(bot_gh pr view ...) || { echo "gh pr view failed" >&2; return 1; }` at each call site.

### F-IN-04: the agent backend retries every failed request, including agent refusals, holding `s.mu` up to about 2 × 30 s

**File:** `internal/keystore/agent/agent.go:108-130`, `208-215`
**Issue:**

- `request` drops the connection and retries on any error, including a clean `SSH_AGENT_FAILURE`, where the connection is healthy and a retry cannot help. For a token with a touch policy, the retry asks for a second touch.
- A hung agent costs about 60 s with `b.mu`, and the signer's `s.mu`, held. `Close()` waits on `b.mu` for the same time at shutdown.

Not a correctness bug: the accept loop no longer waits on `s.mu` (A-WR-07), and `Build` verifies the returned signature.
**Fix:** retry only on transport errors: `net.Error`, `io.EOF`, `io.ErrUnexpectedEOF`, `syscall.EPIPE`/`ECONNRESET`. Return agent protocol failures at once.

### F-IN-05: `Listen`'s liveness probe writes a refusal into the other signer's audit log

**File:** `internal/signer/server.go:42-51`
**Issue:** The probe of a live socket shows up in the running signer's log as a `peer_not_allowed` or `malformed_frame` refusal. That includes an audit-log leaf, attributed to the uid of whoever started the second `serve`. The fix report mentions only the operator log. With the state-dir lock, this happens only for a second signer on a different state directory that shares the socket path, so it is rare. Still, it is an audit entry with no real request behind it.
**Fix:** document it in the `Listen` comment and the runbook. Or probe with a zero-length write plus `CloseWrite` and teach `handle` to classify an immediate EOF as `probe` without a leaf.

### F-IN-06: every failed PIV VERIFY, including a transport error, exits 78 and is never restarted

**File:** `internal/keystore/piv/piv.go:164-168`
**Issue:** By design ("the card may have counted it"), a VERIFY that fails for any reason, a reader hiccup included, wraps `ErrCredentialRefused`. systemd then never restarts the signer. This trades availability for PIN safety and is fine, but the runbook should say that exit 78 can also mean "card or reader error".
**Fix:** state it in `docs/backends/piv.md` and in the unit comment.

### F-IN-07: the new `pr-title.yml` still runs the PR's own `scripts/check-pr-title.sh`, and has no concurrency group

**File:** `.github/workflows/pr-title.yml:26-34`
**Issue:**

- The required check executes a script from the PR's merge ref, so a PR can change the script and pass its own title check. This was already true in ci.yml and is carried over unchanged. Owner review is the only control.
- Rapid title edits start parallel runs with no `concurrency:`. That works today, but relies on GitHub picking the newest check run.

**Fix:** run the check inline (a fixed regex in the workflow, title via `env:`), or check out the base ref's script (`ref: ${{ github.event.pull_request.base.sha }}`). Add `concurrency: { group: pr-title-${{ github.event.pull_request.number }}, cancel-in-progress: true }`.

### F-IN-08: `appendSignature`'s read-modify-write lost `O_APPEND`'s concurrent-writer safety

**File:** `cmd/keyroster/root.go:694-740`
**Issue:**

- **Concurrent signers:** two `root sign` runs into the same out-dir (a shared network folder during a remote ceremony) can each read the same old `.sigs`, and the later rename silently drops the other's signature. Both report `signed ...`. `trust verify` catches the shortfall at the threshold, so this is not a trust bug, only a confusing ceremony failure.
- **Symlinks:** the rename also replaces a symlinked `.sigs` file with a regular file.

**Fix:** document "one signer at a time per out-dir". Or after the rename, re-read the file and confirm that every signature present before is still there.

---

_Reviewed: 2026-10-10_
_Reviewer: Claude (gsd-code-reviewer), area F_
_Depth: standard_
