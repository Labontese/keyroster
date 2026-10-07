---
phase: 01-trust-core
reviewed: 2026-10-07
depth: standard
method: five parallel area reviews (gsd-code-reviewer), merged and de-duplicated by the orchestrator
files_reviewed: 164
findings:
  critical: 4
  warning: 25
  info: 30
  total: 59
status: issues_found
---

# Phase 1 code review (merged)

Five area reviews ran in parallel over every source, CI, script and deploy file of
phase 1 (164 files; docs and planning artifacts excluded). Each area report follows
below unchanged except for its frontmatter. Counts above are after de-duplication.

| Area | Scope | Critical | Warning | Info |
|------|-------|----------|---------|------|
| A | signing boundary: internal/signer, cert, wire, serial, signerclient, signerdb, cmd/keyroster-signer | 1 | 7 | 6 |
| B | trust anchor and roots: internal/trust, rootceremony, sshsig, cmd/keyroster | 1 | 4 | 5 |
| C | Merkle log, audit, doctor: internal/tlog, audit, doctor | 1 | 6 | 6 |
| D | keystores: internal/keystore (agent, tpm, piv) | 2 | 6 | 5 |
| E | CI workflows, rulesets, scripts, deploy units, e2e harness | 0 | 5 | 9 |

## Duplicates found independently by more than one area

| Canonical | Same issue as | Topic |
|-----------|---------------|-------|
| A-CR-01 | C-CR-01 | A running signer never reloads the trust bundle; `install-bundle` against a live signer leaves issuance on the old policy and the log unverifiable. No state-dir lock. |
| A-WR-02 | B-WR-01, C-WR-05 | Policy version / `prev` chain not enforced across successor bundles. |
| D-WR-03 | C-WR-04 | Agent custody `pkcs11-agent` is operator-asserted, never verified; doctor counts it as hardware. |
| A-IN-03 | B-IN-01 | `SigningBytes` returns nil on encode failure; `ca issue` signs evidence before validating. |

## Critical findings (de-duplicated)

1. **A-CR-01 / C-CR-01**: live signer keeps the old policy after `install-bundle`; no lock between serve and install-bundle.
2. **B-CR-01**: a root key may be listed as a policy admin, so a root could authorize issuance (KEY-07).
3. **D-CR-01**: a wrong PIV PIN file can block the card PIN within a second (no retry check + `Restart=on-failure` without `RestartSec`/`RestartPreventExitStatus`).
4. **D-CR-02**: the TPM backend accepts keys imported into the TPM (no `FixedTPM`/`FixedParent`/`SensitiveDataOrigin` check), so software keys can be reported as TPM custody.

## What was checked and holds (from the area reports)

- A certificate is released only after issuance row, serial high-water mark, log leaf and checkpoint commit in one transaction; refusals return fixed reason codes only.
- Canonical JSON is strict and signatures are over raw bytes; SSHSIG handling, pin/threshold counting and root-vs-CA key separation are correct.
- RFC 6962 hashing, strict leaf/checkpoint parsing, ECDSA checkpoints tested against published logs; `audit verify` detects removed/duplicated/reordered entries.
- Key selection by fingerprint, no fallback to weaker backends, default PIV credentials refused.
- No `pull_request_target`; least-privilege permissions; all actions SHA-pinned and verified against their tags; the 17 required checks match real job names.


---

# Area A


# Phase 01: Code Review Report, Area A (signing boundary)

**Reviewed:** 2026-10-07T03:13:09Z
**Depth:** standard
**Files Reviewed:** 49
**Status:** issues_found

## Summary

Scope: `internal/signer`, `cert`, `wire`, `serial`, `signerclient`, `signerdb` and `cmd/keyroster-signer`. I read every non-test source file in full. I checked the test files only for vacuity: whether assertions are present, whether walks can pass empty, and whether failure injection really fails. I did not review them for style.

What holds up well:
- **Wire parsing:** strict throughout. It uses cryptobyte with uint16 length prefixes, enforces per-field limits during parsing and again in `check()`, rejects trailing bytes, and caps frames at 64 KiB before allocating.
- **Domain separation:** the domain tag (`keyroster/issue-request/v1`) is the raw prefix of the signing bytes and also the SSHSIG namespace. The signing bytes cover every field except evidence, including the request id and `CreatedAt`.
- **Certificate release:** I traced every return path of `Issue`. A certificate leaves only after `logTx` gets `nil` from `WithTx`, and that happens only after `tx.Commit()` succeeds. The issuance row, the serial high-water mark, the leaf and the checkpoint commit in one BEGIN IMMEDIATE transaction. A failed commit forces a reload from disk.
- **Error responses:** they carry only fixed reason codes, never request bytes or Go error text.
- **Serial allocation:** clock-floored, and fails closed when the clock is below the stored high-water mark.

The main defect is above the transaction layer. The trust state (policy, admins, profiles) is loaded once at start-up and never re-checked. Nothing stops `install-bundle` from running against a live signer. When it does, the signer keeps authorizing under the superseded policy, and the audit log it writes no longer verifies.

## Critical Issues

### A-CR-01: A running signer keeps issuing under a superseded trust bundle and policy after `install-bundle`; the log it writes then fails `audit verify`

**File:** `internal/signer/signer.go:104`, `internal/signer/logstate.go:208-229`, `internal/signer/issue.go:60,99`, `internal/signer/server.go:34-44`, `cmd/keyroster-signer/install.go:59-70`
**Issue:**
1. The trust state is read only once, in `New` (`signer.go:104`, `loadTrust`), and stored in `s.policy`, `s.profiles` and `s.ca`. No code path reloads it, and no code compares it with the database later.
2. Nothing stops a second writer on the state directory:
   - `serve` takes no lock.
   - `install-bundle` and `ca-init` take no lock and do not check for a running signer.
   - `Listen` (`server.go:35-41`) unlinks whatever socket is at the path, so a second `serve` on the same state directory silently takes over a live signer's socket.
3. When an operator installs a successor bundle (`install.go:70`) while the service runs, the following sequence happens:
   - `InstallBundle` commits a `bundle_install` leaf at index N, with its checkpoint, from the other process.
   - The serving signer's next `appendLocked` uses its stale in-memory size N. `AppendLeaf` then fails its next-index check (`signerdb/log.go:32-34`), the transaction rolls back, and the client gets `state_unavailable`.
   - `logTx` then calls `loadLog` (`logstate.go:223`). That refreshes **only the Merkle tree**. `s.policy`, `s.profiles` and `s.ca` stay stale.
4. Every later request is authorized by `verifyAdminEvidence(req, s.policy)` (`issue.go:60`) against the **old** admin set and quorum, and gets the old profile's TTL cap and extensions. An admin the successor policy removed, for example a suspected malicious insider, can keep authorizing certificates. Nothing on the signer shows this.
5. Each of those certificates carries `pol=<old version>` in its key ID and leaf (`issue.go:99`), and is logged **after** the `bundle_install` leaf for the new policy. `audit.Verify` then rejects the export. It checks `kid.Policy != a.policy.Version` and `b.PolicyVersion != a.policy.Version` against the policy in force at that point of the log (`internal/audit/verify.go:140-145`). So the defect both weakens authorization and breaks the tamper-evidence verification the project depends on (VIS-01, D-13).

No test installs a successor while a signer is serving. `trust_test.go` covers install refusals only on a quiescent database.

**Fix:** Fail closed in the signer, and serialize the writers.
```go
// internal/signerdb/trust.go
func (d *DB) LatestBundleVersion(tx *sql.Tx) (uint64, error) {
	var v int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM trust_bundle`).Scan(&v); err != nil {
		return 0, fmt.Errorf("signerdb: read bundle version: %w", err)
	}
	return uint64(v), nil //nolint:gosec // CHECK (version >= 1)
}

// internal/signer/issue.go, first statement inside the logTx closure
if v, err := s.db.LatestBundleVersion(tx); err != nil {
	return err
} else if v != s.bundleVersion { // record ts.bundle.Version in New
	return errTrustChanged // map to refusalErr(wire.CodeUnavailable, "trust_changed", ...)
}
```
Also take an exclusive `unix.Flock(LOCK_EX|LOCK_NB)` on a lock file in the state directory in `serve`, `ca-init` and `install-bundle`, so `install-bundle` refuses while the service runs. Have `Listen` refuse to unlink a socket that still accepts connections: dial it first, and treat a successful dial as "already running". Document in `signer-install.md` that a successor needs a stop, install, start sequence. Add a test that installs v2 while a `Signer` is live and asserts the next request is refused, not issued under v1.

## Warnings

### A-WR-01: `loadTrust` takes the `trust_bundle` row on faith; it is never tied to the verified log

**File:** `internal/signer/trust.go:397-451`
**Issue:** At start-up, `loadTrust` checks only internal consistency: the version column against the bundle, `PolicySHA256` against the stored policy, and the bundle keys against `ca_keys` and the log origin. It does not check root signatures; the pins are not stored. It also does not compare the stored bundle and policy bytes with the latest `bundle_install` leaf of the log, even though `initLog` verifies that log against a log-key checkpoint right afterwards (`signer.go:127`).

Anyone who can write `signer.db` but cannot use the log key can insert a `trust_bundle` row with version 99. Examples are a tampered backup, an offline disk edit, or a process running as another uid with write access to the file. That row can carry a self-made policy listing the attacker's key as the only admin with quorum 1. Its `bundle_sigs` and `policy_sigs` are never checked. The signer starts and accepts that admin's evidence. The log stays internally consistent, because no new leaf is written. Exploitation needs write access to the state database, so this is defence in depth, not a remote hole. Still, the log-key checkpoint already gives a cheap, strong anchor that the code does not use.
**Fix:** In `New`, after `initLog`, walk the verified leaves for the last `KindBundleInstall` body. Require `bytes.Equal` with `stored.Bundle`, `stored.BundleSigs`, `stored.Policy` and `stored.PolicySigs`, and require its `BundleVersion == stored.Version`. Refuse to start on any mismatch, with `errLogMismatch`.

### A-WR-02: Successor install does not chain or order the policy; `pol=N` in key IDs can name two different policies

**File:** `internal/signer/trust.go:218-228`
**Issue:**
- For a successor bundle, `InstallBundle` checks only that the bundle version increases.
- `trust.VerifySuccessor` checks the bundle chain (`b.Prev`, `b.Version`) but never sees the installed policy.
- Neither function checks that `p.Prev == SHA256(installed policy)` or that `p.Version` increases. `Policy.Prev` is validated only as a hex string (`trust/policy.go:72`).

A root-signed successor can therefore carry a policy with the same version number but different admins or profiles, or an older policy version. The key ID's `pol=` field and the leaf's `PolicyVersion` then no longer identify one policy. An auditor reading `pol=3` on a certificate cannot tell which admin set authorized it, which undermines the "who granted what" guarantee.
**Fix:** In the successor branch, parse `latest.Policy` and require:
- `p.Version > prevPolicy.Version` (or `== prevPolicy.Version` only when `bytes.Equal(policy, latest.Policy)`)
- `p.Prev == trust.SHA256Hex(latest.Policy)` whenever the version changes

Mirror the same rule in `audit.Verify`.

### A-WR-03: A root-signed policy with `admin_quorum` > 4 makes issuance impossible

**File:** `internal/signer/evidence.go:61`, `internal/wire/issue.go:34`, `internal/trust/policy.go:78`
**Issue:** `Policy.Validate` accepts any `AdminQuorum` from 1 to `len(Admins)`. The request format caps evidence at `wire.MaxEvidence = 4`; both `check()` and `ParseIssueRequest` refuse more. With `admin_quorum: 5` or more, every request fails with either `malformed_request` or `admin_quorum_not_met`. The ceremony, `install-bundle` and the signer's start-up all accept such a policy, so the CA ships unable to issue. It fails closed, but the cause is never stated.
**Fix:** Enforce `AdminQuorum <= wire.MaxEvidence` in `trust.Policy.Validate`. If `trust` must not import `wire`, use a shared constant. Alternatively, refuse it in `InstallBundle` and `loadTrust` with an explicit message.

### A-WR-04: A replayed request is refused only after the CA key has signed it

**File:** `internal/signer/issue.go:81-113,156-158`
**Issue:**
- Request-id reuse is detected only by the `UNIQUE` constraint in `InsertIssuance`, inside the commit transaction. By then:
  - `serial.Next` has run, and may have slept.
  - `cert.Build` has made a real CA signature through the backend.
- Within the ±300 s freshness window, anyone on the allowlist can replay a captured, validly signed request. A compromised API process can do this repeatedly, and each replay is one more operation on the CA key. On a PIV backend with a touch policy, the operator is asked to touch the key for a request the signer then refuses. That trains operators to approve touches blindly and contradicts the package contract "decides whether to issue, then issues".
- The certificate is dropped, so it does not leak.
**Fix:** Before `serial.Next`, call `SELECT 1 FROM issuance WHERE request_id = ?`, for example `s.db.RequestIDUsed(ctx, req.RequestID)`, and refuse `duplicate_request` there. Keep the `UNIQUE` constraint as the backstop. `s.mu` already serializes issuance, so the pre-check cannot race within the process.

### A-WR-05: The refusal `cause` is never logged, so internal failures leave no trace

**File:** `internal/signer/issue.go:26-30`, `internal/signer/refusal.go:65-69,158-164`
**Issue:** The struct comment says `cause` is "logged as a type only". In fact `refuseErr` drops it and calls `refuse(..., classify(r.reason), r.reason)`; `refuse` logs only uid, pid, reason, class and code. Nothing reads `cause` (the only reference is `Unwrap`). The affected refusals are `state_unavailable` (a failed commit, `SQLITE_BUSY`, or an `AppendLeaf` index mismatch as in A-CR-01), `build_failed`, `log_encoding`, `serial_unavailable` and `bad_policy`. Each leaves an operator with only the reason code and no way to find the root cause.
**Fix:** Pass the cause's class to the operator log, not to the socket:
```go
func (s *Signer) refuseErr(ctx context.Context, peer Peer, digest [32]byte, err error) *wire.ErrorResponse {
	var r *refusal
	if !errors.As(err, &r) {
		r = &refusal{code: wire.CodeInternal, reason: "internal_error", cause: err}
	}
	if r.cause != nil {
		s.log.Warn("refusal cause", "reason", r.reason, "cause_type", fmt.Sprintf("%T", r.cause), "cause", r.cause.Error())
	}
	return s.refuse(ctx, peer, digest, classify(r.reason), r.reason)
}
```
If logging the full `cause.Error()` is a concern, log `%T` plus the `errors.Is` class. In either case, fix the comment so it matches what the code does.

### A-WR-06: `doctor`'s log check is not snapshot-consistent and reports a false FAIL against a live signer

**File:** `internal/signer/logstate.go:85-92,95-160`, `cmd/keyroster-signer/doctor.go:142`
**Issue:**
- `CheckLog` → `rebuildLogFrom` runs three separate autocommit reads: `db.LeafHashes`, then `db.ForEachLeaf`, then `db.LatestCheckpoint`. In WAL mode, each statement sees its own snapshot.
- The runbook runs `doctor` (step 9) after the service has started (step 7). A refusal or issuance appended between the reads gives one of these results:
  - "leaf n has no stored hash"
  - "N leaves, M hashes"
  - a checkpoint/size mismatch
- `doctor` then prints FAIL and exits 1 on a healthy log. A check that can cry wolf invites operators to ignore the one real tamper alarm.
- `signerdb.ReadLog` already reads one consistent snapshot, but `CheckLog` does not use it.

**Fix:** Run the three reads inside one read transaction, for example by adding a `signerdb.ReadLogWithHashes(ctx, fn)` that opens `BeginTx(ctx, &sql.TxOptions{ReadOnly: true})` and serves hashes, leaves and the latest checkpoint from the same `tx`. Have `rebuildLogFrom` use it.

### A-WR-07: The accept loop blocks on `s.mu` and an fsync'd transaction when over capacity

**File:** `internal/signer/server.go:92-98`, `internal/signer/refusal.go:65-87`
**Issue:**
- When all `maxConns` slots are busy, the accept loop calls `s.refuse(...)` **synchronously**.
- `refuse` takes `s.mu`. The in-flight `Issue` holds that mutex across CA signing (TPM, or PIV with touch), so `refuse` blocks until it is released. It then runs a `synchronous=FULL` write transaction for the refusal leaf.
- While the loop is blocked, no new connections are accepted, so overload causes a total stall.
- The rate limiter is also checked only after the lock is taken.

**Fix:** Do not touch `s.mu` from the accept loop:
- Close the connection and count the overload in an atomic counter.
- Or hand it to a goroutine, but not one that holds a `sem` slot.
- Fold the counter into the next `refusal_summary` in `flushSummaries`, which already runs under `s.mu`.

## Info

### A-IN-01: `allowed_critical_options` in the root-signed policy is dead configuration

**File:** `internal/signer/issue.go:102-111`, `internal/signer/profiles.go:36`, `internal/wire/issue.go:83-93`
**Issue:**
- `IssueRequest` has no critical-options field, and `Issue` never sets `cert.Request.CriticalOptions`.
- A policy that allows `source-address`, `force-command` or `verify-required` therefore has no effect, and nothing tells the root signers this.
- The setting is permissive, not mandatory, so it does not weaken issuance, but the policy says something the signer does not do.

**Fix:** Either add critical options to the wire request and signing bytes, or reject a non-empty `allowed_critical_options` until that exists. If neither is done now, document that the setting is reserved.

### A-IN-02: Fatal paths that do not stop the process, and recoverable ones that do

**File:** `internal/signer/server.go:85-91`, `internal/signer/logstate.go:222-226`
**Issue:** These are two sides of the same supervision gap:
- A transient `AcceptUnix` error, such as `EMFILE` or `ECONNABORTED`, makes `Serve` return and stops the signer.
- When the log is marked `broken` (`logstate.go:224`), the process keeps running and refuses every request with `state_unavailable` until an operator notices. systemd restarts neither case usefully.

**Fix:**
- Retry temporary accept errors with backoff, the way `net/http.Server.Serve` does.
- Make a `broken` log fatal, for example by cancelling the serve context with an error, so the unit restarts and `New` re-verifies the log.

### A-IN-03: `SigningBytes` returns `nil` on an encoding failure

**File:** `internal/wire/issue.go:175-179`
**Issue:** If a caller builds a request with a field over 65535 bytes without calling `Marshal` or `ParseIssueRequest`, `SigningBytes()` returns `nil`. `Digest()` then hashes the empty input, and `verifyAdminEvidence` checks signatures over `nil`. The server path always parses first, so this cannot be reached today. It is still a silent footgun on the most sensitive encoder.
**Fix:** Return `([]byte, error)`, or panic, because the comment says this is a programming error.

### A-IN-04: Serial uniqueness after a restore depends on the wall clock, and the restore rolls back the log without any local alarm

**File:** `internal/serial/serial.go:1-5,45-48`, `internal/signer/logstate.go:143-160`
**Issue:**
- The regression check compares the clock only with the **restored** high-water mark.
- If a restore coincides with a clock that is behind the pre-restore serials, but still ahead of the restored mark, earlier serials can be reissued without `ErrClockRegression`. One example is a VM snapshot restore that brings back both the disk and an old RTC.
- In the same scenario, the restored log is internally consistent, so the signer starts. Certificates issued after the backup disappear from the audit trail without any local signal (`TestSignerRestore` asserts this behaviour).
- This is presumably accepted until the witness work, but the package comment overstates it ("a serial is never issued twice").

**Fix:**
- Qualify the package comment.
- Optionally persist the highest serial or checkpoint size outside `signer.db`, for example in a small append-only file or the witness checkpoint that later phases add, and compare it at start.

### A-IN-05: `ca-pubkeys.json` is created 0600, not the 0644 the code asks for

**File:** `cmd/keyroster-signer/cainit.go:72`, `cmd/keyroster-signer/main.go:18`
**Issue:** `main` sets `Umask(0o077)`, so `OpenFile(..., 0o644)` produces mode 0600. The nolint comment says these are public keys. Nothing breaks, because the same user copies the file, but the intent and the result differ.
**Fix:** `f.Chmod(0o644)` after creating the file, or change the requested mode and comment to 0600.

### A-IN-06: The SignCert guard exempts all of `internal/cert`, not just `Build`

**File:** `internal/cert/signcert_guard_test.go:105-108`
**Issue:** The guard skips every file under `internal/cert/`. A second `SignCert` call added anywhere in that package, outside `Build`, would pass. The guard also cannot see a certificate signed by hand with `ca.Sign` over marshalled certificate bytes. The test asserts that it visited files, so it is not vacuous, but it is narrower than the "Build is the only call site" claim in `builder.go:1-3`.
**Fix:** Allow only `internal/cert/builder.go`, and inside it only the `Build` function, for example by parsing with `go/ast` and checking the enclosing `FuncDecl`.

---

_Reviewed: 2026-10-07T03:13:09Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

---

# Area B


# Phase 01: Code Review Report — Area B (trust anchor and roots)

**Reviewed:** 2026-10-07
**Depth:** standard
**Files Reviewed:** 36
**Status:** issues_found

## Summary

This review covers canonical JSON, SSHSIG, pin and threshold verification, the successor rule, the software root lifecycle and the `root` / `trust` / `ca` / `audit` CLI. Most of the core is solid. Each item below was checked against the source and found sound:

- **Canonical JSON:** `decodeStrict` refuses unknown fields and then compares byte for byte with the canonical re-encoding. Signatures are verified over the raw input bytes, never over a re-serialisation. `VerifySuccessor` also compares `prevCanonical` with `prev.Canonical()`.
- **SSHSIG:**
  - Only `sha512` is accepted.
  - An empty namespace or a namespace mismatch is refused.
  - The reserved field must be empty.
  - The blob must re-marshal to exactly the input.
  - For `sk-*` keys the user-presence flag is required.
  - RSA keys and certificates are refused.
- **Pins and threshold:** distinct fingerprints are counted, and the key bytes are compared as well as the fingerprint. Unpinned signers and signatures under the wrong namespace are ignored. Duplicate pins are refused. A bundle's root set must equal the pinned set exactly.
- **Bundle keys:** a CA, ops or log key that equals a root key is refused (`ErrKeyIsRoot`).
- **Root key file:** the encrypted root is created with `O_EXCL` and mode 0600.
- **Passphrase input:** the passphrase comes only from the terminal or an inherited fd, never from argv or the environment.
- **Confirmation:** signing requires the 8-hex-digit prefix of the bundle hash.

The gaps are cross-document and operational:

- A root key can be listed as an admin (issuance authorizer). This violates KEY-07.
- The policy `prev`/`version` chain is never enforced.
- The `.sigs` append path has two ways to wreck a ceremony output directory.
- `trust verify` can report a signer count that contradicts its own listing.

## Critical Issues

### B-CR-01: A root key is accepted as a policy admin key, so a root can authorize certificate issuance (violates KEY-07)

**File:** `internal/trust/verify.go:66-113` (VerifyGenesisBundle), `internal/trust/verify.go:168-222` (VerifySuccessor), `internal/trust/policy.go:68-116` (Validate), `cmd/keyroster/root.go:232-260` (root sign)

**Issue:** KEY-07 says a root "signs only trust bundles, KRL authority and policy". `Bundle.Validate` (`bundle.go:161-174`) refuses any CA, ops or log key that equals a root key. Admin keys are never compared with root keys:

- `Policy.Validate` checks admin key types and duplicates within the policy only.
- `VerifyGenesisBundle` and `VerifySuccessor` hold both `b` and `p` but never cross-check `p.Admins` against `b.Root.Keys`.
- `root sign` signs such a policy without complaint.
- On the signer side, `checkPolicyAdmins` (`internal/signer/trust.go:325-338`) compares admins only with the signer's CA, ops and log keys, not with roots.

A genesis or successor policy can therefore list a root key (for example a FIDO `sk-ssh-ed25519` root) as an admin, and every layer accepts it. After that:

1. `keyroster ca issue --admin-key <root fingerprint>` works whenever that root is loaded in ssh-agent, for example during a ceremony: `adminEvidence` (`ca.go:137-173`) signs with any agent key.
2. `verifyAdminEvidence` accepts the evidence.
3. The offline root becomes a routine, online issuance authorizer.

The namespaces do keep the signatures from being confused with one another. The defect is the dual use itself: the separation the threat model relies on (offline roots versus online authorizers) is not enforced. The task brief explicitly asks for root keys to be refused here.

**Fix:** refuse the overlap in the trust layer, which every consumer (signer install, audit verify, `trust verify`, `root sign`) goes through. For example, add to `verify.go` and call it from both `VerifyGenesisBundle` (after parsing) and `VerifySuccessor`, against the new bundle's roots and, for successors, the previous bundle's roots as well:

```go
// checkAdminsNotRoots refuses a policy whose admin keys include a root key:
// roots sign only bundles and policies (KEY-07).
func checkAdminsNotRoots(p *Policy, roots map[string]ssh.PublicKey) error {
	for _, a := range p.Admins {
		pub, err := ParseKey(a.Key)
		if err != nil {
			return fmt.Errorf("%w: admin %s: %w", ErrInvalid, a.Name, err)
		}
		if r, ok := roots[ssh.FingerprintSHA256(pub)]; ok && bytes.Equal(r.Marshal(), pub.Marshal()) {
			return fmt.Errorf("%w: policy admin %s is root %s", ErrKeyIsRoot, a.Name, ssh.FingerprintSHA256(pub))
		}
	}
	return nil
}
```

Also check this in `runRootSign` after `prepareBundle`, so a ceremony never signs such a pair, and add a test for each entry point.

## Warnings

### B-WR-01: The policy version/prev chain is never enforced; `prev` is decorative after genesis

**File:** `internal/trust/verify.go:168-200`, `internal/trust/policy.go:72-76`

**Issue:** `Policy` has `version` and `prev` fields, and the genesis check requires `version 1` with the all-zero prev. After genesis nothing checks them:

- `VerifySuccessor` never receives the previously installed policy, so it cannot check `p.Prev == SHA256(previous policy)` or `p.Version == previous.Version+1`.
- Its only policy checks are `ParsePolicy`, the hash in `b.PolicySHA256`, and the root signature thresholds.

A successor bundle can therefore carry a policy with any version and prev, including another `version: 1` with the genesis prev, or a version lower than the one in force.

The consequence: `internal/audit/verify.go:143` and the issue leaves record `PolicyVersion` as if it identified the policy, but two different policies can share a version number. "Policy v2" in an audit report would then not pin down which admin set and profiles were in force. `signer/trust_test.go:374` builds `p.Version, p.Prev = 2, SHA256Hex(v1)`, which shows the chain is intended; the verifier just does not implement it.

**Fix:** Pass the previous policy's canonical bytes into `VerifySuccessor` (both callers, `signer/trust.go:224` and `audit/verify.go:85`, have them). Then require either of the following:
- `p.Version == prevPolicy.Version+1` and `p.Prev == SHA256Hex(prevPolicyBytes)`.
- The policy is byte-identical to the previous one (`b.PolicySHA256 == prev.PolicySHA256`). This is the unchanged-policy case.

Refuse anything else with `ErrVersionChain`.

### B-WR-02: Appending to a `.sigs` file whose last block lacks a trailing newline makes the whole file unparseable

**File:** `cmd/keyroster/root.go:326-331`, `cmd/keyroster/root.go:550-561` (appendFile); `internal/sshsig/sshsig.go:215-222`

**Issue:** `sshsig.ParseAll` explicitly accepts a final block without its newline (tested in `sshsig_test.go:247-250`). `refuseIfSigned` therefore parses such a file successfully, and `appendFile` then writes a new `-----BEGIN SSH SIGNATURE-----` block directly after `-----END SSH SIGNATURE-----` on the same line.

On the next read, `parseBlock` fails with "data after -----END SSH SIGNATURE----- on the same line". `ParseAll` fails the whole file by design, so every root signature already collected in it, including ones from other custodians, stops counting. `trust verify` and bundle install then fail with a malformed-signature error.

A file without a final newline is easy to produce: hand-assembled signatures, an editor that strips trailing newlines, or a copy from a custodian's offline machine.

**Fix:** In `appendFile` (or a `.sigs`-specific variant), read the existing file's last byte and write a `'\n'` first when the file is non-empty and does not end in one. After appending, re-parse the file with `sshsig.ParseAll` and fail loudly if it no longer parses.

### B-WR-03: The two `.sigs` appends are not atomic, and a partial failure blocks completing the ceremony

**File:** `cmd/keyroster/root.go:282-289`, `cmd/keyroster/root.go:326-331`

**Issue:** `runRootSign` makes both signatures and then appends to `bundle.json.sigs` and `policy.json.sigs` one after the other. If the first append succeeds and the second fails (disk full, permissions, removable media pulled), the root has signed the bundle but not the policy.

Rerunning the command hits `refuseIfSigned` on `bundle.json.sigs` ("already holds a signature") and refuses before reaching the policy. The operator can only finish by hand-editing signature files during a root ceremony, which is the step most likely to introduce B-WR-02 or worse.

The same applies when `appendFile` fails mid-write: a truncated block invalidates the whole file, as in B-WR-02. Neither the `.sigs` files nor the encrypted root key (`writeExclusive`, `root.go:538-548`) are fsynced before success is reported. The root key is written to offline or removable media and is the only copy, so a write cached but not yet flushed when the media is removed can lose the key after the public key has already been printed and distributed.

**Fix:**
1. Make the duplicate check per file: skip a document whose `.sigs` already holds a valid signature by this root, and refuse only when both already do.
2. Write each `.sigs` update atomically: read the current file, append the block, write it to a temp file in the same directory, `f.Sync()`, then `os.Rename`.
3. Call `f.Sync()` in `writeExclusive` before `Close`, at least for the root key file.

### B-WR-04: `trust verify` reports a signer count that is not the number of roots that signed both documents

**File:** `cmd/keyroster/trust.go:86-94`

**Issue:** `k := min(len(bundleSigners), len(policySigners))` is printed as "OK: signed by k of N pinned roots", but the "signed by root" lines above it print only the intersection.

Example: with threshold 2 and pins {A, B, C}, suppose A and B sign the bundle and B and C sign the policy. Verification passes, since each document meets the threshold. The tool then prints a single "signed by root B" line followed by "OK: signed by 2 of 3 pinned roots". Two of the roots counted signed only one document each.

The project's core value is accurate visibility of who vouched for what, and this summary line is what operators record during a ceremony.

**Fix:** Collect the intersection once and report from it, and report bundle-only and policy-only signers separately:

```go
var both []string
for _, fp := range bundleSigners {
	if slices.Contains(policySigners, fp) {
		both = append(both, fp)
		fmt.Fprintf(stdout, "signed by root %s\n", fp)
	}
}
fmt.Fprintf(stdout, "OK: bundle signed by %d, policy by %d, both by %d of %d pinned roots (threshold %d)\n",
	len(bundleSigners), len(policySigners), len(both), len(pinned), *threshold)
```

## Info

### B-IN-01: `ca issue` signs admin evidence before validating the request; an oversized request gets an SSHSIG over an empty message

**File:** `cmd/keyroster/ca.go:88-104`, `cmd/keyroster/ca.go:150`

**Issue:** `wire.IssueRequest.SigningBytes()` returns `nil` when a field exceeds the 16-bit length prefixes. The cause in `internal/wire/issue.go:175-178` is outside area B.

The CLI does not bound `--principal` count or length. `adminEvidence` therefore asks each admin key (possibly a touch-required FIDO key) to sign SHA-512 of the empty message under `keyroster/issue-request/v1`. `signerclient.Issue` then fails in `Marshal()`'s `check()`, and the signature is discarded without being sent, so there is no current impact. It is a fail-open sentinel next to an authorization primitive.

**Fix:** Call `req.Marshal()` (or an exported `Check`) before `adminEvidence` and return its error. In `adminEvidence`, refuse `msg == nil`. Separately, have `SigningBytes` return an error instead of `nil` (area of `internal/wire`).

### B-IN-02: Passphrase buffer reallocation leaves uncleared copies in memory

**File:** `internal/rootceremony/passphrase.go:70-94`

**Issue:** `readPassphraseFD` starts with `make([]byte, 0, 128)` and grows with `append` up to 1024 bytes. Each reallocation leaves the previous backing array, holding a passphrase prefix, uncleared, and only the final buffer is zeroed. This undercuts the module's own best-effort zeroing (`defer clear(pass)` at the callers).

**Fix:** Allocate once with `make([]byte, 0, maxPassphraseBytes)`. The existing length check already stops before the capacity is exceeded.

### B-IN-03: Key material zeroing in OpenRoot/GenerateRoot is partial and not documented as such for OpenRoot

**File:** `internal/rootceremony/keygen.go:88-128`, `internal/rootceremony/keygen.go:36-47`

**Issue:** `OpenRoot` zeroes `plain`. `ssh.ParseRawPrivateKey` makes its own copies (the PEM-decoded `block.Bytes` and the parsed OpenSSH key structures), and the age stream reader keeps internal buffers; none of these are zeroed. `GenerateRoot` has the same pattern with `ssh.MarshalPrivateKey`'s intermediate buffers. `GenerateRoot`'s comment admits "best effort"; `OpenRoot`'s does not. The behaviour is acceptable for the documented software-root threat model, but the comments overstate it.

**Fix:** Document the limit on `OpenRoot` and `Root.Close`, for example "zeroes keyroster's copies; library-internal copies are not reachable", so operators do not rely on it.

### B-IN-04: The canonical-JSON fuzz targets check a property the parser enforces by construction

**File:** `internal/trust/fuzz_test.go:24-57`

**Issue:** `FuzzParseBundle` and `FuzzParsePolicy` assert that an accepted input equals `Canonical()` of the parsed value. `decodeStrict` (`canonical.go:39-45`) already returns `ErrNotCanonical` unless exactly that holds, so the assertion can never fail. The targets therefore only check for panics. That is still useful, but the doc comment claims more.

**Fix:** Either reword the comment to "never panics", or make the oracle independent. For example, decode with a second, deliberately lenient `json.Unmarshal` into the same struct and assert that every accepted input also round-trips through it to identical field values, or assert `Validate()` is nil for every accepted value.

### B-IN-05: `TestVerifySuccessor` refusal cases do not assert that no documents are returned

**File:** `internal/trust/verify_test.go:215-235`

**Issue:** `TestVerifyGenesisBundle` checks `b != nil || p != nil` on refusal (lines 113-115), but `TestVerifySuccessor` only checks `errors.Is(err, tc.want)`. A regression that returned the parsed successor along with an error, for a caller that checks the result before the error, would go unnoticed. The suite also has no case for B-WR-01 (a successor with a non-chained policy) or for B-CR-01.

**Fix:** Add `if b != nil || p != nil { t.Fatal("refused but returned documents") }` to the refusal branch. Add cases for the policy chain and for an admin key equal to a root key once those checks exist.

---

_Reviewed: 2026-10-07_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

---

# Area C


# Phase 01 (area C): Code Review Report

**Reviewed:** 2026-10-07
**Depth:** standard (with cross-file reads of the call sites in internal/signer, internal/signerdb, internal/trust, cmd/keyroster/audit.go, cmd/keyroster-signer/{doctor,export}.go)
**Files Reviewed:** 14
**Status:** issues_found

## Summary

The core log machinery is sound and I found no defect in it:

- RFC 6962 hashing goes through `rfc6962.DefaultHasher`, with the 0x00 leaf prefix and 0x01 node prefix. `log_test.go` checks it against a hand-written MTH reference for sizes 0 to 70 and against known empty-tree and empty-leaf vectors.
- Leaves carry their own domain tag and decode strictly. The fuzz target checks that decode followed by encode reproduces the input, for the leaf and for every body kind.
- Checkpoint parsing is strict: exactly 3 lines, canonical decimal size, and canonical, strict base64 for a 32-byte root. The origin must equal the verifier name.
- The C2SP type 0x02 ECDSA verifier has these properties:
  - Its key ID is SHA-256 of the SPKI DER, and signatures are DER over SHA-256.
  - It is tested against checkpoints published by real logs and against an independent re-implementation.
  - The signer side converts the SSH mpint blob to DER and self-verifies before it returns.
- `audit.Verify` detects removed, duplicated, reordered and out-of-index entries. It re-hashes the leaf bytes itself and ignores the stored hashes and the `decoded` field. The log key is anchored only through bundle_install entries that verify against the pins, with the genesis/successor (TUF) rule.
- `--previous` is checked by recomputing the old root from the export's own leaf hashes. That is stronger than a consistency proof.
- Export reads one consistent snapshot, and `forEachLeaf` enforces exactly `size` leaves.

The findings cluster in three places:

1. **The local integrity checks (serve start-up and doctor) cannot tell a rolled-back log or a swapped log key from a healthy one, and still report OK.**
2. **Doctor's custody checks can print the "every online key has hardware custody" OK line without evidence.**
3. **`audit.Verify` does not check the policy chain, and treats `pol=N` as naming a unique policy (C-WR-05). Separately, because serve never reloads its policy, an honest log can permanently fail verification (C-CR-01).**

One finding is a BLOCKER. C-CR-01 is a routine admin action, a successor install-bundle while serve runs, and it permanently writes a signed entry that makes every future export of the log fail `audit verify`. The rest are fail-open or false-OK conditions in a security-first product, rated WARNING. Note: the Go toolchain is not on PATH in this environment, so no tests or fuzz targets were run. Every finding comes from reading the source and its call sites.

## Critical Issues

### C-CR-01: [BLOCKER] An honest log becomes permanently unverifiable if install-bundle runs while serve is running (cross-area: signer)

**File:** `internal/audit/verify.go:140-145`; root cause: `internal/signer/signer.go:112` (policy loaded once in `New`) and `internal/signer/trust.go:195-270` (`InstallBundle` has no exclusion against a running serve; nothing in the repo uses `flock`)

**Issue:** The steps are:

1. serve loads `s.policy` once at start, and every issuance stamps `pol=s.policy.Version` (`issue.go:99`).
2. `keyroster-signer install-bundle` can run against the same `signer.db` while serve is up. SQLite `_txlock=immediate` serializes the writes but does not prevent this. It appends a bundle_install with policy v2.
3. serve's next append fails once because its in-memory tree is stale (`AppendLeaf` "not the next index"). `logTx` reloads the tree but not the policy.
4. Every later issue leaf still carries `pol=1`, now after a bundle_install whose policy is v2.

`audit.Verify` then fails with `key ID pol=1, but the policy in force is version 2`. That entry is signed into the log forever, so no export of this log can ever verify again. Verify is right to flag it, but the signer produces it in normal operation, and the runbooks do not say serve must be stopped for a successor install.

**Fix:** Do both:

1. Make serve check the installed bundle version at the start of each issuance transaction, inside the same `BEGIN IMMEDIATE`, and refuse (or reload trust state) when it changed.
2. Make `install-bundle` refuse to run while serve holds the state directory, using an advisory `flock` on `<state-dir>/signer.lock` that serve takes for its lifetime.

Document "stop serve before install-bundle" as well.

**Why BLOCKER:** the sequence is reachable with the default backends. A second process can open the ssh-agent socket and `/dev/tpmrm0` (the kernel resource manager) while serve holds them. `install-bundle` opens the backend independently (`cmd/keyroster-signer/install.go:64`). The result is permanent loss of verifiability (VIS-03) for the whole log after one routine admin action, and the bad entry cannot be removed without rewriting the signed history.

## Warnings

### C-WR-01: [WARNING] serve and doctor accept a log rolled back to any earlier signed prefix, or wiped entirely (cross-area: signer, signerdb)

**File:** `internal/signer/logstate.go:143-160` (used by `CheckLog`, which doctor calls at `cmd/keyroster-signer/doctor.go:142-146`), `internal/signerdb/log.go:42-54,127`, `internal/doctor/doctor.go:192-196`

**Issue:** Every append stores a signed checkpoint for the new size (`PutCheckpoint`), and the code keeps all of them. `latestCheckpoint` picks the checkpoint with the largest size. Someone with write access to `signer.db` (no key needed) can do either of these:

- **Truncate to a prefix.** Delete leaves `idx >= k` and checkpoints `size > k`. The remaining checkpoint for size `k` is genuinely signed by the log key and matches the prefix. `rebuildLogFrom` accepts it, doctor prints `OK log: the stored leaves reproduce the latest checkpoint`, and serve starts and appends at index `k`. The log key then signs a forked history.
- **Wipe the log.** Delete every `log_leaf` and `checkpoint` row. Lines 144-148 return an empty tree with no error, although `ca_keys` (written in the same transaction as the `ca_init` leaf) proves the log cannot honestly be empty.

`audit verify` without `--previous` accepts the truncated fork, because the bundle_install entry is still in the prefix. Only an operator who kept an earlier checkpoint detects it. The package doc says doctor FAILs on "an audit log that no longer reproduces its signed checkpoint", but this tampering is reported as OK.

Other tables, written in the same transaction as the leaves, contradict a rollback of the log tables alone:

- `last_serial` must equal the serial of the last issue leaf, or 0 with no issue leaf.
- The number of `issuance` rows must equal the number of issue leaves.
- `LatestBundle().Version` must equal the version of the last bundle_install leaf.
- If `ca_keys` exist, the log must contain at least one entry.

**Fix:** In `rebuildLogFrom` (so serve and doctor both get it), cross-check the rebuilt log against the other tables:

```go
// after the checkpoint check in rebuildLogFrom:
if tree.Size() == 0 && haveCAKeys {
    return nil, 0, fmt.Errorf("%w: ca_keys recorded but the log is empty", errLogMismatch)
}
if lastIssueSerial != db.LastSerial() || issueLeaves != db.IssuanceCount() ||
    lastBundleInstallVersion != latestBundle.Version {
    return nil, 0, fmt.Errorf("%w: log does not cover the recorded issuance/bundle state (rolled back?)", errLogMismatch)
}
```

These cross-checks catch only a rollback of the log tables. An attacker who also rolls back `issuance`, `last_serial` and `bundles`, or restores the whole file from a snapshot, is still detectable only through `--previous` or witnesses. Document that limit so the cross-check is not mistaken for a complete fix. No code path deletes rows from `issuance` (no `DELETE` in internal/signerdb), so the count equality holds on honest databases. Also consider keeping only the latest checkpoint, or deleting superseded ones in the append transaction, so the database no longer holds a signed rollback point for every size. Make `audit verify` print a warning when `--previous` is absent (see C-IN-05).

### C-WR-02: [WARNING] doctor checks the log against the log key recorded in the same database and never compares it with the installed bundle (cross-area: cmd)

**File:** `cmd/keyroster-signer/doctor.go:126-146` (feeds `Facts.LogMatches`, `internal/doctor/doctor.go:192-196`)

**Issue:** `readDBFacts` takes the log public key from the `ca_keys` row `role='log'` in `signer.db` and runs `signer.CheckLog` with it. It never compares that key with the installed bundle's `Log.Key`/`Log.Origin`, which `f.Bundle` already holds. serve does that comparison: `loadTrust` → `checkBundleKeys(b, caKeys)` plus `openRoleKey` in the backend (`internal/signer/trust.go:423-447`). So an attacker who can write the database can:

1. replace the `ca_keys` log row with a key they generated;
2. rewrite leaves and checkpoints and sign them with that key.

doctor then prints `OK log: ... signed by the log key`, while serve refuses to start. A health check that passes on state the service itself rejects defeats its purpose.

**Fix:** In `readDBFacts`, once the bundle is parsed, require the recorded log key to match it, or check the log against the bundle key directly:

```go
if f.Bundle != nil {
    bk, err := trust.ParseKey(f.Bundle.Log.Key)
    if err != nil || !bytes.Equal(bk.Marshal(), logKey.Marshal()) {
        f.LogDetail = "recorded log key differs from the installed trust bundle's log key"
        // leave f.LogMatches false
    }
}
```

Better still, run the same `checkBundleKeys` that serve runs and report a mismatch as FAIL.

### C-WR-03: [WARNING] doctor prints OK hardware custody for TPM keys when the TPM was not inspected

**File:** `internal/doctor/doctor.go:291-322`

**Issue:** When keys are recorded with custody `tpm`, the `switch` handles only `TPMError != ""` and `TPMCustody != ""`. If both are empty, nothing is emitted and `weak` stays false. Line 316 then emits `OK custody: every online key has hardware custody`. Both are empty when the gatherer did not run `tpm.Inspect` (it only does so when `BackendConfig` name is `"tpm"`, `cmd/keyroster-signer/doctor.go:167`), or when Inspect returns an empty custody without an error. The function's own contract (lines 245-247) says only a TPM that "still matches the recorded custody" yields an OK custody line. This is a fail-open default in a pure check.

**Fix:**

```go
switch {
case f.TPMError != "":
    ...
case f.TPMCustody != "":
    ...
default:
    weak = true
    rs = append(rs, Result{Level: WARN, Code: CodeTPMUnavailable,
        Message: "keys are recorded with TPM custody but the TPM was not inspected; custody unconfirmed"})
}
```

Add a test case with `TPMCustody=""` and `TPMError=""`.

### C-WR-04: [WARNING] custody `pkcs11-agent` is operator-declared, yet doctor reports it as hardware custody

**File:** `internal/doctor/doctor.go:152-154,316-322`; source of the value: `internal/keystore/agent/agent.go:49-56`

**Issue:** `hardwareCustody` contains `"pkcs11-agent"`. The agent backend sets that custody purely from the `custody=pkcs11-agent` backend option, and nothing confirms that the key in the agent comes from a PKCS#11 token. So these keys get the line `OK custody: every online key has hardware custody (...: pkcs11-agent)`:

- a plain `ssh-add`'ed file key;
- a SoftHSM2 token loaded with `ssh-add -s`.

That contradicts the package guarantee at lines 12-13: "doctor never reports a vTPM-held, agent-held or software key as hardware custody". TPM custody is at least cross-checked against the live TPM manufacturer. `pkcs11-agent` is not checked at all.

**Fix:** Leave `pkcs11-agent` out of the unconditional OK line. Emit `INFO pkcs11_custody_declared: keys X are declared pkcs11-agent; doctor cannot verify that the agent key lives in a hardware token (SoftHSM or a plain ssh-add key would look the same)`. Then print the OK line only for verifiable custodies (`tpm` confirmed by manufacturer, `piv`), or label it "declared hardware custody".

### C-WR-05: [WARNING] The policy hash chain (`Policy.Prev`, version) is never checked, but `audit.Verify` treats `pol=N` as identifying one policy (cross-area: trust)

**File:** `internal/audit/verify.go:73-113,140-145`; `internal/trust/verify.go:168-222`; `internal/trust/policy.go:15-22,68-77`

**Issue:** `trust.Policy` carries `Version` and a `Prev` hash. `Validate` only checks their structure, and `VerifySuccessor` only checks `b.PolicySHA256 == SHA256(policy)`. Neither `VerifySuccessor` nor `anchor.install` requires any of the following of a successor's policy:

- that its version is above the previous one, or equal if the policy is unchanged;
- that `Prev` equals SHA-256 of the previous policy.

A root-signed successor can therefore carry a different policy (other admins, quorum or profiles) under a version number already used. `checkIssue` then checks only `kid.Policy == a.policy.Version`, so issue leaves with `pol=1` under two different policies verify identically. The certificate key ID's `pol=` field, meant to say which policy authorized a cert, becomes ambiguous for anyone holding only the certificate. The documents are root-signed, so this is not an outsider forgery, but it breaks the audit trail's "which rules applied" guarantee, and the `Prev` field gives a false impression of a chain.

**Fix:** In `trust.VerifySuccessor`, and so in `anchor.install` as well, enforce:

```go
prevPolicyHash := ... // SHA-256 of the previous policy document (VerifySuccessor needs it as a parameter)
switch {
case b.PolicySHA256 == prev.PolicySHA256:
    // unchanged policy: same document, nothing more to check
case p.Version == prevPolicy.Version+1 && p.Prev == prevPolicyHash:
    // valid successor policy
default:
    return nil, nil, fmt.Errorf("%w: policy version/prev do not chain", ErrVersionChain)
}
```

`anchor` must then keep the previous policy's canonical bytes, as it already does for the bundle.

### C-WR-06: [WARNING] `audit.Verify` checks neither profile compliance nor issuance authorization, and the logged admin evidence cannot be verified offline at all

**File:** `internal/audit/verify.go:116-147,336-381`; `internal/tlog/leaf.go:160-171` (what an issue leaf records); `internal/sshsig/sshsig.go:12,33,170` and `internal/signer/evidence.go:38,53` (what the evidence signs)

**Issue:** For each issue leaf, Verify checks:

- the CA signature;
- the CA key against the bundle;
- the certificate type against the role;
- `pol`, the serial and the key ID.

It has two gaps:

1. **Profile compliance is not checked, although it could be.** The policy in force (with its `CAProfiles`) and the full certificate are both in the export. Verify still never checks the role's validity cap, the allowed extensions or critical options, or that host certificates carry no extensions. A signer with the CA key, compromised or buggy, can log a certificate with a TTL above the cap or with forbidden extensions, and `keyroster audit verify` reports `OK`.
2. **Authorization cannot be checked from the log.** Each admin's `admin-sshsig/v1` evidence is an SSHSIG over `SHA-512(req.SigningBytes())`: sshsig accepts only sha512, and evidence.go verifies over `msg = req.SigningBytes()`. The issue leaf stores only `RequestDigest = SHA-256(SigningBytes)` and none of the request fields, so an offline auditor can verify neither that the evidence signatures are valid and meet `admin_quorum` of the policy in force, nor that the certificate matches what the admins approved (principals, subject key, validity). A compromised signer can log garbage evidence for an unauthorized issuance, and the log still verifies.

VIS-03 promises verification "end to end", and the core value is that "nobody can hide what they granted". A log that records unauthorized grants and still verifies falls short of that.

**Fix:**

- In `anchor.checkIssue`, re-run the profile check with the same logic as `cert.Build`'s enforcement, applied to `c.ValidBefore - c.ValidAfter`, `c.Extensions`, `c.CriticalOptions` and `c.CertType`.
- For authorization, log the request signing bytes in the issue body, since they are bounded by `wire.MaxFrame`. Verify can then:
  1. recompute `RequestDigest`;
  2. verify each evidence SSHSIG against `a.policy.Admins` and require `AdminQuorum` distinct admins;
  3. check that the certificate's key, principals and validity equal the request's.

  This changes the leaf format, which is cheap before a v1 release.
- If either change is deliberately out of Phase 1 scope, state the limitation in the `Verify` doc comment and in the CLI output.

## Info

### C-IN-01: [INFO] `EncodeLeaf` swallows errors and is dead in production

**File:** `internal/tlog/leaf.go:89-97`

**Issue:** It returns `nil` on any error. No production code calls it; only tests use it, and production uses `MarshalLeaf`. A future caller could hash or store a nil leaf without noticing.

**Fix:** Remove it, or move it to a `_test.go` helper.

### C-IN-02: [INFO] OK and FAIL results share code strings

**File:** `internal/doctor/doctor.go:59-60,76-77`

**Issue:** `codeDBMode = "db_permissions"` equals `CodeDBPermissions`, and `codeIntegrity = "db_integrity"` equals `CodeDBIntegrity`. A consumer that keys on the code alone, such as a monitoring grep for `db_integrity`, cannot tell pass from fail without also parsing the level.

**Fix:** Give OK results distinct codes, as the other checks already do (`log` vs `log_mismatch`), or document that the code names the check rather than the problem.

### C-IN-03: [INFO] `FuzzVerifyExport`'s oracle is weaker than its comment

**File:** `internal/audit/fuzz_test.go:10-30`

**Issue:** The comment promises that anything accepted is "a non-empty log whose checkpoint the log key of a bundle signed by the pinned root signed". The test only asserts `rep.Size != 0 && len(rep.Root) == 32`, and `Verify` already guarantees both. So in practice it is a no-panic fuzz.

**Fix:** Also assert `rep.LogKey` equals the fixture's log key, `rep.BundleVersion >= 1`, and that re-verifying the accepted input gives the same root. Or reword the comment.

### C-IN-04: [INFO] The "strict JSONL" parser accepts case-variant and duplicate keys

**File:** `internal/audit/verify.go:392-414`

**Issue:** `encoding/json` matches field names case-insensitively and lets the last duplicate key win. So `{"INDEX":0,"Leaf":"..."}` and `{"index":5,"index":0,...}` are accepted. Leaf bytes are re-hashed and the index is re-checked, so this has no integrity effect, but the doc comment's "strict" claim is overstated.

**Fix:** Reword the comment, or decode with `json/v2` semantics, or with a token-level check that rejects duplicate and non-canonical keys.

### C-IN-05: [INFO] `audit verify` prints an unqualified OK without `--previous`

**File:** `cmd/keyroster/audit.go:110-111` (consumer of `audit.Verify`)

**Issue:** Without `--previous`, Verify cannot detect truncation or rollback (C-WR-01). The output still reads `OK: N entries ...` with no hint that the append-only property went unchecked.

**Fix:** When `opts.Previous == nil`, append `(append-only not checked: no --previous)` to the human output, and add `"previous_checked": false` to the JSON.

### C-IN-06: [INFO] The refusal-summary total can silently overflow

**File:** `internal/tlog/leaf.go:344-350`, `internal/audit/verify.go:269`

**Issue:** `Count` is any `uint64 > 0`. `Total()` and `rep.SummarizedRefusals +=` wrap around on overflow. It only affects the report, and the leaves are log-key-signed, but a crafted log could show a small refusal count.

**Fix:** Use `bits.Add64` and refuse, or saturate, on carry.

---

_Reviewed: 2026-10-07_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

---

# Area D


# Phase 01: Code Review Report — Area D (keystores)

**Reviewed:** 2026-10-07T12:00:00Z
**Depth:** standard
**Files Reviewed:** 15
**Status:** issues_found

## Summary

I reviewed the keystore registry, the ssh-agent, TPM 2.0 and YubiKey PIV backends, and their tests. I also checked the third-party code they rely on in the module cache: go-piv/piv-go v2.6.0, foxboron/go-tpm-keyfiles @20260902 and x/crypto v0.57.0 ssh/agent. Where a finding depends on caller behaviour, I traced it to `internal/signer/trust.go`, `internal/signer/signer.go`, `cmd/keyroster-signer/serve.go` and `deploy/systemd/keyroster-signer.service`.

**What holds up:**
- **Key selection by fingerprint is sound.** The agent backend skips certificate entries, and every backend refuses an empty fingerprint. Unknown roles never become paths or slots.
- **`pinnedKey` re-checks the result.** It verifies both the fingerprint and `CheckCAKey`, and `openRoleKey` refuses a custody that differs from the recorded one.
- **No error path falls back to a weaker backend.** `keystore.Open` has no fallback, and every `Key` returns an error instead of picking another key.
- **Hash handling is correct.** ECDSA P-256 goes through `ssh.NewSignerFromSigner` with SHA-256, which the TPM keyfile signer maps to `TPMAlgSHA256`. Ed25519 goes through PIV with `Hash(0)`.
- **Locking is correct.** The TPM uses the global `tpmMu`, the PIV backend serialises through its backend mutex, and the agent through the backend mutex. `Public()` never touches the device.
- **Default credentials are refused.** That covers the default PIN and the default management key. AES management keys are fine, because piv-go 2.6.0 detects the key type through GET METADATA.

**Main concerns:**
1. **PIV PIN lockout.** The PIV backend's "one PIN retry per signer start" protection is defeated by the shipped systemd unit (`Restart=on-failure`). A single bad `pin-file` blocks the card's PIN within about a second.
2. **TPM custody can over-claim hardware in three ways:**
   - The TPM backend never checks that a key was generated inside the TPM. The PIV backend does check this.
   - It treats every unknown TPM manufacturer ID as hardware.
   - It trusts the ID reported over the "test only" `swtpm-socket` transport.
3. **TPM dictionary-attack lockout.** The TPM keys are not `noDA`, and a bad auth value only shows up at signing time, so the signer can push the TPM into dictionary-attack lockout.

## Critical Issues

### D-CR-01: A wrong PIV PIN blocks the card's PIN within seconds under the shipped systemd unit (BLOCKER)

**File:** `internal/keystore/piv/piv.go:119-138`, `internal/keystore/piv/card.go:14-31`, `deploy/systemd/keyroster-signer.service:23`

**Issue:**
- `newBackend` calls `c.VerifyPIN(cfg.pin)` on every open. Its comment says a wrong PIN therefore "costs one PIN retry per signer start".
- The only unit that ships, `keyroster-signer.service`, sets `Restart=on-failure`, with no `RestartSec=`, no `StartLimit*=` and no `RestartPreventExitStatus=`.
- With systemd defaults, a wrong or stale `pin-file` restarts the signer about every 100 ms. A YubiKey PIV PIN has 3 retries by default, so it is blocked after the third start, well inside systemd's 5-starts-in-10-seconds limit, with no operator involved.
- Recovery then needs the PUK. If the PUK is unknown or also blocked, the only way out is a PIV reset, which destroys the CA keys in slots 0x82-0x86. That loses the CA keys.
- The backend never reads the remaining retry count before it spends one. piv-go exposes it as `(*YubiKey).Retries()`, but the `card` interface has no such method.
- The fake card in `piv_test.go:70-78` has no retry counter, so the tests cannot catch this.

**Fix:** Read the retry counter first and refuse to spend the last retries. Also make a PIN refusal a non-restartable exit.
```go
// card.go
type card interface {
	// ...
	// PINRetries returns the number of PIN attempts left (VERIFY with no data).
	PINRetries() (int, error)
}

// yubikey.go
func (y *yubiKey) PINRetries() (int, error) { return y.yk.Retries() }

// piv.go, in newBackend before VerifyPIN
const minPINRetries = 2 // never spend the last retry automatically
n, err := c.PINRetries()
if err != nil {
	_ = c.Close()
	return nil, fmt.Errorf("keystore piv: read PIN retries: %w", err)
}
if n < minPINRetries {
	_ = c.Close()
	return nil, fmt.Errorf("keystore piv: only %d PIN retries left; refusing to try the PIN automatically (verify it by hand with ykman)", n)
}
```
In the signer, map a PIN refusal to a dedicated exit code, and add `RestartPreventExitStatus=<code>` to the unit. Also set `RestartSec=5s` and `StartLimitBurst=`. Extend `fakeCard` with a retry counter, and add a test that opens it repeatedly with a wrong PIN and asserts the counter never reaches 0.

### D-CR-02: The TPM backend accepts keys that were not generated inside the TPM and reports them as hardware custody (BLOCKER)

**File:** `internal/keystore/tpm/tpm.go:148-161` (and `:181`)

**Issue:**
- `Key()` checks only the TSS2 key type (`OIDLoadableKey`), the algorithm (ECC) and the curve (P-256). It never checks the object attributes in the key's public area.
- A key that was created in software and wrapped for this TPM with `TPM2_Import` is still a valid loadable key blob. Examples are `tpm2_import` followed by `tpm2_encodeobject`, or go-tpm-keyfiles' importable-to-loadable path.
- An imported object has `fixedTPM` and `fixedParent` CLEAR and `sensitiveDataOrigin` CLEAR, because TPM2_Import requires duplicable objects. Yet `Key()` loads it and `caKey.Custody()` reports `tpm` or `vtpm`.
- This path is reachable: `InitCA` (`internal/signer/trust.go:86-118`) takes an explicit per-role `selection`, without calling `Provision`, for any backend, including `tpm`.
- An admin can therefore keep a software copy of a CA key and have the signed trust bundle and the `ca_init` log entry record it as non-exportable TPM custody.
- The PIV backend explicitly refuses the equivalent case (`piv.go:321`, `info.Origin != ykpiv.OriginGenerated`). The package doc for `tpm` also claims "The CA, ops and log keys are ECDSA P-256 keys created inside the TPM … the TPM never reveals them", which `Key()` does not enforce.
- Keys from `Provision` have the right attributes (`go-tpm-keyfiles tpm.go:198-206`: FixedTPM, FixedParent, SensitiveDataOrigin), so the check costs nothing for legitimate keys. The public area is bound to the private blob through the object name, so the TPM enforces these attributes when it loads the key.

**Fix:**
```go
pubArea, err := k.Pubkey.Contents()
if err != nil {
	return nil, fmt.Errorf("keystore tpm: %s: %w", keyPath, err)
}
a := pubArea.ObjectAttributes
if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
	return nil, fmt.Errorf("keystore tpm: %s was not generated inside this TPM (fixedTPM=%v fixedParent=%v sensitiveDataOrigin=%v)",
		keyPath, a.FixedTPM, a.FixedParent, a.SensitiveDataOrigin)
}
```
Add a test that builds an importable key (`keyfile.NewImportablekey`), turns it into a loadable blob through TPM2_Import on swtpm, and asserts that `Key()` refuses it.

## Warnings

### D-WR-01: TPM CA keys are DA-protected and a bad auth value only fails at signing time, so the signer can lock out the whole TPM (WARNING)

**File:** `internal/keystore/tpm/provision.go:72-73`, `internal/keystore/tpm/tpm.go:144-181`

**Issue:**
- `Provision` creates keys with go-tpm-keyfiles' `createECCKey` template (`go-tpm-keyfiles tpm.go:198-220`). That template does not set `NoDA`, so every failed authorisation on these keys increments the TPM's dictionary-attack counter.
- `Key()` reads `{role}.auth` but never proves it is right. `TestKeyRefusals` (`tpm_test.go:226-235`) confirms that a wrong auth loads fine and only fails at `Sign`.
- Keys are fetched once at startup and reused for every request (`signer.go:135`, `trust.go:348`). A corrupted or truncated auth file therefore fails one TPM authorisation per signing request.
- After the TPM's `maxTries` it enters lockout. Lockout is TPM-wide, so it also breaks unrelated DA-protected users on the host, such as TPM+PIN LUKS unsealing, until `lockoutRecovery` expires or someone uses the lockout hierarchy.
- The PIV backend deliberately avoids the same failure class (D-CR-01). The TPM backend does not.

**Fix:** Do one test signature over a fixed digest inside `Key()`, and refuse the key if it fails, so a bad auth costs one DA attempt per start rather than one per request. Since the auth value is 32 random bytes, DA protection adds nothing here. Create the keys with an own template that sets `NoDA: true`, via `tpm2.Create` under the SRK, instead of `keyfile.NewLoadableKey`. Also apply the D-CR-01 start-loop guards to the TPM path.

### D-WR-02: TPM custody is decided fail-open from an unauthenticated, self-reported manufacturer ID, including over the "test only" swtpm socket (WARNING)

**File:** `internal/keystore/tpm/vendor.go:21,62-67`, `internal/keystore/tpm/tpm.go:98-105`, `internal/keystore/tpm/transport.go:26-27`

**Issue:**
- `CustodyForManufacturer` is a denylist: only `IBM`, `MSFT` and `GOOG` map to `vtpm`, and every other ID maps to hardware `tpm`. `vendor_test.go:24` locks this in, as does the test comment "physical vendors and unknown IDs are tpm".
- Any virtual or emulated TPM whose ID is not on the list is therefore recorded as hardware custody in the trust bundle and the audit log.
- `TPM_PT_MANUFACTURER` is whatever the TPM implementation, or the hypervisor behind it, answers to `GetCapability`. Nothing authenticates it; there is no EK-certificate check against a vendor root.
- The `swtpm-socket` transport is documented as "test and development only", but production builds accept it. Over it, `open` derives custody from the ID that the process behind the Unix socket reports.
- So any TPM emulator that reports a non-denylisted ID gets custody `tpm`. The custody=`tpm` option guard at `tpm.go:102` does not help, because the ID already maps to `tpm`.

**Fix:**
- Make the mapping fail closed: an allowlist of known physical-TPM manufacturer IDs → `tpm`, and everything else → `vtpm`. Operators can still claim more with `custody=tpm` only when the ID is on the allowlist.
- Force `CustodyVTPM` whenever `swtpm-socket` is set, or reject that option outside a test build tag.
- Longer term, base `tpm` custody on verifying the EK certificate chain to a manufacturer CA.

### D-WR-03: Agent custody `pkcs11-agent` is an unverified operator assertion (WARNING)

**File:** `internal/keystore/agent/agent.go:49-56`, `:124`

**Issue:**
- `custody=pkcs11-agent` is accepted as given. Every key in the agent then reports `CustodyPKCS11Agent`, a hardware-token custody, even when it was added from a software file with plain `ssh-add`.
- `openRoleKey` (`trust.go:343-356`) only catches a later *change* of the option, not a false claim at `ca-init`. The signed trust bundle and the `ca_init` entry then over-claim hardware custody, which undermines the "full visibility" goal.
- `TestOptions/custody_pkcs11_agent` (`agent_test.go:260-269`) shows a software Ed25519 key being labelled `pkcs11-agent`.

**Fix:**
- Either verify something observable, such as requiring that the agent entry's comment equals a configured PKCS#11 provider path or label as OpenSSH reports it, or refuse keys whose comment does not match.
- Or record the custody as asserted (for example `pkcs11-agent-asserted`) and surface it as unverified in `doctor` and in the bundle documentation.

### D-WR-04: PIV custody and key origin are taken from the card's self-report, with no attestation; card selection is by reader-name substring (WARNING)

**File:** `internal/keystore/piv/yubikey.go:32-36`, `internal/keystore/piv/piv.go:314-322`

**Issue:**
- Any PC/SC reader whose name contains "yubikey" is accepted. `Origin == OriginGenerated` comes from the card's own GET METADATA answer.
- A virtual smart card, such as vsmartcard/vpcd under a "Yubico YubiKey …" reader name, or any applet answering the Yubico extensions, passes both checks. Its software-held key is then recorded as custody `piv`.
- YubiKeys provide exactly the evidence needed: the per-slot attestation (`(*YubiKey).Attest`), signed by the f9 attestation key and chaining to Yubico's PIV root. The backend does not use it.

**Fix:** In `Key()` (or at least at `ca-init`), fetch `Attest(slot)` and verify it against the card's f9 certificate and Yubico's embedded PIV root CA. Check that the attested public key equals `info.PublicKey`, and take origin and policies from the attestation. Refuse custody `piv` if the attestation does not verify.

### D-WR-05: TPM key-file creation never fsyncs the directory, so a crash after `ca-init` commits can lose the only copy of the CA keys (WARNING)

**File:** `internal/keystore/tpm/provision.go:100-117`, `:121-138`

**Issue:**
- `writeNew` fsyncs each file, but neither `{state-dir}/tpm` nor its parent is ever fsynced after the entries are created.
- `InitCA` commits the fingerprints, the bundle configuration and the `ca_init` log entry right after `Provision` returns.
- The keys are not persistent TPM objects: the wrapped blobs in `{role}.tpmkey` plus `{role}.auth` are the only way to use them.
- POSIX does not guarantee that a new directory entry survives a crash until the directory is fsynced. A power loss after the database commit can leave a pinned CA with no key files, and no way to recover the keys.

**Fix:** After the write loop succeeds, fsync the `tpm` directory (and the state directory if `os.Mkdir` created `tpm` in this run):
```go
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
// in Provision, after all writeNew calls succeed:
if err := syncDir(b.dir); err != nil { /* remove written files, return error */ }
```

### D-WR-06: The agent backend never reconnects; after an ssh-agent restart the signer stays up but cannot sign (WARNING)

**File:** `internal/keystore/agent/agent.go:57-61`, `:118-122`

**Issue:**
- `open` dials the socket once, and every `caKey` signs over that single `net.Conn`.
- Keys are opened once at `serve` start and cached (`signer.go:135`, `trust.go:348`).
- If `keyroster-signer-agent.service` restarts, or the agent or its PKCS#11 helper dies, every signature fails with an I/O error until someone restarts the signer by hand. The process does not exit, so `Restart=on-failure` never fires.
- `Sign` also has no deadline, so an agent that hangs blocks every signing request behind `b.mu`.

**Fix:**
- On a connection error in `caKey.Sign`, redial the socket under `b.mu` and re-list the keys. Re-select the entry by the same fingerprint, so certificate entries are still skipped, and retry once.
- Alternatively, treat a broken agent connection as fatal and exit so systemd restarts the signer.
- Set a deadline on the connection (`conn.SetDeadline`) around each request.

## Info

### D-IN-01: Secret and key files are checked with `Lstat` and then opened by path (TOCTOU)

**File:** `internal/keystore/tpm/tpm.go:229-241`, `internal/keystore/piv/piv.go:379-391`

**Issue:** `readPrivateFile` and `readSecretFile` `Lstat` the path, then `os.ReadFile` it, which follows symlinks. Between the two calls the file can be replaced, for example by a symlink to a file with looser permissions. The risk is limited, because the TPM directory is checked to be 0700. The PIV `pin-file` and `mgmt-key-file` directories are not checked.

**Fix:** Open with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC` (`unix.Open`), `Fstat` the descriptor, check that it is a regular file, its mode and that the owner is `os.Getuid()`, then read from the same descriptor.

### D-IN-02: The PIV `Key()` does not enforce the key policies the design depends on

**File:** `internal/keystore/piv/piv.go:321-334`

**Issue:** Only `Origin` is checked. A selected slot key with `PINPolicyNever` is accepted silently, so the PIN protection is lost. A key with `TouchPolicyAlways` or `Cached` makes every signature wait for a touch while holding `b.mu`, which stalls all signing. The package doc defines the intended policy as PIN once, touch never.

**Fix:** Refuse `info.PINPolicy == ykpiv.PINPolicyNever`. Either refuse touch policies other than `TouchPolicyNever` or report them in `Describe` and `doctor`.

### D-IN-03: The `inner_key_fingerprint` subtest cannot fail

**File:** `internal/keystore/agent/agent_test.go:171-181`

**Issue:** `sshagent.NewKeyring().Add` with `Certificate` set stores only the certificate signer (x/crypto v0.57.0 `ssh/agent/keyring.go:174-184`), so the plain inner key is never listed. The `inner_key_fingerprint` case therefore returns `ErrKeyNotPresent` whether or not `isCertificate` exists. Real OpenSSH `ssh-add` usually adds both the plain key and the certificate. The `certificate_fingerprint` case does discriminate, because `CheckCAKey` would otherwise return `ErrCertificateKey`.

**Fix:** Drop the `inner_key_fingerprint` case, or replace it with a meaningful one: add the plain key *and* the certificate, as `ssh-add` does, pin the inner key's fingerprint, and assert that the plain entry is returned and is not a certificate.

### D-IN-04: The "no YubiKey has serial N" error prints `%!w(<nil>)`

**File:** `internal/keystore/piv/yubikey.go:63`

**Issue:** When no reader matches, or every card opened but had a different serial, `errs` is empty and `errors.Join()` returns nil. `fmt.Errorf("...: %w", nil)` then renders `%!w(<nil>)` in the operator-facing message.

**Fix:** Only append `: %w` when `len(errs) > 0`, and otherwise list the readers that were tried.

### D-IN-05: The TPM CA keys are dual-use (sign + decrypt) with no fixed signing scheme

**File:** `internal/keystore/tpm/provision.go:72` (template from go-tpm-keyfiles `tpm.go:198-220`)

**Issue:** The keyfiles template sets both `SignEncrypt` and `Decrypt`, with `Scheme: TPMAlgNull`. Anyone holding the role's auth value can use the CA key for ECDH (`TPM2_ECDH_ZGen`) as well as for signing, and with any hash. That is not a direct break, but it violates key separation for a CA key.

**Fix:** When replacing the template for D-WR-01, use `SignEncrypt: true, Decrypt: false` and pin the scheme to ECDSA with SHA-256 (`TPMSSchemeHash{HashAlg: TPMAlgSHA256}`). Also have `Key()` check that the scheme is pinned.

---

_Reviewed: 2026-10-07T12:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

---

# Area E


# Phase 01 (area E): Code Review Report

**Reviewed:** 2026-10-07
**Depth:** standard
**Files Reviewed:** 50
**Status:** issues_found

## Summary

Area E covers the CI workflows, rulesets, repo scripts, the systemd/sysusers deploy files, the e2e harness and go.mod/tools. The baseline supply-chain posture holds up. These claims were checked against source and hold:

- No workflow uses `pull_request_target`, `workflow_run` or `issue_comment`.
- Every workflow sets `permissions: {}` and grants per-job `contents: read`. Write scopes appear only in codeql (`security-events`) and scorecard (`security-events`, `id-token`), which have no PR-controlled `run:` steps.
- Every checkout uses `persist-credentials: false`.
- No `${{ }}` expression carrying untrusted data reaches a `run:` block. The PR title reaches `check-pr-title.sh` only through `env: PR_TITLE` (ci.yml:148-150).
- All 7 actions are pinned to 40-hex SHAs. Each pin was checked against its `# vX.Y.Z` tag through the GitHub API, and all 7 match.
- The 17 contexts in `main-integrity.json` match the 17 job/matrix names exactly. `integration_id` 15368 is GitHub Actions, and `RepositoryRole` 5 is admin.
- The e2e workflows set `shell: bash`, so `go test ... | tee` runs under `-eo pipefail`.
- The OpenSSH cache key includes the build script hash, and PR caches are ref-scoped.
- `build-openssh.sh` pins both SHA-256 and the GPG primary fingerprint.
- The negative e2e tests nearly all have a positive control on the same sshd configuration, so a refusal cannot come from a broken setup.
- `merge-gate.sh` uses an explicit-SHA `--force-with-lease`, the safe form.

No BLOCKER-class defect was found. The main issues:

1. The required `pr-title` gate does not re-run on title edits, and CONTRIBUTING claims it does.
2. `merge-gate.sh` loses its token-separation guarantees in two places: it executes the bot wrapper from whatever branch is checked out, and its `git push` identity depends on unversioned local credential config.
3. The security scanners (govulncheck, CodeQL) never see the shipped `-tags piv` build variant.
4. The signer's ssh-agent unit, which holds the CA keys, has no sandbox regression gate.

## Warnings

### E-WR-01: Required `pr-title` check never re-runs on a title edit, so it can be bypassed, and CONTRIBUTING claims otherwise

**File:** `.github/workflows/ci.yml:6` (trigger) and `.github/workflows/ci.yml:137-150` (job); `CONTRIBUTING.md:19-21`

**Issue:** ci.yml subscribes to `pull_request:` with no `types:`, so GitHub uses the defaults `opened`, `synchronize` and `reopened`. `edited` is not among them. Two consequences:

- **Bypass.** A PR opened with a valid title passes `pr-title`. If the title is then edited to anything, nothing re-runs. The squash commit on `main` takes the title at merge time (CONTRIBUTING.md:9-11), so the Conventional Commits guarantee the required check is meant to enforce does not hold.
- **False claim.** CONTRIBUTING.md:20-21 says "Edit the title and the check runs again." It does not. A PR with a bad title stays red after the fix until somebody pushes a new commit or closes and reopens it.

**Fix:** Move the job into its own workflow and delete it from ci.yml. Do not duplicate it: otherwise two check runs named `pr-title` report on the same SHA. The required context name stays `pr-title`.

```yaml
# .github/workflows/pr-title.yml
name: PR title
on:
  pull_request:
    types: [opened, edited, synchronize, reopened]
permissions: {}
jobs:
  pr-title:
    name: pr-title
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Check Conventional Commits PR title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: bash scripts/check-pr-title.sh
```

Update the CONTRIBUTING.md table row (line 73) to name `pr-title.yml` as the workflow.

### E-WR-02: merge-gate.sh runs the token-separation wrapper from the working tree, including after it switches to the unreviewed PR branch

**File:** `scripts/merge-gate.sh:50,99,151,153,167,175,185` (calls) and `scripts/merge-gate.sh:135,137` (branch switch); premise in `scripts/gh-as-bot.sh:4-6`

**Issue:**

- **Premise.** gh-as-bot.sh exists because "GH_TOKEN and GITHUB_TOKEN ... would override that config and make the command run as the owner".
- **How the script calls it.** merge-gate.sh invokes it by relative path, `scripts/gh-as-bot.sh`, at every GitHub call.
- **The branch switch.** In `rebase_onto_main`, the script runs `git switch` to the PR branch (135/137) and then rebases. Every later call (151 `pr view`, 153 `pr merge --auto --squash`, 167/175/185 `pr view`/`pr checks`) executes the PR branch's copy of `gh-as-bot.sh`. That copy is bot-authored and has not been reviewed yet.
- **Inconsistent protection.** The header (28-29) guards merge-gate.sh itself against "a branch switch replaces this file on disk", but not the wrapper that enforces token separation.
- **Consequence.** A PR that edits gh-as-bot.sh, by mistake or otherwise, can make the gate run `gh pr merge --auto --squash` with the owner's `GH_TOKEN` or `GITHUB_TOKEN`. The owner then becomes the actor that enabled the merge. That breaks the "talks to GitHub only as the bot / Claude never ... merges a PR with the owner's credentials" rule in CONTRIBUTING.md:122-125 and :132.

**Fix:** Inline the wrapper as a function inside merge-gate.sh. bash parses the whole file before `main` runs, so the function survives the branch switch. Then replace every `scripts/gh-as-bot.sh` call with `bot_gh`.

```bash
bot_gh() {
	env -u GH_TOKEN -u GITHUB_TOKEN \
		GH_CONFIG_DIR="${KEYROSTER_BOT_GH_CONFIG:-$HOME/.config/gh-keyroster-bot}" gh "$@"
}
```

Optionally, assert the identity once at start: `[ "$(bot_gh api user --jq .login)" = keyroster-bot ] || { echo "gh is not keyroster-bot" >&2; return 1; }`.

### E-WR-03: merge-gate.sh's force-push identity is not controlled by the script; the local helper it relies on does not unset GITHUB_TOKEN

**File:** `scripts/merge-gate.sh:149` (also the fetches at 46 and 104), against the header claim at `scripts/merge-gate.sh:20-23`

**Issue:**

- **What the header claims.** "Every GitHub call runs as keyroster-bot through scripts/gh-as-bot.sh".
- **What actually happens.** `git fetch` and `git push --force-with-lease` do not go through gh-as-bot.sh. They use whatever git credential helper is configured.
- **The helper in use.** The helper this clone uses is unversioned local config, set up per `.planning/phases/01-trust-core/01-01-PLAN.md:262`: `!f() { env -u GH_TOKEN GH_CONFIG_DIR="$HOME/.config/gh-keyroster-bot" gh auth git-credential "$@"; }; f`. It unsets `GH_TOKEN` but not `GITHUB_TOKEN`, and gh gives `GITHUB_TOKEN` precedence over stored config for github.com.
- **When it breaks.** If the shell has an owner `GITHUB_TOKEN`, or the clone lacks the repo-local helper override (a fresh clone falls back to the global `gh auth git-credential`, which uses the owner's login), the rebased branch is force-pushed as the owner.
- **Consequence.** The owner becomes the last pusher. `require_last_push_approval` (main-review.json:25) then refuses the owner's approval, which is exactly the failure CONTRIBUTING.md:129-131 warns about. It also breaks the "only as the bot" guarantee.

**Fix:** Pin the credential helper on the push itself, using the same unset list as gh-as-bot.sh, so the script does not depend on local config.

```bash
git -c credential.https://github.com.helper= \
    -c "credential.https://github.com.helper=!env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR=${KEYROSTER_BOT_GH_CONFIG:-$HOME/.config/gh-keyroster-bot} gh auth git-credential" \
    push --quiet --force-with-lease="refs/heads/$branch:$remote_sha" origin "$branch" || return 1
```

Apply the same `-c` pair to the `git fetch` calls, or route them through a `bot_git` function.

### E-WR-04: govulncheck and CodeQL never analyse the shipped `-tags piv` build

**File:** `.github/workflows/ci.yml:80`, `.github/workflows/codeql.yml:43-45`, `.github/workflows/piv.yml:48-84`

**Issue:**

- **govulncheck.** It runs in source mode with default tags only (`go tool -modfile=tools/go.mod govulncheck ./...`). It reports only vulnerable symbols reachable under those tags. `github.com/go-piv/piv-go/v2` is in go.mod (go.mod:10) but is reachable only under `-tags piv` (cmd/keyroster-signer/backends_piv.go:1). A reachable vulnerability in piv-go, or in the cgo path it pulls in, is therefore never reported.
- **CodeQL.** It builds with `CGO_ENABLED=0 go build ./...`, so `internal/keystore/piv` and `backends_piv.go` are never extracted.
- **piv.yml.** It vets, lints and tests the variant but runs neither scanner.
- **Why it matters.** The variant is a documented, supported build of the signer (piv.yml:3-6; CLAUDE.md: "Ship as a separate -tags piv build"). capslock already documents piv as a deferred target (scripts/capslock-check.sh:22-24) and is not counted here.

**Fix:** In piv.yml, which already installs `libpcsclite-dev`, add:

```yaml
      - name: Scan the piv build for reachable vulnerabilities
        run: CGO_ENABLED=1 go tool -modfile=tools/go.mod govulncheck -tags piv ./...
```

In codeql.yml, for the `go` matrix entry, install `libpcsclite-dev` and add a second build `CGO_ENABLED=1 go build -tags piv ./...` before `analyze`.

### E-WR-05: The signer's ssh-agent unit, which holds the CA keys, has no sandbox gate and its PKCS#11 path is never exercised under systemd

**File:** `test/systemd/smoke.sh:259` (agent: report only) and `:260` (signer: `--threshold`); `deploy/systemd/keyroster-signer-agent.service:23,35-37`

**Issue:**

- **The gate covers only the signer.** smoke.sh gates `systemd-analyze security --threshold` on keyroster-signer.service. For keyroster-signer-agent.service it only prints the last line (`| tail -n 1`, exit status ignored).
- **The agent is the more exposed process.** It holds the CA private keys (agent backend) or the PKCS#11 handles. It keeps the host network namespace (`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `IPAddressAllow=localhost`). It loads vendor `.so` modules through ssh-pkcs11-helper.
- **What the smoke test checks.** It checks the signer's caps, no_new_privs, seccomp and netns (213-233), but none of these for the agent.
- **Consequence.** A later PR can weaken the agent unit (drop `SystemCallFilter`, `ProtectSystem`, `MemoryDenyWriteExecute`, or widen `IPAddressAllow`) and CI stays green.

**Fix:**

1. Gate the agent unit too, for example with `KEYROSTER_AGENT_SECURITY_THRESHOLD`: `systemd-analyze security --no-pager --threshold="$AGENT_THRESHOLD" keyroster-signer-agent.service`. Record the measured value in the systemd.yml comment the same way as for the signer.
2. Assert its `/proc/$agent_pid/status` CapEff, CapBnd, NoNewPrivs and Seccomp the same way as lines 229-233. Get the PID with `systemctl show -p MainPID --value keyroster-signer-agent.service`.

## Info

### E-IN-01: check-pinned-actions.sh validates only the SHA format, not that the SHA belongs to the named upstream tag

**File:** `scripts/check-pinned-actions.sh:24,40`
**Issue:** Any 40-hex value passes. A SHA from a fork in the same fork network (an "impostor commit"), or a pin whose `# vX.Y.Z` comment names a different tag, would pass the required `pinned-actions` check. The allowlist in `apply-security-settings.sh:51` matches on owner/repo, so it does not help either. All 7 current pins were verified to match their commented tags, so there is no live issue.
**Fix:** Add a CI step that resolves each `owner/repo@sha # vX.Y.Z` with `gh api repos/OWNER/REPO/git/ref/tags/vX.Y.Z` (dereferencing annotated tags) and fails on mismatch, or run zizmor's `impostor-commit` and `ref-version-mismatch` audits.

### E-IN-02: The agent unit's `-P` PKCS#11 allowlist is untested and hard-codes x86_64 multiarch paths

**File:** `deploy/systemd/keyroster-signer-agent.service:23`
**Issue:**
- smoke.sh only `ssh-add`s plain Ed25519 keys (smoke.sh:126-130). The PKCS#11 e2e lanes start their own agent with `-P <resolved module>` (pkcs11_test.go:144). The unit's own `-P` list is therefore never exercised.
- All three entries are `/usr/lib/...` or `/usr/lib/x86_64-linux-gnu/...`, so on an arm64 signer host no module can load.
- The repo's own `scripts/softhsm-setup.sh:68-69` says ssh-agent matches the allowlist against the resolved path, but the unit lists `/usr/lib/softhsm/libsofthsm2.so` unresolved. Whether that path is a symlink on Ubuntu could not be checked here (no softhsm2 in the local WSL).
- The test-only SoftHSM2 module also ships in the production allowlist.
**Fix:** Ship the unit with an empty or placeholder `-P` that the install runbook fills with the resolved path of the one module in use. Optionally, add a smoke step that loads a SoftHSM2 token through the installed unit.

### E-IN-03: TestTPMRestartPersistence has a dead assertion and does not check the ops key

**File:** `test/e2e/tpm_test.go:282-293`
**Issue:** `if after := assertTPMKeys(t, env); len(after) != len(before)` can never fire, because `assertTPMKeys` already fatals unless there are exactly 5 keys (tpm_test.go, `len(keys) != len(roleNames)`). It also compares counts, not keys. The fingerprint check after restart (282-290) covers user, host, machine and log, but not ops. The test still exercises the restart through issuance and audit verify.
**Fix:** `if !maps.Equal(after, before) { t.Fatal("ca-pubkeys.json changed") }`, and add the ops key to the log-line check if serve logs it.

### E-IN-04: The TestPKCS11Ed25519 legacy-agent branch passes on any ssh-add failure

**File:** `test/e2e/pkcs11_test.go:462-470`
**Issue:** On ssh-agent older than 10.1, the test passes when `ssh-add -s` failed for any reason, or when the agent holds zero keys. It does not check that the failure is the Ed25519 unsupported-key refusal. So it only weakly proves that the documented 10.1 minimum is still true. The distro lane's p256 run does exercise the same askpass path, which limits the risk.
**Fix:** Also require the agent or helper log (`a.log.String()` / `a.addOut`) to contain the key-type refusal message that OpenSSH 9.6 emits.

### E-IN-05: The removed-leaf tamper case asserts only the exit code

**File:** `test/e2e/audit_test.go:156`
**Issue:** `code != 1` passes for any failure (parse error, I/O error), not specifically a detected gap or root mismatch. The flipped-leaf case right above (149) does check the reason.
**Fix:** Also assert the expected reason substring (for example `root mismatch` or the index-gap message).

### E-IN-06: The e2e workflows have no guard against an empty test run

**File:** `.github/workflows/e2e.yml:62-63`, `e2e-pkcs11.yml:92-93`, `e2e-tpm.yml:77-78`
**Issue:** If a build-tag rename leaves no files under the tag, `go test -tags X ./test/e2e/...` prints `[no test files]` and exits 0, and the required check passes vacuously. fuzz.sh guards exactly this case (fuzz.sh:42-45); the e2e jobs do not.
**Fix:** After the run, `grep -q -- '^--- PASS: Test' e2e-logs/go-test-*.log || { echo "no e2e tests ran" >&2; exit 1; }`, or count with `go test -json`.

### E-IN-07: merge-gate.sh waits out the whole timeout on a failed check or disabled auto-merge after approval

**File:** `scripts/merge-gate.sh:86-102`
**Issue:** The post-approval loop polls only `state`. A required check failing after approval, or auto-merge being off, gives a 900 s wait and then a generic timeout, instead of an immediate error.
**Fix:** In the loop, also read `autoMergeRequest` and run `bot_gh pr checks "$branch" --required`. Return 1 at once on exit status 1, or when auto-merge is null.

### E-IN-08: The askpass helper embeds `$dir` in single quotes without escaping

**File:** `scripts/softhsm-setup.sh:118-122`
**Issue:** `exec cat '$dir/pin'` breaks, and becomes shell injection inside askpass.sh, if DIR contains a `'`. DIR comes from the test harness (`t.TempDir()`), so this is not exploitable today.
**Fix:** Use `printf 'exec cat %q\n' "$dir/pin"` when writing the file.

### E-IN-09: Minor robustness gaps in build-openssh.sh

**File:** `scripts/build-openssh.sh:81,97`
**Issue:**
- `gpg --import ... 2>/dev/null` under `set -e` exits with no message when the import fails.
- `rm -rf "$PREFIX"` deletes a caller-supplied PREFIX (second argument) without any sanity check. For example, `build-openssh.sh 10.5p1 "$HOME"` would wipe the home directory once verification passes.
**Fix:** Use `gpg ... --import RELEASE_KEY.asc || die "importing RELEASE_KEY.asc failed"`. Refuse a PREFIX that exists without a `.keyroster-build` stamp (`[ ! -e "$PREFIX" ] || [ -f "$STAMP" ] || die "refusing to replace $PREFIX"`).

---

_Reviewed: 2026-10-07_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
