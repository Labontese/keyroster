---
phase: 01-trust-core
plan: 09
subsystem: trust-anchor
tags: [age, scrypt, software-root, root-ceremony, passphrase, x-term, runbook, trust-bundle, custody]

requires:
  - phase: 01-06
    provides: "internal/rootceremony (SignBundle, SignPolicy, Summary, BundleHash), internal/trust (roots.pub, custody rules, VerifyGenesisBundle), keyroster root genesis-policy / root sign --agent-key, keyroster trust verify"
provides:
  - "rootceremony.GenerateRoot, rootceremony.OpenRoot, rootceremony.Root (PublicKey, SignBundle, SignPolicy, Close), rootceremony.ReadPassphrase, rootceremony.ValidatePassphrase"
  - "CLI: keyroster root init --out FILE.age [--passphrase-fd N]; keyroster root sign --key FILE.age [--passphrase-fd N] as the alternative to --agent-key"
  - "Key file format: armored age (scrypt, logN 18) holding an OpenSSH Ed25519 private key, plus FILE.age.pub with comment custody=software"
  - "docs/runbooks/root-ceremony.md (offline single-admin ceremony, software and hardware variants) and docs/runbooks/ceremony-transcript-template.md"
affects: [01-10, 01-13 (doctor flags custody=software roots), 01-14 (homelab ceremony uses the runbook), Phase 3 (root rotation re-runs the ceremony)]

actuals:
  tokens: 14100
  tasks: 2
  commits: 2
plan_head_before: 1c0df9e145e6a98f5c5b4e32a99d0970b95e996a
plan_head_after: cd92f9a34cdd429b3072799066744cc6ce123268

tech-stack:
  added: [filippo.io/age v1.3.2, golang.org/x/term v0.46.0, filippo.io/hpke v0.4.0 (indirect, via age)]
  patterns:
    - "A root key object exposes only typed signing methods (SignBundle, SignPolicy); TestExportedAPI pins every exported identifier including methods and fails if any exported result type is a signer, private key, crypto.* or interface value"
    - "Secrets come only from a terminal (echo off) or an inherited descriptor read with syscall.Read; no *os.File wraps a descriptor the package does not own"
    - "Custody labels are enforced, not just displayed: --key refuses a root that roots.pub labels anything but software, and every software-root create or sign prints the SOFTWARE ROOT banner"

key-files:
  created:
    - internal/rootceremony/keygen.go
    - internal/rootceremony/passphrase.go
    - internal/rootceremony/readfd_unix.go
    - internal/rootceremony/readfd_windows.go
    - internal/rootceremony/readfd_other.go
    - internal/rootceremony/keygen_test.go
    - docs/runbooks/root-ceremony.md
    - docs/runbooks/ceremony-transcript-template.md
  modified:
    - go.mod
    - go.sum
    - internal/rootceremony/imports_test.go
    - internal/rootceremony/sign.go
    - cmd/keyroster/root.go
    - cmd/keyroster/root_test.go

key-decisions:
  - "Software root file = armored age, single scrypt recipient at age's default work factor 2^18 (about 1 s and 256 MiB per encrypt or decrypt), wrapping an OpenSSH-format Ed25519 key with comment 'keyroster root'; OpenRoot refuses unarmored files, non-scrypt recipients and any non-Ed25519 key"
  - "--passphrase-fd reads one line with syscall.Read (Unix) / syscall.Read on the handle (Windows), byte by byte so nothing past the line is consumed; the descriptor is left open for its owner (os.NewFile would attach a finalizer that closes it)"
  - "Passphrase minimum is 20 Unicode code points and must be valid UTF-8; GenerateRoot validates too, not only the CLI"
  - "root sign --key decrypts before the summary (the fingerprint is known only after decryption), then checks custody=software in roots.pub, then refuses a repeat signature, then asks for the hash prefix"
  - "Exactly one of --key and --agent-key, and --passphrase-fd only with --key, are usage errors (exit 2); a custody mismatch or wrong passphrase is a refusal (exit 1) that writes no signature"

patterns-established:
  - "documentSigner interface in cmd/keyroster: *rootceremony.Root and an agentRoot adapter both sign only bundles and policies, so root sign has one signing path for both custody kinds"
  - "CLI passphrase tests pass secrets through os.Pipe descriptors (--passphrase-fd); the confirmation prompt is answered by a reader that hashes bundle.json lazily, so no throwaway sign run is needed"

requirements-completed: [KEY-07]

coverage:
  - id: D1
    description: "keyroster root init writes an armored age (scrypt) Ed25519 root with mode 0600 via O_EXCL, a .pub ending in custody=software, the SOFTWARE ROOT banner on stderr and the SHA256 fingerprint on stdout; root sign --key A at threshold 1 then trust verify --pin A --pin B reports 1 of 2"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestSoftwareRoot (Windows; WSL and CI build-test on Linux assert mode 0600)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Refusals: wrong passphrase (no signature file changes), 19-character passphrase, existing FILE.age or leftover FILE.age.pub, --key for a root labelled piv or fido, --key with --agent-key / neither / --passphrase-fd without --key, a --passphrase flag; OpenRoot refuses ECDSA keys, unarmored and X25519-encrypted files"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestSoftwareRoot/{wrong_passphrase,short_passphrase,existing_output,custody_mismatch,key_and_agent_key}; internal/rootceremony/keygen_test.go#TestOpenRootRefusals, #TestValidatePassphrase, #TestReadPassphraseFD, #TestReadPassphraseNeedsTerminal"
        status: pass
    human_judgment: false
  - id: D3
    description: "Two-root 1-of-2 ceremony: both roots sign (2 of 2), a bundle signed by root B alone verifies (1 of 2), a third unrelated key's signature is reported as ignored and alone does not meet the threshold"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestSoftwareRoot/{two_roots_both_sign,one_of_two_root_b_only,unrelated_root_ignored}"
        status: pass
    human_judgment: false
  - id: D4
    description: "No exported rootceremony function or method returns a signer or private key; the package still cannot reach internal/cert, internal/signer or internal/keystore; Close zeroes the key and a closed Root cannot sign"
    requirement: KEY-07
    verification:
      - kind: unit
        ref: "internal/rootceremony/imports_test.go#TestExportedAPI, #TestRootCannotReachCertificateSigning; keygen_test.go#TestGenerateOpenRoot"
        status: pass
    human_judgment: false
  - id: D5
    description: "docs/runbooks/root-ceremony.md lets one admin run the offline ceremony (lo-only network check, reproducible binary hash on a second machine, both roots sign, install-bundle with paper pins, storage) and covers the FIDO2/PIV hardware variant; the transcript template records hashes, date and operator and never secrets"
    requirement: KEY-07
    verification:
      - kind: other
        ref: "grep -q 'ip -br link' / 'custody=fido' / 'install-bundle' docs/runbooks/root-ceremony.md; grep 'never' docs/runbooks/ceremony-transcript-template.md"
        status: pass
    human_judgment: true
    rationale: "Whether a single admin can follow the runbook safely is a judgment the owner makes on review (and in practice in the 01-14 homelab ceremony); grep only proves the required steps are present"
  - id: D6
    description: "PR #9 is green on every required check and waits for the owner at the merge gate"
    requirement: KEY-07
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks p01/09-software-roots --required --watch on cd92f9a: build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz all pass (build-test after one rerun, see Issues)"
        status: pass
    human_judgment: true
    rationale: "Owner approval and the squash merge happen at the Task 3 blocking-human merge gate, after this SUMMARY is written"

duration: 30min
completed: 2026-10-05
status: complete
---

# Phase 1 Plan 09: Software Roots Summary

**`keyroster root init` creates an Ed25519 root in an armored age file (scrypt, work factor 2^18, mode 0600, never overwriting) with a `custody=software` public key. `keyroster root sign --key` decrypts it in memory only and signs bundles and policies through a `rootceremony.Root` that exposes no signer. Two such roots at threshold 1 give a bundle that verifies with either root. Every software-root create or sign prints a `SOFTWARE ROOT:` banner, `--key` refuses a root labelled as hardware, and a runbook covers the offline single-admin ceremony.**

## Performance

- **Duration:** about 30 min
- **Started:** 2026-10-05T11:54:46Z
- **Completed:** 2026-10-05T12:24Z (SUMMARY; the docs commit follows)
- **Tasks:** 2 of 3 executed before the merge gate (Task 3 is the owner's approval)
- **Files modified:** 14 (8 created, 6 modified), 1542 insertions, 40 deletions

## Accomplishments

- **Task 1 (tracer):** `rootceremony.GenerateRoot`/`OpenRoot`/`Root`, `ReadPassphrase`/`ValidatePassphrase`, `keyroster root init`, `root sign --key`, the exported-API test extended to methods and result types, and `TestSoftwareRoot` (init A and B, `roots.pub`, sign with A at threshold 1, `trust verify` reports 1 of 2). The tracer feedback gate (`end-of-phase`, automated-only verify) re-ran both verify commands green on Windows and in WSL (also under `-race`), so expansion continued.
- **Task 2:** the refusal subtests and the two-root flow, `rootceremony` unit tests, the runbook and the transcript template. The branch is pushed and PR #9 is open with auto-merge (squash) enabled by keyroster-bot. All required checks are green.

## PR

- **PR #9** `feat(root): add age-encrypted software trust roots and ceremony runbook` (https://github.com/Labontese/keyroster/pull/9), branch `p01/09-software-roots`, opened by keyroster-bot. Auto-merge (squash) is enabled.
- Both implementation commits show `verified: true` on GitHub (keyroster-bot signature).
- PR #8 (01-07) is still open and also changes STATE.md, ROADMAP.md and REQUIREMENTS.md. Whichever PR merges second gets rebased by `scripts/merge-gate.sh`; for `.planning/` conflicts take `origin/main` and re-apply this plan's entries. The two PRs touch no common code file. `useKeyring` in `cmd/keyroster/root_test.go`, which PR #8's `ca_test.go` uses, is unchanged.

## Recorded Facts

| Item | Value |
|---|---|
| age work factor | scrypt logN 18 (age's default, `NewScryptRecipient` without `SetWorkFactor`); `OpenRoot` accepts age's default maximum logN 22 |
| Key file | `-----BEGIN AGE ENCRYPTED FILE-----` armor, one scrypt stanza, plaintext = PEM `OPENSSH PRIVATE KEY` (Ed25519, comment `keyroster root`), at most 16 KiB accepted on decrypt |
| `.pub` file | `trust.FormatKey(pub) + " custody=software\n"`, mode 0644, O_EXCL |
| Passphrase rules | at least 20 runes, valid UTF-8, at most 1024 bytes on a descriptor; trailing `\r\n` or `\n` dropped |
| Test cost | scrypt costs about 0.7 s per run natively and about 6 s under `-race`; CI build-test on cd92f9a: `cmd/keyroster` 49.9 s, `internal/rootceremony` 24.6 s (race) |
| Modules | `filippo.io/age v1.3.2`, `golang.org/x/term v0.46.0` (direct); `filippo.io/hpke v0.4.0` (indirect); go.sum also records `c2sp.org/CCTV/age` (age's test vectors; not built into any binary) |
| govulncheck | no reachable vulnerabilities (the only module-level finding is GO-2026-5932, `x/crypto/openpgp`, not imported; it predates this plan) |

## Task Commits

1. **Task 1: end-to-end root init → root sign --key → trust verify (tracer).** `54ed378` (feat)
2. **Task 2: refusals, two-root 1-of-2 ceremony, runbook, transcript template, PR.** `cd92f9a` (test)
3. **Task 3: merge gate.** No commit (the owner approves; GitHub squash-merges)

**Plan metadata:** the `docs(01-09): complete software roots plan` commit on the same PR branch.

## Files Created/Modified

- `internal/rootceremony/keygen.go`: `GenerateRoot`, `OpenRoot`, `Root` (`PublicKey`, `SignBundle`, `SignPolicy`, `Close`)
- `internal/rootceremony/passphrase.go`: `ReadPassphrase` (TTY or descriptor), `ValidatePassphrase`
- `internal/rootceremony/readfd_{unix,windows,other}.go`: descriptor reads without `*os.File`
- `internal/rootceremony/imports_test.go`: exported API pinned with methods; no exported signer or key results
- `internal/rootceremony/keygen_test.go`: round trip, `Close`, `OpenRoot` refusals, passphrase rules, descriptor input
- `internal/rootceremony/sign.go`: package doc lists the new API
- `cmd/keyroster/root.go`: `root init`; `root sign --key/--passphrase-fd`; custody check; banner; `documentSigner`; `writeExclusive`
- `cmd/keyroster/root_test.go`: `newCeremonyInputs` split out of `newCeremony`; `TestSoftwareRoot` with nine subtests; banner check on the agent path
- `docs/runbooks/root-ceremony.md`, `docs/runbooks/ceremony-transcript-template.md`
- `go.mod`, `go.sum`

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] `TestExportedAPI` would not have caught a method that leaks the signer**
- **Found during:** Task 1
- **Issue:** the 01-06 test collected exported function names only, so `Root`'s methods either broke the allowlist or, once allowed, any new method (for example `Signer()`) would have passed unnoticed. The truth "no exported rootceremony function returns a general-purpose signer" needs the result types checked.
- **Fix:** the test records methods as `Type.Method`, pins the full list, and fails if any exported function or method returns a type mentioning `Signer`, `PrivateKey`, `crypto.`, `ed25519.`, `any` or `interface`.
- **Files modified:** internal/rootceremony/imports_test.go
- **Committed in:** `54ed378`

**2. [Rule 1 - Bug avoided] Descriptor input does not use `os.NewFile`**
- **Found during:** Task 1
- **Issue:** the plan said to read `--passphrase-fd` through `os.NewFile(uintptr(fd), ...)`. That `*os.File` gets a finalizer that closes the descriptor when collected. In tests it would close a descriptor the test's own `*os.File` still owns, or a reused descriptor number, which is a flaky double close.
- **Fix:** `readFD` calls `syscall.Read` on the raw descriptor (Unix) or handle (Windows), and a fallback file returns an error on other platforms. The descriptor stays owned by the caller.
- **Files modified:** internal/rootceremony/readfd_*.go, passphrase.go
- **Committed in:** `54ed378`

### Additions beyond the plan (documented interpretations)

- `GenerateRoot` validates the passphrase itself (not only the CLI), and `ValidatePassphrase` also refuses invalid UTF-8.
- `root init` also refuses when only `FILE.age.pub` exists, and removes `FILE.age` if writing the `.pub` fails, so a key never exists without its custody label.
- `root sign` refuses `--passphrase-fd` without `--key`. The banner check was added to the existing agent round trip test, and the custody-mismatch case covers `piv` (refused by the new custody check) and `fido` (refused by `roots.pub` parsing, since `fido` is for `sk-*` keys only).
- The runbook uses `ed25519-sk` with `-O resident -O verify-required`, so a later ceremony recovers the key handle with `ssh-keygen -K` instead of relying on a handle file in the live system's RAM.

---

**Total deviations:** 2 auto-fixed (1 Rule 2, 1 Rule 1). **Impact:** both protect plan truths (no signer leak, reliable descriptor input). No scope creep.

## Issues Encountered

- **CI flake outside this plan's files:** the first `build-test` run on PR #9 failed in `internal/signer` `TestSignerRefusals/created_301s_future`. The test captures `now` once and checks the ±300 s skew bound with `now + 301`, so it fails whenever more than about a second passes before that subtest runs. The new scrypt-heavy tests running in parallel packages under `-race` make that more likely. A rerun of the failed job passed. It is logged in `deferred-items.md` with a proposed fix (a fixed test clock). It was not fixed here because `internal/signer/*` belongs to 01-07 (PR #8, open).
- `go mod tidy` added `c2sp.org/CCTV/age` to go.sum (age's test-vector module). It is not compiled into any keyroster package.
- Bash heredocs containing Go raw strings broke in the Git Bash tool, so multi-line edits ran as Python scripts in the scratchpad.

## Known Stubs

None.

## User Setup Required

None. The owner only approves PR #9 at the merge gate.

## Next Phase Readiness

- 01-10 and 01-14 can run the homelab ceremony from `docs/runbooks/root-ceremony.md`. `keyroster-signer ca-init`/`install-bundle`, which the runbook names, arrive with 01-07 (PR #8).
- 01-13 (`doctor`) should flag roots with `custody=software` in the installed bundle. The runbook already promises this.
- KEY-07 is shared with 01-07, 01-10 and 01-14, so GSD's shared-ID gate keeps it Pending in REQUIREMENTS.md until the last of those plans completes.
- Deferred: the `TestSignerRefusals` timing flake (see `deferred-items.md`).

## Self-Check: PASSED

- Files present: all 8 `key-files.created` and 6 `modified` (`git diff --stat 1c0df9e..cd92f9a`: 14 files).
- Commits on `origin/p01/09-software-roots`: `54ed378`, `cd92f9a`, both `verified: true`. `git rev-list --count 1c0df9e..HEAD` = 2 before the docs commit.
- Acceptance: `go.mod` requires `filippo.io/age v1.3.2` and `golang.org/x/term v0.46.0`. The init output starts with `-----BEGIN AGE ENCRYPTED FILE-----`, and mode 0600 is asserted on Linux (WSL run and CI). `.pub` ends with ` custody=software`. There is no `--passphrase` flag (the test asserts exit 2), and no `Getenv` exists for passphrases. `root_test.go` has `wrong_passphrase`, `short_passphrase`, `existing_output`, `custody_mismatch` and `one_of_two_root_b_only`. The transcript template says passphrases are never recorded.
- Plan verify commands: `go test -count=1 ./internal/rootceremony/... ./cmd/keyroster/...` passes on Windows and WSL (and with `-race` in WSL). `-run SoftwareRoot -v` prints `--- PASS: TestSoftwareRoot`. The runbook greps pass. The required checks are green on cd92f9a.
