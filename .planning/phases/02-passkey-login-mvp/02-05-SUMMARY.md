---
phase: 02-passkey-login-mvp
plan: 05
subsystem: signer
tags: [keystore, software-key, age, scrypt, status, custody, d-18, key-06, capslock, cli-banner]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-03: per-type frame caps (maxBodyFor, RequestCaps, ResponseCaps), checkTrustCurrent/trust_changed, the refusal paths; 02-01..02-04 merged (#33-#36, #38, #39)"
provides:
  - "keystore backend software (KEY-06): five Ed25519 keys as armored age files (one scrypt recipient, age's default work factor) in {state-dir}/software/{role}.age, 0600 in 0700; passphrase from passphrase-file or $CREDENTIALS_DIRECTORY/keyroster-software-passphrase only"
  - "wire Status (0x04, empty body) -> StatusResponse (0x84): keys (role, alg, custody, fingerprint), bundle version, bundle, bundle sigs, policy, policy sigs, directory version, SHA-256 and authorized; MaxStatusFrame 256 KiB, ErrStatusTooLarge, ParseStatusResponse"
  - "Signer.Status (custody from the signer, D-18), statusOrRefuse, the shared statusResponse encoder, and InstallBundle's Status-budget refusal"
  - "signerclient.Status"
  - "internal/custodytext: SoftwareCABanner (owner-approved wording) and SoftwareRoles; keyroster ca issue prints the framed banner from Status"
  - "docs/security/custody.md section Software CA keys (KEY-06), quoting the banner verbatim (test-enforced)"
affects: [02-06, 02-08, 02-12, 02-13, KEY-06]

actuals:
  tokens: 22600   # chars/4 over the added lines of the code, test and docs diff (90580 chars); planning docs excluded
  tasks: 2        # Task 1 and Task 3 executed; Task 2 was the owner's decision checkpoint, Task 4 is the owner merge gate
  commits: 5      # git rev-list --count plan_head_before..HEAD at SUMMARY write; this docs commit follows
plan_head_before: 3bd2f6f94f2c3a9690267873c032c9d79a410010
plan_head_after: e959951bd1a61648188d5498ff8ca4960ecb4dba

tech-stack:
  added: []   # filippo.io/age v1.3.2 was already in go.mod (rootceremony); it now also enters the signer graph
  patterns:
    - "Custody is reported by the signer over Status and nowhere else; UI text lives in one constant (internal/custodytext) that the signer never imports"
    - "Install and Status share one encoder and one limit (statusResponse + Marshal), so an accepted trust state is always reportable"
    - "A read-only signer message checks the loaded trust version (checkTrustCurrent) on the same row it reports"

key-files:
  created:
    - internal/keystore/software/software.go
    - internal/keystore/software/software_test.go
    - internal/wire/status.go
    - internal/wire/status_test.go
    - internal/signer/status.go
    - internal/signer/status_test.go
    - internal/custodytext/custodytext.go
    - internal/custodytext/custodytext_test.go
    - test/e2e/software_test.go
  modified:
    - cmd/keyroster-signer/backends_linux.go
    - internal/wire/frame.go
    - internal/wire/fuzz_test.go
    - internal/signer/server.go
    - internal/signer/trust.go
    - internal/signer/signer.go
    - internal/signer/trust_test.go
    - internal/signerclient/client.go
    - cmd/keyroster/ca.go
    - docs/security/custody.md
    - test/capslock/keyroster-signer.json
    - .planning/phases/01-trust-core/deferred-items.md
    - .planning/phases/02-passkey-login-mvp/deferred-items.md

key-decisions:
  - "Owner decision A (2026-10-18): the KEY-06 banner names a compromised signer host; five lines, at most 76 columns with all five roles"
  - "Owner decision B (2026-10-18): the capslock baseline takes 19 new pairs; the 11 outside the plan's allowed list are capslock over-approximations (age's func-typed WriterFunc, error-interface dispatch), not new capabilities; the plan's 'any other new pair is a defect' rule is overridden for exactly these"
  - "The software backend reads the passphrase again for open, every Provision and every Key call and keeps no copy; Status and the issuance after it cannot disagree about custody without a restart"
  - "A Status request with a body is refused malformed_request; Status sizes its reply itself, so an oversize trust state is reported as wire.ErrStatusTooLarge"
  - "requirements-completed is empty: KEY-06 completes in 02-06, when the UI banner exists"

patterns-established:
  - "Bite tests for suites that are green on their first run: one mutant per guarded check, production files restored byte for byte"

requirements-completed: []

coverage:
  - id: D1
    description: "ca-init --backend software creates five Ed25519 keys as armored age files (0600 in 0700) recorded custody software in ca-pubkeys.json and the bundle; serve runs on them; ca issue gets a certificate real sshd accepts; doctor warns software_key; Status reports custody software and exactly the installed bundle; the agent-backend control prints no banner"
    requirement: KEY-06
    verification:
      - kind: e2e
        ref: "test/e2e/software_test.go#TestSoftwareCAEndToEnd (WSL, sshd 10.5p1 and 9.5p1; full suite 20/20 on each)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Backend refusal matrix: passphrase file readable by group or others, 19 characters (counted in runes), no source, wrong passphrase not echoed, truncated or edited key file, fingerprint mismatch, existing files left unchanged, permissive or symlinked key directory, cleanup after a failed directory sync, non-private or symlinked key file, unknown option; success through passphrase-file and CREDENTIALS_DIRECTORY with signatures that verify; the production scrypt work factor pinned"
    requirement: KEY-06
    verification:
      - kind: unit
        ref: "internal/keystore/software/software_test.go#TestSoftwareBackend, TestScryptWorkFactorIsAgeDefault (go test -race, WSL)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Status codec and caps: round trip, trailing byte, truncation, more than 8 keys, no keys, Authorized above 1, one encoding without a directory; frame at MaxStatusFrame round-trips, MaxStatusFrame+1 refused before the body (6 bytes read) and with nothing written; Marshal refuses MaxStatusFrame-1 and accepts MaxStatusFrame-2; RequestCaps keeps Status types at MaxFrame; fuzzed"
    verification:
      - kind: unit
        ref: "internal/wire/status_test.go#TestStatusResponseCodec, TestStatusFrameCaps, FuzzParseStatusResponse; internal/wire/fuzz_test.go#FuzzReadMessage (FUZZTIME=5s scripts/fuzz.sh: all 21 targets passed)"
        status: pass
    human_judgment: false
  - id: D4
    description: "One budget for install and Status: InstallBundle refuses a would-be Status body of MaxStatusFrame-1 (ErrBundleInstall wrapping ErrStatusTooLarge, nothing stored, no leaf) and lets one of MaxStatusFrame-2 through to signature parsing"
    verification:
      - kind: unit
        ref: "internal/signer/trust_test.go#TestInstallBundleRefusals/status_budget_exceeded, /status_budget_at_limit_not_size_refused"
        status: pass
    human_judgment: false
  - id: D5
    description: "Status under a changed bundle through the real socket: version 1 before a foreign install, two trust_changed ErrorResponses (unavailable) after it with a refusal record of 2 (1 leaf + 1 summary count), version 2 after a restart; a Status request with a body is refused malformed_request and logged; Status carries the directory version, hash and authorization"
    verification:
      - kind: unit
        ref: "internal/signer/status_test.go#TestStatusTrustChanged, TestStatusOverSocket, TestStatusReportsDirectory (go test -race, WSL)"
        status: pass
    human_judgment: false
  - id: D6
    description: "The owner-approved banner is one constant, quoted verbatim in custody.md, fits 76 columns, and ca issue prints it framed on stderr before issuing"
    requirement: KEY-06
    verification:
      - kind: unit
        ref: "internal/custodytext/custodytext_test.go#TestSoftwareCABanner (owner_approved_wording, custody_md_quotes_it_verbatim, banner_fits_terminal), TestSoftwareRoles"
        status: pass
      - kind: e2e
        ref: "test/e2e/software_test.go#TestSoftwareCAEndToEnd (exact framed banner on ca issue stderr)"
        status: pass
    human_judgment: false
  - id: D7
    description: "capslock baseline reviewed per pair and updated; piv target re-deferred"
    verification:
      - kind: other
        ref: "bash scripts/capslock-check.sh: 90 pairs, baseline 90; bash scripts/dep-firewall.sh: clean"
        status: pass
    human_judgment: true
    rationale: "The owner accepted 11 pairs as capslock over-approximations; two causes are UNVERIFIED (see the capslock section), so a reviewer should confirm the classification"

duration: 45min
completed: 2026-10-18
status: complete
---

# Phase 2 Plan 05: Software CA Keys Summary

**keyroster now runs with no hardware at all: `ca-init --backend software` keeps the five online keys in age-encrypted files, the signer reports every key's custody itself over a new Status message, and every `keyroster ca issue` on such a signer prints the owner-approved evaluation-only banner before it issues.**

## Performance

- **Duration:** about 45 min of execution: Task 1 2026-10-17T17:00Z to 17:19Z, then the owner's decisions, then Task 3 2026-10-18T09:45Z to about 10:10Z.
- **Tasks:** Task 1 (tracer) and Task 3 (TDD) executed. Task 2 was the owner's decision checkpoint. Task 4 is the owner's merge gate.
- **Files modified:** 22 code, test and docs files, plus planning docs.

## Delivery

- **Branch:** `p02/05-software-key`, cut from origin/main `87608c4`. It also carries the orchestrator's `3bd2f6f docs(phase-02): mark 02-04 complete in roadmap`.
- **PR:** opened by keyroster-bot after the single push that carries this SUMMARY, titled `feat(signer): encrypted software CA keys with an evaluation-only warning`. Its number and check results are reported in the merge-gate checkpoint, not committed (Delivery Protocol step 4; the same order as 02-03, Deviation 7 there).
- **Commits:** all SSH-signed by keyroster-bot. Locally `%G?` shows N because no allowedSignersFile is configured; GitHub verifies them.

## Owner decisions at the Task 2 checkpoint (verbatim, 2026-10-18)

**Decision A: edit.** "Use exactly this banner text, five lines, from custodytext.SoftwareCABanner with all five roles:

```
EVALUATION ONLY - SOFTWARE CA KEY: the user, host, machine, ops, log keys
of this keyroster signer are software keys (custody software). Anyone who
copies the key files and their passphrase, or controls the signer host,
can issue certificates. Do not use this instance for real access
(docs/security/custody.md).
```

Keep the roles placeholder. Lines 1-2 are unchanged. Line 3 becomes "copies the key files and their passphrase, or controls the signer host," (71 columns), line 4 "can issue certificates. Do not use this instance for real access" (64 columns), line 5 "(docs/security/custody.md)." All five lines stay at or under 76 columns with all roles filled in. The reason: project rule that the software level must state what it does not protect against, here a compromised signer host. [...] If a single role renders as "the user keys", leave that as it is; a software ca-init always creates all five."

The constant is exactly that text. `owner_approved_wording` compares it byte for byte, and custody.md quotes it.

**Decision B: accept.** "Run the capslock `--update` in Task 3. [...] record that the owner overrode the plan's 'any other new pair is a defect' rule for these 11 pairs on 2026-10-18, because they are capslock over-approximations (age's func-typed WriterFunc and the error-interface dispatch to os/signal.signalError) and not new capabilities; keep the internal/trust UNANALYZED cause and the MODIFY_SYSTEM_STATE widening labelled UNVERIFIED. Add a deferred item that capslock pair diffs are noisy around func-typed writers and error dispatch."

## Accomplishments

- **Software backend (KEY-06).**
  - `internal/keystore/software` (`//go:build linux`) registers `software` with the one option `passphrase-file`.
  - **Provision** mirrors the TPM backend's provisioning. The helpers are copied, not imported, and rootceremony is not imported (KEY-07). Provision:
    - creates the key directory 0700 and checks it even when it already exists (it must be a directory, not a symlink, with no group or other bits);
    - refuses if any `.age` file is present, if a role is given twice, or if any target already exists;
    - generates each key with crypto/rand and encrypts it in memory;
    - writes with O_EXCL, mode 0600, and syncs each file;
    - writes all files or none (`removeWritten`), then syncs the key directory, and the state directory too when it created the key directory (`syncDir`).
  - **Key** reads only a private regular file in a private directory (16 KiB cap). It decrypts through `armor.NewReader` with a bounded plaintext, requires an Ed25519 key with the pinned fingerprint, and returns custody `software` and algorithm `ssh-ed25519`.
  - **The passphrase** is read into a []byte and cleared with `defer clear` at every read site (open, Provision, Key); no copy is kept between calls. The string copy that age's scrypt API takes cannot be cleared; a comment says so (best effort).
  - **Close** zeroes the keys Key handed out.
- **Status (D-18).**
  - **Wire format:** `TypeStatus` 0x04 has an empty body. `TypeStatusResponse` 0x84 carries a u8 key count, then four u16 strings per key, the u64 bundle version, four u24 documents, the u64 directory version, a 32-byte hash and the u8 authorized flag.
  - **Size limits:** `maxBodyFor(TypeStatusResponse) = MaxStatusFrame - 2`. Marshal refuses anything above that with `ErrStatusTooLarge`, which names the body size and the limit.
  - **Signer.Status** reads the latest trust_bundle row once and runs `checkTrustCurrent` on that row's version under `s.mu`. A read error goes to `checkTrustCurrent(0, err)` and the nil row is never touched. It reports the ca-init keys as start-up verified them, plus the directory state.
  - **The handler** reaches Status only through `statusOrRefuse`, which records a refusal through `refuseErr` after `s.mu` is released.
- **One budget for install and Status (02-05-F6).** Right after `db.CAKeys`, before any verification or `lw.logTx`, InstallBundle builds the would-be reply with the same `statusResponse` and `Marshal`. An over-budget reply is refused with `ErrBundleInstall` wrapping `ErrStatusTooLarge`.
- **CLI.**
  - `keyroster ca issue` calls `signerclient.Status` after reading the public key and before building the request.
  - When `custodytext.SoftwareRoles` is non-empty, it writes the banner between two 76-character `!` lines on stderr. No flag, environment variable or configuration suppresses it.
  - A Status failure aborts the command.
- **Docs.** custody.md:
  - points the `software` table row to the new section "Software CA keys (KEY-06)";
  - says what the section does not protect against: a compromised signer host, a passphrase on the same host, and offline guessing of leaked `.age` files, where 20 characters is a length floor and the advice is `openssl rand -base64 32`;
  - covers the passphrase sources, doctor's `WARN software_key`, and the verbatim banner.

## Status layout (the contract for 02-06 and later CLIs)

| Field | Encoding |
|---|---|
| key count | u8, 1 to 8 (`MaxStatusKeys`) |
| per key: role, alg, custody, fingerprint | u16-length-prefixed strings, each 1 to 255 bytes; keys in role order user, host, machine, ops, log |
| bundle version | u64 |
| bundle, bundle signatures, policy, policy signatures | u24-length-prefixed, exactly the trust_bundle row the signer runs on |
| directory version | u64, 0 for none |
| directory SHA-256 | 32 bytes, all zero for none |
| directory authorized | u8 0 or 1, 0 for none |

Strict decode: no trailing bytes and a body of at most MaxStatusFrame - 2. A request with a body is refused `malformed_request`. After a bundle install under the running signer, Status refuses `trust_changed` (code unavailable) until a restart.

## capslock pairs (owner decision B)

`bash scripts/capslock-check.sh --update`: 90 pairs, against 73 before. 19 are new and 2 are gone. The new signer dependencies are age, age/armor, age/internal/{bech32,format,stream}, filippo.io/hpke (+crypto, ecdh, byteorder), x/crypto/{chacha20poly1305,hkdf,pbkdf2,scrypt}, crypto/hkdf, crypto/pbkdf2, x/sys/cpu and the backend. dep-firewall is clean (default and piv passes). The paths come from capslock `-output json` runs that loaded the signer program.

**Inside the plan's allowed list (age module, software backend): 8 pairs.**

| Pair | Class | Path |
|---|---|---|
| filippo.io/age/armor UNANALYZED | allowed, not traced separately | |
| filippo.io/age/internal/format FILES | traced over-approximation | `format.Header.Marshal → WrappedBase64Encoder.Close → base64.encoder.Close → (format.WriterFunc).Write → writeWrapped → bytes.Buffer.WriteTo → (*os.File).Write` |
| filippo.io/age/internal/format NETWORK | traced over-approximation | the same path to `(*net.conn).Write` |
| filippo.io/age/internal/format UNANALYZED | allowed | `format.Parse → headerReader.ReadBytes → bufio.Reader.ReadSlice` |
| internal/keystore/software FILES | real | os.Open, os.Lstat, os.OpenFile, os.Remove |
| internal/keystore/software READ_SYSTEM_STATE | real | `readPassphrase → os.Getenv("CREDENTIALS_DIRECTORY")` |
| internal/keystore/software UNANALYZED | real | io.ReadAll |
| internal/keystore/software ARBITRARY_EXECUTION | over-approximation | `decryptKey → ssh.ParseRawPrivateKey → x509.ParsePKCS8PrivateKey → ecdh → fips140.isBypassed` |

**Outside the plan's list: 11 pairs, accepted by the owner on 2026-10-18.**

| Pair | Class | Path |
|---|---|---|
| internal/trust FILES | traced over-approximation | `trust.ParseKey → FormatKey → ssh.MarshalAuthorizedKey → base64.encoder.Close → (age format.WriterFunc).Write → writeWrapped → bytes.Buffer.WriteTo → (*os.File).Write` |
| internal/trust NETWORK | traced over-approximation | the same path to `(*net.IPConn).Write` |
| golang.org/x/crypto/ssh FILES, NETWORK | traced over-approximation | the same path through `ssh.MarshalAuthorizedKey`. age's `type WriterFunc func([]byte)(int, error)` is a func-typed io.Writer (internal/format/format.go:50-56), so every base64 encoder Close in the program may dispatch into it, and from there to any io.Writer |
| internal/keystore READ_SYSTEM_STATE | real | `keystore.Open → software.open → readPassphrase → os.Getenv` |
| internal/trust MODIFY_SYSTEM_STATE | traced over-approximation | `trust.ParsePolicy → DecodeStrict → json.Decoder.Decode → (os/signal.signalError).Error` |
| internal/audit MODIFY_SYSTEM_STATE | traced over-approximation | `audit.Decode → json.Marshal → json/v2.transformMarshalError → (os/signal.signalError).Error` |
| internal/keystore MODIFY_SYSTEM_STATE | traced over-approximation | `keystore.Open → tpm.open → tpm.Manufacturer → tpm2.GetCapability.Execute → tpm2.execute → (os/signal.signalError).Error` |
| internal/keystore/tpm MODIFY_SYSTEM_STATE | traced over-approximation | `tpm.Inspect → Manufacturer → ... → (os/signal.signalError).Error` |
| github.com/google/go-tpm/tpm2 MODIFY_SYSTEM_STATE | traced over-approximation, sample path | `tpm2 → crypto/ecdh → fips140.PCT → (os/signal.signalError).Error`, from a run that also loaded tpm2 as a target; the exact path in the signer-only graph is not confirmed |
| internal/trust UNANALYZED | **cause UNVERIFIED** | sample path `trust.BuildSuccessor → errors.Is`; why it is new is not traced |

**Gone (they do not fail the check):** internal/keystore/agent UNANALYZED and golang.org/x/crypto/ssh/agent UNANALYZED.

**UNVERIFIED:**
- why adding age widens capslock's type flow, so that existing error-interface calls now reach `(os/signal.signalError).Error` (the MODIFY_SYSTEM_STATE widening). modernc/libc already linked os/signal before this plan, and no new package imports os/signal or os/exec;
- the cause of the internal/trust UNANALYZED pair.

The deferred item "capslock pair diffs are noisy around func-typed writers and error dispatch" is in phase 02 deferred-items.md.

**piv target:** re-deferred in Phase 1's deferred-items.md (the 01-13 entry). Two reasons: its baseline needs `libpcsclite-dev`, which WSL lacks and which needs sudo to install; and it changes the definition of a required job, so it belongs in its own CI plan. It moves to the Phase 6 review list.

## Task Commits

1. **Task 1: tracer.** `c874e3e` (feat). Tracer gate: the e2e verify was re-run on the committed head and passed. The task carries `gate` nothing and its verify is automated only, so it continued to the planned decision checkpoint.
2. **Task 2: owner decision checkpoint.** No commit. Decisions A and B are above.
3. **Task 3: TDD.**
   - `84cf5ea` (test, RED)
   - `4cf0e67` (feat, GREEN: the constant, custody.md, the e2e banner assertion)
   - `45188d8` (chore: the capslock baseline and the deferred items)
   - `e959951` (test: gosec in the new tests)
4. **Task 4: merge gate.** Not attempted. It is the owner's `checkpoint:human-action`.

**Plan metadata:** `docs(02-05): complete software-key plan` (this file, STATE.md).

## TDD record (Task 3, tdd="true"; workflow.tdd_mode is false, so the gate sequence is advisory)

- **RED (`84cf5ea`).** `go test -count=1 ./internal/custodytext/` failed in exactly two subtests:
  - `TestSoftwareCABanner/owner_approved_wording` (the constant still held the Task 1 wording);
  - `TestSoftwareCABanner/custody_md_quotes_it_verbatim` (custody.md had no section yet).
  - Semantic assessment: the target assertions failed for the planned reason, which is that the behaviour (approved wording, quoted doc) was missing. It was not a compile, fixture or setup failure. The GSD classifier has no Go adapter, so this is a recorded assessment, not a classifier verdict.
- **GREEN (`4cf0e67`).** The same command passes, and so does the e2e with the exact framed banner.
- **Unexpected green, recorded and not dressed up as RED.** Every other Task 3 suite passed on its first run, because Task 1 (the tracer) had built the code: TestSoftwareBackend, TestStatusResponseCodec, TestStatusFrameCaps, TestStatusTrustChanged, TestStatusOverSocket, TestStatusReportsDirectory and the two budget cases. **Bite tests** show that each suite depends on the check it guards. One mutant per check was run, and all 8 were killed. Production files were restored, with `git diff --quiet` clean afterwards.

  | Mutant | Killed by |
  |---|---|
  | budget check disabled in InstallBundle | `status_budget_exceeded` |
  | statusOrRefuse returns the ErrorResponse without refuseErr | TestStatusTrustChanged (refusal record 0) |
  | Status checks `s.bundleVersion` instead of the row | TestStatusTrustChanged |
  | `maxBodyFor(TypeStatusResponse)` back to MaxFrame | `status_frame_at_budget_round_trips`, `caps_of_status_types` |
  | passphrase-file mode check removed | `passphrase_file_world_readable` |
  | `removeWritten` dropped on a sync failure | `provision_cleans_up_on_failure` |
  | length floor lowered to 19 | `passphrase_too_short` |
  | regular-file check removed from readPrivateFile | `key_file_not_private_refused` |

## Verification run

| Check | Where | Result |
|---|---|---|
| Task 1 verify: e2e `TestSoftwareCAEndToEnd\|TestTrustFlowEndToEnd`, sshd 10.5p1 | WSL | PASS before and after the commit, and again after GREEN |
| Task 1 verify: `go test -race` keystore/..., signer/..., wire/..., custodytext/..., cmd/keyroster/... | WSL | PASS, no DATA RACE |
| Task 3 verify 1: `go test -count=1 -v ./internal/custodytext/... ./internal/wire/...` | Windows | PASS; the three named TestStatusFrameCaps PASS lines are present |
| Task 3 verify 2: `go test -race -v -run "TestInstallBundleRefusals\|TestSoftware\|TestStatusTrustChanged"` signer and software | WSL | PASS; `status_budget_exceeded`, `TestStatusTrustChanged` and `provision_cleans_up_on_failure` are in the PASS lines; no DATA RACE |
| Task 3 verify 3: `go test -race ./...`, `go vet ./...`, `go vet -tags e2e`, gofmt (GOROOT gofmt on PATH, from a script file), golangci-lint, capslock-check, dep-firewall | WSL | all pass; lint 0 issues for linux, windows and darwin (after `e959951`); capslock 90/90; testonly-firewall clean |
| Full e2e suite (`-tags e2e`) | WSL | sshd 10.5p1: 20 PASS, 0 FAIL, 0 SKIP; **sshd 9.5p1: 20 PASS, 0 FAIL, 0 SKIP** (run locally this time) |
| `FUZZTIME=5s bash scripts/fuzz.sh` | WSL | `fuzz: all 21 targets passed (5s each)`, FuzzParseStatusResponse included |
| `go test -count=1 ./...`, `go vet` for darwin and windows | Windows | PASS |
| Task 3 verify 4 (the SUMMARY on the pushed head) and 5 (required checks) | GitHub | after the push; reported in the merge-gate checkpoint |

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Scope] internal/wire/fuzz_test.go edited (outside the plan's file list)**
- **Issue:** the environment facts require Status to be wired into the cap sets' fuzz targets.
- **Fix:** FuzzReadMessage gains `ResponseCaps(TypeStatusResponse)` as a fourth cap set and three seeds (a frame at MaxStatusFrame, one at MaxStatusFrame + 1, an empty Status request). wire_test.go is unchanged.
- **Committed in:** c874e3e

**2. [Rule 3 - Test speed] Unexported `scryptWorkFactor` package variable**
- **Issue:** age's default work factor (2^18, about 1 s and 256 MiB per operation) would make the `-race` refusal matrix very slow.
- **Fix:** Provision encrypts with `scryptWorkFactor`, where 0 means age's default; only tests lower it (`fastScrypt`). `TestScryptWorkFactorIsAgeDefault` pins 0. e2e runs at the production default.
- **Committed in:** c874e3e, 84cf5ea

**3. [Interpretation] open() also reads the passphrase once**
- So a missing, short or permissive passphrase fails at open. Provision and every Key call read it again, as planned, and nothing is kept.
- **Committed in:** c874e3e

**4. [Interpretation] The Signer keeps the verified ca-init keys (`caKeys`)**
- The Signer held only the CA keys and the log key, not the ops key's record. Status needs all five records as start-up verified them through openRoleKey.
- This is fixed-at-start state, not new persistent state.
- **Committed in:** c874e3e

**5. [Rule 2] A Status request with a body is refused `malformed_request`**
- Same as GetDirectory. Tested in `TestStatusOverSocket`, with a refusal leaf and a control.
- **Committed in:** c874e3e, 84cf5ea

**6. [Rule 1] Status runs Marshal itself**
- Without this, an oversize trust state would surface as `response_encoding` from `respond()` rather than as `wire.ErrStatusTooLarge`. It is now the Status error, recorded as internal_error by statusOrRefuse.
- **Committed in:** c874e3e

**7. [Interpretation] Strict-decode rules beyond the plan's list**
- 1 to 8 keys;
- each key field non-empty and at most 255 bytes;
- Authorized 0 or 1;
- directory version 0 has one encoding (zero hash, not authorized), as with GetDirectory;
- a body above MaxStatusFrame - 2 is refused.
- **Committed in:** c874e3e

**8. [Interpretation] The mode check applies to the operator's file only**
- The passphrase-file must have no group or other bits. The systemd credential file must only be a regular file, per the plan's wording ("For an operator file").
- **Committed in:** c874e3e
- **Narrowed by the pre-merge review fixes (5cae667):** the credential must now also have no other bits. Group bits stay allowed, so must-have truth 2 ("refuses ... a passphrase file readable by group or others") still holds in full only for the passphrase-file option. The plan is left unedited, and custody.md states both rules.

**9. [Rule 2] Close zeroes the private keys Key handed out (best effort)**
- **Committed in:** c874e3e

**10. [Rule 2] The backend applies cert.CheckCAKey and a 16 KiB key-file cap, as the TPM backend does**
- **Committed in:** c874e3e

**11. [Owner decision A] The banner is five lines, not four**
- The plan's Task 1 text had four lines. The owner's edit adds "or controls the signer host" and moves the doc path onto line 5. The plan's constraints still hold: the grep phrase is unbroken on line 1, each line is at most 76 columns, the roles placeholder is kept, and so is the doc path.
- **Committed in:** 4cf0e67

**12. [Owner decision B] The capslock baseline takes 11 pairs outside the plan's allowed list**
- See the capslock section above.
- **Committed in:** 45188d8

**13. [Scope] Extra tests and files**
- `TestStatusOverSocket` and `TestStatusReportsDirectory` were added beside `TestStatusTrustChanged`.
- The e2e imports internal/custodytext to require the exact framed banner.
- Phase 02's deferred-items.md gains the capslock-noise entry (owner decision B).
- **Committed in:** 84cf5ea, 4cf0e67, 45188d8

**14. [Rule 3 - Lint] gosec G302 and G602 in the new tests**
- G302: a `//nolint:gosec` with a reason on the three intentional permissive chmods.
- G602: the SoftwareRoles cases now take role and custody pairs.
- **Committed in:** e959951

**15. [Process] The SUMMARY precedes the push**
- It therefore cannot name the PR number or check results; those are reported in the merge-gate checkpoint (Delivery Protocol step 4).

---

**Total deviations:** 15. Ten are interpretations, robustness additions and scope items from Task 1; two are owner decisions; one is extra tests; one is a lint fix; one is a process note.
**Impact on plan:** no new module dependency (age was already locked in go.mod), no production code path added only for tests apart from the pinned work-factor variable, and the dependency firewall is unchanged.

## Issues Encountered

- **capslock surprise (Task 3 step 3).** Found right after the blank import in Task 1 and taken to the owner at the Task 2 checkpoint (decision B), instead of being fixed as a "defect".
- **Git Bash path conversion** mangled a `git cat-file -e origin/main:path` argument. Re-run with `MSYS_NO_PATHCONV=1`.
- **WSL command quoting.** Every WSL command with `$` ran from a script file under `.git/gsd-tmp/`, which is never committed, so gofmt really ran in the gate.

## Not exercised (UNVERIFIED)

- **CI.** No required check has run on this branch at SUMMARY time. In particular the e2e-pkcs11, e2e-tpm, cli-windows, cli-macos, systemd-sandbox and build-piv lanes ran only in CI, or not yet.
- **A real systemd `LoadCredential=` / `LoadCredentialEncrypted=`.** The `CREDENTIALS_DIRECTORY` source is tested only with `t.Setenv` in a unit test. custody.md labels this path UNVERIFIED.
- **`keyroster ca issue` and the server (02-06) failing closed on a real signer's `trust_changed` refusal** (the plan's own label, T-02-120). `ca issue` aborts on any Status error. Until the pre-merge review fixes, no test covered that abort: `TestCAIssueRefusesPrivateKey/public_key_dials_signer` (an earlier wording here claimed it did) only sees "signerclient: connect", which the Issue dial prints too. `TestCAIssueStatusGate` now feeds a **synthetic** `trust_changed` and `internal_error` from a fake signer and requires that no IssueRequest is sent. A real signer's `trust_changed` reaching `ca issue` is still not exercised, and the server half (02-06) does not exist yet.
- **The capslock MODIFY_SYSTEM_STATE widening and the internal/trust UNANALYZED cause** (see above).
- **A trust state from Phase 1 code above the Status budget.** Status would refuse it with ErrStatusTooLarge (Marshal is tested); no such state was built against a running signer.
- **Status on the UI (02-06).** The server banner does not exist yet, which is why KEY-06 stays open.

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat model. Status is a new read-only message type for peers on the socket allowlist (planned, D-18). It returns documents the bundle_install log entry already records and the directory hash, and adds no network surface. depguard and dep-firewall are clean.

## User Setup Required

None.

## Next Phase Readiness

- **02-06 (server)** reads custody only from `signerclient.Status` and renders `custodytext.SoftwareCABanner(custodytext.SoftwareRoles(st.Keys))` on every page. It must treat every Status error as fail-closed (503); the plan already says so.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in key-files.created exists.
- Commits `c874e3e`, `84cf5ea`, `4cf0e67`, `45188d8` and `e959951` are ancestors of HEAD.
- Task 1 acceptance:
  - the blank import is present;
  - `go list -deps ./cmd/keyroster-signer | grep -c custodytext` = 0;
  - no rootceremony in the backend;
  - `s.checkTrustCurrent(` appears in Status;
  - the statusOrRefuse definition exists;
  - the non-comment `statusOrRefuse(` count in server.go is 1.
- Task 3 acceptance:
  - custody.md contains the phrase, `rand -base64` and `length floor`;
  - custodytext_test.go reads custody.md and has `banner_fits_terminal`;
  - all nine named TestSoftwareBackend cases are present;
  - `defer clear(pass)` appears at all three read sites;
  - TestStatusFrameCaps has its three cases, and FuzzParseStatusResponse exists;
  - countingReader and frameHeader are used in status_test.go;
  - `git diff origin/main -- internal/wire/wire_test.go` is empty;
  - both budget cases are present;
  - status_test.go starts with `//go:build linux`, with TestStatusTrustChanged and 2 non-comment `signerclient.Status(` calls;
  - `statusResponse(` appears in trust.go and status.go;
  - Phase 1 deferred-items names 02-05 at the piv entry.
- The PR acceptance (open, auto-merge, green, SUMMARY on its head) is checked after the push and reported in the checkpoint.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-18 (before the merge gate)*

## Pre-merge review fixes

These are verified findings from the pre-merge review of PR #40 at head 32f77d5. Each fix has a test that failed before the fix and passes after it. For a test that passed vacuously, the entry names the mutant that the rewritten test now kills.

**Fixed**
- **A FIFO at the passphrase path made ca-init, install-bundle and serve hang** (low). Fixed in 89b4be6. The file is now opened with O_NONBLOCK, and the fstat checks are unchanged. Test: `TestSoftwareBackend/passphrase_fifo_refused_without_blocking`, which covers a FIFO, a symlink to a FIFO and a FIFO credential. Before the fix the open was still blocked after 2 s.
- **A relative passphrase-file resolved against each process's working directory** (low). Fixed in 27c89c4. A relative path is now refused with an error that names the option, and custody.md says the path must be absolute. Test: `TestSoftwareBackend/relative_passphrase_file_refused`. It chdirs to a valid 0600 file and opens it by its relative name. Before the fix that succeeded.
- **Nothing tested ca issue's fail-closed abort on a Status error, although the SUMMARY claimed a test did** (medium, rated low by both skeptics). Fixed in 4023ed5. Test: `TestCAIssueStatusGate`, with a fake signer on a Unix socket.
  - A Status error (`trust_changed`, `internal_error`) must give exit 1 with no IssueRequest sent.
  - For custody software, the framed banner must already be on stderr when the IssueRequest arrives. For custody agent, there must be no banner.
  - Mutants: ignoring the warnCustody error fails both abort cases, and removing the banner print fails the software case.
  - It passes natively on Windows and in WSL.
  - The UNVERIFIED bullet above is reworded. A real signer's `trust_changed` is still not exercised.
- **Two Provision refusal tests passed even with their guards removed** (low). Fixed in 671e881.
  - The new `provision_refuses_any_age_file` plants `stray.age`. It kills X1, the any-.age scan replaced by false.
  - `provision_refuses_bad_roles` now requires the "given twice" refusal. It kills X2, the duplicate-role guard replaced by false.
  - The misleading "even for other roles" comment is fixed.
- **Split finding: a world-readable systemd credential was accepted** (low). Fixed in 5cae667. The credential must now have no other bits, and group bits stay allowed for systemd's ACL case, which is UNVERIFIED. Test: `TestSoftwareBackend/credential_world_readable_refused`. 0644, 0666 and 0604 are refused; 0400 and 0440 are accepted. Before the fix, 0644 was accepted.
- **Split finding: custody.md said every group- or other-readable passphrase file is refused** (low). Fixed in 5693a78. custody.md now states each rule exactly: passphrase-file has no group or other bits, the credential has no other bits, a non-regular file is refused, and CREDENTIALS_DIRECTORY must not be set by hand to a shared directory. The behaviour is pinned by the subtests above. `TestSoftwareCABanner` (custody.md quotes the banner) still passes.
- **Split finding: a passphrase-file stored by ca-init locks out the systemd credential** (low). Fixed in 2f8eabd, **doc part only**. custody.md now says the stored option is permanent for the state directory, so adding LoadCredential= later changes nothing. It also says how to choose the credential at ca-init. The behaviour is pinned by `credentials_directory_source` (the option wins) and `unknown_option` (an empty override is refused).

**Skipped**
- **The code change for the locked-in passphrase source.** All three fixes change the precedence or the storage that the plan specifies, so the choice goes to the owner:
  - (a) Prefer the credential when it is present. This can switch the source silently.
  - (b) Let `--backend-opt passphrase-file=` mean "unset". Every serve would then have to pass it, because the backend_config row is insert-only.
  - (c) Stop storing passphrase-file and require it on every command.
- **O_NOFOLLOW on the passphrase file.** Whether to refuse a symlinked passphrase file is a design question. Symlinks are still followed, and the fstat checks apply to the target.

**Gate run** on 4023ed5:
- `gofmt -l .` is empty.
- `go vet ./...` passes on Windows, and with GOOS=linux and GOOS=darwin.
- `go test -count=1` passes in WSL on internal/keystore/software, cmd/keyroster and internal/custodytext, and natively on Windows on cmd/keyroster and internal/custodytext.
- `go test ./...` in WSL exits 0.
- `-race` was not run (no cgo).
- The e2e lane (`-tags e2e`) was not run locally because no OpenSSH prefix is built here; it runs only in CI.
