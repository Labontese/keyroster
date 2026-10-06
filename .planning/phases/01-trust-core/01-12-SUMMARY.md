---
phase: 01-trust-core
plan: 12
subsystem: keystore-piv
tags: [piv, yubikey, piv-go, cgo, build-tag, needs-hardware, ci]

requires:
  - phase: 01-11
    provides: "keystore.Provisioner and Describer, the reserved state-dir option, ca-init/serve/install-bundle backend plumbing with stored options and --backend-opt overrides"
  - phase: 01-08
    provides: "ca-init without --key provisions through a keystore.Provisioner; InitCA checks Algorithm() == key type and records custody"
provides:
  - "internal/keystore/piv (build tag piv): backend piv with options pin-file, mgmt-key-file, serial; slots user 0x82, host 0x83, machine 0x84, ops 0x85, log 0x86; Ed25519 on firmware >= 5.7.0, P-256 on 5.3.0-5.6.x, firmware < 5.3.0 refused; PIN policy once, touch policy never; custody piv"
  - "card interface (Version, KeyInfo, GenerateKey, PrivateKey, Close), a thin piv-go YubiKey adapter (not exercised in CI) and newWithCard for tests"
  - "cmd/keyroster-signer/backends_piv.go (linux && piv) blank import"
  - ".github/workflows/piv.yml: check build-piv (vet, golangci-lint with --build-tags piv, -race unit tests, tagged signer build with go version -m, default-build exclusion of piv-go and cgo)"
  - "docs/backends/piv.md (operator guide, marked not validated on hardware), docs/security/needs-hardware.md (Phase 6 checklist)"
  - "GitHub label needs-hardware and issue #13"
affects: [01-13, 01-15]

actuals:
  tokens: 13952
  tasks: 2
  commits: 2
plan_head_before: 4e132a609a5ec63676485747ad950e7961b0cb0f
plan_head_after: bb5ebe6fbac91ae5d430209dea3409e01e44cec5

tech-stack:
  added:
    - "github.com/go-piv/piv-go/v2 v2.6.0 (only in -tags piv builds)"
    - "libpcsclite-dev / libpcsclite1 2.0.3-1build1 (Ubuntu archive; CI build-piv only, local WSL via dpkg -x)"
  patterns:
    - "A cgo backend lives behind a build tag on every file of its package; the workflow that tests it also proves that default builds link neither the module nor cgo (go list -deps and go version -m)"
    - "A test fake keeps unsynchronised shared state, so -race fails if the backend's mutex is removed (mutation-checked)"
    - "Hardware code that CI cannot run is kept to a thin adapter, labelled NOT EXERCISED IN CI in the source, the guide and needs-hardware.md"

key-files:
  created:
    - internal/keystore/piv/card.go
    - internal/keystore/piv/piv.go
    - internal/keystore/piv/yubikey.go
    - internal/keystore/piv/piv_test.go
    - cmd/keyroster-signer/backends_piv.go
    - .github/workflows/piv.yml
    - docs/backends/piv.md
    - docs/security/needs-hardware.md
  modified:
    - go.mod
    - go.sum
    - docs/security/custody.md
    - docs/backends/pkcs11.md

key-decisions:
  - "01-12: the PIV backend keeps no files. Key() reads each slot's public key and origin from the card through GET METADATA (piv-go KeyInfo), so firmware below 5.3.0 is refused instead of adding an attestation fallback that CI could not exercise"
  - "01-12: only piv-go's ErrNotFound counts as an empty slot; any other KeyInfo error refuses provisioning. Provision checks all five slots before generating anything, because a real card overwrites an occupied slot silently"
  - "01-12: keys imported into a slot (KeyInfo origin imported) are refused, so custody piv is never claimed for a key that was not generated on the card"
  - "01-12: the default PIN is refused as well as the default management key; mgmt-key-file is needed only for provisioning, and the guide moves it off the host after ca-init (serve and install-bundle override it with --backend-opt mgmt-key-file=)"
  - "01-12: build-piv also runs golangci-lint with --build-tags piv, because the lint job in ci.yml never sees the tagged package"

patterns-established:
  - "Thin hardware adapter plus an interface-level fake, with the unexercised adapter named in needs-hardware.md"

requirements-completed: [KEY-05]

coverage:
  - id: D1
    description: "Tagged build: provisioning fills slots 0x82-0x86 (Ed25519 on firmware 5.7.0, P-256 on 5.4.3), each key opens through Key with custody piv and Algorithm() equal to its SSH type, and the user key issues a certificate through cert.Build that x/crypto's CertChecker verifies against the provisioned key"
    requirement: KEY-05
    verification:
      - kind: unit
        ref: "internal/keystore/piv/piv_test.go#TestPIVProvisionAndIssue (CI build-piv run 37418365266 on PR #14; local WSL with extracted libpcsclite)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Refusals: occupied slot (no GenerateKey call, the old key untouched), unreadable slot, provisioning without a management key, 0644 PIN file, 0640 management key file, symlinked PIN file, missing PIN file, default PIN, default management key, non-hex key, unknown option, bad serial, firmware 5.2.7, wrong fingerprint, empty slot, unknown role, imported key, wrong PIN"
    requirement: KEY-05
    verification:
      - kind: unit
        ref: "internal/keystore/piv/piv_test.go#TestPIVRefusals (18 subtests incl. slot_occupied_refused, pin_file_mode_0644_refused, default_mgmt_key_refused), #TestPIVSignWithoutMgmtKey"
        status: pass
    human_judgment: false
  - id: D3
    description: "Concurrency: eight goroutines sign through one backend (16 signatures each) and all verify under -race; with the lockedSigner mutex removed, the same test reports DATA RACE and fails"
    requirement: KEY-05
    verification:
      - kind: unit
        ref: "go test -race -tags piv ./internal/keystore/piv/... #TestPIVConcurrency/concurrent_sign (CI build-piv; local mutation run: 62 DATA RACE warnings, FAIL)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Default builds stay static: CGO_ENABLED=0 go build ./... succeeds, go list -deps of cmd/keyroster and cmd/keyroster-signer has no piv-go, and both default binaries report CGO_ENABLED=0 without go-piv; the tagged signer reports piv-go v2.6.0, -tags=piv, CGO_ENABLED=1"
    verification:
      - kind: other
        ref: "build-piv steps 'Build keyroster-signer with the PIV backend' and 'Default builds exclude piv-go and cgo' (run 37418365266); local WSL go list -deps"
        status: pass
    human_judgment: false
  - id: D5
    description: "The YubiKey adapter (yubikey.go), piv-go's card code and every ykman/pcscd/polkit step in docs/backends/piv.md on a real YubiKey"
    requirement: KEY-05
    verification: []
    human_judgment: true
    rationale: "No YubiKey in CI or locally; never executed. Tracked in docs/security/needs-hardware.md item 2 and issue #13 for the Phase 6 review (D-12)"
  - id: D6
    description: "needs-hardware checklist (YubiHSM 2, YubiKey PIV, hardware root ceremony) and the open issue #13 labelled needs-hardware"
    verification:
      - kind: other
        ref: "grep YubiHSM 2, YubiKey, ed25519-sk, Phase 6 in docs/security/needs-hardware.md; gh issue list --label needs-hardware --state open → #13"
        status: pass
    human_judgment: true
    rationale: "Whether the checklist steps are complete and accurate enough for the Phase 6 reviewer is a judgment call; the owner reviews it in the PR"
  - id: D7
    description: "PR #14 with every check green, waiting for the owner at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 14 on bb5ebe6: build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz, build-piv, e2e-pkcs11 (both lanes), e2e-tpm, pinned-actions, CodeQL pass"
        status: pass
    human_judgment: true
    rationale: "The owner reviews and approves the PR at the merge gate (Task 3)"

duration: 22min
completed: 2026-10-06
status: complete
---

# Phase 1 Plan 12: YubiKey PIV Backend Summary

**The five online CA keys can now live in YubiKey PIV retired key-management slots 0x82-0x86. They are Ed25519 on firmware 5.7+ and P-256 on 5.3-5.6, custody `piv`, through piv-go v2.6.0 behind the `piv` build tag. CI drives the real backend code with a fake card, from provisioning to a verified certificate, under `-race`, and proves that default binaries stay cgo-free and piv-go-free. The YubiKey adapter itself has never run on a card; that is tracked in issue #13.**

## Performance

- **Duration:** about 22 min, from 2026-10-06T05:09Z (branch created, after closing 01-11) to 05:31Z (all checks green on PR #14).
- **Tasks:** 2 of 3. Task 3 is the merge gate.
- **Files:** 12 (8 created, 4 modified).

## Package Legitimacy Record: `github.com/go-piv/piv-go/v2`

The plan defines no package checkpoint. The research audit approved piv-go (T-01-SC), and the version obtained equals the research pin, so execution continued. This is the same evidence 01-11 Task 1 collected.

| Item | Evidence |
|---|---|
| Version | `v2.6.0`, the research pin and proxy `@latest` (list: v2.0.0-alpha.1 … v2.6.0) |
| Upstream | `refs/tags/v2.6.0` → commit `31dc15be0b15590817f12ce9cc9966ee9e6f43f9` (2026-04-15, "feat: obtain the form factor of the Yubikey", author Scott Leggett, committed by Eric Chiang) |
| Signatures | **None.** The tag is lightweight (it points directly at the commit), and the commit and the last 10 commits are `verified=false` on GitHub. The Go checksum database is the integrity anchor. |
| sumdb | sum.golang.org record 52505796: `h1:/Z+uqlv5luC8aqLh/uO05egk23UH4KT/ldvPHXpnKls=` and go.mod `h1:gcsS2WGbToZk5PwtsCIlCWzV/R+r/wN+Xi+6O6IlU3c=`. They are byte-identical to the two go.sum lines `go get` and `go mod tidy` added, which are the only new go.sum lines. |
| Requires | `golang.org/x/crypto v0.50.0`; the module already uses v0.57.0, so MVS changes nothing |
| Maintainer and activity | `go-piv/piv-go`, Apache-2.0, created 2020-01-07, not archived, 433 stars. ericchiang has 87 commits (then AGWA, maraino, dnesting, …). Recent commits: 2026-04-15 (×2), 2026-02-06 (biometric match), 2025-07 (attestation CA 2024, ErrNotFound for 0x6A88), 2025-01, 2024-10 (Ed25519 hardening by Andrew Ayer) |
| Capabilities (import inventory of non-test files; capslock not run, since it is not pinned in `tools/go.mod` and 01-13 owns the capslock gate) | Imports are stdlib crypto/encoding, `golang.org/x/crypto/cryptobyte` and an in-module fork `third_party/rsa` (PSS). **No `net`, no `os/exec`, no file I/O.** cgo plus `unsafe` appear only in `pcsc_unix.go` and `pcsc_{linux,darwin,freebsd,openbsd}.go` (`#cgo linux pkg-config: libpcsclite`). Windows uses `syscall` plus `unsafe` (winscard). |
| cgo scope | Linked only into `-tags piv` builds; `build-piv` proves the default binaries are `CGO_ENABLED=0` with no piv-go |
| govulncheck | `govulncheck -tags piv ./...` (cgo, WSL, pinned `tools/go.mod` v1.8.0): 0 reachable and 0 imported-package vulnerabilities. The single module-level finding, GO-2026-5932 (x/crypto/openpgp, unused, no fix), is pre-existing and also appears in the untagged scan. |
| System packages | `libpcsclite-dev` / `libpcsclite1` `2.0.3-1build1` from the Ubuntu noble archive, installed in CI only. Locally they were extracted without root with `apt-get download` + `dpkg -x`. |

## Accomplishments

- **Backend `piv`** (`internal/keystore/piv/piv.go`, every file `//go:build piv`):
  - `parseOptions` runs before the card is touched. `pin-file` is required. `mgmt-key-file` is hex, 16, 24 or 32 bytes, and needed only for provisioning. `serial` is optional. Secret files must be regular, non-symlink files with mode 0600 or stricter. The default PIN and the default management key are refused.
  - `newBackend` refuses firmware below 5.3.0 and closes the card.
  - **`Provision`:** under the mutex it checks all target slots with `KeyInfo`, where only `ErrNotFound` means empty. It refuses with `ErrSlotOccupied`, generating nothing, if any slot is taken or unreadable. Then it generates each key with `PINPolicyOnce`/`TouchPolicyNever` and checks the SSH type.
  - **`Key`:** reads the slot through `KeyInfo` and refuses an empty slot (`ErrKeyNotPresent`), an imported key, a wrong fingerprint or a non-CA algorithm. It then calls `PrivateKey` with the PIN and the slot's PIN policy, asserts `crypto.Signer`, wraps it in a `lockedSigner` that shares the backend mutex, and passes that to `ssh.NewSignerFromSigner`. Custody is `piv`, and `Algorithm()` is the key's SSH type.
  - `Describe()` prints `YubiKey PIV firmware X.Y.Z → <alg> keys, custody piv`.
- **`yubikey.go`:** a thin pass-through to piv-go. It picks the card by serial or requires exactly one attached YubiKey. It is marked **NOT EXERCISED IN CI** in its source.
- **Tests** (`piv_test.go`): `fakeCard` holds real Ed25519 and P-256 keys. Like a real card, its `GenerateKey` overwrites and checks the management key, and `PrivateKey` checks the PIN. It counts signatures without a lock.
  - Tests: `TestPIVProvisionAndIssue` (two firmware cases), `TestPIVRefusals` (18 cases), `TestPIVSignWithoutMgmtKey`, `TestPIVConcurrency/concurrent_sign`.
  - **Mutation check:** with the `lockedSigner` lock removed, `-race` reports 62 `DATA RACE` warnings and the test fails. The file was restored afterwards.
- **CI `build-piv`** (`.github/workflows/piv.yml`):
  - Setup: `permissions: {}`, read-only contents, SHA-pinned checkout, setup-go and golangci-lint-action (the same pins as `ci.yml` and `e2e-tpm.yml`), `persist-credentials: false`, apt `--no-install-recommends`, recorded package versions.
  - Checks: `go vet -tags piv`, golangci-lint `--build-tags piv` (0 issues), the `-race` tests, the tagged signer build with `go version -m` assertions, and the default-build exclusion through `go list -deps` and `go version -m` on both default binaries.
- **Docs:**
  - `docs/backends/piv.md`: the build, firmware and algorithm, slot map, PIN-once/touch-never trade-off, ykman preparation without default credentials, polkit rule, 0600 secret files, ca-init, moving the management key off the host, the reset path, options, and what CI does and does not verify. A banner states that it is not yet validated on hardware.
  - `docs/security/needs-hardware.md`: a Phase 6 checklist covering (1) YubiHSM 2 through `yubihsm_pkcs11.so` + ssh-agent, (2) two YubiKeys (5.7+ and 5.3-5.6) running the PIV flow, and (3) hardware root ceremonies with two `ed25519-sk` keys and with PIV roots, each with the evidence to record.
  - Cross-links from `custody.md` (the PIV row) and `pkcs11.md`.
- **GitHub (as keyroster-bot):** label `needs-hardware` and issue **#13**, "needs-hardware: validate YubiHSM 2, YubiKey PIV and a hardware root ceremony on real devices".

## Task Commits

1. **Task 1** (tracer: provision PIV slots on a fake card → Signer issues a certificate → verify; tagged build; CI check): `79e4c0e` (feat).
   - Tracer gate (interactive, end-of-phase, automated-only `<verify>`): the tagged test run, the `go list -deps` exclusion and `CGO_ENABLED=0 go build ./...` passed in WSL and on Windows, so execution continued.
2. **Task 2** (idempotency, concurrency and secret-file tests, PIV guide, needs-hardware checklist and issue, PR): `bb5ebe6` (test, with the docs).
   - Branch pushed, PR **#14** opened with auto-merge (squash) enabled by keyroster-bot, every check green.
3. **Task 3** (merge gate): pending owner approval (checkpoint).

## CI Evidence (PR #14, head bb5ebe6)

- **All checks pass:**
  - required: `build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)`, `fuzz`;
  - not yet required: `build-piv` (new; 01-15 makes it required), `e2e-pkcs11 (distro-p256)`, `e2e-pkcs11 (10.5p1-ed25519)`, `e2e-tpm`;
  - also `pinned-actions`, `CodeQL`.
- **`build-piv` run 37418365266** shows:
  - `libpcsclite-dev:amd64 2.0.3-1build1` and `libpcsclite1:amd64 2.0.3-1build1` installed;
  - golangci-lint: `0 issues.`;
  - `--- PASS` for all 4 tests and all 21 subtests under `-race`;
  - the tagged signer's `dep github.com/go-piv/piv-go/v2 v2.6.0 h1:/Z+uqlv5…` and `build CGO_ENABLED=1`;
  - `default keyroster and keyroster-signer: CGO_ENABLED=0, no piv-go`.
- **Commit signatures:** `79e4c0e` and `bb5ebe6` show `verified: true` on GitHub.
- **Flaky test:** the known flaky `TestSignerRefusals/created_301s_future` did not fail, so no rerun was needed.

## Files Created/Modified

- `internal/keystore/piv/{card,piv,yubikey}.go`: the backend.
- `internal/keystore/piv/piv_test.go`: the fake card and tests.
- `cmd/keyroster-signer/backends_piv.go`: the blank import under `linux && piv`.
- `.github/workflows/piv.yml`: the `build-piv` check.
- `docs/backends/piv.md`, `docs/security/needs-hardware.md`: new docs.
- `docs/security/custody.md`, `docs/backends/pkcs11.md`: cross-links.
- `go.mod`, `go.sum`: piv-go v2.6.0.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The card interface has `KeyInfo` instead of `HasKey`**
- **Found during:** Task 1.
- **Issue:** The planned interface (`Version, HasKey, GenerateKey, PrivateKey, Close`) has no way to get a slot's public key. `Key(role, fp)` needs that key for `PrivateKey` and for the fingerprint check.
- **Fix:** `KeyInfo(slot)`, which is piv-go's GET METADATA. It returns the public key, origin and policies, and "has a key" is derived from it in the backend (`occupied`). The backend therefore keeps no state files. `state-dir` is still accepted, as for every backend, but unused.
- **Files modified:** `card.go`, `piv.go`, `yubikey.go`.
- **Committed in:** `79e4c0e`.

**2. [Rule 2 - Security] Extra refusals beyond the plan**
- **What was added:**
  - the default PIN is refused (the plan refuses only the default management key);
  - imported keys are refused (KeyInfo origin);
  - a symlinked secret file is refused;
  - firmware below 5.3.0 is refused, because GET METADATA needs 5.3.0;
  - an unreadable slot refuses provisioning instead of counting as empty.
- **Why:** each one closes a path to custody `piv` for a key that is not hardware-generated, a default credential, or an accidental overwrite.
- **Committed in:** `79e4c0e`; the tests are in `bb5ebe6`.

**3. [Rule 2 - Correctness] The management key is optional after provisioning**
- **Issue:** The plan treats both secret files as options.
- **Fix:** Only `Provision` needs the management key, so `mgmt-key-file` is optional. The guide moves it off the host after ca-init and overrides it with `--backend-opt mgmt-key-file=` for `install-bundle` and `serve`. `TestPIVSignWithoutMgmtKey` covers signing without it.
- **Committed in:** `79e4c0e` and `bb5ebe6`.

**4. [Rule 2 - Verification] `build-piv` does more than planned**
- **What was added:**
  - `go vet -tags piv` and golangci-lint `--build-tags piv`: the `lint` job in `ci.yml` never sees the tagged package, and `ci.yml` belongs to 01-13, so the step lives in `piv.yml`;
  - the tests run under `-race` (the plan's Task 2 verify uses `-race`);
  - positive and negative `go version -m` assertions on the tagged and default binaries, beyond the planned `go list -deps` check.
- **Committed in:** `79e4c0e`.

**5. [Environment] `dpkg -s libpcsclite-dev` cannot pass in WSL without root**
- **Issue:** The tracer `<verify>` installs the package as root.
- **Substitute:** `libpcsclite-dev` and `libpcsclite1` 2.0.3-1build1 were extracted with `apt-get download` + `dpkg -x` into `~/.cache/keyroster/pkgs/pcsc`. A local `PKG_CONFIG` shim and `LD_LIBRARY_PATH` pointed cgo at them. These files live outside the repository and are not committed.
- **Authoritative run:** CI's `build-piv`, which installs the package normally.

**6. [Scope] Small cross-links in files outside the plan's list**
- `docs/security/custody.md` (the PIV row now links to the guide and states that it is not validated on hardware) and `docs/backends/pkcs11.md` (links needs-hardware.md).
- **Committed in:** `bb5ebe6`.

---

**Total deviations:** 6 (1 interface adaptation, 3 security or verification hardening, 1 local environment substitution, 1 doc cross-link).
**Impact on plan:**
- All must-haves hold.
- The must-have "the backend is exercised through the real Provisioner/Backend/cert.Build path with a fake card in CI" is met. The real card path is not, and is stated as such (see Known Limitations).

## Known Limitations (not exercised anywhere)

01-11's lesson applies here: code that was never run is not presented as verified. The following have never executed:
- `internal/keystore/piv/yubikey.go`: `ykpiv.Cards`, `Open`, `Serial` and serial selection.
- piv-go against a real card:
  - GET METADATA on an empty retired slot. It is expected to return SW 0x6A88, which piv-go maps to `ErrNotFound`; the backend relies on this to treat the slot as empty.
  - `GenerateKey` with the PIN and touch policies.
  - Ed25519 and ECDSA `Sign` on the card.
  - PIN policy once over a long-lived session.
- Every `ykman`, `pcscd` and polkit step in `docs/backends/piv.md`, including whether `ykman piv access change-management-key` prompts for the new key as the guide says.

All of them are items in `docs/security/needs-hardware.md` (item 2) and issue #13.

## Issues Encountered

- A bash heredoc for appending tests failed on quoting. The tests were written to a scratch file and appended instead; no effect on the repository.

## Known Stubs

None. `yubikey.go` is the production adapter, not a stub; it is unverified on hardware, as stated above.

## Threat Flags

None beyond the plan's threat register:
- **T-01-53** (cgo in default builds): mitigated and proven by `build-piv`.
- **T-01-54** (PIN and management key): read only from 0600 files, default credentials refused, never argv. The management key can leave the host after ca-init.
- **T-01-55** (other local processes using the card): the guide's polkit rule. piv-go holds a PC/SC transaction while the signer runs. Both are unverified on hardware.
- **T-01-56** (unverified hardware behaviour): transferred to Phase 6 through needs-hardware.md and #13.
- **T-01-SC** (piv-go and libpcsclite-dev): covered by the record above.

## User Setup Required

None for this plan. A real-hardware run is the Phase 6 needs-hardware item.

## Next Phase Readiness

- **01-13:**
  - `doctor` could report a `piv` custody and the firmware.
  - A PIV signer's systemd unit needs access to the `pcscd` socket (`/run/pcscd/pcscd.comm`), and the sandbox must allow it.
  - The capslock gate should be run once with `-tags piv` to record piv-go's capabilities.
- **01-15:** make `build-piv` a required check (CONTRIBUTING rollout rule).
- **Phase 6:** issue #13.

## Self-Check: PASSED

- All 8 created files exist on disk.
- Commits `79e4c0e` and `bb5ebe6` are on `origin/p01/12-piv` and show as verified on GitHub.
- `actuals.commits` (2) is `git rev-list --count 4e132a6..bb5ebe6`. The docs commit is excluded, by convention.
- `actuals.tasks` (2) counts the tasks before the merge gate.
- `actuals.tokens` (13952) is chars/4 over the added lines of the plan diff (55807 characters).
- Acceptance criteria were re-run:
  - every `.go` file under `internal/keystore/piv/` starts with `//go:build piv`;
  - `backends_piv.go` starts with `//go:build linux && piv`;
  - `piv.yml` has `permissions: {}`, and `check-pinned-actions.sh` passes (33 references);
  - needs-hardware.md mentions YubiHSM 2, YubiKey, ed25519-sk and Phase 6;
  - piv_test.go has the cases `slot_occupied_refused`, `pin_file_mode_0644_refused`, `default_mgmt_key_refused` and `concurrent_sign`;
  - one open issue carries the `needs-hardware` label (#13);
  - PR #14 is open with auto-merge and every check green.
