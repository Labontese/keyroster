---
phase: 01-trust-core
plan: 11
subsystem: keystore-tpm
tags: [tpm, tpm2, swtpm, vtpm, go-tpm, go-tpm-keyfiles, p256, custody, e2e, ci]

requires:
  - phase: 01-08
    provides: "audit verify --pin/--threshold anchored on the trust root; prepareSigner/bootstrapOpts with a Provisioner backend (no --key)"
  - phase: 01-07
    provides: "ca-init with keystore.Provisioner support, install-bundle, stored backend config with --backend-opt overrides"
  - phase: 01-05
    provides: "C2SP type 0x02 ECDSA note signer/verifier for a P-256 log key"
  - phase: 01-10
    provides: "test/e2e/fingerprint_test.go for builds under e2e_tpm without the e2e tag"
provides:
  - "internal/keystore/tpm: backend tpm (options state-dir, device, swtpm-socket, custody), Provision, Key, Describe, Manufacturer, CustodyForManufacturer; key files {state-dir}/tpm/{role}.tpmkey + {role}.auth"
  - "internal/keystore: reserved option state-dir (OptStateDir) passed by ca-init/install-bundle/serve, never stored; Describer interface printed by ca-init"
  - "scripts/swtpm-setup.sh DIR (swtpm on a Unix socket, unixio, the only transport CI exercises); prints KEYROSTER_TPM_OPTS=swtpm-socket=..."
  - "test/e2e/tpm_test.go (tag e2e_tpm, env KEYROSTER_TPM_OPTS): TestTPMFullFlow, TestTPMRestartPersistence, TestTPMCAInitTwiceRefused"
  - ".github/workflows/e2e-tpm.yml: check e2e-tpm (swtpm unixio; also runs the TPM unit tests under -race with KEYROSTER_TPM_REQUIRE=1)"
  - "docs/security/custody.md: custody levels, vTPM and SOFTWARE ROOT statements, CI TPM setup"
affects: [01-13, 01-14, 01-15]

actuals:
  tokens: 16908
  tasks: 3
  commits: 5
plan_head_before: 79794b1cb887336683cbc1a934ccff937a83ebea
plan_head_after: 0b387769c602da5dfce164c3f6f578c296b23c04

tech-stack:
  added:
    - "github.com/foxboron/go-tpm-keyfiles v0.0.0-20260902202739-8c9c2d1005f4"
    - "github.com/google/go-tpm v0.9.9-0.20260124013517-8f8f42cba0de (by MVS)"
    - "swtpm 0.7.3-0ubuntu5.24.04.1 / libtpms0 0.9.3-0ubuntu4.24.04.1 (Ubuntu archive, CI and local tests only)"
  patterns:
    - "Custody is derived at open time from TPM_PT_MANUFACTURER, never stored in key files; an operator override can only weaken it (to vtpm)"
    - "Backends that keep files get the signer's state directory through the reserved state-dir option; it is added at open time and never stored with the backend configuration"
    - "Unit tests that need swtpm start their own private swtpm; they skip without swtpm unless KEYROSTER_TPM_REQUIRE=1, which the e2e-tpm workflow sets"

key-files:
  created:
    - internal/keystore/tpm/tpm.go
    - internal/keystore/tpm/provision.go
    - internal/keystore/tpm/transport.go
    - internal/keystore/tpm/vendor.go
    - internal/keystore/tpm/tpm_test.go
    - internal/keystore/tpm/vendor_test.go
    - scripts/swtpm-setup.sh
    - test/e2e/tpm_test.go
    - .github/workflows/e2e-tpm.yml
    - docs/security/custody.md
  modified:
    - go.mod
    - go.sum
    - internal/keystore/keystore.go
    - internal/keystore/registry.go
    - cmd/keyroster-signer/backends_linux.go
    - cmd/keyroster-signer/cainit.go
    - cmd/keyroster-signer/serve.go
    - cmd/keyroster-signer/install.go
    - .golangci.yml

key-decisions:
  - "01-11: CI runs the TPM lane on swtpm unixio (go-tpm linuxudstpm), the only transport CI exercises. vtpm-proxy was rejected after a CI spike (the ubuntu-24.04 runner kernel 6.17.0-1022-azure has no tpm_vtpm_proxy, not even in linux-modules-extra) and, by owner decision, removed from swtpm-setup.sh because it never ran to completion. The production /dev/tpmrm0 path (linuxtpm.Open) is first exercised by the homelab dogfood (01-14)"
  - "01-11: the planned swtpm-tcp option (go-tpm transport/tcp) is not built. A local spike showed that it works with swtpm's TCP server, but unixio needs no root, and a TCP client in the signer would add network code to a network-less process (KEY-01)"
  - "01-11: custody comes from the TPM manufacturer at open time (IBM, MSFT, GOOG are vtpm; others tpm); --backend-opt custody can only weaken it to vtpm, and custody=tpm on a software or virtual TPM is refused, so a vTPM key is never reported as hardware TPM custody"
  - "01-11: the TPM backend gets the state directory through a reserved keystore option state-dir that ca-init, install-bundle and serve add at open time; it is never stored and is refused as --backend-opt"
  - "01-11: TPM owner hierarchy auth is empty (the default); every key has its own random 32-byte auth value in a 0600 file next to its TSS2 PEM key file"

patterns-established:
  - "keystore.Describer: a backend's one-line operator description, printed by ca-init (TPM manufacturer and custody)"
  - "tpmServe/stop in tpm_test.go: restart a signer inside one e2e test without editing bootstrap_test.go"

requirements-completed: [KEY-04]

coverage:
  - id: D1
    description: "ca-init --backend tpm creates five ECDSA P-256 keys in a TPM (swtpm), then a root-signed bundle, install-bundle, an admin-signed issue signed by the TPM user CA, an sshd 10.5p1 login and audit verify --pin. The checkpoint carries a C2SP type 0x02 ECDSA signature by the TPM log key (key ID from the SPKI, DER signature, verifies)"
    requirement: KEY-04
    verification:
      - kind: e2e
        ref: "test/e2e/tpm_test.go#TestTPMFullFlow (CI e2e-tpm on PR #12; local WSL swtpm unixio)"
        status: pass
    human_judgment: false
  - id: D2
    description: "After a signer restart the same five public keys load from the key files, and issuance plus audit verify continue"
    requirement: KEY-04
    verification:
      - kind: e2e
        ref: "test/e2e/tpm_test.go#TestTPMRestartPersistence (CI e2e-tpm on PR #12)"
        status: pass
      - kind: unit
        ref: "internal/keystore/tpm/tpm_test.go#TestProvisionSignReopen"
        status: pass
    human_judgment: false
  - id: D3
    description: "swtpm (manufacturer IBM) is recorded as custody vtpm in ca-pubkeys.json and the verified bundle for all five keys; ca-init prints 'TPM manufacturer: IBM → custody vtpm'; CustodyForManufacturer maps IBM/MSFT/GOOG to vtpm and INTC and others to tpm; custody=tpm on swtpm is refused"
    requirement: KEY-04
    verification:
      - kind: unit
        ref: "internal/keystore/tpm/vendor_test.go#TestCustodyForManufacturer, #TestManufacturerSWTPM; tpm_test.go#TestOpenOptions/tpm_custody_on_swtpm"
        status: pass
      - kind: e2e
        ref: "test/e2e/tpm_test.go#assertTPMKeys, #TestTPMCAInitTwiceRefused"
        status: pass
    human_judgment: false
  - id: D4
    description: "Idempotency: a second ca-init and a second Provision are refused and overwrite no key file, ca-pubkeys.json or audit log entry; key files are 0600 under a 0700 tpm/ directory"
    requirement: KEY-04
    verification:
      - kind: unit
        ref: "internal/keystore/tpm/tpm_test.go#TestProvisionTwiceRefused, #TestProvisionSignReopen"
        status: pass
      - kind: e2e
        ref: "test/e2e/tpm_test.go#TestTPMCAInitTwiceRefused"
        status: pass
    human_judgment: false
  - id: D5
    description: "Concurrency: eight goroutines sign through one backend and every signature verifies under -race"
    requirement: KEY-04
    verification:
      - kind: unit
        ref: "go test -race ./internal/keystore/tpm/... #TestConcurrentSign (CI e2e-tpm with KEYROSTER_TPM_REQUIRE=1; local WSL)"
        status: pass
    human_judgment: false
  - id: D6
    description: "No package links go-tpm-tools or go-tpm's tpm2/transport/simulator; depguard denies the simulator"
    verification:
      - kind: other
        ref: "bash scripts/linux.sh '! go list -deps ./... | grep -E \"go-tpm-tools|tpm2/transport/simulator\"'; golangci-lint 0 issues"
        status: pass
    human_judgment: false
  - id: D7
    description: "docs/security/custody.md: custody levels, the Proxmox vTPM statement (weaker than a physical TPM, stronger than a software key), SOFTWARE ROOT, the signing-oracle note (D-13), the CI swtpm setup"
    verification:
      - kind: other
        ref: "grep vtpm, Proxmox, SOFTWARE ROOT in docs/security/custody.md"
        status: pass
    human_judgment: true
    rationale: "Whether the custody wording is accurate and clear enough for operators is a judgment call; the owner reviews it in the PR"
  - id: D8
    description: "PR #12 with every check green, waiting for the owner at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 12 on 0b38776 (after the vtpm-proxy removal): build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz, e2e-pkcs11 (both lanes), e2e-tpm (run 37414882288), pinned-actions, CodeQL pass"
        status: pass
    human_judgment: true
    rationale: "The owner reviews and approves the PR at the merge gate (Task 4)"

duration: 40min active (13h 7m wall clock from the Task 1 start, including the owner's legitimacy review)
completed: 2026-10-06
status: complete
---

# Phase 1 Plan 11: TPM 2.0 Backend Summary

**The five online CA keys are now ECDSA P-256 keys created inside a TPM 2.0, through go-tpm and go-tpm-keyfiles in pure Go. Custody comes from the TPM manufacturer, so swtpm and a Proxmox vTPM are labelled `vtpm`, never `tpm`. With these keys the whole keyroster flow works against swtpm: ca-init, root-signed bundle, install-bundle, issuance, a real sshd login, and `audit verify --pin` with ECDSA checkpoints from the TPM log key. It also survives a signer restart.**

## Performance

- **Duration:** about 40 min of execution. Wall clock is 13h 7m from the Task 1 start, because it includes the owner's package review.
- **Started:** 2026-10-05T14:49:12Z (Task 1). The continuation started at about 2026-10-06T03:15Z.
- **Completed:** 2026-10-06T03:57Z
- **Tasks:** 3 of 4 (Task 1 legitimacy gate approved, Tasks 2 and 3 executed; Task 4 is the merge gate)
- **Files modified:** 19 (10 created, 9 modified)

## Package Legitimacy Approval (Task 1)

The owner reviewed the evidence and replied, verbatim, "approved + paket ok". Approved and installed:

| Module | Version | Upstream commit | go.sum |
|---|---|---|---|
| `github.com/foxboron/go-tpm-keyfiles` | `v0.0.0-20260902202739-8c9c2d1005f4` | `8c9c2d1005f4527ada79bc29681bf53d3f0b4540` | `h1:zqtQvVnFZ71RsyDMNVAaWf4g2OVEDH5LDs26MZFHy7s=`, go.mod `h1:wxFx38LbEL4RF0JH6PR3lf7ZJ6ZO0yQWQstLCTQQNjA=` |
| `github.com/google/go-tpm` (by MVS) | `v0.9.9-0.20260124013517-8f8f42cba0de` | `8f8f42cba0de67d10e9c85cb358f3dd94a9815f7` | `h1:U6GxkpXnFhR76KyzdJCa3/YopeqiMgKWEGPp5u2mCSQ=` |

- After `go get` and `go mod tidy`, the go.sum hashes are byte-identical to the approved sumdb values.
- `go list -m github.com/google/go-tpm` prints the research's pseudo-version.
- `github.com/google/go-tpm-tools v0.4.4` appears only in go.sum, because the library's own tests use it. `go list -deps ./...` contains neither it nor `tpm2/transport/simulator`.

## Accomplishments

- **Backend `tpm`** (`internal/keystore/tpm`):
  - **`Provision`:** creates one P-256 key per role with `keyfile.NewLoadableKey(tpm, TPMAlgECC, 256, nil, WithUserAuth(random 32 bytes))` under the owner hierarchy's SRK. It writes `{role}.tpmkey` (TSS2 PEM) and `{role}.auth`, mode 0600 in a 0700 `{state-dir}/tpm`, and writes all files or none. If any file exists it refuses and overwrites nothing.
  - **`Key`:** requires private file modes and the pinned fingerprint, a loadable ECC P-256 key and `cert.CheckCAKey`. It then wraps `TPMKey.Signer` (ASN.1 ECDSA from the TPM) in `ssh.NewSignerFromSigner`.
  - **Locking:** every TPM command (provisioning, the capability query, signatures) runs under one package mutex.
- **Transport:**
  - `device` (default `/dev/tpmrm0`) is `linuxtpm.Open`, the production path.
  - `swtpm-socket` (test and development only) is `linuxudstpm.Open`.
  - The two are mutually exclusive. The whole package is `//go:build linux`, so `GOOS=windows go vet ./...` stays clean.
- **Custody:**
  - `Manufacturer` reads `TPM_PT_MANUFACTURER`, and swtpm reports `IBM`. `CustodyForManufacturer` maps IBM, MSFT and GOOG to `vtpm` and everything else to `tpm`.
  - The `custody` option may force `vtpm`. `custody=tpm` is refused on a virtual TPM.
  - ca-init prints `TPM manufacturer: IBM → custody vtpm`.
- **CLI plumbing:**
  - `keystore.OptStateDir` (`state-dir`) is added by ca-init, install-bundle and serve at open time, as an absolute path. It is never stored, and `--backend-opt state-dir=...` is refused.
  - A new `keystore.Describer` interface lets ca-init print the backend's description.
- **Tests:**
  - Unit tests (each starts a private swtpm): provision, sign and reopen; refusals (wrong fingerprint, `../user` role, 0644 auth file, wrong auth value); option refusals; provisioning twice; 8 concurrent signatures; manufacturer mapping and the swtpm manufacturer.
  - e2e: `TestTPMFullFlow`, `TestTPMRestartPersistence` and `TestTPMCAInitTwiceRefused`.
  - The e2e checkpoint check decodes the signature line. It requires the key ID to equal the first 4 bytes of SHA-256 of the log key's SPKI (C2SP type 0x02) and the signature to be DER, then verifies the note with `tlog.NewNoteVerifier`.
- **CI:** the `E2E TPM` workflow has a single check `e2e-tpm`. It installs swtpm from the Ubuntu archive, runs the TPM unit tests under `-race` with `KEYROSTER_TPM_REQUIRE=1`, starts swtpm in unixio mode and runs the e2e suite. The `build-test` job has no swtpm, so it skips the TPM unit tests; only `e2e-tpm` runs them.
- **Docs:** `docs/security/custody.md`.

## swtpm Transport Spike (research A1/A2, Pitfall 7)

| Mode | Where tried | Result | Kept? |
|---|---|---|---|
| `vtpm-proxy` (production transport, `/dev/tpmrmN`) | CI `ubuntu-24.04`, PR #12 runs 37410548123 and 37410673332 | `modprobe: FATAL: Module tpm_vtpm_proxy not found in directory /lib/modules/6.17.0-1022-azure`, also after installing `linux-modules-extra-6.17.0-1022-azure`. It never got past `modprobe`, so the chardev start, device discovery and chown/chmod never ran | No (A2 false on hosted runners). **Mode removed** from the script (`0b38776`, deviation 8) |
| `unixio` (go-tpm `linuxudstpm`) | CI and WSL2 | Unit tests (`-race`) and all three e2e tests pass | **Yes, CI default** (A1 true) |
| `tcp` (go-tpm `transport/tcp`, MS simulator framing) | WSL2 local spike | Works: swtpm's TCP server answered `TPM2_GetCapability` (manufacturer `IBM`) | Not built (KEY-01, see Deviations) |

CI exercises the swtpm unixio transport only. The production `/dev/tpmrm0` path (`linuxtpm.Open`) is not exercised in CI; it is first exercised in 01-14's homelab dogfood on the Proxmox VM's own vTPM. Everything above the transport is the same code.

## CI Evidence (PR #12, head 0b38776)

The evidence below is for `0b38776`, the head after the vtpm-proxy removal (deviation 8). The earlier head `58a02a4` had the same checks green.

- **All checks pass:**
  - required: `build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)`, `fuzz`;
  - not yet required: `e2e-pkcs11 (distro-p256)`, `e2e-pkcs11 (10.5p1-ed25519)` and the new `e2e-tpm` (01-15 makes them required);
  - also `pinned-actions`, `CodeQL`.
- **The `e2e-tpm` job log** (run 37414882288 on `0b38776`; swtpm 0.7.3-0ubuntu5.24.04.1, libtpms0 0.9.3-0ubuntu4.24.04.1) shows `swtpm-setup: unixio socket ...` from the reworked script, then `--- PASS` for all 7 unit tests and for `TestTPMFullFlow`, `TestTPMRestartPersistence` and `TestTPMCAInitTwiceRefused`.
- **Commit signatures:** `3a329b7`, `0677e98`, `58a02a4` and `0b38776` all show `verified: true` on GitHub.
- **Flaky test:** the known flaky `TestSignerRefusals/created_301s_future` did not fail, so no rerun was needed.
- **Auto-merge:** enabled by keyroster-bot (squash).

## Task Commits

1. **Task 1: package legitimacy check:** approved by the owner. No commit.
2. **Task 2: tracer, ca-init --backend tpm (swtpm) through to audit verify with ECDSA checkpoints:**
   - `3a329b7` (feat): backend, CLI plumbing, script, e2e, workflow.
   - `0677e98` (ci): vtpm-proxy spike retry with linux-modules-extra.
   - Tracer gate (interactive, end-of-phase, automated-only `<verify>`): the local unixio e2e and the dependency check passed, so execution continued.
3. **Task 3: custody detection tests, idempotency e2e, custody docs:** `58a02a4` (feat). It also collapses the workflow to the single `e2e-tpm` job in unixio mode.
   - `d7b1556` (docs): the first version of this SUMMARY and the tracking updates.
   - `0b38776` (fix): removes the unverified vtpm-proxy mode before the merge gate (deviation 8).
4. **Task 4: merge gate:** pending owner approval (checkpoint).

## Files Created/Modified

- `internal/keystore/tpm/{tpm,provision,transport,vendor}.go`: the backend.
- `internal/keystore/tpm/{tpm,vendor}_test.go`: the swtpm-backed unit tests.
- `internal/keystore/{keystore,registry}.go`: `OptStateDir`, `Describer`, and `CheckOptions` accepting `state-dir`.
- `cmd/keyroster-signer/{cainit,serve,install,backends_linux}.go`: the state-dir plumbing, the description line, and the blank import.
- `.golangci.yml`: depguard denies `github.com/google/go-tpm/tpm2/transport/simulator`.
- `scripts/swtpm-setup.sh` (100755), `test/e2e/tpm_test.go`, `.github/workflows/e2e-tpm.yml`, `docs/security/custody.md`.
- `go.mod`, `go.sum`: the two approved modules.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The reserved `state-dir` option did not exist**
- **Found during:** Task 2.
- **Issue:** The plan treats `state-dir` as an option that ca-init and serve already pass. Neither did, and `CheckOptions` would refuse it for every backend.
- **Fix:**
  - Added `keystore.OptStateDir`; `CheckOptions` always allows it.
  - Added `openBackend` in the signer CLI, which adds the absolute `--state-dir` at open time for ca-init, install-bundle and serve, and never stores it.
  - `--backend-opt state-dir=` is refused.
- **Files modified:** `internal/keystore/keystore.go`, `internal/keystore/registry.go`, `cmd/keyroster-signer/cainit.go`, `serve.go`, `install.go`. None of these is in the plan's file list.
- **Committed in:** `3a329b7`.

**2. [Rule 3 - Blocking] ca-init had no way to print the TPM manufacturer**
- **Found during:** Task 3 (needed by its action).
- **Fix:** Added the optional `keystore.Describer` interface. ca-init prints `Describe()` before the key lines.
- **Committed in:** `3a329b7`.

**3. [Rule 2 - Security] The custody override cannot upgrade a vTPM**
- **Issue:** The plan lets `custody` override to `tpm` or `vtpm`. Unrestricted, `custody=tpm` on swtpm or a Proxmox vTPM would break the must-have prohibition that a vTPM key is never reported as hardware TPM custody.
- **Fix:** `custody=vtpm` is always accepted. `custody=tpm` is refused unless the manufacturer already maps to `tpm`. This is tested.
- **Committed in:** `3a329b7`.

**4. [Rule 2 - Security, CLAUDE.md simplicity and KEY-01] The `swtpm-tcp` option and `tcp` setup mode are not built**
- **Issue:** The plan has a third transport, go-tpm `transport/tcp`.
- **Evidence:** A local spike showed that it works with swtpm's TCP server.
- **Why not built:** The unixio socket already works without root, both locally and in CI. A TCP client inside `keystore` would put network code into the signer, which is network-less by design (KEY-01). Every feature is attack surface.
- **Fix:** `swtpm-setup.sh` has no `tcp` mode. `docs/security/custody.md` records the reason. (Since deviation 8 the script supports `unixio` only.)
- **Committed in:** `3a329b7` and `58a02a4`.

**5. [Rule 3 - Blocking] vtpm-proxy unavailable on hosted runners**
- **Issue:** As above, the runner kernel has no `tpm_vtpm_proxy`.
- **Fix:** Tried with `linux-modules-extra` (`0677e98`). When that failed too, the workflow was collapsed to unixio (`58a02a4`).
- **Note:** The CI spike used a temporary two-lane matrix (`e2e-tpm (vtpm-proxy)` and `e2e-tpm (unixio)`). The final check name is exactly `e2e-tpm`.

**6. [Ordering] Task 3 artifacts landed in the Task 2 commit**
- `vendor.go` (Task 2's backend needs the custody) and the unit tests for idempotency and concurrency are in `3a329b7`.
- Task 3's own commit holds `vendor_test.go`, the CA-init idempotency e2e, the docs and the workflow collapse.

**7. [Minor] Only `swtpm` is installed, not `swtpm-tools`**
- `swtpm_setup` is not used, so the CI supply-chain surface stays smaller.

**8. [Owner decision, before the merge gate] The unverified vtpm-proxy mode was removed**
- **Found during:** owner review at the Task 4 merge gate.
- **Issue:** `scripts/swtpm-setup.sh` still had a `vtpm-proxy` mode, and `docs/security/custody.md` described it as a working option. It had never run to completion: both CI attempts stopped at `modprobe tpm_vtpm_proxy`, so the `swtpm chardev --vtpm-proxy` start, the new-device discovery and the `chown`/`chmod` of the device never ran anywhere. Untested code must not look tested.
- **Check:** no later plan depends on it. 01-13 and 01-14 use the VM's own vTPM through `/dev/tpmrm0`, and 01-15 only makes `e2e-tpm` required. The only callers were the workflow, the docs and a test comment.
- **Fix:**
  - `swtpm-setup.sh` now takes `DIR` only and starts the verified unixio path.
  - `e2e-tpm.yml` drops `SWTPM_MODE`, calls the script with `DIR`, and reads the runner-owned swtpm log without `sudo`. The job and check name `e2e-tpm` is unchanged.
  - The comment in `test/e2e/tpm_test.go` no longer presents `device=/dev/tpmrmN` as script output.
  - `custody.md` states plainly that CI exercises the swtpm unixio transport only, that the production `/dev/tpmrm0` path (`linuxtpm.Open`) is first exercised in 01-14's homelab dogfood, and that vtpm-proxy was attempted and dropped because GitHub runners lack `tpm_vtpm_proxy`.
- **Verification:**
  - The new script was run in WSL. `bash -n` passes, and the old `MODE DIR` form is refused with the usage message. The last stdout line is `KEYROSTER_TPM_OPTS=swtpm-socket=...`, the socket appears, and the daemon was then killed.
  - Every check on `0b38776` passes, including `e2e-tpm` (run 37414882288).
- **Committed in:** `0b38776`.

---

**Total deviations:** 8 (2 blocking plumbing additions, 2 security-driven restrictions, 1 CI environment constraint, 2 minor ordering or scope, 1 owner-directed removal of untested code).
**Impact on plan:**
- The must-haves hold, with one stated limit: CI reaches swtpm through unixio, not the production device path.
- `test/e2e/harness_test.go` and `bootstrap_test.go` are unchanged.

## Issues Encountered

- WSL `sudo` needs a password, so the local runs used swtpm and libtpms0 extracted without root (`apt-get download` + `dpkg -x` into `~/.cache/keyroster/pkgs/swtpm`), with `SWTPM`/`KEYROSTER_SWTPM` and `LD_LIBRARY_PATH` set only in the local wrapper.
- `golangci-lint` does not build the e2e tags in CI. Under `e2e_tpm` it reports pre-existing gosec findings in the harness and `bootstrapSigner`/`serve` as unused, because this suite uses `prepareSigner` plus its own restartable serve. Nothing fails.

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat register:
- The TPM device and the swtpm test socket are the only new I/O.
- The workflow has `permissions: {}`, read-only contents, SHA-pinned actions and `persist-credentials: false`, and installs only Ubuntu archive packages.
- Threat mitigations: T-01-49 (per-key auth values, 0600), T-01-50 (manufacturer custody) and T-01-52 (one mutex, race-tested) are implemented.
- T-01-51 (test transport diverging from production) is only partly mitigated. The simulator package is denied, but the planned mitigation "CI prefers vtpm-proxy (same path)" is not met, because CI uses the unixio transport. The gap is documented in `custody.md`, and 01-14's dogfood is the first run of the `/dev/tpmrm0` path.

## User Setup Required

None.

## Next Phase Readiness

- **01-13:**
  - `doctor` should warn on custody `vtpm`, using `CustodyForManufacturer` and the bundle custody.
  - The systemd unit should restrict the device with `DeviceAllow=/dev/tpmrm0 rw` and keep `{state-dir}/tpm` owned by the signer user (T-01-49).
- **01-14:** the homelab dogfood runs `ca-init --backend tpm` on the Proxmox vTPM through `/dev/tpmrm0`, the first run of the production device path. Expect `TPM manufacturer: IBM → custody vtpm`.
- **01-15:** make `e2e-tpm` a required check.
- **KEY-04 is still Pending in REQUIREMENTS.md.** 01-14 declares it too and has no SUMMARY yet, so GSD's shared-ID gate (`requirements.ready-ids`) left the checkbox open. 01-14 marks it Complete.
- **Known limitation:** the TPM owner hierarchy auth is assumed to be empty, which is the default. A TPM with an owner password would need a new option.

## Self-Check: PASSED

- All 10 created files exist on disk.
- Commits `3a329b7`, `0677e98`, `58a02a4`, `d7b1556` and `0b38776` are on `origin/p01/11-tpm`; the task commits and `0b38776` are verified on GitHub.
- `actuals.commits` (5) is `git rev-list --count 79794b1..0b38776`. It includes the first SUMMARY commit `d7b1556`, because the fix landed after it. `actuals.tasks` (3) counts the tasks before the merge gate, as STATE does: the Task 1 legitimacy gate plus Tasks 2 and 3.
- Acceptance criteria were re-run:
  - go.mod has the pinned keyfiles version;
  - `.golangci.yml` denies the simulator;
  - key files are 0600 in a 0700 directory (`TestProvisionSignReopen`);
  - `CustodyForManufacturer("IBM") == "vtpm"` and `("INTC") == "tpm"`;
  - custody `vtpm` for all five keys in ca-pubkeys.json and the bundle (`assertTPMKeys`);
  - the custody doc contains vtpm, Proxmox and SOFTWARE ROOT;
  - `go list -deps` is clean.
