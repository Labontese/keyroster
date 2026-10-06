---
phase: 01-trust-core
plan: 13
subsystem: infra
tags: [systemd, sandbox, seccomp, sysusers, doctor, capslock, dependency-firewall, go-list, tpm, vtpm, runbook, ci]

requires:
  - phase: 01-09
    provides: software roots with custody=software (SOFTWARE ROOT banner) that doctor flags
  - phase: 01-11
    provides: TPM backend, CustodyForManufacturer, vtpm custody, custody.md
  - phase: 01-05
    provides: serve's start-up log check (now exported as signer.CheckLog)
  - phase: 01-02
    provides: finding that os/exec reaches the signer through modernc.org/libc
provides:
  - deploy/systemd/keyroster-signer.service (sandboxed signer unit, exposure 0.7 SAFE)
  - deploy/systemd/keyroster-signer-agent.service (the signer's own ssh-agent, never forwarded)
  - deploy/systemd/keyroster-signer.service.d/tpm.conf (only SupplementaryGroups=tss, DeviceAllow=/dev/tpmrm0 rw)
  - deploy/sysusers.d/keyroster.conf (user keyroster-signer, group keyroster-admin)
  - CI checks systemd-sandbox, dependency-firewall, capslock (to become required in 01-15)
  - keyroster-signer doctor --state-dir [--backend-opt] and package internal/doctor
  - signer.CheckLog, signerdb.(*DB).IntegrityCheck, tpm.Inspect
  - test/capslock/keyroster-signer.json baseline (22 packages, 73 package/capability pairs)
  - docs/runbooks/signer-install.md
affects: [01-14, 01-15]

actuals:
  tokens: 25000
  tasks: 3
  commits: 9
plan_head_before: 4e132a609a5ec63676485747ad950e7961b0cb0f
plan_head_after: de6a2389cd25d732c254b30af55aefa85f2e2bbf

tech-stack:
  added: ["github.com/google/capslock v0.3.3 (tools/go.mod only)"]
  patterns:
    - "Pure check package (internal/doctor) over gathered Facts; the command gathers read-only and turns every read failure into a FAIL, never a silent OK"
    - "Dependency firewall exceptions are (banned package, importer) pairs, so a banned package from any other importer still fails"
    - "capslock baseline at (package, capability) granularity via -output package"

key-files:
  created:
    - deploy/systemd/keyroster-signer.service
    - deploy/systemd/keyroster-signer-agent.service
    - deploy/systemd/keyroster-signer.service.d/tpm.conf
    - deploy/sysusers.d/keyroster.conf
    - test/systemd/smoke.sh
    - .github/workflows/systemd.yml
    - internal/doctor/doctor.go
    - internal/doctor/doctor_test.go
    - cmd/keyroster-signer/doctor.go
    - cmd/keyroster-signer/doctor_test.go
    - internal/keystore/tpm/inspect.go
    - test/e2e/doctor_test.go
    - test/e2e/doctor_tpm_test.go
    - scripts/dep-firewall.sh
    - scripts/capslock-check.sh
    - test/capslock/keyroster-signer.json
    - docs/runbooks/signer-install.md
  modified:
    - internal/signer/logstate.go
    - internal/signerdb/db.go
    - internal/keystore/tpm/vendor_test.go
    - .golangci.yml
    - .github/workflows/ci.yml
    - tools/go.mod
    - tools/go.sum
    - docs/runbooks/root-ceremony.md
    - .planning/phases/01-trust-core/deferred-items.md

key-decisions:
  - "01-13: the signer unit re-allows @chown after ~@privileged, because @privileged contains @chown and the signer chgrps its socket to keyroster-admin; without capabilities chown can only give an owned file to a group the caller is in (costs 0.2 exposure)"
  - "01-13: the capslock baseline is (package, capability) pairs from -output package, not capability names; the signer already reaches 11 of 13 capabilities, so a name-only diff could catch only CGO or OPERATING_SYSTEM"
  - "01-13: one dependency-firewall exception, os/exec <- modernc.org/libc: in the linux build libc uses os/exec only in Xsystem, and modernc.org/sqlite v1.60.1 never references Xsystem or Xpopen; strace.go (also exec) is //go:build ignore"
  - "01-13: systemd-analyze security threshold 20 (exposure 2.0) is set in systemd.yml; measured exposure 0.7 SAFE (signer) and 1.3 OK (agent)"
  - "01-13: doctor reports vtpm keys as WARN vtpm_custody and gives an OK custody line only when every online key is tpm, piv or pkcs11-agent and the live TPM matches; OK tpm is a consistency line only"
  - "01-13: capslock -tags piv and a real piv pass of the dependency firewall are deferred to 01-15, because PR #14 (PIV) was not on main"

patterns-established:
  - "Systemd smoke test on a real runner: install units, bootstrap, check namespace, /proc status and systemd-analyze, all in one root script"
  - "Every untested production path is listed in the PR body and the SUMMARY under 'Not exercised in CI'"

requirements-completed: [KEY-01, REPO-02]

coverage:
  - id: D1
    description: "keyroster-signer runs under systemd as keyroster-signer with PrivateNetwork, AF_UNIX only, IPAddressDeny=any, no capabilities, seccomp; its netns holds only lo; a keyroster-admin member issues over the socket, a non-member holding the admin key is refused; systemd-analyze exposure 0.7 <= 2.0"
    requirement: KEY-01
    verification:
      - kind: e2e
        ref: "test/systemd/smoke.sh (systemd-sandbox, run 37424951081 on de6a238)"
        status: pass
    human_judgment: false
  - id: D2
    description: "keyroster-signer doctor: FAIL for root, state dir, db mode, integrity, log mismatch, clock regression; WARN SOFTWARE ROOT, vtpm_custody, software_key_in_agent, custody_mismatch; no network, no os/exec"
    requirement: KEY-01
    verification:
      - kind: unit
        ref: "internal/doctor/doctor_test.go (all tests)"
        status: pass
      - kind: integration
        ref: "cmd/keyroster-signer/doctor_test.go#TestDoctorAfterCAInit, TestDoctorFailures, TestDoctorDoesNotCreateADatabase, TestDoctorUsage, TestDoctorImports"
        status: pass
      - kind: e2e
        ref: "test/e2e/doctor_test.go#TestDoctorReportsTestCustody (9.5p1, 10.5p1); test/e2e/doctor_tpm_test.go#TestTPMDoctor (swtpm); internal/keystore/tpm#TestInspectSWTPM"
        status: pass
    human_judgment: false
  - id: D3
    description: "Dependency firewall: no banned package in go list -deps ./cmd/keyroster-signer (linux, default and -tags piv) except os/exec <- modernc.org/libc"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "bash scripts/dep-firewall.sh (dependency-firewall job; local negative runs exit 1)"
        status: pass
    human_judgment: false
  - id: D4
    description: "capslock baseline: CI fails on any new (package, capability) pair for cmd/keyroster-signer"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "bash scripts/capslock-check.sh (capslock job; local tampered-baseline run exits 1)"
        status: pass
    human_judgment: false
  - id: D5
    description: "docs/runbooks/signer-install.md takes an admin from a Debian/Ubuntu VM with a vTPM to a sandboxed signer"
    verification: []
    human_judgment: true
    rationale: "The TPM path of the runbook (tpm.conf, /dev/tpmrm0, runuser -G tss) has not run anywhere; it is first exercised on the homelab VM in 01-14. Readability and completeness need the owner."

duration: 47min
completed: 2026-10-06
status: complete
---

# Phase 1 Plan 13: Sandbox and Doctor Summary

**keyroster-signer runs under a hardened systemd unit with only `lo` in its network namespace (systemd-analyze exposure 0.7 SAFE, proven on a real runner), `keyroster-signer doctor` fails on unsafe state and warns loudly about software roots, vTPM and agent-held keys, and CI now blocks banned dependencies (go list firewall) and any new package capability (capslock v0.3.3 baseline).**

## Performance

- **Duration:** 47 min
- **Started:** 2026-10-06T05:59:40Z
- **Completed:** 2026-10-06T06:46:33Z
- **Tasks:** 3 of 4 (Task 4 is the merge gate)
- **Files modified:** 26 (code head de6a238)
- **PR:** #15 (`feat(deploy): sandbox keyroster-signer under systemd and add doctor`), auto-merge (squash) enabled

## Accomplishments

- **Sandboxed signer, proven on a systemd host.** `systemd-sandbox` (run 37424951081 on de6a238) installs the units and the sysusers file, bootstraps the signer with the agent backend, and checks the following:
  - `kradmin` (in `keyroster-admin`) gets a certificate signed by the user CA.
  - `outsider` holding a copy of the admin key gets `connect: permission denied`.
  - `nsenter -n ip -br link` shows only `lo`.
  - `systemctl show` reports `PrivateNetwork=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`, `User=keyroster-signer`, `UMask=0077` and `LimitCORE=0`.
  - `/proc/PID/status` shows `CapEff`/`CapBnd` 0, `NoNewPrivs` 1 and `Seccomp` 2.
  - `doctor` passes, and `systemd-analyze security --threshold=20` passes.
- **doctor.** `doctor` holds pure checks in `internal/doctor`. `keyroster-signer doctor` gathers its facts read-only:
  - the database through `OpenReadOnly`, so it never creates one;
  - `PRAGMA integrity_check`;
  - serve's own start-up log check, exported as `signer.CheckLog`;
  - the latest bundle and `ca_keys`;
  - for the TPM backend, the live manufacturer through `tpm.Inspect`.
- **Dependency firewall.** It checks the signer's graph with and without `-tags piv`. The only exception is the documented `os/exec <- modernc.org/libc`.
- **capslock baseline.** The baseline is 22 packages and 73 (package, capability) pairs, with capslock v0.3.3 pinned and sumdb-verified.
- **Install runbook.** It covers the vTPM caveat, the `tpm.conf` drop-in, `doctor` and the snapshot-restore clock check. It says plainly which steps have not run.

## systemd-analyze security (recorded)

- `keyroster-signer.service`: **0.7 SAFE**, threshold 20 (= 2.0) set in `.github/workflows/systemd.yml`. Remaining ✗ directives:
  - `SystemCallFilter=~@privileged` 0.2 (`@chown` is re-allowed);
  - `RootDirectory=/RootImage=` 0.1;
  - `SupplementaryGroups=` 0.1;
  - `PrivateDevices=` 0.2 (needed for `/dev/tpmrm0` through the drop-in);
  - `RestrictAddressFamilies=~AF_UNIX` 0.1;
  - `PrivateUsers=` 0.2;
  - `DeviceAllow=` 0.1 (char-rtc:r, the default).
- `keyroster-signer-agent.service`: 1.3 OK (informational, not gated).
- These scores are for the units without the `tpm.conf` drop-in, which the runner cannot load (no `tss` group, no TPM).

## capslock baseline (test/capslock/keyroster-signer.json)

Capability names reached by `cmd/keyroster-signer` (GOOS=linux GOARCH=amd64 CGO_ENABLED=0). One sentence each:

- **FILES:** the signer reads and writes its state directory, `signer.db` and the TPM key files, and opens `/dev/tpmrm0` (os, modernc.org/libc, go-tpm linuxtpm).
- **NETWORK:** Unix sockets only. These are `net.ListenUnix` for the signer socket, the ssh-agent client dial (keystore/agent) and the swtpm `unixio` transport (linuxudstpm). The unit's `RestrictAddressFamilies=AF_UNIX` and `PrivateNetwork` enforce that at run time.
- **EXEC:** capslock reaches `os/exec` only through an over-approximated interface call, `signerdb.Open → (*sql.DB).Close → (*os/exec.Cmd).writerDescriptor$1`. No signer code runs a program, and `modernc.org/libc` itself has no EXEC entry. See the firewall exception below.
- **ARBITRARY_EXECUTION:** this comes from `crypto/fips140.isBypassed`, reached through `(*ssh.dsaPublicKey).Verify` by interface dispatch. It is not a DSA acceptance path: sshsig refuses non-Ed25519/ECDSA keys before verifying.
- **MODIFY_SYSTEM_STATE:** `os/signal` (SIGINT/SIGTERM handling in serve), the umask, and libc/sqlite file-locking state.
- **READ_SYSTEM_STATE:** `os/user` (resolving `--allow-group`), `runtime/debug` (version build info) and environment/system reads in os and libc.
- **REFLECT:** `encoding/json` (bundle, policy and backend options) and go-tpm's `tpm2` marshalling.
- **RUNTIME:** `runtime/debug.ReadBuildInfo` for `version`, plus runtime hooks in the SQLite stack.
- **SYSTEM_CALLS:** `syscall`/`x/sys/unix` (SO_PEERCRED, umask, stat), go-tpm's ioctl-free device I/O, and modernc.org/libc and memory (mmap).
- **UNANALYZED:** calls through function values that capslock cannot resolve, in `bufio`, `errors` and `io` used by audit, keystore, the agent client and signerdb.
- **UNSAFE_POINTER:** the transpiled SQLite (`modernc.org/sqlite`, `sqlite/lib`) and `internal/strconv`.

Not reached: CGO and OPERATING_SYSTEM. The check fails on any new (package, capability) pair. The negative test removed `signerdb EXEC` and the `modernc.org/libc` entry from a copy of the baseline; the check reported 5 new pairs and exited 1. `--update` rewrites the baseline in a reviewed PR.

## Dependency firewall exceptions

- `os/exec <- modernc.org/libc` (locked SQLite stack, finding from 01-02).
  - In the linux build, the only `exec.` use in libc is in `func Xsystem` (`libc_musl.go:1196`, `exec.Command("sh", "-c", ...)`). `strace.go`, which also uses exec, is `//go:build ignore`.
  - `grep` finds no `Xsystem` or `Xpopen` anywhere in `modernc.org/sqlite` v1.60.1.
  - The exception names its importer, so `os/exec` imported by anything else fails.
- Negative runs, local WSL with real exit codes:
  - exception removed: exit 1 (`BANNED: os/exec <- modernc.org/libc`);
  - temporary `import _ "net/http"` in `cmd/keyroster-signer`: exit 1;
  - clean: exit 0.
- Default pass: 224 packages. Piv pass: 225, the extra package being `runtime/cgo`.

## Supply chain (T-01-SC)

`go get -tool github.com/google/capslock/cmd/capslock@v0.3.3` in `tools/`. This is the CLAUDE.md research pin and the latest version on proxy.golang.org.

- Modules added to `tools/go.sum`:
  - `capslock` v0.3.3
  - `fatih/color` v1.19.0
  - `mattn/go-colorable` v0.1.14
  - `mattn/go-isatty` v0.0.20
  - `google.golang.org/protobuf` v1.36.11
  - plus a `golang.org/x/sys` v0.6.0 `go.mod` hash
- Every `h1:` line matches `https://sum.golang.org/lookup/<module>@<version>`, and `go mod verify` in `tools/` reports "all modules verified".
- No existing tool version changed: x/tools stays at v0.50.0 and govulncheck at v1.8.0.
- These modules are tools only and are never linked into a product binary.

## Task Commits

1. **Task 1: systemd tracer:**
   - `f6238c4` (feat), PR #15 opened.
   - `cb4a628` (fix: `install -D` for `/etc/sysusers.d`, which is missing on the runner).
   - The tracer gate re-ran `<verify>` on CI and it was green on 567ad93.
2. **Task 2: doctor (TDD):**
   - `f142b94` (test, RED);
   - `567ad93` (feat, GREEN; also `chmod 0600` of the admin key in `smoke.sh`);
   - `3c6cd7c` (fix: gosec G302 nolint in tests, SOFTWARE ROOT wording).
3. **Task 3: firewall, capslock, runbook:**
   - `5d011de` (feat);
   - `8af244d` (fix: capslock version label);
   - `e828544` (ci: threshold in `systemd.yml`);
   - `de6a238` (docs: untested runbook steps). Its scope is `docs(runbooks)`, not `docs(01-13)`: a slip, left as is because the commit was already pushed.

**Plan metadata:** `docs(01-13): complete sandbox and doctor plan` (this commit).

## TDD Gate Compliance (Task 2)

| Gate | Commit | Command | Result |
|------|--------|---------|--------|
| RED | `f142b94` test(01-13) | `go test -count=1 -v ./internal/doctor/...` and `bash scripts/linux.sh 'go test -count=1 -v -run Doctor ./cmd/keyroster-signer/...'` | Exit 1 for both, with every failure on an assertion. In `internal/doctor`, all 15 tests fail (for example "want exactly one FAIL running_as_root, got []"). In `cmd/keyroster-signer`, the `ca-init` setup succeeds, and then `TestDoctorAfterCAInit` (exit 1, want 0), the 6 `TestDoctorFailures` subtests (no `FAIL …` line), `TestDoctorDoesNotCreateADatabase` and `TestDoctorUsage` (exit 1, want 2) fail. `TestDoctorImports` passed at RED as expected, because the stub imports nothing. |
| GREEN | `567ad93` feat(01-13) | same commands, plus the race tests of signer, signerdb and keystore | Exit 0, all pass. |

- The RED commit contains the API skeleton the plan names (types and constants; `Run` returns nothing) and a stub `doctor` command, so that the tests compile and fail on assertions rather than as INVALID_RED.
- Some code arrived with GREEN, not RED-first: `tpm.Inspect` and `TestInspectSWTPM`, the e2e doctor tests (`TestDoctorReportsTestCustody`, `TestTPMDoctor`), `signer.CheckLog` and `signerdb.IntegrityCheck`.
- `gsd-tools check tdd-red-evidence` parses only TAP/Surefire, so the Go RED evidence is recorded here (the 01-02 decision).

## Files Created/Modified

- `deploy/systemd/*`, `deploy/sysusers.d/keyroster.conf`: the units, the drop-in and the identities.
- `test/systemd/smoke.sh`, `.github/workflows/systemd.yml`: the `systemd-sandbox` check.
- `internal/doctor/*`, `cmd/keyroster-signer/doctor{,_test}.go`: doctor.
- `internal/signer/logstate.go`: `rebuildLog` is factored into `rebuildLogFrom(ctx, db, verifier)`, and the new `CheckLog` exposes it read-only. Behaviour is unchanged; the signer race tests are green.
- `internal/signerdb/db.go`: `IntegrityCheck`.
- `internal/keystore/tpm/inspect.go`, plus `vendor_test.go#TestInspectSWTPM`.
- `test/e2e/doctor_test.go` (tag `e2e`), `test/e2e/doctor_tpm_test.go` (tag `e2e_tpm`).
- `scripts/dep-firewall.sh`, `scripts/capslock-check.sh`, `test/capslock/keyroster-signer.json`, `tools/go.mod`, `tools/go.sum`, `.github/workflows/ci.yml` (jobs `dependency-firewall`, `capslock`).
- `.golangci.yml`: depguard `signer-no-network` now covers `internal/doctor`.
- `docs/runbooks/signer-install.md`. `docs/runbooks/root-ceremony.md`: the command is `keyroster-signer doctor`, not `keyroster doctor`.
- `.planning/phases/01-trust-core/deferred-items.md`: three entries.

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `@chown` re-allowed in the signer's system-call filter**
- **Found during:** Task 1.
- **Issue:** The plan's `SystemCallFilter=~@privileged` also removes `@chown`, but `signer.Listen` chgrps its socket to `keyroster-admin`.
- **Fix:** `SystemCallFilter=@chown` after the deny list, with a comment. Without capabilities, chown can only give an owned file to a group the caller is in. This costs 0.2 exposure.
- **Verification:** The smoke test shows a socket `srw-rw---- keyroster-signer keyroster-admin`.
- **Committed in:** `f6238c4`.

**2. [Rule 3 - Blocking] Agent unit differs from "same hardening as the signer"**
- **Found during:** Task 1.
- **Issue:** ssh-agent calls `setgid(getgid())` at start and ignores the result. Under `~@privileged`, the default seccomp action would kill it.
- **Fix:**
  - `SystemCallErrorNumber=EPERM`, on the agent unit only;
  - `Type=exec`, `Before=keyroster-signer.service` and an `[Install]` section on both units.
- **Verification:** The agent unit starts and serves on the runner.
- **Committed in:** `f6238c4`.

**3. [Rule 3 - Blocking] Smoke-test fixes found on the runner**
- **Found during:** Task 1 and Task 2.
- **Issue:**
  - `/etc/sysusers.d` does not exist on ubuntu-24.04.
  - The admin private key under `/home/kradmin` came out mode 0644, which ssh-add refuses. The cause was not investigated.
- **Fix:**
  - `install -D` for the sysusers file;
  - `chmod 0600` on the admin key;
  - the workflow runs `sudo env "PATH=$PATH" …`, because sudo's `secure_path` hides the setup-go toolchain.
- **Committed in:** `cb4a628`, `567ad93`.

**4. [Rule 2 - Missing critical] A stronger negative case**
- **Found during:** Task 1.
- **Issue:** The `outsider` case needed a precise check.
- **Fix:** `outsider` gets a copy of the admin key, so the request carries valid evidence and only the socket's group permission stops it.
- **Verification:** `connect: permission denied`.

**5. [Rule 2 - Missing critical] capslock baseline at (package, capability) granularity**
- **Found during:** Task 3.
- **Issue:** The plan asks for the sorted set of capability names. The signer already reaches 11 capabilities, so a name-only diff could catch only CGO or OPERATING_SYSTEM. That leaves T-01-61 (capability creep) effectively unmitigated.
- **Fix:** `-output package` is reduced to (package, capability) pairs. The baseline file is capslock's JSON verbatim.
- **Verification:** The tampered-baseline run exits 1.
- **Committed in:** `5d011de`.

**6. [Rule 3 - Blocking] Files outside the plan's file list**
- **Found during:** Task 2.
- **Issue:** `doctor` must reuse serve's log check and read integrity and the TPM manufacturer without opening the full backend.
- **Fix:**
  - `internal/signer/logstate.go` (`CheckLog`);
  - `internal/signerdb/db.go` (`IntegrityCheck`);
  - `internal/keystore/tpm/inspect.go` and its test;
  - `.golangci.yml` (depguard covers `internal/doctor`, Rule 2);
  - two e2e test files, so that the bundle and TPM paths of `doctor` run in CI;
  - `docs/runbooks/root-ceremony.md` (wrong command name);
  - `deferred-items.md`.
- **Committed in:** `567ad93`, `5d011de`.

**7. [Rule 2 - Missing critical] doctor additions beyond the plan's list**
- **Found during:** Task 2.
- **Fix:**
  - code `software_key` (online keys with custody software, or an unknown custody, are never OK);
  - code `tpm_unavailable` (the TPM cannot be read: WARN, never a silent OK);
  - `Facts.StateDirError`, `DBError`, `IntegrityDetail`, `LogDetail`, `TPMCustody` and `TPMError`, so that unreadable facts become FAIL or WARN;
  - `doctor --backend-opt`, matching `serve`, so that doctor reaches the same TPM a serve override points at;
  - an OK `tpm` consistency line.
- **Committed in:** `567ad93`.

**8. [Plan detail] `dependency-firewall` installs no `libpcsclite-dev`**
- **Issue:** The plan asks for `libpcsclite-dev` "for the piv pass". `go list -deps` does not run cgo, so it should not need the headers.
- **Status:** This is unproven until PIV code is on the branch (see deferred-items). capslock with `-tags piv` would need the headers; it is deferred.

---

**Total deviations:** 8: 1 bug, 3 blocking, 3 missing critical, 1 plan detail.
**Impact on plan:** Every must-have holds as written. The capslock gate is stricter than planned. The threshold stays at 2.0.

## Not Exercised in CI (stated plainly)

- **The TPM path under systemd:** the `tpm.conf` drop-in, `/dev/tpmrm0`, group `tss`, and the runbook's `runuser -g keyroster-signer -G tss` commands. The runner has no TPM, so the smoke test uses the agent backend. This path is first exercised on the homelab VM in 01-14.
- **`doctor`'s live TPM read on a physical TPM** (custody `tpm`). CI runs swtpm only (IBM → `vtpm`: `TestInspectSWTPM`, `TestTPMDoctor`). The mapping itself is unit-tested (`TestCustodyForManufacturer`).
- **The agent unit's PKCS#11 path:**
  - `-P` loading a module through `ssh-pkcs11-helper` under NoNewPrivileges, MemoryDenyWriteExecute and the filter;
  - `SystemCallErrorNumber=EPERM`;
  - `IPAddressAllow=localhost` for yubihsm.

  The smoke test loads plain keys only.
- **capslock `-tags piv`, and the firewall's piv pass against real PIV code.** Deferred to 01-15 (deferred-items.md). On this branch the piv pass equals the default pass plus `runtime/cgo`.
- **The runbook's reproducible-build hash comparison.** It needs the same Go toolchain and has not been verified by keyroster (Phase 6).
- **The `TestSignerRefusals/created_301s_future` flake** did not occur on PR #15 and stays deferred; no signer test file was touched.

## Threat Flags

None. doctor adds read-only file, database and TPM-capability access for the signer's own user. It adds no network, exec or trust-boundary surface, and depguard plus `TestDoctorImports` pin that.

## Issues Encountered

None beyond the deviations above.

## User Setup Required

None for this plan. Making `systemd-sandbox`, `dependency-firewall` and `capslock` required checks is an owner ruleset change planned for 01-15.

## Next Phase Readiness

- 01-14 (homelab dogfood) can follow `docs/runbooks/signer-install.md` on the Proxmox VM. It exercises the untested TPM-under-systemd path and should record `doctor`'s output there: expect `WARN vtpm_custody` and `WARN software_root`.
- 01-15: make the three new checks required, add capslock `-tags piv` (with `libpcsclite-dev`) and confirm the firewall's piv pass, once PR #14 and PR #15 are both on `main`.

## Self-Check: PASSED

- All 17 created files listed in key-files exist.
- All 9 plan commits exist: f6238c4, f142b94, cb4a628, 567ad93, 3c6cd7c, 5d011de, 8af244d, e828544, de6a238.
- `tools/go.mod` has the `github.com/google/capslock/cmd/capslock` tool line at v0.3.3.
- The runbook contains `tpm.conf` (4×), `doctor` (11×) and `clock` (8×).
- `doctor_test.go` asserts the `SOFTWARE ROOT:` prefix and code `vtpm_custody`.
- `cmd/keyroster-signer/doctor.go` imports neither `os/exec` nor `net`.
- All 17 checks on PR #15 were green at code head de6a238.

---
*Phase: 01-trust-core*
*Completed: 2026-10-06*
