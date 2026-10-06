---
phase: 01-trust-core
plan: 10
subsystem: keystore-pkcs11
tags: [pkcs11, softhsm2, yubihsm2, ssh-agent, ssh-pkcs11-helper, askpass, ed25519, p256, e2e, ci]

requires:
  - phase: 01-08
    provides: "audit verify --pin/--threshold anchored on the trust root; bootstrapSigner used unchanged"
  - phase: 01-07
    provides: "ca-init with --backend agent --backend-opt custody=pkcs11-agent and --key ROLE=fp, install-bundle --pin, bootstrapOpts (RoleKeys, RootAgentSocket/RootFingerprint/RootCustody)"
  - phase: 01-02
    provides: "agent keystore backend: pinned-fingerprint key selection, one mutex around the agent connection, custody pkcs11-agent"
  - phase: 01-04
    provides: "scripts/build-openssh.sh and the e2e harness (startDaemon, startSSHD, sshLogin)"
provides:
  - "scripts/softhsm-setup.sh DIR p256|ed25519: separate CA and root SoftHSM2 tokens (DIR/ca, DIR/root), 0600 PIN file, 0700 askpass helper; prints the resolved module path"
  - "test/e2e/pkcs11_test.go (tag e2e_pkcs11): TestPKCS11FullFlow, TestPKCS11Ed25519, TestPKCS11RootSignsBundle, TestPKCS11CAInitTwiceRefused, TestPKCS11ConcurrentIssue; env KEYROSTER_SSH_AGENT, KEYROSTER_PKCS11_KEYTYPE"
  - "test/e2e/fingerprint_test.go: fingerprint helper for e2e_pkcs11 / e2e_tpm builds without the e2e tag"
  - ".github/workflows/e2e-pkcs11.yml: checks e2e-pkcs11 (distro-p256) and e2e-pkcs11 (10.5p1-ed25519)"
  - "docs/backends/pkcs11.md: YubiHSM 2 / PKCS#11 operator guide"
affects: [01-11, 01-13, 01-15, Phase 6 (needs-hardware review: real YubiHSM 2)]

actuals:
  tokens: 10913
  tasks: 2
  commits: 2
plan_head_before: faba1ce3c95098b2ef2961025399bc522e5473d6
plan_head_after: 5f6c732e88c2b5c69837c1e767d5f1607dc5f3e3

tech-stack:
  added: []
  patterns:
    - "Each PKCS#11 token gets its own SoftHSM2 config and its own ssh-agent (-D -a SOCK -P MODULE); an agent that loads a module sees every token in that module's token directory, so the CA and root keys are separated by configuration, not by PIN"
    - "PINs never reach argv: pkcs11-tool reads env:NAME, ssh-add reads SSH_ASKPASS with SSH_ASKPASS_REQUIRE=force; the test scans every /proc/*/cmdline and all captured output for the PIN"
    - "ssh-agent -P is matched against the resolved provider path, so the setup script prints readlink -f of the module"
    - "A capability that depends on the agent version is tested both ways: Ed25519 PKCS#11 runs the full flow on ssh-agent >= 10.1 and asserts refusal on older agents, so the documented minimum is pinned by CI"

key-files:
  created:
    - scripts/softhsm-setup.sh
    - test/e2e/pkcs11_test.go
    - test/e2e/fingerprint_test.go
    - .github/workflows/e2e-pkcs11.yml
    - docs/backends/pkcs11.md
  modified: []

key-decisions:
  - "01-10: CA and root SoftHSM2 tokens live in separate token directories (DIR/ca, DIR/root) with one config each, so each agent can only ever see its own token (T-01-47); the plan's single DIR/softhsm2.conf would have loaded the root key into the CA agent"
  - "01-10: PINs reach pkcs11-tool through env:NAME (softhsm2-util and pkcs11-tool read PINs only from a TTY or argv), so no PIN is ever a command-line argument; tokens are initialised with pkcs11-tool, not softhsm2-util"
  - "01-10: TestPKCS11Ed25519 runs the Ed25519 flow on ssh-agent 10.1+ and, on older agents (the distro-p256 lane, 9.6p1), asserts that the agent refuses Ed25519 PKCS#11 keys, rather than skipping"
  - "01-10: the e2e_pkcs11 build needs fingerprint(), which only issue_test.go (tag e2e) defined; test/e2e/fingerprint_test.go (tag !e2e && (e2e_pkcs11 || e2e_tpm)) provides it without editing the harness or other suites, and also unblocks 01-11"

patterns-established:
  - "newPKCS11Setup(t, agentBin, keytype) returns both token agents, role fingerprints by label (ssh-keygen -D) and the root fingerprint; s.opts() feeds bootstrapSigner"
  - "Concurrent CLI calls in e2e run exec directly in wg.Go goroutines and are checked on the test goroutine (no t.Fatal off the test goroutine)"

requirements-completed: [KEY-03]

coverage:
  - id: D1
    description: "CA keys generated inside a SoftHSM2 token and reached only through ssh-agent + ssh-pkcs11-helper drive ca-init (custody pkcs11-agent), install-bundle, an admin-signed ca issue, an sshd 10.5p1 login and audit verify --pin; the verified bundle records custody pkcs11-agent and the token's algorithm for user, host, machine, ops and log"
    requirement: KEY-03
    verification:
      - kind: e2e
        ref: "test/e2e/pkcs11_test.go#TestPKCS11FullFlow (CI e2e-pkcs11 (distro-p256) P-256 and e2e-pkcs11 (10.5p1-ed25519) Ed25519 on PR #11; local WSL both lanes)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Two algorithm lanes: P-256 on Ubuntu's 9.6p1 ssh-agent, Ed25519 on the self-built 10.5p1 ssh-agent; the 9.6p1 agent provably refuses Ed25519 PKCS#11 keys"
    requirement: KEY-03
    verification:
      - kind: e2e
        ref: "test/e2e/pkcs11_test.go#TestPKCS11Ed25519 (full flow on 10.5p1; refusal assertion on 9.6p1, CI log: ssh-agent 9.6 refuses Ed25519 PKCS#11 keys as expected)"
        status: pass
    human_judgment: false
  - id: D3
    description: "A root key in a separate PKCS#11 token (PIV-root stand-in) signs the genesis bundle through its own agent; install-bundle refuses the same bundle before the root signature exists and accepts it after; bundle root custody pkcs11"
    requirement: KEY-07
    verification:
      - kind: e2e
        ref: "test/e2e/pkcs11_test.go#TestPKCS11RootSignsBundle (CI both lanes on PR #11)"
        status: pass
    human_judgment: false
  - id: D4
    description: "The PIN reaches ssh-add only through SSH_ASKPASS from a 0600 file; it is absent from the setup output, both agents' logs, ssh-add output, CLI output and every process command line"
    requirement: KEY-03
    verification:
      - kind: e2e
        ref: "test/e2e/pkcs11_test.go#TestPKCS11FullFlow (assertNoPINLeak: captured outputs and /proc/*/cmdline)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Edge cases: a second ca-init with the same PKCS#11 keys is refused (already initialised) and leaves ca_keys, ca-pubkeys.json and the audit log unchanged; eight concurrent admin-signed issuances return distinct serials, all accepted by sshd, and the export verifies"
    requirement: KEY-03
    verification:
      - kind: e2e
        ref: "test/e2e/pkcs11_test.go#TestPKCS11CAInitTwiceRefused, #TestPKCS11ConcurrentIssue (CI both lanes on PR #11)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Operator guide docs/backends/pkcs11.md (YubiHSM 2 connector and auth key, dedicated -P agent never forwarded, askpass PIN file, 10.1 Ed25519 minimum, 10.5 recommendation, ca-init flags, needs-hardware item)"
    requirement: KEY-03
    verification:
      - kind: other
        ref: "grep for 10.1, -P, askpass, needs-hardware in docs/backends/pkcs11.md"
        status: pass
    human_judgment: true
    rationale: "Accuracy and usability of the YubiHSM 2 steps cannot be proven without real hardware (needs-hardware, Phase 6); the owner reviews the guide in the PR"
  - id: D7
    description: "PR #11 with every check green, waiting for the owner at the merge gate"
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks 11 --watch on 5f6c732: build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1), fuzz, e2e-pkcs11 (distro-p256), e2e-pkcs11 (10.5p1-ed25519), pinned-actions, CodeQL pass"
        status: pass
    human_judgment: true
    rationale: "The owner reviews and approves the PR at the merge gate (Task 3); approval is a human decision"

duration: 25min
completed: 2026-10-05
status: complete
---

# Phase 1 Plan 10: PKCS#11 HSM Backend Summary

**The five online CA keys live in a SoftHSM2 token, standing in for a YubiHSM 2. A dedicated OpenSSH ssh-agent with a `-P` allowlist reaches the token only through `ssh-pkcs11-helper`. With these keys the whole keyroster flow works: ca-init with custody `pkcs11-agent`, a genesis bundle signed by a root in its own token (custody `pkcs11`), install-bundle, an admin-signed issue, a real sshd login and `audit verify --pin`. CI covers P-256 on Ubuntu's 9.6p1 agent and Ed25519 on a 10.5p1 agent, and the PIN never appears in argv or in logs.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-10-05T14:15:15Z
- **Completed:** 2026-10-05T14:39:51Z
- **Tasks:** 2 of 3 executed (Task 3 is the merge gate)
- **Files modified:** 5 (all created)

## Accomplishments

- **`scripts/softhsm-setup.sh DIR p256|ed25519`** creates two tokens:
  - `keyroster-ca` holds `user-ca`, `host-ca`, `machine-ca`, `ops` and `log` (CKA_ID 01-05).
  - `keyroster-root` holds `root`.
  - Each token has its own token directory and `softhsm2.conf`.
  - The user PIN is random, 128-bit, in a 0600 file, and is read by a 0700 askpass helper. The SO PIN is random and discarded.
  - The script prints the symlink-resolved module path.
- **Separate agents (T-01-47):** each token is loaded into its own `ssh-agent -D -a SOCK -P MODULE` with `SSH_ASKPASS=… SSH_ASKPASS_REQUIRE=force DISPLAY=:0 ssh-add -s MODULE`. The test asserts that the CA agent holds exactly the five CA keys and the root agent exactly the root key.
- **Full flow (KEY-03):** role keys are pinned by fingerprint from `ssh-keygen -D` labels. The flow runs ca-init (`--backend agent --backend-opt custody=pkcs11-agent`), root sign through the root agent, install-bundle `--pin`, serve, `ca issue`, login on sshd 10.5p1, export-log and `keyroster audit verify --pin --threshold 1`. The output is `OK: 3 entries, … issued 1`.
  - The bundle is verified with `trust.VerifyGenesisBundle`. It records `pkcs11-agent` and the token's algorithm for all five keys, and `pkcs11` for the root.
- **PIN never leaks (T-01-46):** the PIN is absent from:
  - the setup output, both agents' logs and both `ssh-add` outputs;
  - the issue and audit output;
  - every readable `/proc/*/cmdline` (agents and `ssh-pkcs11-helper` are running at that point).
- **Edge cases:**
  - A second `ca-init` is refused, both with the default output (it already exists) and with a fresh `--out` (`already initialised`, no file left behind). `ca_keys`, `ca-pubkeys.json` and the exported log stay byte-identical.
  - Eight parallel issuances get distinct serials, all signed by the token's user CA, and all eight log in on sshd. The export verifies with `issued 8`.
- **Operator guide** `docs/backends/pkcs11.md` covers:
  - YubiHSM 2 (connector on 127.0.0.1, `YUBIHSM_PKCS11_CONF`, a least-privilege auth key, PIN = key ID + password), Nitrokey HSM 2 and SmartCard-HSM;
  - the dedicated agent with `-P` that is never forwarded, and the askpass PIN file;
  - the 10.1 minimum for Ed25519 and the 10.5 recommendation;
  - `ca-init` flags, a root on a PKCS#11 token, and the needs-hardware item for Phase 6.

## Tool Versions per Lane (CI, PR #11)

| Lane | ssh-agent | SoftHSM2 | OpenSC (pkcs11-tool) | sshd/ssh/ssh-keygen under test |
|---|---|---|---|---|
| `e2e-pkcs11 (distro-p256)` | `/usr/bin/ssh-agent`, OpenSSH_9.6p1 Ubuntu-3ubuntu13.19 (openssh-client 1:9.6p1-3ubuntu13.19) | softhsm2 / libsofthsm2 2.6.1-2.2ubuntu3 | 0.25.0~rc1-1ubuntu0.2 | 10.5p1 (build-openssh.sh) |
| `e2e-pkcs11 (10.5p1-ed25519)` | OpenSSH_10.5p1 (build-openssh.sh prefix) | 2.6.1-2.2ubuntu3 | 0.25.0~rc1-1ubuntu0.2 | 10.5p1 |

Locally (WSL Ubuntu 24.04), both lanes passed with the same SoftHSM2/OpenSC packages extracted without root (`apt-get download` + `dpkg -x`, `SOFTHSM2_MODULE` override), because `sudo` in WSL asks for a password.

## PR

- PR **#11**, `test(pkcs11): verify CA keys in a PKCS#11 HSM through ssh-agent` (https://github.com/Labontese/keyroster/pull/11). keyroster-bot enabled auto-merge (squash).
- Every check passed on implementation head `5f6c732`:
  - required: `build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)`, `fuzz`;
  - new, not yet required (01-15 makes them required): `e2e-pkcs11 (distro-p256)` and `e2e-pkcs11 (10.5p1-ed25519)`;
  - also `pinned-actions`, `CodeQL`.
- Both PKCS#11 job logs show `--- PASS` for all five tests. The distro lane logs `ssh-agent 9.6 refuses Ed25519 PKCS#11 keys as expected`.
- Both implementation commits show `verified: true` on GitHub.
- The known flaky `TestSignerRefusals/created_301s_future` did not fail, so no rerun was needed.

## Task Commits

1. **Task 1: tracer, SoftHSM2 P-256 keys through the distro ssh-agent to the full flow:** `c462ae6` (test). Tracer gate (interactive, end-of-phase, automated-only `<verify>`): `TestPKCS11FullFlow` was re-run on the distro agent with P-256 (and on 10.5p1 with Ed25519) and passed, and `check-pinned-actions.sh` passed, so execution continued.
2. **Task 2: Ed25519 lane, token-held root, idempotency, concurrency, guide, PR:** `5f6c732` (test). PR #11 opened with auto-merge.
3. **Task 3: merge gate:** pending owner approval (checkpoint).

## Files Created/Modified

- `scripts/softhsm-setup.sh`: token setup (mode 100755).
- `test/e2e/pkcs11_test.go`: the five tests and their helpers (`newSoftHSM`, `startTokenAgent`, `tokenKeys`, `agentFingerprints`, `newPKCS11Setup`, `assertNoPINLeak`, `verifiedBundle`, `assertPKCS11Bundle`, `pkcs11IssueAndLogin`, `pkcs11AuditVerify`, `agentVersion`).
- `test/e2e/fingerprint_test.go`: `fingerprint` for builds without the `e2e` tag.
- `.github/workflows/e2e-pkcs11.yml`: the `E2E PKCS#11` workflow.
- `docs/backends/pkcs11.md`: the operator guide.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The `e2e_pkcs11` build did not compile**
- **Found during:** Task 1.
- **Issue:** `bootstrap_test.go` (tags `e2e || e2e_pkcs11 || e2e_tpm`) calls `fingerprint`, which only `issue_test.go` (tag `e2e`) defined.
- **Fix:** Added `test/e2e/fingerprint_test.go` with `//go:build !e2e && (e2e_pkcs11 || e2e_tpm)`. The file is not in the plan's file list. `harness_test.go`, `bootstrap_test.go` and the other suites are unchanged. `go vet` passes for `-tags e2e`, `e2e_pkcs11`, `e2e,e2e_pkcs11` and `e2e_tpm`.
- **Committed in:** `c462ae6`.

**2. [Rule 2 - Missing critical] Separate token directories for the CA and root tokens**
- **Found during:** Task 1.
- **Issue:** The plan has one `DIR/softhsm2.conf` holding both tokens. `ssh-add -s` loads every token the module can see, so the CA agent would also have held the root key. That breaks the must-have "CA and root keys never share an agent" (T-01-47).
- **Fix:** The script writes `DIR/ca/softhsm2.conf` and `DIR/root/softhsm2.conf`, each with its own token directory. The test asserts the separation on both agents.
- **Committed in:** `c462ae6`.

**3. [Rule 2 - Missing critical] No PIN in any argv, including token initialisation**
- **Found during:** Task 1.
- **Issue:** `softhsm2-util` and `pkcs11-tool` read PINs only from a TTY, so a here-string fails (`Could not get SO PIN`, `No PIN entered`). Passing `--pin` would put the PIN in `ps` output.
- **Fix:** Tokens are initialised and keys generated with `pkcs11-tool --so-pin/--new-pin/--pin env:NAME`. The variables are exported only inside the script and unset afterwards.
- **Committed in:** `c462ae6`.

**4. [Rule 1 - Bug] ssh-agent refused the provider through a symlink**
- **Found during:** Task 1.
- **Issue:** `/usr/lib/softhsm/libsofthsm2.so` is a symlink. ssh-agent matches `-P` against the resolved path and refused it with `provider not allowed`.
- **Fix:** The script prints `readlink -f` of the module, and the agent, `ssh-add -s` and `ssh-keygen -D` all use that path. The guide says so too.
- **Committed in:** `c462ae6`.

**5. [Rule 3 - Blocking] `softhsm2-util` ignores `SOFTHSM2_MODULE`**
- **Issue:** `softhsm2-util` uses its built-in module path. It is no longer used: everything goes through `pkcs11-tool --module`.
- **Committed in:** `c462ae6`.

---

**Total deviations:** 5 auto-fixed (2 blocking, 2 missing critical, 1 bug).
**Impact on plan:** All are needed for correctness, for the plan's own must-haves (agent separation, PIN never in argv), or to compile. No Go module and no product code changed. `harness_test.go` and `bootstrap_test.go` were not edited.

## Issues Encountered

- `sudo` in WSL needs a password. Local runs therefore used the Ubuntu packages extracted into `~/.cache/keyroster/pkgs` (`SOFTHSM2_MODULE`, `PATH`, `LD_LIBRARY_PATH`). CI installs them with apt as the plan specifies.
- In the distro lane, `TestPKCS11Ed25519` cannot run the Ed25519 flow (Pitfall 2). It asserts the refusal instead of skipping, so a future Ubuntu agent with Ed25519 support fails the test and prompts an update to the guide.

## Known Stubs

None.

## Threat Flags

None. No new network endpoint, auth path or schema. The new workflow has `permissions: {}`, read-only contents, SHA-pinned actions and `persist-credentials: false`, and installs only Ubuntu archive packages (T-01-SC).

## User Setup Required

None.

## Next Phase Readiness

- 01-11 (TPM) can reuse `test/e2e/fingerprint_test.go` under `e2e_tpm` as-is. It must not define its own `fingerprint`.
- 01-13's `keyroster-signer-agent.service` should use the `-P` allowlist with the resolved module path and the askpass PIN file described in `docs/backends/pkcs11.md`. The guide's socket path is `/run/keyroster-signer-agent/agent.sock`. Align it with the unit's `RuntimeDirectory` when 01-13 lands.
- 01-15 makes `e2e-pkcs11 (distro-p256)` and `e2e-pkcs11 (10.5p1-ed25519)` required.
- Real YubiHSM 2 validation remains a needs-hardware item for the Phase 6 review (D-12).

## Self-Check: PASSED

- All five created files exist on disk.
- Commits `c462ae6` and `5f6c732` are on `origin/p01/10-pkcs11` and verified on GitHub.
- Task acceptance criteria were re-run: PIN absence and bundle custody (the tests pass in both lanes), and the guide contains `10.1`, `-P`, `askpass` and `needs-hardware`.
