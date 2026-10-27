---
phase: 03-linux-agent-and-revocation
plan: 06
subsystem: agent
tags: [agent, sshd, preflight, detection, drift, phase2-adoption, distro-matrix, krl, capslock, ci]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-05: the apply engine (Apply, Transition, swapCurrent, RollbackTarget, keepKRLInForce, Dump.LoginGrace, ObserveLoginGrace, generations/<N>.json, execsite constructors pinned by paths.ExecSites); 03-04: RenderPrincipalsFile, pop.hosts"
provides:
  - "apply.Detect (systemd systemctl show, OpenRC conf.d/sshd); review fix round 1 replaced the reload strategy none with systemd-socket:<unit> (systemctl try-reload-or-restart)"
  - "apply.Preflight and PreflightReport: ssh_keygen_missing, no_dropin_dir, foreign_trust_setting, no_loopback_listener, account_excluded (report only), rhel8_unsupported, fips_unsupported, host_pop_not_enabled, login_grace_unbounded, login_grace_unknown, phase2_adoptable (report only); apply-only phase2_adoption_pending and phase2_layout_differs"
  - "apply.StructuralPhase2, apply.Adopt, AdoptPlan, Config.AllowAdoption (set only by apply --once), paths.AllowedRemoval"
  - "apply.Check and DriftReport (AGENT-05), resolving current once"
  - "keyroster-agent preflight (exit 0/3/2) and keyroster-agent check (exit 0/3/2); apply detects the service when flags are absent"
  - "test/distro (e2edistro): TestDistroApply, TestDistroDrift, TestDistroRefusals, TestDistroAdoptPhase2, TestDistroFacts; test/distro/run.sh and run-in.sh"
  - ".github/workflows/e2e-distro.yml (seven jobs) and the seven check names in main-integrity.json"
  - "Carry-overs from PR #67 round 2: krl_header_version_mismatch, Report.KRLKept, the no-op KRL version"
affects: [03-07, 03-08, 03-09, 03-10, 03-14, 03-16]

actuals:
  tokens: 45878
  tasks: 3
  commits: 8
plan_head_before: a269cc70248c38a02cb1f839fa4aa164d63ed18c
plan_head_after: 9d3d2aab1df36b8a67fd27afed8c78c74f56457c

tech-stack:
  added: []
  patterns:
    - "Every host check is a Finding with a stable code, a message and a fix; refusals carry an error for errors.Is (PreflightError)"
    - "The first apply and every drop-in change run the preflight's checks before any write"
    - "Phase 2 paths are only removed, through paths.AllowedRemoval; nothing writes them"
    - "Distro tests make their signed world inside the container with the same signing code as the e2e suite"

key-files:
  created:
    - internal/agent/apply/detect.go
    - internal/agent/apply/preflight.go
    - internal/agent/apply/exclusion.go
    - internal/agent/apply/drift.go
    - internal/agent/apply/adopt.go
    - internal/agent/apply/detect_test.go
    - internal/agent/apply/preflight_test.go
    - internal/agent/apply/adopt_test.go
    - internal/agent/apply/drift_test.go
    - cmd/keyroster-agent/preflight.go
    - cmd/keyroster-agent/check.go
    - test/distro/distro_test.go
    - test/distro/refusals_test.go
    - test/distro/world_test.go
    - test/distro/run.sh
    - test/distro/run-in.sh
    - .github/workflows/e2e-distro.yml
  modified:
    - internal/agent/apply/apply.go
    - internal/agent/apply/sshd.go
    - internal/agent/apply/selftest.go
    - internal/agent/apply/harness_test.go
    - internal/agent/apply/apply_test.go
    - internal/agent/state/state.go
    - internal/agent/state/verify.go
    - internal/agent/execsite/execsite.go
    - internal/agent/paths/paths.go
    - internal/agent/paths/paths_test.go
    - cmd/keyroster-agent/apply.go
    - cmd/keyroster-agent/commands.go
    - test/capslock/keyroster-agent.json
    - .github/rulesets/main-integrity.json
    - docs/runbooks/host-setup.md

key-decisions:
  - "03-06: the trial drop-in sets only TrustedUserCAKeys and AuthorizedPrincipalsFile, never RevokedKeys: sshd treats every key as revoked while its RevokedKeys file is missing, so a reload by something else in the trial's moment would otherwise refuse every public key"
  - "03-06: Phase 2 paths are removed only after the agent's generation is last-good; the plan (<state>/phase2-adopt.json) is durable before the first install, a crash mid-removal resumes, and nothing ever writes the old paths back"
  - "03-06: hostKeys skips host key types it does not read (Arch's OpenSSH 10.6p1 ssh-mldsa44-ed25519, and DSA); a readable type that does not parse stays an error"
  - "03-06: a kept KRL is named in the report (Report.KRLKept), not refused: refusing would stall a host whose rollback kept a newer KRL"
  - "03-06: the distro fixtures are made inside the container by the test binary, not on the host with a -fixtures-out flag"

patterns-established:
  - "Exit codes as errors: cmd/keyroster-agent's exitError carries 0/2/3 for preflight and check"
  - "Distro matrix check names come from a matrix name, not the image digest, so a digest bump keeps the required check names"

requirements-completed: []

coverage:
  - id: D1
    description: "Detect finds sshd, its configuration and the reload strategy from systemd (ssh.service, sshd.service, socket activation gives none) or OpenRC (conf.d/sshd), with explicit flags overriding; one new pinned exec site, execsite.SystemctlShow"
    requirement: "AGENT-04"
    verification:
      - kind: unit
        ref: "internal/agent/apply/detect_test.go#TestDetect (constructed systemctl show output)"
        status: pass
      - kind: unit
        ref: "internal/agent/paths/paths_test.go#TestPaths/exec_sites_pinned"
        status: pass
    human_judgment: true
    rationale: "Detection ran only on constructed systemctl show output and OpenRC files; no booted systemd or OpenRC host ran it (UNVERIFIED until 03-16)"
  - id: D2
    description: "keyroster-agent preflight: the D-07 refusal table with fixes, exit 0 clean or report only, 3 refused, 2 tool error; changes nothing but a trial drop-in it removes; apply refuses on the same codes on a first install and every drop-in change"
    requirement: "AGENT-04"
    verification:
      - kind: unit
        ref: "internal/agent/apply/preflight_test.go#TestPreflight"
        status: pass
      - kind: e2e
        ref: "test/distro/refusals_test.go#TestDistroRefusals (local Docker, all seven pinned images at 1feddd3, archlinux again at 9d3d2aa; CI on the PR head is authoritative)"
        status: pass
    human_judgment: false
  - id: D3
    description: "D-08: only the Phase 2 runbook's exact layout is taken over, only by apply --once, with the header-only report, and its paths go only after the agent's generation passed its self-test"
    requirement: "AGENT-04"
    verification:
      - kind: unit
        ref: "internal/agent/apply/adopt_test.go#TestAdopt"
        status: pass
      - kind: e2e
        ref: "test/distro/refusals_test.go#TestDistroAdoptPhase2 (local Docker, seven images as D2)"
        status: pass
    human_judgment: false
  - id: D4
    description: "keyroster-agent check (AGENT-05): sshd -T and -C per managed account, the generation re-hashed by the path current named once, exit 3 on drift"
    requirement: "AGENT-05"
    verification:
      - kind: unit
        ref: "internal/agent/apply/drift_test.go#TestDrift (incl. check_reads_current_once)"
        status: pass
      - kind: e2e
        ref: "test/distro/distro_test.go#TestDistroDrift (local Docker, seven images as D2)"
        status: pass
    human_judgment: true
    rationale: "AGENT-05 says periodically: the timer that runs check arrives in 03-08, so the requirement is not complete here"
  - id: D5
    description: "Certificate login with StrictModes yes through the current symlink, on each distribution's own sshd with the signal reload"
    requirement: "PLAT-01"
    verification:
      - kind: e2e
        ref: "test/distro/distro_test.go#TestDistroApply (local Docker, seven images as D2)"
        status: pass
    human_judgment: true
    rationale: "Containers run no service manager: systemd and OpenRC reloads, socket activation, SELinux and Proxmox are UNVERIFIED until 03-16"
  - id: D6
    description: "Carry-overs from PR #67 round 2: krl_header_version_mismatch, Report.KRLKept in the report and status.json, the no-op run reports the KRL in force"
    verification:
      - kind: unit
        ref: "internal/agent/apply/apply_test.go#TestApply/krl_header_version_differs_from_manifest_refused, krl_kept_by_*_survives_withheld_capture_commit, noop_reports_krl_in_force"
        status: pass
    human_judgment: false
  - id: D7
    description: "host-setup.md: Supported platforms with per-image facts, Not supported, Before the agent: preflight, Moving a Phase 2 host to the agent, Drift"
    verification: []
    human_judgment: true
    rationale: "A runbook's wording and order need a human reader; the homelab steps are UNVERIFIED until 03-16"

duration: 116min
completed: 2026-10-27
status: complete
---

# Phase 3 Plan 06: Apply Distros Summary

**keyroster-agent now does four things on real distributions:**

- It finds sshd the way each distribution runs it.
- It refuses any host it cannot manage safely, with a code and a fix.
- It takes over exactly the Phase 2 hand-set layout and nothing else.
- It reports drift per managed account.

**It passes on the real sshd of seven distribution images: Debian 12 and 13, Ubuntu 24.04 and 26.04, AlmaLinux 9, Alpine, and Arch. That ran locally on the pinned images. The same runs are now a new CI matrix, listed as required checks for the owner to apply after the merge.**

## Owner attention first

1. **A real bug on Arch, fixed here (Rule 1).** Arch's OpenSSH 10.6p1 generates an ML-DSA-44+Ed25519 host key (`ssh_host_mldsa44_ed25519_key`), and x/crypto/ssh cannot parse it. 03-05's `hostKeys` failed on its `.pub`, which would have failed every apply on such a host. It now skips key types it does not read, and DSA too. A readable type that does not parse is still an error, and a host with no readable key is refused, naming the skipped types.
2. **The trial drop-in sets two keywords, not three (deviation from the must_have).** sshd treats every public key as revoked while its `RevokedKeys` file is missing. So a trial `RevokedKeys` pointing at a `current/` that does not exist yet, met by a reload from something else in that moment, would refuse every key until the next reload. The trial sets only `TrustedUserCAKeys` and `AuthorizedPrincipalsFile`. sshd keeps the first value of each, so they prove the drop-in's precedence as well. A foreign `RevokedKeys` is still caught by the grep and the `sshd -T` check. Residual: a reload in that moment refuses certificate logins until the next reload (Threat Flags).
3. **capslock baseline 20 → 23 pairs.** The agent baseline gains `CAPABILITY_ARBITRARY_EXECUTION` for `internal/agent/state`, `internal/krl`, `internal/sshsig` and `golang.org/x/crypto/ssh`, and loses `internal/agent/apply CAPABILITY_FILES`. capslock's example path runs `runPreflight → Preflight → preflightState → state.Verify → krl.VerifyManifest → sshsig.Verify → ssh.dsaPublicKey.Verify → crypto/dsa.Verify → crypto/fips140.isBypassed`. That is the same `ssh.PublicKey.Verify` over-approximation the Phase 2 baselines recorded (02-01, 02-05), reached through a new root. Review it in the PR.
4. **The ruleset step is yours after the merge** (owner decision D2). See "Owner step" below.

## D-05 network answer

Unchanged: loopback-only (03-05). The self-test, the `-C` specifications and the preflight use loopback addresses only, and `no_loopback_listener` is in the preflight table with its fix.

## Distro facts (TestDistroFacts)

Local Docker in WSL. Each image's `RepoDigest` equals the digest pinned in `e2e-distro.yml`, so the local runs used the pinned images. Each line is the test's FACT output, condensed.

- debian:12: `OpenSSH_9.2, OpenSSL 3.0.22`; `Include /etc/ssh/sshd_config.d/*.conf` at line 12; casignaturealgorithms `ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256`; logingracetime 120; strictmodes yes; ssh-keygen with openssh-server; a revokedkeys line while unset: yes.
- debian:13: `OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.7`; Include at line 12; casignaturealgorithms as debian:12; logingracetime 120; strictmodes yes; ssh-keygen with openssh-server; revokedkeys line: yes.
- ubuntu:24.04: `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13`; Include at line 12; casignaturealgorithms as debian:12; logingracetime 120; strictmodes yes; ssh-keygen with openssh-server; revokedkeys line: yes.
- ubuntu:26.04: `OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5`; Include at line 24; casignaturealgorithms as debian:12; logingracetime 120; strictmodes yes; ssh-keygen with openssh-server; revokedkeys line: yes.
- almalinux:9: `OpenSSH_9.9p1, OpenSSL 3.5.8`; Include at line 15; **casignaturealgorithms `ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-256,rsa-sha2-512`** (assumption A5: Ed25519 CAs are accepted, listed after the ECDSA types by crypto-policies); logingracetime 120; strictmodes yes; ssh-keygen with openssh-server; revokedkeys line: yes; `sshd_config.d` is mode 0700 and ships `50-redhat.conf`.
- alpine (latest): `OpenSSH_10.3p1, OpenSSL 3.5.9`; Include at line 15; casignaturealgorithms as debian:12 plus `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`; logingracetime 120; strictmodes yes; **ssh-keygen needs the extra package `openssh-keygen`**; revokedkeys line: no; no PAM; no OpenRC init script in the container (`openssh-server-openrc` is not installed).
- archlinux (latest): `OpenSSH_10.6p1, OpenSSL 3.6.5`; Include at line 2; casignaturealgorithms as alpine; logingracetime 120; strictmodes yes; ssh-keygen with openssh; revokedkeys line: no; `sshd -T` prints CamelCase keywords (ParseDump lowercases them); an ML-DSA-44+Ed25519 host key.
- **Every image packages LoginGraceTime 120**, so the two-step swap's widening wait is 150 s there. The wait is the LoginGraceTime bound plus 30 s on CLOCK_MONOTONIC (inherited from 03-05's review), not the plan's plus 5 s.
- **Detect inside the containers:** `sshd_not_detected` on every image, because no service manager runs. The tests therefore pass `--sshd`, `--sshd-config` and `--reload signal`.

**Image digests (pinned in `.github/workflows/e2e-distro.yml`, resolved 2026-10-26 with `docker buildx imagetools inspect`):**

| Check name | Image |
|---|---|
| e2e-distro (debian:12) | `debian@sha256:854dd8ab51d62866dbd8f5431d15ce77b12983a2a4a1e1fe43a2395dc7ef9f61` |
| e2e-distro (debian:13) | `debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` |
| e2e-distro (ubuntu:24.04) | `ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac` |
| e2e-distro (ubuntu:26.04) | `ubuntu@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944` |
| e2e-distro (almalinux:9) | `almalinux@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16` |
| e2e-distro (alpine) | `alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` (alpine:latest) |
| e2e-distro (archlinux) | `archlinux@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0` (archlinux:latest) |

## Performance

- **Duration:** 116 min of executor time, from 2026-10-26T22:21:35Z to about 00:18Z, before the PR's CI wait.
- **Tasks:** 3 executed (Tasks 1 to 3), plus the three carry-overs. Tasks 4 and 5 are the owner's checkpoints.
- **Files:** 32 changed outside `.planning/`.

## Accomplishments

- **Detection (`detect.go`).**
  - **systemd:** when `/run/systemd/system` exists, one new pinned exec site, `execsite.SystemctlShow`: `systemctl show -p Id -p LoadState -p ActiveState -p ExecStart ssh.socket ssh.service sshd.service`. The KEY=VALUE blocks are parsed; the loaded service gives the binary (ExecStart's `path=`) and the configuration (its `-f`, else `/etc/ssh/sshd_config`), and the strategy is `systemd:<Id>`. An active `ssh.socket` with an inactive service gives `Socket` and `ReloadNone` (`none`).
  - **OpenRC:** `/etc/init.d/sshd` plus `SSHD_BINARY` and `SSHD_CONFIG` from `/etc/conf.d/sshd`, refusing values with `$`.
  - **CLI:** `apply`, `preflight` and `check` detect the service when the flags are absent, and an explicit flag overrides. Every reload is still preceded by the agent's own `sshd -t`.
- **Preflight (`preflight.go`, `exclusion.go`).** The full D-07 table, each code with a fix.
  - **Foreign trust settings:** found by grepping `sshd_config` and `sshd_config.d/*.conf` (file and line, `Keyword=value` and Match blocks included) and by the `sshd -T` values. An unset value is `none` or no line at all: OpenSSH 10.3 and later print no `revokedkeys` line.
  - **Trial drop-in:** written only while no drop-in exists, with its own header, and removed before return, with no reload. It runs under the apply lock taken without waiting.
  - **Leftovers:** a leftover trial is removed by the preflight and by every apply, and `writeDropIn` never counts one as a previous drop-in. *(Corrected in review fix round 1, F1: as first written, a no-op apply never removed a leftover; see below.)*
  - **Account exclusion:** sshd's `match_pattern` and `match_pattern_list`, with `user@host` entries counted as "may exclude". Groups come from `/etc/passwd` and `/etc/group`.
  - **Policy and accounts:** with pins present, the state is verified as an apply would verify it, for `host_pop_not_enabled` and the managed accounts. Before enrollment this is a note, not a finding.
  - **In apply:** the first apply and every drop-in change run these checks before any write, and refuse with a `PreflightError` that `errors.Is` matches per code.
  - **Per-account check:** `activateDropIn` now also checks `sshd -T -C` for every managed account (T-03-34).
- **Phase 2 takeover (`adopt.go`).**
  - **Structural check:** `StructuralPhase2` needs no signed state; a layout that passes is `phase2_adoptable`, report only, exit 0.
  - **Signed check:** `Adopt` compares the CA file's key with the bundle's active user CA key (the comment is ignored), and each principals file byte for byte with `RenderPrincipalsFile`. A header-only difference is reported as "only the header differs", naming both versions.
  - **Order:** the plan is written before the first install. The paths go after last-good is set: each file is copied to `<state>/phase2/`, removed through `paths.AllowedRemoval`, the principals directory is removed last, then `sshd -t`, `sshd -T` and `-C` per account run. A crash at any removal resumes on the next `apply --once`, and a failed first install undoes the plan.
  - **Gate:** without `Config.AllowAdoption`, the run is `phase2_adoption_pending` and nothing is written.
- **Drift (`drift.go`).**
  - `Check` resolves `current` once and hashes `gen/<N>` by that path against `generations/<N>.json`, reporting missing, added and changed files.
  - It compares `sshd -T`, and `-C` per account (laddr and lport from the first loopback listener).
  - It refreshes `ObserveLoginGrace` under a non-blocking apply lock, skipping it while an apply holds the lock, and reports `logingracetime 0` as drift.
- **CLI exit codes.** `exitError` gives preflight 0, 3 or 2 and check 0, 3 or 2. Preflight's `--state-dir` defaults to `/var/lib/keyroster-agent`, and a missing directory means "before enrollment".
- **Distro harness (`test/distro`, build tag `e2edistro`).**
  - **Build:** `run.sh` builds the agent and the test binary statically on the host and runs `docker run --rm -v <dir>:/k:ro <image> /bin/sh /k/run-in.sh`.
  - **In the container:** `run-in.sh` installs `openssh-server` with apt-get, dnf, apk (plus `openssh-keygen`) or pacman. The test binary keeps a pristine `/etc/ssh` and resets it before every test. It starts the distribution's sshd with its packaged configuration, makes the signed world with fixed seeds through `internal/cert.Build` and the trust, directory and sshsig code, and logs in with x/crypto/ssh.
- **CI (`.github/workflows/e2e-distro.yml`).**
  - Seven jobs named `e2e-distro (<matrix name>)`, each image pinned by digest.
  - `permissions: {}` with `contents: read`, the same checkout and setup-go SHAs as `e2e.yml`, and `timeout-minutes: 30`.
  - `main-integrity.json` lists the seven names.
- **Runbook (`host-setup.md`).** New sections:
  - "Supported platforms", with the facts table;
  - "Not supported" (RHEL 8, FIPS, and what to do);
  - "Before the agent: preflight" (every code and its fix);
  - "Moving a Phase 2 host to the agent" (the exact layout, the four-step order, what is removed, each refusal);
  - "Drift" (including the `Match Address` limit).
- **Carry-overs from PR #67 round 2.**
  - (a) `krl_header_version_mismatch`: `state.Verify` refuses a KRL whose header `krl_version` is not its manifest's.
  - (b) `Report.KRLKept {in_force, verified, generation}` plus a WARNING log line whenever `keepKRLInForce` substitutes; status.json carries it.
  - (c) A no-op run reports `max(accepted/, current's KRL)`.

## Task Commits

1. **Carry-over (a):** `d76903c` (fix): refuse a KRL whose header version differs from its signed manifest
2. **Carry-over (b):** `86a5362` (fix): name a KRL kept in force over an older verified one in the report
3. **Carry-over (c):** `1b2353d` (fix): a no-op apply reports the KRL version in force in current
4. **Task 1 (tracer):** `95fb048` (feat): detect sshd's service, preflight the host and report drift
5. **Rule 1 fix found by the archlinux run:** `4f4d753` (fix): skip host keys of a type x/crypto/ssh cannot read
6. **Task 2:** `1feddd3` (feat): take over the exact Phase 2 layout and test the refusal table
7. **Task 3:** `658489e` (ci): run the distro matrix on every PR and document the platforms
8. **Lint fix:** `9d3d2aa` (fix): read no DSA host keys

**Plan metadata:** the `docs(03-06): complete apply-distros plan` commit that carries this file, STATE.md and ROADMAP.md.

## Tracer gate (Task 1)

This run is interactive, in `end-of-phase` mode, and the tracer's verify has only automated steps, so it continued without a checkpoint.

- **Re-run before Task 2:** `go test -count=1 -v ./internal/agent/... ./cmd/keyroster-agent/...` passed; the apply tests exist, so there was no "no test files" for that package.
- **debian:12:** `bash test/distro/run.sh debian:12` printed `--- PASS: TestDistroApply` and `--- PASS: TestDistroDrift`.
- **Acceptance:**
  - `grep -n systemctl internal/agent/apply/sshd.go` shows `systemctlShow` and its `execsite.SystemctlShow` call;
  - TestPaths passes with it listed in ExecSites;
  - the debian:12 login asserted `strictmodes yes` on `sshd -T` and on `sshd -T -C`.

## What ran and what did not

**Ran (2026-10-26/27, WSL Ubuntu, Go 1.27.3, Docker 29.7.2):**

- **Distro matrix.** All seven pinned images at `1feddd3`: 14 of 14 passes each (TestDistroApply, TestDistroDrift, TestDistroRefusals with 7 subtests, TestDistroAdoptPhase2 with 2 subtests, TestDistroFacts). The final head `9d3d2aa` changed only `readableKeyTypes` (DSA dropped), so archlinux, the image that needs that code, was re-run there: 14 of 14.
- **Local e2e** at `1feddd3`. Both passed on OpenSSH 10.5p1 and on 9.5p1, in 58.9 s and 59.3 s, plus 22.9 s and 20.6 s:
  - `TestAgentApplyEndToEnd`;
  - `TestSshdRereadsTrustFiles`.
- **Full suite** at `1feddd3`: `CGO_ENABLED=1 go test -race -count=1 ./...` passed.
- **Static gates** at `9d3d2aa`:
  - golangci-lint reports 0 issues for linux, windows and darwin, and with `--build-tags e2edistro` on test/distro;
  - `go vet` passes for linux, windows and darwin, `-tags e2e` and `-tags e2edistro`;
  - gofmt is clean;
  - capslock-check: signer 91/91, agent 23/23, EXEC only through execsite (2 edges);
  - dep-firewall and testonly-firewall are clean;
  - check-pinned-actions: 47 of 47 pinned.
- **Mutants.** Nine were applied, run and restored byte for byte, and all are killed (list under "TDD Gate Compliance").

**The required checks on the pushed head** run on the PR. Their result, including the seven e2e-distro jobs, is in the handback.

**UNVERIFIED (not run here):**

- **Service detection on a real host.** systemd's `systemctl show` was only fed constructed output to the parser; OpenRC's conf.d was read only from temporary files.
- **Real reloads:** `systemd:<unit>`, `openrc`, and `none` on a socket-activated Ubuntu. The containers ran the `signal` strategy only (D-17).
- **The homelab:** SELinux on an enforcing EL9 host, Proxmox VE, a RHEL 8 or FIPS host (only unit cases), and every homelab step (03-16).
- **The resume warning:** with `AllowAdoption` unset, the `phase2_adoption_pending` WARNING for a takeover whose removal is unfinished is a log line with no test.
- **The trial's reload window:** a reload of sshd by something else while the trial drop-in exists was not provoked.
- **Ownership checks as root:** the structural principals-directory check uses the applier's uid. Unit tests ran as a non-root user against their own uid; root ran only in the containers.
- **Remote client addresses:** `Match Address` blocks for remote ranges are not checked by `check` (the plan's flagged assumption, now in the runbook).

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] hostKeys failed on Arch's ML-DSA-44+Ed25519 host key**
- **Found during:** Task 2, in the archlinux run (12 of 14 tests failed on `host key /etc/ssh/ssh_host_mldsa44_ed25519_key.pub: ssh: no key found`).
- **Fix:** skip host key types the agent does not read. A readable type that does not parse stays an error.
- **Files modified:** internal/agent/apply/selftest.go, apply_test.go (TestHostKeys).
- **Verification:** archlinux 14 of 14; TestHostKeys covers the hybrid key beside Ed25519, alone, and a corrupt Ed25519 key.
- **Committed in:** 4f4d753, and 9d3d2aa (DSA dropped from the readable types: staticcheck SA1019; DSA is gone from OpenSSH 10.0).

**2. [Rule 2 - Missing critical] The trial drop-in sets no RevokedKeys**
- See "Owner attention first", item 2. The plan's trial wrote all three values.
- **Committed in:** 1feddd3.

**3. [Rule 2 - Missing critical] A leftover trial never passes for the agent's drop-in**
- **Issue:** a trial left by a crash and byte-equal to the real drop-in would make `writeDropIn` see "unchanged", so it would skip activation. On an installed host, the preflight's own cleanup would also delete the real drop-in.
- **Fix:** the trial has its own header. The preflight and every apply remove a file that holds exactly the trial bytes.
- **Verification:** `installed_host_keeps_its_dropin`, `trial_leftover_removed` and `apply_replaces_leftover_trial`. The "trial equal to the drop-in" mutant is killed.
- **Committed in:** 95fb048 and 1feddd3.

**4. [Rule 2 - Missing critical] The preflight takes the apply lock without waiting**
- **Why:** the trial must never race an apply's real drop-in.
- **Effect:** with an apply running, the preflight is a tool error (exit 2). Check takes the lock the same way, for `ObserveLoginGrace` only, so that a hand-run check never resets the LoginGraceTime window while an apply reloads.
- **Committed in:** 95fb048.

**5. [Plan detail] Fixtures inside the container**
- The test binary makes the signed world in the container, not on the host under a `-fixtures-out` flag.
- **Why:** pins.json and the state directory must belong to the container's root, the directory names the container's own sshd host key, and no key material crosses the bind mount.
- **Same code:** the signing code is the e2e suite's (`internal/cert.Build`, trust, directory, sshsig), with fixed seeds.

**6. [Plan detail] One systemctl exec site, KEY=VALUE parsing**
- **One site:** `systemctl show -p Id -p LoadState -p ActiveState -p ExecStart ssh.socket ssh.service sshd.service` replaces the plan's second call, `systemctl is-active ssh.socket`. That keeps "the one new exec site".
- **No `--value`:** with `--value` the lines carry no key, so the parser could not tell properties apart. The output is parsed as KEY=VALUE blocks instead.

**7. [Plan detail] login_grace_unbounded comes from sshd.go**
- 03-05's one check is `Dump.LoginGrace` in sshd.go, not validate.go.
- `grep -n login_grace_unbounded internal/agent/apply/preflight.go` prints the comment that names `d.LoginGrace()` on the next line, and the code constant. There is no second parser.

**8. [Plan detail] Additions**
- **Files beyond the plan's list:** exclusion.go, test/distro/world_test.go, test/distro/refusals_test.go and test/distro/run-in.sh.
- **Reload strategy:** `ReloadNone` joins the closed set.
- **Per-account check:** the `-C` check runs on every drop-in change, not only for adoption.
- **Report fields:** `phase2_removed` and `krl_kept`.
- **CLI:** check takes the same service flags as preflight.

**9. [Plan detail] Matrix names and logins**
- The check names are `e2e-distro (alpine)` and `e2e-distro (archlinux)`, not `...:latest`. The name comes from a matrix `name`, so a digest bump keeps it.
- Distro logins use the x/crypto/ssh client and assert that authentication succeeds, with no session. That is enough to show sshd accepted the certificate under StrictModes, and it avoids PAM session modules that do not run in containers.

**10. [Inherited from 03-05] Swap wait plus 30 s on CLOCK_MONOTONIC**
- Where the plan says LoginGraceTime plus 5 s, the code and runbook use plus 30 s on CLOCK_MONOTONIC (03-05 review, owner decision 2026-10-26).
- The Phase 2 removal entries are removal-only (`AllowedRemoval`), and Allowed still refuses every write to them. This follows the plan's "removal only, never write".

---

**Total deviations:** 10: 1 Rule 1 (with its lint follow-up), 3 Rule 2, 5 plan details and 1 inherited.
**Impact on plan:** No new Go module. The Arch fix and the two trial fixes are safety fixes in scope.

## TDD Gate Compliance

- **Order:** Task 2 is `tdd="true"`, but its code was written before its tests, so there is no separate RED commit. Most of TestAdopt, TestPreflight, TestDetect and TestDrift passed on their first run. Tests and code went into the Task 2 commit.
- **Real RED:**
  - The archlinux run is real RED for `hostKeys` (12 of 14 tests failed before 4f4d753).
  - The carry-over tests failed on their mutants before each fix's commit.
- **Mutants (each applied, run and restored byte for byte; all killed):**
  1. check re-reading `current` instead of `gen/<N>` kills `check_reads_current_once`;
  2. the AllowAdoption gate off kills `adoption_not_allowed_reports_pending`;
  3. the header-only branch off kills `principals_header_only_differs_reported`;
  4. the removal before the commit kills `crash_during_removal_resumes`;
  5. an `os.WriteFile` beside the removal guard kills TestPaths `writes_through_allowed`;
  6. a trial equal to the drop-in kills `installed_host_keeps_its_dropin`;
  7. the trial not removed kills `clean_host`;
  8. the pop.hosts check off kills `host_pop_not_enabled`;
  9. the per-account `-C` off kills `match_block_override_is_drift`.
  Carry-overs: the header check off, the KRLKept report off and the no-op version from accepted/ each failed their tests.
- **Classifier:** not used; Go test output is not a format it reads, and `workflow.tdd_mode` is off.

## Issues Encountered

- **wsl.exe expands `$` in its arguments.** A gate command with `$HOME` was mangled, so the gates ran from script files.
- **Heredocs in Git Bash.** A heredoc that appended Go code failed on quoting. The code went into its own file through the Write tool, with nothing broken committed.
- **Shared build tree.** Each `run.sh` call builds from the working tree. To keep a clean record, the full matrix was re-run on the final code (`1feddd3`) after the edits made during the first run.

## Known Stubs

None. `hostcertificate` is not compared by `check` yet; 03-09 adds it when it installs host certificates.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: config-write window | internal/agent/apply/preflight.go | The trial drop-in exists for one `sshd -T` run, and only on a host where neither `current` nor `last-good` exists (review fix round 1, F1/F5). An sshd that loads it in that moment (a reload by something else, or a socket-activated sshd a connection starts) trusts no CA, because the trial's paths name files that do not exist: certificate logins are refused until the next reload. Plain keys and passwords are unaffected, since the trial sets no RevokedKeys. On an installed host the same lines would trust `current`'s CA keys without its KRL, so no trial is written there. A crash leftover is removed by the next preflight or apply on a host without a generation, and replaced by the agent's drop-in with a reload by any apply on an installed host |
| threat_flag: removal surface | internal/agent/paths/paths.go | `AllowedRemoval` lets the applier unlink three Phase 2 paths outside its tree (only `os.Remove`, one directory level, pinned by TestAllowed and TestPaths) |
| threat_flag: supply chain | .github/workflows/e2e-distro.yml | The images are pinned by digest (T-03-39), but each job installs OpenSSH from its distribution's repositories at run time, unpinned. The jobs get no secrets and contents: read |
| threat_flag: capability baseline | test/capslock/keyroster-agent.json | 20 → 23 pairs (ARBITRARY_EXECUTION through ssh.PublicKey.Verify; see Owner attention, item 3) |

## Owner step (after the merge, owner decision D2)

1. Confirm that the seven `e2e-distro (...)` checks also passed on `main` after the merge.
2. Apply the ruleset from your own workstation, in the repository, with your gh login:

   ```
   git switch main
   git pull --ff-only
   bash scripts/apply-rulesets.sh
   ```

3. Claude then checks the live ruleset (plan Task 5 verify) for the seven names.

## User Setup Required

None.

## Next Phase Readiness

- **03-07:** the run loop leaves `Config.AllowAdoption` unset, and the operator runbook's order is in host-setup.md. Enrollment can call `keyroster-agent preflight`; 03-16's gate reads exit 0 with only `account_excluded` or `phase2_adoptable`.
- **03-08:** the timer runs `keyroster-agent check`, which exits 3 on drift, and `ObserveLoginGrace` is refreshed there. Detect's `systemd:<unit>` gives the unit to reload.
- **03-09:** add `hostcertificate` to `trustKeywords`/`ourValues` and to the drop-in.
- **03-10:** extend the preflight code set with the probe-account codes. `PreflightReport.add` makes a new code a refusal unless it is listed in `ReportOnly`.
- **03-16:** real systemd and OpenRC reloads, socket activation, SELinux, and Proxmox.

## Self-Check: PASSED

- **Files.** Every key-files entry exists (checked with `test -f` before this commit).
- **Commits.** d76903c, 86a5362, 1b2353d, 95fb048, 4f4d753, 1feddd3, 658489e and 9d3d2aa are ancestors of HEAD; `git rev-list --count a269cc7..9d3d2aa` is 8.
- **Acceptance greps:**
  - `grep -c 'e2e-distro (' .github/rulesets/main-integrity.json` is 7;
  - the runbook has UNVERIFIED, FIPS, `keyroster-agent preflight`, `login_grace_unbounded`, `keyroster-agent apply --once`, and `keyroster host principals` in "Moving a Phase 2 host to the agent";
  - every image in e2e-distro.yml is `name@sha256:`.
- **Named cases.** Every case named in Task 2's behaviour list exists and passes (`go test -v` output).

## Review fix round 1 (PR #68)

The pre-merge security review confirmed 16 findings (F1 to F16). The owner made four decisions, quoted here verbatim:

- **D-R1 "try-reload-or-restart"** (F3, F4, F13).
- **D-R2 "Reparera + rapportera"** (F15).
- **D-R3 "Hela Include-grafen + kommando"** (F12, F16; extends D-07).
- **D-R4 "Vägra okända argument"** (F6, F11).

Base `6b17aa4`. Every commit is SSH-signed by keyroster-bot.

### Per finding

| Finding | Commit | What changed | Test (and the mutant that fails it) |
|---|---|---|---|
| F1, F5 (trial on an installed host) | `c41bb92` | Preflight writes no trial while `current` or `last-good` exists, and reports a missing, trial or edited drop-in as the new refusal code `dropin_drift`. Every apply handles a byte-exact trial before forward (`replaceTrial`), so before a no-op return too. Without a last-good it removes the trial. On an installed host it writes the agent's drop-in, then runs `activateDropIn` (with the D-R1 reload action) and the self-test, and the run is not a no-op. The trial comment and the threat flag are corrected. | `TestDropInRepair/noop_apply_replaces_trial_on_installed_host` (mutant: `replaceTrial` always removes). `TestPreflight/installed_host_*` (mutant: Preflight's installed check off fails all four). |
| F2 (stale `phase2-adopt.json`) | `c0fd163` | The marker is written first, then the plan; a failed plan write undoes the first install. A new fault point `adopt-plan` sits between. `finishAdoption` runs from firstInstall only for its own plan. A plan with no marker, no current and no last-good is removed at the start of the run. | `TestAdopt/marker_write_failure_leaves_no_plan` (mutant: the old write order). `plan_write_failure_or_crash_undone`. `stale_plan_never_executed` (the finding's probe; mutant: the start-of-run discard and the `e.adopt` guard both off). |
| F3, F4, F13 (D-R1) | `8f17c81` | New strategy `systemd-socket:<unit>`, chosen whenever `ssh.socket` is active, whatever the service's state. Every reload (activation, `restoreDropIn` in every rollback and undo path) runs `systemctl try-reload-or-restart <unit>` through the new pinned `execsite.SystemctlTryReloadOrRestart`. `none` is gone. Detect refuses a transitional ActiveState. `Report.ReloadActions` names each command that ran. `reloadSystemd` looks for systemctl below the layout's root, as Detect does. | `TestSocketActivatedReload`. The self-test fails after the fake sshd accepted the connection, and the rollback's try-reload-or-restart runs with the drop-in gone and `current` still present. Adoption runs the command before the first Phase 2 removal. Mutant: the socket strategy reloading nothing fails all three. `TestDetect` socket and transitional cases; mutant: the old inactive-only rule fails four. |
| F6, F11 (D-R4) | `d2c378c` | ExecStart accepts only `-D`, `-e` and one `-f <file>`. `$NAME` (word-split) and `${NAME}` are resolved from `Environment` and `EnvironmentFiles` in systemd's precedence. Each EnvironmentFile is read through the new `readTrusted`: root-owned, not group- or world-writable, owned symlinks only, inside the root. OpenRC's `/etc/conf.d/sshd` is read as Alpine's init script reads it (`cfgfile`, `SSHD_CONFIG`, `SSHD_CONFDIR`, `command_args`, `SSHD_OPTS`). Anything else is the new refusal code `sshd_command_unknown`: preflight exit 3 through `apply.DetectRefusal`. The SystemctlShow argv gains `-p EnvironmentFiles -p Environment`. | `TestDetect`, 31 new cases (the commit body says 30), including the captured stock unit, env-file and conf.d contents. Three mutants: accepting unknown arguments, no variable lookup, and no ownership check. `TestDistroDetectStock` and `TestDistroDetectRefusesSSHDArgs`. |
| F7 (runbook overclaim) | `6dd875b` | `TestDistroRefusals` gains `ssh_keygen_missing`, `host_pop_not_enabled`, `no_loopback_listener` (sshd left stopped, new `hostEdit.noStart`) and a held apply lock (exit 2). The runbook names exactly the codes the matrix provokes, and lists the rest as unit-tested only. | Mutant: the pop.hosts check off fails `host_pop_not_enabled` on debian:12. |
| F8 (Arch partial upgrade) | `00bc086` | `run-in.sh` points pacman at the Arch Linux Archive snapshot of the image's build day and runs `pacman -Syyu --needed openssh`. The day is the mtime of the mirrorlist the image build wrote. SigLevel and the image's keyring are unchanged. | No unit test (CI script). Checked on the pinned image: snapshot 2026/10/18, openssh 10.6p1-2, archlinux-keyring 20260909-1. archlinux passed 25 of 25 with it. |
| F9 (CONTRIBUTING) | `e34a0de` | Lists 26 checks, names exactly as in `main-integrity.json` (sorted diff of both lists). | Docs. |
| F10 (run.sh comment) | `6f27dee` | The comment now says the container keeps Docker's default bridge network for the whole run. | Docs. |
| F12, F16 (D-R3) | `be5d99d` | `configGraph` follows every Include from the main configuration recursively: globs, paths relative to `/etc/ssh`, Include inside Match blocks, nothing-matched skipped. A cycle, nesting past sshd's 16 levels (`SERVCONF_MAX_DEPTH`, servconf.c, portable 10.2p1), `~`, more than 512 reads, an unsafe file, or an Include directory others can write is the new refusal code `sshd_config_unsafe`. A trust setting anywhere but the agent's drop-in is `foreign_trust_setting`, Match blocks included. That covers `AuthorizedPrincipalsCommand` other than `none`, and then every `AuthorizedPrincipalsCommandUser`. `authorizedprincipalscommand` must be unset in `foreignFindings`, preflight's per-account `-C` check, `checkDropInEffective` (global and per account) and check. Check walks the graph too (`DriftReport.Foreign`). | `TestIncludeGraph`, 19 cases (the commit body says 20); six mutants each fail it: no Include following, no command grep, no directory check, no depth limit, no per-account command check at activation, no Foreign in check. Distro: an included Match block, a nested glob include, the command in sshd_config and in an included Match block (exit 3, by file and line); an Include cycle, which the real `sshd -T` refuses itself (exit 2); `TestDistroDrift` reports a Match-block principals command. |
| F14 (resume after the directory is gone) | `955ced7` | `removePhase2` fsyncs the nearest existing directory, up to `<root>/etc/ssh`. A new fault point `phase2-removed` sits after the removal loop. | `TestAdopt/crash_after_final_removal_resumes` (mutant: fsync only the parent). |
| F15 (D-R2) | `c41bb92` | Once last-good is the agent's, a differing `00-keyroster.conf` is drift. `writeDropIn` repairs it (`dropin.prev`, `sshd -t`, the `sshd -T` checks, reload, self-test) and it is never refused. A foreign file there is refused only at the first install. `foreignFindings` skips the `sshd -T` comparison for a keyword the on-disk drop-in sets. Check reports drop-in bytes that differ from `DropIn` as a FileDrift. | `TestDropInRepair/edited_dropin_repaired_and_krl_installed` (the finding's probe), `edited_trust_line_repaired` and `foreign_file_refused_at_first_install`. `TestDrift/dropin_edited_or_missing_is_drift`. Mutants: the installed carve-out off, the own-keyword skip off, and check's drop-in compare off. |

### What ran (2026-10-27)

- **e2e (found after the first push):** D-R3's `readTrusted` refuses a configuration outside the layout's root, and the e2e agent host kept its sshd_config in another temporary directory, so `TestAgentApplyEndToEnd` failed with `sshd_config_unsafe` on both OpenSSH builds. `fcb0936` moves it to `<root>/etc/ssh/sshd_config` with explicit modes. The full `test/e2e` suite (`-tags e2e`) then passed in WSL on OpenSSH 10.5p1 (279 s) and 9.5p1 (286 s).

- **Distro matrix:** WSL, Docker, `test/distro/run.sh` on the final code. All seven pinned images passed **25 of 25** each, against 14 before the fix round. `TestDistroDetectStock` found the stock service on every image (systemd units on six, OpenRC conf.d on Alpine).
- **Race suite:** `CGO_ENABLED=1 go test -race -count=1 ./...` in WSL passed.
- **Windows:** `go test -count=1 ./...` passed in every package except `internal/agent/paths` `TestAllowed`. That test fails identically at `6b17aa4`: POSIX paths on Windows, and the package is not in the Windows CI lane (Follow-ups).
- **go vet:** clean for linux, windows and darwin, and with `-tags e2e` and `-tags e2edistro`.
- **gofmt:** clean.
- **golangci-lint:** 0 issues in all four runs (linux, windows, darwin, and `--build-tags e2edistro` on test/distro).
- **capslock-check:** the agent still has 23 of 23 pairs (no change), and EXEC leaves the module only through execsite (2 edges). The signer has 91 of 91.
- **Other gates:** dep-firewall clean; testonly-firewall clean in 6 combinations; check-pinned-actions 47 of 47.
- **Mutants:** every mutant listed above was applied in the WSL copy, run, and restored (a fresh copy for each). All were killed.

### New codes

- `dropin_drift`: a refusal, raised by preflight only.
- `sshd_config_unsafe`: a refusal.
- `sshd_command_unknown`: a refusal, preflight exit 3.

### UNVERIFIED (updated)

- **Real systemd.** `systemctl show` output was only constructed, by hand or from each image's unit file. `systemctl try-reload-or-restart` on Ubuntu's socket activation was never run against a real systemd. The harness answers systemctl without running it (03-16).
- **OpenRC init script.** The script's own command line is not read; a modified script is not detected.
- **Unit-tested only on a distribution sshd:** `login_grace_unknown`, `rhel8_unsupported`, `fips_unsupported`, `dropin_drift`, `sshd_config_unsafe`, `sshd_command_unknown` from a systemd unit, and `phase2_adoption_pending`.
- **Ownership checks as root.** `readTrusted` compares owners with the applier's euid. Unit tests ran as a non-root user against their own uid; root ran only in the containers.
- **Carried over from the original SUMMARY:** real reloads, the homelab (SELinux, Proxmox), the resume warning, and `Match Address` for remote ranges.

### Follow-ups (not done here)

- Make run.sh's no-network claim true: install the packages into a committed image, then run the tests with `--network none` (F10).
- A no-op apply could reinstate a missing (not trial) drop-in on an installed host. Today only an apply with new state rewrites it, by 03-05's "no-op repairs no drift" design.
- The agent's drop-in could set `AuthorizedPrincipalsCommand none` to shadow a later global command. Not done: it changes `DropIn` on every installed host.
- `detectOpenRC` defaults the binary to `/usr/sbin/sshd`, while Alpine's init script picks `sshd.pam` or `sshd.krb5` from the configuration.
- `internal/agent/paths` `TestAllowed` fails on Windows at the PR head (POSIX paths). It needs a build tag or OS-neutral paths.
- The archlinux snapshot day is taken from the mirrorlist's mtime. An image build that stops writing the mirrorlist would move it, so a digest bump should be checked against the run's "snapshot" line.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-27*
