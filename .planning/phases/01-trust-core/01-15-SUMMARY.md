---
phase: 01-trust-core
plan: 15
subsystem: acceptance
tags: [acceptance, windows, openssh-9.5p2, ca-08, rulesets, required-checks, scorecard, audit, dogfood]

requires:
  - phase: 01-03
    provides: Scorecard workflow (publishes from main only) and the pinned-actions and CodeQL checks
  - phase: 01-10
    provides: e2e-pkcs11 lanes
  - phase: 01-12
    provides: build-piv
  - phase: 01-13
    provides: systemd-sandbox, dependency-firewall and capslock
  - phase: 01-14
    provides: homelab vTPM signer (dogfood, TEST roots A/B, bundle v1) with export-log
provides:
  - test/manual/windows-openssh-9.5p2.ps1, a loopback-only temporary sshd check with accept and reject cases and result.json (CA-08 manual 9.5p2 evidence)
  - .github/rulesets/main-integrity.json listing all 17 phase checks (applying it to the live ruleset is the owner's step at the merge gate)
  - CONTRIBUTING.md required-check table with all 17 checks and their workflows
  - Two Windows-check issuances in the homelab signer's log (operational state, not in the repo)
affects: [p01/close, phase-02]

actuals:
  tokens: 5600
  tasks: 3
  commits: 2
plan_head_before: 92c6977fee1849a810436fbafcdaf039fc875f67
plan_head_after: 2957866fbf36adfaea950ab4cbc2d4cc6b88a978

tech-stack:
  added: []
  patterns:
    - "A manual acceptance check runs a throwaway sshd in debug mode (-d, one connection) on 127.0.0.1 from an icacls-restricted temp dir and writes a machine-readable result.json; the installed sshd service is never touched"
    - "Required checks are added to the ruleset file in a PR. The owner applies the file from the PR branch after every check is green and before approving."

key-files:
  created:
    - test/manual/windows-openssh-9.5p2.ps1
    - test/manual/README.md
    - .planning/phases/01-trust-core/01-15-SUMMARY.md
  modified:
    - .github/rulesets/main-integrity.json
    - CONTRIBUTING.md
    - .planning/phases/01-trust-core/deferred-items.md

key-decisions:
  - "01-15: the 9.5p2 check ran on a lab Windows Server 2025 with the inbox OpenSSH_for_Windows_9.5p2 (file version 9.5.5.1), not on the owner's workstation; the owner chose that target and ran it there"
  - "01-15: Claude did not apply the ruleset with the owner token (plan step 2). Rulesets are admin-only, so under the CONTRIBUTING.md rollout rule the owner applies main-integrity.json from the PR branch before approving. The live-rules check (Task 3 verify 1) is pending until then."
  - "01-15: REPO-01 is not marked complete. It is satisfied only once the live ruleset requires all 17 checks, so it is marked in p01/close after that check passes. CA-08 and REPO-03 are marked complete. VIS-03 was already complete, and this plan re-verified it."
  - "01-15: capslock -tags piv is not added (re-deferred to the next plan that edits CI). Its baseline needs libpcsclite-dev, which is not installed locally, and capslock becomes required in this PR, so its content must not change here."
  - "01-15: KEY-07 stays open. The homelab roots are TEST roots, and the real offline ceremony means reinstalling the homelab signer, because no successor-bundle builder exists."

patterns-established:
  - "Scratch dirs of a manual check are removed on every machine that held them, including remote test hosts, and each removal is confirmed with an existence check"

requirements-completed: [CA-08, REPO-03]

coverage:
  - id: D1
    description: "Windows inbox OpenSSH_for_Windows_9.5p2 accepts a homelab-issued user certificate for the listed principal and rejects one for the unlisted principal keyroster-reject-test"
    requirement: CA-08
    verification:
      - kind: manual_procedural
        ref: "Owner ran test/manual/windows-openssh-9.5p2.ps1 elevated on a lab Windows Server 2025. result.json: sshd_version 'OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2', accept PASS, reject PASS, finished_at 2026-10-07T02:19:03Z (after the reject certificate was issued at 02:09:21Z). The Task 2 grep passed on the copied file. Afterwards the sshd service was Running, port 22 was listening and nothing listened on 2222."
        status: pass
    human_judgment: true
    rationale: "The UAC-elevated run is a human-only step; the owner replied 'windows done'."
  - id: D2
    description: "The homelab signer's exported log verifies against the two pinned roots and holds ca_init, bundle_install and the two Windows-check issuances"
    requirement: VIS-03
    verification:
      - kind: manual_procedural
        ref: "keyroster audit verify --pin A --pin B --threshold 1 signer-log.export -> 'OK: 4 entries ... issued 2 (user 2, host 0, machine 0), refusals 0, trust bundle v1, policy v1'. Index 0 ca_init, 1 bundle_install, 2 and 3 issue, with the serials of the accept and reject certificates."
        status: pass
    human_judgment: false
  - id: D3
    description: "main-integrity.json lists exactly the 17 phase checks, and each one reported success on main before it was required"
    requirement: REPO-01
    verification:
      - kind: automated
        ref: "Task 3 verify 2 (node, sorted contexts equal the 17 names): pass. check-runs on main 92c6977: all 16 non-PR checks succeeded under app 15368 (pr-title is skipped on push). On the PR head 2957866, all 17 succeeded under app 15368."
        status: pass
      - kind: automated
        ref: "Task 3 verify 1 (live rules on main equal the 17 names): not yet run. It is pending until the owner applies the ruleset at the merge gate; the live rules still list the old 7."
        status: pending
    human_judgment: true
    rationale: "Applying a ruleset needs admin rights, which only the owner holds."
  - id: D4
    description: "OpenSSF Scorecard publishes for the default branch"
    requirement: REPO-03
    verification:
      - kind: automated
        ref: "Task 3 verify 3: code-scanning analyses with tool_name=Scorecard. The latest, 1905398269 (supply-chain/online-scm), is on refs/heads/main at 92c6977, from scorecard run 37560131304 (push, success); 45 Scorecard analyses in total. The public API and the README badge report 'openssf scorecard: 8'."
        status: pass
    human_judgment: false

duration: ~35min (Task 1 by the previous executor from 02:08Z; owner's Windows run until 02:19Z; Task 3 until about 02:40Z)
completed: 2026-10-07
status: complete
---

# Phase 1 Plan 15: Acceptance (Windows 9.5p2, final required checks, Scorecard) Summary

**Windows' inbox `OpenSSH_for_Windows_9.5p2` accepted a certificate from the homelab vTPM signer and rejected one for an unlisted principal. The homelab log verifies with four entries against both pinned roots. Scorecard publishes from `main` (score 8). `main-integrity.json` now lists all 17 phase checks, all green on PR #18. The owner applies the ruleset from the PR branch before approving.**

## Performance

- **Duration:** about 35 min. Task 1 (previous executor) started at 02:08:44Z. The owner's Windows run finished at 02:19:03Z. Task 3 ran until about 02:40Z on 2026-10-07.
- **Tasks:** 3 of 4. Task 4 is the merge gate.
- **PR:** #18, `test(acceptance): add the Windows OpenSSH 9.5p2 check and require all phase checks`, opened by keyroster-bot. Auto-merge is **not** enabled (see Deviations). Code head `2957866`.

## Windows OpenSSH 9.5p2 result (CA-08)

- **Target:** a lab Windows Server 2025 with the inbox OpenSSH (`sshd.exe` file version 9.5.5.1), a temporary loopback sshd on port 2222.
- **result.json:**
  - `sshd_version`: `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2`
  - `accept`: **PASS**
  - `reject`: **PASS**
  - `finished_at`: `2026-10-07T02:19:03Z`
- **Certificates:** issued by the homelab signer's user CA (`SHA256:InRxix/RORRjHDCbp1a6dCdjWfHVwhOCdZzryALvWi0`), with the owner's admin key as request evidence through a forwarded agent. The accept certificate names the Windows test account. The reject certificate names `keyroster-reject-test`.
- **Service untouched:** after the run, `Get-Service sshd` reported `Running`, port 22 still had listeners, and nothing listened on 2222.
- `test/manual/README.md` has a "Last result" section with these values.

## Homelab log re-verification (VIS-03)

- `keyroster-signer export-log` ran on the signer VM as the signer user and printed `exported 4 entries`. Export SHA-256: `7cce32031e4251c00e70bf6246b0c209449d8c53541f8c2a985b412cc15606ed`.
- `keyroster audit verify --pin SHA256:rLH3utx6DsJeORfSrjkDK9bxFTHjebeJnVog0sX1WbA --pin SHA256:aIDlGVSbtZuDo5wIm6yzA1XGtFk8hb4eFas6qnDjD8M --threshold 1` ran on the workstation with `keyroster` built from this branch (`CGO_ENABLED=0 -trimpath`). It printed:

  `OK: 4 entries, root CywSXEb8Zcm2RpDbrLxAQLzSNjDWZ5l66dzxZJx299Q=, issued 2 (user 2, host 0, machine 0), refusals 0, trust bundle v1, policy v1, log key SHA256:h4CHVPj5/PwKW4A9pp1tt0Lhns09ko5FaD1QUuDhNJU`

- `--json`: `kinds {ca_init: 1, bundle_install: 1, issue: 2}`.
- Entry order:
  - Index 0 is `ca_init`.
  - Index 1 is `bundle_install`.
  - Indices 2 and 3 are the accept and reject issuances. Their serials match the two certificates.
- The log key matches 01-14.

## Final required checks (REPO-01)

`.github/rulesets/main-integrity.json` now requires these 17 checks. Every one keeps `integration_id` 15368 (GitHub Actions):

`build-test`, `lint`, `govulncheck`, `pr-title`, `fuzz`, `e2e (9.5p1)`, `e2e (10.5p1)`, `e2e-pkcs11 (distro-p256)`, `e2e-pkcs11 (10.5p1-ed25519)`, `e2e-tpm`, `build-piv`, `systemd-sandbox`, `dependency-firewall`, `capslock`, `pinned-actions`, `Analyze (go)`, `Analyze (actions)`.

- **Before the change:** on `main` at 92c6977, all 16 checks that run on push succeeded under app 15368. `pr-title` runs on pull requests only and was already required.
- **On PR #18 head `2957866`:** all 17 succeeded under app 15368.
- **CONTRIBUTING.md:** the required-check table lists all 17 with their workflow. The 9.5p2 note points at `test/manual/`.
- **Live-versus-file comparison (read-only, sorted keys):**
  - `main-integrity` differs only by the 10 added contexts.
  - `main-review` differs only by `require_extra_approval_for_unattributed_changes: true` and `required_reviewers: []`. GitHub fills both in, and 01-01 recorded them as its defaults.
- **Live ruleset:** it still requires the old seven checks. It changes when the owner runs `bash scripts/apply-rulesets.sh` from the PR branch at the merge gate (the rollout rule in CONTRIBUTING.md, "Changing the rulesets"). Task 3 verify 1 (the live-rules comparison) runs at the merge gate.

## Scorecard (REPO-03)

- Scorecard workflow run 37560131304 ran on `main` at 92c6977 (push, success).
- It produced three code-scanning analyses on `refs/heads/main`:
  - 1905398269 (`supply-chain/online-scm`)
  - 1905398223 (`supply-chain/local`)
  - 1905398177 (`supply-chain/branch-protection`)
- Scorecard v5.5.0. 45 Scorecard analyses exist in total.
- The public results API (`api.securityscorecards.dev`) reports score 8 for commit 92c6977. The README badge renders `openssf scorecard: 8`.
- The lowest scores come from repository age and process: `Maintained` 0 (the repo is under 90 days old), `CII-Best-Practices` 0, `Code-Review` 5 and `Contributors` 3.

## Deferred items reconciled

These are recorded in `deferred-items.md`.

- **Closed:** the dependency firewall's `-tags piv` pass checks the PIV backend. It downloads `go-piv/piv-go/v2 v2.6.0` and lists 228 packages against 224 for the default pass. Evidence: job 112204110888 (PR #15) and job 112595286211 (`main` at 92c6977).
- **Confirmed:** Scorecard publishing (above).
- **Prepared:** the final required checks. The ruleset file is ready; the owner applies it at the merge gate.
- **Still open, labelled:**
  - capslock `-tags piv`: moved to the next plan that edits CI.
  - `addLogKey` in the e2e harness: the next plan that may edit it.
  - TEST roots, the real offline ceremony and KEY-07. Without a successor-bundle builder, the real ceremony means reinstalling the homelab signer.
  - Real-hardware validation: issue #13.

## Cleanup

All three scratch locations were removed, and each removal was confirmed with an existence check:

- the workstation's `$HOME/keyroster-win-check/` (throwaway private key, certificates, user CA key, log export, the built `keyroster`);
- the lab Windows server's copy of the check inputs, including the throwaway private key;
- the signer VM's temporary directory (public key, certificates, log export).

The signer service stayed `active`.

## Task Commits

1. **Task 1: Windows check script and README.** `f96e985`, `test(01-15): add the manual Windows OpenSSH 9.5p2 acceptance check`.
2. **Task 2: owner's elevated run.** No commit. The owner replied "windows done".
3. **Task 3: required checks, CONTRIBUTING and last result.** `2957866`, `chore(01-15): require all phase checks and record the 9.5p2 result`.

The docs commit (this SUMMARY, `deferred-items.md` and tracking) follows separately.

## Deviations from Plan

### Owner-decided deviations

**1. 9.5p2 target: a lab Windows Server 2025, not the owner's workstation.** The must-have names the workstation. The owner accepted the recommendation and ran the script on a lab Windows Server 2025, whose inbox OpenSSH is the same `OpenSSH_for_Windows_9.5p2`. The result file was read from that server read-only and copied to the workstation scratch dir, so the plan's grep ran unchanged.

### Process deviations

**2. Ruleset not applied by Claude.** Plan step 2 says to run `scripts/apply-rulesets.sh` with the owner token. Rulesets are admin-only, and the orchestrator and CONTRIBUTING.md forbid Claude from using the owner token for it. The owner applies the ruleset from the PR branch at the merge gate, before approving. Task 3 verify 1 (live rules) is therefore pending, not passed.

**3. Auto-merge not enabled.** Claude ran `scripts/gh-as-bot.sh pr merge --auto --squash` (Delivery Protocol step 3). The Claude Code permission classifier denied it ("Merge Without Review"), and Claude did not work around the denial. After approving, the owner either enables auto-merge (squash) in the PR or grants the permission.
  - `scripts/merge-gate.sh` only waits for auto-merge on its normal path.
  - Its rebase path (exit 3) re-enables auto-merge with the bot when the PR has none. A later agent must not take that path unless auto-merge is already on or the owner has granted the permission. Merging without approval is impossible either way, because main-review still requires the owner's approval.

**4. capslock `-tags piv` not added.** `deferred-items.md` assigned it to 01-15, but the plan's files do not include it. Two reasons ruled it out: generating its baseline needs `libpcsclite-dev`, a package install that is not an executor auto-fix, and changing `capslock` in the PR that makes it required would break "succeeded on main before it was required". Moved to the next plan that edits CI.

**5. Cleanup extended to all three machines.** The plan names only the workstation scratch dir. The lab server held a throwaway private key, and the VM held the certificates and the export, so both were removed too.

### Auto-fixed Issues

None.

## Known Stubs

None.

## Owner follow-ups (not part of this plan's code)

- Remove passwordless sudo for the owner's account on the homelab signer VM (set up for 01-14 and 01-15).
- Delete the six public ceremony files from the removable drive used in 01-14.
- Real offline ceremony: reinstall the homelab signer (new state, `ca-init`, genesis bundle from the real roots), because no successor-bundle builder exists yet. KEY-07 stays open until then.
- Optionally remove the lab server's host key line that 01-15 added to the workstation's `known_hosts`.

## Self-Check: PASSED

- `test/manual/windows-openssh-9.5p2.ps1`, `test/manual/README.md` and `.github/rulesets/main-integrity.json` exist on the branch, and commits `f96e985` and `2957866` are in `git log`.
- `$HOME/keyroster-win-check/` no longer exists on the workstation.
- No homelab address, hostname, alias or Windows username appears in the committed changes. A grep of the branch diff and the planning docs for the lab addresses, the VM alias, the owner's account names and home paths matched only the PowerShell role name `[WindowsBuiltInRole]::Administrator` and the label "Run as administrator" in the script.
- Task 3 verify 5 (`scripts/gh-as-bot.sh pr checks p01/15-acceptance --required --watch`) exited 0 against the live seven-check set. The check-runs API shows all 17 phase checks succeeded under app 15368 on the docs head.
