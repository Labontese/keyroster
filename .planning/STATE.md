---
gsd_state_version: "1.0"
current_phase: 01
current_phase_name: trust-core
status: executing
stopped_at: "01-18 Task 4 merge gate: owner approves PR #24"
last_updated: "2026-10-08T12:31:30.758Z"
last_activity: 2026-10-06
last_activity_desc: Phase 01 execution started
state_head: 3172a056222c5fe13d7ad7befe68432bc1406aed
progress:
  total_phases: 6
  completed_phases: 0
  total_plans: 21
  completed_plans: 19
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-04)

**Core value:** Full visibility: at any moment you know exactly who has access to what, and can revoke it immediately.
**Current focus:** Phase 01 — Trust Core

## Current Position

Phase: 01 (trust-core) — READY TO EXECUTE
Plan: 16 of 16
Status: Ready to execute
Last activity: 2026-10-06 - Completed quick task 261006-ixz: Fix flaky signer freshness-boundary tests with a deterministic test clock

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 01 P01 | 54 min | 4 tasks | 23 files |
| Phase 01 P02 | 31 min | 2 tasks | 32 files |
| Phase 01 P03 | 14 min | 2 tasks | 13 files |
| Phase 01 P16 | 22 min | 3 tasks | 11 files |
| Phase 01 P04 | 23 min | 2 tasks | 7 files |
| Phase 01 P05 | 41 min | 3 tasks | 37 files |
| Phase 01 P06 | 38 min | 3 tasks | 29 files |
| Phase 01 P07 | 35 min | 3 tasks | 28 files |
| Phase 01 P09 | 30 min | 2 tasks | 14 files |
| Phase 01 P08 | 25 min | 2 tasks | 8 files |
| Phase 01 P10 | 25 min | 2 tasks | 5 files |
| Phase 01 P11 | 40 min | 3 tasks | 19 files |
| Phase 01 P12 | 22 min | 2 tasks | 12 files |
| Phase 01 P13 | 47 min | 3 tasks | 26 files |
| Phase 01 P14 | 45 min | 3 tasks | 5 files |
| Phase 01 P15 | 35 min | 3 tasks | 6 files |
| Phase 01 P17 | 35 min | 2 tasks | 6 files |
| Phase 01 P19 | 10 min | 2 tasks | 5 files |
| Phase 01 P18 | 29 min | 3 tasks | 10 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: 6 coarse phases; Phase 2 is the MVP checkpoint (passkey, cert in ssh-agent, real SSH login)
- [Roadmap]: The KRL encoder ships with revocation in Phase 3 (REVOKE-02), not Phase 1 as research suggested; Phase 1 only defines the KRL authority in the trust-bundle format
- [Roadmap]: The who-has-access overview (VIS-04) lands in Phase 5 so it covers plain keys from inventory, not only certificates
- [Roadmap]: Break-glass access (BREAK-01) is in Phase 3, since a dogfooding lockout is the likeliest early incident; break-glass logging (BREAK-02) reuses login reconciliation (VIS-05) in Phase 5
- [Roadmap]: Log witnessing by agents and CLI (VIS-02) is an insider-resistance control in Phase 4
- [Phase 01]: Required status checks keep integration_id 15368 (GitHub Actions); accepted by the API and resolved on PR #1
- [Phase 01]: keyroster-bot (id 337682656) signs with ed25519 key 1218459 held only in the Windows ssh-agent; private key file deleted
- [Phase 01]: scripts/merge-gate.sh rebases with --autostash and an explicit lease so GSD's uncommitted working files cannot block the rebase loop
- [Phase 01]: IssueRequest variable fields use uint16 length prefixes (cryptobyte has no uint32 reader); the 64 KiB frame cap is unchanged
- [Phase 01]: keyroster-signer serve: umask 0077, empty allowlist refused, 32 concurrent connections, single DB connection, SetLastSerial only raises; socket group = first --allow-group
- [Phase 01]: Finding for 01-13: keyroster-signer has no net/http or crypto/tls in its deps but reaches os/exec transitively via modernc.org/libc; depguard only catches direct imports
- [Phase 01]: Admin-only repo settings are applied by the owner via scripts/apply-security-settings.sh; the API accepted all of them including sha_pinning_required=true
- [Phase 01]: Code of Conduct contact is @Labontese via GitHub report-abuse (no private messages on GitHub); flagged for the owner
- [Phase 01]: New third-party actions need a selected-actions allowlist entry (owner) plus a SHA pin; Scorecard publishes only from main, verified in 01-15
- [Phase 01]: IssueRequest.SigningBytes starts with the raw keyroster/issue-request/v1 tag (no uint16 length prefix), per the 01-02 contract; 01-07 signs these bytes
- [Phase 01]: The agent keystore backend skips certificate entries by the -cert-v01@openssh.com key type, since the x/crypto agent client returns entries as agent.Key, never ssh.Certificate
- [Phase 01]: gsd-tools tdd-red-evidence parses only TAP/Surefire; Go RED evidence is recorded in the plan SUMMARY
- [Phase 01]: 01-04: a ruleset that adds required checks is applied by the owner from the PR branch after the checks are green on that PR and before approval (Pitfall 10); Claude never applies rulesets
- [Phase 01]: 01-04: every sshd authentication refusal in e2e runs against its own sshd (OpenSSH >= 9.8 PerSourcePenalties; 9.5p1 lacks the option), and each refusal has a control that succeeds
- [Phase 01]: 01-04: the plan's -L 0:... forwarding case was replaced by -W (direct-tcpip) and -R with ExitOnForwardFailure, because ssh rejects -L 0:... before connecting
- [Phase 01]: 01-05: C2SP type 0x02 (P-256) log checkpoints use key ID = first 4 bytes of SHA-256(SPKI DER) without the key name and an ASN.1 DER signature over SHA-256 of the text (transparency-dev/witness); verified against the published Rekor and Pixel 6 checkpoints
- [Phase 01]: 01-05: A7 confirmed: SQLite documents synchronous=FULL as ACID-durable in WAL mode; TestDurabilityPragmas pins wal + synchronous=2 on the signer DB
- [Phase 01]: 01-05: log origin is keyroster/log/ + 16 hex of SHA-256(log key); the signer refuses to start when stored leaves do not reproduce the latest checkpoint signed by the pinned log key
- [Phase 01]: 01-05: every refusal goes through Signer.refuse (slog, then a refusal leaf within 10/min burst 10, else a count in the next refusal_summary leaf, flushed every minute and on shutdown); one clock_regression leaf per episode
- [Phase 01]: 01-05: duplicate_request stays CodeRefused (pinned by 01-16) although detected after cert.Build; every other post-Build failure returns unavailable and no certificate
- [Phase 01]: 01-06: signed documents are canonical JSON = json.Marshal(struct) + one newline; parsing requires byte equality after a DisallowUnknownFields decode; lists are never null and policy extension lists are sorted
- [Phase 01]: 01-06: internal/sshsig refuses RSA and certificate signers and a non-empty reserved field, emits and accepts sha512 only, and requires the sk user-presence flag explicitly
- [Phase 01]: 01-06: root custody fido is exactly the sk-* key types; a CA, ops or log key equal to a root key is refused at bundle validation (ErrKeyIsRoot)
- [Phase 01]: 01-06: VerifySuccessor needs both the previous and the new root threshold on bundle and policy, version prev+1, prev = SHA-256 of the previous canonical bundle, and issued_at not earlier
- [Phase 01]: 01-06: scripts/fuzz.sh passes -fuzzminimizetime 5s; with Go's 60s default FuzzParseBundle ran 123 execs in a 30s CI budget
- [Phase 01]: 01-06: keyroster root sign reaches ssh-agent via SSH_AUTH_SOCK Unix sockets only; a Windows ceremony needs named-pipe support (go-winio) first
- [Phase 01]: 01-07: IssueRequest gains a signed Extensions field (after CreatedAt, before Evidence) so admin evidence covers requested extensions; critical options have no request field in Phase 1
- [Phase 01]: 01-07: evidence refusals log under the new refusal class unauthorized (15); the detail names the reason (missing_evidence, evidence_not_admin, evidence_wrong_namespace, evidence_digest_mismatch, admin_quorum_not_met, ...)
- [Phase 01]: 01-07: install-bundle and serve read the backend from backend_config and accept --backend-opt overrides, but every key must keep the custody ca-init recorded; InstallBundle takes the backend (the bundle_install checkpoint is signed with the log key)
- [Phase 01]: 01-07: a policy admin key may not be a CA, ops or log key; a successor bundle refuses --pin/--threshold; ca-init requires an empty audit log so ca_init is leaf 0
- [Phase 01]: 01-07: install-bundle requires exactly one active CA entry per role equal to the ca-init key; CA rotation (next/retired entries) changes checkBundleKeys in Phase 3
- [Phase 01]: 01-09: software root file = armored age with one scrypt recipient at age's default work factor (logN 18) wrapping an OpenSSH Ed25519 key; OpenRoot refuses unarmored, non-scrypt and non-Ed25519 files
- [Phase 01]: 01-09: --passphrase-fd is read with syscall.Read on the raw descriptor/handle (no os.NewFile finalizer); passphrases need 20 runes and come only from a TTY or an inherited fd
- [Phase 01]: 01-09: root sign --key refuses a root that roots.pub labels anything but custody=software; every software-root init or sign prints the SOFTWARE ROOT banner, also for --agent-key roots labelled software
- [Phase 01]: 01-09: TestExportedAPI pins rootceremony methods (Type.Method) and fails on any exported result type that could carry a signer or private key
- [Phase 01]: 01-08: audit verify trusts only --pin/--threshold; the log key (checkpoint and --previous) and each role's active CA come only from bundle_install entries verified as genesis (pins) or successor (TUF); Phase 1 refuses a log-key change (log key change unsupported)
- [Phase 01]: 01-08: audit verify requires each issue leaf after the first bundle_install, signed by its role's active CA, a host certificate exactly for the host role, and key ID pol and leaf policy version equal to the policy in force; bundle_install's bundle_version must equal its bundle; --threshold is required
- [Phase 01]: 01-08: host certificates presented as user certificates are tested with an x/crypto/ssh client because the OpenSSH client never offers a non-user certificate; sshd refuses them (Certificate invalid: not a user certificate)
- [Phase 01]: 01-10: CA and root SoftHSM2 tokens use separate token directories and agents (T-01-47); PINs reach pkcs11-tool via env:NAME and ssh-add via SSH_ASKPASS, never argv
- [Phase 01]: 01-10: TestPKCS11Ed25519 asserts refusal on ssh-agent older than 10.1 instead of skipping; fingerprint_test.go (!e2e && (e2e_pkcs11 || e2e_tpm)) supplies fingerprint for hardware-backend e2e builds
- [Phase 01]: 01-11: CI runs the TPM lane on swtpm unixio, the only transport CI exercises; vtpm-proxy rejected (azure runner kernel has no tpm_vtpm_proxy, even in linux-modules-extra) and removed from swtpm-setup.sh by owner decision because it never ran to completion; production /dev/tpmrm0 path is first exercised by the 01-14 dogfood
- [Phase 01]: 01-11: swtpm-tcp transport not built (works with swtpm, but a TCP client in the signer conflicts with KEY-01; unixio needs no root)
- [Phase 01]: 01-11: TPM custody derived from TPM_PT_MANUFACTURER at open time (IBM/MSFT/GOOG = vtpm); the custody option can only weaken to vtpm
- [Phase 01]: 01-11: reserved keystore option state-dir is added by ca-init/install-bundle/serve at open time, never stored, refused as --backend-opt
- [Phase 01]: 01-12: the PIV backend keeps no files; Key() reads each slot's public key and origin through GET METADATA, so firmware below 5.3.0 is refused
- [Phase 01]: 01-12: only piv-go ErrNotFound counts as an empty slot; Provision checks all five slots before generating anything and refuses imported keys, default PIN and default management key
- [Phase 01]: 01-12: mgmt-key-file is needed only for provisioning; the guide moves it off the host after ca-init (serve/install-bundle use --backend-opt mgmt-key-file=)
- [Phase 01]: 01-12: the PIV backend verifies the PIN once at open and refuses on a wrong PIN; piv-go checks the PIN only inside Sign, so otherwise each signing request with a wrong PIN would use up a card PIN retry
- [Phase 01]: 01-13: the signer unit re-allows @chown after ~@privileged (socket chgrp to keyroster-admin); systemd-analyze exposure 0.7 SAFE, threshold 2.0 set in systemd.yml
- [Phase 01]: 01-13: capslock baseline is (package, capability) pairs from -output package (22 packages, 73 pairs); a name-only diff would miss almost everything
- [Phase 01]: 01-13: one dependency-firewall exception, os/exec <- modernc.org/libc (only libc.Xsystem, never referenced by modernc.org/sqlite)
- [Phase 01]: 01-13: doctor never reports vtpm, agent or software keys as hardware custody; capslock -tags piv deferred to 01-15
- [Phase 01]: 01-14: owner decision 'Testceremoni nu, riktig sen' - TEST software roots made on the networked workstation (WSL, unshare -r -n); homelab signer is dogfood only until a real offline ceremony plus successor rotation
- [Phase 01]: 01-14: KEY-07 stays open and must-have truth 2 is unmet; only KEY-04 and VIS-03 marked complete
- [Phase 01]: 01-14: the ceremony transcript is kept by the owner, not committed (runbook step 7 and template corrected)
- [Phase 01]: 01-15: the 9.5p2 check ran on a lab Windows Server 2025 (inbox OpenSSH_for_Windows_9.5p2, file version 9.5.5.1) instead of the owner's workstation, by owner choice; accept PASS, reject PASS
- [Phase 01]: 01-15: the ruleset listing all 17 checks is applied by the owner from the PR branch before approval (admin-only); REPO-01 is marked complete in p01/close after the live-rules check passes
- [Phase 01]: 01-15: capslock -tags piv re-deferred to the next plan that edits CI (needs libpcsclite-dev and must not change a check in the PR that makes it required)
- [Phase 01]: 01-15: KEY-07 stays open; the real offline ceremony means reinstalling the homelab signer until a successor-bundle builder exists
- [Phase 01]: 01-17: root sign --prev DIR builds successor bundles; --ca-pubkeys refused with --prev (CA rotation is KEY-08); a previous or a new root may sign; BuildSuccessor and VerifySuccessor share checkSuccessorChain
- [Phase 01]: 01-17: KEY-07 not marked complete; it closes in 01-21 after the owner's offline ceremony and destruction of the TEST roots
- [Phase 01]: 01-19: KEY-07 removed from requirements-completed in 01-06, 01-07 and 01-09 only; coverage rows and bodies unchanged (owner decision 3)
- [Phase 01]: 01-19: C-WR-06 part 2 and C-WR-01 remainder deferred to Phase 4 (VIS-02); D-WR-02 and D-WR-04 deferred to issue #13 before the Phase 6 external review (owner decision 4)
- [Phase 01]: 01-18: audit verify pins the anchor bundle (first bundle whose root set and threshold equal the pins); earlier bundles are authenticated by the prev-hash chain, no match fails closed
- [Phase 01]: 01-18: trust verify --prev checks a successor with VerifySuccessor, then MatchPins against the new roots' paper fingerprints before install
- [Phase 01]: 01-18: fork_under_old_pins is an accepted residual; after rotating away from exposed roots, auditors pin the new roots (runbook)

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 1]: Ed25519 via PKCS#11/ssh-agent and TPM algorithm support unverified; decide CA key algorithm and custody together in phase research
- [Phase 2]: CLI WebAuthn transport undecided (browser loopback is the default); Windows CTAP access for non-admin users unverified
- [Phase 3]: Unknown whether sshd re-reads `RevokedKeys` without a reload; settle with an integration test
- [Phase 5]: Windows edge cases (principal case, domain/Entra accounts, `verify-required`, KRL on 9.5p2) at LOW-MEDIUM confidence
- [General]: HSM signing throughput under login storms not measured

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 261006-ixz | Fix flaky signer freshness-boundary tests with a deterministic test clock | 2026-10-06 | 66fd3c3 | [261006-ixz-fix-flaky-signer-test-created-301s-futur](./quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/) |

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| *(none)* | | | | |

## Session Continuity

Last session: 2026-10-08T12:31:30.687Z
Stopped at: 01-18 Task 4 merge gate: owner approves PR #24
Resume file: None
