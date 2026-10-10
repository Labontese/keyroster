---
phase: 01-trust-core
verified: 2026-10-10T18:00:00Z
status: gaps_found
score: 4/6 roadmap truths verified (SC1, SC4, SC5 and the goal clause "signing rules cannot be bypassed"; SC2's offline-ceremony clause is an owner-accepted open gap; SC3's real-hardware clause is present but behavior-unverified); 150/153 plan must-have truths verified or attested (1 FAILED by owner decision, 1 behavior-unverified, 1 superseded by owner decision)
covered_files:
  - ".github/workflows/ci.yml"
  - ".github/workflows/codeql.yml"
  - ".github/workflows/piv.yml"
  - ".github/workflows/pr-title.yml"
  - ".github/workflows/systemd.yml"
  - ".golangci.yml"
  - ".planning/phases/01-trust-core/01-01-PLAN.md"
  - ".planning/phases/01-trust-core/01-01-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-02-PLAN.md"
  - ".planning/phases/01-trust-core/01-02-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-03-PLAN.md"
  - ".planning/phases/01-trust-core/01-03-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-04-PLAN.md"
  - ".planning/phases/01-trust-core/01-04-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-05-PLAN.md"
  - ".planning/phases/01-trust-core/01-05-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-06-PLAN.md"
  - ".planning/phases/01-trust-core/01-06-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-07-PLAN.md"
  - ".planning/phases/01-trust-core/01-07-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-08-PLAN.md"
  - ".planning/phases/01-trust-core/01-08-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-09-PLAN.md"
  - ".planning/phases/01-trust-core/01-09-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-10-PLAN.md"
  - ".planning/phases/01-trust-core/01-10-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-11-PLAN.md"
  - ".planning/phases/01-trust-core/01-11-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-12-PLAN.md"
  - ".planning/phases/01-trust-core/01-12-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-13-PLAN.md"
  - ".planning/phases/01-trust-core/01-13-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-14-PLAN.md"
  - ".planning/phases/01-trust-core/01-14-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-15-PLAN.md"
  - ".planning/phases/01-trust-core/01-15-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-16-PLAN.md"
  - ".planning/phases/01-trust-core/01-16-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-17-PLAN.md"
  - ".planning/phases/01-trust-core/01-17-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-18-PLAN.md"
  - ".planning/phases/01-trust-core/01-18-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-19-PLAN.md"
  - ".planning/phases/01-trust-core/01-19-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-20-PLAN.md"
  - ".planning/phases/01-trust-core/01-20-SUMMARY.md"
  - ".planning/phases/01-trust-core/01-21-PLAN.md"
  - ".planning/phases/01-trust-core/01-21-SUMMARY.md"
  - "CONTRIBUTING.md"
  - "cmd/keyroster-signer/cainit.go"
  - "cmd/keyroster-signer/commands.go"
  - "cmd/keyroster-signer/doctor.go"
  - "cmd/keyroster-signer/doctor_test.go"
  - "cmd/keyroster-signer/install.go"
  - "cmd/keyroster-signer/lock.go"
  - "cmd/keyroster-signer/lock_test.go"
  - "cmd/keyroster-signer/restart_test.go"
  - "cmd/keyroster-signer/serve.go"
  - "cmd/keyroster/audit.go"
  - "cmd/keyroster/root.go"
  - "cmd/keyroster/root_test.go"
  - "cmd/keyroster/trust.go"
  - "cmd/keyroster/trust_test.go"
  - "deploy/systemd/keyroster-signer.service"
  - "docs/backends/piv.md"
  - "docs/backends/pkcs11.md"
  - "docs/runbooks/root-ceremony.md"
  - "docs/runbooks/signer-install.md"
  - "docs/security/custody.md"
  - "docs/security/needs-hardware.md"
  - "internal/audit/verify.go"
  - "internal/audit/verify_test.go"
  - "internal/cert/builder.go"
  - "internal/cert/builder_test.go"
  - "internal/certprofile/certprofile.go"
  - "internal/doctor/doctor.go"
  - "internal/doctor/doctor_test.go"
  - "internal/keystore/agent/agent.go"
  - "internal/keystore/agent/agent_test.go"
  - "internal/keystore/agent/export_test.go"
  - "internal/keystore/agent/reconnect_test.go"
  - "internal/keystore/keystore.go"
  - "internal/keystore/piv/card.go"
  - "internal/keystore/piv/piv.go"
  - "internal/keystore/piv/piv_test.go"
  - "internal/keystore/piv/yubikey.go"
  - "internal/keystore/tpm/inspect.go"
  - "internal/keystore/tpm/provision.go"
  - "internal/keystore/tpm/tpm.go"
  - "internal/keystore/tpm/tpm_test.go"
  - "internal/keystore/tpm/vendor.go"
  - "internal/keystore/tpm/vendor_test.go"
  - "internal/signer/evidence_test.go"
  - "internal/signer/issue.go"
  - "internal/signer/listen_test.go"
  - "internal/signer/log_test.go"
  - "internal/signer/logstate.go"
  - "internal/signer/overload_test.go"
  - "internal/signer/refusal.go"
  - "internal/signer/refusalcause_test.go"
  - "internal/signer/server.go"
  - "internal/signer/signer.go"
  - "internal/signer/trust.go"
  - "internal/signer/trust_test.go"
  - "internal/signer/trustanchor_test.go"
  - "internal/signer/trustchange_test.go"
  - "internal/signerdb/db.go"
  - "internal/signerdb/db_test.go"
  - "internal/signerdb/issuance.go"
  - "internal/signerdb/log.go"
  - "internal/signerdb/trust.go"
  - "internal/trust/bundle.go"
  - "internal/trust/bundle_test.go"
  - "internal/trust/policy.go"
  - "internal/trust/successor.go"
  - "internal/trust/successor_test.go"
  - "internal/trust/verify.go"
  - "internal/trust/verify_test.go"
  - "scripts/gh-as-bot.sh"
  - "scripts/merge-gate.sh"
  - "test/e2e/audit_test.go"
  - "test/e2e/doctor_test.go"
  - "test/e2e/pkcs11_test.go"
  - "test/e2e/root_sk_test.go"
  - "test/e2e/rotation_test.go"
  - "test/e2e/tpm_test.go"
  - "test/systemd/smoke.sh"
covered_digest: "v3:sha256:036b3b8c9ea5adf09baa1c3fef12ac96a6a3e8d7044c82582cbe59d439454eea"
behavior_unverified: 1
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: "3/5 roadmap success criteria verified (goal-level truth FAILED); 119/121 plan must-have truths verified or attested"
  previous_report: "git show 31f3eb7:.planning/phases/01-trust-core/01-VERIFICATION.md"
  gaps_closed:
    - "Gap 1 (A-CR-01/C-CR-01): a policy change installed on the signer takes effect for the next request (goal clause 'signing rules cannot be bypassed')"
    - "Gap 2 (B-CR-01): the trust root is never an issuance authorizer (no root key may be a policy admin)"
    - "Gap 4 (D-CR-02): CA keys recorded as TPM custody were generated inside the TPM"
    - "Gap 5 (D-CR-01): a YubiKey PIV CA key survives a misconfigured PIN under the shipped unit"
    - "Gap 3, tooling part: successor-bundle builder (root sign --prev), trust verify --prev, audit anchoring on a later bundle, and the KEY-07 SUMMARY overclaims removed"
  gaps_remaining:
    - "Gap 3, ceremony part (SC2/KEY-07): the offline trust-root ceremony has never been performed; the homelab rests on TEST roots C and D (owner-accepted, owed as a v3 rotation)"
  reclassified:
    - "Gap 6 (SC3 real hardware: YubiHSM 2, real YubiKey PIV) moved from gaps to behavior-unverified / human verification: the code paths are present, wired and CI-tested on SoftHSM2 and a fake card; only owner hardware can close it (issue #13)"
  regressions: []
gaps:
  - truth: "SC2/KEY-07 (offline-ceremony clause): the admin has run the offline trust-root ceremony (M-of-N root keys, software on offline media or hardware) and the homelab signer is anchored on roots from it"
    status: failed
    accepted_open: true
    reason: "OWNER-ACCEPTED OPEN GAP, not a code defect. Owner decision 2026-10-09 (deferred-items.md, 01-14 entry 'Rehearsal rotation, not the real ceremony', and the 01-20/01-21 entry; ROADMAP Phase 1 Plans line): KEY-07 stays open until the owner performs the real offline ceremony as a v3 rotation co-signed by TEST root C or D. All tooling the ceremony needs exists and is CI-tested (root init, root sign genesis and --prev with --prev-sha256, trust verify --prev, audit verify anchored on any bundle; e2e TestRootRotationLiveSigner PASS on sshd 9.5p1 and 10.5p1). What has not happened: no ceremony on a live USB with separate physical media and paper fingerprints. The homelab signer runs bundle v2 on TEST roots C and D, generated in WSL on the networked workstation (01-20 coverage D5: fail; 01-21 coverage D5: fail; 01-14 must-have truth 2 still FAILED). No later roadmap phase owns the ceremony, so Step 9b cannot defer it; the recorded owner decision is the reason it is open, not a phase that closes it."
    artifacts:
      - path: "docs/runbooks/root-ceremony.md"
        issue: "Offline steps of 'Rotate the roots' and of the genesis ceremony are labelled UNVERIFIED (lines ~414-435); the --prev-sha256 path has never run outside tests"
      - path: ".planning/phases/01-trust-core/deferred-items.md"
        issue: "Records the owed v3 rotation; no target phase"
    missing:
      - "Owner action (no code): run the offline ceremony on a live USB, two new roots on separate sticks with paper fingerprints; build successor v3 with root sign --prev --prev-sha256 <recorded v2 hash>; co-sign with C or D; trust verify --prev against the paper fingerprints; stop / install-bundle / start on the homelab signer; audit verify pinned to the new roots; destroy C and D and their passphrase files"
      - "Then mark KEY-07 complete in REQUIREMENTS.md and flip 01-14 truth 2"
      - "Or: the owner accepts this deferral formally with the override suggested in this report (the status then becomes human_needed, not passed, because the hardware items remain)"
deferred:
  - truth: "SC5: a log rolled back or truncated to an earlier signed prefix is detected without an operator-supplied --previous checkpoint (C-WR-01 remainder)"
    addressed_in: "Phase 4"
    evidence: "Phase 4 SC4: 'Agents and the CLI verify signed checkpoints with consistency proofs and raise an alert if the log ever shrinks or forks (e.g. a DB admin rewriting history)'; VIS-02 is mapped to Phase 4; deferred-items.md 'C-WR-01 remainder' targets Phase 4"
  - truth: "SC4: serial non-reuse after restore when the wall clock is restored with the snapshot (A-IN-04)"
    addressed_in: "Phase 6"
    evidence: "Phase 6 SC3: 'Admin can back up and restore server state (encrypted); after a restore no serial is reissued and the audit log is intact and still verifies' (OPS-01)"
advisory:
  - finding: "The owner decision of 2026-10-10 to keep passwordless sudo on the homelab test VM is not recorded in .planning/: 01-21-PLAN truth 8, 01-21-SUMMARY coverage D6 (status: pending), the ROADMAP 01-21 plan line and STATE.md stopped_at all still say the sudo rule is removed"
    category: other
    reason: "Relayed to the verifier by the orchestrator; not a gap per owner instruction. Record the decision (deferred-items.md or 01-21-SUMMARY) and correct the ROADMAP/STATE wording, or accept 01-21 truth 8 by override"
    evidence_status: "none provided (documentation drift only)"
  - finding: "REQUIREMENTS.md traceability is stale: every Phase 1 row reads 'Gaps Found' and REPO-01 reads 'Pending', although REPO-01..04, CA-01..08, KEY-01, KEY-03..05, VIS-01 and VIS-03 are satisfied in code and CI"
    category: other
    reason: "Update the traceability table after this verification is accepted; KEY-07 stays Pending"
    evidence_status: "none provided (documentation drift only)"
behavior_unverified_items:
  - truth: "SC3 (real-hardware clause) / KEY-03 / KEY-05: CA keys in a YubiHSM 2 reached via ssh-agent, and in a real YubiKey PIV slot (Ed25519 on firmware >= 5.7, P-256 below), including the PIN-retry guard on a real card"
    test: "Run the PKCS#11 flow (docs/backends/pkcs11.md) against a YubiHSM 2 and the PIV flow (keyroster-signer built with -tags piv, ca-init --backend piv) against a real YubiKey; issue, log in to sshd, audit verify; start once with a wrong pin-file and confirm exit 78, no restart, and that the card still has >= 2 PIN retries"
    expected: "Keys generated on-device, custody recorded truthfully, certificate accepted by sshd, audit verifies; the wrong PIN never drives the retry counter below 2"
    why_human: "CI uses SoftHSM2 and a fake PIV card (TestPIVPINRetriesGuard PASS in build-piv job 114264163393); no physical device exists in CI (issue #13, needs-hardware, OPEN)"
coincidental_reliance_items:
  - truth: "SC4: a serial is never reissued after the signer's state is restored from an older copy"
    reason: undeclared-precondition
    harden: "Holds only while the wall clock after restore is ahead of every pre-restore serial (internal/serial/serial.go; TestSignerRestore uses a forward clock). Persist a high-water mark outside signer.db, or witness it. Phase 6 SC3 owns this."
human_verification:
  - test: "SC3 real hardware (issue #13): YubiHSM 2 via ssh-agent and a real YubiKey PIV slot, as in behavior_unverified_items"
    expected: "Issuance, sshd acceptance and audit verify succeed; custody truthful; PIN-retry guard holds on the real card"
    why_human: "Needs owner hardware"
  - test: "Upgrade the homelab signer from the 6956392 build to d623927 (main after PR #27); start the sandboxed unit; run keyroster-signer doctor; issue one certificate; export and run keyroster audit verify pinned to C and D and to A and B"
    expected: "serve starts (the new root-as-admin-across-all-bundles and validity-window start-up checks accept the real state), doctor shows no FAIL, audit verify prints OK under both pin sets"
    why_human: "01-REVIEW-FIX.md 'UNVERIFIED': only audit verify of the post-01-21 export was run with the PR #27 code; serve and doctor with this build have never run on the real homelab state, which is reachable only by the owner"
---

# Phase 1: Trust Core Verification Report

**Phase Goal:** An admin can stand up a hardware-backed, auditable CA whose certificates stock OpenSSH accepts and whose signing rules cannot be bypassed, before any user or host exists.
**Verified:** 2026-10-10
**Status:** gaps_found (one owner-accepted open gap: the real offline root ceremony, KEY-07; no code gaps remain)
**Re-verification:** Yes, after gap closure (PR #20, gap plans 01-17..01-21 in PRs #21-#26, re-review fixes in PR #27). The previous report is at `git show 31f3eb7:.planning/phases/01-trust-core/01-VERIFICATION.md`.
**Code under test:** `p01/close-reverify` = origin/main `d623927`. The working tree differs only in `.planning/config.json` (one GSD key) and two untracked planning files.

## Method and evidence base

- **CI on main at d623927** (`gh api .../commits/d623927/check-runs`): the 16 required contexts that run on push all completed with success: build-test, lint, govulncheck, fuzz (job 114264163799), capslock, dependency-firewall, pinned-actions, e2e (9.5p1) 114264163598, e2e (10.5p1) 114264163737, e2e-pkcs11 (distro-p256, 10.5p1-ed25519), e2e-tpm 114264163563, build-piv 114264163393, systemd-sandbox, Analyze (go) and Analyze (actions). The 17th required context, pr-title, runs on pull requests only and passed on PR #27. Scorecard (not required) also succeeded. `fuzz` completed with success on main after the report was drafted (and on the PR #27 head, job 114170575958).
- **CI job logs read for test names**:
  - e2e 9.5p1 and 10.5p1: 16 top-level tests PASS each, 0 SKIP, including the new `TestRootRotationLiveSigner`.
  - e2e-tpm: `TestImportedKeyRefused`, `TestProvisionNoDA` and `TestKeyRefusals` PASS. These tests skip locally because there is no swtpm.
  - build-piv: `TestPIVPINRetriesGuard` with 4 subtests PASS.
- **Local run.** WSL, Go 1.27.1, clean clone at d623927: `go test -count=1 ./...` gave all 15 packages `ok`, which was the one full run. Named tests were then run once each:
  - TestTrustChangedUnderLiveSigner, TestTrustChangedDuringIssue, TestListenKeepsLiveSocket;
  - TestStateDirLock, TestCredentialRefusedExitStatus, TestUnitRestartPolicy;
  - TestTrustVerifySuccessor/foreign_prev_refused_by_both_commands;
  - TestCheckGeneratedInTPM.
  All passed except TestImportedKeyRefused, which SKIPs locally (no swtpm); its evidence is the CI job above.
- **Live GitHub state:**
  - rules on main: deletion, non_fast_forward, required_linear_history, required_signatures, required_status_checks with 17 contexts, and pull_request;
  - PRs #16-#27 were all merged by keyroster-bot with APPROVED;
  - the last 12 commits on main have `verification.verified=true`;
  - secret scanning, push protection and Dependabot security updates are enabled;
  - issue #13 is OPEN.
- **Code reading.** Every previous gap was checked against source (details below), and so was the re-review blocker G-CR-01 with its fix.
- **Owner or orchestrator attestation, not re-runnable here:**
  - the homelab rotation to v2 (01-20);
  - the destruction of TEST roots A and B (01-21). This is corroborated locally: WSL `~/kr-test-ceremony` holds only `root-a.age.pub` and `root-b.age.pub`, and `find ~ -maxdepth 4` finds no `root-a.age`, `root-b.age`, `passA.txt` or `passB.txt`;
  - `audit verify` of the post-01-21 homelab export with the PR #27 code (01-REVIEW-FIX.md).

## Goal Achievement: Roadmap Success Criteria (contract)

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | PR-only main, signed commits, review, green CI, pinned least-privilege actions, CodeQL/Dependabot/secret scanning/Scorecard, community files | ✓ VERIFIED | Unchanged from the previous report and re-checked live: 17 required contexts, signed commits, approved PRs, security settings. No regression. |
| 2 | Offline trust-root ceremony with M-of-N roots (software on offline media or hardware); root signs bundles, KRL authority and policy; tooling refuses to use it for certificates | ✗ FAILED (offline-ceremony clause only; **owner-accepted open gap**) | **Tooling: VERIFIED.**<br>• `root init`, `root sign` (genesis and `--prev`), `trust verify --prev` and audit anchoring all exist.<br>• B-CR-01 is closed: `trust.CheckAdminsNotRoots` (internal/trust/verify.go:174-196) is enforced in VerifyGenesisBundle (:95), the successor chain (:365), `root sign` (cmd/keyroster/root.go:305), install (internal/signer/trust.go:345), start-up (logstate.go:116) and `audit verify` across every logged bundle (internal/audit/verify.go:120, F-WR-02).<br>• G-CR-01 is closed: `loadPrev` (cmd/keyroster/trust.go:131-152) requires `--prev-sha256` and prev's own threshold signatures, and `TestTrustVerifySuccessor/foreign_prev_refused_by_both_commands` PASSes.<br>• G-WR-01 is closed: `checkCarriedCustody` (verify.go:377).<br>• The KRL authority is the root-signed ops key (bundle.go:91), used from Phase 3.<br>**Ceremony: NOT PERFORMED.** The homelab rests on TEST roots C and D (rehearsal in WSL on a networked host). The owner decided on 2026-10-09 that KEY-07 stays open until a v3 offline rotation. |
| 3 | Separate user/host/machine CAs in PKCS#11-via-agent (SoftHSM2 CI, YubiHSM 2 real), TPM 2.0 or YubiKey PIV; only the network-less signer uses them | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED (real-hardware clause) | **D-CR-02 closed.** `checkGeneratedInTPM` (internal/keystore/tpm/tpm.go:233-240) refuses keys without FixedTPM, FixedParent and SensitiveDataOrigin. TestImportedKeyRefused PASSes in e2e-tpm on swtpm, and Provision sets NoDA (D-WR-01).<br>**D-CR-01 closed.** `PINRetries()` runs before VerifyPIN, which needs at least 2 retries left (piv.go:154-162). `exitCredentialRefused = 78` (commands.go:42). The unit has `RestartSec=5s`, `RestartPreventExitStatus=78`, `StartLimitBurst=5` and `StartLimitIntervalSec=10min`. TestPIVPINRetriesGuard, TestCredentialRefusedExitStatus and TestUnitRestartPolicy PASS.<br>**Still green:** SoftHSM2 lanes, swtpm and systemd-sandbox.<br>**Never run:** a YubiHSM 2 or a real YubiKey (issue #13). |
| 4 | sshd 9.5p2 and latest accept; unique non-zero never-reissued serial (also after restore); structured key ID; permit-pty only; refusals | ✓ VERIFIED (coincidental-reliance advisory carried) | e2e TestIssueAcceptedBySSHD, TestSSHDRejects and TestSignerRefuses PASS on 9.5p1 and 10.5p1. The Windows 9.5p2 run is unchanged (owner-run, 01-15). Serial restore safety still relies on the wall clock, which is deferred to Phase 6. |
| 5 | Every issuance in the Merkle log before release; `audit verify` end to end, fails on tamper/removal, exports | ✓ VERIFIED | The previous A-CR-01 caveat is gone: an issuance can no longer be logged after a successor's `bundle_install` (issue.go:161, TestTrustChangedUnderLiveSigner asserts the export still verifies). `audit verify` now anchors on any pinned bundle (TestVerifyAnchorsOnLaterBundle). F-WR-01 adds a check that the validity window starts at issuance. TestAuditVerifiesIssuance and TestAuditDetectsTampering PASS on both e2e lanes. |
| G | Goal clause: "whose signing rules cannot be bypassed" | ✓ VERIFIED (behaviorally) | A-CR-01 is closed in three layers:<br>(1) `checkTrustCurrent` runs before signing and again inside the issuance transaction (internal/signer/issue.go:84, 161, 217-230) and refuses `trust_changed`;<br>(2) an exclusive flock on `{state}/signer.lock` is taken by serve (serve.go:87) and by ca-init and install-bundle through `openState` (serve.go:220-224);<br>(3) `Listen` probes a live socket and refuses to unlink it (server.go:34-56).<br>Behavioral tests: TestTrustChangedUnderLiveSigner (refuses, export verifies, restart picks up pol=2), TestTrustChangedDuringIssue (a successor installed mid-signing still refuses, nothing is logged), TestStateDirLock and TestListenKeepsLiveSocket all PASS. e2e TestRootRotationLiveSigner shows that install-bundle is refused while serve runs. B-CR-01 is closed (see SC2). |

**Score:** 4/6 roadmap truths verified (1 present, behavior-unverified: SC3 hardware; 1 failed by owner decision: SC2 ceremony).

### Deferred Items

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | Log rollback to an earlier signed prefix detected without `--previous` (C-WR-01 remainder) | Phase 4 | Phase 4 SC4 (consistency proofs, alert on shrink or fork); VIS-02 |
| 2 | Serial non-reuse when the wall clock is restored with the snapshot (A-IN-04) | Phase 6 | Phase 6 SC3 (restore without serial reissue); OPS-01 |

Design-level review items that deferred-items.md records with targets are not gaps against the SC wording. They are:
- C-WR-06 part 2 (offline authorization check in `audit verify`), targeted at Phase 4;
- D-WR-02 (TPM EK-certificate authentication) and D-WR-04 (PIV attestation), targeted at issue #13 before the Phase 6 review.

### Advisory (New Scope, Unevidenced)

| # | Finding | Category | Why Advisory |
|---|---------|----------|--------------|
| 1 | The owner decision of 2026-10-10 to keep passwordless sudo on the test VM is not recorded in `.planning/`. 01-21 truth 8, the ROADMAP 01-21 line and STATE.md still say it is removed. | other | Documentation drift; the owner instructs that it is not a gap |
| 2 | REQUIREMENTS.md traceability is stale: every row reads "Gaps Found" and REPO-01 reads "Pending". | other | Documentation drift |

### Required Artifacts (gap closure)

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `internal/signer/issue.go` | Bundle-version check before signing and inside logTx | ✓ VERIFIED | Lines 84, 161, 217-230; wired to `signerdb.LatestBundleVersion[Tx]` (signerdb/trust.go:158-166) |
| `cmd/keyroster-signer/lock.go` | Exclusive state-dir flock | ✓ VERIFIED | Used by serve, ca-init and install-bundle |
| `internal/signer/server.go` | Listen refuses a live socket | ✓ VERIFIED | Dial probe; unlinks only on ECONNREFUSED |
| `internal/trust/verify.go` | CheckAdminsNotRoots, checkCarriedCustody, VerifySelfSigned | ✓ VERIFIED | Wired in trust, signer, audit and CLI |
| `internal/trust/successor.go` + `cmd/keyroster/root.go` | `root sign --prev` successor builder | ✓ VERIFIED | Shares `checkSuccessorChain` with VerifySuccessor; `--prev-sha256` is mandatory |
| `cmd/keyroster/trust.go` | `trust verify --prev`, `loadPrev` | ✓ VERIFIED | Hash pin plus prev self-signature |
| `internal/audit/verify.go` | Anchor on any pinned bundle; admins-not-roots across all bundles; validity placement | ✓ VERIFIED | Unit tests PASS; e2e audit tests PASS |
| `internal/keystore/tpm/tpm.go` | Refuse imported/duplicable keys | ✓ VERIFIED | `checkGeneratedInTPM`; swtpm PASS in CI |
| `internal/keystore/piv/piv.go`, `card.go` | PIN-retry guard | ✓ VERIFIED (fake card) | Real card: see human verification |
| `deploy/systemd/keyroster-signer.service` | No restart on credential refusal | ✓ VERIFIED | RestartPreventExitStatus=78, RestartSec, StartLimit*; TestUnitRestartPolicy |
| `docs/runbooks/root-ceremony.md` | Rotation runbook with honest labels | ✓ VERIFIED | Offline steps are labelled UNVERIFIED |

### Key Link Verification

| From | To | Via | Status |
|---|---|---|---|
| install-bundle / ca-init | serve | `openState` → `lockStateDir` flock | WIRED |
| Issue | installed bundle | `checkTrustCurrent(LatestBundleVersionTx)` inside `logTx` | WIRED |
| root sign --prev / trust verify --prev | bundle in force | `loadPrev` (SHA-256 pin + `VerifySelfSigned`) | WIRED |
| BuildSuccessor | VerifySuccessor | shared `checkSuccessorChain` (+ `checkCarriedCustody`, `CheckAdminsNotRoots`) | WIRED |
| audit verify | all logged bundles' roots | `CheckAdminsNotRoots(p, a.roots...)` | WIRED |
| piv backend | systemd | `keystore.ErrCredentialRefused` → exit 78 → `RestartPreventExitStatus=78` | WIRED |

### Data-Flow Trace (Level 4)

Not applicable. There is no rendered UI in this phase. The relevant flow is "installed bundle version → issuance decision", which is traced above and exercised by TestTrustChangedDuringIssue.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Whole unit suite at d623927 | `go test -count=1 ./...` (WSL clean clone, run once) | 15 packages ok | ✓ PASS |
| Live successor install is refused, the log stays verifiable | `go test -run 'TestTrustChangedUnderLiveSigner\|TestTrustChangedDuringIssue\|TestListenKeepsLiveSocket' ./internal/signer/` | PASS | ✓ PASS |
| State lock, exit 78, unit restart policy | `go test -run 'TestStateDirLock\|TestCredentialRefusedExitStatus\|TestUnitRestartPolicy' ./cmd/keyroster-signer/` | PASS | ✓ PASS |
| Forged prev refused by both commands (G-CR-01) | `go test -run 'TestTrustVerifySuccessor/foreign_prev' ./cmd/keyroster/` | PASS | ✓ PASS |
| Imported TPM key refused | e2e-tpm job 114264163563 log | TestImportedKeyRefused PASS (local: SKIP, no swtpm) | ✓ PASS (CI) |
| Rotation end to end with real binaries and sshd | e2e jobs 114264163598 / 114264163737 | TestRootRotationLiveSigner PASS on both | ✓ PASS |

### Probe Execution

No `scripts/*/tests/probe-*.sh` exists, and no PLAN declares one. Skipped.

### Plan must-have truths (153)

| Plans | Truths | Result |
|---|---|---|
| 01-01 … 01-16 | 121 | 119 VERIFIED or attested, unchanged and with no regression in CI. 01-14 truth 2 (offline USB ceremony) is still FAILED, covered by the accepted open gap. 01-12 PIV real card is behavior-unverified. |
| 01-17 successor builder | 7 | 7 VERIFIED (TestBuildSuccessor, TestRootSignSuccessor*, e2e TestRootRotationLiveSigner) |
| 01-18 verify rotations | 6 | 6 VERIFIED (TestMatchPins, TestVerifyAnchorsOnLaterBundle, TestTrustVerifySuccessor; the runbook has UNVERIFIED labels) |
| 01-19 planning corrections | 3 | 3 VERIFIED: `grep -l '^requirements-completed:.*KEY-07' *-SUMMARY.md` finds nothing, and deferred-items.md has the four design items |
| 01-20 rehearsal rotation | 8 | 8 VERIFIED or attested. The homelab steps are owner- and agent-attested. Truth 2 (honest labelling) is VERIFIED; the SUMMARY has "Offline ceremony: UNVERIFIED (rehearsal)" and coverage D5 is fail. |
| 01-21 retire A and B | 8 | 7 VERIFIED or attested. The WSL removal of A and B is corroborated locally. Truth 8 (sudo removed) is **superseded** by the 2026-10-10 owner decision relayed by the orchestrator: it is excluded from the score and not a gap, and an override is suggested. |

Totals: 150 VERIFIED or attested, 1 FAILED (owner-accepted), 1 PRESENT_BEHAVIOR_UNVERIFIED, and 1 superseded.

## Requirements Coverage

All 19 phase IDs appear in at least one PLAN's `requirements:` field. Every ID that REQUIREMENTS.md maps to Phase 1 is covered by a plan, so none is orphaned. No SUMMARY claims KEY-07.

| Requirement | Source Plans | Status | Evidence |
|---|---|---|---|
| REPO-01 | 01-01, 01-04, 01-15 | ✓ SATISFIED | Live rules on main (17 checks, signatures, linear history, PR review). REQUIREMENTS.md still says Pending. |
| REPO-02 | 01-01..04, 01-13, 01-16 | ✓ SATISFIED | All CI jobs are green on d623927. Open warning E-WR-04: the piv build is not scanned by govulncheck or CodeQL, and capslock-piv is still owed (deferred-items.md). |
| REPO-03 | 01-03, 01-15 | ✓ SATISFIED | Live settings, CodeQL and Scorecard on main |
| REPO-04 | 01-01, 01-03 | ✓ SATISFIED | Files present (CONTRIBUTING updated in PR #27) |
| CA-01 | 01-07, 01-08 | ✓ SATISFIED | e2e TestMachineCAIsSeparate, TestHostCAIsNotUserCA, TestHostCertificateNoTOFU |
| CA-02 | 01-02, 01-04, 01-16 | ✓ SATISFIED | TestSignerRefuses e2e; validate tables and fuzz |
| CA-03 | 01-02, 01-05, 01-16 | ✓ SATISFIED | Wall-clock restore reliance deferred to Phase 6 |
| CA-04 | 01-02, 01-07, 01-08, 01-16 | ✓ SATISFIED | keyid.go; `pol=` cannot now be stamped after a successor (A-CR-01 closed) |
| CA-05 | 01-02, 01-04, 01-07, 01-08, 01-16 | ✓ SATISFIED | TestSSHDRejects forwarding cases |
| CA-06 | 01-02, 01-04, 01-16 | ✓ SATISFIED | GenerateKey/SignCert guards |
| CA-07 | 01-02, 01-04, 01-07, 01-16 | ✓ SATISFIED | CheckCAKey |
| CA-08 | 01-02, 01-04, 01-15 | ✓ SATISFIED | CI on 9.5p1 and 10.5p1, plus the owner-run Windows 9.5p2 check |
| KEY-01 | 01-02, 01-07, 01-13, 01-16 | ✓ SATISFIED | systemd-sandbox, dependency-firewall, capslock; trust reload now enforced |
| KEY-03 | 01-02, 01-10 | ✓ SATISFIED (SoftHSM2) / ? NEEDS HUMAN (YubiHSM 2) | Issue #13 |
| KEY-04 | 01-11, 01-14 | ✓ SATISFIED | D-CR-02 closed (generated-in-TPM check, NoDA). EK authentication (D-WR-02) is deferred to #13 and hardens only the `tpm` vs `vtpm` label. |
| KEY-05 | 01-12 | ✓ SATISFIED in code (D-CR-01 closed) / ? NEEDS HUMAN (real card) | Fake card only |
| KEY-07 | 01-06, 01-07, 01-09, 01-10, 01-14, 01-17..01-21 | ✗ OPEN by owner decision | "Signs only" is now enforced (B-CR-01, F-WR-02, G-CR-01, G-WR-01 closed). The offline ceremony has not been performed and is owed as a v3 rotation. Correctly Pending in REQUIREMENTS.md. |
| VIS-01 | 01-05, 01-07 | ✓ SATISFIED (issuance, refusals, ca_init, bundle_install) | issue.go logTx; revocation and approval come in later phases |
| VIS-03 | 01-05, 01-08, 01-14, 01-15, 01-18, 01-20 | ✓ SATISFIED | `audit verify` anchors on any bundle; export; the homelab log verifies (attested) |

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| test/systemd/smoke.sh | 62 | `XXXXXX` | ℹ️ Info | A `mktemp` template, not a debt marker |
| (86 changed non-planning files since 13d55c4) | | TBD, FIXME, XXX, TODO or HACK | none | No debt markers |

Re-review (01-REVIEW.md, 2026-10-10): 1 critical and 7 warnings, all fixed in PR #27 (01-REVIEW-FIX.md: `status: all_fixed`). I confirmed the critical fix G-CR-01 in code and in a named test. The 12 Info items were out of scope and are not blockers. The earlier review's warnings that remain open are tracked in deferred-items.md: C-WR-06 part 2, D-WR-02, D-WR-04, E-WR-04 and capslock-piv.

## Human Verification Required

### 1. Real-hardware CA keys (SC3, KEY-03, KEY-05; issue #13)

**Test:** Run the PKCS#11 flow against a YubiHSM 2 through ssh-agent, and the PIV flow (`-tags piv`) against a real YubiKey: Ed25519 on firmware 5.7 or later, P-256 below that. Issue a certificate, log in to sshd and run `audit verify`. Then start the signer once with a wrong pin-file.
**Expected:** The keys are generated on the device and custody is recorded truthfully. sshd accepts the certificate and the audit verifies. The wrong PIN gives exit 78 with no restart, and the card keeps at least 2 retries.
**Why human:** CI has only SoftHSM2 and a fake card.

### 2. Homelab signer on the PR #27 build

**Test:** Upgrade the homelab signer to d623927: stop, install the binaries, start. Run `doctor`, issue one certificate, export, and run `audit verify` pinned to C+D and to A+B.
**Expected:** serve starts, doctor shows no FAIL, and both audits print OK.
**Why human:** The new start-up checks in serve and doctor (admins against all logged roots, validity placement) have run only through `audit verify` on an export, never on the real state.

## Gaps Summary

**Closed since the previous verification:**

- **Gap 1 (A-CR-01).** The previous goal-level blocker is fixed. A running signer cannot authorize under a superseded policy: it refuses `trust_changed` both before signing and inside the commit transaction. install-bundle cannot run beside serve, and a live socket is never unlinked. Behavioral tests prove it.
- **Gap 2 (B-CR-01).** No root of any logged bundle can be a policy admin, at every entry point.
- **Gap 4 (D-CR-02).** Imported or duplicable TPM keys are refused, proven on swtpm.
- **Gap 5 (D-CR-01).** The PIV PIN is never tried with fewer than 2 retries left. A refused credential exits 78, and the unit does not restart on it.
- **Re-review blocker G-CR-01.** The forged-prev attack is closed by a mandatory `--prev-sha256` and prev's self-signature.

No code gap remains.

**Remaining:**

1. **SC2/KEY-07: the offline ceremony (owner-accepted open gap, not a defect).**
   - All the tooling exists and is tested end to end.
   - The real offline ceremony has never been run. The homelab rests on TEST roots C and D.
   - The owner decided on 2026-10-09 that KEY-07 stays open until a v3 rotation from C or D (recorded in deferred-items.md).
   - No later roadmap phase owns it, so it cannot be moved to `deferred:`, and no code plan can close it.
   - Closing it takes the ceremony itself, or the owner formally accepts the deferral by override.
2. **SC3 real hardware (behavior-unverified, issue #13).** This needs owner hardware. It is now human verification, not a gap.
3. **Homelab deployment of the PR #27 build (human verification).**

### Override suggestions (not applied; the owner accepts or rejects them)

If the owner accepts the first override, the status becomes **human_needed** (items 2 and 3 above remain), not passed.

```yaml
overrides:
  - must_have: "SC2/KEY-07 (offline-ceremony clause): the admin has run the offline trust-root ceremony (M-of-N root keys, software on offline media or hardware) and the homelab signer is anchored on roots from it"
    reason: "Tooling complete and CI-tested (root sign --prev --prev-sha256, trust verify --prev, audit anchoring; e2e TestRootRotationLiveSigner). The real offline ceremony is owed as a v3 rotation co-signed by TEST root C or D (owner decision 2026-10-09, deferred-items.md); KEY-07 stays Pending in REQUIREMENTS.md until then"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
  - must_have: "At the end of the plan the owner has removed /etc/sudoers.d/90-cloud-init-users on the VM, and sudo -n true fails there over SSH"
    reason: "Owner decision 2026-10-10: the homelab test VM keeps passwordless sudo; it is not reachable from outside. Record the decision in .planning/"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
  - must_have: "SC3: CA keys in a PKCS#11 HSM reached via ssh-agent (SoftHSM2 in CI, YubiHSM 2 on real hardware) or a YubiKey PIV slot"
    reason: "Real-device validation is tracked in issue #13 (needs-hardware) before the Phase 6 external security review; SoftHSM2, swtpm and fake-card coverage prove the code paths"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
  - must_have: "Windows inbox OpenSSH_for_Windows_9.5p2 sshd on Daniel-PC accepts the homelab certificate and rejects an unlisted principal"
    reason: "Ran on a lab Windows Server 2025 with the same inbox OpenSSH_for_Windows_9.5p2 (9.5.5.1); the host is incidental to CA-08"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
```

The third override would only move SC3 out of human verification. It would not change the status, because item 3 above still needs the owner.

---

_Verified: 2026-10-10_
_Verifier: Claude (gsd-verifier)_
