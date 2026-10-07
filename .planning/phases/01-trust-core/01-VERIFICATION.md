---
phase: 01-trust-core
verified: 2026-10-07T12:00:00Z
status: gaps_found
score: 3/5 roadmap success criteria verified (goal-level truth "signing rules cannot be bypassed" FAILED); 119/121 plan must-have truths verified or attested
covered_files:
  - ".github/ISSUE_TEMPLATE/bug_report.yml"
  - ".github/ISSUE_TEMPLATE/config.yml"
  - ".github/ISSUE_TEMPLATE/feature_request.yml"
  - ".github/dependabot.yml"
  - ".github/pull_request_template.md"
  - ".github/rulesets/main-integrity.json"
  - ".github/rulesets/main-review.json"
  - ".github/workflows/ci.yml"
  - ".github/workflows/codeql.yml"
  - ".github/workflows/e2e-pkcs11.yml"
  - ".github/workflows/e2e-tpm.yml"
  - ".github/workflows/e2e.yml"
  - ".github/workflows/piv.yml"
  - ".github/workflows/scorecard.yml"
  - ".github/workflows/systemd.yml"
  - ".github/workflows/workflow-lint.yml"
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
  - "CODE_OF_CONDUCT.md"
  - "CONTRIBUTING.md"
  - "README.md"
  - "SECURITY.md"
  - "cmd/keyroster-signer/backends_linux.go"
  - "cmd/keyroster-signer/backends_piv.go"
  - "cmd/keyroster-signer/cainit.go"
  - "cmd/keyroster-signer/commands.go"
  - "cmd/keyroster-signer/doctor.go"
  - "cmd/keyroster-signer/doctor_test.go"
  - "cmd/keyroster-signer/export.go"
  - "cmd/keyroster-signer/install.go"
  - "cmd/keyroster-signer/main.go"
  - "cmd/keyroster-signer/main_other.go"
  - "cmd/keyroster-signer/serve.go"
  - "cmd/keyroster/audit.go"
  - "cmd/keyroster/ca.go"
  - "cmd/keyroster/ca_test.go"
  - "cmd/keyroster/root.go"
  - "cmd/keyroster/root_test.go"
  - "cmd/keyroster/trust.go"
  - "deploy/systemd/keyroster-signer-agent.service"
  - "deploy/systemd/keyroster-signer.service"
  - "deploy/systemd/keyroster-signer.service.d/tpm.conf"
  - "deploy/sysusers.d/keyroster.conf"
  - "docs/backends/piv.md"
  - "docs/backends/pkcs11.md"
  - "docs/runbooks/ceremony-transcript-template.md"
  - "docs/runbooks/root-ceremony.md"
  - "docs/runbooks/signer-install.md"
  - "docs/security/custody.md"
  - "docs/security/needs-hardware.md"
  - "go.mod"
  - "go.sum"
  - "internal/audit/export.go"
  - "internal/audit/fuzz_test.go"
  - "internal/audit/verify.go"
  - "internal/audit/verify_test.go"
  - "internal/cert/builder.go"
  - "internal/cert/builder_test.go"
  - "internal/cert/keyid.go"
  - "internal/cert/keyid_test.go"
  - "internal/cert/signcert_guard_test.go"
  - "internal/cert/validate.go"
  - "internal/doctor/doctor.go"
  - "internal/doctor/doctor_test.go"
  - "internal/keystore/agent/agent.go"
  - "internal/keystore/agent/agent_test.go"
  - "internal/keystore/keystore.go"
  - "internal/keystore/piv/card.go"
  - "internal/keystore/piv/piv.go"
  - "internal/keystore/piv/piv_test.go"
  - "internal/keystore/piv/yubikey.go"
  - "internal/keystore/registry.go"
  - "internal/keystore/tpm/inspect.go"
  - "internal/keystore/tpm/provision.go"
  - "internal/keystore/tpm/tpm.go"
  - "internal/keystore/tpm/tpm_test.go"
  - "internal/keystore/tpm/transport.go"
  - "internal/keystore/tpm/vendor.go"
  - "internal/keystore/tpm/vendor_test.go"
  - "internal/rootceremony/imports_test.go"
  - "internal/rootceremony/keygen.go"
  - "internal/rootceremony/keygen_test.go"
  - "internal/rootceremony/passphrase.go"
  - "internal/rootceremony/readfd_other.go"
  - "internal/rootceremony/readfd_unix.go"
  - "internal/rootceremony/readfd_windows.go"
  - "internal/rootceremony/sign.go"
  - "internal/rootceremony/sign_test.go"
  - "internal/rootceremony/summary.go"
  - "internal/serial/serial.go"
  - "internal/serial/serial_test.go"
  - "internal/signer/evidence.go"
  - "internal/signer/evidence_test.go"
  - "internal/signer/fixture_test.go"
  - "internal/signer/issue.go"
  - "internal/signer/log_test.go"
  - "internal/signer/logstate.go"
  - "internal/signer/peercred_linux.go"
  - "internal/signer/peercred_other.go"
  - "internal/signer/profiles.go"
  - "internal/signer/refusal.go"
  - "internal/signer/refusal_test.go"
  - "internal/signer/server.go"
  - "internal/signer/signer.go"
  - "internal/signer/signer_test.go"
  - "internal/signer/trust.go"
  - "internal/signer/trust_test.go"
  - "internal/signerclient/client.go"
  - "internal/signerdb/db.go"
  - "internal/signerdb/db_test.go"
  - "internal/signerdb/issuance.go"
  - "internal/signerdb/log.go"
  - "internal/signerdb/migrate.go"
  - "internal/signerdb/migrations/0001_issuance.sql"
  - "internal/signerdb/migrations/0002_log.sql"
  - "internal/signerdb/migrations/0003_trust.sql"
  - "internal/signerdb/trust.go"
  - "internal/sshsig/fuzz_test.go"
  - "internal/sshsig/helpers_test.go"
  - "internal/sshsig/oracle_test.go"
  - "internal/sshsig/sshsig.go"
  - "internal/sshsig/sshsig_test.go"
  - "internal/tlog/checkpoint.go"
  - "internal/tlog/fuzz_test.go"
  - "internal/tlog/leaf.go"
  - "internal/tlog/leaf_test.go"
  - "internal/tlog/log.go"
  - "internal/tlog/log_test.go"
  - "internal/tlog/notesig.go"
  - "internal/tlog/notesig_test.go"
  - "internal/trust/bundle.go"
  - "internal/trust/bundle_test.go"
  - "internal/trust/canonical.go"
  - "internal/trust/capubkeys.go"
  - "internal/trust/fuzz_test.go"
  - "internal/trust/helpers_test.go"
  - "internal/trust/policy.go"
  - "internal/trust/roots.go"
  - "internal/trust/vectors_test.go"
  - "internal/trust/verify.go"
  - "internal/trust/verify_test.go"
  - "internal/wire/frame.go"
  - "internal/wire/fuzz_test.go"
  - "internal/wire/issue.go"
  - "internal/wire/wire_test.go"
  - "scripts/apply-rulesets.sh"
  - "scripts/apply-security-settings.sh"
  - "scripts/build-openssh.sh"
  - "scripts/capslock-check.sh"
  - "scripts/check-pinned-actions.sh"
  - "scripts/dep-firewall.sh"
  - "scripts/fuzz.sh"
  - "scripts/gh-as-bot.sh"
  - "scripts/merge-gate.sh"
  - "scripts/softhsm-setup.sh"
  - "scripts/swtpm-setup.sh"
  - "test/capslock/keyroster-signer.json"
  - "test/e2e/audit_test.go"
  - "test/e2e/bootstrap_test.go"
  - "test/e2e/ca_roles_test.go"
  - "test/e2e/doctor_test.go"
  - "test/e2e/doctor_tpm_test.go"
  - "test/e2e/fingerprint_test.go"
  - "test/e2e/harness_test.go"
  - "test/e2e/issue_test.go"
  - "test/e2e/negative_test.go"
  - "test/e2e/pkcs11_test.go"
  - "test/e2e/root_sk_test.go"
  - "test/e2e/tpm_test.go"
  - "test/e2e/trust_flow_test.go"
  - "test/manual/README.md"
  - "test/manual/windows-openssh-9.5p2.ps1"
  - "test/systemd/smoke.sh"
  - "test/vectors/bundle_genesis_v1.json"
  - "test/vectors/checkpoint_ecdsa_p256.golden"
  - "test/vectors/checkpoint_ed25519.golden"
  - "test/vectors/leaf_issue_v1.hex"
  - "test/vectors/policy_genesis_v1.json"
  - "tools/go.mod"
  - "tools/go.sum"
covered_digest: "v2:sha256:ff11d9614c394a811b61e20d4bbca30b7269a5aa19463a5108b896f037eb9581"
behavior_unverified: 1
overrides_applied: 0
gaps:
  - truth: "Goal clause: the CA's signing rules cannot be bypassed — a policy change installed on the signer takes effect for the next request"
    status: failed
    reason: "A-CR-01/C-CR-01 confirmed in code. The trust state (policy, admins, profiles, CA keys) is loaded once in signer.New (internal/signer/signer.go:104, loadTrust) and never re-checked. serve, ca-init and install-bundle take no state-dir lock, and Listen (internal/signer/server.go:34-44) unlinks any existing socket. A successor bundle installed while serve runs leaves the running signer authorizing with the superseded admin set and quorum (an admin the new policy removed can still authorize issuance). Every certificate issued after that carries the old pol= and is logged after the new bundle_install leaf, so audit.Verify (internal/audit/verify.go:140-145) rejects the whole export from then on. Reachability today: no shipped command builds a successor bundle (root sign is genesis-only), so it needs a hand-built root-signed successor. Closing KEY-07 by rotation (or Phase 3 KEY-08) makes it routine. No test installs a successor against a live signer."
    artifacts:
      - path: "internal/signer/signer.go"
        issue: "loadTrust only at start-up (line 104); no bundle-version recheck"
      - path: "internal/signer/issue.go"
        issue: "authorizes against s.policy (line 60) and stamps s.policy.Version (line 99) without checking the installed bundle version inside logTx"
      - path: "internal/signer/server.go"
        issue: "Listen removes a live socket (lines 35-41); no 'already running' check"
      - path: "cmd/keyroster-signer/install.go"
        issue: "install-bundle takes no lock and does not detect a running signer"
    missing:
      - "signerdb.LatestBundleVersion(tx) plus a check inside the Issue logTx closure that refuses (trust_changed, CodeUnavailable) when the installed version differs from the version loaded at start"
      - "An exclusive flock on a lock file in the state dir, taken by serve, ca-init and install-bundle (install-bundle refuses while serve runs)"
      - "Listen: dial the existing socket first and refuse to unlink it if it accepts connections"
      - "A test that installs a v2 successor while a Signer is live and asserts the next request is refused and the exported log still verifies"
      - "docs/runbooks/signer-install.md: stop, install-bundle, start for successors"
  - truth: "SC2/KEY-07: the trust root signs only trust bundles, KRL authority and policy, and is never an issuance authorizer"
    status: failed
    reason: "B-CR-01 confirmed in code. Policy.Validate (internal/trust/policy.go:68-102) checks admin keys only against each other. VerifyGenesisBundle (internal/trust/verify.go:66-113) and VerifySuccessor never compare p.Admins with b.Root.Keys, and checkPolicyAdmins (internal/signer/trust.go:325-338) compares admins only with the CA, ops and log keys. A root-signed policy can therefore list a root key as an admin. A FIDO, PIV or PKCS#11 root reached through ssh-agent can then sign admin-sshsig evidence with `keyroster ca issue --admin-key`, which turns the offline root into an online issuance authorizer. The root never signs a certificate directly: Bundle.Validate refuses CA/ops/log == root (bundle.go:157-168), and the rootceremony API exposes only SignBundle and SignPolicy. So the SC2 clause 'refuses to use for signing certificates' holds literally, but KEY-07's 'signs only' does not."
    artifacts:
      - path: "internal/trust/verify.go"
        issue: "no admin-vs-root cross-check in VerifyGenesisBundle / VerifySuccessor"
      - path: "internal/signer/trust.go"
        issue: "checkPolicyAdmins ignores root keys"
      - path: "cmd/keyroster/root.go"
        issue: "root sign signs a policy whose admins include a root"
    missing:
      - "checkAdminsNotRoots(p, roots) in both verify paths (new roots and, for successors, the previous roots), returning ErrKeyIsRoot"
      - "The same check in runRootSign before signing and in the signer's install path"
      - "A refusal test for each entry point (trust verify, root sign, install-bundle, audit verify)"
  - truth: "SC2/KEY-07: the admin has run the offline trust-root ceremony (M-of-N, 1-of-2 in the homelab) and the homelab signer is anchored on its roots"
    status: failed
    reason: "The homelab roots are TEST roots. Owner decision 'Testceremoni nu, riktig sen' (01-14-SUMMARY key-decisions; deferred-items.md 01-14 entry): Claude generated two age software roots in WSL on the networked workstation, with each command under unshare -r -n, and the passphrase files sit on the same disk. 01-14 must-have truth 2 (offline USB ceremony against paper fingerprints) is FAILED by its own SUMMARY (coverage status: fail). KEY-07 is correctly left Pending in REQUIREMENTS.md, yet 01-06, 01-07 and 01-09 SUMMARY frontmatter still list KEY-07 under requirements-completed, which overclaims. No later phase claims the ceremony (Phase 3 KEY-08 is CA-key rotation, not root rotation), so this cannot be deferred. Software roots for the homelab are an accepted deviation (CONTEXT D-10). The performed ceremony was not offline."
    artifacts:
      - path: "cmd/keyroster/root.go"
        issue: "root sign builds genesis bundles only (version 1, zero prev); no successor builder, so moving to real roots means reinstalling the homelab signer"
    missing:
      - "Either a successor-bundle builder (`keyroster root sign --successor --prev bundle.json` plus tests, signed by a threshold of the current roots) or a documented decision to rebuild the homelab signer from genesis"
      - "The owner runs docs/runbooks/root-ceremony.md offline (live USB, two new roots on separate media, fingerprints on paper), then rotates or reinstalls the homelab signer onto those roots and destroys the test roots"
      - "Correct the requirements-completed lists in 01-06/01-07/01-09 SUMMARY (KEY-07 is not complete)"
  - truth: "SC3/KEY-04: CA keys recorded as TPM custody were generated inside the TPM (hardware-backed custody claim is enforced)"
    status: failed
    reason: "D-CR-02 confirmed in code. tpm.Key() (internal/keystore/tpm/tpm.go:140-165) checks only the TSS2 key type, ECC and P-256. It never checks the public-area attributes FixedTPM, FixedParent and SensitiveDataOrigin. A software key wrapped with TPM2_Import loads, and is recorded as custody tpm or vtpm in ca-pubkeys.json, in the root-signed bundle and in the ca_init leaf. A malicious admin, who is in the threat model, can therefore keep an exportable copy of a CA key while the audit trail claims non-exportable TPM custody. The PIV backend refuses the equivalent case (origin != generated)."
    artifacts:
      - path: "internal/keystore/tpm/tpm.go"
        issue: "Key() accepts imported (duplicable) objects"
    missing:
      - "Refuse keys whose ObjectAttributes lack FixedTPM, FixedParent or SensitiveDataOrigin"
      - "swtpm test: build an importable key, import it, assert Key() refuses it"
  - truth: "SC3/KEY-05: a CA key in a YubiKey PIV slot survives a misconfigured PIN under the shipped deployment"
    status: failed
    reason: "D-CR-01 confirmed. newBackend calls VerifyPIN on every start without first reading the retry counter (no Retries() on the card interface). deploy/systemd/keyroster-signer.service:23 sets Restart=on-failure with no RestartSec, StartLimit* or RestartPreventExitStatus, and the tpm.conf drop-in adds none. With a wrong pin-file, the PIV PIN blocks within about 3 restarts; PUK loss then forces a PIV reset that destroys the CA keys in slots 0x82-0x86. This is not a signing bypass, but it is a key-destroying failure in shipped artifacts for the hardware-backed custody this phase claims. The fake card in piv_test.go has no retry counter, so tests cannot see it."
    artifacts:
      - path: "internal/keystore/piv/piv.go"
        issue: "VerifyPIN without a retry-count guard"
      - path: "deploy/systemd/keyroster-signer.service"
        issue: "Restart=on-failure without RestartSec / RestartPreventExitStatus / StartLimitBurst"
    missing:
      - "card.PINRetries(); refuse automatic VerifyPIN when fewer than 2 retries remain"
      - "A dedicated exit code for PIN refusal, plus RestartPreventExitStatus=<code>, RestartSec=5s and StartLimitBurst in the unit"
      - "fakeCard retry counter and a repeated-wrong-PIN test asserting the counter never reaches 0"
  - truth: "SC3: CA keys in a PKCS#11 HSM via ssh-agent — YubiHSM 2 on real hardware; YubiKey PIV on a real card"
    status: partial
    reason: "SoftHSM2 through ssh-agent passes on main (e2e-pkcs11 distro-p256 job 112610097155 and 10.5p1-ed25519 job 112610097463: TestPKCS11FullFlow, Ed25519, RootSignsBundle, CAInitTwiceRefused, ConcurrentIssue). No YubiHSM 2 or real YubiKey run exists. PIV was exercised only with a fake card (build-piv job 112610096968). Tracked in issue #13 (needs-hardware, OPEN). Phase 6 SC5 ('external security review') is too vague to count as a deferral. Closing this needs owner hardware, not code."
    artifacts:
      - path: "docs/security/needs-hardware.md"
        issue: "real-device validation outstanding"
    missing:
      - "Run the PKCS#11 flow against a YubiHSM 2 and the PIV flow against a real YubiKey (5.7+ Ed25519 and pre-5.7 P-256), and record results in issue #13 — or accept the SC3 hardware clause by override"
deferred:
  - truth: "SC5: a log rolled back or truncated to an earlier signed prefix is detected without an operator-supplied --previous checkpoint (C-WR-01)"
    addressed_in: "Phase 4"
    evidence: "Phase 4 SC4: 'Agents and the CLI verify signed checkpoints with consistency proofs and raise an alert if the log ever shrinks or forks (e.g. a DB admin rewriting history)'; VIS-02 is mapped to Phase 4"
  - truth: "SC4: serial non-reuse after restore when the wall clock is restored with the snapshot (A-IN-04)"
    addressed_in: "Phase 6"
    evidence: "Phase 6 SC3: 'Admin can back up and restore server state (encrypted); after a restore no serial is reissued and the audit log is intact and still verifies' (OPS-01)"
behavior_unverified_items:
  - truth: "KEY-05: YubiKey PIV backend provisions and signs on a real card (Ed25519 on firmware >= 5.7, P-256 below) with touch/PIN policy"
    test: "Build keyroster-signer with -tags piv, run ca-init --backend piv against a real YubiKey, install a bundle, issue, log in to sshd, run audit verify"
    expected: "Keys are generated on-card (origin generated), algorithm matches firmware, certificate accepted, custody piv recorded"
    why_human: "CI uses a fake card; no physical device in CI (issue #13)"
coincidental_reliance_items:
  - truth: "SC4: a serial is never reissued after the signer's state is restored from an older copy"
    reason: undeclared-precondition
    harden: "Holds only while the wall clock after restore is ahead of every pre-restore serial (internal/serial/serial.go:1-5; TestSignerRestore uses a forward clock). Persist a high-water mark or checkpoint size outside signer.db, or witness it, and qualify the package comment. Phase 6 SC3 owns this."
---

# Phase 1: Trust Core Verification Report

**Phase goal:** An admin can stand up a hardware-backed, auditable CA whose certificates stock OpenSSH accepts and whose signing rules cannot be bypassed, before any user or host exists.
**Verified:** 2026-10-07
**Status:** gaps_found
**Re-verification:** No. This is the initial verification.
**Code under test:** `p01/close` at ded5203 (origin/main 0885482 plus the review commit). The review commit touches only `.planning/`.
**Mode:** mvp (the roadmap goal is not phrased as a user story; the success-criteria contract is verified directly).

## Method and evidence base

- **CI on main.** Live check-runs on 0885482: all 17 required contexts succeeded (pr-title is skipped on push by design). Runs: ci 37564848288, e2e 37564848377, e2e-pkcs11 37564848285, e2e-tpm 37564848383, piv 37564848247, systemd 37564848328, codeql 37564848219, scorecard 37564848459.
- **CI job logs.** Read for test names: e2e (9.5p1) 112610097638 and e2e (10.5p1) 112610097720 each have 14 named e2e tests at PASS, none skipped. e2e-tpm 112610097339 has 12 at PASS, the e2e-pkcs11 lanes have 5 each at PASS, and build-piv has the PIV tables at PASS.
- **Local run.** WSL, Go 1.27.1, clean clone at ded5203: `go test -count=1 ./internal/{cert,serial,audit,trust,signer,tlog}/` all ok.
- **Live GitHub state** (`gh api`): rulesets, `rules/branches/main`, security_and_analysis, private vulnerability reporting, Actions workflow permissions, code-scanning analyses, merged PRs, and commit verification.
- **Code reading.** I checked the four critical review findings against the source. All four are present at ded5203.
- **Owner-run evidence** that cannot be re-run from here: the Windows 9.5p2 result (01-15) and the homelab doctor and audit runs (01-14, 01-15). These are attested in SUMMARY and `test/manual/README.md`.

## Goal Achievement: Roadmap Success Criteria (contract)

| # | Success criterion | Status | Evidence |
|---|---|---|---|
| 1 | PR-only main with signed commits, review, green CI (build, test, lint, govulncheck, fuzzing, e2e real sshd), SHA-pinned least-privilege actions; CodeQL, Dependabot, secret scanning + push protection, Scorecard; community files | VERIFIED | See "SC1 detail" below. |
| 2 | Offline trust-root ceremony with M-of-N hardware keys (1-of-2 homelab); root signs bundles, KRL authority, policy (genesis); tooling refuses to use it for signing certificates | **FAILED** | See "SC2 detail" below. |
| 3 | Separate user/host/machine CAs with keys in PKCS#11-via-agent (SoftHSM2 CI, YubiHSM 2 real), TPM 2.0 or YubiKey PIV; only used by the network-less signer | **FAILED (partial)** | See "SC3 detail" below. |
| 4 | Cert accepted by sshd 9.5p2 and latest in CI; unique non-zero never-reissued serial (also after restore); structured key ID; permit-pty only; refuses empty/wildcard/malformed principals, cert-type CA keys, non-client keys | VERIFIED (one coincidental-reliance advisory) | See "SC4 detail" below. |
| 5 | Every issuance in the Merkle log before release; `audit verify` end to end, fails on tampered/removed entries, exports | VERIFIED (with an A-CR-01 caveat) | See "SC5 detail" below. |
| G | Goal clause "whose signing rules cannot be bypassed" | **FAILED** | A-CR-01: a policy change does not reach a running signer. B-CR-01: a root can be an issuance authorizer. Both confirmed in code; see gaps 1 and 2. |

**Score:** 3/5 success criteria verified. The goal-level truth is FAILED. 1 truth is present but behavior-unverified (KEY-05 on a real card).

### SC1 detail (VERIFIED)

**Branch rules on main**
- Live rules on `main` list exactly the 17 contexts, with `strict_required_status_checks_policy: true`.
- `main-integrity`:
  - has no bypass actors;
  - enforces `deletion`, `non_fast_forward`, `required_linear_history`, `required_signatures` and `required_status_checks`.
- `main-review`:
  - requires 1 code-owner approval, with stale-review dismissal, last-push approval and thread resolution;
  - allows squash merges only;
  - has one bypass actor: RepositoryRole 5 in `pull_request` mode.
- REPO-01 is therefore met live. `REQUIREMENTS.md` still shows it as Pending and needs updating.

**PRs and commits**
- 17 PRs were merged: #1-#12 and #14-#18. #13 is the needs-hardware issue, so the "18 PRs" figure in the brief is off by one.
- All 17 were authored by keyroster-bot with reviewDecision APPROVED.
- Every commit on main reports `verification.verified=true`.

**Security settings**
- secret_scanning and push_protection are enabled.
- Dependabot security updates are enabled, and vulnerability alerts return 204.
- Private vulnerability reporting is enabled.
- The default workflow token is `read`, and `can_approve_pull_request_reviews` is false.

**Workflows**
- All 9 workflows declare top-level `permissions: {}`.
- A grep for `uses:` without a 40-hex SHA finds nothing.
- `pinned-actions` passed on main.
- Dependabot covers gomod `/`, gomod `/tools` and github-actions.
- CodeQL `Analyze (go)` and `Analyze (actions)` succeeded on main.

**Scorecard**
- Analyses 1905579987, 1905579931 and 1905579873 ran on `refs/heads/main` (2026-10-07). The score is 8 per 01-15.

**Community files**
- SECURITY.md links to `/security/advisories/new` (line 21).
- LICENSE is Apache-2.0.
- README carries the pre-alpha warning (line 9).
- CONTRIBUTING.md, CODE_OF_CONDUCT.md and CODEOWNERS (`* @Labontese`) are present.
- Issue forms exist (bug, feature, config), along with a PR template.

### SC2 detail (FAILED)

**What exists and works**
- `root init`, `root sign` and `trust verify`.
- Age-encrypted software roots (01-09).
- An sk-dummy FIDO root through ssh-agent, including a 2-of-2 mixed case (e2e TestRootSK PASS on both sshd lanes).
- A PKCS#11-held root (TestPKCS11RootSignsBundle PASS).
- The rootceremony API exports only SignBundle and SignPolicy.
- Bundle.Validate refuses a CA, ops or log key that equals a root key (internal/trust/bundle.go:157-168).
- The genesis policy is root-signed and enforced by the signer (TestEvidence and TestInstallBundleRefusals PASS).

**What fails**
- **The ceremony was not performed offline.** The owner chose a TEST ceremony: software roots generated by Claude on a networked host.
- **Root keys can become policy admins (B-CR-01).** This violates KEY-07's "signs only".
- **No successor-bundle builder exists**, so moving the homelab onto real roots requires a reinstall.
- **The hardware-key wording.** The deviation for the homelab is accepted by D-10 (CONTEXT.md:32). It applies to the homelab only and does not cover the product path, which is CI-only via sk-dummy.

### SC3 detail (FAILED, partial)

**What exists and works**
- **Five distinct role keys.** CA-01 has separate user, host and machine CAs. TestMachineCAIsSeparate, TestHostCAIsNotUserCA and TestHostCertificateNoTOFU PASS on 9.5p1 and 10.5p1.
- **Backends:**
  - PKCS#11 via ssh-agent: SoftHSM2 PASS on both lanes.
  - TPM: swtpm, e2e-tpm PASS. The homelab vTPM is attested in 01-14.
  - PIV: fake card only (build-piv PASS).
- **Network-less signer:**
  - systemd-sandbox CI job PASS.
  - dependency-firewall PASS, with and without `-tags piv`.
  - capslock PASS. Its PIV baseline is still deferred.

**What fails**
- **D-CR-02:** a TPM custody claim can be false.
- **D-CR-01:** the PIV PIN lockout destroys the CA keys under the shipped unit.
- **No real hardware has been tested:** neither a YubiHSM 2 nor a real YubiKey PIV (issue #13 OPEN).

### SC4 detail (VERIFIED, one coincidental-reliance advisory)

**sshd acceptance**
- CI: `TestIssueAcceptedBySSHD` and `TestSSHDRejects` PASS on sshd 9.5p1 and 10.5p1 (jobs 112610097638 and 112610097720). 10.5p1 is the latest release.
- 9.5p2: OpenSSH_for_Windows_9.5p2 (inbox, file version 9.5.5.1) on a lab Windows Server 2025 gave accept PASS and reject PASS. Sources: `test/manual/README.md:81-87` and the 01-15 SUMMARY D1. This was an owner-run check and is not in CI, because upstream has no portable 9.5p2.

**Serials**
- Allocation is clock-floored and strictly increasing (internal/serial/serial.go:37-66). Uniqueness is enforced by the `issuance.serial` PRIMARY KEY.
- Tests PASS locally: TestNext, TestNextAdjacentSerials, TestSignerRestore and TestSignerClockBehindHighWaterMark.

**Key ID**
- Fixed order `kr1/ca=/sub=/req=/pol=/ser=` (internal/cert/keyid.go). TestBuildKeyID, TestParseKeyIDRefusals and FuzzParseKeyID PASS.

**Extensions**
- Default extensions are exactly `permit-pty`. Others are allowed only by profile, and host certificates get none. TestBuildExtensions and TestProfiles PASS. The real-sshd forwarding refusal is covered by TestSSHDRejects.

**Refusals**
- Principals use the allowlist `^[a-z0-9][a-z0-9._@:+-]{0,127}$`, non-empty, at most 32, with no duplicates (internal/cert/validate.go:37,99-117). TestValidatePrincipals and FuzzValidatePrincipals PASS.
- Certificate-type CA keys: CheckCAKey (validate.go:50-63), TestBuildCAKeys.
- Certificate, DSA, short-RSA and subject-equals-CA keys: CheckSubjectKey (validate.go:68-95).
- The signer never generates keys: the SignCert and GenerateKey guards PASS (TestSignCertOnlyInBuild, TestNoGenerateKeyOnSigningPath), and the CLI refuses a private key as `--pubkey` before dialing.
- e2e TestSignerRefuses PASS on both sshd versions.

**Advisory**
- Restore safety depends on the wall clock; see `coincidental_reliance_items`. The deferral to Phase 6 SC3 is noted.

### SC5 detail (VERIFIED, with an A-CR-01 caveat)

**Log before release**
- `Issue` returns the certificate only after `logTx` commits the issuance row, the serial high-water mark, the leaf and the checkpoint in one transaction (internal/signer/issue.go:115-172).
- TestCheckpointFailureReleasesNoCertificate and TestIssueResponseCarriesCommittedLeaf PASS.

**`audit verify`**
- `audit verify` recomputes the root and checks the checkpoint signature, the certificate CA signatures, the serials and the key IDs.
- It detects modified, removed, reordered, duplicated and truncated entries. These tests PASS: TestVerifyDetectsTampering, TestVerifyEmpty, TestVerifyChecksCertificates and TestVerifyPrevious locally, and TestAuditDetectsTampering in e2e on both lanes.

**Export**
- `export-log` exists (cmd/keyroster-signer/export.go), and the e2e TestAuditVerifiesIssuance test PASS.
- Root anchoring: TestVerifyAnchoring PASS.

**Caveat (A-CR-01)**
- The routine-looking action of installing a successor bundle against a live signer makes an honest log fail `audit verify` from that point on. That is listed under gap 1.

## Supporting: plan must-have truths (121)

| Plan | Truths | Result | Notes |
|---|---|---|---|
| 01-01 repo + rulesets | 12 | 12 VERIFIED | Live rulesets, signed commits, pinned actions, merge-gate.sh present. The no-CGNAT/homelab-prefix scrub was not re-scanned here; it rests on the 01-01 SUMMARY plus push protection. |
| 01-02 walking skeleton | 6 | 6 VERIFIED | TestIssueAcceptedBySSHD, peer allowlist (TestSignerPeerAllowlist), SignCert guard, depguard (lint PASS). |
| 01-03 security settings | 7 | 7 VERIFIED | Live API (see SC1). |
| 01-04 e2e matrix + fuzz | 6 | 6 VERIFIED | e2e 9.5p1/10.5p1 and fuzz are required and green on main. |
| 01-05 Merkle log | 11 | 11 VERIFIED | Local and e2e tests above, TestRefusalFloodIsSummarized, TestRefusalClockRegressionEpisodes, TestStartRefusedOnLogMismatch. |
| 01-06 trust anchor | 9 | 9 VERIFIED | TestVerifyGenesisBundle, TestVerifySuccessor, TestCanonicalStrictness, TestRootSK. B-CR-01 is outside these truths' literal wording but contradicts KEY-07 (gap 2). |
| 01-07 signer under bundle | 9 | 9 VERIFIED | TestInitCARefusals, TestInitCAOrdering, TestInstallBundleRefusals, TestEvidence, TestSignerIssuesEveryRole. The live-signer successor case is untested (gap 1). |
| 01-08 separate CAs + pinned audit | 5 | 5 VERIFIED | e2e TestHostCertificateNoTOFU, TestMachineCAIsSeparate, TestHostCAIsNotUserCA, TestAuditVerifiesIssuance. |
| 01-09 software roots + runbook | 5 | 5 VERIFIED | root tests PASS in build-test. The runbook exists (docs/runbooks/root-ceremony.md). |
| 01-10 PKCS#11/SoftHSM2 | 6 | 6 VERIFIED | Both e2e-pkcs11 lanes PASS. The pkcs11-agent custody label is operator-asserted (D-WR-03, warning). |
| 01-11 TPM | 7 | 7 VERIFIED | e2e-tpm PASS. D-CR-02 is outside the literal truths but voids the custody claim (gap 4). |
| 01-12 PIV | 7 | 6 VERIFIED, 1 PRESENT_BEHAVIOR_UNVERIFIED | Fake card only. Real-card behavior is unverified, and the needs-hardware issue #13 is open. |
| 01-13 sandbox, doctor, firewall | 6 | 6 VERIFIED | systemd-sandbox, dependency-firewall and capslock PASS. Doctor tests PASS in e2e. |
| 01-14 homelab vTPM + ceremony | 5 | 3 attested, 1 FAILED, 1 attested | Truth 2 (offline USB ceremony against paper fingerprints) FAILED by the SUMMARY's own coverage (gap 3). The vTPM signer, doctor (no FAIL; WARN software_root and vtpm_custody) and audit verify are owner-attested in the 01-14 and 01-15 SUMMARYs; they cannot be re-run from here. |
| 01-15 acceptance | 4 | 4 VERIFIED | The live ruleset now equals the 17 checks (pending at SUMMARY time, applied since). Scorecard is on main. The 9.5p2 check ran on a lab Windows Server 2025, not Daniel-PC: same inbox binary, so the intent is met. An override is suggested below. |
| 01-16 refusal suite | 16 | 16 VERIFIED | TestRefusalEndToEnd, TestSignerConcurrency, TestBuild* tables, four fuzz targets (FuzzParseIssueRequest, FuzzReadFrame, FuzzParseKeyID, FuzzValidatePrincipals). |

Totals: 119 VERIFIED or attested, 1 FAILED, 1 PRESENT_BEHAVIOR_UNVERIFIED. The failures that matter most come from the review findings, which sit outside the literal plan truths. They are carried as gaps against the roadmap SCs and the goal.

## Requirements Coverage

All 19 phase IDs appear in at least one PLAN's `requirements:` field. No ID mapped to Phase 1 in REQUIREMENTS.md is missing from the plans, so nothing is orphaned.

| Requirement | Plans | Status | Evidence |
|---|---|---|---|
| REPO-01 | 01-01, 01-04, 01-15 | SATISFIED | Live rulesets (SC1). **REQUIREMENTS.md still says Pending; update it.** Info: main-review allows admin bypass in pull_request mode (D-05, unused). E-WR-01: pr-title is not re-run on a title edit. |
| REPO-02 | 01-01..04, 01-13, 01-16 | SATISFIED | build-test, lint, govulncheck, fuzz, e2e and pinned-actions are green on main. E-WR-04: govulncheck and CodeQL do not analyse the `-tags piv` build (warning). |
| REPO-03 | 01-03, 01-15 | SATISFIED | Live API (SC1). |
| REPO-04 | 01-01, 01-03 | SATISFIED | Files present (SC1). |
| CA-01 | 01-07, 01-08 | SATISFIED | Five distinct keys; separation proven against sshd. |
| CA-02 | 01-02, 01-04, 01-16 | SATISFIED | validate.go:37,99-117; tests and fuzz. |
| CA-03 | 01-02, 01-05, 01-16 | SATISFIED | serial.go, PRIMARY KEY, TestSignerRestore. Wall-clock reliance is an advisory, deferred to Phase 6. |
| CA-04 | 01-02, 01-07, 01-08, 01-16 | SATISFIED | keyid.go and tests. A-WR-02: `pol=N` can name two different policies when a successor does not chain (warning). |
| CA-05 | 01-02, 01-04, 01-07, 01-08, 01-16 | SATISFIED | permit-pty default; sshd refuses forwarding. |
| CA-06 | 01-02, 01-04, 01-16 | SATISFIED | No GenerateKey on the signing path (guard test); the CLI refuses private keys. |
| CA-07 | 01-02, 01-04, 01-07, 01-16 | SATISFIED | CheckCAKey; serve refuses a certificate pinned as the CA. |
| CA-08 | 01-02, 01-04, 01-15 | SATISFIED | CI 9.5p1/10.5p1 plus the owner-run Windows 9.5p2 check. The 9.5p2 leg is manual, not automated (accepted plan correction). |
| KEY-01 | 01-02, 01-07, 01-13, 01-16 | SATISFIED | Network-less, sandboxed signer behind the keystore.Backend interface. Gap 1 concerns trust reload, not isolation. |
| KEY-03 | 01-02, 01-10 | SATISFIED (SoftHSM2) / real YubiHSM 2 outstanding | Gap 6 (partial). D-WR-03: custody is operator-asserted. |
| KEY-04 | 01-11, 01-14 | **PARTIAL (BLOCKED by D-CR-02)** | Works on swtpm and the homelab vTPM, but the hardware custody claim is not enforced (gap 4). REQUIREMENTS.md marks it Complete, which overstates it. |
| KEY-05 | 01-12 | **PARTIAL (BLOCKED by D-CR-01)** | Fake card only, and the shipped unit can destroy the keys (gap 5). REQUIREMENTS.md marks it Complete, which overstates it. |
| KEY-07 | 01-06, 01-07, 01-09, 01-10, 01-14 | **BLOCKED** | Gaps 2 and 3. Correctly Pending in REQUIREMENTS.md; the 01-06/07/09 SUMMARYs overclaim it. |
| VIS-01 | 01-05, 01-07 | SATISFIED (issuance, refusals, ca_init, bundle_install; revocation and approval come in later phases) | issue.go:115-172. Gap 1 can make later entries unverifiable. |
| VIS-03 | 01-05, 01-08, 01-14, 01-15 | SATISFIED | audit verify plus export; the homelab log verified (owner-attested). The rollback-without-`--previous` case is deferred to Phase 4. |

## Anti-Patterns and Review Findings

- **Debt markers.** A scan for TBD, FIXME and XXX over cmd, internal, scripts, deploy, .github, test, docs and the top-level docs found none. There is no TODO or HACK in the Go sources.

| Finding | File | Severity | Impact |
|---|---|---|---|
| A-CR-01/C-CR-01 | internal/signer/signer.go:104, server.go:34-44, install.go | BLOCKER | Policy bypass after a live successor install; the audit log breaks (gap 1). |
| B-CR-01 | internal/trust/verify.go:66-113, signer/trust.go:325-338 | BLOCKER | A root becomes an issuance authorizer (gap 2). |
| D-CR-01 | internal/keystore/piv/piv.go:119-138, deploy/systemd/keyroster-signer.service:23 | BLOCKER | PIV PIN lockout destroys the CA keys (gap 5). |
| D-CR-02 | internal/keystore/tpm/tpm.go:140-165 | BLOCKER | A false TPM custody claim (gap 4). |
| A-WR-02 / B-WR-01 / C-WR-05 | trust, signer, audit | Warning | The policy version/prev chain is not enforced. Relevant to Phase 4 SC1. |
| A-WR-04 | internal/signer/issue.go:81-113 | Warning | A replayed request costs a CA signature (or a PIV touch) before the UNIQUE refusal. |
| D-WR-01 | internal/keystore/tpm | Warning | TPM keys are not noDA, so a bad auth can drive the TPM into dictionary-attack lockout. |
| D-WR-02 / D-WR-03 / C-WR-03 / C-WR-04 | keystore, doctor | Warning | Custody is self-reported or operator-asserted, and doctor reports it as hardware. |
| C-WR-01 | signer, doctor | Warning (deferred to Phase 4) | A rolled-back log is accepted at start. |
| E-WR-01..05 | CI and scripts | Warning | pr-title is not re-run on edit; merge-gate runs a working-tree wrapper; the piv build is not scanned; the agent unit is unsandboxed. |
| 30 Info items | various | Info | See 01-REVIEW.md. |

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Core packages pass at ded5203 | `go test -count=1 ./internal/{cert,serial,audit,trust,signer,tlog}/` (WSL, Go 1.27.1, clean clone) | all `ok` (signer 4.3 s) | PASS |
| e2e suite actually ran on both sshd versions (not skipped) | job logs 112610097638 and 112610097720 | 14 named tests PASS each, 0 SKIP | PASS |
| PKCS#11 and TPM lanes ran | job logs 112610097155, 112610097463 and 112610097339 | 5, 5 and 12 tests PASS | PASS |
| Required checks enforced on main | `gh api repos/Labontese/keyroster/rules/branches/main` | 17 contexts, strict | PASS |

## Probe Execution

No `scripts/*/tests/probe-*.sh` exists, and no PLAN declares one. Skipped.

## Override suggestions (not applied; for the owner to accept or reject)

Accepting these would not change the status, because gaps 1, 2, 4 and 5 are code defects.

```yaml
overrides:
  - must_have: "Windows inbox OpenSSH_for_Windows_9.5p2 sshd on Daniel-PC accepts the homelab certificate and rejects an unlisted principal"
    reason: "Ran on a lab Windows Server 2025 with the same inbox OpenSSH_for_Windows_9.5p2 (9.5.5.1); the host is incidental to CA-08"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
  - must_have: "SC3: CA keys in a PKCS#11 HSM reached via ssh-agent (SoftHSM2 in CI, YubiHSM 2 on real hardware) or a YubiKey PIV slot"
    reason: "Real-device validation is tracked in issue #13 (needs-hardware) for the pre-release security review; SoftHSM2 and fake-card coverage prove the code path"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
```

The homelab's software roots (as opposed to hardware keys) are already an owner decision (CONTEXT D-10) and need no override. The non-offline TEST ceremony is not covered by D-10 and stays a gap.

## Gaps Summary

The phase delivered a large, well-tested trust core:
- CI, rulesets and supply-chain controls are fully in force.
- Certificates are accepted by real sshd 9.5p1, 10.5p1 and Windows 9.5p2.
- The refusal rules hold under tables and fuzzing.
- The Merkle log commits before release and `audit verify` catches tampering.
- PKCS#11, TPM and PIV backends exist and pass in CI.

The goal is not met, because of four code-confirmed defects and one unperformed ceremony:

1. **Trust reload.** One plan: lock, version check and live-install test (A-CR-01). A running signer does not pick up a new policy, which is a direct "signing rules can be bypassed" defect, and it breaks audit verification.
2. **Root/admin separation.** One small plan: the B-CR-01 cross-check in the verify paths, `root sign` and install, plus tests.
3. **Hardware custody honesty.** One plan:
   - the D-CR-02 TPM attribute check plus an swtpm import test;
   - the D-CR-01 PIN-retry guard, the non-restart exit code and the unit hardening.
   - D-WR-01 (TPM noDA) fits naturally here too.
4. **Real ceremony and KEY-07.** One plan plus an owner action:
   - add a successor-bundle builder (or decide to rebuild from genesis);
   - the owner runs the offline ceremony and moves the homelab signer onto the real roots;
   - correct the KEY-07 overclaims in the SUMMARYs.
5. **Real hardware.** Owner hardware (issue #13): validate on a YubiHSM 2 and a YubiKey, or accept the clause by override.

Items 1-3 are code and can go in one gap-closure wave. Items 4 and 5 need the owner. Also update REQUIREMENTS.md: REPO-01 is now satisfied live, while KEY-04 and KEY-05 are marked Complete but are partial until gaps 4 and 5 close.

---

_Verified: 2026-10-07_
_Verifier: Claude (gsd-verifier)_
