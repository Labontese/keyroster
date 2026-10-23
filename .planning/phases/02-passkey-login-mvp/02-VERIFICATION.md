---
phase: 02-passkey-login-mvp
verified: 2026-10-23T10:00:45Z
status: passed
score: 5/5 roadmap truths verified or passed by owner override (SC2 macOS real-browser clause by override, still UNVERIFIED; SC5 'every CLI command' by override under D-18); 145/145 plan must-have truths verified, attested or passed by override (02-14 truth 4 verified by the timed Windows cold-start run of 2026-10-23; 02-13 truth 8 and 02-14 truth 9 by override)
finalized: 2026-10-23 (owner decisions applied by the orchestrator; fingerprint regenerated at cbdb6e8 without re-running the verifier, see Post-verification changes)
covered_files:
  - ".github/rulesets/main-integrity.json"
  - ".github/workflows/ci.yml"
  - ".github/workflows/codeql.yml"
  - ".github/workflows/e2e-pkcs11.yml"
  - ".github/workflows/e2e-tpm.yml"
  - ".github/workflows/e2e.yml"
  - ".github/workflows/scorecard.yml"
  - ".golangci.yml"
  - ".planning/phases/02-passkey-login-mvp/02-01-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-01-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-02-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-02-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-03-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-03-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-04-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-04-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-05-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-05-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-06-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-06-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-07-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-07-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-08-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-08-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-09-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-09-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-10-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-10-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-11-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-11-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-12-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-12-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-13-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-13-SUMMARY.md"
  - ".planning/phases/02-passkey-login-mvp/02-14-PLAN.md"
  - ".planning/phases/02-passkey-login-mvp/02-14-SUMMARY.md"
  - "CONTRIBUTING.md"
  - "cmd/keyroster-server/main.go"
  - "cmd/keyroster-server/main_other.go"
  - "cmd/keyroster-server/serve.go"
  - "cmd/keyroster-signer/backends_linux.go"
  - "cmd/keyroster-signer/doctor_test.go"
  - "cmd/keyroster/agent_windows.go"
  - "cmd/keyroster/agent_windows_test.go"
  - "cmd/keyroster/agentconn_unix.go"
  - "cmd/keyroster/agentconn_unix_test.go"
  - "cmd/keyroster/agentconn_windows.go"
  - "cmd/keyroster/audit.go"
  - "cmd/keyroster/browser_darwin.go"
  - "cmd/keyroster/browser_linux.go"
  - "cmd/keyroster/browser_other.go"
  - "cmd/keyroster/browser_windows.go"
  - "cmd/keyroster/ca.go"
  - "cmd/keyroster/ca_status_test.go"
  - "cmd/keyroster/commands.go"
  - "cmd/keyroster/commands_test.go"
  - "cmd/keyroster/config.go"
  - "cmd/keyroster/directory.go"
  - "cmd/keyroster/dirpipe.go"
  - "cmd/keyroster/dirpipe_test.go"
  - "cmd/keyroster/fuzz_user_test.go"
  - "cmd/keyroster/genesis_webauthn_test.go"
  - "cmd/keyroster/group.go"
  - "cmd/keyroster/host.go"
  - "cmd/keyroster/hostgroup.go"
  - "cmd/keyroster/init.go"
  - "cmd/keyroster/init_test.go"
  - "cmd/keyroster/login.go"
  - "cmd/keyroster/login_test.go"
  - "cmd/keyroster/login_unix_test.go"
  - "cmd/keyroster/login_windows_test.go"
  - "cmd/keyroster/loginagent_unix.go"
  - "cmd/keyroster/loginagent_windows.go"
  - "cmd/keyroster/loopback.go"
  - "cmd/keyroster/peer_text_test.go"
  - "cmd/keyroster/remote_text_test.go"
  - "cmd/keyroster/role.go"
  - "cmd/keyroster/role_test.go"
  - "cmd/keyroster/root.go"
  - "cmd/keyroster/root_test.go"
  - "cmd/keyroster/runbook_test.go"
  - "cmd/keyroster/testdata/fuzz/FuzzParseInviteURL/2351378a25f12f2e"
  - "cmd/keyroster/testdata/fuzz/FuzzParseInviteURL/815f58a75006522d"
  - "cmd/keyroster/user.go"
  - "cmd/keyroster/user_pending_test.go"
  - "cmd/keyroster/user_test.go"
  - "deploy/systemd/keyroster-server.service"
  - "deploy/systemd/keyroster-tailscale-cert.service"
  - "deploy/systemd/keyroster-tailscale-cert.timer"
  - "deploy/sysusers.d/keyroster.conf"
  - "docs/runbooks/enroll-user.md"
  - "docs/runbooks/host-setup.md"
  - "docs/runbooks/root-ceremony.md"
  - "docs/runbooks/server-install.md"
  - "docs/runbooks/signer-install.md"
  - "docs/security/custody.md"
  - "docs/security/needs-hardware.md"
  - "go.mod"
  - "go.sum"
  - "internal/adminauth/adminauth.go"
  - "internal/adminauth/adminauth_test.go"
  - "internal/adminauth/fuzz_test.go"
  - "internal/audit/export.go"
  - "internal/audit/export_test.go"
  - "internal/audit/fuzz_test.go"
  - "internal/audit/verify.go"
  - "internal/audit/verify_test.go"
  - "internal/cert/builder.go"
  - "internal/cert/fuzz_test.go"
  - "internal/cert/keyid.go"
  - "internal/cert/keyid_test.go"
  - "internal/custodytext/custodytext.go"
  - "internal/custodytext/custodytext_test.go"
  - "internal/directory/authorize.go"
  - "internal/directory/diff.go"
  - "internal/directory/diff_test.go"
  - "internal/directory/directory.go"
  - "internal/directory/directory_test.go"
  - "internal/directory/fuzz_test.go"
  - "internal/directory/race_off_test.go"
  - "internal/directory/race_on_test.go"
  - "internal/directory/render.go"
  - "internal/directory/render_test.go"
  - "internal/directory/verify.go"
  - "internal/doctor/doctor.go"
  - "internal/keystore/software/software.go"
  - "internal/keystore/software/software_test.go"
  - "internal/rootceremony/sign_test.go"
  - "internal/rootceremony/summary.go"
  - "internal/server/account.go"
  - "internal/server/admin.go"
  - "internal/server/admin_test.go"
  - "internal/server/credential.go"
  - "internal/server/directory.go"
  - "internal/server/directory_test.go"
  - "internal/server/enroll.go"
  - "internal/server/enroll_test.go"
  - "internal/server/fuzz_credential_test.go"
  - "internal/server/headers.go"
  - "internal/server/invite.go"
  - "internal/server/login.go"
  - "internal/server/login_test.go"
  - "internal/server/ratelimit.go"
  - "internal/server/render.go"
  - "internal/server/server.go"
  - "internal/server/server_test.go"
  - "internal/server/servertest/softreg.go"
  - "internal/server/session.go"
  - "internal/server/session_test.go"
  - "internal/server/signer.go"
  - "internal/server/tlsreload.go"
  - "internal/server/tlsreload_test.go"
  - "internal/server/web/embed.go"
  - "internal/server/web/static/app.css"
  - "internal/server/web/static/app.js"
  - "internal/server/web/templates/account.html"
  - "internal/server/web/templates/base.html"
  - "internal/server/web/templates/enroll.html"
  - "internal/server/web/templates/error.html"
  - "internal/server/web/templates/index.html"
  - "internal/server/web/templates/login.html"
  - "internal/server/web/templates/login_approve.html"
  - "internal/server/webauthn_oracle_test.go"
  - "internal/server/weblogin.go"
  - "internal/server/weblogin_test.go"
  - "internal/serverclient/admin.go"
  - "internal/serverclient/admin_test.go"
  - "internal/serverclient/client.go"
  - "internal/serverclient/client_test.go"
  - "internal/serverclient/fuzz_test.go"
  - "internal/serverdb/db.go"
  - "internal/serverdb/db_test.go"
  - "internal/serverdb/migrate.go"
  - "internal/serverdb/migrations/0001_server.sql"
  - "internal/serverdb/migrations/0002_registration.sql"
  - "internal/serverdb/migrations/0003_web.sql"
  - "internal/serverdb/migrations/0004_login.sql"
  - "internal/signer/directory.go"
  - "internal/signer/directory_socket_test.go"
  - "internal/signer/directory_test.go"
  - "internal/signer/fixture_test.go"
  - "internal/signer/issue.go"
  - "internal/signer/log_test.go"
  - "internal/signer/login.go"
  - "internal/signer/login_test.go"
  - "internal/signer/logstate.go"
  - "internal/signer/refusal.go"
  - "internal/signer/refusal_test.go"
  - "internal/signer/server.go"
  - "internal/signer/signer.go"
  - "internal/signer/signer_test.go"
  - "internal/signer/status.go"
  - "internal/signer/status_test.go"
  - "internal/signer/trust.go"
  - "internal/signer/trust_test.go"
  - "internal/signerclient/client.go"
  - "internal/signerclient/client_test.go"
  - "internal/signerdb/db_test.go"
  - "internal/signerdb/directory.go"
  - "internal/signerdb/log.go"
  - "internal/signerdb/migrations/0004_directory.sql"
  - "internal/sshsig/sshsig.go"
  - "internal/sshsig/sshsig_test.go"
  - "internal/tlog/fuzz_test.go"
  - "internal/tlog/leaf.go"
  - "internal/tlog/leaf_test.go"
  - "internal/trust/bundle.go"
  - "internal/trust/canonical.go"
  - "internal/trust/capubkeys.go"
  - "internal/trust/helpers_test.go"
  - "internal/trust/policy.go"
  - "internal/trust/race_off_test.go"
  - "internal/trust/race_on_test.go"
  - "internal/trust/verify.go"
  - "internal/trust/verify_test.go"
  - "internal/trust/webauthn_test.go"
  - "internal/webauthn/clientdata.go"
  - "internal/webauthn/fuzz_test.go"
  - "internal/webauthn/verify.go"
  - "internal/webauthn/verify_test.go"
  - "internal/webauthn/webauthntest/soft.go"
  - "internal/winagent/ensure_windows.go"
  - "internal/winagent/offer_windows_test.go"
  - "internal/winagent/owner_windows.go"
  - "internal/winagent/winagent_windows.go"
  - "internal/winagent/winagent_windows_test.go"
  - "internal/wire/directory.go"
  - "internal/wire/frame.go"
  - "internal/wire/fuzz_test.go"
  - "internal/wire/login.go"
  - "internal/wire/status.go"
  - "internal/wire/status_test.go"
  - "internal/wire/wire_test.go"
  - "scripts/dep-firewall.sh"
  - "scripts/testonly-firewall.sh"
  - "test/capslock/keyroster-signer.json"
  - "test/e2e/approve_test.go"
  - "test/e2e/audit_login_test.go"
  - "test/e2e/bootstrap_test.go"
  - "test/e2e/enroll_test.go"
  - "test/e2e/harness_test.go"
  - "test/e2e/login_refusal_test.go"
  - "test/e2e/login_signer_test.go"
  - "test/e2e/login_test.go"
  - "test/e2e/roles_test.go"
  - "test/e2e/server_test.go"
  - "test/e2e/software_test.go"
  - "test/e2e/tlsca_test.go"
  - "test/e2e/websignin_test.go"
  - "test/vectors/directory_v1.json"
  - "test/vectors/leaf_directory_install_v1.hex"
  - "test/vectors/leaf_login_issue_v1.hex"
  - "test/vectors/login_request_signing_v1.hex"
covered_digest: "v3:sha256:0de2a035e8b604e940ba79466ab32c4318b9281ab684975d8113ae77bbecc9d2"
behavior_unverified: 0
overrides_applied: 4
gaps: []
deferred:
  - truth: "KEY-02 'required approvals' clause: the signer refuses a sensitive login without a second person's approval bound to that request"
    addressed_in: "Phase 4"
    evidence: "Phase 4 SC2: 'A user requests just-in-time access to a sensitive role and another person approves it in the UI with WebAuthn step-up; the approval is bound to that exact request, works once ...'"
advisory:
  - finding: "MVP-mode guard: ROADMAP marks Phase 2 'Mode: mvp', but the goal is not a user story (gsd user-story.validate: valid=false, no 'As a ..., I want to ..., so that ...'). Verified with the goal-backward method, as Phase 1 (also mode mvp, same goal shape) was; a User Flow Coverage table is added below"
    category: other
    reason: "Resolved 2026-10-23: the orchestrator follows the Phase 1 precedent (verified the normal way plus the User Flow Coverage table); the goal was not rewritten"
    evidence_status: "gsd-tools user-story.validate output"
  - finding: "REQUIREMENTS.md still has KEY-02 unchecked and 'Pending', although 02-04-SUMMARY completed it and every Phase 2 clause (assertion over the request digest, quorum-signed directory, root-signed policy) is enforced and tested; the 'required approvals' clause is Phase 4 SC2"
    category: other
    reason: "Resolved 2026-10-23: KEY-02 stays unchecked because its text includes 'required approvals' (Phase 4 SC2); the traceability row now says the Phase 2 clauses are complete and names Phase 4 for the rest"
    evidence_status: "none provided (documentation drift only)"
  - finding: "Plan text left uncorrected: 02-13 truth 8 and 02-14 (L223, L265, L322, L354) say anchor_bundle_version==3; the anchor is 2 by design (deferred-items.md). 02-14 truth 9 says cli-windows is required and green on main since 02-02; owner decision D1 says otherwise"
    category: other
    reason: "Resolved 2026-10-23: both truths accepted by owner override (below); the plan text itself is left as executed (editing it would stale covered_digest) and the correction is a pending todo"
    evidence_status: "deferred-items.md rows 02-13 and 02-14 (D1); todo 2026-10-23-correct-02-13-and-02-14-plan-text-drift.md"
  - finding: "Committed files name the Windows desktop and the zima host by machine name (needs-hardware.md, 02-14-SUMMARY.md), outside the alias allow-list of the 02-13/02-14 hostname prohibition. The guard literals (6) match nothing at 391a49f"
    category: security
    reason: "OPEN: no owner decision yet. Letter of the prohibition vs. the guard. Owner decides whether machine names count; if they do, replace them with the aliases"
    evidence_status: "git grep of the guard literals at 391a49f: 0 files"
owner_decisions:
  - date: "2026-10-23"
    choice: "Godkänn alla tre (Rekommenderas)"
    effect: "The three suggested overrides are accepted: 02-14 truth 9 (cli-windows required) replaced by D1; 02-13 truth 8 (anchor v3) is v2 by design; SC5 'every CLI command' read through D-18 as every command that talks to the server"
  - date: "2026-10-23"
    choice: "Stäng med macOS UNVERIFIED (Rekommenderas)"
    effect: "Phase 2 closes with the macOS real-browser leg UNVERIFIED (no Mac available), recorded as an owner override of SC2's macOS clause; AUTH-03 and PLAT-05 stay partially met (Pending)"
  - date: "2026-10-23"
    choice: "Kör testet nu (Rekommenderas)"
    effect: "The timed Windows expiry run from a cold start was done; 02-14 truth 4 is VERIFIED (see 'Human verification: resolved')"
  - date: "2026-10-23"
    choice: "Acceptera, lägg till tester senare (Rekommenderas)"
    effect: "The verifier's evidence for the five judgment-tier and four test-tier flagged prohibitions is accepted; negative tests for 02-10 (no non-passkey sign-in route) and 02-12 (no file write of the ephemeral key in the login path) are pending todos"
overrides:
  - must_have: "cli-windows and cli-macos have run green on main since 02-02. They are added to the main-integrity ruleset, which the owner applies from the PR branch before approving"
    reason: "Owner decisions D1 (cli-macos only until go-winio PR #41 merges and cli-windows is green on main) and D2 (ruleset applied from main after the merge), recorded in deferred-items.md and 02-14-SUMMARY deviations 10-11. Accepted 2026-10-23: 'Godkänn alla tre (Rekommenderas)'"
    accepted_by: "Daniel (owner)"
    accepted_at: "2026-10-23"
  - must_have: "keyroster audit verify of the exported homelab log prints OK anchored on bundle v3 under pins C and D, and counts the directory installs"
    reason: "audit verify anchors on the first bundle whose root set matches the pins; C and D became the root set in v2, so the anchor is v2 with bundle v3 in force (deferred-items.md 02-13 row; re-run by the verifier: ok, bundle_version 3, anchor_bundle_version 2). Accepted 2026-10-23: 'Godkänn alla tre (Rekommenderas)'"
    accepted_by: "Daniel (owner)"
    accepted_at: "2026-10-23"
  - must_have: "SC5: when the CA runs on an encrypted software key, every CLI command shows a loud evaluation-only warning"
    reason: "D-18 scopes the CLI warning to commands that talk to the server or signer, the only commands that can learn custody; offline commands (root, trust verify, audit verify, version) cannot know it. Accepted 2026-10-23: 'Godkänn alla tre (Rekommenderas)'"
    accepted_by: "Daniel (owner)"
    accepted_at: "2026-10-23"
  - must_have: "SC2 (macOS clause) / AUTH-03 / PLAT-05: `keyroster login` on macOS with a real browser and passkey puts the certificate into the macOS ssh-agent, the user logs in to a stock OpenSSH host, and the certificate leaves the agent when it expires"
    reason: "UNVERIFIED, closed by owner override 2026-10-23: 'Stäng med macOS UNVERIFIED (Rekommenderas)'. No Mac is available. The required cli-macos CI job runs the CLI flow against a fake server with a real ssh-agent (TestLoginFlowFakeServer, TestLoginAgentUnix, KEYROSTER_REQUIRE_SSH_AGENT=1), but no browser, passkey or real server. AUTH-03 and PLAT-05 stay Pending in REQUIREMENTS.md, and needs-hardware.md labels macOS UNVERIFIED, until a Mac run"
    accepted_by: "Daniel (owner)"
    accepted_at: "2026-10-23"
---

# Phase 2: Passkey Login MVP Verification Report

**Phase Goal:** A user signs in with a passkey and, with one command, gets a short-lived certificate in ssh-agent that lets them SSH into a host as exactly the principals their role grants: the first end-to-end login.
**Verified:** 2026-10-23
**Status:** passed (2026-10-23, after the owner's decisions). No code gap. The first end-to-end login is proven on Linux and Windows, and the timed Windows expiry run from a cold start was done. Four owner overrides were applied: the macOS real-browser leg closes as UNVERIFIED (no Mac), 02-13 truth 8 and 02-14 truth 9 are superseded, and SC5 is read through D-18. The owner accepted the evidence for the 9 flagged prohibitions; two negative tests are follow-ups. The original verifier status was human_needed; see "Owner decisions and resolution (2026-10-23)" at the end.
**Re-verification:** No, initial verification.
**Code under test:** `p02/close` at 5d406fc. Its code is identical to main `391a49f` (`git diff 391a49f HEAD -- . ':!.planning'` is empty). The clean clone `C:/Users/labon/kr-verify-02` is at 391a49f.

## Method and evidence base

- **CI on main at 391a49f** (`gh api .../commits/391a49f/check-runs`). Every required context that runs on push completed with success: build-test, lint, govulncheck, fuzz, capslock, dependency-firewall, pinned-actions, e2e (9.5p1), e2e (10.5p1), e2e-pkcs11 (distro-p256, 10.5p1-ed25519), e2e-tpm, build-piv, systemd-sandbox, cli-macos, Analyze (go) and Analyze (actions). pr-title runs on PRs only. scorecard also succeeded.
  - **cli-windows (not required, owner decision D1) FAILED on main at 391a49f**, job 120348006995: `panic: test timed out after 10m0s` in `TestAgent/ensure_retries_once_on_closing_agent`, with goroutines blocked in go-winio v0.6.2 `pipe.go`. This is the known hang. Dependabot PR #41 (go-winio v0.6.4) is still OPEN.
- **CI job logs read for test names.** In both e2e lanes, 32 top-level tests PASS and 0 SKIP. These include TestLoginEndToEnd (subtests login_lifetime_expiry, two_concurrent_logins, unapproved_login_mints_nothing, signer_refusal_after_approval), TestLoginRefusals, TestLoginSignerEndToEnd, TestWebSignInEndToEnd, TestRolesHostPrincipalsEndToEnd, TestEnrollApproveEndToEnd, TestSoftwareCAEndToEnd, TestServerInitEndToEnd, TestServerRefusesStart and TestAuditLoginAcrossPolicyChange. The Phase 1 tests are still green: TestIssueAcceptedBySSHD, TestSSHDRejects, TestSignerRefuses, TestTrustRefuses, TestRootRotationLiveSigner and the audit tests.
- **Local run.** Windows 11, Go 1.27.3, clean clone at 391a49f. `go test -count=1 ./...` was the one full run. Every package passed except `internal/winagent`, where `TestAgent/ensure_starts_real_agent` refused because a keyroster agent already served this account's pipe. That is the test's own guard (`requireAccountPipeFree`), and no agent process was left running afterwards. Named tests were then run once each:
  - `go test -run TestAgent ./internal/winagent/`: ok;
  - `go test -v -run 'TestAgent/lifetime_expiry_exit' ./internal/winagent/`: PASS.
  - `-race` and the e2e suite were not run locally. Their evidence is CI.
- **Independent homelab re-check.** I built `keyroster` from the clean clone and ran `audit verify --json` with the root pins and threshold from the owner's CLI config. The exports are in the owner's evidence directory, outside the repository.
  - homelab-after-windows.export with `--previous homelab.export`: ok, 15 entries, bundle_version 3, policy_version 2, anchor_bundle_version 2, login_issue 2, refusals 0.
  - homelab-after-linux.export with `--previous homelab-after-windows.export`: ok, 17 entries, login_issue 4, refusals 0.
  - The 8 h serials 1792704938150899 (Windows) and 1792726285487553 (Linux) each appear once in the export and once as an `ED25519-CERT ... (serial N) CA` line in the matching host's journal extract.
  - `audit verify` re-proves every login_issue entry's passkey assertion, principals, TTL and certificate binding (02-04). This confirms the SUMMARY's login claims from the raw data, not from its narrative.
- **Live GitHub state:**
  - At the time of verification the `main-integrity` ruleset had deletion, non_fast_forward, required_linear_history, required_signatures and required_status_checks with 18 contexts: cli-macos was in, cli-windows was not (owner decision D1; cli-windows was added afterwards, see Post-verification changes). `main-review` (active) carries pull_request.
  - Every merged PR from #36 to #54 (16 PRs) was merged by keyroster-bot with APPROVED.
  - Issue #13 is OPEN.
- **Code reading.** The signer login path (`internal/signer/login.go`), directory authorization and validation, server routes, sign-in, CSP, embed, the custody banner path, the CLI login, the Windows agent and app.js.
- **Windows CLI binary.** The `keyroster.exe` the owner ran reports revision 99c2795 (the 02-13 build). Against 391a49f only `cmd/keyroster/loginagent_unix.go` and `cmd/keyroster/runbook_test.go` differ among the Go files, so the Windows login path is the same code.
- **Tool checks.**
  - `verify.artifacts`: 77/78 artifacts pass. The one miss is 02-14's `main-integrity.json`, which lacks `cli-windows` by owner decision D1.
  - `verify.key-links`: 39/45 links found by pattern. Two code links were checked by hand. The four homelab links are not file links: they are attested, and re-checked through the audit exports.
  - `scripts/dep-firewall.sh` passes for both default and piv builds, so go-webauthn and fxamacker/cbor are not in the signer graph.
  - The guard literals match nothing at 391a49f.

## Goal Achievement: Roadmap Success Criteria (contract)

| # | Truth | Status | Evidence |
|---|---|---|---|
| 1 | Admin creates a local account that stays unusable until the user registers at least one passkey/FIDO2 key; the user then signs in to the web UI with that key | ✓ VERIFIED | **Unusable until registered.** `directory.Validate` refuses an active user with no credential (internal/directory/directory.go:259). Sign-in reads only the signer's installed, admin-signed directory (`boundCredential`, weblogin.go:222). Server rows never authorize anything. Unit tests `pending_user_uniform_404`, `unapproved_user_uniform_404` and `install_refuses_credential_no_longer_pending` cover this, as do e2e TestUserAddInvite, TestRegisterPasskeyPending and TestEnrollApproveEndToEnd (PASS).<br>**Sign-in.** e2e TestWebSignInEndToEnd PASSes with a soft authenticator. The owner signed in with a synced passkey in Chrome on Windows 11, and `/account` showed the role (02-14, owner attestation). The server journal extract in the owner's evidence directory holds one `signin_ok` line (counted by this verifier). |
| 2 | User runs `sshcm login` (shipped as `keyroster login`) on Linux, macOS or Windows, sees the same fingerprint in CLI and browser, approves, and gets a certificate (hours, capped by role) in ssh-agent that leaves the agent when the certificate expires | ✓ VERIFIED on Linux and Windows; macOS clause PASSED (override), still UNVERIFIED | **Code.** The CLI prints `Key fingerprint:` (login.go:264). The approval page renders the fingerprint the server computes from the stored signed request (`page_shows_stored_fingerprint`). `--ttl` defaults to the smallest role cap, and the signer refuses `ttl_exceeds_role` (signer/login.go). The agent add carries `LifetimeSecs` = the remaining validity (login.go:580).<br>**Linux:** VERIFIED. e2e login_lifetime_expiry runs a real ssh-agent and sshd. The homelab laptop logged in through gcr-ssh-agent, and the 5 m certificate was gone 57 s after expiry. I re-verified the serial in the export and the journal.<br>**Windows:** the login is VERIFIED (serial in the export and the host journal, re-verified). Removal at expiry: VERIFIED on 2026-10-23 by a timed `--ttl 5m` run from a cold start (see "Owner decisions and resolution"): last listing with the key 3.9 s before valid_before, first empty listing 1.1 s after it, at 5 s resolution.<br>**macOS:** the CLI flow is CI-tested (cli-macos green; ssh-agent required). A real browser and passkey on a Mac: **UNVERIFIED** (no Mac). |
| 3 | Admin defines roles mapping users and groups to principals on host groups; the certificate carries exactly those principals and logs in to a manually configured stock-OpenSSH host | ✓ VERIFIED | `Directory.Authorize` derives principals, TTL cap and extensions from the roles only (authorize.go:26-66). The signer refuses `principals_mismatch` unless the request equals the grant exactly (signer/login.go). e2e TestRolesHostPrincipalsEndToEnd: a real sshd fed exactly `host principals` / `host ca-key` output accepts a certificate carrying exactly `role:ops`, and after unmap a fresh sshd refuses it. Homelab: all four certificates carry exactly `role:homelab-admin` (directory v6), and two hosts configured by hand with one sshd drop-in each accepted them. |
| 4 | The signer refuses to sign, whatever the server sends, when the assertion is missing, replayed or bound to a different digest, or when the policy version is not root/quorum-signed | ✓ VERIFIED (behaviorally) | `verifyLoginEvidence` (signer/login.go) is default-deny with named refusals. Replay: `RequestIDUsed`, giving `duplicate_request`, inside the issuance transaction. Digest: `webauthn.VerifyAssertion(..., req.Digest(), ...)`, giving `challenge_mismatch`.<br>e2e TestLoginRefusals (PASS on both lanes) covers missing_assertion, replayed_request, wrong_digest, directory_not_quorum_signed, policy_without_rp and wrong_evidence_type. Each has a succeeding control, and the exported log is checked for no stray login_issue.<br>The unit TestLoginPolicyClause/policy_not_root_signed covers an RP policy signed outside the root set: refused at install with `trust.ErrThreshold`, and the login keeps refusing, also after a restart. TestLoginRefusalMatrix and TestEvidenceMix also PASS (local full run). |
| 5 | Server and signer run on Linux and serve a server-rendered UI embedded in the binary, strict CSP, no npm; with an encrypted software CA key, every CLI command and every UI page shows a loud evaluation-only warning | ✓ VERIFIED (D-18 scope, see note) | **Platform.** `cmd/keyroster-server` and `cmd/keyroster-signer` are `//go:build linux`, with a `!linux` stub. Both run on the homelab under systemd.<br>**UI.** `//go:embed templates static` holds 6 html/template pages and a hand-written app.js/app.css. There is no package.json or node_modules, and no inline script, style or event handler.<br>**CSP.** `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` (headers.go), set on every response.<br>**Banner.** It sits in base.html for every page and comes from signer-reported custody (render.go:60). Its tests are `software_custody_banner`, `custody_banner_on_signin_pages`, `custody_banner_on_approval_page` and `no_banner_without_software`. Every CLI request to the server goes through one `send` path that calls `checkCustody` (serverclient/client.go:434-465); AdminJSON, GetJSON, PostJSON and Trust all go through it. `ca issue` checks signer Status first (ca.go:170). e2e TestSoftwareCAEndToEnd and TestServerInitEndToEnd PASS.<br>**Note:** D-18 (02-CONTEXT) narrows "every CLI command" to "every command that talks to the server" (or the signer, for `ca issue`). Offline commands (`root`, `trust verify`, `audit verify`, `version`) cannot know custody and print no banner. The literal clause is not met for them; an override is suggested below. |

**Score:** 5/5 roadmap truths verified or passed by owner override (SC2's macOS clause and SC5's "every CLI command" by override). None failed. (Before the owner's decisions: 4/5, with SC2 behavior-unverified.)

### User Flow Coverage (MVP mode)

| Step | Expected | Evidence | Status |
|---|---|---|---|
| Admin invites, user registers a passkey, admin approves | Account usable only after an admin-signed directory binds the passkey | TestEnrollApproveEndToEnd; homelab 02-13 (owner, Chrome) | ✓ |
| User signs in to the web UI with the passkey | `/account` shows role and principals | TestWebSignInEndToEnd; homelab Windows/Chrome | ✓ |
| One command: `keyroster login` | Fingerprint on CLI and page, approve, certificate in the agent with a lifetime | TestLoginEndToEnd; homelab Windows and Linux | ✓ Linux and Windows / ⚠️ macOS UNVERIFIED |
| SSH as exactly the role's principals | Stock sshd accepts the certificate; principals = role grant | TestRolesHostPrincipalsEndToEnd; 2 homelab hosts, serials in the journals | ✓ |
| Certificate leaves the agent at expiry | Key removed at valid_before | e2e login_lifetime_expiry; laptop 57 s after expiry; Windows timed cold-start run 2026-10-23 (gone within 1.1 s after valid_before at 5 s resolution) | ✓ Linux and Windows / ⚠️ macOS UNVERIFIED (owner override) |

### Deferred Items

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | KEY-02 "required approvals" (a second person's per-request approval) | Phase 4 | Phase 4 SC2 (two-person JIT approval bound to the exact request) |

Carried from Phase 1 (not a Phase 2 gap): the KEY-07 offline ceremony is still owed. After 02-13 it becomes the v4 rotation. Issue #13 (real hardware) is OPEN.

### Advisory

| # | Finding | Category | Why Advisory |
|---|---------|----------|--------------|
| 1 | The goal fails the MVP user-story guard. The Phase 1 precedent was followed. | other | Owner decision |
| 2 | REQUIREMENTS.md: KEY-02 is unchecked and "Pending" | other | Documentation drift |
| 3 | Plan text still says anchor 3 (02-13, 02-14) and requires cli-windows (02-14) | other | Corrected in deferred-items.md, not in the plans |
| 4 | Machine names outside the alias allow-list are in committed files | security | The guard literals are clean. The owner decides the scope. |

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `internal/signer/login.go` | Login issuance only on a verified assertion over the request digest, exact principals, TTL cap | ✓ VERIFIED | Wired from server.go (LoginIssue frame) and logged as login_issue |
| `internal/webauthn/verify.go` | Assertion verification over SPKI; no CBOR in the signer | ✓ VERIFIED | dep-firewall passes |
| `internal/directory/*` | Admin-signed directory, Authorize, principals renderer | ✓ VERIFIED | Used by signer, server and CLI `host principals` |
| `internal/server/*` + `web/` | Routes, sign-in, enrollment, login approval, CSP, banner, embed | ✓ VERIFIED | e2e server, web sign-in and login tests |
| `cmd/keyroster/login.go`, `loginagent_*.go`, `loopback.go` | One-command login, PKCE/state loopback, own-key check, agent with lifetime | ✓ VERIFIED | TestLoginFlowFakeServer on 3 OSes (cli-windows flaky on an unrelated subtest) |
| `internal/winagent/*` | In-memory Windows agent with lifetime | ✓ VERIFIED (unit) | lifetime_expiry_exit PASS. Known Close hang in go-winio v0.6.2 (see anti-patterns). |
| `internal/keystore/software/*`, `internal/custodytext` | KEY-06 software CA key plus warning | ✓ VERIFIED | TestSoftwareCAEndToEnd |
| `.github/rulesets/main-integrity.json` | cli-macos and cli-windows required (02-14 plan) | ⚠️ cli-macos only | Owner decision D1; live ruleset matches the file |
| `docs/security/needs-hardware.md` | Platform record with UNVERIFIED rows | ✓ VERIFIED | macOS, Edge/Firefox and other gaps labelled UNVERIFIED |

### Key Link Verification

| From | To | Via | Status |
|---|---|---|---|
| server login redeem | signer LoginIssue | `signerclient.Login` after code + PKCE redeem; `signer_not_called_on_refusal`, `redeem_before_approval` | WIRED |
| signer LoginIssue | installed directory | `directory.Authorize` + `Credential` under `directoryAuthorized` | WIRED |
| `cmd/keyroster/init.go` | `trust.MatchPins` | `client.Trust` (serverclient/client.go:802-807) | WIRED (the plan's pattern is in the client, not init.go) |
| `cmd/keyroster/user.go` | admin signature | `AdminJSON` → `adminauth.Sign` (admin.go:237); `adminauth.Message` renamed in 02-07 D1/D2 | WIRED |
| every CLI server call | custody banner | `send` → `checkCustody` | WIRED |
| page render | custody banner | `pageData.Banner` from signer Status | WIRED |
| `host principals` output | homelab sshd | hand-installed principals file plus drop-in | ATTESTED (02-14; hashes in the SUMMARY) |
| owner logins | export + sshd journal | serial match | WIRED (re-checked by this verifier) |

### Data-Flow Trace (Level 4)

| Artifact | Data | Source | Real data | Status |
|---|---|---|---|---|
| login_approve.html | Fingerprint | Server computes it from the stored signed request bytes | yes | ✓ FLOWING |
| account.html | Roles and principals | Signer's installed directory via `currentDirectory` | yes | ✓ FLOWING |
| base.html banner | Custody | `signerclient.Status` (signer-reported) | yes | ✓ FLOWING |
| Certificate principals | `grant.Principals` | Admin-signed directory roles | yes | ✓ FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Unit suite at 391a49f (Windows) | `go test -count=1 ./...` (once) | All ok except winagent `ensure_starts_real_agent` (account pipe in use) | ✓ PASS (environmental refusal, rerun ok) |
| Windows agent drops an expired key | `go test -v -run 'TestAgent/lifetime_expiry_exit' ./internal/winagent/` | PASS | ✓ PASS |
| Signer graph free of go-webauthn/CBOR | `bash scripts/dep-firewall.sh` | default and piv: only the documented os/exec exception | ✓ PASS |
| Homelab logins re-proven | `keyroster audit verify --json --pin … --threshold … --previous …` on both exports | ok, login_issue 2 then 4, refusals 0 | ✓ PASS |
| Login serials on the hosts | Serial in export and journal extract | 1 + 1 per 8 h serial | ✓ PASS |
| SC4 through the real socket | e2e TestLoginRefusals (CI logs, both lanes) | PASS | ✓ PASS |

### Probe Execution

No `scripts/*/tests/probe-*.sh` exists, and no PLAN declares one. Skipped.

### Plan must-have truths (145)

| Plans | Truths | Result |
|---|---|---|
| 02-01 … 02-12 | 126 | 126 VERIFIED. Each artifact passes, each key link is wired (two by hand), the named tests behind them pass in the local run or the CI e2e lanes, and the code was spot-read for the signer login path, directory, server routes, sign-in, CSP, banner, CLI login and Windows agent. |
| 02-13 homelab RP and enrollment | 9 | 8 VERIFIED or attested. Bundle v3, policy v2 with the RP and directory installs are re-proven by my `audit verify`. **Truth 8** ("anchored on bundle v3") is **superseded**: the anchor is v2 by design (deferred-items.md). PASSED (override), accepted 2026-10-23. |
| 02-14 homelab logins | 10 | 9 VERIFIED or attested. Truths 1-3 and 7 carry deviations 1-2: the Windows target was a Proxmox test VM, not zima. **Truth 4** (Windows key gone at expiry) was ⚠️ behavior-unverified at verification time (times not recorded) and is VERIFIED by the timed cold-start run of 2026-10-23. **Truth 9** (cli-windows green and required) is **superseded** by owner decision D1 and is false as written: cli-windows failed on main at 391a49f. PASSED (override), accepted 2026-10-23. |

Totals after the owner's decisions: 143 verified or attested, 2 PASSED (override), 0 PRESENT_BEHAVIOR_UNVERIFIED. (At verification time: 142, 1 and 2 superseded.)

### Prohibitions (ADR-550 routing)

| Plan | Prohibition | Tier | Disposition |
|---|---|---|---|
| 02-01 | No login certificate without a signer-verified assertion | test | ✓ TestLoginRefusals/missing_assertion, TestLoginRefusalMatrix |
| 02-01 / 02-08 | Signer never parses CBOR/COSE; go-webauthn never linked into the signer | test | ✓ dep-firewall.sh (run here) |
| 02-02 | Never the inbox agent, no retry without lifetime, no key-file fallback | test | ✓ TestInboxSSHOffersAgentCert, `constrained_add_refused_no_retry` |
| 02-02 | No ephemeral key on disk or in the registry | judgment | ⚑ holds (non-authoritative: winagent is memory-only; no file write in the login path). Human review recommended. |
| 02-03 | Evidence types never cross message types | test | ✓ TestEvidenceMix, e2e wrong_evidence_type |
| 02-03 | Non-quorum directory never authorizes, also after a policy change | test | ✓ e2e directory_not_quorum_signed, TestLoginPolicyClause |
| 02-04 | `audit verify` never OKs an unprovable login_issue | test | ✓ TestVerifyLoginTampering |
| 02-05 | Warning cannot be suppressed; custody only from the signer | test | ✓ `software_custody_banner_*`, `agent_custody_no_banner`, TestSoftwareCAEndToEnd |
| 02-06 | RP never from server config; no start without it | test | ✓ TestServerRefusesStart/no_rp_in_policy, `policy_without_rp_fails_closed` |
| 02-06 | No npm, third-party or inline script/style | test | ✓ Templates and assets read; CSP headers tested (TestServerHeaders) |
| 02-06 | CLI trusts only pinned TLS roots and root-signed bundles | test | ✓ `unpinned_root_error_names_repin`, `stored_root_without_pin_refused`, init tests |
| 02-07 | Server DB rows never authorize; admin API only for policy admins | test | ✓ pending/unapproved 404 tests, TestAdminAuth |
| 02-08 | A registered credential stays pending until installed | test | ✓ `install_refuses_credential_no_longer_pending`, TestRegisterPasskeyPending |
| 02-09 | Never sign on an unverified base or without a diff/--yes | test | ✓ `fake_base_refused`, `*_requires_yes_without_tty` |
| 02-10 | No non-passkey sign-in path | test | ⚑ **flagged, no named test.** Route table (server.go:122-155) has no password, TOTP, recovery or magic-link handler. |
| 02-10 | A web session never authorizes issuance or directory changes | judgment | ⚑ holds (non-authoritative: the signer verifies the assertion itself; directory changes need SSHSIG). Human review recommended. |
| 02-11 | No empty, wildcard, comma, whitespace or control principal; CLI adds no principals | test | ✓ role/directory tests, `principals_mismatch` refusal |
| 02-12 | Page fingerprint only from stored signed bytes | test | ✓ `page_shows_stored_fingerprint` |
| 02-12 | WebAuthn only from the Approve click | judgment | ⚑ holds (non-authoritative: app.js:259-270 calls `navigator.credentials.get` only in the click handler; owner saw order=ok in Chrome on both OSes). Human review recommended. |
| 02-12 | No signer call before code + PKCE redeem | test | ✓ `signer_not_called_on_refusal`, `redeem_before_approval` |
| 02-12 | CLI never writes the key to disk; no retry without lifetime | test | ◐ the retry half is tested; ⚑ **the disk half is flagged** (no named test; no file write in login.go, loginagent_*.go or loopback.go) |
| 02-13 / 02-14 | No homelab hostname, address or tailnet name committed | test | ✓ guard literals: 0 matches at 391a49f (see advisory 4 on machine names) |
| 02-13 | No .age, passphrase or private key leaves WSL; RP not signed before confirmation | test | ⚑ **flagged (both items)**: attested in 02-13-SUMMARY only; no enforcing test can be run here |
| 02-14 | Nothing unexercised described as verified | judgment | ⚑ holds (non-authoritative: needs-hardware.md and REQUIREMENTS.md label macOS, other browsers and Windows expiry timing UNVERIFIED or open). Human review recommended. |
| 02-14 | No hardware requirement | judgment | ⚑ holds (non-authoritative: a synced passkey was used; hardware optional everywhere). Human review recommended. |

Complete with 9 flagged prohibitions (5 judgment-tier, 4 test-tier without a runnable enforcing test). None is a code gap. The owner accepted the evidence for all 9 on 2026-10-23 ("Acceptera, lägg till tester senare"); the negative tests for 02-10 and the disk half of 02-12 are pending todos.

## Requirements Coverage

All 9 phase IDs appear in at least one PLAN's `requirements:` field. Every ID that REQUIREMENTS.md maps to Phase 2 is claimed by a plan, so none is orphaned.

| Requirement | Source Plans | Status | Evidence |
|---|---|---|---|
| AUTH-01 | 02-07, 02-08, 02-09, 02-13 | ✓ SATISFIED | Invite, pending credential, admin-signed approval; homelab enrollment (02-13) |
| AUTH-02 | 02-10, 02-14 | ✓ SATISFIED | TestWebSignInEndToEnd; Chrome on Windows (owner) |
| AUTH-03 | 02-02, 02-12, 02-14 | ◐ PARTIAL (owner override) | Linux and Windows end to end, Windows removal at expiry timed (2026-10-23). The macOS browser leg is UNVERIFIED (owner override). Stays Pending in REQUIREMENTS.md. |
| AUTH-04 | 02-12, 02-14 | ✓ SATISFIED | Fingerprint on CLI and page; order=ok on both OSes |
| KEY-02 | 02-01, 02-03, 02-04, 02-09 | ✓ SATISFIED (Phase 2 clauses) | SC4 above. "Required approvals" is deferred to Phase 4. Kept Pending in REQUIREMENTS.md with that note (advisory 2). |
| KEY-06 | 02-05, 02-06 | ✓ SATISFIED | Software keystore plus signer-reported banner (D-18 scope) |
| AUTHZ-01 | 02-01, 02-04, 02-11 | ✓ SATISFIED | TestRolesHostPrincipalsEndToEnd; homelab role → host group |
| UI-01 | 02-06, 02-07, 02-08, 02-10, 02-12, 02-13, 02-14 | ✓ SATISFIED | Embedded templates, strict CSP, no npm; all 6 pages opened in Chrome. The DevTools "1 issue" text was never captured (info). |
| PLAT-05 | 02-02, 02-06, 02-12, 02-13, 02-14 | ◐ PARTIAL (owner override) | Server and signer on Linux verified; CLI on Linux and Windows verified; macOS CLI CI-only (UNVERIFIED with a real browser, owner override). Stays Pending. |

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| 225 non-planning files changed since d623927 | | TBD, FIXME, XXX, TODO or HACK | none | No debt markers |
| internal/winagent (go-winio v0.6.2) | winagent_windows.go `Close` path | Intermittent 10-minute hang of `TestAgent/ensure_retries_once_on_closing_agent`, again on main 391a49f | ⚠️ Warning | The non-required cli-windows check is red on main. Whether production `Serve` can hang the same way on exit is UNVERIFIED. Key removal comes from the keyring lifetime, not the exit, so SC2 is not blocked. Owner decision D1: fix via PR #41. |
| internal/winagent tests | `requireAccountPipeFree` | A real keyroster agent on the account pipe fails `go test ./...` on a developer's Windows machine | ℹ️ Info | Environmental; the guard message is clear |
| internal/directory/directory_test.go | TestValidateLinear | Absolute 1 s timing bound | ℹ️ Info | Recorded in deferred-items.md (D1 row) |
| internal/signer/log_test.go | TestCheckLogAgainstLiveSigner | ~1/40 `clock_regression` flake under -race in WSL | ℹ️ Info | Recorded in deferred-items.md (02-03 row) |

## Human Verification (as raised by the verifier; all three resolved on 2026-10-23, see the end of this report)

### 1. macOS real-browser login (SC2, AUTH-03, PLAT-05): closed UNVERIFIED by owner override

**Test:** On a Mac, run `keyroster init`, then `keyroster login` with Safari or Chrome and any passkey. Compare fingerprints, approve, and ssh to a stock OpenSSH host with the certificate. Then run a `--ttl 5m` login with timed `ssh-add -l` listings.
**Expected:** The same fingerprint shows in terminal and page. The host journal shows `ED25519-CERT` with the serial, and an audit-verified export has the matching login_issue. The 5 m certificate is gone from the agent within about a minute after expiry.
**Why human:** There is no Mac. CI covers the CLI against a fake server only.

### 2. Timed Windows expiry (SC2, 02-14 truth 4): done, VERIFIED

**Test:** On the Windows desktop, run `keyroster login --ttl 5m`, then `ssh-add -l` against the keyroster agent pipe, recording the time before expiry and about 1 minute after.
**Expected:** The 5 m certificate is gone within about a minute of valid_before, and the 8 h one stays.
**Why human:** The homelab listing times were not recorded. Only the unit test shows removal.

### 3. Flagged prohibitions (9): accepted by the owner, two negative tests filed as todos

**Test:** Review the five judgment-tier verdicts and the four test-tier items without a runnable enforcing test (02-10 no-password, 02-12 key-on-disk, the two 02-13 items), in the Prohibitions table.
**Expected:** Accept each, or ask for a negative test (no-password route; key never written to disk; the two 02-13 custody/RP items rest on the 02-13 attestation).
**Why human:** These are autonomous-run, non-authoritative verdicts.

## Gaps Summary

No code gap blocks the goal. The first end-to-end passkey login is achieved and independently re-proven: certificates carrying exactly the role's principals reached stock OpenSSH from Linux and Windows. The signer refuses missing, replayed and wrong-digest assertions and unsigned policy or directory, and the UI and banner meet SC5 within D-18's scope.

What remained at verification time (resolution at the end of this report):
1. **macOS** (SC2, AUTH-03, PLAT-05): the real browser and passkey leg is UNVERIFIED.
2. **Windows expiry timing**: unit-tested only.
3. **9 flagged prohibitions** for owner review.
4. **cli-windows is red on main** (known go-winio hang, PR #41 open). It is not a required check, but it should not be forgotten. (Still open after 2026-10-23; owner decision D1.)

### Override suggestions (applied 2026-10-23 by the owner: all three, "Godkänn alla tre (Rekommenderas)"; a fourth, for SC2's macOS clause, was added from the owner's macOS decision; the applied list is in the frontmatter)

At verification time the status was human_needed with or without these overrides, because items 1-3 above remained. The first two cover superseded plan truths. The third is optional: SC5 is already VERIFIED under D-18, an owner decision recorded before execution, and the override would only formalize that scope against the roadmap wording.

```yaml
overrides:
  - must_have: "cli-windows and cli-macos have run green on main since 02-02. They are added to the main-integrity ruleset, which the owner applies from the PR branch before approving"
    reason: "Owner decisions D1 (cli-macos only until go-winio PR #41 merges and cli-windows is green on main) and D2 (ruleset applied from main after the merge), recorded in deferred-items.md and 02-14-SUMMARY deviations 10-11"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
  - must_have: "keyroster audit verify of the exported homelab log prints OK anchored on bundle v3 under pins C and D, and counts the directory installs"
    reason: "audit verify anchors on the first bundle whose root set matches the pins; C and D became the root set in v2, so the anchor is v2 with bundle v3 in force (deferred-items.md 02-13 row; re-run by the verifier: ok, bundle_version 3, anchor_bundle_version 2)"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
  - must_have: "SC5: when the CA runs on an encrypted software key, every CLI command shows a loud evaluation-only warning"
    reason: "D-18 scopes the CLI warning to commands that talk to the server or signer, the only commands that can learn custody; offline commands (root, trust verify, audit verify, version) cannot know it"
    accepted_by: "<owner>"
    accepted_at: "<ISO timestamp>"
```

---

_Verified: 2026-10-23_
_Verifier: Claude (gsd-verifier)_

## Owner decisions and resolution (2026-10-23)

Applied by the orchestrator after the owner answered the verifier's open items. The verifier did not re-run: `covered_digest` is unchanged, and no covered file was edited. The choices are recorded verbatim.

| # | Item | Owner's choice | Effect |
|---|---|---|---|
| 1 | The three override suggestions | "Godkänn alla tre (Rekommenderas)" | 02-14 truth 9 (cli-windows required) replaced by D1; 02-13 truth 8 (anchor v3) is v2 by design; SC5 "every CLI command" read through D-18 as every command that talks to the server (or the signer, for `ca issue`). All three are PASSED (override). |
| 2 | macOS real-browser leg | "Stäng med macOS UNVERIFIED (Rekommenderas)" | Phase 2 closes with the macOS leg UNVERIFIED (no Mac available). Recorded as an override of SC2's macOS clause. AUTH-03 and PLAT-05 stay Pending (partially met) in REQUIREMENTS.md. |
| 3 | Timed Windows expiry | "Kör testet nu (Rekommenderas)" | The run was done; see below. 02-14 truth 4 and SC2's Windows clause are VERIFIED. |
| 4 | The 9 flagged prohibitions | "Acceptera, lägg till tester senare (Rekommenderas)" | The verifier's evidence for the five judgment-tier and four test-tier items is accepted. Negative tests for 02-10 (no non-passkey sign-in route) and 02-12 (no file write of the ephemeral key in the login path) are pending todos. |
| - | MVP goal format (advisory 1) | Orchestrator follows the Phase 1 precedent | Verified the normal way plus the User Flow Coverage table; the goal was not rewritten as a user story. |

### Timed Windows expiry from a cold start (human verification item 2)

Evidence is in the owner's evidence directory, outside the repository (`windows-expiry-run.txt`, UTF-16; the export `homelab-after-wincold.export`; `verify-wincold.json`). The orchestrator re-read each file before writing this.

- **Procedure.** The owner stopped the keyroster agent (cold start; owner-run step, its output not captured), ran `keyroster.exe login --ttl 5m` with 02-13's Windows build, and listed the keyroster agent with the inbox `ssh-add -l` every 5 s with timestamps.
- **Certificate.** Serial 1792752977539626, key `SHA256:rBi3Z86U...`, principals exactly `role:homelab-admin`, directory v6, policy v2. In the signer's export it is the login_issue at index 17: valid_after 12:51:17 and valid_before 13:01:17 CEST (server clock; issued 12:56:17, so the span is the 5 min TTL plus the 300 s backdating).
- **Audit.** `keyroster audit verify --json` with the owner's root pins and threshold and `--previous homelab-after-linux.export`: ok, 18 entries, login_issue 5, refusals 0, bundle_version 3, policy_version 2, anchor_bundle_version 2. The orchestrator re-ran it, and the output was byte-identical to `verify-wincold.json`.
- **Listings** (Daniel-PC clock):
  - The key is listed from 12:56:41.393 onward. The last listing with the key was at 13:01:13.076.
  - The first `The agent has no identities.` came at 13:01:18.103.
  - From 13:01:23.131 on, `ssh-add` cannot connect (the pipe is gone): the agent exited after its last key expired.
- **Result.**
  - The key left the keyroster agent between 3.9 s before and 1.1 s after valid_before. That is within the 5 s listing resolution, after a cold start.
  - The two clocks differ by an unmeasured skew. The CLI refuses a skew of 60 s or more and uses the measured skew for the lifetime, but the skew of this run was not recorded.
  - The run had only the one login key, because the agent was cold-started. The plan's "the 8 h one stays" expectation from the human-verification item was not exercised here; it is not part of 02-14 truth 4.
- **Review finding E-IN-02** (the lifetime is computed before the agent starts, so the key could outlive the certificate by the start delay) did not show at this resolution. It stays a code follow-up (todo `2026-10-23-recompute-agent-lifetime-before-add.md`).

### Status

All human-verification items are resolved or overridden, so the status is **passed** (`gsd-tools query verification.status` reads `passed`).

What stays open is tracked, not hidden:
- **macOS.** UNVERIFIED by override. AUTH-03 and PLAT-05 stay Pending.
- **cli-windows.** Red on main; owner decision D1, PR #41.
- **Advisory 4.** Machine names in committed files; no owner decision yet.
- **Follow-up todos.** The 8 Info findings of 02-REVIEW.md, the two negative tests, the 02-13/02-14 plan-text drift, and the needs-hardware.md Windows expiry row (it still says the times were not recorded). All are in `.planning/todos/pending/`, dated 2026-10-23.

## Post-verification changes (2026-10-23)

Main moved from 391a49f to cbdb6e8 after this report was written: Dependabot PRs #42 (actions), #37 (golang.org/x) and #41 (go-winio 0.6.4, with the one-line `errors.Is(err, net.ErrClosed)` change in `internal/winagent/winagent_windows.go`), and #55, which made `cli-windows` a required check (the live ruleset now requires 19 checks, both `cli-macos` and `cli-windows`; verified on GitHub). That closes the D1 deferral that override 1 records.

The covered-input fingerprint was regenerated with `gsd-tools query verification.fingerprint` at cbdb6e8. The verifier was not re-run: the code changes since 391a49f are dependency bumps and that one line, every PR had green CI, and `cli-windows` has been green on main since the bump. A 1000-iteration loop of the subtest that hung under go-winio v0.6.2 passed on Windows.
