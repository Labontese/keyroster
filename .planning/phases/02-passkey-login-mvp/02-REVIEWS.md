---
phase: 2
reviewers: [codex, ollama-nemotron, ollama-gemma, ollama-gptoss]
reviewed_at: 2026-10-11T05:45:00Z
plans_reviewed: [02-01-PLAN.md, 02-02-PLAN.md, 02-03-PLAN.md, 02-04-PLAN.md, 02-05-PLAN.md, 02-06-PLAN.md, 02-07-PLAN.md, 02-08-PLAN.md, 02-09-PLAN.md, 02-10-PLAN.md, 02-11-PLAN.md, 02-12-PLAN.md, 02-13-PLAN.md, 02-14-PLAN.md]
models:
  codex: "gpt-6-luna (reasoning=high)"
  ollama-nemotron: "nemotron-3-ultra:cloud"
  ollama-gemma: "gemma4:31b-cloud"
  ollama-gptoss: "gpt-oss:120b-cloud"
model_sources:
  codex: "banner"
  ollama-nemotron: "request"
  ollama-gemma: "request"
  ollama-gptoss: "request"
verification:
  method: "every finding adversarially verified by a Claude agent against plan text, CONTEXT/RESEARCH and repo source"
  findings: 250
  verdicts: {already_covered: 127, refuted: 48, partial: 72, confirmed: 3}
  surviving_by_severity: {high: 0, medium: 3, low: 72}
---

# Cross-AI Plan Review — Phase 2

<!-- gsd:plan-revision-conflicts:begin -->
## Plan-Revision Conflicts
<!-- gsd:plan-revision-conflicts:end -->

> **Reviewer caveats.** None of the four external reviewers had repo access. Codex's sandbox
> could not start a shell (Windows error 267). The Ollama models were called through the plain
> chat API. `gpt-oss:120b` (131k context) reviewed each plan separately, with project context,
> roadmap and CONTEXT.md but without RESEARCH.md or the sibling plans. Nemotron and Gemma got the
> full prompt (~160k tokens). Claude was skipped (orchestrator), Kimi had no quota, and the
> other Ollama cloud models are retired or paid-only.
>
> To make up for this, **every finding (250 after per-plan dedup) was adversarially verified**
> by a Claude agent with repo access. Read the Consensus Summary and the Verified Findings
> appendix, not the raw reviews: 70% of raw findings were already covered or wrong.

## Codex Review


**Source verification was unavailable.** The workspace reports `C:\Users\labon\ssh-cert-manager`, but every attempt to start a shell there failed with Windows error 267 (“directory not found”). I could not inspect the referenced source files or verify their line numbers. Per your instruction, source-dependent concerns below are framed as questions to resolve, not as confirmed defects. File paths identify where to check; line-level evidence is unavailable.

### 02-01

**Summary.** The tracer starts with the right security boundary: a root-signed RP policy, quorum-signed directory, and signer-verified passkey assertion, tested through real `sshd`. Its broad scope is understandable for a vertical slice, but it creates a large review and integration burden.

**Strengths**

- Leaves the Phase 1 admin issuance format unchanged.
- Computes principals and TTL limits from signer-held directory state.
- Includes a real SSH acceptance and refusal control.

**Concerns**

- **HIGH — Scope and review risk.** One plan changes policy, wire, storage, signer, audit-log formats and certificate IDs across many files. If the tracer has an architectural flaw, it can be costly to unwind.
- **MEDIUM — Oversized frame limitation.** This plan caps directory traffic at the existing frame size, while 02-03 later raises the directory cap. Confirm the tracer’s test fixtures cannot accidentally establish an inadequate permanent protocol assumption.
- **MEDIUM — Test setup may obscure authorization behavior.** The real `sshd` control/refusal depends on generating correct principals files and matching the user CA configuration. Confirm failures distinguish signer authorization from host configuration.

**Suggestions**

- Define stable format vectors for the directory, login request, log leaves and key IDs before implementation.
- Make the e2e test assert the issued certificate’s principals, TTL, key and audit leaf directly, in addition to the SSH outcome.

**Risk Assessment.** **HIGH** — This plan establishes several durable security formats in one very large change.

### 02-02

**Summary.** Probing Windows agent behavior before implementation is a strong sequencing choice, and the in-memory agent addresses the stated lifetime and persistence constraints. The pipe ownership and lifecycle mechanisms need careful validation on the actual Windows interfaces.

**Strengths**

- Gates implementation on real inbox OpenSSH behavior.
- Explicitly disallows falling back to the persistent inbox agent or dropping lifetime constraints.
- Includes pipe ACL, owner verification and real-client offer tests.

**Concerns**

- **HIGH — Pipe ownership check.** Verify the planned handle-to-server-PID flow works with the concrete `go-winio` connection type and cannot be bypassed by a raced or replaced pipe. The relevant locations are `internal/winagent/owner_windows.go` and `ensure_windows.go`.
- **MEDIUM — Agent shutdown semantics.** The plan polls `keyring.List()` to expire keys and exits when empty. Confirm active SSH connections and concurrent additions cannot cause premature shutdown or keep the process alive indefinitely.
- **MEDIUM — Probe coverage.** A successful `ssh-add` and `ssh` offer proves the pipe spelling, but confirm the test also proves the expected certificate identity and expiry behavior under the exact CLI path.

**Suggestions**

- Test pipe replacement and connection races around `Ensure`, not only a pre-existing pipe.
- Record the SID and pipe security descriptor behavior in tests without embedding machine-specific account details.

**Risk Assessment.** **HIGH** — The Windows agent is security-sensitive process and IPC code, and the plan’s core assumption depends on platform-specific behavior.

### 02-03

**Summary.** This hardening plan covers refusal paths, concurrency, restart verification, frame caps and fuzzing. It is essential to the signer boundary, though its scope is unusually broad and relies on precise synchronization and log-state checks.

**Strengths**

- Tests refusal cases with successful controls.
- Checks directory authority again after policy changes and detects DB/log disagreement at startup.
- Adds per-message size limits before allocation and fuzzes new parsers.

**Concerns**

- **HIGH — Concurrency guarantees need precise transaction boundaries.** Confirm locking and DB uniqueness jointly cover request replay, directory installation and the directory-change check. The named tests alone do not prove there is no authorization-to-commit race.
- **MEDIUM — Frame parser boundary.** The plan changes framing to read type before applying a per-type cap. Confirm malformed or truncated headers cannot cause excess allocation or inconsistent read/write limits.
- **MEDIUM — Large test matrix.** A single plan includes integration refusal tests, signer races, log consistency, frame changes and numerous fuzz targets. Failures may be difficult to localize.

**Suggestions**

- Specify the exact lock and transaction ordering for login issuance versus directory install.
- Test adversarial frame lengths at zero, header-only, cap, cap+1 and integer-boundary values.

**Risk Assessment.** **HIGH** — This plan hardens the most consequential authorization and concurrency paths.

### 02-04

**Summary.** Re-proving login authorization from exported logs is a strong complement to signer enforcement. The main risk is correctness of the audit state machine across bundle and directory successors, rather than the individual signature checks.

**Strengths**

- Verifies the login request, assertion, directory grant, certificate and key ID together.
- Includes tampering with checkpoints re-signed by the log key.
- Keeps earlier log kinds in scope and documents older-verifier incompatibility.

**Concerns**

- **HIGH — Historical policy/directory semantics.** Confirm the audit walk uses exactly the policy and directory in force at each leaf, including after policy successor installs and CA rotation.
- **MEDIUM — Certificate validity reconstruction.** “What `cert.Build` produces” needs a deterministic rule for timestamps, backdating and rounding so valid certificates do not fail audit or malformed ones pass.
- **MEDIUM — Audit state retention.** The verifier must preserve enough prior policy/directory state to validate later entries without trusting mutable current-state data.

**Suggestions**

- Add explicit multi-successor fixtures: policy change, directory change, then login, with old and new CA material as applicable.
- Make tamper errors identify the entry and the exact failed binding, as the plan requires.

**Risk Assessment.** **HIGH** — Audit verification is a core promise of the product; subtle timeline errors could either accept unauthorized issuance or reject valid logs.

### 02-05

**Summary.** The software-key backend and signer-originated custody status cover the evaluation-only path without making hardware mandatory. Passphrase handling and key-file creation need especially careful scrutiny.

**Strengths**

- Makes custody a signer-reported property rather than server configuration.
- Defines concrete refusal tests for weak passphrase setups and edited key files.
- Shares one banner string between code and documentation.

**Concerns**

- **HIGH — Secret lifecycle and filesystem safety.** Confirm the passphrase buffer is cleared on every error path, file creation is atomic, symlinks are refused, and directory ownership/permissions are checked—not just requested at creation.
- **MEDIUM — Passphrase policy.** A 20-rune minimum and protected passphrase file do not ensure a strong passphrase; document the security limitations of the evaluation backend.
- **MEDIUM — Status surface.** Status returns bundle and policy material as well as custody. Confirm access controls and per-type frame caps cover this expanded response.

**Suggestions**

- Test symlink substitution, partial writes, existing directories with permissive modes, and cleanup after provisioning failure.
- State clearly whether decryption happens once at startup or repeatedly, and ensure errors never reveal sensitive input.

**Risk Assessment.** **HIGH** — This adds an online CA key backend and a new signer protocol response containing trust state.

### 02-06

**Summary.** The server core has a clear “untrusted front end” role, with strict headers, pinned TLS roots, signer-sourced RP configuration and deployment hardening. The trust-on-first-initialization flow and the service’s access to the signer socket deserve close review.

**Strengths**

- Keeps RP identity in the signer’s root-signed policy.
- Provides TLS certificate reload with last-good behavior.
- Includes real-binary tests, security headers and a hardened systemd unit.

**Concerns**

- **HIGH — TLS pin bootstrap.** The first `keyroster init` must establish TLS root pins out of band. Confirm the UI and CLI never treat observed pins as trusted until the user has checked them against an independent source.
- **HIGH — Signer socket privilege.** Membership in `keyroster-admin` permits socket access. Confirm every new signer operation remains safe for a compromised server process and does not accidentally gain administrative authority.
- **MEDIUM — Root-chain portability.** The plan stores only roots observed during init; verify behavior when Windows, Linux and macOS build different valid chains, and when the server’s root changes.
- **MEDIUM — Health status freshness.** The 5-second cache and 60-second stale cutoff should be consistent across health checks, UI rendering and trust responses.

**Suggestions**

- Specify exactly how an operator delivers expected TLS root pins to clients, including rotation and recovery.
- Test certificate reload while handshakes are concurrent and ensure an invalid replacement cannot displace a valid certificate.

**Risk Assessment.** **HIGH** — This plan introduces the network-facing process, TLS bootstrap and core client trust configuration.

### 02-07

**Summary.** SSHSIG-authenticated admin requests and non-authoritative pending rows are consistent with the project’s trust model. Replay handling, invite state and rate-limit behavior require transactional and privacy checks.

**Strengths**

- Authenticates request payloads, not merely the transport or socket.
- Stores invite hashes rather than raw tokens.
- Explicitly proves that `user add` does not alter signer authority.

**Concerns**

- **HIGH — Nonce consumption and handler execution.** Confirm nonce insertion is atomic with the authenticated action or that consuming a nonce before a later DB failure has acceptable retry semantics.
- **MEDIUM — Reinvitations and existing users.** The plan allows reinviting a user in the installed directory for an additional credential. Confirm user-handle continuity and concurrent reinvite/registration behavior.
- **MEDIUM — Rate-limit memory.** The limiter is bounded, but confirm eviction does not let an attacker cycle IP keys to evade limits or grow state beyond the cap.

**Suggestions**

- Add tests for concurrent use of the same nonce and concurrent reinvites.
- Ensure all logs and error paths redact invite tokens, signatures and user handles.

**Risk Assessment.** **MEDIUM** — The authority model is sound in outline, but server-side state races and retry behavior need definition.

### 02-08

**Summary.** Registration is cleanly separated from credential binding, and owner review before dependency installation is appropriate. The registration flow’s one-use invite semantics and the credential conversion boundary need focused tests.

**Strengths**

- Keeps go-webauthn and CBOR/JWT dependencies out of the signer.
- Reuses the signer’s SPKI acceptance rules after registration parsing.
- Explicitly compares fingerprints between invitee and admin.

**Concerns**

- **HIGH — Concurrent registration against one invite.** Multiple begin sessions may race to finish against the same invite. Confirm the database transaction guarantees at most one pending credential and one successful invite consumption.
- **MEDIUM — Credential conversion.** Confirm algorithm identifiers and public-key types cannot disagree during COSE-to-SPKI conversion, especially for RSA and EdDSA.
- **MEDIUM — Differential oracle scope.** The claimed agreement with go-webauthn depends on parsing equivalent inputs and matching verification options. Ensure the oracle does not compare different policy defaults.

**Suggestions**

- Add concurrent finish tests using the same invite and credential ID.
- Test exact boundary key sizes, malformed COSE structures and conflicting credential metadata.

**Risk Assessment.** **HIGH** — Registration introduces a third-party parser and creates credentials that later become signer authority.

### 02-09

**Summary.** The verified-base edit pipeline and fingerprint-required approval are strong controls for directory changes. Proposal handling and server cleanup after installation are the main areas to validate.

**Strengths**

- Verifies trust and directory signatures locally before signing changes.
- Displays a diff and requires confirmation or explicit `--yes`.
- Addresses duplicate, empty, repeated and concurrent approvals.

**Concerns**

- **HIGH — Proposal co-signing integrity.** Confirm `directory sign` verifies the exact proposal bytes and every existing signature, and that appending signatures cannot change the document or base hash.
- **MEDIUM — Pending cleanup semantics.** The plan deletes bound credentials and some pending users only after install. Confirm cleanup is transactional and does not remove unbound credentials or erase a user’s ability to enroll another credential.
- **MEDIUM — CLI confirmation.** `--yes` bypasses the prompt. Ensure the displayed diff and signed bytes are the same canonical document, with no later mutation.

**Suggestions**

- Add tamper tests for proposal files between `sign` and `install`, including altered base hash and reordered signatures.
- Document how admins transfer proposal bundles safely and recover from stale proposals.

**Risk Assessment.** **HIGH** — The pipeline controls identity and role authority, and proposal workflows are easy to get subtly wrong.

### 02-10

**Summary.** Passkey-based web sign-in and a read-only account page fit the phase boundary. The session model is sensible, but session invalidation depends on the freshness and consistency of the directory mirror.

**Strengths**

- Uses the installed directory rather than pending server rows.
- Stores only a hash of the opaque session ID and sets a `__Host-` cookie.
- Includes idle, absolute, logout and disabled-user expiry behavior.

**Concerns**

- **HIGH — Directory freshness and revocation.** A user disabled in the signer may retain a session until the server mirror refreshes. Confirm the maximum propagation delay and fail-closed behavior.
- **MEDIUM — Session touch semantics.** Verify `TouchSession` enforces both idle and absolute expiry atomically and cannot extend an expired session.
- **MEDIUM — Username rate limits.** User-controlled identifiers can multiply limiter entries unless the per-user map is bounded and normalized.

**Suggestions**

- Include tests where signer status becomes unavailable and the directory changes between session lookup and rendering.
- Avoid exposing role details for a session whose directory version is stale or unauthorized.

**Risk Assessment.** **MEDIUM** — The session is read-only, limiting impact, but stale authorization data could misrepresent current access.

### 02-11

**Summary.** The shared renderer and signed role/group/host-group edits support the promised principal mapping. The plan’s host-group semantics and empty-principals behavior need clarification before implementation.

**Strengths**

- Reuses one renderer for manual configuration and the future agent.
- Routes all mutations through the verified-base signing pipeline.
- Tests real `sshd` acceptance and refusal.

**Concerns**

- **HIGH — Host-group meaning at issuance.** Certificates are intentionally not host-scoped, while host groups only render accepted principals. Confirm users understand that a certificate may be valid on any host accepting one of its principals.
- **MEDIUM — Empty account mapping.** After `unmap`, `host principals` is specified to fail for an unknown account, yet the e2e expects an empty principals file to test refusal. The plan should define how an existing account with zero mapped roles is represented and rendered.
- **MEDIUM — Update flags.** “Given lists replace the old ones” does not specify how callers clear a principal, extension, user or group list without supplying a replacement.

**Suggestions**

- Define empty mappings separately from unknown accounts and test both outcomes.
- Provide explicit clear/reset flags or a documented replacement syntax for role updates.

**Risk Assessment.** **MEDIUM** — The authorization model is coherent, but host enforcement and CLI mutation semantics are underspecified.

### 02-12

**Summary.** The plan combines the final browser-to-signer path with certificate verification and agent insertion, and correctly makes redemption the issuance boundary. It is the most security-sensitive end-to-end flow and needs careful treatment of one-time state and agent lifetime precision.

**Strengths**

- Shows the fingerprint before WebAuthn and binds it to request bytes.
- Mints only at redemption and binds code, verifier, state and login ID.
- Verifies the returned certificate before adding it to an agent.

**Concerns**

- **HIGH — Redemption consumes code before signing.** The plan says `RedeemLogin` transitions to redeemed before calling the signer. If signing or the connection fails, the user cannot retry and may not know whether issuance occurred. Define safe recovery without enabling duplicate issuance.
- **HIGH — Lifetime rounding.** `ValidBefore − now` is converted to agent lifetime seconds. Confirm rounding cannot make the key outlive the certificate; flooring can also produce a zero/short lifetime near expiry.
- **MEDIUM — Callback code exposure.** The code is placed in a loopback URL query. Ensure callback responses, browser history, access logs and error pages do not retain or expose it.
- **MEDIUM — Cross-platform flow test.** The Windows in-memory agent and Unix `ssh-agent` adapters differ; verify the fake-server test exercises the actual adapter on each OS.

**Suggestions**

- Specify idempotent redemption outcomes and how the CLI handles “signer issued but response lost.”
- Add boundary tests around certificate expiry and the minimum remaining-validity check.

**Risk Assessment.** **HIGH** — This plan joins WebAuthn approval, a network protocol, the signer and local private-key handling.

### 02-13

**Summary.** This is a substantial operational rollout with appropriate one-way hostname and rollback checkpoints. It also combines live signer migration, trust-root signing, service deployment and passkey enrollment, so checkpoints and stop conditions are important.

**Strengths**

- Requires owner confirmation of the RP hostname before signing.
- Backs up signer state and binaries before applying the migration.
- Compares policy fields and bundle hashes across rehearsal, verification and installation.

**Concerns**

- **HIGH — Live migration recovery.** The backup is useful, but confirm rollback covers both DB schema and installed bundle state, and that the old binary can safely reopen the restored copy.
- **HIGH — Root signing environment.** `unshare -r -n` is intended to isolate the rehearsal; verify all signing inputs and executable dependencies are present and that no network path remains.
- **MEDIUM — Operational sequencing.** Server startup, TLS timer, owner init and invite creation span multiple hosts and credentials. A partial failure needs a clear resume point that cannot accidentally sign or install a second successor.

**Suggestions**

- Add a step-by-step rollback and resume table for failures after v3 installation and before enrollment.
- Verify backups by listing metadata and hashes without exposing private material.

**Risk Assessment.** **HIGH** — It changes live trust state and binds the first passkey to a permanent RP identity.

### 02-14

**Summary.** Real-browser and real-`sshd` verification is the right final proof, and the plan avoids claiming macOS coverage without hardware. The operational host change and evidence correlation need robust rollback and identity matching.

**Strengths**

- Corroborates logins with both audit records and `sshd` journals.
- Checks a pre-existing key login before and after the host configuration change.
- Explicitly leaves macOS unverified and avoids marking broad platform requirements complete.

**Concerns**

- **HIGH — Host lockout and stale access.** A correct syntax check does not prove the effective `Match` configuration or principals file is correct for the target account. Ensure effective config is checked with the connection context before relying on certificate login.
- **MEDIUM — Journal correlation.** Matching key IDs and serials should also verify timestamp, CA and target account to avoid associating unrelated logins.
- **MEDIUM — Expiry duration.** A 5-minute certificate followed by a six-minute wait is reasonable, but agent process shutdown and key removal should be separately verified.
- **MEDIUM — Requirement completion.** The plan deliberately keeps AUTH-03 and PLAT-05 pending because macOS is unverified. Confirm roadmap and requirements status remain consistent with that decision.

**Suggestions**

- Keep a second authenticated session open during the sshd change and verify the effective config with `sshd -T -C` for the target connection.
- Record exact audit/journal matching fields while omitting hostnames and addresses from committed summaries.

**Risk Assessment.** **HIGH** — The final validation changes a live SSH host and produces the evidence used to claim the phase goal.

### Cross-plan assessment

The sequence is broadly sensible: signer authority first, platform probes early, audit proof before the full login path, and real homelab evidence last. The largest cross-plan risks are:

- The signer protocol, directory and audit formats are introduced across 02-01 through 02-04, before the UI and enrollment flows exist. Their compatibility and migration behavior should be treated as a single review surface.
- Login redemption and registration both have single-use server state. Their failure and retry semantics should be settled explicitly before implementation.
- Several plans depend on server directory/status mirrors. Define one freshness contract and make session invalidation, login options and custody reporting follow it.
- The 14-plan sequence is unusually large for an MVP. The per-plan PR gates help, but the very large tracers may still make security review difficult.

**Overall risk: HIGH.** The plans emphasize strong controls and meaningful end-to-end evidence, but the scope spans new cryptographic formats, signer state, a public-facing server, platform-specific agents and live trust operations. Repository source verification remains outstanding because of the workspace access failure.

---

---

## Ollama nemotron-3-ultra Review

### 02-01

#### Summary
This is the phase tracer plan that proves the entire security core end-to-end: root-signed policy with WebAuthn RP → admin-signed directory installed online → passkey assertion over LoginIssueRequest → kr2 certificate → real sshd login via AuthorizedPrincipalsFile. It builds `internal/webauthn` (stdlib-only verifier), `internal/directory` (canonical document with quorum verification), new wire types, log kinds 7/8, and key ID `kr2`. The admin path (`IssueRequest`, `TypeIssueRequest` 0x01, `keyroster/issue-request/v1`) is explicitly kept byte-for-byte unchanged.

#### Strengths
- True tracer: crosses every signer layer the phase touches at least once, ending at real sshd accept/refuse
- Clear separation: `internal/webauthn` and `internal/directory` are signer-safe (stdlib only), added to depguard list
- WebAuthn assertion verified entirely in signer with stdlib crypto; CBOR/COSE parsing stays in server via go-webauthn (D-17)
- Directory install is online (no signer restart), with successor chain and quorum verification against policy in force
- Signer computes principals and TTL cap from installed directory, not from request (D-08)
- Login certificates logged with full request signing bytes, enabling audit re-verification (Pattern 5)
- Policy RP fields added as `omitempty` pointer, preserving byte-identical round-trip for installed v1 policies (Resolved Q4)
- Comprehensive must_haves truths covering policy validation, directory canonicalization, evidence verification, authorization, and e2e sshd test

#### Concerns
- **HIGH**: Plan lists 32 files modified (above 15-file threshold) and 140k tokens. While justified as a tracer, the sheer scope increases review burden and merge risk. The split points examined (moving directory install or verifier to separate plans) were rejected correctly for tracer-first principle, but the PR will be massive.
- **HIGH**: `internal/signerdb/migrations/0004_directory.sql` adds a `directory` table but the plan doesn't specify how this interacts with existing trust_bundle migrations or whether migration ordering is tested.
- **MEDIUM**: The `LoginIssueRequest` uses its own domain `keyroster/login-request/v1` but reuses `TypeIssueResponse` 0x81. Need to verify the response parsing doesn't conflate admin and login responses.
- **MEDIUM**: `internal/webauthn/clientdata.go` uses `encoding/json` v1 Token API (since json/v2 requires Go 1.27). Must ensure the token walk correctly handles all browser quirks (extra keys, duplicate names, invalid UTF-8) without panicking.
- **MEDIUM**: Soft authenticator in `internal/webauthn/webauthntest` generates ES256/EdDSA/RS256 assertions. Need to confirm RS256 key generation uses ≥2048-bit modulus and that the test covers Windows Hello's RS256 requirement.
- **LOW**: `audit verify` refuses logs with kinds 7/8 until 02-04 — this interim gap should be explicitly documented in the SUMMARY as a known limitation.

#### Suggestions
- Add a unit test that an installed v1 policy (without webauthn field) parses, re-encodes byte-identically, and a v2 policy with `"webauthn":null` is refused as non-canonical
- Add a test that `ParseLoginIssueRequest` refuses a request carrying `admin-sshsig/v1` evidence and vice versa
- In `test/e2e/login_signer_test.go`, assert the exact refusal detail for the `u:other` account (should be principal mismatch at sshd level, not signer level)
- Consider extracting the soft authenticator into a separate test-only module to make `go list -deps` checks cleaner

#### Risk Assessment: MEDIUM-HIGH
The plan is architecturally sound and addresses the riskiest questions first (signer-side WebAuthn verification, online directory install, kr2 key ID). However, the large scope (32 files, 140k tokens) and the fact that this is the first plan in the phase mean any design flaw here propagates to all subsequent plans. The tracer approach is correct but the PR will need exceptionally careful review.

---

### 02-02

#### Summary
This plan settles the Windows agent question (D-15 option A) by building keyroster's own in-memory agent on a per-user named pipe, since the inbox Win32-OpenSSH agent refuses lifetime constraints and persists keys to the registry. It starts with gating probes (A2: inbox ssh.exe honors named pipe in IdentityAgent/SSH_AUTH_SOCK; A3: GNOME gcr-ssh-agent honors lifetime + certificates), then builds `keyroster agent`, the go-winio dial for admin signing, and adds Windows/macOS CI jobs.

#### Strengths
- **Critical**: Probes assumptions A2 and A3 *before* writing any agent code — if probes fail, plan stops at blocking-human checkpoint with no silent fallback
- Owner decision D-15 option A is enforced: never uses inbox agent for login keys, never retries without lifetime constraint
- Pipe squatting guard: `VerifyServerOwner` checks server process SID matches caller SID before sending keys
- SDDL on pipe grants only current user SID, denies network logons
- Agent exits after last key expires or 5 min idle — keys never persist across reboots
- Admin SSHSIG signing on Windows still uses inbox agent (correct — signing needs no constraint)
- CI jobs for Windows/macOS added but NOT made required yet (respects Pitfall 10/11)
- go-winio v0.6.2 linked only into Windows CLI build; signer graph unchanged

#### Concerns
- **HIGH**: Assumption A2 (inbox ssh.exe honors named pipe in IdentityAgent) is UNVERIFIED until Task 1 probe runs. If it fails, the entire Windows login path (AUTH-03 on Windows) is blocked. The plan correctly stops at a blocking-human checkpoint, but this is a critical path risk.
- **HIGH**: Assumption A3 (gcr-ssh-agent honors lifetime + certificates) is also unproven. If it fails, Linux laptop login may need fallback to plain ssh-agent. The plan moves this to 02-12 if unreachable, but the decision impacts user experience.
- **MEDIUM**: `internal/winagent/ensure_windows.go` starts `keyroster.exe agent` detached. Need to ensure the executable path is correct when installed via systemd vs. manual copy, and that the agent process is properly cleaned up on CLI exit/crash.
- **MEDIUM**: The probe uses a throwaway Go module in scratchpad — must ensure no probe artifacts leak into the repo (verified by `git status --porcelain` check).
- **LOW**: `TestInboxSSHOffersAgentCert` requires `KEYROSTER_REQUIRE_INBOX_SSH=1` to fail on missing inbox ssh. This pattern from Phase 1 is good but must be documented for CI maintainers.

#### Suggestions
- In the probe, also test `ssh.exe -o IdentityAgent=<pipe>` with a certificate to verify the cert is offered, not just the key
- Document the exact pipe spelling that works (`\\.\pipe\keyroster-probe-<hex>` vs `//./pipe/keyroster-probe-<hex>`) in the SUMMARY
- Add a test that `winagent.Serve` refuses a second instance on the same pipe path (already in winagent_windows_test.go)
- Ensure `go list -m github.com/google/go-tpm` is recorded before/after `go get go-winio` to catch transitive version drift

#### Risk Assessment: HIGH
This plan addresses the single biggest platform risk (Windows agent behavior) with appropriate gating probes. However, both probes target unverified assumptions about third-party behavior (Microsoft's inbox OpenSSH, GNOME's gcr-ssh-agent). If either probe fails, the phase's AUTH-03/PLAT-05 on that platform is at risk. The blocking-human checkpoints are the correct mitigation.

---

### 02-03

#### Summary
Hardens the signer boundary from 02-01: SC4 refusal suite through real socket with controls, named refusal matrix for every new detail, concurrency guarantees, restart re-verification of directory under new policy, log-consistency check on start, GetDirectory for server mirror, per-type frame caps, and fuzz targets for all new parsers.

#### Strengths
- **Excellent**: Every refusal case has a succeeding control (Phase 1 rule from 01-04) — prevents false positives from unrelated failures
- SC4 policy clause tested at unit level: a policy successor not root-signed never enables login, even after restart
- Evidence types cannot be mixed: login request with admin evidence refused, admin request with WebAuthn evidence refused
- Concurrency tested under `-race`: 16 identical login requests → 1 cert + 15 duplicate_request; 2 concurrent installs → 1 success + 1 chain failure
- Restart under new admin set: directory becomes unauthorized until re-signed by new admins
- Log consistency: signer refuses start if stored directory ≠ last directory_install leaf
- GetDirectory returns installed directory + sigs + authorized state for server mirror
- Per-type frame caps: 64 KiB for issue/login, 1 MiB+ for directory (prevents OOM on large directories)
- 11 fuzz targets covering all new parsers (wire, webauthn, directory, cert, tlog)

#### Concerns
- **HIGH**: The SC4 e2e test `TestLoginRefusals` has 6 subtests but the `policy_without_rp` case boots a second signer. Need to ensure the test infrastructure supports multiple concurrent signers cleanly.
- **MEDIUM**: `policy_not_root_signed` test constructs a successor policy with RP but signed by a fresh key r2. Must verify this doesn't inadvertently test the wrong failure mode (should be `trust.ErrThreshold` at install, then `no_webauthn_policy` at login).
- **MEDIUM**: Per-type caps in `ReadMessage` read 4-byte length + 2-byte header, then check `length - 2 > maxBodyFor(type)` before allocating body. Must ensure this doesn't break existing `ReadFrame`/`WriteFrame` callers if any exist outside package wire.
- **MEDIUM**: `internal/tlog` test that `wire.MaxDirectory == tlog.MaxDocument` — if these diverge, directory installs could be truncated or rejected inconsistently.
- **LOW**: Fuzz targets use `FUZZTIME=10s` locally but CI may need longer. The `scripts/fuzz.sh` auto-discovers targets — confirm CI timeout is adequate.

#### Suggestions
- Add a test that `GetDirectory` returns version 0, empty directory, empty sigs, authorized=false when no directory installed
- In `internal/signer/directory.go`, the `loadDirectory` re-verification under new policy should log the policy version that caused authorization loss
- Document the exact memory bound: 32 connections × MaxDirectoryFrame (1 MiB + 64 KiB) ≈ 34 MiB worst case
- Ensure `scripts/fuzz.sh` runs all 11 new targets in CI and fails if any target crashes

#### Risk Assessment: LOW-MEDIUM
This plan systematically hardens the signer boundary with comprehensive refusal testing, concurrency guarantees, and fuzzing. The architecture is solid (message-type-separated evidence paths, per-type caps, log-consistency checks). Main risk is test infrastructure complexity for multi-signer e2e tests, but the patterns are established from Phase 1.

---

### 02-04

#### Summary
Makes every login certificate provable after the fact: `keyroster root successor-policy` adds RP to running installation; `keyroster audit verify` verifies new log kinds (directory_install, login_issue) by re-proving passkey authorization, principals, TTL, and certificate binding from logged data. Includes tamper suite where checkpoints are re-signed but authorization checks still catch manipulation.

#### Strengths
- **Core value delivery**: Audit verify now proves each login certificate was approved by the user's bound passkey under quorum-signed directory — a compromised signer holding the log key cannot fake this
- `keyroster root successor-policy` is the only supported way to add/change RP, with explicit one-way warning
- Live e2e `TestAuditLoginAcrossPolicyChange`: RP-less policy → successor-policy → root sign → install+bundle → restart → login → export → audit verify OK
- Tamper suite: 11 cases covering assertion bit-flip, principals widened, other user's credential, directory never installed, non-admin directory sig, chain broken, role TTL above cap, kr2 roles mismatch, cert key mismatch, CreatedAt skew, login under unauthorized directory
- Each tampered log has checkpoints re-signed with test log key — only new authorization checks catch it
- Phase 1 exports (kinds 1-6) still verify unchanged
- Runbook documents policy-change procedure with RP warning

#### Concerns
- **HIGH**: `internal/audit/verify.go` must re-run `webauthn.VerifyAssertion` on logged evidence. The logged evidence includes the full assertion blob. Need to ensure the assertion blob in the log is exactly what the signer verified (no server-side transformation).
- **HIGH**: `ParseLoginIssueSigningBytes` parses the stored request bytes without evidence section. Must handle the case where the stored request was built by a different CLI version (forward compatibility).
- **MEDIUM**: Audit verify requires the directory in force at each leaf to verify under the policy in force at that leaf. The signer's `directory_not_authorized` rule (re-verify after policy change) must be mirrored exactly in audit — any divergence creates a gap.
- **MEDIUM**: `keyroster root successor-policy` refuses no-op (RP unchanged). But what if origins change? The plan says origins default to `https://HOST` but `--webauthn-origin` is repeatable. Should allow origins change without RP change.
- **LOW**: Compatibility note: Phase 1 `audit verify` binaries refuse logs with kinds 7/8 (unknown kind). This fails closed but should be clearly communicated.

#### Suggestions
- Add a test that audit verify accepts a login_issue entry where the directory was re-verified after a policy change that didn't affect its authorization (e.g., RP added, admin set unchanged)
- In `cmd/keyroster/root.go`, allow `successor-policy` to change origins without changing RP (separate flag or allow `--webauthn-origin` without `--webauthn-rp-id` when RP exists)
- Ensure the tamper suite includes a case where the log key is compromised but the root keys are not — the audit should still pass for valid entries and fail only for tampered ones

#### Risk Assessment: LOW
This plan closes the audit gap from 02-01 and delivers on the core value (full visibility). The tamper suite with re-signed checkpoints is a strong validation. The successor-policy tool is a necessary operational capability. Low risk because it builds on proven Phase 1 audit infrastructure.

---

### 02-05

#### Summary
Implements KEY-06: encrypted software CA keystore backend for evaluation, with loud warning in CLI and UI. Adds `internal/keystore/software` (age-encrypted keys), signer `Status` message reporting custody per role, shared banner constant in `internal/custodytext`, and `keyroster ca issue` prints banner when any key has software custody. Owner approves banner wording at checkpoint.

#### Strengths
- Software backend mirrors root ceremony pattern (age scrypt, armored files, 0600 in 0700) but without importing `internal/rootceremony` (KEY-07 import rule)
- Passphrase sources: `--passphrase-file`, `$CREDENTIALS_DIRECTORY/keyroster-software-passphrase` (systemd LoadCredential), never argv/env
- Passphrase validation: ≥20 runes, file mode 0600, buffer cleared after use
- Custody reported by signer's `Status` (D-18) — CLI and UI read from signer, never from config
- `keyroster ca issue` calls `Status` first, prints framed banner to stderr before issuing
- Banner text is one Go constant; `docs/security/custody.md` quotes it verbatim (enforced by test)
- capslock baseline updated for age/scrypt packages; piv target explicitly re-deferred
- e2e `TestSoftwareCAEndToEnd` verifies banner presence on software signer and absence on agent-backend control

#### Concerns
- **HIGH**: The banner wording checkpoint (Task 2) is a blocking-human decision. If the owner delays or rejects, the plan stalls. The proposed text is long for a terminal line — may need truncation for narrow terminals.
- **MEDIUM**: `internal/keystore/software` registers backend `software` via blank import in `cmd/keyroster-signer/backends_linux.go`. Must ensure this doesn't pull age/scrypt into the signer graph unexpectedly (dep-firewall and capslock should catch this).
- **MEDIUM**: `Status` response includes `BundleVersion`, `Bundle`, `BundleSigs`, `Policy`, `PolicySigs`, `DirectoryVersion`, `DirectorySHA256`, `DirectoryAuthorized`. This is a large response — confirm `MaxStatusFrame = 256 KiB` is sufficient.
- **LOW**: The plan says "doctor already has `CodeSoftwareKey = 'software_key'`" — verify this constant exists and the warning matches the banner style.

#### Suggestions
- In the banner constant, consider a shorter form for terminal: `EVALUATION ONLY - SOFTWARE CA KEYS (custody: software). Do not use for real access. See docs/security/custody.md`
- Add a test that `Status` reports correct custody after a key rotation (KEY-08, future) — not needed now but good to design for
- Ensure `internal/custodytext` imports only stdlib (verified by dep-firewall)

#### Risk Assessment: LOW
Well-scoped plan implementing a clear evaluation-only feature with strong safeguards (custody from signer, no suppression, verbatim doc quote). The owner wording checkpoint is appropriate for a user-facing security message. Low technical risk.

---

### 02-06

#### Summary
Stands up `keyroster-server` (Linux-only binary) and `keyroster init`: HTTPS from operator-provided cert/key with reload, strict STACK.md headers + `connect-src 'self'`, server-rendered embedded UI, evaluation banner driven by signer's custody, `/api/v1/trust` endpoint verified by init against TLS root pins and trust-root pins, systemd units, Tailscale cert timer, server install runbook.

#### Strengths
- **Security-first**: RP ID and origins come ONLY from signer's Status (root-signed policy), never from server config — server refuses start without RP
- Strict headers on every response including errors/static: CSP, HSTS, COOP, nosniff, Referrer-Policy no-referrer, Cache-Control no-store, CrossOriginProtection
- Server-rendered with `html/template` + `embed`, no npm, no inline script/style
- `keyroster init` pins TLS root CA set observed at first connect (verified chain roots), then verifies trust bundle against trust-root pins — after init, only pinned roots trusted
- TLS reload without restart: `certHolder` with atomic pointer, validates new cert/key before swap, keeps last good on failure, warns <14 days expiry
- systemd hardening: own user, `NoNewPrivileges`, `ProtectSystem=strict`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, supplementary group for signer socket
- Tailscale cert timer for D-11 homelab path
- e2e `TestServerInitEndToEnd` exercises full flow: software signer → server → init with pins → banner on CLI stderr and page

#### Concerns
- **HIGH**: `keyroster init` resolves `keyroster.localhost` on CI runner. If pure Go resolver doesn't resolve it, plan adds `/etc/hosts` entry in workflow. This is a test-only workaround but must not become a production pattern.
- **HIGH**: Server starts only after signer's Status succeeds (retry 30s). If signer is down, server serves 503. Need to ensure healthz also returns 503 when signer unreachable (plan says it does).
- **MEDIUM**: `internal/serverclient` builds `http.Client` with `RootCAs: pool of stored roots only`, `VerifyConnection: require chain ending in pinned root`. Must verify this doesn't break when server cert is renewed with same root but different intermediate (pin is root SPKI, so should work).
- **MEDIUM**: Config file at `os.UserConfigDir()/keyroster/config.json` written 0600. On Windows, `UserConfigDir` is `%APPDATA%` — ensure path handling is correct cross-platform.
- **LOW**: `addLogKey` helper removed from `test/e2e/harness_test.go` (deferred CI debt) — confirm no other tests depend on it.

#### Suggestions
- In `internal/server/tlsreload.go`, add a test that reload on SIGHUP works when cert/key files are atomically replaced (write to temp, rename)
- Document in runbook that `tailscale cert` generates a NEW key every issuance (not reused) — so leaf SPKI pinning would break; root pinning is correct
- Add a `keyroster init --repin` command for root rotation (future-proofing)

#### Risk Assessment: MEDIUM
This plan delivers the untrusted web front and pinned trust setup — critical infrastructure for all subsequent server plans. The security model (RP from signer, TLS pinning at init, trust bundle verification) is correct. Main risks are CI hostname resolution and the complexity of the pinned client implementation. The systemd hardening is thorough.

---

### 02-07

#### Summary
Admin API with SSHSIG authentication: `keyroster user add` creates pending account, prints invite URL + user's `keyroster init` line. Server stores pending users/invites/admin nonces in SQLite (non-authoritative). Admin requests signed with policy admin keys via SSH agent. Invite page greets invitee. Rate limits per IP.

#### Strengths
- **Correct authority model**: Pending accounts in server DB are NOT authority — only signer's installed admin-signed directory grants access (D-03)
- Admin API uses SSHSIG under `keyroster/admin-api/v1` covering method, path, body SHA-256, timestamp ±120s, single-use nonce
- Admin keys from signer's Status (root-signed policy), never from server config
- `keyroster user add` signs with admin key in ssh-agent (Unix socket or Windows pipe via go-winio)
- Invite token: 32 random bytes, base64url, stored as SHA-256, 24h expiry, Referrer-Policy no-referrer
- `--reinvite` replaces token for pending account; for directory user creates invite for additional credential
- Rate limiting with `golang.org/x/time/rate` per IP (admin 60/min, invite 30/min)
- e2e `TestUserAddInvite` verifies signer directory unchanged after `user add`

#### Concerns
- **HIGH**: `internal/serverdb` uses embedded migrations with `PRAGMA user_version` and refuses newer DB. Must ensure migration `0001_server.sql` is idempotent and doesn't conflict with future migrations (0002, 0003, 0004 in later plans).
- **MEDIUM**: `requireAdmin` middleware reads body with `http.MaxBytesReader` (1 MiB + 64 KiB) then calls `adminauth.Verify`. The body is read twice (once for hash, once for handler) — ensure this works with `http.MaxBytesReader` (may need to buffer).
- **MEDIUM**: Invite URL uses first policy origin + `/enroll/<token>`. If policy has multiple origins, the first is used. Should this be configurable or always the first?
- **MEDIUM**: `keyroster user add` prints the user's `keyroster init` line built from admin's verified config. If admin's config has multiple TLS pins, all are printed. Ensure the line is copy-pasteable (no shell escaping issues).
- **LOW**: Uniform 401 body `{"error":"admin authentication failed"}` for all auth failures — good for not leaking info, but makes debugging harder. Slog logs the specific reason.

#### Suggestions
- Add a test that `requireAdmin` rejects a request with a valid signature but wrong method (e.g., GET instead of POST)
- In `internal/serverdb/migrations/0001_server.sql`, add an index on `pending_users.invite_expires_us` for cleanup queries
- Document the admin key fingerprint format expected by `--admin-key` (SHA256:base64)

#### Risk Assessment: LOW
Solid implementation of the admin API with proper SSHSIG authentication and non-authoritative server state. The patterns (SSHSIG, rate limiting, embedded migrations) are proven from Phase 1. Low risk.

---

### 02-08

#### Summary
Passkey registration through invites: invite page runs WebAuthn create ceremony via hand-written `app.js`; go-webauthn (server-only, owner-reviewed first) verifies registration; server converts COSE key to SPKI DER, validates via `internal/webauthn.ParsePublicKey`; stores pending credential with fingerprint shown to user; `keyroster user pending` shows same fingerprint to admin. Credential grants nothing until 02-09 binds it. Differential oracle tests signer's verifier against go-webauthn.

#### Strengths
- **Critical**: Owner dependency review of go-webauthn v0.18.2 and unlocked transitives (tinylib/msgp, go-viper/mapstructure/v2, go-webauthn/x, philhofer/fwd, x448/float16) BEFORE `go get` — blocking-human checkpoint
- go-webauthn and its CBOR/JWT/TPM dependencies banned from signer graph via dep-firewall and depguard (D-17)
- Registration options: attestation none, UV required, residentKey preferred, pubKeyCredParams EdDSA/ES256/RS256 only
- Server re-validates credential with `internal/webauthn.ParsePublicKey` — same rule as signer and directory
- Pending credential stores BE/BS flags; fingerprint = `SHA256:` + base64(SPKI) shown to user and admin
- Invite registers exactly one credential; used invite shows uniform "invite not valid" page
- Differential oracle: every assertion vector tested against both verifiers; internal/webauthn is deliberately stricter on AT/ED/cross-origin (documented as `strictOnly`)
- `app.js` receives data via data-attributes, no inline script, CSP-compliant

#### Concerns
- **HIGH**: Owner dependency review (Task 1) is a blocking-human checkpoint. If owner rejects any transitive module, the registration design must change (fallback: browser `getPublicKey()` + `getAuthenticatorData()` to avoid CBOR). This could delay the plan significantly.
- **HIGH**: `internal/server/credential.go` converts COSE to SPKI using go-webauthn's `webauthncose.ParsePublicKey`. Must handle all three algorithms correctly: EC2→P-256, OKP→Ed25519, RSA→modulus+exponent. Edge case: RSA key with exponent ≠ 65537.
- **MEDIUM**: `app.js` uses `navigator.credentials.create` with decoded challenge, user.id, excludeCredentials. Must ensure base64url encoding/decoding matches WebAuthn spec exactly (no padding, URL-safe alphabet).
- **MEDIUM**: `servertest.Register` builds soft registration with attestation "none" using go-webauthn's CBOR encoder. This is test-only but links go-webauthn in test binary — ensure it's not linked into production binaries (verified by `go list -deps ./cmd/... | grep -c 'servertest\|webauthntest'` = 0).
- **LOW**: `enroll.html` renders `data-begin` and `data-finish` attributes with html/template escaping. Must ensure the URLs don't contain characters that break attribute quoting.

#### Suggestions
- In the dependency review, explicitly check that `github.com/go-webauthn/x` (2 stars, same org) is acceptable — low popularity but same maintainer
- Add a test that registration with a credential ID already in the installed directory is refused (409)
- Document the `strictOnly` list in the oracle test as known divergences from go-webauthn (AT set, ED set, crossOrigin true, topOrigin present)

#### Risk Assessment: MEDIUM
The owner dependency review is a necessary gate but introduces schedule risk. Technically, the design is sound: CBOR parsing confined to server, re-validation with signer's rules, differential testing. The `app.js` approach avoids CSP issues. Main risk is transitive dependency approval.

---

### 02-09

#### Summary
Closes enrollment loop: `keyroster user approve` binds registered passkey via admin-signed directory version (only authority). Every directory edit uses one pipeline: verify trust bundle against root pins → verify installed directory quorum locally → build successor → validate → diff → confirm → sign with admin SSH key → install via server or save proposal for co-signing. First admin enrolls same way (D-04). Server forwards install to signer, clears pending only on success.

#### Strengths
- **Strong authority model**: CLI verifies served trust bundle against root pins, then verifies installed directory signatures locally against policy admins — never trusts server state
- Pipeline builds successor with version+1, prev=SHA-256(installed), runs Validate/CheckPolicy, prints diff, prompts for confirmation (or `--yes`)
- Quorum >1: writes proposal (`directory.json`, `directory.json.sigs`, `base.sha256`); `directory sign` adds signature; `directory install` uploads
- Server forwards install unchanged to signer; only on success deletes bound pending credentials/accounts
- First admin enrolls identically: `user add` → register → `approve` with own SSH admin key
- AUTH-01 edge cases authored as must_haves: adjacency (credential ID collision), empty (no pending cred), idempotency (approve twice), concurrency (two approvals from same base)
- e2e `TestEnrollApproveEndToEnd` and `TestApproveConflictNoLostUpdate`

#### Concerns
- **HIGH**: `editDirectory` in `cmd/keyroster/dirpipe.go` does a deep copy of the base directory for mutation. For large directories (many users/credentials), this could be memory-intensive. The plan says directory must fit 64 KiB frame until 02-03's per-type caps — but 02-03 is in same wave (wave 2), so this plan may run before caps are merged. Need to ensure frame size doesn't block.
- **HIGH**: The pipeline calls `Trust()` which verifies the bundle against root pins. If the server's bundle is stale (signer updated but server cache not refreshed), the CLI will refuse. The server's status cache has 5s TTL — should be fine but worth noting.
- **MEDIUM**: `keyroster directory sign DIR` re-verifies proposal against currently installed base. If another admin installed a version in between, the proposal's prev won't match and sign will refuse. This is correct but the error message should guide the user to re-run `user approve`.
- **MEDIUM**: `internal/server/directory.go` keeps a directory mirror refreshed when cached Status's directory SHA-256 changes. Must ensure this doesn't race with installer — the server's `POST /api/v1/admin/directory` calls `signerclient.InstallDirectory` then refreshes mirror. If two installs race, the second should fail at signer (version chain) and server should not delete pending rows.
- **LOW**: Proposal layout uses armored SSHSIG blocks newline-separated (root sign convention). Ensure `sshsig.Parse` handles multiple signatures in one file correctly.

#### Suggestions
- In `editDirectory`, add a `--dry-run` flag that shows the diff and proposed version without signing
- Add a test that `directory sign` refuses a proposal whose existing signatures include a non-admin key
- In runbook, emphasize that `directory sign` must be run by a different admin (different SSH key) to count toward quorum

#### Risk Assessment: MEDIUM
The pipeline design is excellent (verify locally, diff, sign, install). The main risk is the frame size limitation for large directories before 02-03's per-type caps land. Since both are in wave 2, the merge order matters: 02-03 must merge before 02-09 if directories can exceed 64 KiB. The plan notes this dependency implicitly.

---

### 02-10

#### Summary
Passkey web sign-in: bound user signs in with passkey; server issues random challenge; browser calls `navigator.credentials.get` with allowCredentials from installed directory; server verifies with `internal/webauthn` (same code as signer). Session: opaque 32-byte ID, SHA-256 stored, `__Host-keyroster-session` cookie (Secure, HttpOnly, SameSite=Strict), 12h absolute / 1h idle, ends on logout or user disabled. `/account` shows read-only own data: roles, principals, TTL cap, credential fingerprints with synced/device-bound. No password/TOTP path.

#### Strengths
- Uses same `internal/webauthn.VerifyAssertion` as signer — single verification semantics
- Uniform 404 for unknown/pending/disabled/credential-less users — no enumeration
- Session cookie follows STACK.md: `__Host-` prefix, Secure, HttpOnly, SameSite=Strict, hashed at rest
- Idle (1h) and absolute (12h) expiry enforced by `TouchSession` on every request
- User disable in directory ends session on next request (mirror refreshed from signer)
- CrossOriginProtection on logout (unsafe method)
- Rate limits per IP and per username
- e2e `TestWebSignInEndToEnd` with soft authenticator, verifies Set-Cookie flags

#### Concerns
- **HIGH**: Username-first sign-in (no discoverable credential flow). Usernames appear in certificate key IDs and audit log — not secret, but uniform 404 + rate limits bound enumeration. Acceptable for Phase 2.
- **MEDIUM**: `internal/server/weblogin.go` creates challenge with 120s expiry. The page's `timeout: 60000` (60s) for `navigator.credentials.get` — if user takes >60s, browser may fail. Consider aligning or making timeout configurable.
- **MEDIUM**: `withSession` middleware requires user active in directory mirror. If mirror is stale (signer updated, server cache 5s TTL), a recently disabled user might get 1 request through. Acceptable window.
- **LOW**: `login.html` has username input + submit button. The `app.js` sign-in ceremony uses data-attributes like enroll page. Ensure CSP `connect-src 'self'` allows the fetch to `/api/v1/web/login/begin` and `/finish`.

#### Suggestions
- Add a test that a session created under policy v1 remains valid after policy v2 install (if user still active)
- In `session.go`, `TouchSession` updates `last_seen_us` — ensure this doesn't cause excessive DB writes (consider debouncing or only updating if >5min since last update)
- Document that web sessions are read-only and never authorize certificates or directory changes

#### Risk Assessment: LOW
Clean implementation of passkey sign-in with proper session security. Reuses signer's verifier. The read-only account page matches UI-01 scope. Low risk.

---

### 02-11

#### Summary
Roles, groups, host groups via admin-signed directory versions (02-09 pipeline). `keyroster role/group/host-group` commands. `keyroster host principals` renders AuthorizedPrincipalsFile using shared renderer `directory.RenderPrincipalsFile` (Phase 3 agent will use same). `keyroster host ca-key` prints user CA key for TrustedUserCAKeys. Owner confirms D-06 principal convention (role:<name> / u:<username>) at checkpoint.

#### Strengths
- All changes go through 02-09 pipeline (verified base, diff, SSHSIG, quorum)
- Shared renderer `RenderPrincipalsFile` ensures CLI and Phase 3 agent generate identical principals files
- Header includes directory version and SHA-256 for drift detection
- Principal validation: `cert.ValidatePrincipals` in CLI before signing, in directory Validate, in signer at install/issuance
- Role TTL capped by user CA profile; CLI refuses TTL > cap before signing
- Windows account names lowercased in host groups (Pitfall: Windows username matching)
- e2e `TestRolesHostPrincipalsEndToEnd`: role → group → host-group map → render → sshd accepts → unmap → sshd refuses

#### Concerns
- **HIGH**: D-06 principal convention is a one-way door (baked into certs and host files). Owner checkpoint (Task 1) is blocking-human. If owner chooses custom prefixes, must validate they pass `cert.ValidatePrincipals` regex `^[a-z0-9][a-z0-9._@:+-]{0,127}$`.
- **MEDIUM**: `role remove` refused while host group maps the role — good. But `group remove` refused while role grants it — what if a role grants a group that's also mapped to host groups? The error should name the dependent roles.
- **MEDIUM**: `keyroster host principals GROUP ACCOUNT` fetches directory via `Trust()` + `GetDirectory` and verifies locally. This duplicates the pipeline's verification logic. Could share a `verifyDirectory` helper.
- **LOW**: Host principals file rendered with `#` comments — sshd ignores these. Good for documentation but ensure no sshd version treats them differently.

#### Suggestions
- In `RenderPrincipalsFile`, sort principals lexicographically for deterministic output (plan says "sorted, de-duplicated")
- Add a test that rendering the same directory twice produces byte-identical output
- Document in runbook that manual host setup requires re-rendering after every role/host-group change until Phase 3 agent automates it

#### Risk Assessment: LOW
Well-scoped authorization plan with shared renderer and proper validation. The D-06 checkpoint is the only significant risk (one-way decision), but it's appropriately gated. The e2e test against real sshd validates the entire chain.

---

### 02-12

#### Summary
The MVP moment: `keyroster login` makes ephemeral key, prints fingerprint/principals/TTL, runs browser loopback with PKCE/state, opens approval page showing same fingerprint, user approves with passkey, loopback callback returns code, CLI redeems code → signer mints certificate (mint at redemption) → CLI verifies cert against root-pinned user CA → adds to ssh-agent with lifetime (SSH_AUTH_SOCK on Unix, keyroster agent on Windows). Server calls signer only at redemption.

#### Strengths
- **Correct mint timing**: Signer called only at redemption (code + PKCE verified) — phished unredeemed approval yields no cert, no serial, no log entry (Resolved Q2)
- Fingerprint parity: CLI and page compute `ssh.FingerprintSHA256` from stored request bytes; challenge = SHA-256(request) so server can't swap key unseen
- Loopback: `127.0.0.1:0`, accepts only `GET /callback` with exact Host header, constant-time state check, serves one response then closes
- Page uses `window.location.assign` (top-level navigation) for loopback — avoids CSP form-action block and Chrome LNA fetch prompts
- CLI verifies certificate before agent add: user CA from root-pinned bundle, key matches ephemeral, principals exact, kr2 key ID, validity ≤ TTL+300s, ≥60s remaining
- Windows uses `winagent.Ensure` (keyroster agent pipe with owner check); never inbox agent; never retries without lifetime constraint
- Clock skew check: CLI refuses if |local - server_time| > 60s
- Concurrency: two simultaneous logins get different fingerprints/pages/codes; approving one doesn't affect the other
- Lifetime expiry test: `--ttl 2m` → cert leaves agent at expiry (success criterion 2)

#### Concerns
- **HIGH**: Plan lists 18 files, 130k tokens — large but justified as single protocol (begin/approve/loopback/redeem) needing CLI+server together.
- **HIGH**: `internal/server/login.go` stores `login_sessions` with `code_hash` (SHA-256 of code), `code_expires_us` (120s). The `RedeemLogin` moves pending→approved→redeemed atomically. Must ensure the code is generated with `crypto/rand` (32 bytes) and the hash uses constant-time compare.
- **HIGH**: Page JS (`app.js` `#kr-approve`) parses `data-options` JSON, decodes challenge/credential IDs, calls `navigator.credentials.get`, posts base64url fields to `/assertion`, then `location.assign(redirect)`. Must ensure no `fetch` to loopback and no form redirect (Pitfalls 4,5).
- **MEDIUM**: `keyroster login` on Unix fails if `SSH_AUTH_SOCK` unset with instruction to start ssh-agent. On Windows, `winagent.Ensure` starts keyroster agent if needed. The A3 decision (gcr-ssh-agent) from 02-02 is applied here — if refuse-gcr, login refuses gcr socket.
- **MEDIUM**: CLI certificate verification uses `Trust()` against root pins to get user CA key. If root pins changed (KEY-07 ceremony), CLI config must be updated. The plan doesn't address root rotation — deferred to KEY-08.
- **LOW**: `--no-browser` only prints URL. User must manually copy-paste — phishable but documented as fallback.

#### Suggestions
- Add a test that `RedeemLogin` refuses a code from login A used on login B's id (cross-login code reuse)
- In `loopback.go`, the handler should log (debug) the received Host header for troubleshooting DNS rebinding attempts
- Document the `--ttl 2m` minimum in e2e is because CLI requires ≥60s remaining at issuance

#### Risk Assessment: MEDIUM-HIGH
This is the core user-facing feature. The design is solid (mint at redemption, fingerprint parity, PKCE, per-OS agent handling). Risks are in the browser-JS/loopback interaction (CSP, Chrome LNA, DNS rebinding) and the Windows agent integration. The e2e test with soft authenticator covers the happy path; real-browser testing in 02-14 is essential.

---

### 02-13

#### Summary
Dogfood part 1: Owner confirms RP hostname (D-09 one-way door) → root-signed policy successor (bundle v3, TEST root C) adds RP to vTPM signer → keyroster-server with `tailscale cert` → owner's Windows CLI init with TLS/trust pins → owner enrolls self (user add → real browser registration → approve with fingerprint). Records KEY-07 consequence: v3 = RP successor, owed offline ceremony becomes v4.

#### Strengths
- **Critical**: D-09 checkpoint (Task 1) presents live MagicDNS FQDN from `tailscale status` with all consequences (Public Suffix List, rename invalidates passkeys, CT logs, v3/v4 renumbering)
- Operational rigor: build from clean worktree, state backup before upgrade, rehearsal signing in WSL under `unshare -r -n`, hash chain verification (bundle SHA-256 equality across root sign, trust verify, sha256sum, install-bundle)
- Field-by-field policy comparison: v2 = v1 except version, prev, webauthn
- Server install with systemd units, Tailscale cert timer, healthz verified over tailnet
- Owner enrolls exactly like any user (D-04): real browser, any authenticator, fingerprint read from page
- Audit verify of exported log anchored on bundle v3
- Runbook steps labeled "run in 02-13"
- Prohibition: no homelab hostnames/FQDNs/addresses in committed files — only SHA-256 prefix in SUMMARY

#### Concerns
- **HIGH**: Task 1 requires Tailscale HTTPS Certificates enabled for tailnet. If not, `tailscale cert` fails. The `user_setup` section documents this but it's an external dependency.
- **HIGH**: Owner's real-browser registration (Task 3) and approval (Task 4) are blocking-human checkpoints. Schedule depends on owner availability.
- **MEDIUM**: WSL rehearsal uses `unshare -r -n` for network isolation during root signing. Must verify this works in the owner's WSL environment (WSL 2 should support unshare).
- **MEDIUM**: `keyroster-server` installed on signer VM alongside signer. The systemd unit has `After=keyroster-signer.service`, `Wants=keyroster-signer.service`, and `SupplementaryGroups=keyroster-admin` for socket access. Ensure the socket permissions allow this.
- **LOW**: `docs/runbooks/root-ceremony.md` updated with v3/v4 renumbering. The Phase 1 line "a later v3 rotation" changed to "a later v4 rotation" in ROADMAP.md — scoped edit only.

#### Suggestions
- In the D-09 checkpoint message, explicitly state the first 12 hex digits of SHA-256(FQDN) so owner can verify the hash in SUMMARY matches
- Record the `systemd-analyze security` exposure score for keyroster-server in SUMMARY as baseline
- Ensure the `transfer/` directory cleanup check (`find ... -name '*.age' -o -name 'pass*'`) runs after every ceremony step

#### Risk Assessment: MEDIUM
This is an operational plan with necessary human checkpoints. The technical steps are well-defined and rehearsed in WSL. Main risks are external (Tailscale HTTPS certs enabled, owner availability for browser steps) and the one-way RP hostname decision. The prohibition on committing homelab identifiers is correctly enforced.

---

### 02-14

#### Summary
Dogfood part 2: Real end-to-end logins. Configure zima-srv (stock OpenSSH) with `keyroster host ca-key` + `host principals`. Owner on Daniel-PC: web sign-in (AUTH-02), `keyroster login` with fingerprint comparison (AUTH-03, AUTH-04), SSH to zima-srv via keyroster agent pipe, cert expiry verified. Owner on laptop: same with GNOME session (respecting A3 decision). Every login corroborated by audit log (kr2 key IDs) and sshd journal. Platform record in needs-hardware.md with UNVERIFIED labels. cli-windows/cli-macos added to required checks (owner applies ruleset).

#### Strengths
- **Complete validation**: Two independent records (audit log + sshd journal) for each login — matches core value "full visibility"
- Real platforms: Windows 11 (inbox OpenSSH 9.5p2, keyroster agent), Ubuntu (GNOME, agent per A3 decision)
- Expiry test: `--ttl 5m` → cert gone from agent after expiry
- Honest platform record: only exercised OS/browser/authenticator/agent combinations marked verified; macOS browser leg UNVERIFIED
- Required checks: cli-windows/cli-macos green on main since 02-02, owner applies ruleset from PR branch (Pitfall 10/11 pattern)
- REQUIREMENTS.md tracking: AUTH-03/PLAT-05 stay Pending with "macOS browser leg UNVERIFIED" note
- Prohibition: no homelab identifiers in repo; ssh aliases (keyroster-signer-vm, zima, ub-daniel) only

#### Concerns
- **HIGH**: Task 2 and Task 4 require owner to perform multiple manual steps in real browsers with authenticators. If any step fails (browser issue, authenticator issue, network), the plan stalls at blocking-human checkpoints.
- **HIGH**: Laptop login depends on A3 decision from 02-02. If gcr-ssh-agent failed and owner chose refuse-gcr, laptop must use plain ssh-agent. The plan handles this but the owner must execute correctly.
- **MEDIUM**: Corroboration requires matching kr2 key IDs and serials between audit verify output and journalctl lines. The journal query uses `--since "-3h"` — ensure time sync between VM and zima-srv.
- **MEDIUM**: Adding cli-windows/cli-macos to main-integrity ruleset requires owner to run `apply-rulesets.sh` with their gh login (admin-only). Must be done before PR approval.
- **LOW**: The plan says "AUTH-03 and PLAT-05 are NOT listed [in requirements-completed]: macOS is UNVERIFIED". This is correct per no-unexercised-paths rule but should be clearly communicated to stakeholders.

#### Suggestions
- In Task 2 instructions, provide the exact `keyroster.exe login` command with the pipe path from 02-02 SUMMARY
- For laptop login, if A3 decision was refuse-gcr, explicitly instruct owner to `eval "$(ssh-agent)"` before `keyroster login`
- In platform record, include the exact authenticator kinds used (Windows Hello, phone passkey, security key, etc.)
- After merge, consider filing a follow-up issue for macOS verification when hardware becomes available

#### Risk Assessment: MEDIUM
This plan achieves the phase goal on real hardware. The blocking-human checkpoints for owner actions are necessary for real-world validation but introduce schedule dependency. The corroboration via audit log + sshd journal is the gold standard for verification. The ruleset update process is established from Phase 1.

---

### Cross-Plan Summary

#### Overall Architecture Assessment
The 14 plans form a coherent, well-sequenced implementation of the Passkey Login MVP. The wave structure correctly manages dependencies:
- Wave 1 (02-01): Core signer security (tracer)
- Wave 2 (02-02, 02-03): Platform probes + signer hardening
- Wave 3 (02-04, 02-05): Audit closure + software key warning
- Wave 4 (02-06): Server core + init
- Wave 5 (02-07): Admin API + invites
- Wave 6 (02-08): Registration (go-webauthn dependency review)
- Wave 7 (02-09): Approval pipeline
- Wave 8 (02-10, 02-11): Web sign-in + roles/groups
- Wave 9 (02-12): CLI login (MVP moment)
- Wave 10 (02-13): Homelab enrollment
- Wave 11 (02-14): Homelab real logins + platform record

#### Key Strengths Across Plans
1. **Security-first design**: Every authority decision (credential binding, role mapping, RP identity) reaches signer as signed payload — server never decides
2. **Tracer-first**: 02-01 proves the hardest security properties end-to-end before building UI/server
3. **Proper gating**: Probes (02-02), dependency reviews (02-08), one-way decisions (02-11 D-06, 02-13 D-09) all have blocking-human checkpoints
4. **Auditability**: 02-04 makes every login certificate re-provable; tamper suite with re-signed checkpoints
5. **Platform honesty**: UNVERIFIED labels for unexercised paths (macOS, Firefox, headless), no-exercised-paths rule enforced
6. **Dependency hygiene**: Signer graph protected by dep-firewall, capslock, depguard; go-webauthn confined to server
7. **Operational rigor**: Homelab plans (02-13, 02-14) use clean builds, state backups, hash verification, runbook labeling

#### Systemic Concerns
1. **Large PRs**: 02-01 (32 files, 140k), 02-06 (29 files, 120k), 02-12 (18 files, 130k) — review burden is high
2. **Wave 2 ordering**: 02-02 and 02-03 both in wave 2 but 02-09 (wave 7) needs 02-03's per-type caps for large directories. Merge order within wave matters.
3. **go-webauthn transitive deps**: 02-08 owner review covers 7 unlocked modules — if any rejected, fallback design needed
4. **Windows agent assumption A2**: Entire Windows AUTH-03 path depends on inbox ssh.exe honoring named pipe. Probe in 02-02 Task 1 is the linchpin.
5. **Root rotation (KEY-08)**: CLI config pins trust roots; no `init --repin` yet. After KEY-07 ceremony, all clients must re-init.

#### Missing/Deferred Items to Track
- `keyroster init --repin` for root rotation (mentioned in 02-06 suggestions)
- Headless login (device-code/polling) — deferred per D-12
- Per-role "require device-bound credential" — deferred
- Native CTAP2 (libfido2/webauthn.dll) — deferred
- Admin actions in web UI (UI-02) — Phase 4
- Host agent, KRL, revocation — Phase 3
- Machine identities (AUTH-06) — Phase 3

#### Risk Assessment Summary
| Plan | Risk | Primary Driver |
|------|------|----------------|
| 02-01 | MEDIUM-HIGH | Large scope, foundational design |
| 02-02 | HIGH | Unverified A2/A3 probes |
| 02-03 | LOW-MEDIUM | Test infrastructure complexity |
| 02-04 | LOW | Proven audit infrastructure |
| 02-05 | LOW | Well-scoped, owner wording gate |
| 02-06 | MEDIUM | CI hostname resolution, pinned client complexity |
| 02-07 | LOW | Proven patterns |
| 02-08 | MEDIUM | Owner dependency review gate |
| 02-09 | MEDIUM | Frame size vs merge order with 02-03 |
| 02-10 | LOW | Clean implementation |
| 02-11 | LOW | D-06 checkpoint only risk |
| 02-12 | MEDIUM-HIGH | Core feature, browser/loopback complexity |
| 02-13 | MEDIUM | Operational, human checkpoints |
| 02-14 | MEDIUM | Real-world validation, schedule dependency |

#### Recommendation
**Proceed with the plan sequence as written.** The architecture is sound, security model is correctly implemented (signer authority, server proposes), and risk mitigations (probes, checkpoints, fuzzing, audit verification) are appropriate. The main execution risks are:
1. 02-02 probes failing → Windows AUTH-03 blocked
2. 02-08 dependency review rejecting modules → registration redesign
3. 02-13/02-14 owner availability for browser steps

These are correctly handled as blocking-human checkpoints rather than silent fallbacks. The phase will deliver a working, auditable passkey login MVP on Linux and Windows with honest platform verification.

---

## Ollama gemma4:31b Review

This is a comprehensive, security-first implementation plan for Phase 2. The "server proposes, signer disposes" architecture is correctly maintained, and the decision to use an in-memory agent on Windows to satisfy lifetime constraints is a critical and correct technical pivot.

### 02-01
**Summary**: Establishes the foundational "Phase Tracer," implementing the root-signed RP policy, the admin-signed directory structure, the signer-side WebAuthn assertion verifier, and the `kr2` certificate issuance path.

**Strengths**:
- High architectural integrity: ensures the signer remains the sole authority for principals and TTLs.
- Correct application of the "no-Cbor-in-signer" rule by converting to SPKI DER.

**Concerns**:
- **LOW**: `internal/directory/directory.go` validation. The plan mentions refusing "an active user with no credentials" (AUTH-01). If a user is disabled, can they have zero credentials? Ensure `Validate()` handles the `Status` field correctly to avoid blocking the disabling of accounts.

**Suggestions**:
- In `internal/webauthn/verify.go`, explicitly ensure that the constant-time comparison is used not just for the challenge, but also for any identity-sensitive checks to prevent timing attacks on credential IDs.

**Risk Assessment**: LOW. The core logic is a direct extension of Phase 1's trust model.

---

### 02-02
**Summary**: Solves the Windows agent problem by implementing a custom in-memory agent on a per-user named pipe and adds cross-platform CI jobs.

**Strengths**:
- Directly addresses the Win32-OpenSSH registry persistence and lifetime refusal issues.
- Strong security on the pipe via SID-based ACLs and the `VerifyServerOwner` check.

**Concerns**:
- **MEDIUM**: `internal/winagent/ensure_windows.go`. The plan starts the agent as a detached process. Ensure there is a robust mechanism to prevent "zombie" agents from accumulating if the CLI crashes before the agent's internal idle-exit timer triggers.

**Suggestions**:
- For the GNOME `gcr-ssh-agent` probe (Task 1), add a check for the `SSH_AUTH_SOCK` environment variable to ensure the probe isn't just hitting a fallback agent.

**Risk Assessment**: LOW. The risk is primarily operational (zombie processes) rather than security-critical.

---

### 02-03
**Summary**: Hardens the signer boundary with a complete refusal matrix, concurrency protections, and fuzz targets for all new parsers.

**Strengths**:
- Rigorous approach to "successes-with-controls" for every refusal case.
- Correct memory bounding via per-type frame caps.

**Concerns**:
- **LOW**: `internal/signer/login.go`. When the directory is updated (Successor), the plan mentions the login might refuse `directory_changed`. Ensure the error message provided to the CLI is actionable (e.g., "directory updated, please retry").

**Suggestions**:
- In the fuzz targets, specifically seed the `clientDataJSON` parser with common browser-injected keys to ensure the "ignore unknown members" logic is robust.

**Risk Assessment**: LOW. The plan is highly disciplined regarding input validation.

---

### 02-04
**Summary**: Implements the `successor-policy` tool for RP management and extends `audit verify` to re-prove passkey authorizations.

**Strengths**:
- Closes the loop on visibility: a compromised signer cannot forge a login without a valid user assertion in the log.
- Correctly handles the one-way nature of the RP ID change.

**Concerns**:
- **LOW**: `internal/audit/verify.go`. The plan requires the auditor to keep the directory in force. Ensure that if a directory is revoked or changed, the auditor can still verify old certificates using the directory version that was in force at the time of issuance.

**Suggestions**:
- Add a check in `audit verify` to ensure that the `PolicyVersion` in the `login_issue` leaf matches the policy in force at that log index.

**Risk Assessment**: LOW.

---

### 02-05
**Summary**: Implements the encrypted software CA keystore for evaluation purposes and the `Status` message to drive the "Evaluation Only" banners.

**Strengths**:
- Proper isolation of the `software` backend.
- High visibility: banner is driven by the signer, not configuration.

**Concerns**:
- **LOW**: `internal/keystore/software/software.go`. The plan uses `age` for encryption. Ensure that the `scrypt` parameters used for the passphrase are sufficient to resist offline brute-force for an "evaluation" instance.

**Suggestions**:
- In `internal/custodytext`, allow the banner to be configured to support different languages in the future, even if only English is used now.

**Risk Assessment**: LOW.

---

### 02-06
**Summary**: Deploys the `keyroster-server` with strict security headers, embedded UI, and a pinned TLS trust model for the CLI.

**Strengths**:
- Extreme caution with the Web UI: no npm, no inline scripts, strict CSP.
- Correct implementation of TLS root pinning to prevent WebPKI-based impersonation of the CA.

**Concerns**:
- **MEDIUM**: `internal/server/tlsreload.go`. The plan reloads certificates on SIGHUP or mtime change. Ensure the reload is atomic (using `atomic.Pointer`) to avoid serving a partial or mismatched cert/key pair during the swap.

**Suggestions**:
- Add a "Health Check" endpoint that not only returns `ok` but also reports the current TLS certificate's expiry date to the operator.

**Risk Assessment**: LOW.

---

### 02-07
**Summary**: Implements an SSHSIG-authenticated admin API and the invitation system for user enrollment.

**Strengths**:
- Correct use of "authentication, not pipes" for the admin API.
- Ensures pending accounts are not authoritative.

**Concerns**:
- **LOW**: `internal/server/invite.go`. The invite token is 32 random bytes. Ensure the `invite_hash` in the DB is computed using a cryptographically secure hash (SHA-256) and compared in constant time.

**Suggestions**:
- For `keyroster user add`, add a flag to specify the invite's expiry if the default 24h is not suitable for a specific user.

**Risk Assessment**: LOW.

---

### 02-08
**Summary**: Implements passkey registration via the server, converting COSE keys to SPKI DER for the signer.

**Strengths**:
- Correct dependency isolation: `go-webauthn` is strictly banned from the signer.
- Use of a differential oracle to verify the internal verifier against the maintained library.

**Concerns**:
- **MEDIUM**: `internal/server/enroll.go`. The plan allows registration of a la passkey. Ensure that the "invite used" marker is set *only* after the credential is successfully persisted to the DB to avoid locking users out on network errors.

**Suggestions**:
- In the `app.js` registration ceremony, provide clear feedback if the browser does not support the requested `pubKeyCredParams` (e.g., no RS256 support).

**Risk Assessment**: LOW.

---

### 02-09
**Summary**: Implements the admin approval pipeline, allowing credentials to be bound to users via signed directory versions.

**Strengths**:
- Strong "Verify Base $\rightarrow$ Mutate $\rightarrow$ Diff $\rightarrow$ Sign $\rightarrow$ Install" pipeline.
- Correct handling of quorum through proposal files.

**Concerns**:
- **LOW**: `internal/directory/diff.go`. Ensure the diff is strictly read-only and does not leak sensitive data (though credentials are already just fingerprints).

**Suggestions**:
- In `keyroster user approve`, add a `--force` flag for the rare case where an admin needs to bind a credential that the server currently thinks is already bound (e.g., after a DB restore).

**Risk Assessment**: LOW.

---

### 02-10
**Summary**: Implements passkey web sign-in and a read-only account view.

**Strengths**:
- Correct session hardening: `__Host-` prefix, hashed at rest, idle/absolute expiry.
-- No "backdoor" sign-in paths.

**Concerns**:
- **LOW**: `internal/server/session.go`. The plan deletes the session if the user is disabled. Ensure this check happens on every request, not just at session creation.

**Suggestions**:
- Add a "Last Login" timestamp to the account page to help users detect unauthorized access.

**Risk Assessment**: LOW.

---

### 02-11
**Summary**: Implements roles, groups, and host groups, and the shared renderer for `AuthorizedPrincipalsFile`.

**Strengths**:
- Consistent use of the 02-09 pipeline for all authority changes.
- Correct a-priori validation of principals (no wildcards/commas).

**Concerns**:
- **LOW**: `internal/directory/render.go`. The plan renders a file with a header. Ensure the renderer handles empty principal sets by producing an empty file (or a file with only the header) rather than an error, so that revoking all access is possible.

**Suggestions**:
- Add a `keyroster role list` command to provide an overview of the current authorization matrix.

**Risk Assessment**: LOW.

---

### 02-12
**Summary**: Implements the `keyroster login` CLI flow with browser loopback, PKCE, and agent integration.

**Strengths**:
- Robust anti-phishing via fingerprint comparison.
- Correct "Mint at Redemption" logic to prevent phished certificates from appearing in the log.

**Concerns**:
- **MEDIUM**: `cmd/keyroster/loopback.go`. The plan listens on `127.0.0.1:0`. Ensure the listener is closed immediately after the first successful callback to minimize the window for local attacks.

**Suggestions**:
- Implement a timeout for the loopback listener that provides a friendly error message if the user takes too long to approve in the browser.

**Risk Assessment**: LOW.

---

### 02-13
**Summary**: Executes the homelab dogfooding for the server and the first admin enrollment.

**Strengths**:
- Strict "no-leak" policy for homelab identifiers.
- Rigorous rehearsal in WSL before applying to the VM.

**Concerns**:
- **LOW**: Task 2. The la backup of the state directory is mentioned. Ensure the backup includes the `ca-pubkeys.json` and any other identity files, not just the DB.

**Suggestions**:
- Record the `systemd-analyze security` score in the SUMMARY to provide a baseline for future hardening.

**Risk Assessment**: LOW.

---

### 02-14
**Summary**: Completes the phase with real end-to-end logins on Windows and Linux, and updates the platform verification record.

**Strengths**:
- Honest reporting of "UNVERIFIED" platforms (macOS).
- Corroboration of logins via independent logs (audit and journal).

**Concerns**:
- **LOW**: Task 5. When adding `cli-windows` and `cli-macos` as required checks, ensure the `main-integrity` ruleset is updated *after* the jobs are confirmed green on `main` to avoid blocking the pipeline.

**Suggestions**:
- Include a "Lessons Learned" section in the SUMMARY regarding the real-world behavior of the Windows inbox agent vs. the custom agent.

**Risk Assessment**: LOW.

---

### Final Review Summary

**Overall Quality**: Excellent. The plans are concrete, cite specific requirements/decisions, and follow a strict "tracer-first" execution model.
**Completeness**: All Phase 2 requirements are mapped to specific plans.
**Risks**: The primary risk is the reliance on third-party browser behavior for the loopback and WebAuthn ceremonies, which is correctly mitigated by labeling those paths as UNVERIFIED until the homelab dogfooding.
**Phase Goal**: The plans provide a clear, verifiable path to achieving the first end-to-end login.

**Verdict**: **APPROVED**. Ready for execution.

---

## Ollama gpt-oss:120b (per plan) Review

### 02-01 – Review  

#### Summary  
Plan 02-01 is the “Phase-tracer” that stitches together every core component needed for the Passkey-Login MVP:

1. **Policy extension** – adds a `WebAuthn *WebAuthnRP` field (last field of `Policy`) and a full validation suite for RP-ID and origins.  
2. **Directory model** – introduces a signed, successor-chained `keyroster/directory/v1` document, with its own parser, validator and authorisation logic.  
3. **WebAuthn verifier** – a tiny std-lib-only verifier that parses `clientDataJSON` and CBOR-encoded authenticator data, checks RP-ID, flags, origin and signature.  
4. **Wire changes** – new frame types for `InstallDirectory` and `LoginIssueRequest`, plus marshaling/unmarshaling code for the new structures.  
5. **Signer changes** – installs a directory, verifies it, and then processes a login request by (a) checking evidence, (b) recomputing the principal set/TTL from the directory, (c) issuing a `kr2` certificate, and (d) logging both a `directory_install` and a `login_issue` leaf.  
6. **CLI and test scaffolding** – adds genesis-policy flags, soft-authenticator test helpers, a full e2e “real sshd” test, and updates the dependency-firewall / capslock checks.

The plan is a concrete “big-bang” tracer: if all pieces compile and the e2e test passes, the whole Phase-2 security core is proved to work.

---

#### Strengths  

| Area | What the plan does well |
|------|--------------------------|
| **Security-by-design** | The signer is the only component that ever sees a verified WebAuthn assertion (step 3 of the signer login flow). All policy and directory checks happen inside the signer, keeping the network-less signer as the trust anchor. |
| **Two-layer authority** | By requiring a root-signed policy *and* an admin-quorum-signed directory before any login can succeed, the plan enforces the “root + quorum” model described in the context doc (D-01). |
| **Tamper-evident logging** | New `KindDirectoryInstall` and `KindLoginIssue` leaves are added atomically with the DB transaction, preserving the Merkle-log guarantees. |
| **Clear separation of concerns** | Wire, policy, directory, WebAuthn, signer and CLI are each given their own package, keeping the attack surface small and the dependency graph clean. |
| **Test coverage** | Unit tests for every new format, a soft-authenticator fuzz-friendly test harness, and a full e2e test against stock OpenSSH hosts give high confidence before any production rollout. |
| **Dependency-firewall discipline** | The plan explicitly adds the new packages to the signer-no-network list and anticipates capslock updates, respecting the existing supply-chain hardening process. |
| **Future-proofing hooks** | The RP-ID validation rules (IP literals, tailnet label counts, etc.) are coded in step 1 and documented as “owner-locked D-09 rule”, making later policy upgrades straightforward. |

---

#### Concerns  

| Severity | Concern (with reference to plan step) | Open question / mitigation |
|----------|--------------------------------------|----------------------------|
| **HIGH** | **(1) Policy canonicalisation** – The plan adds `WebAuthn *WebAuthnRP` as the *LAST* field of `Policy` (step 1). If any downstream code marshals a `Policy` without preserving field order, byte-identical canonical JSON will break and signatures will no longer validate. <br>**Question:** Does the existing `CanonicalJSON` implementation guarantee field order for *all* structs, or only for fields that already appear in the struct definition? Should we enforce a custom encoder that re-orders fields rather than rely on struct order? |
| **HIGH** | **(2) Directory successor validation** – `CheckSuccessor` (step 4) enforces `prev = SHA-256(prevBytes)`. The plan mentions a “GenesisPrev” constant but does not state how that constant is derived (e.g. all-zero hex). <br>**Question:** What happens if the signer restarts with a partially-written directory row (e.g. DB crash after InsertDirectory but before commit of the log leaf)? Is there a recovery path that does not leave the signer in a state where `directoryAuthorized == false` yet the directory exists on disk? |
| **HIGH** | **(3) WebAuthn assertion size limits** – The verifier (step 3) demands `authenticatorData` exactly 37 bytes and a 1024-byte max for the signature. New authenticator firmware (e.g., Windows Hello updates) may add extra extensions or a larger counter field. <br>**Question:** Are we prepared to relax the fixed-size check to “≥ 37 bytes and the flag bits are in the expected positions” while still rejecting unsupported extensions? |
| **MEDIUM** | **(4) Clock-skew handling** – The login flow checks a “maxClockSkew” (step 7 of the login flow) but the plan does not specify the exact value or how it is synchronised with the client. <br>**Question:** What is the chosen skew window, and is it configurable for future deployments that may run on machines with unsynchronised clocks? |
| **MEDIUM** | **(5) Principal equality enforcement** – The signer rejects the request if `req.Principals != grant.Principals` (step 7-3). The wire format permits the client to omit `Principals` (optional field). If a client omits the field but the grant set is non-empty, the signer will reject with `principals_mismatch`. <br>**Question:** Should the CLI automatically populate `Principals` from the directory, or should we add a clearer error message to help developers? |
| **MEDIUM** | **(6) Key ID formatting** – The new `kr2` format appends `/roles=` with a `+`-joined list. The parsing code must reject unsorted or duplicate role strings (step 6). <br>**Question:** Are there any downstream tools (e.g., audit-verify scripts) that currently assume a fixed number of fields and will break when they encounter the extra `/dir=` and `/roles=` components? |
| **LOW** | **(7) Dependency-firewall coverage** – The plan adds `**/internal/webauthn/**` and `**/internal/directory/**` to the signer-no-network block (step 13). However, the CLI also imports `internal/webauthn` indirectly via `signerclient` for the soft-authenticator helper. <br>**Question:** Does the firewall rule differentiate between the signer binary and the CLI binary, or will it unintentionally block the CLI from building? |
| **LOW** | **(8) Windows named-pipe handling** – The CLI uses `github.com/Microsoft/go-winio` (step 13) but the plan does not explicitly add a build tag or OS-guard to avoid pulling the package into non-Windows builds. <br>**Question:** Is the go-mod tidy step guaranteed to keep the dependency only behind the `windows` build tag, and does the capslock baseline treat this as “network-aware” code? |
| **LOW** | **(9) Test-only soft-authenticator** – The soft authenticator lives under `internal/webauthn/webauthntest`. The plan checks that the binary does not depend on it, but the explicit check `go list -deps ./cmd/... | grep -c webauthn/webauthntest` may miss indirect imports via test files. <br>**Question:** Should we add an explicit `go:build !test` guard or move the helper to `test/` to guarantee it never lands in production binaries? |

---

#### Suggestions  

| Area | Recommendation |
|------|----------------|
| **Policy canonicalisation** | Add a dedicated `CanonicalEncodePolicy(p *Policy) ([]byte, error)` that orders fields explicitly (e.g., using a map with a fixed key order) and replace all `json.Marshal` calls with it. This eliminates any reliance on struct field order. |
| **Directory recovery** | Implement a “directory sanity check” at signer start-up: if a directory row exists but its leaf hash does not match the latest log entry, roll back to the previous version (or abort startup with a clear error). Document the recovery procedure. |
| **WebAuthn data flexibility** | Replace the strict `len(authData) == 37` check with `len(authData) >= 37 && (authData[32] & 0x07) == expectedFlags`. Add a comment that extra bytes are ignored for now, and flag them in a new refusal class (`unsupported_authenticator_data`). |
| **Clock-skew configurability** | Introduce a configurable `maxClockSkew = 5 * time.Minute` in the signer and expose it via a `--max-clock-skew` flag (owner-locked). Include the value in the log leaf for auditability. |
| **CLI auto-populate principals** | In `keyroster login`, after fetching the directory, call `Authorize` and inject the resulting `Principals` into the request if the user did not supply them. This avoids a “principals_mismatch” user error. |
| **Key ID backward compatibility** | Add a compatibility shim in `cert.ParseKeyID` that, when encountering an unknown field (e.g., `/dir=`), still parses the known prefix and returns a partially-filled struct, but logs a warning that newer fields are present. This protects older tools that only understand `kr1`. |
| **Dependency-firewall granularity** | Split the firewall rule into two lines: `**/internal/webauthn/**   signer-no-network` and `**/internal/webauthn/**   cli-no-network` (or a comment clarifying that the rule applies only to the signer binary). |
| **Windows build-tag hygiene** | Add `//go:build windows` at the top of the file that imports `go-winio` and ensure the `go.mod` replace block for `github.com/Microsoft/go-winio` is scoped to that file. Verify capslock does not flag the import for non-Windows builds. |
| **Soft-authenticator isolation** | Move the entire `webauthntest` package under `test/` (e.g., `test/webauthn`) and import it with a build tag `//go:build test`. Update the test code to import `test/webauthn`. This guarantees the helper never appears in production builds. |
| **Documentation of error classes** | Extend the refusal-class table (`internal/signer/refusal.go`) with a comment mapping each new sentinel (e.g., `credential_mismatch`) to its `ReasonUnauthorized` enum value, and update the generated docs (`docs/REFUSALS.md`). |

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **Policy-field ordering breaking signatures** | Medium (depends on future code changes) | High – all existing certificates would become unverifiable. | Implement explicit canonical encoder (see suggestion) and lock the struct order via code review gate. |
| **Directory chain corruption on crash** | Low (DB transactions are atomic) | High – signer could refuse every login and become unusable. | Add start-up sanity check and graceful fallback to “no directory installed” mode, with clear admin alert. |
| **Future authenticators exceeding fixed data limits** | Medium (authenticator firmware evolves) | Medium – legitimate logins could be refused. | Relax size checks and add a new refusal class for “unsupported_authenticator_data”. |
| **Clock-skew causing replay failures** | Low (skew window is modest) | Medium – user experience degraded. | Make skew configurable and document the default. |
| **Incorrect principal set leading to denial** | Low (principal equality is strict) | Medium – legitimate logins denied. | Auto-populate principals in CLI and improve error messaging. |
| **Dependency-firewall inadvertently blocking CLI builds** | Low (rules are simple) | Low – CI failures. | Separate firewall lists for signer vs CLI as suggested. |
| **Test-only soft-authenticator leaking into production binary** | Very low (explicit check in plan) | Low – binary size increase, no security issue. | Move helper to `test/` package. |

Overall, the plan is **well-scoped** and **architecturally sound**, but the high-severity concerns around *canonical JSON ordering* and *directory chain robustness* must be addressed before the code can be considered production-ready. Implementing the suggested mitigations will lower the risk to an acceptable level and keep the Phase-2 tracer on track for the MVP success criteria.
### 02-02 – Windows-named-pipe SSH agent & cross-platform CI  
**Phase 2 – Passkey Login MVP**  

#### Summary  
The plan introduces a **per-user, in-memory Windows SSH-agent** that is reachable through a named pipe (`\\.\pipe\keyroster-agent-<SID>`).  
* The agent is started on demand by the CLI (`keyroster agent`) and serves the OpenSSH `ssh-agent` protocol via the Go-standard `agent.NewKeyring()` implementation.  
* Keys/certificates added through the CLI carry a **lifetime constraint**; the agent expires them and exits when the last key is gone or after a configurable idle timeout.  
* A **probe stage (Task 1)** first validates whether the built-in Windows OpenSSH client (`ssh.exe`/`ssh-add.exe`) can talk to a pipe-based agent and whether the GNOME `gcr-ssh-agent` on Linux respects lifetimes. The results of these probes are recorded in a SUMMARY file and feed any required human decision.  
* The **dialer split** (`agentconn_unix.go` / `agentconn_windows.go`) lets the existing `dialAgent` abstraction route to either a UNIX-domain socket (Linux/macOS) or the named pipe (Windows) using `github.com/Microsoft/go-winio@v0.6.2`.  
* **CI extensions** add `cli-windows` and `cli-macos` jobs that build the binary for all three platforms and run the new Windows-agent tests, plus a Unix-agent lifetime test.  
* Documentation (`docs/security/needs-hardware.md`) is updated to capture the platform-verification status (Windows ✔, GNOME ✔, macOS UNVERIFIED).  

Overall the plan attempts to satisfy **AUTH-03** (certificate expires from the agent) and **PLAT-05** (CLI works on Linux, macOS, Windows) while keeping the attack surface small (no fallback to the inbox agent, no disk-write of private material).

---

#### Strengths  

| What the plan does well | Evidence / Plan step |
|------------------------|-----------------------|
| **Isolates Windows credential handling** – a dedicated pipe-agent avoids the registry-based persistence of the stock OpenSSH inbox agent. | Task 2 “keyroster agent … never puts a login key into the Windows inbox ssh-agent” (prohibition resolved). |
| **Defends against pipe-squatting** – the pipe is created with a SID-restricted SDDL and `VerifyServerOwner` checks the server’s token before any key is sent. | Task 2, internal/winagent/owner_windows.go description. |
| **Clear gating probes** – the plan refuses to ship Windows code until the inbox client can actually consume a pipe-based agent and until the GNOME agent correctly enforces lifetimes. | Task 1 “A2” and “A3” with explicit pass/fail checkpoints. |
| **Zero-cgo static binaries** – `go-winio` is pure Go, preserving the “static binary” policy for the core binary (except the Windows build which includes the extra dependency). | Files-modified list, “go-winio is linked only into the Windows build of keyroster”. |
| **CI-driven dependency firewall** – the `go list -m github.com/google/go-tpm` version is confirmed unchanged, and the dep-firewall / capslock checks are run after the `go-get`. | Task 2 verification steps. |
| **Explicit reversibility rating** – the plan acknowledges the long-term cost of a hard-coded pipe name in user configs, which is useful for future migration decisions. | Task 2 “reversibility rating=costly”. |
| **Documented failure paths** – if either probe fails, a `checkpoint:decision` is emitted with concrete remediation options, preventing silent fallback. | Task 1 “blocking-human decision” section. |

---

#### Concerns  

| Severity | Concern | Where it appears in the plan | Why it matters |
|----------|----------|-----------------------------|-----------------|
| **HIGH** | **Reliance on the inbox OpenSSH client to honour the lifetime flag** – the whole Windows flow hinges on `ssh-add -t` and `ssh.exe` reading the `LifetimeSecs` field from the in-memory agent. The probe (Task 1 A2) only demonstrates this on the author’s test machine; if the Windows OpenSSH version is upgraded or the user runs a non-standard client (e.g., MSYS2 `ssh.exe`), the guarantee may break. | Task 1, step 3 (use of `ssh-add.exe -t 30 …` and later `ssh-add.exe -l` to verify expiry). | If the client silently ignores the lifetime, a certificate could persist in the inbox agent, violating AUTH-03 and leaking long-lived credentials. |
| **MEDIUM** | **Potential for SID mismatch on multi-user machines** – `VerifyServerOwner` compares the pipe server’s SID to the *current* caller’s SID. If a user runs the CLI under a different token (elevated, runas, or via a service), the verification may incorrectly reject a legitimate agent or, conversely, accept a malicious server that managed to impersonate the caller’s SID (e.g., via a compromised service). | internal/winagent/owner_windows.go description (Task 2). | The check is only as strong as the Windows APIs used; edge cases (UAC elevation, scheduled tasks) could bypass it, allowing a rogue process to harvest keys. |
| **MEDIUM** | **Hard-coded pipe name may become a migration obstacle** – the plan acknowledges the “costly” reversibility rating, but no migration strategy is defined (e.g., versioned pipe names, env-override). Future changes to the pipe naming scheme would require manual updates to every user’s `~/.ssh/config` or environment variable. | Task 2 “reversibility rating=costly”. | Could lead to configuration drift and broken logins after a later refactor or security hardening step. |
| **LOW** | **Dependency surface on `go-winio` only on Windows** – while the plan checks that the signer's dependency graph is unchanged, adding a new indirect dependency (`golang.org/x/sys/windows`) might introduce a new attack surface for Windows-only builds (e.g., via a malicious update). | Task 2 verification step “go list -deps … | grep go-winio”. | The dep-firewall capslock checks mitigate this, but the plan does not specify a process for future updates (e.g., pinning to a specific commit hash). |
| **LOW** | **MacOS verification remains UNVERIFIED** – the plan records “UNVERIFIED” in docs but does not require any macOS-specific runtime test beyond CI unit tests. Real-world macOS users may encounter subtle differences (e.g., `ssh-add` does not support the `-t` flag). | Task 3 documentation update. | Could surface as a production issue later (failure to honor lifetime on macOS) without a clear mitigation path. |

---

#### Suggestions  

1. **Add a fallback test for non-standard Windows `ssh.exe` binaries**  
   * Extend Task 1 A2 to also run the same probe against the MSYS2/WSL `ssh.exe` (if present) and record the result. If the lifetime flag is ignored, the plan should flag a **policy deviation** and either (a) reject the use of that client (documented in `needs-hardware.md`) or (b) add a wrapper that enforces expiry locally.  

2. **Introduce an optional environment variable to override the pipe name**  
   * Even a simple `KEYROSTER_AGENT_PIPE` would let operators perform a phased migration (e.g., rename to `keyroster-agent-v2-<SID>`). Document the variable in the README and add a tiny test that ensures the CLI respects it. This reduces the “costly” reversibility impact while keeping the default behavior unchanged.  

3. **Explicitly hard-code the allowed client binary paths in the probe**  
   * Instead of relying on `SSH_AUTH_SOCK` being set to the pipe, confirm that the client binary discovered is the Windows-installed OpenSSH (`C:\Windows\System32\OpenSSH\ssh.exe`). If a different binary is seen, emit a warning in CI and record it in the SUMMARY.  

4. **Document the SID-verification edge cases**  
   * In `docs/security/needs-hardware.md` (or a new `docs/security/windows-sid.md`), note that elevated processes may have a different token SID and therefore cannot use the agent. Provide guidance for users who need to run the CLI from an elevated terminal (e.g., run `keyroster agent` as the normal user and export `SSH_AUTH_SOCK`).  

5. **Lock the `go-winio` version to a SHA-pinned commit**  
   * The plan pins the module version (`v0.6.2`), but the dependency firewall could be tightened by adding a `replace` directive that points to the exact commit hash, protecting against accidental minor releases that introduce regressions.  

6. **Add a macOS “lifetime-support” probe to the CI**  
   * Even if macOS users cannot yet use the Windows-style `-t` flag, a small test that checks `ssh-add -t` returns the expected exit code can be added to `cli-macos`. This would upgrade the status from “UNVERIFIED” to “VERIFIED-WITH-NOTE” in the docs, reducing future surprise.  

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Overall | Mitigation |
|------|------------|--------|---------|------------|
| **Certificates linger in the inbox OpenSSH agent** (client ignores lifetime) | Medium (depends on OS version) | High – defeats the core security promise (AUTH-03) | **Medium** | Probe A2; if failure, block Windows login in Phase 2 via a checkpoint decision and require a hardened wrapper or client upgrade. |
| **Pipe-squatting / unauthorized key injection** | Low (guarded by SDDL + VerifyServerOwner) | High – could let another user inject keys that are then used for SSH logins. | **Medium** | Ensure the SDDL is correctly generated (tests); verify SID match; consider adding a random per-process nonce in the pipe name as an additional guard. |
| **Configuration drift due to hard-coded pipe name** | Medium (future refactor) | Medium – could break user SSH configs after an upgrade. | **Low-Medium** | Provide override env-var; document migration path; keep pipe name stable across minor releases. |
| **Dependency-drift in go-winio (or transitive windows syscalls)** | Low (dependency firewall) | Low – could introduce a vulnerability in Windows builds only. | **Low** | Pin to specific commit, run `scripts/dep-firewall.sh` and `capslock-check.sh` on every PR (already required). |
| **Unverified macOS behavior** | Medium (no real-world test yet) | Medium – may cause user confusion when login fails on macOS. | **Low-Medium** | Add CI macOS probe (see suggestion 6) and clearly label the status in docs. |

**Bottom line:** The plan is solid for delivering the Windows in-memory agent and cross-platform CI, **provided the gating probes (Task 1) are executed and any failure is captured as a blocking decision**. The highest-risk area is the reliance on the Windows OpenSSH client to respect `LifetimeSecs`; a fallback strategy should be defined *before* Phase 2 is declared complete. Adding a simple environment override for the pipe name will substantially reduce migration risk without impacting the current MVP.
### 02-03 – Signer Boundary  

#### Summary  
The plan expands the Phase-1 tracer into a hardened “signer boundary” that will:

1. **Expose a new RPC** (`GetDirectory`) so the server can mirror the currently-installed directory.  
2. **Implement a full SC-4 refusal matrix** through the real Unix-socket, with a control that succeeds for every refusal case (missing assertion, replay, wrong digest, unsigned/unauthorized directory, policy lacking a WebAuthn RP, mixed-evidence types).  
3. **Add restart-re-verification** of the stored directory against the active policy and a log-consistency check that aborts startup if the DB row diverges from the last `directory_install` leaf.  
4. **Guarantee concurrency safety** for 16 parallel `LoginIssue` calls and concurrent directory installs, and verify the “directory-changed-while-issuing” race condition.  
5. **Introduce per-message-type frame caps** (64 KiB for issues, 1 MiB + 64 KiB for `InstallDirectory`/`GetDirectoryResponse`) and an exhaustive fuzzing suite for all new parsers.  
6. **Enforce the “no-mixing” rule** that a `LoginIssueRequest` may only contain `webauthn-assertion/v1` evidence and a `InstallDirectory` may only contain `admin-sshsig/v1`.  

Overall the work is well-aligned with KEY-02 (“the signer only issues when the request carries evidence it verifies itself”) and with the Phase-2 success criterion 4.

---

#### Strengths  

| Area | Why it’s strong (citing plan steps) |
|------|--------------------------------------|
| **Complete refusal coverage** | Step 1 of *Task 1* enumerates **six** distinct refusal sub-tests, each paired with a positive control. This mirrors the Phase-1 “refusal-with-control” pattern and satisfies the “every refusal has a succeeding control” rule. |
| **Policy-RP enforcement** | Step 4 in *Task 1* explicitly tests a successor policy that lacks a signed RP, expecting `no_webauthn_policy`. This guards the *root-signed RP* invariant (D-09). |
| **Concurrency guarantees** | *Task 2* defines concrete race-detector tests: 16 identical login requests, two concurrent directory installs, and a “directory-changed-before-commit” case. The required `s.mu` lock and DB-level version checks are codified. |
| **Restart consistency** | The “stored-directory-tampered” sub-test (Task 2) forces a mismatch between the DB row and the last `directory_install` leaf, ensuring the signer aborts on start-up tampering. |
| **Per-type frame caps** | *Task 3* adds `maxBodyFor` with distinct limits for `InstallDirectory`/`GetDirectoryResponse` (1 MiB + 64 KiB). This directly addresses T-02-12 (DoS via oversized frames) and removes the “unknown-type” allocation blind spot. |
| **Fuzzing breadth** | The plan creates **eleven** fuzz targets covering every new parser (login, WebAuthn, directory, GetDirectory, tlog bodies, key IDs). The CI command `FUZZTIME=10s bash scripts/fuzz.sh` guarantees they will be exercised on every PR. |
| **Dependency isolation** | The plan notes that `go-webauthn` stays **server-only** and `go-winio` stays **CLI-only**, preserving the signer’s unchanged dependency graph (per the firewall/capslock baseline). |
| **Documentation & traceability** | The requirement to write `02-03-SUMMARY.md` and to publish a PR with a deterministic title satisfies the “Delivery Protocol” and gives a permanent audit artifact. |

---

#### Concerns  

| Severity | Description (citing plan step) | Open Question / Potential Mitigation |
|----------|--------------------------------|--------------------------------------|
| **HIGH** | **Unauthenticated `GetDirectory`** – *Task 1* adds the RPC but does **not** specify any access control. Returning the entire directory (including public-key hashes, credential IDs, and SSHSIG signatures) to an unauthenticated caller could leak sensitive enrollment data (e.g. which users have which passkeys). | *Should `GetDirectory` be limited to admin-authenticated sessions (e.g. require a signed admin-SSH-SIG token) or at least require TLS client-certificate auth?* |
| **HIGH** | **Potential for “evidence-type confusion”** – The plan mandates refusal when evidence types are mixed, but the implementation details (e.g. validation order) are not described. A malformed request that places an `admin-sshsig/v1` byte-blob where the parser expects a `webauthn-assertion/v1` could cause a panic before the refusal logic runs. | *Are parsers hardened with size caps and strict type checks before content inspection?* |
| **MEDIUM** | **Directory re-verification edge cases** – The restart test (Task 2) only checks the case where the *admin set changes* and the existing directory becomes unauthorized. It does not cover a scenario where the **policy changes but still authorizes the directory** (e.g. adding a new admin while keeping the same quorum). The plan says “keep `directoryAuthorized=false`” only when signatures no longer meet the quorum **or** `CheckPolicy` fails, but the code path for a *policy-upgrade* is vague. | *Will the signer correctly preserve the `authorized` flag when a successor policy adds admins but still validates the installed directory?* |
| **MEDIUM** | **Missing refusal for malformed frames** – The new per-type caps are added, but the plan does not explicitly test a **zero-length frame** or a **frame length that exceeds `maxBodyFor` by a single byte** for *unknown* message types. The existing `unknown_message_type` test may not trigger the allocation-guard path. | *Add a fuzz-driven test that sends malformed frames for every known and unknown type to confirm the signer returns the expected `invalid_frame`/`frame_too_large` refusal before any allocation.* |
| **LOW** | **Potential TLS pinning breakage** – The plan mentions a future “TLS pin-rotation path” (D-10) but leaves the current pinning mechanism unspecified. If the server’s certificate key changes (e.g. after a Tailscale cert rotation), the CLI may reject the server, causing a denial of service for all users. | *Will the CLI fallback to a trust-on-first-use (TOFU) mode or require an admin-signed pin rotation?* |
| **LOW** | **Absence of explicit proof that `maxBodyFor` is used by `WriteMessage`** – The plan says “WriteMessage enforces the same cap”, but no test asserts that an oversized *outgoing* frame is rejected. The current test suite only checks inbound caps. | *Add a unit test that attempts to write an oversized `InstallDirectory` frame and expects an error before any bytes are sent.* |

---

#### Suggestions  

1. **Add authentication to `GetDirectory`.**  
   *Implement a lightweight admin-auth token (signed with an admin SSH key) that the client must present.* The response can then safely include the directory and signatures. If a read-only view is needed for non-admins, consider returning only the *hash* of the directory.  

2. **Add explicit “evidence-type mismatch” test.**  
   Create a table-driven test that sends a well-formed `LoginIssue` request containing an `admin-sshsig/v1` evidence blob (or any unknown type) and expects the `unknown_evidence_type` refusal **before** any decoder attempts to parse the blob.  

3. **Cover policy-upgrade path.**  
   Extend the “restart” sub-test to install a successor policy that **adds** a new admin (keeping the quorum satisfied) and verify that after restart `Signer.GetDirectory().Authorized` remains `true`.  

4. **Validate frame-size enforcement for outgoing messages.**  
   Write a unit test (`TestWriteMessageFrameCap`) that constructs an `InstallDirectory` request larger than `MaxDirectoryFrame` and confirms `WriteMessage` returns `ErrFrameTooLarge`.  

5. **Fuzz the `GetDirectoryResponse` parser.**  
   The existing fuzz list includes `FuzzParseGetDirectoryResponse`; ensure the corpus includes both *valid* and *malformed* directory payloads (e.g., truncated signatures, mismatched version numbers).  

6. **Document the TLS pinning strategy.**  
   Even if the feature is deferred, a short note in the README should state the expected workflow (e.g., “run `keyroster init` again after a certificate rotation”). This prevents operators from being locked out later.  

7. **Review audit-log granularity for the new refusals.**  
   Verify that each newly added refusal reason (`no_webauthn_policy`, `unknown_evidence_type`, `directory_quorum_not_met`, etc.) is recorded with the *exact* `Reason` enum value and includes the request hash, to keep the Merkle log tamper-evident.  

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Overall Rating | Mitigation |
|------|------------|--------|----------------|------------|
| **Leakage of directory contents via unauthenticated `GetDirectory`** | Medium (the RPC is reachable from any local process) | High (exposes user-credential bindings) | **High** | Require admin-auth token; limit returned fields to non-sensitive metadata. |
| **Panic or crash on malformed evidence type** | Low (parsers are fuzzed) | High (could cause denial-of-service) | **Medium** | Add explicit type-validation before parsing; unit test for malformed evidence. |
| **Incorrect `authorized` flag after policy upgrade** | Low (currently untested) | Medium (could incorrectly reject valid logins) | **Medium** | Add upgrade-path test; log explicit reason when `authorized` flips. |
| **Denial-of-service via oversized outgoing frames** | Low (no test yet) | Medium (could fill log or cause client failures) | **Low** | Add outbound frame-size test; ensure caps are applied symmetrically. |
| **Operator lock-out after TLS cert rotation** | Low (future work) | Medium (client cannot connect) | **Low** | Document pin-rotation workflow; provide a recovery command. |

The **critical blocker** is the unauthenticated `GetDirectory` RPC – unless this is secured, the signer will surface sensitive enrollment data to any local attacker, directly violating the “full visibility” core value (the attacker gains visibility without authorization).  

---

**Bottom line:** The plan delivers a substantial hardening of the signer boundary and satisfies the required refusal matrix and concurrency guarantees. Addressing the authentication of `GetDirectory` and tightening evidence-type validation will remove the highest-risk gaps and make the signer ready for Phase 2’s production dogfood. Once those open questions are resolved (via design decisions or added tests), the plan can proceed to PR creation and the merge gate with confidence.  
### 02-04 – Audit-login & successor-policy plan  
**Phase:** 02-passkey-login-mvp  **Wave:** 3  **Owner-gate:** PR p02/04-audit-login  

> *Goal:*  make every short-lived login certificate provably authorized by the user’s passkey (and by a quorum-signed directory) and give operators a safe, documented way to add the WebAuthn RP to an existing deployment.

---

#### Summary  

| Item | What the plan does | Where it lives |
|------|--------------------|----------------|
| **`keyroster root successor-policy`** | Generates a *canonical* successor of the current root policy that adds (or changes) `webauthn_rp_id` and optional origins; refuses no-ops; prints a one-way warning. | `cmd/keyroster/root.go` (new switch case) |
| **Login-issue parsing** | `wire.ParseLoginIssueSigningBytes` parses the exact bytes that the signer logged for a login issuance, guaranteeing a loss-less round-trip. | `internal/wire/login.go` |
| **`keyroster audit verify`** | New verification branches: `verifyDirectoryInstall` (quorum-signed, successor-chained, matches policy version) and `verifyLoginIssue` (checks RP, single WebAuthn evidence, re-runs the WebAuthn verifier, recomputes principals/TTL, checks certificate fields, key-ID, time bounds). | `internal/audit/verify.go` |
| **End-to-end test** | `TestAuditLoginAcrossPolicyChange` spins a live signer, installs a RP-less policy, creates the successor, signs & restarts, installs a directory, issues a login, exports the log and runs `audit verify`. | `test/e2e/audit_login_test.go` |
| **Tamper-suite** | New fuzz / unit cases that deliberately corrupt a valid log (assertion signature, principals, credential, directory chain, admin signatures, TTL, etc.) and expect `audit verify` to reject with a precise error label. | `internal/audit/verify_test.go`, `internal/audit/fuzz_test.go` |
| **Runbook update** | Adds a “Change the policy: successor policy (add WebAuthn RP)” section with the warning and the exact command sequence. | `docs/runbooks/root-ceremony.md` |
| **Release / PR flow** | Scripted creation of branch `p02/04-audit-login`, automated CI gates, auto-merge after owner approval, and a `02-04-SUMMARY.md` artifact. | `scripts/…` (as referenced) |

If the plan lands, auditors will be able to **prove** that every login certificate recorded in a bundle was:

* issued under the **policy version** that contained the RP,  
* backed by a **single WebAuthn assertion** that matches the user’s credential stored in the directory, and  
* limited to the **principals and TTL** the directory defines.

---

#### Strengths  

| Area | Why it’s strong (tied to plan steps) |
|------|--------------------------------------|
| **Security-by-design** – The audit now re-runs the *same* WebAuthn verification that the signer performed (see `verifyLoginIssue → webauthn.VerifyAssertion`). This defeats the “compromised signer can log bogus approvals” threat (T-02-17). |
| **One-way RP binding** – The mandatory warning in the successor-policy command (truth #1) makes the irreversible nature of RP IDs explicit, satisfying D-09 and reducing operator surprise. |
| **Full-chain enforcement** – `verifyDirectoryInstall` validates *both* the successor hash and the admin-quorum signature against the *policy version* that is in force, closing the gap identified in Phase 1 (directory installs were previously “kind 7” but never checked). |
| **Tamper-suite** – By programmatically corrupting every relevant field (signature, principal set, credential ID, etc.) the plan demonstrates that the verifier is not merely “happy-path” but actively validates each invariant. |
| **Test coverage** – The live-signer end-to-end test (Task 1) exercises the *entire* rotation flow, from RP-less policy to a working login, under real `sshd` binaries. This is exactly the “real-world” proof of concept the roadmap demands (success criteria 1-5). |
| **Documentation** – Adding the step-by-step “successor-policy” section to the runbook gives operators a repeatable, auditable procedure, matching the “no-magic-black-box” principle of the project. |
| **Low-impact dependency change** – WebAuthn verification stays **server-only** (`go-webauthn` added only to `keyroster-server`). The signer binary remains free of new third-party code, preserving the strict dependency firewall. |

---

#### Concerns  

| Severity | Concern | Plan step(s) involved | Open question / mitigation |
|----------|---------|----------------------|----------------------------|
| **HIGH** | **Incorrect RP validation could allow IP-origin or malformed hostnames**, breaking the one-way guarantee. | `successor-policy` flag handling (truth #1) – currently only checks “not a no-op”. | *Is there a definitive whitelist/validation routine for RP IDs (e.g., DNS-only, no-underscore, no-port)?* Should the command reject IP literals and non-FQDN tailnet names at parse time? |
| **HIGH** | **Audit verifier must re-load the directory for every `login_issue` entry** – performance on large logs (tens of thousands of entries) may become O(N²). | `verifyLoginIssue` logic (Task 2). | *Will the verifier cache the directory version when it changes, or will it re-parse the same JSON repeatedly?* If not, a scalability test is needed. |
| **MEDIUM** | **Canonical-JSON drift** – the plan assumes the “canonical bytes” produced by `ParsePolicy` and `ParseDirectory` are stable across Go releases. Any change (e.g., map iteration order) breaks the ability to recompute the signing bytes. | All “write canonical” steps (policy successor, directory install). | *Do we have regression tests that serialize → deserialize → serialize and compare byte-for-byte across Go versions?* May need a go.mod `go=1.22` lock and a dedicated test. |
| **MEDIUM** | **Single-evidence assumption** – the verifier rejects login_issue entries that contain more than one evidence item. Future extensions (e.g., JIT approvals) may need multiple evidences. | `verifyLoginIssue` check for “exactly one webauthn-assertion”. | *Is the “exactly one” rule hard-coded or configurable?* If future phases need a composite proof, the current implementation would need a breaking change. |
| **LOW** | **Error-message ergonomics** – failing checks are reported as “entry <N> (login_issue): <check>”. Operators may struggle to locate the offending leaf in large exports. | `verifyLoginIssue` error strings. | *Would adding a reference to the leaf’s hash (or index) improve traceability?* |
| **LOW** | **Dependency addition (go-winio)** – the CLI will now import `github.com/Microsoft/go-winio` for Windows agent access. This adds a Windows-only binary dependency that must be vetted in the capslock baseline. | Task 2 (tamper suite mentions Windows pipe). | *Has the capslock baseline been updated to allow go-winio under the `windows` build tag?* If not, CI may fail later. |

---

#### Suggestions  

| Suggestion | Why it matters | Where to implement |
|------------|----------------|--------------------|
| **Validate RP ID strictly** – reject IP literals, enforce RFC 952/1123 hostnames, and reject tailnet names that contain a dot-less suffix (e.g., “my-tailnet”). Add a helper `validateRP(host string) error`. | Addresses HIGH concern #1; makes the one-way warning reliable. | In the new `runRootSuccessorPolicy` implementation (cmd/keyroster/root.go). |
| **Directory cache in audit verify** – keep the last-seen `DirectoryVersion` and its parsed object; only re-parse when the entry’s `DirectoryVersion` changes. | Mitigates potential O(N²) runtime for large logs (MEDIUM concern). | `internal/audit/verify.go` – add a simple map or struct to hold the current directory. |
| **Canonical-JSON round-trip test** – create a test that marshals a policy/directory, unmarshals, re-marshals and asserts equality of bytes. Run it under `go test -run TestCanonicalRoundTrip`. | Catches accidental map-order changes (MEDIUM concern). | New test file `internal/trust/canonical_test.go`. |
| **Make evidence count configurable** – expose an internal constant `maxEvidence = 1` (or a future-proof slice). Document that more evidences will be supported in Phase 4. | Future-proofs the “exactly one evidence” rule (LOW concern). | `internal/audit/verify.go`. |
| **Rich error reporting** – prepend the leaf hash (e.g., `leafHash=<hex>`), and optionally the raw Base64-encoded entry, to the error message. This aids operators when scanning large exports. | Improves operability (LOW concern). | `verifyLoginIssue` error generation. |
| **CI capslock update** – ensure `go-winio` is whitelisted under the `windows` build tag and that the `-tags windows` variant passes `scripts/dep-firewall.sh`. | Prevents a downstream CI break when the Windows agent code is compiled. | Update `scripts/dep-firewall.sh` and `test/capslock/` baseline. |
| **Add a “dry-run” flag** to `root successor-policy` that prints the new policy JSON (and its SHA-256) *without* writing to disk. This lets operators preview the RP change before signing. | Low-risk usability improvement, no impact on security. | Extend the command’s flag set; the flag can be mutually exclusive with `--out`. |

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Overall | Mitigation |
|------|------------|--------|---------|------------|
| **Incorrect RP binding (operator mistake or validation bypass)** | Medium (depends on operator diligence) | Critical – could invalidate all existing passkeys, forcing a painful re-enrollment. | **High** – enforce strict RP validation (see suggestion). |
| **Audit verifier accepts malformed logs** (e.g., directory version mismatch, missing evidence) | Low (tests cover many cases) | Critical – defeats the whole visibility guarantee. | **High** – expand test matrix (tamper suite) and add canonical-JSON test. |
| **Performance degradation on large logs** | Medium (future logs may grow) | Moderate – could make nightly audit runs time-out. | **Medium** – implement directory caching. |
| **Dependency-firewall regression (go-winio)** | Low (single Windows-only add) | Low – just CI failure. | **Low** – update capslock baseline promptly. |
| **Future incompatibility when adding more evidence types** | Low (currently one-time) | Low – would require a version bump; not a security risk now. | **Low** – document the constant as future-configurable. |

Overall, **the plan is high-value** (it delivers the core visibility promise for Phase 2) and **acceptable** provided the highlighted validation and performance mitigations are applied before merge.

---

#### Bottom-line Recommendations  

1. **Implement strict RP ID validation** (suggestion 1) before the `successor-policy` command is merged.  
2. **Add the directory cache** to `audit verify` (suggestion 2) to keep CI jobs fast and avoid future scalability surprises.  
3. **Add the canonical-JSON round-trip test** (suggestion 3) now; it is cheap and protects against silent breaking changes.  
4. **Update the capslock baseline** for `go-winio` and confirm the Windows agent test passes on the CI matrix.  
5. **Consider the dry-run flag** (suggestion 6) – it adds safety at negligible cost.

Once these items are addressed, the plan can move through the owner gate with confidence that it meets **high-security, full-visibility** goals without introducing undue operational risk.
### 02-05 – Software-CA Backend & Evaluation-Only Warning  

#### Summary  
Plan 02-05 introduces a **software keystore backend** that stores the CA’s online Ed25519 keys encrypted with an age-scrypt “.age” file, adds a **Status** RPC that reports each key’s custody (`software` vs. hardware), and wires a **single-source banner** (`internal/custodytext.SoftwareCABanner`) into every CLI issuance path. The plan also adds extensive unit- and e2e-tests, updates the caps-lock baseline for the new age dependencies, and records the banner wording in `docs/security/custody.md` (owner-approved via a checkpoint).  

If implemented as described, the plan fulfills **KEY-06**: an operator can run a signer with encrypted software keys for evaluation, and the system will loudly warn that the instance must not be used for production access.

---

#### Strengths  

| Area | What the plan does well (cites) |
|------|--------------------------------|
| **Clear separation of custody** | D-18 is enforced: the signer, not the server or CLI, is the sole source of custody information (`Signer.Status` returns the custody for each role). This satisfies the “custody comes from the signer” prohibition (see *must-haves → prohibitions*). |
| **Deterministic warning path** | The banner is produced by a **single constant** (`SoftwareCABanner`) and is printed by the CLI **before every issuance** (`cmd/keyroster/ca.go` step 2). The same function is used by the UI later (02-06), guaranteeing textual consistency. |
| **Secure pass-phrase handling** | The backend requires a **0600 pass-phrase file** (or a systemd credential) and rejects group/other readable files, short passphrases, and any source from argv/env (must-haves → truths 2). The plan explicitly clears the pass-phrase slice after use. |
| **Age-based encryption** | Re-uses the **age+scrypt** pattern already present in `internal/rootceremony/keygen.go` (read-first list), which is well-audited, reproducible, and has a small dependency surface. |
| **Test coverage** | The plan specifies **unit tests** for every failure mode of the software backend (e.g. wrong file mode, too-short passphrase, fingerprint mismatch) and an **e2e test** that runs a full CA init → status → issuance → real `sshd` verification flow. It also adds **FuzzParseStatusResponse** and caps-lock verification. |
| **Dependency gating** | The new packages (`filippo.io/age`, `filippo.io/age/armor`, `golang.org/x/crypto/scrypt`) are added **only to the signer graph**, and the caps-lock check updates the baseline accordingly. This respects the existing `scripts/dep-firewall.sh` and `test/capslock/` policy. |
| **Owner checkpoint for wording** | By making the banner text a **human-approved checkpoint** (Task 2), the plan protects against accidental wording changes that could drift from the documented “evaluation-only” warning. |
| **No hidden overrides** | The “no suppression” prohibition is addressed with explicit tests that verify the banner always appears when any key is software-custody. The plan also ensures the signer never reports a different custody than it actually holds (`Signer.Status` re-checks keys at start). |

---

#### Concerns  

| Severity | Concern | Plan step(s) | Why it matters (open question) |
|----------|----------|--------------|--------------------------------|
| **HIGH** | **Potential leakage of the pass-phrase via error messages** – the plan states “wrong passphrase returns an error that does *not* echo the passphrase,” but the exact error handling code is not shown. If the backend wraps the `age` decryption error directly, the underlying error string may include the user-supplied pass-phrase (e.g. “invalid passphrase ‘foobar’”). | Must-have truth 2 (backend error handling) | *Open question*: Does `software.go` sanitize or wrap the error before returning it to the CLI? A test asserting the exact error text is needed. |
| **HIGH** | **Race condition between `ca-init` and `Status`** – the status response is built from the signer’s in-memory bundle **and** re-checks the keys on each call. If the signer reloads its bundle (e.g. after a policy update) while a CLI issues an `ca issue`, the banner could be printed based on stale custody data, or the CLI could miss the warning entirely. | Task 1, step “Signer.Status runs under s.mu … re-checked at start” | *Open question*: Is the `mu` lock held for the whole status generation **and** for the issuance flow? Does the CLI obtain a fresh status *right before* each issuance, or could a stale cache be used? |
| **MEDIUM** | **File-mode enforcement on Windows** – the plan requires the pass-phrase file to be mode 0600. On Windows, `os.Chmod` does not enforce POSIX bits, and the underlying NTFS ACL may allow broader access. The plan does not address Windows-specific handling. | Must-have truth 2 (pass-phrase file check) | *Open question*: How does the backend verify file permissions on Windows, and what fallback does it use? Should the plan add a Windows-specific permission audit (e.g., deny if file is readable by “Everyone”)? |
| **MEDIUM** | **Potential for “soft-fail” banner suppression in scripts** – the banner is printed to `stderr`, but callers could discard it (e.g., `keyroster ca issue 2>/dev/null`). The plan does not forbid redirection. While this is inevitable for any CLI output, a production-risk assessment might require the warning to be emitted on a **separate log channel** (e.g., syslog) or to set a non-zero exit code when software custody is present. | Must-have prohibition 1 (no suppression) | *Open question*: Are there tests that verify the banner remains present even when `stderr` is redirected? If not, a deliberate “quiet-mode” flag could be introduced later—should the plan pre-emptively block that flag? |
| **MEDIUM** | **Status encoding size limit** – the `wire/status.go` struct limits the response to **256 KiB** (`MaxStatusFrame`). With five roles the payload is tiny, but the plan does not discuss future expansion (e.g., many more roles or larger directory hashes). If a future change adds more fields, the Status response could silently truncate. | `wire/status.go` size constant (Task 1) | *Open question*: Is there a test that verifies `StatusResponse` marshals/unmarshals correctly at the limit, and that the size constant is deliberately chosen for extensibility? |
| **LOW** | **Caps-lock baseline drift** – the plan adds three new capability pairs (age, armor, scrypt). If future plans add other age-related packages (e.g., `filippo.io/age/commit`), the baseline may diverge and cause CI failures. The plan mentions “review each pair,” but does not lock the exact commit hashes. | Task 3, step 3 (caps-lock review) | *Open question*: Are the versions pinned in `go.mod` to a specific commit/tag? If they remain `v0.x.x` without a `replace`, a later upstream bump could introduce new symbols not captured in caps-lock, potentially expanding the attack surface. |
| **LOW** | **Documentation-test coupling** – the test that the doc contains the banner (`custodytext_test.go`) depends on exact wording. Any future re-phrasing (owner-approved) will require updating the test. This is intentional, but it also introduces a **tight coupling** that may cause accidental test failures during minor doc edits. | Task 2 checkpoint & Task 3 test | *Open question*: Is the test tolerant to whitespace changes, or does it require an exact string match? A more robust approach could extract the banner via a helper function rather than a hard-coded literal. |

---

#### Suggestions  

1. **Sanitise error messages** – Wrap any error from `age.Decrypt` with a generic message like “invalid pass-phrase” before returning it. Add a dedicated unit test that feeds a wrong pass-phrase and asserts the error string does **not** contain the supplied phrase.

2. **Atomic status-check before issuance** – Refactor the CLI’s issuance flow so that it **first calls** `signerclient.Status`, **immediately aborts** if any key has `software` custody, and only then proceeds to the signing request. Keep the `mu` lock held across both RPCs (or cache the status in the signer but expose a “must-be-software-free” flag). Document the ordering in a comment.

3. **Windows permission guard** – On Windows, after reading the pass-phrase file, call `syscall.GetFileAttributes` (or the Go `os` equivalent) and reject the file if the `FILE_ATTRIBUTE_READONLY` bit is not set **or** if the ACL grants access to any group other than the current user. Add a Windows-specific unit test.

4. **Consider a dedicated “warning” exit code** – Add a non-zero exit status (e.g., `2`) when the banner is printed due to software custody, and update the e2e test to assert the exit code. This makes accidental silencing via redirection less likely for scripts that check `$?`.

5. **Future-proof Status size** – Introduce a test that builds a `StatusResponse` with **the maximum allowed number of keys** (e.g., 255) and verifies that marshaling succeeds. If the limit is ever raised, the constant can be updated in a single location.

6. **Pin age dependencies** – Ensure `go.mod` pins the exact commit SHA for `filippo.io/age`, `filippo.io/age/armor`, and `golang.org/x/crypto/scrypt`. Add a comment referencing the caps-lock audit, so future maintainers know why the pin is there.

7. **Make the doc-banner test more robust** – Instead of a raw string match, have `custodytext_test.go` retrieve the banner via `SoftwareCABanner([]string{"user","host","machine","ops","log"})` and compare that to the snippet extracted from `docs/security/custody.md`. This decouples the test from formatting quirks while still guaranteeing verbatim consistency.

8. **Explicitly document “no suppression”** – Add a comment near the banner print call stating: “Do not allow suppression via flag, env var or redirection; this is a security-critical warning mandated by D-18.”

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Mitigation (already in plan or suggested) |
|------|------------|--------|-------------------------------------------|
| **Leak of pass-phrase via error** | Medium (depends on current error wrapping) | High – could allow an attacker with console access to see the secret. | Ensure error sanitisation (Suggestion 1). |
| **Missing banner due to stale status** | Low–Medium (depends on concurrency model) | High – operator may think the instance is production-ready. | Atomic status-check before issuance (Suggestion 2). |
| **Pass-phrase file readable on Windows** | Medium (file-mode check ineffective) | Medium – same as above but limited to Windows deployments. | Windows-specific ACL check (Suggestion 3). |
| **Banner silencing via redirection** | Low (requires intentional script) | Medium – automated tooling could ignore the warning. | Dedicated non-zero exit code (Suggestion 4). |
| **Caps-lock baseline drift** | Low (versions typically stable) | Low – CI failure, not a security breach. | Pin versions (Suggestion 6). |
| **Inconsistent documentation** | Low (test catches) | Low – operator confusion. | Robust doc-test (Suggestion 7). |
| **Future Status payload overflow** | Low (current role count small) | Low – could cause denial of status RPC. | Test max keys (Suggestion 5). |

Overall, the plan’s core security guarantees (custody reported by the signer, loud evaluation-only banner, strong pass-phrase enforcement) are solid. The main residual risks revolve around **error-message leakage** and **Windows permission handling**, both of which can be mitigated with relatively small code changes and additional tests.

---  

**Bottom line:** Plan 02-05 is well-structured and aligns with the project’s “security-first, simplicity-first” ethos. By addressing the open questions above—especially error sanitisation and Windows file-mode enforcement—the plan can be merged with high confidence that the software-CA path will be both **auditable** and **clearly communicated** as evaluation-only.
### 02-06 – Review of the “keyroster-server + keyroster init” Plan  

#### Summary  
The plan builds the first public-facing component of the MVP: a Linux-only `keyroster-server` that serves a tiny, CSP-hardened web UI and a `/api/v1/trust` endpoint, and a new `keyroster init` CLI sub-command that pins TLS roots and the CA-bundle before writing a 0600 config file.  

Key-level goals that the plan claims to satisfy are:

| Goal | Where the plan addresses it | Comments |
|------|----------------------------|-----------|
| **UI-01** – server-rendered UI, no npm, strict CSP | `internal/server/web/*` (templates, embed, CSS) + `internal/server/headers.go` (CSP, HSTS, COOP, …) | ✅ |
| **KEY-06** – show an “evaluation-only” banner whenever the signer reports software custody | `custodytext.SoftwareCABanner` rendered from `render.go`, header `Keyroster-Custody` added in `signer.go`, CLI prints banner via `serverclient.Client.checkCustody` | ✅ |
| **PLAT-05** – server runs on Linux only, other OSes abort early | `cmd/keyroster-server/main.go` built with `//go:build linux`, `main_other.go` exits with a clear error | ✅ |
| **D-10** – TLS from files, reload on change or SIGHUP, warning when <14 d left | `tlsreload.go` (certificate holder + watch), `serve.go` wires SIGHUP, warning logic documented in research | ✅ |
| **D-09 / D-11** – RP ID never comes from flags, only from the signer's root-signed policy | `internal/server/signer.go` caches the RP from `signerclient.Status`; server start aborts if RP missing or cert does not cover it | ✅ |
| **End-to-end e2e** – bootstrap signer → server → `keyroster init` → banner on CLI and UI | `test/e2e/server_test.go` assembles a full chain, asserts banner presence, checks CSP header, validates TLS-pin handling | ✅ |

Overall the plan is well-structured and the tasks are broken into traceable units (binary, server core, client, CLI, tests, systemd units, runbook, PR).  

Below are *source-dependent* concerns phrased as open questions, grouped by impact.  

---

#### HIGH-SEVERITY CONCERNS  

| # | Concern (citing plan step) | Why it matters | Open question / mitigation |
|---|----------------------------|----------------|----------------------------|
| H1 | **RP immutability & certificate-RP binding** – Step “The server refuses to start when the signer reports no WebAuthn RP, or when the TLS leaf does not cover the RP” (Task 1, bullet 3). | If the server ever starts with a mismatched certificate the WebAuthn ceremony will succeed against the RP in the policy but the TLS channel will present a different hostname, allowing a *man-in-the-middle* to harvest the assertion. | *How does the server verify that the leaf certificate’s `SubjectAlternativeName` contains the exact RP string?* Is the comparison performed with an exact string match (including possible trailing dot) and with case-folding per RFC 5280? Should the check also enforce that the leaf’s `NotAfter` exceeds the policy-defined `ValidAfter` window? |
| H2 | **Signer-status caching** – Step “signer.go: a status cache (TTL 5 s, refreshed under a mutex) holding the parsed policy, the RP and the custody list” (Task 1). | If the signer is restarted or its policy changes, stale RP data could linger for up to 5 s, potentially allowing a *window* where the server presents a cert that no longer matches the policy. | *What happens if the cached status becomes unavailable (signer crash) after the server has already started?* Does the server continue to serve with the stale RP (risk) or does it transition to a 503 health endpoint (safer)? Should the cache TTL be configurable or forced to zero for production? |
| H3 | **TLS reload error handling** – Step “Reload swaps in a new valid certificate. It keeps the old one, logs an error and keeps serving when the new files are a mismatched cert/key pair, an expired leaf, a leaf for another hostname or an unreadable file.” (Task 2) | If a mis-configured renewal replaces a valid cert with an invalid one *and* the code fails to keep the old cert (bug in the atomic pointer logic), the server could go down unexpectedly or, worse, start serving a cert that does **not** match the RP. | *Is the atomic pointer reset only after successful validation, or could a race allow a partially written cert to be swapped in?* Have the tests exercised the exact failure mode where the cert file is readable but the key is missing (or vice-versa)? |
| H4 | **Root-pin vs TLS-pin handling in `keyroster init`** – Step “keyroster init … prints the TLS root pins, requires at least one `--tls-pin`, refuses when a pin is not observed” (Task 1). | Pinning the *TLS* root is separate from pinning the *trust-bundle* root. A user could mistakenly trust the wrong root (e.g., a CA used for the server’s TLS cert but not for the CA bundle) and the CLI would accept the server, undermining the “software-key warning”. | *Does `init` verify that the TLS chain’s *leaf* is the same leaf that the server later serves via `/api/v1/trust`?* If the server presents a different leaf (e.g., after a cert rotation) the CLI could accept a new TLS chain that still satisfies the pin but whose leaf no longer covers the RP. Is there a check that the leaf’s SAN still matches the RP after the pin verification? |
| H5 | **Keyroster-Custody header format & integrity** – Step “Every response carries `Keyroster-Custody` with each role's custody” (Task 1). | The header is displayed to users but also parsed by the CLI to decide whether to print the evaluation-only banner. If an attacker can inject or modify this header, the CLI may *silently* suppress the warning. | *Is the header value signed or otherwise authenticated?* The plan only says the signer reports custody; is there a cryptographic binding between the header value and the signer’s status? If not, a compromised server could spoof “hardware custody” and hide the warning. |
| H6 | **Hostname resolution for `keyroster.localhost` in CI** – Step “If it does not resolve on the GitHub runner, add a hosts entry” (Task 1). | The e2e test relies on DNS resolution of a hostname that is also the RP. If the runner’s resolver treats `localhost` specially (e.g., resolves to IPv6 `::1` only) or blocks custom hosts entries, the test may falsely pass/fail, masking a real-world failure. | *Has the plan been verified on a clean GitHub runner image (no prior `hosts` modifications)?* Would a test that explicitly checks `net.LookupHost("keyroster.localhost")` be safer? |
| H7 | **Cross-Origin-Protection implementation** – Step “Every unsafe-method request passes through `http.CrossOriginProtection` (UI-01)” (Task 1). | If the middleware is bypassable (e.g., via a custom `Content-Type` or by using a `GET` with a body) an attacker could force a state-changing request from another origin. | *What exact checks does `CrossOriginProtection` enforce?* Does it reject any request whose `Origin` header differs from the server’s RP, regardless of method? Are pre-flight (`OPTIONS`) requests correctly handled? |

---

#### MEDIUM-SEVERITY CONCERNS  

| # | Concern (citing plan step) | Why it matters | Open question / mitigation |
|---|----------------------------|----------------|----------------------------|
| M1 | **Systemd unit hardening coverage** – Step “keyroster-server.service hardens many kernel options” (Task 3). | The list is extensive, but a few critical options that protect against *privilege escalation* (e.g., `ReadWritePaths=`, `ProtectKernelModules=`) are missing from the summary. | *Is `ReadWritePaths=` needed for `/etc/keyroster/tls/*`?* The unit currently uses `ReadOnlyPaths=/etc/keyroster/tls` but writes a log file – where does that go? |
| M2 | **Configuration file permission handling** – Step “`Config.saveConfig` writes 0600 JSON under a 0700 directory” (Task 1). | On Windows and macOS the default directory may have more permissive ACLs; the plan mentions only Linux. | *Will the same permission enforcement work on macOS where `os.UserConfigDir()` points to `$HOME/Library/Application Support/keyroster`?* Should we add a runtime check that the file mode is exactly 0600 even on non-Linux OSes? |
| M3 | **Banner display frequency** – Step “CLI prints the custody banner once per run” (Task 2). | If a user runs a long-lived CLI loop (e.g., a wrapper script that calls `keyroster login` repeatedly) the banner may disappear after the first call, reducing visibility. | *Should the banner be printed on every command that contacts the server, not just the first per-process?* The plan currently says “once per Client”. |
| M4 | **Test-only “addLogKey” helper removal** – Step “remove the unused `addLogKey` helper (deferred CI debt)” (Task 1). | Some existing e2e logs rely on the presence of that helper to inject a log-key into the signer; removing it could break unrelated tests. | *Has the plan verified that no other test in the repository still imports or references `addLogKey`?* A quick grep could confirm. |
| M5 | **Embedded static assets’ MIME types** – Step “static/ folder served with explicit content types” (Task 1). | If the CSS file is served with `text/plain` instead of `text/css`, browsers may ignore it; more importantly, mis-labelled content could violate CSP. | *Do the tests assert the `Content-Type` header for `/static/app.css`?* If not, consider adding a unit test. |

---

#### LOW-SEVERITY CONCERNS  

| # | Concern (citing plan step) | Why it matters |
|---|----------------------------|----------------|
| L1 | **Dependency firewall** – The plan adds `go-winio` to the CLI for Windows named-pipe support (Task 1). | The firewall script should be updated to allow this dependency only behind a build tag (`windows`). Verify that the firewall still blocks the `go-webauthn` import from the signer binary. |
| L2 | **Root-pin format** – The plan stores pins as `sha256/...` strings. | Ensure the format matches the helper `trust.MatchPins` (which expects `sha256/base64`). A mismatch would cause a silent failure. |
| L3 | **Documentation wording** – The runbook must contain “UNVERIFIED until the homelab install (02-13)”. | It's easy to forget to mark a paragraph as UNVERIFIED; a simple `<!-- UNVERIFIED -->` tag could help automated checks. |
| L4 | **CI hosts file modification** – Adding a line to `/etc/hosts` requires `sudo`. | In the GitHub runner, `sudo` may be disabled for the default `ubuntu-latest` image. Confirm that the workflow grants permission (`runs-on: ubuntu-latest` + `sudo: true`). |

---

#### Suggestions & Improvements  

1. **Add an explicit health-check endpoint for the signer** (`GET /healthz` already exists, but make the server *fail* (return 503) if the cached signer status is older than, say, 30 s). This eliminates the “stale RP” window.

2. **Make the RP-certificate validation stricter** – compare the leaf’s SAN exactly to `status.Policy.WebAuthn.RPID` (case-folded, punycode-decoded). Consider rejecting wildcard certificates altogether (they’re not allowed for RP anyway).

3. **Cryptographically bind the `Keyroster-Custody` header** – e.g., sign the header value with the CA’s private key and include the signature in a second header (`Keyroster-Custody-Sig`). The CLI can then verify the signature, preventing a malicious server from falsifying custody.

4. **Expose the TLS-leaf fingerprint in the `/api/v1/trust` response** (in addition to the bundle). `keyroster init` could then double-check that the leaf still matches the RP after pinning, preventing a silent cert rotation attack.

5. **Test the reload-watcher on a *deleted* certificate** – the current tests cover mismatched pairs, expiry, host mismatch, but not the case where the files disappear entirely. The watcher should keep the last-good cert and log a clear error.

6. **Add a unit test for `CrossOriginProtection`** that sends a malformed `Origin` header and verifies a `403` response. This will ensure the middleware correctly rejects any request that does not match the RP origin.

7. **Document the exact format of `Keyroster-Custody`** (e.g., `role=host;alg=ed25519;custody=hardware;fp=ab:cd:…`). This makes downstream parsers (CLI, future audit tools) robust to future schema extensions.

8. **Guard the systemd timer’s environment file** – ensure `tailscale-cert.env` is owned by `root:keyroster-server` and has mode `0640`. Include a `ProtectSystem=strict` and `ReadWritePaths=` whitelist for that file.

9. **Add a CI matrix entry for macOS** (even if the binary aborts) to verify that the “Linux-only” guard truly prints the expected error message and exits with non-zero status. This satisfies the “PLAT-05 – other OSes exit with an error” requirement.

10. **Make the CSP constant testable** – expose it via a public variable (e.g., `internal/server.CSPHeader`) and assert its exact string in a unit test. This prevents accidental drift when the header is edited later.

---

#### Risk Assessment  

| Risk Level | Likelihood | Impact | Primary Mitigations (already in plan) | Additional recommended mitigations |
|------------|------------|--------|--------------------------------------|-----------------------------------|
| **Critical** – RP mismatch leading to successful phishing or credential theft. | Medium (depends on operator correctly rotating certs) | High (full break of the authentication chain) | Server aborts on RP/cert mismatch; reload keeps last good cert. | Add cryptographic binding of custody header, expose leaf fingerprint in `/api/v1/trust`, and double-check leaf after TLS-pin verification. |
| **High** – Signer status becomes stale after a restart, allowing a window with wrong RP. | Low-Medium (5 s cache) | Medium-High (could allow a short-lived phishing attempt) | 5 s TTL cache, health endpoint. | Reduce cache TTL to 0 or make the server reject requests when signer is unreachable for >5 s; add explicit “signer-down” 503 for all routes. |
| **Medium** – TLS reload silently swaps in an invalid cert (e.g., mismatched key) due to race. | Low (covered by tests) | Medium (server downtime, loss of availability) | Atomic pointer swap only after validation; tests for mismatched pair. | Add test for missing key file, and for a cert whose SAN is empty; log an explicit error and emit a metric. |
| **Medium** – Banner suppression via forged `Keyroster-Custody` header. | Low (requires compromised server) | Low-Medium (reduces visibility, but does not affect core security) | Banner driven by signer-reported custody; CLI checks header. | Sign the header (see Suggestion 3). |
| **Low** – CI host-file hack failing on future runner images. | Low (runner images rarely change) | Low (test failures only) | Plan mentions adding a hosts entry if needed. | Add a pre-step that verifies resolution and fails early with a clear message. |

Overall the plan **covers the core security requirements** (RP binding, TLS pinning, custody banner) and includes a solid test suite. The open questions above should be addressed – either by adding clarification to the design docs, extending the test matrix, or implementing the suggested hardening steps – before the merge gate is opened.

---

#### Bottom Line  

*The plan is ambitious but well-scoped. If the open questions are resolved (especially H1–H5) and the suggested mitigations are incorporated, the resulting `keyroster-server` and `keyroster init` will satisfy UI-01, KEY-06, PLAT-05 and D-10 without introducing unacceptable risk.*
### 02-07 – Review of “Admin-Signed API & Invite Flow”

#### TL;DR
The plan puts the right emphasis on **policy-admin-only SSH-SIG authentication**, **one-time invite tokens**, and **clear separation between “pending” DB rows and the signer’s authoritative directory**.  The overall flow matches the success-criteria for AUTH-01 and UI-01, and the artefacts (adminauth package, serverdb schema, rate-limit middleware, CLI `user add`) are well scoped.

Below are the points that need clarification or tightening before the work can be merged.

---

### 1. Strengths  

| Area | Why it’s good (citing plan steps) |
|------|-----------------------------------|
| **Zero-trust admin API** | Step `internal/adminauth/adminauth.go` defines a namespace (`keyroster/admin-api/v1`) and a signed-message format that mirrors the existing admin-evidence format (D-02). This keeps the “payload-authenticated, not pipe-authenticated” guarantee from Phase 1. |
| **Invite token handling** | The migration `0001_server.sql` stores `invite_hash` only (Step “invite_hash column”), and the plan explicitly forbids logging raw tokens.  This follows the “hashed-only, never logged” rule from the threat register (T-02-34). |
| **Replay protection** | `admin_nonces` table + per-request nonce verification (Step “UseNonce”) implements the replay-prevention described in D-02. |
| **Rate-limiting** | `ratelimit.go` adds per-IP `rate.Limiter` with explicit limits (60/min burst 20 for admin, 30/min burst 10 for invites).  The limits are documented in the threat register (T-02-36) and provide an early DoS barrier. |
| **CLI ergonomics** | `keyroster user add` prints a ready-to-paste `keyroster init …` line that includes the server URL, TLS pins, root pins, threshold, and `--user`.  This satisfies the “invite URL + init line” truth clause in the **must-haves**. |
| **Test coverage** | The plan includes a full e2e `TestUserAddInvite` plus unit tests for adminauth, serverdb, server, and CLI.  The scope matches the “TDD=true” flag and the required verification steps. |
| **Dependency hygiene** | The only new dep is `golang.org/x/time` which is already owner-locked.  The plan acknowledges the firewall/capslock checks for the new `go-winio` import on Windows. |

---

### 2. Concerns  

| Severity | Concern | Relevant Step(s) | Open Question / Request for Clarification |
|----------|----------|-------------------|-------------------------------------------|
| **HIGH** | **Admin-key discovery & fallback** – The CLI `keyroster user add` expects the admin key to be `--admin-key` or taken from the agent.  If the user supplies a *wrong* fingerprint, the CLI will error out, but the plan does not specify the exact wording or whether the CLI will *attempt* to enumerate agents to suggest the correct key.  Ambiguous UX could lead admins to retry with an un-approved key, leaking the error to a potential attacker. | `cmd/keyroster/user.go` – “admin key comes from –admin-key or config.AdminKey; with neither, it refuses with instructions.” | *How will the CLI surface the failure?* Will it include the fingerprint that was found but not authorized, or only a generic “admin key not found” message?  Consider a constant-time lookup to avoid timing side-channels that reveal the presence of an admin key. |
| **HIGH** | **Nonce lifetime & cleanup** – `admin_nonces` table stores a nonce with an expiry timestamp, but the plan does not describe a periodic purge or a background worker that removes stale rows.  Over time the table could grow without bound (DoS). | `admin_nonces` schema, `UseNonce` description. | *Is there a GC job?* Will the per-request handler delete expired rows automatically, or is a separate janitor required?  Clarify the lifecycle to guarantee bounded DB size. |
| **MEDIUM** | **Clock-skew handling** – The verification window is ±120 s (MaxSkew).  In distributed deployments (e.g., a server behind NTP vs. an admin machine on a laptop) this may be too tight, causing legitimate admin requests to be rejected. | `adminauth.MaxSkew = 120 * time.Second`. | *Was 120 s chosen after measurement?* If the plan will be used in a homelab where the admin laptop may be offline for hours, a stricter anti-replay window could be counter-productive.  Could the server expose a “max-skew” hint to the CLI at startup? |
| **MEDIUM** | **Invite expiry enforcement** – The plan says “expires in 24 h” and that an “unknown, expired or replaced token shows a uniform ‘invite not valid’ page”.  It does not describe whether the server checks the *absolute* expiry (`invite_expires_us`) **before** hashing the token (i.e., to avoid timing differences). | `internal/server/invite.go` – “lookup a pending, unexpired invite”. | *Will a timing attack be able to distinguish a missing token from an expired token?* Consider normalising the response time (e.g., always hash a fake token) to avoid leaking token-existence. |
| **MEDIUM** | **Admin-API path binding** – `adminauth.Verify` validates the *exact* request path, including the query string.  However, the plan does not specify whether the server will canonicalise the path (e.g., trailing slash, percent-encoding) before verification.  Inconsistent canonicalisation could cause legit admins to be rejected while an attacker could craft an equivalent request that bypasses verification. | `adminauth.Verify` – “path incl. query”. | *What canonicalisation steps are performed?* Will URL-encoded characters be normalised?  Provide a precise algorithm to match the server’s routing logic. |
| **MEDIUM** | **Error-response uniformity** – The plan mandates a “uniform 401” response for any admin-auth failure, but also wants a “uniform 404” for unknown invites.  Uniformity across status codes is fine, but the *body* of the error should be identical (including length) to prevent an attacker from inferring which check failed. | `requireAdmin` – “logs reason, never the token or signature”, and the 401 response body. | *Is the body a fixed JSON string, e.g. `{"error":"unauthorized"}`?* Is the 404 body the same shape?  Confirm that logging does not inadvertently leak header values (e.g., the nonce) to the audit log. |
| **LOW** | **Database file permissions** – The plan says the DB file is opened with mode `0600`.  On systems where the server runs under a dedicated user, that is fine, but on a container or a systemd unit with `DynamicUser=yes` the file may be created with the wrong UID/GID. | `Open(path)` – “file mode 0600”. | *Will the service unit set a `User=` and `Group=` that owns the directory?* Verify that the unit file (step `deploy/systemd/keyroster-server.service`) creates the directory with the correct ownership before the binary starts. |
| **LOW** | **Web UI CSP & Referrer-Policy** – The plan notes a “strict CSP” and `Referrer-Policy: no-referrer` for the enroll page, but does not list the exact CSP directives.  Missing directives (e.g., `frame-ancestors 'none'`) could allow click-jacking or data exfiltration. | `internal/server/web/templates/enroll.html`. | *What exact CSP header will be sent?* Ensure it disallows `<script>` sources other than the single embedded JS file, and disallows embedding the page in iframes. |

---

### 3. Suggestions  

| Area | Recommendation |
|------|----------------|
| **CLI UX** – Provide a *quiet* mode that only prints the invite URL (for scripting) and a *verbose* mode that explains why the admin key was not found.  Keep the failure message constant-time and free of the offending fingerprint. |
| **Nonce GC** – Add a background goroutine that runs every 5 min and deletes rows where `expires_us < now`.  Wire it into the same `rate.Limiter` map cleanup code to keep the memory footprint bounded. |
| **Skew Config** – Expose a server `.conf` option `max_skew_seconds` (default 120) and make the CLI fetch it via a health endpoint.  This will let operators relax the window in environments where NTP cannot be guaranteed. |
| **Path Normalisation** – Document that the server will `url.Parse` the request URI, then reconstruct it with `EscapedPath` (no query) before feeding it to `adminauth.Verify`.  Update the test matrix to cover encoded characters (`%2F`, `+`). |
| **Uniform Error Body** – Define a constant JSON payload `{"error":"unauthorized"}` for both 401 and 404, pad to a fixed length (e.g., 128 bytes) before writing, and verify that the size is identical in tests. |
| **CSP Header** – Use `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'`.  Add a unit test that asserts the header’s presence on every `/enroll/*` response. |
| **Audit Logging** – When `requireAdmin` rejects a request, log **only** the admin name (if any), the remote IP, and the reason code (`missing-header`, `replay`, `bad-sig`).  Do **not** log the nonce value; store the nonce hash instead if you need later forensics. |
| **Invite entropy** – Explicitly state that the token is a 256-bit (32-byte) random string encoded with URL-safe base64 **without** padding.  Confirm that the SHA-256 hash stored in the DB matches exactly the raw token (`sha256(token)`). |
| **Test for DB permission** – Add a CI test that creates a temporary DB file, runs the server startup, and asserts that the file mode is `0600`.  This catches accidental changes in `Open`. |

---

### 4. Risk Assessment  

| Risk | Likelihood | Impact | Mitigation (in-plan / post-plan) |
|------|------------|--------|--------------------------------|
| **Admin key misuse** – An admin inadvertently supplies a non-admin key, causing an auth-failure that reveals the presence/absence of an admin key. | Medium | High (could help an attacker enumerate admin keys) | Enforce constant-time lookup, generic error messages, and avoid logging the supplied fingerprint. |
| **Nonce table exhaustion** – An attacker floods the admin API with unique nonces, filling the `admin_nonces` table and causing DB bloat. | Low-Medium | Medium | Periodic GC (see suggestion) and bounding the map size in the rate-limiter. |
| **Replay due to clock drift** – Legitimate admin requests rejected because the server clock is far behind the client. | Medium (homelab laptops often unsynced) | Medium | Configurable `max_skew_seconds` and clear documentation. |
| **Token leakage via Referrer** – If a user clicks a link from another site, the full invite URL could leak in the HTTP Referrer header. | Low (Referrer-Policy set) | Medium | Verify header is set on all responses (including static assets); test with browsers. |
| **DoS via rate-limit bypass** – Attacker could rotate IPs to evade per-IP limiter. | Low | Low | Future plan: add a global token-bucket limiter or CAPTCHA for invite endpoint. |
| **Database mis-ownership** – Service runs as root, creating DB with 0644 permissions, exposing pending data. | Low | Low | Ensure Systemd unit runs under a dedicated, non-root user and creates directory with `StateDirectoryMode=0700`. |

Overall, the **remaining risk** after applying the suggestions is **low** and well-contained within the threat model.  The biggest open question is the **admin-key discovery UX**, which directly touches the “no-admin-key-leak” requirement (D-02).  Resolving that will finish the security hardening for this plan.

---

### 5. Verdict  

- **Proceed** with the current implementation **provided** the open questions above are answered and the suggested mitigations are incorporated (especially the constant-time admin-key handling and nonce GC).  
- Once the owner signs off on the clarified behaviours, the plan satisfies the Phase 2 success criteria for AUTH-01 and UI-01 and can be merged.  

*Prepared by Claude – review pending owner actions.*
### 02-08 – Passkey Registration (Phase 2 - MVP)

#### TL;DR  
The plan delivers a **complete “invite → passkey registration → pending credential”** flow that satisfies AUTH-01 and UI-01, and it keeps the WebAuthn-related code out of the signer binary as required by D-17.  
The overall design is sound, but a few implementation-level questions and hardening opportunities remain before the plan can be merged safely.

---

### 1. Summary of What the Plan Does  

| Step | What is built / changed | How it meets the requirements |
|------|------------------------|--------------------------------|
| **Task 1** – Owner dependency review | Human-only audit of `github.com/go-webauthn/webauthn@v0.18.2` and every unlocked transitive module (tinylib/msgp, go-viper/mapstructure/v2, go-webauthn/x, philhofer/fwd, x448/float16, fxamacker/cbor/v2, golang-jwt/jwt/v5). | Guarantees that no uncontrolled supply-chain code slips into the signer (D-17, T-02-SC). |
| **Task 2** – DB + API & UI | *Migrations* add `registration_sessions`, `pending_credentials`, and a `invite_used_us` column. <br>*Server* implements `/api/v1/enroll/{token}/begin` and `/finish` using go-webauthn, converts the COSE key to an SPKI DER, validates with the internal `webauthn.ParsePublicKey`, stores a pending credential, and returns a SHA-256 fingerprint. <br>*Web UI* (`enroll.html` + `app.js`) runs the WebAuthn **create** ceremony, shows the fingerprint, and then disables the invite URL. <br>*CLI* adds `keyroster user pending <name>` (admin-signed) to list pending credentials. | - **AUTH-01** – an account stays “unusable” until an admin signs a directory that contains the pending credential (the pending row is never bound). <br>- **UI-01** – a single HTML page with a tiny hand-written JS file, no inline script, strict CSP, meets the UI design rule. |
| **Task 3** – Refusal matrix + differential oracle + CI gating | Exhaustive test matrix that rejects: missing UV/UP, wrong rpIdHash or origin, stale/used sessions, disallowed algorithms, duplicate credential IDs, expired/used invites, etc. <br>Matches every *acceptable* vector against go-webauthn to ensure the internal verifier is **no less strict** (strictOnly list). <br>Updates `scripts/dep-firewall.sh` and `.golangci.yml` to ban all WebAuthn-related packages from the signer graph. | - **D-17** – the signer never imports CBOR/JWT or go-webauthn. <br>- **D-05/D-03** – only allowed algorithms and UV required. <br>- **D-12** – registration uses a short-lived session, limiting replay. |
| **Task 4** – Merge gate | Owner approval → squash-merge → `02-08-SUMMARY.md` recorded on `main`. | Enforces the “owner-only” gate required for any dependency change (see the “Delivery Protocol”). |

---

### 2. Strengths (What the Plan Does Well)

| Area | Observation |
|------|-------------|
| **Supply-chain hygiene** | The explicit, scripted “owner dependency review” (Task 1) forces a *human* gate before any new module enters `go.mod`. The plan even checks that `google/go-tpm` stays unchanged, satisfying the “no new TPM dependency” rule. |
| **Zero-trust separation** | `go-webauthn` is compiled **only** into `keyroster-server` (the UI-side binary). The plan updates `dep-firewall.sh` and `depguard` to guarantee the signer binary never imports it. This matches D-17 and the threat-model entry T-02-41. |
| **Clear data model & auditability** | The pending credential is stored with its algorithm, SPKI blob, backup-eligible flags, and a precise `registered_us` timestamp. Fingerprints are derived from the exact SPKI bytes (`SHA256:base64(SPKI)`) – the same format the signer will later verify against. |
| **Comprehensive refusal testing** | The matrix covers every failure mode listed in the STRIDE register (T-02-39, T-02-40, T-02-41) and adds a **differential oracle** against a maintained library, ensuring the internal verifier is *not weaker* than the reference implementation. |
| **Minimal UI surface** | The HTML template uses only `data-*` attributes and a separate `.js` file. No inline scripts, no external dependencies, strict CSP (added in Wave 4, but already present on the server). |
| **CLI parity** | Admins can view pending credentials via a signed `keyroster user pending` command, keeping the audit trail on the client side and preventing accidental exposure of pending data to non-admins. |
| **Testing hygiene** | The “softreg” test helper lives in a non-test package (`internal/server/servertest`) and is never imported by production binaries – the plan explicitly checks that `go list -deps ./cmd/...` does not include it. |

---

### 3. Concerns (Potential Issues and Open Questions)

| Severity | Concern | Plan step(s) affected | Why it matters |
|----------|----------|----------------------|----------------|
| **HIGH** | **Supply-chain verification completeness** – the owner must manually audit *all* transitive modules (tinylib/msgp, go-viper/mapstructure/v2, go-webauthn/x, philhofer/fwd, x448/float16, fxamacker/cbor/v2, golang-jwt/jwt/v5). If any of these are later added as a transitive dependency of a different module (e.g., a newer go-webauthn version), the firewall may miss it. | Task 1 (dependency review) | The plan relies on a one-time check. A future `go get -u` could silently bring a new transitive module that is *not* in the firewall list. |
| **HIGH** | **TLS / WebAuthn origin requirements** – WebAuthn rejects insecure or self-signed TLS certs. The plan assumes the operator will provide a trusted cert (see D-09), but there is no automated test that the registration page works with a *real* self-signed cert or with Tailscale-issued certs that change keys. | Task 2 (server init) | If an operator tries the homelab with a self-signed cert, registration will silently fail, breaking the MVP. |
| **MEDIUM** | **Race between invite consumption and registration** – the `invite_used_us` column is set in the same transaction that inserts the pending credential, but the plan does not describe locking semantics for concurrent `enroll/begin` calls on the same invite. A malicious user could try two concurrent browsers to create two pending credentials from a single invite. | DB migration & transaction logic (Task 2) | Could lead to multiple pending credentials for a single invite, violating the “single-use invite” guarantee. |
| **MEDIUM** | **Credential-ID collision handling** – the plan rejects a credential ID that is already pending *or* already present in the installed directory. However, the check only compares the raw `id` bytes. If the server stores `id` as a string (e.g., base64url) in the DB, subtle encoding mismatches could slip through. | `enroll.go` / `credential.go` (Task 2) | Might enable a replay or duplicate-ID attack that bypasses the pending-credential check. |
| **MEDIUM** | **Backup-eligible / backed-up flags** – stored as two separate INTEGER columns. The plan does not define whether `0/1` is used, nor does it enforce a Boolean type in the schema. This could cause confusion or bugs when later code interprets the flags. | DB schema (Task 2) | Future visibility tooling expects a strict Boolean; mismatched values could break reporting. |
| **LOW** | **CSP & content-type for `app.js`** – while the plan mentions CSP, the exact header (e.g., `script-src 'self'`) is not shown. Missing `X-Content-Type-Options: nosniff` could allow a mis-served script to be interpreted as something else. | UI files (Task 2) | Minor but could be an easy vector for XSS if the server ever mis-configures the static file handler. |
| **LOW** | **Testing of failure paths on Windows** – the plan’s e2e suite runs on Linux, but the WebAuthn registration flow is also required on Windows (Task 2 mentions `cmd/keyroster/user.go` for admin pending list). No explicit Windows-specific end-to-end test is listed. | e2e `enroll_test.go` (Task 3) | Might hide platform-specific bugs (e.g., path handling for the Windows named-pipe agent). |

---

### 4. Suggestions (How to Mitigate the Concerns)

| Concern | Recommendation |
|---------|----------------|
| **Supply-chain drift** (HIGH) | Add a **continuous CI check** that runs `go list -m all` and asserts that the exact *set* of modules listed in the owner-approved table remains unchanged on `main`. Fail the build if a new transitive module appears. |
| **TLS / Origin** (HIGH) | Include an automated integration test that spins up `keyroster-server` with a self-signed cert *and* with a Tailscale-generated cert, then exercises the `enroll` endpoints via a headless Chrome (or `chromium --headless --disable-gpu`). Record the result – the test should *expect* a failure for the self-signed case and a success for a trusted cert. |
| **Invite race condition** (MEDIUM) | Use a **SELECT … FOR UPDATE** lock on the invite row before checking/setting `invite_used_us`. Ensure the insertion of the pending credential and the update of `invite_used_us` are performed in a single serialized transaction. |
| **Credential-ID encoding** (MEDIUM) | Store the credential ID as a **binary BLOB** (not as TEXT) and compare using `bytes.Equal`. If a string column is required for SQLite, always encode with a deterministic base64url and document the exact routine. Add a unit test that registers the *same* credential with two different base64url encodings and verifies that the second attempt is rejected. |
| **Backup flag semantics** (MEDIUM) | Define the DB columns as `INTEGER NOT NULL CHECK (backup_eligible IN (0,1))` and similarly for `backed_up`. In code, map them to Go `bool` values (`0 → false`, `1 → true`). Add a lint rule or `go vet` check that flags any direct integer use of these fields. |
| **CSP / static file headers** (LOW) | Ensure the server sends an explicit `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'` header on the enroll page, and also `X-Content-Type-Options: nosniff`. Include a test that fetches `/static/app.js` and asserts these headers exist. |
| **Windows e2e coverage** (LOW) | Add a separate test matrix entry that runs the e2e suite on a Windows runner (GitHub Actions `runs-on: windows-latest`). The test only needs to hit the `/begin` endpoint and verify that the JSON response is well-formed – the actual credential ceremony can be mocked with `softreg`. This guarantees the HTTP handling is platform-agnostic. |

---

### 5. Risk Assessment

| Risk | Likelihood | Impact | Overall Rating | Mitigation Priority |
|------|-------------|--------|----------------|---------------------|
| **Supply-chain injection after owner review** | Medium (future `go get -u` could slip in) | High (malicious CBOR/JWT code in signer) | **High** | **Immediate** – add CI lock-down on transitive modules. |
| **Registration failure due to untrusted TLS** | Medium (operators may use self-signed certs) | Medium (MVP broken, no way to register) | **Medium** | **High** – provide CI test and documentation that only trusted certs work. |
| **Duplicate-credential/Invite race** | Low-Medium (unlikely in homelab but possible in production) | High (could allow multiple pending credentials per invite) | **Medium** | **Medium** – enforce DB lock and transaction semantics. |
| **Inadvertent leakage of pending credentials** | Low (admin endpoint protected by SSHSIG) | Medium (information leak) | **Low** | **Low** – ensure admin auth is enforced, already covered. |
| **Incorrect algorithm enforcement** | Low (tests cover major cases) | Medium (weak keys accepted) | **Low** | **Low** – confirm test matrix includes RSA-1024 reject. |
| **Missing CSP/Headers** | Low | Low | **Low** | **Low** – add header test. |

---

### 6. Bottom Line  

The 02-08 plan is **well-structured** and **covers the primary security goals** for Phase 2’s passkey registration MVP. The biggest open risk is the *supply-chain guardrails*: a one-time manual approval is not enough for long-term safety. Adding a CI gate that freezes the transitive dependency set will close that gap without extra manual work.  

Other concerns (TLS trust, race conditions, encoding consistency) are **easily mitigated** with small code or test additions, and they do not block progress. Assuming the owner’s dependency review (Task 1) returns an “approved” with a complete module table, I recommend advancing the plan to the merge gate after the suggested mitigations are in place.
### 02-09 – Approve Passkeys into an Admin-Signed Directory  
*Plan review (one of the 14 Phase-2 plans).  No repository access – source-dependent points are phrased as open questions.*

---

#### 1. Summary  

The plan introduces a **single, auditable pipeline** that lets an admin bind a user’s newly-registered WebAuthn credential to a *directory* document signed by the admin’s SSH key (or a quorum of admin keys).  

Key actions:

| Step | What is built / changed |
|------|------------------------|
| **Server** – `GET/POST /api/v1/admin/directory` and `GET /api/v1/admin/users` (plan 02-09-server) | Provides a read-only mirror of the current directory and a way to install a new version atomically. |
| **CLI** – `editDirectory` (in `cmd/keyroster/dirpipe.go`) (plan 02-09-dirpipe) | Verifies the *trust bundle* against pinned roots, validates the *installed* directory against the policy admins, constructs the successor, prints a **stable diff**, asks for confirmation, signs with the admin’s SSH key, and either posts it or writes a proposal. |
| **CLI sub-commands** – `keyroster user approve …` (plan 02-09-user) | Looks up pending credentials, requires the admin to supply the exact SHA-256 fingerprint shown to the user, mutates the directory, and runs the same pipeline. |
| **Proposal workflow** – `keyroster directory sign` / `install` (plan 02-09-directory) | Supports quorum > 1: a proposal can be written, co-signed, then installed. |
| **Server handling** – `DeleteBound` on successful install (plan 02-09-serverdb) | Cleans up pending rows only after the signer accepts the new directory. |
| **Tests & Docs** – e2e (`TestEnrollApproveEndToEnd`, etc.) and `docs/runbooks/enroll-user.md` (plan 02-09-test-doc) | Drive verification of happy-path, edge cases (adjacency, emptiness, idempotency, concurrency, quorum) and capture the operational run-book. |

If all steps behave as described, the **AUTH-01** requirement (an account stays unusable until an admin binds a passkey) and **KEY-02** (authority is a quorum-signed directory version) are satisfied, while preserving the “no admin can grant themselves access unobserved” guarantee.

---

#### 2. Strengths  

| Area | Why it helps the project goals |
|------|--------------------------------|
| **Zero-trust base verification** – The CLI never trusts the server’s directory without locally verifying *both* the root-pinned policy and that the directory’s signatures belong to the *policy admins* (step 2 of `editDirectory`). This implements the “authenticate payloads, not pipes” rule from the architecture research. |
| **Human-in-the-loop diff** – The stable, ordered diff (`internal/directory/diff.go`) is shown before any signing. This gives the admin a chance to detect accidental changes (e.g., a role-escalation) and satisfies the “diff-before-sign” requirement in the `must_haves` truth list. |
| **Explicit out-of-band fingerprint check** – Requiring `--fingerprint` for `user approve` forces an OOB verification step, mitigating the “compromised-server-shows-attack-credential” risk documented in the run-book. |
| **Quorum-aware design** – The same pipeline works for both single-admin installs and multi-admin proposals, and the signer refuses installs that do not meet the quorum (plan step “policy.AdminQuorum > 1”). This enforces D-01/D-02. |
| **Atomic install & pending-cleanup** – The server only deletes pending credentials *after* the signer returns success, preventing a “lost-credential” window. |
| **Comprehensive edge-case coverage** – The plan enumerates tests for adjacency, emptiness, idempotency, concurrency, and quorum-2 paths, which are precisely the AUTH-01 edge cases flagged earlier. |
| **Documentation of residual risk** – `docs/runbooks/enroll-user.md` explicitly calls out the remaining “phishing-via-compromised server” risk (Pitfall 13), aligning with the project’s transparency promise. |
| **Dependency hygiene** – The only new dependencies (`go-winio` for the Windows pipe) are added to the capslock baseline and the firewall script, preserving the “no new attack surface” rule. |

Overall, the plan tightly couples **policy verification**, **admin intent**, and **signer authority**, fulfilling the core value of “full visibility” while keeping the code footprint small.

---

#### 3. Concerns  

| Severity | Concern | Plan step(s) involved | Why it matters / open question |
|----------|----------|----------------------|--------------------------------|
| **HIGH** | **Potential for a *silent* replay of a previously-approved credential**. The pipeline checks that the *fingerprint* matches a *pending* credential, but the pending store lives on the **server** (step `GET /api/v1/admin/users`). If a malicious server were to *re-use* a pending credential that was already approved (by deleting the pending row after install, but keeping the credential ID in a hidden table), an admin could unintentionally sign the same credential twice under different users. | 02-09-user (`user approve`), 02-09-serverdb (`DeleteBound`). | *Open question*: Does `DeleteBound` also purge the *credential ID* from any “used-once” table? Is there a uniqueness check that prevents the same credential ID from being bound to multiple users across versions? |
| **HIGH** | **Race-condition between concurrent admins building on the same base version**. The plan relies on the signer’s version + prev-hash check (step “409 directory_version_chain”). However, `editDirectory` builds the successor *locally* before the POST. If two admins run `user approve` simultaneously, both will POST the **same** successor bytes (identical hash). The signer will accept the first and reject the second with a 409. The plan expects the CLI to surface the error, but there is no automated *re-run* or merge-resolution logic. | 02-09-dirpipe (`editDirectory`), 02-09-server (`POST /api/v1/admin/directory`). | *Open question*: Does the CLI automatically re-fetch the latest directory on a 409 and re-apply the mutation, or must the operator manually re-run the command? If the second admin’s mutation is *different* (e.g., approving a different user), the re-run might lose that change. |
| **MEDIUM** | **Unclear handling of *signature duplication* in quorum proposals**. The plan says “signing twice by the same admin still counts once (refused at install)”. However, `directory sign` appends a signature block without deduplication logic. If an admin accidentally signs twice, the proposal may contain duplicate signatures, and the signer might treat the duplicate as an extra signature (inflating the count) or reject it as “duplicate signer”. | 02-09-directory (`directory sign`). | *Open question*: Does the verifier (`directory.VerifySignatures`) de-duplicate signatures before counting toward the quorum? What error is returned to the CLI if duplicate signatures are present? |
| **MEDIUM** | **Trust-pin management and rotation are not fleshed out**. The CLI fetches the *trust bundle* and verifies it against `cfg.TrustPins` (step 1 of `editDirectory`). The plan does not describe how many pins are expected, what algorithm (SPKI hash vs full cert) is used, or how operators are to rotate them when the server’s TLS certificate changes (e.g., Tailscale cert renewal). | 02-09-dirpipe (initial `Trust` call). | *Open question*: If the server’s cert rotates (common with Tailscale ACME), does the CLI need a new pin? Is there a documented procedure for updating `cfg.TrustPins` without breaking the pipeline? |
| **MEDIUM** | **CLI behaviour on non-interactive environments**. The pipeline prompts the admin for a diff confirmation unless `--yes` is supplied, but the plan also says “with no TTY and no `--yes`, refuse”. This could cause automated CI runs (e.g., a bot that prepares a proposal) to fail unexpectedly. | 02-09-dirpipe (prompt step). | *Open question*: Is there a documented policy for using `--yes` in automation (e.g., CI to generate a proposal for a quorum)? Could this be abused to auto-sign without review? |
| **LOW** | **Proposal file layout and integrity** – The proposal includes `directory.json`, `directory.json.sigs`, and `base.sha256`. The plan does not state that the `.sigs` file must be *armored* (ASCII-armor) or that the `base.sha256` must be verified against the installed directory before signing. An attacker could replace the `base.sha256` with the hash of a *different* directory and trick the second admin into signing an invalid chain. | 02-09-directory (`sign` step). | *Open question*: Does `directory sign` re-compute the base hash from the *currently installed* directory before allowing a second signature? |
| **LOW** | **Error-message consistency** – The plan lists several distinct HTTP status codes (409, 403, 400) with custom error fields (`directory_version_chain`, `directory_invalid`). Consumers (CLI, scripts) must map each to a human-readable message. The plan does not define a central error-handling library, risking drift between server and client. | 02-09-server `POST` handling. | *Open question*: Are the error codes and JSON fields included in the OpenAPI spec and covered by integration tests? |

---

#### 4. Suggestions  

| Concern | Recommendation |
|--------|----------------|
| Replay of already-approved credentials | Add a **global “used-credential-IDs” index** in the signer (or server) that rejects any install that attempts to bind a credential ID already present in any previous directory version. The check should be part of `directory.Validate` before signing. |
| Concurrent admin edits | Implement a **retry helper** in `editDirectory` that, on a 409, automatically fetches the latest directory, re-applies the *mutation* (the same `mutate` function) and re-prompts the admin. This guarantees no lost updates and reduces manual re-run friction. |
| Duplicate signatures in quorum proposals | In `directory.VerifySignatures` de-duplicate by public-key fingerprint before counting toward the quorum. Emit a clear error (`duplicate_signature`) if the same admin’s key appears twice, so the user can clean the proposal. |
| Trust-pin rotation | Define a **pin-rotation process** in the documentation: store pins as a list of SPKI SHA-256 hashes and allow the CLI to accept a *new* pin if it is signed by an existing root (i.e., a “pin-delegation” signed by the current root). Include a `keyroster trust rotate` sub-command. |
| Non-interactive CI usage | Require the explicit flag `--yes --non-interactive` for CI-driven proposal generation, and make the CLI reject the operation without it. This makes the intent obvious and avoids accidental auto-sign. |
| Proposal integrity | When `directory sign` reads a proposal, recompute the SHA-256 of `directory.json` and compare it against `base.sha256`. If they mismatch, abort with a clear error. Additionally, store the `base.sha256` inside the JSON payload (e.g., a `PrevHash` field) so the signer can double-check. |
| Consistent error handling | Introduce a small **error‐wrapper package** (e.g., `internal/apierr`) that defines the set of error codes and JSON structures. Use it in both server and client to guarantee that `directory_version_chain`, `directory_invalid`, etc., are always marshalled identically. Add a unit test that round-trips every error type. |

---

#### 5. Risk Assessment  

| Risk | Likelihood | Impact | Mitigation (already in plan) | Additional mitigation |
|------|------------|--------|------------------------------|-----------------------|
| **Compromised server feeds a forged fingerprint** (user sees a fake credential, admin approves it) | Medium (depends on server integrity) | High – would bind an attacker-controlled credential to a user | Out-of-band fingerprint verification (required `--fingerprint`) + audit log of directory installs | Add a *credential-binding receipt* on the user side that can be compared with server-side logs (optional for later phases) |
| **Lost update due to concurrent admin installs** | Medium (multiple admins in production) | Medium – could drop a legitimate binding | Signer rejects with 409; CLI surfaces error | Auto-retry logic + explicit documentation of the conflict-resolution flow |
| **Duplicate credential ID bound to different users** | Low (depends on pending-store cleanup) | High – privilege escalation | `DeleteBound` runs after signer success; pending rows cleared | Global uniqueness constraint on credential IDs in directory schema, enforced at Validate |
| **Quorum-size mis-match (admin signs twice, quorum not met)** | Low (human error) | Medium – admin may think the directory is ready when it isn’t | Signer enforces quorum; CLI reports missing signatures | Deduplicate signatures before counting; provide a `keyroster directory status` command |
| **Pin-drift after TLS cert renewal** | Medium (Tailscale certs rotate) | Medium – pipeline will reject all attempts to fetch directory | Trust pins are stored locally and verified before each edit | Provide `keyroster trust update` to add a new pin after a controlled rotation ceremony |

Overall, **the highest residual risk remains the human-factor “fingerprint mismatch”** (phishing) which the plan already mitigates by making the fingerprint mandatory and documenting the residual risk. All other technical risks are either already mitigated by the design (signer checks, quorum enforcement) or can be reduced with the lightweight suggestions above.

---

#### 6. Bottom Line  

The plan presents a **well-structured, security-first workflow** that fulfills the core requirements for Phase 2. The design’s biggest strengths are the *local verification of authority* and the *explicit, human-checked diff*.  

The primary open questions revolve around **global credential uniqueness**, **concurrent admin coordination**, and **trust-pin lifecycle** – areas where a small amount of extra validation or tooling would close the remaining attack surface without compromising the simplicity goal.

If the open questions are answered (or the suggested safeguards are added) before the merge gate, the plan should pass the required CI, audit checks, and merge-gate criteria with a high degree of confidence.
### 02-10 – Passkey Web-Sign-In & Read-Only Account Page  
**Phase:** 02-passkey-login-mvp (Wave 8)  
**Owner:** `keyroster` · Branch `p02/10-web-signin`  
**PR target:** `origin/main` (auto-merge, squash)  

#### Summary  

| Item | Description |
|------|-------------|
| **Goal** | Enable a user whose passkey is bound in the *installed* directory to authenticate to the embedded web UI, receive a cryptographically-random `__Host-keyroster-session` cookie, and view a read-only page that lists the user’s roles, principals, TTL cap and credential fingerprints. |
| **Key artefacts** | • DB migration `0003_web.sql` (tables `web_challenges` & `sessions`)  <br>• `internal/server/weblogin.go` (`GET /login`, `POST /api/v1/web/login/begin`, `POST …/finish`)  <br>• `internal/server/session.go` (`withSession` middleware, cookie handling, idle/absolute expiry)  <br>• `internal/server/account.go` (`GET /account`)  <br>• Rate-limit extensions (per-IP & per-username)  <br>• UI assets (`templates/login.html`, `account.html`, `static/app.js`)  <br>• E2E test `TestWebSignInEndToEnd` |
| **Security properties** | • Challenge is a 32-byte random value, single-use, expires ≤ 120 s. <br>• Assertion is verified with the **identical** `internal/webauthn` verifier used by the signer (no extra dependency in the signer). <br>• Uniform `404` on *any* non-usable username prevents user-enumeration. <br>• Session ID is 32 bytes, stored only as SHA-256 in the DB; cookie uses `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`. <br>• Idle timeout 1 h, absolute timeout 12 h; session is revoked automatically when the directory marks the user disabled. |
| **Success criteria covered** | – SC 1 (user registers a passkey → signs into UI)  <br>– SC 2 (CLI login uses same fingerprint – UI now shows the same fingerprint)  <br>– SC 4 (signer refuses missing/replayed/invalid assertions – covered by same verifier) |
| **Remaining out-of-scope** | Host-side principal files, certificate issuance, JIT approvals, admin UI for directory changes. |

---

### Strengths  

| Area | Why it matters |
|------|-----------------|
| **Clear separation of duties** | The server only *mirrors* the directory; all auth decisions (credential binding, RP ID, policy) are enforced by the signer-side verifier. This respects the “signer-only authority” model from Phase 1. |
| **Uniform error handling** | Identical `404` for unknown, pending, disabled, or credential-less accounts implements the “no-info-leak” stance required by the STRIDE register (T-02-50). |
| **Stateless challenge flow** | Storing only the challenge ID, user name, binary blob, and expiry keeps the DB small and makes replay detection trivial (challenge is deleted on `TakeChallenge`). |
| **Strong session hardening** | `__Host-` cookie, `Secure`-only, `HttpOnly`, `SameSite=Strict`, SHA-256 storage, and automatic revocation on directory disable cover both Spoofing (T-02-47) and Elevation (T-02-51). |
| **Rate-limit per-username** | Adding a per-principal limiter mitigates credential-guessing and enumeration bursts beyond the per-IP bucket. |
| **Comprehensive test coverage** | Unit tests for every refusal case + a full end-to-end flow (incl. real SSHD) give confidence that the flow works in the homelab and that regressions will be caught. |
| **Dependency hygiene** | The only new module (`go-winio`) is limited to the Windows CLI (outside the signer), and the server only adds `go-webauthn` (which is already allowed in the server-only firewall). This respects the capslock baseline. |
| **Documentation of limits** | The plan explicitly notes the “UNVERIFIED” status for macOS UI testing; the risk is tracked for Wave 11. |

---

### Concerns  

| Severity | Reference in plan | Issue / Question |
|----------|-------------------|------------------|
| **HIGH** | **Task 1 – DB & Challenge handling** | *Atomicity & race conditions*: `TakeChallenge(id, now)` must both **delete** the row **and** return the blob atomically. If the DB layer uses two separate statements, a concurrent `finish` could succeed with a stale challenge, violating the single-use guarantee. <br>**Open question:** Does the migration use `DELETE … RETURNING` (SQLite 3.35+) or a transaction that guarantees atomicity? |
| **HIGH** | **Task 1 – Session creation** | *Session fixation*: The plan generates a random session ID *after* verification, but does not rotate the ID on privilege changes (e.g., after a user is disabled and re-enabled). If a session persists across a privilege change, an attacker could retain a valid cookie after the user’s rights are reduced. <br>**Open question:** Will the `withSession` middleware delete the session when the directory indicates a status change *before* checking the request? |
| **MEDIUM** | **Task 1 – Cookie on non-HTTPS dev servers** | The spec requires `Secure`; the e2e test runs on `https://keyroster.localhost:<port>` via a self-signed cert. In local development (e.g., `http://localhost:8080`) the cookie would be rejected and the UI would break, yet the plan does not mention a “development mode” toggle. <br>**Open question:** Is there an explicit opt-out flag for `Secure` in dev, or will developers be forced to run TLS locally? |
| **MEDIUM** | **Task 1 – Uniform 404 timing side-channel** | Although the body is identical, the **response latency** may differ between a user that exists (lookup → DB → success path) and a non-existent user (quick miss). This could still aid enumeration. <br>**Open question:** Are there explicit timing-padding measures (e.g., sleep ≈ 50 ms) to equalise response time? |
| **LOW** | **Task 1 – Challenge storage of raw `blob`** | The `blob` column contains the raw WebAuthn `clientDataJSON` and `authenticatorData`. If an attacker gains read access to the DB (e.g., via OS compromise) they could see the RP ID, challenge, and possibly user-verification flag. This is not a credential leak, but may aid targeted phishing. <br>**Open question:** Is the challenge blob encrypted at rest or does the threat model consider DB compromise a “full compromise” scenario already? |
| **LOW** | **Task 2 – Rate-limit values** | The per-username limiter (`10/min`) may be too permissive for a high-value service where brute-force attempts on a known username are a concern. The policy does not explain the chosen burst/average. <br>**Open question:** Was the limit derived from a quantitative threat model, or is it a placeholder to be tuned later? |
| **LOW** | **Task 2 – CSRF protection on `/logout`** | The plan relies on `SameSite=Strict` + a “CrossOriginProtection” wrapper from Wave 6, but the exact implementation of that wrapper is not restated here. If the wrapper only checks `Origin` header, browsers may omit it on same-site POSTs, causing a blind-spot. <br>**Open question:** Does `CrossOriginProtection` also validate a CSRF token, or is SameSite considered sufficient under the threat model? |

---

### Suggestions  

| Area | Recommendation |
|------|-----------------|
| **Atomic challenge consumption** | Implement `TakeChallenge` as a single `DELETE FROM web_challenges WHERE id = ? AND expires_us > ? RETURNING *` in SQLite. If the SQLite version on the target platform does not support `RETURNING`, wrap the `SELECT` + `DELETE` in a transaction with `BEGIN IMMEDIATE`. |
| **Session revocation on status change** | In `withSession`, after loading the session’s `user_name`, call `directory.IsActive(user_name)` **before** resetting the idle timer. If the user is now disabled, `DeleteSession` should be invoked and the request redirected to `/login`. This guarantees immediate revocation. |
| **Development-mode TLS** | Add a server flag `--insecure` (or an env var) that, when set, allows the cookie to be set without `Secure`. The flag must be **explicitly disabled** in production builds and be gated by a compile-time build tag (`dev`). Document the flag in `README` and ensure CI runs the server with real TLS. |
| **Timing-padding for uniform 404** | After the DB lookup for a username, insert a `time.Sleep(50 * time.Millisecond)` (or a configurable sleep) before writing the response, regardless of outcome. This reduces latency-based enumeration. |
| **Encrypt challenge blobs (optional)** | Store the `challenge` column as raw bytes (already random) but encrypt the `blob` (clientDataJSON etc.) with a server-side static AES-GCM key derived from the server’s TLS private key. This adds negligible overhead and eliminates the residual data exposure if the DB is read by an attacker who does not control the server process. |
| **Rate-limit calibration** | Run a quick load test (e.g., `hey` or `vegeta`) targeting `POST /api/v1/web/login/begin` with a known username to confirm the per-username bucket isn’t trivially bypassed. Adjust the limit to `5/min` with burst 2 if the test reveals high error rates. |
| **CSRF token for logout** | Even with `SameSite=Strict`, add a random `csrf_token` (stored in the session DB row) that the logout form must submit. This provides defense-in-depth and aligns with the existing `CrossOriginProtection` pattern used elsewhere in the codebase. |
| **Explicit audit logging** | Ensure every refusal (uniform 404, 401, 429) logs the *hashed* username and the reason (e.g., “begin-refused-no-credential”). This satisfies the audit-log requirement (P1 D-14). |
| **Explicit documentation of “UNVERIFIED”** | In the `README` or `docs/README.md`, add a note that the web UI is exercised only on Linux/macOS via the e2e test; macOS UI is currently unverified and will be validated in Wave 11. This keeps the public claim accurate. |

---

### Risk Assessment  

| Risk | Likelihood | Impact | Mitigation (already in plan) | Additional mitigation |
|------|------------|--------|------------------------------|----------------------|
| **Replay of a WebAuthn assertion** | Low (single-use challenge) | High (attacker could obtain a valid certificate) | Challenge is deleted atomically (`TakeChallenge`) and expires after 120 s. | Verify atomic delete-return; add a short in-memory cache of used challenge IDs as a fallback. |
| **Session hijack (cookie theft)** | Medium (session ID is bearer token) | High (read-only page leak; could be used as foothold for future CSRF) | Random 32-byte ID, stored as hash, `Secure` + `HttpOnly` + `SameSite=Strict`. | Add optional “binding to User-Agent” (store User-Agent hash in the session row, reject on mismatch). |
| **Privilege escalation via stale session** | Low (session revocation on disable) | High (user could continue to view now-revoked principals) | `withSession` checks directory status on every request and deletes stale sessions. | Add a “session version” field in the directory; on any directory change, bump a global version and invalidate all sessions. |
| **User enumeration** | Medium (username is in request body) | Low (names are already logged in audit) | Uniform 404, rate limits per-IP & per-username. | Introduce constant-time response latency padding (see suggestion). |
| **CSRF on logout** | Low (SameSite=Strict) | Medium (could keep session alive) | SameSite + CrossOriginProtection. | Add CSRF token as extra defense. |
| **Dependency-drift (go-webauthn)** | Low (restricted to server) | Medium (verifier bugs could allow forged assertions) | Dependency firewall + capslock baseline; verifier is fuzzed. | Pin the exact commit hash of `go-webauthn` and add a nightly fuzz job in CI. |

Overall the plan **meets** the Phase 2 security-first constraint. The highest-risk items (atomic challenge consumption and session revocation on status change) are **addressable with minor code adjustments** and clear test coverage. The remaining concerns are low-impact or already mitigated by existing controls.

---

#### Bottom-Line Recommendation  

- **Approve** the plan **provided** the open questions marked above are answered in the implementation (atomic `TakeChallenge`, session revocation flow, and dev-mode TLS handling).  
- Request the owner to add a short note in the PR description confirming: *“Challenge consumption is performed in a single SQLite statement; session revocation on disabled users is enforced before idle-timer reset.”*  
- Once the PR passes CI and the merge gate, proceed to Wave 9 (plan 02-12) which will build the CLI `keyroster login` flow on top of this web-sign-in foundation.  
### 02-11 – Roles, Groups, Host-Groups & Principals Renderer  
**Phase:** 02-passkey-login-mvp → Wave 8  
**Owner-gate:** 02-09 must be merged first  

#### Summary  
The plan adds the first admin-controlled authorization layer:

| Item | What is added | Where it lives |
|------|----------------|----------------|
| **Directory renderer** (`internal/directory/render.go`) | `AccountPrincipals` + `RenderPrincipalsFile` that produce a deterministic `AuthorizedPrincipalsFile` (header + sorted, deduped principals) | Shared package used by the Phase 3 host-agent and the CLI (`keyroster host principals`) |
| **CLI commands** (`cmd/keyroster/*`) | `role`, `group`, `host-group`, `host` sub-commands that edit the signed *directory* via `editDirectory` and expose the renderer | All admin actions go through the same *directory-mutation* pipeline established in 02-09 |
| **Tests** | Unit tests for the renderer; integration/e2e test (`TestRolesHostPrincipalsEndToEnd`) that exercises the full path: role → group → host-group → rendered file → real sshd → revocation | `test/e2e/roles_test.go` |
| **Run-book** (`docs/runbooks/host-setup.md`) | Manual steps for a Phase-2 host to trust the user-CA and to install the generated principals file | Documented for operators and for the future Phase-3 agent |
| **Decision checkpoint (Task 1)** | Owner must confirm the **one-way principal convention** (`role:<name>` / `u:<username>` or a custom prefix) before any defaults are baked | Recorded verbatim in `02-11-SUMMARY.md` |

If the checkpoint is satisfied, the plan delivers a complete admin-side workflow that satisfies **AUTHZ-01** and the third success criterion (certificates grant exactly the principals rendered for the host).

---

#### Strengths  

| Aspect | Why it’s strong (citing plan steps) |
|--------|------------------------------------|
| **One-source-of-truth rendering** – `RenderPrincipalsFile` lives in the same `directory` package used by the signer and by the future host-agent (Task 2, step *“shared renderer”*). Guarantees the file shown to admins is exactly what the signer will validate, mitigating T-02-53. |
| **Policy-driven immutable authority** – All mutating commands (`role add`, `group add-member`, `host-group map`, etc.) are **editDirectory** mutations that produce a signed directory version (Task 2, *“every mutating subcommand is an editDirectory mutation and accepts `--yes`…”*). This enforces the “admin-signed directory” model introduced in D-01/D-07. |
| **Defensive validation** – The plan explicitly requires **CLI-side principal syntax checks** (cert.ValidatePrincipals) *and* signer-side checks (existing `Validate` pipeline). This double-layer guards against accidental mis-configurations and malicious CLI binaries, addressing T-02-52. |
| **End-to-end test against real sshd** – `TestRolesHostPrincipalsEndToEnd` spins a stock OpenSSH server, loads the generated `TrustedUserCAKeys` and the rendered principals file, then verifies login succeeds and fails after un-mapping (Task 2, step 6-7). This directly proves success-criterion 3. |
| **Explicit human decision for one-way change** – Task 1 forces the owner to lock in the principal prefix before any default is baked, satisfying the “one-way door” requirement (D-06). |
| **Run-book ties code to ops** – `host-setup.md` codifies the manual steps that will be automated later, reducing the risk that operators forget to re-render after a revocation (T-02-54). |
| **Granular failure cases covered** – Task 3 lists a comprehensive set of refusal tests (wildcards, commas, empty string, over-TTL, unknown groups/roles, uppercase accounts, removal of mapped entities). This coverage will surface regressions early. |

---

#### Concerns  

| Severity | Concern (plan step) | Explanation / Open Question |
|----------|----------------------|-----------------------------|
| **HIGH** | **Task 1 – Owner decision on principal prefixes** (checkpoint decision) | The plan treats the decision as a *binary* (“role-prefix vs custom-prefix vs account-names”). If the owner selects a *custom* prefix, the CLI default must be generated dynamically, and every downstream test (e2e, renderer header, run-book examples) must be templated accordingly. **Open question:** *How will the custom prefix be communicated to the test suite and to the run-book generation?* Is there a config file or a build-time constant? Without a concrete mechanism the plan could stall at merge-gate. |
| **HIGH** | **PKI rotation & header hash stability** (Task 2 – renderer header) | The header includes “directory version \<n\> sha256 \<hex\>”. If the directory version is signed but the *exact* byte representation used for the hash diverges (e.g., whitespace changes in JSON canonicalisation), the rendered file’s hash may not match the signer’s view, breaking the “evidence that the file came from the current directory”. **Open question:** *Does `RenderPrincipalsFile` compute the hash from the *canonical* JSON bytes of the directory (as stored on disk) or from the in-memory struct?* A mismatch would cause false-positive tampering warnings (T-02-53). |
| **MEDIUM** | **CLI-side validation vs signer-side validation for TTL caps** (Task 3 – refusals) | The plan expects the CLI to reject a `--max-ttl` larger than the *user-CA profile* cap **before** signing. However the user-CA profile lives in the *trust bundle* that is only fetched at runtime by the signer. If the CLI does not have a current copy of the bundle (e.g., offline operation), it may incorrectly allow an oversized TTL, and the signer will later reject it, creating a confusing error path. **Open question:** *Will the CLI pull the bundle and cache it locally for TTL validation, or will it simply rely on the signer to reject?* |
| **MEDIUM** | **Concurrency / race conditions on directory edits** (Task 2 – editDirectory) | Multiple admins could invoke `role add` or `group add-member` concurrently. The plan doesn’t describe how `editDirectory` resolves conflicts (e.g., optimistic lock with version bump, or serialised via a server-side lock). The signer already refuses out-of-order versions, but a race could cause many failed transactions, increasing admin friction. **Open question:** *Is there a back-off / retry strategy in the CLI, or does the plan rely on the operator to serialize changes?* |
| **LOW** | **Windows host-group case** (Task 3 – run-book) | The host-setup run-book mentions “Windows hosts: lowercase account names”. OpenSSH on Windows is case-insensitive, but the `AuthorizedPrincipalsFile` path may be case-sensitive on the underlying file system (NTFS is case-preserving). If the generated file name (`/etc/ssh/principals/<account>`) uses a mixed-case account, host-side sshd may not locate it. **Open question:** *Will the CLI enforce lower-casing of the `<account>` argument on Windows, or is this left to the operator?* |
| **LOW** | **Dependency surface for go-winio (Task 3)** | Adding `github.com/Microsoft/go-winio` to the Windows CLI is required for the named pipe agent. The plan updates the dependency firewall and capslock baseline, but it does not list a **fallback** if the dependency fails the capslock check on a future Go version. This could block CI for Windows builds. **Open question:** *Has the capslock test been run against the current version of go-winio, and is it locked in `scripts/dep-firewall.sh`?* |

---

#### Suggestions  

| Suggestion | Where it applies | Rationale |
|------------|------------------|-----------|
| **Provide a concrete config mechanism for custom prefixes** (Task 1) | Add a tiny `keyroster.yaml` (or an environment variable) that stores `role_prefix` and `user_prefix`. The CLI reads it at start, the test suite loads it, and the run-book can reference the same file. | Guarantees that the owner’s decision propagates consistently without manual code edits. |
| **Document the hash source for the renderer header** (Task 2) | In `RenderPrincipalsFile` comment and in `docs/runbooks/host-setup.md`, state “hash is computed over the canonical JSON representation of the directory version as stored on disk”. Add a unit test that recomputes the hash from the on-disk file and compares it to the header. | Removes ambiguity, prevents T-02-53 mismatches. |
| **Cache the trust bundle for TTL validation** (Task 3) | The CLI should fetch the bundle from the server once per run (or on first use) and keep it in memory for `--max-ttl` checks. If the bundle cannot be fetched, fall back to *signer-only* validation with a clear error message. | Improves UX (early feedback) and aligns with the “defense-in-depth” principle. |
| **Add optimistic-lock semantics to `editDirectory`** (Task 2) | Extend `editDirectory` to include the *expected* parent directory version hash; the server rejects mismatched versions with a clear “stale version – retry” error. The CLI can auto-retry a configurable number of times. | Reduces admin friction, makes concurrent edits safe, and satisfies the existing successor-chain model. |
| **Enforce lowercase accounts on Windows** (Task 3 – run-book) | In `keyroster host principals` and `host-group map` commands, automatically lowercase the `<account>` argument on Windows builds, and emit a warning if the supplied value differs from the normalized form. | Guarantees the generated file name matches the case expected by the Windows OpenSSH service. |
| **Pin go-winio version in the firewall script** (Task 3) | Update `scripts/dep-firewall.sh` to lock `github.com/Microsoft/go-winio@v0.6.2` (or the exact commit) and add a comment explaining the pin. Run the capslock check locally before the PR lands. | Prevents surprise CI failures due to transitive updates. |

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Overall Rating | Mitigation |
|------|-------------|--------|----------------|------------|
| **Incorrect principal convention after owner decision** (Task 1) | Medium (depends on owner response) | High – would require re-issuing every certificate and re-rendering all hosts | **High** | Enforce the decision via a single source of truth (config file) and gate the build until the config exists. |
| **Hash mismatch between rendered file and directory version** (Task 2) | Low (implementation likely straightforward) | Medium – could cause operators to lose confidence in the audit log | **Medium** | Add unit test and explicit documentation; consider including the hash in the e2e test. |
| **Concurrent directory edits causing lost updates** (Task 2) | Medium (multiple admins likely) | Medium – admin friction, possible audit-log gaps | **Medium** | Optimistic-lock version check + auto-retry in CLI. |
| **CLI allowing oversized TTL** (Task 3) | Low (bundle fetch is cheap) | Medium – could temporarily create over-privileged certs if signer is bypassed (unlikely) | **Low** | Cache bundle for TTL checks; surface clear error if bundle unavailable. |
| **Windows host-group case-sensitivity leading to login failures** (Task 3) | Low (few Windows hosts currently) | Low – limited to Windows homelab, but could confuse users | **Low** | Force lowercase on Windows; add documentation. |
| **Dependency-firewall breakage from go-winio** (Task 3) | Low (pinning is simple) | Low – CI failure only | **Low** | Pin version, run capslock check pre-merge. |

Overall, the plan is **well-scoped** for Phase 2 and directly satisfies the required success criterion. The primary risk is the *owner-decision point* for the principal prefix; providing a concrete configuration path will eliminate the biggest blocker.

---  

**Bottom line:**  
Approve the plan **once** the owner records the principal-prefix decision in `02-11-SUMMARY.md` **and** the repository adds a small config mechanism (or hard-codes the chosen prefixes) to propagate the decision to the CLI, tests, and run-book. After that, the plan delivers a secure, auditable admin workflow with full e2e verification against a real OpenSSH host.
### 02-12 – “keyroster login” – Review  

#### TL;DR  
The plan stitches together a new login API, a browser-driven WebAuthn approval page, a loop-back PKCE flow and per-OS agent injection. The design is coherent and most of the security-critical pieces (fingerprint comparison, PKCE, single-use code, signer-side verification) are present.  
The biggest open questions revolve around **state persistence and race conditions** (concurrent logins, code-hash uniqueness, expiry handling) and **boundary-hardening** (loop-back host checks, CSP, TLS pinning). Those should be answered before the PR is merged.  

Below is a concise audit organized by the plan’s major artefacts, with concrete concerns, their severity and suggested mitigations.

---  

#### 1. Database migration & login-session model  

| Step(s) referenced | Concern | Severity | Why / Open question |
|-------------------|---------|----------|----------------------|
| `0004_login.sql` (DB schema) – creation of `login_sessions` table; `CreateLogin`, `Login`, `ApproveLogin`, `RedeemLogin` accessors. | **Race-condition on concurrent login attempts** – Two `login` processes for the same user could generate the same `code_hash` (unlikely but possible if the random generator is weak) or could both try to move a session from `approved` → `redeemed`. | **HIGH** | Does the `RedeemLogin` implementation perform the status check and state transition in a single atomic transaction? The plan says “atomically”, but without repository access we cannot verify the SQL `UPDATE … WHERE status='approved'`. We need to ensure the DB row lock or `SELECT … FOR UPDATE` is used. |
| Same table – `code_hash BLOB UNIQUE`. | **Denial-of-service via exhaustion** – An attacker could flood the table with pending sessions (or with crafted `code_hash` collisions) to fill the DB. | **MEDIUM** | Are there cleanup jobs for expired sessions? The plan does not mention a background reaper. If stale rows linger, capacity could be consumed. |
| `code_expires_us INTEGER` and `expires_us INTEGER`. | **Clock-skew handling** – The plan enforces a 300 s server-client skew check on the request’s `CreatedAt`. The DB stores timestamps in microseconds; any mismatch between server time (used for expiry) and signer time (used for mint) could cause “code expired” errors after a successful assertion. | **MEDIUM** | Does the server read its own clock once per request or repeatedly? A drift between the API handler and the DB write could make the window shorter than intended. |

**Suggested Mitigations**  
1. Explicitly document that `RedeemLogin` runs `UPDATE login_sessions SET status='redeemed' WHERE id=? AND status='approved' AND code_hash=? AND code_expires_us>now();` and returns the rows-affected count. If 0 → reject.  
2. Add a periodic cleanup (`DELETE FROM login_sessions WHERE expires_us < now();`) run by the server’s background goroutine or a cron.  
3. Store timestamps in UTC with monotonic component (e.g., `time.Now().UTC().UnixNano()`) and log any discrepancy between server and signer times for observability.  

---  

#### 2. Server-side login flow (API endpoints)

| Step(s) referenced | Concern | Severity | Why / Open question |
|-------------------|---------|----------|----------------------|
| `GET /api/v1/login/options` – returns user-specific options, 404 on unknown user. | **Information leakage** – Returning 404 for unknown users is good, but the response includes `ca_max_ttl_seconds` and role names for existing users. An attacker could enumerate valid usernames. | **MEDIUM** | Does the endpoint require authentication (e.g., a session cookie after login) or is it unauthenticated? If unauthenticated, consider returning a constant-size “no-info” payload for unknown users to mitigate enumeration. |
| `POST /api/v1/login/begin` – validates request, code_challenge, state, redirect_port, generates `login_id`. | **Port range enforcement** – The plan validates `redirect_port` ∈ [1024,65535] but does not forbid privileged ports that might be bound by a hostile local process (e.g., a malicious user-owned service on 127.0.0.1:1024). | **LOW** | Should we enforce a higher minimum (e.g., 49152-65535) to avoid colliding with well-known local services? |
| `GET /login/{id}` – renders approval page with fingerprint, principals, TTL, JS options. | **Template injection / XSS** – All values are injected into HTML attributes (`data-assertion`, `data-options`). The plan mentions “html/template attribute escaping”, but we cannot verify the exact implementation. | **HIGH** | Are any of the injected fields derived from user-controlled data (e.g., role names, principal strings) that could contain quotes or `\x00`? If so, ensure `template.HTMLEscapeString` or `html/template`’s automatic escaping is used for every attribute value. |
| `POST /api/v1/login/{id}/assertion` – pre-verifies WebAuthn, stores assertion, generates one-time `code`. | **Server-side pre-verification vs. signer verification** – The plan says “pre-verify” then “signer re-verifies”. If the pre-verification has a bug, the signer could still reject but the log would show an “assertion ok / code issued” step that never results in a certificate. This may be acceptable but could be confusing in audit. | **LOW** | Document clearly that the pre-verification is for UX only; the attacker cannot obtain a certificate without the signer’s final check. |
| `POST /api/v1/login/{id}/redeem` – checks PKCE, code hash, calls `signerclient.Login`. | **PKCE implementation correctness** – The plan stores `code_challenge` (base64url) and later checks `base64url(SHA256(code_verifier)) == code_challenge` in constant time. | **MEDIUM** | Does the implementation normalize padding (some libraries output padded base64url)? A mismatch could cause false rejections. Also confirm that the `code_verifier` is never logged or persisted. |
| All endpoints – “uniform error page” for invalid state. | **Error-message consistency** – The plan does not enumerate the exact HTTP status codes (e.g., 400 vs 404 vs 401). Inconsistent codes can be used for enumeration. | **LOW** | Align all error responses with RFC 7231 semantics and document them in the API spec. |

**Suggested Mitigations**  
* Enforce a higher minimum for the loopback port (e.g., 49152).  
* Use a strict CSP on `login_approve.html` (the plan mentions a CSP but verify it includes `default-src 'self'` and disallows `object`, `script-src` only from the embedded JS).  
* Add a “session-token” cookie (HttpOnly, SameSite=Strict) for the approval page to tie the browser session to the login ID, preventing CSRF.  
* Ensure the `code_challenge` and `code_verifier` handling normalizes padding (strip `=`).  

---  

#### 3. Browser-side JS (`app.js`)  

| Step(s) referenced | Concern | Severity | Why / Open question |
|-------------------|---------|----------|----------------------|
| Fingerprint display, countdown, `navigator.credentials.get`, `window.location.assign` to loopback. | **Phishing window** – The page shows the fingerprint *before* invoking WebAuthn, which is the correct user-centric control. However, an attacker could clone the page, display the same fingerprint (re-use a genuine request), and then capture the assertion. The signer will still validate the request, but the attacker could obtain the certificate *if* they also control the loopback listener. | **MEDIUM** | Does the server bind the `code` to the exact `login_id` and to the stored `state`? The plan says yes, but we need to confirm that the generated `code` is **single-use** and tied to the original login ID. |
| No `fetch` or form post to the loopback – a top-level navigation only. | **Browser policy changes** – Some browsers (Chrome) may block navigation to localhost from a cross-origin page unless `allow` is set. The plan assumes the navigation works. | **LOW** | Verify that the page includes `<meta http-equiv="origin-trial" ...>` or that the CSP does not block `navigate-to`. |
| JS builds the `publicKey` options using `data-options` JSON. | **JSON injection** – If `data-options` contains raw JSON from the server, a malformed value could break the script and skip verification. | **LOW** | Ensure the server JSON is escaped via `template.JS` or `json.Marshal` before embedding, not concatenated manually. |

**Suggested Mitigations**  
* Include a short, signed “request-hash” token in the page metadata (e.g., hidden input) that the JS sends back with the assertion. The signer can verify that the assertion indeed belongs to the request whose fingerprint was shown.  
* Log a warning in the server when a `code` is generated but never redeemed within the expiry window (helps detect abandoned approvals).  

---  

#### 4. CLI implementation (`keyroster login` and helpers)  

| Step(s) referenced | Concern | Severity | Why / Open question |
|-------------------|---------|----------|----------------------|
| Ephemeral Ed25519 key generation, in-memory only. | **Key lifetime in memory** – On platforms without a secure memory allocator (e.g., default Go heap), the private key could be swapped to disk. | **MEDIUM** | Does the code call `runtime.LockOSThread` or use a library that zeroes memory after use? |
| Print fingerprint, TTL, role selection, schedule `code_verifier`. | **User-error surface** – If the user supplies an invalid `--role` the CLI aborts, but does it also clear the generated key from memory? | **LOW** | Ensure early exits zero the private key before returning. |
| Loopback listener (`net.Listen("tcp","127.0.0.1:0")`) – strict Host header, constant-time state compare. | **Host-header spoofing** – The check uses string equality; however, an attacker controlling a proxy could inject a `Host: 127.0.0.1:PORT` header with a different port leading to a mismatch. | **MEDIUM** | Verify that the listener extracts the port from `r.Host` and compares to the *actual* bound port, not just the string. |
| Windows agent path (`winagent.Ensure`) – pipe-owner check. | **Pipe-ownership race** – The check ensures the pipe is owned by the current user before writing, but there may be a TOCTOU window between the check and the write. | **MEDIUM** | The plan references the “IdentityAgent spelling” decision from 02-02; double-check that the pipe is opened with `FILE_FLAG_FIRST_PIPE_INSTANCE` to prevent hijacking. |
| Agent add with lifetime (`LifetimeSecs`). | **Lifetime enforcement** – The SSH agent may ignore the lifetime constraint (e.g., older versions of `ssh-agent`). | **LOW** | Include a verification step after adding: list the keys and confirm that the certificate’s `ValidBefore` matches the lifetime reported by the agent. |
| Failure messages (e.g., “start ssh-agent and retry”). | **User experience** – The CLI aborts if `SSH_AUTH_SOCK` is missing. In CI, the test harness creates a temporary agent. Ensure fallback behavior is deterministic. | **LOW** | Add a `--force-agent` flag for test harnesses that bypasses the check (useful for headless CI). |

**Suggested Mitigations**  
* Use `golang.org/x/crypto/ssh/agent`’s `Add` with `LifetimeSecs` and then immediately call `List` to confirm the entry exists with the expected expiration.  
* Zero the private key (`memset` the slice) in a `defer` block before the function returns, even on early error paths.  
* On Windows, open the pipe with `winio.OpenPipe` using `FILE_FLAG_FIRST_PIPE_INSTANCE` to close the TOCTOU window.  

---  

#### 5. Tests & CI  

| Step(s) referenced | Concern | Severity | Why / Open question |
|-------------------|---------|----------|----------------------|
| E2E `TestLoginEndToEnd` uses real OpenSSH 10.5p1, starts a fresh `ssh-agent`. | **Test flakiness** – Real sshd start-up and timing (certificate expiration) can be nondeterministic, especially on CI runners with limited CPU. | **MEDIUM** | Are timeouts generous enough? The test expects the certificate to *expire* after a short TTL; if the CI host’s clock drifts, the test could intermittently fail. |
| Cross-OS CLI flow test (`TestLoginFlowFakeServer`) runs on macOS & Windows CI. | **Platform-specific differences** – The plan marks macOS as UNVERIFIED; the CI test may still pass if the runner’s environment differs from a user’s local macOS (e.g., missing keychain integration). | **LOW** | No immediate blocker, but highlight that the macOS path is not exercised by a *real* browser in the CI (due to headless restrictions). |
| Refusal matrix tests require the fake signer client to “record zero calls”. | **Mock fidelity** – If the fake signer’s interface does not perfectly mirror the real signer (e.g., missing rate-limit handling), some refusal pathways may be untested. | **MEDIUM** | Ensure the fake signer implements the same `Login` signature and logs the request ID for later inspection. |
| No test for **TLS pinning** of the server certificate (required by the CLI). | **Supply-chain / MITM risk** – If the pin is wrong or the server rotates its key (tailscale cert renewal), the CLI will reject all logins. | **MEDIUM** | The plan leaves the pinning mechanism as an “open research question”. Until resolved, the CLI should *fallback* to a warning-only mode (e.g., “server key changed – proceeding in evaluation mode”) rather than aborting the flow, otherwise operator error could lock out all users. |

**Suggested Mitigations**  
* Add a jitter-safe retry layer in the e2e test around `ssh-add -l` to tolerate slight clock skew.  
* Document in the test harness how the TLS pin is generated (e.g., from a static SPKI) and verify it matches the server’s cert.  
* Include a test that simulates a server cert rotation and checks that the CLI prints the evaluation-only banner (as required by D-18).  

---  

#### 6. Documentation & Runbooks  

| Step(s) referenced | Concern | Severity | Why / Open question |
|-------------------|---------|----------|----------------------|
| `docs/runbooks/enroll-user.md` will be updated with a “Logging in” section. | **Operator guidance** – The new section must explicitly warn about the *UNVERIFIED* macOS status, the evaluation-only banner for software CA, and the need for a real browser (not a headless script). | **LOW** | Verify the wording aligns with the security-policy (e.g., “Do not approve a login you did not start”). |
| No explicit mention of the **code-hash cleanup** or the **background DB reaper**. | **Operational drift** – Operators may forget to run the cleanup, leading to DB bloat. | **LOW** | Add a “maintenance” note: “run `keyroster server --cleanup` daily” or embed an internal ticker that logs a warning if pending sessions exceed N. |

---  

#### 7. Open Research Questions / Dependencies  

| Item | Open question | Impact |
|------|----------------|--------|
| **PKCE code verifier length & encoding** – The plan uses 32 random bytes base64url (43 chars). Does the server enforce the exact length? | If the verifier is shorter/longer, constant-time compare may be bypassed. |
| **TLS pinning strategy** – The plan cites a pending decision about whether to pin the SPKI, the whole cert chain, or a rotation-aware token. | Wrong pinning will cause all client logins to fail after a certificate renewal. |
| **Replay protection on the signer** – The signer refusal matrix (02-03) is required but not shown here. Does the signer reject duplicate `RequestID`s across different login sessions? | Could allow a replay attack if the same `RequestID` is reused. |
| **Windows pipe ownership** – The exact spelling (`IdentityAgent` line) is defined in 02-02. Does the CLI use the same constant? | Mismatch would cause the CLI to think the pipe is missing and abort. |
| **MacOS verification status** – The plan labels macOS “UNVERIFIED”. Is there a mitigation (e.g., require a hardware-secured browser) for production? | Could lead to operators deploying a flow that fails on macOS users without realizing it. |

---  

### Recommendations Summary  

| Category | Action |
|----------|--------|
| **Atomic DB updates** | Verify `RedeemLogin` uses a single `UPDATE … WHERE status='approved' …` and returns rows-affected. |
| **Cleanup** | Add a background job to purge `login_sessions` where `expires_us < now()`; expose a `--cleanup` flag for manual runs. |
| **Template safety** | Ensure every attribute inserted into `login_approve.html` is escaped via `html/template`. Add a CSP header (`default-src 'self'; script-src 'self'`). |
| **Port range** | Raise the minimum `redirect_port` to 49152 to avoid colliding with well-known local services. |
| **PKCE handling** | Strip `=` padding from both challenge and verifier before comparison; store only the hash of the verifier. |
| **Loopback validation** | Compare the *numeric* port from the listener (`addr.(*net.TCPAddr).Port`) with the `Host` header value after parsing; reject any mismatch. |
| **Memory hygiene** | Zero the Ed25519 private key slice on all exit paths (including error returns). |
| **Windows pipe** | Open the pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE` and verify ownership atomically. |
| **TLS pinning** | Until the pinning decision is final, make the CLI *warning-only* (evaluation banner) rather than fatal if the pin mismatches. |
| **Documentation** | Add a “maintenance” paragraph about session cleanup; clearly flag macOS as UNVERIFIED and link to the future 02-14 plan. |
| **Testing** | Add a test for DB session expiry cleanup; add a test that forces a TLS-pin mismatch and checks the evaluation banner appears. |
| **Audit & Logging** | Ensure each successful `redeem` logs the `login_id`, `request_id`, and certificate SHA256 in the Merkle log for later verification. |
| **Open Questions** | Resolve the listed research questions (PKCE length, TLS pinning, signer duplicate-request handling) before merging. |

---  

#### Risk Assessment  

| Threat | Likelihood (pre-merge) | Impact | Overall Risk |
|--------|------------------------|--------|--------------|
| **Concurrent login race causing double-redeem** | Medium (if DB transaction not atomic) | Gives an attacker two certificates for the same request (potentially with different TTL) | **High** – Must enforce atomic `RedeemLogin`. |
| **TLS-pin mismatch after server cert rotation** | High (tailscale/ACME certs rotate) | All CLI users blocked; no fallback → loss of access | **High** – Mitigate with evaluation-only banner until pinning strategy is final. |
| **XSS on approval page** | Low (template likely safe) | Phishing / credential theft | **Medium** – Verify escaping and CSP. |
| **Memory leakage of private key** | Low (Go GC) | Private key written to swap | **Medium** – Add explicit zeroing. |
| **Denial-of-service via login-session table fill** | Low (requires flood) | Service slowdown, log bloat | **Low** – Cleanup job reduces impact. |
| **Phishing via cloned approval page** | Medium (user could be tricked) | Attacker obtains assertion, but signer still enforces policy; still possible for credential harvesting | **Medium** – Fingerprint comparison mitigates; educate users via docs. |

---  

#### Bottom Line  

The plan is **well-structured**, covers most security controls required for the Passkey-Login MVP, and includes a thorough e2e test suite. The **critical outstanding items** are:

1. **Atomicity of the `RedeemLogin` transition** – confirm implementation.  
2. **TLS pinning strategy** – decide now and make the CLI tolerant to rotation.  
3. **Template & CSP hardening** – verify no injection vectors.  

Addressing those three will bring the plan’s risk down to **Medium** overall and make it safe to merge. Once the owner has answered the open research questions and the above mitigations are in place, give the green light.  
### 02-13 – Homelab “first enrollment” plan (Phase 2 Passkey-login-MVP)

#### Summary  
This plan bridges Phase 1’s trusted signer to Phase 2’s passkey-based login MVP by:

1. **Confirming the RP hostname** (Task 1 – human checkpoint).  
2. **Building and deploying a new signer binary**, installing a **successor bundle v3** that contains a root-signed policy with the RP fields (Task 2-step 3).  
3. **Installing the bundle on the vTPM signer** and starting the **keyroster-server** with a TLS certificate obtained via `tailscale cert` (Task 2-step 4-5).  
4. **Bootstrapping the owner’s account** (Task 2-step 7 → Task 3 → Task 4) through the regular invite/registration/approval flow, thereby exercising **AUTH-01** on real hardware and a real browser.  
5. **Recording the operation** in runbooks, updating the deferred-items bookkeeping (KEY-07 v4) and the ROADMAP, and finally merging the PR through the owner-only gate (Tasks 4-5).

If all automated checks and human checkpoints succeed, the homelab will have a fully operational Phase 2 stack, the first passkey-protected user account, and an auditable record of the RP-hostname binding.

---

#### Strengths  

| Area | Why it’s solid (plan references) |
|------|-----------------------------------|
| **Human-in-the-loop RP confirmation** | Task 1 forces the owner to read the exact FQDN from the VM, repeat it verbatim, and acknowledge the irreversible binding (checkpoint description). This eliminates accidental hostname typos and makes the one-way decision explicit. |
| **Reproducible build & artifact hash tracking** | Task 2-step 1 builds all binaries from a clean work-tree, records the SHA-256 of each artifact, and discards the work-tree. This satisfies the supply-chain “signed releases, reproducible builds” requirement and gives a verifiable provenance trail. |
| **Back-up & rollback path for the signer** | Steps 2-3-4 create a full copy of `/var/lib/keyroster-signer` and keep the pre-upgrade binaries (`.pre-02-13`). The “restore” instructions are explicit, limiting risk of a broken upgrade (see Threat T-02-68). |
| **Policy successor verification** | The plan runs `keyroster trust verify` **after** the bundle is signed (Task 2-step 3-g) and asserts the SHA-256 equality of the produced bundle, the policy, and the recorded pins. This gives confidence that the RP fields are exactly what the owner approved. |
| **TLS via Tailscale cert + auto-renew timer** | Steps 5-1–5-4 install `keyroster-tailscale-cert.service` and timer, then test the health endpoint over the tailnet (`curl -sf https://<FQDN>/healthz`). This keeps the server’s cert up-to-date without any outbound network code, satisfying D-10/D-11. |
| **Full-stack end-to-end enrollment** | Tasks 3 and 4 exercise the exact flow that a production user will see: invite URL, WebAuthn registration in a real browser, fingerprint display, admin approval with SSH-agent signing, role creation, host-group mapping, audit-log verification. This directly validates AUTH-01, UI-01 and PLAT-05. |
| **Audit-log anchoring & KEY-07 bookkeeping** | Task 4-step 2 runs `keyroster audit verify` anchored on bundle v3 and updates the deferred-items file, ensuring the offline-ceremony renumbering (v4) is recorded and visible to future contributors. |
| **Strict prohibitions on host-name leakage** | Multiple verification steps (grep-based diff checks) guard against committing the full FQDN, any other tailnet name, or IP addresses beyond `127.0.0.1`. This enforces the policy in the “prohibitions” section. |

---

#### Concerns  

| Level | Concern (plan step) | Why it matters / open question |
|-------|-----------------------|--------------------------------|
| **HIGH** | **Task 2-step 3 – `root successor-policy` command** | The plan trusts that the CLI will add **only** the three fields (`version`, `prev`, `webauthn`) and will *not* inadvertently modify other policy sections (e.g., admin-key list, CA profiles). **Open question:** *Has the `root successor-policy` implementation been fuzz-tested for accidental field mutation when a new schema element is added?* |
| **HIGH** | **Task 2-step 5 – TLS pin validation on the Windows CLI** | The owner must supply `--tls-pin` matching the server’s leaf certificate SPKI. The plan assumes the Windows OpenSSH agent can import a pin for a non-CA cert (`openssl x509 -pubkey`). **Open question:** *Will the pin verification succeed on all supported Windows versions (including older 1909 builds) or will a subtle mismatch cause the CLI to reject a perfectly valid connection?* |
| **HIGH** | **Task 4-step 1 – `user approve` fingerprint matching** | The plan relies on the fingerprint printed by the web UI and the one returned by `keyroster user pending`. If the UI or CLI formats the fingerprint differently (e.g., `SHA256:` vs raw base64) a mismatch could cause a false-negative approval. **Open question:** *Is the fingerprint display canonicalised (same base64, same line-break handling) across browser JS and Go CLI?* |
| **MEDIUM** | **Task 2-step 4 – Bundle install without explicit pin checks** | The `install-bundle` command is invoked without passing root pins (`--pin`). The plan counts on the signer’s own verification (already run earlier). However, if an attacker tampers with the bundle after `trust verify` but before `install-bundle`, the signer would accept it (the signer trusts only the bundle file). **Open question:** *Does the signer re-verify the bundle’s signature on install, or is it assumed safe because the bundle file is copied over a trusted channel (scp)?* |
| **MEDIUM** | **Task 2-step 5 – Timer-based cert renewal race** | The `keyroster-tailscale-cert.timer` renews the cert every 24 h. If the timer restarts a few seconds after a certificate expires, the server could briefly present an expired cert, causing CLI health checks to fail. **Open question:** *Is there a grace-period handling in the service that reloads the cert only after a successful `tailscale cert` call?* |
| **MEDIUM** | **Task 4-step 2 – Audit verification counting directory installs** | The audit verification expects **exactly** 4 directory install entries (approve, role, grant, host-group). If any extra “metadata” change (e.g., timestamp update, comment field) is logged, the count could differ, breaking the automated check. **Open question:** *Does the audit log count *only* leaf types `DirectoryInstall` or does it also count ancillary leaves such as `PolicyUpdate`?* |
| **LOW** | **Dependency-firewall impact of `go-winio` (CLI) and `go-webauthn` (server)** | The plan adds two new modules (Task 2). The firewall script must be updated, but the plan does not list a specific step to run `scripts/dep-firewall.sh` after the additions. **Open question:** *Has the CI already been configured to fail if a new import appears in the signer’s dependency graph?* |
| **LOW** | **Task 5 – Merge-gate automation** | The check `scripts/merge-gate.sh --check` is used, but the plan does not state that the script validates the “no-hostname-leak” grep constraints again after PR merge. **Open question:** *Is the post-merge gate re-run automatically by a required GitHub Action, or does it rely on the owner manually re-executing the script?* |

---

#### Suggestions  

| Area | Recommendation |
|------|----------------|
| **Policy successor CLI** | Add an explicit `--dry-run` flag (already used) that **outputs a diff** of the new policy vs the old one, and require the operator to confirm that only the three expected fields changed before proceeding to signing. |
| **TLS pin handling on Windows** | Include a small helper script in the repo (e.g., `scripts/extract-tls-pin.go`) that prints the SPKI SHA-256 for any given hostname, and document its use in the runbook. This removes platform-specific ambiguity. |
| **Fingerprint canonicalisation** | Enforce a single fingerprint format (e.g., `SHA256:<base64>` without spaces) in both the UI JS and the CLI, and add a unit test that parses the UI-generated string and compares it to the CLI output. |
| **Install-bundle verification** | Tighten the install step to call `keyroster signer verify-bundle` internally before applying it, or pipe the bundle through `trust verify` again as a safety net. |
| **Cert renewal graceful reload** | Ensure `keyroster-tailscale-cert.service` runs `systemctl reload keyroster-server.service` *only after* a successful `tailscale cert` and a successful `openssl x509 -checkend`. Add a small “fallback-expire-timer” that logs a warning if the cert is within 30 s of expiry. |
| **Audit-log expectations** | Make the audit verification script accept a *range* of leaf counts (e.g., “≥ 4 and ≤ 6”) and output the actual count, to avoid fragile failures when extra metadata leaves are added later. |
| **Dependency firewall** | Add a post-build CI step that runs `scripts/dep-firewall.sh` and fails if new imports appear in the signer's `go.mod`. Document this step in the runbooks so future contributors know it is required. |
| **Merge-gate re-run** | Add a required status check (GitHub Action) that runs `scripts/merge-gate.sh --check` on every PR push, ensuring the gate is enforced automatically and not reliant on manual re-execution. |

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **Irreversible RP-hostname binding** (T-02-65) | Medium (human mistake) | High (all enrolled passkeys become unusable if the RP changes) | Controlled by Task 1 checkpoint, explicit owner confirmation, and documentation of consequences. |
| **Bundle tampering between verify & install** (T-02-68) | Low (scp over trusted LAN) | Medium (signer could be compromised) | Re-verify on install, keep backup of previous bundle, and keep the signer binary read-only. |
| **TLS-pin mismatch on Windows** (T-02-66) | Medium (different OS cert stores) | Medium (client cannot connect) | Provide the extraction helper, test on each Windows version in CI, and log mismatches clearly. |
| **Fingerprint mismatch causing admin approval error** (T-02-67) | Low (format differences) | Medium (admin may reject a correct credential) | Canonicalise fingerprint format, add unit test, and display the same string verbatim in both UI and CLI. |
| **Timer-based cert expiry window** (T-02-65) | Low (timer runs hourly) | Low (temporary health-check failures) | Add reload-on-success logic and log warnings; optionally configure a 5-minute overlap. |
| **Dependency-firewall breach** (T-02-SC) | Low (process already in place) | Low (extra attack surface) | CI step added (see suggestion). |

Overall, the plan’s **high-impact risk** (RP binding) is well-controlled by the explicit human checkpoint. All other risks are either mitigated by the plan’s existing steps or can be lowered further with the suggested hardening actions.

--- 

**Bottom line:** The plan is a coherent, auditable path to achieve the Phase 2 MVP on the homelab. The primary security guarantees (RP-hostname binding, policy successor integrity, end-to-end passkey enrollment) are addressed, but a few **high-level open questions** (policy-field mutation safety, TLS pin handling on Windows, fingerprint canonicalisation) should be answered before the checkout proceeds. Incorporating the lightweight mitigations listed above will close those gaps and make the merge gate substantially safer.
### 02-14 – Homelab Logins (Phase 2 Passkey Login MVP)  

#### TL;DR  
The plan walks through a full end-to-end dog-food of the MVP:  

1. **Prepare the host** – render CA-key / principals, install a single `sshd_config.d/50-keyroster.conf` drop-in and verify that existing key-based logins still work.  
2. **User-side flow** – the owner registers a passkey (Web UI), runs `keyroster login` on Windows and on Linux, confirms the fingerprint displayed in the CLI and in the browser, and obtains a short-lived certificate that lives only in the host-specific agent (named-pipe on Windows, `ssh-agent` or GCR on Linux).  
3. **Corroboration** – audit-log export + `keyroster audit verify` and the host’s `journalctl` entries are matched to the certificates that were used.  
4. **Documentation & governance** – update the platform-verification table, the host-setup and enrol-user runbooks, add the two new required-status-check contexts (`cli-windows`, `cli-macos`) to `.github/rulesets/main-integrity.json`, push a PR, and run it through the merge-gate.  

Overall the plan is **well-structured** and follows the delivery protocol (branch naming, summary file, PR title, auto-merge).  The logic that ties the three independent evidences together (audit log, sshd journal, CLI output) satisfies the success criteria and the “no-unexercised-paths” rule.

Below are the **specific strengths**, **concerns**, **open questions**, and **actionable suggestions**.  All concerns are tied to concrete steps in the plan, and anything that depends on the current repository state is phrased as an open question.

---

#### Strengths  

| What | Why it matters |
|------|----------------|
| **Explicit “pre-condition” checks** (Task 1) | Guarantees that the host is reachable, OpenSSH version is known, and the laptop’s runtime directory exists before any destructive change. |
| **Atomic host configuration** (Task 1 → Step 2.4) | Uses `sshd -t` before reload and a single drop-in file, making rollback trivial (just delete the drop-in). |
| **Fingerprint-comparison UI** (Task 2 & D-13) | Human-in-the-loop verification prevents a compromised server from silently signing a request. |
| **Two independent sources of truth** (Task 3 & Task 5) | Matching the `kr2` key-ID in the audit log with the `journalctl` entry gives strong evidence against repudiation (T-02-71). |
| **Documentation-first approach** (Task 5) | `needs-hardware.md`, `host-setup.md`, `enroll-user.md` get updated in the same PR that introduces the evidence, ensuring they stay in sync with the code. |
| **Ruleset gate** (Task 6) | The required-status-checks are added *before* the PR is merged, guaranteeing that future PRs must pass the three-OS CI. |
| **Clear “UNVERIFIED” handling** (D-16, tasks 4–6) | The plan explicitly records macOS as UNVERIFIED and never marks AUTH-03/PLAT-05 as complete, preserving the “no-unexercised-paths” invariant. |
| **Reversibility rating** (Task 1) | The host changes are reversible with a single file removal, which matches the threat-model requirement for quick recovery from a mis-configuration. |

---

#### Concerns  

| Severity | Step(s) / Reference | Issue |
|----------|---------------------|-------|
| **HIGH** | **Task 2 – Human login**<br>*(“owner runs `keyroster login` and compares fingerprints”)* | The plan relies on the owner *accurately* comparing two SHA-256 fingerprints that are printed in the CLI and the browser.  If the CLI or the UI accidentally truncates or re-formats the string (e.g., line-breaks, upper-case vs lower-case), a false-positive could slip through.  There is no automated sanity-check. |
| **HIGH** | **Task 3 – Audit verification**<br>*(`keyroster audit verify --pin <C> --pin <D>`)* | The plan assumes the exported log contains the newly-issued certificates and that the `audit verify` command can be run with the same pins that were used to initialise the ceremony (`KR_PIN_C`/`KR_PIN_D`).  If the export omits recent entries (e.g., because the signer buffers logs) the verification will falsely succeed or fail.  There is no explicit “verify-that-export-contains-new-entries” step. |
| **MEDIUM** | **Task 1 Step 2 – TLS pin consistency** | The plan checks that *the laptop’s observed TLS pin equals the Windows machine’s pin*, but it does **not** validate that the pin corresponds to the *actual* server certificate key (e.g., the pin might be hard-coded in an old `kr.env`).  A compromised signer could present a different certificate while still passing the pin check if the pin is stale. |
| **MEDIUM** | **Task 5 – Ruleset JSON edit** | The verification script (`grep -c 'cli-windows\|cli-macos' .github/rulesets/main-integrity.json`) only asserts the strings appear; it does **not** confirm they are placed under the correct `required_status_checks` object or that the JSON remains syntactically valid.  A malformed ruleset could silently break required-checks enforcement. |
| **MEDIUM** | **Task 5 – CI status for `cli-macos`** | The plan expects the `cli-macos` check to be green on the PR, but the earlier “confidence: low” rating suggests the macOS CI may not yet be stable.  If the check fails intermittently, the PR could get stuck, delaying the merge-gate. |
| **LOW** | **Task 4 – GNOME “A3” probe** | The plan says “If 02-02 moved A3 to dogfood, run the 02-02 probe now”.  It does not spell out what to do if the probe *fails* (e.g., fallback to `ssh-agent`).  Leaving it as a “human decision” could lead to inconsistencies across runs. |
| **LOW** | **Host-file permissions** | The plan writes the CA public key and principals file as `root:root 0644`.  On some distributions the default umask or `TrustedUserCAKeys` may expect `0600`.  If the file is readable by everyone, an attacker could enumerate the CA public key, which slightly reduces secrecy (although it’s public by design). |
| **LOW** | **Expiry check timing** | The test uses a fixed `5 m` TTL and waits “6 minutes”.  Clock-skew between the client and the host could cause the key to still appear for a few seconds after expiry, making the test flaky.  A more deterministic way would be to query the agent for the exact expiration timestamp. |

---

#### Open Questions (source-dependent)

| # | Question | Where it matters |
|---|----------|-------------------|
| Q1 | Does the current `keyroster audit verify` output include **both** the certificate **and** the associated `kr2` key-ID in a machine-parsable form?  The plan parses the output with `grep -q 'trust bundle v3'`; if the format changes, the verification could silently miss the new log entries. | Task 3, Task 5 verification steps |
| Q2 | Are the TLS pins (`KR_PIN_C`, `KR_PIN_D`) stored in `kr.env` *derived* from the server’s *current* leaf certificate, or are they static values written during the Phase 1 ceremony?  If they are static, a certificate-rotation (e.g., Tailscale cert renewal) could make the pin mismatch without the plan detecting it. | Task 1 Step 3, Task 5 |
| Q3 | Does the Windows client actually use the **named pipe** format `\\.\pipe\openssh-ssh-agent` on all supported Windows 11 builds, or are there cases where the pipe is `\\.\pipe\keyroster-agent` (if a custom agent is used)?  The plan assumes “the pipe Claude gave you” after `keyroster login`, but the CLI implementation may create a *different* pipe name when `--agent` is omitted. | Task 2, D-15 |
| Q4 | Is the `cli-macos` CI job currently gated by any *platform-specific* secrets (e.g., a macOS signing certificate) that could cause the job to be skipped on the PR?  The plan counts on it being green, but a missing secret would make the check appear as “skipped”, failing the `grep -c` test. | Task 5 rule-set verification |
| Q5 | The `main-integrity.json` file already contains other required-checks (e.g., `lint`, `test`).  Does the addition of two new contexts automatically increase the `required_status_checks` array, or does the file need an explicit `"type": "required_status_checks"` object?  A misplaced entry could be ignored by GitHub. | Task 5 “add both contexts … to .github/rulesets/…”. |
| Q6 | Does the `keyroster login --ttl 5m` command enforce the *exact* expiry that the signer encoded, or does it apply an additional client-side safety margin?  If a margin exists, the key might disappear *before* the 5-minute limit, making the test flaky. | Task 2 & Task 4 expiry expectations |
| Q7 | Are the `ssh-agent`‐lifetime flags (`ssh-add -t`) used by the Windows named-pipe agent (implemented inside `keyroster.exe`) verified to *actually* kill the key on expiry, or does the agent merely stop responding, leaving the key resident in memory?  This impacts the “certificate leaves the agent when it expires” success criterion. | D-15, Task 2 step 5 & Task 4 step 4 |
| Q8 | The plan uses `journalctl -u ssh -u sshd` on the host.  On some distros (e.g., Debian-based) the service name is only `ssh`.  Could the command miss the journal entries on a different OS, falsely reporting a failure? | Task 3 & Task 5 verification |

---

#### Suggestions / Mitigations  

| Area | Suggested improvement |
|------|-----------------------|
| **Fingerprint sanity** | Add a small helper script (e.g., `keyroster verify-fingerprint`) that reads the fingerprint from the CLI output, hashes the same request payload, and checks that the browser-displayed fingerprint (via a temporary file the UI writes) matches exactly.  This removes the “human visual compare” edge case. |
| **Audit-log freshness** | After exporting the log, run `keyroster audit verify … | grep -A1 'latest entry'` and assert that the timestamp is **after** the login start time (`date -u +"%Y-%m-%dT%H:%M:%SZ"`).  If the latest entry is older, retry the export (the signer may be buffering). |
| **TLS-pin rotation** | In the `keyroster init` step, store *both* the SPKI pin and the **certificate serial**.  On each login, the CLI can issue a warning if the server presents a cert with a different serial, prompting the operator to re-run `init`.  Document the pin-rotation process in `docs/runbooks/server-install.md`. |
| **Ruleset JSON validation** | Run `jq` schema validation as part of the PR (e.g., `jq -e 'has("rules") and .rules[] | select(.type=="required_status_checks")' .github/rulesets/main-integrity.json`).  Fail the PR if the JSON is malformed. |
| **CI reliability** | Add a *smoke* step in the PR that runs `keyroster login --dry-run` on the macOS runner (no passkey needed) to guarantee the job finishes even if the real WebAuthn flow cannot be exercised.  Mark the result as “passed” but still keep the `cli-macos` context required. |
| **A3 probe fallback** | If the GNOME GCR probe fails, automatically fall back to `ssh-agent` and record the fallback in `needs-hardware.md` (e.g., “Linux: GCR unavailable → ssh-agent used”).  This makes the outcome deterministic and removes a manual “human decision” point. |
| **Permission hardening** | Consider making the CA public key file `0644` → `0640` and owned by a dedicated `keyroster` system user, then add a note in `host-setup.md` that the file must be readable by the `sshd` user (usually `root`). |
| **Expiry verification** | Instead of a fixed sleep, query the agent for the key’s remaining lifetime (`ssh-add -L | grep -A1 "<key-id>"`) or use `ssh-add -e` (if supported) to confirm the exact expiration timestamp. |
| **Cross-platform pipe naming** | In the Windows CLI, after `keyroster login` succeeds, have the tool echo the exact pipe name (e.g., `\\.\pipe\keyroster-<uuid>`).  The docs should explain that the user must use that exact string when calling `ssh -o IdentityAgent=…`. |
| **Journal unit name detection** | Use `systemctl list-units --type=service | grep -E 'ssh|sshd'` to discover the correct unit name and store it in a variable, then pass that variable to `journalctl`.  This removes OS-specific assumptions. |
| **Documentation lock-down** | Add a pre-commit hook (or CI check) that runs a grep for any FQDN or IP other than `127.0.0.1` on added lines.  This guarantees the “no hostnames in repository” rule stays enforced for future changes. |

---

#### Risk Assessment  

| Risk | Likelihood | Impact | Overall | Mitigation |
|------|------------|--------|---------|------------|
| **Host lock-out due to mis-configured `AuthorizedPrincipalsFile`** | Medium (depends on manual copy-paste) | High – could prevent all SSH access to the homelab host. | **High** | `sshd -t` validation, drop-in rollback, and the “control login before/after” check already present. Add an extra `ssh -o BatchMode=yes -i /dev/null` sanity-check after reload. |
| **Man-in-the-middle on TLS (pin stale / mismatched)** | Low-Medium (pin stored in `kr.env`) | Medium – could let an attacker present a rogue cert and still pass the pin check if the pin is not refreshed. | **Medium** | Pin-rotation procedure, log of observed pin on each client, and optional server-side pin-verification in the CLI. |
| **Phishing / UI-spoofing of fingerprint** | Medium (human comparison) | Medium – if the owner mis-compares, a rogue server could sign a request. | **Medium** | Automate fingerprint verification (see suggestion), and display the fingerprint in a *read-only* `<code>` block with a Content-Security-Policy that disallows scripts from modifying it. |
| **CI/Ruleset mismatch causing merge block** | Low (the plan includes verification) | Medium – blocks the merge gate, stalls the phase. | **Low** | Add a `pre-merge` GitHub Action that validates the JSON schema and that the new contexts are present before the PR can be approved. |
| **Expiration handling bug (certificate stays beyond TTL)** | Low (covered by D-15) | High – could undermine the “short-lived” security promise. | **Medium** | Add a unit-test for the agent’s lifetime handling on each platform, and a runtime watch-dog in the CLI that logs a warning if the key is still present after TTL. |
| **Leakage of homelab host names / tailnet** | Low (prohibited in steps) | Medium – could give an attacker a target for future attacks. | **Low** | Grep-based diff check (already in Task 5) plus the pre-commit hook suggested above. |

---

#### Bottom Line  

The plan is **well-aligned** with the Phase 2 success criteria and the project’s security-first stance.  The biggest open-ended risk is the **human-in-the-loop fingerprint comparison**; automating that check would raise the assurance level from *medium* to *high* without adding significant complexity.

If the open questions (Q1-Q8) are answered positively—i.e. the audit-log format is stable, TLS pins are derived from the current server cert, the Windows named-pipe name is predictable, and the CI jobs for macOS are reliable—then the plan can be executed with **moderate confidence**.  Incorporating the suggested mitigations (especially automated fingerprint verification, TLS-pin freshness checks, and JSON schema validation) would reduce the residual risk to **low** and streamline the merge-gate process.

---

## Consensus Summary

### Verification Method
Four external reviewers (codex, nemotron-3-ultra, gemma4:31b, gpt-oss:120b) reviewed the 14 Phase 2 plans (02-01..02-14). None of them had repo access, and gpt-oss reviewed each plan on its own without RESEARCH.md. A Claude agent then checked every finding adversarially against the plan text, CONTEXT/RESEARCH and the Phase 1 source. Verdicts across 250 findings:

| Verdict | Count |
|---|---|
| ALREADY_COVERED | 127 |
| REFUTED | 48 |
| PARTIAL | 72 |
| CONFIRMED | 3 |

Of the 75 findings that survived (PARTIAL or CONFIRMED), **none is HIGH, 3 are MEDIUM and 72 are LOW**.

### Agreed Strengths
The reviewers gave no clear shared praise, so little can be claimed here. Indirectly, 70% of all findings were either already covered by the plans or refuted. That suggests the plans already handle most of what an outside reviewer looks for: fail-closed defaults, the signer re-verifying everything, single-use tokens and nonces, a uniform 404, and named refusal tests. gemma rated every plan LOW.

### Agreed Concerns (2+ reviewers, by verified severity)

**MEDIUM**
- **02-08-F1** (codex, gptoss): concurrent begin/finish calls can both use one invite.
  - Evidence: finish deletes the session without checking rows-affected (:193). The step-5 transaction sets `invite_used_us` without `WHERE invite_used_us IS NULL` (:197). Only sequential tests exist (:244-257).
  - Fix: delete the session atomically (`DELETE … RETURNING`). Make the step-5 update conditional on `invite_used_us IS NULL` and unexpired, and require rows-affected == 1. Allow at most one pending credential per user. Add an `invite_concurrent_finish` test under `-race`.
- **02-11-F2** (codex, gemma; CONFIRMED): an empty principal set and an unknown account have undefined behaviour.
  - Evidence: AccountPrincipals errors on an unknown account (:153). It is unspecified whether `map` accepts zero roles or what `unmap` keeps (:166). E2E step 7 (:179) feeds sshd a hand-written empty file, so it tests sshd rather than keyroster.
  - Fix: choose one rule. Either an empty mapping renders a header-only file, or an unknown account means "write an empty file, never keep the old one". Rewrite step 7 to use keyroster's real output, and add unit tests for both cases.
- **02-14-F6** (codex, gptoss): the TTL-expiry dogfood check cannot pass as written.
  - Evidence: the earlier 8 h default-TTL certificate is still in the same agent (:171, :230). So "no identities / agent exited" (:173) never happens, and :232 does not say which certificate should be gone.
  - Fix: record the 5 m certificate's serial or fingerprint right after login and check that this entry disappears, or clear the agent first (`ssh-add -D`). Record the listing output, not just yes/no.

**LOW**
- **02-10-F1** (all four): a disabled user keeps their session until the mirror refreshes. The delay is at most 5 s, and installs through the CLI refresh immediately.
  - Fix: state that withSession uses the 02-06 status cache, and that a failed refresh fails closed. Add `signer_unavailable_fails_closed`.
- **02-06-F4** (codex, gptoss, nemotron): line 181 contradicts itself. It says "every Status failure → 503" but also "no stale RP data older than 60 s".
  - Fix: one rule, with no stale fallback after the TTL. Add `status_refresh_failure_fails_closed`.
- **02-05-F6** (nemotron, gptoss, codex): `MaxStatusFrame` (256 KiB) is smaller than what the signer will install (up to 1 MiB per document, about 4 MiB total). An accepted install could make Status, and with it issuance and the server, permanently fail.
  - Fix: align the install cap with the Status budget, and add round-trip tests exactly at the budget and at budget+1.
- **02-10-F2** (codex, gptoss, nemotron): sessions are not tied to directory or credential changes, so disable followed by re-enable does not end a session.
  - Fix (optional): end the session when the credential set or status changes, and add a test that a role change shows up on /account.
- **02-01-F7** (codex, nemotron): the 02-01 E2E never checks that the issued certificate's principals are exact, because sshd cannot catch a superset.
  - Fix: assert `ValidPrincipals == ["role:ops"]`, Key equals the ephemeral key, and the validity window is ≤ 900 s.
- **02-01-F19** (gptoss, nemotron): the `webauthntest`/`servertest` exclusion is checked once at acceptance and is not a CI gate.
  - Fix: run `go list -deps ./cmd/...` in CI for no tags and `-tags piv`, on linux and windows.
- **02-02-F1** (codex, gptoss): VerifyServerOwner has only a positive test.
  - Fix: factor out the SID comparison and test against a foreign SID (S-1-5-18). Test that Ensure fails closed.
- **02-03-F5** (codex, gptoss): the reworked ReadMessage never rejects length 1, which desyncs the stream or makes `make([]byte,-1)` panic.
  - Fix: refuse length < 2 before reading the header and use unsigned arithmetic. Add boundary cases at exactly each cap.
- **02-03-F12** (gemma, gptoss): there is no accept test for clientDataJSON with extra members such as `other_keys_can_be_added_here` or `tokenBinding`.
  - Fix: add a positive verify case and a fuzz seed.
- **02-04-F2** (codex, nemotron): no positive fixture has a directory that outlives an RP-only policy change, i.e. a login with dir=1 and pol=2.
  - Fix: install the directory before successor-policy in the E2E, or add `login_directory_survives_rp_policy_change`.
- **02-05-F4** (codex, gemma): custody.md does not cover offline brute force of leaked `.age` files.
  - Fix: add a bullet saying 20 runes is a length floor, so use a random passphrase.
- **02-06-F10** (codex, nemotron): a pinned-root mismatch has no actionable error, there is no test for a new intermediate, and a future root cannot be pre-pinned.
  - Fix: return a specific error naming `init --force --tls-pin`, and add an intermediate-rotation test.
- **02-06-F11** (nemotron, gptoss): file modes are a no-op on Windows.
  - Fix: document that the config holds only public data, and guard mode assertions with `runtime.GOOS != "windows"`.
- **02-07-F6** (codex, gptoss): the per-IP limiter does not handle IPv6 /64 or have a global backstop.
  - Fix: key IPv6 by /64, add a coarse global limiter and a map-bound test, and label it best-effort in T-02-36.
- **02-09-F10** (nemotron, codex): a stale proposal tells `directory install` to "re-run this command", which fails again.
  - Fix: name the producing command (e.g. `user approve`) in both sign and install errors, and add a runbook line.
- **02-13-F1** (codex, gemma): the rollback keeps the binaries but not the old systemd unit, and the restore commands are not written out.
  - Fix: back up the unit as `.pre-02-13` and list the full restore steps.
- **02-14-F1** (codex, gptoss): `sshd -T` checks global values, so a `Match` override is missed.
  - Fix: use `sshd -T -C user=zima,host=…,addr=…` for both clients, or grep that no `Match` blocks exist.
- **02-14-F5** (codex, nemotron): the journal correlation uses a relative `-3h` window and a count of 2 or more.
  - Fix: use an absolute `--since` (Task 1 install time) and grep for the recorded serials.

### Single-Reviewer Verified Concerns
None at HIGH or MEDIUM.

LOW: 02-01-F2, 02-01-F5, 02-01-F21 (CONFIRMED), 02-02-F5, 02-02-F8, 02-03-F10, 02-03-F13, 02-03-F16, 02-04-F8, 02-05-F1, 02-05-F2, 02-05-F7, 02-05-F11, 02-05-F16, 02-06-F1, 02-06-F15, 02-06-F16, 02-06-F19, 02-07-F1, 02-07-F5, 02-07-F7, 02-07-F8, 02-07-F9, 02-07-F10, 02-07-F12, 02-08-F3, 02-08-F7, 02-08-F10, 02-08-F11, 02-08-F16, 02-09-F6, 02-09-F11, 02-09-F14 (CONFIRMED), 02-10-F5, 02-10-F6, 02-10-F15, 02-10-F16, 02-11-F3, 02-11-F5, 02-11-F6, 02-11-F7, 02-12-F1, 02-12-F2, 02-12-F12, 02-12-F13, 02-12-F14, 02-12-F15, 02-12-F17, 02-12-F21, 02-12-F22, 02-13-F3, 02-13-F14, 02-14-F7, 02-14-F13.

### Divergent Views
- **Overall risk ratings differed sharply.**
  - codex rated 11 of 14 plans HIGH (MEDIUM only for 02-07, 02-10 and 02-11).
  - gptoss rated 02-03, 02-04, 02-06, 02-08, 02-11 and 02-12 HIGH.
  - nemotron ranged from LOW to HIGH and gave HIGH only to 02-01 and 02-02.
  - gemma rated all 14 plans LOW.
  - After verification no HIGH finding survived, so the HIGH ratings were not borne out. gemma's LOW ratings fit better, but they still missed the three MEDIUM items (gemma co-raised only 02-11-F2).
- **Notable downgrades and refutations inside surviving findings:**
  - 02-14-F1: the "lockout" risk was rated HIGH. The drop-in affects only certificate auth, and the key login is checked before and after the change, so it is late detection, not a lockout.
  - 02-01-F19: the claim that the leak would go undetected is wrong, because `go list -deps` is transitive.
  - 02-12-F1: "duplicate issuance" is not a problem. The certificate is bound to an in-memory ephemeral key and is logged, and a retry is impossible by design (`duplicate_request`).
  - 02-12-F15: the claimed code-expiry drift cannot happen, because the same server clock sets and checks the expiry.
  - 02-05-F6: the directory is not part of Status.
  - 02-06-F11: the macOS half is wrong, since POSIX modes work there.
  - 02-09-F11: TLS certificate renewal never touches TrustPins.
  - 02-08-F11: invalid BE/BS values fail loudly on read.
  - 02-05-F7: terminals wrap long lines; they do not truncate them.

### Recommended Plan Changes (for `/gsd-plan-phase 2 --reviews`)
1. [ ] **02-08**: make invite consumption atomic (conditional UPDATE plus rows-affected check, atomic session delete, one pending credential per user) and add a concurrent-finish test. *(MEDIUM)*
2. [ ] **02-11**: define the semantics for an empty mapping versus an unknown account in RenderPrincipalsFile and in `map`/`unmap`, and rewrite E2E step 7 to use real keyroster output. *(MEDIUM)*
3. [ ] **02-14**: make the TTL-expiry check target the 5 m certificate by serial or fingerprint, or clear the agent first. *(MEDIUM)*
4. [ ] **02-06 / 02-10**: make one fail-closed rule for Status and mirror refresh failures (remove the 60 s clause) and add tests for both.
5. [ ] **02-05**: align the install document caps with `MaxStatusFrame` and add boundary tests. Have software Provision mirror the TPM `provision.go` (checkPrivateDir, Lstat pre-checks, all-or-nothing writes, syncDir).
6. [ ] **02-03**: make ReadMessage refuse length < 2 before reading the header, and add read and write boundary tests at each cap.
7. [ ] **02-07 / 02-08 / 02-09**: define what reinvite does (fresh user_handle; reset `invite_used_us`; treatment of orphaned pending credentials). Finish must check that the invite is still current. DeleteBound may remove only what the install newly binds, and never an open, unexpired invite.
8. [ ] **02-12**: check PKCE (and the verifier format, exactly 43 base64url characters) before burning the code. Compute the agent lifetime from a single `now`. Add `defer clear(priv)`. Add a reaper for `login_sessions` and a threat row for what `/login/options` discloses.
9. [ ] **02-01**: add golden vectors for the new formats (directory_install and login_issue leaves, login-request signing bytes, directory JSON, kr2). Assert exact principals, key and validity window in the E2E. Make the testhelper dependency check a CI gate.
10. [ ] **02-07**: re-attach the verified body for the handler, define path canonicalisation (`RequestURI`), add a round-trip test of the printed `keyroster init` line including `--tls-root-file`, and add a clock-skew hint on 401.
11. [ ] **02-13 / 02-14**: back up the systemd unit and write out the rollback commands, add resume guidance after v3, scope `sshd -T -C`, use serial-based journal correlation, and use jq and `audit verify --json` checks.
12. [ ] **Remaining LOW items**: wording and test additions as listed in each finding (e.g. 02-09-F14 `directory_sign_refuses_non_admin_sig`, 02-04-F2 positive multi-successor fixture, 02-03-F12 clientDataJSON accept case, 02-05-F16 stdlib-only inconsistency).

---

## Appendix: Verified Findings (surviving)

CONFIRMED/PARTIAL findings, by plan. The evidence is the verifier's, with plan-line and source citations.

### 02-01

- **02-01-F2 [PARTIAL/LOW] Migration 0004_directory ordering and interaction untested** (nemotron)
  - Evidence: Ordering is enforced by existing Phase 1 code that the plan reuses. internal/signerdb/migrate.go:24-52 (loadMigrations) sorts the embedded NNNN_*.sql files and refuses any gap or out-of-sequence version. migrate.go:58-90 applies ms[current:] from PRAGMA user_version, each migration in its own transaction together with the version bump, and refuses a newer schema (migrate.go:67-69). So a Phase 1 DB at user_version=3 gets exactly 0004 applied, and this is the same code path a fresh DB takes. On interaction: the plan (02-01-PLAN.md:242) defines `directory(version INTEGER PRIMARY KEY CHECK (version >= 1), doc BLOB, sigs BLOB, policy_version INTEGER, installed_at_us INTEGER)` as a standalone table. It has no foreign keys and does not alter trust_bundle or any other 0001-0003 table. policy_version is only a value that the signer checks in loadDirectory/InstallDirectory (02-01-PLAN.md:249-256). On tests: internal/signerdb/db_test.go:74-146 (TestMigrations) is generic over len(ms), so with 0004 added it automatically covers a fresh migration to the new head, idempotent reopen, and refusal of a newer schema. Restart and tamper behaviour of the stored directory is covered in 02-03-PLAN.md:212 (`restart_under_new_admins`, `stored_directory_tampered`). What is missing: no test builds a real version-3 DB containing Phase 1 data (trust_bundle rows, issuance, log) and then opens it with the Phase 2 binary to check that 0004 applies cleanly and leaves the existing rows intact.
  - Fix: Optionally add a `upgrade_from_v3` subtest to TestMigrations. It applies only the first three migrations, inserts a trust_bundle row and an issuance row, then reopens with the full migration set. It checks that user_version is 4, that the directory table exists and is empty, and that the Phase 1 rows are unchanged.

- **02-01-F5 [PARTIAL/LOW] authenticatorData fixed at exactly 37 bytes may refuse real authenticators** (gptoss)
  - Evidence: 02-01-PLAN.md:55 (must_haves truth) and :214/:216 do require authData exactly 37 bytes with AT/ED clear, and :238 caps the signature at 1024 bytes. This strictness is a deliberate, documented choice, not an oversight. 02-RESEARCH.md:298 says the signer requires 37 bytes with AT/ED clear "because no extensions are requested. So no CBOR is ever parsed in the signer." 02-RESEARCH.md:690 calls this the key way of keeping the only new signer parser small. 02-RESEARCH.md:909 records it as assumption A6, with the fallback "widen to 'ED allowed, extensions ignored' only after seeing real data". 02-08-PLAN.md:262 lists AT set and ED set as an intentional `strictOnly` set in the go-webauthn differential test. Only AT (bit 6) and ED (bit 7) are refused. BE/BS (bits 3/4), the flags that real synced passkeys actually vary on, are not refused (02-01:216; 02-08:258 records BE/BS). The 1024-byte signature cap covers RSA up to 8192 bits (512 B for RSA-4096; ECDSA about 72 B), so that part of the claim has no merit. Real authenticators are exercised before the phase closes: 02-13-PLAN.md:247 (Windows Hello, phone passkey or security key) and 02-14-PLAN.md:62 (real logins on Windows and Linux, corroborated from the audit log). A refusal fails closed with a named sentinel (ErrAuthenticatorData / bad_authenticator_data), so it does not fail open. One narrow gap: 02-14-PLAN.md names the A3 probe (:139) but does not explicitly name A6 as a recorded dogfood check, and gives no decision path if the owner's authenticator returns ED.
  - Fix: Keep the strict 37-byte, AT/ED-clear check. In 02-14 (or 02-13), add an explicit A6 check: record the authData length and flags from each real authenticator used, and if a login is refused with bad_authenticator_data because ED is set, stop at a human decision (widen to "ED allowed, extensions ignored" in a follow-up plan) instead of patching it ad hoc.

- **02-01-F7 [PARTIAL/LOW] E2E test may not tell signer authorization apart from sshd config** (codex, nemotron)
  - Evidence: 02-01-PLAN.md:283-286: the test runs signerclient.Login (step 5) and gets a certificate before any sshd is started. The u:other sshd is then given "the same certificate" (step 6). So the refusal cannot come from the signer: the signer has already issued. The control sshd with role:ops accepts the same certificate under the same harness CA config (startSSHD, test/e2e/harness_test.go:251,264,270), which rules out a host/CA misconfiguration. Step 7 (02-01-PLAN.md:286) already checks the kr2 key ID (sub=alice, roles=ops). Acceptance (02-01-PLAN.md:301) requires the log to show both the sshd refusal and the accepted login. The signer-side refusals are covered with exact detail assertions elsewhere: 02-03-PLAN.md:134-155 (TestLoginRefusals through the socket, each case with a control) and 02-03-PLAN.md:164-173 (a named unit case for every detail, including principals_mismatch and ttl_exceeds_role). The login_issue leaf and the certificate binding are checked in 02-04-PLAN.md:135-146: audit verify re-checks that ValidPrincipals equal the request principals, the validity window, Key == SubjectKey and the kr2 fields. That plan also has an e2e test (02-04-PLAN.md:150-157) and a tamper suite (02-04-PLAN.md:177-188, including "request principals widened"). The CLI checks ValidPrincipals for exact equality and checks the TTL window at 02-12-PLAN.md:204-210. What is still missing: nothing in 02-01 itself (TestLoginSignerEndToEnd or the Task 2 units, 02-01-PLAN.md:310-317) checks that the issued certificate's ValidPrincipals are exactly ["role:ops"], or checks its validity window or Key. sshd's accept/refuse cannot catch a certificate that carries a superset of principals.
  - Fix: In TestLoginSignerEndToEnd step 7, parse the returned certificate and assert three things: ValidPrincipals == ["role:ops"] exactly, Key equals the ephemeral public key, and ValidBefore − ValidAfter ≤ 600 + 300. Leave the login_issue leaf checks to 02-04 as planned.

- **02-01-F19 [PARTIAL/LOW] Soft authenticator could leak into production binaries** (gptoss, nemotron)
  - Evidence: 02-01-PLAN.md:225 says "internal/webauthn/webauthntest (new; imported only by tests)". 02-01-PLAN.md:330 and :344 add the check `test "$(go list -deps ./cmd/... | grep -c webauthn/webauthntest)" = 0`. 02-08-PLAN.md:233 repeats it for both `server/servertest` and `webauthn/webauthntest`. `go list -deps` prints the full transitive import closure of non-test files, so an indirect import through any intermediate package does appear. The reviewers' core claim is therefore wrong. The real gap is narrower. This check is only an acceptance step that the executor runs in 02-01 and 02-08, and nothing turns it into a CI gate. scripts/dep-firewall.sh, which CI runs at .github/workflows/ci.yml:100, checks a BANNED list (scripts/dep-firewall.sh:22-33) and only for the signer graph. It runs once with no build tags and once with `-tags piv`, while the plan's own check runs only with the host's default tags and GOOS. Later plans (02-09..02-12 wiring the server and CLI) re-run dep-firewall and capslock but not the webauthntest grep (e.g. 02-10-PLAN.md:215, 02-12-PLAN.md:303). Even if the helper were linked, it creates no bypass: 02-01-PLAN.md:104 says the signer verifies every assertion itself, and there is no test-only path.
  - Fix: Make the check permanent instead of moving the package. In CI (or a small mode in scripts/dep-firewall.sh), run `go list -deps ./cmd/...` with no tags and with `-tags piv`, and for GOOS linux and windows, and fail if internal/webauthn/webauthntest or internal/server/servertest appears.

- **02-01-F21 [CONFIRMED/LOW] No pinned format test vectors for new formats** (codex)
  - Evidence: Phase 1 already pins golden vectors: test/vectors/ holds leaf_issue_v1.hex, policy_genesis_v1.json, bundle_genesis_v1.json and the checkpoint_*.golden files. internal/tlog/leaf_test.go:17-53 has a `-update` flag that rewrites them and an issueVector fixture, and internal/trust/vectors_test.go follows the same pattern. Plan 02-01 Task 2 (02-01-PLAN.md:309-317) checks the new formats only by round-trip. LoginIssueRequest gets Marshal/Parse plus a SigningBytes prefix check on `keyroster/login-request/v1` (line 316). DirectoryInstallBody and LoginIssueBody get a round-trip and a trailing-byte refusal (line 317). kr2 gets a round-trip (line 315). The directory document is checked for insertion-order canonicality (line 311). The only pinned vectors the plan mentions are the existing Phase 1 files (lines 51, 310, 315), used to show that nothing regressed. Sibling plans add nothing here. 02-03 (line 236) seeds fuzz corpora "from valid vectors", but those are generated, not golden files. 02-04 and 02-14 consume kr2 and kinds 7/8 without pinning their bytes. A grep for golden, .hex and test/vectors across 02-*-PLAN.md, 02-CONTEXT.md and 02-RESEARCH.md finds no new vector file. The plan itself calls these exact formats costly to change: line 169 says the directory format, login-request signing bytes, log kinds 7/8 and kr2 "are read by audit verify, by Phase 3 agents and by every later log".
  - Fix: Add golden vectors to Task 2, using the existing `-update` convention. Commit test/vectors/leaf_directory_install_v1.hex, leaf_login_issue_v1.hex, login_request_signing_v1.hex and directory_v1.json, plus a fixed kr2 key ID string, each with a byte-equality test. Name these cases in the acceptance criteria.

### 02-02

- **02-02-F1 [PARTIAL/LOW] VerifyServerOwner / Ensure may be bypassable by a raced or replaced pipe** (codex, gptoss)
  - Evidence: The plan's check (02-02-PLAN.md:204-212) is: Fd() → GetNamedPipeServerProcessId → OpenProcess/OpenProcessToken/GetTokenUser → compare the SID. Ensure runs that check on the connection it returns, before any key is sent (lines 209-212 and must_haves line 62, "Ensure returns a connection only after VerifyServerOwner"). T-02-07 is at line 356. The concrete types support this. go-winio v0.6.2 DialPipeContext returns &win32Pipe{win32File: f} (pipe.go:306). win32Pipe embeds *win32File (pipe.go:112-113), so win32File.Fd() (file.go:277, returns the raw handle) is promoted onto it. golang.org/x/sys/windows already wraps GetNamedPipeServerProcessId (syscall_windows.go:172, zsyscall_windows.go:2524). Serve uses ListenPipe first-instance creation with the SDDL D:P(D;;GA;;;NU)(A;;GA;;;<sid>) (lines 200-201), so other accounts cannot add instances to our pipe. Tests (lines 220-228) only cover the positive path: "VerifyServerOwner succeeds on our own pipe" and "Ensure ... returns a verified connection". No test shows that a pipe served by a different SID is refused. The pipe name keyroster-agent-<SID> is deliberately stable user configuration (IdentityAgent in ~/.ssh/config). It has reversibility "costly" (line 181).
  - Fix: Add a negative test for the owner check. Factor the SID comparison into a helper that takes the server SID as a parameter, then assert it returns an error naming both SIDs when they differ, using a well-known foreign SID such as S-1-5-18. Also assert that Ensure fails closed when the verifier rejects. Do not add a nonce to the pipe name or a separate race test.

- **02-02-F5 [PARTIAL/LOW] Agent lifecycle: polling keyring.List() and exiting when empty can shut down early or never exit** (codex)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-02-PLAN.md:202 defines the lifecycle as a polled check followed by an exit: every opts.Poll (5 s), call keyring.List(); if a key was ever added and the list is now empty, return nil, otherwise return after IdleExit (5 min) when no key was ever added. Line 201 says one keyring is served with agent.ServeAgent on every accepted connection. No step makes the exit atomic with accepting or serving connections: nothing closes the listener and then re-checks the list, and nothing waits for in-flight connections to finish. The consumer is 02-12-PLAN.md:213-214. On Windows it calls winagent.Ensure (which dials the existing pipe), then Add, then List to confirm. Step 10 only proves the certificate is present on that connection at that moment. Ensure (02-02:209-212) starts a new agent only on file-not-found. A dying agent whose pipe is still open is reached and used. The tests (02-02:222-233) cover expiry-exit and idle-exit only one at a time, not an Add that overlaps an exit. 02-CONTEXT.md:113 (D-15) locks the lifetime-in-agent design but says nothing about this ordering.
  - Fix: In Serve, make the exit decision atomic with connection handling. Track in-flight connections under a mutex, close the listener first, re-check keyring.List() and active connections before returning, and resume serving if a key arrived. Add a winagent test where an Add races the expiry poll. Optionally have Ensure retry the dial or start once if the connection drops right after Add.

- **02-02-F8 [PARTIAL/LOW] SID check fails for elevated, runas or service tokens** (gptoss)
  - Evidence: 02-02-PLAN.md:200 has PipePath = `\\.\pipe\keyroster-agent-<current user SID>`, so the pipe is per-user. 02-02-PLAN.md:204-208 has VerifyServerOwner: GetNamedPipeServerProcessId, then OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), then OpenProcessToken and GetTokenUser, and requires that SID to equal the caller's. 02-02-PLAN.md:209-212: Ensure calls VerifyServerOwner before it returns. 02-02-PLAN.md:201: first-instance ListenPipe refuses an existing pipe. 02-02-PLAN.md:203: the agent exits on idle (5 min) or when its last key expires. 02-02-PLAN.md:356: threat T-02-07 is pipe squatting, mitigated by this check. 02-02-PLAN.md:226 tests only the positive case ("succeeds on our own pipe"). No mismatched-SID test and no elevation note appear anywhere in 02-02 or the other 02-* plans (grep for elevat/UAC/runas/integrity finds none relevant).
  - Fix: In VerifyServerOwner, turn an access-denied from OpenProcess/OpenProcessToken into a clear fail-closed error that tells the user the agent may have been started elevated and how to stop it. Document that runas and other accounts get their own per-SID agent. Add a negative test asserting that a mismatched SID is refused (for example by comparing against a fixed foreign SID through an injectable expected-SID).

### 02-03

- **02-03-F5 [PARTIAL/LOW] Frame header and length boundaries not tested adversarially** (codex, gptoss)
  - Evidence: Most of what the finding asks for is already in the plan. - 02-03-PLAN.md:234 adds a test that a 64 KiB+1 issue frame and a MaxDirectoryFrame+1 install frame are refused before allocation. That test uses a reader that fails if anything past the header is read, which is the allocation guard the finding says is missing. - 02-03-PLAN.md:237 adds FuzzReadMessage and :236 requires no panics. The existing FuzzReadFrame seeds at internal/wire/fuzz_test.go:45-75 already include length 0, 1<<30, MaxFrame+1 and short frames. - Phase 1 tests already cover length 0, MaxFrame+1, exactly MaxFrame, a short header and a short payload (internal/wire/wire_test.go:252-314). They also check that a 1 GiB header reads only 4 bytes and allocates under 1 MiB (wire_test.go:253-269). - Unknown types are explicitly mapped to MaxFrame (PLAN:230). One gap is real. PLAN:231 says the reworked ReadMessage "reads the 4-byte length, rejects 0, reads the 2-byte version and type header, ... refuses `length - 2 > maxBodyFor(type)`". It never rejects length 1. The current code rejects it implicitly, because it reads the whole payload first and then checks `len(payload) < 2` (internal/wire/frame.go ReadMessage). In the new shape, a length-1 frame has two problems: - Reading the 2-byte header takes one byte from the next frame, so the stream desyncs. - `length - 2` either underflows (uint32 wraps, so it happens to be refused) or becomes -1 (int, so the check passes and `make([]byte, -1)` panics). The existing test `payload_without_type` (wire_test.go:325-333) would not catch the desync. Its buffer holds only that frame, so the 2-byte read fails with ErrUnexpectedEOF, which still satisfies the assertion "non-nil and not ErrVersion". The plan also does not explicitly test acceptance at exactly MaxDirectoryFrame for TypeInstallDirectory and TypeGetDirectoryResponse, or an unknown type at MaxFrame+1. Both are minor.
  - Fix: In Task 3, make ReadMessage refuse any length below 2 before it reads the 2-byte header, and do the cap comparison in unsigned or widened arithmetic. Add table cases for: - length 1 followed by a second valid frame, which must be refused without consuming the second frame; - length 2 (header only, empty body); - exactly MaxDirectoryFrame for both directory types (accepted) and exactly MaxFrame for issue (accepted); - an unknown type at MaxFrame+1 (refused before allocation).

- **02-03-F10 [PARTIAL/LOW] No test that WriteMessage rejects oversized outgoing frames** (gptoss)
  - Evidence: Plan 02-03-PLAN.md:231 says "WriteMessage enforces the same cap", but the only tests Task 3 adds (line 234) are read-side: a 64 KiB+1 issue frame and a MaxDirectoryFrame+1 install frame "refused before allocation" by a reader. The only check on the write side is acceptance line 261, a grep showing that maxBodyFor appears in WriteMessage. That proves the name is there, not how it behaves. In the current code, WriteMessage (internal/wire/frame.go:75-80) passes through WriteFrame, which enforces the flat MaxFrame (frame.go:63). The existing test wire_test.go:307 only covers WriteFrame with MaxFrame+1. Task 3 has to change WriteMessage so it allows directory types up to MaxDirectoryFrame (more than MaxFrame), which means bypassing or changing WriteFrame. That rewrite is exactly where a write-side regression can slip in, for example a type mapped to the wrong cap or an off-by-2 in the header, and no planned test would catch it. Partial mitigation: the security boundary is the reader-side cap, which is tested (line 234) and fuzzed (FuzzReadMessage, line 237), so an oversized outgoing frame would still be refused by the peer. WriteFrame already builds the whole buffer and writes it once (frame.go:66-69), so "no bytes before the error" is close to guaranteed by construction.
  - Fix: In Task 3, add a write-side table test. WriteMessage(TypeInstallDirectory, body with len(body) == MaxDirectoryFrame) succeeds, and with MaxDirectoryFrame+1 it returns ErrFrameTooLarge and writes nothing to a recording writer. Likewise TypeIssueRequest at MaxFrame-2 succeeds and at MaxFrame-1 is refused, so the boundary holds in both directions. Make that test the acceptance check alongside the maxBodyFor grep.

- **02-03-F12 [PARTIAL/LOW] Seed corpora for clientDataJSON and GetDirectoryResponse fuzzers** (gemma, gptoss)
  - Evidence: The GetDirectoryResponse half is already covered. 02-03-PLAN.md:236 requires "seed corpora from valid vectors plus mutations" for every target, and the existing pattern at internal/wire/fuzz_test.go:9-25 already seeds valid, truncated (valid[:len/2]), trailing-byte, empty and over-limit inputs. FuzzParseGetDirectoryResponse (02-03-PLAN.md:237) is a strict u64/u24/u24/u8 decoder (02-03-PLAN.md:131), so it follows that pattern. "Mismatched versions" means nothing at this layer: Version is just a u64 field, and chain and version checks belong to directory.CheckSuccessor (02-01-PLAN.md:206). "Truncated signatures" are covered by the truncation seeds. The clientDataJSON half points at a real gap. 02-01-PLAN.md:223 says the parser "skips unknown members, because browsers inject extra keys" (see also RESEARCH.md:302 and :890, which name Chrome's other_keys_can_be_added_here). But the default webauthntest vector has no extra keys: 02-01-PLAN.md:229 gives it as `{"type":"webauthn.get","challenge":..,"origin":..,"crossOrigin":false}`. The 02-01 tests (02-01-PLAN.md:315) cover only the happy path and four refusals. The 02-03 Task 2 matrix (02-03-PLAN.md:169) lists only refusals for client data. 02-08's differential test reuses the 02-03 mutation vectors (02-08-PLAN.md:42). No plan has a positive case saying that clientDataJSON with extra members (other_keys_can_be_added_here, tokenBinding, a nested object or array value) parses and verifies. The fuzz targets assert only "sentinel error or no panic" (02-03-PLAN.md:236), so seeding the fuzzer as the reviewers propose would exercise the skip path for crashes. It would not prove that unknown members are accepted.
  - Fix: Add to 02-03 Task 2 (internal/webauthn/verify_test.go) one accept case: clientDataJSON with Chrome's other_keys_can_be_added_here, a tokenBinding object and an unknown array member must verify for an otherwise valid assertion, built with webauthntest.WithClientDataJSON. Also add that JSON as a seed to FuzzParseClientData. No change is needed for FuzzParseGetDirectoryResponse.

- **02-03-F13 [PARTIAL/LOW] GetDirectory empty-state test** (nemotron)
  - Evidence: The empty-state version check is already tested. 02-03-PLAN.md:43 (must_have) promises "version 0 when none is installed". Task 1, case 4 `directory_not_quorum_signed`, at 02-03-PLAN.md:138-141 asserts through the real socket that, after a refused install (so nothing is installed), "GetDirectory then reports version 0". Sibling plans assert the same no-directory state: 02-07-PLAN.md:177 ("signerclient.GetDirectory reports version 0") and 02-08-PLAN.md:223 ("signerclient.GetDirectory still reports version 0"). FuzzParseGetDirectoryResponse (02-03-PLAN.md:237) covers the parser. No plan asserts the other three fields when nothing is installed: Directory and Sigs empty, Authorized=false. The wire shape at 02-03-PLAN.md:131 also does not require ParseGetDirectoryResponse to reject a version-0 response that has non-empty bytes or Authorized=1. The consumer is the server mirror (02-09-PLAN.md:139), which caches by version, so a version-0 response with stray bytes would still be treated as "no directory". That makes the gap cosmetic, not security-relevant.
  - Fix: Extend the existing Task 1 case 4 step at 02-03-PLAN.md:140 to "GetDirectory then reports version 0, empty Directory and Sigs, and Authorized=false". Optionally, have ParseGetDirectoryResponse reject a version-0 response with non-empty bytes or Authorized=1.

- **02-03-F16 [PARTIAL/LOW] Each new refusal reason recorded in the audit log with exact Reason and request hash** (gptoss)
  - Evidence: Phase 1 sends every refusal through one function. internal/signer/refusal.go:72-96 (refuseLogging) writes a tlog.RefusalBody{RequestDigest: digest, PeerUID, Reason: class, Detail: detail}, where detail is the exact reason string. refuseErr (refusal.go:175-185) calls classify(r.reason). Above the rate limit, a refusal is only counted per reason class in a refusal_summary leaf (refusal.go:80-82, 102-138, D-14). That leaf has no detail and no digest by design, so "every refusal with its request hash" contradicts the locked D-14 design. 02-01-PLAN.md:258 sends directory-install refusals through refuseErr with digest SHA-256(doc). 02-01-PLAN.md:261-266 names each login refusal detail, including no_webauthn_policy, unknown_evidence_type and directory_changed. 02-03-PLAN.md:38 and :173 require each new detail to leave a refusal leaf or a refusal_summary count, and require that classify never returns ReasonInternal. :213 greps refusal.go for the new details. :146 has the e2e export-log check for refusal entries. The real gap is narrow. 02-01-PLAN.md:271 does not say which digest the LoginIssue dispatcher passes; the Phase 1 issueOrRefuse at refusal.go:156-166 passes req.Digest(). No 02-03 test checks that a login or InstallDirectory refusal leaf carries the matching RequestDigest and the exact Detail. Phase 1 checks this only for the admin path, in refusal_test.go:206-220 (TestRefusalLeavesCarryDigestAndPeer).
  - Fix: In 02-03 Task 2, add one assertion modelled on TestRefusalLeavesCarryDigestAndPeer, run below the rate limit. A LoginIssue refusal (e.g. no_webauthn_policy) must produce a refusal leaf whose Detail is the exact string and whose RequestDigest equals req.Digest(). An InstallDirectory refusal must produce a leaf whose RequestDigest equals SHA-256(doc). Also state in 02-01 that login refusals pass req.Digest().

### 02-04

- **02-04-F2 [PARTIAL/LOW] No positive multi-successor fixtures (policy change + directory change + login, old/new CA)** (codex, nemotron)
  - Evidence: The plan states the rule but never tests the case where it must accept. .planning/phases/02-passkey-login-mvp/02-04-PLAN.md:137 says the login_issue directory "may have been re-checked after a later bundle_install, which mirrors the signer's directory_not_authorized rule". Line 136 requires DirectoryVersion and PolicyVersion to match the versions in force. Line 134 requires the PolicyVersion in a directory_install body to equal the policy in force when it is installed. Together these allow a valid log with directory v1 installed under policy v1, a later RP-adding policy v2, then a login (dir=1, pol=2), and audit verify has to accept it. No fixture builds that log: (a) The e2e TestAuditLoginAcrossPolicyChange (02-04-PLAN.md:150-157) installs directory v1 only AFTER the policy change (step 6 comes after steps 3-5). (b) The tamper suite (02-04-PLAN.md:177-188) has only negative cases. `login_under_unauthorized_directory` (line 188) is the rejection side. "The untampered log passes" is the base log, which is not described as containing a directory that outlives a policy change. (c) The homelab run (02-13-PLAN.md:174-205, 281) installs bundle v3 with the RP before any directory or login, so it does not exercise this either. (d) 02-03-PLAN.md:41, 176 and 199 cover the same sequence ("a policy change the directory still satisfies, such as adding the RP, leaves it authorized"; restart re-verification) on the signer only. Those plans never run audit verify on that log. A directory can be installed under an RP-less policy (02-03-PLAN.md:143), so the scenario is real. The "old and new CA material" part is weaker. login_issue reuses the kind-1 rule "signed by the active user CA in force" (02-04-PLAN.md:143). That rule is the existing anchor.activeCA check (internal/audit/verify.go:186-198), and Phase 1 fixtures already cover issuances across successor bundles (internal/audit/verify_test.go:1074 TestVerifyAnchorsOnLaterBundle, rotatedTo). Phase 2 also never changes CA keys: successor-policy edits only the RP (02-04-PLAN.md:122-129), and the 02-13 dry run requires the "CA, ops and log keys unchanged" (02-13-PLAN.md:199).
  - Fix: In the Task 1 e2e, install directory v1 (signed by the unchanged admin) BEFORE the successor-policy step and log in after the restart under policy v2, so audit verify must accept a login with dir=1 and pol=2. Alternatively, add an equivalent positive in-process case to the Task 2 suite, such as `login_directory_survives_rp_policy_change`, next to the negative `login_under_unauthorized_directory`.

- **02-04-F8 [PARTIAL/LOW] Directory re-parse per login_issue may be O(N^2) on large logs** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-04-PLAN.md:133 says "In the leaf walk, keep the directory in force (raw bytes, parsed, version), the way the policy in force is kept." So the directory is parsed once, at its directory_install leaf (line 134: directory.Parse, CheckSuccessor, VerifySignatures, CheckPolicy, "Then make it the directory in force"), not again for each login_issue. Line 136 checks login_issue against the cached version numbers. The only open point is line 137: "the directory verifies under the policy in force at this leaf; it may have been re-checked after a later bundle_install". This does not say whether the quorum-signature check is cached per (directory, policy) pair or run again for every login_issue leaf.
  - Fix: Reword line 137 to say the directory is checked against the policy in force only when one of them changes (at directory_install and after each bundle_install), and that the stored result is reused for each login_issue leaf. This is optional and only removes repeated checks; the cost is already linear.

### 02-05

- **02-05-F1 [PARTIAL/LOW] Passphrase buffer not guaranteed cleared on every error path** (codex)
  - Evidence: 02-05-PLAN.md:145 requires the backend to "clear the byte slice after use". Line 130 tells the executor to copy the internal/rootceremony/keygen.go pattern, and the plan quotes `defer clear(plain)` by name. In the real code, a deferred clear runs on every return path: internal/rootceremony/keygen.go:40, 47 and 98, and passphrase.go:42. The early-return error paths also clear: passphrase.go:44, 48, 59, 76 and 83, and keygen.go:119 and 124. Line 147 (Key) puts wrong passphrase, parse failure and fingerprint mismatch after the passphrase has been used. A deferred clear covers all three. Lines 224 and 268 test that a wrong passphrase is not echoed, but nothing tests that memory is zeroed. T-02-23 (line 335) says only "buffer cleared". Two mechanisms limit what clearing can achieve. First, age.NewScryptIdentity and NewScryptRecipient take a Go string, so `string(passphrase)` makes a copy that cannot be zeroed. keygen.go:29-31 already documents this as "best effort: the passphrase string age derives its key from cannot be zeroed". Second, T-02-21 (line 333) accepts that the passphrase file sits on the same host, readable by the signer user. That makes leftover passphrase bytes in heap memory a marginal extra exposure.
  - Fix: Reword line 145 to say: read the passphrase into a []byte and `defer clear()` it right after reading, so it is zeroed on every return, including the short-passphrase and mode refusals and errors from Key and Provision. Also state that the backend does not keep the passphrase longer than the call that needs it, or re-reads it from the file for each Key/Provision. Note in T-02-23 that the string copy passed to age cannot be cleared (best effort, as in keygen.go:29-31).

- **02-05-F2 [PARTIAL/LOW] Key-file creation: atomicity, symlinks, existing-dir permissions, partial-provision cleanup** (codex)
  - Evidence: Plan 02-05-PLAN.md:146 is the whole Provision spec: "refuse if {state-dir}/software already holds any .age file ... Write with O_EXCL, mode 0600, in a 0700 directory, then fsync." It says nothing about cleaning up after a mid-loop failure, about checking an existing directory (Lstat, not a symlink, no group or other bits), or about fsyncing the directory. The Task 3 matrix (02-05-PLAN.md:220-228, 268) tests only provision_refuses_existing, with no cleanup or permissive-directory case. The repo already solves every one of these points in the sibling TPM backend: - internal/keystore/tpm/provision.go:39-45 runs Mkdir and then checkPrivateDir even when the directory already exists. - tpm.go:270-284: checkPrivateDir uses Lstat, rejects anything that is not a directory, so a symlink fails, and requires no group or other bits. - provision.go:60-66 runs a Lstat pre-check on every target before any work starts. - provision.go:105-124: removeWritten gives "write all files, or none". - provision.go:130-139: syncDir covers the key directory and also the parent when Provision created it. - provision.go:214-231: writeNew uses O_EXCL, Sync, and removes the file on error. - tpm.go:286-300: readPrivateFile uses Lstat, requires a regular file and 0600 on read. The plan's read_first (02-05-PLAN.md:129) names only internal/keystore/tpm/tpm.go, not provision.go, so the executor is not pointed at the all-or-nothing and directory-sync code. Parts of the claim are wrong: - temp+rename is not needed. O_CREAT|O_EXCL already refuses a symlink or any existing name at the final path component, and remove-on-failure gives the same atomicity at the file-set level, as the TPM backend shows. - Ownership checks go beyond the existing pattern. checkPrivateDir checks mode only, and systemd's StateDirectory with mode 0700 controls ownership.
  - Fix: Add internal/keystore/tpm/provision.go to Task 1 read_first and require the software Provision step to mirror it. That means checkPrivateDir on an existing {state-dir}/software, an Lstat pre-check on every target, all-or-nothing writes with removeWritten on any failure, and syncDir on the key directory (and on its parent when Provision creates it). Key() should read through an Lstat, regular-file, 0600 check. In Task 3, add the test cases provision_cleans_up_on_failure (inject a failure into a write or a directory sync and assert that no .age file is left) and provision_refuses_permissive_dir.

- **02-05-F4 [PARTIAL/LOW] Passphrase strength and scrypt work factor vs offline brute force** (codex, gemma)
  - Evidence: 02-05-PLAN.md:36 (truth 2: passphrase only from file or systemd credential, at least 20 runes, file must not be group/other readable). 02-05-PLAN.md:146 (Provision: "one scrypt recipient at age's default work factor"). 02-05-PLAN.md:158 (banner: "EVALUATION ONLY ... Anyone who copies the key files and their passphrase can issue certificates. Do not use this instance for real access"). 02-05-PLAN.md:241-246 (custody.md section: evaluation only; "a passphrase stored on the same host makes the key equivalent to plaintext"; passphrase sources; doctor WARN). 02-05-PLAN.md:333 (T-02-21: key files plus passphrase on the same host is rated high and accepted as inherent to the software level). 02-05-PLAN.md:117 (the 20-rune rule is inherited from the locked STATE.md 01-09 decision). In docs/security/custody.md:108 the only passphrase text is about the root keys; nothing covers entropy, scrypt cost or offline guessing.
  - Fix: In Task 2's custody.md "Software CA keys (KEY-06)" section, add one bullet: if the .age files leak alone (from a backup or a copied state dir), they can be attacked offline. Protection then depends only on the passphrase's entropy, at age's default scrypt cost. The 20-rune check is a length floor, not a strength check, so use a randomly generated passphrase. Optionally, extend T-02-21's disposition to name this file-only case.

- **02-05-F6 [PARTIAL/LOW] MaxStatusFrame 256 KiB sizing and boundary testing** (nemotron, gptoss, codex)
  - Evidence: Plan 02-05-PLAN.md:151-153 puts Bundle, BundleSigs, Policy and PolicySigs (each u24-prefixed) in StatusResponse, with `MaxStatusFrame = 256 << 10`. The directory itself is not included, only DirectoryVersion and DirectorySHA256 (line 151), so the reviewers' worry about "directory material" growing is wrong: the 1 MiB directory (02-03-PLAN.md:228) never goes into Status. The real mismatch is in Phase 1 code. The signer accepts bundle and policy documents much larger than 256 KiB. cmd/keyroster-signer/install.go:47-54 reads all four files with uncapped os.ReadFile and passes them to signer.InstallBundle. The only limit is in the audit leaf: internal/tlog/leaf.go:77 sets `MaxDocument = 1 << 20` per document, enforced at leaf.go:513-516. So a signer can install up to about 4 MiB of documents that Status can then never serialize. Plan 02-05 adds no install-side cap that matches the Status budget. In Task 3 (02-05-PLAN.md:230), the Status codec tests cover only round trip, a trailing byte and more than 8 keys; nothing marshals a maximal response at or just past MaxStatusFrame. The failure would not be silent. Line 163 says a Status failure aborts ca issue, and 02-06-PLAN.md:181 says the server serves 503. But that means an accepted install could block all issuance and the server, and recovery would take a new root-signed bundle or policy successor.
  - Fix: Make the two limits agree. Either have signer.InstallBundle (or the Status encoder's budget check) refuse to install documents whose combined size cannot fit in a StatusResponse under MaxStatusFrame, or derive MaxStatusFrame from the documented document caps. Add a Task 3 codec test showing that a StatusResponse exactly at the budget round-trips through WriteMessage/ReadMessage, and that one byte more is refused with an explicit error.

- **02-05-F7 [PARTIAL/LOW] Blocking banner-wording checkpoint can stall; banner too long for terminals** (nemotron)
  - Evidence: 02-05-PLAN.md:189-213 has Task 2 as `checkpoint:decision gate="blocking-human"`. Its own context (line 192) says "Changing it later is cheap (one constant plus the doc), so this is a wording review, not a one-way door", and it justifies the gate with "The owner asked for it as an in-plan checkpoint (RESEARCH Pattern 6)". Neither locked document supports that justification. 02-CONTEXT.md:140 puts "the exact banner text (D-18)" under Claude's Discretion. 02-CONTEXT.md:34 reserves `checkpoint:decision` for one-way items. 02-RESEARCH.md:665 says only "Owner wording review happens at the plan's checkpoint", and the Open Questions at RESEARCH:917-924 do not list the banner as an owner checkpoint (only D-09 and D-15 are listed). On length: the plan already records "long for a terminal line" as a con of the approve option (02-05-PLAN.md:197), and the edit option (line 199-202) lets the owner supply a shorter text, so the reviewer's shorter-form suggestion is already an option the plan offers. The CLI writes to stderr, framed by `!` lines (line 163), and terminals soft-wrap long lines rather than cut them, so the "truncated" part of the claim is wrong. The Phase 1 precedent `softwareRootBanner` (cmd/keyroster/root.go:80-86) is a multi-line, hard-wrapped constant at about 75 columns.
  - Fix: Option 1: downgrade Task 2 to a non-blocking review. Claude picks the wording under D-18 discretion and shows it to the owner in the PR at the existing Task 4 merge gate, and the line saying the owner asked for the checkpoint is removed. Option 2: keep the gate but cite its real basis, RESEARCH:665. Either way, hard-wrap the banner the way the existing softwareRootBanner in cmd/keyroster/root.go is wrapped, or keep the one-line text for the UI and wrap it only for terminal output.

- **02-05-F11 [PARTIAL/LOW] Stale custody / race between Status and issuance** (gptoss)
  - Evidence: Plan 02-05-PLAN.md:154: `Signer.Status()` runs under s.mu and builds its answer from "the keys and custody re-checked at start, the trust_bundle row in force". It "adds no new state". Line 163: ca issue calls Status before every request and aborts if Status fails, so the CLI always fetches status fresh on each issuance and never caches it. Line 39 says the same in must_haves. In the Phase 1 source, the signer never reloads keys or custody at runtime: - Keys are opened only at start, through openRoleKey (internal/signer/trust.go:210, :365, :441). - Custody is recorded at ca-init (trust.go:130-132) and checked against the bundle at start (trust.go:296-314). - If the installed bundle changes under a running signer, checkTrustCurrent (internal/signer/issue.go:215-229) refuses every request with trust_changed until a restart. A bundle change therefore cannot produce a successful issuance under a stale banner. - Issue holds s.mu (issue.go:50-51), but s.mu does not span two separate RPCs, and nothing in the plan says it does.
  - Fix: Optional hardening: have IssueResponse (or Status) carry the signer's bundle version or SHA-256. ca issue would then compare it with the Status reply and fail closed (or re-fetch Status) on a mismatch. Otherwise, add one sentence to the plan noting that custody is fixed for the life of the process and that trust_changed makes the signer refuse requests, so Status-then-Issue cannot diverge without a restart.

- **02-05-F16 [PARTIAL/LOW] custodytext should import only stdlib** (nemotron)
  - Evidence: The plan already sets the requirement. .planning/phases/02-passkey-login-mvp/02-05-PLAN.md:157 says "Banner constant (internal/custodytext, stdlib only, imported by the CLI and later the server; never by the signer)". The isolation that matters for security is already enforced by an acceptance check at 02-05-PLAN.md:182: "`go list -deps ./cmd/keyroster-signer | grep -c custodytext` prints 0". The plan contradicts itself, though. The very next lines (02-05-PLAN.md:158-159) define `func SoftwareRoles(keys []wire.KeyStatus) []string`, so custodytext must import internal/wire. internal/wire is not stdlib: internal/wire/issue.go:8 imports golang.org/x/crypto/cryptobyte. As written, the "stdlib only" statement cannot be true. The suggested enforcement tool does not fit. scripts/dep-firewall.sh:1-5 covers only keyroster-signer: it checks the signer's transitive graph against BANNED (net/http, templates, os/exec, and so on). custodytext is a CLI and server package, deliberately kept out of the signer graph, so this script is the wrong place for a stdlib-only rule about it. Sibling plans also never call on dep-firewall for non-signer packages (02-01-PLAN.md:328, 02-08-PLAN.md:271).
  - Fix: Fix the inconsistency in the plan text. Either change line 157 to "imports only stdlib and internal/wire", or have SoftwareRoles take plain role/custody pairs (for example `map[string]string`, or a local struct) so the package really is stdlib-only. Do not add a custodytext rule to scripts/dep-firewall.sh; the existing check at line 182 (the signer graph does not contain custodytext) is the right guard.

### 02-06

- **02-06-F1 [PARTIAL/LOW] TLS pin bootstrap at keyroster init relies on out-of-band pin verification** (codex)
  - Evidence: Covered: 02-06-PLAN.md:198 makes init require at least one explicit --tls-pin and that every given pin was observed. Without it, init only prints the pins and exits 2, so observed pins are never stored automatically. Line 199 keeps only the observed roots that match the given pins. Lines 187 and 54 say that after init only the pinned roots are used (no system roots), with VerifyConnection requiring a pinned root. Line 275 tests refuses_unobserved_tls_pin and no_config_written_on_refusal, and line 407 (T-02-25) covers this in the threat model. Delivery channel is covered: CONTEXT D-10 (02-CONTEXT.md:90) is a locked decision that the pin comes "in the invite or by keyroster init". 02-07-PLAN.md:39 has `user add` print the exact init line, including TLS pins taken from the admin's own verified config. The first admin's bootstrap is checked against openssl output on the server host (02-06-PLAN.md:314; 02-13-PLAN.md:216-217). Bundle authenticity does not depend on TLS: trust.VerifySelfSigned and MatchPins against --root-pin (line 189). Gaps: (a) the runbook at 02-06-PLAN.md:314 says "or the pin `keyroster init` prints". That is circular and turns the step into trust on first use, unless it is compared with an independent source. (b) Rotation and recovery are missing. RESEARCH.md:224-225 calls for a `keyroster init --repin` path with an out-of-band check, support for more than one pin, and a clear error when the CA moves to a new root (for example the Let's Encrypt root generation change). 02-06 offers only `--force` on an existing config (lines 201, 389), and neither the runbook nor the error text covers a root change.
  - Fix: Remove "or the pin keyroster init prints" from the runbook's first-admin step, or require it to be checked against the openssl output from the host. Also add a short "TLS root changed" section: the CLI error on a pin mismatch names `keyroster init --force` (or `--repin`) with pins re-confirmed out of band, as RESEARCH.md:224-225 recommends.

- **02-06-F4 [PARTIAL/LOW] Signer Status cache staleness and signer-down behaviour** (codex, gptoss, nemotron)
  - Evidence: Mostly covered already. 02-06-PLAN.md:181 says "A Status failure serves 503 from the API and the healthz route, and an error page from HTML routes". So a signer that is down or has crashed already makes /healthz and /api/v1/trust return 503, and every route goes through the same cache. 02-06-PLAN.md:239 tests that the 503 returned while the signer is down carries all the headers, and :267 adds a fake status source interface so that case can be unit-tested. A policy change after start is low-risk for three reasons. First, policies can only be changed with root successor-policy plus install and a signer restart (02-04-PLAN.md:107), and during that restart the server's Status calls fail, so it serves 503. Second, the server is untrusted by design (02-06-PLAN.md:400). Third, the signer re-verifies rpIdHash and origin against its own root-signed policy (02-01-PLAN.md:441 T-02-02, 02-12-PLAN.md:178 and :378 "the signer re-verifies everything"). Stale RP data in the server therefore cannot mint a certificate; at worst it causes a failed login or wrong display for about 5 s. One part is real: line 181 contradicts itself. If every Status failure returns 503, then "never fall back to stale RP data older than 60 s" implies a stale fallback that the first sentence rules out. An implementer could read it as a 60 s grace window during which /api/v1/trust and the banner use cached data after the signer goes down. There is also no named test for refresh failure after the cache has expired.
  - Fix: In line 181, replace the 60 s clause with one rule: when the 5 s TTL has expired and the refresh fails, every route fails closed (API/healthz 503, HTML error page) and there is no stale fallback. Add a Task 2 unit case `status_refresh_failure_fails_closed` using the fake status source and an injected clock.

- **02-06-F10 [PARTIAL/LOW] Root rotation / chain portability for pinned TLS roots** (codex, nemotron)
  - Evidence: Re-pin path exists: 02-06-PLAN.md:201 ("saveConfig. It refuses an existing file without --force"), :253 (test "existing config without --force"), :389 (CLI flags include --force). So re-running `keyroster init --force --tls-pin <new>` with an out-of-band check is the re-pin. That matches RESEARCH Q1 (02-RESEARCH.md:224): when the root changes, the pin "breaks closed" and is re-pinned through init. A separate `--repin` flag is only a naming difference. Several pins are supported: Config.TLSPins []string (02-06-PLAN.md:193), init accepts multiple --tls-pin and keeps every observed root whose pin was given (:198-199), and VerifyConnection accepts any verified chain whose root pin is in Pins (:187). Intermediate rotation under the same root is handled by design. After init, RootCAs holds only the stored roots and Go builds the chain from the intermediates the server sends (:187). RESEARCH 02-RESEARCH.md:224 says this survives intermediate rotation. Cross-platform chains: RESEARCH :221 calls out Windows/Linux chain differences ("pin every root seen at init"). 02-14-PLAN.md:137,156 checks that the laptop's observed TLS pin equals Daniel-PC's. 02-13-PLAN.md:216-217 does the out-of-band pin comparison. Real but narrow gaps: (a) RESEARCH :225 asks the CLI to "give a clear error" when a root pin stops matching. Task 1/2 of 02-06 define no specific error or hint for a post-init pinned-root mismatch (no "server root changed; verify out of band and re-run keyroster init --force"). The tests at :242-244 only check that the connection is refused. (b) There is no unit test that a new intermediate under the same pinned root is still accepted. (c) Init step 4 (:198) requires every given pin to have been observed, so you cannot pre-pin a future root (e.g. a new LE root generation) before the server serves it.
  - Fix: When no verified chain ends in a pinned root, serverclient should return a specific error naming the observed root pin and telling the user to verify it out of band and re-run `keyroster init --force --tls-pin ...`. Add a serverclient test that a leaf issued by a new intermediate under the same pinned root is accepted. Optionally, document in the runbook that re-pinning is `init --force`.

- **02-06-F11 [PARTIAL/LOW] Config file location and permissions across platforms** (nemotron, gptoss)
  - Evidence: The plan says config.json is written "0600 in a 0700 directory" at os.UserConfigDir()/keyroster (.planning/phases/02-passkey-login-mvp/02-06-PLAN.md:193, :53, :389). It says nothing about Windows ACLs. The file holds no secrets. Config is {Server, TLSRootsPEM, TLSPins, TrustPins, TrustThreshold, User, AdminKey} (02-06-PLAN.md:193). AdminKey is a `SHA256:...` fingerprint (02-06-PLAN.md:53, the `--admin-key SHA256:...` flag). Everything in it is public: pins, root certs, a URL and a username. So confidentiality does not apply. The only property worth protecting is integrity, because someone who can edit the file can swap the pins that T-02-25 relies on (02-06-PLAN.md:407). On macOS, os.UserConfigDir() is ~/Library/Application Support, and POSIX modes do work there. Go's os.MkdirAll(0700) and os.WriteFile(0600) are enforced, so the macOS half of the claim is wrong. On Windows, %APPDATA% sits under the user profile, which by default inherits an ACL of user + SYSTEM + Administrators. Anyone who can write there already runs as that user or as an admin, and could just as easily replace the keyroster binary or PATH. Being able to edit the file adds nothing to what that attacker can already do. Mode checks only run on Linux. The e2e check "config.json exists with mode 0600" (02-06-PLAN.md:211) is in the e2e suite, which runs only on ubuntu-24.04 (.github/workflows/e2e.yml:29). Phase 1 already has a precedent for skipping mode checks on Windows: cmd/keyroster/root_test.go:333 ("mode 0600 outside Windows") and :356 (`if runtime.GOOS != "windows"`). Sibling plans 02-09 (line 149) and 02-12 (line 196) only call loadConfig and do not check permissions.
  - Fix: Add one line to the config.go bullet. It should say that on Windows the modes are a no-op, that the file inherits the per-user %APPDATA% ACL, and that this is enough because the config holds only public pins and fingerprints. Any mode assertion outside the Linux-only e2e suite should be guarded with `runtime.GOOS != "windows"`, as cmd/keyroster/root_test.go:356 already does.

- **02-06-F15 [PARTIAL/LOW] No test asserts Content-Type of embedded static assets** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-06-PLAN.md:179 says the route is `GET /static/` (embed FS, explicit content types). The only test that touches static files is 02-06-PLAN.md:239, which asserts that 404, static and 503 responses carry all six security headers. Nothing checks Content-Type. 02-06-PLAN.md:49 makes `X-Content-Type-Options nosniff` global. I grepped every 02-*-PLAN.md for "Content-Type", "text/css" and "mime", and the only hits are the nosniff header lines in 02-06. 02-08-PLAN.md:219 and :234 check only that the page references `/static/app.js`, not the MIME type it is served with. Phase 2 code does not exist yet, so I had no implementation to check.
  - Fix: In 02-06 Task 2, extend the "server headers" behavior (line 239) so the static-file case also asserts that GET /static/app.css returns Content-Type text/css (charset optional). 02-08 should add the same check for /static/app.js with text/javascript.

- **02-06-F16 [PARTIAL/LOW] Tailscale cert timer env file ownership and mode** (gptoss)
  - Evidence: Most of this is already in the plan. .planning/phases/02-passkey-login-mvp/02-06-PLAN.md:302 has the timer's ExecStartPost run `chgrp keyroster-server` and `chmod 0640` on the private key. Line 313 sets the runbook's install permissions to /etc/keyroster/tls root:keyroster-server 0750 with the key at 0640. Line 293 gives the server unit `ProtectSystem=strict` plus `ReadOnlyPaths=/etc/keyroster/tls`. Two things are not specified. (a) Line 302 names /etc/keyroster/tailscale-cert.env but gives it no owner or mode. (b) keyroster-tailscale-cert.service has no sandboxing (no ProtectSystem or ReadWritePaths); lines 302-303 list only Type=oneshot, EnvironmentFile, ExecStart and ExecStartPost.
  - Fix: In Task 3, state that /etc/keyroster/tailscale-cert.env is root:root 0644, not readable by the server group. Optionally harden keyroster-tailscale-cert.service with ProtectSystem=strict, ReadWritePaths=/etc/keyroster/tls and NoNewPrivileges=yes, and mark that as UNVERIFIED until 02-13, since the tailscaled socket and atomic writes must still work.

- **02-06-F19 [PARTIAL/LOW] Linux-only server guard not exercised on non-Linux CI** (gptoss)
  - Evidence: The requirement text is .planning/REQUIREMENTS.md:102: "PLAT-05: Server and signer run on Linux; CLI runs on Linux, macOS and Windows". It does not ask for a clear error on other OSes. That behaviour is the plan's own design choice at 02-06-PLAN.md:48 and :170 ("main_other.go exits 1 with 'keyroster-server runs on Linux only (PLAT-05)'"), and it copies the Phase 1 signer stub in cmd/keyroster-signer/main_other.go. That stub is 3 lines (`//go:build !linux`, Fprintln to stderr, os.Exit(1)) and has no test either. The residual gap is real: nothing ever builds the !linux file. The CI cross-compile step, .github/workflows/ci.yml:35-39, builds only ./cmd/keyroster for windows/darwin/freebsd. `go vet ./...` (ci.yml:41) runs on Linux, so it never sees main_other.go. The 02-06 verify command (02-06-PLAN.md:219) builds keyroster-server only for GOOS=linux. The cli-windows and cli-macos jobs that 02-02 adds (02-02-PLAN.md:263) test only ./cmd/keyroster/... and internal packages, not ./cmd/keyroster-server. No other phase-2 plan adds a non-Linux build of keyroster-server (grep across 02-*-PLAN.md).
  - Fix: In 02-06, add ./cmd/keyroster-server (and ./cmd/keyroster-signer) to the ci.yml cross-compile loop for windows and darwin, or to the Task 1 verify command, so the !linux stub at least compiles in CI. A runtime test of the stub's stderr text is optional and not needed for PLAT-05.

### 02-07

- **02-07-F1 [PARTIAL/LOW] Nonce consumption not atomic with the admin action / retry semantics undefined** (codex)
  - Evidence: 02-07-PLAN.md:147 `Sign(signer, method, path, body, now)` takes no nonce parameter, so every Sign call makes a new nonce; any retry is a new signature and a new nonce, never a reuse of the burned one. 02-07-PLAN.md:153 `UseNonce` is an INSERT on `admin_nonces(nonce TEXT PRIMARY KEY)` (line 151), and 02-07-PLAN.md:152 says serverdb.Open uses "one connection". A duplicate INSERT fails, so the check-and-consume step is a single atomic statement and two concurrent requests with the same nonce cannot both succeed. 02-07-PLAN.md:159 consumes the nonce before the handler runs. This is the safe order for replay protection: it closes the window where a captured request could be replayed while the first copy is still running. 02-07-PLAN.md:162,178,225: a lost response followed by a re-run returns a defined 409 `already pending`, and `--reinvite` is the documented recovery, so failure after consumption has a usable outcome. 02-07-PLAN.md:212,250 test sequential replay (`nonce_replay`) only. No concurrent same-nonce test exists, and the plan does not state the "a failed request is retried by re-signing" rule. Phase 1 serverclient has no automatic transport retry (grep for retry/backoff in internal/ finds only keystore PIN counters).
  - Fix: In requireAdmin, add one sentence saying the nonce is consumed before the handler runs on purpose, and that any failed admin request (5xx, 409, signer unreachable) is retried by signing it again with a new nonce, never by resending the same headers. Optionally, extend `nonce_replay` with a parallel subtest that sends two copies of one signed request and expects exactly one non-401 response.

- **02-07-F5 [PARTIAL/LOW] Reinvite for existing directory users: user-handle continuity and concurrency** (codex)
  - Evidence: 02-07-PLAN.md:162 says a reinvited directory user gets a pending row "keeping its directory user_handle when the server has one or else a fresh one". 02-07-PLAN.md:151 defines pending_users with name as PRIMARY KEY and user_handle as UNIQUE. The installed directory has no user_handle at all. A grep for user_handle/UserHandle over internal/ and every phase-2 plan finds it only in 02-07:151/162/164 and 02-08:191. The directory credential is {id, alg, spki, backup_eligible, backed_up} (02-09-PLAN.md:167). Sign-in is username-first with allowCredentials taken from the directory, and there is no discoverable-credential flow in Phase 2 (02-10-PLAN.md:129 and :261; 02-12-PLAN.md:174). So the user handle never enters authentication and cannot be "continued" from the directory. 02-09-PLAN.md:142 (DeleteBound) also deletes the pending user once it is bound, so the server normally keeps no handle. Registration excludes the user's existing directory credentials (02-08-PLAN.md:191), so a new handle cannot overwrite an existing passkey. On concurrency: serverdb uses exactly one connection (02-07-PLAN.md:152), so writes are serialized, and the name PRIMARY KEY prevents a second pending row. Two concurrent reinvites therefore end as last-writer-wins, with exactly one valid token. Finish is one transaction (02-08-PLAN.md:197), and binding still requires the admin to approve the fingerprint (02-09-PLAN.md:32). What is actually unspecified: (a) whether 02-08's finish re-checks that the invite is still current, or only consumes the session (02-08-PLAN.md:192-197). If it does not, a ceremony begun under a token that a later reinvite replaced can still land a pending credential. (b) whether ReplaceInvite clears invite_used_us (a column 02-08 adds at line 185) when reinviting a pending user whose invite has already been used.
  - Fix: Change step 2 in 02-07 so that reinviting a directory user creates a pending row with a fresh 32-byte user_handle, and drop the "keeping its directory user_handle" clause. Make ReplaceInvite define last-writer-wins and say whether it resets invite_used_us. Then have 02-08's finish require that the session's invite_hash is still the row's current invite, and add a test where a reinvite between begin and finish makes finish fail with no pending credential written.

- **02-07-F6 [PARTIAL/LOW] Per-IP rate limiter can be evaded by IP rotation / LRU eviction** (codex, gptoss)
  - Evidence: 02-07-PLAN.md:157 specifies only "a per-IP rate.Limiter map with LRU-bounded size (10 000 entries) and idle eviction"; admin routes get 60/min burst 20, invite routes 30/min burst 10. It specifies no global limiter, does not say how IPv6 addresses are keyed (single address or /64), and says nothing about what eviction does to an attacker's own bucket. 02-07-PLAN.md:220 tests only "burst plus one returns 429". The threat register at 02-07-PLAN.md:314 rates T-02-36 as DoS, severity low, and the limiter is DoS mitigation only. Authority does not depend on it. Admin requests need an SSHSIG from a root-signed-policy admin key, a ±120 s window and a single-use nonce (T-02-32/33, lines 145-149 and 312-313). Invite tokens are 256-bit crypto/rand values stored hashed with a 24 h expiry (T-02-34, line 313), so getting around the limiter never makes forging or brute-forcing feasible. Request bodies are capped by MaxBytesReader at 1 MiB + 64 KiB (line 159). The sign-in brute-force and enumeration surface gets a separate per-username limiter in 02-10-PLAN.md:151 (T-02-50, line 292), so rotating IPs does not get around those limits. RESEARCH.md:685 and :993 lock x/time/rate keyed per IP and per user.
  - Fix: In ratelimit.go, key IPv6 clients by their /64 prefix and add a coarse global limiter (or concurrency cap) on the admin and invite routes as a backstop. Add a unit test showing the map never exceeds 10 000 entries. State in T-02-36 that the per-IP limiter is best-effort DoS damping, and that authenticity rests on SSHSIG with nonces and on the 256-bit tokens.

- **02-07-F7 [PARTIAL/LOW] Request body consumed by MaxBytesReader before Verify; handler needs the buffered body** (nemotron)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-07-PLAN.md:159 says requireAdmin "reads the body with http.MaxBytesReader (1 MiB + 64 KiB) and calls adminauth.Verify ... The request reaches the handler with the admin name in its context". It says nothing about how the already-read body reaches the handler. Line 160 has POST /api/v1/admin/users decoding a JSON body `{"name":..., "reinvite":false}`. adminauth.Verify takes `body []byte` (line 148), so the middleware has to fully buffer the body. A grep of 02-*-PLAN.md, 02-PATTERNS.md, 02-RESEARCH.md and 02-CONTEXT.md for NopCloser, bytes.NewReader, re-attach or buffer finds no sibling plan that covers it. The repo has no existing MaxBytesReader or NopCloser pattern in *.go, so Phase 1 code offers nothing to copy. However, the plan's own tests would catch the omission straight away. In e2e step 3 (line 175), `keyroster user add alice` must exit 0. The admin_test cases (lines 213-218) post real names and expect 201, 400 or 409. A handler that read an empty r.Body would fail JSON decode on every request, so none of those tests could pass.
  - Fix: At 02-07-PLAN.md:159, add a sentence saying requireAdmin re-attaches the verified bytes (`r.Body = io.NopCloser(bytes.NewReader(buf))`, or passes them in the context) so the handler decodes exactly the body that was signed. Optionally add an admin_test case where the handler sees the signed body.

- **02-07-F8 [PARTIAL/LOW] Invite URL always uses the first policy origin** (nemotron)
  - Evidence: The plan says "first policy origin" without giving a reason (.planning/phases/02-passkey-login-mvp/02-07-PLAN.md:165: "invite_url = first policy origin + `/enroll/` + token"; the must_have at 02-07-PLAN.md:39 says `https://<rp origin>/enroll/<token>`). The set of possible origins is very narrow, though. 02-01-PLAN.md:183-189 and 02-RESEARCH.md:320 require the origins to be "non-empty, sorted and duplicate-free. Each origin is exactly `https://` + rp_id, or that plus `:` + a port ... not 443". 02-01-PLAN.md:191 sets the default to the single origin `https://HOST`. CONTEXT D-09 (02-CONTEXT.md:81) locks one RP hostname with "allowed origin(s)". So every origin has the same host and differs only by port. Any listed origin passes the signer's origin check (02-RESEARCH.md:587, "origin is exactly one of policy.WebAuthn.Origins"), so choosing among them cannot weaken security. The only failure is a usability one. Because the list is sorted, `https://host` comes before `https://host:8443`. If an operator lists both but the server only listens on :8443 (`--listen` is configurable, 02-06-PLAN.md:170), the printed link points at a port nothing serves and does not load. The admin sees this immediately; the token, the CLI line and enrollment are not affected. 02-12-PLAN.md:170 uses the same "first policy origin" rule for approval_url, so the two plans should resolve it the same way.
  - Fix: State in 02-07 (and the same way in 02-12) that the URL uses the policy origin matching the origin of the admin's request or the configured server URL, falling back to the first sorted origin, or else say plainly that the first sorted origin is used and multi-port operators must list the served port first. Add a unit test with a two-origin policy.

- **02-07-F9 [PARTIAL/LOW] Printed `keyroster init` line must be copy-pasteable (quoting/escaping)** (nemotron)
  - Evidence: The quoting concern is refuted. Every value interpolated into the printed line (02-07-PLAN.md:170) comes from a tightly constrained alphabet that the plans already validate: - Server is checked to be https with a DNS host, an optional port, and no path, query or fragment (02-06-PLAN.md:195). - TLS pins are `sha256/` + std base64 (02-06-PLAN.md:190). - Root pins are `SHA256:` + base64, and they are verified against the bundle before they are saved (02-06-PLAN.md:200). - Threshold is an int. - NAME is validated by the directory rule `^[a-z0-9][a-z0-9._-]{0,63}$` (02-01-PLAN.md:198, applied at 02-07-PLAN.md:161). The characters that can appear are [A-Za-z0-9+/=:._-]. None of them is special in bash, sh, PowerShell or cmd, and several pins are passed as repeated flags, so nothing needs quoting. The no-round-trip-test part is true. The e2e only checks that stdout contains `/enroll/` and `--user alice` (02-07-PLAN.md:176). A round-trip test would catch a real omission the reviewer did not name: the printed line has no `--tls-root-file` (02-07-PLAN.md:170), but init accepts and needs it for a private TLS CA (02-06-PLAN.md:53, 196). It is not carried in the printed line even though Config stores TLSRootsPEM (02-06-PLAN.md:193). The e2e itself runs with a private root passed via `--tls-root-file` (02-06-PLAN.md:211), so if the printed line were pasted as-is in the test environment, TLS verification would fail.
  - Fix: In TestUserAddInvite, parse the printed `keyroster init` line and run it in a fresh config dir as the user, asserting exit 0. Make user.go either emit `--tls-root-file <path>` (or say that the TLS root PEM must also be sent) whenever cfg.TLSRootsPEM did not come from the system pool.

- **02-07-F10 [PARTIAL/LOW] Admin-auth clock skew window (±120 s) may reject legitimate admins** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-07-PLAN.md:145 sets `MaxSkew = 120 * time.Second` as a constant with no flag or config. :41 and :213 say every admin-auth failure, skew included, returns the same 401 `{"error":"admin authentication failed"}`. Only the server log records the specific reason. T-02-33 (:311) uses the ±120 s window plus the nonce table as its replay defence. The CLI side (:173, `keyroster user add`, and the 02-09 editDirectory pipeline) never checks the clock and gets no server-time hint. The login path does handle skew: 02-12-PLAN.md:163/197/272/391 has `login/options` return `server_time`, and the CLI refuses with "your clock differs from the server by Ns" when skew is above 60 s (RESEARCH Pitfall 8, 02-RESEARCH.md:731-733). The admin API has nothing like that. The existing signer also hard-codes its window (`internal/signer/issue.go:22 const maxClockSkew = 300 * time.Second`), so a hard-coded constant is the codebase's normal pattern.
  - Fix: Keep MaxSkew a fixed constant. On a 401 from /api/v1/admin/, have the CLI (serverclient.AdminJSON) compare the HTTP `Date` response header with the local clock. If they differ by more than about 60 s, add "your clock differs from the server by Ns" to the error, and add a CLI test for it to Task 2. The 401 body stays uniform, and nothing new is revealed, because the Date header is public anyway.

- **02-07-F12 [PARTIAL/LOW] Signed path canonicalisation unspecified** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-07-PLAN.md:146 defines Message over `<path incl. query>`, and :148 gives Verify a bare `path string` argument. :159 (requireAdmin) and :169 (AdminJSON) never say which request field fills that argument: r.RequestURI, r.URL.RequestURI(), r.URL.Path or EscapedPath on the server, and on the client the URL it actually sends. No other phase-2 plan, CONTEXT or RESEARCH mentions adminauth canonicalisation; a grep for RequestURI, EscapedPath and URL.Path across the phase directory found nothing. So the gap in the text is real. Mitigating evidence from the plan: line 208 and acceptance case `query_changed` (line 249) require the query to be covered. That rules out the most likely wrong choice (r.URL.Path, which drops the query), but only when the test goes through the real server and not just Verify. The e2e TestUserAddInvite (lines 172-179) runs the real Go client against the real Go server, so a client/server mismatch on the path would show up as a 401 and the test would fail.
  - Fix: At line 146/148, state that the client signs exactly the URL's RequestURI() that it sends and that requireAdmin passes r.RequestURI (raw request-target, path plus query, no normalisation) to Verify. Add one server-level test showing that a trailing-slash or percent-encoding variant of a signed path gets 401.

### 02-08

- **02-08-F1 [PARTIAL/MEDIUM] Concurrent begin/finish against one invite can race single-use consumption** (codex, gptoss)
  - Evidence: The plan promises at .planning/phases/02-passkey-login-mvp/02-08-PLAN.md:39 that "An invite registers exactly one credential". The steps that are supposed to deliver that leave a gap when requests overlap: - Begin checks that the invite is unused only when begin runs (:191). - Finish step 1, "load and delete the session (single use)" (:193), never says the delete is atomic or that its rows-affected count is checked. - Steps 2-4, the go-webauthn verification and the 409 lookup, run before the transaction. - Step 5, "in one transaction, insert pending_credentials ... and set invite_used_us" (:197), sets the column with no `WHERE invite_used_us IS NULL` condition and no rows-affected check. So this order works: finish A consumes session 1; begin B, still seeing the invite as unused, writes a new session (registration_sessions has invite_hash as PRIMARY KEY, :183); finish B consumes it. Both transactions then commit, leaving two pending credentials and the column overwritten. The refusal matrix (:244-257) and the acceptance names (:287) contain only sequential cases: invite_single_use, finish_replay_refused and "a used invite". There is no concurrent case. Mitigations the plan already has: - serverdb "mirrors signerdb" with one connection (02-07-PLAN.md:150-152). signerdb uses SetMaxOpenConns(1) and _txlock=immediate (internal/signerdb/db.go:27,49), so each transaction is serialized. - A duplicate credential ID is caught by `pending_credentials.id TEXT PRIMARY KEY` (:184), so the same-credential-ID race already fails at the constraint. - Binding still needs an admin-signed directory (02-09). The admin's user listing shows a pending credential count (02-09-PLAN.md:144).
  - Fix: Finish should consume the session atomically: `DELETE ... RETURNING`, or a delete with a rows-affected check of 1. Step 5's transaction should re-check the invite with `UPDATE pending_users SET invite_used_us=? WHERE name=? AND invite_used_us IS NULL AND invite_expires_us>?`, require rows-affected == 1 (otherwise 404 or 409 with nothing inserted), and enforce at most one pending credential per user. Add an `invite_concurrent_finish` test under -race: N parallel begin/finish pairs on one invite must leave exactly one pending row.

- **02-08-F3 [PARTIAL/LOW] Supply-chain drift: one-time owner review with no CI lock on the transitive module set** (gptoss)
  - Evidence: Plan: 02-08-PLAN.md:127-165 (Task 1 is a one-time, blocking-human review using `go list -m all` before/after and the go mod graph diff); :41, :271, :289, :337 (dep-firewall BANNED gains go-webauthn/fxamacker/cbor/golang-jwt; depguard deny); :302 (owner reviews the go.mod/go.sum diff at the PR checkpoint); :356-357 (T-02-41, T-02-SC). Repo controls the reviewer could not see: .github/CODEOWNERS ("* @Labontese": every change needs the owner's review, including any later go.mod change); .github/dependabot.yml (gomod bumps arrive only as PRs that need that review); .github/workflows/ci.yml:32 (`go mod verify`), :100 (dep-firewall.sh), :104-119 (capslock job, a required check in .github/rulesets/main-integrity.json:36); scripts/capslock-check.sh header (any new (package, capability) pair in the signer graph fails CI until the baseline is updated in a reviewed PR); scripts/dep-firewall.sh:1-30 (a deny list scoped to ./cmd/keyroster-signer, not an allowlist of approved modules). go.mod (go 1.26) lists every indirect module, so any new transitive module shows up as a line in the go.mod diff of the PR that brings it in.
  - Fix: Optional hardening, not a blocker for 02-08: add a small CI check (or extend the PR checklist) that fails when the `go list -m all` set differs from a committed approved-modules list, so that adding a module requires an explicit reviewed update to that list. This could also be tracked as a repo-wide supply-chain item rather than added to plan 02-08.

- **02-08-F7 [PARTIAL/LOW] Invite marked used before the user reliably receives the result** (gemma)
  - Evidence: First half is already covered. 02-08-PLAN.md:197 says /finish step 5 runs "in one transaction, insert pending_credentials ... and set invite_used_us". It comes after session load/delete (193), FinishRegistration with UV (194), the SPKI/ParsePublicKey check (195) and the 409 duplicate check (196). Task 3 (02-08-PLAN.md:244, 257, 287) also asserts that every refusal leaves "no pending row written and the invite still unused". So the marker is never set before durable persistence; both commit atomically. Second half (response lost after commit): this is single-use by design (02-08-PLAN.md:39, "An invite registers exactly one credential"). A recovery path exists. The admin can see the invite was used through `GET /api/v1/admin/users` "invite_used" (02-09-PLAN.md:144) and `keyroster user pending NAME`, which shows the fingerprint (02-08-PLAN.md:215). The admin can then issue a fresh token with `user add --reinvite`: "a pending name gets a new token (the old one becomes invalid)" (02-07-PLAN.md:162). The orphaned credential cannot be bound by accident, because approve needs the fingerprint the user reports out of band (02-09-PLAN.md:32, 225-226). Real but narrow gap: the invite_used_us column is added in 02-08 (line 185), after 02-07 defined reinvite, and /begin requires an "unused" invite (02-08-PLAN.md:191). Neither plan says that reinvite clears invite_used_us, or that it drops the orphaned pending_credentials. If the 02-07 reinvite handler only swaps token_hash and expiry, the new token is already "used" and /begin refuses it. The user then has no recovery path short of DB surgery.
  - Fix: In 02-08 Task 2, state that `user add --reinvite` on a pending name also sets invite_used_us = NULL and deletes that user's unapproved pending_credentials (or keeps them, with that decision written down). Add an enroll_test case `reinvite_after_used_invite_allows_register`. Optionally, add a line to 02-09's enrollment runbook: "page closed before the fingerprint showed → reinvite".

- **02-08-F10 [PARTIAL/LOW] Credential ID stored as TEXT primary key risks encoding mismatches in duplicate checks** (gptoss)
  - Evidence: 02-08-PLAN.md:184 defines pending_credentials(id TEXT PRIMARY KEY). 02-08-PLAN.md:194 runs go-webauthn CreateCredential/FinishRegistration, and step 4 (:196) only then checks for duplicates. The credential ID therefore comes from the server-parsed authData as raw bytes, not from a client-chosen string, so the server picks the encoding. 02-01-PLAN.md:200 fixes the directory form of credential `id` as "base64url without padding decoding to 1-1023 bytes", and :203 requires credential ids to be unique across the whole document. That gives one canonical text form. Login matches on bytes (02-01-PLAN.md:213, "assertion's credential ID equals cred.ID"). The duplicate tests are at 02-08-PLAN.md:254-255 and :287 (`credential_id_in_directory_refused`). Two small gaps remain. (a) 02-08 never says that pending_credentials.id = base64.RawURLEncoding(credential.ID bytes from FinishRegistration), or that step 4 compares in that canonical form. (b) 02-01 Validate decodes with non-strict RawURLEncoding, which accepts non-zero trailing bits, so two different strings can decode to the same bytes. Only a signed directory could carry such a string, and only an admin quorum can sign one.
  - Fix: In 02-08 step 4/5, state that pending_credentials.id is base64.RawURLEncoding of the credential.ID bytes from FinishRegistration (never the client's `id` string), and that the 409 check compares that canonical string against pending rows and the directory. Optionally, have 02-01 Validate require the id to re-encode to itself (strict decoding / canonical round-trip).

- **02-08-F11 [PARTIAL/LOW] BE/BS flag columns lack boolean constraints** (gptoss)
  - Evidence: The literal claim is accurate. .planning/phases/02-passkey-login-mvp/02-08-PLAN.md:184 defines `pending_credentials(... backup_eligible INTEGER NOT NULL, backed_up INTEGER NOT NULL ...)` with no CHECK. The Phase 1 migrations do use CHECKs this way, for example internal/signerdb/migrations/0001_issuance.sql:3-4 and :11-12, and internal/signerdb/migrations/0003_trust.sql:13 (`role TEXT ... CHECK (role IN (...))`). The harm it describes, later reporting misreading the values, does not hold up: (1) The only writer is the finish handler at 02-08-PLAN.md:196 (step 5). It inserts BE/BS straight from go-webauthn's boolean credential flags, so only 0 or 1 can be written. (2) Reading back into a Go bool fails loudly on any other value. database/sql's convertAssign uses driver.Bool.ConvertValue, which returns an error for an int64 other than 0 or 1, so there is no silent misreading. (3) The serverdb is declared non-authoritative. 02-07-PLAN.md:151 says its "header comment stat[es] that nothing here is authority". The record of BE/BS that counts is the signed directory, where `Credential{...; BackupEligible, BackedUp bool}` is typed as bool (02-01-PLAN.md:194) and carried to it through `user approve` (02-09-PLAN.md:167). Later reporting reads that record (02-10-PLAN.md:147, "synced" when backed_up), not the pending table. (4) BE/BS are informational only in phase 2. 02-CONTEXT.md:59 says they are for later visibility, and 02-CONTEXT.md:224 defers enforcement based on them.
  - Fix: Optionally write the two columns in 0002_registration.sql as `backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0,1))` and `backed_up INTEGER NOT NULL CHECK (backed_up IN (0,1))`, to match the CHECK style in the signerdb migrations. No other change to the plan is needed.

- **02-08-F16 [PARTIAL/LOW] No user feedback when authenticator/browser lacks supported pubKeyCredParams** (gemma)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-08-PLAN.md:203: enroll.html has an error `<p role="alert">`, so the page already has a place for errors. Lines 204-208 list app.js's steps: fetch begin, `navigator.credentials.create`, post finish, show fingerprint. None of the steps says that a rejected create, a missing `window.PublicKeyCredential`/`navigator.credentials`, or a failed fetch is caught and its message written into that alert element. Line 190 restricts pubKeyCredParams to EdDSA/ES256/RS256, which in practice covers every platform and roaming authenticator; RS256 exists for Windows Hello. So the "supports none of the algorithms" case named in the finding is close to theoretical. Line 379 says the browser-side create ceremony is UNVERIFIED until 02-13, so it gets a real-browser UAT. Sibling plans repeat the pattern without an error clause: 02-10-PLAN.md:128 has the login page `<p role="alert">` and 02-10-PLAN.md:153 the sign-in ceremony steps.
  - Fix: In 02-08 Task 2's app.js steps, add: feature-detect `window.PublicKeyCredential` and show a "this browser does not support passkeys" message in the role=alert element, and wrap the whole begin/create/finish chain in a try/catch that writes err.name or err.message, or the server's error text, into that same element. 02-10 and 02-12 then inherit the same pattern.

### 02-09

- **02-09-F6 [PARTIAL/LOW] Pending cleanup must be transactional and narrow** (codex)
  - Evidence: Three of the four concerns are already covered in .planning/phases/02-passkey-login-mvp/02-09-PLAN.md: - **Transactional.** Line 142 says cleanup runs "In one serverdb transaction (`DeleteBound`)". - **Runs only after the signer accepts.** Line 142 ("On success it refreshes the mirror..."), line 36 ("Only after the signer accepts it does the server drop the pending credentials...") and key_link line 66 ("cleanup only after success"). - **Nothing deleted on refusal.** Line 143 maps refusals to 409/403/400. Line 215 requires a test: "maps signer refusals to 409, 403 and 400 and deletes no pending row on refusal." - **Never removes unbound credentials.** Line 142 deletes only "each pending credential whose ID now appears in the directory". A user's pending row goes only when that user has "no remaining pending credential". FK context: 02-08-PLAN.md:184 (pending_credentials.user_name REFERENCES pending_users). - **Pending rows are not authority.** 02-07-PLAN.md:74 and T-02-35 at 02-07-PLAN.md:313. The residual gap is about "the ability to enroll another credential". 02-07-PLAN.md:162 says `--reinvite` for a user already in the installed directory "gets a pending row for one additional credential". That row exists in pending_users before the user registers, so it has zero pending credentials. 02-09-PLAN.md:142 deletes "each pending user now present in the directory with no remaining pending credential". So if any later install happens while alice's extra-passkey invite is still open (for example, approving carol), the outstanding invite is deleted. The must_have at line 36 says the narrower thing ("pending accounts the new version binds"), but the action text and the DeleteBound spec do not limit deletion to users whose credentials this install just bound. No test covers this case. Line 215 tests only the refusal case. Also untested: a user with two pending credentials where one is approved keeps the other.
  - Fix: Limit DeleteBound to the users and credential IDs that this install newly binds compared with the previous version. Never delete a pending_users row whose invite is unused and unexpired. Add an admin_test/serverdb case where an unrelated install leaves another user's open extra-passkey invite and unapproved pending credentials in place.

- **02-09-F10 [PARTIAL/LOW] Stale proposal on directory sign needs actionable guidance** (nemotron, codex)
  - Evidence: The plan catches the stale-proposal condition and shows how to recover. What it never writes down is the error text a user gets from `directory sign`, and the text it gives for `directory install` points at the wrong next step. - 02-09-PLAN.md:161 says `directory sign` checks that the proposal's prev equals the SHA-256 of the installed verified directory. Line 213 adds a test that it refuses a proposal with a wrong prev. Neither line gives the refusal message or the next step. - 02-09-PLAN.md:155 (editDirectory step 7) turns a 409 `directory_version_chain` into "the directory changed since it was read (another admin installed a version); re-run this command". That suits `user approve`, which rebuilds from the current base. Line 205 shows `directory install B` gives the same "directory changed since it was read" error. For install, "re-run this command" is wrong: posting the same stale proposal again fails again. - 02-09-PLAN.md:41 (must_haves) and line 206 (e2e TestApproveConflictNoLostUpdate step 5) show the correct recovery, which is to re-run `user approve dave --fingerprint … --yes`. Line 142 confirms why that works: pending rows are deleted only after a successful install, so the credential is still pending. - 02-09-PLAN.md:223-230: the runbook outline covers quorum >1 (--out, `directory sign`, `directory install`) but has no step for a stale proposal.
  - Fix: Make `directory sign` and `directory install` say: "proposal is based on version N but version M is installed; discard DIR and re-run the command that produced it (e.g. `keyroster user approve …`)". Keep "re-run this command" only for the direct editDirectory path. Add one line on stale proposals to the quorum section of docs/runbooks/enroll-user.md.

- **02-09-F11 [PARTIAL/LOW] Trust pin rotation not specified** (gptoss)
  - Evidence: 02-09-PLAN.md:149 calls `Trust(cfg.TrustPins, cfg.TrustThreshold)`. 02-09 does not own that function. Plan 02-06 does, and it defines everything around it: - 02-06-PLAN.md:189 says Trust runs `trust.VerifySelfSigned` and then `trust.MatchPins`. - 02-06-PLAN.md:193 gives the Config layout: `TLSPins []string` and `TrustPins []string; TrustThreshold int` are separate fields. - 02-06-PLAN.md:194-201 has `init --root-pin` (repeatable) and `--threshold`, and 02-06-PLAN.md:201 refuses to overwrite an existing config without `--force`. The pin format and count are already enforced in existing code: - internal/trust/verify.go:131-143 (CheckPins) requires at least one pin, each of the form `SHA256:<base64>`, no repeats, and a threshold from 1 to the number of pins. - internal/trust/verify.go:145-171 (MatchPins) requires the served bundle's root set to equal the pinned set exactly, at exactly the pinned threshold. The "certificate renewal" scenario is wrong. TrustPins are fingerprints of the offline SSH root keys, not TLS certificates. TLS pins are a separate field: they pin the CA root's SPKI, and 02-RESEARCH.md:220-225 says this pin survives leaf and intermediate rotation. When the TLS CA root itself changes, the check fails closed and `keyroster init --repin` is the stated recovery. So a server certificate renewal never touches cfg.TrustPins. The real but narrower remainder is offline-root rotation, which Phase 1 supports (cmd/keyroster/root.go:93, cmd/keyroster/trust.go:160-171, audit.go:62). After a rotation, the served bundle names new roots, so MatchPins rejects every existing admin CLI config. That fails closed, not open. The implied recovery is to re-run `keyroster init --force` with the new pins, obtained out of band. But no plan and no runbook says so: grep for `keyroster init`, `--force` and `re-pin` in docs/ finds nothing.
  - Fix: Leave 02-09's pipeline as it is. In 02-06 or in docs/runbooks/root-ceremony.md ("Rotate the roots"), add a step: after a root rotation, each admin re-runs `keyroster init --force --root-pin <new fps> --threshold <n>` with pins obtained out of band. The trust-pin mismatch error should also suggest this, for example a message saying the bundle roots changed and init should be re-run with the new root pins.

- **02-09-F14 [CONFIRMED/LOW] Test that directory sign refuses non-admin existing signatures** (nemotron)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-09-PLAN.md:161 says `directory sign DIR` must check "that every existing signature is by a policy admin". T-02-46 (line 316) lists this re-verification as the mitigation for proposal files edited between co-signers. The Task 2 behaviour list (lines 198-215) has only one `directory sign` refusal test: a wrong prev (line 213). The non-admin case at line 212 tests editDirectory's base check, not `directory sign`. The named cases at line 245 contain nothing for `directory sign`. The quorum-2 e2e (lines 207-211) only tests the success path and a duplicate same-admin signature, which is refused at install, not at sign. The plan cannot lean on existing behaviour either: 02-01-PLAN.md:312 says `directory.VerifySignatures` does not count a non-admin signer but does not refuse it. So `directory sign` needs its own extra logic to refuse, and nothing tests that logic. The backstop is the signer. It refuses a non-admin-signed directory at install with directory_quorum_not_met (02-03-PLAN.md:139,175), so a non-admin signature can never reach the quorum.
  - Fix: Add a named case to Task 2 (and to the line-245 acceptance list), e.g. `directory_sign_refuses_non_admin_sig`. A proposal whose .sigs contains a signature by a non-admin key, or an admin signature that does not verify over a tampered directory.json, is refused by `directory sign`, and the agent receives no sign request.

### 02-10

- **02-10-F1 [PARTIAL/LOW] Disabled user keeps session until directory mirror refreshes** (codex, nemotron, gemma, gptoss)
  - Evidence: 02-10-PLAN.md:141 says withSession calls TouchSession and then requires the user to still be active in the mirror, deleting the session if not. 02-10-PLAN.md:35 says the session ends "as soon as the directory shows the user disabled". 02-10-PLAN.md:196, 224 and 201 add the tests `disabled_user_ends_session` (next request after a disabled successor) and an e2e test (`keyroster user disable alice --yes`, then /account redirects). The propagation delay is bounded in sibling plans. 02-06-PLAN.md:181 sets the status cache TTL to 5 s, refreshed under a mutex, and says "A Status failure serves 503 from the API ... and an error page from HTML routes. Never fall back to stale RP data older than 60 s", which is a fail-closed rule for an unavailable signer. 02-09-PLAN.md:139 refreshes the mirror when the cached Status's directory SHA-256 changes, and 02-09-PLAN.md:142 refreshes it immediately after any install the server forwards. Disables made through the CLI pipeline (`user disable`, 02-09-PLAN.md:169) therefore take effect on the next request, not after 5 s. A lag of up to 5 s applies only when a directory is installed on the signer by another path. The 02-10 session is read-only: account.go at 02-10-PLAN.md:144-149 renders a view, and certificate signing needs a fresh WebAuthn assertion at the signer, which re-checks the directory. internal/server does not exist yet on main (git ls-tree origin/main shows no internal/server), so there is no Phase 1 code to contradict.
  - Fix: In 02-10 session.go, state explicitly that withSession uses the 02-06 status cache, which can be at most 5 s stale (most disables refresh immediately through the 02-09 install refresh). Also state that if the status or mirror cannot be refreshed, it serves the error page and renders nothing from stale data. Add a session_test case `signer_unavailable_fails_closed`.

- **02-10-F2 [PARTIAL/LOW] Sessions not tied to directory version or privilege changes** (codex, gptoss, nemotron)
  - Evidence: 02-10-PLAN.md:125: the sessions table stores only id_hash, user_name, created_us and last_seen_us. It caches no roles, principals or policy. 02-10-PLAN.md:141: withSession re-checks on every request that the user is still active in the directory mirror and deletes the session if not. 02-10-PLAN.md:144-146: GET /account renders name, status, directory version and `Authorize(user, nil)` fresh on each request. 02-09-PLAN.md:139: the mirror refreshes whenever the signer status's directory SHA-256 changes. 02-10-PLAN.md:196 and 201: tests cover a disable ending an existing session on its next request, and a disable/enable cycle in e2e. 02-10-PLAN.md:38, 67 and 293 (T-02-51): a session gates only GET /account and POST /logout and never authorizes issuance or directory changes. 02-CONTEXT.md:138 leaves session lifetime to Claude's discretion; no locked decision conflicts with the finding.
  - Fix: Optional hardening: in withSession, also end the session when the user no longer has any bound credential, or record the user's credential set or status version at login and end the session if it changes, so that disable followed by re-enable also ends it. Add a session_test case where a session opened under directory v1 stays valid and shows the new role on /account after a non-disabling v2 is installed.

- **02-10-F5 [PARTIAL/LOW] TouchSession must enforce idle and absolute expiry atomically** (codex)
  - Evidence: 02-10-PLAN.md:125 defines `TouchSession(hash, now, idle, absolute)` over `sessions(id_hash, user_name, created_us, last_seen_us)`. Both limits are inputs, and created_us is stored, so absolute expiry can be computed. 02-10-PLAN.md:141 says withSession calls it with idle 1 h and absolute 12 h. 02-10-PLAN.md:194-195 and :224 require the tests `idle_expiry` (61 min) and `absolute_expiry` (12 h 1 min, "ends it even when active"). must_haves (02-10-PLAN.md:35) and T-02-47 (:289) state both limits. So the claim that both checks are needed is already covered. What the plan does not say anywhere is how TouchSession works. It never requires a single conditional statement (for example `UPDATE sessions SET last_seen_us=? WHERE id_hash=? AND ?-last_seen_us<=idle AND ?-created_us<=absolute RETURNING user_name`). It also never requires that an expired row is never updated, or deleted when found. Concurrency: serverdb 'mirrors signerdb' with 'one connection' (02-07-PLAN.md:150-152; internal/signerdb/db.go:49 SetMaxOpenConns(1), :27 _txlock=immediate), so all writes are serialized. No concurrent interleaving can extend a session whose expiry check failed. The only gap is a SELECT-then-UPDATE race measured in milliseconds, against a 1 h idle window.
  - Fix: In Task 1, state that TouchSession is one statement, `UPDATE sessions SET last_seen_us=MAX(last_seen_us,?now) WHERE id_hash=? AND ?now-last_seen_us<=idle AND ?now-created_us<=absolute RETURNING user_name`. If no row matches, it deletes the row and returns ErrNotFound. Add a session_test case showing that a touch after expiry does not revive the session.

- **02-10-F6 [PARTIAL/LOW] Per-username limiter map unbounded and unnormalized** (codex)
  - Evidence: 02-10-PLAN.md:151 says only "ratelimit.go adds a per-username limiter next to the per-IP one: ... 10/min per username"; it gives no bound, no eviction and no key validation for the username map. The per-IP limiter it builds on is already bounded: 02-07-PLAN.md:157 has "a per-IP rate.Limiter map with LRU-bounded size (10 000 entries) and idle eviction", and 02-07-PLAN.md:314 (T-02-36) has "Per-IP x/time/rate limits with bounded state". The normalization claim does not hold. Directory user names must match `^[a-z0-9][a-z0-9._-]{0,63}$` (02-01-PLAN.md:198), and begin requires "active in the directory mirror" with a 404 that is "identical for unknown, pending, disabled and credential-less users" (02-10-PLAN.md:129). So "Alice" or a Unicode variant never resolves to alice and gets no challenge for her credentials. The internal/server code does not exist yet; the directory internal/server/ is absent from the repo.
  - Fix: In 02-10 Task 1 'Rate limits', state that the per-username limiter reuses 02-07's bounded LRU map with idle eviction. Also state that it is keyed only on names that pass the directory name regex (`^[a-z0-9][a-z0-9._-]{0,63}$`); invalid names get the uniform 404 without creating a limiter entry. Add a unit test that the map size stays at or below the cap.

- **02-10-F15 [PARTIAL/LOW] Sign-in refusals not audit-logged** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-10-PLAN.md:138 says "Any failure returns 401 {"error":"sign-in failed"} and logs the specific reason through slog", so finish refusals are logged with a reason. The plan does not say that the begin 404 (lines 130-131), the rate-limit 429 (line 37) or a successful sign-in (lines 132-137) are logged. 02-07-PLAN.md:159 uses the same slog-only pattern for admin-auth refusals on the server, and 02-06-PLAN.md:176 sets slog JSON to stderr as the server's logging channel. The tamper-evident Merkle log belongs to the signer. Its leaf kinds are Issue, Refusal, RefusalSummary, ClockRegression, CAInit and BundleInstall (internal/tlog/leaf.go:39-44), and the server cannot append to it. VIS-01 (.planning/REQUIREMENTS.md:75) covers issuance, revocation, approval and admin actions, not web sessions. A web session grants no SSH access: /account is read-only (02-10-PLAN.md:36). Signing refusals and issuance for login certificates are already audited by the signer (02-12-PLAN.md:296, 388). Hashing the username is pointless, because T-02-50 (02-10-PLAN.md:292) notes that usernames already appear in key IDs and the audit log.
  - Fix: In 02-10 Task 1, state that a successful finish, logout, the begin 404 and 429 rate-limit hits are each logged through slog with the username, the client IP and a reason code, never the session ID or the challenge. Keep web sign-in out of the signer's Merkle audit log, because it grants no access.

- **02-10-F16 [PARTIAL/LOW] Account page lacks last-sign-in information** (gemma)
  - Evidence: The fact is correct. 02-10-PLAN.md:36 (must_have) and :144-149 (account.go) list what /account shows: name, status, directory version, roles/principals/TTL cap, credential fingerprints with synced/device-bound, a logout form, and a read-only notice. None of it is a last-sign-in time or a session list. The 0003_web.sql `sessions` table (:125) already has `created_us` and `last_seen_us` per user_name, so the data exists, but nothing displays it. No sibling 02-*-PLAN, 02-CONTEXT or 02-RESEARCH covers this either: a grep for last sign-in, last login and active session found nothing. Several things shrink the impact. A web session gates only GET /account and POST /logout, and is never authority for a certificate or a directory change (02-10-PLAN.md:39, :293 T-02-51, and the prohibition at :66-68). Sessions die after 1 h idle or 12 h absolute, or when the user is disabled (:35, :141). No requirement asks for this view: UI-01 at REQUIREMENTS.md:91 is only about CSP, embedding and no npm. Page layout is left to Claude's discretion (02-CONTEXT.md:138).
  - Fix: Optional: show the current session's sign-in time and the user's other active sessions (created and last-seen times from the existing sessions table) on /account. Otherwise, add "session list and revoke on /account" to the deferred ideas for the UI-02 phase. Do not block 02-10 on it.

### 02-11

- **02-11-F2 [CONFIRMED/MEDIUM] Empty principal set vs unknown account is undefined** (codex, gemma)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-11-PLAN.md:153 says AccountPrincipals "errors when the host group or the account is unknown", and RenderPrincipalsFile (154-156) defines only header lines plus one principal per line. It does not say what happens with zero principals. Line 166 defines `host-group map NAME ACCOUNT ROLE...` ("sets the account's role list") and `unmap NAME ACCOUNT`, but does not say whether ROLE... may be empty or whether unmap removes the account entry. Line 179: "`host-group unmap web <login> --yes`, then `host principals web <login>` fails (account unknown). An sshd configured with the remaining output (an empty principals file) refuses the same certificate." Once the command fails there is no remaining output, so the test author must write the empty file by hand. The harness at test/e2e/harness_test.go:278-281 writes whatever Principals map it is given, and a missing principals file also refuses. The refusal check therefore passes whether or not the renderer handles zero roles; it tests sshd, not keyroster. No sibling plan covers this. 02-14-PLAN.md:123-154 only renders a non-empty homelab/zima file. 02-10-PLAN.md:146 covers "no roles yet" for Authorize, not for host rendering. 02-REVIEWS.md:274-279 and :381 log the same issue as valid MEDIUM, but the plan text has not been changed.
  - Fix: Choose and state one rule. Either `unmap` (or `map` with zero roles) keeps the account and RenderPrincipalsFile prints a header-only file, or an unknown account is an error and callers must treat that as "write an empty file", never "keep the old file". Then rewrite e2e step 7 so the refusal uses keyroster's actual output for the revoked account (for example, header-only output fed to sshd), and add unit tests that cover both cases: empty mapping and unknown account.

- **02-11-F3 [PARTIAL/LOW] `role update` replace semantics cannot clear a list** (codex)
  - Evidence: 02-11-PLAN.md:162 defines `role update NAME [--max-ttl D] [--principal P]... [--extension E]...: given lists replace the old ones`, so a list flag that is left out keeps the old list. Line 164 handles users and groups separately with `role grant` / `role revoke`, one at a time, and `role update` has no --user or --group flags, so the claim about clearing the user/group list is wrong. Principals cannot be emptied by design: 02-01-PLAN.md:201 says Validate() requires "each role has 1-32 principals", so an empty principal list is a refused state and needs no clear syntax. Extensions are different. Role.Extensions (02-01-PLAN.md:194) are optional extras on top of the user-profile defaults, checked by CheckPolicy (02-01-PLAN.md:207). `role add` makes `--extension` optional (02-11-PLAN.md:161), so an empty list is a valid state. Once a role carries an extra extension, the replace-if-given rule at :162 offers no way back to zero. The only route is unmap, `role remove`, re-add, re-grant and re-map, because `role remove` is refused while the role is mapped (:163). The tests at 02-11-PLAN.md:215 cover only replacing principals.
  - Fix: Add `--no-extensions` (or `--clear-extensions`) to `role update`, refused when combined with `--extension`. State that an omitted list flag keeps the current list and that principals cannot be cleared, since Validate requires 1-32. Add a Task 3 test that removes a role's only extra extension.

- **02-11-F5 [PARTIAL/LOW] Renderer header sha256 source ambiguous** (gptoss)
  - Evidence: 02-11-PLAN.md:153-155 defines RenderPrincipalsFile(d *Directory, ...) and the header `# host group <g>, account <a>, directory version <n> sha256 <hex>` without saying what the hash covers. 02-11-PLAN.md:202 only asserts "the header carries the version and SHA-256", not that the value is right. Two things make the claimed divergence impossible by construction, though. - Throughout phase 2, "directory SHA-256" means SHA-256 of the canonical bytes: - 02-01-PLAN.md:54 and 02-09-PLAN.md:34: prev is the SHA-256 of the installed bytes; - 02-09-PLAN.md:139,142,158: Status, install and `directory show` report the directory SHA-256. - The stored bytes and a re-serialization are identical: - 02-01-PLAN.md:189,195: Parse uses trust.DecodeStrict, and Canonical() uses trust.CanonicalJSON as "the one canonical rule". - 02-01-PLAN.md:60: Validate refuses unsorted or duplicated lists, and Sort() fixes the order. - 02-03-PLAN.md:175: the signer refuses non-canonical directories ("directory_invalid (non-canonical whitespace, unknown field)"). So sha256(d.Canonical()) equals sha256(installed bytes) for any directory that installed. T-02-53 (02-11-PLAN.md:318) is about the renderer's principal set matching the signer's Authorize computation. It is not about the header hash. The header's role as staleness evidence falls under T-02-54 (line 319), which is "accept" for Phase 2.
  - Fix: In 02-11 Task 2, define the header hash as the lowercase hex SHA-256 of d.Canonical(): the same value `keyroster directory show` and the signer Status report, and the next version's prev. In Task 3, add a renderer test asserting the header hex equals sha256 of the stored directory bytes.

- **02-11-F6 [PARTIAL/LOW] Remove-refusal error should name dependents (group remove while granted by role)** (nemotron)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-11-PLAN.md:163 already says "`role remove NAME`. It refuses while a host group maps the role, and names the host groups", so half of the claim is false. Line 165 says only "`group remove NAME` (refused while a role grants it)" and does not require the granting roles to be named. Line 170 says in general "Error messages name the offending role", which arguably covers it but is ambiguous here. The Task 3 refusal tests (lines 212-213) and the named cases (line 251: `remove_mapped_role_refused`, with no `remove_granted_group_refused`) do not assert the content of the message. Independent of the CLI check, 02-01-PLAN.md:203 and :311 make directory Validate refuse any unknown referenced role, group or user. A group removal that left a dangling grant therefore fails closed at Validate in any case.
  - Fix: Change line 165 to "group remove NAME (refused while a role grants it; the error names the granting roles)". Add a named case `remove_granted_group_refused` to the Task 3 acceptance list, asserting that the error names the role.

- **02-11-F7 [PARTIAL/LOW] `host principals` duplicates directory verification logic** (nemotron)
  - Evidence: 02-11-PLAN.md:167 says `host principals` should "Trust, then fetch the directory and verify it locally (the same steps as the pipeline, read only)". It names no helper to reuse. The pipeline in 02-09-PLAN.md:148-150 (cmd/keyroster/dirpipe.go editDirectory) does the fetch and verify inline as steps 1-2: Trust, then GET /api/v1/admin/directory, then directory.Parse and directory.VerifySignatures against the quorum. 02-09 also has `directory show` (02-09-PLAN.md:158) printing "the verified installed directory", and `directory sign` (02-09-PLAN.md:161) checking against "the currently installed verified directory". Neither plan defines a shared fetch-and-verify function, so 02-11 would add the fourth CLI call site of the same glue code. The finding overstates one thing. The verification logic itself is not duplicated: directory.Parse, directory.VerifySignatures and directory.CheckPolicy live in internal/directory and are shared (02-01-PLAN.md:249-253, 02-04-PLAN.md:134). What repeats is about 5-10 lines in cmd/keyroster: Trust, GET, base64 decode, Parse, VerifySignatures, plus the quorum/version-0 handling. The current repo has no such helper yet. The cmd/keyroster/*.go funcs are Phase 1 only (root.go, trust.go, ca.go, audit.go).
  - Fix: In 02-09, pull editDirectory's steps 1-2 out into a named helper, e.g. `fetchVerifiedDirectory(ctx, env) (doc []byte, d *directory.Directory, pol *trust.Policy, err error)` in dirpipe.go, running Parse+VerifySignatures(+CheckPolicy) and handling version 0. Have editDirectory, `directory show/sign` and 02-11's `host principals` call it. Change 02-11-PLAN.md:167 to name that helper instead of "the same steps as the pipeline".

### 02-12

- **02-12-F1 [PARTIAL/LOW] Redemption consumes the code before signing; no safe retry when signing fails or the response is lost** (codex)
  - Evidence: The factual part is correct. 02-12-PLAN.md:160 says "RedeemLogin moves approved to redeemed atomically, so it succeeds once". At :181-186, step 1 consumes the code with RedeemLogin, step 2 checks PKCE and step 4 calls signerclient.Login. At :188 any failure after that returns 403 or 400. Step 9 of the CLI (:204) does not say what happens when redeem fails. So a signer error or a lost response spends the approval. The harm is much smaller than claimed, for four reasons: (1) The finding's "safe retry" cannot exist by design. The passkey assertion's challenge is Digest() of the exact request, which contains RequestID and CreatedAt (:174, :178, :184). The signer refuses a second use of a RequestID with duplicate_request (02-03-PLAN.md:136; 02-CONTEXT.md:26; RESEARCH:628 "RequestID UNIQUE backstop", internal/signer/issue.go:87-95 per research). Calling the signer again for the same login would be refused. The only "idempotent" option would be for the server to cache and re-serve the issued certificate, and that adds state. (2) The intended recovery is to run `keyroster login` again: a new in-memory ed25519 key, a new RequestID and one more passkey touch (:198, :200). It is cheap and safe. (3) "Duplicate issuance" is not a security or visibility problem. If the response is lost after the signer has signed, the certificate is bound to an ephemeral private key that exists only in the CLI's memory and is never written to disk (:198, T-02-62 at :390). Nobody else can use it. It is also logged before release (RESEARCH:252, VIS-01), so the audit log stays accurate: the certificate really was issued. A second run issues a different certificate for a different key, and both are logged. This matches the core value: a complete, accurate picture. (4) Consuming the code before signing is the standard OAuth single-use rule (RESEARCH:279, :988; T-02-57 at :385). It is part of the locked design, which mints at redemption (RESEARCH Q2, :251-252). Two real points remain, both minor: - The CLI has no defined message for a failed redeem, such as "redeem failed; run keyroster login again". - The order of step 1 (consume) before step 2 (PKCE check) means anyone who has intercepted the code but lacks the verifier can burn it. That is a denial of service only, and it requires access to the loopback.
  - Fix: In redeem, run the constant-time PKCE check (and the code lookup and expiry check) before the atomic approved->redeemed transition, so that a wrong verifier does not burn the code. In CLI step 9, state that any redeem failure ends with "login not completed; run keyroster login again" (no automatic retry). Add a sentence noting that a certificate issued but not delivered is logged and is unusable without the in-memory key.

- **02-12-F2 [PARTIAL/LOW] Agent lifetime rounding of ValidBefore - now** (codex)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-12-PLAN.md:210 makes the CLI refuse unless ValidBefore − now ≥ 60. Line 211 then sets `LifetimeSecs: ValidBefore − now`. Line 44 (must_haves) says nothing reaches the agent unless at least 60 s are left. Line 281 (`login_lifetime_expiry`) uses --ttl 2m and checks that both the key and the certificate are gone from the agent at ValidBefore − now + 5 s. Line 272 tests clock skew of 61 s, and line 278 tests a span of TTL + 301 s. No test covers the case where 59 s versus 60 s remain, and no test asserts LifetimeSecs > 0 or LifetimeSecs ≤ the certificate's true remaining validity. The task text does not say how `now` is taken, or whether it is taken once or again between steps 9 and 10.
  - Fix: In step 9-10, read `now` once and compute `lifetime = ValidBefore − ceil(now)`, so the lifetime never exceeds the certificate's remaining validity. Refuse when lifetime < 60 and assert lifetime > 0 before calling Add. Add one unit test to the "CLI checks" list in Task 2 for a certificate with 59 s remaining (refused, agent empty), and one that uses the recording fake agent to assert that LifetimeSecs is in [60, ValidBefore − now].

- **02-12-F12 [PARTIAL/LOW] No cleanup of expired login_sessions; pending-session flood** (gptoss)
  - Evidence: 02-12-PLAN.md:160 defines `login_sessions` with `expires_us` and `code_expires_us` and the accessors CreateLogin, Login, ApproveLogin and RedeemLogin. None of them deletes anything: RedeemLogin only moves the status from approved to redeemed, so even redeemed rows stay. 02-12-PLAN.md:164-170 (begin) inserts a row on every valid begin. The task 2 behavior list at 02-12-PLAN.md:244-283 has no reaping test. The threat model (02-12-PLAN.md:384-393) has no DoS row for login-session growth; T-02-63 and T-02-64 cover clock skew and browser hand-off only. No sibling plan adds a general reaper: a grep across 02-*.md for purge, housekeeping, ticker or DELETE finds only 02-07-PLAN.md:153/221, where `UseNonce` "also deletes expired rows". That is the same pattern on a different table, never applied to login_sessions. Mitigations that do exist: 02-12-PLAN.md:162 says "each route has a per-IP limit and the API routes also a per-user limit" (the per-user value is not given; 02-10-PLAN.md:151 sets 10/min per username for web begin, and 02-07-PLAN.md:157 bounds the per-IP limiter at 10 000 entries). Begin also refuses unless the subject is an active directory user (02-12-PLAN.md:166) and CreatedAt is within 300 s. No Phase 2 code exists yet (internal/ has no server or serverdb packages), so nothing can be checked against real source.
  - Fix: Have CreateLogin delete rows past expires_us plus a short grace period in the same transaction, following 02-07's UseNonce. Delete redeemed rows too, since the signer log is the record. Add a serverdb test showing an expired row is gone after the next CreateLogin, and state 02-12's per-user begin limit values.

- **02-12-F13 [PARTIAL/LOW] Username enumeration via /api/v1/login/options** (gptoss)
  - Evidence: Username enumeration is already an accepted, documented risk in the phase. 02-10-PLAN.md:292 has T-02-50 "user enumeration through begin | low | accept", with the reason "usernames already appear in key IDs and the audit log". 02-10-PLAN.md:264 says "Usernames are not secret here … The uniform 404 and the rate limits bound enumeration noise". 02-RESEARCH.md:993 also lists "uniform errors" plus x/time/rate against enumeration. 02-12 applies the same controls to the options endpoint: - 02-12-PLAN.md:162: "each route has a per-IP limit and the API routes also a per-user limit". - 02-12-PLAN.md:163: every non-usable name gets "the uniform 404". - 02-12-PLAN.md:247 tests the case "unknown user (uniform 404)". The response codes the reviewer calls non-uniform are different outcomes on different endpoints, not different answers to "does this user exist": - 02-12-PLAN.md:188: signer refusal returns 403 and every other redeem failure returns the uniform 400. - 02-12-PLAN.md:175: expired, approved or redeemed sessions get the uniform error page. The real gap is in the 02-12 threat register (02-12-PLAN.md:384-393). It has no row for what the unauthenticated options endpoint returns for a valid username: role names, principals (the host accounts the user can reach), per-role TTLs and ca_max_ttl_seconds. T-02-50 only covers a yes/no on "this user exists" through begin. It does not cover handing out each user's access map without authentication.
  - Fix: Add a threat row to 02-12 for unauthenticated disclosure of roles, principals and TTL caps through /api/v1/login/options. Either accept it explicitly (same reasoning as T-02-50 plus the rate limits), or cut the response down to server_time and role names. If you cut it, the server fills in principals and TTL at begin time and the CLI confirms them on the fingerprint/approval step. Do not change the uniform 404, and do not make status codes uniform across endpoints.

- **02-12-F14 [PARTIAL/LOW] PKCE encoding normalization and verifier handling** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-12-PLAN.md:168: begin requires `code_challenge_method` = `S256` and `code_challenge` of exactly 43 base64url characters. A padded challenge would be 44 characters and contain `=`, so it is refused at intake. Only unpadded base64url can be stored. Task 2 tests this with a 42-character challenge and with `plain` (around line 250). 02-12-PLAN.md:200: the CLI generates the verifier as 32 random bytes in base64url (43 characters) and derives the challenge as base64url(SHA-256(verifier)), the same encoding the server uses. 02-12-PLAN.md:183: redeem requires `base64url(SHA-256(code_verifier)) == code_challenge` in constant time. The redeem steps (181-185) never check the verifier's length or alphabet. 02-12-PLAN.md:160: the `login_sessions` schema stores `code_challenge`, `state` and `code_hash`. It has no verifier column, so the verifier is never persisted. The plan has no "never logged" rule for code_verifier or the code. Sibling plans do write such rules for other secrets: 02-07-PLAN.md:44 and :312 for the invite token, and 02-05-PLAN.md:335 for the passphrase. 02-RESEARCH.md:242 and :255: in the relevant threat (consent phishing) the attacker already holds the verifier, so PKCE is a server-enforced control only. The verifier is not a long-term secret. No internal/server code exists yet (`ls internal` shows no server package), so no logging behaviour can be checked yet.
  - Fix: In the 02-12 Task 1 redeem handler, refuse a code_verifier that is not exactly 43 base64url characters (unpadded), using the uniform 400. Add a Task 2 refusal test for it. Add one line to the must_haves or the T-02-57 entry: the code and code_verifier are never logged or persisted, only SHA-256(code) is stored. This mirrors the invite-token rule in 02-07.

- **02-12-F15 [PARTIAL/LOW] Clock handling between server, DB expiry and signer** (gptoss)
  - Evidence: The claim is wrong as stated. code_expires_us is set to "now + 120 s" by the server at assertion time (02-12-PLAN.md:179), and RedeemLogin checks it against the server's own now (02-12-PLAN.md:160, 182). Both reads come from the same server process, so drift between them cannot make a valid code look expired. The signer never reads code_expires_us or expires_us. Its only time check is |now − CreatedAt| ≤ maxClockSkew = 300 s (internal/signer/issue.go:22, 58; reused for login in 02-01-PLAN.md:260). CreatedAt comes from the CLI clock (02-12-PLAN.md:198). The plan already handles clock skew as a known risk: RESEARCH Pitfall 8 (02-RESEARCH.md:731-733), the must_have at 02-12-PLAN.md:46, the CLI's 60 s skew refusal (02-12-PLAN.md:197), the test clock_skew_refused (02-12-PLAN.md:272, 314), and threat T-02-63, rated low and mitigated (02-12-PLAN.md:391). A narrow edge remains. The CLI stops waiting at CreatedAt + 270 s on its own clock (02-12-PLAN.md:203). The server allows approval until CreatedAt + 300 s on the server clock (02-12-PLAN.md:169, 177). If the CLI clock is up to 60 s behind the signer, which is allowed, a late approval can reach the signer with CreatedAt about 330 s old. The signer then refuses with a 403 (02-12-PLAN.md:188).
  - Fix: Leave a safety margin for the signer's ±300 s check. Have the CLI shorten its callback deadline by the skew it measured (CreatedAt + 270 − |skew|). Have the server refuse an assertion once server_now − CreatedAt exceeds about 240 s, instead of accepting it until CreatedAt + 300.

- **02-12-F17 [PARTIAL/LOW] Ephemeral private key memory hygiene** (gptoss)
  - Evidence: The claim's example is wrong. In .planning/phases/02-passkey-login-mvp/02-12-PLAN.md:197 (step 2), --role is checked against the server options and --ttl against the cap. The key is generated only afterwards, at :198 (step 3, `ed25519.GenerateKey` with crypto/rand, "in memory only"), so a bad --role exits before any private key exists. Persistence is already covered: must_have :88 says the key is never written to disk and an agent add is never retried without the lifetime constraint; T-02-62 at :390 is "memory only; agent add with lifetime; no retry without constraint; Windows keyroster agent". The plan, however, never says to zero the ephemeral key after the agent Add (:211-214) or on the error paths after step 3 (timeout at :203, redeem or verify failure at :204-210, Add error at :214). The repo already zeroes secrets on a best-effort basis: `defer clear(pass)` in cmd/keyroster/root.go:123 and :447, and internal/rootceremony/keygen.go:29-31 ("The plaintext key is zeroed before GenerateRoot returns (best effort ...)"). So the plan does not follow an existing project convention. The swap concern is overstated. The CLI process lives about 270 s at most (:203), and the same private key then sits in ssh-agent memory for the whole certificate TTL by design. The tech stack in CLAUDE.md treats runtime/secret and mlock-style hardening as experimental defence in depth only. Neither 02-CONTEXT.md nor 02-RESEARCH.md has a locked decision against zeroing.
  - Fix: In Task 1 step 3, add a `defer clear(priv)` right after `ed25519.GenerateKey`, so the ephemeral key is zeroed on every return path, as in root.go:123 and rootceremony/keygen.go. Extend T-02-62 to say this is best effort only: the GC may copy the key, and the agent holds it for the TTL anyway. Leave out mlock and runtime/secret.

- **02-12-F21 [PARTIAL/LOW] Lifetime-expiry e2e test timing flakiness** (gptoss)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-12-PLAN.md:281: login_lifetime_expiry uses `--ttl 2m`, checks `ssh-add -l` lists the cert, then waits "ValidBefore − now + 5 s (about 125 s)" and checks that the cert is gone. 02-12-PLAN.md:211: the CLI adds with `LifetimeSecs: ValidBefore − now`, so the agent drops the key at about ValidBefore. 02-12-PLAN.md:210: the CLI refuses unless ValidBefore − now ≥ 60. 02-12-PLAN.md:217-224: signer, server, CLI and ssh-agent all run on the same e2e host, so they share one clock. .github/workflows/e2e.yml:63: `go test -tags e2e -count=1 -v ./test/e2e/...` has no `-timeout`, and grepping the phase-2 plans for `-timeout` finds nothing.
  - Fix: Leave the assertions as they are and add no retry. Optionally run login_lifetime_expiry with t.Parallel(), or give the e2e invocations an explicit `-timeout` (for example 20m) so the fixed 125 s wait cannot push the package past go test's default 10-minute limit.

- **02-12-F22 [PARTIAL/LOW] Fake signer fidelity in refusal-matrix tests** (gptoss)
  - Evidence: 02-12-PLAN.md:256-264 lists the redeem refusals (before approval, wrong code, wrong verifier, code reuse, code after 121 s, cross-login code). The fake signer is asserted to record zero calls for each. 02-12-PLAN.md:291 says the fake is "an interface with a recording fake; production uses signerclient". 02-12-PLAN.md:181-188 shows that every one of these refusals happens in the server (RedeemLogin, the PKCE compare) before step 4 calls signerclient.Login. 02-12-PLAN.md:234 requires exactly one signerclient.Login call site. Real-signer behaviour is covered elsewhere. 02-03-PLAN.md:171 and :211 test the signer's own refusals (principals_mismatch, ttl_exceeds_role, user_verification_missing, origin_mismatch and others) against the real signer. 02-12 e2e (lines 217-225 and 280-283: TestLoginEndToEnd, two_concurrent_logins, unapproved_login_mints_nothing) and 02-11-PLAN.md:177 drive the real signerclient.Login against a real signer. In the repo, internal/signerclient/client.go:19-20 and 53-57 show that a real refusal comes back as a *wire.ErrorResponse error (Code CodeRefused, Message = detail, internal/wire/issue.go:290). The plan does not say the fake must return that type for the 403 case at 02-12-PLAN.md:264.
  - Fix: In Task 2, say that the fake signer client returns signer refusals as *wire.ErrorResponse{Code: wire.CodeRefused, Message: detail}, exactly as signerclient does, so the 403 mapping is tested against the real error type. Optionally, add one e2e redeem that the real signer refuses (for example, revoke alice's role after approval and before redeem) and assert 403 with principals_mismatch.

### 02-13

- **02-13-F1 [PARTIAL/LOW] Backup/rollback completeness for the live signer upgrade** (codex, gemma)
  - Evidence: Plan 02-13-PLAN.md:187-192: stop the signer, then `sudo cp -a /var/lib/keyroster-signer /var/lib/keyroster-signer.pre-02-13` BEFORE the new binary is installed and run. Restoring that copy plus the old binaries is the rollback, and on any doctor FAIL step 5 says to "restore the backup and the binaries, record it, and stop". T-02-68 is at :378. All signer state lives in that one directory. signer.db is at {state-dir}/signer.db (cmd/keyroster-signer/serve.go:93, doctor.go:94, export.go:38), and it holds the trust bundle and policy tables (internal/signerdb/trust.go). ca-pubkeys.json defaults to {state-dir}/ca-pubkeys.json (cmd/keyroster-signer/cainit.go:33,54). The TPM key files are {state-dir}/tpm/{role}.tpmkey (internal/keystore/tpm/tpm.go:7,109; provision.go:29). These are TSS2 blobs that only the vTPM can use, so copying them exposes no private key. The lock file is also in the directory (lock.go:29). An old binary refuses a newer schema (internal/signerdb/migrate.go:55-68), and that is why the copy is taken before migration 0004 runs. The precedent at 01-20-PLAN.md:220 and :523 kept "the 24e0ada binaries and unit" for rollback. 02-13 step 2.3 keeps only the binaries (`.pre-02-13`), while step 2.4 replaces the unit from deploy/systemd. 01-20-SUMMARY.md:243 records that the rollback path was never exercised.
  - Fix: In Task 2 step 2.3, also keep the installed keyroster-signer.service as `.pre-02-13`, as 01-20 did. Write out the restore commands in full: move the failed state directory aside, `cp -a` the backup back, put back the old binaries and unit, then run daemon-reload. Optionally, record `ls -lan` of the backup in the SUMMARY.

- **02-13-F3 [PARTIAL/LOW] No resume point after a partial failure across hosts** (codex)
  - Evidence: The "second successor bundle" half is refuted by the existing Phase 1 code. internal/trust/verify.go:342-346 rejects a successor unless next.Version == prev.Version+1 and next.Prev == SHA256(installed bundle). internal/signer/trust.go:238-246 verifies every install against the latest installed bundle and refuses a version that is not above it. Re-running step 3 in 02-13-PLAN.md:194-203 always passes `--prev "$T/prev-v3"` (the v2 bundle), so a re-run can only produce another version-3 bundle chained to v2. Once v3 is installed, the signer refuses that bundle. Accidentally producing a v4 would mean deliberately pointing --prev at v3, which the plan never says to do. For rollback, step 2 (02-13-PLAN.md:187-192) keeps the pre-02-13 state-dir and binary backups with an explicit restore-and-stop path, and T-02-68 (line 378) covers this. Because no passkey exists before Task 3, restoring that backup also undoes v3. Task 2 is labelled one-way (line 175) and gated by the D-09 checkpoint. Several post-v3 steps can safely be run again: `systemctl enable --now` (step 5), the init re-run with --tls-pin (step 6.3, line 217), and kr.env written outside the repo. 02-07-PLAN.md:170/178/218 adds `user add --reinvite`, and `user add` refuses a duplicate with `already pending`, so a failed or expired invite can be recovered. What is really missing is narrower. 02-13 has no explicit resume guidance after v3 is installed. It does not tell a resumed executor to skip steps 1-4 when doctor already shows v3, and nothing stops step 3 from overwriting v3-out/ and appending a second V3_SHA256 line to pins.env. Either would break the hash-equality table and the Task 2 automated verify on line 230. Task 3's error reply (line 263) also has no next step, such as `user add --reinvite` or a retry.
  - Fix: Add a short resume note to Task 2. If doctor already shows `trust bundle version 3` with install SHA equal to the recorded V3_SHA256, skip steps 1-4 and never re-run root sign or overwrite v3-out/ or pins.env. Also add a line to Task 3: on a browser error or an expired invite, run `keyroster.exe user add <username> --reinvite` and repeat the checkpoint.

- **02-13-F14 [PARTIAL/LOW] Show sha256(FQDN)[:12] in the D-09 checkpoint message** (nemotron)
  - Evidence: The D-09 checkpoint context (.planning/phases/02-passkey-login-mvp/02-13-PLAN.md:133-142) shows the owner the candidate FQDN in full but no hash. The checkpoint acceptance criteria (line 168) list only the PSL, IP refusal, rename, CT logs and v3/v4 facts. The record side asks for "the first 12 hex digits of its SHA-256" (line 167), `sha256(<FQDN>)[:12]` (line 293), "a SHA-256 prefix" (line 316 and must_haves line 57), and "the FQDN replaced by its SHA-256 prefix" in the hash-equality table (line 234). None of these lines fixes the exact hash input: whether a trailing newline is included (`echo` vs `printf %s`), whether the trailing dot that is stripped from Self.DNSName at line 133 is included, and what the case is. So the checkpoint does lack the prefix, as claimed.
  - Fix: Define the hash once (for example `printf %s "<FQDN without trailing dot, lowercase>" | sha256sum | cut -c1-12`) and use it in lines 167, 234 and 293. Have the Task 1 checkpoint message show that 12-hex prefix next to the FQDN so the owner can match it against SUMMARY later.

### 02-14

- **02-14-F6 [PARTIAL/MEDIUM] Expiry check conflates agent exit with key removal, and a fixed 6-minute wait is timing-fragile** (codex, gptoss)
  - Evidence: 02-14-PLAN.md:173 (Task 2 step 5) accepts "no identities, or fail to connect because the keyroster agent exited". 02-14-PLAN.md:232 (Task 4 step 4) says only "the keyroster certificate and key should be gone". 02-14-PLAN.md:202 (Task 3 step 3) investigates only when the owner replies ttl-expired=no, and nothing independent backs up a "yes". What the finding gets wrong: (a) Agent exit vs key removal. 02-02-PLAN.md:35 makes `keyroster agent` an in-memory keyring that "exits once its last key has expired". If the process has exited, its keys are gone too. 02-02-PLAN.md:223 and :233 already check key removal (List shows 0) and process exit as separate assertions in automated tests (TestInboxSSHOffersAgentCert, plus the Serve-returns unit test). (b) Timing. 02-12-PLAN.md:197 refuses a login when client/server clock skew is over 60 s. 02-12-PLAN.md:211 sets LifetimeSecs = ValidBefore − now, truncated (02-REVIEWS.md:380), so the agent lifetime never runs past the certificate. A 6-minute wait on a 5-minute certificate leaves at least 60 s of margin. 02-12-PLAN.md:281 covers the exact-boundary case in CI. What the finding misses, and why it is still partly right: the earlier login in the same session uses the default TTL. Under D-14 (02-CONTEXT.md:109-111) that is the role cap, 8 h (02-13-PLAN.md:277). That is Task 2 step 3 (02-14:171) and Task 4 step 2 (02-14:230). So that 8 h certificate is still in the same agent 6 minutes later. On Windows, `ssh-add -l` will list it, the agent will not exit, and neither expected result at :173 can happen. An honest owner then reports ttl-expired=no, or reads the check the wrong way. On Linux, :232 does not say which certificate should be gone.
  - Fix: In Task 2 step 5 and Task 4 step 4, have the owner note the 5 m certificate's serial/key ID (or its fingerprint from `ssh-add -l`) right after login. The expiry check then passes when `ssh-add -l` no longer lists that entry. Alternatively, have the owner clear the agent first (`ssh-add -D`, or stop keyroster agent) so "no identities" is the right expected result. Task 3/5 should record the listing output, not only a yes/no.

- **02-14-F1 [PARTIAL/LOW] sshd -t does not prove the effective cert-login config; lockout risk** (codex, gptoss)
  - Evidence: Most of what the reviewers asked for is already in 02-14-PLAN.md: - Non-interactive check after the reload: line 148 `ssh.exe -n -o BatchMode=yes zima true` (fails_when "the existing key-based login to zima-srv broke", line 149). Lines 126 and 130 run the key login before and after. Acceptance at line 155 says "works before and after the change". - Rollback: line 131 ("If anything fails, remove the drop-in, reload and stop") and line 113 (one-file reversibility). T-02-70 at line 353 lists sshd -t, the login checks before and after, and the one-file rollback. - The plan uses `systemctl reload` (line 129), which sends SIGHUP. Sessions already logged in keep running, so a held-open second session adds little. The precondition at line 114 requires passwordless `sudo -n` on zima, and CLAUDE.md says zima is reachable over Tailscale from two machines. - The drop-in at line 128 only adds TrustedUserCAKeys and AuthorizedPrincipalsFile. Both apply only to certificate authentication, so the authorized_keys login that guards against lockout is not affected. That makes the claimed lockout (HIGH) overstated. - The effective certificate path is proven end to end later. Task 2 step 4 (line 172) does a real `ssh zima@<zima> whoami` with the certificate. Task 3 (lines 200 and 211) needs `Accepted publickey for zima ... ID kr2/...` lines in the sshd journal. The real gap is narrow. The check at line 146 greps global `sshd -T` with no `-C user=zima,host=...,addr=...`. A `Match` block in zima's existing sshd_config that overrides AuthorizedPrincipalsFile or TrustedUserCAKeys for that user or address would not show up. Neither would a precedence surprise from another drop-in (sshd keeps the first value it sees). The failure would surface later, in Task 2, as a failed certificate login. That is late detection, not a lockout.
  - Fix: In Task 1 step 5 and the verify at line 146, use `sudo sshd -T -C user=zima,host=<daniel-pc tailscale name>,addr=<daniel-pc tailscale IP>`. Also cover the laptop's address, or do a `grep -i '^Match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*` that must come back empty. That way the per-connection effective values are what get checked.

- **02-14-F5 [PARTIAL/LOW] Journal-to-audit correlation is too loose (time window, fields, clock sync)** (codex, nemotron)
  - Evidence: .planning/phases/02-passkey-login-mvp/02-14-PLAN.md:47 (key_link: "kr2 key IDs and serials matched between audit verify output and journal lines"); :198 (Task 3 step 1 lists kr2 key IDs and serials from `audit verify`); :200 (Task 3 step 2 requires journal lines "whose serials match the audit list", using `--since "<the Task 2 window>"`); :215 (acceptance: SUMMARY lists key ID, serial, journal timestamp and browser for each login); :258 (Task 5 step 1 repeats the serial match for the laptop window); :272 (SUMMARY evidence table with serials and timestamps). The coarse greps the finding describes are at :211 and :280. Before 02-14, zima-srv has no TrustedUserCAKeys for keyroster: Task 1 installs it first (:127-129). So no earlier kr2 certificate login can exist in the journal.
  - Fix: In Task 5's automated check, replace the relative `-3h` window with an absolute `--since` set to Task 1's install time. Then grep for the specific serials recorded in Task 3 and Task 5: at least one Windows-window serial and at least one laptop-window serial. Do not use a bare count of 2 or more.

- **02-14-F7 [PARTIAL/LOW] Ruleset JSON check only greps strings; no structure or validity check** (gptoss)
  - Evidence: 02-14-PLAN.md:282: Task 5's automated check is only `grep -c 'cli-windows\|cli-macos' .github/rulesets/main-integrity.json | grep -qx 2`. It does not parse the JSON, does not check where the entries sit, and does not check integration_id. So the factual claim is correct. What happens next, though, limits the damage: (a) Invalid JSON cannot reach the live repo silently. scripts/apply-rulesets.sh:34/36 sends the file with `gh api -X PUT/POST --input "$file"`, the API rejects malformed bodies, and `set -euo pipefail` (line 11) makes the owner's run in Task 6 (02-14-PLAN.md:307) fail loudly. (b) A misplaced context is caught by Task 6's live check (02-14-PLAN.md:316). It reads `.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context` from the applied ruleset and fails if either context is missing. (c) A wrong integration_id leaves a required check that can never be satisfied. Because strict checks are already active (.github/rulesets/main-integrity.json:20) and the ruleset is applied before approval, that would block this very PR's merge, which is loud and visible to the owner (T-02-73, 02-14-PLAN.md:356). (d) The one real gap: the Task 6 check runs after the merge, so a structural mistake is found post-merge and needs a follow-up PR. The live check also never verifies integration_id. A minor side issue: `grep -c` counts lines, so the check falsely fails if both contexts are written on one line.
  - Fix: Swap Task 5's grep for a jq assertion that checks validity and structure. For example: `jq -e '[.rules[]|select(.type=="required_status_checks")|.parameters.required_status_checks[]|select((.context=="cli-windows" or .context=="cli-macos") and .integration_id==15368)]|length==2' .github/rulesets/main-integrity.json`. Optionally also have the Task 6 live check assert integration_id.

- **02-14-F13 [PARTIAL/LOW] Audit verify output parsed by grep on a human-readable string** (gptoss)
  - Evidence: Plan 02-14 line 209 runs `audit verify ... && printf '%s\n' "$A" | grep -q 'trust bundle v3'`, with fails_when at line 210. In the real Phase 1 CLI, cmd/keyroster/audit.go:112 prints "OK: ... trust bundle v%d (current bundle) ..." and audit.go:116 prints "anchored: the pinned roots are the root set of trust bundle v%d". audit.go:86-89 returns an error, and so a non-zero exit, on any verification failure. A machine-readable `--json` flag already exists (audit.go:41-56, 65, 108-110), with `anchor_bundle_version`, `bundle_version`, `issued_by_ca` and `kinds`. It has no per-certificate serial or key-ID list. The serials and kr2 key IDs needed for cross-matching are in the export JSONL, which is already machine-readable. Cross-matching is a manual acceptance item (line 198 "List their kr2 key IDs and serials"; line 215 SUMMARY notes). Independent corroboration comes from the journal grep at lines 211 and 280.
  - Fix: In Task 3, run `audit verify --json` and check `anchor_bundle_version == 3` (and, if wanted, `kinds`/`issued_by_ca.user` against the 02-13 baseline count) instead of grepping the human-readable text. Take serials and kr2 key IDs from the export JSONL, not the verify output.

### Refuted (R) or already covered (C), ids only

- 02-01: F1(C), F3(C), F4(R), F6(C), F8(R), F9(C), F10(C), F11(R), F12(C), F13(C), F14(C), F15(C), F16(R), F17(R), F18(C), F20(C)
- 02-02: F2(C), F3(C), F4(R), F6(C), F7(C), F9(R), F10(C), F11(R), F12(R), F13(C)
- 02-03: F1(R), F2(C), F3(C), F4(R), F6(C), F7(C), F8(C), F9(C), F11(C), F14(R), F15(C), F17(C), F18(C)
- 02-04: F1(C), F3(C), F4(C), F5(R), F6(R), F7(C), F9(C), F10(R), F11(C), F12(C), F13(C), F14(R), F15(C)
- 02-05: F3(C), F5(R), F8(C), F9(C), F10(R), F12(R), F13(C), F14(R), F15(C)
- 02-06: F2(R), F3(C), F5(C), F6(C), F7(C), F8(C), F9(C), F12(R), F13(R), F14(R), F17(C), F18(R)
- 02-07: F2(R), F3(C), F4(C), F11(R), F13(C), F14(R), F15(C), F16(C), F17(C), F18(R), F19(C), F20(R)
- 02-08: F2(C), F4(C), F5(C), F6(C), F8(C), F9(C), F12(C), F13(C), F14(C), F15(R)
- 02-09: F1(C), F2(C), F3(R), F4(C), F5(R), F7(C), F8(C), F9(C), F12(C), F13(C), F15(R), F16(R), F17(C), F18(C)
- 02-10: F3(C), F4(C), F7(R), F8(R), F9(C), F10(C), F11(R), F12(R), F13(C), F14(R), F17(R)
- 02-11: F1(C), F4(C), F8(C), F9(C), F10(C), F11(C), F12(C), F13(C), F14(C)
- 02-12: F3(C), F4(C), F5(C), F6(C), F7(C), F8(C), F9(C), F10(C), F11(C), F16(C), F18(C), F19(C), F20(C), F23(C), F24(R), F25(R), F26(C), F27(R), F28(C), F29(C), F30(C), F31(R)
- 02-13: F2(C), F4(C), F5(C), F6(C), F7(C), F8(C), F9(R), F10(C), F11(R), F12(C), F13(C), F15(C), F16(C)
- 02-14: F2(C), F3(C), F4(C), F8(C), F9(C), F10(C), F11(C), F12(C), F14(R), F15(C), F16(C)
