---
phase: 2
reviewers: [codex]
reviewed_at: 2026-10-11T04:30:00Z
plans_reviewed: [02-01-PLAN.md, 02-02-PLAN.md, 02-03-PLAN.md, 02-04-PLAN.md, 02-05-PLAN.md, 02-06-PLAN.md, 02-07-PLAN.md, 02-08-PLAN.md, 02-09-PLAN.md, 02-10-PLAN.md, 02-11-PLAN.md, 02-12-PLAN.md, 02-13-PLAN.md, 02-14-PLAN.md]
models:
  codex: "gpt-6-luna (reasoning=high)"
model_sources:
  codex: "banner"
---

# Cross-AI Plan Review — Phase 2

<!-- gsd:plan-revision-conflicts:begin -->
## Plan-Revision Conflicts
<!-- gsd:plan-revision-conflicts:end -->

> **Coverage caveat.** Only one external reviewer produced a review. Claude was skipped
> because the orchestrator runs in Claude Code. Kimi Code hit its quota limit. OpenCode was
> unavailable because `jq` is missing. The Codex review is **not source-grounded**: its sandbox
> could not start a shell in the repo (Windows error 267), so it reviewed the pasted plan text
> only. It is down-weighted below, and its concerns are open questions, not confirmed defects.

## Codex Review

# Phase 2 plan review

**Source verification was unavailable.** The workspace reports `C:\Users\labon\ssh-cert-manager`, but every attempt to start a shell there failed with Windows error 267 (“directory not found”). I could not inspect the referenced source files or verify their line numbers. Per your instruction, source-dependent concerns below are framed as questions to resolve, not as confirmed defects. File paths identify where to check; line-level evidence is unavailable.

## 02-01

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

## 02-02

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

## 02-03

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

## 02-04

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

## 02-05

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

## 02-06

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

## 02-07

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

## 02-08

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

## 02-09

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

## 02-10

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

## 02-11

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

## 02-12

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

## 02-13

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

## 02-14

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

## Cross-plan assessment

The sequence is broadly sensible: signer authority first, platform probes early, audit proof before the full login path, and real homelab evidence last. The largest cross-plan risks are:

- The signer protocol, directory and audit formats are introduced across 02-01 through 02-04, before the UI and enrollment flows exist. Their compatibility and migration behavior should be treated as a single review surface.
- Login redemption and registration both have single-use server state. Their failure and retry semantics should be settled explicitly before implementation.
- Several plans depend on server directory/status mirrors. Define one freshness contract and make session invalidation, login options and custody reporting follow it.
- The 14-plan sequence is unusually large for an MVP. The per-plan PR gates help, but the very large tracers may still make security review difficult.

**Overall risk: HIGH.** The plans emphasize strong controls and meaningful end-to-end evidence, but the scope spans new cryptographic formats, signer state, a public-facing server, platform-specific agents and live trust operations. Repository source verification remains outstanding because of the workspace access failure.

---

## Consensus Summary

A consensus is not possible from a single reviewer that had no repo access. The orchestrator
spot-checked the most concrete Codex claims against the plan text. The results are below.
Re-run `/gsd-review --phase 2 --all` once a second reviewer is available (Kimi quota, or `jq`
for OpenCode). That run is the place to get source-grounded findings.

### Spot-checked Codex claims

| Codex claim | Check against plan text | Verdict |
|---|---|---|
| 02-12 HIGH: redemption consumes the code before signing, so a lost response cannot be retried | Confirmed at `02-12-PLAN.md:182-188`: `RedeemLogin` (approved→redeemed) runs before `signerclient.Login`, and every non-signer failure returns the uniform 400. No retry or recovery path is specified. | **Valid, but MEDIUM, not HIGH.** It fails safe: the private key is ephemeral and never leaves the CLI, so an orphaned certificate is useless. The impact is UX (the user restarts `keyroster login`) plus an audit leaf for a certificate nobody received. The plan should state this outcome explicitly, and the CLI error should tell the user to rerun. |
| 02-12 HIGH: rounding of the agent lifetime could let the key outlive the certificate | `02-12-PLAN.md:210-211` requires `ValidBefore − now ≥ 60` and sets `LifetimeSecs: ValidBefore − now`. Integer seconds truncate toward zero, so the agent lifetime is ≤ the remaining validity. | **Mostly a non-issue (LOW).** It is worth one boundary test and one sentence saying that truncation, never ceiling, is intended. |
| 02-11 MEDIUM: an empty mapping and an unknown account are conflated | Confirmed at `02-11-PLAN.md:179`: after `unmap`, `host principals` fails with "account unknown", yet the refusal test uses "the remaining output (an empty principals file)". | **Valid (MEDIUM).** Define whether an account with zero roles renders an empty file or is an error. The 02-14 host and the future agent will both depend on this. |

### Agreed Strengths
n/a (single reviewer)

### Agreed Concerns
n/a (single reviewer). The highest-value open questions from Codex to resolve in replanning:
- **Single-use state retry semantics** (02-08 invite consumption, 02-12 redemption): define the outcome of a failure after the state transition.
- **One directory-mirror freshness contract** shared by sessions (02-10), login options and custody status (02-05/02-06).
- **Signer/directory/audit formats** introduced across 02-01..02-04: review them as one surface, with stable test vectors.
- **02-13 live-migration rollback/resume table** after the v3 install and before enrollment.
- **02-14 `sshd -T -C`** effective-config check for the target connection before relying on certificate login.

### Divergent Views
n/a (single reviewer)
