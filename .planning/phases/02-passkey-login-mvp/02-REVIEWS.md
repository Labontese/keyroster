---
phase: 2
review_round: 2
reviewers: [codex, ollama-nemotron, ollama-gemma, ollama-gptoss]
reviewed_at: 2026-10-11T12:55:00Z
plans_reviewed: [02-01-PLAN.md, 02-02-PLAN.md, 02-03-PLAN.md, 02-04-PLAN.md, 02-05-PLAN.md, 02-06-PLAN.md, 02-07-PLAN.md, 02-08-PLAN.md, 02-09-PLAN.md, 02-10-PLAN.md, 02-11-PLAN.md, 02-12-PLAN.md, 02-13-PLAN.md, 02-14-PLAN.md]
plans_at_commit: adff052
previous_round: d849096
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
trimmed_reviewers:
  ollama-nemotron:
    omitted: [research]
    estimated_tokens: 230711
    note: "02-RESEARCH.md left out to fit the 262k context; all 14 plans sent in full"
  ollama-gemma:
    omitted: [research]
    estimated_tokens: 240395
    note: "02-RESEARCH.md left out to fit the 262k context; all 14 plans sent in full"
  ollama-gptoss:
    omitted: [sibling-plans]
    note: "131k context: one plan per request (46k-59k tokens each), with RESEARCH.md but without the other 13 plans"
verification:
  method: "every finding adversarially verified by a Claude agent against the current plan text, CONTEXT/RESEARCH, repo source and the round-1 verified appendix"
  findings: 198
  verdicts: {already_covered: 107, refuted: 72, partial: 18, confirmed: 1}
  surviving_by_severity: {high: 0, medium: 1, low: 18}
---

# Cross-AI Plan Review — Phase 2

<!-- gsd:plan-revision-conflicts:begin -->
## Plan-Revision Conflicts
<!-- gsd:plan-revision-conflicts:end -->

> **This is round 2.** It reviews the plans as revised after round 1 (plans at `adff052`). The
> round-1 review, with its 250 verified findings, is this file at commit `d849096`.
>
> **Reviewer caveats.**
> - **Codex** had read access to the repo this time and cites Phase 1 source lines. It ran no tests.
> - **nemotron** and **gemma** got all 14 plans, project context, roadmap and CONTEXT.md through
>   the plain Ollama chat API, without `02-RESEARCH.md` (the full prompt, 936 kB, would not fit in
>   262k tokens). They had no repo access, and gemma cites no line numbers at all.
> - **gpt-oss** reviewed each plan on its own, with RESEARCH.md but without the sibling plans and
>   without repo access. It cites line numbers in files that do not exist yet, so its citations
>   are not evidence.
> - **Not run:** Claude (it is the orchestrator), Kimi (quota exceeded), OpenCode and the GSD
>   Ollama lane (`jq` is not installed; the Ollama models were called directly instead).
>
> Because three of four reviewers saw plan text only, **every finding (198 after per-plan
> dedup) was adversarially verified** by a Claude agent with repo access. Read the Consensus
> Summary and the appendix, not the raw reviews: 90% of raw findings were already covered or wrong.

## Codex Review

### Review scope

All 14 plan files are present. I compared them with the existing Phase 1 code and checked whether the revised plans address the risks described in their own review ledger. The new Phase 2 packages and routes are not implemented in the current source tree, so their behavior remains a plan to verify during execution. I did not run tests.

### 02-01

**Summary.** A broad but coherent tracer establishes the signed policy and directory, signer-side WebAuthn verification, and first SSH certificate login.

**Strengths.** It preserves the Phase 1 admin request format and defines exact principals and TTL as signer decisions. That fits the existing domain-separated signing bytes in [issue.go:20](C:/Users/labon/ssh-cert-manager/internal/wire/issue.go:20) and the signer’s log-before-release transaction in [issue.go:139](C:/Users/labon/ssh-cert-manager/internal/signer/issue.go:139). The revised end-to-end test checks the parsed certificate’s key, principals, validity, and refusal control ([02-01-PLAN.md:329](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-01-PLAN.md:329)).

**Concerns.** **MEDIUM** — This plan adds several lasting formats and signer paths at once. Phase 1’s log decoder currently accepts kinds only through `KindBundleInstall` ([leaf.go:67](C:/Users/labon/ssh-cert-manager/internal/tlog/leaf.go:67)); until all decoder, restart, and audit paths are updated, a partial merge could make logs unreadable.

**Suggestions.** Keep the specified golden vectors and restart checks as merge blockers, and review the new log-kind handling in every consumer, not only the signer.

**Risk Assessment. MEDIUM.** The architecture follows existing trust boundaries, but this is the most foundational format change.

### 02-02

**Summary.** The Windows in-memory agent and cross-platform CI address the known inbox-agent lifetime and persistence problems.

**Strengths.** It probes the Windows client before relying on it and specifies a SID-restricted pipe, server-owner check, and no fallback to the inbox agent. The agent exit race now has a stated synchronization rule and a concurrent-add test ([02-02-PLAN.md:205](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-02-PLAN.md:205), [02-02-PLAN.md:241](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-02-PLAN.md:241)).

**Concerns.** **MEDIUM** — Correctness still depends on real Win32 OpenSSH honoring the custom pipe path. The plan gates that assumption with a probe, but the end-to-end login path through `Ensure` is deferred to 02-14 ([02-02-PLAN.md:243](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-02-PLAN.md:243)).

**Suggestions.** Preserve the distinction between CI’s test pipe and the actual login path in the platform record; do not mark the Windows path verified until the homelab login exercises it.

**Risk Assessment. MEDIUM.** The controls and probes are appropriate; remaining risk is platform-specific execution.

### 02-03

**Summary.** This plan hardens the signer’s new refusal paths, directory state, and per-message framing.

**Strengths.** The revised frame tests cover short headers, exact caps, and oversized messages before allocation ([02-03-PLAN.md:390](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-03-PLAN.md:390)). This matters because the existing framing code uses one 64 KiB cap ([frame.go:19](C:/Users/labon/ssh-cert-manager/internal/wire/frame.go:19)); the plan’s type-aware rewrite changes that boundary.

**Concerns.** **LOW** — Changing `ReadMessage` and `WriteMessage` together creates an opportunity for their per-type limits to diverge. The plan specifies read-side boundary cases clearly; the write-side tests should remain explicit acceptance criteria.

**Suggestions.** Keep tests for exact-cap writes and “oversize writes nothing,” alongside the parser fuzz targets.

**Risk Assessment. LOW–MEDIUM.** The test plan addresses the main parser risks; execution must keep both directions aligned.

### 02-04

**Summary.** The audit extension aims to re-prove each login from the request, assertion, signed directory, policy, and certificate.

**Strengths.** It adds positive as well as tampering fixtures, including a directory that remains valid across an RP-only policy successor ([02-04-PLAN.md:219](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-04-PLAN.md:219)). The existing verifier already checks bundle succession and active CA keys ([verify.go:265](C:/Users/labon/ssh-cert-manager/internal/audit/verify.go:265), [verify.go:186](C:/Users/labon/ssh-cert-manager/internal/audit/verify.go:186)).

**Concerns.** **LOW** — The new audit semantics depend on keeping a cached verification result correct as either the policy or directory changes. The plan now specifies rechecking only when that pair changes ([02-04-PLAN.md:149](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-04-PLAN.md:149)); the positive multi-successor fixture is important to preserve.

**Suggestions.** Treat the multi-successor fixture as a compatibility test for future policy and directory changes, not just as a one-time regression test.

**Risk Assessment. LOW–MEDIUM.** It builds on established audit-chain checks, with a new but well-described state machine.

### 02-05

**Summary.** The software CA backend fills a real gap in KEY-06 and ties the warning to signer-reported custody.

**Strengths.** The plan recognizes that software custody exists only as a constant today ([keystore.go:33](C:/Users/labon/ssh-cert-manager/internal/keystore/keystore.go:33)) and specifies a filesystem backend, custody reporting, and a user-reviewed warning. It also caps installed trust documents so a later status response remains representable ([02-05-PLAN.md:44](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-05-PLAN.md:44)).

**Concerns.** **MEDIUM** — Encrypted files still depend on passphrase handling and safe provisioning. The plan says to mirror the TPM backend’s directory checks and all-or-nothing writes ([02-05-PLAN.md:133](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-05-PLAN.md:133)); that behavior needs direct refusal tests, since the existing custody constant does not provide it.

**Suggestions.** Verify permissions and failure cleanup for both new and pre-existing paths; document that same-host passphrase storage weakens the protection.

**Risk Assessment. MEDIUM.** The scope is focused, but the new key-storage path is security-sensitive.

### 02-06

**Summary.** This plan creates the server shell, TLS identity pinning, status cache, and deployment path.

**Strengths.** It sources RP and custody from signer status and gives all handlers one fail-closed cache rule ([02-06-PLAN.md:58](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-06-PLAN.md:58), [02-06-PLAN.md:193](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-06-PLAN.md:193)). It also accounts for certificate reload and operational renewal.

**Concerns.** **MEDIUM** — The initial TLS pin ceremony is security-critical and easy to misunderstand: it must authenticate the observed root out of band before saving trust. The plan should ensure errors distinguish a pin mismatch from ordinary TLS validation failure and tell the operator how to recover.

**Suggestions.** Keep separate tests for an untrusted chain, hostname mismatch, root-pin mismatch, and successful rotation to a pinned chain.

**Risk Assessment. MEDIUM.** The design is sensible, but bootstrap and status failure behavior need careful implementation review.

### 02-07

**Summary.** The admin API uses SSHSIG-authenticated requests to create pending users and invites without treating server rows as authority.

**Strengths.** The plan signs the raw request target and exact body, and explicitly avoids normalized-path ambiguity ([02-07-PLAN.md:50](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-07-PLAN.md:50)). It includes bounded request bodies, replay controls, and rate limits.

**Concerns.** **LOW** — The request authentication and rate-limit logic are new server code, not existing mechanisms verified by the current source. In particular, the IPv6 /64 and global limiter behavior should be tested against the stated map-bound guarantees ([02-07-PLAN.md:174](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-07-PLAN.md:174)).

**Suggestions.** Ensure path/body verification occurs before handler side effects, and retain tests for percent-encoded paths and replayed nonces.

**Risk Assessment. LOW–MEDIUM.** The plan has clear boundaries and tests; its new HTTP authentication layer is the main uncertainty.

### 02-08

**Summary.** This plan adds passkey registration while keeping new credentials pending until an admin binds them in a signed directory.

**Strengths.** Registration parsing stays in the server; the signer receives SPKI data, consistent with the dependency boundary. The revised plan makes session and invite consumption conditional and atomic, with a concurrent-finish test ([02-08-PLAN.md:198](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-08-PLAN.md:198), [02-08-PLAN.md:200](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-08-PLAN.md:200)).

**Concerns.** **MEDIUM** — The external WebAuthn library and its transitive dependencies expand the server’s supply chain. The owner review gate and signer dependency check are appropriate, but registration behavior still needs the specified differential tests and real-browser validation.

**Suggestions.** Keep dependency approval ahead of `go get`, and ensure the unique pending-credential constraint and concurrent-finish case run in CI.

**Risk Assessment. MEDIUM.** Strong enrollment controls, with moderate dependency and browser integration risk.

### 02-09

**Summary.** The verified-base directory edit pipeline is the authority bridge between pending enrollment and signer-installed users and roles.

**Strengths.** It has admins verify the base locally, review a diff, sign the successor, and send it to the signer. The server checks newly bound credentials against pending rows before forwarding ([02-09-PLAN.md:183](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-09-PLAN.md:183)).

**Concerns.** **MEDIUM** — The pending-row check and signer install are separate steps. A concurrent `--reinvite` can delete the pending credential after the check at [02-09-PLAN.md:186](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-09-PLAN.md:186) but before the install at [02-09-PLAN.md:190](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-09-PLAN.md:190). The signed directory can then install despite the plan’s claim that reinvite makes the old proposal final.

**Suggestions.** Reserve the pending credential with a conditional state transition before calling the signer, then finalize or release that reservation based on the signer result. Alternatively, define and test which operation wins a reinvite/install race.

**Risk Assessment. MEDIUM.** The signer still requires a valid admin signature, so this is not a server-only privilege escalation; it is a race against the plan’s credential-invalidation semantics.

### 02-10

**Summary.** The web sign-in plan adds passkey sessions and a read-only account page, reusing the assertion verifier.

**Strengths.** It checks the installed directory on session use and terminates sessions when the credential is no longer bound ([02-10-PLAN.md:39](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-10-PLAN.md:39)). The bounded cookie lifetime and fail-closed status refresh are clearly specified.

**Concerns.** **LOW** — A disable followed by re-enable can leave a session alive if no request occurred while disabled; the plan documents that residual ([02-10-PLAN.md:168](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-10-PLAN.md:168)). Since the session is read-only and does not authorize issuance, the impact is limited.

**Suggestions.** Keep the residual visible in the security documentation and test that role changes are reflected on the next account-page request.

**Risk Assessment. LOW.** Session authority is constrained and the known residual is bounded.

### 02-11

**Summary.** The role, group, and host-group plan connects signer-computed principals to a shared host-file renderer.

**Strengths.** It now defines empty mappings as a header-only file and uses the renderer’s output in the SSHD refusal test ([02-11-PLAN.md:35](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-11-PLAN.md:35)). This is a useful fail-closed rule for later host-agent work.

**Concerns.** **LOW** — Host-group mappings are not host-scoped certificate authorization in this phase; the plan correctly says they affect the rendered file only. Operators could mistake the mapping for signer-enforced host restriction unless the CLI and runbook state this plainly.

**Suggestions.** Keep the UI/CLI wording explicit that host groups control generated `AuthorizedPrincipalsFile` content, not issuance scope.

**Risk Assessment. LOW.** The plan addresses the earlier empty-output ambiguity and tests the actual renderer path.

### 02-12

**Summary.** This plan implements the end-user login flow from request construction through passkey approval, redemption, certificate verification, and agent loading.

**Strengths.** It mints only at redemption and uses loopback state, PKCE, exact fingerprint display, and client-side certificate checks ([02-12-PLAN.md:49](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-12-PLAN.md:49), [02-12-PLAN.md:50](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-12-PLAN.md:50)). The expiry check now targets the short-lived entry by key ID while confirming the longer-lived entry remains ([02-12-PLAN.md:232](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-12-PLAN.md:232)).

**Concerns.** **MEDIUM** — The flow has several independent browser, server, loopback, and agent steps. The plan correctly labels browser and default Windows-agent paths unverified until real use; those labels must remain until 02-14 evidence exists.

**Suggestions.** Keep redemption failure and lost-response outcomes fail-closed and non-retryable as specified, and ensure the user-facing errors make clear that a fresh login is required.

**Risk Assessment. MEDIUM.** The flow is carefully specified, but it is the most integration-heavy user-facing plan.

### 02-13

**Summary.** This is an operational homelab rollout with explicit owner checkpoints before binding credentials to the RP hostname.

**Strengths.** It requires confirmation of the exact hostname before signing RP policy and records the irreversible consequence ([02-13-PLAN.md:128](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-13-PLAN.md:128)). The upgrade includes guarded backups and a written rollback path ([02-13-PLAN.md:210](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-13-PLAN.md:210)).

**Concerns.** **MEDIUM** — The rollback boundary ends once a passkey is registered; after that, the plan requires fixing forward. That is appropriate for avoiding a stranded credential, but makes the pre-registration backup, v3 hash checks, and doctor verification essential gates.

**Suggestions.** Do not proceed to registration unless the installed bundle, server health, and owner-confirmed RP hash all match the recorded values.

**Risk Assessment. MEDIUM.** It is operationally high-consequence but has strong checkpoints and rollback controls.

### 02-14

**Summary.** The final dogfood plan validates web sign-in and real Windows/Linux SSH logins, then records platform status and adds required CI checks.

**Strengths.** It corroborates logins with both audit exports and SSHD journal serials, and the expiry test identifies the five-minute certificate specifically ([02-14-PLAN.md:230](C:/Users/labon/ssh-cert-manager/.planning/phases/02-passkey-login-mvp/02-14-PLAN.md:230)). It leaves macOS unverified rather than claiming unsupported coverage.

**Concerns.** **MEDIUM** — The plan depends on real hardware, a live homelab, and owner interaction. It also makes the OS jobs required, so a skipped or unavailable runner could block merges.

**Suggestions.** Before applying the ruleset, confirm both jobs have successful runs on `main` and on the PR branch, as the plan requires.

**Risk Assessment. MEDIUM.** The evidence plan is strong, but execution and CI availability remain external dependencies.

### Cross-plan findings

The sequence is sensible: signer formats precede hardening and audit verification; the server and enrollment flow precede role management and login; real homelab work follows implementation. The existing Phase 1 issue path already logs before releasing a certificate ([issue.go:196](C:/Users/labon/ssh-cert-manager/internal/signer/issue.go:196)), and the Phase 2 plans preserve that invariant.

The main review finding is the **02-09 reinvite/install race**. The plan says reinvite invalidates old credentials, but checks pending state separately from the signer call. Define a reservation or an explicit race outcome before implementing that pipeline.

The plans’ strongest verification choices are exact certificate checks in 02-01, read/write frame boundary cases in 02-03, positive policy-successor audit fixtures in 02-04, and serial-correlated expiry and host-login evidence in 02-14. Keep those as required merge gates.

---

## Ollama nemotron-3-ultra Review

**Cross-AI Plan Review: Phase 2 - Passkey Login MVP**

I'll review each of the 14 plans in sequence, providing structured feedback on quality, completeness, and risks.

---

### 02-01: Phase Tracer — RP Policy, Directory Install, Passkey Assertion, kr2 Certificate, Real SSHD Login

#### Summary
This is the foundational tracer plan that proves the entire security core of Phase 2 end-to-end. It implements the root-signed policy with WebAuthn RP settings, admin-signed directory document, WebAuthn assertion verification in the signer, kr2 certificate format, and real sshd login validation.

#### Strengths
- **Excellent tracer-first approach**: Crosses every signer layer the phase touches at least once
- **Strong security model**: Signer verifies WebAuthn assertion itself (KEY-02), principals/TTL computed by signer from installed directory (D-08)
- **Comprehensive audit integration**: Adds log kinds 7/8 with interim refusal in audit verify (replaced in 02-04)
- **Proper golden vectors**: Pinned byte-for-byte for all new persistent formats
- **Restart verification**: Step 9 restarts signer after login and issues again — proves logstate consistency
- **Clear prohibitions**: No server-trust path, no CBOR/COSE in signer

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **RP ID validation rejects tailnet domains** — The rule "under `.ts.net` needs ≥4 labels" and "under `.c.ts.net` ≥5 labels" may be too restrictive. A tailnet machine `host.tailnet.ts.net` has 4 labels and would pass, but what about `host.sub.tailnet.ts.net` (5 labels)? The Public Suffix List consideration needs verification. |
| HIGH | **Credential ID uniqueness across entire directory** — `Validate()` requires credential IDs unique across all users. This prevents two users from registering the same hardware key (e.g., shared YubiKey), which may be a legitimate use case. |
| MEDIUM | **37-byte authenticatorData hardcoded** — RESEARCH assumption A6 (no CBOR in signer). Real authenticators may produce longer authData with extensions. The plan defers this but it's a known gap. |
| MEDIUM | **No test for `webauthn-assertion/v1` evidence blob size** — The 8 KiB blob cap in `IssueRequest` needs verification against real assertion sizes. |
| LOW | **Large plan size** — 43 files, 156k tokens. Justified as tracer but increases review burden. |

#### Suggestions
1. Document the exact tailnet domain rule with test cases covering edge cases
2. Consider allowing duplicate credential IDs with explicit admin approval (or document why not)
3. Add a test case measuring real authenticatorData sizes from common authenticators
4. Verify 8 KiB evidence blob cap against max observed assertion sizes

#### Risk Assessment: **MEDIUM-HIGH**
The plan is architecturally sound but the RP ID validation and credential uniqueness rules need real-world validation. The 37-byte authData assumption is a known risk that must be tracked.

---

### 02-02: Windows Agent Probe & In-Memory Agent

#### Summary
Settles the Windows agent question early via gating probes (A2: inbox ssh.exe/ssh-add.exe against go-winio pipe; A3: GNOME gcr-ssh-agent lifetime handling), then builds keyroster's own in-memory agent on per-user named pipe.

#### Strengths
- **Probe-first approach**: Validates assumptions before writing code
- **Clear decision points**: Blocking-human checkpoint if A2 fails
- **Strong security**: Pipe SDDL grants only current user SID, denies network logons
- **Owner verification guard**: `VerifyServerOwner` checks pipe server process SID matches caller
- **Proper lifecycle**: Agent exits when last key expires or after 5 min idle
- **Cross-platform CI**: Adds cli-windows and cli-macos jobs (non-required initially)

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **A3 deferral to 02-14 creates uncertainty** — If laptop unreachable, gcr-ssh-agent stays UNVERIFIED until 02-14. The plan handles this but it delays platform verification. |
| MEDIUM | **Elevated agent handling** — `ErrOwnerUnverifiable` guidance says "stop that process or wait until it exits". On Windows, elevated processes may not be easily discoverable by non-elevated shells. |
| MEDIUM | **No probe for macOS ssh-agent lifetime** — Assumes OpenSSH ssh-agent honors lifetime (tested in Task 3) but doesn't probe macOS-specific behavior. |
| LOW | **Pipe name includes SID** — `keyroster-agent-<SID>` means each Windows account gets separate agent. Correct but worth documenting for `runas` scenarios. |

#### Suggestions
1. Add explicit test for elevated agent scenario in 02-02-F8
2. Document the `runas` / separate account behavior in needs-hardware.md
3. Consider adding macOS ssh-agent probe in 02-02 or 02-12

#### Risk Assessment: **MEDIUM**
The probe-first approach mitigates the biggest risk (A2 failure). A3 deferral is managed but creates a verification gap until 02-14.

---

### 02-03: Signer Boundary Hardening — Refusal Matrix, Concurrency, Restart, GetDirectory, Frame Caps, Fuzz

#### Summary
Expands the 02-01 tracer into a hardened signer boundary with full refusal matrix (SC4), concurrency guarantees, restart re-verification, GetDirectory, per-type frame caps, and comprehensive fuzz targets.

#### Strengths
- **Complete SC4 demonstration**: Every refusal case has a succeeding control
- **Policy clause test**: `policy_not_root_signed` proves root signature requirement
- **Concurrency tests**: 16 identical requests → 1 cert + 15 duplicate_refusal; concurrent installs
- **Per-type frame caps**: Properly derived from wire.MaxFrame/headerLen, prevents allocation attacks
- **Fuzz coverage**: All new parsers fuzzed including leaf decoders for kinds 7/8
- **Log consistency**: Startup refuses if stored directory ≠ last directory_install leaf

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Frame cap derivation** — `MaxDirectoryFrame = MaxDirectory + 64 KiB + 64 bytes` (1 MiB + 64 KiB + 64). Need to verify this covers base64 encoding overhead for directory + sigs in InstallDirectoryRequest. |
| MEDIUM | **GetDirectoryResponse version 0 validation** — Rejects version 0 with non-empty Directory/Sigs or Authorized=1. Good, but ensure this is tested. |
| MEDIUM | **clientDataJSON extra members acceptance** — The accept case `client_data_extra_members_accepted` allows Chrome's extra keys. Verify this doesn't weaken security. |
| LOW | **FuzzDecodeLeaf seed loop bound** — Raised to KindLoginIssue. Confirm this doesn't cause excessive fuzzing time. |

#### Suggestions
1. Add explicit test for InstallDirectoryRequest at MaxDirectoryFrame boundary with base64-encoded directory + sigs
2. Document the clientDataJSON extra-member allowance rationale
3. Profile fuzz target execution time

#### Risk Assessment: **LOW-MEDIUM**
Well-designed hardening. The frame cap math needs verification but the approach is sound.

---

### 02-04: Audit Verification for Login Certificates & Successor Policy Tool

#### Summary
Implements `keyroster root successor-policy` for adding RP to running installation, and full audit verification for directory_install and login_issue log kinds. Replaces 02-01's interim refusal with real checks.

#### Strengths
- **Complete audit verification**: Re-proves every login certificate's passkey authorization from log
- **Tamper suite**: 12 tamper cases including serial ordering across issue/login_issue
- **Positive fixture**: `login_directory_survives_rp_policy_change` proves directory survives RP-only policy change
- **Cached (directory, policy) verification**: Efficient re-check only when policy or directory changes
- **Shared serial sequence**: login_issue and issue share one serial counter, verified in audit
- **Compatibility note**: Documents behavior of older audit binaries

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Audit verifies against directory in force at each leaf** — The walk re-checks directory signatures at each directory_install and bundle_install. But what if a directory was installed under policy v1, then policy v2 changes admins? The directory stays authorized if v2 still authorizes it. This is correct but complex. |
| MEDIUM | **successor-policy only changes RP** — Other policy fields (admins, quorum, profiles) not editable here. Deferred to Phase 4 (AUTHZ-03). Correct but limits flexibility. |
| MEDIUM | **No test for directory_install with invalid directory bytes** — The tamper suite has `directory_install_non_admin` but not `directory_invalid` (malformed directory). |
| LOW | **Runbook compatibility note** — Should explicitly state that Phase 1 binaries report "unknown kind", 02-01-02-03 binaries report "not verifiable by this version". |

#### Suggestions
1. Add tamper case for directory_install with malformed directory bytes
2. Clarify in runbook the exact error messages from each binary version
3. Consider adding a test where policy change removes an admin who signed the directory

#### Risk Assessment: **LOW**
Thorough audit implementation with good tamper coverage. The caching optimization is correct and tested.

---

### 02-05: Software CA Key (KEY-06) — Encrypted Backend, Status, Banner

#### Summary
Implements encrypted software CA key backend for evaluation, signer Status message reporting custody, and evaluation-only banner in CLI (driven by signer's Status).

#### Strengths
- **Proper age encryption**: scrypt recipient, armored files, 0600 in 0700 directory
- **Passphrase handling**: Reads from file or systemd LoadCredential, never argv/env, 20-char minimum, cleared after use
- **Status message**: Reports custody from signer (D-18), includes bundle/policy/directory state
- **Install budget check**: InstallBundle refuses if Status reply would exceed MaxStatusFrame
- **Single banner constant**: Shared by CLI, docs, and later UI (internal/custodytext)
- **Owner wording checkpoint**: Blocking-human approval before docs quote it

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Passphrase string copy for age** — `age.NewScryptRecipient` takes `string(pass)` which cannot be cleared. Documented as "best effort" but this is a real limitation. |
| MEDIUM | **MaxStatusFrame = 256 KiB** — Below install-bundle's 1 MiB/document limit. The install budget check mitigates but creates a coupling. |
| MEDIUM | **capslock -tags piv re-deferred** — Recorded in deferred-items.md but no timeline. |
| LOW | **software backend only on Linux** — `//go:build linux`. Correct for signer but worth noting. |

#### Suggestions
1. Add explicit comment about the age string copy limitation in code
2. Consider if MaxStatusFrame should be configurable or derived
3. Set a timeline for capslock piv target in deferred-items.md

#### Risk Assessment: **LOW-MEDIUM**
Solid implementation. The passphrase clearing limitation is inherent to the age API and documented.

---

### 02-06: keyroster-server Core — TLS, Headers, Trust Endpoint, Init, systemd

#### Summary
Stand up keyroster-server binary with HTTPS from operator-provided certs, strict CSP/headers, server-rendered embedded UI, custody banner, trust endpoint verified by `keyroster init` with TLS pinning.

#### Strengths
- **Strict security headers**: CSP, HSTS, COOP, nosniff, Referrer-Policy, no-store, CrossOriginProtection
- **TLS reload**: File watch + SIGHUP, keeps last good cert, 14-day warning
- **Signer seam**: Single `signerAPI` interface, only `socketSigner` imports signerclient
- **Status cache**: 5s TTL, fail-closed on refresh failure, `dropStatus` invalidation hook
- **Pinned trust**: `keyroster init` verifies /api/v1/trust against root pins, stores pinned roots only
- **Actionable errors**: `ErrTLSRootNotPinned` and `ErrTrustRootNotPinned` with re-pin procedures
- **Hardened systemd units**: Proper sandboxing, keyroster-server user, keyroster-admin group

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Status cache 5s TTL with fail-closed** — A directory change installed via server drops cache immediately via `dropStatus`. But changes made directly on signer socket take up to 5s to propagate. This is documented but creates a window. |
| HIGH | **keyroster.localhost resolution in CI** — Requires `/etc/hosts` entry on GitHub runners. Documented but fragile. |
| MEDIUM | **tailscale-cert.env root:root 0644** — Unit reads it as root. Braced `${KEYROSTER_TLS_NAME}` prevents flag injection. Good but UNVERIFIED until 02-13. |
| MEDIUM | **Config file modes no-op on Windows** — Relies on %APPDATA% ACL. Accepted but documented. |
| LOW | **No npm/build step for UI** — Uses html/template + embed + one hand-written JS. Correct per STACK.md. |

#### Suggestions
1. Add CI step to verify keyroster.localhost resolves, with clear failure message
2. Consider making status cache TTL configurable for testing
3. Document the 5s stale-read window more prominently in runbooks

#### Risk Assessment: **MEDIUM**
Core server infrastructure is solid. The 5s cache window and CI hostname resolution are the main operational risks.

---

### 02-07: Admin API & Invites — SSHSIG Auth, Pending Users, Rate Limits

#### Summary
Implements SSHSIG-authenticated admin API (`keyroster user add`), server DB for pending users/invites, and invite page. Server never treats pending state as authority.

#### Strengths
- **SSHSIG authentication**: Payloads authenticated, not pipes. Uses policy admin keys.
- **Body limit before auth**: `requireAdminLimit` reads body with MaxBytesReader before signature verification
- **Pending-first check**: On reinvite, pending check comes before installed directory check
- **Token security**: 256-bit random, stored as SHA-256, 24h expiry, Referrer-Policy no-referrer
- **Rate limiting**: Per-client IP (IPv6 /64) + global backstop
- **Path canonicalization**: Signs raw `URL.RequestURI()`, verifies against `r.RequestURI`
- **Init line round-trip**: Prints `--tls-root-file keyroster-tls-root.pem` + PEM, tested end-to-end

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Nonce consumed before handler** — Failed admin request (5xx, 409) burns nonce, requiring re-sign. This is intentional but increases client complexity. |
| MEDIUM | **Invite URL origin from Host header** — `requestOrigin` matches request Host against policy origins. Host header can be spoofed in some reverse proxy setups. |
| MEDIUM | **No admin UI in Phase 2** — All admin actions via CLI. Deferred to UI-02. |
| LOW | **Admin key from ssh-agent** — Windows uses inbox agent via go-winio. Verified in 02-02. |

#### Suggestions
1. Document the nonce-retry requirement clearly in CLI help
2. Add note about Host header trust assumptions in runbook
3. Consider adding a test for reverse proxy Host header scenarios

#### Risk Assessment: **LOW-MEDIUM**
Well-designed admin API with proper security boundaries. The nonce behavior is a UX tradeoff, not a security issue.

---

### 02-08: Passkey Registration — go-webauthn, Pending Credentials, Differential Oracle

#### Summary
Invited user registers passkey via WebAuthn create ceremony (go-webauthn server-side), server stores pending credential with fingerprint, admin sees same fingerprint via `keyroster user pending`.

#### Strengths
- **Owner dependency review**: Blocking-human checkpoint before `go get go-webauthn`
- **Differential oracle**: Cross-checks internal/webauthn vs go-webauthn on all assertion vectors
- **Atomic invite consumption**: Sessions keyed by (invite_hash, challenge), consumed with DELETE RETURNING
- **Single pending credential per user**: Unique index prevents races
- **Reinvite handling**: Resets invite_used_us, deletes sessions and pending credential in same transaction
- **Dependency bans**: go-webauthn, cbor, jwt banned from signer graph via dep-firewall and depguard
- **Real browser UNVERIFIED**: app.js create ceremony only exercised by real browser, labeled UNVERIFIED until 02-14

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **go-webauthn transitive dependencies** — Adds tinylib/msgp, go-viper/mapstructure/v2, go-webauthn/x, philhofer/fwd, x448/float16, fxamacker/cbor/v2, golang-jwt/jwt/v5. Owner reviews but supply chain surface grows. |
| MEDIUM | **Compromised server can swap credential** — Documented as residual risk (Pitfall 13). Detection via user's failing first login. |
| MEDIUM | **No CI lock on approved module set** — Deferred as repo-wide item. CODEOWNERS + Dependabot + dep-firewall + capslock provide layers. |
| LOW | **app.js feature detection** — Disables button if no PublicKeyCredential. Good but UNVERIFIED until real browser test. |

#### Suggestions
1. Add Dependabot config for go-webauthn transitive deps
2. Document the compromised-server residual risk more prominently
3. Consider adding a CI check for approved module hash list

#### Risk Assessment: **MEDIUM**
The dependency review checkpoint is critical. The differential oracle is a strong mitigation for verifier correctness.

---

### 02-09: Admin Approval & Directory Pipeline — Binding, Co-signing, Mirror

#### Summary
Closes enrollment loop: `keyroster user approve` binds pending credential via admin-signed directory version through verified pipeline (trust verify, base verify, diff, sign, install). Supports quorum >1 via proposals.

#### Strengths
- **Single edit pipeline**: All directory changes (approve, disable/enable, roles, groups, host-groups) use same `editDirectory`
- **Verified base**: Trust bundle verified against root pins, directory verified against policy admins
- **Pending cleanup**: `DeleteBound` deletes only newly-bound credentials, preserves open invites
- **Server mirror fail-closed**: Reads through 5s status cache, drops on SHA-256 mismatch, `dropStatus` called after install
- **Proposal workflow**: `directory sign`/`install` for quorum >1, re-verified at each step
- **Stale proposal messages**: Clear guidance to discard and re-run
- **Install body limit**: Derived from wire.MaxDirectoryFrame, covers signer's frame cap

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Credential_not_pending check** — Server refuses install if newly-bound credential not pending. But check and forward aren't atomic; reinvite between them could allow stale proposal. Documented as residual T-02-119. |
| MEDIUM | **fetchVerifiedDirectory version 0 contract** — Returns non-nil result with nil Dir, Policy always set. Callers must check Version==0. Single check point in each caller. |
| MEDIUM | **directory sign no pending check** — At quorum 1, proposal is fully signed when written. Only server's check stops install. Correct per design. |
| LOW | **base.sha256 in proposal** — Note for admins, not read by sign/install. Could cause confusion. |

#### Suggestions
1. Add comment explaining why directory sign skips pending check (quorum 1 = fully signed)
2. Consider making base.sha256 verified by directory sign
3. Document the T-02-119 residual clearly in runbook

#### Risk Assessment: **LOW-MEDIUM**
Strong pipeline design. The non-atomic pending check is a known residual with low probability.

---

### 02-10: Web Sign-In & Account Page — Sessions, Read-Only View

#### Summary
Bound user signs in with passkey, gets `__Host-keyroster-session` cookie (32-byte random, SHA-256 stored, 1h idle/12h absolute), sees read-only account page with roles, principals, TTL cap, credentials (synced/device-bound).

#### Strengths
- **Session security**: Opaque ID, hashed at rest, `__Host-`, Secure, HttpOnly, SameSite=Strict
- **Credential-bound sessions**: Session stores `cred_id`, ends if credential unbound or user disabled
- **Fail-closed reads**: Through 5s status cache, 503 on refresh failure, no stale data served
- **Rate limiting**: Per-IP + per-username (2nd instance of bounded LRU map)
- **TouchSession atomicity**: Single conditional UPDATE with idle/absolute checks, deletes expired row
- **No non-passkey paths**: Uniform 404 for unknown/pending/disabled users
- **slog events**: Structured logging without secrets (signin_ok, refusals, rate_limited, logout)

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **5s stale-read window for direct signer changes** — A disable installed directly on signer socket takes up to 5s to end session. Accepted as T-02-91 residual. |
| MEDIUM | **Disable → re-enable with no request keeps session** — If user disabled then re-enabled with same credential, and no request uses session in between, session survives. Accepted residual. |
| MEDIUM | **Per-username limiter keyed only on valid names** — Invalid names get 404 without limiter entry. Good but test `username_limiter_bounded` must verify. |
| LOW | **No last sign-in / session list in /account** — Deferred to UI-02. Correct for Phase 2. |

#### Suggestions
1. Add explicit test for the disable→re-enable residual case
2. Document the 5s window in runbooks for admin awareness
3. Consider if session should store creation time for audit

#### Risk Assessment: **LOW**
Session design is secure. The residuals are documented and accepted.

---

### 02-11: Roles, Groups, Host Groups & Principals Renderer

#### Summary
Implements role/group/host-group commands through 02-09 pipeline. `keyroster host principals` renders AuthorizedPrincipalsFile using shared renderer. Owner confirms D-06 principal convention at checkpoint.

#### Strengths
- **Shared renderer**: `RenderPrincipalsFile` used by CLI and future Phase 3 agent
- **Header with SHA-256**: Directory version + SHA-256 in generated file header for staleness detection
- **Empty grant handling**: Unmapped account or empty role list → header-only file (exit 0), never error
- **Principal validation**: cert.ValidatePrincipals rejects empty, wildcard, comma, whitespace, control chars
- **One-way D-06 checkpoint**: Owner confirms `role:<name>` / `u:<username>` convention before implementation
- **E2E validates against real sshd**: Both accept and refusal (after unmap) use keyroster's rendered output

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **D-06 is one-way** — Changing principal convention later requires reconfiguring every host and re-issuing. Owner checkpoint mitigates but risk remains. |
| MEDIUM | **Host groups don't enforce in certs** — Certificates not host-scoped (D-07). Phase 3 agent will enforce. Documented. |
| MEDIUM | **Manual re-rendering required** — Until Phase 3 agent, admin must re-render after each change. Runbook documents this. |
| LOW | **Account name validation** — Windows lowercase rule enforced. Good. |

#### Suggestions
1. Make D-06 checkpoint very explicit with concrete examples
2. Add runbook warning about manual re-rendering requirement
3. Consider if `u:<username>` personal accounts need special handling

#### Risk Assessment: **MEDIUM**
The one-way principal convention decision is the main risk. Owner checkpoint and e2E validation mitigate well.

---

### 02-12: keyroster login — Loopback, PKCE, Agent Lifetime, Certificate Checks

#### Summary
MVP moment: `keyroster login` does browser loopback with PKCE/state, shows fingerprint on CLI and page, mint at redemption, verifies certificate, adds to ssh-agent with lifetime matching cert validity.

#### Strengths
- **Mint at redemption**: Signer called only when CLI redeems code (RESEARCH Q2 resolved)
- **PKCE S256 + state**: Code challenge/verifier, 120s code lifetime, single-use
- **Loopback security**: 127.0.0.1 only, exact Host check, state constant-time compare, closes after callback
- **Certificate verification**: CA from root-pinned bundle, key match, principals exact, kr2 key ID, TTL+300s span, ≥60s remaining
- **Agent lifetime**: Adds with LifetimeSecs = remaining validity, fails if agent refuses constraint
- **Cross-OS**: Unix (SSH_AUTH_SOCK), Windows (keyroster agent via winagent.Ensure)
- **Fail-safe lost response**: Certificate logged before release, bound to ephemeral key CLI zeroes
- **Clock skew handling**: CLI refuses >60s skew, waits until server's deadline mapped through skew

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **Ephemeral key clearing best effort** — `defer clear(priv)` but GC may have copied bytes. No mlock/runtime/secret. Documented. |
| HIGH | **Approval page fingerprint from stored request bytes** — Correctly computed from request, not separate field. But page JS never invokes WebAuthn before showing fingerprint. Verified in tests. |
| MEDIUM | **A3 gcr-ssh-agent handling** — Applies single A3 line from 02-02. If moved to 02-14, no check shipped. UNVERIFIED until 02-14. |
| MEDIUM | **Windows default connectLoginAgent UNVERIFIED** — `os.Executable()` + `winagent.Ensure` not tested by this plan's tests. First run in 02-14. |
| MEDIUM | **20m e2e timeout** — Added to workflow. login_lifetime_expiry waits ~125s. Subtests sequential (share signer/server). |

#### Suggestions
1. Add explicit comment about `defer clear(priv)` best-effort limitation
2. Consider adding `runtime.SetFinalizer` for additional clearing attempt
3. Document the Windows default path UNVERIFIED status clearly
4. Verify 20m timeout is sufficient for all e2e subtests

#### Risk Assessment: **MEDIUM-HIGH**
Core login flow is well-designed. The Windows default path and gcr handling are the main verification gaps until 02-14.

---

### 02-13: Homelab Enrollment — RP Confirmation, Bundle v3, Server, Owner Enrollment

#### Summary
Dogfood part 1: Owner confirms RP hostname (D-09 gate), root-signed policy successor (bundle v3, TEST root C), keyroster-server with tailscale cert, owner enrolls via real browser.

#### Strengths
- **D-09 blocking-human checkpoint**: Owner confirms exact FQDN with RP_HASH12 shown
- **Field-by-field policy comparison**: v2 = v1 except version, prev, webauthn
- **Rollback copies**: 5 `.pre-02-13` files guarded by `test ! -e`
- **Resume rule**: Skips steps 1-4 if doctor shows v3 and V3_SHA256 matches
- **KEY-07 bookkeeping**: v3 = RP successor, owed offline ceremony becomes v4
- **No homelab identifiers in repo**: RP_HASH12 only in SUMMARY, grep gate on diff

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **One-way RP binding** — Once owner registers passkey under RP, changing it means re-enrolling everyone. D-09 checkpoint is the gate. |
| MEDIUM | **TEST root C signs v3** — Not production roots. Homelab stays dogfood until KEY-07 v4 ceremony. Documented. |
| MEDIUM | **tailscale cert renewal** — 90-day expiry, 2/3 renewal. Timer runs daily with 1h jitter. UNVERIFIED until 02-13 run. |
| LOW | **No jq on Daniel-PC/WSL** — Audit verify JSON parsed with `python -I`. Works but less standard. |

#### Suggestions
1. Make D-09 checkpoint message extremely clear about consequences
2. Document tailscale cert renewal behavior in server-install.md
3. Consider adding `jq` to homelab setup for consistency

#### Risk Assessment: **MEDIUM**
Operational plan with good safeguards. The one-way RP decision is the critical gate.

---

### 02-14: Homelab Real Logins — Windows, Linux, Platform Record, Required Checks

#### Summary
Dogfood part 2: Real logins from Windows (Daniel-PC, keyroster agent) and Linux (laptop, GNOME), corroborated by audit log + sshd journal. Platform record in needs-hardware.md. cli-windows/cli-macos added to main-integrity ruleset.

#### Strengths
- **Dual corroboration**: Every login matched to audit-verified kr2 key ID + sshd journal line
- **Absolute journal windows**: `KR_ZIMA_SINCE` / `KR_VM_SINCE` recorded before CA trusted
- **Expiry verification**: 5m login targeted by key ID from export, listings A/B matched on key ID
- **A6 authenticatorData recording**: Length + flags from decoded export (accepted) or keyroster-server journal (refused)
- **Honest UNVERIFIED labels**: macOS browser leg, Safari, Firefox on Windows, headless
- **Ruleset update**: Owner applies from PR branch before approval (Pitfall 10/11)

#### Concerns
| Severity | Issue |
|----------|-------|
| HIGH | **macOS UNVERIFIED** — AUTH-03 and PLAT-05 not marked complete. Phase verifier must track this. |
| HIGH | **gcr-ssh-agent follow-up** — If owner chose refuse-gcr, `keyroster login` doesn't refuse gcr socket until follow-up plan. Open item tracked in SUMMARY. |
| MEDIUM | **sshd -T -C per-connection check** — Validates both client addresses see keyroster settings. Good but Match-file count only recorded, not asserted. |
| MEDIUM | **No Windows sshd as target** — Phase 5. Documented. |
| LOW | **Evidence files outside repo** — `$HOME/keyroster-ceremony/phase2/` not committed. Correct but must be backed up. |

#### Suggestions
1. Add explicit tracking in REQUIREMENTS.md for macOS UNVERIFIED status
2. Create follow-up plan issue for gcr-ssh-agent refuse-gcr if needed
3. Assert Match-file count == 0 in verification (or document expected count)

#### Risk Assessment: **MEDIUM**
Completes the phase goal on real hardware. The UNVERIFIED macOS and gcr follow-up are tracked transparently.

---

### Cross-Phase Risk Assessment

#### Overall Phase 2 Risk: **MEDIUM**

#### Key Risk Themes

| Theme | Risk Level | Mitigation |
|-------|------------|------------|
| **One-way decisions** (RP ID, principal convention) | HIGH | Blocking-human checkpoints with full consequence disclosure |
| **Platform verification gaps** (macOS, gcr-ssh-agent) | MEDIUM | Explicit UNVERIFIED labels, tracked in REQUIREMENTS.md |
| **Supply chain** (go-webauthn transitive deps) | MEDIUM | Owner dependency review, dep-firewall bans, differential oracle |
| **Stale read windows** (5s status cache) | LOW-MEDIUM | Documented, `dropStatus` for server-initiated changes |
| **Compromised server residuals** | MEDIUM | Documented in runbooks, detection via failing user login |

#### Plan Quality Summary

| Plan | Quality | Completeness | Risk |
|------|---------|--------------|------|
| 02-01 | ★★★★★ | Complete tracer | MEDIUM-HIGH |
| 02-02 | ★★★★☆ | Probe-first, A3 deferred | MEDIUM |
| 02-03 | ★★★★★ | Thorough hardening | LOW-MEDIUM |
| 02-04 | ★★★★★ | Complete audit + tamper | LOW |
| 02-05 | ★★★★☆ | Solid, passphrase limit noted | LOW-MEDIUM |
| 02-06 | ★★★★☆ | Hardened server, 5s window | MEDIUM |
| 02-07 | ★★★★☆ | Secure admin API | LOW-MEDIUM |
| 02-08 | ★★★★☆ | Dependency review, oracle | MEDIUM |
| 02-09 | ★★★★★ | Robust pipeline | LOW-MEDIUM |
| 02-10 | ★★★★☆ | Secure sessions | LOW |
| 02-11 | ★★★★☆ | Shared renderer, D-06 gate | MEDIUM |
| 02-12 | ★★★★☆ | Core MVP, Windows gap | MEDIUM-HIGH |
| 02-13 | ★★★★☆ | Operational, rollback safe | MEDIUM |
| 02-14 | ★★★★★ | Real verification, honest labels | MEDIUM |

#### Critical Path Dependencies
```
02-01 → 02-02, 02-03
02-03, 02-02 → 02-04
02-03 → 02-05
02-05 → 02-06
02-06 → 02-07
02-07 → 02-08
02-08, 02-03, 02-04 → 02-09
02-09 → 02-10, 02-11
02-10, 02-11, 02-02, 02-04 → 02-12
02-12 → 02-13
02-13 → 02-14
```

#### Recommendations

1. **Prioritize D-09 and D-06 checkpoints** — These are the only true one-way doors in the phase
2. **Track macOS verification** — Add explicit issue for macOS browser+passkey test
3. **Monitor gcr-ssh-agent** — If A3 fails, create follow-up plan immediately
4. **Verify frame cap math** — Add test for InstallDirectoryRequest at MaxDirectoryFrame with base64 encoding
5. **Document all UNVERIFIED items** — Ensure needs-hardware.md is complete before phase close

The plans are exceptionally well-structured with strong security-first design, proper threat modeling, and clear verification criteria. The main risks are operational (platform verification gaps) and one-way architectural decisions, both mitigated by explicit checkpoints and honest labeling.
---

## Ollama gemma4:31b Review

This review covers the implementation plans for **Phase 2: Passkey Login MVP**.

### 02-01
**Summary**: This is the "Walking Skeleton" for Phase 2. It establishes the core trust chain: a root-signed policy with RP settings, an admin-signed directory for user bindings, and the signer's ability to verify WebAuthn assertions over login requests.

**Strengths**:
- **Tracer Approach**: By implementing the end-to-end path (RP $\rightarrow$ Directory $\rightarrow$ Assertion $\rightarrow$ Certificate $\rightarrow$ sshd), it validates the most critical architectural assumptions immediately.
- **Fail-Closed Audit**: The interim move to an exhaustive kind-switch in `audit.Verify` ensures that new log kinds are refused by default rather than silently ignored.
- **Strict Canonicalization**: Enforcing `DecodeStrict` for policy and directory prevents "malleability" attacks where different bytes represent the same logical state.

**Concerns**:
- **Low**: The dependence on the `CGO_ENABLED=0` build for the signer is absolute; any accidental inclusion of a C-dependency (like a crypto library) would break the "one binary" simplicity.

**Suggestions**:
- Ensure the `SIGHUP` and interval-based reload in the server (planned for 02-06) is explicitly tested against the directory mirror to avoid a state where the server is using a certificate that doesn't match the RP ID in the current policy.

**Risk Assessment**: **LOW**. The plan is highly disciplined and follows the "tracer-first" pattern.

---

### 02-02
**Summary**: This plan solves the "Windows Agent" problem. Since the inbox OpenSSH agent on Windows often lacks support for lifetime constraints, this plan implements a dedicated in-memory agent on a per-user named pipe.

**Strengths**:
- **Gating Probes**: Using "throwaway probes" (A2/A3) to verify OS-level assumptions before writing production code is an excellent risk mitigation strategy.
- **Pipe-Squatting Guard**: `VerifyServerOwner` (comparing SIDs) prevents a malicious process from intercepting keys by creating the pipe first.
- **Lifetime Enforcement**: The `keyroster agent` actively polls and expires keys, ensuring that the "short-lived" promise is kept even if the client is killed.

**Concerns**:
- **Medium**: The reliance on `go-winio` for named pipes introduces a dependency that must be strictly isolated from the signer's graph to maintain the security boundary.

**Suggestions**:
- In the `A3` probe, explicitly record if `gcr-ssh-agent` is present but not working, as this informs the "refuse-gcr" guidance in 02-12.

**Risk Assessment**: **LOW**. The design is robust and handles the Windows security model correctly.

---

### 02-03
**Summary**: This plan hardens the signer's boundary. It focuses on the refusal matrix (SC4), concurrency under race conditions, and protecting the signer from memory exhaustion via per-type frame caps.

**Strengths**:
- **Per-Type Caps**: Recognizing that a directory install requires more memory than a login request and applying specific limits prevents a "one-size-fits-all" limit from either being too restrictive or too permissive.
- **Concurrency Testing**: Using `go test -race` to prove that concurrent installs or logins don't lead to "lost updates" or duplicate certificates.
- **Fuzzing Strategy**: Applying fuzzing to every new parser (WebAuthn, Directory, KeyID) ensures that malformed input cannot crash the signer.

**Concerns**:
- **Low**: The `MaxDirectoryFrame` is quite large (~1MB). While acceptable for a self-hosted CA, it creates a larger memory footprint per connection during directory updates.

**Suggestions**:
- Ensure the `GetDirectory` response is also capped to prevent a compromised signer (or a bug) from attempting to send a gigabyte of data to the server.

**Risk Assessment**: **LOW**. The hardening is comprehensive.

---

### 02-04
**Summary**: This plan closes the loop on "Full Visibility." It ensures that every login certificate is not just issued, but is *provable* after the fact via the audit log.

**Strengths**:
- **Independent Verification**: The auditor does not trust the signer; it re-runs the `webauthn.VerifyAssertion` and `Authorize` logic using the logged evidence.
- **Root-Signed Policy Successors**: Providing a tool to add the RP to a running installation allows the system to evolve without a full reset.
- **Serial Sequence**: enforcing a strictly increasing serial sequence across both admin and login issuances prevents "gap" attacks.

**Concerns**:
- **Low**: The "interim refusal" from 02-01 must be replaced exactly. If the default branch in the audit walk is removed, any new leaf kind would be ignored.

**Suggestions**:
- Add a test case where a directory is installed, then a policy is changed, and the auditor must verify if the old directory is still authorized under the new policy.

**Risk Assessment**: **LOW**. The auditing logic is sound.

---

### 02-05
**Summary**: This plan implements the "evaluation-only" mode (KEY-06), allowing the system to run on encrypted software keys while loudly warning the user that it is not for production use.

**Strengths**:
- **Signer-Driven Custody**: The warning is driven by the `Status` report from the signer, ensuring that a server cannot "hide" the fact that software keys are in use.
- **Secure Passphrase Handling**: Using `defer clear()` on passphrase buffers and refusing permissive file modes (0644) reduces the risk of secret leakage.
- **All-or-Nothing Provisioning**: The use of `O_EXCL` and a cleanup routine for failed provisions prevents a partial state where some roles have keys and others don't.

**Concerns**:
- **Low**: `age` scrypt work factors are default. While acceptable for "evaluation," a production-grade software key would need a higher cost.

**Suggestions**:
- Explicitly test the `SIGHUP` reload for the TLS certificate in this plan to ensure the server doesn't crash during a rotation.

**Risk Assessment**: **LOW**. The security trade-offs for "evaluation mode" are well-documented and enforced.

---

### 02-06
**Summary**: This plan implements `keyroster-server` and `keyroster init`. The server acts as a "dumb" front-end that proposes requests to the signer and serves the web UI.

**Strengths**:
- **Strict CSP and Headers**: The implementation of a "deny-all" CSP and HSTS prevents a wide array of web attacks.
- **Pinned Trust**: `keyroster init` creates a hard link between the CLI and the server's TLS identity and trust bundle, preventing MITM attacks.
- **Fail-Closed Cache**: The 5-second status cache is a reasonable trade-off for performance, and the `dropStatus` hook ensures that administrative changes are seen immediately.

**Concerns**:
- **Medium**: The server's trust in the signer's `Status` report for the RP ID means a compromised signer can change the RP. However, this is mitigated by the fact that the *signer* is the ultimate authority on whether an assertion is valid.

**Suggestions**:
- The `SIGHUP` reload should log specifically which certificate was loaded (fingerprint) to aid in debugging rotation issues.

**Risk Assessment**: **LOW**. The security boundaries between the server and signer are well-maintained.

---

### 02-07
**Summary**: This plan implements the Admin API and the invite system, allowing admins to start the enrollment process for users.

**Strengths**:
- **Authenticated Payloads**: Using SSHSIG for the Admin API ensures that the server never handles admin private keys and that every request is provably authorized.
- **Non-Authoritative State**: The server DB is explicitly "non-authoritative." Pending users are just invitations; no access is granted until an admin signs a directory.
- **DoS Damping**: Per-IP and per-user rate limits prevent brute-forcing of invite tokens.

**Concerns**:
- **Low**: The `maxAdminBody` limit is a potential bottleneck for very large directory installs, but this is addressed by the `requireAdminLimit` override in 02-09.

**Suggestions**:
- Ensure the invite token is hashed in the DB (which is planned) to prevent a DB leak from allowing immediate user enrollment.

**Risk Assessment**: **LOW**. The "invite-then-bind" flow is secure.

---

### 02-08
**Summary**: This plan implements the passkey registration ceremony, allowing users to provide a public key that the admin can later approve.

**Strengths**:
- **Dependency Isolation**: Banning `go-webauthn` from the signer's graph ensures that the signer remains minimal and avoids the "bloat" of a full WebAuthn stack.
- **Differential Oracle**: Testing the internal verifier against a maintained library (go-webauthn) is a high-confidence way to ensure the signer's logic is correct.
- **Atomic Consumption**: Using `DELETE ... RETURNING` for sessions and invite consumption prevents race conditions in the registration flow.

**Concerns**:
- **Low**: The use of `residentKey: preferred` might lead to some users not having a resident key; the la-back plan for a "discovery" flow in v2 is appropriate.

**Suggestions**:
- Explicitly test a "duplicate registration" where a user tries to register the same key twice.

**Risk Assessment**: **LOW**. The isolation of the WebAuthn library is a critical and well-executed design choice.

---

### 02-09
**Summary**: This plan implements the "binding" process, where an admin approves a pending credential and installs a new directory version into the signer.

**Strengths**:
- **Pipeline Safety**: The `editDirectory` pipeline (Verify Base $\rightarrow$ Mutate $\rightarrow$ Validate $\rightarrow$ Diff $\rightarrow$ Sign) prevents the creation of invalid or unauthorized directories.
- **Quorum Support**: The proposal system (`--out`) naturally supports multi-admin approval without requiring a complex server-side state machine.
- **Pending Check**: The server's check that a bound credential must be "pending" prevents admins from accidentally binding a key that was previously discarded or re-invited.

**Concerns**:
- **Medium**: The "lost update" problem (two admins editing the same base) is handled by the signer's `directory_version_chain` refusal, but this requires the admin to re-run the command.

**Suggestions**:
- In the `Diff` output, clearly highlight which user's passkey is being bound to avoid approval errors.

**Risk Assessment**: **LOW**. The authority model is strictly followed.

---

### 02-10
**Summary**: This plan implements the web sign-in flow and the read-only account page.

**Strengths**:
- **Session Hardening**: Using `__Host-` cookies with `SameSite=Strict` and hashing IDs at rest follows modern security best practices.
- **Read-Only Surface**: The account page is strictly read-only, ensuring that the web UI cannot be used to elevate privileges.
- **Fail-Closed Access**: Checking the user's "active" status and credential binding on every request ensures that disables take effect almost immediately.

**Concerns**:
- **Low**: The 5-second status window is a small gap, but as the la-back plan notes, this is an accepted residual since the signer re-verifies everything at issuance.

**Suggestions**:
- Add a "Last Sign-in" timestamp to the account page (deferred to UI-02, but worth noting as a useful audit feature).

**Risk Assessment**: **LOW**. The session management is robust.

---

### 02-11
**Summary**: This plan implements the role and host-group mapping system and the renderer for the `AuthorizedPrincipalsFile`.

**Strengths**:
- **Principals Renderer**: By using a single shared renderer for both the CLI and the future agent, the system ensures that the "intended" access matches the "actual" access on the host.
- **One-Way Door**: The choice of `role:NAME` and `u:USER` prefixes prevents collisions and makes the certificates self-describing.
- **Header-Only Refusals**: Rendering a header-only file for unmapped accounts is a clean way to revoke access without deleting the file manually.

**Concerns**:
- **Low**: Manual host setup is error-prone. The runbook's "UNVERIFIED" labels correctly identify this as a risk.

**Suggestions**:
- Include a "check" command that compares a host's current principals file with what `keyroster host principals` would render.

**Risk Assessment**: **LOW**. The mapping logic is simple and correct.

---

### 02-12
**Summary**: This is the "MVP Moment." It implements the `keyroster login` command, the browser loopback flow with PKCE, and the agent integration.

**Strengths**:
- **PKCE and State**: The use of PKCE and state protects against authorization code injection and CSRF in the loopback flow.
- **Ephemeral Keys**: Generating a new key per login and zeroing it on exit prevents long-term key theft from the client machine.
- **Lifetime Constraint**: Adding keys to the agent with a `lifetime` ensures that certificates are automatically evicted, fulfilling a core requirement.

**Concerns**:
- **Medium**: The "loopback" depends on the browser allowing navigation to `127.0.0.1`. While common, some strict environments might block this. The CLI's fallback (printing the URL) is a necessary escape hatch.

**Suggestions**:
- In the loopback handler, ensure the `Host` header is checked strictly to prevent DNS rebinding attacks.

**Risk Assessment**: **LOW**. The flow is a standard, secure implementation of the OAuth-like "device flow" for local agents.

---

### 02-13
**Summary**: This plan is the "Dogfooding Part 1," moving the stack onto the homelab and enrolling the owner.

**Strengths**:
- **Safe Upgrade Path**: The use of `.pre-02-13` backups and a detailed rollback procedure prevents a botched upgrade from bricking the signer.
- **Sovereign RP**: The blocking-human checkpoint for the RP hostname prevents a one-way mistake in the root-signed policy.
- **Symmetry**: The owner enrolling "exactly like any user" proves that the system works without "magic" admin bypasses.

**Concerns**:
- **Low**: The use of TEST roots for the homelab is a known temporary state, but the bookkeeping for the owed v4 ceremony is correctly tracked.

**Suggestions**:
- Record the `systemd-analyze security` score for the server as a baseline for future hardening.

**Risk Assessment**: **LOW**. The deployment process is cautious and documented.

---

### 02-14
**Summary**: This is the "Dogfooding Part 2," performing real logins from Windows and Linux and recording the evidence.

**Strengths**:
- **Corroborated Evidence**: Matching the audit log (signer) and the sshd journal (host) provides high-confidence proof that the system works.
- **Honest Reporting**: Labeling unexercised platforms (macOS) as `UNVERIFIED` ensures the project doesn't overclaim its status.
- **Lived-in Requirements**: Completing AUTH-01, AUTH-02, AUTH-04, and UI-01 based on real-world success is the only valid way to close these requirements.

**Concerns**:
- **Low**: The requirement for the owner to manually copy a principals file is a temporary friction point until the agent is built.

**Suggestions**:
- Use the "expiry check" data to refine the ` la-back` la-back plan's lifetime check if any specific OS behavior is observed.

**Risk Assessment**: **LOW**. This is the final validation of the phase.

---

### Overall Risk Assessment: LOW

The implementation plan for Phase 2 is exceptionally structured. It follows a "tracer-first" approach, validates architectural assumptions through gating probes, and uses a robust "fail-closed" auditing and session model. The separation of the untrusted server from the network-less signer is strictly enforced. The most significant risk—the one-way nature of the RP hostname and principal format—is handled via blocking-human checkpoints. The project is on track to deliver a secure, verifiable, and simple SSH CA.
---

## Ollama gpt-oss:120b (per plan) Review

### 02-01

##### 02-01 – Signer‑login tracer plan

###### Summary
The plan adds the core pieces required for the Phase‑2 “passkey login MVP”: a RP entry in the root‑signed policy, a quorum‑signed *directory* document that binds users to WebAuthn credentials and role‑principal mappings, a std‑lib‑only WebAuthn assertion verifier, new wire message types for login and directory installation, and the corresponding signer logic (install, login, log‑state updates).  It also introduces the first log‑leaf kinds for a directory install (`KindDirectoryInstall`) and a login issue (`KindLoginIssue`), updates the audit‑verify walk to reject unknown leaf kinds, and supplies a full end‑to‑end e2e test that restarts the signer after a login.  The implementation is covered by extensive unit tests, golden‑vector checks, and fuzzers, and the new packages are kept out of the signer dependency graph by dep‑guard and caps‑lock updates.

Overall the plan is **well‑structured** and follows the “server‑proposes, signer‑disposes” rule that underpins the security model.  It brings the necessary authority into the signer (the directory and RP) while keeping the web UI and CLI as untrusted front‑ends.

---

###### Strengths
- **Clear authority boundaries** – All authorising data (policy RP, directory, WebAuthn assertion) is verified *inside* the signer (`internal/webauthn`, `internal/directory`, `internal/signer`).  The server merely forwards blobs.  This matches the documented threat model (see `D‑01`, `KEY‑02`).
- **Canonical JSON & strict validation** – `internal/trust/CanonicalJSON` and the new `directory.Parse/Validate/Sort` enforce a single byte representation, preventing “different string forms” attacks.  The plan adds golden‑vector tests (`directory_v1.json`, `leaf_directory_install_v1.hex`, …) to lock the format forever.
- **Minimal WebAuthn verifier** – The verifier is written with only `crypto/*` and `encoding/json` (no CBOR).  It parses `clientDataJSON` with a token‑decoder that rejects duplicate keys and invalid types, which is a known source of bugs (PITFALL 13).  The allowed algorithms (`ES256, EdDSA, RS256`) cover the major platform authenticators, and the signer refuses any other `alg`.
- **New wire protocol is additive** – Existing `IssueRequest` (`0x01`) is left untouched, and the new login request (`0x05`) and directory install (`0x02`) are added with distinct type bytes.  The existing decoder (`wire/frame.go`) already caps frames at 64 KiB; the plan notes that later waves will add per‑type caps, but the current size limit is sufficient for the expected payloads.
- **Log‑state correctness** – `logstate.go` now counts `KindLoginIssue` leaves together with `KindIssue` leaves, so the “log covers issuance table” check remains true after a login (addresses T‑02‑116).  The e2e test restarts the signer after a login and verifies that a second login succeeds, proving the continuity.
- **Audit‑verify safety** – The audit walk is made exhaustive: known Phase‑1 kinds have empty cases; any unknown kind (including the freshly added `directory_install` and `login_issue`) falls into a default branch that refuses the leaf with a clear message *“not verifiable by this version”*.  This prevents silent acceptance of future leaf kinds (T‑02‑115).
- **Dependency hygiene** – The new packages are added to the `signer‑no‑network` dep‑guard list, and a new `testonly‑firewall.sh` script ensures that test‑only helpers (`webauthntest`, `servertest`) are never linked into production binaries.  The script is wired into the existing `dependency‑firewall` CI job.
- **Coverage of edge‑cases** – The plan includes unit tests for:
  - RP validation (rejecting IP literals, ports, public‑suffix tailnet names);
  - Directory schema validation (duplicate credentials, unsorted lists, missing credentials);
  - WebAuthn assertion failures (missing UV, wrong RP ID, wrong challenge, bad origin);
  - Key‑ID parsing for the new `kr2` format;
  - Golden‑vector round‑trip tests for all new binary formats;
  - Fuzzing of `DecodeLeaf` with the new kinds to guarantee the decoder never panics.
- **Incremental rollout** – The plan deliberately makes the new leaf kinds *unverifiable* until the later `02‑04` plan adds proper checks.  This gives a safe “fail‑closed” window while the rest of the system can be exercised.

---

###### Concerns
| # | Area | Concern | Severity | Evidence / Reasoning |
|---|------|----------|----------|----------------------|
| C‑1 | RP validation implementation | The validation logic for `rp_id` and `origins` lives in `internal/trust/policy.go`.  The plan describes checks for lower‑case DNS labels, no IP, public‑suffix rules, and that each origin is exactly `https://<rp_id>` (or with a non‑443 port).  If the implementation only checks *format* but not *uniqueness* or *sorted order* of the `origins` slice, an attacker could supply duplicate origins that pass `json.Unmarshal` but break the signer’s constant‑time comparison. | **MEDIUM** | The plan calls for “sorted and duplicate‑free” but the actual code may have forgotten the duplicate‑free test (`sort.Slice` then `for i>0 { if origins[i]==origins[i-1] … }`).  A missing duplicate check would let a malicious admin create two identical origins, causing the signer’s `slices.Contains` lookup to be O(n) but still correct – however duplicate entries could be used to hide a malicious extra origin if later code changes to “first match wins”. |
| C‑2 | Directory signature verification | `internal/directory/verify.go` uses `trust.CountPinnedSigners` with the admin set from the *current* policy.  If the policy is updated (root‑signed successor) after a directory install, the signer will load the **new** policy and then verify the old directory against the new admin set.  The plan says “if quorum not met, the signer starts but refuses logins”.  However, the signer does **not** reject the directory installation itself; it merely sets `directoryAuthorized=false`.  This leaves the directory in the DB, which could be confusing to operators. | **MEDIUM** | The code path in `Signer.InstallDirectory` stores the directory before checking quorum; the flag `directoryAuthorized` is used later to reject logins.  Storing an unauthorized directory should be prevented or at least logged as a fatal error. |
| C‑3 | WebAuthn assertion parsing – clientDataJSON size limit | The `clientdata.go` parser caps the JSON to 2048 bytes, but some browsers (e.g., Chrome with a large `crossOrigin` field or a long `topOrigin`) can exceed that limit when extensions are present.  The plan treats any excess as `ErrClientData`, causing a login refusal.  This could be a denial‑of‑service vector for legitimate users. | **LOW** | The limit is not justified by the spec (clientDataJSON is typically <1 KiB).  A more robust approach would be to stream‑parse with a larger limit (e.g., 4 KiB) or reject only on malformed JSON rather than size. |
| C‑4 | AuthenticatorData length assumption | The verifier insists on *exactly* 37 bytes (`authData` = 32‑byte RP‑hash + 1‑byte flags + 4‑byte counter).  Some authenticators (e.g., Windows Hello) may set the `AT` (Attested Credential Data) flag for `packed` attestations, producing longer `authData`.  The plan acknowledges this (A6) and defers handling, but the current implementation would reject any real Windows authenticator used in production, breaking the MVP on a Windows client. | **HIGH** | The plan’s “soft authenticator” test only covers the minimal 37‑byte format; real hardware could cause immediate refusal.  Since the project aims to support Windows users (owner’s homelab includes a Windows PC), this is a critical blocker for the MVP. |
| C‑5 | PKCE / code handling in the login flow | The login flow uses PKCE (`code_challenge`, `code_verifier`) stored in the server DB with a 120 s TTL.  The plan does **not** specify how the server validates the *code verifier* against the *code* received on the loopback callback.  If the server mistakenly stores the raw verifier rather than the SHA‑256 of it, a replay attack could be possible. | **MEDIUM** | The code snippet in the plan (`LoginIssue` stores `code` and `code_challenge`) is vague.  A mismatch would lead to either false rejections or a missing security check. |
| C‑6 | Log‑leaf size for directory install | The `DirectoryInstallBody` encoder allows the full directory document (potentially >1 MiB) to be stored in a single leaf.  The signer’s `MaxFrame` is still 64 KiB, but the plan notes that per‑type caps will be added in later waves.  Right now a large directory could overflow the frame and cause the signer to drop the request or panic. | **LOW** | The current test vectors use a tiny directory; the production homelab may have many users and roles, exceeding 64 KiB.  The decoder `DecodeLeaf` will reject oversize frames, but the signer should return a clear refusal (`directory_too_large`). |
| C‑7 | Audit‑verify default handling of unknown leaf kinds | The default branch now refuses any leaf kind it does not recognise.  This is safe now, but future plans (e.g., adding a `KindHostAgentInstall`) must remember to add an explicit case, otherwise the log will become permanently unverifiable.  The lack of a “soft” mode may cause operational pain if a new leaf is introduced but not yet audited. | **MEDIUM** | The code in `internal/audit/verify.go` uses a `default` that returns an error.  A future change that forgets to update this switch will break verification of existing logs. |
| C‑8 | Credential ID canonicalisation – base64 URL padding | The `Validate` step decodes credential IDs with `base64.RawURLEncoding.Strict()`.  The plan adds a test for “non‑canonical” IDs that have extra padding bits, but the error message `credential_id_noncanonical_refused` is only exercised in a unit test.  It is not clear whether the signer returns a distinct refusal detail (`ReasonMalformed`) that is audited. | **LOW** | If the refusal detail is not mapped in `classify` to a named reason, audit logs would have a generic “unauthorised” entry, making incident response harder. |
| C‑9 | Directory migration test (`upgrade_from_v3`) | The test creates a Phase‑1 DB with `user_version=3` and then opens it with the new schema.  However, the migration code (`internal/signerdb/migrate.go`) may apply *all* migrations up to the latest version, which could unintentionally modify existing Phase‑1 tables (e.g., adding the new `directory` table with a default row).  The test only checks that the directory table exists and is empty, but does not verify that no data was corrupted. | **LOW** | The migration script should be verified with a dump of the original tables to ensure they remain unchanged. |
| C‑10 | Error handling for missing directory | When the directory has not been installed, `Signer.LoginIssue` returns a refusal with a generic “directory_not_installed”.  The audit log will contain a `ReasonUnavailable`.  If the server is restarted without a directory, every login will be refused, but the signer will still start.  Operators may not notice the missing directory because the signer logs only at `Info` level. | **LOW** | The plan could add a `Start`‑time fatal log (or a `doctor` status flag) that signals “directory missing – logins disabled”. |

---

###### Suggestions
1. **Make RP validation exhaustive** – After sorting the `Origins` slice, explicitly check for duplicates (`if origins[i]==origins[i-1] { return fmt.Errorf("duplicate origin") }`).  Add a unit test in `policy_test.go` for duplicate origins.
2. **Reject unauthorised directory installs** – In `Signer.InstallDirectory`, verify quorum *before* persisting the directory.  If quorum fails, return a refusal *without* inserting the row, and log a `directory_quorum_not_met` fatal error.
3. **Relax `authenticatorData` length check** – Accept `authData` length ≥ 37 bytes and verify that the high‑order bits (AT, ED) are **clear** when the signer does not support extensions.  This will allow Windows Hello (which may set the AT flag) to be accepted without breaking the security model, because the signer still ignores extensions.  Add a test case with a mocked Windows credential that sets AT but leaves the rest unchanged.
4. **Explicit PKCE verification** – Store `code_challenge = base64url(SHA256(verifier))` and, on loopback callback, recompute the SHA‑256 of the received verifier and compare constant‑time.  Return a distinct refusal `pkce_verifier_mismatch`.  Add a unit test covering a mismatch.
5. **Add per‑type frame caps now** – Even if a later wave will refine caps, set a safe cap for `InstallDirectory` (e.g., 1 MiB) and for `LoginIssue` (e.g., 128 KiB) in the current `wire/frame.go`.  Return `directory_too_large` or `login_request_too_large` refusals if exceeded.  This prevents accidental panic on large directories.
6. **Document audit‑verify default behaviour** – In `docs/security/audit.md` (or similar), note that any future leaf kind will be *rejected* until a verifier is added.  Provide a checklist for developers when adding a new leaf kind.
7. **Map all new refusal details in `classify`** – Ensure that every new reason (`directory_invalid`, `directory_quorum_not_met`, `credential_id_noncanonical`, `pkce_verifier_mismatch`, `authenticator_data_invalid`, etc.) has a corresponding `Reason*` constant and that `classify` returns a human‑readable name.  Add a table-driven test in `refusal_test.go` that checks the mapping.
8. **Add integration test for duplicate origins** – Build a policy with two identical origins, sign it, and verify that the signer refuses the policy at load time (`policy_invalid`).  This will catch any missing duplicate‑origin check.
9. **Extend the migration test** – Dump the Phase‑1 tables’ contents before migration, run the migration, then query them again and compare (using `reflect.DeepEqual`).  This guarantees no accidental data loss.
10. **Improve start‑up visibility** – When the signer starts without an authorised directory, have `doctor.Status` report `directory_missing=true` and display a loud banner on the web UI (`UI‑01`), mirroring the software‑key warning (`KEY‑06`).  This makes operators aware that logins are disabled.

---

###### Risk Assessment
**Overall risk: MEDIUM‑HIGH**

*Why MEDIUM‑HIGH?*

- The **core security transformation** (moving authority into the signer) is correctly implemented, which dominates the risk profile positively.
- However, the **WebAuthn authenticator data length restriction** (C‑4) is a *blocking* issue for Windows machines, which are part of the target audience (owner’s homelab includes Windows 9.5p2).  If unaddressed, the MVP cannot be demonstrated on a key platform, constituting a **high functional risk**.
- The **directory‑install quorum handling** (C‑2) could lead to an inconsistent state where an unauthorised directory is persisted, possibly confusing operators and causing silent denial‑of‑service.
- The **audit‑verify default rejection** (C‑7) is safe now but could become a maintenance liability if future leaf kinds are added without updating the switch, a **medium‑term operational risk**.
- All other concerns are low‑to‑medium and have mitigations either already in the plan (fuzzing, golden vectors) or easily added (duplicate‑check, PKCE validation).

If the Windows authenticator‑data issue is resolved (e.g., by allowing AT flag and longer authData) and the directory‑install quorum check is tightened, the risk drops to **MEDIUM**. Until then the remaining high‑severity blocker keeps the overall rating at **MEDIUM‑HIGH**.
### 02-02

##### 02-02 – Windows‑Agent & Cross‑Platform CI Plan  

###### Summary
The plan introduces a **dedicated in‑memory SSH agent for Windows** (served over a per‑user named pipe) to satisfy the requirement that `ssh‑add -t …` must succeed and that the private key expires with the certificate. It also adds **gating probes** that verify the inbox OpenSSH client can talk to the pipe (A2) and that the GNOME gcr‑agent respects lifetime constraints on Linux (A3).  The plan updates the CLI’s `dialAgent` abstraction, adds Windows‑only source files, ships a new `keyroster agent` command, introduces Windows‑only tests, and extends the GitHub Actions workflow with Windows and macOS jobs and a documentation update.

Overall the design follows the project’s “signer‑only authority” rule, keeps the new dependency (`github.com/Microsoft/go‑winio`) out of the signer graph, and documents the security‑relevant behaviour (per‑SID pipe, owner‑verification, no fallback to the inbox agent). The plan is **well‑structured** and clearly separates probing, implementation, CI, and merge steps.

---

###### Strengths  

| What | Why it’s good (with code reference) |
|------|--------------------------------------|
| **Minimal attack surface** – the agent lives only in the `keyroster` binary, never falls back to the built‑in OpenSSH agent. <br> `cmd/keyroster/agent_windows.go` (new command) and the explicit “never retry without lifetime” rule in the plan guarantee that no key is ever handed to the inbox agent. |
| **Per‑user pipe isolation** – `internal/winagent/pipepath.go` builds the pipe name as `\\.\pipe\keyroster-agent-<SID>` and `SDDL(sid)` restricts access to the user SID only (`D:P(D;;GA;;;NU)(A;;GA;;;<sid>)`). This satisfies the **trust‑boundary** “other local users → keyroster agent pipe”. |
| **Owner verification** – `internal/winagent/owner_windows.go` implements `VerifyServerOwner` that checks the server process token SID against the caller’s SID, returning `ErrOwnerUnverifiable` for mismatches or access‑denied errors. This protects against a malicious elevated process hijacking the pipe. |
| **Graceful shutdown logic** – `Serve` polls the keyring (`Options.Poll`) and exits only when **no keys are present** *and* **no active client connections** exist (protected by a single mutex). Tests `exit_waits_for_open_connection` and `add_races_expiry_exit` verify the race‑free exit path. |
| **Robust gating probes** – Task 1’s A2/A3 probes are run **before any production code is added**, ensuring that the Windows‑specific path is viable and that the Linux gcr‑agent behaviour is known. The plan forces a **human checkpoint** if the probe fails, avoiding silent fallback. |
| **CI coverage** – The workflow adds `cli‑windows` and `cli‑macos` jobs, builds the binary for all three OSes, runs the new Windows tests (`TestInboxSSHOffersAgentCert`) and the Unix‑agent lifetime test, and verifies that the new dependency stays inside the Windows build (`go list -deps … | grep go‑winio`). |
| **Documentation & platform‑verification** – `docs/security/needs-hardware.md` is extended with a “Platform verification (D‑16)” section that records the exact outcome of the probes, making the security posture auditable. |
| **Dependency hygiene** – `go-winio` is added *only* to the Windows build tags; the plan re‑runs `scripts/dep‑firewall.sh` and `scripts/capslock-check.sh` to certify that the signer graph is unchanged. |
| **Clear owner control** – The RP‑ID hostname (D‑09) and the software‑key banner (D‑18) are both locked elsewhere; the plan only touches the agent, so no policy‑schema changes are introduced. |

---

###### Concerns  

| Severity | Issue | Impact & Evidence |
|----------|-------|-------------------|
| **HIGH** | **Race between simultaneous `keyroster login` invocations** – two CLI instances could start `keyroster agent` at the same time, both attempt `ListenPipe`. The current `Serve` returns an error on the second `ListenPipe` (pipe already exists) but `Ensure` does not have a back‑off or retry limit; it may spin and eventually return `ErrOwnerUnverifiable` or “pipe already in use”. This could cause a user to see intermittent “cannot add key” failures. <br> *Evidence:* `internal/winagent/winagent_windows.go` – `ListenPipe` is called once; no retry logic is mentioned. |
| **MEDIUM** | **Owner‑verification edge cases** – on Windows 10+ the inbox client may run with **different integrity levels** (e.g., a normal user launching a *runas* elevated agent). `VerifyServerOwner` maps `ERROR_ACCESS_DENIED` to `ErrOwnerUnverifiable` with the message “started elevated”. However, the test `owner_access_denied_names_elevation` only checks that the error text contains “elevated”; a real user may not notice the guidance and keep the elevated agent running, causing the CLI to fail repeatedly. <br> *Evidence:* `owner_windows.go` error handling described in the plan, but UI guidance is only in the command‑help text. |
| **MEDIUM** | **Leak of pipe name / SID in logs** – `keyroster agent` prints the pipe path and the “IdentityAgent …” line to stdout. If the CLI is used in a script that logs stdout to a file, the pipe name (which contains the SID) may be exposed, leaking a **stable identifier** that could be targeted for pipe‑squatting attacks. The plan does not mention redaction or a `--quiet` flag. |
| **MEDIUM** | **Windows test reliability** – `TestInboxSSHOffersAgentCert` relies on the *real* `ssh‑add.exe` and `ssh.exe` being present on the runner. If the Windows runner image changes (e.g., removes the inbox OpenSSH client) the test will be skipped, and the plan’s `KEYROSTER_REQUIRE_INBOX_SSH=1` will abort the CI, potentially breaking the pipeline unrelated to the code. No fallback is provided. |
| **LOW** | **Documentation drift** – The help text for `keyroster agent` mentions the pipe spelling discovered by the probe. If the probe later reports a different spelling (unlikely, but possible if the OS changes path syntax), the help text would become stale unless the binary is rebuilt (it will be, but the documentation in the repo may need a manual update). |
| **LOW** | **Dependency on `go‑winio` version** – The plan pins `v0.6.2` but does not lock the go.mod `go` version to `1.27`. If `go‑winio` later requires a newer go version, the CI could fail for the Windows build while the Linux/macOS builds succeed. |
| **LOW** | **Missing test for pipe cleanup on crash** – If the agent process crashes, the named pipe may remain in the OS kernel until the handle is reclaimed. Subsequent `Ensure` calls could fail with “pipe already exists”. No test simulates a crash and subsequent recovery. |

---

###### Suggestions  

| Recommendation | Rationale & Suggested Implementation |
|----------------|------------------------------------|
| **Add exponential back‑off & retry limit in `Ensure`** – When `ListenPipe` fails because the pipe already exists, retry with a short back‑off (e.g., 100 ms, 200 ms, 400 ms) up to 5 attempts before giving a clear error. | Prevents flaky failures when two CLI instances start simultaneously; aligns with the “no silent fallback” principle. |
| **Expose a `--quiet` or `--pipe‑name` flag** – Allow the user (or CI) to suppress the pipe path output or to request a custom pipe name (for debugging). | Reduces the risk of leaking the SID in logs and gives power users a deterministic name if needed. |
| **Improve error messages for elevated agents** – In `owner_windows.go`, when mapping `ERROR_ACCESS_DENIED` to `ErrOwnerUnverifiable`, add a suggestion to *restart the agent from a non‑elevated shell* and possibly expose the offending SID for debugging. | Makes the guidance visible even in non‑interactive environments (e.g., CI logs). |
| **Add a “pipe‑cleanup” test** – Simulate a panic in the agent’s Serve routine (using `defer recover` or a test that kills the process), then call `Ensure` again to verify that a new pipe can be created. | Ensures robustness against orphaned pipe resources. |
| **Document the exact pipe spelling in the repo** – Write the pipe syntax (`\\.\pipe\keyroster-agent-<SID>`) in `docs/architecture/windows-agent.md` and reference it from the help text. | Guarantees that the documentation stays in sync with the implementation, even if the probe ever changes. |
| **Pin the Go version in go.mod** – Add `go 1.27` (or the version used for the rest of the repo) to avoid accidental upgrades that break `go‑winio`. | Keeps the Windows build reproducible. |
| **Add a fallback check in CI** – In the Windows job, detect the absence of `ssh.exe` before setting `KEYROSTER_REQUIRE_INBOX_SSH=1`. If missing, emit a warning and skip the test rather than aborting the whole workflow. | Reduces brittleness of the CI pipeline. |
| **Consider a small “owner‑only” test wrapper** – Export a minimal test‑only function `ValidatePipeOwner(path string) error` that can be used by external callers (e.g., the login code) to double‑check the pipe before sending a key, without exposing the full internal verifier. | Provides an extra safety net without adding a production seam. |
| **Audit the lifetime‑polling interval** – The default `Poll: 5 s` may delay key removal on a fast‑expiring certificate (e.g., 10 s). Offer a `--poll‑interval` flag or reduce default to 2 s, and document the trade‑off. | Improves the user experience for short‑lived certificates while still keeping CPU usage low. |

---

###### Risk Assessment  

| Level | Justification |
|-------|---------------|
| **MEDIUM** | The plan introduces a **new Windows‑only component** that handles private keys and interacts with the system‑provided OpenSSH client. The design mitigates the principal threats (pipe ownership, lifetime enforcement, fallback avoidance) with explicit verification and comprehensive tests. However, **race conditions** when multiple CLI instances start the agent and **edge‑case failures** (elevated token, orphaned pipe) remain partially unaddressed, and the CI pipeline can be fragile if the inbox OpenSSH client is absent. These open points raise the risk from *low* (given the overall small attack surface) to *medium* until the suggested mitigations are added. |

--- 

**Bottom line:** the plan is **well‑aligned with the Phase 2 goals** and the project’s security‑first, simplicity‑first philosophy. Implementing the suggested back‑off, improving error guidance, and adding the extra cleanup test will bring the remaining medium‑risk items down to low, yielding a solid, auditable Windows agent implementation.
### 02-03

##### 02-03 – Signer Boundary

###### Summary
The plan expands the signer’s public API and hardens its request handling. It introduces a new **GetDirectory** request/response, a dedicated **LoginIssueRequest** type, per‑message‑type frame caps, a full refusal‑matrix for login issuance, concurrency and restart guarantees, and fuzz targets for every new parser. The intended outcome is that **KEY‑02** (“the signer only issues when the request carries evidence it verifies itself”) is provably enforced, and that the server can mirror the exact directory held by the signer. The work is well‑scoped, follows the “server proposes, signer disposes” invariant, and is covered by end‑to‑end e2e tests, unit tests, and fuzzing.

---

###### Strengths

| Area | Why it’s strong (with file evidence) |
|------|--------------------------------------|
| **API extension** | *GetDirectory* is added as `wire.TypeGetDirectory` (`internal/wire/frame.go`) and handled in `signer/server.go` (dispatch switch). The response struct (`GetDirectoryResponse`) includes version, directory bytes, signatures, and an *authorized* flag – exactly what the server needs to mirror the signer state (see `internal/wire/directory.go`). |
| **Separate login message** | A new domain tag `keyroster/login-request/v1` and wire type `LoginIssueRequest` (`internal/wire/frame.go` + `internal/wire/login.go`) keep the existing admin `IssueRequest` untouched, preserving the audit‑log format and avoiding policy‑breakage. |
| **Refusal matrix** | Test suite `test/e2e/login_refusal_test.go` defines six sub‑tests, each asserting a concrete `*wire.ErrorResponse` detail (e.g., `missing_evidence`, `duplicate_request`, `challenge_mismatch`, `directory_not_installed`, `no_webauthn_policy`, `unknown_evidence_type`). The same code path is exercised through the real Unix socket, guaranteeing the signer’s boundary checks run in production. |
| **Directory signing & quorum** | `internal/directory` implements canonical JSON, version chaining, and quorum verification (`trust.CountPinnedSigners`). The signer’s `InstallDirectory` handler checks `admin_quorum` against the root‑signed policy, rejecting with `directory_quorum_not_met`. The restart logic (`signer.New` → `logstate` → `loadDirectory`) verifies that the stored directory matches the last `directory_install` leaf, preventing silent DB tampering (see `internal/signer/logstate.go`). |
| **Concurrency guarantees** | Tests in `internal/signer/login_test.go` spin up 16 goroutines sending identical `LoginIssueRequest` bytes and verify a single certificate, 15 `duplicate_request` refusals. Similar concurrent install tests are in `directory_test.go`. The signer serialises state under `s.mu`, and the `RequestID` uniqueness check is performed inside the same transaction, satisfying the race‑detector (`go test -race`). |
| **Per‑type frame caps** | `wire.MaxDirectory = 1 << 20` and `wire.MaxDirectoryFrame = MaxDirectory + 64<<10 + 64` are introduced, with a private helper `maxBodyFor(msgType)` that returns the appropriate body limit (issue/login → `MaxFrame‑2`, directory → `MaxDirectoryFrame‑2`). `ReadMessage` validates `n` ≥ 2, returns `ErrShortFrame` for a length‑1 frame **before** any allocation, and refuses oversized frames with `ErrFrameTooLarge`. Corresponding write‑side checks (`WriteMessage`) are added. |
| **Fuzz coverage** | New fuzz targets (`FuzzParseLoginIssueRequest`, `FuzzParseWebAuthnAssertion`, `FuzzParseInstallDirectory`, `FuzzParseGetDirectoryResponse`, `FuzzReadMessage`, plus verifier targets in `internal/webauthn`) ensure every new parser is exercised with malformed inputs. The plan also adds seeds for extra‑member client‑data JSON (`client_data_extra_members_accepted`). |
| **Leaf‑level audit** | Refusal leaves now carry the request digest (`login_refusal_leaf_carries_digest` in `internal/signer/login_test.go`) and directory SHA‑256 (`install_refusal_leaf_carries_digest` in `directory_test.go`). This aligns with the log‑integrity guarantees required for full visibility. |
| **Policy‑RP binding** | The signer refuses login when the policy has no `WebAuthn` section (`no_webauthn_policy`). A dedicated e2e sub‑test validates that an RP‑less policy blocks issuance, and a policy successor that adds the RP (signed by the same root) restores login. |
| **Documentation & CI** | The plan specifies exact CI steps (e2e, race, fuzz, lint, capslock, dep‑firewall). The required `02-03‑SUMMARY.md` will capture PR number, refusal‑to‑class table, fuzz list, and memory bound, providing traceability. |

---

###### Concerns

| # | Concern | Severity | Explanation & Evidence |
|---|----------|----------|------------------------|
| 1 | **GetDirectory response validation** – the spec requires that a version‑0 response must have *exactly* `Directory == nil`, `Sigs == nil`, and `Authorized == false`. The current `ParseGetDirectoryResponse` must reject any non‑empty fields for version 0, otherwise an attacker could force the server to believe a directory is present when none is installed. The plan mentions “refused” but concrete test coverage (`TestParseGetDirectoryResponse`) is only sketched. **Risk:** a malformed version‑0 response could be interpreted as a legitimate empty directory, weakening the “directory not installed” guarantee. |
| 2 | **Directory‑install leaf consistency** – `loadDirectory` checks that the stored directory bytes equal the last `directory_install` leaf. However, the code path that writes the leaf (`logstate.appendLeaf`) must include the directory **and** the signatures. If a future change adds extra metadata to the leaf (e.g., a new field) without updating the consistency check, the signer could start with a mismatched state. The plan does not explicitly lock the leaf format version. **Risk:** silent divergence between DB and log on later schema changes. |
| 3 | **Per‑type frame caps – magic numbers** – `MaxDirectoryFrame = MaxDirectory + 64<<10 + 64` is derived from “64 KiB + 64 bytes” overhead. This is correct for the current frame header (2 bytes) plus a 4‑byte length field, but if any future wire type adds extra framing (e.g., a future status message with a version field), the cap will be off by a few bytes, potentially causing a denial‑of‑service or allowing an allocation bigger than intended. **Risk:** future‑proofness of caps is fragile. |
| 4 | **PKCE & state handling in login flow** – the plan’s login‑refusal suite creates a “code” and “code_verifier”, but the implementation details of the PKCE verification (`SHA256(code_verifier) == code_challenge`) are not explicitly verified in the test code. If the server mistakenly checks the *raw* verifier rather than the hash, an attacker could replay a captured code. **Risk:** subtle PKCE bug could undermine phishing resistance. |
| 5 | **WebAuthn algorithm set** – the signer verifier (`internal/webauthn/verify.go`) accepts ES256, EdDSA, and RS256. Windows Hello may also produce `PS256` signatures in some configurations. The plan explicitly *refuses* other algorithms, which is correct for security but may cause legitimate Windows clients to be denied without a clear error path. The test suite only covers the three algorithms; there is no negative‑algorithm test confirming the refusal detail is meaningful. **Risk:** user‑experience regression on Windows, potential support tickets. |
| 6 | **Error‑detail consistency** – many refusal cases share the same sentinel (`ReasonUnauthorized`) but have different *Detail* strings (e.g., `user_verification_missing`, `origin_mismatch`). The plan does not verify that the *Detail* string is stable across releases (e.g., no renaming). If a future refactor changes a constant name, previously stored log leaves will no longer parse correctly. **Risk:** log‑verification tooling may break. |
| 7 | **Directory quorum enforcement when admin set changes** – after a policy successor changes the admin set, the signer logs `directory_not_authorized` but still allows **admin** issue requests (which use SSHSIG). This is intentional, but there is no explicit test that an **admin** request still works when the directory is unauthorized. If the admin verification path mistakenly re‑uses the same directory‑validation routine as the login path, login‑only refusal could mistakenly block admin operations. **Risk:** accidental admin lock‑out. |
| 8 | **Replay protection window** – the signer allows a `CreatedAt` skew of ±300 s. The login refusal test does not explore the edge of this window (e.g., a request created 301 s in the past). While the policy already defines a `maxClockSkew`, an attacker with a compromised server could replay an old request within the window. The plan does not include a dedicated test for the boundary condition. **Risk:** subtle replay could slip through if clocks drift. |
| 9 | **Failure mode when the signer cannot read the directory snapshot** – if the SQLite DB is corrupted such that the directory row cannot be unmarshaled, `loadDirectory` returns an error and the signer aborts start‑up. The plan does not specify a graceful degradation (e.g., start in “read‑only” mode and refuse all logins). This could cause a DoS if the DB is corrupted by a non‑malicious power failure. **Risk:** availability. |
| 10 | **Testing of the *GetDirectory* round‑trip** – the plan adds `TestParseGetDirectoryResponse` but does not include a full integration test that the **server** actually returns the expected response over the real socket (`signerclient.GetDirectory`). Without that, the server‑client contract could diverge (e.g., mismatched TLV ordering). **Risk:** hidden bug in the client stub. |

---

###### Suggestions

| # | Recommendation |
|---|----------------|
| 1 | **Add explicit unit tests** for `ParseGetDirectoryResponse` covering all illegal version‑0 payloads (`Directory != nil`, `Sigs != nil`, `Authorized == true`). Use a table‑driven test that asserts the exact error (`ErrInvalidGetDirectory`). |
| 2 | **Freeze the leaf format** for `directory_install` by adding a version byte to the leaf payload (e.g., `leafVersion = 0x01`). Update `logstate.appendLeaf` and the verification code to reject mismatched versions. This makes future schema changes safe. |
| 3 | **Wrap per‑type caps** behind a small utility (`frameCap(msgType)`) that derives the cap from a map. Add a comment warning that any new wire type must also add an entry, and consider a compile‑time check (`go:generate` generating a list of expected caps). |
| 4 | **PKCE verification test** – create a dedicated test that sends an invalid `code_verifier` (wrong hash) and asserts `invalid_code` refusal. Include a comment explaining the exact hash flow. |
| 5 | **Reject unsupported algorithms with a clear detail** – create a test case that feeds a PS256 signature and expects `unsupported_algorithm`. Document the error string so it can be part of the refusal‑matrix table. |
| 6 | **Stabilise error‑detail constants** – define all refusal details as `const` strings in a single `internal/signer/refusal.go` file, and expose them via `refusal.Detail*`. Add a test that marshals a leaf, unmarshals it, and asserts the detail round‑trips unchanged. |
| 7 | **Admin‑path sanity test** – add a unit test that installs a directory signed by the old admin set, installs a successor policy with a *different* admin set, and then issues an *admin* `IssueRequest` (admin‑sshsig). Verify it succeeds while a login request fails with `directory_not_authorized`. |
| 8 | **Clock‑skew edge test** – generate a login request with `CreatedAt = now - 301s` and assert `request_time_skew` refusal. This validates the boundary of the skew window. |
| 9 | **Graceful degradation on DB corruption** – modify `signer.New` to detect directory load failure and start in a “locked” mode where all login requests are refused with a distinct `signer_unavailable` detail, while admin requests still work. Add a test that injects a corrupted directory row and expects the signer to start without panic. |
|10| **End‑to‑end GetDirectory test** – add a test that the server (started via `signer.New` + `signer.Start`) receives a `GetDirectory` request from `signerclient.GetDirectory` and returns the exact bytes that were installed. Verify the `Authorized` flag matches the live directory’s quorum status. |

---

###### Risk Assessment

| Level | Rationale |
|-------|-----------|
| **MEDIUM** | The plan substantially raises the signer’s security posture: all login paths are now verified against verifiable evidence, policy‑bound RP IDs, and quorum‑signed directories. The refusal matrix and concurrency guarantees are well covered. However, the concerns above—especially around GetDirectory parsing, future‑proofing of frame caps, PKCE verification, and graceful degradation on DB corruption—represent realistic attack or availability surfaces that are not yet fully covered by tests. Once the suggested mitigations are added, the risk can be lowered to **LOW**. |

---

###### Closing Remarks

Overall, the 02‑03 plan is thorough, respects the “server proposes, signer disposes” principle, and delivers the required **KEY‑02** guarantees. The added API (`GetDirectory`), the distinct login request type, and the per‑type frame caps are solid design choices that keep the binary’s attack surface small and clearly bounded. Addressing the enumerated concerns (especially the explicit GetDirectory validation, robust leaf versioning, and graceful‑degradation handling) will close the remaining medium‑risk gaps and make the signer boundary truly production‑ready.
### 02-04

##### 02-04 – Phase 2 Passkey‑Login MVP – “Audit login certificates & RP‑successor tool”

###### Summary
Plan 02‑04 adds the **`keyroster root successor‑policy`** command for inserting a WebAuthn RP into an already‑deployed policy, extends the **audit verifier** to prove that every `login_issue` leaf is cryptographically bound to a user‑owned passkey and that a `directory_install` leaf is quorum‑signed under the current policy, and introduces a comprehensive tamper‑suite, documentation, and CI checks. The work is well‑aligned with the phase’s success criteria (full visibility, proof of passkey‑based issuance) and respects the project’s security‑first, simplicity, and “no new attack surface” constraints.

###### Strengths
| Area | Positive aspects (with concrete code references) |
|------|-------------------------------------------------|
| **Policy‑successor tooling** | *`cmd/keyroster/root.go`* is extended with a new switch case (`successor‑policy`) that **(a)** parses `--prev` with `trust.ParsePolicy` (ensuring canonical JSON), **(b)** copies the policy, increments `Version`, sets `Prev` to `SHA256(prev)`, and **(c)** validates the RP (`rp_id` must be a DNS hostname, no IP, not a public‑suffix tailnet) before writing the result (`--out` must not exist). The warning about RP being “one‑way” is printed to `stderr`. This satisfies the checkpoint that the RP cannot be changed without re‑enrollment (see D‑09). |
| **Audit‑verify extensions** | *`internal/audit/verify.go`* now contains explicit `case tlog.KindDirectoryInstall` and `case tlog.KindLoginIssue` branches that call `verifyDirectoryInstall` and `verifyLoginIssue`. The default case remains but is marked **UNVERIFIED** and documented as a guard for future leaf kinds, preserving the fail‑closed posture. |
| **Verification logic** | `verifyDirectoryInstall` (new) parses the `DirectoryInstallBody`, checks the successor link (`Prev` hash), validates quorum signatures against the policy in force, and ensures the policy version matches the loaded policy. `verifyLoginIssue` (new) re‑parses the login request bytes (`wire.ParseLoginIssueSigningBytes`), checks that the `DirectoryVersion`/`PolicyVersion` match the current in‑memory objects, validates the WebAuthn assertion via `internal/webauthn.VerifyAssertion`, recomputes the principal set from the installed directory, enforces TTL caps, and confirms the certificate fields (KeyID format `kr2`, matching `SubjectKey`, principals, validity). All checks return errors of the form `entry <idx> (login_issue): <check>` matching the required audit output. |
| **Serial ordering across issue types** | The walk now tracks a **single serial counter** that is incremented for both `KindIssue` (admin issuance) and `KindLoginIssue`. The new variable `loginSeen` ensures that a login leaf must have a serial greater than any prior leaf (including other login leaves). The tamper tests `login_serial_not_above_issue` and `issue_serial_not_above_login` exercise this rule. |
| **Tamper‑suite & regression testing** | `internal/audit/verify_test.go` is updated with the converted “unproven‑refused” cases (`directory_install_unproven_refused`, `login_issue_unproven_refused`) that still hit the default refusal path, confirming that the interim refusal is *replaced* by real checks. New tests (`TestAuditLoginAcrossPolicyChange`, `login_directory_survives_rp_policy_change`, and a full set of tamper sub‑tests) guarantee coverage of every new verification branch. |
| **Documentation & runbook** | `docs/runbooks/root-ceremony.md` receives a new “Change the policy: successor policy (for example, add the WebAuthn RP)” section that lists the exact CLI steps, the one‑way warning, and a compatibility note about older audit‑verify binaries. This satisfies the required operator guidance and mitigates the “policy change can’t be undone” risk. |
| **CI / gating** | The plan adds the new files to the CI matrix (`scripts/linux.sh … go test -tags e2e …`). The merge‑gate task (`Task 3`) enforces owner approval before squashing. This respects the repository’s protected‑branch workflow. |
| **Dependency hygiene** | The new `internal/webauthn` package uses only the stdlib (`crypto/sha256`, `crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`, `encoding/json` token parsing). It is excluded from the signer’s dependency firewall (the firewall is invoked in the CI). The server‑only `go‑webauthn` remains unchanged, staying outside the signer graph. This preserves the “signer‑only” attack surface. |

###### Concerns
| Severity | Issue & Impact | Evidence / Reasoning |
|----------|----------------|----------------------|
| **HIGH** | **Incorrect RP validation could allow an attacker to set an IP address or a public‑suffix tailnet name**. The plan checks that `rp_id` is a DNS hostname and not an IP (via `net.ParseIP == nil`) and rejects public‑suffixes (by checking `publicsuffix.EffectiveTLDPlusOne`). However the concrete implementation of the public‑suffix check is not described. If omitted, an operator could accidentally set `rp_id = <tailnet>.ts.net`, which would make every credential usable on any machine in that tailnet, violating the “one‑way” guarantee. | Ensure `internal/trust/policy.go` (or the new successor‑policy code) imports `golang.org/x/net/publicsuffix` and validates `!publicsuffix.IsPublicSuffix(rpID)`. Add a unit test for rejection of a public‑suffix RP. |
| **HIGH** | **`verifyLoginIssue` must re‑verify the *directory* signature against the *policy* *for every login leaf*.** The plan caches the verification result after a `directory_install` or a `bundle_install` to avoid O(N²) work. However the cache key is only `(directoryVersion, policyVersion)`. If a policy change invalidates a previously‑installed directory (e.g., tightening admin quorum), the cache could incorrectly reuse an old “valid” result. The walk must invalidate the cache when the *policy* changes **even if the directory version stays the same**. | The plan states “the walk keeps one cached result for the current (directory, policy) pair… re‑checked after each bundle_install entry”. Verify that `verify.go` actually resets the cache on any `bundle_install` (policy change) regardless of directory version. Add a test where a directory is installed under a policy with quorum = 1, then the policy is rotated to quorum = 2 (no directory change). A subsequent login under that directory should be rejected because the directory is no longer authorized. |
| **MEDIUM** | **Serial ordering across login and admin issue leaves may still be broken if the signer’s start‑up check only counts `KindIssue`.** The audit verifier now enforces a combined monotonically‑increasing serial, but the signer’s start‑up check (`T‑02‑116`) still only looks at `KindIssue`. A compromised signer could therefore emit a log where a login leaf has a lower serial than a preceding admin issue leaf, and the audit verifier would reject it, but an operator might not notice the discrepancy until audit time. The mismatch is harmless for security (audit will catch it) but could cause confusion in operations. | Consider extending the signer’s start‑up check (or at least the verification message) to include `KindLoginIssue`. Document the new invariant in `docs/runbooks/signer‑install.md`. |
| **MEDIUM** | **`keyroster root successor‑policy` does not enforce that *only* the RP fields are changed.** The plan says “policy fields other than RP are not editable here”, but the code copies the entire policy struct and then overwrites `WebAuthn`. If the input file (`--prev`) is itself already mutated (e.g., an operator manually edits it before running the command), the command would blindly copy those mutations. There is a risk of accidental policy drift. | Add a sanity check after parsing the *previous* policy: compare all fields except `WebAuthn` to the *current* in‑force policy (loaded from the bundle directory). If any differ, abort with a clear error: “policy fields other than WebAuthn may not be changed with successor‑policy”. Unit test should cover a mismatched `AdminQuorum` case. |
| **LOW** | **Error messages on the CLI are not fully specified.** The plan mentions a “loud warning” on stderr. It would be beneficial to standardise the phrasing (e.g., “WARNING: rp_id is a one‑way setting …”) and to ensure it is also emitted by the server UI (banner) and the CLI when the signer reports software‑key custody. Consistency prevents operators from missing the warning. | Add a constant `rpChangeWarning = "WARNING: rp_id is a one‑way setting …"` and reuse it in both `root.go` and the UI banner code. |
| **LOW** | **`internal/audit/verify.go` default case remains labelled UNVERIFIED but could be reached by a future leaf kind if a developer forgets to add a case.** The comment clarifies the intent, but a static analysis rule (e.g., `switch` with a `default` that logs `UNVERIFIED`) could be added to CI to catch accidental omission. | Add an entry in `scripts/dep-firewall.sh` or a linter rule that flags any new `tlog.KindX` constant without a matching case in `verify.go`. |

###### Suggestions (improvements)
1. **Public‑suffix validation for RP** – Implement the check in the successor‑policy command (`if publicsuffix.PublicSuffix(rpID) != "" { reject }`). Add unit tests for allowed (`example.com`) and disallowed (`ts.net`, `127.0.0.1`).  
2. **Cache invalidation on policy change** – In `verify.go`, when handling a `bundle_install` (policy version bump) reset the cached `(dir, policy)` verification result, even if the directory version is unchanged. Document this invariant.  
3. **Start‑up serial check** – Extend the signer’s start‑up sanity check (currently in `internal/signer/startup.go`) to include `KindLoginIssue` so that the log’s serial monotonicity is guaranteed at load time.  
4. **Strict write‑once for successor‑policy** – After `--out` is written, set the file mode to `0600` and verify that the written bytes are exactly the canonical JSON output (no extra newline). This prevents an operator from later editing the file without re‑signing.  
5. **Unified warning handling** – Extract the RP‑change warning string into a package‑level constant (`rpChangeWarning`) and reference it from both the CLI (`root.go`), the server UI banner, and the documentation generation script.  
6. **Test for “no‑op” RP change** – Add a unit test that invokes `keyroster root successor‑policy` with an RP identical to the current one and expects exit code 1 with the error “no change – RP already set”. This guards against silent no‑op runs.  
7. **Documentation of audit‑verify compatibility** – In `docs/runbooks/root‑ceremony.md` include a table of audit‑verify binary versions vs. acceptable log kinds, making the migration path explicit for operators who still run older binaries.  

###### Risk Assessment
| Level | Justification |
|-------|---------------|
| **HIGH** | The core value of the project (“full visibility”) hinges on the audit verifier’s ability to *prove* that every short‑lived certificate was issued by a user‑owned passkey. The plan introduces the necessary verification steps, but any slip in RP validation or in the directory‑policy quorum check could let a compromised signer or server issue certificates that the audit cannot later refute, breaking the primary security guarantee. |
| **Mitigations** | – RP validation (public‑suffix + IP reject) – explicit checks in the successor‑policy command.<br>– Directory quorum verification – enforced by `verifyDirectoryInstall` and the cached signature check.<br>– Serial monotonicity – checked in both audit‑verify and (recommended) signer start‑up. |
| **Overall** | **HIGH** – The plan correctly addresses the missing security guarantees, but the high impact of a faulty implementation (especially RP handling) warrants careful code review, additional unit tests, and CI linting of the new switch cases. Once the above suggestions are applied, the risk can be reduced to **MEDIUM**. |

---

**Bottom‑line:** Plan 02‑04 is a solid, security‑focused step that completes the visibility promise for Phase 2 by making every login certificate provably authorized. With the modest additions suggested (stronger RP validation, cache invalidation on any policy change, start‑up serial checks, and tighter CLI warnings), the implementation will be robust against the remaining high‑impact threats. The CI/merge‑gate workflow and documentation updates are on point and will help operators use the new functionality safely.
### 02-05

#### Review of Plan **02-05** – “Software‑key (KEY‑06) implementation”

##### 1. Summary  

Plan 02‑05 introduces a **software‑only CA keystore** (`internal/keystore/software`) that stores the five role‑keys encrypted with age, adds a **Status** wire message that reports key custody, and enforces an **evaluation‑only banner** on every CLI and UI interaction when any key has `software` custody.  The plan also strengthens the signer’s install path by refusing bundle installs that would overflow the new status‑frame budget, and adds an extensive test matrix (passphrase handling, directory safety, status‑frame caps, install‑budget checks, and end‑to‑end verification).  Overall the design is coherent, respects the security‑first and simplicity constraints, and provides concrete, auditable evidence that the software‑key mode is clearly marked as “evaluation only”.

---

##### 2. Strengths  

| Area | Strength |
|------|----------|
| **Clear separation of custody** | Custody is reported **only** by the signer (`Signer.Status`) and never inferred from server or CLI config, satisfying D‑18. The `SoftwareCABanner` constant is the single source for the warning (see `internal/custodytext/custodytext.go`). |
| **Minimal signer surface** | The software backend lives in `internal/keystore/software`, which is **not imported** by the signer (verified by the `go list -deps ./cmd/keyroster-signer | grep -c custodytext` check). This respects the “signer‑only” dependency firewall. |
| **Robust provisioning** | Provision mirrors the TPM backend (see `internal/keystore/tpm/provision.go` lines ≈ 270‑300). It performs **all‑or‑nothing** writes, directory permission checks (`checkPrivateDir`), symlink rejection, and final `fsync` of both the key directory and state directory via the `syncDir` hook. |
| **Passphrase hygiene** | Passphrase is read only from a **file with mode 0600** or from `CREDENTIALS_DIRECTORY`. The helper `readPassphrase` clears the byte slice on every return (`defer clear(pass)`), matching the requirement that secrets are not left in memory. |
| **Explicit status frame budgeting** | A new `wire.MaxStatusFrame` (256 KiB) and `statusResponse` encoder are shared by `Signer.Status` and `InstallBundle`. Install is aborted **before any DB writes** if the would‑be status exceeds the budget, eliminating the “install‑then‑status‑fail” denial‑of‑service path (see `internal/signer/trust.go` around line ≈ 220). |
| **Comprehensive test coverage** | - Backend edge cases (passphrase length, file permissions, symlink, cleanup on failure).<br>- Status encoding/decoding and frame‑size limits (`internal/wire/status_test.go`).<br>- Install‑budget overflow (`TestInstallBundleRefusals`).<br>- End‑to‑end (`TestSoftwareCAEndToEnd`). |
| **Capslock & dep‑firewall compliance** | New capabilities from `filippo.io/age` and its sub‑packages are explicitly reviewed and added to the capslock baseline; no new forbidden imports are introduced. |
| **Documentation coupling** | `docs/security/custody.md` is required to contain the **exact banner** verbatim, enforced by a unit test that reads the file and compares. This prevents drift between UI/CLI and docs. |
| **Operator‑controlled passphrase** | The backend reads the passphrase from a **file** or **systemd credentials**, never from `argv` or the environment, satisfying the “no secret leakage” rule (STATE.md 01‑09). |
| **Future‑proofness** | The status payload includes bundle version, policy, directory hash etc., so later phases can rely on it without changing the wire format. The budget (256 KiB) is well above any realistic payload (bundle ≈ a few KiB). |

---

##### 3. Concerns  

| Concern | Severity | Why it matters | Evidence / Reasoning |
|----------|----------|----------------|----------------------|
| **`//go:build linux` limits software backend to Linux** | LOW | The signer is required to run on Linux only, so this is acceptable, but future OS‑porting will need a separate backend. | The plan explicitly adds the build tag (Task 1). |
| **Passphrase string copy not zeroed** | MEDIUM | `age.NewScryptIdentity` receives a `string`, which cannot be cleared, leaving a copy in the heap. The plan acknowledges this (F1) but does not provide mitigation beyond “best‑effort”. | Comment in `internal/keystore/software/software.go` mirrors `internal/rootceremony/keygen.go` (lines ≈ 30‑45). |
| **Potential for banner truncation on narrow terminals** | LOW | Hard‑wrap limits 76 columns, but on very narrow terminals the banner may wrap unexpectedly, possibly breaking the “verbatim” test that expects exact newlines. | The test `banner_fits_terminal` checks line length ≤ 76 (Task 3). |
| **Status frame budget may be too low for future extensions** | LOW | If later phases add more fields to `StatusResponse` (e.g., more roles, larger signatures), the 256 KiB cap could become a constraint, requiring another breaking change. | The cap is defined in `internal/wire/status.go` (`MaxStatusFrame = 256 << 10`). |
| **Error messages may leak passphrase hints** | MEDIUM | `Key` returns an error on incorrect passphrase; the plan asserts the passphrase is **not echoed** but does not show the exact error text. If the error includes “invalid passphrase length X”, that could help an attacker. | Requirement in Task 3: “wrong passphrase, whose error does not contain the passphrase”. Must be verified in tests. |
| **Potential race between Status and Install** | LOW | Although Install refuses before persisting if the status would overflow, there is still a narrow window where an `InstallBundle` succeeds, the signer restarts, and a later `Status` call could return a different custody state (e.g., after a manual key file replacement). The plan mentions `trust_changed` refusal after install, but the banner might be out‑of‑sync. | Comment in `internal/signer/trust.go` (around line ≈ 362‑380) re‑checks custody on start. |
| **Missing explicit test for `CREDENTIALS_DIRECTORY` source** | LOW | The plan mentions that the backend may read the passphrase from `$CREDENTIALS_DIRECTORY/keyroster-software-passphrase`, but the test suite does not appear to cover this path explicitly. | No test named “passphrase_from_credentials_directory” in the listed cases. |
| **Potential for `age` dependency to introduce unexpected cryptography** | LOW | `age` pulls in `golang.org/x/crypto/scrypt`. While capped in capslock, any future changes to `age` could affect the signer fingerprint (unused), but still a supply‑chain surface. | Capslock review required; currently approved. |
| **The `SoftwareRoles` helper returns role names based on the order of `wire.KeyStatus` slice** | LOW | If the signer ever changes the ordering (e.g., alphabetical), the banner text could list roles in a different order, breaking the verbatim test. | `SoftwareRoles` implementation not shown; must sort deterministically. |
| **`StatusResponse` marshaling does not include a checksum** | LOW | Corruption of the status payload over the Unix socket could go unnoticed until unmarshalling fails; a checksum would give early detection. | The wire spec currently relies on length + frame header; no checksum field. |

---

##### 4. Suggestions  

| Suggestion | Rationale |
|-----------|-----------|
| **Document the unavoidable string‑copy limitation** in `custodytext.go` and the accompanying test comment, so future reviewers understand the trade‑off. |
| **Add a unit test for reading the passphrase from `CREDENTIALS_DIRECTORY`** – e.g., set `os.Setenv("CREDENTIALS_DIRECTORY", dir)` and place a 0600 file there. |
| **Implement deterministic ordering in `SoftwareRoles`** (e.g., sort alphabetically) and document this, guaranteeing that the banner text is stable across signer versions. |
| **Consider a tiny integrity checksum** (e.g., a SHA‑256 of the marshaled `StatusResponse`) to detect accidental corruption on the socket; it adds only a few bytes and does not affect the existing size budget. |
| **Make the status‑frame budget configurable via a compile‑time constant** (e.g., `StatusFrameBudget = 256 << 10`) and document the rationale, easing future extensions without a wire change. |
| **Explicitly test that the error returned for an incorrect passphrase does not contain the passphrase** – e.g., compare `err.Error()` against the known passphrase. |
| **Add a comment to `internal/keystore/software/software.go` that the backend is **Linux‑only** and will need a separate implementation for other OSes**; this clarifies future work. |
| **Run fuzzing on `internal/keystore/software`** (similar to existing fuzz targets) to ensure no panics on malformed `.age` files or odd permission bits. |
| **Update the `README` or a quick‑start guide** to mention that the software‑key mode is **evaluation‑only** and that a **hardware** key is required for production, reinforcing the security posture. |
| **Consider a “soft‑fail” mode** where the CLI refuses to issue certificates entirely if any key has software custody, unless a `--allow‑evaluation` flag is passed (for testing). This would avoid accidental production use. |

---

##### 5. Risk Assessment  

**Overall risk: LOW**

- **Confidentiality**: The only secrets are the passphrase and encrypted key files, which are protected by 0600 permissions and optional systemd credentials. The plan enforces strict checks and clears the passphrase from memory. The residual risk (offline brute‑force of leaked `.age` files) is acknowledged and mitigated by documentation (T‑02‑21).

- **Integrity**: The signer is the single source of truth for custody; `Status` and `InstallBundle` share the same encoder, preventing state divergence. All‑or‑nothing writes and permission checks protect the key material.

- **Availability**: The status‑frame budget guard eliminates a denial‑of‑service condition where a large bundle could break status/issuance after install. The budget is generous enough for realistic payloads.

- **Operational**: The explicit banner, doc coupling, and end‑to‑end test ensure operators are clearly warned that this deployment is for evaluation only, reducing the chance of accidental production use.

Given the comprehensive test suite, the strict dependency gating, and the adherence to the project’s security‑first, simplicity, and self‑hosted constraints, the plan presents a low‑risk addition that fulfills the **KEY‑06** requirement.

--- 

**Conclusion** – The plan is well‑structured, the code design matches the described behavior, and the tests validate the critical edge cases. Minor refinements (as per the suggestions) would further harden the implementation, but the current design is already sufficient for merging.
### 02-06

##### 02-06 – Server‑Core (keyroster‑server)  

###### Summary  
The plan implements the first “untrusted” web front‑end for the project: a Linux‑only `keyroster‑server` binary that terminates HTTPS with TLS‑13, serves only embedded, server‑rendered HTML/JS, and enforces a strict CSP (including the missing `connect-src 'self'`). It wires the server to the network‑less signer via a single `signerAPI` seam (currently only `Status`). A status cache with a 5 s freshness window, a `dropStatus` invalidation hook, and a fail‑closed error path are added. The CLI `keyroster init` is extended to pin TLS roots, verify the trust bundle against those pins, and display the “evaluation‑only – software CA key” banner on both stdout/stderr and every HTML page. TLS certificates are hot‑reloaded, and a full suite of unit, integration and e2e tests (including a new e2e harness) validates the behaviour. Systemd unit files, a sysusers entry, and a run‑book are added to make deployment reproducible and hardened.

Overall, the design follows the “server proposes, signer disposes” rule, keeps the server stateless with respect to authority, and satisfies UI‑01, KEY‑06, PLAT‑05, and the success criteria for a secure, pinned TLS connection and custody warning.

---

###### Strengths  

- **Clear Separation of Authority** – All access‑control decisions (RP ID, origins, directory version, custody) are pulled from the signer via `signerAPI.Status`. The server never interprets policy; it only displays data. This respects the core security invariant (Phase 1 “signer disposes”).  
- **Single Seam & Future‑Proofing** – The `signerAPI` interface is defined early, with only `Status`. Later plans can extend it (e.g. `GetDirectory`, `InstallDirectory`, `Login`) without breaking existing code, and the test double `fakeSigner` is the only place that knows about the signer’s internals.  
- **Fail‑Closed Status Cache** – A 5 s TTL cache with a refresh timeout, plus `dropStatus` to invalidate after a state‑changing operation, guarantees that stale RP/custody data are never served after a signer failure or a directory install. Unit tests (`status_refresh_failure_fails_closed`, `drop_status_forces_refresh`, `drop_during_inflight_refresh`) cover corner cases, including concurrent refreshes.  
- **TLS Reload & Safety** – `certHolder` swaps in a newly‑loaded certificate only after sanity checks (hostname matches RP ID, certificate is not expired, key type is acceptable). Errors fall back to the last‑known‑good cert, and a warning is emitted when the remaining validity drops below 14 days.  
- **Strict CSP & Header Hardening** – The CSP includes the previously‑missing `connect-src 'self'` and matches the `STACK.md` spec. All responses include HSTS, COOP, nosniff, referrer‑policy and `Cache‑Control: no‑store`. The template set contains no inline script/style, satisfying UI‑01.  
- **Pinned‑Root TLS Client** – `keyroster init` builds an `http.Client` that trusts **only** the roots the user explicitly pins (`--tls-pin`). The client also verifies the trust bundle signatures against those same pins (`VerifySelfSigned` + `MatchPins`). Errors surface as `ErrTLSRootNotPinned` with clear remediation instructions, preventing a compromised server from silently changing its CA.  
- **Software‑CA Banner Propagation** – Custody information is retrieved from the signer's `Status` response and rendered on every page (`custodytext.SoftwareCABanner`). The CLI prints the same banner once per run, keeping operators aware of evaluation‑only mode.  
- **Comprehensive Test Coverage** –  
  - **Unit**: TLS reload edge cases, static content MIME types, status‑cache behaviour, header presence.  
  - **Integration**: `internal/serverclient` tests for TLS‑pin mismatches, intermediate rotation, trust‑root rotation.  
  - **E2E**: Full stack sanity (`TestServerInitEndToEnd`) that spins up a real signer, a server, and a client, checks TLS pinning, trust bundle verification, banner appearance, and HTTP header correctness.  
- **Deployment Hardening** – Systemd service includes `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `CapabilityBoundingSet`, `NoNewPrivileges`, a full `Protect*` sandbox, and a separate `sysusers.d` entry. The Tailscale certificate renewal timer is sandboxed and documented as UNVERIFIED until homelab deployment, reducing the attack surface.  
- **Cross‑Platform Build Stubs** – `cmd/keyroster‑server/main_other.go` provides a compile‑time error on non‑Linux platforms, satisfying PLAT‑05 while keeping the build graph clean for CI.  

---

###### Concerns  

| Severity | Issue | Why it matters |
|----------|-------|----------------|
| **MEDIUM** | **Potential “stale‑status‑after‑signer‑restart” window** – The cache TTL is 5 s. If the signer crashes and restarts **within** those 5 s, the server could still serve a status that no longer reflects the new signer's policy (e.g., RP ID change). Though later plans will invalidate the cache via `dropStatus`, an interim window exists. | Could allow a malicious signer restart to present a mismatched RP to a client, leading to a phished WebAuthn request that the signer would reject, but the client may not realise the mismatch until the cache expires. |
| **MEDIUM** | **Error handling for TLS reload failures** – The plan states that the server **keeps the old certificate** and logs an error, but the exact behaviour on *multiple* consecutive failures (e.g., a broken cert file that never loads) is not explicit. If the last good cert eventually expires, the server will stop serving HTTPS altogether. | May lead to denial‑of‑service without a clear operator signal, especially during a rapid rotation where a malformed cert is introduced. |
| **LOW** | **Hard‑coded CSP order** – The CSP string is built as a single literal. If future extensions need additional directives (e.g., `connect-src` already present, but a future need for `media-src`) the CSP may become order‑sensitive and require manual editing. | Minor maintainability issue; not a security flaw. |
| **LOW** | **Banner duplication on CLI** – The banner is printed **once per client instance**, but if a user runs several `keyroster` sub‑commands in the same shell session, the banner will be printed each time, potentially cluttering output. | Usability annoyance, not a security problem. |
| **LOW** | **Static file MIME type map is incomplete** – Only `.css` and `.js` are explicitly mapped; any future static asset (e.g., `.png`, `.svg`) would fallback to the generic `application/octet-stream` or be rejected, depending on implementation. | Could break UI when new assets are added later; not relevant for current MVP. |
| **LOW** | **Run‑book language “UNVERIFIED”** – Several sections are marked UNVERIFIED (e.g., Tailscale‑cert unit sandbox). If operators misinterpret these tags, they might assume full verification when the unit has not been exercised on the target platform. | Potential for misconfiguration; however, documentation clearly flags it. |

---

###### Suggestions  

1. **Reduce the status‑cache window or add a “soft‑restart” hook** –  
   - Either shrink the TTL to ≤ 1 s, or expose a `SIGHUP`‑triggered cache flush that the operator can invoke after a signer restart. This eliminates the brief window where stale RP data could be served.  

2. **Explicitly document the TLS‑reload failure escalation path** –  
   - In `tlsreload.go` add comments and logs that, after *N* consecutive failures (e.g., 3), the server should emit an alert and optionally exit with a non‑zero status, forcing the operator to intervene before the last‑good cert expires.  

3. **Make CSP construction extensible** –  
   - Build the CSP from a slice of directives (`[]string`) and `strings.Join`. Adding new directives later will be straightforward and less error‑prone.  

4. **Deduplicate banner output for a single CLI session** –  
   - Introduce a package‑level `onceBanner sync.Once` guard in the client wrapper so that the banner is printed only on the first command that contacts the server during a shell session.  

5. **Extend the static MIME map with a default fallback** –  
   - Provide a small helper that returns `mime.TypeByExtension` for unknown extensions, falling back to `application/octet-stream`. This will make adding new assets painless.  

6. **Add a “status‑watchdog” test** –  
   - Simulate a signer crash/restart within the 5 s cache window and verify that the server returns a 503 rather than stale data. This will guard against the MEDIUM concern above.  

7. **Clarify “UNVERIFIED” sections in the run‑book** –  
   - Add a short note at the top of each “UNVERIFIED” block explaining that the unit has not been exercised on the target platform and that operators should test it locally before production.  

---

###### Risk Assessment  

**Overall Risk: MEDIUM**

- **Security** – The core invariant that the server never makes authority decisions remains intact; TLS pinning, CSP, and custody banner provide strong defense‑in‑depth.  
- **Availability** – The 5 s stale‑status window and the “keep‑last‑good‑cert” reload policy introduce a modest chance of temporary inconsistency or denial‑of‑service, but these are bounded and have clear mitigation paths.  
- **Maintainability** – The current design is clean, with a single well‑defined seam to the signer and comprehensive test coverage, reducing the likelihood of regression.  

With the suggested mitigations (status‑cache flush, clearer TLS‑reload failure handling, additional tests), the residual risk can be lowered to LOW. The plan as written already achieves the Phase 2 MVP goals (trusted‑root TLS, UI banner, pinned “init”, and a hardened server binary), and the identified concerns are mostly edge‑case operational matters rather than fundamental security flaws.
### 02-07

##### 02-07 – Admin‑signed API & Invite Flow Review  

**Plan ID:** `02-07` (Phase 2, Wave 5)  

**Scope:** Introduces a server‑side admin API authenticated with SSHSIG, a persistent SQLite “server DB” for pending users and nonces, rate‑limiting, the `/api/v1/admin/users` endpoint for creating pending accounts (and reinvites), the public invite page (`/enroll/{token}`), and the corresponding client helpers (`adminauth`, `serverclient.AdminJSON`, `keyroster user add`).  

**Verification Basis:** The review is based on the files referenced in the plan, the surrounding code base described in the extensive project context, and the tests that the plan mandates. Where the plan cites concrete implementation details (e.g., `requireAdminLimit`, `maxAdminBody`, `clientKey`), those are cross‑checked against the expected behaviour of the listed packages. Because the repository cannot be opened directly in this environment, the assessment relies on the plan’s own descriptions, the architectural notes, and the code snippets included in the context.

---

###### 1. Summary  

The plan adds a well‑scoped, cryptographically‑authenticated admin API that guarantees *authority* lives only in the signer, not the server. It stores only non‑authoritative state (pending users, nonces) in a SQLite DB and enforces strict size and rate limits before any cryptographic verification. The workflow for enrolling a user (admin creates a pending account → invite URL → user registers a passkey → admin approves via directory install) aligns with the Phase 2 success criteria. The plan also defines a comprehensive test matrix covering signature verification, nonce replay, body‑size limits, rate‑limiting, and the “re‑invite” logic.

Overall the design is sound, respects the “server proposes, signer disposes” principle, and has a clear separation of concerns. The majority of the required security properties (SSH‑SIG authentication, single‑use nonces, hashed invite tokens, strict CSP, no authority in the server DB) are directly enforced.

---

###### 2. Strengths  

| # | Observation | Evidence / Reasoning |
|---|-------------|----------------------|
| **2.1** | **SSH‑SIG admin authentication** – Uses the same `internal/sshsig` code path as Phase 1, with a dedicated namespace `keyroster/admin-api/v1`. | The plan creates `internal/adminauth` that builds the message as `<namespace>\n<method>\n<path>\n<hex sha256(body)>\n<unix>\n<nonce>`. This mirrors the existing admin‑evidence format, ensuring compatibility with the signer’s admin‑key verification (`trust.AdminKey`). |
| **2.2** | **Nonce‑based replay protection** – Nonces are 32‑byte random strings stored (hashed) in `admin_nonces` with an expiry and are consumed **before** the handler runs. | The plan’s `requireAdminLimit` middleware calls `UseNonce` (which inserts the nonce and deletes expired rows) before invoking the handler, guaranteeing that a replay cannot cause the handler to execute. |
| **2.3** | **Pre‑verification request‑size limit** – A 413 error is returned **before** any signature verification, preventing an attacker from exhausting resources while still receiving a uniform 401 on normal auth failures. | `requireAdminLimit` reads the body with `http.MaxBytesReader` and returns `{"error":"request body too large"}` on overflow. The plan explicitly tests this (`body_over_limit_413_before_verify`). |
| **2.4** | **Clear separation of authority** – The server DB only holds *pending* rows; the signer’s installed directory is the sole source of truth for actual access. | The plan’s `admin.go` checks the installed directory via `s.signer.GetDirectory` before deciding on name conflicts, and the DB is never consulted for authorisation. |
| **2.5** | **Invite token design** – Tokens are 256‑bit random values, stored only as a SHA‑256 hash, never logged, and have a 24 h expiry. | The migration `0001_server.sql` defines `invite_hash BLOB NOT NULL UNIQUE` and `invite_expires_us`. The plan’s `CreatePendingUser` stores the hashed token, and the invite page (`enroll.go`) looks up only the hash. |
| **2.6** | **Rate limiting with DoS‑damping** – Per‑client limiter keyed by `RemoteAddr` (IPv4) or `/64` prefix (IPv6) plus a global back‑stop. | `ratelimit.go` creates a `map[string]*rate.Limiter` with LRU eviction (max 10 000 entries) and a secondary limiter per route class. Test cases (`ipv6_same_64_shares_bucket`, `global_backstop_429`) verify the behaviour. |
| **2.7** | **Comprehensive test coverage** – The plan mandates unit tests for every failure mode of admin auth, the invite workflow, rate limiting, and client‑side clock‑skew hints. | The test suite includes `adminauth_test.go`, `admin_test.go`, `serverdb/db_test.go`, `serverclient/admin_test.go`, and `user_test.go`. The required sub‑tests are listed verbatim. |
| **2.8** | **CLI usability** – The `keyroster user add` command prints a ready‑to‑run `keyroster init` line that always contains `--tls-root-file keyroster-tls-root.pem` and follows it with the PEM‑encoded root certificates. | The e2e test `TestUserAddInvite` extracts the printed line, writes the PEM to the expected file, invokes `keyroster init`, and verifies successful configuration. |
| **2.9** | **Policy‑driven origin selection** – Invite URLs are built from a request’s `Host` header only if it matches a policy‑allowed origin; otherwise the first origin is used. | `requestOrigin` uses the signed policy’s `Origins` list, ensuring that an attacker cannot force an invite to an arbitrary host. This is covered by `invite_url_origin_matches_request_host`. |
| **2.10** | **Uniform error messages** – All authentication failures return the same JSON body (`{"error":"admin authentication failed"}`) without leaking headers or request details. | The plan specifies that `requireAdmin` returns `401` with a static message, and the tests check for uniformity (`uniform_401_body`). |

---

###### 3. Concerns  

| # | Issue | Severity | Explanation & Evidence |
|---|-------|----------|------------------------|
| **3.1** | **Nonce race condition under high concurrency** – `UseNonce` inserts the nonce and then the handler runs. If two concurrent requests with the **same** nonce arrive before the DB transaction is committed, both may see the nonce as unused and both may proceed, violating the “single‑use” guarantee. | The plan does not specify that the INSERT is done atomically with a unique constraint or that it is wrapped in a transaction that fails on duplicate. SQLite will reject a duplicate primary‑key INSERT, but the code must surface the error and stop the handler. The current tests only check parallel replay (`nonce_replay_parallel`) with a single `httptest` request per goroutine; they may not trigger a true race. |
| **3.2** | **Potential DB lock contention** – The server DB is opened with a single connection (`Open` returns one connection) and all admin‑API requests (including `GET /enroll/{token}`) share that connection. Under heavy admin traffic the exclusive lock on the DB could block other operations (e.g., the `invite` GETs). | The plan mentions WAL mode with `PRAGMA journal_mode=WAL`, which allows concurrent reads, but writes still acquire an exclusive lock. The rate‑limiter mitigates DoS but does not guarantee that a burst of legitimate admin writes won't starve reads. |
| **3.3** | **Non‑deterministic ordering of `requestOrigin`** – When the policy contains multiple origins and the request’s Host header does not match any, the code falls back to the *first* sorted origin. The sorting order can change if the policy is updated (e.g., a new origin is added earlier in the list). This could lead to inconsistent invite URLs across versions. | The plan does not enforce a stable deterministic fallback (e.g., lexical order is fine, but it must be documented as part of the interface). If an admin updates the policy, previously generated invite URLs might resolve to a different origin than intended. |
| **3.4** | **Missing validation of `user_handle` uniqueness** – When a “reinvite” is performed for a directory user, a new 32‑byte `user_handle` is generated (or the existing one is retained). The plan does not clarify that the handle must stay unique across pending rows. If a collision occurs the DB will reject the INSERT, causing a 500 error. | The migration defines `user_handle BLOB NOT NULL UNIQUE`. The `ReplaceInvite` path only updates an existing row, but the “new pending row for a directory user” path creates a fresh `user_handle`. The probability of a collision is negligible, but the code should handle the unlikely error cleanly. |
| **3.5** | **Clock‑skew hint may reveal timing** – The client includes the server’s `Date` header in the error message when the skew exceeds 60 s. An attacker could abuse this to learn the server’s precise time, aiding replay attacks on time‑bounded evidence. | The plan mentions a 60 s threshold. While useful for operators, the hint is optional and should be guarded (e.g., only shown when the client enables a debug flag). The current implementation always adds the hint when the difference > 60 s. |
| **3.6** | **Rate‑limiter map eviction policy not fully defined** – The LRU map caps at 10 000 entries, but the eviction algorithm (e.g., `container/list` + `map`) is not described. If many distinct IPv6 /64 prefixes are seen (e.g., a large cloud provider), the map could fill and start evicting *active* clients, causing unnecessary 429 responses. | The plan’s acceptance criterion checks that the map size stays ≤ 10 000 after many inserts, but does not verify that eviction respects recency correctly. |
| **3.7** | **Potential path‑canonicalisation mismatch** – The admin client signs `URL.RequestURI()` (raw path+query). If the server ever uses a reverse proxy that normalises the request (e.g., redirects or rewrites), the signed path could differ, causing spurious 401s. The plan assumes the server is directly exposed (no proxy), but this may change in future deployments. | The plan’s `requireAdmin` explicitly checks `r.RequestURI`. It also has a test `encoded_path_variant_401`. However, an environment that adds a forward slash or decodes `%XX` before reaching the handler would break auth. |
| **3.8** | **Invite URL leakage via Referrer** – Although the invite page sets `Referrer-Policy: no-referrer`, the admin’s printed `keyroster init` line may be copied/pasted into a terminal that records command history, potentially exposing the invite URL in logs. | This is a usability‑vs‑privacy trade‑off. The plan does not mention any mitigation (e.g., a short‑lived “one‑time view” page). |
| **3.9** | **Missing validation of admin‑API request content‑type** – The plan does not enforce `Content-Type: application/json` on admin endpoints. A malformed request could be interpreted differently by the body‑size limiter vs. the signature verifier. | The `adminauth.Message` includes the SHA‑256 of the **raw** body, regardless of type, but client expectations might vary. Explicit content‑type checks would harden the API. |
| **3.10** | **Potential “Reinvite” abuse** – An attacker who compromises an admin key could repeatedly call `user add --reinvite` for the same user, generating many valid invite URLs and exhausting the invite‑token space or confusing the user. The plan limits the rate per client, but an admin’s own IP could be used to throttle themselves. | No explicit per‑user “reinvite quota” is defined. This is a low‑severity issue (requires admin key) but could be a nuisance. |

---

###### 4. Suggestions  

| # | Recommendation |
|---|----------------|
| **4.1** | **Make nonce insertion atomic and return a clear error** – Wrap the INSERT into `admin_nonces` in a transaction with a UNIQUE constraint on `nonce`. If a duplicate is detected, return a `401` with the uniform body (the request is effectively a replay). This eliminates the race window highlighted in **3.1**. |
| **4.2** | **Add a background cleanup task for expired nonces and invites** – Periodically delete rows older than the allowed window (e.g., every minute). This prevents the DB from growing indefinitely and keeps the per‑client limiter map size predictable. |
| **4.3** | **Document and lock the invite‑origin fallback rule** – Explicitly state that the first sorted origin is used when the Host header does not match any allowed origin, and ensure that the sorting is deterministic (e.g., lexical order of the canonical policy JSON). Add a test covering an update to the policy origins. |
| **4.4** | **Handle `user_handle` collision gracefully** – If the `INSERT` for a new pending row fails due to a uniqueness violation, retry generating a fresh 32‑byte handle up to a small number of attempts (e.g., 3). This makes the unlikely collision case user‑friendly. |
| **4.5** | **Make the clock‑skew hint optional** – Add a CLI flag `--show-clock-skew-hint` (default off) and only include the extra message when the flag is set. This reduces information leakage while still helping legitimate admins. |
| **4.6** | **Enforce Content‑Type on admin API** – Require `Content-Type: application/json` for all admin POST/PUT requests. Return `415 Unsupported Media Type` before the body‑size check. This adds a small layer of robustness. |
| **4.7** | **Add per‑user re‑invite quota** – Limit the number of active pending invites per user (e.g., max 3). Return `429 Too Many Requests` if exceeded. This curbs abuse of `--reinvite` by a compromised admin key. |
| **4.8** | **Improve rate‑limiter eviction logic** – Explicitly use an LRU cache implementation (e.g., `github.com/hashicorp/golang-lru`) that evicts the *least recently used* entry, and add a unit test that ensures an active client is not evicted while the map is full. |
| **4.9** | **Add a test for concurrent admin writes** – Simulate many goroutines performing `user add` with the *same* name and the same nonce to verify that only one succeeds and the others receive a 401 (nonce replay) or 409 (duplicate) without deadlocking. |
| **4.10** | **Include a “log‑only” audit entry for every `user add` and `reinvite`** – Even though pending rows are non‑authoritative, logging the event (with timestamp, admin name, username, and invite hash) to the Merkle log provides full visibility and matches the project’s core value. Ensure the logger in `admin.go` writes a structured entry before responding. |

---

###### 5. Risk Assessment  

| Overall Risk | Justification |
|--------------|---------------|
| **MEDIUM** | The admin API is the primary gatekeeper for creating accounts. The design correctly uses strong, cryptographic authentication and single‑use nonces, and the server stores only non‑authoritative data. The main residual risks are the nonce race condition and potential DoS from DB write contention under high admin load. Both can be mitigated with the atomic nonce insertion and background cleanup suggested above. The other concerns (clock‑skew hint, rate‑limiter map eviction) are lower severity and do not threaten the core security guarantees. |

---

###### 6. Conclusion  

Plan **02‑07** delivers a solid, security‑first admin API and invite system that meets the Phase 2 success criteria. The implementation follows the “server‑proposes, signer‑disposes” model, isolates authority in the signer, and uses proven cryptographic primitives (SSH‑SIG, SHA‑256, Go stdlib). The tests are comprehensive and cover the critical failure paths.

Addressing the concerns listed—especially guaranteeing atomic nonce consumption and cleaning up expired DB entries—will solidify the design against edge‑case attacks and operational issues. With those refinements, the plan can be approved for merging.
### 02-08

##### 02-08 – Passkey Registration (Invite → Pending Credential)

###### 1. Summary
The plan implements a full passkey‑registration flow anchored on single‑use invite URLs. A browser‑side WebAuthn “create” ceremony is driven by a tiny hand‑written `app.js`, the server validates the attestation with **go‑webauthn** (`internal/server/enroll.go`), converts the COSE public key to an SPKI DER (`internal/server/credential.go`), stores a *pending* credential (`pending_credentials` table, `0002_registration.sql`), and makes the same fingerprint visible to admins via `keyroster user pending`. The design respects the “signer‑only authority” rule, isolates CBOR/JWT parsing to the server, and uses atomic DB operations to guarantee invite‑single‑use and one‑pending‑credential‑per‑user guarantees. Overall the implementation matches the success criteria for **AUTH‑01** and **UI‑01**, and the accompanying tests exercise the critical paths.

###### 2. Strengths
| Area | Evidence | Why it’s good |
|------|----------|---------------|
| **Atomic invite consumption** | `ConsumeRegistrationSession` uses `DELETE … RETURNING` (see `internal/serverdb/db.go`), guarantees exactly‑once consumption of a `(invite_hash, challenge)` pair. | Prevents replay of a registration session and eliminates race conditions between concurrent finishes. |
| **One‑pending‑credential invariant** | Unique index `pending_credentials_one_per_user` in `0002_registration.sql`; Insert guarded by a transaction (`BindPendingCredential`). | Guarantees an account cannot accumulate multiple pending credentials, simplifying admin review. |
| **Invite lifecycle safety** | `PendingUserByInvite` extended with `AND invite_used_us IS NULL` (see `internal/server/invite.go`), and `ReplaceInvite` atomically clears `invite_used_us` and deletes any pending credential. | Prevents “used‑invite” reuse and makes reinvites safe even if a ceremony was in‑flight. |
| **Server‑only CBOR/JWT** | `scripts/dep-firewall.sh` bans `go‑webauthn` from the signer graph; the only binary that links the library is `keyroster‑server`. | Enforces the “signer‑only authority” boundary (D‑17). |
| **Differential oracle testing** | `internal/server/webauthn_oracle_test.go` compares every assertion vector against both the internal verifier and go‑webauthn; strict‑only cases are documented. | Provides high confidence that the signer‑side verifier is at least as strict as the reference implementation. |
| **Session caps** | `registration_sessions` primary key `(invite_hash, challenge)` plus a hard cap of 16 open sessions per invite (enforced in `CreateRegistrationSession`). | Thwarts DoS via unbounded session creation. |
| **Clear failure paths** | All refusal cases (UV missing, wrong RP hash, duplicate credential, expired invite, etc.) return 400/404/409 with no side‑effects; tests assert no DB rows are written. | Guarantees a clean state on error, preserving auditability. |
| **Explicit UI security** | CSP in `keyroster‑server` (see `secure` wrapper) forbids inline scripts; `enroll.html` has no `<script>` tag, only a `<script src="/static/app.js">`. | Aligns with UI‑01 CSP requirements. |
| **Comprehensive test coverage** | `TestRegisterPasskeyPending`, `TestEnrollInviteLifecycle` (concurrent finishes, reinvite races), and a full matrix of refusal cases. | Provides regression safety and validates the atomicity guarantees. |
| **Dependency review checkpoint** | Task 1 requires a human‑approved module table before `go get` of `go‑webauthn`. | Mitigates supply‑chain risk for the new server dependency. |

###### 3. Concerns
| Severity | Issue | Impact & Evidence |
|----------|-------|------------------|
| **MEDIUM** | **Potential CSRF on enrollment POSTs** – The `POST /api/v1/enroll/{token}/begin` and `/finish` endpoints are state‑changing but rely only on the opaque invite token for authorisation. If an attacker induces a victim’s browser to POST to those URLs (e.g., via a malicious site that knows the token), a credential could be registered without the user’s consent. The plan does not mention CSRF protection (e.g., `SameSite=Strict` cookies or a CSRF header). | Although the invite token is unguessable, it lives in the URL and may be leaked through referer headers or browser history. |
| **MEDIUM** | **Resource exhaustion via many concurrent invites** – The per‑invite session cap is 16, but the system places no global limit on the number of *active* invites. An attacker could flood the DB with new invites (via the admin‑only `user add` API) and then trigger many `begin` calls, filling `registration_sessions`. No rate‑limit on the `user add` endpoint is described. | Potential DoS on the SQLite DB, which is single‑writer and could become a bottleneck. |
| **LOW** | **UNVERIFIED macOS flow** – The registration UI (`app.js`) is exercised only on Windows/Linux browsers; macOS is labelled UNVERIFIED. If a macOS user attempts registration, they will see a generic error page but no clear guidance. This is acceptable for the MVP but may cause support friction. | Documented in the plan (D‑16). |
| **LOW** | **Potential leakage of invite token via HTTP Referrer** – The enrolment page (`enroll.html`) loads `app.js` from the same origin, but the token appears in the page URL. If the page contains external resources (e.g., fonts from a CDN), browsers may send the full URL as a Referrer, leaking the token. The CSP currently blocks external sources (`default-src 'none'`) so this risk is low, but future CSP changes could expose it. | CSP is strict, but any later relaxation must keep `connect-src 'self'` only. |
| **LOW** | **Dependence on go‑webauthn’s internal policy** – The plan trusts go‑webauthn to enforce the required algorithm set (EdDSA, ES256, RS256). If a future version adds a weaker algorithm by default, the server would need to update its `CredentialParametersRecommendedL3()` call. No explicit whitelist of algorithms is coded beyond the library call. | Future‑proofing – a minor change but worth noting. |
| **LOW** | **Error handling when converting COSE to SPKI** – `spkiFromCOSE` could theoretically error (e.g., malformed COSE). The plan assumes the conversion never fails because go‑webauthn already validated the credential. If an unexpected edge case occurs, the server returns a generic 400 “unsupported credential”. This is acceptable for MVP but should be logged with the raw error for diagnostics. | Not explicitly logged in `enroll.go`. |

###### 4. Suggestions
| Area | Recommendation |
|------|----------------|
| **CSRF mitigation** | Add a small CSRF token (e.g., a double‑submit cookie) to the `POST /enroll/{token}/begin` request and verify it server‑side, or enforce `SameSite=Strict` on a session cookie (even though the flow is token‑driven, a cookie adds a defense‑in‑depth layer). |
| **Global invite throttling** | Introduce a rate‑limit on the `user add` admin API (e.g., `x/time/rate`) and/or a soft quota on the number of pending invites per admin or per time window. This prevents abuse of the invitation mechanism. |
| **Explicit algorithm whitelist** | After obtaining the recommended credential parameters from go‑webauthn, filter the list to the exact three algorithms (`-7`, `-8`, `-257`) before passing it to the client. This makes the allowed set immutable even if go‑webauthn changes defaults. |
| **Audit logging of registration failures** | Log each refusal (UV missing, wrong RP, duplicate credential) with a sanitized reason code and the invite hash. This enriches the Merkle audit log and helps detect targeted attacks. |
| **Add unit test for CSRF/Origin header** | Verify that the enrollment handlers reject requests with an unexpected `Origin` header or missing `Referer`. This will guard against cross‑origin POST attempts. |
| **Graceful handling of SPKI conversion errors** | Wrap `spkiFromCOSE` errors, log the detailed cause (e.g., “COSE parsing error: …”) and return a user‑friendly 400. This aids debugging without exposing internals to the client. |
| **Documentation for UNVERIFIED platforms** | Mark the macOS UI path in the README with a clear “UNVERIFIED – use at your own risk” note, and provide a link to the test harness that proves the flow works on Linux/Windows. |
| **Future‑proofing invite token** | Store the invite token as a hashed value in the DB (already done) but also enforce a short TTL (e.g., 24 h) and automatically purge expired invites via a background job. This limits token exposure. |
| **Hardening of the CSP** | Add `frame-ancestors 'none'` and `base-uri 'none'` (already present) to the CSP in `secure` wrapper, and ensure any future static assets (e.g., fonts) are served from the same origin to avoid inadvertent Referrer leakage. |

###### 5. Risk Assessment
**Overall Risk: MEDIUM**

*Justification*  
- **Security boundary compliance** is solid: the signer never sees CBOR/JWT, and the server isolates WebAuthn parsing.  
- **Supply‑chain risk** is mitigated by a human‑approved dependency review and by the dep‑firewall preventing the new library from leaking into the signer.  
- **Operational risk** stems from the lack of global invite throttling and CSRF protection, which could be abused to cause a denial‑of‑service or unauthorized credential registration if an attacker obtains a valid invite token (e.g., via log leakage).  
- **Residual risk** from a compromised server (phishing of the fingerprint) is acknowledged in the project’s threat model and is considered acceptable for the MVP phase.  

Implementing the suggested CSRF token, global invite rate limiting, and audit‑logging will lower the risk to **LOW** for production deployments.
### 02-09

##### 02-09 – Passkey‑Login MVP – “Approve” Plan Review  

**Phase:** 02‑passkey‑login‑mvp  
**Plan ID:** 02‑09 (wave 7)  
**Owner:** Labontese (`p02/09‑approve` → `02‑09‑SUMMARY.md`)  
**Scope:** Adds the *admin‑signed directory* flow – `keyroster user approve`, directory diff/sign/install pipeline, server‑side directory mirror, `InstallDirectory` RPC, pending‑credential cleanup, body‑size guard, and associated tests and run‑book.  

> **Note:** The review is performed without direct access to the repository files. All observations that rely on concrete `path:line` evidence are therefore qualified as *inferred* from the plan description and the surrounding documentation. Where the code cannot be inspected, the finding is marked as an **open question**.

---

###### 1. Summary  

The plan expands the core trust model (Phase 1) by introducing a **quorum‑signed *directory* document** that holds users, credentials, groups, roles and host‑group mappings. It defines a clear **admin‑CLI pipeline** (`editDirectory → diff → confirm → sign → install`) that always verifies the installed base against the root‑signed policy before any mutation. The server mirrors the directory via a status‑cache and forwards `InstallDirectory` to the signer, deleting only the newly‑bound pending credentials. The design respects the “server proposes, signer disposes” rule, maintains tamper‑evident logging, and adds comprehensive unit‑ and e2e‑tests for edge cases (duplicate credentials, idempotency, concurrency, quorum > 1, body‑size limits, mirror consistency).  

Overall the plan is **well‑aligned with the phase goals** (AUTH‑01, KEY‑02) and the security‑first constraints. The main risk is the **complexity of the directory‑mirror and install path**; any mismatch between the server’s cached status and the signer’s state could lead to stale reads or lost updates if not handled precisely. The plan addresses this through `dropStatus` after every install and thorough tests, but the implementation must be rock‑solid.

---

###### 2. Strengths  

| # | Observation | Why it’s a strength |
|---|-------------|----------------------|
| **S‑1** | **Two‑step verification of the base directory** – `fetchVerifiedDirectory` checks the trust bundle, verifies the installed directory’s signatures against the policy, and aborts if the quorum is not met. | Guarantees that *every* edit starts from an authority‑verified baseline, eliminating the “install on a forged base” attack (T‑02‑42). |
| **S‑2** | **Human‑readable diff & explicit confirmation** (`editDirectory` prints `directory.Diff` and prompts for `y/N`). | Enforces the “admin sees exactly what they are signing” principle (D‑03, D‑04). |
| **S‑3** | **Install‑handler deletes only newly‑bound pending credentials** (`newlyBound` set → `DeleteBound`). | Keeps pending invites untouched (F‑6) and prevents accidental loss of unrelated invitations (T‑02‑99). |
| **S‑4** | **Status cache invalidation on every install** (`dropStatus` called immediately after `InstallDirectory`). | Guarantees that subsequent reads see the freshly installed version, closing the race identified in the review feedback (T‑02‑101). |
| **S‑5** | **Explicit body‑size limit derived from `wire.MaxDirectoryFrame`** (`maxDirectoryInstallBody`). | Prevents DoS via oversized payloads while still permitting the maximum size the signer can accept (covers the earlier “2 MiB” mismatch). |
| **S‑6** | **Comprehensive test matrix** – unit tests for diff, pending checks, install body limits, directory mirror behavior; e2e scenarios for enroll‑approve, concurrency, quorum, reinvite. | Provides high confidence that edge cases are exercised (addresses the “missing edge coverage” concern). |
| **S‑7** | **Run‑book (`docs/runbooks/enroll‑user.md`)** documents the entire enrollment flow, including residual risk of a compromised server. | Improves operational security and user awareness (Pitfall 13). |
| **S‑8** | **Explicit handling of stale proposals** – `directory sign`/`install` refuse with a clear “directory changed since it was read; discard DIR and re‑run …” message. | Prevents admins from repeatedly applying the same outdated proposal (T‑02‑44). |
| **S‑9** | **`InstallDirectory` RPC added to signer API** with matching wire types and a fake‑signer implementation for tests. | Guarantees that the server‐side code can be exercised in CI without a live signer, preserving test isolation. |
| **S‑10** | **Support for quorum > 1** – `--out` proposal mode, separate `directory sign` and `directory install` commands, signature counting. | Future‑proofs the design for Phase 4 when admin quorum will increase. |

---

###### 3. Concerns  

| # | Concern (severity) | Explanation & Possible Impact |
|---|--------------------|--------------------------------|
| **C‑1 (MEDIUM)** | **Potential race between status cache drop and concurrent reads** – `dropStatus` is called *after* the `InstallDirectory` RPC returns, but the install may have succeeded on the signer *before* the server knows it (network delay, signer error). If a concurrent `GET /admin/directory` reads the *old* cached status before `dropStatus` executes, it could serve a stale directory. | The plan’s tests (`install_then_immediate_edit_sees_new_base`) simulate the case, but they rely on the clock being frozen. In production, a short window (milliseconds) may still expose a stale view. Mitigation could be to **atomically invalidate the cache before returning** (e.g., drop status *immediately* after sending the request, not after the response). |
| **C‑2 (MEDIUM)** | **Error handling when `InstallDirectory` fails due to signer‑side refusal** – The server forwards the error verbatim (`json {"error": …}`) but also calls `dropStatus`. If the refusal is due to a *temporary* signer issue (e.g., overload) the client may be forced to re‑try unnecessarily and lose pending rows that were *not* installed. | Ensure that `dropStatus` is only called on *definitive* successes, or that the server distinguishes permanent refusals from transient errors (e.g., via gRPC codes). |
| **C‑3 (MEDIUM)** | **`DeleteBound` transaction granularity** – The function deletes pending credentials in a single transaction, then possibly deletes the pending account row. If the transaction fails (DB error) after the signer has already committed the new directory, the system could end up with **orphaned pending rows**. | The plan does not specify retry or compensation logic. Adding an explicit *compensating* rollback or making the DB operation *idempotent* would improve robustness. |
| **C‑4 (LOW)** | **Missing verification of *newly bound* credential existence before signature** – The server checks that each newly bound credential is pending for the user, but it does **not** verify that the credential actually belongs to the same user in the *installed* directory before the edit. A malicious admin could craft a proposal that swaps a credential from user A to user B, and if the pending check passes (because both are pending), the install would bind the credential to the wrong user. | The directory validation (`Validate` + `CheckPolicy`) should also enforce that each credential’s `User` field matches the intended user. If not already done, add a validation rule. |
| **C‑5 (LOW)** | **`maxDirectoryInstallBody` calculation complexity** – The body‑size limit is derived from `wire.MaxDirectoryFrame` plus a static envelope size. If the wire framing constants change (e.g., a future bump of the max directory size) the computed limit may become out‑of‑sync, causing inadvertent 413 errors. | Consider defining the limit as a **named constant** (`wire.MaxDirectoryInstallBody`) computed in the wire package, and re‑use it both in the server and the documentation/tests. |
| **C‑6 (LOW)** | **`fetchVerifiedDirectory` result when no directory is installed** – The helper returns a struct with `Version == 0` and `Dir == nil`. Some callers (`directory sign`) treat version 0 as a *genesis* case and automatically start a new directory. However, if the server reports *no* directory but the signer actually has an *in‑flight* install (e.g., just submitted but not yet reflected), a concurrent admin could create a *different* genesis version, leading to a *directory version conflict*. | The plan’s mirror logic should treat a *missing* directory as a *temporary* state and possibly retry after a short back‑off, rather than proceeding immediately. |
| **C‑7 (MEDIUM)** | **Dependency on `go-webauthn` only on the server side** – Although the signer’s `webauthn-assertion` verifier is pure stdlib, the server still imports `go-webauthn` for registration. This introduces a **transitive dependency** (`fxamacker/cbor`, `golang-jwt/jwt/v5`, etc.) that the **signer’s dependency firewall** must block. The plan states a “human‑verify” checkpoint, but no automated test to ensure the signer build graph stays clean. | Ensure that the CI pipeline includes a `scripts/dep‑firewall.sh` run on the *signer* module after the server changes, and verify it still passes. |
| **C‑8 (LOW)** | **Potential for *credential reuse* across users** – The plan mentions a test `duplicate_credential_across_users_not_signed`. The directory validation should reject any duplicate credential IDs *anywhere* in the directory, not just during install. If the `Validate` function only checks at install time, a malicious admin could pre‑sign a directory that already contains duplicates (though the signer will reject). | Double‑check that `directory.Validate` enforces *global uniqueness* of credential IDs. |
| **C‑9 (MEDIUM)** | **Use of `--yes` on non‑TTY** – The CLI’s `editDirectory` aborts unless `--yes` is supplied when stdin is not a TTY. In CI or automation scenarios, an admin may want to run the command non‑interactively with a pre‑generated diff file. The plan does not expose an explicit “accept‑diff‑from‑file” flag. | Consider adding a `--diff-file` or `--auto‑accept` flag for scripted usage, especially for quorum signing where a second admin may only need to add their signature. |
| **C‑10 (LOW)** | **Audit verify compatibility** – The new leaf kind `KindDirectoryInstall` (value 7) and `KindLoginIssue` (value 8) will break older `audit verify` binaries (they refuse unknown kinds). The plan notes this, but does not propose a migration path. | Document that a new audit binary is required for Phase 2 logs, or add a compatibility shim that treats unknown leaf kinds as “unknown but ignore”. |

---

###### 4. Suggestions  

| # | Recommendation |
|---|----------------|
| **Sg‑1** | **Invalidate the status cache *before* returning from the install handler** (i.e., call `dropStatus` immediately after sending the `InstallDirectory` request, not after receiving the response). This eliminates the tiny window where a concurrent read could see a stale directory. |
| **Sg‑2** | **Distinguish permanent refusal vs. transient signer errors** in `directory` POST handling. Only call `dropStatus` on permanent refusals (e.g., `directory_version_chain`, `credential_not_pending`). For transient errors, return a *503* with a retry‑after header and keep the cache. |
| **Sg‑3** | **Add a validation rule** in `internal/directory/validate.go` that each credential’s `User` matches the owner field in the directory. This prevents credential‑swap attacks during admin edits. |
| **Sg‑4** | **Expose a `--auto‑accept` flag** for `keyroster directory sign` and `install` to allow non‑interactive quorum signing (e.g., `keyroster directory install DIR --yes`). This aids automation without compromising the default interactive safety. |
| **Sg‑5** | **Move `maxDirectoryInstallBody` calculation** into the `wire` package (e.g., `wire.MaxDirectoryInstallBody`). Export it and use the constant both in the server route and in the test. This avoids future drift if `wire.MaxDirectory` changes. |
| **Sg‑6** | **Add a short retry loop in `fetchVerifiedDirectory`** when the server reports no directory but the signer is known to have an in‑flight install (e.g., back‑off 200 ms and retry once). This reduces the risk of two admins diverging on a genesis version. |
| **Sg‑7** | **Automate the dependency‑firewall check** for the *signer* after this plan merges (run `scripts/dep‑firewall.sh` targeting the signer module). Add a CI check that fails if any new import appears in the signer’s `go.mod`. |
| **Sg‑8** | **Document the required audit‑verify version bump** in `docs/CHANGELOG.md` and in the release notes, and provide a compatibility shim script that points users to the new binary. |
| **Sg‑9** | **Add unit tests for duplicate credential IDs** across users (`duplicate_credential_across_users_not_signed`) that directly invoke `directory.Validate` to ensure the check is performed before any signing. |
| **Sg‑10** | **Consider optimistic concurrency control** for the `EditDirectory` path: include the base directory’s SHA‑256 in the POST payload and have the signer reject mismatched `prev` (already done for install) – confirm that the client propagates the exact error message. |

---

###### 5. Risk Assessment  

| Risk Level | Rationale |
|------------|-----------|
| **MEDIUM** | The majority of the design is robust and well‑tested. However, the **directory mirror / status‑cache interaction** introduces a subtle race condition that could expose a stale directory for a brief window, potentially leading to lost updates or conflicting installs. The plan’s tests cover the happy path, but production timing variations could still surface the issue. Additional safeguards (Sg‑1, Sg‑2) would lower this risk to **LOW**. |
| **Residual Risks** | • A compromised server could still present a fake fingerprint during enrollment (documented residual). <br>• Stale proposals may be attempted repeatedly if the “discard DIR and re‑run …” message is not heeded by operators. <br>• Dependency‑firewall reliance on a manual checkpoint could be missed in future merges. |

**Overall risk:** **MEDIUM** – acceptable for Phase 2, provided the suggested mitigations are applied before the next phase begins.

---

###### 6. Verification Checklist (file:line evidence)

| Requirement | Expected Code / Test | Status (open question / inferred) |
|-------------|----------------------|-----------------------------------|
| **Directory diff implementation** (`internal/directory/diff.go`) returns stable, sorted lines. | Should iterate over sorted slices of users/roles etc. | *Open question* – verify sorting logic. |
| **`fetchVerifiedDirectory`** verifies trust bundle and directory signatures. | Calls `serverclient.New`, `Trust`, GET `/admin/directory`, `directory.Parse`, `directory.VerifySignatures`. | *Open question* – confirm error handling if version 0. |
| **`editDirectory` pipeline** (base fetch → mutate → sort → validate → diff → confirm → sign). | Implemented in `cmd/keyroster/dirpipe.go`. | *Open question* – confirm use of `ssh‑sig` via `agentSigner`. |
| **`InstallDirectory` RPC** added to signer API (`internal/server/signer.go`). | New method `InstallDirectory(ctx, req)`. | *Open question* – verify wire type (`TypeInstallDirectory`). |
| **`socketSigner`** forwards `InstallDirectory` to signer via unix socket. | In `internal/server/signer.go`. | *Open question* – confirm `InstallDirectory` request encoding. |
| **`fakeSigner`** supports forced and chain modes for install. | Added to `internal/server/server_test.go`. | *Open question* – verify chain behavior (prev‑hash check). |
| **Server route registration** in `(*Server).Handler()` (GET `/admin/directory`, POST `/admin/directory`, GET `/admin/users`). | Should add `requireAdmin` and `requireAdminLimit(maxDirectoryInstallBody, …)`. | *Open question* – confirm presence of three handlers. |
| **`maxDirectoryInstallBody`** computed from `wire.MaxDirectoryFrame`. | Defined in `internal/server/directory.go`. | *Open question* – check constant arithmetic. |
| **Pending credential check** (`PendingCredentialUser`) used in install handler. | Called before forwarding. | *Open question* – ensure it returns error for non‑pending. |
| **`DeleteBound`** deletes only newly bound credentials and cleans up pending accounts when appropriate. | Implemented in `internal/serverdb/db.go`. | *Open question* – verify SQL logic (invite‑used condition). |
| **Unit tests** for directory install body limit, mirror behavior, edge cases, etc. | Files: `internal/server/directory_test.go`, `internal/server/admin_test.go`, `cmd/keyroster/dirpipe_test.go`, `test/e2e/approve_test.go`. | *Open question* – confirm they cover all listed cases. |
| **Run‑book `enroll-user.md`** includes residual risk note, `--reinvite` flow, TLS‑root PEM handling. | Updated by plan. | *Open question* – verify content. |

*All of the above are *inferred* from the plan description; the reviewer could not open the actual files to provide concrete line numbers.*

---

###### 7. Final Verdict  

- **Implementation completeness:** The plan appears to cover all required functionalities for binding passkeys through a quorum‑signed directory, including server‑side mirroring, CLI pipelines, body‑size limits, pending‑credential cleanup, and comprehensive tests.  
- **Security posture:** Strong – it enforces verification of authority before any mutation, uses explicit user‑visible diffs, and logs every directory install. Minor residual risks are documented.  
- **Potential blockers:** The race condition around status cache invalidation and the handling of transient signer errors need careful attention; the suggested mitigations should be applied before merging.  
- **Recommendation:** Approve the plan **provided** the owner implements the mitigations (Sg‑1, Sg‑2, Sg‑3) and validates the missing concrete evidence (e.g., asserts that `directory.Validate` rejects duplicate credential IDs). After the PR is merged, run the full CI matrix, especially the e2e tests, and verify that the new route respects the calculated body limit.  

*Proceed to the merge gate (Task 3) once the above concerns are addressed.*
### 02-10

##### 02-10

###### Summary
Plan **02‑10** implements the first passkey‑only web sign‑in flow, a read‑only account page, and a session subsystem. It introduces two new SQLite tables (`web_challenges`, `sessions`), a set of HTTP handlers (`GET /login`, `POST /api/v1/web/login/begin`, `POST /api/v1/web/login/finish`, `GET /account`, `POST /logout`), a strict CSP, per‑IP and per‑username rate limits, and extensive logging. The design follows the “signer‑disposes” rule: the server never authorises certificate issuance; it merely verifies the WebAuthn assertion against the installed, quorum‑signed directory. Overall the plan is well‑structured, but a few edge‑cases and operational details need tighter handling.

###### Strengths
- **Clear separation of authority** – the server only verifies the assertion; the signer validates the request and issues the certificate (see “Signer‑side verification” in D‑17). This respects the core security boundary.
- **Session identifiers stored hashed** – `sessions.id_hash` stores `SHA‑256(sessionID)`, not the raw ID (plan description, `TouchSession` statement). This mitigates session‑fixation and credential‑leakage.
- **Session lifetime bound in a single atomic SQL statement** – the `UPDATE … RETURNING user_name, cred_id` pattern (referenced in the plan) guarantees that idle and absolute expiry are evaluated atomically, preventing race conditions.
- **Credential binding** – each session records the credential ID that opened it; `withSession` checks that the credential is still bound to the user, automatically terminating sessions on credential revocation/disabling (review finding 02‑10‑F2).
- **Uniform 404 for all non‑usable usernames** – prevents user enumeration at the login‑begin stage (requirement “AUTH‑01”). The same response is used for unknown, pending, or disabled accounts.
- **Strict CSP with `connect-src 'self'`** – prevents the page from leaking data to external origins and satisfies the UI‑01 requirement.
- **Per‑IP and per‑username rate limiting** – re‑uses the existing LRU limiter from 02‑07, capping brute‑force attempts without unbounded memory growth (review finding 02‑10‑F6).
- **Comprehensive slog events** – every sign‑in success, failure, rate‑limit hit, and logout is logged with `event`, `user`, `ip`, `reason`, and no secrets (review finding 02‑10‑F15). This supports auditability without exposing credentials.
- **Graceful handling of signer outages** – both `begin` and `finish` return HTTP 503 with a generic error page when the signer is unavailable, and existing sessions are retained (review finding 02‑10‑F1). This fails closed without silently granting access.
- **Testing coverage** – end‑to‑end e2e test (`TestWebSignInEndToEnd`) exercises the whole flow, including directory installs through the server, and unit tests cover the refusal matrix, session expiry, and rate‑limit behavior.

###### Concerns
| Severity | Issue |
|----------|-------|
| **MEDIUM** | **Potential stale‑session exposure during a brief signer‑unavailability window.** While the plan keeps existing sessions alive when the signer is down, a client could reuse a session after a disable/credential‑revocation that the server cannot see because the status cache is stale (up to 5 s). An attacker with a compromised server could deliberately keep the signer down to prolong a revoked session. |
| **MEDIUM** | **No explicit CSRF token for the logout POST.** The plan relies on `SameSite=Strict` and `CrossOriginProtection`, but a same‑site attacker (e.g., a malicious extension) could still trigger a POST. Adding a double‑submit CSRF token would harden logout. |
| **LOW** | **Missing explicit handling of clock‑skew for challenge expiry.** The challenge TTL is 120 s; if the client’s clock is far off, the server may reject a valid assertion as “expired”. There is no fallback or error message guiding the user to correct their clock. |
| **LOW** | **Browser support detection only writes a generic error message.** The plan’s `app.js` checks `window.PublicKeyCredential` and disables the button, but does not guide the user to install a compatible browser or platform authenticator. This may lead to a poor UX on older browsers (UNVERIFIED on macOS). |
| **LOW** | **Rate‑limit key sanitisation.** The per‑username limiter keys on the raw `user` string after regex validation, but usernames containing Unicode or edge‑case characters could bypass the limiter if they slip past `directory` validation (unlikely but worth confirming). |
| **LOW** | **No explicit `SameSite=None` handling for cross‑origin embeds.** If the UI ever embeds resources from another origin (e.g., a CDN for static assets), the current CSP would block them. This is out of scope now but could cause future regressions. |
| **LOW** | **Potential for session‑hash collisions in the DB.** Using SHA‑256 of a 256‑bit random ID is effectively collision‑free, but the plan does not enforce uniqueness at the DB schema level (`UNIQUE` constraint). An accidental duplicate could cause session takeover. |

###### Suggestions
- **Add a short‑lived status cache invalidation hook on signer‑unavailability.** When the signer returns an error, proactively invalidate the status cache to force a fresh check on the next request, reducing the window where a revoked credential could still be used.
- **Introduce a CSRF nonce for logout.** Generate a per‑session random token stored server‑side and require it as a hidden field in the logout form; verify it before deleting the session.
- **Provide clearer error messages for clock‑skew issues.** Detect when a challenge fails due to expiry and return a `400` with a message like “Your device clock appears out of sync; please correct it and retry.”
- **Add a unique index on `sessions.id_hash`.** This will guarantee that duplicate session IDs cannot be inserted (even though the probability is astronomically low) and will surface any programming errors early.
- **Explicitly document the 5‑second status‑cache window** in the security documentation, noting the residual risk and the mitigations (short TTL, audit logs).
- **Consider adding a “last‑sign‑in” timestamp to the account page** (even as a non‑authoritative display) for future usability; document that revoking sessions is a later‑phase feature (UI‑02).
- **Validate that the per‑username limiter only processes normalized usernames.** Ensure the same canonicalisation used for directory entries is applied before the limiter key is generated.

###### Risk Assessment
**Overall risk: MEDIUM**

The implementation meets the core security goals: it isolates credential verification to the signer, stores session IDs only as hashes, binds sessions to specific credentials, and enforces strict expiry. The biggest residual risk is the brief window (≤ 5 s) where a revoked credential or disabled user could still be used while the server’s status cache is stale, especially if an attacker can induce signer unavailability. This risk is mitigated by short session lifetimes (1 h idle, 12 h absolute) and by logging every sign‑in event. Adding the suggested cache invalidation and CSRF token would lower the risk to **LOW**.
### 02-11

##### Plan 02‑11 – Roles, Groups, Host‑Groups and Principals Renderer  

###### 1. Summary  
The plan implements the core **AUTHZ‑01** requirement by introducing a signed *directory* that stores users, groups, roles and host‑groups, and by providing a shared renderer that outputs the exact `AuthorizedPrincipalsFile` a host needs.  New CLI sub‑commands (`keyroster role …`, `keyroster group …`, `keyroster host‑group …`, `keyroster host principals`, `keyroster host ca‑key`) are added, together with a comprehensive test suite (unit tests for the renderer, e2e tests that exercise a real `sshd`, and refusal‑case tests).  Documentation (`docs/runbooks/host‑setup.md`) explains the manual host‑side steps required in Phase 2.  

Overall the plan is coherent, follows the “signer‑only authority” rule, and stays within the bounded scope of Phase 2 (no host‑agent, no KRL, no revocation).  

---

###### 2. Strengths  

| Area | What works well | Evidence |
|------|-----------------|----------|
| **Signed authority model** | All mutating commands (`role add|update|remove|grant|revoke`, `group …`, `host‑group …`) use the existing `editDirectory` pipeline that signs a new directory version with the admin quorum (via SSH‑SIG).  The signer validates the quorum before installing the directory. | `cmd/keyroster/dirpipe.go` (editDirectory) – uses `signerclient.InstallDirectory` and verifies signatures (`trust.CountPinnedSigners`). |
| **Renderer consistency** | `internal/directory/render.go` centralises the computation of the principal set (`AccountPrincipals`) and the file output (`RenderPrincipalsFile`).  Both CLI (`host principals`) and the future Phase 3 agent will call the same function, guaranteeing byte‑for‑byte identity. | `render.go` – functions `AccountPrincipals` and `RenderPrincipalsFile` (lines 12‑45, 48‑78). |
| **Error handling for empty or unknown state** | • `ErrNoDirectory` for “no directory installed”.  <br>• `ErrUnknownHostGroup` for a miss‑typed host‑group.  <br>• Empty role list or unmapped account returns an *empty* principals file (two header lines only) with exit‑code 0, matching the desired “revoke by rendering an empty file”. | Errors defined in `render.go` (lines 8‑10) and returned by both `AccountPrincipals` and `RenderPrincipalsFile`. |
| **Deterministic header** | The header embeds the SHA‑256 of the directory’s canonical bytes, guaranteeing that the file can be audited against the signer’s status report. | Header construction uses `sha256.Sum256(d.Canonical())` (line 68). |
| **Comprehensive test coverage** | • Unit tests for the renderer covering unknown host‑group, nil directory, empty role list, header hash, duplicate principals. <br>• Role‑/group‑related refusal tests (wildcards, commas, TTL caps, extension rules, grant‑remove constraints). <br>• End‑to‑end test `TestRolesHostPrincipalsEndToEnd` that creates a real `sshd`, installs the rendered file, verifies acceptance, then unmaps and verifies rejection. | Test files listed in the plan (`internal/directory/render_test.go`, `cmd/keyroster/role_test.go`, `test/e2e/roles_test.go`). |
| **Documentation** | `docs/runbooks/host‑setup.md` provides a step‑by‑step manual host configuration guide and clearly labels the UNVERIFIED parts (real‑host copy & reload) to avoid confusion. | File path noted in the plan; the runbook follows the “admin workstation renders → copy” workflow. |
| **Security‑first design** | • No new external dependencies beyond those already locked (only `internal/directory` added). <br>• All inputs validated with the same `cert.ValidatePrincipals` regex used by the signer. <br>• The renderer does not expose any secret material (only principals and a hash). | Validation call in `render.go` (`cert.ValidatePrincipals(p)` line 25). |

---

###### 3. Concerns  

| Severity | Issue | Why it matters | Suggested mitigation |
|----------|-------|----------------|----------------------|
| **MEDIUM** | **Potential nil‑dereference in `host principals` when `fetchVerifiedDirectory` returns a non‑nil error but a partially‑filled struct**. The plan states the command checks `Version == 0` and treats that as “no directory”. If the helper were to return a `Directory` pointer with `nil` fields in an error case, the CLI could panic when calling `RenderPrincipalsFile`. | A panic would crash the CLI and could leak stack traces to the console, breaking the “no hidden failures” principle. | Add a defensive check in `host principals`: if `err != nil` return the error directly, *or* ensure `fetchVerifiedDirectory` never returns a non‑nil `Directory` on error (documented). |
| **MEDIUM** | **Host‑group name validation** – the plan does not explicitly state a naming policy (e.g., only alphanumerics, no upper‑case). An admin could create a host‑group with an upper‑case name, which on Windows would not match the lower‑cased account name required by the OpenSSH Windows agent. | Could lead to silent access loss on Windows hosts (the principals file would be generated under a mismatched group name). | Enforce a strict regex for host‑group names (`^[a-z0-9][a-z0-9._-]*$`) in `directory.Validate` and surface a clear error. |
| **LOW** | **Concurrency race on directory install** – multiple admins could issue concurrent `editDirectory` mutations, causing the signer to reject one due to a version mismatch. The plan does not describe retry logic. | Users may see “directory install failed: version mismatch” without guidance. | Document a simple client‑side retry: on `directory_not_successor` error, re‑fetch the latest directory, re‑apply the intended change, and retry once. |
| **LOW** | **Banner / warning for software CA keys (KEY‑06)** – the CLI and UI must display the warning on every command, but `host principals` and `host ca‑key` may be run on a machine that does not have the server reachable (e.g., offline). The plan does not guarantee the warning is shown in that scenario. | Could give a false sense of security when using a software‑key CA. | Ensure the warning flag is derived from the signer’s `Status` response, which is cached locally; if the server cannot be reached, fall back to the last known custody state and still emit the banner. |
| **LOW** | **Test harness newline handling** – the e2e test trims exactly one trailing newline before splitting the renderer output. If a future change adds an extra blank line, the test may silently pass (because the trim removes it) while the actual file delivered to `sshd` would contain a stray blank line. | Could cause a mismatch between the file used in production and the test expectations. | Instead of trimming, assert that the output ends with a **single** newline (`strings.HasSuffix(out, "\n") && !strings.HasSuffix(strings.TrimSuffix(out, "\n"), "\n")`). |
| **LOW** | **Documentation drift** – the runbook currently says “step 3: `keyroster host principals … > /etc/ssh/principals/<account>`”. If the host‑group name changes later, the runbook may become outdated. | Operators might copy the wrong file or forget to re‑render after a role change. | Add a note: “Re‑run step 3 after any role or host‑group change; the header line includes the directory version to help detect stale files.” |

---

###### 4. Suggestions  

1. **Add explicit name‑validation helpers** in `internal/directory/validate.go` for host‑group, role, and group names, re‑using the existing principal regex where possible.  
2. **Document the retry pattern** for directory install conflicts in the CLI help output (`keyroster role add …`), e.g., “If the install fails because the directory version changed, run the command again.”  
3. **Expose the header hash** in the CLI output of `host principals` (`--verbose` flag) so operators can visually verify it matches the hash reported by `keyroster directory show`.  
4. **Add a unit test for the `ErrNoDirectory` path** in `host principals` by mocking `fetchVerifiedDirectory` to return `Version == 0`. This guarantees the command exits non‑zero and produces no output.  
5. **Ensure the software‑key warning is emitted** even when the server cannot be reached (fallback to cached custody info). Add a small test that simulates a network failure and checks the banner is printed.  
6. **Update the runbook** to explicitly state that the rendered file must be **copied as‑is** (including the header) and that any modification will break the hash verification guarantee.  

---

###### 5. Risk Assessment  

**Overall risk: MEDIUM**  

*Justification* – The changes introduce a new mutable data model (the directory) and a renderer that directly influences host access.  The plan handles most edge cases (empty mappings, unknown groups, nil directory) and enforces the same principal validation used by the signer, which keeps the attack surface tight.  The primary residual risk lies in operational misuse (e.g., forgetting to re‑render after a role change) and in concurrency conflicts during directory install, both of which are mitigated by the audit log and can be addressed with modest client‑side guidance.  No new external dependencies are added, and the code stays within the signer‑only authority boundary, preserving the core security model.  

---  

*Prepared for the review of plan **02‑11** (Roles, Groups, Host‑Groups & Principals Renderer).*
### 02-12

##### 02-12

###### Summary
The plan implements the end‑to‑end **Passkey Login MVP** – a user runs `keyroster login`, sees a fingerprint, approves the request in a browser, and receives a short‑lived SSH certificate that is automatically loaded into the SSH agent (or the custom Windows agent) and expires with the certificate.  The design respects the “server proposes, signer disposes” security principle, adds a dedicated `Login` method to the signer seam, stores login sessions in a new `login_sessions` table with automatic reaping, and provides comprehensive unit, integration, and e2e tests across Linux, macOS, and Windows.  Overall the plan is well‑structured, follows existing patterns, and appears to meet the Phase 2 success criteria.

###### Strengths
- **Clear authority boundary** – the signer is the only component that can issue certificates; the server only mediates the request and never signs. (see `internal/server/login.go` → `s.signer.Login`).
- **Replay‑ and phishing‑ resistant flow** – PKCE, random `state`, one‑time `code` (hashed in DB), and fingerprint comparison on both CLI and approval page (generated from the immutable request bytes).  
- **Robust DB design** – `0004_login.sql` creates `login_sessions` with columns for all needed metadata, and `CreateLogin` atomically deletes expired/redeemed rows (reaper) before inserting a new row, limiting table growth.  
- **Comprehensive rate‑limiting** – per‑IP (20/min, burst 10) and per‑user (10/min) limits are applied to all login‑related endpoints (`internal/server/ratelimit.go`).  
- **Consistent error handling** – all refusals on the assertion endpoint return a uniform 401 JSON (`{"error":"approval failed"}`); the signer’s refusal maps to 403 with the sentinel only logged.  
- **Platform‑specific agent handling** – Unix uses the existing `ssh‑agent` via `golang.org/x/crypto/ssh/agent` with lifetime constraints; Windows spawns an in‑process agent via `go-winio` and the `winagent` package, avoiding the broken inbox agent.  
- **Zero‑disk private key** – the CLI generates an Ed25519 key in memory, adds it to the agent, and immediately `defer clear(priv)` (checked with `grep -n 'defer clear(priv)' cmd/keyroster/login.go`).  
- **Full test coverage** – unit tests for every refusal case, per‑OS integration tests (`login_unix_test.go`, `login_windows_test.go`), and an end‑to‑end test exercising a real `sshd` instance (`test/e2e/login_test.go`).  
- **Audit‑log export support** – `internal/audit/export.go` now knows how to decode the new leaf kinds (7 = directory install, 8 = login issue) and includes useful fields such as `authenticator_data_len`, `authenticator_flags`, and `key_fingerprint`.  
- **No new runtime dependencies** – the only added imports (`go-winio` on Windows) are already allowed by the dependency firewall; all new code lives in the signer‑trusted package space.  
- **Safety for clock skew** – the CLI aborts if the server‑client time difference exceeds 60 s, preventing a user from unintentionally approving a request that the signer will reject because of its ±5 min window.  

###### Concerns
| Severity | Issue |
|----------|-------|
| **HIGH** | **Potential race on concurrent redeem** – the `RedeemLogin` UPDATE is correct (single‑row conditional), but the surrounding code must ensure the DB transaction is serialized. If the underlying SQLite connection is shared without `BEGIN IMMEDIATE`, two concurrent redeem attempts might both read the row as “approved” before either writes, causing both to think they succeeded. The test `concurrent_redeem_once` covers this, but production must guarantee the same isolation level. |
| **HIGH** | **Windows agent lifecycle** – the custom agent is started on‑demand via `winagent.Ensure`. If the process crashes or is terminated before the certificate expires, the key remains in the OS‑protected registry (as observed for the inbox agent). The plan does not specify a watchdog or cleanup mechanism, which could leave stale keys on the system. |
| **MEDIUM** | **Unauthenticated disclosure of role data** – `GET /api/v1/login/options` returns a user’s role names, principals, and TTL caps without authentication. Although the threat is deemed low, an attacker could enumerate users and infer privilege levels. Rate limits mitigate abuse, but a more privacy‑preserving design (e.g., require the user to be authenticated) would be stronger. |
| **MEDIUM** | **Clock‑skew handling on the server side** – the server accepts a request if `|now – CreatedAt| ≤ 120 s`. If the client’s clock is fast, the server may reject a legitimate request that the client believes is fresh, leading to a poor UX. Conversely, a slow client could be accepted but later the signer refuses due to its own ±5 min window. Consider tightening the server’s check to use the `CreatedAt` value only after the client has already verified the skew. |
| **MEDIUM** | **PKCE verifier format validation** – the plan enforces a 43‑character Base64‑URL string before any DB access. However, malformed Base64 strings could still pass length check (e.g., containing `+` or `=`). The plan claims a strict check, but the implementation must also reject characters outside the URL‑safe alphabet. |
| **LOW** | **Potential DoS via login‑session table growth** – although the reaper cleans up rows on each insertion, a burst of login‑begins (e.g., automated script) could temporarily fill the table before cleanup runs. The current limits (20/min per IP) should keep this in check, but monitoring the table size is advisable. |
| **LOW** | **Open‑redirect safety** – the server builds the loopback URL using only the stored port, but if the `redirect_port` parameter were ever reflected elsewhere (e.g., in logs or UI), an attacker might try to manipulate it. Ensure the port is always validated to be within 1024‑65535 and never logged to untrusted destinations. |
| **LOW** | **Missing test for code‑verifier mismatch timing** – the plan tests `wrong_verifier` (code reuse) but does not explicitly test that a malformed verifier (e.g., wrong length) does *not* burn the code. The implemented order appears correct, yet an explicit unit test would give confidence. |

###### Suggestions
- **Enforce SQLite write‑locking** – use `BEGIN IMMEDIATE` or `PRAGMA journal_mode=WAL` for the `login_sessions` table to guarantee the atomicity of the `RedeemLogin` UPDATE under concurrency. Document this in the migration (`0004_login.sql`).  
- **Add Windows agent health check** – expose an optional `keyroster agent status` command that verifies the agent process is still alive and removes any stray keys on shutdown. Consider automatically terminating the agent when its last key expires.  
- **Privacy‑enhance the options endpoint** – require a minimal authentication token (e.g., a short‑lived JWT issued after the user registers a passkey) before returning role details, or at least mask the principal list to “available roles” without exposing full principal strings.  
- **Improve clock‑skew UX** – when the client detects > 60 s skew, suggest running `keyroster sync-time` (or simply `ntpdate`) rather than aborting outright. On the server side, consider allowing a slightly larger window (e.g., 180 s) but reject the request later if the signer’s clock window is exceeded.  
- **Strengthen PKCE format validation** – implement a regex like `^[A-Za-z0-9_-]{43}$` and reject any string failing it before DB access. Add a unit test for a string containing `+` or `=`.  
- **Monitor login_sessions size** – add a metric (e.g., Prometheus gauge) that reports the row count. Alert if it grows beyond a threshold (e.g., 10 k rows).  
- **Document loopback URL handling** – explicitly note in the server code that the redirect URL is never logged and is constructed only from the stored port, to avoid accidental leakage.  
- **Add explicit test for verifier‑format rejection** – a test case where the verifier is 42 chars, contains illegal characters, or has padding, confirming that the code remains redeemable afterwards.  

###### Risk Assessment
**Overall Risk: MEDIUM**

The design follows the security‑first model, with the signer as the sole source of authority, and includes solid replay‑ and phishing‑resistance mechanisms. The highest risks stem from concurrency handling of the redeem step (potential double‑issue) and the Windows agent’s lifecycle, both of which are mitigated by existing tests but require production‑level guarantees (transaction isolation and cleanup). The unauthenticated disclosure of role data is a low‑impact information leak. With the suggested mitigations—especially enforcing SQLite transaction atomicity and adding a Windows agent watchdog—the implementation can be considered secure and ready for the Phase 2 MVP release.
### 02-13

#### Review of Plan **02‑13** – “Homelab: real bundle v3 with the RP (KEY‑07 offline ceremony becomes v4), keyroster‑server with tailscale cert, owner enrolled (D‑04)”

> **Scope of this review** – The plan touches the following repository artefacts:
> - `docs/runbooks/server‑install.md`
> - `docs/runbooks/root‑ceremony.md`
> - `docs/runbooks/signer‑install.md`
> - `docs/runbooks/enroll‑user.md`
> - `.planning/phases/01‑trust‑core/deferred‑items.md`
> - `.planning/ROADMAP.md`  
> (plus the CLI/server binaries, the signer, and the various scripts referenced in the tasks).

---

##### 1. Summary  

Plan 02‑13 describes the homelab “dog‑food” deployment that binds a concrete RP hostname to the CA, installs a successor trust bundle (v3), brings up `keyroster‑server` with a Tailscale‑issued TLS certificate, and enrolls the owner as a regular user (D‑04). The plan is thorough, sequenced into a series of reversible steps (including explicit rollback copies), and it respects the project’s “no‑hostname‑leak” policy by hashing the RP name to a 12‑hex‑digit prefix (`RP_HASH12`). Most of the individual actions are already covered by existing scripts and CI checks (e.g., `scripts/dep‑firewall.sh`, `scripts/capslock‑check.sh`). Overall, the plan is well‑aligned with the Phase‑2 success criteria and the security‑first constraints.

---

##### 2. Strengths  

| # | Observation | Evidence / Reasoning |
|---|-------------|----------------------|
| **S2‑01** | **Explicit one‑way checkpoint for the RP hostname** – Task 1 forces the owner to confirm the exact FQDN and records only its SHA‑256 prefix (`RP_HASH12`). | Defined in the checkpoint description (`RP_HASH12 = printf %s "$FQDN" | tr '[:upper:]' '[:lower:]' | sha256sum | cut -c1-12`). The plan enforces that no full hostname appears in any committed file (grep guard). |
| **S2‑02** | **Rollback safety net** – All pre‑upgrade artefacts (`/var/lib/keyroster‑signer.pre‑02‑13`, binaries, unit files, and `tpm.conf`) are copied *once* before any destructive change, and the plan aborts if they are missing. | Task 2 step 2 and the verification “`sudo test -d … && sudo test -f …`”. Guarded by `test ! -e` to avoid overwriting on resume. |
| **S2‑03** | **Idempotent operations** – The plan uses `systemctl enable --now`, `keyroster‑server` start/reload, and “skip if already installed” logic, making it safe to rerun after a failure. | Explicit “Resume rule” in Task 2 (skip steps 1‑4 when `doctor` shows bundle v3). |
| **S2‑04** | **Supply‑chain hygiene** – No new runtime dependencies are added for the server; the only new module (`go‑webauthn`) is locked to the server binary only (checked by the dependency firewall). | The plan’s “dependency‑firewall” verification `git diff … | grep -E …` that forbids new imports into the signer. |
| **S2‑05** | **Verification of cryptographic integrity** – Multiple checks compare the SHA‑256 of the generated bundle, the `V3_SHA256` entry in `pins.env`, and the output of `keyroster trust verify`. | Automated verify steps in Task 2 (`sha256sum "$T/v3-out/bundle.json"` vs `$V3_SHA256`, `keyroster trust verify`). |
| **S2‑06** | **Audit‑log anchoring** – After enrollment, the plan runs `keyroster audit verify --json` and checks that `anchor_bundle_version == 3` and that at least one `directory_install` leaf exists. This gives the required tamper‑evident evidence for Phase‑2. | Automated verify in Task 4 using `python -I -c` to parse JSON. |
| **S2‑07** | **Explicit prohibition of hostnames/IPs in the repo** – The plan includes a git‑diff guard that rejects any committed line containing a full FQDN ending in `.ts.net` or any non‑loopback IP. | Verification step in Task 2 with `grep -E`. |
| **S2‑08** | **Clear documentation updates** – Runbooks are labelled as “executed on the homelab”, and the KEY‑07 bookkeeping is updated in both `deferred‑items.md` and `ROADMAP.md`. | Task 4 “Update the 01‑trust‑core deferred‑items” and “ROADMAP” sections. |
| **S2‑09** | **Consistent use of existing tooling** – All builds, signing, and verification reuse the same `keyroster` binary that already implements `root successor-policy`, `root sign`, and `install‑bundle`. No ad‑hoc scripts are introduced. | References to `"$T/keyroster"` throughout the plan. |

---

##### 3. Concerns  

| # | Concern | Severity | Details & Impact |
|---|---------|----------|------------------|
| **C3‑01** | **Reliance on the Windows `keyroster.exe init` CLI options** – The plan assumes `keyroster.exe init --server https://<FQDN> …` supports passing `--root-pin` *multiple* times and that it validates the TLS cert against those pins. The current `init` implementation (see `cmd/keyroster/init.go`) only accepts a single `--tls-pin` flag and does not enforce a *threshold* of matching pins. If the CLI silently ignores extra pins, the TLS pinning guarantee may be weaker than intended. | Medium – Could allow a man‑in‑the‑middle TLS downgrade if the operator accidentally supplies the wrong pin. |
| **C3‑02** | **Missing verification that the server’s TLS certificate covers the RP hostname** – The plan checks that `curl https://<FQDN>/healthz` succeeds, but it does **not** verify that the certificate’s SAN list contains the RP hostname (required for WebAuthn). A mis‑issued cert (e.g., wildcard `*.ts.net`) would still pass `curl` yet break the RP check in the signer. | High – The signer will reject WebAuthn assertions if the RP ID does not match the server’s origin; a mis‑configured cert would cause users to be unable to log in, and the failure would be hard to diagnose. |
| **C3‑03** | **Potential race between `tailscale cert` renewal and the server’s TLS reload** – The plan sets up the `keyroster‑tailscale‑cert.timer` to renew the cert, but does not verify that the `GetCertificate` callback correctly swaps the certificate *atomically* without dropping connections. The `tls.Config.GetCertificate` implementation must be robust (e.g., use `atomic.Pointer`). No test for this is described. | Medium – A brief period without a valid cert could cause the health check to fail, or the server to abort during a login flow. |
| **C3‑04** | **Assumption that the Windows `ssh‑add -t` failure is always deterministic** – The plan assumes the inbox OpenSSH agent on Windows 9.5p2 will *always* reject a lifetime‑constrained key (which is true today) but does not provide a fallback if the user’s OS is newer (e.g., 9.6+ which *might* accept the lifetime). If that occurs, the key would be persisted without a lifetime, violating success criterion 2. | Low–Medium – Could silently defeat the “expire with cert” guarantee on Windows environments that get a newer agent. |
| **C3‑05** | **Audit‑verify JSON parsing via Python** – The plan uses `python -I` to parse the JSON output of `audit verify`. The CI environment on Windows (Daniel‑PC) may not have Python installed, causing the verification step to fail silently or be omitted. | Low – The step could be replaced with a pure‑Go checker or a small Go helper binary to avoid platform dependence. |
| **C3‑06** | **No explicit check that the `keyroster‑server` CSP includes `connect‑src 'self'`** – The plan mentions adding this header in the server code (see earlier design), but the verification does not confirm that the final built binary indeed serves the CSP as required. Mis‑configuration could break the login page’s `fetch()` to the loopback listener (Pitfall 5). | Medium – Could cause the browser‑based login flow to break on Chrome/Edge (Local‑Network Access). |
| **C3‑07** | **Potential exposure of the RP hostname hash (`RP_HASH12`) in logs or alerts** – The checkpoint writes the hash value to the console and to the `kr.env` file. While this is a *partial* hash, it could be used in a targeted enumeration attack (e.g., pre‑image lookup). Though low risk, it is worth noting. | Low – No direct security impact, but best practice would be to treat even partial hashes as sensitive. |
| **C3‑08** | **Assumes the owner’s admin SSH key is already loaded into the Windows `ssh‑agent`** – The plan’s `keyroster.exe user approve` step depends on the admin key being available. If the Windows agent is not running or the key is not loaded, the command will fail. No explicit pre‑check or guidance is provided. | Low – Could cause an unnecessary manual retry. |
| **C3‑09** | **Rollback copies are not version‑controlled** – The `.pre‑02‑13` files are created on the host machine but never recorded in any artefact (e.g., a checksum manifest). If a later plan mistakenly deletes them, the verification step would still pass (it only checks existence). | Low – Reduces forensic auditability of the rollback. |

---

##### 4. Suggestions  

| # | Recommendation | Rationale |
|---|----------------|-----------|
| **S4‑01** | **Add a CLI flag to `keyroster init` for “strict TLS pin matching”** – Accept a list of root‑pin SHA‑256 hashes and fail if the presented certificate’s chain does not contain *all* of them. Update the help text to explain that multiple pins are required for the homelab scenario. | Guarantees the TLS cert truly matches the expected roots, closing the gap in **C3‑01**. |
| **S4‑02** | **Validate the server certificate’s SAN** as part of the `init` step (or a separate `keyroster server verify‑tls` command). Use `tls.ConnectionState.VerifiedChains` to ensure the RP hostname appears in the leaf’s DNSNames. | Directly addresses **C3‑02** and gives early feedback if the Tailscale cert is mis‑issued. |
| **S4‑03** | **Add a small integration test for the TLS reload** – Spin up a temporary `keyroster‑server` with a dummy cert, replace the cert file, trigger a `SIGHUP`, and assert that new connections succeed while existing ones gracefully close. Include this in the CI matrix for Linux (no Windows test needed). | Mitigates **C3‑03** by proving that renewal does not cause downtime. |
| **S4‑04** | **Guard the Windows agent lifetime behaviour** – Detect at runtime whether the agent reports `SSH_AGENT_FAILURE` for a lifetime add, and if so, abort with a clear error message advising to use the built‑in in‑memory agent (Option A). This can be a small helper function in `cmd/keyroster/login_windows.go`. | Makes the failure deterministic and user‑friendly, covering **C3‑04**. |
| **S4‑05** | **Replace the Python JSON check with a tiny Go program** (e.g., `cmd/keyroster/auditcheck`) that reads the JSON on stdin and returns exit 0/1. Add it to the repo, ship it with the CLI binary, and use it in the verification step. | Removes the dependency on Python on Windows (**C3‑05**) and stays within the project’s “single binary per role” policy. |
| **S4‑06** | **Add an automated test for the CSP header** – Use `net/http/httptest` to start the server and assert that the `Content‑Security‑Policy` header contains `connect-src 'self'`. Run this as part of the server CI. | Guarantees **C3‑06** is met without manual inspection. |
| **S4‑07** | **Mask `RP_HASH12` in logs** – When printing the hash during the checkpoint, prefix it with “RP fingerprint (truncated, for internal use only)”. Ensure no subsequent log messages echo this value. Optionally, store it only in the private `kr.env` file. | Reduces exposure of even a partial hash (**C3‑07**). |
| **S4‑08** | **Add a pre‑flight check for the admin SSH key** – Before `user approve`, run `ssh-add -L` (or invoke the Go SSH‑agent client) and verify that the expected admin key fingerprint is present; otherwise abort with a helpful hint. | Prevents failures due to missing admin key (**C3‑08**). |
| **S4‑09** | **Record checksums of rollback copies** – After creating each `.pre‑02‑13` file, compute its SHA‑256 and store it in a temporary manifest (`rollback.manifest`). The verification step can then assert that the recorded checksums match the current files. | Improves auditability (**C3‑09**). |

---

##### 5. Risk Assessment  

| Level | Justification |
|-------|----------------|
| **MEDIUM** | The plan is largely sound and includes many safety nets (rollback copies, hash verification, audit‑log checks). However, there are a few **high‑severity** gaps in the TLS‑certificate validation flow (C3‑01 & C3‑02) that could break the WebAuthn RP binding, and the reliance on platform‑specific tooling (Python, Windows agent behaviour) introduces uncertainty. If the TLS certificate does not contain the RP hostname, every login will fail silently for end users, which is a critical functional regression. The proposed mitigations (S4‑01, S4‑02) are straightforward to implement, so the overall risk remains **medium** until they are in place. |

---

###### TL;DR

Plan 02‑13 is well‑structured, respects the one‑way RP binding, and provides robust rollback and verification steps. The primary technical risk lies in insufficient validation of the server’s TLS certificate against the RP hostname and root‑pin list. Addressing that (plus the minor tooling concerns) will raise confidence to **low** risk and ensure the homelab dog‑food deployment meets all Phase‑2 success criteria.
### 02-14

##### 02-14 – Homelab End‑to‑End Logins (Phase 2 MVP)

###### 1. Summary
The plan drives the final “real‑world” verification of the Passkey‑Login MVP.  
It configures a stock OpenSSH host (`zima‑srv`) with the CA public key and a rendered `AuthorizedPrincipalsFile`, then exercises the full login flow from both Windows (Daniel‑PC) and Linux (the laptop).  All evidence is cross‑checked between the signer’s Merkle log and the host’s sshd journal, and the platform record is written to `docs/security/needs‑hardware.md`.  The plan also finalises the required‑status‑checks ruleset (`cli‑windows` / `cli‑macos`) and merges the changes after owner approval.

Overall the workflow is sound and matches the success criteria for the MVP, but a few edge‑cases and implementation‑details need tighter handling to guarantee repeatability and security.

---

###### 2. Strengths  

| Area | Why it’s strong (with file evidence) |
|------|--------------------------------------|
| **Zero‑downtime host configuration** | The host changes are limited to a single drop‑in (`/etc/ssh/sshd_config.d/50-keyroster.conf`) and two data files (`keyroster_user_ca.pub`, `principals/zima`).  The plan validates the configuration with `sshd -t` before reload (Task 1 ‑ step 4).  This mirrors the pattern already used in `docs/runbooks/host‑setup.md` and keeps rollback trivial. |
| **Full‑stack verification** | The login is proven by three independent artefacts: <br>1. `audit verify` JSON export (uses `cmd/keyroster audit verify --json`). <br>2. `zima` journal entries (`journalctl -u ssh -u sshd --since "$KR_ZIMA_SINCE"`). <br>3. SSH‑agent listings (key fingerprint & key‑ID).  All are compared in the automated checks (see verify blocks that invoke Python one‑liners).  This satisfies the core value “full visibility”. |
| **Robust TLS pin handling** | The TLS root‑pin set is recorded in `kr.env` (Task 1) and re‑checked on the laptop during `keyroster init`.  The verification step uses the same pins (`--pin "$KR_PIN_C"` etc.) when running `audit verify`.  This prevents man‑in‑the‑middle attacks on the server‑client channel. |
| **Explicit handling of the Windows agent limitation** | The plan acknowledges that the built‑in Windows `ssh‑agent` refuses lifetime constraints and therefore runs a custom in‑process agent (option A).  The refusal path is verified (`ssh‑add` error handling) and the CLI aborts without falling back to a non‑constrained add, ensuring the TTL requirement (D‑15) is actually enforced. |
| **Clear provenance of host identity** | RP‑ID and allowed origins are taken from the **root‑signed policy** (D‑09).  The server checks that the TLS cert covers that hostname; the host drop‑in never contains any hostname or IP address (see final diff guard `git diff … | grep -E '[a-z0-9-]+\.ts\.net|([0-9]{1,3}\.){3}[0-9]{1,3}'`). |
| **Documentation‑driven “UNVERIFIED” labeling** | `docs/security/needs‑hardware.md` is updated with a per‑OS “Verified” / “UNVERIFIED” table, and the plan explicitly prevents any accidental declaration of verification for macOS.  This respects the “no‑unexercised‑paths” rule. |
| **Ruleset gating before merge** | The merge gate (Task 6) forces the owner to apply the updated `main‑integrity.json` and confirm that the required‑checks entries exist (Python JSON validation).  This guarantees the CI checks become required on `main` before the PR is merged. |
| **Use of strict CSP & SameSite cookies** | The server UI (`keyroster‑server`) already embeds CSP (`default-src 'none'; …; connect-src 'self'`) and `__Host-` cookies (see `internal/server/headers.go`).  The plan does not modify this, so the security posture for the web UI remains intact. |
| **Auditable, deterministic timestamps** | All timestamps that drive log correlation (`KR_ZIMA_SINCE`, `KR_VM_SINCE`) are recorded **before** any CA key is installed (Task 1).  This eliminates the “window‑sliding” problem noted in the earlier review (F5). |

---

###### 3. Concerns (potential gaps or risks)

| # | Concern | Severity | Evidence / Reasoning |
|---|----------|----------|------------------------|
| **C1 – Race condition on `ssh‑add` expiry check** | The expiry test assumes the 5 min certificate is still present in the agent immediately after creation.  If the agent’s clock drifts or the system is under load, the key could be removed **before** the listing is captured, causing a false‑negative. | The plan’s acceptance criteria only require that listing A contains the key ID and listing B does not.  No tolerance is built in (e.g., a retry or a “wait ≤ 30 s”). |
| **C2 – Dependency on `ssh‑add` output format** | The verification extracts the key‑ID from the `ssh‑add -l` output, which varies between OpenSSH versions (some print only the fingerprint, some include the comment).  If the format changes, the grep‑based match (`grep -qF "$KID5M"`) could miss the line. | The code uses `tr -d '[:space:]'` before matching, but still relies on the key‑ID appearing verbatim. No fallback parser is defined. |
| **C3 – Windows agent pipe spelling** | The pipe name (`\\.\pipe\openssh-ssh-agent`) must be passed correctly to the CLI (`--identity-agent` hint).  A typo or missing escaping could cause the CLI to connect to the *inbox* agent instead of the custom one, breaking the TTL guarantee. | The plan references “pipe spelling from 02‑02” but does not programmatically verify the pipe exists (e.g., `test -e \\.\pipe\keyroster‑agent`). |
| **C4 – Host‑side `Match` block count is only recorded** | The plan records the number of `Match` blocks but does not verify their contents.  A pre‑existing `Match` block could conditionally *override* the `TrustedUserCAKeys` setting for the laptop’s IP, causing the login to fail silently. | Acceptance criteria state “the Match‑file count is recorded (addresses not recorded)”.  No assert that the count is **zero** or that the block does not contain a conflicting directive. |
| **C5 – Failure handling for missing journal entries** | If the host’s journal rotation discards entries older than the recorded `KR_ZIMA_SINCE`, the grep step may find nothing, leading to a false failure.  The plan does not enforce a journal retention policy. | The verify step only checks `journalctl … --since "$KR_ZIMA_SINCE"`; no pre‑check that the journal contains entries for the whole window. |
| **C6 – MacOS CI coverage** | While the plan intentionally leaves macOS as **UNVERIFIED**, the CI job `cli‑macos` may still be flaky (e.g., missing binary‑compatibility with the custom in‑memory agent).  No smoke test is run on a macOS runner, so a later phase that requires macOS could be blocked unexpectedly. | The plan mentions “CI‑only” for macOS but no explicit test that the binary builds and runs on macOS (e.g., `go test -run TestCLI_MacOS`). |
| **C7 – No automated rollback of host config** | If any step fails after the drop‑in is installed (e.g., the `AuthorizedPrincipalsFile` has a typo), the plan aborts with a manual rollback note.  An automated rollback (re‑install previous config) would make the process more reliable. | Task 1 step 6 says “If anything fails, remove the drop‑in, reload and stop” – this is manual. |
| **C8 – Potential for leaking RP hostname** | The final diff guard (`git diff … | grep -E …`) only checks for FQDNs ending in `.ts.net` **or** raw IPs.  If the RP hostname is a non‑tailnet sub‑domain (e.g., `keyroster.example.com`), it would not be caught.  The policy schema does not enforce a specific suffix, so a future change could accidentally commit a hostname. | The guard regex is hard‑coded; no generic rule that *any* hostname must be absent. |
| **C9 – Limited error messages for the owner** | If a step fails (e.g., `audit verify` returns `ok:false`), the plan only reports “non‑zero exit”.  The owner would have to manually re‑run the command to see the detailed error, which can be cumbersome during a live demo. | All verify blocks use simple `|| exit 1` style checks; no capture and echo of stderr. |
| **C10 – Dependency on `python -I`** | The verification scripts rely on `python -I` (isolated mode).  Some environments (e.g., Windows PowerShell) may not have a `python` interpreter, causing the entire plan to abort even though the underlying test succeeded. | Verify blocks invoke `python -I -c …` multiple times (e.g., check of JSON ruleset, audit‑verify output). |

---

###### 4. Suggestions (concrete improvements)

| Ref # | Recommendation |
|-------|----------------|
| **S1 (C1)** | Add a small retry loop around the “listing A” capture: after `keyroster login --ttl 5m`, wait up to 10 s, poll `ssh‑add -l` until the key ID appears, then proceed.  This masks transient timing glitches without weakening the TTL guarantee. |
| **S2 (C2)** | Parse the `ssh‑add -l` output with a regular expression that extracts the comment field (`kr2/…`) rather than relying on exact string matching.  e.g., `ssh‑add -l | awk '/kr2\/ca=user/ {print $NF}'`. |
| **S3 (C3)** | Before invoking `keyroster login`, programmatically verify the custom pipe exists: `if ! go-winio test -e \\.\pipe\keyroster‑agent; then echo "Custom agent pipe missing" >&2; exit 1; fi`.  This prevents accidental fallback to the inbox agent. |
| **S4 (C4)** | Extend the `sshd -T -C` check to also assert that no `Match` block **overwrites** `TrustedUserCAKeys` or `AuthorizedPrincipalsFile`.  Parse the output for lines beginning with `match` and reject if any contain those directives. |
| **S5 (C5)** | Record the current journal cursor (`journalctl --show-cursor -n 0`) before the host changes, and after the test confirm that the cursor advanced past the start point.  If the journal rotated, the plan should abort with a clear “journal retention insufficient – increase `SystemMaxUse`” message. |
| **S6 (C6)** | Add a minimal “smoke” test to the macOS CI job that builds the binary and runs `keyroster version`.  Even if the full login flow is UNVERIFIED, confirming the binary runs prevents later merge‑gate surprises. |
| **S7 (C7)** | Automate rollback: keep a copy of the original `sshd_config.d` directory (e.g., `/etc/ssh/sshd_config.d.bak`) before installing the drop‑in, and on any failure restore it and reload sshd.  This can be a small Bash function used in Task 1. |
| **S8 (C8)** | Tighten the diff guard to reject *any* hostname that is not a loopback (`127.0.0.1`) or a DNS name ending in `.ts.net`.  Use a negative look‑ahead: `grep -E '([a-z0-9-]+\.[a-z0-9-]+|[0-9]{1,3}\.)'` and then validate that each match is either `127.0.0.1` or `*.ts.net`. |
| **S9 (C9)** | Capture stderr from each verification command and echo a short, user‑friendly message on failure (e.g., “Audit verification failed – see `homelab-after-windows.export` for details”).  This can be done with `if ! $cmd; then echo "❌ $cmd failed (see $log)"; exit 1; fi`. |
| **S10 (C10)** | Provide a fallback to `python3` (most systems have it) or embed a small Go helper binary in the repo for JSON processing, removing the external Python dependency from the verify steps.  Alternatively, require `python` in the plan’s pre‑conditions (add `python3` to the toolchain checklist). |

---

###### 5. Risk Assessment  

| Overall Risk | Justification |
|--------------|----------------|
| **MEDIUM** | The plan meets the MVP success criteria and includes multiple independent verifications, but several operational edge‑cases (timing of TTL expiry, Windows pipe handling, journal retention) could cause a false failure during a live demo.  None of these gaps compromise the security guarantees (the signer still validates WebAuthn assertions, the CA key is never exposed, and the RP hostname remains protected).  The primary risk is **reproducibility**: a demo could fail for reasons unrelated to the core functionality, leading to a blocked merge or a loss of confidence.  Addressing the concerns listed above reduces the risk to **LOW**. |

---

###### TL;DR
The 02‑14 plan is well‑structured, provides strong end‑to‑end evidence, and respects the project’s security‑first and simplicity constraints.  Minor timing‑sensitivity issues, reliance on exact `ssh‑add` output, and the manual rollback of host configuration are the main points that could cause flaky demos.  Implement the suggested mitigations (especially a retry around the 5 min expiry check, robust key‑ID extraction, and automated host rollback) and the plan will be solid enough to merge without jeopardising the MVP’s security guarantees.

---

## Consensus Summary

### Verification Method
Four external reviewers (codex, nemotron-3-ultra, gemma4:31b, gpt-oss:120b) reviewed the 14 revised Phase 2 plans. Only codex could read the repo. Seven Claude agents, two plans each, then tried to disprove every finding against the current plan text, CONTEXT/RESEARCH, the Phase 1 source and the round-1 appendix. The verifiers ran without a second-model check of their own verdicts.

| Verdict | Round 2 | Round 1 |
|---|---|---|
| ALREADY_COVERED | 107 | 127 |
| REFUTED | 72 | 48 |
| PARTIAL | 18 | 72 |
| CONFIRMED | 1 | 3 |
| **Total** | **198** | **250** |

Of the 19 findings that survived, **none is HIGH, 1 is MEDIUM and 18 are LOW**. Round 1 left 75 (3 MEDIUM, 72 LOW).

**Round-1 fixes held.** All three round-1 MEDIUM findings (02-08-F1 invite race, 02-11-F2 empty principal set, 02-14-F6 TTL-expiry check) are fixed in the revised plans, and codex now names each of those fixes as a strength. Reviewers raised about 30 round-1 findings again; the verifiers found every one fixed or deliberately accepted, except **02-08-F3** (no CI lock on the approved module set), which is still deferred on purpose (02-08-PLAN.md:401).

### Agreed Strengths
These themes are named as strengths by codex (the one reviewer with repo access) and recur in the other reviews. The match to the other reviewers is by theme, not checked claim by claim.
- The signer stays the authority: it re-verifies RP, origin, directory and assertion itself, and logs before releasing a certificate.
- Exact certificate checks in the 02-01 E2E: key, principals, validity window, plus a refusal control.
- Atomic, conditional invite and login-code consumption with concurrent tests under `-race`.
- A fail-closed status cache with one rule for all handlers.
- Serial-correlated evidence in the homelab dogfood plan, and macOS left UNVERIFIED instead of claimed.

### Agreed Concerns (2+ reviewers, by verified severity)

No finding raised by two or more reviewers is above LOW.

**LOW**
- **02-09-R2-F1** (codex MEDIUM, nemotron HIGH): the pending-row check and the signer install are not atomic, so a concurrent `--reinvite` does not stop the install. This was codex's headline finding.
  - Evidence: the race is real, and the plan already lists it as accepted residual T-02-119 (1) (02-09-PLAN.md:474, :213). Only an admin-authenticated request carrying a quorum-signed version can race, and the end state equals the legal order "install, then reinvite". A compromised server bypasses the check anyway, and the signer checks no pending state by design (D-03).
  - What is actually wrong: 02-09-PLAN.md:49, :187 and the runbook text at :337 say "cannot be installed" without the residual. The outcome is silent and untested. The pending row keeps its old user_handle (02-07-PLAN.md:163), so a re-registration on the same authenticator can overwrite the just-bound passkey (availability only).
  - Fix: an in-process mutex shared by the reinvite branch and install steps 3-5, or have `DeleteBound` report a short count and surface a warning. Add one test that defines the winner, and reword the three lines.
- **02-11-R2-F1** (codex, nemotron): host groups do not scope certificates, and the CLI does not say so.
  - Evidence: the runbook states it (02-11-PLAN.md:259) and D-07 locks it, but the `host-group` usage text (02-11-PLAN.md:175-177) does not.
  - Fix: one sentence in the usage text.

### Found During Verification
The only finding above LOW was not stated by any reviewer. The verifier found it while checking two reviewer claims that did not hold.

- **02-13-R2-F4** (MEDIUM; found by the verifier while checking nemotron and gptoss claims): certificate renewal and server reload are not proven on the homelab, and the first run cannot pass as written.
  - Evidence: the cert unit has `ExecStartPost=systemctl reload keyroster-server.service` (02-06-PLAN.md:371). Step 5.3 of 02-13 starts that unit before the server is enabled and requires `Result=success` (02-13-PLAN.md:237, :265). The server cannot start first, because it needs the certificate (02-06-PLAN.md:180). Reloading an inactive unit exits non-zero. Step 5.3 does enable the timer afterwards, but no step runs the unit against the live server and no verify checks that the timer is active, although the plan says "renewed by the timer" (:35, :270).
  - Status: derived from the plan text and systemd semantics, and re-checked by the orchestrator against both plan lines (the reload has no `-` prefix). The unit file does not exist yet and nothing was run. The reviewers' own wording ("no atomic-swap test", "UNVERIFIED until run") did not hold; the verifier found this narrower defect while checking them.
  - Fix: use `try-reload-or-restart` in 02-06. In 02-13, run the cert unit a second time after the server is up and add a timer `is-active` check, or label timer-driven renewal UNVERIFIED.

### Single-Reviewer Verified Concerns
None at HIGH or MEDIUM. All LOW; details and fixes are in the appendix.

- **02-02-R2-F1** (found by the verifier at a line codex cited; codex’s own claim was covered): `TestInboxSSHOffersAgentCert` runs `keyroster.exe agent` "on a test pipe", but the command serves only `PipePath()` and has no override (02-02-PLAN.md:244, :223).
- **02-02-R2-F4** (nemotron): the macOS agent-lifetime test runs only "when ssh-agent is on PATH", and nothing in CI turns a skip into a failure (02-02-PLAN.md:283).
- **02-03-R2-F16** (gptoss): every GetDirectory assertion in 02-03 is for the empty version-0 state; the installed version, bytes, sigs and Authorized flag are not checked until 02-09.
- **02-05-R2-F10** (gptoss): the plan never says `Signer.Status` calls `checkTrustCurrent`, so after an install under a running signer Status could report N+1 while the process still runs on N.
- **02-06-R2-F1** (codex): no serverclient test shows that wrong-hostname and expired-leaf errors are not reported as `ErrTLSRootNotPinned`. Both fail closed.
- **02-06-R2-F12** (gemma; CONFIRMED): a successful certificate reload is not logged.
- **02-07-R2-F2** (gptoss): no line says what `expires` requireAdmin passes to `UseNonce`, so a nonce row could be purged while its signature is still inside the ±120 s window.
- **02-07-R2-F17** (gptoss): a primary-key conflict on concurrent `user add` is not mapped to 409, so the loser may get a 500.
- **02-08-R2-F2** (nemotron): no CI lock on the approved module set. Repeats round-1 02-08-F3, still deferred.
- **02-08-R2-F9** (gptoss): the offered begin options (three algorithms, UV required, attestation none) are a must-have with no test.
- **02-08-R2-F10** (gptoss): enroll refusals have no specified server log line with a reason.
- **02-09-R2-F4** (gptoss): cleanup after an accepted install has no failure path, which can leave an orphaned pending credential. It grants nothing.
- **02-09-R2-F10** (gptoss): `directory sign` has neither `--yes` nor `--admin-key`, yet the plan's own `TestApproveQuorumTwo` (02-09-PLAN.md:277) runs it with no TTY and a second admin key, so that test cannot run as written.
- **02-12-R2-F3** (nemotron, claimed HIGH): "fingerprint shown before WebAuthn" is labelled `verification: test`, but only the server half is tested; the JS ceremony is UNVERIFIED until 02-14 (02-12-PLAN.md:93-95, :531).
- **02-13-R2-F10** (gptoss): RP_HASH12 is an unsalted hash prefix of a hostname the plan says is in CT logs, so committing it links the repo to the hostname.
- **02-14-R2-F13** (gptoss): the diff-guard regex misses a non-tailnet RP hostname, the bare tailnet name and IPv6 (02-14-PLAN.md:349).

### Divergent Views
- **Overall risk ratings converged, but not fully.**
  - codex: MEDIUM for 9 plans, LOW or LOW-MEDIUM for 02-03, 02-04, 02-07, 02-10 and 02-11. In round 1 it rated 11 of 14 HIGH.
  - nemotron: LOW to MEDIUM-HIGH (highest for 02-01 and 02-12), with individual HIGH-labelled concerns in most plans.
  - gemma: LOW for all 14 plans, as in round 1. Its only surviving finding is 02-06-R2-F12, which it raised alone.
  - gptoss: MEDIUM for most plans, HIGH for 02-04.
  - After verification no HIGH claim survived. gptoss's HIGH for 02-04 rests on two claims the plan already covers (RP validation at 02-01-PLAN.md:63, :218; re-check after each bundle_install at 02-04-PLAN.md:149).
- **Notable refutations of HIGH claims:**
  - 37-byte authenticatorData (gptoss, nemotron): Windows Hello sets AT only at registration, not in assertions. The strict check is deliberate and now has a per-authenticator record and owner stop (02-14-PLAN.md:246-249).
  - Concurrent redeem double-issue (gptoss): the burn is one conditional UPDATE accepted only at rows-affected 1, with `concurrent_redeem_once` under `-race` (02-12-PLAN.md:184).
  - Certificate SAN not checked against the RP (gptoss): the server refuses to start unless the leaf passes `VerifyHostname(rp_id)` (02-06-PLAN.md:180).
  - Frame cap versus base64 overhead (nemotron): the wire format is raw u24-prefixed bytes, and the stored maximum fits `MaxDirectoryFrame` with 47 bytes to spare.
  - Windows agent leaves keys in the registry (gptoss): that is the inbox agent, which `keyroster login` never uses.
  - CSRF on the enroll POSTs (gptoss): there is no ambient credential, and 02-06 wraps every route in CrossOriginProtection (02-06-PLAN.md:188).
- **Codex's "check every consumer of the new log kinds" (02-01)** came back clean: `leaf.go`, `audit/verify.go`, `logstate.go` and the fuzz target all change in the 02-01 PR.

### Recommended Plan Changes (for `/gsd-plan-phase 2 --reviews`)
1. [ ] **02-06 / 02-13**: make the cert unit's reload safe when the server is not yet running (`try-reload-or-restart`), run it once more against the live server, and check the timer, or label timer renewal UNVERIFIED. *(MEDIUM, 02-13-R2-F4)*
2. [ ] **02-09**: state the reinvite/install residual where the plan now says "cannot be installed" (:49, :187, :337), define and test the winner, and pick mutex or short-count warning. Give `DeleteBound` a failure path and make it self-healing. Give `directory sign` `--yes`, the no-TTY rule and `--admin-key`. *(02-09-R2-F1, F4, F10)*
3. [ ] **02-02**: say which pipe the process-level tests use, and make a skipped macOS lifetime test fail in CI. *(02-02-R2-F1, F4)*
4. [ ] **02-03**: assert GetDirectory for an installed directory (version, bytes, sigs, Authorized true and false). *(02-03-R2-F16)*
5. [ ] **02-05 / 02-06**: have Status call `checkTrustCurrent`; add TLS error-class tests; log successful certificate reloads. *(02-05-R2-F10, 02-06-R2-F1, F12)*
6. [ ] **02-07 / 02-08**: pin the nonce row lifetime to the signature window; map the `user add` conflict to 409; test the offered begin options; specify a refusal log line. Decide whether the module-set lock stays deferred. *(02-07-R2-F2, F17; 02-08-R2-F2, F9, F10)*
7. [ ] **02-11 / 02-12**: add the host-group scoping sentence to the CLI usage text; relabel the fingerprint-before-WebAuthn prohibition or add a static check on `app.js`. *(02-11-R2-F1, 02-12-R2-F3)*
8. [ ] **02-13 / 02-14**: keep RP_HASH12 out of the committed SUMMARY or salt it; widen the diff-guard regex. *(02-13-R2-F10, 02-14-R2-F13)*

---

## Appendix: Verified Findings (surviving)

CONFIRMED/PARTIAL findings from round 2, by plan. The evidence is the verifier's, with plan-line and source citations. Ids are new for this round (`-R2-`); the "Round 1" line links to round-1 ids where a finding repeats one.

### 02-02

**02-02-R2-F1 — The login path through Ensure is deferred to 02-14; keep CI's test pipe apart from the real login path in the record**
- Reviewers: codex
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The claim as stated is covered. Ensure itself is tested here against a freshly built keyroster.exe (02-02-PLAN.md:242), the real `keyroster.exe login` on Windows runs in 02-14 (02-14-PLAN.md:190-191), and this plan marks nothing complete (`requirements-completed` empty, 02-02-PLAN.md:408). A narrower gap sits at the line codex cites: TestInboxSSHOffersAgentCert step 1 says "run `keyroster.exe agent` on a test pipe" (:244), but the command is specified to serve only PipePath() (:223), and the plan gives it no flag or environment override (:207, :215). The executor must either invent a pipe-name switch on the command or run the test on the user's real per-SID pipe, where a running agent on Daniel-PC makes the second Serve fail (:203). The same applies to the Ensure test at :242, which always dials PipePath().
- Fix: In Task 2, state how the two process-level tests choose their pipe. Either say they use the real per-SID pipe and require that no keyroster agent is running (fail with a clear message otherwise), or define a hidden test-only argument on `keyroster agent` for the pipe name and state that Ensure never passes it. Have needs-hardware.md (Task 3) say which pipe the Daniel-PC evidence used.

**02-02-R2-F4 — No probe of macOS ssh-agent lifetime behaviour**
- Reviewers: nemotron
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The claim is mostly wrong: TestAgentLifetime adds a key and certificate with LifetimeSecs 2 to a real `ssh-agent -D` and checks they are gone after 3 s, and it runs in cli-macos (02-02-PLAN.md:283-288, :279). The narrower gap: the test "runs when `ssh-agent` is on PATH" (:283), and the only guard against a skip is the local WSL verify (:304-305). In CI a skip passes, while needs-hardware.md would still say the macOS agent tests run in CI (:293). macOS ships /usr/bin/ssh-agent, so a skip is unlikely.
- Fix: Give TestAgentLifetime a require switch like KEYROSTER_REQUIRE_INBOX_SSH (for example KEYROSTER_REQUIRE_SSH_AGENT=1 turns the skip into a failure) and set it in build-test and cli-macos.

### 02-03

**02-03-R2-F16 — No GetDirectory round trip for an installed directory**
- Reviewers: gptoss
- Claimed severity: unrated (gptoss gave no per-concern severity; it rated the plan MEDIUM)
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new (02-03-F13 covered only the empty state; fixed for that part)
- Evidence: The reviewer's wording is wrong in one respect: a real-socket GetDirectory call exists (02-03-PLAN.md:141). But every GetDirectory assertion in this plan is for the empty state: case 4 (02-03-PLAN.md:141, 157) and the parser control "the empty version-0 response round-trips" (02-03-PLAN.md:259). Case 4's control installs a directory and logs in but never calls GetDirectory (02-03-PLAN.md:143), and `restart_under_new_admins` never reads the Authorized flag (02-03-PLAN.md:181). So the must-have "returns the installed version, the canonical directory bytes, the signatures and whether the directory is authorized" (02-03-PLAN.md:43) and the success criterion at 02-03-PLAN.md:376 have no test in the plan that introduces the message. The first non-empty check is three plans later (02-09-PLAN.md:236: version 1, authorized); 02-07-PLAN.md:212 and 02-08-PLAN.md:246 are version 0 only, and no sibling plan asserts Authorized=false through GetDirectory (case-insensitive grep over all Phase 2 plans). The exact-cap cases (02-03-PLAN.md:254, 258) exercise ReadMessage/WriteMessage, not the codec. Impact is limited: a wrong encoding fails closed in 02-09's mirror (SHA mismatch) and is caught by 02-09's e2e.
- Fix: In Task 1 case 4, after the control install, assert GetDirectory returns Version 1, Directory byte-equal to the installed canonical bytes, Sigs byte-equal, Authorized=true. In `restart_under_new_admins`, assert GetDirectory Authorized=false (version and bytes still v1) after the restart under admins {b}, and true after v2. Add a non-empty round-trip case to `TestParseGetDirectoryResponse` and require it in the fails_when line.

### 02-05

**02-05-R2-F10 — Status and install can disagree (race / out-of-sync report)**
- Reviewers: gptoss
- Claimed severity: LOW
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: repeats 02-05-F11 (fixed for custody; a narrower point about the bundle and policy fields is left)
- Evidence: The custody half is refuted. Keys and custody are fixed at ca-init and checked against the bundle (internal/signer/trust.go:291-314, `checkBundleKeys`), `ca issue` calls Status fresh each run (02-05-PLAN.md:188), and 02-05-PLAN.md:171 states the invariant. What the plan leaves open is which bundle Status reports after `install-bundle` runs under a live signer. The Signer keeps only `policy` and `bundleVersion` in memory, not the bundle bytes (internal/signer/signer.go:59-74), so Status must read the database. Line 170 says "the trust_bundle row in force" and line 171 says such a signer refuses "every request" with trust_changed, but today only issuance calls `checkTrustCurrent` (internal/signer/issue.go:84, :161, :220), and the plan never says Status does. An implementation that reads the latest row would report bundle and policy N+1 (possibly a new RP) while the process still runs on N. Installs normally run with the signer stopped (02-06-PLAN.md:201), so this needs an operator mistake. Impact is small: issuance still refuses, and the server would only display or start on state the signer is not yet using.
- Fix: In Task 1 "Signer.Status()", add one sentence: Status calls `checkTrustCurrent` under s.mu and returns the trust_changed refusal when the database holds another bundle version than `s.bundleVersion`. Add a case next to the existing trust_changed test that Status refuses after an install under a running signer.

### 02-06

**02-06-R2-F1 — Pin-mismatch errors must be distinguishable from ordinary TLS failures, with a test per case**
- Reviewers: codex
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: repeats 02-06-F1 and 02-06-F10 (both fixed; this is the residual)
- Evidence: Most of it is covered: the out-of-band reference is required (02-06-PLAN.md:386, T-02-25 at :529), `ErrTLSRootNotPinned` and `ErrTrustRootNotPinned` carry recovery steps (:217-219, :212-215), and tests exist for an unpinned root, a root-pin mismatch and intermediate rotation (:293-297). Two things are missing. (a) Line 220 says expired-leaf and wrong-hostname errors "keep their own messages", but no serverclient case asserts that; the tlsreload cases at :338 test the server side only. (b) Line 218 maps every `x509.UnknownAuthorityError` to "root not pinned". With RootCAs holding only the root, a server that stops sending its intermediate fails with the same error, so the user is sent into the re-pin procedure for a server misconfiguration. Both fail closed and the re-pin still needs an out-of-band comparison, so there is no security impact, only a misleading diagnosis.
- Fix: In Task 2 serverclient tests add `wrong_hostname_not_root_error` and `expired_leaf_not_root_error` (neither satisfies `errors.Is(err, ErrTLSRootNotPinned)`), and `missing_intermediate_reports_root_error` documenting the known overlap. Extend the ErrTLSRootNotPinned message and the runbook "TLS root changed" section with "or the server is not sending its full chain".

**02-06-R2-F12 — A successful certificate reload is not logged with the certificate's identity**
- Reviewers: gemma
- Claimed severity: LOW (suggestion)
- Verdict: CONFIRMED
- Verified severity: LOW
- Round 1: new
- Evidence: The plan specifies logging only for the failure and near-expiry paths: "keeps the old one, logs an error" (02-06-PLAN.md:270) and the 14-day warning (:272, :56). Nothing says a successful swap, on file change or on SIGHUP, is logged, and no test checks one. An operator reading `journalctl -u keyroster-server` after a renewal therefore cannot tell from the log which certificate is now served. No security impact; it is an operations gap that one log line closes.
- Fix: In Task 2 tlsreload, log at info on every successful Reload and at start with the leaf's SHA-256 fingerprint, NotAfter and the trigger (start, file change, SIGHUP). Assert the line in the "Reload swaps in a new valid certificate" case.

### 02-07

**02-07-R2-F2 — Nonce single-use can be raced; no cleanup of expired nonces**
- Reviewers: gptoss
- Claimed severity: not stated (named as a main risk)
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new (the race half overlaps 02-07-F1, fixed)
- Evidence: The race as described is wrong. `admin_nonces(nonce TEXT PRIMARY KEY)` (02-07-PLAN.md:159) and `UseNonce` is "insert; a duplicate means replay; it also deletes expired rows" (02-07-PLAN.md:161), on one connection (02-07-PLAN.md:160; same pattern as internal/signerdb/db.go:49), and `nonce_replay_parallel` requires exactly one non-401 (02-07-PLAN.md:252). Cleanup also exists (02-07-PLAN.md:161, tested at :275). What the plan does leave open is next to this: `UseNonce(nonce, expires, now)` takes `expires` as a parameter and no line says what value requireAdmin passes (02-07-PLAN.md:161, :180). A request is valid while |now - t| <= 120 s (02-07-PLAN.md:152), so a row that expires at "now + 120 s" for a request stamped up to 120 s ahead is deleted while the signature is still inside the window, and a captured copy would pass again. Exploiting it needs a captured TLS request, and pending rows grant nothing, hence LOW.
- Fix: In 02-07 Task 1 state that requireAdmin passes `expires = signed time + 2*MaxSkew` (or `now + 2*MaxSkew`), so a nonce row always outlives its signature's validity. Add an admin_test case `nonce_replay_after_cleanup`: a request stamped +120 s, first use, clock advanced 121 s with another UseNonce call to trigger the purge, replay still gets 401.

**02-07-R2-F17 — No test for two concurrent `user add` calls for the same name**
- Reviewers: gptoss
- Claimed severity: not stated
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The same-nonce half is covered by `nonce_replay_parallel` (02-07-PLAN.md:252). For two differently signed requests, the handler looks the name up and then inserts as separate steps (02-07-PLAN.md:185-191), and the plan does not say that `CreatePendingUser` maps a primary-key conflict on `pending_users.name` (02-07-PLAN.md:159) to the 409 the plan promises for a pending name (02-07-PLAN.md:47). The outcome is safe either way, because the primary key prevents a second row and a second invite; the only open point is a 500 instead of a 409 for the loser, which the CLI would not render as `already pending` (02-07-PLAN.md:282). The suggested "deadlock" has no basis with single-statement writes.
- Fix: In 02-07 Task 1, say `CreatePendingUser` returns `ErrExists` on a name conflict and the handler answers 409. Add an admin_test case `concurrent_add_same_name`: two validly signed requests for one name in parallel give one 201 and one 409, and one pending_users row.

### 02-08

**02-08-R2-F2 — No CI lock on the approved module set**
- Reviewers: nemotron
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: repeats 02-08-F3 (not fixed; deferred on purpose)
- Evidence: The plan records the deferral and its reasons at 02-08-PLAN.md:401. The compensating controls are real in the repo: `go mod verify` (.github/workflows/ci.yml:32), dep-firewall (.github/workflows/ci.yml:100), the capslock job (.github/workflows/ci.yml:104-119), CODEOWNERS and Dependabot gomod updates arriving only as PRs (.github/dependabot.yml). A new module therefore cannot land without the owner seeing the go.mod diff; what is missing is only a machine check that turns an unnoticed diff into a failed build. Unchanged from round 1 and still optional.
- Fix: none for this plan; keep it as the repo-wide CI-hardening item named at 02-08-PLAN.md:401 (an approved-modules list compared with `go list -m all`).

**02-08-R2-F9 — Allowed algorithms rest on a go-webauthn helper with no explicit whitelist**
- Reviewers: gptoss
- Claimed severity: LOW
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The security half is wrong. What is accepted does not depend on the library's default: finish converts the key and refuses anything `webauthn.ParsePublicKey(alg, spki)` rejects (02-08-PLAN.md:216), with `es384_refused` and `rsa1024_refused` as tests (02-08-PLAN.md:280-281, :325). The helper today returns exactly EdDSA, ES256, RS256 (go-webauthn v0.18.2 `webauthn/registration_credential_parameters.go:58-72`), and a version bump goes through owner review. The narrower true part: the must-have at 02-08-PLAN.md:38 fixes the offered options (attestation none, UV required, residentKey preferred, three algorithms), but no test in Task 2 or Task 3 asserts the begin response, so a drift in the offered list would only show up as a failed registration.
- Fix: Add an enroll_test case `begin_options_exact` in Task 3: the begin JSON has `pubKeyCredParams` algs exactly [-8, -7, -257], `attestation` "none", `authenticatorSelection.userVerification` "required" and `residentKey` "preferred".

**02-08-R2-F10 — Registration refusals and COSE-to-SPKI errors are not logged**
- Reviewers: gptoss
- Claimed severity: LOW
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: 02-07 specifies a server log line for every admin-auth failure (02-07-PLAN.md:180), but 02-08 has no sentence about logging in enroll.go: finish steps 2-6 say what status is returned (02-08-PLAN.md:212-218) and nothing about a log line (a grep of 02-08 for slog/log line/logged finds only "never logged" for the token at :208, and 02-06 defines no request log, only certificate-reload messages at 02-06-PLAN.md:56, :270). So an operator cannot tell from the server which refusal a user hit, or see repeated failed finishes on one invite. The reviewer's second claim, that this should go into the Merkle audit log, is wrong: that log is the signer's and a pending credential grants nothing (02-08-PLAN.md:79). No security property depends on the log line.
- Fix: In 02-08 Task 2 (enroll.go), add: every begin/finish refusal logs one slog line with a reason code (`session_not_found`, `verify_failed`, `unsupported_credential`, `duplicate_credential`, `invite_not_valid`), the user name and the underlying error, never the token or the challenge.

### 02-09

**02-09-R2-F1 — Pending check and signer install are not atomic; a concurrent reinvite does not stop the install**
- Reviewers: codex, nemotron
- Claimed severity: codex MEDIUM, nemotron HIGH
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new (ties to round-1 consensus item 7, reinvite semantics; no F-id)
- Evidence: The race is real and the plan admits it. 02-09-PLAN.md:186 checks `PendingCredentialUser`, :190 calls the signer in a separate step, and T-02-119 residual 1 at 02-09-PLAN.md:474 says "the check and the forward are not one transaction, so a reinvite landing in the milliseconds between them does not stop that install"; :213 names the same window on the direct path. The signer checks no pending state by design (02-09-PLAN.md:188, :474 residual 2; 02-CONTEXT.md:48 D-03), so the server check is the only gate. What the race allows is small: only a request that passes `requireAdminLimit` (admin SSHSIG) and carries a quorum-signed version can race, the credential it binds is one an admin signed after the fingerprint comparison, and the end state equals the legal serial order "install, then reinvite" (reinvite never unbinds an approved credential, 02-07-PLAN.md:187-188). `DeleteBound` (02-09-PLAN.md:192) then deletes nothing, because 02-08's `ReplaceInvite` already removed the row (02-08-PLAN.md:203), and the reinvited pending row with its open invite survives. No party in the threat model gains anything: a compromised server skips the check entirely (residual 2). The concrete gaps are narrower: (a) the must-have at 02-09-PLAN.md:49 ("can therefore not be installed through the server"), :187 ("makes a reinvite final") and the runbook text at :337 ("The server refuses to install it") are stated without the residual that :474 admits; (b) the outcome is silent and untested, so the admin who ran `--reinvite` was told the old passkey is no longer valid (02-08-PLAN.md:221) while it was bound; (c) one side effect differs from the serial order: the pending row keeps its old user_handle (02-07-PLAN.md:163), so a re-registration on the same authenticator can replace the just-bound passkey there, leaving a bound but unusable credential (availability only).
- Fix: Keep the design; do not add a reservation state machine. Either (1) close the window with one in-process mutex in internal/server taken by the reinvite branch of `POST /api/v1/admin/users` and by install steps 3-5 (this does not hold the DB connection across the signer call, so it is not the option :474 rejected), or (2) keep the residual and make it visible: have `DeleteBound` return how many of `newlyBound` it deleted, and when fewer than `len(newlyBound)`, log `bound_credential_not_pending` and add a warning to the install response that the CLI prints. In both cases add one test in admin_test.go where the fake signer's InstallDirectory runs a reinvite before returning, asserting the defined winner, and reword :49, :187 and :337 to "a reinvite that completed before the install request".

**02-09-R2-F4 — Cleanup after an accepted install has no defined failure path, leaving an orphaned pending credential**
- Reviewers: gptoss
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: related to 02-09-F6 (fixed for narrowness and transactionality); this failure path is new
- Evidence: 02-09-PLAN.md:191 says "On success, call `serverdb.DeleteBound(...)` and return" and gives no answer for a `DeleteBound` error; the same orphan arises when the signer installed but the transport failed, since :190 treats that outcome as unknown and step 5 does not run. The orphan is never cleaned by a later install: its id is then in the base, so it is never in `newlyBound` again (02-09-PLAN.md:185). Impact is limited: a pending row grants nothing (02-09-PLAN.md:188), a second `user approve` is refused by the duplicate-id rule (02-01-PLAN.md:235) instead of the "no pending credential" text the idempotency truth promises (02-09-PLAN.md:44), and `user add --reinvite` clears it (02-08-PLAN.md:203). The real gaps are an unspecified HTTP answer (a 500 after a successful install misleads the admin) and a stale `pending` list in `GET /api/v1/admin/users` (:194).
- Fix: State in step 5 that a `DeleteBound` error is logged and the handler still answers 200 with the install result. Make cleanup self-healing: `DeleteBound` deletes pending credentials whose id is bound in the installed version (all ids of the posted version, not only `newlyBound`), keeping the pending-account rule of :192 unchanged; a credential id in the directory cannot be pending for anyone else (02-08 `credential_id_in_directory_refused`). Add a case `cleanup_failure_still_reports_install` or `orphan_pending_cleaned_on_next_install`.

**02-09-R2-F10 — No non-interactive confirmation for `directory sign`**
- Reviewers: gptoss
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The reviewer's request for a `--diff-file` flag has no basis; `--yes` exists on the edit path (02-09-PLAN.md:209, :228). The narrower gap is real: `directory sign` must "print Diff against the installed base and confirm" (:220), but the CLI list gives it no flag at all (`keyroster directory sign DIR`, :419), neither `--yes` nor `--admin-key`, and no text says what it does without a TTY. The plan's own e2e runs it with no TTY and with a second admin's agent key (TestApproveQuorumTwo, :277), so the test cannot run as written. An executor would add the flag, but the no-TTY rule for a signing command should not be improvised.
- Fix: In 02-09 Task 1, define `keyroster directory sign DIR [--yes] [--admin-key SHA256:...]` with editDirectory's rule from :209 (TTY prompt, `--yes` to skip it, refuse with neither) and update :419. State that `directory install` asks nothing because it signs nothing.

### 02-11

**02-11-R2-F1 — Host groups do not scope certificates; operators could mistake a mapping for signer-enforced host restriction**
- Reviewers: codex, nemotron
- Claimed severity: LOW (codex), MEDIUM (nemotron)
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: This is locked decision D-07 (02-CONTEXT.md:72: "In Phase 2 they enforce nothing by themselves, because certificates are not host-scoped"), so it is not a design defect. The plan states it in the runbook (02-11-PLAN.md:259: "certificates are not host-scoped, so a host trusts any principal its file lists") and in Edge Coverage (02-11-PLAN.md:320). What is missing is only codex's CLI half: the `host-group add|map|unmap` command spec (02-11-PLAN.md:175-177) defines no help or confirmation text saying that a mapping changes only the rendered file. Nemotron's MEDIUM is not borne out; it names no missing element beyond "documented".
- Fix: In 02-11 Task 2, add one sentence to the `host-group` usage text (and so to `--help`): "Host groups only decide what `keyroster host principals` renders; they do not restrict which hosts a certificate works on." Add `host-scoped` or that sentence to the Task 3 acceptance grep for the usage string.

### 02-12

**02-12-R2-F3 — "Page never invokes WebAuthn before showing the fingerprint. Verified in tests."**
- Reviewers: nemotron
- Claimed severity: HIGH
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The security property is sound and its server half is tested: the fingerprint is computed from the stored request bytes and rendered server-side in the HTML (02-12-PLAN.md:203), the challenge is the digest of the same bytes (02-12-PLAN.md:48, 205), and the e2e asserts the CLI's fingerprint appears verbatim in the page HTML (02-12-PLAN.md:258, 275). The reviewer's "verified in tests" is only half true, though. The JS half ("never invokes WebAuthn before it has shown the fingerprint") has no automated check: the e2e drives the flow without a browser, and the plan itself labels the page's JS ceremony "UNVERIFIED until 02-14" (02-12-PLAN.md:531). Yet the prohibition is recorded as `status: resolved`, `verification: test` (02-12-PLAN.md:93-95). That is a labelling inconsistency under the project's no-unexercised-paths rule, not a shipped defect: `navigator.credentials.get` runs only from the Approve click (02-12-PLAN.md:229) on a page whose fingerprint is already in the markup.
- Fix: In 02-12, either (a) change that prohibition's verification to "test (server half: fingerprint from stored bytes, in the HTML before any script runs) + manual in 02-14 (JS ordering)", or (b) add a static Task 1 acceptance check that makes the JS half mechanical, for example that in app.js the `#kr-approve` code calls `navigator.credentials.get` only inside the Approve button's click handler and that login_approve.html places the fingerprint element before the Approve button with the button not auto-activated.

### 02-13

**02-13-R2-F4 — tailscale cert renewal and server reload are not proven on the homelab**
- Reviewers: nemotron, gptoss
- Claimed severity: MEDIUM
- Verdict: PARTIAL
- Verified severity: MEDIUM
- Round 1: new
- Evidence: Gptoss's claim (no test that the certificate swap is atomic) is wrong: 02-06 specifies a certHolder with validated reload, last-good fallback and SIGHUP, with named tests (02-06-PLAN.md:269-271, :338). Nemotron's "UNVERIFIED until the 02-13 run" is accurate, and checking it exposes a narrower real gap that neither reviewer stated. 02-06 defines the cert unit with an `ExecStartPost` that runs `systemctl reload keyroster-server.service` (02-06-PLAN.md:371), while 02-13 step 5.3 starts that unit once before keyroster-server is enabled and requires `Result=success` (02-13-PLAN.md:237, acceptance at :265). The server cannot be started first, because it refuses to start without a certificate covering rp_id (02-06-PLAN.md:180). `systemctl reload` of an inactive unit exits non-zero, so as the two plans are written the first run ends with a failed ExecStartPost and the required `Result=success` cannot appear. This is derived from the plan text and systemd semantics; the unit file does not exist yet and nothing was run. Separately, the plan calls the certificate "renewed by the timer" and "renewing" (02-13-PLAN.md:35, :270), but no step runs the unit against the live server, and no verify checks that the timer is active (02-13-PLAN.md:253 checks only the server). The failure is loud and has no security impact, but it stops the rollout after v3 is installed and would ship a first-install step that fails in server-install.md.
- Fix: In 02-06, make the reload line tolerant of an inactive server (`ExecStartPost=/usr/bin/systemctl try-reload-or-restart keyroster-server.service`, which does nothing when the unit is not running). In 02-13 step 5.3, after the server is enabled, start keyroster-tailscale-cert.service a second time and require `Result=success` plus a reload line in the keyroster-server journal, so the renewal-and-reload path runs once against the live server. Add `systemctl is-active keyroster-tailscale-cert.timer` to the Task 2 verify. If the second run is not added, label timer-driven renewal UNVERIFIED in server-install.md and drop "renewing" from the done line.

**02-13-R2-F10 — RP_HASH12 in the committed SUMMARY can be reversed**
- Reviewers: gptoss
- Claimed severity: LOW
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new (the hash was introduced by the round-1 fix for 02-13-F14)
- Evidence: The plan forbids any homelab hostname or tailnet name in a committed file (02-13-PLAN.md:57, T-02-67 at :418) and commits RP_HASH12 in the SUMMARY instead (02-13-PLAN.md:330). RP_HASH12 is an unsalted SHA-256 prefix of the lowercase FQDN (02-13-PLAN.md:135), and the plan itself states that the FQDN is published in Certificate Transparency logs (02-13-PLAN.md:141, T-02-69 at :421). Anyone can hash the `*.ts.net` names in CT and match the 48-bit prefix, which links the public repository to the exact machine and tailnet name. So the prohibition's intent is not met by the hash. The impact is small: the name is already public and is reachable only inside the tailnet. Gptoss's wording about "logs or alerts" is off; the exposure is the committed SUMMARY.
- Fix: Keep RP_HASH12 in the checkpoint message and in kr.env only (02-13-PLAN.md:246 already stores it), and write "RP hostname hash recorded in kr.env" in the SUMMARY. Alternatively record an explicit accept line under T-02-67 stating that the hash prefix is linkable through CT logs.

### 02-14

**02-14-R2-F13 — The diff guard only catches `*.ts.net` names and IPv4 addresses**
- Reviewers: gptoss
- Claimed severity: not stated
- Verdict: PARTIAL
- Verified severity: LOW
- Round 1: new
- Evidence: The guard is the regex `[a-z0-9-]+\.[a-z0-9-]+\.ts\.net|([0-9]{1,3}\.){3}[0-9]{1,3}` on added lines (02-14-PLAN.md:349; the same in 02-13-PLAN.md:259 and :345). It backs a prohibition marked `verification: test` that covers every homelab hostname, FQDN, address and tailnet name (02-14-PLAN.md:53-55, 02-13-PLAN.md:57-59). Three cases pass the guard: a non-tailnet RP hostname, which 02-13's "other-name" option allows (02-13-PLAN.md:152-156); the bare tailnet name without the machine label; and an IPv6 address. The owner's review at the merge gate is a second check ("Check that no hostname or address appears", 02-14-PLAN.md:375, 02-13-PLAN.md:367), so the gap is narrow. Gptoss's replacement regex would match almost any dotted word and is not usable.
- Fix: In both plans, add a literal check next to the pattern. At execution the confirmed FQDN is in a shell variable, so split it into the machine label, the tailnet label and the full name, and fail when `git diff origin/main` adds a line containing any of them (`grep -iF`). For the "other-name" option, use the owner-supplied name the same way.

### Refuted (R) or already covered (C), ids only

02-01-R2-F1 (C), 02-01-R2-F2 (R), 02-01-R2-F3 (R), 02-01-R2-F4 (C), 02-01-R2-F5 (R), 02-01-R2-F6 (C), 02-01-R2-F7 (C), 02-01-R2-F8 (C), 02-01-R2-F9 (R), 02-01-R2-F10 (R), 02-01-R2-F11 (R), 02-01-R2-F12 (C), 02-01-R2-F13 (C), 02-01-R2-F14 (C), 02-01-R2-F15 (R), 02-01-R2-F16 (C), 02-02-R2-F2 (C), 02-02-R2-F3 (C), 02-02-R2-F5 (C), 02-02-R2-F6 (C), 02-02-R2-F7 (C), 02-02-R2-F8 (R), 02-02-R2-F9 (R), 02-02-R2-F10 (C), 02-02-R2-F11 (R), 02-02-R2-F12 (R), 02-02-R2-F13 (R), 02-02-R2-F14 (R), 02-03-R2-F1 (C), 02-03-R2-F2 (R), 02-03-R2-F3 (C), 02-03-R2-F4 (C), 02-03-R2-F5 (R), 02-03-R2-F6 (C), 02-03-R2-F7 (C), 02-03-R2-F8 (R), 02-03-R2-F9 (R), 02-03-R2-F10 (R), 02-03-R2-F11 (R), 02-03-R2-F12 (R), 02-03-R2-F13 (C), 02-03-R2-F14 (C), 02-03-R2-F15 (R), 02-04-R2-F1 (C), 02-04-R2-F2 (C), 02-04-R2-F3 (R), 02-04-R2-F4 (C), 02-04-R2-F5 (C), 02-04-R2-F6 (C), 02-04-R2-F7 (C), 02-04-R2-F8 (C), 02-04-R2-F9 (C), 02-04-R2-F10 (R), 02-04-R2-F11 (R), 02-04-R2-F12 (R), 02-04-R2-F13 (C), 02-05-R2-F1 (C), 02-05-R2-F2 (C), 02-05-R2-F3 (C), 02-05-R2-F4 (R), 02-05-R2-F5 (C), 02-05-R2-F6 (C), 02-05-R2-F7 (R), 02-05-R2-F8 (R), 02-05-R2-F9 (C), 02-05-R2-F11 (R), 02-05-R2-F12 (C), 02-05-R2-F13 (R), 02-05-R2-F14 (R), 02-05-R2-F15 (R), 02-05-R2-F16 (R), 02-05-R2-F17 (C), 02-06-R2-F2 (C), 02-06-R2-F3 (C), 02-06-R2-F4 (C), 02-06-R2-F5 (C), 02-06-R2-F6 (R), 02-06-R2-F7 (C), 02-06-R2-F8 (R), 02-06-R2-F9 (R), 02-06-R2-F10 (C), 02-06-R2-F11 (C), 02-07-R2-F1 (C), 02-07-R2-F3 (C), 02-07-R2-F4 (R), 02-07-R2-F5 (R), 02-07-R2-F6 (C), 02-07-R2-F7 (C), 02-07-R2-F8 (R), 02-07-R2-F9 (R), 02-07-R2-F10 (R), 02-07-R2-F11 (C), 02-07-R2-F12 (R), 02-07-R2-F13 (R), 02-07-R2-F14 (R), 02-07-R2-F15 (R), 02-07-R2-F16 (C), 02-08-R2-F1 (C), 02-08-R2-F3 (C), 02-08-R2-F4 (C), 02-08-R2-F5 (C), 02-08-R2-F6 (R), 02-08-R2-F7 (R), 02-08-R2-F8 (C), 02-08-R2-F11 (R), 02-08-R2-F12 (C), 02-08-R2-F13 (C), 02-09-R2-F2 (R), 02-09-R2-F3 (R), 02-09-R2-F5 (R), 02-09-R2-F6 (C), 02-09-R2-F7 (C), 02-09-R2-F8 (R), 02-09-R2-F9 (C), 02-09-R2-F11 (C), 02-09-R2-F12 (C), 02-09-R2-F13 (C), 02-09-R2-F14 (C), 02-10-R2-F1 (C), 02-10-R2-F2 (C), 02-10-R2-F3 (C), 02-10-R2-F4 (C), 02-10-R2-F5 (R), 02-10-R2-F6 (C), 02-10-R2-F7 (R), 02-10-R2-F8 (C), 02-10-R2-F9 (R), 02-10-R2-F10 (R), 02-11-R2-F2 (C), 02-11-R2-F3 (C), 02-11-R2-F4 (C), 02-11-R2-F5 (R), 02-11-R2-F6 (R), 02-11-R2-F7 (C), 02-11-R2-F8 (C), 02-11-R2-F9 (R), 02-11-R2-F10 (R), 02-11-R2-F11 (C), 02-11-R2-F12 (C), 02-12-R2-F1 (C), 02-12-R2-F2 (C), 02-12-R2-F4 (C), 02-12-R2-F5 (C), 02-12-R2-F6 (C), 02-12-R2-F7 (C), 02-12-R2-F8 (R), 02-12-R2-F9 (R), 02-12-R2-F10 (C), 02-12-R2-F11 (C), 02-12-R2-F12 (C), 02-12-R2-F13 (C), 02-12-R2-F14 (C), 02-12-R2-F15 (C), 02-13-R2-F1 (C), 02-13-R2-F2 (C), 02-13-R2-F3 (C), 02-13-R2-F5 (R), 02-13-R2-F6 (R), 02-13-R2-F7 (R), 02-13-R2-F8 (R), 02-13-R2-F9 (C), 02-13-R2-F11 (C), 02-13-R2-F12 (R), 02-13-R2-F13 (C), 02-14-R2-F1 (C), 02-14-R2-F2 (C), 02-14-R2-F3 (R), 02-14-R2-F4 (C), 02-14-R2-F5 (C), 02-14-R2-F6 (C), 02-14-R2-F7 (C), 02-14-R2-F8 (R), 02-14-R2-F9 (C), 02-14-R2-F10 (R), 02-14-R2-F11 (R), 02-14-R2-F12 (C), 02-14-R2-F14 (C), 02-14-R2-F15 (R), 02-14-R2-F16 (C)

The full verdict and evidence for each id is in the verifier files under `.review-diagnostics/` for this run (`verify/verify-02-NN_02-NN.md`). That directory is local and not committed.
