---
phase: 03-linux-agent-and-revocation
plan: 14d
type: execute
wave: 31
depends_on: ["03-14c"]
files_modified:
  - internal/wire/issue.go
  - internal/wire/wire_test.go
  - internal/wire/fuzz_test.go
  - internal/wire/machineissue_test.go
  - internal/wire/installation_test.go
  - test/vectors/issue_request_signing_v1.hex
  - test/vectors/issue_request_signing_v2.hex
  - internal/signer/issue.go
  - internal/signer/evidence.go
  - internal/signer/refusal.go
  - internal/signer/fixture_test.go
  - internal/signer/log_test.go
  - internal/signer/revoke_test.go
  - internal/signer/revoke_host_test.go
  - internal/signer/issue_installation_test.go
  - cmd/keyroster/ca.go
  - cmd/keyroster/ca_test.go
  - cmd/keyroster/ca_status_test.go
  - test/e2e/bootstrap_test.go
  - test/e2e/negative_test.go
  - test/e2e/pkcs11_test.go
  - test/e2e/stall_test.go
  - docs/runbooks/signer-install.md
  - test/manual/README.md
  - docs/format-registry.md
  - .planning/phases/03-linux-agent-and-revocation/03-14d-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [REVOKE-01, AGENT-06, AUTH-06]

estimate:
  tokens: 220000
  raw_tokens: 220000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-10-29, 2026-11-05 and 2026-11-13): F15 is fixed in this plan, split from 03-14c (Q-C9), with its own threat IDs from T-03-359. It lands directly after 03-14c and before 03-12, at wave 31, the wave of 03-12 on origin/main at 62b4407 (03-14c merged as #99; the stop guard checks it). Q-C2 = A, Q-C8 = accept, Q-D1 = A (exemptions with the owner's reasons) and OQ-1 = A (ca issue takes the ID from its flag only) are decided; no owner question is open"
    - "F15 (Q-C2 A). An admin issue request names the installation it is for: keyroster/issue-request/v2 signs the installation ID first. The signer refuses, after the freshness check and before the admin evidence or any CA key: a request without an ID where its bundle names one (issue_installation_missing), another ID (issue_installation_mismatch), an ID where its bundle names none (issue_installation_unknown). A request whose ID was rewritten after signing is refused by the evidence check. The v1 signing bytes, the v1 body and the v1 constants are unchanged byte for byte, and v1 still issues where the signer's bundle names no installation (the D-04 directory rule). This leaves one replay open, as the owner accepted: an installation whose bundle names no ID accepts any v1 request signed by an admin key its policy lists, including one made for an installation with an ID and refused there"
    - "`keyroster ca issue --installation-id` sets the ID; it is never taken from the signer, and never from or checked against the CLI config's pin (OQ-1 = A). ca issue adds a hint to the three refusals, and to malformed_request when the flag was set, because a signer older than this plan refuses a v2 body that way (reasoned from the parser; UNVERIFIED against a real older signer). keyroster-signer and keyroster are upgraded together before admins pass the flag"
    - "Every keyroster/ string literal in the module's non-test code and every SigningBytes type in internal/wire is classified by one test (TestSignedRequestsBindInstallation): a type's signing bytes change with its InstallationID field, set through reflection; a wire tag classified bound must be carried by its type's signing bytes; a tag outside internal/wire is classified, not proven, and names the test that pins its binding; otherwise a tag is exempt with a recorded reason, or not a request tag. The exemptions are LoginIssueRequest (Q-C8, an owner-recorded residual that assumes each installation has its own RP hostname), adminauth.Message and the agent-identity rotation message (Q-D1 = A, owner-approved). The PoP request types of 03-09 to 03-11 are bound (D5). A tag without the keyroster/ prefix is outside the walk"
    - "Audit verify cannot check which installation an issue request named, because an issue leaf keeps only the request digest; no leaf format changes. A weaker check (refusing v1-namespace evidence after a bundle with an ID) would catch a signer bug, not a compromised signer, and is deferred on purpose (T-03-361)"
    - "Outputs and formats: no trust bundle field, leaf format or root sign output changes. The only signing-format change is IssueRequest v2, recorded through the format registry when it is on main. Every test uses software keys; no hardware is needed"
  artifacts:
    - path: "internal/wire/issue.go"
      provides: "IssueRequest.InstallationID, IssueRequestDomainV2, AdminSSHSIGNamespaceV2, Namespace(), the v2 encoding"
      contains: "IssueRequestDomainV2"
    - path: "internal/signer/issue.go"
      provides: "the issue installation rule before evidence and CA use"
      contains: "issue_installation_mismatch"
    - path: "cmd/keyroster/ca.go"
      provides: "ca issue --installation-id and the four hints"
      contains: "installation-id"
    - path: "internal/wire/installation_test.go"
      provides: "the pinned table of every signed request type in internal/wire and every keyroster/ string literal in the module"
      contains: "func TestSignedRequestsBindInstallation("
    - path: "test/vectors/issue_request_signing_v2.hex"
      provides: "the v2 signing bytes, derived from the v1 vector"
  key_links:
    - from: "internal/signer/issue.go"
      to: "internal/wire/issue.go"
      via: "Signer.Issue compares req.InstallationID with s.installationID and verifies the evidence under req.Namespace()"
      pattern: "req.InstallationID"
    - from: "cmd/keyroster/ca.go"
      to: "internal/wire/issue.go"
      via: "ca issue signs the request under its own namespace (v1 or v2)"
      pattern: "req.Namespace()"
    - from: "internal/signer/evidence.go"
      to: "internal/wire/issue.go"
      via: "verifyAdminEvidence verifies under the request's namespace"
      pattern: "req.Namespace()"
  prohibitions:
    - statement: "This plan changes no trust bundle field or field order, no audit-log leaf format, no KRL, manifest or directory format, no output of root sign, trust verify or audit verify, and no other signed format than IssueRequest's. The v1 signing bytes, body and constants stay byte for byte. It adds no module, and no test or step needs hardware"
      status: resolved
      verification: test
---

<objective>
An admin's approval of a certificate is valid only in the installation it names. An installation whose policy lists the same admin key refuses a request approved for another one before its CA signs, and a request whose installation ID was changed after signing fails the signature check. Every `keyroster/` string literal and every signed request type in internal/wire is classified by one test, so a new wire format either names the installation it is for or carries a recorded exemption, and a new tag elsewhere must at least be classified.

Purpose:
- **F15.** Today an admin's issue request names no installation, and Signer.Issue never compares the request with its bundle's installation ID, so an installation whose policy lists the same admin key issues from a replay within the 300 s window. Revoke v2, forget and recovery requests already name the installation, and the signer refuses a mismatch.
- **The classification (D5 and the format registry's rule).** Installation binding is a rule for every new signed format. This plan makes it a test: the PoP request types of 03-09 to 03-11 are checked, and the formats outside internal/wire that carry no installation ID are named with their reasons instead of being left out.
- **Requirements.** REVOKE-01 (revoke requests stay bound, pinned by the table), AGENT-06 (HostIssueRequest bound, D5) and AUTH-06 (MachineIssueRequest bound, D5). REVOKE-01 and AUTH-06 are complete (03-11b); AGENT-06 is pending, owned by its PoP plans; this plan pins their binding. F15 itself hardens KEY-02 (the signer verifies an issue request's evidence itself), outside Phase 3's IDs.

Output:
- IssueRequest v2 with the signer's rule and `ca issue --installation-id`;
- two vectors, the v2 one derived from the v1 one by a stated rule that a test checks;
- fuzz seeds for the new parse branch;
- the pinned table of every signed request type and every `keyroster/` string literal;
- named tests committed RED first, with mutants;
- the runbook and test/manual updates, the registry rows, two pointer sentences (03-12 and 03-15), the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Fix home (Daniel, 2026-10-29), and the split (Q-C9, 2026-11-05).** F15 was planned with F05 and F06 in 03-14c. After plan check 1 of 03-14c, the owner split it: this plan, 03-14d, takes F15 (IssueRequest v2, `ca issue --installation-id`, and the test that every signed request type is binding-checked), and lands directly after 03-14c and before 03-12. It has its own threat IDs, from T-03-359.
- **Roots are per installation (Daniel, before planning).** F15's condition is different: two installations whose policies list one admin key. The owner's answer about roots does not cover it, and the severity stays low.
- **Q-C2 = A: IssueRequest v2, lenient where the bundle names none (Daniel, 2026-11-05).** The installation ID is signed first; v1 is accepted only where the bundle has no ID; the ID comes from a `ca issue` flag, never from the signer. The facts the owner decided on, as corrected by plan check 1:
  - A closes the replay wherever the target's bundle names an ID. It leaves one replay open: an installation whose bundle names no ID accepts any v1 request signed by an admin key its policy lists, including one made for an installation with an ID and refused there (a flagless request from a new CLI, or any request from an older one). B (refuse every admin issue request where the bundle names none) would have closed it. This statement was widened in plan check 1 of 03-14d; the decision stands;
  - 03-09's HostIssue rule is strict: it refuses a bundle without an installation ID (03-09's revision, `host_issue_no_installation_id`), the B-like precedent;
  - B's operational cost before 03-15 is about zero: no plan from 03-13 to 03-16 runs `ca issue`, and 03-12's e2e genesis always has an ID; only unplanned admin issuance on the homelab and ID-less test fixtures would have been affected;
  - a signer older than this plan refuses a v2 body as malformed_request, because its parser refuses any byte after the evidence (internal/wire/issue.go, `!s.Empty()`), with no hint; and once a signer whose bundle names an ID is upgraded, every `ca issue` without the flag is refused. keyroster-signer and keyroster are installed together from one build (signer-install.md section 2), so both are upgraded before admins pass the flag, and ca issue adds a hint on malformed_request when the flag was set. A keyroster CLI older than the signer cannot send the flag and is refused issue_installation_missing without a hint;
  - an issue leaf keeps only the request digest, the evidence and the certificate (tlog.IssueBody), so audit verify cannot check which installation a request named without a leaf format change;
  - `keyroster ca issue` talks only to the signer socket and reads no CLI config (cmd/keyroster/ca.go; signer-install.md section 8), so the ID comes from the flag. Since 03-14c a config written by `keyroster init` pins the root-verified installation ID (03-14c-SUMMARY.md); ca issue still reads no config, as OQ-1 = A (next) decided.
- **OQ-1 = A: `ca issue` takes the installation ID from `--installation-id` only (Daniel, 2026-11-13).** Raised by the reconcile against main at 62b4407, because since 03-14c a CLI config can hold an installation ID. `ca issue` never reads the CLI config, never defaults the ID from the config's pin and never checks the flag against it. The owner's reason: `ca issue` reads no config and runs on the signer host, where there is normally no CLI config (signer-install.md section 8 has the admin run it as a local account through the signer's socket), and the signer refuses a wrong ID (issue_installation_mismatch) before any CA key is used. Not chosen: B (default from the config's pin and refuse a flag that differs) and C (refuse locally when the flag and a pin differ, with no default). The reconcile had recommended A, because B and C add a config read to the most privileged CLI path for little gain on the signer host.
- **Q-C8 = accept: the LoginIssueRequest exemption is an owner-recorded residual (Daniel, 2026-11-05).** LoginIssueRequest's signing bytes name no installation. The RP ID alone does not separate installations: two installations can share a registrable parent domain. A cross-installation replay needs the same passkey credential bound to the same user in both installations' directories and an origin both policies list (the signer checks the policy's origins, internal/signer/login.go, `origin_mismatch`). The exemption therefore assumes each installation has its own RP hostname. It is recorded as T-03-361's residual, labelled reasoned and UNVERIFIED, and revisited in Phase 4. The PR body must not state the binding as fact.
- **Q-D1 = A: two older formats outside internal/wire are owner-approved exemptions (Daniel, 2026-11-05).** adminauth.Message (`keyroster/admin-api/v1`) and the agent-identity rotation message (`keyroster/agent-identity/v1`, serverclient.AgentIdentityDomain) carry no installation ID and are recorded as exemptions. The binding test lists each explicitly, with the owner's reason, and both are recorded under T-03-361:
  - adminauth.Message: bound to an exact origin taken from the root-verified policy. This assumes each installation has its own hostname, the same assumption as Q-C8.
  - Agent-identity rotation: accepted only over mTLS, from the same old identity that signs it, and that identity is bound to the installation at enrollment.
  - The facts behind it: the server verifies an adminauth request only against a root-verified policy origin it matched exactly (internal/adminauth's package doc; TestVerify/other_deployment_origin_refused tests the origin check, not the cross-installation property, which stays reasoned and UNVERIFIED). A rotation is accepted only over mTLS authenticated by the old identity, for that identity's agents row (internal/server/agent.go, handleAgentIdentity), and the host enrollment proof (enroll.PoP) binds the identity to the installation at enrollment. Binding both formats (a v2 of each, option B) and deferring the rotation to Phase 4 (option C) were not chosen.
- **The PoP request types (03-09 owner decision D5).** HostIssueRequest (03-09), ProbeIssueRequest (03-10) and MachineIssueRequest (03-11) carry the installation ID in their signing bytes, with their own signer refusals and vectors. This plan owns none of them; Task 1's precondition stops if one does not carry it, and the table pins all three.
- **Delivery (owner, 2026-10-29 and 2026-11-02).**
  - The plan lands in the repository in the same PR as its fix, with its ROADMAP and STATE rows, the wave shift of the plans after it and its pointer sentences.
  - The PR title, every commit and the SUMMARY describe the change neutrally, as hardening, and name the issue only as F15.
  - Pushing the branch and opening the PR before the merge is allowed; the PR's diff is public while it is open.
  - Branch commits are signed and authored as Daniel, with keyroster-bot as committer, signer and pusher. The bot opens the PR without auto-merge, and Daniel squash-merges it himself.
- **Outside review.** A reviewer outside Claude (Codex) may review this PR. Its input is the repository diff and the PR's text only, never a ceremony folder, a passphrase file, `~/.ssh` or any planning file outside the repository.
- **Security levels (owner).** Hardware is optional and never required. Every test uses software keys, and no step needs a token.

## Open owner questions

None open.

## Planner decisions (Claude's discretion), recorded with their reasons

- *Wire layout.* The v1 constants keep their names and values (`IssueRequestDomain`, `AdminSSHSIGNamespace`); the new ones carry a `V2` suffix, so TestIssueRequestBytesUnchanged stays a control. That differs from revoke, whose unsuffixed constant names v2; revoke had no v1 left to keep accepting. The v2 signing bytes put the ID first, as revoke, forget and recovery do. The body appends it after the evidence, so a v1 body parses exactly as today.
- *The ID comes only from `ca issue --installation-id`* (owner decision OQ-1 = A, 2026-11-13). ca issue reads no config. Since 03-14c a `keyroster init` config pins the installation ID; ca issue does not read it either (signer-install.md section 8: the admin runs ca issue on the signer host, where no CLI config is assumed), and the signer refuses a wrong ID before any CA key is used. An ID taken from the signer's Status would let a socket the admin was pointed at choose the installation the admin signs for. There is no local pre-check against Status: the signer decides, and ca issue hints on its three refusal codes, and on malformed_request when the flag was set (an older signer). The unknown hint never tells the admin to drop the flag on the socket's word: it says to leave the flag out only after `keyroster trust verify` shows `installation id: none` for the installation the admin means to approve.
- *RED route (a).* R1 declares the struct field, the V2 constants, a `Namespace()` that still returns the v1 namespace, and the flag set on the struct; Marshal, ParseIssueRequest and SigningBytes stay as today. Each refusal case asserts a message only T1 produces, so every case fails on R1 for the right reason. Two test helpers build what R1's Marshal and the existing fake cannot: v2Body for v2 bodies and seeds, and the fake signer's options for ca issue's tests.
- *The vectors are not self-confirming.* The v1 file is written from origin/main's SigningBytes, whose v1 path is unchanged. The v2 file is derived from it mechanically: the domain's `v1` becomes `v2`, and `0020` and the 32 ASCII bytes of the ID are inserted right after the domain. TestIssueRequestSigningVector checks that derivation on the files themselves, independently of SigningBytes.
- *The table classifies `keyroster/` literals module-wide.* go/parser lists every receiver of a method named SigningBytes in internal/wire (pointer or value), and every string literal in the module's non-test files under internal/ and cmd/ whose value starts with `keyroster/`, wherever it occurs (a const, a var or a call argument), keyed by value. An alias such as `AdminSSHSIGNamespace = IssueRequestDomain` holds no literal and needs no rule; at 62b4407 the walk finds 18 values: the 15 of f7eb018 plus the three D5 request domains (`keyroster/host-issue-request/v1`, `keyroster/probe-issue-request/v1` and `keyroster/machine-issue-request/v1`), the same set the exported constants give. A type is checked by setting its exported string field `InstallationID` through reflection on a valid template, so a constructor cannot put the ID in the wrong field; a type without that field fails unless exempt. A wire tag classified bound names a templated type, and the test checks that the template's signing bytes carry the tag. A tag outside internal/wire is classified, not proven: its entry names the test that pins its binding, and a wrong label is caught only by review. Tags without the `keyroster/` prefix (tpm.probeDigest's `keyroster tpm key probe`, the evidence type names `admin-sshsig/v1` and `webauthn-assertion/v1`) are outside the walk, as T-03-360's residual says. This covers the formats outside internal/wire as far as a test can, as the registry's rule asks.
- *The audit side.* An audit-side check that issue evidence after a bundle with an ID uses the v2 namespace is possible without a leaf change (the SSHSIG blob names its namespace in clear), but a compromised signer writes the blob, so it would catch only a signer bug. Deferred on purpose and recorded in T-03-361.

## The installation-ID inventory

What names the installation, and what checks it, as read at f7eb018 (re-checked at 5ec5ff9 and at 62b4407) plus 03-09 to 03-11 (D5), 03-14c and this plan:

| Artifact | Tag | Signed by | Names the installation | Checked by |
|---|---|---|---|---|
| trust bundle (`installation_id`) | `keyroster/trust-bundle/v1` | the root threshold | optional; once set, carried unchanged | trust.VerifySuccessor; the agent's pin; the signer; since 03-14c the CLI's pin and audit verify |
| policy | `keyroster/policy/v1` | the root threshold | through the bundle's policy_sha256 | trust.VerifySelfSigned and VerifySuccessor |
| directory (`installation_id`) | `keyroster/directory/v1` | the admin quorum | yes, lenient while the bundle has none | directory.CheckInstallation and CheckStoredInstallation |
| KRL manifest (`installation_id`) | `keyroster/krl/v1` | the ops key | always | krl.VerifyManifest (agent, CLI, recover) |
| host enrollment proof (`enroll.PoP`) | `keyroster/agent-enroll/v1` | each host key | yes | the server at enrollment |
| RevokeRequest v2 | `keyroster/revoke-request/v2` | admins | yes (wire/revoke.go:136) | signer: revoke_installation_missing, revoke_installation_mismatch |
| RevokeRequest v1 | `keyroster/revoke-request/v1` | admins | no; refused since 03-03, read by audit | signer refuses it |
| ForgetRequest | `keyroster/host-forget-request/v1` | admins | yes (wire/forget.go:65) | signer: forget_no_installation_id, forget_installation_mismatch |
| RecoveryRequest | `keyroster/revoke-recovery/v1` | admins | yes (wire/recovery.go:79) | signer: recovery_installation_mismatch |
| IssueRequest v2 (this plan) | `keyroster/issue-request/v2` | admins | yes | signer: issue_installation_missing, issue_installation_mismatch, issue_installation_unknown |
| IssueRequest v1 | `keyroster/issue-request/v1` | admins | no | accepted only where the signer's bundle names none (Q-C2 A) |
| HostIssueRequest, ProbeIssueRequest, MachineIssueRequest (03-09 to 03-11) | `keyroster/host-issue-request/v1`, `keyroster/probe-issue-request/v1`, `keyroster/machine-issue-request/v1`, each also its PoP namespace | host, probe or machine keys (PoP) | yes, per D5 | their signer rules; this plan's precondition and table |
| LoginIssueRequest | `keyroster/login-request/v1` | the user's passkey | no; exempt (Q-C8) | the installation-bound directory credential and the policy's origins; UNVERIFIED |
| adminauth.Message | `keyroster/admin-api/v1` | admins | no; exempt (Q-D1 = A): an exact origin from the root-verified policy | the server, against the root-verified policy's origins; assumes each installation has its own hostname (UNVERIFIED) |
| agent identity rotation | `keyroster/agent-identity/v1` | the agent's old identity key | no; exempt (Q-D1 = A) | the server, over mTLS by that identity, which enroll.PoP bound to the installation at enrollment |
| Merkle log leaf, checkpoint origin | `keyroster/log-leaf/v1`, `keyroster/log/` | the log key | not a request tag | audit verify; the bundle names the log key |
| join token | not signed | | the ID of the bundle the CLI verified | since 03-14c, the CLI's pinned ID |

## The output contract

These texts are byte for byte, in the parts tests match.
- **ca issue's flag usage:** `the installation ID the request is for: 32 lowercase hex digits from the installation id line of your ceremony transcript, keyroster init or keyroster trust verify; required when the signer's trust bundle names one, and never copied from the signer`.
- **ca issue's hints**, each added to the signer's own text and ending `nothing was issued`:
  - issue_installation_missing: `the signer's trust bundle names an installation ID, so the request must name it: pass --installation-id`;
  - issue_installation_mismatch: `--installation-id names another installation than the signer at --socket serves`;
  - issue_installation_unknown: `this signer says its trust bundle names no installation ID; leave out --installation-id only after keyroster trust verify shows installation id: none for the installation you mean to approve`;
  - malformed_request with the flag set: `a signer older than this keyroster does not read the installation ID: upgrade the signer, or leave out --installation-id only if its trust bundle names no installation`.
  - malformed_request without the flag: no hint; the signer's own text only.
- **The signer's refusal details:** `issue_installation_missing`, `issue_installation_mismatch`, `issue_installation_unknown`, each classified as unauthorized and answered with CodeRefused.
- **The wire refusals (ParseIssueRequest and check):** `the installation ID is not 32 lowercase hex digits`, `an empty installation ID field` and `bytes after the installation ID`.

## Budget

files_modified lists 33 files (re-counted at 62b4407):
- 20 code and test files, two of them new (internal/wire/installation_test.go and internal/signer/issue_installation_test.go), and the two new vectors;
- one runbook, test/manual/README.md and the registry;
- eight planning files for the publish edits.

Per task: Task 1 touches about 17 files (wire, signer, ca issue and their tests, the vectors, revoke_host_test.go's issueKR1 and the two namespace-overlap lists), Task 2 about 5 (the table and the e2e callers), and Task 3 the runbook, test/manual/README.md, the registry and the planning files. Each task is self-contained: a continuation reads the plan's shared sections (frontmatter to `</context>`) and its own tasks only.

About 220k tokens raw, at low confidence (the estimate calibration has no samples, so the projection is not scaled). It covers two sessions:
- the plan itself, about 178 KB or roughly 74k tokens (at about 2.4 bytes per token, as measured in plan check 1), read once per session, so about 148k with the continuation;
- about 80 KB read through the function-scoped read_first lists, roughly 22k tokens;
- about 25k written;
- about 25k of test, mutant, gate and e2e-gate output.

That is over the 100k smart-zone budget. Comparable runs went higher: 03-14c, estimated at 280k raw, ran four sessions (three continuations, after Tasks 1, 2 and 3) and two pre-merge fix rounds (03-14c-SUMMARY.md). This plan has two RED commits, one fix commit and 16 mutants, so expect about 2x to 4x of the estimate. Budget one continuation after Task 1: the executor hands over through the SUMMARY draft (R1, T1, the RED lines, the test-time base, the mutant records so far), and the continuation starts at Task 2. If the continuation's context is about half used before Task 3 starts, it may hand over once more after Task 2, the same way. Each continuation is another session, so its delta gate re-measures the test-time base first (below). The task count and the files are unchanged.

**Test time (Q-09-3, owner decision, 03-09-PLAN.md; it replaces the fixed 400 s and 480 s caps of 03-08k, as in 03-14c).**
- **Timeout.** Every go test command of this plan carries `-timeout 15m`, and every mutant command `-timeout 5m`. CI's build-test already runs with `-timeout 15m` (ci.yml). A timeout is not a kill.
- **Base.** Task 1 measures a quiet base on unchanged origin/main, before any edit and with no other heavy job on the machine: `go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/signer/ ./internal/wire/` through `bash scripts/linux.sh`. It records one SUMMARY line, `test-time base: cmd=<s> signer=<s> wire=<s> at=<epoch seconds>`, each time read from that package's `ok` line in seconds without the trailing `s`. There is exactly one such line.
- **The rule.** Task 3's delta gate runs the same command and stops if any of the three packages adds more than 90 s to its base. If the base is more than 24 h (86400 s) old, re-measure it on origin/main in a detached worktree outside the repository, immediately before; a re-measure REPLACES the base line in place, never appends a second one. Stop and report only if the fresh delta is still above 90 s.
- **Another session.** If the delta gate runs in a different session or WSL boot from the one that measured the base, re-measure the base first on origin/main in a detached worktree outside the repository, and replace the line in place. After the continuation following Task 1 that is always the case. The 24 h age check still applies. The base line keeps its format: the delta gate reads `at=` at the end of the line, so no session or boot field is added.
- **The whole module.** `go test -race -count=1 -timeout 15m ./...` in the full gate is pass or fail only, and is never compared with a base; so is Task 1's whole-package run of internal/signer. internal/agent/apply reads about 450 s to 695 s under load on main (03-09's `./...` base and the multi-package bases of 03-10c and 03-10d), a package this plan does not touch, so no per-package cap is applied to it.
- **Expected.** For orientation, the recent bases on main read cmd/keyroster at about 223 to 270 s under -race (03-10b to 03-14c), internal/signer at about 323 to 417 s in the multi-package bases of 03-10, 03-10d and 03-11 (and 434 s under `./...`, with contention, in 03-09b's first full gate), and internal/wire at about 9 s (03-10 and 03-11). This plan adds about 3 s of tests to internal/signer; its new tests use software keys and in-memory fixtures. A reading near the 15-minute timeout is a stop-and-report, not a reason to raise it.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names. Since PR #79, its steps 2, 3 and 5 carry the owner's authorship and merge rules of 2026-11-02, which the points below restate. The one override is merge-gate.sh's plain form, as in 03-08f.
- **Branch.** Create `p03/14d-issue-installation` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 3 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Authorship (01-SKELETON step 2).** Every `git commit` of this plan is signed (`-S`) and authored as Daniel, with keyroster-bot as committer, SSH signer and pusher. Put the two variables on the same command line as the commit: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit -S ...`. Push with `env -u GITHUB_TOKEN -u GH_TOKEN git push`.
- **No auto-merge (01-SKELETON steps 3 and 5).** The bot opens the PR through scripts/gh-as-bot.sh and never enables auto-merge or waits for it. Daniel reviews, approves and squash-merges the PR in the GitHub web UI, and replies "merged".
- **merge-gate.sh.** Before the merge it runs only as `--check`, which is read-only. Its plain form may rebase and force-push (exit 3), and this plan rebases by hand, so the plain form runs only after Daniel has merged (Task 4).
- **Shells.**
  - The go test, gate and mutant commands run through `bash scripts/linux.sh '...'`. Its single-quoted argument reaches WSL's login shell unexpanded (wsl.exe --exec). A command string run in a worktree runs no git: the worktree's `.git` file holds a Windows path that git inside WSL cannot follow.
  - The git checks run in Git Bash. Every `git show`, `git cat-file` or `git grep` of an `origin/main:path` or `FETCH_HEAD:path` argument is prefixed with `MSYS_NO_PATHCONV=1`.
  - scripts/gh-as-bot.sh and scripts/merge-gate.sh always run in Git Bash without MSYS_NO_PATHCONV.
  - e2e runs in CI (the PR's e2e job), as in 03-08i: local e2e does not run on this machine.
- **Commit references.** `$R1`, `$T1` and so on are the SHAs of the commits the SUMMARY records under those names. Set them as shell variables on the same command line before running a check.
- **Wording.** Conventional Commits with neutral wording and the F-number. No attribution lines, no IP addresses, no real host names.
- **Code comments** cite `(03-14d, F15)`, or `(03-14d; D5)` for the table.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md`, a draft from Task 1 on. The final docs commit is `docs(03-14d): complete issue-installation plan`.
- **The mutant rule** (as 03-14b). Every mutant compiles. Its record is: the unmutated `-run` passing; `go vet` of the mutated package exiting 0; the named `--- FAIL:` lines, with no `[build failed]` or `[setup failed]`. Each mutant is applied to the working tree, run with its exact command, and the file restored and hash-checked before the next. Every mutant command carries `-timeout 5m` (Q-09-3), and a timeout is not a kill. The numbering is local (M1-1 to M1-13, M2-1 to M2-3): this plan allocates no global M-IDs (03-11 and 03-11b use M1 to M110), and 03-12 starts at M111, as 03-14b and 03-14c record.
- **RED first.** In Tasks 1 and 2, commit R holds the new tests (and the vectors), plus only the declarations they need to build, with behaviour unchanged. The RED is re-run from a worktree of R and must end in the named `--- FAIL:` lines. Commit T is the fix. The SUMMARY lists every declaration R added.

**What this plan builds on:**
- **03-14c (landed, #99, 62b4407):** `keyroster audit verify --installation-id` (cmd/keyroster/audit.go) and `keyroster revoke recover --installation-id` (recover.go, owner decision Q-R1); the CLI's pin through serverclient.Trust's fourth parameter, with TrustUnpinned for init only (internal/serverclient/client.go); trust verify's and root sign's installation id line (installationLine, cmd/keyroster/root.go); the transcript's Installation ID line; and the registry's "Since 03-14c" paragraph. ca issue reads no config and calls no Trust, so none of these is in its path. On audit verify and recover the flag `--installation-id` names the installation the command acts for, the meaning ca issue's flag has too.
- **D-04 (03-01, 03-04):** the bundle's installation ID; the signer's revoke, forget and recovery rules, which this plan's rule copies.
- **03-09 to 03-11:** HostIssueRequest, ProbeIssueRequest and MachineIssueRequest with their installation IDs (D5) and their own tags.
- **The format registry (PR #87, merged as 5ec5ff9):** docs/format-registry.md and internal/tlog/registry_test.go are on main, so Task 3's registry step applies; the plan still tolerates their absence (a revert). Its `## Refusal detail names` section names classify as the single source of refusal details, which T1 extends.

**The code this plan changes, as read on main at f7eb018 and re-read at 62b4407** (PR #87, at 5ec5ff9, changed no code this plan reads; it added comment lines to internal/wire/frame.go and internal/tlog/leaf.go. Between f7eb018 and 62b4407, internal/wire/issue.go, internal/signer/issue.go, evidence.go, fixture_test.go, log_test.go, cmd/keyroster/ca.go, ca_test.go and ca_status_test.go have no diff; refusal.go, server.go, revoke_test.go, wire_test.go, fuzz_test.go, bootstrap_test.go and pkcs11_test.go changed only in other functions. New since f7eb018 are the IssueRequest builders of 03-09b and 03-11 named below)**:**
- internal/wire/issue.go: IssueRequest has no installation field; IssueRequestDomain and AdminSSHSIGNamespace are `keyroster/issue-request/v1`; ParseIssueRequest refuses any byte after the evidence.
- internal/wire/wire_test.go: TestIssueRequestBytesUnchanged pins the v1 signing bytes, the v1 body and the constants. internal/wire/fuzz_test.go: FuzzParseIssueRequest seeds v1 bodies only.
- internal/signer/issue.go: Issue checks freshness, then verifyAdminEvidence (internal/signer/evidence.go, under wire.AdminSSHSIGNamespace), and never reads s.installationID. Doc comments in evidence.go, issue.go and cmd/keyroster/ca.go name the v1 namespace.
- internal/signer tests: fixture_test.go's SignRequest signs under wire.AdminSSHSIGNamespace. At 62b4407 there are six `wire.IssueRequest{` literals in the internal/signer and cmd/keyroster tests, five in internal/signer:
  - log_test.go:169, e.request(), which most issue tests use (directory_test.go, evidence_test.go, recovery_test.go, refusalcause_test.go, trust_test.go, probeissue_test.go's TestIssueReserved);
  - revoke_test.go:1011, TestSubjectResolutionTime/older_longer_cap_found, a literal on a fixture with an installation ID;
  - revoke_host_test.go:23, hostEnv.issueKR1 (03-09b), which calls e.s.Issue and fails the test on any error. Its fixture (newHostEnv) carries testInstallationID, so under T1 it is refused issue_installation_missing unless it sets the ID. revoke_host_test.go, revoke_machine_test.go and probeissue_test.go:443 call it;
  - machineissue_test.go:1239, TestMachineIssueBucket/admin_refusals_still_logged (03-11), on newMachineEnv's testInstallationID. It asserts only a refusal and one refusal leaf, so it still passes; under T1 the refusal is issue_installation_missing instead of the evidence refusal.

  The fifth, signer_test.go:378, is newRequest (with requestAt in refusal_test.go), which builds without evidence; its testSigner fixture names no installation, so its requests stay v1 and still issue. evidence_test.go's refusal table builds each logEnv on NewFixture without an installation ID, so e.request() stays v1 there and its `wire.AdminSSHSIGNamespace` evidence for an outsider (:112, :115) still reaches evidence_not_admin. The sixth literal is cmd/keyroster/ca_test.go:113 (TestCAIssueAdminEvidence).
- cmd/keyroster/ca.go: ca issue builds the request with no installation and signs it under wire.AdminSSHSIGNamespace. cmd/keyroster/ca_status_test.go's fake signer socket answers TypeIssueRequest frames with a fixed IssueResponse or the fixed refusal `fake_signer_refuses_issue`; it records each frame's type only and discards the body, and statusWith is a closure inside TestCAIssueStatusGate.
- test/e2e: runIssue (bootstrap_test.go) and four direct `"ca", "issue"` calls (negative_test.go two, pkcs11_test.go, stall_test.go) pass no installation. pkcs11_test.go is built only under the e2e_pkcs11 tag; tpm_test.go (e2e_tpm) issues through runIssue.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "an admin runs keyroster ca issue --installation-id → the request is signed under keyroster/issue-request/v2 with the installation ID first → installation A's signer issues it, and installation B's signer, whose policy lists the same admin key, refuses issue_installation_mismatch before any CA key signs; a request whose ID was rewritten after signing fails the evidence check" (F15), committed RED first and then fixed</name>
  <reversibility rating="costly">A new signed format, decided by the owner (Q-C2 A). No stored state depends on a v2 body: issue leaves keep only the request digest, the evidence and the certificate, and the v1 bytes stay byte for byte. A revert stops sending v2 and restores v1-only parsing; the cost is the published vector and the admins' habit of passing `--installation-id`.</reversibility>
  <precondition>All eight checks hold:
    - `git fetch origin` succeeds, and `P=.planning/phases/03-linux-agent-and-revocation && fw() { awk 'NR>1 && /^---$/{exit} /^wave: /{sub(/^wave: /,""); print}'; } && MSYS_NO_PATHCONV=1 git cat-file -e "origin/main:$P/03-14c-SUMMARY.md" && X12=$(MSYS_NO_PATHCONV=1 git show "origin/main:$P/03-12-PLAN.md") && test "$(printf '%s\n' "$X12" | fw)" = 31 && printf '%s\n' "$X12" | grep -qx 'depends_on: \["03-14c"\]' && W30=$(for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do if [ "$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw)" = 30 ]; then basename "$f"; fi; done) && test "$W30" = 03-14c-PLAN.md` exits 0. This is the stop guard (Q-C9, re-read at 62b4407): this plan's dependency, 03-14c, has its SUMMARY on main; origin/main's 03-12 holds wave 31, the slot this plan takes, and depends on ["03-14c"]; and 03-14c is the only plan at wave 30. Each wave is read from the frontmatter only. Otherwise main moved since the reconcile of 2026-11-13 (another plan was slotted in, or 03-12 moved): stop and report for a re-reconcile. Never re-slot this plan silently.
    - 03-14c is on main and this plan is not: `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md` and `MSYS_NO_PATHCONV=1 git grep -q -e 'func (c \*Client) TrustUnpinned(' origin/main -- internal/serverclient` exit 0, and `! MSYS_NO_PATHCONV=1 git grep -q -e 'IssueRequestDomainV2' origin/main -- internal/wire` exits 0.
    - D5 is delivered: `for T in HostIssueRequest ProbeIssueRequest MachineIssueRequest; do B=$(MSYS_NO_PATHCONV=1 git grep -h -A60 -e "^type $T struct" origin/main -- internal/wire | awk 'NR>1 && /^}/{exit} {print}'); printf '%s\n' "$B" | grep -q "^type $T struct" && printf '%s\n' "$B" | grep -qE '^[[:space:]]+InstallationID[[:space:]]+string' || { echo "missing or unbound: $T"; exit 1; }; done` exits 0. Otherwise stop and report: 03-09 to 03-11 did not deliver D5 as recorded, or named a type differently, and the owner decides. (If `git grep -h` prints a tree prefix on this Git version, strip it with `sed 's/^origin\/main:[^:]*[:-]//'` and record it.)
    - Each code anchor exists on origin/main: `^func (s \*Signer) Issue(` (internal/signer/issue.go), `^func verifyAdminEvidence(` (internal/signer/evidence.go), `^func classify(` (internal/signer/refusal.go), `^func runCAIssue(` (cmd/keyroster/ca.go), `^func TestIssueRequestBytesUnchanged(` (internal/wire/wire_test.go), `^func FuzzParseIssueRequest(` (internal/wire/fuzz_test.go) and `^func (e \*signerEnv) runIssue(` (test/e2e/bootstrap_test.go), each checked with `MSYS_NO_PATHCONV=1 git grep -q -e '<pattern>' origin/main -- <file>`.
    - Every pointer anchor occurs exactly once on origin/main: `` P=.planning/phases/03-linux-agent-and-revocation && test "$(MSYS_NO_PATHCONV=1 git show origin/main:$P/03-12-PLAN.md | grep -oF 'a goroutine runs `keyroster ca issue` (admin path, user CA)' | wc -l)" -eq 1 && test "$(MSYS_NO_PATHCONV=1 git show origin/main:$P/03-15-PLAN.md | grep -oF 'as your first admin action after the install' | wc -l)" -eq 1 ``. Otherwise stop and report.
    - The threat IDs are free as definitions: `! MSYS_NO_PATHCONV=1 git grep -qE '^\| T-03-(359|36[0-2]) \|' origin/main -- .planning` exits 0. It matches only threat-register rows (a line that starts with the ID in a table cell), never a mention such as 03-14c's mapping table, whose rows start with a draft ID and a parenthesis. Otherwise renumber from the highest T-03 ID that starts a register row on origin/main, + 1, keep the order, and record the mapping.
    - The format registry's presence is recorded in the SUMMARY (`MSYS_NO_PATHCONV=1 git cat-file -e origin/main:docs/format-registry.md`); either answer is fine (it is on main since 5ec5ff9).
    - The test-time base (Budget, Q-09-3) is measured on unchanged origin/main before any edit and recorded as the SUMMARY draft's single `test-time base:` line (Task 1's first action step); its format check is in Task 1's acceptance criteria. The base itself never stops the plan; only Task 3's delta over it does. And `awk '/^## Open owner questions/{f=1;next} f && NF{print; exit}' .planning/phases/03-linux-agent-and-revocation/03-14d-PLAN.md | grep -qx 'None open.'` exits 0.
  </precondition>
  <files>internal/wire/issue.go, internal/wire/wire_test.go, internal/wire/fuzz_test.go, internal/wire/machineissue_test.go (the namespace-overlap list), test/vectors/issue_request_signing_v1.hex (new), test/vectors/issue_request_signing_v2.hex (new), internal/signer/issue.go, internal/signer/evidence.go, internal/signer/refusal.go, internal/signer/fixture_test.go, internal/signer/log_test.go, internal/signer/revoke_test.go, internal/signer/revoke_host_test.go (issueKR1), internal/signer/issue_installation_test.go (new), cmd/keyroster/ca.go, cmd/keyroster/ca_test.go, cmd/keyroster/ca_status_test.go, and every other internal/signer or cmd/keyroster test that builds an IssueRequest (found by grep at execution)</files>
  <read_first>
    - internal/wire/issue.go (the whole file, 12 KB). internal/wire/revoke.go: `func (r *RevokeRequest) addFields(`, `func (r *RevokeRequest) SigningBytes(`, `func (r *RevokeRequest) domain(` and `func (r *RevokeRequest) Namespace(` (3 KB).
    - internal/wire/wire_test.go: `func validRequest(`, `func TestIssueRequestBytesUnchanged(`, `func TestRevokeRequestSigningVector(`, `func revokeVectorV2(` and `func marshalUnchecked(` (4 KB), and the namespace-overlap lists: TestForgetRequest's `namespace_is_its_own` (wire_test.go) and TestMachineIssueRequest's `constants_and_frame` (machineissue_test.go), each a `for _, other := range []string{AdminSSHSIGNamespace, ...}` loop (`grep -n 'range \[\]string{AdminSSHSIGNamespace'`). internal/wire/fuzz_test.go: `func FuzzParseIssueRequest(` with its seed() (2 KB).
    - internal/signer/issue.go: `func (s *Signer) Issue(` up to the evidence call, and its doc comment; internal/signer/evidence.go (the whole file, 3 KB); internal/signer/refusal.go: `func classify(`; internal/signer/revoke.go: the installation switch in `func (s *Signer) Revoke(`; internal/signer/server.go: how an unparseable frame is refused (`grep -n 'malformed_request'`), and internal/signer/signer_test.go: TestSignerFraming's `trailing_byte` case.
    - internal/signer/fixture_test.go: `type Fixture struct` and `func SignRequest(`; internal/signer/log_test.go: `func (e *logEnv) request(`; internal/signer/directory_test.go: the classify assertion that names `revoke_installation_mismatch` (`grep -n`); internal/signer/revoke_test.go: its `revoke_installation_mismatch` case and `TestSubjectResolutionTime`'s `older_longer_cap_found`; internal/signer/revoke_host_test.go: `func (e *hostEnv) issueKR1(`; internal/signer/machineissue_test.go: TestMachineIssueBucket's `admin_refusals_still_logged`. Then `git grep -n -E '(^|[^A-Za-z])wire\.IssueRequest\{' -- 'internal/signer/*_test.go' 'cmd/keyroster/*_test.go'` for every builder (authoritative at execution; six at 62b4407, listed in the context). The pattern matches `&wire.IssueRequest{` too, and never HostIssueRequest, ProbeIssueRequest, MachineIssueRequest or LoginIssueRequest.
    - cmd/keyroster/ca.go (the whole file, 8 KB); cmd/keyroster/ca_test.go: `func TestCAIssueAdminEvidence(`; cmd/keyroster/ca_status_test.go: `type fakeSigner struct`, `func startFakeSigner(` and TestCAIssueStatusGate's statusWith closure (`grep -n 'statusWith'`).
  </read_first>
  <behavior>
    - A request one admin signed for installation A is refused by installation B, whose policy lists the same admin key, with issue_installation_mismatch, and B's CA signs nothing (F15's shape). A issues it.
    - B refuses A's frame with issue_installation_mismatch also where B's policy does not list A's admin key: the installation rule runs before the evidence.
    - A's v2 request with its InstallationID rewritten to B's, sent to B, passes B's installation check and is refused by the evidence check with evidence_digest_mismatch (the ID is signed).
    - Where the bundle names an installation, a v1 request is refused issue_installation_missing; where it names none, a v2 request is refused issue_installation_unknown and a v1 request issues.
    - Evidence made under the v1 namespace over v1 bytes does not verify for the same fields as v2 (evidence_wrong_namespace); and a v2 frame stripped of its ID, sent to a signer without an ID that lists the same admin, fails the evidence check (evidence_wrong_namespace).
    - The v1 signing bytes, body and constants are byte for byte today's (TestIssueRequestBytesUnchanged unchanged); the v2 bytes are pinned by a vector derived from the v1 one.
    - ParseIssueRequest refuses an empty trailing ID, bytes after the ID and a malformed ID, each with its own message, and a truncated ID; one test helper builds every v2 body and fuzz seed, and the fuzz seeds cover them.
    - ca issue sends the ID it was given and signs under the request's namespace; a malformed flag is a usage error; the three refusals and an older signer's malformed_request get hints, and malformed_request without the flag gets none.
  </behavior>
  <action>
**The test-time base (Q-09-3, Budget).** Before any edit, while the tree still equals origin/main and no other heavy job runs, run `bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/signer/ ./internal/wire/'`. Create the SUMMARY draft with one line `test-time base: cmd=<s> signer=<s> wire=<s> at=<epoch seconds>`, the three times read from the `ok` lines without the trailing `s`, and `at=` from `date +%s`. A later re-measure uses a detached worktree of origin/main outside the repository and replaces this line in place.

**RED first: commit R1 (route (a)).** R1 holds the tests, the two vector files and the fuzz seeds, plus these declarations only:
- `IssueRequest.InstallationID`, a struct field that Marshal, ParseIssueRequest and SigningBytes do not use yet;
- `IssueRequestDomainV2` and `AdminSSHSIGNamespaceV2`;
- `func (r *IssueRequest) Namespace() string` returning AdminSSHSIGNamespace;
- `ca issue --installation-id`, set on the request without validation;
- the test helpers below, which set the field and sign under req.Namespace();
- in internal/wire/wire_test.go, `v2Body(v1 []byte, id string) []byte`, which appends uint16(len(id)) and the ID's bytes raw to a v1 body. Every v2, trailing-ID, truncated-ID and malformed-ID body and fuzz seed of this plan is built with it: marshalUnchecked writes addFields and the evidence only, and so does Marshal on R1. marshalUnchecked's doc comment is corrected to say that it encodes a v1 body and that v2Body appends the ID;
- in cmd/keyroster/ca_status_test.go, `startFakeSignerOpts(t *testing.T, o fakeSignerOpts) (string, *fakeSigner)`: o holds what startFakeSigner takes today plus `issueErr *wire.ErrorResponse`, answered to every IssueRequest when set, and the fake records the last IssueRequest body (`f.lastIssue()`). startFakeSigner keeps its signature and calls startFakeSignerOpts, so its callers and TestCAIssueStatusGate's assertions do not change. statusWith moves from TestCAIssueStatusGate to file level, unchanged.

**Wire (internal/wire/issue.go, `(03-14d, F15)`).**
- Constants:
  - Keep `IssueRequestDomain = "keyroster/issue-request/v1"` and `AdminSSHSIGNamespace = IssueRequestDomain` unchanged. Their doc comments say that these are the v1 forms, which name no installation, and that a signer accepts them only while its bundle names none.
  - Add `IssueRequestDomainV2 = "keyroster/issue-request/v2"` and `AdminSSHSIGNamespaceV2 = IssueRequestDomainV2`.
  - EvidenceAdminSSHSIG's doc comment says the evidence is made under the request's own SSHSIG namespace: AdminSSHSIGNamespace for a v1 issue request, AdminSSHSIGNamespaceV2 for v2 (Task 1's last verify command checks it).
- `InstallationID string`, first in IssueRequest, documented as the installation ID of the trust bundle the admins approve the request for; empty makes the request v1.
- check(): an InstallationID that is not empty and not trust.IsInstallationID is `%w: the installation ID is not 32 lowercase hex digits` with ErrMalformed.
- `domain()` and `Namespace()`, as revoke's: v2 with an ID, v1 without.
- SigningBytes: domain(), then, for v2, the ID uint16-length-prefixed, then addFields unchanged. Its doc comment says the ID is signed first, as in revoke, forget and recovery requests.
- Marshal writes addFields, then the evidence, then, for v2, the ID uint16-length-prefixed.
- ParseIssueRequest, after the evidence: if bytes remain, it reads the ID (at most 64 bytes as read). An empty ID is `%w: an empty installation ID field`, and anything after the ID is `%w: bytes after the installation ID`, both with ErrMalformed; check() then requires the ID's form. A v1 body parses exactly as today.
- Digest stays the SHA-256 of SigningBytes.
- TestIssueRequestBytesUnchanged is the control for the v1 bytes, body and constants. Do not edit it.

**Vectors (R1).**
- `issueVector`: the Ed25519 key with seed 0x00..0x1f, the user CA, subject `u:alice`, principal `alice`, 600 s, request ID 0x00..0x0f, created 1700000000, no extensions.
- test/vectors/issue_request_signing_v1.hex: the hex of issueVector's signing bytes, written from origin/main's SigningBytes (its v1 path is unchanged).
- test/vectors/issue_request_signing_v2.hex: derived from the v1 file by a short script, recorded in the SUMMARY with its output: replace the domain's `v1` with `v2`, then insert `0020` and the 32 ASCII bytes of `00112233445566778899aabbccddeeff` right after the domain. Record both files' SHA-256.
- **TestIssueRequestSigningVector:**
  - `v1_bytes`: the v1 file equals SigningBytes of issueVector, starts with the raw v1 domain, and Digest is its SHA-256;
  - `v2_bytes`: the v2 file equals SigningBytes of issueVector with the ID, starts with the raw v2 domain, and Digest is its SHA-256. RED: SigningBytes lacks the ID;
  - `v2_derived_from_v1`: the v2 file's bytes equal the derivation applied to the v1 file's bytes, independently of SigningBytes. It passes on R1.

**TestIssueRequestV2** (internal/wire/wire_test.go). Each refusal case asserts a message only T1 produces, except where stated:
- `round_trip_v2`: Marshal, then Parse, keeps the ID and the evidence;
- `v1_body_parses_as_today`: validRequest's body parses with an empty ID;
- `v2_body_helper_parses`: `v2Body(v1, id)` parses with that InstallationID and Namespace() == AdminSSHSIGNamespaceV2, so the helper builds a real v2 body;
- `trailing_empty_id_refused`: `v2Body(v1, "")`, a v1 body plus `0000`, refused with `an empty installation ID field`;
- `trailing_bytes_after_id_refused`: `v2Body(v1, id)` plus one byte, refused with `bytes after the installation ID`;
- `truncated_id_refused`: a v1 body plus `0020` and only 10 bytes of an ID, refused with ErrMalformed. It passes on R1, which refuses every byte after the evidence; it pins that T1's ID reader refuses it too;
- `malformed_id_refused`: `v2Body(v1, ...)` with 31 hex digits, with 33, and with upper case, each refused with `the installation ID is not 32 lowercase hex digits` by Parse, and the same IDs refused by Marshal;
- `domains_differ`: the v1 and v2 signing bytes of the same fields differ, and so do the two namespaces.

**Fuzz (internal/wire/fuzz_test.go).** FuzzParseIssueRequest gains seeds, each built with v2Body: a valid v2 body, a v1 body plus `0000`, a v2 body plus one trailing byte, a truncated ID (`0020` and 10 bytes), IDs of 31 and 33 characters, and an upper-case ID. Its body asserts that a parsed request with an ID has Namespace() == AdminSSHSIGNamespaceV2, and that its SigningBytes start with IssueRequestDomainV2 followed by `0020` and the ID.

**The signer (internal/signer, `(03-14d, F15)`).**
- issue.go, right after the request_time_skew check and before verifyAdminEvidence (never after it: `installation_checked_before_evidence` pins the order):
  - a bundle with an ID and a request without one: refusalErr(wire.CodeRefused, "issue_installation_missing", nil);
  - both set and different: "issue_installation_mismatch";
  - a bundle without an ID and a request with one: "issue_installation_unknown".

  Issue's doc comment names the rule (the D-04 rule of directories, as revoke and forget requests have it), and that evidence is checked under the request's namespace, v1 or v2.
- evidence.go: verifyAdminEvidence verifies under req.Namespace(), never under a fixed namespace; its doc comment names both namespaces.
- refusal.go, classify: the three details as ReasonUnauthorized, next to the revoke and directory installation reasons, under `// Issue installation binding (03-14d, F15; the T-03-20 rule).`.
- **Test helpers (R1).** log_test.go's e.request() sets `req.InstallationID = e.fx.InstallationID` (empty for a fixture without one); fixture_test.go's SignRequest signs under req.Namespace(); revoke_test.go's literal request in TestSubjectResolutionTime/older_longer_cap_found sets its fixture's ID; revoke_host_test.go's issueKR1 sets `req.InstallationID = e.fx.InstallationID` before SignRequest, so every revoke_host_test.go, revoke_machine_test.go and probeissue_test.go caller still issues under T1; and every other builder the grep finds does the same where its fixture names an installation. These pass on R1 and on T1. Record each. Reviewed at 62b4407 and left unedited, unless the whole-package run (second verify command) fails there: machineissue_test.go's admin_refusals_still_logged (it asserts only a refusal and one refusal leaf), evidence_test.go's refusal table (ID-less fixtures, so v1 evidence stays valid) and signer_test.go's newRequest (an ID-less fixture). An edit to one of them is recorded as a deviation.
- **Namespace-overlap lists (R1, `(03-14d, F15)`).** Add AdminSSHSIGNamespaceV2 to the `other` list of TestForgetRequest/namespace_is_its_own (wire_test.go) and of TestMachineIssueRequest/constants_and_frame (machineissue_test.go), next to AdminSSHSIGNamespace. `keyroster/issue-request/v2` is neither equal to nor a prefix of the forget or the machine namespace, nor they of it, so both pass on R1 and on T1; they keep the new namespace inside the existing overlap checks.
- **internal/signer/issue_installation_test.go (new): TestIssueInstallation.**
  - `request_for_other_installation_refused` (F15's shape): fixtures A and B have distinct installation IDs and CA keys, and B's policy lists A's admin key at quorum 1. One frame is signed for A, and A's issueOrRefuse issues it. The byte-identical frame, parsed again, goes to B's issueOrRefuse: B refuses issue_installation_mismatch, and B's user CA signs nothing (no issue leaf; a refusal leaf whose detail is issue_installation_mismatch and whose request digest is A's). RED: B issues.
  - `id_rewritten_refused`: A's admin-signed v2 request with its InstallationID set to B's ID afterwards, sent to B. B's installation check passes, and the evidence check refuses it with evidence_digest_mismatch (the namespace matches, the digest does not); no issue leaf, one refusal leaf. RED: B issues. This is the signer-level killer of mutant M1-3.
  - `v1_refused_where_bundle_names_one`: a v1 request with valid evidence, on A. issue_installation_missing. RED: it issues.
  - `v2_refused_where_bundle_names_none`: on a fixture without an ID. issue_installation_unknown. RED: it issues.
  - `v1_issues_where_bundle_names_none`: the control for the lenient rule. It issues.
  - `v2_issues_for_own_installation`: it issues, signed by A's user CA. It passes on R1 (the field is ignored there) and kills mutant M1-4.
  - `v1_signature_refused_as_v2`: the evidence is made under the v1 namespace over the v1 bytes, and then the request's InstallationID is set to A's. Refused with evidence_wrong_namespace (sshsig checks the namespace first). RED: it issues.
  - `v2_frame_stripped_to_v1_refused`: A's admin signs a v2 request for A; the frame is then built by marshalling the same request with `InstallationID` set to "" and A's evidence attached (never by slicing bytes off the body, which on R1 would cut into the evidence), and sent to a fixture without an ID whose policy lists A's admin key. Refused with evidence_wrong_namespace (the evidence names the v2 namespace); no issue leaf. RED: on R1 the evidence was made over v1 bytes under the v1 namespace, so it issues.
  - `installation_checked_before_evidence`: A's frame goes to a fixture B whose policy does not list A's admin key. B refuses issue_installation_mismatch, not evidence_not_admin, and writes no issue leaf. RED: on R1 it refuses evidence_not_admin. This is the killer of mutant M1-12.
  - `classified_unauthorized`: for each of the three details, `classify(d) == classify("revoke_installation_mismatch")` and `codeFor(classify(d)) == wire.CodeRefused`. RED: ReasonInternal.

**ca issue (cmd/keyroster/ca.go, `(03-14d, F15)`).**
- The `--installation-id` flag, with the usage of the output contract. Empty sends a v1 request. A value that is not trust.IsInstallationID is a usage error before the socket is contacted.
- Set req.InstallationID, and call `adminEvidence(req.SigningBytes(), req.Namespace(), adminKeys)`. adminEvidence's doc comment names both issue namespaces.
- When signerclient.Issue returns a *wire.ErrorResponse with one of the three details, or with malformed_request while the flag was set, return an error that keeps the signer's text and adds the hint of the output contract.
- **TestCAIssueInstallation** (ca_test.go), through startFakeSignerOpts. Every case below is a direct subtest under this name:
  - `flag_malformed_usage`: exit 2, and the fake socket received nothing;
  - `request_signed_under_v2`: the captured IssueRequest body (f.lastIssue()) parses with the ID, and its evidence verifies under AdminSSHSIGNamespaceV2. RED: the body carries no ID;
  - table-driven over the fake's issueErr. Each case asserts the signer's own text, its hint of the output contract (or that none of the four hints is there) and, with a hint, `nothing was issued`:
    - `hint_missing`: CodeRefused issue_installation_missing, without the flag;
    - `hint_mismatch`: CodeRefused issue_installation_mismatch, with the flag set;
    - `hint_unknown`: CodeRefused issue_installation_unknown, with the flag set. The hint is the output contract's trust verify text, never a bare instruction to drop the flag;
    - `hint_malformed_with_flag`: CodeMalformed malformed_request, with the flag set: the older-signer hint;
    - `no_hint_malformed_without_flag`: CodeMalformed malformed_request without the flag: the signer's text and no hint (the control; it passes on R1).

Commit R1 (`test(signer): pin installation binding of admin issue requests (F15)`), then take the RED from a worktree of R1 (second verify command).
- Expected `--- FAIL:` (twenty-one):
  - TestIssueRequestSigningVector/v2_bytes;
  - TestIssueRequestV2/{round_trip_v2, v2_body_helper_parses, trailing_empty_id_refused, trailing_bytes_after_id_refused, malformed_id_refused, domains_differ};
  - TestIssueInstallation/{request_for_other_installation_refused, id_rewritten_refused, v1_refused_where_bundle_names_one, v2_refused_where_bundle_names_none, v1_signature_refused_as_v2, v2_frame_stripped_to_v1_refused, installation_checked_before_evidence, classified_unauthorized};
  - TestCAIssueInstallation/{flag_malformed_usage, request_signed_under_v2, hint_missing, hint_mismatch, hint_unknown, hint_malformed_with_flag}.
- Expected to pass on R1, recorded with why: TestIssueRequestSigningVector/{v1_bytes, v2_derived_from_v1} (the v1 path and the files themselves); TestIssueRequestV2/{v1_body_parses_as_today, truncated_id_refused} (R1 refuses every byte after the evidence, so a truncated ID too); TestIssueInstallation/{v1_issues_where_bundle_names_none, v2_issues_for_own_installation}; TestCAIssueInstallation/no_hint_malformed_without_flag (no hint exists on R1); and TestIssueRequestBytesUnchanged.

**GREEN: commit T1** (`fix(signer): name the installation in admin issue requests (F15)`). T1 changes no test, no vector and no fuzz seed.

**Mutants** (the mutant rule; production code only):
- M1-1: drop the mismatch branch. Killed by `TestIssueInstallation/request_for_other_installation_refused` and `/installation_checked_before_evidence`.
- M1-2: refuse v1 also where the bundle names none (Q-C2 B). Killed by `/v1_issues_where_bundle_names_none`.
- M1-3: SigningBytes leaves out the ID (domain and namespace stay v2). Killed by `TestIssueRequestSigningVector/v2_bytes` and `TestIssueInstallation/id_rewritten_refused`; Task 2 re-runs it against its table and records that FAIL line too. `v1_signature_refused_as_v2` does not kill it: its evidence is refused by namespace either way.
- M1-4: verifyAdminEvidence uses the v1 namespace. Killed by `/v2_issues_for_own_installation`.
- M1-5: classify drops issue_installation_mismatch. Killed by `/classified_unauthorized`.
- M1-6: ParseIssueRequest accepts an empty trailing ID. Killed by `TestIssueRequestV2/trailing_empty_id_refused`.
- M1-7: ParseIssueRequest accepts bytes after the ID. Killed by `/trailing_bytes_after_id_refused`.
- M1-8: ca issue ignores the flag. Killed by `TestCAIssueInstallation/request_signed_under_v2`.
- M1-9: ca issue drops the older-signer hint. Killed by `/hint_malformed_with_flag`.
- M1-10: drop the missing branch. Killed by `TestIssueInstallation/v1_refused_where_bundle_names_one`.
- M1-11: drop the unknown branch. Killed by `/v2_refused_where_bundle_names_none`.
- M1-12: move the installation switch below verifyAdminEvidence. Killed by `/installation_checked_before_evidence`.
- M1-13: ca issue drops the issue_installation_unknown hint. Killed by `TestCAIssueInstallation/hint_unknown`.

Commands: `bash scripts/linux.sh 'go vet ./internal/wire/ && go test -count=1 -timeout 5m -v -run "^(TestIssueRequestSigningVector|TestIssueRequestV2)$" ./internal/wire/'`, `bash scripts/linux.sh 'go vet ./internal/signer/ && go test -count=1 -timeout 5m -v -run "^TestIssueInstallation$" ./internal/signer/'` and `bash scripts/linux.sh 'go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -v -run "^TestCAIssueInstallation$" ./cmd/keyroster/'`.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^(TestIssueRequestSigningVector|TestIssueRequestV2|TestIssueRequestBytesUnchanged|TestParseIssueRequestRefusals|TestRevokeRequestSigningVector|TestForgetRequestSigningVector|TestRecoveryRequestSigningVector)$" ./internal/wire/ && go test -race -count=1 -timeout 15m -v -run "^(TestIssueInstallation|TestSignerFraming)$" ./internal/signer/ && go test -race -count=1 -timeout 15m -v -run "^(TestCAIssueInstallation|TestCAIssueAdminEvidence)$" ./cmd/keyroster/ && go test -race -count=1 -timeout 15m ./internal/wire/ ./cmd/keyroster/ && go test -count=1 -timeout 15m -run NONE -fuzz "^FuzzParseIssueRequest$" -fuzztime 20s ./internal/wire/ && go vet ./... && test -z "$(gofmt -l .)"'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestParseIssueRequestRefusals", "--- PASS: TestSignerFraming" (both unchanged controls: under T1 their trailing_byte and trailing_bytes cases still refuse, one byte being a truncated length and "junk" declaring 27253 bytes), "--- PASS: TestIssueRequestSigningVector/v1_bytes", "--- PASS: TestIssueRequestSigningVector/v2_bytes", "--- PASS: TestIssueRequestSigningVector/v2_derived_from_v1", "--- PASS: TestIssueRequestV2/round_trip_v2", "--- PASS: TestIssueRequestV2/v1_body_parses_as_today", "--- PASS: TestIssueRequestV2/v2_body_helper_parses", "--- PASS: TestIssueRequestV2/trailing_empty_id_refused", "--- PASS: TestIssueRequestV2/trailing_bytes_after_id_refused", "--- PASS: TestIssueRequestV2/truncated_id_refused", "--- PASS: TestIssueRequestV2/malformed_id_refused", "--- PASS: TestIssueRequestV2/domains_differ", "--- PASS: TestIssueRequestBytesUnchanged", "--- PASS: TestIssueInstallation/request_for_other_installation_refused", "--- PASS: TestIssueInstallation/id_rewritten_refused", "--- PASS: TestIssueInstallation/v1_refused_where_bundle_names_one", "--- PASS: TestIssueInstallation/v2_refused_where_bundle_names_none", "--- PASS: TestIssueInstallation/v1_issues_where_bundle_names_none", "--- PASS: TestIssueInstallation/v2_issues_for_own_installation", "--- PASS: TestIssueInstallation/v1_signature_refused_as_v2", "--- PASS: TestIssueInstallation/v2_frame_stripped_to_v1_refused", "--- PASS: TestIssueInstallation/installation_checked_before_evidence", "--- PASS: TestIssueInstallation/classified_unauthorized", "--- PASS: TestCAIssueInstallation/flag_malformed_usage", "--- PASS: TestCAIssueInstallation/request_signed_under_v2", "--- PASS: TestCAIssueInstallation/hint_missing", "--- PASS: TestCAIssueInstallation/hint_mismatch", "--- PASS: TestCAIssueInstallation/hint_unknown", "--- PASS: TestCAIssueInstallation/hint_malformed_with_flag", "--- PASS: TestCAIssueInstallation/no_hint_malformed_without_flag"; or the fuzz run reports a failure</fails_when>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./internal/signer/'</automated>
    <fails_when>non-zero exit, or "FAIL" or "DATA RACE" in the output: an existing internal/signer test broke under T1 (for example a request builder that names no installation on a fixture that has one, such as issueKR1 left unedited). The run is pass or fail only, with no time cap (Q-09-3); a timeout is a stop-and-report</fails_when>
    <automated>W=$(mktemp -d) && git worktree add --detach "$W/r1" "$R1" >/dev/null && { ( cd "$W/r1" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^(TestIssueRequestSigningVector|TestIssueRequestV2|TestIssueRequestBytesUnchanged)$" ./internal/wire/ ; go test -count=1 -timeout 15m -v -run "^TestIssueInstallation$" ./internal/signer/ ; go test -count=1 -timeout 15m -v -run "^TestCAIssueInstallation$" ./cmd/keyroster/ ; true' ) > "$W/red.log" 2>&1; git worktree remove --force "$W/r1"; } && L="$W/red.log" && ! grep -qE '\[(build|setup) failed\]' "$L" && { ! grep -qF 'panic: test timed out' "$L" || { echo "a RED package timed out, so its cases cannot count as RED: $L"; exit 1; }; } && for c in TestIssueRequestSigningVector/v2_bytes TestIssueRequestV2/round_trip_v2 TestIssueRequestV2/v2_body_helper_parses TestIssueRequestV2/trailing_empty_id_refused TestIssueRequestV2/trailing_bytes_after_id_refused TestIssueRequestV2/malformed_id_refused TestIssueRequestV2/domains_differ TestIssueInstallation/request_for_other_installation_refused TestIssueInstallation/id_rewritten_refused TestIssueInstallation/v1_refused_where_bundle_names_one TestIssueInstallation/v2_refused_where_bundle_names_none TestIssueInstallation/v1_signature_refused_as_v2 TestIssueInstallation/v2_frame_stripped_to_v1_refused TestIssueInstallation/installation_checked_before_evidence TestIssueInstallation/classified_unauthorized TestCAIssueInstallation/flag_malformed_usage TestCAIssueInstallation/request_signed_under_v2 TestCAIssueInstallation/hint_missing TestCAIssueInstallation/hint_mismatch TestCAIssueInstallation/hint_unknown TestCAIssueInstallation/hint_malformed_with_flag; do grep -qF -- "--- FAIL: $c " "$L" || { echo "no RED: $c"; exit 1; }; done && for c in TestIssueRequestSigningVector/v1_bytes TestIssueRequestSigningVector/v2_derived_from_v1 TestIssueRequestV2/v1_body_parses_as_today TestIssueRequestV2/truncated_id_refused TestIssueInstallation/v1_issues_where_bundle_names_none TestIssueInstallation/v2_issues_for_own_installation TestCAIssueInstallation/no_hint_malformed_without_flag; do grep -qF -- "--- PASS: $c " "$L" || { echo "not passing on R1: $c"; exit 1; }; done && grep -qF -- '--- PASS: TestIssueRequestBytesUnchanged ' "$L"</automated>
    <fails_when>non-zero exit: R1 did not build, a RED package timed out (`panic: test timed out`, its own message), a named case did not fail on R1, or a named control did not pass on R1. R1 is the commit recorded in the SUMMARY</fails_when>
    <automated>diff <(MSYS_NO_PATHCONV=1 git show origin/main:internal/wire/wire_test.go | awk '/^func TestIssueRequestBytesUnchanged\(/,/^}/') <(awk '/^func TestIssueRequestBytesUnchanged\(/,/^}/' internal/wire/wire_test.go) && test -n "$(awk '/^func TestIssueRequestBytesUnchanged\(/,/^}/' internal/wire/wire_test.go)" && ! git grep -n -E 'wire\.AdminSSHSIGNamespace([^V]|$)' -- '*.go' ':!*_test.go' | grep -vE ':[0-9]+:[[:space:]]*//' | grep -q . && ( for f in $(git grep -l -e 'issue-request/v1' -- 'internal/signer/*.go' 'cmd/keyroster/*.go' ':!*_test.go'); do grep -qE 'issue-request/v2|AdminSSHSIGNamespaceV2' "$f" || { echo "names only the v1 issue namespace: $f"; exit 1; }; done ) && awk '/^\/\//{c=c $0 "\n"; next} /^const EvidenceAdminSSHSIG /{printf "%s", c; exit} {c=""}' internal/wire/issue.go | grep -q 'AdminSSHSIGNamespaceV2' && test -z "$(git diff --name-only $R1 $T1 -- '*_test.go' 'test/vectors')"</automated>
    <fails_when>non-zero exit: TestIssueRequestBytesUnchanged changed or is gone; non-test code outside internal/wire still names the fixed v1 issue namespace instead of req.Namespace(); a non-test file in internal/signer or cmd/keyroster mentions the v1 issue namespace but not the v2 one (checked per file, so a wrapped comment passes), or EvidenceAdminSSHSIG's doc comment does not name AdminSSHSIGNamespaceV2; or T1 changed a test or a vector</fails_when>
  </verify>
  <acceptance_criteria>
    - Every named result passes, and the RED of the twenty-one is recorded with the controls that pass on R1.
    - The thirteen mutants each compile and are killed by their named tests.
    - R1's test helpers (v2Body, startFakeSignerOpts with the last IssueRequest body and a chosen ErrorResponse, statusWith at file level) are recorded among its declarations.
    - TestIssueRequestBytesUnchanged is byte for byte origin/main's; both vectors' SHA-256 values and the derivation script's output are in the SUMMARY.
    - The whole internal/signer package passes alone under `-timeout 15m` (pass or fail, Q-09-3), and every moved request builder is recorded, issueKR1 included, with the reviewed and unedited sites (machineissue_test.go, evidence_test.go, signer_test.go).
    - `test "$(grep -c '^test-time base: ' .planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md)" -eq 1 && grep -Eqx 'test-time base: cmd=[0-9]+(\.[0-9]+)? signer=[0-9]+(\.[0-9]+)? wire=[0-9]+(\.[0-9]+)? at=[0-9]+' .planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md` exits 0 (the base line exists once, in the format Task 3's delta gate reads).
  </acceptance_criteria>
  <done>An admin's approval of a certificate is valid only in the installation it names: another installation whose policy lists the same admin key refuses it before its CA signs, and a rewritten ID fails the signature. Committed as R1 and T1.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: One test classifies every `keyroster/` string literal in the module and every signed request type in internal/wire (D5, the registry's rule), and the e2e callers of ca issue pass the installation ID</name>
  <reversibility rating="reversible">A test file and e2e argument changes. No production behaviour changes.</reversibility>
  <precondition>T1 is committed on the branch. Q-D1 is decided (A, Owner decisions): `keyroster/admin-api/v1` and `keyroster/agent-identity/v1` are classified exempt with the owner's reasons, as below.</precondition>
  <files>internal/wire/installation_test.go (new), test/e2e/bootstrap_test.go, test/e2e/negative_test.go, test/e2e/pkcs11_test.go, test/e2e/stall_test.go, and every other e2e `"ca", "issue"` caller on origin/main at execution</files>
  <read_first>
    - Every SigningBytes receiver in internal/wire: `git grep -n -e 'SigningBytes()' -- 'internal/wire/*.go' ':!*_test.go'`, and the vector or template constructor of each in wire_test.go and the files 03-09 to 03-11 added.
    - Every `keyroster/` string literal in the module's non-test code: `git grep -n -e '"keyroster/' -- 'internal/**/*.go' 'cmd/**/*.go' ':!*_test.go'` (18 distinct values at 62b4407: the 15 of f7eb018 plus the three D5 request domains; the hits in comments, at tlog/leaf.go, tlog/checkpoint.go and trust/bundle.go, do not count).
    - internal/adminauth/adminauth.go: the package doc and Namespace; internal/serverclient/agent.go: AgentIdentityDomain and AgentIdentityMessage; internal/server/agent.go: `func (s *Server) handleAgentIdentity(`'s doc comment. internal/keystore/tpm/tpm.go: probeDigest, a tag without the `keyroster/` prefix (`grep -n probeDigest`).
    - The tests that pin the binding of the documents outside internal/wire, which the table names: TestCheckInstallation (internal/directory/hosts_test.go), TestVerifyManifest's other_installation_refused (internal/krl/krl_test.go), TestPoP's other_installation_refused (internal/agent/enroll/pop_test.go) and TestInstallationIDSuccessor (internal/trust/installation_test.go). Confirm each with `git grep -n`; a function-name grep misses the subtests.
    - test/e2e/bootstrap_test.go: `func (e *signerEnv) runIssue(`; every direct `"ca", "issue"` call (`git grep -n -e '"ca", "issue"' -- test/e2e`) with its env's InstallationID field; test/e2e/negative_test.go around its two calls, in TestTrustRefuses, with that test's second `bootstrapSigner` env, its `newUserKey` and `noCert` helpers (`grep -n 'bootstrapSigner\|newUserKey\|noCert' test/e2e/negative_test.go`), and pkcs11_test.go (build tag e2e_pkcs11) and stall_test.go around theirs.
  </read_first>
  <behavior>
    - Every receiver of a method named SigningBytes in internal/wire (pointer or value) is in the table: either its signing bytes change when its exported `InstallationID` field, set through reflection on a valid template, changes, and contain the ID; or it carries an exemption string.
    - Every string literal in the non-test files under internal/ and cmd/ whose value starts with `keyroster/` is classified by value: bound (a wire tag names a templated type whose signing bytes carry it; a tag outside internal/wire names the test that pins its binding, classified, not proven), exempt (with its reason), or not a request tag (with its reason).
    - An unclassified type or tag, a classified one that no longer exists, a bound type without an InstallationID field, a bound type whose bytes do not change, a template whose SigningBytes fails, and a bound wire tag its type's signing bytes do not carry each fail with their own message, reported with t.Errorf so that every entry is checked.
    - The comparison of found and pinned names is one pure function, tested on a parsed source string (`diff_logic`), so `pinned type not found` is exercised without a production mutant.
    - On origin/main's code the test fails with exactly two messages: IssueRequest has no InstallationID field, and the v2 tag is not found.
    - The e2e helpers and every direct caller pass `--installation-id`, except the one marked no-flag case, and the e2e suite proves the CLI and signer together.
  </behavior>
  <action>
**RED first: commit R2.** R2 is the new test file and the e2e changes; it declares nothing. Its RED is taken against origin/main's code: copy R2's committed test file (`git show "$R2:internal/wire/installation_test.go"`) onto a worktree of origin/main and run it (second verify command). It must fail naming IssueRequest and the tag `keyroster/issue-request/v2`, with exactly two diagnostic lines, and pass for every other entry; `diff_logic` passes there too.

**internal/wire/installation_test.go (new, `(03-14d; D5)`): TestSignedRequestsBindInstallation**, with three subtests. The file stands alone: it defines its own templates and helpers and refers only to identifiers that exist on origin/main (no helper from this plan's wire_test.go, and IssueRequest's field is set through reflection, not by name), so its RED builds on a worktree of origin/main. Every template and helper in it carries a `bind` prefix (bindIssue, bindRevoke, ...), so no name collides with package wire's tests on origin/main (validRequest, loginVector, revokeVector, revokeVectorV2) or on the branch (issueVector, v2Body). The tags subtest classifies by the tag's value string, not by constant name.
- **`types`.**
  - go/parser parses internal/wire's non-test .go files and lists the receiver type, pointer or value, of every method named SigningBytes.
  - A pinned table maps each type name to either a template constructor `func() any`, which returns a pointer to a valid request, or an exemption string.
    - Templates: IssueRequest (with an ID), RevokeRequest, ForgetRequest, RecoveryRequest, and the three D5 types under their names on origin/main.
    - Exemption: LoginIssueRequest, `owner-recorded residual (Q-C8): approved by the user's passkey for a credential the installation-bound directory binds, under an origin the policy lists; assumes each installation has its own RP hostname (reasoned, UNVERIFIED)`.
  - For every template: reflection sets the exported string field named exactly `InstallationID` to `00112233445566778899aabbccddeeff`, then to `ffeeddccbbaa99887766554433221100`, and calls SigningBytes through reflection, accepting a `[]byte` result or a `([]byte, error)` result with a nil error. The two byte strings must differ, and each must contain its ID. Every per-entry message is reported with t.Errorf, never t.Fatalf, so every entry is checked in one run.
  - Messages: `unpinned signed request type <name>`; `pinned type not found <name>`; `<name> has no InstallationID string field`; `<name>: signing bytes do not name the installation`; and `<name>: SigningBytes: <err>` for a template whose SigningBytes returns an error (RecoveryRequest's calls Validate). The first says that a new signed request type names the installation it is for, or gets a recorded exemption.
- **`tags`.**
  - go/parser parses every non-test .go file under internal/ and cmd/ (walked from the repository root, `../..`) and collects every string literal (an *ast.BasicLit of kind STRING) whose unquoted value starts with `keyroster/`, wherever it occurs: a const, a var or a call argument. It keys them by value and keeps the first package and position seen. Comments are not literals, so the mentions in comments (tlog/leaf.go, tlog/checkpoint.go and trust/bundle.go, at f7eb018 and at 62b4407) stay out, and an alias such as `AdminSSHSIGNamespace = IssueRequestDomain` holds no literal and needs no rule. At 62b4407 this gives 18 values: the 15 of the f7eb018 inventory plus the three D5 request domains, the same set the exported constants give, so the RED does not change. `keyroster/log/` is two literals (tlog.OriginPrefix and trust.LogOriginPrefix) and one value.
  - A pinned map classifies each value:
    - bound, a wire tag: `keyroster/issue-request/v2` (IssueRequest), `keyroster/revoke-request/v2` (RevokeRequest), `keyroster/revoke-recovery/v1` (RecoveryRequest), `keyroster/host-forget-request/v1` (ForgetRequest), and the three D5 request tags: `keyroster/host-issue-request/v1` (HostIssueRequest), `keyroster/probe-issue-request/v1` (ProbeIssueRequest) and `keyroster/machine-issue-request/v1` (MachineIssueRequest). Each entry names a type that has a template in `types`, and the test checks that the template's signing bytes, with its ID set, begin with the tag's bytes (`raw`). Every bound format at 62b4407 prepends its domain raw (revoke.go, forget.go, recovery.go and issue.go, and for the D5 types hostissue.go:135, probeissue.go:155 and machineissue.go:136), so `raw` is the only form: a later format that encodes its domain otherwise fails the check and is classified when it lands;
    - no `bound through <Type>` entry: at 62b4407 each D5 PoP namespace equals its request domain (HostPoPNamespace, ProbePoPNamespace and MachinePoPNamespace are aliases: hostissue.go:25, probeissue.go:25, machineissue.go:24), so it is the same value and needs no entry. Such an entry would match no literal and give a `classified tag not found` line, which would break the RED's two-line count;
    - bound where the bundle names one: `keyroster/issue-request/v1`, `accepted only where the signer's bundle names no installation (Q-C2 A)`, naming IssueRequest (raw), checked with the template's InstallationID cleared where the field exists;
    - bound outside internal/wire, classified, not proven (a wrong label is caught only by review): `keyroster/directory/v1` (pinned by TestCheckInstallation), `keyroster/krl/v1` (TestVerifyManifest/other_installation_refused), `keyroster/agent-enroll/v1` (TestPoP/other_installation_refused) and `keyroster/trust-bundle/v1` (`installation_id optional; carried unchanged by VerifySuccessor (TestInstallationIDSuccessor)`);
    - not a request tag, or refused: `keyroster/revoke-request/v1` (refused since 03-03, read by audit), `keyroster/policy/v1` (bound through the bundle's policy_sha256), `keyroster/log-leaf/v1` and `keyroster/log/` (the log key's own domain and origin);
    - exempt, owner-recorded: `keyroster/login-request/v1` (Q-C8, as above); `keyroster/admin-api/v1`, `bound to an exact origin taken from the root-verified policy; assumes each installation has its own hostname, the same assumption as Q-C8 (Q-D1 = A; reasoned, UNVERIFIED)`; and `keyroster/agent-identity/v1`, `accepted only over mTLS, from the same old identity that signs it, and that identity is bound to the installation at enrollment (enroll.PoP) (Q-D1 = A)`.
  - The form check of a bound wire tag runs only for a value the walk found and whose type has an InstallationID field. So on origin/main's code the missing v2 tag gives one message, IssueRequest's missing field (in `types`) another, and nothing else.
  - Any other `keyroster/` literal the walk finds is classified at execution with its reason, and recorded.
  - Messages, each reported with t.Errorf: `unclassified tag <value> (<package>, <position>)`, saying that a new tag is classified here and in docs/format-registry.md; `classified tag not found <value>`; `<value>: bound to <Type>, which has no template`; and `<value>: <Type>'s signing bytes do not carry the tag`.
- **`diff_logic`.** The comparison of found and pinned names is one pure function, used by both subtests, that returns the messages above. This subtest runs the same collection and comparison on a fixed source string parsed with go/parser (two types with a SigningBytes method, `A` and `B`, and one literal `"keyroster/x/v1"`) against a pinned set naming `A` and `Gone` and the tag `keyroster/y/v1`. It requires exactly `unpinned signed request type B`, `pinned type not found Gone`, `unclassified tag keyroster/x/v1` (compared by prefix) and `classified tag not found keyroster/y/v1`, reports only a difference and logs nothing on success. It passes on origin/main's code too, and it is what exercises `pinned type not found`, which no production mutant can reach.

**e2e (runs in CI, `(03-14d, F15)`).**
- runIssue passes `"--installation-id", e.InstallationID` in the same argument list as `"ca", "issue"`, within four lines of it.
- Every direct `"ca", "issue"` call passes its env's installation ID within four lines of that string: negative_test.go's two (ca_issue_without_admin_key too, which still exits 2 on the missing admin key before any socket), pkcs11_test.go's (built only under e2e_pkcs11), stall_test.go's, and every other caller the grep finds.
- negative_test.go's TestTrustRefuses gains the subtest `issue_names_installation`, on the bootstrapped env its ca_issue cases already use (its second bootstrapSigner, negative_test.go:390). It is a subtest, not a top-level test, because test/e2e shares no env between tests, so a top-level test would need its own bootstrapSigner, and the main lanes ran 780.827 s and 803.970 s against the 900 s stop at e38d6b3 (03-14c-SUMMARY.md). It uses its own user key (`newUserKey(t, "id_installation")`), so its no-certificate checks do not depend on the order of the other subtests. TestTrustRefuses's doc comment also names the installation refusals. Its first two cases call ca issue directly, the third goes through runIssue:
  - `without_flag_refused`: exits 1 with issue_installation_missing and the hint, and writes no certificate. This is the one call site without the flag: the line that holds its `"ca", "issue"` ends with the comment `// no --installation-id on purpose (03-14d)`, which appears nowhere else;
  - `other_installation_refused`: with `--installation-id ffffffffffffffffffffffffffffffff`, exits 1 with issue_installation_mismatch and its hint, and writes no certificate;
  - `own_installation_issues`: through runIssue, which passes the env's ID: it issues.

Commit R2 (`test(wire): classify every keyroster/ tag and signed request type by installation binding (F15)`). There is no T2: the test passes on T1's code, which the first verify command shows.

**Mutants** (the mutant rule; production code only):
- M2-1: ForgetRequest's signing bytes leave out its ID. Killed by `TestSignedRequestsBindInstallation/types` and TestForgetRequestSigningVector (both in the mutant's -run).
- M2-2: add the unexported `const exampleDomain = "keyroster/example/v1"` to a non-test file of internal/wire (the literal walk sees unexported constants too). Killed by `/tags` (`unclassified tag keyroster/example/v1`).
- M2-3: add `type ExampleRequest struct{ InstallationID string }` with `func (r *ExampleRequest) SigningBytes() []byte { return []byte(r.InstallationID) }` to a non-test file of internal/wire. It compiles and vets, and is killed by `/types` (`unpinned signed request type ExampleRequest`). (Plan check 1's M2-3, a renamed LoginIssueRequest method, could not compile: package wire's own tests call that method.)
- `pinned type not found` has no production mutant, because removing a SigningBytes method breaks package wire's own tests. `diff_logic` exercises it, and the SUMMARY says so.
- Task 1's M1-3 is re-run here with `-run "^TestSignedRequestsBindInstallation$"`, and its FAIL line (`IssueRequest: signing bytes do not name the installation`) is recorded next to Task 1's record.

Commands: `bash scripts/linux.sh 'go vet ./internal/wire/ && go test -count=1 -timeout 5m -v -run "^(TestSignedRequestsBindInstallation|TestForgetRequestSigningVector)$" ./internal/wire/'`.
  </action>
<!-- plan-criteria-allow: R1 - the counted file is the log of the RED run, not a repository file; each t.Errorf prints exactly one installation_test.go:N line and the RED must show exactly two -->
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^TestSignedRequestsBindInstallation$" ./internal/wire/ && go test -race -count=1 -timeout 15m ./internal/wire/ && go vet -tags e2e ./test/e2e/ && go vet -tags e2e_pkcs11 ./test/e2e/ && go vet -tags e2e_tpm ./test/e2e/ && test -z "$(gofmt -l internal/wire test/e2e)"'</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or any of these lines missing: "--- PASS: TestSignedRequestsBindInstallation/types", "--- PASS: TestSignedRequestsBindInstallation/tags", "--- PASS: TestSignedRequestsBindInstallation/diff_logic". A vet failure under e2e, e2e_pkcs11 or e2e_tpm is an e2e caller that does not compile</fails_when>
    <automated>W=$(mktemp -d) && git worktree add --detach "$W/m" origin/main >/dev/null && MSYS_NO_PATHCONV=1 git show "$R2:internal/wire/installation_test.go" > "$W/m/internal/wire/installation_test.go" && { ( cd "$W/m" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^TestSignedRequestsBindInstallation$" ./internal/wire/ ; true' ) > "$W/red.log" 2>&1; git worktree remove --force "$W/m"; } && L="$W/red.log" && ! grep -qE '\[(build|setup) failed\]' "$L" && { ! grep -qF 'panic: test timed out' "$L" || { echo "the RED run timed out: $L"; exit 1; }; } && grep -qF -- '--- FAIL: TestSignedRequestsBindInstallation/types ' "$L" && grep -qF ': IssueRequest has no InstallationID string field' "$L" && grep -qF -- '--- FAIL: TestSignedRequestsBindInstallation/tags ' "$L" && grep -qF 'classified tag not found keyroster/issue-request/v2' "$L" && grep -qF -- '--- PASS: TestSignedRequestsBindInstallation/diff_logic ' "$L" && test "$(grep -cE 'installation_test\.go:[0-9]+: ' "$L")" -eq 2 && test "$(grep -cE 'unpinned signed request type|pinned type not found|signing bytes do not name the installation|unclassified tag|: SigningBytes: |which has no template|signing bytes do not carry the tag' "$L")" -eq 0</automated>
    <fails_when>non-zero exit: the RED run timed out (its own message); on origin/main's code the test does not fail with exactly two diagnostic lines, one for IssueRequest's missing field and one for the missing v2 tag; it fails there for another entry (a table error to fix before R2); `diff_logic` does not pass there; or R2's committed file could not be read</fails_when>
    <automated>D=$(git diff --name-only $T1...$R2) && ! printf '%s\n' "$D" | grep -vE '^(internal/wire/installation_test\.go|test/e2e/[a-z_0-9]+_test\.go|\.planning/.*)$' | grep -q . && test -z "$(git diff $T1...$R2 -- test/e2e | grep -E '^\+.*bootstrapSigner\(')" && test "$(git grep -h -e '"ca", "issue"' -- test/e2e | wc -l)" -ge 7 && test "$(git grep -h -F -e '// no --installation-id on purpose (03-14d)' -- test/e2e | wc -l)" -eq 1 && ( for f in $(git grep -l -e '"ca", "issue"' -- test/e2e); do awk -v f="$f" '{l[NR]=$0} END{for (i=1; i<=NR; i++) if (index(l[i], "\"ca\", \"issue\"")) {ok=0; for (j=i; j<=i+4 && j<=NR; j++) if (index(l[j], "--installation-id")) ok=1; if (!ok) {print f ":" i ": a ca issue call without --installation-id"; bad=1}} exit bad}' "$f" || exit 1; done )</automated>
    <fails_when>non-zero exit: Task 2 changed a file outside the test and the e2e tests; it added a bootstrapSigner call (lane time, D09 of the 62b4407 reconcile); fewer than seven e2e `"ca", "issue"` call sites were found (five at f7eb018 and at 62b4407, plus the two direct calls of TestTrustRefuses/issue_names_installation); the no-flag marker is missing or on more than one line; or a call site has no `--installation-id` within four lines (the marked site passes because its marker names the flag)</fails_when>
  </verify>
  <acceptance_criteria>
    - The three subtests pass; their RED on origin/main's code names exactly IssueRequest and the v2 tag, in two diagnostic lines, with `diff_logic` passing.
    - The three mutants each compile and are killed, and M1-3's FAIL line against the table is recorded.
    - Every e2e `"ca", "issue"` call site passes the flag, except the one marked no-flag case.
    - Every tag found at execution is classified, with its reason recorded in the SUMMARY.
    - Both main e2e lanes of the PR's run pass TestTrustRefuses/issue_names_installation and its three cases (checked in Task 3), with no new bootstrapSigner.
  </acceptance_criteria>
  <done>Every `keyroster/` string literal in the code and every signed request type in internal/wire is classified by installation binding, the formats outside internal/wire included (classified, not proven), and the e2e suite issues with the installation named. Committed as R2.</done>
</task>

<task type="auto">
  <name>Task 3: The runbook update, the registry rows, the pointer sentences, the publish edits, the gates, the PR, the pre-merge review and the SUMMARY</name>
  <precondition>R2 is committed on the branch, and after `git fetch origin` both pointer anchors still occur exactly once on origin/main (Task 1's anchor check). Otherwise stop and report.</precondition>
  <files>docs/runbooks/signer-install.md, test/manual/README.md, docs/format-registry.md (only if it is on origin/main; it is since 5ec5ff9), .planning/phases/03-linux-agent-and-revocation/03-14d-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/signer-install.md: section 8's `keyroster ca issue` example (`grep -n 'keyroster ca issue'`) and the paragraph after it (2 KB); then `git grep -n -e 'ca issue' -- test/e2e cmd/keyroster/*_test.go` for any test that pins that block. test/manual/README.md: its `keyroster ca issue` example (`grep -n 'ca issue'`).
    - docs/format-registry.md on origin/main (present since 5ec5ff9): its introduction, `## Domain-separation tags and SSHSIG namespaces`, `## Refusal detail names` and `## Installation binding` (5 KB).
    - 03-12-PLAN.md: its frontmatter, its first `<precondition>` line and the line holding the anchor; 03-15-PLAN.md: the line holding its anchor (step 3 of its owner checkpoint). The `wave:` and `depends_on:` lines of 03-13 to 03-16.
    - .planning/ROADMAP.md: Phase 3's Plans line, its wave blocks and the Progress row (`grep -n 'Wave\|Plans:\|^| 3\. Linux Agent'`); .planning/STATE.md: the frontmatter and the `Plan:` line.
  </read_first>
  <action>
**Runbook (CONTEXT D-20), signer-install.md section 8, and test/manual/README.md.** Change a ca issue example only together with any test that pins it, in the same commit.
- In both examples, insert `--installation-id <installation id>` right after `keyroster ca issue`, on the same line. signer-install.md's first line then begins `keyroster ca issue --installation-id <installation id> --admin-key SHA256:<alice admin key>` and keeps its line continuation; test/manual/README.md's code span begins `keyroster ca issue --installation-id <installation id> --ca user`, and after the span add `(the flag is needed where the signer's trust bundle names an installation ID, since 03-14d)`.
- After the signer-install.md example, say:
  - where the ID comes from: the installation id line of the ceremony transcript (its Installation ID line since 03-14c), of `keyroster init` or of `keyroster trust verify`; never from the signer;
  - that the signer refuses a request that does not name its installation (`issue_installation_missing`), names another (`issue_installation_mismatch`), or names one where the signer's trust bundle has none (`issue_installation_unknown`), and that a signer whose bundle names no installation (pre-D-04) accepts the request without the flag. If ca issue says the signer's bundle names no installation ID, leave out the flag only after `keyroster trust verify` shows `installation id: none` for the installation you mean to approve;
  - the upgrade order, as one paragraph that ends with its two labels: upgrade keyroster-signer and keyroster together before admins pass --installation-id (section 2 installs both from one build). An older keyroster-signer refuses a request with the flag as malformed_request, and ca issue then says so (reasoned from the parser and TestSignerFraming's trailing_byte case). A keyroster CLI older than the signer cannot send the flag and is refused issue_installation_missing without a hint: upgrade it. After the upgrade, every ca issue on an installation that has an ID needs the flag. Run in CI: TestIssueInstallation, TestCAIssueInstallation and TestTrustRefuses/issue_names_installation (e2e). UNVERIFIED on the homelab signer, whose bundle names no installation until 03-15, and UNVERIFIED for an upgrade with a real older signer or CLI.
- The exact phrases verify command 4 greps for, with whitespace normalised and backticks removed: `keyroster ca issue --installation-id <installation id>` (in both files), `issue_installation_mismatch`, `leave out the flag only after keyroster trust verify shows installation id: none`, and `upgrade keyroster-signer and keyroster together before admins pass --installation-id` in a paragraph that also holds `Run in CI` and `UNVERIFIED`.

**The format registry (registry rule; PR #87, on main since 5ec5ff9).** If `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:docs/format-registry.md` exits 0 (expected), edit it in this PR:
- in the tag table, right after the `keyroster/issue-request/v1` row (format-registry.md:134 at 62b4407), add `` | `keyroster/issue-request/v2` | domain and SSHSIG, admin issue request that names its installation (03-14d) | `wire.IssueRequestDomainV2`, `wire.AdminSSHSIGNamespaceV2` | ``, and change the v1 row's use to `domain and SSHSIG, admin issue request without an installation ID; accepted only where the signer's bundle names none (03-14d)`;
- in the installation-binding table, as its last row, right after the Machine issue request row (:197 at 62b4407), add `` | Issue request v2 (`wire.IssueRequest`, internal/wire/issue.go) | `InstallationID` | policy admins (SSHSIG) | ``. No D5 row is added: the tag table already holds the three D5 tags (:140-142) and the binding table the three D5 types (:195-197);
- as a new paragraph of its own after the section's last paragraph (the "Since 03-14c" paragraph, :213 at 62b4407, right before `## Reserved names`), never inside an existing paragraph, add the recorded exceptions: an issue request v1 is accepted only where the signer's bundle names no installation ID; LoginIssueRequest names none (an owner-recorded residual, Q-C8, which assumes each installation has its own RP hostname); adminauth.Message is bound to an exact origin taken from the root-verified policy, which assumes each installation has its own hostname, the same assumption as Q-C8; and the agent-identity rotation message is accepted only over mTLS, from the same old identity that signs it, and that identity is bound to the installation at enrollment (both owner-approved, Q-D1 = A). End with: `TestSignedRequestsBindInstallation (internal/wire/installation_test.go) classifies every keyroster/ string literal in the module and every signed request type in internal/wire; a tag without the keyroster/ prefix is outside it.`;
- no leaf kind or message type is allocated, so TestFormatRegistry is unaffected; the three refusal details are in classify, the section's single source. The tag table stays checked by review only, as the registry's introduction says; this plan adds no test of it.

If the registry is not on origin/main (only after a revert of PR #87), record in the SUMMARY the rows and sentences above.

**Pointer sentences.** Each anchor occurs exactly once on origin/main (this task's precondition). Insert each text right after its anchor, inside the same line, and change nothing else in those files.
- **03-12-PLAN.md.** Anchor: ``a goroutine runs `keyroster ca issue` (admin path, user CA)``. Insert: `` (since 03-14d with `--installation-id` set to the bundle's installation ID, because the signer refuses an admin issue request that does not name its installation; see 03-14d-PLAN.md)``.
- **03-15-PLAN.md.** Anchor: `as your first admin action after the install`. Insert: `` (since 03-14d, v4's bundle names an installation ID, so every later `keyroster ca issue` on the signer passes `--installation-id` with v4's ID from the transcript, and a flagless one is refused; the rebind still comes first; see 03-14d-PLAN.md)``.
- No other plan gets a pointer: 03-13, 03-14 and 03-16 run no `ca issue` and add no signed format.

**Publish edits.** Make them in this PR, on top of origin/main. Every wave number is origin/main's value + 1. The totals (edits 2 and 3) are the true counts of the PLAN and SUMMARY files, which is what GSD's tracking update writes (03-14b's R2-1, as 03-14c applied it: the tracking update counts the files, and `state.advance-plan` bumps only the Plan line's leading number and keeps the `of M` it is given). Main's totals are consistent at 62b4407, so the true counts happen to equal main's + 1 this time. The values in brackets are what main holds at 62b4407. W12 is the `wave:` of origin/main's 03-12-PLAN.md [31].
0. **Stop guard, first.** Re-run Task 1's first precondition (03-14c's SUMMARY on main, origin/main's 03-12 at `wave: 31` with `depends_on: ["03-14c"]`, 03-14c the only plan at `wave: 30`). If it fails, main moved since the reconcile of 2026-11-13: stop and report for a re-reconcile, and make none of the edits below. This plan never takes over another plan's values silently.
1. Commit this plan as `.planning/phases/03-linux-agent-and-revocation/03-14d-PLAN.md`, unchanged: `wave: 31` and `depends_on: ["03-14c"]`.
2. ROADMAP.md, Phase 3:
   - The Plans line ([31/36 plans executed in 35 waves] → 31/37 plans executed in 36 waves). The total is the true count: phase 3 has 36 PLAN files on main, and this plan adds the 37th. The wave count goes up by one. GSD's tracking update at the end of this task rewrites only the counts, from the phase's PLAN and SUMMARY files: 32/37 plans executed in 36 waves. No tool touches the wave count.
   - The Progress table's Phase 3 row ([31/36] → 31/37, and 32/37 after the tracking update).
   - Insert, right before 03-12's wave block (ROADMAP.md:257 at 62b4407), the block `**Wave 31** *(blocked on Wave 30 completion)*` with the unchecked entry `- [ ] 03-14d-PLAN.md — Admin issue requests name their installation (F15): keyroster/issue-request/v2, the signer's refusals before any CA key, ca issue --installation-id, and one test that classifies every keyroster/ tag and signed request type`, followed by one blank line. The ROADMAP gate below builds exactly this row, ticked.
   - Renumber every later block one wave later ([31–35] → 32–36), each "blocked on" clause with them.
3. STATE.md, set by hand to the true counts:
   - `total_plans` ([71] → 72): every PLAN file under .planning/phases with this plan (21, 14 and 37);
   - `completed_plans` stays [66]: 66 SUMMARY files until this plan's SUMMARY lands;
   - the Plan line ([Plan: 31 of 36] → Plan: 31 of 37): 31 of phase 3's plans are executed, and the phase has 37 with this one.

   GSD's tracking update then writes, in this order (03-14b's R2-1, as 03-14c recorded it):
   - `state.advance-plan` bumps only the Plan line's leading number, to `Plan: 32 of 37`, and keeps the `of 37` this edit wrote. Like every STATE write, it also resets `total_plans` and `completed_plans` from the files: 72 and 67.
   - `state.update-progress` writes the same 72 and 67 again.
   - `roadmap.update-plan-progress` writes 32/37 into the Plans line and the Progress row and ticks the 03-14d row.

   So main ends at `total_plans: 72`, `completed_plans: 67` and `Plan: 32 of 37`.
4. 03-12-PLAN.md:
   - `depends_on` becomes `["03-14d"]` [it reads `["03-14c"]`];
   - in its first `<precondition>` (a single line at 62b4407, 03-12-PLAN.md:145, ending with 03-14c's SUMMARY clause), add the clause `` `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md` exits 0 `` right before that first `</precondition>`, joined with `; `. Every other clause stays.
5. Every phase-3 plan whose origin/main `wave:` is W12 or above gets `wave:` + 1: 03-12 to 03-16 [31–35] → 32–36. The stop guard ensures no other plan is there.
6. The two pointer sentences above.
7. The registry step above.
8. Nothing else in a landed plan or SUMMARY changes.

**After the tracking update** (the end of this task), check that GSD's roadmap update ticked only this plan's row: in Phase 3, every row other than the new 03-14d row is byte-identical to origin/main's, and the 03-12 to 03-16 rows are still `- [ ]`. An earlier tracking update ticked a plan by prefix (03-11b when 03-11 completed); here the prefix hazard is the 03-14 row. If another row was ticked, untick it with a scoped edit, record it in the SUMMARY, and rerun the ROADMAP gate below.

**Gates.** Run the test-time delta gate (Budget, Q-09-3) and the full gate. If this session or WSL boot is not the one that measured the base (after the continuation it never is), re-measure the base on origin/main in a detached worktree first, in place (Budget, "Another session"). `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record. 03-14c's run showed keyroster-signer at 91 pairs against a baseline of 92 (`internal/signer CAPABILITY_RUNTIME` no longer reported, 03-14c-SUMMARY.md); unless a baseline-tightening PR has landed first, record that stale pair in the SUMMARY as pre-existing, not as this plan's.

**Push, the PR and the pre-merge review.**
1. Before the publish commit, scan this plan file for private terms: `grep -inE 'find[i]ngs|FIX[-]PLAN|security[-]audit[-]skill|scratch[p]ad|App[D]ata' .planning/phases/03-linux-agent-and-revocation/03-14d-PLAN.md` prints nothing (the pattern brackets one character of each term, so the file never holds the terms it looks for; this plan holds the plain word for review results in no case, so the local pre-push scan, which matches case-sensitively on added lines, finds none either). Then commit by path only, signed and authored as Daniel:
   - the runbook and the registry (`docs(runbooks): name the installation in admin issue requests and record the format (F15)`);
   - the publish edits and the pointer (`docs(03-14d): publish the plan, point 03-12 at it, and shift the later waves`);
   - later, the SUMMARY.
2. Push the branch for the first time.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(signer): name the installation in admin issue requests (F15)"`. The body is neutral, lists the changes as in the objective, and names the limits that remain:
   - v1 requests still issue where the signer's bundle names no installation ID: such an installation accepts any v1 request signed by an admin key its policy lists, including one made for an installation with an ID and refused there;
   - audit verify cannot check which installation an issue request named, because an issue leaf keeps only the request digest;
   - LoginIssueRequest names no installation; a replay would need the same credential bound to the same user in both installations' directories and an origin both policies list (an owner-recorded residual that assumes each installation has its own RP hostname; reasoned, UNVERIFIED);
   - adminauth requests are bound to an exact origin from the root-verified policy, which assumes each installation has its own hostname (reasoned, UNVERIFIED), and agent-identity rotations to the agent's enrolled identity, not to the installation ID (as answered in Q-D1);
   - keyroster-signer and keyroster are upgraded together before admins pass `--installation-id`; an upgrade with a real older binary is UNVERIFIED.

   Write each of these bullets on one line: the leak gate requires UNVERIFIED on every line of the body that names LoginIssueRequest or adminauth.

   Do not enable auto-merge, now or later.
4. Wait for the required checks. Then run the house e2e gate in `MODE=pr` (the script between `# E2E_GATE_BEGIN` and `# E2E_GATE_END` of 03-10b-PLAN.md, with 03-11b's PROBE_PASS list, as 03-14c did): it requires the PR's e2e run to be for HEAD, both main lanes to pass at or under 900 s, and both probe lanes to pass. Confirm that both main lanes passed TestTrustRefuses/issue_names_installation, and that cli-windows and cli-macos passed (verify below). Record each main lane's `go test` seconds in the SUMMARY: at e38d6b3 they ran 780.827 s and 803.970 s (03-14c-SUMMARY.md), and the new subtest reuses TestTrustRefuses's env, so it adds no bootstrap. The e2e-pkcs11 and e2e-tpm workflows run on pull_request too; they are the CI proof for the pkcs11 and TPM issuance callers, and their run IDs go into the SUMMARY.
5. The orchestrator then runs the pre-merge review on the green PR, before Task 4. It reviews the diff against this plan's register (T-03-359 to T-03-362, or the recorded renumbering), and that review is the owner's threat review. A Codex lens may be part of it, on `git diff origin/main...HEAD` and the PR's text only. It also checks the diff for host names and private terms, which this plan does not list. Its results, the fix rounds and their checks are recorded in the SUMMARY.

**The SUMMARY** contains:
- the PR number and the check run IDs;
- R1, T1 and R2, with each RED and the cases that passed on R and why;
- the declarations and test helpers R1 added (v2Body, startFakeSignerOpts, statusWith at file level), every moved request builder (issueKR1 included), the reviewed and unedited builder sites, and the two namespace-overlap lists that gained AdminSSHSIGNamespaceV2;
- the unchanged controls that pin v1, green and unedited: TestIssueRequestBytesUnchanged, TestCAIssueAdminEvidence (its request names no ID, so it stays v1), TestParseIssueRequestRefusals' and TestSignerFraming's trailing-byte cases, and the tests that use the v1 tag or namespace as a wrong input (internal/wire/wire_test.go, internal/adminauth/adminauth_test.go, internal/server/admin_test.go, internal/audit/verify_test.go, internal/signer/revoke_test.go and login_test.go, test/e2e/login_refusal_test.go);
- every mutant under the mutant rule, with M1-3's FAIL line against the table, and that `pinned type not found` has no production mutant (`diff_logic` exercises it);
- the vectors' SHA-256 values and the derivation script's output;
- the exact names of 03-09 to 03-11's request types and tags as found, every tag's class with its reason, and that every bound wire tag is `raw` (expected at 62b4407);
- every e2e `"ca", "issue"` call site with its flag, and the one marked no-flag site;
- the `test-time base:` line (re-measured in place after each new session) and the delta gate's readings of cmd/keyroster, internal/signer and internal/wire (the whole-module run and Task 1's whole-signer run are pass or fail only);
- the main e2e lanes' seconds against the 900 s stop;
- the totals after the tracking update: the Plans line `32/37 plans executed in 36 waves`, the Progress row `32/37`, `total_plans: 72`, `completed_plans: 67` and `Plan: 32 of 37`;
- the registry's presence and what was recorded there;
- the threat-ID check (and any renumbering);
- what stays UNVERIFIED:
  - every runbook text on the homelab until its bundle names an installation at 03-15;
  - the e2e cases locally (CI only);
  - the LoginIssueRequest exemption across installations (reasoned, not tested);
  - the adminauth and agent-identity exemptions across installations (reasoned, not tested);
  - an upgrade with a real older binary: a v2 request to a real pre-03-14d signer (reasoned from TestSignerFraming's trailing_byte case), and an older CLI against an upgraded signer;
- capslock (with the pre-existing stale keyroster-signer pair, unless the baseline was tightened first), and the pre-merge review;
- `requirements-completed` left empty: REVOKE-01 and AUTH-06 are complete (03-11b); AGENT-06 is pending, owned by its PoP plans; this plan pins their binding and hardens KEY-02.

Then run the tracking updates once, commit `docs(03-14d): complete issue-installation plan`, push, and wait.
  </action>
  <verify>
    <automated>git diff --quiet HEAD -- docs/runbooks/signer-install.md docs/format-registry.md .planning/ROADMAP.md .planning/STATE.md .planning/phases/03-linux-agent-and-revocation/ && test -z "$(git ls-files --others --exclude-standard .planning/phases/03-linux-agent-and-revocation/03-14d-*.md)"</automated>
    <fails_when>non-zero exit: an edit to a file this plan publishes is not committed. This guard runs first, path-scoped</fails_when>
    <automated>( set -o pipefail; S=.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md; { test "$(grep -c '^test-time base: ' $S)" -eq 1 && T=$(sed -n 's/^test-time base: .* at=\([0-9][0-9]*\)$/\1/p' $S) && test -n "$T" && test $(( $(date +%s) - T )) -le 86400 || { echo 're-measure the base (Budget, test time)'; false; }; } && g() { sed -n "s/^test-time base: \(.* \)\{0,1\}$1=\([0-9.]*\) .*/\2/p" $S; } && CM=$(g cmd) && SG=$(g signer) && WR=$(g wire) && test -n "$CM" && test -n "$SG" && test -n "$WR" && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/signer/ ./internal/wire/' | awk -v m="$CM" -v s="$SG" -v w="$WR" '{print} $1=="ok" {t=$3; sub(/s$/,"",t); if ($2 ~ /\/cmd\/keyroster$/) {n++; if (t+0 > m+90) bad=1} else if ($2 ~ /\/internal\/signer$/) {n++; if (t+0 > s+90) bad=1} else if ($2 ~ /\/internal\/wire$/) {n++; if (t+0 > w+90) bad=1}} END{exit (n!=3||bad)}' )</automated>
    <fails_when>non-zero exit: the SUMMARY's single `test-time base:` line is missing, repeated or more than 24 h old (re-measure it in place, Budget; after a continuation, re-measure it anyway), or the `ok` line of cmd/keyroster, internal/signer or internal/wire is missing or more than 90 s above its base (stop and report, after a fresh re-measure confirms it), or "FAIL" or "DATA RACE" in the output (Q-09-3). The key parser `\(.* \)\{0,1\}` also reads the line's first key, `cmd=` (the defect 03-10c's SUMMARY T4-1 recorded)</fails_when>
    <automated>grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && go vet -tags e2e_pkcs11 ./test/e2e/ && go vet -tags e2e_tpm ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit (a gate failed; the whole-module test run is pass or fail only, with no per-package time cap, Q-09-3), or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>n(){ tr -s '[:space:]' ' ' < "$1"; } && m(){ n "$1" | tr -d '`'; } && m docs/runbooks/signer-install.md | grep -qF -- 'keyroster ca issue --installation-id <installation id>' && m test/manual/README.md | grep -qF -- 'keyroster ca issue --installation-id <installation id>' && m docs/runbooks/signer-install.md | grep -qF 'issue_installation_mismatch' && m docs/runbooks/signer-install.md | grep -qF 'leave out the flag only after keyroster trust verify shows installation id: none' && awk -v p='upgrade keyroster-signer and keyroster together before admins pass --installation-id' 'BEGIN{RS=""} {s=$0; gsub(/`/,"",s); gsub(/[[:space:]]+/," ",s); if (index(s,p)) {f=1; if (index(s,"Run in CI") && index(s,"UNVERIFIED")) ok=1}} END{exit !(f && ok)}' docs/runbooks/signer-install.md && if MSYS_NO_PATHCONV=1 git cat-file -e origin/main:docs/format-registry.md 2>/dev/null; then n docs/format-registry.md | grep -qF '`keyroster/issue-request/v2`' && n docs/format-registry.md | grep -qF 'Issue request v2 (`wire.IssueRequest`' && n docs/format-registry.md | grep -qF 'TestSignedRequestsBindInstallation' && n docs/format-registry.md | grep -qF 'bound to the installation at enrollment' && bash scripts/linux.sh 'go test -count=1 -timeout 15m ./internal/tlog/'; else test -z "$(git diff --name-only origin/main...HEAD -- docs/format-registry.md)"; fi</automated>
    <fails_when>non-zero exit: a ca issue example (signer-install.md or test/manual/README.md) lacks `--installation-id <installation id>` right after `keyroster ca issue` (03-14c's audit verify placeholder in signer-install.md does not satisfy this); the runbook update or its unknown-hint guidance is missing, or the upgrade-order paragraph lacks a `Run in CI` or UNVERIFIED label (backticks are ignored); or the registry is on origin/main and lacks the v2 row, the binding row, the test name or the agent-identity enrollment clause, or its own test fails; or it is not on origin/main and this branch added it</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && ns(){ N=$(git diff --numstat origin/main...HEAD -- "$P/$1") || return 1; printf '%s\n' "$N" | awk 'NF{print $1" "$2}'; } && test "$(ns 03-12-PLAN.md)" = "4 4" && test "$(ns 03-13-PLAN.md)" = "1 1" && test "$(ns 03-14-PLAN.md)" = "1 1" && test "$(ns 03-15-PLAN.md)" = "2 2" && test "$(ns 03-16-PLAN.md)" = "1 1" && test "$(grep -oF 'see 03-14d-PLAN.md)' $P/03-12-PLAN.md | wc -l)" -eq 1 && grep -qF 'a goroutine runs `keyroster ca issue` (admin path, user CA) (since 03-14d' $P/03-12-PLAN.md && test "$(grep -oF 'see 03-14d-PLAN.md)' $P/03-15-PLAN.md | wc -l)" -eq 1 && grep -qF 'as your first admin action after the install (since 03-14d' $P/03-15-PLAN.md && test -z "$(git diff --name-only origin/main...HEAD -- $P/ | grep -E 'SUMMARY\.md$' | grep -v '/03-14d-SUMMARY\.md$')"</automated>
    <fails_when>non-zero exit: a later plan changed beyond its wave line and its pointer line (expected: 03-12 4 4 for the wave, depends_on, precondition and pointer lines; 03-15 2 2 for the wave and pointer lines; 03-13, 03-14 and 03-16 1 1), a pointer is missing, repeated or not right after its anchor, or a landed SUMMARY changed</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && fw() { awk 'NR>1 && /^---$/{exit} /^wave: /{sub(/^wave: /,""); print}'; } && MSYS_NO_PATHCONV=1 git cat-file -e "origin/main:$P/03-14c-SUMMARY.md" && X12=$(MSYS_NO_PATHCONV=1 git show "origin/main:$P/03-12-PLAN.md") && test "$(printf '%s\n' "$X12" | fw)" = 31 && printf '%s\n' "$X12" | grep -qx 'depends_on: \["03-14c"\]' && W30=$(for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do if [ "$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw)" = 30 ]; then basename "$f"; fi; done) && test "$W30" = 03-14c-PLAN.md && test "$(fw < $P/03-14d-PLAN.md)" = 31 && grep -qx 'depends_on: \["03-14c"\]' $P/03-14d-PLAN.md && grep -qx 'depends_on: \["03-14d"\]' $P/03-12-PLAN.md && grep -n '<precondition>' $P/03-12-PLAN.md | head -1 | grep -qF '`MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md` exits 0</precondition>' && ( for e in 03-12:32 03-13:33 03-14:34 03-15:35 03-16:36; do test "$(fw < "$P/${e%%:*}-PLAN.md")" = "${e#*:}" || exit 1; done ) && ( for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do W=$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw) || exit 1; test -n "$W" || exit 1; if [ "$W" -ge 31 ]; then E=$((W+1)); else E=$W; fi; test "$(fw < "$f")" = "$E" || exit 1; done ) && AP='^\.planning/phases/[^/]+/[^/]+-PLAN\.md$' && AS='^\.planning/phases/[^/]+/[^/]+-SUMMARY\.md$' && PP='^\.planning/phases/03-linux-agent-and-revocation/03-[0-9a-z]+-PLAN\.md$' && PS='^\.planning/phases/03-linux-agent-and-revocation/03-[0-9a-z]+-SUMMARY\.md$' && n() { git ls-tree -r --name-only "$1" -- .planning/phases/ | grep -cE "$2"; } && ( for r in "$AP" "$AS" "$PP" "$PS"; do H=$(n HEAD "$r") && M=$(n origin/main "$r") && test "$H" -eq $((M+1)) || exit 1; done ) && ST=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/STATE.md) && printf '%s\n' "$ST" | grep -qx '  total_plans: 71' && printf '%s\n' "$ST" | grep -qx '  completed_plans: 66' && printf '%s\n' "$ST" | grep -qx 'Plan: 31 of 36' && test "$(grep -c '^  total_plans: ' .planning/STATE.md)" -eq 1 && grep -qx "  total_plans: $(n HEAD "$AP")" .planning/STATE.md && test "$(grep -c '^  completed_plans: ' .planning/STATE.md)" -eq 1 && grep -qx "  completed_plans: $(n HEAD "$AS")" .planning/STATE.md && test "$(grep -c '^Plan: ' .planning/STATE.md)" -eq 1 && grep -qx "Plan: $(n HEAD "$PS") of $(n HEAD "$PP")" .planning/STATE.md</automated>
    <fails_when>non-zero exit: the stop guard fails on origin/main (03-14c's SUMMARY missing, 03-12 not at wave 31 with ["03-14c"], or a plan other than 03-14c at wave 30: re-reconcile, publish nothing), or a publish edit is missing or wrong. It passes only on exactly the intended edit:
      - this plan's frontmatter reads `wave: 31` and `depends_on: ["03-14c"]`;
      - 03-12 reads `depends_on: ["03-14d"]`, and its first precondition ends with the new MSYS_NO_PATHCONV=1 clause;
      - 03-12 to 03-16 read waves 32 to 36; every other phase-3 plan on origin/main kept its frontmatter wave (each wave is read from the frontmatter only);
      - HEAD holds exactly one more PLAN file and one more SUMMARY file than origin/main, both in phase 3 (counted in the tree of HEAD, top-level phase directories only);
      - origin/main's STATE held the 62b4407 values `total_plans: 71`, `completed_plans: 66` and `Plan: 31 of 36`, and the branch's STATE holds exactly one line of each, with the true counts of HEAD's files: `total_plans: 72`, `completed_plans: 67` and `Plan: 32 of 37` (phase 3's SUMMARY files of its PLAN files).

      The gate counts files in HEAD's tree, and GSD's tracking update counts them on disk. An untracked PLAN or SUMMARY file under .planning/phases therefore shows up as a mismatch, which is right: that number would be wrong on main. Run it after the tracking update; before that update `completed_plans` reads 66 and the Plan line 31 of 37, and the gate fails by design
    </fails_when>
    <automated>ROW="- [x] 03-14d-PLAN.md — Admin issue requests name their installation (F15): keyroster/issue-request/v2, the signer's refusals before any CA key, ca issue --installation-id, and one test that classifies every keyroster/ tag and signed request type" && E=$(mktemp) && { MSYS_NO_PATHCONV=1 git show origin/main:.planning/ROADMAP.md | awk -v row="$ROW" '/^### Phase /{p=($0 ~ /^### Phase 3:/)} p && /^\*\*Plans:\*\* 31\/36 plans executed in 35 waves\./ {sub(/31\/36 plans executed in 35 waves/, "32/37 plans executed in 36 waves"); np++} p && /^\*\*Wave [0-9]+\*\* \*\(blocked on Wave [0-9]+ completion\)\*$/ {w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; if (w==31) {print "**Wave 31** *(blocked on Wave 30 completion)*"; print row; print ""; ni++} if (w>=31) {$0="**Wave " (w+1) "** *(blocked on Wave " w " completion)*"; nw++}} /^\| 3\. Linux Agent and Revocation \| 31\/36 \|/ {sub(/\| 31\/36 \|/, "| 32/37 |"); nr++} {print} END{exit (np!=1 || ni!=1 || nw!=5 || nr!=1)}' > "$E"; } && diff "$E" .planning/ROADMAP.md; rc=$?; rm -f "$E"; test "$rc" -eq 0</automated>
    <fails_when>non-zero exit: the ROADMAP differs from the exact intended file. The gate builds it from origin/main's ROADMAP (which must hold the 62b4407 base: the Phase 3 Plans line `31/36 plans executed in 35 waves`, Wave blocks 31 to 35, and the Progress row `31/36`), and compares whole files:
      - the Plans line reads `32/37 plans executed in 36 waves`, and the Progress row `| 32/37 |`: the true counts of phase 3's SUMMARY and PLAN files, which the publish gate checks against HEAD's tree, with the wave count 36 that no tool touches;
      - a new `**Wave 31** *(blocked on Wave 30 completion)*` block holds exactly the ticked 03-14d row (publish edit 2's row with `- [x]` for `- [ ]`), followed by one blank line, right before 03-12's block;
      - the former blocks 31 to 35 read 32 to 36, each blocked on the wave before;
      - every other line is byte-identical, so no other row was ticked (the 03-12 to 03-16 rows stay `- [ ]`, the 03-14 row included) and nothing matched by prefix.

      Run it after the tracking update, which ticks the 03-14d row and sets the executed count; before that update the row reads `- [ ]` and the count 31, and the gate fails by design</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')" && RL=$(git rev-list origin/main..HEAD) && test -n "$RL" && ( for c in $RL; do C=$(git cat-file commit "$c") || exit 1; printf '%s\n' "$C" | grep -q '^gpgsig' || exit 1; done )</automated>
    <fails_when>non-zero exit (no commits, another author or committer, or an unsigned commit)</fails_when>
    <automated>git fetch origin p03/14d-issue-installation && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-14d-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics|^\.planning/todos/'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, a forbidden file was committed, or a todo file was added)</fails_when>
    <automated>D=$(git diff origin/main...HEAD) && L=$(git log origin/main..HEAD --format=%B) && B=$(scripts/gh-as-bot.sh pr view p03/14d-issue-installation --json body,title --jq '.title + "\n" + .body') && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '127\.0\.0\.1' | grep -q . && printf '%s\n%s\n' "$L" "$B" | grep -ciE 'co-authored-by|generated with' | grep -qx 0 && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -iqE 'find[i]ngs[.]json|FIND[I]NGS[-]DETAIL|FIX[-]PLAN|security[-]audit[-]skill|scratch[p]ad|App[D]ata' && printf '%s\n' "$B" | grep -qF 'LoginIssueRequest' && printf '%s\n' "$B" | grep -qF 'adminauth' && ! printf '%s\n' "$B" | grep -E 'LoginIssueRequest|adminauth' | grep -vqF 'UNVERIFIED' && PR_TITLE="$(scripts/gh-as-bot.sh pr view p03/14d-issue-installation --json title --jq .title)" bash scripts/check-pr-title.sh</automated>
    <fails_when>non-zero exit: an IP address other than loopback, an attribution line, or a private artefact or local temporary path in the diff, a commit message or the PR text; the PR body lacks the LoginIssueRequest or the adminauth bullet, or a line of it that names either lacks UNVERIFIED; or the PR title is not Conventional Commits within 100 characters</fails_when>
    <automated>B=p03/14d-issue-installation && scripts/gh-as-bot.sh pr checks "$B" --required --watch && test "$(scripts/gh-as-bot.sh pr checks "$B" --json name,bucket --jq '[.[] | select(.name=="cli-windows" or .name=="cli-macos") | .bucket] | sort | join(" ")')" = "pass pass" && G=$(mktemp) && sed -n '/^# E2E_GATE_BEGIN/,/^# E2E_GATE_END/p' .planning/phases/03-linux-agent-and-revocation/03-10b-PLAN.md > "$G" && B="$B" PROBE_PASS='TestProbeSelfTestEndToEnd TestProbePairSpacing TestProbeCertsAgainstSSHD TestProbeSSHDFacts TestMachineIdentityEndToEnd TestMachineIdentityEndToEnd/renew_and_login TestMachineIdentityEndToEnd/collapse_is_generic TestMachineIdentityEndToEnd/if_due_sends_nothing TestMachineIdentityEndToEnd/revoke_machine_refuses_login_and_renewal TestMachineIdentityEndToEnd/keys_revokes_key_for_good TestMachineIdentityEndToEnd/sk_through_agent TestMachineIdentityEndToEnd/sk_key_file_named_error TestMachineIdentityEndToEnd/audit_verify_counts_machine_certificates' MODE=pr bash "$G"; rc=$?; rm -f "$G"; test "$rc" -eq 0 && R=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch "$B" --event pull_request --limit 1 --json databaseId --jq '.[0].databaseId // 0') && test "$R" -gt 0 && test "$(scripts/gh-as-bot.sh run view "$R" --json headSha --jq .headSha)" = "$(git rev-parse HEAD)" && JOBS=$(scripts/gh-as-bot.sh run view "$R" --json jobs --jq '.jobs[] | [(.databaseId|tostring), .conclusion, .name] | join("\t")') && for L in 9.5p1 10.5p1; do ID=$(printf '%s\n' "$JOBS" | awk -F'\t' -v n="e2e ($L)" '$3 == n {print $1}'); test -n "$ID" || { echo "no main lane $L"; exit 1; }; LOG=$(scripts/gh-as-bot.sh run view "$R" --job "$ID" --log); for t in TestTrustRefuses/issue_names_installation TestTrustRefuses/issue_names_installation/without_flag_refused TestTrustRefuses/issue_names_installation/other_installation_refused TestTrustRefuses/issue_names_installation/own_installation_issues; do printf '%s\n' "$LOG" | grep -qF -- "--- PASS: $t (" || { echo "main lane $L: no PASS line of $t"; exit 1; }; done; done</automated>
    <fails_when>non-zero exit: a required check failed or never reported; cli-windows or cli-macos did not pass; the house e2e gate in MODE=pr failed (the PR's pull_request e2e run is not for HEAD, a main lane failed, ran a probe test or took over 900 s, or a probe lane failed, lacks one of 03-11b's PASS lines or took over 420 s); the newest pull_request e2e run is not for HEAD's sha; or a main lane (9.5p1 or 10.5p1) lacks a `--- PASS: TestTrustRefuses/issue_names_installation (` line or one of its three cases. `B` is passed to the gate script as a prefix assignment because the script reads it from its environment</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/14d-issue-installation --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled on the PR)</fails_when>
  </verify>
  <acceptance_criteria>
    - The runbook text names its CI tests and its UNVERIFIED labels, and test/manual/README.md's example passes the flag; the registry carries the rows (it is on main since 5ec5ff9), or the SUMMARY records them after a revert.
    - Every commit is authored as Daniel, committed and signed by keyroster-bot.
    - The PR is open without auto-merge, every required check is green, cli-windows and cli-macos passed, the house e2e gate passed in MODE=pr for HEAD with both main lanes at or under 900 s, both main lanes passed TestTrustRefuses/issue_names_installation and its three cases, and 03-14d-SUMMARY.md is on its head.
    - The test-time delta gate passed against a base at most 24 h old, and the publish and ROADMAP gates passed after the tracking update.
    - The pre-merge review's results and fix rounds are in the SUMMARY.
  </acceptance_criteria>
  <done>The PR waits green and reviewed, with the plan, the runbook update, the registry rows (or their SUMMARY record), the pointers in 03-12 and 03-15 and the publish edits: this plan at wave 31 after 03-14c, and 03-12 to 03-16 one wave later (32 to 36).</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — the owner reviews PR p03/14d-issue-installation, and Daniel squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7), read with this plan's Delivery protocol override (merge-gate.sh's plain form only after the merge)
  </read_first>
  <action>After the pre-merge review (Task 3 step 5), the owner reviews, approves and squash-merges the PR in the GitHub web UI (owner, 2026-11-02). Claude never approves or merges, never enables auto-merge and never waits for it.</action>
  <instructions>
    1. Open `gh pr view p03/14d-issue-installation --web`. Read 03-14d-SUMMARY.md, and review:
       - the v2 encoding in internal/wire/issue.go, and that TestIssueRequestBytesUnchanged is unchanged;
       - Signer.Issue's three refusals and their place before verifyAdminEvidence;
       - the two vectors and the derivation the test checks;
       - TestSignedRequestsBindInstallation's table, every exemption string included;
       - ca issue's flag and hints, and the runbook's upgrade order.
    2. Approve and squash-merge in the GitHub web UI, with your commit email. No admin bypass, no "Update branch".
    3. Reply "merged". If main moved before you merged, Claude rebases the branch by hand and pushes it. Review the new head, then merge it and reply "merged".
  </instructions>
  <verification>
    - **Before the merge.** Claude runs merge-gate.sh only as `bash scripts/merge-gate.sh --check p03/14d-issue-installation`. It never runs the plain form before the merge.
    - **When main moved.** If `git merge-base --is-ancestor origin/main origin/p03/14d-issue-installation` fails after `git fetch origin`, Claude rebases by hand:
      - On the branch, run `git rebase --gpg-sign origin/main`. The authors stay Daniel's, and keyroster-bot is committer and signer.
      - For `.planning/` tracking files, take origin/main's version and re-apply only this plan's entries. For the runbook, test/manual/README.md and the registry, keep main's text and re-apply this plan's updates. If docs/format-registry.md is on origin/main and the branch does not edit it yet, apply Task 3's registry step before pushing.
      - If main added a signed request type, a `keyroster/` literal, an IssueRequest builder or an e2e `"ca", "issue"` call, extend the table or the builder, run Tasks 1 and 2's verify commands again, and record it.
      - Re-run Task 3's checks against the new origin/main: the anchor check, verify command 4 (runbook, test/manual and registry), the numstat and pointer check, the publish gate (with its stop guard) and the ROADMAP gate. Both gates pin main's 62b4407 base, so if main moved in its tracking files or its waves (another plan landed or was slotted in), they fail: stop and report for a re-reconcile, and never re-slot this plan silently. Record their readings.
      - Push with lease, as keyroster-bot, and do not enable auto-merge.
      - Wait for the required checks, run Task 3's authorship and signature check again, and ask the owner to review the new head.
    - **After the owner replies "merged".** From the main checkout, Claude runs `bash scripts/merge-gate.sh p03/14d-issue-installation`, which for a merged PR only fast-forwards local main and exits 0. Then Claude runs the `--check` form below.
  </verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/14d-issue-installation</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-12's new precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/14d-issue-installation --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>On main, every admin issue request names its installation, and every signed request type in internal/wire and every `keyroster/` literal in the code is classified by installation binding. 03-12 may start.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-09, 03-09b, 03-10, 03-10b, 03-10c, 03-10d, 03-11 and 03-11b** landed (#88 to #97).
  - HostIssueRequest, ProbeIssueRequest and MachineIssueRequest carry the installation ID as their first field at 62b4407 (D5). D5 reached 03-10 and 03-11 only through 03-09's Cross-plan notes; this plan's Task 1 precondition is the backstop, and stops if a type lacks the field.
  - Their request domains are classified in the table under their names on origin/main; each PoP evidence namespace is an alias of its request domain, so it needs no entry of its own.
  - Their signer tests that build an IssueRequest are found by Task 1's grep: 03-09b's issueKR1 sets the fixture's ID, and 03-11's admin_refusals_still_logged needs no edit (context).
- **03-14c** landed right before this plan (#99, 62b4407). It pins the CLI's installation and binds audit verify and recover, and does not touch ca issue, the signer or internal/wire. It moved 03-12's depends_on to itself; this plan moves it on to itself. Its stop guard and whole-file ROADMAP gate are the model for this plan's.
- **03-12** (CA rotation) runs after this plan, at wave 32 with ["03-14d"]. Its e2e goroutine's `keyroster ca issue` passes `--installation-id` (pointer sentence); its other e2e issuance goes through runIssue, which passes it.
- **03-13, 03-14 and 03-16** change only their wave: none runs `ca issue`, and none adds a signed request type. **03-15** also gets one pointer: its v4 install gives the homelab bundle an installation ID, after which every `ca issue` there needs the flag (one such issue there would lift the runbook's homelab UNVERIFIED label). A later plan that adds a `keyroster/` literal or a SigningBytes type fails TestSignedRequestsBindInstallation until it is classified, and adds its row to the format registry in the same PR; that row is review-enforced, since no test reads the registry's tag table.
- **The format registry (PR #87).** It merged before this plan (5ec5ff9), so Task 3 edits it, and Task 4's rebase re-applies the edit. Only if it were reverted would the SUMMARY carry the rows instead.
- **Threat IDs of siblings.** 03-09's note lets 03-09b continue after 03-14c's last ID; with this plan holding T-03-359 to T-03-362, 03-09b's overflow must continue after T-03-362. This plan cannot edit 03-09's text. Its row-anchored ID check keeps a mere mention from forcing a renumbering, and stops on a real register row in the range.
- **Phase 4.** Q-C8's review of the LoginIssueRequest exemption, and with it Q-D1's shared hostname assumption.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: what binds, and what does not.**
- **Shared admin keys** (F15's condition). Whether any two installations list a common admin key is UNVERIFIED. A replay needs the request within 300 s and a peer on the other signer's socket. After this plan it is refused wherever the target's bundle names an ID.
- **Installations without an ID** (Q-C2 A). Such an installation accepts any v1 request signed by an admin key its policy lists, including one made for an installation with an ID and refused there; B would have closed it.
- **Mixed versions.** keyroster-signer and keyroster are installed together from one build. A v2 request to an older signer is refused as malformed_request, with ca issue's hint (reasoned from TestSignerFraming's trailing_byte case). Upgrading a signer whose bundle names an ID makes every flagless ca issue refuse, and a keyroster CLI older than the signer gets no hint; the runbook gives the order. Not tested with a real older binary: UNVERIFIED.
- **Audit.** An issue leaf keeps only the request digest, so audit verify cannot show which installation a request named. A namespace check on the evidence after a bundle with an ID would catch only a signer bug; deferred.
- **Exemptions.** LoginIssueRequest (Q-C8), adminauth.Message and the agent-identity rotation (Q-D1 = A), each with its recorded reason; none is tested across installations.
- **Hardware.** None. Every test uses software keys.

**Edges:**
- **Wire:**
  - the v1 bytes, body and constants unchanged; the v2 vector and its derivation from v1;
  - round trip; an empty trailing ID; bytes after the ID; a truncated ID; 31 and 33 hex digits; upper case; the v2 body helper; the two domains and namespaces;
  - the fuzz seeds.
- **Signer:**
  - another installation's frame (F15's shape), also where the policy does not list the admin (the order before the evidence); a rewritten ID;
  - v1 where an ID exists; v2 where none exists; v1 where none exists; v2 for its own installation;
  - v1 evidence under v2; a v2 frame stripped to v1 at an ID-less signer;
  - classification;
  - every existing builder of an issue request.
- **ca issue:** a malformed flag; the request it builds; the three refusal hints, the older-signer hint, and no hint for malformed_request without the flag.
- **The table:** every SigningBytes type, through reflection on its InstallationID field; every `keyroster/` string literal in the module; the bound wire tags in their types' signing bytes; the three exemptions; the comparison on a parsed source (`diff_logic`); the RED on origin/main's code.
- **e2e:** the three cases of TestTrustRefuses/issue_names_installation, and every e2e call site with the flag except the one marked no-flag case.
- **The controls that must not change:** TestIssueRequestBytesUnchanged; the revoke, forget and recovery vectors; TestCAIssueAdminEvidence; TestParseIssueRequestRefusals and TestSignerFraming (their trailing-byte cases); the namespace-overlap checks of the forget and machine namespaces, now with the v2 namespace; the whole internal/signer package.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access granted centrally takes effect in the installation it was granted for, and only there | Tasks 1-2 |
| REQ | REVOKE-01, AGENT-06, AUTH-06 (their requests stay bound; REVOKE-01 and AUTH-06 complete since 03-11b, AGENT-06 pending) | Task 2: the table pins RevokeRequest and the D5 types |
| F15 | The installation in the signed bytes; signer refusals before evidence and CA use; ca issue fills it from the admin, never from the signer; audit cannot check (stated) | Task 1; Q-C2 |
| OQ-1 | A (Daniel, 2026-11-13): ca issue takes the ID from `--installation-id` only, never from or checked against the CLI config's pin; it reads no config and runs on the signer host, and the signer refuses a wrong ID before any CA key | Owner decisions; planner decision "The ID comes only from"; Task 1 (the flag is the ID's only source; ca.go gains no config read) |
| Owner decision | Q-09-3: `-timeout 15m` on every go test gate, a delta over a quiet base at most 24 h old, stop at +90 s | Budget; Task 1 (base line); Task 3 (delta gate, full gate pass or fail); `-timeout 5m` on every mutant |
| Q-C2 | A, on the corrected facts: the open case at ID-less installations (any v1 request, including one refused at an installation with an ID), HostIssue's strict precedent (`host_issue_no_installation_id`), B's small cost, mixed versions | Owner decisions; Task 1 (hint on malformed_request); Task 3 (upgrade order, PR body) |
| Q-C8 | The LoginIssueRequest exemption as an owner-recorded residual; the PR body does not state it as fact | Owner decisions; Task 2 (exemption string); Task 3 (PR body, the leak gate's per-line UNVERIFIED check); T-03-361 |
| Q-D1 | A: adminauth.Message and the agent-identity rotation are owner-approved exemptions with their reasons | Owner decisions; Task 2 (tags); Task 3 (registry, PR body, leak gate); T-03-361 |
| D5 | The PoP request types bound | Task 1 precondition; Task 2 table |
| Registry | A new signed format adds its rows; the rule's exceptions recorded; present (since 5ec5ff9) or absent | Task 3 registry step; Task 4 rebase |
| Critic | The homelab at 03-15, where flagless ca issue starts to be refused | Task 3 (03-15 pointer) |
| Owner decision | Q-C9 split and slot directly after 03-14c, before 03-12 | Frontmatter (wave 31); Task 1's stop guard; Task 3 publish edits, publish gate and ROADMAP gate |
| Owner decision | Delivery: plan in its PR, neutral wording, F-number only, signed commits, no auto-merge, outside review on the diff only | Delivery protocol; Tasks 3 and 4 |
| Owner decision | Hardware never required; untested paths UNVERIFIED | Edge Coverage; runbook label; SUMMARY list |
| CONTEXT | 03-CONTEXT D-04 (the installation-binding rule) | Task 1 (the signer's rule copies D-04's) |
| CONTEXT | 03-CONTEXT D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 3 |
| Deferred | An audit-side namespace check on issue evidence | Planner decisions; T-03-361 |

## Artifacts this phase produces (this plan)

- **internal/wire:** IssueRequest.InstallationID; IssueRequestDomainV2 and AdminSSHSIGNamespaceV2; Namespace(); the v2 encoding with its three refusals; the fuzz seeds; test/vectors/issue_request_signing_v1.hex and v2.hex.
- **internal/signer:** issue_installation_missing, issue_installation_mismatch and issue_installation_unknown, classified as unauthorized; evidence under the request's namespace.
- **cmd/keyroster:** `ca issue --installation-id` with its four hints.
- **Tests:** TestIssueRequestSigningVector (3), TestIssueRequestV2 (8), TestIssueInstallation (10), TestCAIssueInstallation (7), TestSignedRequestsBindInstallation (3), TestTrustRefuses/issue_names_installation (e2e, 3); the test helpers v2Body and startFakeSignerOpts.
- **Docs:** signer-install.md section 8; test/manual/README.md's example; the registry rows.
- **Planning:** the pointers in 03-12 and 03-15.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| a signer socket peer → the signer | An allowed peer (the web server, a human with socket access) submits admin-signed issue requests, possibly captured from another installation within the 300 s window |
| the admin's CLI → the request it signs | The admin states which installation the approval is for; the socket the admin talks to must not choose it |
| a new signed format → every installation | A format added later must name the installation it is for, or carry a recorded exemption |

## STRIDE Threat Register

Threat IDs follow 03-14c (T-03-350 to T-03-356), from T-03-359. Task 1's precondition checks that no threat-register row on origin/main defines T-03-359 to T-03-362 (a mention, such as 03-14c's mapping table, does not count), or renumbers. The mapping from 03-14c's first draft: its T-03-352 (F15) is T-03-359, its T-03-355 (a later signed format) is T-03-360, and the F15 half of its T-03-357 (accepted residuals) is T-03-361.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-359 | Elevation of privilege | an admin issue request approved for installation A is replayed within 300 s to installation B, whose policy lists the same admin key, and B's CA issues (F15) | low | mitigate | IssueRequest v2 signs the installation ID first; the signer refuses missing, mismatch and unknown after the freshness check and before the evidence and any CA key; a rewritten ID fails the evidence; ca issue takes the ID only from the admin, and its unknown hint sends the admin to trust verify instead of dropping the flag on the socket's word. Tests: TestIssueInstallation (installation_checked_before_evidence among them), TestIssueRequestSigningVector, TestIssueRequestV2, TestCAIssueInstallation, TestTrustRefuses/issue_names_installation (e2e), mutants M1-1 to M1-13. **Residual:** an installation whose bundle names no ID accepts any v1 request signed by an admin key its policy lists, including one made for an installation with an ID and refused there (Q-C2 A, accepted) |
| T-03-360 | Spoofing | a signed format added later (or one of 03-09 to 03-11's) names no installation, so an approval or PoP signature for one installation is valid in another | low | mitigate | TestSignedRequestsBindInstallation: every SigningBytes type in internal/wire is checked through its InstallationID field; every `keyroster/` string literal in the module's non-test code is classified, and a bound wire tag must be carried by its type's signing bytes; `diff_logic` tests the comparison itself; Task 1's precondition stops if a D5 type lacks the field; the registry's rule and rows. Mutants M2-1 to M2-3. **Residual:** a tag without the `keyroster/` prefix (tpm.probeDigest's `keyroster tpm key probe`; the evidence type names `admin-sshsig/v1` and `webauthn-assertion/v1`) or one built at run time is not seen by the walk; a tag outside internal/wire is classified, not proven, so a wrong label is caught only by review; the registry's tag table is kept in step by review only |
| T-03-361 | Elevation of privilege | accepted residuals: LoginIssueRequest names no installation (Q-C8); adminauth.Message is bound to an exact origin and the agent-identity rotation to the enrolled identity, not to the installation ID (Q-D1 = A); audit verify cannot bind an issue entry; v1 at ID-less installations | low | accept | LoginIssueRequest is approved by the user's passkey for a credential the installation-bound directory binds, under an origin the policy lists; a replay needs the same credential and user in both directories and an origin both policies list; it assumes each installation has its own RP hostname (owner-recorded, reasoned, UNVERIFIED; revisit in Phase 4). adminauth.Message (owner-approved exemption, Q-D1 = A, Daniel 2026-11-05): bound to an exact origin taken from the root-verified policy; this assumes each installation has its own hostname, the same assumption as Q-C8 (the origin check is tested, TestVerify/other_deployment_origin_refused; the cross-installation property is reasoned, UNVERIFIED). The agent-identity rotation (owner-approved exemption, Q-D1 = A): accepted only over mTLS, from the same old identity that signs it, and that identity is bound to the installation at enrollment (enroll.PoP). An audit-side check needs a leaf format change; a namespace check would catch only a signer bug (deferred). The v1 residual is T-03-359's |
| T-03-362 | Denial of service | mixed versions: a v2 request to an older signer is refused malformed_request; after a signer upgrade, every flagless ca issue on an installation with an ID is refused, and a keyroster CLI older than the signer is refused without a hint | low | mitigate | ca issue hints on malformed_request when the flag is set, and on the three new refusals; the runbook gives the order (keyroster-signer and keyroster together, from one build, then the flag) and says to upgrade an older CLI; the e2e helpers pass the flag. **Residual:** UNVERIFIED with a real older binary (reasoned from TestSignerFraming's trailing_byte case); an older CLI gets no hint |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; go/parser and reflect are stdlib and used in tests only. dep-firewall and testonly-firewall unchanged. The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh) or in CI as stated; the test-time delta gate passes against a base at most 24 h old (Q-09-3), and the full gate passes, its whole-module run pass or fail only; the publish and ROADMAP gates pass after the tracking update; the PR's required checks are green, and the house e2e gate passes in MODE=pr with TestTrustRefuses/issue_names_installation passing in both main lanes; the pre-merge review is recorded, and the merge gate passes.
</verification>

<success_criteria>
- A signer whose bundle names an installation issues only admin requests that name it; a request approved for another installation, or with a rewritten ID, is refused before its CA signs.
- The v1 bytes, body and constants are unchanged and still issue where no installation ID exists; the v2 bytes are pinned by a vector derived from the v1 one.
- `keyroster ca issue --installation-id` names the installation, and its refusals carry hints, an older signer's included.
- Every `keyroster/` string literal in the module and every signed request type in internal/wire is classified by installation binding, with the exemptions recorded.
- No trust bundle field, leaf format or other signed format changed, and no module was added.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-14d-SUMMARY.md` in Task 3, before the merge gate. Leave `requirements-completed` empty: REVOKE-01 and AUTH-06 are complete (03-11b) and AGENT-06 is pending, owned by its PoP plans; this plan pins their binding and hardens KEY-02. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (F15; plan check 1 of 03-14c, whose F15 items moved here with Q-C9; the owner's answers Q-C2, Q-C8 and Q-C9; the format registry's executor's note on adminauth and the agent-identity rotation)

| Item(s) from 03-14c's plan check 1 | Severity | How Addressed here |
|---------------------------------------|----------|--------------------|
| wire-audit-02 + tests-01 (R3's declarations contradicted its RED list) | MAJOR | Fixed: route (a). R1 declares the field, the V2 constants, a v1-returning Namespace() and the flag on the struct; Marshal, Parse and SigningBytes stay as today; each refusal case asserts a T1-only message; mutants M1-6 and M1-7 for the two new parse checks |
| tests-03 (existing signer tests break; the package never ran whole) | MAJOR (ruled MINOR) | Fixed: e.request(), SignRequest and the literal in TestSubjectResolutionTime/older_longer_cap_found set the fixture's ID and sign under req.Namespace() in R1; an execution-time grep finds the rest; internal/signer runs whole in Task 1, under 480 s (since the 62b4407 reconcile, D01, pass or fail under `-timeout 15m`, Q-09-3); revoke_test.go is in files_modified (and revoke_host_test.go since D05) |
| wire-audit-04 + tests-07 (M3-3's killer; the rewritten-ID replay) | MINOR | Fixed: `id_rewritten_refused` is the signer-level killer of M1-3; `v1_signature_refused_as_v2` is no longer listed as one; M2-1's -run includes TestForgetRequestSigningVector |
| wire-audit-05 (fuzz) | MINOR | Fixed: v2, trailing and malformed-ID seeds in FuzzParseIssueRequest, with namespace and prefix assertions, and a 20 s fuzz run in Task 1's verify |
| wire-audit-06 + tests-08 (self-confirming vector) | MINOR | Fixed: the v1 file from origin/main's code, the v2 file derived by a recorded script, and `v2_derived_from_v1` checks the derivation on the files |
| wire-audit-08 + critic-pr-body-login-unverified | MINOR | Resolved by the owner (Q-C8): the exemption reason names the origin check and the credential, not the RP ID; owner-recorded residual; the PR body labels it UNVERIFIED, and the leak gate checks that the label is there |
| wire-audit-09 (table by method name, free-form constructors) | MINOR | Fixed: reflection sets the `InstallationID` field of a valid template; pointer and value receivers; a module-wide walk of `keyroster/` tag constants classifies every tag |
| tests-09 + wire-audit-10 (builder fallback) | MINOR, INFO | Fixed in Round 1 (d-wire-signer-02): the fake socket did not capture the body or answer a chosen refusal, so R1 extends it (startFakeSignerOpts); no builder fallback |
| closure-QC2-facts-incomplete | MINOR | Fixed in the Q-C2 decision: the open case between ID-less installations, 03-09's strict HostIssue rule, B's small cost |
| closure-F15-stripped-downgrade-untested | MINOR | Fixed: `v2_frame_stripped_to_v1_refused` |
| critic-mixed-version + wire-audit-11 | MINOR, INFO | Fixed: the older-signer hint and `hint_malformed_with_flag` (so named since Round 1; mutant M1-9); the upgrade order in signer-install.md and the PR body; in the Q-C2 facts |
| critic-namespace-doc-drift | INFO | Fixed: evidence.go, issue.go and ca.go doc comments name both namespaces; Task 1's last verify command checks that no non-test comment there names only v1 |
| critic-adminauth-inventory, and the registry executor's note | INFO | Raised as Q-D1; decided A by the owner on 2026-11-05 and recorded in Round 1; both formats are in the inventory, the tag table and T-03-361 |
| closure-F15-audit-namespace-check | INFO | Recorded: the weak audit-side namespace check is deferred on purpose (planner decision, T-03-361) |
| wire-audit-01 (format registry, F15 part) | MAJOR (ruled MINOR) | Fixed: Task 3's registry step adds the v2 tag row, rewords the v1 row, adds the binding row and the exceptions, and names the test; it tolerates the registry being present or absent |
| critic-d5-0310-0311-untracked + slot-09 | MINOR, INFO | Recorded in the Cross-plan notes; Task 1's precondition is the backstop |
| slot-01, slot-04, slot-07, slot-08 (the guard, anchors, rebase re-checks, threat IDs) | MINOR | Applied here as in 03-14c: publish edit 1 always takes origin/main's 03-12 values and the guard checks both; the anchor check in Task 1 and Task 3; Task 4's rebase re-runs Task 3's publish checks; Task 1 checks T-03-359 to T-03-362 (row-anchored since Round 1) |

### Round 1 — plan check 1 of 03-14d (2026-11-05, with 03-14c's plan check 2): one MAJOR, MINORs, INFOs and the owner's Q-D1 answer

| Item(s) | Severity | Disposition |
|------------|----------|-------------|
| d-binding-test-01 | MAJOR | Fixed: M2-3 adds a new SigningBytes type (ExampleRequest) to a non-test file of internal/wire, which compiles and vets; `pinned type not found` has no production mutant and is exercised by the new `diff_logic` subtest; acceptance, T-03-360 and the SUMMARY item updated |
| d-slot-docs-threat-02 (and critic-adminauth-inventory) | MINOR | Fixed: Q-D1 = A recorded in Owner decisions with the owner's two reasons verbatim; `## Open owner questions` reads exactly `None open.`, and the planner decisions have their own heading; the B and C branches are gone; the enrollment clause is in the exemption string, the registry sentence and T-03-361 |
| d-slot-docs-threat-01 (and slot-08) | MINOR | Fixed: the threat-ID precondition matches only register rows (`^\| T-03-(359|36[0-2]) \|`), its fallback renumbers from the highest ID that starts a register row, and the review range says "or the recorded renumbering" |
| d-wire-signer-01 (and wire-audit-05) | MINOR | Fixed: R1 adds `v2Body`, which builds every v2, trailing, truncated and malformed-ID body and seed; `v2_body_helper_parses` (RED) and `truncated_id_refused` (passes on R1, recorded) added; marshalUnchecked's doc comment corrected |
| d-wire-signer-02 (and wire-audit-10, tests-09) | MINOR | Fixed: R1 adds startFakeSignerOpts (the last IssueRequest body, a chosen ErrorResponse) and lifts statusWith to file level, with startFakeSigner's callers unchanged; the Round 0 ledger row is corrected |
| d-wire-signer-03 | MINOR | Fixed: TestCAIssueInstallation is table-driven over hint_missing, hint_mismatch, hint_unknown, hint_malformed_with_flag and the control no_hint_malformed_without_flag; mutant M1-13 (the unknown hint) |
| d-wire-signer-04 | MINOR | Fixed: `installation_checked_before_evidence` (B does not list A's admin; mismatch, not evidence_not_admin) and mutant M1-12 |
| d-wire-signer-05 | INFO | Fixed: mutants M1-10 (the missing branch) and M1-11 (the unknown branch) |
| d-wire-signer-06 | MINOR | Fixed: `go vet -tags e2e_pkcs11` and `-tags e2e_tpm` in Task 2's first verify and Task 3's full gate; the e2e-pkcs11 and e2e-tpm runs are named as CI proof |
| d-wire-signer-07 + d-slot-docs-threat-05 | INFO | Fixed with option (a): the older-signer claim is labelled reasoned (TestSignerFraming's trailing_byte case) and UNVERIFIED, in the runbook, the SUMMARY list, Edge Coverage and T-03-362. The order is "keyroster-signer and keyroster together, then the flag", because signer-install.md section 2 installs both binaries from one build (the skeptic's refutation of "CLIs first" holds); the older-CLI case is stated |
| d-wire-signer-08 | INFO | Fixed: exact evidence details asserted (evidence_digest_mismatch, evidence_wrong_namespace twice); the doc-drift gate checks per file, and EvidenceAdminSSHSIG's doc comment must name AdminSSHSIGNamespaceV2 |
| d-binding-test-02 | MINOR | Fixed: a bound wire tag names a templated type whose signing bytes must carry it (raw, or a recorded contains for a D5 type; since the 62b4407 reconcile, D06, raw only, because every D5 type prepends its domain raw); tags outside internal/wire are classified, not proven, and name TestCheckInstallation, TestVerifyManifest/other_installation_refused, TestPoP/other_installation_refused and TestInstallationIDSuccessor; the trust bundle's reason is restated |
| d-binding-test-03 + d-slot-docs-threat-06 (and wire-audit-09) | MINOR | Fixed: the walk collects every `keyroster/` string literal (BasicLit), wherever it occurs; every claim says "every `keyroster/` string literal"; tpm.probeDigest and the evidence type names are in T-03-360's residual |
| d-binding-test-04 | MINOR | Fixed: t.Errorf for every entry, the `<name>: SigningBytes: <err>` message, the anchored `: IssueRequest has no` match, and exactly two diagnostic lines in the RED |
| d-binding-test-05 | INFO | Fixed: the `bind` prefix, and the RED copies R2's committed file |
| d-binding-test-06 | INFO | Fixed: PoP namespaces are classified per type (`bound through <Type>`); 03-09's alias needs no entry. At 62b4407 all three PoP namespaces are aliases, so the `bound through <Type>` form is gone (D06 of the reconcile) |
| d-binding-test-07 | INFO | Fixed: Task 2 re-runs M1-3 against the table and records the FAIL line |
| d-binding-test-08 | INFO | Not taken: the optional check that every tag has a registry row. With the v2 row absent on main it would add a third RED diagnostic, and the registry's own introduction says its tag table is checked by review. Stated as review-enforced in the Cross-plan notes, the registry step and T-03-360 |
| d-slot-docs-threat-03 | MINOR | Fixed: the leak gate requires UNVERIFIED on every PR-body line that names LoginIssueRequest or adminauth, and both bullets must exist; the adminauth bullet names its hostname assumption |
| d-slot-docs-threat-04 | MINOR | Fixed: the residual is restated everywhere as any v1 request at an ID-less installation, including one refused at an installation with an ID; `host_issue_no_installation_id` |
| d-slot-docs-threat-07 | MINOR | Fixed: Task 4's rebase applies the registry step if needed and re-runs verify command 4. PR #87 is on main since 5ec5ff9, so Task 3's registry branch is the live one |
| d-slot-docs-threat-08 | MINOR | Fixed: test/manual/README.md's example gets the flag (Task 3 files, frontmatter, verify command 4) |
| d-slot-docs-threat-09 + critic-runbook-phrase-backticks | INFO, MINOR | Fixed: verify command 4 strips backticks (m() and the awk gsub); the upgrade order is one paragraph with its labels |
| d-slot-docs-threat-10 | INFO | Recorded in the Cross-plan notes (03-09b's overflow continues after T-03-362); 03-09's text is not this plan's to edit |
| critic-unknown-hint-steers-v1 | MINOR | Fixed: the unknown hint sends the admin to `keyroster trust verify` first; pinned by hint_unknown and M1-13; the runbook and a planner decision say so |
| critic-e2e-caller-gate-vacuous | MINOR | Fixed: every e2e `"ca", "issue"` site must have `--installation-id` within four lines; the one no-flag site carries a marker that must appear exactly once; ca_issue_without_admin_key passes the flag too |
| critic-homelab-0315-no-carrier | INFO | Fixed: a 03-15 pointer at `as your first admin action after the install`; Task 1 and Task 3 check that anchor; 03-15's numstat is 2 2 |
| critic-budget-understated | INFO | Fixed: the Budget states the plan's measured size |
| c-new-text-05 (03-14c's plan check 2) | MINOR | Fixed here: verify command 4 anchors on `keyroster ca issue --installation-id <installation id>`, which 03-14c's audit verify placeholder cannot satisfy |

## Reconcile ledger (62b4407, 2026-11-13)

The plan was written, checked and owner-answered at f7eb018. The reconcile of 2026-11-13 compared it with main at 62b4407 (PR #99, 03-14c merged), across the fourteen squash commits #87 to #100. Verdict: fix in place, no re-plan. None of the code this plan edits changed since f7eb018; every code anchor, both pointer anchors and the reserved threat-ID gap (register rows run to T-03-356 and resume at T-03-363) hold. The one owner question it raised, OQ-1, Daniel answered A on 2026-11-13. Every reconcile item was re-checked against 62b4407 before it was applied; where the check differed from the item, its row says so.

| id | severity | what changed in this plan |
|----|----------|---------------------------|
| D01 | BLOCKER | Budget's test-time block is Q-09-3 in 03-14c's form, over this plan's packages: Task 1's first action step writes one `test-time base: cmd=<s> signer=<s> wire=<s> at=<epoch>` line on unchanged origin/main, with a format check in Task 1's acceptance criteria; precondition 8 now says the base is measured and recorded, and never stops the plan by itself. Task 3's delta gate stops at +90 s per package (`n!=3`, with 03-14c's `g()` key parser), requires the base to be at most 24 h old and re-measures it in place in another session or WSL boot. The 400 s and 480 s awk gates (Budget, Task 1's second verify, Task 3's old second and third) and the "480 s alone" acceptance are gone; Task 1's whole-signer run and the whole-module run are pass or fail. Every go test carries `-timeout 15m` (the fuzz, RED and tlog runs included; both `-timeout 300s` replaced) and every mutant command `-timeout 5m`. The Gates paragraph, the SUMMARY list, `<verification>`, a Source Coverage row and the Round 0 tests-03 row say the same. Corrected from the item: internal/signer's 434.274 s is a `./...` reading from 03-09b's first full gate, not an alone run; its multi-package bases read 323 to 417 s (03-10, 03-10d, 03-11), and internal/wire has recorded bases (8.549 s and 8.764 s, 03-10 and 03-11) |
| D02 | BLOCKER | The leak gate spells both artefact names with a bracketed letter inside the word (`find[i]ngs[.]json`, `FIND[I]NGS[-]DETAIL`); under `grep -iE` it matches as before. Reworded: the pre-merge review step ("Its results, the fix rounds and their checks"), its acceptance criterion ("results and fix rounds"), the Round 0 intro ("F15 items") and both ledger headers ("Item(s)"); also the delivery rule ("name the issue only as F15"), which held the singular, so the plan holds the word in no case, as 03-14c's does. Task 3's push step 1 scans this plan file for the private terms before the publish commit, with 03-14c's pattern |
| D03 | MAJOR | Frontmatter `wave: 31`. Truth 1 reads "(31 at 62b4407, 03-14c merged as #99)". Task 1's precondition 1 is 03-14c's stop guard, re-based: 03-14c's SUMMARY on main, origin/main's 03-12 at wave 31 with ["03-14c"], 03-14c the only plan at wave 30, every wave read from the frontmatter (`fw()`). The derived D, the absorb guard (old point 9) and the "+1 from W12" brackets are gone, and publish edit 0 re-runs the stop guard. The brackets are 62b4407's values: the new block `**Wave 31** *(blocked on Wave 30 completion)*` right before ROADMAP.md:257, blocks [31–35] → 32–36, and 03-12 to 03-16 → waves 32 to 36. Task 4's rebase step and the Cross-plan notes follow: a moved base stops for a re-reconcile. Checked at 62b4407: 03-14c is the only plan at wave 30, and 03-12 to 03-16 sit at 31 to 35 |
| D04 | MAJOR | Publish edits 2 and 3 write the true totals (03-14b's R2-1, as 03-14c applied it): `31/37 plans executed in 36 waves`, the Progress row `31/37`, `total_plans: 72`, `completed_plans` kept at 66 and `Plan: 31 of 37`; the tracking update makes them 32/37, 67 and `Plan: 32 of 37`. The publish gate is 03-14c's form: it derives the STATE values from HEAD's PLAN and SUMMARY counts, each exactly one more than origin/main's, and pins main's base (71, 66, `Plan: 31 of 36`). The ROADMAP gate builds the exact intended file from origin/main (`31/36 … 35 waves`, `\| 31/36 \|`, blocks 31 to 35) and compares whole files, so only the 03-14d row may turn `- [x]`; the action adds the after-tracking prefix-tick check (the hazard is the 03-14 row). Publish edit 2's row carries `- [ ] ` and a blank line, byte for byte the gate's row before the tick. Checked at 62b4407: 71 PLAN and 66 SUMMARY files (21, 14 and 36; 21, 14 and 31), ROADMAP.md:163 and :340, and STATE's three values |
| D05 | MAJOR | internal/signer/revoke_host_test.go is in files_modified and Task 1's files, and R1 sets issueKR1's `req.InstallationID = e.fx.InstallationID`. The context lists the six literals at 62b4407 with each one's fixture; machineissue_test.go (TestMachineIssueBucket/admin_refusals_still_logged), evidence_test.go and signer_test.go are recorded as reviewed and left unedited unless the whole-package run fails. The read_first grep is narrowed to `(^\|[^A-Za-z])wire\.IssueRequest\{`, which also matches `&wire.IssueRequest{` and none of the other request types. Found beyond the item: probeissue_test.go:443 also calls issueKR1; evidence_test.go's refusal table builds on ID-less fixtures, so its v1 evidence for an outsider still reaches evidence_not_admin (the item left that open) |
| D06 | MINOR | "15 values" becomes "18 values at 62b4407: the 15 of f7eb018 plus the three D5 request domains" in the planner decision, Task 2's read_first and the tags walk. The "bound through a type" bullet is replaced: each D5 PoP namespace aliases its request domain, so no such entry exists, and one would break the RED's two-line count. The three D5 tags are listed as bound wire tags, all `raw` (hostissue.go:135, probeissue.go:155, machineissue.go:136). The `contains` form is dropped, because no format uses it and it would be an unexercised branch. The inventory row names the three tags; the Cross-plan bullet and two Round 1 rows are annotated |
| D07 | MINOR | The code header reads "as read on main at f7eb018 and re-read at 62b4407", with the no-diff and other-functions-only lists (revoke_test.go added to the second: it lost a subtest of TestRevokeSubject). The "builds on" bullet for 03-14c names audit verify's and recover's `--installation-id`, Trust's pin with TrustUnpinned, installationLine, the transcript line and the registry paragraph, and says that ca issue reads no config and calls no Trust. 03-14c-SUMMARY.md was already in the context |
| D08 | MINOR | The registry step states the placement: the v2 tag row right after the v1 row (:134); the Issue request v2 binding row as the table's last row, after the Machine issue request row; the exceptions as a new paragraph after the "Since 03-14c" paragraph (:213), before `## Reserved names`. No D5 row is added. Corrected from the item: the Machine issue request row is at :197 and the D5 binding rows at :195-197, not :196 and :194-196 |
| D09 | MINOR | Task 3's step 4 and its verify use 03-14c's form: the house e2e gate in MODE=pr with 03-11b's PROBE_PASS list, cli-windows and cli-macos, the run pinned to `--event pull_request` and HEAD's sha, and PASS lines in both main lanes; the SUMMARY records each main lane's seconds (780.827 s and 803.970 s at e38d6b3). Deviation in name, a planner choice as in 03-14c's D11: the e2e test is the subtest `issue_names_installation` of TestTrustRefuses (cases `without_flag_refused`, `other_installation_refused`, `own_installation_issues`) on that test's existing env at negative_test.go:390, because test/e2e shares no env between tests, so a top-level TestIssueNamesInstallation would need its own bootstrapSigner. It uses its own user key, so its no-certificate checks do not depend on subtest order. Task 2's diff gate refuses a new bootstrapSigner call. Every mention is renamed |
| D10 | MINOR | Estimate raised to 220k raw at low confidence, frontmatter and Budget alike (the calibration has 0 samples, factor 1, so tokens = raw_tokens). The item asked for about 150k; recomputed after this pass, the plan is about 178 KB (about 74k tokens at 2.4 bytes per token) and is read in each of two sessions, so the sum is about 220k. Budget: one continuation after Task 1 and an optional one after Task 2, handed over through the SUMMARY draft, each re-measuring the test-time base. Corrected from the item: 03-14c ran four sessions (three continuations) and two pre-merge fix rounds, not two continuations and one fix round |
| D11 | MINOR | The objective, the SUMMARY item, `<output>` and the REQ coverage row say that REVOKE-01 and AUTH-06 are complete (03-11b, whose SUMMARY lists both in requirements-completed), that AGENT-06 is pending, owned by its PoP plans, and that this plan pins their binding and hardens KEY-02. `requirements-completed` stays empty |
| D12 | MINOR | Task 1's RED worktree runs carry `-timeout 15m`, and the gate refuses `panic: test timed out` in the log with its own message. Task 2's RED run gets the same guard, for consistency |
| D13 | MINOR | The publish gate keeps its checks of this plan's wave and depends_on (now read with `fw()` against the fixed values) and gains the stop guard's clause that 03-14c is the only plan at wave 30 |
| D14 | MINOR | The planner decision and the Q-C2 fact say that since 03-14c a `keyroster init` config pins the installation ID, and that ca issue does not read it (signer-install.md section 8: the admin runs ca issue on the signer host, where no CLI config is assumed). Owner decision OQ-1 = A (Daniel, 2026-11-13) is recorded next to the Q-C2 fact with the owner's reason, and in truths 1 and 3 and a Source Coverage row. `## Open owner questions` stays `None open.` |
| D15 | INFO | The mutant rule says the numbering is local (M1-1 to M1-13, M2-1 to M2-3), that this plan allocates no global M-IDs (03-11 and 03-11b use M1 to M110), and that 03-12 starts at M111, as 03-14b and 03-14c record. No text on main for 03-12 reserves M111 (a search for `M111` under .planning and docs finds only 03-14b and 03-14c), so the plan cites those two plans, not the item's 03-12 design note |
| D16 | INFO | Applied: R1 adds AdminSSHSIGNamespaceV2 to the namespace-overlap lists of TestForgetRequest/namespace_is_its_own (wire_test.go) and TestMachineIssueRequest/constants_and_frame (internal/wire/machineissue_test.go, now in files_modified and Task 1's files). These are the only two such lists at 62b4407, and both pass on R1 and T1 |
| D17 | INFO | TestParseIssueRequestRefusals and TestSignerFraming join Task 1's first verify, with their PASS lines. Both survive T1 unedited: the first asserts only `errors.Is(err, ErrMalformed)`, and internal/signer/server.go answers any ParseIssueRequest error with `malformed_request`, which is what TestSignerFraming/trailing_byte expects. The SUMMARY records the v1 controls as unchanged, also internal/signer/login_test.go and test/e2e/login_refusal_test.go, which use the v1 namespace as a wrong input too; Edge Coverage lists the controls |
| D18 | INFO | No change: tlog.IssueBody (leaf.go:262) holds no request field, so no export line, checkLineKeys rule or audit check changes; refusal leaves keep RequestDigest and Detail (leaf.go:390) |
| D19 | INFO | The Gates paragraph and the SUMMARY list record keyroster-signer's stale capslock pair (91 against a baseline of 92) as pre-existing, unless the baseline-tightening PR lands first |
| D20 | INFO | No change: go.mod pins toolchain go1.27.4 (5328ff9, #100), and the plan names no Go version |

Counts after this pass: files_modified lists 33 files (20 code and test, two of them new; two vectors; the runbook, test/manual/README.md and the registry; eight planning files). The mutants are unchanged (13 in Task 1, 3 in Task 2, plus M1-3 re-run against the table), and so are the RED counts (Task 1: twenty-one FAIL lines and seven controls; Task 2: exactly two diagnostic lines).

## Narrow check ledger (2026-11-13)

Check report: checks/03-14d-reconcile-check.md, verdict PASS (0 BLOCKER, 0 MAJOR, 1 WARNING, 4 INFO). Applied by the orchestrator:

| Item | Change |
|------|--------|
| P1 (R1 warning) | plan-criteria-allow comment for R1 added after Task 2's action: the counted file is the RED run's log, and each t.Errorf prints exactly one line |
| P2 | e2e call-site floor raised to -ge 7 ("fewer than seven"): five existing sites plus the two direct calls |
| P3 | apply's orientation figure updated to about 450 s to 695 s (03-14c's full gates) |
| P4 | Truth 1 now says wave 31, the wave of 03-12 at 62b4407, which the stop guard checks |
| P5 (INFO) | no change: OQ-1 keeps ca.go as it is (no config read); a control test is optional and was not added |
