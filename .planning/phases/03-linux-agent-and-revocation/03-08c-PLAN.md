---
phase: 03-linux-agent-and-revocation
plan: 08c
type: execute
wave: 12
depends_on: ["03-08b"]
files_modified:
  - internal/wire/forget.go
  - internal/wire/frame.go
  - internal/wire/wire_test.go
  - internal/wire/fuzz_test.go
  - internal/tlog/leaf.go
  - internal/tlog/leaf_test.go
  - internal/tlog/fuzz_test.go
  - test/vectors/leaf_host_forget_v1.hex
  - test/vectors/forget_request_signing_v1.hex
  - internal/signer/forget.go
  - internal/signer/forget_test.go
  - internal/signer/server.go
  - internal/signer/refusal.go
  - internal/signer/logstate.go
  - internal/signerclient/client.go
  - internal/audit/forget.go
  - internal/audit/verify.go
  - internal/audit/revoke.go
  - internal/audit/export.go
  - internal/audit/verify_test.go
  - internal/audit/fuzz_test.go
  - internal/server/signer.go
  - internal/server/hosts.go
  - internal/server/server_test.go
  - internal/server/forget_test.go
  - internal/serverclient/agent.go
  - cmd/keyroster/host.go
  - cmd/keyroster/ca.go
  - cmd/keyroster/host_test.go
  - test/e2e/agent_enroll_test.go
  - test/e2e/agent_forget_test.go
  - docs/runbooks/host-setup.md
  - .planning/todos/pending/2026-10-28-audit-host-forget-and-directory-reset.md
autonomous: false
requirements: [AGENT-01, REVOKE-02]

estimate:
  tokens: 135000
  raw_tokens: 135000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decisions 03-08 D-1 (2026-10-28) and Q1 (Daniel, 2026-10-29): 03-08c is the signer half of forget. It is split off on the owner's decision and runs after 03-08b, whose pieces it reuses unchanged: the recorded removal confirmation, the identity addressing, ForgetFacts, DeleteAgentIf and the served rows' removal fields"
    - "Every `keyroster host forget`, `--host-gone` included, is a wire.ForgetRequest that keyroster-signer decides. Its domain and SSHSIG namespace are `keyroster/host-forget-request/v1`. Its signing bytes carry: the installation ID; the agent identity's SPKI SHA-256; its expected name; the SHA-256 fingerprints of its enrolled host keys; approved_once; the removal version; the recorded confirmation {directory version, SHA-256} or host_gone; the request ID; and CreatedAt. The signer verifies the evidence with verifyAdminSignatures under the rule of owner decision Q3, then in the same transaction as that decision appends one leaf of kind 16 (`host_forget`) and records the request ID in the revoke_request table that revoke and 03-06b's recovery share (no signerdb migration)"
    - "Owner decision Q3 (2026-10-29): an agent that never received state (approved_once false) is forgotten with one admin signature, and every other agent needs the policy's admin_quorum of distinct admin signatures. The signer applies the rule to the signed approved_once, and also compares it with the server's own statement of the row, which the relay frame carries outside the signing bytes (ServerApprovedOnce). A difference is refused `forget_facts_mismatch`. One admin signature is refused `admin_quorum_not_met` for an approved-once agent at quorum 2, and accepted for a never-approved one. `keyroster audit verify` re-checks the same rule from the logged request. Audit verify checks that the signature count matches the signed approved_once; it cannot detect a false approved_once, because the signer's log records no approvals. One admin together with a compromised server can forget an approved host with one signature; that server could drop the row without the signer anyway (T-03-285)."
    - "What the signer gate buys, and what it does not: at admin_quorum > 1 no single admin, insider or stolen key, can forget an approved host through keyroster-server; and every forget an honest server performs is in the tamper-evident log with the keys that signed it. A compromised keyroster-server can still delete its own agent rows without asking the signer, as it can withhold any state (T-03-50); against it, forget is detection only: the forgotten host's fetcher logs `unknown_agent` at error level (03-08 D-R1), and the log holds no host_forget entry for that identity. host-setup.md says how to check both"
    - "keyroster-server deletes an agent row only after the signer accepted and logged the forget, through 03-08b's DeleteAgentIf, which re-checks the identity, approval, removal version and confirmation in one transaction (plan check item 1). A signer that cannot be reached or does not answer gives 503, with nothing deleted. A refusal answers with the signer's detail and deletes nothing. A logged forget whose row DeleteAgentIf no longer matches (the facts changed or the identity rotated after the signer's answer) gives 409 `forget_logged_not_deleted`, and the CLI says that audit entry N records an authorization the server did not carry out (fail-safe: the agent keeps being served)"
    - "The signer refuses, writing no host_forget leaf and no revoke_request row (a rate-limited refusal leaf may be appended, as for revoke):
      - a request that does not parse strictly, every forbidden combination of fields included;
      - a request outside ±300 s (`request_time_skew`);
      - a used request ID (`duplicate_request`);
      - a bundle in force with no installation ID (`forget_no_installation_id`), or another installation (`forget_installation_mismatch`);
      - signed approved_once differing from the server's statement (`forget_facts_mismatch`);
      - too few distinct admin signatures under Q3's rule (`admin_quorum_not_met` and the other verifyAdminSignatures details);
      - a host key fingerprint held by any entry, active or disabled, of the directory in force (`forget_host_in_directory`);
      - a confirmation above the installed directory version, or with a SHA-256 that differs from the signer's stored directory document at that version (`forget_confirmation_invalid`)"
    - "`keyroster audit verify` checks every kind 16 entry with the same rules, from the log alone:
      - the request parses (wire.ParseForgetSigningBytes) and names the installation of the bundle in force;
      - its evidence meets Q3's rule under the policy in force, over the exact signing bytes, under the forget namespace;
      - the entry's policy and directory versions are those in force;
      - its resolution time is not after the leaf time and is within 300 s of CreatedAt;
      - its request ID is unused by every revoke, recovery and forget entry;
      - no entry of the directory in force holds a named host key;
      - a confirmation lies between the removal version and the version in force, and has the SHA-256 of the logged directory_install document at that version: a version-to-SHA-256 map over DirectoryInstallBody.Directory, the same document-without-signatures basis as the heartbeat and 03-08b's recording (plan check item 8).
    What a confirmation says about the host is the server's rule (03-08b), recorded as attested by the admins who signed. The export renders kind 16 with identity, expected_name, host_key_fingerprints, approved_once, host_gone, removal_version, confirmed_version and confirmed_sha256 (or neither), policy_version, directory_version, evidence_types and admin_fingerprints (the keys that signed, so the entry names who forgot). It has no `kind`, `bundle_version`, `version`, `directory` or `sigs` key of its own"
    - "The CLI collects the signatures as `keyroster ca issue` does (owner decision Q2): a repeatable `--admin-key`, every key reachable from one ssh-agent. Too few keys for Q3's rule are refused locally (`admin_quorum_not_met`, with the number needed), and nothing is sent. CreatedAt is set just before the first signature. When more than 240 s pass between it and the POST (slow touch confirmations), the CLI refuses locally with `request_time_skew` and asks to sign again (plan check item 9)"
    - "Leaf kind 16 `host_forget` joins format v1: tlog's valid set becomes 1 to 10, 15 and 16, and kinds 11 to 14 stay reserved for 03-09 to 03-12. The signer's start-up rebuild decodes every kind 16 body and refuses to start on one that does not decode; it counts nothing. Golden vectors pin the leaf and the request's signing bytes. FuzzParseForgetRequest, FuzzParseForgetSigningBytes and FuzzParseForgetResponse are new fuzz targets; FuzzDecodeLeaf's explicit kind list and FuzzVerifyExport gain kind 16 seeds"
  artifacts:
    - path: "internal/wire/forget.go"
      provides: "ForgetRequest (keyroster/host-forget-request/v1, with the unsigned ServerApprovedOnce) and ForgetResponse, strict parsers, SigningBytes"
      contains: "keyroster/host-forget-request/v1"
    - path: "internal/signer/forget.go"
      provides: "Signer.ForgetAgent: Q3's evidence rule, the facts and directory checks, and the host_forget leaf in one transaction"
      contains: "func (s *Signer) ForgetAgent"
    - path: "internal/audit/forget.go"
      provides: "verifyForget, the audit rule of leaf kind 16"
      contains: "func verifyForget"
    - path: "test/vectors/leaf_host_forget_v1.hex"
      provides: "Golden leaf of kind 16"
  key_links:
    - from: "cmd/keyroster/host.go"
      to: "internal/server/hosts.go"
      via: "host forget POSTs the admin-signed wire.ForgetRequest to AdminForgetHostPath"
      pattern: "ParseForgetRequest"
    - from: "internal/server/hosts.go"
      to: "internal/signer/forget.go"
      via: "handleForgetHost calls signer.ForgetAgent and then 03-08b's DeleteAgentIf"
      pattern: "ForgetAgent"
    - from: "internal/audit/verify.go"
      to: "internal/audit/forget.go"
      via: "Verify's switch checks every kind 16 entry with verifyForget"
      pattern: "case tlog.KindHostForget"
    - from: "internal/signer/logstate.go"
      to: "internal/tlog/leaf.go"
      via: "rebuildLogFrom decodes every host_forget body at start"
      pattern: "KindHostForget"
  prohibitions:
    - statement: "keyroster-server never deletes an agent row unless keyroster-signer accepted and logged a forget for exactly that identity in the same request; the signer never accepts a forget of an approved-once agent with fewer than the policy's admin_quorum distinct admin signatures"
      status: resolved
      verification: test
---

<objective>
Put `keyroster host forget` under the signer, as the second half of the owner's split (owner decision 03-08 D-1, split by Q1 on 2026-10-29). After this plan:
- a forget, `--host-gone` included, carries admin signatures under the owner's Q3 rule (one for a never-approved agent, the policy's admin_quorum otherwise), which the signer verifies;
- the signer records the forget as a `host_forget` entry (leaf kind 16) in its tamper-evident log, in the same transaction as its decision: who signed, which agent identity and host, approved_once, host_gone yes or no, the removal version, and whether the host confirmed it;
- keyroster-server deletes the row through 03-08b's DeleteAgentIf only after that, and fails closed;
- `keyroster audit verify` re-checks every such entry.

Purpose: AGENT-01 (an agent's retirement is decided and recorded) and REVOKE-02 (a host keeps getting the KRL until a quorum-approved, logged forget ends it). It also extends VIS-01, Phase 1's requirement that every admin action is written to the audit log before it takes effect, to forget. It closes threat T-03-282.

Output: the forget request format, socket messages 0x0D and 0x8D, leaf kind 16 with its audit rule and export, Signer.ForgetAgent, the server relay, the quorum CLI, golden vectors, fuzz targets, the tracer, host-setup.md, the todo's forget half closed, and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **03-08 D-1, 2026-10-28:** forget and `--host-gone` need a signer-checked admin quorum and an audit record in a new leaf kind 16.
- **Q1, 2026-10-29: split, server first.**
  - 03-08b carries the server half: carry-overs (a), (b) and (c), the recorded confirmation and DeleteAgentIf.
  - This plan carries the signer path, depends on 03-08b, and checks its SUMMARY on origin/main.
  - The threat rows moved with what they cover; T-03-282 closes here.
- **Q2, 2026-10-29: co-signing.** Accepted as for `ca issue`: every quorum key reachable from one ssh-agent. Multi-machine flows are Phase 4. T-03-292 stays an accepted residual.
- **Q3, 2026-10-29: never-approved agents.**
  - One admin signature suffices for an agent whose approved_at is unset, which never received state.
  - The signer still appends leaf 16, and checks the signed "never approved" fact against the server's statement.
  - The full admin_quorum applies as soon as the agent was ever approved.
  - Both sides are tested, and audit verify re-checks the rule from the log.
- **Q4, 2026-10-29: the homelab proof.** 03-16's forget drill (remove a host, wait for the confirmation, forget, `keyroster audit verify` shows the kind-16 entry) proves this plan on real hosts; host-setup.md labels the homelab steps UNVERIFIED until 03-16.

No `checkpoint:decision` precedes Task 1.

## Budget Exception

**Accepted by the owner (Daniel, 2026-10-29, Q1)** at about 28 files. This file lists 33: 2 generated golden vectors, 11 test files, the runbook and the todo. The 5 above the owner's estimate are the two e2e files, which extend existing tests, the runbook, the todo, and cmd/keyroster/ca.go, whose adminEvidence is generalized rather than copied. About 135k tokens, against the 15-file and 100k smart-zone thresholds.

Why the signer path is one plan: each part alone fails in a dangerous way.
- A request format and leaf kind without the audit rule write logs that every `audit verify` binary refuses ("not verifiable by this version").
- A signer path without the server relay is never called.
- A relay without the fail-closed delete keeps the single-admin forget.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08b-PLAN.md
@.planning/phases/03-linux-agent-and-revocation/03-08-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-06b-PLAN.md
@.planning/phases/01-trust-core/01-SKELETON.md
@internal/signer/evidence.go
@internal/signer/revoke.go
@internal/signer/recovery.go
@internal/wire/revoke.go
@internal/tlog/leaf.go
@internal/audit/revoke.go
@internal/server/hosts.go
@cmd/keyroster/host.go
@cmd/keyroster/ca.go

Delivery protocol: 01-SKELETON.md, phase 03 names. Branch `p03/08c-forget-signer` from origin/main, SUMMARY `.planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md`, docs commit `docs(03-08c): complete forget-signer plan`. `depends_on` holds 03-08b: the recorded confirmation, ForgetFacts, DeleteAgentIf, forget by identity, `forget_name_ambiguous` and TestAgentReenrollEndToEnd. 03-09 depends on this plan (03-09-PLAN.md, edited with the plan check).
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "keyroster host forget --identity <A> → the CLI signs a wire.ForgetRequest under Q3's rule → the server checks the signed facts against its row and relays them with its own statement → the signer verifies the evidence and the directory facts and appends host_forget (kind 16) in one transaction → the server deletes with DeleteAgentIf → the agent gets unknown_agent → audit verify passes the exported log with one host_forget entry"</name>
  <reversibility rating="costly">Leaf kind 16's body and the keyroster/host-forget-request/v1 signing bytes are read by every later verifier; changing them later needs a new domain tag and keeping the old rule. The socket message types 0x0D and 0x8D are a closed set of the signer.</reversibility>
  <precondition>`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md` exits 0, and `git show origin/main:internal/serverdb/agents.go | grep -cF 'func (d *DB) DeleteAgentIf('` prints at least 1 (03-08b's delete is on main)</precondition>
  <files>internal/wire/forget.go, internal/wire/frame.go, internal/tlog/leaf.go, internal/signer/forget.go, internal/signer/server.go, internal/signer/refusal.go, internal/signer/logstate.go, internal/signerclient/client.go, internal/audit/forget.go, internal/audit/verify.go, internal/audit/revoke.go, internal/audit/export.go, internal/server/signer.go, internal/server/hosts.go, internal/server/server_test.go, internal/serverclient/agent.go, cmd/keyroster/host.go, cmd/keyroster/ca.go, test/e2e/agent_enroll_test.go</files>
  <read_first>
    - .planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md (the final names of ForgetFacts, DeleteAgentIf, the forget request's JSON fields, the served rows' removal fields, any deviation)
    - internal/signer/evidence.go (verifyAdminSignatures), internal/signer/revoke.go (Revoke: freshness, RevokeRequestUsed, the installation checks, logTx with checkTrustCurrent, InsertRevokeRequestTx, the log line), internal/signer/recovery.go (its reuse of revoke_request), internal/signer/server.go (handle's switch), internal/signer/refusal.go (revokeOrRefuse, classify), internal/signer/logstate.go (rebuildLogFrom's kind switch)
    - internal/wire/revoke.go (RevokeRequest: Validate, addFields, Marshal, SigningBytes, the parsers, RevokeResponse), internal/wire/frame.go (the message types; 0x0A to 0x0C are claimed by 03-09 to 03-11)
    - internal/tlog/leaf.go (Kind, valid, String, checkBody, RevokeBody and its Encode and Decode)
    - internal/audit/verify.go (Verify's switch, directoryInForce.install, the default branch, checkGrepFields, checkReplayFields), internal/audit/revoke.go (verifyRevoke, verifyRevokeAdmins, the shared requests map), internal/audit/recovery.go, internal/audit/export.go (decodeLeaf, decodeRevoke)
    - internal/server/hosts.go (03-08b's handleForgetHost), internal/server/signer.go (signerAPI and its growth rule), internal/server/revoke.go (handleRevoke's mapping of signer refusals), internal/server/server_test.go (fakeSigner)
    - cmd/keyroster/host.go (03-08b's runHostForget), cmd/keyroster/ca.go (adminEvidence and the repeatable --admin-key)
    - test/e2e/agent_enroll_test.go step 9, test/e2e/revoke_test.go (how a test exports the log and runs `keyroster audit verify`)
  </read_first>
  <action>
Create branch `p03/08c-forget-signer` from origin/main.

**Wire (internal/wire/forget.go, frame.go).** `ForgetRequestDomain = "keyroster/host-forget-request/v1"` and `ForgetSSHSIGNamespace` equal to it, so an issue, revoke or recovery signature never authorizes a forget, nor the reverse. ForgetRequest carries these fields; the signing bytes are the raw domain followed by every field but Evidence and ServerApprovedOnce, in this order:
- InstallationID (32 lowercase hex, 16-bit length prefix as in revoke);
- AgentIdentity, 32 bytes;
- ExpectedName (the directory.ValidUserName grammar, at most 64 bytes);
- HostKeyFingerprints: a count byte, then 1 to directory.MaxHostKeys SHA-256 digests of the host keys' wire encodings, ascending and unique. Digests and not keys, so the frame stays far inside MaxFrame with four evidence items;
- ApprovedOnce and, later, HostGone as single bytes, 0 or 1 only;
- RemovalVersion, uint64;
- ConfirmedVersion, uint64 (0 means no confirmation), then ConfirmedSHA256, 32 bytes, all zero exactly when ConfirmedVersion is 0;
- HostGone;
- RequestID, 16 bytes;
- CreatedAt, uint64.

Validate enforces the combinations:
- ApprovedOnce false requires RemovalVersion 0, no confirmation and HostGone false.
- ApprovedOnce true requires exactly one of:
  - a confirmation with 1 <= RemovalVersion <= ConfirmedVersion and HostGone false;
  - HostGone true with no confirmation.

Marshal appends the evidence list as revoke does (at most MaxEvidence, which covers trust.MaxAdminQuorum), then one byte ServerApprovedOnce, which the server sets and nobody signs. ParseForgetRequest and ParseForgetSigningBytes are strict:
- trailing bytes refused;
- an unknown byte value refused;
- the signing bytes must re-encode identically.

ForgetResponse{Leaf uint64} with its strict parser. frame.go: `TypeForgetAgentRequest 0x0D`, `TypeForgetAgentResponse 0x8D`, both capped at MaxFrame.

**tlog (internal/tlog/leaf.go).** `KindHostForget Kind = 16`, String `host_forget`, and valid() becomes the set 1 to 10, 15 and 16. Rewrite the Kind doc comment so it says that 16 joined in Phase 3 (03-08c), next after 15, and that 11 to 14 stay reserved for 03-09 to 03-12. Add `HostForgetBody{PolicyVersion, DirectoryVersion, ResolvedAtSeconds uint64; Request []byte; Evidence []wire.Evidence}` in RevokeBody's style, with Encode, DecodeHostForgetBody and a checkBody case.

**Signer (internal/signer/forget.go, server.go, refusal.go, logstate.go).** `func (s *Signer) ForgetAgent(ctx, peer, req) (*wire.ForgetResponse, error)` under s.mu, with one clock reading `now`, in Revoke's order. Each check refuses with the detail named in must_haves:
1. the request is valid;
2. freshness ±300 s;
3. RevokeRequestUsed(req.RequestID) is false;
4. the installation ID is in force and equal;
5. req.ApprovedOnce equals req.ServerApprovedOnce;
6. `verifyAdminSignatures(req.Evidence, req.SigningBytes(), wire.ForgetSSHSIGNamespace, need, s.policy)`, where `need` is 1 when ApprovedOnce is false and `int(s.policy.AdminQuorum)` otherwise (owner decision Q3);
7. no entry of the installed directory, active or disabled, holds a host key whose SHA-256 fingerprint is in the request;
8. with a confirmation: ConfirmedVersion is at most the installed directory version, and its SHA-256 equals trust.SHA256Hex of the signer's stored directory document at that version (the lookup GetDirectoryVersion uses).

Then one logTx:
- checkTrustCurrent;
- append the `tlog.KindHostForget` leaf: the policy and directory versions in force, ResolvedAtSeconds = now in whole seconds, the signing bytes and the evidence;
- InsertRevokeRequestTx(req.RequestID, leaf).

After COMMIT, log `agent forget logged` at warning level when host_gone is set (info otherwise), naming:
- the identity and expected name;
- approved_once, host_gone, the removal and confirmed versions;
- the admins;
- the leaf index and the peer.

server.go: `case wire.TypeForgetAgentRequest`, through a new `forgetOrRefuse` in refusal.go that records refusals like revokeOrRefuse; classify the new details. logstate.go's rebuildLogFrom: `case tlog.KindHostForget` decodes the body (errLogMismatch when it does not) and counts nothing. signerclient: `ForgetAgent(ctx, socket, req)`.

**Audit (internal/audit/forget.go, verify.go, revoke.go, export.go).**
- verifyForget implements the must_haves rule.
- directoryInForce keeps a map from each logged directory version to trust.SHA256Hex of DirectoryInstallBody.Directory, filled in install.
- verifyRevokeAdmins gains a quorum argument: 1 for revoke and recovery, Q3's rule for forget.
- The request ID joins the revocations walk's shared requests map.
- Verify's switch gains `case tlog.KindHostForget`; the default branch's comment stays true.
- export.go renders kind 16 with the keys must_haves lists. admin_fingerprints is the SHA-256 fingerprint of each evidence signature's key, sorted. checkGrepFields and checkReplayFields cover the new keys as they cover revoke's.

**Server (internal/server/signer.go, hosts.go, serverclient/agent.go).** signerAPI, socketSigner and fakeSigner gain ForgetAgent, in the commit that adds its caller (the growth rule). handleForgetHost now takes `{"request": <wire.ForgetRequest bytes>}`, decoded strictly, in place of 03-08b's JSON facts. In order:
1. wire.ParseForgetRequest (400 on failure);
2. the identity and ForgetFacts from the request;
3. 03-08b's checks: AgentBySPKI (404), the facts and the row's expected name and host key fingerprints equal to the row (409 `forget_state_changed`, the signer not asked), hostHolds (409);
4. set ServerApprovedOnce from the row's approved_at;
5. signer.ForgetAgent within signerCallTimeout, mapping its refusals as handleRevoke does: malformed to 400, refused to 403 with the detail, anything else to 503 with nothing deleted;
6. DeleteAgentIf with the request's facts (409 `forget_logged_not_deleted` on ErrNotFound, logged at error level with the leaf index).

The answer is ForgetHostAnswer with the row and `leaf`. Rewrite handleForgetHost's doc comment to say all this.

**CLI (cmd/keyroster/host.go, ca.go).**
- Generalize ca.go's adminEvidence to sign given signing bytes under a given namespace, so forget reuses its agent-key lookup.
- runHostForget keeps 03-08b's target resolution and local refusals, and makes `--admin-key` repeatable: the first, or the config's admin_key, also signs the HTTP request.

In order:
1. Pin the trust (installation ID, policy).
2. Build the request from the chosen row.
3. Refuse locally when the keys given are fewer than Q3's rule needs (`admin_quorum_not_met`, with the number).
4. Print what is signed: identity, name, host key fingerprints, approved_once, the removal version, the confirmation or host_gone, the signing keys.
5. Set CreatedAt and sign with each key.
6. Refuse locally `request_time_skew` when more than 240 s passed since CreatedAt.
7. POST, check the answer's identity, and print `logged as audit entry N`.
8. For `forget_logged_not_deleted`, print that entry N records an authorization the server did not carry out and that `keyroster host pending` still lists the agent.

**e2e (test/e2e/agent_enroll_test.go, step 9).** After 03-08b's forget, which now goes through the signer and prints `logged as audit entry N`:
- the exported log passes `keyroster audit verify` with exactly one host_forget entry;
- its export line names web1's identity, `"approved_once":true`, `"host_gone":false`, the removal version and the confirmed directory version and SHA-256, recorded from the real agent's heartbeat.

The CI E2E lanes, dispatched on the pushed branch, are the evidence (WSL cannot resolve `keyroster.localhost`, deferred-items.md).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/wire/... ./internal/tlog/... ./internal/signer/... ./internal/signerclient/... ./internal/audit/... ./internal/server/... ./internal/serverclient/... ./cmd/keyroster/... && go vet -tags e2e ./test/e2e/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output</fails_when>
    <automated>git push -u origin p03/08c-forget-signer && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/08c-forget-signer && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08c-forget-signer --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit (the E2E run on the pushed head failed or never appeared), or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestAgentEnrollEndToEnd" or "logged as audit entry", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'keyroster/host-forget-request/v1' internal/wire/forget.go` prints at least 1, and `grep -n 'KindHostForget' internal/signer/logstate.go internal/audit/verify.go` prints a case line in each.
    - `grep -v '^[[:space:]]*//' internal/signer/forget.go | grep -c 's.policy.AdminQuorum'` prints at least 1.
    - `grep -c 'leaves a server log line only' internal/server/hosts.go` prints 0.
    - TestAgentEnrollEndToEnd's log on both CI lanes shows the forget's audit entry and an audit verify that passes with one host_forget entry, whose confirmation came from a real agent's heartbeat; the SUMMARY names the run ID.
  </acceptance_criteria>
  <done>A forget reaches the server only signed under the owner's rule, the signer decides and logs it as kind 16, the server deletes only after that, and audit verify proves it on a real enrolled host in CI.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The forget decision's edges in wire, tlog, signer and audit, owner decision Q3 on both sides, the golden vectors and the fuzz targets</name>
  <files>internal/wire/forget.go, internal/wire/wire_test.go, internal/wire/fuzz_test.go, internal/tlog/leaf.go, internal/tlog/leaf_test.go, internal/tlog/fuzz_test.go, test/vectors/leaf_host_forget_v1.hex, test/vectors/forget_request_signing_v1.hex, internal/signer/forget.go, internal/signer/forget_test.go, internal/audit/forget.go, internal/audit/verify_test.go, internal/audit/fuzz_test.go</files>
  <behavior>
    - Wire (`TestForgetRequest`, `TestForgetResponse`):
      - Round trip, ServerApprovedOnce included.
      - ServerApprovedOnce is not in SigningBytes: changing it leaves them equal.
      - Refused:
        - a trailing byte;
        - unsorted, duplicated, zero or nine fingerprints;
        - a bool byte of 2;
        - approved_once false with a removal version;
        - approved_once true with neither a confirmation nor host_gone;
        - host_gone with a confirmation;
        - a confirmed version below the removal version;
        - a zero SHA-256 with a version, or a non-zero one without;
        - an installation ID not of the bundle form;
        - a name outside the grammar;
        - five evidence items.
      - ParseForgetSigningBytes re-encodes identically.
      - The namespace differs from the issue, revoke (v1 and v2), recovery and login namespaces.
      - The golden vector `forget_request_signing_v1.hex` is written from fixed literals with `-update` and read back byte for byte.
    - tlog (`TestHostForgetBody` and the kind-set test):
      - Round trip and limits.
      - Kind 16 decodes as `host_forget`; kinds 11 to 14 and 17 are still refused.
      - The golden leaf `leaf_host_forget_v1.hex`.
    - Signer (`TestForgetAgent`, a real signer on a test database, policy admin_quorum 2). Each refusal case calls ForgetAgent directly and asserts that no kind 16 leaf and no revoke_request row exist afterwards (plan check item 5: a refusal leaf may be appended).
      - Q3 accepted: `quorum_met_logs_one_leaf` (two admins, an approved-once agent), `never_approved_one_admin_accepted`.
      - Q3 refused: `approved_once_one_admin_refused` (`admin_quorum_not_met`), `same_admin_twice_counts_once`, `server_statement_mismatch_refused` (signed approved_once false, server statement true: `forget_facts_mismatch`).
      - Evidence: `non_admin_refused`, and `revoke_namespace_refused` (a signature over the same bytes under keyroster/revoke-request/v2 gives `evidence_wrong_namespace`).
      - Request: `installation_mismatch_refused`, `stale_request_refused` (CreatedAt 301 s off), `duplicate_request_refused` (the same request twice, and a request ID a revoke used).
      - Directory: `host_in_directory_refused` (a disabled entry holds one key), `confirmation_above_current_refused`, `confirmation_sha_mismatch_refused`.
      - `host_gone_logged`.
      - `restart_after_forget`: the signer starts again on the database, and refuses to start with errLogMismatch on a database whose kind 16 body was altered.
      - `policy_quorum_1_one_admin`.
    - Audit (`TestVerifyHostForget`, on the audit test fixtures with a directory install):
      - `valid_passes`, `never_approved_one_signature_passes`.
      - Each of these fails, naming the entry: `approved_once_one_signature_fails` (quorum-2 policy), `wrong_installation_fails`, `policy_version_mismatch_fails`, `directory_version_mismatch_fails`, `host_key_in_directory_fails`, `confirmed_above_directory_fails`, `confirmed_sha_not_logged_fails`, `request_id_reused_fails` (a revoke entry used it), `resolved_after_leaf_fails`, `created_skew_fails`.
      - `confirmed_sha_matches_the_heartbeat_basis` (plan check item 8): the confirmation is the {version, sha256} a heartbeat.Status carries for that directory, trust.SHA256Hex of the document bytes the agent stores (apply/status.go: st.Directory, served without signatures). Audit's map value for that version, computed over DirectoryInstallBody.Directory, equals it, and the entry verifies.
      - `TestExportHostForget`: the export line carries the must_haves keys, admin_fingerprints sorted, and none of `kind`, `bundle_version`, `version`, `directory` or `sigs` of its own. checkGrepFields refuses an export line whose rendered `host_gone` or `approved_once` was edited.
    - Fuzz: `FuzzParseForgetRequest`, `FuzzParseForgetSigningBytes` and `FuzzParseForgetResponse` never panic, and whatever parses re-encodes to the same bytes. FuzzDecodeLeaf's explicit kind list and body seeds gain KindHostForget and a HostForgetBody. FuzzVerifyExport gains a seed log with a forget entry that verifies under the fixture's pins.
  </behavior>
  <read_first>
    - The files written in Task 1
    - internal/wire/wire_test.go (the revoke and recovery request cases and their golden-vector tests), internal/wire/fuzz_test.go (FuzzParseRecoveryRequest)
    - internal/tlog/leaf_test.go (recoveryVector and the leaf golden tests), internal/tlog/fuzz_test.go (FuzzDecodeLeaf: an explicit kind list, not a bound)
    - internal/signer/revoke_test.go and recovery_test.go (fixtures for a signer with a directory and policy admins), internal/audit/verify_test.go (the revoke and recovery rule tests), internal/audit/fuzz_test.go
    - internal/agent/heartbeat (the portable Status and Doc types) and internal/agent/apply/status.go (how Directory's SHA-256 is computed; audit's tests do not import the Linux-only apply package)
  </read_first>
  <action>Write the tests in `<behavior>` first and run them RED against Task 1's code where Task 1 left a gap. Record in the SUMMARY each case that was RED and why, and each that was GREEN at once. Then fix what they find in forget.go (wire, signer, audit) and leaf.go. Create both vectors with `-update` from fixed literals, never from a clock or random source. Run every new fuzz target, FuzzDecodeLeaf and FuzzVerifyExport for at least 20 s each (03-06b's pattern).</action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -count=1 -v -run "TestForgetRequest|TestForgetResponse|TestHostForgetBody|TestForgetAgent|TestVerifyHostForget|TestExportHostForget" ./internal/wire/ ./internal/tlog/ ./internal/signer/ ./internal/audit/'</automated>
    <fails_when>non-zero exit, "FAIL" in the output, or any of "--- PASS: TestForgetAgent/approved_once_one_admin_refused", "--- PASS: TestForgetAgent/never_approved_one_admin_accepted", "--- PASS: TestForgetAgent/server_statement_mismatch_refused", "--- PASS: TestForgetAgent/revoke_namespace_refused", "--- PASS: TestForgetAgent/duplicate_request_refused", "--- PASS: TestForgetAgent/restart_after_forget", "--- PASS: TestVerifyHostForget/approved_once_one_signature_fails", "--- PASS: TestVerifyHostForget/never_approved_one_signature_passes", "--- PASS: TestVerifyHostForget/confirmed_sha_matches_the_heartbeat_basis", "--- PASS: TestVerifyHostForget/request_id_reused_fails" or "--- PASS: TestExportHostForget" missing</fails_when>
    <automated>bash scripts/linux.sh 'go test -run NONE -fuzz FuzzParseForgetRequest -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzParseForgetSigningBytes -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzParseForgetResponse -fuzztime 20s -fuzzminimizetime 5s ./internal/wire/ && go test -run NONE -fuzz FuzzDecodeLeaf -fuzztime 20s -fuzzminimizetime 5s ./internal/tlog/ && go test -run NONE -fuzz FuzzVerifyExport -fuzztime 20s -fuzzminimizetime 5s ./internal/audit/'</automated>
    <fails_when>non-zero exit, or a fuzz failure line ("--- FAIL", "Failing input written")</fails_when>
  </verify>
  <acceptance_criteria>
    - `test -s test/vectors/leaf_host_forget_v1.hex && test -s test/vectors/forget_request_signing_v1.hex` exits 0, and a second `-update` run leaves both byte for byte unchanged (`git diff --exit-code test/vectors/`).
    - `grep -c 'KindHostForget' internal/tlog/fuzz_test.go` and `grep -c 'Forget' internal/audit/fuzz_test.go` each print at least 1.
    - Mutants, each applied, run against its named test and restored byte for byte, recorded in the SUMMARY:
      - the signer's `need` fixed at 1 (killed by `approved_once_one_admin_refused`);
      - the signer's `need` fixed at the quorum (killed by `never_approved_one_admin_accepted`);
      - the audit's rule fixed at 1 (killed by `approved_once_one_signature_fails`);
      - the server-statement comparison removed (killed by `server_statement_mismatch_refused`);
      - the confirmation SHA-256 check removed in the signer (`confirmation_sha_mismatch_refused`) and in audit (`confirmed_sha_not_logged_fails`);
      - the shared request-ID lookup skipped (`duplicate_request_refused`, `request_id_reused_fails`);
      - kind 16's case removed from rebuildLogFrom (`restart_after_forget`).
  </acceptance_criteria>
  <done>Every refusal of the signer's forget, both sides of the owner's Q3 rule, and every rule of the audit check are named tests; both formats are pinned by golden vectors; every new parser is fuzzed.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: The relay's fail-closed cases, the quorum CLI, and the re-enroll e2e's audit entry</name>
  <files>internal/server/hosts.go, internal/server/forget_test.go, cmd/keyroster/host.go, cmd/keyroster/host_test.go, test/e2e/agent_forget_test.go</files>
  <behavior>
    - Server (`TestForgetHost`, extending 03-08b's):
      - `signer_unavailable_deletes_nothing` (503) and `signer_refused_deletes_nothing` (403 with the detail).
      - `facts_changed_after_accept` (plan check item 1), through a nil-by-default hook between the signer's answer and DeleteAgentIf that records a confirmation on the row: 409 `forget_logged_not_deleted`, the row still present.
      - `identity_rotated_after_accept`: the same hook rotates the identity, with the same outcome.
      - `server_statement_from_the_row`: the relay sends ServerApprovedOnce from approved_at, whatever the request says. A request claiming never approved for an approved row is refused `forget_state_changed` before the signer is asked.
      - `accepted_deletes_and_names_the_leaf`.
    - CLI (`TestHostForget`, fake server):
      - `quorum_two_keys_two_evidence`: two `--admin-key`; the POSTed request carries two admin-sshsig/v1 items over the forget namespace.
      - `never_approved_one_key_enough`.
      - `approved_once_fewer_keys_refused_locally`: nothing POSTed.
      - `slow_signing_refused_locally` (plan check item 9): an injected clock passes 241 s between CreatedAt and the POST; `request_time_skew`, nothing POSTed.
      - `logged_not_deleted_printed`, `answer_names_another_identity_refused`.
    - e2e (`TestAgentReenrollEndToEnd`, extending 03-08b's): the forget of A by identity prints `logged as audit entry N`. The exported log passes `keyroster audit verify`, and its host_forget entry names A's identity, `"approved_once":true`, `"host_gone":false` and A's recorded confirmation. Every wait keeps 03-08b's deadline (twice the poll interval plus 30 s, failing with the last answer).
  </behavior>
  <read_first>
    - The files written in Tasks 1 and 2; .planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md (the forget hook it added, TestForgetHost's cases)
    - internal/server/forget_test.go and cmd/keyroster/host_test.go as 03-08b left them; test/e2e/agent_forget_test.go
  </read_first>
  <action>Write the tests in `<behavior>` first. Run `facts_changed_after_accept` and `slow_signing_refused_locally` RED on Task 2's head where Task 1 left the gap, and record the outcome in the SUMMARY. Then fix what they find. Add the hook between the signer's answer and DeleteAgentIf, nil by default like 03-08b's. The CLI's clock is an injectable function, nil meaning time.Now. The e2e evidence comes from the CI E2E lanes, as in Task 1.</action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestForgetHost|TestHostForget" ./internal/server/ ./cmd/keyroster/ && go vet -tags e2e ./test/e2e/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of "--- PASS: TestForgetHost/facts_changed_after_accept", "--- PASS: TestForgetHost/identity_rotated_after_accept", "--- PASS: TestForgetHost/signer_unavailable_deletes_nothing", "--- PASS: TestForgetHost/server_statement_from_the_row", "--- PASS: TestHostForget/quorum_two_keys_two_evidence" or "--- PASS: TestHostForget/slow_signing_refused_locally" missing</fails_when>
    <automated>git push origin p03/08c-forget-signer && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/08c-forget-signer && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08c-forget-signer --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit, or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestAgentReenrollEndToEnd" or "--- PASS: TestAgentEnrollEndToEnd", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - Mutants recorded in the SUMMARY:
      - DeleteAgentIf replaced by a delete by (id, identity) only (killed by `facts_changed_after_accept`);
      - the delete moved before the signer call (killed by `signer_unavailable_deletes_nothing`);
      - ServerApprovedOnce taken from the request (killed by `server_statement_from_the_row`).
    - The CI E2E run on the pushed head is the evidence for TestAgentReenrollEndToEnd's audit entry; the SUMMARY names its run ID.
  </acceptance_criteria>
  <done>No path deletes before the signer's answer or after the facts changed, the CLI collects the right number of signatures in time, and the re-enroll flow's forget is in the audit log.</done>
</task>

<task type="auto">
  <name>Task 4: host-setup.md, the todo's forget half, the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/host-setup.md, .planning/todos/pending/2026-10-28-audit-host-forget-and-directory-reset.md</files>
  <read_first>
    - docs/runbooks/host-setup.md "Removing a host" and the refusal table, as 03-08b left them
    - .planning/todos/pending/2026-10-28-audit-host-forget-and-directory-reset.md (Status)
    - .planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md deviation 8 (the SUMMARY is pushed before the PR opens)
  </read_first>
  <action>
**host-setup.md (D-20).** Every changed operator step is labelled as run (where and when) or UNVERIFIED.

**"Removing a host", step 3:**
- forget is signed by the admins: one `--admin-key` for an agent that was never approved, and the policy's admin_quorum, each key with its own `--admin-key` from one ssh-agent, for any other (owner decisions Q2 and Q3);
- the CLI prints what is signed, and refuses when signing took more than 240 s;
- the signer refuses too few signatures;
- the server deletes only after the signer logged the forget, and answers 503 with nothing forgotten while the signer is down;
- the CLI prints the audit entry's number;
- `forget_logged_not_deleted` means the entry exists and the agent is still served: run forget again, which logs a second entry.

This replaces the interim sentence 03-08b ended the section with (it names this plan; 03-08b-PLAN.md Task 3 pins its wording). Labels: run in CI (TestForgetAgent, TestVerifyHostForget, TestForgetHost, TestHostForget, TestAgentEnrollEndToEnd, TestAgentReenrollEndToEnd, 03-08c); on the homelab UNVERIFIED until 03-16, whose forget drill proves it (owner decision Q4).

**A new paragraph in that section, "Checking that a forget was authorized":**
- export the log and run `keyroster audit verify`; every forget is a `host_forget` entry with its identity, approved_once, host_gone and the signing keys' fingerprints;
- a host whose fetcher logs `unknown_agent` while the log has no host_forget entry for its identity was dropped by keyroster-server without a forget: treat the server as compromised;
- this check is detection only, because the server can always stop serving a host.

Labelled run in CI for the entry and the fetcher line (TestAgentEnrollEndToEnd), and UNVERIFIED as an operator check until 03-16.

**The refusal table gains** `admin_quorum_not_met` (forget), `forget_facts_mismatch`, `forget_host_in_directory`, `forget_confirmation_invalid`, `forget_logged_not_deleted` and `request_time_skew` (forget), each with its fix.

**The todo.** It stays in pending/: the reset half is open. Its forget line becomes "resolved in 03-08b and 03-08c (PR from branch p03/08c-forget-signer; the SUMMARY is pushed before the PR opens)". The reset half's line stays as it is.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**The PR.** `scripts/gh-as-bot.sh pr create --title "feat(agent): forget hosts only under signer-checked admin signatures, logged as host_forget"`, without enabling auto-merge (the orchestrator enables it after the pre-merge review). Wait for the required checks.

**The SUMMARY.** Contents:
- the PR number and the CI run IDs;
- the RED evidence and the mutants of Tasks 2 and 3;
- capslock;
- `requirements-completed` empty: AGENT-01 and REVOKE-02 are complete since 03-07, this plan hardens them, and 03-16 proves it on the homelab.

Then the tracking updates once, `docs(03-08c): complete forget-signer plan`, push, and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'host_forget' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'forget_logged_not_deleted' && grep -q 'resolved in 03-08b and 03-08c' .planning/todos/pending/2026-10-28-audit-host-forget-and-directory-reset.md && test ! -e .planning/todos/completed/2026-10-28-audit-host-forget-and-directory-reset.md</automated>
    <fails_when>non-zero exit (the runbook lacks the audit entry or the new refusal, the todo's line is missing, or the todo was moved although its reset half is open)</fails_when>
    <automated>git fetch origin p03/08c-forget-signer && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)"</automated>
    <fails_when>non-zero exit (the SUMMARY is not on the pushed branch, or local commits are unpushed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08c-forget-signer --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - `tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'forget needs no admin quorum and leaves no audit entry'` prints 0 (03-08b's interim sentence is gone).
    - Every new or rewritten section names at least one CI test and `UNVERIFIED until 03-16`.
    - The PR is open without auto-merge (the orchestrator enables it after the pre-merge review), every required check green, 03-08c-SUMMARY.md on its head.
  </acceptance_criteria>
  <done>The runbook tells operators how forget works under the signers' rule and how to check that a forget was authorized; the todo's forget half is closed; the PR waits green.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — owner approves PR p03/08c-forget-signer, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/08c-forget-signer --web`; review the signer's ForgetAgent (Q3's rule, the server-statement check), the audit rule, the relay's order and 03-08c-SUMMARY.md, especially that no path deletes an agent row before the signer's answer.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08c-forget-signer` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08c-forget-signer</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-09's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08c-forget-signer --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>Forget under the signer is on main, and 03-09 may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes (03-09 to 03-16)

Checked against every later plan of the phase on 2026-10-29. No later plan uses forget or a leaf kind above 15. The numbers this plan takes, and what later plans must not change:

- **Leaf kinds and the valid set (plan check item 6).** 11 to 14 stay reserved, each touching internal/tlog/leaf.go and internal/audit/verify.go: 03-09 (KindHostIssue), 03-10 (KindProbeIssue), 03-11 (KindMachineIssue) and 03-12 (KindCAGeneration). 15 is 03-06b's and 16 (`host_forget`) is this plan's. Each later plan appends its kind to tlog's explicit valid set and to FuzzDecodeLeaf's explicit kind list, and never drops 15 or 16. 03-09 and 03-11's wording "raise FuzzDecodeLeaf's seed bound" means that append.
- **Socket message types.** 0x0A, 0x0B and 0x0C are 03-09, 03-10 and 03-11's. This plan takes 0x0D and 0x8D.
- **Migrations.** This plan adds none. serverdb 0007 is 03-08b's, and signerdb 0006 is 03-12's.
- **revoke_request.** The table holds the request IDs of revokes, recoveries and forgets, and audit's walk keeps one request-ID set for all three. A later plan that reads either as revoke-only must not.
- **Ordering (plan check item 2).** 03-09 `depends_on: ["03-08c"]`, and its Task 1 precondition checks 03-08c-SUMMARY.md on origin/main. The `wave:` of 03-09 to 03-16 is 13 to 20, matching ROADMAP.md.
- **03-09 `revoke host`.** A forgotten host's host certificate stays valid until it expires (30 days, D-16). Forget does not revoke it, so 03-09's runbook should put `keyroster revoke host` before forget in "Removing a host".
- **03-16 (owner decision Q4)** owns the homelab proof: its forget drill ends with `keyroster audit verify` showing this plan's kind-16 entry.

## Edge Coverage (spec-less fallback, this plan)

This plan authors the forget decision's edges as truths.

**Flagged assumption, the server is untrusted and owns its rows.** The gate binds every forget an honest server performs to the signatures and a log entry. It cannot stop a compromised server from dropping a row, which is detected by the host's `unknown_agent` line and the missing entry (T-03-285).

**Flagged assumption, approved_once is the server's fact.** The admins sign what `host pending` showed, the honest server re-checks it against its row before the relay and in DeleteAgentIf, and the signer compares it with the server's statement (Q3). A compromised server can state anything, but it does not need the signer to drop a row (T-03-293, T-03-285). Audit verify checks that the signature count matches the signed approved_once; it cannot detect a false approved_once, because the signer's log records no approvals. One admin together with a compromised server can forget an approved host with one signature; that server could drop the row without the signer anyway (T-03-285).

**Flagged assumption, quorum keys in one agent (Q2).** A co-signing flow for admins on separate machines is Phase 4 (T-03-292).

**Edges:**
- adjacency (`stale_request_refused`, 301 s; `slow_signing_refused_locally`, 241 s);
- ordering (`facts_changed_after_accept`, `identity_rotated_after_accept`);
- reuse (`duplicate_request_refused`, `request_id_reused_fails`);
- both sides of Q3 (`never_approved_one_admin_accepted`, `approved_once_one_admin_refused`).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Revocations keep reaching a host until its retirement is decided, signed and recorded | Tasks 1, 3 |
| REQ | AGENT-01 (an agent's retirement is decided and recorded) | Tasks 1, 3 |
| REQ | REVOKE-02 (the KRL reaches every enrolled host until a logged forget ends it) | Tasks 1, 3 |
| REQ (cross-phase) | VIS-01 (admin actions logged before they take effect), extended to forget | Tasks 1, 2 |
| CONTEXT | D-10 (a forgotten host keeps its last state and logs `unknown_agent`) | Task 1 e2e, Task 4 runbook |
| CONTEXT | D-20 (runbook in the same PR, run or UNVERIFIED) | Task 4 |
| Owner decision | 03-08 D-1; Q1 (split), Q2 (one ssh-agent), Q3 (never-approved rule), Q4 (03-16 drill) | Owner decisions block; Tasks 1-4; T-03-292; Cross-plan notes |
| Plan check | Items 1, 5, 6, 8, 9 (and item 2 in 03-09-PLAN.md and ROADMAP.md) | Tasks 1-3; Cross-plan notes |
| Todo | 2026-10-28-audit-host-forget-and-directory-reset.md, the forget half | Tasks 1-4; the reset half stays open (out of scope by the owner's instruction) |

## Artifacts this phase produces (this plan)

- wire: `ForgetRequestDomain` and `ForgetSSHSIGNamespace` (`keyroster/host-forget-request/v1`), `ForgetRequest` (with the unsigned `ServerApprovedOnce`), `ForgetResponse`, `ParseForgetRequest`, `ParseForgetSigningBytes`, `TypeForgetAgentRequest` 0x0D, `TypeForgetAgentResponse` 0x8D.
- tlog: `KindHostForget` 16 (`host_forget`), `HostForgetBody`, `DecodeHostForgetBody`.
- signer: `ForgetAgent`, `forgetOrRefuse`; refusals `forget_no_installation_id`, `forget_installation_mismatch`, `forget_facts_mismatch`, `forget_host_in_directory`, `forget_confirmation_invalid`. signerclient: `ForgetAgent`.
- audit: `verifyForget`, the directory version-to-SHA-256 map, the export of kind 16 with `admin_fingerprints`.
- server: the forget relay with `forget_logged_not_deleted`. CLI: repeatable `--admin-key` for forget, the 240 s local bound.
- Tests: TestForgetRequest, TestForgetResponse, TestHostForgetBody, TestForgetAgent, TestVerifyHostForget, TestExportHostForget, the extended TestForgetHost, TestHostForget and TestAgentReenrollEndToEnd, fuzz targets and vectors.
- Docs: host-setup.md "Removing a host" under the signers' rule, "Checking that a forget was authorized", the refusal table.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| admin CLI → keyroster-server | The server relays the admins' signed forget request and deletes; it is not trusted to decide |
| keyroster-server → keyroster-signer | The signer checks the signatures under Q3's rule and the directory facts, and logs before the server acts |
| host → server (heartbeat) | The confirmation rests on the host's own report (T-03-284; recorded by 03-08b) |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-282 | Repudiation / Elevation of privilege | `keyroster host forget` (and `--host-gone`) decided by one admin and recorded only in keyroster-server's log | medium | mitigate | Accepted in 03-08 and 03-08b (owner decisions D-1, Q1); **closed here**. The forget is a wire.ForgetRequest signed under Q3's rule and checked by the signer (`approved_once_one_admin_refused`, mutants). A `host_forget` entry is appended in the decision's transaction and re-checked by audit verify (`approved_once_one_signature_fails`). The server deletes only after it (the prohibition; `signer_unavailable_deletes_nothing`, `signer_refused_deletes_nothing`). At quorum > 1 no single admin can forget an approved host through the server. **Residual:** T-03-285, T-03-293 |
| T-03-285 | Tampering / Denial of service | a compromised keyroster-server deleting an agent row without a forget, which stops that host's revocations | medium | accept (detection) | The server owns its database, and a server can always stop serving (T-03-50). Detection: the host's fetcher logs `unknown_agent` at error level (03-08 D-R1), and the log holds no host_forget entry for that identity; host-setup.md "Checking that a forget was authorized". **Residual:** detection only, and only by whoever reads the host's journal |
| T-03-286 | Spoofing / Tampering | a replayed, stale or foreign-installation forget request | medium | mitigate | The installation ID is in the signing bytes; ±300 s freshness, with the CLI's own 240 s bound before it sends; the request ID is checked in the request-ID table that revoke and recovery share, and in audit's shared set. Tests: `installation_mismatch_refused`, `stale_request_refused`, `slow_signing_refused_locally`, `duplicate_request_refused`, `request_id_reused_fails`. **Residual (accepted, owner decision D-3, Daniel, 2026-10-30, PR #75 pre-merge review):** the request binds the enrollment by `enrolled_at_us`, stored in whole seconds, so a forget read before a re-enrollment of the same identity in the same second as the original enrollment cannot be told apart from one for the new row (host pending's read, the whole forget and the re-enrollment inside that second); host-setup.md "Removing a host" step 3 states it. Not tested, by construction |
| T-03-290 | Repudiation | a forget the signer logged that the server did not carry out: the facts changed or the identity rotated between the answer and the delete, a crash, or a signer answer lost after its COMMIT (503) | low | accept | Fail-safe: the agent keeps being served. The server answers `forget_logged_not_deleted` (or 503 for a lost answer) and the CLI says so; a re-run is a new request and logs a second entry. A deletion is never made without an entry (`facts_changed_after_accept`, `identity_rotated_after_accept`, `signer_unavailable_deletes_nothing`) |
| T-03-291 | Repudiation | a signer restore that loses host_forget entries made after its snapshot | low | accept | As every later entry, they are lost from the restored log, and the saved export keeps them (signer-install.md's restore compares the two). The server's deletions stand, so no host is served again by the restore. No restore step changes in this plan |
| T-03-292 | Elevation of privilege | admin keys forwarded to one machine so that the quorum can sign from one ssh-agent | low | accept | Owner decision Q2 (2026-10-29): the `keyroster ca issue` mechanism, which keeps the ±300 s freshness window. Admins may instead sign at one workstation with hardware keys present. Multi-machine co-signing is Phase 4 |
| T-03-293 | Elevation of privilege | one admin forgetting an approved host by signing "never approved" (owner decision Q3's single-signature case) | medium | mitigate | The honest server requires the signed approved_once to equal its row before the relay and re-checks `approved_at_us IS NULL` in DeleteAgentIf (03-08b). The signer compares the signed fact with the server's statement (`forget_facts_mismatch`). Audit verify applies the same rule from the log. Tests: `server_statement_mismatch_refused`, `server_statement_from_the_row`, `never_approved_one_signature_passes`, `approved_once_one_signature_fails`. **Residual:** Audit verify checks that the signature count matches the signed approved_once; it cannot detect a false approved_once, because the signer's log records no approvals. One admin together with a compromised server can forget an approved host with one signature; that server could drop the row without the signer anyway (T-03-285). |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; capslock baseline unchanged (a new pair is a recorded deviation) |
</threat_model>

<verification>
- Every verify command passes, including both CI e2e lanes; the merge gate passes.
</verification>

<success_criteria>
- No agent row is deleted without a signer-logged `host_forget` entry that audit verify accepts.
- An approved-once agent needs the policy's admin_quorum of signatures, and a never-approved one needs one.
- Every forget is recorded in the tamper-evident log with the keys that signed it.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md` in Task 4, before the merge gate. `requirements-completed` is empty (AGENT-01 and REVOKE-02 are complete since 03-07; this plan hardens them). Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (owner decision 03-08 D-1, the 03-08b/03-08c plan check and owner decisions of 2026-10-29)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Owner decision 03-08 D-1 (Daniel, 2026-10-28): forget and `--host-gone` need a signer-checked admin quorum and an audit record in leaf kind 16 | — | must_haves truths 2, 6 and 7; Tasks 1 and 2; T-03-282 closed |
| Owner decision Q1 (2026-10-29): split, server first; the signer path here, depending on 03-08b; threat rows moved to their owner | — | This file (33 files, owner-accepted at about 28); T-03-282, 285, 286, 290, 291, 292 and 293 here; T-03-287 to 289 in 03-08b |
| Owner decision Q2: co-signing as for `ca issue` | — | must_haves truth 8, T-03-292 (accepted residual), Task 4 runbook |
| Owner decision Q3: one signature for a never-approved agent, verified against the server's statement; the quorum otherwise; audit re-checks | — | must_haves truth 3, Task 1 (`need`, ServerApprovedOnce), Task 2 (both sides in the signer and audit), Task 3 (`server_statement_from_the_row`), T-03-293 |
| Owner decision Q4: a forget drill in 03-16 | — | Owner decisions block, Cross-plan notes, Task 4 labels; 03-16-PLAN.md edited |
| Plan check item 1 (major): the delete re-checks the signed facts; `facts_changed_after_accept` | MAJOR | must_haves truth 5 (03-08b's DeleteAgentIf after the signer's answer), Task 3 |
| Plan check item 2 (major): ordering of 03-09 to 03-16 | MAJOR | 03-09-PLAN.md `depends_on: ["03-08c"]` and its precondition; waves 13 to 20 in 03-09 to 03-16; ROADMAP.md and STATE.md |
| Plan check item 5 (minor): what a refusal writes | MINOR | must_haves truth 6; Task 2's refusal cases call ForgetAgent directly and count only kind 16 and revoke_request rows |
| Plan check item 6 (minor): 03-12 in the valid-set note | MINOR | Cross-plan notes |
| Plan check item 8 (minor): the SHA-256 basis | MINOR | must_haves truth 7; `confirmed_sha_matches_the_heartbeat_basis`; TestAgentEnrollEndToEnd with a real heartbeat |
| Plan check item 9 (minor): CreatedAt and slow signing | MINOR | must_haves truth 8; `slow_signing_refused_locally` |
| Planner: full host keys in the request could exceed the 64 KiB frame | LOW | The request carries the keys' SHA-256 fingerprints |
| Planner: audit verify keeps only the directory in force | LOW | A version-to-SHA-256 map from the logged directory_install entries; the content rule is 03-08b's server rule, recorded as attested |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| A co-signing flow for admins on separate machines | Phase 4 (owner decision Q2) |
| `keyroster-agent reset-directory --expect` (the todo's second half) | Out of scope by the owner's instruction; it stays open in the todo |
