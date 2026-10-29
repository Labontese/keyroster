---
phase: 03-linux-agent-and-revocation
plan: 08b
type: execute
wave: 11
depends_on: ["03-08"]
files_modified:
  - internal/serverdb/migrations/0007_forget.sql
  - internal/serverdb/agents.go
  - internal/serverdb/db_test.go
  - internal/server/agent.go
  - internal/server/hosts.go
  - internal/server/forget_test.go
  - internal/server/heartbeat_test.go
  - internal/server/heartbeat_edges_test.go
  - internal/server/agent_test.go
  - internal/serverclient/agent.go
  - cmd/keyroster/host.go
  - cmd/keyroster/host_test.go
  - cmd/keyroster/hoststatus_test.go
  - test/e2e/agent_enroll_test.go
  - test/e2e/agent_forget_test.go
  - docs/runbooks/host-setup.md
autonomous: false
requirements: [AGENT-01, REVOKE-02]

estimate:
  tokens: 85000
  raw_tokens: 85000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Owner decision Q1 (Daniel, 2026-10-29): 03-08b is the server half of forget, split off on the owner's decision. It tightens 03-08's forget and is safe to ship alone. Forget stays one admin's signed request on the server path (03-08); the signer-checked quorum and the `host_forget` audit leaf (kind 16) are 03-08c's, which builds on this plan's facts and delete"
    - "PR #72 fix-round carry-over (a): serverdb's TouchAgent, MarkAgentApproved, SetAgentRemovedVersion and the new RecordRemovalConfirmed write only `WHERE id = ? AND identity_spki_sha256 = ?`, and return serverdb.ErrNotFound when no row has both. MarkAgentApproved and SetAgentRemovedVersion check that the row still exists when their conditional UPDATE changes nothing. requireAgent answers 403 `unknown_agent` on ErrNotFound from any of them. PR #74 pre-merge review fix round 1 (finding 8): every agents-row writer also matches the enrolling join token (`token_hash`, serverdb.AgentKey; each join token enrolls at most one row and an identity rotation keeps it), so a re-enrollment of the same identity into the reused rowid is another row. An in-flight request of a forgotten agent therefore never writes a row that reused its rowid, whatever identity that row has"
    - "PR #72 fix-round carry-over (b). A removal is confirmed when an approved-once agent with removal version R has a stored heartbeat whose committed directory {V, SHA-256} meets all of these:
      - R <= V <= the current version;
      - its SHA-256 is that of the server's directory at V (the current one, or the signer's GetDirectoryVersion);
      - in directory V, no entry holds any of the agent's host keys and no active entry carries its expected name.
    The confirmation is then recorded once on the agents row (serverdb migration 0007: removal_confirmed_version, removal_confirmed_sha256). It is recorded when a heartbeat is stored, and again from the stored heartbeat when `host pending` lists the row; that catches rows from before 0007 and recordings skipped while the signer was unreachable. A later directory with an active entry under the agent's name and other keys (a re-key or a re-enrolled agent) clears neither R nor a recorded confirmation; only an entry holding its keys again clears both. The converse holds: an unconfirmed removal followed by a re-add under the name, which the host reached without applying the removal (host_keys_rotated, last-good principals kept), is not confirmed, and its forget needs `--host-gone`. A row whose removal 03-08 cleared, or whose latest stored heartbeat reports a directory that names it again, is not confirmed retroactively; its forget needs `--host-gone`. Owner decision D-R1 (PR #74 pre-merge review fix round 1): the stored heartbeat must also show that the apply which committed V emptied the host's principals (last_apply ok, host_status host_removed or host_disabled, no pending swap, no `principals/` file), and a later heartbeat of the same agent that shows principals again clears the confirmation (not R), through the same identity- and token-keyed writes."
    - "The SHA-256 basis is pinned (plan check item 8): the confirmation's hash, the server's comparison and the agent's heartbeat (`trust.SHA256Hex` of the stored directory document, apply/status.go) are all over the directory document bytes the server serves, without the signatures. These are the bytes a directory_install leaf records as DirectoryInstallBody.Directory, which 03-08c's audit rule hashes"
    - "PR #72 fix-round carry-over (c): a forget names exactly one agent identity. `keyroster host forget --identity SHA256:...` targets it. `keyroster host forget NAME` is a convenience that resolves the name among `keyroster host pending`'s rows, and refuses `forget_name_ambiguous` when more than one agent has it, listing each identity, its state and its `--identity` command and sending nothing. The request carries the identity and the facts the admin saw: approved_once, the removal version, the recorded confirmation or none, and host_gone. The server finds the row by identity (404 `host_not_enrolled`) and refuses `forget_state_changed` (409) unless every fact equals the row"
    - "Plan check item 1: the delete re-checks those facts in ONE serverdb transaction: `DELETE FROM agents WHERE id = ? AND identity_spki_sha256 = ? AND removed_dir_version IS ? AND removal_confirmed_version IS ? AND removal_confirmed_sha256 IS ? AND (approved_at_us IS NULL) = ?`, with the heartbeat row deleted in the same transaction. When it deletes no row (the identity rotated, the confirmation changed, or the row is gone after the check), the answer is 409 `forget_state_changed` and nothing is deleted"
    - "Forget's gate keeps 03-08's meaning. `host_in_directory` (409) while any directory entry holds one of the agent's host keys. `host_removal_not_applied` (409, and refused by the CLI before it sends) for an approved-once agent without a recorded confirmation. `--host-gone` overrides the second, and is printed by the CLI and logged by the server at warning level; the server refuses a request that sets host_gone together with a confirmation (400). A never-approved agent needs neither"
    - "The runbook's re-enroll flow works end to end on CI e2e (TestAgentReenrollEndToEnd):
      - agent A is removed and its removal confirmed;
      - agent B is enrolled and approved under the same name, so A shows `host_keys_changed` and stays confirmed;
      - `keyroster host forget web1` is refused `forget_name_ambiguous`;
      - `keyroster host forget --identity <A>` succeeds without `--host-gone`;
      - B is still served.
    Owner decision Q4 (2026-10-29): the homelab proof is 03-16's forget drill, so host-setup.md labels the homelab steps UNVERIFIED until 03-16"
  artifacts:
    - path: "internal/serverdb/migrations/0007_forget.sql"
      provides: "agents.removal_confirmed_version and removal_confirmed_sha256"
    - path: "internal/serverdb/agents.go"
      provides: "identity-keyed writers, RecordRemovalConfirmed, DeleteAgentIf with the facts re-check in one transaction"
      contains: "removal_confirmed_sha256 IS ?"
    - path: "test/e2e/agent_forget_test.go"
      provides: "TestAgentReenrollEndToEnd, the runbook's re-enroll flow on CI e2e"
      contains: "func TestAgentReenrollEndToEnd"
  key_links:
    - from: "internal/server/agent.go"
      to: "internal/serverdb/agents.go"
      via: "the heartbeat handler records the confirmation with RecordRemovalConfirmed"
      pattern: "RecordRemovalConfirmed"
    - from: "internal/server/hosts.go"
      to: "internal/serverdb/agents.go"
      via: "handleForgetHost deletes with DeleteAgentIf, re-checking the facts in one statement"
      pattern: "DeleteAgentIf"
    - from: "cmd/keyroster/host.go"
      to: "internal/server/hosts.go"
      via: "host forget sends the identity and the facts it read from host pending"
      pattern: "identity_spki_sha256"
  prohibitions:
    - statement: "keyroster-server never deletes an agent row other than the one whose identity the admin named, and never deletes it unless its approval, removal version and recorded confirmation still equal what the admin saw"
      status: resolved
      verification: test
---

<objective>
Tighten 03-08's `keyroster host forget` on the server, as the first half of the owner's split (Q1, 2026-10-29). Each change is safe to ship alone:
- **(a)** every agents-row write names the identity, so a forgotten agent's in-flight request never writes a row that reused its rowid;
- **(b)** a removal the host confirmed is recorded once and stays confirmed when its name is used again, and only then;
- **(c)** forget names one agent identity, refuses an ambiguous name, and deletes in one statement that re-checks what the admin saw.

The runbook's re-enroll flow then works end to end.

Forget stays one admin's signed request on the server path. The signer-checked admin quorum, the `host_forget` audit leaf (kind 16) and the server relay that deletes only after the signer accepted are 03-08c's (owner decision 03-08 D-1, split by Q1). 03-08c builds on this plan's recorded confirmation, its facts and DeleteAgentIf.

Purpose: AGENT-01 (a host's agent is retired and re-enrolled without confusion) and REVOKE-02 (a host keeps getting the KRL until a forget that names it, with facts that are still true, ends it).

Output: serverdb migration 0007 with the recorded confirmation, the identity-keyed writers, DeleteAgentIf, the confirmation recording, forget by identity with the facts re-check, `forget_name_ambiguous`, the e2e of the re-enroll flow, host-setup.md, and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Q1, 2026-10-29: split, server first.** This plan carries carry-overs (a), (b) and (c), the facts re-check in the delete, TestAgentReenrollEndToEnd and the runbook; forget stays single-admin here. 03-08c carries the signer path and depends on this plan.
- **Q2, 2026-10-29: co-signing.** 03-08c's quorum keys must be reachable from one ssh-agent, as for `ca issue`; multi-machine flows are Phase 4. Nothing in this plan depends on it.
- **Q3, 2026-10-29: never-approved agents.** In 03-08c one admin signature suffices for an agent that never received state. This plan supplies the fact (approved_once) that 03-08c signs.
- **Q4, 2026-10-29: the homelab proof.** A forget drill is added to 03-16 (remove a host, wait for the confirmation, forget, audit verify shows the kind-16 entry). This plan's homelab steps stay UNVERIFIED until 03-16.

No `checkpoint:decision` precedes Task 1.

## Budget

16 files (3 new) and about 85k tokens, close to the 15-file threshold and inside the 100k one. One file over: the e2e of the re-enroll flow gets its own file (test/e2e/agent_forget_test.go) instead of growing agent_enroll_test.go further. 7 of the 16 are test files.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-08-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08-PLAN.md
@.planning/phases/01-trust-core/01-SKELETON.md
@internal/server/hosts.go
@internal/server/agent.go
@internal/serverdb/agents.go
@internal/serverclient/agent.go
@cmd/keyroster/host.go
@docs/runbooks/host-setup.md

Delivery protocol: 01-SKELETON.md, phase 03 names. Branch `p03/08b-forget-quorum`, SUMMARY `.planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md`, docs commit `docs(03-08b): complete forget-server plan`. The branch was cut from main at e816620 (03-08 merged, PR #72) and holds this plan. Work on it when it exists, rebased onto origin/main when behind; create it from origin/main only when it does not exist (the plans merged first in their own docs PR). `depends_on` holds 03-08 (removed_dir_version, the heartbeats, the served rows, removalApplied, hostState). 03-08c depends on this plan, and 03-09 on 03-08c.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "web1 removed → the host's heartbeat shows the removal applied → the server records the confirmation (migration 0007) → keyroster host pending shows it → keyroster host forget sends web1's identity and the facts it read → the server deletes in one transaction that re-checks them → the agent gets unknown_agent"</name>
  <reversibility rating="reversible">A nullable column pair on agents, server-side JSON fields and CLI flags. Nothing signed or logged by the signer changes; 03-08c builds on them.</reversibility>
  <precondition>`git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08-SUMMARY.md` exits 0, `git merge-base --is-ancestor origin/main HEAD` exits 0 on branch p03/08b-forget-quorum, and `git ls-tree --name-only origin/main internal/serverdb/migrations/ | grep -c '/0007_'` prints 0</precondition>
  <files>internal/serverdb/migrations/0007_forget.sql, internal/serverdb/agents.go, internal/server/agent.go, internal/server/hosts.go, internal/serverclient/agent.go, cmd/keyroster/host.go, test/e2e/agent_enroll_test.go</files>
  <read_first>
    - .planning/phases/03-linux-agent-and-revocation/03-08-SUMMARY.md (D-1, carry-overs (a) and (b), "Fix round 1": C1 and the afterAgentLookup hook, C4/C5 removalApplied, C14 rekeyed, D-R1 identity rotation)
    - internal/server/hosts.go (handleForgetHost, removalApplied, hostState, handlePendingHosts), internal/server/agent.go (requireAgent's switch, hostHolds, rekeyed, approved, handleAgentHeartbeat around StoreHeartbeat)
    - internal/serverdb/agents.go (Agent, agentColumns, scanAgent, the writers, DeleteAgent, StoreHeartbeat), internal/serverdb/migrations/0006_heartbeats.sql
    - internal/serverclient/agent.go (AdminForgetHostPath, ForgetHostRequest, ForgetHostAnswer, ServedHost)
    - internal/agent/apply/status.go (the Directory doc: trust.SHA256Hex of the stored directory document)
    - cmd/keyroster/host.go (runHostForget, hostAdminRefusal, checkPendingHost, servedLine, the served lines of host pending, host approve's refusal for a served host)
    - test/e2e/agent_enroll_test.go step 9 (removal, the forget loop)
  </read_first>
  <action>
Work on branch `p03/08b-forget-quorum` (Delivery protocol above).

**serverdb.**
- 0007_forget.sql adds the nullable `removal_confirmed_version INTEGER` and `removal_confirmed_sha256 BLOB` to agents; Agent and scanAgent carry them.
- `RecordRemovalConfirmed(ctx, id, spki, removedVersion, version, sha)` sets both only while the removal version the caller validated against is still the recorded one and no confirmation is: `WHERE id = ? AND identity_spki_sha256 = ? AND removed_dir_version = ? AND removal_confirmed_version IS NULL`. A removal re-recorded or cleared between the snapshot and the write (an entry holding the keys again, then a new removal) records nothing; the next heartbeat or `host pending` re-runs the rule. Test: `TestRemovalConfirmation/removal_changed_before_record` (RED if the `removed_dir_version = ?` term is dropped).
- `SetAgentRemovedVersion(..., 0)` clears both.
- A `ForgetFacts{ApprovedOnce bool; RemovalVersion uint64; ConfirmedVersion uint64; ConfirmedSHA256 []byte}` struct, and `DeleteAgentIf(ctx, id, spki, facts)`, which replaces DeleteAgent. In one transaction it deletes the heartbeat row and then the agents row with the statement in must_haves (NULL for an absent removal or confirmation; `IS ?` matches NULL). It rolls back and returns ErrNotFound when the agents row was not deleted.

**Server, the confirmation (agent.go, hosts.go).**
- After StoreHeartbeat stored a higher seq, the heartbeat handler records the confirmation for an approved-once agent with a removal version and none recorded, by must_haves' rule:
  - removalApplied's range and SHA-256 checks;
  - hostState of directory V equal to removed: directory V is the current dv for the current version, else the signer's GetDirectoryVersion parsed.
- Any signer error is logged at warning level and skipped, and the heartbeat's answer never depends on it.
- handlePendingHosts runs the same recording from the stored heartbeat for each served row with a removal version and no confirmation, before it answers.
- The served rows carry `removal_version` and `removal_confirmed {version, sha256}`, omitted when absent.
- The SHA-256 everywhere is trust.SHA256Hex of the document bytes without signatures.

**Server, forget (hosts.go).** handleForgetHost decodes strictly `{"identity_spki_sha256": 64 hex, "approved_once": bool, "removal_version": uint64, "removal_confirmed": {version, sha256} or absent, "host_gone": bool}`. A request with host_gone and a confirmation, or approved_once false with any removal fact, is 400 malformed. In order:
1. the directory in force (503 when unreadable);
2. AgentBySPKI (404 `host_not_enrolled`);
3. the facts equal the row (409 `forget_state_changed`);
4. hostHolds (409 `host_in_directory`);
5. approved-once without a confirmation and without host_gone (409 `host_removal_not_applied`);
6. DeleteAgentIf (409 `forget_state_changed` on ErrNotFound).

It answers ForgetHostAnswer with the one row. The log lines keep 03-08's forms (`agent forgotten` at info level, the `--host-gone` warning) with the identity; the warning says the removal was never confirmed only when no confirmation was recorded. Rewrite handleForgetHost's doc comment: forget is addressed by identity and re-checks the facts; it stays one admin's request until 03-08c adds the signer's quorum and audit entry.

**CLI (host.go).** runHostForget takes `[NAME] [--identity SHA256:...] [--host-gone] [--admin-key FP]`. In order:
1. GET AdminPendingHostsPath; the candidates are its pending and served rows, checked by checkPendingHost and the new removal fields.
2. Pick the target by identity, or by name when exactly one row has it (the ambiguity refusal is Task 2's).
3. An approved-once row without a confirmation and without `--host-gone` is refused locally with `host_removal_not_applied`, its text naming `keyroster host forget --identity <identity> --host-gone`.
4. `--host-gone` given for a confirmed or never-approved row is dropped, with a note.
5. Print the identity, name, state, the removal version and the confirmation or the override.
6. POST, and check that the answer names exactly the requested identity.

hostAdminRefusal states `forget_state_changed` (run the command again; the agent changed since `host pending` was read). host approve's refusal for a served host advises forgetting by identity. The served line for a re-keyed host becomes `host_keys_changed, served until forget`, and every served row of `host pending` prints its confirmation (`removal confirmed at directory v<N>`, or not confirmed) and its `keyroster host forget --identity <identity>` command.

**e2e (test/e2e/agent_enroll_test.go, step 9; plan check item 7).** The forget loop retries while the CLI refuses `host_removal_not_applied`, with a deadline of twice the test fetcher's poll interval plus 30 s, and fails with the last answer. The forget then succeeds, and the agent's next poll gets `unknown_agent` (the fetcher's error line, which the test logs). Like 03-08, the e2e evidence comes from the CI E2E lanes dispatched on the pushed branch: WSL on the owner's workstation does not resolve `keyroster.localhost` (deferred-items.md).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./internal/serverdb/... ./internal/server/... ./internal/serverclient/... ./cmd/keyroster/... && go vet -tags e2e ./test/e2e/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output</fails_when>
    <automated>git push -u origin p03/08b-forget-quorum && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/08b-forget-quorum && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08b-forget-quorum --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit (the E2E run on the pushed head failed or never appeared), or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestAgentEnrollEndToEnd" or "unknown_agent", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'removal_confirmed_sha256 IS ?' internal/serverdb/agents.go` prints at least 1.
    - `grep -c "are 03-08b's" internal/server/hosts.go` prints 0.
    - TestAgentEnrollEndToEnd's log on both CI lanes shows the forget by a confirmation the server recorded from the real agent's heartbeat (the SHA-256 basis of must_haves, end to end), and the fetcher's `unknown_agent` line; the SUMMARY names the run ID.
  </acceptance_criteria>
  <done>A removed host's confirmation is recorded from its own heartbeat, and forget names its identity and deletes only while the facts the admin saw still hold.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Carry-overs (a), (b) and (c) as named tests, the stale-facts delete, the existing forget tests, and the runbook's re-enroll flow on CI e2e</name>
  <files>internal/serverdb/agents.go, internal/serverdb/db_test.go, internal/server/agent.go, internal/server/hosts.go, internal/server/forget_test.go, internal/server/heartbeat_test.go, internal/server/heartbeat_edges_test.go, internal/server/agent_test.go, cmd/keyroster/host.go, cmd/keyroster/host_test.go, cmd/keyroster/hoststatus_test.go, test/e2e/agent_forget_test.go</files>
  <behavior>
    - (a) serverdb (`TestAgentWritesKeyedByIdentity`):
      - Agent A is enrolled as the highest rowid and deleted, then B is enrolled. The test asserts that B got A's rowid, which SQLite reuses for the highest row.
      - Each writer called with (A.ID, A's identity) returns ErrNotFound, and B's row is unchanged column for column: TouchAgent, MarkAgentApproved, SetAgentRemovedVersion, RecordRemovalConfirmed and DeleteAgentIf.
      - MarkAgentApproved on a row already approved keeps the first time and returns nil.
    - (a) server (`TestInFlightRequestOfForgottenAgent`, with 03-08's afterAgentLookup hook): A's state request is looked up, then the hook forgets A and enrolls B into the reused rowid. The request is answered 403 `unknown_agent`, and B's approved_at_us, removed_dir_version and last_seen_us are untouched. RED on the head before this task: B's row is written.
    - (b) server (`TestRemovalConfirmation`):
      - `confirmed_then_readded_kept`: removal at R, and a heartbeat reporting {R, the served SHA-256} records the confirmation. An entry under the same name with other keys at R+1 keeps R and the confirmation, and the forget is accepted without host_gone. RED before: removed_dir_version cleared.
      - `late_heartbeat_reporting_the_removal_confirms`: R is recorded and R+1 re-adds the name; then a heartbeat reporting R arrives, and it is confirmed.
      - `unconfirmed_then_readded_not_confirmed`, the converse: R is recorded unconfirmed and the host jumps to R+1 (an active entry by its name). Its heartbeat reports R+1 and is not confirmed, and forget without host_gone is refused `host_removal_not_applied`.
      - `entry_holding_its_keys_again_clears`: R and the confirmation are cleared.
      - `other_sha_not_confirmed`: V with a SHA-256 the server never served is not confirmed.
      - `signer_unreachable_skips_then_pending_records`: an older V while the signer fails; the heartbeat is 200 and nothing is recorded. Once the signer answers, `host pending` records the confirmation from the stored heartbeat.
      - `confirmation_sha_is_the_document_hash`: the recorded SHA-256 equals trust.SHA256Hex of the signer's GetDirectoryVersion(V).Directory, the document without signatures.
      - `pre_0007_latest_heartbeat_only`: a row from before migration 0007 whose removal 03-08 had cleared, or whose latest stored heartbeat reports a directory that names it again, gets no confirmation when `host pending` lists it; forget without host_gone is refused `host_removal_not_applied`.
    - (c) server (`TestForgetHost`):
      - `by_identity_among_two_with_one_name`: A removed and confirmed, B approved under the same name; A's forget deletes only A's row.
      - `facts_changed_refused`: the request's removal version differs from the row; 409 `forget_state_changed`, nothing deleted.
      - `facts_changed_before_delete` (plan check item 1), through a nil-by-default server hook between the facts check and DeleteAgentIf: the hook records a confirmation, or rotates the identity. The answer is 409 `forget_state_changed` and the row is still present.
      - `host_gone_with_confirmation_malformed` (400); `never_approved_needs_no_confirmation`.
    - (c) CLI (`TestHostForget`, `TestHostForgetHostGone`, fake server):
      - `name_ambiguous_refused`: two rows with the name; non-zero exit, both identities and the `--identity` command printed, nothing POSTed.
      - `by_identity`, `not_confirmed_refused_locally`, `host_gone_sent`, `host_gone_dropped_when_confirmed` (with the note), `answer_names_another_identity_refused`, `state_changed_explained`.
    - The existing forget tests follow the new API with their meaning kept:
      - TestHostForgetWaitsForRemoval;
      - TestForgetGateChecksTheDirectory: its range and SHA-256 cases now test the recording;
      - TestAgentRemoval, TestHeartbeatAfterForget;
      - TestRekeyedHostNotRemoved: a re-key with no earlier removal still records nothing;
      - TestServedLine: the new re-keyed label, the confirmation and the `--identity` line.
    - e2e (`TestAgentReenrollEndToEnd`, test/e2e/agent_forget_test.go, with enrollApproved):
      - web1 is enrolled as agent A and approved, then removed; the test waits until `keyroster host pending` shows A's removal confirmed.
      - A second host layout with new host keys enrolls as agent B under web1 and is approved; A then shows `host_keys_changed` and stays confirmed.
      - `keyroster host forget web1` is refused `forget_name_ambiguous` naming both identities (the test logs the refusal).
      - `keyroster host forget --identity <A>` succeeds without `--host-gone`.
      - A's fetcher logs `unknown_agent`; B still polls and applies a revocation made after the forget (its KRL version grows).
      - Every wait has a deadline of twice the poll interval plus 30 s and fails with the last answer.
  </behavior>
  <read_first>
    - The files written in Task 1; .planning/phases/03-linux-agent-and-revocation/03-08-SUMMARY.md "Fix round 1" (C1, C14, the tests it added)
    - internal/server/heartbeat_edges_test.go (TestHeartbeatAfterForget and its use of afterAgentLookup, TestRekeyedHostNotRemoved, TestForgetGateChecksTheDirectory), internal/server/heartbeat_test.go (TestHostForgetWaitsForRemoval, the e.hbAt helper), internal/server/agent_test.go (TestAgentRemoval)
    - cmd/keyroster/host_test.go (TestHostForget and its fake server), cmd/keyroster/hoststatus_test.go (TestHostForgetHostGone, TestServedLine)
    - test/e2e/agent_status_test.go (enrollApproved, waitStatus), test/e2e/agent_enroll_test.go (newEnrolledHostLayout, startEnrolled)
  </read_first>
  <action>
Write the tests in `<behavior>` first. Run the (a) and (b) cases RED on Task 1's head, and record each RED output in the SUMMARY as 03-08's fix round did. Then implement.

(a) In internal/serverdb/agents.go, TouchAgent, MarkAgentApproved and SetAgentRemovedVersion take the identity and add `AND identity_spki_sha256 = ?`. MarkAgentApproved and SetAgentRemovedVersion keep their own conditions and, when they change no row, check that a row with both still exists: ErrNotFound means gone, and nil means a condition held. requireAgent passes the looked-up identity to each, and answers 403 `unknown_agent` on ErrNotFound from any of them, not only from TouchAgent.

(b) In requireAgent's switch:
- the re-keyed case neither records nor clears;
- the case of an entry holding the agent's keys again clears the removal version and the confirmation, as the approved case does;
- the removal is still recorded only when no entry holds its keys and no active entry carries its name.

Check that Task 1's recording reads directory V's content, not the current directory's.

(c) runHostForget's name resolution refuses `forget_name_ambiguous` when more than one candidate row has the name. For each row it prints the identity, the state with the confirmation when recorded, enrolled_at and its `--identity` command. Add the hook `facts_changed_before_delete` needs (nil by default, like afterAgentLookup).

Update the existing forget tests to the new API without weakening them, and say in the SUMMARY which assertions moved where. Write TestAgentReenrollEndToEnd; its e2e evidence comes from the CI E2E lanes, as in Task 1.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestAgentWritesKeyedByIdentity|TestInFlightRequestOfForgottenAgent|TestRemovalConfirmation|TestForgetHost|TestHostForget|TestServedLine|TestHostForgetWaitsForRemoval|TestForgetGateChecksTheDirectory|TestAgentRemoval|TestHeartbeatAfterForget|TestRekeyedHostNotRemoved" ./internal/serverdb/ ./internal/server/ ./cmd/keyroster/ && go vet -tags e2e ./test/e2e/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of "--- PASS: TestInFlightRequestOfForgottenAgent", "--- PASS: TestRemovalConfirmation/confirmed_then_readded_kept", "--- PASS: TestRemovalConfirmation/unconfirmed_then_readded_not_confirmed", "--- PASS: TestRemovalConfirmation/confirmation_sha_is_the_document_hash", "--- PASS: TestRemovalConfirmation/pre_0007_latest_heartbeat_only", "--- PASS: TestForgetHost/by_identity_among_two_with_one_name", "--- PASS: TestForgetHost/facts_changed_before_delete" or "--- PASS: TestHostForget/name_ambiguous_refused" missing</fails_when>
    <automated>git push origin p03/08b-forget-quorum && scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/08b-forget-quorum && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do RUN=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08b-forget-quorum --event workflow_dispatch --commit "$(git rev-parse HEAD)" --limit 1 --json databaseId --jq '.[0].databaseId'); [ -n "$RUN" ] && break; sleep 10; done && scripts/gh-as-bot.sh run watch "$RUN" --exit-status && scripts/gh-as-bot.sh run view "$RUN" --log</automated>
    <fails_when>non-zero exit, or the log of either job, e2e (9.5p1) and e2e (10.5p1), lacks "--- PASS: TestAgentReenrollEndToEnd", "--- PASS: TestAgentEnrollEndToEnd", "--- PASS: TestAgentStatusEndToEnd" or "forget_name_ambiguous", or reports any e2e test as FAIL</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -c 'identity_spki_sha256 = ?' internal/serverdb/agents.go` covers TouchAgent, MarkAgentApproved, SetAgentRemovedVersion, RecordRemovalConfirmed and DeleteAgentIf (the SUMMARY lists the lines).
    - `grep -c 'host_keys_changed (re-enroll)' cmd/keyroster/host.go`, `grep -c 'forget it (keyroster host forget %s)' cmd/keyroster/host.go` and `grep -c 'run keyroster host forget NAME --host-gone' cmd/keyroster/host.go` each print 0.
    - The SUMMARY records:
      - the RED runs of TestInFlightRequestOfForgottenAgent and `TestRemovalConfirmation/confirmed_then_readded_kept` on the head before this task;
      - the mutant that drops the identity from one writer's WHERE;
      - the mutant that makes the re-keyed case clear again;
      - the mutant that checks the current directory instead of directory V (which `unconfirmed_then_readded_not_confirmed` or `late_heartbeat_reporting_the_removal_confirms` must kill);
      - the mutant that deletes by (id, identity) only (killed by `facts_changed_before_delete`).
    - The CI E2E run on the pushed head is the evidence for TestAgentReenrollEndToEnd; the SUMMARY names its run ID.
  </acceptance_criteria>
  <done>A forgotten agent's in-flight request writes nothing; a removal the host confirmed stays confirmed when its name is re-used, and only then; forget names one identity, refuses an ambiguous name and deletes only while the facts hold; and the re-enroll flow runs end to end in CI.</done>
</task>

<task type="auto">
  <name>Task 3: host-setup.md, the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/host-setup.md</files>
  <read_first>
    - docs/runbooks/host-setup.md "Removing a host", the re-keyed paragraph of "Running the agent" (around `keyroster host status`), "An unexpected identity rotation" and the refusal table of "Enrolling a host"
    - .planning/phases/03-linux-agent-and-revocation/03-03b-SUMMARY.md deviation 8 (the SUMMARY is pushed before the PR opens)
  </read_first>
  <action>
**host-setup.md (D-20).** Every changed operator step is labelled as run (where and when) or UNVERIFIED.

**"Removing a host", step 2:** `keyroster host pending` shows the recorded confirmation (`removal confirmed at directory v<N>`). It is recorded from the host's own heartbeat when the reported directory is one the server served and removes the host, and it stays recorded when the name is used again. A row whose removal 03-08 cleared, or whose latest stored heartbeat reports a directory that names it again, is not confirmed retroactively; its forget needs `--host-gone`.

**Step 3 rewritten:**
- forget names one agent: `keyroster host forget --identity <identity>`, or the name when only one agent has it (`forget_name_ambiguous` otherwise);
- the CLI sends what `host pending` showed, and the server refuses `forget_state_changed` when the agent changed since then: run the command again;
- `--host-gone` stays for a host that never confirmed.

**The closing paragraph of that section** ends with exactly the interim sentence `Until plan 03-08c, forget needs no admin quorum and leaves no audit entry.` (03-08c replaces it and greps for it). Labels: run in CI (TestRemovalConfirmation, TestForgetHost, TestHostForget, TestAgentEnrollEndToEnd, TestAgentReenrollEndToEnd, 03-08b); the homelab steps UNVERIFIED until 03-16, whose forget drill proves them (owner decision Q4).

**The re-keyed paragraph of "Running the agent", replaced, with both orders.** Enrollment refuses an identity or a host key that another agents row still holds (`identity_in_use`, `host_keys_in_use`).

- **Same machine, keeping its fetcher identity (`identity.key`) or its host keys:**
  1. remove the entry;
  2. wait for the confirmation in `keyroster host pending`;
  3. forget the old agent;
  4. mint a new join token and run `keyroster-agent install` again;
  5. approve.

  Labelled UNVERIFIED until 03-16, whose forget drill runs exactly this order.
- **A new identity and new host keys** (another machine, or a reinstalled fetcher on a re-keyed host):
  1. remove the entry;
  2. wait for the confirmation;
  3. enroll and approve the new agent under the name;
  4. forget the old agent by identity.

  The name alone is then refused as ambiguous. Labelled run in CI e2e (TestAgentReenrollEndToEnd, 03-08b).

In both orders the forget needs no `--host-gone` when the old agent confirmed its removal before the name was re-used, and does need it when the old agent never applied the removal.

**"An unexpected identity rotation", step 1:** forget the lost row by its identity, with `--host-gone`.

**The refusal table gains** `forget_name_ambiguous` and `forget_state_changed`, each with its fix. The `host_removal_not_applied` row now names the recorded confirmation.

**Removed:** the sentence naming the plan that adds a quorum and an audit record (now 03-08c), and every label or step that names the old re-keyed label or forgets a re-keyed host by name with `--host-gone`.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**The PR.** `scripts/gh-as-bot.sh pr create --title "fix(agent): forget hosts by identity, keep confirmed removals and key agent writes by identity"`, without enabling auto-merge (the orchestrator enables it after the pre-merge review). Wait for the required checks.

**The SUMMARY.** Contents:
- the PR number and the CI run IDs;
- the RED evidence and the mutants of Task 2;
- capslock;
- `requirements-completed` empty: AGENT-01 and REVOKE-02 are complete since 03-07, and this plan hardens them.

Then the tracking updates once, `docs(03-08b): complete forget-server plan`, push, and wait.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'forget_name_ambiguous' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'forget_state_changed' && tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c '03-08c'</automated>
    <fails_when>non-zero exit (the runbook lacks a new refusal or the pointer to 03-08c)</fails_when>
    <automated>git fetch origin p03/08b-forget-quorum && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)"</automated>
    <fails_when>non-zero exit (the SUMMARY is not on the pushed branch, or local commits are unpushed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08b-forget-quorum --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - Texts this plan makes false are gone from host-setup.md, checked with white space squashed:
      - `tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'Plan 03-08b adds both'` prints 0;
      - the same with `'host_keys_changed (re-enroll)'`, `'To re-enroll it, forget the old agent'` and `'then forget the agent with'` each prints 0.
    - `tr -s '[:space:]' ' ' < docs/runbooks/host-setup.md | grep -c 'Until plan 03-08c, forget needs no admin quorum and leaves no audit entry.'` prints 1.
    - Every new or rewritten section names at least one CI test and `UNVERIFIED until 03-16`.
    - The PR is open without auto-merge (the orchestrator enables it after the pre-merge review), every required check green, 03-08b-SUMMARY.md on its head.
  </acceptance_criteria>
  <done>The runbook tells operators how forget targets one agent, when its removal counts as confirmed and how to re-enroll a host; the PR waits green.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 4: Merge gate — owner approves PR p03/08b-forget-quorum, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. `gh pr view p03/08b-forget-quorum --web`; review DeleteAgentIf, the confirmation rule in the heartbeat path, forget's facts check and 03-08b-SUMMARY.md, especially that a re-key never clears a confirmed removal and never confirms an unconfirmed one.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved"; after a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08b-forget-quorum` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08b-forget-quorum</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-08c's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08b-forget-quorum --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The server half of forget is on main, and 03-08c may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08c** builds on this plan and must not change:
  - the recorded confirmation (columns and rule);
  - ForgetFacts and DeleteAgentIf;
  - forget's identity addressing;
  - the served rows' `removal_version` and `removal_confirmed`.

  03-08c replaces the forget request's JSON facts with an admin-signed wire.ForgetRequest that carries the same facts, and deletes with DeleteAgentIf only after the signer accepted.
- **Migrations.** serverdb 0007 is this plan's; no later plan claims a serverdb migration. 03-12 owns signerdb 0006, and this plan touches no signer code.
- **03-16** (owner decision Q4) owns the homelab proof: its forget drill removes a host, waits for the confirmation, forgets it and checks the kind-16 entry (03-08c).
- **03-09** depends on 03-08c (plan check item 2), and through it on this plan.

## Edge Coverage (spec-less fallback, this plan)

This plan authors the forget path's edges as truths.

**Flagged assumption, the confirmation is the host's word.** It rests on the heartbeat, which the host composes and the server relays (T-03-284). The server records it only for a directory version it served, at or above the removal, that removed the host.

**Flagged assumption, the admin and the server agree on facts, not on authority.** Until 03-08c, one admin's signed HTTP request decides a forget, as in 03-08 (T-03-282, still accepted here).

**Edges:**
- adjacency (`late_heartbeat_reporting_the_removal_confirms`);
- ordering (`facts_changed_before_delete`, `TestInFlightRequestOfForgottenAgent`);
- reuse (`TestAgentWritesKeyedByIdentity`);
- ambiguity (`name_ambiguous_refused`);
- the converse of (b) (`unconfirmed_then_readded_not_confirmed`).

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Revocations keep reaching a host until a forget that names it, with true facts, ends it | Tasks 1, 2 |
| REQ | AGENT-01 (retire and re-enroll a host's agent) | Task 2 (TestAgentReenrollEndToEnd), Task 3 (runbook) |
| REQ | REVOKE-02 (the KRL reaches every enrolled host until it is forgotten) | Tasks 1, 2 |
| CONTEXT | D-10 (a forgotten host keeps its last state and logs `unknown_agent`) | Task 1 e2e |
| CONTEXT | D-20 (runbook in the same PR, run or UNVERIFIED) | Task 3 |
| Owner decision | Q1 (split, server first), Q4 (03-16 owns the homelab proof) | This plan; Cross-plan notes |
| Review | PR #72 fix-round carry-overs (a), (b), (c) | Tasks 1, 2 |
| Plan check | Item 1 (the delete re-checks the facts), item 7 (e2e deadlines), item 8 (the SHA-256 basis) | Tasks 1, 2 |

## Artifacts this phase produces (this plan)

- serverdb: migration `0007_forget.sql` (`removal_confirmed_version`, `removal_confirmed_sha256`), `RecordRemovalConfirmed`, `ForgetFacts`, `DeleteAgentIf`, identity-keyed writers.
- server: the confirmation recording (heartbeat and `host pending`), forget by identity with refusals `forget_state_changed` and `host_removal_not_applied` from the recorded confirmation; served rows carry `removal_version` and `removal_confirmed`.
- CLI: `keyroster host forget [NAME] [--identity SHA256:...] [--host-gone]`, refusal `forget_name_ambiguous`, the served line `host_keys_changed, served until forget` and each served row's forget command.
- Tests: TestAgentWritesKeyedByIdentity, TestInFlightRequestOfForgottenAgent, TestRemovalConfirmation, TestForgetHost, the extended TestHostForget, TestAgentReenrollEndToEnd.
- Docs: host-setup.md "Removing a host", the re-enroll flow, the identity-rotation step, the refusal table.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| admin CLI → keyroster-server | The admin's signed request names an identity and the facts the admin saw; the server deletes only while they hold |
| host → server (heartbeat) | The confirmation rests on the host's own report (T-03-284) |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-282 | Repudiation / Elevation of privilege | `keyroster host forget` (and `--host-gone`) decided by one admin and recorded only in keyroster-server's log | medium | accept (residual, 03-08c) | Unchanged from 03-08 by owner decision Q1: this plan keeps forget single-admin. **Closed by 03-08c** (signer-checked quorum, leaf kind 16, audit verify) |
| T-03-287 | Tampering | an in-flight request of a forgotten agent writing a row that reused its rowid (PR #72 carry-over a), the same identity re-enrolled into it included (PR #74 review finding 8) | medium | mitigate | Every agents-row writer is keyed by (id, identity SPKI, join token hash) (serverdb.AgentKey) and refuses with ErrNotFound; requireAgent answers 403 `unknown_agent`. Tests: TestAgentWritesKeyedByIdentity, TestAgentWritesKeyedByToken, TestInFlightRequestOfForgottenAgent, TestReenrolledIdentityKeepsItsRow (RED before) |
| T-03-288 | Elevation of privilege | a forget counted as confirmed for a host that kept its last-good principals (re-keyed before it applied the removal), or a confirmed removal lost when the name is re-used (PR #72 carry-over b) | medium | mitigate | Confirmation is recorded only for a served directory version V (server's SHA-256 of the document without signatures) at or above the removal version, in which no entry holds the host's keys and no active entry carries its name, and (owner decision D-R1, PR #74 review fix round 1) only when the host's own heartbeat shows that the apply which committed V emptied its principals (last_apply ok, host_status host_removed or host_disabled, no pending swap, no `principals/` file). A later heartbeat that shows principals again clears it; a re-key alone never does; an entry holding its keys again clears it with the removal. Tests: `confirmed_then_readded_kept`, `late_heartbeat_reporting_the_removal_confirms`, `unconfirmed_then_readded_not_confirmed`, `other_sha_not_confirmed`, `report_not_emptied_not_confirmed`, `renamed_then_rekeyed_not_confirmed`, `principals_again_clears`, `keys_rotated_without_principals_kept`. **Residual:** the confirmation is the host's word: a fetcher that lies about what was applied gets it recorded (T-03-284, accepted) |
| T-03-289 | Denial of service / Tampering | a forget that hits another agent, or none, when two agents share a name, or that deletes after the agent changed (PR #72 carry-over c, plan check item 1) | medium | mitigate | The request names the identity; a name is resolved only when exactly one agent has it (`forget_name_ambiguous`). The server requires every fact to equal the row, and DeleteAgentIf re-checks identity, approval, removal and confirmation in one statement (`forget_state_changed`). Tests: `by_identity_among_two_with_one_name`, `name_ambiguous_refused`, `facts_changed_refused`, `facts_changed_before_delete`, TestAgentReenrollEndToEnd |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; capslock baseline unchanged (a new pair is a recorded deviation) |
</threat_model>

<verification>
- Every verify command passes, including both CI e2e lanes; the merge gate passes.
</verification>

<success_criteria>
- A forgotten agent's in-flight request writes nothing.
- A confirmed removal survives the re-use of its name, and an unconfirmed one followed by a re-key is not confirmed.
- Forget names one identity and deletes only while the facts the admin saw hold.
- The runbook's re-enroll flow runs on CI e2e.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md` in Task 3, before the merge gate. `requirements-completed` is empty (AGENT-01 and REVOKE-02 are complete since 03-07; this plan hardens them). Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (owner decision 03-08 D-1, the PR #72 fix-round check, the 03-08b/03-08c plan check and owner decisions of 2026-10-29)

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| PR #72 fix-round check, carry-over (a): MarkAgentApproved, SetAgentRemovedVersion and TouchAgent keyed by agents.id only, so an in-flight request of a forgotten agent can write a reused rowid | MEDIUM | must_haves truth 2, Task 2 (TestAgentWritesKeyedByIdentity, TestInFlightRequestOfForgottenAgent, RED before), T-03-287 |
| PR #72 fix-round check, carry-over (b): re-adding a name after a confirmed removal clears removed_dir_version, so forget needs `--host-gone` and logs a false "never confirmed" warning | MEDIUM | must_haves truths 3 and 4 (recorded once, with the converse and the SHA-256 basis), Task 1 (migration 0007 and the recording), Task 2 (TestRemovalConfirmation, RED before), T-03-288 |
| PR #72 fix-round check, carry-over (c): forget by expected name cannot forget the old row once a re-enrolled agent holds the name, and the re-keyed label leads admins into it | MEDIUM | must_haves truths 5 and 8, Task 1 (forget by identity), Task 2 (`forget_name_ambiguous`, TestForgetHost, TestAgentReenrollEndToEnd), Task 3 (runbook flow), T-03-289 |
| Owner decision Q1 (Daniel, 2026-10-29): split, server first; forget stays single-admin here and must be safe alone | — | This file (16 files, about 85k); the signer path is 03-08c; T-03-282 stays accepted here and closes in 03-08c |
| Owner decision Q4 (2026-10-29): a forget drill in 03-16 | — | Cross-plan notes; host-setup.md labels; 03-16-PLAN.md edited with the drill |
| Plan check item 1 (major): the delete must re-check the signed facts | MAJOR | must_haves truth 6, DeleteAgentIf in Task 1, `facts_changed_before_delete` in Task 2 |
| Plan check item 7 (minor): e2e forget retry loops need a deadline | MINOR | Task 1 (step 9) and Task 2 (TestAgentReenrollEndToEnd): twice the poll interval plus 30 s, failing with the last answer |
| Plan check item 8 (minor): pin the SHA-256 basis of the confirmation | MINOR | must_haves truth 4; `confirmation_sha_is_the_document_hash`; TestAgentEnrollEndToEnd records it from a real heartbeat |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| The signer-checked quorum, leaf kind 16 and the audit rule | 03-08c (owner decision Q1) |
| `keyroster-agent reset-directory --expect` (the todo's second half) | Out of scope by the owner's instruction; it stays open in the todo |
