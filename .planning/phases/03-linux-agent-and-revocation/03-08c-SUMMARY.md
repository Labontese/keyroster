---
phase: 03-linux-agent-and-revocation
plan: 08c
subsystem: agent
tags: [agent, forget, signer, audit-log, admin-quorum, leaf-kind-16, host_forget]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08b: the recorded removal confirmation, ForgetFacts, DeleteAgentIf keyed by serverdb.AgentKey, forget by identity, forget_name_ambiguous, not_yet_polled candidates, TestAgentReenrollEndToEnd"
provides:
  - "wire: ForgetRequestDomain and ForgetSSHSIGNamespace (keyroster/host-forget-request/v1), ForgetRequest (with the unsigned ServerApprovedOnce and the signed EnrolledAtMicros), ForgetResponse, ParseForgetRequest, ParseForgetSigningBytes, ParseForgetResponse, HostKeyDigest, TypeForgetAgentRequest 0x0D, TypeForgetAgentResponse 0x8D"
  - "tlog: KindHostForget 16 (host_forget), HostForgetBody, DecodeHostForgetBody; valid set 1 to 10, 15 and 16"
  - "signer: ForgetAgent, forgetOrRefuse; refusals forget_no_installation_id, forget_installation_mismatch, forget_facts_mismatch, forget_host_in_directory, forget_confirmation_invalid, forget_directory_unreadable; signerclient.ForgetAgent"
  - "audit: verifyForget, the directory version-to-SHA-256 map, verifyRevokeAdmins counting distinct admins against a quorum, the kind-16 export with admin_fingerprints, checkForgetFields"
  - "server: the forget relay (ForgetHostBody, ForgetHostAnswer.Leaf, forget_logged_not_deleted, host_swap_pending); serverdb ForgetFacts.EnrolledAtUS and DeleteAgentIf's in-transaction heartbeat check; StoreHeartbeat keyed on AgentKey"
  - "CLI: repeatable --admin-key for host forget, the local admin_quorum_not_met, request_time_skew (240 s) and host_swap_pending refusals, 'Forget logged as audit entry N'"
  - "tests: TestForgetRequest, TestForgetRequestSigningVector, TestForgetResponse, TestHostForgetBody, TestHostForgetLeafVector, TestForgetAgent, TestVerifyHostForget, TestExportHostForget, the extended TestForgetHost, TestHostForget, TestRemovalConfirmation, TestDeleteAgentIf, TestAgentWritesKeyedByToken, TestReenrolledIdentityKeepsItsRow; FuzzParseForgetRequest, FuzzParseForgetSigningBytes, FuzzParseForgetResponse; golden vectors forget_request_signing_v1.hex and leaf_host_forget_v1.hex"
affects: [03-09, 03-16]

actuals:
  tokens: 64071
  tasks: 4
  commits: 12
plan_head_before: 6dea9f34456c978fb779aa36c0e1dd47b8d66256
plan_head_after: 0edc835f4fb16b0a9c13fd90205bc3a072e4dd59

tech-stack:
  added: []
  patterns:
    - "A server action that removes access is relayed to the signer, which decides and logs it before the server acts; the server's own view of a fact the signer cannot see travels outside the signed bytes and is compared with the signed one"
    - "A delete that depends on a host-reported state re-reads that state inside its own transaction through a pure predicate, so serverdb stays free of the heartbeat format"

key-files:
  created:
    - internal/wire/forget.go
    - internal/signer/forget.go
    - internal/signer/forget_test.go
    - internal/audit/forget.go
    - internal/audit/forget_test.go
    - test/vectors/forget_request_signing_v1.hex
    - test/vectors/leaf_host_forget_v1.hex
  modified:
    - internal/wire/frame.go
    - internal/wire/wire_test.go
    - internal/wire/fuzz_test.go
    - internal/tlog/leaf.go
    - internal/tlog/leaf_test.go
    - internal/tlog/fuzz_test.go
    - internal/signer/refusal.go
    - internal/signer/server.go
    - internal/signer/logstate.go
    - internal/signerclient/client.go
    - internal/audit/verify.go
    - internal/audit/revoke.go
    - internal/audit/recovery.go
    - internal/audit/export.go
    - internal/audit/fuzz_test.go
    - internal/server/hosts.go
    - internal/server/signer.go
    - internal/server/server.go
    - internal/server/server_test.go
    - internal/server/agent_test.go
    - internal/server/forget_test.go
    - internal/server/heartbeat_edges_test.go
    - internal/serverclient/agent.go
    - internal/serverclient/client.go
    - internal/serverclient/admin.go
    - internal/serverdb/agents.go
    - internal/serverdb/db_test.go
    - cmd/keyroster/host.go
    - cmd/keyroster/ca.go
    - cmd/keyroster/ca_test.go
    - cmd/keyroster/host_test.go
    - cmd/keyroster/hoststatus_test.go
    - cmd/keyroster/dirpipe_test.go
    - test/e2e/agent_enroll_test.go
    - test/e2e/agent_forget_test.go
    - docs/runbooks/host-setup.md
    - .planning/phases/03-linux-agent-and-revocation/03-08b-SUMMARY.md
    - .planning/todos/pending/2026-10-28-audit-host-forget-and-directory-reset.md

key-decisions:
  - "03-08c: every forget, --host-gone included, is a keyroster/host-forget-request/v1 request the signer decides under owner decision Q3 (one admin for an agent never approved, the policy's admin_quorum otherwise) and logs as host_forget (leaf kind 16) before the server deletes"
  - "03-08c carried item 1 (owner decision 2026-10-29): a pending swap keeps a recorded confirmation and refuses forget (host_swap_pending) in the CLI, before the signer and inside DeleteAgentIf's transaction; --host-gone overrides it, so the signed format admits host_gone together with a confirmation"
  - "03-08c carried item 2: the forget request signs the agent's enrollment time (enrolled_at_us, whole seconds since enrollment shipped in PR #71), checked by the relay and DeleteAgentIf"
  - "03-08c: the server's host_removal_not_applied refusal is gone, because no signed request can name an approved-once agent without a confirmation or host_gone; the CLI keeps the refusal"

patterns-established:
  - "A log entry kind joins format v1 with its strict body, its audit rule, its export rendering, a golden vector and a fuzz seed in one plan"

requirements-completed: []

duration: 168min
completed: 2026-10-30
status: complete
---

# Phase 3 Plan 08c: Forget Through the Signer Summary

**`keyroster host forget` now sends an admin-signed `keyroster/host-forget-request/v1` request. keyroster-signer checks it under owner decision Q3 (one admin for an agent never approved, the policy's admin quorum for every other) and logs it as a `host_forget` entry (leaf kind 16) in the transaction of its decision. keyroster-server deletes the agent only after that answer, re-checking every fact in the delete, and fails closed. `keyroster audit verify` re-checks every such entry from the log alone. The four items carried from 03-08b's review are in: a pending swap refuses forget instead of clearing the confirmation, the request is bound to the agent's enrollment, the heartbeat writes are keyed, and a sentence in 03-08b's SUMMARY is corrected.**

PR: **#75** (`p03/08c-forget-signer`), opened without auto-merge. `requirements-completed` is empty: AGENT-01 and REVOKE-02 have been complete since 03-07; this plan hardens them, and 03-16 proves it on the homelab.

## Owner attention first

1. **The signed format admits `host_gone` together with a confirmation** (deviation 1). The plan's `Validate` refused that combination, but the addendum's item 1(c) needs `--host-gone` to override the wait for a pending swap on a *confirmed* agent. The request then carries the confirmation the admins saw and the override, and the `host_forget` entry records both.
2. **Forget waits for every swap, the hourly KRL republish included** (carried item 1). While the stored heartbeat shows a pending swap, forget is refused `host_swap_pending` until the next heartbeat shows it committed. E2E run 40977822524 showed this in practice: the revocation after the removal in `TestAgentEnrollEndToEnd` made the removed host swap, and the e2e's forget had to wait (deviation 14).
3. **Same-second re-enrollment residual** (carried item 2). The binding uses `enrolled_at_us`, which every enrollment has stored in whole seconds since enrollment shipped (PR #71, `Truncate(time.Second)`; checked with `git log -S`). A forget read before a re-enrollment of the same identity in the *same second* as the original enrollment cannot be told apart. That would need host pending's read, a full forget and the re-enrollment all inside that second. A nonce derived from the join token would close it, at the cost of a new served field.
4. **CI's e2e runs only the one-key path.** CI's e2e policy has admin quorum 1. The quorum-2 path (two `--admin-key`, the signer's and audit's distinct-admin counts) runs in unit tests only.
5. **capslock: no new pair** (92/37/23, equal to the baseline). No Go module was added.

## Accomplishments

- **Wire** (`internal/wire/forget.go`, `frame.go`). The `ForgetRequest` signing bytes are the raw domain, then:
  - the installation ID;
  - the identity's SPKI SHA-256;
  - the expected name;
  - `EnrolledAtMicros` (deviation 2);
  - 1 to 8 ascending, unique host key digests (`HostKeyDigest`, the SHA-256 that `ssh.FingerprintSHA256` prints);
  - approved_once, the removal version, the confirmed version and SHA-256, host_gone, the request ID and CreatedAt.

  `Marshal` appends the evidence and one unsigned `ServerApprovedOnce` byte. The parsers are strict: trailing bytes, a boolean byte other than 0 or 1, and a count above 8 are refused, and the signing bytes must re-encode identically. Socket messages 0x0D/0x8D.
- **tlog.** `KindHostForget` 16 and `HostForgetBody{PolicyVersion, DirectoryVersion, ResolvedAtSeconds, Request, Evidence}`. The valid set is 1 to 10, 15 and 16, and the Kind comment is rewritten.
- **Signer** (`ForgetAgent`). It takes one clock reading. The order of its checks:
  1. validity;
  2. ±300 s;
  3. a request ID unused by any revoke, recovery or forget;
  4. the installation ID;
  5. the signed approved_once equals `ServerApprovedOnce` (`forget_facts_mismatch`);
  6. `verifyAdminSignatures` with need 1 or `s.policy.AdminQuorum`;
  7. no directory entry, active or disabled, holds a named key (`forget_host_in_directory`; an unreadable stored directory is refused, deviation 11);
  8. the confirmation's document is a stored directory at that version with that SHA-256 (`forget_confirmation_invalid`).

  Then one `logTx`: the trust check, the leaf, and `InsertRevokeRequestTx`. After COMMIT it writes the log line `agent forget logged` (warning level for host_gone). `forgetOrRefuse` logs refusals as for revoke, and `classify` knows every new detail.
- **Audit.**
  - `verifyForget` applies the plan's rule; the request ID joins the shared set of revokes and recoveries.
  - `directoryInForce.shas` maps each logged directory version to the SHA-256 of `DirectoryInstallBody.Directory`.
  - `verifyRevokeAdmins` takes a quorum and now counts distinct admins (1 for revoke and recovery).
  - The export renders kind 16, and `checkForgetFields` binds `approved_once` and `host_gone` to the leaf.
- **Server relay** (`handleForgetHost`). In order:
  1. `{"request": ...}` parsed strictly (400);
  2. the directory (503);
  3. `AgentBySPKI` (404);
  4. the facts, the name, the host keys and the enrollment time equal the row (409 `forget_state_changed`, the signer not asked);
  5. `host_in_directory` (409);
  6. `host_swap_pending` (409, unless host_gone);
  7. `ServerApprovedOnce` from `approved_at_us`;
  8. `signer.ForgetAgent`: malformed gives 400, refused gives 403 with the reason, anything else 503 with nothing deleted;
  9. `DeleteAgentIf`, which re-checks every fact and the pending swap in its transaction; `ErrNotFound` or a swap gives 409 `forget_logged_not_deleted` with the leaf, logged at error level.
- **CLI.**
  - `adminEvidence` signs any bytes under any namespace, for `ca issue` and `host forget`.
  - `host forget` takes a repeatable `--admin-key` (the first signs the HTTP request) and pins the bundle's installation ID.
  - It refuses `admin_quorum_not_met` (distinct keys) before it signs, prints what is signed, and refuses `request_time_skew` after 240 s.
  - It prints `Forget logged as audit entry N` and explains `forget_logged_not_deleted` and `host_swap_pending`.
- **Carried items** (addendum): see "Carried items" below.
- **Runbook** (host-setup.md):
  - "Removing a host", step 3, covers who signs, the 240 s bound, the signer's refusals, the audit entry and `forget_logged_not_deleted`;
  - the new paragraph "Checking that a forget was authorized";
  - the swap text in step 2 and the re-enroll paragraph;
  - the refusal table gains `host_swap_pending`, `admin_quorum_not_met`, `request_time_skew`, `forget_facts_mismatch`, `forget_host_in_directory`, `forget_confirmation_invalid` and `forget_logged_not_deleted`, and `host_removal_not_applied` is now the CLI's.

  Every changed section names CI tests and `UNVERIFIED until 03-16`.
- **Todo.** The forget half reads "resolved in 03-08b and 03-08c (PR from branch p03/08c-forget-signer; ...)". The file stays in pending/, because the reset half is open.

## Task commits

| Commit | What |
|---|---|
| `a01f92f` fix(server): key every heartbeat write on the agent's key | Carried item 3 |
| `f47ebe5` docs(03-08b): correct the upgraded host's lost removal confirmation | Carried item 4 |
| `71c0e3b` feat(agent): forget hosts only under signer-checked admin signatures | Task 1 (tracer), with carried item 2 in the signed fields |
| `0f4bae4` fix(agent): refuse forget during a pending swap instead of clearing | Carried item 1 (a), (b), (c), with its runbook text |
| `8a0dce0` test(agent): pin the forget decision's edges, vectors and fuzz targets | Task 2 |
| `71c9cc1` refactor(signer): drop forget checks that an earlier step already makes | Task 2's equivalent mutants (deviation 13) |
| `b03a719` test(agent): pin the forget relay's fail-closed cases and the quorum CLI | Task 3 |
| `0de1be0` docs(agent): document forget under the admins' signatures and its audit entry | Task 4, runbook |
| `5d95047` test(agent): let the enroll e2e's forget wait for the removed host's swap | Found in CI (deviation 14) |
| `670aac0` test(signer): refuse a forget against an unreadable stored directory | Deviation 11's tests |
| `7bd09aa` refactor(cli): build the forget request from the values host pending checked | Unreachable branches removed |
| `0edc835` test(agent): run the forget's installation and enrollment-time refusals | Two untested refusals |
| this file's `docs(03-08c)` commit | SUMMARY, STATE.md, ROADMAP.md, the todo |

Every commit is SSH-signed by keyroster-bot (one `BEGIN SSH SIGNATURE` per commit object) and has no attribution lines. Before each commit, the staged diff was grepped for 100.x, 10.x and 192.168.x addresses and for the real host names, with none found. gofmt ran by absolute path with a positive control.

## Carried items (addendum, 2026-10-29)

1. **Pending swap: refuse instead of clear** (`0f4bae4`).
   - (a) `principalsShown` no longer counts `Pending`, and `principalsEmptied` requires `st.Pending == nil` itself, so a pending status never confirms (`report_not_emptied_not_confirmed/swap_pending` still passes; mutant I1-a is killed by it).
   - (b) The refusal is enforced where forget decides:
     - the relay refuses `host_swap_pending` before asking the signer, from the stored heartbeat;
     - `DeleteAgentIf(ctx, k, facts, hbCheck)` reads the row's stored heartbeat inside its own transaction (`_txlock=immediate`, one connection) and refuses through `swapPending`.

     A swap stored after the signer's answer therefore ends in `forget_logged_not_deleted` (`pending_swap_after_the_signer_answer`, mutant I1-c).
   - (c) `--host-gone` bypasses both (`pending_swap_host_gone_overrides`, mutant I1-d). `host pending` prints `removal confirmed at directory vN; swap pending, forget waits until the host finishes it` (`ServedHost.SwapPending`; `swap_pending_refused_locally`, mutant I1-g). The CLI keeps `--host-gone` for a confirmed agent with a swap pending and sends both (`swap_pending_host_gone_sends_both`, mutant T3-7).
   - The refusal code is `host_swap_pending`, and the CLI explains it (`server_swap_pending_explained`).
   - `pending_swap_clears_keys_rotated_for_good` is replaced by `pending_swap_refuses_forget_until_it_commits`: the confirmation survives the swap, forget is refused until a committed heartbeat, then it goes through without `--host-gone`. `pending_swap_clears_then_commit_confirms_again` is replaced by `pending_swap_keeps_the_confirmation`.
   - The runbook text from 03-08b round 2 is rewritten (step 2, the re-enroll paragraph, the refusal table).
2. **The CLI GET/POST race** (`71c0e3b`). `EnrolledAtMicros` is in the signing bytes and the golden vector from the start. `ForgetFacts` gains `EnrolledAtUS`, `sameFacts` compares it, and `DeleteAgentIf` adds `AND enrolled_at_us = ?`. The export renders `enrolled_at_us`.
   - RED on 03-08b's code (03-08b's API, in a copy of HEAD): `the forget the CLI built from A: 200 {"forgotten":[... "enrolled_at":"2026-10-19T12:01:00Z"}]}, want 409 forget_state_changed` and `the new enrollment of A's identity was deleted by a forget built from A's row`.
   - Now `TestReenrolledIdentityKeepsItsRow/cli_read_then_reenrolled` passes, and the signer is not asked. Mutant T3-8 (`sameFacts` without the time) is killed, and `DeleteAgentIf` still catches it as `forget_logged_not_deleted`.
   - The residual is Owner attention 3.
3. **StoreHeartbeat keyed on AgentKey** (`a01f92f`). The clock_offset UPDATE, the seq_regressed UPDATE and the heartbeat upsert (`INSERT ... SELECT id FROM agents WHERE <key>`) each name the key, with `ErrNotFound` on zero rows. There is **no behavioural RED**: while `agentExists` shares the transaction, nothing observable changes. The evidence is mutants against `TestAgentWritesKeyedByToken` (with a new `seq_regressed` leg):
   - I3-a-old: 03-08b's code without `agentExists` is **killed**, because B's row and heartbeat change.
   - I3-a-new: this code without `agentExists` **survives**, which is the locality the item asks for.
   - I3-b, I3-c and I3-d: without `agentExists`, with one write back to by-ID: each is **killed** by a changed row or heartbeat.
   - I3-e (the control: without `agentExists`, the keyed writes unchecked) is killed only because the regressed path then answers `ErrSeqRegressed` instead of `ErrNotFound`. No row or heartbeat changed.
4. **03-08b SUMMARY sentence** (`f47ebe5`). An upgraded host's confirmation is not lost for good: the next real render, the signer's at-least-hourly KRL republish (D-10) included, installs a `host_removed` generation, and the next heartbeat confirms again. The agent's apply path was checked: a KRL change renders a new generation.

## Reconciliations with 03-08b's code (the plan predates its fix rounds)

- **AgentKey writers.** The relay deletes with the key of the row it read (`a.Key()`), as 03-08b requires.
- **ForgetFacts and DeleteAgentIf are not unchanged** (the plan says they are reused unchanged). `ForgetFacts` gains `EnrolledAtUS` (carried item 2). `DeleteAgentIf` gains the `hbCheck` parameter (carried item 1). The 20 test call sites pass `nil`.
- **The confirmation rule.** 03-08b's D-R1 rules stay, except item 1's change to the pending swap.
- **Host status `not_yet_polled` and entry names.** These are inherited unchanged by the CLI's target resolution (`TestHostForget/name_ambiguous_with_an_approved_not_polled_agent` still passes).
- **The forget request's JSON** (`serverclient.ForgetHostRequest`) is gone: the body is now `ForgetHostBody{Request}`, and the server tests' helper builds a `wire.ForgetRequest` from the row (deviation 9).

## The tracer and Task 3 in CI

- **E2E run 40974763604** on `71c0e3b` (the tracer): both lanes green.
  - `TestAgentEnrollEndToEnd` passed on 10.5p1 (7.14 s) and 9.5p1 (8.13 s): `Forget logged as audit entry 15 by keyroster-signer`, and `keyroster audit verify --json` gave `"kinds":{...,"host_forget":1,...}`.
  - On 10.5p1 the entry is `{"admin_fingerprints":["SHA256:4J8o…leUM"],"approved_once":true,"confirmed_sha256":"10feea92…0cda","confirmed_version":5,"directory_version":5,"enrolled_at_us":1793317394000000,...,"expected_name":"web1","host_gone":false,"host_key_fingerprints":["SHA256:zkkW…Fryo"],"identity":"SHA256:2+pM…dFo","removal_version":5,...}`.
  - The server's line from the real agent's heartbeat is `"agent removal confirmed",...,"agent":"SHA256:2+pM…dFo","removal_version":5,"directory_version":5`.
  - `TestAgentReenrollEndToEnd` passed too (audit entry 9).
- **E2E run 40977822524** on `b03a719`: 10.5p1 failed `TestAgentEnrollEndToEnd` on `host_swap_pending` (deviation 14). 9.5p1 was green.
- **E2E run 40979222434** on `5d95047`: both lanes green, no `--- FAIL`. `TestAgentEnrollEndToEnd` took 9.17 s on 10.5p1 and 8.16 s on 9.5p1. `TestAgentReenrollEndToEnd` took 20.12 s and 24.17 s; its `host_forget` entry names A's identity, `approved_once` true, `host_gone` false and A's confirmation at v5.
- **The PR's own runs** on later heads are in the handback.

## RED evidence and mutants

**RED runs:**
- Carried item 2: on 03-08b's code (above).
- Carried item 1, on the tracer head `71c0e3b`:
  - `pending_swap_keeps_the_confirmation`: `removed_dir_version 2, confirmed v0 ; want 2, v2 2008d68e…fc3d`;
  - `pending_swap_refuses_forget_until_it_commits`: `confirmed v0 ; want 2, v2 dbc7…b85e`;
  - CLI `swap_pending_refused_locally`: `exit 0, sent true`;
  - CLI `swap_pending_host_gone_sends_both`: sent without the confirmation;
  - CLI `server_swap_pending_explained`: only the server's text.

  `pending_swap_host_gone_overrides` and `pending_swap_after_the_signer_answer` passed on the tracer head through fix round 2's clear. After the change they pass through the new checks, and mutants I1-d and I1-c show they test them.
- The golden vectors were RED by absence (`open ..\..\test\vectors\forget_request_signing_v1.hex: The system cannot find the file`) until `-update` wrote them.

**GREEN at once:**
- Task 2: every `TestForgetRequest`, `TestForgetResponse`, `TestHostForgetBody`, `TestForgetAgent`, `TestVerifyHostForget` and `TestExportHostForget` case. Task 1 had built the code they test.
- Task 3: every new `TestForgetHost` and `TestHostForget` case. `facts_changed_after_accept` and `slow_signing_refused_locally` were GREEN on Task 2's head, because Task 1 left no gap: the delete hook already ran after the signer's answer, and the 240 s bound was already in.

For these, the mutants below are the evidence.

**Mutants.** Windows, Go 1.27.3. Each mutant was applied to the working tree, its named test was run, and the file was restored and hash-checked. The log is outside the repo. In total, 42 ran:
- 38 were killed (I3-e only on the error code);
- 1 survived as intended (I3-a-new, the locality the item asks for);
- 2 are equivalent: T2-5c, whose check was then removed, and T2-6a, which was kept;
- 1 was a build failure (I1-c), rewritten and then killed.

| # | Mutant | Result |
|---|---|---|
| T2-1 | signer `need` fixed at 1 | killed (`approved_once_one_admin_refused`) |
| T2-2 | signer `need` fixed at the quorum | killed (`never_approved_one_admin_accepted`) |
| T2-3 | audit rule fixed at 1 | killed (`approved_once_one_signature_fails`) |
| T2-3b | audit rule fixed at the quorum | killed (`never_approved_one_signature_passes`) |
| T2-3c | audit counts evidence items, not distinct admins | killed (`same_admin_twice_fails`) |
| T2-4 | server-statement comparison removed | killed (`server_statement_mismatch_refused`) |
| T2-5a | signer confirmation SHA-256 check removed | killed (`confirmation_sha_mismatch_refused`) |
| T2-5b | audit confirmation SHA-256 check removed | killed (`confirmed_sha_not_logged_fails`) |
| T2-5c | signer "confirmation above the installed version" check removed | **equivalent**: the stored-directory lookup refuses the same; the check was removed (`71c9cc1`) |
| T2-5d/e | host_in_directory check removed in signer / audit | killed |
| T2-6a | signer's request-ID pre-check skipped | **equivalent, kept**: the `revoke_request` primary key refuses the same inside the transaction, as for Revoke |
| T2-6b | pre-check and record both skipped | killed (`duplicate_request_refused`) |
| T2-6c | audit's shared request-ID lookup skipped | killed (`request_id_reused_fails`) |
| T2-7 | kind 16 not in tlog's valid set | killed (`restart_after_forget`); this replaces the plan's "kind 16 case removed from rebuildLogFrom", which is equivalent (deviation 13) |
| T2-8 | audit directory version check removed | killed |
| T2-9 | `checkForgetFields` removed | killed (`TestExportHostForget`) |
| T2-10/11 | unreadable stored directory / unparsable stored key not refused | killed (`stored_directory_unreadable_refused`) |
| T3-1 | `DeleteAgentIf` by the agent key only (fact terms ORed away) | killed (`facts_changed_after_accept`) |
| T3-2 | the delete moved before the signer call | killed (`signer_unavailable_deletes_nothing`) |
| T3-3 | `ServerApprovedOnce` taken from the request | killed (`server_statement_from_the_row`) |
| T3-4 | CLI `need` fixed at 1 | killed (`approved_once_fewer_keys_refused_locally`) |
| T3-5 | CLI 240 s bound removed | killed (`slow_signing_refused_locally`) |
| T3-6 | CLI counts `--admin-key` values, not distinct keys | killed |
| T3-7 | CLI drops `--host-gone` during a swap | killed |
| T3-8 | relay ignores the enrollment time | killed (`cli_read_then_reenrolled`) |
| T3-9 | relay ignores the name and host keys | killed (`facts_changed_refused`) |
| I1-a…g | item 1 (above) | 7 killed; I1-c first broke the build (an unused variable) and was rewritten, then killed |
| I3-a-old…e | item 3 (above) | 4 killed, 1 survived as intended (I3-a-new), 1 killed only on the error code (I3-e, the control) |

## Grep acceptance

- `grep -c 'keyroster/host-forget-request/v1' internal/wire/forget.go`: 1.
- `KindHostForget` case lines: `internal/signer/logstate.go:367` and `internal/audit/verify.go:881`.
- `grep -v '^[[:space:]]*//' internal/signer/forget.go | grep -c 's.policy.AdminQuorum'`: 1.
- `grep -c 'leaves a server log line only' internal/server/hosts.go`: 0.
- Both vectors are non-empty. Two more `-update` runs of each vector test leave them unchanged (`git diff --exit-code test/vectors/` exits 0).
- `grep -c 'KindHostForget' internal/tlog/fuzz_test.go`: 2. `grep -c 'Forget' internal/audit/fuzz_test.go`: 2.
- host-setup.md (white space squashed): `host_forget` and `forget_logged_not_deleted` are present; `forget needs no admin quorum and leaves no audit entry` is 0.
- The todo has `resolved in 03-08b and 03-08c`, and no completed/ copy exists.

## What ran and what did not

**Ran:**
- **WSL (Ubuntu, Go 1.27.3), each on a copy of the tree (`git archive HEAD`), deleted afterwards:**
  - Task 1's verify on `71c0e3b` (`-race` over wire, tlog, signer, signerclient, audit, server, serverclient, serverdb and the CLI, and `go vet -tags e2e`);
  - Task 2's named `-v` run, with every required `--- PASS` line present;
  - 20 s of fuzzing each of `FuzzParseForgetRequest`, `FuzzParseForgetSigningBytes`, `FuzzParseForgetResponse`, `FuzzDecodeLeaf` and `FuzzVerifyExport`, with no failure;
  - Task 3's named `-race` run;
  - **the full gate twice, the second time on the final code head `0edc835`, exit 0 (`GATE PASSED`):**
    - gofmt by absolute path with its positive control;
    - `CGO_ENABLED=1 go test -race -count=1 ./...`: 34 packages ok, no data race;
    - `go vet` (plain, `e2e`, `e2e systemdsmoke`);
    - golangci-lint: 0 issues for linux, windows and darwin;
    - capslock (92/37/23, equal to the baseline), dep-firewall, testonly-firewall (6 combinations) and check-pinned-actions (47).
- **Windows (Go 1.27.3):** the package tests after each change, every mutant, and `GOOS=linux go vet -tags e2e` of the e2e package.
- **CI:** E2E runs 40974763604, 40977822524 and 40979222434 (above), and the PR's required checks (in the handback).

**Not run here:**
- The e2e tests locally: WSL cannot resolve `keyroster.localhost`. The CI E2E lanes are the evidence.

**UNVERIFIED:**
- **Every homelab step**, until 03-16's forget drill (owner decision Q4): forget with the admins' keys, `--host-gone`, the 240 s bound with real touch-confirming keys, "Checking that a forget was authorized" as an operator check, and the swap wait on a real host.
- **The quorum-2 path end to end.** It is unit-tested only (Owner attention 4).
- **The database-error branches** of the new code: the relay's heartbeat read (500), `DeleteAgentIf`'s non-`ErrNotFound` error after the signer logged (500), the signer's `DirectoryByVersion` error (`state_unavailable`) and `DeleteAgentIf`'s heartbeat query error. Like the existing handlers' DB-error branches, no test injects a database failure.
- **The same-second re-enrollment residual** (Owner attention 3) is not tested, by construction.

## Decisions Made

See `key-decisions`. The owner's decisions applied here are 03-08 D-1, Q1 to Q4 (2026-10-29) and the addendum's item 1 alternative (2026-10-29).

## Deviations from Plan

1. **[Owner decision, addendum item 1(c)] `host_gone` together with a confirmation is valid.** The plan's `Validate` required exactly one of confirmation or host_gone for an approved-once agent, and its test list refused "host_gone with a confirmation". The override of a pending swap on a confirmed agent needs both. The rule is now: approved once needs a confirmation, host_gone, or both. The test `accepted_combinations/host_gone_with_confirmation` pins it. 03-08b's server-side refusal of that combination (its deviation 4) is gone with the JSON request.
2. **[Carried item 2] `EnrolledAtMicros` is in the signing bytes** and in `ForgetFacts`/`DeleteAgentIf`. The export renders `enrolled_at_us` beyond the plan's key list.
3. **[Carried item 3] StoreHeartbeat keyed.** There is no behavioural RED; the mutant evidence is above.
4. **[Carried item 4] The 03-08b SUMMARY sentence is corrected** (a planning file outside the plan's list).
5. **[Reconciliation] `ForgetFacts` and `DeleteAgentIf` changed**, against the plan's "reused unchanged" (see Reconciliations).
6. **[Plan detail] Files outside the plan's list:**
   - `internal/serverclient/client.go` and `admin.go`: `APIError.Leaf` and `HTTPError.Leaf()`, so the CLI can name the entry of a `forget_logged_not_deleted`;
   - `internal/server/server.go` (the hook's comment), `agent_test.go` and `heartbeat_edges_test.go` (the request helpers and the `DeleteAgentIf` call sites);
   - `internal/audit/recovery.go` (the quorum argument);
   - `cmd/keyroster/ca_test.go`, `hoststatus_test.go` and `dirpipe_test.go` (the test agent counts forget signatures);
   - `internal/serverdb` and `test/e2e/agent_forget_test.go`;
   - the audit tests live in a new `internal/audit/forget_test.go` rather than `verify_test.go`.
7. **[Plan detail] The CLI's line** is `Forget logged as audit entry N by keyroster-signer (host_forget; keyroster audit verify checks it).`, which contains the plan's `logged as audit entry`.
8. **[Plan detail] wire defines its own host name grammar and `MaxForgetHostKeys`** instead of importing `directory`, which would add packages to every binary that imports wire, the fetcher included. `TestForgetRequest/grammar_matches_directory` asserts that they equal directory's.
9. **[Rule 1, plan vs code] The server's `host_removal_not_applied` became unreachable and was removed.** A signed request cannot name an approved-once agent without a confirmation or host_gone. The CLI keeps the refusal; its mapping of the server's code and the CLI test `server_refusal_explained` went. The server tests' `forgetFacts` helper emulates the CLI's local refusal, as 03-08b's helper already acted like the CLI.
10. **[Plan detail] One hook, moved.** 03-08b's `beforeForgetDelete` now runs between the signer's answer and `DeleteAgentIf`, instead of a second hook being added. 03-08b's `forget_in_flight` and `facts_changed_before_delete` now expect `forget_logged_not_deleted`. The latter's subtests are `TestForgetHost/facts_changed_after_accept` and `identity_rotated_after_accept`.
11. **[Rule 2] `forget_directory_unreadable`.** A stored directory that does not parse cannot tell whether it holds the host, so the forget is refused. So is a stored host key that does not parse (`bad_stored_directory`). Both are tested white-box (`stored_directory_unreadable_refused`), because Parse refuses both at install.
12. **[Plan detail] `forget_no_installation_id`** is classed `ReasonUnauthorized` (403 with its reason), not unavailable, and the CLI refuses it before it signs (`no_installation_id_refused_locally`).
13. **[Mutants, then code] Equivalent checks removed.**
    - The rebuild's kind-16 case does not decode the body again (DecodeLeaf already did), so the plan's mutant "kind 16 case removed from rebuildLogFrom" is equivalent. T2-7 (kind 16 out of the valid set) is the kill that `restart_after_forget` makes.
    - The signer's above-version check went (T2-5c).
    - The CLI's `forgetRequestOf` no longer repeats checks of values that host pending's checks already made (`7bd09aa`).
14. **[Rule 1, found in CI] The enroll e2e's forget waits for the swap.** E2E run 40977822524 failed `TestAgentEnrollEndToEnd` on 10.5p1 with `host_swap_pending`. The revocation after the removal makes the removed host swap, and item 1 now makes forget wait for it, where fix round 2 had cleared and re-confirmed. The loop retries on it as on `host_removal_not_applied` (`5d95047`), within the same 32 s deadline. Run 40979222434 is green on both lanes.
15. **[Plan detail] The e2e reads `keyroster audit verify --json`** for the kind count and the export file for the entry (`checkForgetEntry`), which also checks that the entry's index is the CLI's `audit entry N` and its identity the forgotten one.

**Total deviations:** 15. Of these, 1 and 2 are addendum-directed, 3 and 4 carry 03-08b items, 5 is a reconciliation, 9 and 14 are Rule 1, 11 is Rule 2, and the rest are plan details or mutant follow-ups. No Go module was added.

## TDD Gate Compliance

- Tasks 2 and 3 are `tdd="true"`. Their tests were written before any fix, and every case was GREEN at once (Task 1 had built the code). The mutants above are the evidence that each test checks its rule.
- Carried items 1 and 2 have RED runs (above). Item 3 has mutant evidence only, as stated.

## Issues Encountered

- Shell heredocs again turned `\\n` and `\d` inside Go strings into newlines or a lost backslash. Each was caught by the build or by vet before any commit, and fixed by writing the edit scripts to files.
- One mutation script also rewrote `func TestDeleteAgentIf(t *testing.T)`. The build caught it before any commit, and it was fixed.

## Known Stubs

None.

## Threat Flags

None beyond the plan's register. The new surface is socket messages 0x0D/0x8D on the signer's peer-checked socket (T-03-282, T-03-286) and the forget route's new body (the same admin-signed route).

## Open questions for the owner (Daniel)

1. Is `host_gone` together with a confirmation acceptable in the signed format (deviation 1)?
2. Is the same-second re-enrollment residual acceptable, or should the binding use a nonce derived from the join token (a new served field)?
3. Forget waits for every swap, the hourly KRL republish included (`host_swap_pending`). Is that delay acceptable in production?
4. Is 403 right for `forget_no_installation_id` (deviation 12)?
5. Should CI get an e2e lane at admin quorum 2?

## User Setup Required

None.

## Next Phase Readiness

- **03-09:** depends on this plan; its precondition checks this SUMMARY on origin/main. The leaf kinds 11 to 14 stay reserved, and 0x0A to 0x0C are free. `revoke_request` now holds revoke, recovery and forget request IDs, and audit keeps one set for all three.
- **03-16:** the forget drill proves every UNVERIFIED homelab item above (owner decision Q4).

## Pre-merge review fix round 1

The review ran at head `ddcc9a2` against base `6dea9f3` in security mode. Daniel decided D-1 to D-4 on 2026-10-30. Findings [3], [4] and [6] were refuted and need no action.

### Owner decisions

- **D-1: audit verify binds the host_forget line (findings [1] and [2], medium).** A `host_forget` export line must now be byte for byte the line the export writes for its verified leaf. Export and verify share one encoder, `exportLeafLine`. Every decoded field is therefore the leaf's own:
  - identity, expected_name, enrolled_at_us and host_key_fingerprints;
  - approved_once and host_gone;
  - removal_version, confirmed_version and confirmed_sha256;
  - request_id, created_at and resolved_at;
  - the policy and directory versions;
  - evidence_types;
  - admin_fingerprints, rendered from the leaf's own evidence, whose signatures verifyForget checks.

  A changed, added, removed, repeated or re-encoded field is refused. So is a duplicated key or a duplicated `decoded` object, which a map comparison would let through.

  This replaces the round's earlier binding of approved_once and host_gone only. Lines 14 and 139 above describe that earlier state. Lines of other kinds still may not carry approved_once or host_gone.

  The runbook's "Checking that a forget was authorized" now lists exactly these fields, and says that they record what the admins signed, not that it was true (T-03-293 stands).
- **D-2: the executor's questions 1, 3 and 4 are owner-approved as built.**
  - host_gone may appear together with a confirmation (deviation 1).
  - Forget waits out every swap (Owner attention 2).
  - forget_no_installation_id answers 403 (deviation 12).
- **D-3: the same-second re-enrollment residual is accepted (Owner attention 3).** It is recorded in threat row T-03-286 of 03-08c-PLAN.md and in host-setup.md's "Removing a host" step 3.
- **D-4: CI gets no quorum-2 e2e lane (Owner attention 4).** 03-16-PLAN.md's forget drill now records the admin quorum the forget used: a `quorum=` field on the forget line, which must equal the entry's admin_fingerprints count. When the homelab policy has at least two admins, the drill runs the forget at quorum 2. Until then, host-setup.md keeps quorum 2 labelled UNVERIFIED end to end.

### Fixes

| Finding | Commit | Test | RED and mutants (scratchpad `fix75-1/`) |
|---|---|---|---|
| [0] a forget could delete a host that resumed service: heartbeat stored, confirmation not yet cleared | `4479225`, then `939b5ef` (the refusal code) | `TestRemovalConfirmation/resumed_{before,after}_the_signer_{principals_file,rendered_entry}`, `resumed_host_gone_overrides`, `no_or_unreadable_heartbeat_refused` | RED: 200 with the row deleted in all four cases. 6 mutants killed: the principalsShown term, the Pending term, a nil body accepted, the pre-signer check, the delete's error mapping, and the delete's predicate reverted to swapPending |
| [7] the signer's forget trusted the in-memory directory | `9bcd77b` | `TestForgetAgent/directory_written_behind_the_signer_refused` | RED: accepted (`Leaf:5`). With only the guard in place: accepted (`Leaf:6`). 2 mutants killed: the guard, and the transaction check |
| [5] --host-gone over a pending swap on a confirmed agent was described as "never confirmed" | `2208e33` | `swap_pending_host_gone_sends_both` (CLI), `TestHostForgetHostGone/host_gone_sent` (CLI, the other branch), `pending_swap_host_gone_overrides` and `principals_again_clears` (server log) | RED in both packages. 4 mutants killed: the CLI summary, the CLI closing line, the server branch, and the server's confirmed version |
| D-1 (findings [1] and [2]) | `3f2caf1` | `TestExportHostForget`: every decoded key changed and removed, admins swapped, a field added, a duplicated key, a duplicated decoded object, extra white space, and an unchanged re-encoding that still verifies | RED: 36 tamper cases verified; the 3 others (kind changed, kind removed, a duplicated decoded object) the kind check already refused. 3 mutants killed: the line equality, the other-kind check, and the call site |
| Docs for the above, D-3 and D-4 | `c3f5c58` | n/a | n/a |

**[0] in detail.** A forget that rests on the recorded confirmation runs `removalStillApplied` on the stored heartbeat twice: before the signer is asked, and again inside DeleteAgentIf's transaction. It accepts a heartbeat only if the heartbeat parses, shows no pending swap, and shows no principals by `principalsShown`, the rule by which reconcileRemoval clears a confirmation. Both checks use the same rule, so they cannot drift apart.

`principalsEmptied` is deliberately not required: host_keys_rotated keeps a confirmation, and `keys_rotated_noop_apply_kept` forgets such a host without --host-gone. A missing or unreadable heartbeat refuses as well, because a confirmation is only ever recorded from a stored heartbeat.

The two checks answer differently:
- Before the signer, the answer is 409 forget_state_changed. The CLI's next run reads host pending, which clears the confirmation, and then refuses locally, naming --host-gone. `939b5ef` changed this code from host_removal_not_applied, which the CLI stopped mapping in deviation 9.
- After the signer, the answer is 409 forget_logged_not_deleted with the leaf.

--host-gone keeps its override.

**[7] in detail.** A confirmation above the version in force is refused forget_confirmation_invalid before any stored row is read; this restores the guard that deviation 13 removed. The forget's transaction also re-reads `LatestDirectoryVersionTx` and refuses directory_changed (unavailable) when it differs, as login does.

**[5] in detail.** With a confirmation in the request, the CLI prints `host_gone: overrides the host's unfinished swap` and closes with "it overrode the host's unfinished swap; the host had confirmed its removal". The server logs `agent forgotten with --host-gone over a pending swap` with removal_confirmed_version.

### Gate and CI

- **Windows (Go 1.27.1):** after each change, the package tests, every RED run, every mutant, and `GOOS=linux go vet -tags e2e ./test/e2e/`.
- **The local gate in WSL, on a `git archive` copy outside the repository.** It ran three times:
  - **On `c3f5c58`:** `GATE PASSED`.
  - **On the final code head `939b5ef`, first run:** failed on `TestFetch/more_repolls_immediately` in `internal/agent/fetch` (`requests ... in 1.10425855s, want two at once`). This package has no diff against the PR's base, and the test passed in the run on `c3f5c58`. It also passed 10 runs out of 10 alone under `-race`. It is recorded in deferred-items.md as a pre-existing timing flake.
  - **On `939b5ef`, rerun: exit 0 (`GATE PASSED`).** Each of these passed:
    - gofmt, with its positive control;
    - `CGO_ENABLED=1 go test -race -count=1 ./...`: 34 packages ok, with no data race;
    - `go vet`: plain, `e2e`, and `e2e systemdsmoke`;
    - golangci-lint: 0 issues for linux, windows and darwin;
    - capslock: 92/37/23, equal to the baseline;
    - dep-firewall;
    - testonly-firewall, in 6 combinations;
    - check-pinned-actions: 47.
- **CI on `939b5ef`:** E2E run 41021936520 is green on both lanes (9.5p1 and 10.5p1). They include `TestAgentEnrollEndToEnd`, whose audit verify reads a real export through the byte-equal host_forget line. The required checks on the head that carries this section are in the handback.

### UNVERIFIED after this round

- Quorum 2 end to end (D-4), until a 03-16 drill runs it.
- The homelab steps, as above.
- The same-second residual (D-3), by construction.
- The database-error branches listed above. The new `LatestDirectoryVersionTx` error branch (`state_unavailable`) joins them: no test injects a database failure.

## Self-Check: PASSED

- **Files.** `internal/wire/forget.go`, `internal/signer/forget.go`, `internal/audit/forget.go`, `test/vectors/leaf_host_forget_v1.hex` and `test/vectors/forget_request_signing_v1.hex` exist.
- **Commits.** The 12 commits above are ancestors of HEAD (`git rev-list --count 6dea9f3..0edc835` is 12; this file's commit makes 13).
- **Staged paths.** No commit stages `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics/`.
