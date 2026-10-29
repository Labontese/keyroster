---
phase: 03-linux-agent-and-revocation
plan: 08b
subsystem: agent
tags: [agent, forget, removal-confirmation, identity, serverdb, migration, re-enroll]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08: removed_dir_version, the heartbeats table, the served rows of host pending, removalApplied, hostState, rekeyed, the afterAgentLookup hook, host forget --host-gone"
provides:
  - "serverdb 0007_forget.sql: agents.removal_confirmed_version and removal_confirmed_sha256 (raw 32 bytes)"
  - "serverdb: ForgetFacts, Agent.ForgetFacts, DeleteAgentIf (replaces DeleteAgent; re-checks identity, approval, removal and confirmation in one statement), RecordRemovalConfirmed; TouchAgent, MarkAgentApproved and SetAgentRemovedVersion keyed by (id, identity) with ErrNotFound"
  - "server: confirmRemoval, run after a stored heartbeat and by host pending; served rows carry removal_version and removal_confirmed {version, sha256}; forget by identity with the facts re-check (forget_state_changed); the nil-by-default beforeForgetDelete test hook"
  - "serverclient: RemovalConfirmation, ForgetHostRequest {identity_spki_sha256, approved_once, removal_version, removal_confirmed, host_gone}, AdminErrForgetStateChanged"
  - "CLI: keyroster host forget [NAME] [--identity SHA256:...] [--host-gone]; forget_name_ambiguous; the served line host_keys_changed, served until forget; host pending prints each served row's confirmation and forget command"
  - "tests: TestAgentWritesKeyedByIdentity, TestDeleteAgentIf, TestRemovalConfirmation (server and serverdb), TestInFlightRequestOfForgottenAgent, TestForgetHost, the extended TestHostForget and TestHostForgetHostGone, the e2e TestAgentReenrollEndToEnd"
affects: [03-08c, 03-09, 03-16]

actuals:
  tokens: 123709
  tasks: 3
  commits: 6
plan_head_before: 18a30c9b50e9835e2c687c6227d4ccd01a1dc2d7
plan_head_after: 046646f5006159af95394a69fb5b562b1ad6814b

tech-stack:
  added: []
  patterns:
    - "Every agents-row writer names the identity as well as the row ID, and an unchanged row is told apart from a gone one by an existence check"
    - "A delete that an admin's view authorizes re-checks that view in its own WHERE clause (IS ? binds NULL for an absent fact)"

key-files:
  created:
    - internal/serverdb/migrations/0007_forget.sql
    - internal/server/forget_test.go
    - test/e2e/agent_forget_test.go
  modified:
    - internal/serverdb/agents.go
    - internal/serverdb/db_test.go
    - internal/server/agent.go
    - internal/server/hosts.go
    - internal/server/server.go
    - internal/server/agent_test.go
    - internal/server/heartbeat_test.go
    - internal/server/heartbeat_edges_test.go
    - internal/serverclient/agent.go
    - cmd/keyroster/host.go
    - cmd/keyroster/hoststatus.go
    - cmd/keyroster/host_test.go
    - cmd/keyroster/hoststatus_test.go
    - test/e2e/agent_enroll_test.go
    - test/e2e/agent_status_test.go
    - docs/runbooks/host-setup.md

key-decisions:
  - "03-08b owner decision Q1 (2026-10-29): forget's server half ships alone; forget stays one admin's request until 03-08c"
  - "03-08b: forget's name resolution also reads keyroster host status, because host pending never lists an agent the directory approves now; such an agent only makes a name ambiguous and is refused as a target"
  - "03-08b: the confirmation's SHA-256 is trust.SHA256Hex of the directory document without signatures, stored raw (32 bytes) and compared hex-decoded"

patterns-established:
  - "A host-reported fact becomes server state only through a rule over server-held documents (confirmRemoval checks the reported directory against the server's own copy at that version)"

requirements-completed: []

duration: 58min
completed: 2026-10-29
status: complete
---

# Phase 3 Plan 08b: Forget, Server Half Summary

**`keyroster host forget` now names one agent identity, with the facts the admin saw in `keyroster host pending`. The server deletes that agent only while those facts still hold, and the delete statement re-checks them itself. A removal the host confirmed in its own heartbeat is recorded once (migration 0007) and stays confirmed when the name is used again. Every agents-row write names the identity, so a forgotten agent's in-flight request never writes a row that reused its ID. The runbook's re-enroll flow runs end to end in CI.**

PR: **#74** (`p03/08b-forget-quorum`), opened without auto-merge. `requirements-completed` is empty: AGENT-01 and REVOKE-02 have been complete since 03-07, and this plan hardens them.

## Owner attention first

1. **Plan versus code: `forget_name_ambiguous` cannot be computed from `host pending` alone (deviation 1).**
   - `handlePendingHosts` skips every agent the directory approves now.
   - So in the plan's own e2e (B approved under web1), `host pending` lists only A, and `keyroster host forget web1` would resolve to A without the ambiguity refusal the plan requires.
   - The CLI therefore also reads `keyroster host status`, which lists every approved-once agent, active ones included.
   - An agent found only there makes the name ambiguous, and as a target it is refused locally ("remove the host first").
   - RED on the head before the fix: `TestHostForget/name_ambiguous_with_an_approved_agent` exited 0 and sent the forget. Mutant M13 pins it.
   - No server API changed for it.
2. **What the confirmation rests on.** It is the host's word (T-03-284, residual), as the plan flags. A compromised fetcher that reports a removal directory it never applied gets the confirmation recorded. The server checks only that the reported `{V, SHA-256}` is a directory it served, at or above the removal and not above the current version, that names the host nowhere.
3. **Forget is still one admin's request** (T-03-282 accepted here, closed by 03-08c). host-setup.md ends "Removing a host" with exactly the interim sentence 03-08c replaces: `Until plan 03-08c, forget needs no admin quorum and leaves no audit entry.`
4. **capslock: no new pair.** keyroster-signer 92, keyroster-agent 37, keyroster-agent-fetch 23, each equal to its baseline. No Go module was added.

## Accomplishments

- **Carry-over (a), identity-keyed writers.**
  - `TouchAgent`, `MarkAgentApproved`, `SetAgentRemovedVersion` and the new `RecordRemovalConfirmed` write only `WHERE id = ? AND identity_spki_sha256 = ?`. When they change no row, they check that the row still exists, and answer `ErrNotFound` when it does not.
  - `DeleteAgentIf` also names the identity, in its one statement.
  - `requireAgent` answers 403 `unknown_agent` on `ErrNotFound` from any of them, the removal-clearing writes included (they only logged a warning before).
- **Carry-over (b), the recorded confirmation.** `confirmRemoval` runs after a heartbeat is stored and from the stored heartbeat in `host pending`. It records `{V, SHA-256}` once, for an approved-once agent with removal version R and none recorded, when all of these hold:
  - R <= V <= the current version;
  - the SHA-256 is the server's directory document at V without signatures: the current document, or the signer's `GetDirectoryVersion(V).Directory`;
  - `hostState` of directory V, not of the current one, is `removed`.

  Its `UPDATE` holds only while `removed_dir_version = R` and no confirmation is recorded. A signer error is a warning and a skip, and the heartbeat's answer never depends on it.

  In `requireAgent` the re-keyed case (an active entry under the agent's name with other keys) neither records nor clears. Only an entry holding the agent's keys again, active or disabled, clears the removal and the confirmation.
- **Carry-over (c), forget by identity.** The request is `{identity_spki_sha256, approved_once, removal_version, removal_confirmed?, host_gone}`, decoded strictly. It is malformed (400) when it combines:
  - `host_gone` with a confirmation;
  - `approved_once` false with any removal fact or `host_gone`;
  - a confirmation with no removal version, or with a version below the removal version.

  The server's order:
  1. the directory in force (503);
  2. `AgentBySPKI` (404 `host_not_enrolled`);
  3. the facts equal the row (409 `forget_state_changed`);
  4. `hostHolds` (409 `host_in_directory`);
  5. approved once without a confirmation and without `host_gone` (409 `host_removal_not_applied`);
  6. `DeleteAgentIf` (409 `forget_state_changed` on `ErrNotFound`).

  It answers the one deleted row. The log lines keep 03-08's forms, with the identity.
- **CLI.** `keyroster host forget [NAME] [--identity SHA256:...] [--host-gone]`. In order:
  1. it reads host pending and host status;
  2. it picks by identity, or by a name only one agent has, and otherwise refuses `forget_name_ambiguous`, listing each identity, state, confirmation, enrolment time and `--identity` command, and sending nothing;
  3. it refuses `host_removal_not_applied` locally, with the `--identity <id> --host-gone` command;
  4. it drops `--host-gone` with a note for a confirmed or never-approved agent;
  5. it prints the target and sends the facts;
  6. it checks that the answer names exactly the requested identity and name.

  Also:
  - `hostAdminRefusal` explains `forget_state_changed`;
  - `host approve`'s refusal for a served host advises forgetting by identity;
  - the re-keyed label is `host_keys_changed, served until forget`;
  - every served row of `host pending` prints its confirmation line and its forget command.
- **Runbook (D-20).** host-setup.md:
  - "Removing a host" is rewritten: the confirmation, forget by identity, the refusals, and the interim sentence;
  - "Running the agent" gains "Re-enrolling a host" with both orders;
  - the identity-rotation step forgets by identity;
  - the refusal table gains `forget_name_ambiguous` and `forget_state_changed`, and its `host_removal_not_applied` row now names the recorded confirmation.

  Each changed section names CI tests and `UNVERIFIED until 03-16`.

## Task commits

| Commit | Task |
|---|---|
| `c30cb83` feat(agent): record confirmed host removals and forget one agent by identity | Task 1 (tracer): migration 0007, RecordRemovalConfirmed, DeleteAgentIf, confirmRemoval, forget by identity with the facts re-check, the CLI's target and local refusal, e2e step 9 |
| `318aaf1` fix(agent): key agent writes by identity, keep confirmed removals and refuse ambiguous forget names | Task 2: carry-overs (a) and (b) in requireAgent, `forget_name_ambiguous` with host status, the named tests, TestAgentReenrollEndToEnd |
| `7cf030c` docs(agent): document forget by identity, the recorded removal confirmation and the re-enroll orders | Task 3: host-setup.md |
| `8a3b49b` test(agent): pace the forget e2e waits to the admin rate limit | Task 2 fix found in CI (deviation 12) |
| `8c9751c` test(agent): check the identity-keyed writers against a fresh reused row | Task 2: `TestAgentWritesKeyedByIdentity/fresh_row` (M2, M3, M17) |
| `046646f` docs(agent): label the host forget refusals in the enrollment refusal table | Task 3: the label line under the refusal table |
| this file's `docs(03-08b)` commit | SUMMARY, STATE.md, ROADMAP.md |

Every commit is SSH-signed by keyroster-bot and has no attribution lines. Each staged diff was grepped for tailnet and LAN addresses and the real host names before its commit; none were found.

## The tracer in CI (Task 1)

E2E run **40854534343** on `c30cb83`, both lanes green (`--- PASS: TestAgentEnrollEndToEnd`, 7.16 s on 10.5p1 and 10.74 s on 9.5p1). Step 9 on 10.5p1:
- `Forgetting agent SHA256:RUnr…xEI, enrolled as web1: removed, served until forget; removal confirmed at directory v5`;
- the server's line from the real agent's heartbeat: `"msg":"agent removal confirmed",...,"removal_version":5,"directory_version":5,"directory_sha256":"78e146bc…4cea"`. That is the SHA-256 basis of must_haves (plan check item 8), end to end: the agent hashed the document it stored, and the server matched it against its own copy;
- the forgotten agent's fetcher: `<3>keyroster-agent-fetch: ERROR unknown_agent: the server does not know this agent's identity SHA256:RUnr…xEI, ...`.

The 9.5p1 lane shows the same three lines (confirmed at v5).

## The re-enroll flow in CI (Task 2)

- **The first run failed on both lanes.** E2E run **40856754505** on `318aaf1` hit the admin rate limit (deviation 12). Its 10.5p1 lane had already shown A as `host_keys_changed, served until forget` and `removal confirmed at directory v5` after B's approval.
- **E2E run 40858236716 on `8a3b49b` is green on both lanes.**
  - `--- PASS: TestAgentReenrollEndToEnd` took 15.06 s on 10.5p1 and 16.14 s on 9.5p1.
  - `TestAgentEnrollEndToEnd`, `TestAgentStatusEndToEnd` and `TestAgentApplyEndToEnd` pass too.
  - Every e2e test passes; the log has no `--- FAIL`.
- **The flow on 10.5p1:**
  - after the removal, `removal confirmed at directory v5` for A (`SHA256:jPGL…UGc`);
  - after B's approval, `Host web1: host_keys_changed, served until forget (agent identity SHA256:jPGL…UGc)`, still `removal confirmed at directory v5`;
  - `keyroster host forget web1` is refused with `forget_name_ambiguous: 2 agents are enrolled under the name web1, ... Nothing was forgotten:`. It lists A (`host_keys_changed, served until forget; removal confirmed at directory v5; enrolled ...`) and B (`active in the directory (entry web1)`), each with its `keyroster host forget --identity` command;
  - `keyroster host forget --identity SHA256:jPGL…UGc` prints `Forgetting agent ..., enrolled as web1: host_keys_changed, served until forget; removal confirmed at directory v5`, and forgets without `--host-gone`;
  - A's fetcher logs `<3>keyroster-agent-fetch: ERROR unknown_agent: ... SHA256:jPGL…UGc`;
  - `B applied the revocation made after A's forget: KRL v1793270043 -> v1793270058`, and the revoked certificate is refused on B (`sshd: "revoked by file"`).
- **The 9.5p1 lane** shows the same (KRL v1793270046 -> v1793270061).
- **Later commits.** `8c9751c` (a serverdb unit test) and `046646f` (the runbook) came after this run and touch no e2e code. The PR's required e2e lanes run on its head.

## RED evidence and mutants

**RED on Task 1's head `c30cb83`**, with only the tests and the nil-by-default `beforeForgetDelete` hook added. One line of `pre_0007_latest_heartbeat_only` was put back to the old `SetAgentRemovedVersion` signature for the run, then restored:
- `TestInFlightRequestOfForgottenAgent/first_state`: `A's in-flight request: 200 {"bundles":[...]}` and `A's request wrote B's row: approved_at_us 1792411200000000, removed_dir_version 0, last_seen_us 1792411200000000`;
- `TestInFlightRequestOfForgottenAgent/removed`: `200 ...` and `wrote B's row: approved_at_us 0, removed_dir_version 2, last_seen_us 1792411200000000`;
- `TestRemovalConfirmation/confirmed_then_readded_kept`: `removed_dir_version 0, confirmed v0 ; want 2, v2 b58a22b7…1a37`. The re-keyed name cleared the removal and its confirmation;
- `late_heartbeat_reporting_the_removal_confirms`: `removed_dir_version 0, confirmed v0 ; want 2, v2 …`;
- `unconfirmed_then_readded_not_confirmed`: `removed_dir_version 0, confirmed v0 ; want 2, v0`;
- `TestAgentWritesKeyedByIdentity` (serverdb): a compile-error RED, `too many arguments in call to d.MarkAgentApproved`, because the writers had no identity parameter. Its behavioural evidence is M1 to M3;
- `TestHostForget/name_ambiguous_with_an_approved_agent`: `exit 0, sent true`, and `name_ambiguous_refused`: `keyroster host: 2 agents are enrolled under the name web1; name one with --identity` (no `forget_name_ambiguous` and no listing).

`entry_holding_its_keys_again_clears`, `other_sha_not_confirmed`, `signer_unreachable_skips_then_pending_records`, `confirmation_sha_is_the_document_hash`, `pre_0007_latest_heartbeat_only` and the `TestForgetHost` cases passed on Task 1's head: Task 1 had built them. M5 to M11 below prove what they check.

**Mutants (Windows, Go 1.27.3; each applied to the working tree, its named test run, and the file restored and compared byte for byte): 17 run, 17 killed.**

| # | Mutant | Killed by |
|---|---|---|
| M1 | `TouchAgent` without the identity in its WHERE | `TestAgentWritesKeyedByIdentity` |
| M2 | `MarkAgentApproved` without the identity | `TestInFlightRequestOfForgottenAgent`, and `TestAgentWritesKeyedByIdentity/fresh_row` (see below) |
| M3 | `SetAgentRemovedVersion` (record) without the identity | the same |
| M4 | the re-keyed case clears again | `TestRemovalConfirmation/confirmed_then_readded_kept` |
| M5 | the confirmation reads the current directory, not directory V | `TestRemovalConfirmation/late_heartbeat_reporting_the_removal_confirms` |
| M6 | `DeleteAgentIf` matches by (id, identity) only (the fact terms ORed away) | `TestForgetHost/facts_changed_before_delete` |
| M7 | `RecordRemovalConfirmed` without `removed_dir_version = ?` | serverdb `TestRemovalConfirmation/removal_changed_before_record` |
| M8 | no SHA-256 check | `TestRemovalConfirmation/other_sha_not_confirmed`, `TestForgetGateChecksTheDirectory` |
| M9 | host pending records nothing | `signer_unreachable_skips_then_pending_records` |
| M10 | forget skips the facts check | `TestForgetHost/facts_changed_refused` (first a survivor, see deviation 9) |
| M11 | forget lets an unconfirmed approved-once agent go | `TestHostForgetWaitsForRemoval`, `unconfirmed_then_readded_not_confirmed` |
| M12 | the CLI resolves an ambiguous name to its first agent | `TestHostForget/name_ambiguous_*` |
| M13 | the CLI ignores host status | `TestHostForget/name_ambiguous_with_an_approved_agent` |
| M14 | the CLI sends an unconfirmed forget without `--host-gone` | `TestHostForget/not_confirmed_refused_locally` |
| M15 | the CLI accepts an answer for another identity | `TestHostForget/answer_names_another_identity_refused` |
| M16 | an entry holding the keys again does not clear | `TestRemovalConfirmation/entry_holding_its_keys_again_clears` |
| M17 | `SetAgentRemovedVersion` (clear) without the identity | `TestAgentWritesKeyedByIdentity` |

M5 and M6 first broke the build (an unused variable): a build failure is not a kill. They were rewritten (M5 keeps `view` at `dv`; M6 ORs the fact terms away but keeps their parameters), and both were then killed by their tests.

M2 and M3 run against `TestAgentWritesKeyedByIdentity` alone first survived. That test's row B is approved and has a removal, so the conditional writers change nothing even when they match by ID only. Only `TestInFlightRequestOfForgottenAgent` killed them. The subtest `fresh_row` (a B that was never approved and has no removal) was added after the advisor review (`8c9751c`); with it, M1, M2, M3 and M17 are each killed by `TestAgentWritesKeyedByIdentity` alone.

## Grep acceptance

- `grep -c 'removal_confirmed_sha256 IS ?' internal/serverdb/agents.go`: 1. `grep -c "are 03-08b's" internal/server/hosts.go`: 0.
- `identity_spki_sha256 = ?` in agents.go covers:
  - `TouchAgent` (`UPDATE agents SET last_seen_us = ? WHERE id = ? AND identity_spki_sha256 = ?`);
  - `MarkAgentApproved`;
  - `SetAgentRemovedVersion`, both statements;
  - `RecordRemovalConfirmed`;
  - `DeleteAgentIf`;
  - `agentExists`;
  - plus 03-08's `RotateAgentIdentity` and `RecordClockOffset`.
  The lines at `7cf030c`: 246 (`TouchAgent`), 258 (`MarkAgentApproved`), 336 (`DeleteAgentIf`), 363 (`RecordRemovalConfirmed`), 386 (`agentExists`), and 412 and 414 (`SetAgentRemovedVersion`).
  `StoreHeartbeat`'s two inner UPDATEs still name only the ID. They run inside its transaction, after `agentExists` checked the identity (03-08's C1).
- In host.go, `host_keys_changed (re-enroll)`, `forget it (keyroster host forget %s)` and `run keyroster host forget NAME --host-gone` each print 0.
- In host-setup.md (white space squashed):
  - `Plan 03-08b adds both`, `host_keys_changed (re-enroll)`, `To re-enroll it, forget the old agent` and `then forget the agent with` each print 0;
  - the interim sentence occurs once;
  - `forget_name_ambiguous`, `forget_state_changed` and `03-08c` are present.

## What ran and what did not

**Ran:**

- **WSL (Ubuntu, Go 1.27.1):**
  - Task 1's verify on `c30cb83`'s tree: `go test -race` for serverdb, server, serverclient and the CLI, and `go vet -tags e2e`;
  - Task 2's verify (the named `-v -run` set with `-race`, every required `--- PASS` line present);
  - the full gate on `7cf030c`'s tree, exit 0:
    - `CGO_ENABLED=1 go test -race -count=1 ./...`: 34 packages ok, no data race;
    - `go vet ./...`, with `-tags e2e` and with `-tags "e2e systemdsmoke"`;
    - golangci-lint: 0 issues for linux, and also for `GOOS=windows` and `GOOS=darwin`;
    - capslock-check (92/37/23, all equal to the baseline), dep-firewall, testonly-firewall (6 GOOS/tag combinations) and check-pinned-actions (47 pinned uses).
    - The gate's gofmt step was vacuous (deviation 11), so gofmt ran on Windows.
- **Windows (Go 1.27.3):**
  - `go vet ./...`;
  - the serverdb, server, serverclient and CLI tests after each change;
  - `gofmt -l .` (empty);
  - `GOOS=linux go vet -tags e2e` and `-tags "e2e systemdsmoke"` of the e2e package;
  - the 16 mutants.
- **CI:** E2E runs 40854534343 (Task 1, green), 40856754505 (Task 2, red: deviation 12) and 40858236716 (Task 2 after the fix, green), each on both lanes; the PR's required checks (see the handback).

**Not run here:**
- The e2e tests locally: WSL cannot resolve `keyroster.localhost` (deferred-items.md). The CI E2E lanes are the evidence for `TestAgentEnrollEndToEnd` and `TestAgentReenrollEndToEnd`.

**UNVERIFIED:**
- **Every homelab step**, until 03-16, whose forget drill proves them (owner decision Q4):
  - waiting for `removal confirmed at directory v<N>` on a real host;
  - forget by identity;
  - both re-enroll orders. The "same machine, keeping its identity or host keys" order is not run by any test, on CI or a host;
  - the identity-rotation step;
  - `--host-gone`.
- **OpenRC**, unchanged here and UNVERIFIED until 03-16 as in 03-08.
- **The pre-0007 path on a real upgraded database.** `pre_0007_latest_heartbeat_only` stores heartbeats through serverdb directly. No database written by a 03-08 server was migrated by 0007 in a test.

## Decisions Made

See `key-decisions`. Q1 and Q4 are the owner's (2026-10-29); Q2 and Q3 concern 03-08c only.

## Deviations from Plan

1. **[Plan vs code, Rule 1] The name ambiguity needs host status** (Owner attention 1). `runHostForget` also GETs `AdminHostsStatusPath` (`fetchHostsStatus`, factored out of `runHostStatus`). Rows not in host pending become candidates that are never targets. Test `name_ambiguous_with_an_approved_agent` (RED above), `approved_agent_by_identity_refused`, M13.
2. **[Plan detail] One file more than planned: test/e2e/agent_status_test.go.** `enrollApproved` is split into its setup and `joinApproved`, so agent B enrolls under web1 without running `role add ops` a second time.
3. **[Plan detail] Where the serverdb tests live.**
   - `TestAgentWritesKeyedByIdentity` and the new `TestDeleteAgentIf` are in db_test.go.
   - `removal_changed_before_record` is serverdb's `TestRemovalConfirmation/removal_changed_before_record`. The race it covers is inside `RecordRemovalConfirmed`'s conditional UPDATE, and the server has no seam between its snapshot and that write.
   - The plan's server `TestRemovalConfirmation` holds the other eight cases.
4. **[Rule 2] Stricter request checks.** Beyond the plan's two malformed combinations (`host_gone` with a confirmation; `approved_once` false with a removal fact), the server also refuses with 400:
   - `approved_once` false with `host_gone`;
   - a confirmation without a removal version, or below it;
   - an identity that is not 64 lowercase hex digits.
   The CLI never sends any of these: it drops `--host-gone` for a never-approved agent.
5. **[Rule 2] The migration's CHECK.** 0007 adds `CHECK (removal_confirmed_sha256 IS NULL OR length(removal_confirmed_sha256) = 32)`.
6. **[Plan detail] The CLI's local refusals.** `--identity` must be an identity fingerprint (`SHA256:` and 43 base64 characters, decoding to 32 bytes). With NAME and `--identity` both given, both must match. The answer must name the requested identity and name.
7. **[Interpretation] `host_not_enrolled`** now says that no agent has this identity (it was forgotten, or its identity rotated), since the request names an identity rather than a name.
8. **[Test plumbing] The server tests' `e.forget(name)` acts like the CLI:** it reads host pending, which may record a confirmation, then sends the facts of the one row with that name. A name no agent has is sent as an unknown identity (404).
9. **[Test fix] `TestForgetHost/facts_changed_refused`.**
   - Its first edit (`RemovalVersion++`) produced a confirmation below the removal version, which is 400 malformed, not 409; it is now `RemovalVersion--`.
   - M10 (no facts check) first survived, because `DeleteAgentIf` refuses the same requests with the same 409.
   - A case where the gate would answer differently was added: the row is confirmed, and the request carries no confirmation and no `host_gone`. Without the facts check it gets `host_removal_not_applied`; with it, `forget_state_changed`.
10. **[Existing tests, meaning kept]** Which assertions moved where:
    - **`TestHostForgetWaitsForRemoval`:** unchanged assertions; the helper now sends the identity and the facts.
    - **`TestForgetGateChecksTheDirectory`:** its three cases (above the current version, the same number with another SHA-256, an older served version) now test the recording, because forget reads the recorded confirmation.
    - **`TestAgentRemoval/forget_refused_while_in_directory`:** "nosuch" is an unknown identity (404).
    - **`TestHeartbeatAfterForget/row_gone_after_lookup_refused`:** deletes with `DeleteAgentIf` and the row's facts.
    - **`TestRekeyedHostNotRemoved`:** unchanged; a re-key with no earlier removal records nothing, and forget needs `--host-gone`.
    - **`TestServedLine`:** the new label, plus host pending's confirmation and `--identity` lines.
    - **CLI `TestHostForgetHostGone/removal_not_applied_refused`:** now refused locally with nothing sent. The server refusal's text moved to the new `server_refusal_explained`. `host_gone_sent_and_printed` is now `host_gone_sent`.
11. **[Process] The local gate's gofmt step was vacuous.** `wsl.exe` expands `$(gofmt -l .)` in a non-login shell, where gofmt is not on PATH, so the step passed without running. gofmt ran on Windows instead (`gofmt -l .` empty), and CI runs its own. 03-08's local gate was likely affected the same way (not checked).

12. **[Rule 1, found in CI] The re-enroll e2e spent the admin rate limit.**
    - E2E run 40856754505 on `318aaf1` failed `TestAgentReenrollEndToEnd` on both lanes.
    - Its 500 ms `host pending` polls spent the admin limiter's burst (20, then 60 a minute per client address). Then `host approve` (9.5p1) and the ambiguous `host forget` (10.5p1) were refused rate-limited.
    - The 10.5p1 lane had already shown A `host_keys_changed, served until forget` and `removal confirmed at directory v5` after B's approval.
    - The fix, `8a3b49b`: the test's waits poll every 2 s, and each command is retried after a refusal by the limiter (3 s, at most 10 times).
    - Step 9 of `TestAgentEnrollEndToEnd` now waits 2 s between forget attempts and retries a rate-limited one: an attempt now spends three admin requests (host pending, host status, the forget).
    - Production is unchanged. One `keyroster host forget` spends three admin requests, well inside the default 60 a minute.

**Total deviations:** 12: 2 Rule 1, 2 Rule 2, 1 interpretation, 4 plan details, 1 test-plumbing note, 1 test fix and 1 process note. No Go module was added.

## TDD Gate Compliance

Task 2 is `tdd="true"`.
- The tests were written first. The (a) and (b) cases ran RED on Task 1's head (above), and the CLI ambiguity cases ran RED before their fix.
- There is no separate RED commit: Task 2 is one commit. Its RED runs are the evidence above, as in 03-08's fix round.
- `TestAgentWritesKeyedByIdentity`'s RED is a compile error. Its behaviour is pinned by M1, M2, M3 and M17, killed by its `fresh_row` leg and its main loop.

## Issues Encountered

- **Shell heredocs** again turned `\\n` inside Go strings into newlines twice, and Git Bash rewrote a leading `//` in a script argument to `/` (MSYS path conversion), which produced a stray `/` and a `///` in hosts.go. Each was caught by the build or by inspection before any commit and fixed with the Edit tool or `MSYS_NO_PATHCONV=1`.

## Known Stubs

None.

## Threat Flags

None beyond the plan's register. No new route; the forget route's body changed shape (T-03-289), and host forget makes one more admin GET (hosts/status, read-only).

## Open questions for the owner

1. **Deviation 1:** is reading host status in `host forget` acceptable, or should the server's pending answer list the approved agents (a server API change that 03-08c would inherit)?
2. **The "same machine, keeping its identity or host keys" re-enroll order** is documented and UNVERIFIED until 03-16. Should 03-16's forget drill run that order rather than the new-identity one, which CI now covers?

## User Setup Required

None.

## Next Phase Readiness

- **03-08c:** builds on these unchanged:
  - `RecordRemovalConfirmed`;
  - the columns `removal_confirmed_version` and `removal_confirmed_sha256` (raw);
  - `ForgetFacts`, `Agent.ForgetFacts` and `DeleteAgentIf(ctx, id, spki, facts)`;
  - forget's identity addressing;
  - the served rows' `removal_version` and `removal_confirmed {version, sha256}` (hex);
  - the CLI's target resolution, which now includes host status (deviation 1);
  - the hook `beforeForgetDelete` (between the facts check and the delete). 03-08c adds its own hook between the signer's answer and the delete.
- **03-16:** every UNVERIFIED item above (owner decision Q4's forget drill).

## Self-Check: PASSED

- **Files.** `internal/serverdb/migrations/0007_forget.sql`, `internal/server/forget_test.go` and `test/e2e/agent_forget_test.go` exist.
- **Commits.** `c30cb83`, `318aaf1`, `7cf030c`, `8a3b49b`, `8c9751c` and `046646f` are ancestors of HEAD. `git rev-list --count 18a30c9..046646f` is 6, and this file's commit makes 7. Each is SSH-signed (one `BEGIN SSH SIGNATURE` block per commit object), authored by keyroster-bot, and has no attribution lines.
- **Acceptance greps.** As listed under "Grep acceptance".
- **CI.** E2E runs 40854534343 and 40858236716 are green on both lanes.
- **No private address or host name** is in any staged diff (checked before each commit).
