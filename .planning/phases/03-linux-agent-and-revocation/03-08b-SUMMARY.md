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
  - "03-08b fix round 1, owner decision D-R1 (2026-10-29): a removal is confirmed only when the host's own heartbeat shows the apply that committed V emptied its principals, and a later heartbeat that shows principals again clears the confirmation"
  - "03-08b fix round 1, owner decision D-R2 (2026-10-29): host status lists approved agents that have not polled yet (not_yet_polled), so forget's name resolution sees them"
  - "03-08b fix round 1, owner decision D-R3 (2026-10-29): 03-16's forget drill runs the same-machine re-enroll order"
  - "03-08b fix round 1: every agents-row write is keyed on (id, identity, join token hash) through serverdb.AgentKey"

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
  - `ForgetFacts`, `Agent.ForgetFacts` and `DeleteAgentIf` (since fix round 1 `DeleteAgentIf(ctx, k serverdb.AgentKey, facts)`; see "Pre-merge review fix round 1", "For 03-08c");
  - forget's identity addressing;
  - the served rows' `removal_version` and `removal_confirmed {version, sha256}` (hex);
  - the CLI's target resolution, which now includes host status (deviation 1);
  - the hook `beforeForgetDelete` (between the facts check and the delete). 03-08c adds its own hook between the signer's answer and the delete.
- **03-16:** every UNVERIFIED item above (owner decision Q4's forget drill).

## Pre-merge review fix round 1

Review run wf_cd240bdc-2a4 on `4ff905e`. Owner decisions D-R1, D-R2 and D-R3 (Daniel, 2026-10-29) and the no-decision fixes [8], [4] and [6]. Each fix was written test-first and is one commit, SSH-signed by keyroster-bot, without attribution lines; each staged diff was grepped for tailnet and LAN addresses and the real host names (none).

| Commit | Item | Tests |
|---|---|---|
| `da76092` fix(agent): key every agents-row write on the enrolling join token too | [8] (and split [2]) | `TestReenrolledIdentityKeepsItsRow` (server), `TestAgentWritesKeyedByToken` (serverdb) |
| `6fbc083` fix(agent): confirm a host removal only from the host's own emptied apply | D-R1 ([0], [7], [10]) | `TestRemovalConfirmation/{removed_host_reporting_removed_confirmed, report_not_emptied_not_confirmed/*, renamed_then_rekeyed_not_confirmed, principals_again_clears, rendered_entry_without_principals_files_clears, pending_clears_from_the_stored_heartbeat, keys_rotated_without_principals_kept}`; serverdb `TestRemovalConfirmation/{heartbeat_changed_before_record, cleared_only_from_the_stored_heartbeat}` |
| `08da89a` fix(agent): list approved agents that have not polled yet in host status | D-R2 ([3], split [1]) | `TestServedHostsNeverPending/approved_not_yet_polled_in_status`, `TestHostStatus/approved_not_yet_polled`, `TestHostForget/name_ambiguous_with_an_approved_not_polled_agent`, the e2e window in `TestAgentReenrollEndToEnd` |
| `d755686` fix(cli): name the directory entry, not the enrollment name, in host forget | [4] | `TestHostForget/approved_agent_under_another_entry_named` |
| `1d99c61` test(cli): run host forget's host_not_enrolled text, and name the real tests | [6] | `TestHostForget/not_enrolled_explained` |
| `c296d33` docs(03-16): run the same-machine re-enroll order in the forget drill | D-R3 | none (plan text) |

### [8] Writers keyed on the join token

- **Change.** `serverdb.AgentKey {ID, SPKI, TokenSHA256}` and `Agent.Key()`. Every agents-row writer matches `id = ? AND identity_spki_sha256 = ? AND token_hash = ?` (the one constant `agentKeyWhere`):
  - `TouchAgent`, `MarkAgentApproved`, both `SetAgentRemovedVersion` statements, `RecordRemovalConfirmed`;
  - the new `ClearRemovalConfirmed` (D-R1);
  - `agentExists`, which `StoreHeartbeat` checks;
  - `RotateAgentIdentity`, its follow-up existence check included;
  - `RecordClockOffset` and `DeleteAgentIf`.

  `requireAgent`, the heartbeat route, the identity route and forget pass the looked-up row's `Key()`.
- **Why token_hash holds.** A join token enrolls at most one row (`EnrollAgent` uses it in the transaction that records the row). The identity rotation keeps it: the UPDATE in `RotateAgentIdentity` sets only `identity_spki_sha256`, `identity_rotated_at_us` and `identity_rotations`. The agents table was not rebuilt and `foreign_keys` stays off.
- **RED on `4ff905e`** (`TestReenrolledIdentityKeepsItsRow`, written against the old API):
  - `state_request_in_flight`: `A's in-flight request: 200 {"bundles":[...]}, want 403 unknown_agent`; `A's request wrote the new row: approved_at_us 0, removed_dir_version 2, last_seen_us 1792411200000000`; `forget of the new pending row: 400 {"error":"malformed request"}` (the stuck row of the finding);
  - `forget_in_flight`: `the forget checked against A: 200 {"forgotten":[...]}, want 409 forget_state_changed`; `the new row <nil>`.
- **serverdb leg.** `TestAgentWritesKeyedByToken` (same identity, reused row ID, new token; a fresh B, an approved and removed B, a confirmed B). Its RED is a compile error, as in Task 2, so one mutant per writer drops the token term while keeping the bound argument. **9 run, 9 killed:** TouchAgent, MarkAgentApproved, DeleteAgentIf, RecordRemovalConfirmed, agentExists, SetAgentRemovedVersion (clear), SetAgentRemovedVersion (record), RotateAgentIdentity, RecordClockOffset.
- **Plan claims.** must_haves truth 2 and T-03-287 now hold through the token. Their wording in 03-08b-PLAN.md names it. The literal `identity_spki_sha256 = ?` now occurs once in agents.go, in `agentKeyWhere`, which every writer uses.

### D-R1 A removal is confirmed only from the host's own report

- **The rule (`confirmRemoval`, `principalsEmptied`).** The existing checks stay: R <= V <= current, the SHA-256 of directory V, and `hostState(V)` removed. In addition, the stored heartbeat must show all of these:
  - `last_apply` present, result `ok`, no rollback;
  - `host_status` `host_removed` or `host_disabled`;
  - no pending swap;
  - no `principals/` file in `Status.Files`;
  - `files_truncated` false.
- **"The apply that committed V".** The heartbeat carries no version in `last_apply`. The observable used is: an `ok` apply without a rollback, with no swap pending. The applier commits and accepts the generation and its directory only on such an apply, and a later refused or failed apply carries another result (apply/status.go `applyResult`).
- **Invalidation (`reconcileRemoval`, `principalsShown`).** A recorded confirmation (not R) is cleared when a later heartbeat of the same agent shows principals:
  - any `principals/` file;
  - `files_truncated`;
  - an `ok` apply without a rollback whose `host_status` is empty, meaning it rendered an active entry under the host's current keys.

  This runs after a stored heartbeat and, from the stored heartbeat, in `host pending`. The write is `ClearRemovalConfirmed`, keyed by `AgentKey`. It is logged `agent removal confirmation cleared` at warning level.
- **Interpretation for the owner (see Owner attention below).** `host_keys_rotated`/`host_keys_disagree` without a principals file, and refused or failed applies, do **not** clear.
- **[Rule 2] The stored heartbeat's seq guards both writes.** `RecordRemovalConfirmed(ctx, k, hbSeq, R, V, sha)` and `ClearRemovalConfirmed(ctx, k, hbSeq)` hold only while the stored heartbeat still has the seq the decision was made from (`storedSeqIs`).
  - Without the guard, this race is possible: `host pending` reads an emptied heartbeat S, heartbeat S+1 with principals is stored and finds nothing to clear, and then `host pending` records the confirmation from S.
  - Those facts would reach the admin and pass `sameFacts` and `DeleteAgentIf`.
- **RED on `da76092`** (the new tests, against the old rule):
  - all ten `report_not_emptied_not_confirmed/*` cases (`principals_rendered` = finding 10, `host_status_empty`, `keys_rotated`, `keys_disagree`, `principals_file`, `files_truncated`, `apply_refused`, `apply_rolled_back`, `no_last_apply`, `swap_pending`): `removed_dir_version 2, confirmed v2 <sha>; want 2, v0`;
  - `renamed_then_rekeyed_not_confirmed` (finding 7): `removed_dir_version 3, confirmed v3 947b48…1a25; want 3, v0`;
  - `principals_again_clears` (finding 0): `removed_dir_version 2, confirmed v2 b57729…8c59; want 2, v0`;
  - `keys_rotated_without_principals_kept`: its first half passed (kept), and its second half failed (`confirmed v2 …; want 2, v0`), because nothing cleared.
- **Fixtures.** `testHBStatus` lists `principals/deploy` with an empty `host_status`. Left unchanged, every "not confirmed because X" test would pass without testing X. A helper `hbRemovedAt` (with `asEmptied`) builds the emptied report, and these tests use it:
  - every test that expects a confirmation;
  - `other_sha`, `version_above_current`, `same_number_other_sha` and the older-version tests;
  - `pre_0007_*`, `unconfirmed_then_readded` and `late_heartbeat`;
  - the disabled-first case (`host_disabled`).

  `unconfirmed_then_readded_not_confirmed` deliberately sends an emptied report at the re-adding version. It pins the server's own `hostState(V)` check, which the host's report does not replace.
- **Mutants (Windows, Go 1.27.3; each applied, its tests run, the file restored and compared): 16 run, 16 killed.**

  | # | Mutant | Killed by |
  |---|---|---|
  | D1 | `principalsEmptied` ignores the host status | `report_not_emptied_not_confirmed/keys_rotated`, `/keys_disagree`, … |
  | D2 | `confirmRemoval` skips `principalsEmptied` | `report_not_emptied_not_confirmed/*` |
  | D3 | `principalsShown` ignores the file list | `report_not_emptied_not_confirmed/principals_file`, `keys_rotated_without_principals_kept` |
  | D4 | `principalsShown` ignores an active render | `rendered_entry_without_principals_files_clears` |
  | D5 | `principalsShown` ignores `files_truncated` | `report_not_emptied_not_confirmed/files_truncated` |
  | D6 | the pending-swap condition dropped | `report_not_emptied_not_confirmed/swap_pending` |
  | D7 | a rollback counts as ok | `report_not_emptied_not_confirmed/apply_rolled_back` |
  | D8 | reconcile never clears | `principals_again_clears`, `pending_clears_from_the_stored_heartbeat`, … |
  | D9 | host pending only records (the old condition) | `pending_clears_from_the_stored_heartbeat` |
  | D10 | the heartbeat route does not reconcile | `confirmed_then_readded_kept`, `late_heartbeat_…`, … |
  | D11 | `RecordRemovalConfirmed` without the stored-seq term | serverdb `heartbeat_changed_before_record` |
  | D12 | `ClearRemovalConfirmed` without the stored-seq term | serverdb `cleared_only_from_the_stored_heartbeat` |
  | M5 | (again, new fixtures) the current directory instead of V | `late_heartbeat_reporting_the_removal_confirms` |
  | M7 | (again) without `removed_dir_version = ?` | serverdb `removal_changed_before_record` |
  | M8 | (again) no SHA-256 check | `other_sha_not_confirmed`, `TestForgetGateChecksTheDirectory/same_number_other_sha_refused` |

  D3 first broke the build (an unused import) and was rewritten to `false && …`. M11 (forget lets an unconfirmed approved-once agent go) was not re-run: its gate code is unchanged.
- **CI evidence of the reading.** E2E run **40938179992** on `6fbc083`, both lanes green. On both lanes, after B's approval A reports `directory v6, last apply ok, host_status "host_keys_rotated", 2 files` (the test now waits for this before it checks) and stays `removal confirmed at directory v5`. `forget --identity A` succeeds without `--host-gone`. The literal reading of D-R1 would have cleared A there. The normal path is confirmed from the real agent's heartbeat in `TestAgentEnrollEndToEnd` (`agent removal confirmed`, v5, both lanes).
- **Docs.**
  - host-setup.md: the "keeps the last good principals" claim is corrected. A host whose current keys are on an active entry renders it normally, and `host_keys_rotated` keeps last-good's files.
  - host-setup.md: step 2 of "Removing a host" now states the rule, the clear and the T-03-284 residual (a lying fetcher gets a confirmation recorded).
  - 03-08b-PLAN.md: truth 3 and the T-03-288 row describe the new rule, and the row names the residual.
  - The comments in migration 0007, requireAgent and confirmRemoval are updated; no migration checksum exists.

### D-R2 Approved but not yet polled agents in host status

- **Server.** `hosts/status` also lists an agent the current directory approves (`approved(dv, keys)`) whose `approved_at_us` is unset. Such a row carries `not_yet_polled: true` (`omitempty`, so the other rows encode as before), state `active`, and no heartbeat. `host pending` is unchanged.
- **CLI.**
  - `checkHostsStatus` refuses a `not_yet_polled` row that is not active or that carries a heartbeat.
  - `host status` shows it as `approved, not yet polled`.
  - `host forget`'s candidates include it, so its name is refused `forget_name_ambiguous`, with the listing line `approved, not yet polled (enrolled as …, directory entry …)`.
- **RED on `6fbc083`** (the JSON field added first, so the RED is behavioural):
  - `hosts/status of an approved agent that has not polled: []`;
  - CLI `host status`: no `approved, not yet polled` (exit 0, the row shown as active);
  - CLI forget: refused ambiguous, but without the `approved, not yet polled` state.
- **e2e window.** `joinApprovedHeld` stops B's fetcher before `host approve` and starts it again after the check. In that window, `keyroster host forget web1` must be refused `forget_name_ambiguous`, naming A's `--identity` and `approved, not yet polled`. E2E run **40941045281** on `c296d33` shows it on both lanes, for example on 10.5p1: `keyroster host forget web1 before B polled (refused):` with `agent SHA256:ocgA…I3Q: approved, not yet polled (enrolled as web1, directory entry web1)`. After B's first poll, the existing ambiguity step and the forget by identity pass as before (`--- PASS: TestAgentReenrollEndToEnd`, 19.01 s on 10.5p1 and 17.16 s on 9.5p1).
- **Compatibility.** The CLI decodes admin answers strictly (`DisallowUnknownFields`). A CLI older than this server refuses a hosts/status answer that holds such a row. Server and CLI ship together (unreleased); 03-08c inherits the field.

### [4] The directory entry name in host forget

- **Change.** Candidates from host status keep `HostStatusRow.Name` (the entry holding the agent's keys) as `EntryName`, next to the enrollment name.
- **Output.** The listing reads `(enrolled as web1, directory entry db1)`, and the refusal names `keyroster host remove db1`.
- **RED on `08da89a`:** `the directory approves agent SHA256:IiIi… now (host entry web1): remove the host first (keyroster host remove)…`.

### [6] host_not_enrolled and the runbook's test claim

- **Test.** `TestHostForget/not_enrolled_explained` answers 404 `host_not_enrolled` and checks the CLI's text.
- **Coverage only.** The mapping already existed, so there is no behavioural RED. The mutant that drops the mapping case was killed by the new test.
- **Runbook.** host-setup.md now names, per refusal, the server test and the CLI test that run it. `host_in_directory` and `host_not_enrolled` run in `TestAgentRemoval` on the server, and the CLI mappings run in `TestHostForget`/`TestHostForgetHostGone`.

### D-R3 The 03-16 forget drill runs the same-machine order

03-16-PLAN.md:
- **The drill.** The forget drill's re-enrollment runs host-setup.md's same-machine order, keeping both `identity.key` and the sshd host keys. It records that the agent came back with the same identity and host keys and stayed pending (fetcher `not_approved`) until `host approve`. The `forget` line gains `same_identity=`, `same_host_keys=` and `pending_until_approved=`, and its acceptance requires all three to be yes.
- **Labels.** The runbook keeps that order UNVERIFIED until the drill runs.

### Refuted, no action

- The forget checks `host_in_directory` against a directory read before the delete: 03-08c moves the decision into the signer.
- The forget request carries neither the name nor the enrolment time: the token in `DeleteAgentIf` binds the enrollment.

### Owner attention

1. **D-R1's invalidation is implemented on what is in force, not on the literal host_status rule.**
   - **The literal text.** "A host_status other than removed/disabled" would clear a confirmation on `host_keys_rotated`. That is exactly what the confirmed old agent of the re-enroll flow reports once the new agent is approved under its name (last-good principals kept, and none after the applied removal; CI shows `host_keys_rotated, 2 files`). The literal rule would make step 5 of `TestAgentReenrollEndToEnd` need `--host-gone` and break must_haves truth 3.
   - **What was implemented.** A clear happens on a `principals/` file, a truncated file list, or an `ok` apply that rendered an active entry (empty `host_status`). That covers finding 0. It does not clear on `host_keys_rotated`/`host_keys_disagree` without a principals file, nor on a refused or failed apply, which changes no file.
   - **For the owner.** Please confirm this reading, or decide that the literal rule applies and the re-enroll flow then needs `--host-gone`.
2. **[Rule 2] The seq guard on the confirmation writes** (above) is an addition that D-R1's invalidation needs to be race-free. It changes `RecordRemovalConfirmed`'s signature.

### For 03-08c (reconcile in its plan)

- **serverdb signatures.** Every writer now takes a `serverdb.AgentKey` (`a.Key()`) instead of `(id, spki)`:
  - `DeleteAgentIf(ctx, k, facts)`;
  - `RecordRemovalConfirmed(ctx, k, hbSeq, removedVersion, version, sha)`;
  - the new `ClearRemovalConfirmed(ctx, k, hbSeq)`.

  The function names are unchanged, so 03-08c's precondition grep `func (d *DB) DeleteAgentIf(` still matches. Its relay must delete with the key of the row it read.
- **A confirmation is no longer monotonic.** It can be cleared between the admins' signatures and the delete, when the host shows principals again. `DeleteAgentIf` then refuses, and 03-08c's `forget_logged_not_deleted` (fail-safe) becomes more reachable than its plan assumes.
- **The forget request's JSON and `ForgetFacts` are unchanged**, as are the served rows' `removal_version` and `removal_confirmed`.
- **Host status rows can carry `not_yet_polled`**, and forget's target resolution includes them. Candidates from host status carry the entry name separately from the enrollment name. 03-08c-PLAN.md:269 "keeps 03-08b's target resolution" inherits both.

### What ran

- **WSL (Ubuntu, Go 1.27.3), on `c296d33`'s tree:** the full gate, exit 0.
  - gofmt was called by absolute path (`$(go env GOROOT)/bin/gofmt`) inside a script, with a positive control: a misformatted file in a temporary directory had to be listed, and was. `gofmt -l .` was then empty. This fixes deviation 11's vacuous step.
  - `CGO_ENABLED=1 go test -race -count=1 ./...`: every package ok.
  - `go vet ./...`, with `-tags e2e` and with `-tags "e2e systemdsmoke"`.
  - golangci-lint: 0 issues for linux, windows and darwin.
  - capslock-check (92/37/23, equal to the baseline), dep-firewall, testonly-firewall (6 combinations) and check-pinned-actions (47).
- **Windows (Go 1.27.3):** the package tests after each change, the mutants, and `GOOS=linux go vet -tags e2e` of the e2e package.
- **CI:**
  - E2E run 40938179992 (dispatched) on `6fbc083`: both lanes green, no `--- FAIL`.
  - Every workflow of the PR on `c296d33` is green: CI 40941045279, E2E 40941045281 (both lanes; `TestAgentEnrollEndToEnd`, `TestAgentReenrollEndToEnd` and `TestAgentStatusEndToEnd` pass, no `--- FAIL`), E2E distro 40941045296, E2E TPM 40941045287, E2E PKCS#11 40941045292, Systemd 40941045288, PIV 40941045290, CodeQL 40941045300, PR title 40941045294, Workflow lint 40941045280.
  - This file's docs commit reruns them; the handback names the final head.

**Not run, and UNVERIFIED:**
- the e2e tests locally (WSL cannot resolve `keyroster.localhost`);
- every homelab step, until 03-16, the same-machine re-enroll order included (D-R3).

### Self-check (fix round 1): PASSED

- **Commits.** `da76092`, `6fbc083`, `08da89a`, `d755686`, `1d99c61` and `c296d33` are ancestors of HEAD. Each is SSH-signed by keyroster-bot and has no attribution lines.
- **Staged paths.** No commit stages `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics/`.
- **Original metrics.** The `actuals` above are the original plan's and are left as they were.

## Pre-merge review fix round 2

Review run wf_9baec2a4-cb1 (Claude only) at `bf746b5` against base `4ff905e`. Owner decisions (Daniel, 2026-10-29): fix round 2 now, and D-R1's clearing rule as round 1 implemented it is approved. Each fix was written test-first and is one commit, SSH-signed by keyroster-bot, without attribution lines; each staged diff was grepped for tailnet and LAN addresses and the real host names (none). Evidence (RED output, mutants, gate log) is kept outside the repo.

| Commit | Item | Tests |
|---|---|---|
| `0fe5b8e` fix(agent): report the committed generation's host status in every apply | Fix 1 (medium, regression from `6fbc083`) | `TestStatusHostStatus/*` (agent, Linux); `TestRemovalConfirmation/{noop_apply_after_restart_kept, restart_before_the_removal_heartbeat_confirms, keys_rotated_noop_apply_kept}` (server guards); the restart step 2b in `TestAgentReenrollEndToEnd` |
| `8f57e4e` fix(server): read agents and heartbeats in one transaction for host status | Fix 2 (low, from `08da89a`) | serverdb `TestAgentsAndHeartbeatsOneRead` |
| `b1eefc0` fix(server): clear a removal confirmation while a swap is pending | Fix 3 (hardening) | `TestRemovalConfirmation/{pending_swap_clears_then_commit_confirms_again, pending_swap_clears_keys_rotated_for_good}` |

### D-R1 refinement, owner-approved

A recorded confirmation is cleared only on a `principals/` file, `files_truncated`, or an `ok` apply with an empty `host_status`. With Fix 3, a pending swap now counts as a fourth case, because it "cannot tell". The confirmation is **not** cleared on `host_keys_rotated` or `host_keys_disagree` without a `principals/` file. This is the owner-approved refinement of D-R1 (2026-10-29). The plan's truth 3 and threat row T-03-288 stay as round 1 wrote them.

### Fix 1: a no-op apply cleared the confirmation

- **The bug.** `Report.HostStatus` was set only in `render()`'s `RenderFallback` branch, and `buildStatus` copied it into `last_apply.host_status`. A no-op apply returns from `forward()` before `render()`, but it still writes `StatusUpdate{Applied: true}`. A no-op is the first round after a restart, a reboot or an upgrade. It therefore reported `{ok, ""}` for a host whose committed generation was rendered `host_removed`. `principalsShown` reads ok with an empty status as an active entry rendered again, so it cleared the confirmation. `principalsEmptied` needs `host_removed`/`host_disabled`, so the confirmation was never made again, and forget answered `host_removal_not_applied`. The same held for variant (a), a restart before the server stored the `host_removed` heartbeat, which never confirmed. It also held for variant (b): the re-enroll flow's old agent, confirmed and reporting `host_keys_rotated`, lost its confirmation.
- **Approach chosen: persist the status with the generation.** `Generation.HostStatus` and `genRecord.HostStatus` (`host_status`, `omitempty`) hold the status a generation was rendered with. `render()` sets it from `RenderFallback`, and a normal `Render` leaves it `""`. `installGeneration` writes it into the record. `buildStatus` reports the committed generation's status: current, or the marker's `from` during a swap, read from the record it already reads for the file list. The run's report is not used. The alternative, carrying the previous `last_apply.host_status` forward, was rejected for four reasons:
  - it is lost when `heartbeat.json` is reset;
  - after a rollback it names the failed render, not what is in force;
  - "the committed generation is unchanged" does not line up across rollback and recovery, which change the generation number;
  - it needs a separate "rendered" flag, so that a real render to `""` still overwrites.
- **A real render always overwrites.**
  - When a render's files equal the generation in force (the `sameBytes` commit in `forward()`, for example a removed entry listed again under other keys: `host_keys_rotated` with last-good's principals, which are none), `setHostStatus` rewrites that generation's record before the commit. `spool.WriteFileAt` writes the whole record or leaves the old one, never a torn one.
  - The status difference does **not** force a new generation, because that would run `Transition` and publish a pending status, which Fix 3 clears on.
  - A re-added entry's render writes `""` (tested).
- **Rollback and recovery carry last-good's status.**
  - `RollbackTarget` copies `lg.HostStatus`.
  - `backToLastGood` and `recoverToLastGood` load it from last-good's record next to `Host`.
  - `rollbackTarget`'s in-place branch (current already holds the rollback content) rewrites current's record to last-good's status.
  - `Intermediate` is unchanged: its status is never reported (`buildStatus` uses `m.From`), and the mutant that would carry it survived, so the change was removed (no unexercised paths).
- **RED on `bf746b5`** (`TestStatusHostStatus`, Linux, WSL):
  - `host_removed_kept_by_a_noop_apply`: `after a no-op apply: host_status "", want "host_removed" (the committed generation's)`;
  - the same for `host_disabled` and `host_keys_rotated`;
  - `same_files_rendered_under_another_status`: `after a no-op apply: host_status "", want "host_keys_rotated"`;
  - `rollback_reports_last_good_status`: `last_apply … Result:rolled_back … HostStatus:}; want rolled_back with "host_removed"`.

  `rollback_in_place_reports_last_good_status` and `recover_to_last_good_reports_last_good_status` were added after the fix, to pin those two branches. Their mutants are below.
- **Mutants (WSL, a copy of the tree per mutant): 9 run. 7 were killed by a test; m1 was a build failure, whose behaviour the RED above shows; m9 survived, and its change was removed.**

  | # | Mutant | Killed by |
  |---|---|---|
  | m2 | `render()` does not keep the fallback status in the generation | every `*_kept_by_a_noop_apply`, `same_files…`, `rollback_reports…` |
  | m3 | the `sameBytes` commit keeps the old record status | `same_files_rendered_under_another_status` (`"host_removed", want "host_keys_rotated"`) |
  | m4 | `RollbackTarget` drops last-good's status | `rollback_reports_last_good_status` |
  | m5 | `backToLastGood` does not load last-good's status | `rollback_reports_last_good_status` |
  | m6 | the in-place rollback keeps the failed render's status | `rollback_in_place_reports_last_good_status` (`HostStatus:host_keys_rotated`) |
  | m7 | `installGeneration` does not persist the status | every `*_kept_by_a_noop_apply`, `rollback_reports…` |
  | m8 | `recoverToLastGood` does not load last-good's status | `recover_to_last_good_reports_last_good_status` |
  | m1 | `buildStatus` reports the run's status (the pre-fix code) | a build failure (an unused variable); the RED above is that behaviour |
  | m9 | `Intermediate` does not carry the target's status | **survived**; the change was removed |
- **Server.** `principalsShown` and `principalsEmptied` keep their semantics. The three new server tests are **regression guards, not RED**, because the server code did not change:
  - a confirmed host followed by a no-op heartbeat that names `host_removed` stays confirmed, while the pre-fix shape (`host_status ""`) still clears, so the agent fix is what keeps it;
  - variant (a) confirms on the no-op heartbeat;
  - variant (b) stays confirmed through `host_keys_rotated` no-ops, and forget succeeds.
- **e2e.** `TestAgentReenrollEndToEnd` step 2b restarts agent A's `keyroster-agent run` once its removal is confirmed (new `enrolledHost.startRun`/`restartRun`; the run's cmd is kept). It waits until host status shows a `last_apply.at` from after the restart, then requires `ok` with `host_status host_removed`. `host pending` must still show `removal confirmed at directory v<N>`. Step 5's forget without `--host-gone` then covers the rest. It runs only in CI (see What ran).
- **Downgrade note.** `readRecord` decodes strictly (`DisallowUnknownFields`). An older agent binary that reads a record with `host_status` treats the link as foreign, and is then `pending_state_unknown` until `--recover-to-last-good`. `Host` set the same precedent in PR #67. Nothing is released. Records written before this fix carry no `host_status`, though. On a host whose removal an older build committed, the first no-op apply after the upgrade still reports `""`, which clears the confirmation. It is not lost for good (corrected in 03-08c): any later real render installs a new generation rendered `host_removed`, and the next heartbeat confirms again. The signer republishes the KRL at least hourly (D-10), and a new KRL is such a render, so this takes at most about an hour. Until then the host's forget is refused `host_removal_not_applied`, and `--host-gone` overrides it. This matters only for a development build already running, for example on the homelab before 03-16.
- **Not changed.** The `sameBytes` path keeps the record's `Host` as before, and only the status is rewritten. `pollSpool`'s `sameBytes(g, target)` keeps the target, and so its status, for a superseding capture with the same files. The commit then stores the older verified state, and the next apply renders the newer one and rewrites the status through `forward()`.

### Fix 2: not_yet_polled with a heartbeat

- **Coverage.** `approved_at_us` is only ever set where it is NULL (`MarkAgentApproved`) and never reset while a heartbeat row survives, so the race was the only way to get a `not_yet_polled` row with a heartbeat. The `!hasHB` rule is not needed in addition.
- **Change.** `serverdb.AgentsAndHeartbeats` reads `listAgents` and `heartbeats` (now queryer helpers, with `Heartbeats` a wrapper) in one transaction, and `handleHostsStatus` uses it. With `SetMaxOpenConns(1)` and `_txlock=immediate`, a request that marks the agent approved and stores its heartbeat waits until the read ends. It is therefore seen whole or not at all. A heartbeat is also never paired with another agent's row under a reused ID.
- **Why one transaction rather than the `!hasHB` rule.** serverdb supports it cleanly, and `PendingState` with its `afterPendingInvite` hook is the precedent for both the code and the test. The transaction holds the only connection, so nothing inside it may use `d.db`; the method is self-contained in serverdb. `host pending` keeps its two reads, because its writes are guarded by the stored seq and the spec names host status only.
- **RED (mutant reproducing the pre-fix two auto-commit reads, with the hook between them):** `read during the request: approved_at_us 0, heartbeat stored true; want approved and a heartbeat both false`, which is exactly the row the CLI refused. After the fix the request waits for the connection (`WaitCount` rises), the read sees the agent before it, and a second read sees both.

### Fix 3: a pending swap counts as "cannot tell"

- **Change.** `principalsShown` returns true when `st.Pending != nil`, as for `files_truncated`. It therefore never confirms, and it clears a recorded confirmation. `principalsEmptied`'s own `Pending == nil` check is now implied, and was dropped. The clear's log line reads `… its host reports principals again, or a swap whose outcome it cannot tell yet`. host-setup.md (Removing a host, step 2, and the re-enroll paragraph) states it.
- **RED on `8f57e4e`:** `pending_swap_clears_then_commit_confirms_again` and `pending_swap_clears_keys_rotated_for_good` both failed with `confirmed v2 <sha>; want 2, v0`.
- **The normal flow.** Every `Transition` publishes a pending status (`publishPending`), but the server only sees it if the fetcher posts during the window. For a removed or disabled host, the commit's status names `host_removed` again (Fix 1), and the next heartbeat confirms again (tested). `TestAgentEnrollEndToEnd`'s forget already retries on `host_removal_not_applied`. In `TestAgentReenrollEndToEnd`, A's apply of B's directory is a `sameBytes` commit without a `Transition`, so it publishes no pending status.

### Carried to 03-08c (not fixed here)

- **The CLI GET/POST race.** Between the CLI's GET and its POST, a pending agent A can be forgotten and the same identity re-enrolled, pending, with identical facts. The forget then deletes the new pending row, which costs one re-enrollment. To close it, carry `enrolled_at` or a row nonce in `ForgetHostRequest`, which 03-08c's relay may want anyway.
- **StoreHeartbeat's by-ID writes.** The `clock_offset_s`, `seq_regressed_at_us` and heartbeats upsert writes are safe only because they share the transaction with `agentExists(k)`. Keying them on `AgentKey` would make that safety local.

### Owner attention (fix round 2)

1. **Fix 3 and variant (b).** A confirmed old agent of the re-enroll flow reports `host_keys_rotated`. If it goes through a swap, for example any KRL update between the new agent's approval and the forget, and the server happens to receive the pending status, its confirmation is cleared. `host_keys_rotated` never confirms again (the approved rule), so its forget then needs `--host-gone`. This fails safe and follows the spec as written. It is now stated in the runbook and pinned by `pending_swap_clears_keys_rotated_for_good`. A narrower alternative, if this is unwanted: refuse forget while the stored heartbeat shows a swap pending, instead of clearing the confirmation.

### What ran (fix round 2)

- **WSL (Ubuntu, Go 1.27.3), on a copy of `b1eefc0`'s tree:** the full gate, exit 0 (`GATE PASSED`).
  - gofmt by absolute path with the positive control (the misformatted control file was listed), then `gofmt -l .` empty;
  - `CGO_ENABLED=1 go test -race -count=1 ./...`: every package ok;
  - `go vet ./...`, with `-tags e2e` and with `-tags "e2e systemdsmoke"`;
  - golangci-lint: 0 issues for linux, windows and darwin;
  - capslock-check (92/37/23, equal to the baseline), dep-firewall, testonly-firewall (6 combinations), check-pinned-actions (47).

  The gate's first run failed once in `internal/signer` `TestSignerConcurrency/sixteen_clients` (`clock_regression` under `-race`). Nothing under internal/signer changed. It passed on a five-run rerun and on the second full run, and is recorded in deferred-items.md next to Phase 2's flake of the same class.
- **WSL:** the RED runs and the Fix 1 mutants (`TestStatusHostStatus` is Linux-tagged), each on a fresh copy of the tree.
- **Windows (Go 1.27.3):** the server, serverdb and CLI package tests after each change, the Fix 2 and Fix 3 RED runs, and `GOOS=linux go vet -tags e2e` of the e2e package.
- **CI on `b1eefc0`:** every required check of PR #74 green (`gh pr checks 74 --required`), among them CI 40957298555 (build-test, lint, fuzz, cli-windows, cli-macos, capslock, govulncheck, dependency-firewall) and E2E 40957298730, both lanes. In E2E, `TestAgentReenrollEndToEnd` passed on 10.5p1 (25.07 s) and 9.5p1 (22.27 s), and step 2b logged `keyroster host pending after A's restart:` with `removal confirmed at directory v5` on both. The other runs were E2E distro 40957298608, E2E TPM 40957298749, E2E PKCS#11 40957298625, Systemd 40957298697, PIV 40957298643, CodeQL 40957298719, PR title 40957298678 and pinned actions 40957298582.
- This file's docs commit reruns them; the handback names the final head.

**Not run, and UNVERIFIED:**
- the e2e tests locally (WSL cannot resolve `keyroster.localhost`);
- step 2b's restart check against the pre-fix agent: it was not run in CI on a pre-fix tree, so its RED is inferred from the unit RED, not observed;
- every homelab step, until 03-16.

### Self-check (fix round 2): PASSED

- **Commits.** `0fe5b8e`, `8f57e4e` and `b1eefc0` are ancestors of HEAD. Each carries an SSH signature by keyroster-bot and has no attribution lines. `git rev-list --count bf746b5..b1eefc0` is 3, and this file's commit makes 4.
- **Staged paths.** No commit stages `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics/`. The staged diffs hold no tailnet or LAN address and no real host name.
- **Carried items.** The two items under "Carried to 03-08c" are listed and not fixed.
- **Original metrics.** The `actuals` above are the original plan's and are left as they were.

## Self-Check: PASSED

- **Files.** `internal/serverdb/migrations/0007_forget.sql`, `internal/server/forget_test.go` and `test/e2e/agent_forget_test.go` exist.
- **Commits.** `c30cb83`, `318aaf1`, `7cf030c`, `8a3b49b`, `8c9751c` and `046646f` are ancestors of HEAD. `git rev-list --count 18a30c9..046646f` is 6, and this file's commit makes 7. Each is SSH-signed (one `BEGIN SSH SIGNATURE` block per commit object), authored by keyroster-bot, and has no attribution lines.
- **Acceptance greps.** As listed under "Grep acceptance".
- **CI.** E2E runs 40854534343 and 40858236716 are green on both lanes.
- **No private address or host name** is in any staged diff (checked before each commit).
