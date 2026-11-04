---
phase: 03-linux-agent-and-revocation
plan: 08g
subsystem: server
tags: [server, signer, budget, capacity, agent, directory, krl, f11, f12, f13]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-07 (bundleItems, directoryItems, requireAgent and its token bucket), 03-08b (reconcileRemoval and confirmRemoval on the heartbeat path), 03-08c (ForgetAgent in signerAPI), PR #69 review F4 (the served floor follows the disk); 03-08d to 03-08f, 03-08j and 03-08k touch none of this plan's files"
provides:
  - "server: maxSignerCalls (12), maxAgentCalls (6), budgetSigner (named next field, agent token before total token, GetKRL exempt), budgeted and withSignerBudget; newServer wraps every signer"
  - "server: maxAgentInFlight (2), agentSlot, inFlightMu and agentInFlight; the state and heartbeat routes take the slot after requireAgent"
  - "server: dirFetch, dirKey, dirMirror.pending (one pending fetch per SHA-256 and version; first a single inflight pointer, changed in pre-merge review fix round 1), directoryUnder and fetchDirectory; currentDirectory shares one detached fetch per Status SHA-256 and version"
  - "server: servedKRL.durable; keepKRL's equal-version shortcut only for a durable copy; the copy read at start is not durable, so every start rewrites it once before it is served (pre-merge review fix round 1, owner follow-up)"
  - "the growth rule in signerAPI's and budgetSigner's comments: new methods go through budgetSigner, agent-relayed calls take the agent share, agent routes that relay take agentSlot"
  - "tests: TestSignerBudget (5 cases; total_bounded has 8 method rows and catch_up_bounded_interactive_room 6 since pre-merge review fix round 1), TestKRLDuringFullBudget (2), TestAgentInFlight (5), TestDirectoryMirrorFill (7), TestKRLServedCopy (4 new cases: dir_sync_failure_never_served, copy_read_at_start_rewritten_once, copy_read_at_start_served_after_write, restart_after_dir_sync_failure)"
  - "docs: server-install.md, the durable KRL copy, the signer-call budget and the per-host requests in flight"
  - "planning: the agent-share sentence in 03-09 (HostIssue, hostcert) and 03-10 (ProbeIssue, probecert); 03-08g at wave 18, 03-09 to 03-16 one wave later"
affects: [03-08h, 03-09, 03-10]

requirements-completed: []

actuals:
  tokens: 23400
  tasks: 4
  commits: 5
plan_head_before: 741e2f6b99bb8acc642ce46617bbbf4a22706add
plan_head_after: 0a0913d7c69aaab987521bde550200237d381cc1

tech-stack:
  added: []
  patterns:
    - "A signerAPI wrapper with a named (never embedded) next field, so a new signer method does not build until it is budgeted"
    - "Two token channels, agent share first, so queued agent calls hold no total token"
    - "currentStatus's coalescing copied to the directory mirror: a detached fetch per SHA-256 and version Status reported, pending side by side, stored only when its key is that of the Status the server holds when it ends"
    - "A durable flag instead of a second fsync: only a full write that synced lets the shortcut skip the write, so the copy read at start is rewritten once per start"

key-files:
  created:
    - internal/server/capacity_test.go
    - .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md
  modified:
    - internal/server/signer.go
    - internal/server/server.go
    - internal/server/agent.go
    - internal/server/directory.go
    - internal/server/revoke.go
    - internal/server/revoke_test.go
    - docs/runbooks/server-install.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (and the wave lines of 03-10 to 03-16)
    - .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md

key-decisions:
  - "F11: the server's signer budget is a wrapper that newServer installs around whatever signer it gets, so every fakeSigner test runs through it; the share is chosen by method (GetBundle, GetDirectoryVersion), so the heartbeat and admin pending-hosts callers of GetDirectoryVersion take it too"
  - "F11: an agent call takes its agent token before its total token, and gives the agent token back when its ctx ends at the total wait; GetKRL alone skips the budget (no signer lock, coalesced to one call), so the server holds at most 13 signer calls"
  - "F11: one per-agent in-flight count (cap 2) across the state and heartbeat routes, keyed on the agents row ID, taken after requireAgent charged the bucket; its 429 carries Retry-After 1 and rate limited"
  - "F12: the mirror fill is coalesced per Status SHA-256 and version, detached from every request; a failure is never cached; pending fetches are kept per SHA-256 and version, and only the fetch for the Status the server holds when it ends (or any fetch, when it holds no Status) becomes the entry (pre-merge review fix round 1)"
  - "F13: a KRL version is served only once its copy is durable; the equal-version shortcut is taken only for a durable copy, otherwise the full write is redone; the copy read at start is never durable, so every start rewrites it once before it is served (owner decision, pre-merge review fix round 1, owner follow-up; it replaced a sync at start)"

metrics:
  duration: "about 1 h 15 min (21:30 to 22:45 local time, 2026-11-03), of which about 35 min are the gate runs"
  completed: 2026-11-03
---

# Phase 3 Plan 08g: server signer capacity (F11, F12, F13) Summary

**keyroster-server keeps at most 12 budgeted signer calls in flight, at most 6 of them relayed for host agents (agent token first), plus its one coalesced GetKRL; one agent has at most 2 requests in flight on the state and heartbeat routes; concurrent directory-mirror misses share one detached GetDirectory fetch; and a KRL is served only once its copy in krl-served.json is durable.**

## Delivery

- **PR:** #83, https://github.com/Labontese/keyroster/pull/83, opened by keyroster-bot without auto-merge.
- **Branch:** `p03/08g-server-capacity`, from origin/main 741e2f6.
- **Required checks:** see "CI" below.

## Commits

| Task | Commit | Message |
|------|--------|---------|
| 1 | e12fdac | fix(server): bound the server's signer calls, with an agent share (F11) |
| 2 | 64e7c36 | fix(server): bound each agent's requests in flight on the relaying routes (F11) |
| 3 | 09444d9 | fix(server): serve a KRL only once its copy is durable, and fetch each directory once (F12, F13) |
| 4 | 49f7dbb | docs(server): describe the signer-call budget, the per-host requests in flight and the durable KRL copy (03-08g) |
| 4 | 0a0913d | docs(03-08g): add the server-capacity plan at wave 18 |

Plus the completion commit `docs(03-08g): complete server-capacity plan` with this file and the tracking updates. Every commit has Daniel as author and keyroster-bot as committer, with an SSH signature.

## Test time (03-08k's limits: 400 s alone, 480 s under ./...)

| Run | internal/agent/apply | internal/server |
|-----|----------------------|-----------------|
| Base, before any edit: alone gate | 344.814 s (limit 400) | n/a |
| Base, before any edit: margin gate (`./...`) | 328.365 s (limit 480) | 108.286 s |
| Task 4: alone gate | 334.811 s (limit 400) | n/a |
| Task 4: margin gate (`./...`) | 368.770 s (limit 480) | 135.816 s |
| Task 4: full gate's `./...` | 351.777 s | 125.258 s |
| CI build-test on 0a0913d (job 126222055215, 11 m 21 s) | 233.224 s | 127.697 s |

Neither base was above its limit, so the stop rule did not fire. internal/server on its own under -race took 75.3 s after Task 1, 76.5 s after Task 2, and 114.1 s and then 80.5 s after Task 3. The new tests add about 10 s to the package. The rest of the spread is load on the machine; the slowest tests on the 80.5 s run were TestLoginRedeem (7.5 s) and TestRemovalConfirmation (6.6 s), which this plan does not touch.

## CI

On head 0a0913d, before this SUMMARY was committed, all 26 required checks passed (27 of 27 checks in all). Runs: 41723483721 (build-test 11 m 21 s, lint, fuzz 25 m 34 s, capslock, govulncheck, dependency-firewall, cli-macos, cli-windows), 41723484156 (e2e 9.5p1 and 10.5p1), 41723483936 (e2e-distro, 7 images), 41723483823 (e2e-pkcs11, 2), 41723483979 (e2e-tpm), 41723483883 (systemd-sandbox), 41723484862 (build-piv), 41723483647 (CodeQL, actions and go), 41723483688 (pinned-actions), 41723483680 (pr-title). The completion commit reruns them on the new head.

## RED evidence

Every RED was taken in WSL through `bash scripts/linux.sh`, with the same `-run` patterns as the task's verify.

**Task 1**, on a stub: the constants `maxSignerCalls`/`maxAgentCalls` and `withSignerBudget` returning sg unchanged, with newServer not yet wrapping. catch_up_reads_leave_room used the literal 6 here and the constant once committed.
- `TestSignerBudget/total_bounded`: RED, "20 calls in flight, peak 20; want 12".
- `TestSignerBudget/catch_up_bounded_interactive_room`: RED, "interactive in flight 20, agent peak 20, total peak 40; want 6, 6, 12".
- `TestSignerBudget/waiter_ctx_ends`: RED, "a Status whose ctx ended while it waited = context deadline exceeded after 1 calls at the signer; want its ctx's error and none".
- `TestAgentInFlight/catch_up_reads_leave_room`: RED, "12 calls entered the signer, want 6".

**Task 2**, on Task 1's head (e12fdac), with the literal 2:
- `TestAgentInFlight/one_agent_bounded_in_flight`: RED, "6 calls entered the signer, want 2" (the agent share, and no 429).
- `TestAgentInFlight/heartbeat_shares_cap`: RED, "a heartbeat with 2 state requests in flight = 200".
- `TestAgentInFlight/cap_released_after_answer` reads the new map, so it was written right after the map's declaration and has no RED of its own; the release-skipped mutant (N5) is its failing run.

**Task 3**, on Task 2's head (64e7c36):
- `TestKRLServedCopy/dir_sync_failure_never_served`: RED, "GET 2 of v200, the sync still failing = 200 after 1 syncs; want 503 after 2".
- `TestDirectoryMirrorFill/concurrent_misses_one_fetch`: RED, "24 GetDirectory calls for 24 concurrent misses, want 1".
- `TestDirectoryMirrorFill/new_sha_new_fetch`: RED, "the mirror holds version 1 while the version-2 fetch is in flight, want no entry".

## GREEN at once, with the reasons

- `TestSignerBudget/tokens_released_on_error` (Task 1 stub): the stub budgets nothing, so no token can be kept. Its mutant M6 is the failing run.
- `TestSignerBudget/getkrl_outside_budget` (Task 1 stub): the stub budgets nothing, as the plan expected. M7 is its failing run.
- `TestKRLDuringFullBudget/krl_route_answers_inside_status_ttl` (Task 1 stub): nothing waits on the stub, and the route only needs a fresh Status and one GetKRL. M7 is its failing run.
- `TestKRLDuringFullBudget/getkrl_coalesced_one_call` (Task 1 stub and origin/main): currentKRL already coalesced on krlInflight. The test pins the coalescing that the bound of 13 rests on.
- `TestAgentInFlight/cap_per_agent` (Task 2, on Task 1's head): two agents with 2 requests each make 4 calls, within the agent share of 6.
- `TestKRLServedCopy/copy_read_at_start_is_durable` (Task 3): before the flag, the equal-version shortcut never wrote, durable or not. P3 is its failing run. (Renamed `copy_read_at_start_rewritten_once` in pre-merge review fix round 1, owner follow-up; RED there.)
- `TestDirectoryMirrorFill/failure_not_cached` (Task 3): before coalescing, a failed fetch returned before the store, and each caller fetched for itself. P6 is its failing run.
- `TestDirectoryMirrorFill/waiter_ctx_ends_fetch_continues` (Task 3): before coalescing, the second waiter made its own call on its own ctx, so the first caller's cancel could not reach it. P5 is its failing run.
- `TestDirectoryMirrorFill/ended_ctx_starts_no_fetch` (Task 3): Task 1's budget already refuses an ended ctx before the signer. With the detached fetch, the explicit ctx check in currentDirectory keeps this true.
- `TestDirectoryMirrorFill/mismatch_drops_status` (Task 3): each caller already dropped the status on its own mismatch. The test pins that the rule holds inside the shared fetch.
- The existing `TestKRLServedCopy/dir_sync_failure_advances_floor` and `equal_identical_no_write` stayed green, with their meaning.

## Mutants

Each mutant was applied to the committed code, run against its named test, and restored with `git checkout -- <file>`. `git diff --exit-code` then confirmed the file byte for byte.

| ID | Mutant | Named test | Result |
|----|--------|------------|--------|
| M1 | newServer stores sg without the budget | TestAgentInFlight/catch_up_reads_leave_room | killed: 12 calls entered, want 6 |
| M2 | the agent calls take only a total token | TestSignerBudget/catch_up_bounded_interactive_room | killed: the interactive room never filled |
| M3 | acquisition order swapped, total token first | TestSignerBudget/catch_up_bounded_interactive_room | killed: the interactive calls find no room |
| M4 | maxAgentCalls = maxSignerCalls | TestSignerBudget/catch_up_bounded_interactive_room | killed (after the test fix in Deviations 1): the interactive room never filled |
| M5 | the agent token kept when ctx ends at the total wait | TestSignerBudget/waiter_ctx_ends | killed: the whole agent share never got in (5 of 6) |
| M6 | release skipped on the error path (in `budgeted`) | TestSignerBudget/tokens_released_on_error | killed: failing call 13 hit context deadline exceeded |
| M7 | GetKRL takes a token | TestSignerBudget/getkrl_outside_budget and TestKRLDuringFullBudget/krl_route_answers_inside_status_ttl | killed by both: GetKRL never reached the signer, and the route did not answer within 2 s |
| N1 | agentSlot call removed from handleAgentState | TestAgentInFlight/one_agent_bounded_in_flight | killed: 6 calls entered, want 2 |
| N2 | agentSlot call removed from handleAgentHeartbeat | TestAgentInFlight/heartbeat_shares_cap | killed: the heartbeat answered 200 |
| N3 | a separate count per route (key on row ID and route) | TestAgentInFlight/heartbeat_shares_cap | killed: the heartbeat answered 200 |
| N4 | one count for all agents | TestAgentInFlight/cap_per_agent | killed: 4 held calls never reached |
| N5 | release skipped | TestAgentInFlight/cap_released_after_answer | killed: the second round's 2 calls never reached |
| P1 | the shortcut without `prev.durable` | TestKRLServedCopy/dir_sync_failure_never_served | killed: GET 2 answered 200 after 1 sync |
| P2 | `durable: true` whatever err is | TestKRLServedCopy/dir_sync_failure_never_served | killed: GET 2 answered 200 after 1 sync |
| P3 | loadServedKRL without `durable: true` | TestKRLServedCopy/copy_read_at_start_is_durable | killed: a sync and a rewrite of the marker (at the time; since the owner follow-up a rewrite at start is the intended behaviour, see there) |
| P4 | each caller fetches for itself (inflight never reused) | TestDirectoryMirrorFill/concurrent_misses_one_fetch | killed: 24 calls, want 1 |
| P5 | the fetch runs on the caller's ctx | TestDirectoryMirrorFill/waiter_ctx_ends_fetch_continues | killed: the second waiter got context canceled |
| P6 | a failed fetch kept (stays the fetch in flight, so its error is served again) | TestDirectoryMirrorFill/failure_not_cached | killed: the next call got the cached "signer down" |
| P7 | the `inflight == f` guard on the store removed | TestDirectoryMirrorFill/new_sha_new_fetch | killed: the version-1 result became the entry |

P6 note: a failed fetch carries a nil view, so "storing" it as the entry would change nothing. The mutant is therefore the form a cached failure would actually take: the finished, failed fetch stays recorded as the one in flight, and later callers reuse it.

## Tests that bypass the budget, and moved assertions

- The only server tests that replace `e.s.signer` after newServer, and so run unbudgeted: admin_test.go `cleanup_survives_client_hangup` (`sentSigner{e.fake}`) and login_test.go's `stallSigner`. They test a client hang-up and a stalled Status, not capacity, and their files are unchanged. No test asserts the type of `e.s.signer`.
- No existing test held more than 12 calls of one non-coalesced method at once, so none waited on the budget. This was checked by reading the 12 `fake.hold(` callers outside capacity_test.go. The most concurrent are revoke_test.go's 12 GET krl requests, which coalesce into one GetKRL, and server_test.go's 8 currentStatus calls, which coalesce into one Status; every other caller starts one or two calls. No existing test sent more than 2 concurrent requests from one agent: the only goroutines in the agent, heartbeat, forget and enroll tests are heartbeat_edges_test.go's one held heartbeat and enroll_test.go's user-invite finishes. `in_flight_heartbeat_not_inherited` holds one heartbeat in flight and stays green. No existing assertion moved in any task.

## Gates (Task 4)

- Alone and margin gates: passed (figures above).
- Full gate: passed. That is `go test -race ./...`, `go vet` (plain, `e2e`, and `e2e systemdsmoke`), `gofmt -l .` empty (scripts/linux.sh uses `--exec`), golangci-lint "0 issues.", capslock-check, dep-firewall, testonly-firewall and check-pinned-actions (47 pinned).
- **capslock:** no new pair. keyroster-signer has 92 pairs, keyroster-agent 37 and keyroster-agent-fetch 23, each equal to its baseline. capslock-check.sh does not analyse keyroster-server, the binary this plan changes. No module was added.

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 1 - Bug] `catch_up_bounded_interactive_room` did not kill the maxAgentCalls = maxSignerCalls mutant (M4)**
- **Found during:** Task 1's mutant runs.
- **Issue:** The subtest measured the agent share against `maxAgentCalls`, the constant the mutant changes. Under the mutant it waited for 12 agent calls and an interactive room of 0, and passed.
- **Fix:** The subtest now asserts the owner's rule itself (Q-G1: the agent share is half of the total): `share := maxSignerCalls / 2` for the agent peak and the interactive room. M2, M3 and M4 were then rerun, and all three were killed.
- **Files modified:** internal/server/capacity_test.go.
- **Commit:** folded into Task 1's commit e12fdac by amending it before the first push. The original was e03effb, and nothing had been pushed.

### Readings of the plan, recorded

- **gateSigner's GetKRL passes the gate.** The plan says every method of the double waits on one gate. `getkrl_outside_budget` also needs a GetKRL that "reaches the double at once and returns" while the gate holds 12 Logins, and a budgeted peak that stays 12. So the double's GetKRL is counted in calls only, never waits at the gate, and is not counted among budgeted calls in flight. M7 still fails it, because a budgeted GetKRL never reaches the double.
- **`heartbeat_shares_cap`'s setup.** polledAgent discards the host keys, so the subtest does what polledAgent does inline (approvedAgent, then the first state) and installs every later version with `e.webEntry(t)`. That way no removal is recorded and the heartbeat relays no signer call.
- **`new_sha_new_fetch` ordering.** The version-1 fetch and the version-2 fetch are held at two separate gates (a second `fake.hold`), so the version-1 fetch ends first, while the version-2 fetch is still in flight. That makes P7 fail deterministically. It is not a signer swap: the fake stays the same, and the two bypass tests above are still the only ones that bypass the budget.
- **`mismatch_drops_status`.** newAgentEnv's fake runs in chain mode, where Status reports the SHA-256 of the bytes the fake holds, so a mismatch cannot occur in it. The subtest turns chain mode off under the fake's lock and sets a Status for version 1 and a GetDirectory answer with other bytes.
- **agentSlot's 429** is written with a nil status, as agentAllow writes its 429. The log key for the agents row ID is `agent_row`.
- **Commits per task.** Each task's tests and code went into one `fix(server)` commit, as in 03-08f. The REDs were taken on the uncommitted tests and are recorded above.
- **Runbook labels.** The plan wanted each note labelled "run in CI; UNVERIFIED on a real host". Two parts are not run in CI at all, so they are labelled more narrowly: the 503 during a long touch signature, which is UNVERIFIED in CI and on a real host (TestKRLDuringFullBudget only covers the route answering while the status is recent), and the heartbeat's 429 path in the fetcher, which has no test of its own (the state poll's has: `TestFetch/rate_limited_continues_next_poll`). The touch note is worded so that hardware stays optional ("If the signer's key is on a hardware token that asks for a touch").

## Pre-merge review fix round 1

The pre-merge review of PR #83, on head 6bd1324, found four things to fix in this PR. They are fixed in five commits on that head; history was not rewritten. One more finding was refuted: that a pending KRL drops out of the agent state answer while a catch-up read waits in the agent share. It falls within T-03-308 residual (1), so it is not acted on.

### What changed

| Commit | Message | Change |
|--------|---------|--------|
| ddeb8f6 | fix(server): sync the KRL copy read at start before it counts as durable (F13) | Superseded by 5c60311 (owner follow-up, below). loadServedKRL syncs the copy's file (`syncFile`, a new test seam) and its directory (`syncDir`) once at start. The copy is durable only when both syncs succeed. Otherwise the first refresh writes it again in full, and the route answers 503 until a write succeeds. A failed sync does not stop the start. The floor follows the copy read at start, durable or not, as before. Before this commit, a copy read back at start counted as durable with no sync at all. So restarting the process after a failed directory sync served a version that might never have reached the disk. |
| 43904d6 | fix(server): pin each budgeted signer method's share of the budget (F11) | Test only. `total_bounded` is a table over all 8 budgeted methods, each called alone. `catch_up_bounded_interactive_room` holds the agent share, then runs each interactive method alone, in its own subtest. |
| 431f698 | fix(server): keep one pending directory fetch per SHA-256 and version (F12) | dirMirror's single `inflight` pointer becomes `pending map[dirKey]*dirFetch`. Each fetch is removed when it ends, so the map is bounded by the keys in flight. A late caller with an older Status no longer replaces another key's pending fetch. A fetch becomes the entry only when its key is that of the Status the server holds when the fetch ends, or when the server holds no Status. A caller with an older Status leaves the held entry alone. The part of currentDirectory after currentStatus is now `directoryUnder(ctx, v)`, so a test can run a caller that read an older Status. |
| c477169 | fix(server): count the directory fetches of a waiter whose ctx ends (F12) | Test only. `waiter_ctx_ends_fetch_continues` counts GetDirectory calls from the start of the subtest. Once the second waiter returns, it asserts that exactly one call was made. |
| 1822dad | docs(server): name the KRL copy's 503 body and its sync at start (F13) | server-install.md: the 503 body is `signer unavailable`, and `KRL not kept: ...` is in the log at every refresh. A restart alone does not end the 503 while the disk still fails. Also the new UNVERIFIED item below. |

The plan was updated to match, and each change is marked "pre-merge review fix round 1". The changes cover:
- the F13 must_have and its rationale;
- the Task 1 and Task 3 test descriptions;
- the loadServedKRL and dirMirror actions;
- the P3 mutant line;
- the edge list.

### Tests added or changed

- TestKRLServedCopy:
  - `copy_read_at_start_is_durable` keeps its name, because the plan's Task 3 verify names it. It now expects exactly one directory sync at the restart, then no further sync and no write.
  - New: `copy_read_at_start_not_synced/dir_sync_fails` and `copy_read_at_start_not_synced/file_sync_fails`.
  - New: `restart_after_dir_sync_failure`, the review's reproduction with a floor check added.
- TestSignerBudget:
  - `total_bounded` has 8 rows.
  - `catch_up_bounded_interactive_room` has 6 rows.
- TestDirectoryMirrorFill:
  - New: `competing_status_one_fetch_per_key`.
  - `waiter_ctx_ends_fetch_continues` gains the fetch count.
  - The other five cases stay green, with their meaning.

### RED evidence

Every RED was taken in WSL through `bash scripts/linux.sh`, with `-race -count=1 -v -run` on the test.

- **F13**, on 6bd1324 plus only the unused `syncFile` seam. The file-sync case needs the seam to compile.
  - `copy_read_at_start_is_durable`: "the start made 0 directory syncs, want 1".
  - `copy_read_at_start_not_synced/dir_sync_fails`: "GET 1 of the copy's own version, the start sync and this one failing = 200 after 0 syncs, copy "marker"; want 503 after 2 syncs and a full rewrite".
  - `copy_read_at_start_not_synced/file_sync_fails`: "= 200 after 0 directory syncs, copy "marker"; want 200 after a full rewrite and 1 sync".
  - `restart_after_dir_sync_failure`: "GET 1 of v200 after the restart, the sync still failing = 200; want 503".
- **F12**, on 6bd1324's directory.go plus only the extraction of `directoryUnder`, which changes no behaviour.
  - `competing_status_one_fetch_per_key`: "4 GetDirectory calls for the callers of versions 1, 2, 1 and 2, want 2 (one per SHA-256 and version)".
- **F11 per-method tables:** GREEN at once on 6bd1324. The code was right, but the old test could not see the four mutants below, which are the failing runs. Each mutant was also run against 6bd1324's capacity_test.go, and that test passed under every one of them.
- **`waiter_ctx_ends_fetch_continues`:** GREEN at once on 6bd1324, for the same reason. The P5 runs below are its failing runs.

### Mutants

Each mutant was applied to the committed code and run against the named test. It was then restored with `git checkout -- <file>`, and `git diff --exit-code <file>` confirmed the file byte for byte. For the runs against 6bd1324's capacity_test.go, that file was written into the tree for the run and restored the same way.

| ID | Mutant | 6bd1324's test | New test |
|----|--------|----------------|----------|
| Q1 | loadServedKRL sets `durable: true` whatever the start sync gives | n/a | killed by `copy_read_at_start_not_synced/dir_sync_fails` ("= 200 after 1 syncs"), `/file_sync_fails`, and `restart_after_dir_sync_failure` ("GET 1 of v200 after the restart ... = 200") |
| Q2 | the start sync skipped (`durable := true`) | n/a | killed by `copy_read_at_start_is_durable` (0 start syncs) and by the three above |
| P3 | rerun: the copy read at start never durable | n/a | killed by `copy_read_at_start_is_durable` ("= 200 after 2 syncs", the marker rewritten) |
| R1 | Revoke takes the agent share (`agent=true`) | survived (ok) | killed by `total_bounded/Revoke` and `catch_up_bounded_interactive_room/Revoke` (the calls never got in) |
| R2 | ForgetAgent unbudgeted | survived (ok) | killed by `total_bounded/ForgetAgent` ("20 in flight, peak 20, agent peak 0; want 12, 12, 0") and `catch_up_bounded_interactive_room/ForgetAgent` ("interactive in flight 20 ... total peak 26") |
| R3 | InstallDirectory unbudgeted | survived (ok) | killed by both rows, as R2 |
| R4 | GetDirectory unbudgeted | survived (ok) | killed by both rows, as R2 |
| M2, M4 | rerun on the new subtests: agent calls take only a total token; maxAgentCalls = maxSignerCalls | n/a | still killed (`total_bounded/GetBundle`, `/GetDirectoryVersion`, `catch_up_bounded_interactive_room/Login`) |
| S1 | back to one pending fetch (the map reset to the newest key at every start) | n/a | killed by `competing_status_one_fetch_per_key` ("4 GetDirectory calls ... want 2") |
| S2 | the store ignores obsolete (any successful fetch becomes the entry) | n/a | killed by `new_sha_new_fetch` ("the mirror holds version 1 while the version-2 fetch is in flight") |
| S3 | a caller with an older Status still drops the entry | n/a | killed by `competing_status_one_fetch_per_key` ("a caller with the older version-1 Status dropped the version-2 entry") |
| P5 | the fetch runs on the first caller's ctx | n/a | killed by `waiter_ctx_ends_fetch_continues` as committed ("the second waiter = ... context canceled") |
| P5, late joiner | P5, with the test edited so the second waiter starts only after the cancel | survived (ok) | killed: "2 GetDirectory calls for the two waiters, want 1". Control without the mutant: ok |

### Gates

Run in WSL on 1822dad, the last code commit of the round. The plan and SUMMARY edits that follow change no code.

| Run | internal/agent/apply | internal/server |
|-----|----------------------|-----------------|
| `go test -race -count=1 -v ./internal/server/` | n/a | ok, 85.250 s: no FAIL and no DATA RACE; every touched test PASSes |
| Alone gate (limit 400 s) | ok, 345.869 s | n/a |
| Margin gate (`./...`, limit 480 s), run 1 | ok, 323.595 s | ok, 125.214 s |
| Margin gate, run 2 | ok, 330.525 s | ok, 131.437 s |
| Full gate's `./...` | ok, 349.373 s | ok, 120.265 s |

- **Margin gate, run 1.** It exited non-zero. The cause was not internal/agent/apply, which was within its limit, but `TestFetch/more_repolls_immediately` in internal/agent/fetch: "requests [...] in 2.963714409s, want two at once". That case has a 900 ms wall-clock bound, and this branch does not change the package.
  - It is the pre-existing timing flake already recorded in deferred-items.md and in the 03-08, 03-08c and 03-08f summaries.
  - It passed in the full gate's `./...` (ok, 43.854 s), 5 of 5 times alone under `-race`, and in margin run 2 (ok, 38.042 s). Margin run 2 exited 0.
- **Full gate:** passed. That covers `go test -race ./...`, `go vet` (plain, `e2e`, and `e2e systemdsmoke`), an empty `gofmt -l .` (scripts/linux.sh uses `--exec`), golangci-lint ("0 issues."), capslock-check, dep-firewall, testonly-firewall and check-pinned-actions (47 pinned).
- **capslock:** keyroster-signer, keyroster-agent and keyroster-agent-fetch have 92, 37 and 23 pairs, each equal to its baseline. No module was added.

### Owner follow-up: rewrite at start

The round left one question open: a sync at start that follows a failed sync can report success although the earlier rename never reached the disk. After a failed fsync, Linux may mark the pages clean. The owner then decided "Skriv om vid start": a copy read back at start is always `durable: false`, with no sync at start.

| Commit | Message | Change |
|--------|---------|--------|
| 5c60311 | fix(server): rewrite the KRL copy read at start before it is served (F13) | `loadServedKRL` returns the copy with `durable` false. The sync at start and the `syncFile` seam are gone. Nothing else in keepKRL changes: the same version with the same bytes and a copy that is not durable falls through to keepKRLFile (write, rename, syncDir). `served` becomes durable only when that write succeeds, and the next refresh takes the shortcut. So every start rewrites the copy exactly once before it is served. The route answers 503 until that write succeeds, and the floor follows the copy read at start as before. Nothing waits longer than one successful write. |

Against 6bd1324, revoke.go's change in this round is now only that `durable: true` is dropped, plus the comments.

**Tests (TestKRLServedCopy):**
- `copy_read_at_start_rewritten_once` replaces `copy_read_at_start_is_durable`. The restart makes no directory sync. The first GET returns 200 after one full rewrite (the marker is replaced) and one sync. A second GET writes nothing and syncs nothing.
- `copy_read_at_start_served_after_write` replaces `copy_read_at_start_not_synced`, whose file-sync case went with the seam. The first refresh's directory sync fails: 503, `KRL not kept: injected EIO`, and krlItem refuses. Once the sync works, one more full write, then 200, then no write.
- `restart_after_dir_sync_failure` is kept unchanged: 503 after the restart until a sync succeeds, and v150 is still refused below v200.

**RED on 7aaf58e:**
- `copy_read_at_start_rewritten_once`: "the start made 1 directory syncs, want 0 (the copy read at start is rewritten, not synced)".
- `copy_read_at_start_served_after_write`: "GET 1 of the copy's own version, its directory sync failing = 503 after 2 syncs ...; want 503 after a full rewrite and 1 sync".
- `restart_after_dir_sync_failure`: GREEN at once on 7aaf58e. Both designs answer 503 there, since the start sync fails too.

**GREEN:** all of TestKRLServedCopy, in WSL under `-race` and natively on Windows.

**Mutants** (applied to 5c60311 and restored byte for byte):

| ID | Mutant | Result |
|----|--------|--------|
| T1 | `durable: true` at start | killed by `copy_read_at_start_rewritten_once` ("= 200 after 0 syncs, copy "marker""), `copy_read_at_start_served_after_write` ("= 200 after 0 syncs") and `restart_after_dir_sync_failure` ("GET 1 of v200 after the restart ... = 200") |
| T2 | the first refresh skips the write when the bytes are the same (`case same:` without `prev.durable`) | killed by `dir_sync_failure_never_served` ("GET 2 ... = 200 after 1 syncs"), and by the same three as T1 |

The runbook paragraph now says the copy read at start counts as not yet durable, so every start rewrites it once before it is served. The plan's F13 must_have, its rationale, the Task 3 test list and verify, the loadServedKRL action, the mutant line, the edge list and T-03-311's tests now say the same, each marked "owner follow-up".

**Gates of the follow-up:**

Run in WSL on 5c60311.

| Run | internal/agent/apply | internal/server |
|-----|----------------------|-----------------|
| `go test -race -count=1 -v ./internal/server/` | n/a | ok, 88.723 s; no FAIL, no DATA RACE; the three start-copy cases PASS |
| Alone gate (limit 400 s) | ok, 313.723 s | n/a |
| Margin gate (`./...`, limit 480 s) | ok, 395.600 s | ok, 158.797 s |
| Full gate's `./...` | ok, 331.743 s | ok, 128.105 s |

The margin run is the slowest of the round: internal/server took 158.8 s, against 120 to 131 s in the other runs. So the machine was loaded during that run, and it still stayed within its limit. The full gate passed: vet three times, gofmt clean, golangci-lint "0 issues.", capslock 92/37/23 (each equal to its baseline), dep-firewall, testonly-firewall, and 47 pinned actions. TestFetch passed in both `./...` runs.

### Fix-round check follow-up

The narrow check of this round found the code correct and three low gaps in the evidence, fixed in one commit:
- `restart_after_dir_sync_failure` now checks the 503 body (`{"error":"signer unavailable"}`) with requireUnavailable, so the runbook's "503 (signer unavailable)" is run in CI. A mutant that changes that body in handleKRL now fails it.
- Task 3's verify also requires `copy_read_at_start_served_after_write`, `restart_after_dir_sync_failure` and `competing_status_one_fetch_per_key`.
- The F12 key decision here and the PR body say that a fetch also becomes the entry when the server holds no Status.

### Deviations in this round

- **`total_bounded` for the two agent methods.** The review asked that 20 calls of every budgeted method peak at maxSignerCalls. For GetBundle and GetDirectoryVersion that cannot hold, because alone they are bounded by the agent share. So those two rows assert a peak of the share (6) and an agent peak of 6. The six interactive rows assert a peak of 12 and an agent peak of 0. The share is the owner's rule (`maxSignerCalls / 2`), not the constant under test, so M4 still fails these rows.
- **The F12 interleaving uses `directoryUnder`.** A caller that read an older Status cannot be staged through currentDirectory: swapping the server's held Status would make that caller current, not late. So the part after currentStatus became `directoryUnder(ctx, v)`, and the test passes it the version-1 Status while the server holds version 2. Its RED was taken on 6bd1324 with only that extraction.
- **The F12 store guard.** "An obsolete fetch never replaces a newer entry" first meant a fetch that was no longer the most recently started one. With a map, every pending fetch is the latest for its own key, so that reading no longer tells them apart. It now means a fetch whose key is not that of the Status the server holds when the fetch ends. That Status is read under Server.mu, before the mirror lock is taken, so the two locks are never held together. With no Status held (just after an install drops it), a fetch is not known to be obsolete and is stored, as before.
- **`copy_read_at_start_is_durable` kept its name** in this round, because the plan's Task 3 verify greps for it. The owner follow-up renamed it to `copy_read_at_start_rewritten_once`, since "is durable" no longer holds, and updated the plan's verify to match.
- **Commit types.** As asked for this round, the two test-only commits use `fix(server)`, one per fix, rather than `test(server)`.

## UNVERIFIED

- Every runbook note of this plan on a real host. 03-16's homelab drill provokes none of these limits (owner decision).
- KRL and agent-state delivery during a signer stall past statusTTL. It is expected to answer 503 as today, and no test runs it. It is follow-up plan 03-08i's.
- The fetcher's handling of a 429 on the heartbeat route. heartbeat.go returns nil on RateLimited, but no test drives that path.
- Added in pre-merge review fix round 1:
  - (Removed by the owner follow-up: the question whether a sync at start can report a false success. No sync at start remains.)
  - Every sync failure in the F13 tests is injected through `syncDir`, so the real-disk behaviour after an I/O error is not run.
  - The F12 store guard reads the server's held Status before it takes the mirror lock. If that Status changes between the read and the store, an obsolete entry can be kept, which costs at most one more fetch, since every use checks the entry against its caller's Status. No test drives that window.

## Known Stubs

None.

## Threat Flags

None. No route, endpoint, file path or schema was added. agentSlot and the budget only delay or refuse, the durable flag only withholds a KRL, and the coalesced fetch serves only bytes whose SHA-256 and version equal what Status reported (the prohibition).

## Self-Check: PASSED

- All ten created or modified code, doc and plan files exist, this SUMMARY included.
- All five plan commits (e12fdac, 64e7c36, 09444d9, 49f7dbb, 0a0913d) are ancestors of HEAD. `git rev-list --count 741e2f6..0a0913d` = 5.
- The must-have artifacts are present: `func withSignerBudget(`, `func (s *Server) agentSlot(`, `func (s *Server) fetchDirectory(`, `durable` in revoke.go. So are the key links: `withSignerBudget(` in newServer, `s.agentSlot(` twice in agent.go, and `s.dropStatus()` in directory.go's fetch.
- No forbidden file (`.planning/config.json`, `milestone.lock`, `state.json`, `.review-diagnostics/`) is in the branch's diff.
- Pre-merge review fix round 1: the five commits ddeb8f6, 43904d6, 431f698, c477169 and 1822dad, the SUMMARY commit 7aaf58e, the owner follow-up's 5c60311 and its docs commit are all ancestors of HEAD. They sit on 6bd1324 with no rewrite. `dirKey`, `pending map[dirKey]*dirFetch` and `func (s *Server) directoryUnder(` are present. Neither `inflight` (in directory.go) nor `syncFile` (in internal/server) appears any more.
