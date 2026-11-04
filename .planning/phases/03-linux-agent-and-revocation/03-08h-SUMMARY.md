---
phase: 03-linux-agent-and-revocation
plan: 08h
subsystem: signer
tags: [signer, signerclient, directory, capacity, connections, render, f07, f16]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08g (budgetSigner around socketSigner, maxSignerCalls 12 with maxAgentCalls = maxSignerCalls / 2, agentSlot, GetKRL outside the budget); 03-08d (checkCandidate and the KRL-alone pass on the agent)"
provides:
  - "directory: MaxPrincipalsFile, MaxAccounts, MaxHostGroupAccounts, ErrUnrenderable, principalsHeader, the sizer (roles and principals indexed once, deduplicated without sorting) and CheckRenderable with the non-growth rule (Q-G7) and the moved-host check (E-2)"
  - "agent/apply: maxPrincipalsFile and maxAccounts are the directory constants"
  - "signer: directory_unrenderable (unauthorized class) in InstallDirectory after CheckPolicy; maxConnsPerPeer, connSlots, acceptLimiter; credentials read in the accept loop; uid_share_exceeded; the slot released before the close"
  - "wire: MaxPeerConns (16) and MaxServerSignerCalls (MaxPeerConns - 4)"
  - "signerclient: Client with AwaitClose; package functions are one-line wrappers; the receive error names both causes"
  - "server: socketSigner through s.client() (AwaitClose: true); maxSignerCalls = wire.MaxServerSignerCalls"
  - "tests (pre-merge review of PR #84): TestCheckRenderableFastEnough (3), TestMoveUnion (2), TestMoveByName (3), TestMoveGroupsAndKeys (4), TestCheckRenderableMatchesReference; TestDirectoryUnrenderable +2, TestRenderable +1"
  - "tests: TestDirectoryUnrenderable (10), TestRenderable (23), TestSizerMatchesRender, TestConnSlots (5), TestPeerShare (6), TestOverloadDoesNotStallAccept (new setup), TestAwaitClose (5), TestSocketSignerAwaitsClose"
  - "docs: enroll-user.md (directories hosts cannot render, with host moves), signer-install.md (connection limits, slow signature)"
  - "planning: the release-ordering sentence in 03-09 and 03-10; 03-08h at wave 19, 03-09 to 03-16 one wave later"
affects: [03-08i, 03-09, 03-10, 03-12, 03-14]

requirements-completed: []

actuals:
  tokens: 36700
  tasks: 4
  commits: 4
plan_head_before: 71e540dc07e1ddab5592dae38daeba53e237c3cb
plan_head_after: 7bdcc2674d738a82b77b5407f1d4a0fd8966bcbc

tech-stack:
  added: []
  patterns:
    - "A per-account stamp array over interned principal numbers: dedupe without a map or a sort per account"
    - "Deferred calls in the connection goroutine ordered so the slot is released before the close"
    - "A client that reads to the end of the stream after its frame, so the caller's budget token outlives the server-side slot"

key-files:
  created:
    - internal/agent/apply/renderable_test.go
    - internal/directory/render_size_test.go
    - internal/directory/render_moves_test.go
    - .planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md
  modified:
    - internal/directory/render.go
    - internal/agent/apply/swap.go
    - internal/signer/directory.go
    - internal/signer/refusal.go
    - internal/signer/directory_test.go
    - internal/wire/frame.go
    - internal/signer/server.go
    - internal/signer/signer.go
    - internal/signer/overload_test.go
    - internal/signerclient/client.go
    - internal/signerclient/client_test.go
    - internal/server/signer.go
    - internal/server/capacity_test.go
    - docs/runbooks/enroll-user.md
    - docs/runbooks/signer-install.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (and the wave lines of 03-10 to 03-16)
    - .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md

key-decisions:
  - "F07: CheckRenderable runs in InstallDirectory after CheckPolicy against s.directory, never on stored state; files are sized at the widest version (20 digits); above-cap installed groups may only shrink (subset), too-large files may not grow"
  - "E-1 (owner decision 2026-11-04, execution stop at Task 1): files are sized by a sizer that indexes roles and principals once and dedupes by a per-account stamp, without sorting, with exactly the rendered sizes (TestSizerMatchesRender); the 2 s bound under -race is kept"
  - "E-2 (owner decision 2026-11-04, execution stop at Task 1): a version that moves an active host (matched by a shared host key; since R-2 also by name) to another host group is refused directory_unrenderable when the union of the two groups' accounts is above 4096 or a file of the new group is above 64 KiB"
  - "R-1 (pre-merge review of PR #84): host groups are looked up through one name index, and a move's union is counted once per (from, to) pair, not at all while the two groups' sizes add up to at most 4096; the answers are those of the previous implementation"
  - "R-2 (owner decision (2026-11-04), pre-merge review): an active offered host and an active installed host of the same name in different host groups are a move too, checked by the same rules; a host renamed and rekeyed in one version is not found (limitation, UNVERIFIED)"
  - "F16: the accept loop reads peer credentials, then takes a per-uid slot (16 of 32) from connSlots, which has its own mutex and never waits for s.mu; refusals are closed, counted in overloaded, and logged with the uid through the loop's own acceptLimiter"
  - "F16: release ordering: the goroutine defers wg.Done, conn.Close, then conns.put, so the slot is freed before the close; socketSigner's Client waits for the close, so the server's live connections never exceed its 12 tokens plus its GetKRL"

metrics:
  completed: 2026-11-04
---

# Phase 3 Plan 08h: Signer connection shares Summary

The signer refuses at install every directory the host agents' own caps would refuse, the intermediate generation and a host's move between host groups included, unless nothing grows beyond an above-cap installed version. It also gives each local account at most 16 of its 32 connections, and keyroster-server's calls return only after the signer has freed their slots, so the server's own load never meets its share.

## CI

On head 7bdcc26 (the code and docs before this SUMMARY), all 26 required checks passed: build-test 11m10s, fuzz 24m49s, lint, capslock, govulncheck, the e2e, e2e-distro, e2e-pkcs11 and e2e-tpm jobs, systemd-sandbox, cli-windows, cli-macos and build-piv. The checks on the SUMMARY commit are waited for after its push.

## Delivery

- Branch `p03/08h-signer-shares` from origin/main 71e540d (03-08g merged as PR #83).
- PR: #84 (open, without auto-merge). Required check runs on 7bdcc26: 41819306542, 41819306555, 41819306556, 41819306557, 41819306594, 41819306596, 41819306601, 41819306649, 41819306675 and 41819306754. All 26 required checks passed.

## Commits

| Task | Commit | Message |
|------|--------|---------|
| 1 | ca35019 | fix(signer): refuse directories host agents cannot render at install (F07) |
| 2 | 5a0cf65 | fix(signer): per-account connection shares in the accept loop (F16) |
| 3 | 30d40c5 | fix(signerclient): server calls return only after the signer's close (F16) |
| 4 | 7bdcc26 | docs(03-08h): runbook notes on render limits and signer connection limits |
| 4 | (this) | docs(03-08h): complete signer-shares plan |

## Execution stop at Task 1, and the owner's decisions (2026-11-04)

The first implementation of fileSize called AccountPrincipals per account. That call scans the host group and builds and sorts a set. `check_renderable_is_fast_enough` then measured, under -race:

| Shape | Before | After E-1 (two runs) |
|---|---|---|
| Normal path, 2048 accounts × ~60 KiB, against an installed version of the same shape | 0.879 s, 0.871 s | 0.116 s, 0.118 s |
| Plan-literal exception shape, 4096 accounts × ~60 KiB in both versions | 2.25 s (probe) | 0.231 s, 0.252 s |
| Every file above the bound and unchanged, so every file is sized in both versions | 4.84 s, 4.91 s | 0.483 s, 0.560 s |

- The "before" figures without -race were 0.27, 0.55 and 1.14 s, on 16 CPUs.
- The plan's 2 s bound fired, and the executor stopped and reported.
- The plan also contradicted itself in that case. Under the rule a file within the bound never consults the installed version, so the literal ~60 KiB shape does not "size every file in both versions". Both readings are now timed.

The owner decided (Daniel, 2026-11-04):
- **E-1.** Keep the 2 s bound, and rewrite the sizing:
  - Roles are indexed by name and principals by number, once per directory.
  - Each account's roles are walked once, deduplicated by a per-account stamp, with no sort and no cache by role list.
  - Sizes are exactly the same. TestSizerMatchesRender pins them on eight varied directories: 550 accounts with overlapping roles, plus accounts with no roles, twin roles and repeated role names. Each size is compared with the header at math.MaxUint64 plus AccountPrincipals, and with len(RenderPrincipalsFile) at the widest version.
- **E-2.** Refuse a host's move in the signer when its intermediate would exceed the agent's caps.

Both decisions are recorded in the committed plan: truth 2, the owner decisions block, Task 1, the mutant list, Edge Coverage, Task 4's runbook note and ledger round 4.

## Test time (03-08k's limits: 400 s alone, 480 s under ./...)

| Reading | internal/agent/apply `ok` line |
|---|---|
| Base alone (71e540d, before any edit) | 371.173 s |
| Base under ./... (71e540d) | 403.890 s (internal/server 135.365 s, internal/signer 392.448 s) |
| After Task 1, first implementation (stop) | FAIL 329.787 s, only `check_renderable_is_fast_enough` failing |
| After Task 1 with E-1/E-2, alone | 397.977 s (exit 0, within 400 s, with little room) |
| Task 4, under ./... (margin gate, exit 0) | 424.694 s |
| Task 4, full gate ./... | 358.942 s |

Other readings:
- Under ./... in Task 4: internal/signer 404.585 s and internal/server 175.174 s.
- Task 3's verify: internal/signer 351.278 s and internal/server 155.183 s.
- CI build-test on 7bdcc26: 11 m 10 s. Inside it: internal/agent/apply 241.171 s, internal/signer 285.666 s, internal/server 128.452 s, internal/directory 5.080 s, internal/signerclient 2.705 s.
- The apply alone readings vary from 330 to 398 s on this machine, against 335 s recorded on 741e2f6. TestRenderable adds about 9 s, run sequentially.

## RED evidence

**Task 1, origin/main's code** (TestDirectoryUnrenderable with literals). All four refusal cases failed at directory_test.go:851, `install: &{Version:2 ...}, <nil>; want the refusal directory_unrenderable` (Version:3 for the growth case). The install was *accepted*:
- `principals_file_above_cap`
- `host_group_above_account_share`
- `host_group_at_agent_cap`
- `above_cap_installed_growth_refused`

**E-2, against Task 1's pre-E-2 render.go** (origin/main checks nothing, so it accepts too). `host_moved_above_agent_cap_refused` failed with `install: &{Version:3 ...}, <nil>; want the refusal directory_unrenderable`. The two control cases passed.

**Task 2, Task 1's head (ca35019).** `own_share_full_next_closed` read `i/o timeout` instead of EOF: the 17th connection got a slot and its handler waited for s.mu. TestOverloadDoesNotStallAccept passed there with its old setup. With the share in place and the old setup it fails with "count 19 overloaded connections, want 3", which is why it got the new setup.

**Task 3.**
- On a Client stub that ignored AwaitClose, three TestAwaitClose cases failed:
  - `returns_after_close` returned while the connection was held;
  - `refusal_awaits_close` returned the refusal while the connection was held;
  - `deadline_ends_wait` returned 49 µs after the frame, not about 300 ms, which is also RED.
- `package_function_unchanged` and `trailing_bytes_ignored` passed on the stub.
- TestSocketSignerAwaitsClose failed on Task 2's head (5a0cf65): Login returned while the connection was held.

## GREEN at once, with the reasons

- `unsigned_unrenderable_refused_for_quorum`: VerifySignatures runs first and refuses `directory_quorum_not_met`. CheckRenderable never sees an unsigned document (T-02-12).
- `above_cap_installed_disable_accepted`: origin/main checks nothing, so it accepts. Its mutant is M11.
- `at_share_installs`, `host_moved_union_fits_installs` and `host_moved_within_share_installs` are controls.
- `other_account_share_full_status_answered` and `slot_released_before_close` are new seams, with no RED on origin/main: there was no per-uid accounting to fill or hold. Their mutants are T2-M2 and T2-M7.

## Shapes and seeding

- **`principals_file_above_cap`:** 65537 bytes at the widest version. That is a 205-byte header plus 507 principals in 16 roles (no users), 506 of them 128 characters long and the last 57. `at_share_installs` uses the same shape with the last principal at 56, for 65536 bytes.
- **Seeding an above-cap installed version:** the test helper `seedDirectory` repeats InstallDirectory's write after its checks: one logTx with InsertDirectory and appendLocked of a DirectoryInstallBody, under s.mu. It then reopens the signer on the store (`e.close(); e.open()`), and loadDirectory loads the directory and verifies it as authorized. No production code or exported hook was added. The same helper ran unchanged on origin/main.

## Mutants (each applied, run against its named test, restored byte for byte; the diff hash is equal before and after)

**Task 1** (13 from the plan, 3 for E-1/E-2). All killed; none was a build failure.

| # | Mutant | Killed by |
|---|---|---|
| M01 | CheckRenderable call removed | TestDirectoryUnrenderable/principals_file_above_cap (install accepted) |
| M02 | account bound MaxAccounts instead of MaxHostGroupAccounts | host_group_above_account_share |
| M03 | `size <= MaxPrincipalsFile` turned into `<` | TestRenderable/file_at_cap_accepted and TestDirectoryUnrenderable/at_share_installs |
| M04 | apply maxPrincipalsFile = 64<<10 - 1 | file_at_cap_accepted ("65536 bytes, above 65535") |
| M05 | call moved before VerifySignatures (own Parse) | unsigned_unrenderable_refused_for_quorum (got directory_unrenderable) |
| M06 | classify entry removed | refuseInstall's class check ("is internal") in principals_file_above_cap, host_group_above_account_share, host_group_at_agent_cap, above_cap_installed_growth_refused and host_moved_above_agent_cap_refused |
| M07 | count comparison instead of subset | above_cap_swap_refused |
| M08 | growth by one account allowed | above_cap_growth_refused |
| M09 | exception for a group with no installed counterpart | new_group_above_share_refused |
| M10 | any file accepted on the exception path | above_cap_file_grown_refused |
| M11 | nil passed as installed in InstallDirectory | above_cap_installed_disable_accepted |
| M12 | fileSize at the real version | rollover_9_to_10_file_at_cap_accepted and rollover_99_to_100_file_at_cap_accepted ("65537 bytes") |
| M13 | corrected in the pre-merge review (R-3): as first described, an AccountPrincipals call on the installed side. The shipped CheckRenderable never calls AccountPrincipals (E-1's sizer replaced it) and cannot return ErrUnknownHostGroup, so that was not a mutant of the shipped code. Re-run as one: the file exception granted to a host group with no installed counterpart | new_group_file_above_bound_refused (`CheckRenderable = <nil>, want ErrUnrenderable`) |
| M14 | E-1: deduplication broken | TestSizerMatchesRender ("sizer 2323 bytes, want 2184") |
| M15 | E-2: moved-host check skipped | host_moved_above_agent_cap_refused and TestRenderable/host_moved_union_above_cap_refused |
| M16 | E-2: moved-host file check skipped | host_moved_to_file_above_bound_refused |

**Task 2.** All killed.

| # | Mutant | Killed by |
|---|---|---|
| T2-M1 | share check removed | own_share_full_next_closed (i/o timeout) |
| T2-M2 | one counter for all uids | other_account_share_full_status_answered (receive error) |
| T2-M3 | put skipped | TestConnSlots/put_frees_and_deletes |
| T2-M4 | the over-capacity log line through s.refuse | own_share_full_next_closed, through "count 2 overloaded, want 1". See below |
| T2-M5 | acceptLimiter check removed | operator_log_names_uid_rate_limited ("40 refused lines, want 1 to 11") |
| T2-M6 | uid logged as tlog.PeerUnknown | operator_log_names_uid_rate_limited |
| T2-M7a | close before release (defers swapped) | slot_released_before_close (EOF while the release waited) |
| T2-M7b | close before release (handle keeps its own deferred Close) | slot_released_before_close |

T2-M4 is killed by its named test, but not by the stall. The accept loop closes the connection before it reaches the log line, so the client sees EOF first. The loop does then block on s.mu, and the refusal is counted twice: once in overloaded and once by refuse's limiter.

**Task 3.** All killed.

| # | Mutant | Killed by |
|---|---|---|
| T3-M1 | AwaitClose ignored | returns_after_close |
| T3-M2 | wait skipped after a refusal frame | refusal_awaits_close |
| T3-M3 | a deadline during the wait turned into an error | deadline_ends_wait (i/o timeout) |
| T3-M4 | the package functions waiting too | package_function_unchanged |
| T3-M5 | socketSigner built without AwaitClose | TestSocketSignerAwaitsClose |

## The two real-socket runs on Task 2's head (temporary copy, deleted)

The copy called the package-level `signerclient.Status` and `GetKRL`, which do not wait for the close, on 5a0cf65:

| Case | -race, 3 runs | without -race, 3 runs |
|---|---|---|
| `server_budget_within_share` (12 Status callers + 1 GetKRL, 2 s) | 0 / 0 / 0 refusals | 0 / 0 / 0 |
| `share_exact_never_refused` (16 Status callers, 2 s) | 0 / 0 / 0 | **1 / 2 / 1** overloaded refusals |

The committed cases go through `Client{AwaitClose: true}`. Under -race they had 0 refusals in 10 of 10 repeats each (verify), and without -race also 0 in 10 of 10 each. No stop rule fired.

## Existing assertions that moved

- **TestOverloadDoesNotStallAccept** keeps its name and meaning with a new setup. A foreign uid's share (16) is pre-filled in the accounting, then 16 idle connections as the test's uid fill the global cap with s.mu held. The 3 extra connections close at once, and the summaries count 3. With the old setup (32 idle connections as one uid), the 17th is already refused under the share and the count is 19.
- **TestReadResponseRefusesUnexpectedType:** its three readResponse calls gained the new `await` argument (`false`). The assertions are unchanged.
- Every other refusal, socket, KRL-loop, log and peer_not_allowed test in internal/signer passes unchanged. TestSignerBudget (including `total_bounded` and `catch_up_bounded_interactive_room`, expressed via maxSignerCalls) and TestAgentInFlight pass unchanged with `maxSignerCalls = wire.MaxServerSignerCalls`.

## Gates (Task 4)

- Full gate: exit 0. It covers go test -race ./..., go vet (including the e2e and systemdsmoke tags), gofmt, golangci-lint (0 issues), capslock-check, dep-firewall, testonly-firewall (clean, 6 combinations) and check-pinned-actions (47 pinned).
- capslock: no new pair. keyroster-signer has 92 pairs, keyroster-agent 37 and keyroster-agent-fetch 23, each equal to its baseline.
- dep-firewall: exit 0, and `go list -deps ./cmd/keyroster-signer | grep -c keyroster/internal/agent` prints 0.
- `git diff --name-only origin/main...HEAD -- cmd/` is empty.
- **e2e under one uid.** test/e2e has no t.Parallel. Its two `go func`s wait on child processes (harness_test.go:141, login_test.go:49). The only concurrent signer use is two `keyroster login` processes at login_test.go:509, both relayed through the server. No test has more than 3 extra signer calls in flight beside the server, so no local e2e run was required. The CI e2e jobs on 7bdcc26 all passed, with no connection closed unanswered: e2e (9.5p1) 9 m 52 s, e2e (10.5p1) 9 m 51 s, seven e2e-distro jobs, two e2e-pkcs11 jobs, e2e-tpm and systemd-sandbox.

## Deviations from Plan

1. **Owner decision (2026-11-04), execution stop at Task 1: E-1.**
   - The sizer replaces the per-account AccountPrincipals call.
   - The new internal/directory/render_size_test.go (TestSizerMatchesRender) is a new test file.
   - The timed case now times three shapes. The all-files-above-bound shape is added, because under the rule the literal ~60 KiB shape does not consult the installed version (a contradiction in the plan text).
2. **Owner decision (2026-11-04), execution stop at Task 1: E-2.** The moved-host check:
   - checkMoves matches active entries by a shared host key, as the agent finds its entry. A disabled entry renders no principals on either side, so it is skipped.
   - It refuses when the union of the old group's accounts (installed) and the new group's (offered) is above MaxAccounts, or when a file of the new group is above MaxPrincipalsFile. That file may be accepted for the group's own hosts under Q-G7, but the moving host never rendered it.
   - Tests: 3 new TestDirectoryUnrenderable cases (seeded v2 with lab 3000, web 2048 and db 1096 accounts) and 3 TestRenderable cases that check the same moves with the agent's own Intermediate and checkLimits. An enroll-user.md note.
   - Same-name groups stay under the Q-G7 subset rule, so a disable under a never-rendered directory installed before this release still goes through.
3. **readResponse gains an `await` parameter**, instead of a second reader in roundTripRead, so there is one path. The existing test's calls pass `false` (mechanical).
4. **TestAwaitClose lives in client_test.go**, as the plan names. Its holdSigner is a new helper beside startSlowSigner. `deadline_ends_wait` was also RED on the stub, by its timing assertion.
5. **Tooling:** the first Task 1 mutant run used a Python subprocess whose `bash` resolved to WSL's bash.exe. Go was not found, so nothing ran and every mutant was reported as surviving. The runner was pointed at Git Bash and every mutant re-run. The table above is from the re-run.

## Closed: the moved-host check's time under the signer's lock (R-1, pre-merge review of PR #84)

Closed by R-1 (see "Pre-merge review fixes (PR #84)"): the same shape now takes about 0.15 s under -race. The figures below are from before the fix.

A temporary, uncommitted probe (deleted) timed CheckRenderable under -race. The installed version had host groups lab (3000 accounts) and web (1000), and the offered version moved 5000 active hosts from lab to web:

| Keys per host | Time | Result |
|---|---|---|
| 1 | 3.50 s | accepted |
| 4 | 13.15 s | accepted |

Both are above the 2 s bound that the owner keeps for the work under s.mu. The cause is checkMoves: it builds the union map of both groups' accounts (unionAccounts) once per matching host key.

The two fixes proposed here (the union once per (from, to) pair, and no count while the two groups' sizes add up to at most 4096) were both applied in R-1.

The three shapes of `check_renderable_is_fast_enough` have no host moves and are unaffected.

## Pre-merge review fixes (PR #84)

Three findings on PR #84 at 75620a1. All are fixed on the branch, each with its own commit. The owner decided how (owner decision (2026-11-04), pre-merge review).

| Finding | Commit | Message |
|---|---|---|
| R-1 | 4aa3178 | perf(directory): index host groups once and count move unions per group pair (R-1) |
| R-2 | d5e9b68 | fix(directory): treat a same-named host in another host group as a move (R-2) |
| R-3 | f4292a8 | test(directory): moved-host cases that change the groups and use several keys (R-3) |
| all | (this) | docs(03-08h): pre-merge review fixes for PR #84 |

### R-1 (medium): the moved-host check and the host group lookup under s.mu

**Fix.** Changes in internal/directory/render.go:
- `hostGroupIndex` maps each host group name to its index, once per directory. It keeps the first index for a repeated name, as `slices.IndexFunc` did. CheckRenderable uses it for the installed counterpart, and the moved-host check uses it for both versions.
- `moveUnions.count` counts a move's union once per (from, to) pair:
  - It counts nothing while the two groups' list lengths add up to at most 4096. The union cannot exceed that sum, duplicates or not.
  - Otherwise it builds the installed from-group's account set once per from-group, and counts the target's accounts that are not in it, each once.
- The target group's file check (`aboveBound`) still runs first, before the count and independently of it.

**Same answers.** `TestCheckRenderableMatchesReference` keeps a test-only copy of the previous CheckRenderable, checkMoves and unionAccounts. For R-2's commit, that copy also gains the match by name, as a scan. On 48 drawn pairs the two give the same accept or refuse, with the same error text, so the same first failing host:
- host groups of 0 to 4096 accounts, drawn as runs of one name pool so overlaps vary;
- accounts with a file above the bound;
- hosts with 1 to 4 keys from a pool of 12, so keys repeat across hosts;
- disabled hosts, hosts in a group the other version lacks, and renamed hosts.

The draws reach every kind of answer: 30 accepted, 3 move-union refusals, 10 move-file refusals and 5 others. The test fails if any kind is missing. The draws do not show the counted path (sum above 4096, union within) separately. `hosts_moved_into_overlapping_group` and `overlap_at_cap_accepted` pin that path.

**Timed cases.** `TestCheckRenderableFastEnough` is in internal/directory, outside apply's budget. It has no t.Parallel and a 2 s bound per shape. Run under -race on this machine:

| Shape | At 75620a1 (RED) | After R-1 |
|---|---|---|
| 5000 hosts with 4 keys each, moved from lab (3000 accounts, above the share) to web (1000), accepted | 14.06 s | 0.157 s |
| The same hosts moved into web of 1100 accounts, 100 of them lab's (sum 4100, union 4000), accepted | 14.33 s | 0.153 s |
| 30000 host groups with no accounts in both versions (960235 bytes, within wire.MaxDirectory) | 6.05 s | 0.132 s |

**More tests.** `TestMoveUnion`:
- `per_group_pair`: h0 moves from db to web, which fits; h1 moves from lab to web, 4097 accounts, refused;
- `overlap_at_cap_accepted`: lab 3000 and web 1097 with one shared account, a union of exactly 4096.

**Mutants.** Each was applied to the working tree and compiled (`go vet`), then run against its test, then restored. The file's SHA-256 was equal before and after each one.

| # | Mutant | Killed by |
|---|---|---|
| R1-M1 | union cached by the target group only | TestMoveUnion/per_group_pair (`CheckRenderable = <nil>`) |
| R1-M2 | count skipped up to MaxAccounts + 1 | TestMoveUnion/overlap_at_cap_accepted (4097 refused) |
| R1-M3 | target accounts counted without excluding the from group's | TestCheckRenderableFastEnough/hosts_moved_into_overlapping_group (4100 refused) |
| R1-M4 | file check only when the union is counted above the cap | TestRenderable/host_moved_to_file_above_bound_refused |

R1-M2 first survived TestMoveUnion's first case. The skip returns the sum, and for two disjoint groups the sum is the union. `overlap_at_cap_accepted` was added for it. The first-index rule of `hostGroupIndex` matters only for repeated names, which Validate refuses. No test pins it, and no mutant was run on it.

### R-2 (low): a host whose keys are all replaced and that moves

**Fix.** Owner decision (2026-11-04), pre-merge review. checkMoves indexes each active installed host by name, once, keeping the first entry of a name, as HostByName does. For each active offered host it checks:
1. the installed entries of its keys, in key order, as before;
2. then the entry with its name.

Both are checked with the same rules. Old answers change only where a move is found by name alone.

The doc comments of CheckRenderable and checkMoves say this. enroll-user.md, next to the move note, says that a host renamed *and* rekeyed in the same version is still not recognised as moved. That is labelled as a limitation and UNVERIFIED, with the advice to rename and rekey in separate versions.

**Tests and RED.** Each RED below was run at R-1's head, with the tests in place before the fix:

| Test | RED |
|---|---|
| TestMoveByName/rekeyed_and_moved_above_cap_refused | `CheckRenderable = <nil>, want h1's move refused with 4097 accounts` |
| TestRenderable/host_rekeyed_and_moved_union_above_cap_refused (also checks `agentMove`: Intermediate plus checkLimits gives ErrGenerationTooLarge) | `CheckRenderable = <nil>, want ErrUnrenderable` |
| TestDirectoryUnrenderable/host_rekeyed_and_moved_above_agent_cap_refused (v3 with a fresh host key, moved to web) | `install: &{Version:3 ...}, <nil>; want the refusal directory_unrenderable` |

Controls, which passed before and after:
- TestMoveByName/rekeyed_and_moved_at_cap_accepted;
- TestMoveByName/disabled_installed_host_not_a_move;
- TestDirectoryUnrenderable/host_rekeyed_and_moved_union_fits_installs (moved to db, 3000 + 1096).

**Mutants.**

| # | Mutant | Killed by |
|---|---|---|
| R2-M1 | match by name removed | TestMoveByName/rekeyed_and_moved_above_cap_refused, TestDirectoryUnrenderable/host_rekeyed_and_moved_above_agent_cap_refused and TestRenderable/host_rekeyed_and_moved_union_above_cap_refused (each run separately) |
| R2-M2 | name index includes disabled installed entries | TestMoveByName/disabled_installed_host_not_a_move |

### R-3 (low): moved-host tests that never change the groups, and an unreachable assertion

**(a) Fix.** `TestMoveGroupsAndKeys` in internal/directory has four cases:
- `target_grown_in_offered_refused`: web has 500 accounts in installed and 1097 offered;
- `source_shrunk_in_offered_refused`: the offered lab keeps 2000 of installed's 3000, and web has 2000. The move holds 5000 accounts;
- `shared_key_last_of_four_refused`: a host renamed with three of four keys replaced. The shared key sorts last in both versions;
- `second_matching_host_refused`: the first key was a db host's (fits) and the second a lab host's.

These are test-only additions to correct code, so they passed at once. Their RED is the mutants below.

| # | Mutant | Killed by | Pre-existing move tests |
|---|---|---|---|
| R3-M1 | target group taken from installed | target_grown_in_offered_refused | survived TestRenderable and TestDirectoryUnrenderable `host_moved*` (the finding) and TestMoveUnion, TestMoveByName and TestCheckRenderableFastEnough |
| R3-M2 | source group taken from the offered version | source_shrunk_in_offered_refused | not run |
| R3-M3 | only the offered host's first key | shared_key_last_of_four_refused, second_matching_host_refused | survived TestRenderable and TestDirectoryUnrenderable `host_moved*` (the finding) |
| R3-M4 | only the installed host's first key indexed | shared_key_last_of_four_refused | not run |
| R3-M5 | only the first matching installed entry checked | second_matching_host_refused | not run |

The survivor runs were checked to execute their tests. The same `-run` pattern on the unmutated tree ran three TestRenderable and three TestDirectoryUnrenderable `host_moved*` subtests.

**(b) Finding.** `new_group_file_above_bound_refused` also asserted `!errors.Is(err, directory.ErrUnknownHostGroup)`. The shipped CheckRenderable never calls AccountPrincipals, because E-1's sizer replaced that call. None of its paths returns ErrUnknownHostGroup. Its errors wrap a single `%w`, so a refusal that is ErrUnrenderable cannot also be ErrUnknownHostGroup. The assertion could not fail.

**(b) Fix.** The assertion is replaced. The refusal must now name `host group web account root` and `principals file of 65537 bytes, above 65536`: the file refusal, because installed has no web to grant an exception. M13's description in the mutant table above is corrected. M13 was re-run as a mutant of the shipped code (the file exception granted to a host group with no installed counterpart) and was killed by new_group_file_above_bound_refused (`CheckRenderable = <nil>, want ErrUnrenderable`).

### Gates on f4292a8 (before this docs commit)

| Gate | Figure |
|---|---|
| Alone gate, internal/agent/apply alone under -race | 317.624 s, exit 0 (limit 400 s) |
| Margin gate, apply's `ok` line under ./... | 376.394 s, exit 0 (limit 480 s). internal/signer 393.932 s, internal/server 145.255 s, internal/directory 16.461 s |
| Full gate (Task 4's command) | exit 0. apply 361.464 s, internal/signer 387.606 s, internal/server 124.809 s, internal/directory 16.497 s |

The full gate includes:
- go vet with the e2e and systemdsmoke tags, and gofmt;
- golangci-lint, 0 issues;
- capslock-check: keyroster-signer 92 pairs, keyroster-agent 37 and keyroster-agent-fetch 23, each equal to its baseline;
- dep-firewall, testonly-firewall (clean, 6 combinations) and check-pinned-actions (47 pinned).

`go list -deps ./cmd/keyroster-signer | grep -c keyroster/internal/agent` prints 0, and `git diff --name-only origin/main...HEAD -- cmd/` is empty.

### Observation, not fixed (outside R-1's scope)

Parse's validateHosts scans the host groups once per host (`slices.ContainsFunc`), O(hosts × host groups), and InstallDirectory parses under s.mu. A temporary probe (uncommitted, deleted) parsed a valid directory of 935245 bytes:
- 15000 host groups;
- 2500 hosts with real Ed25519 keys, all in the last group.

It took 1.86 s under -race and 0.156 s without. This is not a finding of this review, and it is left as it is.

## UNVERIFIED

- Every runbook note on a real host: the render-limit refusal, the above-cap rules, the split advice, the host-move refusal, the connection limits, the journal lines and the slow-signature behaviour. All are run in CI only, through the named tests (owner decision: no 03-16 drill provokes these limits).
- That the CLI's error names `directory_unrenderable`. This is reasoned from serverclient's error text; no test runs the CLI against the refusal.
- The slow-signature pile-up with a real hardware touch (T-03-307 residual). It is reasoned, not tested.
- A host renamed *and* rekeyed in the same version that also moves group. checkMoves matches by a shared host key or, since R-2, by name, so it does not find that host; enroll-user.md states the limitation. The rekeyed-and-moved case (host_keys_rotated on its agent) is now tested (R-2). A host whose sshd keys match two entries of the offered version (host_keys_disagree on its agent) and that moves: each offered entry is checked against installed on its own, but no test sets that case up.

## Known Stubs

None.

## Threat Flags

None. No new endpoint, file access or schema. The new surface is in the plan's threat model (T-03-306, T-03-307, T-03-310, T-03-313, T-03-315). E-2 adds a refusal only.

## Self-Check: PASSED

- Created files exist: internal/agent/apply/renderable_test.go, internal/directory/render_size_test.go, 03-08h-PLAN.md and 03-08h-SUMMARY.md.
- Commits ca35019, 5a0cf65, 30d40c5 and 7bdcc26 are ancestors of HEAD. `git rev-list --count 71e540d..HEAD` is 4 before this SUMMARY's own commit.
- Pre-merge review fixes: internal/directory/render_moves_test.go exists, and commits 4aa3178, d5e9b68 and f4292a8 are ancestors of HEAD.
