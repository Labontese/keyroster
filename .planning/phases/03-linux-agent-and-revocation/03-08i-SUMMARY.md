---
phase: 03-linux-agent-and-revocation
plan: 08i
subsystem: signer
tags: [signer, status, snapshot, trust, server, e2e, revoke-02, agent-02]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08g (budgetSigner with Status inside the budget and GetKRL outside it, currentStatus's coalesced refresh, statusTTL, statusTimeout, krlTTL, the fakeSigner hold hooks); 03-08h (the per-account share and the release ordering); 03-01 (Signer.krl, the atomic.Pointer precedent); signerdb.OpenReadOnly (export, doctor)"
provides:
  - "signer: Config.StatusDB (a read-only handle; New refuses one equal to DB), the status atomic.Pointer[statusSnapshot], bundleRow (the trust_bundle row loaded at start), statusSnapshot, newStatusSnapshot, publishStatusLocked, copyReply, setDirectoryLocked (the one writer of the directory state) and readDirectory"
  - "signer: Status takes no lock and reads nothing through the main handle; it checks the latest bundle version through StatusDB on every call (checkTrustCurrent) and refuses state_unavailable without a handle, on a read error or a cancelled ctx"
  - "cmd/keyroster-signer: serve opens signerdb.OpenReadOnly after the main handle and closes it first"
  - "tests: TestStatusLockFree (10), TestStatusSnapshot (6), TestStatusWriters, the snapshot check in wantDirectory (21 call sites), TestRoutesPastStatusTTLWithHeldCall (2), TestDeliveryDuringHeldSignature (e2e) with its gated agent proxy and serverOpts.SignerServe"
  - "docs: server-install.md (the routes during a long touch, start-up during a signature, /healthz), signer-install.md (the status during a slow signature, how long a signature can hold the lock, what a superseded bundle refuses)"
  - "planning: 03-08i at wave 20, 03-09 to 03-16 one wave later, 03-09 depends on 03-08i; the Q-I4 pointer after five sentences of 03-08g and 03-08h"
affects: [03-09, 03-10, 03-12, 03-13, 03-16]

requirements-completed: []

actuals:
  tokens: 25400
  tasks: 4
  commits: 8
plan_head_before: d8199045c3b4f3d0e2ec5d844930f5fb421d0d04
plan_head_after: 8ad8178bf23b97dbb85c91b77cbea0063832effb

tech-stack:
  added: []
  patterns:
    - "An immutable reply snapshot behind an atomic.Pointer, published by the one setter of the state it reports, after COMMIT"
    - "A second, read-only SQLite handle for a check that must not wait for the main handle's one connection"
    - "A syntactic writers gate (go/parser) with an allowlist that fails when an entry goes stale"
    - "A gated ssh-agent proxy (agent.ServeAgent over agent.NewClient) that holds one signature in an e2e test"

key-files:
  created:
    - internal/signer/statussnapshot_test.go
    - internal/signer/statuswriters_test.go
    - test/e2e/stall_test.go
    - .planning/phases/03-linux-agent-and-revocation/03-08i-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md
  modified:
    - internal/signer/status.go
    - internal/signer/signer.go
    - internal/signer/directory.go
    - internal/signer/issue.go
    - cmd/keyroster-signer/serve.go
    - internal/signer/log_test.go
    - internal/signer/status_test.go
    - internal/signer/directory_test.go
    - internal/server/capacity_test.go
    - test/e2e/server_test.go
    - docs/runbooks/server-install.md
    - docs/runbooks/signer-install.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (and the wave lines of 03-10 to 03-16)

key-decisions:
  - "Q-I1 B (Daniel, 2026-11-05): Status checks the latest bundle version through a second, read-only handle (Config.StatusDB, opened by serve) on every call, without s.mu, and refuses trust_changed on a mismatch; a missing handle, a read error or a cancelled ctx refuses state_unavailable"
  - "Q-I2 A (Daniel, 2026-11-05): Status stays inside keyroster-server's budget; with every token held the routes still answer 503 past statusTTL (budget_full_status_waits)"
  - "Q-I3 A (Daniel, 2026-11-05): GetDirectory keeps taking s.mu; a cold mirror leaves the host routes at 503 until the signature ends"
  - "The snapshot is the whole reply, built by statusResponse at each directory change; setDirectoryLocked is the only writer of the directory state and the only caller of publishStatusLocked; InstallDirectory calls it after COMMIT and before it answers"
  - "Every reply carries the trust_bundle row this process loaded and checked against the log at start (bundleRow), never a row read later; an emptied trust_bundle table is refused trust_changed, as issuance refuses it"

metrics:
  completed: 2026-11-05
---

# Phase 3 Plan 08i: Signer Status without the lock Summary

The signer answers Status from an immutable snapshot that is published after every committed directory change, without taking its lock or touching its main database connection. It still checks, on every call and through a separate read-only handle, that the bundle it loaded is the latest. So keyroster-server's KRL route and host routes keep answering while a slow signature holds the lock, and a bundle installed under the running signer is still refused at once.

## CI

On head a55b82d (everything before this CI note), all 26 required checks passed:
- build-test 8m58s, with `internal/signer` 244.651 s, `internal/server` 107.710 s and `internal/agent/apply` 199.325 s;
- fuzz 25m21s, lint, capslock, govulncheck and dependency-firewall;
- e2e (9.5p1) 10m11s and e2e (10.5p1) 9m52s, seven e2e-distro jobs, two e2e-pkcs11 jobs, e2e-tpm and systemd-sandbox;
- cli-windows, cli-macos, build-piv, pinned-actions, pr-title and the two CodeQL analyses.

**The e2e GREEN.** The PR's e2e run is 41994732631:
- e2e (9.5p1): `--- PASS: TestDeliveryDuringHeldSignature (13.52s)`, `the signature was held for 2.001841055s`.
- e2e (10.5p1): `--- PASS: TestDeliveryDuringHeldSignature (13.55s)`, `the signature was held for 2.000008833s`.

The checks on the commit that adds this note are waited for after its push.

## Delivery

- Branch `p03/08i-status-snapshot` from origin/main d819904 (03-08h merged as PR #84), created by the owner before execution.
- PR: **#85**, opened by keyroster-bot without auto-merge. Daniel reviews and squash-merges it.
- Required check runs on a55b82d: 41994732534, 41994732538, 41994732539, 41994732540, 41994732544, 41994732571, 41994732597, 41994732598, 41994732627 and 41994732631.

## Commits

| Task | Commit | Message |
|------|--------|---------|
| - | 4e2e8f7 | docs(03-08i): add status-snapshot plan |
| 1 | 89d3d3e | fix(signer): answer Status from a snapshot without the signer's lock |
| 1 | 845d870 | test(signer): summarize Status replies in TestStatusLockFree failures |
| 1 (T1) | c798c18 | test(signer): report New's StatusDB refusal without printing the signer |
| 2 (T2) | 824f8d5 | test(signer,server): gate the Status snapshot's writers and pin the routes past statusTTL |
| 3 (T3) | 3a93b18 | test(e2e): deliver the KRL and an agent's state during a held signature |
| 4 | f2ed388 | docs(runbooks): the signer's status during a slow signature, and what a superseded bundle refuses |
| 4 | 8ad8178 | docs(03-08i): slot the status-snapshot plan into wave 20 and point the landed plans at it |
| 4 | a55b82d | docs(03-08i): complete status-snapshot plan |
| 4 | e2a09f7 | docs(03-08i): record the PR's checks in the SUMMARY |
| fix 1 | 79d8e71 | docs(server): name the late commit after an unknown revoke or install outcome |
| fix 1 | fd374fa | test(signer): refuse aliases of the trust state and pin directoryState's fields |
| fix 1 | (this) | docs(03-08i): record review fix round 1 |

## Test time (03-08k's limits: 400 s alone, 480 s under ./...)

All readings are local, under WSL (`bash scripts/linux.sh`, -race -count=1).

| Reading | internal/agent/apply | internal/signer |
|---|---|---|
| Base, origin/main code (before Task 1's first edit), apply alone | 369.511 s | - |
| Base, origin/main code, `./...` | 359.077 s | 370.595 s |
| Task 1, `./internal/signer/ ./cmd/keyroster-signer/` | - | 326.489 s |
| Task 2, `./internal/signer/ ./internal/server/ ./internal/signerclient/ ./cmd/...` | - | 295.659 s (internal/server 107.480 s) |
| Task 4, apply alone | 353.907 s | - |
| Task 4, full gate `./...` | 360.204 s | 380.519 s (internal/server 129.845 s) |

No reading is above its limit, so the stop rule did not fire.

## RED evidence

**Task 1, TestStatusLockFree on origin/main's production code** (the test file only, with the helper opening no read-only handle, `-timeout 120s`, local). `--- FAIL: TestStatusLockFree (51.28s)`:
- `answers_with_mu_held` (10.18 s): `status_test.go:453: answers_with_mu_held: no answer within 10 s (Status waits for the signer's lock or its main connection)`.
- `answers_during_ca_signature` (10.14 s): `status_test.go:479: answers_during_ca_signature over the socket: no answer within 10 s`.
- `answers_during_log_key_signature` (10.13 s): `status_test.go:479: answers_during_log_key_signature over the socket: no answer within 10 s`.
- `successor_refused_while_mu_held` (10.15 s): `status_test.go:509: successor_refused_while_mu_held: no answer within 10 s`.
- `successor_refused_during_ca_signature` (10.15 s): `status_test.go:535: successor_refused_during_ca_signature direct: no answer within 10 s`.
- `emptied_bundle_table_refused`: `status_test.go:557: Status with the trust_bundle table emptied = <nil>, unavailable: state_unavailable; want no reply and errTrustChanged`.
- `reply_carries_loaded_bundle`: `status_test.go:573: Status after the policy was edited in place: version 1, policy equal to the loaded one false; want the row the signer loaded`.
- Each of the five lock cases ended in its named hang-guard failure, not a binary timeout.

**GREEN at once on origin/main, with the reason.** `install_then_status_over_socket` (0.17 s) and `failed_transaction_keeps_snapshot` (0.15 s) passed: a locked Status reads the directory fields, which InstallDirectory writes before it answers and only after COMMIT.

**`status_db_missing_or_failing_refuses`** was written after Config.StatusDB existed. Its RED was taken against a Status that ignores the handle: nil handle and read errors are skipped and the snapshot is answered (mutant `red_status_db_ignored`). It failed at the first sub-case: `status_test.go:576: without StatusDB: Status = <a full reply>, <nil>; want no reply and a state_unavailable refusal (unavailable)`.

**Task 2.**
- TestStatusWriters' rules fail on origin/main. The non-test internal/signer/*.go files of origin/main were copied to a temporary directory and passed to `statusWriterViolations` from a temporary test, which was deleted afterwards. It listed 20 violations:
  - five direct field writes in loadDirectory (directory.go:58 three, :65, :87) and five in InstallDirectory (directory.go:190 to 194);
  - placement: no `ds, err := s.readDirectory(` in loadDirectory, and no top-level setDirectoryLocked call in InstallDirectory;
  - setDirectoryLocked, publishStatusLocked, readDirectory and newStatusSnapshot declared 0 times;
  - loadDirectory and InstallDirectory call setDirectoryLocked 0 times, and setDirectoryLocked calls publishStatusLocked 0 times;
  - publishStatusLocked stores the snapshot 0 times.
  The allowlist entry (`ts.caKeys` in trust.go's loadTrust) matched there too.
- The TestStatusSnapshot cases and the wantDirectory check are pins of Task 1's code, as the plan states.
- `refused_status_waits_for_refusal_log` is GREEN on origin/main too, as the plan expects, because there the whole Status waits for the lock. It was run in a temporary detached worktree of origin/main, with the test files adapted to open no read-only handle: `--- PASS: TestStatusSnapshot/refused_status_waits_for_refusal_log (0.36s)`. The worktree was removed afterwards.
- TestRoutesPastStatusTTLWithHeldCall runs against the test double, whose Status never waits, so neither case has a RED on origin/main. It pins the server's half; the e2e case proves the whole.

**Task 3, TestDeliveryDuringHeldSignature on origin/main, from CI.**
- The throwaway branch `p03/08i-e2e-red` was built from origin/main plus the two test files only (commit 9a61cdb). `git diff --name-only origin/main...p03/08i-e2e-red` listed exactly test/e2e/server_test.go and test/e2e/stall_test.go before the push.
- Dispatched run **41991864014** (`workflow_dispatch`, e2e.yml, head 9a61cdb):
  - e2e (9.5p1): `stall_test.go:243: held-signature krl: got 503`, `stall_test.go:256: held-signature state: state: https://keyroster.localhost:<port>: the server cannot reach its signer (HTTP 503); try again later`, `--- FAIL: TestDeliveryDuringHeldSignature (19.57s)`. The signature was held for 8.00 s, and the issue still exited 0 after the release.
  - e2e (10.5p1): the same two lines, `--- FAIL: TestDeliveryDuringHeldSignature (18.48s)`, held 8.00 s, the issue exited 0.
  - No other `--- FAIL:` line. Task 3's RED verify command passed on this log.
- The branch was then deleted on origin and locally. `git ls-remote --exit-code origin p03/08i-e2e-red` exits 2. No PR was opened from it.
- Local e2e cannot run on this machine. Only `go vet -tags e2e ./test/e2e/` and gofmt ran locally. The test's GREEN run is the PR's own e2e run.

## Mutants (each applied by a script, run with `-timeout 120s` against its named test, restored with `git checkout -- <file>`, and `git diff --quiet` over internal/, cmd/ and test/ checked afterwards)

Task 1 (all killed):

| Mutant | Killed by |
|---|---|
| Status takes s.mu again | `answers_with_mu_held` (:462), `answers_during_ca_signature` (:488), `answers_during_log_key_signature` (:488), `successor_refused_while_mu_held` (:518), each by its 10 s hang guard |
| The version read through the main handle (`s.db.LatestBundleVersion`) | `answers_during_log_key_signature`: Status over the socket, no answer within 10 s |
| The trust check removed (read errors still refuse; the version is not compared) | TestStatusTrustChanged (:152), `successor_refused_while_mu_held` (:531), `successor_refused_during_ca_signature` (:557) |
| On a read error, skip checkTrustCurrent and answer the snapshot | `status_db_missing_or_failing_refuses`: with a cancelled ctx (:597) |
| A nil statusDB answered from the snapshot | `status_db_missing_or_failing_refuses`: without StatusDB (:587) |
| New accepting a StatusDB equal to DB | `status_db_missing_or_failing_refuses` (:590) |
| setDirectoryLocked without its publish | `install_then_status_over_socket`. The kill comes at the helper's first Status (state_unavailable), because loadDirectory's call publishes nothing either, so no snapshot exists |
| setDirectoryLocked called in InstallDirectory before logTx | `failed_transaction_keeps_snapshot` (:671, directory 2 reported after the failed install) |
| The reply built from a fresh read of the bundle row | `reply_carries_loaded_bundle` (:628) |
| serve without StatusDB | Reasoned, not run (UNVERIFIED). Every e2e server start would fail at probeStatus (cmd/keyroster-server/serve.go:76), because every Status would refuse state_unavailable |

Task 2 (all killed):

| Mutant | Killed by |
|---|---|
| publishStatusLocked keeps one snapshot and changes its fields in place after the first Store | `no_torn_reply`: four DATA RACE reports (the pairs themselves matched) |
| The copy omits PolicySigs, sharing it with the snapshot | `reply_is_a_copy` (:109, PolicySigs) |
| Status ignores the snapshot's err | `too_large_refused` (:127) |
| The nil-snapshot branch returns no reply and no error | `nil_snapshot_refused` (:134) |
| A direct `s.directoryVersion = d.Version` next to the setter call in InstallDirectory | TestStatusWriters: directory.go:232 assignment to s.directoryVersion |
| `ds := &s.directoryState; ds.directoryVersion = 0` in InstallDirectory | TestStatusWriters: :232 address-of s.directoryState, :233 assignment to ds.directoryVersion |
| `*s = *s` in InstallDirectory | TestStatusWriters: :232 an assignment through a pointer dereference |
| `s.caKeys[0].Custody = "software"` in InstallDirectory | TestStatusWriters: :232 assignment to s.caKeys[...].Custody (watched caKeys) |
| setDirectoryLocked moved inside the logTx closure after appendLocked | TestStatusWriters: not called as a top-level statement |
| setDirectoryLocked without its publishStatusLocked call | TestStatusWriters: setDirectoryLocked calls publishStatusLocked 0 times |
| A Store of s.status added in Status | TestStatusWriters: status.go:146 s.status.Store |
| A tenth field added to wire.StatusResponse | TestStatusWriters: the field list |
| readDirectory returning authorized after a failed VerifySignatures | TestDirectoryRestart `restart_under_new_admins`, through wantDirectory (directory_test.go:345) |
| readDirectory returning authorized after a failed CheckPolicy | TestDirectoryRestart `restart_under_tighter_cap`, through wantDirectory (:372) |
| server: budgetSigner.Status calls next.Status without a token | `budget_full_status_waits` (capacity_test.go:1182: 200) |
| server: currentStatus serves the cached entry past statusTTL | `krl_and_state_past_status_ttl` (:1171: 0 Status calls) |

The two restart mutants are killed by wantDirectory's existing GetDirectory assertion, which runs before its new snapshot check.

## The allowlist grep (Task 2)

A read-only grep of the package's non-test files on Task 1's head, for writes, `&` and the mutating calls on the watched names, and for fields of a watched name:
- outside directory.go, the only write to a watched name is `ts.caKeys = caKeys` in trust.go (loadTrust), a trustState field;
- the only types with a field of a watched name are directoryState itself, Signer, and trustState (`caKeys`).

So the allowlist is the one entry the plan names. Task 1 introduced no collision.

## Existing assertions that moved

None. Two test helpers gained the read-only handle, with no assertion changed:
- logEnv.open opens one and passes it as StatusDB, and logEnv.close closes it before the main handle. close is nil-safe for it, because login_test.go's `directory_changed_before_commit` sets e.db and e.s by hand.
- serveStatusSigner opens one, for TestStatusTrustChanged (also on its restart) and TestStatusOverSocket.

Every other test that asks a real signer for Status uses one of these two helpers: TestStatusReportsDirectory, and TestPeerShare and shareLoad in overload_test.go. Every other test passed unchanged in Task 1's and Task 2's package runs, including TestStatusTrustChanged, TestStatusOverSocket, TestStatusReportsDirectory, TestDirectoryRestart, the TestDirectoryInstallRefusals cases, TestPeerShare, TestStateDirLock, TestKRLDuringFullBudget, TestSignerBudget, TestConnSlots and TestAgentInFlight.

**Kept sentence edited in signer-install.md.** The clause "although it could otherwise answer those at once" now ends "at once outside a signature that runs inside the signer's database transaction". The plan required this edit.

## Gates (Task 4)

- **Full gate: exit 0.** It covers:
  - `go test -race -count=1 ./...` (no FAIL, no DATA RACE);
  - `go vet ./...`, and `go vet` with the `e2e` and `e2e systemdsmoke` tags;
  - gofmt;
  - golangci-lint (0 issues);
  - capslock-check, dep-firewall, testonly-firewall (clean, 6 combinations) and check-pinned-actions (47 pinned).
- **capslock: no new pair.** keyroster-signer has 92 pairs, keyroster-agent 37 and keyroster-agent-fetch 23, each equal to its baseline.
- **dep-firewall:** exit 0, and `go list -deps ./cmd/keyroster-signer | grep -c keyroster/internal/agent` prints 0. The e2e test imports internal/agent/fetch, which is test code only.
- **Lint of the e2e files:** `golangci-lint run --build-tags e2e ./test/e2e/` reports nothing in stall_test.go or server_test.go. Its 16 issues are all in files this plan does not touch.
- **cmd/:** `git diff --name-only origin/main...HEAD -- cmd/` is exactly cmd/keyroster-signer/serve.go.
- **Scope checks:**
  - Task 1 changes only internal/signer, serve.go and .planning;
  - Task 2 adds tests only;
  - Task 3 changes only test/e2e;
  - internal/server has no code change;
  - test/e2e changes exactly server_test.go and stall_test.go.

## Deviations from Plan

1. **The plan file was committed first** (4e2e8f7), byte for byte, where the plan places it untracked until Task 4. This followed the owner's execution instruction, so that Task 1's precondition could read it. It is unchanged since; `cmp` against the source was re-run at Task 4.
2. **Two small Task 1 test commits after the first.** Failure messages print a reply summary instead of `%+v` of a whole reply or Signer (845d870, c798c18). The first mutant runs printed kilobytes of bytes. No assertion changed. T1 is c798c18.
3. **Task 1's first targeted run** took 33.99 s, with `answers_during_ca_signature` at 25.78 s. Later runs of the same command took 0.15 to 0.28 s for that case (10.85 s in all). No hang guard fired, and the cause was not found. This is recorded, not explained.
4. **startServerEnv's if/else became a switch** with the SignerServe case. Its other branches are unchanged.
5. **The PR was opened without auto-merge, and merge-gate.sh was not run, not even `--check`.** This is the owner's execution instruction, which overrides the plan's `--check` before the merge. The SUMMARY was pushed before the PR was opened, and the PR number and check IDs were added in a later SUMMARY commit.
6. **GSD tooling.** Commits used plain `git commit -S` with Daniel as author, never `gsd-tools commit`. REQUIREMENTS.md was not touched: requirements-completed stays empty, as the plan says.

## UNVERIFIED

- readDirectory's unparsed state as loaded from storage. The setter's handling of it is pinned (`unparsed_state_published`), but no stored state reaches that path today.
- That catch-up reads (GetBundle, GetDirectoryVersion) wait for a transaction that signs inside it. This is reasoned from the code.
- Status during the ops key's KRL signature inside the transaction. It is covered by the log-key case's property, not by its own test.
- That the read-only handle sees only committed state (SQLite WAL reader isolation). Only the planner's uncommitted probe measured it. `answers_during_log_key_signature` proves the no-wait part, and `successor_refused_during_ca_signature` proves that another handle's commit is seen.
- WAL recovery waits on the read-only handle (busy_timeout), and a reconnect after signer.db is renamed or replaced under the running signer.
- The serve-without-StatusDB mutant: reasoned, not run.
- server-install.md's start-up, cold-mirror and /healthz bullets.
- Every runbook claim on a real host. No 03-16 drill provokes a slow signature.

## Known Stubs

None.

## Threat Flags

None. No new endpoint, route, wire message, stored format or log leaf. The read-only handle opens the same signer.db with `mode=ro` and `query_only`, inside the plan's threat model (T-03-324 to T-03-328).

## Actuals

- `tokens` is chars/4 over the added lines of the branch's diff (the plan copy excluded), this SUMMARY and the tracking updates included. That is 101,620 characters.
- `commits` is `git rev-list --count d819904..8ad8178` (8), measured before this SUMMARY's own commit.

## Pre-merge review

The orchestrator runs the pre-merge review on the green PR, as the owner's threat review against T-03-324 to T-03-328. Its findings and any fix rounds are recorded here after it runs.

## Review fix round 1 (pre-merge review of PR #85, head e2a09f7)

The pre-merge review found three low items: R-1 and R-2 (2 of 2 lenses each), and R-3 (split 1 of 1). Codex, the status-lockfree lens and the critic found nothing. Daniel decided all three on 2026-11-05.

**R-1 and R-2. Owner decision A: document only, no server code change (Q-I2 holds).**
- The cases:
  - A revocation or directory install whose answer the server lost (its call times out, or the connection breaks) can still commit later, once the signature it waits behind ends.
  - The server dropped its KRL cache (dropKRL) or status cache (dropStatus) when the call failed.
  - Because Status is now lock-free, a read during the held signature can refill that cache with the state from before the change: the KRL through GetKRL's atomic load, or the status through the snapshot.
  - Readers then see the change at most krlTTL or statusTTL (5 s each) after the signer commits. Before 03-08i the same window answered 503.
- Commit 79d8e71:
  - the krlTTL comment (internal/server/revoke.go) and the statusTTL comment (internal/server/signer.go) name the case;
  - revoke.md gets a new section, "A 503 whose outcome is unknown";
  - enroll-user.md gets a paragraph in "After "the server cannot reach its signer": look before you retry".
- What a rerun does, from the code:
  - A rerun of `keyroster revoke` draws a fresh request ID (checkRevokeRequest), so it is not `duplicate_request`.
  - Signer Revoke has no "already revoked" refusal, and the revocation table has no uniqueness constraint. So a target already revoked is recorded again and the next KRL version is published.
  - On that success the server calls dropKRL, and the CLI exits 0 only when the KRL it reads verifies (confirmRevokeAnswer) and lists the target.
  - The revoke.md text says this, and says that the signer host's `revoked` journal line is the other confirmation.
  - The CLI has no standalone KRL check command, so "wait krlTTL and check with the CLI" is not offered.
- For directory installs:
  - A rerun built on the older version is refused `directory_version_chain` (CheckSuccessorBytes) once the first install committed.
  - The CLI then says the directory changed since it was read (dirpipe.go), or re-reads the directory (afterChainRefusal).
  - So nothing installs twice, and enroll-user.md says to wait for the touch prompt, then 5 s, before reading the views.
- Run in CI: TestKRLCache/uncertain_outcome_drops_cache, TestRevokeSubject/explicit_key_cap_relist_accepted and revoke_user_second_sweep_relists, and TestRevokeKRLCheck.
- UNVERIFIED, in CI and on a real host:
  - a second revocation of the same serial or key ID;
  - a rerun after an unknown outcome;
  - the older KRL or status served during a held signature;
  - the install-rerun path.

**R-3. Owner decision A: tighten TestStatusWriters now.** Commit fd374fa:
- Every reference, read or write, to a `caKeys` or `bundleRow` selector outside New and publishStatusLocked fails the gate.
  - The only allowlist entry is trust.go loadTrust `ts.caKeys`, the trustState field. A stale entry fails the gate.
  - On the head the only such references are in New (signer.go) and publishStatusLocked (status.go).
- directoryState is pinned to its five fields, by name and type, through reflect.
- The test's doc comment says so. Must-have truth 4 in 03-08i-PLAN.md now names the reference rule and the field pin. This is the plan file's only edit since its first commit, so it is no longer byte for byte equal to its source.

Mutants (each applied by script, run with `-timeout 120s` against TestStatusWriters, restored with `git checkout`, and `git diff` clean afterwards). All were killed:

| Mutant | Gate line |
|---|---|
| `row := s.bundleRow; row.Version = 9` in InstallDirectory after `sum := sha256.Sum256(req.Directory)` | `directory.go:233: InstallDirectory: a reference to s.bundleRow` |
| `ks := s.caKeys; ks[0].Custody = "x"` at the same place | `directory.go:233: InstallDirectory: a reference to s.caKeys` |
| a sixth directoryState field (`mutantExtra uint64`) | `directoryState has fields [... "mutantExtra uint64"], want [the five]` |

Tests and lint on the fix round (local, WSL, -race):
- `--- PASS: TestStatusWriters (0.08s)`, `ok github.com/Labontese/keyroster/internal/signer 1.113s`;
- `ok github.com/Labontese/keyroster/internal/server 106.452s`;
- `golangci-lint run ./internal/signer/... ./internal/server/...`: `0 issues.`

The fix round touched only comments, docs, statuswriters_test.go and the plan's wording, so the full `./...` gate was not re-run, as the coordinator's rules allow. CI on the new head is recorded in the handback.

## Self-Check: PASSED

- The created files exist: internal/signer/statussnapshot_test.go, internal/signer/statuswriters_test.go, test/e2e/stall_test.go, 03-08i-PLAN.md and 03-08i-SUMMARY.md.
- Commits 4e2e8f7, 89d3d3e, 845d870, c798c18, 824f8d5, 3a93b18, f2ed388 and 8ad8178 are ancestors of HEAD.
- The plan copy is byte-for-byte equal to its source (`cmp`).
