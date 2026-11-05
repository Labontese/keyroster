---
phase: 03-linux-agent-and-revocation
plan: 08i
type: execute
wave: 20
depends_on: ["03-08h"]
files_modified:
  - internal/signer/status.go
  - internal/signer/signer.go
  - internal/signer/directory.go
  - internal/signer/issue.go
  - cmd/keyroster-signer/serve.go
  - internal/signer/log_test.go
  - internal/signer/status_test.go
  - internal/signer/directory_test.go
  - internal/signer/statussnapshot_test.go
  - internal/signer/statuswriters_test.go
  - internal/server/capacity_test.go
  - test/e2e/stall_test.go
  - test/e2e/server_test.go
  - docs/runbooks/server-install.md
  - docs/runbooks/signer-install.md
  - .planning/phases/03-linux-agent-and-revocation/03-08i-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [REVOKE-02, AGENT-02]

estimate:
  tokens: 65000
  raw_tokens: 65000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-10-30 and 2026-11-05): the signer keeps a lock-free Status snapshot that is updated under s.mu at every state change and read without the lock, so KRL and agent-state delivery keep working during a long touch signature. This plan is that follow-up, after 03-08h, with its own threat review and plan check. It carries no finding number. Q-I1 to Q-I5 are decided"
    - "Signer.Status takes no lock. It never takes s.mu, and it never reads through the signer's main database handle, whose one connection a transaction holds across the log key's checkpoint signature and the ops key's KRL signature. It answers from one immutable snapshot of the whole reply (an atomic.Pointer, as Signer.krl is). So it answers at once while any signature holds s.mu: the CA key's in cert.Build, or the log key's and ops key's inside the transaction. The log-key case is tested; the ops-key case holds by the same property and is not tested on its own"
    - "trust_changed is kept, fail-closed, on every call (Q-I1 B). Status reads the latest bundle version through a second, read-only database handle (Config.StatusDB, signerdb.OpenReadOnly, opened by serve) and runs checkTrustCurrent on it, as issuance does. Under WAL that read does not wait for a transaction open on the main handle, and it sees only committed state (SQLite WAL isolation; UNVERIFIED in CI). A bundle installed under the running signer is refused at the next Status, also while s.mu is held. A missing handle, a read error or a cancelled ctx refuses state_unavailable, and never answers success without the check. Every reply carries the bundle row this process loaded and checked against the log at start, never a row read later"
    - "The snapshot is consistent. setDirectoryLocked is the only writer of the directory state and always publishes the snapshot. InstallDirectory calls it once, as a statement after logTx has returned and its error was handled, so only after COMMIT and before it answers. loadDirectory calls it once at start, on the value readDirectory returns. So a reply is never torn, never ahead of committed state, and an install followed by a Status from the same client reports the new version. TestStatusWriters is a syntactic gate against the common write forms (go/parser, with an explicit allowlist); it does not prove that no write form exists"
    - "What stays locked, and the limits that remain. A refused Status is still logged through refuseLogging, which takes s.mu, so a refusal during a slow signature waits for it. GetDirectory and every call that issues, installs, revokes or forgets still take s.mu (Q-I3). keyroster-server is unchanged (Q-I2): its Status refresh still takes one of the budget's 12 tokens, so the routes still answer 503 past statusTTL when the budget is full, which takes as few as 6 interactive calls beside 6 catch-up reads during the part of a signature that runs inside the transaction. 03-08h's per-account share still closes the server's calls once more than 3 abandoned calls hold slots beyond its 13. The runbooks say so"
  artifacts:
    - path: "internal/signer/status.go"
      provides: "the Status snapshot, its publisher and the lock-free Status with the read-only trust check"
      contains: "func (s *Signer) publishStatusLocked("
    - path: "internal/signer/directory.go"
      provides: "the one writer of the directory state, which publishes the snapshot, and readDirectory"
      contains: "func (s *Signer) setDirectoryLocked("
    - path: "internal/signer/signer.go"
      provides: "Config.StatusDB, the snapshot pointer and the loaded bundle row"
      contains: "atomic.Pointer[statusSnapshot]"
    - path: "cmd/keyroster-signer/serve.go"
      provides: "the read-only status handle, opened after the main handle and closed before it"
      contains: "StatusDB:"
    - path: "internal/signer/statuswriters_test.go"
      provides: "the syntactic gate on who writes what Status reports"
      contains: "func TestStatusWriters("
    - path: "test/e2e/stall_test.go"
      provides: "a real server in front of the real signer during a held signature"
      contains: "func TestDeliveryDuringHeldSignature("
  key_links:
    - from: "internal/signer/directory.go"
      to: "internal/signer/status.go"
      via: "setDirectoryLocked writes the directory state and publishes the snapshot in one call"
      pattern: "publishStatusLocked()"
    - from: "internal/signer/status.go"
      to: "internal/signerdb/trust.go"
      via: "Status checks the bundle version (LatestBundleVersion, trust.go) through the read-only handle (OpenReadOnly, log.go), never the main one"
      pattern: "s.statusDB.LatestBundleVersion("
    - from: "cmd/keyroster-signer/serve.go"
      to: "internal/signer/signer.go"
      via: "serve opens the read-only handle and passes it as Config.StatusDB"
      pattern: "signerdb.OpenReadOnly("
  prohibitions:
    - statement: "Nothing here widens what the signer accepts or serves. Status reports only state that was committed under the bundle this process loaded, and refuses when it cannot check that bundle is still the latest; no wire message, stored format, log leaf or server route changes, and no module is added"
      status: resolved
      verification: test
---

<objective>
The signer answers Status without waiting for its lock, so keyroster-server's KRL route and host routes keep a recent signer status while a slow signature (for example a hardware key waiting for a touch) holds the lock. Today Status takes s.mu, and both routes need a Status younger than statusTTL (5 s), so past that they answer 503 for the rest of the signature. The trust check stays on every Status, fail-closed, through a read-only database handle.

Purpose:
- REVOKE-02: KRLs keep reaching every host during a slow signature.
- AGENT-02: the pull channel keeps answering hosts at the current versions during a slow signature.

Output:
- a Status snapshot published by one setter after every committed directory change;
- the trust check through a read-only handle that serve opens;
- named tests with RED evidence and mutants, a syntactic gate on the snapshot's writers, two server pins, and an e2e case with a real server in front of the real signer during a held signature;
- three runbook updates;
- the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Status during a slow signature (Daniel, 2026-10-30).** "The signer keeps a lock-free Status snapshot that is updated under s.mu at every state change and read without the lock, so KRL and agent-state delivery keep working during a long touch signature. It gets its own threat review and plan check."
  - It came out of plan check 2 of 03-08g (items 1 and 7): 03-08g kept GetKRL outside the server budget (Q-G5), but both routes also need a fresh Status, which waited for the lock.
  - 03-08g recorded the limit in its Deferred ledger and 03-08h in its Edge Coverage, both pointing here.
- **Delivery (owner, 2026-10-29 and 2026-11-02).** The plan lands in the same PR as its fix. The PR title and every commit use neutral wording. Pushing the branch and opening the PR before the merge is allowed. Branch commits are signed and authored as Daniel, with keyroster-bot as committer, signer and pusher. The bot opens the PR without auto-merge, and Daniel squash-merges it himself.
- **Numbers that stand.** Q-G1 (32 connections, 16 per account, 12 server calls of which 6 for agents, 2 per agent), Q-G2 (no reserved slot) and Q-G5 (GetKRL outside the budget) are unchanged.

The answers of 2026-11-05 (Daniel), given after plan check 1 with its corrected facts:

- **Q-I1 = B: a second, read-only database handle for the trust check.**
  - Facts:
    - signerdb.Open sets SetMaxOpenConns(1), so every read through the signer's main handle waits while a transaction holds that one connection. Every transaction runs under s.mu (logTx), and two signatures run inside one: each appended leaf's checkpoint (log key), and the KRL manifest of every revocation and republish (ops key). The CA key's signature (cert.Build) runs before the transaction.
    - signerdb.OpenReadOnly already exists (export and doctor use it): `mode=ro`, `query_only`, busy_timeout 5000, one connection.
    - Under WAL a read-only connection does not wait for a write transaction open on another connection. It waits only in edge cases such as WAL recovery, bounded by its busy_timeout. A planner probe on a copy of signerdb (uncommitted; go1.27.3, modernc.org/sqlite, on linux/amd64 under WSL and on windows/amd64) measured it:
      - with a write transaction open on the main handle (BEGIN IMMEDIATE, an uncommitted insert), three read-only reads answered within 4 ms and saw the committed version only, while a main-handle read with a 300 ms deadline ended in context.DeadlineExceeded;
      - after the commit, and after another read-write handle's commit, the read-only handle saw the new version;
      - after a TRUNCATE checkpoint it read in under 1 ms;
      - a closed handle and a cancelled ctx both returned an error.

      The committed proofs, on Linux: `answers_during_log_key_signature` proves the no-wait part, and `successor_refused_during_ca_signature` proves that another handle's commit is seen. That the read-only handle sees only committed state rests on SQLite's WAL reader isolation, measured by the uncommitted planner probe only (UNVERIFIED in CI).
  - Decision: on every call, Status reads the latest bundle version through that handle, without s.mu, and refuses trust_changed on a mismatch, as today. The server stays fail-closed. The reply is still built from the snapshot and the loaded row.
  - **Option A was rejected** (a sticky flag plus TryLock, with the check only when the lock was free). While s.mu was contended, keyroster-server would have kept authorising admins and RP origins, minting invites and join tokens, and serving agents under the superseded policy. It would also have started with a superseded policy's RP ID, because start-up's probeStatus calls Status. Today it answers 503 within statusTTL.
- **Q-I2 = A: Status stays inside the server budget.** A test pins that a full budget still gives 503.
  - Corrected facts: during the part of a signature that runs inside the transaction, up to 6 catch-up reads (GetBundle, GetDirectoryVersion, which take the agent share) wait for the signer's one connection and hold their tokens. So as few as 6 interactive calls beside them fill the 12. Every refused request also waits for s.mu, to be logged.
- **Q-I3 = A: GetDirectory stays locked.**
  - Corrected facts: the mirror is cold when it lacks the version the latest Status reports. That happens after a server restart, or after an install (over the socket, or through this server) that no request fetched before the signature began. During the signature, each failed fetch leaves one abandoned connection per signerCallTimeout, which feeds 03-08h's share residual.
  - This is new behaviour. Before 03-08i, a server started during a signature longer than statusWait (30 s) exited at probeStatus. Now it starts: its KRL route works at once, and its host routes answer 503 until the signature ends.
- **Q-I4 = B: the fixed pointer in the landed plans.**
  - Corrected premise: landed plans and SUMMARYs have been corrected in later PRs (#23, #44, #64, #71, #75), each with a small targeted edit.
  - Insert ` (Since 03-08i, a Status that answers does not wait for s.mu; see 03-08i-PLAN.md.)` right after each of these five sentences. Each occurs exactly once in its file on d819904:
    - 03-08g, Edge Coverage "The limit this plan does not remove": `planned as follow-up plan 03-08i (owner decision 2026-10-30; Deferred ledger).`
    - 03-08g, T-03-308 residual (2): `a Status that does not wait for the lock is follow-up plan 03-08i.`
    - 03-08g, the Deferred row: `a Status snapshot updated under s.mu at every state change and read without the lock (owner decision 2026-10-30).`
    - 03-08h, the last stalled-signer bullet in Edge Coverage: `A Status read without the lock is follow-up plan 03-08i (owner decision 2026-10-30).`
    - 03-08h, T-03-307 residual: `Status, GetDirectory and the issuing and installing calls take s.mu; GetKRL, GetBundle and GetDirectoryVersion do not.`
  - Left alone, with the reason for each:
    - 03-08g line 135 and 03-08h line 169 are owner-decision records, which stay as decided;
    - 03-08g line 694 and 03-08h line 847 are source-audit rows, true of those plans;
    - 03-08g line 780 is a review-history row;
    - 03-08g-SUMMARY.md line 351 is in a SUMMARY. Both SUMMARYs and every frontmatter stay untouched.
- **Q-I5 = build the e2e test.** test/e2e gets a case in which a real keyroster-server sits in front of the real signer, the agent backend runs behind a gated proxy, and one signature is held. Past statusTTL and krlTTL, GET /api/v1/krl and an approved agent's state must answer 200. The RED on origin/main (503) is taken from CI, because local e2e cannot run on this machine (Task 3). That depends on keyroster-bot being allowed to dispatch the e2e workflow (`workflow_dispatch`); if it cannot, Task 3 stops by design and the owner decides how the RED is taken.

## Open owner questions

None open.

**Planner decisions (Claude's discretion), recorded with their reasons:**
- *How the signer gets the read-only handle.*
  - A new `Config.StatusDB *signerdb.DB`, documented as a read-only handle (signerdb.OpenReadOnly) on the same database as DB.
  - New refuses a StatusDB that is the same handle as DB, because that would bring back the wait for the main connection.
  - A nil StatusDB is allowed, and then every Status refuses state_unavailable. That keeps the signers built only for recovery (cmd/keyroster-signer/recover.go, which never serves) and for tests that never ask for Status unchanged, and it can never answer success without the check.
  - serve opens the handle with `signerdb.OpenReadOnly` on the same path, right after signerdb.Open (whose migrations OpenReadOnly's schema check needs). If opening fails, serve fails to start. The handle is closed by a deferred call registered after the main handle's, so it closes first and outlives Serve.
  - Rejected: a read-only twin opened inside signerdb.Open. Every user of Open (ca-init, install-bundle, recover) would open a second handle it never reads.
  - Also rejected: New opening the handle from a path. The Signer has no Close, so tests would leak handles.
- *No sticky flag.* With the check on every call, a flag would only change Status's answer when the database's latest version goes back to the loaded one after a successor was seen (a successor row deleted under the running signer). Issuance's checks answer again then, and so does today's Status. A flag in Status alone would make Status and issuance disagree, for the cost of a field, gate rules and mutants.
- *The snapshot is the whole reply.* Only the directory part changes while the process runs. The CA keys are fixed after New, and so are the bundle version and the trust state, which are loaded only in New. So publishStatusLocked builds the reply once per directory change with the existing statusResponse, which also hashes the directory once instead of on every Status.
- *The bundle bytes come from the row the signer loaded* (loadTrust's `ts.stored`, checked against the log by checkBundleLogged), kept in a new field `bundleRow`, never read again. Status reads only the latest version, not the blobs. Two answers change, both toward the documented rule "a reply never carries a bundle or policy other than the one the signer runs on":
  - a row edited in place under the running signer is no longer passed on (`reply_carries_loaded_bundle`);
  - an emptied trust_bundle table is refused trust_changed, as issuance refuses it, instead of state_unavailable (`emptied_bundle_table_refused`).
- *The trust check is the issuance's own function*, checkTrustCurrent, fed from the read-only handle. It reads only fields New sets (bundleVersion, log), so Status calls it without s.mu; its doc comment says so.
- *Which requests a superseded bundle refuses.* Four texts on main say the signer refuses all requests until restart: New's doc comment (signer.go), errTrustChanged's comment and checkTrustCurrent's Error log message (issue.go), and signer-install.md. That is not what the code does, today or after this plan. Status refuses, and so does every request that issues, logs in, installs a directory, revokes, forgets, publishes a KRL or recovers (the callers of checkTrustCurrent). GetKRL, GetBundle, GetDirectoryVersion and GetDirectory do not check. Task 1 rewords the three code texts to that list; Task 4 rewords the runbook sentence, without recovery, which a running signer never serves.
- *One setter, and readDirectory keeps loadDirectory's partial states.* loadDirectory becomes `ds, err := s.readDirectory(ctx)`, then one setDirectoryLocked(ds). readDirectory holds today's checks and log lines and returns exactly today's states:
  - the zero value when nothing is stored;
  - bytes and version but no parsed directory when the stored document does not parse;
  - a parsed directory but not authorized when it fails the installation, signature or policy check;
  - authorized only when every check passes.

  The unparsed state cannot be reached from stored state today, because installs accept only parsed documents and start-up requires the stored row to match the log. It is kept byte for byte, its loadDirectory path is labelled UNVERIFIED, and a white-box case pins how the setter publishes it.
- *Status returns a copy* (slices.Clone of Keys, bytes.Clone of the four documents), as GetKRL and GetDirectory clone. A caller that changes its reply cannot change the next one.
- *The size verdict is computed once, at publish.* The reply's size depends only on the CA keys and the loaded row, because the directory part is fixed-size on the wire (wire/status.go), and InstallBundle already refuses a bundle whose reply would not fit (statusResponse, trust.go). Status's own size refusal cannot be reached through a stored bundle. `too_large_refused` reaches it by storing an oversized snapshot in an internal test.
- *TestStatusWriters is syntactic.* go/types was rejected. Its stdlib source importer would type-check the whole dependency graph from source on every run, modernc.org/sqlite included (expected to be slow; not measured), and golang.org/x/tools/go/packages would be a new module. The gate matches the watched field names on any selector, whatever its root, with an explicit allowlist for main's own collisions, and must_haves and T-03-324 call it a syntactic gate against the common write forms.
- *Tests hold s.mu from the test, or stall the hook backend* (trustchange_test.go's signHookBackend, whose hook runs inside a key's Sign: the CA key outside the transaction, the log key inside it, since cpSigner is built from the backend's log key). This is the same internal-state technique as 03-08h's pre-filled accounting, not a production seam. There is no wall-clock assert. The only timed waits are 10 s hang guards that the fixed code meets in milliseconds, and "no answer after 200 ms" checks on paths that cannot answer until the test releases them. Subtests with either do not call t.Parallel.
- *The server needs no code change (Q-I2 A).* fakeSigner's Status never blocks, so the server's half is shown by pins against the test double, with two mutants of the server's own code. The composed claim is proven by the e2e case (Q-I5).
- *The stop rule reads the base and Task 4's gates.* Task 1's and Task 2's package runs record internal/signer's time.

## Budget

13 code and test files (three of them new) and two runbooks:
- Task 1 touches 7 files, two of them small: issue.go's doc comment, and log_test.go's helper, which must pass the read-only handle. They stay together because the tracer wires serve's handle end to end.
- Tasks 2 and 3 touch 4 and 2 files.
- The publish edits add this plan, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16, plus the Q-I4 pointers in 03-08g and 03-08h and the trust_changed sentence of signer-install.md.

About 65k tokens:
- about 75 KB read through the function-scoped read_first lists, roughly 21k tokens;
- about 24k written, most of it tests;
- about 20k of test and gate output.

The plan itself adds about 52k tokens (about 134 KB), so the executor's total is about 117k, close to 03-08h's 115k. Each task is self-contained, so the executor can drop a task's read_first context once it is done.

**Test time.** 03-08k's two limits apply: 400 s for internal/agent/apply alone under -race, and 480 s for its `ok` line under `./...`. This plan adds nothing to that package. It adds about 25 s of tests to internal/signer, and about 4 s to internal/server (`budget_full_status_waits` waits out the real 3 s statusTimeout). internal/signer is held to the same 480 s under `./...`: it read 380–405 s there in 03-08h, against go test's default per-binary timeout of 10 minutes.
- Alone gate: `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'`
- Margin gate: `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./...' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} $1=="ok" && $2 ~ /\/internal\/signer$/ {u=$3; sub(/s$/,"",u); m++; if (u+0 > 480) bad=1} END{exit (n!=1 || m!=1 || bad)}'`
- **Stop rule.** Measure both gates on origin/main before Task 1's first edit, and again in Task 4, and record every reading in the SUMMARY. If one is above its limit, stop and report the two options without choosing: raise CI's -timeout, or move slow cases to their own package.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names. Since PR #79, its steps 2, 3 and 5 carry the owner's authorship and merge rules of 2026-11-02, which the points below restate. The one override is merge-gate.sh's plain form, as in 03-08f.
- **Branch.** Create `p03/08i-status-snapshot` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 4 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Authorship (01-SKELETON step 2).** Every `git commit` of this plan is signed (`-S`) and authored as Daniel, with keyroster-bot as committer, SSH signer and pusher. Put the two variables on the same command line as the commit, because shell state does not persist between commands: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit -S ...`. Push with `env -u GITHUB_TOKEN -u GH_TOKEN git push`.
- **No auto-merge (01-SKELETON steps 3 and 5).** The bot opens the PR through scripts/gh-as-bot.sh and never enables auto-merge or waits for it. Daniel reviews, approves and squash-merges the PR in the GitHub web UI, and replies "merged".
- **merge-gate.sh.** Before the merge it runs only as `--check`, which is read-only. Its plain form may rebase and force-push (exit 3), and this plan rebases by hand, so the plain form runs only after Daniel has merged (Task 5).
- **Shells.**
  - The go test, gate and mutant commands run through `bash scripts/linux.sh '...'`. Its single-quoted argument reaches WSL's login shell unexpanded (wsl.exe --exec), so `$(...)` and `$VAR` inside it expand in WSL.
  - The git checks run in Git Bash. Every `git show` or `git cat-file` of an `origin/main:path` or `FETCH_HEAD:path` argument is prefixed with `MSYS_NO_PATHCONV=1`, because Git Bash would rewrite the path otherwise (or run it in PowerShell).
  - scripts/gh-as-bot.sh and scripts/merge-gate.sh always run in Git Bash without MSYS_NO_PATHCONV.
- **Wording.** Conventional Commits (`fix(signer): ...`, `test(...)`, `docs(...)`) with neutral wording. There is no finding number. No attribution lines, no IP addresses, no real host names.
- **Code comments** cite `(03-08i)`.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md`, a draft from Task 1 on. Record T1, T2 and T3 there: the last commit of Tasks 1, 2 and 3. The final docs commit is `docs(03-08i): complete status-snapshot plan`.

**What this plan builds on:**
- **03-08g:** budgetSigner, with Status inside the budget and GetKRL outside it (Q-G5); currentStatus's coalesced refresh; statusTTL (5 s), statusTimeout (3 s) and krlTTL (serverclient.KRLMaxStale, 5 s); TestKRLDuringFullBudget and the fakeSigner hold/enter hooks.
- **03-08h:** the per-account share (wire.MaxPeerConns, 16), the server's 12 + 1 calls, and the release ordering. All stay as they are. This plan removes Status from the calls that wait for the lock.
- **Earlier:**
  - Signer.krl, the atomic.Pointer that GetKRL reads without the lock (03-01), is the precedent for the snapshot;
  - signerdb.OpenReadOnly (export, doctor) is the read-only handle;
  - TestStatusTrustChanged (02-05) and TestTrustChangedDuringIssue pin trust_changed;
  - the e2e harness's default agent backend, the `--backend-opt socket=PATH` override of serve, and enrollApproved are the e2e building blocks.

**The code this plan changes, as read on main at d819904 (03-08h merged as PR #84):**
- internal/signer/status.go: Status locks s.mu for its whole body. It reads the latest trust_bundle row through the main handle, runs checkTrustCurrent on its version, hashes s.directoryRaw, builds the reply from s.caKeys and the row, and sizes it by marshalling. statusOrRefuse logs a refusal through refuseErr after Status has returned.
- Status has three callers outside the signer, all unchanged by this plan:
  - the server's coalesced refresh (internal/server/signer.go, inside the budget);
  - start-up's probeStatus (cmd/keyroster-server/serve.go, outside the budget, retried for statusWait, 30 s);
  - the CLI's warnCustody (cmd/keyroster/ca.go).
- internal/signer/directory.go: loadDirectory writes the five directoryState fields step by step and returns early in four places; InstallDirectory writes them after logTx returns nil; GetDirectory reads them under s.mu. These are the only writers outside tests.
- internal/signer/signer.go: Signer embeds directoryState. caKeys and bundleVersion are set only in New's composite literal; newLogWriter (trust.go) builds a second, log-only Signer literal. loadTrust's `ts.stored` is used only by checkBundleLogged and then dropped.
- internal/signer/issue.go: checkTrustCurrent logs and returns trust_changed on a mismatch; "The caller holds s.mu."
- internal/signerdb/db.go: SetMaxOpenConns(1), WAL, busy_timeout 5000, BEGIN IMMEDIATE. log.go: OpenReadOnly.
- cmd/keyroster-signer/serve.go: opens signerdb.Open, the backend, then New and Serve.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a signature holds the signer's lock (the CA key outside the transaction, or the log key inside it) → Status over the real socket answers at once from the snapshot setDirectoryLocked published after COMMIT → a bundle installed under the running signer is refused at once through the read-only handle serve opened"</name>
  <reversibility rating="reversible">An in-process change in how Status reads its answer, plus one read-only handle opened by serve. No wire message, stored format, log leaf or configuration file changes. Reverting restores the locked Status.</reversibility>
  <precondition>All four checks hold:
    - `git fetch origin` succeeds, and `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md` exits 0.
    - `D=$(MSYS_NO_PATHCONV=1 git show origin/main:internal/signer/directory.go) && printf '%s\n' "$D" | grep -c 'func (s \*Signer) setDirectoryLocked('` prints 0: this plan is not applied yet.
    - `S=$(MSYS_NO_PATHCONV=1 git show origin/main:internal/signer/status.go) && printf '%s\n' "$S" | awk '/^func \(s \*Signer\) Status\(/,/^}/' | grep -q 'mu\.Lock()'` exits 0: Status still takes the lock, as this plan assumes.
    - `awk '/^## Open owner questions/{f=1;next} f && NF{print; exit}' .planning/phases/03-linux-agent-and-revocation/03-08i-PLAN.md | grep -qx 'None open.'` exits 0.
  </precondition>
  <files>internal/signer/status.go, internal/signer/signer.go, internal/signer/directory.go, internal/signer/issue.go, cmd/keyroster-signer/serve.go, internal/signer/log_test.go, internal/signer/status_test.go</files>
  <read_first>
    Read functions, not files. Find each with `grep -n` and read only that range.
    - internal/signer/status.go: the whole file (about 4 KB).
    - internal/signer/directory.go: `type directoryState`, `func (s *Signer) loadDirectory(`, `func (s *Signer) InstallDirectory(` from its logTx to its return, and `func (s *Signer) GetDirectory(` (about 7 KB).
    - internal/signer/signer.go: `type Config`, the Signer fields from `bundleVersion uint64` to `clockEpisode bool`, and `func New(` (about 8 KB).
    - internal/signer/trust.go: `type trustState` and the LatestBundle read in `func loadTrust(` (about 1 KB).
    - internal/signer/issue.go: `func refusalErr(`, `var errTrustChanged` and `func (s *Signer) checkTrustCurrent(` (about 1 KB).
    - internal/signerdb/log.go: `func OpenReadOnly(` (about 1.5 KB). internal/signerdb/trust.go: `func (d *DB) LatestBundleVersion(` (about 0.5 KB).
    - cmd/keyroster-signer/serve.go: from `signerdb.Open(` to `signer.New(` and its Config literal (about 1 KB).
    - internal/signer/status_test.go: the whole file (about 9 KB). serveStatusSigner, requireStatusOf and TestStatusTrustChanged are the models.
    - internal/signer/trustchange_test.go: signHookBackend, hookKey, installSuccessor, and TestTrustChangedDuringIssue (about 5 KB).
    - internal/signer/log_test.go: `type logEnv`, `func newLogEnvClock(`, `func (e *logEnv) open(`, `func (e *logEnv) close(` (which sets e.s to nil), `func (e *logEnv) request(` (which calls e.t.Fatal), `type failingSigner` and the cpSigner swap in `func TestCheckpointFailureReleasesNoCertificate(` (about 4 KB).
    - internal/signer/overload_test.go: the deferred conditional unlock at the head of `func TestOverloadDoesNotStallAccept(` (about 0.5 KB).
    - internal/signer/directory_test.go: `func execSQL(` (about 0.5 KB).
    - internal/signer/login_test.go: `func loginDirectory(`, `func signDirectory(`, `func newLoginEnv(` and `func (e *logEnv) installDirectory(` (about 2 KB).
  </read_first>
  <action>
Create branch `p03/08i-status-snapshot` from origin/main. Place this plan file untracked in the phase directory; Task 4 commits it. Run the Budget's two test-time gates on the unchanged code and record the base readings in the SUMMARY draft.

**RED first.** Add `TestStatusLockFree` to internal/signer/status_test.go (Linux-tagged).
- **The helper.** Write one next to serveStatusSigner. It builds a Signer on a given backend, allowing the test's own uid, on its own main handle of the env's store, with Clock e.clock. During RED, while Config.StatusDB does not exist yet, it opens no read-only handle; once the field exists, it opens one with signerdb.OpenReadOnly and passes it.
  - The env's own handle is closed first, as serveStatusSigner does. e.close() sets e.s to nil, so every case uses the Signer the helper returns, and its mu, never e.s.
  - It is used with `newSignHookBackend(e.backend)`, and it can serve the signer or only build it.
- **Keep the served signer quiet**, so that nothing but the call under test signs:
  - before Serve, the helper sets `newKRLTicker` to a channel that never fires (the field exists for tests);
  - after Serve, it waits for one answered `signerclient.Status`. Serve runs its first republishIfDue before it accepts a connection, so an answer means that check is done;
  - flushSummaries appends nothing while no refusal is counted, and no case counts one before its stall.
- **No hangs, on origin/main or under a mutant:**
  - Arm a hook with a one-shot gate: on its first call it signals `entered` and blocks until `release` is closed. Right after arming, write a Once-guarded release and defer it in the subtest. Defers run before t.Cleanup, so the gate opens before the helper's stop waits for Serve.
  - Every step where the test takes a signer's mu unlocks through a deferred, conditional unlock, as overload_test.go's TestOverloadDoesNotStallAccept does.
  - Goroutines that call Status, issueOrRefuse or InstallDirectory report only through buffered channels, and never call t.Errorf or t.Fatal. Build `e.request()` in the test goroutine, because it calls e.t.Fatal.
  - Each hook case also requires `be.count(fp)` to have risen by exactly 1 across the case, so the stalled signature was the issuance's.
  - Every wait for an answer has a 10 s hang guard that fails the test with a message naming the case. None of these subtests calls t.Parallel.

The cases:
- `answers_with_mu_held`: on newLoginEnv with directory version 1 installed, read GetDirectory first. Then the test takes e.s.mu (this env is never closed), and Signer.Status, called in a goroutine, returns a reply with BundleVersion 1, DirectoryVersion 1, DirectorySHA256 equal to sha256 of the installed document, and DirectoryAuthorized true.
- `answers_during_ca_signature`: a hook on the user CA key's fingerprint, on a served signer. An admin issue (`issueOrRefuse` with a request built in the test goroutine) runs in a goroutine and stalls in cert.Build with s.mu held. While it is stalled, both a `signerclient.Status` over the socket and a direct Signer.Status answer. After release, the issue succeeds.
- `answers_during_log_key_signature`: the same with the hook on the log key's fingerprint (keystore.RoleLog). The issue stalls inside logTx, in appendLocked's checkpoint signature, with s.mu and the main handle's one connection held. Both Status calls answer: the trust check reads through the read-only handle.
- `successor_refused_while_mu_held`, on a signer built through the helper and not served:
  1. Signer.Status answers.
  2. Install a successor bundle through a second read-write handle (installSuccessor).
  3. The test takes that signer's mu, and Signer.Status returns an error satisfying `errors.Is(err, errTrustChanged)`, within the hang guard.
- `successor_refused_during_ca_signature`, on a served signer:
  1. The user-CA hook stalls an admin issue. While it is stalled, installSuccessor through a second handle; the stalled issue holds no transaction.
  2. A `signerclient.Status` over the socket comes back as the trust_changed ErrorResponse (CodeUnavailable). The refusal is logged under s.mu, so the answer comes only after release; it must still be trust_changed.
  3. A direct Signer.Status returns errTrustChanged at once, before release.
  4. After release, the issue is refused `trust_changed` by its own check in the transaction (as in TestTrustChangedDuringIssue).
- `status_db_missing_or_failing_refuses`. In each of the three handle sub-cases the error is a refusal (errors.As to *refusal) whose reason is exactly `state_unavailable`, with CodeUnavailable:
  - a signer built without StatusDB;
  - the read-only handle closed by the test;
  - an already-cancelled ctx, after which the next Status with a live ctx answers.

  New refuses a Config whose StatusDB is its DB.

  None of these ever returns a reply. During RED this case is written last, after the field exists, because it needs StatusDB.
- `emptied_bundle_table_refused`: on newLogEnv, `execSQL(t, e.dbPath, "DELETE FROM trust_bundle")` while the signer runs. Signer.Status returns errTrustChanged. RED on origin/main: it returns state_unavailable.
- `reply_carries_loaded_bundle`: on newLogEnv, read the trust_bundle row, then rewrite the policy of version 1 in place through execSQL while the signer runs. Signer.Status still reports the policy the signer loaded, and the row's other bytes. RED on origin/main: it reports the edited bytes.
- `install_then_status_over_socket`: on newLoginEnv(t, pk, fx, true, false), with nothing installed, on the served signer. `signerclient.InstallDirectory` of a quorum-signed version 1 (loginDirectory, signDirectory), then `signerclient.Status` on the same socket reports version 1 with its SHA-256 and authorized. Then the same for version 2. That an install followed by a Status sees the new version is a property, not a timing: the snapshot is published before InstallDirectory's answer is written.
- `failed_transaction_keeps_snapshot`: on newLoginEnv with version 1, swap e.s.cpSigner for `failingSigner{orig}` under e.s.mu, as TestCheckpointFailureReleasesNoCertificate does. `e.s.InstallDirectory` of version 2 returns an unavailable refusal. Call InstallDirectory itself, not installDirectoryOrRefuse, whose refusal leaf would meet the failing signer too. Restore cpSigner. Signer.Status still reports version 1 and its SHA-256. This pins failures before COMMIT; that the publish comes after COMMIT is TestStatusWriters' rule (Task 2).

Run the RED with `-timeout 120s` on the `-run`-filtered command only. The whole internal/signer run takes 380–405 s, so it never gets that flag. Record each RED line in the SUMMARY. Expected on origin/main:
- `answers_with_mu_held`, `answers_during_ca_signature`, `answers_during_log_key_signature`, `successor_refused_while_mu_held` and `successor_refused_during_ca_signature` each end in a named `--- FAIL` with its hang-guard message, not a binary timeout;
- `emptied_bundle_table_refused` fails on state_unavailable, and `reply_carries_loaded_bundle` on the edited policy;
- `install_then_status_over_socket` and `failed_transaction_keeps_snapshot` pass at once, because a locked Status reads the fields.

Record each of these facts.

**internal/signer/signer.go, `(03-08i)`.**
- `Config.StatusDB *signerdb.DB`. Its doc: a read-only handle (signerdb.OpenReadOnly) on the same database as DB, through which Status checks the latest bundle version without the signer's lock, and which under WAL does not wait for a transaction on DB. Nil means every Status refuses state_unavailable.
- New refuses `cfg.StatusDB != nil && cfg.StatusDB == cfg.DB` with an error saying the status handle must be a separate read-only handle. It sets `statusDB: cfg.StatusDB` in its composite literal.
- Add `status atomic.Pointer[statusSnapshot]`, next to krl, with a comment: written under mu (publishStatusLocked) and read without it, so Status never waits for a signature in flight. A stored snapshot is never modified.
- Add `bundleRow *signerdb.StoredBundle`: the trust_bundle row this process loaded and checkBundleLogged checked against the log at start (loadTrust's `ts.stored`). New sets it in its composite literal, as `bundleRow: ts.stored`, next to caKeys. It is never modified, and Status reports its bytes. loadDirectory runs later in New, so its setDirectoryLocked call already sees caKeys and bundleRow.
- Extend the comment on caKeys: only New sets it, and TestStatusWriters checks that.

**internal/signer/status.go, `(03-08i)`.**
- `type statusSnapshot struct { reply *wire.StatusResponse; err error }`. reply is built by statusResponse and never handed out. err is reply.Marshal's verdict at publish: wire.ErrStatusTooLarge above wire.MaxStatusFrame, nil when it fits.
- `func newStatusSnapshot(caKeys []signerdb.CAKey, row *signerdb.StoredBundle, ds directoryState) *statusSnapshot`. It builds the statusDirectory from ds (version, authorized, and sha256.Sum256 of the raw bytes when they are not nil), calls statusResponse with row's version and documents, and marshals once for err.
- `func (s *Signer) publishStatusLocked()`: one Store of `newStatusSnapshot(s.caKeys, s.bundleRow, s.directoryState)`. The caller holds s.mu, or runs in New before Serve.
- A method on statusSnapshot that returns a copy of reply: slices.Clone of Keys and bytes.Clone of Bundle, BundleSigs, Policy and PolicySigs.
- Status, in this order:
  1. A nil statusDB refuses `state_unavailable` (CodeUnavailable).
  2. `s.checkTrustCurrent(s.statusDB.LatestBundleVersion(ctx))`. Its error is returned: state_unavailable for a read error, trust_changed for another version.
  3. Load the snapshot. A nil snapshot cannot occur after New; refuse it `state_unavailable`.
  4. Return the snapshot's err if set, otherwise the copy.

  Status takes no lock and reads nothing through the main handle.
- Rewrite Status's doc comment. It says:
  - what the reply holds, and that it comes from a snapshot published after every committed directory change;
  - that Status takes no lock, and checks the latest bundle version through the read-only handle, which does not wait for a transaction on the main handle, so a bundle installed under the running signer is refused at once, also while a signature holds the lock;
  - that it refuses rather than answer without that check;
  - that the bundle and policy are the ones this process loaded.
- statusOrRefuse's comment: a refusal is still logged through refuseErr, which takes s.mu, so a refused Status waits for a signature in flight (03-08i).
- statusResponse is unchanged; InstallBundle keeps sizing with it.

**internal/signer/issue.go and New's doc comment.** checkTrustCurrent's doc comment: it reads only fields New sets, so Status calls it without s.mu (03-08i); every other caller holds s.mu. Three texts claim that all requests are refused after a bundle change, and each is reworded to the list of what refuses (Planner decisions):
- New's doc comment in signer.go, its last sentence;
- errTrustChanged's comment in issue.go;
- checkTrustCurrent's Error log message in issue.go, which becomes `trust bundle changed under the running signer: refusing status and every issuing, login, install, revoke, forget, KRL-publish and recovery request until restart`. No test or document matches the old message.

**internal/signer/directory.go, `(03-08i)`.**
- Add `func (s *Signer) setDirectoryLocked(ds directoryState)`, which assigns the embedded directoryState as a whole and then calls publishStatusLocked. Its doc comment says it is the only writer of the directory state (TestStatusWriters), that a caller holds s.mu or runs in New before Serve, and that InstallDirectory calls it only after COMMIT.
- Split loadDirectory. `func (s *Signer) readDirectory(ctx) (directoryState, error)` holds LatestDirectory, checkDirectoryLogged and every check and log line, in today's order, and returns today's states (Planner decisions). loadDirectory becomes `ds, err := s.readDirectory(ctx)`, a return of the error, `s.setDirectoryLocked(ds)` and `return nil`.
- InstallDirectory: once logTx has returned nil and its `if err != nil` block has been passed, its five field assignments become one setDirectoryLocked call with the parsed directory, copies of the request's document and signatures, its version and authorized true. It is a statement of the function body, not inside the logTx closure. It comes before the `directory installed` log line and the return.
- GetDirectory is unchanged (Q-I3).

**cmd/keyroster-signer/serve.go, `(03-08i)`.** Right after the main handle is opened and its Close deferred:
- open `sdb, err := signerdb.OpenReadOnly(<the same signer.db path>)`; on error, return it, so serve does not start;
- defer `sdb.Close()` after the main handle's deferred Close, so it closes first;
- pass `StatusDB: sdb` in New's Config.

recover.go is unchanged: it never serves, so its signer never answers Status.

**Test helpers.**
- logEnv.open opens a read-only handle after the main one and passes it as StatusDB; logEnv.close closes it before the main handle.
- serveStatusSigner and the new helper pass one.
- Any other test that asks a signer built without one for Status now fails with state_unavailable. Add the handle to that test's helper and record which.

Then run the signer package and cmd/keyroster-signer. Every existing test must keep its meaning: TestStatusTrustChanged, TestStatusOverSocket, TestStatusReportsDirectory, the TestDirectoryRestart and refusal cases, 03-08h's TestPeerShare and TestStateDirLock among them. Record any assertion that moved, and why.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 120s -v -run "TestStatusLockFree|TestStatusTrustChanged|TestStatusOverSocket|TestStatusReportsDirectory|TestDirectoryInstallRefusals|TestDirectoryRestart|TestTrustChangedDuringIssue|TestTrustChangedUnderLiveSigner|TestCheckpointFailureReleasesNoCertificate" ./internal/signer/ && go test -race -count=1 ./internal/signer/ ./cmd/keyroster-signer/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestStatusLockFree/answers_with_mu_held", "--- PASS: TestStatusLockFree/answers_during_ca_signature", "--- PASS: TestStatusLockFree/answers_during_log_key_signature", "--- PASS: TestStatusLockFree/successor_refused_while_mu_held", "--- PASS: TestStatusLockFree/successor_refused_during_ca_signature", "--- PASS: TestStatusLockFree/status_db_missing_or_failing_refuses", "--- PASS: TestStatusLockFree/emptied_bundle_table_refused", "--- PASS: TestStatusLockFree/reply_carries_loaded_bundle", "--- PASS: TestStatusLockFree/install_then_status_over_socket", "--- PASS: TestStatusLockFree/failed_transaction_keeps_snapshot", "--- PASS: TestStatusTrustChanged", "--- PASS: TestDirectoryRestart". The SUMMARY records internal/signer's `ok` time from the second command</fails_when>
    <automated>bash scripts/linux.sh 'go list -deps ./cmd/keyroster-signer | grep -c "keyroster/internal/agent" ; bash scripts/dep-firewall.sh'</automated>
    <fails_when>the first number printed is not 0, or dep-firewall exits non-zero</fails_when>
  </verify>
  <acceptance_criteria>
    - `awk '/^func \(s \*Signer\) Status\(/,/^}/' internal/signer/status.go | grep -v '^[[:space:]]*//' | grep -cE 'mu\.(Try)?Lock\(\)|s\.db\.'` prints 0, and the same pipeline ending in `grep -q 's\.statusDB\.LatestBundleVersion('` exits 0.
    - `awk '/^func \(s \*Signer\) setDirectoryLocked\(/,/^}/' internal/signer/directory.go | grep -q 'publishStatusLocked()'` exits 0. That it is the only one of its kind is TestStatusWriters' job (Task 2).
    - `grep -v '^[[:space:]]*//' cmd/keyroster-signer/serve.go | grep -q 'signerdb.OpenReadOnly('` exits 0, and the same with `'StatusDB:'` exits 0.
    - `D=$(git diff --name-only origin/main...T1) && ! printf '%s\n' "$D" | grep -v '^internal/signer/' | grep -v '^cmd/keyroster-signer/serve\.go$' | grep -v '^\.planning/' | grep -q .`, with T1 as recorded in the SUMMARY: Task 1 changes nothing else.
    - The SUMMARY records the RED of the seven cases that fail on origin/main's code, why `install_then_status_over_socket` and `failed_transaction_keeps_snapshot` pass there at once, the RED of `status_db_missing_or_failing_refuses` (written after the field exists, so its RED is taken against a Status that ignores the handle's error), and every existing assertion that moved.
    - The SUMMARY lists these mutants, each applied, run with `-timeout 120s` against its named test, and restored byte for byte:
      - Status takes s.mu again (killed by `answers_with_mu_held`, `answers_during_ca_signature`, `answers_during_log_key_signature` and `successor_refused_while_mu_held`);
      - the version read through the main handle instead of the read-only one (killed by `answers_during_log_key_signature`);
      - the trust check removed from Status (killed by TestStatusTrustChanged, `successor_refused_while_mu_held` and `successor_refused_during_ca_signature`);
      - on a read error, skip checkTrustCurrent and return the snapshot's copy (killed by `status_db_missing_or_failing_refuses`, which requires the reason `state_unavailable`);
      - a nil statusDB answered from the snapshot (killed by the same);
      - New accepting a StatusDB equal to DB (killed by the same);
      - setDirectoryLocked without its publish (killed by `install_then_status_over_socket`);
      - setDirectoryLocked called in InstallDirectory before logTx (killed by `failed_transaction_keeps_snapshot`);
      - the reply built from a fresh database read of the bundle row (killed by `reply_carries_loaded_bundle`);
      - serve without StatusDB: reasoned, not run (UNVERIFIED). Every e2e server start would fail at probeStatus (cmd/keyroster-server/serve.go:76). Record it so in the SUMMARY.
    - `F=$(ls internal/signer/*.go | grep -v '_test\.go$') && test -z "$(grep -nE 'refus(es|ing) every request' $F)"`: no code text in the package still says that all requests are refused.
  </acceptance_criteria>
  <done>Status answers at once while any signature holds the signer's lock, inside or outside the transaction, from the snapshot of committed state, and a bundle installed under the running signer is refused at once, also while the lock is held. A missing or failing read-only handle refuses.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The durable gates — who may write what Status reports, the publish after COMMIT, copies, the size verdict and the refused-Status residual — and the server's routes past statusTTL with a held signer call</name>
  <files>internal/signer/statussnapshot_test.go, internal/signer/statuswriters_test.go, internal/signer/directory_test.go, internal/server/capacity_test.go</files>
  <behavior>
    - `TestStatusWriters` (statuswriters_test.go, no build tag). Its rules live in a function, `statusWriterViolations(dir string) []string`, which parses every non-test .go file of dir with go/parser, as internal/agent/paths' TestPaths does; the test runs it on the package directory and fails on any violation, naming the file, line and function. The rules: The watched names are directory, directoryRaw, directorySigs, directoryVersion, directoryAuthorized, directoryState, status, statusDB, caKeys, bundleVersion and bundleRow. A watched selector is any selector naming one of them, whatever its root, after unwrapping ParenExpr, StarExpr, IndexExpr and SliceExpr.
      - **Writes.** The check walks down an expression through SelectorExpr.X, IndexExpr.X, SliceExpr.X, StarExpr.X and ParenExpr.X, and flags it when any selector in that chain names a watched field, so `s.caKeys[0].Custody = ...` is a write to caKeys. It is applied to the left side of every assignment, define and inc/dec; to the operand of every `&`; and to the first argument of copy, clear, delete, append and the mutating slices functions (Sort, SortFunc, SortStableFunc, Reverse, Delete, DeleteFunc, Insert, Replace, Compact, CompactFunc, Grow, Clip). Read-only calls such as slices.Clone, Contains or Equal are not writes. An assignment whose left side, after ParenExpr unwrapping, is a StarExpr fails wherever it appears: on d819904 the package's non-test files hold none, so no allowlist entry is needed. The allowed exceptions:
        - in setDirectoryLocked, the directoryState write;
        - in readDirectory, writes to its own local directoryState value;
        - the allowlist for main's collisions, each with its reason in a comment: the trustState write `ts.caKeys` in trust.go, a trustState field, not the Signer's.

        The test fails if an allowlist entry no longer matches anything. On d819904 that one entry is complete: a read-only grep of the package's non-test files finds no other write, `&` or mutating call on a watched name outside directory.go, and no other type with a field of a watched name except trustState's caKeys. Before writing the test, run that grep again on the branch and add, with its reason, any collision Task 1 introduced; record the list in the SUMMARY.
      - **Composite literals.** A `Signer` composite literal may set the keys caKeys, bundleVersion, bundleRow and statusDB only in New, and no Signer literal, New's included, may set directoryState or status. newLogWriter's literal (db, logKey, clock, log) sets none of them.
      - **The snapshot pointer.** A call on `.status` other than Load, and any method value of it, anywhere but the one Store in publishStatusLocked.
      - **Callers.** setDirectoryLocked is called only from loadDirectory and InstallDirectory, and exactly once in each. publishStatusLocked is called only from setDirectoryLocked, which must call it. So a new caller has to update the test on purpose.
      - **The publish after COMMIT.** In InstallDirectory, the setDirectoryLocked call is a top-level statement of the function body (inside no FuncLit), after the `err = s.logTx(` assignment and after the `if err != nil` block that follows it. In loadDirectory it is a top-level statement after `ds, err := s.readDirectory(`.
      - **Receivers.** No method has a directoryState or *directoryState receiver.
      - **Renames.** The test fails when setDirectoryLocked, publishStatusLocked, readDirectory, newStatusSnapshot or Status is not found exactly once, so a rename cannot pass silently.
      - **The reply's fields.** The fields of wire.StatusResponse, as a list of `Name Type` strings through reflect, must equal the literal list of the 9 known today (Keys []wire.KeyStatus, BundleVersion uint64, Bundle []uint8, BundleSigs []uint8, Policy []uint8, PolicySigs []uint8, DirectoryVersion uint64, DirectorySHA256 [32]uint8, DirectoryAuthorized bool), with the message that a new or changed reply field must be added to the snapshot and to this test.
    - `TestStatusSnapshot` (statussnapshot_test.go, Linux-tagged):
      - `no_torn_reply`: on newLoginEnv with version 1, build all eight documents (versions 2 to 9, each chained to the one before) and their SHA-256 values into a read-only map before any reader starts. Four goroutines call Signer.Status in a loop and only collect their (version, SHA-256) observations while the test installs versions 2 to 9. After all readers have joined, every observation must be a pair of the map (or version 1's), and each reader's versions must never decrease. It is repeated 5 times in verify, under -race.
      - `reply_is_a_copy`: in a returned reply, change one field of Keys[0] and one byte of each of Bundle, BundleSigs, Policy and PolicySigs. The next reply must hold the original value of each, checked one by one, naming the field on failure.
      - `too_large_refused`: a snapshot from newStatusSnapshot with a row whose Bundle has wire.MaxStatusFrame bytes is stored in e.s.status by the test (internal state, as 03-08h pre-fills its accounting). Signer.Status returns an error satisfying `errors.Is(err, wire.ErrStatusTooLarge)`, and the snapshot's err is that error. This is the only path to Status's own size refusal.
      - `nil_snapshot_refused`: the test stores nil in e.s.status, and Signer.Status returns a state_unavailable refusal.
      - `unparsed_state_published`: with e.s.mu taken, the test calls setDirectoryLocked with a directoryState holding raw bytes, signatures and version 7, no parsed directory and authorized false. The snapshot reports version 7, the SHA-256 of the raw bytes and authorized false. This pins how the setter publishes readDirectory's unparsed state; that readDirectory still returns it is UNVERIFIED (Planner decisions).
      - `refused_status_waits_for_refusal_log`, which pins a stated residual:
        1. On a signer served through Task 1's quiet helper, installSuccessor through a second handle.
        2. The test takes the served signer's mu (the helper's returned Signer). A `signerclient.Status` over the socket, in a goroutine reporting through a buffered channel, has no answer after 200 ms: its trust_changed refusal waits for refuseLogging's lock.
        3. Unlock, through the deferred conditional unlock. The answer is the trust_changed ErrorResponse within 10 s.

        GREEN on origin/main too; record that.
    - `wantDirectory` in directory_test.go, besides GetDirectory, requires `e.s.status.Load()` to be non-nil, and its reply to carry the same version, sha256 of doc (all zero for version 0) and the same authorization. It reads the snapshot, not Status, because one caller (TestDirectoryInstallRefusals `trust_changed`) runs while Status refuses. Its 21 call sites then pin the snapshot after a load, an install or a refusal, the restart cases included.
    - `TestRoutesPastStatusTTLWithHeldCall` (internal/server/capacity_test.go). Its doc comment says that it runs against the test double and holds no signature: fakeSigner's Status never waits, so neither case has a RED on origin/main. It pins the server's half, and the e2e case (Task 3) proves the whole.
      - `krl_and_state_past_status_ttl`:
        1. On newAgentEnv, publishKRL and approvedAgent, and one GET krl and one state request answer 200, before anything is held.
        2. `hold("Login")`, and one Login enters through e.s.signer (goCalls with 1).
        3. Move e.clock past statusTTL.
        4. GET /api/v1/krl answers 200 with the published KRL, and the approved agent's state request answers 200, each within a 10 s hang guard.
        5. The fake's Status count rose by exactly 1: the answers came from a fresh refresh, not the cache.
        6. Release and collect.
      - `budget_full_status_waits`, the Q-I2 A residual:
        1. As above, but maxSignerCalls Logins enter, so every token is held.
        2. Past statusTTL, GET /api/v1/krl answers 503 after the refresh's statusTimeout, and the fake's Status count is unchanged. Assert only the code and the count.
        3. Release and collect.

        A second fill of 6 agent calls and 6 Logins is not possible with the fake, whose hold arms one method at a time; record that.
  </behavior>
  <read_first>
    - internal/agent/paths/paths_test.go: the go/parser walk in `func TestPaths(` (about 3 KB), for the AST pattern.
    - internal/signer/trust.go: `func newLogWriter(` and the `ts.caKeys` write (about 1 KB), the allowlist's subjects.
    - Task 1's diff of internal/signer (in context).
    - internal/signer/directory_test.go: `func (e *logEnv) wantDirectory(` and the `trust_changed` case of TestDirectoryInstallRefusals (about 2 KB).
    - internal/server/capacity_test.go: `settle`, `waitFor`, `goCalls`, `collect`, `only` and `func TestKRLDuringFullBudget(` (about 5 KB).
    - internal/server/server_test.go: `type fakeSigner` through `func (f *fakeSigner) Status(` and `type testClock` with its set method (about 5 KB).
    - internal/server/agent_test.go: `func newAgentEnv(`, `func (e *agentEnv) approvedAgent(`, `func (e *agentEnv) publishKRL(`; internal/server/forget_test.go `func (e *agentEnv) state(` (about 3 KB).
    - internal/server/signer.go: `func (b *budgetSigner) Status(`, and from `statusTTL` to the end of `func (s *Server) refresh(`, with currentStatus's cache check (about 3 KB). Read only.
  </read_first>
  <action>
Write the tests in `<behavior>`.
- TestStatusWriters passes on Task 1's head. Record that its rules fail on origin/main, where loadDirectory and InstallDirectory write the fields directly and readDirectory does not exist. Copy origin/main's non-test internal/signer/*.go (`MSYS_NO_PATHCONV=1 git show origin/main:internal/signer/<file>`) into a temporary directory, call `statusWriterViolations` on it from a temporary, uncommitted test in the package, record the violations it lists, and delete the test. Nothing is compiled from the copied files: the checker only parses them.
- Name every rule's violation clearly, so a later plan that trips it learns which writer must go through the setter.

Change no production code in this task. If a case needs a change, stop and report.

Run the signer, server and signerclient packages and cmd/. Every existing test must keep its meaning: 03-08g's TestKRLDuringFullBudget and TestSignerBudget, and 03-08h's TestConnSlots and TestPeerShare, among them.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 120s -v -run "TestStatusSnapshot|TestStatusWriters|TestDirectoryInstallRefusals|TestDirectoryRestart" ./internal/signer/ && go test -race -count=5 -timeout 120s -run "TestStatusSnapshot/no_torn_reply" ./internal/signer/ && go test -race -count=1 -v -run "TestRoutesPastStatusTTLWithHeldCall|TestKRLDuringFullBudget|TestSignerBudget" ./internal/server/ && go test -race -count=1 ./internal/signer/ ./internal/server/ ./internal/signerclient/ ./cmd/...'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestStatusWriters", "--- PASS: TestStatusSnapshot/no_torn_reply", "--- PASS: TestStatusSnapshot/reply_is_a_copy", "--- PASS: TestStatusSnapshot/too_large_refused", "--- PASS: TestStatusSnapshot/nil_snapshot_refused", "--- PASS: TestStatusSnapshot/unparsed_state_published", "--- PASS: TestStatusSnapshot/refused_status_waits_for_refusal_log", "--- PASS: TestRoutesPastStatusTTLWithHeldCall/krl_and_state_past_status_ttl", "--- PASS: TestRoutesPastStatusTTLWithHeldCall/budget_full_status_waits", "--- PASS: TestKRLDuringFullBudget". The SUMMARY records internal/signer's `ok` time from the last command</fails_when>
  </verify>
  <acceptance_criteria>
    - `D=$(git diff --name-only T1...T2) && ! printf '%s\n' "$D" | grep -v '_test\.go$' | grep -v '^\.planning/' | grep -q .`, with T1 and T2 as recorded in the SUMMARY: this task adds tests only.
    - `D=$(git diff --name-only origin/main...HEAD -- internal/server/) && ! printf '%s\n' "$D" | grep -v '_test\.go$' | grep -q .`: no server code changes (Q-I2 A).
    - The SUMMARY records the violations statusWriterViolations lists on origin/main's files, the allowlist grep, and why the other cases are pins.
    - The SUMMARY lists these mutants, each applied, run with `-timeout 120s` against its named test, and restored byte for byte:
      - publishStatusLocked keeps one snapshot and changes its fields in place after the first Store (killed by `no_torn_reply`, a DATA RACE or a mismatched pair);
      - the copy omits PolicySigs, sharing it with the snapshot (killed by `reply_is_a_copy`);
      - Status ignores the snapshot's err (killed by `too_large_refused`);
      - the nil-snapshot branch returns no reply and no error (killed by `nil_snapshot_refused`);
      - one direct directory-field assignment put back in InstallDirectory next to the setter call (killed by TestStatusWriters);
      - an alias write, `ds := &s.directoryState; ds.directoryVersion = 0`, in InstallDirectory (killed by TestStatusWriters);
      - `*s = *s` in InstallDirectory, which compiles (killed by TestStatusWriters' StarExpr rule);
      - `s.caKeys[0].Custody = "software"` in InstallDirectory (killed by TestStatusWriters' chain walk);
      - setDirectoryLocked moved inside the logTx closure after appendLocked (killed by TestStatusWriters);
      - setDirectoryLocked without its publishStatusLocked call (killed by TestStatusWriters);
      - a Store of s.status added in Status (killed by TestStatusWriters);
      - a tenth field added to wire.StatusResponse, temporarily (killed by TestStatusWriters' field list);
      - loadDirectory's VerifySignatures and CheckPolicy returns: readDirectory returning authorized true after a failed VerifySignatures (killed by TestDirectoryRestart `restart_under_new_admins` through wantDirectory), and after a failed CheckPolicy (killed by `restart_under_tighter_cap`);
      - server, budgetSigner.Status calling next.Status without acquiring a token (killed by `budget_full_status_waits`: it gets 200 and the Status count rises);
      - server, currentStatus serving the cached entry past statusTTL (killed by `krl_and_state_past_status_ttl` step 5: the count rises by 0).
  </acceptance_criteria>
  <done>A later writer that skips the snapshot in a common write form, a publish before COMMIT, a reply shared between callers, a dropped size verdict or a changed reply type fails a named test in CI. The server's routes are pinned past statusTTL with a held call, with the budget residual and two mutants of the server's own code.</done>
</task>

<task type="auto">
  <name>Task 3: The e2e case (Q-I5) — a real keyroster-server in front of the real signer, one signature held behind a gated agent proxy, GET /api/v1/krl and an approved agent's state answering 200 past statusTTL and krlTTL — with its RED taken from CI on origin/main</name>
  <files>test/e2e/stall_test.go, test/e2e/server_test.go</files>
  <read_first>
    - test/e2e/server_test.go: `type serverOpts`, `func startServerEnv(`, `type response` and `func (e *serverEnv) get(` (about 5 KB).
    - test/e2e/bootstrap_test.go: `type bootstrapOpts`, `func prepareSigner(`, `func initSigner(` (where RoleAgent is set), `func (e *signerEnv) serve(`, `func (e *signerEnv) runIssue(` and `func runBin(` (about 6 KB).
    - test/e2e/harness_test.go: `func startDaemon(`, `func waitFor(`, `func shortTempDir(` and `func startAgent(` (about 3 KB).
    - test/e2e/agent_status_test.go: `func enrollApproved(` and the head of `func TestAgentStatusEndToEnd(` with its `kr` helper (about 3 KB).
    - test/e2e/agent_enroll_test.go: `func (e *enrolledHost) startFetch(` and `func (e *enrolledHost) stopFetch(` (about 1 KB).
    - internal/agent/fetch/fetch.go: `type Config`, `func New(` and `func (f *Fetcher) Once(` (about 2 KB).
    - internal/signer/server.go: `connDeadline` (10 s, line 20), and internal/signerclient/client.go: `defaultTimeout` (10 s, line 17). These bound the held issue's connection, so they are the hold's binding limit.
    - cmd/keyroster-signer/serve.go: the `--backend-opt` flag (about 0.5 KB).
    - .github/workflows/e2e.yml: its `on:` block (workflow_dispatch) and the go test line (about 1 KB).
  </read_first>
  <action>
**test/e2e/server_test.go.** Add one field to serverOpts, `SignerServe func(t *testing.T, sg *signerEnv)`. When it is set, startServerEnv runs prepareSigner and then SignerServe, instead of bootstrapSigner. Nothing else changes.

**test/e2e/stall_test.go (new, `//go:build e2e`), `(03-08i)`.**
- **The gated agent proxy.** An agentGate type with a `serve(t, sg)` method suitable for SignerServe.
  - It listens on a Unix socket in shortTempDir. For each connection it dials sg.RoleAgent and runs `agent.ServeAgent` over a wrapper of `agent.NewClient` on that connection. The wrapper implements agent.ExtendedAgent and forwards every call, except that Sign and SignWithFlags block once armed. The first signature with the armed key's fingerprint signals `entered` and waits until release.
  - It then starts the signer as signerEnv.serve does, with `--backend-opt socket=<proxy socket>` added. The keys and custody are the role agent's, so they match the bundle.
  - Release is Once-guarded. The test registers it with t.Cleanup when it arms the gate (step 3), which is after startServerEnv started the daemons, so on a failure it runs before their cleanups stop a blocked signer.
- **The binding limit.** The held issue's connection is bounded by the signer's connDeadline (internal/signer/server.go:20) and the CLI's defaultTimeout (internal/signerclient/client.go:17), 10 s each. So the gate must open within 7 s of the issue's start, which leaves 3 s for the rest of the issuance. The hold is therefore anchored to t0, the moment the control Once returns: every server cache entry was fetched at or before t0, because currentStatus and currentKRL stamp an entry when its refresh starts.
- **`TestDeliveryDuringHeldSignature`**:
  1. startServerEnv with `PoPHosts`, `AgentListen` and `SignerServe` set. Admin `kr` as in TestAgentStatusEndToEnd, then enrollApproved for host web1.
  2. Controls:
     - GET serverclient.KRLPath answers 200; record its body;
     - stop the host's fetcher (stopFetch), and wait 4 s so the agent's token bucket refills;
     - build a Fetcher in the test with fetch.New on the host's own config, dir, spool and outbox (the paths startFetch passes), with `Log` set to a buffer;
     - `Once` returns nil, and the buffer holds neither `rate limiting` nor `waiting for an admin's approval`.

     t0 is the moment that Once returns.
  3. Sleep until t0 + 4 s. Nothing refreshes the server's caches meanwhile: the fetcher is stopped, and the CLI talks to the signer directly.
     - Arm the gate with the user CA key's fingerprint (fingerprint of signerEnv.UserCAPub), and register its release with t.Cleanup.
     - In a goroutine, run `keyroster ca issue` against the signer socket with the admin agent, as runIssue builds it, and record its start time. Build the exec.Cmd in the goroutine itself and report its exit code and output through a buffered channel. runBin calls t.Fatalf, which a goroutine must not.
  4. Wait for `entered` (10 s guard). The signer now holds s.mu in cert.Build.
  5. Sleep until t0 + 6 s (statusTTL + 1 s; krlTTL, serverclient.KRLMaxStale, is also 5 s), so both caches are stale.
  6. GET serverclient.KRLPath, with a 10 s client timeout, must answer 200 with the recorded body. Otherwise `t.Errorf("held-signature krl: got %d", code)`. On origin/main it answers 503: the status refresh waits for the lock and gives up at statusTimeout.
  7. `Once`, with a 10 s ctx, must return nil, with neither phrase in the log buffer. Otherwise `t.Errorf("held-signature state: %v", err)`. On origin/main it returns the state route's 503. Both steps report with t.Errorf, so both RED lines print.
  8. Release the gate.
     - When steps 6 and 7 passed, require that the release came within 7 s of the issue's start (otherwise `t.Errorf("held-signature hold: released %v after the issue started, budget 7s", d)`), and that the issue exits 0 within 15 s.
     - When either failed, only release and drain the channel (15 s). On origin/main steps 6 and 7 take about 3 s each, so the release comes about 8 s into the issue, and the issue may then fail at its 10 s deadline. That is expected on RED, not another reason.
  9. startFetch again.

  On GREEN the hold lasts about 2 s plus the GET and the Once.

**Local checks.** Local e2e cannot run on this machine. Run `bash scripts/linux.sh 'go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l test/e2e)"'`, and record that the test's first run is in CI.

**The RED on origin/main, from CI.**
1. Build the throwaway branch from the two test files only: `git switch -c p03/08i-e2e-red origin/main && git checkout T3 -- test/e2e/server_test.go test/e2e/stall_test.go`, then commit, signed and authored as Daniel. They reference no symbol this plan adds.
2. Before pushing, require that `git diff --name-only origin/main...p03/08i-e2e-red` lists exactly those two files. The push is public and cannot be taken back.
3. Push it (`env -u GITHUB_TOKEN -u GH_TOKEN git push origin p03/08i-e2e-red`), then switch back to `p03/08i-status-snapshot`.
4. Dispatch the e2e workflow: `scripts/gh-as-bot.sh workflow run e2e.yml --ref p03/08i-e2e-red`.
5. Poll `scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08i-e2e-red --limit 1 --json databaseId --jq '.[0].databaseId'` until it prints an ID, for up to about 60 s. Then `scripts/gh-as-bot.sh run watch "$R"`, and after it completes save `run view "$R" --log` outside the repository.
6. The expected RED: `--- FAIL: TestDeliveryDuringHeldSignature` once in each of the two OpenSSH lanes, each with the line `held-signature krl: got 503`, and no other `--- FAIL:` line. The issue's own failure there is expected.
7. Record the run ID and the failing lines in the SUMMARY. Delete the branch: `env -u GITHUB_TOKEN -u GH_TOKEN git push origin --delete p03/08i-e2e-red && git branch -D p03/08i-e2e-red`. Open no PR from it.

If the bot cannot dispatch the workflow, the run fails for another reason, or the RED is not as described in step 6, stop and report. The owner's decision takes the RED from CI; do not substitute a reasoned one.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l test/e2e)"'</automated>
    <fails_when>non-zero exit (the e2e package does not build, or is not gofmt-clean)</fails_when>
    <automated>R=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08i-e2e-red --limit 1 --json databaseId --jq '.[0].databaseId') && test -n "$R" && L=$(scripts/gh-as-bot.sh run view "$R" --log) && test "$(printf '%s\n' "$L" | grep -- '--- FAIL: TestDeliveryDuringHeldSignature ' | wc -l)" -eq 2 && test "$(printf '%s\n' "$L" | grep -- 'held-signature krl: got 503' | wc -l)" -ge 2 && ! printf '%s\n' "$L" | grep -- '--- FAIL: ' | grep -v 'TestDeliveryDuringHeldSignature' | grep -q .</automated>
    <fails_when>non-zero exit: no dispatched run on the throwaway branch, TestDeliveryDuringHeldSignature did not fail in exactly the two lanes, the line `held-signature krl: got 503` is not there in both, or another test failed</fails_when>
    <automated>D=$(git diff --name-only T2...T3) && ! printf '%s\n' "$D" | grep -v '^test/e2e/' | grep -v '^\.planning/' | grep -q . && { git ls-remote --exit-code origin p03/08i-e2e-red >/dev/null; test $? -eq 2; }</automated>
    <fails_when>non-zero exit: Task 3 changed a file outside test/e2e, or the throwaway branch still exists on origin, or the remote could not be asked (any ls-remote exit other than 2)</fails_when>
  </verify>
  <acceptance_criteria>
    - `D=$(git diff --name-only origin/main...HEAD -- test/e2e/) && test "$(printf '%s\n' "$D" | sort | tr '\n' ' ')" = "test/e2e/server_test.go test/e2e/stall_test.go "`: the e2e change is exactly these two files.
    - The SUMMARY records the CI run ID and the failing lines of the RED on origin/main, and that the branch was deleted.
    - Task 4's check of the PR's own e2e run shows `--- PASS: TestDeliveryDuringHeldSignature`.
  </acceptance_criteria>
  <done>A real keyroster-server in front of the real signer answers GET /api/v1/krl and an approved agent's state with 200 while one signature is held past statusTTL and krlTTL, and the same test fails on origin/main with 503 in CI.</done>
</task>

<task type="auto">
  <name>Task 4: The runbook updates, the Q-I4 pointers, the publish edits, the gates, the PR, the pre-merge review and the SUMMARY</name>
  <files>docs/runbooks/server-install.md, docs/runbooks/signer-install.md, .planning/phases/03-linux-agent-and-revocation/03-08i-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/server-install.md: `**Signer calls in flight.**` through the paragraph after it (about 1 KB).
    - docs/runbooks/signer-install.md: `**During a slow signature**` with the `Run in CI` line after it, and the sentence about a successor installed under a running signer, before `> **UNVERIFIED on the homelab signer.**` (about 2 KB).
    - .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md and 03-08h-PLAN.md: only the five lines that hold the sentences Q-I4 quotes, found with `grep -nF` on each sentence.
    - .planning/ROADMAP.md: Phase 3's Plans line, its wave blocks (`grep -n 'Wave\|Plans:'`) and the Progress table's Phase 3 row (`grep -n '^| 3\. Linux Agent'`).
    - .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter and Task 1's `<precondition>`. The `wave:` and `depends_on:` lines of 03-10 to 03-16.
  </read_first>
  <action>
**Runbooks (CONTEXT D-20).** Each new text is labelled with what runs it: the named CI tests (03-08i), and UNVERIFIED on a real host. None describes how to provoke a limit.
1. **server-install.md.** Replace the paragraph that begins `If the signer's key is on a hardware token` with one that says:
   - Calls that need the signer's lock wait while it waits for a touch. Neither the KRL read nor the signer's status is among them: the signer answers its status from a snapshot without waiting for the lock (03-08i). So the KRL route and the host routes keep answering during a long touch, for hosts at the current versions.
   - Calls that wait for the signer pile up during a signature: those that need its lock, and, while the signature runs inside the signer's database transaction (its audit-log and KRL signatures), the reads of older bundles and directories that hosts catching up need. When they fill the server's 12 signer calls (as few as 6 interactive calls beside 6 such reads), or once the signer still holds connections of calls the server gave up on (signer-install.md, "During a slow signature"), the routes answer 503. A host catching up may get 503 until the signature ends. (The waiting catch-up reads are reasoned from the code; no test runs them. UNVERIFIED.)
   - A server started or restarted during a signature now starts. Before 03-08i, it exited if the signature lasted longer than its 30 s start-up wait. Its KRL route works at once. Its host routes answer 503 until the signature ends, because the server cannot fill its copy of the directory before that, and the same holds after an install that no request fetched before the signature began. (Reasoned from the code; no test starts a server, or meets a cold mirror, during a signature. UNVERIFIED.)
   - /healthz shows only that the server can read the signer's status. It no longer shows that the signer is free to sign or that its main database connection is free (not held by a signature inside a transaction). Watch for timeouts or 503s on issuing, login and revocation calls. (Reasoned from the code; no test runs /healthz during a signature. UNVERIFIED.)
   - Hosts keep what they applied and ask again at their next poll.
   - Run in CI: TestStatusLockFree and TestStatusSnapshot (the signer), TestRoutesPastStatusTTLWithHeldCall (the server, against its test double), and TestDeliveryDuringHeldSignature (e2e: a real server in front of the real signer with one signature held). UNVERIFIED on a real host.
2. **signer-install.md**, in `**During a slow signature**`:
   - Name the calls that wait for the lock: logins, issues, revocations, directory installs and directory reads, forgets, and the logging of every refused request.
   - Add that the signer's status is not among them (03-08i): it answers from a snapshot of the installed directory and the trust state it loaded, and checks the latest bundle version through a separate read-only database handle, so keyroster-server keeps a recent status.
   - Change the clause about calls it could otherwise answer at once to say: at once outside a signature that runs inside the signer's database transaction. Record this edit to a kept sentence in the SUMMARY.
   - Replace any wording that implies a fixed cap on how long a signature can hold the lock. Say instead that with the agent backend each signature can take up to twice its 30 s request deadline (one retry on a new connection), that a PIV key pinned with `--key` and generated with a touch policy waits for the card's own timeout, and that one operation can sign more than once while it holds the lock.
   - Add `TestStatusLockFree`, `TestStatusSnapshot` and `TestDeliveryDuringHeldSignature` (03-08i) to the following `Run in CI` line.
3. **signer-install.md**, the sentence about a successor installed under a running signer anyway, which says that signer refuses all requests with `trust_changed` until a restart. Reword it: that signer refuses `trust_changed` for its status and for every request that issues, logs in, installs a directory, revokes, forgets or publishes a KRL, until it is restarted; it never issues under the superseded policy. Recovery is left out: a running signer never serves it. The test names in the UNVERIFIED note after it stay.

**Q-I4 (B).** Insert exactly ` (Since 03-08i, a Status that answers does not wait for s.mu; see 03-08i-PLAN.md.)` right after each of the five sentences the Q-I4 decision quotes: three in 03-08g-PLAN.md and two in 03-08h-PLAN.md. Inside a table row it stays within the cell. Change nothing else in either file, and nothing in any SUMMARY.

**Publish edits.** Make them in this PR, on top of origin/main. Every number is origin/main's value + 1. The values in brackets are what main holds at d819904.
1. Commit this plan unchanged as `.planning/phases/03-linux-agent-and-revocation/03-08i-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each go up by one (N/28 in 27 waves → N/29 in 28 waves). GSD's tracking update sets N.
   - The Progress table's Phase 3 row's total goes up by one (20/28 → N/29).
   - After 03-08h's Wave 19 block, insert `**Wave 20** *(blocked on Wave 19 completion)*` with the unchecked entry `03-08i-PLAN.md — Signer status without the lock: one snapshot published after every committed directory change, answered while a slow signature holds the signer's lock, with the trust check kept through a read-only handle`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 20–27 → 21–28), each "blocked on" clause with them.
3. STATE.md: `total_plans` + 1 (63 → 64), and the Plan line's `of M` + 1 (of 28 → of 29).
4. 03-09-PLAN.md:
   - `wave:` + 1 (20 → 21);
   - `depends_on` becomes `["03-08i"]`;
   - in Task 1's `<precondition>`, add the clause `` `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md` exits 0 `` right after the 03-08h clause, joined with `; `, before the `(03-08c shares` parenthetical. Every other clause stays.
5. The `wave:` lines of 03-10 to 03-16 each go up by one (21–27 → 22–28).
6. **Guard.** If origin/main's 03-09 does not hold `wave: 20` and `depends_on: ["03-08h"]`, another plan was slotted in first. Then apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY. The checks below compute from origin/main, so they hold either way.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record.

**Push, the PR and the pre-merge review.**
1. Commit by path only, signed and authored as Daniel.
2. Push the branch for the first time.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(signer): answer Status without waiting for the signer's lock"` with a neutral body that lists the changes as in the objective and names the limits that remain (Q-I2, Q-I3). Do not enable auto-merge, now or later.
4. Wait for the required checks, and confirm that the PR's e2e run passed TestDeliveryDuringHeldSignature (verify below).
5. The orchestrator then runs the pre-merge review on the green PR, before Task 5. It reviews the diff against T-03-324 to T-03-328, and that review is the owner's threat review. It also checks the diff for host names and private terms, which this plan does not list. Its findings, the fix rounds and their checks are recorded in the SUMMARY.

**The SUMMARY** contains:
- the PR number and the check run IDs;
- the RED evidence of Tasks 1 to 3, with where each was taken, the e2e RED's CI run ID included;
- the mutants of Tasks 1 and 2;
- the base and Task 4 readings of both test-time gates (apply alone, and apply and internal/signer under ./...), Task 1's and Task 2's internal/signer times, and CI's build-test time with its internal/signer and internal/server times;
- every existing assertion that moved, and why, and the edit to signer-install.md's kept sentence;
- what stays UNVERIFIED: readDirectory's unparsed state; the catch-up reads waiting for the transaction; Status during the ops key's KRL signature inside the transaction (covered by the log-key case's property, not by its own test); the read-only handle's committed-state isolation (the planner's probe only); the serve-without-StatusDB mutant (reasoned, not run); server-install.md's start-up, cold-mirror and /healthz bullets; and every runbook claim on a real host;
- capslock, and the pre-merge review;
- `requirements-completed` left empty: REVOKE-02 and AGENT-02 were completed by earlier plans, and this plan hardens both.

Then run the tracking updates once, commit `docs(03-08i): complete status-snapshot plan`, push, and wait.
  </action>
  <verify>
    <automated>git diff --quiet HEAD -- docs/runbooks/server-install.md docs/runbooks/signer-install.md .planning/ROADMAP.md .planning/STATE.md .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md .planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md .planning/phases/03-linux-agent-and-revocation/03-1[0-6]-PLAN.md && test -z "$(git ls-files --others --exclude-standard .planning/phases/03-linux-agent-and-revocation/03-08i-*.md)"</automated>
    <fails_when>non-zero exit: an edit to a file this plan publishes is not committed, so the content checks below would read the working tree instead of the commit. This guard runs first. It is path-scoped, because the intentionally dirty .planning files would fail a bare `git status --porcelain`</fails_when>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit: internal/agent/apply took more than 400 s alone, or no single ok line; a figure above its limit is a deviation to stop on and report</fails_when>
    <automated>set -o pipefail; grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} $1=="ok" && $2 ~ /\/internal\/signer$/ {u=$3; sub(/s$/,"",u); m++; if (u+0 > 480) bad=1} END{exit (n!=1 || m!=1 || bad)}'</automated>
    <fails_when>non-zero exit (a gate failed, or the `ok` line of internal/agent/apply or internal/signer under `./...` is missing or above 480 s), or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -q 'without waiting for the lock (03-08i)' && tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -q 'TestDeliveryDuringHeldSignature' && tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -q '/healthz shows only' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -q 'TestStatusLockFree' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -q 'forgets or publishes a KRL' && test "$(tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -c 'few seconds')" -eq 0 && test "$(tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'refuses every request')" -eq 0</automated>
    <fails_when>non-zero exit: a runbook update is missing, server-install.md still states the old limit, or signer-install.md still says every request is refused</fails_when>
    <automated>( P=.planning/phases/03-linux-agent-and-revocation && X=" (Since 03-08i, a Status that answers does not wait for s.mu; see 03-08i-PLAN.md.)" && for f in 03-08g 03-08h; do diff <(MSYS_NO_PATHCONV=1 git show origin/main:$P/$f-PLAN.md) <(sed 's/ (Since 03-08i, a Status that answers does not wait for s\.mu; see 03-08i-PLAN\.md\.)//' $P/$f-PLAN.md) >/dev/null || exit 1; done && test "$(grep -oF "$X" $P/03-08g-PLAN.md | wc -l)" -eq 3 && test "$(grep -oF "$X" $P/03-08h-PLAN.md | wc -l)" -eq 2 && grep -qF "planned as follow-up plan 03-08i (owner decision 2026-10-30; Deferred ledger).$X" $P/03-08g-PLAN.md && grep -qF "a Status that does not wait for the lock is follow-up plan 03-08i.$X" $P/03-08g-PLAN.md && grep -qF "read without the lock (owner decision 2026-10-30).$X" $P/03-08g-PLAN.md && grep -qF "A Status read without the lock is follow-up plan 03-08i (owner decision 2026-10-30).$X" $P/03-08h-PLAN.md && grep -qF "GetKRL, GetBundle and GetDirectoryVersion do not.$X" $P/03-08h-PLAN.md && S=$(git diff --name-only origin/main...HEAD -- $P/03-08g-SUMMARY.md $P/03-08h-SUMMARY.md) && test -z "$S" )</automated>
    <fails_when>non-zero exit: a landed plan changed beyond the Q-I4 pointer, a pointer is missing after its sentence or appears elsewhere, or a landed SUMMARY changed</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')" && RL=$(git rev-list origin/main..HEAD) && test -n "$RL" && ( for c in $RL; do C=$(git cat-file commit "$c") || exit 1; printf '%s
' "$C" | grep -q '^gpgsig' || exit 1; done )</automated>
    <fails_when>non-zero exit (the branch has no commits, a commit has another author or a committer other than keyroster-bot, or a commit is unsigned)</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && ( for n in 09 10 11 12 13 14 15 16; do X=$(MSYS_NO_PATHCONV=1 git show origin/main:$P/03-$n-PLAN.md) || exit 1; W=$(printf '%s\n' "$X" | sed -n 's/^wave: //p'); test -n "$W" && grep -qx "wave: $((W+1))" $P/03-$n-PLAN.md || exit 1; done ) && grep -qx 'depends_on: \["03-08i"\]' $P/03-09-PLAN.md && grep -n '<precondition>' $P/03-09-PLAN.md | head -1 | grep -qF '03-08h-SUMMARY.md` exits 0; `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md` exits 0 (03-08c shares' && ST=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/STATE.md) && T=$(printf '%s\n' "$ST" | sed -n 's/^  total_plans: //p') && test -n "$T" && grep -qx "  total_plans: $((T+1))" .planning/STATE.md && O=$(printf '%s\n' "$ST" | sed -n 's/^Plan: [0-9]* of \([0-9]*\)$/\1/p') && test -n "$O" && grep -Eq "^Plan: [0-9]+ of $((O+1))$" .planning/STATE.md && RM=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/ROADMAP.md) && R=$(printf '%s\n' "$RM" | grep -m1 -oE '[0-9]+/[0-9]+ plans executed in [0-9]+ waves') && M=$(printf '%s' "$R" | sed -E 's#^[0-9]+/([0-9]+) .*#\1#') && V=$(printf '%s' "$R" | sed -E 's#.* in ([0-9]+) waves#\1#') && grep -Eq "[0-9]+/$((M+1)) plans executed in $((V+1)) waves" .planning/ROADMAP.md && PR0=$(printf '%s\n' "$RM" | awk -F'|' '/^\| 3\. Linux Agent/{print $3}' | sed -E 's#.*/([0-9]+).*#\1#') && test -n "$PR0" && awk -F'|' '/^\| 3\. Linux Agent/{print $3}' .planning/ROADMAP.md | grep -Eq "/$((PR0+1)) *$" && grep -q '03-08i-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit: a publish edit is missing or wrong. Each of these is checked against origin/main's value + 1: the waves of 03-09 to 03-16, 03-09's dependency and the place of its new precondition clause, STATE's total_plans and `of M`, the ROADMAP Plans line's total and wave count, the Progress row's total, and the ROADMAP row</fails_when>
    <automated>RM=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/ROADMAP.md) && X=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md) && W9=$(printf '%s\n' "$X" | sed -n 's/^wave: //p') && test -n "$W9" && N0=$(printf '%s\n' "$RM" | awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}') && N1=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{n++} END{print n+0}' .planning/ROADMAP.md) && test "$N1" -eq "$((N0+1))" && awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; n++; if (w!=n) bad=1; if (w>1 && index($0,"*(blocked on Wave " (w-1) " completion)*")==0) bad=1} END{exit bad}' .planning/ROADMAP.md && K8=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-08i-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K8" | grep -q "^\*\*Wave $W9\*\*" && K9=$(awk '/^### Phase 3:/{p=1;next} /^### Phase /{p=0} p && /^\*\*Wave [0-9]+\*\*/{w=$0} p && /03-09-PLAN\.md/{print w; exit}' .planning/ROADMAP.md) && printf '%s\n' "$K9" | grep -q "^\*\*Wave $((W9+1))\*\*"</automated>
    <fails_when>non-zero exit: any of these fails in Phase 3 of the ROADMAP:
      - the wave headers number one more than on origin/main;
      - they run 1..N in order;
      - every block N above 1 says "blocked on Wave N-1 completion";
      - the 03-08i row sits under the wave origin/main's 03-09 had, and the 03-09 row one wave later.
    </fails_when>
    <automated>git fetch origin p03/08i-status-snapshot && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08i-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics' && C=$(git diff --name-only origin/main...HEAD -- cmd/) && test "$C" = "cmd/keyroster-signer/serve.go"</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, a forbidden file was committed, or cmd/ changed beyond serve.go)</fails_when>
    <automated>D=$(git diff origin/main...HEAD) && L=$(git log origin/main..HEAD --format=%B) && B=$(scripts/gh-as-bot.sh pr view p03/08i-status-snapshot --json body --jq .body) && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '127\.0\.0\.1' | grep -q . && printf '%s\n%s\n' "$L" "$B" | grep -ciE 'co-authored-by|generated with' | grep -qx 0</automated>
    <fails_when>non-zero exit: an IP address other than loopback is in the diff, a commit message or the PR body, or an attribution line is present</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08i-status-snapshot --required --watch && R=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch p03/08i-status-snapshot --limit 1 --json databaseId --jq '.[0].databaseId') && test -n "$R" && L=$(scripts/gh-as-bot.sh run view "$R" --log) && printf '%s\n' "$L" | grep -q -- '--- PASS: TestDeliveryDuringHeldSignature'</automated>
    <fails_when>non-zero exit (a required check failed or never reported, or the PR's e2e run did not pass TestDeliveryDuringHeldSignature)</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/08i-status-snapshot --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled on the PR)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new runbook text names at least one CI test and says UNVERIFIED on a real host.
    - `git log origin/main..HEAD --format='%an <%ae> %cn'` prints at least one line, every line is `Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot`, and every commit carries a signature.
    - The PR is open without auto-merge, every required check is green, the PR's e2e run passed TestDeliveryDuringHeldSignature, and 03-08i-SUMMARY.md is on its head.
    - The pre-merge review's findings and fix rounds are in the SUMMARY.
  </acceptance_criteria>
  <done>The PR waits green, reviewed, with the plan, the runbook updates, the Q-I4 pointers and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — the owner reviews PR p03/08i-status-snapshot, and Daniel squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7), read with this plan's Delivery protocol override (merge-gate.sh's plain form only after the merge)
  </read_first>
  <action>After the pre-merge review (Task 4 step 5), the owner reviews, approves and squash-merges the PR in the GitHub web UI (owner, 2026-11-02). Claude never approves or merges, never enables auto-merge and never waits for it.</action>
  <instructions>
    1. Open `gh pr view p03/08i-status-snapshot --web`. Read 03-08i-SUMMARY.md, and review:
       - Status, the snapshot, publishStatusLocked, setDirectoryLocked and readDirectory;
       - Config.StatusDB and serve's read-only handle;
       - TestStatusWriters, TestDeliveryDuringHeldSignature and the runbook texts.

       Check especially:
       - Status takes no lock and reads only through the read-only handle;
       - a missing or failing handle refuses;
       - the snapshot is published only after COMMIT, and before InstallDirectory answers;
       - every reply carries the bundle row the signer loaded;
       - a refused Status is still logged.
    2. Approve and squash-merge in the GitHub web UI, with your commit email. No admin bypass, no "Update branch".
    3. Reply "merged". If main moved before you merged, Claude rebases the branch by hand and pushes it. Review the new head, then merge it and reply "merged".
  </instructions>
  <verification>
    - **Before the merge.** Claude runs merge-gate.sh only as `bash scripts/merge-gate.sh --check p03/08i-status-snapshot`, which is read-only and exits 1 while the PR is open. It never runs the plain form before the merge.
    - **When main moved.** If `git merge-base --is-ancestor origin/main origin/p03/08i-status-snapshot` fails after `git fetch origin`, Claude rebases by hand:
      - on the branch, run `git rebase --gpg-sign origin/main`. The authors stay Daniel's, and keyroster-bot is committer and signer;
      - for `.planning/` tracking files, take origin/main's version and re-apply only this plan's entries, as 01-SKELETON step 5's exit 4 describes. For the runbooks, keep main's text and re-apply this plan's updates;
      - push with lease, as keyroster-bot, and do not enable auto-merge;
      - wait for the required checks, run Task 4's authorship and signature check again, and ask the owner to review the new head.
    - **After the owner replies "merged".** From the main checkout, Claude runs `bash scripts/merge-gate.sh p03/08i-status-snapshot` (the script refuses to run as any copy but origin/main's). For a merged PR it only fast-forwards local main and exits 0. Then Claude runs the `--check` form below.
  </verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08i-status-snapshot</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-09's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08i-status-snapshot --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The signer's Status no longer waits for its lock on main, and 03-09 may start.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08g** gives this plan the coalesced refresh, statusTTL, statusTimeout, krlTTL and the budget. Its budgetSigner and signerAPI growth rule stay unchanged (Q-I2 A). TestKRLDuringFullBudget, TestSignerBudget and TestAgentInFlight must stay green.
- **03-08h** gives this plan the share and the release ordering. Its stall residual (T-03-307) loses its main source: the server's status refresh, which used to wait for the lock and was retried by the next request after statusTimeout, leaving a stuck connection each time. The start-up probe's abandoned connections go away as well. Logins, revocations, installs, forgets, directory reads and refused requests still wait and still pile up. TestConnSlots and TestPeerShare must stay green, and their numbers do not change.
- **03-09 and 03-10** add HostIssue and ProbeIssue. Both take s.mu on the signer and change no field Status reports, so they need nothing from this plan beyond keeping TestStatusWriters green.
- **03-12 and 03-13** change the CA, log and ops keys through install-bundle and a restart. trustState.caKeys becomes the active generation, read in New. New builds the snapshot from it, so Status reports the key in use. If either plan changes a Status field while the process runs, it goes through setDirectoryLocked or extends publishStatusLocked, and TestStatusWriters' lists with it. A new or changed field in wire.StatusResponse trips its field list.
- **Later plans that edit the same files** must keep TestStatusLockFree, TestStatusSnapshot, TestStatusWriters and TestDeliveryDuringHeldSignature green. Any new writer of the directory state goes through setDirectoryLocked. Any new caller of signer.New that serves passes Config.StatusDB.
- **03-16 (homelab drill)** provokes no slow signature, so the runbook texts stay UNVERIFIED on a real host.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: what a slow signature still blocks** (all residuals of T-03-326):
- **The lock.** Logins, issues, revocations, directory installs, forgets, GetDirectory (Q-I3), and refuseLogging for every refused request, a refused Status included, still take s.mu. A refused Status during a signature therefore waits and holds its signer slot. The server answers 503 then either way, because a refused Status is a failed refresh.
- **The main database connection.** GetBundle and GetDirectoryVersion read through the signer's one main connection without the lock. They wait while a transaction is open, which includes the log key's checkpoint signature on every state change and the ops key's KRL signature on revocations and republishes. They do not wait during the CA key's signature, which runs before the transaction. Agents at the current versions make neither call. Status reads only through the read-only handle, so never waits for it. That the catch-up reads wait is reasoned from the code and UNVERIFIED.
- **The read-only handle.** It does not wait for the main handle's transaction: measured by the planner's probe and pinned by `answers_during_log_key_signature`. It reads committed state only: SQLite's WAL reader isolation, measured by the uncommitted planner probe only, UNVERIFIED in CI. In WAL edge cases such as recovery it can wait up to its busy_timeout (5 s) and then fail; Status then refuses state_unavailable. UNVERIFIED: no test provokes WAL recovery. The handle is opened by path and stays on the opened file while its one pooled connection lives. A reconnect after signer.db is renamed or replaced under the running signer could make Status check another file than issuance does. UNVERIFIED; it needs the signer's uid and a bypassed state-directory lock. No code change.
- **The server's budget (Q-I2).** If calls waiting for the signer hold all 12 tokens (as few as 6 interactive calls beside 6 catch-up reads during the in-transaction part of a signature), the refresh waits up to statusTimeout, and both routes answer 503 past statusTTL (`budget_full_status_waits`).
- **The signer's share (03-08h, T-03-307).** Calls the server abandoned keep their slots until the signature ends. Once more than 3 are stuck beyond the server's 13, its next calls are closed unanswered, Status and GetKRL included.
- **The cold mirror (Q-I3).** The mirror is cold when it lacks the version the latest Status reports: after a server restart, or after an install that no request fetched before the signature began. Its host routes then answer 503 until the signature ends, and each failed fetch leaves one abandoned connection per signerCallTimeout. The KRL route is unaffected. A server started during a signature now starts, where before 03-08i it exited after statusWait (30 s).
- **Detection is immediate.** A bundle installed and committed under the running signer is refused at the next Status, also while s.mu is held (`successor_refused_while_mu_held`). An install whose transaction has not committed yet is not seen, which is correct. A Status whose read came just before an external commit reports the old bundle, as today. No issuance, login, revocation, KRL publish, directory install, forget or recovery can commit under the superseded bundle (their in-transaction checks); only refusal and summary records can.
- **Visibility (T-03-328).** A Status answer no longer shows that the signer can sign or that its main database connection is free. It shows that the signer's process answers, that the read-only handle reads, and that the loaded bundle is the latest. /healthz, which reads the status, says ok while a signature holds the lock.
- **How long a signature can hold the lock.** With the agent backend, each signature can take up to twice its 30 s request deadline, because the backend retries once on a new connection. A PIV key pinned with `--key` and generated with a touch policy waits for the card's own timeout; ca-init creates PIV keys with touch policy never, and TPM and software keys never ask. One operation can sign more than once while it holds the lock (the CA key, then the log key; or the ops key, then the log key). Before this plan, the routes answered 503 once the cached status was older than statusTTL, so within about 5 s of such a signature's start.

**Edges:**
- ordering:
  - the snapshot is published after COMMIT and before InstallDirectory answers (TestStatusWriters, `install_then_status_over_socket`);
  - a failed transaction leaves the old snapshot;
  - a restart publishes the loaded state, authorized or not, and the zero state when no directory is stored;
- concurrency:
  - readers during a run of installs see only whole, committed (version, SHA-256) pairs, never decreasing;
  - Status with s.mu held by a CA-key signature, by a log-key signature inside the transaction, and by the test itself;
- trust: a successor installed while s.mu is held, and during a CA-key signature (refused at once); an emptied bundle table (refused); a row edited in place (not passed on);
- failures: no read-only handle, a closed one, a cancelled ctx (each refused); a reply above wire.MaxStatusFrame; a nil snapshot; a refusal while the lock is held;
- the server: past statusTTL with one held call (200, one refresh) and with the whole budget held (503, no refresh); the real server in front of the real signer with one signature held past statusTTL and krlTTL (200, e2e);
- the controls that must not change:
  - TestStatusTrustChanged, TestStatusOverSocket and TestStatusReportsDirectory;
  - every wantDirectory site;
  - 03-08g's and 03-08h's capacity tests.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access granted or revoked centrally takes effect across the fleet | Tasks 1-3 |
| REQ | REVOKE-02 (KRLs distributed to all hosts automatically) | Task 1 (Status during a held signature), Task 2 (`krl_and_state_past_status_ttl`), Task 3 (e2e GET krl), Task 4 runbooks |
| REQ | AGENT-02 (the pull channel) | Task 2 (the state route past statusTTL), Task 3 (an approved agent's Once); Q-I3 scopes the cold mirror |
| Owner decision | A lock-free Status snapshot, updated under s.mu at every state change, read without the lock; its own threat review and plan check (2026-10-30) | Tasks 1, 2; threat register T-03-324 to T-03-328; the pre-merge review as the threat review (Task 4 step 5) |
| Owner decision | Q-I1 B: the trust check through a read-only handle on every call, fail-closed | Task 1 (Config.StatusDB, serve, Status, the successor, handle-failure and emptied-table cases and mutants); T-03-325 |
| Owner decision | Q-I2 A, Q-I3 A with the corrected facts | Task 2 (`budget_full_status_waits`); Task 4 runbooks; Edge Coverage; T-03-326 |
| Owner decision | Q-I4 B, the fixed pointer | Task 4 (the pointers and their diff check) |
| Owner decision | Q-I5: the e2e case, its RED from CI | Task 3 |
| Owner decision | Delivery: plan in its PR, neutral wording, signed commits authored as Daniel, no auto-merge | Delivery protocol; Tasks 4, 5 |
| Owner decision | Q-G1, Q-G2, Q-G5 unchanged | Q-I2 A; Cross-plan notes |
| Plan check 2 of 03-08g | Item 1 (Q-G5's aim beyond statusTTL had no home), item 7 (a snapshot every s.mu-holding state change refreshes) | Tasks 1-3 |
| Plan check 1 of 03-08i | 45 surviving findings and 8 critic findings | Review Dispositions Ledger, Round 1 |
| 03-08g | Deferred row, Edge Coverage and T-03-308 pointing here | This plan; Q-I4 pointers (Task 4) |
| 03-08h | Edge Coverage's last stalled-signer bullet, T-03-307 | This plan; Q-I4 pointers (Task 4); Cross-plan notes |
| CONTEXT | 03-CONTEXT D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 4 |
| CONTEXT | 01-CONTEXT D-14 (refusals logged at a rate, the rest summarized) | Unchanged: statusOrRefuse still logs; `refused_status_waits_for_refusal_log` |
| Deferred | GetDirectory from the snapshot; Status outside the budget; refusal logging without s.mu | Deferred ledger |

## Artifacts this phase produces (this plan)

- **signer:**
  - Config.StatusDB, statusSnapshot, newStatusSnapshot and publishStatusLocked;
  - setDirectoryLocked and readDirectory;
  - the status pointer and bundleRow;
  - Status without any lock, with the trust check through the read-only handle.
- **cmd/keyroster-signer:** serve opens and closes the read-only handle.
- **Tests:**
  - TestStatusLockFree (10 cases);
  - TestStatusSnapshot (6 cases), TestStatusWriters, and the snapshot check in wantDirectory;
  - TestRoutesPastStatusTTLWithHeldCall (2 cases, internal/server);
  - TestDeliveryDuringHeldSignature and its gated agent proxy (test/e2e).
- **Docs:**
  - server-install.md, the routes during a long touch, start-up during a signature, and /healthz;
  - signer-install.md, the status during a slow signature and what a superseded bundle refuses.
- **Planning:** the Q-I4 pointers in 03-08g and 03-08h.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| signer state → Status readers | Status is read without the signer's lock by keyroster-server (which takes the policy, RP, custody and directory versions from it, at start-up and on every refresh) and by the CLI. It must report only committed state under the bundle the signer runs on |
| another process → the signer's database | A process that bypasses the state-directory lock can install a bundle or edit rows under the running signer. Status must not carry such state, and must refuse once a successor is committed |
| a slow signature → delivery | While a signature holds the lock, the server's KRL and host routes depend on Status not waiting for it |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-324 | Tampering | Signer.Status read without the lock: a reply torn between two installs, ahead of a commit that then failed, or behind an install that has already answered its caller (this plan's own risk) | low | mitigate | One immutable snapshot behind an atomic.Pointer, built whole by newStatusSnapshot. Only setDirectoryLocked publishes it, once in InstallDirectory as a statement after logTx and its error check, and once in loadDirectory. Tests: `no_torn_reply`, `failed_transaction_keeps_snapshot`, `install_then_status_over_socket`, the snapshot check in every wantDirectory call. TestStatusWriters is a syntactic gate against the common write forms (field names on any selector, `&`, copy-like calls, composite literals, callers and placement), with an explicit allowlist; it does not prove that no write form exists. **Residual:** a write form the gate does not parse (for example through reflection or unsafe) would pass it; review is the second line |
| T-03-325 | Elevation of privilege | trust_changed on the lock-free path: a signer whose bundle was superseded under it keeps answering Status, so keyroster-server keeps authorising admins and RP origins, minting invites and join tokens, and serving agents under the superseded policy, and starts with its RP ID | medium | mitigate | Q-I1 B: on every call Status reads the latest bundle version through the read-only handle and refuses trust_changed on a mismatch, also while s.mu is held, so the server stays fail-closed as today. A missing handle, a read error or a cancelled ctx refuses state_unavailable; Status never answers without the check. Every reply carries the row loaded and checked against the log at start. A refused Status is still logged (D-14). Option A, which would have deferred detection while s.mu was contended, was rejected for this reason. Tests: TestStatusTrustChanged, `successor_refused_while_mu_held`, `successor_refused_during_ca_signature`, `status_db_missing_or_failing_refuses`, `emptied_bundle_table_refused`, `reply_carries_loaded_bundle`, and their mutants. **Residual:** a Status whose read came just before an external commit reports the old bundle, as today; in WAL edge cases the read can wait up to its busy_timeout before it refuses; the handle is opened by path, so a reconnect after signer.db is renamed or replaced under the running signer could check another file than issuance does (UNVERIFIED; it needs the signer's uid and a bypassed state-directory lock) |
| T-03-326 | Denial of service | KRL and agent-state delivery during a slow signature (the owner's aim) | low | mitigate | Status never waits for the lock or the main connection, so the server's status cache refreshes during the signature. Tests: `answers_during_ca_signature`, `answers_during_log_key_signature`, TestDeliveryDuringHeldSignature (e2e, a real server in front of the real signer). `krl_and_state_past_status_ttl` pins the server's half against the test double; it is not a test of this change. **Residual:** (1) the server's budget: calls waiting for the signer that hold all 12 tokens, as few as 6 interactive calls beside 6 catch-up reads during the in-transaction part of a signature, still starve the refresh (Q-I2; `budget_full_status_waits`); (2) 03-08h's share: more than 3 abandoned calls beyond the server's 13 still close its calls, and each failed directory fetch adds one per signerCallTimeout; (3) GetDirectory still waits, so a cold mirror (after a restart, or an install no request fetched) leaves the host routes at 503 until the signature ends (Q-I3); (4) catch-up reads wait for transactions that sign inside them (UNVERIFIED); (5) a refused Status waits for the lock to log its refusal (`refused_status_waits_for_refusal_log`). With the agent backend a signature can hold the lock up to twice its 30 s deadline, and a PIV key generated with a touch policy up to the card's timeout. server-install.md and signer-install.md say so |
| T-03-327 | Tampering | a Status reply shared between callers, so a caller that changes it changes every later reply (this plan's own risk) | low | mitigate | Status returns a copy; the snapshot's reply is never handed out. Test: `reply_is_a_copy`, checking every slice field, and its mutant |
| T-03-328 | Repudiation | visibility: a Status answered from the snapshot no longer shows that the signer is stuck in a signature or that its main database connection is busy, so /healthz and the server look healthy while issuing and revocation wait | low | accept | A Status answer still shows that the signer's process answers, that the read-only handle reads, and that the loaded bundle is the latest. Issuing, login and revocation calls still time out or answer 503 while the lock is held, and server-install.md tells operators to watch those, not /healthz. The signer logs nothing while a signature waits; a stuck signature shows as issuing, login and revocation calls that time out or answer 503 (server-install.md), and on the token or agent itself (a touch prompt). UNVERIFIED on a real host. Accepted: the owner's aim is that delivery keeps working during exactly that wait |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; reflect and go/parser are stdlib and used in tests only, and the e2e proxy uses x/crypto/ssh/agent, already a test dependency. The signer still imports nothing under internal/agent (dep-firewall). The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh) or in CI as stated, the full gate passes, the PR's required checks are green with TestDeliveryDuringHeldSignature passing, the pre-merge review is recorded, and the merge gate passes.
</verification>

<success_criteria>
- While a signature holds the signer's lock, inside or outside the database transaction, Status answers at once from committed state, directly and over the socket, and a real keyroster-server in front of the real signer keeps answering GET /api/v1/krl and an approved agent's state with 200 past statusTTL and krlTTL.
- A bundle installed and committed under the running signer is refused trust_changed at the next Status, also while the lock is held. A missing or failing read-only handle refuses; Status never answers without the check.
- No reply is torn, ahead of a commit, or behind an install that has answered. TestStatusWriters fails on the common forms of a write that bypasses the snapshot.
- With the whole server budget held, the routes still answer 503, as server-install.md says.
- Nothing any component accepts or serves is widened, and no module is added.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08i-SUMMARY.md` in Task 4, before the merge gate. Leave `requirements-completed` empty: REVOKE-02 and AGENT-02 were completed by earlier plans, and this plan hardens both. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (the owner decision of 2026-10-30; plan check 2 of 03-08g, items 1 and 7; 03-08g's Deferred row and 03-08h's Edge Coverage)

### Round 0b — planner self-review while drafting (2026-11-05), before plan check 1

| Concern | Severity | How Addressed |
|---------|----------|---------------|
| Plan check 2 of 03-08g, item 1: Q-G5's aim held only while the status cache was fresh, and the rest had no home | WARNING | This plan: Tasks 1-3; T-03-326 |
| Plan check 2 of 03-08g, item 7: a snapshot that every s.mu-holding state change refreshes, with its own threat review | INFO | setDirectoryLocked as the one writer; TestStatusWriters; threat register |
| Planner: the signer's main database has one connection, and the log and ops keys sign inside transactions, so a Status that skipped the lock but read the main handle would still stall. A probe measured that the read waits | HIGH | Put to the owner as Q-I1; decided B (Round 1) |
| Planner: a writer that forgets to refresh the snapshot would make Status lie silently | MEDIUM | One setter that writes and publishes; TestStatusWriters |
| Planner: the server's budget and 03-08h's share still bound delivery with a lock-free Status | MEDIUM | Q-I2; `budget_full_status_waits`; T-03-326 |

### Round 1 — plan check 1 (2026-11-05, FAIL, fixable) and the owner's answers to Q-I1 to Q-I5 (Daniel, 2026-11-05)

Merged as the check's completeness critic directs; the 7 findings both skeptics refuted are dropped. "Moot (Q-I1 B)" marks findings about the rejected TryLock design.

| Finding(s) | Severity | Disposition |
|------------|----------|-------------|
| mechanics-qi4-diff-never-passes, with mechanics-pointer-overclaims and mechanics-pointer-and-precondition-checks-loose | BLOCKER | Fixed: the diff compares `git show` output directly through process substitution, in a subshell; the pointer reads "a Status that answers does not wait for s.mu" in the decision, the action, the sed and every grep -F; the counts use `grep -oF \| wc -l` (3 and 2); the 03-09 clause is checked inside its precondition line, before the `(03-08c shares` parenthetical |
| mechanics-gitbash-pathconv-and-linuxsh-claim | MINOR | Fixed: MSYS_NO_PATHCONV=1 on every `git show`/`git cat-file` of `origin/main:` or `FETCH_HEAD:`; the Shells bullet says what linux.sh actually does; gh-as-bot.sh and merge-gate.sh run without it |
| concurrency-01 + tests-01 (with refused_status_waits_for_refusal_log) | MAJOR | Fixed: Once-guarded release in a defer, deferred conditional unlocks, buffered channels, e.request() built in the test goroutine; RED is a named `--- FAIL`; `-timeout 120s` only on the `-run`-filtered RED and mutant commands |
| trust-1, with trust-6's recategorisation, critic-01's start-up case and trust-3 | MAJOR | Resolved by the owner (Q-I1 B): the check runs on every Status through the read-only handle, so the server stays fail-closed; A recorded as rejected for the fail-open reason; T-03-325 recategorised as Elevation of privilege, medium; B's facts corrected (OpenReadOnly exists; busy waits only in WAL edge cases) |
| mechanics-task1-scope-check-fails-at-finalize + tests-09 | MAJOR | Fixed with one check over `origin/main...T1`: nothing outside internal/signer, serve.go (Q-I1 B) and .planning/ |
| server-e2e-stall | MAJOR | Resolved by the owner (Q-I5): Task 3 builds TestDeliveryDuringHeldSignature with a gated agent proxy; its RED is taken from a dispatched CI run on a throwaway branch |
| mechanics-qi4-false-fact + mechanics-qi4-passage-list-incomplete | MAJOR | Fixed: the premise names #23, #44, #64, #71 and #75; the passages left alone are listed with reasons; the Round 0b row that repeated the false premise is gone |
| concurrency-04 + tests-02 + tests-03 + trust-4 + critic-02 (TestStatusWriters) | MINOR | Fixed: name-based matching on any selector after unwrapping, `&`, copy-like calls, composite-literal keys, callers, placement, receivers, rename guards and an allowlist that fails when stale; go/types rejected with its reason; truth 4 and T-03-324 say "syntactic gate against the common write forms"; the aliasing mutant added. The trustChanged rules and the "Store above the err return" mutant are moot (Q-I1 B: no flag); trust-4's cancelled-ctx case is kept as part of `status_db_missing_or_failing_refuses` |
| concurrency-02 + trust-2 (TryLock and the detection bound) | MINOR | Moot (Q-I1 B): no TryLock, and detection is immediate. republishIfDue's not-due path no longer matters to detection |
| concurrency-03 | MINOR | Fixed: TestStatusWriters' placement rule (a top-level statement after logTx and its error block, once); the in-closure mutant; the case renamed `failed_transaction_keeps_snapshot` and scoped to failures before COMMIT |
| concurrency-05 + tests-05 | MINOR | Fixed without unsafe.SliceData: every slice field and one Keys field changed and checked separately; the PolicySigs mutant; the field list as `Name Type` strings |
| concurrency-06 + tests-07 | MINOR | Fixed: all eight documents and SHA-256 values in a read-only map before the readers start, and readers check only after join |
| concurrency-07 | INFO | Fixed: truth 2 says the ops-key case holds by the log-key case's property and is not tested on its own |
| concurrency-09 + trust-6 + critic-05 (visibility) | MINOR | Fixed: T-03-328 (accepted, with reason); the /healthz sentence in server-install.md; Edge Coverage "Visibility" |
| concurrency-10 + tests-06 | INFO, MINOR | Fixed: readDirectory refactor with one setter call; `unparsed_state_published` pins the setter; the unparsed load path is UNVERIFIED; the VerifySignatures and CheckPolicy returns named in the mutants with their restart cases |
| trust-7 + critic-03 | INFO, MINOR | Fixed: the planner decision lists what a superseded bundle refuses; issue.go's comments and signer-install.md's sentence are reworded to that list (Task 1, Task 4 item 3), with a grep |
| tests-08 + the critic's note that e.close() sets e.s to nil | MINOR | Fixed: the helper returns its Signer, and every case uses that signer's mu, never e.s |
| tests-10 | MINOR | Fixed: `emptied_bundle_table_refused`, RED on origin/main (state_unavailable) |
| tests-13 | INFO | Fixed: the server test's doc comment and T-03-326 call it a pin of the server's half; `budget_full_status_waits` asserts only the code and the count; the helper passes e.clock; newLoginEnv(..., install=false) named |
| server-touch-bound | MINOR | Fixed: twice the 30 s deadline with the agent backend's retry, PIV keys pinned with `--key` and a touch policy, several signatures per operation; in Edge Coverage, T-03-326 and signer-install.md |
| server-qi3-cold-mirror + critic-01 | MINOR | Fixed in the Q-I3 decision, server-install.md, Edge Coverage and T-03-326: the cold-mirror definition, one abandoned fetch per signerCallTimeout, and the new start-up behaviour; Status's three callers named in Context |
| server-qi2-facts | MINOR | Fixed in the Q-I2 decision, truth 5, Edge Coverage and T-03-326 (6 interactive calls beside 6 catch-up reads; refused requests wait for the lock). B's rewording is moot (A chosen). The second fill is not possible with the fake's one-method hold; recorded |
| server-pins-no-mutants | MINOR | Fixed: the two server mutants; the test renamed TestRoutesPastStatusTTLWithHeldCall, with a doc comment saying it runs against the test double |
| server-runbook-residual4 + mechanics-runbook-catchup-reads | MINOR | Fixed: server-install.md's pile-up bullet names the catch-up reads and hosts catching up (UNVERIFIED); signer-install.md's kept clause is qualified and recorded |
| mechanics-roadmap-progress-row | MINOR | Fixed: a publish edit and a check from origin/main for the Progress row |
| mechanics-no-signature-check | MINOR | Fixed: a gpgsig check over every branch commit in Task 4, re-run after a rebase in Task 5 |
| mechanics-stop-rule-no-per-task-reading | MINOR | Fixed: the stop rule reads the base and Task 4; Tasks 1 and 2 record internal/signer's time |
| mechanics-budget-counts | MINOR | Fixed: 13 code and test files (three new); the plan's cost about 52k, the total about 117k (corrected in Round 2) |
| mechanics-qi4-a-frontmatter | INFO | Moot: the owner chose Q-I4 B |
| mechanics-no-automated-scrub | INFO | Fixed in part: an IP-address check over the diff, the commit messages and the PR body. Host names and private terms are checked by the orchestrator's pre-merge review, because this plan cannot list them |
| critic-04 | MINOR | Fixed: `nil_snapshot_refused` and its mutant |
| critic-06 | INFO | Fixed: Edge Coverage names what cannot commit under a superseded bundle, and that refusal and summary records can |
| critic-07 | INFO | Not applied: `settle` exists (internal/server/capacity_test.go, `const settle = 100 * time.Millisecond`), and the lens finding that said the same was refuted by both skeptics. Task 2's read_first keeps it |
| critic-08 | INFO | Fixed: Task 4 step 5 schedules the pre-merge review on the green PR, against T-03-324 to T-03-328, as the owner's threat review, recorded in the SUMMARY |
| Owner, Q-I1 B design: a sticky flag as a second line | — | Not kept (Planner decisions): with the check on every call it would only make Status disagree with issuance after a successor row disappears |

### Round 2 — plan check 2 (2026-11-05, narrow, PASS WITH FIXES: one MAJOR)

| Finding | Severity | Disposition |
|---------|----------|-------------|
| e2e-01 | MAJOR | Fixed: the hold is anchored to t0 (the control Once's return); the binding limit is the 10 s connDeadline (signer/server.go:20) and defaultTimeout (signerclient/client.go:17), and the 30 s and retry reasoning is gone from Task 3; a named `held-signature hold` failure when the release is more than 7 s after the issue's start; steps 6 and 7 report with t.Errorf; step 8's exit 0 is required only when steps 6 and 7 passed; the issue's failure on RED is stated as expected |
| e2e-02 | MINOR | Fixed: the in-test Fetcher logs to a buffer, and steps 2 and 7 fail on `rate limiting` or `waiting for an admin's approval`; a 4 s wait after stopFetch lets the bucket refill |
| e2e-03 | MINOR | Fixed: the RED verify requires the test's `--- FAIL` exactly twice, `held-signature krl: got 503` at least twice, and no other `--- FAIL:` line |
| e2e-04 | MINOR | Fixed: the throwaway branch is built from the two paths only, its diff is checked before the push, and the delete commands are spelled out |
| e2e-05 | MINOR | Fixed: the run list is polled until it prints an ID (about 60 s), then watched, then its log fetched |
| e2e-06 | INFO | Fixed: the release is registered with t.Cleanup when the gate is armed, after startServerEnv |
| close-ct-trust7-every-request-left, close-ts-04, design-b-04 | MINOR, INFO, INFO | Fixed: Task 1 names New's doc comment, errTrustChanged's comment and checkTrustCurrent's log message, rewords each to the list (the log message's new text is given), and checks that no code text in the package still says all requests are refused; the planner decision lists the four places |
| close-ct-c04-deref-assign-dropped | MINOR | Fixed: the StarExpr assignment rule (no allowlist entry needed on d819904) and the `*s = *s` mutant |
| close-ct-t328-journal-claim | MINOR | Fixed: T-03-328 says the signer logs nothing while a signature waits, with the visible symptoms, UNVERIFIED on a real host |
| close-ct-healthz-db-written, design-b-03 | MINOR | Fixed: the /healthz bullet says the signer is free to sign and its main connection is free, not that the database can be written |
| close-ct-runbook-recovers | INFO | Fixed: the runbook sentence ends at "publishes a KRL", with the reason; Task 4's grep uses 'forgets or publishes a KRL'; the code comments keep recovery |
| close-ct-c07-summary, close-ts-05 | INFO | Fixed: the SUMMARY's UNVERIFIED list names Status during the ops key's KRL signature |
| close-ts-01 | MINOR | Fixed: the Writes rule walks the selector chain, and the `s.caKeys[0].Custody` mutant |
| close-ts-02 | MINOR | Fixed: the start-up, cold-mirror and /healthz bullets carry inline UNVERIFIED notes, and the SUMMARY lists them |
| close-ts-03 | INFO | Fixed: no Signer literal may set directoryState or status |
| close-m-checks-read-worktree | MINOR | Fixed: a path-scoped committed-tree guard runs first in Task 4's verify |
| close-m-budget-tokens-stale | INFO | Fixed: the plan's own cost about 52k (about 134 KB after this round), the total about 117k; the Round 1 row corrected |
| design-b-01 | MINOR | Fixed: truth 3, the Q-I1 facts and Edge Coverage separate the no-wait proof from the committed-state isolation, which is UNVERIFIED in CI |
| design-b-02 | MINOR | Fixed: the serve-without-StatusDB mutant is recorded as reasoned, not run (UNVERIFIED), at probeStatus (cmd/keyroster-server/serve.go:76) |
| design-b-05 | INFO | Fixed: Edge Coverage and T-03-325 record the path-opened handle's rename or replace residual (UNVERIFIED); no code change |
| design-b-06 | INFO | Fixed: the mutant is concrete, and each handle sub-case requires the reason `state_unavailable` |
| design-b-07 | INFO | Fixed: the key link points to trust.go, and its via text names OpenReadOnly in log.go |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| Status outside the server budget, or with a reserved token | Q-I2 A (Daniel, 2026-11-05) |
| GetDirectory served from the snapshot | Q-I3 A (Daniel, 2026-11-05): the decision names Status; a warm mirror is unaffected |
| Refusal logging without s.mu | It would change how refusals reach the audit log (D-14); a refused Status means delivery is refused by design |
| A type-checked TestStatusWriters (go/types) | The stdlib source importer would type-check every dependency on each run, and x/tools would be a new module |
