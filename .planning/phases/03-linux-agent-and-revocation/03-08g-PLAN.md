---
phase: 03-linux-agent-and-revocation
plan: 08g
type: execute
wave: 18
depends_on: ["03-08f"]
files_modified:
  - internal/server/signer.go
  - internal/server/server.go
  - internal/server/agent.go
  - internal/server/capacity_test.go
  - internal/server/revoke.go
  - internal/server/revoke_test.go
  - internal/server/directory.go
  - docs/runbooks/server-install.md
  - .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md
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
requirements: [REVOKE-01, REVOKE-02, REVOKE-03]

estimate:
  tokens: 68000
  raw_tokens: 68000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-10-29 and 2026-10-30): this plan is the server side of the signer-capacity work and holds F11, F12 and F13. It runs after 03-08f and before 03-08h, which holds F16 and the signer half of F07. Q-G1 to Q-G7 are decided; the numbers below are the owner's"
    - "F11. keyroster-server never has more than maxSignerCalls (12, Q-G1) signer calls in flight. At most half of them (maxAgentCalls, 6) are calls relayed for host agents, today the catch-up reads GetBundle and GetDirectoryVersion. Such a call takes its agent token before its total token, so logins, revocations, directory installs, forgets and the coalesced Status and directory reads always have at least 6 calls of room. No caller holds a token across another signer call. GetKRL takes no token (Q-G5): it takes no lock on the signer and is coalesced to one call in flight (refreshKRL), so it never waits behind budgeted calls, and the server holds at most 13 signer calls at once. Historical versions are not cached (Q-G4)"
    - "F11, per agent. One enrolled agent has at most maxAgentInFlight (2, Q-G1) requests in flight, counted together on every agent route that relays a signer call for it: the state route and the heartbeat route (confirmRemoval's GetDirectoryVersion). A further request is answered 429 with `Retry-After: 1` and the body `rate limited`, after the token bucket has charged it. The growth rule (owner decision 2026-10-30): every signer call relayed for a host agent takes the agent share, and every agent route that relays one takes the per-agent slot"
    - "F12. While the directory mirror holds no entry for the SHA-256 and version that Status reports, all concurrent callers of currentDirectory share one detached GetDirectory fetch for that SHA-256 and version, bounded by signerCallTimeout. Each waiter stops at the end of its own ctx. A failed fetch is never cached, a mismatch still drops the status cache, and a caller whose ctx has already ended starts no fetch"
    - "F13. A KRL version is served (GET /api/v1/krl, krlItem) only after its copy in krl-served.json was written, renamed and directory-synced in one successful keepKRLFile, or was read back at start and its file and directory synced then, once (pre-merge review fix round 1: a read-back alone proves only that the page cache holds it). Until then every refresh redoes the full write and answers 503. The floor still follows the disk after a rename whose sync failed (PR #69 review F4)"
  artifacts:
    - path: "internal/server/signer.go"
      provides: "the server's signer-call budget with its agent share"
      contains: "func withSignerBudget("
    - path: "internal/server/agent.go"
      provides: "the per-agent in-flight slot on the routes that relay signer calls"
      contains: "func (s *Server) agentSlot("
    - path: "internal/server/directory.go"
      provides: "one coalesced GetDirectory fetch per Status SHA-256 and version"
      contains: "func (s *Server) fetchDirectory("
    - path: "internal/server/revoke.go"
      provides: "the durable flag of the served KRL copy"
      contains: "durable"
  key_links:
    - from: "internal/server/server.go"
      to: "internal/server/signer.go"
      via: "newServer wraps every signer in the budget, so the test double goes through it too"
      pattern: "withSignerBudget("
    - from: "internal/server/agent.go"
      to: "internal/server/server.go"
      via: "handleAgentState and handleAgentHeartbeat take the per-agent slot, counted in the Server's agentInFlight map"
      pattern: "s.agentSlot("
    - from: "internal/server/directory.go"
      to: "internal/server/signer.go"
      via: "fetchDirectory drops the status cache on a mismatch, as currentDirectory did"
      pattern: "s.dropStatus()"
  prohibitions:
    - statement: "Nothing here widens what the server accepts or serves. The budget and the per-agent slot only delay or refuse calls and requests. The durable flag only withholds a KRL. The coalesced fetch serves only bytes whose SHA-256 and version equal what Status reported"
      status: resolved
      verification: test
---

<objective>
Capacity and robustness hardening of keyroster-server's calls to its signer. After this plan:
- **F11.** keyroster-server bounds its own signer calls. Calls relayed for host agents never crowd out logins, revocations or the server's own reads, and one agent cannot run many requests at once.
- **F12.** A change of the installed directory is read from the signer once, however many requests arrive meanwhile.
- **F13.** A KRL is never served before its copy on the server is durable.

03-08h then gives the signer per-account connection shares (F16), on top of this plan's budget, and refuses at install a directory that hosts cannot render (F07, signer half).

Purpose:
- REVOKE-01: a revocation from the CLI reaches the signer through the server relay, with room kept for it.
- REVOKE-02: KRLs and state keep reaching every host.
- REVOKE-03: the served KRL copy, the restore source, is durable before any host gets it.

Output:
- the server's signer budget with its agent share;
- the per-agent in-flight slot on the state and heartbeat routes;
- the coalesced mirror fill;
- the durable flag;
- named tests with RED evidence and mutants;
- two runbook notes in server-install.md;
- the publish edits, with the agent-share rule added to 03-09 and 03-10, and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Fix homes (Daniel, 2026-10-29, "kör på förslagen").** F11, F12, F13 and F16 run after 03-08f, together with the signer half of F07 (`directory_unrenderable`). They were to be planned only after 03-08c merged, because they overlap 03-08c's signer work; 03-08c is on main.
- **Split (Daniel, 2026-10-30), after plan check 1.**
  - 03-08g, this plan: the server side, F11, F12 and F13. Wave 18, after 03-08f.
  - 03-08h: the signer side, F16 and F07's signer half. Wave 19, after this plan.
  - Since 2026-11-01 the order before them is 03-08e → 03-08j → 03-08k → 03-08f (owner decisions on the 03-08j/03-08k split, 2026-11-01, and of 2026-11-02, which keep 03-08j directly before 03-08k).
  - The server side goes first. F16's per-account share without F11's budget would refuse keyroster-server itself under load.
  - Each plan publishes itself, as 03-08d does: origin/main's values + 1, with the guard.
- **Grades.** F11, F12 and F13 are low as reported.
- **Delivery (2026-10-29).**
  - The plan lands in the same PR as its fix.
  - The PR title and every commit use neutral hardening wording and name findings only by F-number.
  - Pushing the branch and opening the PR before the merge is allowed, with its diff public while it is open.
- **Homelab.** No 03-16 drill provokes these limits on a real host. The runbook text this plan writes is labelled run in CI, and UNVERIFIED on a real host.
- **Q-G1, the numbers (Daniel, 2026-10-30): 16/12/6/2.**
  - Signer: 32 connections in all, at most 16 per account (uid). That is 03-08h's.
  - Server: at most 12 signer calls in flight, of which at most 6 are relayed for host agents. That is this plan's.
  - Agents: at most 2 requests in flight each. That is this plan's.
  - The release ordering, so that the server's budget can never be refused by its own signer share, is 03-08h's, together with the share: the signer frees a connection's slot before it closes the connection, and socketSigner reads to the end of the stream before it returns, and so before its budget token is freed. The CLI is unchanged.
  - The owner accepted the stalled-signer trade-off. 03-08h documents it in its threat model (T-03-307) and in signer-install.md.
- **Q-G2 (Daniel, 2026-10-30).** No reserved slot: no named account and no reserved pool (03-08h).
- **Q-G3 (Daniel, 2026-10-30).** At most 2048 accounts per host group and 64 KiB per principals file, with runbook text (03-08h).
- **Q-G4 (Daniel, 2026-10-30).** No cache of older bundle or directory versions on the server. The budget and the per-agent slot bound the signer connections, and a signer restore can re-make a version number with other bytes (signer-install.md, "Enrolled hosts and a re-made version").
- **The agent-share rule (Daniel, 2026-10-30, plan check 1).** Every signer call made on behalf of a host agent takes the agent share, and every agent route that relays such a call takes the per-agent in-flight slot.
  - This plan states the rule in budgetSigner's doc comment and in signerAPI's growth rule.
  - It applies the rule to the state route and the heartbeat route.
  - Its publish edits add one sentence each to 03-09 (HostIssue, the hostcert route) and 03-10 (ProbeIssue, the probecert route).
- **Q-G5 (Daniel, 2026-10-30): GetKRL stays outside the server budget.**
  - GetKRL takes no lock on the signer and does not count toward the 12. The server therefore holds at most 13 signer calls at once, inside 03-08h's share of 16.
  - The owner's aim is that revocation delivery keeps working during a touch signature.
  - Task 1 pins what this plan can deliver toward that aim:
    - GetKRL never waits behind budgeted calls;
    - with the total full, GET /api/v1/krl answers 200 while the status cache is fresh.
  - **The limit beyond that** is outside this plan. handleKRL and requireAgent both need a fresh Status, and the signer's Status takes its lock. So past statusTTL (5 s), delivery during a stall still fails, as it does today (Edge Coverage, T-03-308).
- **Q-G6 (Daniel, 2026-10-30): one shared per-agent in-flight count** across the state and heartbeat routes, cap 2 (Task 2).
- **Q-G7 (Daniel, 2026-10-30).** The non-growth rule for directories above the cap, with every file sized against the widest version header (03-08h).
- **Status during a slow signature (Daniel, 2026-10-30): a follow-up plan.** Working ID 03-08i, after 03-08h. It gets its own threat review and plan check.
  - The signer keeps a Status snapshot, updated under s.mu at every state change and read without the lock, so KRL and agent-state delivery keep working during a long touch signature.
  - This plan records the limit in its Deferred ledger and builds nothing toward it.

## Open owner questions

None open.

**Planner decisions (Claude's discretion), recorded with their reasons:**
- *The server budget is a signerAPI wrapper that newServer installs around whatever signer it gets.* The fakeSigner tests then run through the real budget. It adds no second interface.
- *The total is local to internal/server here* (`maxSignerCalls = 12`). The signer has no per-account share yet, so this plan has nothing to derive it from. 03-08h introduces the share and moves the total to internal/wire as `MaxServerSignerCalls = MaxPeerConns - 4`, with the same value, so that the signer's own tests can drive exactly the server's total.
- *The agent share is chosen by method.* The old draft called it the catch-up share. It is renamed so that 03-09's HostIssue and 03-10's ProbeIssue, which are not catch-up reads, fit the rule by name. GetBundle and GetDirectoryVersion take it wherever they are called:
  - from the state route (bundleItems, directoryItems);
  - from the heartbeat route, through reconcileRemoval and confirmRemoval in internal/server/hosts.go;
  - from the admin pending-hosts route, which runs reconcileRemoval for each agent (hosts.go). That route is rate-limited as an admin route, and a failed call there is logged and skipped, as today.

  hosts.go is not changed. The subtests keep the names plan check 1 cites (`catch_up_bounded_interactive_room`, `catch_up_reads_leave_room`), because they drive catch-up reads.
- *Acquisition order.* A call in the agent share takes its agent token first and its total token second. Each wrapper method releases both before it returns, so no caller holds a token across another signerAPI call. In the other order, agent calls queued on the agent share would sit on total tokens and starve the interactive calls.
- *One per-agent counter for every relaying route.*
  - The fetcher sends its state rounds and then its heartbeat, one after another, under its identity lock. An honest agent therefore has one request in flight, and the second slot absorbs a handler that outlives a client timeout.
  - One counter across the state and heartbeat routes keeps "2 in flight each" literally true. Counters per route would let one agent hold 2 per route, and so more of the agent share with each route that later plans add.
  - The slot is taken after requireAgent has charged the token bucket, so every 429 it writes has already been rate-limited.
  - It is keyed on the agents row ID, as the bucket is, released with defer, and its key is deleted at zero.
  - Its 429 carries `Retry-After: 1` and the body `rate limited`. The state fetcher's RateLimited branch (internal/agent/fetch/fetch.go) then continues at the next poll, and the heartbeat's (internal/agent/fetch/heartbeat.go) returns nil.
- *budgetSigner holds the next signer as a named field, never embedded.* A signerAPI method added later then fails to build until budgetSigner implements it. The rule above decides which share it takes.
- *The one exemption (Q-G5).* budgetSigner.GetKRL calls the next signer without a token. A call may skip the budget only when both of these hold, and the growth rule says so:
  - it takes no lock on the signer;
  - it is coalesced to one call in flight.

  For GetKRL, the coalescing is refreshKRL's krlInflight. An acceptance check pins refreshKRL as GetKRL's only caller, because the bound of 13 depends on it.
- *Tests that replace e.s.signer after newServer.* Two of them do: admin_test.go `cleanup_survives_client_hangup` and login_test.go's stallSigner. They test a client hang-up and a stalled Status, not capacity. They stay unbudgeted, and their files stay out of this plan.
- *The server's start-up Status* (cmd/keyroster-server/serve.go) calls signerclient directly, outside the budget. That is fine: it runs, with retries, before the server serves any request, so nothing else is in flight.
- *F12 copies currentStatus's coalescing.* A detached refresh on `context.WithoutCancel`, a done channel, and a result stored only while the fetch is still the one in flight.
- *F13 needs a flag, not another syncDir call.* After a failed fsync, a second fsync can report success without the data having been written. So only a full rewrite, or a copy read back at start whose file and directory were synced then, counts as durable. (Pre-merge review fix round 1: the plan first counted a read-back alone, which proves only that the page cache holds the copy, so a restart after a failed directory sync served it. A sync at start that follows a failed sync in the previous process may itself report a false success; that stays UNVERIFIED.)

## Budget

There are 7 code and test files, one of them a new test file, and one runbook. The publish edits add the plan itself, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16, plus one sentence each in 03-09 and 03-10. Four tasks precede the merge gate, as in 03-08f. Every implementation task touches at most 4 files.

About 68k tokens:
- about 62 KB of code read through the function-scoped read_first lists, roughly 18k tokens;
- about 27k written;
- about 23k of test and gate output.

Like the estimates of 03-08d to 03-08f, this leaves out the plan itself. At about 80 KB (roughly 21k tokens), it brings the executor's total to about 89k.

**Test time.** 03-08k's two limits apply, although this plan adds only server tests, because those run beside internal/agent/apply under `./...` and in CI: 400 s for internal/agent/apply alone under -race, and 480 s for its `ok` line under `./...`. On 741e2f6 they measured 335.1 s and 368.5 s (03-08f-SUMMARY).
- Alone gate: `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'`
- Margin gate: `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./...' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} END{exit (n!=1 || bad)}'`
- Stop rule, as 03-08f's: if either base is above its limit before any edit, stop and report the two options (raise CI's -timeout, or move slow cases to their own package) without choosing.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names.
- **Branch.** Create `p03/08g-server-capacity` from origin/main in Task 1.
- **Plan file.** Place this file untracked in the phase directory at the start. Task 4 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Wording.** Commits and PR text use neutral hardening wording (`fix(server): ...`, `test(server): ...`) and name findings only by F-number. No attribution lines, no IP addresses, no real host names.
- **Code comments** cite `F11 (03-08g)`, `F12 (03-08g)` or `F13 (03-08g)`. A bare F-number would be read as an earlier review's: agent.go already says "(F12)" on fillAgentState for PR #71's review.
- **Linux tests.** Every verify command runs in WSL through `bash scripts/linux.sh '...'`, as in 03-08d to 03-08f.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md`, with the docs commit `docs(03-08g): complete server-capacity plan`.

**What this plan builds on:**
- 03-07: bundleItems and directoryItems, the catch-up reads.
- 03-08b: reconcileRemoval and confirmRemoval on the heartbeat path.
- 03-08c: ForgetAgent in signerAPI.
- PR #69 review F4: the served floor follows the disk.
- 03-08d, 03-08e, 03-08j, 03-08k and 03-08f touch none of this plan's files (`git diff --stat 98e9e5c..741e2f6 -- internal/server docs/runbooks/server-install.md` is empty). 03-08e, 03-08j and 03-08f edit internal/agent/fetch/fetch.go and heartbeat.go, which this plan only reads, so find their RateLimited branches with grep.

**The code this plan changes, as read on main at 98e9e5c. 03-08d to 03-08f, with 03-08j and 03-08k, leave these functions unchanged (main 741e2f6).**
- **F11.**
  - bundleItems and directoryItems read every older version from the signer, one call after another.
  - requireAgent charges each enrolled agent a token bucket, but does not bound its requests in flight. The heartbeat route can relay GetDirectoryVersion through confirmRemoval.
  - socketSigner opens one signer connection per call, and nothing in the server bounds how many are open at once.
- **F12.** On a mirror miss, currentDirectory clears the entry and calls GetDirectory itself. Concurrent misses each make their own call and parse. currentStatus and currentKRL coalesce; dirMirror has no in-flight record.
- **F13.**
  - When the directory sync after the rename fails, keepKRL records the new version as served (correct for the floor) and returns the error, so that refresh answers 503.
  - The next refresh with the same answer takes the "same version, same bytes" branch and returns nil without writing. That version is then served, although its directory entry was never made durable.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "six enrolled agents send catch-up state requests at once → bundleItems and directoryItems call the signer through budgetSigner, which newServer installs around every signer → each call takes its agent token before its total token, so at most 6 of the 12 calls in flight are agent calls → while they are held, the server's own Status and GetKRL get in at once → every request answers 200 after release"</name>
  <reversibility rating="reversible">A wrapper around the signer and two constants. No stored format, wire message, route or log leaf changes.</reversibility>
  <precondition>All four checks hold:
    - `git fetch origin` succeeds.
    - `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08f-SUMMARY.md` exits 0.
    - `V=$(git show origin/main:internal/agent/state/verify.go) && printf '%s\n' "$V" | grep -c 'func checkStored('` prints at least 1, which shows that 03-08f is merged.
    - `S=$(git show origin/main:internal/server/signer.go) && printf '%s\n' "$S" | grep -c 'func withSignerBudget('` prints 0, which shows that this plan is not applied yet.
  </precondition>
  <files>internal/server/signer.go, internal/server/server.go, internal/server/capacity_test.go</files>
  <read_first>
    Read functions, not files: find each with `grep -n` and read only that range.
    - internal/server/signer.go: `type signerAPI interface` with its growth-rule comment, `type socketSigner` with its methods, `type refresh struct`, `func (s *Server) currentStatus(`, `func (s *Server) refresh(` and `func (s *Server) dropStatus(` (about 8 KB).
    - internal/server/server.go: `type Server struct` (its mutex comments), `func New(` and `func newServer(` (about 4 KB).
    - internal/server/agent.go: `func (s *Server) handleAgentState(`, `func (s *Server) bundleItems(` and `func (s *Server) directoryItems(` (about 5 KB).
    - internal/server/hosts.go, read only: the GetDirectoryVersion call in `func (s *Server) confirmRemoval(`, and the callers of reconcileRemoval (`grep -n 'reconcileRemoval('`), about 2 KB.
    - internal/server/server_test.go: `type fakeSigner struct`, `count`, `hold`, `enter`, and the fake's GetBundle, GetDirectoryVersion, Status and GetKRL (about 5 KB). `entered` is buffered at 16 and its send blocks, so a test that holds more than 16 calls drains it in a goroutine.
    - internal/server/agent_test.go: `func newAgentEnv(`, `func (e *agentEnv) agentDo(`, `func (e *agentEnv) approvedAgent(`, `func (e *agentEnv) mustMint(`, `func (e *agentEnv) enroll(` and `func (e *agentEnv) installDir(` (about 4 KB).
    - The two tests that set e.s.signer: `grep -n 'e.s.signer = ' internal/server/*_test.go` (about 1 KB).
    - internal/server/revoke.go: `func (s *Server) handleKRL(`, `func (s *Server) currentKRL(` and `func (s *Server) refreshKRL(` (about 3 KB). handleKRL needs a fresh Status before it reads the KRL; currentKRL coalesces on krlInflight. Also `func (e *agentEnv) publishKRL(` in agent_test.go.
  </read_first>
  <action>
Create branch `p03/08g-server-capacity` from origin/main. Place this plan file untracked in the phase directory; Task 4 commits it.

**Bases first.** Before any edit, run the Budget section's alone and margin gates on the new branch and record both apply `ok` lines and internal/server's `ok` line in the SUMMARY. If either is above its limit, follow the stop rule.

**RED first.** Create internal/server/capacity_test.go with the three tests below. To make TestSignerBudget compile, first add to internal/server/signer.go the constants `maxSignerCalls` and `maxAgentCalls` and `func withSignerBudget(sg signerAPI) signerAPI` returning sg unchanged, so its subtests fail on the peaks. Run the tests on that code, with the same two -run patterns as the verify (go test splits -run at `/` before it reads `|`, so one combined pattern skips the subtests), and record every RED, and every GREEN at once with its reason, in the SUMMARY.

`TestSignerBudget`, on withSignerBudget directly. Its double is `gateSigner`, a test type in capacity_test.go that embeds *fakeSigner. Every method waits on one shared gate, or for the end of its ctx, and records the calls in flight and the peak, both for all methods and for GetBundle plus GetDirectoryVersion. Each subtest waits until the expected count is reached, then settles about 100 ms and checks that the count did not grow.
- `total_bounded`: 20 goroutines call Login. The peak is maxSignerCalls (12). After release, all 20 return nil. (Pre-merge review fix round 1: a table over every budgeted method, each alone; an interactive method peaks at 12, an agent method at the share, 6.)
- `catch_up_bounded_interactive_room`:
  1. Start 20 goroutines of GetBundle and GetDirectoryVersion. Wait until 6 (maxAgentCalls) are in flight. Then wait out the settle time (about 100 ms) before step 2, so that the 14 queued calls have reached their token waits first. Only then is the swapped-order mutant killed: under it, those 14 hold total tokens before the interactive calls start (plan check 1).
  2. Start 20 goroutines of Login and Revoke.
  3. Assert: the interactive calls in flight reach maxSignerCalls − maxAgentCalls (6), the agent peak stays 6, and the total peak is 12.
  4. After release, all 40 return nil.

  (Pre-merge review fix round 1: step 2 starts one interactive method at a time, in its own subtest: Login, Revoke, InstallDirectory, ForgetAgent, GetDirectory, Status. Each alone fills the room of 6, and the agent calls stay at 6.)
- `waiter_ctx_ends`:
  - With the total full, a Status whose ctx ends while it waits returns that ctx's error and never reaches the double (its call count is unchanged).
  - A Status with an already-ended ctx neither waits nor reaches it.
  - An agent call whose ctx ends while it waits for the total token gives its agent token back. After the Logins are released, 6 concurrent agent calls are all in flight at once; with the token kept, only 5 would be.
- `tokens_released_on_error`: the double fails every call. After 3 × maxSignerCalls failing calls, one after another, both kinds of call still get in without waiting.
- `getkrl_outside_budget` (Q-G5): with the total full of held Logins, a GetKRL reaches the double at once and returns, and the peak of budgeted calls stays 12. It is GREEN against the stub, which budgets nothing; record that. Its mutant is GetKRL taking a token.

`TestKRLDuringFullBudget` (Q-G5), on newAgentEnv with a published KRL (publishKRL). The route needs a fresh Status, so the test works inside statusTTL and claims nothing beyond it.
- `krl_route_answers_inside_status_ttl`:
  1. One GET /api/v1/krl fills the status and KRL caches.
  2. Drop the KRL cache: set `e.s.krl` to nil under e.s.mu, as an internal test may.
  3. Fill the total with 12 held budgeted calls (Login through e.s.signer, held at the fake).
  4. A second GET /api/v1/krl, at the same clock and run in a goroutine, answers 200 with the KRL within 2 s. It reached the fake's GetKRL although no budget token was free. Under the mutant it would wait for a token until its refresh timeout.
  5. After release, every held call returns.
- `getkrl_coalesced_one_call`: with the KRL cache dropped and GetKRL held at the fake, 20 concurrent `e.s.currentKRL` calls make one GetKRL call (`entered` settles at 1, and the count is 1 after release), and all 20 get the KRL. It is GREEN on origin/main, because currentKRL already coalesces; record that. It pins the coalescing that the bound of 13 rests on.

`TestAgentInFlight/catch_up_reads_leave_room`, on newAgentEnv. The numbers are literals during RED (6, with a comment naming the constant); the committed test uses the constant.
- Setup:
  - 6 approved agents, made with mustMint and enroll as approvedAgent does, then one installDir naming all six hosts;
  - directory versions up to 18;
  - `fake.hold("GetDirectoryVersion")`, with `entered` drained in a goroutine.
- Each agent sends 2 concurrent `GET state?directory=1` requests (agentDo).
- Assert: `entered` settles at 6 (maxAgentCalls), and no request is answered 429. While they are held, `e.s.signer.Status(ctx)` (through the budget) and `e.s.signer.GetKRL(ctx)` (outside it) each return at once.
- After release, all 12 answer 200.
- RED on origin/main: 12 entered.

Then implement as follows.

**internal/server/signer.go, `F11 (03-08g)`.**
- Constants, each with a doc comment:
  - `maxSignerCalls = 12`: the most signer calls keyroster-server has in flight, well inside the signer's 32 connections;
  - `maxAgentCalls = maxSignerCalls / 2`: the most of them relayed for host agents.
- `type budgetSigner struct` holds the next signerAPI as a named field, never embedded, and two buffered channels: total (maxSignerCalls) and agent (maxAgentCalls). Because the field is not embedded, a signerAPI method added later does not compile until budgetSigner implements it. An embedded interface would pass it through unbudgeted.
- `func withSignerBudget(sg signerAPI) signerAPI` returns one.
- `acquire(ctx, agent bool) (release func(), err error)`:
  - An ended ctx returns its error at once and takes nothing.
  - An agent call takes an agent token first, then a total token. Each wait is a select on the channel and ctx.Done().
  - When ctx ends while it waits for the total token, it gives the agent token back.
  - release frees the total token, then the agent token.
- Eight of the nine methods (Status, GetDirectory, InstallDirectory, Login, Revoke, GetBundle, GetDirectoryVersion, ForgetAgent) acquire the budget, defer release and call the next signer. GetBundle and GetDirectoryVersion are the agent calls.
- GetKRL calls the next signer without a token (Q-G5). Its doc comment gives the two reasons: it takes no lock on the signer, and refreshKRL coalesces it to one call in flight. So the server holds at most maxSignerCalls + 1 signer calls at once. A budget error is returned as is, so `errors.Is(err, context.DeadlineExceeded)` still holds, and every caller already answers it as signer unavailable.
- Login: the wait is part of the send, so ctx's deadline bounds it. The read timeout after the send stays signerCallTimeout (socketSigner is unchanged).
- budgetSigner's doc comment states:
  - the two bounds;
  - the acquisition order, and why;
  - that no caller holds a token across another signerAPI call;
  - the agent-share rule (owner decision 2026-10-30), with today's three callers of GetDirectoryVersion: the state route, the heartbeat route through confirmRemoval, and the admin pending-hosts route through reconcileRemoval;
  - the one exemption, GetKRL, and the bound of 13 that rests on its coalescing.
- Extend signerAPI's growth rule:
  - a new method also goes through budgetSigner, in the same commit;
  - a call relayed for a host agent takes the agent share;
  - a call may skip the budget only if it takes no lock on the signer and is coalesced to one call in flight.

  Task 2 adds the route half of the rule.

**internal/server/server.go.** newServer stores `withSignerBudget(sg)` as s.signer, so every handler and every fakeSigner test goes through the budget. New is unchanged.

**Tests that replace e.s.signer after newServer** (admin_test.go `cleanup_survives_client_hangup` with `sentSigner{e.fake}`, and login_test.go's `stallSigner`) stay as they are. Name both in the SUMMARY as the only server tests that bypass the budget. No test asserts the type of e.s.signer.

Run the whole server package. Every existing test must keep its meaning. An existing test that holds more than 12 calls of one non-coalesced method at once now waits on the budget. Record each such test, its adjustment and the reason in the SUMMARY.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "^(TestSignerBudget|TestKRLDuringFullBudget)$" ./internal/server/ && go test -race -count=1 -v -run "^TestAgentInFlight$/^catch_up_reads_leave_room$" ./internal/server/ && go test -race -count=1 ./internal/server/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestSignerBudget/total_bounded", "--- PASS: TestSignerBudget/catch_up_bounded_interactive_room", "--- PASS: TestSignerBudget/waiter_ctx_ends", "--- PASS: TestSignerBudget/tokens_released_on_error", "--- PASS: TestSignerBudget/getkrl_outside_budget", "--- PASS: TestKRLDuringFullBudget/krl_route_answers_inside_status_ttl", "--- PASS: TestKRLDuringFullBudget/getkrl_coalesced_one_call", "--- PASS: TestAgentInFlight/catch_up_reads_leave_room"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/server/server.go | grep -c 'withSignerBudget(sg)'` prints 1.
    - `awk '/^type budgetSigner struct/,/^}/' internal/server/signer.go | grep -cE '^[[:space:]]+signerAPI[[:space:]]*$'` prints 0: the next signer is a named field.
    - `G=$(grep -l 'signerclient\.' internal/server/*.go | grep -v _test.go) && test "$G" = internal/server/signer.go`: only signer.go calls signerclient.
    - `K=$(grep -n 's\.signer\.GetKRL(' internal/server/*.go | grep -v '_test.go') && test "$(printf '%s\n' "$K" | wc -l)" = 1 && printf '%s\n' "$K" | grep -q '^internal/server/revoke.go:'`, and `awk '/^func \(s \*Server\) refreshKRL\(/,/^}/' internal/server/revoke.go | grep -c 's\.signer\.GetKRL('` prints 1: the one call is inside refreshKRL. The bound of 13 rests on GetKRL's single, coalesced caller.
    - `grep -n '\.GetKRL(' internal/server/*.go | grep -v '_test.go'` prints only refreshKRL's call and the GetKRL methods of budgetSigner and socketSigner: no other name for the signer reaches GetKRL.
    - The SUMMARY records the REDs, with where each was taken, and names the two tests that bypass the budget.
    - The SUMMARY lists these mutants, each applied, run against its named test, and restored byte for byte:
      - newServer storing sg without the budget (killed by `catch_up_reads_leave_room`);
      - the agent calls taking only a total token (killed by `catch_up_bounded_interactive_room`);
      - the acquisition order swapped, total first (killed by `catch_up_bounded_interactive_room`: the interactive calls find no room);
      - maxAgentCalls set to maxSignerCalls (killed by `catch_up_bounded_interactive_room`);
      - the agent token kept when ctx ends during the total wait (killed by `waiter_ctx_ends`);
      - release skipped on the error path (killed by `tokens_released_on_error`);
      - GetKRL taking a token (killed by `getkrl_outside_budget` and `krl_route_answers_inside_status_ttl`).
  </acceptance_criteria>
  <done>keyroster-server never has more than 12 budgeted signer calls in flight plus its one coalesced GetKRL, calls relayed for host agents never take more than 6 of them, and the server's own reads get in while those are held.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: F11, the per-agent in-flight slot on every agent route that relays a signer call (state and heartbeat)</name>
  <files>internal/server/agent.go, internal/server/server.go, internal/server/signer.go, internal/server/capacity_test.go</files>
  <behavior>
    All cases are subtests of `TestAgentInFlight` in capacity_test.go, on newAgentEnv. The numbers are literals during RED (2, with a comment naming the constant); the committed test uses the constant.
    - `one_agent_bounded_in_flight`:
      - Setup: one approved agent, directory versions up to 18 (installDir), `fake.hold("GetDirectoryVersion")`, and `entered` drained in a goroutine.
      - Send 12 concurrent `GET state?directory=1` requests from that agent (agentDo).
      - Assert: `entered` settles at 2 (maxAgentInFlight). The other 10 answer 429 with `Retry-After: 1` and the error `rate limited`.
      - After release, the 2 answer 200.
      - RED on Task 1's head: 6 entered (the agent share) and no 429.
    - `heartbeat_shares_cap`:
      - Setup as heartbeat_test.go's tests do (polledAgent), then directory versions up to 18 and GetDirectoryVersion held.
      - With 2 state requests of the agent held, a heartbeat from the same agent (e.heartbeat with testHBStatus) is answered 429 with `Retry-After: 1` and `rate limited`. The 429 is what kills both mutants. The fake's GetDirectoryVersion count is also checked unchanged, but only as a guard that the refused heartbeat made no call: without a pending removal, confirmRemoval makes none anyway.
      - After release, the next heartbeat is answered 200.
      - RED on Task 1's head: the heartbeat answers 200.
    - `cap_released_after_answer`: after one agent's 2 held requests end, its next 2 concurrent requests are both admitted. Once they end, the in-flight map holds no key.
    - `cap_per_agent`: two agents, with 2 concurrent requests each, held. `entered` reaches 4, and no request is answered 429. It is GREEN on Task 1's head; record why (4 is within the agent share).
    - `catch_up_reads_leave_room` (Task 1) stays green: 6 agents with 2 requests each never meet the per-agent slot.
  </behavior>
  <read_first>
    Read functions, not files; find each with `grep -n`.
    - internal/server/agent.go: the limiter const block, `func (s *Server) agentAllow(`, the head of `func (s *Server) requireAgent(` (where it charges the bucket), the head of `func (s *Server) handleAgentState(` and the head of `func (s *Server) handleAgentHeartbeat(` with its doc comment (about 5 KB).
    - internal/agent/fetch/fetch.go: the `RateLimited` branch of `func (f *Fetcher) pollState(`, found with `grep -n 'RateLimited'`, and internal/agent/fetch/heartbeat.go: the `RateLimited` branch of `func (f *Fetcher) sendHeartbeat(` (about 1 KB together). Read only: they are why the 429 must carry a Retry-After of 1 to 3600, and they show that both answers continue at the next poll.
    - internal/server/heartbeat_test.go: `func testHBStatus(`, `func (e *agentEnv) heartbeat(` and `func polledAgent(` (about 2 KB).
    - internal/server/heartbeat_edges_test.go: `in_flight_heartbeat_not_inherited` (about 2 KB). It holds one heartbeat in flight; it must stay green.
  </read_first>
  <action>
Write the tests in `<behavior>` first. Take the RED of `one_agent_bounded_in_flight` and `heartbeat_shares_cap` on Task 1's head. `cap_released_after_answer` reads the new map; write it right after the map's declaration. Record every RED and every GREEN at once in the SUMMARY.

**internal/server/server.go.** Add to Server:
- `inFlightMu sync.Mutex`, with a comment that it guards only agentInFlight and is never held with mu or across a signer call;
- `agentInFlight map[int64]int`, made in newServer.

**internal/server/agent.go, `F11 (03-08g)`.**
- Add `maxAgentInFlight = 2` to the limiter const block. Its comment: the fetcher sends its state rounds and its heartbeat one after another, so the second slot only absorbs a handler that outlives a client timeout; one count covers every agent route that relays a signer call.
- Add `func (s *Server) agentSlot(w http.ResponseWriter, r *http.Request, ar *agentRequest) (release func(), ok bool)`:
  - Under inFlightMu it refuses at maxAgentInFlight for ar.agent.ID, else it counts the request. release decrements the count and deletes the key at zero.
  - On refusal it logs Warn `agent requests in flight` with the route (r.Pattern), expected_name and the agent's row ID, sets `Retry-After: 1`, and answers 429 with `serverclient.APIError{Error: "rate limited"}`, the body agentAllow writes.
- handleAgentState and handleAgentHeartbeat each take the slot first and defer release. Extend both doc comments with the slot.
- Do not change requireAgent, the token bucket, bundleItems, directoryItems, reconcileRemoval or anything in hosts.go. The admin pending-hosts route is an admin route, not an agent route; it takes the agent share by method only (Task 1).

**internal/server/signer.go.** Add the route half of the growth rule to signerAPI's comment and to budgetSigner's: an agent route that relays a signer call takes agentSlot after requireAgent, as the state and heartbeat routes do.

Run the whole server package. Every existing agent and heartbeat test must keep its meaning, including `in_flight_heartbeat_not_inherited`. Check with grep for any existing test that sends more than 2 concurrent requests from one agent; record each one that now meets the slot, its adjustment and the reason in the SUMMARY.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestAgentInFlight" ./internal/server/ && go test -race -count=1 ./internal/server/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestAgentInFlight/one_agent_bounded_in_flight", "--- PASS: TestAgentInFlight/heartbeat_shares_cap", "--- PASS: TestAgentInFlight/cap_released_after_answer", "--- PASS: TestAgentInFlight/cap_per_agent", "--- PASS: TestAgentInFlight/catch_up_reads_leave_room"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/server/agent.go | grep -c 's.agentSlot('` prints 2: the state and heartbeat handlers.
    - The SUMMARY records the REDs (on Task 1's head) and why `cap_per_agent` is GREEN at once.
    - The SUMMARY lists these mutants, each applied, run against its named test, and restored byte for byte:
      - the agentSlot call removed from handleAgentState (killed by `one_agent_bounded_in_flight`);
      - the agentSlot call removed from handleAgentHeartbeat (killed by `heartbeat_shares_cap`);
      - a separate count per route (killed by `heartbeat_shares_cap`);
      - one count for all agents (killed by `cap_per_agent`);
      - release skipped (killed by `cap_released_after_answer`).
  </acceptance_criteria>
  <done>One enrolled agent never has more than 2 requests in flight on the routes that relay signer calls for it, and a further one is answered 429 with Retry-After 1, which the fetcher reads as "continue at the next poll".</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: F13, a KRL served only once its copy is durable; F12, one directory fetch per change</name>
  <files>internal/server/revoke.go, internal/server/revoke_test.go, internal/server/directory.go, internal/server/capacity_test.go</files>
  <behavior>
    - F13, in `TestKRLServedCopy`:
      - `dir_sync_failure_never_served`:
        1. Serve v100.
        2. Make syncDir fail and count its calls.
        3. Set v200. GET 1 answers 503, as today.
        4. GET 2 of the same v200, with the sync still failing, answers 503 and calls syncDir again: a full rewrite, not a shortcut. `e.s.krlItem(ctx, 100)` returns an error.
        5. Restore syncDir. GET 3 answers 200 with v200.
        6. GET 4 of v200 calls syncDir no more: the shortcut is back once the copy is durable.

        RED: GET 2 answers 200, and syncDir is not called.
      - `copy_read_at_start_is_durable`: write a copy of v5 with writeCopy, restart, and serve v5. The answer is 200 with no syncDir call and no write. (Pre-merge review fix round 1: the restart syncs the copy's file and directory once, so one syncDir call at start, then none and no write.)
      - Pre-merge review fix round 1: `copy_read_at_start_not_synced` (the directory sync, or the file sync, fails at start: the first refresh rewrites in full, 503 while that write fails too, then 200) and `restart_after_dir_sync_failure` (serve v100; v200's directory sync fails, 503; restart with the sync still failing: still 503, the floor is v200, then 200 once a sync succeeds).
      - The existing `dir_sync_failure_advances_floor` and `equal_identical_no_write` stay green, with their meaning.
    - F12, in `TestDirectoryMirrorFill` (capacity_test.go, on newAgentEnv with one installed directory):
      - `concurrent_misses_one_fetch`: arm `fake.hold("GetDirectory")`, start 24 concurrent `e.s.currentDirectory` calls, and drain `entered` in a goroutine. Once one call has entered, wait a short settle time, then release. `fake.count("GetDirectory")` is 1, and every caller gets the same version and SHA-256. RED on Task 2's head: the count is 24 after release (the budget queues half of them; each still makes its own call).
      - `failure_not_cached`: GetDirectory fails once (setDirectory with an error). Every waiter of that fetch gets an error for which `errors.Is(err, errMirrorStale)` holds, as today's failure path wraps it. The next call fetches again and succeeds.
      - `waiter_ctx_ends_fetch_continues`: the first caller's ctx is cancelled while the fetch is held. That caller returns ctx.Err(); a second waiter, and the mirror, still get the result after release. (Pre-merge review fix round 1: exactly one GetDirectory call from the start of the subtest, so a late second waiter cannot hide a fetch run on the first caller's ctx.)
      - Pre-merge review fix round 1: `competing_status_one_fetch_per_key`: callers of versions 1, 2, 1 (a late caller that read the version-1 Status) and 2 make one GetDirectory per version, and the version-2 fetch becomes the entry.
      - `ended_ctx_starts_no_fetch`: a caller whose ctx has already ended makes no GetDirectory call.
      - `new_sha_new_fetch`: a fetch for version 1 is held; version 2 is installed (installDir, which drops the status cache). A caller for version 2 starts its own fetch, and the version-1 result never becomes the entry for version 2.
      - `mismatch_drops_status`: the signer answers another SHA-256 than Status. Every waiter gets errMirrorStale, and Status is read again on the next call (the existing rule, now inside the fetch).
  </behavior>
  <read_first>
    Read functions, not files; find each with `grep -n`.
    - internal/server/revoke.go: from `type krlView struct` to the end of `var syncDir` (about 10 KB). It covers currentKRL, refreshKRL, servedKRL, loadServedKRL, servedFloor, keepKRL and keepKRLFile.
    - internal/server/revoke_test.go: `func newCopyEnv(`, `krlDoc`, `restart`, `writeCopy`, `get`, `copyBytes`, and the subtests `equal_identical_no_write` and `dir_sync_failure_advances_floor` (about 6 KB).
    - internal/server/directory.go: `type dirMirror struct`, `func (s *Server) currentDirectory(`, `func (e *directoryView) under(` and the head of `func newDirectoryView(` (about 5 KB).
    - internal/server/server_test.go: `setDirectory` and the fake's `GetDirectory` (about 1 KB; the rest of fakeSigner was read in Task 1).
    - internal/server/directory_test.go: `mirror_sha_mismatch_refused` (about 1 KB). It branches on errMirrorStale.
  </read_first>
  <action>
Write the tests in `<behavior>` first, before any code below. Run them on Task 2's head and record in the SUMMARY:
- which are RED;
- for each GREEN at once, why.

**F13 (revoke.go), `F13 (03-08g)`.**
- Add `durable bool` to servedKRL. Its doc comment: set when the copy was renamed into place and its directory synced in one keepKRLFile, or read back at start and its file and directory synced then; only a durable copy lets keepKRL skip the write.
- loadServedKRL syncs the copy's file and directory once and sets `durable` only when both syncs succeed (pre-merge review fix round 1; first `durable: true`). servedFloor's copy keeps it.
- In keepKRL:
  - the equal-version, equal-bytes case returns nil only when prev.durable is true;
  - otherwise it falls through to keepKRLFile, the full sequence (planner decision: a syncDir call alone is not enough);
  - after a rename, s.served gets `durable: err == nil`;
  - the lower-version and other-bytes refusals are unchanged.
- Rewrite keepKRL's doc comment to state the rule.
- Correct the comment at the rename, which says the floor follows the disk: the floor still does, and serving now waits for durability.

**F12 (directory.go), `F12 (03-08g)`.**
- dirMirror gains `inflight *dirFetch`. dirFetch holds:
  - the SHA-256 and the version it fetches;
  - `done chan struct{}`;
  - the result fields: the view and the error.
- currentDirectory, after currentStatus and the version-0 case:
  1. Under the mirror lock, a matching entry is returned as today.
  2. Otherwise it reuses the in-flight fetch when its SHA-256 and version equal the Status's.
  3. Otherwise:
     - a caller whose ctx has ended returns ctx.Err() and starts nothing;
     - else it clears the entry, records a new dirFetch, and starts `go s.fetchDirectory(context.WithoutCancel(ctx), f)`.
  4. It waits for f.done or its own ctx. On success it returns `f.v.under(v)`.
- fetchDirectory:
  - runs GetDirectory under signerCallTimeout, through the budget like every other call, and wraps a failure as errMirrorStale, as today;
  - checks version and SHA-256 against f's, calling s.dropStatus() on a mismatch, with no lock held;
  - parses with newDirectoryView;
  - then, under the mirror lock, stores the entry only when the fetch succeeded and `s.mirror.inflight == f`, and clears inflight only when it is still f; it then closes done.
  - Pre-merge review fix round 1: the single `inflight` pointer let a late caller with an older Status replace another key's pending fetch. dirMirror now holds `pending map[dirKey]*dirFetch`, one per SHA-256 and version, each removed when its fetch ends. A fetch becomes the entry only when its key is that of the Status the server holds when it ends (or it holds none), and a caller with an older Status leaves the entry alone.
  - A failure is never stored.
- Keep dirMirror's lock rule (never held across a signer call, or together with Server.mu). Extend currentDirectory's doc comment with the coalescing, as currentStatus's says it.

Run the whole server package. Every existing directory, login, agent and KRL test must keep its meaning; record any assertion that moved, and why.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestKRLServedCopy|TestDirectoryMirrorFill" ./internal/server/ && go test -race -count=1 ./internal/server/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestKRLServedCopy/dir_sync_failure_never_served", "--- PASS: TestKRLServedCopy/copy_read_at_start_is_durable", "--- PASS: TestKRLServedCopy/dir_sync_failure_advances_floor", "--- PASS: TestKRLServedCopy/equal_identical_no_write", "--- PASS: TestDirectoryMirrorFill/concurrent_misses_one_fetch", "--- PASS: TestDirectoryMirrorFill/failure_not_cached", "--- PASS: TestDirectoryMirrorFill/waiter_ctx_ends_fetch_continues", "--- PASS: TestDirectoryMirrorFill/ended_ctx_starts_no_fetch", "--- PASS: TestDirectoryMirrorFill/new_sha_new_fetch", "--- PASS: TestDirectoryMirrorFill/mismatch_drops_status"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/server/revoke.go | grep -c 'prev.durable'` prints at least 1, and `grep -v '^[[:space:]]*//' internal/server/directory.go | grep -c 'context.WithoutCancel('` prints at least 1.
    - The SUMMARY lists these mutants, each applied, run against its named test, and restored byte for byte:
      - the shortcut without `prev.durable` (killed by `dir_sync_failure_never_served`);
      - `durable: true` regardless of err (killed by the same test);
      - loadServedKRL without `durable: true` (killed by `copy_read_at_start_is_durable`); since the pre-merge review fix round 1 also `durable: true` whatever the start sync gives, and the start sync skipped (killed by `copy_read_at_start_not_synced` and `restart_after_dir_sync_failure`);
      - each caller fetching for itself, with inflight never reused (killed by `concurrent_misses_one_fetch`);
      - the fetch run on the caller's ctx (killed by `waiter_ctx_ends_fetch_continues`);
      - a failed fetch stored (killed by `failure_not_cached`);
      - the `inflight == f` guard on the store removed (killed by `new_sha_new_fetch`, or recorded as equivalent with its reason).
  </acceptance_criteria>
  <done>A KRL is never served while its copy is not durable, and every concurrent miss of the directory mirror shares one signer fetch.</done>
</task>

<task type="auto">
  <name>Task 4: The runbook notes, the publish edits (with the agent-share rule in 03-09 and 03-10), the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/server-install.md, .planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/server-install.md: the paragraph on `krl-served.json` in step 3, and `### The agent listener (host agents, 03-07)` (about 4 KB).
    - .planning/ROADMAP.md: Phase 3's Plans line and its wave blocks (`grep -n 'Wave\|Plans:'`).
    - .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter, Task 1's precondition, and the sentence of Task 2's action that ends `HostIssue joins the server's signerAPI and the fakeSigner test double in internal/server/server_test.go.` (`grep -n 'HostIssue joins'`).
    - 03-10-PLAN.md: the sentence of Task 1's action that ends `server route POST /api/v1/agent/probecert (requireAgent, host name equal to the approved host).` (`grep -n 'agent/probecert (requireAgent'`).
    - The `wave:` lines of 03-10 to 03-16 (`grep -n '^wave:\|^depends_on:'`).
  </read_first>
  <action>
**Runbook notes (CONTEXT D-20).** Each note is labelled "run in CI (the named tests, 03-08g); UNVERIFIED on a real host", per the Homelab owner decision. None names a finding or describes how to provoke a limit.
1. **server-install.md, the `krl-served.json` paragraph**, after the `KRL not kept: ...` case:
   - When the copy was renamed into place but its directory could not be synced, the route keeps answering 503 with `KRL not kept: ...`, and rewrites the copy at every refresh until a write succeeds. Only then is that version served.
   - A failing disk therefore shows as a steady 503, not a single one.
   - Test: TestKRLServedCopy.
2. **server-install.md, `The agent listener`:**
   - The server keeps at most 12 signer calls in flight, plus one read of the published KRL, which never waits for the others. At most 6 of the 12 are calls made for host agents, such as reads of older versions for hosts catching up, so logins and revocations always have room.
   - While the signer waits for a hardware key's touch, calls that need its lock wait with it. The KRL read is not among them. But the KRL route also needs a recent signer status, which waits for that lock, so a long wait still makes the route answer 503 after a few seconds. Hosts keep the KRL they applied and ask again at their next poll.
   - One host agent may have at most 2 requests in flight on the state and heartbeat routes together. A further one is answered 429 with `Retry-After: 1`, and the server logs `agent requests in flight` with the route and the host's expected name.
   - The fetcher sends one request at a time. It meets this limit only while earlier requests of its own are still being answered after it gave up on them, and it then continues at the next poll.
   - Tests: TestSignerBudget, TestKRLDuringFullBudget, TestAgentInFlight.

**Publish edits.** Make them in this PR, on top of origin/main, which holds 03-08d to 03-08f, 03-08j and 03-08k. Every number is origin/main's value + 1. The values in brackets are the expectation after 03-08f (main at 9ac9c12 plus one per plan for 03-08j, 03-08k and 03-08f).
1. Commit this plan unchanged as `.planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each go up by one (N/26 in 25 waves → N/27 in 26 waves). GSD's tracking update sets N.
   - After 03-08f's Wave 17 block, insert `**Wave 18** *(blocked on Wave 17 completion)*` with the unchecked entry `03-08g-PLAN.md — Server signer capacity (F11, F12, F13): the server's signer-call budget with its agent share and a per-agent in-flight slot, one directory fetch per change, and a KRL served only once its copy is durable`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 18–25 → 19–26), each "blocked on" clause with them.
   - Add nothing about 03-08h; it publishes itself.
3. STATE.md: `total_plans` + 1 (61 → 62), and the Plan line's `of M` + 1 (of 26 → of 27).
4. 03-09-PLAN.md:
   - `wave:` + 1 (18 → 19);
   - `depends_on` becomes `["03-08g"]`;
   - Task 1's `<precondition>` gains the clause `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md` exits 0, next to its 03-08c, 03-08d, 03-08e, 03-08j, 03-08k and 03-08f clauses, which stay;
   - **the agent-share rule:** after the sentence that ends `HostIssue joins the server's signerAPI and the fakeSigner test double in internal/server/server_test.go.`, add the sentence `HostIssue also goes through budgetSigner and takes its agent share, and the hostcert route takes agentSlot after requireAgent, as the state and heartbeat routes do (03-08g's agent-share rule).`
5. 03-10-PLAN.md, **the agent-share rule:** after the sentence that ends `server route POST /api/v1/agent/probecert (requireAgent, host name equal to the approved host).`, add the sentence `ProbeIssue also goes through budgetSigner and takes its agent share, and the probecert route takes agentSlot after requireAgent (03-08g's agent-share rule).`
6. The `wave:` lines of 03-10 to 03-16 each go up by one (19–25 → 20–26).
7. **Guards.**
   - If origin/main's 03-09 does not hold `wave: 18` and `depends_on: ["03-08f"]`, another plan was slotted in first. Then apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY.
   - If either anchor sentence of items 4 and 5 is not on origin/main verbatim, add the sentence at the end of the paragraph that adds the hostcert or probecert route, and record where in the SUMMARY.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair, since no package gains a capability; a new pair is a deviation to review and record.

**Push and the PR.**
1. Commit by path only.
2. Push the branch for the first time. The owner allows pushing before the merge.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(server): bound signer calls, coalesce directory fetches, serve only durable KRLs (F11, F12, F13)"` with a neutral body that lists the changes as in the objective. Do not enable auto-merge; the orchestrator enables it after the pre-merge review.
4. Wait for the required checks.

**The SUMMARY** contains:
- the PR number and the check run IDs;
- the RED evidence of Tasks 1 to 3, with where each RED was taken;
- the mutants of Tasks 1 to 3;
- the GREEN-at-once cases with their reasons;
- the two tests that bypass the budget, and every existing assertion that moved, with the reason;
- capslock;
- `requirements-completed` left empty: REVOKE-02 and REVOKE-03 were completed by earlier plans, REVOKE-01 stays pending for parts outside this plan, and this plan hardens all three.

In the SUMMARY, also record the apply `ok` lines and internal/server's `ok` line from the alone and margin gates, with the base values from Task 1, and CI's build-test time once CI has run.

Then run the tracking updates once, commit `docs(03-08g): complete server-capacity plan`, push, and wait.
  </action>
  <verify>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit: internal/agent/apply took more than 400 s alone, or no single ok line</fails_when>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./...' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit: internal/agent/apply's ok line under ./... is above 480 s, or missing</fails_when>
    <automated>grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -c 'agent requests in flight' && tr -s '[:space:]' ' ' < docs/runbooks/server-install.md | grep -c 'TestKRLServedCopy' && grep -c 'agentSlot' .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md && grep -c 'agentSlot' .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md</automated>
    <fails_when>non-zero exit, or any count printed is 0 (a runbook note or an agent-share sentence is missing)</fails_when>
    <automated>grep -qx 'depends_on: \["03-08g"\]' .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md && M=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md) && W=$(printf '%s\n' "$M" | sed -n 's/^wave: //p') && test -n "$W" && grep -qx "wave: $((W+1))" .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md && grep -c '03-08g-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit (the dependency, the +1 wave shift computed from origin/main, or the ROADMAP row is missing)</fails_when>
    <automated>git fetch origin p03/08g-server-capacity && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08g-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08g-server-capacity --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new runbook paragraph names at least one CI test and says UNVERIFIED on a real host.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0, and `B=$(scripts/gh-as-bot.sh pr view p03/08g-server-capacity --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08g-SUMMARY.md is on its head. The PR title and every commit message name findings only by F-number.
  </acceptance_criteria>
  <done>The PR waits green, with the plan, the runbook notes, the agent-share rule in 03-09 and 03-10, and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — owner approves PR p03/08g-server-capacity, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. Open `gh pr view p03/08g-server-capacity --web` and review:
       - budgetSigner, its acquisition order, its agent share, and GetKRL outside it (Q-G5);
       - agentSlot on the state and heartbeat routes;
       - the coalesced directory fetch;
       - the durable flag in keepKRL;
       - the two runbook notes and the agent-share sentences in 03-09 and 03-10;
       - 03-08g-SUMMARY.md.

       Check especially three things:
       - no caller holds a budget token across another signer call;
       - every signer call relayed for a host agent takes the agent share;
       - a KRL is never served before its copy is durable.
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved". After a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08g-server-capacity` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08g-server-capacity</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-08h's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08g-server-capacity --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The server's signer budget is on main, and 03-08h may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08h** runs next. It gives the signer per-account connection shares of 16 (F16), on top of this plan's budget. It also:
  - moves maxSignerCalls to internal/wire as `MaxServerSignerCalls = MaxPeerConns - 4`, with the same value, and counts the server's ceiling at the signer as that plus this plan's one GetKRL (13 against 16);
  - adds the release ordering: the signer frees a slot before it closes the connection, and socketSigner reads to the end of the stream before it returns.

  It edits internal/server/signer.go (socketSigner and the constant) and leaves budgetSigner and agentSlot unchanged.
- **03-08c** added ForgetAgent to signerAPI. budgetSigner wraps it like every other method, and the forget tests run through the budget.
- **03-09 and 03-10** add HostIssue and ProbeIssue to signerAPI, with the hostcert and probecert routes. This plan's publish edits give each one sentence: the call takes the agent share, and the route takes agentSlot after requireAgent. The named field in budgetSigner makes the build fail until each method is wrapped.
- **Later plans that edit the same files** must keep these tests green:
  - TestSignerBudget and TestAgentInFlight, in plans that edit internal/server/signer.go, server.go or agent.go;
  - TestDirectoryMirrorFill, in plans that edit internal/server/directory.go;
  - TestKRLServedCopy, in plans that edit internal/server/revoke.go.
- **03-16 (homelab drill).** It provokes none of these limits on a real host (owner decision), so the runbook notes stay UNVERIFIED on a real host.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: a stalled signer (Q-G5, Daniel, 2026-10-30).**
- Status, GetDirectory and the calls that issue or install take s.mu on the signer. GetKRL, GetBundle and GetDirectoryVersion do not, when they succeed. A not-found answer to GetBundle or GetDirectoryVersion goes through chainRefusal, s.refuse and refuseLogging, which takes s.mu. Honest agents read versions that exist, so the conclusions below hold.
- While the signer holds s.mu across a slow signature, the calls that need it hold their budget tokens until their own timeouts.
- GetKRL takes no token, so it never waits behind them (Q-G5).
- Once those calls and the agent calls in flight hold all 12 tokens, further catch-up reads wait in the budget, although the signer could answer them without s.mu. While 6 agent calls are in flight, 6 stuck calls suffice. The agent share caps the agent calls; it reserves no tokens for them.
- **The limit this plan does not remove.** GET /api/v1/krl, and every agent route through requireAgent, need a Status no older than statusTTL (5 s), and Status waits for s.mu. Past that, KRL and state delivery during a stall answers as when the signer is unavailable, as it does today. Hosts keep what they applied and ask again at their next poll. A Status that does not wait for the lock is a signer change, planned as follow-up plan 03-08i (owner decision 2026-10-30; Deferred ledger).

**Edges:**
- boundaries, each at the cap and one above:
  - 12 server calls;
  - 6 agent calls;
  - 2 requests per agent, on the state and heartbeat routes together;
- ordering:
  - an agent token is taken before a total token;
  - a fetch result is stored only while it is still the one in flight;
- cancellation:
  - a waiter's ctx ends while the fetch goes on;
  - an ended ctx starts nothing and takes no token;
  - a ctx that ends during the total wait gives the agent token back;
- failures:
  - a failed fetch is never cached;
  - a sync that keeps failing gives a 503 at every refresh;
  - every error path releases its tokens;
- concurrency: 24 concurrent mirror misses, 12 concurrent state requests from one agent, and 6 agents with 2 requests each;
- persistence: the copy read at start counts as durable once its file and directory synced at start;
- the controls that must not change:
  - the server's own Status and GetKRL get in while agent calls are held;
  - two agents with 2 requests each are both admitted;
  - an honest fetcher, which sends one request at a time, never meets the slot.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access granted or revoked centrally takes effect across the fleet | Tasks 1-3 |
| REQ | REVOKE-01 (revocation from the CLI, which reaches the signer through the server relay) | Task 1 (the interactive room) |
| REQ | REVOKE-02 (KRLs distributed to all hosts automatically) | Tasks 1-3 |
| REQ | REVOKE-03 (last-good copy kept; a KRL that is not durable is never served) | Task 3 |
| Finding | F11 (the server's signer calls, catch-up fan-out, per-agent in-flight) | Tasks 1, 2; Task 4 runbook |
| Finding | F12 (one directory fetch per change) | Task 3 |
| Finding | F13 (a KRL served only when its copy is durable) | Task 3; Task 4 runbook |
| CONTEXT | 03-CONTEXT D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 4 |
| Owner decision | Fix homes, split, grades, delivery, homelab | Owner decisions block, Tasks 1-5 |
| Owner decision | Q-G1: 12 server calls, 6 agent calls, 2 per agent | Tasks 1, 2. The share of 16 and the release ordering are 03-08h's |
| Owner decision | Q-G2 and Q-G3 | 03-08h |
| Owner decision | Q-G4: no cache of older versions | Nothing built; Deferred ledger |
| Owner decision | The agent-share rule | Task 1 (share), Task 2 (routes), Task 4 (03-09 and 03-10) |
| Owner decision | Q-G5: GetKRL outside the budget, at most 13 calls | Task 1 (`getkrl_outside_budget`, TestKRLDuringFullBudget, the single-caller checks); Task 4 runbook; Edge Coverage and T-03-308 for the Status limit |
| Owner decision | A Status that does not wait for the signer's lock | Not built here: follow-up plan 03-08i (Deferred ledger) |
| Owner decision | Q-G6: one per-agent count across the state and heartbeat routes | Task 2 (`heartbeat_shares_cap`) |
| Owner decision | Q-G7: the non-growth rule | 03-08h |
| Plan check 1 | Item 3 (MAJOR, agent-relayed calls), item 5 (MINOR, the settle wait), item 6 (WARNING, scope) | Tasks 1, 2 and 4; the split. Items 1, 2 and 4 are 03-08h's |
| Finding fix, optional parts | F11: a cache of historical versions; a signerclient receive error that names capacity | Deferred (Q-G4); 03-08h |

## Artifacts this phase produces (this plan)

- **server:**
  - maxSignerCalls, maxAgentCalls, budgetSigner (GetKRL exempt) and withSignerBudget;
  - maxAgentInFlight, agentSlot, inFlightMu and agentInFlight;
  - dirFetch and fetchDirectory;
  - servedKRL.durable.
- **Tests:**
  - TestSignerBudget (5 cases), TestKRLDuringFullBudget (2) and TestAgentInFlight (5);
  - TestKRLServedCopy (2 new cases) and TestDirectoryMirrorFill (6).
- **Docs:** server-install.md: the durable KRL copy, the server's signer budget and the per-agent slot.
- **Planning:** the agent-share sentence in 03-09 and 03-10.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| enrolled agents and unauthenticated clients → keyroster-server → signer | Lower-trust callers. Their requests become signer calls, which must stay within the server's own budget and leave room for logins and revocations |
| keyroster-server → its state directory | krl-served.json is the restore source for revocations. A KRL may reach hosts only once its copy is durable |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-308 | Denial of service | keyroster-server's signer calls: calls relayed for one agent, or concurrent mirror misses from unauthenticated routes, crowding out logins, revocations and the server's own reads (F11, F12) | low | mitigate | budgetSigner: 12 calls in all, at most 6 of them agent calls, which take the agent token first. The share is chosen by method, so the heartbeat and admin pending-hosts paths' GetDirectoryVersion is bounded by it too. agentSlot: at most 2 requests per agent across the state and heartbeat routes. One coalesced directory fetch per Status SHA-256 and version. Tests: TestSignerBudget, TestAgentInFlight, TestDirectoryMirrorFill. **Residual:** (1) the budget is a queue: under catch-up from many agents at once, a state request can wait out signerCallTimeout and answer 503, and the agent continues at its next poll; a login redeem waits for room only until its ctx ends. (2) A stalled signer: calls that need s.mu hold their tokens until their own timeouts. GetKRL is outside the budget and never waits behind them (Q-G5, Daniel, 2026-10-30; `getkrl_outside_budget`, TestKRLDuringFullBudget). Catch-up reads can still wait once they and the stuck calls hold all 12. The KRL and state routes also need a Status younger than statusTTL, which waits for s.mu, so delivery past that during a stall fails as today; a Status that does not wait for the lock is follow-up plan 03-08i. GetBundle and GetDirectoryVersion take s.mu on a not-found answer, through refuseLogging. (3) A row ID reused after a forget counts the forgotten agent's last in-flight request against the new agent until that handler ends, as the token bucket does |
| T-03-311 | Tampering | krl-served.json: a KRL served to hosts before its copy is durable, so that a later restore from that copy lacks its revocations (F13) | low | mitigate | servedKRL.durable. The equal-version shortcut is taken only for a durable copy; otherwise the full write is redone and the route answers 503. Tests: `dir_sync_failure_never_served`, `copy_read_at_start_is_durable` |
| T-03-312 | Tampering | the coalesced directory fetch handing a caller bytes of another SHA-256 or version (this plan's own risk) | low | mitigate | dirFetch is keyed on the Status SHA-256 and version. Its result is stored only while it is still the fetch in flight, and a mismatch drops the status cache as before. Tests: `new_sha_new_fetch`, `mismatch_drops_status`. The prohibition |
| T-03-314 | Denial of service | signer calls that later plans relay for host agents (HostIssue in 03-09, ProbeIssue in 03-10) taking interactive tokens, or their routes lacking the per-agent slot (plan check 1) | low | mitigate | The owner's agent-share rule, in budgetSigner's and signerAPI's comments and as one sentence each in 03-09 and 03-10 (Task 4, checked by its grep). The named field makes a new method fail to build until budgetSigner wraps it. **Residual:** the compiler forces the wrapping; the choice of share and the slot rest on the rule and on review |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added. The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh), the full gate passes, the PR's required checks are green, and the merge gate passes.
</verification>

<success_criteria>
- keyroster-server never has more than 12 budgeted signer calls in flight, of which at most 6 are relayed for host agents, plus its one coalesced GetKRL, which never waits for the budget. One agent never has more than 2 requests in flight on the routes that relay signer calls.
- Concurrent mirror misses make one signer fetch, and a KRL is never served before its copy is durable.
- 03-09 and 03-10 carry the agent-share rule.
- Nothing the server accepts or serves is widened, and no module is added.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md` in Task 4, before the merge gate. Leave `requirements-completed` empty: REVOKE-02 and REVOKE-03 were completed by earlier plans, REVOKE-01 stays pending for parts outside this plan, and this plan hardens all three. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (F11, F12 and F13, and the owner decisions of 2026-10-29)

### Round 0b — planner self-review while completing the plan (2026-10-30), before plan check 1

### Round 1 — plan check 1 (2026-10-30, PASS WITH FIXES) and the owner's answers (Daniel, 2026-10-30)

### Round 2 — plan check 2 (2026-10-30, PASS WITH FIXES) and the owner's third set of answers (Daniel, 2026-10-30)

### Round 3 — reconcile check against main 741e2f6 (2026-11-03, PASS WITH FIXES)

No overlap with PRs #77 to #82 (no diff under internal/server, internal/signer, internal/wire, internal/serverclient, cmd/keyroster-server or server-install.md since 98e9e5c); every cited reference still holds. Fixed: (B1) Task 1's verify split into two -run patterns, since go test splits at `/` before `|`, and the RED uses the same patterns; (W1) the Budget section carries 03-08k's 400 s / 480 s apply limits, the stop rule, base measurements in Task 1 and both gates in Task 4; (W2) the Context lines name 03-08j and 03-08k and the files fetch.go and heartbeat.go; (I1) Task 4's full gate first checks that scripts/linux.sh uses `--exec`, so the gofmt step cannot pass vacuously. No new owner questions.

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| F11: catch-up reads relayed for one agent fan out into signer calls with no server-side bound and no per-agent in-flight limit | LOW | Truths 2 and 3; Tasks 1 and 2; T-03-308 |
| F12: concurrent mirror misses each make their own GetDirectory call | LOW | Truth 4; Task 3; T-03-308, T-03-312 |
| F13: after a failed directory sync, the next refresh serves the version through the equal-bytes shortcut | LOW | Truth 5; Task 3; T-03-311 |
| Planner: in the other acquisition order, queued agent calls hold total tokens and starve logins and revocations | MEDIUM | Agent token first; the swapped-order mutant is killed by `catch_up_bounded_interactive_room` |
| Planner: an embedded signerAPI in budgetSigner would pass later methods through without the budget | MEDIUM | Named field, an acceptance check, and a cross-plan note |
| Planner: the per-agent 429 must reach the fetcher's rate-limited paths | LOW | `Retry-After: 1` and the body `rate limited`; both RateLimited branches read in Task 2 |
| Planner: GetDirectoryVersion also has heartbeat-path and admin-path callers | LOW | The share is chosen by method; Task 1 and T-03-308 |
| Planner: two server tests replace e.s.signer after newServer | LOW | Left unbudgeted, since their meaning does not involve capacity; the SUMMARY names them |
| Planner: GetDirectory failures must stay errMirrorStale | LOW | Task 3's fetchDirectory wraps them, and `failure_not_cached` asserts it |
| Check 1 item 3 (MAJOR): HostIssue and ProbeIssue would take interactive tokens, and their routes have no per-agent cap | MAJOR | The owner's agent-share rule: in budgetSigner's and signerAPI's comments, on the state and heartbeat routes, and one sentence each in 03-09 and 03-10. The share is renamed from "catch-up" to "agent". T-03-314 |
| Check 1 item 3, applied today: the heartbeat route relays GetDirectoryVersion through confirmRemoval, so the rule covers it | MEDIUM | One per-agent count across the state and heartbeat routes (Task 2, `heartbeat_shares_cap`). The pre-split draft left heartbeats uncounted. Confirmed by the owner (Q-G6, Daniel, 2026-10-30) |
| Planner, while splitting: during a stall, GetKRL queued in the budget behind calls that need the signer's lock | MEDIUM | Q-G5 (Daniel, 2026-10-30): GetKRL outside the budget, with its single coalesced caller pinned. The remaining limit, the routes' fresh Status, is stated in Edge Coverage, T-03-308 and server-install.md |
| Check 1 item 5 (MINOR): the swapped-order mutant is killed only if the queued agent calls reach their token waits first | MINOR | `catch_up_bounded_interactive_room` waits out the settle time after 6 are in flight, before the interactive calls start |
| Check 1 item 6 (WARNING): scope | WARNING | Split by the owner (2026-10-30): this plan is the server side; 03-08h is the signer side |
| Check 1 item 1 (MAJOR), as it touches the budget: during a stall, calls that need s.mu hold budget tokens | MAJOR | Stated without the false premise in Edge Coverage and T-03-308, with GetKRL outside the budget (Q-G5). The slot half, and its correction in three places plus the runbook, is 03-08h's |
| Check 1 items 2 and 4 (WARNING, MINOR) | — | 03-08h's: the release ordering, and the Q-G3 runbook text |
| Check 2 item 1 (WARNING): Q-G5's aim is met only while the status cache is fresh, and the rest had no home | WARNING | Owner decision 2026-10-30: follow-up plan 03-08i. A Deferred row, and pointers in the owner decisions, Edge Coverage, T-03-308 and the source audit |
| Check 2 item 2 (WARNING): "inside refreshKRL" was prose only | WARNING | An awk range check in Task 1's acceptance, plus a grep that no other name for the signer reaches GetKRL |
| Check 2 item 3 (MINOR): the GetDirectoryVersion count in `heartbeat_shares_cap` is trivially unchanged | MINOR | Stated as a no-call guard; the 429 kills the mutants |
| Check 2 item 8 (INFO): GetBundle and GetDirectoryVersion take s.mu on a not-found answer | INFO | Stated in Edge Coverage and T-03-308 |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| F11: cache historical bundle and directory versions on the server | Q-G4 (Daniel, 2026-10-30): not cached. A signer restore can re-make a version number with other bytes, and the budget and the per-agent slot already bound the signer connections |
| F11: a reserved slot for keyroster-server or for admins | Q-G2 (Daniel, 2026-10-30): no reserved slot |
| F11 and F12: a login redeem burns its code before signer.Login, so a failed signer call loses the code | Pre-existing, and a login-flow change. The budget's interactive room makes a capacity failure of that call rarer |
| KRL and agent-state delivery during a long slow signature: both routes need a Status younger than statusTTL (5 s), and the signer's Status waits for its lock | A signer change with its own threat review. Planned as follow-up plan 03-08i, after 03-08h: a Status snapshot updated under s.mu at every state change and read without the lock (owner decision 2026-10-30). Until then this plan's Q-G5 change keeps GetKRL out of the budget queue, and delivery past statusTTL during a stall fails as it does today |

