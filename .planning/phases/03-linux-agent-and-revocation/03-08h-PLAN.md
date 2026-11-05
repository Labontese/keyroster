---
phase: 03-linux-agent-and-revocation
plan: 08h
type: execute
wave: 19
depends_on: ["03-08g"]
files_modified:
  - internal/directory/render.go
  - internal/directory/render_size_test.go
  - internal/agent/apply/swap.go
  - internal/agent/apply/renderable_test.go
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
requirements: [REVOKE-01, REVOKE-02, AUTHZ-02]

estimate:
  tokens: 85000
  raw_tokens: 85000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-10-29 and 2026-10-30): this plan is the signer side of the signer-capacity work and holds F16 and the signer half of F07 (`directory_unrenderable`). It runs after 03-08g, whose signer budget in keyroster-server it builds on. Q-G1 to Q-G7 are decided; the numbers below are the owner's"
    - "F07, signer half. Signer.InstallDirectory refuses, after CheckPolicy and before anything is stored or logged as installed, a directory that host agents cannot render: `directory_unrenderable` (unauthorized class, CodeRefused, so the server answers 403), logged on the install refusal bucket. The rule is directory.CheckRenderable:
      - every host group maps at most directory.MaxHostGroupAccounts accounts, which is half of directory.MaxAccounts (2048, Q-G3), so the intermediate generation between any two accepted versions still fits;
      - every account's principals file, as directory.RenderPrincipalsFile would write it at the widest version, is at most directory.MaxPrincipalsFile bytes (64 KiB, Q-G3 and Q-G7).
    The non-growth rule (Q-G7) covers a directory installed before this release that is above a cap. A host group above the account bound is still accepted when the installed version has a host group of that name and its accounts are a subset of the installed group's. A principals file above the size bound is still accepted when it is no larger than the same host group's and account's file in the installed version. A host group with no installed counterpart always meets the bounds. Every file is sized as if its header held the widest version, 20 digits (Q-G7, Daniel, 2026-10-30), for the bound and for the comparison alike. So a file accepted once stays within 64 KiB at every later version, and an unchanged file never grows when the version gains a digit. Nothing then grows beyond the installed version: hosts at that version keep rendering it, so disabling and removing users always go through. The installed directory is the one the signer holds (s.directory); before the first install it is nil, and only the bounds apply.
    The agent's generation caps in internal/agent/apply are defined as directory.MaxPrincipalsFile and directory.MaxAccounts, and CheckRenderable sizes each file with the renderer's own header function, so the signer and the agent cannot drift. The check runs at install only: never in Parse, Validate or loadDirectory, which also read stored state.
    E-1 (owner decision (2026-11-04), execution stop at Task 1): the sizes come from a sizer that indexes the roles and every distinct principal once, iterates each host group's accounts directly and deduplicates principals without sorting. It gives exactly the length RenderPrincipalsFile writes at the widest version (TestSizerMatchesRender), and keeps CheckRenderable under 2 s under -race at 4096 accounts in both versions.
    E-2 (owner decision (2026-11-04), execution stop at Task 1): a version that moves a host to another host group is refused `directory_unrenderable` when that host's intermediate would exceed the agent's caps. A host is the same when an active entry of the offered version and an active entry of the installed version share a host key, as the agent finds its entry by its host keys. The move is refused when the union of the old group's accounts (installed) and the new group's (offered) is above MaxAccounts, or when a file of the new group is above MaxPrincipalsFile, since the host never rendered it. With both groups within the share it always holds, so it bites only with Q-G7's above-share installed groups"
    - "F16. The signer reads each connection's peer credentials in the accept loop, without s.mu, before it takes a slot. No account (uid) holds more than wire.MaxPeerConns (16) of the maxConns (32) slots (Q-G1), and no slot is reserved (Q-G2), so after any one account takes its whole share, 16 slots remain. A peer that is not allowed, or whose credentials cannot be read, counts against its uid's share (tlog.PeerUnknown for the latter) and is still refused through s.refuse in its own goroutine, never in the accept loop. A connection over the global cap or over its account's share is closed unanswered and counted in the refusal_summary leaf as before. The operator log line names its uid and is rate-limited by a bucket only the accept loop uses. The audit log format is unchanged"
    - "Release ordering (Q-G1, Daniel, 2026-10-30). The signer frees a connection's slot before it closes the connection, on every path out of handle. socketSigner, and only socketSigner, reads each call's connection to the end of the stream, bounded by the call's deadline, before it returns, and so before 03-08g's budget frees its token. The server's live connections counted at the signer therefore never exceed the budget tokens it holds, wire.MaxServerSignerCalls (12, MaxPeerConns − 4), plus its one coalesced GetKRL, which 03-08g keeps outside the budget (Q-G5): 13 against the share of 16. The 3 left are margin for other callers under the same uid and for abandoned calls, not a timing assumption. The CLI's calls are unchanged"
    - "Stalled signer (accepted, Q-G1, Daniel, 2026-10-30). Status, GetDirectory and the calls that issue or install take s.mu on the signer; GetKRL, GetBundle and GetDirectoryVersion do not, and connDeadline bounds socket I/O, not the wait for s.mu. A call the server abandons at its own timeout while s.mu is held across a slow signature frees its token but keeps its slot until its handler ends. Once more than 3 are stuck while the server's 13 are in use, the share can close the server's next calls unanswered, GetKRL and the catch-up reads included. T-03-307 and signer-install.md say so"
  artifacts:
    - path: "internal/directory/render.go"
      provides: "the shared render caps and CheckRenderable"
      contains: "func CheckRenderable("
    - path: "internal/signer/directory.go"
      provides: "the install-time refusal of directories host agents cannot render"
      contains: "directory_unrenderable"
    - path: "internal/signer/server.go"
      provides: "per-account connection shares in the accept loop, each slot released before its connection closes"
      contains: "maxConnsPerPeer"
    - path: "internal/signerclient/client.go"
      provides: "the Client whose AwaitClose reads a call's connection to the end of the stream"
      contains: "AwaitClose"
    - path: "internal/wire/frame.go"
      provides: "the signer's per-account share and the server's total derived from it"
      contains: "MaxServerSignerCalls"
  key_links:
    - from: "internal/agent/apply/swap.go"
      to: "internal/directory/render.go"
      via: "the agent's generation caps are the directory package's constants"
      pattern: "directory.MaxPrincipalsFile"
    - from: "internal/signer/directory.go"
      to: "internal/directory/render.go"
      via: "InstallDirectory calls CheckRenderable after CheckPolicy"
      pattern: "directory.CheckRenderable("
    - from: "internal/signer/server.go"
      to: "internal/wire/frame.go"
      via: "the signer's per-account share is the constant the server's total is derived from"
      pattern: "wire.MaxPeerConns"
    - from: "internal/server/signer.go"
      to: "internal/wire/frame.go"
      via: "03-08g's budget total is the wire constant, 4 below the share"
      pattern: "wire.MaxServerSignerCalls"
    - from: "internal/server/signer.go"
      to: "internal/signerclient/client.go"
      via: "socketSigner makes every call through a Client that waits for the signer's close"
      pattern: "AwaitClose: true"
  prohibitions:
    - statement: "Nothing here widens what any component accepts or serves. CheckRenderable only adds a refusal at install. The shares only refuse connections. AwaitClose only delays when a call returns, never what it returns. The signer imports nothing under internal/agent"
      status: resolved
      verification: test
---

<objective>
Capacity and robustness hardening of the signer, on top of 03-08g's budget in keyroster-server. After this plan:
- **F16.** No single account on the signer socket can take every signer connection, and keyroster-server's own calls can never be refused by its share.
- **F07, signer half.** The signer refuses at install a directory that host agents cannot render, using the agent's own caps.

Purpose:
- REVOKE-01: a revocation from the CLI reaches the signer through the server relay, whatever another account does on the socket.
- REVOKE-02: the server's KRL and state reads keep reaching the signer, so KRLs keep reaching every host.
- AUTHZ-02: every installed directory can be rendered as principals files.

Output:
- directory.CheckRenderable, with the non-growth rule against the installed directory (Q-G7), and the shared caps;
- the signer's per-account shares, with each slot released before its connection closes;
- signerclient.Client with AwaitClose, used only by socketSigner;
- named tests with RED evidence and mutants;
- two runbook notes;
- the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Fix homes (Daniel, 2026-10-29, "kör på förslagen").** F11, F12, F13 and F16 run after 03-08f, together with the signer half of F07. They were to be planned only after 03-08c merged, because they overlap 03-08c's signer work; 03-08c is on main.
- **directory_unrenderable (Daniel, 2026-10-29).** The signer-side refusal, at install, of a directory the agent cannot render belongs here. 03-08d fixed the host side (state.KRLAlone, checkCandidate).
- **Split (Daniel, 2026-10-30), after plan check 1.**
  - 03-08g: the server side, F11, F12 and F13. Wave 18, after 03-08f.
  - 03-08h, this plan: the signer side, F16 and F07's signer half. Wave 19, after 03-08g. It holds the CheckRenderable tracer.
  - Since 2026-11-01 the order before them is 03-08e → 03-08j → 03-08k → 03-08f (owner decisions on the 03-08j/03-08k split, 2026-11-01, and of 2026-11-02, which keep 03-08j directly before 03-08k).
  - The server side goes first. F16's per-account share without F11's budget would refuse keyroster-server itself under load.
  - Each plan publishes itself, as 03-08d does: origin/main's values + 1, with the guard.
- **Grades.** F07 low (owner, 2026-10-29). F16 is low as reported.
- **Delivery (2026-10-29).**
  - The plan lands in the same PR as its fix.
  - The PR title and every commit use neutral hardening wording and name findings only by F-number.
  - Pushing the branch and opening the PR before the merge is allowed, with its diff public while it is open.
- **Homelab.** No 03-16 drill provokes these refusals or limits on a real host. The runbook text this plan writes is labelled run in CI, and UNVERIFIED on a real host.
- **Q-G1, the numbers (Daniel, 2026-10-30): 16/12/6/2.**
  - Signer: 32 connections in all, at most 16 per account (uid). That is this plan's (`wire.MaxPeerConns`).
  - Server: at most 12 signer calls in flight, of which at most 6 are relayed for host agents. 03-08g built that budget; this plan derives its total from the share (`wire.MaxServerSignerCalls = MaxPeerConns - 4`).
  - Agents: at most 2 requests in flight each (03-08g).
  - **The release ordering**, so that the server's own budget can never be refused by its signer share:
    - the signer frees a connection's slot before it closes the connection;
    - socketSigner reads to the end of the stream before it returns, and so before its budget token is freed. Only socketSigner does this; the CLI is unchanged.

    It replaces the pre-split draft's timing margin. MaxServerSignerCalls stays 4 below the share. With 03-08g's GetKRL outside the budget (Q-G5), the server's ceiling at the signer is 13, which leaves 3 slots as margin. The stop rule of `server_budget_within_share` stays.
  - **The stalled-signer trade-off is accepted** and documented in T-03-307, in Edge Coverage and in signer-install.md. During a long touch signature, abandoned calls keep their slots. Once more than 3 are stuck, the server's GetKRL is refused. The owner's first answer said more than 4; with GetKRL outside the budget (Q-G5), GetKRL itself takes one of those four.
- **Q-G2 (Daniel, 2026-10-30).** No reserved slot: no named account, no reserved pool, and no new flag or unit change. Two allowed accounts together can still hold every slot (T-03-309).
- **Q-G3 (Daniel, 2026-10-30).** At most 2048 accounts per host group, half the agent's 4096, and at most 64 KiB per principals file as rendered. The runbook says three things, as refined by Q-G7:
  - an installed directory above the cap stays in force and renders;
  - a later install that grows such a group or file is refused until the group is split, while disabling and removing go through (Q-G7);
  - a split keeps the account names, because new disjoint names can push the intermediate set past the agent's 4096 on hosts (KRLs still land, through 03-08d).
- **Q-G4 (Daniel, 2026-10-30).** No cache of older versions on the server (03-08g).
- **Q-G5 (Daniel, 2026-10-30).** GetKRL stays outside 03-08g's server budget. The server's ceiling at the signer is therefore 13, inside the share of 16. This plan carries it into the arithmetic (TestConnSlots `arithmetic`) and into `server_budget_within_share`, which drives 12 budgeted callers plus one GetKRL caller.
- **Q-G6 (Daniel, 2026-10-30).** One shared per-agent in-flight count across the state and heartbeat routes (03-08g).
- **Q-G7 (Daniel, 2026-10-30): the non-growth rule.**
  - A directory above the cap may still be installed when no host group's accounts grow and no principals file grows.
  - Disabling and removing therefore always go through: `keyroster revoke user` can disable a user even while an above-cap directory is installed.
  - The intermediate stays within the agent's caps, because the old version already renders.
  - Task 1 carries it, with tests and mutants for:
    - a disable or a removal under an above-cap directory, which is accepted;
    - growth under an above-cap directory, which is refused;
    - the normal path under the cap.
- **Q-G7, version digits (Daniel, 2026-10-30): size against the widest header.** Every principals file is size-checked as if its header held the widest version (20 digits), for the bound and for the non-growth comparison.
  - One rule then covers every case, at a cost of about 19 bytes of the cap, and disabling and removing always go through.
  - Task 1 tests it at 9 → 10 and at 99 → 100, with a file at the cap, and has a mutant for it.
- **Confirmed (Daniel, 2026-10-30):** the subset reading of Q-G7, and keeping this plan whole. The share and both halves of the release ordering must land together.
- **Execution stop at Task 1 (Daniel, 2026-11-04).** The executor stopped on `check_renderable_is_fast_enough`: under -race the plan's literal exception shape (4096 accounts × ~60 KiB in both versions) took 2.25 s, and the all-files-above-bound shape 4.84 s, with fileSize calling AccountPrincipals per account. The owner decided:
  - **E-1, a faster fileSize.** Keep the 2 s bound under -race. CheckRenderable sizes through a sizer that indexes roles by name and principals by number once, iterates the group's accounts directly and deduplicates without sorting, with exactly the same sizes. No cache keyed by identical role lists. TestSizerMatchesRender compares every account's size, on varied non-uniform directories, with the rendered file at the widest version; a mutant that breaks deduplication fails it. The timed case times three shapes: normal (2048 accounts), the literal exception shape, and the all-files-above-bound shape.
  - **E-2, refuse in the signer.** A version that moves a host to another host group is refused `directory_unrenderable` when that host's intermediate during the move would exceed the agent's caps (the union of the old and new group's accounts against 4096, and the new group's files against 64 KiB). Tests: the 3000-account installed group with a host moved to a 2048-account group, refused; the same move into a group whose union with lab is exactly 4096, installs; a move between two within-share groups, installs. enroll-user.md says such a move is refused until the group is split.
- **Status during a slow signature (Daniel, 2026-10-30): follow-up plan 03-08i**, after this plan, with its own threat review and plan check. It adds a Status snapshot read without the signer's lock. This plan builds nothing toward it.

## Open owner questions

None open.

**Planner decisions (Claude's discretion), recorded with their reasons:**
- *The release ordering lives here, with the share, not in 03-08g.*
  - Neither half guarantees anything alone. Reading to the end of the stream orders the release only if the signer frees the slot before it closes, and freeing it first helps only if the client waits for the close.
  - It matters only once a per-account share exists. Under 03-08g alone, the server's 12 calls meet only the signer's global 32.
  - The tests that prove it need the share: `slot_released_before_close` reads the share's accounting, and `server_budget_within_share` counts refusals by it.
  - internal/signer/server.go stays owned by one plan.
  - 03-08g's budgetSigner wraps socketSigner, so a socketSigner call that returns only at the end of the stream holds its token until then. budgetSigner itself is unchanged.
- *The signer half is structural.* Serve's goroutine defers wg.Done, then conn.Close, then the slot release. Deferred calls run in reverse, so the slot is released, then the connection closed, on every path out of handle. handle no longer closes the connection, and Serve's goroutine is its only caller.
- *The client half is a signerclient.Client value with AwaitClose.*
  - Every package-level function becomes a one-line wrapper of `Client{Socket: socket}`, with unchanged behaviour. The CLI (cmd/keyroster) and the server's start-up Status (cmd/keyroster-server/serve.go) keep calling them, unchanged.
  - socketSigner keeps its socket field and builds `signerclient.Client{Socket: s.socket, AwaitClose: true}` for every call, so New and TestSocketSignerLoginReadsPastSendDeadline stay unchanged.
  - Rejected: a context value, which hides a parameter, and an option argument on every function, which changes eleven signatures for one flag.
- *AwaitClose never changes a call's result.*
  - After a whole response frame (an answer or a refusal), it reads and discards until EOF, the deadline already on the connection, or 64 KiB. That deadline is ctx's, or for LoginSend the read deadline after the send.
  - Each of those ends returns what the frame said, so a login certificate is never lost to the wait.
  - When no whole frame arrived, there is nothing to wait for: the signer closed, or the deadline passed.
  - The signer writes nothing after its one frame, and it frees the slot and closes right after it, so the wait is short.
- *The 3 slots above the server's 13 are margin, not a timing assumption.* With the ordering, the server's live counted connections never exceed its 12 tokens plus its one coalesced GetKRL (Q-G5). The 3 are for other callers under the same uid and for calls the server abandoned during a stall. CI's e2e jobs run every component as one uid, and a deployment may run an admin under the server's uid.
- *wire holds both constants*, `MaxPeerConns` and `MaxServerSignerCalls = MaxPeerConns - 4`, so the signer's real-socket tests drive exactly the server's total without importing internal/server. 03-08g's local `maxSignerCalls = 12` becomes `wire.MaxServerSignerCalls`, with the same value.
- *Shared caps live in internal/directory.* It already holds the one principals renderer (02-CONTEXT D-07). The signer must not import internal/agent/apply: that package reaches internal/agent/execsite and so os/exec, which scripts/dep-firewall.sh bans for keyroster-signer. apply's `maxPrincipalsFile` and `maxAccounts` become the directory constants.
- *CheckRenderable sizes files arithmetically, with the renderer's header function at the widest version.* It computes the canonical SHA-256 once, then for each account takes the length of `principalsHeader(group, account, math.MaxUint64, sha)` plus len(p)+1 per principal of AccountPrincipals. The widest version makes the size independent of the version number (Q-G7). Rendering every file through PrincipalsRenderer would build every file's bytes under s.mu, and at the real version, not the widest.
  - The bound is therefore up to 19 bytes stricter than the agent's checkLimits. It still refuses everything the agent would refuse, at any version.
- *Intermediate files.* An intermediate principals file holds a subset of the target file's lines under intermediateHeader. A test pins that this header is not longer than any real header, so the per-file check covers intermediates too.
- *Q-G7 is a subset rule for accounts, not a count rule.* The owner's justification is that the intermediate stays within the caps because the old version renders. That holds only when the new group's accounts are a subset of the installed group's: the intermediate is then the installed set. With the same count but one name swapped, the union grows by one account. So:
  - an above-bound group is accepted only as a subset of the installed group of the same name;
  - a host group that is new in the offered version gets no exception.
- *Q-G7 for files is "no file grows", measured at the widest header.* A file above the bound is accepted only when it is no larger, sized at the widest header, than the same host group's and account's file in the installed version.
  - A disable or removal never adds a principal, so it always goes through, at every version, digit rollovers included.
  - A file accepted within the bound stays within 64 KiB as rendered at every later version.
  - One residual is left for directories installed before this release: a file that rendered at exactly the agent's cap. Unchanged across a digit rollover, it still installs, but it renders one byte above the cap. Hosts then refuse that generation and keep applying KRLs (03-08d) until the file is reduced. T-03-306 says so.
- *Q-G7's guarantee is scoped.* It covers hosts at the installed version. A host further behind can still meet an intermediate above its caps, and 03-08d's KRL-alone pass keeps its KRLs landing.
- *CheckRenderable takes the installed directory* (`CheckRenderable(d, installed *Directory)`). InstallDirectory passes s.directory, which it already holds under s.mu, and which is nil before the first install. The exception path renders the installed version's sizes only for the groups and files that need it.
- *The new refusal is classified next to `directory_exceeds_policy`* (unauthorized, CodeRefused, 403 through installRefusalStatus) and goes through installDirectoryOrRefuse's bucket. It needs no server change. The CLI prints the API error code; a dedicated CLI message is deferred (ledger).
- *No identity-override seam in the signer.* Tests of the share between accounts pre-fill another uid's share in the accounting itself, and dial as the test's own uid through the real accept loop. `slot_released_before_close` holds the accounting's mutex from the test. Both are internal tests acting on internal state before or while serving; neither is a production seam. A function field that overrides peer credentials would be a path around the allowlist.
- *Over-capacity logging.* The accept loop owns its own refusalLimiter instance, used by no other goroutine, so it never takes s.mu. Every refused connection still counts in s.overloaded, and so in the refusal_summary leaf. No tlog format changes.
- *The signerclient receive error* also names capacity as a cause. Today it names only the allowlist.

## Budget

There are 14 code and test files, two of them new test files, and two runbooks. The publish edits add the plan itself, ROADMAP.md, STATE.md and the wave lines of 03-09 to 03-16, plus one sentence each in 03-09 and 03-10. Four tasks precede the merge gate, as in 03-08f. Every implementation task touches at most 6 files; the tracer's six are the ones the pre-split draft checked.

About 85k tokens:
- about 86 KB of code read through the function-scoped read_first lists (signerclient/client.go, about 8 KB, whole), roughly 24k tokens;
- about 39k written, Q-G7's exception, the widest header and their cases included;
- about 22k of test and gate output.

Like the estimates of 03-08d to 03-08g, this leaves out the plan itself. At about 110 KB (roughly 30k tokens), it brings the executor's total to about 115k. That is above the siblings. The plan is kept whole by owner decision (2026-10-30): the share and both halves of the release ordering must land together. Task 1 is self-contained, so the executor can drop its read_first context once it is done.

**Test time.** 03-08k's two limits apply, and Task 1 adds TestRenderable to internal/agent/apply, the heaviest package: 400 s for internal/agent/apply alone under -race, and 480 s for its `ok` line under `./...`. On 741e2f6 they measured 335.1 s and 368.5 s (03-08f-SUMMARY, fix round 2).
- Alone gate: `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'`
- Margin gate: `set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./...' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} END{exit (n!=1 || bad)}'`
- Stop rule, as 03-08f's: measure both bases before Task 1's first edit and record them in the SUMMARY. If a base, or a reading after Task 1, is above its limit, stop and report the two options (raise CI's -timeout, or move slow cases to their own package) without choosing.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-08d-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names.
- **Branch.** Create `p03/08h-signer-shares` from origin/main in Task 1.
- **Plan file.** Place this file untracked in the phase directory at the start. Task 4 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Wording.** Commits and PR text use neutral hardening wording (`fix(signer): ...`, `fix(signerclient): ...`, `test(...)`) and name findings only by F-number. No attribution lines, no IP addresses, no real host names.
- **Code comments** cite `F07 (03-08h)` or `F16 (03-08h)`. A bare F-number would be read as an earlier review's.
- **Linux tests.** The signer's tests are Linux-tagged and run in WSL through `bash scripts/linux.sh '...'`. So does every verify command below, as in 03-08d to 03-08g.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md`, with the docs commit `docs(03-08h): complete signer-shares plan`.

**What this plan builds on:**
- **From 03-08g:** budgetSigner, which newServer installs around socketSigner and which frees a token when the wrapped call returns; `maxSignerCalls` (12); agentSlot.
- **From 03-08d:**
  - checkCandidate, which checks the target's and the intermediate's caps on the agent;
  - the KRL-alone pass after a content refusal.

  Both keep working unchanged, now on caps defined in internal/directory.
- 03-08d and 03-08f edit other parts of apply/swap.go and apply/render.go, so find the const block and intermediateHeader with grep. 03-08d, 03-08j and 03-08f edit signer-install.md, and 03-08f edits enroll-user.md, in other places. 03-08e and 03-08k touch none of this plan's files.

**The code this plan changes, as read on main at 741e2f6 (03-08d, 03-08e, 03-08j, 03-08k and 03-08f merged). 03-08g leaves these functions unchanged, except socketSigner's surroundings in internal/server/signer.go.**
- **F07, signer half.**
  - InstallDirectory checks signatures, the version chain, Parse/Validate, the installation binding and CheckPolicy.
  - Directory.Validate bounds principals per role and per user, but not accounts per host group or the rendered size of an account's principals file.
  - The agent's caps (swap.go: 64 KiB per principals file, 4096 principals files) are defined only in internal/agent/apply.
- **F16.**
  - Serve takes a slot from one listener-wide semaphore of maxConns (32) in the accept loop, before the peer is identified.
  - handle reads the peer credentials only after that.
  - handle closes the connection in its own deferred call, and the goroutine frees the slot after handle returns, so the close comes first.
  - An allowed connection keeps its slot until its handler ends. One account's connections therefore count against every account's capacity.
  - Every over-capacity close is logged once, anonymously.
- **signerclient.** Every call returns as soon as readResponse has read the frame, and its deferred Close follows. The receive error names only the allowlist.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "a quorum-signed directory whose host group or principals file is above what host agents render → InstallDirectory, after CheckPolicy, runs directory.CheckRenderable on the agent's own caps against the installed directory → refused directory_unrenderable on the install bucket, nothing stored, unless nothing grows beyond an above-cap installed version (Q-G7) → the agent's checkLimits agrees at the boundary, the intermediate included"</name>
  <reversibility rating="reversible">An added refusal at install and constants moved between packages. No stored format, wire message or log leaf changes. A directory installed before this plan stays installed; the next install must fit, or grow nothing beyond it (Q-G7).</reversibility>
  <precondition>All four checks hold:
    - `git fetch origin` succeeds.
    - `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08g-SUMMARY.md` exits 0.
    - `S=$(git show origin/main:internal/server/signer.go) && printf '%s\n' "$S" | grep -c 'func withSignerBudget('` prints 1, which shows that 03-08g is merged.
    - `R=$(git show origin/main:internal/signer/refusal.go) && printf '%s\n' "$R" | grep -c 'directory_unrenderable'` prints 0, which shows that this plan is not applied yet.
  </precondition>
  <files>internal/directory/render.go, internal/agent/apply/swap.go, internal/agent/apply/renderable_test.go, internal/signer/directory.go, internal/signer/refusal.go, internal/signer/directory_test.go</files>
  <read_first>
    Read functions, not files: find each with `grep -n` and read only that range.
    - internal/directory/render.go: the whole file (about 5.4 KB). It holds AccountPrincipals, RenderPrincipalsFile, PrincipalsRenderer and HostPrincipals.
    - internal/directory/directory.go: the host-group loop of `func (d *Directory) Validate(` (`grep -n 'host_groups'`) and `func checkSorted(`, about 2 KB. Accounts in a host group are strictly sorted, so they are unique.
    - internal/agent/apply/swap.go: the generation-cap const block, `ErrGenerationTooLarge` and `func checkLimits(` (about 2 KB).
    - internal/agent/apply/render.go: `const intermediateHeader`, `func ClassOf(`, `func Intermediate(` and the principals loop of `func Render(` (about 4 KB).
    - internal/signer/directory.go: `func (s *Signer) InstallDirectory(`, including its logTx that stores the version and writes the directory_install leaf, and `func (s *Signer) loadDirectory(` (about 7 KB). s.directory is the installed directory, nil before the first install.
    - internal/signer/log_test.go: `func (e *logEnv) open(` (how a test reopens a signer on its store), found with grep (about 1 KB).
    - internal/signer/refusal.go: `func classify(` and `func codeFor(` (about 3 KB).
    - internal/signer/directory_test.go:
      - `func (e *logEnv) refuseInstall(`;
      - the head of `func TestDirectoryInstallRefusals(` and one of its `directory_exceeds_policy` cases;
      - `loginDirectory`, `signDirectory` and `newLoginEnv(t, pk, fx, rp, install)` in internal/signer/login_test.go, found with `grep -n 'func loginDirectory\|func signDirectory\|func newLoginEnv' internal/signer/login_test.go`.

      About 6 KB.
    - internal/server/directory.go: `func installRefusalStatus(` (about 1 KB). Read only; it already answers 403 for every CodeRefused refusal.
  </read_first>
  <action>
Create branch `p03/08h-signer-shares` from origin/main. Place this plan file untracked in the phase directory; Task 4 commits it.

**RED first.** Add `TestDirectoryUnrenderable` to internal/signer/directory_test.go, on newLoginEnv with one admin and quorum 1, as TestDirectoryInstallRefusals does. Each case first calls `e.s.installDirectoryOrRefuse` directly. It asserts:
- that the answer is a refusal whose Message is `directory_unrenderable`;
- that GetDirectory still reports version 1.

Only then does it run `e.refuseInstall` for the leaf and the class. On origin/main the RED therefore shows the install being *accepted*, not a classify failure.

Every case builds valid documents (Validate passes) and uses only symbols that exist on origin/main. The numbers are literals here, with a comment naming the constant they stand for:
- `principals_file_above_cap`: roles mapped to one account of host group lab, whose principals file, sized with the widest header (the file RenderPrincipalsFile writes at version math.MaxUint64), is one byte above 65536. Tune the last principal's length, and record the shape in the SUMMARY.
- `host_group_above_account_share`: host group lab with 2049 accounts (MaxHostGroupAccounts + 1, Q-G3).
- `host_group_at_agent_cap`: host group lab with 4096 accounts. It is within the agent's own cap, but above the share.
- `unsigned_unrenderable_refused_for_quorum`: the first case's document signed by a non-admin key. It is refused `directory_quorum_not_met`, so renderability is never checked before the signatures (T-02-12). It is GREEN at once; record why.
- `at_share_installs`: the control. A host group with exactly 2048 accounts, and a principals file of exactly 65536 bytes sized with the widest header, installs as version 2.
- The non-growth cases (Q-G7) start from an installed version 2 whose host group lab maps 2049 accounts, seeded as an upgrade would find it (below). Their GetDirectory check reads version 2.
  - `above_cap_installed_disable_accepted`: version 3 disables one user and changes no account. It installs as version 3. It is GREEN on origin/main, which checks nothing; record that. Its mutant is nil passed as the installed directory.
  - `above_cap_installed_growth_refused`: version 3 adds one account to lab. It is refused `directory_unrenderable`. RED on origin/main: accepted.

**Seeding an above-cap installed version.** On origin/main a plain install seeds it. Once the check exists, the committed test seeds it through the same store-and-log write that InstallDirectory performs after its checks, and then reopens the signer on that store (as log_test.go's open does), so that loadDirectory loads and verifies it.
- Either the test helper repeats that write, or InstallDirectory's write after its checks moves into an unexported function that the test also calls. Record which in the SUMMARY.
- Neither adds a path reachable from outside the package.
- If a valid seed needs anything else (a production flag, an exported hook, or log state that loadDirectory refuses), stop and report.

Run the test on the unchanged code and record the failing lines in the SUMMARY.

**internal/directory/render.go, `F07 (03-08h)`.**
- Add the exported constants, each with a doc comment saying which agent cap it is and why:
  - `MaxPrincipalsFile = 64 << 10`;
  - `MaxAccounts = 4096`;
  - `MaxHostGroupAccounts = MaxAccounts / 2`. Its comment: an intermediate generation holds the union of two versions' accounts.
- Add `ErrUnrenderable`, with the text `directory: host agents cannot render it`.
- Move the two header lines of `(*PrincipalsRenderer).File` into an unexported `principalsHeader(hostGroup, account string, version uint64, sha string) string`. File writes through it, so RenderPrincipalsFile, PrincipalsRenderer and HostPrincipals stay byte for byte the same (TestRenderPrincipalsFile, TestPrincipalsRendererMatchesReference and TestRenderMatchesAuthorize in internal/directory/render_test.go stay green).
- Add an unexported `fileSize(d, sha, hostGroup, account)`. It returns `len(principalsHeader(hostGroup, account, math.MaxUint64, sha))` plus len(p)+1 for every principal of AccountPrincipals: the file's size as RenderPrincipalsFile would write it with the widest version, 20 digits (Q-G7). It never uses d.Version, so the size does not change when the version gains a digit.
- Add `func CheckRenderable(d, installed *Directory) error`:
  - A nil d is ErrNoDirectory. A nil installed means no directory is installed yet.
  - It computes `trust.SHA256Hex` of d.Canonical() once, and of installed's only if a group or file needs the exception.
  - **Accounts (Q-G3, Q-G7).** For each host group in order, more than MaxHostGroupAccounts accounts is accepted only when installed has a host group of that name and every one of the group's accounts is in it, a subset, not a count comparison. Otherwise it is an error wrapping ErrUnrenderable that names the group and the count.
  - **Files (Q-G3, Q-G7).** For each account, a fileSize above MaxPrincipalsFile is accepted only when installed's fileSize for the same host group and account is at least as large. Otherwise it is an error wrapping ErrUnrenderable that names the group, the account and the size.
  - **The installed counterpart is looked up first.** The exception path first checks that installed has a host group of that name, and for files an account of that name in it. A missing group or account means no exception, so the result is the ErrUnrenderable error above. It is never an AccountPrincipals error such as ErrUnknownHostGroup from the installed side.
  - An AccountPrincipals error for d itself is returned wrapped.
- Its doc comment says four things:
  - it runs only when a directory is offered for install, never on stored state;
  - its bounds are the host agent's generation caps, with files sized at the widest header, so they hold at every later version;
  - an intermediate file is a subset of the target's lines under a header that is not longer;
  - the non-growth exception: nothing grows beyond the installed version, so hosts at that version keep rendering, and hosts further behind rely on the KRL-alone pass (03-08d).

**internal/agent/apply/swap.go.** In the generation-cap const block:
- `maxPrincipalsFile = directory.MaxPrincipalsFile`;
- `maxAccounts = directory.MaxAccounts`;
- maxCAFile stays.

Add a comment that the signer refuses at install what would break these (`F07 (03-08h)`). 03-08d's checkCandidate and every TestKRLAlone case keep their meaning, because the values are unchanged.

**internal/signer/directory.go.** In InstallDirectory, right after the CheckPolicy refusal and before the leaf body is built:
- `directory.CheckRenderable(d, s.directory)` → `refusalErr(wire.CodeRefused, "directory_unrenderable", err)`. s.directory is the installed directory, held under s.mu, and nil before the first install.
- Extend the doc comment's list of checks.
- Do not touch loadDirectory, Parse or Validate.

**internal/signer/refusal.go.** In classify, add `"directory_unrenderable"` to the unauthorized group, next to `"directory_exceeds_policy"`.

**internal/agent/apply/renderable_test.go (new), `TestRenderable`, the agreement test.** It builds directory.Directory values directly and generations from directory.RenderPrincipalsFile output, as Render does through directory.PrincipalsRenderer (byte for byte RenderPrincipalsFile): PrincipalsDir + "/" + account for each account of the host group. The cases:
- `at_share_fits_target_and_intermediate`:
  - two directories, each with one host group of MaxHostGroupAccounts accounts, and disjoint account names;
  - CheckRenderable accepts both;
  - checkLimits accepts each generation, and also `Intermediate(g1, g2)`, which holds MaxAccounts principals files.
- `file_at_cap_accepted`: one account's file of exactly MaxPrincipalsFile bytes at the widest header. CheckRenderable accepts it, and checkLimits accepts the generation rendered at version math.MaxUint64, where the file is exactly 64 KiB.
- `file_one_byte_above_cap_refused`: the same, one principal byte longer. CheckRenderable refuses with ErrUnrenderable, and checkLimits refuses the generation rendered at version math.MaxUint64 with ErrGenerationTooLarge.
- `stricter_than_agent_by_header_width_only`: the file of `file_one_byte_above_cap_refused`, rendered at version 1. checkLimits accepts it, because its real size is 19 bytes smaller. CheckRenderable refuses it. This pins the cost of the widest header: at most 19 bytes.
- `accounts_above_share_refused`: MaxHostGroupAccounts + 1 accounts. CheckRenderable refuses.
- `intermediate_header_not_longer`: len(intermediateHeader) is at most the length of the shortest header principalsHeader can produce (a one-character group and account, version 1). Compute it through a RenderPrincipalsFile of an account with no principals.
- `check_renderable_is_fast_enough`: two timed shapes, each asserted under 2 s under -race, well inside signerCallTimeout. Record both measured times. This bounds the work done under s.mu. It does not call t.Parallel(), so its wall-clock assert does not share the CPU with the package's parallel tests.
  - The normal path: a directory at the share, each account at about 60 KiB, against an installed directory of the same shape.
  - The exception path: an offered and an installed directory, each with one host group of MaxAccounts (4096) accounts at about 60 KiB per file, so that every group and file is sized in both versions. AccountPrincipals scans the group's accounts per call, so this is the worst case.
  - A time above 2 s is a deviation to stop on and report, never a reason to loosen the bound.

The cases above pass nil as installed, except where stated. The non-growth cases (Q-G7) use an installed directory whose host group lab maps 3000 accounts (above the share, within the agent's 4096):
- `under_cap_rule_unchanged_with_installed`: with an installed directory under the cap, `accounts_above_share_refused` and `file_one_byte_above_cap_refused` give the same answers as with nil.
- `above_cap_disable_accepted`: the offered version disables one user, with the same 3000 accounts. CheckRenderable accepts it, and checkLimits accepts `Intermediate(g_installed, g_offered)`.
- `above_cap_remove_accepted`: the offered version maps 2999 of the 3000 accounts. Accepted, and the intermediate fits.
- `above_cap_growth_refused`: 3001 accounts, the 3000 plus one. Refused.
- `above_cap_swap_refused`: 3000 accounts with one name swapped for a new one. Refused, although the count did not grow.
- `new_group_above_share_refused`: the offered version keeps lab as installed and adds host group web with MaxHostGroupAccounts + 1 accounts. Refused, naming web.
- `new_group_file_above_bound_refused`: the offered version adds host group web with two accounts, one of whose files is above the bound. The installed directory has no web. The error satisfies `errors.Is(err, directory.ErrUnrenderable)`, names web and the account, and does not wrap ErrUnknownHostGroup.
- `above_cap_file_not_grown_accepted`: an installed account file of about 70 KiB; the offered version leaves that file's lines unchanged (it disables another user). Accepted.
- `above_cap_file_grown_refused`: the same file with one more principal. Refused.
- `rendered_file_above_cap_refused`: an installed file at exactly the bound (widest header), offered one principal byte longer. Refused: the file rendered, so it may not grow past the bound.
- The version-digit cases (Q-G7), at 9 → 10 and 99 → 100. The installed directory is at version 9 (or 99), with one account file of exactly MaxPrincipalsFile bytes as RenderPrincipalsFile writes it at that version: a file at the agent's cap, from before this release. The offered version 10 (or 100) disables another user, so that file's lines are unchanged.
  - `rollover_9_to_10_file_at_cap_accepted`: CheckRenderable accepts. At the widest header the file did not grow.
  - `rollover_99_to_100_file_at_cap_accepted`: the same at 99 → 100.
  - Under the mutant that sizes with the real version, both are refused: the file is one byte longer at the new version.
  - `rollover_file_within_bound_stays_within_cap`: the control. An installed file at the widest-header bound, at version 9, unchanged at version 10. CheckRenderable accepts it, and checkLimits accepts the version-10 generation: a file accepted within the bound stays within 64 KiB.

Then make TestDirectoryUnrenderable use the constants instead of the literals, with unchanged assertions.

**E-1 and E-2 (owner decision (2026-11-04), execution stop at Task 1).**
- internal/directory/render.go: CheckRenderable sizes through an unexported sizer (roles by name and principals by number, indexed once; each account's roles walked once, deduplicated by a per-account stamp, no sort), the header still from principalsHeader at math.MaxUint64. Then checkMoves refuses a host moved, by a shared host key between active entries, to another host group when the union of the two groups' accounts is above MaxAccounts or a file of the new group is above MaxPrincipalsFile.
- internal/directory/render_size_test.go (new), `TestSizerMatchesRender`: eight varied directories (overlapping principals of 1 to 128 characters, accounts with no roles, one role, twin roles with the same principals, all roles, random role lists with repeats, group and account names of different lengths); every account's sizer size equals the header at the widest version plus AccountPrincipals one per line, and len(RenderPrincipalsFile) at math.MaxUint64.
- `check_renderable_is_fast_enough` times three shapes, each under 2 s under -race: the normal path (2048 accounts), the literal exception shape (4096 × ~60 KiB in both versions) and the all-files-above-bound shape (4096 files each above the bound and unchanged).
- TestRenderable gains `host_moved_union_above_cap_refused` (3000 + 1097 accounts; the agent's Intermediate refuses it too), `host_moved_union_at_cap_accepted` (3000 + 1096; the agent's move fits) and `host_moved_to_file_above_bound_refused` (a file accepted for the new group's own hosts under Q-G7, but not for a host moving into it).
- TestDirectoryUnrenderable gains `host_moved_above_agent_cap_refused`, `host_moved_union_fits_installs` and `host_moved_within_share_installs`, on a seeded version 2 with h1 in lab (3000 accounts), web (2048) and db (1096).
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestDirectoryUnrenderable|TestDirectoryInstallRefusals|TestDirectoryOverSocket" ./internal/signer/ && go test -race -count=1 -v -run "TestRenderable|TestKRLAlone" ./internal/agent/apply/ && go test -race -count=1 ./internal/directory/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestDirectoryUnrenderable/principals_file_above_cap", "--- PASS: TestDirectoryUnrenderable/host_group_above_account_share", "--- PASS: TestDirectoryUnrenderable/host_group_at_agent_cap", "--- PASS: TestDirectoryUnrenderable/unsigned_unrenderable_refused_for_quorum", "--- PASS: TestDirectoryUnrenderable/at_share_installs", "--- PASS: TestDirectoryUnrenderable/above_cap_installed_disable_accepted", "--- PASS: TestDirectoryUnrenderable/above_cap_installed_growth_refused", "--- PASS: TestDirectoryUnrenderable/host_moved_above_agent_cap_refused", "--- PASS: TestDirectoryUnrenderable/host_moved_union_fits_installs", "--- PASS: TestDirectoryUnrenderable/host_moved_within_share_installs", "--- PASS: TestRenderable/at_share_fits_target_and_intermediate", "--- PASS: TestRenderable/file_at_cap_accepted", "--- PASS: TestRenderable/file_one_byte_above_cap_refused", "--- PASS: TestRenderable/accounts_above_share_refused", "--- PASS: TestRenderable/intermediate_header_not_longer", "--- PASS: TestRenderable/check_renderable_is_fast_enough", "--- PASS: TestRenderable/under_cap_rule_unchanged_with_installed", "--- PASS: TestRenderable/above_cap_disable_accepted", "--- PASS: TestRenderable/above_cap_remove_accepted", "--- PASS: TestRenderable/above_cap_growth_refused", "--- PASS: TestRenderable/above_cap_swap_refused", "--- PASS: TestRenderable/new_group_above_share_refused", "--- PASS: TestRenderable/above_cap_file_not_grown_accepted", "--- PASS: TestRenderable/above_cap_file_grown_refused", "--- PASS: TestRenderable/rendered_file_above_cap_refused", "--- PASS: TestRenderable/new_group_file_above_bound_refused", "--- PASS: TestRenderable/stricter_than_agent_by_header_width_only", "--- PASS: TestRenderable/rollover_9_to_10_file_at_cap_accepted", "--- PASS: TestRenderable/rollover_99_to_100_file_at_cap_accepted", "--- PASS: TestRenderable/rollover_file_within_bound_stays_within_cap", "--- PASS: TestRenderable/host_moved_union_above_cap_refused", "--- PASS: TestRenderable/host_moved_union_at_cap_accepted", "--- PASS: TestRenderable/host_moved_to_file_above_bound_refused" (the host_moved lines: owner decision (2026-11-04), execution stop at Task 1)</fails_when>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./internal/agent/apply/' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 400) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit: internal/agent/apply took more than 400 s alone, or no single ok line</fails_when>
    <automated>bash scripts/linux.sh 'go list -deps ./cmd/keyroster-signer | grep -c "keyroster/internal/agent" ; bash scripts/dep-firewall.sh'</automated>
    <fails_when>the first number printed is not 0, or dep-firewall exits non-zero</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/agent/apply/swap.go | grep -cE 'maxPrincipalsFile += directory\.MaxPrincipalsFile|maxAccounts += directory\.MaxAccounts'` prints 2.
    - `grep -v '^[[:space:]]*//' internal/signer/directory.go | grep -c 'directory.CheckRenderable(d, s.directory)'` prints 1, and the call's line number is above the line holding `tlog.DirectoryInstallBody{` and below the line holding `refusalErr(wire.CodeRefused, "directory_exceeds_policy"` (directory.go:141 on main).
    - `awk '/^func \(s \*Signer\) loadDirectory\(/,/^}/' internal/signer/directory.go | grep -c 'CheckRenderable'` prints 0, and `awk '/^func Parse\(/,/^}/;/^func \(d \*Directory\) Validate\(/,/^}/' internal/directory/directory.go | grep -c 'CheckRenderable'` prints 0: neither Parse, Validate nor loadDirectory calls it.
    - The SUMMARY records:
      - the RED output of the four refusal cases on origin/main's code, showing the install accepted;
      - why `unsigned_unrenderable_refused_for_quorum` and `above_cap_installed_disable_accepted` are GREEN at once;
      - how the above-cap installed version is seeded.
    - The SUMMARY lists these mutants, each applied, run against its named test, and restored byte for byte:
      - the CheckRenderable call removed (killed by `principals_file_above_cap`);
      - the account bound compared with MaxAccounts instead of MaxHostGroupAccounts (killed by `host_group_above_account_share`);
      - `<=` turned into `<` in the size check (killed by `file_at_cap_accepted` or `at_share_installs`);
      - apply's maxPrincipalsFile set to a literal one byte smaller (killed by `file_at_cap_accepted`);
      - the call moved before VerifySignatures (killed by `unsigned_unrenderable_refused_for_quorum`);
      - the classify entry removed (killed by refuseInstall's class check in every refusal case);
      - a count comparison instead of the subset (killed by `above_cap_swap_refused`);
      - growth by one account allowed (killed by `above_cap_growth_refused`);
      - the exception applied to a host group with no installed counterpart (killed by `new_group_above_share_refused`);
      - any file accepted on the exception path, without the size comparison (killed by `above_cap_file_grown_refused`);
      - nil passed as the installed directory in InstallDirectory (killed by `above_cap_installed_disable_accepted`);
      - fileSize using the real version instead of the widest (killed by `rollover_9_to_10_file_at_cap_accepted` and `rollover_99_to_100_file_at_cap_accepted`);
      - the installed counterpart not looked up first, so a missing installed group surfaces as an AccountPrincipals error (killed by `new_group_file_above_bound_refused`);
      - E-1: deduplication broken in the sizer (killed by TestSizerMatchesRender);
      - E-2: the moved-host check skipped (killed by `host_moved_above_agent_cap_refused` and `host_moved_union_above_cap_refused`);
      - E-2: the moved-host file check skipped (killed by `host_moved_to_file_above_bound_refused`).
    - `grep -v '^[[:space:]]*//' internal/directory/render.go | grep -c 'math.MaxUint64'` prints at least 1: fileSize sizes at the widest version.
  </acceptance_criteria>
  <done>The signer refuses at install every directory the agent's own caps would refuse, its intermediate included, with directory_unrenderable on the install bucket, unless nothing grows beyond an above-cap installed version, so disabling and removing always go through. The two packages share one set of constants.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: F16, per-account connection shares in the signer's accept loop, each slot released before its connection closes, with the uid named in a rate-limited operator log line</name>
  <files>internal/wire/frame.go, internal/signer/server.go, internal/signer/signer.go, internal/signer/refusal.go, internal/signer/overload_test.go</files>
  <behavior>
    All tests are in overload_test.go (package signer, Linux-tagged), on newLogEnv. A test that needs an answer over the socket sets `e.s.allowUIDs` to the test's own uid before Serve, and a test that reads the operator log sets `e.s.log` to a capturing logger before Serve. These are field writes in an internal test before serving, not a production seam.
    - `TestConnSlots`, unit tests of the accounting type:
      - `share_per_uid`: uid A takes maxConnsPerPeer slots; its next take is refused with `uid_share_exceeded`; a take for uid B succeeds.
      - `global_cap`: two uids at their share fill maxConns; a third uid's take is refused with `too_many_connections`.
      - `put_frees_and_deletes`: after A puts back every slot, A can take again, and the per-uid map holds no key for A.
      - `unknown_peer_own_key`: tlog.PeerUnknown counts under its own key, like any uid.
      - `arithmetic`:
        - maxConnsPerPeer equals wire.MaxPeerConns;
        - maxConns is at least 2 × maxConnsPerPeer;
        - the server's ceiling, wire.MaxServerSignerCalls + 1 (its budget plus the one GetKRL outside it, Q-G5), is 13, and it is at most maxConnsPerPeer − 3 and at most maxConns − maxConnsPerPeer − 3: 3 slots of margin within the share, and when another account holds its whole share.
    - `TestPeerShare`, through the real accept loop (Listen and Serve, as TestOverloadDoesNotStallAccept does):
      - `own_share_full_next_closed`:
        - With s.mu held, dial maxConnsPerPeer idle connections as the test's uid.
        - The next one is closed at once (EOF within 3 s), although maxConns − maxConnsPerPeer slots are free.
        - After Serve ends, the refusal summaries count 1 overloaded connection.
        - RED on origin/main: the read times out instead of returning EOF.
      - `other_account_share_full_status_answered`:
        - Pre-fill the accounting with maxConnsPerPeer takes for a foreign uid (the test's uid + 1).
        - Dial maxConnsPerPeer − 1 idle connections as the test's uid.
        - A `signerclient.Status` from the test's uid is answered. This is its 16th slot, and the global 32nd.
        - It is a new seam with no RED on origin/main; record that. Its mutant is the per-uid count shared across uids.
      - `operator_log_names_uid_rate_limited`:
        - Fill the test uid's share with idle connections, then dial 40 more.
        - Each of the 40 is closed at once.
        - The captured log holds at least 1 and at most DefaultRefusalLogBurst + 1 `refused` lines with reason `uid_share_exceeded`, each naming the test's uid.
        - The refusal summaries count 40 overloaded connections.
      - `slot_released_before_close`, the signer half of the release ordering:
        1. Dial one connection as the test's uid. Poll `e.s.conns` under its mutex until the uid's count is 1, then keep holding the mutex.
        2. Write a Status request frame and read the whole response frame (wire.ReadMessage).
        3. With the mutex still held, read once more with a 200 ms deadline. The read must time out, not return EOF: the handler's slot release waits for the mutex, and the close follows the release.
        4. Unlock. A read with a 3 s deadline returns io.EOF, and the uid's count is 0.

        It is a new seam with no RED on origin/main; record that. Its mutant, the close before the release, sees EOF in step 3, so it is killed deterministically, not by timing.
    - `TestOverloadDoesNotStallAccept` keeps its name and meaning, with a new setup. Today it dials maxConns idle connections as one uid; under the share the 17th would already be refused, and the count would be 19, not 3.
      - Pre-fill a foreign uid's share with maxConnsPerPeer takes.
      - With s.mu held, dial maxConnsPerPeer as the test's uid to fill the global cap.
      - The 3 extra connections are closed at once, and the summaries count 3.
      - Record the moved setup in the SUMMARY.
  </behavior>
  <read_first>
    Read functions, not files; find each with `grep -n`.
    - internal/signer/server.go: the `connDeadline` and `maxConns` consts, `func (s *Signer) Serve(` and the head of `func (s *Signer) handle(` up to `wire.ReadMessage` (about 5 KB). `grep -n 's.handle(' internal/signer/*.go` shows Serve's goroutine as its only caller.
    - internal/signer/signer.go: the Signer fields from `mu sync.Mutex` to `clockEpisode`, the limiter lines of `func New(`, and `func (s *Signer) allowed(` (about 3 KB). allowed takes no lock.
    - internal/signer/refusal.go: `type refusalLimiter`, `func (l *refusalLimiter) allow(`, `func (s *Signer) refuseLogging(` and the head of `func (s *Signer) flushSummaries(` (about 4 KB).
    - internal/signer/peercred_linux.go: `func peerCredentials(` (about 1 KB). It takes no lock and makes no blocking call.
    - internal/signer/overload_test.go: the whole file (about 2 KB).
    - internal/signer/log_test.go: `type logEnv`, `func newLogEnv(`, `func (e *logEnv) open(` and `leavesOf` (about 2 KB).
    - internal/wire/frame.go: the const block from `MaxFrame` to `Version` (about 1 KB).
  </read_first>
  <action>
Write the tests in `<behavior>` first.
- `own_share_full_next_closed` and the rewritten TestOverloadDoesNotStallAccept use only maxConns and literals during RED.
- Run them on the unchanged code. Record the RED of the first, and why the second needs its new setup only once the share exists.
- TestConnSlots and the other TestPeerShare cases need the new type. Write them right after its declaration, before Serve uses it.

**internal/wire/frame.go.** Add two constants, each with a doc comment:
- `MaxPeerConns = 16`, `F16 (03-08h)`: the most connections one account (uid) may hold on the signer socket at once, half of the signer's 32, so after one account holds its share the other half stays free.
- `MaxServerSignerCalls = MaxPeerConns - 4`, `F16 (03-08h)`: the most signer calls keyroster-server has in flight (03-08g's budget). The signer frees a slot before it closes the connection, and socketSigner's calls return only after the close, so the server never holds more live connections than calls. With its one GetKRL outside the budget (Q-G5), that is at most MaxServerSignerCalls + 1 = 13, and the 3 left are margin for other callers under its uid and for calls it abandoned while the signer was stalled.

**internal/signer/server.go, `F16 (03-08h)`.**
- Add `const maxConnsPerPeer = wire.MaxPeerConns`. Its doc comment says three things:
  - the share bounds how much of the pool one account takes;
  - keyroster-server keeps its own calls 3 below it: wire.MaxServerSignerCalls plus its one GetKRL;
  - two accounts at their share together can still hold every slot (Q-G2: no reserved slot).
- Extend maxConns's comment: per-uid shares within it.
- Add `type connSlots struct`:
  - its own sync.Mutex, with total and perUID map[uint32]int;
  - `take(uid uint32) (ok bool, detail string)`, which refuses `too_many_connections` at maxConns and `uid_share_exceeded` at maxConnsPerPeer for that uid;
  - `put(uid uint32)`, which deletes the key at zero.
  - Its mutex is never held with s.mu or across I/O, so the accept loop never waits for an issuance.
- Serve makes its own `acceptLimiter := newRefusalLimiter(s.refusalPerMinute, s.refusalBurst, s.clock())` before the loop. It is a local variable that only the accept loop's goroutine ever touches, so it needs no lock, even if a test serves two listeners on one Signer.
- Serve, after each AcceptUnix:
  - Read `peerCredentials(conn)` there. On error, the uid for accounting is tlog.PeerUnknown.
  - Then `s.conns.take(uid)`.
  - On refusal:
    - close the connection and add 1 to s.overloaded;
    - when `acceptLimiter.allow(s.clock())`, log Warn `refused` with the uid, the pid (0 when unknown), the detail, and the overloaded class and code, as today's line has;
    - nothing is sent, and the loop continues.
  - Otherwise start the goroutine with three deferred calls in this order: `wg.Done()`, then `conn.Close()`, then `s.conns.put(uid)`. They run in reverse, so the slot is released, then the connection closed, on every path out of handle (Q-G1's release ordering). It then calls `s.handle(ctx, conn, peer, credErr)`.
- handle takes the peer and the credentials error instead of reading them, and no longer closes the connection:
  - a non-nil credErr is refused `peer_credentials_unavailable` as today;
  - a peer that is not allowed is refused `peer_not_allowed` as today.

  Both refusals go through s.refuse in the connection's goroutine, so their uids still reach the audit log. The deadline is still set first.
- Update the doc comments of Serve and handle, including the release order and why: the server's next call may dial the moment it sees the close.

**internal/signer/signer.go.**
- Add the field `conns *connSlots`, made in New.
- Add `refusalPerMinute` and `refusalBurst`, the rate and burst New already computes for limiter and installLimiter. They are set once in New and only read afterwards. Serve builds its acceptLimiter from them. Their comment: that limiter is never under mu, and what it does not log is still counted in overloaded.
- Update the comment on overloaded: connections refused over the global cap or over their account's share.

**internal/signer/refusal.go.** In refusalLimiter's comment, name the one exception to "Guarded by Signer.mu": Serve's acceptLimiter, a local variable of the accept loop.

Run the whole signer package. Every existing refusal, socket, KRL-loop and log test must keep its meaning, including the peer_not_allowed tests in refusal_test.go. Record any assertion that moved, and why.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestConnSlots|TestPeerShare|TestOverloadDoesNotStallAccept" ./internal/signer/ && go test -race -count=1 ./internal/signer/ ./internal/wire/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestConnSlots/share_per_uid", "--- PASS: TestConnSlots/global_cap", "--- PASS: TestConnSlots/put_frees_and_deletes", "--- PASS: TestConnSlots/unknown_peer_own_key", "--- PASS: TestConnSlots/arithmetic", "--- PASS: TestPeerShare/own_share_full_next_closed", "--- PASS: TestPeerShare/other_account_share_full_status_answered", "--- PASS: TestPeerShare/operator_log_names_uid_rate_limited", "--- PASS: TestPeerShare/slot_released_before_close", "--- PASS: TestOverloadDoesNotStallAccept"</fails_when>
    <automated>bash scripts/linux.sh 'go list -deps ./cmd/keyroster-signer | grep -c "keyroster/internal/agent" ; bash scripts/dep-firewall.sh'</automated>
    <fails_when>the first number printed is not 0, or dep-firewall exits non-zero</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/signer/server.go | grep -c 'peerCredentials('` prints 1: only Serve reads the credentials.
    - `grep -v '^[[:space:]]*//' internal/signer/server.go | grep -c 'maxConnsPerPeer *= *wire.MaxPeerConns'` prints 1.
    - `grep -v '^[[:space:]]*//' internal/signer/server.go | grep -c 's.handle('` prints 1, and `awk '/^func \(s \*Signer\) handle\(/,/^}/' internal/signer/server.go | grep -c 'conn.Close()'` prints 0: handle no longer closes the connection.
    - The SUMMARY records the RED of `own_share_full_next_closed`, and why `other_account_share_full_status_answered` and `slot_released_before_close` are new seams.
    - The SUMMARY lists these mutants, each applied, run against its named test, and restored byte for byte:
      - the share check removed (killed by `own_share_full_next_closed`);
      - one counter for all uids instead of per uid (killed by `other_account_share_full_status_answered`);
      - put skipped (killed by `put_frees_and_deletes`);
      - the over-capacity log line written through s.refuse (killed by `own_share_full_next_closed`, since s.mu is held);
      - the acceptLimiter check removed, so every refusal is logged (killed by `operator_log_names_uid_rate_limited`);
      - the uid logged as tlog.PeerUnknown (killed by `operator_log_names_uid_rate_limited`);
      - the close before the release, with handle keeping its own deferred Close or the goroutine's two defers swapped (killed by `slot_released_before_close`).
  </acceptance_criteria>
  <done>No account holds more than 16 of the signer's 32 connections, every slot is released before its connection closes, and a refused connection's uid reaches the operator log at a bounded rate.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: The client half of the release ordering — signerclient.Client with AwaitClose, used only by socketSigner, the server's total taken from the share, and its real-socket pins</name>
  <files>internal/signerclient/client.go, internal/signerclient/client_test.go, internal/server/signer.go, internal/server/capacity_test.go, internal/signer/overload_test.go</files>
  <behavior>
    - `TestAwaitClose` in client_test.go. Its test signer is like startSlowSigner, except that after writing its frame it holds the connection open until the test releases it.
      - `returns_after_close`: `Client{Socket: s, AwaitClose: true}.LoginSend` has not returned 150 ms after the frame was written. Once the test signer closes, it returns the certificate (Serial 7).
      - `package_function_unchanged`: `signerclient.LoginSend`, the CLI's path, returns the certificate while the connection is still held open.
      - `refusal_awaits_close`: an ErrorResponse frame, then the held close. The `*wire.ErrorResponse` comes back only after the close.
      - `deadline_ends_wait`: the test signer answers and never closes. With a read timeout of 300 ms, the call returns the certificate, not an error, after about 300 ms.
      - `trailing_bytes_ignored`: the frame plus a few more bytes, then the close. The call returns the certificate.
      - TestLoginSendReadDeadline and TestReadResponseRefusesUnexpectedType stay green.
    - `TestSocketSignerAwaitsClose` in internal/server/capacity_test.go. A Unix-socket test signer, made as TestSocketSignerLoginReadsPastSendDeadline makes one, answers a Login and holds the connection open. `socketSigner{socket: s}.Login` has not returned 150 ms after the answer; once the test signer closes, it returns the certificate. TestSocketSignerLoginReadsPastSendDeadline stays green: its test signer closes right after answering.
    - In `TestPeerShare` (overload_test.go), both cases call through `signerclient.Client{Socket: path, AwaitClose: true}.Status`, the path socketSigner uses; a test of the package function would prove nothing about the ordering.
      - `server_budget_within_share`:
        - The server's real maximum: wire.MaxServerSignerCalls goroutines as the test's uid each make Status calls, one after another, for 2 s, and one more goroutine makes GetKRL calls the same way (Q-G5).
        - Every call succeeds, and the refusal summaries count no overloaded connection.
        - It is repeated 10 times in verify.
      - `share_exact_never_refused`: the same, with wire.MaxPeerConns goroutines. With the release ordering each goroutine has at most one connection counted at any time, so the share is never exceeded. This replaces the pre-split draft's "slack-removed run".
      - The comparison run on Task 2's head cannot use these cases, because signerclient.Client does not exist there yet. So the executor runs a temporary, uncommitted copy of both cases that calls the package-level `signerclient.Status`, which does not wait for the close. It records each refusal count and then deletes the copy. Zero there is possible and is recorded as such; the deterministic proofs are `slot_released_before_close`, TestAwaitClose and TestSocketSignerAwaitsClose.
      - **Stop rule.** A refusal in either case, in any of the ten repeated runs or in CI, is a deviation to stop on and report. Under the release ordering it is not an expected possibility: it means the ordering is broken somewhere. It is never a reason to loosen the test, add retries or skip it.
  </behavior>
  <read_first>
    - internal/signerclient/client.go: the whole file (about 8 KB). Every function becomes a Client method.
    - internal/signerclient/client_test.go: `func startSlowSigner(` with `type slowSigner` and `countReader`, and `func TestLoginSendReadDeadline(` (about 4 KB).
    - internal/server/signer.go: `type socketSigner` with its methods, `maxSignerCalls`, and the signerAPI growth-rule comment as 03-08g left it (about 4 KB).
    - internal/server/signer_test.go: `func TestSocketSignerLoginReadsPastSendDeadline(` (about 2 KB).
    - `grep -rn 'signerclient: receive' --include=*.go .` (no caller may match the receive error's text; server_test.go's errLostAnswer is a test double's own error, not a match on signerclient's text), and `grep -rn 'signerclient\.' cmd/` (the CLI's and the start-up's calls, which must stay unchanged).
  </read_first>
  <action>
Write the tests in `<behavior>` first.
- To make TestAwaitClose compile, first add `type Client struct{ Socket string; AwaitClose bool }` with a LoginSend method that ignores AwaitClose. `returns_after_close` and `refusal_awaits_close` are then RED.
- TestSocketSignerAwaitsClose is RED on Task 2's head.
- Record each RED, and the two real-socket runs on Task 2's head (through the temporary copy described in `<behavior>`, deleted afterwards), in the SUMMARY.

**internal/signerclient/client.go, `F16 (03-08h)`.**
- `type Client struct { Socket string; AwaitClose bool }`. Its doc comment: AwaitClose makes every call read on after its response frame until the signer closes the connection, bounded by the call's deadline. keyroster-server sets it so that a call returns only after the signer has freed the connection's slot, which the signer does before it closes. The CLI does not set it.
- Every package function (Issue, Login, LoginSend, InstallDirectory, GetDirectory, Status, Revoke, ForgetAgent, GetKRL, GetBundle, GetDirectoryVersion) becomes a Client method with the same body. Each package function becomes a one-line wrapper, `return Client{Socket: socket}.X(...)`, so every caller in cmd/ is unchanged and behaves as today.
- roundTripRead becomes a Client method. Whenever wire.ReadMessage returned a whole frame, whatever the frame said, and AwaitClose is set, it reads and discards from the connection until EOF, the deadline already set on it, or 64 KiB. Then it returns exactly what it would have returned without the wait. When no whole frame arrived, it returns at once, as today.
- readResponse's receive error names both causes: the signer closes connections unanswered from peers that are not on its allowlist, and from accounts over its connection limits. The error is still wrapped, and no caller matches its text.

**internal/server/signer.go.**
- socketSigner keeps `socket string`, and gains `func (s socketSigner) client() signerclient.Client` returning `signerclient.Client{Socket: s.socket, AwaitClose: true}`. Every method calls through it, for example `s.client().Status(ctx)` and `s.client().LoginSend(ctx, req, signerCallTimeout)`.
- socketSigner's doc comment says why: budgetSigner frees a token when the method returns, and the signer frees the slot before it closes, so the server's counted connections never exceed its tokens. Its growth rule: a later method calls its signerclient Client method through s.client().
- `maxSignerCalls = wire.MaxServerSignerCalls`. Its comment says why it is 4 below the signer's share: with the one GetKRL outside the budget the server's ceiling is 13, and the 3 left are margin, not a timing allowance.

**internal/server/capacity_test.go** gains TestSocketSignerAwaitsClose; **internal/signer/overload_test.go** gains the two TestPeerShare cases.

Run the signerclient, server and signer packages and cmd/. Every existing test must keep its meaning; record any assertion that moved, and why.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -v -run "TestAwaitClose|TestLoginSendReadDeadline|TestReadResponseRefusesUnexpectedType" ./internal/signerclient/ && go test -race -count=1 -v -run "TestSocketSignerAwaitsClose|TestSocketSignerLoginReadsPastSendDeadline" ./internal/server/ && go test -race -count=1 -v -run "TestPeerShare" ./internal/signer/ && go test -race -count=1 ./internal/signerclient/ ./internal/server/ ./internal/signer/ ./cmd/... && go test -race -count=10 -run "TestPeerShare/(server_budget_within_share|share_exact_never_refused)" ./internal/signer/'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestAwaitClose/returns_after_close", "--- PASS: TestAwaitClose/package_function_unchanged", "--- PASS: TestAwaitClose/refusal_awaits_close", "--- PASS: TestAwaitClose/deadline_ends_wait", "--- PASS: TestAwaitClose/trailing_bytes_ignored", "--- PASS: TestLoginSendReadDeadline", "--- PASS: TestSocketSignerAwaitsClose", "--- PASS: TestSocketSignerLoginReadsPastSendDeadline", "--- PASS: TestPeerShare/server_budget_within_share", "--- PASS: TestPeerShare/share_exact_never_refused", "--- PASS: TestPeerShare/slot_released_before_close"</fails_when>
  </verify>
  <acceptance_criteria>
    - `grep -v '^[[:space:]]*//' internal/server/signer.go | grep -c 'AwaitClose: true'` prints 1, and `grep -v '^[[:space:]]*//' internal/server/signer.go | grep -cE 'signerclient\.(Issue|Login|LoginSend|InstallDirectory|GetDirectory|Status|Revoke|ForgetAgent|GetKRL|GetBundle|GetDirectoryVersion)\('` prints 0: socketSigner never calls a package function.
    - `grep -v '^[[:space:]]*//' internal/server/signer.go | grep -c 'maxSignerCalls *= *wire.MaxServerSignerCalls'` prints 1, and `grep -cE 'maxSignerCalls *= *[0-9]' internal/server/signer.go` prints 0: no literal total is left.
    - `test -z "$(git diff --name-only origin/main...HEAD -- cmd/)"`: the CLI and the server's start-up are unchanged.
    - The SUMMARY records the REDs, and the two real-socket runs on Task 2's head with their refusal counts.
    - The SUMMARY lists these mutants, each applied, run against its named test, and restored byte for byte:
      - AwaitClose ignored (killed by `returns_after_close`);
      - the wait skipped after a refusal frame (killed by `refusal_awaits_close`);
      - a deadline during the wait turned into an error (killed by `deadline_ends_wait`);
      - the package functions waiting too (killed by `package_function_unchanged`);
      - socketSigner built without AwaitClose (killed by TestSocketSignerAwaitsClose).
  </acceptance_criteria>
  <done>keyroster-server's calls return only after the signer has freed their slots, so its 12 budgeted calls and its one GetKRL never exceed its share of 16, and the CLI's calls are unchanged.</done>
</task>

<task type="auto">
  <name>Task 4: The runbook notes, the publish edits, the e2e check, the gates, the PR and the SUMMARY</name>
  <files>docs/runbooks/enroll-user.md, docs/runbooks/signer-install.md, .planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - docs/runbooks/enroll-user.md: the section `## After "the server cannot reach its signer": look before you retry` and the head of `## Disabling a user` (about 2 KB).
    - docs/runbooks/signer-install.md: `## 8. Add admins` (about 1 KB).
    - .planning/ROADMAP.md: Phase 3's Plans line and its wave blocks (`grep -n 'Wave\|Plans:'`).
    - .planning/STATE.md: the frontmatter and the `Plan:` line.
    - 03-09-PLAN.md: its frontmatter, Task 1's precondition, and the sentence 03-08g added (`grep -n "03-08g's agent-share rule"`).
    - 03-10-PLAN.md: the sentence 03-08g added (same grep).
    - The `wave:` lines of 03-10 to 03-16 (`grep -n '^wave:\|^depends_on:'`).
  </read_first>
  <action>
**Runbook notes (CONTEXT D-20).** Each note is labelled "run in CI (the named tests, 03-08h); UNVERIFIED on a real host", per the Homelab owner decision. None names a finding or describes how to provoke a limit.
1. **enroll-user.md**, a new section after `After "the server cannot reach its signer"`: `## A directory hosts cannot render is refused at install`.
   - Every command that installs a directory version can be refused with `directory_unrenderable`, and the CLI's error names that code. That is `keyroster directory install`, `user approve`, and the other user, role, host and machine commands that sign a new version. This happens when:
     - a host group maps more than 2048 accounts. While a host moves between two versions it holds both versions' accounts, so the limit is half of the agent's 4096 (Q-G3);
     - or one account's principals file, as the host agent writes it, would be larger than 64 KiB.
   - Nothing is installed, and the directory keeps its version. Split the host group, or map fewer roles to the account, then sign again.
   - **A directory installed before this release** whose host group maps more accounts than that, or whose principals file is larger, stays in force, and hosts keep rendering what they rendered (Q-G7).
     - A later version that only disables or removes users, roles or accounts installs as usual. That includes `user disable` and the disable step of `keyroster revoke user`.
     - A version that adds an account to that host group, swaps one of its accounts for a new name, or makes a file that is already too large any larger is refused until the group is split.
   - (That the CLI's error names the code is reasoned from serverclient's error text; no test runs the CLI against this refusal. UNVERIFIED.)
     - A new host group must meet the limits.
   - **The 64 KiB limit is measured as if the version number had its largest possible length**, so a file accepted once stays within the limit at every later version. In practice the limit is up to about 19 bytes below 64 KiB.
   - **When you split, keep the account names.** A host that moves to the split version holds the accounts of both versions for a moment. New, disjoint account names can push that set above the agent's 4096, and the host then refuses the move (`generation_too_large`). Its KRLs still land (host-setup.md, "Revocations keep applying"), but it keeps its old principals.
   - **Moving a host to another host group** (owner decision (2026-11-04), execution stop at Task 1): a version that moves a host into another host group is refused with `directory_unrenderable` when, during the move, the host would hold more than 4096 accounts (both groups' together) or a principals file of the new group above 64 KiB. Split the old host group first. With both groups at most 2048 accounts this never happens.
   - Tests: TestDirectoryUnrenderable, TestRenderable, TestSizerMatchesRender.
2. **signer-install.md**, in `## 8. Add admins`, a paragraph `Connection limits`:
   - The signer handles at most 32 connections at once, and at most 16 from one account (uid). No slot is reserved. keyroster-server keeps its own calls to 12, plus one read of the published KRL, and each of its calls returns only after the signer has freed that connection. So outside a slow signature (below), the server alone never fills its share.
   - A connection over either limit is closed unanswered, and the CLI's receive error names both causes. Retry.
   - The journal shows `refused` with `reason=uid_share_exceeded` or `reason=too_many_connections` and the uid, at most about 10 lines a minute. Every such connection is counted as overloaded in the next `refusal_summary` entry.
   - Two admin accounts together can still fill every slot.
   - Shares are counted per uid. In the shipped layout keyroster-server runs as its own user (deploy/sysusers.d). A deployment that runs it and an admin under one uid gives them a single share of 16 between them.
   - **During a slow signature**, for example while a hardware key waits for a touch, the calls that need the signer's lock wait with it. keyroster-server gives up on such a call at its own timeout, but the connection keeps its slot until the signature is done. When more than 3 of them pile up, the signer can close the server's next calls unanswered, its KRL and catch-up reads included, although it could otherwise answer those at once. Hosts keep the KRL they applied and ask again at their next poll, and distribution resumes once the signature is done. Answer touch prompts promptly.
   - Tests: TestPeerShare, TestOverloadDoesNotStallAccept, TestAwaitClose.

**Publish edits.** Make them in this PR, on top of origin/main, which holds 03-08d to 03-08g, 03-08j and 03-08k. Every number is origin/main's value + 1. The values in brackets are the expectation after 03-08g (main at 9ac9c12 plus one per plan for 03-08j, 03-08k, 03-08f and 03-08g).
1. Commit this plan unchanged as `.planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md`.
2. ROADMAP.md, Phase 3:
   - The Plans line's plan total and wave count each go up by one (N/27 in 26 waves → N/28 in 27 waves). GSD's tracking update sets N.
   - After 03-08g's Wave 18 block, insert `**Wave 19** *(blocked on Wave 18 completion)*` with the unchecked entry `03-08h-PLAN.md — Signer connection shares (F07, F16): directories hosts cannot render refused at install, per-account connection shares in the accept loop, and each slot released before the server's next call`.
   - Renumber the blocks of 03-09 to 03-16 one wave later (Waves 19–26 → 20–27), each "blocked on" clause with them.
3. STATE.md: `total_plans` + 1 (62 → 63), and the Plan line's `of M` + 1 (of 27 → of 28).
4. 03-09-PLAN.md:
   - `wave:` + 1 (19 → 20);
   - `depends_on` becomes `["03-08h"]`;
   - Task 1's `<precondition>` gains the clause `git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md` exits 0, next to its 03-08c, 03-08d, 03-08e, 03-08j, 03-08k, 03-08f and 03-08g clauses, which stay;
   - **the release ordering:** after the sentence that ends `(03-08g's agent-share rule).`, add the sentence `signerclient's HostIssue is a Client method with a package-level wrapper, and socketSigner calls it through s.client(), so the call returns only after the signer has closed the connection (03-08h's release ordering).`
5. 03-10-PLAN.md, **the release ordering:** after the sentence that ends `(03-08g's agent-share rule).`, add the sentence `signerclient's ProbeIssue is a Client method with a package-level wrapper, and socketSigner calls it through s.client(), so the call returns only after the signer has closed the connection (03-08h's release ordering).`
6. The `wave:` lines of 03-10 to 03-16 each go up by one (20–26 → 21–27).
7. **Guards.**
   - If origin/main's 03-09 does not hold `wave: 19` and `depends_on: ["03-08g"]`, another plan was slotted in first. Then apply the same +1 edits from origin/main's actual values, point 03-09's `depends_on` at this plan, and record the deviation in the SUMMARY.
   - If 03-08g's sentence is not on origin/main in either file, add this plan's sentence at the end of the paragraph that adds the hostcert or probecert route, and record where in the SUMMARY.

**e2e under one uid.** CI's e2e jobs run the signer, the server, the CLI and the tests' own signerclient calls as one uid, so all of them share one share of 16. The server's live connections never exceed its 12 calls plus its one KRL read, which leaves 3 for everything else.
1. Before pushing, grep test/e2e for signer use that runs concurrently: a `go func` around signerclient or CLI calls.
2. If any test can have more than 3 such calls in flight beside the server, run it locally first, with `bash scripts/linux.sh 'go test -tags e2e -count=1 -run <name> ./test/e2e/'`, and record the result.
3. A failure in an e2e job where a connection was closed unanswered is a deviation to analyze and report. It is never a reason to retry the job.

**Gates.** Run the full gate. `scripts/capslock-check.sh` is expected to report no new pair, since no package gains a capability; a new pair is a deviation to review and record.

**Push and the PR.**
1. Commit by path only.
2. Push the branch for the first time. The owner allows pushing before the merge.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(signer): per-account connection shares and directories hosts can render (F07, F16)"` with a neutral body that lists the changes as in the objective. Do not enable auto-merge; the orchestrator enables it after the pre-merge review.
4. Wait for the required checks.

**The SUMMARY** contains:
- the PR number and the check run IDs;
- the RED evidence of Tasks 1 to 3, with where each RED was taken;
- the mutants of Tasks 1 to 3;
- the two real-socket runs on Task 2's head, with their refusal counts;
- the shape of `principals_file_above_cap` and the measured time of `check_renderable_is_fast_enough`;
- the internal/agent/apply `ok` lines from the alone and margin gates (bases, after Task 1 and in Task 4) and CI's build-test time;
- every existing assertion that moved, and why (TestOverloadDoesNotStallAccept included);
- the e2e check and capslock;
- `requirements-completed` left empty: REVOKE-02 and AUTHZ-02 were completed by earlier plans, REVOKE-01 stays pending for parts outside this plan, and this plan hardens all three.

Then run the tracking updates once, commit `docs(03-08h): complete signer-shares plan`, push, and wait.
  </action>
  <verify>
    <automated>set -o pipefail; bash scripts/linux.sh 'go test -race -count=1 ./...' | awk '{print} $1=="ok" && $2 ~ /\/internal\/agent\/apply$/ {t=$3; sub(/s$/,"",t); n++; if (t+0 > 480) bad=1} END{exit (n!=1 || bad)}'</automated>
    <fails_when>non-zero exit: internal/agent/apply's ok line under ./... is above 480 s, or missing; a figure above its limit is a deviation to stop on and report</fails_when>
    <automated>grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 ./... && go vet ./... && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit, or "FAIL", "DATA RACE" or a golangci-lint issue line in the output</fails_when>
    <automated>tr -s '[:space:]' ' ' < docs/runbooks/enroll-user.md | grep -c 'directory_unrenderable' && tr -s '[:space:]' ' ' < docs/runbooks/enroll-user.md | grep -c 'keep the account names' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'uid_share_exceeded' && tr -s '[:space:]' ' ' < docs/runbooks/signer-install.md | grep -c 'During a slow signature' && grep -c 's.client()' .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md && grep -c 's.client()' .planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md</automated>
    <fails_when>non-zero exit, or any count printed is 0 (a runbook note or a release-ordering sentence is missing)</fails_when>
    <automated>grep -qx 'depends_on: \["03-08h"\]' .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md && M=$(git show origin/main:.planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md) && W=$(printf '%s\n' "$M" | sed -n 's/^wave: //p') && test -n "$W" && grep -qx "wave: $((W+1))" .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md && grep -c '03-08h-PLAN.md' .planning/ROADMAP.md</automated>
    <fails_when>non-zero exit (the dependency, the +1 wave shift computed from origin/main, or the ROADMAP row is missing)</fails_when>
    <automated>git fetch origin p03/08h-signer-shares && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md && git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-08h-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, or a forbidden file was committed)</fails_when>
    <automated>scripts/gh-as-bot.sh pr checks p03/08h-signer-shares --required --watch</automated>
    <fails_when>non-zero exit (a required check failed or never reported)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new runbook paragraph names at least one CI test and says UNVERIFIED on a real host.
    - `L=$(git log origin/main..HEAD --format=%B) && printf '%s\n' "$L" | grep -ciE 'co-authored-by|generated with'` prints 0, and `B=$(scripts/gh-as-bot.sh pr view p03/08h-signer-shares --json body --jq .body) && printf '%s\n' "$B" | grep -ciE 'co-authored-by|generated with'` prints 0.
    - The PR is open without auto-merge, every required check is green, and 03-08h-SUMMARY.md is on its head. The PR title and every commit message name findings only by F-number.
  </acceptance_criteria>
  <done>The PR waits green, with the plan, the runbook notes, the release-ordering sentences in 03-09 and 03-10, and the publish edits.</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — owner approves PR p03/08h-signer-shares, GitHub squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7)
  </read_first>
  <action>After the orchestrator's pre-merge review has enabled auto-merge, the owner reviews and approves the PR in the GitHub web UI; auto-merge then squash-merges it. Claude never approves or merges with the owner's token.</action>
  <instructions>
    1. Open `gh pr view p03/08h-signer-shares --web` and review:
       - CheckRenderable, its place in InstallDirectory, and the shared caps in swap.go;
       - connSlots, the accept loop, and the release before the close;
       - signerclient.Client and socketSigner's AwaitClose;
       - the two runbook notes and the sentences in 03-09 and 03-10;
       - 03-08h-SUMMARY.md, including the two real-socket runs.

       Check especially four things:
       - the accept loop never takes s.mu;
       - a not-allowed peer is still refused with its uid in the audit log;
       - every slot is released before its connection closes, and only socketSigner waits for the close;
       - CheckRenderable runs only at install, and its non-growth exception compares account sets, not counts (Q-G7).
    2. Approve. No admin bypass, no "Update branch".
    3. Reply "approved". After a rebase, approve the new head and reply again.
  </instructions>
  <verification>Claude runs `bash scripts/merge-gate.sh p03/08h-signer-shares` and handles exits 0-4 per the Delivery Protocol.</verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/08h-signer-shares</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-09's precondition checks)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/08h-signer-shares --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>The signer's capacity is shared per account on main, and 03-09 may start.</done>
  <resume-signal>Type "approved" after approving the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-08g** gives this plan budgetSigner (with GetKRL outside it, Q-G5), agentSlot and `maxSignerCalls`. This plan changes only socketSigner and that constant in internal/server/signer.go, and counts the server's ceiling as `wire.MaxServerSignerCalls + 1`. budgetSigner's tests (TestSignerBudget, TestAgentInFlight) must stay green.
- **03-08d** gives this plan checkCandidate and the KRL-alone pass after a content refusal. Both keep their meaning: apply's caps become the directory constants with unchanged values, so every TestKRLAlone case stays green. The signer now refuses at install what checkCandidate would refuse later, so the host-side fallback becomes a second line, not the only one. 03-08d and 03-08f edit other parts of apply/swap.go and apply/render.go; on a rebase conflict, keep their text and re-apply the const-block change.
- **03-08d, 03-08j and 03-08f** edit signer-install.md, and **03-08f** edits enroll-user.md, in other places. On a rebase conflict, keep their text and re-apply this plan's notes (Task 4).
- **03-09 and 03-10** add HostIssue and ProbeIssue. 03-08g's publish edits give them the agent share and agentSlot. This plan's give them a Client method each, called through s.client(), so their calls also return only after the close.
- **Later plans that edit the same files** must keep these tests green:
  - TestPeerShare and TestOverloadDoesNotStallAccept, in plans that edit the signer's accept loop or handle;
  - TestAwaitClose and TestSocketSignerAwaitsClose, in plans that edit signerclient or socketSigner;
  - TestRenderable, in plans that edit the renderer or the generation caps. 03-10, 03-12 and 03-14 edit apply/render.go; a longer intermediateHeader would fail `intermediate_header_not_longer`.
- **03-16 (homelab drill).** It provokes none of these limits on a real host (owner decision), so the runbook notes stay UNVERIFIED on a real host.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: two allowed accounts.** Two accounts at their share together can still hold every signer slot. That takes two admins colluding, or an admin together with a compromised server (Q-G2, residual of T-03-309).

**Flagged assumption: a stalled signer (accepted, Q-G1, Daniel, 2026-10-30).**
- On the signer, Status, GetDirectory and the calls that issue or install (InstallDirectory, Login, Revoke, ForgetAgent) take s.mu. GetKRL, GetBundle and GetDirectoryVersion do not, when they succeed. A not-found answer to GetBundle or GetDirectoryVersion goes through chainRefusal, s.refuse and refuseLogging, which takes s.mu. Honest agents read versions that exist, so the conclusions below hold.
- connDeadline bounds a connection's socket I/O, not its wait for s.mu.
- While s.mu is held across a slow signature, every call of the first kind that keyroster-server gives up on at its own timeout frees its budget token, but its connection keeps its slot until the handler gets s.mu. The coalesced Status refresh is retried by the next request after statusTimeout, so such calls accumulate.
- The release ordering keeps the server's live calls within its 12 budgeted calls plus its one GetKRL (Q-G5). Once more than 3 abandoned calls are stuck while all 13 are in use, the share can close the server's next calls unanswered, GetKRL and the catch-up reads included, although the signer could answer them without s.mu.
- KRL and state distribution to hosts pauses until the signature completes and the stuck handlers end. Hosts keep what they applied and ask again at their next poll. Before this plan, the same pile-up met only the global 32.
- Independently of the share, the server's KRL and state routes need a Status younger than statusTTL, which waits for s.mu (03-08g). A Status read without the lock is follow-up plan 03-08i (owner decision 2026-10-30). (Since 03-08i, a Status that answers does not wait for s.mu; see 03-08i-PLAN.md.)

**Edges:**
- boundaries, each at the cap and one above:
  - 2048 and 2049 accounts in a host group;
  - a principals file of 64 KiB and of one byte more;
  - 16 and 17 connections from one uid, and 32 and 33 in all;
  - 13 (12 budgeted and one GetKRL) and 16 back-to-back callers from one uid, through the client that waits for the close;
  - under an above-cap installed group: the same accounts, one fewer, one more, and one swapped; a too-large file unchanged and one principal larger;
  - version-digit rollovers 9 → 10 and 99 → 100, with a file at the agent's cap and one at the widest-header bound;
  - a host moved out of an above-share installed group: a union of 4097 and of 4096 accounts, and a new group with a file above the bound (owner decision (2026-11-04), execution stop at Task 1);
- ordering:
  - signatures are checked before renderability;
  - a connection's slot is released before the connection closes;
  - a call that waits for the close returns only after it;
- cancellation and deadlines: a wait for the close ends at the call's deadline with the answer intact;
- failures:
  - a refusal frame is followed by the same wait as an answer;
  - bytes after the frame do not change the answer;
- concurrency: 40 over-share connections while s.mu is held;
- the controls that must not change:
  - a directory at the share installs;
  - a disable under an above-cap installed directory installs;
  - another account's Status is answered while one account holds its share;
  - the server's own load at its budget, and at the share, sees no refusal;
  - the CLI's calls return as soon as the frame is read;
  - a peer that is not allowed is refused with its uid, as before.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access granted or revoked centrally takes effect across the fleet | Tasks 1-3 |
| REQ | REVOKE-01 (revocation from the CLI, which reaches the signer through the server relay) | Tasks 2, 3 |
| REQ | REVOKE-02 (KRLs distributed to all hosts automatically) | Tasks 2, 3 |
| REQ | AUTHZ-02 (principals files from the signed host policy) | Task 1 |
| Finding | F07, signer half (`directory_unrenderable` at install) | Task 1; Task 4 runbook |
| Finding | F16 (per-account shares; the uid in a rate-limited log line) | Task 2; Task 4 runbook |
| Finding | F11's optional part: a receive error that names capacity | Task 3 |
| CONTEXT | 02-CONTEXT D-07 (one principals renderer) | Task 1: the shared caps and the header function live in internal/directory |
| CONTEXT | 01-CONTEXT D-14 (refusals logged at a rate, the rest summarized) | Task 2: acceptLimiter and overloaded |
| CONTEXT | 03-CONTEXT D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 4 |
| Owner decision | Fix homes, directory_unrenderable here, split, grades, delivery, homelab | Owner decisions block, Tasks 1-5 |
| Owner decision | Q-G1: 16 per uid, the server's 12 derived from it, the release ordering, the stall trade-off | Tasks 2, 3; Task 4 runbook; T-03-307 |
| Owner decision | Q-G2: no reserved slot | Task 2 (nothing reserved); T-03-309 |
| Owner decision | Q-G3: 2048 accounts per host group, 64 KiB per file, and the runbook text | Task 1; Task 4 runbook |
| Owner decision | Q-G4, Q-G6 and the agent-share rule | 03-08g |
| Owner decision | Q-G5: GetKRL outside the server budget, a ceiling of 13 | Task 2 (TestConnSlots `arithmetic`); Task 3 (`server_budget_within_share` with a GetKRL caller); Task 4 runbook; T-03-307 |
| Owner decision | Q-G7: the non-growth rule above the cap | Task 1 (CheckRenderable with the installed directory, the TestRenderable and TestDirectoryUnrenderable cases and their mutants); Task 4 runbook; T-03-306 |
| Owner decision | Q-G7: files sized at the widest version header | Task 1 (fileSize at math.MaxUint64; the rollover and header-width cases; the real-version mutant); Task 4 runbook; T-03-306 |
| Owner decision | Subset reading confirmed; this plan kept whole; Status without the lock as 03-08i | Planner decisions; Budget; Edge Coverage |
| Plan check 1 | Item 1 (MAJOR, the stall text), item 2 (WARNING, the release ordering), item 4 (MINOR, Q-G3 compatibility) | Edge Coverage, T-03-307, the Q-G1 record and signer-install.md; Tasks 2 and 3; Task 4's enroll-user.md note |
| Finding fix, optional parts | A separate CLI message for `directory_unrenderable`; F07's agent half | Deferred with reasons in the ledger. F07's agent half is 03-08d's (owner decision) |

## Artifacts this phase produces (this plan)

- **directory:** MaxPrincipalsFile, MaxAccounts, MaxHostGroupAccounts, ErrUnrenderable, principalsHeader and CheckRenderable.
- **signer:**
  - `directory_unrenderable` (unauthorized class) in InstallDirectory;
  - maxConnsPerPeer, connSlots and acceptLimiter;
  - the credentials read in the accept loop, the `uid_share_exceeded` detail, and the release before the close.
- **wire:** MaxPeerConns and MaxServerSignerCalls.
- **signerclient:** Client with AwaitClose, and a receive error that names both causes.
- **server:** socketSigner through `s.client()`, and maxSignerCalls taken from wire.
- **Tests:**
  - TestDirectoryUnrenderable (10 cases), TestRenderable (23) and TestSizerMatchesRender (owner decision (2026-11-04), execution stop at Task 1);
  - TestConnSlots (5) and TestPeerShare (6);
  - TestAwaitClose (5) and TestSocketSignerAwaitsClose;
  - TestOverloadDoesNotStallAccept, with a new setup.
- **Docs:**
  - enroll-user.md: directories hosts cannot render, with the installed-directory and split notes;
  - signer-install.md: connection limits, and the slow-signature note.
- **Planning:** the release-ordering sentence in 03-09 and 03-10.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| admin quorum → signer → hosts | A quorum-signed directory is installed by the signer and rendered by every host agent. A directory that can be installed but not rendered stalls the hosts of its host groups |
| local accounts on the signer socket → signer | Every allowed account (the admins and keyroster-server) shares one pool of connection slots. No account may take the whole pool, and keyroster-server must never be refused by its own share |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-306 | Denial of service | Signer.InstallDirectory: a quorum-signed directory that host agents cannot render, alone or in the intermediate generation of a move between two versions (F07, signer half) | low | mitigate | directory.CheckRenderable after CheckPolicy, on the agent's own caps, which are now one set of constants; at most half the agent's accounts per host group (Q-G3), so the intermediate fits. Above the caps, the non-growth rule against the installed directory (Q-G7): a group's accounts must be a subset of the installed group's, and a too-large file no larger than its installed counterpart, so disabling and removing always install. Tests: TestDirectoryUnrenderable (the above-cap disable and growth cases), TestRenderable (`at_share_fits_target_and_intermediate`, `intermediate_header_not_longer`, the subset, swap, new-group and file cases). **Residual:** the non-growth guarantee covers hosts at the installed version; a host further behind can meet an intermediate above its caps and relies on 03-08d's KRL-alone pass. A directory installed before this release that never rendered stays unrenderable until it is reduced, though it cannot grow. Files are sized at the widest version header, so a file accepted within the bound renders within 64 KiB at every later version. A file from before this release that rendered at exactly the agent's cap still installs unchanged across a version-digit rollover, but renders one byte above the cap; hosts keep applying KRLs until it is reduced. A split into new, disjoint account names can exceed the agent's 4096 on hosts, which then keep their old principals while the KRL-alone pass keeps KRLs landing. enroll-user.md says so |
| T-03-307 | Denial of service | the signer socket: one allowed account holding every connection slot, and keyroster-server's own calls refused by its share (F16) | low | mitigate | Per-uid shares of 16 of the 32 slots, taken in the accept loop after reading the credentials, without s.mu. The release ordering: the signer releases a slot before it closes the connection, and socketSigner returns only after the close, so the server's live counted connections never exceed its 12 budget tokens plus its one coalesced GetKRL (Q-G5): 13, with 3 to spare. Tests: `own_share_full_next_closed`, `other_account_share_full_status_answered`, `slot_released_before_close`, `server_budget_within_share`, `share_exact_never_refused`, TestAwaitClose, TestSocketSignerAwaitsClose, TestOverloadDoesNotStallAccept. **Residual (accepted, Q-G1, Daniel, 2026-10-30):** Status, GetDirectory and the issuing and installing calls take s.mu; GetKRL, GetBundle and GetDirectoryVersion do not. (Since 03-08i, a Status that answers does not wait for s.mu; see 03-08i-PLAN.md.) connDeadline bounds socket I/O, not the wait for s.mu. While s.mu is held across a slow signature, a call of the first kind that the server abandons at its own timeout frees its token but keeps its slot until its handler ends. Once more than 3 are stuck while the server's 13 are in use (the owner's first answer said 4; GetKRL outside the budget takes one, Q-G5), the share can close the server's next calls unanswered, GetKRL and the catch-up reads included, although the signer could answer them; KRL and state distribution pauses until the signature completes. Before this plan the same pile-up met only the global 32. signer-install.md says so |
| T-03-309 | Denial of service | two allowed accounts at their share together holding every slot | low | accept | Q-G2 (Daniel, 2026-10-30): no reserved slot. It needs two admins colluding, or an admin with a compromised server, which can already withhold every relay. The operator log names each refused uid, and refusal_summary counts every refused connection |
| T-03-310 | Repudiation | the operator log: a flood of over-capacity connections hiding which account caused it (F16) | low | mitigate | The accept loop's line names the uid and pid, at the rate of its own acceptLimiter, so a flood cannot drown it. Every refused connection is still counted in overloaded and so in refusal_summary (01-CONTEXT D-14). The audit log format is unchanged. Test: `operator_log_names_uid_rate_limited` |
| T-03-313 | Elevation of privilege | the accept loop reading credentials before the slot: a path around the allowlist (this plan's own risk) | low | mitigate | No identity-override seam. The accounting only refuses more. A peer that is not allowed, or whose credentials cannot be read, is still refused through s.refuse in its own goroutine, with its uid in the audit log. Tests: the existing peer_not_allowed tests, and TestConnSlots `unknown_peer_own_key`. The prohibition |
| T-03-315 | Denial of service | socketSigner's wait for the close: a signer connection that answers and never closes holding the server's call and budget token (this plan's own risk) | low | mitigate | The wait is bounded by the deadline already on the connection and by 64 KiB, and it never changes the answer, so a login certificate is never lost to it. The signer releases the slot and closes right after its one frame, on every path. Only socketSigner sets AwaitClose; the CLI's calls are unchanged. Tests: TestAwaitClose (`deadline_ends_wait`, `trailing_bytes_ignored`, `package_function_unchanged`) |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added. The signer still imports nothing under internal/agent (dep-firewall). The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh), the full gate passes, the PR's required checks are green, and the merge gate passes.
</verification>

<success_criteria>
- The signer refuses at install every directory that the host agents' own caps would refuse, the intermediate generation included, unless nothing grows beyond an above-cap installed version (Q-G7), so disabling and removing users always install.
- No account holds more than 16 of the signer's 32 connections, and every slot is released before its connection closes. Outside a slow signature, keyroster-server's live calls (its 12 budgeted calls and its one GetKRL) never exceed its share.
- The CLI's signer calls are unchanged.
- Nothing any component accepts or serves is widened, and no module is added.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-08h-SUMMARY.md` in Task 4, before the merge gate. Leave `requirements-completed` empty: REVOKE-02 and AUTHZ-02 were completed by earlier plans, REVOKE-01 stays pending for parts outside this plan, and this plan hardens all three. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (F07's signer half and F16, and the owner decisions of 2026-10-29)

### Round 0b — planner self-review while completing the plan (2026-10-30), before plan check 1

### Round 1 — plan check 1 (2026-10-30, PASS WITH FIXES) and the owner's answers (Daniel, 2026-10-30)

### Round 2 — plan check 2 (2026-10-30, PASS WITH FIXES) and the owner's third set of answers (Daniel, 2026-10-30)

### Round 3 — reconcile check against main 741e2f6 (2026-11-03, PASS WITH FIXES)

No overlap with PRs #77 to #82 in internal/signer, internal/signerclient, internal/wire or internal/server. `directory_unrenderable` lives in this plan (Task 1), not 03-08g; 03-08f's join with `directory_not_authorized` and the accepted above-cap record change nothing here; nothing is assumed from 03-08i. Fixed: (1) the never-failing CheckRenderable grep now scopes to loadDirectory, Parse and Validate; (2) principalsHeader comes out of `(*PrincipalsRenderer).File`, as 03-08d left the renderer; (3, 4) the Context base is 741e2f6 and the file histories name 03-08j/k; (5) the login_test.go helpers; (6) the 400 s / 480 s apply gates, bases, stop rule, and no t.Parallel in the timed case; (7) the anchor line for the call; (8) the CLI error claim labelled UNVERIFIED; (9, 10) wording. Task 4's full gate first checks that scripts/linux.sh uses `--exec`. No new owner questions.

### Round 4: execution stop at Task 1 (Daniel, 2026-11-04)

The executor stopped on the 2 s bound of `check_renderable_is_fast_enough`. The plan's literal exception shape took 2.25 s under -race and the all-files-above-bound shape 4.84 s. The plan also contradicted itself in that case: a file within the bound never consults the installed version, so ~60 KiB files are not "sized in both versions". The executor also reported that a host moved out of an above-share installed group could meet an intermediate above 4096 accounts. Owner decisions E-1 (a faster sizer with the same sizes, the bound kept) and E-2 (refuse such a move in the signer) are recorded in the owner decisions block, truth 2, Task 1, the mutant list, Edge Coverage and Task 4's enroll-user.md note.

### Round 5: pre-merge review of PR #84 (2026-11-04)

Three findings at 75620a1. The fixes and owner decisions are recorded as "owner decision (2026-11-04), pre-merge review":
- **R-1 (medium):** the moved-host check counted a move's union once per matching host key, and CheckRenderable scanned the installed host groups once per offered group. Fixed with one name index per directory, and the union counted once per (from, to) pair and skipped while the two groups' sizes add up to at most 4096. The answers are pinned to the previous implementation, and three timed shapes stay under 2 s with -race.
- **R-2 (low):** a host whose keys are all replaced and that moves was not seen as a move. The owner decided to also match by host name. A host renamed and rekeyed in one version stays a limitation in enroll-user.md (UNVERIFIED).
- **R-3 (low):** the move tests never changed the groups between versions and used one key per host. Added cases kill the surviving mutants. An assertion on ErrUnknownHostGroup that the shipped code cannot reach was replaced, and M13 was corrected and re-run.

Details are in 03-08h-SUMMARY.md, "Pre-merge review fixes (PR #84)".

### Round 6: fix-round check of PR #84 (2026-11-04)

A check of round 5's fixes found three problems. The owner decided all three (owner decision (2026-11-04), fix-round check):
- **C-1 (medium):** a move's union still cost the target group's size per distinct pair. Fixed by caching each target group's set too and counting through the smaller set.
- **C-2 (low):** R-2's name match refused name swaps and renames onto a removed name. It now applies only to a host with a key no active installed host holds.
- **C-3 (low):** a union cache keyed by the source group alone survived every test. Fixed with a new case, and the equivalence check now draws 96 pairs.

Parse's validateHosts (O(hosts × host groups) under s.mu) is deferred to 03-08l (owner decision). Details are in 03-08h-SUMMARY.md, "Fix-round check (C-1 to C-3)".

### Review Feedback Addressed
| Concern | Severity | How Addressed |
|---------|----------|---------------|
| F07, signer half: InstallDirectory accepts a quorum-signed directory that host agents cannot render, alone or in the intermediate between two versions | LOW | Truth 2; Task 1; T-03-306 |
| F16: one allowed account can take every signer slot, and the over-capacity log line names no uid | LOW | Truth 3; Task 2; T-03-307, T-03-310 |
| Planner: a server budget equal to the signer's share refuses the server's own calls, because the signer used to free a slot only after the server had read the answer | HIGH | The release ordering (Q-G1): Tasks 2 and 3, truth 4. The 4 slots below the share stay as margin |
| Planner: the accept loop must never wait for s.mu, so it must not refuse through s.refuse | HIGH | Credentials only in the loop. Refusals of not-allowed peers stay in the goroutine, and the log line goes through acceptLimiter. The tests run with s.mu held, and the s.refuse mutant is killed |
| Planner: TestOverloadDoesNotStallAccept changes meaning under the share (one uid's 17th connection is already refused) | MEDIUM | New setup with a pre-filled foreign share, recorded as a moved assertion |
| Planner: "D-07" and "D-14" are decisions of Phases 2 and 1, not 03-CONTEXT's | LOW | Cited as 02-CONTEXT D-07 and 01-CONTEXT D-14 |
| Planner: e2e runs every component as one uid | MEDIUM | Task 4's e2e step, with its stop rule, and the per-uid line in signer-install.md |
| Planner: HostIssue and ProbeIssue would bypass the wait for the close if socketSigner called package functions | MEDIUM | One sentence each in 03-09 and 03-10 (Task 4), socketSigner's growth rule, and Task 3's acceptance grep |
| Check 1 item 1 (MAJOR): the stalled-signer residual claimed the abandoned calls "need" the lock anyway; GetKRL, GetBundle and GetDirectoryVersion do not take it | MAJOR | Corrected in Edge Coverage, the T-03-307 residual and the Q-G1 record, and stated in signer-install.md. The owner accepted the trade-off (Q-G1) |
| Check 1 item 2 (WARNING): the 4-slot slack worked by probability | WARNING | Replaced by the release ordering. `slot_released_before_close`, TestAwaitClose and TestSocketSignerAwaitsClose kill each half deterministically; `share_exact_never_refused` replaces the slack-removed run; the stop rule stays |
| Check 1 item 4 (MINOR): an installed directory above the cap blocks every later install, and a split into new names can exceed the agent's cap | MINOR | The Q-G3 runbook text in enroll-user.md; T-03-306's residual. Refined by Q-G7 below |
| Planner, while splitting: the disable step of `keyroster revoke user` signs a directory version, so an above-cap installed directory would have left a revoked user enabled | MAJOR | Q-G7 (Daniel, 2026-10-30): the non-growth rule. Task 1 takes the installed directory, with a subset rule for accounts (a count rule would let a swapped name grow the intermediate) and literal non-growth for files; named cases and mutants; enroll-user.md and T-03-306 rewritten |
| Owner, Q-G5: GetKRL outside the server budget | — | The server's ceiling at the signer is 13: TestConnSlots `arithmetic`, `server_budget_within_share` with a GetKRL caller, and the stall threshold of 3 in Edge Coverage, T-03-307, the Q-G1 record and signer-install.md |
| Check 1 item 6 (WARNING): scope | WARNING | Split by the owner (2026-10-30): 03-08g is the server side, this plan the signer side |
| Check 1 items 3 and 5 (MAJOR, MINOR) | — | 03-08g's: the agent-share rule, and the settle wait in `catch_up_bounded_interactive_room` |
| Check 2 item 1 (MAJOR): the header's version digits made an unchanged file grow at a rollover, which could refuse a disable, also for files that rendered near the cap | MAJOR | Owner decision 2026-10-30: size every file at the widest version header (20 digits), for the bound and the comparison. fileSize at math.MaxUint64; boundaries redefined; the 9 → 10 and 99 → 100 cases, the header-width case and the real-version mutant; T-03-306 and enroll-user.md |
| Check 2 item 2 (WARNING): signer-install.md and success criterion 2 said the server never fills its share, also during a stall | WARNING | Both now say "outside a slow signature", and the criterion says live calls |
| Check 2 item 3 (WARNING): the Budget section referred to a private review file and carried an open question | WARNING | Replaced with the owner's decision to keep the plan whole |
| Check 2 item 4 (MINOR): a host group missing in the installed version could surface as an AccountPrincipals error | MINOR | The installed counterpart is looked up first; `new_group_file_above_bound_refused` and its mutant |
| Check 2 item 5 (MINOR): the timing test did not exercise the exception path | MINOR | `check_renderable_is_fast_enough` also times 4096 accounts in both versions, under the same 2 s bound |
| Check 2 item 6 (INFO): GetBundle and GetDirectoryVersion take s.mu on a not-found answer | INFO | Stated in Edge Coverage |

### Review Feedback Deferred
| Concern | Reason |
|---------|--------|
| F11 and F16: a reserved pool, or a dedicated share for keyroster-server's uid | Q-G2 (Daniel, 2026-10-30): no reserved slot |
| F07: a dedicated CLI message for `directory_unrenderable` | The CLI's error already names the code, and enroll-user.md explains it |
| F07: the agent half (refusing such a directory at verify on the host) | 03-08d's, by owner decision (checkCandidate and the KRL-alone pass) |
| F16: a frame-header deadline shorter than connDeadline | It does not help on its own, because an account that redials just redials faster. The share bounds what idle connections can hold |
| F16: uids in the refusal_summary leaf | It would change the audit log format. The operator log names them at a bounded rate |

